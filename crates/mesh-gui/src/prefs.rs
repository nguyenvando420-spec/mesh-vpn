//! Unprivileged user-space UI preferences (`ThemeMode` & `LocaleMode`, `ADR-031`, `WP-U-C1`).
//!
//! Persisted atomically in `%LOCALAPPDATA%\MeshVPN\ui-prefs.json` on Windows (and
//! `$XDG_CONFIG_HOME/MeshVPN/ui-prefs.json` on Linux) using `.part` -> `sync_all()` ->
//! `fs::rename` with zero `unsafe`, zero UAC elevation, and zero secrets.

use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use mesh_core::{AppError, AppResult};
use serde::{Deserialize, Serialize};

use crate::app::GUI_APP_DATA_DIR_NAME;
use crate::i18n::LocaleMode;
use crate::theme::ThemeMode;

/// Canonical preferences file name under the user-space `MeshVPN` directory (`ADR-031`).
pub(crate) const UI_PREFS_FILENAME: &str = "ui-prefs.json";

static PART_SEQ: AtomicU64 = AtomicU64::new(1);

/// Persisted user-space theme and language preferences (`ADR-031`).
///
/// Serializes strictly as `{"theme":"system"|"light"|"dark","locale":"system"|"en"|"vi"}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) struct UiPrefs {
    /// Selected color theme mode (`"system"`, `"light"`, or `"dark"`).
    pub(crate) theme: ThemeMode,
    /// Selected interface language mode (`"system"`, `"en"`, or `"vi"`).
    pub(crate) locale: LocaleMode,
}

/// Computes `<base>/MeshVPN/ui-prefs.json` when a user-space base directory is provided.
#[must_use]
pub(crate) fn prefs_path_from_base(base: Option<&Path>) -> Option<PathBuf> {
    base.filter(|p| !p.as_os_str().is_empty())
        .map(|dir| dir.join(GUI_APP_DATA_DIR_NAME).join(UI_PREFS_FILENAME))
}

/// Resolves the default user-space preferences file path without requiring elevation.
#[must_use]
pub(crate) fn default_prefs_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
        prefs_path_from_base(base.as_deref())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
        prefs_path_from_base(base.as_deref())
    }
}

/// Loads user UI preferences from `path`, logging `tracing::warn!` and falling back to
/// [`UiPrefs::default`] on I/O or JSON parse failure (deleting corrupt JSON files).
#[must_use]
pub(crate) fn load_prefs_from_path(path: &Path) -> UiPrefs {
    let raw = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return UiPrefs::default(),
        Err(err) => {
            tracing::warn!(
                component = "mesh-gui",
                event = "ui_prefs_read_failed",
                error = %err,
                "failed reading UI preferences file; falling back to defaults"
            );
            return UiPrefs::default();
        }
    };

    match serde_json::from_str::<UiPrefs>(&raw) {
        Ok(parsed) => parsed,
        Err(err) => {
            tracing::warn!(
                component = "mesh-gui",
                event = "ui_prefs_parse_failed",
                error = %err,
                "corrupt UI preferences JSON detected; removing file and falling back to defaults"
            );
            let _removed = fs::remove_file(path);
            UiPrefs::default()
        }
    }
}

/// Atomically persists `prefs` to `path` via sibling `.part` -> `sync_all()` -> `fs::rename`.
pub(crate) fn save_prefs_to_path(path: &Path, prefs: &UiPrefs) -> AppResult<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| AppError::invalid_argument("UI preferences path has no parent directory"))?;
    fs::create_dir_all(parent).map_err(|err| {
        AppError::internal(format!("failed creating UI preferences directory: {err}"))
    })?;

    let payload = serde_json::to_string(prefs)
        .map_err(|err| AppError::internal(format!("failed serializing UI preferences: {err}")))?;

    let pid = std::process::id();
    let seq = PART_SEQ.fetch_add(1, Ordering::Relaxed);
    let part_path = parent.join(format!("{UI_PREFS_FILENAME}.{pid}.{seq}.part"));

    let write_res: io::Result<()> = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part_path)?;
        file.write_all(payload.as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&part_path, path)?;
        Ok(())
    })();

    if let Err(err) = write_res {
        let _removed = fs::remove_file(&part_path);
        return Err(AppError::internal(format!(
            "failed atomically saving UI preferences: {err}"
        )));
    }
    Ok(())
}

/// Loads user UI preferences from `%LOCALAPPDATA%\MeshVPN\ui-prefs.json`, safely falling back
/// to [`UiPrefs::default`] on missing, unreadable, or corrupt files.
#[must_use]
pub(crate) fn load_prefs() -> UiPrefs {
    let Some(path) = default_prefs_path() else {
        tracing::warn!(
            component = "mesh-gui",
            event = "ui_prefs_path_unavailable",
            "user-space preferences directory unavailable; using defaults"
        );
        return UiPrefs::default();
    };
    load_prefs_from_path(&path)
}

/// Atomically persists user UI preferences in `%LOCALAPPDATA%\MeshVPN\ui-prefs.json`.
pub(crate) fn save_prefs(prefs: &UiPrefs) -> AppResult<()> {
    let Some(path) = default_prefs_path() else {
        return Err(AppError::unavailable(
            "user-space preferences directory unavailable",
        ));
    };
    save_prefs_to_path(&path, prefs)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use tempfile::tempdir;

    use super::{
        UI_PREFS_FILENAME, UiPrefs, load_prefs_from_path, prefs_path_from_base, save_prefs_to_path,
    };
    use crate::i18n::LocaleMode;
    use crate::theme::ThemeMode;

    #[test]
    fn test_prefs_atomic_save_load_corrupt_fallback_and_serde_contract() {
        // Arrange
        let Ok(dir) = tempdir() else {
            return;
        };
        let Some(prefs_path) = prefs_path_from_base(Some(dir.path())) else {
            return;
        };
        assert_eq!(
            prefs_path.file_name().and_then(|s| s.to_str()),
            Some(UI_PREFS_FILENAME)
        );
        assert!(prefs_path_from_base(Some(Path::new(""))).is_none());

        // Missing file -> defaults cleanly
        let defaults = load_prefs_from_path(&prefs_path);
        assert_eq!(defaults, UiPrefs::default());

        // Act: atomic save -> verify exact JSON fields "theme" & "locale" -> reload
        let custom = UiPrefs {
            theme: ThemeMode::Dark,
            locale: LocaleMode::Vi,
        };
        assert!(save_prefs_to_path(&prefs_path, &custom).is_ok());
        let raw = fs::read_to_string(&prefs_path).unwrap_or_default();
        assert_eq!(raw, r#"{"theme":"dark","locale":"vi"}"#);
        assert_eq!(load_prefs_from_path(&prefs_path), custom);

        // Atomic overwrite replaces existing file with zero leftover .part siblings
        let updated = UiPrefs {
            theme: ThemeMode::Light,
            locale: LocaleMode::En,
        };
        assert!(save_prefs_to_path(&prefs_path, &updated).is_ok());
        assert_eq!(load_prefs_from_path(&prefs_path), updated);
        if let Some(parent) = prefs_path.parent()
            && let Ok(entries) = fs::read_dir(parent)
        {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                assert!(!name.ends_with(".part"), "leftover temp file {name}");
            }
        }

        // Corrupt JSON -> deletes corrupt file and falls back to defaults
        assert!(fs::write(&prefs_path, "{corrupt-json").is_ok());
        assert_eq!(load_prefs_from_path(&prefs_path), UiPrefs::default());
        assert!(!prefs_path.exists());
        let _default_api = (
            super::default_prefs_path,
            super::load_prefs,
            super::save_prefs,
        );
    }
}
