//! Unprivileged user-space UI preferences skeleton (`ThemeMode` & `LocaleMode`, `ADR-031`, `WP-U-A0`).
//!
//! Atomic `%LOCALAPPDATA%\MeshVPN\ui-prefs.json` storage is wired in `WP-U-C1`.

use mesh_core::AppResult;
use serde::{Deserialize, Serialize};

use crate::i18n::LocaleMode;
use crate::theme::ThemeMode;

/// Persisted user-space theme and language preferences (`WP-U-A0` skeleton).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) struct UiPrefs {
    /// Selected color theme mode (`"system"`, `"light"`, or `"dark"`).
    pub(crate) theme: ThemeMode,
    /// Selected interface language mode (`"system"`, `"en"`, or `"vi"`).
    pub(crate) locale: LocaleMode,
}

/// Loads user UI preferences, safely falling back to [`UiPrefs::default`] (`WP-U-A0` stub).
#[must_use]
pub(crate) fn load_prefs() -> UiPrefs {
    UiPrefs::default()
}

/// Atomically persists user UI preferences in user-space (`WP-U-A0` stub).
pub(crate) fn save_prefs(prefs: &UiPrefs) -> AppResult<()> {
    let _snapshot = (prefs.theme, prefs.locale);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{UiPrefs, load_prefs, save_prefs};
    use crate::i18n::LocaleMode;
    use crate::theme::ThemeMode;

    #[test]
    fn test_prefs_skeleton_default_and_serde_contract() {
        // Arrange
        let defaults = load_prefs();

        // Act
        let json = serde_json::to_string(&defaults).expect("serialize UiPrefs");
        let parsed: UiPrefs = serde_json::from_str(&json).expect("deserialize UiPrefs");

        // Assert
        assert_eq!(defaults.theme, ThemeMode::System);
        assert_eq!(defaults.locale, LocaleMode::System);
        assert_eq!(json, r#"{"theme":"system","locale":"system"}"#);
        assert_eq!(parsed, defaults);
        assert!(save_prefs(&defaults).is_ok());
    }
}
