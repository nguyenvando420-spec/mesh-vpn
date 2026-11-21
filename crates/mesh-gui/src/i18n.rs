//! Bilingual UI localization skeleton (`en` / `vi`, `213` keys, `ADR-029`, `WP-U-A0`).
//!
//! Full 213-key tables and live locale switching are wired in `WP-U-C1`.

use serde::{Deserialize, Serialize};

/// User-selectable UI language mode (`ADR-029`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum LocaleMode {
    /// Follow the operating system UI locale.
    #[default]
    System,
    /// Force English UI labels.
    En,
    /// Force Vietnamese UI labels.
    Vi,
}

/// Compile-time English UI string table (`213` canonical keys, populated in `WP-U-C1`).
pub(crate) const EN_STRINGS: [(&str, &str); 213] = [("", ""); 213];

/// Compile-time Vietnamese UI string table (`213` canonical keys, populated in `WP-U-C1`).
pub(crate) const VI_STRINGS: [(&str, &str); 213] = [("", ""); 213];

/// Pure UI string lookup using system locale (stub returning `""` in `WP-U-A0`).
#[must_use]
pub(crate) fn t(key: &str) -> &'static str {
    t_for(key, LocaleMode::System)
}

/// Pure UI string lookup for an explicit [`LocaleMode`] (race-free for parallel unit tests).
#[must_use]
pub(crate) fn t_for(key: &str, locale: LocaleMode) -> &'static str {
    let use_vi = match locale {
        LocaleMode::System => system_locale_is_vi(),
        LocaleMode::En => false,
        LocaleMode::Vi => true,
    };
    let table: &[(&str, &str)] = if use_vi { &VI_STRINGS } else { &EN_STRINGS };
    for &(entry_key, entry_val) in table {
        if !entry_key.is_empty() && entry_key == key {
            return entry_val;
        }
    }
    ""
}

fn system_locale_is_vi() -> bool {
    #[cfg(target_os = "windows")]
    {
        mesh_sys::gui_windows::detect_windows_system_locale_is_vi()
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::{EN_STRINGS, LocaleMode, VI_STRINGS, t, t_for};

    #[test]
    fn test_i18n_skeleton_213_slot_tables_and_pure_lookup() {
        // Arrange & Act & Assert
        assert_eq!(EN_STRINGS.len(), 213);
        assert_eq!(VI_STRINGS.len(), 213);
        assert_eq!(t("tab.status"), "");
        assert_eq!(t_for("tab.status", LocaleMode::En), "");
        assert_eq!(t_for("tab.status", LocaleMode::Vi), "");
        assert_eq!(t_for("tab.status", LocaleMode::System), "");
    }
}
