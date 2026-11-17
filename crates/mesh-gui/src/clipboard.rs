//! Atomic Win32 clipboard capture and sequence-plus-SHA-256 auto-clear guard
//! (`US-105`, `IG-DGUI-WA-01`, `BLK-DGUI-G2-05`).

use std::fmt;

use mesh_crypto::{ct_eq_bytes, sha256_digest};
#[cfg(target_os = "windows")]
use mesh_sys::error::SysResult;
#[cfg(target_os = "windows")]
use mesh_sys::gui_windows::clear_clipboard_if_seq_and_predicate;

/// Auto-clear delay after pasting sensitive Pre-Auth credentials or `mesh://` URIs (30 seconds).
pub(crate) const CLIPBOARD_WIPE_DELAY_MS: u32 = 30_000;

/// Captures only the clipboard sequence number and a SHA-256 digest of sensitive text so plaintext
/// credentials stay out of the guard and clipboard ownership stays atomic (`IG-DGUI-WA-01`).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ClipboardSecretGuard {
    expected_seq: u32,
    expected_sha256: [u8; 32],
    armed: bool,
}

impl fmt::Debug for ClipboardSecretGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClipboardSecretGuard")
            .field("expected_seq", &self.expected_seq)
            .field("armed", &self.armed)
            .field("expected_sha256", &"[REDACTED_DIGEST]")
            .finish()
    }
}

impl ClipboardSecretGuard {
    /// Arms an atomic auto-clear guard for `(expected_seq, text)`.
    #[must_use]
    pub(crate) fn arm(expected_seq: u32, text: &str) -> Self {
        Self {
            expected_seq,
            expected_sha256: sha256_digest(text.as_bytes()),
            armed: true,
        }
    }

    /// Returns whether the guard is currently waiting to clear a pasted secret.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn is_armed(&self) -> bool {
        self.armed
    }

    /// Returns the captured `GetClipboardSequenceNumber()` value at paste time.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn expected_seq(&self) -> u32 {
        self.expected_seq
    }

    /// Disarms the guard without touching the system clipboard.
    #[cfg(test)]
    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }

    /// Returns `true` iff the guard is armed and `current_text` matches the captured SHA-256 digest
    /// in constant time.
    #[must_use]
    pub(crate) fn matches_text(&self, current_text: &str) -> bool {
        if !self.armed {
            return false;
        }
        let actual = sha256_digest(current_text.as_bytes());
        ct_eq_bytes(&self.expected_sha256, &actual)
    }

    /// Pure state transition checking whether `(current_seq, current_text)` should be cleared,
    /// always disarming afterwards.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn evaluate_clear(&mut self, current_seq: u32, current_text: Option<&str>) -> bool {
        if !self.armed {
            return false;
        }
        let should_clear = current_seq == self.expected_seq
            && current_text.is_some_and(|text| self.matches_text(text));
        self.armed = false;
        should_clear
    }
}

/// Returns `true` if pasted clipboard text represents a sensitive credential or join URI that
/// merits scheduled auto-clear.
#[must_use]
pub(crate) fn looks_like_sensitive_paste(text: &str) -> bool {
    let trimmed = text.trim();
    !trimmed.is_empty()
        && (trimmed.starts_with("mesh://")
            || trimmed.starts_with("mpk_")
            || trimmed.starts_with("mesh_pak_")
            || (!trimmed.chars().any(char::is_whitespace) && trimmed.len() >= 8))
}

/// Executes the single-lock `ClipboardGuard` sequence check + SHA-256 check + `EmptyClipboard()`
/// sequence on Windows (`IG-DGUI-WA-01`), disarming the guard afterwards.
#[cfg(target_os = "windows")]
pub(crate) fn attempt_atomic_clipboard_clear(guard: &mut ClipboardSecretGuard) -> SysResult<bool> {
    if !guard.armed {
        return Ok(false);
    }
    let snapshot = guard.clone();
    guard.armed = false;
    clear_clipboard_if_seq_and_predicate(snapshot.expected_seq, |current_text| {
        snapshot.matches_text(current_text)
    })
}
