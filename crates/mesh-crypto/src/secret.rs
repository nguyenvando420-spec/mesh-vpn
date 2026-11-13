//! Constant-redaction secret wrapper guaranteeing automatic memory zeroization on drop (`SEC-01`).

use std::fmt;

use serde::{Serialize, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Wrapper around sensitive memory (keys, pre-auth tokens, DER private keys) that zeroes
/// its contents on drop and always formats/serializes as `"[REDACTED]"`.
pub struct Secret<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> Secret<T> {
    /// Moves sensitive material into a zeroize-on-drop [`Secret`] container.
    #[must_use]
    pub const fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Exposes a shared reference to the underlying secret value.
    ///
    /// Workspace static checks permit calls to this method ONLY in `mesh-crypto`,
    /// `mesh-datapath`, `mesh-net` (keystore), and `mesh` (one-time CLI display).
    #[must_use]
    pub const fn expose_secret(&self) -> &T {
        &self.inner
    }

    /// Duplicates the secret into a new zeroized container when explicitly required.
    #[must_use]
    pub fn clone_secret(&self) -> Self
    where
        T: Clone,
    {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: Zeroize> Zeroize for Secret<T> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: Zeroize> ZeroizeOnDrop for Secret<T> {}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: Zeroize> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: Zeroize> Serialize for Secret<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn test_secret_always_redacts_debug_display_and_json() {
        // Arrange
        let secret = Secret::new([0xde_u8; 32]);
        let secret_str = Secret::new("mpk_top_secret_token".to_owned());

        // Act
        let dbg_out = format!("{secret:?}");
        let disp_out = format!("{secret_str}");
        let json_out = serde_json::to_string(&secret_str).unwrap_or_default();

        // Assert
        assert_eq!(dbg_out, "[REDACTED]");
        assert_eq!(disp_out, "[REDACTED]");
        assert_eq!(json_out, "\"[REDACTED]\"");
    }
}
