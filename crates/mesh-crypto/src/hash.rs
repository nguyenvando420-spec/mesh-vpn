//! SHA-256 digests, constant-time byte comparisons, and streaming file integrity verification.

use std::fs::File;
use std::io::{BufReader, Read as _};
use std::path::Path;

use data_encoding::{HEXLOWER, HEXLOWER_PERMISSIVE};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use mesh_core::{AppError, AppResult};

/// Computes the raw 32-byte SHA-256 digest of `data`.
#[must_use]
pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes the 64-character lowercase hexadecimal SHA-256 digest of `data`.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    HEXLOWER.encode(&sha256_digest(data))
}

/// Compares two byte slices in constant time with respect to their contents.
///
/// Length inequality short-circuits cleanly without reading mismatched buffers.
#[must_use]
pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

/// Streams a file on disk and verifies its SHA-256 digest in constant time against `expected_hex`.
///
/// Used before loading external signed/verified binaries such as Windows `wintun.dll` or snapshot archives.
pub fn verify_file_sha256(path: &Path, expected_hex: &str) -> AppResult<[u8; 32]> {
    let expected_raw = HEXLOWER_PERMISSIVE
        .decode(expected_hex.trim().as_bytes())
        .map_err(|_| AppError::invalid_argument("invalid expected SHA-256 hexadecimal string"))?;
    let expected = <[u8; 32]>::try_from(expected_raw.as_slice())
        .map_err(|_| AppError::invalid_argument("expected SHA-256 digest must be 32 bytes"))?;

    let file = File::open(path).map_err(|err| {
        AppError::internal(format!(
            "failed to open `{}` for SHA-256 check: {err}",
            path.display()
        ))
    })?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 8_192];
    loop {
        let read_bytes = reader.read(&mut buf).map_err(|err| {
            AppError::internal(format!("failed reading `{}`: {err}", path.display()))
        })?;
        if read_bytes == 0 {
            break;
        }
        if let Some(chunk) = buf.get(..read_bytes) {
            hasher.update(chunk);
        }
    }
    let actual: [u8; 32] = hasher.finalize().into();
    if !ct_eq_bytes(&actual, &expected) {
        return Err(AppError::pin_mismatch(format!(
            "SHA-256 mismatch for `{}`",
            path.display()
        )));
    }
    Ok(actual)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::{ct_eq_bytes, sha256_digest, sha256_hex, verify_file_sha256};

    #[test]
    fn test_sha256_vectors_and_constant_time_equality() {
        // Arrange
        let empty = b"";

        // Act
        let hex = sha256_hex(empty);
        let digest = sha256_digest(b"mesh");

        // Assert
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(ct_eq_bytes(&digest, &sha256_digest(b"mesh")));
        assert!(!ct_eq_bytes(&digest, &[0_u8; 32]));
        assert!(!ct_eq_bytes(&digest, &[0_u8; 31]));
    }

    #[test]
    fn test_verify_file_sha256_accepts_match_and_rejects_tamper() {
        // Arrange
        let Ok(tmp) = tempfile::NamedTempFile::new() else {
            return;
        };
        let payload = b"wintun-binary-stub-content";
        let expected = sha256_hex(payload);
        assert!(tmp.as_file().write_all(payload).is_ok());

        // Act
        let ok_res = verify_file_sha256(tmp.path(), &expected);
        let bad_res = verify_file_sha256(
            tmp.path(),
            "0000000000000000000000000000000000000000000000000000000000000000",
        );

        // Assert
        assert!(ok_res.is_ok());
        assert!(bad_res.is_err());
    }
}
