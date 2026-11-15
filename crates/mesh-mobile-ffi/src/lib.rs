//! UniFFI `0.29.5` FFI boundary for Android (`libmesh_mobile_ffi.so`) and iOS (`MeshMobileFFI`).
//!
//! Hand-written `unsafe` and direct `jni` dependencies are strictly forbidden here (`IG-MOB-G2-01`).

uniffi::setup_scaffolding!();

/// Returns the FFI package semantic version while retaining Android JNI symbols across LTO/GC.
#[uniffi::export]
#[must_use]
pub fn mobile_ffi_version() -> String {
    #[cfg(target_os = "android")]
    mesh_sys::jni_android::ensure_jni_symbols_linked();
    env!("CARGO_PKG_VERSION").to_owned()
}

#[cfg(test)]
mod tests {
    use super::mobile_ffi_version;

    #[test]
    fn test_mobile_ffi_version_matches_package_version() {
        // Arrange & Act
        let ver = mobile_ffi_version();

        // Assert
        assert_eq!(ver, env!("CARGO_PKG_VERSION"));
    }
}
