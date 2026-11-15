//! Android JNI bridge for caching process `JavaVM` and `Context` (`ADR-014`, `IG-MOB-G2-01`).

use std::io::Error;
use std::sync::OnceLock;

use jni::objects::{GlobalRef, JClass, JObject};
use jni::sys::{JNI_FALSE, JNI_TRUE, jboolean};
use jni::{JNIEnv, JavaVM};

use crate::error::{SysError, SysResult};

struct AndroidJniContext {
    jvm: JavaVM,
    app_context: GlobalRef,
}

static ANDROID_JNI_STATE: OnceLock<AndroidJniContext> = OnceLock::new();

/// Idempotent JNI initialization entrypoint invoked by Android `MeshApplication.onCreate()`.
///
/// Caches the process [`JavaVM`] and global `Context` reference inside `mesh-sys` so upper crates
/// (`mesh-crypto`) never declare `jni` or `unsafe` directly (`IG-MOB-G2-01`).
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_meshvpn_android_ffi_MeshNativeInit_initPlatformVerifier(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    context: JObject<'_>,
) -> jboolean {
    if ANDROID_JNI_STATE.get().is_some() {
        return JNI_TRUE;
    }
    if context.is_null() {
        return JNI_FALSE;
    }
    let Ok(jvm) = env.get_java_vm() else {
        return JNI_FALSE;
    };
    let Ok(app_context) = env.new_global_ref(&context) else {
        return JNI_FALSE;
    };
    let _ignored = ANDROID_JNI_STATE.set(AndroidJniContext { jvm, app_context });
    JNI_TRUE
}

/// Attaches the current thread to the cached Android [`JavaVM`] and invokes `f` with an active
/// [`JNIEnv`] and the cached application [`JObject`] context.
pub fn with_attached_env_and_context<R>(
    f: impl FnOnce(&mut JNIEnv<'_>, &JObject<'_>) -> SysResult<R>,
) -> SysResult<R> {
    let state = ANDROID_JNI_STATE.get().ok_or_else(|| SysError::SecurityViolation {
        operation: "with_attached_env_and_context",
        detail: "Android JNI context not initialized; call MeshNativeInit.initPlatformVerifier(context) first"
            .to_owned(),
    })?;
    let mut env = state.jvm.attach_current_thread().map_err(|err| {
        SysError::io(
            "with_attached_env_and_context",
            Error::other(format!("failed attaching thread to Android JavaVM: {err}")),
        )
    })?;
    f(&mut env, state.app_context.as_obj())
}

/// References [`Java_dev_meshvpn_android_ffi_MeshNativeInit_initPlatformVerifier`] so linker
/// `--gc-sections` / ThinLTO cannot discard the JNI entrypoint from `libmesh_mobile_ffi.so`.
pub fn ensure_jni_symbols_linked() {
    let entry: extern "system" fn(JNIEnv<'_>, JClass<'_>, JObject<'_>) -> jboolean =
        Java_dev_meshvpn_android_ffi_MeshNativeInit_initPlatformVerifier;
    let _kept = std::hint::black_box(entry);
}
