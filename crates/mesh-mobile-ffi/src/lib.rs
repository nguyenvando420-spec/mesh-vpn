//! UniFFI `0.29.5` Mobile FFI boundary for Android (`VpnService`) & iOS (`NEPacketTunnelProvider`).
//!
//! # Zero-Trust & FFI Invariants
//! - `0` hand-written `unsafe` blocks across `crates/mesh-mobile-ffi/src/*.rs`.
//! - `0` calls to `expose_secret` inside `mesh-mobile-ffi`.
//! - All secret tokens remain inside opaque `ZeroizeOnDrop` handles; control-plane registration
//!   secrets never cross out of Rust diagnostics, status snapshots (`<= 4096 B`), or `.tar` bundles.

mod bridge;
mod bugreport;
mod dns_responder;
mod engine;
mod tun_bridge;
mod types;

uniffi::setup_scaffolding!();

pub use dns_responder::MobileSplitDnsInterceptor;
pub use engine::{
    JetsamEvaluation, JetsamPressureController, JetsamPressureStage, MobileEngine,
    mobile_enroll_or_rotate_node,
};
pub use types::{
    MobileActivePathKind, MobileBugreportResult, MobileDaemonState, MobileEngineInitConfig,
    MobileEnrollConfig, MobileError, MobileJoinUriData, MobileNatKind, MobileNetEventKind,
    MobileNetcheckResponse, MobileParsedJoinUri, MobilePeerStatus, MobilePendingJoinSession,
    MobilePingRequest, MobilePingResponse, MobilePingSample, MobilePingVia, MobilePlatformKind,
    MobilePlatformWarning, MobileRotateKeyConfig, MobileSelfNetworkStatus, MobileServerStatus,
    MobileSetConfig, MobileStatusSnapshot, MobileTlsAuthMode, MobileTunnelConfig,
    MobileTunnelNetworkConfig, MobileUnderlayState, MobileUpConfig, MobileWarningKind,
    PlatformNetworkBridge, create_pending_join_session, parse_mobile_join_uri,
};

/// Returns the crate semantic version exported across UniFFI and links Android `JNI_OnLoad`.
#[uniffi::export]
#[must_use]
pub fn mobile_ffi_version() -> String {
    #[cfg(target_os = "android")]
    mesh_sys::jni_android::ensure_jni_symbols_linked();
    env!("CARGO_PKG_VERSION").to_owned()
}
