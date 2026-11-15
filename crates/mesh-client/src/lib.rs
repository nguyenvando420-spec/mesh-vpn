//! Shared OS-neutral client runtime crate bridging desktop `meshd` and `mesh-mobile-ffi`
//! (`ADR-012`, `US-076`).

use mesh_core::defaults::DEFAULT_MOBILE_MAX_WS_FRAME_BYTES;

/// Identifies the shared `mesh-client` runtime core (`v0.2.0` foundation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientRuntimeDescriptor {
    /// Default bounded WebSocket frame budget on constrained mobile environments.
    pub mobile_ws_frame_limit_bytes: usize,
}

impl Default for ClientRuntimeDescriptor {
    fn default() -> Self {
        Self {
            mobile_ws_frame_limit_bytes: DEFAULT_MOBILE_MAX_WS_FRAME_BYTES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ClientRuntimeDescriptor;
    use mesh_core::defaults::DEFAULT_MOBILE_MAX_WS_FRAME_BYTES;

    #[test]
    fn test_mesh_client_descriptor_uses_mobile_frame_budget_constant() {
        // Arrange & Act
        let desc = ClientRuntimeDescriptor::default();

        // Assert
        assert_eq!(
            desc.mobile_ws_frame_limit_bytes,
            DEFAULT_MOBILE_MAX_WS_FRAME_BYTES
        );
    }
}
