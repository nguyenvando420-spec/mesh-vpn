//! Single-instance version negotiation and `WM_APP_QUERY_VERSION` packing (`US-103`, `US-107`,
//! `ADR-026`).

/// Maximum time an upgrade launcher waits for an older `MeshVPN.exe` instance to release its
/// single-instance mutex and exit cleanly before proceeding (`US-107`, `ADR-026`).
pub(crate) const UPGRADE_SHUTDOWN_WAIT_MS: u32 = 3_000;

/// Win32 window class name registered by the main Mesh VPN Dashboard window.
pub(crate) const MAIN_WINDOW_CLASS_NAME: &str = "MeshVpnDashboardWindowClass";

/// Parsed `(major, minor, patch)` semantic version packed into `WM_APP_QUERY_VERSION` (`u32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SemVerTriple {
    pub(crate) major: u8,
    pub(crate) minor: u8,
    pub(crate) patch: u8,
}

impl SemVerTriple {
    /// Parses `MAJOR.MINOR.PATCH` (ignoring optional `-prerelease` / `+build` suffix).
    #[must_use]
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        let core = raw.split(['-', '+']).next()?.trim();
        let mut parts = core.split('.');
        let major = parts.next()?.parse::<u8>().ok()?;
        let minor = parts.next()?.parse::<u8>().ok()?;
        let patch = parts.next()?.parse::<u8>().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
        })
    }

    /// Packs `(major, minor, patch)` into `(major << 16) | (minor << 8) | patch`.
    #[must_use]
    pub(crate) const fn pack_u32(self) -> u32 {
        ((self.major as u32) << 16) | ((self.minor as u32) << 8) | (self.patch as u32)
    }

    /// Unpacks a `WM_APP_QUERY_VERSION` reply back into `SemVerTriple`.
    #[must_use]
    pub(crate) const fn unpack_u32(packed: u32) -> Self {
        let major = ((packed >> 16) & 0xff) as u8;
        let minor = ((packed >> 8) & 0xff) as u8;
        let patch = (packed & 0xff) as u8;
        Self {
            major,
            minor,
            patch,
        }
    }
}

/// Returns `true` when an already-running instance reported an older SemVer than `current`, so the
/// newer binary should signal `GUI_SHUTDOWN_EVENT` and take over instead of merely focusing it.
#[must_use]
pub(crate) fn should_request_upgrade_shutdown(
    current: SemVerTriple,
    running_packed: Option<u32>,
) -> bool {
    running_packed.is_some_and(|packed| SemVerTriple::unpack_u32(packed) < current)
}
