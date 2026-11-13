//! `clap` command structure for the unified `mesh` CLI (`mesh <noun> <verb> --kebab-flag`).

use clap::{Parser, Subcommand};

/// Unified Mesh VPN CLI supporting local client daemon control and server administration.
#[derive(Debug, Parser)]
#[command(name = "mesh", version, about = "Mesh VPN CLI")]
pub(crate) struct Cli {
    /// Emit machine-readable JSON output for automation scripts.
    #[arg(long, global = true)]
    pub(crate) json: bool,

    /// Subcommand to execute.
    #[command(subcommand)]
    pub(crate) command: TopCommand,
}

/// Top-level CLI nouns and client operations.
#[derive(Debug, Subcommand)]
pub(crate) enum TopCommand {
    /// Display local daemon connection status (`meshd-ro`).
    Status,
    /// List overlay peers and active direct/relay paths (`meshd-ro`).
    Peers,
    /// Measure overlay latency to a peer (`meshd-ro`).
    Ping {
        /// Peer hostname or overlay IP address.
        target: String,
    },
    /// Probe NAT behavior and STUN/Relay reachability (`meshd-ro`).
    Netcheck,
    /// Bring the overlay interface up (`meshd-admin`).
    Up {
        /// Optional server endpoint override.
        #[arg(long)]
        server: Option<String>,
    },
    /// Shut down the active overlay session cleanly (`meshd-admin`).
    Down,
    /// Update persistent client runtime preferences (`meshd-admin`).
    Set,
    /// Rotate local node WireGuard/Control keypair (`meshd-admin`).
    RotateKey,
    /// Clean up leftover OS network resources from `ledger.json` (`meshd-admin`).
    Cleanup,
    /// Bundle sanitized non-secret diagnostic logs (`meshd-admin`).
    Bugreport,
    /// Server pre-authentication key management (`/run/mesh-server/admin.sock`).
    Preauthkey {
        /// Action on pre-auth keys (`create`, `list`, `revoke`).
        #[command(subcommand)]
        action: PreauthkeyVerb,
    },
    /// Server node administration commands (`/run/mesh-server/admin.sock`).
    Node {
        /// Action on registered nodes (`list`, `revoke`).
        #[command(subcommand)]
        action: NodeVerb,
    },
    /// Server status and certificate operations (`/run/mesh-server/admin.sock`).
    Server {
        /// Server administration action (`status`).
        #[command(subcommand)]
        action: ServerVerb,
    },
    /// Create a hot atomic database snapshot backup.
    Backup,
    /// Restore database from a verified SHA-256 backup snapshot.
    Restore {
        /// Path to backup directory or archive.
        path: String,
    },
    /// Run VPS/host hardening verification checks.
    HardeningCheck,
}

/// Sub-verbs under `mesh preauthkey`.
#[derive(Debug, Subcommand)]
pub(crate) enum PreauthkeyVerb {
    /// Generate a new high-entropy `mpk_` token.
    Create,
    /// List active pre-auth key metadata (secrets redacted).
    List,
    /// Revoke a pre-auth key identifier immediately.
    Revoke {
        /// Pre-auth key UUID.
        key_id: String,
    },
}

/// Sub-verbs under `mesh node`.
#[derive(Debug, Subcommand)]
pub(crate) enum NodeVerb {
    /// List registered overlay nodes.
    List,
    /// Revoke a compromised node immediately.
    Revoke {
        /// Node UUID or name.
        target: String,
    },
}

/// Sub-verbs under `mesh server`.
#[derive(Debug, Subcommand)]
pub(crate) enum ServerVerb {
    /// Print control server operational summary.
    Status,
}
