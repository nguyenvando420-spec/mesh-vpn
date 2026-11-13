//! Root Clap CLI parser composition separating client vs admin subcommands (`HR-G2-04`).

use clap::{Parser, Subcommand};

use crate::admin_cmds::AdminCommand;
use crate::client_cmds::ClientCommand;

/// Unified Mesh VPN CLI entrypoint (`mesh`).
#[derive(Debug, Parser)]
#[command(
    name = "mesh",
    version,
    about = "Mesh VPN unified node & server administration CLI"
)]
pub(crate) struct Cli {
    /// Output machine-readable JSON instead of human tables.
    #[arg(long, global = true)]
    pub(crate) json: bool,
    /// Override local read-only agent IPC socket/pipe path.
    #[arg(long, global = true, hide = true)]
    pub(crate) ro_ipc: Option<String>,
    /// Override local admin agent IPC socket/pipe path.
    #[arg(long, global = true, hide = true)]
    pub(crate) admin_ipc: Option<String>,
    /// Override Linux mesh-server admin Unix socket path.
    #[arg(long, global = true, hide = true)]
    pub(crate) server_admin_socket: Option<String>,
    /// Dispatched command tree split cleanly between client and admin scopes.
    #[command(subcommand)]
    pub(crate) command: TopCommand,
}

/// Top-level command router flattening client and server-admin subcommands cleanly (`HR-G2-04`).
#[derive(Debug, Subcommand)]
pub(crate) enum TopCommand {
    /// Local client commands routed to `meshd-ro` / `meshd-admin`.
    #[command(flatten)]
    Client(ClientCommand),
    /// Server administration commands routed to `/run/mesh-server/admin.sock`.
    #[command(flatten)]
    Admin(AdminCommand),
}

/// Returns diagnostic subsystem label.
#[cfg(test)]
#[must_use]
pub(crate) const fn status_label() -> &'static str {
    "cli:ready"
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::admin_cmds::{AdminCommand, PreauthkeySubcommand, ServerSubcommand};
    use crate::client_cmds::ClientCommand;

    use super::{Cli, TopCommand};

    #[test]
    fn test_cli_parses_client_and_admin_trees_and_blocks_raw_authkey_argv() {
        // Arrange / Act
        let status = Cli::try_parse_from(["mesh", "status", "--json"]).expect("status");
        assert!(status.json);
        assert!(matches!(
            status.command,
            TopCommand::Client(ClientCommand::Status)
        ));

        let ping =
            Cli::try_parse_from(["mesh", "ping", "vps-1", "-c", "6", "--direct"]).expect("ping");
        assert!(matches!(
            ping.command,
            TopCommand::Client(ClientCommand::Ping(ref args))
                if args.peer == "vps-1" && args.count == 6 && args.direct
        ));

        let up_bad = Cli::try_parse_from([
            "mesh",
            "up",
            "--server",
            "203.0.113.10:8443",
            "--authkey",
            "mpk_inline_leak",
        ]);
        assert!(up_bad.is_err(), "--authkey argv flag must not exist");

        let preauth = Cli::try_parse_from([
            "mesh",
            "preauthkey",
            "create",
            "--ttl",
            "2h",
            "--for",
            "macbook",
            "--reusable",
            "--max-uses",
            "4",
            "--ephemeral",
        ])
        .expect("preauthkey create");
        assert!(matches!(
            preauth.command,
            TopCommand::Admin(AdminCommand::Preauthkey(ref pa))
                if matches!(
                    pa.action,
                    PreauthkeySubcommand::Create(ref args)
                        if args.ttl == "2h"
                            && args.for_node.as_deref() == Some("macbook")
                            && args.reusable
                            && args.max_uses == Some(4)
                            && args.ephemeral
                )
        ));

        let restore = Cli::try_parse_from([
            "mesh",
            "server",
            "restore",
            "snap.tar",
            "--min-netmap-version",
            "12",
            "--force-repin",
        ])
        .expect("server restore");
        assert!(matches!(
            restore.command,
            TopCommand::Admin(AdminCommand::Server(ref srv))
                if matches!(
                    srv.action,
                    ServerSubcommand::Restore(ref r)
                        if r.file == "snap.tar" && r.min_netmap_version == Some(12) && r.force_repin
                )
        ));
    }
}
