# Mesh VPN — Linux Desktop & NAS Service Package (`US-054`)

Systemd desktop deployment assets reusing the `meshd` agent daemon and `mesh` CLI with least-privilege capabilities and non-destructive NetworkManager / `systemd-resolved` / firewall coexistence.

## Guarantees

1. **Minimal Capabilities**: `meshd` runs with `CAP_NET_ADMIN`, `CAP_NET_RAW`, and `CAP_CHOWN` under `NoNewPrivileges=yes` and `ProtectSystem=strict`.
2. **DNS & NetworkManager Preservation**: `/etc/resolv.conf` stays read-only under `ProtectSystem=strict`; only the fenced `# BEGIN mesh managed hosts` ... `# END mesh managed hosts` block in `/etc/hosts` is managed.
3. **Firewall Coexistence (`nftables` / `iptables`)**: Existing user, Docker, or UFW firewall rules are never flushed. When configuring firewall rules, `scripts/install-linux.sh` creates only the isolated `inet mesh_vpn` `nftables` table or dedicated `MESH_VPN` `iptables` chain strictly matching incoming `mesh0` overlay traffic.
4. **Non-root Desktop CLI Access**: Creating the `mesh-admin` group (`usermod -aG mesh-admin <user>`) grants access to `/run/meshd/meshd-admin.sock` (`0660 root:mesh-admin`), while unprivileged users retain read-only access to `mesh status` / `mesh peers` / `mesh ping` via `/run/meshd/meshd-ro.sock` (`0666`).

## Usage

Install or upgrade (from repository root or extracted release archive):

```sh
sudo ./scripts/install-linux.sh --from ./target/release
```

Allow a desktop user to run `mesh up` / `mesh down` without `sudo`:

```sh
sudo usermod -aG mesh-admin "$USER"
```

Uninstall cleanly while preserving node identity (`keys.json`):

```sh
sudo ./scripts/install-linux.sh --uninstall
```

Complete removal including node keys (`keys.json`) and logs:

```sh
sudo ./scripts/install-linux.sh --uninstall --purge
```
