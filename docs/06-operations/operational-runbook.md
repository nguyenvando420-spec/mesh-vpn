# Mesh VPN — Operational Runbook (`US-059`)

**Version:** `0.1.0` | **Scope:** Day-0 to Day-2 VPS Control/Relay/STUN & Multi-OS Client Operations
**Target Execution Time:** `<= 30 min` per procedure without guesswork.
**Pre-flight Rule:** All commands below match the compiled binaries (`mesh`, `meshd`, `mesh-server`), `scripts/install-*.{sh,ps1}`, and `deploy/` units in this repository. Never pass raw pre-auth keys on CLI argv (`--authkey` is intentionally disabled per `SEC-01`).

---

## Table of Contents

- [Procedure 1 — VPS Installation & Safe Hardening](#procedure-1--vps-installation--safe-hardening)
- [Procedure 2 — Client Onboarding (macOS, Windows, Headless VPS-node & Linux)](#procedure-2--client-onboarding-macos-windows-headless-vps-node--linux)
- [Procedure 3 — Emergency Stolen/Lost Laptop Revocation (`US-029`, `US-030`)](#procedure-3--emergency-stolenlost-laptop-revocation-us-029-us-030)
- [Procedure 4 — Key Expiry & Rotation (`US-031`, `US-032`)](#procedure-4--key-expiry--rotation-us-031-us-032)
- [Procedure 5 — Hot Atomic `redb` Backup, Encrypted Off-VPS Sync & Restore Drill (`US-045`, `REL-12`)](#procedure-5--hot-atomic-redb-backup-encrypted-off-vps-sync--restore-drill-us-045-rel-12)
- [Procedure 6 — Live Endpoint Migration & Server TLS Key Rotation (`US-074`, `US-047 AC5`, `SEC-15`)](#procedure-6--live-endpoint-migration--server-tls-key-rotation-us-074-us-047-ac5-sec-15)
- [Procedure 7 — Incident Response & Diagnostics (`REL-01`)](#procedure-7--incident-response--diagnostics-rel-01)
- [Known Limitations (`US-059 AC2`)](#known-limitations-us-059-ac2)

---

## Procedure 1 — VPS Installation & Safe Hardening

**Estimated Time:** `15–25 min` | **Target OS:** Linux VPS (`systemd`, non-root `mesh` service user)

### 1.1 Check Port Conflicts Without Breaking Existing Web or Custom SSH

Inspect active TCP/UDP listeners and your active SSH port before choosing ports:

```bash
sudo ss -tulpn | grep -E ':(22|80|443|3478|8443|9091)\b'
sudo ss -tlnp | grep sshd
```

Choose one of two modes:
- **Mode A — Standalone IP + SPKI Pin (Default):** Control/Relay on TCP `443` (or custom TCP `8443` if `443` is already used by an existing web server) + STUN on UDP `3478` (or custom UDP `3479`).
- **Mode B — Reverse Proxy (`nginx` or `caddy`):** Existing web proxy keeps public TCP `443`; `mesh-server` binds `127.0.0.1:8443` with `tls_mode = "reverse_proxy"` and mandatory `trusted_proxies = ["127.0.0.1"]`, plus UDP STUN directly on public port `3478` (or `3479`).

### 1.2 Install `mesh-server` and `mesh` CLI

On the VPS (with built release binaries `./target/release/mesh-server` and `./target/release/mesh`):

```bash
# Option A: Standalone IP+Pin on default ports 443/TCP + 3478/UDP
sudo sh scripts/install-server.sh \
  --public-host <VPS_PUBLIC_IP_OR_DNS> \
  --tcp-port 443 \
  --stun-port 3478 \
  --overlay-cidr 100.115.0.0/16 \
  --binary ./target/release/mesh-server

# Option A (port 443 occupied): Standalone IP+Pin on custom 8443/TCP + 3479/UDP
sudo sh scripts/install-server.sh \
  --public-host <VPS_PUBLIC_IP_OR_DNS> \
  --tcp-port 8443 \
  --stun-port 3479 \
  --overlay-cidr 100.115.0.0/16 \
  --binary ./target/release/mesh-server

# Install the admin CLI and add your operator user to mesh-admin
sudo install -m 0755 ./target/release/mesh /usr/local/bin/mesh
sudo usermod -aG mesh-admin "$USER"
newgrp mesh-admin
```

What `scripts/install-server.sh` creates:
- Service user/group `mesh` and admin socket group `mesh-admin`.
- Config `/etc/mesh/server.toml` (`0640 root:mesh`).
- Systemd unit `/etc/systemd/system/mesh-server.service` (`User=mesh`, `SupplementaryGroups=mesh-admin`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`).
- State directory `/var/lib/mesh` (`0700 mesh:mesh`) storing `control.redb`, pre-allocated `emergency-revocations.bin`, and `backups/`.
- Admin UDS `/run/mesh-server/admin.sock` (`0660 mesh:mesh-admin`, `SO_PEERCRED` enforced).
- Observability listener bound strictly to `127.0.0.1:9091` (`/healthz`, `/readyz`, `/metrics`).

### 1.3 Reverse Proxy Configuration (Mode B Only)

If sharing port `443` behind Caddy (`deploy/reverse-proxy/Caddyfile.example`) or Nginx (`deploy/reverse-proxy/nginx-mesh.conf.example`):

1. Edit `/etc/mesh/server.toml` so `mesh-server` listens only on loopback behind the proxy:
   ```toml
   control_bind_ip = "127.0.0.1"
   control_tcp_port = 8443
   stun_bind_ip = "0.0.0.0"
   stun_udp_port = 3478
   tls_mode = "reverse_proxy"
   trusted_proxies = ["127.0.0.1"]
   ```
   > **CRITICAL:** `trusted_proxies` is mandatory whenever `tls_mode = "reverse_proxy"`. `ServerConfig::validate()` and `mesh server hardening-check` fail closed if `trusted_proxies` is empty or allows wildcard trust.
2. Deploy `deploy/reverse-proxy/Caddyfile.example` or `deploy/reverse-proxy/nginx-mesh.conf.example`, reload the reverse proxy, and validate:
   ```bash
   sudo -u mesh mesh-server --config /etc/mesh/server.toml --check-config
   sudo systemctl restart mesh-server
   ```

### 1.4 Opt-In Firewall With Dry-Run and `60–120 s` Auto-Rollback

> **WARNING:** Never enable a host firewall blindly over SSH. Always preview rules (`dry-run`), detect your live SSH port, and arm a `60–120 s` automatic rollback before applying.

`scripts/install-server.sh --enable-firewall` (alias `--enable-ufw`) enables UFW while preserving the detected SSH port, but for maximum safety on production VPSes run the manual dry-run + timed rollback first:

```bash
# 1. Detect live SSH port (never assume 22)
SSH_PORT=$(sudo ss -tlnp | awk '/sshd/ {sub(/.*:/, "", $4); print $4; exit}')
echo "Detected SSH port: ${SSH_PORT:-22}"

# 2. Dry-run preview (UFW does not modify live kernel tables during --dry-run)
sudo ufw allow "${SSH_PORT:-22}/tcp" comment "mesh-ssh-preserve"
sudo ufw allow 443/tcp comment "mesh-control-relay"   # or 8443/tcp
sudo ufw allow 3478/udp comment "mesh-stun"           # or 3479/udp
sudo ufw --dry-run enable

# 3. Arm a 90-second automatic rollback BEFORE enabling (cancels if you stop the timer)
nohup sh -c 'sleep 90 && [ -f /tmp/mesh-fw-pending ] && ufw disable && rm -f /tmp/mesh-fw-pending' \
  >/dev/null 2>&1 &
ROLLBACK_PID=$!
touch /tmp/mesh-fw-pending

# 4. Enable firewall and test a NEW SSH session in another terminal within 90 s
sudo ufw --force enable

# 5. Once the new SSH session succeeds, confirm and disarm rollback:
rm -f /tmp/mesh-fw-pending && kill "$ROLLBACK_PID" 2>/dev/null || true
sudo ufw status verbose
```

### 1.5 Cloud Security Group Manual Reminder

Host firewalls (`ufw`/`nftables`) do **not** open upstream cloud provider firewalls. Manually verify your provider Security Group / Cloud Firewall (AWS EC2, Hetzner, DigitalOcean, GCP, Vultr, etc.) allows:
- **Inbound TCP:** `443` (or your custom `control_tcp_port`, e.g., `8443`) from `0.0.0.0/0` (and `::/0` if dual-stack).
- **Inbound UDP:** `3478` (or your custom `stun_udp_port`, e.g., `3479`) from `0.0.0.0/0`.
- **Keep CLOSED externally:** `9091/tcp` (metrics/healthz must stay `127.0.0.1` only) and never expose any admin socket over TCP (`SEC-14`).

### 1.6 Post-Install Verification & SPKI Pin Extraction

```bash
mesh server hardening-check
mesh server status
curl -fsS http://127.0.0.1:9091/healthz
curl -fsS http://127.0.0.1:9091/readyz
```

Record the `server_pin` (`sha256:<64hex>`) and `public_host` printed by `mesh server status` (or `/etc/mesh/server.toml` + cert SPKI) for client onboarding in Procedure 2.

---

## Procedure 2 — Client Onboarding (macOS, Windows, Headless VPS-node & Linux)

**Estimated Time:** `10–20 min` per node

### 2.1 Issue a Single-Use Pre-Auth Key on the VPS

Run as an operator in `mesh-admin` on the VPS (default TTL `1h`, bound optionally to a target node name):

```bash
mesh preauthkey create --ttl 1h --for alice-mbp
# Transfer the generated key to the target device via an encrypted channel (password manager / SCP)
# and save it to a mode-0600 file; NEVER pass the key directly as a CLI argument.
```

### 2.2 macOS 13+ (`aarch64-apple-darwin` & `x86_64-apple-darwin`)

> **SECURITY RULE:** Never run `spctl --master-disable` on any Mac. `scripts/install-macos.sh` performs a browser-free SHA-256 checksum verification, clears quarantine only on verified binaries, and ad-hoc signs them locally (`codesign --force -s -`).

1. Place `meshd`, `mesh`, and `SHA256SUMS` in `./dist/` (or build output), verify checksums, and install as `root`:
   ```bash
   sudo sh scripts/install-macos.sh --from ./dist --sha256-file ./dist/SHA256SUMS --yes-firewall
   ```
   Use `--no-firewall` to skip optional macOS firewall rules.
   Installed layout verified by `install-macos.sh`:
   - Binaries: `/usr/local/libexec/mesh/meshd` and `/usr/local/bin/mesh`
   - Daemon plist: `/Library/LaunchDaemons/internal.mesh.meshd.plist` (`root:wheel 0644`, label `internal.mesh.meshd`)
   - State/run/log dirs: `/var/db/mesh` (`0700 root:wheel`), `/var/run/meshd` (`0755 root:wheel`), `/var/log/mesh/meshd.log`
   - Dual IPC sockets: admin `/var/run/meshd/meshd-admin.sock` (`0660 root:admin`) and read-only `/var/run/meshd/meshd-ro.sock` (`0666`)
   - Opt-in firewall: `/usr/libexec/ApplicationFirewall/socketfilterfw` + `pf` anchor `com.internal.mesh`
2. Store the pre-auth key in a `0600` file (e.g., `/tmp/mesh.key`, deleted immediately after join) and enroll with mandatory Zero-TOFU SPKI pin:
   ```bash
   install -m 0600 /dev/null /tmp/mesh.key
   printf '%s\n' '<PREAUTH_KEY>' > /tmp/mesh.key
   sudo mesh up \
     --server <VPS_IP_OR_HOST>:<TCP_PORT> \
     --server-pin sha256:<64HEX> \
     --authkey-file /tmp/mesh.key \
     --name alice-mbp
   rm -f /tmp/mesh.key
   ```
3. Verify unprivileged read-only commands work without `sudo`:
   ```bash
   mesh status
   mesh peers
   mesh netcheck
   ```

### 2.3 Windows 10 / 11 (`x86_64-pc-windows-msvc`)

1. Open an **Administrator PowerShell** session. Ensure `meshd.exe`, `mesh.exe`, `wintun.dll`, `WINTUN-LICENSE.txt`, and `wintun.dll.sha256` are in `.\dist\`:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/install-windows.ps1 `
     -SourceDir .\dist `
     -WintunSha256File .\dist\wintun.dll.sha256
   ```
   What `install-windows.ps1` sets up:
   - Verifies SHA-256 of `wintun.dll` before installing into `C:\Program Files\Mesh\` (`LOAD_LIBRARY_SEARCH_APPLICATION_DIR` enforces strict pin at runtime).
   - Creates `C:\ProgramData\Mesh\` with restricted ACL `D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)` (`SYSTEM` + `Administrators` only).
   - Registers & starts Windows Service `MeshVpnAgent` (`LocalSystem`, auto-start, `sc.exe failure` restart `5000`/`10000` ms) exposing:
     - Admin Named Pipe: `\\.\pipe\mesh-agent-admin` (`SY` + `BA`)
     - Read-Only Named Pipe: `\\.\pipe\mesh-agent-ro` (non-admin `mesh status`, `mesh peers`, `mesh ping`, `mesh netcheck`)
   - Adds Windows Firewall rule `MeshVPN-Overlay-Inbound` for adapter `MeshVPN`.
2. Write the pre-auth key to a protected file and join (from Administrator PowerShell):
   ```powershell
   Set-Content -Path C:\ProgramData\Mesh\join.key -Value '<PREAUTH_KEY>' -NoNewline
   & "C:\Program Files\Mesh\mesh.exe" up `
     --server <VPS_IP_OR_HOST>:<TCP_PORT> `
     --server-pin sha256:<64HEX> `
     --authkey-file C:\ProgramData\Mesh\join.key `
     --name win-laptop
   Remove-Item C:\ProgramData\Mesh\join.key -Force
   ```
3. Verify in a **standard (non-admin)** PowerShell window (if `C:\Program Files\Mesh` is not in system `PATH`, invoke `& "C:\Program Files\Mesh\mesh.exe"` directly):
   ```powershell
   & "C:\Program Files\Mesh\mesh.exe" status
   & "C:\Program Files\Mesh\mesh.exe" peers
   & "C:\Program Files\Mesh\mesh.exe" netcheck
   ```

### 2.4 Headless Linux / VPS-Node (`vps.mesh.internal`) & Linux Desktop

1. On the Linux target (server or desktop), install `meshd` + `mesh`:
   ```bash
   # Server / headless VPS-node (uses deploy/systemd/meshd.service):
   sudo sh scripts/install-linux.sh --from ./dist --sha256-file ./dist/SHA256SUMS

   # Linux desktop (optional desktop unit deploy/linux-desktop/meshd-desktop.service):
   sudo sh scripts/install-linux.sh --from ./dist --unit deploy/linux-desktop/meshd-desktop.service
   ```
   Installed layout: `/usr/bin/meshd`, `/usr/bin/mesh`, `/etc/systemd/system/meshd.service`, `/var/lib/meshd` (`0700 root:root`), `/run/meshd/meshd-admin.sock`, `/run/meshd/meshd-ro.sock`. Linux policy routing binds overlay traffic cleanly (`SO_MARK = 0x5d56` / `table 51820` / `ip rule` priorities `51810` and `51820`) and opens `mesh0` via `nftables` (`inet mesh_vpn`) or `iptables` (`MESH_VPN`).
2. Enroll via `--authkey-stdin` (no temp file needed on Linux):
   ```bash
   printf '%s\n' '<PREAUTH_KEY>' | sudo mesh up \
     --server <VPS_IP_OR_HOST>:<TCP_PORT> \
     --server-pin sha256:<64HEX> \
     --authkey-stdin \
     --name vps
   ```
3. For unattended headless VPS/NAS nodes, exempt the node key from 180-day expiration on the Control VPS (see Procedure 4):
   ```bash
   mesh node expire vps --never
   ```

> **Reverse Proxy / Public ACME TLS Only:** Replace `--server-pin sha256:<64HEX>` with `--ca-tls` only when the server is fronted by a publicly trusted ACME/CA certificate (`tls_mode = "acme"` or `"reverse_proxy"`). Zero-TOFU remains enforced in all modes.

---

## Procedure 3 — Emergency Stolen/Lost Laptop Revocation (`US-029`, `US-030`)

**Estimated Time:** `< 5 min` (live cut `< 100 ms` Control RAM, `<= 2 s` connected peers)

### 3.1 Immediate Revocation on VPS Control

Run from an operator account in `mesh-admin` (communicates exclusively over `/run/mesh-server/admin.sock`):

```bash
mesh node revoke <LOST_NODE_NAME_OR_ID>
mesh node inspect <LOST_NODE_NAME_OR_ID>
mesh audit list --limit 10
```

Expected normal output:
- `ram_enforced = true`, `persisted = true`, `tier = redb`.
- Control immediately drops the stolen node's stream/relay sessions (`< 100 ms`), increments `netmap_version`, pushes updated netmap causing active peers to drop the WireGuard peer within `<= 2 s`, and quarantines the node's overlay IP for **24 hours** against reuse.

### 3.2 Handling VPS `ENOSPC` (`tier=emergency_slot`) or Dual-`EIO` (`tier=ram_only`)

`mesh-server` pre-allocates a 64 KiB A/B file `/var/lib/mesh/emergency-revocations.bin` so revocations succeed even when `control.redb` hits `ENOSPC`:

1. **If `mesh node revoke` reports `tier = emergency_slot` (and `/readyz` returns HTTP `503`):**
   - The revocation **succeeded and is crash-safe** in `emergency-revocations.bin`, while `control.redb` could not commit due to disk full (`ENOSPC`).
   - Do **not** skip recovery: free disk space immediately (never delete `/var/lib/mesh/control.redb`, `emergency-revocations.bin`, or recent `backups/`):
     ```bash
     df -h /var/lib/mesh /var/log
     sudo journalctl --vacuum-time=3d
     ```
   - Trigger compaction once space is freed by creating a backup or issuing a harmless admin write, then verify `/readyz` returns `200 OK`:
     ```bash
     mesh server backup
     curl -fsS http://127.0.0.1:9091/readyz
     ```

2. **If `mesh node revoke` prints `URGENT WARNING` with `tier = ram_only` and `persisted = false` (Dual-`EIO`):**
   - Both `control.redb` and `emergency-revocations.bin` failed I/O (`EIO` / severe filesystem failure).
   - **CRITICAL: DO NOT RESTART `mesh-server`!** Restarting while `persisted = false` wipes the RAM-only revocation block and would allow the stolen laptop back on restart.
   - Revocation **is active in RAM right now** (`ram_enforced = true`); peers and relay are severed.
   - Keep `mesh-server` running while fixing the underlying disk/volume issue (`dmesg -T`, `df -h`, remount/free space).
   - Once the filesystem is writable again, re-run `mesh node revoke <LOST_NODE_NAME_OR_ID>` and `mesh server backup` until `persisted = true` and `tier = redb`, and verify `curl -fsS http://127.0.0.1:9091/readyz` succeeds before ever restarting `mesh-server`.

---

## Procedure 4 — Key Expiry & Rotation (`US-031`, `US-032`)

**Estimated Time:** `5–10 min`

### 4.1 Check Expiring Nodes and Set Exemptions (`--never`)

Nodes expire after **180 days** by default (`NodeKeyExpiring` alert fires before expiry):

```bash
mesh node list
mesh node inspect <NODE_NAME>

# Exempt unattended servers / NAS / VPS nodes from 180-day expiry:
mesh node expire <NODE_NAME> --never

# Restore default 180-day expiry policy on a node:
mesh node expire <NODE_NAME>
```

### 4.2 Rotate a Node's Key Without Losing Its Overlay IP

1. On the VPS (`mesh-admin`), mint a single-use renewal key bound strictly to that node:
   ```bash
   mesh preauthkey create --for <NODE_NAME> --ttl 1h
   ```
2. On the client device, put the renewal key in a protected file (or stdin on Unix) and rotate:
   ```bash
   # Linux / macOS:
   printf '%s\n' '<RENEWAL_KEY>' | sudo mesh rotate-key --authkey-stdin

   # Windows (Admin PowerShell):
   Set-Content -Path C:\ProgramData\Mesh\renew.key -Value '<RENEWAL_KEY>' -NoNewline
   & "C:\Program Files\Mesh\mesh.exe" rotate-key --authkey-file C:\ProgramData\Mesh\renew.key
   Remove-Item C:\ProgramData\Mesh\renew.key -Force
   ```
3. Verify new key validity and unchanged overlay IP:
   ```bash
   mesh status
   ```

---

## Procedure 5 — Hot Atomic `redb` Backup, Encrypted Off-VPS Sync & Restore Drill (`US-045`, `REL-12`)

**Estimated Time:** `10–20 min` | **Recovery Time Objective (RTO):** `<= 5 min`

> **SECURITY WARNING — NEVER COPY UNENCRYPTED `.redb` BACKUPS OFF-VPS:**
> Every `control.redb` snapshot contains `server_identity` (the Control server's private identity key) and node metadata. Always encrypt before transferring off the VPS.

### 5.1 Run an On-VPS Hot Atomic Backup

```bash
mesh server backup
ls -la /var/lib/mesh/backups/
```

Expected result:
- Creates `/var/lib/mesh/backups/control-<unix_ms>.redb` and `.sha256` (`0600 mesh:mesh`), verified atomically without stopping `mesh-server`.
- Automatically retains the newest **7** backups on disk.

### 5.2 Encrypted Off-VPS Sync Recipes

Pick **one** encrypted off-site mechanism via cron/systemd timer after `mesh server backup`:

- **Option A — `age` + `scp`/`rsync` (minimal dependency):**
  ```bash
  LATEST=$(ls -1t /var/lib/mesh/backups/*.redb | head -n1)
  sha256sum -c "${LATEST}.sha256"
  age -r "age1<YOUR_PUBLIC_RECIPIENT_KEY>" -o "${LATEST}.age" "$LATEST"
  scp "${LATEST}.age" "${LATEST}.sha256" backup-host:/srv/mesh-backups/
  shred -u "${LATEST}.age"
  ```
- **Option B — `restic` (client-side AES-256 + deduplication):**
  ```bash
  export RESTIC_REPOSITORY="sftp:backup-host:/srv/restic-mesh"
  export RESTIC_PASSWORD_FILE="/etc/mesh/restic.pass"   # chmod 0600 root:root
  restic backup /var/lib/mesh/backups/
  ```
- **Option C — `rclone crypt` (encrypted remote object storage):**
  ```bash
  rclone sync /var/lib/mesh/backups/ mesh-crypt:mesh-control-backups/
  ```

### 5.3 Restore Drill (Proving `0` Re-Registration & `0` Re-Pinning, `RTO <= 5 min`)

Execute periodically on staging (or during disaster recovery on a replacement VPS):

```bash
# 1. If encrypted off-VPS, decrypt locally into /var/lib/mesh/backups/ and verify checksum:
age -d -i /root/backup-identity.key -o /var/lib/mesh/backups/restore.redb restore.redb.age
sha256sum /var/lib/mesh/backups/restore.redb   # Compare with recorded .sha256

# 2. Ensure mesh-server is RUNNING (`mesh server restore` sends POST /v1/admin/restore over /run/mesh-server/admin.sock):
#    Running `mesh-server` hot-restores control.redb, reloads ACME/server identity, drops live streams to force clean re-auth,
#    and advances netmap_version_watermark (+1,000,000).
sudo systemctl start mesh-server
mesh server restore /var/lib/mesh/backups/restore.redb

# 3. Optionally restart cleanly after restore and validate RTO + watermark jump:
sudo systemctl restart mesh-server
mesh server status
mesh node list
curl -fsS http://127.0.0.1:9091/readyz
```

If restoring an older snapshot when you know the minimum prior `netmap_version`, pass `--min-netmap-version <N>` to guarantee monotonic watermark advancement.
**Success Criteria (`US-045`):**
- Existing clients reconnect automatically with **0 re-registration** and **0 re-pinning** (`server_identity` and `server_pin` remain identical).
- Do **not** pass `--force-repin` or `--skip-sha256` in routine drills (those flags exist only for emergency corrupted/identity-lost recovery).

---

## Procedure 6 — Live Endpoint Migration & Server TLS Key Rotation (`US-074`, `US-047 AC5`, `SEC-15`)

**Estimated Time:** `10–20 min` (plus optional multi-day rotation grace window)

### 6.1 Live Endpoint Migration (`ip_pinned` / Port / Host / TLS Mode Change)

When moving the Control/Relay VPS IP, changing ports, or switching `tls_mode`, keep old and new listeners running simultaneously during the grace window (`DEFAULT = 300 s`, max `86400 s`):

```bash
mesh server migrate-endpoint \
  --host <NEW_IP_OR_HOST> \
  --tcp-port <NEW_TCP_PORT> \
  --stun-port <NEW_STUN_PORT> \
  --tls-mode ip_pinned \
  --transition-window-secs 600
```

- Online nodes receive the migration directive and switch seamlessly before the old listener shuts down.
- If online nodes still need extra time before cutoff, extend dynamically:
  ```bash
  mesh server migrate-endpoint --extend-window 600
  ```
- Inspect which nodes have updated vs remained offline:
  ```bash
  mesh node list
  mesh server status
  ```
- Any node that remained offline past the grace window must be updated locally with its admin socket/pipe:
  ```bash
  # On the offline client (macOS/Linux sudo, Windows Admin PowerShell):
  mesh set --server <NEW_IP_OR_HOST>:<NEW_TCP_PORT> --server-pin sha256:<HEX>
  ```

### 6.2 Zero-Downtime Server TLS Key Rotation (`SEC-15`, 7-Day Grace Window)

Never swap the SPKI certificate in one step on `ip_pinned` deployments without staging `next_pin`, or offline clients will be locked out:

```bash
# Step 1: Stage the new certificate key (publishes active_pin + next_pin for 7 days)
mesh server rotate-tls-key --stage
mesh server status

# Step 2: Monitor online peers acknowledging next_pin via control netmap updates
mesh node list

# Step 3: For any laptop that stays offline > 7 days, update its pin locally:
#   mesh set --server <VPS_IP:PORT> --server-pin sha256:<NEW_PIN_HEX>

# Step 4: Promote next_pin -> active_pin once online fleet has received next_pin
mesh server rotate-tls-key --promote
mesh server status
```

---

## Procedure 7 — Incident Response & Diagnostics (`REL-01`)

**Estimated Time:** `5–15 min`

### 7.1 Control Plane Outage (`REL-01`)

If the VPS Control server goes offline:
- **Expected behavior:** Existing P2P WireGuard/Disco tunnels between online clients **keep passing traffic** using cached peer endpoints.
- Verify on clients:
  ```bash
  mesh status
  mesh peers
  mesh ping <PEER_NAME_OR_OVERLAY_IP> -c 4 --direct
  ```
- **Do not** run `mesh down` or `mesh cleanup` on healthy clients during a Control outage unless explicitly decommissioning, as `mesh up` cannot register fresh sessions until Control returns (`ExponentialBackoff` retries automatically up to a 5-minute cap).

### 7.2 Safe Binary Upgrade / Rollback Without Stranding OS State

Before upgrading `mesh-server` or `meshd`:
1. Take a hot backup on VPS: `mesh server backup`.
2. Upgrade server binary (`install -m 0755 ...` + `systemctl restart mesh-server`) and check `curl -fsS http://127.0.0.1:9091/readyz` + `mesh server hardening-check`.
3. On clients, `meshd` performs graceful shutdown (`<= 5 s`) cleaning up routes, `hosts` block (`# BEGIN mesh managed hosts ... # END mesh managed hosts`), and TUN state strictly via `ResourceLedger`. If a client crashed ungracefully (`SIGKILL`), recover OS networking cleanly using:
   ```bash
   sudo mesh cleanup   # or Administrator PowerShell on Windows
   ```

### 7.3 Diagnostic Command Matrix (0 Secrets Exposed)

| Check | Command | Privilege | What It Confirms |
| --- | --- | --- | --- |
| Agent state | `mesh status` (`--json`) | Non-admin (RO IPC) | Control link, overlay IP, daemon health, key expiry |
| Peer datapath | `mesh peers` (`--json`) | Non-admin (RO IPC) | Direct vs Relay path, last handshake, RX/TX bytes |
| End-to-end ping | `mesh ping <peer> -c 4 [--direct]` | Non-admin (RO IPC) | Overlay RTT, packet loss, P2P vs relay hop |
| NAT / STUN probe | `mesh netcheck` | Non-admin (RO IPC) | UDP/STUN reachability, NAT mapping type |
| Support bundle | `mesh bugreport` | Admin IPC | Redacted diagnostics (`0` private keys / authkeys) |
| Server health | `curl -fsS http://127.0.0.1:9091/readyz` | VPS localhost | DB integrity, emergency slot clean, listeners healthy |
| Server metrics | `curl -fsS http://127.0.0.1:9091/metrics` | VPS localhost | Active streams, relay bytes/drops, STUN PPS, disk % |
| Audit log | `mesh audit list --limit 50` | `mesh-admin` | Admin revocations, key issuances, rotations |

---

## Known Limitations (`US-059 AC2`)

Operators and stakeholders must acknowledge these 10 architectural and MVP boundaries before Go-Live:

1. **Control-Offline Revocation:** `mesh node revoke` cannot propagate to peers while the VPS Control server is unreachable; cached peer tunnels remain active until Control recovers or peer key lifetimes expire (`REL-01` trade-off).
2. **Symmetric / Hard-NAT <-> Hard-NAT Fallback:** When both peers sit behind symmetric/address-dependent NATs with UDP blocked or non-deterministic port allocation, direct hole-punching cannot succeed and traffic deterministically flows over the VPS Blind Relay (throughput capped per-peer, default `2.5 MB/s` / `20 Mbps`).
3. **VPS Root of Trust:** In Control/Relay topology, the VPS operator controls node membership, key issuance, netmap distribution, and IP allocation. Although WireGuard payload is end-to-end encrypted between peers, compromising the VPS compromises network admission (`Control` trust boundary).
4. **Single-IP STUN Classification Limit:** Because the MVP deploys one VPS public IP with one STUN UDP socket (`3478` default), STUN detects external mapped IP:port and hairpins/mapping reachability, not full RFC 5780 multi-IP NAT mapping-behavior classification.
5. **Non-443 TCP Blocked on Strict Port-80/443 Networks:** If an existing web server occupies port `443` and you run standalone Control on a custom port (e.g., `8443/tcp`), strict corporate or hotel firewalls permitting only TCP `80`/`443` will block Control unless you use **Reverse Proxy mode** (`deploy/reverse-proxy/`) on port `443`.
6. **UDP-Blocked Networks Lose P2P Only:** Captive/enterprise networks that block all outbound UDP force clients onto TCP-framed Blind Relay over the Control TLS connection; connectivity continues, with higher latency and relay bandwidth capping.
7. **macOS MVP Browser-Free SHA-256 Install (No Apple Notarized `.pkg` Yet):** Phase 1 ships unsigned/ad-hoc signed `meshd` + `mesh` installed via `scripts/install-macos.sh` with mandatory SHA-256 verification. Signed & Apple-notarized `.pkg` + System Extension / NetworkExtension distribution is deferred to Phase 2+.
8. **macOS Application Firewall Opt-In Impact on P2P:** Enabling macOS `socketfilterfw` (`--yes-firewall`) restricts unsolicited inbound UDP until `meshd` is allowed; strict stealth/PF rules on managed Macs can push some peers toward Blind Relay unless UDP traversal is permitted.
9. **Lost `server_identity` Key Forces Manual Client Re-Pin:** If both `/var/lib/mesh/control.redb` and every encrypted backup containing `server_identity` are permanently lost, a newly initialized VPS generates a new SPKI pin; **every client must manually re-pin** via `mesh set --server ... --server-pin sha256:<new>` (Zero-TOFU intentionally refuses silent pin changes).
10. **Cloud Security Groups Must Be Opened Manually:** `scripts/install-server.sh` and `scripts/install-linux.sh` configure only local host rules (`ufw`/`nftables`/`iptables`). Operators must manually open TCP Control and UDP STUN ports in their cloud provider Security Group / VPC firewall.
