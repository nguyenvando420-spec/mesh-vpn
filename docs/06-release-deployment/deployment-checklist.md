# Mesh VPN `0.1.0` — Deployment Checklist

**Target:** Production VPS (`mesh-server`) & Multi-OS Client Fleet (`meshd`, `mesh`)
**Post-Deployment Smoke Target:** `<= 15 min`

---

## 1. Pre-Deployment Checklist (Before Touching Production)

- [ ] **CI & Gates Green:** `static-and-lab-lint`, `check-linux`, `check-macos`, `check-windows`, and `release-build-matrix` passed on target release commit; SLO fail-closed gates verified.
- [ ] **Checksums Verified:** Download `SHA256SUMS` (and `wintun.dll.sha256` for Windows) and verify all target binaries locally (`sha256sum -c SHA256SUMS` / `Get-FileHash`).
- [ ] **Go-Live & Hardware Sign-Off:** Confirm `docs/06-operations/go-live-checklist.md` (20/20) and `docs/06-operations/hardware-sleep-wake-protocol.md` are signed for the release candidate.
- [ ] **VPS Pre-Upgrade Hot Backup (`US-045`):**
  ```bash
  mesh server backup
  ls -lt /var/lib/mesh/backups/ | head -n 4
  ```
- [ ] **Encrypted Off-VPS Sync Complete:** Sync the newest `.redb` + `.sha256` off-VPS via `age`/`restic`/`rclone crypt` (never unencrypted!).
- [ ] **Save Known-Good Previous Binaries:** Copy current `/usr/local/bin/mesh-server` and `/usr/local/bin/mesh` to `/var/lib/mesh/rollback-bin/` (mode `0755`, owned `root:root`) for instant rollback.
- [ ] **Cloud Security Group & SSH Safety Confirmed:** Verify live SSH port (`ss -tlnp | grep sshd`), Cloud Security Group (`443/tcp` or custom TCP, `3478/udp` or custom STUN UDP), and keep loopback obs (`127.0.0.1:9091`) private.

---

## 2. During Deployment — VPS (`mesh-server`)

- [ ] **Check Configuration Compatibility:**
  ```bash
  sudo -u mesh ./mesh-server --config /etc/mesh/server.toml --check-config
  ```
- [ ] **Deploy New Binaries & Restart Service:**
  ```bash
  sudo install -m 0755 ./mesh-server /usr/local/bin/mesh-server
  sudo install -m 0755 ./mesh /usr/local/bin/mesh
  sudo systemctl restart mesh-server
  sudo systemctl status mesh-server --no-pager
  ```
- [ ] **If Reverse Proxy Mode (`nginx`/`caddy`):** Confirm `/etc/mesh/server.toml` still defines `tls_mode = "reverse_proxy"`, `control_bind_ip = "127.0.0.1"`, and non-empty `trusted_proxies`.
- [ ] **Run VPS Hardening & Readiness Checks:**
  ```bash
  mesh server hardening-check
  mesh server status
  curl -fsS http://127.0.0.1:9091/healthz
  curl -fsS http://127.0.0.1:9091/readyz
  ```

---

## 3. During Deployment — Canary Clients

- [ ] **macOS (`arm64` / `x86_64`):**
  ```bash
  sudo sh scripts/install-macos.sh --from ./dist --sha256-file ./dist/SHA256SUMS
  ```
- [ ] **Windows 10/11 (Admin PowerShell):**
  ```powershell
  powershell -ExecutionPolicy Bypass -File scripts/install-windows.ps1 `
    -SourceDir .\dist `
    -WintunSha256File .\dist\wintun.dll.sha256
  ```
- [ ] **Linux Headless (`vps.mesh.internal`) / Desktop:**
  ```bash
  sudo sh scripts/install-linux.sh --from ./dist --sha256-file ./dist/SHA256SUMS
  ```

---

## 4. Post-Deployment `<= 15 min` Smoke Test

Complete all checks within `15 minutes` of VPS restart; trigger `docs/06-release-deployment/rollback-plan.md` if any item fails past threshold:

| Minute | Check | Exact Command | Expected Pass Condition | Status |
| --- | --- | --- | --- | --- |
| `T+1 min` | VPS Liveness & Readiness | `curl -fsS http://127.0.0.1:9091/healthz && curl -fsS http://127.0.0.1:9091/readyz` | HTTP `200 OK` on both; `disk_degraded = false` | `[ ]` |
| `T+2 min` | VPS Security Self-Audit | `mesh server hardening-check` | All checks (`tls_13_only`, `obs_loopback_only`, `reverse_proxy_trust`, `storage_integrity`, `non_root_uid`) PASS | `[ ]` |
| `T+4 min` | Fleet Reconnection | `mesh node list` | Pre-existing nodes reconnect automatically with `0` re-registration and `0` re-pinning | `[ ]` |
| `T+6 min` | Canary Non-Admin Read IPC | `mesh status && mesh peers && mesh netcheck` (standard user) | Agent connected; peers visible; STUN mapped IP:port resolved | `[ ]` |
| `T+8 min` | P2P & Relay Datapath | `mesh ping <CANARY_PEER> -c 4` | `0%` packet loss; expected `direct` (or `relay` behind symmetric NAT) | `[ ]` |
| `T+10 min` | Live Revocation Drill (test node) | `mesh node revoke <SMOKE_TEST_NODE>` | `ram_enforced = true`, `persisted = true`, `tier = redb`; peer cut `<= 2 s` | `[ ]` |
| `T+12 min` | Resource & Metrics Check | `curl -fsS http://127.0.0.1:9091/metrics` | Memory & relay drop counters nominal; no panic or restart loops (`journalctl -u mesh-server -n 50`) | `[ ]` |
| `T+15 min` | Post-Deploy Clean Audit | `mesh audit list --limit 20` | Deployment actions & smoke revocation recorded accurately | `[ ]` |
