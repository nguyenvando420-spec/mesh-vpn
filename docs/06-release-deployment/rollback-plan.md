# Mesh VPN `0.1.0` — Rollback Plan

**Recovery Target:** `RTO <= 5 min` for Control VPS; clean host isolation via `ResourceLedger` on clients.
**Golden Rule:** Always preserve `/var/lib/mesh/control.redb` (`server_identity`) on VPS and `ResourceLedger` (`ledger.json`) on clients. **Never** run destructive wildcards (`rm -rf /var/lib/mesh`, deleting arbitrary `utun*`, or `--force-repin`) during rollback.

---

## 1. Quantitative Rollback Triggers

Initiate rollback **immediately** if any trigger fires during or within 24 hours after deployment:

| Trigger ID | Condition | Quantitative Threshold | Action |
| --- | --- | --- | --- |
| `RB-01` | Control VPS Readiness Failure | `http://127.0.0.1:9091/readyz` returns non-`200` (e.g., `503`) for `> 60 s` | Roll back `mesh-server` binary (and restore pre-upgrade `.redb` only if schema/DB corrupted) |
| `RB-02` | Server Crash Loop or Panic | `>= 2` unexpected `mesh-server` restarts within `5 min` | Roll back `mesh-server` binary immediately |
| `RB-03` | Mass Client Disconnect / Re-Pin Failure | `> 10%` of previously online nodes fail to reconnect within `5 min` or report SPKI mismatch | Roll back `mesh-server` & verify `server_identity` matches pre-upgrade snapshot |
| `RB-04` | Datapath / Sleep-Wake Regression | Canary `mesh ping` packet loss `> 5%` on direct paths OR wake recovery `P95 > 15 s` | Roll back client `meshd`/`mesh` binary on affected platform |
| `RB-05` | Host Routing Loop / OS State Leak | Default internet route broken (`0.0.0.0/0` hijacked) or `ResourceLedger` fails cleanup | Run `mesh down` / `mesh cleanup` on client and roll back `meshd` |
| `RB-06` | Revocation Persistence Degraded | `mesh node revoke` drops to `tier = ram_only` (`persisted = false`) caused by upgrade regression | **DO NOT restart blindly if Dual-EIO!** Stabilize disk first (Procedure 3 of Runbook), then roll back binary |

---

## 2. VPS (`mesh-server`) Rollback Procedure (`RTO <= 5 min`, Preserves `server_identity`)

### Case A — Binary-Only Rollback (Database Healthy)

Use when the upgraded `mesh-server` binary misbehaves but `control.redb` was not structurally altered:

```bash
# 1. Verify pre-upgrade rollback binaries exist:
ls -l /var/lib/mesh/rollback-bin/mesh-server /var/lib/mesh/rollback-bin/mesh

# 2. Stop service cleanly (flushes redb & closes listeners):
sudo systemctl stop mesh-server

# 3. Restore previous binaries and validate config:
sudo install -m 0755 /var/lib/mesh/rollback-bin/mesh-server /usr/local/bin/mesh-server
sudo install -m 0755 /var/lib/mesh/rollback-bin/mesh /usr/local/bin/mesh
sudo -u mesh /usr/local/bin/mesh-server --config /etc/mesh/server.toml --check-config

# 4. Restart and verify:
sudo systemctl start mesh-server
curl -fsS http://127.0.0.1:9091/healthz
curl -fsS http://127.0.0.1:9091/readyz
mesh server hardening-check
mesh server status
```

### Case B — Full State + Binary Rollback (If `control.redb` Needs Restoration)

Use only if `control.redb` failed integrity, needs restoration on a replacement VPS, or must roll back to the pre-upgrade `mesh server backup` snapshot. Existing clients reconnect with **0 re-registration** and **0 re-pinning** because `server_identity` is restored and `netmap_version_watermark` advances by `+1_000_000`:

#### Path 1 — Cold / Offline Restore (`control.redb` Corrupted or Replacement VPS)

**CRITICAL:** Do **not** run `systemctl start mesh-server` before restoring when `control.redb` is corrupted or absent (starting on a corrupt DB fails before UDS opens; starting on a fresh VPS generates a conflicting `Pin_TEMP`). Keep `mesh-server` stopped and restore offline as `mesh`:

```bash
# 1. Keep mesh-server stopped while swapping binaries (if rolling back binaries):
sudo systemctl stop mesh-server || true
sudo install -m 0755 /var/lib/mesh/rollback-bin/mesh-server /usr/local/bin/mesh-server
sudo install -m 0755 /var/lib/mesh/rollback-bin/mesh /usr/local/bin/mesh

# 2. Place/decrypt BOTH restore.redb and its companion restore.redb.sha256 sidecar,
#    enforce strict mesh:mesh 0600 ownership, and verify checksum:
sudo chown mesh:mesh /var/lib/mesh/backups/restore.redb /var/lib/mesh/backups/restore.redb.sha256
sudo chmod 0600 /var/lib/mesh/backups/restore.redb /var/lib/mesh/backups/restore.redb.sha256
(cd /var/lib/mesh/backups && sudo -u mesh sha256sum -c restore.redb.sha256)

# 3. Execute offline cold restore as user `mesh` (omit --min-netmap-version if unknown):
sudo -u mesh /usr/local/bin/mesh-server \
  --config /etc/mesh/server.toml \
  --restore-from /var/lib/mesh/backups/restore.redb \
  --min-netmap-version <PRIOR_NETMAP_VERSION>

# 4. Start mesh-server cleanly and verify:
sudo systemctl start mesh-server
curl -fsS http://127.0.0.1:9091/readyz
mesh server status
mesh node list
```

#### Path 2 — Hot Restore (Only When `mesh-server` Is Running Healthy With Same Identity)

When `mesh-server` is already running cleanly with `/run/mesh-server/admin.sock` open and the same `server_identity`:

```bash
PRE_BACKUP="/var/lib/mesh/backups/<PRE_UPGRADE_TIMESTAMP>.redb"
(cd /var/lib/mesh/backups && sudo -u mesh sha256sum -c "$(basename "$PRE_BACKUP").sha256")
mesh server restore "$PRE_BACKUP" --min-netmap-version <PRIOR_NETMAP_VERSION>

# Verify readiness and watermark jump:
curl -fsS http://127.0.0.1:9091/readyz
mesh server status
mesh node list
```

> **CRITICAL:** Never pass `--force-repin` or `--skip-sha256` during rollback restore; doing so weakens integrity checks or changes identity guarantees.

---

## 3. Client Rollback Procedure (Preserves `ResourceLedger`)

Always drain/stop the client daemon cleanly so `ResourceLedger` (`ledger.json`) deletes only its own routes, TUN adapter, firewall anchor, and `# BEGIN mesh managed hosts ... # END mesh managed hosts` block:

### 3.1 macOS (`arm64` / `x86_64`)

```bash
# 1. Cleanly tear down tunnel using current daemon (preserves pre-existing utun* & /etc/hosts symlink):
sudo mesh down || sudo mesh cleanup

# 2. Re-install previous verified tarball + SHA256SUMS:
sudo sh scripts/install-macos.sh --from ./prev-dist --sha256-file ./prev-dist/SHA256SUMS

# 3. Verify host cleanliness and daemon status:
sudo bash lab/macos/verify-macos-host.sh
mesh status
```

### 3.2 Windows 10 / 11

```powershell
# 1. Cleanly tear down tunnel and ResourceLedger state (Admin PowerShell):
mesh down
if ($LASTEXITCODE -ne 0) { mesh cleanup }

# 2. Re-install previous verified binaries & wintun.dll SHA-256:
powershell -ExecutionPolicy Bypass -File scripts/install-windows.ps1 `
  -SourceDir .\prev-dist `
  -WintunSha256File .\prev-dist\wintun.dll.sha256

# 3. Verify status as standard user (use full path if C:\Program Files\Mesh is not in system PATH):
& "C:\Program Files\Mesh\mesh.exe" status
& "C:\Program Files\Mesh\mesh.exe" peers
```

### 3.3 Linux Client / Headless VPS-Node

```bash
# 1. Cleanly tear down policy routes (table 51820, ip rule 51810/51820) and nft/iptables chain:
sudo mesh down || sudo mesh cleanup

# 2. Re-install previous verified package:
sudo sh scripts/install-linux.sh --from ./prev-dist --sha256-file ./prev-dist/SHA256SUMS

# 3. Verify:
mesh status
mesh peers
```

---

## 4. Post-Rollback Verification & Incident Follow-Up

1. Confirm `mesh server status` and `curl -fsS http://127.0.0.1:9091/readyz` remain `200 OK` for `>= 10 min`.
2. Confirm online clients re-established direct or relay paths (`mesh peers`, `mesh ping <peer> -c 4`).
3. Collect redacted client diagnostics (`mesh bugreport`) and server logs (`journalctl -u mesh-server --since "30 min ago"`) before filing a post-mortem.
4. Keep `0` temporary files or unencrypted `.redb` snapshots outside `/var/lib/mesh/backups/`.
