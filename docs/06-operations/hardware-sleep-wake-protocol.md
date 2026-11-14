# Real Hardware Sleep/Wake, Boot & Roaming Verification Protocol (`US-035`, `US-036 AC2`, `US-057 AC5`, `PERF-07`)

**Version:** `0.1.0` | **Status:** Pre-Go-Live Manual Hardware Sign-Off Required
**Rule:** Automated lab/CI results validate code paths on virtualized runners and Docker NAT namespaces, **not** physical Wi-Fi drivers, macOS DarkWake/AppNap power states, or Windows Modern Standby. Operators MUST execute this protocol on physical hardware and record real observed timings in the sign-off ledger below before Go-Live. **Never fabricate or pre-fill hardware measurements.**

---

## 1. Automated Baseline vs. Real Hardware Scope

| Validation Layer | Where It Runs | What It Proves | Gate / Reference |
| --- | --- | --- | --- |
| Automated Sleep/Wake & Roam Simulation | CI / Docker Lab (`20` automated rounds via `scripts/run-slo-suite.sh` / `.ps1`) | `ScdynamicStore`/Netlink interface change handlers, socket rebind, WireGuard re-handshake `P95 <= 15 s`, `0` leaked `utun`/routes | `docs/05-quality-assurance/slo-verification-report.md` |
| macOS Host Script Dry-Run | CI `check-macos` (`bash lab/macos/verify-macos-host.sh --ci-dry-run`) | Script syntax, `launchd` plist structure, expected privilege/path checks | `.github/workflows/ci.yml` |
| Real Hardware Verification (This Document) | Physical MacBooks (Apple Silicon + Intel) & Windows 10/11 Laptops | Real `>= 4 min` lid-close DarkWake/Modern Standby recovery (`2–3` trials per device, `P95 <= 15 s`), pre-login boot, concurrent VPN `utun` isolation, Wi-Fi -> 4G hotspot roaming | Operator Sign-Off Ledger (§6) |

---

## 2. Target Hardware Matrix

Execute on at least one device from each platform family prior to `0.1.0` Go-Live:
1. **macOS Apple Silicon (`aarch64-apple-darwin`):** macOS 13+ (Ventura/Sonoma/Sequoia) MacBook Air/Pro.
2. **macOS Intel (`x86_64-apple-darwin`):** macOS 13+ Intel MacBook (if Intel Macs remain in fleet).
3. **Windows 10 / Windows 11 (`x86_64-pc-windows-msvc`):** Physical laptop supporting Modern Standby (S0ix) or S3 sleep, with `MeshVpnAgent` + `wintun.dll`.

---

## 3. Pre-Flight Setup on Each Test Laptop

1. Ensure `meshd` is installed via the production installer:
   - macOS: `sudo sh scripts/install-macos.sh --from ./dist --sha256-file ./dist/SHA256SUMS`
   - Windows (Admin PowerShell): `powershell -ExecutionPolicy Bypass -File scripts/install-windows.ps1 -SourceDir .\dist -WintunSha256File .\dist\wintun.dll.sha256`
   - **Note for local Windows builds (`cargo build --release`):** CI release artifacts pre-bake `MESH_WINTUN_SHA256`, whereas local Windows source builds MUST export `$env:MESH_WINTUN_SHA256 = (Get-FileHash .\dist\wintun.dll -Algorithm SHA256).Hash.ToLowerInvariant()` prior to `cargo build --release` (otherwise `mesh up` rejects `wintun.dll` fail-closed at runtime).
2. Join the test mesh with an active reachable peer (e.g., `vps.mesh.internal` or another online peer):
   ```bash
   mesh status
   mesh peers
   mesh ping vps -c 4
   ```
3. On macOS, run the automated host verification helper before and after hardware checks:
   ```bash
   sudo bash lab/macos/verify-macos-host.sh
   ```

---

## 4. Test Cases (Execute in Order)

### Test H1 — Pre-Login Daemon Boot Check (`US-036 AC2`)

Verify the daemon comes online as a system service **before** any desktop user logs in:

- **macOS:**
  1. Confirm `/Library/LaunchDaemons/internal.mesh.meshd.plist` is owned by `root:wheel` (`0644`) with `RunAtLoad = true` and `KeepAlive = true`, and `/usr/local/libexec/mesh/meshd` is non-world-writable (`mode & 0o022 == 0`).
  2. Reboot the MacBook and **wait 45 seconds at the FileVault/macOS login screen** without logging in.
  3. From another mesh node (`vps`), run:
     ```bash
     mesh ping <MAC_NODE_NAME> -c 4
     ```
  4. Log in to macOS and confirm `mesh status` works as a non-admin user via `/var/run/meshd/meshd-ro.sock`.
- **Windows:**
  1. Confirm service `MeshVpnAgent` (`LocalSystem`, `AUTO_START`) is running (`sc.exe query MeshVpnAgent`).
  2. Reboot and wait 45 seconds at the Windows lock/login screen without signing in.
  3. From `vps`, run `mesh ping <WIN_NODE_NAME> -c 4`.
  4. Sign in as a **standard (non-admin)** Windows user and verify `mesh status` succeeds via `\\.\pipe\mesh-agent-ro`.
- **Pass Criteria:** Remote `mesh ping` succeeds while laptop sits at OS login screen; non-admin `mesh status` works after sign-in.

### Test H2 — iCloud Private Relay & Concurrent VPN `utun` / Adapter Isolation (`PLAT-06`, `US-035`)

Verify `meshd` neither hijacks nor is disrupted by OS privacy tunnels or corporate VPNs, and honors `ResourceLedger`:

1. Record existing interfaces before starting or while toggling concurrent VPN/Private Relay:
   - macOS: `ifconfig -l`, `netstat -rn -f inet`, enable iCloud Private Relay (if available) or a secondary WireGuard/OpenVPN tunnel (`utunX`).
   - Windows: `Get-NetAdapter`, `route print -4`, optionally connect a secondary corporate VPN adapter alongside `MeshVPN`.
2. Verify `meshd` allocates its own tunnel interface without touching unrelated `utun*` or non-`MeshVPN` adapters, and routes **only** the mesh overlay CIDR (`100.115.0.0/16` default).
3. Run `sudo mesh down` (or `mesh down` in Admin PowerShell), then re-inspect interfaces and `hosts`:
   - Confirm only the `mesh`-recorded adapter and `# BEGIN mesh managed hosts ... # END mesh managed hosts` block were removed; pre-existing `utun*` / corporate VPN routes and `/etc/hosts` symlink remain untouched.
4. Re-connect with `mesh up` (or restart service) before Test H3.

### Test H3 — Real Lid-Close Sleep / Wake Recovery (`>= 4 min` Sleep, `2–3` Trials, `P95 <= 15 s`, `PERF-07`)

Repeat **2 to 3 independent trials** per physical laptop:

1. Verify baseline health before sleep:
   ```bash
   mesh status
   mesh ping vps -c 2
   ```
2. **Close the laptop lid** (do not disable sleep or keep external display attached) and leave it sleeping for **at least 4 minutes** (`>= 240 s`) so Wi-Fi/NIC sleeps and NAT/conntrack mappings expire.
3. Prepare a continuous stopwatch / ping check on a separate terminal (or run on wake):
   - Open the laptop lid and unlock (mark `T0 = lid open / OS network-up event`).
   - Measure `T_recover` = elapsed seconds until `mesh ping vps -c 2` receives valid ICMP/overlay replies (and `mesh peers` shows healthy handshake).
4. Record `Sleep Duration (s)`, `T_recover (s)`, and `Path (direct/relay)` for each trial in the §6 ledger.
- **Pass Criteria:** Every measured recovery across the 2–3 real hardware trials achieves `T_recover <= 15.0 s` (`PERF-07` SLO), `0` daemon crash/restart required, and normal internet browsing outside `100.115.0.0/16` works immediately.

### Test H4 — Wi-Fi to 4G/5G Hotspot Live Roaming (`US-035`, `US-057 AC5`)

1. Start continuous overlay verification from the laptop:
   ```bash
   # Repeat pings while roaming networks:
   mesh ping vps -c 20 --timeout-ms 2500
   ```
2. Switch the laptop's active uplink from **Office/Home Wi-Fi** to a **Phone 4G/5G Hotspot** (and optionally back to Wi-Fi).
3. Observe `mesh peers` and `mesh netcheck` after roaming:
   - Confirm `meshd` re-binds its outer socket (`IP_BOUND_IF` on macOS / `IP_UNICAST_IF` on Windows), re-runs Disco/STUN discovery, and restores overlay reachability within `<= 15 s` without restarting `meshd` or leaking stale routes.

---

## 5. Failure Capture If Any Trial Fails

If any real hardware trial exceeds `15 s` or drops traffic:
1. Capture redacted diagnostic bundle immediately (contains `0` secrets):
   ```bash
   mesh bugreport
   ```
2. On macOS, inspect `/var/log/mesh/meshd.log` and re-run `sudo bash lab/macos/verify-macos-host.sh`.
3. On Windows, inspect `C:\ProgramData\Mesh\` logs and Windows Event Viewer (`MeshVpnAgent`).
4. Mark `[X] FAIL` in the §6 ledger and do **not** sign off Go-Live until fixed and re-tested.

---

## 6. Operator Hardware Sign-Off Ledger (Must Be Filled During Live Testing)

> **Instructions:** Print or edit this table after running Tests H1–H4 on physical devices. Leave unused rows untouched until tested; **do not invent timings**.

| Trial / Device | OS & Hardware Model | Tester | Date (UTC) | H1 Boot Pre-Login | H2 `utun` / Hosts Isolation | H3 Sleep Dur (s) & Wake `T_recover` (s) (`<= 15 s`) | H4 Wi-Fi -> 4G Roam `T_recover` (s) (`<= 15 s`) | Result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| macOS `arm64` — Trial 1 | `____________________` | `________` | `__________` | `[ ] PASS  [ ] FAIL` | `[ ] PASS  [ ] FAIL` | Sleep: `___ s` / Wake: `____ s` | `____ s` (`direct`/`relay`) | `[ ] PASS  [ ] FAIL` |
| macOS `arm64` — Trial 2 | `____________________` | `________` | `__________` | *(n/a repeat)* | *(n/a repeat)* | Sleep: `___ s` / Wake: `____ s` | `____ s` (`direct`/`relay`) | `[ ] PASS  [ ] FAIL` |
| macOS `arm64` — Trial 3 | `____________________` | `________` | `__________` | *(n/a repeat)* | *(n/a repeat)* | Sleep: `___ s` / Wake: `____ s` | *(optional)* | `[ ] PASS  [ ] FAIL` |
| macOS `x86_64` — Trial 1 | `____________________` | `________` | `__________` | `[ ] PASS  [ ] FAIL` | `[ ] PASS  [ ] FAIL` | Sleep: `___ s` / Wake: `____ s` | `____ s` (`direct`/`relay`) | `[ ] PASS  [ ] FAIL` |
| macOS `x86_64` — Trial 2 | `____________________` | `________` | `__________` | *(n/a repeat)* | *(n/a repeat)* | Sleep: `___ s` / Wake: `____ s` | `____ s` (`direct`/`relay`) | `[ ] PASS  [ ] FAIL` |
| Windows 10/11 — Trial 1 | `____________________` | `________` | `__________` | `[ ] PASS  [ ] FAIL` | `[ ] PASS  [ ] FAIL` | Sleep: `___ s` / Wake: `____ s` | `____ s` (`direct`/`relay`) | `[ ] PASS  [ ] FAIL` |
| Windows 10/11 — Trial 2 | `____________________` | `________` | `__________` | *(n/a repeat)* | *(n/a repeat)* | Sleep: `___ s` / Wake: `____ s` | `____ s` (`direct`/`relay`) | `[ ] PASS  [ ] FAIL` |
| Windows 10/11 — Trial 3 | `____________________` | `________` | `__________` | *(n/a repeat)* | *(n/a repeat)* | Sleep: `___ s` / Wake: `____ s` | *(optional)* | `[ ] PASS  [ ] FAIL` |

**Final Hardware Sign-Off:**
- Release Candidate Commit / Tag: `______________________`
- Operator Name & Signature: `______________________`
- Sign-Off Timestamp (UTC): `______________________`
- Overall Verdict: `[ ] APPROVED FOR GO-LIVE   [ ] BLOCKED (attach mesh bugreport)`
