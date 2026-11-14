# Mesh VPN `0.1.0` — Release Plan

**Product Version:** `0.1.0` (matches workspace `Cargo.toml`)
**Toolchain:** Rust `1.94.1` (`edition = "2024"`, `resolver = "3"`)
**Release Profile:** `opt-level = 3`, `lto = "thin"`, `codegen-units = 1`, `strip = "symbols"`, `panic = "abort"`
**Zero-C-TLS Policy:** Pure Rust + `ring` (`cargo deny check` blocks `openssl-sys`, `aws-lc-rs`, `native-tls`, `rusqlite`)

---

## 1. Release Target Matrix

CI job `release-build-matrix` (`.github/workflows/ci.yml`) builds and packages the 4 primary production targets plus the secondary Windows MinGW compile check:

| Target Triple | Artifacts Produced | Distribution & Verification | Tier |
| --- | --- | --- | --- |
| `x86_64-unknown-linux-musl` | `mesh-server`, `meshd`, `mesh`, `SHA256SUMS` | `scripts/install-server.sh` (VPS) / `scripts/install-linux.sh` (clients & VPS-nodes) | Primary |
| `aarch64-apple-darwin` | `meshd`, `mesh`, `SHA256SUMS` | Browser-free SHA-256 install (`scripts/install-macos.sh`), ad-hoc `codesign`, `internal.mesh.meshd.plist` | Primary |
| `x86_64-apple-darwin` | `meshd`, `mesh`, `SHA256SUMS` | Browser-free SHA-256 install (`scripts/install-macos.sh`), ad-hoc `codesign`, `internal.mesh.meshd.plist` | Primary |
| `x86_64-pc-windows-msvc` | `meshd.exe`, `mesh.exe`, `wintun.dll`, `WINTUN-LICENSE.txt`, `wintun.dll.sha256` | `scripts/install-windows.ps1` (`MeshVpnAgent` service, SHA-256 checked `wintun.dll`) | Primary |
| `x86_64-pc-windows-gnu` | Workspace `--all-targets` compile check | Ensures MinGW toolchain compatibility in CI (`check-windows` / matrix) | Compile Check |

> **Note on macOS Packaging:** MVP (`0.1.0`) distributes tarballs + `SHA256SUMS` via `scripts/install-macos.sh`. Signed & Apple-notarized `.pkg` installers are scoped for Phase 2+. Never disable Gatekeeper (`spctl --master-disable`).
>
> **Note on Windows `MESH_WINTUN_SHA256` Compile-Time Pin:** `meshd.exe` embeds the verified `wintun.dll` SHA-256 at compile time (`option_env!("MESH_WINTUN_SHA256")`). CI sets this automatically in `release-build-matrix`; for manual Windows release builds run `$env:MESH_WINTUN_SHA256 = (Get-FileHash .\dist\wintun.dll -Algorithm SHA256).Hash.ToLowerInvariant()` prior to `cargo build --release` (otherwise `mesh up` fails closed with `PermissionDenied`).

---

## 2. Release Gating Criteria (Mandatory Before Tagging `v0.1.0`)

1. **Static & Workspace Checks (`check-linux`, `check-macos`, `check-windows`, `static-and-lab-lint`):**
   - UTF-8 without BOM + LF endings on workflows, scripts, lab assets, and docs.
   - `cargo fmt --all -- --check`
   - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
   - `cargo test --workspace --all-features`
   - `cargo deny check advisories bans licenses sources`
2. **Automated SLO Verification Gate (`US-058`):**
   - `scripts/run-slo-suite.sh --skip-static-checks` (Linux) and `scripts/run-slo-suite.ps1 -SkipStaticChecks` (Windows) pass all `PERF-01/05/06/07` thresholds.
   - CI confirms `--simulate-fail` / `-SimulateFail` exits non-zero (fail-closed gate integrity).
3. **Docker NAT & Chaos Lab (`lab/scenarios/run-all-chaos.sh`):**
   - Run full live NAT/chaos suite (`docker-build-and-lab` with `run_live_nat_lab == true` on release candidates) verifying hole punch, Blind Relay fallback, Control outage P2P survival, and revocation `<= 2 s` cut.
4. **Physical Hardware Sign-Off:**
   - Complete `docs/06-operations/hardware-sleep-wake-protocol.md` ledger for Apple Silicon macOS, Intel macOS (if applicable), and Windows 10/11 laptops.
5. **Go-Live Checklist:**
   - All 20 items checked `[x]` in `docs/06-operations/go-live-checklist.md`.

---

## 3. Compatibility & Upgrade Policy

- **N-1 Protocol Compatibility:**
  - Control protocol (`mesh-proto`) uses versioned framing and additive fields so `0.1.x` servers tolerate `N-1` clients during rolling upgrades.
  - Endpoint migration (`mesh server migrate-endpoint`) and server TLS key rotation (`mesh server rotate-tls-key --stage` / `--promote`, 7-day `next_pin` window) keep online peers connected without mass re-pinning.
- **`redb` State & Backup Guarantee (`US-045`):**
  - Every `mesh-server` upgrade MUST begin with `mesh server backup`, generating an atomic `<prefix>-<unix_ms>.redb` + `.sha256` (`0600`) containing `server_identity` and monotonic `netmap_version`.
  - Encrypted off-VPS backup (`age`, `restic`, or `rclone crypt`) MUST complete before binary swap.

---

## 4. Phased Rollout Sequence

1. **Stage 0 — Staging / Lab Validation:** Deploy candidate binaries to Docker NAT lab and staging VPS; run 15-minute smoke (`docs/06-release-deployment/deployment-checklist.md`) and restore drill (`RTO <= 5 min`).
2. **Stage 1 — Control & Blind Relay VPS:** Backup `redb` -> swap `mesh-server` + `mesh` -> validate `/readyz`, `mesh server hardening-check`, and `mesh server status`.
3. **Stage 2 — Canary Clients (1 macOS + 1 Windows + 1 Linux headless):** Upgrade via platform installers (`scripts/install-{macos,windows,linux}.{sh,ps1}`), verify P2P + relay + `ResourceLedger` cleanliness.
4. **Stage 3 — Fleet Rollout:** Roll out remaining nodes; monitor `127.0.0.1:9091/metrics` and `mesh audit list` for 24 hours.
