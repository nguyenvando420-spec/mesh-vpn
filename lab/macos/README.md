# macOS Real-Host & Runner Verification Guide

This directory contains the automated and manual verification suite for macOS (`US-057 AC5`, `GNFR-12`, `US-073`, `US-060`, `US-035`).

> Note: Linux `utun`/Docker cannot emulate macOS Darwin kernel interfaces (`utun`), `launchd`, `PF` anchors, `/etc/hosts` symlink behavior, or `LOCAL_PEERCRED` (`xucred.cr_groups`). These checks must execute on real macOS hardware (`arm64` / `x86_64`) or GitHub Actions `macos-latest` runners.

## 1. Prerequisites

- **Supported OS**: macOS 13 (Ventura) or newer on Apple Silicon (`arm64`) or Intel (`x86_64`).
- **Signing & Gatekeeper Policy (`GNFR-12`)**:
  - Release and test binaries are ad-hoc signed (`codesign --force -s -`).
  - Do **not** disable Gatekeeper globally (`spctl --master-disable` is prohibited).
  - Browserless installation clears `com.apple.quarantine` only after SHA-256 verification.

## 2. Browserless SHA-256 Install Flow (`US-073 AC5`)

Download release artifacts (`mesh-darwin-<arch>.tar.gz` or raw binaries) alongside `SHA256SUMS` using `curl` (no browser download quarantine), verify checksums, and run `scripts/install-macos.sh`:

```bash
# 1. Verify archive checksum before extracting
shasum -a 256 -c SHA256SUMS --ignore-missing

# 2. Extract binaries, launchd plist, and per-binary SHA256SUMS into a staging directory
mkdir -p ./dist-macos
tar -xzf mesh-darwin-arm64.tar.gz -C ./dist-macos

# 3. Install daemon, CLI, launchd plist, and optional PF/firewall rules
sudo sh ./dist-macos/scripts/install-macos.sh \
  --from ./dist-macos \
  --sha256-file ./dist-macos/SHA256SUMS \
  --yes-firewall
```

To remove all components cleanly:

```bash
sudo sh scripts/install-macos.sh --uninstall --purge
```

## 3. Running `verify-macos-host.sh`

### CI / Runner Static Dry-Run (uninstalled runner check)

Validates macOS platform/arch, Gatekeeper posture, and `/etc/hosts` symlink integrity without failing when `meshd` is not installed as root:

```bash
bash lab/macos/verify-macos-host.sh --ci-dry-run
```

### Installed IPC & Host Security Verification (requires active `meshd`)

Validates `root:wheel` permissions on binaries/plist, ad-hoc codesign, zero `com.apple.quarantine`, `/etc/hosts -> /private/etc/hosts` symlink, dual IPC sockets (`meshd-ro.sock` `0666` vs `meshd-admin.sock` `0660 root:admin`), zero secrets in `mesh status --json`, `utun[0-9]+` tracking in `/var/db/mesh/ledger.json`, and foreign `utun` preservation:

```bash
sudo bash lab/macos/verify-macos-host.sh --mode ipc --peer-host node-2.mesh.internal
```

### Full End-to-End Verification (includes `SIGKILL` respawn and clean uninstall)

> Warning: `--test-uninstall` removes `/usr/local/libexec/mesh/meshd`, `/usr/local/bin/mesh`, the `launchd` plist, and `/var/db/mesh`.

```bash
sudo bash lab/macos/verify-macos-host.sh \
  --mode full \
  --peer-host node-2.mesh.internal \
  --test-respawn \
  --test-uninstall \
  --uninstall-script scripts/install-macos.sh
```

## 4. Manual Hardware Sign-Off Checklist (`GNFR-12` & `US-035 AC2`)

CI virtual machines cannot close a physical lid or pair with iCloud Private Relay / corporate VPN `utun` tunnels. Before signing off a macOS release candidate on physical hardware, record pass/fail results for each item below:

| ID | Check | Procedure | Expected Result |
| --- | --- | --- | --- |
| `MAC-01` | Foreign `utun` preservation (`US-035`) | Enable iCloud Private Relay or another VPN (`ifconfig -l` shows `utunX`), then run `sudo mesh up` and `sudo mesh down`. | Foreign `utunX` remains active and untouched; `ledger.json` tracks only Mesh's `utunY` and cleans only `utunY` on `down`. |
| `MAC-02` | Lid close / Sleep & Wake >= 4 min (`US-036`) | Establish mesh ping between Mac and remote node; close MacBook lid (or `pmset sleepnow`) for **>= 4 minutes** (> 180 s WireGuard `REJECT_AFTER_TIME`); wake Mac. | `ClockJumpDetector` triggers immediate WireGuard re-handshake + control reconnect; tunnel recovers within `<= 10 s` (direct) or `<= 15 s` (relay) without restarting `meshd`. |
| `MAC-03` | Wi-Fi / Thunderbolt NIC switch (`US-035`) | Switch active default interface from Wi-Fi (`en0`) to USB-C Ethernet or Hotspot while streaming `iperf3` / `ping`. | `meshd` rebinds `IP_BOUND_IF` to new physical interface without routing loops and restores peer reachability. |
| `MAC-04` | Dual IPC RBAC as Standard User (`US-060`) | Log in as a non-admin macOS user (not in `admin` group `gid 80`); run `mesh status --json` and `mesh down`. | `mesh status --json` succeeds (`0` secrets); `mesh down` is rejected via `LOCAL_PEERCRED` (`xucred.cr_groups`). |
| `MAC-05` | Clean Uninstall Residue Check (`US-073`) | Run `sudo sh scripts/install-macos.sh --uninstall --purge`, then check `ifconfig -l`, `ls -la /etc/hosts`, `launchctl list`. | `0` `meshd` processes, `0` mesh `utun` interfaces, `# BEGIN mesh` block gone, `/etc/hosts` symlink intact. |
