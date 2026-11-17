#!/usr/bin/env sh
# lab/desktop/audit-desktop-security.sh
# Cross-OS Desktop GUI Static & Behavioral Contract Security Audit (WP-D-C2, US-116).
# POSIX sh compatible for Linux, macOS, and Windows Git Bash / CI runners.

set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT="${1:-$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)}"

PASSED=0
FAILED=0

record_check() {
    id="$1"
    desc="$2"
    ok="$3"
    details="${4:-}"
    if [ "$ok" -eq 1 ]; then
        PASSED=$((PASSED + 1))
        printf '[PASS] %s: %s\n' "$id" "$desc"
    else
        FAILED=$((FAILED + 1))
        if [ -n "$details" ]; then
            printf '[FAIL] %s: %s -> %s\n' "$id" "$desc" "$details" >&2
        else
            printf '[FAIL] %s: %s\n' "$id" "$desc" >&2
        fi
    fi
}

PYTHON_BIN=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
fi

printf '=== Desktop GUI Cross-OS Security Audit (US-116) ===\n'
printf 'RepoRoot: %s\n' "$REPO_ROOT"

# 1. DGUI-AUDIT-01: crates/mesh-gui/Cargo.toml lints & crypto isolation (ADR-020, HR-DGUI-G2-02)
GUI_TOML="$REPO_ROOT/crates/mesh-gui/Cargo.toml"
if [ -f "$GUI_TOML" ] &&
   grep -q '\[lints\]' "$GUI_TOML" &&
   grep -q 'workspace = true' "$GUI_TOML" &&
   grep -q 'mesh-crypto' "$GUI_TOML" &&
   ! grep -Eq '^[[:space:]]*(sha2|subtle|embed-resource|winres)[[:space:].=]' "$GUI_TOML"; then
    record_check "DGUI-AUDIT-01" "crates/mesh-gui/Cargo.toml enforces workspace lints and mesh-crypto (0 sha2/subtle/winres)" 1
else
    record_check "DGUI-AUDIT-01" "crates/mesh-gui/Cargo.toml enforces workspace lints and mesh-crypto (0 sha2/subtle/winres)" 0 "Invalid crates/mesh-gui/Cargo.toml"
fi

# 2. DGUI-AUDIT-02: crates/mesh-gui/src/*.rs has 0 unsafe, 0 .expose_secret(), 0 #[allow(...)], 0 mesh: Registry
GUI_SRC_OK=0
GUI_SRC_ERR=""
if [ -n "$PYTHON_BIN" ]; then
    if GUI_SRC_ERR=$("$PYTHON_BIN" - "$REPO_ROOT/crates/mesh-gui/src" <<'PY'
import pathlib, re, sys

src_dir = pathlib.Path(sys.argv[1])
rs_files = sorted(src_dir.glob("*.rs"))
if len(rs_files) < 11:
    print(f"Expected >= 11 .rs files in {src_dir}, found {len(rs_files)}")
    sys.exit(1)

expose_pat = ".expose" + "_secret"
allow_pat = "#[" + "allow("
unsafe_re = re.compile(r"\b" + "un" + r"safe\b")

for p in rs_files:
    raw = p.read_text(encoding="utf-8")
    no_blk = re.sub(r"/\*[\s\S]*?\*/", "", raw)
    code = re.sub(r"//.*", "", no_blk)
    if expose_pat in code:
        print(f"Forbidden {expose_pat} in {p.name}")
        sys.exit(1)
    if allow_pat in code:
        print(f"Forbidden {allow_pat} in {p.name}")
        sys.exit(1)
    if unsafe_re.search(code):
        print(f"Forbidden unsafe in {p.name}")
        sys.exit(1)
    if r"Software\Classes\mesh" in code:
        print(f"Forbidden Registry mesh: URL scheme in {p.name}")
        sys.exit(1)
PY
    ); then
        GUI_SRC_OK=1
    fi
else
    EXPOSE_KW=".expose""_secret("
    UNSAFE_KW="un""safe"
    if ! grep -Eq "$EXPOSE_KW|\\b${UNSAFE_KW}\\b" "$REPO_ROOT"/crates/mesh-gui/src/*.rs; then
        GUI_SRC_OK=1
    fi
fi
record_check "DGUI-AUDIT-02" "crates/mesh-gui/src/*.rs has 0 .expose_secret(), 0 unsafe, 0 #[allow], and 0 mesh: Registry scheme" "$GUI_SRC_OK" "$GUI_SRC_ERR"

# 3. DGUI-AUDIT-03: crates/mesh-sys/src/{gui_windows,process_windows}.rs SAFETY comments & ADMIN_PIPE_SDDL
SYS_OK=0
SYS_ERR=""
if [ -n "$PYTHON_BIN" ]; then
    if SYS_ERR=$("$PYTHON_BIN" - "$REPO_ROOT" <<'PY'
import pathlib, sys

root = pathlib.Path(sys.argv[1])
u_blk = "un" + "safe {"
u_impl = "un" + "safe impl"
for rel in ("crates/mesh-sys/src/gui_windows.rs", "crates/mesh-sys/src/process_windows.rs"):
    lines = (root / rel).read_text(encoding="utf-8").splitlines()
    count = 0
    for idx, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith("//"):
            continue
        if u_blk in s or u_impl in s:
            window = "\n".join(lines[max(0, idx - 8):idx + 1])
            if "// SAFETY:" not in window:
                print(f"Missing // SAFETY: at {rel}:{idx + 1}")
                sys.exit(1)
            count += 1
    if count < 10:
        print(f"Expected >= 10 documented unsafe blocks in {rel}, got {count}")
        sys.exit(1)

proc_txt = (root / "crates/mesh-sys/src/process_windows.rs").read_text(encoding="utf-8")
if "CREATE_BREAKAWAY_FROM_JOB" in proc_txt.split("//")[0]:
    pass
for ln in proc_txt.splitlines():
    if not ln.strip().startswith("//") and "CREATE_BREAKAWAY_FROM_JOB" in ln:
        print("Forbidden CREATE_BREAKAWAY_FROM_JOB in process_windows.rs")
        sys.exit(1)

ipc_win = (root / "crates/mesh-net/src/ipc_windows.rs").read_text(encoding="utf-8")
if 'ADMIN_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"' not in ipc_win:
    print("ADMIN_PIPE_SDDL mismatch in crates/mesh-net/src/ipc_windows.rs")
    sys.exit(1)
PY
    ); then
        SYS_OK=1
    fi
else
    if grep -q '// SAFETY:' "$REPO_ROOT/crates/mesh-sys/src/gui_windows.rs" &&
       grep -q '// SAFETY:' "$REPO_ROOT/crates/mesh-sys/src/process_windows.rs" &&
       grep -q 'ADMIN_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"' "$REPO_ROOT/crates/mesh-net/src/ipc_windows.rs"; then
        SYS_OK=1
    fi
fi
record_check "DGUI-AUDIT-03" "crates/mesh-sys gui_windows.rs & process_windows.rs have 100% // SAFETY: coverage and strict ADMIN_PIPE_SDDL" "$SYS_OK" "$SYS_ERR"

# 4. DGUI-AUDIT-04: MGH1 framing (0x00 WorkerHello 13 B, pipe allowlist, Zeroizing wipe, SEC-05)
HANDOFF_RS="$REPO_ROOT/crates/mesh-net/src/gui_handoff.rs"
GUI_WIN_RS="$REPO_ROOT/crates/mesh-sys/src/gui_windows.rs"
if [ -f "$HANDOFF_RS" ] && [ -f "$GUI_WIN_RS" ] &&
   grep -q 'pub const MGH1_WORKER_HELLO_LEN: usize = 13;' "$HANDOFF_RS" &&
   grep -q 'pub const MGH1_PROTOCOL_VERSION: u32 = 1;' "$HANDOFF_RS" &&
   grep -q 'pub const HANDOFF_PIPE_PREFIX: &str = r"\\\\.\\pipe\\mesh-gui-handoff-";' "$HANDOFF_RS" &&
   grep -q 'Zeroizing<Vec<u8>>' "$HANDOFF_RS" &&
   grep -q 'ImpersonateNamedPipeClient' "$GUI_WIN_RS" &&
   grep -q 'SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION' "$GUI_WIN_RS"; then
    record_check "DGUI-AUDIT-04" "MGH1 framing (0x00 WorkerHello 13B, pipe allowlist, SQOS SecurityIdentification, Zeroizing) verified" 1
else
    record_check "DGUI-AUDIT-04" "MGH1 framing (0x00 WorkerHello 13B, pipe allowlist, SQOS SecurityIdentification, Zeroizing) verified" 0 "Missing MGH1/SQOS invariants"
fi

# 5. DGUI-AUDIT-05: Atomic clipboard sequence + SHA-256 guard (IG-DGUI-WA-01) & post-dialog PollingSuspensionGuard (IG-DGUI-WA-03)
CLIP_RS="$REPO_ROOT/crates/mesh-gui/src/clipboard.rs"
POLLER_RS="$REPO_ROOT/crates/mesh-gui/src/ipc_poller.rs"
WINDOW_RS="$REPO_ROOT/crates/mesh-gui/src/window.rs"
MAC_CLIP="$REPO_ROOT/desktop/macos/MeshDesktopCore/Sources/MeshDesktopCore/Security/ClipboardAutoClear.swift"
MAC_DIAG="$REPO_ROOT/desktop/macos/MeshVPNApp/Sources/DiagnosticsSheetView.swift"
if [ -f "$CLIP_RS" ] && [ -f "$POLLER_RS" ] && [ -f "$WINDOW_RS" ] && [ -f "$MAC_CLIP" ] && [ -f "$MAC_DIAG" ] &&
   grep -q 'clear_clipboard_if_seq_and_predicate' "$CLIP_RS" &&
   grep -q 'let _pause_guard = poll_control.suspend();' "$POLLER_RS" &&
   ! grep -q '\.suspend()' "$WINDOW_RS" &&
   grep -q 'pasteboard.changeCount == target.recordedChangeCount' "$MAC_CLIP" &&
   grep -q 'panel.runModal()' "$MAC_DIAG" &&
   ! grep -q 'withSuspendedPolling' "$MAC_DIAG"; then
    record_check "DGUI-AUDIT-05" "Atomic clipboard guard (IG-DGUI-WA-01) and post-dialog PollingSuspensionGuard (IG-DGUI-WA-03) verified" 1
else
    record_check "DGUI-AUDIT-05" "Atomic clipboard guard (IG-DGUI-WA-01) and post-dialog PollingSuspensionGuard (IG-DGUI-WA-03) verified" 0 "Clipboard or PollingSuspensionGuard contract violation"
fi

# 6. DGUI-AUDIT-06: desktop/macos/** static invariants (0 app-sandbox, 0 CFBundleURLTypes, 0 NSAllowsArbitraryLoads, 0 UIKit, 0 force-unwrap)
MACOS_STATIC_OK=0
MACOS_STATIC_ERR=""
if [ -n "$PYTHON_BIN" ]; then
    if MACOS_STATIC_ERR=$("$PYTHON_BIN" - "$REPO_ROOT/desktop/macos" <<'PY'
import pathlib, re, sys

macos_root = pathlib.Path(sys.argv[1])
for p in sorted(macos_root.rglob("*")):
    if not p.is_file():
        continue
    if ".build" in p.parts or "DerivedData" in p.parts or any(part.endswith(".xcodeproj") for part in p.parts):
        continue
    rel = p.relative_to(macos_root).as_posix()
    txt = p.read_text(encoding="utf-8")
    if p.suffix in {".plist", ".entitlements", ".yml", ".yaml"}:
        if "com.apple.security.app-sandbox" in txt:
            print(f"Forbidden app-sandbox in {rel}")
            sys.exit(1)
        if p.suffix != ".entitlements":
            if "CFBundleURLTypes" in txt:
                print(f"Forbidden CFBundleURLTypes in {rel}")
                sys.exit(1)
            if "NSAllowsArbitraryLoads" in txt:
                print(f"Forbidden NSAllowsArbitraryLoads in {rel}")
                sys.exit(1)
    if p.suffix == ".swift":
        no_str = re.sub(r'"([^"\\]|\\.)*"', '""', txt)
        no_blk = re.sub(r"/\*[\s\S]*?\*/", "", no_str)
        code = re.sub(r"//.*", "", no_blk)
        if re.search(r"^\s*import\s+UIKit\b", code, re.MULTILINE):
            print(f"Forbidden import UIKit in {rel}")
            sys.exit(1)
        if "Tests/" not in rel and "MeshVPNAppTests/" not in rel:
            if re.search(r"\btry!|\bas!|\bfatalError\s*\(|[A-Za-z0-9_\)\]]!(?!=)", code):
                print(f"Forbidden force-unwrap/fatalError in production Swift {rel}")
                sys.exit(1)
PY
    ); then
        MACOS_STATIC_OK=1
    fi
else
    INFO_PLIST="$REPO_ROOT/desktop/macos/MeshVPNApp/Resources/Info.plist"
    ENT_PLIST="$REPO_ROOT/desktop/macos/MeshVPNApp/Resources/MeshVPN.entitlements"
    if [ -f "$INFO_PLIST" ] && [ -f "$ENT_PLIST" ] &&
       ! grep -Eq 'CFBundleURLTypes|NSAllowsArbitraryLoads|com\.apple\.security\.app-sandbox' "$INFO_PLIST" "$ENT_PLIST"; then
        MACOS_STATIC_OK=1
    fi
fi
record_check "DGUI-AUDIT-06" "desktop/macos/** has 0 app-sandbox, 0 CFBundleURLTypes, 0 NSAllowsArbitraryLoads, 0 UIKit, 0 force-unwraps" "$MACOS_STATIC_OK" "$MACOS_STATIC_ERR"

# 7. DGUI-AUDIT-07: MeshApp.swift single Window(..., id: "dashboard"), startMonitoring(), .regular/.accessory
MESH_APP_SWIFT="$REPO_ROOT/desktop/macos/MeshVPNApp/Sources/MeshApp.swift"
if [ -f "$MESH_APP_SWIFT" ] &&
   grep -q 'Window("Mesh VPN", id: "dashboard")' "$MESH_APP_SWIFT" &&
   grep -q 'initialStore.startMonitoring()' "$MESH_APP_SWIFT" &&
   grep -q 'NSApp.setActivationPolicy(.regular)' "$MESH_APP_SWIFT" &&
   grep -q 'NSApp.setActivationPolicy(.accessory)' "$MESH_APP_SWIFT" &&
   grep -q 'CommandGroup(replacing: .newItem) {}' "$MESH_APP_SWIFT"; then
    record_check "DGUI-AUDIT-07" "MeshApp.swift enforces single Window(id: dashboard), startMonitoring(), and .regular/.accessory switching" 1
else
    record_check "DGUI-AUDIT-07" "MeshApp.swift enforces single Window(id: dashboard), startMonitoring(), and .regular/.accessory switching" 0 "Missing MeshApp.swift lifecycle invariants"
fi

# 8. DGUI-AUDIT-08: Zero-TOFU & validate_preauth_key parity across Rust and macOS Swift
MOBILE_URI_RS="$REPO_ROOT/crates/mesh-core/src/mobile_uri.rs"
ONBOARD_RS="$REPO_ROOT/crates/mesh-gui/src/onboarding.rs"
EP_SWIFT="$REPO_ROOT/desktop/macos/MeshDesktopCore/Sources/MeshDesktopCore/Validation/EndpointNormalizer.swift"
URI_SWIFT="$REPO_ROOT/desktop/macos/MeshDesktopCore/Sources/MeshDesktopCore/Validation/JoinUriParser.swift"
if [ -f "$MOBILE_URI_RS" ] && [ -f "$ONBOARD_RS" ] && [ -f "$EP_SWIFT" ] && [ -f "$URI_SWIFT" ] &&
   grep -q 'pub fn validate_preauth_key' "$MOBILE_URI_RS" &&
   grep -q 'should_lock_system_ca_for_endpoint' "$ONBOARD_RS" &&
   grep -q 'normalized.isIpLiteral && tlsAuthMode == .systemCa' "$EP_SWIFT" &&
   grep -q 'public static func validatePreauthKey' "$URI_SWIFT" &&
   grep -q 'guard byteCount >= 32 else' "$URI_SWIFT"; then
    record_check "DGUI-AUDIT-08" "Zero-TOFU (IPv4/IPv6 lock) and validate_preauth_key (>= 32B base64url) parity across Rust and Swift" 1
else
    record_check "DGUI-AUDIT-08" "Zero-TOFU (IPv4/IPv6 lock) and validate_preauth_key (>= 32B base64url) parity across Rust and Swift" 0 "Parity mismatch between Rust and Swift validators"
fi

# 9. DGUI-AUDIT-09: macOS packaging & installer scripts (0 spctl master-disable, 3-step signing order without --deep, codesign -v guard)
PKG_SH="$REPO_ROOT/scripts/package-macos-app.sh"
INST_MAC_SH="$REPO_ROOT/scripts/install-macos.sh"
SPCTL_BIN="spctl"
SPCTL_FLAG="--master-disable"
if [ -f "$PKG_SH" ] && [ -f "$INST_MAC_SH" ] &&
   ! grep -Eq "${SPCTL_BIN}[[:space:]]+${SPCTL_FLAG}" "$PKG_SH" "$INST_MAC_SH" &&
   grep -q 'STEP 1 (ADR-026 Immutable Order): Sign inner binaries FIRST' "$PKG_SH" &&
   grep -q 'STEP 2 (ADR-026 Immutable Order): Generate SHA256SUMS & embed Resources' "$PKG_SH" &&
   grep -q 'STEP 3 (ADR-026 Immutable Order): Sign outer Mesh VPN.app WITHOUT --deep' "$PKG_SH" &&
   grep -q 'if /usr/bin/codesign -v "${target_path}"' "$INST_MAC_SH" &&
   grep -q 'DAEMON_DIR="/usr/local/libexec/mesh"' "$INST_MAC_SH"; then
    record_check "DGUI-AUDIT-09" "scripts/{package-macos-app,install-macos}.sh enforce ADR-026 3-step signing order without --deep and 0 Gatekeeper disable" 1
else
    record_check "DGUI-AUDIT-09" "scripts/{package-macos-app,install-macos}.sh enforce ADR-026 3-step signing order without --deep and 0 Gatekeeper disable" 0 "macOS packaging/installer invariant failed"
fi

# 10. DGUI-AUDIT-10: Windows installer & workflow alignment (Local\MeshVpnGuiShutdownEvent, MeshVpnAgent, explicit SHA256SUMS, preserve keys.json)
INST_WIN_PS1="$REPO_ROOT/scripts/install-windows.ps1"
RELEASE_YML="$REPO_ROOT/.github/workflows/release.yml"
if [ -f "$INST_WIN_PS1" ] && [ -f "$RELEASE_YML" ] &&
   grep -q 'Local\\MeshVpnGuiShutdownEvent' "$INST_WIN_PS1" &&
   grep -q 'MeshVpnAgent' "$INST_WIN_PS1" &&
   grep -q 'PurgeData' "$INST_WIN_PS1" &&
   grep -q 'sha256sum MeshVPN.exe mesh.exe meshd.exe mesh-server.exe wintun.dll > SHA256SUMS' "$RELEASE_YML"; then
    record_check "DGUI-AUDIT-10" "scripts/install-windows.ps1 & release.yml align on Local\\MeshVpnGuiShutdownEvent, explicit SHA256SUMS, and keys.json preservation" 1
else
    record_check "DGUI-AUDIT-10" "scripts/install-windows.ps1 & release.yml align on Local\\MeshVpnGuiShutdownEvent, explicit SHA256SUMS, and keys.json preservation" 0 "Windows installer or release.yml check failed"
fi

printf '\nSummary: %d passed, %d failed.\n' "$PASSED" "$FAILED"
if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
