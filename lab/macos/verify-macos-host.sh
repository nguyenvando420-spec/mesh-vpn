#!/usr/bin/env bash
set -euo pipefail

# macOS Real-Host & Runner Verification Script (US-057 AC5, GNFR-12, US-073, US-060, US-035)
# Verifies filesystem ownership/permissions, ad-hoc codesigning, zero quarantine xattr,
# /etc/hosts symlink preservation, utun ledger tracking, dual IPC RBAC separation,
# launchd respawn <= 10s, and clean uninstall with zero host residue.

DAEMON_BIN="/usr/local/libexec/mesh/meshd"
CLI_BIN="/usr/local/bin/mesh"
PLIST_PATH="/Library/LaunchDaemons/internal.mesh.meshd.plist"
LAUNCHD_LABEL="internal.mesh.meshd"
STATE_DIR="/var/db/mesh"
LEDGER_FILE="/var/db/mesh/ledger.json"
RUN_DIR="/var/run/meshd"
RO_SOCK="/var/run/meshd/meshd-ro.sock"
ADMIN_SOCK="/var/run/meshd/meshd-admin.sock"

MODE="full"
PEER_HOST=""
TEST_RESPAWN=0
TEST_UNINSTALL=0
UNINSTALL_SCRIPT=""
SKIP_IF_UNINSTALLED=0

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

log_info() {
  printf '[INFO] %s\n' "$*"
}

log_pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf '[PASS] %s\n' "$*"
}

log_warn() {
  WARN_COUNT=$((WARN_COUNT + 1))
  printf '[WARN] %s\n' "$*" >&2
}

log_fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf '[FAIL] %s\n' "$*" >&2
}

usage() {
  cat <<'EOF'
Usage: verify-macos-host.sh [OPTIONS]

Options:
  --mode <static|ipc|full>   Verification scope (default: full)
                               static: OS, runner arch, /etc/hosts baseline, file permissions, codesign
                               ipc:    static + dual IPC sockets (ro vs admin RBAC) + utun ledger checks
                               full:   ipc + optional respawn and uninstall checks
  --ci-dry-run               Alias for --mode static --skip-if-uninstalled
  --skip-if-uninstalled      Do not fail if mesh/meshd binaries are not installed on runner
  --peer-host <fqdn>         Verify dscacheutil resolution for a mesh peer host
  --test-respawn             Kill -9 meshd and verify launchd respawns it within 10s (requires root)
  --test-uninstall           Run install-macos.sh --uninstall and verify zero leftovers (requires root)
  --uninstall-script <path>  Path to scripts/install-macos.sh for --test-uninstall
  -h, --help                 Show this help message
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode)
      [ "$#" -ge 2 ] || { echo "Missing value for --mode" >&2; exit 2; }
      MODE="$2"
      shift 2
      ;;
    --ci-dry-run)
      MODE="static"
      SKIP_IF_UNINSTALLED=1
      shift
      ;;
    --skip-if-uninstalled)
      SKIP_IF_UNINSTALLED=1
      shift
      ;;
    --peer-host)
      [ "$#" -ge 2 ] || { echo "Missing value for --peer-host" >&2; exit 2; }
      PEER_HOST="$2"
      shift 2
      ;;
    --test-respawn)
      TEST_RESPAWN=1
      shift
      ;;
    --test-uninstall)
      TEST_UNINSTALL=1
      shift
      ;;
    --uninstall-script)
      [ "$#" -ge 2 ] || { echo "Missing value for --uninstall-script" >&2; exit 2; }
      UNINSTALL_SCRIPT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

case "$MODE" in
  static|ipc|full) ;;
  *)
    echo "Invalid --mode '$MODE'. Expected static, ipc, or full." >&2
    exit 2
    ;;
esac

# Helpers using BSD stat on macOS: `stat -f '%u:%g:%Lp'`
stat_ugm() {
  stat -f '%u:%g:%Lp' "$1"
}

check_darwin_platform() {
  local os_name arch_name os_ver major_ver
  os_name="$(uname -s)"
  if [ "$os_name" != "Darwin" ]; then
    log_fail "Expected Darwin host, got '$os_name'"
    return 1
  fi

  arch_name="$(uname -m)"
  case "$arch_name" in
    arm64|x86_64)
      log_pass "macOS architecture verified: $arch_name"
      ;;
    *)
      log_fail "Unsupported macOS architecture: $arch_name"
      ;;
  esac

  os_ver="$(sw_vers -productVersion 2>/dev/null || echo '0.0')"
  major_ver="${os_ver%%.*}"
  if [ "${major_ver:-0}" -ge 13 ]; then
    log_pass "macOS version >= 13 verified: $os_ver"
  else
    log_fail "macOS >= 13 required, found: $os_ver"
  fi
}

check_secure_root_file() {
  local path="$1"
  local label="$2"
  local info uid gid mode perm_bits

  if [ -L "$path" ]; then
    log_fail "$label must not be a symlink: $path"
    return
  fi
  if [ ! -f "$path" ]; then
    log_fail "$label missing regular file: $path"
    return
  fi

  info="$(stat_ugm "$path")"
  uid="${info%%:*}"
  gid="${info#*:}"; gid="${gid%%:*}"
  mode="${info##*:}"
  perm_bits=$((8#$mode))

  if [ "$uid" -ne 0 ] || [ "$gid" -ne 0 ]; then
    log_fail "$label must be owned by root:wheel (0:0), got ${uid}:${gid} ($path)"
  elif [ $((perm_bits & 022)) -ne 0 ]; then
    log_fail "$label has group/world write bits set: mode $mode ($path)"
  else
    log_pass "$label ownership root:wheel and non-writable mode $mode verified"
  fi
}

check_secure_dir() {
  local path="$1"
  local expected_mode="$2"
  local label="$3"
  local info uid gid mode

  if [ -L "$path" ] || [ ! -d "$path" ]; then
    log_fail "$label must be a real directory (not symlink): $path"
    return
  fi
  info="$(stat_ugm "$path")"
  uid="${info%%:*}"
  gid="${info#*:}"; gid="${gid%%:*}"
  mode="${info##*:}"

  if [ "$uid" -ne 0 ] || [ "$gid" -ne 0 ]; then
    log_fail "$label must be owned by root:wheel (0:0), got ${uid}:${gid}"
  elif [ "$mode" != "$expected_mode" ]; then
    log_fail "$label expected mode $expected_mode, got $mode"
  else
    log_pass "$label directory $path verified (root:wheel $mode)"
  fi
}

check_codesign_and_quarantine() {
  local path="$1"
  local label="$2"

  if codesign -v "$path" >/dev/null 2>&1 && codesign -dv --verbose=2 "$path" >/dev/null 2>&1; then
    log_pass "$label codesign signature verified ($path)"
  else
    log_fail "$label failed codesign verification ($path)"
  fi

  if xattr -p com.apple.quarantine "$path" >/dev/null 2>&1; then
    log_fail "$label still has com.apple.quarantine attribute ($path)"
  else
    log_pass "$label has zero com.apple.quarantine attribute"
  fi
}

check_gatekeeper_posture() {
  if command -v spctl >/dev/null 2>&1; then
    local status
    status="$(spctl --status 2>&1 || true)"
    log_info "Gatekeeper posture: $status"
    if printf '%s' "$status" | grep -qi 'assessments disabled'; then
      log_warn "Gatekeeper assessments are disabled on this host; mesh must never require spctl --master-disable"
    else
      log_pass "Gatekeeper assessments remain enabled (no spctl --master-disable dependency)"
    fi
  fi
}

check_hosts_symlink_integrity() {
  if [ -L /etc/hosts ]; then
    local target
    target="$(readlink /etc/hosts)"
    case "$target" in
      private/etc/hosts|/private/etc/hosts)
        log_pass "/etc/hosts symlink intact -> $target"
        ;;
      *)
        log_fail "/etc/hosts points to unexpected target: $target"
        return
        ;;
    esac
  elif [ -L /etc ]; then
    local etc_target
    etc_target="$(readlink /etc)"
    case "$etc_target" in
      private/etc|/private/etc)
        if [ -f /private/etc/hosts ]; then
          log_pass "/etc symlink intact (-> $etc_target) and /private/etc/hosts regular file verified"
        else
          log_fail "/private/etc/hosts missing regular file"
          return
        fi
        ;;
      *)
        log_fail "/etc points to unexpected target: $etc_target"
        return
        ;;
    esac
  else
    log_fail "Neither /etc/hosts nor /etc is a symlink to /private/etc"
    return
  fi

  if [ -f /private/etc/hosts ]; then
    local info uid gid mode
    info="$(stat_ugm /private/etc/hosts)"
    uid="${info%%:*}"
    gid="${info#*:}"; gid="${gid%%:*}"
    mode="${info##*:}"
    if [ "$uid" -eq 0 ] && [ "$gid" -eq 0 ] && [ "$mode" = "644" ]; then
      log_pass "/private/etc/hosts permissions verified (root:wheel 0644)"
    else
      log_warn "/private/etc/hosts has unexpected ownership/mode: ${uid}:${gid} $mode"
    fi
  fi
}

capture_baseline_snapshot() {
  local tmp_base snapshot_dir
  tmp_base="${TMPDIR:-/tmp}"
  tmp_base="${tmp_base%/}"
  snapshot_dir="$(mktemp -d "${tmp_base}/mesh-macos-baseline.XXXXXX")"
  ifconfig -l >"$snapshot_dir/ifconfig_l.txt" 2>/dev/null || true
  scutil --dns >"$snapshot_dir/scutil_dns.txt" 2>/dev/null || true
  ls -la /etc/resolver >"$snapshot_dir/etc_resolver.txt" 2>/dev/null || true
  log_info "Captured baseline host snapshot in $snapshot_dir" >&2
  printf '%s\n' "$snapshot_dir"
}

check_installed_artifacts() {
  if [ ! -e "$DAEMON_BIN" ] && [ ! -e "$CLI_BIN" ]; then
    if [ "$SKIP_IF_UNINSTALLED" -eq 1 ]; then
      log_warn "mesh/meshd binaries not installed; skipping installed binary checks (--skip-if-uninstalled)"
      return 1
    fi
    log_fail "Required binaries not installed ($DAEMON_BIN, $CLI_BIN)"
    return 1
  fi

  check_secure_root_file "$DAEMON_BIN" "meshd binary"
  check_secure_root_file "$CLI_BIN" "mesh CLI binary"
  check_secure_root_file "$PLIST_PATH" "launchd plist"
  check_secure_dir "$STATE_DIR" "700" "state directory"
  check_secure_dir "$RUN_DIR" "755" "runtime directory"

  check_codesign_and_quarantine "$DAEMON_BIN" "meshd binary"
  check_codesign_and_quarantine "$CLI_BIN" "mesh CLI binary"
  return 0
}

check_ipc_and_rbac() {
  if [ ! -S "$RO_SOCK" ]; then
    log_fail "Read-only IPC socket missing: $RO_SOCK"
  else
    local ro_info ro_mode
    ro_info="$(stat_ugm "$RO_SOCK")"
    ro_mode="${ro_info##*:}"
    if [ "$ro_mode" = "666" ]; then
      log_pass "Read-only IPC socket mode 0666 verified: $RO_SOCK"
    else
      log_fail "Read-only IPC socket expected mode 0666, got $ro_mode"
    fi
  fi

  if [ ! -S "$ADMIN_SOCK" ]; then
    log_fail "Admin IPC socket missing: $ADMIN_SOCK"
  else
    local adm_info adm_uid adm_gid adm_mode
    adm_info="$(stat_ugm "$ADMIN_SOCK")"
    adm_uid="${adm_info%%:*}"
    adm_gid="${adm_info#*:}"; adm_gid="${adm_gid%%:*}"
    adm_mode="${adm_info##*:}"
    if [ "$adm_uid" -eq 0 ] && [ "$adm_gid" -eq 80 ] && [ "$adm_mode" = "660" ]; then
      log_pass "Admin IPC socket verified (root:admin[80] mode 0660): $ADMIN_SOCK"
    else
      log_fail "Admin IPC socket expected 0:80 mode 0660, got ${adm_uid}:${adm_gid} mode ${adm_mode}"
    fi
  fi

  # Non-admin user read-only status check + secret leakage guard
  local status_json=""
  if [ "$(id -u)" -eq 0 ]; then
    status_json="$(su -m nobody -c "$CLI_BIN status --json" 2>/dev/null || true)"
  else
    status_json="$("$CLI_BIN" status --json 2>/dev/null || true)"
  fi

  if [ -n "$status_json" ]; then
    if printf '%s' "$status_json" | grep -Eqi '"(private_key|pre_auth_key|wireguard_private_key|admin_token|secret)"'; then
      log_fail "Read-only status JSON leaked secret field(s)!"
    else
      log_pass "Non-admin read-only 'mesh status --json' succeeded with zero secret fields"
    fi
  else
    log_fail "Failed to query read-only 'mesh status --json' as non-admin user"
  fi

  # Non-admin admin mutation denial check (using nobody when running as root, or non-admin current user)
  local run_as_non_admin=0
  if [ "$(id -u)" -eq 0 ]; then
    run_as_non_admin=1
  elif ! id -G | tr ' ' '\n' | grep -qx '80'; then
    run_as_non_admin=2
  fi

  if [ "$run_as_non_admin" -eq 1 ]; then
    if su -m nobody -c "$CLI_BIN down" >/dev/null 2>&1; then
      log_fail "Non-admin user (nobody) was permitted to invoke 'mesh down' on admin socket!"
    else
      log_pass "Non-admin user (nobody) denied on admin socket ('mesh down')"
    fi
  elif [ "$run_as_non_admin" -eq 2 ]; then
    if "$CLI_BIN" down >/dev/null 2>&1; then
      log_fail "Non-admin user was permitted to invoke 'mesh down' on admin socket!"
    else
      log_pass "Non-admin user denied on admin socket ('mesh down')"
    fi
  else
    log_warn "Current user is in macOS admin group (gid 80); skipping non-admin denial probe (run with sudo to test via nobody)"
  fi
}

check_utun_and_ledger() {
  local baseline_dir="$1"
  local pre_ifaces post_ifaces mesh_utun

  if [ ! -f "$LEDGER_FILE" ]; then
    log_fail "ResourceLedger missing: $LEDGER_FILE"
    return
  fi

  mesh_utun="$(python3 - "$LEDGER_FILE" <<'PY' 2>/dev/null || true
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)
print(data.get("tun_interface_name") or "")
PY
)"

  if printf '%s' "$mesh_utun" | grep -Eq '^utun[0-9]+$'; then
    log_pass "ResourceLedger tracks macOS TUN interface: $mesh_utun"
  else
    log_fail "ResourceLedger missing valid utun[0-9]+ name (got '$mesh_utun')"
  fi

  if [ -n "$mesh_utun" ] && ifconfig "$mesh_utun" >/dev/null 2>&1; then
    log_pass "Active mesh interface $mesh_utun verified via ifconfig"
  elif [ -n "$mesh_utun" ]; then
    log_fail "Tracked interface $mesh_utun not present in ifconfig"
  fi

  pre_ifaces="$(tr ' ' '\n' <"$baseline_dir/ifconfig_l.txt" | grep -E '^utun[0-9]+$' || true)"
  post_ifaces="$(ifconfig -l | tr ' ' '\n' | grep -E '^utun[0-9]+$' || true)"
  if [ -n "$pre_ifaces" ]; then
    local iface missing=0
    for iface in $pre_ifaces; do
      if [ "$iface" != "$mesh_utun" ] && ! printf '%s\n' "$post_ifaces" | grep -qx "$iface"; then
        log_fail "Foreign TUN interface disappeared: $iface"
        missing=1
      fi
    done
    if [ "$missing" -eq 0 ]; then
      log_pass "All pre-existing foreign utun interfaces remain intact"
    fi
  fi
}

check_dns_resolution() {
  if [ -z "$PEER_HOST" ]; then
    return
  fi
  if dscacheutil -q host -a name "$PEER_HOST" | grep -q 'ip_address:'; then
    log_pass "dscacheutil resolved mesh peer host: $PEER_HOST"
  else
    log_fail "dscacheutil failed to resolve mesh peer host: $PEER_HOST"
  fi
}

check_launchd_respawn() {
  if [ "$TEST_RESPAWN" -ne 1 ]; then
    return
  fi
  if [ "$(id -u)" -ne 0 ]; then
    log_fail "--test-respawn requires root privileges"
    return
  fi

  local old_pid new_pid deadline
  old_pid="$(pgrep -x meshd | head -n1 || true)"
  if [ -z "$old_pid" ]; then
    log_fail "Cannot test respawn: meshd is not currently running"
    return
  fi

  log_info "Sending SIGKILL to meshd PID $old_pid to verify launchd respawn <= 10s"
  kill -9 "$old_pid" || true

  deadline=$(($(date +%s) + 10))
  new_pid=""
  while [ "$(date +%s)" -le "$deadline" ]; do
    new_pid="$(pgrep -x meshd | head -n1 || true)"
    if [ -n "$new_pid" ] && [ "$new_pid" != "$old_pid" ] && [ -S "$RO_SOCK" ]; then
      break
    fi
    sleep 1
  done

  if [ -n "$new_pid" ] && [ "$new_pid" != "$old_pid" ] && [ -S "$RO_SOCK" ]; then
    log_pass "launchd respawned meshd within 10s (old PID $old_pid -> new PID $new_pid)"
  else
    log_fail "launchd failed to respawn healthy meshd within 10s (label $LAUNCHD_LABEL)"
  fi
}

check_clean_uninstall() {
  if [ "$TEST_UNINSTALL" -ne 1 ]; then
    return
  fi
  if [ "$(id -u)" -ne 0 ]; then
    log_fail "--test-uninstall requires root privileges"
    return
  fi

  local script_path="$UNINSTALL_SCRIPT"
  if [ -z "$script_path" ]; then
    script_path="$(cd "$(dirname "$0")/../.." && pwd)/scripts/install-macos.sh"
  fi
  if [ ! -f "$script_path" ]; then
    log_fail "install-macos.sh not found for uninstall check: $script_path"
    return
  fi

  local tracked_utun=""
  if [ -f "$LEDGER_FILE" ]; then
    tracked_utun="$(python3 - "$LEDGER_FILE" <<'PY' 2>/dev/null || true
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    print(json.load(fh).get("tun_interface_name") or "")
PY
)"
  fi

  log_info "Executing clean uninstall via $script_path --uninstall --purge"
  bash "$script_path" --uninstall --purge

  if pgrep -x meshd >/dev/null 2>&1; then
    log_fail "meshd process still running after uninstall"
  else
    log_pass "Zero meshd processes remain after uninstall"
  fi

  if [ -e "$DAEMON_BIN" ] || [ -e "$CLI_BIN" ] || [ -e "$PLIST_PATH" ]; then
    log_fail "Leftover binary or plist found after uninstall"
  else
    log_pass "All binaries and launchd plist removed"
  fi

  if [ -n "$tracked_utun" ] && ifconfig "$tracked_utun" >/dev/null 2>&1; then
    log_fail "Mesh TUN interface $tracked_utun still exists after uninstall"
  elif [ -n "$tracked_utun" ]; then
    log_pass "Tracked mesh interface $tracked_utun removed on uninstall"
  fi

  if grep -q '# BEGIN mesh' /etc/hosts 2>/dev/null; then
    log_fail "# BEGIN mesh block still present in /etc/hosts after uninstall"
  else
    log_pass "/etc/hosts mesh block cleaned up"
  fi

  check_hosts_symlink_integrity
}

BASELINE_DIR=""

main() {
  BASELINE_DIR="$(capture_baseline_snapshot)"
  trap '[ -n "${BASELINE_DIR:-}" ] && rm -rf "${BASELINE_DIR}"' EXIT

  check_darwin_platform
  check_gatekeeper_posture
  check_hosts_symlink_integrity

  if check_installed_artifacts; then
    if [ "$MODE" = "ipc" ] || [ "$MODE" = "full" ]; then
      check_ipc_and_rbac
      check_utun_and_ledger "$BASELINE_DIR"
      check_dns_resolution
    fi
    if [ "$MODE" = "full" ]; then
      check_launchd_respawn
      check_clean_uninstall
    fi
  fi

  printf '\n=== macOS Verification Summary ===\n'
  printf 'PASS: %d | WARN: %d | FAIL: %d\n' "$PASS_COUNT" "$WARN_COUNT" "$FAIL_COUNT"

  if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
  fi
  exit 0
}

main
