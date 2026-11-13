#!/bin/sh
set -eu

DAEMON_DIR="/usr/local/libexec/mesh"
DAEMON_BIN="${DAEMON_DIR}/meshd"
CLI_BIN="/usr/local/bin/mesh"
PLIST_DEST="/Library/LaunchDaemons/internal.mesh.meshd.plist"
LAUNCHD_LABEL="internal.mesh.meshd"
STATE_DIR="/var/db/mesh"
RUN_DIR="/var/run/meshd"
LOG_DIR="/var/log/mesh"
PF_ANCHOR="com.internal.mesh"
SOCKETFILTERFW="/usr/libexec/ApplicationFirewall/socketfilterfw"

ACTION="install"
PURGE=0
FROM_DIR="."
PLIST_SRC=""
CHECKSUMS_FILE=""
MESHD_SHA256=""
MESH_CLI_SHA256=""
FIREWALL_OPTIN="ask"

usage() {
  cat <<'EOF'
Usage:
  sudo install-macos.sh [--from DIR] [--sha256-file FILE] [--yes-firewall | --no-firewall]
  sudo install-macos.sh --uninstall [--purge]
EOF
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "error: this script must be run as root (use sudo)." >&2
    exit 1
  fi
}

check_macos_platform() {
  if [ "$(uname -s)" != "Darwin" ]; then
    echo "error: unsupported OS $(uname -s); macOS 13+ is required." >&2
    exit 1
  fi

  product_ver="$(/usr/bin/sw_vers -productVersion)"
  major_ver="$(printf '%s' "${product_ver}" | cut -d. -f1)"
  if [ -z "${major_ver}" ] || [ "${major_ver}" -lt 13 ] 2>/dev/null; then
    echo "error: macOS ${product_ver} is unsupported; macOS 13 or newer is required." >&2
    exit 1
  fi

  arch="$(uname -m)"
  case "${arch}" in
    arm64|x86_64) ;;
    *)
      echo "error: unsupported macOS architecture '${arch}'." >&2
      exit 1
      ;;
  esac
}

verify_root_owned_ancestors() {
  target_dir="$1"
  check_path="${target_dir}"
  while [ -n "${check_path}" ]; do
    if [ -e "${check_path}" ]; then
      if [ -L "${check_path}" ]; then
        echo "error: untrusted symlink in root install path '${check_path}'." >&2
        exit 1
      fi
      owner_uid="$(/usr/bin/stat -f '%u' "${check_path}")"
      perm_mode="$(/usr/bin/stat -f '%OLp' "${check_path}")"
      if [ "${owner_uid}" -ne 0 ]; then
        echo "error: directory '${check_path}' is not owned by root (uid=${owner_uid})." >&2
        exit 1
      fi
      group_world_write=$((8#${perm_mode} & 022))
      if [ "${group_world_write}" -ne 0 ]; then
        echo "error: directory '${check_path}' is group/world writable (mode=${perm_mode})." >&2
        exit 1
      fi
    fi
    if [ "${check_path}" = "/" ]; then
      break
    fi
    check_path="$(dirname "${check_path}")"
  done
}

verify_sha256() {
  file_path="$1"
  expected_hash="$2"
  actual_hash="$(/usr/bin/shasum -a 256 "${file_path}" | awk '{print $1}')"
  if [ -z "${expected_hash}" ] || [ "${actual_hash}" != "${expected_hash}" ]; then
    echo "error: SHA-256 mismatch for '${file_path}' (expected '${expected_hash}', got '${actual_hash}')." >&2
    exit 1
  fi
}

lookup_checksum_in_file() {
  sum_file="$1"
  artifact_name="$2"
  awk -v target="${artifact_name}" '
    $2 == target || $2 == ("./" target) { print $1; exit }
  ' "${sum_file}"
}

inspect_and_configure_firewall() {
  if [ ! -x "${SOCKETFILTERFW}" ]; then
    return 0
  fi

  fw_state="$("${SOCKETFILTERFW}" --getglobalstate 2>/dev/null || true)"
  case "${fw_state}" in
    *enabled*) ;;
    *) return 0 ;;
  esac

  stealth_state="$("${SOCKETFILTERFW}" --getstealthmode 2>/dev/null || true)"
  blockall_state="$("${SOCKETFILTERFW}" --getblockall 2>/dev/null || true)"
  case "${blockall_state}" in
    *enabled*)
      echo "warning: macOS Firewall 'Block all incoming connections' is enabled; direct P2P may be limited (relay fallback remains active)."
      ;;
  esac
  case "${stealth_state}" in
    *enabled*)
      echo "warning: macOS Firewall stealth mode is enabled; direct NAT traversal may prefer relay fallback."
      ;;
  esac

  allow_fw="no"
  if [ "${FIREWALL_OPTIN}" = "yes" ]; then
    allow_fw="yes"
  elif [ "${FIREWALL_OPTIN}" = "ask" ] && [ -t 0 ]; then
    printf "macOS Application Firewall is enabled. Add opt-in exception for %s? [y/N]: " "${DAEMON_BIN}"
    read -r answer || answer=""
    case "${answer}" in
      y|Y|yes|YES) allow_fw="yes" ;;
    esac
  fi

  if [ "${allow_fw}" = "yes" ]; then
    "${SOCKETFILTERFW}" --add "${DAEMON_BIN}" >/dev/null
    "${SOCKETFILTERFW}" --unblockapp "${DAEMON_BIN}" >/dev/null
    echo "Added Application Firewall exception for ${DAEMON_BIN}."
  else
    echo "Skipped Application Firewall exception; Mesh VPN will fall back to relay when direct UDP is blocked."
  fi
}

do_install() {
  require_root
  check_macos_platform

  meshd_src="${FROM_DIR}/meshd"
  mesh_src="${FROM_DIR}/mesh"
  if [ -z "${PLIST_SRC}" ]; then
    PLIST_SRC="${FROM_DIR}/deploy/launchd/internal.mesh.meshd.plist"
  fi
  if [ -z "${CHECKSUMS_FILE}" ] && [ -f "${FROM_DIR}/SHA256SUMS" ]; then
    CHECKSUMS_FILE="${FROM_DIR}/SHA256SUMS"
  fi

  for required in "${meshd_src}" "${mesh_src}" "${PLIST_SRC}"; do
    if [ ! -f "${required}" ]; then
      echo "error: missing required install file '${required}'." >&2
      exit 1
    fi
  done

  if [ -n "${CHECKSUMS_FILE}" ]; then
    if [ ! -f "${CHECKSUMS_FILE}" ]; then
      echo "error: checksum file '${CHECKSUMS_FILE}' not found." >&2
      exit 1
    fi
    if [ -z "${MESHD_SHA256}" ]; then
      MESHD_SHA256="$(lookup_checksum_in_file "${CHECKSUMS_FILE}" "meshd")"
    fi
    if [ -z "${MESH_CLI_SHA256}" ]; then
      MESH_CLI_SHA256="$(lookup_checksum_in_file "${CHECKSUMS_FILE}" "mesh")"
    fi
  fi

  if [ -z "${MESHD_SHA256}" ] || [ -z "${MESH_CLI_SHA256}" ]; then
    echo "error: SHA-256 verification is mandatory before installing; provide --sha256-file or both --meshd-sha256 and --mesh-sha256." >&2
    exit 1
  fi

  verify_sha256 "${meshd_src}" "${MESHD_SHA256}"
  verify_sha256 "${mesh_src}" "${MESH_CLI_SHA256}"

  verify_root_owned_ancestors "/usr/local"
  verify_root_owned_ancestors "/Library/LaunchDaemons"
  verify_root_owned_ancestors "/var/db"

  /usr/bin/install -d -o root -g wheel -m 0755 "${DAEMON_DIR}"
  /usr/bin/install -d -o root -g wheel -m 0755 "/usr/local/bin"
  /usr/bin/install -d -o root -g wheel -m 0700 "${STATE_DIR}"
  /usr/bin/install -d -o root -g wheel -m 0755 "${RUN_DIR}"
  /usr/bin/install -d -o root -g wheel -m 0750 "${LOG_DIR}"

  /usr/bin/install -o root -g wheel -m 0755 "${meshd_src}" "${DAEMON_BIN}"
  /usr/bin/install -o root -g wheel -m 0755 "${mesh_src}" "${CLI_BIN}"
  /usr/bin/install -o root -g wheel -m 0644 "${PLIST_SRC}" "${PLIST_DEST}"

  /usr/bin/xattr -d com.apple.quarantine "${DAEMON_BIN}" "${CLI_BIN}" >/dev/null 2>&1 || true
  /usr/bin/codesign --force -s - "${DAEMON_BIN}" >/dev/null
  /usr/bin/codesign --force -s - "${CLI_BIN}" >/dev/null
  /usr/bin/plutil -lint "${PLIST_DEST}" >/dev/null

  inspect_and_configure_firewall

  /bin/launchctl bootout "system/${LAUNCHD_LABEL}" >/dev/null 2>&1 || true
  /bin/launchctl bootstrap system "${PLIST_DEST}"
  echo "Installed and started ${LAUNCHD_LABEL}."
}

strip_hosts_block_preserving_symlink() {
  real_hosts="$(/bin/realpath /etc/hosts 2>/dev/null || printf '/private/etc/hosts')"
  case "${real_hosts}" in
    /*) ;;
    *) real_hosts="/private/etc/${real_hosts}" ;;
  esac
  if [ ! -f "${real_hosts}" ]; then
    return 0
  fi
  if grep -Fxq "# BEGIN mesh managed hosts (do not edit manually)" "${real_hosts}" 2>/dev/null \
    || grep -Fxq "# BEGIN mesh" "${real_hosts}" 2>/dev/null; then
    tmp_hosts="${real_hosts}.mesh.uninstall.$$"
    awk '
      $0 == "# BEGIN mesh managed hosts (do not edit manually)" || $0 == "# BEGIN mesh" { skip=1; next }
      $0 == "# END mesh managed hosts" || $0 == "# END mesh" { skip=0; next }
      !skip { print }
    ' "${real_hosts}" > "${tmp_hosts}"
    /usr/sbin/chown root:wheel "${tmp_hosts}"
    /bin/chmod 0644 "${tmp_hosts}"
    /bin/mv "${tmp_hosts}" "${real_hosts}"
    /usr/bin/dscacheutil -flushcache >/dev/null 2>&1 || true
    /usr/bin/killall -HUP mDNSResponder >/dev/null 2>&1 || true
  fi
}

do_uninstall() {
  require_root
  check_macos_platform

  /bin/launchctl bootout "system/${LAUNCHD_LABEL}" >/dev/null 2>&1 || true
  if [ -x "${CLI_BIN}" ]; then
    "${CLI_BIN}" cleanup >/dev/null 2>&1 || true
  fi

  if [ -f "${STATE_DIR}/ledger.json" ]; then
    recorded_utun="$(awk -F'"' '/"tun_interface_name"/ { print $4; exit }' "${STATE_DIR}/ledger.json" 2>/dev/null || true)"
    case "${recorded_utun}" in
      utun[0-9]*)
        if printf '%s' "${recorded_utun}" | grep -Eq '^utun[0-9]+$'; then
          /sbin/ifconfig "${recorded_utun}" down >/dev/null 2>&1 || true
        fi
        ;;
    esac
  fi

  /sbin/pfctl -a "${PF_ANCHOR}" -F all >/dev/null 2>&1 || true
  if [ -x "${SOCKETFILTERFW}" ]; then
    "${SOCKETFILTERFW}" --remove "${DAEMON_BIN}" >/dev/null 2>&1 || true
  fi
  strip_hosts_block_preserving_symlink

  /bin/rm -f "${PLIST_DEST}" "${DAEMON_BIN}" "${CLI_BIN}"
  /bin/rmdir "${DAEMON_DIR}" >/dev/null 2>&1 || true
  /bin/rm -rf "${RUN_DIR}" "${LOG_DIR}"
  /bin/rm -f "${STATE_DIR}/ledger.json"

  if [ "${PURGE}" -eq 1 ]; then
    /bin/rm -rf "${STATE_DIR}"
    echo "Uninstalled Mesh VPN and purged node identity keys (${STATE_DIR})."
  else
    echo "Uninstalled Mesh VPN (preserved ${STATE_DIR}/keys.json; pass --purge to remove)."
  fi
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --from|--plist|--sha256-file|--meshd-sha256|--mesh-sha256)
      if [ "$#" -lt 2 ]; then
        echo "error: option '$1' requires an argument." >&2
        usage >&2
        exit 1
      fi
      opt="$1"
      val="$2"
      shift 2
      case "${opt}" in
        --from) FROM_DIR="${val}" ;;
        --plist) PLIST_SRC="${val}" ;;
        --sha256-file) CHECKSUMS_FILE="${val}" ;;
        --meshd-sha256) MESHD_SHA256="${val}" ;;
        --mesh-sha256) MESH_CLI_SHA256="${val}" ;;
      esac
      ;;
    --yes-firewall)
      FIREWALL_OPTIN="yes"
      shift
      ;;
    --no-firewall)
      FIREWALL_OPTIN="no"
      shift
      ;;
    --uninstall)
      ACTION="uninstall"
      shift
      ;;
    --purge)
      PURGE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option '$1'." >&2
      usage >&2
      exit 1
      ;;
  esac
done

case "${ACTION}" in
  install) do_install ;;
  uninstall) do_uninstall ;;
esac
