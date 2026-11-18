#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"

DAEMON_DIR="/usr/local/libexec/mesh"
DAEMON_BIN="${DAEMON_DIR}/meshd"
CLI_BIN="/usr/local/bin/mesh"
PLIST_DEST="/Library/LaunchDaemons/internal.mesh.meshd.plist"
LAUNCHD_LABEL="internal.mesh.meshd"
STATE_DIR="/var/db/mesh"
RUN_DIR="/var/run/meshd"
LOG_DIR="/var/log/mesh"
APP_DEST="/Applications/Mesh VPN.app"
APP_BUNDLE_ID="dev.meshvpn.macos"
PF_ANCHOR="com.internal.mesh"
SOCKETFILTERFW="/usr/libexec/ApplicationFirewall/socketfilterfw"

ACTION="install"
PURGE=0
DRY_RUN=0
REMOVE_APP=1
FROM_DIR="."
APP_SRC=""
PLIST_SRC=""
CHECKSUMS_FILE=""
MESHD_SHA256=""
MESH_CLI_SHA256=""
FIREWALL_OPTIN="ask"

usage() {
  cat <<'EOF'
Usage:
  sudo install-macos.sh [--from DIR] [--app PATH] [--plist FILE] [--sha256-file FILE]
                        [--yes-firewall | --no-firewall] [--dry-run]
  sudo install-macos.sh --uninstall [--purge | --purge-data] [--keep-app] [--dry-run]
EOF
}

run_cmd() {
  if [ "${DRY_RUN}" -eq 1 ]; then
    printf '[dry-run]'
    for arg in "$@"; do
      printf ' %s' "${arg}"
    done
    printf '\n'
    return 0
  fi
  "$@"
}

require_root() {
  if [ "${DRY_RUN}" -eq 1 ]; then
    return 0
  fi
  if [ "$(id -u)" -ne 0 ]; then
    echo "error: this script must be run as root (use sudo)." >&2
    exit 1
  fi
}

check_macos_platform() {
  if [ "$(uname -s)" != "Darwin" ]; then
    if [ "${DRY_RUN}" -eq 1 ]; then
      echo "[dry-run] non-macOS host detected ($(uname -s)); skipping Darwin checks."
      return 0
    fi
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
  if [ "${DRY_RUN}" -eq 1 ]; then
    echo "[dry-run] verify root-owned non-symlink ancestors for ${target_dir}"
    return 0
  fi
  check_path="${target_dir}"
  while [ -n "${check_path}" ]; do
    if [ -L "${check_path}" ]; then
      link_uid="$(/usr/bin/stat -f '%u' "${check_path}")"
      if [ "${link_uid}" -ne 0 ]; then
        echo "error: untrusted symlink in root install path '${check_path}' (uid=${link_uid})." >&2
        exit 1
      fi
      check_path="$(/bin/realpath "${check_path}")"
      continue
    fi
    if [ -e "${check_path}" ]; then
      owner_uid="$(/usr/bin/stat -f '%u' "${check_path}")"
      owner_gid="$(/usr/bin/stat -f '%g' "${check_path}")"
      perm_mode="$(/usr/bin/stat -f '%OLp' "${check_path}")"
      if [ "${owner_uid}" -ne 0 ]; then
        echo "error: directory '${check_path}' is not owned by root (uid=${owner_uid})." >&2
        exit 1
      fi
      is_macos_var_run=0
      if { [ "${check_path}" = "/var/run" ] || [ "${check_path}" = "/private/var/run" ]; } && [ "${owner_gid}" -eq 1 ]; then
        is_macos_var_run=1
      fi
      if [ "${is_macos_var_run}" -eq 1 ]; then
        world_write=$((0${perm_mode} & 002))
        if [ "${world_write}" -ne 0 ]; then
          echo "error: directory '${check_path}' is world writable (mode=${perm_mode})." >&2
          exit 1
        fi
      else
        group_world_write=$((0${perm_mode} & 022))
        if [ "${group_world_write}" -ne 0 ]; then
          echo "error: directory '${check_path}' is group/world writable (mode=${perm_mode})." >&2
          exit 1
        fi
      fi
    fi
    if [ "${check_path}" = "/" ]; then
      break
    fi
    check_path="$(dirname "${check_path}")"
  done
}

verify_installed_file_security() {
  target_path="$1"
  if [ "${DRY_RUN}" -eq 1 ]; then
    echo "[dry-run] verify mode & 0o022 == 0 and root ownership on ${target_path}"
    return 0
  fi
  if [ ! -e "${target_path}" ] || [ -L "${target_path}" ]; then
    echo "error: installed artifact '${target_path}' missing or symlink." >&2
    exit 1
  fi
  owner_uid="$(/usr/bin/stat -f '%u' "${target_path}")"
  perm_mode="$(/usr/bin/stat -f '%OLp' "${target_path}")"
  if [ "${owner_uid}" -ne 0 ]; then
    echo "error: artifact '${target_path}' not owned by root (uid=${owner_uid})." >&2
    exit 1
  fi
  group_world_write=$((0${perm_mode} & 022))
  if [ "${group_world_write}" -ne 0 ]; then
    echo "error: artifact '${target_path}' has group/world write bits (mode=${perm_mode})." >&2
    exit 1
  fi
}

ensure_valid_codesign() {
  target_path="$1"
  if [ "${DRY_RUN}" -eq 1 ]; then
    echo "[dry-run] verify codesign (or ad-hoc fallback) for ${target_path}"
    return 0
  fi
  if /usr/bin/codesign -v "${target_path}" >/dev/null 2>&1; then
    return 0
  fi
  /usr/bin/codesign --force -s - "${target_path}" >/dev/null
}

verify_sha256() {
  file_path="$1"
  expected_hash="$2"
  if [ "${DRY_RUN}" -eq 1 ]; then
    echo "[dry-run] verify SHA-256 of ${file_path}"
    return 0
  fi
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
  if [ "${DRY_RUN}" -eq 1 ]; then
    echo "[dry-run] inspect macOS firewall (opt-in=${FIREWALL_OPTIN})"
    return 0
  fi
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

resolve_app_source() {
  if [ -n "${APP_SRC}" ]; then
    return 0
  fi
  case "${FROM_DIR}" in
    */Contents/Resources|*/Contents/Resources/)
      bundle_root="$(dirname -- "$(dirname -- "${FROM_DIR}")")"
      if [ -d "${bundle_root}" ] && [ -f "${bundle_root}/Contents/Info.plist" ]; then
        APP_SRC="${bundle_root}"
        return 0
      fi
      ;;
  esac
  for candidate in \
    "${FROM_DIR}/Mesh VPN.app" \
    "$(dirname -- "${FROM_DIR}")/Mesh VPN.app"; do
    if [ -d "${candidate}" ]; then
      APP_SRC="${candidate}"
      return 0
    fi
  done
}

install_app_bundle_if_present() {
  resolve_app_source
  if [ -z "${APP_SRC}" ]; then
    return 0
  fi
  if [ ! -d "${APP_SRC}" ]; then
    if [ "${DRY_RUN}" -eq 1 ]; then
      echo "[dry-run] app bundle '${APP_SRC}' not found; skipping app install."
      return 0
    fi
    echo "error: app bundle '${APP_SRC}' not found." >&2
    exit 1
  fi

  verify_root_owned_ancestors "/Applications"
  if [ "${DRY_RUN}" -eq 1 ]; then
    echo "[dry-run] install '${APP_SRC}' -> '${APP_DEST}' (root:wheel, quarantine removed)"
    return 0
  fi

  real_src="$(/bin/realpath "${APP_SRC}" 2>/dev/null || printf '%s' "${APP_SRC}")"
  real_dest="$(/bin/realpath "${APP_DEST}" 2>/dev/null || printf '%s' "${APP_DEST}")"
  if [ "${real_src}" != "${real_dest}" ]; then
    tmp_app="${APP_DEST}.install.$$"
    /bin/rm -rf "${tmp_app}"
    /usr/bin/ditto "${APP_SRC}" "${tmp_app}"
    /usr/sbin/chown -R root:wheel "${tmp_app}"
    /bin/chmod -R go-w "${tmp_app}"
    /bin/rm -rf "${APP_DEST}"
    /bin/mv "${tmp_app}" "${APP_DEST}"
  else
    /usr/sbin/chown -R root:wheel "${APP_DEST}"
    /bin/chmod -R go-w "${APP_DEST}"
  fi

  /usr/bin/xattr -dr com.apple.quarantine "${APP_DEST}" >/dev/null 2>&1 || true
  ensure_valid_codesign "${APP_DEST}"
  verify_installed_file_security "${APP_DEST}"
  app_exec="${APP_DEST}/Contents/MacOS/Mesh VPN"
  if [ -f "${app_exec}" ]; then
    verify_installed_file_security "${app_exec}"
  fi
  echo "Installed ${APP_DEST}."
}

do_install() {
  require_root
  check_macos_platform

  if [ "${FROM_DIR}" = "." ] && [ ! -f "${FROM_DIR}/meshd" ] && [ -f "${REPO_ROOT}/meshd" ]; then
    FROM_DIR="${REPO_ROOT}"
  fi

  meshd_src="${FROM_DIR}/meshd"
  mesh_src="${FROM_DIR}/mesh"
  if [ -z "${PLIST_SRC}" ]; then
    for candidate in \
      "${FROM_DIR}/internal.mesh.meshd.plist" \
      "${FROM_DIR}/deploy/launchd/internal.mesh.meshd.plist" \
      "${SCRIPT_DIR}/internal.mesh.meshd.plist" \
      "${REPO_ROOT}/deploy/launchd/internal.mesh.meshd.plist"; do
      if [ -f "${candidate}" ]; then
        PLIST_SRC="${candidate}"
        break
      fi
    done
    if [ -z "${PLIST_SRC}" ]; then
      PLIST_SRC="${FROM_DIR}/deploy/launchd/internal.mesh.meshd.plist"
    fi
  fi
  if [ -z "${CHECKSUMS_FILE}" ] && [ -f "${FROM_DIR}/SHA256SUMS" ]; then
    CHECKSUMS_FILE="${FROM_DIR}/SHA256SUMS"
  fi

  if [ "${DRY_RUN}" -eq 0 ]; then
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
  fi

  verify_sha256 "${meshd_src}" "${MESHD_SHA256}"
  verify_sha256 "${mesh_src}" "${MESH_CLI_SHA256}"

  verify_root_owned_ancestors "/usr/local"
  verify_root_owned_ancestors "/Library/LaunchDaemons"
  verify_root_owned_ancestors "/var/db"

  run_cmd /usr/bin/install -d -o root -g wheel -m 0755 "${DAEMON_DIR}"
  run_cmd /usr/bin/install -d -o root -g wheel -m 0755 "/usr/local/bin"
  run_cmd /usr/bin/install -d -o root -g wheel -m 0700 "${STATE_DIR}"
  run_cmd /usr/bin/install -d -o root -g wheel -m 0755 "${RUN_DIR}"
  run_cmd /usr/bin/install -d -o root -g wheel -m 0750 "${LOG_DIR}"

  if [ "${DRY_RUN}" -eq 0 ]; then
    # Unload running daemon and unlink prior Mach-O binaries before install to avoid
    # Apple Silicon vnode code-signing invalidation (SIGKILL CODESIGNING).
    /bin/launchctl bootout "system/${LAUNCHD_LABEL}" >/dev/null 2>&1 || true
    /bin/rm -f "${DAEMON_BIN}" "${CLI_BIN}"
  else
    echo "[dry-run] /bin/launchctl bootout system/${LAUNCHD_LABEL}"
    echo "[dry-run] /bin/rm -f ${DAEMON_BIN} ${CLI_BIN}"
  fi

  run_cmd /usr/bin/install -o root -g wheel -m 0755 "${meshd_src}" "${DAEMON_BIN}"
  run_cmd /usr/bin/install -o root -g wheel -m 0755 "${mesh_src}" "${CLI_BIN}"
  run_cmd /usr/bin/install -o root -g wheel -m 0644 "${PLIST_SRC}" "${PLIST_DEST}"

  if [ "${DRY_RUN}" -eq 0 ]; then
    /usr/bin/xattr -d com.apple.quarantine "${DAEMON_BIN}" "${CLI_BIN}" >/dev/null 2>&1 || true
    ensure_valid_codesign "${DAEMON_BIN}"
    ensure_valid_codesign "${CLI_BIN}"
    /usr/bin/plutil -lint "${PLIST_DEST}" >/dev/null
    verify_installed_file_security "${DAEMON_BIN}"
    verify_installed_file_security "${CLI_BIN}"
    verify_installed_file_security "${PLIST_DEST}"
  else
    echo "[dry-run] strip quarantine, validate codesign, and verify mode & 0o022 == 0 on ${DAEMON_BIN}, ${CLI_BIN}, ${PLIST_DEST}"
  fi

  install_app_bundle_if_present
  inspect_and_configure_firewall

  if [ "${DRY_RUN}" -eq 0 ]; then
    /bin/launchctl bootout "system/${LAUNCHD_LABEL}" >/dev/null 2>&1 || true
    /bin/launchctl bootstrap system "${PLIST_DEST}"
    echo "Installed and started ${LAUNCHD_LABEL}."
  else
    echo "[dry-run] /bin/launchctl bootout system/${LAUNCHD_LABEL}"
    echo "[dry-run] /bin/launchctl bootstrap system ${PLIST_DEST}"
  fi
}

strip_hosts_block_preserving_symlink() {
  if [ "${DRY_RUN}" -eq 1 ]; then
    echo "[dry-run] strip '# BEGIN mesh ... # END mesh' block from /etc/hosts preserving symlink"
    return 0
  fi
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

quit_gui_app_gracefully() {
  if [ "${DRY_RUN}" -eq 1 ]; then
    echo "[dry-run] gracefully quit ${APP_BUNDLE_ID} (Mesh VPN.app)"
    return 0
  fi
  /usr/bin/osascript -e "tell application id \"${APP_BUNDLE_ID}\" to quit" >/dev/null 2>&1 || true
  wait_count=0
  while /usr/bin/pgrep -x "Mesh VPN" >/dev/null 2>&1 && [ "${wait_count}" -lt 10 ]; do
    /bin/sleep 0.2
    wait_count=$((wait_count + 1))
  done
  /usr/bin/pkill -x "Mesh VPN" >/dev/null 2>&1 || true
}

do_uninstall() {
  require_root
  check_macos_platform

  if [ "${DRY_RUN}" -eq 0 ]; then
    /bin/launchctl bootout "system/${LAUNCHD_LABEL}" >/dev/null 2>&1 || true
    if [ -x "${CLI_BIN}" ]; then
      "${CLI_BIN}" cleanup >/dev/null 2>&1 || true
    elif [ -x "${DAEMON_BIN}" ]; then
      "${DAEMON_BIN}" cleanup-stale >/dev/null 2>&1 || true
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
  else
    echo "[dry-run] /bin/launchctl bootout system/${LAUNCHD_LABEL}"
    echo "[dry-run] ${CLI_BIN} cleanup (or ${DAEMON_BIN} cleanup-stale)"
    echo "[dry-run] /sbin/pfctl -a ${PF_ANCHOR} -F all"
  fi

  strip_hosts_block_preserving_symlink

  run_cmd /bin/rm -f "${PLIST_DEST}" "${DAEMON_BIN}" "${CLI_BIN}"
  if [ "${DRY_RUN}" -eq 0 ]; then
    /bin/rmdir "${DAEMON_DIR}" >/dev/null 2>&1 || true
  fi
  run_cmd /bin/rm -rf "${RUN_DIR}" "${LOG_DIR}"
  run_cmd /bin/rm -f "${STATE_DIR}/ledger.json"

  if [ "${PURGE}" -eq 1 ]; then
    run_cmd /bin/rm -rf "${STATE_DIR}"
    echo "Uninstalled Mesh VPN daemon and purged node identity keys (${STATE_DIR})."
  else
    echo "Uninstalled Mesh VPN daemon (preserved ${STATE_DIR}/keys.json; pass --purge-data to remove)."
  fi

  if [ "${REMOVE_APP}" -eq 1 ] && [ -d "${APP_DEST}" ]; then
    quit_gui_app_gracefully
    run_cmd /bin/rm -rf "${APP_DEST}"
    echo "Removed ${APP_DEST}."
  elif [ "${DRY_RUN}" -eq 1 ] && [ "${REMOVE_APP}" -eq 1 ]; then
    quit_gui_app_gracefully
    echo "[dry-run] /bin/rm -rf '${APP_DEST}' (if present)"
  fi
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --from|--app|--plist|--sha256-file|--meshd-sha256|--mesh-sha256)
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
        --app) APP_SRC="${val}" ;;
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
    --purge|--purge-data)
      PURGE=1
      shift
      ;;
    --keep-app)
      REMOVE_APP=0
      shift
      ;;
    --remove-app)
      REMOVE_APP=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
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
