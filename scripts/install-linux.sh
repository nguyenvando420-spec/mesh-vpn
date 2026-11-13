#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"

DAEMON_BIN="/usr/bin/meshd"
CLI_BIN="/usr/bin/mesh"
SERVICE_NAME="meshd.service"
SERVICE_DEST="/etc/systemd/system/${SERVICE_NAME}"
STATE_DIR="/var/lib/meshd"
RUN_DIR="/run/meshd"
LOG_DIR="/var/log/meshd"
TUN_IFNAME="mesh0"
NFT_TABLE="mesh_vpn"
IPT_CHAIN="MESH_VPN"
ADMIN_GROUP="mesh-admin"

ACTION="install"
PURGE=0
CONFIGURE_FIREWALL=1
FROM_DIR=""
UNIT_SRC=""
CHECKSUMS_FILE=""
MESHD_SHA256=""
MESH_CLI_SHA256=""

usage() {
  cat <<'EOF'
Usage:
  sudo install-linux.sh [--from DIR] [--unit FILE] [--sha256-file FILE] [--no-firewall]
  sudo install-linux.sh --uninstall [--purge]
EOF
}

log_info() {
  printf '[mesh-install] %s\n' "$1"
}

log_warn() {
  printf '[mesh-install] warning: %s\n' "$1" >&2
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "error: install-linux.sh must be run as root (use sudo)." >&2
    exit 1
  fi
}

check_linux_platform() {
  if [ "$(uname -s)" != "Linux" ]; then
    echo "error: unsupported OS $(uname -s); Linux desktop/server is required." >&2
    exit 1
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "error: systemd (systemctl) is required for meshd.service installation." >&2
    exit 1
  fi
  if [ ! -e /dev/net/tun ]; then
    log_warn "/dev/net/tun is not currently present; attempting modprobe tun"
    if command -v modprobe >/dev/null 2>&1; then
      modprobe tun 2>/dev/null || true
    fi
  fi
  if [ ! -c /dev/net/tun ]; then
    echo "error: /dev/net/tun character device is unavailable; load the 'tun' kernel module first." >&2
    exit 1
  fi
}

resolve_artifact() {
  name="$1"
  if [ -n "${FROM_DIR}" ]; then
    candidate="${FROM_DIR}/${name}"
    if [ -f "${candidate}" ]; then
      printf '%s' "${candidate}"
      return 0
    fi
  fi
  for dir in \
    "${SCRIPT_DIR}" \
    "${REPO_ROOT}" \
    "${REPO_ROOT}/target/release" \
    "${REPO_ROOT}/target/debug"; do
    candidate="${dir}/${name}"
    if [ -f "${candidate}" ]; then
      printf '%s' "${candidate}"
      return 0
    fi
  done
  return 1
}

resolve_unit_src() {
  if [ -n "${UNIT_SRC}" ] && [ -f "${UNIT_SRC}" ]; then
    printf '%s' "${UNIT_SRC}"
    return 0
  fi
  for candidate in \
    "${FROM_DIR}/deploy/linux-desktop/meshd-desktop.service" \
    "${FROM_DIR}/meshd-desktop.service" \
    "${SCRIPT_DIR}/meshd-desktop.service" \
    "${REPO_ROOT}/deploy/linux-desktop/meshd-desktop.service" \
    "${REPO_ROOT}/deploy/systemd/meshd.service"; do
    if [ -n "${candidate}" ] && [ -f "${candidate}" ]; then
      printf '%s' "${candidate}"
      return 0
    fi
  done
  return 1
}

compute_sha256() {
  target="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${target}" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${target}" | awk '{print $1}'
  else
    echo "error: neither sha256sum nor shasum is installed for integrity verification." >&2
    exit 1
  fi
}

lookup_checksum_in_file() {
  target_name="$1"
  sums_file="$2"
  awk -v name="${target_name}" '
    $2 == name || $2 == ("./" name) || $2 ~ ("/" name "$") {
      print tolower($1);
      exit 0;
    }
  ' "${sums_file}"
}

verify_sha256_if_configured() {
  file_path="$1"
  expected_hash="$2"
  if [ -z "${expected_hash}" ]; then
    return 0
  fi
  actual_hash="$(compute_sha256 "${file_path}")"
  if [ "${actual_hash}" != "${expected_hash}" ]; then
    echo "error: SHA-256 mismatch for '${file_path}' (expected '${expected_hash}', got '${actual_hash}')." >&2
    exit 1
  fi
}

ensure_admin_group() {
  if getent group "${ADMIN_GROUP}" >/dev/null 2>&1; then
    return 0
  fi
  if command -v groupadd >/dev/null 2>&1; then
    groupadd --system "${ADMIN_GROUP}"
  elif command -v addgroup >/dev/null 2>&1; then
    addgroup --system "${ADMIN_GROUP}"
  else
    log_warn "neither groupadd nor addgroup found; admin socket falls back to root:root 0600"
  fi
}

configure_desktop_firewall() {
  if [ "${CONFIGURE_FIREWALL}" -eq 0 ]; then
    log_info "skipping firewall configuration (--no-firewall)"
    return 0
  fi

  # Non-destructive firewall integration: never flush existing user, UFW, or Docker chains.
  if command -v nft >/dev/null 2>&1 && nft list tables >/dev/null 2>&1; then
    if nft list table inet "${NFT_TABLE}" >/dev/null 2>&1; then
      nft delete table inet "${NFT_TABLE}"
    fi
    nft -f - <<EOF
table inet ${NFT_TABLE} {
  chain input {
    type filter hook input priority filter; policy accept;
    iifname "${TUN_IFNAME}" accept comment "mesh-vpn-desktop"
  }
}
EOF
    log_info "configured isolated nftables table 'inet ${NFT_TABLE}' (existing rules untouched)"
    return 0
  fi

  if command -v iptables >/dev/null 2>&1; then
    iptables -N "${IPT_CHAIN}" 2>/dev/null || iptables -F "${IPT_CHAIN}"
    iptables -A "${IPT_CHAIN}" -i "${TUN_IFNAME}" -j ACCEPT
    iptables -A "${IPT_CHAIN}" -j RETURN
    while iptables -C INPUT -j "${IPT_CHAIN}" >/dev/null 2>&1; do
      iptables -D INPUT -j "${IPT_CHAIN}"
    done
    iptables -I INPUT 1 -j "${IPT_CHAIN}"
    log_info "configured isolated iptables chain '${IPT_CHAIN}' (existing rules untouched)"
    return 0
  fi

  log_info "no active nftables or iptables management tool detected; skipping firewall rule setup"
}

remove_desktop_firewall() {
  if command -v nft >/dev/null 2>&1 && nft list table inet "${NFT_TABLE}" >/dev/null 2>&1; then
    nft delete table inet "${NFT_TABLE}" || true
  fi

  if command -v iptables >/dev/null 2>&1; then
    while iptables -C INPUT -j "${IPT_CHAIN}" >/dev/null 2>&1; do
      iptables -D INPUT -j "${IPT_CHAIN}" || true
    done
    if iptables -L "${IPT_CHAIN}" >/dev/null 2>&1; then
      iptables -F "${IPT_CHAIN}" || true
      iptables -X "${IPT_CHAIN}" || true
    fi
  fi
}

do_install() {
  meshd_src="$(resolve_artifact "meshd")" || {
    echo "error: compiled 'meshd' binary not found (pass --from DIR)." >&2
    exit 1
  }
  mesh_cli_src="$(resolve_artifact "mesh")" || {
    echo "error: compiled 'mesh' CLI binary not found (pass --from DIR)." >&2
    exit 1
  }
  unit_src="$(resolve_unit_src)" || {
    echo "error: systemd desktop unit 'meshd-desktop.service' not found." >&2
    exit 1
  }

  if [ -n "${CHECKSUMS_FILE}" ]; then
    if [ ! -f "${CHECKSUMS_FILE}" ]; then
      echo "error: checksums file '${CHECKSUMS_FILE}' not found." >&2
      exit 1
    fi
    if [ -z "${MESHD_SHA256}" ]; then
      MESHD_SHA256="$(lookup_checksum_in_file "meshd" "${CHECKSUMS_FILE}" || true)"
    fi
    if [ -z "${MESH_CLI_SHA256}" ]; then
      MESH_CLI_SHA256="$(lookup_checksum_in_file "mesh" "${CHECKSUMS_FILE}" || true)"
    fi
  fi
  verify_sha256_if_configured "${meshd_src}" "${MESHD_SHA256}"
  verify_sha256_if_configured "${mesh_cli_src}" "${MESH_CLI_SHA256}"

  ensure_admin_group

  if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
    systemctl stop "${SERVICE_NAME}"
  fi

  install -d -m 0700 -o root -g root "${STATE_DIR}"
  install -d -m 0750 -o root -g root "${LOG_DIR}"
  install -d -m 0755 -o root -g root "${RUN_DIR}"

  install -m 0755 -o root -g root "${meshd_src}" "${DAEMON_BIN}"
  install -m 0755 -o root -g root "${mesh_cli_src}" "${CLI_BIN}"
  install -m 0644 -o root -g root "${unit_src}" "${SERVICE_DEST}"

  configure_desktop_firewall

  systemctl daemon-reload
  systemctl enable --now "${SERVICE_NAME}"
  log_info "installed '${SERVICE_NAME}' cleanly without modifying /etc/resolv.conf"
}

do_uninstall() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    systemctl stop "meshd-desktop.service" 2>/dev/null || true
    systemctl disable "meshd-desktop.service" 2>/dev/null || true
  fi

  if [ -x "${CLI_BIN}" ]; then
    "${CLI_BIN}" cleanup >/dev/null 2>&1 || true
  fi

  rm -f "${SERVICE_DEST}" "/etc/systemd/system/meshd-desktop.service"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload 2>/dev/null || true
  fi

  remove_desktop_firewall

  rm -f "${DAEMON_BIN}" "${CLI_BIN}"
  rm -rf "${RUN_DIR}"

  if [ "${PURGE}" -eq 1 ]; then
    rm -rf "${STATE_DIR}" "${LOG_DIR}"
    log_info "uninstalled Mesh VPN completely (--purge removed keys and state)"
  elif [ -d "${STATE_DIR}" ]; then
    rm -f "${STATE_DIR}/ledger.json" "${STATE_DIR}/netmap-cache.json"
    log_info "uninstalled Mesh VPN cleanly while preserving node keys in ${STATE_DIR}"
  fi
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --from)
      FROM_DIR="${2:-}"
      shift 2
      ;;
    --unit)
      UNIT_SRC="${2:-}"
      shift 2
      ;;
    --sha256-file)
      CHECKSUMS_FILE="${2:-}"
      shift 2
      ;;
    --meshd-sha256)
      MESHD_SHA256="$(printf '%s' "${2:-}" | tr '[:upper:]' '[:lower:]')"
      shift 2
      ;;
    --mesh-sha256)
      MESH_CLI_SHA256="$(printf '%s' "${2:-}" | tr '[:upper:]' '[:lower:]')"
      shift 2
      ;;
    --no-firewall)
      CONFIGURE_FIREWALL=0
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
      echo "error: unknown argument '$1'." >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_root
if [ "${ACTION}" = "uninstall" ]; then
  do_uninstall
else
  if [ "${PURGE}" -eq 1 ]; then
    echo "error: --purge can only be used together with --uninstall." >&2
    exit 2
  fi
  check_linux_platform
  do_install
fi
