#!/usr/bin/env bash
set -euo pipefail

# Idempotent VPS installer for Mesh VPN Control, Blind Relay, and STUN server.
# Safe defaults:
# - Checks TCP & UDP port conflicts before modifying systemd units.
# - Runs mesh-server unprivileged as `mesh` (`Group=mesh-admin` for `/run/mesh-server` ACL).
# - Never enables a firewall deny policy unless `--enable-firewall` / `--enable-ufw` is passed.

PUBLIC_HOST=""
TCP_PORT=443
STUN_PORT=3478
OVERLAY_CIDR="100.115.0.0/16"
ENABLE_FIREWALL=0
BINARY_PATH="./target/release/mesh-server"
INSTALL_BIN="/usr/local/bin/mesh-server"
SERVICE_DEST="/etc/systemd/system/mesh-server.service"
CONFIG_DIR="/etc/mesh"
CONFIG_PATH="/etc/mesh/server.toml"
STATE_DIR="/var/lib/mesh"
ADMIN_SOCK="/run/mesh-server/admin.sock"

usage() {
  cat <<'EOF'
Usage: install-server.sh [OPTIONS]

Options:
  --public-host <IP_OR_HOST>   Public IP or hostname advertised to peers (auto-detected if omitted)
  --tcp-port <PORT>            Control/Relay HTTPS TCP port (default: 443)
  --stun-port <PORT>           Embedded STUN UDP port (default: 3478)
  --overlay-cidr <CIDR>        Overlay IPv4 CIDR >= 64 hosts (default: 100.115.0.0/16)
  --binary <PATH>              Path to compiled mesh-server binary
  --enable-firewall            Configure UFW explicitly keeping active SSH port open (alias: --enable-ufw)
  --enable-ufw                 Alias for --enable-firewall
  -h, --help                   Show this help message
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --public-host)
      PUBLIC_HOST="${2:-}"
      shift 2
      ;;
    --tcp-port)
      TCP_PORT="${2:-}"
      shift 2
      ;;
    --stun-port)
      STUN_PORT="${2:-}"
      shift 2
      ;;
    --overlay-cidr)
      OVERLAY_CIDR="${2:-}"
      shift 2
      ;;
    --binary)
      BINARY_PATH="${2:-}"
      shift 2
      ;;
    --enable-firewall|--enable-ufw)
      ENABLE_FIREWALL=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "Error: install-server.sh must be run as root (or via sudo)." >&2
  exit 1
fi

if [ ! -f "$BINARY_PATH" ]; then
  echo "Error: mesh-server binary not found at $BINARY_PATH" >&2
  exit 1
fi

detect_public_host() {
  local detected=""
  if command -v ip >/dev/null 2>&1; then
    detected="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n1 || true)"
  fi
  if [ -z "$detected" ]; then
    detected="127.0.0.1"
  fi
  printf '%s' "$detected"
}

check_port_available() {
  local proto="$1"
  local port="$2"
  local existing=""
  if command -v ss >/dev/null 2>&1; then
    if [ "$proto" = "tcp" ]; then
      existing="$(ss -ltnp "sport = :$port" 2>/dev/null | tail -n +2 || true)"
    else
      existing="$(ss -lunp "sport = :$port" 2>/dev/null | tail -n +2 || true)"
    fi
  elif command -v lsof >/dev/null 2>&1; then
    if [ "$proto" = "tcp" ]; then
      existing="$(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
    else
      existing="$(lsof -nP -iUDP:"$port" 2>/dev/null || true)"
    fi
  fi

  if [ -n "$existing" ] && ! printf '%s' "$existing" | grep -q 'mesh-server'; then
    echo "Error: $proto port $port is already bound by another process:" >&2
    printf '%s\n' "$existing" >&2
    echo "Resolve the conflict or pass --tcp-port / --stun-port cleanly." >&2
    exit 1
  fi
}

if [ -z "$PUBLIC_HOST" ]; then
  PUBLIC_HOST="$(detect_public_host)"
fi

echo "==> Checking port availability (TCP/$TCP_PORT, UDP/$STUN_PORT)..."
check_port_available tcp "$TCP_PORT"
check_port_available udp "$STUN_PORT"

echo "==> Ensuring mesh user and mesh-admin group exist..."
if ! getent group mesh-admin >/dev/null 2>&1; then
  groupadd --system mesh-admin
fi
if ! getent group mesh >/dev/null 2>&1; then
  groupadd --system mesh
fi
if ! id -u mesh >/dev/null 2>&1; then
  useradd --system --gid mesh --no-create-home --shell /usr/sbin/nologin mesh
fi
if ! id -nG mesh 2>/dev/null | grep -qw mesh-admin; then
  usermod -a -G mesh-admin mesh
fi

install -d -m 0750 -o root -g mesh "$CONFIG_DIR"
install -d -m 0700 -o mesh -g mesh "$STATE_DIR"
install -m 0755 -o root -g root "$BINARY_PATH" "$INSTALL_BIN"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
UNIT_SRC="$REPO_ROOT/deploy/systemd/mesh-server.service"
if [ -f "$UNIT_SRC" ]; then
  install -m 0644 -o root -g root "$UNIT_SRC" "$SERVICE_DEST"
fi

if [ ! -f "$CONFIG_PATH" ]; then
  cat >"$CONFIG_PATH" <<EOF
control_bind_ip = "0.0.0.0"
control_tcp_port = $TCP_PORT
stun_bind_ip = "0.0.0.0"
stun_udp_port = $STUN_PORT
obs_bind_addr = "127.0.0.1:9091"
overlay_cidr = "$OVERLAY_CIDR"
domain_suffix = "mesh.internal"
public_host = "$PUBLIC_HOST"
state_dir = "$STATE_DIR"
admin_socket_path = "$ADMIN_SOCK"
admin_group_name = "mesh-admin"
tls_mode = "ip_pinned"
EOF
  chown root:mesh "$CONFIG_PATH"
  chmod 0640 "$CONFIG_PATH"
fi

"$INSTALL_BIN" --config "$CONFIG_PATH" --check-config

if [ "$ENABLE_FIREWALL" -eq 1 ]; then
  if ! command -v ufw >/dev/null 2>&1; then
    echo "Error: --enable-firewall / --enable-ufw requested, but ufw is not installed." >&2
    exit 1
  fi
  SSH_PORT="$(ss -ltnp 2>/dev/null | awk '/sshd/ {split($4,a,":"); print a[length(a)]}' | head -n1 || true)"
  if [ -z "$SSH_PORT" ]; then
    SSH_PORT=22
  fi
  echo "==> Configuring UFW firewall (preserving SSH port $SSH_PORT)..."
  ufw allow "${SSH_PORT}/tcp" >/dev/null
  ufw allow "${TCP_PORT}/tcp" >/dev/null
  ufw allow "${STUN_PORT}/udp" >/dev/null
  ufw --force enable >/dev/null
fi

if command -v systemctl >/dev/null 2>&1 && [ -f "$SERVICE_DEST" ]; then
  systemctl daemon-reload
  systemctl enable mesh-server.service >/dev/null
  systemctl restart mesh-server.service

  READY=0
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if [ -S "$ADMIN_SOCK" ] && command -v curl >/dev/null 2>&1; then
      if curl -fsS http://127.0.0.1:9091/readyz >/dev/null 2>&1; then
        READY=1
        break
      fi
    fi
    sleep 1
  done

  if [ "$READY" -ne 1 ]; then
    echo "Warning: mesh-server did not report /readyz healthy within 10s; check journalctl -u mesh-server" >&2
  fi
fi

ACTIVE_PIN="<pending>"
if [ -S "$ADMIN_SOCK" ] && command -v curl >/dev/null 2>&1; then
  STATUS_JSON="$(curl -fsS --unix-socket "$ADMIN_SOCK" http://localhost/v1/admin/server/status 2>/dev/null || true)"
  PARSED_PIN="$(printf '%s' "$STATUS_JSON" | sed -n 's/.*"active_pin":"\([^"]*\)".*/\1/p' | head -n1 || true)"
  if [ -n "$PARSED_PIN" ]; then
    ACTIVE_PIN="$PARSED_PIN"
  fi
fi

cat <<EOF

====================================================================
Mesh VPN Server installed cleanly
====================================================================
Control HTTPS/Relay : https://${PUBLIC_HOST}:${TCP_PORT}
Embedded STUN UDP   : ${PUBLIC_HOST}:${STUN_PORT}
Active SPKI Pin     : ${ACTIVE_PIN}
Admin Socket        : ${ADMIN_SOCK}

Cloud Security Group reminder:
  Allow inbound TCP ${TCP_PORT} and UDP ${STUN_PORT} in your VPS/Cloud firewall.

Create your first pre-auth key (as root or member of mesh-admin):
  curl -sS -X POST --unix-socket ${ADMIN_SOCK} \\
    -H 'Content-Type: application/json' \\
    -d '{"ttl_secs":3600,"reusable":false,"max_uses":1,"is_ephemeral":false,"ephemeral_timeout_secs":null,"target_node":null}' \\
    http://localhost/v1/admin/preauth-keys

Client join command template (pass pre-auth key via stdin or a chmod 0600 --authkey-file ./preauth.key):
  printf '%s\n' '<PREAUTH_KEY>' | sudo mesh up --server ${PUBLIC_HOST}:${TCP_PORT} --server-pin ${ACTIVE_PIN} --authkey-stdin
  # Or using a protected 0600 key file (e.g., Windows/macOS):
  # mesh up --server ${PUBLIC_HOST}:${TCP_PORT} --server-pin ${ACTIVE_PIN} --authkey-file ./preauth.key
====================================================================
EOF
