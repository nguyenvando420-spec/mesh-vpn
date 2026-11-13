#!/usr/bin/env bash
set -euo pipefail

# Unprivileged container entrypoint for `mesh-server` in the NAT lab.
# Generates /var/lib/mesh/server.toml from environment variables while preserving
# persistent redb identity/state inside /var/lib/mesh.

CONFIG_PATH="${MESH_SERVER_CONFIG:-/var/lib/mesh/server.toml}"
STATE_DIR="${MESH_STATE_DIR:-/var/lib/mesh}"
CONTROL_BIND_IP="${MESH_CONTROL_BIND_IP:-0.0.0.0}"
CONTROL_TCP_PORT="${MESH_CONTROL_TCP_PORT:-443}"
STUN_BIND_IP="${MESH_STUN_BIND_IP:-0.0.0.0}"
STUN_UDP_PORT="${MESH_STUN_UDP_PORT:-3478}"
OBS_BIND_ADDR="${MESH_OBS_BIND_ADDR:-127.0.0.1:9091}"
OVERLAY_CIDR="${MESH_OVERLAY_CIDR:-100.115.0.0/16}"
DOMAIN_SUFFIX="${MESH_DOMAIN_SUFFIX:-mesh.internal}"
PUBLIC_HOST="${MESH_PUBLIC_HOST:-172.28.0.10}"
TLS_MODE="${MESH_TLS_MODE:-ip_pinned}"
TRUSTED_PROXY_IP="${MESH_TRUSTED_PROXY_IP:-172.28.0.12}"

mkdir -p "$(dirname "${CONFIG_PATH}")" "${STATE_DIR}"

TRUSTED_PROXIES_LINE="trusted_proxies = []"
if [ "${TLS_MODE}" = "reverse_proxy" ]; then
  TRUSTED_PROXIES_LINE="trusted_proxies = [\"${TRUSTED_PROXY_IP}\"]"
fi

cat > "${CONFIG_PATH}" <<EOF
control_bind_ip = "${CONTROL_BIND_IP}"
control_tcp_port = ${CONTROL_TCP_PORT}
stun_bind_ip = "${STUN_BIND_IP}"
stun_udp_port = ${STUN_UDP_PORT}
obs_bind_addr = "${OBS_BIND_ADDR}"
obs_allow_non_loopback = false
overlay_cidr = "${OVERLAY_CIDR}"
domain_suffix = "${DOMAIN_SUFFIX}"
public_host = "${PUBLIC_HOST}"
state_dir = "${STATE_DIR}"
admin_socket_path = "/run/mesh-server/admin.sock"
admin_group_name = "mesh-admin"
tls_mode = "${TLS_MODE}"
${TRUSTED_PROXIES_LINE}
EOF

chmod 0640 "${CONFIG_PATH}"

/usr/local/bin/mesh-server --config "${CONFIG_PATH}" --check-config
exec /usr/local/bin/mesh-server --config "${CONFIG_PATH}"
