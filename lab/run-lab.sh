#!/usr/bin/env bash
set -euo pipefail

# One-command lifecycle manager for the Mesh VPN NAT & Chaos Lab (US-057 AC1/AC4).
# Enforces non-privileged container execution (NET_ADMIN + /dev/net/tun only) and
# guarantees 100% clean host network/container teardown on `down` / `clean`.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.nat-lab.yml"
TMP_DIR="${SCRIPT_DIR}/.tmp"
BASELINE_FILE="${TMP_DIR}/host-baseline.txt"

CMD="${1:-up}"
shift || true

TCP_PORT="${MESH_CONTROL_TCP_PORT:-443}"
STUN_PORT="${MESH_STUN_UDP_PORT:-3478}"
TLS_MODE="${MESH_TLS_MODE:-ip_pinned}"
TOPOLOGY="${LAB_TOPOLOGY:-default}"
NO_BUILD=0
SKIP_BOOTSTRAP=0

usage() {
  cat <<'EOF'
Usage: lab/run-lab.sh <up|down|clean|status|logs> [OPTIONS]

Options (for `up`):
  --tcp-port <PORT>      Control/Relay TCP port (default: 443; e.g., 8443)
  --stun-port <PORT>     Embedded STUN UDP port (default: 3478; e.g., 3479)
  --tls-mode <MODE>      ip_pinned (default) | reverse_proxy
  --topology <NAME>      default | mixed | udp-block | 443-only | 80-443-only
  --no-build             Skip `docker compose build`
  --skip-bootstrap       Start containers without registering nodes automatically
  -h, --help             Show this help message
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --tcp-port)
      TCP_PORT="${2:?--tcp-port requires value}"
      shift 2
      ;;
    --stun-port)
      STUN_PORT="${2:?--stun-port requires value}"
      shift 2
      ;;
    --tls-mode)
      TLS_MODE="${2:?--tls-mode requires value}"
      shift 2
      ;;
    --topology)
      TOPOLOGY="${2:?--topology requires value}"
      shift 2
      ;;
    --no-build)
      NO_BUILD=1
      shift
      ;;
    --skip-bootstrap)
      SKIP_BOOTSTRAP=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      if [ "${CMD}" = "logs" ]; then
        LOG_TARGET="$1"
        shift
      else
        echo "ERROR: unknown argument '$1'" >&2
        usage >&2
        exit 2
      fi
      ;;
  esac
done

compose_cmd() {
  local profile_args=()
  if [ "${TLS_MODE}" = "reverse_proxy" ]; then
    profile_args+=(--profile reverse-proxy)
  fi
  docker compose "${profile_args[@]}" -f "${COMPOSE_FILE}" "$@"
}

apply_topology_env() {
  case "${TOPOLOGY}" in
    default)
      export ROUTER_1_MODE="${ROUTER_1_MODE:-eim}"
      export ROUTER_2_MODE="${ROUTER_2_MODE:-eim}"
      export ROUTER_3_MODE="${ROUTER_3_MODE:-apdm}"
      export ROUTER_4_MODE="${ROUTER_4_MODE:-eim}"
      export ROUTER_5_MODE="${ROUTER_5_MODE:-eim}"
      ;;
    mixed)
      export ROUTER_1_MODE="eim"
      export ROUTER_2_MODE="apdm"
      export ROUTER_3_MODE="udp-block"
      export ROUTER_4_MODE="mtu-1400"
      export ROUTER_5_MODE="eim"
      ;;
    udp-block|443-only|80-443-only)
      export ROUTER_1_MODE="${TOPOLOGY}"
      export ROUTER_2_MODE="${TOPOLOGY}"
      export ROUTER_3_MODE="${TOPOLOGY}"
      export ROUTER_4_MODE="${TOPOLOGY}"
      export ROUTER_5_MODE="${TOPOLOGY}"
      ;;
    *)
      echo "ERROR: unknown topology '${TOPOLOGY}'" >&2
      exit 2
      ;;
  esac
}

capture_host_baseline() {
  mkdir -p "${TMP_DIR}"
  if [ ! -f "${BASELINE_FILE}" ]; then
    {
      echo "# Host network baseline captured at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
      if command -v ip >/dev/null 2>&1; then
        echo "--- ip route ---"
        ip route show || true
        echo "--- ip rule ---"
        ip rule show || true
      fi
    } > "${BASELINE_FILE}"
  fi
}

verify_zero_compose_privilege() {
  if grep -Eq '^[[:space:]]*privileged:[[:space:]]*true' "${COMPOSE_FILE}"; then
    echo "SECURITY ERROR: privileged: true is strictly forbidden in ${COMPOSE_FILE}" >&2
    exit 1
  fi
}

wait_for_vps_ready() {
  echo "==> Waiting for mesh-server /readyz inside mesh-lab-vps..."
  for _ in $(seq 1 30); do
    if docker exec mesh-lab-vps curl -fsS http://127.0.0.1:9091/readyz >/dev/null 2>&1; then
      echo "    mesh-server is ready."
      return 0
    fi
    sleep 1
  done
  echo "ERROR: mesh-server did not become ready within 30s." >&2
  docker logs --tail 50 mesh-lab-vps >&2 || true
  exit 1
}

wait_for_node_sockets() {
  echo "==> Waiting for /var/run/meshd/meshd-admin.sock on node-1..5 (timeout 15s)..."
  for idx in 1 2 3 4 5; do
    local container="mesh-lab-node-${idx}"
    local ready=0
    for _ in $(seq 1 30); do
      if docker exec "${container}" test -S /var/run/meshd/meshd-admin.sock 2>/dev/null; then
        ready=1
        break
      fi
      sleep 0.5
    done
    if [ "${ready}" -ne 1 ]; then
      echo "ERROR: ${container} did not expose /var/run/meshd/meshd-admin.sock within 15s." >&2
      docker exec "${container}" cat /var/log/meshd/meshd.log 2>/dev/null || true
      exit 1
    fi
  done
  echo "    All 5 node admin IPC sockets are ready."
}

bootstrap_nodes() {
  wait_for_node_sockets

  local endpoint_host="172.28.0.10"
  local endpoint_port="${TCP_PORT}"
  local pin=""

  if [ "${TLS_MODE}" = "reverse_proxy" ]; then
    endpoint_host="vpn.mesh.internal"
    echo "==> Waiting for Reverse Proxy Lab Root CA and TLS listener on 172.28.0.12:${endpoint_port}..."
    local ca_ready=0
    for _ in $(seq 1 30); do
      if docker exec mesh-lab-node-1 test -s /etc/mesh/lab-ca/ca.crt 2>/dev/null \
        && docker exec mesh-lab-node-1 nc -z 172.28.0.12 "${endpoint_port}" 2>/dev/null; then
        ca_ready=1
        break
      fi
      sleep 0.5
    done
    if [ "${ca_ready}" -ne 1 ]; then
      echo "ERROR: Reverse Proxy CA cert or TLS listener did not become ready within 15s." >&2
      docker logs --tail 50 mesh-lab-vps-proxy >&2 || true
      exit 1
    fi
    echo "    Server endpoint : ${endpoint_host}:${endpoint_port} (SystemCA via Lab Root CA)"
  else
    echo "==> Fetching Control SPKI pin from /run/mesh-server/admin.sock..."
    local status_json
    status_json="$(docker exec mesh-lab-vps curl -fsS --unix-socket /run/mesh-server/admin.sock http://localhost/v1/admin/server/status)"
    pin="$(printf '%s' "${status_json}" | jq -r '.active_pin // empty')"
    if [ -z "${pin}" ]; then
      echo "ERROR: failed to obtain active SPKI pin from lab server." >&2
      exit 1
    fi
    echo "    Server endpoint : ${endpoint_host}:${endpoint_port}"
    echo "    Active SPKI pin : ${pin}"
  fi

  for idx in 1 2 3 4 5; do
    local node="node-${idx}"
    local container="mesh-lab-${node}"

    if [ "${TLS_MODE}" = "reverse_proxy" ]; then
      docker exec "${container}" sh -c '
        set -eu
        cp /etc/mesh/lab-ca/ca.crt /usr/local/share/ca-certificates/mesh-lab-ca.crt
        update-ca-certificates >/dev/null
        if ! grep -Eq "[[:space:]]vpn\.mesh\.internal([[:space:]]|$)" /etc/hosts; then
          printf "172.28.0.12 vpn.mesh.internal\n" >> /etc/hosts
        fi
      '
    fi

    local key_json
    key_json="$(docker exec mesh-lab-vps curl -fsS -X POST \
      --unix-socket /run/mesh-server/admin.sock \
      -H 'Content-Type: application/json' \
      -d '{"ttl_secs":3600,"reusable":false,"max_uses":1,"is_ephemeral":false,"ephemeral_timeout_secs":null,"target_node":null}' \
      http://localhost/v1/admin/preauth-keys)"
    local raw_key
    raw_key="$(printf '%s' "${key_json}" | jq -r '.raw_key // empty')"
    if [ -z "${raw_key}" ]; then
      echo "ERROR: failed creating pre-auth key for ${node}" >&2
      exit 1
    fi

    echo "==> Registering ${node} via mesh up (authkey-file, zero argv key leak)..."
    if [ "${TLS_MODE}" = "reverse_proxy" ]; then
      docker exec "${container}" sh -c '
        set -eu
        umask 077
        printf "%s\n" "$1" > /run/mesh-preauth.key
        trap "rm -f /run/mesh-preauth.key" EXIT
        /usr/local/bin/mesh up \
          --server "$2" \
          --ca-tls \
          --authkey-file /run/mesh-preauth.key \
          --name "$3"
      ' sh "${raw_key}" "${endpoint_host}:${endpoint_port}" "${node}"
    else
      docker exec "${container}" sh -c '
        set -eu
        umask 077
        printf "%s\n" "$1" > /run/mesh-preauth.key
        trap "rm -f /run/mesh-preauth.key" EXIT
        /usr/local/bin/mesh up \
          --server "$2" \
          --server-pin "$3" \
          --authkey-file /run/mesh-preauth.key \
          --name "$4"
      ' sh "${raw_key}" "${endpoint_host}:${endpoint_port}" "${pin}" "${node}"
    fi
  done

  echo "==> Waiting for all 5 nodes to converge on /v1/netmap/stream (5 peers each, timeout 20s)..."
  for idx in 1 2 3 4 5; do
    local container="mesh-lab-node-${idx}"
    local converged=0
    for _ in $(seq 1 40); do
      if docker exec "${container}" /usr/local/bin/mesh status --json 2>/dev/null \
        | jq -e '.daemon_state == "connected" and .server_connection.control_connected == true and ((.peers | length) >= 5)' >/dev/null 2>&1; then
        converged=1
        break
      fi
      sleep 0.5
    done
    if [ "${converged}" -ne 1 ]; then
      echo "ERROR: ${container} failed to converge on 5-node netmap within 20s." >&2
      docker exec "${container}" /usr/local/bin/mesh status --json >&2 || true
      docker exec "${container}" tail -n 60 /var/log/meshd/meshd.log >&2 || true
      exit 1
    fi
  done
  echo "    All 5 nodes connected and converged on 5-peer Netmap."
}

do_up() {
  verify_zero_compose_privilege
  capture_host_baseline
  apply_topology_env

  export MESH_CONTROL_TCP_PORT="${TCP_PORT}"
  export MESH_PROXY_TCP_PORT="${TCP_PORT}"
  export MESH_STUN_UDP_PORT="${STUN_PORT}"
  export MESH_TLS_MODE="${TLS_MODE}"
  if [ "${TLS_MODE}" = "reverse_proxy" ]; then
    export MESH_PUBLIC_HOST="vpn.mesh.internal"
    export LAB_VPS_IP="172.28.0.12"
  else
    export MESH_PUBLIC_HOST="172.28.0.10"
    export LAB_VPS_IP="172.28.0.10"
  fi

  if [ "${NO_BUILD}" -eq 0 ]; then
    echo "==> Building lab images (non-privileged NET_ADMIN + unprivileged mesh-server)..."
    compose_cmd build
  fi

  echo "==> Starting 1 VPS + 5 NAT routers + 5 Linux nodes (topology=${TOPOLOGY}, tls=${TLS_MODE}, tcp=${TCP_PORT}, udp=${STUN_PORT})..."
  compose_cmd up -d

  wait_for_vps_ready

  if [ "${SKIP_BOOTSTRAP}" -eq 0 ]; then
    bootstrap_nodes
  else
    echo "==> Skipping automatic node registration (--skip-bootstrap)."
  fi

  echo "==> Lab is UP."
}

do_down() {
  echo "==> Tearing down Mesh NAT Lab containers, networks, and volumes..."
  docker compose --profile reverse-proxy -f "${COMPOSE_FILE}" down -v --remove-orphans

  # Verify zero leftover lab containers or networks on host (US-057 AC4).
  local leftover_containers leftover_nets
  leftover_containers="$(docker ps -aq --filter 'name=^mesh-lab-' || true)"
  if [ -n "${leftover_containers}" ]; then
    echo "ERROR: leftover lab containers detected: ${leftover_containers}" >&2
    exit 1
  fi
  leftover_nets="$(docker network ls -q --filter 'name=^mesh-nat-lab' || true)"
  if [ -n "${leftover_nets}" ]; then
    echo "ERROR: leftover lab networks detected: ${leftover_nets}" >&2
    exit 1
  fi

  if [ -f "${BASELINE_FILE}" ] && command -v ip >/dev/null 2>&1; then
    local after_routes
    after_routes="$(ip route show || true)"
    if printf '%s\n' "${after_routes}" | grep -q '100\.115\.'; then
      echo "ERROR: host routing table polluted with lab overlay CIDR!" >&2
      exit 1
    fi
  fi

  rm -rf "${TMP_DIR}"
  echo "==> Clean teardown complete (0 leftover containers, networks, or host routes)."
}

do_status() {
  compose_cmd ps
  echo "--- Routers ---"
  for idx in 1 2 3 4 5; do
    if docker inspect -f '{{.State.Running}}' "mesh-lab-router-${idx}" 2>/dev/null | grep -q true; then
      printf 'router-%s: ' "${idx}"
      docker exec "mesh-lab-router-${idx}" /usr/local/bin/router-entrypoint.sh ctl status || true
    fi
  done
  echo "--- Nodes ---"
  for idx in 1 2 3 4 5; do
    if docker inspect -f '{{.State.Running}}' "mesh-lab-node-${idx}" 2>/dev/null | grep -q true; then
      echo "[node-${idx}]"
      docker exec "mesh-lab-node-${idx}" /usr/local/bin/mesh status || true
    fi
  done
}

case "${CMD}" in
  up) do_up ;;
  down|clean) do_down ;;
  status) do_status ;;
  logs)
    compose_cmd logs -f --tail=100 ${LOG_TARGET:-}
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    echo "ERROR: unknown command '${CMD}'" >&2
    usage >&2
    exit 2
    ;;
esac
