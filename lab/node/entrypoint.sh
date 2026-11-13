#!/usr/bin/env bash
set -euo pipefail

# Lab node container entrypoint (non-privileged: NET_ADMIN + /dev/net/tun only).
# 1. Routes all traffic through the assigned NAT router (`LAB_ROUTER_IP`).
# 2. Initializes /var/lib/meshd, /var/run/meshd, /var/log/meshd, and libfaketime clock-jump file.
# 3. Supervises `meshd` so `kill -9 meshd` keeps the container inspectable and allows clean restarts.

ROUTER_IP="${LAB_ROUTER_IP:?LAB_ROUTER_IP must be set}"
NODE_NAME="${LAB_NODE_NAME:-$(hostname)}"
ENABLE_FAKETIME="${LAB_ENABLE_FAKETIME:-1}"
AUTO_RESTART="${LAB_AUTO_RESTART:-1}"
STATE_DIR="${MESH_STATE_DIR:-/var/lib/meshd}"
RUN_DIR="/var/run/meshd"
LOG_DIR="/var/log/meshd"
FAKETIME_FILE="${STATE_DIR}/faketime.rc"
PAUSE_FLAG="${STATE_DIR}/supervisor.paused"

install -d -m 0700 -o root -g root "${STATE_DIR}"
install -d -m 0755 -o root -g root "${RUN_DIR}"
install -d -m 0750 -o root -g root "${LOG_DIR}"

if [ ! -f "${FAKETIME_FILE}" ]; then
  printf '+0s\n' > "${FAKETIME_FILE}"
  chmod 0644 "${FAKETIME_FILE}"
fi
rm -f "${PAUSE_FLAG}"

# Point default gateway to the simulated NAT router on the LAN interface.
# Docker bridge networks mark `internal: true`, so replace or add default route via ROUTER_IP.
LAN_IF="$(ip -4 route show to match "${ROUTER_IP}" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' || true)"
if [ -n "${LAN_IF}" ]; then
  ip route replace default via "${ROUTER_IP}" dev "${LAN_IF}"
else
  ip route replace default via "${ROUTER_IP}"
fi

FAKETIME_LIB="$(find /usr/lib -name 'libfaketime.so.1' 2>/dev/null | head -n1 || true)"

MESHD_PID=""
STOP_REQUESTED=0

handle_sigterm() {
  STOP_REQUESTED=1
  if [ -n "${MESHD_PID}" ] && kill -0 "${MESHD_PID}" 2>/dev/null; then
    kill -TERM "${MESHD_PID}" 2>/dev/null || true
    # Respect Graceful Shutdown <= 5s budget.
    for _ in $(seq 1 50); do
      if ! kill -0 "${MESHD_PID}" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    if kill -0 "${MESHD_PID}" 2>/dev/null; then
      kill -KILL "${MESHD_PID}" 2>/dev/null || true
    fi
  fi
  exit 0
}

trap handle_sigterm TERM INT

start_meshd() {
  if [ "${ENABLE_FAKETIME}" = "1" ] && [ -n "${FAKETIME_LIB}" ]; then
    LD_PRELOAD="${FAKETIME_LIB}" \
    FAKETIME_TIMESTAMP_FILE="${FAKETIME_FILE}" \
    FAKETIME_NO_CACHE=1 \
    FAKETIME_DONT_FAKE_MONOTONIC=1 \
    MESH_STATE_DIR="${STATE_DIR}" \
    MESH_NODE_NAME="${NODE_NAME}" \
      /usr/local/bin/meshd >> "${LOG_DIR}/meshd.log" 2>&1 &
  else
    MESH_STATE_DIR="${STATE_DIR}" \
    MESH_NODE_NAME="${NODE_NAME}" \
      /usr/local/bin/meshd >> "${LOG_DIR}/meshd.log" 2>&1 &
  fi
  MESHD_PID=$!
}

# Wait until `/dev/net/tun` is ready, then run supervised `meshd` loop.
if [ ! -c /dev/net/tun ]; then
  echo "ERROR: /dev/net/tun device missing inside container (${NODE_NAME})" >&2
  exit 1
fi

while [ "${STOP_REQUESTED}" -eq 0 ]; do
  if [ -f "${PAUSE_FLAG}" ]; then
    sleep 0.5
    continue
  fi

  if [ -z "${MESHD_PID}" ] || ! kill -0 "${MESHD_PID}" 2>/dev/null; then
    start_meshd
  fi

  wait "${MESHD_PID}" || true
  MESHD_PID=""

  if [ "${STOP_REQUESTED}" -eq 1 ]; then
    break
  fi
  if [ "${AUTO_RESTART}" != "1" ] || [ -f "${PAUSE_FLAG}" ]; then
    sleep 0.5
  else
    sleep 1
  fi
done
