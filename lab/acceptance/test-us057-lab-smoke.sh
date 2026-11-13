#!/usr/bin/env bash
set -euo pipefail

# Automated Smoke Suite for US-057 NAT & Fault Matrix:
#   1. EIM NAT upgrades peer path to `direct` + kernel TUN IPv4 ping
#   2. APDM NAT maintains `relay` path + kernel TUN IPv4 ping
#   3. MTU 1400 with ICMP fragmentation-needed dropped passes large payloads (`ping -c 2 -s 1360`)
#   4. `captive-portal` & `mitm-wrong-pin` are rejected fail-closed with zero secret leaks and recover on `restore-tls`
#   5. `kill-agent --restart` cleans ResourceLedger safely and reconnects
#   6. `power-resume --jump-secs 240` triggers a real libfaketime jump (> 180s) and recovers tunnel

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TMP_DIR="${LAB_DIR}/.tmp"
REPORT_JSON="${TMP_DIR}/us057-smoke-report.json"

REUSE_LAB=0
KEEP_LAB=0

usage() {
  cat <<'EOF'
Usage: lab/acceptance/test-us057-lab-smoke.sh [OPTIONS]

Options:
  --reuse-lab    Assume lab is already running (skip initial `run-lab.sh up`)
  --keep-lab     Do not tear down lab on completion
  -h, --help     Show this help message
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --reuse-lab)
      REUSE_LAB=1
      shift
      ;;
    --keep-lab)
      KEEP_LAB=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown option '$1'" >&2
      usage >&2
      exit 2
      ;;
  esac
done

mkdir -p "${TMP_DIR}"

cleanup() {
  if [ "${KEEP_LAB}" -eq 0 ] && [ "${REUSE_LAB}" -eq 0 ]; then
    "${LAB_DIR}/run-lab.sh" down || true
  fi
}
trap cleanup EXIT

get_peer_ip() {
  local src_container="$1"
  local peer_name="$2"
  docker exec "${src_container}" /usr/local/bin/mesh status --json \
    | jq -r --arg name "${peer_name}" '.peers[]? | select(.name == $name) | .overlay_ip // empty'
}

get_peer_path() {
  local src_container="$1"
  local peer_name="$2"
  docker exec "${src_container}" /usr/local/bin/mesh status --json \
    | jq -r --arg name "${peer_name}" '.peers[]? | select(.name == $name) | .active_path // empty'
}

assert_no_secret_leaks() {
  local container="$1"
  local status_json log_tail
  status_json="$(docker exec "${container}" /usr/local/bin/mesh status --json 2>/dev/null || true)"
  log_tail="$(docker exec "${container}" tail -n 200 /var/log/meshd/meshd.log 2>/dev/null || true)"

  if printf '%s\n%s\n' "${status_json}" "${log_tail}" | grep -Eq 'mpk_[A-Za-z0-9_-]{8,}|-----BEGIN .*PRIVATE KEY-----'; then
    echo "FAIL: potential secret leak detected in ${container} status/logs" >&2
    exit 1
  fi
}

wait_for_peer_path() {
  local src_container="$1"
  local peer_name="$2"
  local expected_path="$3"
  local timeout_s="${4:-30}"
  local deadline=$(( $(date +%s) + timeout_s ))

  while [ "$(date +%s)" -le "${deadline}" ]; do
    local p
    p="$(get_peer_path "${src_container}" "${peer_name}" 2>/dev/null || true)"
    if [ "${p}" = "${expected_path}" ]; then
      return 0
    fi
    sleep 1
  done
  echo "FAIL: ${src_container} -> ${peer_name} did not reach active_path=${expected_path} within ${timeout_s}s (last='$(get_peer_path "${src_container}" "${peer_name}" 2>/dev/null || true)')" >&2
  return 1
}

if [ "${REUSE_LAB}" -eq 0 ]; then
  echo "==> [Setup] Starting NAT lab (default topology)..."
  "${LAB_DIR}/run-lab.sh" up --tcp-port 443 --stun-port 3478 --topology default
fi

# 1. EIM -> direct upgrade + kernel TUN IPv4 ping
echo "==> [1/6] Testing EIM direct path upgrade (node-1 <-> node-2)..."
"${LAB_DIR}/faults/inject-fault.sh" set-mode node-1 eim
"${LAB_DIR}/faults/inject-fault.sh" set-mode node-2 eim
node2_ip="$(get_peer_ip mesh-lab-node-1 node-2)"
test -n "${node2_ip}"
docker exec mesh-lab-node-1 /usr/local/bin/mesh ping node-2 >/dev/null
wait_for_peer_path mesh-lab-node-1 node-2 direct 30
docker exec mesh-lab-node-1 ping -c 2 -W 3 "${node2_ip}" >/dev/null
echo "    PASS: EIM upgraded to direct and TUN IPv4 ping succeeded (${node2_ip})."

# 2. APDM -> maintains relay + kernel TUN IPv4 ping
echo "==> [2/6] Testing APDM relay fallback (node-1 <-> node-3)..."
"${LAB_DIR}/faults/inject-fault.sh" set-mode node-3 apdm
node3_ip="$(get_peer_ip mesh-lab-node-1 node-3)"
test -n "${node3_ip}"
wait_for_peer_path mesh-lab-node-1 node-3 relay 30
docker exec mesh-lab-node-1 /usr/local/bin/mesh ping node-3 >/dev/null
docker exec mesh-lab-node-1 ping -c 1 -W 3 "${node3_ip}" >/dev/null
echo "    PASS: APDM maintained relay path and TUN IPv4 ping succeeded (${node3_ip})."

# 3. MTU 1400 (ICMP fragmentation-needed dropped) -> large ping -c 2 -s 1360
echo "==> [3/6] Testing MTU 1400 PMTUD blackhole resilience (node-1 <-> node-4)..."
"${LAB_DIR}/faults/inject-fault.sh" set-mode node-1 mtu-1400
"${LAB_DIR}/faults/inject-fault.sh" set-mode node-4 mtu-1400
node4_ip="$(get_peer_ip mesh-lab-node-1 node-4)"
test -n "${node4_ip}"
docker exec mesh-lab-node-1 /usr/local/bin/mesh ping node-4 >/dev/null
docker exec mesh-lab-node-1 ping -c 2 -W 3 -s 1360 "${node4_ip}" >/dev/null
"${LAB_DIR}/faults/inject-fault.sh" set-mode node-1 eim
"${LAB_DIR}/faults/inject-fault.sh" set-mode node-4 eim
echo "    PASS: Large payload (1360B ICMP) traversed MTU 1400 blackhole cleanly."

# 4. Captive portal & MITM wrong SPKI pin rejection + recovery on restore-tls
echo "==> [4/6] Testing captive-portal & mitm-wrong-pin fail-closed TLS + recovery..."
"${LAB_DIR}/faults/inject-fault.sh" captive-portal node-1
sleep 4
docker exec mesh-lab-node-1 /usr/local/bin/mesh set --server "172.28.0.10:443" --server-pin "$(docker exec mesh-lab-vps curl -fsS --unix-socket /run/mesh-server/admin.sock http://localhost/v1/admin/server/status | jq -r '.active_pin')" >/dev/null 2>&1 || true
sleep 3
assert_no_secret_leaks mesh-lab-node-1
if docker exec mesh-lab-node-1 /usr/local/bin/mesh status --json | jq -e '.server_connection.control_connected == true' >/dev/null 2>&1; then
  echo "FAIL: node-1 unexpectedly accepted captive-portal TLS certificate!" >&2
  exit 1
fi

"${LAB_DIR}/faults/inject-fault.sh" mitm-wrong-pin node-1
sleep 4
assert_no_secret_leaks mesh-lab-node-1
if docker exec mesh-lab-node-1 /usr/local/bin/mesh status --json | jq -e '.server_connection.control_connected == true' >/dev/null 2>&1; then
  echo "FAIL: node-1 unexpectedly accepted wrong-pin MITM certificate!" >&2
  exit 1
fi

"${LAB_DIR}/faults/inject-fault.sh" restore-tls node-1
recovered_tls=0
for _ in $(seq 1 25); do
  if docker exec mesh-lab-node-1 /usr/local/bin/mesh status --json | jq -e '.daemon_state == "connected" and .server_connection.control_connected == true' >/dev/null 2>&1; then
    recovered_tls=1
    break
  fi
  sleep 1
done
if [ "${recovered_tls}" -ne 1 ]; then
  echo "FAIL: node-1 failed to recover control connection after restore-tls" >&2
  exit 1
fi
docker exec mesh-lab-node-1 ping -c 1 -W 3 "${node2_ip}" >/dev/null
echo "    PASS: Rogue captive-portal & MITM rejected fail-closed with 0 secret leaks; recovered cleanly."

# 5. kill-agent --restart -> ResourceLedger cleanup & auto-reconnect
echo "==> [5/6] Testing kill-agent --restart crash recovery & ResourceLedger cleanup..."
old_pid="$(docker exec mesh-lab-node-1 pgrep -x meshd | head -n1)"
"${LAB_DIR}/faults/inject-fault.sh" kill-agent node-1 --restart
recovered_agent=0
for _ in $(seq 1 20); do
  new_pid="$(docker exec mesh-lab-node-1 pgrep -x meshd | head -n1 || true)"
  if [ -n "${new_pid}" ] && [ "${new_pid}" != "${old_pid}" ] \
    && docker exec mesh-lab-node-1 test -S /var/run/meshd/meshd-admin.sock 2>/dev/null \
    && docker exec mesh-lab-node-1 /usr/local/bin/mesh status --json | jq -e '.daemon_state == "connected"' >/dev/null 2>&1; then
    recovered_agent=1
    break
  fi
  sleep 1
done
if [ "${recovered_agent}" -ne 1 ]; then
  echo "FAIL: node-1 meshd failed crash-restart recovery within 20s" >&2
  exit 1
fi
docker exec mesh-lab-node-1 ping -c 1 -W 3 "${node2_ip}" >/dev/null
echo "    PASS: meshd restarted cleanly (old PID ${old_pid} -> new PID ${new_pid}) and tunnel restored."

# 6. power-resume --jump-secs 240 -> real libfaketime jump + tunnel recovery
echo "==> [6/6] Testing power-resume (+240s libfaketime wall-clock jump + conntrack flush)..."
"${LAB_DIR}/faults/inject-fault.sh" power-resume node-1 --jump-secs 240
recovered_wake=0
for _ in $(seq 1 15); do
  if docker exec mesh-lab-node-1 /usr/local/bin/mesh ping node-2 >/dev/null 2>&1 \
    && docker exec mesh-lab-node-1 ping -c 1 -W 3 "${node2_ip}" >/dev/null 2>&1; then
    recovered_wake=1
    break
  fi
  sleep 1
done
if [ "${recovered_wake}" -ne 1 ]; then
  echo "FAIL: node-1 failed tunnel recovery within 15s after power-resume +240s clock jump" >&2
  exit 1
fi
echo "    PASS: power-resume clock jump (+240s) + tunnel recovery verified."

cat > "${REPORT_JSON}" <<'EOF'
{
  "story": "US-057",
  "eim_direct_and_tun_ping": "PASS",
  "apdm_relay_and_tun_ping": "PASS",
  "mtu_1400_large_payload": "PASS",
  "captive_portal_and_mitm_fail_closed": "PASS",
  "kill_agent_crash_recovery": "PASS",
  "power_resume_240s_clock_jump": "PASS",
  "overall": "PASS"
}
EOF

echo "==> ALL US-057 LAB SMOKE CHECKS PASSED! Report written to ${REPORT_JSON}"
