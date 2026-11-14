#!/usr/bin/env bash
set -euo pipefail

# Unified Docker NAT & Chaos Suite Orchestrator for US-058 / US-057 / US-028 / US-074 / REL-01 / REL-12.
# Exercises real Linux containers (NET_ADMIN + /dev/net/tun, unprivileged mesh-server) across:
#   1. US-057 lab smoke (EIM direct upgrade, APDM relay fallback, MTU 1400 PMTUD, captive portal / wrong SPKI pin, power-resume +240s)
#   2. REL-01 Control VPS SIGKILL outage -> P2P tunnel continuity -> recovery
#   3. US-074 AC8 Live endpoint migration 443 -> 8443 -> 443 via Admin UDS (/run/mesh-server/admin.sock)
#   4. REL-12 Hot atomic backup -> DB wipe -> restore preserving original SPKI pin
#   5. US-028 UDP-blocked + 443-only + 30s NAT flap chaos + 8443 egress diagnostic

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${LAB_DIR}/docker-compose.nat-lab.yml"
TMP_DIR="${LAB_DIR}/.tmp"

REPORT_JSON="${TMP_DIR}/chaos-report.json"
KEEP_LAB=0
FLAP_DURATION_SECS="${US028_FLAP_DURATION_SECS:-120}"

usage() {
  cat <<'EOF'
Usage: lab/scenarios/run-all-chaos.sh [OPTIONS]

Options:
  --report-json <PATH>     Output JSON summary path (default: lab/.tmp/chaos-report.json)
  --keep-lab               Keep NAT lab containers up after completion
  --flap-duration <SECS>   Duration of 30s NAT flap loop in US-028 AC3 (default: 120)
  -h, --help               Show this help message
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --report-json)
      REPORT_JSON="${2:?--report-json requires a file path}"
      shift 2
      ;;
    --keep-lab)
      KEEP_LAB=1
      shift
      ;;
    --flap-duration)
      FLAP_DURATION_SECS="${2:?--flap-duration requires seconds}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument '$1'" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "${REPORT_JSON}" in
  /*) ;;
  *) REPORT_JSON="$(pwd)/${REPORT_JSON}" ;;
esac

STAGED_REPORT="$(mktemp "${TMPDIR:-/tmp}/mesh-chaos-report.XXXXXX.json")"

US057_STATUS="PENDING"
REL01_STATUS="PENDING"
US074_STATUS="PENDING"
REL12_STATUS="PENDING"
US028_STATUS="PENDING"
US057_DURATION_MS=0
REL01_DURATION_MS=0
US074_DURATION_MS=0
REL12_DURATION_MS=0
US028_DURATION_MS=0
OVERALL_STATUS="FAIL"

now_ms() {
  date +%s%3N 2>/dev/null || printf '%s000\n' "$(date +%s)"
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: required command '$1' not found in PATH" >&2
    exit 1
  fi
}

wait_vps_ready() {
  local timeout_s="${1:-30}"
  for _ in $(seq 1 "${timeout_s}"); do
    if docker exec mesh-lab-vps curl -fsS http://127.0.0.1:9091/readyz >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "ERROR: mesh-lab-vps /readyz did not become healthy within ${timeout_s}s" >&2
  return 1
}

wait_all_nodes_control_connected() {
  local timeout_s="${1:-30}"
  local idx connected_count
  connected_count=0
  for _ in $(seq 1 "${timeout_s}"); do
    connected_count=0
    for idx in 1 2 3 4 5; do
      if [ "$(docker exec "mesh-lab-node-${idx}" /usr/local/bin/mesh status --json 2>/dev/null | jq -r '.server_connection.control_connected // false')" = "true" ]; then
        connected_count=$((connected_count + 1))
      fi
    done
    if [ "${connected_count}" -eq 5 ]; then
      return 0
    fi
    sleep 1
  done
  echo "ERROR: only ${connected_count}/5 nodes reconnected to control within ${timeout_s}s" >&2
  return 1
}

write_report() {
  local finished_at_utc
  finished_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
  cat > "${STAGED_REPORT}" <<EOF
{
  "suite": "mesh-lab-all-chaos",
  "generated_at_utc": "${finished_at_utc}",
  "flap_duration_secs": ${FLAP_DURATION_SECS},
  "overall": "${OVERALL_STATUS}",
  "scenarios": {
    "us057_lab_smoke": { "status": "${US057_STATUS}", "duration_ms": ${US057_DURATION_MS} },
    "rel01_kill_server_p2p_continuity": { "status": "${REL01_STATUS}", "duration_ms": ${REL01_DURATION_MS} },
    "us074_live_migrate_endpoint_443_8443": { "status": "${US074_STATUS}", "duration_ms": ${US074_DURATION_MS} },
    "rel12_backup_wipe_restore_pin": { "status": "${REL12_STATUS}", "duration_ms": ${REL12_DURATION_MS} },
    "us028_udp_blocked_443_only": { "status": "${US028_STATUS}", "duration_ms": ${US028_DURATION_MS} }
  }
}
EOF
  mkdir -p "$(dirname "${REPORT_JSON}")"
  cp "${STAGED_REPORT}" "${REPORT_JSON}"
  rm -f "${STAGED_REPORT}"
}

cleanup() {
  local rc=$?
  if [ "${KEEP_LAB}" -eq 0 ]; then
    "${LAB_DIR}/run-lab.sh" down || true
  fi
  write_report || true
  exit "${rc}"
}
trap cleanup EXIT

require_tool docker
require_tool jq

if [ ! -f "${COMPOSE_FILE}" ]; then
  echo "ERROR: compose file not found: ${COMPOSE_FILE}" >&2
  exit 1
fi

echo "==> [Chaos 1/5] Running US-057 NAT Lab baseline & EIM/APDM/PMTUD/MITM/power-resume..."
t0="$(now_ms)"
"${LAB_DIR}/acceptance/test-us057-lab-smoke.sh" --keep-lab
t1="$(now_ms)"
US057_DURATION_MS=$((t1 - t0))
US057_STATUS="PASS"

echo "==> [Chaos 2/5] Running REL-01 kill-server control outage & P2P tunnel continuity check..."
t0="$(now_ms)"
"${LAB_DIR}/faults/inject-fault.sh" set-mode node-1 eim
"${LAB_DIR}/faults/inject-fault.sh" set-mode node-2 eim
node2_ip="$(docker exec mesh-lab-node-1 /usr/local/bin/mesh status --json | jq -r '.peers[] | select(.name == "node-2") | .overlay_ip')"
test -n "${node2_ip}"

wait_all_nodes_control_connected 20
rel01_direct=0
for _ in $(seq 1 25); do
  docker exec mesh-lab-node-1 /usr/local/bin/mesh ping -c 1 --timeout-ms 500 node-2 >/dev/null 2>&1 || true
  docker exec mesh-lab-node-2 /usr/local/bin/mesh ping -c 1 --timeout-ms 500 node-1 >/dev/null 2>&1 || true
  if [ "$(docker exec mesh-lab-node-1 /usr/local/bin/mesh status --json | jq -r '.peers[] | select(.name == "node-2") | .active_path')" = "direct" ] \
    && [ "$(docker exec mesh-lab-node-2 /usr/local/bin/mesh status --json | jq -r '.peers[] | select(.name == "node-1") | .active_path')" = "direct" ] \
    && docker exec mesh-lab-node-1 ping -c 2 -W 2 "${node2_ip}" >/dev/null 2>&1; then
    rel01_direct=1
    break
  fi
  sleep 1
done
if [ "${rel01_direct}" -ne 1 ]; then
  echo "FAIL: node-1 <-> node-2 did not establish bidirectional direct path before kill-server" >&2
  exit 1
fi

"${LAB_DIR}/faults/inject-fault.sh" kill-server
if docker exec mesh-lab-vps curl -fsS --max-time 2 http://127.0.0.1:9091/readyz >/dev/null 2>&1; then
  echo "FAIL: mesh-lab-vps still responded after kill-server" >&2
  exit 1
fi
docker exec mesh-lab-node-1 ping -c 3 -W 3 "${node2_ip}" >/dev/null
docker compose -f "${COMPOSE_FILE}" up -d vps
wait_vps_ready 30
wait_all_nodes_control_connected 30
t1="$(now_ms)"
REL01_DURATION_MS=$((t1 - t0))
REL01_STATUS="PASS"
echo "    PASS: P2P ping to ${node2_ip} succeeded continuously with Control VPS down."

echo "==> [Chaos 3/5] Running US-074 AC8 live 443 -> 8443 -> 443 migrate-endpoint via Admin UDS..."
t0="$(now_ms)"
migrate_out="$(docker exec mesh-lab-vps curl -fsS --unix-socket /run/mesh-server/admin.sock \
  -H 'Content-Type: application/json' \
  -d '{"host":"172.28.0.10","tcp_port":8443,"transition_window_secs":30}' \
  http://localhost/v1/admin/server/migrate-endpoint)"
migrated_ep="$(printf '%s' "${migrate_out}" | jq -r '.control_tcp_endpoint')"
if [ "${migrated_ep}" != "172.28.0.10:8443" ]; then
  echo "FAIL: expected migrated control_tcp_endpoint 172.28.0.10:8443, got '${migrated_ep}'" >&2
  exit 1
fi
sleep 2
docker exec mesh-lab-node-1 ping -c 2 -W 3 "${node2_ip}" >/dev/null

restore_ep_out="$(docker exec mesh-lab-vps curl -fsS --unix-socket /run/mesh-server/admin.sock \
  -H 'Content-Type: application/json' \
  -d '{"host":"172.28.0.10","tcp_port":443,"transition_window_secs":5}' \
  http://localhost/v1/admin/server/migrate-endpoint)"
restored_ep="$(printf '%s' "${restore_ep_out}" | jq -r '.control_tcp_endpoint')"
if [ "${restored_ep}" != "172.28.0.10:443" ]; then
  echo "FAIL: expected restored control_tcp_endpoint 172.28.0.10:443, got '${restored_ep}'" >&2
  exit 1
fi
wait_all_nodes_control_connected 30
t1="$(now_ms)"
US074_DURATION_MS=$((t1 - t0))
US074_STATUS="PASS"
echo "    PASS: Live Admin UDS migrate-endpoint transitioned 443 -> 8443 -> 443 cleanly."

echo "==> [Chaos 4/5] Running REL-12 backup -> wipe -> restore preserving SPKI pin..."
t0="$(now_ms)"
orig_pin="$(docker exec mesh-lab-vps curl -fsS --unix-socket /run/mesh-server/admin.sock http://localhost/v1/admin/server/status | jq -r '.active_pin')"
test -n "${orig_pin}"
backup_json="$(docker exec mesh-lab-vps curl -fsS -X POST --unix-socket /run/mesh-server/admin.sock http://localhost/v1/admin/backup)"
snap_path="$(printf '%s' "${backup_json}" | jq -r '.snapshot_path')"
test -n "${snap_path}"

# Simulate catastrophic DB loss on vps_state volume while keeping backup archive.
docker compose -f "${COMPOSE_FILE}" stop vps
docker compose -f "${COMPOSE_FILE}" run --rm --no-deps --entrypoint sh vps -c \
  'rm -f /var/lib/mesh/control.redb /var/lib/mesh/emergency-revocations.bin /var/lib/mesh/emergency-revocations.bin.bak'
docker compose -f "${COMPOSE_FILE}" up -d vps
wait_vps_ready 30

fresh_pin="$(docker exec mesh-lab-vps curl -fsS --unix-socket /run/mesh-server/admin.sock http://localhost/v1/admin/server/status | jq -r '.active_pin')"
if [ "${fresh_pin}" = "${orig_pin}" ]; then
  echo "FAIL: wiped VPS unexpectedly kept original SPKI pin without restore" >&2
  exit 1
fi

restore_resp="$(docker exec mesh-lab-vps curl -fsS -X POST --unix-socket /run/mesh-server/admin.sock \
  -H 'Content-Type: application/json' \
  -d "{\"snapshot_path\":\"${snap_path}\",\"verify_sha256\":true}" \
  'http://localhost/v1/admin/restore?allow_pin_change=true')"
if ! printf '%s' "${restore_resp}" | jq -e '.restored == true and (.node_count >= 5)' >/dev/null; then
  echo "FAIL: restore response invalid: ${restore_resp}" >&2
  exit 1
fi
after_pin="$(docker exec mesh-lab-vps curl -fsS --unix-socket /run/mesh-server/admin.sock http://localhost/v1/admin/server/status | jq -r '.active_pin')"
if [ "${after_pin}" != "${orig_pin}" ]; then
  echo "FAIL: SPKI pin mismatch after restore (expected=${orig_pin}, got=${after_pin})" >&2
  exit 1
fi
wait_all_nodes_control_connected 30
docker exec mesh-lab-node-1 ping -c 2 -W 3 "${node2_ip}" >/dev/null
t1="$(now_ms)"
REL12_DURATION_MS=$((t1 - t0))
REL12_STATUS="PASS"
echo "    PASS: Backup -> DB wipe -> Restore preserved exact SPKI pin ${orig_pin}."

echo "==> [Chaos 5/5] Running US-028 UDP-blocked & 443-only chaos acceptance (flap=${FLAP_DURATION_SECS}s)..."
t0="$(now_ms)"
"${LAB_DIR}/acceptance/test-udp-blocked-443-only.sh" --reuse-lab --keep-lab --flap-duration "${FLAP_DURATION_SECS}"
t1="$(now_ms)"
US028_DURATION_MS=$((t1 - t0))
US028_STATUS="PASS"

OVERALL_STATUS="PASS"
echo "==> ALL CHAOS & ACCEPTANCE SCENARIOS PASSED. JSON summary will be written to ${REPORT_JSON}"
