#!/usr/bin/env bash
set -euo pipefail

# Automated Acceptance Suite for US-028 (UDP-Blocked & 443-Only Relay Traversal) and REL-06.
# Covers:
#   - AC1: All UDP blocked (except DNS 53) -> 10/10 pairs ping via Blind Relay (`status` == relay)
#   - AC2: All UDP blocked + all TCP except 443 blocked -> 10/10 pairs succeed
#   - AC3: NAT IP + conntrack flap every 30s over 10 minutes (default 600s) -> P95 recovery <= 15s
#   - AC4: Network allows only outbound TCP 80/443 while Relay is on 8443 -> honest diagnostic
#          without hanging; switching Relay back to 443 restores 10/10 pairs.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TMP_DIR="${LAB_DIR}/.tmp"
REPORT_JSON="${TMP_DIR}/us028-report.json"
REPORT_MD="${TMP_DIR}/us028-report.md"

FLAP_DURATION_SECS="${US028_FLAP_DURATION_SECS:-600}"
FLAP_INTERVAL_SECS="${US028_FLAP_INTERVAL_SECS:-30}"
REUSE_LAB=0
KEEP_LAB=0
AC_TIMEOUT_SECS=15

usage() {
  cat <<'EOF'
Usage: lab/acceptance/test-udp-blocked-443-only.sh [OPTIONS]

Options:
  --flap-duration <SECS>   Duration of 30s NAT flap loop for AC3 (default: 600 = 10 min)
  --reuse-lab              Assume lab is already running (skip initial `run-lab.sh up`)
  --keep-lab               Do not tear down lab on completion
  -h, --help               Show this help message
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --flap-duration)
      FLAP_DURATION_SECS="${2:?--flap-duration requires seconds}"
      shift 2
      ;;
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

now_ms() {
  date +%s%3N 2>/dev/null || printf '%s000\n' "$(date +%s)"
}

verify_all_ten_pairs() {
  local expected_path="${1:-relay}" # relay | any
  local pass_count=0
  local total_pairs=10

  for i in 1 2 3 4; do
    local src_container="mesh-lab-node-${i}"
    local status_json
    status_json="$(docker exec "${src_container}" /usr/local/bin/mesh status --json)"

    for j in $(seq $((i + 1)) 5); do
      local dst_name="node-${j}"
      local active_path peer_overlay_ip
      active_path="$(printf '%s' "${status_json}" | jq -r --arg name "${dst_name}" '.peers[]? | select(.name == $name) | .active_path // empty')"
      peer_overlay_ip="$(printf '%s' "${status_json}" | jq -r --arg name "${dst_name}" '.peers[]? | select(.name == $name) | .overlay_ip // empty')"

      if [ "${expected_path}" != "any" ] && [ "${active_path}" != "${expected_path}" ]; then
        echo "FAIL: ${src_container} -> ${dst_name} expected active_path=${expected_path}, got '${active_path}'" >&2
        return 1
      fi

      if [ -z "${peer_overlay_ip}" ]; then
        echo "FAIL: ${src_container} -> ${dst_name} missing overlay_ip in status --json" >&2
        return 1
      fi

      if ! docker exec "${src_container}" /usr/local/bin/mesh ping "${dst_name}" >/dev/null 2>&1; then
        echo "FAIL: ${src_container} -> ${dst_name} mesh ping failed" >&2
        return 1
      fi

      if ! docker exec "${src_container}" ping -c 1 -W 3 "${peer_overlay_ip}" >/dev/null 2>&1; then
        echo "FAIL: ${src_container} -> ${dst_name} (${peer_overlay_ip}) kernel TUN IPv4 ping failed" >&2
        return 1
      fi

      pass_count=$((pass_count + 1))
    done
  done

  if [ "${pass_count}" -ne "${total_pairs}" ]; then
    echo "FAIL: verified ${pass_count}/${total_pairs} pairs" >&2
    return 1
  fi
  echo "PASS: ${pass_count}/${total_pairs} pairs verified (path=${expected_path})"
}

wait_for_relay_convergence() {
  local timeout_s="${1:-20}"
  local deadline=$(( $(date +%s) + timeout_s ))
  while [ "$(date +%s)" -le "${deadline}" ]; do
    if verify_all_ten_pairs "relay" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  verify_all_ten_pairs "relay"
}

compute_p95_ms() {
  local samples_file="$1"
  local count
  count="$(wc -l < "${samples_file}" | tr -d '[:space:]')"
  if [ "${count}" -eq 0 ]; then
    echo "0"
    return 0
  fi
  local idx
  idx=$(( (count * 95 + 99) / 100 ))
  if [ "${idx}" -lt 1 ]; then
    idx=1
  fi
  sort -n "${samples_file}" | sed -n "${idx}p"
}

if [ "${REUSE_LAB}" -eq 0 ]; then
  echo "==> [Setup] Starting 5-node + 1-VPS NAT lab on TCP 443..."
  "${LAB_DIR}/run-lab.sh" up --tcp-port 443 --stun-port 3478 --topology udp-block
fi

echo "==> [US-028 AC1] Verifying 10/10 pairs over Blind Relay with UDP blocked..."
"${LAB_DIR}/faults/inject-fault.sh" set-mode all udp-block
wait_for_relay_convergence 30
verify_all_ten_pairs "relay"
AC1_STATUS="PASS"

echo "==> [US-028 AC2] Blocking all TCP except 443 + all UDP, verifying 10/10 pairs..."
"${LAB_DIR}/faults/inject-fault.sh" set-mode all 443-only
wait_for_relay_convergence 30
verify_all_ten_pairs "relay"
AC2_STATUS="PASS"

echo "==> [US-028 AC3] Running 30s NAT IP/conntrack flap loop for ${FLAP_DURATION_SECS}s (P95 <= 15000 ms)..."
RECOVERY_SAMPLES="${TMP_DIR}/us028-recovery-ms.txt"
: > "${RECOVERY_SAMPLES}"
flap_start_s="$(date +%s)"
flap_round=0

while true; do
  flap_round=$((flap_round + 1))
  echo "    Flap round #${flap_round}..."
  "${LAB_DIR}/faults/inject-fault.sh" flap-ip all
  t0_ms="$(now_ms)"

  recovered=0
  deadline_s=$(( $(date +%s) + AC_TIMEOUT_SECS ))
  while [ "$(date +%s)" -le "${deadline_s}" ]; do
    if verify_all_ten_pairs "relay" >/dev/null 2>&1; then
      recovered=1
      break
    fi
    sleep 0.5
  done

  t1_ms="$(now_ms)"
  elapsed_ms=$((t1_ms - t0_ms))
  echo "${elapsed_ms}" >> "${RECOVERY_SAMPLES}"
  echo "    Round #${flap_round} recovery=${elapsed_ms}ms (recovered=${recovered})"

  if [ "${recovered}" -ne 1 ]; then
    echo "FAIL: US-028 AC3 pairs failed to recover within ${AC_TIMEOUT_SECS}s on flap round #${flap_round}" >&2
    exit 1
  fi

  now_s="$(date +%s)"
  if [ $((now_s - flap_start_s)) -ge "${FLAP_DURATION_SECS}" ]; then
    break
  fi
  sleep "${FLAP_INTERVAL_SECS}"
done

P95_RECOVERY_MS="$(compute_p95_ms "${RECOVERY_SAMPLES}")"
echo "    US-028 AC3 P95 recovery across ${flap_round} flap rounds = ${P95_RECOVERY_MS} ms"
if [ "${P95_RECOVERY_MS}" -gt 15000 ]; then
  echo "FAIL: US-028 AC3 P95 recovery ${P95_RECOVERY_MS}ms exceeded 15000ms SLO" >&2
  exit 1
fi
AC3_STATUS="PASS"

echo "==> [US-028 AC4] Testing 80/443-only egress with Relay on port 8443 -> honest diagnostic, then restore port 443..."
"${LAB_DIR}/faults/inject-fault.sh" set-mode all 80-443-only

# Switch lab VPS to custom TCP port 8443 while keeping state/identity.
MESH_CONTROL_TCP_PORT=8443 MESH_STUN_UDP_PORT=3479 \
  docker compose -f "${LAB_DIR}/docker-compose.nat-lab.yml" up -d --force-recreate vps
for _ in $(seq 1 20); do
  if docker exec mesh-lab-vps curl -fsS http://127.0.0.1:9091/readyz >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

# Point node-1 to :8443 under strict 80/443-only egress and verify fast non-hanging diagnostic.
vps_pin="$(docker exec mesh-lab-vps curl -fsS --unix-socket /run/mesh-server/admin.sock http://localhost/v1/admin/server/status | jq -r '.active_pin')"
docker exec mesh-lab-node-1 /usr/local/bin/mesh set --server "172.28.0.10:8443" --server-pin "${vps_pin}"

netcheck_out="$(timeout 6 docker exec mesh-lab-node-1 /usr/local/bin/mesh netcheck --json)"
if ! printf '%s' "${netcheck_out}" | jq -e '
  .control_tcp_reachable == false and
  .udp_egress_ok == false and
  .stun_reachable == false and
  (.diagnostic_hint != null) and
  ((.diagnostic_hint | length) > 0) and
  (.diagnostic_hint | test("443|8443|TLS|firewall"; "i"))
' >/dev/null; then
  echo "FAIL: US-028 AC4 netcheck --json failed strict diagnostic check: ${netcheck_out}" >&2
  exit 1
fi
echo "    Verified honest non-hanging diagnostic when TCP 8443 is blocked by 80/443-only egress."

# Restore Relay to TCP 443 under the same 80/443-only router firewall and verify 10/10 pairs recover.
MESH_CONTROL_TCP_PORT=443 MESH_STUN_UDP_PORT=3478 \
  docker compose -f "${LAB_DIR}/docker-compose.nat-lab.yml" up -d --force-recreate vps
for _ in $(seq 1 20); do
  if docker exec mesh-lab-vps curl -fsS http://127.0.0.1:9091/readyz >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec mesh-lab-node-1 /usr/local/bin/mesh set --server "172.28.0.10:443" --server-pin "${vps_pin}"
wait_for_relay_convergence 30
verify_all_ten_pairs "relay"
AC4_STATUS="PASS"

cat > "${REPORT_JSON}" <<EOF
{
  "story": "US-028",
  "ac1_udp_blocked_10_of_10_relay": "${AC1_STATUS}",
  "ac2_443_only_10_of_10_relay": "${AC2_STATUS}",
  "ac3_nat_flap_30s_rounds": ${flap_round},
  "ac3_p95_recovery_ms": ${P95_RECOVERY_MS},
  "ac3_slo_threshold_ms": 15000,
  "ac3_status": "${AC3_STATUS}",
  "ac4_80_443_only_8443_diagnostic_and_443_recovery": "${AC4_STATUS}",
  "overall": "PASS"
}
EOF

cat > "${REPORT_MD}" <<EOF
# US-028 Acceptance Report (UDP-Blocked & 443-Only Relay Traversal)

| Check | Result | Details |
|---|---|---|
| AC1: UDP Blocked (10/10 pairs via Blind Relay) | ${AC1_STATUS} | Verified all 10 pairs across 5 NAT nodes |
| AC2: TCP 443-Only + UDP Blocked (10/10 pairs) | ${AC2_STATUS} | Verified all 10 pairs via TCP 443 |
| AC3: 30s NAT IP/Conntrack Flap (${FLAP_DURATION_SECS}s) | ${AC3_STATUS} | Rounds: ${flap_round}, P95 recovery: ${P95_RECOVERY_MS} ms (SLO <= 15000 ms) |
| AC4: 80/443-Only Egress on Port 8443 Diagnostic + 443 Recovery | ${AC4_STATUS} | Reported honest 8443/443 diagnostic; recovered 10/10 on port 443 |
EOF

echo "==> ALL US-028 ACCEPTANCE CHECKS PASSED! Report written to ${REPORT_JSON}"
