#!/usr/bin/env bash
set -euo pipefail

# Scriptable chaos & fault-injection CLI for the Mesh VPN NAT Lab (US-057 AC3, US-036 AC2).
# Invoked manually or from automated acceptance suites.

CMD="${1:-}"
shift || true

usage() {
  cat <<'EOF'
Usage: lab/faults/inject-fault.sh <COMMAND> [ARGS...]

Commands:
  kill-agent <node-1..5> [--restart]         SIGKILL `meshd` inside a lab node
  restart-agent <node-1..5>                  Resume/start `meshd` inside a lab node
  kill-server [--restart]                    SIGKILL `mesh-server` (and optionally restart)
  set-mode <node-1..5|all> <MODE>            Set router mode: eim|apdm|udp-block|443-only|80-443-only|mtu-1400|captive-portal|mitm-wrong-pin
  block-udp <node-1..5|all>                  Alias for `set-mode <target> udp-block`
  unblock-udp <node-1..5|all>                Alias for `set-mode <target> eim`
  set-netem <node-1..5|all> <DELAY_MS> <LOSS_PCT>
  clear-netem <node-1..5|all>
  flap-ip <node-1..5|all>                    Rotate NAT public IP + flush conntrack once
  flap-nat <node-1..5|all> [--interval 30] [--duration 600]
                                             Periodic NAT IP flap + conntrack flush loop
  power-resume <node-1..5> [--jump-secs 240] Simulate sleep/wake: conntrack flush + clock jump > 180s + NIC flap
  mitm-wrong-pin <node-1..5|all>             Inject CA-valid / wrong-SPKI-pin MITM on TCP 443/8443
  captive-portal <node-1..5|all>             Inject rogue captive portal TLS on TCP 443/8443
  restore-tls <node-1..5|all>                Restore clean NAT mode (`eim`)
EOF
}

resolve_router_indices() {
  local target="${1:?target required (node-1..5 or all)}"
  case "${target}" in
    all) echo "1 2 3 4 5" ;;
    node-1|router-1|1) echo "1" ;;
    node-2|router-2|2) echo "2" ;;
    node-3|router-3|3) echo "3" ;;
    node-4|router-4|4) echo "4" ;;
    node-5|router-5|5) echo "5" ;;
    *)
      echo "ERROR: invalid target '${target}' (expected node-1..5 or all)" >&2
      exit 2
      ;;
  esac
}

resolve_node_container() {
  local target="${1:?node required (node-1..5)}"
  case "${target}" in
    node-1|node-2|node-3|node-4|node-5) echo "mesh-lab-${target}" ;;
    1|2|3|4|5) echo "mesh-lab-node-${target}" ;;
    *)
      echo "ERROR: invalid node '${target}' (expected node-1..5)" >&2
      exit 2
      ;;
  esac
}

cmd_kill_agent() {
  local target="${1:?node required}"
  local restart=0
  if [ "${2:-}" = "--restart" ]; then
    restart=1
  fi
  local container
  container="$(resolve_node_container "${target}")"

  if [ "${restart}" -eq 0 ]; then
    docker exec "${container}" sh -c 'touch /var/lib/meshd/supervisor.paused && pkill -9 -x meshd || true'
    echo "SIGKILL sent to meshd in ${container} (supervisor paused; call restart-agent to resume)"
  else
    docker exec "${container}" sh -c 'rm -f /var/lib/meshd/supervisor.paused && pkill -9 -x meshd || true'
    echo "SIGKILL sent to meshd in ${container} (auto-restart active)"
  fi
}

cmd_restart_agent() {
  local target="${1:?node required}"
  local container
  container="$(resolve_node_container "${target}")"
  docker exec "${container}" rm -f /var/lib/meshd/supervisor.paused
  echo "Resumed meshd supervisor in ${container}"
}

cmd_kill_server() {
  local restart=0
  if [ "${1:-}" = "--restart" ]; then
    restart=1
  fi
  docker kill -s KILL mesh-lab-vps
  echo "SIGKILL sent to mesh-lab-vps"
  if [ "${restart}" -eq 1 ]; then
    docker start mesh-lab-vps
    for _ in $(seq 1 30); do
      if docker exec mesh-lab-vps curl -fsS http://127.0.0.1:9091/readyz >/dev/null 2>&1; then
        echo "mesh-lab-vps restarted and /readyz is 200 OK"
        return 0
      fi
      sleep 1
    done
    echo "ERROR: mesh-lab-vps did not recover /readyz within 30s" >&2
    exit 1
  fi
}

cmd_set_mode() {
  local target="${1:?target required}"
  local mode="${2:?mode required}"
  for idx in $(resolve_router_indices "${target}"); do
    docker exec "mesh-lab-router-${idx}" /usr/local/bin/router-entrypoint.sh ctl mode "${mode}"
  done
}

cmd_set_netem() {
  local target="${1:?target required}"
  local delay_ms="${2:-50}"
  local loss_pct="${3:-2}"
  for idx in $(resolve_router_indices "${target}"); do
    docker exec "mesh-lab-router-${idx}" /usr/local/bin/router-entrypoint.sh ctl netem "${delay_ms}" "${loss_pct}"
  done
}

cmd_clear_netem() {
  local target="${1:?target required}"
  for idx in $(resolve_router_indices "${target}"); do
    docker exec "mesh-lab-router-${idx}" /usr/local/bin/router-entrypoint.sh ctl clear-netem
  done
}

cmd_flap_ip() {
  local target="${1:?target required}"
  for idx in $(resolve_router_indices "${target}"); do
    docker exec "mesh-lab-router-${idx}" /usr/local/bin/router-entrypoint.sh ctl flap-ip
  done
}

cmd_flap_nat() {
  local target="${1:?target required}"
  shift
  local interval=30
  local duration=600
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --interval) interval="${2:?--interval requires seconds}"; shift 2 ;;
      --duration) duration="${2:?--duration requires seconds}"; shift 2 ;;
      *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
  done

  local start_ts now_ts elapsed
  start_ts="$(date +%s)"
  while true; do
    cmd_flap_ip "${target}"
    now_ts="$(date +%s)"
    elapsed=$((now_ts - start_ts))
    if [ "${elapsed}" -ge "${duration}" ]; then
      break
    fi
    sleep "${interval}"
  done
}

cmd_power_resume() {
  local target="${1:?node required}"
  shift
  local jump_secs=240
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --jump-secs) jump_secs="${2:?--jump-secs requires seconds}"; shift 2 ;;
      *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
  done

  local idx container router_ip
  idx="$(resolve_router_indices "${target}")"
  container="$(resolve_node_container "${target}")"
  router_ip="172.28.${idx}0.254"

  # 1. Wipe NAT conntrack state and flap router SNAT IP.
  docker exec "mesh-lab-router-${idx}" /usr/local/bin/router-entrypoint.sh ctl flap-ip

  # 2. Advance wall-clock offset via libfaketime (> 180s WireGuard REJECT_AFTER_TIME)
  #    while CLOCK_MONOTONIC remains real, triggering ClockJumpDetector (US-035/036).
  docker exec "${container}" sh -c '
    set -eu
    f="/var/lib/meshd/faketime.rc"
    faketime_lib="$(find /usr/lib -name "libfaketime.so.1" 2>/dev/null | head -n1 || true)"
    if [ -z "${faketime_lib}" ]; then
      echo "ERROR: libfaketime.so.1 not found inside container" >&2
      exit 1
    fi
    if [ ! -f "$f" ]; then
      printf "+0s\n" > "$f"
    fi
    before_ts="$(LD_PRELOAD="${faketime_lib}" FAKETIME_TIMESTAMP_FILE="$f" FAKETIME_NO_CACHE=1 FAKETIME_DONT_FAKE_MONOTONIC=1 date +%s)"
    cur="$(tr -d "[:space:]" < "$f")"
    cur_num="${cur#+}"
    cur_num="${cur_num%s}"
    cur_num="${cur_num:-0}"
    next_num=$((cur_num + $1))
    tmp_f="${f}.tmp.$$"
    printf "+%ss\n" "${next_num}" > "${tmp_f}"
    chmod 0644 "${tmp_f}"
    mv "${tmp_f}" "$f"
    after_ts="$(LD_PRELOAD="${faketime_lib}" FAKETIME_TIMESTAMP_FILE="$f" FAKETIME_NO_CACHE=1 FAKETIME_DONT_FAKE_MONOTONIC=1 date +%s)"
    delta=$((after_ts - before_ts))
    min_expected=$(($1 - 2))
    if [ "${delta}" -lt "${min_expected}" ]; then
      echo "ERROR: libfaketime clock jump failed (before=${before_ts}, after=${after_ts}, delta=${delta}s, expected>=${min_expected}s)" >&2
      exit 1
    fi
    echo "faketime wall-clock verified jump: +${cur_num}s -> +${next_num}s (before=${before_ts}, after=${after_ts}, delta=${delta}s)"
  ' sh "${jump_secs}"

  # 3. Flap container LAN interface to emit a real OS netlink link/route event.
  docker exec "${container}" sh -c '
    set -eu
    lan_if="$(ip -4 route show to match "$1" | awk "{for(i=1;i<=NF;i++) if(\$i==\"dev\") {print \$(i+1); exit}}")"
    if [ -z "${lan_if}" ]; then
      lan_if="eth0"
    fi
    ip link set dev "${lan_if}" down
    sleep 1
    ip link set dev "${lan_if}" up
    ip route replace default via "$1" dev "${lan_if}"
    echo "power-resume simulated on ${lan_if}: link flapped + default route restored via $1"
  ' sh "${router_ip}"
}

case "${CMD}" in
  kill-agent) cmd_kill_agent "$@" ;;
  restart-agent) cmd_restart_agent "$@" ;;
  kill-server) cmd_kill_server "$@" ;;
  set-mode) cmd_set_mode "$@" ;;
  block-udp) cmd_set_mode "${1:?target required}" "udp-block" ;;
  unblock-udp) cmd_set_mode "${1:?target required}" "eim" ;;
  set-netem) cmd_set_netem "$@" ;;
  clear-netem) cmd_clear_netem "$@" ;;
  flap-ip) cmd_flap_ip "$@" ;;
  flap-nat) cmd_flap_nat "$@" ;;
  power-resume) cmd_power_resume "$@" ;;
  mitm-wrong-pin) cmd_set_mode "${1:?target required}" "mitm-wrong-pin" ;;
  captive-portal) cmd_set_mode "${1:?target required}" "captive-portal" ;;
  restore-tls) cmd_set_mode "${1:?target required}" "eim" ;;
  -h|--help|help|"")
    usage
    ;;
  *)
    echo "ERROR: unknown fault command '${CMD}'" >&2
    usage >&2
    exit 2
    ;;
esac
