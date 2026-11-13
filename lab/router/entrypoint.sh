#!/usr/bin/env bash
set -euo pipefail

# Linux NAT / Firewall / Chaos Lab Router (`US-057`, `US-028`, `US-017 AC2`).
# Runs with only `CAP_NET_ADMIN` (never `privileged: true`).
#
# Can run as PID 1 (configures interfaces and sleeps until SIGTERM) OR as a control CLI:
#   docker exec router-1 /usr/local/bin/router-entrypoint.sh ctl <command> [args...]

STATE_FILE="/run/router-state.env"
MITM_PID_FILE="/run/router-mitm.pid"
MITM_DIR="/run/router-mitm"

discover_interfaces() {
  local wan_prefix="${LAB_WAN_SUBNET_PREFIX:-172.28.0.}"
  local lan_prefix="${LAB_LAN_SUBNET_PREFIX:?LAB_LAN_SUBNET_PREFIX must be set}"

  WAN_IF=""
  LAN_IF=""

  while read -r _ ifname _ cidr _; do
    case "${cidr}" in
      "${wan_prefix}"*) WAN_IF="${ifname}" ;;
      "${lan_prefix}"*) LAN_IF="${ifname}" ;;
    esac
  done < <(ip -4 -o addr show scope global)

  if [ -z "${WAN_IF}" ] || [ -z "${LAN_IF}" ]; then
    echo "ERROR: could not discover WAN (${wan_prefix}*) and LAN (${lan_prefix}*) interfaces" >&2
    ip -4 -o addr show >&2
    exit 1
  fi

  PRIMARY_WAN_IP="$(ip -4 -o addr show dev "${WAN_IF}" scope global | awk '{split($4,a,"/"); print a[1]; exit}')"
  SECONDARY_WAN_IP="${LAB_SECONDARY_WAN_IP:-}"
  ACTIVE_WAN_IP="${PRIMARY_WAN_IP}"
  CURRENT_MODE="${LAB_ROUTER_MODE:-eim}"
  VPS_IP="${LAB_VPS_IP:-172.28.0.10}"

  if [ -n "${SECONDARY_WAN_IP}" ]; then
    ip addr replace "${SECONDARY_WAN_IP}/24" dev "${WAN_IF}" 2>/dev/null || true
  fi

  save_state
}

save_state() {
  cat > "${STATE_FILE}" <<EOF
WAN_IF="${WAN_IF}"
LAN_IF="${LAN_IF}"
PRIMARY_WAN_IP="${PRIMARY_WAN_IP}"
SECONDARY_WAN_IP="${SECONDARY_WAN_IP}"
ACTIVE_WAN_IP="${ACTIVE_WAN_IP}"
CURRENT_MODE="${CURRENT_MODE}"
VPS_IP="${VPS_IP}"
EOF
}

load_state() {
  if [ ! -f "${STATE_FILE}" ]; then
    echo "ERROR: router state not initialized (${STATE_FILE} missing)" >&2
    exit 1
  fi
  # shellcheck disable=SC1090
  . "${STATE_FILE}"
}

stop_mitm_server() {
  if [ -f "${MITM_PID_FILE}" ]; then
    local pid
    pid="$(cat "${MITM_PID_FILE}" 2>/dev/null || true)"
    if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
      kill -TERM "${pid}" 2>/dev/null || true
      sleep 0.2
      kill -KILL "${pid}" 2>/dev/null || true
    fi
    rm -f "${MITM_PID_FILE}"
  fi
}

start_rogue_tls_server() {
  local kind="$1" # captive-portal | mitm-wrong-pin
  local listen_port="$2"
  stop_mitm_server
  mkdir -p "${MITM_DIR}"

  if [ "${kind}" = "mitm-wrong-pin" ]; then
    # Generate a synthetic public-style CA + leaf cert with SAN=IP:<VPS_IP> but WRONG SPKI key.
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -nodes -days 30 \
      -keyout "${MITM_DIR}/ca.key" \
      -out "${MITM_DIR}/ca.crt" \
      -subj "/CN=Lab-Rogue-CA" >/dev/null 2>&1

    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -nodes \
      -keyout "${MITM_DIR}/leaf.key" \
      -out "${MITM_DIR}/leaf.csr" \
      -subj "/CN=${VPS_IP}" >/dev/null 2>&1

    printf 'subjectAltName=IP:%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' \
      "${VPS_IP}" > "${MITM_DIR}/ext.cnf"

    openssl x509 -req -in "${MITM_DIR}/leaf.csr" \
      -CA "${MITM_DIR}/ca.crt" -CAkey "${MITM_DIR}/ca.key" -CAcreateserial \
      -out "${MITM_DIR}/leaf.crt" -days 15 -extfile "${MITM_DIR}/ext.cnf" >/dev/null 2>&1

    openssl s_server -accept "${listen_port}" \
      -cert "${MITM_DIR}/leaf.crt" -key "${MITM_DIR}/leaf.key" \
      -cert_chain "${MITM_DIR}/ca.crt" -www >/dev/null 2>&1 &
    echo $! > "${MITM_PID_FILE}"
  else
    # Captive portal intercept certificate for an untrusted portal domain.
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -nodes -days 7 \
      -keyout "${MITM_DIR}/portal.key" \
      -out "${MITM_DIR}/portal.crt" \
      -subj "/CN=captive-portal.hotel.local" \
      -addext "subjectAltName=DNS:captive-portal.hotel.local" >/dev/null 2>&1

    openssl s_server -accept "${listen_port}" \
      -cert "${MITM_DIR}/portal.crt" -key "${MITM_DIR}/portal.key" \
      -www >/dev/null 2>&1 &
    echo $! > "${MITM_PID_FILE}"
  fi
}

reset_firewall_and_mtu() {
  stop_mitm_server

  iptables -F FORWARD
  iptables -P FORWARD DROP
  iptables -t nat -F PREROUTING
  iptables -t nat -F POSTROUTING

  ip link set dev "${WAN_IF}" mtu 1500 2>/dev/null || true
  ip link set dev "${LAN_IF}" mtu 1500 2>/dev/null || true
}

apply_base_nat_snat() {
  local nat_flavor="$1" # eim | apdm
  if [ "${nat_flavor}" = "apdm" ]; then
    # Address-and-Port-Dependent Mapping: randomize mapped source port per 5-tuple.
    iptables -t nat -A POSTROUTING -o "${WAN_IF}" -p udp -j SNAT --to-source "${ACTIVE_WAN_IP}" --random-fully
    iptables -t nat -A POSTROUTING -o "${WAN_IF}" -p tcp -j SNAT --to-source "${ACTIVE_WAN_IP}" --random-fully
    iptables -t nat -A POSTROUTING -o "${WAN_IF}" -j SNAT --to-source "${ACTIVE_WAN_IP}"
  else
    # Easy NAT (Endpoint-Independent Mapping): deterministic source IP SNAT without port randomization.
    iptables -t nat -A POSTROUTING -o "${WAN_IF}" -j SNAT --to-source "${ACTIVE_WAN_IP}"
  fi
}

apply_mode() {
  local mode="$1"
  load_state
  reset_firewall_and_mtu

  case "${mode}" in
    eim)
      apply_base_nat_snat "eim"
      iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      iptables -A FORWARD -i "${LAN_IF}" -o "${WAN_IF}" -j ACCEPT
      # Permit peer-to-peer NAT traversal once LAN initiated or hairpinned via WAN.
      iptables -A FORWARD -i "${WAN_IF}" -o "${LAN_IF}" -p udp -j ACCEPT
      ;;

    apdm)
      apply_base_nat_snat "apdm"
      iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      iptables -A FORWARD -i "${LAN_IF}" -o "${WAN_IF}" -j ACCEPT
      ;;

    udp-block)
      apply_base_nat_snat "eim"
      iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      # Allow DNS UDP/53 if queried, drop all other UDP forwarding (forces Blind Relay).
      iptables -A FORWARD -i "${LAN_IF}" -o "${WAN_IF}" -p udp --dport 53 -j ACCEPT
      iptables -A FORWARD -p udp -j DROP
      iptables -A FORWARD -i "${LAN_IF}" -o "${WAN_IF}" -j ACCEPT
      ;;

    443-only)
      apply_base_nat_snat "eim"
      iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      iptables -A FORWARD -i "${LAN_IF}" -o "${WAN_IF}" -p udp --dport 53 -j ACCEPT
      iptables -A FORWARD -p udp -j DROP
      iptables -A FORWARD -i "${LAN_IF}" -o "${WAN_IF}" -p tcp --dport 443 -j ACCEPT
      iptables -A FORWARD -j DROP
      ;;

    80-443-only)
      apply_base_nat_snat "eim"
      iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      iptables -A FORWARD -i "${LAN_IF}" -o "${WAN_IF}" -p udp --dport 53 -j ACCEPT
      iptables -A FORWARD -p udp -j DROP
      iptables -A FORWARD -i "${LAN_IF}" -o "${WAN_IF}" -p tcp --dport 80 -j ACCEPT
      iptables -A FORWARD -i "${LAN_IF}" -o "${WAN_IF}" -p tcp --dport 443 -j ACCEPT
      iptables -A FORWARD -j DROP
      ;;

    mtu-1400)
      apply_base_nat_snat "eim"
      ip link set dev "${WAN_IF}" mtu 1400
      ip link set dev "${LAN_IF}" mtu 1400
      # Drop ICMP Fragmentation Needed (type 3 code 4) to create a PMTUD blackhole (US-017 AC2).
      iptables -A FORWARD -p icmp --icmp-type fragmentation-needed -j DROP
      iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      iptables -A FORWARD -i "${LAN_IF}" -o "${WAN_IF}" -j ACCEPT
      iptables -A FORWARD -i "${WAN_IF}" -o "${LAN_IF}" -p udp -j ACCEPT
      ;;

    captive-portal)
      apply_base_nat_snat "eim"
      start_rogue_tls_server "captive-portal" 8444
      iptables -t nat -A PREROUTING -i "${LAN_IF}" -p tcp --dport 443 -j REDIRECT --to-ports 8444
      iptables -t nat -A PREROUTING -i "${LAN_IF}" -p tcp --dport 8443 -j REDIRECT --to-ports 8444
      iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      iptables -A FORWARD -i "${LAN_IF}" -o "${WAN_IF}" -j ACCEPT
      ;;

    mitm-wrong-pin)
      apply_base_nat_snat "eim"
      start_rogue_tls_server "mitm-wrong-pin" 8445
      iptables -t nat -A PREROUTING -i "${LAN_IF}" -p tcp --dport 443 -j REDIRECT --to-ports 8445
      iptables -t nat -A PREROUTING -i "${LAN_IF}" -p tcp --dport 8443 -j REDIRECT --to-ports 8445
      iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      iptables -A FORWARD -i "${LAN_IF}" -o "${WAN_IF}" -j ACCEPT
      ;;

    *)
      echo "ERROR: unsupported router mode '${mode}'" >&2
      exit 2
      ;;
  esac

  CURRENT_MODE="${mode}"
  save_state
  conntrack -F >/dev/null 2>&1 || true
  echo "router mode applied: mode=${CURRENT_MODE} wan=${WAN_IF}(${ACTIVE_WAN_IP}) lan=${LAN_IF}"
}

flap_ip() {
  load_state
  if [ -z "${SECONDARY_WAN_IP}" ]; then
    echo "ERROR: LAB_SECONDARY_WAN_IP is not configured on this router" >&2
    exit 1
  fi
  if [ "${ACTIVE_WAN_IP}" = "${PRIMARY_WAN_IP}" ]; then
    ACTIVE_WAN_IP="${SECONDARY_WAN_IP}"
  else
    ACTIVE_WAN_IP="${PRIMARY_WAN_IP}"
  fi
  save_state
  apply_mode "${CURRENT_MODE}"
  echo "router NAT IP flapped to ${ACTIVE_WAN_IP} (conntrack flushed)"
}

apply_netem() {
  local delay_ms="${1:-50}"
  local loss_pct="${2:-2}"
  load_state
  tc qdisc replace dev "${WAN_IF}" root netem delay "${delay_ms}ms" loss "${loss_pct}%"
  echo "netem applied on ${WAN_IF}: delay=${delay_ms}ms loss=${loss_pct}%"
}

clear_netem() {
  load_state
  tc qdisc del dev "${WAN_IF}" root 2>/dev/null || true
  echo "netem cleared on ${WAN_IF}"
}

flush_conntrack() {
  conntrack -F >/dev/null 2>&1 || true
  echo "conntrack table flushed"
}

show_status() {
  load_state
  printf 'mode=%s wan_if=%s lan_if=%s active_wan_ip=%s primary=%s secondary=%s\n' \
    "${CURRENT_MODE}" "${WAN_IF}" "${LAN_IF}" "${ACTIVE_WAN_IP}" "${PRIMARY_WAN_IP}" "${SECONDARY_WAN_IP}"
  tc qdisc show dev "${WAN_IF}" || true
}

if [ "${1:-}" = "ctl" ]; then
  shift
  cmd="${1:-status}"
  shift || true
  case "${cmd}" in
    mode) apply_mode "${1:?mode required}" ;;
    flap-ip) flap_ip ;;
    flush-conntrack) flush_conntrack ;;
    netem) apply_netem "${1:-50}" "${2:-2}" ;;
    clear-netem) clear_netem ;;
    status) show_status ;;
    *)
      echo "Unknown ctl command: ${cmd}" >&2
      exit 2
      ;;
  esac
  exit 0
fi

discover_interfaces
apply_mode "${CURRENT_MODE}"

STOP=0
trap 'STOP=1; stop_mitm_server; exit 0' TERM INT
while [ "${STOP}" -eq 0 ]; do
  sleep 1
done
