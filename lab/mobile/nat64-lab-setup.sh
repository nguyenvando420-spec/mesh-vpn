#!/usr/bin/env bash
# lab/mobile/nat64-lab-setup.sh
# Reproducible NAT64 (64:ff9b::/96) + DNS64 (RFC 7050 ipv4only.arpa) lab setup & verification
# for Android (Emulator/Device) and iOS (Simulator/Device) testing (US-077, US-095).

set -euo pipefail

NAT64_PREFIX="${NAT64_PREFIX:-64:ff9b::/96}"
LAB_IPV4_POOL="${LAB_IPV4_POOL:-192.168.255.0/24}"
LAB_V6_NET="${LAB_V6_NET:-fd00:6464::/64}"
LAB_NS="${LAB_NS:-mesh-nat64}"
TAYGA_IF="${TAYGA_IF:-nat64-mesh0}"

usage() {
    cat <<'EOF'
Usage: nat64-lab-setup.sh <command>

Commands:
  up-linux       Create isolated Linux IPv6-only + NAT64 (tayga + dnsmasq/bind9) lab namespace (requires root)
  down-linux     Tear down the Linux NAT64 lab namespace and tayga device (requires root)
  verify-dns64   Query ipv4only.arpa AAAA (RFC 7050) and confirm 64:ff9b::/96 synthesis
  macos-guide    Print macOS Internet Sharing NAT64 setup steps for iPhone/iOS simulator testing
  android-guide  Print Android Emulator/ADB NAT64 test verification commands
EOF
}

require_linux_root() {
    if [ "$(uname -s)" != "Linux" ]; then
        printf '[ERROR] This subcommand requires Linux.\n' >&2
        exit 1
    fi
    if [ "$(id -u)" -ne 0 ]; then
        printf '[ERROR] Please run as root (sudo) to manage Linux network namespaces and tayga.\n' >&2
        exit 1
    fi
}

cmd_up_linux() {
    require_linux_root
    for bin in ip tayga iptables; do
        if ! command -v "$bin" >/dev/null 2>&1; then
            printf '[ERROR] Missing required binary: %s\n' "$bin" >&2
            exit 1
        fi
    done

    mkdir -p /run/mesh-nat64 /var/db/tayga-mesh
    cat > /run/mesh-nat64/tayga.conf <<EOF
tun-device $TAYGA_IF
ipv4-addr 192.168.255.1
prefix $NAT64_PREFIX
dynamic-pool $LAB_IPV4_POOL
data-dir /var/db/tayga-mesh
EOF

    ip netns del "$LAB_NS" 2>/dev/null || true
    ip link del veth-nat64-host 2>/dev/null || true
    ip netns add "$LAB_NS"

    # Host <-> IPv6-only client namespace (intentionally ZERO IPv4 address on veth-nat64-cli)
    ip link add veth-nat64-host type veth peer name veth-nat64-cli
    ip link set veth-nat64-cli netns "$LAB_NS"
    ip addr add fd00:6464::1/64 dev veth-nat64-host
    ip link set veth-nat64-host up

    ip netns exec "$LAB_NS" ip link set lo up
    ip netns exec "$LAB_NS" ip link set veth-nat64-cli up
    ip netns exec "$LAB_NS" ip addr add fd00:6464::2/64 dev veth-nat64-cli
    ip netns exec "$LAB_NS" ip -6 route add default via fd00:6464::1 dev veth-nat64-cli

    # Start tayga translator in background for NAT64 64:ff9b::/96
    tayga --config /run/mesh-nat64/tayga.conf --mktun || true
    ip link set "$TAYGA_IF" up
    ip addr add 192.168.255.2/32 dev "$TAYGA_IF" || true
    ip route add "$LAB_IPV4_POOL" dev "$TAYGA_IF" || true
    ip -6 route add "$NAT64_PREFIX" dev "$TAYGA_IF" || true

    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null

    # Emit RFC 7050 ipv4only.arpa AAAA records (192.0.0.170 -> 64:ff9b::c000:00aa, .171 -> 64:ff9b::c000:00ab)
    if command -v dnsmasq >/dev/null 2>&1; then
        cat > /run/mesh-nat64/dnsmasq.conf <<'EOF'
no-resolv
listen-address=fd00:6464::1
bind-interfaces
host-record=ipv4only.arpa,192.0.0.170,64:ff9b::c000:00aa
host-record=ipv4only.arpa,192.0.0.171,64:ff9b::c000:00ab
EOF
        dnsmasq --conf-file=/run/mesh-nat64/dnsmasq.conf --pid-file=/run/mesh-nat64/dnsmasq.pid
    fi

    printf '[OK] Linux IPv6-only NAT64 lab active (ns=%s, prefix=%s, dns64=fd00:6464::1)\n' \
        "$LAB_NS" "$NAT64_PREFIX"
}

cmd_down_linux() {
    require_linux_root
    if [ -f /run/mesh-nat64/dnsmasq.pid ]; then
        kill "$(cat /run/mesh-nat64/dnsmasq.pid)" 2>/dev/null || true
    fi
    pkill -f '/run/mesh-nat64/tayga.conf' 2>/dev/null || true
    ip link del "$TAYGA_IF" 2>/dev/null || true
    ip netns del "$LAB_NS" 2>/dev/null || true
    ip link del veth-nat64-host 2>/dev/null || true
    rm -rf /run/mesh-nat64
    printf '[OK] Torn down NAT64 lab.\n'
}

cmd_verify_dns64() {
    printf '=== Verifying RFC 7050 ipv4only.arpa & NAT64 Prefix %s ===\n' "$NAT64_PREFIX"
    if command -v dig >/dev/null 2>&1; then
        dig +short AAAA ipv4only.arpa || true
    elif command -v python3 >/dev/null 2>&1; then
        python3 - <<'PY'
import ipaddress, socket
try:
    infos = socket.getaddrinfo("ipv4only.arpa", 0, socket.AF_INET6)
    addrs = sorted({i[4][0] for i in infos})
    print("ipv4only.arpa AAAA:", addrs)
    for a in addrs:
        v6 = ipaddress.IPv6Address(a)
        pref = ipaddress.IPv6Network((int(v6) >> 32 << 32, 96))
        print("  detected /96 prefix:", pref)
except Exception as exc:
    print("lookup note:", exc)
PY
    else
        printf 'Neither dig nor python3 installed; verify AAAA ipv4only.arpa manually.\n'
    fi
}

cmd_macos_guide() {
    cat <<'EOF'
macOS Host Internet Sharing NAT64 (for physical iPhone & iOS Simulator):
  1. System Settings -> General -> Sharing -> Internet Sharing (off while configuring).
  2. Hold Option (Alt) when clicking Internet Sharing checkbox/options -> check "Create NAT64 Network".
  3. Share from Ethernet/Wi-Fi to a USB Ethernet/secondary Wi-Fi adapter or iPhone USB hotspot interface.
  4. Verify RFC 7050 prefix on device / macOS:
       scutil --dns | grep -A3 ipv4only
       dig @2001:4860:4860::6464 AAAA ipv4only.arpa
  5. Expect 64:ff9b::c000:00aa and 64:ff9b::c000:00ab (or carrier /96 prefix).
EOF
}

cmd_android_guide() {
    cat <<'EOF'
Android NAT64 Lab Verification (US-077 / US-095):
  1. Connect Android device or emulator to an IPv6-only Wi-Fi / Linux NAT64 bridge (no DHCPv4).
  2. Inspect LinkProperties & NAT64 prefix detection:
       adb shell dumpsys connectivity | grep -E "Nat64Prefix|DnsAddresses|LinkAddresses"
  3. Verify `mesh-mobile-ffi` activates `Nat64Synthesizer` ONLY when `!has_ipv4 && has_ipv6`
     and NEVER synthesizes RFC 1918 LAN targets (`10/8`, `172.16/12`, `192.168/16`).
EOF
}

case "${1:-}" in
    up-linux)
        cmd_up_linux
        ;;
    down-linux)
        cmd_down_linux
        ;;
    verify-dns64)
        cmd_verify_dns64
        ;;
    macos-guide)
        cmd_macos_guide
        ;;
    android-guide)
        cmd_android_guide
        ;;
    *)
        usage
        exit 1
        ;;
esac
