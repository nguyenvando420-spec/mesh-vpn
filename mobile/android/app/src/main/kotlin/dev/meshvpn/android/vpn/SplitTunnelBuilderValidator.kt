package dev.meshvpn.android.vpn

import android.content.pm.PackageManager
import android.net.VpnService
import java.net.Inet4Address
import java.net.InetAddress
import uniffi.mesh_mobile_ffi.MobileTunnelNetworkConfig

data class ValidatedRouteCidr(
    val address: String,
    val prefixLength: Int,
)

data class ValidatedTunnelConfig(
    val overlayIp: String,
    val tunPrefixLength: Int,
    val overlayDnsIp: String,
    val domainSuffix: String,
    val mtu: Int,
    val routes: List<ValidatedRouteCidr>,
)

/**
 * Validates and applies Rust [MobileTunnelNetworkConfig] to Android [VpnService.Builder].
 *
 * Security invariants (`ADR-015`, `US-081`, `US-083`):
 * - TUN interface prefix is always `/32` to prevent implicit kernel subnet routes.
 * - Default route `0.0.0.0/0` is rejected fail-closed (`OQ-MOB-04` Split-Tunnel only).
 * - At least one included split-tunnel route must cover `overlayDnsIp/32`.
 * - `allowBypass()` is never enabled, and the app package itself is disallowed from TUN routing.
 */
object SplitTunnelBuilderValidator {
    const val REQUIRED_TUN_PREFIX_LEN = 32
    private const val MIN_MTU = 576
    private const val MAX_MTU = 1420
    private const val SESSION_NAME = "Mesh VPN"

    fun validate(config: MobileTunnelNetworkConfig): ValidatedTunnelConfig {
        require(config.tunInterfacePrefixLen.toInt() == REQUIRED_TUN_PREFIX_LEN) {
            "TUN interface prefix length must be /32, got /${config.tunInterfacePrefixLen}"
        }
        val overlayV4 = parseIpv4(config.overlayIp, "overlayIp")
        val dnsV4 = parseIpv4(config.overlayDnsIp, "overlayDnsIp")

        val mtu = config.tunMtu.toInt()
        require(mtu in MIN_MTU..MAX_MTU) {
            "TUN MTU $mtu outside valid range $MIN_MTU..$MAX_MTU"
        }

        require(config.includedRoutesCidr.isNotEmpty()) {
            "includedRoutesCidr must contain at least one split-tunnel route"
        }

        val parsedRoutes = config.includedRoutesCidr.map { rawCidr ->
            parseSplitTunnelRoute(rawCidr)
        }

        val dnsCovered = parsedRoutes.any { route -> cidrContains(route, dnsV4) }
        require(dnsCovered) {
            "Split-tunnel routes must cover overlayDnsIp (${dnsV4.hostAddress}/32)"
        }

        return ValidatedTunnelConfig(
            overlayIp = overlayV4.hostAddress ?: config.overlayIp,
            tunPrefixLength = REQUIRED_TUN_PREFIX_LEN,
            overlayDnsIp = dnsV4.hostAddress ?: config.overlayDnsIp,
            domainSuffix = config.domainSuffix.trim(),
            mtu = mtu,
            routes = parsedRoutes,
        )
    }

    fun applyToBuilder(
        builder: VpnService.Builder,
        packageName: String,
        config: MobileTunnelNetworkConfig,
    ): ValidatedTunnelConfig {
        val validated = validate(config)
        builder.setSession(SESSION_NAME)
        builder.addAddress(validated.overlayIp, REQUIRED_TUN_PREFIX_LEN)
        builder.addDnsServer(validated.overlayDnsIp)
        if (validated.domainSuffix.isNotEmpty()) {
            builder.addSearchDomain(validated.domainSuffix)
        }
        for (route in validated.routes) {
            builder.addRoute(route.address, route.prefixLength)
        }
        builder.setMtu(validated.mtu)
        builder.setBlocking(false)
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: PackageManager.NameNotFoundException) {
            // Package lookup should always succeed for own package; protect(fd) remains active.
        }
        return validated
    }

    internal fun parseSplitTunnelRoute(rawCidr: String): ValidatedRouteCidr {
        val trimmed = rawCidr.trim()
        val parts = trimmed.split('/')
        require(parts.size == 2) {
            "Invalid split-tunnel CIDR '$rawCidr'"
        }
        val ip = parseIpv4(parts[0], "route address")
        val prefix = parts[1].toIntOrNull()
            ?: throw IllegalArgumentException("Invalid CIDR prefix in '$rawCidr'")
        require(prefix in 1..32) {
            "Forbidden route prefix /$prefix in '$rawCidr' (0.0.0.0/0 is disallowed)"
        }
        val maskedIp = maskIpv4(ip, prefix)
        return ValidatedRouteCidr(
            address = intToIpv4String(maskedIp),
            prefixLength = prefix,
        )
    }

    private fun cidrContains(route: ValidatedRouteCidr, target: Inet4Address): Boolean {
        val routeNet = ipv4ToInt(parseIpv4(route.address, "validated route"))
        val targetInt = ipv4ToInt(target)
        val mask = prefixMaskInt(route.prefixLength)
        return (routeNet and mask) == (targetInt and mask)
    }

    private fun parseIpv4(raw: String, label: String): Inet4Address {
        val trimmed = raw.trim()
        val parts = trimmed.split('.')
        require(parts.size == 4) { "Invalid IPv4 $label: $raw" }
        val bytes = ByteArray(4)
        for (i in 0 until 4) {
            val octet = parts[i].toIntOrNull()
            require(octet != null && octet in 0..255) { "Invalid IPv4 octet in $label: $raw" }
            bytes[i] = octet.toByte()
        }
        return InetAddress.getByAddress(bytes) as Inet4Address
    }

    private fun ipv4ToInt(addr: Inet4Address): Int {
        val b = addr.address
        return ((b[0].toInt() and 0xFF) shl 24) or
            ((b[1].toInt() and 0xFF) shl 16) or
            ((b[2].toInt() and 0xFF) shl 8) or
            (b[3].toInt() and 0xFF)
    }

    private fun prefixMaskInt(prefixLen: Int): Int {
        if (prefixLen == 0) {
            return 0
        }
        return (-1) shl (32 - prefixLen)
    }

    private fun maskIpv4(addr: Inet4Address, prefixLen: Int): Int =
        ipv4ToInt(addr) and prefixMaskInt(prefixLen)

    private fun intToIpv4String(ipInt: Int): String =
        "${(ipInt ushr 24) and 0xFF}.${(ipInt ushr 16) and 0xFF}." +
            "${(ipInt ushr 8) and 0xFF}.${ipInt and 0xFF}"
}
