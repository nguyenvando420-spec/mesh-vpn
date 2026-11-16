package dev.meshvpn.android.data.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkAddress
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.NetworkInterface
import java.net.SocketException
import uniffi.mesh_mobile_ffi.MobileNetEventKind
import uniffi.mesh_mobile_ffi.MobileUnderlayState

/**
 * Pure JVM-testable underlay snapshot inputs abstracted away from Android framework types.
 */
data class RawLinkSnapshot(
    val activeInterfaceName: String?,
    val physicalIfIndex: UInt?,
    val hasIpv4: Boolean,
    val hasIpv6: Boolean,
    val underlayDnsServers: List<String>,
    val osNat64Prefix: String?,
    val physicalSubnets: List<String>,
    val isAndroidLockdownEnabled: Boolean,
    val isPrivateDnsActive: Boolean,
    val privateDnsServerName: String?,
)

object UnderlayStateClassifier {
    fun classifyPrivateDnsStrict(
        isPrivateDnsActive: Boolean,
        privateDnsServerName: String?,
    ): Boolean = isPrivateDnsActive && !privateDnsServerName.isNullOrBlank()

    fun toMobileUnderlayState(raw: RawLinkSnapshot): MobileUnderlayState {
        val cleanInterface = raw.activeInterfaceName?.trim()?.takeIf { it.isNotEmpty() }
        val cleanDns = raw.underlayDnsServers
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .distinct()
        val cleanSubnets = raw.physicalSubnets
            .map { it.trim() }
            .filter { it.contains("/") }
            .distinct()
        val strictPrivateDns = classifyPrivateDnsStrict(
            isPrivateDnsActive = raw.isPrivateDnsActive,
            privateDnsServerName = raw.privateDnsServerName,
        )
        val cleanServerName = raw.privateDnsServerName?.trim()?.takeIf { it.isNotEmpty() }
        return MobileUnderlayState(
            activeInterfaceName = cleanInterface,
            physicalIfIndex = raw.physicalIfIndex,
            hasIpv4 = raw.hasIpv4,
            hasIpv6 = raw.hasIpv6,
            underlayDnsServers = cleanDns,
            osNat64Prefix = raw.osNat64Prefix?.trim()?.takeIf { it.isNotEmpty() },
            physicalSubnets = cleanSubnets,
            isAndroidLockdownEnabled = raw.isAndroidLockdownEnabled,
            isAndroidPrivateDnsStrict = strictPrivateDns,
            privateDnsServerName = cleanServerName,
        )
    }

    fun inferChangeKind(
        previous: MobileUnderlayState?,
        current: MobileUnderlayState,
    ): MobileNetEventKind {
        if (previous == null) {
            return MobileNetEventKind.CONNECTIVITY_RESTORED
        }
        val prevOnline = previous.hasIpv4 || previous.hasIpv6
        val currOnline = current.hasIpv4 || current.hasIpv6
        return when {
            prevOnline && !currOnline -> MobileNetEventKind.CONNECTIVITY_LOST
            !prevOnline && currOnline -> MobileNetEventKind.CONNECTIVITY_RESTORED
            previous.activeInterfaceName != current.activeInterfaceName ||
                previous.physicalIfIndex != current.physicalIfIndex ->
                MobileNetEventKind.INTERFACE_CHANGED
            previous.underlayDnsServers != current.underlayDnsServers ||
                previous.osNat64Prefix != current.osNat64Prefix ||
                previous.isAndroidPrivateDnsStrict != current.isAndroidPrivateDnsStrict ->
                MobileNetEventKind.DNS_SERVERS_CHANGED
            else -> MobileNetEventKind.ADDRESS_CHANGED
        }
    }

    fun emptyOfflineState(isLockdownEnabled: Boolean): MobileUnderlayState = MobileUnderlayState(
        activeInterfaceName = null,
        physicalIfIndex = null,
        hasIpv4 = false,
        hasIpv6 = false,
        underlayDnsServers = emptyList(),
        osNat64Prefix = null,
        physicalSubnets = emptyList(),
        isAndroidLockdownEnabled = isLockdownEnabled,
        isAndroidPrivateDnsStrict = false,
        privateDnsServerName = null,
    )
}

/**
 * Collects live underlay network state from Android [ConnectivityManager], avoiding VPN interfaces
 * so Split-DNS upstream servers and NAT64 prefixes reflect the physical underlay network.
 */
class AndroidUnderlayStateCollector(
    private val context: Context,
    private val lockdownProvider: () -> Boolean,
) {
    fun collectUnderlayState(explicitNetwork: Network? = null): MobileUnderlayState {
        val cm = context.getSystemService(ConnectivityManager::class.java)
            ?: return UnderlayStateClassifier.emptyOfflineState(lockdownProvider())

        val physicalNet = findBestPhysicalNetwork(cm, explicitNetwork)
            ?: return UnderlayStateClassifier.emptyOfflineState(lockdownProvider())

        val lp = cm.getLinkProperties(physicalNet)
            ?: return UnderlayStateClassifier.emptyOfflineState(lockdownProvider())

        val raw = extractRawSnapshot(cm, lp)
        return UnderlayStateClassifier.toMobileUnderlayState(raw)
    }

    private fun findBestPhysicalNetwork(
        cm: ConnectivityManager,
        explicitNetwork: Network?,
    ): Network? {
        if (explicitNetwork != null) {
            val caps = cm.getNetworkCapabilities(explicitNetwork)
            if (isPhysicalInternetNetwork(caps)) {
                return explicitNetwork
            }
        }
        val active = cm.activeNetwork
        if (active != null && isPhysicalInternetNetwork(cm.getNetworkCapabilities(active))) {
            return active
        }
        @Suppress("DEPRECATION")
        val allNetworks = cm.allNetworks
        return allNetworks.firstOrNull { net ->
            isPhysicalInternetNetwork(cm.getNetworkCapabilities(net))
        }
    }

    private fun isPhysicalInternetNetwork(caps: NetworkCapabilities?): Boolean {
        if (caps == null) {
            return false
        }
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
    }

    private fun extractRawSnapshot(
        cm: ConnectivityManager,
        activeLp: LinkProperties,
    ): RawLinkSnapshot {
        val ifName = activeLp.interfaceName
        val ifIndex = resolveInterfaceIndex(ifName)

        var hasIpv4 = false
        var hasIpv6 = false
        for (la in activeLp.linkAddresses) {
            val addr = la.address
            if (addr is Inet4Address && !addr.isLoopbackAddress) {
                hasIpv4 = true
            } else if (addr is Inet6Address &&
                !addr.isLoopbackAddress &&
                !addr.isLinkLocalAddress
            ) {
                hasIpv6 = true
            }
        }

        val dnsServers = activeLp.dnsServers.mapNotNull { it.hostAddress }
        val nat64Prefix = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            activeLp.nat64Prefix?.let { prefix ->
                val addr = prefix.address.hostAddress
                if (addr != null) "$addr/${prefix.prefixLength}" else null
            }
        } else {
            null
        }

        val physicalSubnets = collectAllPhysicalSubnets(cm, activeLp)
        val isPrivateDnsActive = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            activeLp.isPrivateDnsActive
        } else {
            false
        }
        val privateDnsServerName = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            activeLp.privateDnsServerName
        } else {
            null
        }

        return RawLinkSnapshot(
            activeInterfaceName = ifName,
            physicalIfIndex = ifIndex,
            hasIpv4 = hasIpv4,
            hasIpv6 = hasIpv6,
            underlayDnsServers = dnsServers,
            osNat64Prefix = nat64Prefix,
            physicalSubnets = physicalSubnets,
            isAndroidLockdownEnabled = lockdownProvider(),
            isPrivateDnsActive = isPrivateDnsActive,
            privateDnsServerName = privateDnsServerName,
        )
    }

    private fun collectAllPhysicalSubnets(
        cm: ConnectivityManager,
        activeLp: LinkProperties,
    ): List<String> {
        val subnets = linkedSetOf<String>()
        addSubnetsFromLinkAddresses(activeLp.linkAddresses, subnets)
        @Suppress("DEPRECATION")
        for (net in cm.allNetworks) {
            val caps = cm.getNetworkCapabilities(net)
            if (isPhysicalInternetNetwork(caps)) {
                val lp = cm.getLinkProperties(net)
                if (lp != null) {
                    addSubnetsFromLinkAddresses(lp.linkAddresses, subnets)
                }
            }
        }
        return subnets.toList()
    }

    private fun addSubnetsFromLinkAddresses(
        addresses: List<LinkAddress>,
        dest: MutableSet<String>,
    ) {
        for (la in addresses) {
            val addr = la.address
            if (!addr.isLoopbackAddress && !addr.isLinkLocalAddress) {
                val host = addr.hostAddress
                if (host != null) {
                    dest.add("$host/${la.prefixLength}")
                }
            }
        }
    }

    private fun resolveInterfaceIndex(ifName: String?): UInt? {
        if (ifName.isNullOrBlank()) {
            return null
        }
        return try {
            val nif = NetworkInterface.getByName(ifName)
            val idx = nif?.index ?: 0
            if (idx > 0) idx.toUInt() else null
        } catch (_: SocketException) {
            null
        } catch (_: SecurityException) {
            null
        }
    }
}
