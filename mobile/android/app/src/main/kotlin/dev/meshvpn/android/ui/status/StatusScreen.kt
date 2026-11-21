package dev.meshvpn.android.ui.status

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.meshvpn.android.ffi.UiErrorInfo
import dev.meshvpn.android.ffi.UiErrorKind
import dev.meshvpn.android.ui.MainUiScreenState
import dev.meshvpn.android.ui.theme.MeshTokens
import dev.meshvpn.android.vpn.MeshSessionUiState
import uniffi.mesh_mobile_ffi.MobileDaemonState
import uniffi.mesh_mobile_ffi.MobileNetcheckResponse
import uniffi.mesh_mobile_ffi.MobileStatusSnapshot
import uniffi.mesh_mobile_ffi.MobileWarningKind

fun canonicalDaemonStateLabel(state: MobileDaemonState): String =
    when (state) {
        MobileDaemonState.STOPPED -> "Disconnected"
        MobileDaemonState.DEVICE_LOCKED -> "Waiting for Unlock"
        MobileDaemonState.CONNECTING -> "Connecting"
        MobileDaemonState.CONNECTED -> "Connected"
        MobileDaemonState.DEGRADED -> "Degraded"
        MobileDaemonState.REAUTH_REQUIRED -> "Re-auth Required"
        MobileDaemonState.REVOKED -> "Device Revoked"
        MobileDaemonState.SERVER_UPGRADE_REQUIRED -> "Attention Required"
    }

fun daemonStateSemanticColor(state: MobileDaemonState): Color =
    when (state) {
        MobileDaemonState.CONNECTED -> MeshTokens.SemanticSuccess
        MobileDaemonState.CONNECTING,
        MobileDaemonState.DEGRADED,
        MobileDaemonState.REAUTH_REQUIRED,
        -> MeshTokens.SemanticWarning
        MobileDaemonState.REVOKED,
        MobileDaemonState.SERVER_UPGRADE_REQUIRED,
        -> MeshTokens.SemanticError
        MobileDaemonState.STOPPED,
        MobileDaemonState.DEVICE_LOCKED,
        -> MeshTokens.SemanticNeutral
    }

@Composable
fun StatusScreen(
    screenState: MainUiScreenState,
    onToggleTunnel: () -> Unit,
    onRunNetcheck: () -> Unit,
    onOpenVpnSettings: () -> Unit,
    onOpenNetworkSettings: () -> Unit,
    onOpenDateTimeSettings: () -> Unit,
    onOpenPeersTab: () -> Unit,
    onOpenSettingsTab: () -> Unit,
    onResetAndReenroll: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val session = screenState.session
    Column(
        modifier =
            modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        StatusHeaderCard(session = session, onToggleTunnel = onToggleTunnel)

        if (session.isBusy) {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        }

        WarningBanners(
            session = session,
            onOpenVpnSettings = onOpenVpnSettings,
            onOpenNetworkSettings = onOpenNetworkSettings,
        )

        ActionableErrorSection(
            uiError = session.lastError,
            inputError = screenState.inputError,
            infoBanner = screenState.infoBanner,
            onOpenDateTimeSettings = onOpenDateTimeSettings,
            onOpenNetworkSettings = onOpenNetworkSettings,
            onOpenSettingsTab = onOpenSettingsTab,
            onResetAndReenroll = onResetAndReenroll,
        )

        SelfTelemetryCard(session = session)
        NetcheckSection(
            isConnected = session.daemonState == MobileDaemonState.CONNECTED,
            netcheck = session.lastNetcheckResult,
            onRunNetcheck = onRunNetcheck,
        )
        PeersSummaryCard(
            snapshot = session.snapshot,
            onOpenPeersTab = onOpenPeersTab,
        )
    }
}

@Composable
private fun StatusHeaderCard(
    session: MeshSessionUiState,
    onToggleTunnel: () -> Unit,
) {
    val active =
        session.daemonState == MobileDaemonState.CONNECTED ||
            session.daemonState == MobileDaemonState.CONNECTING ||
            session.daemonState == MobileDaemonState.DEGRADED
    val statusColor = daemonStateSemanticColor(session.daemonState)
    val stateLabel = canonicalDaemonStateLabel(session.daemonState)

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                AssistChip(
                    onClick = {},
                    colors =
                        AssistChipDefaults.assistChipColors(
                            labelColor = statusColor,
                        ),
                    label = {
                        Text(
                            text = stateLabel,
                            style = MaterialTheme.typography.titleMedium,
                            modifier = Modifier.testTag("daemon_state_label"),
                        )
                    },
                )
                AssistChip(
                    onClick = {},
                    label = {
                        val ip =
                            session.snapshot?.overlayIp
                                ?: session.bootstrapSummary?.overlayIp
                                ?: "--"
                        Text(ip)
                    },
                )
            }
            val fqdn = session.snapshot?.fqdn ?: session.bootstrapSummary?.fqdn
            if (!fqdn.isNullOrBlank()) {
                Text(
                    text = fqdn,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.labelMedium,
                )
            }
            Button(
                onClick = onToggleTunnel,
                enabled = !session.isBusy && session.isDeviceUnlocked,
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .testTag("toggle_tunnel_button"),
            ) {
                Text(if (active) "Disconnect VPN" else "Connect VPN")
            }
        }
    }
}

@Composable
private fun WarningBanners(
    session: MeshSessionUiState,
    onOpenVpnSettings: () -> Unit,
    onOpenNetworkSettings: () -> Unit,
) {
    if (session.isLockdownEnabled) {
        WarningCard(
            title = "Always-On Lockdown Enabled",
            detail = "Android 'Block connections without VPN' may interrupt pre-TUN probes.",
            actionLabel = "Open VPN Settings",
            onAction = onOpenVpnSettings,
            modifier = Modifier.testTag("warning_lockdown"),
        )
    }
    if (session.isPrivateDnsStrict) {
        val dnsHost = session.privateDnsServerName ?: "hostname"
        WarningCard(
            title = "Strict Private DNS (:853) Active",
            detail = "Android Private DNS ($dnsHost) can bypass Mesh Split-DNS for *.mesh names.",
            actionLabel = "Network Settings",
            onAction = onOpenNetworkSettings,
            modifier = Modifier.testTag("warning_private_dns"),
        )
    }
    for (warning in session.activeWarnings) {
        if (warning.kind != MobileWarningKind.ANDROID_LOCKDOWN_ACTIVE &&
            warning.kind != MobileWarningKind.ANDROID_PRIVATE_DNS_STRICT
        ) {
            WarningCard(
                title = warning.kind.name,
                detail = warning.message,
                actionLabel = null,
                onAction = {},
            )
        }
    }
}

@Composable
private fun WarningCard(
    title: String,
    detail: String,
    actionLabel: String?,
    onAction: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(
        colors =
            CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.tertiaryContainer,
            ),
        modifier = modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(
                    imageVector = Icons.Outlined.WarningAmber,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onTertiaryContainer,
                )
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onTertiaryContainer,
                )
            }
            Text(
                text = detail,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onTertiaryContainer,
            )
            if (actionLabel != null) {
                OutlinedButton(onClick = onAction) {
                    Text(actionLabel)
                }
            }
        }
    }
}

@Composable
private fun ActionableErrorSection(
    uiError: UiErrorInfo?,
    inputError: String?,
    infoBanner: String?,
    onOpenDateTimeSettings: () -> Unit,
    onOpenNetworkSettings: () -> Unit,
    onOpenSettingsTab: () -> Unit,
    onResetAndReenroll: () -> Unit,
) {
    if (!infoBanner.isNullOrBlank()) {
        Card(
            colors =
                CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.secondaryContainer,
                ),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                text = infoBanner,
                color = MaterialTheme.colorScheme.onSecondaryContainer,
                modifier = Modifier.padding(12.dp),
            )
        }
    }

    val error =
        uiError ?: inputError?.let {
            UiErrorInfo(
                kind = UiErrorKind.INVALID_ARGUMENT,
                code = "E_INPUT",
                title = "Notice",
                detail = it,
                actionHint = "",
            )
        } ?: return

    Card(
        colors =
            CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.errorContainer,
            ),
        modifier =
            Modifier
                .fillMaxWidth()
                .testTag("error_card"),
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                text = "${error.title} (${error.code})",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onErrorContainer,
            )
            Text(
                text = error.detail,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onErrorContainer,
            )
            if (error.actionHint.isNotBlank()) {
                Text(
                    text = error.actionHint,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
            }
            ErrorRecoveryButton(
                kind = error.kind,
                onOpenDateTimeSettings = onOpenDateTimeSettings,
                onOpenNetworkSettings = onOpenNetworkSettings,
                onOpenSettingsTab = onOpenSettingsTab,
                onResetAndReenroll = onResetAndReenroll,
            )
        }
    }
}

@Composable
private fun ErrorRecoveryButton(
    kind: UiErrorKind,
    onOpenDateTimeSettings: () -> Unit,
    onOpenNetworkSettings: () -> Unit,
    onOpenSettingsTab: () -> Unit,
    onResetAndReenroll: () -> Unit,
) {
    when (kind) {
        UiErrorKind.CLOCK_SKEW ->
            OutlinedButton(onClick = onOpenDateTimeSettings) {
                Text("Date & Time Settings")
            }
        UiErrorKind.CAPTIVE_PORTAL ->
            OutlinedButton(onClick = onOpenNetworkSettings) {
                Text("Network Settings")
            }
        UiErrorKind.PIN_MISMATCH ->
            OutlinedButton(onClick = onOpenSettingsTab) {
                Text("Review Server Pin")
            }
        UiErrorKind.NODE_REVOKED,
        UiErrorKind.NODE_KEY_EXPIRED,
        UiErrorKind.KEYSTORE_INVALIDATED,
        ->
            OutlinedButton(onClick = onResetAndReenroll) {
                Text("Reset & Re-enroll")
            }
        else -> Unit
    }
}

@Composable
private fun SelfTelemetryCard(session: MeshSessionUiState) {
    val snap = session.snapshot
    val server = snap?.serverConnection
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text("Tunnel Telemetry", style = MaterialTheme.typography.titleMedium)
            val endpoint =
                server?.controlEndpoint
                    ?: session.bootstrapSummary?.serverEndpoint
                    ?: "Not configured"
            Text("Control: $endpoint")
            if (snap != null) {
                val net = snap.selfNetwork
                Text("NAT: ${net.natType.name} | UDP Port: ${net.localUdpPort}")
                val relayState =
                    if (server?.relayConnected == true) {
                        "Connected (${server.relayRttMs ?: "-"} ms)"
                    } else {
                        "Disconnected"
                    }
                Text("Blind Relay: $relayState")
                net.boundPhysicalInterface?.let { iface ->
                    Text("Physical Interface: $iface")
                }
                net.nat64ActivePrefix?.let { prefix ->
                    Text("NAT64 Prefix: $prefix")
                }
            }
        }
    }
}

@Composable
private fun NetcheckSection(
    isConnected: Boolean,
    netcheck: MobileNetcheckResponse?,
    onRunNetcheck: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("Network Check", style = MaterialTheme.typography.titleMedium)
                OutlinedButton(onClick = onRunNetcheck, enabled = isConnected) {
                    Text("Run Netcheck")
                }
            }
            if (netcheck != null) {
                Text("UDP Reachable: ${netcheck.udpReachable} | NAT: ${netcheck.natType.name}")
                Text("IPv4: ${netcheck.ipv4Available} | IPv6: ${netcheck.ipv6Available}")
                Text(
                    "Relay: ${netcheck.relayConnected} (${netcheck.relayRttMs ?: "-"} ms)" +
                        (netcheck.mappedEndpoint?.let { " | Mapped: $it" } ?: ""),
                )
            }
        }
    }
}

@Composable
private fun PeersSummaryCard(
    snapshot: MobileStatusSnapshot?,
    onOpenPeersTab: () -> Unit,
) {
    val peers = snapshot?.peers.orEmpty()
    val onlineCount = peers.count { it.online }
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text("Mesh Peers", style = MaterialTheme.typography.titleMedium)
                Text(
                    text = "$onlineCount online of ${peers.size} total",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            OutlinedButton(onClick = onOpenPeersTab) {
                Text("View Peers")
            }
        }
    }
}
