package dev.meshvpn.android.ui.status

import androidx.annotation.StringRes
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.meshvpn.android.LocaleHelper
import dev.meshvpn.android.R
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

@StringRes
fun daemonStateLabelRes(state: MobileDaemonState): Int =
    when (state) {
        MobileDaemonState.STOPPED -> R.string.state_disconnected
        MobileDaemonState.DEVICE_LOCKED -> R.string.notif_waiting_unlock
        MobileDaemonState.CONNECTING -> R.string.state_connecting
        MobileDaemonState.CONNECTED -> R.string.state_connected
        MobileDaemonState.DEGRADED -> R.string.state_degraded
        MobileDaemonState.REAUTH_REQUIRED -> R.string.state_reauth_required
        MobileDaemonState.REVOKED -> R.string.state_revoked
        MobileDaemonState.SERVER_UPGRADE_REQUIRED -> R.string.state_error
    }

@Composable
private fun localizedDaemonStateLabel(state: MobileDaemonState): String =
    stringResource(daemonStateLabelRes(state))

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
    val stateLabel = localizedDaemonStateLabel(session.daemonState)

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
                val toggleRes =
                    if (active) R.string.action_disconnect_vpn else R.string.action_connect_vpn
                Text(stringResource(toggleRes))
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
    val context = LocalContext.current
    if (session.isLockdownEnabled) {
        WarningCard(
            title = stringResource(R.string.warn_lockdown),
            detail =
                LocaleHelper.tr(
                    context,
                    "Android 'Block connections without VPN' may interrupt pre-TUN probes.",
                    "Chế độ chặn kết nối ngoài VPN của Android có thể làm gián đoạn dò đường.",
                ),
            actionLabel = stringResource(R.string.settings_open_vpn_settings),
            onAction = onOpenVpnSettings,
            modifier = Modifier.testTag("warning_lockdown"),
        )
    }
    if (session.isPrivateDnsStrict) {
        val dnsHost = session.privateDnsServerName ?: "hostname"
        WarningCard(
            title = stringResource(R.string.warn_private_dns),
            detail =
                LocaleHelper.tr(
                    context,
                    "Android Private DNS ($dnsHost) can bypass Mesh Split-DNS for *.mesh names.",
                    "DNS riêng Android ($dnsHost) có thể bỏ qua Split-DNS cho tên miền *.mesh.",
                ),
            actionLabel = stringResource(R.string.error_captive_portal),
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
                Text(stringResource(R.string.error_clock_skew))
            }
        UiErrorKind.CAPTIVE_PORTAL ->
            OutlinedButton(onClick = onOpenNetworkSettings) {
                Text(stringResource(R.string.error_captive_portal))
            }
        UiErrorKind.PIN_MISMATCH ->
            OutlinedButton(onClick = onOpenSettingsTab) {
                Text(stringResource(R.string.error_pin_mismatch))
            }
        UiErrorKind.NODE_REVOKED,
        UiErrorKind.NODE_KEY_EXPIRED,
        UiErrorKind.KEYSTORE_INVALIDATED,
        ->
            OutlinedButton(onClick = onResetAndReenroll) {
                Text(stringResource(R.string.error_reset_reenroll))
            }
        else -> Unit
    }
}

@Composable
private fun SelfTelemetryCard(session: MeshSessionUiState) {
    val context = LocalContext.current
    val snap = session.snapshot
    val server = snap?.serverConnection
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = stringResource(R.string.diag_tunnel_telemetry),
                style = MaterialTheme.typography.titleMedium,
            )
            val notConfigured = LocaleHelper.tr(context, "Not configured", "Chưa cấu hình")
            val endpoint =
                server?.controlEndpoint
                    ?: session.bootstrapSummary?.serverEndpoint
                    ?: notConfigured
            Text("${stringResource(R.string.label_control)}: $endpoint")
            if (snap != null) {
                val net = snap.selfNetwork
                val udpLabel = LocaleHelper.tr(context, "UDP Port", "Cổng UDP")
                Text("NAT: ${net.natType.name} | $udpLabel: ${net.localUdpPort}")
                val relayState =
                    if (server?.relayConnected == true) {
                        val connected = stringResource(R.string.state_connected)
                        "$connected (${server.relayRttMs ?: "-"} ms)"
                    } else {
                        stringResource(R.string.state_disconnected)
                    }
                Text("${stringResource(R.string.label_blind_relay)}: $relayState")
                net.boundPhysicalInterface?.let { iface ->
                    val ifaceLabel =
                        LocaleHelper.tr(context, "Physical Interface", "Giao diện vật lý")
                    Text("$ifaceLabel: $iface")
                }
                net.nat64ActivePrefix?.let { prefix ->
                    val nat64Label = LocaleHelper.tr(context, "NAT64 Prefix", "Tiền tố NAT64")
                    Text("$nat64Label: $prefix")
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
    val context = LocalContext.current
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
                Text(
                    text = stringResource(R.string.diag_network_check),
                    style = MaterialTheme.typography.titleMedium,
                )
                OutlinedButton(onClick = onRunNetcheck, enabled = isConnected) {
                    Text(stringResource(R.string.diag_run_netcheck))
                }
            }
            if (netcheck != null) {
                val udpLabel = LocaleHelper.tr(context, "UDP Reachable", "UDP khả dụng")
                Text("$udpLabel: ${netcheck.udpReachable} | NAT: ${netcheck.natType.name}")
                Text("IPv4: ${netcheck.ipv4Available} | IPv6: ${netcheck.ipv6Available}")
                val relayPrefix = stringResource(R.string.peers_filter_relay)
                val mappedPart =
                    netcheck.mappedEndpoint?.let { " | Mapped: $it" } ?: ""
                Text(
                    "$relayPrefix: ${netcheck.relayConnected} " +
                        "(${netcheck.relayRttMs ?: "-"} ms)$mappedPart",
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
    val context = LocalContext.current
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
                Text(
                    text = stringResource(R.string.tab_peers),
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    text =
                        LocaleHelper.tr(
                            context,
                            "$onlineCount online of ${peers.size} total",
                            "$onlineCount trực tuyến / ${peers.size} thiết bị",
                        ),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            OutlinedButton(onClick = onOpenPeersTab) {
                Text(LocaleHelper.tr(context, "View Peers", "Xem thiết bị"))
            }
        }
    }
}
