package dev.meshvpn.android.ui.peers

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Clear
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.meshvpn.android.ui.MainUiScreenState
import dev.meshvpn.android.ui.theme.MeshTokens
import java.util.Locale
import uniffi.mesh_mobile_ffi.MobileActivePathKind
import uniffi.mesh_mobile_ffi.MobilePeerStatus
import uniffi.mesh_mobile_ffi.MobilePingResponse

enum class PeerFilterMode {
    ALL,
    ONLINE,
    DIRECT,
    RELAY,
}

data class PeerFilterCounts(
    val all: Int = 0,
    val online: Int = 0,
    val direct: Int = 0,
    val relay: Int = 0,
)

fun countPeersByMode(peers: List<MobilePeerStatus>): PeerFilterCounts =
    PeerFilterCounts(
        all = peers.size,
        online = peers.count { it.online },
        direct = peers.count { it.activePath == MobileActivePathKind.DIRECT },
        relay = peers.count { it.activePath == MobileActivePathKind.RELAY },
    )

fun filterPeers(
    peers: List<MobilePeerStatus>,
    query: String,
    mode: PeerFilterMode,
): List<MobilePeerStatus> {
    val normalizedQuery = query.trim().lowercase(Locale.ROOT)
    return peers.filter { peer ->
        val matchesMode =
            when (mode) {
                PeerFilterMode.ALL -> true
                PeerFilterMode.ONLINE -> peer.online
                PeerFilterMode.DIRECT -> peer.activePath == MobileActivePathKind.DIRECT
                PeerFilterMode.RELAY -> peer.activePath == MobileActivePathKind.RELAY
            }
        if (!matchesMode) {
            false
        } else if (normalizedQuery.isEmpty()) {
            true
        } else {
            peer.name.lowercase(Locale.ROOT).contains(normalizedQuery) ||
                peer.fqdn.lowercase(Locale.ROOT).contains(normalizedQuery) ||
                peer.overlayIp.lowercase(Locale.ROOT).contains(normalizedQuery) ||
                peer.nodeId.lowercase(Locale.ROOT).contains(normalizedQuery)
        }
    }
}

@Composable
fun PeersScreen(
    screenState: MainUiScreenState,
    onSearchQueryChanged: (String) -> Unit,
    onSelectFilterMode: (PeerFilterMode) -> Unit,
    onPingPeer: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val allPeers = screenState.session.snapshot?.peers.orEmpty()
    val counts = countPeersByMode(allPeers)
    val filteredPeers =
        filterPeers(
            peers = allPeers,
            query = screenState.peerSearchQuery,
            mode = screenState.peerFilterMode,
        )

    Column(
        modifier =
            modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Peers (${allPeers.size})", style = MaterialTheme.typography.headlineSmall)

        PeerSearchField(
            query = screenState.peerSearchQuery,
            onQueryChanged = onSearchQueryChanged,
        )

        PeerFilterChipsRow(
            selected = screenState.peerFilterMode,
            counts = counts,
            onSelect = onSelectFilterMode,
        )

        screenState.session.lastPingResult?.let { ping ->
            PeersPingResultCard(ping = ping)
        }

        if (allPeers.isEmpty()) {
            Text(
                text = "No peers visible yet. Connect to receive mesh Netmap.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else if (filteredPeers.isEmpty()) {
            Text(
                text = "No peers match the current search or filter.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            for (peer in filteredPeers) {
                PeerDetailCard(
                    peer = peer,
                    onCopyIp = {
                        copyNonSecretText(
                            context = context,
                            label = "Mesh Overlay IP",
                            value = peer.overlayIp,
                            toastMessage = "Copied IP: ${peer.overlayIp}",
                        )
                    },
                    onCopyFqdn = {
                        copyNonSecretText(
                            context = context,
                            label = "Mesh FQDN",
                            value = peer.fqdn,
                            toastMessage = "Copied FQDN: ${peer.fqdn}",
                        )
                    },
                    onPingPeer = { onPingPeer(peer.overlayIp) },
                )
            }
        }
    }
}

@Composable
private fun PeerSearchField(
    query: String,
    onQueryChanged: (String) -> Unit,
) {
    OutlinedTextField(
        value = query,
        onValueChange = onQueryChanged,
        label = { Text("Search peers") },
        placeholder = { Text("Name, FQDN, IP, or node ID") },
        leadingIcon = {
            Icon(imageVector = Icons.Outlined.Search, contentDescription = null)
        },
        trailingIcon = {
            if (query.isNotEmpty()) {
                IconButton(onClick = { onQueryChanged("") }) {
                    Icon(
                        imageVector = Icons.Outlined.Clear,
                        contentDescription = "Clear search",
                    )
                }
            }
        },
        singleLine = true,
        modifier =
            Modifier
                .fillMaxWidth()
                .testTag("peers_search_field"),
    )
}

@Composable
private fun PeerFilterChipsRow(
    selected: PeerFilterMode,
    counts: PeerFilterCounts,
    onSelect: (PeerFilterMode) -> Unit,
) {
    val chips =
        listOf(
            Triple(PeerFilterMode.ALL, "All (${counts.all})", "peers_filter_all"),
            Triple(PeerFilterMode.ONLINE, "Online (${counts.online})", "peers_filter_online"),
            Triple(PeerFilterMode.DIRECT, "Direct (${counts.direct})", "peers_filter_direct"),
            Triple(PeerFilterMode.RELAY, "Relay (${counts.relay})", "peers_filter_relay"),
        )
    Row(
        modifier =
            Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        for ((mode, label, tag) in chips) {
            FilterChip(
                selected = selected == mode,
                onClick = { onSelect(mode) },
                label = { Text(label) },
                modifier = Modifier.testTag(tag),
            )
        }
    }
}

@Composable
private fun PeerDetailCard(
    peer: MobilePeerStatus,
    onCopyIp: () -> Unit,
    onCopyFqdn: () -> Unit,
    onPingPeer: () -> Unit,
) {
    val statusColor = peerStatusColor(peer)
    val pathLabel = peerPathLabel(peer)

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = peer.name,
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Text(
                        text = peer.nodeId,
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                AssistChip(
                    onClick = {},
                    label = { Text(pathLabel) },
                    colors =
                        AssistChipDefaults.assistChipColors(
                            labelColor = statusColor,
                        ),
                )
            }
            Text(
                text = peer.overlayIp,
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodyMedium,
            )
            if (peer.fqdn.isNotBlank()) {
                Text(
                    text = peer.fqdn,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(
                text =
                    "RTT: ${peer.rttMs?.let { "$it ms" } ?: "--"} | " +
                        "RX ${peer.rxBytes} B / TX ${peer.txBytes} B",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(
                    onClick = onCopyIp,
                    enabled = peer.overlayIp.isNotBlank(),
                    modifier = Modifier.testTag("peers_copy_ip_button"),
                ) {
                    Icon(imageVector = Icons.Outlined.ContentCopy, contentDescription = null)
                    Text(" Copy IP")
                }
                OutlinedButton(
                    onClick = onCopyFqdn,
                    enabled = peer.fqdn.isNotBlank(),
                    modifier = Modifier.testTag("peers_copy_fqdn_button"),
                ) {
                    Icon(imageVector = Icons.Outlined.ContentCopy, contentDescription = null)
                    Text(" Copy FQDN")
                }
                OutlinedButton(
                    onClick = onPingPeer,
                    enabled = peer.online,
                ) {
                    Text("Ping")
                }
            }
        }
    }
}

@Composable
private fun PeersPingResultCard(ping: MobilePingResponse) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            val avg =
                ping.avgRttMs?.let {
                    String.format(Locale.US, "%.1f ms", it)
                } ?: "timeout"
            Text(
                text = "Last Ping: ${ping.peerName} (${ping.peerOverlayIp}) avg=$avg",
                style = MaterialTheme.typography.titleMedium,
            )
            for (sample in ping.samples) {
                val rtt = sample.rttMs?.let { String.format(Locale.US, "%.1f ms", it) } ?: "--"
                Text(
                    text = "#${sample.seq} via ${sample.via.name}: $rtt",
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.labelMedium,
                )
            }
        }
    }
}

private fun peerStatusColor(peer: MobilePeerStatus): Color =
    when {
        !peer.online -> MeshTokens.SemanticNeutral
        peer.activePath == MobileActivePathKind.DIRECT -> MeshTokens.SemanticSuccess
        peer.activePath == MobileActivePathKind.RELAY -> MeshTokens.SemanticWarning
        else -> MeshTokens.SemanticNeutral
    }

private fun peerPathLabel(peer: MobilePeerStatus): String =
    when {
        !peer.online -> "Offline"
        peer.activePath == MobileActivePathKind.DIRECT -> "Direct"
        peer.activePath == MobileActivePathKind.RELAY -> "Relay"
        else -> "Online"
    }

private fun copyNonSecretText(
    context: Context,
    label: String,
    value: String,
    toastMessage: String,
) {
    if (value.isBlank()) {
        return
    }
    val manager = context.getSystemService(ClipboardManager::class.java) ?: return
    // Non-secret IP/FQDN copy must NOT schedule any clipboard wipe or trigger FLAG_SECURE.
    manager.setPrimaryClip(ClipData.newPlainText(label, value))
    Toast.makeText(context, toastMessage, Toast.LENGTH_SHORT).show()
}
