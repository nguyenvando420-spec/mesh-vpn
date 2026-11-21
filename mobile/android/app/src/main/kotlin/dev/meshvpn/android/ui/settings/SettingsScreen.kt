package dev.meshvpn.android.ui.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import dev.meshvpn.android.ui.MainUiScreenState
import dev.meshvpn.android.ui.theme.ThemeMode
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import uniffi.mesh_mobile_ffi.MobileDaemonState
import uniffi.mesh_mobile_ffi.MobileNetcheckResponse
import uniffi.mesh_mobile_ffi.MobileTlsAuthMode

@Composable
fun SettingsScreen(
    screenState: MainUiScreenState,
    onSelectThemeMode: (ThemeMode) -> Unit,
    onToggleRevealPins: () -> Unit,
    onSensitiveModalChanged: (Boolean) -> Unit,
    onUpdateServerConfig: (String, MobileTlsAuthMode, String) -> Unit,
    onRotateKey: (CharArray) -> Unit,
    onToggleAlwaysOnHint: (Boolean) -> Unit,
    onOpenVpnSettings: () -> Unit,
    onRunNetcheck: () -> Unit,
    onExportBugreport: () -> Unit,
    onCleanupDiagnostics: () -> Unit,
    onResetIdentity: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var showServerDialog by remember { mutableStateOf(false) }
    var showRotateDialog by remember { mutableStateOf(false) }
    var showResetDialog by remember { mutableStateOf(false) }

    val session = screenState.session
    val snapshot = session.snapshot
    val bootstrap = session.bootstrapSummary
    val currentEndpoint =
        snapshot?.serverConnection?.controlEndpoint ?: bootstrap?.serverEndpoint.orEmpty()
    val currentTlsMode =
        snapshot?.serverConnection?.tlsAuthMode
            ?: bootstrap?.tlsAuthMode
            ?: MobileTlsAuthMode.SPKI_PIN
    val activePin = snapshot?.serverConnection?.activePin ?: bootstrap?.activePin
    val nextPin = snapshot?.serverConnection?.nextPin ?: bootstrap?.nextPin

    SettingsBody(
        screenState = screenState,
        currentEndpoint = currentEndpoint,
        currentTlsMode = currentTlsMode,
        activePin = activePin,
        nextPin = nextPin,
        onSelectThemeMode = onSelectThemeMode,
        onToggleRevealPins = onToggleRevealPins,
        onOpenUpdateServer = {
            onSensitiveModalChanged(true)
            showServerDialog = true
        },
        onOpenRotateKey = {
            onSensitiveModalChanged(true)
            showRotateDialog = true
        },
        onOpenResetIdentity = { showResetDialog = true },
        onToggleAlwaysOnHint = onToggleAlwaysOnHint,
        onOpenVpnSettings = onOpenVpnSettings,
        onRunNetcheck = onRunNetcheck,
        onExportBugreport = onExportBugreport,
        onCleanupDiagnostics = onCleanupDiagnostics,
        modifier = modifier,
    )

    SettingsDialogs(
        showServerDialog = showServerDialog,
        showRotateDialog = showRotateDialog,
        showResetDialog = showResetDialog,
        currentEndpoint = currentEndpoint,
        currentTlsMode = currentTlsMode,
        activePin = activePin,
        onSensitiveModalChanged = onSensitiveModalChanged,
        onDismissServerDialog = { showServerDialog = false },
        onSubmitServerConfig = { ep, mode, pin ->
            showServerDialog = false
            onUpdateServerConfig(ep, mode, pin)
        },
        onDismissRotateDialog = { showRotateDialog = false },
        onSubmitRotateKey = { chars ->
            showRotateDialog = false
            onRotateKey(chars)
        },
        onDismissResetDialog = { showResetDialog = false },
        onConfirmResetIdentity = {
            showResetDialog = false
            onResetIdentity()
        },
    )
}

@Composable
private fun SettingsBody(
    screenState: MainUiScreenState,
    currentEndpoint: String,
    currentTlsMode: MobileTlsAuthMode,
    activePin: String?,
    nextPin: String?,
    onSelectThemeMode: (ThemeMode) -> Unit,
    onToggleRevealPins: () -> Unit,
    onOpenUpdateServer: () -> Unit,
    onOpenRotateKey: () -> Unit,
    onOpenResetIdentity: () -> Unit,
    onToggleAlwaysOnHint: (Boolean) -> Unit,
    onOpenVpnSettings: () -> Unit,
    onRunNetcheck: () -> Unit,
    onExportBugreport: () -> Unit,
    onCleanupDiagnostics: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val session = screenState.session
    val snapshot = session.snapshot
    val bootstrap = session.bootstrapSummary
    Column(
        modifier =
            modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Settings & Security", style = MaterialTheme.typography.headlineSmall)
        AppearanceCard(
            themeMode = screenState.themeMode,
            onSelectThemeMode = onSelectThemeMode,
        )
        ServerSecurityCard(
            endpoint = currentEndpoint,
            tlsMode = currentTlsMode,
            activePin = activePin,
            nextPin = nextPin,
            pinsRevealed = screenState.isAdminPinsRevealed,
            isBusy = session.isBusy,
            onToggleRevealPins = onToggleRevealPins,
            onOpenUpdateServer = onOpenUpdateServer,
        )
        IdentityManagementCard(
            nodeId = snapshot?.nodeId ?: bootstrap?.nodeId,
            nodeName = snapshot?.nodeName ?: bootstrap?.nodeName,
            keyExpiresAtMs = snapshot?.keyExpiresAtMs,
            isBusy = session.isBusy,
            onOpenRotateKey = onOpenRotateKey,
            onOpenResetIdentity = onOpenResetIdentity,
        )
        BootAndAlwaysOnCard(
            alwaysOnHint = session.isAlwaysOnHintEnabled,
            onToggleAlwaysOnHint = onToggleAlwaysOnHint,
            onOpenVpnSettings = onOpenVpnSettings,
        )
        DiagnosticsCard(
            isBusy = session.isBusy,
            isConnected = session.daemonState == MobileDaemonState.CONNECTED,
            hasActiveTunnel = snapshot != null,
            netcheck = session.lastNetcheckResult,
            onRunNetcheck = onRunNetcheck,
            onExportBugreport = onExportBugreport,
            onCleanupDiagnostics = onCleanupDiagnostics,
        )
    }
}

@Composable
private fun AppearanceCard(
    themeMode: ThemeMode,
    onSelectThemeMode: (ThemeMode) -> Unit,
) {
    val options =
        listOf(
            Triple(ThemeMode.SYSTEM, "System", "theme_option_system"),
            Triple(ThemeMode.LIGHT, "Light", "theme_option_light"),
            Triple(ThemeMode.DARK, "Dark", "theme_option_dark"),
        )
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text("Appearance", style = MaterialTheme.typography.titleMedium)
            Row(
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .testTag("theme_selector"),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                for ((mode, label, tag) in options) {
                    FilterChip(
                        selected = themeMode == mode,
                        onClick = { onSelectThemeMode(mode) },
                        label = { Text(label) },
                        modifier = Modifier.testTag(tag),
                    )
                }
            }
        }
    }
}

@Composable
private fun SettingsDialogs(
    showServerDialog: Boolean,
    showRotateDialog: Boolean,
    showResetDialog: Boolean,
    currentEndpoint: String,
    currentTlsMode: MobileTlsAuthMode,
    activePin: String?,
    onSensitiveModalChanged: (Boolean) -> Unit,
    onDismissServerDialog: () -> Unit,
    onSubmitServerConfig: (String, MobileTlsAuthMode, String) -> Unit,
    onDismissRotateDialog: () -> Unit,
    onSubmitRotateKey: (CharArray) -> Unit,
    onDismissResetDialog: () -> Unit,
    onConfirmResetIdentity: () -> Unit,
) {
    if (showServerDialog) {
        UpdateServerConfigDialog(
            initialEndpoint = currentEndpoint,
            initialMode = currentTlsMode,
            initialPin = activePin.orEmpty(),
            onDismiss = {
                onDismissServerDialog()
                onSensitiveModalChanged(false)
            },
            onSubmit = { ep, mode, pin ->
                onSensitiveModalChanged(false)
                onSubmitServerConfig(ep, mode, pin)
            },
        )
    }

    if (showRotateDialog) {
        RotateKeyDialog(
            onDismiss = {
                onDismissRotateDialog()
                onSensitiveModalChanged(false)
            },
            onSubmit = { chars ->
                onSensitiveModalChanged(false)
                onSubmitRotateKey(chars)
            },
        )
    }

    if (showResetDialog) {
        ResetIdentityConfirmDialog(
            onDismiss = onDismissResetDialog,
            onConfirm = onConfirmResetIdentity,
        )
    }
}

@Composable
private fun ServerSecurityCard(
    endpoint: String,
    tlsMode: MobileTlsAuthMode,
    activePin: String?,
    nextPin: String?,
    pinsRevealed: Boolean,
    isBusy: Boolean,
    onToggleRevealPins: () -> Unit,
    onOpenUpdateServer: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text("Control Server & TLS Pin", style = MaterialTheme.typography.titleMedium)
            Text("Endpoint: ${endpoint.ifBlank { "Not configured" }}")
            Text("TLS Mode: ${tlsMode.name}")
            if (activePin != null) {
                val displayed = if (pinsRevealed) activePin else maskPin(activePin)
                Text(
                    text = "Active SPKI Pin:\n$displayed",
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.labelMedium,
                    modifier = Modifier.testTag("spki_pin_value"),
                )
            }
            if (pinsRevealed && nextPin != null) {
                Text(
                    text = "Next Staged Pin:\n$nextPin",
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.labelMedium,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (activePin != null) {
                    OutlinedButton(
                        onClick = onToggleRevealPins,
                        enabled = !isBusy,
                        modifier = Modifier.testTag("reveal_pin_button"),
                    ) {
                        Text(if (pinsRevealed) "Hide Pin" else "Reveal Full Pin")
                    }
                }
                OutlinedButton(onClick = onOpenUpdateServer, enabled = !isBusy) {
                    Text("Update Server")
                }
            }
        }
    }
}

@Composable
private fun IdentityManagementCard(
    nodeId: String?,
    nodeName: String?,
    keyExpiresAtMs: ULong?,
    isBusy: Boolean,
    onOpenRotateKey: () -> Unit,
    onOpenResetIdentity: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text("Node Identity & Keystore DEK", style = MaterialTheme.typography.titleMedium)
            Text("Device Name: ${nodeName ?: "--"}")
            Text(
                text = "Node ID: ${nodeId ?: "--"}",
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.labelMedium,
            )
            Text("Key Expires: ${formatExpiryUtc(keyExpiresAtMs)}")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onOpenRotateKey, enabled = !isBusy) {
                    Text("Rotate Key")
                }
                Button(
                    onClick = onOpenResetIdentity,
                    enabled = !isBusy,
                    colors =
                        ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.error,
                        ),
                ) {
                    Text("Erase Identity")
                }
            }
        }
    }
}

@Composable
private fun BootAndAlwaysOnCard(
    alwaysOnHint: Boolean,
    onToggleAlwaysOnHint: (Boolean) -> Unit,
    onOpenVpnSettings: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text("Direct Boot & Always-On VPN", style = MaterialTheme.typography.titleMedium)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = "Auto-start after unlock",
                    modifier = Modifier.weight(1f),
                )
                Switch(
                    checked = alwaysOnHint,
                    onCheckedChange = onToggleAlwaysOnHint,
                )
            }
            OutlinedButton(onClick = onOpenVpnSettings, modifier = Modifier.fillMaxWidth()) {
                Text("Open Android VPN Settings")
            }
        }
    }
}

@Composable
private fun DiagnosticsCard(
    isBusy: Boolean,
    isConnected: Boolean,
    hasActiveTunnel: Boolean,
    netcheck: MobileNetcheckResponse?,
    onRunNetcheck: () -> Unit,
    onExportBugreport: () -> Unit,
    onCleanupDiagnostics: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text("Scrubbed Diagnostics", style = MaterialTheme.typography.titleMedium)
            Text(
                text =
                    "Generates a bounded <= 1 MiB .tar archive with all private keys, " +
                        "tokens, and credentials removed before sharing.",
                style = MaterialTheme.typography.bodyMedium,
            )
            OutlinedButton(
                onClick = onRunNetcheck,
                enabled = !isBusy && isConnected,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Run Network Check")
            }
            if (netcheck != null) {
                Text(
                    text =
                        "UDP: ${netcheck.udpReachable} | NAT: ${netcheck.natType.name} | " +
                            "Relay: ${netcheck.relayRttMs ?: "-"} ms",
                    style = MaterialTheme.typography.labelMedium,
                )
            }
            Button(
                onClick = onExportBugreport,
                enabled = !isBusy && hasActiveTunnel,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Export & Share Bugreport (Biometric)")
            }
            OutlinedButton(onClick = onCleanupDiagnostics, modifier = Modifier.fillMaxWidth()) {
                Text("Purge Cached Bugreports")
            }
        }
    }
}

@Composable
private fun UpdateServerConfigDialog(
    initialEndpoint: String,
    initialMode: MobileTlsAuthMode,
    initialPin: String,
    onDismiss: () -> Unit,
    onSubmit: (String, MobileTlsAuthMode, String) -> Unit,
) {
    var endpoint by remember { mutableStateOf(initialEndpoint) }
    var tlsMode by remember { mutableStateOf(initialMode) }
    var pin by remember { mutableStateOf(initialPin) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Update Control Server Config") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = endpoint,
                    onValueChange = { endpoint = it },
                    label = { Text("Endpoint (host:port)") },
                    singleLine = true,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = tlsMode == MobileTlsAuthMode.SPKI_PIN,
                        onClick = { tlsMode = MobileTlsAuthMode.SPKI_PIN },
                        label = { Text("SPKI Pin") },
                    )
                    FilterChip(
                        selected = tlsMode == MobileTlsAuthMode.SYSTEM_CA,
                        onClick = {
                            tlsMode = MobileTlsAuthMode.SYSTEM_CA
                            pin = ""
                        },
                        label = { Text("System CA") },
                    )
                }
                if (tlsMode == MobileTlsAuthMode.SPKI_PIN) {
                    OutlinedTextField(
                        value = pin,
                        onValueChange = { pin = it },
                        label = { Text("SPKI Pin (sha256:...)") },
                        singleLine = true,
                    )
                }
            }
        },
        confirmButton = {
            Button(onClick = { onSubmit(endpoint, tlsMode, pin) }) {
                Text("Authorize & Save")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

@Composable
private fun RotateKeyDialog(
    onDismiss: () -> Unit,
    onSubmit: (CharArray) -> Unit,
) {
    var keyDraft by remember { mutableStateOf("") }
    DisposableEffect(Unit) {
        onDispose { keyDraft = "" }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Rotate Node Identity Key") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Enter a fresh pre-auth key (mpk_...) to re-key this device cleanly.")
                OutlinedTextField(
                    value = keyDraft,
                    onValueChange = { keyDraft = it },
                    label = { Text("New Pre-auth Key") },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions =
                        KeyboardOptions(
                            keyboardType = KeyboardType.Password,
                            autoCorrectEnabled = false,
                        ),
                    singleLine = true,
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val chars = keyDraft.toCharArray()
                    keyDraft = ""
                    onSubmit(chars)
                },
                enabled = keyDraft.isNotBlank(),
            ) {
                Text("Authorize & Rotate")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

@Composable
private fun ResetIdentityConfirmDialog(
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Erase Local Mesh Identity?") },
        text = {
            Text(
                "This stops the tunnel and permanently wipes Android Keystore DEK, " +
                    "sealed identity keys, and bootstrap state on this device.",
            )
        },
        confirmButton = {
            Button(
                onClick = onConfirm,
                colors =
                    ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                    ),
            ) {
                Text("Authorize & Erase")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

private fun maskPin(raw: String): String {
    if (raw.length <= 16) {
        return "sha256:••••"
    }
    return "${raw.take(12)}••••••••${raw.takeLast(6)}"
}

private fun formatExpiryUtc(expiryMs: ULong?): String {
    val rawMs = expiryMs?.toLong() ?: return "Not enrolled / unknown"
    if (rawMs <= 0L) {
        return "Not configured"
    }
    return runCatching {
        DateTimeFormatter.ISO_INSTANT.format(
            Instant.ofEpochMilli(rawMs).atOffset(ZoneOffset.UTC),
        )
    }.getOrDefault("$rawMs ms")
}
