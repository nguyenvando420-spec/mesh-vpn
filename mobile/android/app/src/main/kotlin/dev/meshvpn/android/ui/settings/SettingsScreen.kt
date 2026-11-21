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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import dev.meshvpn.android.LocaleHelper
import dev.meshvpn.android.LocaleMode
import dev.meshvpn.android.R
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
    onSelectLocaleMode: (LocaleMode) -> Unit,
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
        onSelectLocaleMode = onSelectLocaleMode,
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
    onSelectLocaleMode: (LocaleMode) -> Unit,
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
        Text(
            text = stringResource(R.string.settings_section_header),
            style = MaterialTheme.typography.headlineSmall,
        )
        AppearanceCard(
            themeMode = screenState.themeMode,
            onSelectThemeMode = onSelectThemeMode,
        )
        LanguageCard(
            localeMode = screenState.localeMode,
            onSelectLocaleMode = onSelectLocaleMode,
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
            Triple(ThemeMode.SYSTEM, stringResource(R.string.theme_system), "theme_option_system"),
            Triple(ThemeMode.LIGHT, stringResource(R.string.theme_light), "theme_option_light"),
            Triple(ThemeMode.DARK, stringResource(R.string.theme_dark), "theme_option_dark"),
        )
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.theme_appearance),
                style = MaterialTheme.typography.titleMedium,
            )
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
private fun LanguageCard(
    localeMode: LocaleMode,
    onSelectLocaleMode: (LocaleMode) -> Unit,
) {
    val options =
        listOf(
            Triple(
                LocaleMode.SYSTEM,
                stringResource(R.string.locale_system),
                "locale_option_system",
            ),
            Triple(
                LocaleMode.VI,
                stringResource(R.string.locale_vietnamese),
                "locale_option_vi",
            ),
            Triple(
                LocaleMode.EN,
                stringResource(R.string.locale_english),
                "locale_option_en",
            ),
        )
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.locale_language),
                style = MaterialTheme.typography.titleMedium,
            )
            Row(
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .testTag("locale_selector"),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                for ((mode, label, tag) in options) {
                    FilterChip(
                        selected = localeMode == mode,
                        onClick = { onSelectLocaleMode(mode) },
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
    val context = LocalContext.current
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.settings_server_tls),
                style = MaterialTheme.typography.titleMedium,
            )
            val notConfigured = LocaleHelper.tr(context, "Not configured", "Chưa cấu hình")
            Text("Endpoint: ${endpoint.ifBlank { notConfigured }}")
            Text("${LocaleHelper.tr(context, "TLS Mode", "Chế độ TLS")}: ${tlsMode.name}")
            if (activePin != null) {
                val displayed = if (pinsRevealed) activePin else maskPin(activePin)
                val activeHeading =
                    LocaleHelper.tr(context, "Active SPKI Pin:", "Ghim SPKI hiện tại:")
                Text(
                    text = "$activeHeading\n$displayed",
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.labelMedium,
                    modifier = Modifier.testTag("spki_pin_value"),
                )
            }
            if (pinsRevealed && nextPin != null) {
                val nextHeading = LocaleHelper.tr(context, "Next Staged Pin:", "Ghim kế tiếp:")
                Text(
                    text = "$nextHeading\n$nextPin",
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
                        val pinBtnRes =
                            if (pinsRevealed) {
                                R.string.settings_hide_pin
                            } else {
                                R.string.settings_reveal_pin
                            }
                        Text(stringResource(pinBtnRes))
                    }
                }
                OutlinedButton(onClick = onOpenUpdateServer, enabled = !isBusy) {
                    Text(stringResource(R.string.settings_update_server))
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
    val context = LocalContext.current
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.settings_identity_title),
                style = MaterialTheme.typography.titleMedium,
            )
            val nameLabel = LocaleHelper.tr(context, "Device Name", "Tên thiết bị")
            Text("$nameLabel: ${nodeName ?: "--"}")
            Text(
                text = "Node ID: ${nodeId ?: "--"}",
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.labelMedium,
            )
            val expLabel = LocaleHelper.tr(context, "Key Expires", "Hạn khóa")
            Text("$expLabel: ${formatExpiryUtc(keyExpiresAtMs)}")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onOpenRotateKey, enabled = !isBusy) {
                    Text(stringResource(R.string.settings_rotate_key))
                }
                Button(
                    onClick = onOpenResetIdentity,
                    enabled = !isBusy,
                    colors =
                        ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.error,
                        ),
                ) {
                    Text(stringResource(R.string.settings_erase_identity))
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
            Text(
                text = stringResource(R.string.settings_boot_title),
                style = MaterialTheme.typography.titleMedium,
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = stringResource(R.string.settings_auto_start),
                    modifier = Modifier.weight(1f),
                )
                Switch(
                    checked = alwaysOnHint,
                    onCheckedChange = onToggleAlwaysOnHint,
                )
            }
            OutlinedButton(onClick = onOpenVpnSettings, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.settings_open_vpn_settings))
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
    val context = LocalContext.current
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.settings_diag_title),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text =
                    LocaleHelper.tr(
                        context,
                        "Generates a bounded <= 1 MiB .tar archive with all private keys, " +
                            "tokens, and credentials removed before sharing.",
                        "Tạo tệp lưu trữ .tar <= 1 MiB đã loại bỏ khóa riêng, mã thông báo " +
                            "và thông tin bí mật trước khi chia sẻ.",
                    ),
                style = MaterialTheme.typography.bodyMedium,
            )
            OutlinedButton(
                onClick = onRunNetcheck,
                enabled = !isBusy && isConnected,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.diag_run_netcheck))
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
                Text(stringResource(R.string.settings_export_share))
            }
            OutlinedButton(onClick = onCleanupDiagnostics, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.settings_purge_bugreports))
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
    val context = LocalContext.current
    var endpoint by remember { mutableStateOf(initialEndpoint) }
    var tlsMode by remember { mutableStateOf(initialMode) }
    var pin by remember { mutableStateOf(initialPin) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.settings_update_dialog)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                val epLabel =
                    LocaleHelper.tr(context, "Endpoint (host:port)", "Điểm cuối (host:port)")
                OutlinedTextField(
                    value = endpoint,
                    onValueChange = { endpoint = it },
                    label = { Text(epLabel) },
                    singleLine = true,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = tlsMode == MobileTlsAuthMode.SPKI_PIN,
                        onClick = { tlsMode = MobileTlsAuthMode.SPKI_PIN },
                        label = { Text(stringResource(R.string.onboarding_tls_spki_pin)) },
                    )
                    FilterChip(
                        selected = tlsMode == MobileTlsAuthMode.SYSTEM_CA,
                        onClick = {
                            tlsMode = MobileTlsAuthMode.SYSTEM_CA
                            pin = ""
                        },
                        label = { Text(stringResource(R.string.onboarding_tls_system_ca)) },
                    )
                }
                if (tlsMode == MobileTlsAuthMode.SPKI_PIN) {
                    OutlinedTextField(
                        value = pin,
                        onValueChange = { pin = it },
                        label = { Text(stringResource(R.string.onboarding_spki_pin_label)) },
                        singleLine = true,
                    )
                }
            }
        },
        confirmButton = {
            Button(onClick = { onSubmit(endpoint, tlsMode, pin) }) {
                Text(stringResource(R.string.settings_authorize_save))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.generic_cancel)) }
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
        title = { Text(stringResource(R.string.rotation_dialog_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.rotation_subtitle))
                OutlinedTextField(
                    value = keyDraft,
                    onValueChange = { keyDraft = it },
                    label = { Text(stringResource(R.string.rotation_new_key)) },
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
                Text(stringResource(R.string.rotation_authorize))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.generic_cancel)) }
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
        title = { Text(stringResource(R.string.settings_erase_dialog)) },
        text = { Text(stringResource(R.string.settings_erase_detail)) },
        confirmButton = {
            Button(
                onClick = onConfirm,
                colors =
                    ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                    ),
            ) {
                Text(stringResource(R.string.settings_authorize_erase))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.generic_cancel)) }
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
