package dev.meshvpn.android.ui.onboarding

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ContentPaste
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.QrCodeScanner
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
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
import dev.meshvpn.android.ui.JoinConfirmationUiModel
import dev.meshvpn.android.ui.MainUiScreenState
import dev.meshvpn.android.ui.OnboardingMethod
import uniffi.mesh_mobile_ffi.MobileTlsAuthMode

@Composable
fun OnboardingScreen(
    screenState: MainUiScreenState,
    onSelectMethod: (OnboardingMethod) -> Unit,
    onSubmitJoinUri: (String) -> Unit,
    onPasteFromClipboard: () -> Unit,
    onSubmitManual: (String, MobileTlsAuthMode, String, CharArray, String) -> Unit,
    onToggleConnectOnConfirm: (Boolean) -> Unit,
    onConfirmJoin: () -> Unit,
    onCancelConfirmation: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        OnboardingHeaderBanner(isBusy = screenState.session.isBusy)

        OnboardingMethodTabs(
            selected = screenState.onboardingMethod,
            onSelectMethod = onSelectMethod,
        )

        ErrorOrInfoNotice(
            errorMessage = screenState.inputError ?: screenState.session.lastError?.detail,
            infoMessage = screenState.infoBanner,
        )

        when (screenState.onboardingMethod) {
            OnboardingMethod.SCAN_QR -> {
                QrScannerPane(
                    paused = screenState.pendingConfirmation != null || screenState.session.isBusy,
                    onQrDecoded = onSubmitJoinUri,
                )
            }
            OnboardingMethod.PASTE_URI -> {
                PasteUriSection(
                    isBusy = screenState.session.isBusy,
                    onPasteClipboard = onPasteFromClipboard,
                    onSubmitPastedText = onSubmitJoinUri,
                )
            }
            OnboardingMethod.MANUAL -> {
                ManualJoinSection(
                    isBusy = screenState.session.isBusy,
                    onSubmitManual = onSubmitManual,
                )
            }
        }
    }

    screenState.pendingConfirmation?.let { confirmation ->
        JoinConfirmationDialog(
            confirmation = confirmation,
            connectOnConfirm = screenState.connectOnConfirm,
            onToggleConnect = onToggleConnectOnConfirm,
            onConfirm = onConfirmJoin,
            onDismiss = onCancelConfirmation,
        )
    }
}

@Composable
private fun OnboardingHeaderBanner(isBusy: Boolean) {
    Text(
        text = "Join Mesh Network",
        style = MaterialTheme.typography.headlineSmall,
    )
    Text(
        text = "Scan an administrator QR or enter server fingerprint details. " +
            "Automatic trust-on-first-use is disabled.",
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    AssistChip(
        onClick = {},
        leadingIcon = {
            Icon(imageVector = Icons.Outlined.Lock, contentDescription = null)
        },
        label = { Text("Screen capture blocked (FLAG_SECURE)") },
    )
    if (isBusy) {
        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
    }
}

@Composable
private fun OnboardingMethodTabs(
    selected: OnboardingMethod,
    onSelectMethod: (OnboardingMethod) -> Unit,
) {
    val methods = listOf(
        Triple(OnboardingMethod.SCAN_QR, "Scan QR", Icons.Outlined.QrCodeScanner),
        Triple(OnboardingMethod.PASTE_URI, "Paste URI", Icons.Outlined.ContentPaste),
        Triple(OnboardingMethod.MANUAL, "Manual", Icons.Outlined.Edit),
    )
    TabRow(selectedTabIndex = methods.indexOfFirst { it.first == selected }.coerceAtLeast(0)) {
        methods.forEach { (method, label, icon) ->
            Tab(
                selected = selected == method,
                onClick = { onSelectMethod(method) },
                modifier = Modifier.testTag("onboarding_tab_${method.name}"),
                text = { Text(label) },
                icon = { Icon(imageVector = icon, contentDescription = null) },
            )
        }
    }
}

@Composable
private fun PasteUriSection(
    isBusy: Boolean,
    onPasteClipboard: () -> Unit,
    onSubmitPastedText: (String) -> Unit,
) {
    var uriDraft by remember { mutableStateOf("") }
    DisposableEffect(Unit) {
        onDispose { uriDraft = "" }
    }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = "Import mesh://join URI",
                style = MaterialTheme.typography.titleMedium,
            )
            Button(
                onClick = onPasteClipboard,
                enabled = !isBusy,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("paste_clipboard_clear_button"),
            ) {
                Text("Paste from Clipboard & Clear Immediately")
            }
            OutlinedTextField(
                value = uriDraft,
                onValueChange = { uriDraft = it },
                label = { Text("Or enter mesh://join?... URI") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    autoCorrectEnabled = false,
                ),
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("paste_uri_input"),
            )
            OutlinedButton(
                onClick = {
                    val value = uriDraft
                    uriDraft = ""
                    onSubmitPastedText(value)
                },
                enabled = !isBusy && uriDraft.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Review URI Details")
            }
        }
    }
}

@Composable
private fun ManualJoinSection(
    isBusy: Boolean,
    onSubmitManual: (String, MobileTlsAuthMode, String, CharArray, String) -> Unit,
) {
    var endpoint by remember { mutableStateOf("") }
    var tlsMode by remember { mutableStateOf(MobileTlsAuthMode.SPKI_PIN) }
    var spkiPin by remember { mutableStateOf("") }
    var preauthKeyDraft by remember { mutableStateOf("") }
    var nodeName by remember { mutableStateOf("") }

    DisposableEffect(Unit) {
        onDispose { preauthKeyDraft = "" }
    }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            OutlinedTextField(
                value = endpoint,
                onValueChange = { endpoint = it },
                label = { Text("Control server (host:port)") },
                placeholder = { Text("203.0.113.10:443") },
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("manual_endpoint_input"),
            )
            TlsModeSelector(
                tlsMode = tlsMode,
                onSelectMode = { mode ->
                    tlsMode = mode
                    if (mode == MobileTlsAuthMode.SYSTEM_CA) {
                        spkiPin = ""
                    }
                },
            )
            if (tlsMode == MobileTlsAuthMode.SPKI_PIN) {
                OutlinedTextField(
                    value = spkiPin,
                    onValueChange = { spkiPin = it },
                    label = { Text("SPKI Pin (sha256:<64 hex>)") },
                    singleLine = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("manual_pin_input"),
                )
            } else {
                Text(
                    text = "System CA validates DNS domain certificates using Android root store.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            OutlinedTextField(
                value = preauthKeyDraft,
                onValueChange = { preauthKeyDraft = it },
                label = { Text("Pre-auth Key (mpk_...)") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    autoCorrectEnabled = false,
                ),
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("manual_preauth_input"),
            )
            OutlinedTextField(
                value = nodeName,
                onValueChange = { nodeName = it },
                label = { Text("Device Name (optional RFC 1123)") },
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("manual_nodename_input"),
            )
            Button(
                onClick = {
                    val keyChars = preauthKeyDraft.toCharArray()
                    preauthKeyDraft = ""
                    onSubmitManual(endpoint, tlsMode, spkiPin, keyChars, nodeName)
                },
                enabled = !isBusy,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("manual_submit_button"),
            ) {
                Text("Review Server & Continue")
            }
        }
    }
}

@Composable
private fun TlsModeSelector(
    tlsMode: MobileTlsAuthMode,
    onSelectMode: (MobileTlsAuthMode) -> Unit,
) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        FilterChip(
            selected = tlsMode == MobileTlsAuthMode.SPKI_PIN,
            onClick = { onSelectMode(MobileTlsAuthMode.SPKI_PIN) },
            label = { Text("SPKI Pin (Default)") },
        )
        FilterChip(
            selected = tlsMode == MobileTlsAuthMode.SYSTEM_CA,
            onClick = { onSelectMode(MobileTlsAuthMode.SYSTEM_CA) },
            label = { Text("System CA (Domain)") },
        )
    }
}

@Composable
private fun ErrorOrInfoNotice(errorMessage: String?, infoMessage: String?) {
    if (!errorMessage.isNullOrBlank()) {
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.errorContainer,
            ),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                text = errorMessage,
                color = MaterialTheme.colorScheme.onErrorContainer,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(12.dp),
            )
        }
    }
    if (!infoMessage.isNullOrBlank()) {
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.secondaryContainer,
            ),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                text = infoMessage,
                color = MaterialTheme.colorScheme.onSecondaryContainer,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(12.dp),
            )
        }
    }
}

@Composable
private fun JoinConfirmationDialog(
    confirmation: JoinConfirmationUiModel,
    connectOnConfirm: Boolean,
    onToggleConnect: (Boolean) -> Unit,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Verify Control Server Identity") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Endpoint: ${confirmation.serverEndpoint}")
                val trustLabel = if (confirmation.tlsAuthMode == MobileTlsAuthMode.SPKI_PIN) {
                    "Pinned SPKI SHA-256"
                } else {
                    "Android System CA (Domain Verified)"
                }
                Text("TLS Policy: $trustLabel")
                confirmation.serverPin?.let { pin ->
                    Text(
                        text = "SPKI Pin:\n$pin",
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.labelMedium,
                    )
                }
                Text("Key Preview: ${confirmation.preauthKeyMasked}")
                confirmation.nodeName?.let { name ->
                    Text("Device Name: $name")
                }
                Spacer(modifier = Modifier.height(4.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(
                        checked = connectOnConfirm,
                        onCheckedChange = onToggleConnect,
                    )
                    Text("Connect VPN immediately after enrollment")
                }
            }
        },
        confirmButton = {
            Button(
                onClick = onConfirm,
                modifier = Modifier.testTag("confirm_join_button"),
            ) {
                Text(if (connectOnConfirm) "Trust & Connect" else "Trust & Enroll")
            }
        },
        dismissButton = {
            TextButton(
                onClick = onDismiss,
                modifier = Modifier.testTag("cancel_join_button"),
            ) {
                Text("Cancel")
            }
        },
    )
}
