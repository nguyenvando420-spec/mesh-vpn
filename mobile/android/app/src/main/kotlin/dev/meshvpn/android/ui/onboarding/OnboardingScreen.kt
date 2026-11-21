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
import dev.meshvpn.android.ui.JoinConfirmationUiModel
import dev.meshvpn.android.ui.MainUiScreenState
import dev.meshvpn.android.ui.OnboardingMethod
import dev.meshvpn.android.ui.theme.ThemeMode
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
    onSelectThemeMode: (ThemeMode) -> Unit = {},
    onSelectLocaleMode: (LocaleMode) -> Unit = {},
) {
    Column(
        modifier =
            modifier
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

        OnboardingQuickPreferencesCard(
            themeMode = screenState.themeMode,
            localeMode = screenState.localeMode,
            onSelectThemeMode = onSelectThemeMode,
            onSelectLocaleMode = onSelectLocaleMode,
        )
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
        text = stringResource(R.string.onboarding_title),
        style = MaterialTheme.typography.headlineSmall,
    )
    Text(
        text = stringResource(R.string.onboarding_subtitle),
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    AssistChip(
        onClick = {},
        leadingIcon = {
            Icon(imageVector = Icons.Outlined.Lock, contentDescription = null)
        },
        label = { Text(stringResource(R.string.onboarding_flag_secure)) },
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
    val methods =
        listOf(
            Triple(
                OnboardingMethod.SCAN_QR,
                stringResource(R.string.onboarding_tab_scan_qr),
                Icons.Outlined.QrCodeScanner,
            ),
            Triple(
                OnboardingMethod.PASTE_URI,
                stringResource(R.string.onboarding_tab_paste_uri),
                Icons.Outlined.ContentPaste,
            ),
            Triple(
                OnboardingMethod.MANUAL,
                stringResource(R.string.onboarding_tab_manual),
                Icons.Outlined.Edit,
            ),
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
                text = stringResource(R.string.onboarding_import_uri),
                style = MaterialTheme.typography.titleMedium,
            )
            Button(
                onClick = onPasteClipboard,
                enabled = !isBusy,
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .testTag("paste_clipboard_clear_button"),
            ) {
                Text(stringResource(R.string.onboarding_paste_clipboard))
            }
            OutlinedTextField(
                value = uriDraft,
                onValueChange = { uriDraft = it },
                label = { Text(stringResource(R.string.onboarding_or_enter_uri)) },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions =
                    KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        autoCorrectEnabled = false,
                    ),
                singleLine = true,
                modifier =
                    Modifier
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
                Text(stringResource(R.string.onboarding_review_uri))
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
                label = { Text(stringResource(R.string.onboarding_control_server)) },
                placeholder = { Text("203.0.113.10:443") },
                singleLine = true,
                modifier =
                    Modifier
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
            ManualSpkiOrSystemCaFields(
                tlsMode = tlsMode,
                spkiPin = spkiPin,
                onPinChange = { spkiPin = it },
            )
            OutlinedTextField(
                value = preauthKeyDraft,
                onValueChange = { preauthKeyDraft = it },
                label = { Text(stringResource(R.string.onboarding_preauth_key)) },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions =
                    KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        autoCorrectEnabled = false,
                    ),
                singleLine = true,
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .testTag("manual_preauth_input"),
            )
            OutlinedTextField(
                value = nodeName,
                onValueChange = { nodeName = it },
                label = { Text(stringResource(R.string.onboarding_node_name)) },
                singleLine = true,
                modifier =
                    Modifier
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
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .testTag("manual_submit_button"),
            ) {
                Text(stringResource(R.string.onboarding_review_server))
            }
        }
    }
}

@Composable
private fun ManualSpkiOrSystemCaFields(
    tlsMode: MobileTlsAuthMode,
    spkiPin: String,
    onPinChange: (String) -> Unit,
) {
    val context = LocalContext.current
    if (tlsMode == MobileTlsAuthMode.SPKI_PIN) {
        OutlinedTextField(
            value = spkiPin,
            onValueChange = onPinChange,
            label = { Text(stringResource(R.string.onboarding_spki_pin_label)) },
            singleLine = true,
            modifier =
                Modifier
                    .fillMaxWidth()
                    .testTag("manual_pin_input"),
        )
    } else {
        Text(
            text =
                LocaleHelper.tr(
                    context,
                    "System CA validates DNS domain certificates using Android root store.",
                    "CA hệ thống xác thực chứng chỉ tên miền DNS bằng kho gốc Android.",
                ),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
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
            label = { Text(stringResource(R.string.onboarding_tls_spki_pin)) },
        )
        FilterChip(
            selected = tlsMode == MobileTlsAuthMode.SYSTEM_CA,
            onClick = { onSelectMode(MobileTlsAuthMode.SYSTEM_CA) },
            label = { Text(stringResource(R.string.onboarding_tls_system_ca)) },
        )
    }
}

@Composable
private fun ErrorOrInfoNotice(
    errorMessage: String?,
    infoMessage: String?,
) {
    if (!errorMessage.isNullOrBlank()) {
        Card(
            colors =
                CardDefaults.cardColors(
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
            colors =
                CardDefaults.cardColors(
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
        title = { Text(stringResource(R.string.confirm_verify_server)) },
        text = {
            JoinConfirmationDetails(
                confirmation = confirmation,
                connectOnConfirm = connectOnConfirm,
                onToggleConnect = onToggleConnect,
            )
        },
        confirmButton = {
            Button(
                onClick = onConfirm,
                modifier = Modifier.testTag("confirm_join_button"),
            ) {
                val labelRes =
                    if (connectOnConfirm) {
                        R.string.onboarding_trust_connect
                    } else {
                        R.string.onboarding_trust_enroll
                    }
                Text(stringResource(labelRes))
            }
        },
        dismissButton = {
            TextButton(
                onClick = onDismiss,
                modifier = Modifier.testTag("cancel_join_button"),
            ) {
                Text(stringResource(R.string.generic_cancel))
            }
        },
    )
}

@Composable
private fun JoinConfirmationDetails(
    confirmation: JoinConfirmationUiModel,
    connectOnConfirm: Boolean,
    onToggleConnect: (Boolean) -> Unit,
) {
    val context = LocalContext.current
    val trustLabel =
        if (confirmation.tlsAuthMode == MobileTlsAuthMode.SPKI_PIN) {
            LocaleHelper.tr(context, "Pinned SPKI SHA-256", "Ghim SPKI SHA-256")
        } else {
            LocaleHelper.tr(
                context,
                "Android System CA (Domain Verified)",
                "CA hệ thống Android (Đã xác minh tên miền)",
            )
        }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            LocaleHelper.tr(
                context,
                "Endpoint: ${confirmation.serverEndpoint}",
                "Điểm cuối: ${confirmation.serverEndpoint}",
            ),
        )
        Text(
            LocaleHelper.tr(
                context,
                "TLS Policy: $trustLabel",
                "Chính sách TLS: $trustLabel",
            ),
        )
        confirmation.serverPin?.let { pin ->
            val pinHeading = LocaleHelper.tr(context, "SPKI Pin:", "Ghim SPKI:")
            Text(
                text = "$pinHeading\n$pin",
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.labelMedium,
            )
        }
        Text(
            LocaleHelper.tr(
                context,
                "Key Preview: ${confirmation.preauthKeyMasked}",
                "Xem trước khóa: ${confirmation.preauthKeyMasked}",
            ),
        )
        confirmation.nodeName?.let { name ->
            Text(
                LocaleHelper.tr(
                    context,
                    "Device Name: $name",
                    "Tên thiết bị: $name",
                ),
            )
        }
        Spacer(modifier = Modifier.height(4.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(
                checked = connectOnConfirm,
                onCheckedChange = onToggleConnect,
            )
            Text(stringResource(R.string.onboarding_connect_after))
        }
    }
}
