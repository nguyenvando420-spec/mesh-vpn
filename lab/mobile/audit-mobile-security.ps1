# lab/mobile/audit-mobile-security.ps1
# Automated Mobile AppSec & Static Compliance Audit for Android, iOS, and mesh-mobile-ffi (US-096)
# Runs with exit code 0 on 100% pass, non-zero on any security/safety violation.

[CmdletBinding()]
param(
    [string]$RepoRoot = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}
else {
    $RepoRoot = (Resolve-Path $RepoRoot).Path
}

$script:Failures = [System.Collections.Generic.List[string]]::new()
$script:Passed = 0

function Record-Check {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][bool]$Ok,
        [string]$Details = ""
    )
    if ($Ok) {
        $script:Passed++
        Write-Host ("[PASS] {0}: {1}" -f $Id, $Description) -ForegroundColor Green
    }
    else {
        $msg = if ([string]::IsNullOrWhiteSpace($Details)) {
            "{0}: {1}" -f $Id, $Description
        }
        else {
            "{0}: {1} -> {2}" -f $Id, $Description, $Details
        }
        $script:Failures.Add($msg)
        Write-Host ("[FAIL] {0}" -f $msg) -ForegroundColor Red
    }
}

function Get-Utf8Text {
    param([Parameter(Mandatory = $true)][string]$RelativePath)
    $full = Join-Path $RepoRoot $RelativePath
    if (-not (Test-Path -LiteralPath $full)) {
        return $null
    }
    return [System.IO.File]::ReadAllText($full, [System.Text.Encoding]::UTF8)
}

function Strip-CodeComments {
    param([Parameter(Mandatory = $true)][string]$Text)
    $noBlock = [regex]::Replace($Text, '/\*[\s\S]*?\*/', '')
    $lines = $noBlock -split "`r?`n"
    $cleaned = foreach ($line in $lines) {
        if ($line -match '^\s*//') { "" } else { $line -replace '//.*$', '' }
    }
    return ($cleaned -join "`n")
}

Write-Host "=== Mobile Static Security Audit (US-096) ==="
Write-Host "RepoRoot: $RepoRoot"

# 1. Android Manifest: allowBackup="false" and 0 mesh:// deep-link intent filters
$manifest = Get-Utf8Text "mobile\android\app\src\main\AndroidManifest.xml"
Record-Check "MOB-SEC-01" "AndroidManifest.xml enforces android:allowBackup=`"false`"" `
    ($null -ne $manifest -and $manifest -match 'android:allowBackup\s*=\s*"false"') `
    "Missing android:allowBackup=`"false`" in AndroidManifest.xml"

$hasAndroidMeshScheme = ($null -ne $manifest) -and (
    ($manifest -match 'android:scheme\s*=\s*"mesh"') -or
    ($manifest -match 'mesh://')
)
Record-Check "MOB-SEC-02" "AndroidManifest.xml defines 0 mesh:// deep-link intent-filters" `
    (-not $hasAndroidMeshScheme) `
    "Found forbidden mesh:// deep-link scheme in AndroidManifest.xml"

# 2. Android backup exclusion XML files
$extractRules = Get-Utf8Text "mobile\android\app\src\main\res\xml\data_extraction_rules.xml"
$fullBackup = Get-Utf8Text "mobile\android\app\src\main\res\xml\full_backup_content.xml"
Record-Check "MOB-SEC-03" "Android XML backup rules exclude identity.sealed.bin and dek.enc" `
    (($null -ne $extractRules -and $extractRules -match 'identity\.sealed\.bin' -and $extractRules -match 'dek\.enc') -and
     ($null -ne $fullBackup -and $fullBackup -match 'identity\.sealed\.bin' -and $fullBackup -match 'dek\.enc')) `
    "Missing sealed identity / DEK backup exclusions in Android XML rules"

# 3. Android Kotlin main sources: 0 `!!`, 0 `GlobalScope`, 0 `ServerSocket`
$ktMainDir = Join-Path $RepoRoot "mobile\android\app\src\main\kotlin"
$ktFiles = if (Test-Path $ktMainDir) {
    Get-ChildItem -Path $ktMainDir -Filter "*.kt" -Recurse -File
} else { @() }

$ktBangHits = [System.Collections.Generic.List[string]]::new()
$ktGlobalScopeHits = [System.Collections.Generic.List[string]]::new()
$ktTcpHits = [System.Collections.Generic.List[string]]::new()
$hasAndroidSealedName = $false
$hasAndroidVerifierCall = $false

foreach ($f in $ktFiles) {
    $raw = [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8)
    $codeOnly = Strip-CodeComments $raw
    $rel = $f.FullName.Substring($RepoRoot.Length + 1)

    if ($codeOnly -match '!!') {
        $ktBangHits.Add($rel)
    }
    if ($codeOnly -match '\bGlobalScope\b') {
        $ktGlobalScopeHits.Add($rel)
    }
    if ($codeOnly -match '\bServerSocket\b') {
        $ktTcpHits.Add($rel)
    }
    if ($codeOnly -match '"identity\.sealed\.bin"') {
        $hasAndroidSealedName = $true
    }
    if ($codeOnly -match 'MeshNativeInit\.initPlatformVerifier' -or
        ($codeOnly -match 'package\s+dev\.meshvpn\.android\.ffi' -and $codeOnly -match 'fun\s+initPlatformVerifier')) {
        $hasAndroidVerifierCall = $true
    }
}

Record-Check "MOB-SEC-04" "Android main Kotlin sources contain 0 non-null assertions (!!)" `
    ($ktFiles.Count -gt 0 -and $ktBangHits.Count -eq 0) `
    ("Found `!!` in: " + ($ktBangHits -join ", "))

Record-Check "MOB-SEC-05" "Android main Kotlin sources contain 0 GlobalScope usages" `
    ($ktFiles.Count -gt 0 -and $ktGlobalScopeHits.Count -eq 0) `
    ("Found GlobalScope in: " + ($ktGlobalScopeHits -join ", "))

Record-Check "MOB-SEC-06" "Android Gradle/deps forbid EncryptedSharedPreferences, GMS, and ndk-context" `
    ($(
        $gradleFiles = Get-ChildItem -Path (Join-Path $RepoRoot "mobile\android") -Include "*.kts","*.toml","*.pro" -Recurse -File
        $badDeps = [System.Collections.Generic.List[string]]::new()
        foreach ($gf in $gradleFiles) {
            $txt = Strip-CodeComments ([System.IO.File]::ReadAllText($gf.FullName, [System.Text.Encoding]::UTF8))
            if ($txt -match 'EncryptedSharedPreferences|security-crypto|com\.google\.android\.gms|com\.google\.mlkit|ndk-context') {
                $badDeps.Add($gf.FullName.Substring($RepoRoot.Length + 1))
            }
        }
        $badDeps.Count -eq 0
    )) `
    "Forbidden dependency (EncryptedSharedPreferences / GMS / ML Kit / ndk-context) found in mobile/android"

$meshNativeInitKt = Get-Utf8Text "mobile\android\app\src\main\kotlin\dev\meshvpn\android\ffi\MeshNativeInit.kt"
$meshAppKt = Get-Utf8Text "mobile\android\app\src\main\kotlin\dev\meshvpn\android\MeshApplication.kt"
$proguard = Get-Utf8Text "mobile\android\app\proguard-rules.pro"
$androidJniOk = ($null -ne $meshNativeInitKt) -and
    ($meshNativeInitKt -match 'package\s+dev\.meshvpn\.android\.ffi') -and
    ($meshNativeInitKt -match 'fun\s+initPlatformVerifier\s*\(') -and
    ($null -ne $meshAppKt) -and ($meshAppKt -match 'MeshNativeInit\.ensureInitialized') -and
    ($null -ne $proguard) -and ($proguard -match 'dev\.meshvpn\.android\.ffi\.MeshNativeInit') -and
    ($proguard -match 'org\.rustls\.platformverifier\.\*\*') -and $hasAndroidVerifierCall

Record-Check "MOB-SEC-07" "Android JNI dev.meshvpn.android.ffi.MeshNativeInit.initPlatformVerifier & ProGuard keep rules verified" `
    $androidJniOk `
    "Missing MeshNativeInit.initPlatformVerifier declaration, MeshApplication init call, or ProGuard keep rule"

# 4. iOS Info.plist & Entitlements checks
$iosPlistPaths = @(
    "mobile\ios\MeshApp\Info.plist",
    "mobile\ios\MeshPacketTunnel\Info.plist",
    "mobile\ios\MeshCoreKit\Info.plist"
)
$iosUrlTypeHits = [System.Collections.Generic.List[string]]::new()
$iosAtsHits = [System.Collections.Generic.List[string]]::new()
foreach ($rel in $iosPlistPaths) {
    $plist = Get-Utf8Text $rel
    if ($null -eq $plist) {
        $iosUrlTypeHits.Add("MISSING:$rel")
        continue
    }
    if ($plist -match 'CFBundleURLTypes|CFBundleURLSchemes|mesh://') {
        $iosUrlTypeHits.Add($rel)
    }
    if ($plist -match 'NSAllowsArbitraryLoads') {
        $iosAtsHits.Add($rel)
    }
}

$entitlementFiles = Get-ChildItem -Path (Join-Path $RepoRoot "mobile\ios\Entitlements") -Filter "*.entitlements" -File -ErrorAction SilentlyContinue
foreach ($ef in $entitlementFiles) {
    $etxt = [System.IO.File]::ReadAllText($ef.FullName, [System.Text.Encoding]::UTF8)
    if ($etxt -match 'com\.apple\.developer\.associated-domains') {
        $iosUrlTypeHits.Add($ef.FullName.Substring($RepoRoot.Length + 1))
    }
}

Record-Check "MOB-SEC-08" "iOS Info.plist & Entitlements contain 0 CFBundleURLTypes/mesh:// deep links and 0 associated-domains" `
    ($iosUrlTypeHits.Count -eq 0) `
    ("Deep-link / URL type issue in: " + ($iosUrlTypeHits -join ", "))

Record-Check "MOB-SEC-09" "iOS Info.plist files contain 0 NSAllowsArbitraryLoads" `
    ($iosAtsHits.Count -eq 0) `
    ("NSAllowsArbitraryLoads found in: " + ($iosAtsHits -join ", "))

# 5. iOS Swift production source checks
$swiftProdRoots = @(
    (Join-Path $RepoRoot "mobile\ios\MeshApp\Sources"),
    (Join-Path $RepoRoot "mobile\ios\MeshCoreKit\Sources"),
    (Join-Path $RepoRoot "mobile\ios\MeshPacketTunnel\Sources")
)
$swiftProdFiles = foreach ($root in $swiftProdRoots) {
    if (Test-Path $root) {
        Get-ChildItem -Path $root -Filter "*.swift" -Recurse -File
    }
}

$swiftForceHits = [System.Collections.Generic.List[string]]::new()
$swiftTcpHits = [System.Collections.Generic.List[string]]::new()
$hasIosSealedName = $false

foreach ($sf in $swiftProdFiles) {
    $raw = [System.IO.File]::ReadAllText($sf.FullName, [System.Text.Encoding]::UTF8)
    # Remove comments and string literals before scanning for force operators (!, try!, as!, fatalError)
    $noStrings = [regex]::Replace($raw, '"([^"\\]|\\.)*"', '""')
    $codeOnly = Strip-CodeComments $noStrings
    $rel = $sf.FullName.Substring($RepoRoot.Length + 1)

    if (($codeOnly -match '\btry!') -or
        ($codeOnly -match '\bas!') -or
        ($codeOnly -match '\bfatalError\s*\(') -or
        ($codeOnly -match '[A-Za-z0-9_\)\]]!(?!=)')) {
        $swiftForceHits.Add($rel)
    }
    if ($codeOnly -match '\b(NWListener|ServerSocket)\b') {
        $swiftTcpHits.Add($rel)
    }
    if ($raw -match '"identity\.sealed\.bin"') {
        $hasIosSealedName = $true
    }
}

Record-Check "MOB-SEC-10" "iOS Swift production sources contain 0 !, try!, as!, and fatalError" `
    (($swiftProdFiles | Measure-Object).Count -gt 0 -and $swiftForceHits.Count -eq 0) `
    ("Force unwrap/try/cast/fatalError in: " + ($swiftForceHits -join ", "))

# 6. iOS Keychain accessibility & non-synchronizable + OnDemand ordering before stopTunnel
$keychainSwift = Get-Utf8Text "mobile\ios\MeshCoreKit\Sources\KeychainDekStore.swift"
$keychainOk = ($null -ne $keychainSwift) -and
    ($keychainSwift -match 'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly') -and
    ($keychainSwift -match 'kSecAttrSynchronizable') -and
    ($keychainSwift -match 'kCFBooleanFalse|\bfalse\b')
Record-Check "MOB-SEC-11" "iOS Keychain uses kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly and kSecAttrSynchronizable=false" `
    $keychainOk `
    "KeychainDekStore.swift missing AfterFirstUnlockThisDeviceOnly or Synchronizable=false"

$tunnelMgrSwift = Get-Utf8Text "mobile\ios\MeshCoreKit\Sources\TunnelManagerClient.swift"
$onDemandOrderOk = ($null -ne $tunnelMgrSwift) -and (
    $tunnelMgrSwift -match 'isOnDemandEnabled\s*=\s*false[\s\S]*?manager\.stopTunnel\s*\('
)
Record-Check "MOB-SEC-12" "iOS TunnelManagerClient disables isOnDemandEnabled = false before stopTunnel()" `
    $onDemandOrderOk `
    "Missing isOnDemandEnabled = false before manager.stopTunnel() in TunnelManagerClient.swift"

# 7. Sealed identity file consistency + 0 mpk_* passed into MeshPacketTunnel
Record-Check "MOB-SEC-13" "Both Android and iOS use sealed identity filename `"identity.sealed.bin`"" `
    ($hasAndroidSealedName -and $hasIosSealedName) `
    "Missing `"identity.sealed.bin`" reference in Android Kotlin or iOS Swift"

$packetTunnelDir = Join-Path $RepoRoot "mobile\ios\MeshPacketTunnel"
$packetTunnelSwift = Get-ChildItem -Path $packetTunnelDir -Filter "*.swift" -Recurse -File
$mpkLeakHits = [System.Collections.Generic.List[string]]::new()
foreach ($ptf in $packetTunnelSwift) {
    $txt = [System.IO.File]::ReadAllText($ptf.FullName, [System.Text.Encoding]::UTF8)
    # Reject any hardcoded mpk_ preauth token literal (4+ token chars).
    if ($txt -match 'mpk_[A-Za-z0-9_\-]{4,}') {
        $mpkLeakHits.Add($ptf.FullName.Substring($RepoRoot.Length + 1))
    }
}
$ptpSwift = Get-Utf8Text "mobile\ios\MeshPacketTunnel\Sources\PacketTunnelProvider.swift"
$constantsSwift = Get-Utf8Text "mobile\ios\MeshCoreKit\Sources\MeshConstants.swift"
$constantsForbidsSecrets = ($null -ne $constantsSwift) -and ($constantsSwift -match 'isForbiddenProviderConfigKey') -and ($constantsSwift -match '"mpk"') -and ($constantsSwift -match '"preauth"')
$providerRejectsPreauth = ($null -ne $ptpSwift) -and ($ptpSwift -match 'validateNoSecretOptions') -and ($ptpSwift -match 'isForbiddenProviderConfigKey')
$mgrStripsPreauth = ($null -ne $tunnelMgrSwift) -and ($tunnelMgrSwift -match 'buildValidatedProviderConfiguration') -and ($tunnelMgrSwift -match 'isForbiddenProviderConfigKey')

Record-Check "MOB-SEC-14" "0 mpk_* preauth keys passed into MeshPacketTunnel (both app and extension enforce rejection)" `
    ($mpkLeakHits.Count -eq 0 -and $constantsForbidsSecrets -and $providerRejectsPreauth -and $mgrStripsPreauth) `
    ("Found mpk_* token or missing providerConfiguration preauth guard: " + ($mpkLeakHits -join ", "))

# 8. Zero TCP listeners in Android/iOS + Rust FFI production safety
Record-Check "MOB-SEC-15" "0 TCP listeners in Android/iOS sources (IPC stays in-process / platform bridge)" `
    ($ktTcpHits.Count -eq 0 -and $swiftTcpHits.Count -eq 0) `
    ("TCP listener hit: " + (($ktTcpHits + $swiftTcpHits) -join ", "))

$ffiSrcFiles = Get-ChildItem -Path (Join-Path $RepoRoot "crates\mesh-mobile-ffi\src") -Filter "*.rs" -File
$ffiViolations = [System.Collections.Generic.List[string]]::new()
foreach ($rf in $ffiSrcFiles) {
    $raw = [System.IO.File]::ReadAllText($rf.FullName, [System.Text.Encoding]::UTF8)
    $prodOnly = $raw.Split(@("#[cfg(test)]"), [System.StringSplitOptions]::None)[0]
    $codeOnly = Strip-CodeComments $prodOnly
    $rel = $rf.FullName.Substring($RepoRoot.Length + 1)
    if ($codeOnly -match '\.unwrap\s*\(|\.expect\s*\(|\bunsafe\b') {
        $ffiViolations.Add($rel)
    }
}
Record-Check "MOB-SEC-16" "crates/mesh-mobile-ffi/src production code has 0 .unwrap(), 0 .expect(), and 0 hand-written unsafe" `
    ($ffiSrcFiles.Count -gt 0 -and $ffiViolations.Count -eq 0) `
    ("Violation in: " + ($ffiViolations -join ", "))

Write-Host ""
Write-Host ("Summary: {0} passed, {1} failed." -f $script:Passed, $script:Failures.Count)
if ($script:Failures.Count -gt 0) {
    exit 1
}
exit 0
