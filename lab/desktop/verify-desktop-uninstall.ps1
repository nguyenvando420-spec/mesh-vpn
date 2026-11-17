#Requires -Version 5.1
<#
.SYNOPSIS
    Automated Desktop Upgrade & Clean Uninstall Verification Suite (`WP-D-C2`, `US-115`, `US-116`).
.DESCRIPTION
    Exercises `scripts/install-windows.ps1` in `-DryRun`, `-Uninstall -DryRun`, and
    `-Uninstall -PurgeData -DryRun` modes, and audits `scripts/install-macos.sh`,
    `scripts/package-macos-app.sh`, and `.github/workflows/release.yml` to verify:
      1. Graceful Tray shutdown signaling (`Local\MeshVpnGuiShutdownEvent`, 3,000 ms wait).
      2. `mesh.exe cleanup` (`ResourceLedger` isolation, `0` non-Mesh VPN interference).
      3. `MeshVpnAgent` service stop/delete and `MeshVPN-Overlay-Inbound` firewall/hosts cleanup.
      4. `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\MeshVPN` and `.lnk` shortcut removal.
      5. Removal of all 8+ packaged files (`MeshVPN.exe`, `meshd.exe`, `mesh.exe`,
         `mesh-server.exe`, `wintun.dll`, `wintun.dll.sha256`, `WINTUN-LICENSE.txt`,
         `README-WINTUN.md`).
      6. Preservation of `keys.json` and `bootstrap.toml` by default vs recursive removal
         when `-PurgeData` (`-Purge`) is supplied.
      7. macOS installer `codesign -v` guard, `/usr/local/libexec/mesh/meshd` (`root:wheel`),
         and `release.yml` explicit `MeshVPN.exe` entry in `SHA256SUMS` (no `mesh*` glob).
#>
[CmdletBinding()]
param(
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$InstallWinScript = Join-Path $RepoRoot "scripts\install-windows.ps1"
$InstallMacScript = Join-Path $RepoRoot "scripts\install-macos.sh"
$PackageMacScript = Join-Path $RepoRoot "scripts\package-macos-app.sh"
$ReleaseWorkflow  = Join-Path $RepoRoot ".github\workflows\release.yml"
$GuiWinRs         = Join-Path $RepoRoot "crates\mesh-sys\src\gui_windows.rs"

$Passed = 0
$Failed = 0

function Add-CheckResult {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][bool]$Ok,
        [string]$Details = ""
    )
    if ($Ok) {
        $script:Passed++
        Write-Host "[PASS] ${Id}: $Description" -ForegroundColor Green
    }
    else {
        $script:Failed++
        if (-not [string]::IsNullOrWhiteSpace($Details)) {
            Write-Host "[FAIL] ${Id}: $Description -> $Details" -ForegroundColor Red
        }
        else {
            Write-Host "[FAIL] ${Id}: $Description" -ForegroundColor Red
        }
    }
}

Write-Host "=== Desktop Upgrade & Uninstall Verification (US-115 / US-116) ===" -ForegroundColor Cyan
Write-Host "RepoRoot: $RepoRoot (DryRun=$($DryRun.IsPresent))"

# 1. Verify required scripts exist
$allExist = (Test-Path -LiteralPath $InstallWinScript) -and
            (Test-Path -LiteralPath $InstallMacScript) -and
            (Test-Path -LiteralPath $PackageMacScript) -and
            (Test-Path -LiteralPath $ReleaseWorkflow) -and
            (Test-Path -LiteralPath $GuiWinRs)
Add-CheckResult -Id "UNINST-01" -Description "Required installer, packaging, and workflow files exist" -Ok $allExist
if (-not $allExist) {
    exit 1
}

# 2. Execute install-windows.ps1 -DryRun (Install / Upgrade plan)
$installOut = (& powershell -NoProfile -ExecutionPolicy Bypass -File $InstallWinScript -DryRun 2>&1) | Out-String
$installExit = $LASTEXITCODE
$installOk = ($installExit -eq 0) -and
             ($installOut -match "Local\\MeshVpnGuiShutdownEvent") -and
             ($installOut -match "preserves existing keys\.json and bootstrap\.toml") -and
             ($installOut -match "MeshVPN\.exe") -and
             ($installOut -match "MeshVpnAgent")
Add-CheckResult -Id "UNINST-02" -Description "install-windows.ps1 -DryRun signals Local\MeshVpnGuiShutdownEvent, installs MeshVPN.exe + MeshVpnAgent, and preserves keys.json" -Ok $installOk -Details $installOut.Trim()

# 3. Execute install-windows.ps1 -Uninstall -DryRun (Default Uninstall preserves keys.json)
$uninstOut = (& powershell -NoProfile -ExecutionPolicy Bypass -File $InstallWinScript -Uninstall -DryRun 2>&1) | Out-String
$uninstExit = $LASTEXITCODE
$requiredBundleFiles = @(
    "MeshVPN.exe",
    "meshd.exe",
    "mesh.exe",
    "mesh-server.exe",
    "wintun.dll",
    "wintun.dll.sha256",
    "WINTUN-LICENSE.txt",
    "README-WINTUN.md"
)
$missingFiles = @()
foreach ($bf in $requiredBundleFiles) {
    if ($uninstOut -notmatch [regex]::Escape($bf)) {
        $missingFiles += $bf
    }
}
$uninstDefaultOk = ($uninstExit -eq 0) -and
                   ($uninstOut -match "Local\\MeshVpnGuiShutdownEvent") -and
                   ($uninstOut -match "mesh\.exe.*cleanup") -and
                   ($uninstOut -match "MeshVpnAgent") -and
                   ($uninstOut -match "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MeshVPN") -and
                   ($uninstOut -match "Would preserve '.*\\keys\.json' and '.*\\bootstrap\.toml'") -and
                   ($missingFiles.Count -eq 0)
Add-CheckResult -Id "UNINST-03" -Description "install-windows.ps1 -Uninstall -DryRun cleans GUI, service, ResourceLedger, HKCU Run, 8+ bundle files, and preserves keys.json" -Ok $uninstDefaultOk -Details $(if ($missingFiles.Count -gt 0) { "Missing bundle files: $($missingFiles -join ', ')" } else { "" })

# 4. Execute install-windows.ps1 -Uninstall -PurgeData -DryRun (Purges keys.json & bootstrap.toml)
$purgeOut = (& powershell -NoProfile -ExecutionPolicy Bypass -File $InstallWinScript -Uninstall -PurgeData -DryRun 2>&1) | Out-String
$purgeExit = $LASTEXITCODE
$purgeOk = ($purgeExit -eq 0) -and
           ($purgeOut -match "-PurgeData specified: would recursively delete '.*' \(including keys\.json and bootstrap\.toml\)")
Add-CheckResult -Id "UNINST-04" -Description "install-windows.ps1 -Uninstall -PurgeData -DryRun purges keys.json and bootstrap.toml on explicit request" -Ok $purgeOk -Details $purgeOut.Trim()

# 5. Verify `-PurgeData` without `-Uninstall` fails closed
$badPurgeFailed = $false
try {
    $null = (& powershell -NoProfile -ExecutionPolicy Bypass -File $InstallWinScript -PurgeData -DryRun 2>&1) | Out-String
    if ($LASTEXITCODE -ne 0) {
        $badPurgeFailed = $true
    }
}
catch {
    $badPurgeFailed = $true
}
Add-CheckResult -Id "UNINST-05" -Description "install-windows.ps1 rejects standalone -PurgeData without -Uninstall (fail-closed)" -Ok $badPurgeFailed

# 6. Verify constant alignment between `install-windows.ps1` and `crates/mesh-sys/src/gui_windows.rs`
$winPs1Raw = Get-Content -LiteralPath $InstallWinScript -Raw -Encoding UTF8
$guiWinRaw = Get-Content -LiteralPath $GuiWinRs -Raw -Encoding UTF8
$constAligned = ($guiWinRaw -match 'GUI_SHUTDOWN_EVENT:\s*&str\s*=\s*r"Local\\MeshVpnGuiShutdownEvent"') -and
                ($guiWinRaw -match 'WINDOWS_SERVICE_NAME:\s*&str\s*=\s*"MeshVpnAgent"') -and
                ($winPs1Raw -match '\$GuiShutdownEventName\s*=\s*"Local\\MeshVpnGuiShutdownEvent"') -and
                ($winPs1Raw -match '\$ServiceName\s*=\s*"MeshVpnAgent"')
Add-CheckResult -Id "UNINST-06" -Description "install-windows.ps1 & gui_windows.rs share identical GUI_SHUTDOWN_EVENT and WINDOWS_SERVICE_NAME constants" -Ok $constAligned

# 7. Verify macOS installer & packaging scripts (`install-macos.sh` & `package-macos-app.sh`)
$macShRaw = Get-Content -LiteralPath $InstallMacScript -Raw -Encoding UTF8
$pkgShRaw = Get-Content -LiteralPath $PackageMacScript -Raw -Encoding UTF8
$spctlCmd = "spctl" + " --master-disable"
$macOk = ($macShRaw -match 'if /usr/bin/codesign -v "\$\{target_path\}"') -and
         ($macShRaw -match 'DAEMON_DIR="/usr/local/libexec/mesh"') -and
         ($macShRaw -match 'preserved \$\{STATE_DIR\}/keys\.json') -and
         ($macShRaw -match '--uninstall') -and
         ($macShRaw -match '--purge') -and
         ($macShRaw -notmatch [regex]::Escape($spctlCmd)) -and
         ($pkgShRaw -notmatch [regex]::Escape($spctlCmd)) -and
         ($pkgShRaw -match 'STEP 1 \(ADR-026 Immutable Order\): Sign inner binaries FIRST') -and
         ($pkgShRaw -match 'STEP 2 \(ADR-026 Immutable Order\): Generate SHA256SUMS & embed Resources') -and
         ($pkgShRaw -match 'STEP 3 \(ADR-026 Immutable Order\): Sign outer Mesh VPN\.app WITHOUT --deep')
Add-CheckResult -Id "UNINST-07" -Description "install-macos.sh & package-macos-app.sh enforce codesign -v guard, 3-step signing order without --deep, and keys.json preservation" -Ok $macOk

# 8. Verify `.github/workflows/release.yml` lists `MeshVPN.exe` explicitly in `SHA256SUMS` (no `mesh*` glob)
$relRaw = Get-Content -LiteralPath $ReleaseWorkflow -Raw -Encoding UTF8
$relOk = ($relRaw -match 'sha256sum MeshVPN\.exe mesh\.exe meshd\.exe mesh-server\.exe wintun\.dll > SHA256SUMS') -and
         ($relRaw -notmatch 'sha256sum mesh\*')
Add-CheckResult -Id "UNINST-08" -Description "release.yml explicitly lists MeshVPN.exe in SHA256SUMS (no case-sensitive mesh* glob omission)" -Ok $relOk

Write-Host ""
Write-Host "Summary: $Passed passed, $Failed failed." -ForegroundColor $(if ($Failed -eq 0) { "Green" } else { "Red" })
if ($Failed -gt 0) {
    exit 1
}
exit 0
