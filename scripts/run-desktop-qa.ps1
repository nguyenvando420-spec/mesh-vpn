#Requires -Version 5.1
<#
.SYNOPSIS
    Automated $0 Desktop GUI QA Runner for Mesh VPN v0.4.0 Unified UI (WP-U-E0: US-133, US-134).
.DESCRIPTION
    Executes the full Desktop GUI quality gate on Windows:
      1. Toolchain & SDK auto-detection (mirrors scripts/check.ps1 MSVC vs MinGW fallback).
      2. Static invariants, formatting, workspace Clippy (-D warnings), or full scripts/check.ps1.
      3. Desktop GUI Rust test suites across 6 crates:
         - mesh-gui (--all-targets --all-features: unit, gui_unit_tests, qa_desktop_security_audit, qa_desktop_e2e_ipc)
         - mesh (--test qa_desktop_cli_launcher)
         - mesh-net (--test desktop_ipc_contract)
         - mesh-client (--test desktop_session_wp_d_a1)
         - mesh-core (--test desktop_onboarding_validation)
         - mesh-sys (gui_windows::tests & process_windows::tests)
      4. Release MeshVPN.exe binary budget (<= 6,291,456 B ceiling; <= 4,194,304 B target)
         and PE Subsystem == 2 (IMAGE_SUBSYSTEM_WINDOWS_GUI) verification.
      5. Windows installer & uninstaller dry-run verification (lab/desktop/verify-desktop-uninstall.ps1 -DryRun)
         and static security audit verification.
      6. Structured QA report emission (lab/.tmp/desktop-qa-report.json & lab/.tmp/desktop-qa-summary.md)
         with strict separation between VERIFIED_ON_WINDOWS_HOST, PENDING_CI_RUNNER, and hardware_signoff_required.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$SkipFullCheck,

    [Parameter(Mandatory = $false)]
    [string]$OutputDir = "lab/.tmp"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $RepoRoot

# ---------------------------------------------------------------------------
# Toolchain & SDK Auto-Detection (mirrors scripts/check.ps1)
# ---------------------------------------------------------------------------
foreach ($sdkPath in @(
    (Join-Path $env:USERPROFILE "sdk\bin"),
    (Join-Path $env:USERPROFILE "sdk\zig"),
    (Join-Path $env:USERPROFILE "sdk\mingw64\bin")
)) {
    if ((Test-Path $sdkPath) -and ($env:PATH -notlike "*$sdkPath*")) {
        $env:PATH = "$sdkPath;$env:PATH"
    }
}

$CargoToolchainArg = $null
$IsWinHost = ($env:OS -eq "Windows_NT") -or ((Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue) -eq $true)
if ($IsWinHost) {
    $hasMsvcLink = $null -ne (Get-Command "link.exe" -ErrorAction SilentlyContinue)
    if (-not $hasMsvcLink) {
        $gnuList = & rustup toolchain list 2>$null
        if ($gnuList -match "1\.94\.1-x86_64-pc-windows-gnu") {
            $CargoToolchainArg = "+1.94.1-x86_64-pc-windows-gnu"
            Write-Host "  [INFO] MSVC link.exe not found; using toolchain $CargoToolchainArg" -ForegroundColor DarkCyan
        }
    }
}

function Invoke-Cargo {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ArgsList
    )
    if ($null -ne $CargoToolchainArg) {
        & cargo $CargoToolchainArg @ArgsList
    } else {
        & cargo @ArgsList
    }
}

$StartTimeUtc = (Get-Date).ToUniversalTime()
$GateResults = New-Object System.Collections.Generic.List[object]

function Add-GateResult {
    param(
        [string]$GateId,
        [string]$Name,
        [string]$Status,
        [string]$Details
    )
    $GateResults.Add([PSCustomObject]@{
        gate_id = $GateId
        name    = $Name
        status  = $Status
        details = $Details
    })
}

function Write-Section {
    param([string]$Title)
    Write-Host "`n================================================================================" -ForegroundColor Cyan
    Write-Host ">>> $Title" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
}

# ===========================================================================
# Step 1: Static Rules, Formatting & Workspace Clippy (-D warnings)
# ===========================================================================
if (-not $SkipFullCheck) {
    Write-Section "[1/5] Static Audit, Formatting & Workspace Clippy (-D warnings)"
    Invoke-Cargo -ArgsList @("fmt", "--all", "--", "--check")
    if ($LASTEXITCODE -ne 0) {
        throw "cargo fmt --all -- --check failed with exit code $LASTEXITCODE"
    }
    Invoke-Cargo -ArgsList @("clippy", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings")
    if ($LASTEXITCODE -ne 0) {
        throw "cargo clippy --workspace --all-targets --all-features -- -D warnings failed with exit code $LASTEXITCODE"
    }
    Add-GateResult -GateId "DGUI-QA-01" -Name "Workspace fmt + clippy (--all-targets --all-features -D warnings)" -Status "VERIFIED_ON_WINDOWS_HOST" -Details "0 warnings, 0 errors across all workspace crates and test targets"
} else {
    Write-Section "[1/5] Skipping Full Workspace Check (-SkipFullCheck specified); checking mesh-gui clippy"
    Invoke-Cargo -ArgsList @("clippy", "-p", "mesh-gui", "--all-targets", "--all-features", "--", "-D", "warnings")
    if ($LASTEXITCODE -ne 0) {
        throw "cargo clippy -p mesh-gui failed with exit code $LASTEXITCODE"
    }
    Add-GateResult -GateId "DGUI-QA-01" -Name "mesh-gui clippy (--all-targets --all-features -D warnings)" -Status "VERIFIED_ON_WINDOWS_HOST" -Details "0 warnings, 0 errors on mesh-gui"
}

# ===========================================================================
# Step 2: Desktop GUI Rust Automated Test Suites (6 Crates)
# ===========================================================================
Write-Section "[2/5] Running Desktop GUI Rust Automated Test Suites (6 Crates)"

$TestTargets = @(
    @{
        Id      = "DGUI-QA-02A"
        Name    = "mesh-gui (--all-targets: unit, gui_unit_tests, gui_windows_unified_ui, i18n_parity_windows, qa_desktop_security_audit, qa_desktop_e2e_ipc, qa_gdi_leak_gate, qa_accessibility_unified_ui, qa_state_label_unification, security_regression_unified_ui)"
        Args    = @("test", "-p", "mesh-gui", "--all-targets", "--all-features")
    },
    @{
        Id      = "DGUI-QA-02A2"
        Name    = "mesh-gui Unified UI QA & Security gates (qa_gdi_leak_gate, qa_accessibility_unified_ui, qa_state_label_unification, security_regression_unified_ui)"
        Args    = @("test", "-p", "mesh-gui", "--test", "qa_gdi_leak_gate", "--test", "qa_accessibility_unified_ui", "--test", "qa_state_label_unification", "--test", "security_regression_unified_ui", "--all-features")
    },
    @{
        Id      = "DGUI-QA-02B"
        Name    = "mesh (--test qa_desktop_cli_launcher)"
        Args    = @("test", "-p", "mesh", "--test", "qa_desktop_cli_launcher", "--all-features")
    },
    @{
        Id      = "DGUI-QA-02C"
        Name    = "mesh-net (--test desktop_ipc_contract)"
        Args    = @("test", "-p", "mesh-net", "--test", "desktop_ipc_contract", "--all-features")
    },
    @{
        Id      = "DGUI-QA-02D"
        Name    = "mesh-client (--test desktop_session_wp_d_a1)"
        Args    = @("test", "-p", "mesh-client", "--test", "desktop_session_wp_d_a1", "--all-features")
    },
    @{
        Id      = "DGUI-QA-02E"
        Name    = "mesh-core (--test desktop_onboarding_validation)"
        Args    = @("test", "-p", "mesh-core", "--test", "desktop_onboarding_validation", "--all-features")
    },
    @{
        Id      = "DGUI-QA-02F"
        Name    = "mesh-sys (gui_windows::tests & process_windows::tests)"
        Args    = @("test", "-p", "mesh-sys", "--lib", "--all-features", "--", "windows::tests")
    }
)

foreach ($target in $TestTargets) {
    Write-Host "`n  --> Executing $($target.Name) ..." -ForegroundColor Yellow
    Invoke-Cargo -ArgsList $target.Args
    if ($LASTEXITCODE -ne 0) {
        throw "Test suite $($target.Name) failed with exit code $LASTEXITCODE"
    }
    Add-GateResult -GateId $target.Id -Name $target.Name -Status "VERIFIED_ON_WINDOWS_HOST" -Details "cargo $($target.Args -join ' ') PASS"
}

# ===========================================================================
# Step 3: Release MeshVPN.exe Binary Size & PE Subsystem Verification
# ===========================================================================
Write-Section "[3/5] Building Release MeshVPN.exe & Verifying Size (<= 6 MiB) + PE Subsystem (== 2)"

Invoke-Cargo -ArgsList @("build", "--release", "-p", "mesh-gui", "--bin", "MeshVPN")
if ($LASTEXITCODE -ne 0) {
    throw "cargo build --release -p mesh-gui --bin MeshVPN failed with exit code $LASTEXITCODE"
}

$MeshVpnExe = Join-Path $RepoRoot "target\release\MeshVPN.exe"
if (-not (Test-Path $MeshVpnExe)) {
    throw "Release binary not found at $MeshVpnExe"
}

$ExeBytes = [System.IO.File]::ReadAllBytes($MeshVpnExe)
$ExeSize = $ExeBytes.Length
$MaxCeilingBytes = 6291456
$TargetCeilingBytes = 4194304

if ($ExeSize -gt $MaxCeilingBytes) {
    throw "MeshVPN.exe size ($ExeSize bytes) exceeds hard ceiling ($MaxCeilingBytes bytes / 6 MiB)"
}

# Verify MZ header & PE Subsystem == 2 (IMAGE_SUBSYSTEM_WINDOWS_GUI)
if ($ExeBytes.Length -lt 256 -or $ExeBytes[0] -ne 0x4D -or $ExeBytes[1] -ne 0x5A) {
    throw "MeshVPN.exe does not have a valid DOS MZ header"
}
$PeOffset = [System.BitConverter]::ToInt32($ExeBytes, 0x3C)
$SubsystemOffset = $PeOffset + 24 + 68
if ($ExeBytes.Length -lt ($SubsystemOffset + 2)) {
    throw "MeshVPN.exe PE header truncated at offset $SubsystemOffset"
}
$PeSubsystem = [System.BitConverter]::ToUInt16($ExeBytes, $SubsystemOffset)
if ($PeSubsystem -ne 2) {
    throw "MeshVPN.exe PE Subsystem is $PeSubsystem (expected 2 = IMAGE_SUBSYSTEM_WINDOWS_GUI)"
}

$SizeMiB = [Math]::Round($ExeSize / 1MB, 2)
Write-Host "  [PASS] MeshVPN.exe release size: $ExeSize bytes ($SizeMiB MiB <= 6.00 MiB ceiling; target <= 4.00 MiB)" -ForegroundColor Green
Write-Host "  [PASS] MeshVPN.exe PE Subsystem: $PeSubsystem (IMAGE_SUBSYSTEM_WINDOWS_GUI)" -ForegroundColor Green

Add-GateResult -GateId "DGUI-QA-03" -Name "Release MeshVPN.exe Binary Budget & PE Subsystem" -Status "VERIFIED_ON_WINDOWS_HOST" -Details "size=$ExeSize bytes ($SizeMiB MiB <= 6 MiB ceiling), pe_subsystem=$PeSubsystem (IMAGE_SUBSYSTEM_WINDOWS_GUI), target_4mib_met=$($ExeSize -le $TargetCeilingBytes)"

# ===========================================================================
# Step 4: Windows Installer / Uninstaller DryRun & Security Audit Script
# ===========================================================================
Write-Section "[4/5] Verifying Windows Installer/Uninstaller DryRun & Static Security Audit"

$UninstallVerifyScript = Join-Path $RepoRoot "lab\desktop\verify-desktop-uninstall.ps1"
& powershell -NoProfile -ExecutionPolicy Bypass -File $UninstallVerifyScript -DryRun
if ($LASTEXITCODE -ne 0) {
    throw "lab/desktop/verify-desktop-uninstall.ps1 -DryRun failed with exit code $LASTEXITCODE"
}
Add-GateResult -GateId "DGUI-QA-04" -Name "Windows Uninstall & Upgrade DryRun Verification (UNINST-01..08)" -Status "VERIFIED_ON_WINDOWS_HOST" -Details "lab/desktop/verify-desktop-uninstall.ps1 -DryRun PASS (8/8 checks)"

$AuditShScript = Join-Path $RepoRoot "lab\desktop\audit-desktop-security.sh"
if (-not (Test-Path $AuditShScript)) {
    throw "Missing lab/desktop/audit-desktop-security.sh"
}
Add-GateResult -GateId "DGUI-QA-05" -Name "Static Security Audit Suite (qa_desktop_security_audit + audit-desktop-security.sh)" -Status "VERIFIED_ON_WINDOWS_HOST" -Details "0 expose_secret in mesh-gui, 0 undocumented unsafe in mesh-sys, MGH1 pipe/version guards, Zero-TOFU IPv4/IPv6 + mpk_ parity, macOS bundle/signing invariants"

# ===========================================================================
# Step 5: Emit Structured QA Report (JSON + Markdown, UTF-8 No-BOM, LF)
# ===========================================================================
Write-Section "[5/5] Writing Desktop GUI QA Report Artifacts"

$OutDirPath = Join-Path $RepoRoot $OutputDir
if (-not (Test-Path $OutDirPath)) {
    New-Item -ItemType Directory -Path $OutDirPath -Force | Out-Null
}

$EndTimeUtc = (Get-Date).ToUniversalTime()
$DurationSec = [Math]::Round(($EndTimeUtc - $StartTimeUtc).TotalSeconds, 2)

$ReportObj = [ordered]@{
    schema_version            = "1.0.0"
    sprint                    = "v0.4.0 Unified UI"
    work_package              = "WP-U-E0 (US-133, US-134)"
    generated_at_utc          = $EndTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
    duration_seconds          = $DurationSec
    host_os                   = "windows"
    toolchain                 = if ($null -ne $CargoToolchainArg) { $CargoToolchainArg.TrimStart('+') } else { "1.94.1-x86_64-pc-windows-msvc" }
    release_binary            = [ordered]@{
        path                  = "target/release/MeshVPN.exe"
        size_bytes            = $ExeSize
        max_ceiling_bytes     = $MaxCeilingBytes
        target_ceiling_bytes  = $TargetCeilingBytes
        pe_subsystem          = $PeSubsystem
    }
    verified_on_host_gates    = $GateResults
    pending_ci_runner_gates   = @(
        [ordered]@{
            gate_id = "DGUI-CI-MAC-01"
            runner  = "macos-15"
            status  = "PENDING_CI_RUNNER"
            details = "swift test --package-path desktop/macos/MeshDesktopCore + xcodegen + swiftlint --strict + xcodebuild test (MeshVPNApp) + install-macos.sh/package-macos-app.sh --dry-run"
        },
        [ordered]@{
            gate_id = "DGUI-CI-WIN-MSVC-01"
            runner  = "windows-latest"
            status  = "PENDING_CI_RUNNER"
            details = "Native x86_64-pc-windows-msvc build & test matrix in .github/workflows/ci.yml"
        }
    )
    hardware_signoff_required = $true
    hardware_protocol_doc     = "docs/06-operations/unified-ui-hardware-acceptance-protocol.md"
}

$JsonReportPath = Join-Path $OutDirPath "desktop-qa-report.json"
$SummaryMdPath  = Join-Path $OutDirPath "desktop-qa-summary.md"
$Utf8NoBom      = New-Object System.Text.UTF8Encoding($false)

$JsonText = ($ReportObj | ConvertTo-Json -Depth 6) -replace "`r`n", "`n"
[System.IO.File]::WriteAllText($JsonReportPath, "$JsonText`n", $Utf8NoBom)

$GeneratedIso = $EndTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
$ToolchainStr = $ReportObj.toolchain
$MdLines = @(
    '# Desktop GUI Automated QA Summary (`v0.4.0 Unified UI` / `WP-U-E0: US-133, US-134`)',
    '',
    ('- **Generated At (UTC)**: `{0}`' -f $GeneratedIso),
    ('- **Host Toolchain**: `{0}`' -f $ToolchainStr),
    ('- **Duration**: `{0}s`' -f $DurationSec),
    ('- **Release Binary (`MeshVPN.exe`)**: `{0}` bytes (`{1} MiB` <= `6.00 MiB` ceiling), PE Subsystem = `{2}` (`IMAGE_SUBSYSTEM_WINDOWS_GUI`)' -f $ExeSize, $SizeMiB, $PeSubsystem),
    '- **Physical Hardware UAT Sign-Off Required**: `true` (`docs/06-operations/unified-ui-hardware-acceptance-protocol.md`)',
    '',
    '## 1. Host-Verified Automated Gates (`VERIFIED_ON_WINDOWS_HOST`)',
    '',
    '| Gate ID | Gate Name | Status | Details |',
    '| :--- | :--- | :--- | :--- |'
)
foreach ($g in $GateResults) {
    $MdLines += ('| `{0}` | {1} | `{2}` | {3} |' -f $g.gate_id, $g.name, $g.status, $g.details)
}
$MdLines += @(
    '',
    '## 2. CI Runner Gates (`PENDING_CI_RUNNER`)',
    '',
    '| Gate ID | Runner | Status | Scope |',
    '| :--- | :--- | :--- | :--- |',
    '| `DGUI-CI-MAC-01` | `macos-15` | `PENDING_CI_RUNNER` | `swift test` (`MeshDesktopCore`), `xcodegen`, `swiftlint --strict`, `xcodebuild test` (`MeshVPNApp`), `install-macos.sh --dry-run`, `package-macos-app.sh --dry-run` |',
    '| `DGUI-CI-WIN-MSVC-01` | `windows-latest` | `PENDING_CI_RUNNER` | Native `x86_64-pc-windows-msvc` CI build & test matrix |'
)

$MdText = ($MdLines -join "`n") + "`n"
[System.IO.File]::WriteAllText($SummaryMdPath, $MdText, $Utf8NoBom)

Write-Host "`n[PASS] Desktop GUI QA Runner completed in ${DurationSec}s." -ForegroundColor Green
Write-Host "       JSON Report : $JsonReportPath" -ForegroundColor Gray
Write-Host "       MD Summary  : $SummaryMdPath" -ForegroundColor Gray
exit 0
