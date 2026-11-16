#Requires -Version 5.1
<#
.SYNOPSIS
    Cross-platform Mobile QA Runner for Mesh VPN v0.2.0 (`WP-M-C2`, `US-097`).
.DESCRIPTION
    Executes end-to-end mobile verification without faking passes:
      1. Runs `scripts/check.ps1 -Cross` (unless `-SkipCheck` is supplied).
      2. Loops over all 5 mobile targets (`aarch64-linux-android`, `x86_64-linux-android`,
         `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`):
         - `cargo-deny --target <t> check advisories bans licenses sources`
         - `cargo check -p mesh-core -p mesh-sys --target <t>`
         - Conditional `cargo check -p mesh-mobile-ffi --target <t>` when NDK/Xcode SDK is present,
           otherwise logs `[SKIP - Host lacks NDK/Xcode SDK; enforced in mobile CI workflows]`.
      3. Verifies `.so` ELF size budget (`<= 6_291_456` bytes = `6 MiB`) via `zig` + `cargo-zigbuild`
         and runs `mesh-uniffi-bindgen generate` for Kotlin + Swift in `$env:TEMP\mesh-mobile-qa-bindgen`.
      4. Runs mobile static security audit (`lab/mobile/audit-mobile-security.ps1` if present plus
         core Android/iOS hygiene rules) and `cargo test -p mesh-mobile-ffi -p mesh-client -p mesh --all-features`.
      5. Emits `lab/.tmp/mobile-qa-report.json` and `lab/.tmp/mobile-qa-summary.md` (UTF-8 no BOM, LF).
#>
[CmdletBinding()]
param(
    [switch]$SkipCheck,
    [string]$OutputDir = "lab/.tmp"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $RepoRoot

$MaxSoBytes = 6291456
$MobileTargets = @(
    "aarch64-linux-android",
    "x86_64-linux-android",
    "aarch64-apple-ios",
    "aarch64-apple-ios-sim",
    "x86_64-apple-ios"
)
$RequiredFfiSymbols = @(
    "MobileEngine",
    "PlatformNetworkBridge",
    "mobileEnrollOrRotateNode",
    "parseMobileJoinUri",
    "createPendingJoinSession",
    "completeRouteChange",
    "startTunnel",
    "stopTunnel",
    "shutdown"
)

$Steps = [System.Collections.Generic.List[object]]::new()
$TargetMatrix = [System.Collections.Generic.List[object]]::new()
$OverallPassed = $true
$ExitCode = 0
$ElfSizeBytes = $null
$BindgenTempDir = Join-Path $env:TEMP "mesh-mobile-qa-bindgen"

function Write-Utf8NoBomLf {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content
    )
    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $lf = ($Content -replace "`r`n", "`n") -replace "`r", "`n"
    if (-not $lf.EndsWith("`n")) {
        $lf += "`n"
    }
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $lf, $enc)
}

function Add-StepResult {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet("PASS", "FAIL", "SKIP")][string]$Status,
        [Parameter(Mandatory = $true)][long]$DurationMs,
        [Parameter(Mandatory = $true)][string]$Details
    )
    $Steps.Add([ordered]@{
        id          = $Id
        name        = $Name
        status      = $Status
        duration_ms = $DurationMs
        details     = $Details
    })
    if ($Status -eq "FAIL") {
        $script:OverallPassed = $false
    }
}

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][string[]]$Args
    )
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $Exe @Args 2>&1
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $prevPref
    }
    $lines = @($output | ForEach-Object { $_.ToString() })
    return [PSCustomObject]@{
        ExitCode = $code
        Output   = ($lines -join "`n")
    }
}

function Get-AndroidNdkPath {
    foreach ($cand in @($env:ANDROID_NDK_HOME, $env:ANDROID_NDK_ROOT)) {
        if (-not [string]::IsNullOrWhiteSpace($cand) -and (Test-Path $cand)) {
            return $cand
        }
    }
    foreach ($sdkRoot in @($env:ANDROID_HOME, $env:ANDROID_SDK_ROOT)) {
        if (-not [string]::IsNullOrWhiteSpace($sdkRoot)) {
            $ndkParent = Join-Path $sdkRoot "ndk"
            if (Test-Path $ndkParent) {
                $latest = Get-ChildItem -Path $ndkParent -Directory -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
                if ($null -ne $latest) {
                    return $latest.FullName
                }
            }
        }
    }
    return $null
}

function Test-AppleSdkAvailable {
    if (-not [string]::IsNullOrWhiteSpace($env:SDKROOT) -and (Test-Path $env:SDKROOT)) {
        return $true
    }
    return ($null -ne (Get-Command xcrun -ErrorAction SilentlyContinue))
}

function Invoke-MobileSecurityAudit {
    $errors = [System.Collections.Generic.List[string]]::new()

    $manifestPath = Join-Path $RepoRoot "mobile/android/app/src/main/AndroidManifest.xml"
    if (-not (Test-Path $manifestPath)) {
        $errors.Add("Missing AndroidManifest.xml at mobile/android/app/src/main/AndroidManifest.xml")
    }
    else {
        $manifest = Get-Content -Path $manifestPath -Raw -Encoding UTF8
        if ($manifest -notmatch 'android:allowBackup="false"') {
            $errors.Add('AndroidManifest.xml must set android:allowBackup="false"')
        }
        if ($manifest -match 'android:scheme="mesh"') {
            $errors.Add('AndroidManifest.xml must not register android:scheme="mesh" OS deep-link')
        }
    }

    $kotlinMainDir = Join-Path $RepoRoot "mobile/android/app/src/main/kotlin"
    $foundMeshNativeInit = $false
    if (-not (Test-Path $kotlinMainDir)) {
        $errors.Add("Missing Kotlin main source tree at mobile/android/app/src/main/kotlin")
    }
    else {
        $ktFiles = Get-ChildItem -Path $kotlinMainDir -Recurse -Filter "*.kt" -File
        foreach ($kf in $ktFiles) {
            $rel = $kf.FullName.Substring($RepoRoot.Length + 1).Replace("\", "/")
            $text = Get-Content -Path $kf.FullName -Raw -Encoding UTF8
            if ($text -match "dev\.meshvpn\.android\.ffi\.MeshNativeInit|object\s+MeshNativeInit\b") {
                $foundMeshNativeInit = $true
            }
            $lines = @($text -split "`r?`n")
            for ($i = 0; $i -lt $lines.Count; $i++) {
                $line = $lines[$i]
                $trimmed = $line.Trim()
                if ($trimmed.StartsWith("//") -or $trimmed.StartsWith("/*") -or $trimmed.StartsWith("*")) {
                    continue
                }
                if ($line -match "!!") {
                    $errors.Add("Forbidden Kotlin force-unwrap '!!' in ${rel}:$($i + 1)")
                }
            }
        }
    }
    if (-not $foundMeshNativeInit) {
        $errors.Add("Missing dev.meshvpn.android.ffi.MeshNativeInit in mobile/android/app/src/main/kotlin")
    }

    $iosRoot = Join-Path $RepoRoot "mobile/ios"
    if (-not (Test-Path $iosRoot)) {
        $errors.Add("Missing iOS directory at mobile/ios")
    }
    else {
        $iosPlists = Get-ChildItem -Path $iosRoot -Recurse -Include "*.plist", "*.entitlements" -File
        foreach ($pf in $iosPlists) {
            $rel = $pf.FullName.Substring($RepoRoot.Length + 1).Replace("\", "/")
            $text = Get-Content -Path $pf.FullName -Raw -Encoding UTF8
            if ($text -match "NSAllowsArbitraryLoads") {
                $errors.Add("Forbidden ATS bypass NSAllowsArbitraryLoads in $rel")
            }
            if ($text -match "CFBundleURLTypes") {
                $errors.Add("Forbidden deep-link scheme CFBundleURLTypes in $rel")
            }
        }

        $prodDirs = @("MeshApp", "MeshCoreKit", "MeshPacketTunnel")
        foreach ($pd in $prodDirs) {
            $dirPath = Join-Path $iosRoot $pd
            if (-not (Test-Path $dirPath)) {
                continue
            }
            $swiftFiles = Get-ChildItem -Path $dirPath -Recurse -Filter "*.swift" -File
            foreach ($sf in $swiftFiles) {
                $rel = $sf.FullName.Substring($RepoRoot.Length + 1).Replace("\", "/")
                $lines = @((Get-Content -Path $sf.FullName -Raw -Encoding UTF8) -split "`r?`n")
                for ($i = 0; $i -lt $lines.Count; $i++) {
                    $line = $lines[$i]
                    $trimmed = $line.Trim()
                    if ($trimmed.StartsWith("//") -or $trimmed.StartsWith("/*") -or $trimmed.StartsWith("*")) {
                        continue
                    }
                    $codeOnly = ($line -replace '"(?:\\.|[^"\\])*"', '""')
                    if ($codeOnly -match "\bfatalError\s*\(") {
                        $errors.Add("Forbidden fatalError in ${rel}:$($i + 1)")
                    }
                    if ($codeOnly -match "\b(try|as)!") {
                        $errors.Add("Forbidden try!/as! in ${rel}:$($i + 1)")
                    }
                    if ($codeOnly -match "[A-Za-z0-9_)\]]!(?!=)") {
                        $errors.Add("Forbidden Swift force-unwrap '!' in ${rel}:$($i + 1)")
                    }
                }
            }
        }
    }

    $ffiBridgePath = Join-Path $RepoRoot "crates/mesh-mobile-ffi/src/bridge.rs"
    if (-not (Test-Path $ffiBridgePath)) {
        $errors.Add("Missing crates/mesh-mobile-ffi/src/bridge.rs")
    }
    else {
        $bridgeText = Get-Content -Path $ffiBridgePath -Raw -Encoding UTF8
        if ($bridgeText -notmatch '"identity\.sealed\.bin"') {
            $errors.Add('Missing "identity.sealed.bin" constant in crates/mesh-mobile-ffi/src/bridge.rs')
        }
    }

    return $errors
}

try {
    # Prepend portable SDK directories matching scripts/check.ps1
    $SdkRoot = Join-Path $env:USERPROFILE "sdk"
    foreach ($dir in @(
        (Join-Path $SdkRoot "bin"),
        (Join-Path $SdkRoot "zig"),
        (Join-Path $SdkRoot "mingw64\bin")
    )) {
        if (Test-Path $dir) {
            $env:PATH = "$dir;$env:PATH"
        }
    }

    # Detect Windows linker toolchain matching scripts/check.ps1
    $CargoToolchainArgs = @()
    $CargoTargetArgs = @()
    $HostTargetTriple = "x86_64-pc-windows-msvc"
    if (-not (Get-Command link.exe -ErrorAction SilentlyContinue)) {
        if (-not (Get-Command x86_64-w64-mingw32-gcc.exe -ErrorAction SilentlyContinue)) {
            throw "Neither MSVC 'link.exe' nor MinGW 'x86_64-w64-mingw32-gcc.exe' was found on PATH."
        }
        $toolchains = (& rustup toolchain list 2>&1) | Out-String
        if ($toolchains -match "1\.94\.1-x86_64-pc-windows-gnu") {
            $CargoToolchainArgs = @("+1.94.1-x86_64-pc-windows-gnu")
            $HostTargetTriple = "x86_64-pc-windows-gnu"
            Write-Host "[Toolchain] MSVC link.exe absent; using +1.94.1-x86_64-pc-windows-gnu" -ForegroundColor Yellow
        }
        else {
            $CargoTargetArgs = @("--target", "x86_64-pc-windows-gnu")
            $HostTargetTriple = "x86_64-pc-windows-gnu"
            Write-Host "[Toolchain] MSVC link.exe absent; using --target x86_64-pc-windows-gnu" -ForegroundColor Yellow
        }
    }

    # Step 1: Workspace check.ps1 -Cross
    Write-Host "==> [Step 1/5] Workspace Verification (scripts/check.ps1 -Cross)..." -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if ($SkipCheck) {
        $sw.Stop()
        Write-Host "    [SKIP] Skipped via -SkipCheck." -ForegroundColor Yellow
        Add-StepResult -Id "step_1_workspace_check" -Name "scripts/check.ps1 -Cross" -Status "SKIP" -DurationMs $sw.ElapsedMilliseconds -Details "Skipped by -SkipCheck flag"
    }
    else {
        $res = Invoke-NativeChecked -Exe "powershell" -Args @("-ExecutionPolicy", "Bypass", "-File", (Join-Path $RepoRoot "scripts/check.ps1"), "-Cross")
        $sw.Stop()
        if ($res.ExitCode -ne 0) {
            Add-StepResult -Id "step_1_workspace_check" -Name "scripts/check.ps1 -Cross" -Status "FAIL" -DurationMs $sw.ElapsedMilliseconds -Details $res.Output
            throw "Step 1 failed: scripts/check.ps1 -Cross exited with code $($res.ExitCode)"
        }
        Add-StepResult -Id "step_1_workspace_check" -Name "scripts/check.ps1 -Cross" -Status "PASS" -DurationMs $sw.ElapsedMilliseconds -Details "Workspace static checks, fmt, clippy, tests, cargo-deny, and desktop cross checks passed."
    }

    # Step 2: 5 Mobile Targets (cargo-deny, cargo check core+sys, conditional cargo check ffi)
    Write-Host "==> [Step 2/5] Checking 5 Mobile Targets..." -ForegroundColor Cyan
    $sw.Restart()
    $androidNdk = Get-AndroidNdkPath
    $hasAppleSdk = Test-AppleSdkAvailable
    $hasCargoDeny = $null -ne (Get-Command cargo-deny -ErrorAction SilentlyContinue)
    if (-not $hasCargoDeny) {
        $sw.Stop()
        Add-StepResult -Id "step_2_mobile_targets" -Name "5 Mobile Targets" -Status "FAIL" -DurationMs $sw.ElapsedMilliseconds -Details "cargo-deny not found on PATH"
        throw "cargo-deny is required for Step 2"
    }

    $targetFailures = [System.Collections.Generic.List[string]]::new()
    $targetSkippedFfi = 0
    foreach ($t in $MobileTargets) {
        Write-Host "    -> Target: $t"
        $denyRes = Invoke-NativeChecked -Exe "cargo-deny" -Args @("--target", $t, "check", "advisories", "bans", "licenses", "sources")
        if ($denyRes.ExitCode -ne 0) {
            $targetFailures.Add("${t}: cargo-deny failed ($($denyRes.Output))")
            $TargetMatrix.Add([ordered]@{ target = $t; cargo_deny = "FAIL"; core_sys_check = "NOT_RUN"; mobile_ffi_check = "NOT_RUN"; notes = "cargo-deny failed" })
            continue
        }

        $coreArgs = @() + $CargoToolchainArgs + @("check", "-p", "mesh-core", "-p", "mesh-sys", "--target", $t)
        $coreRes = Invoke-NativeChecked -Exe "cargo" -Args $coreArgs
        if ($coreRes.ExitCode -ne 0) {
            $targetFailures.Add("${t}: cargo check -p mesh-core -p mesh-sys failed ($($coreRes.Output))")
            $TargetMatrix.Add([ordered]@{ target = $t; cargo_deny = "PASS"; core_sys_check = "FAIL"; mobile_ffi_check = "NOT_RUN"; notes = "mesh-core/mesh-sys check failed" })
            continue
        }

        $isAndroid = $t -like "*-linux-android"
        $canCheckFfi = ($isAndroid -and ($null -ne $androidNdk)) -or ((-not $isAndroid) -and $hasAppleSdk)
        if ($canCheckFfi) {
            $ffiArgs = @() + $CargoToolchainArgs + @("check", "-p", "mesh-mobile-ffi", "--target", $t)
            $ffiRes = Invoke-NativeChecked -Exe "cargo" -Args $ffiArgs
            if ($ffiRes.ExitCode -ne 0) {
                $targetFailures.Add("${t}: cargo check -p mesh-mobile-ffi failed ($($ffiRes.Output))")
                $TargetMatrix.Add([ordered]@{ target = $t; cargo_deny = "PASS"; core_sys_check = "PASS"; mobile_ffi_check = "FAIL"; notes = "mesh-mobile-ffi check failed" })
                continue
            }
            $TargetMatrix.Add([ordered]@{ target = $t; cargo_deny = "PASS"; core_sys_check = "PASS"; mobile_ffi_check = "PASS"; notes = "Native SDK present; full FFI check passed" })
        }
        else {
            $skipMsg = "[SKIP - Host lacks NDK/Xcode SDK; enforced in mobile CI workflows]"
            Write-Host "       $skipMsg" -ForegroundColor Yellow
            $targetSkippedFfi++
            $TargetMatrix.Add([ordered]@{ target = $t; cargo_deny = "PASS"; core_sys_check = "PASS"; mobile_ffi_check = "SKIP"; notes = $skipMsg })
        }
    }
    $sw.Stop()
    if ($targetFailures.Count -gt 0) {
        $detailStr = $targetFailures -join " | "
        Add-StepResult -Id "step_2_mobile_targets" -Name "5 Mobile Targets" -Status "FAIL" -DurationMs $sw.ElapsedMilliseconds -Details $detailStr
        throw "Step 2 failed: $detailStr"
    }
    Add-StepResult -Id "step_2_mobile_targets" -Name "5 Mobile Targets" -Status "PASS" -DurationMs $sw.ElapsedMilliseconds -Details "All 5 mobile targets passed cargo-deny + mesh-core/mesh-sys check ($targetSkippedFfi FFI checks skipped due to missing NDK/Xcode SDK)."

    # Step 3: ELF .so Size Budget (<= 6 MiB) & UniFFI Codegen
    Write-Host "==> [Step 3/5] ELF .so Size Budget (<= 6 MiB) & UniFFI Bindings Codegen..." -ForegroundColor Cyan
    $sw.Restart()
    $step3Details = [System.Collections.Generic.List[string]]::new()

    $hasZig = $null -ne (Get-Command zig -ErrorAction SilentlyContinue)
    $hasZigbuild = $null -ne (Get-Command cargo-zigbuild -ErrorAction SilentlyContinue)
    if ($hasZig -and $hasZigbuild) {
        $zigExePath = (Get-Command zig -ErrorAction Stop).Source
        $zigVerStr = ((& $zigExePath version) | Out-String).Trim()
        $zigbuildExePath = (Get-Command cargo-zigbuild -ErrorAction Stop).Source

        $ShimDir = Join-Path $env:TEMP "mesh-zigcc-shims"
        New-Item -ItemType Directory -Force -Path $ShimDir | Out-Null
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        $muslCc = Join-Path $ShimDir "zigcc-x86_64-unknown-linux-musl.bat"
        $zigAr = Join-Path $ShimDir "zig-ar.bat"
        $shimHeader = "@echo off`r`nsetlocal DisableDelayedExpansion`r`nset CARGO_ZIGBUILD_ZIG_VERSION=$zigVerStr`r`nset `"CARGO_ZIGBUILD_ZIG_COMMAND=$zigExePath`"`r`n"
        [System.IO.File]::WriteAllText($muslCc, "$shimHeader`"$zigbuildExePath`" zig cc -- -g -fno-sanitize=all -target x86_64-linux-musl %*`r`n", $utf8NoBom)
        [System.IO.File]::WriteAllText($zigAr, "@echo off`r`n`"$zigExePath`" ar %*`r`n", $utf8NoBom)

        $prevCc = $env:CC_x86_64_unknown_linux_musl
        $prevAr = $env:AR_x86_64_unknown_linux_musl
        $prevOpt = $env:CARGO_PROFILE_RELEASE_OPT_LEVEL
        $prevLto = $env:CARGO_PROFILE_RELEASE_LTO
        $prevRustflags = $env:RUSTFLAGS
        try {
            $env:CC_x86_64_unknown_linux_musl = $muslCc
            $env:AR_x86_64_unknown_linux_musl = $zigAr
            $env:CARGO_PROFILE_RELEASE_OPT_LEVEL = "z"
            $env:CARGO_PROFILE_RELEASE_LTO = "fat"
            $env:RUSTFLAGS = "-C target-feature=-crt-static"

            $zigArgs = @() + $CargoToolchainArgs + @("zigbuild", "--release", "-p", "mesh-mobile-ffi", "--target", "x86_64-unknown-linux-musl")
            $zigRes = Invoke-NativeChecked -Exe "cargo" -Args $zigArgs
            if ($zigRes.ExitCode -ne 0) {
                $sw.Stop()
                Add-StepResult -Id "step_3_size_and_bindgen" -Name "ELF Size Budget & UniFFI Codegen" -Status "FAIL" -DurationMs $sw.ElapsedMilliseconds -Details "cargo zigbuild failed: $($zigRes.Output)"
                throw "Step 3a failed: cargo zigbuild exited with code $($zigRes.ExitCode)"
            }
        }
        finally {
            $env:CC_x86_64_unknown_linux_musl = $prevCc
            $env:AR_x86_64_unknown_linux_musl = $prevAr
            $env:CARGO_PROFILE_RELEASE_OPT_LEVEL = $prevOpt
            $env:CARGO_PROFILE_RELEASE_LTO = $prevLto
            $env:RUSTFLAGS = $prevRustflags
        }

        $soPath = Join-Path $RepoRoot "target/x86_64-unknown-linux-musl/release/libmesh_mobile_ffi.so"
        if (-not (Test-Path $soPath)) {
            $sw.Stop()
            Add-StepResult -Id "step_3_size_and_bindgen" -Name "ELF Size Budget & UniFFI Codegen" -Status "FAIL" -DurationMs $sw.ElapsedMilliseconds -Details "Expected ELF binary missing at $soPath"
            throw "Step 3a failed: missing $soPath"
        }
        $ElfSizeBytes = (Get-Item $soPath).Length
        Write-Host "    libmesh_mobile_ffi.so size: $ElfSizeBytes bytes (budget <= $MaxSoBytes bytes)"
        if ($ElfSizeBytes -gt $MaxSoBytes) {
            $sw.Stop()
            Add-StepResult -Id "step_3_size_and_bindgen" -Name "ELF Size Budget & UniFFI Codegen" -Status "FAIL" -DurationMs $sw.ElapsedMilliseconds -Details "libmesh_mobile_ffi.so size $ElfSizeBytes > $MaxSoBytes bytes"
            throw "Step 3a failed: ELF size $ElfSizeBytes exceeds $MaxSoBytes bytes"
        }
        $step3Details.Add("libmesh_mobile_ffi.so=${ElfSizeBytes}B (<=${MaxSoBytes}B)")
    }
    else {
        $step3Details.Add("[SKIP - zig/cargo-zigbuild absent for ELF size check]")
        Write-Host "    [SKIP] zig or cargo-zigbuild not installed; skipping musl .so size check." -ForegroundColor Yellow
    }

    # Step 3b: Build host --release -p mesh-mobile-ffi & run mesh-uniffi-bindgen generate
    $hostBuildArgs = @() + $CargoToolchainArgs + @("build", "--release", "-p", "mesh-mobile-ffi") + $CargoTargetArgs
    $hostBuildRes = Invoke-NativeChecked -Exe "cargo" -Args $hostBuildArgs
    if ($hostBuildRes.ExitCode -ne 0) {
        $sw.Stop()
        Add-StepResult -Id "step_3_size_and_bindgen" -Name "ELF Size Budget & UniFFI Codegen" -Status "FAIL" -DurationMs $sw.ElapsedMilliseconds -Details "Host release build failed: $($hostBuildRes.Output)"
        throw "Step 3b failed: host release build of mesh-mobile-ffi failed"
    }

    $hostDllCandidates = @(
        (Join-Path $RepoRoot "target/release/mesh_mobile_ffi.dll"),
        (Join-Path $RepoRoot "target/$HostTargetTriple/release/mesh_mobile_ffi.dll")
    )
    $hostLibPath = $hostDllCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($null -eq $hostLibPath) {
        $sw.Stop()
        Add-StepResult -Id "step_3_size_and_bindgen" -Name "ELF Size Budget & UniFFI Codegen" -Status "FAIL" -DurationMs $sw.ElapsedMilliseconds -Details "Could not locate built mesh_mobile_ffi.dll"
        throw "Step 3b failed: mesh_mobile_ffi.dll not found"
    }

    if (Test-Path $BindgenTempDir) {
        Remove-Item -Path $BindgenTempDir -Recurse -Force
    }
    $kotlinOutDir = Join-Path $BindgenTempDir "kotlin"
    $swiftOutDir = Join-Path $BindgenTempDir "swift"
    New-Item -ItemType Directory -Force -Path $kotlinOutDir, $swiftOutDir | Out-Null

    foreach ($langSpec in @(
        @{ Lang = "kotlin"; OutDir = $kotlinOutDir; Filter = "*.kt" },
        @{ Lang = "swift"; OutDir = $swiftOutDir; Filter = "*.swift" }
    )) {
        $bgArgs = @() + $CargoToolchainArgs + @("run", "-p", "mesh-uniffi-bindgen") + $CargoTargetArgs + @("--", "generate", "--library", $hostLibPath, "--language", $langSpec.Lang, "--out-dir", $langSpec.OutDir)
        $bgRes = Invoke-NativeChecked -Exe "cargo" -Args $bgArgs
        if ($bgRes.ExitCode -ne 0) {
            $sw.Stop()
            Add-StepResult -Id "step_3_size_and_bindgen" -Name "ELF Size Budget & UniFFI Codegen" -Status "FAIL" -DurationMs $sw.ElapsedMilliseconds -Details "mesh-uniffi-bindgen ($($langSpec.Lang)) failed: $($bgRes.Output)"
            throw "Step 3b failed: mesh-uniffi-bindgen failed for $($langSpec.Lang)"
        }

        $genFiles = @(Get-ChildItem -Path $langSpec.OutDir -Recurse -Filter $langSpec.Filter -File)
        if ($genFiles.Count -eq 0) {
            $sw.Stop()
            Add-StepResult -Id "step_3_size_and_bindgen" -Name "ELF Size Budget & UniFFI Codegen" -Status "FAIL" -DurationMs $sw.ElapsedMilliseconds -Details "No $($langSpec.Filter) files generated for $($langSpec.Lang)"
            throw "Step 3b failed: no generated files for $($langSpec.Lang)"
        }
        $combinedText = ($genFiles | ForEach-Object { Get-Content -Path $_.FullName -Raw -Encoding UTF8 }) -join "`n"
        $missingSyms = @()
        foreach ($sym in $RequiredFfiSymbols) {
            if ($combinedText -notmatch "\b$([regex]::Escape($sym))\b") {
                $missingSyms += $sym
            }
        }
        if ($missingSyms.Count -gt 0) {
            $sw.Stop()
            $msg = "Missing UniFFI $($langSpec.Lang) symbols: $($missingSyms -join ', ')"
            Add-StepResult -Id "step_3_size_and_bindgen" -Name "ELF Size Budget & UniFFI Codegen" -Status "FAIL" -DurationMs $sw.ElapsedMilliseconds -Details $msg
            throw "Step 3b failed: $msg"
        }
    }
    $sw.Stop()
    $step3Details.Add("UniFFI Kotlin & Swift bindings generated and verified ($($RequiredFfiSymbols.Count)/$($RequiredFfiSymbols.Count) symbols)")
    Add-StepResult -Id "step_3_size_and_bindgen" -Name "ELF Size Budget & UniFFI Codegen" -Status "PASS" -DurationMs $sw.ElapsedMilliseconds -Details ($step3Details -join "; ")

    # Step 4: Mobile Static Security Audit & Crate Tests
    Write-Host "==> [Step 4/5] Mobile Static Security Audit & Crate Tests..." -ForegroundColor Cyan
    $sw.Restart()
    $step4Details = [System.Collections.Generic.List[string]]::new()

    $labAuditPs1 = Join-Path $RepoRoot "lab/mobile/audit-mobile-security.ps1"
    if (Test-Path $labAuditPs1) {
        $extAuditRes = Invoke-NativeChecked -Exe "powershell" -Args @("-ExecutionPolicy", "Bypass", "-File", $labAuditPs1)
        if ($extAuditRes.ExitCode -ne 0) {
            $sw.Stop()
            Add-StepResult -Id "step_4_security_and_tests" -Name "Mobile Security Audit & Tests" -Status "FAIL" -DurationMs $sw.ElapsedMilliseconds -Details "lab/mobile/audit-mobile-security.ps1 failed: $($extAuditRes.Output)"
            throw "Step 4 failed: lab/mobile/audit-mobile-security.ps1 exited with code $($extAuditRes.ExitCode)"
        }
        $step4Details.Add("lab/mobile/audit-mobile-security.ps1 PASSED")
    }

    $auditErrors = @(Invoke-MobileSecurityAudit)
    if ($auditErrors.Count -gt 0) {
        $sw.Stop()
        $msg = $auditErrors -join " | "
        Add-StepResult -Id "step_4_security_and_tests" -Name "Mobile Security Audit & Tests" -Status "FAIL" -DurationMs $sw.ElapsedMilliseconds -Details $msg
        throw "Step 4 failed: static mobile security audit errors: $msg"
    }
    $step4Details.Add("Built-in Android/iOS/FFI static security audit PASSED")

    $testArgs = @() + $CargoToolchainArgs + @("test", "-p", "mesh-mobile-ffi", "-p", "mesh-client", "-p", "mesh", "--all-features") + $CargoTargetArgs
    $testRes = Invoke-NativeChecked -Exe "cargo" -Args $testArgs
    $sw.Stop()
    if ($testRes.ExitCode -ne 0) {
        Add-StepResult -Id "step_4_security_and_tests" -Name "Mobile Security Audit & Tests" -Status "FAIL" -DurationMs $sw.ElapsedMilliseconds -Details "cargo test failed: $($testRes.Output)"
        throw "Step 4 failed: cargo test exited with code $($testRes.ExitCode)"
    }
    $step4Details.Add("cargo test -p mesh-mobile-ffi -p mesh-client -p mesh --all-features PASSED")
    Add-StepResult -Id "step_4_security_and_tests" -Name "Mobile Security Audit & Tests" -Status "PASS" -DurationMs $sw.ElapsedMilliseconds -Details ($step4Details -join "; ")

    Write-Host "==> MOBILE QA SUITE PASSED!" -ForegroundColor Green
}
catch {
    $ExitCode = 1
    $OverallPassed = $false
    Write-Error $_.Exception.Message
}
finally {
    if (Test-Path $BindgenTempDir) {
        Remove-Item -Path $BindgenTempDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Step 5: Emit JSON & Markdown reports into lab/.tmp/
    $outAbs = if ([System.IO.Path]::IsPathRooted($OutputDir)) { $OutputDir } else { Join-Path $RepoRoot $OutputDir }
    $jsonReportPath = Join-Path $outAbs "mobile-qa-report.json"
    $mdReportPath = Join-Path $outAbs "mobile-qa-summary.md"

    $reportObj = [ordered]@{
        schema_version = 1
        generated_utc  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        host_os        = "windows"
        overall_status = if ($OverallPassed) { "PASS" } else { "FAIL" }
        elf_so_bytes   = $ElfSizeBytes
        elf_budget_bytes = $MaxSoBytes
        steps          = @($Steps)
        mobile_targets = @($TargetMatrix)
    }

    $jsonContent = $reportObj | ConvertTo-Json -Depth 6
    Write-Utf8NoBomLf -Path $jsonReportPath -Content $jsonContent

    $mdLines = [System.Collections.Generic.List[string]]::new()
    $mdLines.Add('# Mesh VPN Mobile QA Summary (`v0.2.0`)')
    $mdLines.Add("")
    $mdLines.Add("- **Generated (UTC):** $($reportObj.generated_utc)")
    $mdLines.Add("- **Host OS:** Windows")
    $mdLines.Add("- **Overall Status:** **$($reportObj.overall_status)**")
    if ($null -ne $ElfSizeBytes) {
        $mdLines.Add("- **ELF ``libmesh_mobile_ffi.so`` Size:** $ElfSizeBytes bytes (Budget ``<= $MaxSoBytes`` bytes)")
    }
    $mdLines.Add("")
    $mdLines.Add("## Pipeline Steps")
    $mdLines.Add("")
    $mdLines.Add("| Step | Status | Duration (ms) | Details |")
    $mdLines.Add("| --- | --- | ---: | --- |")
    foreach ($s in $Steps) {
        $safeDetails = ($s.details -replace "\r?\n", " ") -replace "\|", "\|"
        $mdLines.Add("| $($s.name) | **$($s.status)** | $($s.duration_ms) | $safeDetails |")
    }
    $mdLines.Add("")
    $mdLines.Add("## Mobile Target Matrix")
    $mdLines.Add("")
    $mdLines.Add('| Target | `cargo-deny` | `mesh-core` + `mesh-sys` | `mesh-mobile-ffi` | Notes |')
    $mdLines.Add("| --- | --- | --- | --- | --- |")
    foreach ($tm in $TargetMatrix) {
        $safeNotes = ($tm.notes -replace "\r?\n", " ") -replace "\|", "\|"
        $mdLines.Add("| ``$($tm.target)`` | $($tm.cargo_deny) | $($tm.core_sys_check) | $($tm.mobile_ffi_check) | $safeNotes |")
    }

    Write-Utf8NoBomLf -Path $mdReportPath -Content ($mdLines -join "`n")
    Write-Host "Reports written to: $jsonReportPath and $mdReportPath" -ForegroundColor Cyan

    Pop-Location
}

exit $ExitCode
