#Requires -Version 5.1
<#
.SYNOPSIS
    Standard Check Command for Mesh VPN (Rust 1.94.1) on Windows.
.DESCRIPTION
    Executes static repository rules (no UTF-8 BOM, no unsafe outside mesh-sys, no unauthorized
    expose_secret(), no hardcoded ports 443/3478 outside mesh-core), followed by:
      - cargo fmt --all -- --check
      - cargo clippy --workspace --all-targets --all-features -- -D warnings
      - cargo test --workspace --all-features
      - cargo deny check advisories bans licenses sources
    Automatically uses +1.94.1-x86_64-pc-windows-gnu when MSVC link.exe is absent.
#>
[CmdletBinding()]
param(
    [switch]$Cross
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $RepoRoot

try {
    # Prepend portable SDK directories installed via scripts/bootstrap-toolchain.ps1
    $SdkRoot = Join-Path $env:USERPROFILE "sdk"
    $SdkMingwBin = Join-Path $SdkRoot "mingw64\bin"
    $SdkZig = Join-Path $SdkRoot "zig"
    $SdkBin = Join-Path $SdkRoot "bin"

    foreach ($dir in @($SdkBin, $SdkZig, $SdkMingwBin)) {
        if (Test-Path $dir) {
            $env:PATH = "$dir;$env:PATH"
        }
    }

    Write-Host "==> [1/5] Checking Rust toolchain version (pinned 1.94.1)..." -ForegroundColor Cyan
    $rustcOut = (& rustc --version 2>&1) | Out-String
    $rustcOut = $rustcOut.Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "rustc not found on PATH."
    }
    if ($rustcOut -notmatch "^rustc 1\.94\.1\b") {
        throw "Rust compiler version mismatch: expected 'rustc 1.94.1', got '$rustcOut'."
    }
    Write-Host "    $rustcOut"

    Write-Host "==> [2/5] Enforcing static repository & security rules..." -ForegroundColor Cyan

    # 2a. Check for UTF-8 BOM (0xEF 0xBB 0xBF) and LF line endings across text files
    $TextExtensions = @(".rs", ".toml", ".md", ".ps1", ".sh", ".json", ".yml", ".yaml", ".plist", ".service", ".kt", ".kts", ".swift", ".xml", ".pbxproj", ".editorconfig", ".gitattributes", ".gitignore")
    $AllFiles = Get-ChildItem -Path $RepoRoot -Recurse -File -Force | Where-Object {
        $_.FullName -notlike "*\.git\*" -and
        $_.FullName -notlike "*\target\*" -and
        $_.FullName -notlike "*\lab\.tmp\*" -and
        $_.FullName -notlike "*\mobile\android\.gradle\*" -and
        $_.FullName -notlike "*\mobile\android\build\*" -and
        $_.FullName -notlike "*\mobile\android\*\build\*" -and
        $_.FullName -notlike "*\mobile\ios\.build\*" -and
        $_.FullName -notlike "*\mobile\ios\DerivedData\*"
    }

    $BomFailures = @()
    $CrlfFailures = @()
    foreach ($file in $AllFiles) {
        $ext = $file.Extension.ToLowerInvariant()
        if ($TextExtensions -contains $ext -or $TextExtensions -contains $file.Name.ToLowerInvariant()) {
            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
            if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
                $BomFailures += $file.FullName
            }
            if ($ext -ne ".ps1" -and $ext -ne ".bat" -and $ext -ne ".cmd") {
                if ([System.Array]::IndexOf($bytes, [byte]0x0D) -ge 0) {
                    $CrlfFailures += $file.FullName
                }
            }
        }
    }
    if ($BomFailures.Count -gt 0) {
        Write-Error "UTF-8 BOM detected in files (must be UTF-8 without BOM):`n  $($BomFailures -join "`n  ")"
        exit 1
    }
    if ($CrlfFailures.Count -gt 0) {
        Write-Error "CRLF/CR line endings detected in files (must be LF):`n  $($CrlfFailures -join "`n  ")"
        exit 1
    }

    # 2b. Rust source code static invariants (crates/ and tools/)
    $RustScanDirs = @("crates", "tools") | ForEach-Object { Join-Path $RepoRoot $_ } | Where-Object { Test-Path $_ }
    if ($RustScanDirs.Count -gt 0) {
        $RsFiles = Get-ChildItem -Path $RustScanDirs -Recurse -Filter "*.rs" -File
        foreach ($rs in $RsFiles) {
            $rel = $rs.FullName.Substring($RepoRoot.Length + 1).Replace("\", "/")
            $content = Get-Content -Path $rs.FullName -Raw

            # Rule: unsafe is forbidden outside crates/mesh-sys/ (including crates/mesh-mobile-ffi/ and tools/)
            if ($rel -notlike "crates/mesh-sys/*") {
                if ($content -match "(?m)^\s*(pub(\([^)]*\))?\s+)?unsafe\s+(fn|trait|impl|extern)\b|\bunsafe\s*\{|#\[unsafe\s*\(") {
                    Write-Error "Forbidden 'unsafe' usage outside crates/mesh-sys/: $rel"
                    exit 1
                }
            }

            # Rule: .expose_secret() is restricted to mesh-crypto, mesh-datapath, mesh-net, and mesh CLI
            if ($rel -notlike "crates/mesh-crypto/*" -and
                $rel -notlike "crates/mesh-datapath/*" -and
                $rel -notlike "crates/mesh-net/*" -and
                $rel -notlike "crates/mesh/*") {
                if ($content -match "\.expose_secret\s*\(") {
                    Write-Error "Forbidden '.expose_secret()' call outside allowlisted crates (SEC-01): $rel"
                    exit 1
                }
            }

            # Rule: GNFR-11 no hardcoded port 443/3478 in non-test code outside mesh-core
            if ($rel -notlike "crates/mesh-core/*" -and $rel -notlike "*/tests/*") {
                $nonTestPart = ($content -split "#\[cfg\(test\)\]")[0]
                if ($nonTestPart -match ":(443|3478)\b") {
                    Write-Error "Hardcoded default port ':443' or ':3478' outside crates/mesh-core (GNFR-11): $rel"
                    exit 1
                }
            }
        }
    }

    # 2c. Mobile source & config hygiene (when mobile/ exists)
    $MobileDir = Join-Path $RepoRoot "mobile"
    if (Test-Path $MobileDir) {
        $ForbiddenMobileExts = @(".jks", ".keystore", ".p12", ".mobileprovision", ".apk", ".aab", ".ipa")
        $MobileFiles = Get-ChildItem -Path $MobileDir -Recurse -File -Force | Where-Object {
            $_.FullName -notlike "*\.gradle\*" -and
            $_.FullName -notlike "*\build\*" -and
            $_.FullName -notlike "*\.build\*" -and
            $_.FullName -notlike "*\DerivedData\*"
        }
        foreach ($mf in $MobileFiles) {
            $rel = $mf.FullName.Substring($RepoRoot.Length + 1).Replace("\", "/")
            $ext = $mf.Extension.ToLowerInvariant()
            if ($ForbiddenMobileExts -contains $ext) {
                Write-Error "Forbidden mobile binary/signing artifact in repository: $rel"
                exit 1
            }
            if ($ext -eq ".plist") {
                $plistRaw = Get-Content -Path $mf.FullName -Raw
                if ($plistRaw -match "NSAllowsArbitraryLoads") {
                    Write-Error "Forbidden ATS bypass 'NSAllowsArbitraryLoads' in plist: $rel"
                    exit 1
                }
            }
        }
    }
    Write-Host "    Static repository rules PASSED." -ForegroundColor Green

    $CargoToml = Join-Path $RepoRoot "Cargo.toml"
    if (-not (Test-Path $CargoToml)) {
        Write-Host "==> [SKIP] Cargo.toml workspace not yet initialized (pre-Gate-2 design phase). Static checks PASSED." -ForegroundColor Yellow
        exit 0
    }

    # Detect Windows linker: if MSVC link.exe is absent, switch to +1.94.1-x86_64-pc-windows-gnu + MinGW-w64
    $CargoToolchainArgs = @()
    $CargoTargetArgs = @()
    if (-not (Get-Command link.exe -ErrorAction SilentlyContinue)) {
        if (-not (Get-Command x86_64-w64-mingw32-gcc.exe -ErrorAction SilentlyContinue)) {
            throw "Neither MSVC 'link.exe' nor MinGW 'x86_64-w64-mingw32-gcc.exe' was found on PATH. Run 'powershell -ExecutionPolicy Bypass -File scripts/bootstrap-toolchain.ps1' first."
        }
        $toolchains = (& rustup toolchain list 2>&1) | Out-String
        if ($toolchains -match "1\.94\.1-x86_64-pc-windows-gnu") {
            $CargoToolchainArgs = @("+1.94.1-x86_64-pc-windows-gnu")
            Write-Host "    [Linker] MSVC link.exe not found; using host toolchain +1.94.1-x86_64-pc-windows-gnu (MinGW-w64 UCRT)" -ForegroundColor Yellow
        }
        else {
            $CargoTargetArgs = @("--target", "x86_64-pc-windows-gnu")
            Write-Host "    [Linker] MSVC link.exe not found; using --target x86_64-pc-windows-gnu" -ForegroundColor Yellow
        }
    }

    Write-Host "==> [3/5] Running cargo fmt --all -- --check..." -ForegroundColor Cyan
    & cargo @CargoToolchainArgs fmt --all -- --check
    if ($LASTEXITCODE -ne 0) {
        Write-Error "cargo fmt check failed. Run 'cargo fmt --all' to fix formatting."
        exit 1
    }

    Write-Host "==> [4/5] Running cargo clippy (-D warnings) and cargo test..." -ForegroundColor Cyan
    & cargo @CargoToolchainArgs clippy --workspace --all-targets --all-features @CargoTargetArgs -- -D warnings
    if ($LASTEXITCODE -ne 0) {
        Write-Error "cargo clippy failed."
        exit 1
    }

    & cargo @CargoToolchainArgs test --workspace --all-features @CargoTargetArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Error "cargo test failed."
        exit 1
    }

    Write-Host "==> [5/5] Running cargo-deny (licenses, bans, advisories, sources)..." -ForegroundColor Cyan
    if (Get-Command cargo-deny -ErrorAction SilentlyContinue) {
        & cargo-deny check advisories bans licenses sources
        if ($LASTEXITCODE -ne 0) {
            Write-Error "cargo deny check failed."
            exit 1
        }
    }
    else {
        Write-Error "cargo-deny is not installed. Run 'scripts/bootstrap-toolchain.ps1' before running workspace checks."
        exit 1
    }

    if ($Cross) {
        Write-Host "==> [Cross] Checking cross-compilation targets..." -ForegroundColor Cyan
        $CrossTargets = @("x86_64-unknown-linux-musl", "aarch64-apple-darwin", "x86_64-apple-darwin")
        $hasZigbuild = [bool](Get-Command cargo-zigbuild -ErrorAction SilentlyContinue)
        $hasZig = [bool](Get-Command zig -ErrorAction SilentlyContinue)
        $hasAppleSdk = (($null -ne $env:SDKROOT) -and ($env:SDKROOT.Trim().Length -gt 0) -and (Test-Path $env:SDKROOT)) -or
                       [bool](Get-Command xcrun -ErrorAction SilentlyContinue)

        # Prepare temporary zig cc / zig ar shims in $env:TEMP so ring's cc-rs build.rs compiles cleanly
        # for cross-target clippy --all-targets --all-features without requiring xcrun or musl-gcc.
        if ($hasZig -and $hasZigbuild) {
            $zigExePath = (Get-Command zig -ErrorAction Stop).Source
            $zigVerStr = ((& $zigExePath version) | Out-String).Trim()
            $zigbuildExePath = (Get-Command cargo-zigbuild -ErrorAction Stop).Source

            $ShimDir = Join-Path $env:TEMP "mesh-zigcc-shims"
            New-Item -ItemType Directory -Force -Path $ShimDir | Out-Null
            $utf8NoBom = New-Object System.Text.UTF8Encoding($false)

            $muslCc = Join-Path $ShimDir "zigcc-x86_64-unknown-linux-musl.bat"
            $aarchDarwinCc = Join-Path $ShimDir "zigcc-aarch64-apple-darwin.bat"
            $x86DarwinCc = Join-Path $ShimDir "zigcc-x86_64-apple-darwin.bat"
            $zigAr = Join-Path $ShimDir "zig-ar.bat"

            $shimHeader = "@echo off`r`nsetlocal DisableDelayedExpansion`r`nset CARGO_ZIGBUILD_ZIG_VERSION=$zigVerStr`r`nset `"CARGO_ZIGBUILD_ZIG_COMMAND=$zigExePath`"`r`n"
            [System.IO.File]::WriteAllText($muslCc, "$shimHeader`"$zigbuildExePath`" zig cc -- -g -fno-sanitize=all -target x86_64-linux-musl %*`r`n", $utf8NoBom)
            [System.IO.File]::WriteAllText($aarchDarwinCc, "$shimHeader`"$zigbuildExePath`" zig cc -- -g -fno-sanitize=all -target aarch64-macos-none %*`r`n", $utf8NoBom)
            [System.IO.File]::WriteAllText($x86DarwinCc, "$shimHeader`"$zigbuildExePath`" zig cc -- -g -fno-sanitize=all -target x86_64-macos-none %*`r`n", $utf8NoBom)
            [System.IO.File]::WriteAllText($zigAr, "@echo off`r`n`"$zigExePath`" ar %*`r`n", $utf8NoBom)

            $env:CC_x86_64_unknown_linux_musl = $muslCc
            $env:AR_x86_64_unknown_linux_musl = $zigAr
            $env:CC_aarch64_apple_darwin = $aarchDarwinCc
            $env:AR_aarch64_apple_darwin = $zigAr
            $env:CC_x86_64_apple_darwin = $x86DarwinCc
            $env:AR_x86_64_apple_darwin = $zigAr
        }

        foreach ($t in $CrossTargets) {
            if ($t -eq "x86_64-unknown-linux-musl") {
                if ($hasZigbuild) {
                    Write-Host "    cargo zigbuild --workspace --exclude mesh-mobile-ffi --exclude mesh-uniffi-bindgen --target $t"
                    & cargo @CargoToolchainArgs zigbuild --workspace --exclude mesh-mobile-ffi --exclude mesh-uniffi-bindgen --target $t
                    if ($LASTEXITCODE -ne 0) {
                        Write-Error "Cross-link (cargo zigbuild) failed for target $t"
                        exit 1
                    }
                }
                Write-Host "    cargo clippy --workspace --exclude mesh-mobile-ffi --exclude mesh-uniffi-bindgen --all-targets --all-features --target $t -- -D warnings"
                & cargo @CargoToolchainArgs clippy --workspace --exclude mesh-mobile-ffi --exclude mesh-uniffi-bindgen --all-targets --all-features --target $t -- -D warnings
                if ($LASTEXITCODE -ne 0) {
                    Write-Error "Cross-clippy failed for target $t"
                    exit 1
                }
            }
            elseif ($t -like "*-apple-darwin") {
                if ($hasZigbuild -and $hasAppleSdk) {
                    Write-Host "    cargo zigbuild --workspace --exclude mesh-mobile-ffi --exclude mesh-uniffi-bindgen --target $t"
                    & cargo @CargoToolchainArgs zigbuild --workspace --exclude mesh-mobile-ffi --exclude mesh-uniffi-bindgen --target $t
                    if ($LASTEXITCODE -ne 0) {
                        Write-Error "Cross-link (cargo zigbuild) failed for target $t"
                        exit 1
                    }
                }
                else {
                    Write-Host "    [Cross] SDKROOT not set for $t; running full clippy --all-targets --all-features (-D warnings) cross-check" -ForegroundColor Yellow
                }
                Write-Host "    cargo clippy --workspace --exclude mesh-mobile-ffi --exclude mesh-uniffi-bindgen --all-targets --all-features --target $t -- -D warnings"
                & cargo @CargoToolchainArgs clippy --workspace --exclude mesh-mobile-ffi --exclude mesh-uniffi-bindgen --all-targets --all-features --target $t -- -D warnings
                if ($LASTEXITCODE -ne 0) {
                    Write-Error "Cross-clippy failed for target $t"
                    exit 1
                }
            }
        }
    }

    Write-Host "==> ALL CHECKS PASSED!" -ForegroundColor Green
}
finally {
    $EmptyObj = Join-Path $RepoRoot ".intentionally-empty-file.o"
    if (Test-Path $EmptyObj) {
        Remove-Item -Force -ErrorAction SilentlyContinue $EmptyObj
    }
    Pop-Location
}
