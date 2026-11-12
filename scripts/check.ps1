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
    # Prepend portable Zig if installed via bootstrap-toolchain.ps1
    $PortableZig = Join-Path $env:USERPROFILE "sdk\zig"
    if (Test-Path (Join-Path $PortableZig "zig.exe")) {
        $env:PATH = "$PortableZig;$env:PATH"
    }

    Write-Host "==> [1/5] Checking Rust toolchain version..." -ForegroundColor Cyan
    $rustcOut = (& rustc --version 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "rustc not found on PATH."
    }
    Write-Host "    $rustcOut"

    Write-Host "==> [2/5] Enforcing static repository & security rules..." -ForegroundColor Cyan

    # 2a. Check for UTF-8 BOM (0xEF 0xBB 0xBF) across text files
    $TextExtensions = @(".rs", ".toml", ".md", ".ps1", ".sh", ".json", ".yml", ".yaml", ".editorconfig", ".gitattributes", ".gitignore")
    $AllFiles = Get-ChildItem -Path $RepoRoot -Recurse -File -Force | Where-Object {
        $_.FullName -notlike "*\.git\*" -and
        $_.FullName -notlike "*\target\*" -and
        $_.FullName -notlike "*\docs\04-sprint-management\*"
    }

    $BomFailures = @()
    foreach ($file in $AllFiles) {
        $ext = $file.Extension.ToLowerInvariant()
        if ($TextExtensions -contains $ext -or $TextExtensions -contains $file.Name.ToLowerInvariant()) {
            if ($file.Length -ge 3) {
                $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
                if ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
                    $BomFailures += $file.FullName
                }
            }
        }
    }
    if ($BomFailures.Count -gt 0) {
        Write-Error "UTF-8 BOM detected in files (must be UTF-8 without BOM):`n  $($BomFailures -join "`n  ")"
        exit 1
    }

    # 2b. Rust source code static invariants (when crates/ exists)
    $CratesDir = Join-Path $RepoRoot "crates"
    if (Test-Path $CratesDir) {
        $RsFiles = Get-ChildItem -Path $CratesDir -Recurse -Filter "*.rs" -File
        foreach ($rs in $RsFiles) {
            $rel = $rs.FullName.Substring($RepoRoot.Length + 1).Replace("\", "/")
            $content = Get-Content -Path $rs.FullName -Raw

            # Rule: unsafe is forbidden outside crates/mesh-sys/
            if ($rel -notlike "crates/mesh-sys/*") {
                if ($content -match "(?m)^\s*(pub\s+)?unsafe\s+(fn|trait|impl)\b|\bunsafe\s*\{") {
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
    Write-Host "    Static repository rules PASSED." -ForegroundColor Green

    $CargoToml = Join-Path $RepoRoot "Cargo.toml"
    if (-not (Test-Path $CargoToml)) {
        Write-Host "==> [SKIP] Cargo.toml workspace not yet initialized (pre-Gate-2 design phase). Static checks PASSED." -ForegroundColor Yellow
        exit 0
    }

    Write-Host "==> [3/5] Running cargo fmt --all -- --check..." -ForegroundColor Cyan
    & cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) {
        Write-Error "cargo fmt check failed. Run 'cargo fmt --all' to fix formatting."
        exit 1
    }

    Write-Host "==> [4/5] Running cargo clippy (-D warnings) and cargo test..." -ForegroundColor Cyan
    & cargo clippy --workspace --all-targets --all-features -- -D warnings
    if ($LASTEXITCODE -ne 0) {
        Write-Error "cargo clippy failed."
        exit 1
    }

    & cargo test --workspace --all-features
    if ($LASTEXITCODE -ne 0) {
        Write-Error "cargo test failed."
        exit 1
    }

    Write-Host "==> [5/5] Running cargo-deny (licenses, bans, advisories, sources)..." -ForegroundColor Cyan
    if (Get-Command cargo-deny -ErrorAction SilentlyContinue) {
        & cargo deny check advisories bans licenses sources
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
        foreach ($t in $CrossTargets) {
            Write-Host "    cargo check --workspace --target $t"
            & cargo check --workspace --target $t
            if ($LASTEXITCODE -ne 0) {
                Write-Error "Cross-check failed for target $t"
                exit 1
            }
        }
    }

    Write-Host "==> ALL CHECKS PASSED!" -ForegroundColor Green
}
finally {
    Pop-Location
}
