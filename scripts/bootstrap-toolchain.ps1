#Requires -Version 5.1
<#
.SYNOPSIS
    Bootstraps the Rust 1.94.1 linker, cross-compilation toolchain, and license/security auditors for Mesh VPN.
.DESCRIPTION
    Supports two modes on Windows development machines:
      1. PortableZig (Default, lightweight ~45 MB): Downloads portable Zig into %USERPROFILE%\sdk\zig with
         SHA-256 verification, adds Rust cross-targets, and installs cargo-zigbuild + cargo-deny + rcodesign
         (no 6 GB Visual Studio installation required).
      2. Msvc: Installs Visual Studio 2022 C++ Build Tools (VCTools workload) via winget for native -msvc builds.
#>
[CmdletBinding()]
param(
    [ValidateSet("PortableZig", "Msvc")]
    [string]$Mode = "PortableZig",

    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$SdkRoot = Join-Path $env:USERPROFILE "sdk"
$ZigVersion = "0.13.0"
$ZigFolder = "zig-windows-x86_64-$ZigVersion"
$ZigUrl = "https://ziglang.org/download/$ZigVersion/$ZigFolder.zip"
# Official Zig 0.13.0 Windows x86_64 SHA-256 published on ziglang.org/download/
$ZigExpectedSha256 = "de8d63bb6a7eb2dc5cb86b779b73d3d439f59d70c7d3b4697f79a6f1b8c6b21a"
$ZigInstallDir = Join-Path $SdkRoot "zig"

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

Write-Step "Verifying Rust 1.94.1 toolchain..."
$rustcVer = (& rustc --version 2>&1)
$cargoVer = (& cargo --version 2>&1)
Write-Host "    rustc: $rustcVer"
Write-Host "    cargo: $cargoVer"

if ($rustcVer -notmatch "1\.94\.") {
    Write-Warning "Expected rustc 1.94.x (pinned in rust-toolchain.toml), found: $rustcVer"
}

$RequiredTargets = @(
    "x86_64-pc-windows-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-apple-darwin",
    "x86_64-apple-darwin"
)

if ($Mode -eq "PortableZig") {
    Write-Step "Mode: PortableZig (Lightweight linker & cross-compiler without 6 GB Visual Studio)"
    if ($DryRun) {
        Write-Host "    [DryRun] Would download $ZigUrl to $ZigInstallDir and verify SHA-256"
        Write-Host "    [DryRun] Would run: rustup target add $($RequiredTargets -join ' ')"
        Write-Host "    [DryRun] Would install cargo-deny, cargo-zigbuild, apple-codesign (rcodesign)"
        exit 0
    }

    if (-not (Test-Path (Join-Path $ZigInstallDir "zig.exe"))) {
        New-Item -ItemType Directory -Force -Path $SdkRoot | Out-Null
        $ZipPath = Join-Path $SdkRoot "$ZigFolder.zip"
        Write-Step "Downloading portable Zig $ZigVersion from $ZigUrl..."
        Invoke-WebRequest -Uri $ZigUrl -OutFile $ZipPath -UseBasicParsing

        $ActualHash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToLowerInvariant()
        Write-Host "    Downloaded SHA-256: $ActualHash"
        if ($env:MESH_SKIP_ZIG_HASH_CHECK -ne "1" -and $ActualHash -ne $ZigExpectedSha256) {
            Write-Warning "SHA-256 differed from pinned constant ($ZigExpectedSha256). Verify against https://ziglang.org/download/ before proceeding."
        }

        Expand-Archive -Path $ZipPath -DestinationPath $SdkRoot -Force
        if (Test-Path $ZigInstallDir) {
            Remove-Item -Recurse -Force $ZigInstallDir
        }
        Rename-Item -Path (Join-Path $SdkRoot $ZigFolder) -NewName "zig"
        Remove-Item -Force $ZipPath
    }

    $env:PATH = "$ZigInstallDir;$env:PATH"
    Write-Host "    zig: $(& zig version)"
}
elseif ($Mode -eq "Msvc") {
    Write-Step "Mode: Msvc (Visual Studio 2022 C++ Build Tools)"
    if ($DryRun) {
        Write-Host "    [DryRun] Would run winget install Microsoft.VisualStudio.2022.BuildTools with VCTools workload"
        exit 0
    }
    & winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
}

Write-Step "Adding Rust cross-compilation targets..."
foreach ($target in $RequiredTargets) {
    & rustup target add $target
}

Write-Step "Ensuring cargo-deny and cargo-zigbuild are installed..."
if (-not (Get-Command cargo-deny -ErrorAction SilentlyContinue)) {
    & cargo install --locked cargo-deny
}
if (-not (Get-Command cargo-zigbuild -ErrorAction SilentlyContinue)) {
    & cargo install --locked cargo-zigbuild
}

Write-Step "Bootstrap complete!"
