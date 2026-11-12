#Requires -Version 5.1
<#
.SYNOPSIS
    Bootstraps the Rust 1.94.1 linker, cross-compilation toolchain, and prebuilt security auditors for Mesh VPN.
.DESCRIPTION
    Supports two modes on Windows development machines:
      1. PortableZig (Default, lightweight, no 6 GB Visual Studio required):
         - Installs host GNU toolchain '1.94.1-x86_64-pc-windows-gnu' (so proc-macros, build.rs such as ring,
           and workspace crates compile cleanly without MSVC link.exe / ml64.exe).
         - Downloads 5 official prebuilt archives into %USERPROFILE%\sdk with strict fail-closed SHA-256 verification:
           (a) MinGW-w64 GCC UCRT (winlibs 16.2.0) for x86_64-pc-windows-gnu linking & ring C/ASM compilation
           (b) Zig 0.13.0 for Linux musl and macOS cross-linking
           (c) cargo-deny 0.20.2 prebuilt binary
           (d) cargo-zigbuild v0.24.1 prebuilt binary
           (e) apple-codesign (rcodesign.exe) 0.29.0 prebuilt binary for Mach-O arm64 ad-hoc signing (ADR-011)
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
$BinDir = Join-Path $SdkRoot "bin"
$MingwDir = Join-Path $SdkRoot "mingw64"
$ZigDir = Join-Path $SdkRoot "zig"

# Official prebuilt artifacts & pinned SHA-256 digests (Fail-Closed Supply-Chain Verification — ADR-011)
$Artifacts = @(
    @{
        Name   = "MinGW-w64 GCC 16.2.0 UCRT (winlibs)"
        Url    = "https://github.com/brechtsanders/winlibs_mingw/releases/download/16.2.0posix-23.1.3-14.0.0-ucrt-r3/winlibs-x86_64-posix-seh-gcc-16.2.0-mingw-w64ucrt-14.0.0-r3.zip"
        Sha256 = "3c69305081e4a647144339a936244fcf7d3d9e558319e1ad7be2cd2886d4b6a1"
        File   = "winlibs-mingw64-16.2.0.zip"
        Check  = (Join-Path $MingwDir "bin\x86_64-w64-mingw32-gcc.exe")
    },
    @{
        Name   = "Zig 0.13.0 Windows x86_64"
        Url    = "https://ziglang.org/download/0.13.0/zig-windows-x86_64-0.13.0.zip"
        Sha256 = "d859994725ef9402381e557c60bb57497215682e355204d754ee3df75ee3c158"
        File   = "zig-windows-x86_64-0.13.0.zip"
        Check  = (Join-Path $ZigDir "zig.exe")
    },
    @{
        Name   = "cargo-deny 0.20.2 Windows x86_64"
        Url    = "https://github.com/EmbarkStudios/cargo-deny/releases/download/0.20.2/cargo-deny-0.20.2-x86_64-pc-windows-msvc.tar.gz"
        Sha256 = "975a22143262fd27476d19ee00c7af67978426e40e1dee94eed6bbade1cf87dc"
        File   = "cargo-deny-0.20.2.tar.gz"
        Check  = (Join-Path $BinDir "cargo-deny.exe")
    },
    @{
        Name   = "cargo-zigbuild v0.24.1 Windows x86_64"
        Url    = "https://github.com/rust-cross/cargo-zigbuild/releases/download/v0.24.1/cargo-zigbuild-x86_64-pc-windows-msvc.zip"
        Sha256 = "7f660482f8dada6dfcd495bfc52a4c4f0cf6b2e01ac9740811855a1de7c4f60a"
        File   = "cargo-zigbuild-v0.24.1.zip"
        Check  = (Join-Path $BinDir "cargo-zigbuild.exe")
    },
    @{
        Name   = "apple-codesign (rcodesign) 0.29.0 Windows x86_64"
        Url    = "https://github.com/indygreg/apple-platform-rs/releases/download/apple-codesign/0.29.0/apple-codesign-0.29.0-x86_64-pc-windows-msvc.zip"
        Sha256 = "54bb500e2da7a8de02fcae0f331d1cac6e6d7173b4281042ff9c528ba3159aaa"
        File   = "apple-codesign-0.29.0.zip"
        Check  = (Join-Path $BinDir "rcodesign.exe")
    }
)

$RequiredTargets = @(
    "x86_64-pc-windows-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-apple-darwin",
    "x86_64-apple-darwin"
)

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Assert-FileSha256 {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )
    if (-not (Test-Path $Path)) {
        throw "File not found for SHA-256 check: $Path"
    }
    $actual = (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    $expected = $ExpectedSha256.ToLowerInvariant()
    if ($actual -ne $expected) {
        Remove-Item -Force -ErrorAction SilentlyContinue $Path
        throw "SECURITY ERROR (Fail-Closed): SHA-256 mismatch for '$Path'. Expected '$expected', got '$actual'."
    }
    Write-Host "    [SHA-256 OK] $actual" -ForegroundColor Green
}

Write-Step "Verifying Rust 1.94.1 toolchain..."
$rustcVer = (& rustc --version 2>&1) | Out-String
$rustcVer = $rustcVer.Trim()
$cargoVer = (& cargo --version 2>&1) | Out-String
$cargoVer = $cargoVer.Trim()
Write-Host "    rustc: $rustcVer"
Write-Host "    cargo: $cargoVer"

if ($rustcVer -notmatch "^rustc 1\.94\.1\b") {
    throw "Toolchain mismatch: rust-toolchain.toml requires exactly rustc 1.94.1, but found '$rustcVer'."
}

if ($Mode -eq "PortableZig") {
    Write-Step "Mode: PortableZig (Prebuilt MinGW-w64 + Zig + cargo-deny + cargo-zigbuild + rcodesign)"
    if ($DryRun) {
        Write-Host "    [DryRun] Would run: rustup toolchain install 1.94.1-x86_64-pc-windows-gnu --component rustfmt,clippy"
        Write-Host "    [DryRun] Would run: rustup target add --toolchain 1.94.1-x86_64-pc-windows-gnu $($RequiredTargets -join ' ')"
        foreach ($art in $Artifacts) {
            Write-Host "    [DryRun] Would download $($art.Name):"
            Write-Host "             URL    : $($art.Url)"
            Write-Host "             SHA256 : $($art.Sha256)"
            Write-Host "             Target : $($art.Check)"
        }
        exit 0
    }

    New-Item -ItemType Directory -Force -Path $SdkRoot | Out-Null
    New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

    Write-Step "Installing Rust GNU host toolchain (1.94.1-x86_64-pc-windows-gnu) for link.exe-free proc-macro & build.rs..."
    & rustup toolchain install 1.94.1-x86_64-pc-windows-gnu --component rustfmt,clippy
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install toolchain 1.94.1-x86_64-pc-windows-gnu."
    }

    foreach ($target in $RequiredTargets) {
        & rustup target add --toolchain 1.94.1-x86_64-pc-windows-gnu $target
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to add target $target to toolchain 1.94.1-x86_64-pc-windows-gnu."
        }
        & rustup target add $target
    }

    # 1. MinGW-w64 GCC UCRT
    $mingwArt = $Artifacts[0]
    if (-not (Test-Path $mingwArt.Check)) {
        $archivePath = Join-Path $SdkRoot $mingwArt.File
        Write-Step "Downloading $($mingwArt.Name)..."
        Invoke-WebRequest -Uri $mingwArt.Url -OutFile $archivePath -UseBasicParsing
        Assert-FileSha256 -Path $archivePath -ExpectedSha256 $mingwArt.Sha256
        Expand-Archive -Path $archivePath -DestinationPath $SdkRoot -Force
        Remove-Item -Force $archivePath
    }

    # 2. Zig 0.13.0
    $zigArt = $Artifacts[1]
    if (-not (Test-Path $zigArt.Check)) {
        $archivePath = Join-Path $SdkRoot $zigArt.File
        Write-Step "Downloading $($zigArt.Name)..."
        Invoke-WebRequest -Uri $zigArt.Url -OutFile $archivePath -UseBasicParsing
        Assert-FileSha256 -Path $archivePath -ExpectedSha256 $zigArt.Sha256
        Expand-Archive -Path $archivePath -DestinationPath $SdkRoot -Force
        if (Test-Path $ZigDir) {
            Remove-Item -Recurse -Force $ZigDir
        }
        Rename-Item -Path (Join-Path $SdkRoot "zig-windows-x86_64-0.13.0") -NewName "zig"
        Remove-Item -Force $archivePath
    }

    # 3. cargo-deny 0.20.2 (.tar.gz)
    $denyArt = $Artifacts[2]
    if (-not (Test-Path $denyArt.Check)) {
        $archivePath = Join-Path $SdkRoot $denyArt.File
        $extractTmp = Join-Path $SdkRoot "tmp-cargo-deny"
        Write-Step "Downloading $($denyArt.Name)..."
        Invoke-WebRequest -Uri $denyArt.Url -OutFile $archivePath -UseBasicParsing
        Assert-FileSha256 -Path $archivePath -ExpectedSha256 $denyArt.Sha256
        New-Item -ItemType Directory -Force -Path $extractTmp | Out-Null
        & "$env:SystemRoot\System32\tar.exe" -xzf $archivePath -C $extractTmp
        if ($LASTEXITCODE -ne 0) {
            throw "tar.exe failed to extract $archivePath"
        }
        $denyExe = Get-ChildItem -Path $extractTmp -Recurse -Filter "cargo-deny.exe" | Select-Object -First 1
        if (-not $denyExe) {
            throw "cargo-deny.exe not found inside archive"
        }
        Copy-Item -Force $denyExe.FullName $denyArt.Check
        Remove-Item -Recurse -Force $extractTmp
        Remove-Item -Force $archivePath
    }

    # 4. cargo-zigbuild v0.24.1 (.zip)
    $zigbuildArt = $Artifacts[3]
    if (-not (Test-Path $zigbuildArt.Check)) {
        $archivePath = Join-Path $SdkRoot $zigbuildArt.File
        $extractTmp = Join-Path $SdkRoot "tmp-cargo-zigbuild"
        Write-Step "Downloading $($zigbuildArt.Name)..."
        Invoke-WebRequest -Uri $zigbuildArt.Url -OutFile $archivePath -UseBasicParsing
        Assert-FileSha256 -Path $archivePath -ExpectedSha256 $zigbuildArt.Sha256
        Expand-Archive -Path $archivePath -DestinationPath $extractTmp -Force
        $zigbuildExe = Get-ChildItem -Path $extractTmp -Recurse -Filter "cargo-zigbuild.exe" | Select-Object -First 1
        if (-not $zigbuildExe) {
            throw "cargo-zigbuild.exe not found inside archive"
        }
        Copy-Item -Force $zigbuildExe.FullName $zigbuildArt.Check
        Remove-Item -Recurse -Force $extractTmp
        Remove-Item -Force $archivePath
    }

    # 5. apple-codesign (rcodesign.exe) 0.29.0 (.zip)
    $rcodesignArt = $Artifacts[4]
    if (-not (Test-Path $rcodesignArt.Check)) {
        $archivePath = Join-Path $SdkRoot $rcodesignArt.File
        $extractTmp = Join-Path $SdkRoot "tmp-rcodesign"
        Write-Step "Downloading $($rcodesignArt.Name)..."
        Invoke-WebRequest -Uri $rcodesignArt.Url -OutFile $archivePath -UseBasicParsing
        Assert-FileSha256 -Path $archivePath -ExpectedSha256 $rcodesignArt.Sha256
        Expand-Archive -Path $archivePath -DestinationPath $extractTmp -Force
        $rcodesignExe = Get-ChildItem -Path $extractTmp -Recurse -Filter "rcodesign.exe" | Select-Object -First 1
        if (-not $rcodesignExe) {
            throw "rcodesign.exe not found inside archive"
        }
        Copy-Item -Force $rcodesignExe.FullName $rcodesignArt.Check
        Remove-Item -Recurse -Force $extractTmp
        Remove-Item -Force $archivePath
    }

    $env:PATH = "$MingwDir\bin;$ZigDir;$BinDir;$env:PATH"
    Write-Host "    gcc           : $((& x86_64-w64-mingw32-gcc --version | Select-Object -First 1))"
    Write-Host "    zig           : $(& zig version)"
    Write-Host "    cargo-deny    : $(& cargo-deny --version)"
    Write-Host "    cargo-zigbuild: $(& cargo-zigbuild --version)"
    Write-Host "    rcodesign     : $(& rcodesign --version)"
}
elseif ($Mode -eq "Msvc") {
    Write-Step "Mode: Msvc (Visual Studio 2022 C++ Build Tools)"
    if ($DryRun) {
        Write-Host "    [DryRun] Would run winget install Microsoft.VisualStudio.2022.BuildTools with VCTools workload"
        Write-Host "    [DryRun] Would download prebuilt cargo-deny, cargo-zigbuild, rcodesign and verify SHA-256"
        exit 0
    }
    & winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
    foreach ($target in $RequiredTargets) {
        & rustup target add $target
    }
}

Write-Step "Bootstrap complete!"
