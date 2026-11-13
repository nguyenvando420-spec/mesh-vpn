#Requires -Version 5.1
<#
.SYNOPSIS
    Installs, upgrades, or cleanly removes the Mesh VPN Windows Service (`MeshVpnAgent`).
.DESCRIPTION
    - Verifies Administrator/UAC elevation before touching system state (`US-052 AC4`).
    - Verifies SHA-256 integrity of `wintun.dll` before installing (`US-015 AC3`, `ADR-011`).
    - Creates `C:\ProgramData\Mesh` with strict SDDL `D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)` (`SEC-01`).
    - Registers `MeshVpnAgent` (`LocalSystem`, auto-start, `sc.exe failure` restart <= 10 s).
    - `-Uninstall` removes service, firewall rule, overlay routes, adapter, and `# BEGIN mesh` hosts
      block while preserving `keys.json` unless `-Purge` is also specified (`US-052 AC2`).
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Uninstall,
    [switch]$Purge,
    [string]$SourceDir = $PSScriptRoot,
    [string]$InstallDir = $(Join-Path $env:ProgramFiles "Mesh"),
    [string]$DataDir = $(Join-Path $env:ProgramData "Mesh"),
    [string]$WintunSha256 = "",
    [string]$WintunSha256File = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ServiceName = "MeshVpnAgent"
$AdapterName = "MeshVPN"
$FirewallRuleName = "MeshVPN-Overlay-Inbound"
$AdminSddl = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)"
$InstallDirSddl = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GRGX;;;AU)"
$HostsBeginMarker = "# BEGIN mesh managed hosts (do not edit manually)"
$HostsEndMarker = "# END mesh managed hosts"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-System32Executable {
    param([Parameter(Mandatory = $true)][string]$ExeName)
    $sys32 = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
    if ([string]::IsNullOrWhiteSpace($sys32)) {
        throw "Failed to resolve Windows System32 directory."
    }
    $full = Join-Path $sys32 $ExeName
    if (-not (Test-Path -LiteralPath $full)) {
        throw "Required Windows system binary not found: $full"
    }
    return $full
}

function Set-DirectorySddl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Sddl
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm($Sddl)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Resolve-SourceArtifactPath {
    param(
        [Parameter(Mandatory = $true)][string]$PrimaryDir,
        [Parameter(Mandatory = $true)][string]$FileName
    )
    $direct = Join-Path $PrimaryDir $FileName
    if (Test-Path -LiteralPath $direct) {
        return $direct
    }
    if ($PrimaryDir -eq $PSScriptRoot -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $parentDir = Split-Path -Parent $PSScriptRoot
        if (-not [string]::IsNullOrWhiteSpace($parentDir)) {
            $parentCandidate = Join-Path $parentDir $FileName
            if (Test-Path -LiteralPath $parentCandidate) {
                return $parentCandidate
            }
        }
    }
    return $direct
}

function Resolve-ExpectedWintunSha256 {
    param(
        [string]$ExplicitHash,
        [string]$HashFilePath,
        [string]$DefaultSourceDir
    )
    $candidate = $ExplicitHash
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        $resolvedFile = $HashFilePath
        if ([string]::IsNullOrWhiteSpace($resolvedFile)) {
            $fallback = Resolve-SourceArtifactPath -PrimaryDir $DefaultSourceDir -FileName "wintun.dll.sha256"
            if (Test-Path -LiteralPath $fallback) {
                $resolvedFile = $fallback
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($resolvedFile) -and (Test-Path -LiteralPath $resolvedFile)) {
            $raw = (Get-Content -LiteralPath $resolvedFile -Raw).Trim()
            $parts = $raw -split '\s+'
            if ($parts.Length -ge 1) {
                $candidate = $parts[0]
            }
        }
    }
    $normalized = ($candidate -replace '^sha256:', '').Trim().ToLowerInvariant()
    if ($normalized -notmatch '^[0-9a-f]{64}$') {
        throw "A valid 64-character SHA-256 checksum for wintun.dll is required via -WintunSha256 or wintun.dll.sha256 (fail-closed)."
    }
    return $normalized
}

function Assert-FileSha256 {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Required binary not found: $Path"
    }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $ExpectedSha256.ToLowerInvariant()) {
        throw "SHA-256 verification failed for '$Path'. Expected $ExpectedSha256, got $actual."
    }
}

function Stop-ServiceGracefully {
    param([Parameter(Mandatory = $true)][string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        return
    }
    if ($svc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
        $deadline = (Get-Date).AddSeconds(10)
        while ((Get-Date) -lt $deadline) {
            $svc.Refresh()
            if ($svc.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
                break
            }
            Start-Sleep -Milliseconds 250
        }
    }
}

function Remove-MeshHostsBlockInPlace {
    $sys32 = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
    $hostsPath = Join-Path (Join-Path $sys32 "drivers\etc") "hosts"
    if (-not (Test-Path -LiteralPath $hostsPath)) {
        return
    }
    # Open in-place so existing NTFS ACLs (`Users` / `Dnscache` read access) remain untouched.
    $fs = [System.IO.File]::Open(
        $hostsPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::Read
    )
    try {
        $reader = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8, $false, 4096, $true)
        $content = $reader.ReadToEnd()
        $reader.Dispose()

        $lines = $content -split "`r?`n", -1
        $filtered = New-Object System.Collections.Generic.List[string]
        $insideBlock = $false
        $changed = $false
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if (
                $trimmed -eq $HostsBeginMarker -or
                $trimmed -eq "# BEGIN mesh managed hosts" -or
                $trimmed -eq "# BEGIN mesh"
            ) {
                $insideBlock = $true
                $changed = $true
                continue
            }
            if ($trimmed -eq $HostsEndMarker -or $trimmed -eq "# END mesh") {
                $insideBlock = $false
                $changed = $true
                continue
            }
            if (-not $insideBlock) {
                $filtered.Add($line)
            }
        }
        if ($changed) {
            $updated = ($filtered -join "`r`n")
            if (-not [string]::IsNullOrEmpty($updated) -and -not $updated.EndsWith("`r`n")) {
                $updated += "`r`n"
            }
            $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
            $bytes = $utf8NoBom.GetBytes($updated)
            $fs.Position = 0
            $fs.Write($bytes, 0, $bytes.Length)
            $fs.SetLength($bytes.Length)
            $fs.Flush($true)
        }
    }
    finally {
        $fs.Dispose()
    }
}

function Remove-MeshFirewallAndRoutes {
    $netsh = Get-System32Executable "netsh.exe"
    $ipconfig = Get-System32Executable "ipconfig.exe"

    # Delete strictly the MeshVPN rule without touching unrelated user/system rules (`US-053 AC3`).
    & $netsh advfirewall firewall delete rule name="$FirewallRuleName" | Out-Null

    # Remove residual Wintun adapter routes if the interface still exists.
    $adapter = Get-NetAdapter -Name $AdapterName -ErrorAction SilentlyContinue
    if ($null -ne $adapter) {
        Get-NetRoute -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue |
            Where-Object { $_.DestinationPrefix -ne "0.0.0.0/0" -and $_.DestinationPrefix -ne "::/0" } |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        Disable-NetAdapter -Name $AdapterName -Confirm:$false -ErrorAction SilentlyContinue
    }

    Remove-MeshHostsBlockInPlace
    & $ipconfig /flushdns | Out-Null
}

function Install-MeshService {
    $scExe = Get-System32Executable "sc.exe"
    $expectedHash = Resolve-ExpectedWintunSha256 `
        -ExplicitHash $WintunSha256 `
        -HashFilePath $WintunSha256File `
        -DefaultSourceDir $SourceDir

    $srcMeshd = Resolve-SourceArtifactPath -PrimaryDir $SourceDir -FileName "meshd.exe"
    $srcMesh = Resolve-SourceArtifactPath -PrimaryDir $SourceDir -FileName "mesh.exe"
    $srcWintun = Resolve-SourceArtifactPath -PrimaryDir $SourceDir -FileName "wintun.dll"

    foreach ($bin in @($srcMeshd, $srcMesh, $srcWintun)) {
        if (-not (Test-Path -LiteralPath $bin)) {
            throw "Required installer artifact not found: $bin"
        }
    }
    Assert-FileSha256 -Path $srcWintun -ExpectedSha256 $expectedHash

    if ($PSCmdlet.ShouldProcess($InstallDir, "Install Mesh VPN binaries and service")) {
        Stop-ServiceGracefully -Name $ServiceName

        Set-DirectorySddl -Path $InstallDir -Sddl $InstallDirSddl
        Set-DirectorySddl -Path $DataDir -Sddl $AdminSddl
        Set-DirectorySddl -Path (Join-Path $DataDir "logs") -Sddl $AdminSddl

        Copy-Item -LiteralPath $srcMeshd -Destination (Join-Path $InstallDir "meshd.exe") -Force
        Copy-Item -LiteralPath $srcMesh -Destination (Join-Path $InstallDir "mesh.exe") -Force
        $dstWintun = Join-Path $InstallDir "wintun.dll"
        Copy-Item -LiteralPath $srcWintun -Destination $dstWintun -Force
        Assert-FileSha256 -Path $dstWintun -ExpectedSha256 $expectedHash

        $srcLicense = Resolve-SourceArtifactPath -PrimaryDir $SourceDir -FileName "WINTUN-LICENSE.txt"
        if (Test-Path -LiteralPath $srcLicense) {
            Copy-Item -LiteralPath $srcLicense -Destination (Join-Path $InstallDir "WINTUN-LICENSE.txt") -Force
        }

        $binPath = "`"$(Join-Path $InstallDir 'meshd.exe')`" --service"
        $existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($null -eq $existingSvc) {
            & $scExe create $ServiceName binPath= $binPath start= auto obj= LocalSystem DisplayName= "Mesh VPN Agent" | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "sc.exe create $ServiceName failed with exit code $LASTEXITCODE"
            }
        }
        else {
            & $scExe config $ServiceName binPath= $binPath start= auto obj= LocalSystem | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "sc.exe config $ServiceName failed with exit code $LASTEXITCODE"
            }
        }

        & $scExe description $ServiceName "Mesh VPN encrypted overlay daemon (LocalSystem service)" | Out-Null
        # Auto-restart after crash in 5 seconds (<= 10 s SLO per US-052 AC1).
        & $scExe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/10000 | Out-Null
        & $scExe failureflag $ServiceName 1 | Out-Null

        Start-Service -Name $ServiceName
    }
}

function Uninstall-MeshService {
    $scExe = Get-System32Executable "sc.exe"

    if ($PSCmdlet.ShouldProcess($ServiceName, "Uninstall Mesh VPN service and cleanup resources")) {
        $meshCli = Join-Path $InstallDir "mesh.exe"
        if (Test-Path -LiteralPath $meshCli) {
            try {
                & $meshCli cleanup 2>$null | Out-Null
            }
            catch {
                # Best-effort daemon cleanup; explicit Windows cleanup below also runs.
            }
        }

        Stop-ServiceGracefully -Name $ServiceName
        $existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($null -ne $existingSvc) {
            & $scExe delete $ServiceName | Out-Null
        }

        Remove-MeshFirewallAndRoutes

        foreach ($file in @("meshd.exe", "mesh.exe", "wintun.dll", "WINTUN-LICENSE.txt")) {
            $target = Join-Path $InstallDir $file
            if (Test-Path -LiteralPath $target) {
                Remove-Item -LiteralPath $target -Force
            }
        }
        if ((Test-Path -LiteralPath $InstallDir) -and (@(Get-ChildItem -LiteralPath $InstallDir -Force).Count -eq 0)) {
            Remove-Item -LiteralPath $InstallDir -Force
        }

        if ($Purge) {
            if (Test-Path -LiteralPath $DataDir) {
                Remove-Item -LiteralPath $DataDir -Recurse -Force
            }
        }
        elseif (Test-Path -LiteralPath $DataDir) {
            # Preserve keys.json unless -Purge is specified (`US-052 AC2`).
            foreach ($ephemeral in @("ledger.json", "netmap-cache.json")) {
                $ephemeralPath = Join-Path $DataDir $ephemeral
                if (Test-Path -LiteralPath $ephemeralPath) {
                    Remove-Item -LiteralPath $ephemeralPath -Force
                }
            }
        }
    }
}

if (-not (Test-IsAdministrator)) {
    Write-Error "Administrator privileges (UAC elevation) are required to run install-windows.ps1."
    exit 1
}

if ($Purge -and -not $Uninstall) {
    throw "Use -Uninstall -Purge together to remove keys.json and all state directories."
}

if ($Uninstall) {
    Uninstall-MeshService
}
else {
    Install-MeshService
}
