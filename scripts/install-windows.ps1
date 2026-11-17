#Requires -Version 5.1
<#
.SYNOPSIS
    Installs, upgrades, or cleanly removes Mesh VPN (`MeshVPN.exe`, `mesh.exe`, `meshd.exe`,
    `mesh-server.exe`, `wintun.dll`, and the `MeshVpnAgent` Windows Service).
.DESCRIPTION
    - Verifies Administrator/UAC elevation before touching system state (`US-052 AC4`, `US-115`).
    - Signals `Local\MeshVpnGuiShutdownEvent` and waits up to 3,000 ms for `MeshVPN.exe` to exit
      gracefully before upgrading or uninstalling binaries (`ERROR_SHARING_VIOLATION` fix, `ADR-026`).
    - Verifies SHA-256 integrity of `wintun.dll` before and after copying (`US-015 AC3`, `ADR-011`).
    - Creates `C:\ProgramData\Mesh` with strict SDDL `D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)` (`SEC-01`).
    - Registers `MeshVpnAgent` (`LocalSystem`, auto-start, `sc.exe failure` restart <= 10 s) and
      installs Start Menu + Desktop shortcuts for `MeshVPN.exe`.
    - `-Uninstall` gracefully stops `MeshVPN.exe`, runs `mesh.exe cleanup`, removes `MeshVpnAgent`,
      firewall rules, overlay routes, adapter, `# BEGIN mesh` hosts block, `HKCU\...\Run\MeshVPN`,
      user shortcuts, and all bundle files while preserving `keys.json` and `bootstrap.toml`
      unless `-PurgeData` (alias `-Purge`) is specified (`US-115`, `US-052 AC2`).
    - `-DryRun` exercises validation and logs planned operations with zero system mutation.
    - Multi-account note: cleaning `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MeshVPN`
      and per-user `.lnk` shortcuts applies to the active Windows user profile context.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Uninstall,
    [Alias("Purge")]
    [switch]$PurgeData,
    [switch]$DryRun,
    [switch]$SkipShortcuts,
    [string]$SourceDir = "",
    [string]$InstallDir = $(Join-Path $env:ProgramFiles "Mesh"),
    [string]$DataDir = $(Join-Path $env:ProgramData "Mesh"),
    [string]$WintunSha256 = "",
    [string]$WintunSha256File = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($SourceDir)) {
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $SourceDir = $PSScriptRoot
    }
    else {
        $SourceDir = (Get-Location).Path
    }
}

$ServiceName = "MeshVpnAgent"
$AdapterName = "MeshVPN"
$FirewallRuleName = "MeshVPN-Overlay-Inbound"
$GuiProcessName = "MeshVPN"
$GuiShutdownEventName = "Local\MeshVpnGuiShutdownEvent"
$GuiShutdownTimeoutMs = 3000
$AutostartRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$AutostartValueName = "MeshVPN"
$AdminSddl = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)"
$InstallDirSddl = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GRGX;;;AU)"
$HostsBeginMarker = "# BEGIN mesh managed hosts (do not edit manually)"
$HostsEndMarker = "# END mesh managed hosts"
$BundleCleanupFiles = @(
    "MeshVPN.exe",
    "MeshVPN.exe.new",
    "meshd.exe",
    "mesh.exe",
    "mesh-server.exe",
    "wintun.dll",
    "wintun.dll.sha256",
    "WINTUN-LICENSE.txt",
    "README-WINTUN.md",
    "LICENSE",
    "NOTICE",
    "README.txt"
)

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
        [string]$DefaultSourceDir,
        [switch]$AllowMissingInDryRun
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
    if ([string]::IsNullOrWhiteSpace($candidate) -and $AllowMissingInDryRun) {
        return ""
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

function Stop-MeshGuiGracefully {
    param([switch]$DryRunMode)

    $running = @(Get-Process -Name $GuiProcessName -ErrorAction SilentlyContinue)
    if ($DryRunMode) {
        Write-Output "[dry-run] Would signal '$GuiShutdownEventName' and wait up to $GuiShutdownTimeoutMs ms for '$GuiProcessName.exe' graceful exit (currently running: $($running.Count); Stop-Process fallback only after timeout)."
        return
    }

    $waitHandle = $null
    try {
        $waitHandle = [System.Threading.EventWaitHandle]::OpenExisting($GuiShutdownEventName)
        [void]$waitHandle.Set()
    }
    catch [System.Threading.WaitHandleCannotBeOpenedException] {
        # No active GUI instance is listening on the session shutdown event.
    }
    catch {
        Write-Verbose "Unable to signal '$GuiShutdownEventName': $($_.Exception.Message)"
    }
    finally {
        if ($null -ne $waitHandle) {
            $waitHandle.Dispose()
        }
    }

    if ($running.Count -eq 0) {
        return
    }

    $deadline = (Get-Date).AddMilliseconds($GuiShutdownTimeoutMs)
    while ((Get-Date) -lt $deadline) {
        $remaining = @(Get-Process -Name $GuiProcessName -ErrorAction SilentlyContinue)
        if ($remaining.Count -eq 0) {
            return
        }
        Start-Sleep -Milliseconds 100
    }

    $stillRunning = @(Get-Process -Name $GuiProcessName -ErrorAction SilentlyContinue)
    if ($stillRunning.Count -gt 0) {
        Write-Warning "$GuiProcessName.exe did not exit within $GuiShutdownTimeoutMs ms after shutdown event; forcing termination."
        $stillRunning | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 300
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

function Install-MeshShortcuts {
    param(
        [Parameter(Mandatory = $true)][string]$ExePath,
        [Parameter(Mandatory = $true)][string]$WorkingDir
    )
    $desktopDir = [Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)
    $programsDir = [Environment]::GetFolderPath([Environment+SpecialFolder]::Programs)
    $targets = @()
    if (-not [string]::IsNullOrWhiteSpace($desktopDir)) {
        $targets += (Join-Path $desktopDir "Mesh VPN.lnk")
    }
    if (-not [string]::IsNullOrWhiteSpace($programsDir)) {
        $menuDir = Join-Path $programsDir "Mesh VPN"
        if (-not (Test-Path -LiteralPath $menuDir)) {
            New-Item -ItemType Directory -Path $menuDir -Force | Out-Null
        }
        $targets += (Join-Path $menuDir "Mesh VPN.lnk")
    }
    if ($targets.Count -eq 0) {
        return
    }

    $shell = $null
    try {
        $shell = New-Object -ComObject WScript.Shell
        foreach ($lnkPath in $targets) {
            $shortcut = $null
            try {
                $shortcut = $shell.CreateShortcut($lnkPath)
                $shortcut.TargetPath = $ExePath
                $shortcut.WorkingDirectory = $WorkingDir
                $shortcut.Description = "Mesh VPN Desktop Client"
                $shortcut.Save()
            }
            finally {
                if ($null -ne $shortcut) {
                    [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut)
                }
            }
        }
    }
    finally {
        if ($null -ne $shell) {
            [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
        }
    }
}

function Remove-UserAutostartAndShortcuts {
    param([switch]$DryRunMode)

    if ($DryRunMode) {
        Write-Output "[dry-run] Would remove '$AutostartRegPath\$AutostartValueName' and user Start Menu / Desktop '.lnk' shortcuts."
        return
    }

    if (Test-Path -LiteralPath $AutostartRegPath) {
        try {
            $existing = Get-ItemProperty -LiteralPath $AutostartRegPath -Name $AutostartValueName -ErrorAction SilentlyContinue
            if ($null -ne $existing) {
                Remove-ItemProperty -LiteralPath $AutostartRegPath -Name $AutostartValueName -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Verbose "Unable to clear autostart registry value: $($_.Exception.Message)"
        }
    }

    $folderCandidates = @(
        [Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory),
        [Environment]::GetFolderPath([Environment+SpecialFolder]::Programs),
        [Environment]::GetFolderPath([Environment+SpecialFolder]::StartMenu)
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

    foreach ($dir in $folderCandidates) {
        foreach ($lnk in @("Mesh VPN.lnk", "MeshVPN.lnk")) {
            $candidate = Join-Path $dir $lnk
            if (Test-Path -LiteralPath $candidate) {
                Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
            }
        }
        $subdir = Join-Path $dir "Mesh VPN"
        if (Test-Path -LiteralPath $subdir) {
            foreach ($lnk in @("Mesh VPN.lnk", "MeshVPN.lnk")) {
                $candidate = Join-Path $subdir $lnk
                if (Test-Path -LiteralPath $candidate) {
                    Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
                }
            }
            if (@(Get-ChildItem -LiteralPath $subdir -Force -ErrorAction SilentlyContinue).Count -eq 0) {
                Remove-Item -LiteralPath $subdir -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Install-MeshService {
    $scExe = Get-System32Executable "sc.exe"
    $expectedHash = Resolve-ExpectedWintunSha256 `
        -ExplicitHash $WintunSha256 `
        -HashFilePath $WintunSha256File `
        -DefaultSourceDir $SourceDir `
        -AllowMissingInDryRun:$DryRun

    $srcGui = Resolve-SourceArtifactPath -PrimaryDir $SourceDir -FileName "MeshVPN.exe"
    $srcMeshd = Resolve-SourceArtifactPath -PrimaryDir $SourceDir -FileName "meshd.exe"
    $srcMesh = Resolve-SourceArtifactPath -PrimaryDir $SourceDir -FileName "mesh.exe"
    $srcServer = Resolve-SourceArtifactPath -PrimaryDir $SourceDir -FileName "mesh-server.exe"
    $srcWintun = Resolve-SourceArtifactPath -PrimaryDir $SourceDir -FileName "wintun.dll"

    if ($DryRun) {
        Stop-MeshGuiGracefully -DryRunMode
        Write-Output "[dry-run] Source directory: $SourceDir"
        Write-Output "[dry-run] Install directory: $InstallDir (SDDL $InstallDirSddl)"
        Write-Output "[dry-run] Data directory: $DataDir (SDDL $AdminSddl; preserves existing keys.json and bootstrap.toml)"
        if ([string]::IsNullOrWhiteSpace($expectedHash)) {
            Write-Output "[dry-run] Would verify wintun.dll SHA-256 via -WintunSha256 or wintun.dll.sha256"
        }
        else {
            Write-Output "[dry-run] Expected wintun.dll SHA-256: $expectedHash"
        }
        foreach ($pair in @(
            @("MeshVPN.exe", $srcGui),
            @("meshd.exe", $srcMeshd),
            @("mesh.exe", $srcMesh),
            @("mesh-server.exe (optional)", $srcServer),
            @("wintun.dll", $srcWintun)
        )) {
            $status = if (Test-Path -LiteralPath $pair[1]) { "found" } else { "not staged in source dir" }
            Write-Output "[dry-run] Would install $($pair[0]) -> $(Join-Path $InstallDir ($pair[0] -replace ' \(optional\)$', '')) [$status]"
        }
        Write-Output "[dry-run] Would register/start Windows Service '$ServiceName' -> `"$(Join-Path $InstallDir 'meshd.exe')`" --service"
        if (-not $SkipShortcuts) {
            Write-Output "[dry-run] Would create Desktop and Start Menu shortcuts ('Mesh VPN.lnk') for $(Join-Path $InstallDir 'MeshVPN.exe')"
        }
        return
    }

    foreach ($bin in @($srcGui, $srcMeshd, $srcMesh, $srcWintun)) {
        if (-not (Test-Path -LiteralPath $bin)) {
            throw "Required installer artifact not found: $bin"
        }
    }
    Assert-FileSha256 -Path $srcWintun -ExpectedSha256 $expectedHash

    if ($PSCmdlet.ShouldProcess($InstallDir, "Install Mesh VPN binaries, shortcuts, and service")) {
        Stop-MeshGuiGracefully
        Stop-ServiceGracefully -Name $ServiceName

        Set-DirectorySddl -Path $InstallDir -Sddl $InstallDirSddl
        Set-DirectorySddl -Path $DataDir -Sddl $AdminSddl
        Set-DirectorySddl -Path (Join-Path $DataDir "logs") -Sddl $AdminSddl

        $dstGui = Join-Path $InstallDir "MeshVPN.exe"
        Copy-Item -LiteralPath $srcGui -Destination $dstGui -Force
        Copy-Item -LiteralPath $srcMeshd -Destination (Join-Path $InstallDir "meshd.exe") -Force
        Copy-Item -LiteralPath $srcMesh -Destination (Join-Path $InstallDir "mesh.exe") -Force
        if (Test-Path -LiteralPath $srcServer) {
            Copy-Item -LiteralPath $srcServer -Destination (Join-Path $InstallDir "mesh-server.exe") -Force
        }

        $dstWintun = Join-Path $InstallDir "wintun.dll"
        Copy-Item -LiteralPath $srcWintun -Destination $dstWintun -Force
        Assert-FileSha256 -Path $dstWintun -ExpectedSha256 $expectedHash

        [System.IO.File]::WriteAllText(
            (Join-Path $InstallDir "wintun.dll.sha256"),
            "$expectedHash  wintun.dll`n",
            [System.Text.UTF8Encoding]::new($false)
        )

        foreach ($docAsset in @("WINTUN-LICENSE.txt", "README-WINTUN.md")) {
            $srcDoc = Resolve-SourceArtifactPath -PrimaryDir $SourceDir -FileName $docAsset
            if (Test-Path -LiteralPath $srcDoc) {
                Copy-Item -LiteralPath $srcDoc -Destination (Join-Path $InstallDir $docAsset) -Force
            }
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

        if (-not $SkipShortcuts) {
            try {
                Install-MeshShortcuts -ExePath $dstGui -WorkingDir $InstallDir
            }
            catch {
                Write-Warning "Installed service and binaries, but shortcut creation skipped: $($_.Exception.Message)"
            }
        }
    }
}

function Uninstall-MeshService {
    $scExe = Get-System32Executable "sc.exe"

    if ($DryRun) {
        Stop-MeshGuiGracefully -DryRunMode
        Write-Output "[dry-run] Would invoke `"$(Join-Path $InstallDir 'mesh.exe')`" cleanup"
        Write-Output "[dry-run] Would stop and delete Windows Service '$ServiceName'"
        Write-Output "[dry-run] Would remove firewall rule '$FirewallRuleName', Wintun routes, and '# BEGIN mesh ... # END mesh' hosts block"
        Remove-UserAutostartAndShortcuts -DryRunMode
        Write-Output "[dry-run] Would remove bundle files from '$InstallDir': $($BundleCleanupFiles -join ', ')"
        if ($PurgeData) {
            Write-Output "[dry-run] -PurgeData specified: would recursively delete '$DataDir' (including keys.json and bootstrap.toml)"
        }
        else {
            Write-Output "[dry-run] Would preserve '$DataDir\keys.json' and '$DataDir\bootstrap.toml' (removing ephemeral ledger.json / netmap-cache.json only)"
        }
        return
    }

    if ($PSCmdlet.ShouldProcess($ServiceName, "Uninstall Mesh VPN GUI, service, and cleanup resources")) {
        Stop-MeshGuiGracefully

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
        Remove-UserAutostartAndShortcuts

        foreach ($file in $BundleCleanupFiles) {
            $target = Join-Path $InstallDir $file
            if (Test-Path -LiteralPath $target) {
                Remove-Item -LiteralPath $target -Force
            }
        }
        if ((Test-Path -LiteralPath $InstallDir) -and (@(Get-ChildItem -LiteralPath $InstallDir -Force).Count -eq 0)) {
            Remove-Item -LiteralPath $InstallDir -Force
        }

        if ($PurgeData) {
            if (Test-Path -LiteralPath $DataDir) {
                Remove-Item -LiteralPath $DataDir -Recurse -Force
            }
        }
        elseif (Test-Path -LiteralPath $DataDir) {
            # Preserve keys.json and bootstrap.toml unless -PurgeData/-Purge is specified (`US-115`).
            foreach ($ephemeral in @("ledger.json", "netmap-cache.json")) {
                $ephemeralPath = Join-Path $DataDir $ephemeral
                if (Test-Path -LiteralPath $ephemeralPath) {
                    Remove-Item -LiteralPath $ephemeralPath -Force
                }
            }
        }
    }
}

if (-not $DryRun -and -not (Test-IsAdministrator)) {
    Write-Error "Administrator privileges (UAC elevation) are required to run install-windows.ps1."
    exit 1
}

if ($PurgeData -and -not $Uninstall) {
    throw "Use -Uninstall -PurgeData (or -Uninstall -Purge) together to remove keys.json, bootstrap.toml, and all state directories."
}

if ($Uninstall) {
    Uninstall-MeshService
}
else {
    Install-MeshService
}
