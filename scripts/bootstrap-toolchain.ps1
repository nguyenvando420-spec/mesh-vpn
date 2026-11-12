<#
.SYNOPSIS
  Installs the pinned Go toolchain for mesh-vpn into a user-level directory (no admin rights, no PATH changes).
  Downloads the official zip, verifies SHA-256 against the hash pinned in this script, extracts to
  %USERPROFILE%\sdk\go<version>, and prints how to use it. scripts/check.ps1 finds it automatically.

.PARAMETER Force
  Re-download and re-extract even if the target directory already exists.
#>
[CmdletBinding()]
param([switch]$Force)

$ErrorActionPreference = 'Stop'

# Pinned toolchain. To bump: take file name + sha256 from https://go.dev/dl/?mode=json, update here + go.mod + docs (ADR-001).
$Version  = '1.27.4'
$FileName = "go$Version.windows-amd64.zip"
$Sha256   = '178ab98950ac69ab25069307dc6ade79f3816e414cce95b4da166a115cde1e7e'
$Url      = "https://go.dev/dl/$FileName"

$Sdk  = Join-Path $env:USERPROFILE 'sdk'
$Dest = Join-Path $Sdk "go$Version"
$GoExe = Join-Path $Dest 'bin\go.exe'

if ((Test-Path $GoExe) -and -not $Force) {
  Write-Host "Go $Version already present: $GoExe"
} else {
  New-Item -ItemType Directory -Force $Sdk | Out-Null
  $Tmp = Join-Path ([IO.Path]::GetTempPath()) $FileName
  Write-Host "Downloading $Url ..."
  Invoke-WebRequest -Uri $Url -OutFile $Tmp -UseBasicParsing
  $Actual = (Get-FileHash -Algorithm SHA256 -Path $Tmp).Hash.ToLowerInvariant()
  if ($Actual -ne $Sha256) {
    Remove-Item -Force $Tmp
    throw "SHA-256 mismatch for $FileName. expected=$Sha256 actual=$Actual (download discarded)"
  }
  Write-Host 'SHA-256 verified.'
  if (Test-Path $Dest) { Remove-Item -Recurse -Force $Dest }
  $Stage = Join-Path $Sdk "go$Version.stage"
  if (Test-Path $Stage) { Remove-Item -Recurse -Force $Stage }
  Expand-Archive -Path $Tmp -DestinationPath $Stage -Force
  Move-Item -Path (Join-Path $Stage 'go') -Destination $Dest
  Remove-Item -Recurse -Force $Stage, $Tmp
}

& $GoExe version
Write-Host ''
Write-Host 'Use it for this shell:'
Write-Host ('  $env:PATH = "{0};$env:PATH"; $env:GOTOOLCHAIN = "local"' -f (Join-Path $Dest 'bin'))
Write-Host 'Then run:  powershell -File scripts/check.ps1'
