<#
.SYNOPSIS
  Dependency licence policy (tech-stack-decision.md section 11.3): every transitive dependency of the product
  binaries, for every target OS, must be MIT / BSD-2-Clause / BSD-3-Clause / Apache-2.0 / ISC.
  AGPL, GPL, LGPL, SSPL, BUSL, unknown => FAIL. Developer tools in tools/go.mod are intentionally out of scope.
#>
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)

$Module  = 'meshvpn.internal/mesh'
$Allowed = 'MIT,BSD-2-Clause,BSD-3-Clause,Apache-2.0,ISC'

$go = if ($env:MESH_GO -and (Test-Path $env:MESH_GO)) { $env:MESH_GO } else { (Get-Command go -ErrorAction Stop).Source }
$env:CGO_ENABLED = '0'; $env:GOTOOLCHAIN = 'local'; $env:GOFLAGS = '-mod=readonly'
Remove-Item Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue

# NOTE: -modfile value must be quoted for Windows PowerShell.
$tool = (& $go tool -n '-modfile=tools/go.mod' go-licenses | Select-Object -Last 1)
if ($LASTEXITCODE -ne 0 -or -not $tool) { throw 'cannot build go-licenses from tools/go.mod' }

$failed = $false
foreach ($os in 'linux', 'darwin', 'windows') {
  Write-Host "    licences for GOOS=$os"
  $env:GOOS = $os
  $out = & $tool check './...' --ignore $Module --allowed_licenses=$Allowed 2>&1
  if ($LASTEXITCODE -ne 0) {
    $failed = $true
    $out | Where-Object { $_ -notmatch "non-Go code|\.s$" } | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
  }
}
Remove-Item Env:GOOS -ErrorAction SilentlyContinue
if ($failed) { exit 1 }
Write-Host '    licence policy OK'
exit 0
