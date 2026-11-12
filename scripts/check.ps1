<#
.SYNOPSIS
  Standard Check Commands for mesh-vpn (Windows PowerShell 5.1+ / PowerShell 7).
  Must be GREEN (exit code 0) before any hand-over. Same steps run in CI (see docs/03-system-design/coding-standards.md section 10).

.PARAMETER Race
  Run `go test -race` (needs cgo + C compiler). On Windows/macOS this runs inside Docker image golang:<pinned>; on Linux natively.
.PARAMETER Deps
  Also run govulncheck and the dependency licence policy check (mandatory in CI; run locally when go.mod changes).
.PARAMETER Fix
  Apply formatter fixes (golangci-lint fmt) instead of only checking. Never use as a substitute for the check run.
.PARAMETER Quick
  Local iteration only: skips cross-OS lint/build matrix and race. NOT acceptable for hand-over.
#>
[CmdletBinding()]
param(
  [switch]$Race,
  [switch]$Deps,
  [switch]$Fix,
  [switch]$Quick
)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)

$PinnedGo = '1.27'                      # go.mod `go 1.27.x`; bootstrap pins the exact patch (scripts/bootstrap-toolchain.ps1)
$GoImage  = 'golang:1.27.4'
$Targets  = @('linux/amd64', 'darwin/arm64', 'darwin/amd64', 'windows/amd64')
$LintOS   = @('linux', 'darwin', 'windows')
$Failures = New-Object System.Collections.Generic.List[string]

function Resolve-Go {
  if ($env:MESH_GO -and (Test-Path $env:MESH_GO)) { return $env:MESH_GO }
  $c = Get-Command go -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  $fallback = Join-Path $env:USERPROFILE 'sdk\go1.27.4\bin\go.exe'
  if (Test-Path $fallback) { return $fallback }
  throw 'Go toolchain not found. Run: powershell -File scripts/bootstrap-toolchain.ps1'
}

$Go = Resolve-Go
$env:PATH = (Split-Path -Parent $Go) + [IO.Path]::PathSeparator + $env:PATH
$env:CGO_ENABLED = '0'            # invariant (ADR-001); only the race step overrides it
$env:GOTOOLCHAIN = 'local'        # never silently download another toolchain
$env:GOFLAGS = '-mod=readonly'

function Step {
  param([string]$Name, [scriptblock]$Body)
  Write-Host ("==> {0}" -f $Name) -ForegroundColor Cyan
  try {
    & $Body
  } catch {
    Write-Host ("    FAILED: {0}" -f $_.Exception.Message) -ForegroundColor Red
    $Failures.Add($Name)
  }
}

function Exec {
  # Run a native command; stream its output as plain text (stderr is merged, so Windows PowerShell does not turn
  # warnings such as `go: warning: "./..." matched no packages` into terminating errors); throw on non-zero exit code.
  param([string]$File, [string[]]$Arguments)
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try {
    & $File @Arguments 2>&1 | ForEach-Object { Write-Host ("    " + $_) }
    $code = $LASTEXITCODE
  } finally { $ErrorActionPreference = $prev }
  if ($code -ne 0) { throw ("'{0} {1}' exited with {2}" -f $File, ($Arguments -join ' '), $code) }
}

function Capture {
  # Run a native command and return its stdout lines (stderr discarded); never throws on stderr output.
  param([string]$File, [string[]]$Arguments)
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try { $out = & $File @Arguments 2>$null; $script:CaptureExit = $LASTEXITCODE } finally { $ErrorActionPreference = $prev }
  return $out
}

function With-Target {
  param([string]$Goos, [string]$Goarch, [scriptblock]$Body)
  $oldOs = $env:GOOS; $oldArch = $env:GOARCH
  $env:GOOS = $Goos
  if ($Goarch) { $env:GOARCH = $Goarch } else { Remove-Item Env:GOARCH -ErrorAction SilentlyContinue }
  try { & $Body } finally {
    if ($null -ne $oldOs) { $env:GOOS = $oldOs } else { Remove-Item Env:GOOS -ErrorAction SilentlyContinue }
    if ($null -ne $oldArch) { $env:GOARCH = $oldArch } else { Remove-Item Env:GOARCH -ErrorAction SilentlyContinue }
  }
}

function Test-HasGoPackages {
  # Decide by the presence of .go files, NOT by `go list` success: a syntax error must never look like "no code yet".
  $any = Get-ChildItem -Recurse -File -Filter *.go -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\(\.git|tools|testdata|vendor)\\' } | Select-Object -First 1
  return [bool]$any
}

# Resolve the golangci-lint binary for the HOST (GOOS must be unset while building a tool).
function Get-Tool([string]$Name) {
  # NOTE: the -modfile value MUST be quoted: Windows PowerShell splits an unquoted `-modfile=tools/go.mod` at the dot.
  $p = (Capture $Go @('tool', '-n', '-modfile=tools/go.mod', $Name) | Select-Object -Last 1)
  if ($script:CaptureExit -ne 0 -or -not $p) { throw "cannot build tool $Name from tools/go.mod" }
  return $p
}

# ---------------------------------------------------------------------------------------------
Step 'toolchain: go version' {
  $v = (& $Go version)
  Write-Host "    $v"
  if ($v -notmatch ("go{0}\.\d+" -f [regex]::Escape($PinnedGo))) { throw "expected Go $PinnedGo.x, got: $v" }
}

Step 'module: go mod verify + tidy -diff' {
  Exec $Go @('mod', 'verify')
  Exec $Go @('mod', 'tidy', '-diff')
}

Step 'repo rules: forbidden patterns, BOM, cgo' {
  $files = Get-ChildItem -Recurse -File -Include *.go |
    Where-Object { $_.FullName -notmatch '\\(\.git|tools|testdata|vendor)\\' }
  $rel = { param($f) ($f.FullName.Substring((Get-Location).Path.Length + 1)) -replace '\\', '/' }
  $bad = New-Object System.Collections.Generic.List[string]

  foreach ($f in $files) {
    $r = & $rel $f
    $isTest = $r.EndsWith('_test.go')
    $lines = [IO.File]::ReadAllLines($f.FullName)
    for ($i = 0; $i -lt $lines.Length; $i++) {
      $l = $lines[$i]; $t = $l.TrimStart()
      if ($t.StartsWith('//')) { continue }
      $where = "{0}:{1}" -f $r, ($i + 1)
      if ($l -match 'InsecureSkipVerify' -and $r -notmatch '^internal/tlspin/') { $bad.Add("$where InsecureSkipVerify outside internal/tlspin (SEC-04)") }
      if (-not $isTest -and $r -notmatch '^internal/defaults/' -and $l -match '(?<![\w.])(443|3478)(?![\w.])') { $bad.Add("$where hard-coded port 443/3478 (GNFR-11): use internal/defaults") }
      if (-not $isTest -and $r -notmatch '^internal/(httpx|listener)/' -and $l -match '(net\.Listen\("tcp|net\.ListenTCP|tls\.Listen\(|http\.ListenAndServe)') { $bad.Add("$where TCP listener outside internal/httpx|internal/listener (SEC-14)") }
      if (-not $isTest -and $r -notmatch '^(internal/(secure|keystore|adminapi)/|internal/datapath/wgcfg/|cmd/mesh/)' -and $l -match '\.Reveal\(\)') { $bad.Add("$where Reveal() outside the allowed packages (SEC-01)") }
      if ($l -match 'import "C"' -or $l -match '^//go:build.*\bcgo\b') { $bad.Add("$where cgo is forbidden (ADR-001)") }
      if ($l -match 'spctl\s+--master-disable') { $bad.Add("$where disabling Gatekeeper is forbidden (PLAT-06)") }
    }
  }

  # UTF-8 BOM breaks go.mod and Go tooling; .editorconfig mandates UTF-8 without BOM.
  $text = Get-ChildItem -Recurse -File -Include *.go, go.mod, go.sum, *.toml, *.yml, *.yaml, *.json, *.sql, *.sh |
    Where-Object { $_.FullName -notmatch '\\\.git\\' }
  foreach ($f in $text) {
    $b = [IO.File]::ReadAllBytes($f.FullName)
    if ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) { $bad.Add(("{0} has a UTF-8 BOM" -f (& $rel $f))) }
  }

  if ($bad.Count -gt 0) { $bad | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }; throw "$($bad.Count) repo-rule violation(s)" }
}

if (Test-HasGoPackages) {
  Step 'format check (gofumpt + gci)' {
    $lint = Get-Tool 'golangci-lint'
    if ($Fix) { Exec $lint @('fmt') } else { Exec $lint @('fmt', '--diff') }
  }

  if ($Quick) { $osList = @($(& $Go env GOOS)) } else { $osList = $LintOS }
  Step ("lint (golangci-lint) for: {0}" -f ($osList -join ', ')) {
    $lint = Get-Tool 'golangci-lint'
    foreach ($os in $osList) {
      Write-Host "    -> GOOS=$os"
      With-Target $os $null { Exec $lint @('run', './...') }
    }
  }

  if ($Quick) { $tg = @("$(& $Go env GOOS)/$(& $Go env GOARCH)") } else { $tg = $Targets }
  Step ("vet + build for: {0}" -f ($tg -join ', ')) {
    foreach ($t in $tg) {
      $os, $arch = $t.Split('/')
      Write-Host "    -> $t"
      With-Target $os $arch {
        Exec $Go @('vet', './...')
        Exec $Go @('build', '-trimpath', './...')
      }
    }
  }

  Step 'unit tests (native)' {
    Exec $Go @('test', '-shuffle=on', '-count=1', '-timeout', '5m', './...')
  }

  if ($Race -and -not $Quick) {
    Step 'race tests (cgo + C compiler required)' {
      if ($IsLinux) {
        $env:CGO_ENABLED = '1'
        try { Exec $Go @('test', '-race', '-shuffle=on', '-count=1', '-timeout', '10m', './...') } finally { $env:CGO_ENABLED = '0' }
      } else {
        if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Docker not found: run -Race in WSL/Linux or rely on the CI Linux race job' }
        Exec 'docker' @('run', '--rm', '-v', ("{0}:/src" -f (Get-Location).Path), '-v', 'mesh-gomod:/go/pkg/mod', '-w', '/src',
          '-e', 'CGO_ENABLED=1', '-e', 'GOFLAGS=-mod=readonly', $GoImage,
          'go', 'test', '-race', '-shuffle=on', '-count=1', '-timeout', '10m', './...')
      }
    }
  } elseif (-not $Quick) {
    Write-Host '==> race tests: SKIPPED locally (add -Race, or CI Linux job must be green before merge)' -ForegroundColor Yellow
  }

  if ($Deps) {
    Step 'govulncheck' {
      $v = Get-Tool 'govulncheck'
      Exec $v @('./...')
    }
    Step 'dependency licence policy' {
      & (Join-Path $PSScriptRoot 'check-licenses.ps1')
      if ($LASTEXITCODE -ne 0) { throw 'licence policy violated' }
    }
  }
} else {
  Write-Host '==> no Go packages yet: fmt/lint/vet/build/test skipped (Foundation sprint adds code)' -ForegroundColor Yellow
}

Write-Host ''
if ($Failures.Count -gt 0) {
  Write-Host ('CHECK FAILED: {0}' -f ($Failures -join ' | ')) -ForegroundColor Red
  exit 1
}
Write-Host 'CHECK PASSED' -ForegroundColor Green
exit 0
