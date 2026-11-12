#!/bin/sh
# Standard Check Commands for mesh-vpn (macOS / Linux / CI). Must be GREEN (exit 0) before any hand-over.
# Mirrors scripts/check.ps1 (see docs/03-system-design/coding-standards.md section 10).
#
# Usage: sh scripts/check.sh [--race] [--deps] [--fix] [--quick]
#   --race   run `go test -race` (needs cgo + C compiler; on Linux/macOS runs natively)
#   --deps   also run govulncheck + licence policy (mandatory in CI)
#   --fix    apply formatter fixes instead of only checking
#   --quick  local iteration only (skips cross-OS lint/build matrix and race). NOT acceptable for hand-over.
set -eu

cd "$(dirname "$0")/.."

RACE=0 DEPS=0 FIX=0 QUICK=0
for a in "$@"; do
  case "$a" in
    --race) RACE=1 ;;
    --deps) DEPS=1 ;;
    --fix) FIX=1 ;;
    --quick) QUICK=1 ;;
    *) echo "unknown flag: $a" >&2; exit 2 ;;
  esac
done

PINNED_GO="1.27"
TARGETS="linux/amd64 darwin/arm64 darwin/amd64 windows/amd64"
LINT_OS="linux darwin windows"
FAILED=""

GO="${MESH_GO:-go}"
if ! command -v "$GO" >/dev/null 2>&1; then
  if [ -x "$HOME/sdk/go1.27.4/bin/go" ]; then GO="$HOME/sdk/go1.27.4/bin/go"; else echo "Go toolchain not found" >&2; exit 2; fi
fi

# golangci-lint itself shells out to `go`: make sure the chosen toolchain is first on PATH.
case "$GO" in */*) PATH="$(dirname "$GO"):$PATH"; export PATH ;; esac

export CGO_ENABLED=0   # invariant (ADR-001); only the race step overrides it
export GOTOOLCHAIN=local
export GOFLAGS=-mod=readonly

step() { # step "name" command...
  name="$1"; shift
  printf '==> %s\n' "$name"
  if ! "$@"; then
    printf '    FAILED: %s\n' "$name" >&2
    FAILED="$FAILED | $name"
  fi
}

host_os=$($GO env GOOS)
host_arch=$($GO env GOARCH)

get_tool() { env -u GOOS -u GOARCH "$GO" tool -n -modfile=tools/go.mod "$1" | tail -n 1; }

check_go_version() {
  v=$($GO version); echo "    $v"
  case "$v" in *" go$PINNED_GO."*) return 0 ;; esac
  echo "expected Go $PINNED_GO.x, got: $v" >&2; return 1
}

check_module() { "$GO" mod verify && "$GO" mod tidy -diff; }

check_repo_rules() {
  rc=0
  files=$(find . -name '*.go' -not -path './.git/*' -not -path './tools/*' -not -path '*/testdata/*' -not -path './vendor/*')
  # shellcheck disable=SC2086
  [ -n "$files" ] || { true; }
  for f in $files; do
    p=${f#./}
    case "$p" in *_test.go) is_test=1 ;; *) is_test=0 ;; esac
    awk -v P="$p" -v T="$is_test" '
      { l=$0; t=l; sub(/^[ \t]+/, "", t); if (substr(t,1,2)=="//") next }
      l ~ /InsecureSkipVerify/ && P !~ /^internal\/tlspin\// { printf "    %s:%d InsecureSkipVerify outside internal/tlspin (SEC-04)\n", P, NR; bad=1 }
      T==0 && P !~ /^internal\/defaults\// && l ~ /(^|[^A-Za-z0-9_.])(443|3478)([^A-Za-z0-9_.]|$)/ { printf "    %s:%d hard-coded port 443/3478 (GNFR-11): use internal/defaults\n", P, NR; bad=1 }
      T==0 && P !~ /^internal\/(httpx|listener)\// && l ~ /(net\.Listen\("tcp|net\.ListenTCP|tls\.Listen\(|http\.ListenAndServe)/ { printf "    %s:%d TCP listener outside internal/httpx|listener (SEC-14)\n", P, NR; bad=1 }
      T==0 && P !~ /^(internal\/(secure|keystore|adminapi)\/|internal\/datapath\/wgcfg\/|cmd\/mesh\/)/ && l ~ /\.Reveal\(\)/ { printf "    %s:%d Reveal() outside allowed packages (SEC-01)\n", P, NR; bad=1 }
      l ~ /import "C"/ { printf "    %s:%d cgo is forbidden (ADR-001)\n", P, NR; bad=1 }
      l ~ /spctl[ \t]+--master-disable/ { printf "    %s:%d disabling Gatekeeper is forbidden (PLAT-06)\n", P, NR; bad=1 }
      END { exit bad }' "$f" || rc=1
  done
  # UTF-8 BOM check
  for f in $(find . \( -name '*.go' -o -name 'go.mod' -o -name 'go.sum' -o -name '*.toml' -o -name '*.yml' -o -name '*.yaml' -o -name '*.json' -o -name '*.sql' -o -name '*.md' -o -name '*.sh' -o -name '*.ps1' \) -not -path './.git/*'); do
    if head -n 1 "$f" | LC_ALL=C grep -q "^$(printf '\357\273\277')"; then echo "    $f has a UTF-8 BOM" >&2; rc=1; fi
  done
  return $rc
}

# Decide by the presence of .go files, NOT by `go list` success: a syntax error must never look like "no code yet".
has_go_packages() { [ -n "$(find . -name '*.go' -not -path './.git/*' -not -path './tools/*' -not -path '*/testdata/*' -not -path './vendor/*' | head -n 1)" ]; }

lint_all() {
  lint=$(get_tool golangci-lint)
  for os in $1; do
    echo "    -> GOOS=$os"
    GOOS=$os "$lint" run ./... || return 1
  done
}

vet_build_all() {
  for t in $1; do
    os=${t%/*}; arch=${t#*/}
    echo "    -> $t"
    GOOS=$os GOARCH=$arch "$GO" vet ./... || return 1
    GOOS=$os GOARCH=$arch "$GO" build -trimpath ./... || return 1
  done
}

race_tests() {
  CGO_ENABLED=1 "$GO" test -race -shuffle=on -count=1 -timeout 10m ./...
}

step "toolchain: go version" check_go_version
step "module: go mod verify + tidy -diff" check_module
step "repo rules: forbidden patterns, BOM, cgo" check_repo_rules

if has_go_packages; then
  lint_bin=$(get_tool golangci-lint)
  if [ "$FIX" = 1 ]; then step "format (fix)" "$lint_bin" fmt; else step "format check (gofumpt + gci)" "$lint_bin" fmt --diff; fi

  if [ "$QUICK" = 1 ]; then os_list="$host_os"; tg="$host_os/$host_arch"; else os_list="$LINT_OS"; tg="$TARGETS"; fi
  step "lint (golangci-lint) for: $os_list" lint_all "$os_list"
  step "vet + build for: $tg" vet_build_all "$tg"
  step "unit tests (native)" "$GO" test -shuffle=on -count=1 -timeout 5m ./...

  if [ "$RACE" = 1 ] && [ "$QUICK" = 0 ]; then
    step "race tests (cgo + C compiler required)" race_tests
  elif [ "$QUICK" = 0 ]; then
    echo "==> race tests: SKIPPED locally (add --race; CI Linux race job must be green before merge)"
  fi

  if [ "$DEPS" = 1 ]; then
    step "govulncheck" "$(get_tool govulncheck)" ./...
    step "dependency licence policy" sh scripts/check-licenses.sh
  fi
else
  echo "==> no Go packages yet: fmt/lint/vet/build/test skipped (Foundation sprint adds code)"
fi

echo
if [ -n "$FAILED" ]; then echo "CHECK FAILED:$FAILED" >&2; exit 1; fi
echo "CHECK PASSED"
