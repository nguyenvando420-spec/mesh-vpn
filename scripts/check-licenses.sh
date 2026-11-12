#!/bin/sh
# Dependency licence policy (tech-stack-decision.md section 11.3). See scripts/check-licenses.ps1.
set -eu
cd "$(dirname "$0")/.."

MODULE="meshvpn.internal/mesh"
ALLOWED="MIT,BSD-2-Clause,BSD-3-Clause,Apache-2.0,ISC"
GO="${MESH_GO:-go}"

export CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
TOOL=$(env -u GOOS -u GOARCH "$GO" tool -n -modfile=tools/go.mod go-licenses | tail -n 1)

rc=0
for os in linux darwin windows; do
  echo "    licences for GOOS=$os"
  if ! out=$(GOOS=$os "$TOOL" check ./... --ignore "$MODULE" --allowed_licenses="$ALLOWED" 2>&1); then
    rc=1
    printf '%s\n' "$out" | grep -v -e 'non-Go code' -e '\.s$' | sed 's/^/      /' || true
  fi
done
if [ "$rc" -eq 0 ]; then echo "    licence policy OK"; fi
exit "$rc"
