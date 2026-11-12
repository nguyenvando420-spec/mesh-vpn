#!/bin/sh
# Standard Check Command for Mesh VPN (Rust 1.94.1) on Linux / macOS.
# Enforces static repository & security rules, rustfmt, clippy (-D warnings), unit/property tests, and cargo-deny.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$REPO_ROOT"

CROSS=0
for arg in "$@"; do
  case "$arg" in
    --cross) CROSS=1 ;;
    *)
      echo "Unknown option: $arg (supported: --cross)" >&2
      exit 2
      ;;
  esac
done

echo "==> [1/5] Checking Rust toolchain version (pinned 1.94.1)..."
RUSTC_VER=$(rustc --version)
echo "    $RUSTC_VER"
case "$RUSTC_VER" in
  "rustc 1.94.1 "*) ;;
  *)
    echo "ERROR: Toolchain mismatch: expected 'rustc 1.94.1', got '$RUSTC_VER'." >&2
    exit 1
    ;;
esac
cargo --version

echo "==> [2/5] Enforcing static repository & security rules..."

# 2a. Check for UTF-8 BOM (0xEF 0xBB 0xBF) per file using FNR == 1 (POSIX awk compatible across gawk, mawk, BSD awk)
BOM_FILES=$(find . -type f \
  -not -path './.git/*' \
  -not -path './target/*' \
  -not -path './docs/04-sprint-management/*' \
  \( -name '*.rs' -o -name '*.toml' -o -name '*.md' -o -name '*.sh' -o -name '*.ps1' -o -name '.editorconfig' -o -name '.gitignore' -o -name '.gitattributes' \) \
  -exec awk 'BEGIN { bom = sprintf("%c%c%c", 239, 187, 191) } FNR == 1 && index($0, bom) == 1 { print FILENAME }' {} +)

if [ -n "$BOM_FILES" ]; then
  echo "ERROR: UTF-8 BOM detected in files (must be UTF-8 without BOM):" >&2
  echo "$BOM_FILES" >&2
  exit 1
fi

# 2b. Rust source code static invariants (when crates/ exists)
if [ -d "crates" ]; then
  # Rule: unsafe is forbidden outside crates/mesh-sys/
  UNSAFE_HITS=$(find crates -type f -name '*.rs' -not -path 'crates/mesh-sys/*' \
    -exec grep -HnE '(^[[:space:]]*(pub[[:space:]]+)?unsafe[[:space:]]+(fn|trait|impl)[^a-zA-Z0-9_]|unsafe[[:space:]]*\{)' {} + || true)
  if [ -n "$UNSAFE_HITS" ]; then
    echo "ERROR: Forbidden 'unsafe' usage outside crates/mesh-sys/:" >&2
    echo "$UNSAFE_HITS" >&2
    exit 1
  fi

  # Rule: .expose_secret() restricted to mesh-crypto, mesh-datapath, mesh-net, mesh
  EXPOSE_HITS=$(find crates -type f -name '*.rs' \
    -not -path 'crates/mesh-crypto/*' \
    -not -path 'crates/mesh-datapath/*' \
    -not -path 'crates/mesh-net/*' \
    -not -path 'crates/mesh/*' \
    -exec grep -HnE '\.expose_secret[[:space:]]*\(' {} + || true)
  if [ -n "$EXPOSE_HITS" ]; then
    echo "ERROR: Forbidden '.expose_secret()' call outside allowlisted crates (SEC-01):" >&2
    echo "$EXPOSE_HITS" >&2
    exit 1
  fi

  # Rule: GNFR-11 no hardcoded :443 or :3478 outside crates/mesh-core and tests (resets in_test per file at FNR == 1)
  PORT_HITS=$(find crates -type f -name '*.rs' \
    -not -path 'crates/mesh-core/*' \
    -not -path '*/tests/*' \
    -exec awk 'FNR == 1 { in_test = 0 } /#\[cfg\(test\)\]/ { in_test = 1 } !in_test && /:(443|3478)([^0-9]|$)/ { print FILENAME ":" FNR ":" $0 }' {} + || true)
  if [ -n "$PORT_HITS" ]; then
    echo "ERROR: Hardcoded default port ':443' or ':3478' outside crates/mesh-core (GNFR-11):" >&2
    echo "$PORT_HITS" >&2
    exit 1
  fi
fi

echo "    Static repository rules PASSED."

if [ ! -f "Cargo.toml" ]; then
  echo "==> [SKIP] Cargo.toml workspace not yet initialized (pre-Gate-2 design phase). Static checks PASSED."
  exit 0
fi

echo "==> [3/5] Running cargo fmt --all -- --check..."
cargo fmt --all -- --check

echo "==> [4/5] Running cargo clippy (-D warnings) and cargo test..."
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

echo "==> [5/5] Running cargo-deny (licenses, bans, advisories, sources)..."
cargo deny check advisories bans licenses sources

if [ "$CROSS" -eq 1 ]; then
  echo "==> [Cross] Checking cross-compilation targets..."
  for target in x86_64-unknown-linux-musl aarch64-apple-darwin x86_64-apple-darwin x86_64-pc-windows-gnu; do
    echo "    cargo check --workspace --target $target"
    cargo check --workspace --target "$target"
  done
fi

echo "==> ALL CHECKS PASSED!"
