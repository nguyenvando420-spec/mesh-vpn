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

# 2a. Check for UTF-8 BOM (0xEF 0xBB 0xBF) and LF line endings (POSIX awk compatible across gawk, mawk, BSD awk)
BOM_FILES=$(find . -type f \
  -not -path './.git/*' \
  -not -path './target/*' \
  -not -path './lab/.tmp/*' \
  -not -path './mobile/android/.gradle/*' \
  -not -path './mobile/android/build/*' \
  -not -path './mobile/android/*/build/*' \
  -not -path './mobile/ios/.build/*' \
  -not -path './mobile/ios/DerivedData/*' \
  -not -path './desktop/macos/.build/*' \
  -not -path './desktop/macos/DerivedData/*' \
  -not -path './desktop/macos/*.xcodeproj/*' \
  \( -name '*.rs' -o -name '*.toml' -o -name '*.md' -o -name '*.sh' -o -name '*.ps1' -o -name '*.json' -o -name '*.yml' -o -name '*.yaml' -o -name '*.plist' -o -name '*.entitlements' -o -name '*.strings' -o -name '*.xcstrings' -o -name '*.service' -o -name '*.kt' -o -name '*.kts' -o -name '*.swift' -o -name '*.xml' -o -name '*.pbxproj' -o -name '.editorconfig' -o -name '.gitignore' -o -name '.gitattributes' \) \
  -exec awk 'BEGIN { bom = sprintf("%c%c%c", 239, 187, 191) } FNR == 1 && index($0, bom) == 1 { print FILENAME }' {} +)

if [ -n "$BOM_FILES" ]; then
  echo "ERROR: UTF-8 BOM detected in files (must be UTF-8 without BOM):" >&2
  echo "$BOM_FILES" >&2
  exit 1
fi

CRLF_FILES=$(find . -type f \
  -not -path './.git/*' \
  -not -path './target/*' \
  -not -path './lab/.tmp/*' \
  -not -path './mobile/android/.gradle/*' \
  -not -path './mobile/android/build/*' \
  -not -path './mobile/android/*/build/*' \
  -not -path './mobile/ios/.build/*' \
  -not -path './mobile/ios/DerivedData/*' \
  -not -path './desktop/macos/.build/*' \
  -not -path './desktop/macos/DerivedData/*' \
  -not -path './desktop/macos/*.xcodeproj/*' \
  \( -name '*.rs' -o -name '*.toml' -o -name '*.md' -o -name '*.sh' -o -name '*.json' -o -name '*.yml' -o -name '*.yaml' -o -name '*.plist' -o -name '*.entitlements' -o -name '*.strings' -o -name '*.xcstrings' -o -name '*.service' -o -name '*.kt' -o -name '*.kts' -o -name '*.swift' -o -name '*.xml' -o -name '*.pbxproj' -o -name '.editorconfig' -o -name '.gitignore' -o -name '.gitattributes' \) \
  -exec awk 'BEGIN { cr = sprintf("%c", 13) } index($0, cr) > 0 { if (!seen[FILENAME]++) print FILENAME }' {} +)

if [ -n "$CRLF_FILES" ]; then
  echo "ERROR: CRLF/CR line endings detected in files (must be LF):" >&2
  echo "$CRLF_FILES" >&2
  exit 1
fi

# 2b. Rust source code static invariants (crates/ and tools/)
RUST_DIRS=""
[ -d "crates" ] && RUST_DIRS="crates"
[ -d "tools" ] && RUST_DIRS="$RUST_DIRS tools"

if [ -n "$RUST_DIRS" ]; then
  # Rule: unsafe is forbidden outside crates/mesh-sys/ (including crates/mesh-mobile-ffi/ and tools/)
  # shellcheck disable=SC2086
  UNSAFE_HITS=$(find $RUST_DIRS -type f -name '*.rs' -not -path 'crates/mesh-sys/*' \
    -exec grep -HnE '(^[[:space:]]*(pub(\([^)]*\))?[[:space:]]+)?unsafe[[:space:]]+(fn|trait|impl|extern)[^a-zA-Z0-9_]|unsafe[[:space:]]*\{|#\[unsafe[[:space:]]*\()' {} + || true)
  if [ -n "$UNSAFE_HITS" ]; then
    echo "ERROR: Forbidden 'unsafe' usage outside crates/mesh-sys/:" >&2
    echo "$UNSAFE_HITS" >&2
    exit 1
  fi

  # Rule: .expose_secret() restricted to mesh-crypto, mesh-datapath, mesh-net, mesh
  # shellcheck disable=SC2086
  EXPOSE_HITS=$(find $RUST_DIRS -type f -name '*.rs' \
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
  # shellcheck disable=SC2086
  PORT_HITS=$(find $RUST_DIRS -type f -name '*.rs' \
    -not -path 'crates/mesh-core/*' \
    -not -path '*/tests/*' \
    -exec awk 'FNR == 1 { in_test = 0 } /#\[cfg\(test\)\]/ { in_test = 1 } !in_test && /:(443|3478)([^0-9]|$)/ { print FILENAME ":" FNR ":" $0 }' {} + || true)
  if [ -n "$PORT_HITS" ]; then
    echo "ERROR: Hardcoded default port ':443' or ':3478' outside crates/mesh-core (GNFR-11):" >&2
    echo "$PORT_HITS" >&2
    exit 1
  fi
fi

# 2c. Mobile source & config hygiene (when mobile/ exists)
if [ -d "mobile" ]; then
  FORBIDDEN_MOBILE=$(find mobile -type f \
    -not -path '*/.gradle/*' \
    -not -path '*/build/*' \
    -not -path '*/.build/*' \
    -not -path '*/DerivedData/*' \
    \( -name '*.jks' -o -name '*.keystore' -o -name '*.p12' -o -name '*.mobileprovision' -o -name '*.apk' -o -name '*.aab' -o -name '*.ipa' \) || true)
  if [ -n "$FORBIDDEN_MOBILE" ]; then
    echo "ERROR: Forbidden mobile binary/signing artifact in repository:" >&2
    echo "$FORBIDDEN_MOBILE" >&2
    exit 1
  fi
  ATS_HITS=$(find mobile -type f -name '*.plist' -exec grep -Hn 'NSAllowsArbitraryLoads' {} + || true)
  if [ -n "$ATS_HITS" ]; then
    echo "ERROR: Forbidden ATS bypass 'NSAllowsArbitraryLoads' in plist:" >&2
    echo "$ATS_HITS" >&2
    exit 1
  fi
fi

# 2d. Desktop macOS & Gatekeeper hygiene (desktop/macos/, scripts/, crates/)
SPCTL_DIRS=""
[ -d "desktop/macos" ] && SPCTL_DIRS="desktop/macos"
[ -d "scripts" ] && SPCTL_DIRS="$SPCTL_DIRS scripts"
[ -d "crates" ] && SPCTL_DIRS="$SPCTL_DIRS crates"
if [ -n "$SPCTL_DIRS" ]; then
  # shellcheck disable=SC2086
  SPCTL_HITS=$(find $SPCTL_DIRS -type f \
    -not -path 'desktop/macos/.build/*' \
    -not -path 'desktop/macos/DerivedData/*' \
    -not -path 'desktop/macos/*.xcodeproj/*' \
    -not -path 'scripts/check.ps1' \
    -not -path 'scripts/check.sh' \
    \( -name '*.rs' -o -name '*.swift' -o -name '*.sh' -o -name '*.ps1' -o -name '*.yml' -o -name '*.yaml' -o -name '*.plist' -o -name '*.entitlements' -o -name '*.toml' -o -name '*.md' \) \
    -exec grep -HnE 'spctl[[:space:]]+--master-disable' {} + || true)
  if [ -n "$SPCTL_HITS" ]; then
    echo "ERROR: Forbidden Gatekeeper bypass 'spctl --master-disable' detected:" >&2
    echo "$SPCTL_HITS" >&2
    exit 1
  fi
fi

if [ -d "desktop/macos" ]; then
  FORBIDDEN_DESKTOP=$(find desktop/macos \
    -not -path 'desktop/macos/.build/*' \
    -not -path 'desktop/macos/DerivedData/*' \
    -not -path 'desktop/macos/*.xcodeproj/*' \
    \( -name '*.p12' -o -name '*.mobileprovision' -o -name '*.cer' -o -name '*.dmg' -o -name '*.pkg' -o -name '*.app' \) || true)
  if [ -n "$FORBIDDEN_DESKTOP" ]; then
    echo "ERROR: Forbidden desktop macOS signing/distribution artifact in repository:" >&2
    echo "$FORBIDDEN_DESKTOP" >&2
    exit 1
  fi

  SANDBOX_HITS=$(find desktop/macos -type f \
    -not -path 'desktop/macos/.build/*' \
    -not -path 'desktop/macos/DerivedData/*' \
    -not -path 'desktop/macos/*.xcodeproj/*' \
    \( -name '*.entitlements' -o -name '*.plist' -o -name '*.yml' -o -name '*.yaml' \) \
    -exec grep -Hn 'com\.apple\.security\.app-sandbox' {} + || true)
  if [ -n "$SANDBOX_HITS" ]; then
    echo "ERROR: Forbidden App Sandbox entitlement in desktop/macos:" >&2
    echo "$SANDBOX_HITS" >&2
    exit 1
  fi

  URL_SCHEME_HITS=$(find desktop/macos -type f \
    -not -path 'desktop/macos/.build/*' \
    -not -path 'desktop/macos/DerivedData/*' \
    -not -path 'desktop/macos/*.xcodeproj/*' \
    \( -name '*.plist' -o -name '*.yml' -o -name '*.yaml' \) \
    -exec grep -HnE '(CFBundleURLTypes|NSAllowsArbitraryLoads)' {} + || true)
  if [ -n "$URL_SCHEME_HITS" ]; then
    echo "ERROR: Forbidden 'CFBundleURLTypes' or 'NSAllowsArbitraryLoads' in desktop/macos:" >&2
    echo "$URL_SCHEME_HITS" >&2
    exit 1
  fi

  UIKIT_HITS=$(find desktop/macos -type f \
    -not -path 'desktop/macos/.build/*' \
    -not -path 'desktop/macos/DerivedData/*' \
    -not -path 'desktop/macos/*.xcodeproj/*' \
    -name '*.swift' \
    -exec grep -HnE '^[[:space:]]*import[[:space:]]+UIKit([^a-zA-Z0-9_]|$)' {} + || true)
  if [ -n "$UIKIT_HITS" ]; then
    echo "ERROR: Forbidden iOS-only 'import UIKit' in desktop/macos:" >&2
    echo "$UIKIT_HITS" >&2
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
    echo "    cargo check --workspace --exclude mesh-mobile-ffi --exclude mesh-uniffi-bindgen --target $target"
    cargo check --workspace --exclude mesh-mobile-ffi --exclude mesh-uniffi-bindgen --target "$target"
  done
fi

echo "==> ALL CHECKS PASSED!"
