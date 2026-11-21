#!/bin/sh
# ==============================================================================
# Mesh VPN v0.4.0 Unified UI — Automated $0 Desktop GUI QA Runner (POSIX / Linux / macOS)
# Work Package: WP-U-E0 (US-133, US-134)
# ==============================================================================
# Executes:
#   1. Static security audit (lab/desktop/audit-desktop-security.sh).
#   2. Workspace fmt + clippy (--workspace --all-targets --all-features -- -D warnings).
#   3. Desktop GUI Rust test suites across 5 cross-platform crates:
#      - mesh-gui (--all-targets --all-features)
#      - mesh (--test qa_desktop_cli_launcher)
#      - mesh-net (--test desktop_ipc_contract)
#      - mesh-client (--test desktop_session_wp_d_a1)
#      - mesh-core (--test desktop_onboarding_validation)
#   4. On Darwin (macOS 13+ / macos-15 CI):
#      - swift test --package-path desktop/macos/MeshDesktopCore
#      - xcodegen generate --spec desktop/macos/project.yml (if xcodegen installed)
#      - (cd desktop/macos && swiftlint lint --strict) (if swiftlint installed)
#      - xcodebuild test -project desktop/macos/MeshVPNApp.xcodeproj -scheme MeshVPNApp
#        -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO (if xcodebuild + project present)
#      - sh scripts/install-macos.sh --dry-run
#      - sh scripts/install-macos.sh --uninstall --dry-run
#      - sh scripts/install-macos.sh --uninstall --purge-data --dry-run
#      - sh scripts/package-macos-app.sh --dry-run
#   5. Emits structured JSON + Markdown QA report in lab/.tmp/.
# ==============================================================================

set -eu

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

SKIP_FULL_CHECK=0
OUTPUT_DIR="lab/.tmp"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --skip-full-check)
      SKIP_FULL_CHECK=1
      shift
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: sh scripts/run-desktop-qa.sh [--skip-full-check] [--output-dir <dir>]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

HOST_OS="$(uname -s)"
START_TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

echo "================================================================================"
echo ">>> [1/5] Running Static Desktop GUI Security Audit (lab/desktop/audit-desktop-security.sh)"
echo "================================================================================"
sh "$REPO_ROOT/lab/desktop/audit-desktop-security.sh"

echo "================================================================================"
echo ">>> [2/5] Running Rust Formatting & Clippy (-D warnings)"
echo "================================================================================"
if [ "$SKIP_FULL_CHECK" -eq 0 ]; then
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --all-features -- -D warnings
else
  cargo clippy -p mesh-gui --all-targets --all-features -- -D warnings
fi

echo "================================================================================"
echo ">>> [3/5] Running Desktop GUI & Unified UI Rust Automated Test Suites"
echo "================================================================================"
cargo test -p mesh-gui --all-targets --all-features
cargo test -p mesh-gui --test qa_gdi_leak_gate --all-features
cargo test -p mesh-gui --test qa_accessibility_unified_ui --all-features
cargo test -p mesh-gui --test qa_state_label_unification --all-features
cargo test -p mesh-gui --test security_regression_unified_ui --all-features
cargo test -p mesh --test qa_desktop_cli_launcher --all-features
cargo test -p mesh-net --test desktop_ipc_contract --all-features
cargo test -p mesh-client --test desktop_session_wp_d_a1 --all-features
cargo test -p mesh-core --test desktop_onboarding_validation --all-features

MACOS_GATE_STATUS="PENDING_CI_RUNNER"
MACOS_GATE_DETAILS="Requires Darwin / macos-15 runner for SwiftPM, XcodeGen, SwiftLint, xcodebuild, and macOS installer/packaging dry-runs"

echo "================================================================================"
echo ">>> [4/5] Platform-Specific Desktop GUI Verification (HOST_OS=$HOST_OS)"
echo "================================================================================"
if [ "$HOST_OS" = "Darwin" ]; then
  echo "  --> Running SwiftPM test suite (desktop/macos/MeshDesktopCore)..."
  swift test --package-path "$REPO_ROOT/desktop/macos/MeshDesktopCore"

  if command -v swiftlint >/dev/null 2>&1; then
    echo "  --> Running SwiftLint (--strict)..."
    (cd "$REPO_ROOT/desktop/macos" && swiftlint lint --strict)
  fi

  if command -v xcodegen >/dev/null 2>&1; then
    echo "  --> Generating Xcode project via XcodeGen..."
    (cd "$REPO_ROOT/desktop/macos" && xcodegen generate)
  fi

  if [ -d "$REPO_ROOT/desktop/macos/MeshVPNApp.xcodeproj" ] && command -v xcodebuild >/dev/null 2>&1; then
    echo "  --> Running xcodebuild test (scheme: MeshVPNApp, CODE_SIGNING_ALLOWED=NO)..."
    xcodebuild test \
      -project "$REPO_ROOT/desktop/macos/MeshVPNApp.xcodeproj" \
      -scheme MeshVPNApp \
      -destination "platform=macOS" \
      CODE_SIGNING_ALLOWED=NO \
      CODE_SIGNING_REQUIRED=NO \
      CODE_SIGN_IDENTITY=""
  fi

  echo "  --> Running macOS installer & packager dry-run checks..."
  sh "$REPO_ROOT/scripts/install-macos.sh" --dry-run
  sh "$REPO_ROOT/scripts/install-macos.sh" --uninstall --dry-run
  sh "$REPO_ROOT/scripts/install-macos.sh" --uninstall --purge-data --dry-run
  sh "$REPO_ROOT/scripts/package-macos-app.sh" --dry-run

  MACOS_GATE_STATUS="VERIFIED_ON_DARWIN_HOST"
  MACOS_GATE_DETAILS="swift test + installer/packager dry-runs PASS on Darwin"
else
  echo "  --> Non-Darwin host ($HOST_OS): validating shell syntax (sh -n) on macOS scripts..."
  sh -n "$REPO_ROOT/scripts/install-macos.sh"
  sh -n "$REPO_ROOT/scripts/package-macos-app.sh"
  sh -n "$REPO_ROOT/lab/desktop/audit-desktop-security.sh"
fi

echo "================================================================================"
echo ">>> [5/5] Writing Desktop GUI QA Report Artifacts ($OUTPUT_DIR)"
echo "================================================================================"
mkdir -p "$REPO_ROOT/$OUTPUT_DIR"
END_TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

JSON_REPORT="$REPO_ROOT/$OUTPUT_DIR/desktop-qa-report.json"
MD_SUMMARY="$REPO_ROOT/$OUTPUT_DIR/desktop-qa-summary.md"

cat > "$JSON_REPORT" <<EOF
{
  "schema_version": "1.0.0",
  "sprint": "v0.4.0 Unified UI",
  "work_package": "WP-U-E0 (US-133, US-134)",
  "generated_at_utc": "$END_TS",
  "started_at_utc": "$START_TS",
  "host_os": "$HOST_OS",
  "rust_desktop_suites_status": "VERIFIED",
  "static_security_audit_status": "VERIFIED",
  "macos_native_suite_status": "$MACOS_GATE_STATUS",
  "macos_native_suite_details": "$MACOS_GATE_DETAILS",
  "hardware_signoff_required": true,
  "hardware_protocol_doc": "docs/06-operations/unified-ui-hardware-acceptance-protocol.md"
}
EOF

cat > "$MD_SUMMARY" <<EOF
# Desktop GUI Automated QA Summary (\`v0.4.0 Unified UI\` / \`WP-U-E0: US-133, US-134\`)

- **Started At (UTC)**: \`$START_TS\`
- **Completed At (UTC)**: \`$END_TS\`
- **Host OS**: \`$HOST_OS\`
- **Static Security Audit (\`DGUI-AUDIT-01..10\`)**: \`VERIFIED\`
- **Rust Desktop Suites (\`mesh-gui\`, \`mesh\`, \`mesh-net\`, \`mesh-client\`, \`mesh-core\`)**: \`VERIFIED\`
- **macOS Native Gate**: \`$MACOS_GATE_STATUS\` ($MACOS_GATE_DETAILS)
- **Physical Hardware UAT Sign-Off Required**: \`true\` (\`docs/06-operations/unified-ui-hardware-acceptance-protocol.md\`)
EOF

echo "[PASS] Desktop GUI QA Runner completed. Artifacts written to $OUTPUT_DIR."
exit 0
