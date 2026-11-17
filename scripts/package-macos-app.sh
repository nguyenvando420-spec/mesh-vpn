#!/usr/bin/env bash
set -euo pipefail

# Packages Mesh VPN.app and optional .dmg/.pkg on macOS obeying ADR-026's immutable
# 3-step signing order:
#   1. Sign inner binaries (meshd, mesh, mesh-server) FIRST (Developer ID or ad-hoc).
#   2. Generate SHA256SUMS for meshd, mesh, internal.mesh.meshd.plist and embed
#      SHA256SUMS + meshd + mesh + internal.mesh.meshd.plist + install-macos.sh
#      into Mesh VPN.app/Contents/Resources/.
#   3. Sign outer Mesh VPN.app WITHOUT --deep (conditional Developer ID +
#      notarytool + stapler, or $0 ad-hoc), then verify codesign --verify --strict
#      and `shasum -a 256 -c SHA256SUMS`.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"

ARCH=""
BIN_DIR=""
ARM64_BIN_DIR=""
X86_64_BIN_DIR=""
MESHD_BIN=""
MESH_BIN=""
MESH_SERVER_BIN=""
APP_PATH=""
PLIST_PATH="${REPO_ROOT}/deploy/launchd/internal.mesh.meshd.plist"
INSTALL_SCRIPT="${REPO_ROOT}/scripts/install-macos.sh"
ENTITLEMENTS_PATH="${REPO_ROOT}/desktop/macos/MeshVPNApp/Resources/MeshVPN.entitlements"
OUT_DIR="${REPO_ROOT}/dist/macos"
DMG_NAME=""
SKIP_DMG=0
DRY_RUN=0

MAX_APP_BYTES=$((15 * 1024 * 1024))
MAX_DMG_BYTES=$((15 * 1024 * 1024))

usage() {
  cat <<'EOF'
Usage:
  package-macos-app.sh [options]

Options:
  --arch <arm64|x86_64|universal>   Target architecture (default: host uname -m)
  --bin-dir <dir>                   Directory containing single-arch meshd, mesh, mesh-server
  --arm64-bin-dir <dir>             Directory containing arm64 binaries (for --arch universal)
  --x86_64-bin-dir <dir>            Directory containing x86_64 binaries (for --arch universal)
  --meshd <path>                    Explicit path to single-arch meshd binary
  --mesh <path>                     Explicit path to single-arch mesh binary
  --mesh-server <path>              Explicit path to single-arch mesh-server binary
  --app-path <path>                 Prebuilt "Mesh VPN.app" bundle (skips xcodebuild)
  --plist <path>                    LaunchDaemon plist path
  --install-script <path>           install-macos.sh path
  --out-dir <dir>                   Output directory (default: dist/macos)
  --dmg-name <filename>             Output DMG filename
  --skip-dmg                        Skip .dmg creation
  --dry-run                         Validate inputs and print packaging/signing plan only
  -h, --help                        Show this help message
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --arch|--bin-dir|--arm64-bin-dir|--x86_64-bin-dir|--meshd|--mesh|--mesh-server|--app-path|--plist|--install-script|--out-dir|--dmg-name)
      if [ "$#" -lt 2 ]; then
        echo "error: option '$1' requires an argument." >&2
        usage >&2
        exit 1
      fi
      opt="$1"
      val="$2"
      shift 2
      case "${opt}" in
        --arch) ARCH="${val}" ;;
        --bin-dir) BIN_DIR="${val}" ;;
        --arm64-bin-dir) ARM64_BIN_DIR="${val}" ;;
        --x86_64-bin-dir) X86_64_BIN_DIR="${val}" ;;
        --meshd) MESHD_BIN="${val}" ;;
        --mesh) MESH_BIN="${val}" ;;
        --mesh-server) MESH_SERVER_BIN="${val}" ;;
        --app-path) APP_PATH="${val}" ;;
        --plist) PLIST_PATH="${val}" ;;
        --install-script) INSTALL_SCRIPT="${val}" ;;
        --out-dir) OUT_DIR="${val}" ;;
        --dmg-name) DMG_NAME="${val}" ;;
      esac
      ;;
    --skip-dmg)
      SKIP_DMG=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option '$1'." >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [ -z "${ARCH}" ]; then
  if [ -n "${ARM64_BIN_DIR}" ] && [ -n "${X86_64_BIN_DIR}" ]; then
    ARCH="universal"
  else
    host_arch="$(uname -m)"
    case "${host_arch}" in
      arm64|x86_64) ARCH="${host_arch}" ;;
      *) ARCH="universal" ;;
    esac
  fi
fi

case "${ARCH}" in
  arm64|x86_64|universal) ;;
  *)
    echo "error: unsupported --arch '${ARCH}' (expected arm64, x86_64, or universal)." >&2
    exit 1
    ;;
esac

if [ -z "${DMG_NAME}" ]; then
  DMG_NAME="MeshVPN-macos-${ARCH}.dmg"
fi

for required_repo_file in \
  "${PLIST_PATH}" \
  "${INSTALL_SCRIPT}" \
  "${ENTITLEMENTS_PATH}" \
  "${REPO_ROOT}/desktop/macos/project.yml" \
  "${REPO_ROOT}/desktop/macos/MeshVPNApp/Resources/Info.plist"; do
  if [ ! -f "${required_repo_file}" ]; then
    echo "error: required packaging asset missing: ${required_repo_file}" >&2
    exit 1
  fi
done

DEVELOPER_ID_APP="${APPLE_DEVELOPER_ID_APP:-}"
DEVELOPER_ID_INSTALLER="${APPLE_DEVELOPER_ID_INSTALLER:-}"
NOTARY_APPLE_ID="${APPLE_NOTARY_APPLE_ID:-}"
NOTARY_TEAM_ID="${APPLE_NOTARY_TEAM_ID:-}"
NOTARY_PASSWORD="${APPLE_NOTARY_APP_PASSWORD:-}"
NOTARY_KEY_PATH="${APPLE_NOTARY_KEY_PATH:-}"
NOTARY_KEY_ID="${APPLE_NOTARY_KEY_ID:-}"
NOTARY_ISSUER_ID="${APPLE_NOTARY_ISSUER_ID:-}"

has_dev_id_app=0
if [ -n "${DEVELOPER_ID_APP}" ]; then
  has_dev_id_app=1
fi

has_notary=0
if [ "${has_dev_id_app}" -eq 1 ]; then
  if [ -n "${NOTARY_KEY_PATH}" ] && [ -n "${NOTARY_KEY_ID}" ] && [ -n "${NOTARY_ISSUER_ID}" ]; then
    has_notary=1
  elif [ -n "${NOTARY_APPLE_ID}" ] && [ -n "${NOTARY_TEAM_ID}" ] && [ -n "${NOTARY_PASSWORD}" ]; then
    has_notary=1
  fi
fi

if [ "${DRY_RUN}" -eq 1 ]; then
  echo "[dry-run] macOS packaging plan (arch=${ARCH}, out=${OUT_DIR}, dmg=${DMG_NAME})"
  echo "[dry-run] verified repo assets: project.yml, Info.plist, MeshVPN.entitlements, internal.mesh.meshd.plist, install-macos.sh"
  if [ -z "${APP_PATH}" ]; then
    echo "[dry-run] would run xcodegen generate + xcodebuild build (CODE_SIGNING_ALLOWED=NO) in desktop/macos"
  else
    echo "[dry-run] would use prebuilt app bundle: ${APP_PATH}"
  fi
  if [ "${ARCH}" = "universal" ]; then
    echo "[dry-run] step 0: would merge arm64 + x86_64 binaries via lipo for meshd, mesh, mesh-server"
  fi
  if [ "${has_dev_id_app}" -eq 1 ]; then
    echo "[dry-run] step 1: codesign --force --options runtime --timestamp --sign <APPLE_DEVELOPER_ID_APP> inner binaries (meshd, mesh, mesh-server)"
  else
    echo "[dry-run] step 1: codesign --force -s - inner binaries (meshd, mesh, mesh-server) [\$0 ad-hoc]"
  fi
  echo "[dry-run] step 2: generate SHA256SUMS covering meshd, mesh, internal.mesh.meshd.plist and embed + install-macos.sh in Contents/Resources/"
  if [ "${has_dev_id_app}" -eq 1 ]; then
    echo "[dry-run] step 3: codesign --force --options runtime --timestamp --entitlements MeshVPN.entitlements --sign <APPLE_DEVELOPER_ID_APP> 'Mesh VPN.app' (NO --deep)"
  else
    echo "[dry-run] step 3: codesign --force -s - 'Mesh VPN.app' (NO --deep)"
  fi
  echo "[dry-run] post-verify: codesign --verify --strict + shasum -a 256 -c SHA256SUMS + otool -L + 0 quarantine xattrs + size <= ${MAX_APP_BYTES} bytes"
  if [ "${SKIP_DMG}" -eq 0 ]; then
    echo "[dry-run] would create ${OUT_DIR}/${DMG_NAME} via hdiutil create (size <= ${MAX_DMG_BYTES} bytes)"
  fi
  if [ "${has_notary}" -eq 1 ]; then
    echo "[dry-run] would submit to xcrun notarytool + xcrun stapler staple"
  else
    echo "[dry-run] Apple Developer ID / notarytool secrets absent; commercial notarization skipped (\$0 Mode)"
  fi
  exit 0
fi

if [ "$(uname -s)" != "Darwin" ]; then
  echo "error: live macOS packaging requires Darwin host (use --dry-run on non-macOS hosts)." >&2
  exit 1
fi

sign_macho() {
  local target_path="$1"
  local entitlements="${2:-}"
  if [ "${has_dev_id_app}" -eq 1 ]; then
    if [ -n "${entitlements}" ]; then
      /usr/bin/codesign --force --options runtime --timestamp \
        --entitlements "${entitlements}" \
        --sign "${DEVELOPER_ID_APP}" "${target_path}"
    else
      /usr/bin/codesign --force --options runtime --timestamp \
        --sign "${DEVELOPER_ID_APP}" "${target_path}"
    fi
  else
    /usr/bin/codesign --force -s - "${target_path}"
  fi
}

check_otool_deps() {
  local bin_path="$1"
  local bad_deps
  bad_deps="$(/usr/bin/otool -L "${bin_path}" | tail -n +2 | awk '{print $1}' | grep -Ev '^(/usr/lib/|/System/Library/|@rpath/|@executable_path/|@loader_path/)' || true)"
  if [ -n "${bad_deps}" ]; then
    echo "error: non-system dynamic library dependency detected in ${bin_path}:" >&2
    echo "${bad_deps}" >&2
    exit 1
  fi
}

assert_no_quarantine() {
  local target_path="$1"
  local qhits
  qhits="$(/usr/bin/xattr -r "${target_path}" 2>/dev/null | grep 'com\.apple\.quarantine' || true)"
  if [ -n "${qhits}" ]; then
    echo "error: quarantine xattr remained on ${target_path}:" >&2
    echo "${qhits}" >&2
    exit 1
  fi
}

directory_size_bytes() {
  local dir_path="$1"
  local kib
  kib="$(du -sk "${dir_path}" | awk '{print $1}')"
  echo $((kib * 1024))
}

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mesh-pkg-macos.XXXXXX")"
cleanup() {
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

/usr/bin/plutil -lint "${PLIST_PATH}" >/dev/null
/usr/bin/plutil -lint "${REPO_ROOT}/desktop/macos/MeshVPNApp/Resources/Info.plist" >/dev/null
/usr/bin/plutil -lint "${ENTITLEMENTS_PATH}" >/dev/null

# Prepare inner binaries (single-arch or lipo universal)
INNER_DIR="${WORK_DIR}/inner"
mkdir -p "${INNER_DIR}" "${OUT_DIR}"

resolve_single_bin() {
  local explicit="$1"
  local fallback_dir="$2"
  local name="$3"
  if [ -n "${explicit}" ]; then
    printf '%s' "${explicit}"
  elif [ -n "${fallback_dir}" ]; then
    printf '%s/%s' "${fallback_dir}" "${name}"
  else
    printf ''
  fi
}

if [ "${ARCH}" = "universal" ]; then
  if [ -z "${ARM64_BIN_DIR}" ]; then
    ARM64_BIN_DIR="${REPO_ROOT}/target/aarch64-apple-darwin/release"
  fi
  if [ -z "${X86_64_BIN_DIR}" ]; then
    X86_64_BIN_DIR="${REPO_ROOT}/target/x86_64-apple-darwin/release"
  fi
  for name in meshd mesh; do
    arm_bin="${ARM64_BIN_DIR}/${name}"
    x86_bin="${X86_64_BIN_DIR}/${name}"
    test -f "${arm_bin}"
    test -f "${x86_bin}"
    /usr/bin/lipo -create "${arm_bin}" "${x86_bin}" -output "${INNER_DIR}/${name}"
    chmod 0755 "${INNER_DIR}/${name}"
  done
  if [ -f "${ARM64_BIN_DIR}/mesh-server" ] && [ -f "${X86_64_BIN_DIR}/mesh-server" ]; then
    /usr/bin/lipo -create "${ARM64_BIN_DIR}/mesh-server" "${X86_64_BIN_DIR}/mesh-server" -output "${INNER_DIR}/mesh-server"
    chmod 0755 "${INNER_DIR}/mesh-server"
  fi
else
  if [ -z "${BIN_DIR}" ]; then
    if [ "${ARCH}" = "arm64" ]; then
      BIN_DIR="${REPO_ROOT}/target/aarch64-apple-darwin/release"
    else
      BIN_DIR="${REPO_ROOT}/target/x86_64-apple-darwin/release"
    fi
  fi
  src_meshd="$(resolve_single_bin "${MESHD_BIN}" "${BIN_DIR}" "meshd")"
  src_mesh="$(resolve_single_bin "${MESH_BIN}" "${BIN_DIR}" "mesh")"
  src_server="$(resolve_single_bin "${MESH_SERVER_BIN}" "${BIN_DIR}" "mesh-server")"
  test -f "${src_meshd}"
  test -f "${src_mesh}"
  cp "${src_meshd}" "${INNER_DIR}/meshd"
  cp "${src_mesh}" "${INNER_DIR}/mesh"
  chmod 0755 "${INNER_DIR}/meshd" "${INNER_DIR}/mesh"
  if [ -n "${src_server}" ] && [ -f "${src_server}" ]; then
    cp "${src_server}" "${INNER_DIR}/mesh-server"
    chmod 0755 "${INNER_DIR}/mesh-server"
  fi
fi

# Build Mesh VPN.app if not prebuilt
STAGED_APP="${OUT_DIR}/Mesh VPN.app"
rm -rf "${STAGED_APP}"

if [ -n "${APP_PATH}" ]; then
  if [ ! -d "${APP_PATH}" ]; then
    echo "error: --app-path '${APP_PATH}' not found." >&2
    exit 1
  fi
  /usr/bin/ditto "${APP_PATH}" "${STAGED_APP}"
else
  if ! command -v xcodegen >/dev/null 2>&1; then
    echo "error: xcodegen is required to build Mesh VPN.app." >&2
    exit 1
  fi
  XCODE_BUILD_DIR="${WORK_DIR}/xcode-build"
  XCODE_ARCHS="${ARCH}"
  if [ "${ARCH}" = "universal" ]; then
    XCODE_ARCHS="arm64 x86_64"
  fi
  (
    cd "${REPO_ROOT}/desktop/macos"
    xcodegen generate
    xcodebuild \
      -project MeshVPNApp.xcodeproj \
      -scheme MeshVPNApp \
      -configuration Release \
      -destination "generic/platform=macOS" \
      -derivedDataPath "${XCODE_BUILD_DIR}" \
      ARCHS="${XCODE_ARCHS}" \
      ONLY_ACTIVE_ARCH=NO \
      CODE_SIGNING_ALLOWED=NO \
      build
  )
  BUILT_APP="${XCODE_BUILD_DIR}/Build/Products/Release/Mesh VPN.app"
  if [ ! -d "${BUILT_APP}" ]; then
    echo "error: built bundle not found at ${BUILT_APP}" >&2
    exit 1
  fi
  /usr/bin/ditto "${BUILT_APP}" "${STAGED_APP}"
fi

# Strip quarantine from staged app & inner binaries
/usr/bin/xattr -cr "${STAGED_APP}" "${INNER_DIR}" >/dev/null 2>&1 || true

# Check otool -L on inner binaries and main app executable
APP_EXEC="${STAGED_APP}/Contents/MacOS/Mesh VPN"
test -f "${APP_EXEC}"
check_otool_deps "${APP_EXEC}"
check_otool_deps "${INNER_DIR}/meshd"
check_otool_deps "${INNER_DIR}/mesh"
if [ -f "${INNER_DIR}/mesh-server" ]; then
  check_otool_deps "${INNER_DIR}/mesh-server"
fi

# ---------------------------------------------------------------------------
# STEP 1 (ADR-026 Immutable Order): Sign inner binaries FIRST
# ---------------------------------------------------------------------------
for inner_bin in "${INNER_DIR}/meshd" "${INNER_DIR}/mesh"; do
  sign_macho "${inner_bin}"
  /usr/bin/codesign --verify --strict "${inner_bin}"
done
if [ -f "${INNER_DIR}/mesh-server" ]; then
  sign_macho "${INNER_DIR}/mesh-server"
  /usr/bin/codesign --verify --strict "${INNER_DIR}/mesh-server"
  cp "${INNER_DIR}/mesh-server" "${OUT_DIR}/mesh-server"
fi

# ---------------------------------------------------------------------------
# STEP 2 (ADR-026 Immutable Order): Generate SHA256SUMS & embed Resources
# ---------------------------------------------------------------------------
RES_DIR="${STAGED_APP}/Contents/Resources"
mkdir -p "${RES_DIR}"
cp "${INNER_DIR}/meshd" "${RES_DIR}/meshd"
cp "${INNER_DIR}/mesh" "${RES_DIR}/mesh"
cp "${PLIST_PATH}" "${RES_DIR}/internal.mesh.meshd.plist"
cp "${INSTALL_SCRIPT}" "${RES_DIR}/install-macos.sh"
chmod 0755 "${RES_DIR}/meshd" "${RES_DIR}/mesh" "${RES_DIR}/install-macos.sh"
chmod 0644 "${RES_DIR}/internal.mesh.meshd.plist"

(
  cd "${RES_DIR}"
  /usr/bin/shasum -a 256 meshd mesh internal.mesh.meshd.plist > SHA256SUMS
)
chmod 0644 "${RES_DIR}/SHA256SUMS"

# Verify embedded plist
/usr/bin/plutil -lint "${RES_DIR}/internal.mesh.meshd.plist" >/dev/null
/usr/bin/plutil -lint "${STAGED_APP}/Contents/Info.plist" >/dev/null

# ---------------------------------------------------------------------------
# STEP 3 (ADR-026 Immutable Order): Sign outer Mesh VPN.app WITHOUT --deep
# ---------------------------------------------------------------------------
/usr/bin/xattr -cr "${STAGED_APP}" >/dev/null 2>&1 || true
sign_macho "${STAGED_APP}" "${ENTITLEMENTS_PATH}"

# Post-verify bundle codesign, quarantine absence, embedded SHA256SUMS, and size
/usr/bin/codesign --verify --strict --verbose=2 "${STAGED_APP}"
assert_no_quarantine "${STAGED_APP}"
(
  cd "${RES_DIR}"
  /usr/bin/shasum -a 256 -c SHA256SUMS
)

app_bytes="$(directory_size_bytes "${STAGED_APP}")"
echo "Mesh VPN.app (${ARCH}) size: ${app_bytes} bytes (limit ${MAX_APP_BYTES})"
if [ "${app_bytes}" -gt "${MAX_APP_BYTES}" ]; then
  echo "error: Mesh VPN.app exceeds 15 MiB ceiling (${app_bytes} > ${MAX_APP_BYTES})." >&2
  exit 1
fi

# Build .dmg if requested
DMG_PATH="${OUT_DIR}/${DMG_NAME}"
if [ "${SKIP_DMG}" -eq 0 ]; then
  DMG_STAGE="${WORK_DIR}/dmg-stage"
  mkdir -p "${DMG_STAGE}"
  /usr/bin/ditto "${STAGED_APP}" "${DMG_STAGE}/Mesh VPN.app"
  ln -s /Applications "${DMG_STAGE}/Applications"
  rm -f "${DMG_PATH}"
  /usr/bin/hdiutil create \
    -volname "Mesh VPN" \
    -srcfolder "${DMG_STAGE}" \
    -ov \
    -format UDZO \
    "${DMG_PATH}" >/dev/null
  /usr/bin/xattr -cr "${DMG_PATH}" >/dev/null 2>&1 || true
  assert_no_quarantine "${DMG_PATH}"

  if [ "${has_dev_id_app}" -eq 1 ]; then
    /usr/bin/codesign --force --timestamp --sign "${DEVELOPER_ID_APP}" "${DMG_PATH}"
    /usr/bin/codesign --verify --verbose=2 "${DMG_PATH}"
  fi

  dmg_bytes="$(wc -c < "${DMG_PATH}" | tr -d '[:space:]')"
  echo "${DMG_NAME} size: ${dmg_bytes} bytes (limit ${MAX_DMG_BYTES})"
  if [ "${dmg_bytes}" -gt "${MAX_DMG_BYTES}" ]; then
    echo "error: ${DMG_NAME} exceeds 15 MiB ceiling (${dmg_bytes} > ${MAX_DMG_BYTES})." >&2
    exit 1
  fi
fi

# Conditional notarization & stapling (US-117)
if [ "${has_notary}" -eq 1 ]; then
  NOTARY_TARGET="${DMG_PATH}"
  if [ "${SKIP_DMG}" -eq 1 ]; then
    NOTARY_TARGET="${WORK_DIR}/MeshVPN-notary.zip"
    /usr/bin/ditto -c -k --keepParent "${STAGED_APP}" "${NOTARY_TARGET}"
  fi
  if [ -n "${NOTARY_KEY_PATH}" ]; then
    /usr/bin/xcrun notarytool submit "${NOTARY_TARGET}" \
      --key "${NOTARY_KEY_PATH}" \
      --key-id "${NOTARY_KEY_ID}" \
      --issuer "${NOTARY_ISSUER_ID}" \
      --wait
  else
    /usr/bin/xcrun notarytool submit "${NOTARY_TARGET}" \
      --apple-id "${NOTARY_APPLE_ID}" \
      --team-id "${NOTARY_TEAM_ID}" \
      --password "${NOTARY_PASSWORD}" \
      --wait
  fi
  /usr/bin/xcrun stapler staple "${STAGED_APP}"
  if [ "${SKIP_DMG}" -eq 0 ]; then
    /usr/bin/xcrun stapler staple "${DMG_PATH}"
  fi
  if [ -n "${DEVELOPER_ID_INSTALLER}" ]; then
    PKG_PATH="${OUT_DIR}/MeshVPN-macos-${ARCH}.pkg"
    /usr/bin/productbuild \
      --component "${STAGED_APP}" /Applications \
      --sign "${DEVELOPER_ID_INSTALLER}" \
      "${PKG_PATH}"
    if [ -n "${NOTARY_KEY_PATH}" ]; then
      /usr/bin/xcrun notarytool submit "${PKG_PATH}" \
        --key "${NOTARY_KEY_PATH}" \
        --key-id "${NOTARY_KEY_ID}" \
        --issuer "${NOTARY_ISSUER_ID}" \
        --wait
    else
      /usr/bin/xcrun notarytool submit "${PKG_PATH}" \
        --apple-id "${NOTARY_APPLE_ID}" \
        --team-id "${NOTARY_TEAM_ID}" \
        --password "${NOTARY_PASSWORD}" \
        --wait
    fi
    /usr/bin/xcrun stapler staple "${PKG_PATH}"
  fi
else
  echo "Notarization skipped (APPLE_DEVELOPER_ID_APP / notary credentials not set; \$0 ad-hoc mode)."
fi

echo "Successfully packaged ${STAGED_APP}"
