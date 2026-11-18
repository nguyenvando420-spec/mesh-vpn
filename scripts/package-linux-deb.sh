#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BIN_DIR=""
OUT_DIR=""
VERSION="0.3.0"
DEB_ARCH="amd64"
DEB_NAME="mesh-vpn-linux-amd64.deb"
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage:
  package-linux-deb.sh --bin-dir DIR --out-dir DIR [--version VER] [--arch DEB_ARCH] [--deb-name FILE] [--dry-run]
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --bin-dir)
      BIN_DIR="$2"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --arch)
      DEB_ARCH="$2"
      shift 2
      ;;
    --deb-name)
      DEB_NAME="$2"
      shift 2
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
      echo "error: unknown argument '$1'" >&2
      usage >&2
      exit 2
      ;;
  esac
done

REQUIRED_ASSETS=(
  "${REPO_ROOT}/deploy/linux-desktop/meshd-desktop.service"
  "${REPO_ROOT}/deploy/linux-desktop/mesh-vpn.desktop"
  "${REPO_ROOT}/deploy/linux-desktop/mesh-vpn.svg"
  "${REPO_ROOT}/deploy/linux-desktop/internal.mesh.pkexec.policy"
)
for asset in "${REQUIRED_ASSETS[@]}"; do
  if [ ! -f "${asset}" ]; then
    echo "error: missing required Linux desktop asset: ${asset}" >&2
    exit 1
  fi
done

if [ "${DRY_RUN}" -eq 1 ]; then
  echo "[deb-pkg] dry-run ok: assets validated for version=${VERSION} arch=${DEB_ARCH} pkg=${DEB_NAME}"
  exit 0
fi

if [ -z "${BIN_DIR}" ] || [ -z "${OUT_DIR}" ]; then
  echo "error: --bin-dir and --out-dir are required unless --dry-run is specified" >&2
  usage >&2
  exit 2
fi

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "error: dpkg-deb is required to build Ubuntu/Debian .deb packages" >&2
  exit 1
fi

for bin in MeshVPN mesh meshd mesh-server; do
  if [ ! -f "${BIN_DIR}/${bin}" ]; then
    echo "error: required Linux binary missing at ${BIN_DIR}/${bin}" >&2
    exit 1
  fi
done

STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "${STAGE_DIR}"' EXIT

PKG_ROOT="${STAGE_DIR}/pkg"
mkdir -p \
  "${PKG_ROOT}/DEBIAN" \
  "${PKG_ROOT}/usr/bin" \
  "${PKG_ROOT}/lib/systemd/system" \
  "${PKG_ROOT}/usr/share/applications" \
  "${PKG_ROOT}/usr/share/icons/hicolor/scalable/apps" \
  "${PKG_ROOT}/usr/share/polkit-1/actions"

for bin in MeshVPN mesh meshd mesh-server; do
  install -m 0755 "${BIN_DIR}/${bin}" "${PKG_ROOT}/usr/bin/${bin}"
done

install -m 0644 \
  "${REPO_ROOT}/deploy/linux-desktop/meshd-desktop.service" \
  "${PKG_ROOT}/lib/systemd/system/meshd.service"
install -m 0644 \
  "${REPO_ROOT}/deploy/linux-desktop/mesh-vpn.desktop" \
  "${PKG_ROOT}/usr/share/applications/mesh-vpn.desktop"
install -m 0644 \
  "${REPO_ROOT}/deploy/linux-desktop/mesh-vpn.svg" \
  "${PKG_ROOT}/usr/share/icons/hicolor/scalable/apps/mesh-vpn.svg"
install -m 0644 \
  "${REPO_ROOT}/deploy/linux-desktop/internal.mesh.pkexec.policy" \
  "${PKG_ROOT}/usr/share/polkit-1/actions/internal.mesh.pkexec.policy"

cat > "${PKG_ROOT}/DEBIAN/control" <<EOF
Package: mesh-vpn
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${DEB_ARCH}
Maintainer: Mesh VPN Contributors <noreply@mesh.internal>
Depends: systemd, policykit-1 | polkitd, iproute2
Recommends: xdg-utils
Description: Mesh VPN Overlay Client, CLI, Daemon, and Linux Desktop GUI
 Zero-config P2P/Relay overlay mesh VPN daemon (meshd), CLI (mesh),
 server binary (mesh-server), and desktop graphical interface (MeshVPN).
EOF

cat > "${PKG_ROOT}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if ! getent group mesh-admin >/dev/null 2>&1; then
  groupadd --system mesh-admin || addgroup --system mesh-admin || true
fi
mkdir -p /var/lib/meshd /run/meshd /var/log/meshd
chmod 0700 /var/lib/meshd
chmod 0755 /run/meshd
chmod 0750 /var/log/meshd
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
  systemctl enable --now meshd.service || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -f -t /usr/share/icons/hicolor || true
fi
EOF
chmod 0755 "${PKG_ROOT}/DEBIAN/postinst"

cat > "${PKG_ROOT}/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl stop meshd.service || true
    systemctl disable meshd.service || true
  fi
  if [ -x /usr/bin/mesh ]; then
    /usr/bin/mesh cleanup >/dev/null 2>&1 || true
  fi
fi
EOF
chmod 0755 "${PKG_ROOT}/DEBIAN/prerm"

cat > "${PKG_ROOT}/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi
if [ "$1" = "purge" ]; then
  rm -rf /var/lib/meshd /run/meshd /var/log/meshd
fi
EOF
chmod 0755 "${PKG_ROOT}/DEBIAN/postrm"

mkdir -p "${OUT_DIR}"
OUT_DEB="${OUT_DIR}/${DEB_NAME}"
dpkg-deb --build --root-owner-group "${PKG_ROOT}" "${OUT_DEB}"
(
  cd "${OUT_DIR}"
  sha256sum "${DEB_NAME}" > "${DEB_NAME}.sha256"
)
echo "[deb-pkg] built ${OUT_DEB} ($(wc -c < "${OUT_DEB}" | tr -d '[:space:]') bytes)"
