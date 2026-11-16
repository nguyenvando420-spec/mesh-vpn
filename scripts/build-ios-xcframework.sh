#!/usr/bin/env bash
set -euo pipefail

if [ "$(uname -s)" != "Darwin" ]; then
    echo "ERROR: scripts/build-ios-xcframework.sh must run on macOS with Xcode installed." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-15.0}"
export CARGO_PROFILE_RELEASE_OPT_LEVEL="${CARGO_PROFILE_RELEASE_OPT_LEVEL:-z}"
export CARGO_PROFILE_RELEASE_LTO="${CARGO_PROFILE_RELEASE_LTO:-fat}"

MAX_DYNAMIC_LIB_BYTES=6291456
IOS_TARGETS=(
    "aarch64-apple-ios"
    "aarch64-apple-ios-sim"
    "x86_64-apple-ios"
)

for target in "${IOS_TARGETS[@]}"; do
    if ! rustup target list --installed | grep -qx "${target}"; then
        echo "Installing missing Rust iOS target: ${target}"
        rustup target add "${target}"
    fi
done

for target in "${IOS_TARGETS[@]}"; do
    echo "Building mesh-mobile-ffi (release opt-level=z, lto=fat) for ${target}..."
    cargo build --locked --release -p mesh-mobile-ffi --target "${target}"
done

DEV_LIB="${REPO_ROOT}/target/aarch64-apple-ios/release/libmesh_mobile_ffi.a"
SIM_ARM_LIB="${REPO_ROOT}/target/aarch64-apple-ios-sim/release/libmesh_mobile_ffi.a"
SIM_X86_LIB="${REPO_ROOT}/target/x86_64-apple-ios/release/libmesh_mobile_ffi.a"

DEV_DYLIB="${REPO_ROOT}/target/aarch64-apple-ios/release/libmesh_mobile_ffi.dylib"
SIM_ARM_DYLIB="${REPO_ROOT}/target/aarch64-apple-ios-sim/release/libmesh_mobile_ffi.dylib"
SIM_X86_DYLIB="${REPO_ROOT}/target/x86_64-apple-ios/release/libmesh_mobile_ffi.dylib"

for lib in "${DEV_LIB}" "${SIM_ARM_LIB}" "${SIM_X86_LIB}"; do
    if [ ! -f "${lib}" ]; then
        echo "ERROR: Expected static library missing: ${lib}" >&2
        exit 1
    fi
done

for dylib in "${DEV_DYLIB}" "${SIM_ARM_DYLIB}" "${SIM_X86_DYLIB}"; do
    if [ ! -f "${dylib}" ]; then
        echo "ERROR: Expected dynamic library slice missing: ${dylib}" >&2
        exit 1
    fi
    size_bytes="$(wc -c < "${dylib}" | tr -d '[:space:]')"
    echo "Mach-O slice ${dylib}: ${size_bytes} bytes (limit ${MAX_DYNAMIC_LIB_BYTES})"
    if [ "${size_bytes}" -gt "${MAX_DYNAMIC_LIB_BYTES}" ]; then
        echo "ERROR: ${dylib} (${size_bytes} B) exceeds 6 MiB limit (${MAX_DYNAMIC_LIB_BYTES} B)" >&2
        exit 1
    fi
done

GENERATED_DIR="${REPO_ROOT}/mobile/ios/Generated"
FRAMEWORKS_DIR="${REPO_ROOT}/mobile/ios/Frameworks"
XCFRAMEWORK_OUT="${FRAMEWORKS_DIR}/MeshMobileFFI.xcframework"

rm -rf "${GENERATED_DIR}" "${XCFRAMEWORK_OUT}"
mkdir -p "${GENERATED_DIR}" "${FRAMEWORKS_DIR}"

echo "Generating UniFFI 0.29.5 Swift bindings..."
cargo run --locked -p mesh-uniffi-bindgen -- generate \
    --library "${DEV_DYLIB}" \
    --language swift \
    --out-dir "${GENERATED_DIR}"

echo "Patching UniFFI generated Swift vtable for Swift 6 strict concurrency..."
python3 - "${GENERATED_DIR}/mesh_mobile_ffi.swift" <<'PY'
import pathlib
import sys

swift_path = pathlib.Path(sys.argv[1])
text = swift_path.read_text(encoding="utf-8")
target = "    static let vtable: [UniffiVTableCallbackInterfacePlatformNetworkBridge]"
replacement = (
    "    nonisolated(unsafe) static let vtable: "
    "[UniffiVTableCallbackInterfacePlatformNetworkBridge]"
)
if target not in text:
    raise SystemExit("ERROR: Expected UniFFI vtable declaration not found in mesh_mobile_ffi.swift")
patched = text.replace(target, replacement, 1).replace("\r\n", "\n")
swift_path.write_bytes(patched.encode("utf-8"))
PY

STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "${STAGE_DIR}"' EXIT

mkdir -p "${STAGE_DIR}/sim" "${STAGE_DIR}/headers-device" "${STAGE_DIR}/headers-sim"

echo "Creating fat simulator static archive with lipo..."
lipo -create "${SIM_ARM_LIB}" "${SIM_X86_LIB}" -output "${STAGE_DIR}/sim/libmesh_mobile_ffi.a"

for hdr_dir in "${STAGE_DIR}/headers-device" "${STAGE_DIR}/headers-sim"; do
    cp "${GENERATED_DIR}/mesh_mobile_ffiFFI.h" "${hdr_dir}/mesh_mobile_ffiFFI.h"
    cp "${GENERATED_DIR}/mesh_mobile_ffiFFI.modulemap" "${hdr_dir}/module.modulemap"
done

echo "Packaging MeshMobileFFI.xcframework..."
xcodebuild -create-xcframework \
    -library "${DEV_LIB}" -headers "${STAGE_DIR}/headers-device" \
    -library "${STAGE_DIR}/sim/libmesh_mobile_ffi.a" -headers "${STAGE_DIR}/headers-sim" \
    -output "${XCFRAMEWORK_OUT}"

echo "Successfully built ${XCFRAMEWORK_OUT} and ${GENERATED_DIR}/mesh_mobile_ffi.swift"
