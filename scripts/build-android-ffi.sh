#!/usr/bin/env bash
# Builds Android JNI `.so` (`arm64-v8a`, `x86_64`), stages `rustls-platform-verifier`
# local Maven repo, and generates UniFFI 0.29.5 Kotlin bindings (`WP-M-B1`, `ADR-014`).
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
ANDROID_DIR="${REPO_ROOT}/mobile/android"
JNI_LIBS_DIR="${ANDROID_DIR}/app/src/main/jniLibs"
UNIFFI_OUT_DIR="${ANDROID_DIR}/app/build/generated/uniffi/main/kotlin"
LOCAL_M2_DIR="${ANDROID_DIR}/.m2"
ANDROID_MIN_SDK="${ANDROID_MIN_SDK:-26}"
MAX_SO_BYTES=$((6 * 1024 * 1024))
REQUIRED_JNI_SYMBOL="Java_dev_meshvpn_android_ffi_MeshNativeInit_initPlatformVerifier"

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: required command '$1' was not found on PATH" >&2
        exit 1
    fi
}

resolve_ndk_dir() {
    if [[ -n "${ANDROID_NDK_HOME:-}" && -d "${ANDROID_NDK_HOME}" ]]; then
        printf '%s\n' "${ANDROID_NDK_HOME}"
        return 0
    fi
    if [[ -n "${ANDROID_NDK_ROOT:-}" && -d "${ANDROID_NDK_ROOT}" ]]; then
        printf '%s\n' "${ANDROID_NDK_ROOT}"
        return 0
    fi
    local sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
    if [[ -n "${sdk_root}" && -d "${sdk_root}/ndk" ]]; then
        local latest
        latest="$(find "${sdk_root}/ndk" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -n 1 || true)"
        if [[ -n "${latest}" ]]; then
            printf '%s\n' "${latest}"
            return 0
        fi
    fi
    echo "error: Android NDK not found. Set ANDROID_NDK_HOME or install NDK r27c+." >&2
    exit 1
}

verify_elf_and_size() {
    local so_path="$1"
    if [[ ! -f "${so_path}" ]]; then
        echo "error: expected JNI library missing at ${so_path}" >&2
        exit 1
    fi

    local size_bytes
    size_bytes="$(wc -c < "${so_path}" | tr -d '[:space:]')"
    echo "Checking ${so_path}: ${size_bytes} bytes (limit ${MAX_SO_BYTES} bytes)"
    if (( size_bytes > MAX_SO_BYTES )); then
        echo "error: ${so_path} exceeds 6 MiB budget (${size_bytes} > ${MAX_SO_BYTES})" >&2
        exit 1
    fi

    python3 - "${so_path}" "${REQUIRED_JNI_SYMBOL}" <<'PY'
import struct
import sys

so_path = sys.argv[1]
required_sym = sys.argv[2].encode("ascii")

with open(so_path, "rb") as fh:
    data = fh.read()

if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
    raise SystemExit(f"error: {so_path} is not little-endian ELF64")

e_phoff = struct.unpack_from("<Q", data, 32)[0]
e_phentsize = struct.unpack_from("<H", data, 54)[0]
e_phnum = struct.unpack_from("<H", data, 56)[0]

pt_load_count = 0
for idx in range(e_phnum):
    off = e_phoff + idx * e_phentsize
    p_type = struct.unpack_from("<I", data, off)[0]
    p_align = struct.unpack_from("<Q", data, off + 48)[0]
    if p_type == 1:  # PT_LOAD
        pt_load_count += 1
        if p_align < 16384:
            raise SystemExit(
                f"error: {so_path} PT_LOAD[{idx}] p_align={p_align} < 16384 (16 KB required)"
            )

if pt_load_count == 0:
    raise SystemExit(f"error: {so_path} contains zero PT_LOAD segments")

if required_sym not in data:
    raise SystemExit(f"error: {so_path} missing JNI symbol {required_sym.decode('ascii')}")

print(f"Verified ELF64 {pt_load_count} PT_LOAD segments (p_align >= 16384) and JNI symbol.")
PY
}

stage_rustls_verifier_maven_repo() {
    local maven_src
    maven_src="$(
        python3 - "${REPO_ROOT}" <<'PY'
import json
import os
import subprocess
import sys

repo_root = sys.argv[1]
cmd = [
    "cargo",
    "metadata",
    "--format-version",
    "1",
    "--locked",
    "--filter-platform",
    "aarch64-linux-android",
]
raw = subprocess.check_output(cmd, cwd=repo_root)
meta = json.loads(raw)
for pkg in meta.get("packages", []):
    if pkg.get("name") == "rustls-platform-verifier-android":
        pkg_dir = os.path.dirname(pkg["manifest_path"])
        maven_dir = os.path.join(pkg_dir, "maven")
        if os.path.isdir(maven_dir):
            print(maven_dir)
            sys.exit(0)
raise SystemExit("error: rustls-platform-verifier-android maven directory not found")
PY
    )"

    rm -rf "${LOCAL_M2_DIR}"
    mkdir -p "${LOCAL_M2_DIR}"
    cp -R "${maven_src}/." "${LOCAL_M2_DIR}/"
    echo "Staged rustls-platform-verifier local Maven repository in ${LOCAL_M2_DIR}"
}

main() {
    require_cmd cargo
    require_cmd rustup
    require_cmd python3
    if ! cargo ndk --version >/dev/null 2>&1; then
        echo "error: cargo-ndk is required (install via cargo install cargo-ndk)" >&2
        exit 1
    fi

    local ndk_dir
    ndk_dir="$(resolve_ndk_dir)"
    export ANDROID_NDK_HOME="${ndk_dir}"
    echo "Using ANDROID_NDK_HOME=${ANDROID_NDK_HOME}"

    rm -rf "${JNI_LIBS_DIR}" "${UNIFFI_OUT_DIR}"
    mkdir -p "${JNI_LIBS_DIR}" "${UNIFFI_OUT_DIR}"

    local link_rustflags="-C link-arg=-Wl,-z,max-page-size=16384"
    if [[ -n "${RUSTFLAGS:-}" ]]; then
        link_rustflags="${link_rustflags} ${RUSTFLAGS}"
    fi

    (
        cd "${REPO_ROOT}"
        CARGO_PROFILE_RELEASE_OPT_LEVEL=z \
        CARGO_PROFILE_RELEASE_LTO=fat \
        RUSTFLAGS="${link_rustflags}" \
        cargo ndk \
            -t arm64-v8a \
            -t x86_64 \
            -o "${JNI_LIBS_DIR}" \
            --platform "${ANDROID_MIN_SDK}" \
            build --release --locked -p mesh-mobile-ffi
    )

    verify_elf_and_size "${JNI_LIBS_DIR}/arm64-v8a/libmesh_mobile_ffi.so"
    verify_elf_and_size "${JNI_LIBS_DIR}/x86_64/libmesh_mobile_ffi.so"

    stage_rustls_verifier_maven_repo

    (
        cd "${REPO_ROOT}"
        cargo run --release --locked -p mesh-uniffi-bindgen -- \
            generate \
            --library "${JNI_LIBS_DIR}/arm64-v8a/libmesh_mobile_ffi.so" \
            --language kotlin \
            --out-dir "${UNIFFI_OUT_DIR}"
    )

    echo "Generated UniFFI Kotlin bindings in ${UNIFFI_OUT_DIR}"
}

main "$@"
