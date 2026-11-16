#!/usr/bin/env bash
# Cross-platform Mobile QA Runner for Mesh VPN v0.2.0 (`WP-M-C2`, `US-097`).
# Runs workspace checks, 5 mobile target checks, ELF/static size budget (<= 6 MiB),
# UniFFI Kotlin/Swift codegen verification, mobile security audit, and crate tests,
# then emits `lab/.tmp/mobile-qa-report.json` and `lab/.tmp/mobile-qa-summary.md`.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

SKIP_CHECK=0
OUTPUT_DIR="lab/.tmp"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-check)
            SKIP_CHECK=1
            shift
            ;;
        --output-dir)
            if [[ $# -lt 2 ]]; then
                echo "error: --output-dir requires an argument" >&2
                exit 2
            fi
            OUTPUT_DIR="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1 (supported: --skip-check, --output-dir <dir>)" >&2
            exit 2
            ;;
    esac
done

MAX_SO_BYTES=6291456
MOBILE_TARGETS=(
    "aarch64-linux-android"
    "x86_64-linux-android"
    "aarch64-apple-ios"
    "aarch64-apple-ios-sim"
    "x86_64-apple-ios"
)

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mesh-mobile-qa-state.XXXXXX")"
BINDGEN_TMP="$(mktemp -d "${TMPDIR:-/tmp}/mesh-mobile-qa-bindgen.XXXXXX")"
STEPS_NDJSON="${STATE_DIR}/steps.ndjson"
TARGETS_NDJSON="${STATE_DIR}/targets.ndjson"
touch "${STEPS_NDJSON}" "${TARGETS_NDJSON}"

OVERALL_STATUS="PASS"
MEASURED_BIN_BYTES=""
MEASURED_BIN_LABEL=""

now_ms() {
    python3 -c 'import time; print(int(time.time() * 1000))'
}

record_step() {
    local id="$1"
    local name="$2"
    local status="$3"
    local duration_ms="$4"
    local details="$5"
    python3 - "${STEPS_NDJSON}" "${id}" "${name}" "${status}" "${duration_ms}" "${details}" <<'PY'
import json
import sys

path, sid, name, status, dur, details = sys.argv[1:7]
with open(path, "a", encoding="utf-8") as fh:
    fh.write(json.dumps({
        "id": sid,
        "name": name,
        "status": status,
        "duration_ms": int(dur),
        "details": details,
    }) + "\n")
PY
    if [[ "${status}" == "FAIL" ]]; then
        OVERALL_STATUS="FAIL"
    fi
}

record_target() {
    local target="$1"
    local deny_st="$2"
    local core_st="$3"
    local ffi_st="$4"
    local notes="$5"
    python3 - "${TARGETS_NDJSON}" "${target}" "${deny_st}" "${core_st}" "${ffi_st}" "${notes}" <<'PY'
import json
import sys

path, target, deny_st, core_st, ffi_st, notes = sys.argv[1:7]
with open(path, "a", encoding="utf-8") as fh:
    fh.write(json.dumps({
        "target": target,
        "cargo_deny": deny_st,
        "core_sys_check": core_st,
        "mobile_ffi_check": ffi_st,
        "notes": notes,
    }) + "\n")
PY
}

write_reports() {
    local out_abs="${OUTPUT_DIR}"
    if [[ "${out_abs}" != /* ]]; then
        out_abs="${REPO_ROOT}/${OUTPUT_DIR}"
    fi
    mkdir -p "${out_abs}"

    python3 - "${out_abs}" "${STEPS_NDJSON}" "${TARGETS_NDJSON}" "${OVERALL_STATUS}" "${MAX_SO_BYTES}" "${MEASURED_BIN_BYTES}" "${MEASURED_BIN_LABEL}" <<'PY'
import datetime
import json
import os
import platform
import sys

out_abs, steps_p, targets_p, overall, max_bytes, bin_bytes, bin_label = sys.argv[1:8]

steps = []
with open(steps_p, "r", encoding="utf-8") as fh:
    for line in fh:
        if line.strip():
            steps.append(json.loads(line))

targets = []
with open(targets_p, "r", encoding="utf-8") as fh:
    for line in fh:
        if line.strip():
            targets.append(json.loads(line))

generated_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
report = {
    "schema_version": 1,
    "generated_utc": generated_utc,
    "host_os": platform.system().lower(),
    "overall_status": overall,
    "artifact_size_bytes": int(bin_bytes) if bin_bytes else None,
    "artifact_size_label": bin_label or None,
    "elf_budget_bytes": int(max_bytes),
    "steps": steps,
    "mobile_targets": targets,
}

json_path = os.path.join(out_abs, "mobile-qa-report.json")
with open(json_path, "wb") as fh:
    fh.write((json.dumps(report, indent=2) + "\n").encode("utf-8"))

md_lines = [
    "# Mesh VPN Mobile QA Summary (`v0.2.0`)",
    "",
    f"- **Generated (UTC):** {generated_utc}",
    f"- **Host OS:** {platform.system()}",
    f"- **Overall Status:** **{overall}**",
]
if bin_bytes:
    md_lines.append(f"- **Release Binary Size (`{bin_label}`):** {bin_bytes} bytes (Budget `<= {max_bytes}` bytes)")

md_lines.extend([
    "",
    "## Pipeline Steps",
    "",
    "| Step | Status | Duration (ms) | Details |",
    "| --- | --- | ---: | --- |",
])
for s in steps:
    details = str(s["details"]).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    md_lines.append(f"| {s['name']} | **{s['status']}** | {s['duration_ms']} | {details} |")

md_lines.extend([
    "",
    "## Mobile Target Matrix",
    "",
    "| Target | `cargo-deny` | `mesh-core` + `mesh-sys` | `mesh-mobile-ffi` | Notes |",
    "| --- | --- | --- | --- | --- |",
])
for t in targets:
    notes = str(t["notes"]).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    md_lines.append(
        f"| `{t['target']}` | {t['cargo_deny']} | {t['core_sys_check']} | {t['mobile_ffi_check']} | {notes} |"
    )

md_path = os.path.join(out_abs, "mobile-qa-summary.md")
with open(md_path, "wb") as fh:
    fh.write(("\n".join(md_lines) + "\n").encode("utf-8"))

print(f"Reports written to: {json_path} and {md_path}")
PY
}

cleanup() {
    local rc=$?
    if [[ ${rc} -ne 0 && "${OVERALL_STATUS}" == "PASS" ]]; then
        OVERALL_STATUS="FAIL"
    fi
    write_reports || true
    rm -rf "${BINDGEN_TMP}" "${STATE_DIR}"
    exit "${rc}"
}
trap cleanup EXIT

resolve_android_ndk() {
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
    return 1
}

ANDROID_MIN_SDK="${ANDROID_MIN_SDK:-26}"

configure_android_ndk_env() {
    local ndk_dir="$1"
    if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
        export ANDROID_NDK_HOME="${ndk_dir}"
    fi
    local prebuilt_root="${ndk_dir}/toolchains/llvm/prebuilt"
    local host_tag=""
    case "$(uname -s)" in
        Linux) host_tag="linux-x86_64" ;;
        Darwin)
            if [[ -d "${prebuilt_root}/darwin-arm64/bin" ]]; then
                host_tag="darwin-arm64"
            else
                host_tag="darwin-x86_64"
            fi
            ;;
    esac

    local llvm_bin=""
    if [[ -n "${host_tag}" && -d "${prebuilt_root}/${host_tag}/bin" ]]; then
        llvm_bin="${prebuilt_root}/${host_tag}/bin"
    elif [[ -d "${prebuilt_root}" ]]; then
        local cand_dir
        for cand_dir in "${prebuilt_root}"/*/bin; do
            if [[ -d "${cand_dir}" ]]; then
                llvm_bin="${cand_dir}"
                break
            fi
        done
    fi

    if [[ -n "${llvm_bin}" && -d "${llvm_bin}" ]]; then
        local aarch64_cc="${llvm_bin}/aarch64-linux-android${ANDROID_MIN_SDK}-clang"
        local x86_64_cc="${llvm_bin}/x86_64-linux-android${ANDROID_MIN_SDK}-clang"
        local ndk_ar="${llvm_bin}/llvm-ar"

        if [[ -z "${CC_aarch64_linux_android:-}" && -x "${aarch64_cc}" ]]; then
            export CC_aarch64_linux_android="${aarch64_cc}"
        fi
        if [[ -z "${AR_aarch64_linux_android:-}" && -x "${ndk_ar}" ]]; then
            export AR_aarch64_linux_android="${ndk_ar}"
        fi
        if [[ -z "${CC_x86_64_linux_android:-}" && -x "${x86_64_cc}" ]]; then
            export CC_x86_64_linux_android="${x86_64_cc}"
        fi
        if [[ -z "${AR_x86_64_linux_android:-}" && -x "${ndk_ar}" ]]; then
            export AR_x86_64_linux_android="${ndk_ar}"
        fi
    fi
}

has_apple_sdk() {
    if [[ -n "${SDKROOT:-}" && -d "${SDKROOT}" ]]; then
        return 0
    fi
    if [[ "$(uname -s)" == "Darwin" ]] && command -v xcrun >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# Step 1: scripts/check.sh
echo "==> [Step 1/5] Workspace Verification (scripts/check.sh)..."
t0="$(now_ms)"
if [[ "${SKIP_CHECK}" -eq 1 ]]; then
    t1="$(now_ms)"
    echo "    [SKIP] Skipped via --skip-check."
    record_step "step_1_workspace_check" "scripts/check.sh" "SKIP" "$((t1 - t0))" "Skipped by --skip-check flag"
else
    if sh scripts/check.sh; then
        t1="$(now_ms)"
        record_step "step_1_workspace_check" "scripts/check.sh" "PASS" "$((t1 - t0))" "Workspace static checks, fmt, clippy, tests, and cargo-deny passed."
    else
        t1="$(now_ms)"
        record_step "step_1_workspace_check" "scripts/check.sh" "FAIL" "$((t1 - t0))" "scripts/check.sh failed"
        exit 1
    fi
fi

# Step 2: 5 Mobile Targets
echo "==> [Step 2/5] Checking 5 Mobile Targets..."
t0="$(now_ms)"
if ! command -v cargo-deny >/dev/null 2>&1; then
    t1="$(now_ms)"
    record_step "step_2_mobile_targets" "5 Mobile Targets" "FAIL" "$((t1 - t0))" "cargo-deny not found on PATH"
    exit 1
fi

ANDROID_NDK_DIR="$(resolve_android_ndk || true)"
HAS_CARGO_NDK=0
if [[ -n "${ANDROID_NDK_DIR}" ]]; then
    configure_android_ndk_env "${ANDROID_NDK_DIR}"
    if cargo ndk --version >/dev/null 2>&1; then
        HAS_CARGO_NDK=1
    fi
fi
APPLE_SDK_OK=0
if has_apple_sdk; then
    APPLE_SDK_OK=1
fi

TARGET_FAIL=0
SKIPPED_FFI_COUNT=0
for t in "${MOBILE_TARGETS[@]}"; do
    echo "    -> Target: ${t}"
    if ! cargo-deny --target "${t}" check advisories bans licenses sources; then
        record_target "${t}" "FAIL" "NOT_RUN" "NOT_RUN" "cargo-deny failed"
        TARGET_FAIL=1
        continue
    fi

    if ! cargo check -p mesh-core -p mesh-sys --target "${t}"; then
        record_target "${t}" "PASS" "FAIL" "NOT_RUN" "cargo check -p mesh-core -p mesh-sys failed"
        TARGET_FAIL=1
        continue
    fi

    can_check_ffi=0
    if [[ "${t}" == *-linux-android && -n "${ANDROID_NDK_DIR}" ]]; then
        can_check_ffi=1
    elif [[ "${t}" == *-apple-ios* && "${APPLE_SDK_OK}" -eq 1 ]]; then
        can_check_ffi=1
    fi

    if [[ "${can_check_ffi}" -eq 1 ]]; then
        ffi_ok=0
        if [[ "${t}" == *-linux-android && "${HAS_CARGO_NDK}" -eq 1 ]]; then
            abi=""
            case "${t}" in
                aarch64-linux-android) abi="arm64-v8a" ;;
                x86_64-linux-android) abi="x86_64" ;;
            esac
            if [[ -n "${abi}" ]]; then
                if cargo ndk -t "${abi}" --platform "${ANDROID_MIN_SDK}" check -p mesh-mobile-ffi; then
                    ffi_ok=1
                fi
            elif cargo check -p mesh-mobile-ffi --target "${t}"; then
                ffi_ok=1
            fi
        elif cargo check -p mesh-mobile-ffi --target "${t}"; then
            ffi_ok=1
        fi

        if [[ "${ffi_ok}" -eq 1 ]]; then
            record_target "${t}" "PASS" "PASS" "PASS" "Native SDK present; full FFI check passed"
        else
            record_target "${t}" "PASS" "PASS" "FAIL" "cargo check -p mesh-mobile-ffi failed"
            TARGET_FAIL=1
        fi
    else
        skip_msg="[SKIP - Host lacks NDK/Xcode SDK; enforced in mobile CI workflows]"
        echo "       ${skip_msg}"
        SKIPPED_FFI_COUNT=$((SKIPPED_FFI_COUNT + 1))
        record_target "${t}" "PASS" "PASS" "SKIP" "${skip_msg}"
    fi
done

t1="$(now_ms)"
if [[ "${TARGET_FAIL}" -ne 0 ]]; then
    record_step "step_2_mobile_targets" "5 Mobile Targets" "FAIL" "$((t1 - t0))" "One or more mobile target checks failed"
    exit 1
fi
record_step "step_2_mobile_targets" "5 Mobile Targets" "PASS" "$((t1 - t0))" "All 5 mobile targets passed cargo-deny + mesh-core/mesh-sys check (${SKIPPED_FFI_COUNT} FFI checks skipped due to missing NDK/Xcode SDK)."

# Step 3: Binary Size Budget (<= 6 MiB) & UniFFI Codegen
echo "==> [Step 3/5] Release Binary Size Budget (<= 6 MiB) & UniFFI Codegen..."
t0="$(now_ms)"
HOST_OS="$(uname -s)"
STEP3_NOTES=()

if [[ "${HOST_OS}" == "Linux" ]]; then
    if ! CARGO_PROFILE_RELEASE_OPT_LEVEL=z CARGO_PROFILE_RELEASE_LTO=fat cargo build --release -p mesh-mobile-ffi; then
        t1="$(now_ms)"
        record_step "step_3_size_and_bindgen" "Size Budget & UniFFI Codegen" "FAIL" "$((t1 - t0))" "Linux release build of mesh-mobile-ffi failed"
        exit 1
    fi
    SO_PATH="${REPO_ROOT}/target/release/libmesh_mobile_ffi.so"
    if [[ ! -f "${SO_PATH}" ]]; then
        t1="$(now_ms)"
        record_step "step_3_size_and_bindgen" "Size Budget & UniFFI Codegen" "FAIL" "$((t1 - t0))" "Missing ${SO_PATH}"
        exit 1
    fi
    MEASURED_BIN_BYTES="$(wc -c < "${SO_PATH}" | tr -d '[:space:]')"
    MEASURED_BIN_LABEL="target/release/libmesh_mobile_ffi.so"
    echo "    ${MEASURED_BIN_LABEL}: ${MEASURED_BIN_BYTES} bytes (budget <= ${MAX_SO_BYTES})"
    if (( MEASURED_BIN_BYTES > MAX_SO_BYTES )); then
        t1="$(now_ms)"
        record_step "step_3_size_and_bindgen" "Size Budget & UniFFI Codegen" "FAIL" "$((t1 - t0))" "${MEASURED_BIN_LABEL} (${MEASURED_BIN_BYTES} B) > ${MAX_SO_BYTES} B"
        exit 1
    fi
    STEP3_NOTES+=("${MEASURED_BIN_LABEL}=${MEASURED_BIN_BYTES}B (<=${MAX_SO_BYTES}B)")
    HOST_CDYLIB="${SO_PATH}"
elif [[ "${HOST_OS}" == "Darwin" ]]; then
    if [[ "${APPLE_SDK_OK}" -eq 1 ]] && rustup target list --installed | grep -qx "aarch64-apple-ios"; then
        if ! IPHONEOS_DEPLOYMENT_TARGET=15.0 CARGO_PROFILE_RELEASE_OPT_LEVEL=z CARGO_PROFILE_RELEASE_LTO=fat cargo build --release -p mesh-mobile-ffi --target aarch64-apple-ios; then
            t1="$(now_ms)"
            record_step "step_3_size_and_bindgen" "Size Budget & UniFFI Codegen" "FAIL" "$((t1 - t0))" "macOS aarch64-apple-ios release build failed"
            exit 1
        fi
        A_PATH="${REPO_ROOT}/target/aarch64-apple-ios/release/libmesh_mobile_ffi.a"
        MEASURED_BIN_BYTES="$(wc -c < "${A_PATH}" | tr -d '[:space:]')"
        MEASURED_BIN_LABEL="target/aarch64-apple-ios/release/libmesh_mobile_ffi.a"
        echo "    ${MEASURED_BIN_LABEL}: ${MEASURED_BIN_BYTES} bytes (budget <= ${MAX_SO_BYTES})"
        if (( MEASURED_BIN_BYTES > MAX_SO_BYTES )); then
            t1="$(now_ms)"
            record_step "step_3_size_and_bindgen" "Size Budget & UniFFI Codegen" "FAIL" "$((t1 - t0))" "${MEASURED_BIN_LABEL} (${MEASURED_BIN_BYTES} B) > ${MAX_SO_BYTES} B"
            exit 1
        fi
        STEP3_NOTES+=("${MEASURED_BIN_LABEL}=${MEASURED_BIN_BYTES}B (<=${MAX_SO_BYTES}B)")
    else
        STEP3_NOTES+=("[SKIP - Xcode SDK or aarch64-apple-ios target absent for .a slice size check]")
    fi

    if ! cargo build --release -p mesh-mobile-ffi; then
        t1="$(now_ms)"
        record_step "step_3_size_and_bindgen" "Size Budget & UniFFI Codegen" "FAIL" "$((t1 - t0))" "macOS host release build failed"
        exit 1
    fi
    HOST_CDYLIB="${REPO_ROOT}/target/release/libmesh_mobile_ffi.dylib"
else
    if ! cargo build --release -p mesh-mobile-ffi; then
        t1="$(now_ms)"
        record_step "step_3_size_and_bindgen" "Size Budget & UniFFI Codegen" "FAIL" "$((t1 - t0))" "Host release build failed"
        exit 1
    fi
    HOST_CDYLIB="${REPO_ROOT}/target/release/mesh_mobile_ffi.dll"
fi

mkdir -p "${BINDGEN_TMP}/kotlin" "${BINDGEN_TMP}/swift"
if ! cargo run -p mesh-uniffi-bindgen -- generate --library "${HOST_CDYLIB}" --language kotlin --out-dir "${BINDGEN_TMP}/kotlin"; then
    t1="$(now_ms)"
    record_step "step_3_size_and_bindgen" "Size Budget & UniFFI Codegen" "FAIL" "$((t1 - t0))" "mesh-uniffi-bindgen kotlin generation failed"
    exit 1
fi
if ! cargo run -p mesh-uniffi-bindgen -- generate --library "${HOST_CDYLIB}" --language swift --out-dir "${BINDGEN_TMP}/swift"; then
    t1="$(now_ms)"
    record_step "step_3_size_and_bindgen" "Size Budget & UniFFI Codegen" "FAIL" "$((t1 - t0))" "mesh-uniffi-bindgen swift generation failed"
    exit 1
fi

if ! python3 - "${BINDGEN_TMP}" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
required = [
    "MobileEngine",
    "PlatformNetworkBridge",
    "mobileEnrollOrRotateNode",
    "parseMobileJoinUri",
    "createPendingJoinSession",
    "completeRouteChange",
    "startTunnel",
    "stopTunnel",
    "shutdown",
]

for lang, ext in (("kotlin", "*.kt"), ("swift", "*.swift")):
    files = list((root / lang).rglob(ext))
    if not files:
        raise SystemExit(f"No {ext} files generated for {lang}")
    combined = "\n".join(f.read_text(encoding="utf-8") for f in files)
    missing = [sym for sym in required if not re.search(rf"\b{re.escape(sym)}\b", combined)]
    if missing:
        raise SystemExit(f"Missing UniFFI {lang} symbols: {', '.join(missing)}")
print(f"Verified {len(required)} UniFFI symbols in Kotlin and Swift bindings.")
PY
then
    t1="$(now_ms)"
    record_step "step_3_size_and_bindgen" "Size Budget & UniFFI Codegen" "FAIL" "$((t1 - t0))" "Required UniFFI FFI symbols missing in generated bindings"
    exit 1
fi

t1="$(now_ms)"
STEP3_NOTES+=("UniFFI Kotlin & Swift bindings generated and verified (9/9 symbols)")
record_step "step_3_size_and_bindgen" "Size Budget & UniFFI Codegen" "PASS" "$((t1 - t0))" "$(IFS='; '; echo "${STEP3_NOTES[*]}")"

# Step 4: Mobile Static Security Audit & Crate Tests
echo "==> [Step 4/5] Mobile Static Security Audit & Crate Tests..."
t0="$(now_ms)"
STEP4_NOTES=()

if [[ -f "lab/mobile/audit-mobile-security.sh" ]]; then
    if ! bash lab/mobile/audit-mobile-security.sh; then
        t1="$(now_ms)"
        record_step "step_4_security_and_tests" "Mobile Security Audit & Tests" "FAIL" "$((t1 - t0))" "lab/mobile/audit-mobile-security.sh failed"
        exit 1
    fi
    STEP4_NOTES+=("lab/mobile/audit-mobile-security.sh PASSED")
fi

if ! python3 - <<'PY'
import pathlib
import re
import sys

errors = []
manifest_p = pathlib.Path("mobile/android/app/src/main/AndroidManifest.xml")
if not manifest_p.is_file():
    errors.append("Missing AndroidManifest.xml")
else:
    manifest = manifest_p.read_text(encoding="utf-8")
    if 'android:allowBackup="false"' not in manifest:
        errors.append('AndroidManifest.xml missing android:allowBackup="false"')
    if 'android:scheme="mesh"' in manifest:
        errors.append('AndroidManifest.xml must not register android:scheme="mesh"')

kt_dir = pathlib.Path("mobile/android/app/src/main/kotlin")
found_init = False
if not kt_dir.is_dir():
    errors.append("Missing mobile/android/app/src/main/kotlin")
else:
    for p in kt_dir.rglob("*.kt"):
        text = p.read_text(encoding="utf-8")
        if "dev.meshvpn.android.ffi.MeshNativeInit" in text or re.search(r"\bobject\s+MeshNativeInit\b", text):
            found_init = True
        for idx, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue
            if "!!" in line:
                errors.append(f"Forbidden '!!' in {p}:{idx}")
if not found_init:
    errors.append("Missing dev.meshvpn.android.ffi.MeshNativeInit in Kotlin sources")

ios_dir = pathlib.Path("mobile/ios")
if not ios_dir.is_dir():
    errors.append("Missing mobile/ios")
else:
    for ext in ("*.plist", "*.entitlements"):
        for p in ios_dir.rglob(ext):
            text = p.read_text(encoding="utf-8")
            if "NSAllowsArbitraryLoads" in text:
                errors.append(f"Forbidden NSAllowsArbitraryLoads in {p}")
            if "CFBundleURLTypes" in text:
                errors.append(f"Forbidden CFBundleURLTypes in {p}")
    for prod in ("MeshApp", "MeshCoreKit", "MeshPacketTunnel"):
        pdir = ios_dir / prod
        if not pdir.is_dir():
            continue
        for p in pdir.rglob("*.swift"):
            for idx, line in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
                stripped = line.strip()
                if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                    continue
                code_only = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
                if re.search(r"\bfatalError\s*\(", code_only):
                    errors.append(f"Forbidden fatalError in {p}:{idx}")
                if re.search(r"\b(try|as)!", code_only):
                    errors.append(f"Forbidden try!/as! in {p}:{idx}")
                if re.search(r"[A-Za-z0-9_)\]]!(?!=)", code_only):
                    errors.append(f"Forbidden Swift force-unwrap '!' in {p}:{idx}")

bridge_p = pathlib.Path("crates/mesh-mobile-ffi/src/bridge.rs")
if not bridge_p.is_file() or '"identity.sealed.bin"' not in bridge_p.read_text(encoding="utf-8"):
    errors.append('Missing "identity.sealed.bin" in crates/mesh-mobile-ffi/src/bridge.rs')

if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print("Built-in Android/iOS/FFI static security audit PASSED.")
PY
then
    t1="$(now_ms)"
    record_step "step_4_security_and_tests" "Mobile Security Audit & Tests" "FAIL" "$((t1 - t0))" "Built-in static mobile security audit failed"
    exit 1
fi
STEP4_NOTES+=("Built-in Android/iOS/FFI static security audit PASSED")

if ! cargo test -p mesh-mobile-ffi -p mesh-client -p mesh --all-features; then
    t1="$(now_ms)"
    record_step "step_4_security_and_tests" "Mobile Security Audit & Tests" "FAIL" "$((t1 - t0))" "cargo test -p mesh-mobile-ffi -p mesh-client -p mesh --all-features failed"
    exit 1
fi

t1="$(now_ms)"
STEP4_NOTES+=("cargo test -p mesh-mobile-ffi -p mesh-client -p mesh --all-features PASSED")
record_step "step_4_security_and_tests" "Mobile Security Audit & Tests" "PASS" "$((t1 - t0))" "$(IFS='; '; echo "${STEP4_NOTES[*]}")"

echo "==> MOBILE QA SUITE PASSED!"
