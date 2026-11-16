#!/usr/bin/env sh
# lab/mobile/audit-mobile-security.sh
# Automated Mobile AppSec & Static Compliance Audit for Android, iOS, and mesh-mobile-ffi (US-096)
# POSIX sh compatible for Linux and macOS CI runners.

set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT="${1:-$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)}"

PASSED=0
FAILED=0

record_check() {
    id="$1"
    desc="$2"
    ok="$3"
    details="${4:-}"
    if [ "$ok" -eq 1 ]; then
        PASSED=$((PASSED + 1))
        printf '[PASS] %s: %s\n' "$id" "$desc"
    else
        FAILED=$((FAILED + 1))
        if [ -n "$details" ]; then
            printf '[FAIL] %s: %s -> %s\n' "$id" "$desc" "$details" >&2
        else
            printf '[FAIL] %s: %s\n' "$id" "$desc" >&2
        fi
    fi
}

strip_comments() {
    # Strip // line comments (sufficient for fast portable audit without python dependency; prefers python3 when present)
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$1" <<'PY'
import re, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    txt = fh.read()
txt = re.sub(r"/\*[\s\S]*?\*/", "", txt)
txt = re.sub(r"//.*", "", txt)
sys.stdout.write(txt)
PY
    else
        sed 's|//.*$||' "$1"
    fi
}

printf '=== Mobile Static Security Audit (US-096) ===\n'
printf 'RepoRoot: %s\n' "$REPO_ROOT"

MANIFEST="$REPO_ROOT/mobile/android/app/src/main/AndroidManifest.xml"
if [ -f "$MANIFEST" ] && grep -Eq 'android:allowBackup[[:space:]]*=[[:space:]]*"false"' "$MANIFEST"; then
    record_check "MOB-SEC-01" 'AndroidManifest.xml enforces android:allowBackup="false"' 1
else
    record_check "MOB-SEC-01" 'AndroidManifest.xml enforces android:allowBackup="false"' 0 "Missing android:allowBackup=false"
fi

if [ -f "$MANIFEST" ] && ! grep -Eq 'android:scheme[[:space:]]*=[[:space:]]*"mesh"|mesh://' "$MANIFEST"; then
    record_check "MOB-SEC-02" "AndroidManifest.xml defines 0 mesh:// deep-link intent-filters" 1
else
    record_check "MOB-SEC-02" "AndroidManifest.xml defines 0 mesh:// deep-link intent-filters" 0 "Found mesh:// scheme"
fi

EXTRACT_XML="$REPO_ROOT/mobile/android/app/src/main/res/xml/data_extraction_rules.xml"
FULL_BACKUP_XML="$REPO_ROOT/mobile/android/app/src/main/res/xml/full_backup_content.xml"
if [ -f "$EXTRACT_XML" ] && [ -f "$FULL_BACKUP_XML" ] &&
   grep -q 'identity\.sealed\.bin' "$EXTRACT_XML" && grep -q 'dek\.enc' "$EXTRACT_XML" &&
   grep -q 'identity\.sealed\.bin' "$FULL_BACKUP_XML" && grep -q 'dek\.enc' "$FULL_BACKUP_XML"; then
    record_check "MOB-SEC-03" "Android XML backup rules exclude identity.sealed.bin and dek.enc" 1
else
    record_check "MOB-SEC-03" "Android XML backup rules exclude identity.sealed.bin and dek.enc" 0 "Missing backup exclusions"
fi

KT_MAIN_DIR="$REPO_ROOT/mobile/android/app/src/main/kotlin"
KT_BANG_HITS=""
KT_GS_HITS=""
KT_TCP_HITS=""
KT_SEALED=0
KT_VERIFIER=0

if [ -d "$KT_MAIN_DIR" ]; then
    for kf in $(find "$KT_MAIN_DIR" -type f -name '*.kt' | sort); do
        stripped=$(strip_comments "$kf")
        if printf '%s' "$stripped" | grep -q '!!'; then
            KT_BANG_HITS="$KT_BANG_HITS $kf"
        fi
        if printf '%s' "$stripped" | grep -Eq '\bGlobalScope\b'; then
            KT_GS_HITS="$KT_GS_HITS $kf"
        fi
        if printf '%s' "$stripped" | grep -Eq '\bServerSocket\b'; then
            KT_TCP_HITS="$KT_TCP_HITS $kf"
        fi
        if printf '%s' "$stripped" | grep -q '"identity\.sealed\.bin"'; then
            KT_SEALED=1
        fi
        if printf '%s' "$stripped" | grep -q 'MeshNativeInit\.initPlatformVerifier' ||
           (printf '%s' "$stripped" | grep -Eq 'package[[:space:]]+dev\.meshvpn\.android\.ffi' &&
            printf '%s' "$stripped" | grep -Eq 'fun[[:space:]]+initPlatformVerifier'); then
            KT_VERIFIER=1
        fi
    done
fi

if [ -z "$KT_BANG_HITS" ] && [ -d "$KT_MAIN_DIR" ]; then
    record_check "MOB-SEC-04" "Android main Kotlin sources contain 0 non-null assertions (!!)" 1
else
    record_check "MOB-SEC-04" "Android main Kotlin sources contain 0 non-null assertions (!!)" 0 "$KT_BANG_HITS"
fi

if [ -z "$KT_GS_HITS" ] && [ -d "$KT_MAIN_DIR" ]; then
    record_check "MOB-SEC-05" "Android main Kotlin sources contain 0 GlobalScope usages" 1
else
    record_check "MOB-SEC-05" "Android main Kotlin sources contain 0 GlobalScope usages" 0 "$KT_GS_HITS"
fi

BAD_DEPS=""
for gf in $(find "$REPO_ROOT/mobile/android" -type f \( -name '*.kts' -o -name '*.toml' -o -name '*.pro' \) | sort); do
    stripped=$(strip_comments "$gf")
    if printf '%s' "$stripped" | grep -Eq 'EncryptedSharedPreferences|security-crypto|com\.google\.android\.gms|com\.google\.mlkit|ndk-context'; then
        BAD_DEPS="$BAD_DEPS $gf"
    fi
done
if [ -z "$BAD_DEPS" ]; then
    record_check "MOB-SEC-06" "Android Gradle/deps forbid EncryptedSharedPreferences, GMS, and ndk-context" 1
else
    record_check "MOB-SEC-06" "Android Gradle/deps forbid EncryptedSharedPreferences, GMS, and ndk-context" 0 "$BAD_DEPS"
fi

INIT_KT="$KT_MAIN_DIR/dev/meshvpn/android/ffi/MeshNativeInit.kt"
APP_KT="$KT_MAIN_DIR/dev/meshvpn/android/MeshApplication.kt"
PROGUARD="$REPO_ROOT/mobile/android/app/proguard-rules.pro"
if [ -f "$INIT_KT" ] && [ -f "$APP_KT" ] && [ -f "$PROGUARD" ] && [ "$KT_VERIFIER" -eq 1 ] &&
   grep -Eq 'package[[:space:]]+dev\.meshvpn\.android\.ffi' "$INIT_KT" &&
   grep -q 'initPlatformVerifier' "$INIT_KT" &&
   grep -q 'MeshNativeInit\.ensureInitialized' "$APP_KT" &&
   grep -q 'dev\.meshvpn\.android\.ffi\.MeshNativeInit' "$PROGUARD" &&
   grep -q 'org\.rustls\.platformverifier\.\*\*' "$PROGUARD"; then
    record_check "MOB-SEC-07" "Android JNI dev.meshvpn.android.ffi.MeshNativeInit.initPlatformVerifier & ProGuard keep rules verified" 1
else
    record_check "MOB-SEC-07" "Android JNI dev.meshvpn.android.ffi.MeshNativeInit.initPlatformVerifier & ProGuard keep rules verified" 0 "Missing JNI or ProGuard rules"
fi

URL_HITS=""
ATS_HITS=""
for plist in \
    "$REPO_ROOT/mobile/ios/MeshApp/Info.plist" \
    "$REPO_ROOT/mobile/ios/MeshPacketTunnel/Info.plist" \
    "$REPO_ROOT/mobile/ios/MeshCoreKit/Info.plist"; do
    if [ ! -f "$plist" ]; then
        URL_HITS="$URL_HITS MISSING:$plist"
        continue
    fi
    if grep -Eq 'CFBundleURLTypes|CFBundleURLSchemes|mesh://' "$plist"; then
        URL_HITS="$URL_HITS $plist"
    fi
    if grep -q 'NSAllowsArbitraryLoads' "$plist"; then
        ATS_HITS="$ATS_HITS $plist"
    fi
done
for ent in "$REPO_ROOT"/mobile/ios/Entitlements/*.entitlements; do
    [ -f "$ent" ] || continue
    if grep -q 'com\.apple\.developer\.associated-domains' "$ent"; then
        URL_HITS="$URL_HITS $ent"
    fi
done

if [ -z "$URL_HITS" ]; then
    record_check "MOB-SEC-08" "iOS Info.plist & Entitlements contain 0 CFBundleURLTypes/mesh:// deep links and 0 associated-domains" 1
else
    record_check "MOB-SEC-08" "iOS Info.plist & Entitlements contain 0 CFBundleURLTypes/mesh:// deep links and 0 associated-domains" 0 "$URL_HITS"
fi

if [ -z "$ATS_HITS" ]; then
    record_check "MOB-SEC-09" "iOS Info.plist files contain 0 NSAllowsArbitraryLoads" 1
else
    record_check "MOB-SEC-09" "iOS Info.plist files contain 0 NSAllowsArbitraryLoads" 0 "$ATS_HITS"
fi

SWIFT_FORCE_HITS=""
SWIFT_TCP_HITS=""
IOS_SEALED=0
for sf in $(find "$REPO_ROOT/mobile/ios/MeshApp/Sources" "$REPO_ROOT/mobile/ios/MeshCoreKit/Sources" "$REPO_ROOT/mobile/ios/MeshPacketTunnel/Sources" -type f -name '*.swift' 2>/dev/null | sort); do
    if grep -q '"identity\.sealed\.bin"' "$sf"; then
        IOS_SEALED=1
    fi
    if command -v python3 >/dev/null 2>&1; then
        if ! python3 - "$sf" <<'PY'
import re, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    raw = fh.read()
no_str = re.sub(r'"([^"\\]|\\.)*"', '""', raw)
no_blk = re.sub(r"/\*[\s\S]*?\*/", "", no_str)
code = re.sub(r"//.*", "", no_blk)
if re.search(r'\btry!|\bas!|\bfatalError\s*\(|[A-Za-z0-9_\)\]]!(?!=)', code):
    sys.exit(1)
PY
        then
            SWIFT_FORCE_HITS="$SWIFT_FORCE_HITS $sf"
        fi
    else
        stripped=$(strip_comments "$sf")
        if printf '%s' "$stripped" | grep -Eq '\btry!|\bas!|\bfatalError[[:space:]]*\('; then
            SWIFT_FORCE_HITS="$SWIFT_FORCE_HITS $sf"
        fi
    fi
    stripped=$(strip_comments "$sf")
    if printf '%s' "$stripped" | grep -Eq '\b(NWListener|ServerSocket)\b'; then
        SWIFT_TCP_HITS="$SWIFT_TCP_HITS $sf"
    fi
done

if [ -z "$SWIFT_FORCE_HITS" ]; then
    record_check "MOB-SEC-10" "iOS Swift production sources contain 0 !, try!, as!, and fatalError" 1
else
    record_check "MOB-SEC-10" "iOS Swift production sources contain 0 !, try!, as!, and fatalError" 0 "$SWIFT_FORCE_HITS"
fi

KEYCHAIN_SWIFT="$REPO_ROOT/mobile/ios/MeshCoreKit/Sources/KeychainDekStore.swift"
if [ -f "$KEYCHAIN_SWIFT" ] &&
   grep -q 'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly' "$KEYCHAIN_SWIFT" &&
   grep -q 'kSecAttrSynchronizable' "$KEYCHAIN_SWIFT" &&
   grep -Eq 'kCFBooleanFalse|\bfalse\b' "$KEYCHAIN_SWIFT"; then
    record_check "MOB-SEC-11" "iOS Keychain uses kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly and kSecAttrSynchronizable=false" 1
else
    record_check "MOB-SEC-11" "iOS Keychain uses kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly and kSecAttrSynchronizable=false" 0 "Missing Keychain flags"
fi

TUNNEL_MGR_SWIFT="$REPO_ROOT/mobile/ios/MeshCoreKit/Sources/TunnelManagerClient.swift"
ON_DEMAND_OK=0
if [ -f "$TUNNEL_MGR_SWIFT" ]; then
    line_ondemand=$(grep -n 'isOnDemandEnabled = false' "$TUNNEL_MGR_SWIFT" | head -n1 | cut -d: -f1 || true)
    line_stop=$(grep -n 'manager\.stopTunnel(' "$TUNNEL_MGR_SWIFT" | head -n1 | cut -d: -f1 || true)
    if [ -n "$line_ondemand" ] && [ -n "$line_stop" ] && [ "$line_ondemand" -lt "$line_stop" ]; then
        ON_DEMAND_OK=1
    fi
fi
record_check "MOB-SEC-12" "iOS TunnelManagerClient disables isOnDemandEnabled = false before stopTunnel()" "$ON_DEMAND_OK" "Missing isOnDemandEnabled ordering"

if [ "$KT_SEALED" -eq 1 ] && [ "$IOS_SEALED" -eq 1 ]; then
    record_check "MOB-SEC-13" 'Both Android and iOS use sealed identity filename "identity.sealed.bin"' 1
else
    record_check "MOB-SEC-13" 'Both Android and iOS use sealed identity filename "identity.sealed.bin"' 0 "Missing identity.sealed.bin"
fi

MPK_LEAK=""
for ptf in $(find "$REPO_ROOT/mobile/ios/MeshPacketTunnel" -type f -name '*.swift' | sort); do
    if grep -Eq 'mpk_[A-Za-z0-9_-]{4,}' "$ptf"; then
        MPK_LEAK="$MPK_LEAK $ptf"
    fi
done
PTP_SWIFT="$REPO_ROOT/mobile/ios/MeshPacketTunnel/Sources/PacketTunnelProvider.swift"
CONSTANTS_SWIFT="$REPO_ROOT/mobile/ios/MeshCoreKit/Sources/MeshConstants.swift"
if [ -z "$MPK_LEAK" ] && [ -f "$CONSTANTS_SWIFT" ] && grep -q 'isForbiddenProviderConfigKey' "$CONSTANTS_SWIFT" &&
   grep -q '"mpk"' "$CONSTANTS_SWIFT" && grep -q '"preauth"' "$CONSTANTS_SWIFT" &&
   [ -f "$PTP_SWIFT" ] && grep -q 'validateNoSecretOptions' "$PTP_SWIFT" && grep -q 'isForbiddenProviderConfigKey' "$PTP_SWIFT" &&
   [ -f "$TUNNEL_MGR_SWIFT" ] && grep -q 'buildValidatedProviderConfiguration' "$TUNNEL_MGR_SWIFT" &&
   grep -q 'isForbiddenProviderConfigKey' "$TUNNEL_MGR_SWIFT"; then
    record_check "MOB-SEC-14" "0 mpk_* preauth keys passed into MeshPacketTunnel (both app and extension enforce rejection)" 1
else
    record_check "MOB-SEC-14" "0 mpk_* preauth keys passed into MeshPacketTunnel (both app and extension enforce rejection)" 0 "$MPK_LEAK"
fi

if [ -z "$KT_TCP_HITS" ] && [ -z "$SWIFT_TCP_HITS" ]; then
    record_check "MOB-SEC-15" "0 TCP listeners in Android/iOS sources (IPC stays in-process / platform bridge)" 1
else
    record_check "MOB-SEC-15" "0 TCP listeners in Android/iOS sources (IPC stays in-process / platform bridge)" 0 "$KT_TCP_HITS $SWIFT_TCP_HITS"
fi

FFI_VIOLATIONS=""
for rf in "$REPO_ROOT"/crates/mesh-mobile-ffi/src/*.rs; do
    [ -f "$rf" ] || continue
    if command -v python3 >/dev/null 2>&1; then
        if ! python3 - "$rf" <<'PY'
import re, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    raw = fh.read()
prod = raw.split("#[cfg(test)]", 1)[0]
prod = re.sub(r"/\*[\s\S]*?\*/", "", prod)
prod = re.sub(r"//.*", "", prod)
if re.search(r'\.unwrap\s*\(|\.expect\s*\(|\bunsafe\b', prod):
    sys.exit(1)
PY
        then
            FFI_VIOLATIONS="$FFI_VIOLATIONS $rf"
        fi
    fi
done
if [ -z "$FFI_VIOLATIONS" ]; then
    record_check "MOB-SEC-16" "crates/mesh-mobile-ffi/src production code has 0 .unwrap(), 0 .expect(), and 0 hand-written unsafe" 1
else
    record_check "MOB-SEC-16" "crates/mesh-mobile-ffi/src production code has 0 .unwrap(), 0 .expect(), and 0 hand-written unsafe" 0 "$FFI_VIOLATIONS"
fi

printf '\nSummary: %d passed, %d failed.\n' "$PASSED" "$FAILED"
if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
