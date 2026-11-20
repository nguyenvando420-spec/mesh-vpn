# Unified UI Readiness Requirements

> Cross-platform design synchronization specification for Mesh VPN desktop
> (Windows, macOS) and mobile (Android, iOS) applications.
>
> **Authored by**: Agile Researcher (UI Stream)
> **Decisions in scope**: DEC-UI-01 · DEC-UI-02 · DEC-UI-03 · DEC-UI-04
> **Baseline branch**: `feat/desktop-gui` @ v0.3.0 (desktop) / v0.2.0 (mobile)
> **Revision**: v1.1 — addresses `BLK-UUI-G1-01..03`, `HR-UUI-G1-01..03`,
> `MED-UUI-G1-02`, `LOW-UUI-G1-01` from Gate 1 Critique

---

## Table of Contents

1. [Platform Status Matrix](#1-platform-status-matrix)
2. [Design System Standards](#2-design-system-standards)
3. [Information Architecture](#3-information-architecture)
4. [Bilingual Standard (vi / en)](#4-bilingual-standard-vi--en)
5. [Production-Readiness Technical Specifications](#5-production-readiness-technical-specifications)
6. [Requirements Catalog (UUI-01 … UUI-xx)](#6-requirements-catalog)

---

## 1. Platform Status Matrix

Cross-platform audit of current implementation state against DEC-UI-01..04.
Every cell marked `[V]` was verified from the referenced source file.

### 1.1 State Machine

| Aspect | Windows (Rust) | macOS (Swift) | Android (Kotlin) | iOS (Swift) |
|---|---|---|---|---|
| **Enum type** | `DesktopUiState` (8 variants) `[V]` | `DesktopUiState` (8 cases) `[V]` | `MobileDaemonState` (FFI enum) `[V]` | `MeshTunnelConnectionStatus` (NEVPNStatus wrapper) `[V]` |
| **Source file** | `crates/mesh-gui/src/app.rs:20-37` | `MeshDesktopCore/.../DesktopUiState.swift:49-78` | `ui/status/StatusScreen.kt:34` (import) | `MeshApp/Sources/DashboardView.swift:305-312` |
| **Sub-state** | `TunnelSubState` (7 variants) `app.rs:103-112` `[V]` | `MenuBarStatusGroup` (5 cases) `DesktopUiState.swift:82-103` `[V]` | Implicit via `MobileDaemonState` name fields `[V]` | `NEVPNStatus` raw values (connected, connecting, reasserting, disconnecting, disconnected, invalid) `[V]` |
| **Derivation** | `derive_desktop_ui_state()` `app.rs:195` `[V]` | `DesktopStateMapper.compute()` `DesktopUiState.swift:315-367` `[V]` | Mapped in `StatusHeaderCard` composable `StatusScreen.kt:103-106` `[V]` | Mapped in `statusTitle` computed property `DashboardView.swift:304-312` `[V]` |

#### Desktop 8-State Cross-Reference

| # | Windows Rust Variant | Windows Label `[V]` | macOS Swift Case | macOS displayTitle `[V]` |
|---|---|---|---|---|
| 1 | `AgentUnavailable` | `"Agent Unavailable"` | `serviceNotInstalled` | `"Service Not Installed"` |
| 2 | `ServiceStopped` | `"Service Stopped"` | `serviceStopped` | `"Service Stopped"` |
| 3 | `NotEnrolled` | `"Not Enrolled"` | `unconfigured` | `"Not Enrolled"` |
| 4 | `Connecting` | `"Connecting"` | `connecting` | `"Connecting"` |
| 5 | `Connected` | `"Enrolled"` | `connected` | `"Connected"` |
| 6 | `ReauthRequired` | `"Re-auth Required"` | `reauthRequired` | `"Key Rotation Required"` |
| 7 | `Revoked` | `"Revoked"` | `revoked` | `"Device Revoked"` |
| 8 | `ErrorRecoverable` | `"Error (Recoverable)"` | `error` | `"Attention Required"` |

> **Gap — State #5 label ambiguity**: Windows `DesktopUiState::Connected.label()`
> returns `"Enrolled"` while macOS uses `"Connected"`. However, on Windows when
> `DaemonState::Stopped` + `enrolled == true`, the state maps to
> `(TunnelSubState::Disconnected, DesktopUiState::Connected)` (`app.rs:281-287`
> `[V]`), causing tray tooltip and status header to show misleading
> `"Status: Connected"` when the VPN is actually OFF. The canonical label for
> state #5 must vary by `TunnelSubState`: show `"Connected"` only when
> `TunnelSubState::Connected`, `"Degraded"` for `Degraded`, `"Disconnected"` for
> `Disconnected`, etc.
>
> **Gap — ReauthRequired color mismatch**: Windows maps `ReauthRequired` to
> `Amber` (`icons.rs:64` `[V]`), but macOS maps it to `.warning`
> (`menuBarGroup: .warning` → `exclamationmark.shield.fill` with `.red` tint at
> `DashboardWindowView.swift:300` `[V]`, `DesktopUiState.swift:338` `[V]`).
> Must unify to **Amber** per DEC-UI-03 semantic token `semantic.warning`.
>
> States 1 and 6-8 have divergent display labels requiring canonical unification.
> On Android, `StatusScreen.kt:118` `[V]` prints raw enum name
> `"State: ${session.daemonState.name}"` on `testTag("daemon_state_label")` —
> must map to canonical display labels.

#### Mobile State Cross-Reference

| # | Android `MobileDaemonState` `[V]` | iOS Status Title `[V]` |
|---|---|---|
| 1 | `STOPPED` | `"Disconnected"` |
| 2 | `DEVICE_LOCKED` | — (implicit) |
| 3 | `CONNECTING` | `"Connecting"` |
| 4 | `CONNECTED` | `"Connected"` |
| 5 | `DEGRADED` | `"Reconnecting"` (reasserting) |
| 6 | `REAUTH_REQUIRED` | — (via error) |
| 7 | `REVOKED` | — (via error) |

### 1.2 Color System

| Aspect | Windows | macOS | Android | iOS |
|---|---|---|---|---|
| **Token system** | Hardcoded RGB in `icons.rs:35-38` `[V]` | System appearance (AppKit/SwiftUI) `[V]` | Material3 `MeshTheme.kt` dynamic color scheme `[V]` | System SwiftUI colors `[V]` |
| **Tray/Badge tones** | 4 `UiIconTone` BGRA procedural `icons.rs:19-28` `[V]` | 5 `MenuBarStatusGroup` SF Symbol names `DesktopUiState.swift:89-102` `[V]` | N/A (notification icon only) | N/A |
| **Dark/Light toggle** | ❌ Not implemented (Linux CSS has `--bg: #0f172a` `app.css:4` `[V]`) | System appearance | ✅ `MeshTheme.kt:84-96` `isSystemInDarkTheme()` `[V]` | System appearance |
| **Brand primary** | — | — | `0xFF0B57D0` (Cobalt) `MeshTheme.kt:14` `[V]` | System `.accentColor` |

### 1.3 Internationalization (i18n)

| Aspect | Windows | macOS | Android | iOS |
|---|---|---|---|---|
| **Framework** | ❌ Hardcoded `&'static str` in `app.rs:42-98` `[V]` | ❌ Hardcoded `String` in `DesktopUiState.swift:59-78` `[V]` | ❌ English-only `strings.xml` (17 `<string>` tags, `strings.xml:3-19`) `[V]` | ✅ Partial — `Localizable.xcstrings` (13 `vi` translations) `[V]` |
| **Locale switch** | ❌ None | ❌ None | ❌ None | System only |
| **Coverage** | 0% vi | 0% vi | 0% vi | ~25% vi (13/~50+ strings) |

### 1.4 Navigation Structure

| Aspect | Windows | macOS | Android | iOS |
|---|---|---|---|---|
| **Layout** | Single Dashboard window + System Tray (9-item menu `tray.rs:21-37` `[V]`) | `Window("Mesh VPN", id: "dashboard")` + `MenuBarExtra` (`MeshApp.swift:111-138` `[V]`); connected state shows Segmented `Picker` **2 tabs** (`Peers` / `Diagnostics & Settings`) (`DashboardWindowView.swift:15-20,206-212` `[V]`) | 2-tab (`STATUS`/`SETTINGS` `MainTab` enum `MeshMainViewModel.kt:33-36` `[V]`) | Single NavigationView list (`DashboardView.swift:16-101` `[V]`) |
| **Onboarding** | Inline in Dashboard `window.rs` `[V]` | Sheet modal `[V]` | Dedicated `OnboardingScreen.kt` `[V]` | `OnboardingView.swift` `[V]` |
| **Peers view** | ListBox in Dashboard `peers_view.rs` `[V]` | `PeersTableView` with `HSplitView` inspector, 4-state `PeerFilter` (All/Online/Direct/Relay), Search, Copy Overlay IP/FQDN buttons (`PeersTableView.swift:13-20,161-166` `[V]`) | Inline `PeersSection` in StatusScreen `StatusScreen.kt:406-427` `[V]` | Inline `peersSection` in DashboardView `DashboardView.swift:187-210` `[V]` |

> **Gap — macOS tab visibility**: macOS 2-tab Picker only renders in `.connected`
> state (`DashboardWindowView.swift:203-222` `[V]`); other 7 states render
> `DashboardCenteredCard` full-frame with no access to Peers/Diagnostics/Settings.
> DEC-UI-01 requires the 3-tab navigation to be accessible across **all enrolled
> states** (not just `.connected`), including `connecting`, `reauthRequired`,
> `degraded`, and `error` — so users can always reach Settings (Theme/Language),
> Diagnostics (Netcheck/Bugreport), and maintenance actions (Rotate Key, Update
> Server/Pin) even when the tunnel is down.
>
> **Gap — Rotate Key & Update Server after enrollment**: On Windows, the
> Onboarding form controls (`IDC_EDIT_ENDPOINT..IDC_BTN_UPDATE_SERVER`) currently
> serve triple duty: initial enrollment, Rotate Key (`window.rs:745-749` `[V]`),
> and Update Server/Pin (`window.rs:740-743,1105-1120` `[V]`). Simply hiding the
> form when `is_enrolled == true` (per UUI-03) would remove access to Rotate Key
> and Update Server. These must be **relocated to Zone 3 (Diagnostics & Settings)**
> as dedicated CTA buttons/modals, with a ReauthRequired CTA in Zone 1 Header Hero.
>
> **Gap — `linux_gui.rs` compatibility**: `crates/mesh-gui/src/main.rs:9-29` `[V]`
> compiles `app.rs`, `diagnostics_view.rs`, `onboarding.rs`, `peers_view.rs` for
> both `target_os = "windows"` and `target_os = "linux"`. The `linux_gui.rs:574-602`
> `[V]` calls `filter_peers()`, `ui_state.label()`, `ui_state.headline()`,
> `ui_state.tray_tooltip_summary()`. Any signature changes to shared modules must
> maintain `clippy -D warnings` on `x86_64-unknown-linux-musl` via
> `scripts/check.ps1 -Cross`.

### 1.5 Test Infrastructure

| Platform | Test Files | Key Test Suites | Tags/Markers |
|---|---|---|---|
| **Windows** | `crates/mesh-gui/src/*.rs` (unit tests) | 23/23 from `run-desktop-qa.ps1` `[V]` | `#[test]`, `#[ignore = "privileged"]` |
| **macOS** | `DesktopStoreTests.swift` (23355B), `DesktopCoreTests.swift` (9368B) `[V]` | `DesktopStoreTests`, `DesktopCoreTests` | XCTest |
| **Android** | 10 unit tests, 3 instrumented tests incl. `OnboardingComposeUiTest.kt` `[V]` | Compose UI tests | `testTag("daemon_state_label")` `StatusScreen.kt:120` `[V]`, `testTag("toggle_tunnel_button")` `StatusScreen.kt:147` `[V]`; also asserts `"Verify Control Server Identity"` text `OnboardingComposeUiTest.kt:78` `[V]` |
| **iOS** | 5 test files incl. `TunnelLifecycleAndAppViewModelTests.swift` (11572B) `[V]` | `MeshVPNTests` | XCTest |

### 1.6 Security Invariants (Immutable)

| Invariant | Windows | macOS | Android | iOS |
|---|---|---|---|---|
| **SEC-01** `Secret<T>` / REDACTED | `preauth_key_raw` → `"[REDACTED]"` in `Debug` `onboarding.rs:42,80` `[V]` | `preauthKeySecret` → `[REDACTED]` in `description` `DesktopUiState.swift:175` `[V]` | `CharArray` submission + clipboard wipe `[V]` | Keychain sealed `[V]` |
| **SEC-04** Zero-TOFU | `should_lock_system_ca_for_endpoint()` `onboarding.rs:143` `[V]` | TLS auth mode picker `[V]` | FFI TLS validation `[V]` | TLS mode picker `DashboardView.swift:456-464` `[V]` |
| **SEC-05** Auth error | `format_user_facing_error()` sanitizer `app.rs:234` `[V]` | `MeshSecretScrubber.scrub()` `DesktopUiState.swift:229-244` `[V]` | `FfiErrorMapper` `[V]` | Scrubbed `[V]` |
| **FLAG_SECURE** | N/A | N/A | `requireFlagSecure` `MeshMainViewModel.kt:64-69` `[V]` | N/A |
| **Biometric gate** | N/A | N/A | `BiometricGate.kt` (5574B) `[V]` | `BiometricAuthorizer.swift` (`LAContext` Face ID/Touch ID/Passcode) `[V]` |
| **MGH1 UAC** | `build_handoff_payload()` `onboarding.rs:88-106` `[V]` | N/A | N/A | N/A |
| **Clipboard 30s wipe** | `ClipboardSecretGuard` + `TIMER_CLIPBOARD_WIPE` in GUI process `clipboard.rs:13,18-22` `[V]` | `clipboardWipeDelaySeconds = 30.0` `DesktopUiState.swift:17` `[V]` | `ClipboardAccess` `MeshMainViewModel.kt:79` `[V]` | Scrub on dispose `[V]` |
| **Binary budget** | `MeshVPN.exe ≤ 6 MiB` (actual 2.43 MiB) `[V]` | `Mesh VPN.app` `[V]` | `libmesh_mobile_ffi.so ≤ 6 MiB` `[V]` | Static lib `[V]` |
| **13-field AgentStatusResponse** | Used in `diagnostics_view.rs:14` `[V]` | Used via IPC `[V]` | Via FFI `MobileStatusSnapshot` `[V]` | Via FFI `MobileStatusSnapshot` `[V]` |

---

## 2. Design System Standards

### 2.1 Design Tokens — Color Palette (DEC-UI-03)

#### Surface & Background Tokens

| Token | Light Mode | Dark Mode | Usage |
|---|---|---|---|
| `surface.background` | `#F8FAFC` | `#0F172A` | App background |
| `surface.card` | `#FFFFFF` | `#1E293B` | Card / panel fill |
| `surface.border` | `#CBD5E1` | `#334155` | Dividers, outlines |
| `surface.text.primary` | `#0F172A` | `#F1F5F9` | Primary text |
| `surface.text.secondary` | `#475569` | `#94A3B8` | Secondary / caption |

#### Brand Tokens

| Token | Value | Usage |
|---|---|---|
| `brand.cobalt` | `#0B57D0` | Primary action, accent (light mode) |
| `brand.sky` | `#60A5FA` | Primary action, accent (dark mode) |
| `brand.teal` | `#0D9488` | Connected status accent (light mode) |
| `brand.teal.light` | `#2DD4BF` | Connected status accent (dark mode) |

#### Semantic Tokens

| Token | Light | Dark | Usage |
|---|---|---|---|
| `semantic.success` | `#16A34A` (Emerald 600) | `#4ADE80` (Emerald 400) | Connected state |
| `semantic.warning` | `#D97706` (Amber 600) | `#FBBF24` (Amber 400) | Connecting, Degraded, ReauthRequired |
| `semantic.error` | `#DC2626` (Coral/Red 600) | `#F87171` (Red 400) | Revoked, Error, destructive actions |
| `semantic.neutral` | `#6B7280` (Slate 500) | `#9CA3AF` (Slate 400) | Offline, unavailable |

> **Current state**: Windows `icons.rs:35-38` uses `[22,163,74]` = `#16A34A`,
> `[217,119,6]` = `#D97706`, `[220,38,38]` = `#DC2626`, `[107,114,128]` =
> `#6B7280` — matches Semantic tokens above `[V]`. Android `MeshTheme.kt:14` uses
> `0xFF0B57D0` matching `brand.cobalt` `[V]`.

### 2.2 Typography

| Element | Windows (Win32 GDI) | macOS (SwiftUI) | Android (Compose) | iOS (SwiftUI) |
|---|---|---|---|---|
| **System font** | `"Segoe UI"` via `CreateFontIndirectW` | SF Pro (system default) | Material3 default (`Roboto`) `[V]` | SF Pro (system default) |
| **Headline** | 20sp `FW_SEMIBOLD` | `.headline` | `titleMedium` `StatusScreen.kt:119` `[V]` | `.headline` `DashboardView.swift:109` `[V]` |
| **Body** | 14sp `FW_NORMAL` | `.body` | `bodyMedium` `StatusScreen.kt:229` `[V]` | `.subheadline` |
| **Caption** | 12sp `FW_NORMAL` | `.caption` | `labelMedium` `StatusScreen.kt:139` `[V]` | `.caption` / `.caption2` `DashboardView.swift:139,253` `[V]` |
| **Monospace** | `"Consolas"` for IP/FQDN | `.monospaced()` | `FontFamily.Monospace` `StatusScreen.kt:137` `[V]` | `.monospaced()` `DashboardView.swift:113,118` `[V]` |

### 2.3 Spacing System

| Token | dp/pt Value | Usage |
|---|---|---|
| `spacing.xs` | 2 dp | Intra-element (line spacing within card) |
| `spacing.sm` | 4 dp | Icon-to-label gap |
| `spacing.md` | 8 dp | Between controls in a row |
| `spacing.lg` | 12 dp | Card internal padding, between sections |
| `spacing.xl` | 16 dp | Screen edge padding, card outer padding |
| `spacing.xxl` | 24 dp | Between major sections |

> **Current state**: Android uses `12.dp` card padding, `16.dp` screen padding,
> `8.dp` section spacing `StatusScreen.kt:60,110` `[V]`. iOS uses SwiftUI default
> `List` spacing.

### 2.4 Iconography & Tray/Badge Mapping

#### System Tray / Menu Bar Status Icons

| State Group | Windows Tone `[V]` | Windows RGB `[V]` | macOS SF Symbol `[V]` | Semantic |
|---|---|---|---|---|
| Connected | `Green` | `#16A34A` | `checkmark.shield.fill` | ✅ Healthy tunnel |
| Connecting / Degraded | `Amber` | `#D97706` | `bolt.shield.fill` | ⚡ In-progress or degraded |
| Disconnected / Not Enrolled | `Gray` | `#6B7280` | `shield` | ⬜ Idle |
| Service Offline | `Gray` | `#6B7280` | `shield.slash` | ❌ No daemon |
| Warning / Error / Revoked | `Red` | `#DC2626` | `exclamationmark.shield.fill` | 🔴 Attention needed |

Sources: `icons.rs:19-28,56-74` `[V]`, `DesktopUiState.swift:82-102` `[V]`.

> **Action — Unify ReauthRequired tray color**: macOS currently maps
> `reauthRequired` to `MenuBarStatusGroup.warning` → `.red` tint
> (`DesktopUiState.swift:338` `[V]`), but Windows uses `Amber` (`icons.rs:64`
> `[V]`). Per DEC-UI-03 `semantic.warning` token, `ReauthRequired` must render
> as **Amber** on both platforms. macOS needs `reauthRequired` moved from
> `.warning` (red) to `.connecting` (amber/bolt icon) or a new `.reauthRequired`
> case with Amber tint.

#### Tray Context Menu (Windows — 9 Items)

| # | Item | Command ID `[V]` |
|---|---|---|
| 1 | Status header (disabled) | `IDM_STATUS_HEADER = 1001` |
| 2 | Open Dashboard | `IDM_OPEN_DASHBOARD = 1002` |
| 3 | Connect | `IDM_CONNECT_UP = 1003` |
| 4 | Disconnect | `IDM_DISCONNECT = 1004` |
| 5 | Run Netcheck Diagnostics | `IDM_NETCHECK = 1005` |
| 6 | Export Bugreport (.tar)... | `IDM_EXPORT_BUGREPORT = 1006` |
| 7 | Launch at Login (checkable) | `IDM_TOGGLE_AUTOSTART = 1007` |
| 8 | Quit Mesh VPN (Keep Connected) | `IDM_QUIT_KEEP_BACKGROUND = 1008` |
| 9 | Disconnect & Quit Mesh VPN | `IDM_DISCONNECT_AND_QUIT = 1009` |

Source: `tray.rs:21-37` `[V]`.

---

## 3. Information Architecture

### 3.1 Three-Zone Layout (DEC-UI-01)

```
┌─────────────────────────────────────────────────────┐
│  ZONE                        DEC-UI-01 DEFINITION   │
├─────────────────────────────────────────────────────┤
│  Status (Zone 1)      Connection state, toggle,     │
│                       overlay IP, telemetry,         │
│                       self-network summary,          │
│                       error/warning banners,         │
│                       CTA: ReauthRequired →          │
│                         "Rotate Key" action          │
├─────────────────────────────────────────────────────┤
│  Peers (Zone 2)       Search bar, 4-state filter,   │
│                       peer list w/ Path Badge, RTT,  │
│                       Copy IP/FQDN, Ping action,     │
│                       Ping result display            │
├─────────────────────────────────────────────────────┤
│  Diagnostics &        Netcheck + Bugreport export,   │
│  Settings (Zone 3)    Update Control Server / Pin,   │
│                       Rotate Node Key,               │
│                       Theme toggle (System/Light/    │
│                         Dark),                       │
│                       Language toggle (System/vi/en),│
│                       Reset Device Identity,         │
│                       Start/Repair Service (Desktop) │
└─────────────────────────────────────────────────────┘
```

**Onboarding** is a **separate flow** (not a tab), shown only when
`is_enrolled == false`. After enrollment, the onboarding form is hidden from the
main navigation. **Rotate Key** and **Update Server/Pin** actions (currently
embedded in Windows onboarding form `window.rs:740-749` `[V]`) must be
**relocated to Zone 3** as dedicated modals/dialogs, with a shortcut CTA in
Zone 1's ReauthRequired banner.

**Zone 3 accessibility rule**: The 3-tab navigation (Header Hero + Status /
Peers / Diagnostics & Settings) must be visible across **all enrolled states**,
not only `.connected`. Users must be able to access Theme/Language settings,
Netcheck/Bugreport, and maintenance actions even when in `connecting`,
`reauthRequired`, `degraded`, `revoked`, or `error` states. When
`is_enrolled == false`, Language/Theme settings and Service diagnostics should
still be accessible (e.g., via a reduced Settings surface or separate entry
point).

### 3.2 Desktop Layout Wireframe (Windows & macOS)

```
╔══════════════════════════════════════════════════════════╗
║  ┌─ Header Hero ────────────────────────────────────┐   ║
║  │  🟢 Connected to Mesh Network                    │   ║
║  │  100.64.0.5 — my-node.mesh                       │   ║
║  │  [Connect/Disconnect]                             │   ║
║  └───────────────────────────────────────────────────┘   ║
║                                                          ║
║  ┌─ Tab Bar ─────────────────────────────────────────┐   ║
║  │  [ Status ]  [ Peers ]  [ Diagnostics & Settings ]│   ║
║  └───────────────────────────────────────────────────┘   ║
║                                                          ║
║  ┌─ Tab Content Area ────────────────────────────────┐   ║
║  │                                                    │   ║
║  │  (Content varies by selected tab)                  │   ║
║  │                                                    │   ║
║  └───────────────────────────────────────────────────┘   ║
╚══════════════════════════════════════════════════════════╝
         + System Tray (Windows) / Menu Bar (macOS)
```

### 3.3 Mobile Layout Wireframe (Android & iOS)

```
╔══════════════════════════════╗
║  ┌─ App Bar ─────────────┐  ║
║  │  Mesh VPN    [Refresh] │  ║
║  └────────────────────────┘  ║
║                              ║
║  ┌─ Content Area ─────────┐  ║
║  │                         │  ║
║  │  (Scrollable content    │  ║
║  │   for selected tab)     │  ║
║  │                         │  ║
║  └─────────────────────────┘  ║
║                              ║
║  ┌─ Bottom Tab Bar ────────┐  ║
║  │  Status │ Peers │ Setgs  │  ║
║  └──────────────────────────┘  ║
╚══════════════════════════════╝
```

**Mobile Zone-to-Tab mapping**:

| Mobile Tab | Content (from Zone mapping) |
|---|---|
| **Status** | Connection toggle, state headline, overlay IP/FQDN, self-network telemetry (`SelfTelemetryCard`), warning banners, error actions |
| **Peers** | Search bar, 4-state filter, peer list with Path Badge/RTT, Copy IP/FQDN, Ping button + **Ping result display inline** |
| **Settings** | Netcheck + Bugreport export, Update Server/Pin, Rotate Key, Theme selector, Language selector, Reset Identity, Always-On hint |

> **Rationale**: `SelfTelemetry` stays in Status (Zone 1) as it shows the
> node's own network state. `Ping` results display inline in `Peers` tab so
> users see output in context of the peer they pinged. `Netcheck` and
> `Bugreport` move to `Settings` (Zone 3) alongside other diagnostics and
> maintenance actions, matching macOS `DiagnosticsSheetView` and Windows
> tray menu grouping. This is consistent across Android and iOS.

### 3.4 Desktop 8-State → Tray / Badge Mapping

| `DesktopUiState` | `TunnelSubState` | Icon Tone | Headline (canonical EN) |
|---|---|---|---|
| `AgentUnavailable` | — | Gray | Mesh Agent Unreachable |
| `ServiceStopped` | — | Gray | Windows Service Stopped / Not Installed |
| `NotEnrolled` | `NotEnrolled` | Gray | Set Up Mesh VPN |
| `Connecting` | `Connecting` | Amber | Connecting to Mesh Network... |
| `Connected` | `Connected` | Green | Connected to Mesh Network |
| `Connected` | `Degraded` | Amber | Connected (Degraded: Control Stream Offline) |
| `Connected` | `Disconnected` | Gray | Disconnected (Enrolled — Ready to Reconnect) |
| `ReauthRequired` | `ReauthRequired` | Amber | Node Key Expired — Re-auth Required |
| `Revoked` | `Revoked` | Red | Node Revoked — Identity Reset Required |
| `ErrorRecoverable` | — | Red | Action Failed (Recoverable) |

Sources: `app.rs:57-98` `[V]`, `icons.rs:56-74` `[V]`.

### 3.5 Peers Zone — Feature Specification (DEC-UI-01)

| Feature | Required | Current Windows `[V]` | Current macOS `[V]` | Current Android `[V]` | Current iOS `[V]` |
|---|---|---|---|---|---|
| **Search** | ✅ Substring (name, FQDN, IP, ID) | ✅ `filter_peers()` `peers_view.rs:27-48` (name, FQDN, IP, nodeId) | ⚠️ `filteredPeers` `PeersTableView.swift:22-41` — searches name, FQDN, IP but **missing `nodeId`** | ❌ None | ❌ None |
| **4-State Filter** | ✅ All / Online / Direct / Relay | ❌ None | ✅ `PeerFilter` enum (All/Online/Direct/Relay) `PeersTableView.swift:13-20` — **missing count badges** on filter chips | ❌ None | ❌ None |
| **Path Badge** | ✅ Direct / Relay / None | ✅ `format_peer_list_entry()` `peers_view.rs:52-73` | ✅ Inspector grid `PeersTableView.swift` | ✅ `peer.activePath.name` `StatusScreen.kt:480` | ✅ `pathSubtitle` `DashboardView.swift:400-406` |
| **RTT** | ✅ ms value | ✅ `rtt_ms` mapped `peers_view.rs:57-58` | ✅ `peer.rttMs` inspector `PeersTableView.swift:145` | ✅ `peer.rttMs` `StatusScreen.kt:481` | ✅ `peer.rttMs` `DashboardView.swift:402-403` |
| **Copy IP/FQDN** | ✅ Clipboard + toast | ❌ None | ⚠️ `copyToPasteboard()` → "Copy Overlay IP" / "Copy FQDN" buttons `PeersTableView.swift:161-166,220-224` — **no 30s wipe timer** (writes directly to `NSPasteboard.general`) | ❌ None | ❌ None |
| **Ping** | ✅ ICMP-over-tunnel | ✅ `format_ping_response()` `peers_view.rs:115-148` | ✅ "Ping Peer" button `PeersTableView.swift:168-176` | ✅ `onPingPeer` `StatusScreen.kt:425` | ✅ `Ping` button `DashboardView.swift:395` |

> **Copy IP/FQDN vs SEC-01 Clipboard Security**: Overlay IP (`100.64.0.x`) and
> FQDN (`*.mesh.internal`) are **non-secret network addresses**, not
> authentication credentials per SEC-01. The 30-second clipboard auto-wipe
> (`ClipboardSecretGuard` on Windows, `clipboardWipeDelaySeconds` on macOS) is
> reserved exclusively for SEC-01 secrets (`mpk_*` pre-auth keys,
> `mesh://join?...` URIs, private keys). Copy IP/FQDN should use standard
> clipboard copy with a toast confirmation, **without** `FLAG_SECURE` activation
> (which would cause screen blackout in Peers tab on Android), and **without**
> background clipboard read-back on Android 10+ (blocked by OS) or iOS 16+
> (triggers privacy paste banner). On Windows, Copy IP/FQDN must NOT share the
> same `ClipboardSecretGuard` timer as `mpk_*` wipe to avoid canceling the
> secret wipe prematurely.

### 3.6 Onboarding Flow — Cross-Platform

| Feature | Windows `[V]` | macOS `[V]` | Android `[V]` | iOS `[V]` |
|---|---|---|---|---|
| **Entry method** | Manual form + `mesh://` URI paste | Sheet modal + Manual/URI | QR scan + URI paste + Manual (`OnboardingMethod` enum `MeshMainViewModel.kt:38-42`) | QR scan + Manual |
| **TLS mode** | `OnboardingTlsMode` radio `onboarding.rs:19-24` | Picker `[V]` | FFI `MobileTlsAuthMode` `[V]` | Picker `DashboardView.swift:456-458` |
| **SPKI Pin** | `sha256:<64_hex>` validated `onboarding.rs:200-207` | Validated `[V]` | Validated via FFI `[V]` | Validated `[V]` |
| **Pre-auth key** | `Secret<String>` + masked preview `onboarding.rs:67,222` | `preauthKeySecret` + `wipeSecret()` `DesktopUiState.swift:139,167-169` | `CharArray` submission `SettingsScreen.kt:48` | `SecureField` `[V]` |
| **Confirmation** | Modal `format_confirmation_summary()` `onboarding.rs:110-138` | Sheet `EnrollmentConfirmationSheet` | Dialog `JoinConfirmationUiModel` `MeshMainViewModel.kt:44-50` | Sheet `EnrollmentConfirmationSheet` `DashboardView.swift:38-47` |
| **UAC/Elevation** | MGH1 handoff `build_handoff_payload()` `onboarding.rs:88` | N/A (admin socket `SO_PEERCRED`) | N/A (VPN permission) | N/A (NE permission) |

---

## 4. Bilingual Standard (vi / en)

### 4.1 Canonical Glossary

All UI-facing strings that must be translated. The `en` column is the canonical
source; `vi` translations are normative.

#### Navigation & Tabs

| Key | EN (canonical) | VI (canonical) | Context |
|---|---|---|---|
| `tab.status` | Status | Trạng thái | Tab / section header |
| `tab.peers` | Peers | Thiết bị cùng mạng | Tab / section header |
| `tab.settings` | Settings | Cài đặt | Tab / section header (mobile) |
| `tab.diagnostics_settings` | Diagnostics & Settings | Chẩn đoán & Cài đặt | Tab (desktop) |

#### Connection States

| Key | EN | VI | Source |
|---|---|---|---|
| `state.connected` | Connected | Đã kết nối | iOS `Localizable.xcstrings:29` `[V]` |
| `state.connecting` | Connecting | Đang kết nối | — |
| `state.disconnected` | Disconnected | Đã ngắt kết nối | iOS `Localizable.xcstrings:49` `[V]` |
| `state.degraded` | Degraded | Suy giảm | — |
| `state.reconnecting` | Reconnecting | Đang kết nối lại | — |
| `state.not_enrolled` | Not Enrolled | Chưa đăng ký | — |
| `state.agent_unavailable` | Agent Unavailable | Dịch vụ không sẵn sàng | — |
| `state.service_stopped` | Service Stopped | Dịch vụ đã dừng | — |
| `state.reauth_required` | Re-auth Required | Yêu cầu xác thực lại | — |
| `state.revoked` | Device Revoked | Thiết bị bị thu hồi | — |
| `state.error` | Attention Required | Cần xử lý | — |

#### Headlines (Desktop)

| Key | EN `[V]` | VI | Source |
|---|---|---|---|
| `headline.connected` | Connected to Mesh Network | Đã kết nối mạng Mesh | `app.rs:64` |
| `headline.degraded` | Connected (Degraded: Control Stream Offline) | Đã kết nối (Suy giảm: Kênh điều khiển ngoại tuyến) | `app.rs:65` |
| `headline.disconnected_enrolled` | Disconnected (Enrolled — Ready to Reconnect) | Đã ngắt (Đã đăng ký — Sẵn sàng kết nối lại) | `app.rs:66` |
| `headline.connecting` | Connecting to Mesh Network... | Đang kết nối mạng Mesh... | `app.rs:63` |
| `headline.setup` | Set Up Mesh VPN | Thiết lập Mesh VPN | `app.rs:62` |
| `headline.agent_unreachable` | Mesh Agent Unreachable | Dịch vụ Mesh không truy cập được | `app.rs:59` |
| `headline.service_stopped` | Windows Service Stopped / Not Installed | Dịch vụ Windows đã dừng / Chưa cài đặt | `app.rs:60` |
| `headline.reauth` | Node Key Expired — Re-auth Required | Khóa nút đã hết hạn — Yêu cầu xác thực lại | `app.rs:72` |
| `headline.revoked` | Node Revoked — Identity Reset Required | Nút bị thu hồi — Cần đặt lại danh tính | `app.rs:73` |
| `headline.error` | Action Failed (Recoverable) | Thao tác thất bại (Có thể khôi phục) | `app.rs:74` |

#### Action Buttons

| Key | EN | VI | Source |
|---|---|---|---|
| `action.connect` | Connect | Kết nối | iOS `Localizable.xcstrings:19` `[V]` |
| `action.disconnect` | Disconnect | Ngắt kết nối | iOS `Localizable.xcstrings:39` `[V]` |
| `action.connect_vpn` | Connect VPN | Kết nối VPN | Android `StatusScreen.kt:149` `[V]` |
| `action.disconnect_vpn` | Disconnect VPN | Ngắt kết nối VPN | Android `StatusScreen.kt:149` `[V]` |
| `action.enroll` | Enroll Mesh VPN | Đăng ký Mesh VPN | iOS `Localizable.xcstrings:59` `[V]` |
| `action.rotate_key` | Rotate Node Key | Xoay vòng khóa nút | iOS `Localizable.xcstrings:119` `[V]` |
| `action.reset_identity` | Reset Device Identity | Đặt lại danh tính thiết bị | iOS `Localizable.xcstrings:109` `[V]` |
| `action.export_bugreport` | Export Redacted Bugreport | Xuất báo lỗi đã che bí mật | iOS `Localizable.xcstrings:69` `[V]` |
| `action.run_netcheck` | Run Netcheck Diagnostics | Chạy chẩn đoán mạng | `tray.rs:109` `[V]` |
| `action.on_demand` | On-Demand Auto-Connect | Tự động kết nối On-Demand | iOS `Localizable.xcstrings:89` `[V]` |
| `action.scan_qr` | Scan Enrollment QR Code | Quét mã QR đăng ký | iOS `Localizable.xcstrings:129` `[V]` |
| `action.confirm_server` | Confirm Server | Xác nhận máy chủ | iOS `Localizable.xcstrings:9` `[V]` |
| `action.open_dashboard` | Open Dashboard | Mở bảng điều khiển | `tray.rs:87` `[V]` |
| `action.launch_at_login` | Launch at Login | Khởi chạy cùng hệ thống | `tray.rs:122` `[V]` |
| `action.quit_keep` | Quit Mesh VPN (Keep Connected in Background) | Thoát Mesh VPN (Giữ kết nối nền) | `tray.rs:131` `[V]` |
| `action.disconnect_quit` | Disconnect & Quit Mesh VPN | Ngắt kết nối & Thoát Mesh VPN | `tray.rs:138` `[V]` |
| `action.ping` | Ping | Ping | — |
| `action.review_rotation` | Review Rotation | Xem xét xoay khóa | `DashboardView.swift:425` `[V]` |
| `action.update_server` | Update Control Server | Cập nhật máy chủ điều khiển | `DashboardView.swift:278` `[V]` |
| `action.verify_save` | Verify & Save | Xác minh & Lưu | `DashboardView.swift:467` `[V]` |
| `action.verify_server_identity` | Verify Control Server Identity | Xác minh danh tính máy chủ điều khiển | `OnboardingComposeUiTest.kt:78` `[V]` — test-guarded string |

#### Warning Banners

| Key | EN | VI | Source |
|---|---|---|---|
| `warn.lockdown` | Always-On Lockdown Enabled | Chế độ luôn bật đã kích hoạt | `StatusScreen.kt:163` `[V]` |
| `warn.private_dns` | Strict Private DNS (:853) Active | DNS riêng nghiêm ngặt (:853) đang hoạt động | `StatusScreen.kt:173` `[V]` |
| `warn.legacy_agent` | Incompatible legacy agent (< 0.3.0) detected | Phát hiện agent cũ không tương thích (< 0.3.0) | `app.rs:208` `[V]` |
| `warn.version_mismatch` | Version mismatch: GUI {v1} vs Agent {v2} | Không khớp phiên bản: Giao diện {v1} vs Agent {v2} | `app.rs:218` `[V]` |

#### Error Messages

| Key | EN | VI | Notes |
|---|---|---|---|
| `error.clock_skew` | Date & Time Settings | Cài đặt ngày & giờ | `StatusScreen.kt:313` `[V]` |
| `error.captive_portal` | Network Settings | Cài đặt mạng | `StatusScreen.kt:316` `[V]` |
| `error.pin_mismatch` | Review Server Pin | Xem lại ghim máy chủ | `StatusScreen.kt:320` `[V]` |
| `error.reset_reenroll` | Reset & Re-enroll | Đặt lại & Đăng ký lại | `StatusScreen.kt:328` `[V]` |
| `error.auth_failed` | authentication failed | authentication failed | **SEC-05**: Wire-level error MUST remain English |

#### Tray Tooltips (Windows)

| Key | EN `[V]` | VI | Source |
|---|---|---|---|
| `tray.connected` | Mesh VPN - Connected | Mesh VPN - Đã kết nối | `app.rs:87` |
| `tray.connecting` | Mesh VPN - Connecting... | Mesh VPN - Đang kết nối... | `app.rs:85` |
| `tray.degraded` | Mesh VPN - Degraded (Control Offline) | Mesh VPN - Suy giảm (Điều khiển ngoại tuyến) | `app.rs:88` |
| `tray.disconnected` | Mesh VPN - Disconnected | Mesh VPN - Đã ngắt kết nối | `app.rs:89` |
| `tray.not_enrolled` | Mesh VPN - Not Enrolled | Mesh VPN - Chưa đăng ký | `app.rs:84` |
| `tray.agent_unavailable` | Mesh VPN - Agent Unavailable | Mesh VPN - Dịch vụ không sẵn sàng | `app.rs:82` |
| `tray.service_stopped` | Mesh VPN - Service Stopped | Mesh VPN - Dịch vụ đã dừng | `app.rs:83` |
| `tray.reauth` | Mesh VPN - Re-auth Required | Mesh VPN - Yêu cầu xác thực lại | `app.rs:95` |
| `tray.revoked` | Mesh VPN - Node Revoked | Mesh VPN - Nút bị thu hồi | `app.rs:96` |
| `tray.attention` | Mesh VPN - Attention Needed | Mesh VPN - Cần xử lý | `app.rs:97` |

#### Appearance & Theme

| Key | EN | VI | Context |
|---|---|---|---|
| `theme.appearance` | Appearance | Giao diện | Settings section header |
| `theme.system` | System | Hệ thống | Follow OS appearance |
| `theme.light` | Light | Sáng | Force light mode |
| `theme.dark` | Dark | Tối | Force dark mode |

#### Language

| Key | EN | VI | Context |
|---|---|---|---|
| `locale.language` | Language | Ngôn ngữ | Settings section header |
| `locale.system` | System | Hệ thống | Follow OS locale |
| `locale.vietnamese` | Tiếng Việt | Tiếng Việt | Force Vietnamese |
| `locale.english` | English | English | Force English |

#### Peer Filters, Badges & Search

| Key | EN | VI | Context |
|---|---|---|---|
| `peers.filter.all` | All | Tất cả | Filter chip — show all peers |
| `peers.filter.online` | Online | Trực tuyến | Filter chip — connected peers |
| `peers.filter.direct` | Direct | Trực tiếp | Filter chip — P2P path |
| `peers.filter.relay` | Relay | Chuyển tiếp | Filter chip — relayed path |
| `peers.badge.offline` | Offline | Ngoại tuyến | Peer status badge |
| `peers.badge.idle` | Idle | Nhàn rỗi | Peer status badge |
| `peers.search_placeholder` | Search peers... | Tìm thiết bị... | Search bar placeholder |
| `peers.copy_overlay_ip` | Copy Overlay IP | Sao chép IP lớp phủ | Context action; macOS `PeersTableView.swift:161` `[V]` |
| `peers.copy_fqdn` | Copy FQDN | Sao chép FQDN | Context action; macOS `PeersTableView.swift:166` `[V]` |
| `peers.copied_toast` | Copied to clipboard | Đã sao chép vào bộ nhớ tạm | Toast feedback |
| `peers.ping_selected` | Ping Selected Peer | Ping thiết bị đã chọn | Windows `window.rs:437` `[V]` |
| `peers.force_direct` | Force Direct P2P | Bắt buộc kết nối trực tiếp | macOS `PeersTableView.swift:178` `[V]` (if present) |
| `peers.section_header` | Peers & Diagnostics: | Thiết bị & Chẩn đoán: | Windows `window.rs:435` `[V]` |

#### Onboarding — Mobile (3-Tab: Scan QR / Paste URI / Manual)

| Key | EN | VI | Source |
|---|---|---|---|
| `onboarding.title` | Join Mesh Network | Tham gia mạng Mesh | `OnboardingScreen.kt:122` `[V]` |
| `onboarding.subtitle` | Scan an administrator QR or enter server fingerprint details. Automatic trust-on-first-use is disabled. | Quét mã QR từ quản trị viên hoặc nhập chi tiết vân tay máy chủ. Tự động tin tưởng lần đầu đã bị tắt. | `OnboardingScreen.kt:127-128` `[V]` |
| `onboarding.tab.scan_qr` | Scan QR | Quét QR | `OnboardingScreen.kt:151` `[V]` |
| `onboarding.tab.paste_uri` | Paste URI | Dán URI | `OnboardingScreen.kt:152` `[V]` |
| `onboarding.tab.manual` | Manual | Thủ công | `OnboardingScreen.kt:153` `[V]` |
| `onboarding.flag_secure` | Screen capture blocked (FLAG_SECURE) | Chặn chụp màn hình (FLAG_SECURE) | `OnboardingScreen.kt:137` `[V]` |
| `onboarding.import_uri` | Import mesh://join URI | Nhập URI mesh://join | `OnboardingScreen.kt:185` `[V]` |
| `onboarding.paste_clipboard` | Paste from Clipboard & Clear Immediately | Dán từ bộ nhớ tạm & Xóa ngay | `OnboardingScreen.kt:196` `[V]` |
| `onboarding.or_enter_uri` | Or enter mesh://join?... URI | Hoặc nhập URI mesh://join?... | `OnboardingScreen.kt:201` `[V]` |
| `onboarding.review_uri` | Review URI Details | Xem chi tiết URI | `OnboardingScreen.kt:223` `[V]` |
| `onboarding.review_server` | Review Server & Continue | Xem máy chủ & Tiếp tục | `OnboardingScreen.kt:312` `[V]` |
| `onboarding.control_server` | Control server (host:port) | Máy chủ điều khiển (host:port) | `OnboardingScreen.kt:252` `[V]` |
| `onboarding.spki_pin_label` | SPKI Pin (sha256:<64 hex>) | Ghim SPKI (sha256:<64 hex>) | `OnboardingScreen.kt:328` `[V]` |
| `onboarding.preauth_key` | Pre-auth Key (mpk_...) | Khóa xác thực trước (mpk_...) | `OnboardingScreen.kt:277` `[V]` |
| `onboarding.node_name` | Device Name (optional RFC 1123) | Tên thiết bị (RFC 1123, không bắt buộc) | `OnboardingScreen.kt:293` `[V]` |
| `onboarding.tls_spki_pin` | SPKI Pin (Default) | Ghim SPKI (Mặc định) | `OnboardingScreen.kt:353` `[V]` |
| `onboarding.tls_system_ca` | System CA (Domain) | CA hệ thống (Tên miền) | `OnboardingScreen.kt:358` `[V]` |
| `onboarding.connect_after` | Connect VPN immediately after enrollment | Kết nối VPN ngay sau khi đăng ký | `OnboardingScreen.kt:440` `[V]` |
| `onboarding.trust_connect` | Trust & Connect | Tin tưởng & Kết nối | `OnboardingScreen.kt:449` `[V]` |
| `onboarding.trust_enroll` | Trust & Enroll | Tin tưởng & Đăng ký | `OnboardingScreen.kt:449` `[V]` |

#### Onboarding — Desktop (2-Tab: Join URI / Manual Setup)

| Key | EN | VI | Source |
|---|---|---|---|
| `onboarding.desktop.title` | Join Mesh VPN Network | Tham gia mạng Mesh VPN | macOS `OnboardingSheetView.swift:68` `[V]` |
| `onboarding.desktop.subtitle` | Paste a mesh://join URI or enter your Control server details manually. | Dán URI mesh://join hoặc nhập chi tiết máy chủ điều khiển thủ công. | macOS `OnboardingSheetView.swift:89` `[V]` |
| `onboarding.desktop.tab.join_uri` | Join URI | URI tham gia | macOS `OnboardingSheetView.swift:27` `[V]` |
| `onboarding.desktop.tab.manual` | Manual Setup | Thiết lập thủ công | macOS `OnboardingSheetView.swift:28` `[V]` |
| `onboarding.desktop.review` | Review Connection Details | Xem chi tiết kết nối | macOS `OnboardingSheetView.swift:145` `[V]` |
| `onboarding.desktop.paste_uri` | Paste mesh:// URI | Dán URI mesh:// | Windows `window.rs:404` `[V]` |
| `onboarding.desktop.enroll_connect` | Enroll && Connect | Đăng ký && Kết nối | Windows `window.rs:424` `[V]` |
| `onboarding.desktop.setup_label` | Control Onboarding / Server Settings: | Hướng dẫn gia nhập / Cài đặt máy chủ: | Windows `window.rs:400` `[V]` |

#### Key Rotation

| Key | EN | VI | Source |
|---|---|---|---|
| `rotation.title` | Rotate Node Pre-Auth Key | Xoay vòng khóa xác thực nút | macOS `OnboardingSheetView.swift:68` `[V]` |
| `rotation.subtitle` | Provide a fresh mpk_ pre-auth key to renew this node's credentials. | Cung cấp khóa mpk_ mới để gia hạn chứng danh nút. | macOS `OnboardingSheetView.swift:87` `[V]` |
| `rotation.dialog_title` | Rotate Node Identity Key | Xoay vòng khóa danh tính nút | Android `SettingsScreen.kt:434` `[V]` |
| `rotation.new_key` | New Pre-auth Key | Khóa xác thực trước mới | Android `SettingsScreen.kt:441` `[V]` |
| `rotation.authorize` | Authorize & Rotate | Ủy quyền & Xoay vòng | Android `SettingsScreen.kt:461` `[V]` |
| `rotation.review_key` | Review Key Rotation | Xem xét xoay khóa | macOS `OnboardingSheetView.swift:273` `[V]` |
| `rotation.rotate_reconnect` | Rotate Key & Reconnect | Xoay khóa & Kết nối lại | macOS `OnboardingSheetView.swift:374` `[V]` |

#### Enrollment Confirmation

| Key | EN | VI | Source |
|---|---|---|---|
| `confirm.enrollment` | Confirm Mesh Node Enrollment | Xác nhận đăng ký nút Mesh | `onboarding.rs:121` `[V]` |
| `confirm.rotation` | Confirm Pre-Auth Key Rotation | Xác nhận xoay vòng khóa xác thực | `onboarding.rs:131` `[V]` |
| `confirm.verify_server` | Verify Control Server Identity | Xác minh danh tính máy chủ điều khiển | Android `OnboardingScreen.kt:412` `[V]` — test-guarded string |
| `confirm.verify_before_enroll` | Verify Server Trust Before Enrolling | Xác minh tin tưởng máy chủ trước khi đăng ký | macOS `OnboardingSheetView.swift:340` `[V]` |
| `confirm.confirm_rotation` | Confirm Key Rotation | Xác nhận xoay khóa | macOS `OnboardingSheetView.swift:339` `[V]` |
| `confirm.trust_connect` | Trust & Connect | Tin tưởng & Kết nối | macOS `OnboardingSheetView.swift:374` `[V]` |
| `confirm.back_edit` | Back / Edit | Quay lại / Sửa | macOS `OnboardingSheetView.swift:370` `[V]` |

#### Settings — Server & Security

| Key | EN | VI | Source |
|---|---|---|---|
| `settings.server_tls` | Control Server & TLS Pin | Máy chủ điều khiển & Ghim TLS | Android `SettingsScreen.kt:219` `[V]` |
| `settings.reveal_pin` | Reveal Full Pin | Hiện đầy đủ ghim | Android `SettingsScreen.kt:245` `[V]` |
| `settings.hide_pin` | Hide Pin | Ẩn ghim | Android `SettingsScreen.kt:245` `[V]` |
| `settings.update_server` | Update Server | Cập nhật máy chủ | Android `SettingsScreen.kt:249` `[V]` |
| `settings.update_dialog` | Update Control Server Config | Cập nhật cấu hình máy chủ điều khiển | Android `SettingsScreen.kt:377` `[V]` |
| `settings.authorize_save` | Authorize & Save | Ủy quyền & Lưu | Android `SettingsScreen.kt:413` `[V]` |
| `settings.server_endpoint` | Control Server Endpoint & SPKI Pin | Điểm cuối máy chủ & Ghim SPKI | macOS `DiagnosticsSheetView.swift:174` `[V]` |
| `settings.apply_update` | Apply Server Update | Áp dụng cập nhật máy chủ | macOS `DiagnosticsSheetView.swift:209` `[V]` |
| `settings.load_current` | Load Current | Tải cấu hình hiện tại | macOS `DiagnosticsSheetView.swift:205` `[V]` |

#### Settings — Identity Management

| Key | EN | VI | Source |
|---|---|---|---|
| `settings.identity_title` | Node Identity & Keystore DEK | Danh tính nút & Khóa DEK | Android `SettingsScreen.kt:270` `[V]` |
| `settings.rotate_key` | Rotate Key | Xoay vòng khóa | Android `SettingsScreen.kt:280` `[V]` |
| `settings.erase_identity` | Erase Identity | Xóa danh tính | Android `SettingsScreen.kt:290` `[V]` |
| `settings.erase_dialog` | Erase Local Mesh Identity? | Xóa danh tính Mesh cục bộ? | Android `SettingsScreen.kt:477` `[V]` |
| `settings.erase_detail` | This stops the tunnel and permanently wipes Android Keystore DEK, sealed identity keys, and bootstrap state on this device. | Thao tác này dừng đường hầm và xóa vĩnh viễn DEK, khóa danh tính đã niêm phong và trạng thái khởi tạo trên thiết bị. | Android `SettingsScreen.kt:480-481` `[V]` |
| `settings.authorize_erase` | Authorize & Erase | Ủy quyền & Xóa | Android `SettingsScreen.kt:492` `[V]` |

#### Settings — Boot & VPN

| Key | EN | VI | Source |
|---|---|---|---|
| `settings.boot_title` | Direct Boot & Always-On VPN | Khởi động trực tiếp & VPN luôn bật | Android `SettingsScreen.kt:308` `[V]` |
| `settings.auto_start` | Auto-start after unlock | Tự khởi động sau mở khóa | Android `SettingsScreen.kt:315` `[V]` |
| `settings.open_vpn_settings` | Open Android VPN Settings | Mở cài đặt VPN Android | Android `SettingsScreen.kt:324` `[V]` |

#### Settings — Diagnostics

| Key | EN | VI | Source |
|---|---|---|---|
| `settings.diag_title` | Scrubbed Diagnostics | Chẩn đoán đã che bí mật | Android `SettingsScreen.kt:342` `[V]` |
| `settings.export_share` | Export & Share Bugreport (Biometric) | Xuất & Chia sẻ báo lỗi (Sinh trắc học) | Android `SettingsScreen.kt:354` `[V]` |
| `settings.purge_bugreports` | Purge Cached Bugreports | Xóa báo lỗi đã lưu | Android `SettingsScreen.kt:357` `[V]` |
| `settings.section_header` | Settings & Security | Cài đặt & Bảo mật | Android `SettingsScreen.kt:82` `[V]` |

#### macOS — Service Lifecycle

| Key | EN | VI | Source |
|---|---|---|---|
| `service.start_repair` | Start / Repair Service | Khởi động / Sửa chữa dịch vụ | macOS `DashboardBannersAndCards.swift:96` `[V]` |
| `service.update` | Update Service | Cập nhật dịch vụ | macOS `DashboardBannersAndCards.swift:77` `[V]` |
| `service.update_recommended` | Background Service Update Recommended | Khuyến nghị cập nhật dịch vụ nền | macOS `DashboardBannersAndCards.swift:75` `[V]` |
| `service.cleanup_stale` | Clean Up Stale Network State | Dọn dẹp trạng thái mạng cũ | macOS `DiagnosticsSheetView.swift:238` `[V]` |
| `service.firewall_allow` | Allow macOS Firewall | Cho phép tường lửa macOS | macOS `DiagnosticsSheetView.swift:245` `[V]` |
| `service.reset_identity` | Reset Device Identity... | Đặt lại danh tính thiết bị... | macOS `DiagnosticsSheetView.swift:256` `[V]` |
| `service.uninstall` | Uninstall Service... | Gỡ cài đặt dịch vụ... | macOS `DiagnosticsSheetView.swift:261` `[V]` |
| `service.uninstall_title` | Uninstall Mesh VPN Background Service | Gỡ cài đặt dịch vụ nền Mesh VPN | macOS `DiagnosticsSheetView.swift:276` `[V]` |
| `service.purge_keys` | Also purge saved device identity keys | Đồng thời xóa khóa danh tính đã lưu | macOS `DiagnosticsSheetView.swift:286` `[V]` |

#### macOS — Diagnostics & Netcheck

| Key | EN | VI | Source |
|---|---|---|---|
| `diag.netcheck_title` | Network & NAT Diagnostics | Chẩn đoán mạng & NAT | macOS `DiagnosticsSheetView.swift:67` `[V]` |
| `diag.run_netcheck` | Run Netcheck | Chạy kiểm tra mạng | macOS `DiagnosticsSheetView.swift:70` `[V]` |
| `diag.bugreport_export` | Redacted Bugreport Export | Xuất báo lỗi đã che bí mật | macOS `DiagnosticsSheetView.swift:132` `[V]` |
| `diag.export_archive` | Export Daemon Diagnostics Archive (.tar) | Xuất tệp lưu trữ chẩn đoán daemon (.tar) | macOS `DiagnosticsSheetView.swift:135` `[V]` |
| `diag.export_button` | Export Bugreport... | Xuất báo lỗi... | macOS `DiagnosticsSheetView.swift:145` `[V]` |
| `diag.service_settings` | Diagnostics & Service Settings | Chẩn đoán & Cài đặt dịch vụ | macOS `DiagnosticsSheetView.swift:31` `[V]` |
| `diag.service_lifecycle` | Service Lifecycle & Recovery | Vòng đời dịch vụ & Khôi phục | macOS `DiagnosticsSheetView.swift:235` `[V]` |

#### macOS — Warning Banners

| Key | EN | VI | Source |
|---|---|---|---|
| `warn.subnet_conflict` | Local Network Subnet Conflict | Xung đột mạng con cục bộ | macOS `DashboardBannersAndCards.swift:25` `[V]` |
| `warn.firewall` | macOS Application Firewall Warning | Cảnh báo tường lửa ứng dụng macOS | macOS `DashboardBannersAndCards.swift:36` `[V]` |
| `warn.degraded_tunnel` | Tunnel Operating in Degraded Mode | Đường hầm hoạt động ở chế độ suy giảm | macOS `DashboardBannersAndCards.swift:50` `[V]` |
| `warn.degraded_detail` | Direct P2P paths are unavailable; traffic falls back via Relay. | Đường trực tiếp P2P không khả dụng; lưu lượng chuyển qua Relay. | macOS `DashboardBannersAndCards.swift:51` `[V]` |

#### Windows — Service & Dialogs

| Key | EN | VI | Source |
|---|---|---|---|
| `win.start_update_service` | Start / Update Service (UAC) | Khởi động / Cập nhật dịch vụ (UAC) | `window.rs:385` `[V]` |
| `win.cleanup` | Cleanup | Dọn dẹp | `window.rs:390` `[V]` |
| `win.reset_identity` | Reset Identity | Đặt lại danh tính | `window.rs:391` `[V]` |
| `win.netcheck` | Netcheck | Kiểm tra mạng | `window.rs:392` `[V]` |
| `win.bugreport` | Bugreport... | Báo lỗi... | `window.rs:393` `[V]` |
| `win.uninstall` | Uninstall... | Gỡ cài đặt... | `window.rs:395` `[V]` |
| `win.update_server_pin` | Update Server / Pin | Cập nhật máy chủ / Ghim | `window.rs:429` `[V]` |
| `win.confirm_reset` | Confirm Reset Identity | Xác nhận đặt lại danh tính | `window.rs:1560` `[V]` |
| `win.confirm_uninstall` | Uninstall Mesh VPN | Gỡ cài đặt Mesh VPN | `window.rs:1580` `[V]` |
| `win.purge_keys_q` | Purge Identity Keys? | Xóa khóa danh tính? | `window.rs:1590` `[V]` |

#### Biometric Prompts

| Key | EN | VI | Source |
|---|---|---|---|
| `biometric.verify_identity` | Verify identity | Xác minh danh tính | Android `strings.xml:16` `[V]` |
| `biometric.auth_subtitle` | Authenticate to perform sensitive Mesh VPN action | Xác thực để thực hiện thao tác nhạy cảm Mesh VPN | Android `strings.xml:17` `[V]` |
| `biometric.cancel` | Cancel | Hủy | Android `strings.xml:18` `[V]`, generic |

#### Android Notification Strings

| Key | EN `[V]` | VI | Source |
|---|---|---|---|
| `notif.app_name` | Mesh VPN | Mesh VPN | `strings.xml:3` |
| `notif.qs_tile` | Mesh VPN | Mesh VPN | `strings.xml:4` |
| `notif.channel_vpn` | Mesh VPN Tunnel | Đường hầm Mesh VPN | `strings.xml:5` |
| `notif.channel_alerts` | Mesh VPN Alerts | Cảnh báo Mesh VPN | `strings.xml:6` |
| `notif.title` | Mesh VPN | Mesh VPN | `strings.xml:7` |
| `notif.connected` | Connected (%1$s) | Đã kết nối (%1$s) | `strings.xml:8` |
| `notif.connecting` | Connecting to Mesh… | Đang kết nối Mesh… | `strings.xml:9` |
| `notif.degraded` | Control offline; P2P active | Điều khiển ngoại tuyến; P2P hoạt động | `strings.xml:10` |
| `notif.stopped` | Disconnected | Đã ngắt kết nối | `strings.xml:11` |
| `notif.waiting_unlock` | Waiting for device unlock to load VPN keys | Đang chờ mở khóa thiết bị để nạp khóa VPN | `strings.xml:12` |
| `notif.action_disconnect` | Disconnect | Ngắt kết nối | `strings.xml:13` |
| `notif.warn_lockdown` | Lockdown active: non-VPN internet is blocked by Android | Chế độ khóa: Android chặn internet ngoài VPN | `strings.xml:14` |
| `notif.warn_private_dns` | Strict Private DNS active: .mesh.internal may bypass Split-DNS | DNS riêng nghiêm ngặt: .mesh.internal có thể bỏ qua Split-DNS | `strings.xml:15` |
| `notif.share_bugreport` | Share scrubbed Mesh VPN diagnostics | Chia sẻ chẩn đoán Mesh VPN đã che bí mật | `strings.xml:19` |

#### Misc / Diagnostics (Legacy)

| Key | EN | VI | Source |
|---|---|---|---|
| `diag.tunnel_telemetry` | Tunnel Telemetry | Dữ liệu đường hầm | `StatusScreen.kt:345` `[V]` |
| `diag.network_check` | Network Check | Kiểm tra mạng | `StatusScreen.kt:388` `[V]` |
| `diag.no_peers` | No peers visible yet | Chưa có thiết bị nào | `StatusScreen.kt:418` `[V]` |
| `diag.bugreport_title` | Mesh VPN Minimized | Mesh VPN đã thu nhỏ | `tray.rs:240` `[V]` |
| `diag.bugreport_body` | Mesh VPN continues running in the System Tray. | Mesh VPN tiếp tục chạy trong khay hệ thống. | `tray.rs:241` `[V]` |
| `label.overlay` | Overlay | Lớp phủ mạng | `diagnostics_view.rs:24` `[V]` |
| `label.control` | Control | Điều khiển | `diagnostics_view.rs:71` `[V]` |
| `label.blind_relay` | Blind Relay | Chuyển tiếp ẩn | `StatusScreen.kt:360` `[V]` |
| `confirm.reset` | Reset Device Identity? | Đặt lại danh tính thiết bị? | `DashboardView.swift:89` `[V]` |
| `confirm.reset_detail` | This removes the VPN profile, sealed node keys, and Keychain DEK. | Thao tác này xóa cấu hình VPN, khóa nút đã niêm phong và DEK trong Keychain. | `DashboardView.swift:98` `[V]` |

#### Generic / Shared

| Key | EN | VI | Context |
|---|---|---|---|
| `generic.cancel` | Cancel | Hủy | Dialog dismiss button |
| `generic.close` | Close | Đóng | Sheet close button |
| `generic.dismiss` | Dismiss | Bỏ qua | Banner dismiss |
| `generic.refresh` | Refresh | Làm mới | Reload data |
| `generic.connect` | Connect | Kết nối | macOS `DashboardBannersAndCards.swift:230` `[V]` |
| `generic.disconnect` | Disconnect | Ngắt kết nối | macOS `DashboardBannersAndCards.swift:238` `[V]` |

### 4.2 i18n Implementation Gap Analysis

| Platform | Current State | Required Work |
|---|---|---|
| **Windows** | 0% — All strings are `&'static str` or `String::to_owned()` | Introduce string table module with `locale` parameter; load canonical glossary at startup |
| **macOS** | 0% — Hardcoded `displayTitle` etc. | Migrate to `String(localized:)` or `NSLocalizedString` with `Localizable.xcstrings` |
| **Android** | 0% — 17 English `<string>` tags in `values/strings.xml` (`strings.xml:3-19` `[V]`), no `values-vi/` | Add `values-vi/strings.xml`; map canonical glossary keys to `@string/` resources |
| **iOS** | ~25% — 13 vi translations in `Localizable.xcstrings` | Extend `Localizable.xcstrings` to cover all ~210+ canonical keys |

### 4.3 Locale Selection UX (DEC-UI-04)

- Settings screen exposes 3-way selector: **System / Tiếng Việt / English**
- Stored locally per-app (not synced to daemon)
- Daemon wire protocol, SEC-05 `"authentication failed"`, and JSON logs (`OPS-01`)
  remain English-only regardless of locale
- Switching locale takes effect immediately without daemon restart

---

## 5. Production-Readiness Technical Specifications

### 5.1 Windows — Win32 GDI/DWM Modern (DEC-UI-02)

#### 5.1.1 Double-Buffering

- ***(KN)* Gate 2**: Full double-buffering strategy (memory DC `BitBlt` +
  `WM_CTLCOLOR*` message handling for `EDIT`/`LISTBOX`/`BUTTON`/`STATIC`
  child controls) is deferred to Gate 2 implementation design.
- **Gate 1 scope**: Document that `WS_EX_COMPOSITED` alone is **insufficient**
  when mixed with classic `USER32` child controls (`EDIT`, `LISTBOX`) with
  scrollbars — causes black rendering artifacts and caret flicker on Windows
  10/11. Prefer `WS_EX_CLIPCHILDREN` combined with custom `WM_CTLCOLORSTATIC`,
  `WM_CTLCOLOREDIT`, `WM_CTLCOLORLISTBOX`, `WM_CTLCOLORBTN` message handlers
  to set background brush per-control.
- Reference: `window.rs` control IDs `IDC_STATUS_TITLE` through
  `IDC_EDIT_DETAILS` `[V]`; `gui_windows.rs:583-612` `WindowEventHandler` `[V]`

#### 5.1.2 RAII GDI Handle Guards

- **Separation of RAII wrappers** in `mesh-sys/gui_windows.rs`:
  - `OwnedGdiObj` (wraps `HGDIOBJ` via `DeleteObject`) — for `HBRUSH`, `HPEN`,
    `HFONT`, `HBITMAP`. **Must** call `SelectObject(hdc, old_stock_object)` to
    restore the original stock object **before** calling `DeleteObject` on the
    custom object; otherwise `DeleteObject` returns 0 and the handle leaks.
    Current impl: `gui_windows.rs:332-361` `OwnedGdiObj(HGDIOBJ)` +
    `DeleteObject(self.0)` `[V]`.
  - `OwnedMemDc` (wraps `HDC` from `CreateCompatibleDC` via **`DeleteDC`**) —
    **NOT** `DeleteObject`, which is undefined behavior on `HDC` handles.
  - `PaintGuard` (wraps `HDC` from `BeginPaint` via **`EndPaint`**) — must call
    `EndPaint(hwnd, &ps)` exactly once per `BeginPaint`.
  - `OwnedIcon` already wraps `HICON` via `DestroyIcon` `[V]` (used in
    `tray.rs:162` `TrayStateManager`)
- **Win32 has no `DestroyFont` API** — fonts are `HGDIOBJ` disposed via
  `DeleteObject` after `SelectObject` restoration.
- Monitor GDI handle count: `GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS)`
  — alert if > 5000 (Windows limit: 10000 per process)
- Zero GDI leak is a gate criterion (`ADR-020`)

#### 5.1.3 Theme Change Handling

- Handle `WM_SETTINGCHANGE` (system-wide registry change) and
  `WM_THEMECHANGED` (theme swap)
- On theme change: read registry key
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\AppsUseLightTheme`
  (DWORD: 0 = dark, 1 = light) — **do NOT use undocumented internal API
  `ShouldAppsUseDarkMode()` from `uxtheme.dll` ordinal #132**, which is not
  exported by name, not in `windows-sys`, and not guaranteed by Microsoft.
- Call `DwmSetWindowAttribute(DWMWA_USE_IMMERSIVE_DARK_MODE, &value)` to
  toggle titlebar dark/light — requires enabling `Win32_Graphics_Dwm` feature
  in `crates/mesh-sys/Cargo.toml` (currently not enabled `[V]`)
- Invalidate all cached brushes/pens; rebuild color tokens from Design System
  §2.1
- For `SPI_GETHIGHCONTRAST` / `HIGHCONTRASTW`: requires enabling
  `Win32_UI_Accessibility` feature in `crates/mesh-sys/Cargo.toml` (currently
  not enabled `[V]`)

#### 5.1.4 DPI Per-Monitor V2

- Already using `get_dpi_for_window()` and `get_sm_icon_px_for_dpi()`
  `tray.rs:188-189` `[V]`
- Handle `WM_DPICHANGED`: resize window, recalculate all layout metrics,
  regenerate procedural icons via `create_status_icon_for_px()` `icons.rs:127`
  `[V]`
- Font sizes scale with DPI via `CreateFontIndirectW` with
  `lfHeight = -MulDiv(pt, dpi, 72)`

#### 5.1.5 Accessibility & Keyboard Navigation

- All interactive controls must have `WS_TABSTOP` for keyboard `Tab` traversal
- Tab order: Status Hero → Tab Bar → Active Tab Content → Onboarding fields
- `WM_GETDLGCODE` returns `DLGC_WANTTAB` for custom controls
- Provide MSAA/UIA names for screen readers on status badge and peer list
- High-contrast mode: respect `SystemParametersInfoW(SPI_GETHIGHCONTRAST)`
  and fall back to system colors

#### 5.1.6 Dark Titlebar

- `DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &TRUE, 4)` on
  Windows 10 1903+ (build 18362+)
- Pair with matching `surface.background` dark token for client area
- Guard with runtime version check; no-op on older Windows

#### 5.1.7 Binary Budget & Build

- `MeshVPN.exe ≤ 6 MiB` (current: 2.43 MiB — 60% headroom) `[V]`
- `unsafe_code = "forbid"` in `crates/mesh-gui/Cargo.toml`; all unsafe in
  `crates/mesh-sys/src/gui_windows.rs` `[V]`
- `0` WebView, `0` embedded browser, `0` Chromium
- `#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]` `[V]`
- **Cross-compilation constraint**: `crates/mesh-gui/src/main.rs:9-29` `[V]`
  compiles `app.rs`, `diagnostics_view.rs`, `onboarding.rs`, `peers_view.rs`
  for both `target_os = "windows"` and `target_os = "linux"`. The
  `linux_gui.rs:574-602` `[V]` calls `filter_peers()`, `ui_state.label()`,
  `ui_state.headline()`, `ui_state.tray_tooltip_summary()`. Any signature
  changes to shared modules must maintain `clippy -D warnings` on
  `x86_64-unknown-linux-musl` via `scripts/check.ps1 -Cross`.

#### 5.1.8 Test Considerations

- Existing: 23 unit tests covering state derivation, tray menu model, peer
  formatting, onboarding validation, diagnostics formatting `[V]`
- Add: GDI handle leak test (`GetGuiResources` before/after window
  create/destroy cycle)
- Add: Theme toggle simulation test (mock `WM_SETTINGCHANGE`)
- Add: Tab keyboard navigation smoke test
- `count_non_separator_entries()` asserts exactly 9 tray menu items
  `tray.rs:149-154` `[V]`

### 5.2 macOS — SwiftUI/AppKit Menu Bar App

#### 5.2.1 Architecture

- `LSUIElement = true` — no Dock icon, Menu Bar only (`ADR-025`) `[V]`
- `Window("Mesh VPN", id: "dashboard")` as main dashboard
  (`MeshApp.swift:111-122` `[V]`), `defaultSize(860, 620)`, `minWidth: 760,
  minHeight: 540` (`DashboardWindowView.swift:113` `[V]`)
- `MenuBarExtra` with SF Symbol icons per `MenuBarStatusGroup`
  (`MeshApp.swift:128-138` `[V]`)
- In `connected` state: Segmented `Picker` with 2 tabs — `Peers` and
  `Diagnostics & Settings` (`DashboardTab` enum
  `DashboardWindowView.swift:15-20` `[V]`)
- Non-Sandboxed (requires Unix domain socket access to `/var/run/meshd/`) `[V]`

#### 5.2.2 Theme

- System appearance via SwiftUI `@Environment(\.colorScheme)`
- For manual toggle: `NSApp.appearance = NSAppearance(named: .darkAqua)` or
  `.aqua`
- SF Symbols automatically adapt to light/dark

#### 5.2.3 IPC & Constants

- `roSocketPath = "/var/run/meshd/meshd-ro.sock"` `[V]` (DesktopUiState.swift:28)
- `adminSocketPath = "/var/run/meshd/meshd-admin.sock"` `[V]` (DesktopUiState.swift:29)
- `clipboardWipeDelaySeconds = 30.0` `[V]` (DesktopUiState.swift:17)
- Admin socket auth: `xucred.cr_groups` GID==80 + fallback `getgrouplist`

#### 5.2.4 Privacy Logging

- `SafeOsLogger` wraps `os.Logger` with `%{private}@` for dynamic fields
  `DesktopUiState.swift:262-303` `[V]`
- `MeshSecretScrubber` regex scrubbing for `mpk_`, `mesh://join?`, PEM keys
  `DesktopUiState.swift:213-258` `[V]`

#### 5.2.5 Test Infrastructure

- `DesktopStoreTests.swift` (23 KiB) — covers `DesktopStateMapper`,
  `EnrollmentConfirmationDraft`, IPC error mapping `[V]`
- `DesktopCoreTests.swift` (9 KiB) — core validation tests `[V]`
- State derivation is pure (`DesktopStateMapper.compute()`) — easily testable
  without UI

### 5.3 Android — Jetpack Compose Material3

#### 5.3.1 Architecture

- `MeshMainViewModel` coordinates Compose UI with `MeshSessionRepository`
  `MeshMainViewModel.kt:76-80` `[V]`
- Current 2-tab: `MainTab.STATUS` / `MainTab.SETTINGS` → extend to 3 tabs
  `[V]`
- Material3 dynamic color via `MeshTheme` `MeshTheme.kt:84-96` `[V]`
- VPN lifecycle via Android `VpnService` + `NetworkExtension` FFI

#### 5.3.2 Security

- `FLAG_SECURE` guarded by `requireFlagSecure` property
  `MeshMainViewModel.kt:64-69` `[V]` — applied on onboarding, pin reveal,
  confirmation modals
- `BiometricGate.kt` (5574B) for admin operations `[V]`
- `ClipboardAccess` interface for 30s wipe `[V]`
- `CharArray` pre-auth key submission (not `String`) for zeroization
  `SettingsScreen.kt:48` `[V]`
- `PasswordVisualTransformation` for secret fields
  `SettingsScreen.kt:34` `[V]`

#### 5.3.3 Test Infrastructure

- Compose `testTag` markers: `"daemon_state_label"` `StatusScreen.kt:120` `[V]`,
  `"toggle_tunnel_button"` `StatusScreen.kt:147` `[V]`,
  `"error_card"` `StatusScreen.kt:287` `[V]`,
  `"warning_lockdown"` `StatusScreen.kt:167` `[V]`,
  `"warning_private_dns"` `StatusScreen.kt:177` `[V]`
- `OnboardingComposeUiTest.kt` — instrumented compose test; asserts `testTag`
  markers (`manual_endpoint_input`, `manual_pin_input`, `manual_preauth_input`,
  `manual_submit_button`, `confirm_join_button`) and text
  `"Verify Control Server Identity"` (`OnboardingComposeUiTest.kt:68-78` `[V]`)
  — these tags and strings must be preserved during refactoring
- 10 unit test files covering ViewModel, FFI, session state `[V]`

#### 5.3.4 i18n Readiness

- Current: `values/strings.xml` with 17 English-only `<string>` resources `[V]`
- Need: `values-vi/strings.xml` with canonical glossary
- ***(KN)* Gate 2 — runtime locale mechanism**: The concrete API for live
  locale switching is deferred to Gate 2 implementation design. Note:
  `MainActivity` extends `FragmentActivity` (`MainActivity.kt:50` `[V]`), and
  the project does **not** include `androidx.appcompat:appcompat`
  (`libs.versions.toml` `[V]`), so `AppCompatDelegate.setApplicationLocales()`
  is **not available**. Alternative approaches (e.g.,
  `CompositionLocalProvider(LocalContext provides localizedContext)` +
  `createConfigurationContext()`, or per-app language on API 33+
  `LocaleManager`) will be evaluated at Gate 2.
- Existing test guard: `OnboardingComposeUiTest.kt:78` `[V]` asserts
  `onNodeWithText("Verify Control Server Identity").assertIsDisplayed()` —
  this is a **direct UI text assertion** (not a testTag check), so it will
  break if the string is translated while the test runs under `vi` locale.
  Tests must run under default `en` locale; new separate Compose tests should
  verify `vi` display.

### 5.4 iOS — SwiftUI + NetworkExtension

#### 5.4.1 Architecture

- `AppViewModel` as `@MainActor ObservableObject`
  `AppViewModel.swift` `[V]`
- `DashboardView` single NavigationView list → migrate to `TabView` with 3 tabs
  `DashboardView.swift:16-101` `[V]`
- `MeshTunnelConnectionStatus` from `NEVPNStatus` `[V]`
- `MobileStatusSnapshot` from FFI `[V]`

#### 5.4.2 Security

- Keychain sealed node keys + DEK `[V]`
- `BiometricAuthorizer.swift` wraps `LAContext` with Face ID / Touch ID /
  Device Passcode fallback (`BiometricAuthOutcome` enum: authorized, cancelled,
  unavailable, failed) `[V]` — protocol `BiometricAuthorizing` enables test fakes
- `confirmationDialog` for destructive reset `DashboardView.swift:88-99` `[V]`
- `SecureField` for pre-auth key input `DashboardView.swift:419` `[V]`
- Share sheet for bugreport export with cleanup callback
  `DashboardView.swift:48-52` `[V]`

#### 5.4.3 i18n

- `Localizable.xcstrings` with 13 `vi` translations `[V]`
- Using String Catalog format (Xcode 15+) `[V]`
- Extend to cover all canonical glossary keys (~210+ strings)
- ***(KN)* Gate 2 — runtime locale mechanism**: `String(localized:)` reads
  `Locale.current` at process startup and is effectively static. For immediate
  locale switching without app restart (DEC-UI-04), use SwiftUI
  `.environment(\.locale, selectedLocale)` combined with a helper
  `localized(key:locale:)` or `Bundle(forLocalizationNamed:)`. Do **NOT**
  attempt `Locale.preferredLanguages` manipulation — it is a read-only
  property on Foundation.
- `MeshDesktopCore` (Swift Package at `desktop/macos/MeshDesktopCore/Package.swift`
  `[V]`) currently has no `defaultLocalization` declared; must add
  `defaultLocalization: "en"` and resource bundle for localized strings.

#### 5.4.4 Test Infrastructure

- `TunnelLifecycleAndAppViewModelTests.swift` (11572B) `[V]`
- `UniFFIBindingsAndSecurityTests.swift` (3218B) `[V]`
- 5 test files total in `MeshVPNTests` `[V]`
- `StatusBadge` visual component `DashboardView.swift:339-360` testable
  with SwiftUI previews

---

## 6. Requirements Catalog

### Legend

- **P0** — Must-have for milestone completion (gate criterion)
- **P1** — Should-have; planned for milestone but deferrable within sprint
- **P2** — Nice-to-have; deferred if capacity constrained
- **Platforms**: **W** = Windows, **M** = macOS, **A** = Android, **I** = iOS

### 6.1 Information Architecture (DEC-UI-01)

| ID | Priority | Platforms | Requirement | Verification Criteria |
|---|---|---|---|---|
| UUI-01 | P0 | W, M | Implement 3-tab horizontal navigation (Status / Peers / Diagnostics & Settings) with Header Hero | Tab bar renders; each tab shows correct zone content; keyboard Tab traversal works (W) |
| UUI-02 | P0 | A, I | Implement Bottom Tab Bar with 3 items (Status / Peers / Settings) | `BottomNavigation` / `TabView` renders; swipe between tabs; `testTag` on each tab |
| UUI-03 | P0 | W, M, A, I | Separate Onboarding flow from main navigation; hide when enrolled | After enrollment, onboarding form is not visible in any tab; `is_enrolled` check gates visibility |
| UUI-04 | P0 | W, M, A, I | Peers zone: Search bar with substring filter (name, FQDN, IP, **nodeId**) | Type query → list filters; clear → shows all; case-insensitive; macOS `filteredPeers` must add `nodeId` matching (currently missing `PeersTableView.swift:38-41` `[V]`) |
| UUI-05 | P0 | W, M, A, I | Peers zone: 4-state filter chips (All / Online / Direct / Relay) with **count badges** | Chip toggles filter; count badges update per filter; works with search; macOS `PeerFilter` must add count display (currently missing `PeersTableView.swift:73-79` `[V]`); `testTag` on filter chips (A) |
| UUI-06 | P1 | W, M, A, I | Peers zone: Copy IP/FQDN with toast feedback (non-secret, **no** `FLAG_SECURE`, **no** background clipboard read-back) | Copy button copies + toast; does NOT trigger `FLAG_SECURE` on Android; does NOT share `ClipboardSecretGuard` with `mpk_*` wipe on Windows; does NOT read clipboard back on iOS (avoids paste banner); macOS `copyToPasteboard()` as reference |
| UUI-07 | P1 | A, I | Peers zone: Path Badge (Direct/Relay/None) + RTT display per peer | Badge renders per `activePath`; RTT shows ms value or `"-"` |

### 6.2 Design System (DEC-UI-03)

| ID | Priority | Platforms | Requirement | Verification Criteria |
|---|---|---|---|---|
| UUI-08 | P0 | W | Implement Design Token system (§2.1) in GDI custom drawing | Colors match hex values in token table; verified via screenshot pixel sampling |
| UUI-09 | P0 | W | Dark/Light theme toggle in Settings with `DwmSetWindowAttribute` dark titlebar | Toggle switches theme; titlebar follows; `WM_SETTINGCHANGE` syncs system-wide |
| UUI-10 | P0 | M | Dark/Light/System theme selector in Settings | `NSApp.appearance` updated; Menu Bar icon adapts; persisted across launches |
| UUI-11 | P0 | A | Verify `MeshTheme.kt` colors match Design Token table (§2.1); add 3-way Theme Selector (System/Light/Dark) in Settings | Light/Dark color scheme values match canonical hex (note: `MeshTheme.kt` currently uses `0xFFF8F9FC` vs token `#F8FAFC`, `0xFF111318` vs `#0F172A`, `0xFFA8C7FA` vs `#60A5FA` — must reconcile `[V]`); `isSystemInDarkTheme()` default; Settings exposes System/Light/Dark picker |
| UUI-12 | P0 | I | Dark/Light/System theme selector in Settings | SwiftUI `preferredColorScheme` or `UIUserInterfaceStyle` override |
| UUI-13 | P1 | W | RAII `OwnedGdiObj` for all new GDI handles (brushes, pens, fonts for rounded cards, pills) | `GetGuiResources` before/after test shows zero leak; no raw `DeleteObject` calls |
| UUI-14 | P1 | W | Double-buffering via memory DC for custom-drawn controls | No visible flicker on resize, tab switch, or theme change |
| UUI-15 | P1 | W, M | Tray/Menu Bar icon tone matches §2.4 mapping table exactly; unify `ReauthRequired` to Amber | Icon color correct for each of 10 state+sub-state combinations; macOS `reauthRequired` currently maps to `.warning` → `.red` tint (`DesktopUiState.swift:338` `[V]`) — must change to Amber per `semantic.warning` token |

### 6.3 Bilingual (DEC-UI-04)

| ID | Priority | Platforms | Requirement | Verification Criteria |
|---|---|---|---|---|
| UUI-16 | P0 | W | Introduce string table module supporting `en`/`vi` from canonical glossary (§4.1) | All user-facing strings loaded from table; no hardcoded English in render path |
| UUI-17 | P0 | M | Migrate to `String(localized:)` with `.xcstrings` covering full glossary | All `displayTitle`, menu labels, sheet titles use localized strings |
| UUI-18 | P0 | A | Add `values-vi/strings.xml` covering full canonical glossary | `adb shell setprop persist.sys.locale vi-VN` → all strings display Vietnamese |
| UUI-19 | P0 | I | Extend `Localizable.xcstrings` from 13 to full glossary (~210+ keys) | Switch iOS locale to `vi` → all UI strings display Vietnamese |
| UUI-20 | P0 | W, M, A, I | Settings: 3-way locale selector (System / Tiếng Việt / English) | Switching locale updates all visible strings immediately without daemon restart |
| UUI-21 | P0 | W, M, A, I | SEC-05 `"authentication failed"` remains English on wire regardless of locale | Unit test asserts wire error string is `"authentication failed"` even when locale=vi |
| UUI-22 | P0 | W, M, A, I | JSON structured logs (`OPS-01`) remain English regardless of locale | Log file inspection confirms English keys and messages after locale switch |

### 6.4 Windows Production-Readiness (DEC-UI-02)

| ID | Priority | Platforms | Requirement | Verification Criteria |
|---|---|---|---|---|
| UUI-23 | P0 | W | Custom-drawn rounded cards for Status Hero and Peer cards | Rounded corners render correctly at 96/120/144/192 DPI |
| UUI-24 | P0 | W | Status pill badges with semantic colors | Pill renders with correct background color per state; text readable |
| UUI-25 | P0 | W | 3-tab bar custom control with hover/active states | Tab bar renders; click switches content; hover highlights; keyboard arrow keys move selection |
| UUI-26 | P0 | W | `WM_DPICHANGED` handling with full layout recalculation | Move window between monitors with different DPI; layout recalculates; icons regenerate |
| UUI-27 | P1 | W | `WM_THEMECHANGED` / `WM_SETTINGCHANGE` live reload | Change Windows theme in Settings → app updates within 1 frame |
| UUI-28 | P1 | W | Keyboard Tab traversal through all interactive controls | Tab cycles through controls in order; Enter activates focused control |
| UUI-29 | P1 | W | High-contrast mode fallback to system colors | Enable high-contrast → app remains usable; text readable |
| UUI-30 | P2 | W | MSAA/UIA accessibility names for screen reader support | Narrator announces status badge, peer names, button labels |
| UUI-31 | P1 | W | GDI handle leak test (gate: 0 leak after window lifecycle) | `GetGuiResources` delta == 0 after open+close+open cycle |
| UUI-32 | P0 | W | Binary ≤ 6 MiB; `unsafe_code = "forbid"` in mesh-gui | `cargo build --release` → check binary size; `cargo clippy` → no unsafe in mesh-gui |

### 6.5 Cross-Platform

| ID | Priority | Platforms | Requirement | Verification Criteria |
|---|---|---|---|---|
| UUI-33 | P0 | W, M, A, I | Unified state label glossary — all 4 platforms use canonical EN labels from §1.1 | State #5 desktop shows sub-state-aware label: `"Connected"` only when `TunnelSubState::Connected`, `"Degraded"` for `Degraded`, `"Disconnected"` for `Disconnected` (not misleading `"Enrolled"` — see §1.1 gap note `app.rs:281-287` `[V]`); state #6 shows `"Re-auth Required"` consistently; Android maps `MobileDaemonState.name` to canonical labels (not raw enum `StatusScreen.kt:118` `[V]`) |
| UUI-34 | P0 | W, M, A, I | Preserve all security invariants (§1.6) during refactoring | SEC-01, SEC-04, SEC-05, FLAG_SECURE, biometric, MGH1, clipboard 30s wipe, 13-field AgentStatusResponse — all existing tests pass |
| UUI-35 | P1 | W, M | Tray/Menu Bar context menu items use canonical bilingual strings | Menu items display in selected locale; `IDM_*` command IDs unchanged |
| UUI-36 | P1 | A, I | Notification/badge matches semantic color mapping (§2.4) | Android: `NotificationCompat.Builder.setColor()` in `MeshVpnService` uses correct semantic tint per connection state; iOS: `StatusBadge` in-app component (`DashboardView.swift:339-360` `[V]`) uses semantic colors — iOS has **no persistent notification icon** (uses NE status bar indicator only) |
| UUI-37 | P1 | W, M, A, I | Existing test suites pass with zero regression after UI refactoring | `scripts/check.ps1` / `check.sh` green; Android `./gradlew test`; iOS `xcodebuild test` |
| UUI-38 | P2 | A, I | Tablet/iPad adaptive layout (wider screens show 2-column peers) | On tablet/iPad landscape, Peers list renders in 2-column grid |

### Summary Statistics

| Priority | Count | Coverage |
|---|---|---|
| P0 | 24 | Core milestone gates |
| P1 | 12 | Should-have polish |
| P2 | 2 | Deferred enhancements |
| **Total** | **38** | |

---

## Appendix A — File Reference Index

| Platform | Key Files Read for `[V]` Verification |
|---|---|
| **Windows** | `crates/mesh-gui/src/app.rs`, `window.rs`, `icons.rs`, `tray.rs`, `onboarding.rs`, `peers_view.rs`, `diagnostics_view.rs`, `clipboard.rs`; `crates/mesh-gui/assets/linux_ui/app.css` |
| **macOS** | `desktop/macos/MeshDesktopCore/Sources/MeshDesktopCore/Models/DesktopUiState.swift`; `desktop/macos/MeshVPNApp/Sources/MeshApp.swift`, `DashboardWindowView.swift`, `PeersTableView.swift`, `OnboardingSheetView.swift`, `DiagnosticsSheetView.swift`, `DashboardBannersAndCards.swift`; `desktop/macos/project.yml` |
| **Android** | `mobile/android/app/src/main/kotlin/dev/meshvpn/android/ui/status/StatusScreen.kt`, `ui/settings/SettingsScreen.kt`, `ui/MeshMainViewModel.kt`, `ui/onboarding/OnboardingScreen.kt`, `ui/theme/MeshTheme.kt`; `app/src/main/res/values/strings.xml`; `app/src/androidTest/.../OnboardingComposeUiTest.kt`; `libs.versions.toml`, `MainActivity.kt` |
| **iOS** | `mobile/ios/MeshApp/Sources/DashboardView.swift`, `AppViewModel.swift`, `BiometricAuthorizer.swift`; `mobile/ios/MeshApp/Resources/Localizable.xcstrings` |
| **Docs** | `docs/03-system-design/desktop-gui-adr.md`, `desktop-gui-ipc-and-ui-contracts.md`, `mobile-adr.md`, `mobile-system-architecture.md`; `docs/04-sprint-management/agile-state.md` |
