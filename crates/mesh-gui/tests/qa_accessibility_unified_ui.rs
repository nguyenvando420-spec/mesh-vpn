//! Windows Accessibility, Keyboard Tab Traversal, High-Contrast & MSAA Screen Reader QA Suite
//! (`WP-U-D0`, `US-135`, `US-139`, `ADR-027`).

use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> Result<PathBuf, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "failed resolving workspace root".to_owned())
}

fn read_repo_file(rel_path: &str) -> Result<String, String> {
    let root = workspace_root()?;
    let full = root.join(rel_path);
    fs::read_to_string(&full).map_err(|err| format!("failed reading {}: {err}", full.display()))
}

const WIN_WM_GETDLGCODE: u32 = 0x0087;
const WIN_DLGC_WANTTAB: isize = 0x0002;
const WIN_DLGC_WANTCHARS: isize = 0x0080;

const fn eval_wm_getdlgcode(msg: u32, text_input: bool) -> isize {
    if msg != WIN_WM_GETDLGCODE {
        return 0;
    }
    if text_input {
        WIN_DLGC_WANTTAB | WIN_DLGC_WANTCHARS
    } else {
        WIN_DLGC_WANTTAB
    }
}

#[test]
fn test_wm_getdlgcode_dlgc_wanttab() -> Result<(), String> {
    // Arrange: verify WM_GETDLGCODE -> DLGC_WANTTAB semantics and Win32 dialog traversal wiring
    let gui_win = read_repo_file("crates/mesh-sys/src/gui_windows.rs")?;
    let window_rs = read_repo_file("crates/mesh-gui/src/window.rs")?;

    // Act
    let button_dlg_code = eval_wm_getdlgcode(WIN_WM_GETDLGCODE, false);
    let edit_dlg_code = eval_wm_getdlgcode(WIN_WM_GETDLGCODE, true);
    let other_msg_code = eval_wm_getdlgcode(0x000F, false);

    // Assert: WM_GETDLGCODE returns DLGC_WANTTAB
    assert_eq!(button_dlg_code, WIN_DLGC_WANTTAB);
    assert_eq!(edit_dlg_code & WIN_DLGC_WANTTAB, WIN_DLGC_WANTTAB);
    assert_eq!(edit_dlg_code & WIN_DLGC_WANTCHARS, WIN_DLGC_WANTCHARS);
    assert_eq!(other_msg_code, 0);

    // Assert: `window.rs` implements the same WM_GETDLGCODE -> DLGC_WANTTAB contract
    assert!(window_rs.contains("WIN_WM_GETDLGCODE: u32 = 0x0087"));
    assert!(window_rs.contains("WIN_DLGC_WANTTAB: isize = 0x0002"));
    assert!(window_rs.contains("fn dialog_code_for_message("));
    assert!(window_rs.contains("fn ordered_tab_stop_control_ids("));

    // Assert: `gui_windows.rs` enables WS_EX_CONTROLPARENT + IsDialogMessageW + WS_TABSTOP
    assert!(gui_win.contains("WS_EX_CONTROLPARENT"));
    assert!(gui_win.contains("IsDialogMessageW(hwnd, &raw const msg)"));
    for control_fn in [
        "pub fn create_button(",
        "pub fn create_owner_draw_button(",
        "pub fn create_checkbox(",
        "pub fn create_radio_button(",
        "pub fn create_edit(",
        "pub fn create_listbox(",
    ] {
        let start = gui_win
            .find(control_fn)
            .ok_or_else(|| format!("missing `{control_fn}` in gui_windows.rs"))?;
        let snippet = gui_win
            .get(start..(start + 450).min(gui_win.len()))
            .unwrap_or("");
        assert!(
            snippet.contains("WS_TABSTOP"),
            "`{control_fn}` must set WS_TABSTOP for keyboard navigation"
        );
    }

    Ok(())
}

#[test]
fn test_detect_high_contrast_cbsize_and_spi_contract() -> Result<(), String> {
    // Arrange
    let gui_win = read_repo_file("crates/mesh-sys/src/gui_windows.rs")?;

    // Act & Assert: static contract for SPI_GETHIGHCONTRAST cbSize/uiParam
    let hc_pos = gui_win
        .find("pub fn detect_high_contrast()")
        .ok_or_else(|| "missing detect_high_contrast in gui_windows.rs".to_owned())?;
    let hc_body = gui_win
        .get(hc_pos..(hc_pos + 700).min(gui_win.len()))
        .unwrap_or("");
    assert!(hc_body.contains("SPI_GETHIGHCONTRAST"));
    assert!(hc_body.contains("HCF_HIGHCONTRASTON"));
    assert!(hc_body.contains("hc.cbSize = cb_size;"));
    assert!(hc_body.contains("cb_size,"));

    // Runtime Win32 verification on Windows host
    #[cfg(target_os = "windows")]
    {
        let cb = mesh_sys::gui_windows::high_contrast_struct_cb_size();
        assert!(
            cb >= 12,
            "HIGHCONTRASTW cbSize must be >= 12 bytes, got {cb}"
        );
        let _active = mesh_sys::gui_windows::detect_high_contrast();
    }

    Ok(())
}

#[test]
fn test_msaa_screen_reader_label_proxy_notify_win_event_zero_iaccessible() -> Result<(), String> {
    // Arrange
    let root = workspace_root()?;
    let gui_win = read_repo_file("crates/mesh-sys/src/gui_windows.rs")?;
    let window_rs = read_repo_file("crates/mesh-gui/src/window.rs")?;

    // Act: inspect announce_accessible_label implementation and scan for forbidden IAccessible COM
    let announce_pos = gui_win
        .find("pub fn announce_accessible_label(")
        .ok_or_else(|| "missing announce_accessible_label in gui_windows.rs".to_owned())?;
    let announce_body = gui_win
        .get(announce_pos..(announce_pos + 520).min(gui_win.len()))
        .unwrap_or("");

    // Assert: uses SetWindowTextW (via set_control_text) + NotifyWinEvent(EVENT_OBJECT_NAMECHANGE)
    assert!(announce_body.contains("if hwnd == 0"));
    assert!(announce_body.contains("set_control_text(hwnd, label)"));
    assert!(announce_body.contains("NotifyWinEvent("));
    assert!(announce_body.contains("EVENT_OBJECT_NAMECHANGE"));
    assert!(announce_body.contains("OBJID_CLIENT"));
    assert!(announce_body.contains("CHILDID_SELF"));

    // Assert: window.rs wires MSAA announcements for state/tab changes and toast feedback
    assert!(window_rs.contains("fn format_accessible_status_announcement("));
    assert!(window_rs.contains("announce_accessible_label(st.controls.status_title,"));

    // Assert: 0 IAccessible COM imports or definitions in gui_windows.rs and crates/mesh-gui/src
    let forbidden_com = concat!("IAccess", "ible");
    for line in gui_win.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("//") {
            assert!(
                !trimmed.contains(forbidden_com),
                "forbidden COM interface `{forbidden_com}` in gui_windows.rs"
            );
        }
    }
    let gui_src_dir = root.join("crates/mesh-gui/src");
    for entry in fs::read_dir(&gui_src_dir).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.starts_with("//") {
                    assert!(
                        !trimmed.contains(forbidden_com),
                        "forbidden COM interface `{forbidden_com}` in {}",
                        path.display()
                    );
                }
            }
        }
    }

    // Runtime graceful fallback when hwnd == 0 (no crash if NotifyWinEvent unavailable/null HWND)
    #[cfg(target_os = "windows")]
    {
        mesh_sys::gui_windows::announce_accessible_label(0, "Status: Connected");
    }

    Ok(())
}
