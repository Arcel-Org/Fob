/// Copy `text` to the clipboard, then clear it after 30s — but only if it's
/// still what we put there, so we don't stomp on something the user copied
/// from elsewhere in the meantime. Mirrors the browser vault and TUI's
/// identical clipboard threat-model behavior.
#[tauri::command(rename_all = "snake_case")]
pub fn copy_to_clipboard(text: String) -> Result<(), String> {
    fob_host::clipboard::copy(&text).map_err(|e| e.to_string())?;
    std::thread::spawn(move || {
        std::thread::sleep(fob_host::clipboard::CLEAR_AFTER);
        let _ = fob_host::clipboard::clear_if_unchanged(&text);
    });
    Ok(())
}
