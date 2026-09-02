// Fob desktop app — Tauri shell around fob-core and fob-host.
//
// The frontend never touches vault crypto directly: every operation is a
// Tauri command that calls straight into fob-core, so there is exactly one
// implementation of the vault format/crypto in this app (unlike the browser
// vault, which reimplements it in WebCrypto). Session state (the decrypted
// blob, the derived passphrase, the running SSH agent) lives here in Rust,
// managed by Tauri, never serialized to disk or held only in JS.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod dto;
mod session;

use std::sync::Mutex;

use session::SessionState;

fn main() {
    tauri::Builder::default()
        .manage(Mutex::new(None) as SessionState)
        .invoke_handler(tauri::generate_handler![
            commands::list_devices,
            commands::format_device,
            commands::vault_header_info,
            commands::create_vault,
            commands::unlock_vault,
            commands::lock_vault,
            commands::is_unlocked,
            commands::generate_password,
            commands::add_password,
            commands::update_password,
            commands::add_totp,
            commands::update_totp,
            commands::add_ssh_key,
            commands::update_ssh_key,
            commands::add_note,
            commands::update_note,
            commands::delete_entry,
            commands::totp_code,
            commands::copy_to_clipboard,
            commands::ssh_agent_status,
            commands::recover_vault,
            commands::set_new_passphrase,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Fob app");
}
