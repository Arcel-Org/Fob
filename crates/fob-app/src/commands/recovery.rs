use std::path::PathBuf;

use fob_core::vault::{VaultBlob, VaultFile};
use tauri::State;

use super::with_session_mut;
use crate::session::{Session, SessionState};

/// Unlock the Main slot via a recovery key instead of a passphrase. The
/// session this opens has no passphrase yet — the frontend must immediately
/// follow up with `set_new_passphrase` before the vault can be saved to
/// (mirrors the CLI's `fob recover` flow).
#[tauri::command(rename_all = "snake_case")]
pub fn recover_vault(
    state: State<SessionState>,
    device_path: String,
    recovery_key: String,
) -> Result<VaultBlob, String> {
    let vault_path = PathBuf::from(device_path).join("vault.fob");
    let bytes = std::fs::read(&vault_path).map_err(|e| e.to_string())?;

    let privkey = fob_core::recovery::decode_private_key_from_display(&recovery_key)
        .map_err(|e| format!("invalid recovery key: {e}"))?;
    let (slot, blob) = fob_core::vault::recover_vault(&bytes, &privkey)
        .map_err(|e| format!("recovery failed: {e}"))?;
    // privkey's X25519/ML-KEM secrets self-zeroize on drop.
    drop(privkey);

    let vault_file = VaultFile::from_bytes(bytes).map_err(|e| e.to_string())?;
    let mut session = Session {
        vault_path,
        vault_file,
        slot,
        passphrase: String::new(),
        blob: blob.clone(),
        ssh_agent: None,
    };
    session.sync_ssh_agent();
    *state
        .lock()
        .map_err(|_| "session lock poisoned".to_string())? = Some(session);
    Ok(blob)
}

/// Set a new main passphrase after a successful `recover_vault`, and save
/// immediately so the new passphrase takes effect on disk right away.
#[tauri::command(rename_all = "snake_case")]
pub fn set_new_passphrase(
    state: State<SessionState>,
    new_passphrase: String,
) -> Result<(), String> {
    if new_passphrase.is_empty() {
        return Err("passphrase cannot be empty".to_string());
    }
    with_session_mut(&state, |s| {
        s.passphrase = new_passphrase;
        s.save()
    })
}
