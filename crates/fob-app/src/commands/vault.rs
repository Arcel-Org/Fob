use std::path::PathBuf;

use fob_core::vault::{self, KdfParams, VaultBlob, VaultFile, VaultInitParams};
use fob_host::fs_util::atomic_write;
use tauri::State;

use crate::dto::{CreateVaultResult, VaultHeaderDto};
use crate::session::{Session, SessionState};

/// Read a vault file's header only — no passphrase, no decryption. Used by
/// the lock screen and the Security panel.
#[tauri::command(rename_all = "snake_case")]
pub fn vault_header_info(device_path: String) -> Result<VaultHeaderDto, String> {
    let bytes = std::fs::read(vault_file_path(&device_path)).map_err(|e| e.to_string())?;
    let header = fob_core::format::VaultHeader::parse(&bytes).map_err(|e| e.to_string())?;
    Ok(VaultHeaderDto::from(&header))
}

#[tauri::command(rename_all = "snake_case")]
pub fn create_vault(
    state: State<SessionState>,
    device_path: String,
    passphrase: String,
    recovery_enabled: bool,
) -> Result<CreateVaultResult, String> {
    let vault_path = vault_file_path(&device_path);

    let mut params = VaultInitParams::new(
        passphrase.clone().into_bytes(),
        fob_core::format::DEFAULT_VAULT_SIZE,
    );
    params.kdf_params = KdfParams::default_argon2id();

    let mut recovery_key_display = None;
    if recovery_enabled {
        let (pubkey, privkey) = fob_core::recovery::generate_recovery_keypair();
        recovery_key_display = Some(
            fob_core::recovery::encode_private_key_for_display(&privkey)
                .map_err(|e| e.to_string())?,
        );
        // privkey's X25519/ML-KEM secrets self-zeroize on drop.
        params.recovery_pubkey = Some(pubkey);
    }

    let vault_bytes = vault::init_vault(params).map_err(|e| e.to_string())?;
    atomic_write(&vault_path, &vault_bytes).map_err(|e| e.to_string())?;

    let blob = do_unlock(&state, vault_path, passphrase)?;
    Ok(CreateVaultResult {
        recovery_key_display,
        blob,
    })
}

#[tauri::command(rename_all = "snake_case")]
pub fn unlock_vault(
    state: State<SessionState>,
    device_path: String,
    passphrase: String,
) -> Result<VaultBlob, String> {
    do_unlock(&state, vault_file_path(&device_path), passphrase)
}

#[tauri::command(rename_all = "snake_case")]
pub fn lock_vault(state: State<SessionState>) {
    // Dropping the session zeroizes the passphrase and kills the SSH agent.
    *state.lock().unwrap() = None;
}

#[tauri::command(rename_all = "snake_case")]
pub fn is_unlocked(state: State<SessionState>) -> bool {
    state.lock().map(|g| g.is_some()).unwrap_or(false)
}

fn vault_file_path(device_path: &str) -> PathBuf {
    PathBuf::from(device_path).join("vault.fob")
}

/// Shared unlock path for both `create_vault` (unlock the vault it just
/// made) and `unlock_vault`. Wrong passphrase and duress passphrase are
/// deliberately indistinguishable — both just report "Incorrect passphrase."
fn do_unlock(
    state: &State<SessionState>,
    vault_path: PathBuf,
    passphrase: String,
) -> Result<VaultBlob, String> {
    let bytes = std::fs::read(&vault_path).map_err(|e| format!("could not read vault: {e}"))?;
    let (slot, blob) =
        vault::unlock_vault_with_duress_wipe(&bytes, passphrase.as_bytes(), &vault_path)
            .map_err(|_| "Incorrect passphrase.".to_string())?;
    let vault_file = VaultFile::from_bytes(bytes).map_err(|e| e.to_string())?;

    let mut session = Session {
        vault_path,
        vault_file,
        slot,
        passphrase,
        blob: blob.clone(),
        ssh_agent: None,
    };
    session.sync_ssh_agent();
    *state
        .lock()
        .map_err(|_| "session lock poisoned".to_string())? = Some(session);
    Ok(blob)
}
