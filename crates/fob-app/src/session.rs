//! The single vault session held open while the app is unlocked. Owned by
//! Tauri's managed state as `Mutex<Option<Session>>` — `None` means locked.

use std::path::PathBuf;
use std::sync::Mutex;

use fob_core::vault::{SlotKind, VaultBlob, VaultFile};
use fob_host::ssh_agent::SshAgentHandle;
use zeroize::Zeroize;

pub type SessionState = Mutex<Option<Session>>;

pub struct Session {
    pub vault_path: PathBuf,
    pub vault_file: VaultFile,
    pub slot: SlotKind,
    pub passphrase: String,
    pub blob: VaultBlob,
    pub ssh_agent: Option<SshAgentHandle>,
}

impl Session {
    /// Re-derive the AES key for this session's slot from the current
    /// passphrase and header. Mirrors `fob-cli`'s `DashboardState::slot_key`.
    fn slot_key(&self) -> Result<fob_core::mem::LockedSecret<32>, String> {
        let kdf_out =
            fob_core::kdf::derive_master(self.passphrase.as_bytes(), &self.vault_file.header)
                .map_err(|e| e.to_string())?;
        let mut keys = fob_core::kdf::derive_all_slot_keys(kdf_out.master_secret());
        let idx = self.slot.index();
        Ok(std::mem::replace(
            &mut keys[idx],
            fob_core::mem::LockedSecret::new([0u8; 32]),
        ))
    }

    /// Re-encrypt the current blob into its slot and write the vault file
    /// back to disk. Call after any mutation to `blob`.
    pub fn save(&mut self) -> Result<(), String> {
        self.blob.touch();
        let key = self.slot_key()?;
        self.vault_file
            .write_slot(self.slot, key.bytes(), &self.blob)
            .map_err(|e| e.to_string())?;
        fob_host::fs_util::atomic_write(&self.vault_path, &self.vault_file.data)
            .map_err(|e| e.to_string())
    }

    /// (Re)spawn the SSH agent with the vault's current SSH keys. Failure is
    /// silent (no SSH keys, or the agent binary/socket couldn't be set up)
    /// since it's a convenience feature, not core vault functionality.
    pub fn sync_ssh_agent(&mut self) {
        self.ssh_agent = None;
        if self.blob.ssh_keys.is_empty() {
            return;
        }
        let (socket_path, owns_socket_dir) = fob_host::ssh_agent::session_socket_path();
        if let Ok(handle) = SshAgentHandle::spawn(socket_path, owns_socket_dir, &self.blob.ssh_keys)
        {
            self.ssh_agent = Some(handle);
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.passphrase.zeroize();
    }
}
