use zeroize::Zeroize;

use fob_host::fs_util::atomic_write;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screen {
    Boot,
    DevicePicker,
    Formatting,
    SetupWizard(WizardStep),
    Unlock,
    Dashboard,
    Done,
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WizardStep {
    ExistingVault,
    ConfirmWipe,
    Master,
    Confirm,
}

pub struct AppState {
    pub screen: Screen,
    pub devices: Vec<fob_host::device::UsbDevice>,
    pub selected_device: usize,
    pub boot_tick: u8,
    pub wizard: WizardState,
    pub unlock: UnlockState,
    pub dashboard: Option<DashboardState>,
    pub tick: u64,
    pub format_rx: Option<std::sync::mpsc::Receiver<anyhow::Result<()>>>,
    pub update_mode: bool,
}

#[derive(Default)]
pub struct WizardState {
    pub main_pass: String,
    pub main_pass_confirm: String,
    pub field: usize,
    pub cursor: usize,
    pub mismatch_flash: u8,
    /// Opt-in: generate a hybrid X25519+ML-KEM-1024 post-quantum recovery
    /// key alongside the vault (toggled at the Confirm step).
    pub recovery_enabled: bool,
    /// The recovery private key, encoded for one-time display, set after a
    /// successful `run_vault_init` when `recovery_enabled` was set. Shown
    /// once on the Done screen — never written to disk.
    pub recovery_key_display: Option<String>,
}

#[derive(Default)]
pub struct UnlockState {
    pub passphrase: String,
    pub cursor: usize,
    pub error: Option<String>,
}

impl Drop for UnlockState {
    fn drop(&mut self) {
        self.passphrase.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashboardTab {
    Passwords,
    Totp,
    Ssh,
    Notes,
}

impl DashboardTab {
    pub const ALL: [DashboardTab; 4] = [Self::Passwords, Self::Totp, Self::Ssh, Self::Notes];

    pub fn label(self) -> &'static str {
        match self {
            Self::Passwords => "Passwords",
            Self::Totp => "TOTP",
            Self::Ssh => "SSH Keys",
            Self::Notes => "Notes",
        }
    }

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|t| *t == self).unwrap()
    }
}

/// Each form modal serves both "add new" (`editing: None`) and "edit
/// existing" (`editing: Some(index into the relevant blob Vec)`).
pub enum Modal {
    None,
    AddPassword(PasswordForm),
    AddNote(NoteForm),
    AddTotp(TotpForm),
    AddSsh(SshForm),
    ConfirmDelete,
}

#[derive(Default)]
pub struct PasswordForm {
    pub name: String,
    pub username: String,
    pub password: String,
    pub field: usize,
    pub cursor: usize,
    pub editing: Option<usize>,
}

impl PasswordForm {
    pub fn for_edit(idx: usize, e: &fob_core::types::PasswordEntry) -> Self {
        let name = e.name.clone();
        Self {
            cursor: name.chars().count(),
            name,
            username: e.username.clone(),
            password: e.password.expose().to_string(),
            field: 0,
            editing: Some(idx),
        }
    }
}

impl Drop for PasswordForm {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Default)]
pub struct NoteForm {
    pub title: String,
    pub body: String,
    pub field: usize,
    pub cursor: usize,
    pub editing: Option<usize>,
}

impl NoteForm {
    pub fn for_edit(idx: usize, e: &fob_core::types::NoteEntry) -> Self {
        let title = e.title.clone();
        Self {
            cursor: title.chars().count(),
            title,
            body: e.body.expose().to_string(),
            field: 0,
            editing: Some(idx),
        }
    }
}

impl Drop for NoteForm {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

#[derive(Default)]
pub struct TotpForm {
    pub issuer: String,
    pub account: String,
    pub secret: String,
    pub field: usize,
    pub cursor: usize,
    pub editing: Option<usize>,
}

impl TotpForm {
    pub fn for_edit(idx: usize, e: &fob_core::types::TotpEntry) -> Self {
        let issuer = e.issuer.clone();
        Self {
            cursor: issuer.chars().count(),
            issuer,
            account: e.account.clone(),
            secret: fob_core::totp::encode_secret(&e.secret.0),
            field: 0,
            editing: Some(idx),
        }
    }
}

impl Drop for TotpForm {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Default)]
pub struct SshForm {
    pub name: String,
    pub public_key: String,
    pub private_key: String,
    pub field: usize,
    pub cursor: usize,
    pub editing: Option<usize>,
}

impl SshForm {
    pub fn for_edit(idx: usize, e: &fob_core::types::SshKeyEntry) -> Self {
        let name = e.name.clone();
        Self {
            cursor: name.chars().count(),
            name,
            public_key: e.public_key.clone(),
            private_key: e.private_key.expose().to_string(),
            field: 0,
            editing: Some(idx),
        }
    }
}

impl Drop for SshForm {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

/// An unlocked vault and the UI state for browsing/editing it.
pub struct DashboardState {
    pub vault_path: std::path::PathBuf,
    pub vault_file: fob_core::vault::VaultFile,
    pub slot: fob_core::vault::SlotKind,
    pub passphrase: String,
    pub blob: fob_core::vault::VaultBlob,
    pub tab: DashboardTab,
    pub selected: usize,
    pub modal: Modal,
    pub reveal: bool,
    pub status: Option<String>,
    /// Running SSH agent for this session, if `fob-agent` could be spawned.
    /// `None` means no SSH keys yet, or the agent binary/socket setup failed
    /// (`status` carries the reason in the latter case).
    pub ssh_agent: Option<fob_host::ssh_agent::SshAgentHandle>,
    /// What's currently on the clipboard (so we only clear it if it's still
    /// what we put there) and when to clear it.
    pub clipboard: Option<(String, std::time::Instant)>,
}

impl Drop for DashboardState {
    fn drop(&mut self) {
        self.passphrase.zeroize();
        if let Some((text, _)) = &self.clipboard {
            let _ = fob_host::clipboard::clear_if_unchanged(text);
        }
    }
}

impl DashboardState {
    /// Re-derive this vault's slot key from the held passphrase. Cheap only
    /// relative to how the vault was configured — this repeats the
    /// PBKDF2/Argon2id work on every save, matching the design used
    /// throughout fob-core.
    ///
    /// Returns a `LockedSecret` (mlocked + zeroized-on-drop), not a bare
    /// `[u8; 32]` — this is a real AES-256-GCM key capable of decrypting the
    /// whole vault, not incidental data.
    pub fn slot_key(&self) -> anyhow::Result<fob_core::mem::LockedSecret<32>> {
        let kdf_out =
            fob_core::kdf::derive_master(self.passphrase.as_bytes(), &self.vault_file.header)?;
        let mut keys = fob_core::kdf::derive_all_slot_keys(kdf_out.master_secret());
        let idx = self.slot.index();
        // Swap the wanted key out with a zero-filled placeholder rather than
        // copying it out from behind the `LockedSecret`, so the returned key
        // stays the only live copy — the other three (already useless once
        // separated from `keys`) get dropped, zeroized, and munlocked as
        // this array goes out of scope.
        Ok(std::mem::replace(
            &mut keys[idx],
            fob_core::mem::LockedSecret::new([0u8; 32]),
        ))
    }

    /// Re-encrypt the current blob into its slot and write the vault file back to disk.
    pub fn save(&mut self) -> anyhow::Result<()> {
        self.blob.touch();
        let key = self.slot_key()?;
        self.vault_file
            .write_slot(self.slot, key.bytes(), &self.blob)?;
        atomic_write(&self.vault_path, &self.vault_file.data)?;
        Ok(())
    }

    /// Number of entries in the currently active tab.
    pub fn tab_len(&self) -> usize {
        match self.tab {
            DashboardTab::Passwords => self.blob.passwords.len(),
            DashboardTab::Totp => self.blob.totps.len(),
            DashboardTab::Ssh => self.blob.ssh_keys.len(),
            DashboardTab::Notes => self.blob.notes.len(),
        }
    }

    /// The single most useful thing to put on the clipboard for the
    /// currently selected entry — the password itself, the live TOTP code,
    /// the SSH public key (the half people actually paste elsewhere), or
    /// the note body.
    pub fn copyable_text(&self) -> Option<String> {
        match self.tab {
            DashboardTab::Passwords => self
                .blob
                .passwords
                .get(self.selected)
                .map(|e| e.password.expose().to_string()),
            DashboardTab::Totp => self
                .blob
                .totps
                .get(self.selected)
                .and_then(|e| fob_core::totp::generate_now(e).ok()),
            DashboardTab::Ssh => self
                .blob
                .ssh_keys
                .get(self.selected)
                .map(|e| e.public_key.clone()),
            DashboardTab::Notes => self
                .blob
                .notes
                .get(self.selected)
                .map(|e| e.body.expose().to_string()),
        }
    }

    /// (Re)spawn the SSH agent with the vault's current SSH keys. Called on
    /// unlock and after every SSH key add/delete so the running agent's
    /// identity set never drifts from the vault. Dropping the old handle
    /// first (if any) kills that process and frees its socket path.
    pub fn sync_ssh_agent(&mut self) {
        self.ssh_agent = None;
        if self.blob.ssh_keys.is_empty() {
            return;
        }
        let (socket_path, owns_socket_dir) = fob_host::ssh_agent::session_socket_path();
        match fob_host::ssh_agent::SshAgentHandle::spawn(
            socket_path,
            owns_socket_dir,
            &self.blob.ssh_keys,
        ) {
            Ok(handle) => self.ssh_agent = Some(handle),
            Err(e) => self.status = Some(format!("SSH agent unavailable: {e}")),
        }
    }
}

impl AppState {
    pub fn new(devices: Vec<fob_host::device::UsbDevice>) -> Self {
        Self {
            screen: Screen::Boot,
            devices,
            selected_device: 0,
            boot_tick: 0,
            wizard: WizardState::default(),
            unlock: UnlockState::default(),
            dashboard: None,
            tick: 0,
            format_rx: None,
            update_mode: false,
        }
    }
}

impl Drop for AppState {
    fn drop(&mut self) {
        self.wizard.main_pass.zeroize();
        self.wizard.main_pass_confirm.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fob_core::types::{NoteEntry, PasswordEntry, SshKeyEntry, TotpEntry};
    use fob_core::vault::{unlock_vault, VaultFile, VaultInitParams};

    fn test_dashboard() -> DashboardState {
        let bytes = fob_core::vault::init_vault(VaultInitParams {
            main_passphrase: b"test-pass".to_vec(),
            decoy_passphrase: None,
            duress_passphrase: None,
            vault_size: 256 * 1024,
            decoy_blob: None,
            kdf_params: fob_core::vault::KdfParams::pbkdf2(1000),
            recovery_pubkey: None,
        })
        .unwrap();
        let (slot, blob) = unlock_vault(&bytes, b"test-pass").unwrap();
        let vault_file = VaultFile::from_bytes(bytes).unwrap();

        DashboardState {
            vault_path: std::path::PathBuf::from("/dev/null"),
            vault_file,
            slot,
            passphrase: "test-pass".to_string(),
            blob,
            tab: DashboardTab::Passwords,
            selected: 0,
            modal: Modal::None,
            reveal: false,
            status: None,
            ssh_agent: None,
            clipboard: None,
        }
    }

    #[test]
    fn copyable_text_is_none_for_empty_tab() {
        let dash = test_dashboard();
        assert_eq!(dash.copyable_text(), None);
    }

    #[test]
    fn copyable_text_returns_password_for_passwords_tab() {
        let mut dash = test_dashboard();
        dash.blob
            .passwords
            .push(PasswordEntry::new("GitHub", "alice", "hunter2"));
        assert_eq!(dash.copyable_text(), Some("hunter2".to_string()));
    }

    #[test]
    fn copyable_text_returns_live_totp_code() {
        let mut dash = test_dashboard();
        dash.tab = DashboardTab::Totp;
        dash.blob.totps.push(TotpEntry::new(
            "Example",
            "alice@example.com",
            b"12345678901234567890".to_vec(),
        ));
        let code = dash.copyable_text().unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn copyable_text_returns_ssh_public_key_not_private() {
        let mut dash = test_dashboard();
        dash.tab = DashboardTab::Ssh;
        dash.blob.ssh_keys.push(
            SshKeyEntry::new(
                "laptop",
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJm7X5tIxbUkIb6VLD91P65Cr0iqKyTKTDd0cYpQHtv test@example",
                "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----",
            )
            .unwrap(),
        );
        assert_eq!(
            dash.copyable_text(),
            Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJm7X5tIxbUkIb6VLD91P65Cr0iqKyTKTDd0cYpQHtv test@example".to_string())
        );
    }

    #[test]
    fn copyable_text_returns_note_body() {
        let mut dash = test_dashboard();
        dash.tab = DashboardTab::Notes;
        dash.blob
            .notes
            .push(NoteEntry::new("Recovery", "1234-5678"));
        assert_eq!(dash.copyable_text(), Some("1234-5678".to_string()));
    }

    #[test]
    fn tab_len_tracks_the_active_tab_only() {
        let mut dash = test_dashboard();
        dash.blob.passwords.push(PasswordEntry::new("A", "a", "a"));
        dash.blob.notes.push(NoteEntry::new("B", "b"));
        assert_eq!(dash.tab_len(), 1); // Passwords tab active
        dash.tab = DashboardTab::Notes;
        assert_eq!(dash.tab_len(), 1);
        dash.tab = DashboardTab::Ssh;
        assert_eq!(dash.tab_len(), 0);
    }
}
