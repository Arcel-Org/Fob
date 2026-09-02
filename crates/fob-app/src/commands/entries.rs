use tauri::State;
use uuid::Uuid;

use fob_core::types::{NoteEntry, PasswordEntry, SecretString, SshKeyEntry, TotpEntry};
use fob_core::vault::{unix_now, VaultBlob};

use super::with_session_mut;
use crate::session::SessionState;

fn parse_id(id: &str) -> Result<Uuid, String> {
    Uuid::parse_str(id).map_err(|_| "invalid entry id".to_string())
}

#[tauri::command(rename_all = "snake_case")]
pub fn generate_password(length: usize) -> Result<String, String> {
    fob_core::generator::generate_password(length).map_err(|e| e.to_string())
}

// ── Passwords ────────────────────────────────────────────────────────────

#[tauri::command(rename_all = "snake_case")]
pub fn add_password(
    state: State<SessionState>,
    name: String,
    username: String,
    password: String,
) -> Result<VaultBlob, String> {
    with_session_mut(&state, |s| {
        s.blob
            .passwords
            .push(PasswordEntry::new(name, username, password));
        s.save()?;
        Ok(s.blob.clone())
    })
}

#[tauri::command(rename_all = "snake_case")]
pub fn update_password(
    state: State<SessionState>,
    id: String,
    name: String,
    username: String,
    password: String,
) -> Result<VaultBlob, String> {
    let id = parse_id(&id)?;
    with_session_mut(&state, |s| {
        let entry = s
            .blob
            .passwords
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| "entry not found".to_string())?;
        entry.name = name;
        entry.username = username;
        entry.password = SecretString::new(password);
        entry.modified = unix_now();
        s.save()?;
        Ok(s.blob.clone())
    })
}

// ── TOTP ─────────────────────────────────────────────────────────────────

#[tauri::command(rename_all = "snake_case")]
pub fn add_totp(
    state: State<SessionState>,
    issuer: String,
    account: String,
    secret_base32: String,
) -> Result<VaultBlob, String> {
    let secret_bytes = fob_core::totp::decode_secret(&secret_base32).map_err(|e| e.to_string())?;
    with_session_mut(&state, |s| {
        s.blob
            .totps
            .push(TotpEntry::new(issuer, account, secret_bytes));
        s.save()?;
        Ok(s.blob.clone())
    })
}

#[tauri::command(rename_all = "snake_case")]
pub fn update_totp(
    state: State<SessionState>,
    id: String,
    issuer: String,
    account: String,
    secret_base32: String,
) -> Result<VaultBlob, String> {
    let id = parse_id(&id)?;
    let secret_bytes = fob_core::totp::decode_secret(&secret_base32).map_err(|e| e.to_string())?;
    with_session_mut(&state, |s| {
        let entry = s
            .blob
            .totps
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| "entry not found".to_string())?;
        entry.issuer = issuer;
        entry.account = account;
        entry.secret = fob_core::types::SecretBytes(secret_bytes);
        s.save()?;
        Ok(s.blob.clone())
    })
}

// ── SSH keys ─────────────────────────────────────────────────────────────

#[tauri::command(rename_all = "snake_case")]
pub fn add_ssh_key(
    state: State<SessionState>,
    name: String,
    public_key: String,
    private_key: String,
) -> Result<VaultBlob, String> {
    with_session_mut(&state, |s| {
        let entry = SshKeyEntry::new(name, public_key, private_key).map_err(|e| e.to_string())?;
        s.blob.ssh_keys.push(entry);
        s.save()?;
        s.sync_ssh_agent();
        Ok(s.blob.clone())
    })
}

#[tauri::command(rename_all = "snake_case")]
pub fn update_ssh_key(
    state: State<SessionState>,
    id: String,
    name: String,
    public_key: String,
    private_key: String,
) -> Result<VaultBlob, String> {
    let id = parse_id(&id)?;
    let fingerprint = fob_core::sshkey::fingerprint(&public_key).map_err(|e| e.to_string())?;
    let algorithm = fob_core::sshkey::algorithm(&public_key);
    with_session_mut(&state, |s| {
        let entry = s
            .blob
            .ssh_keys
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| "entry not found".to_string())?;
        entry.name = name;
        entry.public_key = public_key;
        entry.private_key = SecretString::new(private_key);
        entry.fingerprint = fingerprint;
        entry.algorithm = algorithm;
        s.save()?;
        s.sync_ssh_agent();
        Ok(s.blob.clone())
    })
}

// ── Notes ────────────────────────────────────────────────────────────────

#[tauri::command(rename_all = "snake_case")]
pub fn add_note(
    state: State<SessionState>,
    title: String,
    body: String,
) -> Result<VaultBlob, String> {
    with_session_mut(&state, |s| {
        s.blob.notes.push(NoteEntry::new(title, body));
        s.save()?;
        Ok(s.blob.clone())
    })
}

#[tauri::command(rename_all = "snake_case")]
pub fn update_note(
    state: State<SessionState>,
    id: String,
    title: String,
    body: String,
) -> Result<VaultBlob, String> {
    let id = parse_id(&id)?;
    with_session_mut(&state, |s| {
        let entry = s
            .blob
            .notes
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| "entry not found".to_string())?;
        entry.title = title;
        entry.body = SecretString::new(body);
        entry.modified = unix_now();
        s.save()?;
        Ok(s.blob.clone())
    })
}

// ── Delete (generic across entry kinds) ─────────────────────────────────

#[tauri::command(rename_all = "snake_case")]
pub fn delete_entry(
    state: State<SessionState>,
    kind: String,
    id: String,
) -> Result<VaultBlob, String> {
    let id = parse_id(&id)?;
    with_session_mut(&state, |s| {
        let was_ssh = kind == "ssh";
        match kind.as_str() {
            "password" => s.blob.passwords.retain(|e| e.id != id),
            "totp" => s.blob.totps.retain(|e| e.id != id),
            "ssh" => s.blob.ssh_keys.retain(|e| e.id != id),
            "note" => s.blob.notes.retain(|e| e.id != id),
            other => return Err(format!("unknown entry kind '{other}'")),
        }
        s.save()?;
        if was_ssh {
            s.sync_ssh_agent();
        }
        Ok(s.blob.clone())
    })
}
