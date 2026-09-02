// Integration test — exercises the exact save/reload sequence
// DashboardState::save() performs (fob-cli's tui/state.rs), using only
// fob-core's public API directly since fob-cli has no lib target to import.
use fob_core::format::DEFAULT_VAULT_SIZE;
use fob_core::types::{NoteEntry, PasswordEntry, SshKeyEntry, TotpEntry};
use fob_core::vault::{unlock_vault, SlotKind, VaultFile, VaultInitParams};

fn save(
    vault_file: &mut VaultFile,
    slot: SlotKind,
    passphrase: &str,
    blob: &mut fob_core::vault::VaultBlob,
    path: &std::path::Path,
) {
    blob.touch();
    let kdf_out = fob_core::kdf::derive_master(passphrase.as_bytes(), &vault_file.header).unwrap();
    let keys = fob_core::kdf::derive_all_slot_keys(kdf_out.master_secret());
    vault_file
        .write_slot(slot, keys[slot.index()].bytes(), blob)
        .unwrap();
    std::fs::write(path, &vault_file.data).unwrap();
}

#[test]
fn dashboard_entries_survive_save_and_reload() {
    let dir = std::env::temp_dir().join(format!("fob-dashboard-scratch-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let vault_path = dir.join("vault.fob");

    let bytes = fob_core::vault::init_vault(VaultInitParams::new(
        b"correct-horse-battery-staple".to_vec(),
        DEFAULT_VAULT_SIZE,
    ))
    .unwrap();
    std::fs::write(&vault_path, &bytes).unwrap();

    let (slot, mut blob) = unlock_vault(&bytes, b"correct-horse-battery-staple").unwrap();
    let mut vault_file = VaultFile::from_bytes(bytes).unwrap();

    blob.passwords
        .push(PasswordEntry::new("GitHub", "alice", "gh-secret"));
    blob.notes
        .push(NoteEntry::new("Recovery codes", "1234-5678"));
    blob.totps.push(TotpEntry::new(
        "Example",
        "alice@example.com",
        b"12345678901234567890".to_vec(),
    ));
    blob.ssh_keys.push(SshKeyEntry::new("laptop", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBaLexhIIfz1MorwSoTHf07P8SEwaxjc9V2t8GLzuFgz test@example", "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----").unwrap());

    save(
        &mut vault_file,
        slot,
        "correct-horse-battery-staple",
        &mut blob,
        &vault_path,
    );

    // Reload completely fresh, as if the app were restarted.
    let reloaded_bytes = std::fs::read(&vault_path).unwrap();
    let (slot2, blob2) = unlock_vault(&reloaded_bytes, b"correct-horse-battery-staple").unwrap();
    assert_eq!(slot2, slot);
    assert_eq!(blob2.passwords.len(), 1);
    assert_eq!(blob2.passwords[0].name, "GitHub");
    assert_eq!(blob2.passwords[0].password.expose(), "gh-secret");
    assert_eq!(blob2.notes.len(), 1);
    assert_eq!(blob2.notes[0].title, "Recovery codes");
    assert_eq!(blob2.totps.len(), 1);
    assert_eq!(blob2.ssh_keys.len(), 1);
    assert_eq!(
        blob2.ssh_keys[0].fingerprint,
        "SHA256:ZE2JLEe57KcPkMk5xzA0EwxIrjNLP1W6WvaL+N87Ggg"
    );

    // Delete the password entry and verify it's gone after another save/reload.
    blob.passwords.remove(0);
    save(
        &mut vault_file,
        slot,
        "correct-horse-battery-staple",
        &mut blob,
        &vault_path,
    );
    let reloaded2 = std::fs::read(&vault_path).unwrap();
    let (_, blob3) = unlock_vault(&reloaded2, b"correct-horse-battery-staple").unwrap();
    assert_eq!(blob3.passwords.len(), 0);
    assert_eq!(
        blob3.notes.len(),
        1,
        "unrelated entries must survive an edit"
    );

    std::fs::remove_dir_all(&dir).ok();
    println!("dashboard save/reload roundtrip OK");
}
