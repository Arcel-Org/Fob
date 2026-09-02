//! fob-wasm — browser (WASM) bindings for `fob-core`.
//!
//! The point of this crate is to remove the browser vault's *second,
//! hand-written* crypto implementation. Today `web/index.html` reimplements
//! PBKDF2/AES-GCM/TOTP in WebCrypto JavaScript, independent from
//! `fob-core`'s Rust. Two implementations that must stay bit-compatible is
//! a correctness hazard and it's what locks the browser to v3/PBKDF2 (WebCrypto
//! has no Argon2id primitive).
//!
//! Compiling this crate to `wasm32-unknown-unknown` and embedding it in the
//! page means the browser runs the *exact same* Rust crypto the CLI and agent
//! ship. One implementation, one audit, three targets.
//!
//! # Security model
//!
//! - `fob-core` is pure logic (no fs/network); this crate only re-exposes it.
//! - `getrandom` is wired to `crypto.getRandomValues` for the wasm target.
//! - `mem::LockedSecret` mlock is a native-only no-op on wasm; `zeroize`
//!   still runs on drop, so secret buffers are cleared even in wasm.
//! - The only filesystem path in fob-core (duress physical wipe) is NOT
//!   exposed here — a browser page cannot overwrite the vault file anyway.
//!
//! # Wire format
//!
//! All functions take/return `Uint8Array` (vault file bytes) and `String`
//! (JSON blobs). The JSON blob is `fob-core`'s native `VaultBlob`
//! serialization — the browser must hold its entries in exactly that shape
//! (e.g. TOTP `secret` is raw bytes, `algorithm` is `"Sha1"`).

use wasm_bindgen::prelude::*;

use fob_core::format::{VaultHeader, DEFAULT_VAULT_SIZE};
use fob_core::vault::{SlotKind, VaultBlob, VaultFile, VaultInitParams};

/// Header info returned to JS. Field names match the browser's needs for the
/// lock screen and security panel.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderInfo {
    pub format_version: u32,
    pub kdf_algorithm: String,
    pub kdf_time_cost: u32,
    pub argon2_memory_kib: u32,
    pub argon2_parallelism: u32,
    pub recovery_enabled: bool,
    pub fingerprint: String,
}

/// Result of a successful unlock: which slot matched and the decrypted blob.
#[derive(serde::Serialize)]
pub struct UnlockResult {
    pub slot: u32,
    pub json: String,
}

fn header_to_info(header: &VaultHeader) -> HeaderInfo {
    let salt: [u8; 32] = header.salt;
    let fp = fob_core::vault::vault_fingerprint(&salt);
    HeaderInfo {
        format_version: header.format_version,
        kdf_algorithm: match header.kdf_algorithm {
            fob_core::format::KdfAlgorithm::Pbkdf2Sha256 => "Pbkdf2Sha256".into(),
            fob_core::format::KdfAlgorithm::Argon2id => "Argon2id".into(),
        },
        kdf_time_cost: header.kdf_time_cost,
        argon2_memory_kib: header.argon2_memory_kib,
        argon2_parallelism: header.argon2_parallelism,
        recovery_enabled: header.recovery_enabled,
        fingerprint: fp,
    }
}

/// Parse a vault file's header only — no passphrase, no decryption.
#[wasm_bindgen]
pub fn parse_header(bytes: &[u8]) -> Result<JsValue, JsValue> {
    let vault = VaultFile::from_bytes(bytes.to_vec()).map_err(js_err)?;
    serde_wasm(&header_to_info(&vault.header))
}

/// Create a fresh v4 vault (Argon2id by default). Returns the vault file
/// bytes. `recovery_enabled` optionally embeds a post-quantum recovery slot
/// and returns the one-time recovery key via `last_recovery_key()`.
#[wasm_bindgen]
pub fn create_vault(
    main_pass: &str,
    decoy_pass: Option<String>,
    duress_pass: Option<String>,
    recovery_enabled: bool,
) -> Result<Vec<u8>, JsValue> {
    let mut params = VaultInitParams::new(main_pass.as_bytes().to_vec(), DEFAULT_VAULT_SIZE);

    if let Some(decoy) = decoy_pass {
        params.decoy_passphrase = Some(decoy.into_bytes());
    }
    if let Some(duress) = duress_pass {
        params.duress_passphrase = Some(duress.into_bytes());
    }
    if recovery_enabled {
        let (pubkey, privkey) = fob_core::recovery::generate_recovery_keypair();
        params.recovery_pubkey = Some(pubkey);
        let display =
            fob_core::recovery::encode_private_key_for_display(&privkey).map_err(js_err)?;
        set_last_recovery_key(display);
    }

    fob_core::vault::init_vault(params).map_err(js_err)
}

thread_local! {
    static LAST_RECOVERY_KEY: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

/// The one-time recovery key produced by the most recent `create_vault`
/// call that had `recovery_enabled = true`. Empty string if none.
#[wasm_bindgen]
pub fn last_recovery_key() -> String {
    LAST_RECOVERY_KEY.with(|c| c.borrow().clone().unwrap_or_default())
}

fn set_last_recovery_key(k: String) {
    LAST_RECOVERY_KEY.with(|c| *c.borrow_mut() = Some(k));
}

/// Unlock a vault with a passphrase. Tries Main, Decoy, then Duress.
/// Returns `{ slot, json }`; the caller must check `slot` and treat the
/// duress slot as a wipe trigger, never as a normal unlock.
#[wasm_bindgen]
pub fn unlock_vault(bytes: &[u8], passphrase: &str) -> Result<JsValue, JsValue> {
    let (slot, blob) =
        fob_core::vault::unlock_vault(bytes, passphrase.as_bytes()).map_err(js_err)?;
    let json = String::from_utf8(blob.to_json().map_err(js_err)?).map_err(js_err)?;
    serde_wasm(&UnlockResult {
        slot: slot.index() as u32,
        json,
    })
}

/// Re-encrypt a slot with the current passphrase and return the new vault
/// bytes. `json` is the current `VaultBlob` JSON (as returned by unlock).
#[wasm_bindgen]
pub fn save_vault(
    bytes: &[u8],
    passphrase: &str,
    slot: u32,
    json: &str,
) -> Result<Vec<u8>, JsValue> {
    let mut vault = VaultFile::from_bytes(bytes.to_vec()).map_err(js_err)?;
    let slot_kind = SlotKind::from_index(slot as usize)
        .ok_or_else(|| JsValue::from_str(&format!("invalid slot index {slot}")))?;

    let blob = VaultBlob::from_json(json.as_bytes()).map_err(js_err)?;
    let kdf_out =
        fob_core::kdf::derive_master(passphrase.as_bytes(), &vault.header).map_err(js_err)?;
    let keys = fob_core::kdf::derive_all_slot_keys(kdf_out.master_secret());
    let key = keys[slot_kind.index()].bytes();
    vault.write_slot(slot_kind, key, &blob).map_err(js_err)?;
    Ok(vault.data)
}

/// Generate a TOTP code for a base32 secret. Mirrors `fob-core::totp`.
#[wasm_bindgen]
pub fn totp_code(secret_base32: &str, period: u32, digits: u8) -> Result<String, JsValue> {
    let secret = fob_core::totp::decode_secret(secret_base32).map_err(js_err)?;
    let entry = fob_core::types::TotpEntry {
        id: uuid::Uuid::new_v4(),
        issuer: String::new(),
        account: String::new(),
        secret: fob_core::types::SecretBytes(secret),
        algorithm: fob_core::types::TotpAlgorithm::Sha1,
        digits,
        period,
        created: 0,
    };
    fob_core::totp::generate_now(&entry).map_err(js_err)
}

/// Seconds remaining in the current TOTP window.
#[wasm_bindgen]
pub fn totp_seconds_remaining(period: u32) -> u32 {
    fob_core::totp::seconds_remaining(period).unwrap_or(0)
}

/// Generate a random password of the given length (same charset as the CLI).
#[wasm_bindgen]
pub fn generate_password(length: usize) -> Result<String, JsValue> {
    fob_core::generator::generate_password(length).map_err(js_err)
}

/// OpenSSH `SHA256:...` fingerprint of a public key line.
#[wasm_bindgen]
pub fn ssh_fingerprint(public_key_line: &str) -> Result<String, JsValue> {
    fob_core::sshkey::fingerprint(public_key_line).map_err(js_err)
}

/// Recover a vault's Main slot with a post-quantum recovery key (bypassing
/// the passphrase) and set a new main passphrase. Returns the recovered JSON
/// blob so the UI can show it, then the new vault bytes are available via
/// `recover_new_bytes()`. Mirrors the CLI's `fob recover` flow.
#[wasm_bindgen]
pub fn recover_vault(
    bytes: &[u8],
    recovery_key: &str,
    new_passphrase: &str,
) -> Result<String, JsValue> {
    let privkey =
        fob_core::recovery::decode_private_key_from_display(recovery_key).map_err(js_err)?;
    let (_, blob) = fob_core::vault::recover_vault(bytes, &privkey).map_err(js_err)?;

    // Re-encrypt the Main slot under the new passphrase.
    let mut vault = VaultFile::from_bytes(bytes.to_vec()).map_err(js_err)?;
    let kdf_out =
        fob_core::kdf::derive_master(new_passphrase.as_bytes(), &vault.header).map_err(js_err)?;
    let keys = fob_core::kdf::derive_all_slot_keys(kdf_out.master_secret());
    let key = keys[SlotKind::Main.index()].bytes();
    vault
        .write_slot(SlotKind::Main, key, &blob)
        .map_err(js_err)?;
    set_recover_new_bytes(vault.data);

    String::from_utf8(blob.to_json().map_err(js_err)?).map_err(js_err)
}

thread_local! {
    static RECOVER_NEW_BYTES: std::cell::RefCell<Option<Vec<u8>>> =
        const { std::cell::RefCell::new(None) };
}

/// Vault bytes produced by the most recent `recover_vault` call.
#[wasm_bindgen]
pub fn recover_new_bytes() -> Vec<u8> {
    RECOVER_NEW_BYTES.with(|c| c.borrow().clone().unwrap_or_default())
}

fn set_recover_new_bytes(v: Vec<u8>) {
    RECOVER_NEW_BYTES.with(|c| *c.borrow_mut() = Some(v));
}

/// Estimate passphrase strength (0.0..1.0) using a conservative character-set
/// entropy model. Shared so browser and CLI use the same bar.
#[wasm_bindgen]
pub fn passphrase_strength(passphrase: &str) -> f64 {
    crate::passphrase::estimate(passphrase)
}

/// Check whether a passphrase clears the minimum bar for new vaults.
#[wasm_bindgen]
pub fn passphrase_acceptable(passphrase: &str) -> bool {
    crate::passphrase::acceptable(passphrase)
}

fn js_err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// Install a panic hook that surfaces Rust panics to the browser console via
/// `console.error`, so a failing call logs the real message instead of the
/// opaque `wasm://... unreachable`. Call once at page load.
#[wasm_bindgen]
pub fn init_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        // Route through js_sys to the host console without pulling in web-sys.
        let msg = format!("[fob-wasm] panic: {info}");
        let _ = js_sys::eval(&format!("console.error({:?})", msg));
    }));
}

fn serde_wasm<T: serde::Serialize>(v: &T) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(v).map_err(|e| JsValue::from_str(&e.to_string()))
}

mod passphrase;
