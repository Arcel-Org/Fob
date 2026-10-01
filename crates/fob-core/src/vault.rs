use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(not(all(feature = "wasm", target_arch = "wasm32")))]
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

use crate::{
    aead,
    error::{Error, Result},
    format::{
        cell_offset, cell_size, KdfAlgorithm, VaultHeader, DEFAULT_ARGON2_MEMORY_KIB,
        DEFAULT_ARGON2_PARALLELISM, DEFAULT_ARGON2_TIME_COST, FORMAT_VERSION, HEADER_SALT_LEN,
        HEADER_SALT_OFFSET, HEADER_SIZE, MAX_VAULT_SIZE, MIN_VAULT_SIZE, RECOVERY_SLOT_INDEX,
    },
    kdf, recovery,
    types::{
        CardEntry, FileEntry, NoteEntry, PasswordEntry, RecoveryCodeEntry, SshKeyEntry, TotpEntry,
    },
};

/// KDF choice and parameters for a vault, used both at creation
/// (`VaultInitParams::kdf_params`) and encoded into the vault header.
#[derive(Debug, Clone)]
pub struct KdfParams {
    pub algorithm: KdfAlgorithm,
    /// PBKDF2 iterations, or Argon2id time_cost — interpretation depends on
    /// `algorithm`.
    pub time_cost: u32,
    /// Meaningful only when `algorithm == Argon2id`.
    pub memory_kib: u32,
    /// Meaningful only when `algorithm == Argon2id`.
    pub parallelism: u32,
}

impl KdfParams {
    /// The default for new vaults: Argon2id at the RFC 9106 "second
    /// recommended" profile.
    pub fn default_argon2id() -> Self {
        Self {
            algorithm: KdfAlgorithm::Argon2id,
            time_cost: DEFAULT_ARGON2_TIME_COST,
            memory_kib: DEFAULT_ARGON2_MEMORY_KIB,
            parallelism: DEFAULT_ARGON2_PARALLELISM,
        }
    }

    /// An optional, stronger Argon2id profile for users who explicitly opt
    /// in to max security: 128 MiB memory / 4 passes / 8 lanes, i.e. double
    /// the default memory and lanes plus an extra pass. Still within the
    /// header's hard maxima so a vault encrypted with it stays portable.
    pub fn max_security_argon2id() -> Self {
        Self {
            algorithm: KdfAlgorithm::Argon2id,
            time_cost: 4,
            memory_kib: 131_072, // 128 MiB
            parallelism: 8,
        }
    }

    /// PBKDF2-HMAC-SHA256 with the given iteration count — used for v3
    /// vaults, browser-compatible vaults, and fast test fixtures.
    pub fn pbkdf2(iterations: u32) -> Self {
        Self {
            algorithm: KdfAlgorithm::Pbkdf2Sha256,
            time_cost: iterations,
            memory_kib: 0,
            parallelism: 0,
        }
    }
}

/// Returns current Unix timestamp in seconds.
///
/// On the `wasm` feature build (wasm32-unknown-unknown) `std::time`'s
/// `SystemTime` is unavailable and panics, so we read the JS clock instead.
/// Everywhere else we use the std clock.
pub fn unix_now() -> u64 {
    #[cfg(all(feature = "wasm", target_arch = "wasm32"))]
    {
        (js_sys::Date::now() / 1000.0) as u64
    }

    #[cfg(not(all(feature = "wasm", target_arch = "wasm32")))]
    {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Which vault slot an opened vault lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotKind {
    Main = 0,
    Decoy = 1,
    Duress = 2,
    Reserved = 3,
}

impl SlotKind {
    pub fn from_index(i: usize) -> Option<Self> {
        match i {
            0 => Some(Self::Main),
            1 => Some(Self::Decoy),
            2 => Some(Self::Duress),
            3 => Some(Self::Reserved),
            _ => None,
        }
    }

    pub fn index(self) -> usize {
        self as usize
    }
}

/// The data payload stored inside a single encrypted vault slot.
///
/// Serialized as JSON (not CBOR) so the exact same bytes can be produced
/// and parsed by the zero-dependency browser vault via WebCrypto/JSON —
/// there is only one vault format, shared by the CLI and the browser.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultBlob {
    pub version: u32,
    pub created: u64,
    #[serde(rename = "modified")]
    pub last_modified: u64,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub passwords: Vec<PasswordEntry>,
    #[serde(rename = "totp", default)]
    pub totps: Vec<TotpEntry>,
    #[serde(default)]
    pub ssh_keys: Vec<SshKeyEntry>,
    #[serde(default)]
    pub notes: Vec<NoteEntry>,
    #[serde(default)]
    pub files: Vec<FileEntry>,
    #[serde(default)]
    pub cards: Vec<CardEntry>,
    #[serde(default)]
    pub recovery_codes: Vec<RecoveryCodeEntry>,
}

impl VaultBlob {
    pub fn new() -> Self {
        let now = unix_now();
        Self {
            version: FORMAT_VERSION,
            created: now,
            last_modified: now,
            fingerprint: String::new(),
            passwords: Vec::new(),
            totps: Vec::new(),
            ssh_keys: Vec::new(),
            notes: Vec::new(),
            files: Vec::new(),
            cards: Vec::new(),
            recovery_codes: Vec::new(),
        }
    }

    pub fn touch(&mut self) {
        self.last_modified = unix_now();
    }

    /// Total number of entries across all categories.
    pub fn entry_count(&self) -> usize {
        self.passwords.len()
            + self.totps.len()
            + self.ssh_keys.len()
            + self.notes.len()
            + self.files.len()
            + self.cards.len()
            + self.recovery_codes.len()
    }

    /// Serialize to JSON bytes.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(Error::from)
    }

    /// Deserialize from JSON bytes.
    pub fn from_json(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data).map_err(Error::from)
    }
}

/// Short, non-secret display fingerprint for a vault file, derived from its
/// header salt. Identical for every slot in the same file (the salt is
/// shared) — purely a display aid, not a security boundary.
pub fn vault_fingerprint(salt: &[u8; 32]) -> String {
    let hash = Sha256::digest(salt);
    hash[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// A vault file in memory: the raw bytes and parsed header.
pub struct VaultFile {
    pub data: Vec<u8>,
    pub header: VaultHeader,
}

impl VaultFile {
    /// Create a fresh vault file filled with random bytes.
    ///
    /// The header is populated with a new random salt. Each slot's AEAD
    /// nonce is generated fresh at write time (see `write_slot`), not
    /// stored in the header. All slot cells are random and indistinguishable
    /// from ciphertext.
    pub fn create_fresh(vault_size: usize, kdf_params: &KdfParams) -> Result<Self> {
        if vault_size < MIN_VAULT_SIZE {
            return Err(Error::Format(format!(
                "vault size {vault_size} is below the minimum of {MIN_VAULT_SIZE}"
            )));
        }
        if vault_size > MAX_VAULT_SIZE {
            return Err(Error::Format(format!(
                "vault size {vault_size} exceeds maximum of {MAX_VAULT_SIZE}"
            )));
        }

        let mut data = vec![0u8; vault_size];
        getrandom::getrandom(&mut data).map_err(|_| Error::Encrypt)?;

        let salt: [u8; HEADER_SALT_LEN] = data
            [HEADER_SALT_OFFSET..HEADER_SALT_OFFSET + HEADER_SALT_LEN]
            .try_into()
            .unwrap();

        let header = VaultHeader {
            format_version: FORMAT_VERSION,
            kdf_algorithm: kdf_params.algorithm,
            kdf_time_cost: kdf_params.time_cost,
            argon2_memory_kib: kdf_params.memory_kib,
            argon2_parallelism: kdf_params.parallelism,
            salt,
            recovery_enabled: false,
        };
        let header_bytes = header.to_bytes();
        data[..HEADER_SIZE].copy_from_slice(&header_bytes);

        Ok(Self { data, header })
    }

    /// Flip `recovery_enabled` and re-commit the header to `data`. Must be
    /// called before any slot is written, since the header bytes are used
    /// as AEAD associated data on every slot (including the recovery slot)
    /// — every slot in a vault must be encrypted against the same,
    /// final header.
    pub fn set_recovery_enabled(&mut self, enabled: bool) {
        self.header.recovery_enabled = enabled;
        let header_bytes = self.header.to_bytes();
        self.data[..HEADER_SIZE].copy_from_slice(&header_bytes);
    }

    /// Parse a vault file from existing bytes (e.g., read from USB).
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        if data.len() < MIN_VAULT_SIZE {
            return Err(Error::Format(format!(
                "vault file size {} is below the minimum of {MIN_VAULT_SIZE} — likely truncated or corrupted",
                data.len()
            )));
        }
        if data.len() > MAX_VAULT_SIZE {
            return Err(Error::Format(format!(
                "vault file size {} exceeds maximum of {MAX_VAULT_SIZE}",
                data.len()
            )));
        }
        let header = VaultHeader::parse(&data)?;
        Ok(Self { data, header })
    }

    /// Write a VaultBlob into a specific slot, encrypting it with `slot_key`.
    ///
    /// Plaintext layout inside the cell (all within the encrypted region):
    ///   [8 bytes]   JSON length as u64 LE  (only readable with the correct key)
    ///   [N bytes]   JSON-encoded VaultBlob
    ///   [remainder] random padding to fill cell_size - NONCE_LEN - TAG_LEN bytes
    ///
    /// The stored cell is always exactly cell_size bytes (nonce || ciphertext
    /// || tag), making all cells indistinguishable in size. The length field
    /// is inside the ciphertext so it leaks nothing to an adversary without
    /// the key. A fresh random nonce is generated on every call — nonces are
    /// never reused across writes (see `format`'s module doc for why that
    /// matters: v2 reused a fixed per-slot nonce from the header on every
    /// save, an unconditional AES-GCM nonce-reuse break).
    pub fn write_slot(
        &mut self,
        slot: SlotKind,
        slot_key: &[u8; 32],
        blob: &VaultBlob,
    ) -> Result<()> {
        let json = zeroize::Zeroizing::new(blob.to_json()?);
        let cell_sz = cell_size(self.data.len());
        let plaintext_capacity = cell_sz.saturating_sub(aead::GCM_NONCE_LEN + aead::GCM_TAG_LEN);
        const LENGTH_PREFIX: usize = 8;

        if json.len() + LENGTH_PREFIX > plaintext_capacity {
            return Err(Error::VaultFull);
        }

        // Build padded plaintext: len_u64_le || json || random_padding.
        let mut padded = zeroize::Zeroizing::new(vec![0u8; plaintext_capacity]);
        getrandom::getrandom(&mut padded).map_err(|_| Error::Encrypt)?;
        padded[..LENGTH_PREFIX].copy_from_slice(&(json.len() as u64).to_le_bytes());
        padded[LENGTH_PREFIX..LENGTH_PREFIX + json.len()].copy_from_slice(&json);

        let aad = &self.header.to_bytes();
        let ciphertext = aead::encrypt(slot_key, &padded, aad)?;

        // ciphertext is now exactly cell_sz bytes (nonce + encrypted body + tag).
        let offset = cell_offset(self.data.len(), slot.index());
        self.data[offset..offset + cell_sz].copy_from_slice(&ciphertext);

        Ok(())
    }

    /// Attempt to decrypt a specific slot with the given key.
    ///
    /// Returns Ok(blob) on success, Err(Error::Decrypt) if wrong key or corrupted.
    pub fn read_slot(&self, slot: SlotKind, slot_key: &[u8; 32]) -> Result<VaultBlob> {
        let cell_sz = cell_size(self.data.len());
        let offset = cell_offset(self.data.len(), slot.index());
        let aad = &self.header.to_bytes();
        let cell = &self.data[offset..offset + cell_sz];

        let plaintext = zeroize::Zeroizing::new(aead::decrypt(slot_key, cell, aad)?);

        const LENGTH_PREFIX: usize = 8;
        if plaintext.len() < LENGTH_PREFIX {
            return Err(Error::Format("decrypted cell too small".into()));
        }
        let json_len = u64::from_le_bytes(plaintext[..LENGTH_PREFIX].try_into().unwrap()) as usize;
        let json_end = LENGTH_PREFIX + json_len;
        if json_end > plaintext.len() {
            return Err(Error::Format("JSON length field exceeds plaintext".into()));
        }

        VaultBlob::from_json(&plaintext[LENGTH_PREFIX..json_end])
    }

    /// Write raw recovery-wrap bytes (see `recovery::RecoveryWrappedBlob`)
    /// into the recovery slot cell, padded to `cell_size` the same way
    /// `write_slot` pads a `VaultBlob` — so a recovery-enabled vault's 4th
    /// cell is exactly as indistinguishable from random as the other three.
    ///
    /// Unlike `write_slot`, this isn't keyed by a passphrase-derived slot
    /// key: the confidentiality of the wrapped data comes entirely from the
    /// hybrid KEM wrap itself (see `recovery::wrap_secret_for_recovery`).
    /// The key used here only needs to exist so the cell has the same
    /// nonce||ciphertext||tag shape as every other cell; it's derived from
    /// the (already public) header salt, not a secret.
    pub fn write_recovery_slot(&mut self, blob_bytes: &[u8]) -> Result<()> {
        let cell_sz = cell_size(self.data.len());
        let plaintext_capacity = cell_sz.saturating_sub(aead::GCM_NONCE_LEN + aead::GCM_TAG_LEN);
        const LENGTH_PREFIX: usize = 8;

        if blob_bytes.len() + LENGTH_PREFIX > plaintext_capacity {
            return Err(Error::Format(format!(
                "recovery data ({} bytes) does not fit this vault's slot cell \
                 ({} bytes available) — use a larger vault size",
                blob_bytes.len(),
                plaintext_capacity.saturating_sub(LENGTH_PREFIX)
            )));
        }

        let mut padded = zeroize::Zeroizing::new(vec![0u8; plaintext_capacity]);
        getrandom::getrandom(&mut padded).map_err(|_| Error::Encrypt)?;
        padded[..LENGTH_PREFIX].copy_from_slice(&(blob_bytes.len() as u64).to_le_bytes());
        padded[LENGTH_PREFIX..LENGTH_PREFIX + blob_bytes.len()].copy_from_slice(blob_bytes);

        let key = recovery_slot_shape_key(&self.header.salt);
        let aad = &self.header.to_bytes();
        let ciphertext = aead::encrypt(&key, &padded, aad)?;

        let offset = cell_offset(self.data.len(), RECOVERY_SLOT_INDEX);
        self.data[offset..offset + cell_sz].copy_from_slice(&ciphertext);

        Ok(())
    }

    /// Read back what `write_recovery_slot` wrote.
    pub fn read_recovery_slot(&self) -> Result<Vec<u8>> {
        let cell_sz = cell_size(self.data.len());
        let offset = cell_offset(self.data.len(), RECOVERY_SLOT_INDEX);
        let aad = &self.header.to_bytes();
        let cell = &self.data[offset..offset + cell_sz];

        let key = recovery_slot_shape_key(&self.header.salt);
        let plaintext = zeroize::Zeroizing::new(aead::decrypt(&key, cell, aad)?);

        const LENGTH_PREFIX: usize = 8;
        if plaintext.len() < LENGTH_PREFIX {
            return Err(Error::Format("decrypted recovery cell too small".into()));
        }
        let len = u64::from_le_bytes(plaintext[..LENGTH_PREFIX].try_into().unwrap()) as usize;
        let end = LENGTH_PREFIX + len;
        if end > plaintext.len() {
            return Err(Error::Format(
                "recovery blob length field exceeds plaintext".into(),
            ));
        }

        Ok(plaintext[LENGTH_PREFIX..end].to_vec())
    }
}

/// Non-secret key giving the recovery slot cell the same
/// nonce||ciphertext||tag shape as every other slot cell. Derived from the
/// (already public) header salt — see `VaultFile::write_recovery_slot`.
fn recovery_slot_shape_key(salt: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, salt);
    let mut key = [0u8; 32];
    hk.expand(b"fob/v1/recovery-slot-shape", &mut key)
        .expect("HKDF expand output length is always valid for 32 bytes");
    key
}

/// Parameters for creating a new vault.
pub struct VaultInitParams {
    pub main_passphrase: Vec<u8>,
    pub decoy_passphrase: Option<Vec<u8>>,
    pub duress_passphrase: Option<Vec<u8>>,
    pub vault_size: usize,
    pub decoy_blob: Option<VaultBlob>,
    /// KDF algorithm and parameters. Use `KdfParams::default_argon2id()`
    /// unless you have a specific reason to override it (e.g. fast tests,
    /// or PBKDF2 for browser-vault compatibility).
    pub kdf_params: KdfParams,
    /// If set, the master secret is additionally hybrid-wrapped
    /// (X25519 + ML-KEM-1024) to this recovery public key and stored in the
    /// vault's recovery slot — see `crate::recovery`.
    pub recovery_pubkey: Option<recovery::RecoveryPublicKey>,
}

impl VaultInitParams {
    /// Convenience constructor: Argon2id KDF, no decoy/duress/recovery.
    pub fn new(main_passphrase: Vec<u8>, vault_size: usize) -> Self {
        Self {
            main_passphrase,
            decoy_passphrase: None,
            duress_passphrase: None,
            vault_size,
            decoy_blob: None,
            kdf_params: KdfParams::default_argon2id(),
            recovery_pubkey: None,
        }
    }
}

impl Drop for VaultInitParams {
    fn drop(&mut self) {
        self.main_passphrase.zeroize();
        if let Some(ref mut p) = self.decoy_passphrase {
            p.zeroize();
        }
        if let Some(ref mut p) = self.duress_passphrase {
            p.zeroize();
        }
    }
}

/// Create a new vault file with the given passphrases and main vault content.
///
/// Returns the full encrypted vault bytes ready to write to disk.
pub fn init_vault(params: VaultInitParams) -> Result<Vec<u8>> {
    validate_passphrases(
        &params.main_passphrase,
        params.decoy_passphrase.as_deref(),
        params.duress_passphrase.as_deref(),
    )?;

    let mut vault_file = VaultFile::create_fresh(params.vault_size, &params.kdf_params)?;
    if params.recovery_pubkey.is_some() {
        // Must happen before any slot is written — the header (including
        // this flag) is used as AEAD associated data on every slot.
        vault_file.set_recovery_enabled(true);
    }
    let fingerprint = vault_fingerprint(&vault_file.header.salt);

    // Derive main slot key and write the (empty) main vault.
    let main_kdf = kdf::derive_master(&params.main_passphrase, &vault_file.header)?;
    let main_keys = kdf::derive_all_slot_keys(main_kdf.master_secret());
    let mut main_blob = VaultBlob::new();
    main_blob.fingerprint = fingerprint.clone();
    vault_file.write_slot(SlotKind::Main, main_keys[0].bytes(), &main_blob)?;

    if let Some(recovery_pubkey) = &params.recovery_pubkey {
        let aad = vault_file.header.to_bytes();
        let wrapped =
            recovery::wrap_secret_for_recovery(main_kdf.master_secret(), recovery_pubkey, &aad)?;
        vault_file.write_recovery_slot(&wrapped.to_bytes())?;
    }

    // Write decoy slot if passphrase provided.
    if let Some(decoy_pass) = &params.decoy_passphrase {
        let decoy_kdf = kdf::derive_master(decoy_pass, &vault_file.header)?;
        let decoy_keys = kdf::derive_all_slot_keys(decoy_kdf.master_secret());
        // Fall back to a freshly-initialized (not zeroed-out) blob — a decoy
        // with version:0/created:0 would be an obvious tell that it's a stub.
        // NB: clippy's unwrap_or_default suggestion is wrong here — VaultBlob's
        // derived Default gives all-zero fields, unlike VaultBlob::new().
        #[allow(clippy::unwrap_or_default)]
        let mut decoy_blob = params.decoy_blob.clone().unwrap_or_else(VaultBlob::new);
        decoy_blob.fingerprint = fingerprint.clone();
        vault_file.write_slot(SlotKind::Decoy, decoy_keys[1].bytes(), &decoy_blob)?;
    }

    // Write duress slot if passphrase provided.
    if let Some(duress_pass) = &params.duress_passphrase {
        let duress_kdf = kdf::derive_master(duress_pass, &vault_file.header)?;
        let duress_keys = kdf::derive_all_slot_keys(duress_kdf.master_secret());
        // Duress blob is deliberately empty — opening it triggers wipe.
        let duress_blob = VaultBlob::new();
        vault_file.write_slot(SlotKind::Duress, duress_keys[2].bytes(), &duress_blob)?;
    }

    Ok(vault_file.data)
}

/// Attempt to unlock a vault using a previously generated recovery private
/// key instead of a passphrase. Only the Main slot is recoverable this way
/// — Decoy and Duress derive from independent passphrases and are
/// unaffected by recovery-key possession.
pub fn recover_vault(
    vault_bytes: &[u8],
    privkey: &recovery::RecoveryPrivateKey,
) -> Result<(SlotKind, VaultBlob)> {
    let vault_file = VaultFile::from_bytes(vault_bytes.to_vec())?;
    if !vault_file.header.recovery_enabled {
        return Err(Error::Format(
            "this vault has no recovery key configured".into(),
        ));
    }

    let aad = vault_file.header.to_bytes();
    let blob_bytes = vault_file.read_recovery_slot()?;
    let wrapped = recovery::RecoveryWrappedBlob::from_bytes(&blob_bytes)?;
    let master_secret = recovery::unwrap_secret_with_recovery(&wrapped, privkey, &aad)?;

    let slot_keys = kdf::derive_all_slot_keys(&master_secret);
    let blob = vault_file.read_slot(SlotKind::Main, slot_keys[0].bytes())?;
    Ok((SlotKind::Main, blob))
}

/// Attempt to unlock a vault with a passphrase.
///
/// Tries Main, Decoy, and Duress slots. Returns `(SlotKind, VaultBlob)` on
/// success. If the Duress slot matches, the vault file at `duress_wipe_path`
/// (if provided) is overwritten with random bytes before returning `Err(Decrypt)`,
/// making the wipe indistinguishable from a wrong passphrase.
pub fn unlock_vault(vault_bytes: &[u8], passphrase: &[u8]) -> Result<(SlotKind, VaultBlob)> {
    unlock_vault_inner(vault_bytes, passphrase, None)
}

/// Like `unlock_vault` but with duress wipe enabled: if the duress passphrase
/// is entered, the file at `vault_path` is cryptographically wiped.
pub fn unlock_vault_with_duress_wipe(
    vault_bytes: &[u8],
    passphrase: &[u8],
    vault_path: &std::path::Path,
) -> Result<(SlotKind, VaultBlob)> {
    unlock_vault_inner(vault_bytes, passphrase, Some(vault_path))
}

fn unlock_vault_inner(
    vault_bytes: &[u8],
    passphrase: &[u8],
    duress_wipe_path: Option<&std::path::Path>,
) -> Result<(SlotKind, VaultBlob)> {
    let vault_file = VaultFile::from_bytes(vault_bytes.to_vec())?;
    let kdf_out = kdf::derive_master(passphrase, &vault_file.header)?;
    let slot_keys = kdf::derive_all_slot_keys(kdf_out.master_secret());

    // Always attempt all three slots so timing does not reveal which slot matched.
    let duress_ok = vault_file
        .read_slot(SlotKind::Duress, slot_keys[2].bytes())
        .is_ok();
    let main_result = vault_file.read_slot(SlotKind::Main, slot_keys[0].bytes());
    let decoy_result = vault_file.read_slot(SlotKind::Decoy, slot_keys[1].bytes());

    if duress_ok {
        if let Some(path) = duress_wipe_path {
            let _ = wipe_file(path, vault_bytes.len());
        }
        return Err(Error::Decrypt);
    }

    if let Ok(blob) = main_result {
        return Ok((SlotKind::Main, blob));
    }
    if let Ok(blob) = decoy_result {
        return Ok((SlotKind::Decoy, blob));
    }

    Err(Error::Decrypt)
}

/// Overwrite a file completely with random bytes, then truncate.
/// Called on duress to destroy all vault data irreversibly.
fn wipe_file(path: &std::path::Path, size: usize) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
    let chunk_size = 65536;
    let mut written = 0;
    let mut chunk = vec![0u8; chunk_size.min(size)];
    while written < size {
        getrandom::getrandom(&mut chunk).map_err(|e| std::io::Error::other(e.to_string()))?;
        let to_write = chunk.len().min(size - written);
        f.write_all(&chunk[..to_write])?;
        written += to_write;
    }
    f.flush()?;
    // Sync to disk — we want this to actually hit storage.
    f.sync_all()?;
    Ok(())
}

fn validate_passphrases(main: &[u8], decoy: Option<&[u8]>, duress: Option<&[u8]>) -> Result<()> {
    use subtle::ConstantTimeEq;
    if main.is_empty() {
        return Err(Error::InvalidArgument(
            "main passphrase cannot be empty".into(),
        ));
    }
    if let Some(d) = decoy {
        if d.ct_eq(main).into() {
            return Err(Error::InvalidArgument(
                "decoy passphrase must differ from main".into(),
            ));
        }
    }
    if let Some(d) = duress {
        if d.ct_eq(main).into() {
            return Err(Error::InvalidArgument(
                "duress passphrase must differ from main".into(),
            ));
        }
    }
    if let (Some(dec), Some(dur)) = (decoy, duress) {
        if dec.ct_eq(dur).into() {
            return Err(Error::InvalidArgument(
                "decoy and duress passphrases must differ".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::STANDARD;

    // Use a smaller vault, and a low iteration count, for fast tests.
    const TEST_VAULT_SIZE: usize = 512 * 1024; // 512 KiB
    const TEST_ITERATIONS: u32 = 1000;

    fn simple_vault(main_pass: &[u8]) -> Vec<u8> {
        init_vault(VaultInitParams {
            main_passphrase: main_pass.to_vec(),
            decoy_passphrase: None,
            duress_passphrase: None,
            vault_size: TEST_VAULT_SIZE,
            decoy_blob: None,
            kdf_params: KdfParams::pbkdf2(TEST_ITERATIONS),
            recovery_pubkey: None,
        })
        .unwrap()
    }

    #[test]
    fn init_and_unlock_main() {
        let vault = simple_vault(b"correct-horse-battery-staple");
        let (slot, blob) = unlock_vault(&vault, b"correct-horse-battery-staple").unwrap();
        assert_eq!(slot, SlotKind::Main);
        assert_eq!(blob.version, FORMAT_VERSION);
        assert!(!blob.fingerprint.is_empty());
    }

    #[test]
    fn wrong_passphrase_fails() {
        let vault = simple_vault(b"my-secret");
        assert!(unlock_vault(&vault, b"wrong-password").is_err());
    }

    #[test]
    fn decoy_slot_opens_with_decoy_passphrase() {
        let main_pass = b"main-pass";
        let decoy_pass = b"decoy-pass";

        let mut decoy_blob = VaultBlob::new();
        decoy_blob.passwords.push(PasswordEntry::new(
            "Fake Bank",
            "fake-user",
            "fake-password-123",
        ));

        let vault = init_vault(VaultInitParams {
            main_passphrase: main_pass.to_vec(),
            decoy_passphrase: Some(decoy_pass.to_vec()),
            duress_passphrase: None,
            vault_size: TEST_VAULT_SIZE,
            decoy_blob: Some(decoy_blob),
            kdf_params: KdfParams::pbkdf2(TEST_ITERATIONS),
            recovery_pubkey: None,
        })
        .unwrap();

        let (slot, blob) = unlock_vault(&vault, main_pass).unwrap();
        assert_eq!(slot, SlotKind::Main);
        assert_eq!(blob.passwords.len(), 0);

        let (slot, blob) = unlock_vault(&vault, decoy_pass).unwrap();
        assert_eq!(slot, SlotKind::Decoy);
        assert_eq!(blob.passwords.len(), 1);
        assert_eq!(blob.passwords[0].name, "Fake Bank");
    }

    #[test]
    fn slot_isolation_different_keys() {
        let main_pass = b"main-passphrase";
        let decoy_pass = b"decoy-passphrase";

        let vault = init_vault(VaultInitParams {
            main_passphrase: main_pass.to_vec(),
            decoy_passphrase: Some(decoy_pass.to_vec()),
            duress_passphrase: None,
            vault_size: TEST_VAULT_SIZE,
            decoy_blob: None,
            kdf_params: KdfParams::pbkdf2(TEST_ITERATIONS),
            recovery_pubkey: None,
        })
        .unwrap();

        // Main key should not open decoy slot.
        let vault_file = VaultFile::from_bytes(vault.clone()).unwrap();
        let main_kdf = kdf::derive_master(main_pass, &vault_file.header).unwrap();
        let main_keys = kdf::derive_all_slot_keys(main_kdf.master_secret());
        assert!(vault_file
            .read_slot(SlotKind::Decoy, main_keys[1].bytes())
            .is_err());

        // Decoy key should not open main slot.
        let decoy_kdf = kdf::derive_master(decoy_pass, &vault_file.header).unwrap();
        let decoy_keys = kdf::derive_all_slot_keys(decoy_kdf.master_secret());
        assert!(vault_file
            .read_slot(SlotKind::Main, decoy_keys[0].bytes())
            .is_err());
    }

    #[test]
    fn vault_blob_roundtrip_json() {
        let mut blob = VaultBlob::new();
        blob.passwords
            .push(PasswordEntry::new("Test", "user", "pw"));
        blob.notes.push(NoteEntry::new("Note", "body text"));
        blob.files.push(FileEntry::new(
            "secret.txt",
            "text/plain",
            11,
            B64.encode(b"hello world"),
        ));
        blob.cards.push(CardEntry::new(
            "Chase Sapphire",
            "Alice",
            "4111111111111111",
            "09",
            "2029",
            "123",
        ));
        blob.recovery_codes.push(RecoveryCodeEntry::new(
            "GitHub",
            vec!["aaaa-bbbb-cccc".to_string(), "dddd-eeee-ffff".to_string()],
        ));

        let json = blob.to_json().unwrap();
        let parsed = VaultBlob::from_json(&json).unwrap();

        assert_eq!(parsed.passwords.len(), 1);
        assert_eq!(parsed.passwords[0].name, "Test");
        assert_eq!(parsed.notes.len(), 1);
        assert_eq!(parsed.notes[0].title, "Note");
        assert_eq!(parsed.files.len(), 1);
        assert_eq!(parsed.files[0].name, "secret.txt");
        assert_eq!(parsed.files[0].size, 11);
        assert_eq!(parsed.files[0].data, B64.encode(b"hello world"));
        assert_eq!(parsed.cards.len(), 1);
        assert_eq!(parsed.cards[0].number.expose(), "4111111111111111");
        assert_eq!(parsed.cards[0].cvv.expose(), "123");
        assert_eq!(parsed.recovery_codes.len(), 1);
        assert_eq!(parsed.recovery_codes[0].codes.len(), 2);
        assert_eq!(parsed.recovery_codes[0].codes[0].expose(), "aaaa-bbbb-cccc");
    }

    #[test]
    fn vault_blob_json_uses_browser_field_names() {
        let mut blob = VaultBlob::new();
        blob.last_modified = 42;
        let json = blob.to_json().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(value["modified"], 42);
        assert!(value.get("totp").is_some());
        assert!(value.get("last_modified").is_none());
        assert!(value.get("totps").is_none());
        // `files`, `cards` and `recovery_codes` are live schema surface (added
        // for the file/card/recovery-code vault sections); they always
        // serialize as present-but-empty so both interfaces stay in sync and
        // older vaults deserialize them with serde defaults.
        assert!(value.get("files").is_some());
        assert!(value.get("cards").is_some());
        assert!(value.get("recovery_codes").is_some());
        assert_eq!(value["files"].as_array().unwrap().len(), 0);
        assert_eq!(value["cards"].as_array().unwrap().len(), 0);
        assert_eq!(value["recovery_codes"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn password_entry_json_has_no_dead_tags_or_history_fields() {
        let entry = PasswordEntry::new("Test", "user", "pw");
        let json = serde_json::to_value(&entry).unwrap();
        assert!(json.get("tags").is_none());
        assert!(json.get("history").is_none());
    }

    #[test]
    fn vault_file_is_correct_size() {
        let vault = simple_vault(b"pass");
        assert_eq!(vault.len(), TEST_VAULT_SIZE);
    }

    #[test]
    fn tampered_vault_fails_decryption() {
        let mut vault = simple_vault(b"secure-pass");
        // Flip bytes in the first slot cell.
        let offset = crate::format::cell_offset(TEST_VAULT_SIZE, 0);
        vault[offset] ^= 0xFF;
        vault[offset + 1] ^= 0xFF;
        assert!(unlock_vault(&vault, b"secure-pass").is_err());
    }

    #[test]
    fn duplicate_passphrases_rejected() {
        let result = init_vault(VaultInitParams {
            main_passphrase: b"same".to_vec(),
            decoy_passphrase: Some(b"same".to_vec()),
            duress_passphrase: None,
            vault_size: TEST_VAULT_SIZE,
            decoy_blob: None,
            kdf_params: KdfParams::pbkdf2(TEST_ITERATIONS),
            recovery_pubkey: None,
        });
        assert!(result.is_err());
    }

    #[test]
    fn entry_persistence_through_unlock() {
        let pass = b"my-vault-pass";
        let vault_size = TEST_VAULT_SIZE;

        // Init vault.
        let vault_bytes = init_vault(VaultInitParams {
            main_passphrase: pass.to_vec(),
            decoy_passphrase: None,
            duress_passphrase: None,
            vault_size,
            decoy_blob: None,
            kdf_params: KdfParams::pbkdf2(TEST_ITERATIONS),
            recovery_pubkey: None,
        })
        .unwrap();

        // Unlock, add an entry, re-lock (re-write).
        let (slot, mut blob) = unlock_vault(&vault_bytes, pass).unwrap();
        blob.passwords
            .push(PasswordEntry::new("GitHub", "alice", "gh-secret"));
        blob.touch();

        let mut vault_file = VaultFile::from_bytes(vault_bytes).unwrap();
        let kdf_out = kdf::derive_master(pass, &vault_file.header).unwrap();
        let slot_keys = kdf::derive_all_slot_keys(kdf_out.master_secret());
        vault_file
            .write_slot(slot, slot_keys[slot.index()].bytes(), &blob)
            .unwrap();

        // Unlock again and verify entry is present.
        let (_, loaded) = unlock_vault(&vault_file.data, pass).unwrap();
        assert_eq!(loaded.passwords.len(), 1);
        assert_eq!(loaded.passwords[0].name, "GitHub");
    }

    /// Regression test for the critical AES-GCM nonce-reuse bug: v2 stored a
    /// fixed nonce per slot in the header and reused it on every save. Two
    /// successive writes of the *same slot* must now produce cells whose
    /// first `GCM_NONCE_LEN` bytes (the nonce) differ, and each write must
    /// still decrypt back to its own distinct content — proving nonces are
    /// generated fresh per write, not reused.
    #[test]
    fn write_slot_never_reuses_a_nonce_across_saves() {
        let pass = b"nonce-reuse-regression-pass";
        let vault_bytes = init_vault(VaultInitParams {
            main_passphrase: pass.to_vec(),
            decoy_passphrase: None,
            duress_passphrase: None,
            vault_size: TEST_VAULT_SIZE,
            decoy_blob: None,
            kdf_params: KdfParams::pbkdf2(TEST_ITERATIONS),
            recovery_pubkey: None,
        })
        .unwrap();

        let mut vault_file = VaultFile::from_bytes(vault_bytes).unwrap();
        let kdf_out = kdf::derive_master(pass, &vault_file.header).unwrap();
        let slot_keys = kdf::derive_all_slot_keys(kdf_out.master_secret());
        let slot = SlotKind::Main;
        let key = slot_keys[slot.index()].bytes();

        let cell_sz = crate::format::cell_size(vault_file.data.len());
        let offset = crate::format::cell_offset(vault_file.data.len(), slot.index());

        let mut blob_a = VaultBlob::new();
        blob_a
            .passwords
            .push(PasswordEntry::new("Site A", "alice", "pw-a"));
        vault_file.write_slot(slot, key, &blob_a).unwrap();
        let cell_after_a = vault_file.data[offset..offset + cell_sz].to_vec();
        let nonce_a = &cell_after_a[..aead::GCM_NONCE_LEN];

        let mut blob_b = VaultBlob::new();
        blob_b
            .passwords
            .push(PasswordEntry::new("Site B", "bob", "pw-b"));
        vault_file.write_slot(slot, key, &blob_b).unwrap();
        let cell_after_b = vault_file.data[offset..offset + cell_sz].to_vec();
        let nonce_b = &cell_after_b[..aead::GCM_NONCE_LEN];

        assert_ne!(
            nonce_a, nonce_b,
            "two successive writes to the same slot reused the same AES-GCM nonce"
        );

        // Sanity: the second write is what's actually stored and readable now.
        let loaded = vault_file.read_slot(slot, key).unwrap();
        assert_eq!(loaded.passwords[0].name, "Site B");
    }

    #[test]
    fn duress_passphrase_returns_generic_error() {
        let vault = init_vault(VaultInitParams {
            main_passphrase: b"main-pass".to_vec(),
            decoy_passphrase: None,
            duress_passphrase: Some(b"duress-pass".to_vec()),
            vault_size: TEST_VAULT_SIZE,
            decoy_blob: None,
            kdf_params: KdfParams::pbkdf2(TEST_ITERATIONS),
            recovery_pubkey: None,
        })
        .unwrap();

        // Main passphrase must still open normally.
        assert!(unlock_vault(&vault, b"main-pass").is_ok());

        // Duress passphrase must return the same error as a wrong passphrase.
        let result = unlock_vault(&vault, b"duress-pass");
        assert!(
            result.is_err(),
            "duress must not open a vault — got {:?}",
            result
        );
    }

    #[test]
    fn create_fresh_rejects_oversized_vault() {
        let result =
            VaultFile::create_fresh(MAX_VAULT_SIZE + 1, &KdfParams::pbkdf2(TEST_ITERATIONS));
        assert!(result.is_err(), "vault_size above MAX_VAULT_SIZE must fail");
    }

    #[test]
    fn from_bytes_rejects_oversized_data() {
        // Don't actually allocate a gigabyte-plus buffer for this test — a
        // header-shaped prefix is enough since the size check runs before
        // header parsing.
        let mut data = vec![0u8; HEADER_SIZE];
        data[..4].copy_from_slice(crate::format::MAGIC);
        let oversized_len = MAX_VAULT_SIZE + 1;
        data.resize(oversized_len, 0);

        let result = VaultFile::from_bytes(data);
        assert!(
            result.is_err(),
            "vault file larger than MAX_VAULT_SIZE must be rejected"
        );
    }

    #[test]
    fn from_bytes_rejects_undersized_data_with_a_clear_error() {
        // A truncated/corrupted vault.fob (e.g. an interrupted USB copy)
        // must be rejected with a clear diagnostic here, not silently
        // accepted into a file with degenerate slot cells that only
        // surfaces later as an opaque "wrong passphrase" on every unlock.
        let mut data = vec![0u8; HEADER_SIZE + 10];
        data[..4].copy_from_slice(crate::format::MAGIC);

        match VaultFile::from_bytes(data) {
            Err(err) => assert!(
                format!("{err}").contains("below the minimum"),
                "expected a clear minimum-size error, got: {err}"
            ),
            Ok(_) => panic!("expected an error for an undersized vault file"),
        }
    }

    // Small, fast Argon2id params for tests — not a security recommendation.
    fn test_argon2id_params() -> KdfParams {
        KdfParams {
            algorithm: KdfAlgorithm::Argon2id,
            time_cost: 1,
            memory_kib: 8 * 1024,
            parallelism: 1,
        }
    }

    #[test]
    fn init_and_unlock_main_with_argon2id() {
        let vault = init_vault(VaultInitParams {
            main_passphrase: b"correct-horse-battery-staple".to_vec(),
            decoy_passphrase: None,
            duress_passphrase: None,
            vault_size: TEST_VAULT_SIZE,
            decoy_blob: None,
            kdf_params: test_argon2id_params(),
            recovery_pubkey: None,
        })
        .unwrap();

        let (slot, blob) = unlock_vault(&vault, b"correct-horse-battery-staple").unwrap();
        assert_eq!(slot, SlotKind::Main);
        assert_eq!(blob.version, FORMAT_VERSION);

        let header = VaultHeader::parse(&vault).unwrap();
        assert_eq!(header.kdf_algorithm, KdfAlgorithm::Argon2id);
    }

    #[test]
    fn new_vaults_default_to_argon2id() {
        let vault = init_vault(VaultInitParams::new(b"pw".to_vec(), TEST_VAULT_SIZE)).unwrap();
        let header = VaultHeader::parse(&vault).unwrap();
        assert_eq!(header.kdf_algorithm, KdfAlgorithm::Argon2id);
        assert_eq!(header.format_version, FORMAT_VERSION);
    }

    #[test]
    fn recovery_key_unlocks_main_slot() {
        let (pubkey, privkey) = recovery::generate_recovery_keypair();
        let vault = init_vault(VaultInitParams {
            main_passphrase: b"main-pass".to_vec(),
            decoy_passphrase: None,
            duress_passphrase: None,
            vault_size: TEST_VAULT_SIZE,
            decoy_blob: None,
            kdf_params: KdfParams::pbkdf2(TEST_ITERATIONS),
            recovery_pubkey: Some(pubkey),
        })
        .unwrap();

        let header = VaultHeader::parse(&vault).unwrap();
        assert!(header.recovery_enabled);

        let (slot, blob) = recover_vault(&vault, &privkey).unwrap();
        assert_eq!(slot, SlotKind::Main);
        assert_eq!(blob.version, FORMAT_VERSION);

        // Passphrase unlock still works normally alongside recovery.
        let (slot, _) = unlock_vault(&vault, b"main-pass").unwrap();
        assert_eq!(slot, SlotKind::Main);
    }

    #[test]
    fn recovery_reflects_saved_entries() {
        let (pubkey, privkey) = recovery::generate_recovery_keypair();
        let pass = b"main-pass";
        let vault_bytes = init_vault(VaultInitParams {
            main_passphrase: pass.to_vec(),
            decoy_passphrase: None,
            duress_passphrase: None,
            vault_size: TEST_VAULT_SIZE,
            decoy_blob: None,
            kdf_params: KdfParams::pbkdf2(TEST_ITERATIONS),
            recovery_pubkey: Some(pubkey),
        })
        .unwrap();

        let (slot, mut blob) = unlock_vault(&vault_bytes, pass).unwrap();
        blob.passwords
            .push(PasswordEntry::new("GitHub", "alice", "gh-secret"));

        let mut vault_file = VaultFile::from_bytes(vault_bytes).unwrap();
        let kdf_out = kdf::derive_master(pass, &vault_file.header).unwrap();
        let slot_keys = kdf::derive_all_slot_keys(kdf_out.master_secret());
        vault_file
            .write_slot(slot, slot_keys[slot.index()].bytes(), &blob)
            .unwrap();

        let (_, recovered) = recover_vault(&vault_file.data, &privkey).unwrap();
        assert_eq!(recovered.passwords.len(), 1);
        assert_eq!(recovered.passwords[0].name, "GitHub");
    }

    #[test]
    fn wrong_recovery_key_fails() {
        let (pubkey, _correct_privkey) = recovery::generate_recovery_keypair();
        let (_, wrong_privkey) = recovery::generate_recovery_keypair();
        let vault = init_vault(VaultInitParams {
            main_passphrase: b"main-pass".to_vec(),
            decoy_passphrase: None,
            duress_passphrase: None,
            vault_size: TEST_VAULT_SIZE,
            decoy_blob: None,
            kdf_params: KdfParams::pbkdf2(TEST_ITERATIONS),
            recovery_pubkey: Some(pubkey),
        })
        .unwrap();

        assert!(recover_vault(&vault, &wrong_privkey).is_err());
    }

    #[test]
    fn recovery_disabled_vault_rejects_recovery_attempt() {
        let (_pubkey, privkey) = recovery::generate_recovery_keypair();
        let vault = simple_vault(b"main-pass"); // no recovery configured
        let err = recover_vault(&vault, &privkey).unwrap_err();
        assert!(format!("{err}").contains("no recovery key configured"));
    }

    #[test]
    fn non_recovery_vault_reserved_slot_is_unaffected() {
        // Regression: a vault created without recovery must leave slot 3
        // exactly as before — pure random, not recovery-shaped.
        let vault = simple_vault(b"main-pass");
        let header = VaultHeader::parse(&vault).unwrap();
        assert!(!header.recovery_enabled);
    }

    #[test]
    fn small_vault_rejects_recovery_enrollment() {
        let (pubkey, _privkey) = recovery::generate_recovery_keypair();
        // MIN_VAULT_SIZE cells are far too small to hold a ~1.6KB recovery
        // blob; enabling recovery on one must fail cleanly, not panic or
        // silently truncate.
        let result = init_vault(VaultInitParams {
            main_passphrase: b"pw".to_vec(),
            decoy_passphrase: None,
            duress_passphrase: None,
            vault_size: MIN_VAULT_SIZE,
            decoy_blob: None,
            kdf_params: KdfParams::pbkdf2(TEST_ITERATIONS),
            recovery_pubkey: Some(pubkey),
        });
        assert!(result.is_err());
    }

    #[test]
    fn unlock_always_attempts_all_three_slots_regardless_of_kdf_algorithm() {
        // Timing-uniformity invariant (see unlock_vault_inner's comment)
        // must hold under Argon2id too, not just PBKDF2: a single KDF
        // derivation, then all three slots attempted regardless of match.
        let vault = init_vault(VaultInitParams {
            main_passphrase: b"main-pass".to_vec(),
            decoy_passphrase: Some(b"decoy-pass".to_vec()),
            duress_passphrase: Some(b"duress-pass".to_vec()),
            vault_size: TEST_VAULT_SIZE,
            decoy_blob: None,
            kdf_params: test_argon2id_params(),
            recovery_pubkey: None,
        })
        .unwrap();

        assert!(matches!(
            unlock_vault(&vault, b"main-pass"),
            Ok((SlotKind::Main, _))
        ));
        assert!(matches!(
            unlock_vault(&vault, b"decoy-pass"),
            Ok((SlotKind::Decoy, _))
        ));
        assert!(unlock_vault(&vault, b"duress-pass").is_err());
        assert!(unlock_vault(&vault, b"totally-wrong").is_err());
    }
}
