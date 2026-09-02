use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

use crate::{
    error::{Error, Result},
    format::{KdfAlgorithm, VaultHeader},
    mem::LockedSecret,
};

/// Vault master secret, derived from a passphrase via either PBKDF2 or
/// Argon2id (see `derive_master`).
///
/// Backed by `LockedSecret`: mlocked (best-effort, non-fatal if the OS
/// denies it) and excluded from core dumps for as long as it's alive, and
/// zeroized + munlocked on drop — not just zeroized.
pub struct KdfOutput(LockedSecret<32>);

impl KdfOutput {
    pub fn master_secret(&self) -> &[u8; 32] {
        self.0.bytes()
    }
}

/// Derive the master secret using the KDF and parameters recorded in a
/// vault header. This is the single call site vault.rs should use — it
/// dispatches on `header.kdf_algorithm` so callers never need an `if`.
pub fn derive_master(passphrase: &[u8], header: &VaultHeader) -> Result<KdfOutput> {
    match header.kdf_algorithm {
        KdfAlgorithm::Pbkdf2Sha256 => Ok(derive_master_pbkdf2(
            passphrase,
            &header.salt,
            header.kdf_time_cost,
        )),
        KdfAlgorithm::Argon2id => derive_master_argon2id(
            passphrase,
            &header.salt,
            header.argon2_memory_kib,
            header.kdf_time_cost,
            header.argon2_parallelism,
        ),
    }
}

/// Derive the 32-byte master secret via PBKDF2-HMAC-SHA256.
///
/// Used for v3 vaults (permanently supported) and the WebCrypto browser
/// vault, which has no native Argon2id primitive — this keeps the CLI and
/// browser vault on one interoperable KDF for files created either way.
///
/// The salt must be random (from CSPRNG) and stored in the vault header.
pub fn derive_master_pbkdf2(passphrase: &[u8], salt: &[u8; 32], iterations: u32) -> KdfOutput {
    let mut output = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase, salt, iterations, &mut output);
    KdfOutput(LockedSecret::new(output))
}

/// Derive the 32-byte master secret via Argon2id — the default KDF for new
/// (v4) vaults created by the CLI. Memory-hard, unlike PBKDF2, which raises
/// the cost of GPU/ASIC offline brute-force against a stolen vault file.
///
/// Not available to the WebCrypto browser vault (no native Argon2id
/// primitive there), so browser-created vaults stay on PBKDF2.
pub fn derive_master_argon2id(
    passphrase: &[u8],
    salt: &[u8; 32],
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
) -> Result<KdfOutput> {
    let params = Params::new(memory_kib, time_cost, parallelism, Some(32))
        .map_err(|e| Error::Kdf(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut output)
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(KdfOutput(LockedSecret::new(output)))
}

/// HKDF-SHA256 key derivation for individual vault slot keys.
///
/// `master_secret` is a KDF output above (PBKDF2 or Argon2id).
/// `info` is a domain-separation string like `"fob/v1/main"`.
pub fn derive_slot_key(master_secret: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master_secret);
    let mut key = [0u8; 32];
    hk.expand(info, &mut key)
        .expect("HKDF expand output length is always valid for 32 bytes");
    key
}

/// Domain-separated labels for each vault slot.
pub const SLOT_LABELS: [&[u8]; 4] = [
    b"fob/v1/main",
    b"fob/v1/decoy",
    b"fob/v1/duress",
    b"fob/v1/reserved",
];

/// Derive all four slot keys from a master secret.
///
/// Each key is individually mlocked and zeroized on drop via `LockedSecret`
/// — these are real AES-256-GCM keys capable of decrypting the whole vault,
/// not incidental scratch data.
pub fn derive_all_slot_keys(master_secret: &[u8; 32]) -> [LockedSecret<32>; 4] {
    [
        LockedSecret::new(derive_slot_key(master_secret, SLOT_LABELS[0])),
        LockedSecret::new(derive_slot_key(master_secret, SLOT_LABELS[1])),
        LockedSecret::new(derive_slot_key(master_secret, SLOT_LABELS[2])),
        LockedSecret::new(derive_slot_key(master_secret, SLOT_LABELS[3])),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{KdfAlgorithm, VaultHeader};

    const TEST_ITERATIONS: u32 = 1000; // small, fast iteration count for tests

    // Small, fast Argon2id params for tests — not a security recommendation.
    const TEST_ARGON2_MEMORY_KIB: u32 = 8 * 1024;
    const TEST_ARGON2_TIME_COST: u32 = 1;
    const TEST_ARGON2_PARALLELISM: u32 = 1;

    fn test_salt() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn test_header_pbkdf2() -> VaultHeader {
        VaultHeader {
            format_version: 4,
            kdf_algorithm: KdfAlgorithm::Pbkdf2Sha256,
            kdf_time_cost: TEST_ITERATIONS,
            argon2_memory_kib: 0,
            argon2_parallelism: 0,
            salt: test_salt(),
            recovery_enabled: false,
        }
    }

    fn test_header_argon2id() -> VaultHeader {
        VaultHeader {
            format_version: 4,
            kdf_algorithm: KdfAlgorithm::Argon2id,
            kdf_time_cost: TEST_ARGON2_TIME_COST,
            argon2_memory_kib: TEST_ARGON2_MEMORY_KIB,
            argon2_parallelism: TEST_ARGON2_PARALLELISM,
            salt: test_salt(),
            recovery_enabled: false,
        }
    }

    #[test]
    fn derive_master_pbkdf2_produces_32_bytes() {
        let out = derive_master_pbkdf2(b"test-passphrase", &test_salt(), TEST_ITERATIONS);
        assert_ne!(out.master_secret(), &[0u8; 32]);
    }

    #[test]
    fn derive_master_pbkdf2_is_deterministic() {
        let a = derive_master_pbkdf2(b"hunter2", &test_salt(), TEST_ITERATIONS);
        let b = derive_master_pbkdf2(b"hunter2", &test_salt(), TEST_ITERATIONS);
        assert_eq!(a.master_secret(), b.master_secret());
    }

    #[test]
    fn derive_master_pbkdf2_different_passphrases() {
        let a = derive_master_pbkdf2(b"passphrase-a", &test_salt(), TEST_ITERATIONS);
        let b = derive_master_pbkdf2(b"passphrase-b", &test_salt(), TEST_ITERATIONS);
        assert_ne!(a.master_secret(), b.master_secret());
    }

    #[test]
    fn derive_master_pbkdf2_different_salts() {
        let salt_a = [0x11u8; 32];
        let salt_b = [0x22u8; 32];
        let a = derive_master_pbkdf2(b"same-passphrase", &salt_a, TEST_ITERATIONS);
        let b = derive_master_pbkdf2(b"same-passphrase", &salt_b, TEST_ITERATIONS);
        assert_ne!(a.master_secret(), b.master_secret());
    }

    #[test]
    fn derive_master_pbkdf2_different_iterations() {
        let a = derive_master_pbkdf2(b"same-passphrase", &test_salt(), 1000);
        let b = derive_master_pbkdf2(b"same-passphrase", &test_salt(), 2000);
        assert_ne!(a.master_secret(), b.master_secret());
    }

    #[test]
    fn derive_master_argon2id_produces_32_bytes() {
        let out = derive_master_argon2id(
            b"test-passphrase",
            &test_salt(),
            TEST_ARGON2_MEMORY_KIB,
            TEST_ARGON2_TIME_COST,
            TEST_ARGON2_PARALLELISM,
        )
        .unwrap();
        assert_ne!(out.master_secret(), &[0u8; 32]);
    }

    #[test]
    fn derive_master_argon2id_is_deterministic() {
        let a = derive_master_argon2id(
            b"hunter2",
            &test_salt(),
            TEST_ARGON2_MEMORY_KIB,
            TEST_ARGON2_TIME_COST,
            TEST_ARGON2_PARALLELISM,
        )
        .unwrap();
        let b = derive_master_argon2id(
            b"hunter2",
            &test_salt(),
            TEST_ARGON2_MEMORY_KIB,
            TEST_ARGON2_TIME_COST,
            TEST_ARGON2_PARALLELISM,
        )
        .unwrap();
        assert_eq!(a.master_secret(), b.master_secret());
    }

    #[test]
    fn derive_master_argon2id_different_passphrases() {
        let a = derive_master_argon2id(
            b"passphrase-a",
            &test_salt(),
            TEST_ARGON2_MEMORY_KIB,
            TEST_ARGON2_TIME_COST,
            TEST_ARGON2_PARALLELISM,
        )
        .unwrap();
        let b = derive_master_argon2id(
            b"passphrase-b",
            &test_salt(),
            TEST_ARGON2_MEMORY_KIB,
            TEST_ARGON2_TIME_COST,
            TEST_ARGON2_PARALLELISM,
        )
        .unwrap();
        assert_ne!(a.master_secret(), b.master_secret());
    }

    #[test]
    fn derive_master_argon2id_rejects_invalid_params() {
        // p_cost = 0 is out of range for argon2's Params::new.
        let err = derive_master_argon2id(b"pw", &test_salt(), TEST_ARGON2_MEMORY_KIB, 1, 0);
        assert!(err.is_err());
    }

    #[test]
    fn derive_master_dispatches_pbkdf2() {
        let header = test_header_pbkdf2();
        let a = derive_master(b"hunter2", &header).unwrap();
        let b = derive_master_pbkdf2(b"hunter2", &header.salt, header.kdf_time_cost);
        assert_eq!(a.master_secret(), b.master_secret());
    }

    #[test]
    fn derive_master_dispatches_argon2id() {
        let header = test_header_argon2id();
        let a = derive_master(b"hunter2", &header).unwrap();
        let b = derive_master_argon2id(
            b"hunter2",
            &header.salt,
            header.argon2_memory_kib,
            header.kdf_time_cost,
            header.argon2_parallelism,
        )
        .unwrap();
        assert_eq!(a.master_secret(), b.master_secret());
    }

    #[test]
    fn slot_keys_are_distinct() {
        let master = [0xABu8; 32];
        let keys = derive_all_slot_keys(&master);
        assert_ne!(keys[0].bytes(), keys[1].bytes());
        assert_ne!(keys[0].bytes(), keys[2].bytes());
        assert_ne!(keys[1].bytes(), keys[2].bytes());
        assert_ne!(keys[0].bytes(), keys[3].bytes());
    }

    #[test]
    fn slot_keys_are_deterministic() {
        let master = [0xABu8; 32];
        let a = derive_all_slot_keys(&master);
        let b = derive_all_slot_keys(&master);
        for i in 0..4 {
            assert_eq!(a[i].bytes(), b[i].bytes());
        }
    }

    #[test]
    fn slot_key_changes_with_master() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        assert_ne!(
            derive_slot_key(&a, SLOT_LABELS[0]),
            derive_slot_key(&b, SLOT_LABELS[0])
        );
    }
}
