/// Hybrid X25519 + ML-KEM-1024 post-quantum recovery key.
///
/// Optional, opt-in at vault creation: generates an offline recovery
/// keypair. The vault's master secret gets an additional copy wrapped to
/// the recovery public key, so presenting the recovery private key later
/// unlocks the vault without the passphrase (Main slot only — Decoy and
/// Duress derive from independent passphrases and are unaffected). The KEM
/// is hybrid (classical X25519 + post-quantum ML-KEM-1024, FIPS 203) so the
/// recovery path stays quantum-hard even if one of the two primitives is
/// ever broken.
///
/// This does *not* change the quantum posture of the passphrase-unlock path
/// (PBKDF2/Argon2id + AES-256-GCM, see `kdf.rs`) — that path never depended
/// on asymmetric crypto and already keeps ~128-bit security under Grover's
/// algorithm. This module adds the vault's first asymmetric component, and
/// makes it PQ-hybrid from day one.
///
/// The recovery private key is never written to disk by this module — it
/// exists only in memory (self-zeroizing on drop, via the `zeroize`
/// features of `x25519-dalek`/`ml-kem`) and as a one-time display string
/// (see `encode_private_key_for_display`) the caller must persist
/// out-of-band (printed, written down, stored in a safe).
use base64::{engine::general_purpose::STANDARD, Engine};
use hkdf::Hkdf;
use ml_kem::{Decapsulate, Encapsulate, Kem as _, MlKem1024};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use crate::{
    aead,
    error::{Error, Result},
};

type MlKemEncapsulationKey = ml_kem::EncapsulationKey1024;
type MlKemDecapsulationKey = ml_kem::DecapsulationKey1024;
type MlKemCiphertext = ml_kem::ml_kem_1024::Ciphertext;

const X25519_LEN: usize = 32;
/// ML-KEM-1024 encapsulation key (public key) size in bytes, per FIPS 203.
pub const MLKEM_EK_LEN: usize = 1568;
/// ML-KEM-1024 ciphertext size in bytes, per FIPS 203.
pub const MLKEM_CT_LEN: usize = 1568;
/// ML-KEM decapsulation key seed size in bytes (constant across all
/// ML-KEM parameter sets).
pub const MLKEM_SEED_LEN: usize = 64;

/// Total serialized size of a `RecoveryWrappedBlob`:
/// ephemeral X25519 public key + ML-KEM-1024 ciphertext + AEAD(32-byte
/// secret) = 32 + 1568 + (12 nonce + 32 ct + 16 tag) = 1660 bytes.
pub const RECOVERY_BLOB_LEN: usize =
    X25519_LEN + MLKEM_CT_LEN + aead::GCM_NONCE_LEN + 32 + aead::GCM_TAG_LEN;

/// Domain-separation label for the HKDF step combining the X25519 and
/// ML-KEM shared secrets into a single AES-256-GCM wrapping key.
const WRAP_HKDF_INFO: &[u8] = b"fob/v1/recovery-wrap-v1";

/// Recovery public key — used once at vault-creation time to wrap the
/// master secret. Not persisted on its own (only the resulting
/// `RecoveryWrappedBlob` is stored in the vault).
pub struct RecoveryPublicKey {
    x25519: X25519PublicKey,
    mlkem: MlKemEncapsulationKey,
}

/// Recovery private key. Never stored on disk — see module docs.
pub struct RecoveryPrivateKey {
    x25519: X25519StaticSecret,
    mlkem: MlKemDecapsulationKey,
}

/// The master secret, hybrid-wrapped to a `RecoveryPublicKey`. This is what
/// actually gets stored on disk (in the vault's recovery slot).
pub struct RecoveryWrappedBlob {
    ephemeral_x25519_public: [u8; X25519_LEN],
    mlkem_ciphertext: [u8; MLKEM_CT_LEN],
    /// `nonce || ciphertext || tag` from `aead::encrypt`, always exactly
    /// `GCM_NONCE_LEN + 32 + GCM_TAG_LEN` bytes (the wrapped value is
    /// always a 32-byte master secret).
    aead_blob: Vec<u8>,
}

impl RecoveryWrappedBlob {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RECOVERY_BLOB_LEN);
        out.extend_from_slice(&self.ephemeral_x25519_public);
        out.extend_from_slice(&self.mlkem_ciphertext);
        out.extend_from_slice(&self.aead_blob);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != RECOVERY_BLOB_LEN {
            return Err(Error::Format(format!(
                "recovery blob has wrong length: {} (expected {RECOVERY_BLOB_LEN})",
                data.len()
            )));
        }
        let ephemeral_x25519_public: [u8; X25519_LEN] = data[..X25519_LEN].try_into().unwrap();
        let mlkem_ciphertext: [u8; MLKEM_CT_LEN] = data[X25519_LEN..X25519_LEN + MLKEM_CT_LEN]
            .try_into()
            .unwrap();
        let aead_blob = data[X25519_LEN + MLKEM_CT_LEN..].to_vec();
        Ok(Self {
            ephemeral_x25519_public,
            mlkem_ciphertext,
            aead_blob,
        })
    }
}

/// Generate a fresh hybrid recovery keypair.
pub fn generate_recovery_keypair() -> (RecoveryPublicKey, RecoveryPrivateKey) {
    let x25519_secret = X25519StaticSecret::random();
    let x25519_public = X25519PublicKey::from(&x25519_secret);
    let (mlkem_dk, mlkem_ek) = MlKem1024::generate_keypair();

    (
        RecoveryPublicKey {
            x25519: x25519_public,
            mlkem: mlkem_ek,
        },
        RecoveryPrivateKey {
            x25519: x25519_secret,
            mlkem: mlkem_dk,
        },
    )
}

/// Hybrid-wrap a 32-byte secret (the vault's master secret) to a recovery
/// public key.
///
/// `aad` binds the wrap to its context (pass the vault header bytes, same
/// as every other slot) so a wrapped blob from one vault can't be replayed
/// into another.
pub fn wrap_secret_for_recovery(
    secret: &[u8; 32],
    pubkey: &RecoveryPublicKey,
    aad: &[u8],
) -> Result<RecoveryWrappedBlob> {
    let ephemeral_secret = X25519StaticSecret::random();
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let x25519_shared = ephemeral_secret.diffie_hellman(&pubkey.x25519);

    let (mlkem_ct, mlkem_shared) = pubkey.mlkem.encapsulate();

    let wrap_key = derive_wrap_key(x25519_shared.as_bytes(), mlkem_shared.as_ref());
    let aead_blob = aead::encrypt(&wrap_key, secret, aad)?;

    Ok(RecoveryWrappedBlob {
        ephemeral_x25519_public: ephemeral_public.to_bytes(),
        mlkem_ciphertext: <[u8; MLKEM_CT_LEN]>::try_from(mlkem_ct.as_ref()).unwrap(),
        aead_blob,
    })
}

/// Reverse `wrap_secret_for_recovery`, recovering the original 32-byte
/// secret. `aad` must match exactly what was passed to `wrap_secret_for_recovery`.
pub fn unwrap_secret_with_recovery(
    blob: &RecoveryWrappedBlob,
    privkey: &RecoveryPrivateKey,
    aad: &[u8],
) -> Result<[u8; 32]> {
    let ephemeral_public = X25519PublicKey::from(blob.ephemeral_x25519_public);
    let x25519_shared = privkey.x25519.diffie_hellman(&ephemeral_public);

    let ct = MlKemCiphertext::try_from(blob.mlkem_ciphertext.as_slice())
        .map_err(|_| Error::Format("invalid recovery ML-KEM ciphertext".into()))?;
    let mlkem_shared = privkey.mlkem.decapsulate(&ct);

    let wrap_key = derive_wrap_key(x25519_shared.as_bytes(), mlkem_shared.as_ref());
    let plaintext = aead::decrypt(&wrap_key, &blob.aead_blob, aad)?;

    plaintext
        .try_into()
        .map_err(|_| Error::Format("recovered secret has the wrong length".into()))
}

fn derive_wrap_key(x25519_shared: &[u8; 32], mlkem_shared: &[u8]) -> zeroize::Zeroizing<[u8; 32]> {
    let mut ikm = zeroize::Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(x25519_shared);
    ikm[32..].copy_from_slice(mlkem_shared);

    let hk = Hkdf::<Sha256>::new(None, &*ikm);
    let mut wrap_key = zeroize::Zeroizing::new([0u8; 32]);
    hk.expand(WRAP_HKDF_INFO, &mut *wrap_key)
        .expect("HKDF expand output length is always valid for 32 bytes");
    wrap_key
}

/// Encode a recovery private key as a string for one-time display to the
/// user (e.g. to print or write down). Includes a truncated SHA-256
/// checksum so a transcription error is caught on `decode` rather than
/// silently producing an unusable key.
pub fn encode_private_key_for_display(key: &RecoveryPrivateKey) -> Result<String> {
    let seed = key
        .mlkem
        .to_seed()
        .ok_or_else(|| Error::Kdf("recovery key has no seed representation".into()))?;

    let mut payload = Vec::with_capacity(X25519_LEN + MLKEM_SEED_LEN + 4);
    payload.extend_from_slice(key.x25519.as_bytes());
    payload.extend_from_slice(seed.as_ref());
    let checksum = Sha256::digest(&payload);
    payload.extend_from_slice(&checksum[..4]);

    Ok(STANDARD.encode(payload))
}

/// Decode a recovery private key previously produced by
/// `encode_private_key_for_display`.
pub fn decode_private_key_from_display(s: &str) -> Result<RecoveryPrivateKey> {
    let payload = STANDARD
        .decode(s.trim())
        .map_err(|_| Error::InvalidArgument("invalid recovery key encoding".into()))?;

    let expected_len = X25519_LEN + MLKEM_SEED_LEN + 4;
    if payload.len() != expected_len {
        return Err(Error::InvalidArgument(format!(
            "invalid recovery key length: {} (expected {expected_len})",
            payload.len()
        )));
    }

    let (body, checksum) = payload.split_at(X25519_LEN + MLKEM_SEED_LEN);
    let expected_checksum = Sha256::digest(body);
    if expected_checksum[..4] != *checksum {
        return Err(Error::InvalidArgument(
            "recovery key checksum mismatch — check for typos".into(),
        ));
    }

    let x25519_bytes: [u8; X25519_LEN] = body[..X25519_LEN].try_into().unwrap();
    let mlkem_seed = ml_kem::Seed::try_from(&body[X25519_LEN..])
        .map_err(|_| Error::InvalidArgument("invalid ML-KEM seed length".into()))?;

    Ok(RecoveryPrivateKey {
        x25519: X25519StaticSecret::from(x25519_bytes),
        mlkem: MlKemDecapsulationKey::from_seed(mlkem_seed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let (pubkey, privkey) = generate_recovery_keypair();
        let secret = [0x42u8; 32];
        let aad = b"test-aad";

        let blob = wrap_secret_for_recovery(&secret, &pubkey, aad).unwrap();
        let recovered = unwrap_secret_with_recovery(&blob, &privkey, aad).unwrap();

        assert_eq!(recovered, secret);
    }

    #[test]
    fn blob_bytes_roundtrip() {
        let (pubkey, _privkey) = generate_recovery_keypair();
        let secret = [0x11u8; 32];
        let blob = wrap_secret_for_recovery(&secret, &pubkey, b"aad").unwrap();

        let bytes = blob.to_bytes();
        assert_eq!(bytes.len(), RECOVERY_BLOB_LEN);
        let parsed = RecoveryWrappedBlob::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.ephemeral_x25519_public, blob.ephemeral_x25519_public);
        assert_eq!(parsed.mlkem_ciphertext, blob.mlkem_ciphertext);
        assert_eq!(parsed.aead_blob, blob.aead_blob);
    }

    #[test]
    fn wrong_recovery_key_fails() {
        let (pubkey, _) = generate_recovery_keypair();
        let (_, other_privkey) = generate_recovery_keypair();
        let secret = [0x22u8; 32];

        let blob = wrap_secret_for_recovery(&secret, &pubkey, b"aad").unwrap();
        assert!(unwrap_secret_with_recovery(&blob, &other_privkey, b"aad").is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let (pubkey, privkey) = generate_recovery_keypair();
        let secret = [0x33u8; 32];

        let blob = wrap_secret_for_recovery(&secret, &pubkey, b"correct-aad").unwrap();
        assert!(unwrap_secret_with_recovery(&blob, &privkey, b"wrong-aad").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (pubkey, privkey) = generate_recovery_keypair();
        let secret = [0x44u8; 32];

        let mut blob = wrap_secret_for_recovery(&secret, &pubkey, b"aad").unwrap();
        blob.aead_blob[aead::GCM_NONCE_LEN] ^= 0xFF;
        assert!(unwrap_secret_with_recovery(&blob, &privkey, b"aad").is_err());
    }

    #[test]
    fn tampered_mlkem_ciphertext_fails() {
        let (pubkey, privkey) = generate_recovery_keypair();
        let secret = [0x55u8; 32];

        let mut blob = wrap_secret_for_recovery(&secret, &pubkey, b"aad").unwrap();
        blob.mlkem_ciphertext[0] ^= 0xFF;
        assert!(unwrap_secret_with_recovery(&blob, &privkey, b"aad").is_err());
    }

    #[test]
    fn tampered_ephemeral_pubkey_fails() {
        let (pubkey, privkey) = generate_recovery_keypair();
        let secret = [0x66u8; 32];

        let mut blob = wrap_secret_for_recovery(&secret, &pubkey, b"aad").unwrap();
        blob.ephemeral_x25519_public[0] ^= 0xFF;
        assert!(unwrap_secret_with_recovery(&blob, &privkey, b"aad").is_err());
    }

    #[test]
    fn display_encode_decode_roundtrip() {
        let (pubkey, privkey) = generate_recovery_keypair();
        let secret = [0x77u8; 32];
        let aad = b"aad";

        let encoded = encode_private_key_for_display(&privkey).unwrap();
        let decoded = decode_private_key_from_display(&encoded).unwrap();

        let blob = wrap_secret_for_recovery(&secret, &pubkey, aad).unwrap();
        let recovered = unwrap_secret_with_recovery(&blob, &decoded, aad).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn display_decode_rejects_typo() {
        let (_pubkey, privkey) = generate_recovery_keypair();
        let mut encoded = encode_private_key_for_display(&privkey).unwrap();
        // Flip a character to simulate a transcription error.
        let mid = encoded.len() / 2;
        let flipped = if encoded.as_bytes()[mid] == b'A' {
            'B'
        } else {
            'A'
        };
        encoded.replace_range(mid..mid + 1, &flipped.to_string());

        assert!(decode_private_key_from_display(&encoded).is_err());
    }

    #[test]
    fn wrap_is_nondeterministic() {
        let (pubkey, _) = generate_recovery_keypair();
        let secret = [0x88u8; 32];

        let blob_a = wrap_secret_for_recovery(&secret, &pubkey, b"aad").unwrap();
        let blob_b = wrap_secret_for_recovery(&secret, &pubkey, b"aad").unwrap();

        assert_ne!(blob_a.to_bytes(), blob_b.to_bytes());
    }
}
