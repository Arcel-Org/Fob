use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Opaque wrapper for secret byte slices that zeroizes on drop and never
/// serializes its contents in a human-readable form.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SecretBytes(pub Vec<u8>);

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

/// Opaque wrapper for secret strings.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SecretString(pub String);

impl SecretString {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TotpAlgorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SshAlgorithm {
    #[default]
    Ed25519,
    Rsa,
    Ecdsa,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordEntry {
    pub id: Uuid,
    pub name: String,
    pub username: String,
    pub password: SecretString,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    pub created: u64,
    pub modified: u64,
}

impl PasswordEntry {
    pub fn new(
        name: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        let now = crate::vault::unix_now();
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            username: username.into(),
            password: SecretString::new(password),
            url: None,
            notes: None,
            created: now,
            modified: now,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpEntry {
    pub id: Uuid,
    pub issuer: String,
    pub account: String,
    pub secret: SecretBytes,
    pub algorithm: TotpAlgorithm,
    pub digits: u8,
    pub period: u32,
    pub created: u64,
}

impl TotpEntry {
    pub fn new(
        issuer: impl Into<String>,
        account: impl Into<String>,
        secret_bytes: Vec<u8>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            issuer: issuer.into(),
            account: account.into(),
            secret: SecretBytes(secret_bytes),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            created: crate::vault::unix_now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyEntry {
    pub id: Uuid,
    pub name: String,
    pub algorithm: SshAlgorithm,
    pub public_key: String,
    pub private_key: SecretString,
    pub fingerprint: String,
    pub created: u64,
}

impl SshKeyEntry {
    /// Import an existing SSH key pair. `public_key` must be a standard
    /// `ssh-ed25519 AAAA... comment`-style line — the algorithm and
    /// fingerprint are derived from it, not asserted by the caller.
    pub fn new(
        name: impl Into<String>,
        public_key: impl Into<String>,
        private_key: impl Into<String>,
    ) -> crate::error::Result<Self> {
        let public_key = public_key.into();
        let fingerprint = crate::sshkey::fingerprint(&public_key)?;
        let algorithm = crate::sshkey::algorithm(&public_key);
        Ok(Self {
            id: Uuid::new_v4(),
            name: name.into(),
            algorithm,
            public_key,
            private_key: SecretString::new(private_key),
            fingerprint,
            created: crate::vault::unix_now(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteEntry {
    pub id: Uuid,
    pub title: String,
    pub body: SecretString,
    pub created: u64,
    pub modified: u64,
}

impl NoteEntry {
    pub fn new(title: impl Into<String>, body: impl Into<String>) -> Self {
        let now = crate::vault::unix_now();
        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            body: SecretString::new(body),
            created: now,
            modified: now,
        }
    }
}

/// An encrypted file attachment stored inside a vault slot.
///
/// The raw bytes are base64-encoded in `data`. Like every other field this
/// lives inside the AES-256-GCM-encrypted slot, so at rest it is encrypted;
/// base64 (rather than a byte array) keeps the JSON payload the browser and
/// CLI share small and copy-paste safe. Vaults are fixed-size (16 MiB
/// default) so file storage is capped in the UI (see the browser's file
/// modal) and total capacity is bounded by the slot size.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub id: Uuid,
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub data: String, // base64
    pub created: u64,
}

impl FileEntry {
    pub fn new(
        name: impl Into<String>,
        mime: impl Into<String>,
        size: u64,
        data: impl Into<String>,
    ) -> Self {
        let now = crate::vault::unix_now();
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            mime: mime.into(),
            size,
            data: data.into(),
            created: now,
        }
    }
}

/// A payment card stored in the vault (number and CVV are secret).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardEntry {
    pub id: Uuid,
    pub name: String, // label, e.g. "Chase Sapphire"
    #[serde(default)]
    pub holder: String,
    pub number: SecretString,
    #[serde(default)]
    pub exp_month: String,
    #[serde(default)]
    pub exp_year: String,
    pub cvv: SecretString,
    pub created: u64,
    pub modified: u64,
}

impl CardEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        holder: impl Into<String>,
        number: impl Into<String>,
        exp_month: impl Into<String>,
        exp_year: impl Into<String>,
        cvv: impl Into<String>,
    ) -> Self {
        let now = crate::vault::unix_now();
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            holder: holder.into(),
            number: SecretString::new(number),
            exp_month: exp_month.into(),
            exp_year: exp_year.into(),
            cvv: SecretString::new(cvv),
            created: now,
            modified: now,
        }
    }
}

/// A per-account set of recovery / backup codes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCodeEntry {
    pub id: Uuid,
    pub title: String,
    #[serde(default)]
    pub codes: Vec<SecretString>,
    pub created: u64,
}

impl RecoveryCodeEntry {
    pub fn new(title: impl Into<String>, codes: Vec<String>) -> Self {
        let now = crate::vault::unix_now();
        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            codes: codes.into_iter().map(SecretString::new).collect(),
            created: now,
        }
    }
}
