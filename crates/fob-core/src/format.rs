/// On-disk vault file format constants and header layout.
///
/// The vault file is a fixed-size blob split into `NUM_SLOTS` equal-size
/// cells. Each cell is either:
/// - Populated: AES-256-GCM(nonce || len_u64_le || JSON blob || random_padding || tag)
/// - Unpopulated: random bytes
///
/// Layout (v4):
/// ```text
/// Offset  Length  Field
/// ------  ------  -----
/// 0       4       magic "FOB2"
/// 4       4       format_version — u32 LE
/// 8       4       kdf_time_cost — u32 LE (PBKDF2 iterations, or Argon2id time_cost)
/// 12      32      salt — KDF salt, shared across all slot derivations
/// 44      1       kdf_algorithm — u8 (0 = PBKDF2-HMAC-SHA256, 1 = Argon2id)
/// 45      4       argon2_memory_kib — u32 LE (meaningful iff kdf_algorithm == 1)
/// 49      4       argon2_parallelism — u32 LE (meaningful iff kdf_algorithm == 1)
/// 53      1       recovery_enabled — u8 (0/1)
/// 54      46      reserved — zeroed
/// 100     ...     Encrypted slot region
/// ```
///
/// v3 vaults (format_version == 3) remain permanently readable: their header
/// ends at the salt (byte 44 onward was always zeroed), and are parsed with
/// `kdf_algorithm` implicitly `Pbkdf2Sha256` and `recovery_enabled` implicitly
/// `false`. New vaults are always written as v4.
///
/// The header intentionally carries a magic + version + KDF params in the
/// clear (unlike a random-looking blob) so both the CLI and the
/// zero-dependency browser vault can parse it without guessing. The vault's
/// deniability guarantees (decoy/duress) protect *which passphrase unlocks
/// which content*, not whether the file is a Fob vault at all — the
/// filename `vault.fob` already reveals that.
///
/// Each slot cell carries its own fresh, randomly-generated AES-GCM nonce as
/// the first 12 bytes of the cell (see `aead::encrypt`/`decrypt`), generated
/// anew on every write. Format v2 stored one nonce per slot *in the header*,
/// reused unchanged across every subsequent save of that slot for the
/// vault's entire lifetime — an unconditional AES-GCM nonce reuse, which
/// breaks confidentiality (XORing two on-disk snapshots of the same slot
/// leaks the plaintext XOR) and, via the GCM "forbidden attack", lets an
/// attacker holding two same-key/nonce ciphertexts forge undetectable
/// replacement content. v3 fixes this structurally: nonces never repeat
/// because they're never reused, and the header holds no nonce at all.
///
/// When `recovery_enabled`, slot index `RECOVERY_SLOT_INDEX` (the 4th cell,
/// otherwise unused/random) carries a hybrid X25519+ML-KEM-1024-wrapped copy
/// of the master secret instead of random filler — see `crate::recovery`.
///
/// Cell size = (FILE_SIZE - HEADER_SIZE) / NUM_SLOTS
use crate::error::Error;

pub const MAGIC: &[u8; 4] = b"FOB2";
pub const MAGIC_OFFSET: usize = 0;
pub const MAGIC_LEN: usize = 4;

pub const HEADER_VERSION_OFFSET: usize = 4;
pub const HEADER_VERSION_LEN: usize = 4;

pub const HEADER_ITERATIONS_OFFSET: usize = 8;
pub const HEADER_ITERATIONS_LEN: usize = 4;

pub const HEADER_SALT_OFFSET: usize = 12;
pub const HEADER_SALT_LEN: usize = 32;

pub const HEADER_KDF_ALGO_OFFSET: usize = 44;
pub const HEADER_KDF_ALGO_LEN: usize = 1;

pub const HEADER_ARGON2_MEMORY_OFFSET: usize = 45;
pub const HEADER_ARGON2_MEMORY_LEN: usize = 4;

pub const HEADER_ARGON2_PARALLELISM_OFFSET: usize = 49;
pub const HEADER_ARGON2_PARALLELISM_LEN: usize = 4;

pub const HEADER_RECOVERY_OFFSET: usize = 53;
pub const HEADER_RECOVERY_LEN: usize = 1;

pub const NUM_SLOTS: usize = 4;

/// Index of the slot cell repurposed for recovery-key wrapped data when
/// `recovery_enabled`. This slot is never tried during passphrase unlock
/// (see `vault::unlock_vault_inner`) — it's only read by `vault::recover_vault`.
pub const RECOVERY_SLOT_INDEX: usize = 3;

pub const HEADER_RESERVED_OFFSET: usize = 54;
pub const HEADER_RESERVED_LEN: usize = 46;

pub const HEADER_SIZE: usize = 100;

/// Default vault file size: 16 MiB.
pub const DEFAULT_VAULT_SIZE: usize = 16 * 1024 * 1024;

/// Maximum supported vault file size: 1 GiB.
pub const MAX_VAULT_SIZE: usize = 1024 * 1024 * 1024;

/// Minimum vault file size — enough header + a floor per-slot cell size
/// (64 bytes) for all `NUM_SLOTS` slots. Below this, a cell wouldn't even
/// have room for the nonce + length-prefix + GCM tag, so the file can't be
/// a genuine Fob vault. Enforced both when creating a fresh vault
/// (`VaultFile::create_fresh`) and when parsing an existing one
/// (`VaultFile::from_bytes`) — the latter is the one that reads untrusted
/// bytes off a USB drive, where a truncated/corrupted file would otherwise
/// parse "successfully" into a file with degenerate (even zero-byte) slot
/// cells, later surfacing only as an opaque "wrong passphrase or corrupted
/// data" on every unlock attempt instead of a clear diagnostic here.
pub const MIN_VAULT_SIZE: usize = HEADER_SIZE + NUM_SLOTS * 64;

/// Oldest format version still readable.
pub const MIN_SUPPORTED_FORMAT_VERSION: u32 = 3;

/// Current format version — written by every new/upgraded vault.
///
/// Bumped 3 -> 4 to add Argon2id as an available KDF (alongside permanently
/// supported PBKDF2, for v3 vaults and the WebCrypto browser vault, which
/// has no native Argon2id primitive) and an optional post-quantum recovery
/// path (`recovery_enabled`, see `crate::recovery`). v3 vaults are not
/// migrated automatically; they remain fully readable and writable via the
/// PBKDF2 path forever.
///
/// Bumped 2 -> 3 to fix a critical AES-GCM nonce-reuse vulnerability: v2
/// stored a fixed nonce per slot in the header, reused for every save. v3
/// stores a fresh random nonce inline in each cell on every write instead.
/// v2 vaults are rejected outright (see `VaultHeader::parse`) rather than
/// silently misread, since the on-disk cell layout is incompatible.
pub const FORMAT_VERSION: u32 = 4;

/// Default PBKDF2-HMAC-SHA256 iteration count (v3 vaults, and the browser
/// vault, which has no native Argon2id primitive).
pub const DEFAULT_KDF_ITERATIONS: u32 = 310_000;

/// Highest PBKDF2 iteration count accepted from an on-disk header.
///
/// `kdf_time_cost` lives in the cleartext, unauthenticated part of the
/// header — it's read and used before any slot's AEAD tag is checked, so a
/// corrupted or maliciously-modified vault file could otherwise force an
/// arbitrarily expensive PBKDF2 pass (e.g. `u32::MAX`, ~4.29 billion
/// iterations) on every unlock attempt before authentication ever runs, a
/// denial-of-service reachable without knowing any passphrase. This cap is
/// deliberately generous (normal use is ~310k) but still bounded.
pub const MAX_KDF_ITERATIONS: u32 = 10_000_000;

/// Default Argon2id parameters (v4 vaults) — RFC 9106 "second recommended"
/// profile, appropriate for a single-user desktop/CLI unlock rather than a
/// multi-tenant server: ~64 MiB memory, 3 passes, 4 lanes.
pub const DEFAULT_ARGON2_MEMORY_KIB: u32 = 65_536;
pub const DEFAULT_ARGON2_TIME_COST: u32 = 3;
pub const DEFAULT_ARGON2_PARALLELISM: u32 = 4;

/// Bounds on attacker-controlled Argon2id header fields, enforced in
/// `VaultHeader::parse` before any KDF work runs — the same DoS-prevention
/// role as `MAX_KDF_ITERATIONS`, but covering memory and lane count too:
/// an oversized `argon2_memory_kib` could exhaust RAM, and an oversized
/// `argon2_parallelism` could over-spawn threads, both before the AEAD tag
/// is ever checked.
pub const MAX_ARGON2_TIME_COST: u32 = 64;
pub const MAX_ARGON2_MEMORY_KIB: u32 = 262_144;
pub const MAX_ARGON2_PARALLELISM: u32 = 8;

/// Which KDF a vault's `kdf_time_cost` (and, for Argon2id, the accompanying
/// memory/parallelism fields) should be interpreted under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfAlgorithm {
    Pbkdf2Sha256 = 0,
    Argon2id = 1,
}

impl KdfAlgorithm {
    fn from_u8(v: u8) -> Result<Self, Error> {
        match v {
            0 => Ok(Self::Pbkdf2Sha256),
            1 => Ok(Self::Argon2id),
            other => Err(Error::Format(format!("unknown kdf_algorithm byte {other}"))),
        }
    }

    fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Parsed vault file header.
#[derive(Debug, Clone)]
pub struct VaultHeader {
    pub format_version: u32,
    pub kdf_algorithm: KdfAlgorithm,
    /// PBKDF2 iteration count, or Argon2id time_cost — interpretation
    /// depends on `kdf_algorithm`.
    pub kdf_time_cost: u32,
    /// Meaningful only when `kdf_algorithm == Argon2id`.
    pub argon2_memory_kib: u32,
    /// Meaningful only when `kdf_algorithm == Argon2id`.
    pub argon2_parallelism: u32,
    pub salt: [u8; HEADER_SALT_LEN],
    pub recovery_enabled: bool,
}

impl VaultHeader {
    /// Parse a header from the first `HEADER_SIZE` bytes of the vault file.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() < HEADER_SIZE {
            return Err(Error::Format(format!(
                "vault too small: {} < {}",
                data.len(),
                HEADER_SIZE
            )));
        }

        if &data[MAGIC_OFFSET..MAGIC_OFFSET + MAGIC_LEN] != MAGIC {
            return Err(Error::Format("not a Fob vault".into()));
        }

        let format_version = u32::from_le_bytes(
            data[HEADER_VERSION_OFFSET..HEADER_VERSION_OFFSET + HEADER_VERSION_LEN]
                .try_into()
                .unwrap(),
        );
        if !(MIN_SUPPORTED_FORMAT_VERSION..=FORMAT_VERSION).contains(&format_version) {
            return Err(Error::Format(format!(
                "unsupported vault format version {format_version} (supported: {MIN_SUPPORTED_FORMAT_VERSION}..={FORMAT_VERSION})"
            )));
        }

        let kdf_time_cost = u32::from_le_bytes(
            data[HEADER_ITERATIONS_OFFSET..HEADER_ITERATIONS_OFFSET + HEADER_ITERATIONS_LEN]
                .try_into()
                .unwrap(),
        );

        let salt: [u8; HEADER_SALT_LEN] = data
            [HEADER_SALT_OFFSET..HEADER_SALT_OFFSET + HEADER_SALT_LEN]
            .try_into()
            .unwrap();

        if format_version == 3 {
            if kdf_time_cost > MAX_KDF_ITERATIONS {
                return Err(Error::Format(format!(
                    "kdf_time_cost {kdf_time_cost} exceeds maximum of {MAX_KDF_ITERATIONS}"
                )));
            }
            return Ok(Self {
                format_version,
                kdf_algorithm: KdfAlgorithm::Pbkdf2Sha256,
                kdf_time_cost,
                argon2_memory_kib: 0,
                argon2_parallelism: 0,
                salt,
                recovery_enabled: false,
            });
        }

        // format_version == 4
        let kdf_algorithm = KdfAlgorithm::from_u8(data[HEADER_KDF_ALGO_OFFSET])?;
        match kdf_algorithm {
            KdfAlgorithm::Pbkdf2Sha256 => {
                if kdf_time_cost > MAX_KDF_ITERATIONS {
                    return Err(Error::Format(format!(
                        "kdf_time_cost {kdf_time_cost} exceeds maximum of {MAX_KDF_ITERATIONS}"
                    )));
                }
            }
            KdfAlgorithm::Argon2id => {
                if kdf_time_cost > MAX_ARGON2_TIME_COST {
                    return Err(Error::Format(format!(
                        "argon2 time_cost {kdf_time_cost} exceeds maximum of {MAX_ARGON2_TIME_COST}"
                    )));
                }
            }
        }

        let argon2_memory_kib = u32::from_le_bytes(
            data[HEADER_ARGON2_MEMORY_OFFSET
                ..HEADER_ARGON2_MEMORY_OFFSET + HEADER_ARGON2_MEMORY_LEN]
                .try_into()
                .unwrap(),
        );
        if argon2_memory_kib > MAX_ARGON2_MEMORY_KIB {
            return Err(Error::Format(format!(
                "argon2_memory_kib {argon2_memory_kib} exceeds maximum of {MAX_ARGON2_MEMORY_KIB}"
            )));
        }

        let argon2_parallelism = u32::from_le_bytes(
            data[HEADER_ARGON2_PARALLELISM_OFFSET
                ..HEADER_ARGON2_PARALLELISM_OFFSET + HEADER_ARGON2_PARALLELISM_LEN]
                .try_into()
                .unwrap(),
        );
        if argon2_parallelism > MAX_ARGON2_PARALLELISM {
            return Err(Error::Format(format!(
                "argon2_parallelism {argon2_parallelism} exceeds maximum of {MAX_ARGON2_PARALLELISM}"
            )));
        }

        let recovery_enabled = match data[HEADER_RECOVERY_OFFSET] {
            0 => false,
            1 => true,
            other => {
                return Err(Error::Format(format!(
                    "invalid recovery_enabled byte {other}"
                )))
            }
        };

        Ok(Self {
            format_version,
            kdf_algorithm,
            kdf_time_cost,
            argon2_memory_kib,
            argon2_parallelism,
            salt,
            recovery_enabled,
        })
    }

    /// Serialize the header to `HEADER_SIZE` bytes.
    ///
    /// Written per the header's own `format_version`, not always the latest
    /// `FORMAT_VERSION`: a header parsed from an existing v3 vault must
    /// re-serialize to byte-identical v3 bytes, since the header is used
    /// verbatim as AEAD associated data on every slot (see `vault.rs`) — the
    /// v3 shape (bytes 44..100 always zero) is exactly what those slots were
    /// originally encrypted against.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[MAGIC_OFFSET..MAGIC_OFFSET + MAGIC_LEN].copy_from_slice(MAGIC);
        out[HEADER_VERSION_OFFSET..HEADER_VERSION_OFFSET + HEADER_VERSION_LEN]
            .copy_from_slice(&self.format_version.to_le_bytes());
        out[HEADER_ITERATIONS_OFFSET..HEADER_ITERATIONS_OFFSET + HEADER_ITERATIONS_LEN]
            .copy_from_slice(&self.kdf_time_cost.to_le_bytes());
        out[HEADER_SALT_OFFSET..HEADER_SALT_OFFSET + HEADER_SALT_LEN].copy_from_slice(&self.salt);

        if self.format_version >= 4 {
            out[HEADER_KDF_ALGO_OFFSET] = self.kdf_algorithm.to_u8();
            out[HEADER_ARGON2_MEMORY_OFFSET
                ..HEADER_ARGON2_MEMORY_OFFSET + HEADER_ARGON2_MEMORY_LEN]
                .copy_from_slice(&self.argon2_memory_kib.to_le_bytes());
            out[HEADER_ARGON2_PARALLELISM_OFFSET
                ..HEADER_ARGON2_PARALLELISM_OFFSET + HEADER_ARGON2_PARALLELISM_LEN]
                .copy_from_slice(&self.argon2_parallelism.to_le_bytes());
            out[HEADER_RECOVERY_OFFSET] = self.recovery_enabled as u8;
        }
        // bytes 44..100 stay zero for format_version == 3, matching every
        // v3 header ever written.

        out
    }
}

/// Size of each slot cell given a vault file size.
pub fn cell_size(vault_size: usize) -> usize {
    (vault_size - HEADER_SIZE) / NUM_SLOTS
}

/// Byte offset of cell `i` within the vault file.
pub fn cell_offset(vault_size: usize, slot: usize) -> usize {
    HEADER_SIZE + slot * cell_size(vault_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_header() -> VaultHeader {
        VaultHeader {
            format_version: FORMAT_VERSION,
            kdf_algorithm: KdfAlgorithm::Argon2id,
            kdf_time_cost: DEFAULT_ARGON2_TIME_COST,
            argon2_memory_kib: DEFAULT_ARGON2_MEMORY_KIB,
            argon2_parallelism: DEFAULT_ARGON2_PARALLELISM,
            salt: [0x11u8; 32],
            recovery_enabled: false,
        }
    }

    fn test_header_v3() -> VaultHeader {
        VaultHeader {
            format_version: 3,
            kdf_algorithm: KdfAlgorithm::Pbkdf2Sha256,
            kdf_time_cost: DEFAULT_KDF_ITERATIONS,
            argon2_memory_kib: 0,
            argon2_parallelism: 0,
            salt: [0x22u8; 32],
            recovery_enabled: false,
        }
    }

    #[test]
    fn header_roundtrip_v4_argon2id() {
        let header = test_header();
        let bytes = header.to_bytes();
        let parsed = VaultHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.salt, header.salt);
        assert_eq!(parsed.format_version, FORMAT_VERSION);
        assert_eq!(parsed.kdf_algorithm, KdfAlgorithm::Argon2id);
        assert_eq!(parsed.kdf_time_cost, DEFAULT_ARGON2_TIME_COST);
        assert_eq!(parsed.argon2_memory_kib, DEFAULT_ARGON2_MEMORY_KIB);
        assert_eq!(parsed.argon2_parallelism, DEFAULT_ARGON2_PARALLELISM);
        assert!(!parsed.recovery_enabled);
    }

    #[test]
    fn header_roundtrip_v4_recovery_enabled() {
        let mut header = test_header();
        header.recovery_enabled = true;
        let bytes = header.to_bytes();
        let parsed = VaultHeader::parse(&bytes).unwrap();
        assert!(parsed.recovery_enabled);
    }

    #[test]
    fn header_v3_still_parses() {
        let header = test_header_v3();
        let bytes = header.to_bytes();
        // v3 headers never wrote anything past the salt.
        assert!(bytes[HEADER_KDF_ALGO_OFFSET..HEADER_SIZE]
            .iter()
            .all(|&b| b == 0));
        let parsed = VaultHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.format_version, 3);
        assert_eq!(parsed.kdf_algorithm, KdfAlgorithm::Pbkdf2Sha256);
        assert_eq!(parsed.kdf_time_cost, DEFAULT_KDF_ITERATIONS);
        assert!(!parsed.recovery_enabled);
    }

    #[test]
    fn header_v3_roundtrip_is_byte_identical() {
        let header = test_header_v3();
        let bytes = header.to_bytes();
        let parsed = VaultHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn header_too_small_fails() {
        let tiny = vec![0u8; 10];
        assert!(VaultHeader::parse(&tiny).is_err());
    }

    #[test]
    fn header_wrong_magic_fails() {
        let mut bytes = test_header().to_bytes();
        bytes[0] = b'X';
        assert!(VaultHeader::parse(&bytes).is_err());
    }

    #[test]
    fn header_wrong_version_rejected() {
        let mut bytes = test_header().to_bytes();
        bytes[HEADER_VERSION_OFFSET..HEADER_VERSION_OFFSET + HEADER_VERSION_LEN]
            .copy_from_slice(&2u32.to_le_bytes());
        let err = VaultHeader::parse(&bytes).unwrap_err();
        assert!(format!("{err}").contains("unsupported vault format version"));
    }

    #[test]
    fn header_future_version_rejected() {
        let mut bytes = test_header().to_bytes();
        bytes[HEADER_VERSION_OFFSET..HEADER_VERSION_OFFSET + HEADER_VERSION_LEN]
            .copy_from_slice(&5u32.to_le_bytes());
        let err = VaultHeader::parse(&bytes).unwrap_err();
        assert!(format!("{err}").contains("unsupported vault format version"));
    }

    #[test]
    fn header_excessive_kdf_iterations_rejected() {
        let mut bytes = test_header_v3().to_bytes();
        bytes[HEADER_ITERATIONS_OFFSET..HEADER_ITERATIONS_OFFSET + HEADER_ITERATIONS_LEN]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        let err = VaultHeader::parse(&bytes).unwrap_err();
        assert!(format!("{err}").contains("exceeds maximum"));
    }

    #[test]
    fn header_excessive_argon2_time_cost_rejected() {
        let mut bytes = test_header().to_bytes();
        bytes[HEADER_ITERATIONS_OFFSET..HEADER_ITERATIONS_OFFSET + HEADER_ITERATIONS_LEN]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        let err = VaultHeader::parse(&bytes).unwrap_err();
        assert!(format!("{err}").contains("exceeds maximum"));
    }

    #[test]
    fn header_excessive_argon2_memory_rejected() {
        let mut bytes = test_header().to_bytes();
        bytes[HEADER_ARGON2_MEMORY_OFFSET..HEADER_ARGON2_MEMORY_OFFSET + HEADER_ARGON2_MEMORY_LEN]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        let err = VaultHeader::parse(&bytes).unwrap_err();
        assert!(format!("{err}").contains("exceeds maximum"));
    }

    #[test]
    fn header_excessive_argon2_parallelism_rejected() {
        let mut bytes = test_header().to_bytes();
        bytes[HEADER_ARGON2_PARALLELISM_OFFSET
            ..HEADER_ARGON2_PARALLELISM_OFFSET + HEADER_ARGON2_PARALLELISM_LEN]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        let err = VaultHeader::parse(&bytes).unwrap_err();
        assert!(format!("{err}").contains("exceeds maximum"));
    }

    #[test]
    fn header_unknown_kdf_algorithm_rejected() {
        let mut bytes = test_header().to_bytes();
        bytes[HEADER_KDF_ALGO_OFFSET] = 7;
        let err = VaultHeader::parse(&bytes).unwrap_err();
        assert!(format!("{err}").contains("unknown kdf_algorithm"));
    }

    #[test]
    fn header_invalid_recovery_byte_rejected() {
        let mut bytes = test_header().to_bytes();
        bytes[HEADER_RECOVERY_OFFSET] = 42;
        let err = VaultHeader::parse(&bytes).unwrap_err();
        assert!(format!("{err}").contains("invalid recovery_enabled"));
    }

    #[test]
    fn cell_sizes_are_equal() {
        let vault_size = DEFAULT_VAULT_SIZE;
        let c0 = cell_size(vault_size);
        for i in 0..NUM_SLOTS {
            assert_eq!(
                cell_offset(vault_size, i + 1) - cell_offset(vault_size, i),
                c0
            );
        }
    }

    #[test]
    fn cell_offset_does_not_exceed_file() {
        let vault_size = DEFAULT_VAULT_SIZE;
        let last_cell_end = cell_offset(vault_size, NUM_SLOTS - 1) + cell_size(vault_size);
        assert_eq!(last_cell_end, vault_size);
    }
}
