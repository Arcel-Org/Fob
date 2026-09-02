//! Serializable view types sent to the frontend over Tauri's IPC bridge.
//! Kept separate from `fob-core`'s own types so the wire format can evolve
//! independently of the on-disk/crypto types.

use serde::Serialize;

#[derive(Serialize)]
pub struct UsbDeviceDto {
    pub name: String,
    pub size_display: String,
    pub path: String,
    pub has_fob_vault: bool,
}

impl From<&fob_host::device::UsbDevice> for UsbDeviceDto {
    fn from(d: &fob_host::device::UsbDevice) -> Self {
        Self {
            name: d.name.clone(),
            size_display: d.size_display(),
            path: d.path.display().to_string(),
            has_fob_vault: d.has_fob_vault,
        }
    }
}

#[derive(Serialize)]
pub struct VaultHeaderDto {
    pub format_version: u32,
    pub kdf_algorithm: String,
    pub kdf_time_cost: u32,
    pub argon2_memory_kib: u32,
    pub argon2_parallelism: u32,
    pub recovery_enabled: bool,
}

impl From<&fob_core::format::VaultHeader> for VaultHeaderDto {
    fn from(h: &fob_core::format::VaultHeader) -> Self {
        Self {
            format_version: h.format_version,
            kdf_algorithm: match h.kdf_algorithm {
                fob_core::format::KdfAlgorithm::Pbkdf2Sha256 => "PBKDF2-HMAC-SHA256".to_string(),
                fob_core::format::KdfAlgorithm::Argon2id => "Argon2id".to_string(),
            },
            kdf_time_cost: h.kdf_time_cost,
            argon2_memory_kib: h.argon2_memory_kib,
            argon2_parallelism: h.argon2_parallelism,
            recovery_enabled: h.recovery_enabled,
        }
    }
}

#[derive(Serialize)]
pub struct CreateVaultResult {
    pub recovery_key_display: Option<String>,
    pub blob: fob_core::vault::VaultBlob,
}

#[derive(Serialize)]
pub struct TotpCodeDto {
    pub code: String,
    pub seconds_remaining: u32,
}
