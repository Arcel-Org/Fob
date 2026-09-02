use std::path::PathBuf;

mod linux;
mod macos;

#[derive(Debug, Clone)]
pub struct UsbDevice {
    pub name: String,
    pub size_bytes: u64,
    pub path: PathBuf,     // mount point, e.g. /Volumes/MyDrive
    pub disk_node: String, // e.g. "disk4" — used for formatting
    #[allow(dead_code)]
    pub serial: Option<String>,
    pub has_fob_vault: bool,
}

impl UsbDevice {
    pub fn size_display(&self) -> String {
        let gb = self.size_bytes as f64 / 1_073_741_824.0;
        if gb >= 1.0 {
            format!("{:.1} GB", gb)
        } else {
            format!("{:.1} MB", self.size_bytes as f64 / 1_048_576.0)
        }
    }

    pub fn is_system_drive(&self) -> bool {
        let p = self.path.to_string_lossy();
        // Never allow the primary boot volume.
        p == "/Volumes/Macintosh HD" || p == "/" || p == "/Volumes/Macintosh HD - Data"
    }
}

/// Enumerate only removable, external USB drives visible to the OS.
///
/// On macOS this uses `diskutil info -all` to get authoritative removability data.
/// System drives are always excluded.
pub fn enumerate_usb_devices() -> Vec<UsbDevice> {
    #[cfg(target_os = "macos")]
    return macos::enumerate();

    #[cfg(target_os = "linux")]
    return linux::enumerate();

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    return Vec::new();
}

/// Format the given USB device as ExFAT with the label "FOB".
/// This is destructive — all data is erased.
///
/// On macOS uses `diskutil eraseDisk`.
/// On Linux uses `mkfs.exfat`.
pub fn format_device(dev: &UsbDevice) -> anyhow::Result<()> {
    if dev.is_system_drive() {
        anyhow::bail!("Refusing to format system drive.");
    }

    #[cfg(target_os = "macos")]
    return macos::erase(dev);

    #[cfg(target_os = "linux")]
    return linux::erase(dev);

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    anyhow::bail!("Formatting a USB device is not supported on this platform.")
}

/// Find the new mount point after formatting (diskutil remounts automatically).
#[allow(dead_code)]
pub fn find_mount_after_format(_old_disk_node: &str) -> Option<PathBuf> {
    // Give the OS a moment to remount.
    std::thread::sleep(std::time::Duration::from_secs(2));
    let mount = PathBuf::from("/Volumes/FOB");
    if mount.exists() {
        return Some(mount);
    }
    // Fallback: try probing
    #[cfg(target_os = "macos")]
    if let Some(dev) = macos::probe_disk(_old_disk_node) {
        return Some(dev.path);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_display_formats_gb_and_mb() {
        let gb_dev = UsbDevice {
            name: "x".into(),
            size_bytes: 16 * 1_073_741_824,
            path: PathBuf::new(),
            disk_node: "disk4".into(),
            serial: None,
            has_fob_vault: false,
        };
        assert_eq!(gb_dev.size_display(), "16.0 GB");

        let mb_dev = UsbDevice {
            size_bytes: 512 * 1_048_576,
            ..gb_dev
        };
        assert_eq!(mb_dev.size_display(), "512.0 MB");
    }

    #[test]
    fn is_system_drive_matches_known_boot_volumes() {
        let make = |path: &str| UsbDevice {
            name: "x".into(),
            size_bytes: 0,
            path: PathBuf::from(path),
            disk_node: "disk1".into(),
            serial: None,
            has_fob_vault: false,
        };
        assert!(make("/").is_system_drive());
        assert!(make("/Volumes/Macintosh HD").is_system_drive());
        assert!(make("/Volumes/Macintosh HD - Data").is_system_drive());
        assert!(!make("/Volumes/FOB").is_system_drive());
    }
}
