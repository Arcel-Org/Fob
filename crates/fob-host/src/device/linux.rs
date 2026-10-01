use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
use super::UsbDevice;

/// Is this `/sys/block` entry name likely the system's primary disk? Purely
/// a heuristic (`sda` with no partition suffix) — real safety comes from
/// `UsbDevice::is_system_drive`'s mount-point check.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn is_likely_system_disk(name: &str) -> bool {
    name.starts_with("sda") && name.len() == 3
}

/// Decode the octal escapes (`\040` space, `\011` tab, `\012` newline,
/// `\134` backslash) the kernel uses for special characters in
/// `/proc/mounts` fields. Without this, any USB drive whose volume label
/// contains a space — extremely common (Windows-default names, "FOB
/// BACKUP", "My Passport") — resolves to a mount path containing a literal
/// `\040` instead of a space, which doesn't exist on disk, so `vault.fob`
/// detection and every subsequent file operation silently fail.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn decode_mounts_escapes(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..i + 4].iter().all(u8::is_ascii_digit)
        {
            let octal = std::str::from_utf8(&bytes[i + 1..i + 4]).unwrap();
            if let Ok(byte) = u8::from_str_radix(octal, 8) {
                out.push(byte);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Find the mount point for a block device named `device_name` (a whole
/// disk like `sdb`, or a specific partition like `sdb1`) by scanning
/// `/proc/mounts`-formatted content.
///
/// Matches the device itself or any of its partitions (`sdb` matches
/// `/dev/sdb1`, `/dev/sdb2`, ...) via a boundary-anchored prefix check, not
/// a bare substring — a raw `.contains()` could also match an unrelated
/// device whose name happens to contain the same characters. If a disk has
/// multiple mounted partitions, prefers whichever one already has a
/// `vault.fob` (there's no other principled way to pick among them), else
/// falls back to the first one found.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn find_mount_point(mounts_content: &str, device_name: &str) -> Option<PathBuf> {
    let candidates: Vec<PathBuf> = mounts_content
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                return None;
            }
            let dev = parts[0].strip_prefix("/dev/").unwrap_or(parts[0]);
            let is_this_disk = dev == device_name
                || (dev.len() > device_name.len()
                    && dev.starts_with(device_name)
                    && dev[device_name.len()..].bytes().all(|b| b.is_ascii_digit()));
            is_this_disk.then(|| PathBuf::from(decode_mounts_escapes(parts[1])))
        })
        .collect();

    candidates
        .iter()
        .find(|p| p.join("vault.fob").exists())
        .cloned()
        .or_else(|| candidates.into_iter().next())
}

/// Does this resolved/symlink-target `/sys/block/<name>` device path
/// indicate the device is attached via USB (a path component that's
/// exactly `usb` followed by a bus number, e.g. `.../usb1/1-1/...`),
/// regardless of what the device's own `removable` sysfs flag says?
///
/// Many USB-to-SATA and USB-to-NVMe bridge chips report `removable=0`
/// (reflecting the bridge's own SCSI RMB bit, not whether the whole
/// enclosure is actually hot-pluggable) — relying on `removable` alone
/// silently hides external SSDs/NVMe enclosures from `fob devices` while
/// plain flash drives (which do report `removable=1`) work fine.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn resolved_path_indicates_usb(resolved_path: &str) -> bool {
    resolved_path.split('/').any(|component| {
        component
            .strip_prefix("usb")
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
    })
}

#[cfg(target_os = "linux")]
pub(super) fn enumerate() -> Vec<UsbDevice> {
    let mut devices = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/block") else {
        return devices;
    };

    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return devices;
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let removable = std::fs::read_to_string(entry.path().join("removable"))
            .map(|s| s.trim() == "1")
            .unwrap_or(false);
        // `removable` alone misses USB-SATA/USB-NVMe bridges that report
        // removable=0 — also accept devices whose sysfs symlink resolves
        // through a USB bus, so those enclosures aren't silently invisible.
        let is_usb = std::fs::read_link(entry.path())
            .map(|p| resolved_path_indicates_usb(&p.to_string_lossy()))
            .unwrap_or(false);
        if (!removable && !is_usb) || is_likely_system_disk(&name) {
            continue;
        }

        let size_bytes = std::fs::read_to_string(entry.path().join("size"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|s| s * 512)
            .unwrap_or(0);

        let Some(mount) = find_mount_point(&mounts, &name) else {
            continue;
        };
        let has_fob_vault = mount.join("vault.fob").exists();
        devices.push(UsbDevice {
            name: name.clone(),
            size_bytes,
            path: mount,
            disk_node: name,
            serial: None,
            has_fob_vault,
        });
    }

    devices.sort_by(|a, b| a.name.cmp(&b.name));
    devices
}

/// Format the given USB device as ExFAT with the label "FOB" via
/// `mkfs.exfat`, after unmounting it. This is destructive — all data is
/// erased. Caller (`format_device`) already checked `!dev.is_system_drive()`.
#[cfg(target_os = "linux")]
pub(super) fn erase(dev: &UsbDevice) -> anyhow::Result<()> {
    // Unmount first
    let _ = Command::new("umount").arg(&dev.disk_node).status();
    let status = Command::new("mkfs.exfat")
        .args(["-n", "FOB", &format!("/dev/{}", dev.disk_node)])
        .status()?;
    if !status.success() {
        anyhow::bail!("mkfs.exfat failed. Install exfat-utils.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC_MOUNTS_SAMPLE: &str = "\
/dev/sda1 / ext4 rw,relatime 0 0
/dev/sdb1 /media/user/FOB exfat rw,nosuid,nodev,relatime 0 0
tmpfs /tmp tmpfs rw 0 0
";

    #[test]
    fn finds_mount_point_for_matching_device() {
        assert_eq!(
            find_mount_point(PROC_MOUNTS_SAMPLE, "sdb1"),
            Some(PathBuf::from("/media/user/FOB"))
        );
    }

    #[test]
    fn finds_no_mount_point_for_unknown_device() {
        assert_eq!(find_mount_point(PROC_MOUNTS_SAMPLE, "sdz1"), None);
    }

    #[test]
    fn ignores_malformed_mounts_lines() {
        assert_eq!(find_mount_point("garbage-line-no-spaces", "sdb1"), None);
    }

    #[test]
    fn finds_mount_point_via_whole_disk_name_matching_a_partition() {
        // enumerate() passes the whole-disk /sys/block name ("sdb"), not a
        // specific partition — must match /dev/sdb1 via that name.
        assert_eq!(
            find_mount_point(PROC_MOUNTS_SAMPLE, "sdb"),
            Some(PathBuf::from("/media/user/FOB"))
        );
    }

    #[test]
    fn whole_disk_name_does_not_substring_match_an_unrelated_device() {
        // "sdb" must not match "/dev/sdbx1" (a different, unrelated device
        // that merely starts with the same characters) via a bare
        // substring/prefix check with no boundary.
        let mounts = "/dev/sdbx1 /mnt/other ext4 rw 0 0\n";
        assert_eq!(find_mount_point(mounts, "sdb"), None);
    }

    #[test]
    fn decodes_octal_escaped_spaces_in_mount_path() {
        // Real /proc/mounts octal-escapes spaces in the mount path as
        // \040 — a volume literally named "FOB BACKUP" (or any
        // Windows-default label with a space) must still resolve to a
        // real, existing-on-disk path, not a literal "\040".
        let mounts = "/dev/sdb1 /media/user/FOB\\040BACKUP exfat rw 0 0\n";
        assert_eq!(
            find_mount_point(mounts, "sdb1"),
            Some(PathBuf::from("/media/user/FOB BACKUP"))
        );
    }

    #[test]
    fn decode_mounts_escapes_handles_all_four_kernel_escapes() {
        assert_eq!(decode_mounts_escapes("a\\040b"), "a b");
        assert_eq!(decode_mounts_escapes("a\\011b"), "a\tb");
        assert_eq!(decode_mounts_escapes("a\\012b"), "a\nb");
        assert_eq!(decode_mounts_escapes("a\\134b"), "a\\b");
        assert_eq!(decode_mounts_escapes("no escapes here"), "no escapes here");
    }

    #[test]
    fn prefers_the_partition_that_already_has_a_vault_when_disk_has_several() {
        // A disk with multiple mounted partitions (sdb1, sdb2) must not
        // just silently return whichever happens to appear first in
        // /proc/mounts with no regard for which one is actually the vault.
        let dir = std::env::temp_dir().join(format!(
            "fob-device-test-{}-{}",
            std::process::id(),
            "prefers_vault_partition"
        ));
        let empty = dir.join("empty_partition");
        let has_vault = dir.join("vault_partition");
        std::fs::create_dir_all(&empty).unwrap();
        std::fs::create_dir_all(&has_vault).unwrap();
        std::fs::write(
            has_vault.join("vault.fob"),
            b"not a real vault, just a marker",
        )
        .unwrap();

        let mounts = format!(
            "/dev/sdb1 {} ext4 rw 0 0\n/dev/sdb2 {} exfat rw 0 0\n",
            empty.display(),
            has_vault.display()
        );

        assert_eq!(find_mount_point(&mounts, "sdb"), Some(has_vault.clone()));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn detects_usb_bus_component_in_resolved_sysfs_path() {
        // A real /sys/block/sdb symlink target for a USB-attached device.
        let usb_path =
            "../devices/pci0000:00/0000:00:14.0/usb1/1-1/1-1:1.0/host0/target0:0:0/0:0:0:0/block/sdb";
        assert!(resolved_path_indicates_usb(usb_path));
    }

    #[test]
    fn does_not_flag_internal_sata_path_as_usb() {
        let sata_path =
            "../devices/pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0/block/sda";
        assert!(!resolved_path_indicates_usb(sata_path));
    }

    #[test]
    fn does_not_falsely_match_a_component_that_merely_starts_with_usb() {
        // "usbfoo" is not "usb" + a bus number — must not match.
        assert!(!resolved_path_indicates_usb("../devices/usbfoo/block/sdb"));
    }

    #[test]
    fn system_disk_heuristic_matches_bare_sda_only() {
        assert!(is_likely_system_disk("sda"));
        assert!(!is_likely_system_disk("sda1")); // a partition, not the whole disk
        assert!(!is_likely_system_disk("sdb"));
    }
}
