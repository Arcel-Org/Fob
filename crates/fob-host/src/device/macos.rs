use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::Command;

#[cfg(target_os = "macos")]
use super::UsbDevice;

// ── diskutil output parsing (pure — platform-independent, unit tested) ────
//
// Split out from the macOS I/O-driving code below so the parsing logic —
// where real bugs hide — can be tested on any OS, not just under
// `#[cfg(target_os = "macos")]` on a macOS CI runner.

/// Parse a `diskutil info` block's "Mount Point:" line.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn parse_mount_point(info: &str) -> Option<PathBuf> {
    let raw = info
        .lines()
        .find(|l| l.trim_start().starts_with("Mount Point:"))?
        .trim_start()
        .trim_start_matches("Mount Point:")
        .trim();
    if raw.is_empty() || raw == "Not applicable" {
        None
    } else {
        Some(PathBuf::from(raw))
    }
}

/// Parse a `diskutil info` block's "Volume Name:" line. Returns `None` for
/// a blank label (common on cheap/factory-formatted FAT32 sticks — real
/// diskutil renders these as an empty "Volume Name:" value, not the word
/// "Untitled" that only appears for the *default OS-assigned* name), not
/// `Some("")` — callers fall back to the disk node identifier via
/// `unwrap_or_else`, and that fallback never triggers if this returns
/// `Some` for an empty string.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn parse_volume_name(info: &str) -> Option<String> {
    let name = info
        .lines()
        .find(|l| l.trim_start().starts_with("Volume Name:"))?
        .trim()
        .trim_start_matches("Volume Name:")
        .trim()
        .to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Parse a `diskutil info` block's size line, e.g.
/// `   Disk Size:   15.6 GB (15636365312 Bytes) ...` → `15636365312`.
///
/// Checks "Disk Size:"/"Total Size:" (ExFAT/FAT32/plain disks) as well as
/// "Volume Total Space:"/"Container Total Space:" (real diskutil's field
/// names for HFS+ volumes and APFS containers respectively) — without the
/// latter two, any pre-existing non-ExFAT drive (e.g. a Mac-formatted
/// external HFS+/APFS drive the user is about to reformat) silently shows
/// a size of 0.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn parse_disk_size_bytes(info: &str) -> u64 {
    info.lines()
        .find(|l| {
            l.contains("Disk Size:")
                || l.contains("Total Size:")
                || l.contains("Volume Total Space:")
                || l.contains("Container Total Space:")
        })
        .and_then(|l| l.split('(').nth(1))
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.replace(',', "").parse::<u64>().ok())
        .unwrap_or(0)
}

/// Parse a `diskutil info` block's "Device Node:" line into a bare node name
/// (`/dev/disk4s1` → `disk4s1`).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn parse_device_node(info: &str) -> Option<String> {
    info.lines()
        .find_map(|l| l.trim_start().strip_prefix("Device Node:"))
        .map(|rest| rest.trim().trim_start_matches("/dev/").to_string())
}

/// Does this `diskutil info` block (queried by mount point) describe an
/// external disk?
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn is_external_diskutil_info(info: &str) -> bool {
    let protocol_says_external = info
        .lines()
        .find(|l| l.contains("Protocol:"))
        .is_some_and(|l| l.contains("USB") || l.contains("SD") || l.contains("Thunderbolt"));
    // Real diskutil's actual field for this is "Device Location: External"
    // (vs. "Internal") — a literal "External: Yes" line, the previous
    // fallback here, doesn't correspond to any real diskutil output and
    // was dead code. This fallback also catches Thunderbolt/USB4 NVMe
    // enclosures that diskutil sometimes reports as `Protocol: PCI-Express`
    // instead of a bus name the check above would recognize.
    let device_location_says_external = info
        .lines()
        .any(|l| l.contains("Device Location:") && l.contains("External"));
    protocol_says_external || device_location_says_external
}

/// Extract every probeable disk node identifier from `diskutil list
/// external` output: both whole-disk headers (`/dev/disk4 (external,
/// physical):` → `disk4`) and each disk's partition rows (an indented
/// numbered row like `1:  Windows_FAT_32 FOB  15.6 GB  disk4s1` →
/// `disk4s1`, identified by the last whitespace-separated token).
///
/// Real `diskutil info` only reports Mount Point/Volume Name on a
/// PARTITION identifier, never on the whole-disk identifier of a normally
/// partitioned drive — probing only whole-disk ids (this function's
/// previous behavior) silently found nothing for any real partitioned USB
/// stick, leaving detection entirely dependent on the separate `/Volumes`
/// fallback scan (which only sees already-mounted volumes). Whole-disk ids
/// are still included too, since that's the one case where a whole-disk
/// query *does* succeed: an unpartitioned "superfloppy"-formatted drive.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn parse_external_disk_nodes(list_output: &str) -> Vec<String> {
    let mut nodes: Vec<String> = Vec::new();
    let mut push_unique = |node: String| {
        if !nodes.contains(&node) {
            nodes.push(node);
        }
    };

    for line in list_output.lines() {
        if let Some(rest) = line.strip_prefix("/dev/") {
            if let Some(node) = rest.split_whitespace().next() {
                push_unique(node.to_string());
            }
            continue;
        }

        // An indented row like "   1:   Windows_FAT_32 FOB   15.6 GB   disk4s1"
        // — the header row ("#:  TYPE NAME  SIZE  IDENTIFIER") starts with
        // '#' rather than a digit, so it's naturally excluded here.
        let trimmed = line.trim_start();
        let is_numbered_row = trimmed
            .split_once(':')
            .is_some_and(|(n, _)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
        if is_numbered_row {
            if let Some(identifier) = line.split_whitespace().last() {
                if identifier.starts_with("disk") {
                    push_unique(identifier.to_string());
                }
            }
        }
    }
    nodes
}

/// The whole-disk identifier for a given disk node — `diskutil eraseDisk`
/// needs the whole disk (`disk4`), not a partition (`disk4s1`).
///
/// Only strips the `sM` partition suffix when one is actually present.
/// The previous version unconditionally trimmed trailing digits then a
/// trailing `s`, which also mangled a disk node that's *already* a bare
/// whole-disk identifier with no partition suffix at all (an unpartitioned
/// "superfloppy"-formatted drive, the one case where a whole-disk
/// `diskutil info` query actually succeeds) — `"disk4"` (no partition)
/// would incorrectly become `"disk"`, an invalid device id.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn whole_disk_identifier(disk_node: &str) -> String {
    if let Some(s_pos) = disk_node.rfind('s') {
        let (before, after) = disk_node.split_at(s_pos);
        let partition_suffix = &after[1..]; // skip the 's' itself
        let looks_like_partition = !partition_suffix.is_empty()
            && partition_suffix.bytes().all(|b| b.is_ascii_digit())
            && before.ends_with(|c: char| c.is_ascii_digit());
        if looks_like_partition {
            return before.to_string();
        }
    }
    disk_node.to_string()
}

#[cfg(target_os = "macos")]
pub(super) fn enumerate() -> Vec<UsbDevice> {
    // `diskutil list -plist external` returns only external drives.
    // We parse /Volumes for mounted volumes on those disks.
    let mut devices = Vec::new();

    let out = match Command::new("diskutil").args(["list", "external"]).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(_) => return devices,
    };

    for disk in parse_external_disk_nodes(&out) {
        if let Some(dev) = probe_disk(&disk) {
            if !dev.is_system_drive() {
                devices.push(dev);
            }
        }
    }

    // Also scan /Volumes for anything we may have missed (e.g. disk already mounted).
    if let Ok(entries) = std::fs::read_dir("/Volumes") {
        for entry in entries.flatten() {
            let mount = entry.path();
            // Skip Macintosh HD
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "Macintosh HD" || name == "Macintosh HD - Data" {
                continue;
            }

            // Check if already in devices list
            if devices.iter().any(|d| d.path == mount) {
                continue;
            }

            // Probe via diskutil info
            if let Some(dev) = probe_mount(&mount) {
                if !dev.is_system_drive() {
                    devices.push(dev);
                }
            }
        }
    }

    devices.sort_by(|a, b| a.name.cmp(&b.name));
    devices
}

#[cfg(target_os = "macos")]
pub(super) fn probe_disk(disk_node: &str) -> Option<UsbDevice> {
    let info_out = Command::new("diskutil")
        .args(["info", disk_node])
        .output()
        .ok()?;
    let info = String::from_utf8_lossy(&info_out.stdout).into_owned();

    // No is_removable_diskutil_info() check here: every disk_node this is
    // called with already came from `diskutil list external`, so it's
    // already known to be external at the listing stage — that's the real
    // gate, not the separate "Removable Media:" flag (which some external
    // SSDs report as "Fixed" despite genuinely being external/USB-attached).
    let mount = parse_mount_point(&info)?;
    let name = parse_volume_name(&info).unwrap_or_else(|| disk_node.to_string());
    let size_bytes = parse_disk_size_bytes(&info);
    let has_fob_vault = mount.join("vault.fob").exists();

    Some(UsbDevice {
        name,
        size_bytes,
        path: mount,
        disk_node: disk_node.to_string(),
        serial: None,
        has_fob_vault,
    })
}

#[cfg(target_os = "macos")]
fn probe_mount(mount: &std::path::Path) -> Option<UsbDevice> {
    let info_out = Command::new("diskutil")
        .args(["info", &mount.to_string_lossy()])
        .output()
        .ok()?;
    let info = String::from_utf8_lossy(&info_out.stdout).into_owned();

    if !is_external_diskutil_info(&info) {
        return None;
    }

    let disk_node = parse_device_node(&info).unwrap_or_default();
    let name = parse_volume_name(&info).unwrap_or_else(|| {
        mount
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string()
    });
    let size_bytes = parse_disk_size_bytes(&info);
    let has_fob_vault = mount.join("vault.fob").exists();

    Some(UsbDevice {
        name,
        size_bytes,
        path: mount.to_path_buf(),
        disk_node,
        serial: None,
        has_fob_vault,
    })
}

/// Format the given USB device as ExFAT with the label "FOB" via `diskutil
/// eraseDisk`, requesting admin privileges through the standard macOS
/// dialog. This is destructive — all data is erased. Caller
/// (`format_device`) already checked `!dev.is_system_drive()`.
#[cfg(target_os = "macos")]
pub(super) fn erase(dev: &UsbDevice) -> anyhow::Result<()> {
    let whole_disk = whole_disk_identifier(&dev.disk_node);
    let cmd = format!("diskutil eraseDisk ExFAT FOB {}", whole_disk);
    // Use osascript to request admin privileges via the standard macOS dialog.
    let out = Command::new("osascript")
        .args([
            "-e",
            &format!("do shell script \"{}\" with administrator privileges", cmd),
        ])
        .output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("Format failed: {}", stderr.trim());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DISKUTIL_INFO_EXTERNAL_USB: &str = "
   Device Identifier:        disk4s1
   Device Node:              /dev/disk4s1
   Whole:                    No
   Part of Whole:            disk4

   Volume Name:              FOB
   Mounted:                  Yes
   Mount Point:              /Volumes/FOB

   Partition Type:           Windows_FAT_32
   File System Personality:  ExFAT

   Removable Media:          Removable
   Media Type:               Generic

   Protocol:                 USB

   Disk Size:                15.6 GB (15636365312 Bytes) (exactly 30539776 512-Byte-Units)
";

    const DISKUTIL_INFO_INTERNAL: &str = "
   Device Identifier:        disk1s1
   Device Node:              /dev/disk1s1
   Volume Name:              Macintosh HD
   Mounted:                  Yes
   Mount Point:              /

   Protocol:                 Apple Fabric
   Disk Size:                500.3 GB (500277790720 Bytes)
";

    const DISKUTIL_INFO_UNMOUNTED: &str = "
   Device Identifier:        disk5s1
   Device Node:              /dev/disk5s1
   Volume Name:              Untitled
   Mounted:                  No
   Mount Point:              Not applicable

   Protocol:                 USB
   Disk Size:                8.0 GB (8000000000 Bytes)
";

    #[test]
    fn parses_mount_point_from_real_diskutil_output() {
        assert_eq!(
            parse_mount_point(DISKUTIL_INFO_EXTERNAL_USB),
            Some(PathBuf::from("/Volumes/FOB"))
        );
    }

    #[test]
    fn parses_mount_point_none_when_not_applicable() {
        assert_eq!(parse_mount_point(DISKUTIL_INFO_UNMOUNTED), None);
    }

    #[test]
    fn parses_volume_name() {
        assert_eq!(
            parse_volume_name(DISKUTIL_INFO_EXTERNAL_USB),
            Some("FOB".to_string())
        );
    }

    #[test]
    fn parses_volume_name_returns_none_for_blank_label() {
        let info = "
   Device Identifier:        disk6s1
   Device Node:              /dev/disk6s1
   Volume Name:
   Mounted:                  Yes
   Mount Point:              /Volumes/Untitled 1

   Protocol:                 USB
   Disk Size:                4.0 GB (4000000000 Bytes)
";
        assert_eq!(parse_volume_name(info), None);
    }

    #[test]
    fn parses_disk_size_bytes() {
        assert_eq!(
            parse_disk_size_bytes(DISKUTIL_INFO_EXTERNAL_USB),
            15636365312
        );
        assert_eq!(parse_disk_size_bytes(DISKUTIL_INFO_INTERNAL), 500277790720);
    }

    #[test]
    fn parses_disk_size_bytes_for_hfs_volume_total_space() {
        let info = "
   Volume Name:              Backup
   Protocol:                 USB
   Volume Total Space:       128.0 GB (128035676160 Bytes)
";
        assert_eq!(parse_disk_size_bytes(info), 128035676160);
    }

    #[test]
    fn parses_disk_size_bytes_for_apfs_container_total_space() {
        let info = "
   Volume Name:              MyAPFS
   Protocol:                 USB
   Container Total Space:    250.0 GB (250059350016 Bytes)
";
        assert_eq!(parse_disk_size_bytes(info), 250059350016);
    }

    #[test]
    fn parses_disk_size_bytes_zero_when_missing() {
        assert_eq!(parse_disk_size_bytes("no size info here"), 0);
    }

    #[test]
    fn parses_device_node_strips_dev_prefix() {
        assert_eq!(
            parse_device_node(DISKUTIL_INFO_EXTERNAL_USB),
            Some("disk4s1".to_string())
        );
    }

    #[test]
    fn detects_external_by_protocol() {
        assert!(is_external_diskutil_info(DISKUTIL_INFO_EXTERNAL_USB));
        assert!(!is_external_diskutil_info(DISKUTIL_INFO_INTERNAL));
    }

    #[test]
    fn detects_external_by_thunderbolt_protocol() {
        let info = "
   Volume Name:              TBDrive
   Protocol:                 Thunderbolt
";
        assert!(is_external_diskutil_info(info));
    }

    #[test]
    fn detects_external_via_device_location_fallback() {
        // A Thunderbolt/USB4 NVMe enclosure diskutil reports as
        // Protocol: PCI-Express — must still be caught via the real
        // "Device Location: External" field.
        let info = "
   Volume Name:              NVMeDrive
   Protocol:                 PCI-Express
   Device Location:          External
";
        assert!(is_external_diskutil_info(info));
    }

    #[test]
    fn internal_pcie_drive_is_not_external() {
        let info = "
   Volume Name:              Macintosh HD
   Protocol:                 PCI-Express
   Device Location:          Internal
";
        assert!(!is_external_diskutil_info(info));
    }

    #[test]
    fn parses_external_disk_nodes_from_list_output() {
        let list_output = "\
/dev/disk4 (external, physical):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:      FDisk_partition_scheme                        *15.6 GB    disk4
   1:                 Windows_FAT_32 FOB                  15.6 GB    disk4s1

/dev/disk5 (external, physical):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:      FDisk_partition_scheme                        *8.0 GB     disk5
";
        // Must include the real partition identifier "disk4s1" — real
        // diskutil only reports Mount Point/Volume Name on a partition
        // identifier, never on a normally-partitioned drive's whole-disk
        // identifier, so probing only "disk4"/"disk5" (the old behavior)
        // silently found nothing for either drive.
        assert_eq!(
            parse_external_disk_nodes(list_output),
            vec![
                "disk4".to_string(),
                "disk4s1".to_string(),
                "disk5".to_string()
            ]
        );
    }

    #[test]
    fn parses_external_disk_nodes_empty_when_none_present() {
        assert_eq!(
            parse_external_disk_nodes("No disks found.\n"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn whole_disk_identifier_strips_partition_suffix() {
        assert_eq!(whole_disk_identifier("disk4s1"), "disk4");
        assert_eq!(whole_disk_identifier("disk10s2"), "disk10");
    }

    #[test]
    fn whole_disk_identifier_leaves_unpartitioned_disk_unchanged() {
        // Regression test: an unpartitioned "superfloppy"-formatted drive
        // has a bare whole-disk identifier with no "sM" suffix at all —
        // the previous unconditional trim-trailing-digits-then-'s' logic
        // mangled "disk4" into the invalid "disk".
        assert_eq!(whole_disk_identifier("disk4"), "disk4");
        assert_eq!(whole_disk_identifier("disk10"), "disk10");
    }
}
