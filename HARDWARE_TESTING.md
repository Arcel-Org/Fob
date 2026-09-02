# Fob — Manual Hardware Testing Checklist

> **This is a checklist for a human to execute on real physical hardware.**
> Nothing in this document has been run. Every test in this codebase to date
> (147 unit/integration tests, clippy, fmt, audit) has executed inside a
> sandboxed container with no real block devices, no real `diskutil`/`udev`,
> and no real USB controller. That means the entire device-detection layer
> (`crates/fob-host/src/device/`) and the format/erase path are **unverified on real hardware**.
> A "fresh audit pass" or code review cannot substitute for the checks below —
> someone with physical USB drives and a keyboard needs to run them.
>
> Record results (pass/fail + notes) inline in a copy of this file, or in
> whatever issue tracker the project uses. If a step fails, capture:
> the exact command run, full stdout/stderr, `diskutil info <disk>` /
> `lsblk` / `cat /proc/mounts` output at the time of failure, and the OS
> version.

## 0. Prerequisites

- [ ] Build release binaries on each target OS:
  ```
  cargo build --release --workspace
  ```
  The `fob` binary lands at `target/release/fob`.
- [ ] macOS: a machine actually running macOS (Intel and Apple Silicon if you
  have both — Apple Silicon Macs are far more likely to have USB-C/Thunderbolt
  NVMe enclosures instead of classic USB-A flash drives).
- [ ] Linux: a machine actually running Linux, not a container. `/sys/block`
  and `/proc/mounts` do not mean the same thing inside Docker.
- [ ] Have `exfat-utils` or `exfatprogs` installed on Linux (`mkfs.exfat`
  needs one of them: `apt install exfatprogs` or `apt install exfat-utils`
  depending on distro/version). If neither is installed, `fob`'s
  `format_device` will fail with "Install exfat-utils." — confirm the error
  message actually appears and is legible, don't just take it on faith.
- [ ] At least **4 different physical USB drives**, covering:
  - [ ] A classic USB-A flash/thumb drive (the "boring" common case).
  - [ ] A USB drive formatted exFAT with a **volume label containing a space**
    (e.g. name it `FOB BACKUP` or leave a Windows-default name like
    `Removable Disk`). This is the single most important non-default
    fixture — see § 8.1.
  - [ ] An external USB **SSD or NVMe-in-enclosure** drive (not a flash
    stick) — these often report differently to the OS than thumb drives
    (see § 8.4).
  - [ ] A drive with **two partitions** on it (e.g. a small first partition
    plus a larger second one — an old bootable-USB-installer stick works, or
    partition one yourself with `diskutil` / `fdisk`).
---

## 1. Fresh drive setup

Run once on macOS, once on Linux, for at least two different drives from the
prerequisite list (the space-in-label one and the plain one).

- [ ] Insert a **completely blank/unpartitioned** drive (if you can get one
  into that state — `diskutil eraseDisk` with "Free Space" scheme on macOS,
  or `wipefs -a /dev/sdX` on Linux). Run `fob status`.
  - [ ] **Expected-but-unverified**: the current `device.rs` logic finds
    drives by scanning currently-mounted volumes (`/Volumes` on macOS,
    `/proc/mounts` on Linux). A truly blank, unformatted disk has no mount
    point and may not appear in the list at all. **Confirm what actually
    happens** — does `fob` offer to format it, or does it just not show up?
    If it doesn't show up, that's a real gap to file, not a test failure to
    paper over.
- [ ] Insert a drive already formatted exFAT/FAT32 but with **no Fob vault
  on it** (blank data drive). Run `fob status` — confirm it's listed, size
  is correct (compare to what the OS itself reports, e.g. Finder "Get Info"
  or `lsblk -b`), and `[vault present]` is **absent**.
- [ ] Run `fob format <device>` against that drive. Follow the prompts: set and confirm a master passphrase, optionally a
decoy and duress passphrase and a post-quantum recovery key. Let it format
+ initialize.
- [ ] Eject and re-insert the drive. Run `fob status` again — confirm
  `[vault present]` is now shown, and the reported size didn't change
  (formatting shouldn't silently shrink/grow the reported capacity by more
  than filesystem overhead).
- [ ] Inspect the drive with a **different machine's** file browser (or `ls`)
  — confirm a `vault.fob` file exists at the root and nothing unexpected
  (stray `.Trashes`, `System Volume Information`, etc. from formatting) is
  broken.

---

## 2. Existing-vault detection

- [ ] With the drive from § 1 still having its vault, unplug it, plug it
  into a **different USB port**, and re-run `fob status`. Confirm detection doesn't depend on port/bus ordering.
- [ ] Reboot the test machine with the vault drive already inserted, then
  run `fob status` — confirm it's detected on a "cold" boot, not just
  hot-plug.
- [ ] Rename the volume label (via OS tools) after the vault exists, re-run
  `fob status` — confirm the vault is still found (vault detection should
  key off `vault.fob` file presence, not volume name).

---

## 3. Wrong passphrase

- [ ] Unlock with a deliberately wrong passphrase. Confirm:
  - [ ] A generic error is shown — **it must not reveal whether the
    passphrase was "close"**, whether a decoy/duress slot exists, or which
    slot type failed.
  - [ ] Repeated wrong attempts don't crash, hang, or corrupt the vault file
    (compare a checksum/hash of `vault.fob` before and after several failed
    attempts — it should be byte-identical).
  - [ ] Time a wrong-passphrase attempt against a correct one a few times.
    They shouldn't be trivially distinguishable by a stopwatch (the code
    comment in `vault.rs` claims constant-time-ish behavior across slots —
    this is the only way to sanity-check that claim outside a proper timing
    harness).

---

## 4. Decoy passphrase

- [ ] Unlock with the decoy passphrase set up in § 1. Confirm it opens into
  what looks like a normal, usable vault (not an error, not obviously
  labeled "decoy" anywhere in the UI).
- [ ] Add a few entries to the decoy vault, lock, re-unlock with the decoy
  passphrase — confirm the entries persisted.
- [ ] Re-unlock with the **main** passphrase — confirm the decoy's entries
  are **not** visible in the main vault, and vice versa (add something to
  main, confirm it doesn't leak into decoy).
- [ ] Confirm the real `vault.fob` file size on disk doesn't change in a way
  that reveals which slots are "in use" vs empty (eyeball file size before
  and after using each slot).

---

## 5. Duress passphrase — verify the file is *actually* wiped

This is the highest-stakes check in this whole document — a duress feature
that silently no-ops is worse than not having one.

- [ ] Before triggering duress: `cp` the vault file to a scratch location
  and compute `sha256sum vault.fob` (or `shasum -a 256`). Note the exact
  byte size (`ls -l` / `stat`).
- [ ] Unlock with the **duress** passphrase configured in § 1.
- [ ] Immediately after (don't let the app "helpfully" clean anything up
  first — kill/eject if needed to catch it right after the wipe claims to
  happen), on a **different machine or by re-mounting read-only**, inspect
  `vault.fob` directly:
  - [ ] `stat`/`ls -l` — is the file still present, and is its size still
    plausible for a vault (not truncated to 0, not deleted)?
  - [ ] `sha256sum vault.fob` — **must differ** from the pre-duress hash.
  - [ ] `xxd vault.fob | head` — confirm the first bytes are no longer the
    `FOB2` magic (`46 4f 42 32`) — i.e. the header itself got overwritten,
    not just the slot contents. If the magic bytes are still intact, the
    wipe touched slots but left the header recognizable — decide whether
    that's the intended threat model or a bug.
  - [ ] Confirm the wipe actually hit **persistent storage**, not just the
    OS page cache: after the app exits, physically re-insert the drive
    into a machine that hasn't cached it (or `sync; echo 3 >
    /proc/sys/vm/drop_caches` on Linux as root, or just power-cycle the
    drive/reboot) and re-read the bytes. `fob-core`'s wipe path calls
    `sync_all()` — confirm that claim holds on your actual filesystem/drive
    combination, since exFAT/FUSE-backed mounts and some USB bridge chips
    are known to lie about write completion.
- [ ] Confirm trying to open the wiped drive in the browser vault afterward
  fails cleanly (corrupt-vault error, not a panic) rather than pretending
  to succeed.
- [ ] Repeat this whole section on both macOS and Linux — the wipe path is
  shared `fob-core` code, but the underlying filesystem driver (exFAT
  implementations differ between the two OSes) is not, and this is exactly
  the kind of thing that can differ silently between them.

---

## 6. Multiple drives plugged in at once

- [ ] Plug in **at least two** Fob-formatted drives (different passphrases
  on each) simultaneously, plus one plain USB drive with unrelated data.
  Run `fob status` — confirm all three are listed, sizes and vault-present
  flags are correct **per drive**, and none are confused with each other.
- [ ] Open the browser vault (`index.html` on the drive) for each vault drive
  in turn — confirm the right vault's data comes up each time, not a stale
  selection from a previous run.
- [ ] With two vault drives plugged in, unlock one, then **while still
  unlocked**, unplug the *other* (non-active) drive. Confirm nothing about
  the active session is disturbed.
- [ ] Plug in a **second copy of the exact same drive model/label** (e.g.
  two identically-labeled blank "Untitled" exFAT sticks) — confirm `fob`
  distinguishes them by disk node / mount path and doesn't merge or drop one
  from the list. This directly probes the ambiguity noted in the code audit
  around device-node vs. mount-point identity.

---

## 7. Drive removed mid-write

Do these deliberately, expecting some data loss on the *drive*, but no
crash-with-corrupted-state on the *host*.

- [ ] During `fob format`'s format step, physically yank the drive partway
  through. Re-insert it. Confirm `fob` doesn't hang or panic, and correctly
  reports either "no valid Fob drive" or offers to (re-)format rather than
  claiming success.
- [ ] While the browser vault is open and you're editing/adding an entry
  (mid-keystroke, before an explicit save if the UI has an explicit save
  step — otherwise right as you hit save), yank the drive. Confirm:
  - [ ] `fob` doesn't panic — it should surface an I/O error.
  - [ ] Re-inserting the drive and re-unlocking either shows the
    last-successfully-written state, or a clean "vault corrupted" error —
    **not** a silently truncated/half-written vault that decrypts into
    garbage without complaint. (`fs_util::atomic_write` is supposed to
    prevent partial writes via a temp-file-then-rename; confirm that
    actually holds when the rename itself can't complete because the
    device disappeared mid-rename.)
---

## 8. Drives with pre-existing non-Fob data

For each sub-case, plug the drive in with real, pre-existing data on it
(not freshly formatted) and run `fob status` / attempt setup, then confirm
the reported name/size look right and that `fob` does **not** touch the
drive's data without an explicit, confirmed format step.

- [ ] **8.1 — exFAT, volume label with a space** (e.g. `FOB BACKUP`,
  `Untitled 1`, or a Windows-default name). On Linux, `/proc/mounts`
  octal-escapes spaces in mount paths as `\040` (and other punctuation
  similarly) — this was a real bug (found by source review, now fixed:
  `find_mount_point` decodes these escapes before use) — confirm `fob status` shows the **actual** un-escaped path (e.g. `/media/you/FOB
  BACKUP`), not a literal `\040` in the displayed path, and that
  `has_fob_vault`/any file access against that drive actually reaches the
  real directory rather than a mangled one. If the path shown still
  contains a literal backslash-and-digits sequence, or `fob` still reports
  the drive as vault-less when it demonstrably has a `vault.fob` on it, the
  fix didn't hold up against real `/proc/mounts` output — file it.
- [ ] **8.2 — FAT32 with no volume label** (blank/`NO NAME`). Confirm `fob status`
  shows *something* sensible for the name (a fallback like the
  disk identifier), not a blank row in the list.
- [ ] **8.3 — macOS-native filesystem** (APFS or HFS+, *not* exFAT) with
  real data on it, e.g. a Time Machine drive or an old HFS+ backup disk.
  On macOS, confirm:
  - [ ] The reported size is non-zero and roughly correct (not "0.0 MB") —
    `diskutil info` reports capacity for APFS/HFS+ volumes under
    "Volume Total Space" / "Container Total Space" rather than "Disk
    Size"; the parser now matches both (a real bug found by source review,
    fixed — confirm it holds against real output).
  - [ ] `fob` does not offer to write a vault onto it without an explicit
    format step, and does not corrupt the existing data merely by *listing*
    it.
- [ ] **8.4 — external SSD / USB-NVMe enclosure**, pre-existing data. On
  Linux specifically, check whether it **appears** in `fob status` at all:
  many USB-SATA/NVMe bridge chips report `removable = 0` in
  `/sys/block/<dev>/removable` — Linux enumeration now also accepts a
  device whose sysfs symlink resolves through a USB bus (a real bug found
  by source review, fixed), so this should no longer be invisible. Confirm
  what actually happens with your enclosure and note the bridge chipset
  either way. On macOS, also confirm a Thunderbolt/USB4 NVMe enclosure
  (often reported as `Protocol: PCI-Express`) is detected via the
  `Device Location: External` fallback (also fixed).
- [ ] **8.5 — multi-partition drive** (two partitions, both real
  filesystems with data). `find_mount_point` now prefers whichever
  partition already has a `vault.fob` over an arbitrary/first-found match
  (a real bug found by source review, fixed) — confirm `fob` targets the
  partition that actually has your vault, not just whichever appears first
  in `/proc/mounts`.
- [ ] **8.6 — drive with a partition table but formatted with no partition
  table at all** ("superfloppy": filesystem written directly to the whole
  disk, e.g. some very small/cheap sticks ship this way). If `fob` detects
  it and later you format it, confirm the **format/erase step targets the
  correct physical device**, not a mis-derived sub-identifier —
  `whole_disk_identifier` used to mangle a bare whole-disk identifier with
  no partition suffix (a real bug found by source review, fixed); confirm
  it holds against a real superfloppy-formatted drive.

---

## 9. Permission-denied scenarios

- [ ] Run `fob` as a non-admin user on macOS with a drive that needs
  `diskutil eraseDisk` — confirm the OS's own admin-privilege prompt
  (`osascript ... with administrator privileges`) actually appears, and
  that declining it produces a clean "format failed" message rather than a
  hang or panic.
- [ ] On Linux, run `fob` as a normal (non-root) user against a drive that
  needs `mkfs.exfat` — confirm the failure mode is legible (permission
  denied surfaced to the user) rather than a bare exit code. Then retry with
  whatever privilege mechanism the project expects (sudo/polkit/udisks) and
  confirm it succeeds.
- [ ] Make the vault file itself read-only (`chmod 444 vault.fob` /
  equivalent) and attempt to unlock + edit + save. Confirm a clear
  permission error surfaces rather than a silent no-op "save".
- [ ] Remove write permission on the **mount point directory** (not the
  vault file) and attempt setup on a blank drive — confirm `fob` reports
  the failure instead of retrying forever or panicking.
- [ ] (Linux) Attempt to read `/proc/mounts` / `/sys/block` in a locked-down
  environment (e.g. a restrictive container or a user without the
  permissions your distro normally grants for those paths) — confirm `fob status` degrades to "no drives found" rather than crashing.

---

## Appendix: parsing areas that were fixed from source review alone (still need real-hardware confirmation)

All 8 items below were found by source review (not real-hardware testing)
and have since been **fixed in code**, with unit tests added against
hand-written fixture strings modeled on documented real `diskutil`/
`/proc/mounts` output. That's a meaningfully different confidence level
than actually running on the hardware in question — the checklist sections
referenced below still exist specifically to confirm each fix behaves
correctly against a *real* drive/OS, not just a fixture string someone
typed by hand:

- **Fixed**: `/proc/mounts` mount paths are now decoded for the kernel's
  octal escaping of spaces/tabs/backslashes/newlines (`decode_mounts_escapes`)
  before being used — confirm in § 8.1 that a real volume label with a
  space resolves to the actual path, not a literal `\040`.
- **Fixed**: `parse_external_disk_nodes` now also extracts each disk's
  partition identifiers (e.g. `disk4s1`) from `diskutil list external`'s
  indented rows, not just the whole-disk header line — since real
  `diskutil info` only reports `Mount Point:`/`Volume Name:` on a partition
  identifier, the old code's primary enumeration path silently found
  nothing for any normally-partitioned drive. Confirm in § 8.6 that the
  "superfloppy" (unpartitioned) case *and* normally-partitioned drives both
  get detected via the primary path now, not just the `/Volumes` fallback.
- **Fixed**: `format_device`'s whole-disk-identifier derivation
  (`whole_disk_identifier`) no longer mangles a bare, unpartitioned disk
  identifier (e.g. `disk4` with no `sM` suffix) into an invalid one — it
  only strips a partition suffix when one is actually present. Confirm in
  § 8.6 that formatting a superfloppy-formatted drive targets the correct
  physical device.
- **Fixed**: `is_external_diskutil_info` now also matches `Protocol:
  Thunderbolt`, and its external-disk fallback checks the real
  `Device Location: External` field instead of a `External:`/`Yes` pattern
  that didn't correspond to any actual `diskutil` output. Confirm in § 8.4
  that a Thunderbolt/USB4 NVMe enclosure (often reported as
  `Protocol: PCI-Express`) is now detected via this fallback.
- **Fixed**: Linux enumeration no longer filters solely on
  `/sys/block/<dev>/removable` — it also accepts a device whose sysfs
  symlink resolves through a USB bus component (`resolved_path_indicates_usb`),
  since many USB-SATA/USB-NVMe bridge chips report `removable=0`. Confirm
  in § 8.4 that your external SSD/NVMe enclosure is now detected.
- **Fixed**: `find_mount_point` no longer does a bare substring match
  against a disk name — it's now boundary-anchored (matches the disk
  itself or `disk` + digits, e.g. `sdb` matches `/dev/sdb1` but not
  `/dev/sdbx1`) and, when a disk has multiple mounted partitions, prefers
  whichever one already has a `vault.fob` rather than an arbitrary
  first-found match. Confirm in § 8.5 that a multi-partition drive
  resolves to the partition that actually has your vault on it.
- **Fixed**: `parse_disk_size_bytes` now also matches `Volume Total Space:`/
  `Container Total Space:` (real diskutil's field names for HFS+
  volumes/APFS containers), not just `Disk Size:`/`Total Size:`. Confirm in
  § 8.3 that a pre-existing APFS/HFS+ drive shows its real size, not 0.
- **Fixed**: `parse_volume_name` now returns `None` (triggering the
  disk-identifier fallback) for a blank volume label instead of
  `Some("")`. Confirm in § 8.2 that a blank-labeled FAT32 stick shows a
  sensible fallback name, not an empty row.
