//! Host-OS integration for the Fob CLI.
//!
//! Everything here talks to the operating system (enumerating block devices,
//! touching the clipboard, writing files) — deliberately kept out of
//! `fob-core`, which stays pure crypto/format logic with no I/O.

pub mod clipboard;
pub mod device;
pub mod fs_util;
