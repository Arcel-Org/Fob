//! Host-OS integration shared by `fob-cli` and `fob-app`.
//!
//! Everything here talks to the operating system (spawning processes,
//! enumerating block devices, touching the clipboard, writing files) —
//! deliberately kept out of `fob-core`, which stays pure crypto/format logic
//! with no I/O.

pub mod clipboard;
pub mod device;
pub mod fs_util;
pub mod ssh_agent;
