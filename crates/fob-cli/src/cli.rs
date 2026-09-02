use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::tui;
use fob_host::fs_util::atomic_write;

pub const WEB_INDEX_HTML: &str = include_str!("../../../web/index.html");

const RELEASES_API: &str = "https://api.github.com/repos/Arcel-Org/Fob/releases/latest";

/// `install.sh` pinned to a specific release tag rather than the mutable
/// `main` branch. Used everywhere `fob update` downloads-and-executes the
/// script (once we already know the exact tag we're updating to) — piping
/// an arbitrary always-latest branch ref into `sh` means the content
/// executed can silently change between the moment a user is shown the
/// command and the moment they run it (or on every future re-run of a
/// copy-pasted command), with nothing to detect that. Pinning to the tag
/// doesn't add cryptographic verification, but it does mean "update to
/// v1.2.3" always runs the exact script that shipped with v1.2.3, not
/// whatever `main` happens to contain right now.
fn pinned_install_url(tag: &str) -> String {
    format!("https://raw.githubusercontent.com/Arcel-Org/Fob/{tag}/install/install.sh")
}

#[derive(Parser)]
#[command(
    name = "fob",
    about = "Fob — encrypted vault on a USB drive",
    version = env!("CARGO_PKG_VERSION"),
    long_about = None,
)]
pub struct Cli {
    /// Path to a specific USB device or vault file.
    #[arg(short, long, global = true)]
    pub device: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Interactive setup: format USB, create vault, write web UI.
    Setup,

    /// Open the TUI for an existing vault.
    Unlock { device: Option<PathBuf> },

    /// Show detected USB drives.
    Devices,

    /// Check for and install updates.
    Update {
        /// Only print whether an update is available; don't install.
        #[arg(long)]
        check: bool,
    },

    /// Unlock a vault's Main slot using a recovery key instead of a
    /// passphrase (see the "recovery key" prompt during `fob setup`), and
    /// set a new main passphrase.
    Recover { device: Option<PathBuf> },
}

impl Cli {
    pub fn run(self) -> Result<()> {
        match self.command {
            None | Some(Commands::Setup) => tui::run_tui(self.device),
            Some(Commands::Unlock { device }) => tui::run_tui(device.or(self.device)),
            Some(Commands::Devices) => cmd_devices(),
            Some(Commands::Update { check }) => cmd_update(check),
            Some(Commands::Recover { device }) => cmd_recover(device.or(self.device)),
        }
    }
}

/// List detected removable USB devices (does not require unlocking).
fn cmd_devices() -> Result<()> {
    let devices = fob_host::device::enumerate_usb_devices();
    if devices.is_empty() {
        println!("No USB drives detected. Insert a USB drive and retry.");
        return Ok(());
    }
    println!("Detected USB drives:");
    for (i, d) in devices.iter().enumerate() {
        let vault = if d.has_fob_vault {
            " [vault present]"
        } else {
            ""
        };
        println!(
            "  [{}]  {}  {}  {}{}",
            i + 1,
            d.name,
            d.size_display(),
            d.path.display(),
            vault
        );
    }
    Ok(())
}

/// Resolve a device/vault argument to an actual `vault.fob` path: a
/// directory (USB mount point) has `vault.fob` joined on; a path already
/// ending in a file is used as-is. With no argument, auto-picks the sole
/// detected USB drive with a vault, or errors listing what was found.
fn resolve_vault_path(device: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = device {
        return Ok(if path.is_dir() {
            path.join("vault.fob")
        } else {
            path
        });
    }

    let candidates: Vec<_> = fob_host::device::enumerate_usb_devices()
        .into_iter()
        .filter(|d| d.has_fob_vault)
        .collect();

    match candidates.as_slice() {
        [only] => Ok(only.path.join("vault.fob")),
        [] => Err(anyhow::anyhow!(
            "no USB drive with a Fob vault detected — specify one with --device"
        )),
        many => Err(anyhow::anyhow!(
            "multiple vaults found — specify one with --device:\n{}",
            many.iter()
                .map(|d| format!("  {}  ({})", d.path.display(), d.name))
                .collect::<Vec<_>>()
                .join("\n")
        )),
    }
}

/// Unlock a vault's Main slot with a recovery key and set a new main
/// passphrase — for when the original passphrase is lost. Only the Main
/// slot is recoverable this way; Decoy and Duress are unaffected.
fn cmd_recover(device: Option<PathBuf>) -> Result<()> {
    use std::io::Write as _;
    use zeroize::Zeroize;

    let vault_path = resolve_vault_path(device)?;
    let vault_bytes = std::fs::read(&vault_path)
        .map_err(|e| anyhow::anyhow!("couldn't read {}: {e}", vault_path.display()))?;

    print!("Paste your Fob recovery key: ");
    std::io::stdout().flush()?;
    let mut recovery_input = String::new();
    std::io::stdin().read_line(&mut recovery_input)?;
    let privkey = fob_core::recovery::decode_private_key_from_display(&recovery_input)
        .map_err(|e| anyhow::anyhow!("invalid recovery key: {e}"))?;
    recovery_input.zeroize();

    let (_, blob) = fob_core::vault::recover_vault(&vault_bytes, &privkey)
        .map_err(|e| anyhow::anyhow!("recovery failed: {e}"))?;
    // privkey's X25519/ML-KEM secrets self-zeroize on drop (see recovery.rs).
    drop(privkey);

    println!(
        "Recovery key accepted — {} entries found.",
        blob.entry_count()
    );

    print!("Enter a new main passphrase: ");
    std::io::stdout().flush()?;
    let mut new_passphrase = String::new();
    std::io::stdin().read_line(&mut new_passphrase)?;
    let new_passphrase = new_passphrase.trim_end_matches(['\r', '\n']).to_string();
    if new_passphrase.is_empty() {
        anyhow::bail!("passphrase cannot be empty");
    }

    let mut vault_file = fob_core::vault::VaultFile::from_bytes(vault_bytes)?;
    let kdf_out = fob_core::kdf::derive_master(new_passphrase.as_bytes(), &vault_file.header)?;
    let slot_keys = fob_core::kdf::derive_all_slot_keys(kdf_out.master_secret());
    vault_file.write_slot(
        fob_core::vault::SlotKind::Main,
        slot_keys[fob_core::vault::SlotKind::Main.index()].bytes(),
        &blob,
    )?;
    atomic_write(&vault_path, &vault_file.data)?;

    println!("Main passphrase reset. The vault now unlocks with the new passphrase.");
    Ok(())
}

/// Write the embedded web UI to the USB device path.
pub fn write_web_ui(device_path: &std::path::Path) -> Result<()> {
    let dest = device_path.join("index.html");
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("chflags")
            .args(["nouchg", &dest.to_string_lossy()])
            .status();
    }
    atomic_write(&dest, WEB_INDEX_HTML.as_bytes())?;
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("chflags")
            .args(["uchg", &dest.to_string_lossy()])
            .status();
    }
    Ok(())
}

/// Check GitHub for a newer release and optionally install it.
fn cmd_update(check_only: bool) -> Result<()> {
    use std::io::Write as _;

    let current = concat!("v", env!("CARGO_PKG_VERSION"));
    println!("Current version: {current}");
    print!("Checking for updates…  ");
    std::io::stdout().flush()?;

    // Fetch latest release tag via GitHub API using the system curl.
    let out = std::process::Command::new("curl")
        .args([
            "-fsSL",
            "--max-time",
            "10",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "X-GitHub-Api-Version: 2022-11-28",
            RELEASES_API,
        ])
        .output();

    let latest = match out {
        Ok(o) if o.status.success() => {
            let body = String::from_utf8_lossy(&o.stdout);
            // Extract "tag_name" without pulling in a JSON dep.
            body.lines()
                .find(|l| l.contains("\"tag_name\""))
                .and_then(|l| l.split('"').nth(3))
                .map(str::to_owned)
                .unwrap_or_else(|| "unknown".into())
        }
        _ => {
            println!("could not reach GitHub. Check your connection.");
            return Ok(());
        }
    };

    if latest == "unknown" {
        println!("could not parse release info.");
        return Ok(());
    }

    if latest == current {
        println!("up to date ✓");
        return Ok(());
    }

    println!("update available → {latest}");
    let install_url = pinned_install_url(&latest);

    if check_only {
        println!(
            "\nRun `fob update` or re-run the install script to upgrade:\n  curl -fsSL {install_url} | sh"
        );
        return Ok(());
    }

    print!("\nInstall {latest} now? [y/N] ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    if input.trim().eq_ignore_ascii_case("y") {
        println!("Running install script…");
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("curl -fsSL {install_url} | sh -s -- --no-path"))
            .status()?;
        if status.success() {
            println!("\n✓ Updated. Restart fob to use {latest}.");
        } else {
            println!("\nInstall script failed. Try manually:\n  curl -fsSL {install_url} | sh");
        }
    } else {
        println!("\nTo update manually:\n  curl -fsSL {install_url} | sh");
    }

    Ok(())
}
