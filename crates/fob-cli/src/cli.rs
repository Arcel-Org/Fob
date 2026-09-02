use anyhow::Result;
use clap::{Parser, Subcommand};
use std::io::Write as _;
use std::path::PathBuf;

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
    long_about = "Fob keeps a browser vault on a USB drive. This command is only for\ninstalling/updating and low-level device operations — daily use happens\nentirely in the browser (open index.html on the USB).",
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
    /// Write (or update) the browser vault UI on the USB device.
    Install {
        /// Path to a specific USB device. Auto-picks the sole USB drive if omitted.
        device: Option<PathBuf>,
    },

    /// Format a USB drive (erases it) and create a fresh v4/Argon2id vault.
    Format {
        /// Path to a specific USB device. Auto-picks the sole USB drive if omitted.
        device: Option<PathBuf>,
        /// Use the max-security Argon2id profile (128 MiB / 4 passes / 8 lanes).
        #[arg(long)]
        max_security: bool,
    },

    /// Show detected USB drives, which have a vault, and the current version.
    Status,

    /// Unlock a vault's Main slot using a recovery key instead of a
    /// passphrase (see the "recovery key" prompt during format), and set a
    /// new main passphrase.
    Recover { device: Option<PathBuf> },

    /// Check for and install updates.
    Update {
        /// Only print whether an update is available; don't install.
        #[arg(long)]
        check: bool,
    },
}

impl Cli {
    pub fn run(self) -> Result<()> {
        match self.command {
            None => cmd_status(),
            Some(Commands::Install { device }) => cmd_install(device.or(self.device)),
            Some(Commands::Format {
                device,
                max_security,
            }) => cmd_format(device.or(self.device), max_security),
            Some(Commands::Status) => cmd_status(),
            Some(Commands::Recover { device }) => cmd_recover(device.or(self.device)),
            Some(Commands::Update { check }) => cmd_update(check),
        }
    }
}

/// Resolve a device argument to a USB mount path: an explicit path is used
/// as-is; with no argument, auto-picks the sole detected USB drive, or errors
/// listing what was found.
fn resolve_device_path(device: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = device {
        return Ok(path);
    }
    let devices = fob_host::device::enumerate_usb_devices();
    if devices.len() == 1 {
        return Ok(devices[0].path.clone());
    }
    if devices.is_empty() {
        anyhow::bail!("No USB drives detected. Insert a USB drive and retry.");
    }
    let mut msg = String::from("Multiple USB drives detected — pick one with --device:\n");
    for (i, d) in devices.iter().enumerate() {
        msg.push_str(&format!(
            "  [{}]  {}  {}\n",
            i + 1,
            d.name,
            d.path.display()
        ));
    }
    anyhow::bail!("{msg}");
}

/// Write the embedded web UI to the USB device path.
fn write_web_ui(device_path: &std::path::Path) -> Result<()> {
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

/// `fob install` — put/refresh the browser vault on the USB. Non-destructive.
fn cmd_install(device: Option<PathBuf>) -> Result<()> {
    let mount = resolve_device_path(device)?;
    write_web_ui(&mount)?;
    println!(
        "✓ Browser vault written to {}",
        mount.join("index.html").display()
    );
    println!("  Open index.html (or vault.fob) on the USB to use Fob.");
    Ok(())
}

/// `fob status` — list USB drives, which have a vault, and current version.
fn cmd_status() -> Result<()> {
    println!("Fob v{}", env!("CARGO_PKG_VERSION"));
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

/// `fob format` — format a USB drive and create a fresh v4/Argon2id vault.
fn cmd_format(device: Option<PathBuf>, max_security: bool) -> Result<()> {
    use zeroize::Zeroize;

    let mount = resolve_device_path(device)?;
    let devices = fob_host::device::enumerate_usb_devices();
    let dev = devices
        .iter()
        .find(|d| d.path == mount)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("{} is not a detected USB drive", mount.display()))?;

    if dev.is_system_drive() {
        anyhow::bail!("Refusing to format a system drive.");
    }

    print!(
        "Format {} ({}) — this ERASES all data. Continue? [y/N] ",
        dev.name,
        dev.size_display()
    );
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if !input.trim().eq_ignore_ascii_case("y") {
        println!("Aborted.");
        return Ok(());
    }

    fob_host::device::format_device(&dev)?;
    println!("✓ Formatted as ExFAT (label FOB).");

    // Re-find the mount point after formatting (macOS remounts automatically).
    let mount = fob_host::device::find_mount_after_format(&dev.disk_node)
        .filter(|p| p.exists())
        .unwrap_or(mount);

    // Read and confirm the main passphrase, enforcing the shared policy.
    let mut main_pass = read_new_passphrase()?;

    // Optional recovery key.
    let mut params = fob_core::vault::VaultInitParams::new(
        main_pass.as_bytes().to_vec(),
        fob_core::format::DEFAULT_VAULT_SIZE,
    );
    if max_security {
        params.kdf_params = fob_core::vault::KdfParams::max_security_argon2id();
        println!("✓ Max-security Argon2id profile (128 MiB / 4 passes / 8 lanes).");
    }

    print!("Generate a post-quantum recovery key? [y/N] ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim().eq_ignore_ascii_case("y") {
        let (pubkey, privkey) = fob_core::recovery::generate_recovery_keypair();
        params.recovery_pubkey = Some(pubkey);
        let display = fob_core::recovery::encode_private_key_for_display(&privkey)?;
        println!("\nRecovery key (write this down now — it is shown only once):");
        println!("{display}");
        println!("The private key is never stored on disk.\n");
        // privkey's X25519/ML-KEM secrets self-zeroize on drop.
    }

    let vault_bytes = fob_core::vault::init_vault(params)?;
    atomic_write(&mount.join("vault.fob"), &vault_bytes)?;
    write_web_ui(&mount)?;

    main_pass.zeroize();
    println!("✓ Vault created: {}", mount.join("vault.fob").display());
    println!("  Open index.html on the USB to use Fob.");
    Ok(())
}

/// Prompt for a new main passphrase (twice) and enforce the shared policy
/// (fob-core::passphrase — same bar the browser enforces).
fn read_new_passphrase() -> Result<String> {
    use zeroize::Zeroize;

    loop {
        print!("Enter a new main passphrase (14+ chars, mixed): ");
        std::io::stdout().flush()?;
        let mut p1 = String::new();
        std::io::stdin().read_line(&mut p1)?;
        let mut p1 = p1.trim_end_matches(['\r', '\n']).to_string();

        if let Some(reason) = fob_core::passphrase::rejection_reason(&p1) {
            println!("Passphrase {reason}.");
            p1.zeroize();
            continue;
        }

        print!("Confirm passphrase: ");
        std::io::stdout().flush()?;
        let mut p2 = String::new();
        std::io::stdin().read_line(&mut p2)?;
        let mut p2 = p2.trim_end_matches(['\r', '\n']).to_string();

        if p1 == p2 {
            p2.zeroize();
            return Ok(p1);
        }
        println!("Passphrases do not match.");
        p1.zeroize();
        p2.zeroize();
    }
}

/// `fob recover` — unlock a vault's Main slot with a recovery key and set a
/// new main passphrase.
fn cmd_recover(device: Option<PathBuf>) -> Result<()> {
    use zeroize::Zeroize;

    let mount = resolve_device_path(device)?;
    let vault_path = if mount.is_dir() {
        mount.join("vault.fob")
    } else {
        mount
    };
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
    // privkey's X25519/ML-KEM secrets self-zeroize on drop.
    drop(privkey);

    println!(
        "Recovery key accepted — {} entries found.",
        blob.entry_count()
    );

    let new_passphrase = read_new_passphrase()?;

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

/// Check GitHub for a newer release and optionally install it.
fn cmd_update(check_only: bool) -> Result<()> {
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
