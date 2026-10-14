use anyhow::Result;
use clap::{Parser, Subcommand};
use std::io::Write as _;
use std::path::PathBuf;

use fob_host::fs_util::atomic_write;

pub const WEB_INDEX_HTML: &str = include_str!("../../../web/index.html");

const RELEASES_API: &str = "https://api.github.com/repos/Arcel-Org/Fob/releases/latest";

/// Platform key -> full Rust target triple used in GitHub release artifacts.
/// `fob install` places one `fob-<key>` binary per platform on the USB, and
/// the `fob.sh` launcher picks the right one at runtime, so the whole CLI
/// (wipe/status/recover/...) works on any macOS/Linux machine — not just the
/// one the drive was set up on. (Windows is intentionally absent: the browser
/// vault already handles the wipe there via the File System Access API.)
const PLATFORM_RELEASE_TRIPLES: &[(&str, &str)] = &[
    ("windows-x86_64", "x86_64-pc-windows-msvc"),
    ("darwin-arm64", "aarch64-apple-darwin"),
    ("darwin-x86_64", "x86_64-apple-darwin"),
    ("linux-x86_64", "x86_64-unknown-linux-musl"),
    ("linux-aarch64", "aarch64-unknown-linux-gnu"),
    ("linux-armv7", "armv7-unknown-linux-gnueabihf"),
];

/// On-USB launcher. `sh`-compatible so it runs on macOS and Linux with no
/// install step; resolves the correct prebuilt `fob` binary for the machine.
/// Defaults to the duress-wipe subcommand but passes through any other fob
/// command (status/verify/passwd/doctor/recover/...), so the stick carries
/// the whole CLI. A launcher-only `check` lists which platform binaries are
/// present.
const USB_TOOL_LAUNCHER: &str = r##"#!/bin/sh
# Fob on-USB tool — runs the prebuilt fob binary for this machine.
#
# Usage:
#   ./fob.sh            duress wipe vault.fob (silent; the default)
#   ./fob.sh status     show vault/version info on this USB
#   ./fob.sh verify     check the vault is intact (no passphrase needed)
#   ./fob.sh passwd     change the main passphrase
#   ./fob.sh doctor     crypto self-test — is this binary genuine?
#   ./fob.sh recover    reset the main passphrase with your recovery key
#   ./fob.sh check      which platform binaries are on this USB
#   ./fob.sh <other>    any other fob subcommand (format/update/install)
#
# Works on any macOS/Linux machine — no fob install needed. On Windows,
# open index.html in a browser instead.
set -u
dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
os=$(uname -s)
arch=$(uname -m)
case "$os" in
  Darwin) key="darwin" ;;
  Linux)  key="linux" ;;
  *) echo "fob: unsupported OS ($os) — use the browser vault (index.html) instead." >&2; exit 1 ;;
esac
case "$arch" in
  arm64|aarch64) arch="arm64" ;;
  x86_64|amd64)  arch="x86_64" ;;
  armv7*|armv6l) arch="armv7" ;;
  *) echo "fob: unsupported architecture ($arch)." >&2; exit 1 ;;
esac
bin="$dir/fob-$key-$arch"
if [ ! -x "$bin" ]; then
  # Emulation fallback: Apple Silicon runs x86_64 via Rosetta 2.
  case "$key-$arch" in
    darwin-arm64) [ -x "$dir/fob-darwin-x86_64" ] && bin="$dir/fob-darwin-x86_64" ;;
    *) : ;;
  esac
fi
if [ "${1:-}" = "check" ]; then
  echo "Fob on-USB binaries:"
  n=0
  for b in windows-x86_64 darwin-arm64 darwin-x86_64 linux-x86_64 linux-aarch64 linux-armv7; do
    if [ -x "$dir/fob-$b" ] || [ -x "$dir/fob-$b.exe" ]; then echo "  ✓ fob-$b"; n=$((n+1)); else echo "  - fob-$b (missing)"; fi
  done
  echo "($n/6 platforms — re-run 'fob install' with internet to fetch the rest)"
  [ -x "$bin" ] && "$bin" --version
  exit 0
fi
if [ ! -x "$bin" ]; then
  echo "fob: no binary for $os/$arch on this USB." >&2
  echo "Re-run 'fob install' (with internet) on the host that set up this drive, or use the browser vault (index.html)." >&2
  exit 1
fi
if [ "$#" -eq 0 ]; then set -- wipe; fi
exec "$bin" "$@"
"##;

/// On-USB Windows launcher (batch file). Picks the Windows x86_64 binary
/// and passes through to the same fob subcommands as `fob.sh`. Written
/// alongside `fob.sh` so a drive provisioned on any platform works everywhere.
const WINDOWS_LAUNCHER: &str = r##"@echo off
REM Fob on-USB tool - Windows.  Usage:
REM   fob.cmd              duress wipe vault.fob (default)
REM   fob.cmd status       show vault/version info
REM   fob.cmd verify       is the vault intact? (no passphrase needed)
REM   fob.cmd doctor       crypto self-test
REM   fob.cmd passwd       change the main passphrase
REM   fob.cmd recover      reset with your recovery key
REM   fob.cmd check        which platform binaries are on this USB
setlocal
set "DIR=%~dp0"
set "BIN=%DIR%fob-windows-x86_64.exe"
if not exist "%BIN%" (
  echo fob: no Windows x86_64 binary on this USB.
  echo Re-run 'fob install' on a machine with internet, or open index.html in a browser.
  exit /b 1
)
if "%~1"=="" (
  "%BIN%" wipe
  exit /b %errorlevel%
)
if /i "%~1"=="check" (
  echo Fob on-USB binaries:
  for %%b in (windows-x86_64 darwin-arm64 darwin-x86_64 linux-x86_64 linux-aarch64 linux-armv7) do (
    if exist "%DIR%fob-%%b.exe" (echo   [x] fob-%%b.exe) else (
      if exist "%DIR%fob-%%b" (echo   [x] fob-%%b) else (echo   [ ] fob-%%b)
    )
  )
  "%BIN%" --version
  exit /b 0
)
"%BIN%" %*
exit /b %errorlevel%
"##;

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

    /// Destroy the vault on this USB using the duress passphrase, from a
    /// terminal and without the browser. `fob install` ships this command
    /// onto the USB (as a binary + the `fob.sh` launcher) so it works
    /// on any macOS/Linux machine, even one that never had fob installed.
    Wipe {
        /// Path to the vault file (or its mount dir). Defaults to vault.fob
        /// in the current directory or next to this binary.
        device: Option<PathBuf>,
    },

    /// Check a vault.fob is structurally intact and print its non-secret
    /// metadata (format version, KDF, recovery flag) — no passphrase needed.
    Verify {
        /// Path to the vault file (or its mount dir). Defaults to vault.fob
        /// in the current directory or next to this binary.
        device: Option<PathBuf>,
    },

    /// Run a built-in crypto self-test (vault + recovery roundtrips) and
    /// print version/build info — confirms this binary is genuine and
    /// works on the machine you're on.
    Doctor,

    /// Change the vault's main passphrase (needs the current passphrase).
    Passwd {
        /// Path to the vault file (or its mount dir). Defaults to vault.fob
        /// in the current directory or next to this binary.
        device: Option<PathBuf>,
    },

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
            Some(Commands::Wipe { device }) => cmd_wipe(device.or(self.device)),
            Some(Commands::Verify { device }) => cmd_verify(device.or(self.device)),
            Some(Commands::Doctor) => cmd_doctor(),
            Some(Commands::Passwd { device }) => cmd_passwd(device.or(self.device)),
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
    ship_usb_tool(&mount)?;
    fetch_other_platform_binaries(&mount);
    println!("  Open index.html (or vault.fob) on the USB to use Fob.");
    println!("  Terminal tool on any machine (no install needed):");
    println!("    macOS/Linux: cd into the USB and run  ./fob.sh");
    println!("    Windows:     open the USB and run  fob.cmd");
    println!("    (commands: wipe · status · verify · passwd · recover · check)");
    Ok(())
}

/// Ship the on-USB tool: a copy of this `fob` binary (so the whole CLI —
/// wipe/status/verify/doctor/passwd/recover/... — works even with no
/// network, on this machine's OS family), plus BOTH cross-platform
/// launchers (`fob.sh` for macOS/Linux and `fob.cmd` for Windows) so a
/// drive provisioned anywhere works everywhere.
fn ship_usb_tool(mount: &std::path::Path) -> Result<()> {
    let exe = std::env::current_exe()?;
    match current_platform_key() {
        Some(key) => {
            let dest = mount.join(platform_bin_name(key));
            std::fs::copy(&exe, &dest)?;
            make_executable(&dest)?;
            println!(
                "  ✓ Copied fob binary for this machine → {}",
                dest.file_name().unwrap_or_default().to_string_lossy()
            );
        }
        None => {
            println!("  ⚠  This platform isn't one we ship binaries for; only the launchers will be written.");
        }
    }
    let sh = mount.join("fob.sh");
    atomic_write(&sh, USB_TOOL_LAUNCHER.as_bytes())?;
    make_executable(&sh)?;
    let cmd = mount.join("fob.cmd");
    atomic_write(&cmd, WINDOWS_LAUNCHER.as_bytes())?;
    println!("  ✓ Wrote fob.sh and fob.cmd launchers");
    Ok(())
}

#[cfg(unix)]
fn make_executable(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(perms.mode() | 0o111);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &std::path::Path) -> Result<()> {
    Ok(()) // executability on Windows is conveyed by the .exe extension.
}

/// Platform key for the running OS/arch, or None if it's not one we ship.
fn current_platform_key() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => Some("windows-x86_64"),
        ("macos", "aarch64") => Some("darwin-arm64"),
        ("macos", "x86_64") => Some("darwin-x86_64"),
        ("linux", "x86_64") => Some("linux-x86_64"),
        ("linux", "aarch64") => Some("linux-aarch64"),
        ("linux", "arm") => Some("linux-armv7"),
        _ => None,
    }
}

/// Filename for a platform's on-USB binary (Windows executables carry `.exe`).
fn platform_bin_name(platform_key: &str) -> String {
    if platform_key.starts_with("windows-") {
        format!("fob-{platform_key}.exe")
    } else {
        format!("fob-{platform_key}")
    }
}

/// Best-effort: download the prebuilt `fob` binaries for the other platforms
/// from the latest GitHub release, so the USB's duress wipe works on any
/// macOS/Linux machine. Skips the current platform (already shipped) and
/// continues on any failure — a single-platform USB still works offline.
fn fetch_other_platform_binaries(mount: &std::path::Path) {
    let tag = match latest_release_tag() {
        Some(t) => t,
        None => {
            println!("  ⚠  Could not reach GitHub — only this machine's platform was shipped (offline wipe still works).");
            return;
        }
    };
    let host_key = current_platform_key();
    let mut fetched = 0usize;
    for (key, triple) in PLATFORM_RELEASE_TRIPLES {
        if Some(*key) == host_key {
            continue;
        }
        let dest = mount.join(platform_bin_name(key));
        if dest.exists() {
            continue; // already on the USB
        }
        let url = format!(
            "https://github.com/Arcel-Org/Fob/releases/download/{tag}/fob-{tag}-{triple}.tar.gz"
        );
        match download_and_extract(&url, &dest) {
            Ok(true) => {
                fetched += 1;
                println!(
                    "  ✓ Fetched {key} → {}",
                    dest.file_name().unwrap_or_default().to_string_lossy()
                );
            }
            Ok(false) => println!("  ⚠  No release artifact for {key} (tag {tag}) — skipping."),
            Err(e) => println!("  ⚠  Could not fetch {key}: {e} — skipping."),
        }
    }
    if fetched == 0 {
        println!("  (Other platform binaries not fetched — wipe works on this machine, and via the browser anywhere.)");
    }
}

/// Fetch the latest release tag_name from the GitHub API via the system curl
/// (same mechanism `fob update` uses). Returns None if unreachable.
fn latest_release_tag() -> Option<String> {
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
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let body = String::from_utf8_lossy(&out.stdout);
    body.lines()
        .find(|l| l.contains("\"tag_name\""))
        .and_then(|l| l.split('"').nth(3))
        .map(str::to_owned)
}

/// Download `url` (a release tarball containing a single `fob` binary) and
/// write the binary to `dest`. Returns Ok(false) when the asset 404s (no
/// artifact for that platform yet), Ok(true) on success, Err on other issues.
fn download_and_extract(url: &str, dest: &std::path::Path) -> Result<bool> {
    let tmpdir = std::env::temp_dir().join(format!("fob-install-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir)?;
    let tarball = tmpdir.join("fob.tar.gz");

    let dl = std::process::Command::new("curl")
        .args(["-fsSL", "--max-time", "60", "-o"])
        .arg(&tarball)
        .arg(url)
        .output()?;
    if !dl.status.success() {
        // Missing asset (404) and network errors both just mean "skip".
        let _ = std::fs::remove_dir_all(&tmpdir);
        return Ok(false);
    }

    let tx = std::process::Command::new("tar")
        .args(["xzf"])
        .arg(&tarball)
        .current_dir(&tmpdir)
        .output()?;
    if !tx.status.success() {
        let _ = std::fs::remove_dir_all(&tmpdir);
        return Err(anyhow::anyhow!("tar extraction failed"));
    }

    let extracted = if tmpdir.join("fob").exists() {
        tmpdir.join("fob")
    } else if tmpdir.join("fob.exe").exists() {
        tmpdir.join("fob.exe")
    } else {
        let _ = std::fs::remove_dir_all(&tmpdir);
        return Err(anyhow::anyhow!(
            "release tarball had no `fob`/`fob.exe` binary"
        ));
    };
    std::fs::copy(&extracted, dest)?;
    make_executable(dest)?;
    let _ = std::fs::remove_dir_all(&tmpdir);
    Ok(true)
}

/// `fob wipe` — physically destroy vault.fob using the duress passphrase,
/// from a terminal, without the browser. Works even on machines that never
/// had fob installed, because `fob install` ships this binary and a launcher
/// onto the USB.
///
/// Output is deliberately indistinguishable from a wrong passphrase whether
/// or not the wipe actually happened, so an observer can't tell a duress
/// passphrase from a mistake — mirroring the browser vault's behaviour.
fn cmd_wipe(device: Option<PathBuf>) -> Result<()> {
    use zeroize::Zeroize;

    let vault_path = resolve_vault_path(device)?;
    let vault_bytes = std::fs::read(&vault_path)
        .map_err(|e| anyhow::anyhow!("couldn't read {}: {e}", vault_path.display()))?;

    let mut pass = read_secret("Enter passphrase: ")?;
    let mut pass_bytes = pass.as_bytes().to_vec();
    pass.zeroize();
    drop(pass);

    let result =
        fob_core::vault::unlock_vault_with_duress_wipe(&vault_bytes, &pass_bytes, &vault_path);

    pass_bytes.zeroize();
    let mut vb = vault_bytes;
    vb.zeroize();

    match result {
        // Duress slot matched → the file was already wiped. Wrong passphrase
        // or real passphrase → nothing was wiped. All report the same thing.
        Err(fob_core::Error::Decrypt) | Ok(_) => {
            println!("Incorrect passphrase.");
        }
        Err(e) => return Err(anyhow::anyhow!("unlock failed: {e}")),
    }
    Ok(())
}

/// `fob verify` — check a vault.fob is structurally intact and print its
/// non-secret metadata (format, KDF, recovery flag), without needing the
/// passphrase. Useful on a machine you don't trust fully: "is this stick's
/// vault intact / which crypto profile is it using?"
fn cmd_verify(device: Option<PathBuf>) -> Result<()> {
    let vault_path = resolve_vault_path(device)?;
    let data = std::fs::read(&vault_path)
        .map_err(|e| anyhow::anyhow!("couldn't read {}: {e}", vault_path.display()))?;

    let vf = fob_core::vault::VaultFile::from_bytes(data)
        .map_err(|e| anyhow::anyhow!("not a valid Fob vault: {e}"))?;
    let h = &vf.header;
    let kdf = match h.kdf_algorithm {
        fob_core::format::KdfAlgorithm::Argon2id => format!(
            "Argon2id — {} MiB / {} passes / {} lanes",
            h.argon2_memory_kib / 1024,
            h.kdf_time_cost,
            h.argon2_parallelism
        ),
        fob_core::format::KdfAlgorithm::Pbkdf2Sha256 => {
            format!("PBKDF2-SHA256 — {} iterations", h.kdf_time_cost)
        }
    };
    println!("✓ valid Fob vault: {}", vault_path.display());
    println!("  format v{}", h.format_version);
    println!("  KDF: {kdf}");
    println!(
        "  recovery key: {}",
        if h.recovery_enabled {
            "enabled"
        } else {
            "not set"
        }
    );
    println!("  size: {} KiB", vf.data.len() / 1024);
    println!(
        "  fingerprint: {}",
        fob_core::vault::vault_fingerprint(&h.salt)
    );
    Ok(())
}

/// `fob doctor` — built-in crypto self-test. Exercises the real vault path
/// (KDF + AEAD init/unlock roundtrip) and the post-quantum recovery path
/// (X25519 + ML-KEM wrap/unwrap roundtrip) plus the passphrase policy,
/// then prints version/build info. On an untrusted machine this confirms
/// the on-USB binary is genuine and the crypto works before you trust it
/// with your vault.
fn cmd_doctor() -> Result<()> {
    use zeroize::Zeroize;

    println!("Fob doctor — v{}", env!("CARGO_PKG_VERSION"));
    if let Ok(exe) = std::env::current_exe() {
        println!("  binary: {}", exe.display());
    }

    // 1) Vault roundtrip: init a tiny vault, unlock it with the same pass.
    let main = "doctor-self-test-main-passphrase";
    let mut params = fob_core::vault::VaultInitParams::new(
        main.as_bytes().to_vec(),
        fob_core::format::MIN_VAULT_SIZE + 1024,
    );
    params.kdf_params = fob_core::vault::KdfParams::pbkdf2(10_000);
    let vault = fob_core::vault::init_vault(params)?;
    match fob_core::vault::unlock_vault(&vault, main.as_bytes()) {
        Ok((fob_core::vault::SlotKind::Main, blob)) => {
            drop(blob);
            println!("  ✓ vault roundtrip (KDF + AEAD)");
        }
        Ok((_, blob)) => {
            drop(blob);
            anyhow::bail!("vault roundtrip opened the wrong slot");
        }
        Err(e) => anyhow::bail!("vault roundtrip failed: {e}"),
    }
    let mut vault = vault;
    vault.zeroize();

    // 2) Recovery roundtrip: hybrid X25519 + ML-KEM 1024 wrap/unwrap.
    let (pubkey, privkey) = fob_core::recovery::generate_recovery_keypair();
    let secret = *b"0123456789abcdef0123456789abcdef"; // 32 bytes
    let aad = b"doctor-self-test-aad";
    let wrapped = fob_core::recovery::wrap_secret_for_recovery(&secret, &pubkey, aad)?;
    let unwrapped = fob_core::recovery::unwrap_secret_with_recovery(&wrapped, &privkey, aad)?;
    drop(pubkey); // privkey's X25519/ML-KEM secrets self-zeroize on drop.
    if unwrapped != secret {
        anyhow::bail!("recovery roundtrip mismatch");
    }
    println!("  ✓ recovery roundtrip (X25519 + ML-KEM 1024)");

    // 3) Passphrase policy sanity.
    if fob_core::passphrase::rejection_reason("weak").is_none() {
        anyhow::bail!("passphrase policy accepted a known-weak passphrase");
    }
    if fob_core::passphrase::rejection_reason(main).is_some() {
        anyhow::bail!("passphrase policy rejected the self-test passphrase");
    }
    println!("  ✓ passphrase policy");

    println!("✓ all crypto self-tests passed — this binary is genuine and works here.");
    Ok(())
}

/// `fob passwd` — change the vault's main passphrase from a terminal
/// (the browser has no recovery path, and previously the CLI could only do
/// it via `recover` with a recovery key). Re-encrypts the Main slot in
/// place under keys derived from the new passphrase; decoy/duress/recovery
/// slots are untouched.
fn cmd_passwd(device: Option<PathBuf>) -> Result<()> {
    use zeroize::Zeroize;

    let vault_path = resolve_vault_path(device)?;
    let vault_bytes = std::fs::read(&vault_path)
        .map_err(|e| anyhow::anyhow!("couldn't read {}: {e}", vault_path.display()))?;

    let mut current = read_secret("Current passphrase: ")?;
    let cur_bytes = current.as_bytes().to_vec();
    current.zeroize();
    drop(current);

    let unlock = fob_core::vault::unlock_vault(&vault_bytes, &cur_bytes);
    let mut cb = cur_bytes;
    cb.zeroize();

    let (slot, blob) = match unlock {
        Ok(pair) => pair,
        Err(_) => {
            let mut vb = vault_bytes;
            vb.zeroize();
            println!("Incorrect passphrase.");
            return Ok(());
        }
    };
    match slot {
        fob_core::vault::SlotKind::Main => {}
        _ => {
            println!(
                "That passphrase opens the decoy slot, not the main one — use the main passphrase."
            );
            return Ok(());
        }
    }

    let mut new_pass = read_new_passphrase()?;
    let mut vault_file = fob_core::vault::VaultFile::from_bytes(vault_bytes)?;
    let kdf_out = fob_core::kdf::derive_master(new_pass.as_bytes(), &vault_file.header)?;
    let slot_keys = fob_core::kdf::derive_all_slot_keys(kdf_out.master_secret());
    vault_file.write_slot(
        fob_core::vault::SlotKind::Main,
        slot_keys[fob_core::vault::SlotKind::Main.index()].bytes(),
        &blob,
    )?;
    atomic_write(&vault_path, &vault_file.data)?;

    // kdf_out and slot_keys are LockedSecret and self-zeroize on drop.
    drop(kdf_out);
    new_pass.zeroize();

    println!("Main passphrase changed. The vault now unlocks with the new passphrase.");
    Ok(())
}

/// Resolve the vault file for `fob wipe`: an explicit path is used as-is (a
/// directory means `vault.fob` inside it); with no argument, look for
/// `vault.fob` in the current directory, then next to this executable (which
/// covers running the on-USB binary from anywhere).
fn resolve_vault_path(device: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = device {
        return Ok(if p.is_dir() { p.join("vault.fob") } else { p });
    }
    let here = std::env::current_dir()?.join("vault.fob");
    if here.exists() {
        return Ok(here);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join("vault.fob");
            if sibling.exists() {
                return Ok(sibling);
            }
        }
    }
    Ok(here)
}

/// Read a line from stdin with terminal echo disabled (so a duress
/// passphrase can't be shoulder-surfed). Works on macOS, Linux and Windows
/// (rpassword uses the Console API on Windows, termios elsewhere) when stdin
/// is a real terminal; falls back to a plain read when stdin is piped (e.g.
/// automation), where there's nothing to echo anyway.
fn read_secret(prompt: &str) -> Result<String> {
    use std::io::IsTerminal;

    print!("{prompt}");
    std::io::stdout().flush()?;
    let line = if std::io::stdin().is_terminal() {
        rpassword::read_password()?
    } else {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        s
    };
    println!();
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
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
        let mut p1 = read_secret("Enter a new main passphrase (14+ chars, mixed): ")?;

        if let Some(reason) = fob_core::passphrase::rejection_reason(&p1) {
            println!("Passphrase {reason}.");
            p1.zeroize();
            continue;
        }

        let p2 = read_secret("Confirm passphrase: ")?;

        if p1 == p2 {
            return Ok(p1);
        }
        println!("Passphrases do not match.");
        p1.zeroize();
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

    let latest = match latest_release_tag() {
        Some(tag) => tag,
        None => {
            println!("could not reach GitHub. Check your connection.");
            return Ok(());
        }
    };

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
