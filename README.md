<div align="center">

# Fob

**Your secrets, on your keychain.**

An encrypted vault that lives on a USB drive — passwords, TOTP codes, SSH keys, and secure notes, protected by Argon2id and AES-256-GCM. Nothing installed on your computer; the vault opens entirely in your browser.

[![CI](https://github.com/Arcel-Org/Fob/actions/workflows/ci.yml/badge.svg)](https://github.com/Arcel-Org/Fob/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88+-orange.svg)](#building-from-source)
[![GitHub Pages](https://img.shields.io/badge/web-fob.site-blue.svg)](https://arcel-org.github.io/Fob/)

</div>

Fob turns any USB stick into a cryptographic security key. Plug it in, open `index.html`, and unlock with a passphrase — your credentials are available as a password manager, TOTP generator, and SSH key store. Unplug and everything locks. The browser vault runs the exact same Rust crypto as the CLI (compiled to WASM and embedded in the single HTML file), so a vault created on the command line opens in the browser and vice versa.

<div align="center">

![The Fob browser vault, locked](docs/screenshots/vault-lock.png)

*The vault lives on the USB drive — open `index.html`, enter your passphrase.*

</div>

---

## Screenshots

<div align="center">

| | |
|---|---|
| ![Unlocked vault](docs/screenshots/vault-main.png) | ![Landing page](docs/screenshots/site-landing.png) |
| *The unlocked vault — passwords, TOTP codes, SSH keys, notes* | *The Fob landing page (arcel-org.github.io/Fob)* |

</div>

---

## What's in the vault

- **Passwords** — store, generate (with strength meter), and auto-copy credentials
- **TOTP** — built-in two-factor code generation with live countdown; add by secret or by pasting an `otpauth://` setup URI
- **SSH keys** — import Ed25519/RSA/ECDSA keys; unlocked keys are exposed via a local SSH agent socket, compatible with any SSH client (spawned automatically by the CLI — passphrase-protected keys must have that passphrase stripped first, e.g. `ssh-keygen -p -N ""`)
- **Secure notes** — encrypted free-text entries
- **Plausible deniability** — decoy vault slot with realistic fake data; duress slot that destroys the vault silently
- **Browser vault** — a single self-contained HTML file that runs entirely offline, using the exact same encrypted vault format as the CLI — either can create, open, or update a vault the other made
- **Passphrase policy** — length, entropy and blocklist checks, enforced identically in the browser and CLI from shared Rust code; optional **max-security Argon2id** profile (128 MiB / 4 passes / 8 lanes)

---

## Security

### Cryptographic primitives

There is **one crypto implementation** — `fob-core` (Rust) — used everywhere.
The browser vault doesn't hand-write WebCrypto; it embeds `fob-core` compiled
to `wasm32-unknown-unknown` (via the `fob-wasm` crate) as a single
self-contained HTML file, so the CLI, agent, and browser all run identical
code. Every vault is format v4 with Argon2id by default, plus an optional
hybrid post-quantum recovery key. v3 (PBKDF2) vaults written by older versions
remain readable.

| Component | Algorithm |
|---|---|
| Key derivation | Argon2id (default) — 64 MiB / 3 passes / 4 lanes. PBKDF2-HMAC-SHA256 — 310,000 iterations (v3, legacy) |
| Encryption | AES-256-GCM |
| Key separation | HKDF-SHA256, per vault slot |
| Post-quantum | Optional recovery key — hybrid X25519 + ML-KEM-1024 (FIPS 203), wraps the master secret to an offline keypair generated at vault creation |
| TOTP | RFC 6238 — HMAC-SHA1/SHA256/SHA512 |

Lost your passphrase? If you generated a recovery key during setup, run
`fob recover` and paste it in — it resets the main passphrase without
needing the old one. There's no other recovery path; without a recovery key,
a lost main passphrase means the Main slot's contents are gone for good.

### Threat model

| Threat | Mitigation |
|---|---|
| USB stolen | v4 vaults use Argon2id (memory-hard), raising GPU/ASIC brute-force cost substantially over PBKDF2; v3 vaults (PBKDF2 at 310k iterations) remain weaker against GPU/ASIC attackers — choose a long passphrase either way |
| Coercion | Decoy vault slot opens with its own independent, realistic-looking data |
| Extreme coercion | Duress passphrase returns the same error as a wrong passphrase and wipes the local copy (logical wipe only — see [Known limitations](#known-limitations)) |
| Quantum adversary | The passphrase-unlock path (PBKDF2/Argon2id → AES-256-GCM) was never asymmetric and already keeps ~128-bit security under Grover's algorithm — nothing to mitigate there. The optional recovery key is the vault's only asymmetric component and is post-quantum hybrid (X25519 + ML-KEM-1024) from day one |
| Clipboard exfil | Auto-clears 30 seconds after any copy |
| Memory dumps | Sensitive buffers zeroized and mlocked where possible |

### Architecture

All cryptographic operations live in `fob-core`, which has no filesystem or network access. The CLI and browser vault cannot leak key material because they never handle raw secrets — passphrases are passed directly to the crypto layer and zeroized immediately after use.

### Known limitations

- **RSA SSH keys are stored but not signed.** The `rsa` crate used by our SSH library carries [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) (a timing side-channel), with no fixed version available upstream. RSA key *entries* can still be stored and viewed in the vault, but the SSH agent won't load them for signing. Use Ed25519 (the default for new keys) instead.
- **Imported SSH keys must not be passphrase-protected** — the vault passphrase is already the protection layer; strip a key's own passphrase before importing it (`ssh-keygen -p -N ""`).
- **The duress wipe overwrites the vault file's logical content, not necessarily its physical storage.** On a copy-on-write filesystem (e.g. macOS APFS) or an SSD doing wear-leveling internally, an in-place overwrite can leave the pre-wipe bytes recoverable from other physical blocks via forensic tools, filesystem snapshots, or drive firmware — the OS-level guarantee "this file's contents are now random bytes" does not extend to "the old bytes are physically gone." If your threat model includes forensic recovery of the underlying storage medium, don't rely on the duress wipe alone; treat it as closing off the easy/logical recovery path, not a physical-media guarantee.
- **The browser vault can only wipe the actual `vault.fob` file if it was opened via the native file picker in a Chromium browser** (Chrome, Edge, Opera — anything supporting the File System Access API). Opening the vault by drag-and-drop, via a plain `<input type=file>` fallback, or via the automatic same-directory load on a `file://` page gives the page no writable handle to the original file at all — browsers don't allow arbitrary local file writes without one. In those cases (and always in Firefox/Safari, which don't implement the File System Access API), a duress passphrase still clears the browser's own IndexedDB cache, but the `vault.fob` file on the USB drive itself is left completely untouched. If you rely on the duress feature, use the CLI (`fob`), which always wipes the real file, or confirm you opened the browser vault through its file picker (not drag-and-drop) in a supported browser.
- **The vault file is trivially identifiable as a Fob vault, even without the passphrase.** The first 4 bytes of `vault.fob` are the literal ASCII magic `FOB2` — anyone with the file (a `file`/`xxd`/`head` away) can immediately confirm "this is a Fob password vault," before ever touching a passphrase. The decoy/duress design protects *which passphrase unlocks which content* once someone is already trying to open the vault; it does not hide that the file is a vault at all — the filename (`vault.fob`) gives that away too. If your threat model requires the file itself to be unidentifiable (e.g. deniability that you even use a password manager), rename it to something innocuous and be aware the magic bytes still identify it to anyone who inspects the content directly, not just the name.
- **Actively-edited secret fields (the master passphrase, a password, a note body, an SSH private key) aren't guaranteed zeroized in every intermediate state while you're typing.** The CLI zeroizes each field's *final* value when its form is dropped, but Rust's `String` can reallocate internally as you type (e.g. via `push`/`insert`) — each old backing buffer is freed by the allocator without being zeroed first, so fragments of an in-progress passphrase can in principle linger in freed-but-unoverwritten heap memory until something else reuses that allocation. This only matters against an adversary who can already read the process's memory (a debugger, a core dump, a swapped-out page) — a much higher bar than a passing observer — but it means the README's "sensitive buffers zeroized" claim is exact for data at rest and for a field's value once you stop editing it, not for every transient buffer touched while you were actively typing it.

---

## Installation

```sh
curl -fsSL https://raw.githubusercontent.com/Arcel-Org/Fob/main/install/install.sh | sh
```

Installs `fob` and `fob-agent` to `~/.fob/bin` and adds that to your PATH.
Every downloaded release is verified against its published SHA256 checksum
before anything is installed, and against its [cosign](https://docs.sigstore.dev/)
signature too if `cosign` is on your PATH.

Useful flags (pass them after `| sh -s --`, e.g. `... | sh -s -- --no-path`):

| Flag | Effect |
|---|---|
| `--version=vX.Y.Z` | install a specific release instead of latest |
| `--no-path` | don't modify your shell rc file |
| `--local=/path/to/fob` | install from a local build instead of downloading |
| `--uninstall` | remove Fob's installed binaries |
| `--help` | show all flags |

No release built yet, or want to build it yourself? See below.

---

## Building from source

Requires Rust 1.88+.

```sh
git clone https://github.com/Arcel-Org/Fob.git
cd Fob
cargo build --release -p fob-cli -p fob-agent
```

The binaries land at `target/release/fob` and `target/release/fob-agent` — both are required (the CLI spawns the agent as a sibling process for SSH agent support).

---

## Testing

```sh
cargo test --workspace                                    # crypto/vault + CLI tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

python3 web/tests/browser_interaction_test.py              # headless-chromium checks for web/index.html
```

The browser-vault check drives a real headless Chromium instance (requires
`chromium` and Python's `websockets` package) through the actual UI — search
filtering, the TOTP countdown, auto-lock on inactivity, v4 round-tripping,
the max-security profile, otpauth:// URI import, passphrase policy, and
entry-list rendering/scrolling with many entries.

Automated tests cover the logic and rendering paths; they are not a
substitute for a real person using the app. See `USABILITY_TESTING.md` for a
first-time-user test script covering both interfaces.

---

## Repository layout

```
fob/
├── crates/
│   ├── fob-core/       # cryptography and vault format — no I/O, pure logic
│   ├── fob-wasm/       # browser bindings for fob-core (compiled to wasm32)
│   ├── fob-cli/        # install/format/status/recover — USB provisioning only
│   ├── fob-host/       # host-OS integration for the CLI
│   └── fob-agent/      # SSH agent daemon
├── install/
│   └── install.sh      # one-line installer
├── site/               # GitHub Pages front door: landing page + header inspector
│                       # (public metadata only, never decrypts)
├── web/
│   ├── index.template.html # browser vault source (WASM crypto inlined at build)
│   ├── index.html          # generated self-contained browser vault (shipped to USB)
│   ├── build_wasm.sh       # compile fob-wasm → inline into index.html / inspector
│   └── tests/              # headless-chromium interaction checks for index.html
└── docs/screenshots/   # README screenshots (captured from the real UI)
```

The `fob` command is intentionally small: it only installs/updates and does
low-level USB operations (`fob status`, `fob format`, `fob install`, `fob
recover`, `fob update`). Day-to-day use happens entirely in the browser vault
on the USB.

---

## Contributing

Issues and pull requests welcome. For security vulnerabilities, please open a [private advisory](https://github.com/Arcel-Org/Fob/security/advisories/new) rather than a public issue.

---

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE) at your option.
