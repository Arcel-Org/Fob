# Changelog

Fob is pre-1.0 (`0.1.x`) and under active development: breaking changes may
land between releases. This file records what changed in each release.

## [Unreleased]

### Added

- **Vault sections: Files, Cards, Recovery Codes** — three new encrypted
  categories alongside passwords/TOTP/SSH/notes:
  - **Files** — store small sensitive attachments inside the vault (capped
    at ~1 MiB each, because vault slots are a few MiB total) and download
    them back on demand.
  - **Cards** — payment-card storage with masked number/CVV, holder and
    expiry; number and CVV are revealed/copied individually like passwords.
  - **Recovery Codes** — per-account backup codes, one per line, with
    per-code reveal and copy.
  - All three live in the same encrypted `vault.fob`, are byte-compatible
    with the CLI's format (`fob-core`), and survive lock/unlock round-trips.
- **"Connect USB" auto-save** — replacing the old "Export to USB" chore:
  pair a `vault.fob` once via Chromium's file picker and every change after
  that writes straight back to that file automatically (the writable handle
  is remembered across visits). The download fallback stays for browsers
  without the File System Access API. An "Auto-save on" badge shows in the
  top bar when a vault is connected.
- **Add button moved to the top of the sidebar**, above the Vault section,
  so it's always one click away regardless of the active view.

## [0.1.0] - 2026-09-02

Initial release of the browser-first Fob platform.

### Added

- **Browser vault** — a single self-contained `index.html` that opens
  entirely offline from `file://`. Runs `fob-core`'s Rust crypto compiled to
  WASM (via `fob-wasm`) and embedded in the file; no hand-written WebCrypto.
  - Passwords (store, generate with strength meter, auto-copy to clipboard,
    clipboard auto-clears after 30s).
  - TOTP codes (RFC 6238, HMAC-SHA1/SHA256/SHA512) with live countdown;
    add by secret or by pasting an `otpauth://` setup URI.
  - SSH keys (Ed25519/RSA/ECDSA) with fingerprints; stored and managed in the
    vault, not exposed to a local SSH agent.
  - Secure notes.
  - Plausible deniability: decoy vault slot (realistic fake data) and a
    duress slot that silently destroys the vault.
  - Auto-lock on inactivity; unplug-and-lock model.
- **Vault format v4** — Argon2id key derivation (default 64 MiB / 3 passes /
  4 lanes; optional max-security profile 128 MiB / 4 passes / 8 lanes),
  AES-256-GCM encryption, HKDF-SHA256 per-slot key separation, and an
  optional hybrid post-quantum recovery key (X25519 + ML-KEM-1024, FIPS 203).
  v3 (PBKDF2) vaults from older versions remain readable.
- **`fob` CLI** — intentionally small: `fob install`, `fob format`
  (incl. `--max-security`), `fob status`, `fob recover`, `fob update`.
  No unlock command; day-to-day use happens in the browser.
- **`fob install`** — writes the embedded browser vault to a USB drive.
- **One-line installer** (`install/install.sh`) — downloads a pinned release
  binary and verifies SHA256 + cosign signature.
- **GitHub Pages front door** (`site/`) — landing page with install command,
  live version badge, and a **header inspector** that reads public vault
  metadata (format, KDF params, recovery status) without ever decrypting.
- **Shared passphrase policy** — length (≥ 14), entropy (≥ 60 bits), diversity
  and blocklist checks enforced identically in the browser and CLI from the
  same Rust code.
- **Testing** — 100+ Rust unit/integration tests, headless-chromium
  interaction checks for the browser vault (including a full
  create → export → reopen → update USB lifecycle), fuzz harness, and
  hardware/usability testing guides.

### Removed

- Native desktop app (`fob-app`) — redundant with the browser vault.
- SSH agent daemon (`fob-agent`) and the `ssh_agent` host module — dead under
  the browser-first model (a browser cannot spawn a background agent).
- `rsa`, `tokio`, `ssh-key`, `signature`, `directories`, `tauri` dependency
  tree — not needed by the final architecture. The lockfile now has no
  outstanding advisories (0 vulnerabilities / 0 warnings, no ignores).

### Security

- One crypto implementation (`fob-core`) used by both the CLI and the
  browser — no divergent browser crypto to drift.
- Hybrid post-quantum recovery key: secret wrapped under both classical
  X25519 and ML-KEM-1024.
- Zeroize + memory locking on secret material; strict CSPs (incl.
  `wasm-unsafe-eval` for the embedded WASM); clipboard auto-clear.
- Recovery path is the only way to reset a lost main passphrase.

### Fixed

- Header inspector reported a confusing "Not a valid Fob vault: undefined"
  error — wasm-bindgen throws a plain string; the handler now reads it
  correctly.
- README falsely claimed the CLI always wipes the real file on duress (the
  CLI has no unlock/wipe command) — rewritten to describe the true path.

<!-- Versions -->
[0.1.0]: https://github.com/Arcel-Org/Fob/releases/tag/v0.1.0
