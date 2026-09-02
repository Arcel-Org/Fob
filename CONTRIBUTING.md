# Contributing to Fob

Thank you for your interest in contributing to Fob.

## Getting started

Requires Rust 1.88+.

```sh
git clone https://github.com/Arcel-Org/Fob
cd Fob
cargo test --workspace --all-targets
cargo clippy --all-targets -- -D warnings
```

## Guidelines

- Zero clippy warnings (`-D warnings`) required before merge — CI enforces this
- `cargo audit` must pass — if a flagged advisory is a genuine false positive (e.g. an optional dependency feature we don't enable), justify and ignore it in `.cargo/audit.toml`, don't just silence CI
- All cryptographic changes must include tests in `fob-core`
- `fob-core` must remain pure logic — no filesystem, no network, no I/O of any kind
- Changes to the vault format (`src/format.rs`) are breaking changes — discuss in an issue first
- The CLI, agent, and browser vault must not handle raw key material — passphrases go directly to `fob-core` and are zeroized immediately after use
- When bumping a crypto-adjacent dependency (`aes-gcm`, `hkdf`, `sha2`, `hmac`, `sha1`, `pbkdf2`, `ssh-key`, ...), the full `fob-core` test suite — including the RFC 6238 TOTP known-answer vectors and the vault init/unlock/decoy/duress round-trip tests — must still pass unchanged. Those tests are the regression net for "the API changed but the actual bytes coming out didn't"

## Architecture rule

```
fob-core  ← no I/O, pure crypto logic, fully testable
fob-cli   ← install/format/status/recover: USB device management, calls fob-core
fob-agent ← SSH agent daemon, calls fob-core
fob-wasm  ← browser bindings for fob-core, compiled to wasm32
```

Do not add I/O to `fob-core`. Do not add cryptographic logic to `fob-cli`.

## Security

For security vulnerabilities, open a [private advisory](https://github.com/Arcel-Org/Fob/security/advisories/new) — not a public issue. Do not disclose vulnerabilities publicly until a fix is available.

## License

Fob is licensed under MIT OR Apache-2.0. By contributing, you agree your contributions will be licensed under the same terms.
