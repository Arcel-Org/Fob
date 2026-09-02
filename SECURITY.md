# Security Policy

Fob is a security-focused project. We take vulnerabilities seriously and appreciate responsible disclosure.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not open public issues for security vulnerabilities.**

Instead, report them privately via GitHub Security Advisories:

1. Go to [Security Advisories](https://github.com/Arcel-Org/Fob/security/advisories/new)
2. Click "New draft security advisory"
3. Fill in the details and submit

We will respond within 72 hours and work with you to verify, fix, and disclose the issue responsibly.

## What to Include

- A clear description of the vulnerability
- Steps to reproduce (proof-of-concept if possible)
- Impact assessment (what data or operations are at risk)
- Suggested fix or mitigation (if you have one)

## Scope

We consider vulnerabilities in the following in-scope:

- Cryptographic implementation errors (KDF, AEAD, key derivation)
- Memory safety issues (use-after-free, buffer overflows, information leaks)
- Vault format parsing vulnerabilities
- TOTP implementation bugs
- Clipboard handling or auto-lock bypasses

Out of scope:

- Physical attacks on the USB device (intended threat model)
- Compromised host machines (keyloggers, screen capture)
- Social engineering or passphrase guessing
- Issues in third-party dependencies (report to upstream)

## Recognition

With your permission, we will credit you in the release notes and advisory once the fix is published.
