#!/usr/bin/env sh
# Fob — installer
# ──────────────────────────────────────────────────────────────────────────────
# curl -fsSL https://raw.githubusercontent.com/Arcel-Org/Fob/main/install/install.sh | sh
#
# Downloads the fob + fob-agent binaries and verifies them. Falls back to
# building from source if no release is published yet.
#
# Flags:
#   --version=vX.Y.Z   install a specific release (default: latest)
#   --no-path          skip adding ~/.fob/bin to your shell rc
#   --local=/path      use a locally built binary instead of downloading
#   --uninstall        remove Fob's installed binaries
#   --help, -h         show this help
# ──────────────────────────────────────────────────────────────────────────────
set -eu

FOB_INSTALL_DIR="${HOME}/.fob/bin"
FOB_RELEASES_API="https://api.github.com/repos/Arcel-Org/Fob/releases/latest"
FOB_BASE_URL="https://github.com/Arcel-Org/Fob/releases/download"

VERSION=""
MODIFY_PATH=1
LOCAL_BIN=""
DO_UNINSTALL=0

usage() {
  cat <<'EOF'
Fob installer

Usage: install.sh [flags]

Flags:
  --version=vX.Y.Z   install a specific release (default: latest)
  --no-path          skip adding ~/.fob/bin to your shell rc
  --local=/path      use a locally built binary instead of downloading
                     (looks for a sibling fob-agent binary next to it)
  --uninstall        remove Fob's installed binaries from ~/.fob/bin
  --help, -h         show this help and exit

Downloaded releases are verified against the published SHA256SUMS before
anything is installed, and against the cosign signature bundle too if
`cosign` is available locally.
EOF
}

for arg in "$@"; do
  case "$arg" in
    --version=*)  VERSION="${arg#*=}" ;;
    --no-path)    MODIFY_PATH=0 ;;
    --uninstall)  DO_UNINSTALL=1 ;;
    --help|-h)    usage; exit 0 ;;
    --local=*)
      LOCAL_BIN="${arg#*=}"
      case "$LOCAL_BIN" in
        "~/"*) LOCAL_BIN="${HOME}/${LOCAL_BIN#~/}" ;;
      esac
      ;;
    *)            printf 'Unknown flag: %s\n\n' "$arg" >&2; usage >&2; exit 1 ;;
  esac
done

# ── helpers ───────────────────────────────────────────────────────────────────
die() { printf '\n  ERROR: %s\n\n' "$*" >&2; exit 1; }
say() { printf '  %s\n' "$*"; }
hr()  { printf '  ──────────────────────────────────────────\n'; }

# curl is load-bearing for every network path below (version lookup, download,
# checksums, cosign bundle) — check for it up front with a direct message,
# rather than letting a bare "command not found" surface later disguised as
# "no release found" (curl failing gets swallowed by `|| true` around the
# version-lookup pipeline further down). Mirrors the exact branching below:
# --local and "in-repo with no explicit --version" both skip the network
# entirely and never touch curl.
if [ "$DO_UNINSTALL" != "1" ] && [ -z "$LOCAL_BIN" ] \
   && ! { [ -f "Cargo.toml" ] && [ -z "$VERSION" ]; }; then
  command -v curl >/dev/null 2>&1 || die "curl is required but not installed. Install curl and retry."
fi

# ── uninstall ─────────────────────────────────────────────────────────────────
if [ "$DO_UNINSTALL" = "1" ]; then
  if [ ! -e "${FOB_INSTALL_DIR}/fob" ] && [ ! -e "${FOB_INSTALL_DIR}/fob-agent" ]; then
    say "Nothing installed at ${FOB_INSTALL_DIR} — nothing to do."
    exit 0
  fi
  rm -f "${FOB_INSTALL_DIR}/fob" "${FOB_INSTALL_DIR}/fob-agent"
  rmdir "${FOB_INSTALL_DIR}" 2>/dev/null || true
  say "Removed Fob from ${FOB_INSTALL_DIR}."
  say "Your vault(s) on USB drives are untouched — only the installed binaries were removed."
  say "If you added ${FOB_INSTALL_DIR} to PATH in your shell rc file, remove that line manually."
  exit 0
fi

# ── platform ──────────────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin)
    case "$ARCH" in
      x86_64) PLATFORM="x86_64-apple-darwin" ;;
      arm64)  PLATFORM="aarch64-apple-darwin" ;;
      *)      die "Unsupported architecture: $ARCH" ;;
    esac
    ;;
  Linux)
    case "$ARCH" in
      x86_64)  PLATFORM="x86_64-unknown-linux-musl" ;;
      aarch64) PLATFORM="aarch64-unknown-linux-gnu" ;;
      armv7l)  PLATFORM="armv7-unknown-linux-gnueabihf" ;;
      *)       die "Unsupported architecture: $ARCH" ;;
    esac
    ;;
  *)
    die "Unsupported OS: $OS. Fob supports macOS and Linux." ;;
esac

# ── banner ────────────────────────────────────────────────────────────────────
printf '\n'
hr
printf '  Fob — Encrypted USB Vault\n'
hr
printf '\n'

# ── version resolution ────────────────────────────────────────────────────────
if [ -n "$LOCAL_BIN" ]; then
  [ -x "$LOCAL_BIN" ] || die "Local binary not found or not executable: $LOCAL_BIN"
  say "Using local build: $LOCAL_BIN"
  VERSION="local"
elif [ -f "Cargo.toml" ] && [ -z "$VERSION" ]; then
  # Running from inside the repo — build from source directly.
  # Both binaries: fob-agent must sit next to fob for the SSH agent to work.
  if ! command -v cargo >/dev/null 2>&1; then
    die "cargo not found. Install Rust from https://rustup.rs and retry."
  fi
  say "Building from source..."
  cargo build --release -p fob-cli -p fob-agent 2>&1 | tail -3
  [ -f "target/release/fob" ] || die "Build failed."
  [ -f "target/release/fob-agent" ] || die "Build failed (fob-agent)."
  LOCAL_BIN="$(pwd)/target/release/fob"
  VERSION="local"
elif [ -z "$VERSION" ]; then
  say "Fetching latest release..."
  VERSION="$(curl -fsSL --max-time 10 "$FOB_RELEASES_API" \
    | grep '"tag_name"' \
    | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')" || true

  if [ -z "$VERSION" ]; then
    die "No release found and not in a source repo.
  Clone the repo and re-run:
    git clone https://github.com/Arcel-Org/Fob.git
    cd Fob && sh install/install.sh"
  fi
  say "Version: $VERSION"
fi

# ── checksum helper ───────────────────────────────────────────────────────────
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "Neither sha256sum nor shasum is available — cannot verify the download."
  fi
}

# ── download / copy binary ────────────────────────────────────────────────────
TMPDIR_WORK="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_WORK"' EXIT

if [ -n "$LOCAL_BIN" ]; then
  cp "$LOCAL_BIN" "${TMPDIR_WORK}/fob"
  # fob-agent must ship alongside fob — look for it next to the given binary.
  LOCAL_AGENT="$(dirname "$LOCAL_BIN")/fob-agent"
  if [ -x "$LOCAL_AGENT" ]; then
    cp "$LOCAL_AGENT" "${TMPDIR_WORK}/fob-agent"
  else
    say "WARNING: no fob-agent found next to $LOCAL_BIN — SSH agent support will be unavailable."
  fi
else
  ARTIFACT="fob-${VERSION}-${PLATFORM}.tar.gz"
  ARTIFACT_URL="${FOB_BASE_URL}/${VERSION}/${ARTIFACT}"
  ARTIFACT_FILE="${TMPDIR_WORK}/${ARTIFACT}"

  say "Downloading ${ARTIFACT}..."
  curl -fsSL --progress-bar --max-time 120 \
    -o "$ARTIFACT_FILE" "$ARTIFACT_URL" \
    || die "Download failed. Check your internet connection."

  say "Verifying checksum..."
  SUMS_FILE="${TMPDIR_WORK}/SHA256SUMS"
  curl -fsSL --max-time 30 -o "$SUMS_FILE" "${FOB_BASE_URL}/${VERSION}/SHA256SUMS" \
    || die "Could not download SHA256SUMS — refusing to install an unverified binary."
  EXPECTED_SUM="$(grep " ${ARTIFACT}\$" "$SUMS_FILE" | awk '{print $1}')"
  [ -n "$EXPECTED_SUM" ] || die "No checksum entry for ${ARTIFACT} in SHA256SUMS — refusing to install."
  ACTUAL_SUM="$(sha256_of "$ARTIFACT_FILE")"
  if [ "$EXPECTED_SUM" != "$ACTUAL_SUM" ]; then
    die "Checksum mismatch for ${ARTIFACT}!
  Expected: ${EXPECTED_SUM}
  Got:      ${ACTUAL_SUM}
  Refusing to install — the download may be corrupted or tampered with."
  fi
  say "Checksum OK."

  if command -v cosign >/dev/null 2>&1; then
    BUNDLE_FILE="${ARTIFACT_FILE}.bundle"
    if curl -fsSL --max-time 30 -o "$BUNDLE_FILE" "${ARTIFACT_URL}.bundle" 2>/dev/null; then
      say "Verifying cosign signature..."
      if cosign verify-blob \
          --bundle "$BUNDLE_FILE" \
          --certificate-identity-regexp "^https://github\.com/Arcel-Org/Fob/" \
          --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
          "$ARTIFACT_FILE" >/dev/null 2>&1; then
        say "Signature OK."
      else
        die "Cosign signature verification FAILED for ${ARTIFACT} — refusing to install."
      fi
    else
      say "No signature bundle found for this release — skipping cosign verification (checksum was still verified)."
    fi
  else
    say "cosign not installed — skipping signature verification (checksum was still verified)."
    say "Install cosign for full verification: https://docs.sigstore.dev/system_config/installation/"
  fi

  say "Extracting..."
  tar -xzf "$ARTIFACT_FILE" -C "$TMPDIR_WORK" \
    || die "Extraction failed."
fi

[ -f "${TMPDIR_WORK}/fob" ] || die "Binary not found."
chmod 755 "${TMPDIR_WORK}/fob"
[ -f "${TMPDIR_WORK}/fob-agent" ] && chmod 755 "${TMPDIR_WORK}/fob-agent"

# ── install ───────────────────────────────────────────────────────────────────
mkdir -p "$FOB_INSTALL_DIR"
cp "${TMPDIR_WORK}/fob" "${FOB_INSTALL_DIR}/fob"
chmod 755 "${FOB_INSTALL_DIR}/fob"
if [ -f "${TMPDIR_WORK}/fob-agent" ]; then
  cp "${TMPDIR_WORK}/fob-agent" "${FOB_INSTALL_DIR}/fob-agent"
  chmod 755 "${FOB_INSTALL_DIR}/fob-agent"
fi
say "Installed to: ${FOB_INSTALL_DIR}/fob"

# ── PATH setup ────────────────────────────────────────────────────────────────
if [ "$MODIFY_PATH" = "1" ]; then
  SHELL_NAME="$(basename "${SHELL:-sh}")"
  RC_FILE=""
  case "$SHELL_NAME" in
    bash) RC_FILE="${HOME}/.bashrc" ;;
    zsh)  RC_FILE="${HOME}/.zshrc" ;;
    fish) RC_FILE="${HOME}/.config/fish/config.fish" ;;
  esac

  if [ -n "$RC_FILE" ]; then
    if grep -qF "$FOB_INSTALL_DIR" "$RC_FILE" 2>/dev/null; then
      : # already there
    else
      if [ "$SHELL_NAME" = "fish" ]; then
        printf '\nfish_add_path %s\n' "$FOB_INSTALL_DIR" >> "$RC_FILE"
      else
        printf '\nexport PATH="$PATH:%s"\n' "$FOB_INSTALL_DIR" >> "$RC_FILE"
      fi
      say "Added to PATH in $RC_FILE"
    fi
  fi
fi

# ── next steps ────────────────────────────────────────────────────────────────
printf '\n'
hr
say "Fob installed."
hr
printf '\n'
say "The fob command only installs/updates and manages USB drives."
say "Day-to-day use happens in the browser vault on the USB itself."
printf '\n'
say "Quick start:"
say "  1. fob status              — list USB drives"
say "  2. fob format /dev/sdX     — format a USB stick and create a vault"
say "  3. Open index.html on the USB in a browser — that is the vault."
printf '\n'
say "See https://github.com/Arcel-Org/Fob for details."
if [ -t 0 ] && [ -t 1 ]; then
  say "Run 'fob status' (or '${FOB_INSTALL_DIR}/fob status' if not yet on PATH)."
else
  say "Run 'fob' (or '${FOB_INSTALL_DIR}/fob' if not yet on PATH)."
fi
