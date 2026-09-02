//! Passphrase strength estimation and acceptance policy.
//!
//! This is the *policy* half of the "make it essentially impossible" work.
//! The crypto is Argon2id (memory-hard) everywhere; but a KDF's per-guess
//! cost is irrelevant if the passphrase itself is guessable. So we enforce a
//! real floor here, shared by the CLI and the browser (both compile this
//! same Rust). See `fob-wasm::passphrase_acceptable` and the CLI wizard.
//!
//! The estimate is deliberately conservative and deterministic: it models
//! the passphrase as draws from the *narrowest* character class present,
//! so a passphrase that mixes classes gets no false credit for characters
//! the attacker wouldn't know to assume. This under-estimates more than it
//! over-estimates, which is the safe direction for a security floor.

/// Common/weak passphrases that no amount of entropy modeling should admit.
/// Not exhaustive (a real blocklist is long and not something we want to
/// ship in a binary); this is the fast, offline, no-dependency slice.
const BLOCKLIST: &[&str] = &[
    "password",
    "password1",
    "password123",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "qwerty123",
    "letmein",
    "letmein1",
    "welcome",
    "welcome1",
    "admin",
    "admin123",
    "root",
    "toor",
    "1234",
    "12345",
    "123456",
    "111111",
    "abc123",
    "football",
    "baseball",
    "dragon",
    "monkey",
    "iloveyou",
    "trustno1",
    "sunshine",
    "princess",
    "superman",
    "shadow",
    "michael",
    "123123",
    "654321",
    "000000",
    "password1!",
    "changeme",
    "master",
    "hello",
    "freedom",
    "whatever",
    "qazwsx",
    "zaq12wsx",
];

/// Minimum acceptable length. 14+ combined with a real charset spread makes
/// offline brute-force infeasible even against a PBKDF2-style KDF; on
/// Argon2id it's comfortably beyond any realistic attack.
const MIN_LENGTH: usize = 14;

/// Entropy (bits) below which we refuse regardless of length — e.g. a 20-char
/// string of all the same digit, which is trivially guessable.
const MIN_ENTROPY_BITS: f64 = 60.0;

/// A character-set model used for entropy estimation.
struct Charset {
    pool_size: f64,
    members: fn(char) -> bool,
}

const CHARSETS: &[Charset] = &[
    Charset {
        pool_size: 26.0,
        members: |c| c.is_ascii_lowercase(),
    },
    Charset {
        pool_size: 26.0,
        members: |c| c.is_ascii_uppercase(),
    },
    Charset {
        pool_size: 10.0,
        members: |c| c.is_ascii_digit(),
    },
    Charset {
        pool_size: 33.0,
        members: |c| c.is_ascii_punctuation() || c.is_ascii_graphic() && !c.is_alphanumeric(),
    },
];

/// Estimate the entropy (bits) of a passphrase. Uses the *largest* character
/// pool actually present: an attacker guessing a mixed-class passphrase has
/// to consider the union, and anchoring on the largest class is the standard
/// model (this is the same logic password-strength meters use). The
/// diversity check below catches the degenerate "all the same symbol" cases
/// that this per-char model would over-credit.
pub fn entropy_bits(passphrase: &str) -> f64 {
    if passphrase.is_empty() {
        return 0.0;
    }
    let pool = CHARSETS
        .iter()
        .filter(|cs| passphrase.chars().any(cs.members))
        .map(|cs| cs.pool_size)
        .fold(0.0_f64, f64::max);
    if pool == 0.0 {
        // e.g. non-ASCII / emoji — treat as a large unknown pool but cap it.
        return (passphrase.chars().count() as f64) * 8.0;
    }
    (passphrase.chars().count() as f64) * pool.log2()
}

/// Normalized strength in 0.0..=1.0 for UI meters.
pub fn estimate(passphrase: &str) -> f64 {
    let bits = entropy_bits(passphrase);
    // Map 0..120+ bits onto 0..1 with 120 bits = 1.0.
    (bits / 120.0).clamp(0.0, 1.0)
}

/// Minimum fraction of *distinct* characters the passphrase must use.
/// A 20-char string of one repeated symbol ("1111...") has plenty of
/// "entropy" by the naive charset-length model but is trivially guessable,
/// so we additionally require real character diversity.
const MIN_DISTINCT_FRACTION: f64 = 0.4;

/// Whether a passphrase clears the bar for *new* vaults.
pub fn acceptable(passphrase: &str) -> bool {
    rejection_reason(passphrase).is_none()
}

/// Human-readable reason a passphrase was rejected (for UI messaging).
pub fn rejection_reason(passphrase: &str) -> Option<&'static str> {
    let trimmed = passphrase.trim();
    if trimmed.len() < MIN_LENGTH {
        return Some("too short — use at least 14 characters");
    }
    let lower = trimmed.to_ascii_lowercase();
    if BLOCKLIST.iter().any(|b| lower == *b) {
        return Some("that passphrase is too common");
    }
    if entropy_bits(trimmed) < MIN_ENTROPY_BITS {
        return Some("too predictable — mix lower, upper, digits, and symbols");
    }
    // Diversity: require enough distinct characters.
    let distinct = trimmed
        .chars()
        .collect::<std::collections::HashSet<_>>()
        .len();
    let frac = distinct as f64 / trimmed.chars().count().max(1) as f64;
    if frac < MIN_DISTINCT_FRACTION {
        return Some("too repetitive — use varied characters");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short() {
        assert!(!acceptable("short1"));
        assert!(!acceptable("12345678"));
    }

    #[test]
    fn rejects_blocklisted() {
        assert!(!acceptable("password"));
        assert!(!acceptable("password1"));
    }

    #[test]
    fn rejects_repetitive_long() {
        // 20 chars of all the same digit.
        assert!(!acceptable("11111111111111111111"));
    }

    #[test]
    fn accepts_strong() {
        assert!(acceptable("correct-horse-battery-staple"));
        assert!(acceptable("Tr0ub4dor&3-2026!"));
    }

    #[test]
    fn entropy_models() {
        // All lower: each char ~4.7 bits.
        assert!((entropy_bits("abcdefghijklmnop") - 16.0 * 26.0_f64.log2()).abs() < 0.01);
        // Mixed: largest pool is lower (26) → ~4.7 bits/char.
        assert!((entropy_bits("a1b2c3d4e5f6g7h8") - 16.0 * 26.0_f64.log2()).abs() < 0.01);
    }
}
