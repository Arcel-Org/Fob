use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::{
    error::{Error, Result},
    types::{TotpAlgorithm, TotpEntry},
    vault::unix_now,
};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// Generate a TOTP code for the given entry at the given Unix timestamp.
pub fn generate_at(entry: &TotpEntry, timestamp: u64) -> Result<String> {
    if entry.period == 0 {
        return Err(Error::InvalidTotp("period must be non-zero".into()));
    }
    let counter = timestamp / entry.period as u64;
    let code = hotp(&entry.secret.0, counter, entry.digits, entry.algorithm)?;
    Ok(format!("{:0>width$}", code, width = entry.digits as usize))
}

/// Generate a TOTP code using the current system time.
pub fn generate_now(entry: &TotpEntry) -> Result<String> {
    generate_at(entry, unix_now())
}

/// Seconds remaining in the current TOTP window.
pub fn seconds_remaining(period: u32) -> Result<u32> {
    if period == 0 {
        return Err(Error::InvalidTotp("period must be non-zero".into()));
    }
    let now = unix_now();
    let elapsed = (now % period as u64) as u32;
    Ok(period - elapsed)
}

/// HOTP: HMAC-based OTP per RFC 4226.
fn hotp(secret: &[u8], counter: u64, digits: u8, algorithm: TotpAlgorithm) -> Result<u32> {
    if !(6..=8).contains(&digits) {
        return Err(Error::InvalidTotp(format!(
            "digits must be 6 or 8, got {}",
            digits
        )));
    }

    let msg = counter.to_be_bytes();
    let digest = match algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac = HmacSha1::new_from_slice(secret)
                .map_err(|_| Error::InvalidTotp("bad key".into()))?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut mac = HmacSha256::new_from_slice(secret)
                .map_err(|_| Error::InvalidTotp("bad key".into()))?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha512 => {
            let mut mac = HmacSha512::new_from_slice(secret)
                .map_err(|_| Error::InvalidTotp("bad key".into()))?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
    };

    // Dynamic truncation per RFC 4226 §5.4.
    let offset = (digest[digest.len() - 1] & 0x0F) as usize;
    let code = u32::from_be_bytes([
        digest[offset] & 0x7F,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);

    let modulus = 10u32.pow(digits as u32);
    Ok(code % modulus)
}

/// Encode raw TOTP secret bytes back to a base32 string (inverse of
/// `decode_secret`) — for displaying/editing a secret that's already stored.
pub fn encode_secret(bytes: &[u8]) -> String {
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, bytes)
}

/// Decode a base32-encoded TOTP secret string into raw bytes.
pub fn decode_secret(base32_str: &str) -> Result<Vec<u8>> {
    let normalized: String = base32_str
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();

    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &normalized)
        .ok_or_else(|| Error::InvalidTotp(format!("invalid base32 secret: {}", base32_str)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TotpEntry;

    // RFC 6238 test vectors — SHA1, secret = "12345678901234567890"
    // https://datatracker.ietf.org/doc/html/rfc6238#appendix-B
    fn rfc6238_sha1_entry() -> TotpEntry {
        TotpEntry {
            id: uuid::Uuid::new_v4(),
            issuer: "Test".into(),
            account: "test".into(),
            secret: crate::types::SecretBytes(b"12345678901234567890".to_vec()),
            algorithm: TotpAlgorithm::Sha1,
            digits: 8,
            period: 30,
            created: 0,
        }
    }

    #[test]
    fn rfc6238_sha1_vectors() {
        let entry = rfc6238_sha1_entry();
        // Time=59 → counter=1
        assert_eq!(generate_at(&entry, 59).unwrap(), "94287082");
        // Time=1111111109 → counter=37037036
        assert_eq!(generate_at(&entry, 1111111109).unwrap(), "07081804");
        // Time=1111111111 → counter=37037037
        assert_eq!(generate_at(&entry, 1111111111).unwrap(), "14050471");
        // Time=1234567890 → counter=41152263
        assert_eq!(generate_at(&entry, 1234567890).unwrap(), "89005924");
    }

    #[test]
    fn rfc6238_sha256_vectors() {
        let mut entry = rfc6238_sha1_entry();
        entry.algorithm = TotpAlgorithm::Sha256;
        entry.secret = crate::types::SecretBytes(b"12345678901234567890123456789012".to_vec());

        assert_eq!(generate_at(&entry, 59).unwrap(), "46119246");
        assert_eq!(generate_at(&entry, 1111111109).unwrap(), "68084774");
    }

    #[test]
    fn rfc6238_sha512_vectors() {
        let mut entry = rfc6238_sha1_entry();
        entry.algorithm = TotpAlgorithm::Sha512;
        entry.secret = crate::types::SecretBytes(
            b"1234567890123456789012345678901234567890123456789012345678901234".to_vec(),
        );

        assert_eq!(generate_at(&entry, 59).unwrap(), "90693936");
    }

    #[test]
    fn base32_decode_roundtrip() {
        // Use the crate to encode, then verify decode inverts it.
        let input = b"totp-test";
        let enc = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, input);
        let decoded = decode_secret(&enc).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn encode_secret_then_decode_secret_roundtrip() {
        let input = b"another-totp-secret";
        let encoded = encode_secret(input);
        assert_eq!(decode_secret(&encoded).unwrap(), input);
    }

    #[test]
    fn base32_decode_case_insensitive() {
        let input = b"secret-key";
        let enc = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, input);
        let upper = decode_secret(&enc.to_uppercase()).unwrap();
        let lower = decode_secret(&enc.to_lowercase()).unwrap();
        assert_eq!(upper, lower);
        assert_eq!(upper, input);
    }

    #[test]
    fn base32_decode_rejects_invalid() {
        assert!(decode_secret("not-valid-base32-!@#").is_err());
    }

    #[test]
    fn six_digit_code_works() {
        let mut entry = rfc6238_sha1_entry();
        entry.digits = 6;
        let code = generate_at(&entry, 1234567890).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn invalid_digit_count_rejected() {
        let mut entry = rfc6238_sha1_entry();
        entry.digits = 5;
        assert!(generate_at(&entry, 0).is_err());
    }

    /// Regression test: a `period` of 0 (from a corrupted or hand-edited
    /// vault file — nothing validates this field on deserialize) used to
    /// cause an unconditional Rust division-by-zero panic here, reachable
    /// just by revealing or copying the TOTP code. It must now be a
    /// graceful `Err`, not a crash.
    #[test]
    fn zero_period_rejected_not_panicking() {
        let mut entry = rfc6238_sha1_entry();
        entry.period = 0;
        assert!(generate_at(&entry, 1234567890).is_err());
    }

    #[test]
    fn seconds_remaining_rejects_zero_period() {
        assert!(seconds_remaining(0).is_err());
    }

    #[test]
    fn seconds_remaining_works_for_normal_period() {
        let remaining = seconds_remaining(30).unwrap();
        assert!(remaining <= 30);
    }
}
