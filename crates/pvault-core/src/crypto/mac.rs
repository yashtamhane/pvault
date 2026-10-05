//! HMAC-SHA-512 and SHA-512 (spec Sections 4.2, 7.8, 8.1).
//!
//! Inputs are given as a list of parts, which are hashed as their
//! concatenation. Domain-separation prefixes are passed as the first part by
//! the callers that define them.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha512};

/// Length of an HMAC-SHA-512 tag and of a SHA-512 digest.
pub const TAG_LEN: usize = 64;

fn keyed(key: &[u8], parts: &[&[u8]]) -> Hmac<Sha512> {
    // HMAC accepts keys of every length, so this cannot fail.
    let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(key)
        .expect("HMAC-SHA-512 accepts keys of any length");
    for part in parts {
        mac.update(part);
    }
    mac
}

/// HMAC-SHA-512 of the concatenation of `parts`.
pub fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> [u8; TAG_LEN] {
    keyed(key, parts).finalize().into_bytes().into()
}

/// Verifies a full 64-byte HMAC-SHA-512 tag in constant time. Tags of any
/// other length are rejected.
pub fn verify_hmac_sha512(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
    tag.len() == TAG_LEN && keyed(key, parts).verify_slice(tag).is_ok()
}

/// SHA-512 of the concatenation of `parts`.
pub fn sha512(parts: &[&[u8]]) -> [u8; TAG_LEN] {
    let mut hasher = Sha512::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testvec::{field, hex_field, records};

    #[test]
    fn rfc4231_hmac_sha512() {
        let vectors = records(include_str!("../../testdata/rfc4231_hmac_sha512.txt"));
        assert_eq!(vectors.len(), 6);
        for v in &vectors {
            let (key, data, tag) = (
                hex_field(v, "key"),
                hex_field(v, "data"),
                hex_field(v, "tag"),
            );
            assert_eq!(
                hmac_sha512(&key, &[&data]).as_slice(),
                tag,
                "case {}",
                field(v, "case")
            );
            assert!(verify_hmac_sha512(&key, &[&data], &tag));
        }
    }

    #[test]
    fn wycheproof_hmac_sha512() {
        let vectors = records(include_str!("../../testdata/wycheproof_hmac_sha512.txt"));
        assert!(vectors.len() > 50);
        for v in &vectors {
            let (key, msg, tag) = (
                hex_field(v, "key"),
                hex_field(v, "msg"),
                hex_field(v, "tag"),
            );
            let valid = field(v, "result") == "valid";
            assert_eq!(
                verify_hmac_sha512(&key, &[&msg], &tag),
                valid,
                "tcId {}",
                field(v, "tcId")
            );
            if valid {
                assert_eq!(hmac_sha512(&key, &[&msg]).as_slice(), tag);
            }
        }
    }

    #[test]
    fn parts_are_concatenated() {
        let key = [7u8; 32];
        assert_eq!(
            hmac_sha512(&key, &[b"pvault/", b"v1/", b"core"]),
            hmac_sha512(&key, &[b"pvault/v1/core"])
        );
        assert_eq!(sha512(&[b"a", b"bc"]), sha512(&[b"abc"]));
    }

    #[test]
    fn sha512_fips_180_example() {
        // FIPS 180-2, Appendix C.1: SHA-512("abc").
        let expected = crate::testvec::hex(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        );
        assert_eq!(sha512(&[b"abc"]).as_slice(), expected);
    }

    #[test]
    fn short_or_long_tags_are_rejected() {
        let key = [1u8; 32];
        let tag = hmac_sha512(&key, &[b"m"]);
        assert!(!verify_hmac_sha512(&key, &[b"m"], &tag[..32]));
        let mut long = tag.to_vec();
        long.push(0);
        assert!(!verify_hmac_sha512(&key, &[b"m"], &long));
    }
}
