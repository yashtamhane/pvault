//! Unauthenticated XChaCha20 key wraps (spec Section 7.5).
//!
//! `ct = plaintext XOR XChaCha20_keystream(key, nonce)`, with a fresh random
//! 24-byte nonce per wrap. Wraps carry no tag: whether an unwrap was correct
//! is proven only by the header MACs checked afterwards (spec 5.4). They are
//! used for S1, S2 and the portable slot.

use chacha20::XChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};

use crate::crypto::random;
use crate::errors::Error;
use crate::secrets::SecretBytes;

/// Length of a wrap nonce, in bytes.
pub const NONCE_LEN: usize = 24;

/// XORs the XChaCha20 keystream for `(key, nonce)` into `data`, in place.
/// Applying it twice restores the input.
pub fn apply_keystream(key: &SecretBytes<32>, nonce: &[u8; NONCE_LEN], data: &mut [u8]) {
    let mut cipher = XChaCha20::new(key.expose_secret().into(), nonce.into());
    cipher.apply_keystream(data);
}

/// Wraps a secret under `key` with a fresh random nonce. Returns the nonce
/// and the ciphertext. The ciphertext is not secret on its own.
pub fn wrap<const N: usize>(
    key: &SecretBytes<32>,
    plaintext: &SecretBytes<N>,
) -> Result<([u8; NONCE_LEN], [u8; N]), Error> {
    let nonce = random::array::<NONCE_LEN>()?;
    let mut ciphertext = *plaintext.expose_secret();
    apply_keystream(key, &nonce, &mut ciphertext);
    Ok((nonce, ciphertext))
}

/// Unwraps a ciphertext into a new secret. A wrong key or nonce yields wrong
/// bytes, never an error; callers detect that through the MACs.
pub fn unwrap<const N: usize>(
    key: &SecretBytes<32>,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8; N],
) -> SecretBytes<N> {
    let mut out = SecretBytes::<N>::zeroed();
    out.expose_secret_mut().copy_from_slice(ciphertext);
    apply_keystream(key, nonce, out.expose_secret_mut());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testvec::{field, hex, hex_field, records};
    use subtle::ConstantTimeEq;

    fn key(bytes: Vec<u8>) -> SecretBytes<32> {
        SecretBytes::take_from(&mut bytes.clone()).unwrap()
    }

    /// draft-irtf-cfrg-xchacha-03, Appendix A.3.2.1 (block counter 0).
    #[test]
    fn published_xchacha20_keystream() {
        let v = &records(include_str!("../../testdata/xchacha20_draft.txt"))[0];
        let mut data = hex_field(v, "plaintext");
        let nonce: [u8; NONCE_LEN] = hex_field(v, "iv").try_into().unwrap();
        apply_keystream(&key(hex_field(v, "key")), &nonce, &mut data);
        assert_eq!(data, hex_field(v, "ciphertext"));

        let mut zeros = vec![0u8; hex_field(v, "keystream").len()];
        apply_keystream(&key(hex_field(v, "key")), &nonce, &mut zeros);
        assert_eq!(zeros, hex_field(v, "keystream"));
    }

    #[test]
    fn pvault_wrap_vectors() {
        let vectors = records(include_str!("../../testdata/pvault_wrap.txt"));
        assert!(!vectors.is_empty());
        for v in &vectors {
            let k = key(hex_field(v, "key"));
            let nonce: [u8; NONCE_LEN] = hex_field(v, "nonce").try_into().unwrap();
            let ciphertext: [u8; 96] = hex_field(v, "ciphertext").try_into().unwrap();
            let plain = unwrap(&k, &nonce, &ciphertext);
            assert_eq!(
                plain.expose_secret().as_slice(),
                hex_field(v, "plaintext"),
                "{}",
                field(v, "name")
            );
        }
    }

    #[test]
    fn wrap_round_trip_with_fresh_nonces() {
        let k = random::secret::<32>().unwrap();
        let secret = random::secret::<96>().unwrap();
        let (n1, c1) = wrap(&k, &secret).unwrap();
        let (n2, c2) = wrap(&k, &secret).unwrap();
        assert_ne!(n1, n2);
        assert_ne!(c1, c2);
        assert!(bool::from(unwrap(&k, &n1, &c1).ct_eq(&secret)));
        assert!(bool::from(unwrap(&k, &n2, &c2).ct_eq(&secret)));
    }

    #[test]
    fn wrong_key_gives_wrong_bytes_not_an_error() {
        let secret = random::secret::<96>().unwrap();
        let (nonce, ct) = wrap(&random::secret::<32>().unwrap(), &secret).unwrap();
        let wrong = unwrap(&random::secret::<32>().unwrap(), &nonce, &ct);
        assert!(!bool::from(wrong.ct_eq(&secret)));
        assert_eq!(hex("00").len(), 1);
    }
}
