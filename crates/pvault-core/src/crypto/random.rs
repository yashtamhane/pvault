//! Randomness (spec Section 7.1).
//!
//! Every random byte comes from the operating system through
//! [`getrandom::fill`]. A failure is returned to the caller, and no other
//! source is ever substituted. Where an API requires a `rand_core` RNG,
//! `getrandom::SysRng` (behind `getrandom`'s `sys_rng` feature, not yet enabled) is
//! the only permitted generator.

use crate::errors::Error;
use crate::secrets::SecretBytes;

/// Fills `dest` from the operating system's CSPRNG.
pub fn fill(dest: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(dest).map_err(Error::Random)
}

/// Returns a new random secret, generated in place in its final storage.
pub fn secret<const N: usize>() -> Result<SecretBytes<N>, Error> {
    let mut secret = SecretBytes::zeroed();
    fill(secret.expose_secret_mut())?;
    Ok(secret)
}

/// Returns random bytes that are not secret, such as nonces and identifiers.
pub fn array<const N: usize>() -> Result<[u8; N], Error> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use subtle::ConstantTimeEq;

    #[test]
    fn independent_draws_differ() {
        let a = secret::<32>().unwrap();
        let b = secret::<32>().unwrap();
        assert!(!bool::from(a.ct_eq(&b)));
        assert_ne!(array::<24>().unwrap(), array::<24>().unwrap());
    }

    #[test]
    fn output_is_not_all_zero() {
        // A 32-byte all-zero output has probability 2^-256.
        assert_ne!(array::<32>().unwrap(), [0u8; 32]);
    }

    #[test]
    fn empty_fill_is_allowed() {
        fill(&mut []).unwrap();
    }
}
