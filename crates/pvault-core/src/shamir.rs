//! Shamir secret sharing over GF(2^8) (spec Section 7.4).
//!
//! The field is GF(2^8) with the AES polynomial x^8 + x^4 + x^3 + x + 1
//! (0x11B). Each byte of the 96-byte bundle is shared separately with a
//! degree-1 polynomial `f(x) = s + a·x`, whose x-coordinates are 1, 2, 3
//! (bound 2-of-3) or 1, 2 (portable 2-of-2). Combination is Lagrange
//! interpolation at x = 0.
//!
//! Arithmetic comes from `vsss-rs` 6.0.1 (SI-08), but only through its public
//! polynomial API. pvault owns every buffer that holds the secret, a
//! coefficient or a share: the polynomial storage, the per-byte share arrays
//! and the outputs. Each is wiped on every exit path. The crate's own byte
//! API is not used, because it frees secret-derived heap memory without
//! wiping it.
//!
//! The coefficients are drawn by pvault from the OS RNG and written directly
//! into its own polynomial storage, so known-answer vectors do not depend on
//! how `vsss-rs` maps RNG output to coefficients.

use vsss_rs::{DefaultShare, Gf256, IdentifierGf256, Polynomial, ReadableShareSet, shamir};
use zeroize::Zeroize;

use crate::crypto::random;
use crate::errors::Error;
use crate::secrets::SecretBytes;

/// Length of the shared secret (the key bundle), in bytes.
pub const SECRET_LEN: usize = 96;

type GfShare = DefaultShare<IdentifierGf256, IdentifierGf256>;

const fn element(byte: u8) -> IdentifierGf256 {
    IdentifierGf256(Gf256(byte))
}

/// One share: an x-coordinate and 96 y-bytes.
#[derive(Debug)]
pub struct Share {
    x: u8,
    y: SecretBytes<SECRET_LEN>,
}

impl Share {
    /// Builds a share. The x-coordinate must be non-zero, because zero is
    /// reserved for the secret.
    pub fn new(x: u8, y: SecretBytes<SECRET_LEN>) -> Result<Self, Error> {
        if x == 0 {
            return Err(Error::Shamir);
        }
        Ok(Self { x, y })
    }

    /// The x-coordinate.
    pub fn x(&self) -> u8 {
        self.x
    }

    /// The y-bytes.
    pub fn y(&self) -> &SecretBytes<SECRET_LEN> {
        &self.y
    }
}

/// Polynomial storage owned by pvault: `[a0 = secret byte, a1]`, wiped on drop.
#[derive(Default)]
struct WipingPolynomial([GfShare; 2]);

impl Polynomial<GfShare> for WipingPolynomial {
    fn create(_size_hint: usize) -> Self {
        Self::default()
    }

    fn coefficients(&self) -> &[GfShare] {
        &self.0
    }

    fn coefficients_mut(&mut self) -> &mut [GfShare] {
        &mut self.0
    }
}

impl WipingPolynomial {
    /// `vsss-rs` evaluates `coefficients[0].value` as the constant term and
    /// `coefficients[i].identifier` as the coefficient of x^i.
    fn set(&mut self, secret: u8, a1: u8) {
        self.0[0].value = element(secret);
        self.0[1].identifier = element(a1);
    }

    fn wipe(&mut self) {
        wipe_shares(&mut self.0);
    }
}

impl Drop for WipingPolynomial {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// A fixed array of field shares that is wiped on drop.
struct WipingShares<const N: usize>([GfShare; N]);

impl<const N: usize> Drop for WipingShares<N> {
    fn drop(&mut self) {
        wipe_shares(&mut self.0);
    }
}

fn wipe_shares(shares: &mut [GfShare]) {
    for share in shares {
        share.identifier.0.0.zeroize();
        share.value.0.0.zeroize();
    }
}

/// Splits a 96-byte secret 2-of-3 for bound mode (x = 1, 2, 3).
pub fn split_2_of_3(secret: &SecretBytes<SECRET_LEN>) -> Result<[Share; 3], Error> {
    let coefficients = random::secret::<SECRET_LEN>()?;
    split_with(secret, &coefficients, [1, 2, 3])
}

/// Splits a 96-byte secret 2-of-2 for portable recovery (x = 1, 2).
pub fn split_2_of_2(secret: &SecretBytes<SECRET_LEN>) -> Result<[Share; 2], Error> {
    let coefficients = random::secret::<SECRET_LEN>()?;
    split_with(secret, &coefficients, [1, 2])
}

/// Evaluates `f_i(x) = secret[i] + coefficients[i]·x` at each x in `xs`.
pub(crate) fn split_with<const N: usize>(
    secret: &SecretBytes<SECRET_LEN>,
    coefficients: &SecretBytes<SECRET_LEN>,
    xs: [u8; N],
) -> Result<[Share; N], Error> {
    if N < 2 || xs.contains(&0) || has_duplicates(&xs) {
        return Err(Error::Shamir);
    }

    let mut ys: [SecretBytes<SECRET_LEN>; N] = core::array::from_fn(|_| SecretBytes::zeroed());
    let ids = xs.map(element);
    let mut polynomial = WipingPolynomial::default();
    for i in 0..SECRET_LEN {
        polynomial.set(secret.expose_secret()[i], coefficients.expose_secret()[i]);
        let set = WipingShares::<N>(
            shamir::create_shares_from_polynomial(&polynomial, 2, N, ids.iter().copied())
                .map_err(|_| Error::Shamir)?,
        );
        for (y, share) in ys.iter_mut().zip(set.0.iter()) {
            y.expose_secret_mut()[i] = share.value.0.0;
        }
    }

    let mut ys = ys.into_iter();
    Ok(xs.map(|x| Share {
        x,
        y: ys.next().expect("one y per x"),
    }))
}

/// Recombines a secret from two shares with different, non-zero x-coordinates.
pub fn combine(a: &Share, b: &Share) -> Result<SecretBytes<SECRET_LEN>, Error> {
    if a.x == 0 || b.x == 0 || a.x == b.x {
        return Err(Error::Shamir);
    }
    let mut out = SecretBytes::<SECRET_LEN>::zeroed();
    let mut value = element(0);
    for i in 0..SECRET_LEN {
        let pair = WipingShares([
            GfShare {
                identifier: element(a.x),
                value: element(a.y.expose_secret()[i]),
            },
            GfShare {
                identifier: element(b.x),
                value: element(b.y.expose_secret()[i]),
            },
        ]);
        let result = pair.0.combine_in_place(&mut value);
        if result.is_err() {
            value.0.0.zeroize();
            return Err(Error::Shamir);
        }
        out.expose_secret_mut()[i] = value.0.0;
    }
    value.0.0.zeroize();
    Ok(out)
}

fn has_duplicates(xs: &[u8]) -> bool {
    xs.iter().enumerate().any(|(i, x)| xs[i + 1..].contains(x))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testvec::{field, hex, hex_field, records};
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;

    fn secret_from(bytes: Vec<u8>) -> SecretBytes<SECRET_LEN> {
        SecretBytes::take_from(&mut bytes.clone()).unwrap()
    }

    /// Independent reference multiply (shift-and-add with reduction by
    /// 0x11B). A different algorithm from the branch-free one in `vsss-rs`.
    fn ref_mul(mut a: u8, mut b: u8) -> u8 {
        let mut r = 0u8;
        while b != 0 {
            if b & 1 != 0 {
                r ^= a;
            }
            let carry = a & 0x80 != 0;
            a <<= 1;
            if carry {
                a ^= 0x1b;
            }
            b >>= 1;
        }
        r
    }

    #[test]
    fn published_vectors_f62() {
        let vectors = records(include_str!("../testdata/pvault_shamir.txt"));
        assert!(!vectors.is_empty());
        for v in &vectors {
            let secret = secret_from(hex_field(v, "secret"));
            let coefficients = secret_from(hex_field(v, "coefficients"));
            let shares = split_with(&secret, &coefficients, [1, 2, 3]).unwrap();
            for (share, key) in shares.iter().zip(["share_x1", "share_x2", "share_x3"]) {
                assert_eq!(
                    share.y().expose_secret().as_slice(),
                    hex_field(v, key),
                    "{} {key}",
                    field(v, "name")
                );
            }
            for (i, j) in [(0, 1), (0, 2), (1, 2)] {
                let back = combine(&shares[i], &shares[j]).unwrap();
                assert!(bool::from(back.ct_eq(&secret)));
            }
        }
    }

    #[test]
    fn field_multiplication_matches_independent_reference() {
        let table = records(include_str!("../testdata/pvault_gf256.txt"));
        let v = &table[0];
        let mut product_table = Vec::with_capacity(65_536);
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                let ours = (Gf256(a) * Gf256(b)).0;
                assert_eq!(ours, ref_mul(a, b), "{a:#04x} * {b:#04x}");
                product_table.push(ours);
            }
        }
        assert_eq!(
            Sha256::digest(&product_table).as_slice(),
            hex_field(v, "mul_table_sha256")
        );

        let inverses = hex_field(v, "inverses");
        for a in 1..=255u8 {
            let inv = vsss_rs::ShareIdentifier::invert(&element(a)).unwrap().0.0;
            assert_eq!(ref_mul(a, inv), 1, "inverse of {a:#04x}");
            assert_eq!(inv, inverses[usize::from(a)]);
        }
    }

    #[test]
    fn every_pair_recovers_bound_and_portable() {
        let secret = random::secret::<SECRET_LEN>().unwrap();
        let bound = split_2_of_3(&secret).unwrap();
        assert_eq!(bound.iter().map(Share::x).collect::<Vec<_>>(), [1, 2, 3]);
        for (i, j) in [(0, 1), (0, 2), (1, 2), (1, 0), (2, 0), (2, 1)] {
            assert!(bool::from(
                combine(&bound[i], &bound[j]).unwrap().ct_eq(&secret)
            ));
        }
        let portable = split_2_of_2(&secret).unwrap();
        assert_eq!(portable.iter().map(Share::x).collect::<Vec<_>>(), [1, 2]);
        assert!(bool::from(
            combine(&portable[0], &portable[1]).unwrap().ct_eq(&secret)
        ));
    }

    /// F5: a single share is not the secret, and a share paired with itself
    /// is refused.
    #[test]
    fn one_share_is_not_the_secret_f5() {
        let secret = random::secret::<SECRET_LEN>().unwrap();
        let shares = split_2_of_3(&secret).unwrap();
        for share in &shares {
            assert!(!bool::from(share.y().ct_eq(&secret)));
            assert!(matches!(combine(share, share), Err(Error::Shamir)));
        }
    }

    /// F6: shares from two different splits do not recombine to either secret.
    #[test]
    fn shares_from_different_splits_do_not_combine_f6() {
        let a = random::secret::<SECRET_LEN>().unwrap();
        let b = random::secret::<SECRET_LEN>().unwrap();
        let sa = split_2_of_3(&a).unwrap();
        let sb = split_2_of_3(&b).unwrap();
        let mixed = combine(&sa[0], &sb[1]).unwrap();
        assert!(!bool::from(mixed.ct_eq(&a)));
        assert!(!bool::from(mixed.ct_eq(&b)));
    }

    #[test]
    fn fresh_coefficients_per_split() {
        let secret = random::secret::<SECRET_LEN>().unwrap();
        let first = split_2_of_3(&secret).unwrap();
        let second = split_2_of_3(&secret).unwrap();
        assert!(!bool::from(first[0].y().ct_eq(second[0].y())));
    }

    #[test]
    fn invalid_coordinates_are_rejected_before_interpolation() {
        let zero = SecretBytes::<SECRET_LEN>::zeroed();
        assert!(matches!(
            Share::new(0, SecretBytes::zeroed()),
            Err(Error::Shamir)
        ));
        assert!(matches!(
            split_with(&zero, &zero, [1, 1]),
            Err(Error::Shamir)
        ));
        assert!(matches!(
            split_with(&zero, &zero, [0, 2]),
            Err(Error::Shamir)
        ));
        let a = Share::new(1, SecretBytes::zeroed()).unwrap();
        let b = Share::new(1, SecretBytes::zeroed()).unwrap();
        assert!(matches!(combine(&a, &b), Err(Error::Shamir)));
    }

    #[test]
    fn polynomial_storage_is_wiped() {
        let mut polynomial = WipingPolynomial::default();
        polynomial.set(0xA5, 0x5A);
        assert_eq!(polynomial.0[0].value.0.0, 0xA5);
        polynomial.wipe();
        for c in &polynomial.0 {
            assert_eq!((c.identifier.0.0, c.value.0.0), (0, 0));
        }
    }

    /// Drop must wipe: inspect the storage after `drop_in_place` without
    /// freeing it.
    #[test]
    #[allow(unsafe_code)]
    fn dropped_storage_is_zeroed() {
        let mut slot = core::mem::MaybeUninit::<WipingPolynomial>::uninit();
        slot.write(WipingPolynomial::default()).set(0xC3, 0x3C);
        // SAFETY: `slot` was initialized just above and is dropped exactly
        // once here. The memory stays owned by `slot`.
        unsafe { core::ptr::drop_in_place(slot.as_mut_ptr()) };
        // SAFETY: the bytes of the dropped value are still initialized
        // memory owned by `slot`. They are read as plain bytes, never as a
        // live `WipingPolynomial`.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                slot.as_ptr().cast::<u8>(),
                core::mem::size_of::<WipingPolynomial>(),
            )
        };
        assert!(bytes.iter().all(|&b| b == 0));

        let mut shares = core::mem::MaybeUninit::<WipingShares<3>>::uninit();
        let set = shares.write(WipingShares(core::array::from_fn(|i| GfShare {
            identifier: element(i as u8 + 1),
            value: element(0x77),
        })));
        assert_eq!(set.0[2].value.0.0, 0x77);
        // SAFETY: as above, for `shares`.
        unsafe { core::ptr::drop_in_place(shares.as_mut_ptr()) };
        // SAFETY: as above, for `shares`.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                shares.as_ptr().cast::<u8>(),
                core::mem::size_of::<WipingShares<3>>(),
            )
        };
        assert!(bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn hex_helper_round_trip() {
        assert_eq!(hex("00ff"), [0, 255]);
    }
}
