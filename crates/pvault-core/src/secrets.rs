//! Secret-holding types (spec Section 10).
//!
//! Every secret lives in a [`SecretBytes`] (fixed length) or a [`SecretBuf`]
//! (length chosen at creation). Both:
//!
//! - keep their bytes on the heap inside [`secrecy::SecretBox`], so moving the
//!   wrapper never copies the secret;
//! - zeroize on drop, including while unwinding from a panic;
//! - print `[REDACTED]` for `Debug`, and implement neither `Display`, `Clone`,
//!   `PartialEq` nor `Serialize`;
//! - compare only in constant time, through [`subtle::ConstantTimeEq`].
//!
//! [`LockedBuf`] adds best-effort memory locking (Section 10.2) for the
//! key-table buffers (Milestone 3). Strict mode and its reporting arrive in
//! Milestone 7.

use core::fmt;

use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::Error;

const REDACTED: &str = "[REDACTED]";

/// A fixed-length secret of `N` bytes.
///
/// Secrets cannot be cloned, printed with `Display`, or compared with `==`:
///
/// ```compile_fail
/// let key = pvault_core::secrets::SecretBytes::<32>::zeroed();
/// let copy = key.clone();
/// ```
///
/// ```compile_fail
/// let key = pvault_core::secrets::SecretBytes::<32>::zeroed();
/// println!("{key}");
/// ```
///
/// ```compile_fail
/// let a = pvault_core::secrets::SecretBytes::<32>::zeroed();
/// let b = pvault_core::secrets::SecretBytes::<32>::zeroed();
/// let _ = a == b;
/// ```
///
/// Comparison goes through `ConstantTimeEq`, and `Debug` is redacted:
///
/// ```
/// use pvault_core::secrets::SecretBytes;
/// use subtle::ConstantTimeEq;
///
/// let a = SecretBytes::<32>::zeroed();
/// let b = SecretBytes::<32>::zeroed();
/// assert!(bool::from(a.ct_eq(&b)));
/// assert_eq!(format!("{a:?}"), "[REDACTED]");
/// ```
pub struct SecretBytes<const N: usize> {
    inner: SecretBox<[u8; N]>,
}

impl<const N: usize> SecretBytes<N> {
    /// Length of the secret in bytes.
    pub const LEN: usize = N;

    /// Creates an all-zero secret, to be filled in place through
    /// [`expose_secret_mut`](Self::expose_secret_mut).
    pub fn zeroed() -> Self {
        Self {
            inner: SecretBox::new(Box::new([0u8; N])),
        }
    }

    /// Copies `src` into a new secret. `src` is wiped whether or not the call
    /// succeeds.
    pub fn take_from(src: &mut [u8]) -> Result<Self, Error> {
        let result = if src.len() == N {
            let mut secret = Self::zeroed();
            secret.expose_secret_mut().copy_from_slice(src);
            Ok(secret)
        } else {
            Err(Error::SecretLength {
                expected: N,
                actual: src.len(),
            })
        };
        src.zeroize();
        result
    }

    /// Borrows the secret bytes.
    pub fn expose_secret(&self) -> &[u8; N] {
        self.inner.expose_secret()
    }

    /// Mutably borrows the secret bytes.
    pub fn expose_secret_mut(&mut self) -> &mut [u8; N] {
        self.inner.expose_secret_mut()
    }
}

impl<const N: usize> ConstantTimeEq for SecretBytes<N> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.expose_secret()[..].ct_eq(&other.expose_secret()[..])
    }
}

impl<const N: usize> Zeroize for SecretBytes<N> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

// `SecretBox` zeroizes its contents when dropped.
impl<const N: usize> ZeroizeOnDrop for SecretBytes<N> {}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

/// A secret whose length is fixed when it is created.
///
/// The buffer never grows, so it is never reallocated and never leaves a stale
/// copy behind. Constant-time comparison reveals whether the lengths differ,
/// but not where the contents differ.
///
/// ```compile_fail
/// let buf = pvault_core::secrets::SecretBuf::zeroed(16);
/// let copy = buf.clone();
/// ```
///
/// ```compile_fail
/// let buf = pvault_core::secrets::SecretBuf::zeroed(16);
/// println!("{buf}");
/// ```
pub struct SecretBuf {
    inner: SecretBox<[u8]>,
}

impl SecretBuf {
    /// Creates an all-zero secret of `len` bytes.
    pub fn zeroed(len: usize) -> Self {
        Self {
            inner: SecretBox::new(vec![0u8; len].into_boxed_slice()),
        }
    }

    /// Creates an all-zero secret of `len` bytes, failing instead of aborting
    /// when memory is short. For lengths that come from (authenticated) file
    /// data (D3).
    pub fn try_zeroed(len: usize) -> Result<Self, Error> {
        let mut v = Vec::new();
        v.try_reserve_exact(len)
            .map_err(|_| Error::MemoryResource {
                needed_mib: (len as u64).div_ceil(1 << 20),
            })?;
        v.resize(len, 0);
        Ok(Self {
            inner: SecretBox::new(v.into_boxed_slice()),
        })
    }

    /// Copies `src` into a new secret of the same length, then wipes `src`.
    pub fn take_from(src: &mut [u8]) -> Self {
        let mut secret = Self::zeroed(src.len());
        secret.expose_secret_mut().copy_from_slice(src);
        src.zeroize();
        secret
    }

    /// Length of the secret in bytes.
    pub fn len(&self) -> usize {
        self.expose_secret().len()
    }

    /// Whether the secret is zero bytes long.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Borrows the secret bytes.
    pub fn expose_secret(&self) -> &[u8] {
        self.inner.expose_secret()
    }

    /// Mutably borrows the secret bytes.
    pub fn expose_secret_mut(&mut self) -> &mut [u8] {
        self.inner.expose_secret_mut()
    }
}

impl ConstantTimeEq for SecretBuf {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.expose_secret().ct_eq(other.expose_secret())
    }
}

impl Zeroize for SecretBuf {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

// `SecretBox` zeroizes its contents when dropped.
impl ZeroizeOnDrop for SecretBuf {}

impl fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

/// A [`SecretBuf`] whose pages are locked into RAM, best effort (10.2). On
/// drop it is wiped first, then unlocked, then freed.
pub struct LockedBuf {
    buf: SecretBuf,
    locked: bool,
}

impl LockedBuf {
    /// Allocates `len` zeroed bytes fallibly and tries to lock them.
    pub fn try_zeroed(len: usize) -> Result<Self, Error> {
        let buf = SecretBuf::try_zeroed(len)?;
        let locked = crate::platform::memory::lock_region(buf.expose_secret().as_ptr(), len);
        Ok(Self { buf, locked })
    }

    /// Whether the lock succeeded.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Borrows the bytes.
    pub fn expose_secret(&self) -> &[u8] {
        self.buf.expose_secret()
    }

    /// Mutably borrows the bytes.
    pub fn expose_secret_mut(&mut self) -> &mut [u8] {
        self.buf.expose_secret_mut()
    }
}

impl Drop for LockedBuf {
    fn drop(&mut self) {
        self.buf.zeroize();
        if self.locked {
            let s = self.buf.expose_secret();
            crate::platform::memory::unlock_region(s.as_ptr(), s.len());
        }
    }
}

impl fmt::Debug for LockedBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARKER: u8 = 0xAB;

    fn assert_no_marker(debug: &str) {
        for needle in ["171", "ab", "AB"] {
            assert!(!debug.contains(needle), "{debug:?} leaks {needle:?}");
        }
    }

    #[test]
    fn secret_bytes_debug_is_redacted() {
        let mut secret = SecretBytes::<32>::zeroed();
        secret.expose_secret_mut().fill(MARKER);

        assert_eq!(format!("{secret:?}"), "[REDACTED]");
        assert_eq!(format!("{secret:#?}"), "[REDACTED]");
        assert_no_marker(&format!("{secret:?}"));
    }

    #[test]
    fn secret_buf_debug_is_redacted() {
        let mut secret = SecretBuf::zeroed(48);
        secret.expose_secret_mut().fill(MARKER);

        assert_eq!(format!("{secret:?}"), "[REDACTED]");
        assert_eq!(format!("{secret:#?}"), "[REDACTED]");
        assert_no_marker(&format!("{secret:?}"));
    }

    #[test]
    fn debug_of_containing_struct_is_redacted() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            name: &'static str,
            key: SecretBytes<32>,
            buf: SecretBuf,
        }

        let mut holder = Holder {
            name: "holder",
            key: SecretBytes::zeroed(),
            buf: SecretBuf::zeroed(8),
        };
        holder.key.expose_secret_mut().fill(MARKER);
        holder.buf.expose_secret_mut().fill(MARKER);

        let debug = format!("{holder:?}");
        assert_eq!(
            debug,
            r#"Holder { name: "holder", key: [REDACTED], buf: [REDACTED] }"#
        );
        assert_no_marker(&format!("{holder:#?}"));
    }

    #[test]
    fn secret_bytes_take_from_copies_and_wipes_source() {
        let mut src = [MARKER; 32];
        let secret = SecretBytes::<32>::take_from(&mut src).unwrap();

        assert_eq!(secret.expose_secret(), &[MARKER; 32]);
        assert_eq!(src, [0u8; 32]);
    }

    #[test]
    fn secret_bytes_take_from_rejects_wrong_length_and_still_wipes() {
        let mut src = [MARKER; 31];
        let err = SecretBytes::<32>::take_from(&mut src).unwrap_err();

        assert!(matches!(
            err,
            Error::SecretLength {
                expected: 32,
                actual: 31
            }
        ));
        assert_eq!(src, [0u8; 31]);
    }

    #[test]
    fn secret_buf_take_from_copies_and_wipes_source() {
        let mut src = vec![MARKER; 100];
        let secret = SecretBuf::take_from(&mut src);

        assert_eq!(secret.len(), 100);
        assert!(secret.expose_secret().iter().all(|&b| b == MARKER));
        assert!(src.iter().all(|&b| b == 0));
    }

    #[test]
    fn zeroize_clears_contents() {
        let mut key = SecretBytes::<96>::zeroed();
        key.expose_secret_mut().fill(MARKER);
        key.zeroize();
        assert_eq!(key.expose_secret(), &[0u8; 96]);

        let mut buf = SecretBuf::zeroed(10);
        buf.expose_secret_mut().fill(MARKER);
        buf.zeroize();
        assert_eq!(buf.len(), 10);
        assert!(buf.expose_secret().iter().all(|&b| b == 0));
    }

    #[test]
    fn constant_time_equality() {
        let mut a = SecretBytes::<32>::zeroed();
        let mut b = SecretBytes::<32>::zeroed();
        a.expose_secret_mut().fill(MARKER);
        b.expose_secret_mut().fill(MARKER);
        assert!(bool::from(a.ct_eq(&b)));

        b.expose_secret_mut()[31] ^= 1;
        assert!(!bool::from(a.ct_eq(&b)));

        let x = SecretBuf::take_from(&mut [1, 2, 3]);
        let y = SecretBuf::take_from(&mut [1, 2, 3]);
        let z = SecretBuf::take_from(&mut [1, 2]);
        assert!(bool::from(x.ct_eq(&y)));
        assert!(!bool::from(x.ct_eq(&z)));
    }

    #[test]
    fn empty_secret_buf() {
        let buf = SecretBuf::zeroed(0);
        assert!(buf.is_empty());
        assert_eq!(format!("{buf:?}"), "[REDACTED]");
    }
}
