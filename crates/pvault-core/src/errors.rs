//! Error types for `pvault-core`.
//!
//! Errors never carry secret material (spec Section 10.6).

use thiserror::Error;

/// Errors returned by `pvault-core`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// A secret was built from input of the wrong length.
    #[error("secret has the wrong length: expected {expected} bytes, got {actual}")]
    SecretLength {
        /// Required length in bytes.
        expected: usize,
        /// Length that was supplied.
        actual: usize,
    },

    /// The operating system refused to disable core dumps.
    #[error("could not disable core dumps: {0}")]
    CoreDumps(#[source] std::io::Error),

    /// The operating system's random number generator failed. No other
    /// source is ever substituted (spec Section 7.1).
    #[error("the operating system's random number generator failed: {0}")]
    Random(getrandom::Error),

    /// Argon2id parameters are outside the hard caps of spec Section 4.3.
    #[error("Argon2id parameters are outside the permitted limits")]
    KdfParams,

    /// Memory for Argon2id could not be allocated.
    #[error("not enough memory for Argon2id")]
    OutOfMemory,

    /// Key derivation failed.
    #[error("key derivation failed")]
    Kdf,

    /// An encrypted stream is malformed or not authentic. Deliberately
    /// carries no detail about what failed.
    #[error("encrypted data is damaged or not authentic")]
    Stream,

    /// The plaintext source did not supply exactly the declared size.
    #[error("the input did not match its declared size")]
    InputLength,

    /// Reading or writing a stream failed.
    #[error("I/O error: {0}")]
    Io(#[source] std::io::Error),
}
