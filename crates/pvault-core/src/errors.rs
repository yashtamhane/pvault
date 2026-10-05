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
}
