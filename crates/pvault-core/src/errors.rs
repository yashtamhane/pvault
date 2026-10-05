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

    /// Resource limits for the estimator child process could not be set.
    #[error("could not set process limits: {0}")]
    ProcessLimits(#[source] std::io::Error),

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

    /// Shares are invalid or inconsistent (zero or duplicate x-coordinates).
    #[error("invalid secret shares")]
    Shamir,

    /// The custom-passphrase strength estimate could not be obtained.
    #[error("the passphrase strength could not be estimated")]
    Estimator,

    /// The header does not parse, is outside the 4.4 profile or a hard cap,
    /// or fails a MAC. Shown to the user as `Unlock failed.` (spec 5.8).
    #[error("Unlock failed.")]
    HeaderInvalid,

    /// The authenticated key table does not decode (spec 7.8). Payload-free,
    /// so no path text can reach a message.
    #[error("The key table is damaged.")]
    KeyTableCorrupt,

    /// A journal record does not parse or does not authenticate (spec 8.1).
    #[error("the journal is malformed or not authentic")]
    JournalInvalid,

    /// A TPM-identity token does not authenticate (spec 8.1). Never
    /// authorizes a deletion.
    #[error("a TPM-identity token is damaged or not authentic")]
    TpmIdToken,

    /// More entries than the format allows: the key table holds at most
    /// 65,536 entries (N5), `tpm_cleanup` at most 32.
    #[error("{0}")]
    Capacity(&'static str),

    /// The Argon2 memory policy limit of spec 4.3 (step 2).
    #[error("This vault needs {needed_mib} MiB of memory, more than this computer can provide.")]
    MemoryPolicy {
        /// `argon2_m` in MiB.
        needed_mib: u64,
    },

    /// The resource check of spec 4.3 (step 3), or an allocation failure.
    #[error("Not enough free memory to open this vault right now (needs {needed_mib} MiB).")]
    MemoryResource {
        /// Memory needed, in MiB.
        needed_mib: u64,
    },

    /// The file system cannot safely store vault changes (spec 8.5).
    #[error(
        "This file system cannot safely store vault changes ({0}). Copy the vault to a supported drive to change it."
    )]
    UnsupportedFileSystem(String),

    /// Another pvault process holds the vault lock (spec 8.4).
    #[error("The vault is in use by another pvault process.")]
    VaultInUse,

    /// A required file-system or platform primitive is unavailable; the
    /// operation is refused rather than weakened (spec 7.6a).
    #[error("this operation is not supported here: {0}")]
    Unsupported(&'static str),

    /// A file that pvault must not touch blocks the operation (an unowned
    /// leftover at a protocol name, spec 8.1 to 8.3).
    #[error("an unowned file blocks this operation: {0}")]
    Blocked(&'static str),

    /// The header replacement became visible, but the required flush failed
    /// (spec 8.5 failure boundary). Never an ordinary abort; the journal and
    /// every old and new dependency are kept.
    #[error("The new header is visible, but commit durability could not be confirmed; run fsck.")]
    DurabilityUnknown,

    /// The header replacement call reported failure, and re-reading
    /// `vault.hdr` found neither the previous header nor the new one, or could
    /// not read it (spec 8.5 failure boundary). The journal and the header
    /// temp are kept.
    #[error(
        "The header replacement outcome could not be determined. Run fsck before making further changes."
    )]
    OutcomeUnknown,

    /// The on-disk header generation changed during the operation (spec 8.4
    /// generation check, F58). The header was not replaced; the journal and
    /// any temporary files the operation already wrote remain.
    #[error("The vault changed during this operation. The header was not committed.")]
    GenerationChanged,

    /// A restart found a header that matches no side the journal allows, or
    /// an artifact the authenticated state depends on is missing or does not
    /// match (spec 6.6, 8.2). Returned before any cleanup; the journal and
    /// every file are kept.
    #[error("The vault state could not be determined safely. No cleanup was performed. Run fsck.")]
    Indeterminate,

    /// Reading or writing a stream failed.
    #[error("I/O error: {0}")]
    Io(#[source] std::io::Error),
}
