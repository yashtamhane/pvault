//! Error types for `pvault-core`.
//!
//! Errors never carry secret material (spec Section 10.6).

use thiserror::Error;

/// Where exports and card files can go (O3; `platform::fs::is_private_destination_type`).
#[cfg(target_os = "macos")]
const PRIVATE_DESTINATION_HINT: &str =
    "a local APFS or HFS+ drive, for example in your home folder";
#[cfg(target_os = "linux")]
const PRIVATE_DESTINATION_HINT: &str =
    "a local ext4, XFS, Btrfs or tmpfs file system, for example in your home folder";
#[cfg(windows)]
const PRIVATE_DESTINATION_HINT: &str =
    "a local NTFS or ReFS drive, for example in your user folder";
#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
const PRIVATE_DESTINATION_HINT: &str = "a supported local drive";

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

    // ---- Milestone 4 (`docs/CLI.md` 7) ----
    /// A bound vault given to a portable-only command (F17, portable part).
    #[error("This version of pvault opens portable vaults only; this vault is bound.")]
    BoundVault,

    /// A journal of a kind the command does not resolve.
    #[error("This vault has an unfinished {0}. Run fsck to finish it.")]
    PendingJournal(&'static str),

    /// An `update` whose cleanup cannot be finished (`docs/M4_READINESS.md` 9.5).
    #[error(
        "This vault's last change was saved, but its cleanup could not be finished because a file it needs is missing. Nothing was deleted. Run fsck."
    )]
    UnresolvedCleanup,

    /// Files at protocol names whose ownership cannot be proved (9.7).
    #[error("Files pvault cannot prove it created block this change: {}. Nothing was deleted.", .0.join(", "))]
    UnownedLeftovers(Vec<String>),

    /// The settings folder cannot be used (7.1).
    #[error("The pvault settings folder is unavailable: {0}.")]
    SettingsUnavailable(String),

    /// The settings folder is not private to the user (7.1).
    #[error("The pvault settings folder {} is not private to you.", .0.display())]
    SettingsNotPrivate(std::path::PathBuf),

    /// Tracking records need an 8.5-supported local settings folder (7.1).
    #[error("Exports and card files need a settings folder on a supported local drive ({0}).")]
    RegistrationUnsupported(String),

    /// A tracking record failed to parse; it is never modified (7.5, 7.6).
    #[error("The record {} is damaged; pvault will not change it. Move it aside to continue (anything it tracked is then untracked).", .0.display())]
    RecordDamaged(std::path::PathBuf),

    /// A tracking record is full.
    #[error("Too many unfinished {0} are recorded. Run pvault clean-partials.")]
    RecordFull(&'static str),

    /// A registration flush failed: no secret byte was written (7.1).
    #[error("The {0} could not be registered durably; nothing was written.")]
    NotRegistered(&'static str),

    /// A path too long for a record.
    #[error("This path is too long to track safely.")]
    PathTooLongToTrack,

    /// A card structure or combination error (7.4a).
    #[error("{0}")]
    Card(crate::card::CardError),

    /// Card text input error.
    #[error("{0}")]
    CardText(crate::card::CardTextError),

    /// PNG or QR input error (7.4c).
    #[error("{0}")]
    Png(crate::card::PngError),

    /// A delivered card does not match the card in memory (6.4).
    #[error("{0} does not match what was printed.")]
    CardMismatch(&'static str),

    /// An export or card-file destination whose file system pvault cannot
    /// confirm enforces owner-only access (7.9, 7.4b; decided 2026-10-06,
    /// O3, fail closed).
    #[error(
        "pvault writes exported files and recovery cards only where it can confirm that the file system keeps them private to you (owner-only access). This destination is on {0}, which it cannot confirm. Nothing was written. Choose a folder on {suggestion}.",
        suggestion = PRIVATE_DESTINATION_HINT
    )]
    DestinationNotPrivate(String),

    /// A card file failed the format 1 reader (SI-52 6.1).
    #[error("{0}")]
    CardFile(crate::card::CardFileError),

    /// Digital mode: both card folders are the same folder (SI-52 7).
    #[error("Card A and Card B cannot be saved in the same folder.")]
    SameCardFolder,

    /// Digital mode: a required risk acknowledgment was not given (SI-52 5).
    #[error("{0}")]
    AckRequired(&'static str),

    /// A typed confirmation that only a terminal can give was missing or
    /// declined; nothing was changed.
    #[error("{0}")]
    NotConfirmed(&'static str),

    /// A saved digital card file no longer is the file pvault wrote.
    #[error("The saved {0} file changed after it was written; the setup was rolled back.")]
    CardFileChanged(&'static str),

    /// The optional card check after the commit failed (SI-52 R5). The
    /// vault exists and is unchanged; no card file was deleted.
    #[error(
        "The vault was created, but the card check failed: {0} The vault is unchanged and no card file was deleted. Check the drives and the card files before relying on them."
    )]
    CardCheckFailed(String),

    /// The recovery rehearsal with the delivered cards failed (SI-52 6.4).
    #[error(
        "Recovering this vault from the delivered cards failed, so the setup was rolled back; the cards are invalid."
    )]
    RehearsalFailed,

    /// The card destination is the vault folder or inside it (7.4b).
    #[error("Card files cannot be written inside the vault folder.")]
    CardDestinationInVault,

    /// A file name already exists (card or export).
    #[error("A file named {0} already exists; nothing was written.")]
    NameExists(String),

    /// A file name is too long for the destination file system.
    #[error("The destination name is too long to add the .pvpartial suffix on this file system.")]
    NameTooLong,

    /// A typed vault path breaks an input rule.
    #[error("This path is not allowed in a vault: {0}.")]
    PathNotAllowed(&'static str),

    /// A typed vault path contains an unassigned code point.
    #[error("This path contains a character this version of pvault does not support.")]
    PathUnsupported,

    /// The typed vault path exists.
    #[error("This path already exists in the vault. Use --replace to replace it.")]
    PathExists,

    /// The typed vault path collides with another entry by case or form.
    #[error(
        "This path collides with an existing entry that differs only by letter case or Unicode form. Use pvault list to see it."
    )]
    PathCollision,

    /// `--replace` must name the stored path exactly.
    #[error("--replace must name the stored path exactly. Use pvault list to see it.")]
    ReplaceNeedsStoredPath,

    /// No entry at the vault path.
    #[error("No file or folder with this path is in the vault.")]
    PathNotFound,

    /// A folder where a file is needed, or the reverse.
    #[error("{0}")]
    WrongKind(&'static str),

    /// `rm` of a non-empty folder without `--recursive`.
    #[error("This folder is not empty. Use --recursive to remove it and its contents.")]
    FolderNotEmpty,

    /// An `add` source that is not a regular file.
    #[error("The source is not a regular file.")]
    SourceNotRegular,

    /// An `add` source whose final component is a link.
    #[error("The source is a symbolic link or reparse point; give the file itself.")]
    SourceLink,

    /// Windows: the source is open for writing elsewhere.
    #[error("The source file is in use by another program.")]
    SourceInUse,

    /// The source changed during `add`; rolled back.
    #[error("The source file changed while it was being added; the vault was not changed.")]
    SourceChanged,

    /// The export destination exists.
    #[error("The destination already exists; nothing was written.")]
    DestinationExists,

    /// The destination folder is a link.
    #[error("The destination folder is a symbolic link or reparse point.")]
    DestinationFolderLink,

    /// A no-replace rename is unsupported at the destination.
    #[error("This file system cannot export without overwriting safely; nothing was written.")]
    NoReplaceUnsupported,

    /// An export was published but its durability is unconfirmed (exit 5).
    #[error("The export was written to the destination, but it could not be confirmed as durable.")]
    ExportUnconfirmed,

    /// Whether an export was published could not be determined (exit 5).
    #[error("The export's outcome could not be determined; check the destination.")]
    ExportOutcomeUnknown,

    /// `--force` is refused in Milestone 4.
    #[error("The --force option is not available in this version; nothing was written.")]
    ForceRefused,

    /// Two passphrase entries differ.
    #[error("The passphrases do not match.")]
    PassphraseMismatch,

    /// A passphrase was refused by the creation rules.
    #[error("{0}")]
    Passphrase(crate::passphrase::PassphraseError),

    /// The custom passphrase was estimated weak.
    #[error("This passphrase is too weak. Choose a stronger one or a generated passphrase.")]
    PassphraseWeak,

    /// A required terminal is missing (generated passphrase display, or a
    /// confirmation needed without one).
    #[error("{0}")]
    NeedsTerminal(&'static str),

    /// Secret input failed.
    #[error("{0}")]
    Input(crate::input::InputError),

    /// `--secrets-stdin` ended before a needed line, or its last line had
    /// no terminator.
    #[error("Input ended before all secrets were read.")]
    InputEnded,

    /// The owner declined or cancelled.
    #[error("Cancelled.")]
    Cancelled,

    /// The target folder for `init` is not empty.
    #[error("The folder is not empty; choose an empty or new folder for the vault.")]
    TargetNotEmpty,

    /// An init journal is present and must be resolved by `pvault init`.
    #[error("This folder holds an interrupted setup. Run pvault init on it to resolve it.")]
    InitPending,

    /// Reading or writing a stream failed.
    #[error("I/O error: {0}")]
    Io(#[source] std::io::Error),
}
