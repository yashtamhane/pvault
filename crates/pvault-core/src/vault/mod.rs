//! Portable vault operations (spec 5.3, 5.7, 7.8, 7.9, 8.3; Milestone 4).
//!
//! - [`unlock`]: the ordinary unlock, in the 5.7 order: lock, header,
//!   Argon2 limits, passphrase and word check, Argon2id, duress check,
//!   pending-journal check, slot unwrap and both MACs, rollback check, key
//!   table. Until the duress trigger is built (Milestone 9), a duress match
//!   returns `Unlock failed.` and changes nothing (decided 2026-10-05).
//! - `edit`: `add` and `rm` with the `update` journal (`docs/M4_READINESS.md`
//!   section 9).
//! - `export`: `list`, `get`, `clean-partials` (7.9, readiness 7.5).
//! - `init`: portable `init` and its resume (8.3; readiness 11 for cards).
//! - `status`.
//!
//! All interaction goes through [`Prompter`], which the CLI implements for
//! the terminal and `--secrets-stdin`, and tests implement with scripts.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use subtle::ConstantTimeEq;

use crate::crypto::cascade::StreamKeys;
use crate::crypto::{kdf, mac, random, wrap};
use crate::errors::Error;
use crate::header::{Header, Mode, PassphraseKind, SlotFields};
use crate::input::SecretLine;
use crate::journal::Record;
use crate::keytable::{self, KeyTable};
use crate::lock::VaultLock;
use crate::passphrase;
use crate::platform::fs::Dir;
use crate::records::{RollbackOutcome, Settings};
use crate::resources::{self, SystemMemory};
use crate::secrets::{SecretBuf, SecretBytes};
use crate::store::{self, JOURNAL, JOURNAL_TMP};

pub mod discard;
pub mod edit;
pub mod export;
pub mod init;
pub mod status;
mod update;

#[cfg(test)]
mod tests;

/// Everything an operation asks of the owner.
pub trait Prompter {
    /// One hidden secret line (terminal, or the next `--secrets-stdin` line).
    fn secret(&mut self, prompt: &str) -> Result<SecretLine, Error>;
    /// One card's text, under the whole-line rules (`docs/CLI.md` 2).
    fn card_text(
        &mut self,
        label: &str,
    ) -> Result<SecretBytes<{ crate::card::PAYLOAD_LEN }>, Error>;
    /// Interactive only: a PNG photo path for a card, or `None` to type the
    /// text. Non-interactive prompters return `None`.
    fn card_png_path(&mut self, label: &str) -> Result<Option<PathBuf>, Error>;
    /// A typed confirmation from the terminal device. `Ok(false)` when
    /// declined or when there is no terminal.
    fn confirm(&mut self, prompt: &str, phrase: &str) -> Result<bool, Error>;
    /// An acknowledgment ("Press Enter"); skipped without a terminal.
    fn acknowledge(&mut self, prompt: &str) -> Result<(), Error>;
    /// Shows a secret on the terminal device only.
    fn show_secret(&mut self, text: &str) -> Result<(), Error>;
    /// A message for standard error.
    fn notice(&mut self, text: &str);
    /// Whether retries are allowed (terminal input, no `--secrets-stdin`).
    fn interactive(&self) -> bool;
    /// Whether a terminal device is available.
    fn has_terminal(&self) -> bool;
}

/// Unix seconds now.
pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `YYYY-MM-DD` (UTC) for Unix seconds.
pub(crate) fn date(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    // Civil-from-days (H. Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// `YYYY-MM-DDTHH:MM:SSZ`.
pub fn timestamp(secs: u64) -> String {
    let rem = secs % 86_400;
    format!(
        "{}T{:02}:{:02}:{:02}Z",
        date(secs),
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

pub(crate) fn copy32(k: &SecretBytes<32>) -> Result<SecretBytes<32>, Error> {
    SecretBytes::take_from(&mut k.expose_secret().to_vec())
}

/// The key bundle `K_aes || K_chacha || K_mac` (7.2).
pub(crate) struct Bundle {
    pub(crate) k_aes: SecretBytes<32>,
    pub(crate) k_chacha: SecretBytes<32>,
    pub(crate) k_mac: SecretBytes<32>,
}

impl Bundle {
    pub(crate) fn generate() -> Result<Self, Error> {
        Ok(Self {
            k_aes: random::secret()?,
            k_chacha: random::secret()?,
            k_mac: random::secret()?,
        })
    }

    pub(crate) fn from_bytes(b: &SecretBytes<96>) -> Result<Self, Error> {
        let b = b.expose_secret();
        Ok(Self {
            k_aes: SecretBytes::take_from(&mut b[..32].to_vec())?,
            k_chacha: SecretBytes::take_from(&mut b[32..64].to_vec())?,
            k_mac: SecretBytes::take_from(&mut b[64..].to_vec())?,
        })
    }

    pub(crate) fn to_bytes(&self) -> SecretBytes<96> {
        let mut out = SecretBytes::<96>::zeroed();
        let o = out.expose_secret_mut();
        o[..32].copy_from_slice(self.k_aes.expose_secret());
        o[32..64].copy_from_slice(self.k_chacha.expose_secret());
        o[64..].copy_from_slice(self.k_mac.expose_secret());
        out
    }

    pub(crate) fn keytable_keys(&self) -> Result<StreamKeys, Error> {
        Ok(StreamKeys::new(
            copy32(&self.k_aes)?,
            copy32(&self.k_chacha)?,
        ))
    }

    pub(crate) fn journal_key(&self) -> Result<SecretBytes<32>, Error> {
        kdf::journal_key(&self.k_mac)
    }
}

/// Handles a typed passphrase for its kind (7.3). The word-list hint and
/// custom refusals are input-only and come before any Argon2id run.
pub(crate) fn handle(kind: PassphraseKind, raw: &[u8]) -> Result<SecretBuf, Error> {
    match kind {
        PassphraseKind::Words => {
            let h = passphrase::handle_words(raw).map_err(Error::Passphrase)?;
            passphrase::check_word_list(&h).map_err(Error::Passphrase)?;
            Ok(h)
        }
        PassphraseKind::Custom => {
            let c = passphrase::handle_custom(raw).map_err(Error::Passphrase)?;
            Ok(SecretBuf::take_from(
                &mut c.bytes().expose_secret().to_vec(),
            ))
        }
    }
}

/// The portable duress tag (9.6).
pub(crate) fn duress_tag(duress_key: &SecretBytes<32>, vault_id: &[u8; 16]) -> [u8; 64] {
    mac::hmac_sha512(
        duress_key.expose_secret(),
        &[b"pvault/v1/duress-tag", vault_id, b"portable"],
    )
}

/// A pending journal found at 5.7 step 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pending {
    None,
    Update,
    Init,
    Other(&'static str),
    /// A journal temp without a canonical record (residue).
    TempOnly,
}

pub(crate) fn pending(dir: &Dir) -> Result<Pending, Error> {
    let canonical = store::read_capped(dir, JOURNAL, crate::journal::MAX_JOURNAL_LEN, || {
        Error::JournalInvalid
    });
    match canonical {
        Ok(Some(bytes)) => Ok(match Record::parse(&bytes) {
            Ok(Record::Update(_)) => Pending::Update,
            Ok(Record::Init(_)) => Pending::Init,
            Ok(Record::Transition(t)) => Pending::Other(match t.op {
                crate::journal::TransitionOp::Recover => "recovery",
                crate::journal::TransitionOp::Convert => "conversion",
            }),
            Err(_) => Pending::Other("operation"),
        }),
        Ok(None) => Ok(if dir.exists(JOURNAL_TMP).map_err(Error::Io)? {
            Pending::TempOnly
        } else {
            Pending::None
        }),
        Err(_) => Ok(Pending::Other("operation")),
    }
}

/// Read or write access after the unlock (5.7 lock column).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// `list`, `get`: downgraded to the shared lock after the unlock.
    Read,
    /// `add`, `rm`: the exclusive lock throughout.
    Write,
}

/// An unlocked vault.
pub struct Session {
    pub(crate) path: PathBuf,
    pub(crate) dir: Dir,
    /// Held for the session's life; releasing it is its `Drop`.
    #[allow(dead_code)]
    pub(crate) lock: VaultLock,
    pub(crate) header: Header,
    pub(crate) bundle: Bundle,
    pub(crate) table: KeyTable,
    /// The `update` cleanup could not be finished (readiness 9.5).
    pub(crate) unresolved: bool,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Session([REDACTED])")
    }
}

impl Session {
    /// The vault's ID.
    pub fn vault_id(&self) -> [u8; 16] {
        self.header.core().vault_id
    }

    /// The current generation.
    pub fn generation(&self) -> u64 {
        self.header.core().generation
    }

    /// The vault folder.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Parses the vault's header (unauthenticated).
pub(crate) fn header_of(dir: &Dir) -> Result<Header, Error> {
    match store::read_header(dir)? {
        Some(h) => Ok(h),
        None => {
            if matches!(pending(dir)?, Pending::Init) {
                Err(Error::InitPending)
            } else {
                Err(Error::Unsupported("this folder is not a pvault vault"))
            }
        }
    }
}

/// Derives `master_pw` and checks the duress tag. On a duress match the
/// unlock fails with `Unlock failed.` and nothing is modified (Milestone 4
/// limitation; the trigger is Milestone 9).
pub(crate) fn derive_and_check_duress(
    header: &Header,
    raw: &SecretLine,
    run_duress: bool,
) -> Result<SecretBytes<32>, Error> {
    let core = header.core();
    let handled = handle(core.passphrase_kind, raw.as_bytes())?;
    let master = kdf::master_pw(&handled, &core.salt, core.argon2)?;
    drop(handled);
    let tag = match header.slots() {
        SlotFields::Portable(p) => p.duress_tag,
        SlotFields::Bound(_) => return Err(Error::BoundVault),
    };
    if let (true, Some(tag)) = (run_duress, tag) {
        let duress_key = match core.passphrase_kind {
            PassphraseKind::Words => {
                Some(kdf::passphrase_subkey(&master, kdf::PassphraseKey::Duress)?)
            }
            PassphraseKind::Custom => match passphrase::handle_words(raw.as_bytes()) {
                // N3: refused generated-word handling is a non-match; the
                // duress-only run is skipped.
                Err(_) => None,
                Ok(words) => {
                    let m2 = kdf::master_pw(&words, &core.salt, core.argon2)?;
                    Some(kdf::passphrase_subkey(&m2, kdf::PassphraseKey::Duress)?)
                }
            },
        };
        if let Some(k) = duress_key
            && bool::from(duress_tag(&k, &core.vault_id).ct_eq(&tag))
        {
            return Err(Error::HeaderInvalid); // `Unlock failed.`; no action
        }
    }
    Ok(master)
}

/// Unwraps the portable slot and verifies both MACs.
pub(crate) fn open_bundle(header: &Header, master: &SecretBytes<32>) -> Result<Bundle, Error> {
    let SlotFields::Portable(p) = header.slots() else {
        return Err(Error::BoundVault);
    };
    let k_slot = kdf::passphrase_subkey(master, kdf::PassphraseKey::PortableSlot)?;
    let bytes = wrap::unwrap::<96>(&k_slot, &p.slot_nonce, &p.slot_ct);
    let bundle = Bundle::from_bytes(&bytes)?;
    if !header.verify_core(&bundle.k_mac) || !header.verify_slots(&bundle.k_mac) {
        return Err(Error::HeaderInvalid);
    }
    Ok(bundle)
}

/// Reads and decrypts the current key table.
pub(crate) fn read_table(dir: &Dir, header: &Header, bundle: &Bundle) -> Result<KeyTable, Error> {
    let core = header.core();
    let file = dir
        .open_regular(store::keytable_name(core.keytable_gen), false)
        .map_err(|_| Error::KeyTableCorrupt)?
        .ok_or(Error::KeyTableCorrupt)?;
    keytable::read_file(
        file,
        &core.vault_id,
        core.keytable_gen,
        &core.keytable_digest,
        &bundle.keytable_keys()?,
        &SystemMemory,
    )
}

/// The rollback check and update (9.7), reported as a warning.
pub(crate) fn rollback(settings: Option<&Settings>, header: &Header, ui: &mut dyn Prompter) {
    let core = header.core();
    let outcome = match settings {
        Some(s) => s.rollback_observe(&core.vault_id, core.generation),
        None => RollbackOutcome::Unavailable("the settings folder is unavailable".into()),
    };
    match outcome {
        RollbackOutcome::Recorded => {}
        RollbackOutcome::Older { recorded } => ui.notice(&format!(
            "Warning: this vault is older than a copy opened on this computer before (generation {} < {recorded}). It may be an old copy.",
            core.generation
        )),
        RollbackOutcome::Full => ui.notice("Warning: the rollback record is full; this vault is not tracked."),
        RollbackOutcome::Unavailable(r) => {
            ui.notice(&format!("Warning: rollback detection is unavailable: {r}."))
        }
    }
}

/// The ordinary unlock (5.3 and 5.7).
pub fn unlock(
    vault: &Path,
    ui: &mut dyn Prompter,
    settings: Option<&Settings>,
    access: Access,
) -> Result<Session, Error> {
    // 1. Lock.
    let dir = Dir::open(vault).map_err(Error::Io)?;
    let mut lock = VaultLock::exclusive(&dir)?;
    // 2. Header (4.3, 4.4); a bound vault is refused by its public mode.
    let header = header_of(&dir)?;
    if header.core().mode != Mode::Portable {
        return Err(Error::BoundVault);
    }
    // 3. Argon2 limits.
    resources::check_argon2(&header.core().argon2, &SystemMemory)?;
    // 4. Passphrase and word-list check; 5. Argon2id; 6. duress check.
    let raw = ui.secret("Passphrase: ")?;
    let master = derive_and_check_duress(&header, &raw, true)?;
    drop(raw);
    // 7. Pending journal.
    let pend = pending(&dir)?;
    match pend {
        Pending::Init => return Err(Error::InitPending),
        Pending::Other(op) => return Err(Error::PendingJournal(op)),
        Pending::None | Pending::Update | Pending::TempOnly => {}
    }
    // Slot unwrap and both MACs.
    let bundle = open_bundle(&header, &master)?;
    drop(master);
    let mut header = header;
    let mut unresolved = false;
    if pend == Pending::Update {
        match update::resolve(&dir, &header, &bundle, ui)? {
            update::Resolution::Unresolved => unresolved = true,
            update::Resolution::Done => {}
        }
        // A roll-forward may have committed nothing new, but re-read anyway.
        header = store::read_header(&dir)?.ok_or(Error::HeaderInvalid)?;
        if !header.verify_core(&bundle.k_mac) || !header.verify_slots(&bundle.k_mac) {
            return Err(Error::Indeterminate);
        }
    }
    // Rollback check, then the key table.
    rollback(settings, &header, ui);
    let table = read_table(&dir, &header, &bundle)?;
    if access == Access::Read {
        lock.downgrade()?;
    }
    Ok(Session {
        path: vault.to_path_buf(),
        dir,
        lock,
        header,
        bundle,
        table,
        unresolved,
    })
}
