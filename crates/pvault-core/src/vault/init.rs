//! `init` and its resume (spec 8.3, 7.4a, 7.4b, 6.4; `docs/CLI.md` 6.1;
//! `docs/M4_READINESS.md` section 11; portable approved for Milestone 4,
//! bound for Milestone 5).
//!
//! Bound (D1 to D12): the TPM is checked first (C2, C3, the H-2 identity,
//! N2); the bundle is split 2-of-3; the `prepared` journal names the chosen
//! handle, both Names, the policy nonce and the scope-2 identity token
//! before the index is defined; S2 is written and both Names confirmed; S1
//! goes into the slots and S3 onto the single bound card. A failure before
//! `committing` removes the index under 9.2b and rolls the setup back.
//!
//! Order: bootstrap and preflight (8.3 steps 1 to 6), settings and card
//! destination checks, passphrase, Argon2id, `prepared`, key table
//! (`keytable_created`, `keytable_written`), card files W1 to W4, printing,
//! delivery verification and type-back (W5), `committing`, the first-header
//! commit (W6), card deletion through the held handles (W7, W8), journal
//! removal. Any failure before the commit runs W7 and W8 and rolls the setup
//! back; the cards of a rolled-back setup are invalid (7.4a).

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::card::{self, Card, CardMode};
use crate::crypto::kdf::{self, Argon2Params, PassphraseKey};
use crate::crypto::{random, wrap};
use crate::errors::Error;
use crate::estimator::{self, Band};
use crate::header::{
    BoundSlots, CoreFields, Header, Mode, PassphraseKind, PortableSlots, SlotFields,
};
use crate::journal::{self, Idx, InitPhase, InitRecord, Record};
use crate::keytable::{self, KeyTable};
use crate::lock::VaultLock;
use crate::passphrase::{self, CustomPassphrase, WordCount};
use crate::platform::fs::{self as pfs, Dir};
use crate::records::{
    CardEntry, CardRole, Delivery, OpKind, OpLock, RecordedFile, Settings, hex, native_path,
};
use crate::resources::{self, SystemMemory};
use crate::secrets::{SecretBuf, SecretBytes};
use crate::shamir;
use crate::store::{
    self, HEADER, HEADER_TMP, JOURNAL, JOURNAL_TMP, Owned, keytable_name, keytable_tmp_name,
};

use crate::tpm::{Tpm, TpmOptions, TpmState};
use crate::tpmid::{self, IndexContext, Scope};

use super::bound::{self, BoundKeys};
use super::{Bundle, Pending, Prompter, date, now, pending};

const LOCK_FILES: [&str; 2] = ["vault.gate", "vault.lock"];

/// How the main passphrase is chosen.
#[derive(Debug, Clone, Copy)]
pub enum PassphraseChoice {
    /// Generated words, shown on the terminal device only.
    Generated(WordCount),
    /// Written by the owner (estimated at creation, SI-51).
    Custom,
}

/// The strength estimate of a new custom passphrase: the band and fixed
/// feedback texts. The CLI uses [`estimator::estimate`]; tests inject one.
pub type Estimate<'a> = &'a dyn Fn(&CustomPassphrase, &str) -> Result<(Band, Vec<String>), Error>;

/// `init` options (`docs/CLI.md` 6.1).
pub struct InitOptions<'a> {
    /// The vault folder.
    pub vault: PathBuf,
    /// Paper or digital card delivery (SI-52 R1).
    pub delivery: Delivery,
    /// Paper: the card folder (outside the vault).
    pub cards_dir: PathBuf,
    /// Digital: Card A's folder.
    pub card_a_dir: Option<PathBuf>,
    /// Digital: Card B's folder.
    pub card_b_dir: Option<PathBuf>,
    /// Digital: `--accept-risk digital-cards` (SI-52 5).
    pub accept_digital_cards: bool,
    /// Digital: `--accept-risk same-volume` (SI-52 5).
    pub accept_same_volume: bool,
    /// Generated or custom.
    pub passphrase: PassphraseChoice,
    /// Argon2id parameters (already range-checked by the CLI).
    pub argon2: Argon2Params,
    /// Verify Card A from this PNG instead of typing.
    pub card_a_png: Option<PathBuf>,
    /// Verify Card B from this PNG instead of typing.
    pub card_b_png: Option<PathBuf>,
    /// The custom-passphrase estimator.
    pub estimate: Estimate<'a>,
    /// Portable or bound (`--mode`; required by the CLI, D9).
    pub mode: Mode,
    /// Bound, digital: the single card's folder (`--card-dir`, D8).
    pub card_dir: Option<PathBuf>,
    /// Bound, paper: verify the bound card from this PNG (`--card-png`).
    pub card_png: Option<PathBuf>,
    /// `--tpm`, `--tpm-owner-auth` (bound, and the resume of a bound setup).
    pub tpm: TpmOptions,
}

impl std::fmt::Debug for InitOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitOptions")
            .field("vault", &self.vault)
            .field("mode", &self.mode)
            .field("delivery", &self.delivery)
            .field("cards_dir", &self.cards_dir)
            .field("card_a_dir", &self.card_a_dir)
            .field("card_b_dir", &self.card_b_dir)
            .field("passphrase", &self.passphrase)
            .field("argon2", &self.argon2)
            .finish_non_exhaustive()
    }
}

/// What `init` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitOutcome {
    /// A new vault.
    Created {
        /// Its ID.
        vault_id: [u8; 16],
        /// Digital delivery: the saved card files (Card A and Card B, or the
        /// bound card), for the optional check after the commit
        /// ([`card_check_after_commit`]).
        card_files: Option<Vec<PathBuf>>,
    },
    /// An interrupted setup whose header was committed was finished.
    Finished {
        /// Its ID.
        vault_id: [u8; 16],
    },
    /// An interrupted setup without a header was removed.
    RolledBack,
}

/// The target folder after the bootstrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Empty,
    Occupied,
}

fn is_link(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink())
}

/// Empty apart from zero-length regular `vault.gate` / `vault.lock`.
fn target_state(t: &Dir) -> Result<Target, Error> {
    for n in t.list().map_err(Error::Io)? {
        let lock_file = n.to_str().is_some_and(|n| {
            LOCK_FILES.contains(&n)
                && matches!(t.open_regular(n, false), Ok(Some(f)) if f.metadata().is_ok_and(|m| m.len() == 0))
        });
        if !lock_file {
            return Ok(Target::Occupied);
        }
    }
    Ok(Target::Empty)
}

/// 8.3 bootstrap steps 1 to 6.
fn bootstrap(vault: &Path) -> Result<(Dir, VaultLock, Target), Error> {
    let vault = std::path::absolute(vault).map_err(Error::Io)?;
    let parent_path = vault
        .parent()
        .ok_or(Error::Unsupported("the vault folder needs a parent folder"))?;
    // A native name (7.2): any Unix bytes, any Windows UTF-16.
    let name = vault
        .file_name()
        .ok_or(Error::Unsupported("the vault folder needs a name"))?;
    if is_link(parent_path) || is_link(&vault) {
        return Err(Error::Unsupported(
            "a symbolic link or reparse point in the vault location",
        ));
    }
    // 1.
    let parent = Dir::open(parent_path).map_err(Error::Io)?;
    // 2.
    let created = if parent.exists(name).map_err(Error::Io)? {
        None
    } else {
        let vol = pfs::preflight(&parent)?;
        parent.create_dir(name).map_err(Error::Io)?;
        parent.flush().map_err(Error::Io)?;
        Some(vol)
    };
    // 3.
    let t = parent.open_dir(name).map_err(Error::Io)?;
    match &created {
        Some(vol) => pfs::same_volume(vol, &t)?,
        None => {
            pfs::preflight(&t)?;
        }
    }
    // An occupied target is examined only under the lock (resume or refuse).
    // 4.
    let lock = VaultLock::exclusive(&t)?;
    // 5.
    let state = target_state(&t)?;
    // 6.
    pfs::preflight(&t)?;
    Ok((t, lock, state))
}

fn write_init(
    t: &Dir,
    rec: &InitRecord,
    key: &crate::secrets::SecretBytes<32>,
) -> Result<(), Error> {
    let mut r = Record::Init(rec.clone());
    r.seal(key, None)?;
    store::write_journal(t, &r.encode())
}

/// The chosen passphrase, handled.
struct Chosen {
    kind: PassphraseKind,
    handled: SecretBuf,
    /// Custom and refused by generated-word handling (N3; D7).
    words_refused: bool,
}

fn choose_passphrase(
    choice: PassphraseChoice,
    estimate: Estimate<'_>,
    context: &str,
    ui: &mut dyn Prompter,
) -> Result<Chosen, Error> {
    match choice {
        PassphraseChoice::Generated(count) => {
            if !ui.has_terminal() {
                return Err(Error::NeedsTerminal(
                    "A generated passphrase is shown only on a terminal. Use --custom with --secrets-stdin.",
                ));
            }
            let words = passphrase::generate(count)?;
            let text = std::str::from_utf8(words.expose_secret())
                .map_err(|_| Error::Unsupported("word list"))?;
            let shown = Zeroizing::new(format!(
                "Your passphrase:\n\n    {text}\n\nEntropy: {:.1} bits. Rating: {}.\nWrite this passphrase down. Press Enter when done.",
                count.entropy_bits(),
                count.rating()
            ));
            ui.show_secret(&shown)?;
            drop(shown);
            let handled = super::handle(PassphraseKind::Words, words.expose_secret())?;
            Ok(Chosen {
                kind: PassphraseKind::Words,
                handled,
                words_refused: false,
            })
        }
        PassphraseChoice::Custom => {
            let attempts = if ui.interactive() { 3 } else { 1 };
            let mut accepted = None;
            for attempt in 1..=attempts {
                let a = ui.secret("Enter the new passphrase: ")?;
                let b = ui.secret("Enter it again: ")?;
                if bool::from(a.as_bytes().ct_eq(b.as_bytes())) {
                    accepted = Some(a);
                    break;
                }
                ui.notice(&Error::PassphraseMismatch.to_string());
                if attempt == attempts {
                    return Err(Error::PassphraseMismatch);
                }
            }
            let raw = accepted.ok_or(Error::PassphraseMismatch)?;
            let custom = passphrase::handle_custom(raw.as_bytes()).map_err(Error::Passphrase)?;
            let words_refused = passphrase::handle_words(raw.as_bytes()).is_err();
            drop(raw);
            for w in custom.warnings() {
                ui.notice(&w.to_string());
            }
            if custom.nfc_changed() {
                ui.notice(passphrase::NFC_NOTICE);
            }
            let (band, feedback) = estimate(&custom, context)?;
            ui.notice(&format!("{band}. {}", estimator::ESTIMATE_WARNING));
            for f in feedback {
                ui.notice(&f);
            }
            match band {
                Band::Weak => return Err(Error::PassphraseWeak),
                Band::Medium => {
                    if !ui.has_terminal() {
                        return Err(Error::NeedsTerminal(
                            "A medium passphrase needs the confirmation ACCEPT MEDIUM PASSPHRASE on a terminal.",
                        ));
                    }
                    let phrase = estimator::MEDIUM_ACKNOWLEDGMENT;
                    if !ui.confirm(&format!("Type {phrase} to use it: "), phrase)? {
                        return Err(Error::Cancelled);
                    }
                }
                Band::Strong => {}
            }
            let handled = SecretBuf::take_from(&mut custom.bytes().expose_secret().to_vec());
            Ok(Chosen {
                kind: PassphraseKind::Custom,
                handled,
                words_refused,
            })
        }
    }
}

/// Reads a PNG photo (bounded) and decodes the card payload.
fn read_png(path: &Path) -> Result<crate::secrets::SecretBytes<{ card::PAYLOAD_LEN }>, Error> {
    let file = File::open(path).map_err(Error::Io)?;
    if file.metadata().map_err(Error::Io)?.len() > card::MAX_PNG_FILE {
        return Err(Error::Png(card::PngError::TooLarge));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(card::MAX_PNG_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(Error::Io)?;
    card::decode_png(&bytes).map_err(Error::Png)
}

/// Errors that end verification at once instead of using up an attempt.
fn ends_attempts(e: &Error) -> bool {
    matches!(
        e,
        Error::Cancelled | Error::Input(_) | Error::NeedsTerminal(_) | Error::Random(_)
    )
}

/// Delivery verification of one card (6.4): the whole decoded payload must
/// equal the expected one.
fn verify_card(
    card: &Card,
    label: &'static str,
    png: Option<&Path>,
    ui: &mut dyn Prompter,
) -> Result<SecretBytes<{ card::PAYLOAD_LEN }>, Error> {
    let attempts = if png.is_none() && ui.interactive() {
        3
    } else {
        1
    };
    for attempt in 1..=attempts {
        let decoded = match png {
            Some(p) => read_png(p),
            None if ui.interactive() => match ui.card_png_path(label)? {
                Some(p) => read_png(&p),
                None => ui.card_text(label),
            },
            None => ui.card_text(label),
        };
        // On success the delivered payload itself is returned: the
        // rehearsal (SI-52 6.4) uses it, never the in-memory original.
        let result = decoded.and_then(|payload| {
            if card.matches(&payload) {
                Ok(payload)
            } else {
                // Report structure errors of the entered card; never its content.
                match Card::parse(payload) {
                    Err(e) => Err(Error::Card(e)),
                    Ok(other) if other.vault_id() != card.vault_id() => {
                        Err(Error::Card(card::CardError::OtherVault))
                    }
                    Ok(other) if other.set_id() != card.set_id() => {
                        Err(Error::Card(card::CardError::OldCard))
                    }
                    Ok(_) => Err(Error::CardMismatch(label)),
                }
            }
        });
        match result {
            Ok(payload) => return Ok(payload),
            Err(e) if ends_attempts(&e) || attempt == attempts => return Err(e),
            Err(e) => ui.notice(&e.to_string()),
        }
    }
    Err(Error::CardMismatch(label))
}

/// Type-back from memory (6.4).
fn type_back(chosen: &Chosen, ui: &mut dyn Prompter) -> Result<(), Error> {
    let attempts = if ui.interactive() { 3 } else { 1 };
    for attempt in 1..=attempts {
        let raw = ui.secret("Type your passphrase from memory: ")?;
        let ok = super::handle(chosen.kind, raw.as_bytes())
            .is_ok_and(|h| bool::from(h.expose_secret().ct_eq(chosen.handled.expose_secret())));
        if ok {
            return Ok(());
        }
        ui.notice(&Error::PassphraseMismatch.to_string());
        if attempt == attempts {
            break;
        }
    }
    Err(Error::PassphraseMismatch)
}

/// One card file, held open from creation to its end (`docs/M4_READINESS.md`
/// 11.2; SI-52 11).
struct CardFile {
    dir: Dir,
    name: String,
    path: PathBuf,
    file: File,
}

/// The card files of one operation: paper (temporary print artifacts) or
/// digital (the owner's permanent files).
struct CardFiles<'a> {
    settings: &'a Settings,
    lock: OpLock,
    files: Vec<CardFile>,
    registered: bool,
}

/// Reads at most [`card::MAX_CARD_FILE`] + 1 bytes into wiped memory.
pub(crate) fn read_bounded(file: &File) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut bytes = Zeroizing::new(Vec::new());
    let f: &File = file;
    f.take(card::MAX_CARD_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(Error::Io)?;
    Ok(bytes)
}

impl<'a> CardFiles<'a> {
    /// W1 to W4 (paper) and D1 to D4 (digital). `targets` are the folder of
    /// each card; for paper every card goes to the same folder. Portable:
    /// Card A and Card B; bound: the one bound card.
    #[allow(clippy::too_many_arguments)]
    fn write(
        settings: &'a Settings,
        targets: Vec<(Dir, PathBuf)>,
        cards: &[(&Card, CardRole, &str)],
        vault_id: &[u8; 16],
        set_id: &[u8; 8],
        delivery: Delivery,
        vault_path: Vec<u8>,
    ) -> Result<Self, Error> {
        // W1 / D1 (the settings policy was checked before anything else).
        let lock = settings.begin_operation(OpKind::Cards)?;
        let mut this = Self {
            settings,
            lock,
            files: Vec::new(),
            registered: false,
        };
        let result = (|| -> Result<(), Error> {
            // W2 / D2.
            let mut entries = Vec::new();
            let created_at = now();
            for ((dir, dir_path), (_, role, suffix)) in targets.into_iter().zip(cards) {
                let name = format!(
                    "pvault-{}-{}-{suffix}.svg",
                    hex(&vault_id[..4]),
                    hex(&set_id[..4])
                );
                let path = dir_path.join(&name);
                let file = dir.create_new(&name).map_err(|e| match e.kind() {
                    std::io::ErrorKind::AlreadyExists => {
                        Error::NameExists(crate::render::path(&path))
                    }
                    std::io::ErrorKind::InvalidFilename => Error::NameTooLong,
                    _ => Error::Io(e),
                })?;
                let id = pfs::record_identity(&file).map_err(Error::Io);
                this.files.push(CardFile {
                    dir,
                    name,
                    path: path.clone(),
                    file,
                });
                entries.push(CardEntry {
                    op_id: this.lock.id(),
                    role: *role,
                    set_id: *set_id,
                    vault_id: *vault_id,
                    created_at,
                    file: RecordedFile {
                        path: native_path(&path).ok_or(Error::PathTooLongToTrack)?,
                        id: id?,
                    },
                    delivery,
                    vault_path: Some(vault_path.clone()),
                });
            }
            failpoint!("init.cards-created");
            // W3 / D3.
            this.registered = true;
            settings.register_cards(entries).map_err(|e| match e {
                Error::NotRegistered(_) => Error::NotRegistered("card files"),
                other => other,
            })?;
            failpoint!("init.cards-registered");
            // W4 / D4.
            let today = date(created_at);
            for ((card, _, _), f) in cards.iter().zip(&this.files) {
                let svg = card::render_svg(card, &today)?;
                let mut w: &File = &f.file;
                w.write_all(svg.as_bytes()).map_err(Error::Io)?;
                pfs::flush_file(&f.file).map_err(Error::Io)?;
            }
            for f in &this.files {
                f.dir.flush().map_err(Error::Io)?;
            }
            failpoint!("init.cards-written");
            #[cfg(test)]
            hooks::after_cards_written(
                &this
                    .files
                    .iter()
                    .map(|f| f.path.clone())
                    .collect::<Vec<_>>(),
            );
            Ok(())
        })();
        match result {
            Ok(()) => Ok(this),
            Err(e) => {
                // Before `committing`: the cards can never be valid (SI-52 8.1).
                report_kept(&this.delete(), None);
                Err(e)
            }
        }
    }

    /// The written paths, rendered.
    fn shown(&self) -> Vec<String> {
        self.files
            .iter()
            .map(|f| crate::render::path(&f.path))
            .collect()
    }

    /// Digital delivery (SI-52 6.4 step 1): reopen each file by name without
    /// following links, require the identity of the handle pvault created,
    /// read it through the format 1 reader and compare it with the card
    /// that was written. Returns the payloads read from the files.
    fn read_back(
        &self,
        expected: &[(&Card, &'static str)],
    ) -> Result<Vec<SecretBytes<{ card::PAYLOAD_LEN }>>, Error> {
        let mut out = Vec::with_capacity(expected.len());
        for (f, &(card, label)) in self.files.iter().zip(expected) {
            let reopened = f
                .dir
                .open_regular(&f.name, false)
                .map_err(Error::Io)?
                .ok_or(Error::CardFileChanged(label))?;
            let held = f.dir.identity(&f.file).map_err(Error::Io)?;
            if f.dir.identity(&reopened).map_err(Error::Io)? != held {
                return Err(Error::CardFileChanged(label));
            }
            let bytes = read_bounded(&reopened)?;
            let read = card::parse_card_file(&bytes).map_err(Error::CardFile)?;
            if !card.matches(&SecretBytes::take_from(&mut read.payload().to_vec())?) {
                return Err(Error::CardFileChanged(label));
            }
            out.push(SecretBytes::take_from(&mut read.payload().to_vec())?);
        }
        if out.len() != expected.len() {
            return Err(Error::RehearsalFailed);
        }
        Ok(out)
    }

    /// W7 and W8, or the in-process rollback before `committing` (both
    /// modes): delete through the held handles. Returns the paths left.
    fn delete(self) -> Vec<String> {
        let mut kept = Vec::new();
        for f in &self.files {
            if !f.dir.delete_held(&f.name, &f.file).unwrap_or(false) {
                kept.push(crate::render::path(&f.path));
            }
        }
        for f in &self.files {
            let _ = f.dir.flush();
        }
        failpoint!("init.cards-deleted");
        drop(self.files);
        if !self.registered || self.settings.unregister_cards(&self.lock.id()).is_ok() {
            self.lock.finish();
        }
        kept
    }

    /// D7 (digital, after the commit): keep the files, remove the entries.
    fn release(self) {
        drop(self.files);
        failpoint!("init.cards-released");
        if self.settings.unregister_cards(&self.lock.id()).is_ok() {
            self.lock.finish();
        }
    }

    /// Digital, after the `committing` attempt, when the outcome is not
    /// known to be a commit: keep the files and the entries (SI-52 8.1).
    fn retain(self) {
        drop(self.files);
        drop(self.lock);
    }
}

#[cfg(test)]
pub(crate) mod hooks {
    use std::cell::RefCell;
    use std::path::PathBuf;

    type Hook = Box<dyn FnOnce(&[PathBuf])>;

    thread_local! {
        static AFTER_CARDS: RefCell<Option<Hook>> = RefCell::new(None);
    }

    /// Runs `hook` once with the card file paths, right after they are
    /// written and before delivery verification.
    pub(crate) fn set_after_cards_written(hook: impl FnOnce(&[PathBuf]) + 'static) {
        AFTER_CARDS.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    pub(super) fn after_cards_written(paths: &[PathBuf]) {
        if let Some(hook) = AFTER_CARDS.with(|h| h.borrow_mut().take()) {
            hook(paths);
        }
    }

    type DefineHook = Box<dyn FnOnce(u32)>;

    thread_local! {
        static BEFORE_DEFINE: RefCell<Option<DefineHook>> = RefCell::new(None);
    }

    /// Runs `hook` once with the chosen handle, after the `prepared` journal
    /// and before `NV_DefineSpace` (F87: another program takes the handle).
    #[cfg_attr(not(all(target_os = "linux", feature = "tpm")), allow(dead_code))]
    pub(crate) fn set_before_define(hook: impl FnOnce(u32) + 'static) {
        BEFORE_DEFINE.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    pub(super) fn before_define(handle: u32) {
        if let Some(hook) = BEFORE_DEFINE.with(|h| h.borrow_mut().take()) {
            hook(handle);
        }
    }

    type Hook0 = Box<dyn FnOnce()>;

    thread_local! {
        static AFTER_COMMIT: RefCell<Option<Hook0>> = RefCell::new(None);
    }

    /// Runs `hook` once right after the first header commit, before the
    /// journal is removed (F59: a panic there leaves the post-commit state).
    #[cfg_attr(not(all(target_os = "linux", feature = "tpm")), allow(dead_code))]
    pub(crate) fn set_after_commit(hook: impl FnOnce() + 'static) {
        AFTER_COMMIT.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    pub(super) fn after_commit() {
        if let Some(hook) = AFTER_COMMIT.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }
}

/// The recovery rehearsal (SI-52 6.4): from the delivered payloads only,
/// through the recovery path, against the candidate header and key table.
pub(crate) fn rehearse(
    t: &Dir,
    delivered: &[SecretBytes<{ card::PAYLOAD_LEN }>; 2],
    candidate: &[u8],
) -> Result<(), Error> {
    let header = Header::parse(candidate)?;
    let core = header.core();
    let mut cards = Vec::with_capacity(2);
    for p in delivered {
        let c = Card::parse(SecretBytes::take_from(&mut p.expose_secret().to_vec())?)
            .map_err(Error::Card)?;
        c.check_for_vault(&core.vault_id, &core.card_set_id, CardMode::Portable)
            .map_err(Error::Card)?;
        cards.push(c);
    }
    card::check_portable_roles(&cards[0], &cards[1]).map_err(Error::Card)?;
    let secret = shamir::combine(&cards[0].share()?, &cards[1].share()?)?;
    let recovered = Bundle::from_bytes(&secret)?;
    drop(secret);
    if !header.verify_core(&recovered.k_mac) || !header.verify_slots(&recovered.k_mac) {
        return Err(Error::RehearsalFailed);
    }
    let table = t
        .open_regular(keytable_name(core.keytable_gen), false)
        .map_err(Error::Io)?
        .ok_or(Error::RehearsalFailed)?;
    keytable::read_file(
        table,
        &core.vault_id,
        core.keytable_gen,
        &core.keytable_digest,
        &recovered.keytable_keys()?,
        &SystemMemory,
    )
    .map_err(|_| Error::RehearsalFailed)?;
    Ok(())
}

/// The digital-card risk text (SI-52 5, 10), printed in every case.
pub const DIGITAL_RISKS: &str = "Digital recovery cards: Card A and Card B together open this vault without the passphrase. Keep them on different drives in different places, never in one cloud account or one backup set, and never both on the computer that holds the vault. Losing a card's drive loses that card; with the passphrase forgotten and one card lost, the vault cannot be recovered. Deleting a card file does not erase it from flash storage, snapshots, backups, cloud history or thumbnail caches. pvault never deletes these files after the vault is created.";

/// The bound digital card's risk text (D8), printed in every case.
pub const DIGITAL_RISKS_BOUND: &str = "Digital recovery card: this card file together with your passphrase opens this vault without the TPM. Keep it on a drive in a different place, never in a cloud account or a backup set shared with the vault, and never on the computer that holds the vault. Losing the card's drive loses the card; with the passphrase forgotten, the card alone recovers nothing. Deleting a card file does not erase it from flash storage, snapshots, backups, cloud history or thumbnail caches. pvault never deletes this file after the vault is created.";

#[cfg(test)]
thread_local! {
    static MOCK_SYNC_ROOTS: std::cell::RefCell<Option<Vec<PathBuf>>> =
        const { std::cell::RefCell::new(None) };
}

/// Replaces the listed sync roots on this thread (`None` restores them).
#[cfg(test)]
pub(crate) fn mock_sync_roots(roots: Option<Vec<PathBuf>>) {
    MOCK_SYNC_ROOTS.with(|m| *m.borrow_mut() = roots);
}

/// The well-known sync roots of R4: a best-effort list, not exhaustive.
fn sync_roots() -> Vec<PathBuf> {
    #[cfg(test)]
    if let Some(r) = MOCK_SYNC_ROOTS.with(|m| m.borrow().clone()) {
        return r;
    }
    let mut roots = Vec::new();
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        let home = PathBuf::from(home);
        roots.push(home.join("Library").join("Mobile Documents"));
        roots.push(home.join("Library").join("CloudStorage"));
        roots.push(home.join("Dropbox"));
    }
    for var in ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"] {
        if let Some(p) = std::env::var_os(var) {
            roots.push(PathBuf::from(p));
        }
    }
    roots
}

/// The listed sync root containing `path`, if any (SI-52 R4); not
/// exhaustive, and never presented as such.
fn sync_root(path: &Path) -> Option<PathBuf> {
    let roots = sync_roots();
    let real = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    roots.into_iter().find(|r| {
        let r = std::fs::canonicalize(r).unwrap_or_else(|_| r.clone());
        real.starts_with(&r)
    })
}

fn open_card_folder(p: &Path) -> Result<(Dir, PathBuf), Error> {
    let abs = std::path::absolute(p).map_err(Error::Io)?;
    if is_link(&abs) {
        return Err(Error::Unsupported(
            "a card folder is a symbolic link or reparse point",
        ));
    }
    let dir = Dir::open(&abs).map_err(Error::Io)?;
    // O3 and G1: owner-only access must be verifiable (exit 6).
    pfs::check_private_destination(&dir)?;
    Ok((dir, abs))
}

/// SI-52 D0 for digital mode: folders, acknowledgments and warnings, all
/// before any secret is read or anything is created. Portable: Card A's and
/// Card B's folders; bound: the single card's folder (D8; no same-volume
/// acknowledgment, since there is one card).
fn digital_preflight(
    opts: &InitOptions<'_>,
    ui: &mut dyn Prompter,
) -> Result<Vec<(Dir, PathBuf)>, Error> {
    let bound = opts.mode == Mode::Bound;
    let (folders, labels): (Vec<(Dir, PathBuf)>, &[&str]) = if bound {
        let c = open_card_folder(
            opts.card_dir
                .as_deref()
                .ok_or(Error::Unsupported("a digital bound card needs --card-dir"))?,
        )?;
        (vec![c], &["The bound card"])
    } else {
        let a = open_card_folder(opts.card_a_dir.as_deref().ok_or(Error::Unsupported(
            "digital cards need --card-a-dir and --card-b-dir",
        ))?)?;
        let b = open_card_folder(opts.card_b_dir.as_deref().ok_or(Error::Unsupported(
            "digital cards need --card-a-dir and --card-b-dir",
        ))?)?;
        if a.0.contains(&b.0).map_err(Error::Io)? && b.0.contains(&a.0).map_err(Error::Io)? {
            return Err(Error::SameCardFolder);
        }
        (vec![a, b], &["Card A", "Card B"])
    };
    ui.notice(if bound {
        DIGITAL_RISKS_BOUND
    } else {
        DIGITAL_RISKS
    });
    if !opts.accept_digital_cards {
        let phrase = "STORE CARDS DIGITALLY";
        if !ui.has_terminal() || !ui.confirm(&format!("Type {phrase} to continue: "), phrase)? {
            return Err(Error::AckRequired(
                "Digital recovery cards need your acknowledgment: give --accept-risk digital-cards, or type STORE CARDS DIGITALLY on a terminal. Nothing was written.",
            ));
        }
    }
    let volumes = folders
        .iter()
        .map(|f| f.0.volume())
        .collect::<Result<Vec<_>, _>>()
        .map_err(Error::Io)?;
    if !bound && volumes[0] == volumes[1] {
        ui.notice(&format!(
            "Card A and Card B are on the same volume ({}). Anyone who gets that drive, its backups or its synced copies gets both cards, which open the vault without the passphrase. Different volumes are not proof of different devices either: keep the cards on separate drives in separate places.",
            volumes[0].fs_type
        ));
        if !opts.accept_same_volume {
            let phrase = "SAME DRIVE";
            if !ui.has_terminal()
                || !ui.confirm(
                    &format!("Type {phrase} to keep both cards on this drive: "),
                    phrase,
                )?
            {
                return Err(Error::AckRequired(
                    "Both cards on one volume need your acknowledgment: give --accept-risk same-volume, or type SAME DRIVE on a terminal. Nothing was written.",
                ));
            }
        }
    }
    let vault_abs = std::path::absolute(&opts.vault).map_err(Error::Io)?;
    if let Some(parent) = vault_abs.parent()
        && let Ok(pv) = Dir::open(parent).and_then(|d| d.volume())
    {
        for (label, v) in labels.iter().zip(&volumes) {
            if *v == pv {
                ui.notice(&format!(
                    "Warning: {label} is on the same drive as the vault."
                ));
            }
        }
    }
    for (label, (_, p)) in labels.iter().zip(&folders) {
        if let Some(root) = sync_root(p) {
            ui.notice(&format!(
                "Warning: {label}'s folder is inside {}, which is usually synced to a cloud account: the card would be copied to the provider, to other devices and to version history. pvault cannot detect every synced or backed-up folder, so no warning does not mean not synced.",
                crate::render::path(&root)
            ));
        }
    }
    Ok(folders)
}

/// Removes the authenticated init artifacts (rollback) and the journal.
fn rollback_setup(t: &Dir, rec: &InitRecord) -> Result<(), Error> {
    if let Some(id) = &rec.keytable_id {
        for name in [keytable_tmp_name(1), keytable_name(1)] {
            pfs::remove_if_owned(t, &name, id).map_err(Error::Io)?;
        }
    }
    if let Some(id) = &rec.header_id {
        pfs::remove_if_owned(t, HEADER_TMP, id).map_err(Error::Io)?;
    }
    t.flush().map_err(Error::Io)?;
    store::remove_journal(t)
}

fn report_kept(kept: &[String], ui: Option<&mut dyn Prompter>) {
    if let Some(ui) = ui {
        for k in kept {
            ui.notice(&format!(
                "The card file {k} was moved or replaced and was not deleted; delete it yourself. It may hold a recovery card."
            ));
        }
    }
}

/// A bound setup in progress: the TPM, its identity and the index this
/// setup defined (journal form, with the pre-write Name).
struct BoundSetup {
    tpm: Box<dyn Tpm>,
    state: TpmState,
    ek: SecretBytes<32>,
    owner: Option<SecretBuf>,
    keys: BoundKeys,
    index: IndexContext,
    s1: shamir::Share,
    s3: shamir::Share,
    s2_nonce: [u8; 24],
}

/// Bound: chooses a handle, journals it (with the scope-2 token) before
/// `NV_DefineSpace`, defines the index, confirms the pre-write public area,
/// writes S2 and confirms the post-write one (8.3, 9.1; SI-35). A raced
/// handle (`TPM_RC_NV_DEFINED`, F87) rolls back and starts over with a new
/// journal; an unknown outcome (F88) keeps the journal.
#[allow(clippy::too_many_arguments)]
fn bound_index(
    t: &Dir,
    rec: &mut InitRecord,
    init_key: &SecretBytes<32>,
    master: &SecretBytes<32>,
    bundle: &Bundle,
    mut tpm: Box<dyn Tpm>,
    state: TpmState,
    ek: [u8; 32],
    owner: Option<SecretBuf>,
) -> Result<BoundSetup, Error> {
    let keys = BoundKeys::derive(master)?;
    let ek = SecretBytes::take_from(&mut ek.to_vec())?;
    let [s1, s2, s3] = shamir::split_2_of_3(&bundle.to_bytes())?;
    let (s2_nonce, data) = bound::index_data(&s2, &keys.s2)?;
    drop(s2);
    for attempt in 0..3 {
        let handle = crate::tpm::free_handle(tpm.as_mut())?;
        let nonce = random::array::<32>()?;
        let (pre, post) = crate::tpm::expected_names(handle, &nonce);
        let index = IndexContext {
            tpm_index: handle,
            name_prewrite: Some(pre),
            name_postwrite: post,
            policy_nonce: nonce,
        };
        let token = tpmid::seal(Scope::Init, init_key, &rec.vault_id, &index, &ek)?;
        rec.idx = Some(Idx { index, token });
        // Write-ahead (8.1): durable before the index can exist.
        write_init(t, rec, init_key)?;
        failpoint!("init.prepared");
        #[cfg(test)]
        hooks::before_define(handle);
        match tpm.define(handle, &nonce, &keys.auth, owner.as_ref()) {
            Ok(()) => {}
            Err(Error::TpmHandleTaken) if attempt < 2 => {
                // Nothing was created (F87): the normal rollback, then a new
                // journal; the index fields are never rewritten in place.
                store::remove_journal(t)?;
                rec.idx = None;
                continue;
            }
            // The index may exist: keep the journal for the resume (F88).
            Err(Error::TpmDefineUnknown) => return Err(Error::TpmDefineUnknown),
            Err(e) => {
                store::remove_journal(t)?;
                return Err(e);
            }
        }
        // Tests: a definition whose outcome is unknown (F88): the index
        // exists, but the process cannot tell.
        fail_io!("init.define-unknown").map_err(|_| Error::TpmDefineUnknown)?;
        failpoint!("init.index-defined");
        let mut setup = BoundSetup {
            tpm,
            state,
            ek,
            owner,
            keys,
            index,
            s1,
            s3,
            s2_nonce,
        };
        let written = (|| -> Result<(), Error> {
            let found = setup.tpm.read_public(handle)?;
            if !found.is_some_and(|p| p.matches(handle, &nonce, false) && p.name == pre) {
                return Err(Error::Tpm(
                    "the new index does not have the expected public area".into(),
                ));
            }
            setup.tpm.write(handle, &setup.keys.auth, &data)?;
            failpoint!("init.index-written");
            let found = setup.tpm.read_public(handle)?;
            if !found.is_some_and(|p| p.matches(handle, &nonce, true) && p.name == post) {
                return Err(Error::Tpm(
                    "the written index does not have the expected Name".into(),
                ));
            }
            Ok(())
        })();
        if let Err(e) = written {
            let _ = rollback_all(t, rec, Some(&mut setup));
            return Err(e);
        }
        return Ok(setup);
    }
    Err(Error::TpmNoFreeHandle)
}

/// The rollback of an uncommitted setup: bound first removes the index it
/// defined under 9.2b (same TPM, exact public area, journaled Name); if that
/// fails the journal is kept so that `pvault init` can resolve it later.
fn rollback_all(t: &Dir, rec: &InitRecord, setup: Option<&mut BoundSetup>) -> Result<(), Error> {
    if let Some(s) = setup {
        bound::remove_owned(s.tpm.as_mut(), &s.index, &s.ek, s.owner.as_ref())?;
    }
    rollback_setup(t, rec)
}

/// The optional duress step of an interactive `init` (6.10, D5 to D7):
/// returns the header bytes with the tag, or `None` when skipped.
fn init_duress(
    chosen: &Chosen,
    core: &CoreFields,
    slots: &SlotFields,
    k_mac: &SecretBytes<32>,
    bound_setup: Option<&BoundSetup>,
    ui: &mut dyn Prompter,
) -> Result<Option<Vec<u8>>, Error> {
    let ek = match bound_setup {
        Some(b) => {
            let why = b.state.duress_unavailable(true);
            if !why.is_empty() {
                ui.notice(&Error::DuressUnavailable(why.join(", ")).to_string());
                return Ok(None);
            }
            let mut ek = [0u8; 32];
            ek.copy_from_slice(b.ek.expose_secret());
            Some(ek)
        }
        None => None,
    };
    let phrase = "SET DURESS";
    if !ui.confirm(
        &format!("Type {phrase} to create a duress passphrase now, or press Enter to skip: "),
        phrase,
    )? {
        return Ok(None);
    }
    if chosen.words_refused {
        ui.notice(super::duress::N3_NOTICE);
    }
    let mut is_main = |raw: &[u8]| -> Result<bool, Error> {
        Ok(super::handle(chosen.kind, raw)
            .is_ok_and(|h| bool::from(h.expose_secret().ct_eq(chosen.handled.expose_secret()))))
    };
    let words = super::duress::new_duress_words(ui, &mut is_main)?;
    let slots = super::duress::slots_with_tag(core, slots, &words, ek.as_ref())?;
    drop(words);
    ui.notice("Duress passphrase set. It is inactive in this version: entering it fails like a wrong passphrase and changes nothing.");
    Ok(Some(Header::build(core, &slots, k_mac)?))
}

/// `pvault init`: a new vault, or the resume of an interrupted setup.
pub fn init(
    opts: &InitOptions<'_>,
    settings: &Settings,
    ui: &mut dyn Prompter,
) -> Result<InitOutcome, Error> {
    let digital = opts.delivery == Delivery::Digital;
    let bound_mode = opts.mode == Mode::Bound;
    // A PNG photo of a printed card can exist only after the cards are
    // written and printed: its verification waits for the printing
    // acknowledgment on the terminal device (decided 2026-10-06, O1), also
    // under `--secrets-stdin`. Without a terminal it is refused here, before
    // any bootstrap creation.
    let photos = opts.card_a_png.is_some() || opts.card_b_png.is_some() || opts.card_png.is_some();
    if photos && digital {
        return Err(Error::Unsupported(
            "PNG verification belongs to paper cards",
        ));
    }
    if photos && !ui.has_terminal() {
        return Err(Error::NeedsTerminal(
            "Verifying a card from a PNG photo needs a terminal for the printing acknowledgment, also with --secrets-stdin. Nothing was written.",
        ));
    }
    // Bound (D10, N2, 9.3): the TPM is checked before anything is created
    // and before any secret is read.
    let mut tpm_pre = None;
    if bound_mode {
        let mut tpm = bound::connect(&opts.tpm)?;
        let state = tpm.state()?;
        if !state.storage_enabled() {
            return Err(Error::TpmHierarchyDisabled);
        }
        if state.in_lockout() {
            return Err(Error::TpmLockout);
        }
        let ek = tpm.ek_digest()?;
        bound::owner_auth_possible(&opts.tpm, &state, ui)?;
        tpm_pre = Some((tpm, state, ek));
    }
    // O3 (decided 2026-10-06): card files hold shares and must stay
    // owner-only; an unverifiable card folder is refused before anything is
    // created, the vault folder included. (A resume without card options
    // writes no card file.)
    let mut targets = None;
    if digital {
        targets = Some(digital_preflight(opts, ui)?);
    } else if !opts.cards_dir.as_os_str().is_empty() {
        let cards_path = std::path::absolute(&opts.cards_dir).map_err(Error::Io)?;
        if let Ok(dir) = Dir::open(&cards_path) {
            pfs::check_private_destination(&dir)?;
        }
    }
    let (t, _lock, state) = bootstrap(&opts.vault)?;
    if state == Target::Occupied {
        return resume(&t, settings, ui, opts);
    }
    let card_count = if bound_mode { 1 } else { 2 };
    // Settings and card destination, before any vault artifact.
    settings.check_registration()?;
    settings.check_card_room(card_count)?;
    let vault_abs = std::path::absolute(&opts.vault).map_err(Error::Io)?;
    let vault_path = native_path(&vault_abs).ok_or(Error::PathTooLongToTrack)?;
    let folders: Vec<(Dir, PathBuf)> = match targets {
        Some(v) => v,
        None => {
            let cards_path = std::path::absolute(&opts.cards_dir).map_err(Error::Io)?;
            if is_link(&cards_path) {
                return Err(Error::Unsupported(
                    "the card folder is a symbolic link or reparse point",
                ));
            }
            (0..card_count)
                .map(|_| Dir::open(&cards_path).map(|d| (d, cards_path.clone())))
                .collect::<Result<_, _>>()
                .map_err(Error::Io)?
        }
    };
    for (dir, _) in &folders {
        if t.contains(dir).map_err(Error::Io)? {
            return Err(Error::CardDestinationInVault);
        }
        // Again on the handle the cards are written through (O3, G1).
        pfs::check_private_destination(dir)?;
    }
    opts.argon2.check_hard_caps()?;
    resources::check_argon2(&opts.argon2, &SystemMemory)?;
    let context = opts
        .vault
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .chars()
        .take(64)
        .collect::<String>();
    let chosen = choose_passphrase(opts.passphrase, opts.estimate, &context, ui)?;
    // Bound: the owner authorization, after the passphrase (D9).
    let owner = match &tpm_pre {
        Some((_, state, _)) => bound::owner_auth(&opts.tpm, state, ui)?,
        None => None,
    };
    ui.notice("Deriving keys…");
    let vault_id = random::array::<16>()?;
    let setup_id = random::array::<16>()?;
    let salt = random::array::<32>()?;
    let set_id = random::array::<8>()?;
    let master = kdf::master_pw(&chosen.handled, &salt, opts.argon2)?;
    let init_key = kdf::init_journal_key(&master)?;
    let bundle = Bundle::generate()?;
    let mut rec = InitRecord {
        phase: InitPhase::Prepared,
        vault_id,
        setup_id,
        mode: opts.mode,
        salt,
        argon2: opts.argon2,
        passphrase_kind: chosen.kind,
        idx: None,
        keytable_id: None,
        keytable_digest: None,
        new_core_digest: None,
        header_id: None,
        mac: [0; 64],
    };
    let mut setup = match tpm_pre.take() {
        Some((tpm, state, ek)) => Some(bound_index(
            &t, &mut rec, &init_key, &master, &bundle, tpm, state, ek, owner,
        )?),
        None => {
            write_init(&t, &rec, &init_key)?;
            failpoint!("init.prepared");
            None
        }
    };

    let staged = (|| -> Result<(Vec<u8>, CoreFields, SlotFields), Error> {
        // Key table 1 (empty).
        let kt = Owned::create(&t, &keytable_tmp_name(1), "a key-table temp")?;
        rec.phase = InitPhase::KeytableCreated;
        rec.keytable_id = Some(kt.id());
        write_init(&t, &rec, &init_key)?;
        failpoint!("init.keytable-created");
        let table = KeyTable::from_entries(Vec::new())?;
        let digest =
            keytable::write_file(&table, &vault_id, 1, &bundle.keytable_keys()?, kt.file())?;
        pfs::flush_file(kt.file()).map_err(Error::Io)?;
        drop(kt);
        t.rename_noreplace(keytable_tmp_name(1), keytable_name(1))
            .map_err(Error::Io)?;
        t.flush().map_err(Error::Io)?;
        // The exact future core and header.
        let core = CoreFields {
            vault_id,
            mode: opts.mode,
            argon2: opts.argon2,
            salt,
            generation: 1,
            created_at: now(),
            keytable_gen: 1,
            keytable_digest: digest,
            card_set_id: set_id,
            setup_id,
            passphrase_kind: chosen.kind,
            tpm_cleanup: Vec::new(),
        };
        let slots = match &setup {
            None => {
                let k_slot = kdf::passphrase_subkey(&master, PassphraseKey::PortableSlot)?;
                let (slot_nonce, slot_ct) = wrap::wrap::<96>(&k_slot, &bundle.to_bytes())?;
                SlotFields::Portable(PortableSlots {
                    slot_nonce,
                    slot_ct,
                    duress_tag: None,
                })
            }
            Some(b) => {
                let (s1_nonce, s1_ct) = wrap::wrap::<96>(&b.keys.s1, b.s1.y())?;
                // The slots keep the post-write Name only (4.1).
                let index = IndexContext {
                    name_prewrite: None,
                    ..b.index
                };
                SlotFields::Bound(BoundSlots {
                    s1_nonce,
                    s1_ct,
                    s2_nonce: b.s2_nonce,
                    index,
                    tpm_id: tpmid::seal(Scope::Slots, &bundle.k_mac, &vault_id, &index, &b.ek)?,
                    duress_tag: None,
                })
            }
        };
        let bytes = Header::build(&core, &slots, &bundle.k_mac)?;
        rec.phase = InitPhase::KeytableWritten;
        rec.keytable_digest = Some(digest);
        rec.new_core_digest = Some(core.digest()?);
        write_init(&t, &rec, &init_key)?;
        failpoint!("init.keytable-written");
        Ok((bytes, core, slots))
    })();
    let (mut header_bytes, final_core, final_slots) = match staged {
        Ok(v) => v,
        Err(e) => {
            rollback_or_report(&t, &rec, setup.as_mut(), ui);
            return Err(e);
        }
    };
    drop(master);

    // Cards: portable, a 2-of-2 split of the bundle (Card A, Card B); bound,
    // S3 of the 2-of-3 split on the single bound card (7.4, 7.4d).
    let cards: Vec<(Card, CardRole, &str, &'static str)> = match &setup {
        None => {
            let shares = shamir::split_2_of_2(&bundle.to_bytes())?;
            let a = Card::new(&vault_id, CardMode::Portable, &set_id, &shares[0])?;
            let b = Card::new(&vault_id, CardMode::Portable, &set_id, &shares[1])?;
            card::check_pair(&a, &b).map_err(Error::Card)?;
            vec![
                (a, CardRole::CardA, "card-a", "Card A"),
                (b, CardRole::CardB, "card-b", "Card B"),
            ]
        }
        Some(s) => vec![(
            Card::new(&vault_id, CardMode::Bound, &set_id, &s.s3)?,
            CardRole::Bound,
            "bound",
            "Bound card",
        )],
    };
    let entries: Vec<(&Card, CardRole, &str)> =
        cards.iter().map(|(c, r, sfx, _)| (c, *r, *sfx)).collect();
    let files = match CardFiles::write(
        settings,
        folders,
        &entries,
        &vault_id,
        &set_id,
        opts.delivery,
        vault_path,
    ) {
        Ok(f) => f,
        Err(e) => {
            rollback_or_report(&t, &rec, setup.as_mut(), ui);
            return Err(e);
        }
    };
    drop(entries);
    let shown = files.shown();
    let labelled = shown
        .iter()
        .zip(&cards)
        .map(|(p, c)| format!("{p} ({})", c.3))
        .collect::<Vec<_>>()
        .join(", ");
    match (digital, bound_mode) {
        (true, false) => ui.notice(&format!(
            "Card files saved: {labelled}. Checking them now."
        )),
        (true, true) => ui.notice(&format!("Card file saved: {labelled}. Checking it now.")),
        (false, false) => ui.notice(&format!(
            "Card files written: {}. Print both, then keep the printed cards in two different places.",
            shown.join(", ")
        )),
        (false, true) => ui.notice(&format!(
            "Card file written: {}. Print it, then keep the printed card away from this computer.",
            shown.join(", ")
        )),
    }

    // W5 / D5, the rehearsal, the type-back, the optional duress step, then
    // the header temp and `committing`.
    let mut committing_attempted = false;
    let verified = (|| -> Result<Owned, Error> {
        let delivered = if digital {
            // Digital: no printing acknowledgment; the saved files are read
            // back through the format 1 reader (SI-52 6.4).
            let expected: Vec<(&Card, &'static str)> =
                cards.iter().map(|(c, _, _, l)| (c, *l)).collect();
            files.read_back(&expected)?
        } else {
            // With a terminal this always waits (also under
            // `--secrets-stdin`); PNG photos are opened only after it.
            ui.acknowledge(match (photos, bound_mode) {
                (true, false) => {
                    "Print both cards and save the PNG photos at the paths you gave, then press Enter. "
                }
                (true, true) => {
                    "Print the card and save the PNG photo at the path you gave, then press Enter. "
                }
                (false, _) => "Press Enter after printing. ",
            })?;
            let pngs = if bound_mode {
                vec![opts.card_png.as_deref()]
            } else {
                vec![opts.card_a_png.as_deref(), opts.card_b_png.as_deref()]
            };
            let mut out = Vec::with_capacity(cards.len());
            for ((card, _, _, label), png) in cards.iter().zip(pngs) {
                out.push(verify_card(card, label, png, ui)?);
            }
            out
        };
        // The recovery rehearsal from the delivered cards (SI-52 6.4; bound:
        // S1 + S3, spec 6.1).
        let rehearse_now = |bytes: &[u8]| -> Result<(), Error> {
            match &setup {
                None => {
                    let pair: &[SecretBytes<{ card::PAYLOAD_LEN }>; 2] = delivered
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::RehearsalFailed)?;
                    rehearse(&t, pair, bytes)
                }
                Some(b) => bound::rehearse(&t, &b.keys.s1, &delivered[0], bytes),
            }
        };
        rehearse_now(&header_bytes)?;
        failpoint!("init.rehearsed");
        type_back(&chosen, ui)?;
        // The optional duress step, interactive only (6.10). The header that
        // will be committed is rehearsed again.
        if ui.interactive()
            && let Some(bytes) = init_duress(
                &chosen,
                &final_core,
                &final_slots,
                &bundle.k_mac,
                setup.as_ref(),
                ui,
            )?
        {
            rehearse_now(&bytes)?;
            header_bytes = bytes;
        }
        drop(delivered);
        let hdr = Owned::create(&t, HEADER_TMP, HEADER_TMP)?;
        rec.phase = InitPhase::Committing;
        rec.header_id = Some(hdr.id());
        committing_attempted = true;
        write_init(&t, &rec, &init_key)?;
        failpoint!("init.committing");
        Ok(hdr)
    })();
    let mut hdr = match verified {
        Ok(h) => h,
        Err(e) => {
            if digital && committing_attempted {
                // SI-52 8.1: once `committing` may exist, keep the files.
                files.retain();
                rollback_or_report(&t, &rec, setup.as_mut(), ui);
                ui.notice(&format!(
                    "The setup was rolled back. The card files {} were kept; they are probably invalid. pvault does not delete them now; check them with pvault discard-card.",
                    shown.join(", ")
                ));
                return Err(e);
            }
            report_kept(&files.delete(), Some(ui));
            rollback_or_report(&t, &rec, setup.as_mut(), ui);
            if !matches!(e, Error::NeedsTerminal(_)) {
                ui.notice(if digital {
                    "The setup was rolled back; the card files were deleted. If you copied them anywhere, delete those copies: they are invalid."
                } else {
                    "The setup was rolled back; the printed cards are invalid."
                });
            }
            return Err(e);
        }
    };
    drop(cards);

    // W6: the first header, by no-replace rename.
    let committed = (|| -> Result<(), Error> {
        hdr.rewrite(&header_bytes).map_err(Error::Io)?;
        // Tests fail the rename here: after `committing`, before the header.
        let renamed =
            fail_io!("init.header-rename").and_then(|()| t.rename_noreplace(HEADER_TMP, HEADER));
        if let Err(e) = renamed {
            let now = store::read_capped(&t, HEADER, crate::header::MAX_HEADER_LEN, || {
                Error::HeaderInvalid
            })
            .ok()
            .flatten();
            match now {
                Some(b) if b == header_bytes => {}
                None => return Err(Error::Io(e)), // verifiably not committed
                Some(_) => return Err(Error::OutcomeUnknown),
            }
        }
        failpoint!("init.committed");
        t.flush().map_err(|_| Error::DurabilityUnknown)
    })();
    drop(hdr);
    match committed {
        Ok(()) => {
            #[cfg(test)]
            hooks::after_commit();
        }
        Err(Error::Io(e)) => {
            if digital {
                // After `committing`: retained (SI-52 8.1).
                files.retain();
                rollback_or_report(&t, &rec, setup.as_mut(), ui);
                ui.notice(&format!(
                    "The setup was rolled back. The card files {} were kept; they are probably invalid. pvault does not delete them now; check them with pvault discard-card.",
                    shown.join(", ")
                ));
            } else {
                report_kept(&files.delete(), Some(ui));
                rollback_or_report(&t, &rec, setup.as_mut(), ui);
                ui.notice("The setup was rolled back; the printed cards are invalid.");
            }
            return Err(Error::Io(e));
        }
        Err(e) => {
            // Committed or unknown: the journal stays for the resume. Paper:
            // the cards are printed and verified, so the files go now (W7).
            // Digital: the files are kept with their entries (SI-52 8.1).
            if digital {
                files.retain();
            } else {
                report_kept(&files.delete(), Some(ui));
            }
            return Err(e);
        }
    }
    let card_files = digital.then(|| {
        files
            .files
            .iter()
            .map(|f| f.path.clone())
            .collect::<Vec<_>>()
    });
    if digital {
        // D7: the files are the owner's; only the entries go.
        files.release();
        if bound_mode {
            ui.notice(&format!(
                "Your recovery card file: {labelled}. Keep it on a drive in a different place; pvault will not delete it."
            ));
        } else {
            ui.notice(&format!(
                "Your recovery card files: {} (Card A) and {} (Card B). Keep them on different drives in different places; pvault will not delete them.",
                shown[0], shown[1]
            ));
        }
    } else {
        // W7, W8.
        report_kept(&files.delete(), Some(ui));
    }
    store::remove_journal(&t)?;
    let _ = settings.rollback_observe(&vault_id, 1);
    Ok(InitOutcome::Created {
        vault_id,
        card_files,
    })
}

/// [`rollback_all`], telling the owner when a bound index could not be
/// removed now (the journal is then kept for `pvault init`).
fn rollback_or_report(
    t: &Dir,
    rec: &InitRecord,
    setup: Option<&mut BoundSetup>,
    ui: &mut dyn Prompter,
) {
    let bound = setup.is_some();
    if rollback_all(t, rec, setup).is_err() && bound {
        ui.notice("The TPM index of this setup could not be removed now. The setup journal was kept; run pvault init on the folder again to finish removing it.");
    }
}

/// What the optional card check after the commit did (SI-52 R5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardCheck {
    /// Not offered (no interactive terminal) or skipped by the owner.
    Skipped,
    /// Both files read back and recovered the vault.
    Passed,
}

/// SI-52 R5 (decided 2026-10-06): an optional check of digital card files
/// after the commit. Run after `init` returned, so its card-file handles,
/// card-operation lock and vault lock are all released and the owner can
/// eject and re-insert the drives. Offered only to an interactive `init`.
///
/// Each file is opened afresh by path (no link followed), read through the
/// format 1 reader, and the pair goes through the recovery rehearsal (6.4)
/// against the header and key table as now stored, under a shared lock. The
/// recovery itself shows that the files are this vault's current Card A and
/// Card B, so no copy of the cards is kept in memory while the owner
/// re-inserts the drives. A failure is reported as
/// [`Error::CardCheckFailed`]: the vault is not rolled back and no card file
/// is deleted.
pub fn card_check_after_commit(
    vault: &Path,
    files: &[PathBuf],
    ui: &mut dyn Prompter,
) -> Result<CardCheck, Error> {
    if !ui.interactive() {
        return Ok(CardCheck::Skipped);
    }
    let bound = files.len() == 1;
    ui.notice(if bound {
        "The vault has already been created. Optional check: pvault has closed the card file, so you can now eject the drive that holds it, insert it again, and let pvault check that the card reads back and, with your passphrase, recovers the vault. A failed check changes nothing: the vault stays, and the card file is not deleted."
    } else {
        "The vault has already been created. Optional check: pvault has closed the card files, so you can now eject the drives that hold them, insert them again, and let pvault check that both cards read back and recover the vault. A failed check changes nothing: the vault stays, and no card file is deleted."
    });
    let phrase = "CHECK";
    if !ui.confirm(
        &format!(
            "Type {phrase} after re-inserting the {} to check the card {}, or press Enter to skip: ",
            if bound { "drive" } else { "drives" },
            if bound { "file" } else { "files" }
        ),
        phrase,
    )? {
        ui.notice("Card check skipped.");
        return Ok(CardCheck::Skipped);
    }
    check_saved_cards(vault, files, ui).map_err(|e| {
        // The vault exists: never repeat a setup-time "rolled back" text.
        let mut reason = match e {
            Error::RehearsalFailed if bound => {
                "the file and the passphrase do not recover this vault.".to_owned()
            }
            Error::RehearsalFailed => "the two files do not recover this vault.".to_owned(),
            other => other.to_string(),
        };
        if !reason.ends_with('.') {
            reason.push('.');
        }
        Error::CardCheckFailed(reason)
    })?;
    if bound {
        ui.notice(&format!(
            "Card check passed: {} (Bound card) reads back and, with your passphrase, recovers this vault.",
            crate::render::path(&files[0])
        ));
    } else {
        ui.notice(&format!(
            "Card check passed: {} (Card A) and {} (Card B) read back and recover this vault.",
            crate::render::path(&files[0]),
            crate::render::path(&files[1])
        ));
    }
    Ok(CardCheck::Passed)
}

fn check_saved_cards(vault: &Path, files: &[PathBuf], ui: &mut dyn Prompter) -> Result<(), Error> {
    let mut delivered = Vec::with_capacity(files.len());
    for path in files {
        let abs = std::path::absolute(path).map_err(Error::Io)?;
        let (Some(parent), Some(name)) = (abs.parent(), abs.file_name()) else {
            return Err(Error::Unsupported("a card file needs a folder and a name"));
        };
        let dir = super::export::open_parent(parent)?;
        let file = dir
            .open_regular(name, false)
            .map_err(Error::Io)?
            .ok_or_else(|| {
                Error::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "a card file is missing",
                ))
            })?;
        let bytes = read_bounded(&file)?;
        let read = card::parse_card_file(&bytes).map_err(Error::CardFile)?;
        delivered.push(SecretBytes::take_from(&mut read.payload().to_vec())?);
    }
    let t = Dir::open(vault).map_err(Error::Io)?;
    let _shared = crate::lock::status_shared(&t)?.ok_or(Error::VaultInUse)?;
    let header = crate::store::read_capped(
        &t,
        crate::store::HEADER,
        crate::header::MAX_HEADER_LEN,
        || Error::HeaderInvalid,
    )?
    .ok_or(Error::HeaderInvalid)?;
    let parsed = Header::parse(&header)?;
    match parsed.slots() {
        SlotFields::Portable(_) => {
            let pair: [SecretBytes<{ card::PAYLOAD_LEN }>; 2] =
                delivered.try_into().map_err(|_| Error::RehearsalFailed)?;
            rehearse(&t, &pair, &header)
        }
        SlotFields::Bound(_) => {
            // A bound card recovers only with the passphrase (spec 6.1).
            let core = parsed.core();
            let raw = ui.secret("Enter the passphrase to check the card: ")?;
            let handled = super::handle(core.passphrase_kind, raw.as_bytes())?;
            drop(raw);
            let master = kdf::master_pw(&handled, &core.salt, core.argon2)?;
            drop(handled);
            let keys = BoundKeys::derive(&master)?;
            drop(master);
            let card = delivered.first().ok_or(Error::RehearsalFailed)?;
            bound::rehearse(&t, &keys.s1, card, &header)
        }
    }
}

/// Card entries left by an interrupted setup of `vault_id` (11.3; SI-52 8.2).
/// Paper files are offered for deletion as before. Digital files are never
/// deleted here: with `current_set` (an authenticated header's card set)
/// matching, their entries are released and the files named as the
/// owner's current cards; otherwise files and entries are kept and the files
/// named as probably invalid.
fn offer_stale_cards(
    settings: &Settings,
    vault_id: &[u8; 16],
    current_set: Option<[u8; 8]>,
    ui: &mut dyn Prompter,
) -> Result<(), Error> {
    let stale = settings.stale_cards(Some(vault_id)).unwrap_or_default();
    let (digital, paper): (Vec<_>, Vec<_>) = stale
        .into_iter()
        .partition(|(entries, _)| entries.iter().any(|e| e.delivery == Delivery::Digital));
    let shown =
        |e: &CardEntry| crate::render::path(&crate::records::path_from_native(&e.file.path));
    for (entries, lock) in digital {
        let names = entries.iter().map(shown).collect::<Vec<_>>().join(", ");
        let current = entries.iter().all(|e| Some(e.set_id) == current_set);
        if current {
            ui.notice(&format!(
                "Your recovery card files are: {names}. Keep them on different drives in different places."
            ));
            settings.unregister_cards(&lock.id())?;
            lock.finish();
        } else {
            let set = entries.first().map(|e| hex(&e.set_id)).unwrap_or_default();
            ui.notice(&format!(
                "Card files of the interrupted setup (card set {set}) were kept: {names}. They are probably invalid, but pvault does not delete them after a restart; check them with pvault discard-card."
            ));
            drop(lock);
        }
    }
    let n: usize = paper.iter().map(|(e, _)| e.len()).sum();
    if n == 0 {
        return Ok(());
    }
    let label = if current_set.is_some() {
        format!("current cards of vault {}", hex(vault_id))
    } else {
        "cards of the interrupted setup (invalid)".to_owned()
    };
    let mut msg = format!("Card files left by an interrupted setup ({label}):\n");
    for (entries, _) in &paper {
        for e in entries {
            msg.push_str(&format!("  {}\n", shown(e)));
        }
    }
    ui.notice(msg.trim_end());
    let phrase = format!("DELETE {n} STALE FILES");
    if !ui.confirm(&format!("Type {phrase} to confirm: "), &phrase)? {
        return Ok(());
    }
    for (entries, lock) in paper {
        for e in &entries {
            let name = shown(e);
            match crate::records::delete_recorded(&e.file)? {
                crate::records::StaleOutcome::Deleted => ui.notice(&format!("Deleted {name}.")),
                crate::records::StaleOutcome::Missing => {}
                _ => ui.notice(&format!(
                    "pvault cannot prove that {name} is the file it created; delete it yourself if it is. It may hold a recovery card."
                )),
            }
        }
        settings.unregister_cards(&lock.id())?;
        lock.finish();
    }
    Ok(())
}

/// The 8.3 restart table (portable and bound setups).
fn resume(
    t: &Dir,
    settings: &Settings,
    ui: &mut dyn Prompter,
    opts: &InitOptions<'_>,
) -> Result<InitOutcome, Error> {
    match pending(t)? {
        Pending::Init => {}
        Pending::Other(op) => return Err(Error::PendingJournal(op)),
        // An existing vault, or a journal temp without an ownership root.
        Pending::None | Pending::Update | Pending::TempOnly => return Err(Error::TargetNotEmpty),
    }
    let header = store::read_header(t)?;
    let bytes = store::read_capped(t, JOURNAL, journal::MAX_JOURNAL_LEN, || {
        Error::JournalInvalid
    })?
    .ok_or(Error::JournalInvalid)?;
    let Ok(Record::Init(unverified)) = Record::parse(&bytes) else {
        return Err(Error::PendingJournal("operation"));
    };
    if unverified.mode == Mode::Bound && !crate::tpm::supported() {
        return Err(Error::BoundVault);
    }
    unverified.argon2.check_hard_caps()?;
    resources::check_argon2(&unverified.argon2, &SystemMemory)?;
    match header {
        Some(h) => finish_committed(t, &h, settings, ui, &opts.tpm),
        None => remove_uncommitted(t, &unverified, settings, ui, &opts.tpm),
    }
}

fn authenticated(t: &Dir, init_key: &crate::secrets::SecretBytes<32>) -> Result<InitRecord, Error> {
    let loaded = store::load_journal(t, |c, tmp| journal::promote_init(c, tmp, init_key))?;
    let bytes = loaded.record.ok_or(Error::JournalInvalid)?;
    match Record::parse(&bytes) {
        Ok(Record::Init(r)) if Record::Init(r.clone()).verify_old(init_key) => Ok(r),
        _ => Err(Error::HeaderInvalid),
    }
}

/// Header present (Path A): finish the post-commit steps.
fn finish_committed(
    t: &Dir,
    h: &Header,
    settings: &Settings,
    ui: &mut dyn Prompter,
    tpm_opts: &TpmOptions,
) -> Result<InitOutcome, Error> {
    // Bound: Path A reads S2 from the TPM (5.5; no duress check).
    let mut tpm = match h.core().mode {
        Mode::Portable => None,
        Mode::Bound => Some(bound::connect(tpm_opts)?),
    };
    let raw = ui.secret(
        "This vault's setup was interrupted after it was saved. Enter the passphrase to finish: ",
    )?;
    let handled = super::handle(h.core().passphrase_kind, raw.as_bytes())?;
    drop(raw);
    let master = kdf::master_pw(&handled, &h.core().salt, h.core().argon2)?;
    drop(handled);
    let _bundle = match tpm.as_deref_mut() {
        Some(t) => bound::open_bundle(h, &master, t)?,
        None => super::open_bundle(h, &master)?,
    };
    drop(tpm);
    let init_key = kdf::init_journal_key(&master)?;
    drop(master);
    let rec = authenticated(t, &init_key)?;
    let matches = rec.vault_id == h.core().vault_id
        && rec
            .new_core_digest
            .is_some_and(|d| bool::from(d.ct_eq(&h.core_digest())));
    if !matches {
        return Err(Error::Indeterminate);
    }
    t.flush().map_err(|_| Error::DurabilityUnknown)?;
    if let Some(id) = &rec.header_id
        && t.exists(HEADER_TMP).map_err(Error::Io)?
        && pfs::remove_if_owned(t, HEADER_TMP, id).map_err(Error::Io)? != pfs::Ownership::Removed
    {
        ui.notice("A vault.hdr.tmp that pvault cannot prove it created was left in place.");
    }
    offer_stale_cards(settings, &rec.vault_id, Some(h.core().card_set_id), ui)?;
    store::remove_journal(t)?;
    let _ = settings.rollback_observe(&rec.vault_id, h.core().generation);
    Ok(InitOutcome::Finished {
        vault_id: rec.vault_id,
    })
}

/// No header: remove the authenticated setup.
fn remove_uncommitted(
    t: &Dir,
    unverified: &InitRecord,
    settings: &Settings,
    ui: &mut dyn Prompter,
    tpm_opts: &TpmOptions,
) -> Result<InitOutcome, Error> {
    let raw =
        ui.secret("This folder holds an interrupted setup. Enter the passphrase used for it: ")?;
    let handled = super::handle(unverified.passphrase_kind, raw.as_bytes())?;
    drop(raw);
    let master = kdf::master_pw(&handled, &unverified.salt, unverified.argon2)?;
    drop(handled);
    let init_key = kdf::init_journal_key(&master)?;
    drop(master);
    let rec = authenticated(t, &init_key)?;
    // Bound (8.3 restart table): resolve the journaled index first, on the
    // TPM that created it, under 9.2b. Elsewhere the journal and every
    // artifact are kept.
    if let Some(idx) = &rec.idx {
        let expected = tpmid::open(
            Scope::Init,
            &init_key,
            &rec.vault_id,
            &idx.index,
            &idx.token,
        )?;
        let mut tpm = bound::connect(tpm_opts)?;
        let state = tpm.state()?;
        let live = tpm
            .ek_digest()
            .map_err(|_| Error::TpmIndexElsewhere(idx.index.tpm_index))?;
        if !bool::from(live.ct_eq(expected.expose_secret())) {
            return Err(Error::TpmIndexElsewhere(idx.index.tpm_index));
        }
        let present = tpm.read_public(idx.index.tpm_index)?.is_some();
        // A declared owner authorization is always read, so that the
        // `--secrets-stdin` line order does not depend on TPM state.
        let owner = if present || tpm_opts.owner_auth_declared {
            bound::owner_auth(tpm_opts, &state, ui)?
        } else {
            None
        };
        match bound::remove_owned(tpm.as_mut(), &idx.index, &expected, owner.as_ref())? {
            bound::Resolution::Removed => {
                ui.notice(&format!(
                    "Removed this setup's TPM index (handle 0x{:08x}).",
                    idx.index.tpm_index
                ));
            }
            bound::Resolution::Absent => {}
            bound::Resolution::Foreign => ui.notice(&format!(
                "TPM handle 0x{:08x} now holds an index that is not this setup's; it was left alone.",
                idx.index.tpm_index
            )),
        }
    }
    // Authenticated artifacts.
    if let Some(id) = &rec.keytable_id {
        for name in [keytable_tmp_name(1), keytable_name(1)] {
            pfs::remove_if_owned(t, &name, id).map_err(Error::Io)?;
        }
    }
    if let Some(id) = &rec.header_id {
        pfs::remove_if_owned(t, HEADER_TMP, id).map_err(Error::Io)?;
    }
    t.flush().map_err(Error::Io)?;
    // The four exact unauthenticated candidates.
    let mut candidates = Vec::new();
    let mut reported = Vec::new();
    for name in [
        keytable_tmp_name(1),
        keytable_name(1),
        HEADER_TMP.to_owned(),
        JOURNAL_TMP.to_owned(),
    ] {
        if !t.exists(&name).map_err(Error::Io)? {
            continue;
        }
        match t.open_regular(&name, false) {
            Ok(Some(f)) => {
                let id = t.identity(&f).map_err(Error::Io)?;
                let len = f.metadata().map_err(Error::Io)?.len();
                candidates.push((name, id, len));
            }
            _ => reported.push(name),
        }
    }
    if !candidates.is_empty() || !reported.is_empty() {
        let mut msg =
            String::from("Files pvault cannot prove it created block removing the setup:\n");
        for (n, id, len) in &candidates {
            msg.push_str(&format!("  {n} (identity {id:?}, {len} bytes)\n"));
        }
        for n in &reported {
            msg.push_str(&format!("  {n} (not a regular file; reported only)\n"));
        }
        ui.notice(msg.trim_end());
        let phrase = format!("DELETE INIT LEFTOVERS {}", hex(&rec.setup_id[..4]));
        if !candidates.is_empty() {
            if !ui.confirm(
                &format!("Type {phrase} to delete exactly these files: "),
                &phrase,
            )? {
                return Err(Error::UnownedLeftovers(
                    candidates.into_iter().map(|c| c.0).collect(),
                ));
            }
            for (name, id, len) in &candidates {
                let Some(f) = t.open_regular(name, false).map_err(Error::Io)? else {
                    continue;
                };
                if t.identity(&f).ok() != Some(*id)
                    || f.metadata().map_err(Error::Io)?.len() != *len
                {
                    reported.push(name.clone());
                    continue;
                }
                if !t.delete_held(name, &f).map_err(Error::Io)? {
                    reported.push(name.clone());
                }
            }
            t.flush().map_err(Error::Io)?;
        }
        if !reported.is_empty() {
            return Err(Error::UnownedLeftovers(reported));
        }
    }
    offer_stale_cards(settings, &rec.vault_id, None, ui)?;
    store::remove_journal(t)?;
    Ok(InitOutcome::RolledBack)
}
