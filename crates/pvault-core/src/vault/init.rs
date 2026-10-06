//! Portable `init` and its resume (spec 8.3, 7.4a, 7.4b, 6.4; `docs/CLI.md`
//! 6.1; `docs/M4_READINESS.md` section 11; approved for Milestone 4).
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
use crate::header::{CoreFields, Header, Mode, PassphraseKind, PortableSlots, SlotFields};
use crate::journal::{self, InitPhase, InitRecord, Record};
use crate::keytable::{self, KeyTable};
use crate::lock::VaultLock;
use crate::passphrase::{self, CustomPassphrase, WordCount};
use crate::platform::fs::{self as pfs, Dir};
use crate::records::{
    CardEntry, CardRole, OpKind, OpLock, RecordedFile, Settings, hex, native_path,
};
use crate::resources::{self, SystemMemory};
use crate::secrets::SecretBuf;
use crate::shamir;
use crate::store::{
    self, HEADER, HEADER_TMP, JOURNAL, JOURNAL_TMP, Owned, keytable_name, keytable_tmp_name,
};

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
    /// The card folder (outside the vault).
    pub cards_dir: PathBuf,
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
}

impl std::fmt::Debug for InitOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitOptions")
            .field("vault", &self.vault)
            .field("cards_dir", &self.cards_dir)
            .field("passphrase", &self.passphrase)
            .field("argon2", &self.argon2)
            .finish_non_exhaustive()
    }
}

/// What `init` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitOutcome {
    /// A new vault.
    Created {
        /// Its ID.
        vault_id: [u8; 16],
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
) -> Result<(), Error> {
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
        let result = decoded.and_then(|payload| {
            if card.matches(&payload) {
                Ok(())
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
            Ok(()) => return Ok(()),
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

/// Card files of one operation, held open from creation to deletion
/// (`docs/M4_READINESS.md` 11.2).
struct CardFiles<'a> {
    dir: &'a Dir,
    settings: &'a Settings,
    lock: OpLock,
    files: Vec<(String, PathBuf, File)>,
    registered: bool,
}

impl<'a> CardFiles<'a> {
    /// W1 to W4.
    fn write(
        settings: &'a Settings,
        dir: &'a Dir,
        dir_path: &Path,
        cards: [(&Card, CardRole, &str); 2],
        vault_id: &[u8; 16],
        set_id: &[u8; 8],
    ) -> Result<Self, Error> {
        // W1 (the settings policy was checked before anything was written).
        let lock = settings.begin_operation(OpKind::Cards)?;
        let mut this = Self {
            dir,
            settings,
            lock,
            files: Vec::new(),
            registered: false,
        };
        let result = (|| -> Result<(), Error> {
            // W2.
            let mut entries = Vec::new();
            let created_at = now();
            for (_, role, suffix) in &cards {
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
                this.files.push((name, path.clone(), file));
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
                });
            }
            failpoint!("init.cards-created");
            // W3.
            this.registered = true;
            settings.register_cards(entries).map_err(|e| match e {
                Error::NotRegistered(_) => Error::NotRegistered("card files"),
                other => other,
            })?;
            failpoint!("init.cards-registered");
            // W4.
            let today = date(created_at);
            for ((card, _, _), (_, _, file)) in cards.iter().zip(&this.files) {
                let svg = card::render_svg(card, &today)?;
                let mut f: &File = file;
                f.write_all(svg.as_bytes()).map_err(Error::Io)?;
                pfs::flush_file(file).map_err(Error::Io)?;
            }
            dir.flush().map_err(Error::Io)?;
            failpoint!("init.cards-written");
            Ok(())
        })();
        match result {
            Ok(()) => Ok(this),
            Err(e) => {
                this.finish();
                Err(e)
            }
        }
    }

    /// The written paths, rendered.
    fn shown(&self) -> Vec<String> {
        self.files
            .iter()
            .map(|(_, p, _)| crate::render::path(p))
            .collect()
    }

    /// W7 and W8. Returns the rendered paths left in place.
    fn finish(self) -> Vec<String> {
        let mut kept = Vec::new();
        for (name, path, file) in &self.files {
            if !self.dir.delete_held(name, file).unwrap_or(false) {
                kept.push(crate::render::path(path));
            }
        }
        let _ = self.dir.flush();
        failpoint!("init.cards-deleted");
        drop(self.files);
        if !self.registered || self.settings.unregister_cards(&self.lock.id()).is_ok() {
            self.lock.finish();
        }
        kept
    }
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

fn report_kept(kept: &[String], ui: &mut dyn Prompter) {
    for k in kept {
        ui.notice(&format!(
            "The card file {k} was moved or replaced and was not deleted; delete it yourself. It may hold a recovery card."
        ));
    }
}

/// `pvault init`: a new vault, or the resume of an interrupted setup.
pub fn init(
    opts: &InitOptions<'_>,
    settings: &Settings,
    ui: &mut dyn Prompter,
) -> Result<InitOutcome, Error> {
    // A PNG photo of a printed card can exist only after the cards are
    // written and printed: its verification waits for the printing
    // acknowledgment on the terminal device (decided 2026-10-06, O1), also
    // under `--secrets-stdin`. Without a terminal it is refused here, before
    // any bootstrap creation.
    let photos = opts.card_a_png.is_some() || opts.card_b_png.is_some();
    if photos && !ui.has_terminal() {
        return Err(Error::NeedsTerminal(
            "Verifying a card from a PNG photo needs a terminal for the printing acknowledgment, also with --secrets-stdin. Nothing was written.",
        ));
    }
    // O3 (decided 2026-10-06): card files hold shares and must stay
    // owner-only; a FAT or exFAT card folder is refused before anything is
    // created, the vault folder included. (A resume without `--cards-dir`
    // writes no card file.)
    if !opts.cards_dir.as_os_str().is_empty() {
        let cards_path = std::path::absolute(&opts.cards_dir).map_err(Error::Io)?;
        if let Ok(dir) = Dir::open(&cards_path) {
            pfs::check_private_destination(&dir)?;
        }
    }
    let (t, _lock, state) = bootstrap(&opts.vault)?;
    if state == Target::Occupied {
        return resume(&t, settings, ui);
    }
    // Settings and card destination, before any vault artifact.
    settings.check_registration()?;
    settings.check_card_room(2)?;
    let cards_path = std::path::absolute(&opts.cards_dir).map_err(Error::Io)?;
    if is_link(&cards_path) {
        return Err(Error::Unsupported(
            "the card folder is a symbolic link or reparse point",
        ));
    }
    let cards_dir = Dir::open(&cards_path).map_err(Error::Io)?;
    if t.contains(&cards_dir).map_err(Error::Io)? {
        return Err(Error::CardDestinationInVault);
    }
    // Again on the handle the cards are written through (O3).
    pfs::check_private_destination(&cards_dir)?;
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

    ui.notice("Deriving keys…");
    let vault_id = random::array::<16>()?;
    let setup_id = random::array::<16>()?;
    let salt = random::array::<32>()?;
    let set_id = random::array::<8>()?;
    let master = kdf::master_pw(&chosen.handled, &salt, opts.argon2)?;
    let init_key = kdf::init_journal_key(&master)?;
    let mut rec = InitRecord {
        phase: InitPhase::Prepared,
        vault_id,
        setup_id,
        mode: Mode::Portable,
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
    write_init(&t, &rec, &init_key)?;
    failpoint!("init.prepared");

    let bundle = Bundle::generate()?;
    let staged = (|| -> Result<Vec<u8>, Error> {
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
            mode: Mode::Portable,
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
        let k_slot = kdf::passphrase_subkey(&master, PassphraseKey::PortableSlot)?;
        let (slot_nonce, slot_ct) = wrap::wrap::<96>(&k_slot, &bundle.to_bytes())?;
        let slots = SlotFields::Portable(PortableSlots {
            slot_nonce,
            slot_ct,
            duress_tag: None,
        });
        let bytes = Header::build(&core, &slots, &bundle.k_mac)?;
        rec.phase = InitPhase::KeytableWritten;
        rec.keytable_digest = Some(digest);
        rec.new_core_digest = Some(core.digest()?);
        write_init(&t, &rec, &init_key)?;
        failpoint!("init.keytable-written");
        Ok(bytes)
    })();
    let header_bytes = match staged {
        Ok(b) => b,
        Err(e) => {
            let _ = rollback_setup(&t, &rec);
            return Err(e);
        }
    };
    drop(master);

    // Cards: a 2-of-2 split of the bundle (7.4).
    let shares = shamir::split_2_of_2(&bundle.to_bytes())?;
    let card_a = Card::new(&vault_id, CardMode::Portable, &set_id, &shares[0])?;
    let card_b = Card::new(&vault_id, CardMode::Portable, &set_id, &shares[1])?;
    drop(shares);
    card::check_pair(&card_a, &card_b).map_err(Error::Card)?;
    let files = match CardFiles::write(
        settings,
        &cards_dir,
        &cards_path,
        [
            (&card_a, CardRole::CardA, "card-a"),
            (&card_b, CardRole::CardB, "card-b"),
        ],
        &vault_id,
        &set_id,
    ) {
        Ok(f) => f,
        Err(e) => {
            let _ = rollback_setup(&t, &rec);
            return Err(e);
        }
    };
    let shown = files.shown();
    ui.notice(&format!(
        "Card files written: {}. Print both, then keep the printed cards in two different places.",
        shown.join(", ")
    ));

    // W5, then the header temp and `committing`.
    let verified = (|| -> Result<Owned, Error> {
        // With a terminal this always waits (also under `--secrets-stdin`);
        // PNG photos are opened only after it.
        ui.acknowledge(if photos {
            "Print both cards and save the PNG photos at the paths you gave, then press Enter. "
        } else {
            "Press Enter after printing. "
        })?;
        verify_card(&card_a, "Card A", opts.card_a_png.as_deref(), ui)?;
        verify_card(&card_b, "Card B", opts.card_b_png.as_deref(), ui)?;
        type_back(&chosen, ui)?;
        let hdr = Owned::create(&t, HEADER_TMP, HEADER_TMP)?;
        rec.phase = InitPhase::Committing;
        rec.header_id = Some(hdr.id());
        write_init(&t, &rec, &init_key)?;
        failpoint!("init.committing");
        Ok(hdr)
    })();
    let mut hdr = match verified {
        Ok(h) => h,
        Err(e) => {
            report_kept(&files.finish(), ui);
            let _ = rollback_setup(&t, &rec);
            if !matches!(e, Error::NeedsTerminal(_)) {
                ui.notice("The setup was rolled back; the printed cards are invalid.");
            }
            return Err(e);
        }
    };
    drop(card_a);
    drop(card_b);

    // W6: the first header, by no-replace rename.
    let committed = (|| -> Result<(), Error> {
        hdr.rewrite(&header_bytes).map_err(Error::Io)?;
        if let Err(e) = t.rename_noreplace(HEADER_TMP, HEADER) {
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
        Ok(()) => {}
        Err(Error::Io(e)) => {
            report_kept(&files.finish(), ui);
            let _ = rollback_setup(&t, &rec);
            ui.notice("The setup was rolled back; the printed cards are invalid.");
            return Err(Error::Io(e));
        }
        Err(e) => {
            // Committed or unknown: the journal stays for the resume; the
            // card files are printed and verified, so they go now (W7).
            report_kept(&files.finish(), ui);
            return Err(e);
        }
    }
    // W7, W8.
    report_kept(&files.finish(), ui);
    store::remove_journal(&t)?;
    let _ = settings.rollback_observe(&vault_id, 1);
    Ok(InitOutcome::Created { vault_id })
}

/// Lists and, with confirmation, deletes stale card files of `vault_id`
/// (11.3); `current` labels them as the vault's current cards.
fn offer_stale_cards(
    settings: &Settings,
    vault_id: &[u8; 16],
    current: bool,
    ui: &mut dyn Prompter,
) -> Result<(), Error> {
    let stale = settings.stale_cards(Some(vault_id)).unwrap_or_default();
    let n: usize = stale.iter().map(|(e, _)| e.len()).sum();
    if n == 0 {
        return Ok(());
    }
    let label = if current {
        format!("current cards of vault {}", hex(vault_id))
    } else {
        "cards of the interrupted setup (invalid)".to_owned()
    };
    let mut msg = format!("Card files left by an interrupted setup ({label}):\n");
    for (entries, _) in &stale {
        for e in entries {
            msg.push_str(&format!(
                "  {}\n",
                crate::render::path(&crate::records::path_from_native(&e.file.path))
            ));
        }
    }
    ui.notice(msg.trim_end());
    let phrase = format!("DELETE {n} STALE FILES");
    if !ui.confirm(&format!("Type {phrase} to confirm: "), &phrase)? {
        return Ok(());
    }
    for (entries, lock) in stale {
        for e in &entries {
            let shown = crate::render::path(&crate::records::path_from_native(&e.file.path));
            match crate::records::delete_recorded(&e.file)? {
                crate::records::StaleOutcome::Deleted => ui.notice(&format!("Deleted {shown}.")),
                crate::records::StaleOutcome::Missing => {}
                _ => ui.notice(&format!(
                    "pvault cannot prove that {shown} is the file it created; delete it yourself if it is. It may hold a recovery card."
                )),
            }
        }
        settings.unregister_cards(&lock.id())?;
        lock.finish();
    }
    Ok(())
}

/// The 8.3 restart table for portable setups.
fn resume(t: &Dir, settings: &Settings, ui: &mut dyn Prompter) -> Result<InitOutcome, Error> {
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
    if unverified.mode != Mode::Portable {
        return Err(Error::BoundVault);
    }
    unverified.argon2.check_hard_caps()?;
    resources::check_argon2(&unverified.argon2, &SystemMemory)?;
    match header {
        Some(h) => finish_committed(t, &h, settings, ui),
        None => remove_uncommitted(t, &unverified, settings, ui),
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
) -> Result<InitOutcome, Error> {
    if h.core().mode != Mode::Portable {
        return Err(Error::BoundVault);
    }
    let raw = ui.secret(
        "This vault's setup was interrupted after it was saved. Enter the passphrase to finish: ",
    )?;
    let handled = super::handle(h.core().passphrase_kind, raw.as_bytes())?;
    drop(raw);
    let master = kdf::master_pw(&handled, &h.core().salt, h.core().argon2)?;
    drop(handled);
    let _bundle = super::open_bundle(h, &master)?;
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
    offer_stale_cards(settings, &rec.vault_id, true, ui)?;
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
    offer_stale_cards(settings, &rec.vault_id, false, ui)?;
    store::remove_journal(t)?;
    Ok(InitOutcome::RolledBack)
}
