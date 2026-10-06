//! Milestone 4 vault tests with a scripted owner (in-process). The
//! cross-process crash tests are in `tests/failure_scenarios.rs`.

use std::collections::VecDeque;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use super::export::{self, GetError};
use super::init::{InitOptions, InitOutcome, PassphraseChoice};
use super::{Access, Prompter, Session, edit, unlock};
use crate::card::{self, PAYLOAD_LEN};
use crate::crypto::kdf::{self, Argon2Params, PassphraseKey};
use crate::errors::Error;
use crate::estimator::Band;
use crate::failpoints::inject;
use crate::header::{Header, PortableSlots, SlotFields};
use crate::input::{SecretLine, UnbufferedSource, read_line};
use crate::keytable::{EntryKind, KeyTable, NewEntry};
use crate::passphrase;
use crate::platform::fs::tests::tempdir;
use crate::records::Settings;
use crate::secrets::SecretBytes;
use crate::store;

const PW: &[u8] = b"correct horse battery staple violin quantum harbor 9172";
const FAST: Argon2Params = Argon2Params {
    m_kib: 262_144,
    t: 3,
    p: 1,
};

fn line(bytes: &[u8]) -> SecretLine {
    let mut v = bytes.to_vec();
    v.push(b'\n');
    read_line(&mut UnbufferedSource(Cursor::new(v))).unwrap()
}

/// A scripted owner. Card text is read from the card files when asked for,
/// as the CLI harness does.
pub(crate) struct Script {
    secrets: VecDeque<Vec<u8>>,
    confirms: VecDeque<bool>,
    pub(crate) notices: Vec<String>,
    cards_dir: Option<PathBuf>,
    wrong_card: bool,
    /// At the printing acknowledgment, write PNG photos of the cards here
    /// (Card A, Card B), as an owner with a terminal would before pressing
    /// Enter.
    photos: Option<(PathBuf, PathBuf)>,
    /// A terminal device exists (generated passphrases are shown to it).
    tty: bool,
    /// The generated passphrase shown on the "terminal"; it answers secret
    /// prompts once the scripted ones run out (the type-back).
    shown_words: Option<Vec<u8>>,
    /// Every card payload entered, in order.
    entered_cards: Vec<SecretBytes<PAYLOAD_LEN>>,
}

impl Script {
    fn new() -> Self {
        Self {
            secrets: VecDeque::new(),
            confirms: VecDeque::new(),
            notices: Vec::new(),
            cards_dir: None,
            wrong_card: false,
            photos: None,
            tty: false,
            shown_words: None,
            entered_cards: Vec::new(),
        }
    }

    fn pw(n: usize) -> Self {
        let mut s = Self::new();
        for _ in 0..n {
            s.secrets.push_back(PW.to_vec());
        }
        s
    }

    fn confirm(mut self, answers: &[bool]) -> Self {
        self.confirms.extend(answers);
        self
    }

    fn said(&self, text: &str) -> bool {
        self.notices.iter().any(|n| n.contains(text))
    }
}

/// The Base32 text of a card file (`font-size="16"` lines).
pub(crate) fn card_text_of(svg: &str) -> String {
    svg.split("font-size=\"16\">")
        .skip(1)
        .map(|s| s.split('<').next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}

impl Prompter for Script {
    fn secret(&mut self, _prompt: &str) -> Result<SecretLine, Error> {
        let s = match self.secrets.pop_front() {
            Some(s) => s,
            None => self.shown_words.clone().ok_or(Error::InputEnded)?,
        };
        Ok(line(&s))
    }

    fn card_text(&mut self, label: &str) -> Result<SecretBytes<PAYLOAD_LEN>, Error> {
        let dir = self.cards_dir.as_ref().ok_or(Error::InputEnded)?;
        // `wrong_card`: answer with the other card (valid, same set).
        let suffix = if (label == "Card A") != self.wrong_card {
            "card-a.svg"
        } else {
            "card-b.svg"
        };
        let file = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.to_string_lossy().ends_with(suffix))
            .ok_or(Error::InputEnded)?;
        let text = card_text_of(&fs::read_to_string(file).unwrap());
        let payload = card::decode_base32(text.as_bytes()).map_err(Error::CardText)?;
        self.entered_cards.push(SecretBytes::take_from(
            &mut payload.expose_secret().to_vec(),
        )?);
        Ok(payload)
    }

    fn card_png_path(&mut self, _label: &str) -> Result<Option<PathBuf>, Error> {
        Ok(None)
    }

    fn confirm(&mut self, prompt: &str, _phrase: &str) -> Result<bool, Error> {
        self.notices.push(format!("[confirm] {prompt}"));
        Ok(self.confirms.pop_front().unwrap_or(false))
    }

    fn acknowledge(&mut self, _prompt: &str) -> Result<(), Error> {
        if let (Some((a, b)), Some(dir)) = (self.photos.clone(), self.cards_dir.clone()) {
            for (dest, suffix) in [(a, "card-a.svg"), (b, "card-b.svg")] {
                let svg = fs::read_dir(&dir)
                    .unwrap()
                    .map(|e| e.unwrap().path())
                    .find(|p| p.to_string_lossy().ends_with(suffix))
                    .unwrap();
                let text = card_text_of(&fs::read_to_string(svg).unwrap());
                let payload = card::decode_base32(text.as_bytes()).unwrap();
                let (side, gray) = card::tests::qr_bitmap(payload.expose_secret(), 5);
                fs::write(dest, card::tests::encode_png(side, side, &gray)).unwrap();
            }
        }
        Ok(())
    }

    fn show_secret(&mut self, text: &str) -> Result<(), Error> {
        if !self.tty {
            return Err(Error::NeedsTerminal("no terminal in tests"));
        }
        let words = text
            .split("Your passphrase:\n\n    ")
            .nth(1)
            .and_then(|t| t.split('\n').next())
            .expect("the shown text holds the words");
        self.shown_words = Some(words.as_bytes().to_vec());
        Ok(())
    }

    fn notice(&mut self, text: &str) {
        self.notices.push(text.to_owned());
    }

    fn interactive(&self) -> bool {
        false
    }

    fn has_terminal(&self) -> bool {
        self.tty
    }
}

fn strong(_p: &passphrase::CustomPassphrase, _c: &str) -> Result<(Band, Vec<String>), Error> {
    Ok((Band::Strong, Vec::new()))
}

struct Fixture {
    root: PathBuf,
    vault: PathBuf,
    cards: PathBuf,
    settings: Settings,
}

impl Fixture {
    fn new() -> Self {
        let root = tempdir();
        let cards = root.join("cards");
        fs::create_dir(&cards).unwrap();
        let settings = Settings::open_at(&root.join("settings")).unwrap();
        Self {
            vault: root.join("vault"),
            root,
            cards,
            settings,
        }
    }

    fn opts(&self) -> InitOptions<'static> {
        InitOptions {
            vault: self.vault.clone(),
            cards_dir: self.cards.clone(),
            passphrase: PassphraseChoice::Custom,
            argon2: FAST,
            card_a_png: None,
            card_b_png: None,
            estimate: &strong,
        }
    }

    fn init(self) -> Self {
        let mut ui = Script::pw(3);
        ui.cards_dir = Some(self.cards.clone());
        let out = super::init::init(&self.opts(), &self.settings, &mut ui).unwrap();
        assert!(matches!(out, InitOutcome::Created { .. }));
        self
    }

    fn unlock(&self, access: Access, ui: &mut Script) -> Result<Session, Error> {
        ui.secrets.push_front(PW.to_vec());
        unlock(&self.vault, ui, Some(&self.settings), access)
    }

    fn source(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.root.join(name);
        fs::write(&p, bytes).unwrap();
        p
    }

    fn add(&self, src: &Path, path: &str, replace: bool) -> Result<edit::AddOutcome, Error> {
        let mut ui = Script::new();
        let mut s = self.unlock(Access::Write, &mut ui)?;
        edit::add(&mut s, src, path, replace, Some(&self.settings), &mut ui)
    }

    fn objects(&self) -> Vec<String> {
        let mut v: Vec<String> = match fs::read_dir(self.vault.join("objects")) {
            Ok(d) => d
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => Vec::new(),
        };
        v.sort();
        v
    }

    /// Every file under the vault with its bytes (lock files excluded).
    fn snapshot(&self) -> Vec<(String, Vec<u8>)> {
        fn walk(dir: &Path, prefix: &str, out: &mut Vec<(String, Vec<u8>)>) {
            for e in fs::read_dir(dir).unwrap() {
                let e = e.unwrap();
                let name = format!("{prefix}{}", e.file_name().to_string_lossy());
                // Lock files are zero-length and may be locked (mandatory
                // locks on Windows); they are not vault content.
                if name == "vault.lock" || name == "vault.gate" {
                    continue;
                }
                if e.file_type().unwrap().is_dir() {
                    walk(&e.path(), &format!("{name}/"), out);
                } else {
                    out.push((name, fs::read(e.path()).unwrap()));
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.vault, "", &mut out);
        out.sort();
        out
    }

    fn generation(&self) -> u64 {
        store::read_header(&crate::platform::fs::Dir::open(&self.vault).unwrap())
            .unwrap()
            .unwrap()
            .core()
            .generation
    }

    fn listing(&self) -> String {
        let mut ui = Script::new();
        let s = self.unlock(Access::Read, &mut ui).unwrap();
        let mut out = Vec::new();
        export::list(&s, None, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }
}

#[test]
fn init_writes_and_deletes_cards_and_commits_generation_one() {
    let f = Fixture::new().init();
    assert_eq!(f.generation(), 1);
    assert_eq!(
        fs::read_dir(&f.cards).unwrap().count(),
        0,
        "card files deleted"
    );
    assert!(
        f.settings.stale_cards(None).unwrap().is_empty(),
        "card entries removed"
    );
    let mut names: Vec<String> = fs::read_dir(&f.vault)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        ["keytable.1.pv", "vault.gate", "vault.hdr", "vault.lock"]
    );
}

/// CLI 6.1: cards verified from PNG photos (no card text read). The
/// photos are written at the printing acknowledgment.
#[test]
fn init_verifies_cards_from_png_photos() {
    let f = Fixture::new();
    let (a, b) = (f.root.join("a.png"), f.root.join("b.png"));
    let mut opts = f.opts();
    opts.card_a_png = Some(a.clone());
    opts.card_b_png = Some(b.clone());
    // O1: without a terminal, refused before anything is created.
    let mut ui = Script::pw(3);
    assert!(matches!(
        super::init::init(&opts, &f.settings, &mut ui),
        Err(Error::NeedsTerminal(_))
    ));
    assert!(!f.vault.exists());
    assert_eq!(ui.secrets.len(), 3, "no line read");
    // With a terminal: two passphrase lines and the type-back; no card line.
    let mut ui = Script::pw(3);
    ui.tty = true;
    ui.cards_dir = Some(f.cards.clone());
    ui.photos = Some((a.clone(), b.clone()));
    super::init::init(&opts, &f.settings, &mut ui).unwrap();
    assert!(ui.secrets.is_empty());
    // Photos swapped: Card A's photo shows Card B. One attempt; rolled back.
    let f = Fixture::new();
    let mut opts = f.opts();
    opts.card_a_png = Some(b.clone());
    opts.card_b_png = Some(a.clone());
    let mut ui = Script::pw(3);
    ui.tty = true;
    ui.cards_dir = Some(f.cards.clone());
    ui.photos = Some((a, b));
    let e = super::init::init(&opts, &f.settings, &mut ui).unwrap_err();
    assert!(matches!(e, Error::CardMismatch("Card A")), "{e:?}");
    assert_eq!(fs::read_dir(&f.vault).unwrap().count(), 2);
}

#[test]
fn init_card_mismatch_rolls_back_and_deletes_cards() {
    let f = Fixture::new();
    let mut ui = Script::pw(2);
    ui.cards_dir = Some(f.cards.clone());
    ui.wrong_card = true;
    let e = super::init::init(&f.opts(), &f.settings, &mut ui).unwrap_err();
    assert!(matches!(e, Error::CardMismatch("Card A")), "{e:?}");
    assert!(ui.said("rolled back"));
    assert_eq!(fs::read_dir(&f.cards).unwrap().count(), 0);
    assert!(f.settings.stale_cards(None).unwrap().is_empty());
    let mut names: Vec<String> = fs::read_dir(&f.vault)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["vault.gate", "vault.lock"]);
}

#[test]
fn init_refuses_mismatch_weak_medium_and_cards_inside_the_vault() {
    let f = Fixture::new();
    let mut ui = Script::new();
    ui.secrets.extend([PW.to_vec(), b"other".to_vec()]);
    assert!(matches!(
        super::init::init(&f.opts(), &f.settings, &mut ui),
        Err(Error::PassphraseMismatch)
    ));
    let weak = |_: &passphrase::CustomPassphrase, _: &str| Ok((Band::Weak, Vec::new()));
    let medium = |_: &passphrase::CustomPassphrase, _: &str| Ok((Band::Medium, Vec::new()));
    let mut opts = f.opts();
    opts.estimate = &weak;
    assert!(matches!(
        super::init::init(&opts, &f.settings, &mut Script::pw(2)),
        Err(Error::PassphraseWeak)
    ));
    opts.estimate = &medium;
    assert!(matches!(
        super::init::init(&opts, &f.settings, &mut Script::pw(2)),
        Err(Error::NeedsTerminal(_))
    ));
    // Generated mode needs the terminal device.
    let mut opts = f.opts();
    opts.passphrase = PassphraseChoice::Generated(passphrase::WordCount::new(12).unwrap());
    assert!(matches!(
        super::init::init(&opts, &f.settings, &mut Script::new()),
        Err(Error::NeedsTerminal(_))
    ));
    // Nothing but the bootstrap creations exist.
    assert_eq!(fs::read_dir(&f.vault).unwrap().count(), 2);
    let mut opts = f.opts();
    opts.cards_dir = f.vault.clone();
    assert!(matches!(
        super::init::init(&opts, &f.settings, &mut Script::pw(2)),
        Err(Error::CardDestinationInVault)
    ));
}

#[test]
fn add_replace_get_rm_with_fresh_ids_and_object_cleanup() {
    let f = Fixture::new().init();
    let src = f.source("a.txt", &vec![7u8; 100_000]);
    let out = f.add(&src, "docs/a.txt", false).unwrap();
    assert_eq!((out.size, out.created_dirs), (100_000, 1));
    let first = f.objects();
    assert_eq!(first.len(), 1);
    assert!(matches!(
        f.add(&src, "docs/a.txt", false),
        Err(Error::PathExists)
    ));
    assert!(matches!(
        f.add(&src, "DOCS/A.TXT", false),
        Err(Error::PathCollision)
    ));
    assert!(matches!(
        f.add(&src, "Docs/A.txt", true),
        Err(Error::ReplaceNeedsStoredPath)
    ));
    assert!(matches!(
        f.add(&src, "docs", true),
        Err(Error::WrongKind(_))
    ));
    assert!(matches!(
        f.add(&src, "docs/a.txt/x", false),
        Err(Error::WrongKind(_))
    ));
    // F64: --replace makes a new object with a new ID; the old one is gone.
    let src2 = f.source("b.txt", b"replaced");
    f.add(&src2, "docs/a.txt", true).unwrap();
    let second = f.objects();
    assert_eq!(second.len(), 1);
    assert_ne!(first, second);
    assert_eq!(f.generation(), 3);
    assert!(!f.vault.join("keytable.2.pv").exists());
    // get.
    let mut ui = Script::new();
    let s = f.unlock(Access::Read, &mut ui).unwrap();
    let dest = f.root.join("out.txt");
    export::get(&s, "docs/a.txt", &dest, &f.settings, &mut ui).unwrap();
    assert_eq!(fs::read(&dest).unwrap(), b"replaced");
    assert!(matches!(
        export::get(&s, "docs/a.txt", &dest, &f.settings, &mut ui),
        Err(GetError::Failed(Error::DestinationExists))
    ));
    assert!(matches!(
        export::get(&s, "docs", &f.root.join("x"), &f.settings, &mut ui),
        Err(GetError::Failed(Error::WrongKind(_)))
    ));
    drop(s);
    // F20: rm.
    let mut ui = Script::new();
    let mut s = f.unlock(Access::Write, &mut ui).unwrap();
    assert!(matches!(
        edit::rm(&mut s, "docs", false, Some(&f.settings), &mut ui),
        Err(Error::FolderNotEmpty)
    ));
    let (n, kept) = edit::rm(&mut s, "docs/a.txt", false, Some(&f.settings), &mut ui).unwrap();
    assert_eq!((n, kept.len()), (1, 0));
    assert!(f.objects().is_empty());
    drop(s);
    let listing = f.listing();
    assert!(
        listing.starts_with("dir\t-\t") && listing.ends_with("\tdocs\n"),
        "{listing}"
    );
}

#[test]
fn stored_paths_are_rendered_safely_in_list() {
    let f = Fixture::new().init();
    let src = f.source("a", b"x");
    // 7.8 rejects C0, DEL and backslash; C1 and bidirectional controls are
    // storable and must be escaped on output.
    f.add(&src, "a\u{9B}b\u{202E}c\u{2066}d\u{FEFF}", false)
        .unwrap();
    let out = f.listing();
    assert!(
        out.ends_with("a\\u{009B}b\\u{202E}c\\u{2066}d\\u{FEFF}\n"),
        "{out}"
    );
    assert!(!out.contains('\u{9B}') && !out.contains('\u{202E}'));
}

#[test]
fn wrong_passphrase_is_unlock_failed_and_changes_nothing() {
    let f = Fixture::new().init();
    let before = f.snapshot();
    let mut ui = Script::new();
    ui.secrets.push_back(b"wrong passphrase entirely".to_vec());
    assert!(matches!(
        unlock(&f.vault, &mut ui, Some(&f.settings), Access::Write),
        Err(Error::HeaderInvalid)
    ));
    assert_eq!(f.snapshot(), before);
}

/// F74 (portable duress part): a duress match is `Unlock failed.` and
/// changes nothing (Milestone 4 has no duress action).
#[test]
fn duress_match_modifies_nothing() {
    let f = Fixture::new().init();
    let mut ui = Script::new();
    let s = f.unlock(Access::Write, &mut ui).unwrap();
    let core = s.header.core().clone();
    let duress_words = b"apple banana cherry dragon eagle falcon grape honey igloo jungle";
    let handled = passphrase::handle_words(duress_words).unwrap();
    let m2 = kdf::master_pw(&handled, &core.salt, core.argon2).unwrap();
    let dk = kdf::passphrase_subkey(&m2, PassphraseKey::Duress).unwrap();
    let SlotFields::Portable(p) = s.header.slots().clone() else {
        panic!()
    };
    let slots = SlotFields::Portable(PortableSlots {
        duress_tag: Some(super::duress_tag(&dk, &core.vault_id)),
        ..p
    });
    let bytes = Header::build(&core, &slots, &s.bundle.k_mac).unwrap();
    drop(s);
    fs::write(f.vault.join("vault.hdr"), &bytes).unwrap();
    let before = f.snapshot();
    let mut ui = Script::new();
    ui.secrets.push_back(duress_words.to_vec());
    assert!(matches!(
        unlock(&f.vault, &mut ui, Some(&f.settings), Access::Write),
        Err(Error::HeaderInvalid)
    ));
    assert_eq!(f.snapshot(), before);
    // The real passphrase still opens it.
    f.unlock(Access::Read, &mut Script::new()).unwrap();
}

/// F92: the N5 entry limit is checked before any side effect.
#[test]
fn entry_limit_is_refused_before_side_effects() {
    let f = Fixture::new().init();
    let src = f.source("a", b"x");
    let mut ui = Script::new();
    let mut s = f.unlock(Access::Write, &mut ui).unwrap();
    let entries: Vec<NewEntry> = (0..crate::keytable::MAX_ENTRIES)
        .map(|i| NewEntry {
            kind: EntryKind::Dir,
            path: zeroize::Zeroizing::new(format!("d{i:05}")),
            file_id: [0; 16],
            size: 0,
            created_at: 0,
            modified_at: 0,
            keys: None,
        })
        .collect();
    s.table = KeyTable::from_entries(entries).unwrap();
    let before = f.snapshot();
    let e = edit::add(&mut s, &src, "new", false, Some(&f.settings), &mut ui).unwrap_err();
    assert!(matches!(e, Error::Capacity(_)), "{e:?}");
    assert_eq!(f.snapshot(), before);
}

#[test]
fn unowned_leftovers_block_until_confirmed() {
    let f = Fixture::new().init();
    let src = f.source("a", b"x");
    fs::write(f.vault.join("vault.hdr.tmp"), b"not ours").unwrap();
    assert!(matches!(
        f.add(&src, "a", false),
        Err(Error::UnownedLeftovers(_))
    ));
    assert!(f.vault.join("vault.hdr.tmp").exists());
    let mut ui = Script::new().confirm(&[true]);
    let mut s = f.unlock(Access::Write, &mut ui).unwrap();
    edit::add(&mut s, &src, "a", false, Some(&f.settings), &mut ui).unwrap();
    assert!(ui.said("DELETE VAULT LEFTOVERS"));
    assert!(!f.vault.join("vault.hdr.tmp").exists());
}

/// 9.5 unresolved cleanup and its explicit closure.
#[test]
fn unresolved_cleanup_keeps_the_journal_reads_continue_and_close_removes_only_it() {
    let f = Fixture::new().init();
    f.add(&f.source("a", b"aaa"), "a", false).unwrap();
    f.add(&f.source("b", b"bbb"), "b", false).unwrap();
    let a_object = f.objects();
    let gen_before = f.generation();
    // Stop after the commit of `rm a` (header new, journal `committing`).
    let mut ui = Script::new();
    let mut s = f.unlock(Access::Write, &mut ui).unwrap();
    inject("update.before-cleanup");
    assert!(matches!(
        edit::rm(&mut s, "a", false, Some(&f.settings), &mut ui),
        Err(Error::Io(_))
    ));
    drop(s);
    assert_eq!(f.generation(), gen_before + 1);
    let journal = fs::read(f.vault.join("vault.journal")).unwrap();
    // Outside the protocol: the old key table disappears.
    fs::remove_file(f.vault.join(format!("keytable.{gen_before}.pv"))).unwrap();
    let objects_before = f.objects();
    // Reads continue, with the report.
    let mut ui = Script::new();
    let s = f.unlock(Access::Read, &mut ui).unwrap();
    assert!(s.unresolved);
    assert!(ui.said("cleanup could not be finished"));
    assert!(ui.said(&format!("Missing: keytable.{gen_before}.pv")));
    let mut out = Vec::new();
    export::list(&s, None, &mut out).unwrap();
    assert!(String::from_utf8(out).unwrap().ends_with("\tb\n"));
    drop(s);
    // Mutations stop (exit 5) unless the owner closes it.
    let src = f.source("c", b"c");
    assert!(matches!(
        f.add(&src, "c", false),
        Err(Error::UnresolvedCleanup)
    ));
    assert_eq!(fs::read(f.vault.join("vault.journal")).unwrap(), journal);
    assert_eq!(f.objects(), objects_before);
    let mut ui = Script::new().confirm(&[true]);
    let mut s = f.unlock(Access::Write, &mut ui).unwrap();
    edit::add(&mut s, &src, "c", false, Some(&f.settings), &mut ui).unwrap();
    assert!(ui.said("CLOSE UNFINISHED CLEANUP"));
    drop(s);
    // Nothing was deleted: `a`'s object is still there, unreferenced.
    let after = f.objects();
    for o in &a_object {
        assert!(after.contains(o));
    }
    assert!(!f.vault.join("vault.journal").exists());
}

/// 9.6 rows U10b (residue journal temp): the restart offers only that file.
#[test]
fn residue_journal_temp_blocking_cleanup_is_offered() {
    let f = Fixture::new().init();
    f.add(&f.source("a", b"aaa"), "a", false).unwrap();
    let mut ui = Script::new();
    let mut s = f.unlock(Access::Write, &mut ui).unwrap();
    inject("update.before-cleanup");
    let src = f.source("a2", b"new");
    assert!(edit::add(&mut s, &src, "a", true, Some(&f.settings), &mut ui).is_err());
    drop(s);
    assert_eq!(f.objects().len(), 2);
    fs::write(f.vault.join("vault.journal.tmp"), b"partial").unwrap();
    let mut ui = Script::new();
    assert!(matches!(
        f.unlock(Access::Read, &mut ui),
        Err(Error::UnownedLeftovers(_))
    ));
    assert!(f.vault.join("vault.journal.tmp").exists());
    let mut ui = Script::new().confirm(&[true]);
    f.unlock(Access::Read, &mut ui).unwrap();
    assert!(ui.said("An interrupted change was found and completed."));
    assert!(!f.vault.join("vault.journal.tmp").exists());
    assert!(!f.vault.join("vault.journal").exists());
    assert_eq!(f.objects().len(), 1);
}

/// An interrupted change before its commit is rolled back by the next
/// unlock.
#[test]
fn staged_change_is_rolled_back() {
    let f = Fixture::new().init();
    let generation = f.generation();
    let before = f.snapshot();
    let src = f.source("a", b"aaa");
    // Fail the commit's post-replacement point? No: fail before it, at the
    // header replacement, which leaves `committing` with the old header.
    let mut ui = Script::new();
    let mut s = f.unlock(Access::Write, &mut ui).unwrap();
    inject("header.replace");
    assert!(edit::add(&mut s, &src, "a", false, Some(&f.settings), &mut ui).is_err());
    drop(s);
    assert!(f.vault.join("vault.journal").exists());
    let mut ui = Script::new();
    f.unlock(Access::Read, &mut ui).unwrap();
    assert!(ui.said("undone"));
    assert_eq!(f.generation(), generation);
    let mut after = f.snapshot();
    // `objects/` stays (never deleted); compare the rest.
    after.retain(|(n, _)| !n.starts_with("objects/"));
    assert_eq!(after, before);
    assert!(f.objects().is_empty());
}

/// 10.2 and 10.4: changes visible at a check point are detected; the
/// transient case is demonstrated, not claimed.
#[cfg(not(windows))]
#[test]
fn source_changes() {
    use std::io::Write;
    let f = Fixture::new().init();
    let generation = f.generation();
    let src = f.source("s", &vec![1u8; 300_000]);
    edit::tests::set_after_snapshot(|p| {
        fs::OpenOptions::new()
            .append(true)
            .open(p)
            .unwrap()
            .write_all(b"more")
            .unwrap();
    });
    assert!(matches!(
        f.add(&src, "grow", false),
        Err(Error::SourceChanged)
    ));
    fs::write(&src, vec![1u8; 300_000]).unwrap();
    edit::tests::set_after_snapshot(|p| {
        fs::OpenOptions::new()
            .write(true)
            .open(p)
            .unwrap()
            .set_len(1000)
            .unwrap();
    });
    assert!(matches!(
        f.add(&src, "shrink", false),
        Err(Error::SourceChanged)
    ));
    fs::write(&src, vec![1u8; 300_000]).unwrap();
    edit::tests::set_after_snapshot(|p| {
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(p, vec![2u8; 300_000]).unwrap();
    });
    assert!(matches!(
        f.add(&src, "rewrite", false),
        Err(Error::SourceChanged)
    ));
    assert_eq!(f.generation(), generation, "nothing committed");
    assert!(!f.vault.join("vault.journal").exists());
    // Transient: same size, modification time restored. Unix change time
    // still moves (normally detected); a coarse clock or a privileged
    // writer can hide it (10.4). Either outcome is reported, not asserted.
    fs::write(&src, vec![1u8; 300_000]).unwrap();
    edit::tests::set_after_snapshot(|p| {
        let m = fs::metadata(p).unwrap().modified().unwrap();
        let file = fs::OpenOptions::new().write(true).open(p).unwrap();
        (&file).write_all(&[9u8; 10]).unwrap();
        file.set_modified(m).unwrap();
    });
    match f.add(&src, "transient", false) {
        Err(Error::SourceChanged) => eprintln!("transient change: detected (change time moved)"),
        Ok(_) => eprintln!("transient change: NOT detected (documented limit, 10.4)"),
        Err(e) => panic!("{e:?}"),
    }
}

/// 10.1 on Windows: the source is open with read sharing only, so no new
/// writer can open it while pvault reads (prevention; Unix detects instead:
/// `source_changes`).
#[cfg(windows)]
#[test]
fn source_writers_are_blocked_on_windows() {
    let f = Fixture::new().init();
    let generation = f.generation();
    let src = f.source("s", &vec![1u8; 300_000]);
    // Windows (10.1): the source is open with read sharing only, so no new
    // writer can open it while pvault reads; prevention replaces detection.
    use std::cell::Cell;
    use std::rc::Rc;
    let tried = Rc::new(Cell::new(false));
    let seen = tried.clone();
    edit::tests::set_after_snapshot(move |p| {
        for e in [
            fs::OpenOptions::new().append(true).open(p).err(),
            fs::OpenOptions::new().write(true).open(p).err(),
        ] {
            assert_eq!(
                e.and_then(|e| e.raw_os_error()),
                Some(32),
                "sharing violation"
            );
        }
        seen.set(true);
    });
    let out = f.add(&src, "blocked", false).unwrap();
    assert!(tried.get());
    assert_eq!(out.size, 300_000, "the original content was stored");
    assert_eq!(f.generation(), generation + 1);
}

#[test]
fn source_kinds_are_refused() {
    let f = Fixture::new().init();
    assert!(matches!(
        f.add(&f.root, "dir", false),
        Err(Error::SourceNotRegular)
    ));
    #[cfg(unix)]
    {
        let target = f.source("t", b"x");
        let link = f.root.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(f.add(&link, "l", false), Err(Error::SourceLink)));
        let fifo = f.root.join("fifo");
        let st = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(st.success());
        assert!(matches!(
            f.add(&fifo, "p", false),
            Err(Error::SourceNotRegular)
        ));
    }
}

/// 7.5 publication rule: before publication nothing exists at the
/// destination (exit 1); after it the file is kept (exit 5).
#[test]
fn export_publication_classification() {
    let f = Fixture::new().init();
    let data = vec![5u8; 70_000];
    f.add(&f.source("a", &data), "a", false).unwrap();
    let mut ui = Script::new();
    let s = f.unlock(Access::Read, &mut ui).unwrap();
    let vid = s.vault_id();
    let dest = |n: &str| f.root.join(n);
    let partial = |n: &str| f.root.join(format!("{n}.pvpartial"));
    let stale = || f.settings.stale_partials(Some(&vid)).unwrap();

    inject("export.rename");
    assert!(matches!(
        export::get(&s, "a", &dest("e1"), &f.settings, &mut ui),
        Err(GetError::Failed(Error::Io(_)))
    ));
    assert!(!dest("e1").exists() && !partial("e1").exists());
    assert!(stale().is_empty());

    inject("export.rename-reported");
    assert!(matches!(
        export::get(&s, "a", &dest("e2"), &f.settings, &mut ui),
        Err(GetError::Unconfirmed(_))
    ));
    assert_eq!(fs::read(dest("e2")).unwrap(), data);
    assert!(stale().is_empty());

    inject("export.flush-parent");
    assert!(matches!(
        export::get(&s, "a", &dest("e3"), &f.settings, &mut ui),
        Err(GetError::Unconfirmed(_))
    ));
    assert_eq!(fs::read(dest("e3")).unwrap(), data);

    inject("records.flush-file");
    assert!(matches!(
        export::get(&s, "a", &dest("e4"), &f.settings, &mut ui),
        Err(GetError::Failed(Error::NotRegistered(_)))
    ));
    assert!(!dest("e4").exists() && !partial("e4").exists());

    // E6 fails: kept, and the entry names only the partial path; the
    // cleaner drops it without touching the published file.
    inject("export.unregister");
    assert!(matches!(
        export::get(&s, "a", &dest("e5"), &f.settings, &mut ui),
        Err(GetError::Unconfirmed(_))
    ));
    assert_eq!(stale().len(), 1);
    drop(stale());
    let mut cleaner = Script::new().confirm(&[true]);
    let report = export::clean_partials(&f.settings, &mut cleaner).unwrap();
    assert_eq!((report.stale, report.confirmed), (1, true));
    assert!(stale().is_empty());
    assert_eq!(fs::read(dest("e5")).unwrap(), data);

    // Name too long for the suffix: refused before any file exists.
    let long = "n".repeat(250);
    assert!(matches!(
        export::get(&s, "a", &dest(&long), &f.settings, &mut ui),
        Err(GetError::Failed(Error::NameTooLong))
    ));
    assert!(
        fs::read_dir(&f.root).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("nnnn"))
    );
    drop(s);

    // A damaged object: decryption fails; the partial is removed.
    let obj = f.vault.join("objects").join(&f.objects()[0]);
    let mut bytes = fs::read(&obj).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&obj, bytes).unwrap();
    let mut ui = Script::new();
    let s = f.unlock(Access::Read, &mut ui).unwrap();
    assert!(matches!(
        export::get(&s, "a", &dest("e6"), &f.settings, &mut ui),
        Err(GetError::Failed(Error::Stream))
    ));
    assert!(!dest("e6").exists() && !partial("e6").exists());
    assert!(stale().is_empty());
}

/// F4 (portable part): one card cannot open the vault. Card A combined with
/// any guess for Card B gives a bundle the header's MACs reject; a card
/// cannot be paired with itself.
#[test]
fn one_portable_card_cannot_open_the_vault() {
    let f = Fixture::new();
    let mut ui = Script::pw(3);
    ui.cards_dir = Some(f.cards.clone());
    super::init::init(&f.opts(), &f.settings, &mut ui).unwrap();
    let card_a = card::Card::parse(ui.entered_cards.remove(0)).unwrap();
    let card_b = card::Card::parse(ui.entered_cards.remove(0)).unwrap();
    let header = store::read_header(&crate::platform::fs::Dir::open(&f.vault).unwrap())
        .unwrap()
        .unwrap();
    let opens = |a: &crate::shamir::Share, b: &crate::shamir::Share| {
        crate::shamir::combine(a, b).is_ok_and(|secret| {
            let bundle = super::Bundle::from_bytes(&secret).unwrap();
            header.verify_core(&bundle.k_mac) && header.verify_slots(&bundle.k_mac)
        })
    };
    let a = card_a.share().unwrap();
    // Both cards together do open it (the control).
    assert!(opens(&a, &card_b.share().unwrap()));
    for guess in [
        [0u8; 96],
        [0xff; 96],
        *card_a.share().unwrap().y().expose_secret(),
    ] {
        let forged =
            crate::shamir::Share::new(2, SecretBytes::take_from(&mut guess.to_vec()).unwrap())
                .unwrap();
        assert!(!opens(&a, &forged));
    }
    assert!(crate::shamir::combine(&a, &card_a.share().unwrap()).is_err());
}

/// F17 (portable part): a bound vault is refused by a portable-only command
/// before any passphrase is read.
#[test]
fn bound_header_is_refused_before_the_passphrase() {
    use crate::header::tests::{sample_bound_slots, sample_core};
    use crate::header::{Mode, PassphraseKind};
    let f = Fixture::new();
    fs::create_dir(&f.vault).unwrap();
    let core = sample_core(Mode::Bound, PassphraseKind::Custom);
    let key = SecretBytes::<32>::take_from(&mut [7u8; 32].to_vec()).unwrap();
    let bytes = Header::build(&core, &sample_bound_slots(false), &key).unwrap();
    fs::write(f.vault.join("vault.hdr"), bytes).unwrap();
    let mut ui = Script::new(); // no secret available: none may be read
    for access in [Access::Read, Access::Write] {
        assert!(matches!(
            unlock(&f.vault, &mut ui, Some(&f.settings), access),
            Err(Error::BoundVault)
        ));
    }
    let mut opts = f.opts();
    opts.cards_dir = f.cards.clone();
    assert!(matches!(
        super::init::init(&opts, &f.settings, &mut Script::new()),
        Err(Error::TargetNotEmpty)
    ));
}

/// F75: generated-word normalization at unlock; an unknown word gives the
/// hint with no Argon2id run.
#[test]
fn word_hint_and_normalization_without_argon2() {
    let f = Fixture::new();
    let mut opts = f.opts();
    opts.passphrase = PassphraseChoice::Generated(passphrase::WordCount::new(10).unwrap());
    let mut ui = Script::new();
    ui.tty = true;
    ui.cards_dir = Some(f.cards.clone());
    super::init::init(&opts, &f.settings, &mut ui).unwrap();
    let words = String::from_utf8(ui.shown_words.clone().unwrap()).unwrap();
    // Mixed case, extra and mixed whitespace, fullwidth (NFKC) letters.
    let mut varied = String::from(" \t");
    for (i, w) in words.split(' ').enumerate() {
        if i > 0 {
            varied.push_str(if i % 2 == 0 { "  " } else { "\u{3000}" });
        }
        if i == 0 {
            varied.extend(
                w.chars()
                    .map(|c| char::from_u32(c as u32 - 'a' as u32 + 0xFF41).unwrap()),
            );
        } else if i % 3 == 0 {
            varied.push_str(&w.to_uppercase());
        } else {
            varied.push_str(w);
        }
    }
    varied.push(' ');
    let mut ui = Script::new();
    ui.secrets.push_back(varied.into_bytes());
    unlock(&f.vault, &mut ui, Some(&f.settings), Access::Read).unwrap();
    // A word outside the list: the hint, and no Argon2id run.
    let mut wrong: Vec<&str> = words.split(' ').collect();
    wrong[3] = "notaword";
    let mut ui = Script::new();
    ui.secrets.push_back(wrong.join(" ").into_bytes());
    let before = kdf::ARGON2_RUNS.with(|c| c.get());
    let e = unlock(&f.vault, &mut ui, Some(&f.settings), Access::Read).unwrap_err();
    assert_eq!(e.to_string(), "Word 4 is not in the word list.");
    assert_eq!(kdf::ARGON2_RUNS.with(|c| c.get()), before);
}

/// F74: on an unsupported file system (mocked type) mutations are refused
/// and write nothing; read-only commands still work.
#[test]
fn unsupported_file_system_refuses_mutations_only() {
    use crate::platform::fs::tests::mock_fs_type;
    let f = Fixture::new().init();
    let src = f.source("a", b"aaa");
    f.add(&src, "a", false).unwrap();
    let before = f.snapshot();
    mock_fs_type(Some("msdos"));
    let refused = |e: Error| matches!(e, Error::UnsupportedFileSystem(ref t) if t == "msdos");
    assert!(refused(f.add(&src, "b", false).unwrap_err()));
    let mut ui = Script::new();
    let mut s = f.unlock(Access::Write, &mut ui).unwrap();
    assert!(refused(
        edit::rm(&mut s, "a", false, Some(&f.settings), &mut ui).unwrap_err()
    ));
    drop(s);
    assert_eq!(f.snapshot(), before, "nothing written");
    assert!(f.listing().ends_with("\ta\n"), "list works");
    let (report, _) = super::status::status(&f.vault, Some(&f.settings), None).unwrap();
    assert!(report.contains("Generation:"));
    // A new vault is refused before its folder exists (the mock makes the
    // card folder FAT too, so the O3 card-folder refusal may come first).
    let other = f.root.join("v2");
    let mut opts = f.opts();
    opts.vault = other.clone();
    let e = super::init::init(&opts, &f.settings, &mut Script::pw(3)).unwrap_err();
    assert!(
        matches!(
            e,
            Error::UnsupportedFileSystem(_) | Error::DestinationNotPrivate(_)
        ),
        "{e:?}"
    );
    assert!(!other.exists());
    mock_fs_type(None);
}

/// 7.1 and 7.7: a settings folder on an unsupported type (mocked) refuses
/// `get` before any destination file exists.
#[test]
fn unsupported_settings_folder_refuses_get_before_any_file() {
    use crate::platform::fs::tests::mock_fs_type;
    let f = Fixture::new().init();
    f.add(&f.source("a", b"aaa"), "a", false).unwrap();
    let mut ui = Script::new();
    let s = f.unlock(Access::Read, &mut ui).unwrap();
    let dest = f.root.join("out");
    // The settings-folder policy on its own.
    mock_fs_type(Some("nfs"));
    let direct = f.settings.check_registration();
    mock_fs_type(None);
    assert!(
        matches!(direct, Err(Error::RegistrationUnsupported(ref t)) if t == "nfs"),
        "{direct:?}"
    );
    // Through `get`. The mock applies to every folder, so a type that is a
    // supported destination but not a supported settings folder is needed
    // to reach the settings refusal: Linux `tmpfs`. Elsewhere the O3
    // destination refusal comes first; both refuse before any file.
    let t = if cfg!(target_os = "linux") {
        "tmpfs"
    } else {
        "nfs"
    };
    mock_fs_type(Some(t));
    let r = export::get(&s, "a", &dest, &f.settings, &mut ui);
    mock_fs_type(None);
    if cfg!(target_os = "linux") {
        assert!(
            matches!(r, Err(GetError::Failed(Error::RegistrationUnsupported(ref x))) if x == t),
            "{r:?}"
        );
    } else {
        assert!(
            matches!(r, Err(GetError::Failed(Error::DestinationNotPrivate(ref x))) if x == t),
            "{r:?}"
        );
    }
    assert!(!dest.exists());
    assert!(!f.root.join("out.pvpartial").exists());
}

/// A native name that is not valid Unicode: Unix byte 0xFF, Windows an
/// unpaired surrogate. `None` when this file system rejects such names
/// (APFS refuses invalid UTF-8), reported as a skip.
fn non_unicode_name(dir: &Path, stem: &str, ext: &str) -> Option<std::ffi::OsString> {
    #[cfg(unix)]
    let name = {
        use std::os::unix::ffi::OsStrExt;
        std::ffi::OsStr::from_bytes(&[stem.as_bytes(), b"\xff", ext.as_bytes()].concat()).to_owned()
    };
    #[cfg(windows)]
    let name = {
        use std::os::windows::ffi::OsStringExt;
        let units: Vec<u16> = stem
            .encode_utf16()
            .chain([0xD800])
            .chain(ext.encode_utf16())
            .collect();
        std::ffi::OsString::from_wide(&units)
    };
    assert!(name.to_str().is_none());
    let probe = dir.join(&name);
    match fs::write(&probe, b"") {
        Ok(()) => {
            fs::remove_file(&probe).unwrap();
            Some(name)
        }
        Err(e) => {
            // The dedicated Linux and Windows CI step sets this: there a skip
            // is a failure. Locally on APFS the skip is the documented limit.
            if std::env::var_os("PVAULT_TEST_REQUIRE_NATIVE_NAMES").is_some() {
                panic!("non-Unicode native names are required here but were rejected: {e}");
            }
            eprintln!(
                "skipped: this file system rejects non-Unicode names ({e}; APFS refuses invalid UTF-8)"
            );
            None
        }
    }
}

/// 7.2 native names (2026-10-06, item 4): an export to a destination name
/// that is not valid Unicode is published, recorded by its native bytes and
/// cleaned up by them; a vault folder with such a name is created. Vault
/// paths stay strict Unicode.
#[test]
fn non_unicode_native_names_export_record_and_cleanup() {
    use crate::platform::fs::{self as pfs, Dir};
    use crate::records::{OpKind, PartialEntry, RecordedFile, StaleOutcome, native_path};
    let f = Fixture::new();
    let Some(odd) = non_unicode_name(&f.root, "out", ".bin") else {
        return;
    };
    let f = f.init();
    f.add(&f.source("a", b"payload"), "a", false).unwrap();
    let mut ui = Script::new();
    let s = f.unlock(Access::Read, &mut ui).unwrap();
    let dest = f.root.join(&odd);
    export::get(&s, "a", &dest, &f.settings, &mut ui).unwrap();
    assert_eq!(fs::read(&dest).unwrap(), b"payload");
    drop(s);
    // A stale partial with a non-Unicode name, as a crash at E4 leaves it.
    let mut partial = odd.clone();
    partial.push(".pvpartial");
    let lock = f.settings.begin_operation(OpKind::Transfer).unwrap();
    let dir = Dir::open(&f.root).unwrap();
    let file = dir.create_new(&partial).unwrap();
    let id = pfs::record_identity(&file).unwrap();
    let has_btime = id.btime.is_some();
    let recorded = RecordedFile {
        path: native_path(&f.root.join(&partial)).unwrap(),
        id,
    };
    assert_eq!(
        crate::records::path_from_native(&recorded.path),
        f.root.join(&partial)
    );
    f.settings
        .register_partial(PartialEntry {
            transfer_id: lock.id(),
            vault_id: [1; 16],
            created_at: 1,
            file: recorded.clone(),
        })
        .unwrap();
    drop(file);
    drop(lock); // as a crash
    let mut ui = Script::new().confirm(&[true]);
    let report = export::clean_partials(&f.settings, &mut ui).unwrap();
    assert_eq!((report.stale, report.confirmed), (1, true));
    if has_btime {
        assert!(
            !f.root.join(&partial).exists(),
            "deleted by its native name"
        );
        assert!(ui.said("Deleted"));
    } else {
        assert_eq!(
            crate::records::delete_recorded(&recorded).unwrap(),
            StaleOutcome::Unprovable
        );
        assert!(f.root.join(&partial).exists(), "kept: no birth time");
    }
    // The rendered name escapes the invalid part.
    assert!(
        ui.notices
            .iter()
            .any(|n| n.contains("out\\xFF.bin") || n.contains("out\\u{D800}.bin"))
    );
    // A vault folder with a non-Unicode name.
    let g = Fixture::new();
    let mut opts = g.opts();
    opts.vault = g.root.join(non_unicode_name(&g.root, "vault", "").unwrap());
    let mut ui = Script::pw(3);
    ui.cards_dir = Some(g.cards.clone());
    assert!(matches!(
        super::init::init(&opts, &g.settings, &mut ui).unwrap(),
        InitOutcome::Created { .. }
    ));
    // Vault paths remain strict Unicode (they are `&str` by type, and the
    // CLI decodes them strictly, 7.8 and `docs/M4_READINESS.md` 8).
}

/// O3 (decided 2026-10-06, fail closed), mocked types: exports and card
/// files go only to identified file systems that enforce owner-only access
/// locally; FAT/exFAT, FUSE (`fuseblk`), network, other, unknown and
/// unidentifiable destinations are refused before any destination file,
/// record entry or secret. The real-image and real-destination tests in
/// `tests/failure_scenarios.rs` check the same on real file systems.
#[test]
fn private_destinations_required_for_exports_and_cards() {
    use crate::platform::fs::is_private_destination_type;
    use crate::platform::fs::tests::{mock_fs_type, mock_unidentified};
    let refused_types = [
        "msdos",
        "vfat",
        "exfat",
        "FAT",
        "FAT32",
        "exFAT",
        "fuseblk",
        "fuse.sshfs",
        "fuse",
        "nfs",
        "nfs4",
        "cifs",
        "smb3",
        "smbfs",
        "afpfs",
        "webdav",
        "9p",
        "zfs",
        "overlay",
        "devfs",
        "proc",
        "unknownfs",
        "",
        "Ext4",
        "APFS",
        "ntfs",
    ];
    for t in refused_types {
        assert!(!is_private_destination_type(t), "{t}");
    }
    let supported: &[&str] = if cfg!(target_os = "linux") {
        &["ext4", "xfs", "btrfs", "tmpfs"]
    } else if cfg!(target_os = "macos") {
        &["apfs", "hfs"]
    } else {
        &["NTFS", "ReFS"]
    };
    for t in supported {
        assert!(is_private_destination_type(t), "{t}");
    }
    let f = Fixture::new().init();
    f.add(&f.source("a", b"aaa"), "a", false).unwrap();
    let mut ui = Script::new();
    let s = f.unlock(Access::Read, &mut ui).unwrap();
    let dest = f.root.join("out");
    let nothing = |f: &Fixture| {
        assert!(!dest.exists() && !f.root.join("out.pvpartial").exists());
        assert!(
            f.settings.stale_partials(None).unwrap().is_empty(),
            "nothing recorded"
        );
    };
    for t in refused_types {
        mock_fs_type(Some(t));
        let early = export::check_destination(&dest);
        let r = export::get(&s, "a", &dest, &f.settings, &mut ui);
        mock_fs_type(None);
        assert!(
            matches!(early, Err(Error::DestinationNotPrivate(ref x)) if x == t),
            "{t}: {early:?}"
        );
        assert!(
            matches!(r, Err(GetError::Failed(Error::DestinationNotPrivate(ref x))) if x == t),
            "{t}: {r:?}"
        );
        nothing(&f);
    }
    // Unidentifiable (a Windows network share): refused too.
    mock_unidentified(true);
    let early = export::check_destination(&dest);
    let r = export::get(&s, "a", &dest, &f.settings, &mut ui);
    mock_unidentified(false);
    assert!(
        matches!(early, Err(Error::DestinationNotPrivate(_))),
        "{early:?}"
    );
    assert!(
        matches!(r, Err(GetError::Failed(Error::DestinationNotPrivate(_)))),
        "{r:?}"
    );
    nothing(&f);
    // The supported local type passes.
    export::check_destination(&dest).unwrap();
    drop(s);
    // Card folders: refused before the vault folder exists and before any
    // secret is read.
    for t in ["fuseblk", "unknownfs", "exfat"] {
        let g = Fixture::new();
        mock_fs_type(Some(t));
        let mut ui = Script::pw(3);
        ui.cards_dir = Some(g.cards.clone());
        let r = super::init::init(&g.opts(), &g.settings, &mut ui);
        mock_fs_type(None);
        assert!(
            matches!(r, Err(Error::DestinationNotPrivate(_))),
            "{t}: {r:?}"
        );
        assert!(
            !g.vault.exists(),
            "{t}: refused before the vault folder exists"
        );
        assert_eq!(fs::read_dir(&g.cards).unwrap().count(), 0);
        assert_eq!(ui.secrets.len(), 3, "{t}: no secret read");
        assert!(g.settings.stale_cards(None).unwrap().is_empty());
    }
    let g = Fixture::new();
    mock_unidentified(true);
    let mut ui = Script::pw(3);
    ui.cards_dir = Some(g.cards.clone());
    let r = super::init::init(&g.opts(), &g.settings, &mut ui);
    mock_unidentified(false);
    assert!(matches!(r, Err(Error::DestinationNotPrivate(_))), "{r:?}");
    assert!(!g.vault.exists());
    assert_eq!(ui.secrets.len(), 3);
    // The message explains and suggests (exit 6 in the CLI).
    let msg = Error::DestinationNotPrivate("fuseblk".into()).to_string();
    assert!(msg.contains("only where it can confirm") && msg.contains("on fuseblk"));
    assert!(msg.contains("Nothing was written.") && msg.contains("Choose a folder on a local"));
}
