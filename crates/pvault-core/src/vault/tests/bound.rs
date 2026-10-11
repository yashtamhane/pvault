//! Bound mode on `swtpm` (Milestone 5; Linux with the `tpm` feature). Every
//! test starts its own emulator with fresh state (D12); no real TPM is ever
//! opened.
//!
//! These tests start processes, so they run one at a time in a test process
//! of their own, not among the others (`crate::test_process`).

use super::*;
use crate::header::{BoundSlots, Mode, SlotFields};
use crate::tpm::testing::Swtpm;
use crate::tpm::{TpmOptions, TpmState};

fn tpm_opts(sw: &Swtpm) -> TpmOptions {
    TpmOptions {
        target: sw.target(),
        owner_auth_declared: false,
    }
}

fn bound_opts(f: &Fixture, sw: &Swtpm) -> InitOptions<'static> {
    let mut o = f.opts();
    o.mode = Mode::Bound;
    o.tpm = tpm_opts(sw);
    o
}

/// A bound vault (paper card, custom passphrase) on `sw`.
fn init_bound(f: &Fixture, sw: &Swtpm) {
    let mut ui = Script::pw(3);
    ui.cards_dir = Some(f.cards.clone());
    let out = super::super::init::init(&bound_opts(f, sw), &f.settings, &mut ui).unwrap();
    assert!(matches!(out, InitOutcome::Created { .. }), "{out:?}");
}

fn slots(f: &Fixture) -> BoundSlots {
    let h = crate::store::read_header(&crate::platform::fs::Dir::open(&f.vault).unwrap())
        .unwrap()
        .unwrap();
    match h.slots() {
        SlotFields::Bound(b) => b.clone(),
        SlotFields::Portable(_) => panic!("portable"),
    }
}

fn state(sw: &Swtpm) -> TpmState {
    crate::tpm::open(&sw.target()).unwrap().state().unwrap()
}

fn unlock_b(f: &Fixture, sw: &Swtpm, pw: &[u8]) -> Result<Session, Error> {
    let mut ui = Script::new();
    ui.secrets.push_back(pw.to_vec());
    super::super::unlock_with(
        &f.vault,
        &mut ui,
        Some(&f.settings),
        Access::Write,
        &tpm_opts(sw),
    )
}

fn vault_bytes(f: &Fixture) -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<_> = fs::read_dir(&f.vault)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_file())
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                fs::read(&p).unwrap(),
            )
        })
        .collect();
    v.sort();
    v
}

/// The bound flow end to end; F30 (only the post-write Name is stored and
/// it is the TPM's); everyday commands; `status`.
#[test]
#[ignore = "starts processes: runs in its own test process (test_process)"]
fn bound_init_unlock_and_everyday_commands() {
    let Some(sw) = Swtpm::start() else { return };
    let f = Fixture::new();
    init_bound(&f, &sw);
    let b = slots(&f);
    assert!(
        b.index.name_prewrite.is_none(),
        "the slots keep the post-write Name only"
    );
    let public = crate::tpm::open(&sw.target())
        .unwrap()
        .read_public(b.index.tpm_index)
        .unwrap()
        .unwrap();
    assert!(public.matches(b.index.tpm_index, &b.index.policy_nonce, true));
    assert_eq!(public.name, b.index.name_postwrite);
    // Unlock, add, list.
    let mut s = unlock_b(&f, &sw, PW).unwrap();
    let src = f.source("a.txt", b"hello bound");
    edit::add(
        &mut s,
        &src,
        "a.txt",
        false,
        Some(&f.settings),
        &mut Script::new(),
    )
    .unwrap();
    drop(s);
    let s = unlock_b(&f, &sw, PW).unwrap();
    assert_eq!(s.table.len(), 1);
    drop(s);
    let (report, _) =
        super::super::status::status(&f.vault, Some(&f.settings), None, &tpm_opts(&sw)).unwrap();
    for line in [
        "Mode:                bound",
        "reachable",
        "Owner authorization: not set",
        "Lockout:             no",
        "TPM identity:        measurable",
        "Duress:              off",
    ] {
        assert!(report.contains(line), "{line}\n{report}");
    }
}

/// F1 (a copy on another TPM) and F3 (the index missing on the same TPM):
/// `Unlock failed.`, no passphrase-only path.
#[test]
#[ignore = "starts processes: runs in its own test process (test_process)"]
fn bound_vault_needs_its_index() {
    let Some(sw) = Swtpm::start() else { return };
    let f = Fixture::new();
    init_bound(&f, &sw);
    let Some(other) = Swtpm::start() else { return };
    assert!(matches!(
        unlock_b(&f, &other, PW),
        Err(Error::HeaderInvalid)
    ));
    let handle = format!("0x{:08x}", slots(&f).index.tpm_index);
    sw.tool(&["tpm2_nvundefine", &handle]);
    assert!(matches!(unlock_b(&f, &sw, PW), Err(Error::HeaderInvalid)));
}

/// F2 (wrong passphrase: generic failure, DA counter +1) and F19 (lockout:
/// a clear message, before any passphrase is read).
#[test]
#[ignore = "starts processes: runs in its own test process (test_process)"]
fn wrong_passphrase_and_lockout() {
    let Some(sw) = Swtpm::start() else { return };
    sw.short_lockout(2);
    let f = Fixture::new();
    init_bound(&f, &sw);
    let before = state(&sw).lockout_counter;
    assert!(matches!(
        unlock_b(&f, &sw, b"wrong passphrase entirely"),
        Err(Error::HeaderInvalid)
    ));
    assert_eq!(state(&sw).lockout_counter, before + 1);
    let _ = unlock_b(&f, &sw, b"wrong passphrase entirely");
    assert!(state(&sw).in_lockout());
    let mut ui = Script::new(); // no secret may be read
    let r = super::super::unlock_with(
        &f.vault,
        &mut ui,
        Some(&f.settings),
        Access::Read,
        &tpm_opts(&sw),
    );
    assert!(matches!(r, Err(Error::TpmLockout)), "{r:?}");
}

/// F52: a decoy at the handle (another size, or other attributes): generic
/// failure, `NV_Read` never called (the DA counter does not move).
#[test]
#[ignore = "starts processes: runs in its own test process (test_process)"]
fn decoy_public_areas() {
    let Some(sw) = Swtpm::start() else { return };
    let f = Fixture::new();
    init_bound(&f, &sw);
    let handle = format!("0x{:08x}", slots(&f).index.tpm_index);
    // Another size; NO_DA set; and pvault's exact attributes and size with
    // an empty `authPolicy` (another policy, so another Name).
    for (size, attrs) in [
        ("96", "authread|authwrite"),
        ("97", "authread|authwrite|no_da"),
        ("97", "authread|authwrite"),
    ] {
        sw.tool(&["tpm2_nvundefine", &handle]);
        sw.tool(&[
            "tpm2_nvdefine",
            &handle,
            "-s",
            size,
            "-a",
            attrs,
            "-p",
            "decoy",
        ]);
        let before = state(&sw).lockout_counter;
        assert!(matches!(unlock_b(&f, &sw, PW), Err(Error::HeaderInvalid)));
        assert_eq!(
            state(&sw).lockout_counter,
            before,
            "NV_Read was not attempted"
        );
    }
}

/// F17, F61, F65 for the bound card: digital bound delivery keeps one file,
/// a bound card (`share_x = 3`); the R5 check asks for the passphrase.
#[test]
#[ignore = "starts processes: runs in its own test process (test_process)"]
fn digital_bound_card_and_check() {
    let Some(sw) = Swtpm::start() else { return };
    let f = Fixture::new();
    let dir = f.root.join("card");
    fs::create_dir(&dir).unwrap();
    let mut o = bound_opts(&f, &sw);
    o.delivery = crate::records::Delivery::Digital;
    o.cards_dir = PathBuf::new();
    o.card_dir = Some(dir.clone());
    o.accept_digital_cards = true;
    let mut ui = Script::pw(3);
    let out = super::super::init::init(&o, &f.settings, &mut ui).unwrap();
    assert!(ui.said("Digital recovery card: this card file together with your passphrase"));
    assert!(
        !ui.said("SAME DRIVE"),
        "one card: no same-volume acknowledgment"
    );
    let InitOutcome::Created {
        card_files: Some(files),
        ..
    } = out
    else {
        panic!()
    };
    assert_eq!(files.len(), 1);
    let c = card::parse_card_file(&fs::read(&files[0]).unwrap()).unwrap();
    assert_eq!(
        (c.mode(), c.x(), c.role()),
        (card::CardMode::Bound, 3, "Bound card")
    );
    let h = crate::store::read_header(&crate::platform::fs::Dir::open(&f.vault).unwrap())
        .unwrap()
        .unwrap();
    assert!(
        c.check_for_vault(
            &h.core().vault_id,
            &h.core().card_set_id,
            card::CardMode::Bound
        )
        .is_ok()
    );
    assert_eq!(
        c.check_for_vault(
            &h.core().vault_id,
            &h.core().card_set_id,
            card::CardMode::Portable
        ),
        Err(card::CardError::WrongMode)
    );
    // R5 for a bound card: CHECK, then the passphrase.
    let mut ui = Script::new().confirm(&[true]);
    (ui.tty, ui.interactive) = (true, true);
    ui.secrets.push_back(PW.to_vec());
    let r = super::super::init::card_check_after_commit(&f.vault, &files, &mut ui).unwrap();
    assert_eq!(r, super::super::init::CardCheck::Passed);
    assert!(ui.said("with your passphrase, recovers this vault"));
    // A wrong passphrase fails the check and changes nothing.
    let mut ui = Script::new().confirm(&[true]);
    (ui.tty, ui.interactive) = (true, true);
    ui.secrets.push_back(b"not the passphrase at all".to_vec());
    assert!(matches!(
        super::super::init::card_check_after_commit(&f.vault, &files, &mut ui),
        Err(Error::CardCheckFailed(_))
    ));
}

/// F87: another program takes the journaled handle before `NV_DefineSpace`:
/// the setup starts over with a new journal and handle; the foreign index
/// is untouched.
#[test]
#[ignore = "starts processes: runs in its own test process (test_process)"]
fn raced_handle_starts_over() {
    let Some(sw) = Swtpm::start() else { return };
    let f = Fixture::new();
    let target = sw.target();
    let raced = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let r2 = raced.clone();
    super::super::init::hooks::set_before_define(move |handle| {
        let mut other = crate::tpm::open(&target).unwrap();
        let auth = SecretBytes::<32>::take_from(&mut [0x77; 32]).unwrap();
        other.define(handle, &[0x66; 32], &auth, None).unwrap();
        r2.set(handle);
    });
    init_bound(&f, &sw);
    let raced = raced.get();
    assert_ne!(raced, 0);
    assert_ne!(slots(&f).index.tpm_index, raced, "a new handle was chosen");
    let foreign = crate::tpm::open(&sw.target())
        .unwrap()
        .read_public(raced)
        .unwrap()
        .unwrap();
    assert!(
        foreign.matches(raced, &[0x66; 32], false),
        "the foreign index is untouched"
    );
    assert!(unlock_b(&f, &sw, PW).is_ok());
}

/// F88 (`init` part): an unknown definition outcome keeps the journal; the
/// resume removes the index under 9.2b.
#[test]
#[ignore = "starts processes: runs in its own test process (test_process)"]
fn unknown_define_outcome_is_resolved_by_the_resume() {
    let Some(sw) = Swtpm::start() else { return };
    let f = Fixture::new();
    crate::failpoints::inject("init.define-unknown");
    let mut ui = Script::pw(3);
    ui.cards_dir = Some(f.cards.clone());
    let r = super::super::init::init(&bound_opts(&f, &sw), &f.settings, &mut ui);
    assert!(matches!(r, Err(Error::TpmDefineUnknown)), "{r:?}");
    assert!(
        f.vault.join("vault.journal").exists(),
        "the journal is kept"
    );
    let rec = journal_init(&f);
    let handle = rec.idx.unwrap().index.tpm_index;
    let mut t = crate::tpm::open(&sw.target()).unwrap();
    assert!(t.read_public(handle).unwrap().is_some(), "the index exists");
    let r =
        super::super::init::init(&bound_opts(&f, &sw), &f.settings, &mut Script::pw(1)).unwrap();
    assert_eq!(r, InitOutcome::RolledBack);
    assert!(
        t.read_public(handle).unwrap().is_none(),
        "removed under 9.2b"
    );
}

fn journal_init(f: &Fixture) -> crate::journal::InitRecord {
    match crate::journal::Record::parse(&fs::read(f.vault.join("vault.journal")).unwrap()) {
        Ok(crate::journal::Record::Init(r)) => r,
        other => panic!("{other:?}"),
    }
}

/// F60: interrupted before the header write; the resume with the passphrase
/// removes the journaled index (9.2b) and the setup; without it nothing is
/// touched.
#[test]
#[ignore = "starts processes: runs in its own test process (test_process)"]
fn interrupted_before_the_header() {
    let Some(sw) = Swtpm::start() else { return };
    let f = Fixture::new();
    super::super::init::hooks::set_after_cards_written(|_| panic!("simulated crash"));
    let mut ui = Script::pw(3);
    ui.cards_dir = Some(f.cards.clone());
    let opts = bound_opts(&f, &sw);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        super::super::init::init(&opts, &f.settings, &mut ui)
    }));
    assert!(r.is_err());
    let handle = journal_init(&f).idx.unwrap().index.tpm_index;
    let mut t = crate::tpm::open(&sw.target()).unwrap();
    assert!(t.read_public(handle).unwrap().is_some());
    // Without the passphrase: nothing is touched.
    let mut wrong = Script::new();
    wrong
        .secrets
        .push_back(b"not the setup passphrase".to_vec());
    assert!(super::super::init::init(&opts, &f.settings, &mut wrong).is_err());
    assert!(t.read_public(handle).unwrap().is_some(), "left untouched");
    assert!(f.vault.join("vault.journal").exists());
    // With it: the index and the setup are removed.
    let r = super::super::init::init(&opts, &f.settings, &mut Script::pw(1)).unwrap();
    assert_eq!(r, InitOutcome::RolledBack);
    assert!(t.read_public(handle).unwrap().is_none());
    assert!(!f.vault.join("vault.journal").exists());
}

/// F59: interrupted after the header write, before the journal is removed;
/// the resume (Path A through the TPM) finishes and keeps the index; with
/// the duress passphrase it fails generically and changes nothing.
#[test]
#[ignore = "starts processes: runs in its own test process (test_process)"]
fn interrupted_after_the_header() {
    let Some(sw) = Swtpm::start() else { return };
    let f = Fixture::new();
    let opts = bound_opts(&f, &sw);
    // An interactive setup with the duress step, then a crash after commit.
    super::super::init::hooks::set_after_commit(|| panic!("simulated crash"));
    let mut ui = Script::pw(3).confirm(&[true]);
    (ui.tty, ui.interactive) = (true, true);
    ui.cards_dir = Some(f.cards.clone());
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        super::super::init::init(&opts, &f.settings, &mut ui)
    }));
    assert!(r.is_err());
    let duress = ui
        .duress_words
        .clone()
        .expect("a duress passphrase was set");
    assert!(slots(&f).duress_tag.is_some());
    assert!(f.vault.join("vault.hdr").exists() && f.vault.join("vault.journal").exists());
    let handle = slots(&f).index.tpm_index;
    let before = vault_bytes(&f);
    let mut d = Script::new();
    d.secrets.push_back(duress.clone());
    assert!(super::super::init::init(&opts, &f.settings, &mut d).is_err());
    assert_eq!(vault_bytes(&f), before, "nothing modified");
    let r = super::super::init::init(&opts, &f.settings, &mut Script::pw(1)).unwrap();
    assert!(matches!(r, InitOutcome::Finished { .. }), "{r:?}");
    assert!(!f.vault.join("vault.journal").exists());
    let mut t = crate::tpm::open(&sw.target()).unwrap();
    assert!(
        t.read_public(handle).unwrap().is_some(),
        "the live index is kept"
    );
    assert!(unlock_b(&f, &sw, PW).is_ok());
    // The configured duress passphrase is inactive: a generic failure, and
    // nothing changes (D6; F81 part).
    let before = vault_bytes(&f);
    assert!(matches!(
        unlock_b(&f, &sw, &duress),
        Err(Error::HeaderInvalid)
    ));
    assert_eq!(vault_bytes(&f), before);
    assert!(t.read_public(handle).unwrap().is_some());
}

/// F81: duress availability. Owner authorization set, the storage
/// hierarchy disabled, lockout: `duress set` is refused and `status` says
/// "unavailable".
#[test]
#[ignore = "starts processes: runs in its own test process (test_process)"]
fn duress_availability() {
    for (setup, why) in [
        ("owner", "owner authorization is set"),
        ("lockout", "the TPM is in lockout"),
    ] {
        let Some(sw) = Swtpm::start() else { return };
        let f = Fixture::new();
        init_bound(&f, &sw);
        let mut s = unlock_b(&f, &sw, PW).unwrap();
        match setup {
            "owner" => {
                sw.tool(&["tpm2_changeauth", "-c", "owner", "owner-auth"]);
            }
            _ => {
                sw.short_lockout(1);
                let _ = crate::tpm::open(&sw.target()).unwrap().read(
                    slots(&f).index.tpm_index,
                    &SecretBytes::<32>::take_from(&mut [1; 32]).unwrap(),
                );
                assert!(state(&sw).in_lockout());
            }
        }
        let mut ui = Script::new();
        ui.tty = true;
        let r = super::super::duress::set(&mut s, Some(&f.settings), &mut ui);
        assert!(
            matches!(&r, Err(Error::DuressUnavailable(w)) if w.contains(why)),
            "{r:?}"
        );
        drop(s);
        let (report, _) =
            super::super::status::status(&f.vault, Some(&f.settings), None, &tpm_opts(&sw))
                .unwrap();
        assert!(
            report.contains(&format!(
                "Duress:              off (unavailable on this TPM: {why}"
            )),
            "{report}"
        );
    }
    // The storage hierarchy disabled: the vault cannot be opened, and a new
    // bound vault is refused before anything is created.
    let Some(sw) = Swtpm::start() else { return };
    sw.tool(&["tpm2_hierarchycontrol", "-C", "p", "shEnable", "clear"]);
    let f = Fixture::new();
    let r = super::super::init::init(&bound_opts(&f, &sw), &f.settings, &mut Script::pw(3));
    assert!(matches!(r, Err(Error::TpmHierarchyDisabled)), "{r:?}");
    assert!(!f.vault.exists());
}

/// Duress set and disable on a bound vault (D5, D6); status says inactive;
/// a configured but unavailable duress is reported in status only.
#[test]
#[ignore = "starts processes: runs in its own test process (test_process)"]
fn bound_duress_set_and_disable() {
    let Some(sw) = Swtpm::start() else { return };
    let f = Fixture::new();
    init_bound(&f, &sw);
    let mut s = unlock_b(&f, &sw, PW).unwrap();
    let mut ui = Script::new();
    ui.tty = true;
    super::super::duress::set(&mut s, Some(&f.settings), &mut ui).unwrap();
    assert!(ui.said("It is inactive in this version"));
    let words = ui.duress_words.clone().unwrap();
    drop(s);
    assert!(slots(&f).duress_tag.is_some());
    let before = vault_bytes(&f);
    assert!(matches!(
        unlock_b(&f, &sw, &words),
        Err(Error::HeaderInvalid)
    ));
    assert_eq!(
        vault_bytes(&f),
        before,
        "an inactive duress match changes nothing"
    );
    sw.tool(&["tpm2_changeauth", "-c", "owner", "owner-auth"]);
    let (report, _) =
        super::super::status::status(&f.vault, Some(&f.settings), None, &tpm_opts(&sw)).unwrap();
    assert!(report.contains("configured (inactive: no duress action in this version); unavailable on this TPM: owner authorization is set"), "{report}");
    let mut s = unlock_b(&f, &sw, PW).unwrap();
    let mut ui = Script::new().confirm(&[true]);
    ui.tty = true;
    super::super::duress::disable(&mut s, Some(&f.settings), &mut ui).unwrap();
    drop(s);
    assert!(slots(&f).duress_tag.is_none());
    assert!(unlock_b(&f, &sw, &words).is_err());
}

/// F91 (N2): the H-2 identity cannot be measured: refused before anything
/// is created.
#[test]
#[ignore = "starts processes: runs in its own test process (test_process)"]
fn unmeasurable_identity_refuses_bound_init() {
    for cmd in [
        &["tpm2_changeauth", "-c", "endorsement", "e-auth"][..],
        &["tpm2_hierarchycontrol", "-C", "p", "ehEnable", "clear"][..],
    ] {
        let Some(sw) = Swtpm::start() else { return };
        sw.tool(cmd);
        let f = Fixture::new();
        let r = super::super::init::init(&bound_opts(&f, &sw), &f.settings, &mut Script::pw(3));
        assert!(matches!(r, Err(Error::TpmIdentity)), "{r:?}");
        assert!(!f.vault.exists(), "nothing created");
    }
}

/// D9: owner authorization. Non-interactive without `--tpm-owner-auth`:
/// refused before anything; declared: the line after the passphrase pair.
#[test]
#[ignore = "starts processes: runs in its own test process (test_process)"]
fn owner_authorization() {
    let Some(sw) = Swtpm::start() else { return };
    sw.tool(&["tpm2_changeauth", "-c", "owner", "owner-test-auth"]);
    let f = Fixture::new();
    let r = super::super::init::init(&bound_opts(&f, &sw), &f.settings, &mut Script::pw(3));
    assert!(matches!(r, Err(Error::TpmOwnerAuthRequired)), "{r:?}");
    assert!(!f.vault.exists());
    let mut o = bound_opts(&f, &sw);
    o.tpm.owner_auth_declared = true;
    // A wrong owner authorization: refused, nothing left behind.
    let mut ui = Script::new();
    ui.secrets.extend([
        PW.to_vec(),
        PW.to_vec(),
        b"wrong-owner".to_vec(),
        PW.to_vec(),
    ]);
    ui.cards_dir = Some(f.cards.clone());
    let r = super::super::init::init(&o, &f.settings, &mut ui);
    assert!(matches!(r, Err(Error::TpmOwnerAuthRejected)), "{r:?}");
    assert!(!f.vault.join("vault.journal").exists());
    let mut ui = Script::new();
    ui.secrets.extend([
        PW.to_vec(),
        PW.to_vec(),
        b"owner-test-auth".to_vec(),
        PW.to_vec(),
    ]);
    ui.cards_dir = Some(f.cards.clone());
    let f2 = Fixture::new();
    let mut o2 = bound_opts(&f2, &sw);
    o2.tpm.owner_auth_declared = true;
    ui.cards_dir = Some(f2.cards.clone());
    let out = super::super::init::init(&o2, &f2.settings, &mut ui).unwrap();
    assert!(matches!(out, InitOutcome::Created { .. }));
    assert!(unlock_b(&f2, &sw, PW).is_ok());
}
