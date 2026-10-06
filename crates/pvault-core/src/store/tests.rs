//! Crash/restart and failure-boundary tests for the vault directory.
//!
//! Crash tests run the scenario in a child process (this test binary,
//! `crash_child`) with `PVAULT_FAILPOINT` set, so the child aborts at the
//! named point; the parent then restarts on the files it left. Process
//! crashes do not establish power-loss safety (8.5 "Testing").

use std::path::Path;
use std::process::{Command, Stdio};

use super::*;
use crate::header::tests::{sample_bound_slots, sample_core};
use crate::header::{Mode, PassphraseKind, SlotFields, TpmCleanupEntry};
use crate::journal::tests as jt;
use crate::journal::{Idx, InitPhase, InitRecord, TransitionOp};
use crate::keytable::tests::sample;
use crate::platform::fs::tests::tempdir;
use crate::resources::tests::Fake;

const OLD_GEN: u64 = 7;
const NEW_GEN: u64 = 8;
const TRACK_GEN: u64 = 9;
const PROBE: Fake = Fake(Some(16 << 30), Some(8 << 30));

fn sb(b: u8) -> SecretBytes<32> {
    SecretBytes::take_from(&mut [b; 32]).unwrap()
}

/// Deterministic old and new bundles, so a child process derives the same.
struct Keys {
    kmac_old: SecretBytes<32>,
    jk_old: SecretBytes<32>,
    kt_old: StreamKeys,
    kmac_new: SecretBytes<32>,
    jk_new: SecretBytes<32>,
    kt_new: StreamKeys,
}

fn keys() -> Keys {
    let kmac_old = sb(0x11);
    let kmac_new = sb(0x22);
    Keys {
        jk_old: crate::crypto::kdf::journal_key(&kmac_old).unwrap(),
        jk_new: crate::crypto::kdf::journal_key(&kmac_new).unwrap(),
        kmac_old,
        kmac_new,
        kt_old: StreamKeys::new(sb(0x31), sb(0x32)),
        kt_new: StreamKeys::new(sb(0x41), sb(0x42)),
    }
}

impl Keys {
    fn old(&self) -> OldSide<'_> {
        OldSide {
            k_mac: &self.kmac_old,
            journal_key: &self.jk_old,
            keytable_keys: &self.kt_old,
            probe: &PROBE,
        }
    }

    fn new_side(&self) -> NewSide<'_> {
        NewSide {
            k_mac: &self.kmac_new,
            journal_key: &self.jk_new,
        }
    }
}

/// The TPM-identity digest sealed into the target index's token.
fn ek_digest() -> SecretBytes<32> {
    sb(0xee)
}

/// A bound vault at generation 7 with a real, encrypted key table.
fn setup(path: &Path) -> CoreFields {
    let dir = Dir::open(path).unwrap();
    let k = keys();
    let mut core = sample_core(Mode::Bound, PassphraseKind::Words);
    assert_eq!((core.generation, core.keytable_gen), (OLD_GEN, OLD_GEN));
    let f = dir.create_new(keytable_name(OLD_GEN)).unwrap();
    core.keytable_digest =
        keytable::write_file(&sample(), &core.vault_id, OLD_GEN, &k.kt_old, &f).unwrap();
    fs::flush_file(&f).unwrap();
    let bytes = Header::build(&core, &sample_bound_slots(false), &k.kmac_old).unwrap();
    let mut h = dir.create_new(HEADER).unwrap();
    h.write_all(&bytes).unwrap();
    fs::flush_file(&h).unwrap();
    dir.flush().unwrap();
    core
}

fn target_idx(k: &Keys, vault_id: &[u8; 16]) -> Idx {
    let index = jt::sample_idx().index;
    let token = tpmid::seal(
        Scope::NewIndexOldSide,
        &k.jk_old,
        vault_id,
        &index,
        &ek_digest(),
    )
    .unwrap();
    Idx { index, token }
}

fn prepared_rec(core: &CoreFields, k: &Keys) -> TransitionRecord {
    TransitionRecord {
        op: TransitionOp::Recover,
        phase: TransitionPhase::Prepared,
        vault_id: core.vault_id,
        old_gen: OLD_GEN,
        new_gen: NEW_GEN,
        target_mode: Mode::Bound,
        old_core_digest: core.digest().unwrap(),
        old_keytable_digest: core.keytable_digest,
        idx: Some(target_idx(k, &core.vault_id)),
        target_kt_id: None,
        new_core_digest: None,
        header_id: None,
        old_slots_authenticated: None,
        tracking_gen: None,
        cleanup_token: None,
        track_kt_id: None,
        tracking_core_digest: None,
        track_hdr_id: None,
        macs: Macs::Single([0; 64]),
    }
}

fn seal(rec: &TransitionRecord, k: &Keys) -> Vec<u8> {
    let dual = rec.phase == TransitionPhase::Committing;
    let mut r = Record::Transition(rec.clone());
    r.seal(&k.jk_old, dual.then_some(&k.jk_new)).unwrap();
    r.encode()
}

/// The new core and slots of the forward commit (deterministic).
fn new_header(core: &CoreFields, k: &Keys, kt_digest: [u8; 64]) -> (CoreFields, Vec<u8>) {
    let mut c = core.clone();
    c.generation = NEW_GEN;
    c.keytable_gen = NEW_GEN;
    c.keytable_digest = kt_digest;
    c.salt = [0x6b; 32];
    let SlotFields::Bound(mut slots) = sample_bound_slots(false) else {
        unreachable!()
    };
    slots.index = jt::sample_idx().index;
    slots.index.name_prewrite = None;
    let bytes = Header::build(&c, &SlotFields::Bound(slots), &k.kmac_new).unwrap();
    (c, bytes)
}

/// Drives the forward protocol to `phase` with real artifacts and durable
/// journals, as recovery (Milestone 6) will.
fn drive(dir: &Dir, core: &CoreFields, k: &Keys, phase: TransitionPhase) -> TransitionRecord {
    let mut rec = prepared_rec(core, k);
    write_journal(dir, &seal(&rec, k)).unwrap();
    if phase == TransitionPhase::Prepared {
        return rec;
    }
    let kt = Owned::create(dir, &keytable_tmp_name(NEW_GEN), "t").unwrap();
    rec.phase = TransitionPhase::TargetCreated;
    rec.target_kt_id = Some(kt.id());
    write_journal(dir, &seal(&rec, k)).unwrap();
    let digest =
        keytable::write_file(&sample(), &core.vault_id, NEW_GEN, &k.kt_new, &kt.file).unwrap();
    fs::flush_file(&kt.file).unwrap();
    drop(kt);
    dir.rename_noreplace(keytable_tmp_name(NEW_GEN), keytable_name(NEW_GEN))
        .unwrap();
    dir.flush().unwrap();
    if phase == TransitionPhase::TargetCreated {
        return rec;
    }
    let hdr = Owned::create(dir, HEADER_TMP, "h").unwrap();
    let (new_core, _) = new_header(core, k, digest);
    rec.phase = TransitionPhase::Committing;
    rec.new_core_digest = Some(new_core.digest().unwrap());
    rec.header_id = Some(hdr.id());
    rec.old_slots_authenticated = Some(true);
    rec.macs = Macs::Dual {
        old: [0; 64],
        new: [0; 64],
    };
    write_journal(dir, &seal(&rec, k)).unwrap();
    rec
}

/// The canonical record, authenticated with the old journal key.
fn canonical(dir: &Dir, k: &Keys) -> TransitionRecord {
    let bytes = read_capped(dir, JOURNAL, MAX_JOURNAL_LEN, || Error::JournalInvalid)
        .unwrap()
        .unwrap();
    transition(&bytes, |r| r.verify_old(&k.jk_old)).unwrap()
}

/// `tracking_core_digest` of any authenticated `rollback_tracking` record
/// on disk (canonical or a complete temp).
fn recorded_tracking_digest(path: &Path, k: &Keys) -> Option<[u8; 64]> {
    [JOURNAL, JOURNAL_TMP].iter().find_map(|n| {
        let bytes = std::fs::read(path.join(n)).ok()?;
        match Record::parse(&bytes).ok()? {
            Record::Transition(t) if Record::Transition(t.clone()).verify_old(&k.jk_old) => {
                t.tracking_core_digest
            }
            _ => None,
        }
    })
}

/// The child half of every crash test.
#[test]
#[ignore = "run by the crash tests in a child process"]
fn crash_child() {
    let Some(path) = std::env::var_os("PVAULT_CRASH_DIR") else {
        return;
    };
    let dir = Dir::open(Path::new(&path)).unwrap();
    let k = keys();
    match std::env::var("PVAULT_CRASH_SCENARIO").unwrap().as_str() {
        "tracking" => {
            start_tracking(&dir, &k.old(), canonical(&dir, &k)).unwrap();
        }
        "new-commit" => {
            let rec = canonical(&dir, &k);
            let header = read_header(&dir).unwrap().unwrap();
            let digest = file_digest(&dir, &keytable_name(NEW_GEN)).unwrap().unwrap();
            let (_, bytes) = new_header(header.core(), &k, digest);
            let mut tmp = Owned::reopen(&dir, HEADER_TMP, &rec.header_id.unwrap(), "h")
                .unwrap()
                .unwrap();
            commit_header(&dir, &mut tmp, &bytes, OLD_GEN).unwrap();
            dir.flush().unwrap();
        }
        other => panic!("unknown scenario {other}"),
    }
}

/// Runs `scenario` in a child that aborts at `failpoint`. Returns whether
/// it crashed (a failpoint on a path not taken lets the child finish).
fn run_child(path: &Path, scenario: &str, failpoint: &str) -> bool {
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "store::tests::crash_child",
            "--ignored",
            "--test-threads=1",
        ])
        .env("PVAULT_CRASH_DIR", path)
        .env("PVAULT_CRASH_SCENARIO", scenario)
        .env("PVAULT_FAILPOINT", failpoint)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    !status.success()
}

/// Restarts until done. A `Blocked` name is removed as the owner would
/// after exact confirmation (8.3), and the names removed are returned.
fn restart(path: &Path, k: &Keys) -> Vec<&'static str> {
    let dir = Dir::open(path).unwrap();
    let mut removed = Vec::new();
    for _ in 0..4 {
        let result = match resume_old_side(&dir, &k.old()) {
            Ok(Resumed::NeedsRollback(rec)) => start_tracking(&dir, &k.old(), rec).map(|_| ()),
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        };
        match result {
            Ok(()) => return removed,
            Err(Error::Blocked(label)) => {
                let name = match label {
                    "a key-table temp" => "keytable.9.pv.tmp",
                    n => n,
                };
                std::fs::remove_file(path.join(name)).unwrap();
                removed.push(label);
            }
            Err(e) => panic!("restart failed: {e:?}"),
        }
    }
    panic!("restart did not finish");
}

/// The finished tracking commit: the header is exactly the tracking core
/// (old core, generation and key-table generation `old_gen + 2`, the
/// digest of the final tracking key table, the scope-5 cleanup entry), and
/// equals `recorded` when a `rollback_tracking` record was durable.
fn verify_tracked(path: &Path, old_core: &CoreFields, k: &Keys, recorded: Option<[u8; 64]>) {
    let dir = Dir::open(path).unwrap();
    let header = read_header(&dir).unwrap().unwrap();
    assert!(header.verify_core(&k.kmac_old) && header.verify_slots(&k.kmac_old));
    assert_eq!(
        header.slots(),
        &sample_bound_slots(false),
        "the old slots are kept"
    );
    let core = header.core();
    let kt_digest = file_digest(&dir, &keytable_name(TRACK_GEN))
        .unwrap()
        .unwrap();
    let idx = target_idx(k, &old_core.vault_id);
    assert_eq!(core.tpm_cleanup.len(), 1);
    let token = core.tpm_cleanup[0].token;
    let opened = tpmid::open(
        Scope::Cleanup,
        &k.kmac_old,
        &old_core.vault_id,
        &idx.index,
        &token,
    )
    .unwrap();
    assert_eq!(opened.expose_secret(), ek_digest().expose_secret());
    let mut expected = old_core.clone();
    expected.generation = TRACK_GEN;
    expected.keytable_gen = TRACK_GEN;
    expected.keytable_digest = kt_digest;
    expected
        .add_cleanup(TpmCleanupEntry {
            index: idx.index,
            token,
        })
        .unwrap();
    assert_eq!(core, &expected);
    if let Some(d) = recorded {
        assert!(
            header.core_digest_is(&d),
            "the header is the core authenticated by tracking_core_digest"
        );
    }
    let file = dir
        .open_regular(keytable_name(TRACK_GEN), false)
        .unwrap()
        .unwrap();
    let table = keytable::read_file(
        file,
        &core.vault_id,
        TRACK_GEN,
        &kt_digest,
        &k.kt_old,
        &PROBE,
    )
    .unwrap();
    assert_eq!(
        table.encode().unwrap().expose_secret(),
        sample().encode().unwrap().expose_secret()
    );
    for gone in [
        keytable_name(OLD_GEN),
        keytable_name(NEW_GEN),
        keytable_tmp_name(NEW_GEN),
        keytable_tmp_name(TRACK_GEN),
        HEADER_TMP.into(),
        JOURNAL.into(),
        JOURNAL_TMP.into(),
    ] {
        assert!(!dir.exists(&gone).unwrap(), "{gone} remains");
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Expect {
    Done,
    /// The restart blocks on these unowned names first.
    Blocked(&'static [&'static str]),
}

/// Every crash point of the tracking path (8.2 crash table), from each
/// phase a remote rollback can start in.
#[test]
fn tracking_crash_restart_matrix() {
    use Expect::*;
    let points: &[(&str, Expect)] = &[
        (
            "journal.partial#1",
            Blocked(&[JOURNAL_TMP, "a key-table temp"]),
        ),
        ("tracking.kt-created", Blocked(&["a key-table temp"])),
        ("journal.tmp-complete#1", Done),
        ("journal.renamed#1", Done),
        ("tracking.kt-written", Done),
        ("tracking.kt-flushed", Done),
        ("tracking.kt-renamed", Done),
        ("tracking.hdr-unlinked", Done),
        ("tracking.hdr-created", Blocked(&[HEADER_TMP])),
        ("journal.partial#2", Blocked(&[JOURNAL_TMP, HEADER_TMP])),
        ("journal.tmp-complete#2", Done),
        ("journal.renamed#2", Done),
        ("header.tmp-written", Done),
        ("header.replaced", Done),
        ("tracking.cleaned", Done),
        ("journal.unlinked", Done),
    ];
    let k = keys();
    let mut with_digest = 0;
    for from in [
        TransitionPhase::Prepared,
        TransitionPhase::TargetCreated,
        TransitionPhase::Committing,
    ] {
        for (point, expect) in points {
            let tmp = tempdir();
            let old_core = setup(&tmp);
            drive(&Dir::open(&tmp).unwrap(), &old_core, &k, from);
            let crashed = run_child(&tmp, "tracking", point);
            let recorded = recorded_tracking_digest(&tmp, &k);
            with_digest += usize::from(recorded.is_some());
            let removed = restart(&tmp, &k);
            match expect {
                Done => assert!(removed.is_empty(), "{from:?} {point}: {removed:?}"),
                Blocked(names) => {
                    assert!(crashed, "{from:?} {point}");
                    assert_eq!(&removed, names, "{from:?} {point}");
                }
            }
            verify_tracked(&tmp, &old_core, &k, recorded);
            std::fs::remove_dir_all(&tmp).unwrap();
        }
    }
    // Five crash points per start phase leave a durable `rollback_tracking`
    // (canonical or a complete temp): tmp-complete#2 through cleaned.
    assert_eq!(with_digest, 3 * 5);
}

/// File identity alone is not sufficient: after `rollback_tracking` is
/// durable, a tracking key table re-encrypted in place (same file, fresh
/// nonces) has another digest, so the rebuilt core no longer matches
/// `tracking_core_digest`. The restart blocks and deletes nothing.
#[test]
fn reencrypted_tracking_keytable_is_indeterminate() {
    let k = keys();
    let tmp = tempdir();
    let old_core = setup(&tmp);
    let dir = Dir::open(&tmp).unwrap();
    drive(&dir, &old_core, &k, TransitionPhase::Committing);
    assert!(run_child(&tmp, "tracking", "header.tmp-written"));
    let recorded = recorded_tracking_digest(&tmp, &k).unwrap();
    let name = keytable_name(TRACK_GEN);
    let before = file_digest(&dir, &name).unwrap().unwrap();
    let file = dir.open_regular(&name, true).unwrap().unwrap();
    let id = dir.identity(&file).unwrap();
    file.set_len(0).unwrap();
    keytable::write_file(&sample(), &old_core.vault_id, TRACK_GEN, &k.kt_old, &file).unwrap();
    assert_eq!(dir.identity(&file).unwrap(), id, "same file");
    drop(file);
    assert_ne!(
        file_digest(&dir, &name).unwrap().unwrap(),
        before,
        "fresh nonces"
    );
    let header_before = std::fs::read(tmp.join(HEADER)).unwrap();
    assert!(matches!(
        resume_old_side(&dir, &k.old()),
        Err(Error::Indeterminate)
    ));
    assert_eq!(std::fs::read(tmp.join(HEADER)).unwrap(), header_before);
    assert!(dir.exists(JOURNAL).unwrap() && dir.exists(HEADER_TMP).unwrap());
    assert!(dir.exists(keytable_name(OLD_GEN)).unwrap());
    // The journaled digest is the exact core; the unchanged old core is not it.
    assert!(
        !Header::parse(&header_before)
            .unwrap()
            .core_digest_is(&recorded)
    );
    std::fs::remove_dir_all(&tmp).unwrap();
}

/// A tracking key table replaced by another file (another identity) while
/// `tracking_created` is canonical blocks; nothing is overwritten.
#[test]
fn replaced_tracking_keytable_blocks() {
    let k = keys();
    let tmp = tempdir();
    let old_core = setup(&tmp);
    let dir = Dir::open(&tmp).unwrap();
    drive(&dir, &old_core, &k, TransitionPhase::Committing);
    assert!(run_child(&tmp, "tracking", "tracking.kt-renamed"));
    let name = keytable_name(TRACK_GEN);
    std::fs::remove_file(tmp.join(&name)).unwrap();
    std::fs::write(tmp.join(&name), b"foreign").unwrap();
    assert!(matches!(
        resume_old_side(&dir, &k.old()),
        Err(Error::Blocked(_))
    ));
    assert_eq!(std::fs::read(tmp.join(&name)).unwrap(), b"foreign");
    std::fs::remove_dir_all(&tmp).unwrap();
}

/// The new side (8.2): after the header replacement, old material sees an
/// unauthenticated header and deletes nothing; new material finishes.
#[test]
fn new_side_restart_after_commit() {
    let k = keys();
    for point in ["header.replaced", "journal.unlinked-never-hit"] {
        let tmp = tempdir();
        let old_core = setup(&tmp);
        let dir = Dir::open(&tmp).unwrap();
        drive(&dir, &old_core, &k, TransitionPhase::Committing);
        run_child(&tmp, "new-commit", point);
        assert!(matches!(
            resume_old_side(&dir, &k.old()),
            Err(Error::Indeterminate)
        ));
        assert!(dir.exists(keytable_name(OLD_GEN)).unwrap() && dir.exists(JOURNAL).unwrap());
        let done = resume_new_side(&dir, &k.new_side()).unwrap();
        assert!(done.kept.is_empty());
        assert_eq!(done.core.generation, NEW_GEN);
        assert!(!dir.exists(keytable_name(OLD_GEN)).unwrap());
        assert!(dir.exists(keytable_name(NEW_GEN)).unwrap());
        assert!(!dir.exists(JOURNAL).unwrap() && !dir.exists(HEADER_TMP).unwrap());
        std::fs::remove_dir_all(&tmp).unwrap();
    }
}

/// A crash before the replacement leaves the old side: new material finds
/// no new header and deletes nothing; old material gets the rollback choice.
#[test]
fn crash_before_replacement_stays_old() {
    let k = keys();
    let tmp = tempdir();
    let old_core = setup(&tmp);
    let dir = Dir::open(&tmp).unwrap();
    drive(&dir, &old_core, &k, TransitionPhase::Committing);
    assert!(run_child(&tmp, "new-commit", "header.tmp-written"));
    assert!(matches!(
        resume_new_side(&dir, &k.new_side()),
        Err(Error::Indeterminate)
    ));
    assert!(matches!(
        resume_old_side(&dir, &k.old()),
        Ok(Resumed::NeedsRollback(r)) if r.phase == TransitionPhase::Committing
    ));
    assert!(
        dir.exists(keytable_name(OLD_GEN)).unwrap() && dir.exists(keytable_name(NEW_GEN)).unwrap()
    );
    std::fs::remove_dir_all(&tmp).unwrap();
}

/// The Windows WO-1 case on real files: C = `target_created`, T =
/// `committing`, and the header already new. Only the new material is
/// available; T authenticates through `mac_new` and is promoted.
#[test]
fn new_side_promotes_committing_temp() {
    let k = keys();
    let tmp = tempdir();
    let old_core = setup(&tmp);
    let dir = Dir::open(&tmp).unwrap();
    let mut rec = drive(&dir, &old_core, &k, TransitionPhase::TargetCreated);
    let hdr = Owned::create(&dir, HEADER_TMP, "h").unwrap();
    let digest = file_digest(&dir, &keytable_name(NEW_GEN)).unwrap().unwrap();
    let (new_core, bytes) = new_header(&old_core, &k, digest);
    rec.phase = TransitionPhase::Committing;
    rec.new_core_digest = Some(new_core.digest().unwrap());
    rec.header_id = Some(hdr.id());
    rec.old_slots_authenticated = Some(true);
    rec.macs = Macs::Dual {
        old: [0; 64],
        new: [0; 64],
    };
    std::fs::write(tmp.join(JOURNAL_TMP), seal(&rec, &k)).unwrap();
    drop(hdr);
    std::fs::write(tmp.join(HEADER_TMP), &bytes).unwrap();
    dir.rename_replace(HEADER_TMP, HEADER).unwrap();
    let done = resume_new_side(&dir, &k.new_side()).unwrap();
    assert_eq!(done.core, new_core);
    assert!(!dir.exists(JOURNAL).unwrap() && !dir.exists(JOURNAL_TMP).unwrap());
    assert!(!dir.exists(keytable_name(OLD_GEN)).unwrap());
    std::fs::remove_dir_all(&tmp).unwrap();
}

/// 8.5 failure boundary, in process with injected errors.
#[test]
fn failure_boundary() {
    let k = keys();
    let run = |inject: &'static str| {
        let tmp = tempdir();
        let old_core = setup(&tmp);
        let dir = Dir::open(&tmp).unwrap();
        let rec = drive(&dir, &old_core, &k, TransitionPhase::Committing);
        crate::failpoints::inject(inject);
        let result = start_tracking(&dir, &k.old(), rec);
        (tmp, old_core, dir, result)
    };

    // The replacement reports failure and did not happen: re-reading finds
    // exactly the previous header, so this is an ordinary pre-commit I/O
    // failure (not "outcome unknown"). The journal and the written header
    // temp remain, and the restart finishes the commit.
    let (tmp, old_core, dir, r) = run("header.replace");
    assert!(matches!(r, Err(Error::Io(_))), "{r:?}");
    assert!(dir.exists(JOURNAL).unwrap() && dir.exists(HEADER_TMP).unwrap());
    let recorded = recorded_tracking_digest(&tmp, &k);
    assert!(
        read_header(&dir)
            .unwrap()
            .unwrap()
            .core_digest_is(&old_core.digest().unwrap())
    );
    restart(&tmp, &k);
    verify_tracked(&tmp, &old_core, &k, recorded);
    std::fs::remove_dir_all(&tmp).unwrap();

    // The replacement happened but reported failure: re-reading the header
    // finds the exact tracking core, so the commit completes.
    let (tmp, old_core, _, r) = run("header.replace-reported-failure");
    r.unwrap();
    verify_tracked(&tmp, &old_core, &k, None);
    std::fs::remove_dir_all(&tmp).unwrap();

    // The post-replacement flush fails: durability unknown, never an
    // ordinary abort; the journal and every dependency stay.
    let (tmp, old_core, dir, r) = run("header.post-flush");
    assert!(matches!(r, Err(Error::DurabilityUnknown)));
    let recorded = recorded_tracking_digest(&tmp, &k).unwrap();
    assert!(
        read_header(&dir)
            .unwrap()
            .unwrap()
            .core_digest_is(&recorded)
    );
    assert!(dir.exists(JOURNAL).unwrap() && dir.exists(keytable_name(OLD_GEN)).unwrap());
    restart(&tmp, &k);
    verify_tracked(&tmp, &old_core, &k, Some(recorded));
    std::fs::remove_dir_all(&tmp).unwrap();

    // The journal unlink's directory flush fails: durability unknown.
    let (tmp, old_core, _, r) = run("journal.unlink-flush");
    assert!(matches!(r, Err(Error::DurabilityUnknown)));
    restart(&tmp, &k);
    verify_tracked(&tmp, &old_core, &k, None);
    std::fs::remove_dir_all(&tmp).unwrap();
}

/// F58: a header generation changed by another writer between the start
/// of the operation and the check aborts the commit; nothing is replaced.
#[test]
fn generation_check_aborts_commit() {
    let k = keys();
    let tmp = tempdir();
    let old_core = setup(&tmp);
    let dir = Dir::open(&tmp).unwrap();
    let rec = drive(&dir, &old_core, &k, TransitionPhase::Committing);
    let mut other = old_core.clone();
    other.generation = NEW_GEN;
    other.keytable_gen = NEW_GEN;
    let foreign = Header::build(&other, &sample_bound_slots(false), &k.kmac_old).unwrap();
    std::fs::write(tmp.join(HEADER), &foreign).unwrap();
    let mut hdr = Owned::reopen(&dir, HEADER_TMP, &rec.header_id.unwrap(), "h")
        .unwrap()
        .unwrap();
    let digest = file_digest(&dir, &keytable_name(NEW_GEN)).unwrap().unwrap();
    let (_, bytes) = new_header(&old_core, &k, digest);
    let e = commit_header(&dir, &mut hdr, &bytes, OLD_GEN).unwrap_err();
    assert!(matches!(e, Error::GenerationChanged), "{e:?}");
    assert_eq!(
        e.to_string(),
        "The vault changed during this operation. The header was not committed."
    );
    assert_eq!(std::fs::read(tmp.join(HEADER)).unwrap(), foreign);
    assert!(dir.exists(HEADER_TMP).unwrap() && dir.exists(JOURNAL).unwrap());
    std::fs::remove_dir_all(&tmp).unwrap();
}

/// A tracking commit needs a free `tpm_cleanup` entry before any side
/// effect (8.1 capacity rule).
#[test]
fn full_cleanup_table_refuses_before_side_effects() {
    let k = keys();
    let tmp = tempdir();
    let dir = Dir::open(&tmp).unwrap();
    let mut core = sample_core(Mode::Bound, PassphraseKind::Words);
    for i in 0..crate::header::MAX_CLEANUP as u32 {
        core.add_cleanup(crate::header::tests::cleanup(0x0180_0000 + i, false))
            .unwrap();
    }
    let f = dir.create_new(keytable_name(OLD_GEN)).unwrap();
    core.keytable_digest =
        keytable::write_file(&sample(), &core.vault_id, OLD_GEN, &k.kt_old, &f).unwrap();
    std::fs::write(
        tmp.join(HEADER),
        Header::build(&core, &sample_bound_slots(false), &k.kmac_old).unwrap(),
    )
    .unwrap();
    let rec = drive(&dir, &core, &k, TransitionPhase::Prepared);
    let journal_before = std::fs::read(tmp.join(JOURNAL)).unwrap();
    assert!(matches!(
        start_tracking(&dir, &k.old(), rec),
        Err(Error::Capacity(_))
    ));
    assert_eq!(std::fs::read(tmp.join(JOURNAL)).unwrap(), journal_before);
    assert!(!dir.exists(keytable_tmp_name(TRACK_GEN)).unwrap());
    std::fs::remove_dir_all(&tmp).unwrap();
}

/// Every permitted transition-journal promotion (8.2), on real files, with
/// old-side and new-side authentication; then duplicates and residue.
#[test]
fn journal_temp_promotion_on_disk() {
    use TransitionPhase::*;
    let (old, new) = (jt::key(1), jt::key(2));
    let old_only = JournalKeys {
        old: Some(&old),
        new: None,
    };
    let new_only = JournalKeys {
        old: None,
        new: Some(&new),
    };
    let old_hdr = AuthenticatedHeader {
        core_digest: [0x0c; 64],
        by: Bundle::Old,
    };
    let new_hdr = AuthenticatedHeader {
        core_digest: [0x4e; 64],
        by: Bundle::New,
    };
    let p = jt::prepared(Mode::Bound);
    let tc = jt::advance(p.clone(), TargetCreated);
    let cm = jt::advance(tc.clone(), Committing);
    let tr_p = jt::advance(p.clone(), TrackingCreated);
    let tr_tc = jt::advance(tc.clone(), TrackingCreated);
    let tr_cm = jt::advance(cm.clone(), TrackingCreated);
    let rt = jt::advance(tr_cm.clone(), RollbackTracking);
    let s = |r: &TransitionRecord| jt::sealed(r.clone(), &old, &new);
    let files = |c: &[u8], t: &[u8]| {
        let tmp = tempdir();
        std::fs::write(tmp.join(JOURNAL), c).unwrap();
        std::fs::write(tmp.join(JOURNAL_TMP), t).unwrap();
        tmp
    };
    let cases: [(
        &TransitionRecord,
        &TransitionRecord,
        &JournalKeys<'_>,
        &AuthenticatedHeader,
    ); 7] = [
        (&p, &tc, &old_only, &old_hdr),
        (&p, &tr_p, &old_only, &old_hdr),
        (&tc, &cm, &old_only, &old_hdr),
        (&tc, &cm, &new_only, &new_hdr),
        (&tc, &tr_tc, &old_only, &old_hdr),
        (&cm, &tr_cm, &old_only, &old_hdr),
        (&tr_cm, &rt, &old_only, &old_hdr),
    ];
    for (c, t, keys, hdr) in cases {
        let (cb, tb) = (s(c), s(t));
        let tmp = files(&cb, &tb);
        let dir = Dir::open(&tmp).unwrap();
        let loaded = load_journal(&dir, |c, t| {
            journal::promote_transition(c, t, keys, Some(hdr))
        })
        .unwrap();
        assert_eq!(
            loaded.temp,
            TempState::Promoted,
            "{:?} -> {:?}",
            c.phase,
            t.phase
        );
        assert_eq!(loaded.record.as_deref(), Some(&tb[..]));
        assert_eq!(std::fs::read(tmp.join(JOURNAL)).unwrap(), tb);
        assert!(!dir.exists(JOURNAL_TMP).unwrap());
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    // Duplicate: unlinked.
    let cb = s(&cm);
    let tmp = files(&cb, &cb);
    let dir = Dir::open(&tmp).unwrap();
    let loaded = load_journal(&dir, |c, t| {
        journal::promote_transition(c, t, &old_only, Some(&old_hdr))
    })
    .unwrap();
    assert_eq!(loaded.temp, TempState::Duplicate);
    assert!(!dir.exists(JOURNAL_TMP).unwrap());
    std::fs::remove_dir_all(&tmp).unwrap();

    // Residue: a skipped phase, a partial temp, committing -> tracking on
    // the new side. The temp is kept, C drives, and rewrites block.
    for (c, t, keys, hdr) in [
        (s(&p), s(&cm), &old_only, &old_hdr),
        (s(&tc), s(&cm)[..40].to_vec(), &old_only, &old_hdr),
        (
            s(&cm),
            s(&tr_cm),
            &JournalKeys {
                old: Some(&old),
                new: Some(&new),
            },
            &new_hdr,
        ),
    ] {
        let tmp = files(&c, &t);
        let dir = Dir::open(&tmp).unwrap();
        let loaded = load_journal(&dir, |a, b| {
            journal::promote_transition(a, b, keys, Some(hdr))
        })
        .unwrap();
        assert_eq!(loaded.temp, TempState::Residue);
        assert_eq!(loaded.record.as_deref(), Some(&c[..]));
        assert_eq!(std::fs::read(tmp.join(JOURNAL_TMP)).unwrap(), t);
        assert!(matches!(
            write_journal(&dir, &c),
            Err(Error::Blocked(JOURNAL_TMP))
        ));
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    // A temp without a canonical record has no ownership root.
    let tmp = tempdir();
    std::fs::write(tmp.join(JOURNAL_TMP), s(&p)).unwrap();
    let dir = Dir::open(&tmp).unwrap();
    let loaded = load_journal(&dir, |_, _| Promotion::Promote).unwrap();
    assert_eq!((loaded.record, loaded.temp), (None, TempState::Residue));
    assert!(dir.exists(JOURNAL_TMP).unwrap());
    std::fs::remove_dir_all(&tmp).unwrap();

    // A directory at the temp name is residue, never followed or removed.
    let tmp = files(&s(&p), b"");
    std::fs::remove_file(tmp.join(JOURNAL_TMP)).unwrap();
    std::fs::create_dir(tmp.join(JOURNAL_TMP)).unwrap();
    let dir = Dir::open(&tmp).unwrap();
    let loaded = load_journal(&dir, |_, _| Promotion::Promote).unwrap();
    assert_eq!(loaded.temp, TempState::Residue);
    std::fs::remove_dir_all(&tmp).unwrap();

    // An oversized canonical journal is refused before parsing.
    let tmp = tempdir();
    std::fs::write(tmp.join(JOURNAL), vec![0xa0; MAX_JOURNAL_LEN + 1]).unwrap();
    let dir = Dir::open(&tmp).unwrap();
    assert!(matches!(
        load_journal(&dir, |_, _| Promotion::Promote),
        Err(Error::JournalInvalid)
    ));
    std::fs::remove_dir_all(&tmp).unwrap();
}

/// Init promotions (8.3) on real files.
#[test]
fn init_journal_promotion_on_disk() {
    let k = jt::key(9);
    let mut r = InitRecord {
        phase: InitPhase::Prepared,
        vault_id: [1; 16],
        setup_id: [2; 16],
        mode: Mode::Portable,
        salt: [3; 32],
        argon2: crate::crypto::kdf::Argon2Params::DEFAULT,
        passphrase_kind: PassphraseKind::Words,
        idx: None,
        keytable_id: None,
        keytable_digest: None,
        new_core_digest: None,
        header_id: None,
        mac: [0; 64],
    };
    let seal = |r: &InitRecord| {
        let mut rec = Record::Init(r.clone());
        rec.seal(&k, None).unwrap();
        rec.encode()
    };
    let mut seq = vec![seal(&r)];
    r.phase = InitPhase::KeytableCreated;
    r.keytable_id = Some(FileIdentity::Unix([5; 20]));
    seq.push(seal(&r));
    r.phase = InitPhase::KeytableWritten;
    r.keytable_digest = Some([6; 64]);
    r.new_core_digest = Some([7; 64]);
    seq.push(seal(&r));
    r.phase = InitPhase::Committing;
    r.header_id = Some(FileIdentity::Unix([8; 20]));
    seq.push(seal(&r));
    for w in seq.windows(2) {
        let tmp = tempdir();
        std::fs::write(tmp.join(JOURNAL), &w[0]).unwrap();
        std::fs::write(tmp.join(JOURNAL_TMP), &w[1]).unwrap();
        let dir = Dir::open(&tmp).unwrap();
        let loaded = load_journal(&dir, |c, t| journal::promote_init(c, t, &k)).unwrap();
        assert_eq!(loaded.temp, TempState::Promoted);
        assert_eq!(std::fs::read(tmp.join(JOURNAL)).unwrap(), w[1]);
        std::fs::remove_dir_all(&tmp).unwrap();
    }
    let tmp = tempdir();
    std::fs::write(tmp.join(JOURNAL), &seq[0]).unwrap();
    std::fs::write(tmp.join(JOURNAL_TMP), &seq[2]).unwrap();
    let dir = Dir::open(&tmp).unwrap();
    let loaded = load_journal(&dir, |c, t| journal::promote_init(c, t, &k)).unwrap();
    assert_eq!(loaded.temp, TempState::Residue, "skipped phase");
    std::fs::remove_dir_all(&tmp).unwrap();
}

/// Owned artifacts: exclusive creation, resume in place keeps the identity,
/// a replaced file is not owned.
#[test]
fn owned_artifacts() {
    let tmp = tempdir();
    let dir = Dir::open(&tmp).unwrap();
    let mut a = Owned::create(&dir, "a.tmp", "a").unwrap();
    assert!(matches!(
        Owned::create(&dir, "a.tmp", "a"),
        Err(Error::Blocked("a"))
    ));
    a.rewrite(b"first, longer").unwrap();
    let id = a.id();
    drop(a);
    let mut again = Owned::reopen(&dir, "a.tmp", &id, "a").unwrap().unwrap();
    again.rewrite(b"second").unwrap();
    assert_eq!(again.id(), id);
    drop(again);
    assert_eq!(std::fs::read(tmp.join("a.tmp")).unwrap(), b"second");
    std::fs::remove_file(tmp.join("a.tmp")).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    std::fs::write(tmp.join("a.tmp"), b"other").unwrap();
    assert!(matches!(
        Owned::reopen(&dir, "a.tmp", &id, "a"),
        Err(Error::Blocked("a"))
    ));
    assert!(Owned::reopen(&dir, "b.tmp", &id, "b").unwrap().is_none());
    std::fs::remove_dir_all(&tmp).unwrap();
}

/// The three outcomes of a re-read after a failed replacement (8.5): only
/// "neither header" (or an unreadable one) is "outcome unknown".
#[test]
fn failed_replacement_classification() {
    let (before, new) = (b"old header".as_slice(), b"new header".as_slice());
    assert_eq!(after_failed_replace(Some(new), before, new), Replaced::Yes);
    assert_eq!(
        after_failed_replace(Some(before), before, new),
        Replaced::No
    );
    assert_eq!(
        after_failed_replace(Some(b"other"), before, new),
        Replaced::Unknown
    );
    assert_eq!(after_failed_replace(None, before, new), Replaced::Unknown);
    assert_eq!(
        Error::OutcomeUnknown.to_string(),
        "The header replacement outcome could not be determined. Run fsck before making further changes."
    );
}

/// `rollback_tracking` durable, header still old, and the tracking header
/// temp missing: the restart is indeterminate, keeps the journal, and
/// performs no cleanup (decided 2026-10-05).
#[test]
fn missing_tracking_header_temp_blocks_without_cleanup() {
    let k = keys();
    let tmp = tempdir();
    let old_core = setup(&tmp);
    let dir = Dir::open(&tmp).unwrap();
    drive(&dir, &old_core, &k, TransitionPhase::Committing);
    assert!(run_child(&tmp, "tracking", "header.tmp-written"));
    assert!(recorded_tracking_digest(&tmp, &k).is_some());
    std::fs::remove_file(tmp.join(HEADER_TMP)).unwrap();
    let names = |p: &Path| {
        let mut v: Vec<String> = std::fs::read_dir(p)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    };
    let before = names(&tmp);
    let header_before = std::fs::read(tmp.join(HEADER)).unwrap();
    let journal_before = std::fs::read(tmp.join(JOURNAL)).unwrap();
    for _ in 0..2 {
        let e = resume_old_side(&dir, &k.old()).unwrap_err();
        assert!(matches!(e, Error::Indeterminate), "{e:?}");
        assert_eq!(
            e.to_string(),
            "The vault state could not be determined safely. No cleanup was performed. Run fsck."
        );
    }
    assert_eq!(names(&tmp), before, "no file was created or removed");
    assert!(before.contains(&keytable_name(OLD_GEN)) && before.contains(&keytable_name(NEW_GEN)));
    assert!(before.contains(&keytable_name(TRACK_GEN)));
    assert_eq!(std::fs::read(tmp.join(HEADER)).unwrap(), header_before);
    assert_eq!(std::fs::read(tmp.join(JOURNAL)).unwrap(), journal_before);
    std::fs::remove_dir_all(&tmp).unwrap();
}

/// "No cleanup was performed" holds for an old-side restart whose header
/// does not authenticate: a byte-identical journal temp (an authenticated
/// duplicate) is not unlinked, and nothing else changes.
#[test]
fn indeterminate_restart_touches_nothing() {
    let k = keys();
    let tmp = tempdir();
    let old_core = setup(&tmp);
    let dir = Dir::open(&tmp).unwrap();
    drive(&dir, &old_core, &k, TransitionPhase::Committing);
    std::fs::copy(tmp.join(JOURNAL), tmp.join(JOURNAL_TMP)).unwrap();
    let mut foreign = old_core.clone();
    foreign.created_at += 1;
    let other = Header::build(&foreign, &sample_bound_slots(false), &k.kmac_new).unwrap();
    std::fs::write(tmp.join(HEADER), &other).unwrap();
    let e = resume_old_side(&dir, &k.old()).unwrap_err();
    assert!(matches!(e, Error::Indeterminate), "{e:?}");
    assert_eq!(
        e.to_string(),
        "The vault state could not be determined safely. No cleanup was performed. Run fsck."
    );
    assert!(
        dir.exists(JOURNAL_TMP).unwrap(),
        "the duplicate temp was kept"
    );
    // The same with a header authenticated under the old bundle but matching
    // no journaled core.
    let other = Header::build(&foreign, &sample_bound_slots(false), &k.kmac_old).unwrap();
    std::fs::write(tmp.join(HEADER), &other).unwrap();
    assert!(matches!(
        resume_old_side(&dir, &k.old()),
        Err(Error::Indeterminate)
    ));
    assert!(dir.exists(JOURNAL_TMP).unwrap());
    for name in [
        keytable_name(OLD_GEN),
        keytable_name(NEW_GEN),
        HEADER_TMP.into(),
    ] {
        assert!(dir.exists(&name).unwrap(), "{name}");
    }
    std::fs::remove_dir_all(&tmp).unwrap();
}
