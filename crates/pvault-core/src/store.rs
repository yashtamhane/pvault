//! The vault directory on disk (spec 8.1 to 8.3, 8.5; D6).
//!
//! - **Owned artifacts:** created empty and exclusively without following
//!   symlinks, identity captured from the open handle, identity journaled,
//!   only then written ([`Owned`]).
//! - **Journal writes:** `vault.journal.tmp`, flush, replace, directory
//!   flush; at restart a temp is promoted, unlinked as a duplicate, or left
//!   as residue by the 8.2/8.3 rules ([`load_journal`]).
//! - **Header commit:** the generation check (F58), the replacement and the
//!   8.5 failure boundary ([`commit_header`]).
//! - **Remote-rollback tracking commit and restart** (8.1, 8.2):
//!   [`start_tracking`] and [`resume_old_side`], plus the new-side restart
//!   [`resume_new_side`]. The decision to roll back remotely (the target
//!   index may exist only on another TPM) belongs to recovery (Milestone 6);
//!   this module executes it.
//!
//! Every function expects the caller to hold the exclusive vault lock and a
//! directory that passed [`preflight`](crate::platform::fs::preflight).

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};

use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;

use crate::crypto::cascade::StreamKeys;
use crate::errors::Error;
use crate::header::{CoreFields, Header, MAX_HEADER_LEN};
use crate::journal::{
    self, AuthenticatedHeader, Bundle, FileIdentity, JournalKeys, MAX_JOURNAL_LEN, Macs, Promotion,
    Record, Side, TransitionPhase, TransitionRecord,
};
use crate::keytable::{self, KeyTable};
use crate::platform::fs::{self, Dir, Ownership};
use crate::resources::MemoryProbe;
use crate::secrets::SecretBytes;
use crate::tpmid::{self, Scope};

/// The header.
pub const HEADER: &str = "vault.hdr";
/// The header temp.
pub const HEADER_TMP: &str = "vault.hdr.tmp";
/// The journal.
pub const JOURNAL: &str = "vault.journal";
/// The journal temp.
pub const JOURNAL_TMP: &str = "vault.journal.tmp";

/// `keytable.<generation>.pv`.
pub fn keytable_name(generation: u64) -> String {
    format!("keytable.{generation}.pv")
}

/// `keytable.<generation>.pv.tmp`.
pub fn keytable_tmp_name(generation: u64) -> String {
    format!("keytable.{generation}.pv.tmp")
}

fn io(e: io::Error) -> Error {
    Error::Io(e)
}

/// Reads a regular file of at most `max` bytes. `Ok(None)` if absent;
/// `Err(over)` if larger or not a regular file.
pub(crate) fn read_capped(
    dir: &Dir,
    name: &str,
    max: usize,
    over: fn() -> Error,
) -> Result<Option<Vec<u8>>, Error> {
    let file = match dir.open_regular(name, false) {
        Ok(Some(f)) => f,
        Ok(None) => return Ok(None),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => return Err(over()),
        Err(e) => return Err(io(e)),
    };
    read_handle(&file, max)
        .map_err(io)?
        .ok_or_else(over)
        .map(Some)
}

fn read_handle(file: &File, max: usize) -> io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut buf)?;
    Ok((buf.len() <= max).then_some(buf))
}

/// The SHA-512 of a regular file, or `None` if absent.
pub(crate) fn file_digest(dir: &Dir, name: &str) -> Result<Option<[u8; 64]>, Error> {
    let Some(file) = dir.open_regular(name, false).map_err(io)? else {
        return Ok(None);
    };
    hash_handle(&file).map(Some)
}

pub(crate) fn hash_handle(mut file: &File) -> Result<[u8; 64], Error> {
    let mut hash = Sha512::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).map_err(io)?;
        if n == 0 {
            return Ok(hash.finalize().into());
        }
        hash.update(&buf[..n]);
    }
}

fn eq64(a: &[u8; 64], b: &[u8; 64]) -> bool {
    bool::from(a.ct_eq(b))
}

/// An artifact whose identity this process captured (spec 8.1).
#[derive(Debug)]
pub struct Owned {
    file: File,
    id: FileIdentity,
}

impl Owned {
    /// Creates `name` empty and exclusively and captures its identity
    /// (refusal rule 2: a failed identity query stops before any byte).
    /// Anything already at `name` blocks.
    pub fn create(dir: &Dir, name: &str, label: &'static str) -> Result<Self, Error> {
        let file = dir.create_new(name).map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                Error::Blocked(label)
            } else {
                io(e)
            }
        })?;
        let id = dir
            .identity(&file)
            .map_err(|_| Error::Unsupported("file identity for a new artifact"))?;
        Ok(Self { file, id })
    }

    /// Reopens the artifact with identity `id` at `name`. `Ok(None)` if
    /// absent; anything else at the name blocks.
    pub fn reopen(
        dir: &Dir,
        name: &str,
        id: &FileIdentity,
        label: &'static str,
    ) -> Result<Option<Self>, Error> {
        match fs::open_owned(dir, name, id, true).map_err(io)? {
            Ok(Some(file)) => Ok(Some(Self { file, id: *id })),
            Ok(None) => Ok(None),
            Err(_) => Err(Error::Blocked(label)),
        }
    }

    /// The captured identity.
    pub fn id(&self) -> FileIdentity {
        self.id
    }

    /// The open file.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Truncates and rewrites the file, then flushes it (resume in place).
    pub fn rewrite(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.truncate()?;
        self.file.write_all(bytes)?;
        fs::flush_file(&self.file)
    }

    pub(crate) fn truncate(&mut self) -> io::Result<()> {
        self.file.set_len(0)?;
        self.file.seek(SeekFrom::Start(0)).map(|_| ())
    }
}

/// Writes the journal: temp, flush, replace, directory flush (8.1, 8.5).
/// An existing temp is residue and blocks the rewrite.
pub fn write_journal(dir: &Dir, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > MAX_JOURNAL_LEN {
        return Err(Error::JournalInvalid);
    }
    let mut tmp = Owned::create(dir, JOURNAL_TMP, JOURNAL_TMP)?;
    let result = (|| -> io::Result<()> {
        let half = bytes.len() / 2;
        tmp.file.write_all(&bytes[..half])?;
        failpoint!("journal.partial");
        tmp.file.write_all(&bytes[half..])?;
        fs::flush_file(&tmp.file)?;
        failpoint!("journal.tmp-complete");
        dir.rename_replace(JOURNAL_TMP, JOURNAL)
    })();
    if let Err(e) = result {
        // Our own temp: remove it by identity so it does not block the retry.
        let id = tmp.id;
        drop(tmp);
        let _ = fs::remove_if_owned(dir, JOURNAL_TMP, &id);
        return Err(io(e));
    }
    failpoint!("journal.renamed");
    dir.flush().map_err(io)
}

/// Removes the journal durably. A failed directory flush is "durability
/// unknown": a restart may still see the journal (8.5).
pub fn remove_journal(dir: &Dir) -> Result<(), Error> {
    dir.unlink(JOURNAL).map_err(io)?;
    failpoint!("journal.unlinked");
    fail_io!("journal.unlink-flush")
        .and_then(|()| dir.flush())
        .map_err(|_| Error::DurabilityUnknown)
}

/// What [`load_journal`] did with `vault.journal.tmp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TempState {
    /// No temp.
    None,
    /// The temp replaced the canonical record.
    Promoted,
    /// The temp was an authenticated duplicate and was unlinked.
    Duplicate,
    /// Unowned residue: kept, and every journal rewrite blocks on it.
    Residue,
}

/// The canonical journal after temp handling.
#[derive(Debug)]
pub struct LoadedJournal {
    /// The canonical record bytes, if any (unauthenticated until verified).
    pub record: Option<Vec<u8>>,
    /// What happened to the temp.
    pub temp: TempState,
}

/// Loads `vault.journal` and resolves `vault.journal.tmp` with `decide`
/// ([`journal::promote_transition`] or [`journal::promote_init`]). A temp
/// without a canonical record has no ownership root and is residue.
pub fn load_journal(
    dir: &Dir,
    decide: impl FnOnce(&[u8], &[u8]) -> Promotion,
) -> Result<LoadedJournal, Error> {
    let canonical = read_capped(dir, JOURNAL, MAX_JOURNAL_LEN, || Error::JournalInvalid)?;
    let temp = match dir.open_regular(JOURNAL_TMP, false) {
        Ok(None) => None,
        Ok(Some(f)) => {
            let id = dir.identity(&f).ok();
            Some((read_handle(&f, MAX_JOURNAL_LEN).map_err(io)?, id))
        }
        // A non-regular entry at the temp name is residue too.
        Err(e) if e.kind() == io::ErrorKind::InvalidData => Some((None, None)),
        Err(e) => return Err(io(e)),
    };
    let Some((temp, temp_id)) = temp else {
        return Ok(LoadedJournal {
            record: canonical,
            temp: TempState::None,
        });
    };
    let residue = |record| LoadedJournal {
        record,
        temp: TempState::Residue,
    };
    let (Some(c), Some(t), Some(t_id)) = (canonical.as_ref(), temp.as_ref(), temp_id) else {
        return Ok(residue(canonical));
    };
    match decide(c, t) {
        Promotion::Residue => Ok(residue(canonical)),
        Promotion::Duplicate => {
            match fs::remove_if_owned(dir, JOURNAL_TMP, &t_id).map_err(io)? {
                Ownership::Removed => dir.flush().map_err(io)?,
                Ownership::Absent => {}
                Ownership::NotOwned => return Ok(residue(canonical)),
            }
            Ok(LoadedJournal {
                record: canonical,
                temp: TempState::Duplicate,
            })
        }
        Promotion::Promote => {
            // The name must still hold the file that was read.
            if !matches!(
                fs::open_owned(dir, JOURNAL_TMP, &t_id, false).map_err(io)?,
                Ok(Some(_))
            ) {
                return Ok(residue(canonical));
            }
            dir.rename_replace(JOURNAL_TMP, JOURNAL).map_err(io)?;
            failpoint!("journal.promoted");
            dir.flush().map_err(io)?;
            Ok(LoadedJournal {
                record: temp,
                temp: TempState::Promoted,
            })
        }
    }
}

/// Reads and parses `vault.hdr` (unauthenticated). `Ok(None)` if absent.
pub fn read_header(dir: &Dir) -> Result<Option<Header>, Error> {
    read_capped(dir, HEADER, MAX_HEADER_LEN, || Error::HeaderInvalid)?
        .map(|b| Header::parse(&b))
        .transpose()
}

/// Commits a header through the owned temp `tmp` (8.4, 8.5):
/// 1. write and flush the temp;
/// 2. the generation check (F58): re-read `vault.hdr` and abort with
///    [`Error::GenerationChanged`] if its generation is not
///    `expected_generation`; nothing is replaced;
/// 3. replace. If the call reports failure, re-read `vault.hdr`: exactly the
///    new bytes means the replacement happened and the commit continues;
///    exactly the previous bytes means it did not, and the I/O error is
///    returned as a pre-commit failure; anything else (including an
///    unreadable header) is [`Error::OutcomeUnknown`];
/// 4. flush the directory; a failure is [`Error::DurabilityUnknown`].
///
/// Errors from steps 1 and 2, and a verified non-replacement, are ordinary
/// pre-commit failures: the old header stands, and the journal and the
/// temp (already written) remain for the restart.
pub fn commit_header(
    dir: &Dir,
    tmp: &mut Owned,
    bytes: &[u8],
    expected_generation: u64,
) -> Result<(), Error> {
    tmp.rewrite(bytes).map_err(io)?;
    failpoint!("header.tmp-written");
    let current = read_header(dir)?.ok_or(Error::GenerationChanged)?;
    if current.core().generation != expected_generation {
        return Err(Error::GenerationChanged);
    }
    if let Err(e) = replace_header(dir) {
        let now = read_capped(dir, HEADER, MAX_HEADER_LEN, || Error::HeaderInvalid)
            .ok()
            .flatten();
        match after_failed_replace(now.as_deref(), current.raw(), bytes) {
            Replaced::Yes => {}
            Replaced::No => return Err(io(e)),
            Replaced::Unknown => return Err(Error::OutcomeUnknown),
        }
    }
    failpoint!("header.replaced");
    fail_io!("header.post-flush")
        .and_then(|()| dir.flush())
        .map_err(|_| Error::DurabilityUnknown)
}

/// What a re-read after a failed replacement shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Replaced {
    Yes,
    No,
    Unknown,
}

/// Classifies `vault.hdr` after a replacement reported failure, by exact
/// bytes: the new header (built and MACed by this process), the previous one
/// (read and checked just before), or neither.
fn after_failed_replace(now: Option<&[u8]>, before: &[u8], new: &[u8]) -> Replaced {
    match now {
        Some(b) if b == new => Replaced::Yes,
        Some(b) if b == before => Replaced::No,
        _ => Replaced::Unknown,
    }
}

fn replace_header(dir: &Dir) -> io::Result<()> {
    fail_io!("header.replace")?;
    dir.rename_replace(HEADER_TMP, HEADER)?;
    fail_io!("header.replace-reported-failure")
}

/// Old-side material for a transition restart: the old bundle's `K_mac`,
/// its `journal_key` and its key-table stream keys.
pub struct OldSide<'a> {
    /// `K_mac` of the old bundle.
    pub k_mac: &'a SecretBytes<32>,
    /// `journal_key(old_bundle)`.
    pub journal_key: &'a SecretBytes<32>,
    /// Stream keys of the old bundle's key table.
    pub keytable_keys: &'a StreamKeys,
    /// Memory probe for reading the key table.
    pub probe: &'a dyn MemoryProbe,
}

impl core::fmt::Debug for OldSide<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OldSide([REDACTED])")
    }
}

/// New-side material: the new bundle's `K_mac` and `journal_key`.
pub struct NewSide<'a> {
    /// `K_mac` of the new bundle.
    pub k_mac: &'a SecretBytes<32>,
    /// `journal_key(new_bundle)`.
    pub journal_key: &'a SecretBytes<32>,
}

impl core::fmt::Debug for NewSide<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NewSide([REDACTED])")
    }
}

/// Where an old-side restart ended.
// One short-lived value per restart; boxing would add an allocation for nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Resumed {
    /// No journal.
    Clean,
    /// `prepared`, `target_created` or `committing` on the old side: the
    /// caller decides between local and remote rollback (Milestones 5, 6).
    NeedsRollback(TransitionRecord),
    /// The tracking commit finished; the header is the tracking core.
    Tracked(Finished),
}

/// A finished commit and what cleanup could not remove.
#[derive(Debug)]
pub struct Finished {
    /// The committed core.
    pub core: CoreFields,
    /// Names left in place because their identity or digest did not match.
    pub kept: Vec<String>,
}

/// The authenticated old header: both MACs verify under the old `K_mac`
/// (8.1: the tracking rewrite needs the old `slots_mac`).
fn old_header(dir: &Dir, old: &OldSide<'_>) -> Result<Option<Header>, Error> {
    Ok(read_header(dir)?.filter(|h| h.verify_core(old.k_mac) && h.verify_slots(old.k_mac)))
}

fn transition(bytes: &[u8], verify: impl Fn(&Record) -> bool) -> Result<TransitionRecord, Error> {
    match Record::parse(bytes)? {
        Record::Transition(t) if verify(&Record::Transition(t.clone())) => Ok(t),
        _ => Err(Error::JournalInvalid),
    }
}

fn sealed(
    rec: TransitionRecord,
    key: &SecretBytes<32>,
) -> Result<(TransitionRecord, Vec<u8>), Error> {
    let mut r = Record::Transition(rec);
    r.seal(key, None)?;
    let bytes = r.encode();
    match r {
        Record::Transition(t) => Ok((t, bytes)),
        Record::Init(_) | Record::Update(_) => Err(Error::JournalInvalid),
    }
}

/// Restart with old material (8.2 transition restart table, old-side rows).
/// Journal temps are resolved first, then the header is classified by exact
/// core digest.
pub fn resume_old_side(dir: &Dir, old: &OldSide<'_>) -> Result<Resumed, Error> {
    let header = old_header(dir, old)?;
    let auth = header.as_ref().map(|h| AuthenticatedHeader {
        core_digest: h.core_digest(),
        by: Bundle::Old,
    });
    let keys = JournalKeys {
        old: Some(old.journal_key),
        new: None,
    };
    // Without an authenticated header no journal temp is promoted or
    // unlinked: every temp is left as residue.
    let loaded = match &auth {
        Some(a) => load_journal(dir, |c, t| {
            journal::promote_transition(c, t, &keys, Some(a))
        })?,
        None => load_journal(dir, |_, _| Promotion::Residue)?,
    };
    let Some(bytes) = loaded.record else {
        return Ok(Resumed::Clean);
    };
    let rec = transition(&bytes, |r| r.verify_old(old.journal_key))?;
    let (Some(header), Some(auth)) = (header, auth) else {
        return Err(Error::Indeterminate);
    };
    match (journal::classify(&rec, &auth), rec.phase) {
        (Side::Old, TransitionPhase::TrackingCreated) => {
            continue_tracking_created(dir, old, rec, &header).map(Resumed::Tracked)
        }
        (Side::Old, TransitionPhase::RollbackTracking) => {
            continue_rollback_tracking(dir, old, &rec, &header, None).map(Resumed::Tracked)
        }
        (Side::Tracking, _) => {
            finish_tracking(dir, &rec, header.core().clone()).map(Resumed::Tracked)
        }
        (Side::Old, _) => Ok(Resumed::NeedsRollback(rec)),
        _ => Err(Error::Indeterminate),
    }
}

/// Restart with new material after a `committing` record whose header is
/// the exact new core (8.2, last-but-one row): repeat the post-replacement
/// flush, delete the old key table only on a digest match, remove the
/// journal.
pub fn resume_new_side(dir: &Dir, new: &NewSide<'_>) -> Result<Finished, Error> {
    let header = read_header(dir)?
        .filter(|h| h.verify_core(new.k_mac) && h.verify_slots(new.k_mac))
        .ok_or(Error::Indeterminate)?;
    let auth = AuthenticatedHeader {
        core_digest: header.core_digest(),
        by: Bundle::New,
    };
    let keys = JournalKeys {
        old: None,
        new: Some(new.journal_key),
    };
    let loaded = load_journal(dir, |c, t| {
        journal::promote_transition(c, t, &keys, Some(&auth))
    })?;
    let bytes = loaded.record.ok_or(Error::Indeterminate)?;
    let rec = transition(&bytes, |r| r.verify_new(new.journal_key))?;
    if journal::classify(&rec, &auth) != Side::New {
        return Err(Error::Indeterminate);
    }
    dir.flush().map_err(|_| Error::DurabilityUnknown)?;
    let mut kept = Vec::new();
    remove_old_keytable(dir, &rec, &mut kept)?;
    if let Some(id) = &rec.header_id {
        remove_owned(dir, HEADER_TMP, id, &mut kept)?;
    }
    dir.flush().map_err(|_| Error::DurabilityUnknown)?;
    remove_journal(dir)?;
    Ok(Finished {
        core: header.core().clone(),
        kept,
    })
}

/// Starts the remote-rollback tracking commit (8.1, 8.2) from an
/// authenticated `prepared`, `target_created` or `committing` record whose
/// header is the exact old core with authenticated old slots.
pub fn start_tracking(
    dir: &Dir,
    old: &OldSide<'_>,
    rec: TransitionRecord,
) -> Result<Finished, Error> {
    if !matches!(
        rec.phase,
        TransitionPhase::Prepared | TransitionPhase::TargetCreated | TransitionPhase::Committing
    ) {
        return Err(Error::JournalInvalid);
    }
    let idx = rec.idx.ok_or(Error::Unsupported(
        "rollback tracking needs a bound target index",
    ))?;
    let header = old_header(dir, old)?.ok_or(Error::Indeterminate)?;
    if !header.core_digest_is(&rec.old_core_digest) {
        return Err(Error::Indeterminate);
    }
    let tracking_gen = rec
        .old_gen
        .checked_add(2)
        .ok_or(Error::Unsupported("generation overflow"))?;
    let cleanup_token = tpmid::rewrap(
        (Scope::NewIndexOldSide, old.journal_key),
        (Scope::Cleanup, old.k_mac),
        &rec.vault_id,
        &idx.index,
        &idx.token,
    )?;
    // Reserve the cleanup entry before any side effect (8.1 capacity rule).
    let mut probe_core = header.core().clone();
    probe_core.add_cleanup(crate::header::TpmCleanupEntry {
        index: idx.index,
        token: cleanup_token,
    })?;
    no_journal_residue(dir)?;
    if dir.exists(keytable_name(tracking_gen)).map_err(io)? {
        return Err(Error::Blocked(
            "a key-table file at the tracking generation",
        ));
    }
    let kt = Owned::create(dir, &keytable_tmp_name(tracking_gen), "a key-table temp")?;
    failpoint!("tracking.kt-created");
    let next = TransitionRecord {
        phase: TransitionPhase::TrackingCreated,
        new_core_digest: None,
        old_slots_authenticated: None,
        tracking_gen: Some(tracking_gen),
        cleanup_token: Some(cleanup_token),
        track_kt_id: Some(kt.id()),
        macs: Macs::Single([0; 64]),
        ..rec
    };
    let (next, bytes) = sealed(next, old.journal_key)?;
    write_journal(dir, &bytes)?;
    drop(kt);
    continue_tracking_created(dir, old, next, &header)
}

/// `tracking_created` on the old side: resume the tracking key table in
/// place, resolve the committing header temp, create the tracking header
/// temp and make `rollback_tracking` durable.
fn continue_tracking_created(
    dir: &Dir,
    old: &OldSide<'_>,
    rec: TransitionRecord,
    header: &Header,
) -> Result<Finished, Error> {
    let (Some(tracking_gen), Some(kt_id)) = (rec.tracking_gen, rec.track_kt_id) else {
        return Err(Error::JournalInvalid);
    };
    no_journal_residue(dir)?;
    let old_core = header.core();
    let table = read_keytable(dir, old, old_core)?;

    // Resume in place: the file is referenced by no header yet.
    let (tmp_name, final_name) = (keytable_tmp_name(tracking_gen), keytable_name(tracking_gen));
    let (mut kt, at_tmp) = match Owned::reopen(dir, &tmp_name, &kt_id, "a key-table temp")? {
        Some(f) => (f, true),
        None => (
            Owned::reopen(dir, &final_name, &kt_id, "a key-table file")?
                .ok_or(Error::Blocked("the tracking key table is missing"))?,
            false,
        ),
    };
    kt.truncate().map_err(io)?;
    let digest = keytable::write_file(
        &table,
        &old_core.vault_id,
        tracking_gen,
        old.keytable_keys,
        &kt.file,
    )?;
    failpoint!("tracking.kt-written");
    fs::flush_file(&kt.file).map_err(io)?;
    drop(kt);
    if at_tmp {
        failpoint!("tracking.kt-flushed");
        dir.rename_noreplace(&tmp_name, &final_name).map_err(io)?;
        failpoint!("tracking.kt-renamed");
    }
    dir.flush().map_err(io)?;

    // 8.1 steps 1 to 3: resolve an existing vault.hdr.tmp.
    match &rec.header_id {
        Some(id) => match fs::remove_if_owned(dir, HEADER_TMP, id).map_err(io)? {
            Ownership::Removed | Ownership::Absent => {
                failpoint!("tracking.hdr-unlinked");
                dir.flush().map_err(io)?;
            }
            Ownership::NotOwned => return Err(Error::Blocked(HEADER_TMP)),
        },
        None => {
            if dir.exists(HEADER_TMP).map_err(io)? {
                return Err(Error::Blocked(HEADER_TMP));
            }
        }
    }

    let core = journal::tracking_core(old_core, &rec, &digest)?;
    let hdr = Owned::create(dir, HEADER_TMP, HEADER_TMP)?;
    failpoint!("tracking.hdr-created");
    let next = TransitionRecord {
        phase: TransitionPhase::RollbackTracking,
        tracking_core_digest: Some(core.digest()?),
        track_hdr_id: Some(hdr.id()),
        ..rec
    };
    let (next, bytes) = sealed(next, old.journal_key)?;
    write_journal(dir, &bytes)?;
    continue_rollback_tracking(dir, old, &next, header, Some(hdr))
}

/// `rollback_tracking` on the old side: rebuild the tracking core from the
/// authenticated old core, `tracking_gen`, the SHA-512 of
/// `keytable.<tracking_gen>.pv` and the journaled cleanup entry; it must
/// hash to `tracking_core_digest`. Then write the header and commit.
fn continue_rollback_tracking(
    dir: &Dir,
    old: &OldSide<'_>,
    rec: &TransitionRecord,
    header: &Header,
    hdr: Option<Owned>,
) -> Result<Finished, Error> {
    let (Some(tracking_gen), Some(hdr_id)) = (rec.tracking_gen, rec.track_hdr_id) else {
        return Err(Error::JournalInvalid);
    };
    // The key table is final; it is hashed, never rewritten, in this phase.
    let digest = file_digest(dir, &keytable_name(tracking_gen))?.ok_or(Error::Indeterminate)?;
    let core =
        journal::tracking_core(header.core(), rec, &digest).map_err(|_| Error::Indeterminate)?;
    let bytes = Header::build(&core, header.slots(), old.k_mac)?;
    let mut hdr = match hdr {
        Some(h) => h,
        // Absent while the header is still old: the authenticated phase
        // cannot journal a replacement identity. Treat this as indeterminate,
        // keep the journal, and touch nothing (decided 2026-10-05; M3-F4).
        None => Owned::reopen(dir, HEADER_TMP, &hdr_id, HEADER_TMP)?.ok_or(Error::Indeterminate)?,
    };
    commit_header(dir, &mut hdr, &bytes, rec.old_gen)?;
    drop(hdr);
    finish_tracking(dir, rec, core)
}

/// The header is the exact tracking core: repeat the post-replacement flush,
/// remove identity-owned temps and target artifacts and the old key table
/// by digest, then remove the journal.
fn finish_tracking(dir: &Dir, rec: &TransitionRecord, core: CoreFields) -> Result<Finished, Error> {
    dir.flush().map_err(|_| Error::DurabilityUnknown)?;
    let mut kept = Vec::new();
    if let Some(id) = &rec.target_kt_id {
        remove_owned(dir, &keytable_tmp_name(rec.new_gen), id, &mut kept)?;
        remove_owned(dir, &keytable_name(rec.new_gen), id, &mut kept)?;
    }
    if let Some(id) = &rec.header_id {
        remove_owned(dir, HEADER_TMP, id, &mut kept)?;
    }
    remove_old_keytable(dir, rec, &mut kept)?;
    failpoint!("tracking.cleaned");
    dir.flush().map_err(|_| Error::DurabilityUnknown)?;
    remove_journal(dir)?;
    Ok(Finished { core, kept })
}

/// A journal temp blocks every journal rewrite, so it is checked before an
/// operation creates any artifact it would then have to journal.
fn no_journal_residue(dir: &Dir) -> Result<(), Error> {
    if dir.exists(JOURNAL_TMP).map_err(io)? {
        return Err(Error::Blocked(JOURNAL_TMP));
    }
    Ok(())
}

fn remove_owned(
    dir: &Dir,
    name: &str,
    id: &FileIdentity,
    kept: &mut Vec<String>,
) -> Result<(), Error> {
    if fs::remove_if_owned(dir, name, id).map_err(io)? == Ownership::NotOwned {
        kept.push(name.to_owned());
    }
    Ok(())
}

/// Deletes `keytable.<old_gen>.pv` only if its SHA-512 is
/// `old_keytable_digest` (6.5 o).
fn remove_old_keytable(
    dir: &Dir,
    rec: &TransitionRecord,
    kept: &mut Vec<String>,
) -> Result<(), Error> {
    let name = keytable_name(rec.old_gen);
    let Some(file) = dir.open_regular(&name, false).map_err(io).ok().flatten() else {
        if dir.exists(&name).map_err(io)? {
            kept.push(name);
        }
        return Ok(());
    };
    let id = dir.identity(&file).map_err(io)?;
    let digest = hash_handle(&file)?;
    drop(file);
    if eq64(&digest, &rec.old_keytable_digest) {
        remove_owned(dir, &name, &id, kept)
    } else {
        kept.push(name);
        Ok(())
    }
}

fn read_keytable(dir: &Dir, old: &OldSide<'_>, core: &CoreFields) -> Result<KeyTable, Error> {
    let file = dir
        .open_regular(keytable_name(core.keytable_gen), false)
        .map_err(|_| Error::KeyTableCorrupt)?
        .ok_or(Error::KeyTableCorrupt)?;
    keytable::read_file(
        file,
        &core.vault_id,
        core.keytable_gen,
        &core.keytable_digest,
        old.keytable_keys,
        old.probe,
    )
}

#[cfg(test)]
mod tests;
