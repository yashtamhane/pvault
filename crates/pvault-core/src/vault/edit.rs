//! `add` and `rm` (spec 7.7, 7.8; `docs/M4_READINESS.md` sections 8 to 10;
//! approved for Milestone 4, A3 to A5).

use std::fs::File;
use std::path::Path;

use zeroize::Zeroizing;

use crate::crypto::cascade::{self, StreamHeader, StreamKeys, StreamKind};
use crate::crypto::random;
use crate::errors::Error;
use crate::header::Header;
use crate::journal::{UpdatePhase, UpdateRecord};
use crate::keytable::{self, EntryKind, KeyTable, NewEntry};
use crate::paths::{self, InputPathError};
use crate::platform::fs::{self as pfs, Dir, SourceError, SourceMeta};
use crate::records::{Settings, hex};
use crate::secrets::SecretBytes;
use crate::store::{self, HEADER_TMP, JOURNAL_TMP, Owned, keytable_name, keytable_tmp_name};

use super::update::{self, OBJECTS, object_name, object_tmp_name, objects_dir};
use super::{Prompter, Session, now};

/// What `add` did.
#[derive(Debug)]
pub struct AddOutcome {
    /// The stored (NFC) path.
    pub stored: Zeroizing<String>,
    /// Whether normalization changed the typed path.
    pub changed: bool,
    /// Bytes added.
    pub size: u64,
    /// Parent folders created.
    pub created_dirs: usize,
    /// Files left in place after cleanup (could not be proven).
    pub kept: Vec<String>,
}

fn path_error(e: InputPathError) -> Error {
    match e {
        InputPathError::Unassigned => Error::PathUnsupported,
        InputPathError::Invalid(r) => Error::PathNotAllowed(r),
    }
}

fn source_error(e: SourceError) -> Error {
    match e {
        SourceError::Link => Error::SourceLink,
        SourceError::NotRegular => Error::SourceNotRegular,
        SourceError::InUse => Error::SourceInUse,
        SourceError::Io(e) => Error::Io(e),
    }
}

/// Checks the 9.7 gate: an unresolved cleanup may be closed, and unowned
/// files at names this change needs block it unless the owner removes them.
fn gate(s: &mut Session, ui: &mut dyn Prompter) -> Result<(), Error> {
    let hex8 = hex(&s.vault_id()[..4]);
    if s.unresolved {
        ui.notice(&Error::UnresolvedCleanup.to_string());
        let phrase = format!("CLOSE UNFINISHED CLEANUP {hex8}");
        if ui.confirm(
            &format!("Type {phrase} to stop tracking it (no file is deleted): "),
            &phrase,
        )? {
            update::close_unresolved(&s.dir, &s.bundle)?;
            s.unresolved = false;
        } else {
            return Err(Error::UnresolvedCleanup);
        }
    }
    let g = s
        .generation()
        .checked_add(1)
        .ok_or(Error::Unsupported("generation limit reached"))?;
    let needed = [
        HEADER_TMP.to_owned(),
        JOURNAL_TMP.to_owned(),
        keytable_name(g),
        keytable_tmp_name(g),
    ];
    let mut blocking = Vec::new();
    for n in &needed {
        if s.dir.exists(n).map_err(Error::Io)? {
            blocking.push(n.clone());
        }
    }
    if blocking.is_empty() {
        return Ok(());
    }
    // Candidates: the blocking names plus object temps and unreferenced
    // objects; regular files only, snapshotted by identity and size.
    let mut candidates: Vec<(Option<Dir>, String, pfs::FileIdentity, u64)> = Vec::new();
    let mut reported = Vec::new();
    for n in &blocking {
        match s.dir.open_regular(n, false) {
            Ok(Some(f)) => {
                let id = s.dir.identity(&f).map_err(Error::Io)?;
                let len = f.metadata().map_err(Error::Io)?.len();
                candidates.push((None, n.clone(), id, len));
            }
            _ => reported.push(n.clone()),
        }
    }
    if let Some(objects) = objects_dir(&s.dir)? {
        let referenced: Vec<String> = (0..s.table.len())
            .filter_map(|i| s.table.entry(i).and_then(|e| e.file_id))
            .map(|id| object_name(&id))
            .collect();
        for name in objects.list().map_err(Error::Io)? {
            let Some(name) = name.to_str().map(str::to_owned) else {
                continue;
            };
            let is_tmp = name.ends_with(".pv.tmp");
            let is_obj = name.ends_with(".pv") && !referenced.contains(&name);
            if !(is_tmp || is_obj) {
                continue;
            }
            if let Ok(Some(f)) = objects.open_regular(&name, false) {
                let id = objects.identity(&f).map_err(Error::Io)?;
                let len = f.metadata().map_err(Error::Io)?.len();
                candidates.push((
                    Some(objects_dir(&s.dir)?.ok_or(Error::Indeterminate)?),
                    format!("{OBJECTS}/{name}"),
                    id,
                    len,
                ));
            }
        }
    }
    let names: Vec<String> = blocking.clone();
    let mut listing = String::from("Files pvault cannot prove it created block this change:\n");
    for (_, n, _, len) in &candidates {
        listing.push_str(&format!("  {} ({len} bytes)\n", crate::render::text(n)));
    }
    for n in &reported {
        listing.push_str(&format!(
            "  {} (not a regular file; reported only)\n",
            crate::render::text(n)
        ));
    }
    ui.notice(listing.trim_end());
    let phrase = format!("DELETE VAULT LEFTOVERS {hex8}");
    if !ui.confirm(
        &format!("Type {phrase} to delete exactly these files: "),
        &phrase,
    )? {
        return Err(Error::UnownedLeftovers(names));
    }
    for (sub, n, id, len) in candidates {
        let (dir, name) = match &sub {
            Some(d) => (d, n.trim_start_matches("objects/").to_owned()),
            None => (&s.dir, n.clone()),
        };
        // Snapshot recheck immediately before the unlink.
        let Some(f) = dir.open_regular(&name, false).map_err(Error::Io)? else {
            continue;
        };
        if dir.identity(&f).ok() != Some(id) || f.metadata().map_err(Error::Io)?.len() != len {
            continue;
        }
        dir.delete_held(&name, &f).map_err(Error::Io)?;
        dir.flush().map_err(Error::Io)?;
    }
    if !reported.is_empty() {
        return Err(Error::UnownedLeftovers(reported));
    }
    Ok(())
}

/// The planned key-table change for `add`.
struct Plan {
    replaced: Option<usize>,
    new_dirs: Vec<String>,
}

fn plan_add(table: &KeyTable, stored: &str, replace: bool) -> Result<Plan, Error> {
    let keys: Vec<(Zeroizing<Vec<char>>, usize)> = (0..table.len())
        .filter_map(|i| table.entry(i).map(|e| (paths::collision_key(e.path), i)))
        .collect();
    let find = |p: &str| {
        let k = paths::collision_key(p);
        keys.iter().find(|(kk, _)| **kk == *k).map(|(_, i)| *i)
    };
    let mut replaced = None;
    if let Some(i) = find(stored) {
        let e = table.entry(i).ok_or(Error::KeyTableCorrupt)?;
        if e.path != stored {
            return Err(if replace {
                Error::ReplaceNeedsStoredPath
            } else {
                Error::PathCollision
            });
        }
        if e.kind == EntryKind::Dir {
            return Err(Error::WrongKind("A folder cannot be replaced by a file."));
        }
        if !replace {
            return Err(Error::PathExists);
        }
        replaced = Some(i);
    }
    let mut new_dirs = Vec::new();
    let mut prefix = String::new();
    let parts: Vec<&str> = stored.split('/').collect();
    for part in &parts[..parts.len() - 1] {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(part);
        match find(&prefix) {
            Some(i) => {
                let e = table.entry(i).ok_or(Error::KeyTableCorrupt)?;
                if e.path != prefix {
                    return Err(Error::PathCollision);
                }
                if e.kind == EntryKind::File {
                    return Err(Error::WrongKind(
                        "A file in the vault is in the way of this path.",
                    ));
                }
            }
            None => new_dirs.push(prefix.clone()),
        }
    }
    Ok(Plan { replaced, new_dirs })
}

fn new_file_id(table: &KeyTable) -> Result<[u8; 16], Error> {
    loop {
        let id = random::array::<16>()?;
        if !(0..table.len()).any(|i| table.entry(i).and_then(|e| e.file_id) == Some(id)) {
            return Ok(id);
        }
    }
}

/// A source prepared for U7.
struct Source {
    file: File,
    meta: SourceMeta,
    oid: [u8; 16],
    keys: (SecretBytes<32>, SecretBytes<32>),
}

/// U3 to U11 for both commands.
fn transact(
    s: &mut Session,
    new_table: KeyTable,
    mut source: Option<Source>,
    settings: Option<&Settings>,
) -> Result<Vec<String>, Error> {
    let core = s.header.core().clone();
    let old_gen = core.generation;
    let new_gen = old_gen
        .checked_add(1)
        .ok_or(Error::Unsupported("generation limit reached"))?;
    // U3.
    let objects = match &source {
        Some(_) => {
            let vol = pfs::preflight(&s.dir)?;
            if objects_dir(&s.dir)?.is_none() {
                s.dir.create_dir(OBJECTS).map_err(Error::Io)?;
                s.dir.flush().map_err(Error::Io)?;
            }
            let o = objects_dir(&s.dir)?.ok_or(Error::Indeterminate)?;
            pfs::same_volume(&vol, &o)?;
            pfs::preflight(&o)?;
            Some(o)
        }
        None => None,
    };
    let old_kt = s
        .dir
        .open_regular(keytable_name(old_gen), false)
        .map_err(Error::Io)?
        .ok_or(Error::KeyTableCorrupt)?;
    let old_kt_id = s.dir.identity(&old_kt).map_err(Error::Io)?;
    drop(old_kt);
    failpoint!("update.prepared");
    // U4.
    let kt = Owned::create(&s.dir, &keytable_tmp_name(new_gen), "a key-table temp")?;
    let mut hdr = Owned::create(&s.dir, HEADER_TMP, HEADER_TMP)?;
    let mut obj = match (&source, &objects) {
        (Some(src), Some(o)) => Some(Owned::create(
            o,
            &object_tmp_name(&src.oid),
            "an object temp",
        )?),
        _ => None,
    };
    failpoint!("update.created");
    // U5.
    let mut rec = UpdateRecord {
        phase: UpdatePhase::Staged,
        vault_id: core.vault_id,
        old_gen,
        new_gen,
        old_core_digest: s.header.core_digest(),
        old_keytable_digest: core.keytable_digest,
        old_kt_id,
        target_kt_id: kt.id(),
        header_id: hdr.id(),
        new_object: match (&source, &obj) {
            (Some(src), Some(o)) => Some((src.oid, o.id())),
            _ => None,
        },
        new_core_digest: None,
        mac: [0; 64],
    };
    update::write(&s.dir, &rec, &s.bundle)?;
    failpoint!("update.staged");
    let result = (|| -> Result<([u8; 64], Vec<u8>), Error> {
        // U6.
        let digest = keytable::write_file(
            &new_table,
            &core.vault_id,
            new_gen,
            &s.bundle.keytable_keys()?,
            kt.file(),
        )?;
        failpoint!("update.keytable-written");
        pfs::flush_file(kt.file()).map_err(Error::Io)?;
        s.dir
            .rename_noreplace(keytable_tmp_name(new_gen), keytable_name(new_gen))
            .map_err(Error::Io)?;
        s.dir.flush().map_err(Error::Io)?;
        failpoint!("update.keytable-final");
        // U7.
        if let (Some(src), Some(o), Some(objects)) = (&mut source, &mut obj, &objects) {
            let header = StreamHeader {
                kind: StreamKind::Object,
                stream_id: src.oid,
                context: 0,
                plain_size: src.meta.size,
            };
            let keys = StreamKeys::new(super::copy32(&src.keys.0)?, super::copy32(&src.keys.1)?);
            o.truncate().map_err(Error::Io)?;
            match cascade::encrypt(&keys, &header, &src.file, o.file()) {
                Ok(()) => {}
                Err(Error::InputLength) => return Err(Error::SourceChanged),
                Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Err(Error::SourceChanged);
                }
                Err(e) => return Err(e),
            }
            failpoint!("update.object-written");
            if pfs::source_meta(&src.file).map_err(Error::Io)? != src.meta {
                return Err(Error::SourceChanged);
            }
            pfs::flush_file(o.file()).map_err(Error::Io)?;
            objects
                .rename_noreplace(object_tmp_name(&src.oid), object_name(&src.oid))
                .map_err(Error::Io)?;
            objects.flush().map_err(Error::Io)?;
            failpoint!("update.object-final");
        }
        // U8.
        let mut new_core = core.clone();
        new_core.generation = new_gen;
        new_core.keytable_gen = new_gen;
        new_core.keytable_digest = digest;
        let bytes = Header::build(&new_core, s.header.slots(), &s.bundle.k_mac)?;
        Ok((new_core.digest()?, bytes))
    })();
    let (new_core_digest, bytes) = match result {
        Ok(v) => v,
        Err(e) => {
            drop((kt, hdr, obj));
            update::rollback(&s.dir, &rec)?;
            return Err(e);
        }
    };
    drop(kt);
    drop(obj);
    rec.phase = UpdatePhase::Committing;
    rec.new_core_digest = Some(new_core_digest);
    update::write(&s.dir, &rec, &s.bundle)?;
    failpoint!("update.committing");
    // U9: the journal stays on any error from here; the next unlock resolves.
    store::commit_header(&s.dir, &mut hdr, &bytes, old_gen)?;
    drop(hdr);
    failpoint!("update.committed");
    // Tests stop here to leave the after-commit state in-process.
    fail_io!("update.before-cleanup").map_err(Error::Io)?;
    // U10 and U11.
    let kept = update::finish(&s.dir, &rec, &s.bundle, &new_table, None)?;
    s.header = store::read_header(&s.dir)?.ok_or(Error::HeaderInvalid)?;
    s.table = new_table;
    if let Some(settings) = settings {
        let _ = settings.rollback_observe(&core.vault_id, new_gen);
    }
    Ok(kept)
}

/// `add <source> <vault-path> [--replace]`.
pub fn add(
    s: &mut Session,
    source: &Path,
    vault_path: &str,
    replace: bool,
    settings: Option<&Settings>,
    ui: &mut dyn Prompter,
) -> Result<AddOutcome, Error> {
    pfs::preflight(&s.dir)?;
    gate(s, ui)?;
    let input = paths::normalize_input(vault_path).map_err(path_error)?;
    let plan = plan_add(&s.table, &input.stored, replace)?;
    let file = pfs::open_source(source).map_err(source_error)?;
    let meta = pfs::source_meta(&file).map_err(Error::Io)?;
    #[cfg(test)]
    tests::after_snapshot(source);
    let oid = new_file_id(&s.table)?;
    let keys = (random::secret::<32>()?, random::secret::<32>()?);
    let t = now();
    let modified = u64::try_from(meta.mtime.0).unwrap_or(0);
    let mut entries = s.table.to_new_entries()?;
    if let Some(i) = plan.replaced {
        let path = s
            .table
            .entry(i)
            .ok_or(Error::KeyTableCorrupt)?
            .path
            .to_owned();
        entries.retain(|e| *e.path != path);
    }
    for d in &plan.new_dirs {
        entries.push(NewEntry {
            kind: EntryKind::Dir,
            path: Zeroizing::new(d.clone()),
            file_id: [0; 16],
            size: 0,
            created_at: t,
            modified_at: t,
            keys: None,
        });
    }
    entries.push(NewEntry {
        kind: EntryKind::File,
        path: Zeroizing::new(input.stored.to_string()),
        file_id: oid,
        size: meta.size,
        created_at: t,
        modified_at: modified,
        keys: Some((super::copy32(&keys.0)?, super::copy32(&keys.1)?)),
    });
    // N5 and every decode rule are checked here, before any side effect.
    let new_table = KeyTable::from_entries(entries)?;
    let size = meta.size;
    let kept = transact(
        s,
        new_table,
        Some(Source {
            file,
            meta,
            oid,
            keys,
        }),
        settings,
    )?;
    Ok(AddOutcome {
        stored: input.stored,
        changed: input.changed,
        size,
        created_dirs: plan.new_dirs.len(),
        kept,
    })
}

/// `rm <vault-path> [--recursive]`: returns the number of entries removed
/// and any files left in place.
pub fn rm(
    s: &mut Session,
    vault_path: &str,
    recursive: bool,
    settings: Option<&Settings>,
    ui: &mut dyn Prompter,
) -> Result<(usize, Vec<String>), Error> {
    pfs::preflight(&s.dir)?;
    gate(s, ui)?;
    let input = paths::normalize_input(vault_path).map_err(path_error)?;
    let target = s.table.find(&input.stored).ok_or(Error::PathNotFound)?;
    let prefix = format!("{}/", input.stored.as_str());
    let entries = s.table.to_new_entries()?;
    let descendants = entries
        .iter()
        .filter(|e| e.path.starts_with(&prefix))
        .count();
    let is_dir = s.table.entry(target).map(|e| e.kind) == Some(EntryKind::Dir);
    if is_dir && descendants > 0 && !recursive {
        return Err(Error::FolderNotEmpty);
    }
    let keep: Vec<NewEntry> = entries
        .into_iter()
        .filter(|e| *e.path != *input.stored && !e.path.starts_with(&prefix))
        .collect();
    let removed = s.table.len() - keep.len();
    let new_table = KeyTable::from_entries(keep)?;
    let kept = transact(s, new_table, None, settings)?;
    Ok((removed, kept))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::cell::RefCell;
    use std::path::Path;

    type Hook = Box<dyn FnOnce(&Path)>;

    thread_local! {
        static AFTER_SNAPSHOT: RefCell<Option<Hook>> = RefCell::new(None);
    }

    /// Runs `hook` once, right after the next source snapshot (10.2), to
    /// change the source while it is being added.
    pub(crate) fn set_after_snapshot(hook: impl FnOnce(&Path) + 'static) {
        AFTER_SNAPSHOT.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    pub(super) fn after_snapshot(source: &Path) {
        if let Some(hook) = AFTER_SNAPSHOT.with(|h| h.borrow_mut().take()) {
            hook(source);
        }
    }
}
