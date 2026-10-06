//! `update` journals: restart resolution and the shared cleanup steps
//! (`docs/M4_READINESS.md` 9.2 to 9.6; approved for Milestone 4, A3).

use std::io;

use subtle::ConstantTimeEq;

use crate::crypto::cascade::{self, Expected, StreamKind};
use crate::errors::Error;
use crate::header::Header;
use crate::journal::{self, AuthenticatedHeader, Record, UpdatePhase, UpdateRecord};
use crate::keytable::{self, KeyTable, MAX_PLAINTEXT};
use crate::platform::fs::{self as pfs, Dir, Ownership};
use crate::resources::SystemMemory;
use crate::store::{self, HEADER_TMP, JOURNAL_TMP, keytable_name, keytable_tmp_name};

use super::{Bundle, Prompter};

/// The objects folder name.
pub(crate) const OBJECTS: &str = "objects";

/// `<hex>.pv` and `<hex>.pv.tmp` for an object ID.
pub(crate) fn object_name(oid: &[u8; 16]) -> String {
    format!("{}.pv", crate::records::hex(oid))
}

pub(crate) fn object_tmp_name(oid: &[u8; 16]) -> String {
    format!("{}.pv.tmp", crate::records::hex(oid))
}

/// The objects folder, if it exists.
pub(crate) fn objects_dir(dir: &Dir) -> Result<Option<Dir>, Error> {
    match dir.open_dir(OBJECTS) {
        Ok(d) => Ok(Some(d)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::Io(e)),
    }
}

pub(crate) enum Resolution {
    Done,
    Unresolved,
}

fn sealed(rec: UpdateRecord, key: &crate::secrets::SecretBytes<32>) -> Result<Vec<u8>, Error> {
    let mut r = Record::Update(rec);
    r.seal(key, None)?;
    Ok(r.encode())
}

/// Writes an `update` record.
pub(crate) fn write(dir: &Dir, rec: &UpdateRecord, bundle: &Bundle) -> Result<(), Error> {
    store::write_journal(dir, &sealed(rec.clone(), &bundle.journal_key()?)?)
}

/// Resolves a pending `update` journal after the unlock (9.5).
pub(crate) fn resolve(
    dir: &Dir,
    header: &Header,
    bundle: &Bundle,
    ui: &mut dyn Prompter,
) -> Result<Resolution, Error> {
    let jk = bundle.journal_key()?;
    let auth = AuthenticatedHeader {
        core_digest: header.core_digest(),
        by: journal::Bundle::Old,
    };
    let loaded = store::load_journal(dir, |c, t| journal::promote_update(c, t, &jk, Some(&auth)))?;
    let bytes = loaded.record.ok_or(Error::PendingJournal("operation"))?;
    let rec = match Record::parse(&bytes) {
        Ok(Record::Update(r)) if Record::Update(r.clone()).verify_old(&jk) => r,
        _ => return Err(Error::PendingJournal("operation")),
    };
    let digest = header.core_digest();
    let is_old = bool::from(digest.ct_eq(&rec.old_core_digest));
    let is_new = rec
        .new_core_digest
        .is_some_and(|d| bool::from(digest.ct_eq(&d)));
    if is_old {
        rollback(dir, &rec)?;
        ui.notice("An interrupted change was found and undone; the vault is as it was before it.");
        return Ok(Resolution::Done);
    }
    if !is_new {
        return Err(Error::Indeterminate);
    }
    let table = super::read_table(dir, header, bundle)?;
    match rec.phase {
        UpdatePhase::Committing => {
            if !dir.exists(keytable_name(rec.old_gen)).map_err(Error::Io)? {
                // Unresolved cleanup: infer no cause; delete nothing; keep
                // the journal (9.5).
                report_unresolved(dir, &rec, &table, ui)?;
                return Ok(Resolution::Unresolved);
            }
            dir.flush().map_err(|_| Error::DurabilityUnknown)?;
            finish(dir, &rec, bundle, &table, Some(ui))?;
        }
        UpdatePhase::Cleaned => finish_cleaned(dir, &rec)?,
        UpdatePhase::Staged => return Err(Error::Indeterminate),
    }
    ui.notice("An interrupted change was found and completed.");
    Ok(Resolution::Done)
}

/// Roll back: delete the identity-owned staged artifacts at their temp or
/// final names; flush; remove the journal.
pub(crate) fn rollback(dir: &Dir, rec: &UpdateRecord) -> Result<(), Error> {
    for name in [keytable_tmp_name(rec.new_gen), keytable_name(rec.new_gen)] {
        pfs::remove_if_owned(dir, &name, &rec.target_kt_id).map_err(Error::Io)?;
    }
    pfs::remove_if_owned(dir, HEADER_TMP, &rec.header_id).map_err(Error::Io)?;
    if let (Some((oid, id)), Some(objects)) = (&rec.new_object, objects_dir(dir)?) {
        for name in [object_tmp_name(oid), object_name(oid)] {
            pfs::remove_if_owned(&objects, &name, id).map_err(Error::Io)?;
        }
        objects.flush().map_err(Error::Io)?;
    }
    dir.flush().map_err(Error::Io)?;
    store::remove_journal(dir)
}

/// The 9.5 report for an unresolved cleanup: the message, the missing
/// file's name and the objects the current key table does not reference.
fn report_unresolved(
    dir: &Dir,
    rec: &UpdateRecord,
    table: &KeyTable,
    ui: &mut dyn Prompter,
) -> Result<(), Error> {
    let mut msg = Error::UnresolvedCleanup.to_string();
    msg.push_str(&format!("\nMissing: {}", keytable_name(rec.old_gen)));
    for (name, len) in unreferenced_objects(dir, table)? {
        msg.push_str(&format!(
            "\nNot referenced by the current key table: {OBJECTS}/{name} ({len} bytes)"
        ));
    }
    ui.notice(&msg);
    Ok(())
}

/// Regular files `objects/<hex>.pv` that `table` does not reference, with
/// their sizes.
pub(crate) fn unreferenced_objects(
    dir: &Dir,
    table: &KeyTable,
) -> Result<Vec<(String, u64)>, Error> {
    let Some(objects) = objects_dir(dir)? else {
        return Ok(Vec::new());
    };
    let referenced: Vec<String> = (0..table.len())
        .filter_map(|i| table.entry(i).and_then(|e| e.file_id))
        .map(|id| object_name(&id))
        .collect();
    let mut out = Vec::new();
    for name in objects.list().map_err(Error::Io)? {
        let Some(name) = name.to_str() else { continue };
        if !name.ends_with(".pv") || referenced.iter().any(|r| r == name) {
            continue;
        }
        if let Ok(Some(f)) = objects.open_regular(name, false) {
            out.push((name.to_owned(), f.metadata().map_err(Error::Io)?.len()));
        }
    }
    out.sort();
    Ok(out)
}

/// 9.7, journal pending: offers only a residue `vault.journal.tmp` that
/// blocks the journal rewrite the restart needs.
fn offer_journal_residue(
    dir: &Dir,
    vault_id: &[u8; 16],
    ui: &mut dyn Prompter,
) -> Result<(), Error> {
    let blocked = || Error::UnownedLeftovers(vec![JOURNAL_TMP.to_owned()]);
    let Some(f) = dir
        .open_regular(JOURNAL_TMP, false)
        .map_err(|_| blocked())?
    else {
        return Ok(());
    };
    let id = dir.identity(&f).map_err(Error::Io)?;
    let len = f.metadata().map_err(Error::Io)?.len();
    drop(f);
    ui.notice(&format!(
        "A file pvault cannot prove it created blocks finishing the interrupted change:\n  {JOURNAL_TMP} ({len} bytes)"
    ));
    let phrase = format!(
        "DELETE VAULT LEFTOVERS {}",
        crate::records::hex(&vault_id[..4])
    );
    if !ui.confirm(
        &format!("Type {phrase} to delete exactly this file: "),
        &phrase,
    )? {
        return Err(blocked());
    }
    let Some(f) = dir.open_regular(JOURNAL_TMP, false).map_err(Error::Io)? else {
        return Ok(());
    };
    if dir.identity(&f).ok() != Some(id) || f.metadata().map_err(Error::Io)?.len() != len {
        return Err(blocked());
    }
    if !dir.delete_held(JOURNAL_TMP, &f).map_err(Error::Io)? {
        return Err(blocked());
    }
    dir.flush().map_err(Error::Io)
}

/// U10a to U11 (the header is the new core; the old key table is present).
/// `ui` is given on a restart, where a residue journal temp may block U10b.
pub(crate) fn finish(
    dir: &Dir,
    rec: &UpdateRecord,
    bundle: &Bundle,
    new_table: &KeyTable,
    ui: Option<&mut dyn Prompter>,
) -> Result<Vec<String>, Error> {
    let mut kept = Vec::new();
    // U10a: the removed set, from the authenticated old key table.
    let old_file = dir
        .open_regular(keytable_name(rec.old_gen), false)
        .map_err(Error::Io)?
        .ok_or(Error::UnresolvedCleanup)?;
    let old = keytable::read_file(
        old_file,
        &rec.vault_id,
        rec.old_gen,
        &rec.old_keytable_digest,
        &bundle.keytable_keys()?,
        &SystemMemory,
    )?;
    if let Some(objects) = objects_dir(dir)? {
        for i in 0..old.len() {
            let Some(e) = old.entry(i) else { continue };
            let Some(oid) = e.file_id else { continue };
            let still = (0..new_table.len())
                .any(|j| new_table.entry(j).and_then(|n| n.file_id) == Some(oid));
            if still {
                continue;
            }
            let name = object_name(&oid);
            let Some(file) = objects.open_regular(&name, false).map_err(Error::Io)? else {
                continue; // already deleted
            };
            let keys = old.stream_keys(i)?.ok_or(Error::KeyTableCorrupt)?;
            let expected = Expected {
                kind: StreamKind::Object,
                stream_id: oid,
                context: 0,
                plain_size: Some(e.size),
                max_plain_size: e.size.max(MAX_PLAINTEXT),
            };
            // Expected content: the whole stream authenticates under the
            // removed entry's unique keys (stricter than the first record).
            let ok = cascade::decrypt(&keys, &expected, &file, io::sink()).is_ok();
            if ok && objects.delete_held(&name, &file).map_err(Error::Io)? {
                continue;
            }
            kept.push(format!("{}/{}", super::update::OBJECTS, name));
        }
        failpoint!("update.objects-removed");
        objects.flush().map_err(|_| Error::DurabilityUnknown)?;
    }
    // U10b.
    let mut cleaned = rec.clone();
    cleaned.phase = UpdatePhase::Cleaned;
    match (write(dir, &cleaned, bundle), ui) {
        (Err(Error::Blocked(_)), Some(ui)) => {
            offer_journal_residue(dir, &rec.vault_id, ui)?;
            write(dir, &cleaned, bundle)?;
        }
        (r, _) => r?,
    }
    failpoint!("update.cleaned");
    finish_cleaned(dir, rec)?;
    Ok(kept)
}

/// U10c and U11.
pub(crate) fn finish_cleaned(dir: &Dir, rec: &UpdateRecord) -> Result<(), Error> {
    let name = keytable_name(rec.old_gen);
    if let Some(file) = dir.open_regular(&name, false).map_err(Error::Io)? {
        let digest = store::hash_handle(&file)?;
        let same = dir.identity(&file).ok() == Some(rec.old_kt_id);
        drop(file);
        if same && bool::from(digest.ct_eq(&rec.old_keytable_digest)) {
            if pfs::remove_if_owned(dir, &name, &rec.old_kt_id).map_err(Error::Io)?
                != Ownership::Removed
            {
                // Changed meanwhile: left in place.
            }
            failpoint!("update.old-table-removed");
        }
    }
    dir.flush().map_err(|_| Error::DurabilityUnknown)?;
    store::remove_journal(dir)
}

/// `CLOSE UNFINISHED CLEANUP`: removes only the authenticated pending
/// `update` journal; deletes nothing else.
pub(crate) fn close_unresolved(dir: &Dir, bundle: &Bundle) -> Result<(), Error> {
    let jk = bundle.journal_key()?;
    let bytes = store::read_capped(dir, store::JOURNAL, journal::MAX_JOURNAL_LEN, || {
        Error::JournalInvalid
    })?
    .ok_or(Error::JournalInvalid)?;
    match Record::parse(&bytes) {
        Ok(rec @ Record::Update(_)) if rec.verify_old(&jk) => store::remove_journal(dir),
        _ => Err(Error::JournalInvalid),
    }
}
