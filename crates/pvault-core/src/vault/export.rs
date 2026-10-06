//! `list`, `get` and `clean-partials` (spec 7.9; `docs/M4_READINESS.md` 7.5
//! and 11.3; approved for Milestone 4, A2 and A6).

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::crypto::cascade::{self, Expected, StreamKind};
use crate::errors::Error;
use crate::keytable::{EntryKind, MAX_PLAINTEXT};
use crate::paths;
use crate::platform::fs::{self as pfs, Dir};
use crate::records::{
    self, CardRole, Delivery, OpKind, PartialEntry, RecordedFile, Settings, StaleOutcome,
    native_path, path_from_native,
};
use crate::render;

use super::update::{object_name, objects_dir};
use super::{Prompter, Session, now, timestamp};

/// The partial-file suffix (7.9).
pub const PARTIAL_SUFFIX: &str = ".pvpartial";

/// Writes the `list` output (`docs/CLI.md` 6.3), optionally for one entry
/// and its descendants. Returns the number of lines written.
pub fn list(s: &Session, prefix: Option<&str>, out: &mut dyn Write) -> Result<usize, Error> {
    let filter = match prefix {
        Some(p) => {
            let input = paths::normalize_input(p).map_err(|e| match e {
                paths::InputPathError::Unassigned => Error::PathUnsupported,
                paths::InputPathError::Invalid(r) => Error::PathNotAllowed(r),
            })?;
            s.table.find(&input.stored).ok_or(Error::PathNotFound)?;
            Some(input.stored)
        }
        None => None,
    };
    let mut n = 0;
    for i in 0..s.table.len() {
        let Some(e) = s.table.entry(i) else { continue };
        if let Some(f) = &filter {
            let under = e
                .path
                .strip_prefix(f.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'));
            if !under {
                continue;
            }
        }
        let line = Zeroizing::new(match e.kind {
            EntryKind::File => format!(
                "file\t{}\t{}\t{}\n",
                e.size,
                timestamp(e.modified_at),
                render::text(e.path)
            ),
            EntryKind::Dir => format!(
                "dir\t-\t{}\t{}\n",
                timestamp(e.modified_at),
                render::text(e.path)
            ),
        });
        out.write_all(line.as_bytes()).map_err(Error::Io)?;
        n += 1;
    }
    out.flush().map_err(Error::Io)?;
    Ok(n)
}

/// What `get` did.
#[derive(Debug)]
pub struct GetOutcome {
    /// The stored path that was exported.
    pub stored: Zeroizing<String>,
    /// Bytes written.
    pub size: u64,
}

/// A `get` failure after publication or with an unknown outcome; the CLI
/// names the destination.
#[derive(Debug)]
pub enum GetError {
    /// Nothing was published.
    Failed(Error),
    /// `<destination>` exists and is the export; durability unconfirmed
    /// (exit 5).
    Unconfirmed(GetOutcome),
    /// The rename's outcome could not be classified (exit 5).
    Unknown,
}

impl From<Error> for GetError {
    fn from(e: Error) -> Self {
        Self::Failed(e)
    }
}

fn absolute(p: &Path) -> Result<PathBuf, Error> {
    std::path::absolute(p).map_err(Error::Io)
}

fn render_recorded(f: &RecordedFile) -> String {
    render::path(&path_from_native(&f.path))
}

/// Opens the destination folder. A symbolic link or reparse point is
/// refused (Rust reports Windows name-surrogate reparse points, including
/// junctions, as symlinks); `Dir::open` itself does not follow one.
pub(crate) fn open_parent(parent: &Path) -> Result<Dir, Error> {
    if std::fs::symlink_metadata(parent).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(Error::DestinationFolderLink);
    }
    Dir::open(parent).map_err(Error::Io)
}

/// Offers deletion of this vault's stale exports (7.9); declining continues.
fn offer_stale(
    settings: &Settings,
    vault_id: &[u8; 16],
    ui: &mut dyn Prompter,
) -> Result<(), Error> {
    let stale = settings.stale_partials(Some(vault_id))?;
    if stale.is_empty() {
        return Ok(());
    }
    let mut msg = String::from("An interrupted export of this vault left these files:\n");
    for (e, _) in &stale {
        msg.push_str(&format!("  {}\n", render_recorded(&e.file)));
    }
    ui.notice(msg.trim_end());
    let phrase = "DELETE STALE EXPORTS";
    if !ui.confirm(&format!("Delete them? Type {phrase} to confirm: "), phrase)? {
        return Ok(());
    }
    for (e, lock) in stale {
        report_stale(ui, &e.file, " It may contain exported plaintext.")?;
        settings.unregister_partial(&e.transfer_id)?;
        lock.finish();
    }
    Ok(())
}

/// Applies the after-restart rule to one recorded file and reports it.
fn report_stale(
    ui: &mut dyn Prompter,
    f: &RecordedFile,
    extra: &str,
) -> Result<StaleOutcome, Error> {
    let outcome = records::delete_recorded(f)?;
    let shown = render_recorded(f);
    match outcome {
        StaleOutcome::Deleted => ui.notice(&format!("Deleted {shown}.")),
        StaleOutcome::Missing => ui.notice(&format!("{shown} no longer exists.")),
        StaleOutcome::Mismatch | StaleOutcome::Unprovable => ui.notice(&format!(
            "pvault cannot prove that {shown} is the file it created; delete it yourself if it is.{extra}"
        )),
    }
    Ok(outcome)
}

/// Deletes the unpublished partial through its open handle and removes the
/// entry (failure before publication).
fn discard(
    parent: &Dir,
    partial: &std::ffi::OsStr,
    file: File,
    settings: &Settings,
    lock: records::OpLock,
    registered: bool,
) {
    let _ = parent.delete_held(partial, &file);
    drop(file);
    let _ = parent.flush();
    if registered {
        if settings.unregister_partial(&lock.id()).is_ok() {
            lock.finish();
        }
    } else {
        lock.finish();
    }
}

/// The O3 destination check alone (decided 2026-10-06, fail closed), for
/// the CLI to run **before the unlock**, so a refused destination costs no
/// secret. [`get`] repeats it on the handle it writes through.
pub fn check_destination(destination: &Path) -> Result<(), Error> {
    let destination = absolute(destination)?;
    let parent_path = destination.parent().ok_or(Error::DestinationExists)?;
    let parent = open_parent(parent_path)?;
    pfs::check_private_destination(&parent)
}

/// `get <vault-path> <destination>` (7.9 with E1 to E6).
pub fn get(
    s: &Session,
    vault_path: &str,
    destination: &Path,
    settings: &Settings,
    ui: &mut dyn Prompter,
) -> Result<GetOutcome, GetError> {
    let input = paths::normalize_input(vault_path).map_err(|e| match e {
        paths::InputPathError::Unassigned => Error::PathUnsupported,
        paths::InputPathError::Invalid(r) => Error::PathNotAllowed(r),
    })?;
    let i = s.table.find(&input.stored).ok_or(Error::PathNotFound)?;
    let e = s.table.entry(i).ok_or(Error::KeyTableCorrupt)?;
    if e.kind != EntryKind::File {
        return Err(Error::WrongKind("This path is a folder; get exports one file.").into());
    }
    let oid = e.file_id.ok_or(Error::KeyTableCorrupt)?;
    let size = e.size;
    let destination = absolute(destination)?;
    // Native names (7.2): any Unix bytes, any Windows UTF-16. The suffix is
    // appended to the native name; only vault paths must be Unicode.
    let name = destination
        .file_name()
        .ok_or(Error::DestinationExists)?
        .to_owned();
    let mut partial = name.clone();
    partial.push(PARTIAL_SUFFIX);
    let parent_path = destination.parent().ok_or(Error::DestinationExists)?;
    let parent = open_parent(parent_path)?;
    // O3 (decided 2026-10-06): plaintext only where it can stay owner-only;
    // refused before any destination file exists and before any prompt.
    pfs::check_private_destination(&parent)?;
    // E1: the registration policy before any destination file exists.
    settings.check_registration()?;
    offer_stale(settings, &s.vault_id(), ui)?;
    settings.check_partial_room()?;
    if parent.exists(&name).map_err(Error::Io)? {
        return Err(Error::DestinationExists.into());
    }
    let partial_path = parent_path.join(&partial);
    let recorded_path = native_path(&partial_path).ok_or(Error::PathTooLongToTrack)?;
    let lock = settings.begin_operation(OpKind::Transfer)?;
    // E2.
    let file = match parent.create_new(&partial) {
        Ok(f) => f,
        Err(e) => {
            lock.finish();
            return Err(match e.kind() {
                io::ErrorKind::AlreadyExists => Error::NameExists(render::path(&partial_path)),
                io::ErrorKind::InvalidFilename => Error::NameTooLong,
                _ => Error::Io(e),
            }
            .into());
        }
    };
    let id = match pfs::record_identity(&file) {
        Ok(id) => id,
        Err(e) => {
            discard(&parent, &partial, file, settings, lock, false);
            return Err(Error::Io(e).into());
        }
    };
    failpoint!("export.created");
    // E3.
    let entry = PartialEntry {
        transfer_id: lock.id(),
        vault_id: s.vault_id(),
        created_at: now(),
        file: RecordedFile {
            path: recorded_path,
            id,
        },
    };
    if let Err(e) = settings.register_partial(entry) {
        // Best effort: the entry may or may not exist.
        discard(&parent, &partial, file, settings, lock, true);
        return Err(match e {
            Error::NotRegistered(_) => Error::NotRegistered("export"),
            other => other,
        }
        .into());
    }
    failpoint!("export.registered");
    // E4: only verified plaintext reaches the partial.
    let written = (|| -> Result<(), Error> {
        let objects = objects_dir(&s.dir)?.ok_or(Error::KeyTableCorrupt)?;
        let object = objects
            .open_regular(object_name(&oid), false)
            .map_err(Error::Io)?
            .ok_or(Error::Stream)?;
        let keys = s.table.stream_keys(i)?.ok_or(Error::KeyTableCorrupt)?;
        let expected = Expected {
            kind: StreamKind::Object,
            stream_id: oid,
            context: 0,
            plain_size: Some(size),
            max_plain_size: size.max(MAX_PLAINTEXT),
        };
        cascade::decrypt(&keys, &expected, io::BufReader::new(object), &file)?;
        failpoint!("export.written");
        pfs::flush_file(&file).map_err(Error::Io)
    })();
    if let Err(e) = written {
        discard(&parent, &partial, file, settings, lock, true);
        return Err(e.into());
    }
    let outcome = GetOutcome {
        stored: input.stored,
        size,
    };
    // E5a: publication, classified by the names.
    let renamed = (|| -> io::Result<()> {
        fail_io!("export.rename")?;
        parent.rename_noreplace(&partial, &name)?;
        fail_io!("export.rename-reported")
    })();
    if let Err(e) = renamed {
        let at_dest = parent.held_at(&name, &file).ok().flatten() == Some(true);
        let at_partial = parent.held_at(&partial, &file).ok().flatten() == Some(true);
        if at_dest {
            let _ = settings.unregister_partial(&lock.id());
            return Err(GetError::Unconfirmed(outcome));
        }
        if at_partial {
            discard(&parent, &partial, file, settings, lock, true);
            return Err(match e.kind() {
                io::ErrorKind::AlreadyExists => Error::DestinationExists,
                io::ErrorKind::Unsupported => Error::NoReplaceUnsupported,
                _ => Error::Io(e),
            }
            .into());
        }
        // Neither: delete nothing, keep the entry (the record names only the
        // partial path, never the destination).
        drop(lock);
        return Err(GetError::Unknown);
    }
    failpoint!("export.published");
    // E5b.
    if fail_io!("export.flush-parent")
        .and_then(|()| parent.flush())
        .is_err()
    {
        let _ = settings.unregister_partial(&lock.id());
        return Err(GetError::Unconfirmed(outcome));
    }
    drop(file);
    // E6.
    let removed = fail_io!("export.unregister")
        .map_err(Error::Io)
        .and_then(|()| settings.unregister_partial(&lock.id()));
    if removed.is_err() {
        return Err(GetError::Unconfirmed(outcome));
    }
    lock.finish();
    Ok(outcome)
}

/// What `clean-partials` found and did.
#[derive(Debug, Default)]
pub struct CleanReport {
    /// Stale entries found.
    pub stale: usize,
    /// Whether the owner confirmed.
    pub confirmed: bool,
    /// Damaged records (reported; never changed).
    pub damaged: Vec<String>,
}

/// `clean-partials` (`docs/CLI.md` 6.7): no vault lock.
pub fn clean_partials(settings: &Settings, ui: &mut dyn Prompter) -> Result<CleanReport, Error> {
    let mut report = CleanReport {
        damaged: settings
            .check_records()
            .iter()
            .map(ToString::to_string)
            .collect(),
        ..CleanReport::default()
    };
    for d in &report.damaged {
        ui.notice(d);
    }
    let partials = settings.stale_partials(None).unwrap_or_default();
    let cards = settings.stale_cards(None).unwrap_or_default();
    // Digital card files are the owner's recovery files: never deleted here
    // (SI-52 8.2); only their record entries can be forgotten.
    let (digital, paper): (Vec<_>, Vec<_>) = cards
        .into_iter()
        .partition(|(entries, _)| entries.iter().any(|e| e.delivery == Delivery::Digital));
    let paper_files = paper.iter().map(|(e, _)| e.len()).sum::<usize>();
    let digital_files = digital.iter().map(|(e, _)| e.len()).sum::<usize>();
    report.stale = partials.len() + paper_files + digital_files;
    if report.stale == 0 {
        return Ok(report);
    }
    let role = |r: CardRole| match r {
        CardRole::CardA => "Card A",
        CardRole::CardB => "Card B",
        CardRole::Bound => "card",
    };
    let mut confirmed = true;
    let deletable = partials.len() + paper_files;
    if deletable > 0 {
        let mut msg = String::from("Stale files recorded by interrupted operations:\n");
        for (e, _) in &partials {
            msg.push_str(&format!("  export: {}\n", render_recorded(&e.file)));
        }
        for (entries, _) in &paper {
            for e in entries {
                msg.push_str(&format!(
                    "  {} file: {}\n",
                    role(e.role),
                    render_recorded(&e.file)
                ));
            }
        }
        ui.notice(msg.trim_end());
        let phrase = format!("DELETE {deletable} STALE FILES");
        if ui.confirm(&format!("Type {phrase} to confirm: "), &phrase)? {
            for (e, lock) in partials {
                report_stale(ui, &e.file, " It may contain exported plaintext.")?;
                settings.unregister_partial(&e.transfer_id)?;
                lock.finish();
            }
            for (entries, lock) in paper {
                for e in &entries {
                    report_stale(ui, &e.file, " It may hold a recovery card.")?;
                }
                settings.unregister_cards(&lock.id())?;
                lock.finish();
            }
        } else {
            confirmed = false;
        }
    }
    if digital_files > 0 {
        let mut msg = String::from(
            "Digital recovery card files of interrupted setups (pvault never deletes these; they may be valid current cards):\n",
        );
        for (entries, _) in &digital {
            for e in entries {
                let vault = e
                    .vault_path
                    .as_deref()
                    .map(|p| render::path(&path_from_native(p)))
                    .unwrap_or_else(|| "unknown".to_owned());
                msg.push_str(&format!(
                    "  {} file: {} (card set {}, vault folder {vault})\n",
                    role(e.role),
                    render_recorded(&e.file),
                    records::hex(&e.set_id)
                ));
            }
        }
        msg.push_str("Compare the card set with pvault status for that vault, or run pvault init on the vault folder. Forgetting the records keeps every file.");
        ui.notice(&msg);
        let phrase = format!("FORGET {digital_files} CARD RECORDS");
        if ui.confirm(
            &format!("Type {phrase} to remove only the records: "),
            &phrase,
        )? {
            for (_, lock) in digital {
                settings.unregister_cards(&lock.id())?;
                lock.finish();
            }
        } else {
            confirmed = false;
        }
    }
    report.confirmed = confirmed;
    Ok(report)
}
