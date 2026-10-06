//! Per-user records in the settings folder (spec 7.4b, 7.9, 9.7; approved
//! for Milestone 4, A2; `docs/M4_READINESS.md` section 7).
//!
//! | Record | Policy |
//! | --- | --- |
//! | `partials.cbor`, `cards.cbor` | Tracking: an entry is *registered* only when the update's flush calls all reported success, on a settings folder that passes the 8.5 identification and preflight. No secret byte is written before that |
//! | `rollback.cbor` | Advisory: atomic replacement, best-effort durability |
//!
//! A successful flush establishes durability only as far as the device
//! honors the platform flush primitive, and on Windows only under the
//! unverified WO/W1 assumptions; it is not verified power-loss safety.
//!
//! The settings folder is checked to be private on every open. Inside it,
//! pvault manages its own fixed-name files by name, under the record lock;
//! that is the only place a name is enough.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::cbor::{CborError, Decoder, Encoder, key_order};
use crate::errors::Error;
use crate::platform::fs::{self, Dir, IdKind, RecordIdentity};

/// Overrides the settings folder (tests and unusual setups; not a secret).
pub const SETTINGS_ENV: &str = "PVAULT_CONFIG_DIR";

const R_WAIT: Duration = Duration::from_secs(2);

/// The settings folder.
#[derive(Debug)]
pub struct Settings {
    dir: Dir,
    path: PathBuf,
}

/// Opens (creating owner-only if needed) a directory component by component
/// below its deepest existing ancestor.
fn ensure_dir(path: &Path) -> Result<Dir, Error> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.is_dir() {
            return Err(Error::SettingsUnavailable(
                "the settings path is not a folder".into(),
            ));
        }
        return Dir::open(path).map_err(|e| Error::SettingsUnavailable(e.to_string()));
    }
    let mut missing = Vec::new();
    let mut base = path.to_path_buf();
    while std::fs::symlink_metadata(&base).is_err() {
        let name = base
            .file_name()
            .ok_or_else(|| Error::SettingsUnavailable("unusable settings path".into()))?
            .to_owned();
        missing.push(name);
        if !base.pop() {
            return Err(Error::SettingsUnavailable(
                "no existing parent folder".into(),
            ));
        }
    }
    let mut dir = Dir::open(&base).map_err(|e| Error::SettingsUnavailable(e.to_string()))?;
    for name in missing.iter().rev() {
        match dir.create_dir(name) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(Error::SettingsUnavailable(e.to_string())),
        }
        dir = dir
            .open_dir(name)
            .map_err(|e| Error::SettingsUnavailable(e.to_string()))?;
    }
    Ok(dir)
}

fn sub(parent: &Dir, path: &Path, name: &str) -> Result<Dir, Error> {
    match parent.create_dir(name) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(Error::SettingsUnavailable(e.to_string())),
    }
    let d = parent
        .open_dir(name)
        .map_err(|e| Error::SettingsUnavailable(e.to_string()))?;
    if !d
        .is_private()
        .map_err(|e| Error::SettingsUnavailable(e.to_string()))?
    {
        return Err(Error::SettingsNotPrivate(path.join(name)));
    }
    Ok(d)
}

impl Settings {
    /// The configured location: [`SETTINGS_ENV`], or `config_local_dir()`.
    pub fn default_path() -> Result<PathBuf, Error> {
        if let Some(p) = std::env::var_os(SETTINGS_ENV).filter(|p| !p.is_empty()) {
            return Ok(PathBuf::from(p));
        }
        directories::ProjectDirs::from("", "", "pvault")
            .map(|d| d.config_local_dir().to_path_buf())
            .ok_or_else(|| Error::SettingsUnavailable("no home folder".into()))
    }

    /// Opens the settings folder.
    pub fn open() -> Result<Self, Error> {
        Self::open_at(&Self::default_path()?)
    }

    /// Opens a settings folder at `path`, creating it owner-only if needed,
    /// and checks that it is private.
    pub fn open_at(path: &Path) -> Result<Self, Error> {
        let dir = ensure_dir(path)?;
        if !dir
            .is_private()
            .map_err(|e| Error::SettingsUnavailable(e.to_string()))?
        {
            return Err(Error::SettingsNotPrivate(path.to_path_buf()));
        }
        Ok(Self {
            dir,
            path: path.to_path_buf(),
        })
    }

    /// The folder's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The tracking-record storage policy (7.1): the 8.5 identification and
    /// preflight on the settings folder.
    pub fn check_registration(&self) -> Result<(), Error> {
        match fs::preflight(&self.dir) {
            Ok(_) => Ok(()),
            Err(Error::UnsupportedFileSystem(t)) => Err(Error::RegistrationUnsupported(t)),
            Err(e) => Err(e),
        }
    }

    fn record_lock(&self, name: &str, exclusive: bool) -> Result<File, Error> {
        let file = open_lock_file(&self.dir, name)?;
        let started = Instant::now();
        loop {
            let got = if exclusive {
                file.try_lock()
            } else {
                file.try_lock_shared()
            };
            match got {
                Ok(()) => return Ok(file),
                Err(std::fs::TryLockError::WouldBlock) if started.elapsed() < R_WAIT => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(Error::SettingsUnavailable("a record is busy".into()));
                }
                Err(std::fs::TryLockError::Error(e)) => return Err(Error::Io(e)),
            }
        }
    }

    fn read(&self, kind: RecordKind) -> Result<Option<Vec<u8>>, Error> {
        let Some(mut file) = self
            .dir
            .open_regular(kind.file(), false)
            .map_err(Error::Io)?
        else {
            return Ok(None);
        };
        let len = file.metadata().map_err(Error::Io)?.len();
        if len > kind.max_bytes() {
            return Err(Error::RecordDamaged(self.path.join(kind.file())));
        }
        let mut buf = Vec::new();
        (&mut file)
            .take(kind.max_bytes() + 1)
            .read_to_end(&mut buf)
            .map_err(Error::Io)?;
        Ok(Some(buf))
    }

    /// Steps 3 to 5 of 7.3. `Err(NotRegistered)` if a flush failed.
    fn write(&self, kind: RecordKind, bytes: &[u8]) -> Result<(), Error> {
        let tmp = kind.tmp();
        let mut file = match self.dir.open_regular(tmp, true).map_err(Error::Io)? {
            Some(f) => {
                f.set_len(0).map_err(Error::Io)?;
                f
            }
            None => self.dir.create_new(tmp).map_err(Error::Io)?,
        };
        file.write_all(bytes).map_err(Error::Io)?;
        fail_io!("records.flush-file")
            .and_then(|()| fs::flush_file(&file))
            .map_err(|_| Error::NotRegistered(kind.what()))?;
        drop(file);
        self.dir
            .rename_replace(tmp, kind.file())
            .map_err(Error::Io)?;
        failpoint!("records.renamed");
        fail_io!("records.flush-dir")
            .and_then(|()| self.dir.flush())
            .map_err(|_| Error::NotRegistered(kind.what()))
    }

    fn load<E: Entry>(&self, kind: RecordKind) -> Result<Vec<E>, Error> {
        match self.read(kind)? {
            None => Ok(Vec::new()),
            Some(bytes) => decode::<E>(kind, &bytes)
                .map_err(|_| Error::RecordDamaged(self.path.join(kind.file()))),
        }
    }

    fn modify<E: Entry>(
        &self,
        kind: RecordKind,
        change: impl FnOnce(&mut Vec<E>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let _r = self.record_lock(kind.lock(), true)?;
        let mut entries = self.load::<E>(kind)?;
        change(&mut entries)?;
        entries.sort_by_key(|a| a.sort_key());
        entries.dedup_by(|a, b| a.sort_key() == b.sort_key());
        if entries.len() > kind.max_entries() {
            return Err(Error::RecordFull(kind.full_name()));
        }
        let bytes = encode(kind, &entries);
        if bytes.len() as u64 > kind.max_bytes() {
            return Err(Error::RecordFull(kind.full_name()));
        }
        self.write(kind, &bytes)
    }

    // ---- rollback.cbor (advisory, 9.7) ----

    /// The rollback check and update after an ordinary unlock or a commit.
    pub fn rollback_observe(&self, vault_id: &[u8; 16], generation: u64) -> RollbackOutcome {
        let mut outcome = RollbackOutcome::Recorded;
        let result = self.modify::<RollbackEntry>(RecordKind::Rollback, |entries| {
            match entries.iter_mut().find(|e| &e.vault_id == vault_id) {
                Some(e) => {
                    if e.generation > generation {
                        outcome = RollbackOutcome::Older {
                            recorded: e.generation,
                        };
                    }
                    e.generation = e.generation.max(generation);
                }
                None => {
                    if entries.len() >= RecordKind::Rollback.max_entries() {
                        outcome = RollbackOutcome::Full;
                        return Err(Error::RecordFull("vaults"));
                    }
                    entries.push(RollbackEntry {
                        vault_id: *vault_id,
                        generation,
                    });
                }
            }
            Ok(())
        });
        match result {
            Ok(()) | Err(Error::NotRegistered(_)) => outcome,
            Err(Error::RecordFull(_)) => RollbackOutcome::Full,
            Err(Error::RecordDamaged(_)) => {
                RollbackOutcome::Unavailable("the record is damaged".into())
            }
            Err(e) => RollbackOutcome::Unavailable(e.to_string()),
        }
    }

    /// The recorded generation for a vault (for `status`); never updates.
    pub fn rollback_recorded(&self, vault_id: &[u8; 16]) -> Result<Option<u64>, Error> {
        let _r = self.record_lock(RecordKind::Rollback.lock(), false)?;
        Ok(self
            .load::<RollbackEntry>(RecordKind::Rollback)?
            .into_iter()
            .find(|e| &e.vault_id == vault_id)
            .map(|e| e.generation))
    }

    // ---- operation locks (T and C) ----

    /// Creates and exclusively locks `transfers/<id>.lock` or
    /// `cards/<id>.lock` for a new random operation ID.
    pub fn begin_operation(&self, kind: OpKind) -> Result<OpLock, Error> {
        let folder = sub(&self.dir, &self.path, kind.folder())?;
        let id = crate::crypto::random::array::<16>()?;
        let name = format!("{}.lock", hex(&id));
        let file = folder.create_new(&name).map_err(Error::Io)?;
        file.try_lock()
            .map_err(|_| Error::SettingsUnavailable("an operation lock is busy".into()))?;
        Ok(OpLock {
            folder,
            name,
            file,
            id,
        })
    }

    /// Tries to take the lock of a recorded operation without blocking.
    /// `Ok(None)`: the operation is alive (or its lock is busy).
    fn try_operation(&self, kind: OpKind, id: &[u8; 16]) -> Result<Option<OpLock>, Error> {
        let folder = sub(&self.dir, &self.path, kind.folder())?;
        let name = format!("{}.lock", hex(id));
        let file = match folder.open_regular(&name, true).map_err(Error::Io)? {
            Some(f) => f,
            None => folder.create_new(&name).map_err(Error::Io)?,
        };
        match file.try_lock() {
            Ok(()) => Ok(Some(OpLock {
                folder,
                name,
                file,
                id: *id,
            })),
            Err(_) => Ok(None),
        }
    }

    // ---- partials.cbor (tracking, 7.5) ----

    /// Registers an export entry (E3). The caller holds its transfer lock.
    pub fn register_partial(&self, entry: PartialEntry) -> Result<(), Error> {
        self.modify::<PartialEntry>(RecordKind::Partials, |entries| {
            entries.push(entry);
            Ok(())
        })
    }

    /// Refuses before E2 when the export record has no room (7.5).
    pub fn check_partial_room(&self) -> Result<(), Error> {
        let _r = self.record_lock(RecordKind::Partials.lock(), false)?;
        if self.load::<PartialEntry>(RecordKind::Partials)?.len()
            >= RecordKind::Partials.max_entries()
        {
            return Err(Error::RecordFull(RecordKind::Partials.full_name()));
        }
        Ok(())
    }

    /// Refuses before W1 when the card record has no room for `n` entries.
    pub fn check_card_room(&self, n: usize) -> Result<(), Error> {
        let _r = self.record_lock(RecordKind::Cards.lock(), false)?;
        if self.load::<CardEntry>(RecordKind::Cards)?.len() + n > RecordKind::Cards.max_entries() {
            return Err(Error::RecordFull(RecordKind::Cards.full_name()));
        }
        Ok(())
    }

    /// Removes an export entry (E6).
    pub fn unregister_partial(&self, transfer_id: &[u8; 16]) -> Result<(), Error> {
        self.modify::<PartialEntry>(RecordKind::Partials, |entries| {
            entries.retain(|e| &e.transfer_id != transfer_id);
            Ok(())
        })
    }

    /// Stale export entries (their transfer lock can be taken), optionally
    /// for one vault, each with its transfer lock held.
    pub fn stale_partials(
        &self,
        vault: Option<&[u8; 16]>,
    ) -> Result<Vec<(PartialEntry, OpLock)>, Error> {
        let snapshot = {
            let _r = self.record_lock(RecordKind::Partials.lock(), false)?;
            self.load::<PartialEntry>(RecordKind::Partials)?
        };
        let mut out = Vec::new();
        for e in snapshot {
            if vault.is_some_and(|v| v != &e.vault_id) {
                continue;
            }
            if let Some(lock) = self.try_operation(OpKind::Transfer, &e.transfer_id)? {
                // Re-read under R: the entry may have vanished meanwhile.
                let still = {
                    let _r = self.record_lock(RecordKind::Partials.lock(), false)?;
                    self.load::<PartialEntry>(RecordKind::Partials)?
                        .into_iter()
                        .find(|x| x.transfer_id == e.transfer_id)
                };
                if let Some(e) = still {
                    out.push((e, lock));
                } else {
                    lock.finish();
                }
            }
        }
        Ok(out)
    }

    // ---- cards.cbor (tracking, section 11) ----

    /// Registers card entries in one update (W3).
    pub fn register_cards(&self, entries: Vec<CardEntry>) -> Result<(), Error> {
        self.modify::<CardEntry>(RecordKind::Cards, |all| {
            all.extend(entries);
            Ok(())
        })
    }

    /// Removes an operation's card entries (W8).
    pub fn unregister_cards(&self, op_id: &[u8; 16]) -> Result<(), Error> {
        self.modify::<CardEntry>(RecordKind::Cards, |all| {
            all.retain(|e| &e.op_id != op_id);
            Ok(())
        })
    }

    /// Removes one card entry.
    pub fn unregister_card(&self, op_id: &[u8; 16], role: CardRole) -> Result<(), Error> {
        self.modify::<CardEntry>(RecordKind::Cards, |all| {
            all.retain(|e| !(&e.op_id == op_id && e.role == role));
            Ok(())
        })
    }

    /// Removes one export entry after cleanup (same as unregister).
    pub fn drop_partial(&self, transfer_id: &[u8; 16]) -> Result<(), Error> {
        self.unregister_partial(transfer_id)
    }

    /// Stale card operations (their lock can be taken), optionally for one
    /// vault, each with its operation lock held and its entries.
    pub fn stale_cards(
        &self,
        vault: Option<&[u8; 16]>,
    ) -> Result<Vec<(Vec<CardEntry>, OpLock)>, Error> {
        let snapshot = {
            let _r = self.record_lock(RecordKind::Cards.lock(), false)?;
            self.load::<CardEntry>(RecordKind::Cards)?
        };
        let mut ops: Vec<[u8; 16]> = snapshot.iter().map(|e| e.op_id).collect();
        ops.dedup();
        let mut out = Vec::new();
        for op in ops {
            if let Some(lock) = self.try_operation(OpKind::Cards, &op)? {
                let entries: Vec<CardEntry> = {
                    let _r = self.record_lock(RecordKind::Cards.lock(), false)?;
                    self.load::<CardEntry>(RecordKind::Cards)?
                        .into_iter()
                        .filter(|e| e.op_id == op && vault.is_none_or(|v| v == &e.vault_id))
                        .collect()
                };
                if entries.is_empty() {
                    lock.finish();
                } else {
                    out.push((entries, lock));
                }
            }
        }
        Ok(out)
    }

    /// Whether any record is damaged (for `clean-partials` reporting).
    pub fn check_records(&self) -> Vec<Error> {
        let mut out = Vec::new();
        if let Err(e) = self.load::<PartialEntry>(RecordKind::Partials) {
            out.push(e);
        }
        if let Err(e) = self.load::<CardEntry>(RecordKind::Cards) {
            out.push(e);
        }
        out
    }
}

fn open_lock_file(dir: &Dir, name: &str) -> Result<File, Error> {
    let file = match dir.open_regular(name, true).map_err(Error::Io)? {
        Some(f) => f,
        None => match dir.create_new(name) {
            Ok(f) => f,
            Err(_) => dir
                .open_regular(name, true)
                .map_err(Error::Io)?
                .ok_or_else(|| Error::SettingsUnavailable("lock file".into()))?,
        },
    };
    if file.metadata().map_err(Error::Io)?.len() != 0 {
        return Err(Error::SettingsUnavailable(
            "a lock file is not empty".into(),
        ));
    }
    Ok(file)
}

/// Rollback check result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackOutcome {
    /// Recorded; no warning.
    Recorded,
    /// This vault is older than a copy seen before.
    Older {
        /// The recorded generation.
        recorded: u64,
    },
    /// The record is full; this vault is not tracked.
    Full,
    /// Rollback detection is unavailable.
    Unavailable(String),
}

/// Operation lock kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
    /// `transfers/<id>.lock` (T).
    Transfer,
    /// `cards/<id>.lock` (C).
    Cards,
}

impl OpKind {
    fn folder(self) -> &'static str {
        match self {
            Self::Transfer => "transfers",
            Self::Cards => "cards",
        }
    }
}

/// A held operation lock (T or C).
#[derive(Debug)]
pub struct OpLock {
    folder: Dir,
    name: String,
    file: File,
    id: [u8; 16],
}

impl OpLock {
    /// The operation ID.
    pub fn id(&self) -> [u8; 16] {
        self.id
    }

    /// Releases the lock and deletes its file (after the operation's
    /// entries are removed). The settings folder is private (7.1).
    pub fn finish(self) {
        let _ = self.file.unlock();
        drop(self.file);
        let _ = self.folder.unlink(&self.name);
    }
}

// ---- schemas ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordKind {
    Rollback,
    Partials,
    Cards,
}

impl RecordKind {
    fn file(self) -> &'static str {
        match self {
            Self::Rollback => "rollback.cbor",
            Self::Partials => "partials.cbor",
            Self::Cards => "cards.cbor",
        }
    }
    fn tmp(self) -> &'static str {
        match self {
            Self::Rollback => "rollback.cbor.tmp",
            Self::Partials => "partials.cbor.tmp",
            Self::Cards => "cards.cbor.tmp",
        }
    }
    fn lock(self) -> &'static str {
        match self {
            Self::Rollback => "rollback.lock",
            Self::Partials => "partials.lock",
            Self::Cards => "cards.lock",
        }
    }
    fn kind(self) -> &'static str {
        match self {
            Self::Rollback => "pvault-rollback",
            Self::Partials => "pvault-partials",
            Self::Cards => "pvault-cards",
        }
    }
    fn max_entries(self) -> usize {
        match self {
            Self::Rollback => 4096,
            Self::Partials | Self::Cards => 256,
        }
    }
    fn max_bytes(self) -> u64 {
        match self {
            Self::Rollback => 256 << 10,
            Self::Partials | Self::Cards => 2 << 20,
        }
    }
    fn what(self) -> &'static str {
        match self {
            Self::Rollback => "rollback record",
            Self::Partials => "export",
            Self::Cards => "card files",
        }
    }
    fn full_name(self) -> &'static str {
        match self {
            Self::Rollback => "vaults",
            Self::Partials => "exports",
            Self::Cards => "card files",
        }
    }
}

#[derive(Clone)]
enum V {
    U(u64),
    B(Vec<u8>),
    T(&'static str),
}

trait Entry: Sized {
    const KEYS: &'static [&'static str];
    fn fields(&self) -> Vec<(&'static str, V)>;
    fn decode(d: &mut Decoder<'_>) -> Result<Self, CborError>;
    fn sort_key(&self) -> Vec<u8>;
}

fn encode<E: Entry>(kind: RecordKind, entries: &[E]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    let _ = (|| -> Result<(), CborError> {
        e.map(3)?;
        e.key("kind")?;
        e.text(kind.kind())?;
        e.key("entries")?;
        e.array(entries.len())?;
        for entry in entries {
            let mut f = entry.fields();
            f.sort_by(|a, b| key_order(a.0, b.0));
            e.map(f.len())?;
            for (k, v) in &f {
                e.key(k)?;
                match v {
                    V::U(u) => e.uint(*u)?,
                    V::B(b) => e.bytes(b)?,
                    V::T(t) => e.text(t)?,
                }
            }
        }
        e.key("version")?;
        e.uint(1)
    })();
    e.into_sink()
}

fn decode<E: Entry>(kind: RecordKind, bytes: &[u8]) -> Result<Vec<E>, CborError> {
    let mut entries = Vec::new();
    let mut ok_kind = false;
    let mut version = 0;
    let mut d = Decoder::new(bytes);
    d.map(&["kind", "entries", "version"], 0b111, |d, k| {
        match k {
            0 => ok_kind = d.text()? == kind.kind(),
            1 => {
                d.array(kind.max_entries(), |d, _| {
                    entries.push(E::decode(d)?);
                    Ok(())
                })?;
            }
            _ => version = d.uint()?,
        }
        Ok(())
    })?;
    d.finish()?;
    if !ok_kind || version != 1 {
        return Err(CborError);
    }
    if entries
        .windows(2)
        .any(|w| w[0].sort_key() >= w[1].sort_key())
    {
        return Err(CborError);
    }
    // Exactly canonical: re-encoding reproduces the input.
    if encode(kind, &entries) != bytes {
        return Err(CborError);
    }
    Ok(entries)
}

/// One rollback entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackEntry {
    /// The vault.
    pub vault_id: [u8; 16],
    /// Highest generation seen.
    pub generation: u64,
}

impl Entry for RollbackEntry {
    const KEYS: &'static [&'static str] = &["vault_id", "generation"];
    fn fields(&self) -> Vec<(&'static str, V)> {
        vec![
            ("vault_id", V::B(self.vault_id.to_vec())),
            ("generation", V::U(self.generation)),
        ]
    }
    fn decode(d: &mut Decoder<'_>) -> Result<Self, CborError> {
        let (mut v, mut g) = (None, None);
        d.map(Self::KEYS, 0b11, |d, k| {
            match k {
                0 => v = Some(*d.bytes_exact::<16>()?),
                _ => g = Some(d.uint()?),
            }
            Ok(())
        })?;
        Ok(Self {
            vault_id: v.ok_or(CborError)?,
            generation: g.ok_or(CborError)?,
        })
    }
    fn sort_key(&self) -> Vec<u8> {
        self.vault_id.to_vec()
    }
}

/// A recorded file outside the vault: native path bytes and identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedFile {
    /// Native path bytes (Unix bytes; Windows UTF-16LE).
    pub path: Vec<u8>,
    /// Identity captured after exclusive creation.
    pub id: RecordIdentity,
}

/// Native encoding of an absolute path (7.2). `None`: too long to record.
pub fn native_path(path: &Path) -> Option<Vec<u8>> {
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    };
    #[cfg(windows)]
    let bytes = {
        use std::os::windows::ffi::OsStrExt;
        path.as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<u8>>()
    };
    (!bytes.is_empty() && bytes.len() <= 4096).then_some(bytes)
}

/// The path back from its native encoding.
pub fn path_from_native(bytes: &[u8]) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        PathBuf::from(std::ffi::OsString::from_wide(&units))
    }
}

fn id_fields(f: &RecordedFile, out: &mut Vec<(&'static str, V)>) {
    out.push(("path", V::B(f.path.clone())));
    out.push(("dev", V::U(f.id.dev)));
    out.push(("ino", V::B(f.id.ino.clone())));
    if let Some(b) = &f.id.btime {
        out.push(("btime", V::B(b.clone())));
    }
    out.push((
        "id_kind",
        V::T(match f.id.kind {
            IdKind::Unix => "unix",
            IdKind::Windows => "windows",
        }),
    ));
}

#[derive(Default)]
struct IdRaw<'a> {
    path: Option<&'a [u8]>,
    dev: Option<u64>,
    ino: Option<&'a [u8]>,
    btime: Option<&'a [u8]>,
    kind: Option<&'a str>,
}

impl IdRaw<'_> {
    fn build(self) -> Result<RecordedFile, CborError> {
        let kind = match self.kind.ok_or(CborError)? {
            "unix" => IdKind::Unix,
            "windows" => IdKind::Windows,
            _ => return Err(CborError),
        };
        let path = self.path.ok_or(CborError)?;
        let ino = self.ino.ok_or(CborError)?;
        let (ino_len, btime_len) = match kind {
            IdKind::Unix => (8, 12),
            IdKind::Windows => (16, 8),
        };
        if path.is_empty()
            || ino.len() != ino_len
            || self.btime.is_some_and(|b| b.len() != btime_len)
        {
            return Err(CborError);
        }
        if kind == IdKind::Windows && path.len() % 2 != 0 {
            return Err(CborError);
        }
        Ok(RecordedFile {
            path: path.to_vec(),
            id: RecordIdentity {
                kind,
                dev: self.dev.ok_or(CborError)?,
                ino: ino.to_vec(),
                btime: self.btime.map(<[u8]>::to_vec),
            },
        })
    }
}

/// One export entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialEntry {
    /// The export's transfer ID.
    pub transfer_id: [u8; 16],
    /// The vault exported from.
    pub vault_id: [u8; 16],
    /// Unix seconds.
    pub created_at: u64,
    /// The `.pvpartial` file.
    pub file: RecordedFile,
}

impl Entry for PartialEntry {
    const KEYS: &'static [&'static str] = &[
        "dev",
        "ino",
        "path",
        "btime",
        "id_kind",
        "vault_id",
        "created_at",
        "transfer_id",
    ];
    fn fields(&self) -> Vec<(&'static str, V)> {
        let mut f = Vec::new();
        id_fields(&self.file, &mut f);
        f.push(("vault_id", V::B(self.vault_id.to_vec())));
        f.push(("created_at", V::U(self.created_at)));
        f.push(("transfer_id", V::B(self.transfer_id.to_vec())));
        f
    }
    fn decode(d: &mut Decoder<'_>) -> Result<Self, CborError> {
        let mut id = IdRaw::default();
        let (mut vault, mut created, mut transfer) = (None, None, None);
        d.map(Self::KEYS, 0b1111_0111, |d, k| {
            match Self::KEYS[k] {
                "dev" => id.dev = Some(d.uint()?),
                "ino" => id.ino = Some(d.bytes_max(16)?),
                "path" => id.path = Some(d.bytes_max(4096)?),
                "btime" => id.btime = Some(d.bytes_max(12)?),
                "id_kind" => id.kind = Some(d.text()?),
                "vault_id" => vault = Some(*d.bytes_exact::<16>()?),
                "created_at" => created = Some(d.uint()?),
                _ => transfer = Some(*d.bytes_exact::<16>()?),
            }
            Ok(())
        })?;
        Ok(Self {
            transfer_id: transfer.ok_or(CborError)?,
            vault_id: vault.ok_or(CborError)?,
            created_at: created.ok_or(CborError)?,
            file: id.build()?,
        })
    }
    fn sort_key(&self) -> Vec<u8> {
        self.transfer_id.to_vec()
    }
}

/// Card roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CardRole {
    /// Portable Card A.
    CardA,
    /// Portable Card B.
    CardB,
    /// The bound card (reserved for Milestone 5).
    Bound,
}

impl CardRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::CardA => "card-a",
            Self::CardB => "card-b",
            Self::Bound => "bound",
        }
    }
}

/// One card-file entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardEntry {
    /// The writing operation.
    pub op_id: [u8; 16],
    /// The card's role.
    pub role: CardRole,
    /// The card set.
    pub set_id: [u8; 8],
    /// The vault.
    pub vault_id: [u8; 16],
    /// Unix seconds.
    pub created_at: u64,
    /// The card file.
    pub file: RecordedFile,
}

impl Entry for CardEntry {
    const KEYS: &'static [&'static str] = &[
        "dev",
        "ino",
        "path",
        "role",
        "btime",
        "op_id",
        "set_id",
        "id_kind",
        "vault_id",
        "created_at",
    ];
    fn fields(&self) -> Vec<(&'static str, V)> {
        let mut f = Vec::new();
        id_fields(&self.file, &mut f);
        f.push(("role", V::T(self.role.as_str())));
        f.push(("op_id", V::B(self.op_id.to_vec())));
        f.push(("set_id", V::B(self.set_id.to_vec())));
        f.push(("vault_id", V::B(self.vault_id.to_vec())));
        f.push(("created_at", V::U(self.created_at)));
        f
    }
    fn decode(d: &mut Decoder<'_>) -> Result<Self, CborError> {
        let mut id = IdRaw::default();
        let (mut role, mut op, mut set, mut vault, mut created) = (None, None, None, None, None);
        d.map(Self::KEYS, 0b11_1110_1111, |d, k| {
            match Self::KEYS[k] {
                "dev" => id.dev = Some(d.uint()?),
                "ino" => id.ino = Some(d.bytes_max(16)?),
                "path" => id.path = Some(d.bytes_max(4096)?),
                "role" => {
                    role = Some(match d.text()? {
                        "card-a" => CardRole::CardA,
                        "card-b" => CardRole::CardB,
                        "bound" => CardRole::Bound,
                        _ => return Err(CborError),
                    })
                }
                "btime" => id.btime = Some(d.bytes_max(12)?),
                "op_id" => op = Some(*d.bytes_exact::<16>()?),
                "set_id" => set = Some(*d.bytes_exact::<8>()?),
                "id_kind" => id.kind = Some(d.text()?),
                "vault_id" => vault = Some(*d.bytes_exact::<16>()?),
                _ => created = Some(d.uint()?),
            }
            Ok(())
        })?;
        Ok(Self {
            op_id: op.ok_or(CborError)?,
            role: role.ok_or(CborError)?,
            set_id: set.ok_or(CborError)?,
            vault_id: vault.ok_or(CborError)?,
            created_at: created.ok_or(CborError)?,
            file: id.build()?,
        })
    }
    fn sort_key(&self) -> Vec<u8> {
        let mut k = self.op_id.to_vec();
        k.push(self.role as u8);
        k
    }
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// After-restart cleanup of a recorded file (7.2): deletes only if a birth
/// time was recorded and the identity still matches on a no-follow reopen of
/// a regular file. Returns what happened.
pub fn delete_recorded(file: &RecordedFile) -> Result<StaleOutcome, Error> {
    if file.id.btime.is_none() {
        return Ok(StaleOutcome::Unprovable);
    }
    let path = path_from_native(&file.path);
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Ok(StaleOutcome::Unprovable);
    };
    let dir = match Dir::open(parent) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(StaleOutcome::Missing),
        Err(_) => return Ok(StaleOutcome::Unprovable),
    };
    let opened = match dir.open_regular(name, false) {
        Ok(Some(f)) => f,
        Ok(None) => return Ok(StaleOutcome::Missing),
        Err(_) => return Ok(StaleOutcome::Mismatch),
    };
    match fs::record_identity(&opened) {
        Ok(id) if id == file.id => {}
        _ => return Ok(StaleOutcome::Mismatch),
    }
    if dir.delete_held(name, &opened).map_err(Error::Io)? {
        dir.flush().map_err(Error::Io)?;
        Ok(StaleOutcome::Deleted)
    } else {
        Ok(StaleOutcome::Mismatch)
    }
}

/// What [`delete_recorded`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleOutcome {
    /// Deleted (identity and birth time matched).
    Deleted,
    /// Nothing at the recorded path.
    Missing,
    /// Something else is there; nothing deleted.
    Mismatch,
    /// No birth time was recorded, or the path cannot be checked; nothing
    /// deleted (identity stability cannot be established).
    Unprovable,
}

#[cfg(test)]
mod tests;
