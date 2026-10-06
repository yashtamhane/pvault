//! The key table, `keytable.<gen>.pv` (spec 7.8; D3, D7, N5).
//!
//! **Plaintext:** a deterministic-CBOR array of at most 65,536 entries,
//! sorted by path (bytewise):
//!
//! ```text
//! file: { kind: "file", path, size, fk_aes(32), file_id(16), fk_chacha(32),
//!         created_at, modified_at }
//! dir:  { kind: "dir",  path, created_at, modified_at }
//! ```
//!
//! **Decoding** (D3) has two passes:
//! - **Pass 1** validates the whole structure and every decode-time path rule
//!   while borrowing from the plaintext. It allocates nothing, and computes
//!   the entry count `N`, the file count `F` and the path bytes `P`. The v1
//!   validity rules are `N ≤ 65,536` and
//!   `decoded_charge = 4096 + 128·N + 64·F + P ≤ 128 MiB`.
//! - **Pass 2** allocates three exact-capacity arenas, once each and
//!   fallibly: entry descriptors, a zeroizing path arena and a best-effort
//!   locked key arena. It fills them, then checks that every parent is a
//!   `dir` entry.
//!
//! Every decode failure is the payload-free [`Error::KeyTableCorrupt`]
//! ("The key table is damaged.").
//!
//! **Paths are confidential** (D3): zeroized, but not separately locked.

use std::io::{Read, Seek, SeekFrom, Write};

use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::cbor::{CborError, Counter, Decoder, Encoder, Sink, SliceSink};
use crate::crypto::cascade::{self, Expected, StreamHeader, StreamKeys, StreamKind};
use crate::errors::Error;
use crate::paths;
use crate::resources::{self, MemoryProbe};
use crate::secrets::{LockedBuf, SecretBuf, SecretBytes};

/// Most entries (files and directories together) in a v1 key table (N5).
pub const MAX_ENTRIES: usize = 65_536;
/// Largest key-table plaintext (7.8).
pub const MAX_PLAINTEXT: u64 = 64 << 20;
/// Largest decoded charge (D3), a v1 validity rule.
pub const MAX_DECODED_CHARGE: u64 = 134_217_728;
/// Fixed charge for the stream decryptor's scratch and parser stack (D3).
pub const STREAM_CHARGE: u64 = 131_072;
/// The refusal shown when an operation would exceed [`MAX_ENTRIES`] (N5).
pub const LIMIT_MESSAGE: &str = "This vault can hold at most 65,536 files and folders.";

/// The smallest possible encoded entry (a directory with a one-byte path),
/// used to bound `N` from the plaintext length before decoding.
const MIN_ENTRY_BYTES: u64 = 40;

const ENTRY_KEYS: &[&str] = &[
    "kind",
    "path",
    "size",
    "fk_aes",
    "file_id",
    "fk_chacha",
    "created_at",
    "modified_at",
];
const FILE_MASK: u64 = 0xff;
const DIR_MASK: u64 = 0b1100_0011;

/// File or directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A file, with an object and two keys.
    File,
    /// A directory.
    Dir,
}

/// Compact descriptor, at most 128 bytes (the per-entry charge of D3).
#[derive(Debug, Clone, Copy, Default)]
struct Desc {
    is_file: bool,
    path_off: u32,
    path_len: u32,
    key_off: u32,
    file_id: [u8; 16],
    size: u64,
    created_at: u64,
    modified_at: u64,
}

const _: () = assert!(core::mem::size_of::<Desc>() <= 128);

impl Zeroize for Desc {
    fn zeroize(&mut self) {
        self.is_file.zeroize();
        self.path_off.zeroize();
        self.path_len.zeroize();
        self.key_off.zeroize();
        self.file_id.zeroize();
        self.size.zeroize();
        self.created_at.zeroize();
        self.modified_at.zeroize();
    }
}

/// One entry, borrowed from a [`KeyTable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry<'a> {
    /// File or directory.
    pub kind: EntryKind,
    /// The vault path.
    pub path: &'a str,
    /// The object ID (files only).
    pub file_id: Option<[u8; 16]>,
    /// Plaintext size (files only; 0 for directories).
    pub size: u64,
    /// Creation time, unix seconds.
    pub created_at: u64,
    /// Modification time, unix seconds.
    pub modified_at: u64,
}

/// A decoded key table, in exact-capacity arenas.
pub struct KeyTable {
    descs: Zeroizing<Vec<Desc>>,
    paths: SecretBuf,
    keys: LockedBuf,
}

impl core::fmt::Debug for KeyTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "KeyTable({} entries, [REDACTED])", self.descs.len())
    }
}

/// An entry to put into a new key table (for `add`, conversion and tests).
#[derive(Debug)]
pub struct NewEntry {
    /// File or directory.
    pub kind: EntryKind,
    /// The vault path. Input-time rules (NFC, case-fold collisions) are the
    /// caller's job (Milestone 4); decode-time rules are checked here.
    pub path: Zeroizing<String>,
    /// Object ID (files).
    pub file_id: [u8; 16],
    /// Size (files).
    pub size: u64,
    /// Creation time.
    pub created_at: u64,
    /// Modification time.
    pub modified_at: u64,
    /// `fk_aes`, `fk_chacha` (files).
    pub keys: Option<(SecretBytes<32>, SecretBytes<32>)>,
}

/// Pass-1 statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Counts {
    entries: usize,
    files: usize,
    path_bytes: usize,
}

impl Counts {
    fn decoded_charge(&self) -> u64 {
        4096 + 128 * self.entries as u64 + 64 * self.files as u64 + self.path_bytes as u64
    }
}

/// Upper bound of the whole parser working set for a plaintext of `c`
/// bytes, checked before the plaintext buffer is allocated (D3).
pub fn working_charge_bound(c: u64) -> u64 {
    let n = (MAX_ENTRIES as u64).min(c / MIN_ENTRY_BYTES + 1);
    let decoded = (4096 + 192 * n + c).min(MAX_DECODED_CHARGE);
    c + decoded + STREAM_CHARGE
}

/// The parts of one encoded entry, borrowed from the plaintext.
struct Raw<'a> {
    is_file: bool,
    path: &'a str,
    size: u64,
    file_id: [u8; 16],
    fk_aes: &'a [u8; 32],
    fk_chacha: &'a [u8; 32],
    created_at: u64,
    modified_at: u64,
}

const ZERO_KEY: [u8; 32] = [0; 32];

fn decode_entry<'a>(d: &mut Decoder<'a>) -> Result<Raw<'a>, CborError> {
    let mut kind = None;
    let mut raw = Raw {
        is_file: false,
        path: "",
        size: 0,
        file_id: [0; 16],
        fk_aes: &ZERO_KEY,
        fk_chacha: &ZERO_KEY,
        created_at: 0,
        modified_at: 0,
    };
    let present = d.map(ENTRY_KEYS, DIR_MASK, |d, k| {
        match k {
            0 => {
                kind = Some(match d.text()? {
                    "file" => true,
                    "dir" => false,
                    _ => return Err(CborError),
                })
            }
            1 => raw.path = d.text()?,
            2 => raw.size = d.uint()?,
            3 => raw.fk_aes = d.bytes_exact()?,
            4 => raw.file_id = *d.bytes_exact()?,
            5 => raw.fk_chacha = d.bytes_exact()?,
            6 => raw.created_at = d.uint()?,
            _ => raw.modified_at = d.uint()?,
        }
        Ok(())
    })?;
    raw.is_file = kind.ok_or(CborError)?;
    let expected = if raw.is_file { FILE_MASK } else { DIR_MASK };
    if present != expected || !paths::is_valid_decoded(raw.path) {
        return Err(CborError);
    }
    Ok(raw)
}

/// Pass 1: structure, order and per-entry rules; allocates nothing.
fn pass1(plaintext: &[u8]) -> Result<Counts, CborError> {
    let mut counts = Counts {
        entries: 0,
        files: 0,
        path_bytes: 0,
    };
    let mut d = Decoder::new(plaintext);
    let mut prev: Option<&str> = None;
    counts.entries = d.array(MAX_ENTRIES, |d, _| {
        let e = decode_entry(d)?;
        if prev.is_some_and(|p| p.as_bytes() >= e.path.as_bytes()) {
            return Err(CborError); // unsorted or duplicate
        }
        prev = Some(e.path);
        counts.files += usize::from(e.is_file);
        counts.path_bytes = counts
            .path_bytes
            .checked_add(e.path.len())
            .ok_or(CborError)?;
        Ok(())
    })?;
    d.finish()?;
    if counts.decoded_charge() > MAX_DECODED_CHARGE {
        return Err(CborError);
    }
    Ok(counts)
}

fn try_vec<T: Default + Clone>(n: usize) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::MemoryResource {
        needed_mib: ((n * core::mem::size_of::<T>()) as u64).div_ceil(1 << 20),
    })?;
    Ok(v)
}

impl KeyTable {
    /// Decodes an authenticated plaintext (D3). A structural failure is
    /// [`Error::KeyTableCorrupt`]; an allocation failure is the resource
    /// error.
    pub fn decode(plaintext: &[u8]) -> Result<Self, Error> {
        let counts = pass1(plaintext).map_err(|_| Error::KeyTableCorrupt)?;
        let mut descs = Zeroizing::new(try_vec::<Desc>(counts.entries)?);
        let mut paths = SecretBuf::try_zeroed(counts.path_bytes)?;
        let mut keys = LockedBuf::try_zeroed(64 * counts.files)?;

        let mut d = Decoder::new(plaintext);
        let (mut p_at, mut k_at) = (0usize, 0usize);
        d.array(MAX_ENTRIES, |d, _| {
            let e = decode_entry(d)?;
            let pb = e.path.as_bytes();
            paths.expose_secret_mut()[p_at..p_at + pb.len()].copy_from_slice(pb);
            let mut desc = Desc {
                is_file: e.is_file,
                path_off: p_at as u32,
                path_len: pb.len() as u32,
                key_off: k_at as u32,
                file_id: e.file_id,
                size: e.size,
                created_at: e.created_at,
                modified_at: e.modified_at,
            };
            p_at += pb.len();
            if e.is_file {
                let k = keys.expose_secret_mut();
                k[k_at..k_at + 32].copy_from_slice(e.fk_aes);
                k[k_at + 32..k_at + 64].copy_from_slice(e.fk_chacha);
                k_at += 64;
            } else {
                desc.key_off = 0;
            }
            descs.push(desc);
            Ok(())
        })
        .map_err(|_| Error::KeyTableCorrupt)?;
        d.finish().map_err(|_| Error::KeyTableCorrupt)?;

        let table = Self { descs, paths, keys };
        table.check_parents()?;
        Ok(table)
    }

    fn check_parents(&self) -> Result<(), Error> {
        for i in 0..self.descs.len() {
            if let Some(parent) = paths::parent(self.path(i)) {
                match self.find(parent) {
                    Some(j) if !self.descs[j].is_file => {}
                    _ => return Err(Error::KeyTableCorrupt),
                }
            }
        }
        Ok(())
    }

    fn path(&self, i: usize) -> &str {
        let d = &self.descs[i];
        let bytes = &self.paths.expose_secret()
            [d.path_off as usize..d.path_off as usize + d.path_len as usize];
        // Validated UTF-8 in pass 1; an empty string cannot occur.
        core::str::from_utf8(bytes).unwrap_or("")
    }

    /// Copies every entry, keys included, as the input of a successor
    /// table (`add`, `rm`). The copies are zeroized when dropped.
    pub(crate) fn to_new_entries(&self) -> Result<Vec<NewEntry>, Error> {
        let mut out = Vec::with_capacity(self.len());
        for i in 0..self.len() {
            let e = self.entry(i).ok_or(Error::KeyTableCorrupt)?;
            let keys = match self.file_keys(i) {
                Some((a, c)) => Some((
                    SecretBytes::take_from(&mut a.to_vec())?,
                    SecretBytes::take_from(&mut c.to_vec())?,
                )),
                None => None,
            };
            out.push(NewEntry {
                kind: e.kind,
                path: Zeroizing::new(e.path.to_owned()),
                file_id: e.file_id.unwrap_or([0; 16]),
                size: e.size,
                created_at: e.created_at,
                modified_at: e.modified_at,
                keys,
            });
        }
        Ok(out)
    }

    /// The stream keys of file entry `i`.
    pub(crate) fn stream_keys(&self, i: usize) -> Result<Option<StreamKeys>, Error> {
        match self.file_keys(i) {
            Some((a, c)) => Ok(Some(StreamKeys::new(
                SecretBytes::take_from(&mut a.to_vec())?,
                SecretBytes::take_from(&mut c.to_vec())?,
            ))),
            None => Ok(None),
        }
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.descs.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.descs.is_empty()
    }

    /// Whether the key arena is locked in RAM (best effort, 10.2).
    pub fn keys_locked(&self) -> bool {
        self.keys.is_locked()
    }

    /// The entry at index `i` (sorted order).
    pub fn entry(&self, i: usize) -> Option<Entry<'_>> {
        let d = self.descs.get(i)?;
        Some(Entry {
            kind: if d.is_file {
                EntryKind::File
            } else {
                EntryKind::Dir
            },
            path: self.path(i),
            file_id: d.is_file.then_some(d.file_id),
            size: d.size,
            created_at: d.created_at,
            modified_at: d.modified_at,
        })
    }

    /// Index of `path`, by binary search.
    pub fn find(&self, path: &str) -> Option<usize> {
        let mut lo = 0;
        let mut hi = self.descs.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            match self.path(mid).as_bytes().cmp(path.as_bytes()) {
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
                core::cmp::Ordering::Equal => return Some(mid),
            }
        }
        None
    }

    /// `fk_aes` and `fk_chacha` of a file entry. Crate-private (10.1).
    pub(crate) fn file_keys(&self, i: usize) -> Option<(&[u8], &[u8])> {
        let d = self.descs.get(i)?;
        if !d.is_file {
            return None;
        }
        let k = &self.keys.expose_secret()[d.key_off as usize..d.key_off as usize + 64];
        Some((&k[..32], &k[32..]))
    }

    /// Builds a table from entries, enforcing N5 and the decode-time rules.
    /// Exceeding [`MAX_ENTRIES`] is refused before anything is encoded.
    pub fn from_entries(mut entries: Vec<NewEntry>) -> Result<Self, Error> {
        if entries.len() > MAX_ENTRIES {
            return Err(Error::Capacity(LIMIT_MESSAGE));
        }
        entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
        let mut c = Encoder::new(Counter::default());
        write_new(&mut c, &entries).map_err(|_| Error::KeyTableCorrupt)?;
        let len = c.into_sink().0;
        if len as u64 > MAX_PLAINTEXT {
            return Err(Error::Capacity("The key table would exceed 64 MiB."));
        }
        let mut plain = SecretBuf::try_zeroed(len)?;
        let mut e = Encoder::new(SliceSink::new(plain.expose_secret_mut()));
        write_new(&mut e, &entries).map_err(|_| Error::KeyTableCorrupt)?;
        Self::decode(plain.expose_secret())
    }

    /// Encodes the table canonically into an exact, zeroizing buffer.
    pub fn encode(&self) -> Result<SecretBuf, Error> {
        let mut c = Encoder::new(Counter::default());
        self.write(&mut c).map_err(|_| Error::KeyTableCorrupt)?;
        let len = c.into_sink().0;
        if len as u64 > MAX_PLAINTEXT {
            return Err(Error::Capacity("The key table would exceed 64 MiB."));
        }
        let mut plain = SecretBuf::try_zeroed(len)?;
        let mut e = Encoder::new(SliceSink::new(plain.expose_secret_mut()));
        self.write(&mut e).map_err(|_| Error::KeyTableCorrupt)?;
        Ok(plain)
    }

    fn write<S: Sink>(&self, e: &mut Encoder<S>) -> Result<(), CborError> {
        e.array(self.descs.len())?;
        for i in 0..self.descs.len() {
            let d = &self.descs[i];
            let keys = self.file_keys(i);
            write_entry(
                e,
                d.is_file,
                self.path(i),
                d.size,
                &d.file_id,
                keys,
                d.created_at,
                d.modified_at,
            )?;
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn write_entry<S: Sink>(
    e: &mut Encoder<S>,
    is_file: bool,
    path: &str,
    size: u64,
    file_id: &[u8; 16],
    keys: Option<(&[u8], &[u8])>,
    created_at: u64,
    modified_at: u64,
) -> Result<(), CborError> {
    e.map(if is_file { 8 } else { 4 })?;
    e.key("kind")?;
    e.text(if is_file { "file" } else { "dir" })?;
    e.key("path")?;
    e.text(path)?;
    if is_file {
        let (aes, chacha) = keys.ok_or(CborError)?;
        e.key("size")?;
        e.uint(size)?;
        e.key("fk_aes")?;
        e.bytes(aes)?;
        e.key("file_id")?;
        e.bytes(file_id)?;
        e.key("fk_chacha")?;
        e.bytes(chacha)?;
    }
    e.key("created_at")?;
    e.uint(created_at)?;
    e.key("modified_at")?;
    e.uint(modified_at)
}

fn write_new<S: Sink>(e: &mut Encoder<S>, entries: &[NewEntry]) -> Result<(), CborError> {
    e.array(entries.len())?;
    for n in entries {
        let is_file = n.kind == EntryKind::File;
        let keys = n
            .keys
            .as_ref()
            .map(|(a, c)| (&a.expose_secret()[..], &c.expose_secret()[..]));
        if is_file != keys.is_some() {
            return Err(CborError);
        }
        write_entry(
            e,
            is_file,
            &n.path,
            if is_file { n.size } else { 0 },
            &n.file_id,
            keys,
            n.created_at,
            n.modified_at,
        )?;
    }
    Ok(())
}

/// Largest key-table file: a 64 MiB plaintext plus 7.7 record overhead.
pub fn max_file_len() -> u64 {
    StreamHeader {
        kind: StreamKind::KeyTable,
        stream_id: [0; 16],
        context: 0,
        plain_size: MAX_PLAINTEXT,
    }
    .encoded_len()
}

/// Encrypts the table to `out` as `keytable.<gen>.pv` and returns the SHA-512
/// of the bytes written (the future `core.keytable_digest`).
pub fn write_file<W: Write>(
    table: &KeyTable,
    vault_id: &[u8; 16],
    generation: u64,
    keys: &StreamKeys,
    out: W,
) -> Result<[u8; 64], Error> {
    let plain = table.encode()?;
    let header = StreamHeader {
        kind: StreamKind::KeyTable,
        stream_id: *vault_id,
        context: generation,
        plain_size: plain.len() as u64,
    };
    let mut tee = HashingWriter {
        inner: out,
        hash: Sha512::new(),
    };
    cascade::encrypt(keys, &header, plain.expose_secret(), &mut tee)?;
    Ok(tee.hash.finalize().into())
}

/// Reads, authenticates and decodes `keytable.<gen>.pv` (D3 order):
/// 1. the file length is at most [`max_file_len`];
/// 2. a streaming SHA-512 of the whole file equals the authenticated
///    `keytable_digest`;
/// 3. the stream header's `plain_size` is at most 64 MiB, and the memory for
///    the whole working set is available;
/// 4. decryption writes straight into one locked buffer, while the file is
///    hashed again (so a file swapped between the passes is refused);
/// 5. the two-pass decode.
pub fn read_file<R: Read + Seek>(
    mut input: R,
    vault_id: &[u8; 16],
    generation: u64,
    expected_digest: &[u8; 64],
    keys: &StreamKeys,
    probe: &dyn MemoryProbe,
) -> Result<KeyTable, Error> {
    let len = input.seek(SeekFrom::End(0)).map_err(Error::Io)?;
    if len > max_file_len() {
        return Err(Error::KeyTableCorrupt);
    }
    input.seek(SeekFrom::Start(0)).map_err(Error::Io)?;
    let first = hash_reader(&mut input)?;
    if !bool::from(first.ct_eq(expected_digest)) {
        return Err(Error::KeyTableCorrupt);
    }

    input.seek(SeekFrom::Start(0)).map_err(Error::Io)?;
    let mut head = [0u8; cascade::HEADER_LEN];
    input
        .read_exact(&mut head)
        .map_err(|_| Error::KeyTableCorrupt)?;
    let plain_size = u64::from_be_bytes(
        head[30..38]
            .try_into()
            .map_err(|_| Error::KeyTableCorrupt)?,
    );
    if plain_size > MAX_PLAINTEXT {
        return Err(Error::KeyTableCorrupt);
    }
    resources::check_available(working_charge_bound(plain_size), probe)?;

    let mut plain = LockedBuf::try_zeroed(plain_size as usize)?;
    input.seek(SeekFrom::Start(0)).map_err(Error::Io)?;
    let mut tee = HashingReader {
        inner: &mut input,
        hash: Sha512::new(),
    };
    let expected = Expected {
        kind: StreamKind::KeyTable,
        stream_id: *vault_id,
        context: generation,
        plain_size: Some(plain_size),
        max_plain_size: MAX_PLAINTEXT,
    };
    let mut sink = SliceWriter {
        buf: plain.expose_secret_mut(),
        pos: 0,
    };
    cascade::decrypt(keys, &expected, &mut tee, &mut sink).map_err(|_| Error::KeyTableCorrupt)?;
    if sink.pos != plain_size as usize {
        return Err(Error::KeyTableCorrupt);
    }
    let second: [u8; 64] = tee.hash.finalize().into();
    if !bool::from(second.ct_eq(expected_digest)) {
        return Err(Error::KeyTableCorrupt);
    }
    KeyTable::decode(plain.expose_secret())
}

fn hash_reader<R: Read>(input: &mut R) -> Result<[u8; 64], Error> {
    let mut hash = Sha512::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = input.read(&mut buf).map_err(Error::Io)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(hash.finalize().into())
}

struct HashingWriter<W: Write> {
    inner: W,
    hash: Sha512,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hash.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct HashingReader<R: Read> {
    inner: R,
    hash: Sha512,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hash.update(&buf[..n]);
        Ok(n)
    }
}

/// Writes into a fixed buffer and refuses to overflow it.
struct SliceWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl Write for SliceWriter<'_> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let end = self
            .pos
            .checked_add(data.len())
            .filter(|&e| e <= self.buf.len())
            .ok_or_else(|| std::io::Error::other("key table larger than declared"))?;
        self.buf[self.pos..end].copy_from_slice(data);
        self.pos = end;
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::resources::tests::Fake;

    pub(crate) fn file(path: &str, id: u8) -> NewEntry {
        NewEntry {
            kind: EntryKind::File,
            path: Zeroizing::new(path.to_owned()),
            file_id: [id; 16],
            size: u64::from(id) * 100,
            created_at: 1,
            modified_at: 2,
            keys: Some((
                SecretBytes::take_from(&mut [id; 32]).unwrap(),
                SecretBytes::take_from(&mut [id ^ 0xff; 32]).unwrap(),
            )),
        }
    }

    pub(crate) fn dir(path: &str) -> NewEntry {
        NewEntry {
            kind: EntryKind::Dir,
            path: Zeroizing::new(path.to_owned()),
            file_id: [0; 16],
            size: 0,
            created_at: 3,
            modified_at: 4,
            keys: None,
        }
    }

    pub(crate) fn sample() -> KeyTable {
        KeyTable::from_entries(vec![
            file("a/b.txt", 1),
            dir("a"),
            file("z", 2),
            dir("a/c"),
            file("a/c/d", 3),
        ])
        .unwrap()
    }

    #[test]
    fn round_trip_sorted_with_keys() {
        let t = sample();
        let paths: Vec<_> = (0..t.len()).map(|i| t.entry(i).unwrap().path).collect();
        assert_eq!(paths, ["a", "a/b.txt", "a/c", "a/c/d", "z"]);
        let i = t.find("a/c/d").unwrap();
        let (aes, chacha) = t.file_keys(i).unwrap();
        assert_eq!(aes, &[3; 32]);
        assert_eq!(chacha, &[3 ^ 0xff; 32]);
        assert!(t.file_keys(t.find("a").unwrap()).is_none());
        let again = KeyTable::decode(t.encode().unwrap().expose_secret()).unwrap();
        assert_eq!(
            again.encode().unwrap().expose_secret(),
            t.encode().unwrap().expose_secret()
        );
    }

    /// F73 (decode part): each decode-checked violation inside an encoded key
    /// table fails with `KeyTableCorrupt`.
    #[test]
    fn decode_rejects_rule_violations_f73() {
        let bad_sets: Vec<Vec<NewEntry>> = vec![
            vec![file("a/b", 1)],               // missing parent
            vec![file("a", 1), file("a/b", 2)], // file as parent
            vec![dir("CON")],                   // reserved
            vec![dir("a/../b")],                // traversal
            vec![dir("x"), dir("x")],           // duplicate
            vec![file("bad\u{1}", 1)],          // control character
        ];
        for set in bad_sets {
            assert!(matches!(
                KeyTable::from_entries(set),
                Err(Error::KeyTableCorrupt)
            ));
        }
        // Unsorted order, crafted directly.
        let mut e = Encoder::new(Vec::new());
        e.array(2).unwrap();
        for p in ["b", "a"] {
            write_entry(&mut e, false, p, 0, &[0; 16], None, 0, 0).unwrap();
        }
        assert!(matches!(
            KeyTable::decode(&e.into_sink()),
            Err(Error::KeyTableCorrupt)
        ));
        // A directory carrying file fields, and a file missing a key.
        let mut e = Encoder::new(Vec::new());
        e.array(1).unwrap();
        e.map(5).unwrap();
        e.key("kind").unwrap();
        e.text("dir").unwrap();
        e.key("path").unwrap();
        e.text("d").unwrap();
        e.key("size").unwrap();
        e.uint(1).unwrap();
        e.key("created_at").unwrap();
        e.uint(0).unwrap();
        e.key("modified_at").unwrap();
        e.uint(0).unwrap();
        assert!(matches!(
            KeyTable::decode(&e.into_sink()),
            Err(Error::KeyTableCorrupt)
        ));
        // NFC and case-fold differences are NOT decode errors (input-only).
        let t = KeyTable::from_entries(vec![dir("Cafe\u{301}"), dir("caf\u{e9}"), dir("CAFE")]);
        assert!(t.is_ok());
    }

    /// N5: 65,536 entries are accepted; one more is refused before anything
    /// is encoded.
    #[test]
    fn entry_limit_n5() {
        let many: Vec<NewEntry> = (0..MAX_ENTRIES).map(|i| dir(&format!("d{i:05}"))).collect();
        let t = KeyTable::from_entries(many).unwrap();
        assert_eq!(t.len(), MAX_ENTRIES);
        let over: Vec<NewEntry> = (0..=MAX_ENTRIES)
            .map(|i| dir(&format!("d{i:05}")))
            .collect();
        assert!(
            matches!(KeyTable::from_entries(over), Err(Error::Capacity(m)) if m == LIMIT_MESSAGE)
        );
        // A crafted table with 65,537 entries fails to decode.
        let mut e = Encoder::new(Vec::new());
        e.array(MAX_ENTRIES + 1).unwrap();
        for i in 0..=MAX_ENTRIES {
            write_entry(&mut e, false, &format!("d{i:05}"), 0, &[0; 16], None, 0, 0).unwrap();
        }
        assert!(matches!(
            KeyTable::decode(&e.into_sink()),
            Err(Error::KeyTableCorrupt)
        ));
    }

    #[test]
    fn decoded_charge_is_architecture_independent() {
        let c = Counts {
            entries: 3,
            files: 2,
            path_bytes: 10,
        };
        assert_eq!(c.decoded_charge(), 4096 + 384 + 128 + 10);
        assert!(working_charge_bound(MAX_PLAINTEXT) <= (192 << 20) + STREAM_CHARGE);
    }

    #[test]
    fn file_round_trip_and_tamper_f12() {
        let t = sample();
        let keys = StreamKeys::generate().unwrap();
        let mut file = Vec::new();
        let digest = write_file(&t, &[7; 16], 5, &keys, &mut file).unwrap();
        let probe = Fake(Some(16 << 30), Some(8 << 30));
        let back = read_file(
            std::io::Cursor::new(&file),
            &[7; 16],
            5,
            &digest,
            &keys,
            &probe,
        )
        .unwrap();
        assert_eq!(back.len(), t.len());
        // F12: wrong digest (older or foreign file), wrong generation, wrong vault.
        let mut other = Vec::new();
        let other_digest = write_file(&t, &[7; 16], 5, &keys, &mut other).unwrap();
        assert_ne!(other_digest, digest, "fresh nonces change the digest");
        assert!(
            read_file(
                std::io::Cursor::new(&other),
                &[7; 16],
                5,
                &digest,
                &keys,
                &probe
            )
            .is_err()
        );
        assert!(
            read_file(
                std::io::Cursor::new(&file),
                &[7; 16],
                6,
                &digest,
                &keys,
                &probe
            )
            .is_err()
        );
        assert!(
            read_file(
                std::io::Cursor::new(&file),
                &[8; 16],
                5,
                &digest,
                &keys,
                &probe
            )
            .is_err()
        );
        // Not enough memory for the working set: the resource refusal.
        let tight = Fake(Some(16 << 30), Some(1000));
        assert!(matches!(
            read_file(
                std::io::Cursor::new(&file),
                &[7; 16],
                5,
                &digest,
                &keys,
                &tight
            ),
            Err(Error::MemoryResource { .. })
        ));
    }
}
