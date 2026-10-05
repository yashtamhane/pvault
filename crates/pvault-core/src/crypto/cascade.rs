//! Chunked dual-cipher stream format (spec Section 7.7), shared by objects
//! (`PVOB`) and the key table (`PVKT`).
//!
//! ```text
//! magic(4) version(u16 BE) stream_id(16) context(u64 BE) plain_size(u64 BE)
//! chunk_count = max(1, ceil(plain_size / 65536)) records:
//!   rec_len(u32 BE) n2(24) c2(rec_len - 24)
//!
//! aad = "pvault/v1/" || magic || u16_be(version) || stream_id || u64_be(context)
//!       || u64_be(plain_size) || u64_be(chunk_count) || u64_be(i) || u8(is_last)
//! c1  = AES-256-GCM-SIV(key_aes, n1).encrypt(chunk_i, aad)
//! c2  = XChaCha20-Poly1305(key_chacha, n2).encrypt(n1 || c1, aad)
//! ```
//!
//! Plaintext exists only in one zeroize-on-drop chunk buffer. Encryption
//! happens in place, so the buffer holds ciphertext by the time it is written.
//! Decryption verifies the outer tag and then the inner tag before a chunk
//! reaches the writer; any failure aborts the whole stream.

use std::io::{self, Read, Write};

use aes_gcm_siv::Aes256GcmSiv;
use aes_gcm_siv::aead::{AeadInOut, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use zeroize::Zeroizing;

use crate::crypto::random;
use crate::errors::Error;
use crate::secrets::SecretBytes;

/// Plaintext bytes per chunk.
pub const CHUNK_SIZE: usize = 65_536;
/// The only supported format version.
pub const VERSION: u16 = 1;
/// Length of the fixed stream header.
pub const HEADER_LEN: usize = 4 + 2 + 16 + 8 + 8;

const N1_LEN: usize = 12;
const N2_LEN: usize = 24;
const TAG_LEN: usize = 16;
const AAD_LEN: usize = 10 + 4 + 2 + 16 + 8 + 8 + 8 + 8 + 1;
const CHUNK_SIZE_U64: u64 = CHUNK_SIZE as u64;

/// Which kind of stream this is. It selects the magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// An encrypted file (`PVOB`).
    Object,
    /// The encrypted key table (`PVKT`).
    KeyTable,
}

impl StreamKind {
    const fn magic(self) -> &'static [u8; 4] {
        match self {
            Self::Object => b"PVOB",
            Self::KeyTable => b"PVKT",
        }
    }
}

/// The authenticated parameters of one stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamHeader {
    /// Object or key table.
    pub kind: StreamKind,
    /// `file_id` for objects, `vault_id` for the key table.
    pub stream_id: [u8; 16],
    /// 0 for objects, `keytable_gen` for the key table.
    pub context: u64,
    /// Exact plaintext length.
    pub plain_size: u64,
}

impl StreamHeader {
    /// Number of records: `max(1, ceil(plain_size / 65536))`. Derived, never
    /// read from input.
    pub const fn chunk_count(&self) -> u64 {
        let full = self.plain_size / CHUNK_SIZE_U64;
        let partial = (!self.plain_size.is_multiple_of(CHUNK_SIZE_U64)) as u64;
        if full + partial == 0 {
            1
        } else {
            full + partial
        }
    }

    /// Plaintext length of chunk `i`.
    fn chunk_len(&self, i: u64) -> usize {
        if i + 1 < self.chunk_count() {
            CHUNK_SIZE
        } else {
            // At most 65,536, so the conversion cannot truncate.
            (self.plain_size - CHUNK_SIZE_U64 * (self.chunk_count() - 1)) as usize
        }
    }

    /// Exact length of the encoded stream.
    pub fn encoded_len(&self) -> u64 {
        let overhead = (4 + N2_LEN + N1_LEN + TAG_LEN + TAG_LEN) as u64;
        HEADER_LEN as u64 + self.plain_size + self.chunk_count() * overhead
    }

    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(self.kind.magic());
        out[4..6].copy_from_slice(&VERSION.to_be_bytes());
        out[6..22].copy_from_slice(&self.stream_id);
        out[22..30].copy_from_slice(&self.context.to_be_bytes());
        out[30..38].copy_from_slice(&self.plain_size.to_be_bytes());
        out
    }

    fn aad(&self, i: u64) -> [u8; AAD_LEN] {
        let mut aad = [0u8; AAD_LEN];
        let fields: [&[u8]; 9] = [
            b"pvault/v1/",
            self.kind.magic(),
            &VERSION.to_be_bytes(),
            &self.stream_id,
            &self.context.to_be_bytes(),
            &self.plain_size.to_be_bytes(),
            &self.chunk_count().to_be_bytes(),
            &i.to_be_bytes(),
            &[u8::from(i + 1 == self.chunk_count())],
        ];
        let mut at = 0;
        for field in fields {
            aad[at..at + field.len()].copy_from_slice(field);
            at += field.len();
        }
        debug_assert_eq!(at, AAD_LEN);
        aad
    }
}

/// The two keys of a stream: per-file `fk_aes`/`fk_chacha` for objects, or
/// `K_aes`/`K_chacha` for the key table.
#[derive(Debug)]
pub struct StreamKeys {
    aes: SecretBytes<32>,
    chacha: SecretBytes<32>,
}

impl StreamKeys {
    /// Wraps existing keys.
    pub fn new(aes: SecretBytes<32>, chacha: SecretBytes<32>) -> Self {
        Self { aes, chacha }
    }

    /// Two fresh, independent random keys (spec Section 7.7).
    pub fn generate() -> Result<Self, Error> {
        Ok(Self::new(random::secret()?, random::secret()?))
    }

    fn ciphers(&self) -> Result<(Aes256GcmSiv, XChaCha20Poly1305), Error> {
        let inner =
            Aes256GcmSiv::new_from_slice(self.aes.expose_secret()).map_err(|_| Error::Stream)?;
        let outer = XChaCha20Poly1305::new_from_slice(self.chacha.expose_secret())
            .map_err(|_| Error::Stream)?;
        Ok((inner, outer))
    }
}

/// What a decrypted stream must declare. Anything else is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Expected {
    /// Object or key table.
    pub kind: StreamKind,
    /// Required `stream_id`.
    pub stream_id: [u8; 16],
    /// Required `context`.
    pub context: u64,
    /// Required exact `plain_size`, if known (objects).
    pub plain_size: Option<u64>,
    /// Upper bound on `plain_size` (64 MiB for the key table).
    pub max_plain_size: u64,
}

/// Source of per-chunk nonces. Production code always uses the OS CSPRNG.
trait NonceSource {
    fn next(&mut self, n1: &mut [u8; N1_LEN], n2: &mut [u8; N2_LEN]) -> Result<(), Error>;
}

struct OsNonces;

impl NonceSource for OsNonces {
    fn next(&mut self, n1: &mut [u8; N1_LEN], n2: &mut [u8; N2_LEN]) -> Result<(), Error> {
        random::fill(n1)?;
        random::fill(n2)
    }
}

/// Encrypts exactly `header.plain_size` bytes from `plaintext` into `out`.
/// The source must supply exactly that many bytes.
pub fn encrypt<R: Read, W: Write>(
    keys: &StreamKeys,
    header: &StreamHeader,
    plaintext: R,
    out: W,
) -> Result<(), Error> {
    encrypt_with(keys, header, plaintext, out, &mut OsNonces)
}

fn encrypt_with<R: Read, W: Write, N: NonceSource>(
    keys: &StreamKeys,
    header: &StreamHeader,
    mut plaintext: R,
    mut out: W,
    nonces: &mut N,
) -> Result<(), Error> {
    let (inner_cipher, outer_cipher) = keys.ciphers()?;
    out.write_all(&header.encode()).map_err(Error::Io)?;

    let mut buf = Zeroizing::new(vec![0u8; N1_LEN + CHUNK_SIZE + TAG_LEN]);
    let mut n1 = [0u8; N1_LEN];
    let mut n2 = [0u8; N2_LEN];
    for i in 0..header.chunk_count() {
        let len = header.chunk_len(i);
        let aad = header.aad(i);
        nonces.next(&mut n1, &mut n2)?;

        let record = &mut buf[..N1_LEN + len + TAG_LEN];
        record[..N1_LEN].copy_from_slice(&n1);
        plaintext
            .read_exact(&mut record[N1_LEN..N1_LEN + len])
            .map_err(input_error)?;

        let inner_tag = inner_cipher
            .encrypt_inout_detached(&n1.into(), &aad, (&mut record[N1_LEN..N1_LEN + len]).into())
            .map_err(|_| Error::Stream)?;
        record[N1_LEN + len..].copy_from_slice(&inner_tag);

        let outer_tag = outer_cipher
            .encrypt_inout_detached(&n2.into(), &aad, (&mut record[..]).into())
            .map_err(|_| Error::Stream)?;

        let rec_len = u32::try_from(N2_LEN + record.len() + TAG_LEN).map_err(|_| Error::Stream)?;
        for part in [&rec_len.to_be_bytes()[..], &n2, record, &outer_tag] {
            out.write_all(part).map_err(Error::Io)?;
        }
    }

    if read_probe(&mut plaintext).map_err(Error::Io)? {
        return Err(Error::InputLength);
    }
    out.flush().map_err(Error::Io)
}

/// Decrypts and verifies a stream, writing only verified plaintext to `out`.
/// Returns the stream's header.
///
/// Plaintext of earlier chunks may already have been written when a later
/// chunk fails. Callers write to a `.pvpartial` and discard it on any error
/// (spec Section 7.9).
pub fn decrypt<R: Read, W: Write>(
    keys: &StreamKeys,
    expected: &Expected,
    mut input: R,
    mut out: W,
) -> Result<StreamHeader, Error> {
    let (inner_cipher, outer_cipher) = keys.ciphers()?;

    let mut raw = [0u8; HEADER_LEN];
    input.read_exact(&mut raw).map_err(stream_error)?;
    let header = parse_header(&raw, expected)?;

    let mut buf = Zeroizing::new(vec![0u8; N1_LEN + CHUNK_SIZE + TAG_LEN]);
    for i in 0..header.chunk_count() {
        let len = header.chunk_len(i);
        let aad = header.aad(i);

        let mut rec_len = [0u8; 4];
        input.read_exact(&mut rec_len).map_err(stream_error)?;
        let rec_len = usize::try_from(u32::from_be_bytes(rec_len)).map_err(|_| Error::Stream)?;
        if rec_len != N2_LEN + N1_LEN + len + TAG_LEN + TAG_LEN {
            return Err(Error::Stream);
        }

        let mut n2 = [0u8; N2_LEN];
        let mut outer_tag = [0u8; TAG_LEN];
        let record = &mut buf[..N1_LEN + len + TAG_LEN];
        input.read_exact(&mut n2).map_err(stream_error)?;
        input.read_exact(record).map_err(stream_error)?;
        input.read_exact(&mut outer_tag).map_err(stream_error)?;

        outer_cipher
            .decrypt_inout_detached(
                &n2.into(),
                &aad,
                (&mut record[..]).into(),
                &outer_tag.into(),
            )
            .map_err(|_| Error::Stream)?;

        let (n1, rest) = record.split_at_mut(N1_LEN);
        let (chunk, inner_tag) = rest.split_at_mut(len);
        let n1: [u8; N1_LEN] = (&*n1).try_into().map_err(|_| Error::Stream)?;
        let inner_tag: [u8; TAG_LEN] = (&*inner_tag).try_into().map_err(|_| Error::Stream)?;
        inner_cipher
            .decrypt_inout_detached(&n1.into(), &aad, chunk.into(), &inner_tag.into())
            .map_err(|_| Error::Stream)?;

        out.write_all(chunk).map_err(Error::Io)?;
    }

    if read_probe(&mut input).map_err(Error::Io)? {
        return Err(Error::Stream);
    }
    out.flush().map_err(Error::Io)?;
    Ok(header)
}

fn parse_header(raw: &[u8; HEADER_LEN], expected: &Expected) -> Result<StreamHeader, Error> {
    let u64_at = |at: usize| {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&raw[at..at + 8]);
        u64::from_be_bytes(bytes)
    };
    let mut stream_id = [0u8; 16];
    stream_id.copy_from_slice(&raw[6..22]);
    let header = StreamHeader {
        kind: expected.kind,
        stream_id,
        context: u64_at(22),
        plain_size: u64_at(30),
    };

    let valid = &raw[0..4] == expected.kind.magic()
        && raw[4..6] == VERSION.to_be_bytes()
        && header.stream_id == expected.stream_id
        && header.context == expected.context
        && header.plain_size <= expected.max_plain_size
        && expected
            .plain_size
            .is_none_or(|size| size == header.plain_size);
    if valid {
        Ok(header)
    } else {
        Err(Error::Stream)
    }
}

/// Returns true if `reader` has at least one more byte.
fn read_probe<R: Read>(reader: &mut R) -> io::Result<bool> {
    let mut probe = [0u8; 1];
    loop {
        match reader.read(&mut probe) {
            Ok(n) => return Ok(n > 0),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

fn input_error(e: io::Error) -> Error {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        Error::InputLength
    } else {
        Error::Io(e)
    }
}

fn stream_error(e: io::Error) -> Error {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        Error::Stream
    } else {
        Error::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::mac::sha512;
    use crate::testvec::{Record, field, hex, hex_field, records};
    use sha2::{Digest, Sha256};

    struct FixedNonces(std::vec::IntoIter<([u8; N1_LEN], [u8; N2_LEN])>);

    impl NonceSource for FixedNonces {
        fn next(&mut self, n1: &mut [u8; N1_LEN], n2: &mut [u8; N2_LEN]) -> Result<(), Error> {
            let (a, b) = self
                .0
                .next()
                .expect("vector supplies a nonce for every chunk");
            *n1 = a;
            *n2 = b;
            Ok(())
        }
    }

    fn key32(v: &Record, name: &str) -> SecretBytes<32> {
        SecretBytes::take_from(&mut hex_field(v, name)).unwrap()
    }

    #[test]
    fn pvault_stream_vectors() {
        let vectors = records(include_str!("../../testdata/pvault_stream.txt"));
        assert_eq!(vectors.len(), 5);
        for v in &vectors {
            let name = field(v, "name");
            let keys = StreamKeys::new(key32(v, "key_aes"), key32(v, "key_chacha"));
            let kind = match field(v, "kind") {
                "object" => StreamKind::Object,
                "keytable" => StreamKind::KeyTable,
                other => panic!("unknown kind {other}"),
            };
            let header = StreamHeader {
                kind,
                stream_id: hex_field(v, "stream_id").try_into().unwrap(),
                context: field(v, "context").parse().unwrap(),
                plain_size: field(v, "plain_size").parse().unwrap(),
            };
            let plaintext: Vec<u8> = (0..header.plain_size)
                .map(|j| ((j * 31 + 7) % 256) as u8)
                .collect();
            let nonces: Vec<_> = field(v, "nonces")
                .split(',')
                .map(|pair| {
                    let bytes = hex(pair);
                    (
                        bytes[..N1_LEN].try_into().unwrap(),
                        bytes[N1_LEN..].try_into().unwrap(),
                    )
                })
                .collect();
            assert_eq!(nonces.len() as u64, header.chunk_count(), "{name}");

            let mut stream = Vec::new();
            encrypt_with(
                &keys,
                &header,
                plaintext.as_slice(),
                &mut stream,
                &mut FixedNonces(nonces.into_iter()),
            )
            .unwrap();
            assert_eq!(stream.len().to_string(), field(v, "stream_len"), "{name}");
            assert_eq!(stream.len() as u64, header.encoded_len(), "{name}");
            assert_eq!(
                hex(field(v, "stream_sha256")),
                Sha256::digest(&stream).as_slice(),
                "{name}"
            );
            if let Some(full) = v.get("stream") {
                assert_eq!(hex(full), stream, "{name}");
            }

            let expected = Expected {
                kind,
                stream_id: header.stream_id,
                context: header.context,
                plain_size: Some(header.plain_size),
                max_plain_size: u64::MAX,
            };
            let mut decrypted = Vec::new();
            assert_eq!(
                decrypt(&keys, &expected, stream.as_slice(), &mut decrypted).unwrap(),
                header
            );
            assert_eq!(sha512(&[&decrypted]), sha512(&[&plaintext]), "{name}");
        }
    }

    /// Wycheproof AES-GCM-SIV vectors, run through the same in-place calls the
    /// stream uses.
    #[test]
    fn wycheproof_aes256_gcm_siv() {
        let vectors = records(include_str!("../../testdata/wycheproof_aes256_gcm_siv.txt"));
        assert!(vectors.len() > 50);
        for v in &vectors {
            let cipher = Aes256GcmSiv::new_from_slice(&hex_field(v, "key")).unwrap();
            let nonce: [u8; N1_LEN] = hex_field(v, "iv").try_into().unwrap();
            let aad = hex_field(v, "aad");
            let tag = hex_field(v, "tag");
            let id = field(v, "tcId");
            let mut buf = hex_field(v, "ct");
            let opened = <[u8; TAG_LEN]>::try_from(tag.as_slice())
                .ok()
                .and_then(|tag| {
                    cipher
                        .decrypt_inout_detached(
                            &nonce.into(),
                            &aad,
                            buf.as_mut_slice().into(),
                            &tag.into(),
                        )
                        .ok()
                });
            if field(v, "result") == "valid" {
                assert!(opened.is_some(), "tcId {id}");
                assert_eq!(buf, hex_field(v, "msg"), "tcId {id}");
                let mut buf = hex_field(v, "msg");
                let sealed = cipher
                    .encrypt_inout_detached(&nonce.into(), &aad, buf.as_mut_slice().into())
                    .unwrap();
                assert_eq!(buf, hex_field(v, "ct"), "tcId {id}");
                assert_eq!(sealed.as_slice(), tag, "tcId {id}");
            } else {
                assert!(opened.is_none(), "tcId {id}");
            }
        }
    }

    /// Wycheproof XChaCha20-Poly1305 vectors, run through the same in-place
    /// calls the stream uses.
    #[test]
    fn wycheproof_xchacha20_poly1305() {
        let vectors = records(include_str!(
            "../../testdata/wycheproof_xchacha20_poly1305.txt"
        ));
        assert!(vectors.len() > 50);
        for v in &vectors {
            let cipher = XChaCha20Poly1305::new_from_slice(&hex_field(v, "key")).unwrap();
            let nonce: [u8; N2_LEN] = hex_field(v, "iv").try_into().unwrap();
            let aad = hex_field(v, "aad");
            let tag = hex_field(v, "tag");
            let id = field(v, "tcId");
            let mut buf = hex_field(v, "ct");
            let opened = <[u8; TAG_LEN]>::try_from(tag.as_slice())
                .ok()
                .and_then(|tag| {
                    cipher
                        .decrypt_inout_detached(
                            &nonce.into(),
                            &aad,
                            buf.as_mut_slice().into(),
                            &tag.into(),
                        )
                        .ok()
                });
            if field(v, "result") == "valid" {
                assert!(opened.is_some(), "tcId {id}");
                assert_eq!(buf, hex_field(v, "msg"), "tcId {id}");
                let mut buf = hex_field(v, "msg");
                let sealed = cipher
                    .encrypt_inout_detached(&nonce.into(), &aad, buf.as_mut_slice().into())
                    .unwrap();
                assert_eq!(buf, hex_field(v, "ct"), "tcId {id}");
                assert_eq!(sealed.as_slice(), tag, "tcId {id}");
            } else {
                assert!(opened.is_none(), "tcId {id}");
            }
        }
    }

    /// The AES key schedule inside `Aes256GcmSiv` is `aes::Aes256`, which
    /// wipes itself on drop only when the `aes` crate's `zeroize` feature is
    /// enabled. This fails to compile if that feature is ever lost.
    #[test]
    fn aes_key_schedule_is_zeroized_on_drop() {
        fn zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        zeroize_on_drop::<aes::Aes256>();
        zeroize_on_drop::<XChaCha20Poly1305>();
    }

    #[test]
    fn chunk_arithmetic() {
        let h = |plain_size| StreamHeader {
            kind: StreamKind::Object,
            stream_id: [0; 16],
            context: 0,
            plain_size,
        };
        assert_eq!(h(0).chunk_count(), 1);
        assert_eq!(h(0).chunk_len(0), 0);
        assert_eq!(h(1).chunk_count(), 1);
        assert_eq!(h(65_536).chunk_count(), 1);
        assert_eq!(h(65_536).chunk_len(0), 65_536);
        assert_eq!(h(65_537).chunk_count(), 2);
        assert_eq!(h(65_537).chunk_len(0), 65_536);
        assert_eq!(h(65_537).chunk_len(1), 1);
        assert_eq!(h(u64::MAX).chunk_count(), u64::MAX / 65_536 + 1);
    }
}
