//! Deterministic CBOR, spec 4.4: a fixed-schema, in-house codec (SI-07
//! option 2; `docs/M3_READINESS.md` D3).
//!
//! The decoder accepts **only** the 4.4 profile:
//! - unsigned integers, byte strings, UTF-8 text strings, arrays, maps,
//!   `false` and `true`;
//! - definite lengths and shortest-form heads;
//! - text-string map keys in strictly ascending encoded order, each known to
//!   the schema;
//! - nesting depth at most [`MAX_DEPTH`];
//! - exactly one top-level item, with no trailing bytes.
//!
//! It borrows every string from its input and **never allocates**. Every
//! length is checked against the remaining input before it is used. Errors
//! carry no payload, so no input byte can reach an error message.
//!
//! The encoder writes into a [`Sink`]. Callers size an output exactly with
//! [`Counter`] first, then encode into a buffer of that size, so a buffer
//! holding secrets never grows.

/// Maximum nesting depth of containers (4.4).
pub const MAX_DEPTH: usize = 4;

/// A deterministic-CBOR error. Deliberately carries no detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CborError;

impl core::fmt::Display for CborError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("malformed or non-canonical CBOR")
    }
}

impl std::error::Error for CborError {}

type Result<T> = core::result::Result<T, CborError>;

const MAJOR_UINT: u8 = 0;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_SIMPLE: u8 = 7;
const FALSE: u64 = 20;
const TRUE: u64 = 21;

/// A strict, allocation-free decoder over a borrowed buffer.
#[derive(Debug)]
pub struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Decoder<'a> {
    /// Starts decoding `input`.
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            pos: 0,
            depth: 0,
        }
    }

    /// Current offset into the input.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Requires that the whole input was consumed (no trailing bytes).
    pub fn finish(self) -> Result<()> {
        if self.pos == self.input.len() && self.depth == 0 {
            Ok(())
        } else {
            Err(CborError)
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(CborError)?;
        let out = self.input.get(self.pos..end).ok_or(CborError)?;
        self.pos = end;
        Ok(out)
    }

    /// Reads one head: (major type, argument). Rejects non-shortest
    /// arguments, indefinite lengths, reserved values, negative integers,
    /// tags, floats and every simple value except `false` and `true`.
    fn head(&mut self) -> Result<(u8, u64)> {
        let initial = self.take(1)?[0];
        let major = initial >> 5;
        let info = initial & 0x1f;
        let value = match info {
            0..=23 => u64::from(info),
            24 => {
                let v = u64::from(self.take(1)?[0]);
                if v < 24 {
                    return Err(CborError);
                }
                v
            }
            25 => {
                let b = self.take(2)?;
                let v = u64::from(u16::from_be_bytes([b[0], b[1]]));
                if v <= 0xff {
                    return Err(CborError);
                }
                v
            }
            26 => {
                let b = self.take(4)?;
                let v = u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
                if v <= 0xffff {
                    return Err(CborError);
                }
                v
            }
            27 => {
                let b = self.take(8)?;
                let mut a = [0u8; 8];
                a.copy_from_slice(b);
                let v = u64::from_be_bytes(a);
                if v <= 0xffff_ffff {
                    return Err(CborError);
                }
                v
            }
            // 28-30 are reserved; 31 is an indefinite length or "break".
            _ => return Err(CborError),
        };
        match major {
            MAJOR_UINT | MAJOR_BYTES | MAJOR_TEXT | MAJOR_ARRAY | MAJOR_MAP => Ok((major, value)),
            // Only `false` and `true`. Simple values 24..=31 use info >= 24
            // and floats use 25..=27; both are rejected here.
            MAJOR_SIMPLE if info == 20 || info == 21 => Ok((major, value)),
            _ => Err(CborError),
        }
    }

    fn expect(&mut self, major: u8) -> Result<u64> {
        let (m, v) = self.head()?;
        if m == major { Ok(v) } else { Err(CborError) }
    }

    fn length(&mut self, major: u8) -> Result<usize> {
        let len = usize::try_from(self.expect(major)?).map_err(|_| CborError)?;
        // A length can never exceed what remains, so a hostile length never
        // reaches an allocation or a slice operation.
        if len > self.input.len() - self.pos {
            return Err(CborError);
        }
        Ok(len)
    }

    /// An unsigned integer (`u64`).
    pub fn uint(&mut self) -> Result<u64> {
        self.expect(MAJOR_UINT)
    }

    /// An unsigned integer that must fit `u32`.
    pub fn u32(&mut self) -> Result<u32> {
        u32::try_from(self.uint()?).map_err(|_| CborError)
    }

    /// An unsigned integer that must fit `u8`.
    pub fn u8(&mut self) -> Result<u8> {
        u8::try_from(self.uint()?).map_err(|_| CborError)
    }

    /// `false` or `true`.
    pub fn bool(&mut self) -> Result<bool> {
        match self.expect(MAJOR_SIMPLE)? {
            FALSE => Ok(false),
            TRUE => Ok(true),
            _ => Err(CborError),
        }
    }

    /// A byte string, borrowed from the input.
    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.length(MAJOR_BYTES)?;
        self.take(len)
    }

    /// A byte string of exactly `N` bytes.
    pub fn bytes_exact<const N: usize>(&mut self) -> Result<&'a [u8; N]> {
        self.bytes()?.try_into().map_err(|_| CborError)
    }

    /// A byte string of at most `max` bytes.
    pub fn bytes_max(&mut self, max: usize) -> Result<&'a [u8]> {
        let b = self.bytes()?;
        if b.len() <= max {
            Ok(b)
        } else {
            Err(CborError)
        }
    }

    /// A valid UTF-8 text string, borrowed from the input.
    pub fn text(&mut self) -> Result<&'a str> {
        let len = self.length(MAJOR_TEXT)?;
        core::str::from_utf8(self.take(len)?).map_err(|_| CborError)
    }

    fn enter(&mut self) -> Result<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            Err(CborError)
        } else {
            Ok(())
        }
    }

    /// An array of at most `max` items. `item` is called once per element,
    /// with the element's index.
    pub fn array(
        &mut self,
        max: usize,
        mut item: impl FnMut(&mut Self, usize) -> Result<()>,
    ) -> Result<usize> {
        let n = usize::try_from(self.expect(MAJOR_ARRAY)?).map_err(|_| CborError)?;
        // Every element takes at least one byte, so a count above the
        // remaining input is malformed, whatever the schema maximum.
        if n > max || n > self.input.len() - self.pos {
            return Err(CborError);
        }
        self.enter()?;
        for i in 0..n {
            item(self, i)?;
        }
        self.depth -= 1;
        Ok(n)
    }

    /// A map whose keys are drawn from `schema`, which lists every permitted
    /// key in canonical order (4.4: shortest encoded first, then bytewise).
    /// Keys must appear in strictly ascending canonical order, so duplicates
    /// and unknown keys are rejected. `required` is a bit mask over `schema`
    /// indices. `value` is called with each key's schema index. Returns the
    /// bit mask of keys present.
    pub fn map(
        &mut self,
        schema: &[&str],
        required: u64,
        mut value: impl FnMut(&mut Self, usize) -> Result<()>,
    ) -> Result<u64> {
        debug_assert!(schema.len() <= 64);
        debug_assert!(schema.windows(2).all(|w| key_order(w[0], w[1]).is_lt()));
        let n = usize::try_from(self.expect(MAJOR_MAP)?).map_err(|_| CborError)?;
        if n > schema.len() {
            return Err(CborError);
        }
        self.enter()?;
        let mut present = 0u64;
        let mut last: Option<usize> = None;
        for _ in 0..n {
            let key = self.text()?;
            let index = schema.iter().position(|k| *k == key).ok_or(CborError)?;
            // Schema order is canonical order, so ascending indices mean
            // strictly ascending keys.
            if last.is_some_and(|l| index <= l) {
                return Err(CborError);
            }
            last = Some(index);
            present |= 1 << index;
            value(self, index)?;
        }
        self.depth -= 1;
        if present & required == required {
            Ok(present)
        } else {
            Err(CborError)
        }
    }
}

/// Canonical order of two map keys (4.4): by encoded form, which for text
/// keys shorter than 24 bytes is shorter first, then bytewise.
pub fn key_order(a: &str, b: &str) -> core::cmp::Ordering {
    (a.len(), a.as_bytes()).cmp(&(b.len(), b.as_bytes()))
}

/// Output of the encoder.
pub trait Sink {
    /// Appends `bytes`.
    fn put(&mut self, bytes: &[u8]) -> Result<()>;
}

/// Counts bytes without storing them, for exact sizing.
#[derive(Debug, Default)]
pub struct Counter(pub usize);

impl Sink for Counter {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self.0 = self.0.checked_add(bytes.len()).ok_or(CborError)?;
        Ok(())
    }
}

/// Writes into a fixed slice; fails rather than grow.
#[derive(Debug)]
pub struct SliceSink<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> SliceSink<'a> {
    /// Writes into `buf` from the start.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes written so far.
    pub fn written(&self) -> usize {
        self.pos
    }
}

impl Sink for SliceSink<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self.pos.checked_add(bytes.len()).ok_or(CborError)?;
        self.buf
            .get_mut(self.pos..end)
            .ok_or(CborError)?
            .copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }
}

/// Non-secret structures (header, journal) may encode into a `Vec`.
impl Sink for Vec<u8> {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

/// Shortest-form encoder.
#[derive(Debug)]
pub struct Encoder<S: Sink> {
    sink: S,
}

impl<S: Sink> Encoder<S> {
    /// Encodes into `sink`.
    pub fn new(sink: S) -> Self {
        Self { sink }
    }

    /// Returns the sink.
    pub fn into_sink(self) -> S {
        self.sink
    }

    fn head(&mut self, major: u8, value: u64) -> Result<()> {
        let m = major << 5;
        if value < 24 {
            self.sink.put(&[m | value as u8])
        } else if value <= 0xff {
            self.sink.put(&[m | 24, value as u8])
        } else if value <= 0xffff {
            self.sink.put(&[m | 25])?;
            self.sink.put(&(value as u16).to_be_bytes())
        } else if value <= 0xffff_ffff {
            self.sink.put(&[m | 26])?;
            self.sink.put(&(value as u32).to_be_bytes())
        } else {
            self.sink.put(&[m | 27])?;
            self.sink.put(&value.to_be_bytes())
        }
    }

    /// An unsigned integer.
    pub fn uint(&mut self, value: u64) -> Result<()> {
        self.head(MAJOR_UINT, value)
    }

    /// `false` or `true`.
    pub fn bool(&mut self, value: bool) -> Result<()> {
        self.head(MAJOR_SIMPLE, if value { TRUE } else { FALSE })
    }

    /// A byte string, written straight from `bytes`.
    pub fn bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.head(MAJOR_BYTES, bytes.len() as u64)?;
        self.sink.put(bytes)
    }

    /// A text string.
    pub fn text(&mut self, text: &str) -> Result<()> {
        self.head(MAJOR_TEXT, text.len() as u64)?;
        self.sink.put(text.as_bytes())
    }

    /// An array head for `n` items.
    pub fn array(&mut self, n: usize) -> Result<()> {
        self.head(MAJOR_ARRAY, n as u64)
    }

    /// A map head for `n` entries. The caller writes keys in canonical order.
    pub fn map(&mut self, n: usize) -> Result<()> {
        self.head(MAJOR_MAP, n as u64)
    }

    /// A map key.
    pub fn key(&mut self, key: &str) -> Result<()> {
        self.text(key)
    }

    /// Already-encoded CBOR (for example a nested structure whose exact
    /// bytes are MACed).
    pub fn raw(&mut self, encoded: &[u8]) -> Result<()> {
        self.sink.put(encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(f: impl FnOnce(&mut Encoder<Vec<u8>>) -> Result<()>) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        f(&mut e).unwrap();
        e.into_sink()
    }

    #[test]
    fn shortest_heads_round_trip_at_every_boundary() {
        for v in [
            0u64,
            23,
            24,
            255,
            256,
            65_535,
            65_536,
            u32::MAX as u64,
            u32::MAX as u64 + 1,
            u64::MAX,
        ] {
            let bytes = enc(|e| e.uint(v));
            let mut d = Decoder::new(&bytes);
            assert_eq!(d.uint().unwrap(), v);
            d.finish().unwrap();
        }
    }

    #[test]
    fn rejects_everything_outside_the_profile() {
        let bad: &[&[u8]] = &[
            &[0x18, 0x17],       // non-shortest 23
            &[0x19, 0x00, 0xff], // non-shortest 255
            &[0x1a, 0x00, 0x00, 0xff, 0xff],
            &[0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
            &[0x1c],             // reserved
            &[0x20],             // negative integer
            &[0xc0, 0x00],       // tag
            &[0xf9, 0x3c, 0x00], // half float
            &[0xfa, 0, 0, 0, 0], // float
            &[0xf6],             // null
            &[0xf7],             // undefined
            &[0xf0],             // simple value 16
            &[0xf8, 0x20],       // simple value 32
            &[0x5f, 0xff],       // indefinite bytes
            &[0x9f, 0xff],       // indefinite array
            &[0xbf, 0xff],       // indefinite map
            &[0xff],             // break
            &[0x00, 0x00],       // trailing bytes
            &[0x42, 0x00],       // truncated byte string
            &[0x62, 0xc3, 0x28], // invalid UTF-8 text
        ];
        for b in bad {
            let parses = |read: fn(&mut Decoder<'_>) -> bool| {
                let mut d = Decoder::new(b);
                read(&mut d) && d.finish().is_ok()
            };
            assert!(!parses(|d| d.uint().is_ok()), "{b:02x?}");
            assert!(!parses(|d| d.bytes().is_ok()), "{b:02x?}");
            assert!(!parses(|d| d.text().is_ok()), "{b:02x?}");
            assert!(!parses(|d| d.bool().is_ok()), "{b:02x?}");
        }
    }

    #[test]
    fn maps_require_canonical_known_unique_keys() {
        const SCHEMA: &[&str] = &["a", "b", "aa"];
        let good = enc(|e| {
            e.map(2)?;
            e.key("b")?;
            e.uint(1)?;
            e.key("aa")?;
            e.uint(2)
        });
        let mut d = Decoder::new(&good);
        let mask = d.map(SCHEMA, 0b100, |d, _| d.uint().map(|_| ())).unwrap();
        assert_eq!(mask, 0b110);
        d.finish().unwrap();

        let cases: Vec<Vec<u8>> = vec![
            // wrong order
            enc(|e| {
                e.map(2)?;
                e.key("aa")?;
                e.uint(1)?;
                e.key("b")?;
                e.uint(2)
            }),
            // duplicate
            enc(|e| {
                e.map(2)?;
                e.key("a")?;
                e.uint(1)?;
                e.key("a")?;
                e.uint(2)
            }),
            // unknown
            enc(|e| {
                e.map(1)?;
                e.key("z")?;
                e.uint(1)
            }),
            // missing required "aa"
            enc(|e| {
                e.map(1)?;
                e.key("a")?;
                e.uint(1)
            }),
            // non-text key
            vec![0xa1, 0x01, 0x01],
        ];
        for c in cases {
            let mut d = Decoder::new(&c);
            assert!(
                d.map(SCHEMA, 0b100, |d, _| d.uint().map(|_| ())).is_err(),
                "{c:02x?}"
            );
        }
    }

    #[test]
    fn depth_is_limited_to_four() {
        // [[[[0]]]] is depth 4; [[[[[0]]]]] is depth 5.
        fn nested(levels: usize) -> Vec<u8> {
            let mut v = vec![0x81; levels];
            v.push(0x00);
            v
        }
        fn walk(d: &mut Decoder<'_>, left: usize) -> Result<()> {
            if left == 0 {
                return d.uint().map(|_| ());
            }
            d.array(1, |d, _| walk(d, left - 1)).map(|_| ())
        }
        let ok = nested(4);
        let mut d = Decoder::new(&ok);
        walk(&mut d, 4).unwrap();
        d.finish().unwrap();
        let deep = nested(5);
        let mut d = Decoder::new(&deep);
        assert!(walk(&mut d, 5).is_err());
    }

    #[test]
    fn hostile_lengths_never_exceed_the_input() {
        // A byte string claiming 2^32 bytes, and an array claiming 2^20 items.
        let big = [0x5a, 0x01, 0x00, 0x00, 0x00];
        assert!(Decoder::new(&big).bytes().is_err());
        let many = [0x9a, 0x00, 0x10, 0x00, 0x00];
        assert!(
            Decoder::new(&many)
                .array(usize::MAX, |d, _| d.uint().map(|_| ()))
                .is_err()
        );
    }

    #[test]
    fn counter_and_slice_sink_agree_and_never_grow() {
        fn write<S: Sink>(e: &mut Encoder<S>) -> Result<()> {
            e.map(1)?;
            e.key("k")?;
            e.bytes(&[7u8; 300])
        }
        let mut c = Encoder::new(Counter::default());
        write(&mut c).unwrap();
        let n = c.into_sink().0;
        let mut buf = vec![0u8; n];
        let mut s = Encoder::new(SliceSink::new(&mut buf));
        write(&mut s).unwrap();
        assert_eq!(s.into_sink().written(), n);
        let mut small = vec![0u8; n - 1];
        let mut s = Encoder::new(SliceSink::new(&mut small));
        assert!(write(&mut s).is_err());
    }
}
