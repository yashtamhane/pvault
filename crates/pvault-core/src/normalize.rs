//! Unicode NFC and NFKC in one pvault-owned, wiped buffer (spec 7.3, SI-51).
//!
//! The iterators of `unicode-normalization` keep small inline buffers that
//! spill to the heap when four or more combining marks follow one another,
//! and those heap blocks are freed without being wiped. For passphrases,
//! pvault therefore runs the UAX #15 algorithm itself over the crate's
//! per-character primitives (full decomposition, canonical combining class
//! and primary composition), which do not allocate. The only working storage
//! is one fixed-capacity buffer, allocated once and wiped when dropped.
//!
//! Two data sources are used (spec 7.3; `docs/M3_READINESS.md` D2):
//! - [`Form::Nfc`] (custom passphrases, H_c) uses the pinned
//!   `unicode-normalization` crate, whose Unicode version only increases;
//! - [`Form::NfkcV1`] (generated words, `H_w_v1`) uses the frozen Unicode
//!   17.0.0 tables of [`crate::ucd17`], so it never changes between releases.
//!
//! The results are tested against the crate's `nfc()` and `nfkc()` iterators
//! and against the Unicode 17.0.0 conformance file.

use unicode_normalization::char as crate_char;
use zeroize::Zeroizing;

use crate::ucd17;

use crate::passphrase::MAX_RAW_BYTES;

/// Decomposition grows text by at most 6 characters per UTF-8 byte (the
/// largest is U+FDFA: 3 bytes to 18 characters), so this always suffices
/// for inputs of at most [`MAX_RAW_BYTES`]. Larger results are refused,
/// never truncated.
const CAPACITY: usize = 6 * MAX_RAW_BYTES;

/// Normalization form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Form {
    /// Canonical composition, with the crate's tables (H_c).
    Nfc,
    /// Compatibility decomposition, then canonical composition, with the
    /// frozen Unicode 17.0.0 tables (`H_w_v1`).
    NfkcV1,
}

impl Form {
    fn ccc(self, c: char) -> u8 {
        match self {
            Self::Nfc => crate_char::canonical_combining_class(c),
            Self::NfkcV1 => ucd17::ccc(c),
        }
    }

    fn compose(self, a: char, b: char) -> Option<char> {
        match self {
            Self::Nfc => crate_char::compose(a, b),
            Self::NfkcV1 => ucd17::compose(a, b),
        }
    }
}

/// Normalized text, held in a buffer that is wiped on drop.
pub(crate) struct Normalized {
    buf: Zeroizing<Box<[char]>>,
    len: usize,
}

impl Normalized {
    /// The normalized characters.
    pub(crate) fn chars(&self) -> impl Iterator<Item = char> + '_ {
        self.buf[..self.len].iter().copied()
    }
}

/// Normalizes `text`. Returns `None` only if the decomposed text would not
/// fit in the buffer, which cannot happen for inputs of at most
/// [`MAX_RAW_BYTES`].
pub(crate) fn normalize(text: &str, form: Form) -> Option<Normalized> {
    normalize_with_capacity(text, form, CAPACITY)
}

/// [`normalize`] with an explicit buffer capacity in characters (vault
/// paths, which may be longer than passphrases).
pub(crate) fn normalize_with_capacity(
    text: &str,
    form: Form,
    capacity: usize,
) -> Option<Normalized> {
    let mut buf = Zeroizing::new(vec!['\0'; capacity].into_boxed_slice());

    // 1. Full decomposition.
    let mut len = 0;
    let mut overflow = false;
    {
        let mut emit = |d: char| {
            if len < capacity {
                buf[len] = d;
                len += 1;
            } else {
                overflow = true;
            }
        };
        for c in text.chars() {
            match form {
                Form::Nfc => crate_char::decompose_canonical(c, &mut emit),
                Form::NfkcV1 => ucd17::decompose_compatible(c, &mut emit),
            }
        }
    }
    if overflow {
        return None;
    }

    // 2. Canonical ordering: a stable sort, by combining class, of every run
    //    of non-starters. Insertion sort works in place.
    for i in 1..len {
        let ccc = form.ccc(buf[i]);
        if ccc == 0 {
            continue;
        }
        let mut j = i;
        while j > 0 {
            let before = form.ccc(buf[j - 1]);
            if before == 0 || before <= ccc {
                break;
            }
            buf.swap(j - 1, j);
            j -= 1;
        }
    }

    // 3. Canonical composition, in place (the write index never passes the
    //    read index). A character is blocked from the last starter if a
    //    character between them is a starter or has a class at least as
    //    high as its own.
    let mut out = 0;
    let mut starter: Option<usize> = None;
    let mut last_ccc: Option<u8> = None;
    for i in 0..len {
        let c = buf[i];
        let ccc = form.ccc(c);
        if let Some(s) = starter {
            let blocked = last_ccc.is_some_and(|last| last >= ccc);
            if !blocked && let Some(composite) = form.compose(buf[s], c) {
                buf[s] = composite;
                continue;
            }
        }
        if ccc == 0 {
            starter = Some(out);
            last_ccc = None;
        } else {
            last_ccc = Some(ccc);
        }
        buf[out] = c;
        out += 1;
    }
    buf[out..len].fill('\0');

    Some(Normalized { buf, len: out })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use unicode_normalization::UnicodeNormalization;

    fn ours(text: &str, form: Form) -> String {
        normalize(text, form).unwrap().chars().collect()
    }

    fn check(text: &str) {
        assert_eq!(
            ours(text, Form::Nfc),
            text.nfc().collect::<String>(),
            "NFC {text:?}"
        );
        assert_eq!(
            ours(text, Form::NfkcV1),
            text.nfkc().collect::<String>(),
            "NFKC {text:?}"
        );
    }

    #[test]
    fn matches_the_crate_on_known_cases() {
        for text in [
            "",
            "plain ascii",
            "cafe\u{301}",
            "\u{301}leading mark",
            "a\u{316}\u{301}\u{316}\u{301}\u{316}\u{301}\u{316}\u{301}b",
            "a\u{301}\u{301}\u{316}",
            "\u{1e0b}\u{323}",
            "\u{1100}\u{1161}\u{11a8} \u{ac00}\u{11a8}",
            "\u{fdfa}\u{fb01}\u{2163}\u{3000}\u{ff21}",
            "\u{b47}\u{b3e}",
            "\u{f900}\u{2126}\u{212b}",
            "\u{344}\u{f73}\u{f75}\u{f81}",
            "e\u{304}\u{301}\u{30c}",
            "\u{0627}\u{0653}\u{0654}\u{0655}",
            "\u{05d1}\u{05bc}\u{05b8}\u{0591}\u{05a3}",
        ] {
            check(text);
        }
    }

    /// Unicode 17.0.0 `NormalizationTest.txt` (Unicode License V3): for every
    /// line, `c4 == NFKC(c1) == NFKC(c2) == NFKC(c3) == NFKC(c4) == NFKC(c5)`,
    /// and for NFC `c2 == NFC(c1) == NFC(c2) == NFC(c3)`. The `H_w_v1` tables
    /// must pass the NFKC part exactly; the crate-backed NFC is checked too.
    #[test]
    fn unicode_17_conformance_file() {
        let text = include_str!("../testdata/unicode/NormalizationTest-17.0.0.txt");
        let parse = |field: &str| -> String {
            field
                .split(' ')
                .map(|h| char::from_u32(u32::from_str_radix(h, 16).unwrap()).unwrap())
                .collect()
        };
        let mut lines = 0;
        for line in text.lines() {
            let line = line.split('#').next().unwrap().trim();
            if line.is_empty() || line.starts_with('@') {
                continue;
            }
            let cols: Vec<String> = line.split(';').take(5).map(parse).collect();
            for col in &cols {
                assert_eq!(ours(col, Form::NfkcV1), cols[3], "NFKC {line}");
            }
            for col in &cols[..3] {
                assert_eq!(ours(col, Form::Nfc), cols[1], "NFC {line}");
            }
            lines += 1;
        }
        assert!(lines > 19_000, "{lines}");
    }

    #[test]
    fn largest_input_fits() {
        let text = "\u{fdfa}".repeat(MAX_RAW_BYTES / 3);
        let count = normalize(&text, Form::NfkcV1).unwrap().chars().count();
        assert_eq!(count, 18 * (MAX_RAW_BYTES / 3));
        assert!(count <= CAPACITY);
        let too_much = "\u{fdfa}".repeat(MAX_RAW_BYTES / 3 + 1);
        assert!(normalize(&too_much, Form::NfkcV1).is_none());
    }

    fn interesting_char() -> impl Strategy<Value = char> {
        prop_oneof![
            // ASCII and Latin-1 / Latin Extended (precomposed letters)
            (0x20u32..0x250).prop_filter_map("char", char::from_u32),
            // Combining diacritical marks, several classes
            (0x300u32..0x370).prop_filter_map("char", char::from_u32),
            // Hebrew and Arabic marks, Devanagari, Tibetan
            (0x591u32..0x5c8).prop_filter_map("char", char::from_u32),
            (0x610u32..0x670).prop_filter_map("char", char::from_u32),
            (0x900u32..0x980).prop_filter_map("char", char::from_u32),
            (0xf40u32..0xf90).prop_filter_map("char", char::from_u32),
            // Hangul jamo and syllables
            (0x1100u32..0x11ff).prop_filter_map("char", char::from_u32),
            (0xac00u32..0xac80).prop_filter_map("char", char::from_u32),
            // Latin extended additional, Greek extended
            (0x1e00u32..0x2000).prop_filter_map("char", char::from_u32),
            // Compatibility forms
            (0x2150u32..0x2190).prop_filter_map("char", char::from_u32),
            (0x3300u32..0x3400).prop_filter_map("char", char::from_u32),
            (0xf900u32..0xfb50).prop_filter_map("char", char::from_u32),
            (0xfdf0u32..0xfe00).prop_filter_map("char", char::from_u32),
            (0xff00u32..0xffef).prop_filter_map("char", char::from_u32),
            // Musical symbols with canonical decompositions
            (0x1d15eu32..0x1d1c1).prop_filter_map("char", char::from_u32),
            any::<char>(),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]
        #[test]
        fn matches_the_crate_on_generated_text(
            chars in proptest::collection::vec(interesting_char(), 0..48)
        ) {
            let text: String = chars.into_iter().collect();
            prop_assert_eq!(ours(&text, Form::Nfc), text.nfc().collect::<String>());
            prop_assert_eq!(ours(&text, Form::NfkcV1), text.nfkc().collect::<String>());
        }
    }
}
