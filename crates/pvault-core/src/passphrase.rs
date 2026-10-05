//! Passphrases (spec Section 7.3; SI-51).
//!
//! Two kinds of main passphrase exist:
//! - **generated words** (`words`): 10 to 16 words from the EFF large
//!   wordlist, default 12, processed with [`handle_words`];
//! - **custom** text written by the owner, processed with
//!   [`handle_custom`].
//!
//! Duress passphrases are always generated, with exactly
//! [`WordCount::DURESS`] words.
//!
//! Every function here writes secret output into an exactly sized
//! [`SecretBuf`]. Lengths are counted in a first pass, so no buffer holding
//! passphrase material ever grows or reallocates. Unicode normalization runs
//! in one fixed, wiped working buffer (`crate::normalize`), so it leaves no
//! unwiped heap copies either.

use core::fmt;
use std::sync::OnceLock;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::crypto::random;
use crate::errors::Error;
use crate::normalize::{Form, normalize};
use crate::secrets::SecretBuf;

/// Largest raw input accepted, in bytes, before any processing.
pub const MAX_RAW_BYTES: usize = 1024;
/// Largest result of [`handle_words`], in bytes.
pub const MAX_WORDS_BYTES: usize = 1024;
/// Largest result of [`handle_custom`], in bytes.
pub const MAX_CUSTOM_BYTES: usize = 256;

/// Number of words in the EFF large wordlist.
pub const WORDLIST_LEN: usize = 7776;
/// SHA-256 of the unmodified EFF file in `assets/` (lowercase hex).
pub const WORDLIST_SHA256: &str =
    "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e";

/// The EFF large wordlist, unmodified. Licensed CC BY 4.0 International by
/// the Electronic Frontier Foundation (see `THIRD_PARTY_NOTICES.md`).
pub(crate) const WORDLIST_FILE: &str = include_str!("../../../assets/eff_large_wordlist.txt");

/// Rejection-sampling bound: the largest multiple of 7,776 that fits in 16 bits.
const SAMPLE_BOUND: u16 = 62_208;

struct Wordlist {
    by_index: Vec<&'static str>,
    sorted: Vec<&'static str>,
}

fn wordlist() -> &'static Wordlist {
    static LIST: OnceLock<Wordlist> = OnceLock::new();
    LIST.get_or_init(|| {
        let by_index: Vec<&'static str> = WORDLIST_FILE
            .lines()
            .map(|line| {
                line.split_once('\t')
                    .expect("wordlist lines are `ddddd<TAB>word`")
                    .1
            })
            .collect();
        let mut sorted = by_index.clone();
        sorted.sort_unstable();
        Wordlist { by_index, sorted }
    })
}

/// Whether `word` is in the EFF large wordlist (exact match).
pub fn is_listed(word: &str) -> bool {
    wordlist().sorted.binary_search(&word).is_ok()
}

/// Number of words in a generated passphrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WordCount(u8);

impl WordCount {
    /// Fewest words allowed (meets assumption A3).
    pub const MIN: u8 = 10;
    /// Most words allowed.
    pub const MAX: u8 = 16;
    /// Default for main passphrases.
    pub const DEFAULT: Self = Self(12);
    /// Fixed length of duress passphrases.
    pub const DURESS: Self = Self(12);

    /// A word count between [`Self::MIN`] and [`Self::MAX`].
    pub fn new(words: u8) -> Result<Self, PassphraseError> {
        if (Self::MIN..=Self::MAX).contains(&words) {
            Ok(Self(words))
        } else {
            Err(PassphraseError::WordCountOutOfRange)
        }
    }

    /// The number of words.
    pub fn get(self) -> u8 {
        self.0
    }

    /// Calculated classical entropy, `words × log2(7776)` bits. It is exact
    /// for words drawn uniformly by [`generate`].
    pub fn entropy_bits(self) -> f64 {
        f64::from(self.0) * (WORDLIST_LEN as f64).log2()
    }

    /// Policy rating. It is not a guarantee of strength.
    pub fn rating(self) -> GeneratedRating {
        if self.0 >= 12 {
            GeneratedRating::Strong
        } else {
            GeneratedRating::Medium
        }
    }
}

/// Policy rating of a generated passphrase (SI-51).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneratedRating {
    /// 10 or 11 words: meets assumption A3.
    Medium,
    /// 12 to 16 words.
    Strong,
}

impl fmt::Display for GeneratedRating {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Medium => "Medium (policy rating, not a guarantee)",
            Self::Strong => "Strong (policy rating, not a guarantee)",
        })
    }
}

/// Generates a passphrase of uniformly random words, lowercase and
/// separated by single spaces.
pub fn generate(count: WordCount) -> Result<SecretBuf, Error> {
    generate_with(count, random::fill)
}

/// Generation with an injectable byte source, for known-answer tests. Each
/// word index comes from two bytes read as a big-endian `u16`. Values of
/// 62,208 or more are rejected, and the rest are reduced modulo 7,776, which
/// is unbiased.
pub(crate) fn generate_with(
    count: WordCount,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), Error>,
) -> Result<SecretBuf, Error> {
    let words = usize::from(count.0);
    let mut indices = Zeroizing::new([0u16; WordCount::MAX as usize]);
    let mut pair = Zeroizing::new([0u8; 2]);
    let mut chosen = 0;
    while chosen < words {
        fill(&mut pair[..])?;
        let value = u16::from_be_bytes(*pair);
        if value < SAMPLE_BOUND {
            indices[chosen] = value % WORDLIST_LEN as u16;
            chosen += 1;
        }
    }

    let list = &wordlist().by_index;
    let len = indices[..words]
        .iter()
        .map(|&i| list[usize::from(i)].len())
        .sum::<usize>()
        + words
        - 1;
    let mut out = SecretBuf::zeroed(len);
    let buf = out.expose_secret_mut();
    let mut at = 0;
    for (n, &i) in indices[..words].iter().enumerate() {
        if n > 0 {
            buf[at] = b' ';
            at += 1;
        }
        let word = list[usize::from(i)].as_bytes();
        buf[at..at + word.len()].copy_from_slice(word);
        at += word.len();
    }
    Ok(out)
}

/// Generated-word handling, `H_w` (spec 7.3): NFKC, trim, collapse every
/// whitespace run to one U+0020, then lowercase each character (full
/// Unicode mapping, applied per character).
pub fn handle_words(raw: &[u8]) -> Result<SecretBuf, PassphraseError> {
    let text = checked_text(raw)?;
    let too_long = PassphraseError::TooLong {
        limit: MAX_WORDS_BYTES,
    };
    let normalized = normalize(text, Form::Nfkc).ok_or(too_long)?;
    let len = words_pipeline(normalized.chars())
        .map(char::len_utf8)
        .sum::<usize>();
    if len > MAX_WORDS_BYTES {
        return Err(PassphraseError::TooLong {
            limit: MAX_WORDS_BYTES,
        });
    }
    if len == 0 {
        return Err(PassphraseError::Empty);
    }
    Ok(fill_exact(len, words_pipeline(normalized.chars())))
}

fn words_pipeline(mut chars: impl Iterator<Item = char>) -> impl Iterator<Item = char> {
    let mut started = false;
    let mut pending_space = false;
    let mut lower: Option<core::char::ToLowercase> = None;
    core::iter::from_fn(move || {
        loop {
            if let Some(c) = lower.as_mut().and_then(Iterator::next) {
                return Some(c);
            }
            lower = None;
            let c = chars.next()?;
            if c.is_whitespace() {
                pending_space |= started;
                continue;
            }
            started = true;
            lower = Some(c.to_lowercase());
            if pending_space {
                pending_space = false;
                return Some(' ');
            }
        }
    })
}

/// Checks every word of a [`handle_words`] result against the word list.
/// It runs only for generated-word input, and reports the first unknown word.
pub fn check_word_list(handled: &SecretBuf) -> Result<(), PassphraseError> {
    let text =
        core::str::from_utf8(handled.expose_secret()).map_err(|_| PassphraseError::InvalidUtf8)?;
    for (n, word) in text.split(' ').enumerate() {
        if !is_listed(word) {
            return Err(PassphraseError::UnknownWord { position: n + 1 });
        }
    }
    Ok(())
}

/// A custom passphrase after [`handle_custom`].
pub struct CustomPassphrase {
    bytes: SecretBuf,
    nfc_changed: bool,
    warnings: Vec<CustomWarning>,
}

impl CustomPassphrase {
    /// The handled bytes, which are the Argon2id password input.
    pub fn bytes(&self) -> &SecretBuf {
        &self.bytes
    }

    /// Whether NFC normalization changed the typed bytes. If so, the owner is
    /// told before confirming.
    pub fn nfc_changed(&self) -> bool {
        self.nfc_changed
    }

    /// Warnings shown at creation. Their positions are character numbers,
    /// starting at 1.
    pub fn warnings(&self) -> &[CustomWarning] {
        &self.warnings
    }
}

impl fmt::Debug for CustomPassphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Explanation shown before confirmation when NFC changed the input.
pub const NFC_NOTICE: &str = "pvault stores Unicode text in its standard composed form (NFC). Some characters you typed were converted to that form. They look the same, and typing them the same way will work.";

/// A permitted but noteworthy feature of a custom passphrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomWarning {
    /// The passphrase starts with whitespace, which is kept exactly.
    LeadingWhitespace,
    /// The passphrase ends with whitespace, which is kept exactly.
    TrailingWhitespace,
    /// An invisible character (ZWNJ, ZWJ, word joiner or soft hyphen).
    InvisibleCharacter {
        /// Character number, starting at 1.
        position: usize,
    },
}

impl fmt::Display for CustomWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LeadingWhitespace => {
                f.write_str("Your passphrase starts with a space. It is kept exactly; you must type it every time.")
            }
            Self::TrailingWhitespace => {
                f.write_str("Your passphrase ends with a space. It is kept exactly; you must type it every time.")
            }
            Self::InvisibleCharacter { position } => write!(
                f,
                "Character {position} is invisible (a joiner or soft hyphen). It is kept exactly."
            ),
        }
    }
}

/// Custom handling, `H_c` (SI-51 section 3): Unicode NFC only. Nothing is
/// trimmed, lowercased or collapsed. Refused characters are rejected rather
/// than altered.
pub fn handle_custom(raw: &[u8]) -> Result<CustomPassphrase, PassphraseError> {
    let text = checked_text(raw)?;
    let normalized = normalize(text, Form::Nfc).ok_or(PassphraseError::TooLong {
        limit: MAX_CUSTOM_BYTES,
    })?;
    let len = normalized.chars().map(char::len_utf8).sum::<usize>();
    if len == 0 {
        return Err(PassphraseError::Empty);
    }
    if len > MAX_CUSTOM_BYTES {
        return Err(PassphraseError::TooLong {
            limit: MAX_CUSTOM_BYTES,
        });
    }
    let bytes = fill_exact(len, normalized.chars());
    drop(normalized);
    let nfc_changed =
        !(bytes.expose_secret().len() == raw.len() && bool::from(bytes.expose_secret().ct_eq(raw)));

    let handled =
        core::str::from_utf8(bytes.expose_secret()).map_err(|_| PassphraseError::InvalidUtf8)?;
    if let Some((n, class)) = handled
        .chars()
        .enumerate()
        .find_map(|(n, c)| refused_class(c).map(|class| (n, class)))
    {
        return Err(PassphraseError::Refused {
            position: n + 1,
            class,
        });
    }
    let mut warnings = Vec::new();
    let mut last = '\0';
    for (n, c) in handled.chars().enumerate() {
        if n == 0 && is_edge_whitespace(c) {
            warnings.push(CustomWarning::LeadingWhitespace);
        }
        if is_invisible(c) {
            warnings.push(CustomWarning::InvisibleCharacter { position: n + 1 });
        }
        last = c;
    }
    if is_edge_whitespace(last) {
        warnings.push(CustomWarning::TrailingWhitespace);
    }
    Ok(CustomPassphrase {
        bytes,
        nfc_changed,
        warnings,
    })
}

/// The collision rule for duress setup (SI-51): the actual main credential,
/// after generated-word processing, equals the generated duress credential.
/// Checked at setup and whenever either credential changes.
pub fn duress_collides(main_raw: &[u8], duress_words: &SecretBuf) -> bool {
    match handle_words(main_raw) {
        Ok(handled) => {
            handled.len() == duress_words.len() && bool::from(handled.ct_eq(duress_words))
        }
        Err(_) => false,
    }
}

/// A class of character that custom passphrases refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusedClass {
    /// C0 or C1 control characters, or DEL. Includes tab and line breaks.
    Control,
    /// U+2028 or U+2029.
    LineSeparator,
    /// Bidirectional formatting controls.
    Bidirectional,
    /// U+FEFF.
    ByteOrderMark,
    /// Unicode noncharacters.
    Noncharacter,
}

fn refused_class(c: char) -> Option<RefusedClass> {
    let cp = u32::from(c);
    match cp {
        0x00..=0x1F | 0x7F..=0x9F => Some(RefusedClass::Control),
        0x2028 | 0x2029 => Some(RefusedClass::LineSeparator),
        0x061C | 0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069 => {
            Some(RefusedClass::Bidirectional)
        }
        0xFEFF => Some(RefusedClass::ByteOrderMark),
        0xFDD0..=0xFDEF => Some(RefusedClass::Noncharacter),
        _ if cp & 0xFFFE == 0xFFFE => Some(RefusedClass::Noncharacter),
        _ => None,
    }
}

fn is_edge_whitespace(c: char) -> bool {
    matches!(
        u32::from(c),
        0x0020 | 0x00A0 | 0x1680 | 0x2000..=0x200A | 0x202F | 0x205F | 0x3000
    )
}

fn is_invisible(c: char) -> bool {
    matches!(u32::from(c), 0x200C | 0x200D | 0x2060 | 0x00AD)
}

fn checked_text(raw: &[u8]) -> Result<&str, PassphraseError> {
    if raw.len() > MAX_RAW_BYTES {
        return Err(PassphraseError::TooLong {
            limit: MAX_RAW_BYTES,
        });
    }
    core::str::from_utf8(raw).map_err(|_| PassphraseError::InvalidUtf8)
}

fn fill_exact(len: usize, chars: impl Iterator<Item = char>) -> SecretBuf {
    let mut out = SecretBuf::zeroed(len);
    let buf = out.expose_secret_mut();
    let mut at = 0;
    for c in chars {
        at += c.encode_utf8(&mut buf[at..]).len();
    }
    debug_assert_eq!(at, len);
    out
}

/// Input problems. Messages describe only the input's shape, never its
/// content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PassphraseError {
    /// The input exceeds a size limit.
    TooLong {
        /// The limit, in bytes.
        limit: usize,
    },
    /// The input is not valid UTF-8.
    InvalidUtf8,
    /// Nothing remains after handling.
    Empty,
    /// A refused character (custom passphrases).
    Refused {
        /// Character number, starting at 1.
        position: usize,
        /// What kind of character it is.
        class: RefusedClass,
    },
    /// A word that is not in the word list (generated-word input).
    UnknownWord {
        /// Word number, starting at 1.
        position: usize,
    },
    /// A generated passphrase must have 10 to 16 words.
    WordCountOutOfRange,
}

impl fmt::Display for PassphraseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { limit } => {
                write!(f, "The passphrase is too long (at most {limit} bytes).")
            }
            Self::InvalidUtf8 => f.write_str("The passphrase is not valid UTF-8 text."),
            Self::Empty => f.write_str("The passphrase is empty."),
            Self::Refused { position, class } => {
                let what = match class {
                    RefusedClass::Control => "a control character (such as a tab or line break)",
                    RefusedClass::LineSeparator => "a line or paragraph separator",
                    RefusedClass::Bidirectional => "a bidirectional text control",
                    RefusedClass::ByteOrderMark => "a byte-order mark",
                    RefusedClass::Noncharacter => "a Unicode noncharacter",
                };
                write!(
                    f,
                    "Character {position} is {what}, which pvault does not accept."
                )
            }
            Self::UnknownWord { position } => {
                write!(f, "Word {position} is not in the word list.")
            }
            Self::WordCountOutOfRange => f.write_str("Generated passphrases have 10 to 16 words."),
        }
    }
}

impl std::error::Error for PassphraseError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testvec::{field, hex, hex_field, records};
    use sha2::{Digest, Sha256};

    fn text(buf: &SecretBuf) -> &str {
        core::str::from_utf8(buf.expose_secret()).unwrap()
    }

    #[test]
    fn wordlist_is_the_unmodified_eff_file() {
        assert_eq!(
            Sha256::digest(WORDLIST_FILE.as_bytes()).as_slice(),
            hex(WORDLIST_SHA256)
        );
        let list = &wordlist().by_index;
        assert_eq!(list.len(), WORDLIST_LEN);
        let mut dedup = wordlist().sorted.clone();
        dedup.dedup();
        assert_eq!(dedup.len(), WORDLIST_LEN, "words are unique");
        for (n, line) in WORDLIST_FILE.lines().enumerate() {
            let (dice, word) = line.split_once('\t').unwrap();
            assert_eq!(dice.len(), 5);
            assert!(dice.bytes().all(|d| (b'1'..=b'6').contains(&d)), "line {n}");
            assert!(
                word.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
                "{word}"
            );
        }
        let hyphenated: Vec<_> = list.iter().filter(|w| w.contains('-')).collect();
        assert_eq!(
            hyphenated,
            [&"drop-down", &"felt-tip", &"t-shirt", &"yo-yo"]
        );
    }

    #[test]
    fn word_counts_and_ratings() {
        assert_eq!(WordCount::DEFAULT.get(), 12);
        assert_eq!(WordCount::DURESS.get(), 12);
        for n in 0..=40 {
            assert_eq!(WordCount::new(n).is_ok(), (10..=16).contains(&n));
        }
        assert_eq!(
            WordCount::new(10).unwrap().rating(),
            GeneratedRating::Medium
        );
        assert_eq!(
            WordCount::new(11).unwrap().rating(),
            GeneratedRating::Medium
        );
        assert_eq!(
            WordCount::new(12).unwrap().rating(),
            GeneratedRating::Strong
        );
        assert_eq!(
            WordCount::new(16).unwrap().rating(),
            GeneratedRating::Strong
        );
        let bits = WordCount::new(12).unwrap().entropy_bits();
        assert!((bits - 155.098).abs() < 0.001, "{bits}");
        assert!((WordCount::new(10).unwrap().entropy_bits() - 129.248).abs() < 0.001);
    }

    #[test]
    fn generated_passphrases_have_the_requested_shape() {
        for n in [10u8, 12, 16] {
            let pass = generate(WordCount::new(n).unwrap()).unwrap();
            let words: Vec<_> = text(&pass).split(' ').collect();
            assert_eq!(words.len(), usize::from(n));
            assert!(words.iter().all(|w| is_listed(w)));
            check_word_list(&pass).unwrap();
            let rehandled = handle_words(pass.expose_secret()).unwrap();
            assert!(bool::from(rehandled.ct_eq(&pass)), "already normalized");
        }
        let a = generate(WordCount::DEFAULT).unwrap();
        let b = generate(WordCount::DEFAULT).unwrap();
        assert!(!bool::from(a.ct_eq(&b)));
    }

    /// Independent vectors: rejection sampling from fixed bytes, and both
    /// handlings computed by the Python reference.
    #[test]
    fn independent_passphrase_vectors() {
        for v in records(include_str!("../testdata/pvault_passphrase.txt")) {
            match field(&v, "kind") {
                "sampling" => {
                    let stream = hex_field(&v, "random_bytes");
                    let mut at = 0;
                    let count = WordCount::new(field(&v, "words").parse().unwrap()).unwrap();
                    let pass = generate_with(count, |buf| {
                        buf.copy_from_slice(&stream[at..at + buf.len()]);
                        at += buf.len();
                        Ok(())
                    })
                    .unwrap();
                    assert_eq!(
                        pass.expose_secret(),
                        hex_field(&v, "passphrase_utf8").as_slice()
                    );
                    assert_eq!(at.to_string(), field(&v, "bytes_used"));
                }
                "words" => {
                    let out = handle_words(&hex_field(&v, "input")).unwrap();
                    assert_eq!(
                        out.expose_secret(),
                        hex_field(&v, "output").as_slice(),
                        "{}",
                        field(&v, "name")
                    );
                }
                "custom" => {
                    let input = hex_field(&v, "input");
                    match field(&v, "result") {
                        "ok" => {
                            let out = handle_custom(&input).unwrap();
                            assert_eq!(
                                out.bytes().expose_secret(),
                                hex_field(&v, "output").as_slice(),
                                "{}",
                                field(&v, "name")
                            );
                            assert_eq!(out.nfc_changed().to_string(), field(&v, "nfc_changed"));
                        }
                        class => {
                            let err = handle_custom(&input).unwrap_err();
                            let got = match err {
                                PassphraseError::Refused { class, .. } => format!("{class:?}"),
                                other => format!("{other:?}"),
                            };
                            assert!(
                                got.starts_with(class),
                                "{}: {got} vs {class}",
                                field(&v, "name")
                            );
                        }
                    }
                }
                other => panic!("unknown vector kind {other}"),
            }
        }
    }

    #[test]
    fn words_handling_normalizes_case_space_and_compatibility_forms() {
        let out = handle_words("  Abacus\t\tZONE \u{3000} ｙｏ-ｙｏ \n".as_bytes()).unwrap();
        assert_eq!(text(&out), "abacus zone yo-yo");
        check_word_list(&out).unwrap();
        assert!(matches!(handle_words(b" \t "), Err(PassphraseError::Empty)));
        assert!(matches!(
            handle_words(&[0xff]),
            Err(PassphraseError::InvalidUtf8)
        ));
        assert!(matches!(
            handle_words(&vec![b'a'; MAX_RAW_BYTES + 1]),
            Err(PassphraseError::TooLong {
                limit: MAX_RAW_BYTES
            })
        ));
        // NFKC can expand: U+FDFA becomes 18 characters (33 bytes).
        let expanding = "\u{FDFA}".repeat(MAX_RAW_BYTES / 3);
        assert!(matches!(
            handle_words(expanding.as_bytes()),
            Err(PassphraseError::TooLong {
                limit: MAX_WORDS_BYTES
            })
        ));
    }

    #[test]
    fn word_list_check_reports_the_first_unknown_word() {
        let out = handle_words(b"abacus tshirt zoom").unwrap();
        assert_eq!(
            check_word_list(&out),
            Err(PassphraseError::UnknownWord { position: 2 })
        );
        let ok = handle_words(b"t-shirt drop-down").unwrap();
        check_word_list(&ok).unwrap();
    }

    #[test]
    fn custom_handling_keeps_text_exactly_except_nfc() {
        let out = handle_custom("  Mixed Case  with  spaces ".as_bytes()).unwrap();
        assert_eq!(text(out.bytes()), "  Mixed Case  with  spaces ");
        assert!(!out.nfc_changed());
        assert_eq!(
            out.warnings(),
            [
                CustomWarning::LeadingWhitespace,
                CustomWarning::TrailingWhitespace
            ]
        );

        let nfd = "cafe\u{0301}".as_bytes();
        let nfc = "caf\u{00E9}".as_bytes();
        let a = handle_custom(nfd).unwrap();
        let b = handle_custom(nfc).unwrap();
        assert!(bool::from(a.bytes().ct_eq(b.bytes())));
        assert!(a.nfc_changed());
        assert!(!b.nfc_changed());

        let joined = handle_custom("a\u{200D}b".as_bytes()).unwrap();
        assert_eq!(
            joined.warnings(),
            [CustomWarning::InvisibleCharacter { position: 2 }]
        );
    }

    #[test]
    fn custom_handling_refuses_listed_characters() {
        let cases: &[(&str, RefusedClass)] = &[
            ("tab\there", RefusedClass::Control),
            ("line\nbreak", RefusedClass::Control),
            ("cr\rhere", RefusedClass::Control),
            ("del\u{7F}", RefusedClass::Control),
            ("nel\u{85}", RefusedClass::Control),
            ("ls\u{2028}", RefusedClass::LineSeparator),
            ("ps\u{2029}", RefusedClass::LineSeparator),
            ("rlo\u{202E}x", RefusedClass::Bidirectional),
            ("lri\u{2066}x", RefusedClass::Bidirectional),
            ("alm\u{061C}x", RefusedClass::Bidirectional),
            ("\u{FEFF}bom", RefusedClass::ByteOrderMark),
            ("nc\u{FDD0}", RefusedClass::Noncharacter),
            ("nc\u{FFFF}", RefusedClass::Noncharacter),
            ("nc\u{10FFFE}", RefusedClass::Noncharacter),
        ];
        for (input, class) in cases {
            match handle_custom(input.as_bytes()) {
                Err(PassphraseError::Refused { class: got, .. }) => {
                    assert_eq!(got, *class, "{input:?}")
                }
                other => panic!("{input:?}: {other:?}"),
            }
        }
        assert!(matches!(handle_custom(b""), Err(PassphraseError::Empty)));
        assert!(matches!(
            handle_custom(&vec![b'a'; MAX_CUSTOM_BYTES + 1]),
            Err(PassphraseError::TooLong {
                limit: MAX_CUSTOM_BYTES
            })
        ));
        handle_custom(&vec![b'a'; MAX_CUSTOM_BYTES]).unwrap();
    }

    #[test]
    fn errors_never_contain_the_input() {
        let secret = "s3cret\tvalue";
        let message = handle_custom(secret.as_bytes()).unwrap_err().to_string();
        assert!(!message.contains("s3cret"));
        assert_eq!(
            format!("{:?}", handle_custom(b"ok text").unwrap()),
            "[REDACTED]"
        );
    }

    #[test]
    fn collision_rule_compares_generated_word_processing() {
        let duress = generate(WordCount::DURESS).unwrap();
        // The owner's actual main credential equals the duress words after
        // generated-word processing (here: different case and spacing).
        let mut typed = text(&duress).to_uppercase().replace(' ', "   ");
        assert!(duress_collides(typed.as_bytes(), &duress));
        typed.push_str(" abacus");
        assert!(!duress_collides(typed.as_bytes(), &duress));
        assert!(!duress_collides(b"a different custom passphrase", &duress));
    }
}
