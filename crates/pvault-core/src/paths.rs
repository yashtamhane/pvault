//! Vault paths: the decode-time rules (spec 7.8; D7).
//!
//! These rules do not depend on any Unicode version, so a newer Unicode table
//! can never make an existing vault unreadable:
//! - valid UTF-8 (guaranteed by the CBOR decoder);
//! - 1 to 4096 bytes in total; components separated by `/`, each 1 to 255
//!   bytes;
//! - no leading `/`, empty component, `.` or `..`;
//! - no `\`, U+0000 to U+001F, U+007F, or any of `< > : " | ? *`;
//! - no component ending in a space or a dot;
//! - no Windows reserved name (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`,
//!   `LPT1`–`LPT9`), ASCII case-insensitive, with or without an extension.
//!
//! NFC form and case-fold collisions are checked on **input** only
//! (Milestone 4, `add`), never at decode time (F73).
//!
//! **Input** (approved for Milestone 4; `docs/M4_READINESS.md` section 8):
//! code points unassigned in Unicode 17.0.0 are refused; the text is
//! normalized to NFC in a wiped buffer; the decode-time rules then apply;
//! collisions use Unicode canonical caseless matching (D145),
//! `NFD(toCasefold(NFD(x)))`, with the vendored Unicode 17.0.0 tables.

use zeroize::Zeroizing;

use crate::normalize::{Form, normalize_with_capacity};
use crate::ucd17;

/// Largest vault path, in bytes.
pub const MAX_PATH_BYTES: usize = 4096;
/// Largest path component, in bytes.
pub const MAX_COMPONENT_BYTES: usize = 255;

const RESERVED: &[&str] = &["CON", "PRN", "AUX", "NUL"];
const FORBIDDEN: &[char] = &['\\', '<', '>', ':', '"', '|', '?', '*'];

/// Whether `path` satisfies every decode-time rule.
pub fn is_valid_decoded(path: &str) -> bool {
    violation(path).is_none()
}

/// The first decode-time rule `path` breaks, as message text (no path
/// text is included).
pub fn violation(path: &str) -> Option<&'static str> {
    if path.is_empty() {
        return Some("the path is empty");
    }
    if path.len() > MAX_PATH_BYTES {
        return Some("the path is longer than 4,096 bytes");
    }
    path.split('/').find_map(component_violation)
}

fn component_violation(c: &str) -> Option<&'static str> {
    if c.is_empty() || c == "." || c == ".." {
        return Some("absolute paths and empty, \".\" or \"..\" names are not allowed");
    }
    if c.len() > MAX_COMPONENT_BYTES {
        return Some("a name is longer than 255 bytes");
    }
    if c.chars()
        .any(|ch| ch <= '\u{1f}' || ch == '\u{7f}' || FORBIDDEN.contains(&ch))
    {
        return Some("control characters and \\ < > : \" | ? * are not allowed");
    }
    if c.ends_with(' ') || c.ends_with('.') {
        return Some("a name may not end with a space or a dot");
    }
    if is_reserved(c) {
        return Some("Windows reserved names such as CON, NUL or COM1 are not allowed");
    }
    None
}

fn is_reserved(component: &str) -> bool {
    let base = component.split('.').next().unwrap_or(component);
    if RESERVED.iter().any(|r| base.eq_ignore_ascii_case(r)) {
        return true;
    }
    let b = base.as_bytes();
    // Bytes, not `str` slicing: a 4-byte component can end in a multi-byte
    // character, and slicing it at byte 3 would panic.
    b.len() == 4
        && (b[..3].eq_ignore_ascii_case(b"COM") || b[..3].eq_ignore_ascii_case(b"LPT"))
        && (b'1'..=b'9').contains(&b[3])
}

/// Why an input path was refused. No variant carries path text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputPathError {
    /// A code point unassigned in Unicode 17.0.0 (or a noncharacter).
    Unassigned,
    /// A decode-time rule (the reason).
    Invalid(&'static str),
}

/// A normalized input path.
pub struct InputPath {
    /// The NFC form that is stored.
    pub stored: Zeroizing<String>,
    /// Whether normalization changed the typed text.
    pub changed: bool,
}

impl core::fmt::Debug for InputPath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("InputPath([REDACTED])")
    }
}

/// Applies the input rules to a typed path.
pub fn normalize_input(raw: &str) -> Result<InputPath, InputPathError> {
    if raw.is_empty() {
        return Err(InputPathError::Invalid("the path is empty"));
    }
    // Bound the work before normalizing: NFC never makes text longer than
    // 3 times in UTF-8, so anything over 3 × 4096 bytes cannot be valid.
    if raw.len() > 3 * MAX_PATH_BYTES {
        return Err(InputPathError::Invalid(
            "the path is longer than 4,096 bytes",
        ));
    }
    if raw.chars().any(|c| !ucd17::is_assigned(c)) {
        return Err(InputPathError::Unassigned);
    }
    let capacity = 6 * raw.len() + 1;
    let n = normalize_with_capacity(raw, Form::Nfc, capacity).ok_or(InputPathError::Invalid(
        "the path is longer than 4,096 bytes",
    ))?;
    let mut stored = Zeroizing::new(String::with_capacity(raw.len() + 8));
    for c in n.chars() {
        stored.push(c);
    }
    if let Some(reason) = violation(&stored) {
        return Err(InputPathError::Invalid(reason));
    }
    let changed = stored.as_str() != raw;
    Ok(InputPath { stored, changed })
}

fn nfd(text: impl Iterator<Item = char>, out: &mut Zeroizing<Vec<char>>) {
    out.clear();
    for c in text {
        ucd17::decompose_canonical(c, &mut |d| out.push(d));
    }
    // Canonical ordering (stable, in place).
    for i in 1..out.len() {
        let ccc = ucd17::ccc(out[i]);
        if ccc == 0 {
            continue;
        }
        let mut j = i;
        while j > 0 {
            let before = ucd17::ccc(out[j - 1]);
            if before == 0 || before <= ccc {
                break;
            }
            out.swap(j - 1, j);
            j -= 1;
        }
    }
}

/// The collision key: `NFD(toCasefold(NFD(path)))` with the frozen Unicode
/// 17.0.0 tables (canonical caseless matching, Unicode D145).
pub fn collision_key(path: &str) -> Zeroizing<Vec<char>> {
    let mut first = Zeroizing::new(Vec::with_capacity(path.len() * 2));
    nfd(path.chars(), &mut first);
    let mut folded = Zeroizing::new(Vec::with_capacity(first.len() * 2));
    for &c in first.iter() {
        ucd17::case_fold(c, &mut |f| folded.push(f));
    }
    let mut key = Zeroizing::new(Vec::with_capacity(folded.len() * 2));
    nfd(folded.iter().copied(), &mut key);
    key
}

/// The parent of `path`, if it has one (`a/b/c` → `a/b`).
pub fn parent(path: &str) -> Option<&str> {
    path.rfind('/').map(|i| &path[..i])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F73 input part.
    #[test]
    fn input_rules() {
        let ok = normalize_input("cafe\u{301}/Report.pdf").unwrap();
        assert_eq!(ok.stored.as_str(), "caf\u{e9}/Report.pdf");
        assert!(ok.changed);
        assert!(!normalize_input("a/b").unwrap().changed);
        for bad in [
            "", "/abs", "a//b", "../x", "a/./b", "C:x", "a\\b", "x\u{1}y", "CON.txt", "dir/LPT3",
            "trail.", "sp ", "a?b",
        ] {
            assert!(
                matches!(normalize_input(bad), Err(InputPathError::Invalid(_))),
                "{bad:?}"
            );
        }
        assert!(matches!(
            normalize_input("a\u{378}"),
            Err(InputPathError::Unassigned)
        ));
        assert!(matches!(
            normalize_input("a\u{fdd0}"),
            Err(InputPathError::Unassigned)
        ));
        assert!(normalize_input("pua\u{e000}").is_ok());
        assert!(matches!(
            normalize_input(&"x".repeat(256)),
            Err(InputPathError::Invalid(_))
        ));
        let long = vec!["y".repeat(255); 17].join("/");
        assert!(matches!(
            normalize_input(&long),
            Err(InputPathError::Invalid(_))
        ));
    }

    /// Canonical caseless matching: case, NFC/NFD, and folding that needs
    /// the second NFD all collide; different names do not.
    #[test]
    fn collision_keys() {
        let key = |s: &str| collision_key(s).to_vec();
        assert_eq!(key("Docs/Report"), key("docs/REPORT"));
        assert_eq!(key("caf\u{e9}"), key("CAFE\u{301}"));
        assert_eq!(key("Stra\u{df}e"), key("STRASSE"));
        assert_eq!(key("\u{1e9e}"), key("ss")); // capital sharp s
        assert_eq!(key("\u{3a3}\u{3c2}"), key("\u{3c3}\u{3c3}")); // final sigma
        // U+0345 (ypogegrammeni) folds to U+03B9: the case needing D145's
        // outer NFD to be closed under canonical equivalence.
        assert_eq!(key("\u{1f80}"), key("\u{1f00}\u{3b9}"));
        assert_ne!(key("a"), key("b"));
        assert_ne!(key("file1"), key("file2"));
    }

    #[test]
    fn accepts_ordinary_paths() {
        for p in [
            "a",
            "docs/report 2026.pdf",
            "café/naïve",
            "a/b/c/d",
            ".hidden",
        ] {
            assert!(is_valid_decoded(p), "{p}");
        }
        assert!(is_valid_decoded(&"x".repeat(255)));
        // Four bytes ending inside a multi-byte character (found in review:
        // byte slicing used to panic here).
        for p in ["ab\u{e9}", "a\u{e9}b", "\u{e9}ab", "x\u{20ac}"] {
            assert!(is_valid_decoded(p), "{p}");
        }
        let long = vec!["y".repeat(255); 16].join("/");
        assert!(long.len() <= MAX_PATH_BYTES && is_valid_decoded(&long));
    }

    #[test]
    fn rejects_every_decode_time_violation_f73() {
        let too_long_total = vec!["z".repeat(200); 21].join("/");
        assert!(too_long_total.len() > MAX_PATH_BYTES);
        for p in [
            "",
            "/abs",
            "a//b",
            "a/",
            ".",
            "a/..",
            "a\\b",
            "C:/x",
            "a\u{0}b",
            "a\u{1f}b",
            "a\u{7f}b",
            "a<b",
            "a>b",
            "a\"b",
            "a|b",
            "a?b",
            "a*b",
            "trailing ",
            "trailing.",
            "CON",
            "con.txt",
            "Com1",
            "lpt9.log",
            "dir/nul",
        ] {
            assert!(!is_valid_decoded(p), "{p:?}");
        }
        assert!(!is_valid_decoded(&"x".repeat(256)));
        assert!(!is_valid_decoded(&too_long_total));
        assert!(is_valid_decoded("COM10") && is_valid_decoded("CONSOLE"));
    }

    #[test]
    fn parent_of_paths() {
        assert_eq!(parent("a/b/c"), Some("a/b"));
        assert_eq!(parent("a"), None);
    }
}
