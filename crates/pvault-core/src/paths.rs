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

/// Largest vault path, in bytes.
pub const MAX_PATH_BYTES: usize = 4096;
/// Largest path component, in bytes.
pub const MAX_COMPONENT_BYTES: usize = 255;

const RESERVED: &[&str] = &["CON", "PRN", "AUX", "NUL"];
const FORBIDDEN: &[char] = &['\\', '<', '>', ':', '"', '|', '?', '*'];

/// Whether `path` satisfies every decode-time rule.
pub fn is_valid_decoded(path: &str) -> bool {
    if path.is_empty() || path.len() > MAX_PATH_BYTES {
        return false;
    }
    path.split('/').all(is_valid_component)
}

fn is_valid_component(c: &str) -> bool {
    if c.is_empty() || c.len() > MAX_COMPONENT_BYTES || c == "." || c == ".." {
        return false;
    }
    if c.chars()
        .any(|ch| ch <= '\u{1f}' || ch == '\u{7f}' || FORBIDDEN.contains(&ch))
    {
        return false;
    }
    if c.ends_with(' ') || c.ends_with('.') {
        return false;
    }
    !is_reserved(c)
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

/// The parent of `path`, if it has one (`a/b/c` → `a/b`).
pub fn parent(path: &str) -> Option<&str> {
    path.rfind('/').map(|i| &path[..i])
}

#[cfg(test)]
mod tests {
    use super::*;

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
