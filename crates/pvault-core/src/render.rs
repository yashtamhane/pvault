//! Safe rendering of paths and names for output (`docs/CLI.md` 1.2;
//! approved for Milestone 4, A1). Every path or file name pvault prints goes
//! through here, so no output can carry terminal control sequences or
//! reorder text. The escaping is unambiguous and reversible.

use std::fmt::Write;
use std::path::Path;

use crate::ucd17;

fn escaped(c: char) -> bool {
    let cp = u32::from(c);
    cp <= 0x1F
        || (0x7F..=0x9F).contains(&cp)
        || cp == 0x2028
        || cp == 0x2029
        || matches!(cp, 0x061C | 0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069)
        || cp == 0xFEFF
        || !ucd17::is_assigned(c)
}

/// Renders text: `\` → `\\`; listed characters → `\u{XXXX}`.
pub fn text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\\' {
            out.push_str("\\\\");
        } else if escaped(c) {
            let _ = write!(out, "\\u{{{:04X}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

/// Renders a native path: invalid UTF-8 bytes as `\xHH` (Unix), unpaired
/// surrogates as `\u{D800}` style (Windows).
pub fn path(p: &Path) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let mut out = String::new();
        let mut bytes = p.as_os_str().as_bytes();
        while !bytes.is_empty() {
            match std::str::from_utf8(bytes) {
                Ok(s) => {
                    out.push_str(&text(s));
                    break;
                }
                Err(e) => {
                    let (good, rest) = bytes.split_at(e.valid_up_to());
                    out.push_str(&text(std::str::from_utf8(good).unwrap_or("")));
                    let bad = e.error_len().unwrap_or(rest.len()).max(1);
                    for b in &rest[..bad] {
                        let _ = write!(out, "\\x{b:02X}");
                    }
                    bytes = &rest[bad..];
                }
            }
        }
        out
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let units: Vec<u16> = p.as_os_str().encode_wide().collect();
        let mut out = String::new();
        for r in char::decode_utf16(units.iter().copied()) {
            match r {
                Ok(c) => out.push_str(&text(c.encode_utf8(&mut [0u8; 4]))),
                Err(e) => {
                    let _ = write!(out, "\\u{{{:04X}}}", e.unpaired_surrogate());
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_controls_bidi_and_backslash() {
        assert_eq!(text("a\u{9b}[2Jb"), "a\\u{009B}[2Jb");
        assert_eq!(text("x\u{1b}y\u{7}"), "x\\u{001B}y\\u{0007}");
        assert_eq!(text("ab\u{202e}cd"), "ab\\u{202E}cd");
        assert_eq!(text("\u{feff}a\u{2028}"), "\\u{FEFF}a\\u{2028}");
        assert_eq!(text("a\\b"), "a\\\\b");
        assert_eq!(text("caf\u{e9} 日本"), "caf\u{e9} 日本");
        assert_eq!(text("\u{378}"), "\\u{0378}");
        assert_eq!(text("\u{fdd0}"), "\\u{FDD0}");
    }

    #[cfg(unix)]
    #[test]
    fn invalid_utf8_bytes() {
        use std::os::unix::ffi::OsStrExt;
        let p = Path::new(std::ffi::OsStr::from_bytes(b"a\xffb\x1b"));
        assert_eq!(path(p), "a\\xFFb\\u{001B}");
    }
}
