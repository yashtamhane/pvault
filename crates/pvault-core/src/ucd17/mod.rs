//! Frozen Unicode 17.0.0 data for generated-word handling, `H_w_v1`
//! (spec 7.3; `docs/M3_READINESS.md` D2).
//!
//! `H_w_v1` must give the same bytes in every pvault release. These tables are
//! therefore vendored and never follow a crate or toolchain update. They are
//! produced offline by `tools/unicode/gen_ucd17.py` from the hash-pinned UCD
//! archive. A future Unicode algorithm would be `H_w_v2`, a format revision.
//!
//! Custom passphrases (H_c) do **not** use these tables. They use the pinned
//! `unicode-normalization` crate, whose Unicode version may only increase.

// Generated tables; `UNICODE_VERSION` is read only by tests.
#[rustfmt::skip]
#[allow(dead_code)]
mod tables;

/// The frozen Unicode version of these tables.
#[cfg(test)]
pub(crate) const UNICODE_VERSION: (u8, u8, u8) = tables::UNICODE_VERSION;

const S_BASE: u32 = 0xAC00;
const L_BASE: u32 = 0x1100;
const V_BASE: u32 = 0x1161;
const T_BASE: u32 = 0x11A7;
const L_COUNT: u32 = 19;
const V_COUNT: u32 = 21;
const T_COUNT: u32 = 28;
const N_COUNT: u32 = V_COUNT * T_COUNT;
const S_COUNT: u32 = L_COUNT * N_COUNT;

fn in_ranges(ranges: &[(u32, u32)], cp: u32) -> bool {
    ranges
        .binary_search_by(|&(lo, hi)| {
            if hi < cp {
                core::cmp::Ordering::Less
            } else if lo > cp {
                core::cmp::Ordering::Greater
            } else {
                core::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Whether `c` is assigned (General_Category is not `Cn`) in Unicode 17.0.0.
/// Private-use code points are assigned.
pub(crate) fn is_assigned(c: char) -> bool {
    in_ranges(tables::ASSIGNED, u32::from(c))
}

/// Whether `c` has the `White_Space` property in Unicode 17.0.0.
pub(crate) fn is_white_space(c: char) -> bool {
    in_ranges(tables::WHITE_SPACE, u32::from(c))
}

/// Canonical combining class.
pub(crate) fn ccc(c: char) -> u8 {
    let cp = u32::from(c);
    tables::CCC
        .binary_search_by_key(&cp, |&(k, _)| k)
        .map_or(0, |i| tables::CCC[i].1)
}

fn mapping(index: &[(u32, u16, u8)], data: &'static [u32], cp: u32) -> Option<&'static [u32]> {
    let i = index.binary_search_by_key(&cp, |&(k, _, _)| k).ok()?;
    let (_, off, len) = index[i];
    data.get(usize::from(off)..usize::from(off) + usize::from(len))
}

fn emit_all(cps: &[u32], emit: &mut impl FnMut(char)) {
    // The generator emits only valid scalar values; a test checks every entry.
    for &d in cps {
        if let Some(ch) = char::from_u32(d) {
            emit(ch);
        }
    }
}

/// Full compatibility decomposition of `c`, emitted in order (not yet
/// canonically reordered).
pub(crate) fn decompose_compatible(c: char, emit: &mut impl FnMut(char)) {
    let cp = u32::from(c);
    if (S_BASE..S_BASE + S_COUNT).contains(&cp) {
        let s = cp - S_BASE;
        let parts = [
            L_BASE + s / N_COUNT,
            V_BASE + (s % N_COUNT) / T_COUNT,
            T_BASE + s % T_COUNT,
        ];
        let n = if parts[2] == T_BASE { 2 } else { 3 };
        emit_all(&parts[..n], emit);
        return;
    }
    match mapping(tables::DECOMP_INDEX, tables::DECOMP_DATA, cp) {
        Some(cps) => emit_all(cps, emit),
        None => emit(c),
    }
}

/// Primary composite of `a` followed by `b`, if one exists.
pub(crate) fn compose(a: char, b: char) -> Option<char> {
    let (a, b) = (u32::from(a), u32::from(b));
    // Hangul LV and LVT.
    if (L_BASE..L_BASE + L_COUNT).contains(&a) && (V_BASE..V_BASE + V_COUNT).contains(&b) {
        return char::from_u32(S_BASE + ((a - L_BASE) * V_COUNT + (b - V_BASE)) * T_COUNT);
    }
    if (S_BASE..S_BASE + S_COUNT).contains(&a)
        && (a - S_BASE).is_multiple_of(T_COUNT)
        && (T_BASE + 1..T_BASE + T_COUNT).contains(&b)
    {
        return char::from_u32(a + (b - T_BASE));
    }
    tables::COMPOSE
        .binary_search_by_key(&(a, b), |&(x, y, _)| (x, y))
        .ok()
        .and_then(|i| char::from_u32(tables::COMPOSE[i].2))
}

/// Full default case folding of `c` (statuses C and F).
pub(crate) fn case_fold(c: char, emit: &mut impl FnMut(char)) {
    match mapping(tables::FOLD_INDEX, tables::FOLD_DATA, u32::from(c)) {
        Some(cps) => emit_all(cps, emit),
        None => emit(c),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unicode_normalization::char as crate_char;

    #[test]
    fn version_is_frozen() {
        assert_eq!(UNICODE_VERSION, (17, 0, 0));
    }

    #[test]
    fn every_table_entry_is_a_valid_scalar_and_sorted() {
        for w in tables::ASSIGNED.windows(2) {
            assert!(w[0].1 < w[1].0);
        }
        for w in tables::CCC.windows(2) {
            assert!(w[0].0 < w[1].0);
        }
        for w in tables::COMPOSE.windows(2) {
            assert!((w[0].0, w[0].1) < (w[1].0, w[1].1));
        }
        for &d in tables::DECOMP_DATA.iter().chain(tables::FOLD_DATA) {
            assert!(char::from_u32(d).is_some(), "{d:#x}");
        }
        for &(a, b, c) in tables::COMPOSE {
            for x in [a, b, c] {
                assert!(char::from_u32(x).is_some());
            }
        }
    }

    /// The pinned `unicode-normalization` 0.1.25 is also Unicode 17.0.0, so
    /// the two independently produced data sets must agree everywhere today.
    /// (Later crate updates do not affect `H_w_v1`.)
    #[test]
    fn agrees_with_the_crate_at_unicode_17() {
        assert_eq!(unicode_normalization::UNICODE_VERSION, (17, 0, 0));
        for cp in 0..=0x10FFFFu32 {
            let Some(c) = char::from_u32(cp) else {
                continue;
            };
            assert_eq!(
                ccc(c),
                crate_char::canonical_combining_class(c),
                "ccc {cp:#x}"
            );
            let mut ours = Vec::new();
            decompose_compatible(c, &mut |d| ours.push(d));
            let mut theirs = Vec::new();
            crate_char::decompose_compatible(c, |d| theirs.push(d));
            assert_eq!(ours, theirs, "decomposition {cp:#x}");
            let private = (0xE000..=0xF8FF).contains(&cp)
                || (0xF0000..=0xFFFFD).contains(&cp)
                || (0x100000..=0x10FFFD).contains(&cp);
            assert_eq!(
                is_assigned(c),
                crate_char::is_public_assigned(c) || private,
                "assigned {cp:#x}"
            );
        }
        for &(a, b, c) in tables::COMPOSE {
            let (a, b) = (char::from_u32(a).unwrap(), char::from_u32(b).unwrap());
            assert_eq!(crate_char::compose(a, b), char::from_u32(c));
        }
    }

    #[test]
    fn case_folding_examples() {
        let fold = |s: &str| {
            let mut out = String::new();
            for c in s.chars() {
                case_fold(c, &mut |d| out.push(d));
            }
            out
        };
        assert_eq!(fold("Straße"), "strasse");
        assert_eq!(fold("ΣΑΣ"), "σασ");
        assert_eq!(fold("\u{130}"), "i\u{307}"); // default, not Turkic
        assert_eq!(fold("\u{AB70}"), "\u{13A0}"); // Cherokee folds to uppercase
        assert_eq!(fold("ﬁ"), "fi");
    }

    #[test]
    fn white_space_is_the_frozen_set() {
        let expected: Vec<u32> = (0x09..=0x0D)
            .chain([0x20, 0x85, 0xA0, 0x1680])
            .chain(0x2000..=0x200A)
            .chain([0x2028, 0x2029, 0x202F, 0x205F, 0x3000])
            .collect();
        let ours: Vec<u32> = (0..=0x10FFFFu32)
            .filter(|&cp| char::from_u32(cp).is_some_and(is_white_space))
            .collect();
        assert_eq!(ours, expected);
    }
}
