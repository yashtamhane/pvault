//! Reader for the known-answer vector files in `testdata/`, which are
//! produced by `tools/vectors/gen_vectors.py`, never by pvault itself.

use std::collections::HashMap;

/// One `key = value` record.
pub(crate) type Record = HashMap<String, String>;

/// Splits a vector file into records separated by blank lines. Lines starting
/// with `#` are comments.
pub(crate) fn records(text: &str) -> Vec<Record> {
    let mut out = Vec::new();
    let mut current = Record::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            continue;
        }
        // `trim` removes the space after `=` when the value is empty.
        let (key, value) = line.split_once(" =").expect("malformed vector line");
        assert!(
            current
                .insert(key.to_owned(), value.trim_start().to_owned())
                .is_none(),
            "duplicate key {key}"
        );
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// Decodes lowercase or uppercase hex.
pub(crate) fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex length");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

/// Field accessor with a clear failure message.
pub(crate) fn field<'a>(record: &'a Record, key: &str) -> &'a str {
    record
        .get(key)
        .unwrap_or_else(|| panic!("vector record lacks {key}"))
}

/// Hex field accessor.
pub(crate) fn hex_field(record: &Record, key: &str) -> Vec<u8> {
    hex(field(record, key))
}
