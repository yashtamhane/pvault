//! Chunked stream parser (spec 7.7) with fixed keys: never panics, and never
//! outputs more than the bound it was given.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pvault_core::crypto::cascade::{self, Expected, StreamKeys, StreamKind};
use pvault_core::secrets::SecretBytes;

fuzz_target!(|data: &[u8]| {
    let keys = StreamKeys::new(
        SecretBytes::take_from(&mut [1; 32]).unwrap(),
        SecretBytes::take_from(&mut [2; 32]).unwrap(),
    );
    let expected = Expected {
        kind: StreamKind::Object,
        stream_id: [3; 16],
        context: 0,
        plain_size: None,
        max_plain_size: 1 << 20,
    };
    let mut out = Vec::new();
    if cascade::decrypt(&keys, &expected, data, &mut out).is_ok() {
        assert!(out.len() <= 1 << 20);
    }
});
