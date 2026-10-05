//! Key-table plaintext decoder (spec 7.8; D3): never panics; an accepted
//! table re-encodes to the same bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pvault_core::keytable::KeyTable;

fuzz_target!(|data: &[u8]| {
    if let Ok(t) = KeyTable::decode(data) {
        assert_eq!(t.encode().unwrap().expose_secret(), data);
    }
});
