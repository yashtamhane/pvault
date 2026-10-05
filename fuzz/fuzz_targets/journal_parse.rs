//! Journal parser (spec 8.1): never panics; an accepted record is exactly
//! its canonical encoding.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pvault_core::journal::Record;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = Record::parse(data) {
        assert_eq!(r.encode(), data);
    }
});
