//! Header parser (spec 4.3, 4.4): never panics; a parsed header re-encodes
//! to its own core and slots bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pvault_core::header::Header;

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = Header::parse(data) {
        assert_eq!(h.raw(), data);
        assert_eq!(h.core().encode().unwrap(), h.core_bytes());
        assert_eq!(h.slots().encode().unwrap(), h.slots_bytes());
    }
});
