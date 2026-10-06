//! Recovery-card payload and text parsers (spec 7.4a): never panic; a valid
//! payload round-trips through its exact Base32 form.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pvault_core::card::{Card, PAYLOAD_LEN, decode_base32};
use pvault_core::secrets::SecretBytes;

fuzz_target!(|data: &[u8]| {
    let _ = decode_base32(data);
    if data.len() == PAYLOAD_LEN {
        let payload = SecretBytes::<PAYLOAD_LEN>::take_from(&mut data.to_vec()).unwrap();
        if let Ok(card) = Card::parse(payload) {
            let text = card.base32();
            let decoded = decode_base32(text.expose_secret()).unwrap();
            assert_eq!(decoded.expose_secret(), card.payload());
        }
    }
});
