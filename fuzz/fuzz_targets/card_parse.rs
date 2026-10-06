//! Recovery-card payload and text parsers (spec 7.4a) and the card-file
//! reader (format 1, spec 7.4d): never panic; a valid payload round-trips
//! through its exact Base32 form; an accepted card file is exactly the
//! rendering of its payload and date.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pvault_core::card::{
    Card, PAYLOAD_LEN, card_file_date, decode_base32, parse_card_file, render_svg,
};
use pvault_core::secrets::SecretBytes;

fuzz_target!(|data: &[u8]| {
    let _ = decode_base32(data);
    if let Ok(card) = parse_card_file(data) {
        let date = card_file_date(core::str::from_utf8(data).unwrap()).unwrap();
        assert_eq!(render_svg(&card, date).unwrap().as_bytes(), data);
    }
    if data.len() == PAYLOAD_LEN {
        let payload = SecretBytes::<PAYLOAD_LEN>::take_from(&mut data.to_vec()).unwrap();
        if let Ok(card) = Card::parse(payload) {
            let text = card.base32();
            let decoded = decode_base32(text.expose_secret()).unwrap();
            assert_eq!(decoded.expose_secret(), card.payload());
        }
    }
});
