use super::*;
use crate::input::{ByteSource, read_line};
use crate::shamir;
use crate::testvec::{field, hex_field, records};

struct Bytes(Vec<u8>, usize);

impl ByteSource for Bytes {
    fn next_byte(&mut self) -> std::io::Result<Option<u8>> {
        let b = self.0.get(self.1).copied();
        self.1 += 1;
        Ok(b)
    }
}

pub(crate) fn sample_cards() -> (Card, Card) {
    let secret = SecretBytes::take_from(&mut [0x5a; SECRET_LEN]).unwrap();
    let shares = shamir::split_2_of_2(&secret).unwrap();
    let a = Card::new(&[0xa1; 16], CardMode::Portable, &[0xc5; 8], &shares[0]).unwrap();
    let b = Card::new(&[0xa1; 16], CardMode::Portable, &[0xc5; 8], &shares[1]).unwrap();
    (a, b)
}

/// A card with fixed share bytes, so its QR code is the same in every run.
pub(crate) fn fixed_card(x: u8, fill: u8) -> Card {
    let y = SecretBytes::take_from(&mut [fill; SECRET_LEN]).unwrap();
    let share = Share::new(x, y).unwrap();
    Card::new(&[0xa1; 16], CardMode::Portable, &[0xc5; 8], &share).unwrap()
}

fn owned(p: &[u8; PAYLOAD_LEN]) -> SecretBytes<PAYLOAD_LEN> {
    SecretBytes::take_from(&mut p.to_vec()).unwrap()
}

#[test]
fn payload_round_trip_and_fields() {
    let (a, b) = sample_cards();
    assert_eq!(a.role(), "Card A");
    assert_eq!(b.role(), "Card B");
    assert_eq!(&a.payload()[..5], b"PVC1\x01");
    let again = Card::parse(owned(a.payload())).unwrap();
    assert!(again.matches(&owned(a.payload())));
    assert!(!again.matches(&owned(b.payload())));
    let text = a.base32();
    assert_eq!(text.len(), SYMBOLS);
    let decoded = decode_base32(text.expose_secret()).unwrap();
    assert_eq!(decoded.expose_secret(), a.payload());
    assert_eq!(a.base32_lines().len(), 7);
    let combined = shamir::combine(&a.share().unwrap(), &b.share().unwrap()).unwrap();
    assert_eq!(combined.expose_secret(), &[0x5a; SECRET_LEN]);
}

/// Independent Python vector for all three representations required by 7.4a.
#[test]
fn independent_payload_base32_and_qr_vector() {
    let all = records(include_str!("../../testdata/pvault_card.txt"));
    assert_eq!(all.len(), 1);
    let vector = &all[0];

    let payload = hex_field(vector, "payload");
    let card = Card::parse(SecretBytes::take_from(&mut payload.clone()).unwrap()).unwrap();
    assert_eq!(card.vault_id().as_slice(), hex_field(vector, "vault_id"));
    assert_eq!(card.mode().byte().to_string(), field(vector, "mode"));
    assert_eq!(card.set_id().as_slice(), hex_field(vector, "set_id"));
    assert_eq!(card.x().to_string(), field(vector, "share_x"));
    assert_eq!(
        card.share().unwrap().y().expose_secret().as_slice(),
        hex_field(vector, "share")
    );
    assert_eq!(
        card.base32().expose_secret(),
        field(vector, "base32").as_bytes()
    );

    let (width, dark) = qr_matrix(card.payload()).unwrap();
    assert_eq!(width.to_string(), field(vector, "qr_width"));
    let mut packed = vec![0u8; dark.len().div_ceil(8)];
    for (i, &module) in dark.iter().enumerate() {
        if module {
            packed[i / 8] |= 1 << (7 - i % 8);
        }
    }
    assert_eq!(packed, hex_field(vector, "qr_bits"));
}

/// F93: card-file format 1 against the independent Python rendering, byte
/// for byte; the reader returns the vector's payload.
#[test]
fn independent_card_file_vector() {
    use sha2::{Digest, Sha256};
    let vector = &records(include_str!("../../testdata/pvault_card.txt"))[0];
    let file: &[u8] = include_bytes!("../../testdata/pvault_card_a.svg");
    assert_eq!(field(vector, "file"), "pvault_card_a.svg");
    assert_eq!(file.len().to_string(), field(vector, "file_len"));
    assert_eq!(
        Sha256::digest(file).as_slice(),
        hex_field(vector, "file_sha256")
    );
    let payload = hex_field(vector, "payload");
    let card = Card::parse(SecretBytes::take_from(&mut payload.clone()).unwrap()).unwrap();
    let rendered = render_svg(&card, field(vector, "file_created")).unwrap();
    assert_eq!(rendered.as_bytes(), file);
    assert_eq!(parse_card_file(file).unwrap().payload().as_slice(), payload);
}

/// F61: invalid payloads are refused; substitutions decode.
#[test]
fn invalid_payloads_and_substitutions() {
    let (a, _) = sample_cards();
    let mutate = |at: usize, v: u8| {
        let mut p = *a.payload();
        p[at] = v;
        Card::parse(owned(&p)).unwrap_err()
    };
    assert_eq!(mutate(0, b'X'), CardError::NotACard); // magic
    assert_eq!(mutate(4, 2), CardError::NotACard); // version
    assert_eq!(mutate(134, a.payload()[134] ^ 1), CardError::NotACard); // check
    assert_eq!(mutate(40, a.payload()[40] ^ 1), CardError::NotACard); // share bit under check
    // Mode and x-coordinate, with a recomputed check.
    let resigned = |at: usize, v: u8| {
        let mut p = *a.payload();
        p[at] = v;
        let c = check_value(&p[..127]);
        p[127..].copy_from_slice(&c);
        Card::parse(owned(&p)).unwrap_err()
    };
    assert_eq!(resigned(21, 2), CardError::WrongMode);
    assert_eq!(resigned(30, 3), CardError::WrongShare); // portable with x = 3
    assert_eq!(resigned(21, 0), CardError::WrongShare); // bound with x = 1
    // Foreign vault and old set.
    assert_eq!(
        a.check_for_vault(&[0xa2; 16], &[0xc5; 8], CardMode::Portable),
        Err(CardError::OtherVault)
    );
    assert_eq!(
        a.check_for_vault(&[0xa1; 16], &[0xc6; 8], CardMode::Portable),
        Err(CardError::OldCard)
    );
    assert_eq!(
        a.check_for_vault(&[0xa1; 16], &[0xc5; 8], CardMode::Bound),
        Err(CardError::WrongMode)
    );
    assert!(
        a.check_for_vault(&[0xa1; 16], &[0xc5; 8], CardMode::Portable)
            .is_ok()
    );
    // Base32: lower case, I/L/O substitutions, separators; U refused.
    let text = String::from_utf8(a.base32().expose_secret().to_vec()).unwrap();
    let sub = text.replace('1', "l").replace('0', "o").to_lowercase();
    let spaced: String = sub
        .chars()
        .enumerate()
        .flat_map(|(i, c)| if i % 4 == 3 { vec![c, '-'] } else { vec![c] })
        .collect();
    assert_eq!(
        decode_base32(spaced.as_bytes()).unwrap().expose_secret(),
        a.payload()
    );
    let mut bad = text.clone().into_bytes();
    bad[10] = b'U';
    assert_eq!(
        decode_base32(&bad).unwrap_err(),
        CardTextError::InvalidChar(11)
    );
    assert!(matches!(
        decode_base32(&text.as_bytes()[..215]),
        Err(CardTextError::TooFew(215))
    ));
    let mut long = text.clone();
    long.push('0');
    assert_eq!(
        decode_base32(long.as_bytes()).unwrap_err(),
        CardTextError::TooMany
    );
}

/// F65: combination inputs are checked before any combination.
#[test]
fn pair_checks() {
    let (a, b) = sample_cards();
    assert!(check_pair(&a, &b).is_ok());
    let a2 = Card::parse(owned(a.payload())).unwrap();
    assert_eq!(check_pair(&a, &a2), Err(CardError::Duplicate(1)));
    assert_eq!(
        CardError::Duplicate(1).to_string(),
        "These two cards are both Card A."
    );
    let secret = SecretBytes::take_from(&mut [1; SECRET_LEN]).unwrap();
    let other = shamir::split_2_of_2(&secret).unwrap();
    let foreign_set = Card::new(&[0xa1; 16], CardMode::Portable, &[0xc6; 8], &other[1]).unwrap();
    assert_eq!(check_pair(&a, &foreign_set), Err(CardError::DifferentSets));
}

fn lines_reader(input: &str) -> Result<SecretBytes<PAYLOAD_LEN>, CardTextError> {
    let mut source = Bytes(input.as_bytes().to_vec(), 0);
    let mut reader = CardTextReader::new();
    loop {
        let line = match read_line(&mut source) {
            Ok(l) => l,
            Err(_) => return Err(reader.ended()),
        };
        if reader.push_line(&line)? == CardTextProgress::Complete {
            return reader.payload();
        }
    }
}

/// Whole-line card input boundaries (`docs/CLI.md` 2).
#[test]
fn card_text_boundaries() {
    let (a, _) = sample_cards();
    let text = String::from_utf8(a.base32().expose_secret().to_vec()).unwrap();
    let printed = a.base32_lines().join("\n");
    // One line, with and without separators; terminator required.
    assert_eq!(
        lines_reader(&format!("{text}\n")).unwrap().expose_secret(),
        a.payload()
    );
    assert_eq!(
        lines_reader(&format!("{}\r\n", a.base32_lines().join(" ")))
            .unwrap()
            .expose_secret(),
        a.payload()
    );
    assert_eq!(
        lines_reader(&text).unwrap_err(),
        CardTextError::Unterminated
    );
    // As printed on 7 lines; nothing after the seventh is read.
    let mut source = Bytes(format!("{printed}\nEXTRA LINE\n").into_bytes(), 0);
    let mut reader = CardTextReader::new();
    let mut lines = 0;
    loop {
        lines += 1;
        let line = read_line(&mut source).unwrap();
        if reader.push_line(&line).unwrap() == CardTextProgress::Complete {
            break;
        }
    }
    assert_eq!(lines, 7);
    assert_eq!(read_line(&mut source).unwrap().as_bytes(), b"EXTRA LINE");
    // 200 symbols, then a line of 17: rejected as a whole.
    let first = &text[..200];
    let rest = &text[200..];
    assert_eq!(
        lines_reader(&format!("{first}\n{rest}0\n")).unwrap_err(),
        CardTextError::TooMany
    );
    // The 217th symbol on the same line as the 216th.
    assert_eq!(
        lines_reader(&format!("{text}0\n")).unwrap_err(),
        CardTextError::TooMany
    );
    // 215 then an empty line; 9 lines; an invalid character on the last line.
    assert_eq!(
        lines_reader(&format!("{}\n\n", &text[..215])).unwrap_err(),
        CardTextError::TooFew(215)
    );
    let nine: String = text
        .as_bytes()
        .chunks(24)
        .map(|c| format!("{}\n", std::str::from_utf8(c).unwrap()))
        .collect();
    assert_eq!(
        lines_reader(&nine).unwrap_err(),
        CardTextError::TooManyLines
    );
    let mut bad_last = format!("{}\n{}", &text[..200], &text[200..]);
    bad_last.replace_range(bad_last.len() - 1.., "U");
    bad_last.push('\n');
    assert_eq!(
        lines_reader(&bad_last).unwrap_err(),
        CardTextError::InvalidChar(16)
    );
    // End of input right after symbol 216 on a continuation line.
    assert_eq!(
        lines_reader(&format!("{first}\n{rest}")).unwrap_err(),
        CardTextError::Unterminated
    );
}

pub(crate) fn encode_png(width: usize, height: usize, gray: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, width as u32, height as u32);
        enc.set_color(png::ColorType::Grayscale);
        enc.set_depth(png::BitDepth::Eight);
        let mut w = enc.write_header().unwrap();
        w.write_image_data(gray).unwrap();
    }
    out
}

/// Renders a payload's QR matrix as a grayscale bitmap: `scale` pixels per
/// module, 4 modules of quiet zone.
pub(crate) fn qr_bitmap(payload: &[u8; PAYLOAD_LEN], scale: usize) -> (usize, Vec<u8>) {
    let (width, dark) = qr_matrix(payload).unwrap();
    let side = (width + 8) * scale;
    let mut img = vec![255u8; side * side];
    for y in 0..width {
        for x in 0..width {
            if dark[y * width + x] {
                for dy in 0..scale {
                    for dx in 0..scale {
                        img[((y + 4) * scale + dy) * side + (x + 4) * scale + dx] = 0;
                    }
                }
            }
        }
    }
    (side, img)
}

/// Rotation with bilinear resampling (closer to a photo than nearest
/// neighbor, which aliases module edges).
fn rotate(side: usize, img: &[u8], degrees: f64) -> (usize, Vec<u8>) {
    let out_side = side * 3 / 2;
    let (s, c) = degrees.to_radians().sin_cos();
    let (cx, cy) = (side as f64 / 2.0, side as f64 / 2.0);
    let (ox, oy) = (out_side as f64 / 2.0, out_side as f64 / 2.0);
    let px = |x: i64, y: i64| -> f64 {
        if x < 0 || y < 0 || x >= side as i64 || y >= side as i64 {
            255.0
        } else {
            f64::from(img[y as usize * side + x as usize])
        }
    };
    let mut out = vec![255u8; out_side * out_side];
    for y in 0..out_side {
        for x in 0..out_side {
            let (dx, dy) = (x as f64 - ox, y as f64 - oy);
            let sx = c * dx + s * dy + cx;
            let sy = -s * dx + c * dy + cy;
            let (x0, y0) = (sx.floor() as i64, sy.floor() as i64);
            let (fx, fy) = (sx - sx.floor(), sy - sy.floor());
            let v = px(x0, y0) * (1.0 - fx) * (1.0 - fy)
                + px(x0 + 1, y0) * fx * (1.0 - fy)
                + px(x0, y0 + 1) * (1.0 - fx) * fy
                + px(x0 + 1, y0 + 1) * fx * fy;
            out[y * out_side + x] = v.round().clamp(0.0, 255.0) as u8;
        }
    }
    (out_side, out)
}

fn gaussian_blur(side: usize, img: &[u8]) -> Vec<u8> {
    let kernel = [1u32, 4, 6, 4, 1];
    let mut horizontal = img.to_vec();
    for y in 0..side {
        for x in 2..side - 2 {
            let sum = (0..5)
                .map(|k| u32::from(img[y * side + x + k - 2]) * kernel[k])
                .sum::<u32>();
            horizontal[y * side + x] = (sum / 16) as u8;
        }
    }
    let mut out = horizontal.clone();
    for y in 2..side - 2 {
        for x in 0..side {
            let sum = (0..5)
                .map(|k| u32::from(horizontal[(y + k - 2) * side + x]) * kernel[k])
                .sum::<u32>();
            out[y * side + x] = (sum / 16) as u8;
        }
    }
    out
}

/// A mild photographed-page trapezoid, inverse-mapped with nearest-neighbor
/// sampling. The bottom edge is inset by `inset` pixels on each side.
fn perspective(side: usize, img: &[u8], inset: usize) -> Vec<u8> {
    let mut out = vec![255u8; side * side];
    for y in 0..side {
        let edge = inset * y / side;
        let span = side.saturating_sub(edge * 2).max(1);
        for x in edge..side - edge {
            let sx = ((x - edge) * side / span).min(side - 1);
            out[y * side + x] = img[y * side + sx];
        }
    }
    out
}

/// Deterministic compression-like 8x8 blocking: coarsen luminance and add a
/// small alternating block bias, without using a JPEG decoder in the PNG-only
/// input path.
fn jpeg_like(side: usize, img: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; img.len()];
    for y in 0..side {
        for x in 0..side {
            let p = i32::from(img[y * side + x]);
            let bias = if ((x / 8) + (y / 8)) % 2 == 0 { -6 } else { 6 };
            let biased = (p + bias).clamp(0, 255);
            out[y * side + x] = ((biased + 8) / 16 * 16).clamp(0, 255) as u8;
        }
    }
    out
}

fn noisy(img: &[u8], amp: i32, seed: u32) -> Vec<u8> {
    let mut state = seed | 1;
    img.iter()
        .map(|&p| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let n = (state % (2 * amp as u32 + 1)) as i32 - amp;
            (i32::from(p) + n).clamp(0, 255) as u8
        })
        .collect()
}

fn decode_gray(side: usize, img: &[u8]) -> Result<SecretBytes<PAYLOAD_LEN>, PngError> {
    decode_png(&encode_png(side, side, img))
}

/// Synthetic distortions (approved QR-photo direction; the printed-photo
/// check is a separate manual gate). Asserts the conditions that decode
/// reliably; `qr_reliability_measurement` records the rest.
#[test]
fn qr_round_trips_through_synthetic_distortions() {
    for a in [fixed_card(1, 0x5a), fixed_card(2, 0x3c)] {
        // Relative to 4 px/module, this covers 0.5x through 4x.
        for scale in [2usize, 4, 8, 16] {
            let (side, img) = qr_bitmap(a.payload(), scale);
            assert!(
                a.matches(&decode_gray(side, &img).unwrap()),
                "scale {scale}"
            );
        }
        let (side, img) = qr_bitmap(a.payload(), 6);
        for deg in [5.0, 15.0, 30.0, 45.0] {
            let (s, r) = rotate(side, &img, deg);
            assert!(a.matches(&decode_gray(s, &r).unwrap()), "rotation {deg}");
        }
        assert!(
            a.matches(&decode_gray(side, &gaussian_blur(side, &img)).unwrap()),
            "Gaussian blur"
        );
        assert!(
            a.matches(&decode_gray(side, &perspective(side, &img, side / 48)).unwrap()),
            "perspective"
        );
        assert!(
            a.matches(&decode_gray(side, &jpeg_like(side, &img)).unwrap()),
            "JPEG-like blocking"
        );
        let low: Vec<u8> = img.iter().map(|&p| if p == 0 { 90 } else { 170 }).collect();
        assert!(a.matches(&decode_gray(side, &low).unwrap()), "low contrast");
        for seed in 1..=5u32 {
            let n = noisy(&img, 20, seed.wrapping_mul(0x9E37_79B9));
            assert!(
                a.matches(&decode_gray(side, &n).unwrap()),
                "noise seed {seed}"
            );
        }
    }
}

/// Measurement for SI-09 (run explicitly): decode rates under noise and
/// rotation at several module sizes. A miss is a measured limitation, never
/// a wrong payload: a decoded payload always equals the card.
#[test]
#[ignore = "measurement; run with --ignored --nocapture"]
fn qr_reliability_measurement() {
    let cards: Vec<Card> = (0..20).map(|_| sample_cards().0).collect();
    for amp in [10, 20, 30, 40, 60, 80] {
        let mut ok = 0;
        for (i, a) in cards.iter().enumerate() {
            let (side, img) = qr_bitmap(a.payload(), 6);
            for seed in 1..=4u32 {
                if let Ok(p) = decode_gray(
                    side,
                    &noisy(&img, amp, (i as u32 * 7 + seed).wrapping_mul(0x9E37_79B9)),
                ) {
                    assert!(a.matches(&p), "a decoded payload must equal the card");
                    ok += 1;
                }
            }
        }
        println!("noise ±{amp}, 6 px/module: {ok}/80 decoded");
    }
    for scale in [2usize, 3, 4, 6] {
        let mut ok = 0;
        for a in &cards {
            let (sd, im) = qr_bitmap(a.payload(), scale);
            for deg in (0..=45).step_by(5) {
                let (s2, r) = rotate(sd, &im, f64::from(deg));
                if let Ok(p) = decode_gray(s2, &r) {
                    assert!(a.matches(&p), "a decoded payload must equal the card");
                    ok += 1;
                }
            }
        }
        println!("scale {scale} px/module, rotations 0..=45 step 5: {ok}/200 decoded");
    }
}

/// 7.4c limits and structure.
#[test]
fn png_limits() {
    let (a, b) = sample_cards();
    assert_eq!(decode_png(b"not a png").unwrap_err(), PngError::NotPng);
    assert_eq!(
        decode_png(&vec![0u8; MAX_PNG_FILE as usize + 1]).unwrap_err(),
        PngError::TooLarge
    );
    // A declared width over 4096 is refused before any pixel allocation.
    let big = encode_png(4097, 1, &vec![255u8; 4097]);
    assert_eq!(decode_png(&big).unwrap_err(), PngError::TooLarge);
    // Blank image: no code.
    assert_eq!(
        decode_png(&encode_png(64, 64, &[255u8; 64 * 64])).unwrap_err(),
        PngError::NoCode
    );
    // Two codes side by side.
    let (side, ia) = qr_bitmap(a.payload(), 3);
    let (_, ib) = qr_bitmap(b.payload(), 3);
    let mut two = vec![255u8; side * 2 * side];
    for y in 0..side {
        two[y * 2 * side..y * 2 * side + side].copy_from_slice(&ia[y * side..(y + 1) * side]);
        two[y * 2 * side + side..(y + 1) * 2 * side].copy_from_slice(&ib[y * side..(y + 1) * side]);
    }
    assert_eq!(
        decode_png(&encode_png(side * 2, side, &two)).unwrap_err(),
        PngError::MultipleCodes
    );
    // An animated PNG (acTL chunk) is refused.
    let mut apng = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut apng, side as u32, side as u32);
        enc.set_color(png::ColorType::Grayscale);
        enc.set_depth(png::BitDepth::Eight);
        enc.set_animated(1, 0).unwrap();
        let mut w = enc.write_header().unwrap();
        w.write_image_data(&ia).unwrap();
    }
    assert_eq!(decode_png(&apng).unwrap_err(), PngError::Animated);
}

#[test]
fn svg_contains_labels_and_text_but_no_passphrase() {
    let (a, _) = sample_cards();
    let svg = render_svg(&a, "2026-10-05").unwrap();
    assert!(svg.starts_with("<?xml"));
    assert!(svg.contains("pvault recovery card: Card A"));
    assert!(svg.contains(&format!("Vault ID: {}", "a1".repeat(16))));
    assert!(svg.contains(&format!("Card set: {}", "c5".repeat(8))));
    assert!(svg.contains("Created: 2026-10-05"));
    for line in a.base32_lines().iter() {
        assert!(svg.contains(line.as_str()));
    }
}

/// F93: the card-file reader accepts only unmodified format 1 files.
#[test]
fn card_file_reader_format_1() {
    let (a, b) = sample_cards();
    let file = render_svg(&a, "2026-10-06").unwrap();
    let bytes = file.as_bytes();
    let read = parse_card_file(bytes).unwrap();
    assert_eq!(read.payload(), a.payload());
    let other = render_svg(&b, "2026-10-06").unwrap();
    assert_eq!(parse_card_file(other.as_bytes()).unwrap().x(), 2);
    let not = Err(CardFileError::NotFormat1);
    // One changed byte anywhere: in the text, the QR path, a label, the date.
    let text_at = bytes
        .windows(15)
        .position(|w| w == b"font-size=\"16\">")
        .unwrap()
        + 16;
    let path_at = bytes.windows(3).position(|w| w == b"d=\"").unwrap() + 10;
    let label_at = bytes.windows(10).position(|w| w == b"Vault ID: ").unwrap() + 10;
    let date_at = bytes.windows(9).position(|w| w == b"Created: ").unwrap() + 9;
    for at in [text_at, path_at, label_at, 0, bytes.len() - 1] {
        let mut changed = bytes.to_vec();
        changed[at] = if changed[at] == b'1' { b'2' } else { b'1' };
        assert_eq!(parse_card_file(&changed).map(|_| ()), not, "byte {at}");
    }
    // The creation date is a label outside the payload: a malformed date is
    // rejected; another well-formed date is simply another valid rendering.
    let mut bad_date = bytes.to_vec();
    bad_date[date_at] = b'X';
    assert_eq!(parse_card_file(&bad_date).map(|_| ()), not);
    // A second card appended; a missing Base32 line; CRLF; a BOM; a DOCTYPE.
    let two = [bytes, other.as_bytes()].concat();
    assert_eq!(parse_card_file(&two).map(|_| ()), not);
    let first_line = text_at - 16;
    let line_end = first_line
        + bytes[first_line..]
            .windows(8)
            .position(|w| w == b"</text>\n")
            .unwrap()
        + 8;
    let missing = [&bytes[..first_line], &bytes[line_end..]].concat();
    assert_eq!(parse_card_file(&missing).map(|_| ()), not);
    let crlf = String::from_utf8(bytes.to_vec())
        .unwrap()
        .replace('\n', "\r\n");
    assert_eq!(parse_card_file(crlf.as_bytes()).map(|_| ()), not);
    let bom = [&[0xEF, 0xBB, 0xBF][..], bytes].concat();
    assert_eq!(parse_card_file(&bom).map(|_| ()), not);
    let decl_end = bytes.iter().position(|&c| c == b'\n').unwrap() + 1;
    let doctype = [
        &bytes[..decl_end],
        b"<!DOCTYPE svg [<!ENTITY x \"y\">]>\n",
        &bytes[decl_end..],
    ]
    .concat();
    assert_eq!(parse_card_file(&doctype).map(|_| ()), not);
    // Size limit, checked before anything else.
    let big = vec![b' '; MAX_CARD_FILE as usize + 1];
    assert_eq!(
        parse_card_file(&big).map(|_| ()),
        Err(CardFileError::TooLarge)
    );
    // A valid file with another date is a different, equally valid file.
    let dated = render_svg(&a, "2027-01-02").unwrap();
    assert!(parse_card_file(dated.as_bytes()).is_ok());
}

/// F94: pair validation, separate from the per-file check.
#[test]
fn pair_validation() {
    let (a, b) = sample_cards();
    assert!(check_pair(&a, &b).is_ok());
    assert!(check_portable_roles(&a, &b).is_ok());
    // The same card twice; two Card A; two Card B.
    assert_eq!(check_pair(&a, &a), Err(CardError::Duplicate(1)));
    assert_eq!(check_pair(&b, &b), Err(CardError::Duplicate(2)));
    let a2 = fixed_card(1, 0x11);
    assert_eq!(check_pair(&a, &a2), Err(CardError::Duplicate(1)));
    // Roles in the named positions.
    assert_eq!(check_portable_roles(&b, &a), Err(CardError::WrongRole(1)));
    // Different vaults; different card sets.
    let share = b.share().unwrap();
    let other_vault = Card::new(&[0xb2; 16], CardMode::Portable, &[0xc5; 8], &share).unwrap();
    assert_eq!(
        check_pair(&a, &other_vault),
        Err(CardError::DifferentVaults)
    );
    let other_set = Card::new(&[0xa1; 16], CardMode::Portable, &[0xd6; 8], &share).unwrap();
    assert_eq!(check_pair(&a, &other_set), Err(CardError::DifferentSets));
    assert_eq!(
        CardError::DifferentSets.to_string(),
        "These two cards are from different card sets."
    );
}
