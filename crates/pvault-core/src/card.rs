//! Recovery cards (spec 7.4a to 7.4c; approved for Milestone 4).
//!
//! - **Payload** (135 bytes): `"PVC1" || u8(1) || vault_id[16] || u8(mode)
//!   || set_id[8] || u8(share_x) || share[96] || check[8]`, where `check` is
//!   the first 8 bytes of `SHA-512("pvault/v1/card" || all preceding bytes)`.
//! - **Typed form:** Crockford Base32 of the payload as one big-endian bit
//!   string, 216 symbols, printed in groups of 4, 8 groups per line (7 lines).
//!   Input: case-insensitive, `I`/`L` read as `1`, `O` as `0`, spaces and
//!   hyphens ignored, anything else refused.
//! - **Card text input** is read and validated whole lines at a time and is
//!   accepted only when a complete, terminated final line brings the count to
//!   exactly 216 ([`CardTextReader`]; `docs/CLI.md` 2).
//! - **QR:** the raw payload in byte mode, error correction M, rendered as
//!   SVG; input from a PNG under the 7.4c limits, decoded with `rqrr`.
//!
//! Every buffer that holds share material is wiped. `rqrr` and `png` keep
//! internal buffers of their own, which pvault cannot wipe; they hold image
//! data derived from the share and are freed when decoding ends.

use std::fmt;

use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::errors::Error;
use crate::input::SecretLine;
use crate::secrets::{SecretBuf, SecretBytes};
use crate::shamir::{SECRET_LEN, Share};

/// Payload length in bytes.
pub const PAYLOAD_LEN: usize = 135;
/// Base32 symbols in the typed form.
pub const SYMBOLS: usize = 216;
/// Largest PNG file accepted (7.4c).
pub const MAX_PNG_FILE: u64 = 16 << 20;
/// Largest PNG width or height (7.4c).
pub const MAX_PNG_SIDE: u32 = 4096;
/// Largest decoded PNG buffer (7.4c).
pub const MAX_PNG_BUFFER: usize = 64 << 20;
/// Most lines one typed card text may span.
pub const MAX_TEXT_LINES: usize = 8;

const MAGIC: &[u8; 4] = b"PVC1";
const VERSION: u8 = 1;
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The mode byte of a card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardMode {
    /// 0: the bound card (x = 3).
    Bound,
    /// 1: portable Card A (x = 1) or Card B (x = 2).
    Portable,
}

impl CardMode {
    fn byte(self) -> u8 {
        match self {
            Self::Bound => 0,
            Self::Portable => 1,
        }
    }
}

/// Card structure and combination errors. Their messages depend only on the
/// card's own public fields and the vault's public header (5.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardError {
    /// Wrong magic, version, length or check value.
    NotACard,
    /// `vault_id` differs from the vault's.
    OtherVault,
    /// `set_id` differs from the vault's current card set.
    OldCard,
    /// `mode` differs from the vault's mode, or is not 0 or 1.
    WrongMode,
    /// `share_x` is not valid for the mode.
    WrongShare,
    /// Two cards with the same x-coordinate.
    Duplicate(u8),
}

impl fmt::Display for CardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotACard => "This is not a pvault recovery card.",
            Self::OtherVault => "This card belongs to another vault.",
            Self::OldCard => "This is an old card.",
            Self::WrongMode => "This card is for a vault of the other mode.",
            Self::WrongShare => "This is not a pvault recovery card.",
            Self::Duplicate(1) => "These two cards are both Card A.",
            Self::Duplicate(2) => "These two cards are both Card B.",
            Self::Duplicate(_) => "These two cards are the same card.",
        })
    }
}

/// A recovery card: the full payload, which holds a share.
pub struct Card {
    payload: SecretBytes<PAYLOAD_LEN>,
}

impl fmt::Debug for Card {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Card([REDACTED])")
    }
}

fn check_value(head: &[u8]) -> [u8; 8] {
    let digest = Sha512::new()
        .chain_update(b"pvault/v1/card")
        .chain_update(head)
        .finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

impl Card {
    /// Builds the card for one share.
    pub fn new(
        vault_id: &[u8; 16],
        mode: CardMode,
        set_id: &[u8; 8],
        share: &Share,
    ) -> Result<Self, Error> {
        let mut payload = SecretBytes::<PAYLOAD_LEN>::zeroed();
        {
            let p = payload.expose_secret_mut();
            p[..4].copy_from_slice(MAGIC);
            p[4] = VERSION;
            p[5..21].copy_from_slice(vault_id);
            p[21] = mode.byte();
            p[22..30].copy_from_slice(set_id);
            p[30] = share.x();
            p[31..127].copy_from_slice(share.y().expose_secret());
            let check = check_value(&p[..127]);
            p[127..].copy_from_slice(&check);
        }
        let card = Self { payload };
        card.validate_structure()
            .map_err(|_| Error::Unsupported("invalid card fields"))?;
        Ok(card)
    }

    /// Parses a payload: magic, version, check, mode and x-coordinate
    /// (7.4a). It takes ownership of the bytes.
    pub fn parse(payload: SecretBytes<PAYLOAD_LEN>) -> Result<Self, CardError> {
        let card = Self { payload };
        card.validate_structure()?;
        Ok(card)
    }

    fn validate_structure(&self) -> Result<(), CardError> {
        let p = self.payload.expose_secret();
        if &p[..4] != MAGIC || p[4] != VERSION {
            return Err(CardError::NotACard);
        }
        if !bool::from(check_value(&p[..127]).ct_eq(&p[127..])) {
            return Err(CardError::NotACard);
        }
        match (p[21], p[30]) {
            (0, 3) | (1, 1) | (1, 2) => Ok(()),
            (0 | 1, _) => Err(CardError::WrongShare),
            _ => Err(CardError::WrongMode),
        }
    }

    /// The raw payload.
    pub fn payload(&self) -> &[u8; PAYLOAD_LEN] {
        self.payload.expose_secret()
    }

    /// `vault_id`.
    pub fn vault_id(&self) -> [u8; 16] {
        let mut v = [0u8; 16];
        v.copy_from_slice(&self.payload()[5..21]);
        v
    }

    /// Mode.
    pub fn mode(&self) -> CardMode {
        if self.payload()[21] == 0 {
            CardMode::Bound
        } else {
            CardMode::Portable
        }
    }

    /// `set_id`.
    pub fn set_id(&self) -> [u8; 8] {
        let mut v = [0u8; 8];
        v.copy_from_slice(&self.payload()[22..30]);
        v
    }

    /// The Shamir x-coordinate.
    pub fn x(&self) -> u8 {
        self.payload()[30]
    }

    /// The share.
    pub fn share(&self) -> Result<Share, Error> {
        let mut y = [0u8; SECRET_LEN];
        y.copy_from_slice(&self.payload()[31..127]);
        let secret = SecretBytes::take_from(&mut y)?;
        Share::new(self.x(), secret)
    }

    /// Role label: "Card A", "Card B" or "Bound card".
    pub fn role(&self) -> &'static str {
        match (self.mode(), self.x()) {
            (CardMode::Portable, 1) => "Card A",
            (CardMode::Portable, _) => "Card B",
            (CardMode::Bound, _) => "Bound card",
        }
    }

    /// Checks a card used to authenticate against the vault's public header
    /// fields (7.4a): vault, card set and mode.
    pub fn check_for_vault(
        &self,
        vault_id: &[u8; 16],
        card_set_id: &[u8; 8],
        mode: CardMode,
    ) -> Result<(), CardError> {
        if &self.vault_id() != vault_id {
            return Err(CardError::OtherVault);
        }
        if self.mode() != mode {
            return Err(CardError::WrongMode);
        }
        if &self.set_id() != card_set_id {
            return Err(CardError::OldCard);
        }
        Ok(())
    }

    /// Delivery verification (6.4): the whole decoded payload must equal the
    /// expected one, in constant time. A checksum alone is never enough.
    pub fn matches(&self, decoded: &SecretBytes<PAYLOAD_LEN>) -> bool {
        bool::from(self.payload.expose_secret().ct_eq(decoded.expose_secret()))
    }

    /// The 216-symbol Crockford Base32 text.
    pub fn base32(&self) -> SecretBuf {
        let mut out = SecretBuf::zeroed(SYMBOLS);
        let p = self.payload();
        let o = out.expose_secret_mut();
        for (i, slot) in o.iter_mut().enumerate() {
            let bit = i * 5;
            let mut v = 0u8;
            for b in 0..5 {
                let pos = bit + b;
                let byte = p[pos / 8];
                v = (v << 1) | ((byte >> (7 - pos % 8)) & 1);
            }
            *slot = ALPHABET[v as usize];
        }
        out
    }

    /// The typed form as printed: groups of 4 separated by spaces, 8 groups
    /// per line (7 lines).
    pub fn base32_lines(&self) -> Zeroizing<Vec<String>> {
        let text = self.base32();
        let symbols = text.expose_secret();
        let mut lines = Zeroizing::new(Vec::with_capacity(SYMBOLS.div_ceil(32)));
        for line in symbols.chunks(32) {
            let mut rendered = String::with_capacity(line.len() + line.len().saturating_sub(1) / 4);
            for (i, group) in line.chunks(4).enumerate() {
                if i != 0 {
                    rendered.push(' ');
                }
                rendered.push_str(core::str::from_utf8(group).unwrap_or(""));
            }
            lines.push(rendered);
        }
        lines
    }
}

/// Checks a pair of cards before any combination (7.4a): both valid for the
/// vault, and different x-coordinates.
pub fn check_pair(a: &Card, b: &Card) -> Result<(), CardError> {
    if a.x() == b.x() {
        return Err(CardError::Duplicate(a.x()));
    }
    if a.vault_id() != b.vault_id() || a.set_id() != b.set_id() || a.mode() != b.mode() {
        return Err(CardError::OldCard);
    }
    Ok(())
}

/// Maps one input byte to a Base32 value (`None`: a separator).
fn symbol(byte: u8) -> Result<Option<u8>, ()> {
    let c = byte.to_ascii_uppercase();
    let c = match c {
        b' ' | b'-' => return Ok(None),
        b'I' | b'L' => b'1',
        b'O' => b'0',
        c => c,
    };
    ALPHABET
        .iter()
        .position(|&a| a == c)
        .map(|v| Some(v as u8))
        .ok_or(())
}

/// Card-text input errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardTextError {
    /// A character that is not a Crockford symbol or separator, at this
    /// 1-based position of its line.
    InvalidChar(usize),
    /// The text holds more than 216 symbols.
    TooMany,
    /// The text ended (empty line or end of input) with this many symbols.
    TooFew(usize),
    /// More than [`MAX_TEXT_LINES`] lines.
    TooManyLines,
    /// End of input without a final line terminator.
    Unterminated,
}

impl fmt::Display for CardTextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChar(n) => {
                write!(
                    f,
                    "The card text contains an invalid character at position {n}."
                )
            }
            Self::TooMany => f.write_str("The card text has more than 216 symbols."),
            Self::TooFew(n) => write!(
                f,
                "The card text must have 216 characters; {n} were entered."
            ),
            Self::TooManyLines => f.write_str("The card text has too many lines."),
            Self::Unterminated => f.write_str("Input ended before all secrets were read."),
        }
    }
}

/// Progress of [`CardTextReader::push_line`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardTextProgress {
    /// Read another line.
    NeedMore,
    /// Exactly 216 symbols, ending with a terminated line.
    Complete,
}

/// Accumulates card text **whole lines at a time** (`docs/CLI.md` 2): each
/// line is validated completely before its symbols count; a line that takes
/// the count past 216 rejects the attempt; acceptance needs exactly 216
/// symbols after a complete, terminated line.
pub struct CardTextReader {
    values: SecretBytes<SYMBOLS>,
    count: usize,
    lines: usize,
}

impl fmt::Debug for CardTextReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CardTextReader([REDACTED])")
    }
}

impl Default for CardTextReader {
    fn default() -> Self {
        Self::new()
    }
}

impl CardTextReader {
    /// An empty reader.
    pub fn new() -> Self {
        Self {
            values: SecretBytes::zeroed(),
            count: 0,
            lines: 0,
        }
    }

    /// Adds one complete line.
    pub fn push_line(&mut self, line: &SecretLine) -> Result<CardTextProgress, CardTextError> {
        self.lines += 1;
        if self.lines > MAX_TEXT_LINES {
            return Err(CardTextError::TooManyLines);
        }
        let bytes = line.as_bytes();
        // Validate the whole line before counting any of it.
        let mut n = 0usize;
        for (i, &b) in bytes.iter().enumerate() {
            match symbol(b) {
                Ok(Some(_)) => n += 1,
                Ok(None) => {}
                Err(()) => return Err(CardTextError::InvalidChar(i + 1)),
            }
        }
        if self.count + n > SYMBOLS {
            return Err(CardTextError::TooMany);
        }
        if n == 0 {
            return Err(CardTextError::TooFew(self.count));
        }
        let values = self.values.expose_secret_mut();
        for &b in bytes {
            if let Ok(Some(v)) = symbol(b) {
                values[self.count] = v;
                self.count += 1;
            }
        }
        if !line.terminated() {
            return Err(CardTextError::Unterminated);
        }
        if self.count == SYMBOLS {
            Ok(CardTextProgress::Complete)
        } else {
            Ok(CardTextProgress::NeedMore)
        }
    }

    /// End of input before completion.
    pub fn ended(&self) -> CardTextError {
        if self.count == 0 {
            CardTextError::Unterminated
        } else {
            CardTextError::TooFew(self.count)
        }
    }

    /// The decoded payload, once complete.
    pub fn payload(&self) -> Result<SecretBytes<PAYLOAD_LEN>, CardTextError> {
        if self.count != SYMBOLS {
            return Err(CardTextError::TooFew(self.count));
        }
        let mut out = SecretBytes::<PAYLOAD_LEN>::zeroed();
        let o = out.expose_secret_mut();
        for (i, &v) in self.values.expose_secret().iter().enumerate() {
            for b in 0..5 {
                if (v >> (4 - b)) & 1 == 1 {
                    let pos = i * 5 + b;
                    o[pos / 8] |= 1 << (7 - pos % 8);
                }
            }
        }
        Ok(out)
    }
}

/// Decodes a single complete text (all 216 symbols in one string), for
/// tests and vectors.
pub fn decode_base32(text: &[u8]) -> Result<SecretBytes<PAYLOAD_LEN>, CardTextError> {
    let mut reader = CardTextReader::new();
    for (i, &b) in text.iter().enumerate() {
        if b == b'\n' || b == b'\r' {
            continue;
        }
        match symbol(b) {
            Ok(Some(v)) => {
                if reader.count == SYMBOLS {
                    return Err(CardTextError::TooMany);
                }
                reader.values.expose_secret_mut()[reader.count] = v;
                reader.count += 1;
            }
            Ok(None) => {}
            Err(()) => return Err(CardTextError::InvalidChar(i + 1)),
        }
    }
    reader.payload()
}

/// The QR module matrix of a payload: byte mode, error correction M, the
/// smallest version that fits. Returns `(width, dark modules row-major)`.
pub fn qr_matrix(payload: &[u8; PAYLOAD_LEN]) -> Result<(usize, Vec<bool>), Error> {
    use qrcode::bits::Bits;
    use qrcode::{Color, EcLevel, QrCode, Version};
    for v in 1..=40 {
        let mut bits = Bits::new(Version::Normal(v));
        if bits.push_byte_data(payload).is_err() || bits.push_terminator(EcLevel::M).is_err() {
            continue;
        }
        let code = QrCode::with_bits(bits, EcLevel::M)
            .map_err(|_| Error::Unsupported("QR encoding failed"))?;
        let width = code.width();
        let dark = code
            .to_colors()
            .into_iter()
            .map(|c| c == Color::Dark)
            .collect();
        return Ok((width, dark));
    }
    Err(Error::Unsupported("QR encoding failed"))
}

/// Renders a card file (7.4b): the QR code, the Base32 text in 7 lines, and
/// labels for the vault ID, the role, the card set and the creation date.
/// Never a passphrase. The returned text holds the share; it is wiped.
pub fn render_svg(card: &Card, created_date: &str) -> Result<Zeroizing<String>, Error> {
    let (width, dark) = qr_matrix(card.payload())?;
    let module = 4usize;
    let quiet = 4usize;
    let qr_size = (width + 2 * quiet) * module;
    let text_x = qr_size + 24;
    let page_w = text_x + 560;
    let page_h = qr_size.max(330);
    let mut svg = Zeroizing::new(String::with_capacity(32 * 1024));
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    svg.push_str(&format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{page_w}\" height=\"{page_h}\" viewBox=\"0 0 {page_w} {page_h}\">\n<rect width=\"{page_w}\" height=\"{page_h}\" fill=\"#fff\"/>\n<path fill=\"#000\" d=\""
    ));
    for y in 0..width {
        for x in 0..width {
            if dark[y * width + x] {
                svg.push_str(&format!(
                    "M{} {}h{module}v{module}h-{module}z",
                    (x + quiet) * module,
                    (y + quiet) * module
                ));
            }
        }
    }
    svg.push_str("\"/>\n");
    let mut line_y = 40;
    let text = |svg: &mut String, size: u32, s: &str, y: &mut usize| {
        svg.push_str(&format!(
            "<text x=\"{text_x}\" y=\"{y}\" font-family=\"monospace\" font-size=\"{size}\">{s}</text>\n"
        ));
        *y += size as usize + 10;
    };
    text(
        &mut svg,
        22,
        &format!("pvault recovery card: {}", card.role()),
        &mut line_y,
    );
    text(
        &mut svg,
        14,
        &format!("Vault ID: {}", hex(&card.vault_id())),
        &mut line_y,
    );
    text(
        &mut svg,
        14,
        &format!("Card set: {}", hex(&card.set_id())),
        &mut line_y,
    );
    text(
        &mut svg,
        14,
        &format!("Created: {created_date}"),
        &mut line_y,
    );
    line_y += 10;
    for line in card.base32_lines().iter() {
        text(&mut svg, 16, line, &mut line_y);
    }
    svg.push_str("</svg>\n");
    let mut matrix = dark;
    matrix.zeroize();
    Ok(svg)
}

/// PNG and QR input errors (7.4c).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PngError {
    /// Not a PNG, or damaged.
    NotPng,
    /// Over the file, side or buffer limits.
    TooLarge,
    /// An animated PNG.
    Animated,
    /// No QR code found or decodable.
    NoCode,
    /// More than one QR code.
    MultipleCodes,
    /// The QR content is not exactly 135 bytes.
    WrongLength,
}

impl fmt::Display for PngError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotPng => "The image is not a PNG file.",
            Self::TooLarge => "The image is too large.",
            Self::Animated => "Animated PNG images are not supported.",
            Self::NoCode => "No QR code was found in the image.",
            Self::MultipleCodes => "More than one QR code was found in the image.",
            Self::WrongLength => "This is not a pvault recovery card.",
        })
    }
}

/// Decodes the card payload from PNG file bytes (7.4c): size limits checked
/// before any pixel allocation, APNG refused, converted to 8-bit grayscale,
/// exactly one QR code of exactly 135 bytes. Pixel buffers are wiped.
pub fn decode_png(file: &[u8]) -> Result<SecretBytes<PAYLOAD_LEN>, PngError> {
    if file.len() as u64 > MAX_PNG_FILE {
        return Err(PngError::TooLarge);
    }
    if !file.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Err(PngError::NotPng);
    }
    let limits = png::Limits {
        bytes: MAX_PNG_BUFFER,
    };
    let mut decoder = png::Decoder::new_with_limits(std::io::Cursor::new(file), limits);
    decoder.set_transformations(png::Transformations::normalize_to_color8());
    let mut reader = decoder.read_info().map_err(|e| match e {
        png::DecodingError::LimitsExceeded => PngError::TooLarge,
        _ => PngError::NotPng,
    })?;
    let (w, h) = {
        let info = reader.info();
        if info.animation_control.is_some() {
            return Err(PngError::Animated);
        }
        (info.width, info.height)
    };
    if w == 0 || h == 0 || w > MAX_PNG_SIDE || h > MAX_PNG_SIDE {
        return Err(PngError::TooLarge);
    }
    let (color, _) = reader.output_color_type();
    let samples = color.samples();
    let size = (w as usize)
        .checked_mul(h as usize)
        .and_then(|p| p.checked_mul(samples))
        .ok_or(PngError::TooLarge)?;
    if size > MAX_PNG_BUFFER || reader.output_buffer_size() != Some(size) {
        return Err(PngError::TooLarge);
    }
    let mut pixels = Zeroizing::new(vec![0u8; size]);
    reader
        .next_frame(&mut pixels)
        .map_err(|_| PngError::NotPng)?;
    let mut gray = Zeroizing::new(vec![0u8; w as usize * h as usize]);
    for (i, g) in gray.iter_mut().enumerate() {
        let px = &pixels[i * samples..(i + 1) * samples];
        let (r, gr, b, a) = match samples {
            1 => (px[0], px[0], px[0], 255),
            2 => (px[0], px[0], px[0], px[1]),
            3 => (px[0], px[1], px[2], 255),
            _ => (px[0], px[1], px[2], px[3]),
        };
        let lum = (u32::from(r) * 299 + u32::from(gr) * 587 + u32::from(b) * 114) / 1000;
        // Composite on white.
        let a = u32::from(a);
        *g = ((lum * a + 255 * (255 - a)) / 255) as u8;
    }
    drop(pixels);
    let width = w as usize;
    let mut img =
        rqrr::PreparedImage::prepare_from_greyscale(width, h as usize, |x, y| gray[y * width + x]);
    let grids = img.detect_grids();
    drop(gray);
    match grids.len() {
        0 => return Err(PngError::NoCode),
        1 => {}
        _ => return Err(PngError::MultipleCodes),
    }
    let mut content = Zeroizing::new(Vec::with_capacity(PAYLOAD_LEN + 16));
    grids[0]
        .decode_to(&mut *content)
        .map_err(|_| PngError::NoCode)?;
    if content.len() != PAYLOAD_LEN {
        return Err(PngError::WrongLength);
    }
    SecretBytes::take_from(&mut content).map_err(|_| PngError::WrongLength)
}

#[cfg(test)]
pub(crate) mod tests;
