//! Bounded secret input (SI-51, section 4).
//!
//! Secrets are read into a fixed, zeroize-on-drop buffer of [`MAX_LINE`]
//! bytes. Nothing grows, so no partial copy is left behind by reallocation.
//!
//! - **Line boundary:** a line ends at the first LF. A single CR directly
//!   before that LF is dropped as part of a CRLF line ending. No other byte
//!   is removed.
//! - **Too long:** a line longer than [`MAX_LINE`] bytes is drained and
//!   refused.
//! - **End of input:** EOF ends a non-empty final line. EOF before any byte
//!   is a cancellation.
//!
//! Terminal reading with echo control lives in `platform::terminal`.
//! [`StdinSecrets`] implements the explicit `--secrets-stdin` mode.

use core::fmt;
use std::io::{self, IsTerminal, Read};

use zeroize::Zeroize;

use crate::passphrase::MAX_RAW_BYTES;
use crate::secrets::SecretBytes;

/// Largest secret line accepted, in bytes (not counting the line ending).
pub const MAX_LINE: usize = MAX_RAW_BYTES;

/// One secret line in a fixed buffer.
pub struct SecretLine {
    buf: SecretBytes<MAX_LINE>,
    len: usize,
    terminated: bool,
}

impl SecretLine {
    fn new() -> Self {
        Self {
            buf: SecretBytes::zeroed(),
            len: 0,
            terminated: false,
        }
    }

    /// Whether the line ended with LF (rather than end of input). Card text
    /// is accepted only after a complete, terminated final line (A1).
    pub fn terminated(&self) -> bool {
        self.terminated
    }

    /// The bytes of the line, without its line ending.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf.expose_secret()[..self.len]
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the line is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn push(&mut self, byte: u8) -> bool {
        if self.len == MAX_LINE {
            return false;
        }
        self.buf.expose_secret_mut()[self.len] = byte;
        self.len += 1;
        true
    }
}

impl fmt::Debug for SecretLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Input failures. They never carry secret content.
#[derive(Debug)]
#[non_exhaustive]
pub enum InputError {
    /// The line is longer than [`MAX_LINE`] bytes.
    TooLong,
    /// Input ended before anything was entered.
    Cancelled,
    /// No terminal is available, and `--secrets-stdin` was not given.
    NoTerminal,
    /// `--secrets-stdin` was given, but stdin is a terminal, where echo
    /// cannot be controlled.
    StdinIsTerminal,
    /// A secret would be read without `--secrets-stdin` while standard input
    /// is not a terminal (redirected from a file or a pipe). Refused: spec
    /// 10 item 6, `docs/CLI.md` 2.
    StdinNotTerminal,
    /// The console delivered invalid UTF-16 (a lone surrogate).
    InvalidUtf16,
    /// Reading failed.
    Io(io::Error),
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => write!(f, "The input is too long (at most {MAX_LINE} bytes)."),
            Self::Cancelled => f.write_str("Input cancelled."),
            Self::NoTerminal => f.write_str(
                "No terminal is available for entering secrets. Use --secrets-stdin to read them from standard input.",
            ),
            Self::StdinIsTerminal => f.write_str(
                "--secrets-stdin reads from a pipe or file. Standard input is a terminal, so type the secret at the prompt instead.",
            ),
            Self::StdinNotTerminal => f.write_str(
                "Standard input is redirected. pvault reads secrets from it only with --secrets-stdin; otherwise run it with standard input on the terminal.",
            ),
            Self::InvalidUtf16 => f.write_str("The console delivered invalid text."),
            Self::Io(e) => write!(f, "Reading input failed: {e}"),
        }
    }
}

impl std::error::Error for InputError {}

/// A source of input bytes. `Ok(None)` means end of input.
pub trait ByteSource {
    /// Reads one byte.
    fn next_byte(&mut self) -> io::Result<Option<u8>>;
}

/// Reads one secret line from `source` (rules in the module docs).
pub fn read_line<S: ByteSource + ?Sized>(source: &mut S) -> Result<SecretLine, InputError> {
    let mut line = SecretLine::new();
    let mut pending_cr = false;
    let mut any = false;
    loop {
        let Some(mut byte) = source.next_byte().map_err(InputError::Io)? else {
            if !any {
                return Err(InputError::Cancelled);
            }
            if pending_cr && !line.push(b'\r') {
                return Err(InputError::TooLong);
            }
            return Ok(line);
        };
        any = true;
        if byte == b'\n' {
            line.terminated = true;
            return Ok(line);
        }
        if pending_cr {
            pending_cr = false;
            if !line.push(b'\r') {
                byte.zeroize();
                drain(source)?;
                return Err(InputError::TooLong);
            }
        }
        if byte == b'\r' {
            pending_cr = true;
            continue;
        }
        if !line.push(byte) {
            byte.zeroize();
            drain(source)?;
            return Err(InputError::TooLong);
        }
    }
}

/// Discards the rest of an over-long line, so the next read starts cleanly.
fn drain<S: ByteSource + ?Sized>(source: &mut S) -> Result<(), InputError> {
    while let Some(mut byte) = source.next_byte().map_err(InputError::Io)? {
        let end = byte == b'\n';
        byte.zeroize();
        if end {
            break;
        }
    }
    Ok(())
}

/// Reads one byte at a time from any reader, retrying on interruption.
/// The reader must not buffer internally (for example an unbuffered `File`).
#[derive(Debug)]
pub struct UnbufferedSource<R: Read>(pub R);

impl<R: Read> ByteSource for UnbufferedSource<R> {
    fn next_byte(&mut self) -> io::Result<Option<u8>> {
        let mut byte = [0u8; 1];
        loop {
            match self.0.read(&mut byte) {
                Ok(0) => return Ok(None),
                Ok(_) => {
                    let b = byte[0];
                    byte.zeroize();
                    return Ok(Some(b));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}

/// Explicit `--secrets-stdin` input: one secret per line, in prompt order.
///
/// Standard input is read through an unbuffered duplicate of its handle, so
/// no secret byte passes through the standard library's internal stdin
/// buffer. It is refused when stdin is a terminal.
pub struct StdinSecrets {
    source: UnbufferedSource<std::fs::File>,
}

impl StdinSecrets {
    /// Opens standard input for secret reading.
    pub fn open() -> Result<Self, InputError> {
        let stdin = io::stdin();
        if stdin.is_terminal() {
            return Err(InputError::StdinIsTerminal);
        }
        #[cfg(unix)]
        let owned = std::os::fd::AsFd::as_fd(&stdin)
            .try_clone_to_owned()
            .map_err(InputError::Io)?;
        #[cfg(windows)]
        let owned = std::os::windows::io::AsHandle::as_handle(&stdin)
            .try_clone_to_owned()
            .map_err(InputError::Io)?;
        Ok(Self {
            source: UnbufferedSource(std::fs::File::from(owned)),
        })
    }

    /// Reads the next secret. A line that is too long refuses the whole
    /// command: the caller must stop reading further secrets.
    pub fn next_secret(&mut self) -> Result<SecretLine, InputError> {
        read_line(&mut self.source)
    }
}

impl fmt::Debug for StdinSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StdinSecrets")
    }
}

/// Decodes UTF-16 code units (from the Windows console) into UTF-8 bytes,
/// one unit at a time, with no growing buffer.
#[derive(Default)]
pub struct Utf16Decoder {
    high: Option<u16>,
    pending: [u8; 4],
    pending_len: usize,
    pending_pos: usize,
}

impl Utf16Decoder {
    /// Feeds one code unit. Returns `Ok(true)` when a complete character is
    /// ready to drain with [`Self::next_byte`].
    pub fn push(&mut self, unit: u16) -> Result<bool, InputError> {
        let c = match (self.high.take(), unit) {
            (None, 0xD800..=0xDBFF) => {
                self.high = Some(unit);
                return Ok(false);
            }
            (None, 0xDC00..=0xDFFF) => return Err(InputError::InvalidUtf16),
            (None, u) => char::from_u32(u32::from(u)).ok_or(InputError::InvalidUtf16)?,
            (Some(h), l @ 0xDC00..=0xDFFF) => {
                let cp = 0x10000 + ((u32::from(h) - 0xD800) << 10) + (u32::from(l) - 0xDC00);
                char::from_u32(cp).ok_or(InputError::InvalidUtf16)?
            }
            (Some(_), _) => return Err(InputError::InvalidUtf16),
        };
        self.pending_len = c.encode_utf8(&mut self.pending).len();
        self.pending_pos = 0;
        Ok(true)
    }

    /// Takes the next decoded byte, if any.
    pub fn next_byte(&mut self) -> Option<u8> {
        if self.pending_pos < self.pending_len {
            let b = self.pending[self.pending_pos];
            self.pending[self.pending_pos] = 0;
            self.pending_pos += 1;
            Some(b)
        } else {
            None
        }
    }

    /// Whether a high surrogate is waiting for its pair.
    pub fn is_mid_character(&self) -> bool {
        self.high.is_some()
    }
}

impl Drop for Utf16Decoder {
    fn drop(&mut self) {
        self.pending.zeroize();
        self.high.zeroize();
    }
}

impl fmt::Debug for Utf16Decoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Utf16Decoder")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Bytes(std::collections::VecDeque<u8>);

    impl ByteSource for Bytes {
        fn next_byte(&mut self) -> io::Result<Option<u8>> {
            Ok(self.0.pop_front())
        }
    }

    fn src(bytes: &[u8]) -> Bytes {
        Bytes(bytes.iter().copied().collect())
    }

    #[test]
    fn line_endings() {
        let mut s = src(b"one\ntwo\r\nthree\rx\nlast");
        assert_eq!(read_line(&mut s).unwrap().as_bytes(), b"one");
        assert_eq!(read_line(&mut s).unwrap().as_bytes(), b"two");
        assert_eq!(
            read_line(&mut s).unwrap().as_bytes(),
            b"three\rx",
            "a lone CR is kept"
        );
        assert_eq!(
            read_line(&mut s).unwrap().as_bytes(),
            b"last",
            "EOF ends the final line"
        );
        assert!(matches!(read_line(&mut s), Err(InputError::Cancelled)));
    }

    #[test]
    fn spaces_are_preserved_exactly() {
        let mut s = src(b"  two leading, two trailing  \n");
        assert_eq!(
            read_line(&mut s).unwrap().as_bytes(),
            b"  two leading, two trailing  "
        );
        let mut s = src(b"\n");
        assert!(
            read_line(&mut s).unwrap().is_empty(),
            "an empty line is not a cancellation"
        );
    }

    #[test]
    fn limit_is_exact_and_overlong_lines_are_drained() {
        let mut exact = vec![b'a'; MAX_LINE];
        exact.extend_from_slice(b"\r\n");
        assert_eq!(read_line(&mut src(&exact)).unwrap().len(), MAX_LINE);

        let mut long = vec![b'b'; MAX_LINE + 1];
        long.extend_from_slice(b"\nnext\n");
        let mut s = src(&long);
        assert!(matches!(read_line(&mut s), Err(InputError::TooLong)));
        assert_eq!(
            read_line(&mut s).unwrap().as_bytes(),
            b"next",
            "the rest of the long line was drained"
        );

        let mut cr_overflow = vec![b'c'; MAX_LINE];
        cr_overflow.extend_from_slice(b"\rz\n");
        assert!(matches!(
            read_line(&mut src(&cr_overflow)),
            Err(InputError::TooLong)
        ));
    }

    #[test]
    fn debug_is_redacted() {
        let line = read_line(&mut src(b"secret\n")).unwrap();
        assert_eq!(format!("{line:?}"), "[REDACTED]");
    }

    #[test]
    fn utf16_decoding() {
        let mut d = Utf16Decoder::default();
        let mut out = Vec::new();
        for unit in "é😀a".encode_utf16() {
            if d.push(unit).unwrap() {
                while let Some(b) = d.next_byte() {
                    out.push(b);
                }
            }
        }
        assert_eq!(out, "é😀a".as_bytes());
        assert!(!d.is_mid_character());
        assert!(matches!(
            Utf16Decoder::default().push(0xDC00),
            Err(InputError::InvalidUtf16)
        ));
        let mut d = Utf16Decoder::default();
        d.push(0xD83D).unwrap();
        assert!(d.is_mid_character());
        assert!(matches!(d.push(0x0041), Err(InputError::InvalidUtf16)));
    }
}
