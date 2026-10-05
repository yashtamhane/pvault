//! Custom-passphrase strength estimation (SI-51, section 5).
//!
//! The estimate is made **only** when a custom main passphrase is created or
//! replaced. It is never made during unlock, verification, or a recovery
//! that keeps the existing passphrase. A failure refuses the *new* custom
//! credential; it never affects access to an existing vault.
//!
//! `zxcvbn` 3.1.1 runs inside a dedicated, short-lived child process: a
//! re-execution of the pvault binary with the single argument [`CHILD_ARG`].
//!
//! - **Hardening:** the child hardens itself
//!   ([`crate::platform::harden_estimator_child`]) before reading anything.
//! - **Transport:** the handled passphrase is transmitted **locally through
//!   an anonymous pipe**. It is never sent over the network, and never placed
//!   in arguments, environment variables or files.
//! - **Reply:** numeric estimates and feedback codes. These are derived from
//!   the input, but never contain any of it.
//! - **Memory (documented):** the child's internal heap copies and the
//!   kernel's pipe buffers are not wiped, and process exit does not
//!   guarantee erasure from RAM, swap or hibernation files.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;
use zxcvbn::feedback::{Suggestion, Warning};

use crate::errors::Error;
use crate::input::UnbufferedSource;
use crate::passphrase::{CustomPassphrase, MAX_CUSTOM_BYTES};
use crate::secrets::SecretBuf;

/// The argument that makes the pvault binary act as the estimator child.
pub const CHILD_ARG: &str = "__pvault-estimate-child";

/// Wall-clock limit for one estimate.
pub const TIMEOUT: Duration = Duration::from_secs(5);

/// Typed acknowledgment required to accept an "Estimated medium" passphrase.
pub const MEDIUM_ACKNOWLEDGMENT: &str = "ACCEPT MEDIUM PASSPHRASE";

/// Shown with every custom-passphrase estimate.
pub const ESTIMATE_WARNING: &str = "Estimated only. Famous quotations, song lyrics, book or film lines, and well-known phrases can receive falsely high ratings.";

const MAX_CONTEXT: usize = 255;
const REQUEST_MAX: usize = 2 + MAX_CUSTOM_BYTES + 1 + MAX_CONTEXT;
const REPLY_MAX: usize = 64;
const REPLY_VERSION: u8 = 1;

/// Provisional product policy (SI-51). These are not validated security
/// boundaries.
const WEAK_BELOW_LOG10_X100: u16 = 1400;
const STRONG_FROM_LOG10_X100: u16 = 1800;

/// Estimated band. Always presented with the word "Estimated".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Band {
    /// Fewer than 10^14 estimated guesses: refused.
    Weak,
    /// 10^14 to under 10^18: accepted only after [`MEDIUM_ACKNOWLEDGMENT`].
    Medium,
    /// 10^18 or more estimated guesses.
    Strong,
}

impl Band {
    fn from_log10_x100(value: u16) -> Self {
        if value < WEAK_BELOW_LOG10_X100 {
            Self::Weak
        } else if value < STRONG_FROM_LOG10_X100 {
            Self::Medium
        } else {
            Self::Strong
        }
    }
}

impl core::fmt::Display for Band {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Weak => "Estimated weak",
            Self::Medium => "Estimated medium",
            Self::Strong => "Estimated strong",
        })
    }
}

/// The result of one estimate.
#[derive(Debug, Clone, PartialEq)]
pub struct Estimate {
    log10_guesses_x100: u16,
    warning: Option<Warning>,
    suggestions: Vec<Suggestion>,
}

impl Estimate {
    /// The estimated band.
    pub fn band(&self) -> Band {
        Band::from_log10_x100(self.log10_guesses_x100)
    }

    /// `log10` of the estimated guesses. The estimator saturates near 19.27
    /// (2^64).
    pub fn log10_guesses(&self) -> f64 {
        f64::from(self.log10_guesses_x100) / 100.0
    }

    /// zxcvbn's warning, if any. A fixed text.
    pub fn warning(&self) -> Option<Warning> {
        self.warning
    }

    /// zxcvbn's suggestions. Fixed texts.
    pub fn suggestions(&self) -> &[Suggestion] {
        &self.suggestions
    }
}

/// Estimates a custom passphrase being created. `context` is non-secret text
/// the estimator should penalize, such as the vault folder name.
pub fn estimate(passphrase: &CustomPassphrase, context: &str) -> Result<Estimate, Error> {
    #[cfg(target_os = "linux")]
    let program = std::path::PathBuf::from("/proc/self/exe");
    #[cfg(not(target_os = "linux"))]
    let program = std::env::current_exe().map_err(|_| Error::Estimator)?;
    estimate_with(&program, passphrase.bytes(), context, TIMEOUT)
}

/// [`estimate`] with an explicit program and timeout. For tests and for
/// launchers that are not the pvault binary.
#[doc(hidden)]
pub fn estimate_with(
    program: &Path,
    secret: &SecretBuf,
    context: &str,
    timeout: Duration,
) -> Result<Estimate, Error> {
    let request = encode_request(secret, context)?;
    let started = Instant::now();
    let mut command = Command::new(program);
    command
        .arg(CHILD_ARG)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // Windows needs SystemRoot to start a process. It is not secret.
    #[cfg(windows)]
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    let mut child = command.spawn().map_err(|_| Error::Estimator)?;

    let sent = child
        .stdin
        .take()
        .map(|mut pipe| pipe.write_all(request.expose_secret()))
        .unwrap_or(Ok(()));
    drop(request);
    if sent.is_err() {
        return Err(terminate(child));
    }

    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            // Already reaped by `try_wait`.
            Ok(Some(_)) => return Err(Error::Estimator),
            Err(_) => return Err(terminate(child)),
            Ok(None) if started.elapsed() >= timeout => return Err(terminate(child)),
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
        }
    }

    let mut reply = Vec::with_capacity(REPLY_MAX + 1);
    child
        .stdout
        .take()
        .ok_or(Error::Estimator)?
        .take(REPLY_MAX as u64 + 1)
        .read_to_end(&mut reply)
        .map_err(|_| Error::Estimator)?;
    decode_reply(&reply)
}

/// Kills the child if it is still running, then waits for it, so that no
/// estimator process outlives a failed estimate.
fn terminate(mut child: std::process::Child) -> Error {
    let _ = child.kill();
    let _ = child.wait();
    Error::Estimator
}

/// Child entry point. Called by the CLI when its first argument is
/// [`CHILD_ARG`]. Returns the process exit code.
pub fn run_child() -> i32 {
    if crate::platform::harden_estimator_child().is_err() {
        return 10;
    }
    let mut buffer = Zeroizing::new([0u8; REQUEST_MAX]);
    let Ok(stdin) = unbuffered_stdin() else {
        return 11;
    };
    let mut source = UnbufferedSource(stdin);
    let Some(len) = read_request(&mut source, &mut buffer[..]) else {
        return 12;
    };
    let Some((secret, context)) = split_request(&buffer[..len]) else {
        return 13;
    };
    let context: &[&str] = if context.is_empty() { &[] } else { &[context] };
    let estimate = zxcvbn::zxcvbn(secret, context);
    let reply = encode_reply(&estimate);
    drop(estimate);
    let ok = std::io::stdout()
        .write_all(&reply)
        .and_then(|()| std::io::stdout().flush());
    if ok.is_ok() { 0 } else { 14 }
}

fn unbuffered_stdin() -> std::io::Result<std::fs::File> {
    let stdin = std::io::stdin();
    #[cfg(unix)]
    let owned = std::os::fd::AsFd::as_fd(&stdin).try_clone_to_owned()?;
    #[cfg(windows)]
    let owned = std::os::windows::io::AsHandle::as_handle(&stdin).try_clone_to_owned()?;
    Ok(std::fs::File::from(owned))
}

/// Request: `u16_be(len) ‖ secret ‖ u8(ctx_len) ‖ context`. The secret is
/// at most [`MAX_CUSTOM_BYTES`] bytes.
fn encode_request(secret: &SecretBuf, context: &str) -> Result<SecretBuf, Error> {
    let secret = secret.expose_secret();
    let context = context.as_bytes();
    if secret.is_empty() || secret.len() > MAX_CUSTOM_BYTES {
        return Err(Error::Estimator);
    }
    let context = &context[..context.len().min(MAX_CONTEXT)];
    let mut out = SecretBuf::zeroed(2 + secret.len() + 1 + context.len());
    let buf = out.expose_secret_mut();
    buf[..2].copy_from_slice(&(secret.len() as u16).to_be_bytes());
    buf[2..2 + secret.len()].copy_from_slice(secret);
    buf[2 + secret.len()] = context.len() as u8;
    buf[3 + secret.len()..].copy_from_slice(context);
    Ok(out)
}

/// Reads one framed request into `buffer`. Returns its total length.
fn read_request<S: crate::input::ByteSource>(source: &mut S, buffer: &mut [u8]) -> Option<usize> {
    let mut read = |at: usize, n: usize, buffer: &mut [u8]| -> Option<()> {
        for slot in &mut buffer[at..at + n] {
            *slot = source.next_byte().ok()??;
        }
        Some(())
    };
    read(0, 2, buffer)?;
    let secret_len = usize::from(u16::from_be_bytes([buffer[0], buffer[1]]));
    if secret_len == 0 || secret_len > MAX_CUSTOM_BYTES {
        return None;
    }
    read(2, secret_len + 1, buffer)?;
    let context_len = usize::from(buffer[2 + secret_len]);
    read(3 + secret_len, context_len, buffer)?;
    Some(3 + secret_len + context_len)
}

fn split_request(request: &[u8]) -> Option<(&str, &str)> {
    let secret_len = usize::from(u16::from_be_bytes([*request.first()?, *request.get(1)?]));
    let secret = core::str::from_utf8(request.get(2..2 + secret_len)?).ok()?;
    let context = core::str::from_utf8(request.get(3 + secret_len..)?).ok()?;
    Some((secret, context))
}

/// Reply: `version ‖ u16_be(log10 × 100) ‖ warning (0 = none, else code + 1)
/// ‖ count ‖ suggestion codes`. It contains only numbers.
fn encode_reply(estimate: &zxcvbn::Entropy) -> Vec<u8> {
    let log10 = (estimate.guesses_log10() * 100.0)
        .round()
        .clamp(0.0, f64::from(u16::MAX)) as u16;
    let feedback = estimate.feedback();
    let warning = feedback
        .and_then(|f| f.warning())
        .map_or(0, |w| w as u8 + 1);
    let suggestions: Vec<u8> = feedback
        .map(|f| f.suggestions().iter().map(|s| *s as u8).collect())
        .unwrap_or_default();
    let mut out = Vec::with_capacity(5 + suggestions.len());
    out.push(REPLY_VERSION);
    out.extend_from_slice(&log10.to_be_bytes());
    out.push(warning);
    out.push(suggestions.len() as u8);
    out.extend(suggestions);
    out
}

fn decode_reply(reply: &[u8]) -> Result<Estimate, Error> {
    if reply.len() < 5 || reply.len() > REPLY_MAX || reply[0] != REPLY_VERSION {
        return Err(Error::Estimator);
    }
    let log10_guesses_x100 = u16::from_be_bytes([reply[1], reply[2]]);
    let warning = match reply[3] {
        0 => None,
        code => Some(
            *WARNINGS
                .get(usize::from(code - 1))
                .ok_or(Error::Estimator)?,
        ),
    };
    let count = usize::from(reply[4]);
    if reply.len() != 5 + count {
        return Err(Error::Estimator);
    }
    let suggestions = reply[5..]
        .iter()
        .map(|&code| {
            SUGGESTIONS
                .get(usize::from(code))
                .copied()
                .ok_or(Error::Estimator)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Estimate {
        log10_guesses_x100,
        warning,
        suggestions,
    })
}

/// zxcvbn 3.1.1 warnings, in declaration order. The code is the variant's
/// discriminant.
const WARNINGS: [Warning; 14] = [
    Warning::StraightRowsOfKeysAreEasyToGuess,
    Warning::ShortKeyboardPatternsAreEasyToGuess,
    Warning::RepeatsLikeAaaAreEasyToGuess,
    Warning::RepeatsLikeAbcAbcAreOnlySlightlyHarderToGuess,
    Warning::ThisIsATop10Password,
    Warning::ThisIsATop100Password,
    Warning::ThisIsACommonPassword,
    Warning::ThisIsSimilarToACommonlyUsedPassword,
    Warning::SequencesLikeAbcAreEasyToGuess,
    Warning::RecentYearsAreEasyToGuess,
    Warning::AWordByItselfIsEasyToGuess,
    Warning::DatesAreOftenEasyToGuess,
    Warning::NamesAndSurnamesByThemselvesAreEasyToGuess,
    Warning::CommonNamesAndSurnamesAreEasyToGuess,
];

/// zxcvbn 3.1.1 suggestions, in declaration order.
const SUGGESTIONS: [Suggestion; 13] = [
    Suggestion::UseAFewWordsAvoidCommonPhrases,
    Suggestion::NoNeedForSymbolsDigitsOrUppercaseLetters,
    Suggestion::AddAnotherWordOrTwo,
    Suggestion::CapitalizationDoesntHelpVeryMuch,
    Suggestion::AllUppercaseIsAlmostAsEasyToGuessAsAllLowercase,
    Suggestion::ReversedWordsArentMuchHarderToGuess,
    Suggestion::PredictableSubstitutionsDontHelpVeryMuch,
    Suggestion::UseALongerKeyboardPatternWithMoreTurns,
    Suggestion::AvoidRepeatedWordsAndCharacters,
    Suggestion::AvoidSequences,
    Suggestion::AvoidRecentYears,
    Suggestion::AvoidYearsThatAreAssociatedWithYou,
    Suggestion::AvoidDatesAndYearsThatAreAssociatedWithYou,
];

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(text: &str) -> SecretBuf {
        SecretBuf::take_from(&mut text.as_bytes().to_vec())
    }

    #[test]
    fn code_tables_match_discriminants() {
        for (i, w) in WARNINGS.iter().enumerate() {
            assert_eq!(*w as usize, i);
        }
        for (i, s) in SUGGESTIONS.iter().enumerate() {
            assert_eq!(*s as usize, i);
        }
    }

    #[test]
    fn bands_are_the_provisional_policy() {
        assert_eq!(Band::from_log10_x100(1399), Band::Weak);
        assert_eq!(Band::from_log10_x100(1400), Band::Medium);
        assert_eq!(Band::from_log10_x100(1799), Band::Medium);
        assert_eq!(Band::from_log10_x100(1800), Band::Strong);
        for band in [Band::Weak, Band::Medium, Band::Strong] {
            assert!(band.to_string().starts_with("Estimated "));
        }
    }

    #[test]
    fn request_framing_round_trip() {
        let request = encode_request(&secret("pass phrase"), "my-vault").unwrap();
        let mut source = UnbufferedSource(request.expose_secret());
        let mut buffer = [0u8; REQUEST_MAX];
        let len = read_request(&mut source, &mut buffer).unwrap();
        assert_eq!(
            split_request(&buffer[..len]),
            Some(("pass phrase", "my-vault"))
        );
        assert!(encode_request(&SecretBuf::zeroed(MAX_CUSTOM_BYTES + 1), "").is_err());
        assert!(encode_request(&SecretBuf::zeroed(0), "").is_err());
    }

    #[test]
    fn oversized_or_truncated_requests_are_refused() {
        let mut too_big = vec![0x01, 0x01]; // declares 257 bytes
        too_big.extend(vec![b'a'; 300]);
        let mut buffer = [0u8; REQUEST_MAX];
        assert!(read_request(&mut UnbufferedSource(&too_big[..]), &mut buffer).is_none());
        let truncated = [0x00, 0x05, b'a', b'b'];
        assert!(read_request(&mut UnbufferedSource(&truncated[..]), &mut buffer).is_none());
    }

    #[test]
    fn replies_carry_only_numbers_and_never_the_input() {
        let input = "Tr0ub4dor&3";
        let reply = encode_reply(&zxcvbn::zxcvbn(input, &[]));
        assert!(reply.len() <= REPLY_MAX);
        assert!(
            !reply
                .windows(4)
                .any(|w| input.as_bytes().windows(4).any(|i| i == w))
        );
        let decoded = decode_reply(&reply).unwrap();
        assert_eq!(
            decoded.log10_guesses_x100,
            u16::from_be_bytes([reply[1], reply[2]])
        );
    }

    #[test]
    fn malformed_replies_are_refused() {
        for bad in [
            &[][..],
            &[2, 0, 0, 0, 0][..],
            &[1, 0, 0, 15, 0][..],
            &[1, 0, 0, 0, 1][..],
            &[1, 0, 0, 0, 1, 13][..],
            &[1, 0, 0, 0, 0, 0][..],
        ] {
            assert!(decode_reply(bad).is_err(), "{bad:?}");
        }
        assert!(decode_reply(&[1u8; 70]).is_err());
    }

    #[test]
    fn in_process_classification_examples() {
        let band = |s: &str| {
            Band::from_log10_x100((zxcvbn::zxcvbn(s, &[]).guesses_log10() * 100.0).round() as u16)
        };
        assert_eq!(band("P@ssw0rd2026"), Band::Weak);
        assert_eq!(band("MyVaultPassword2026"), Band::Weak);
        // Known false positive, documented with every result.
        assert_eq!(band("correct horse battery staple"), Band::Strong);
    }
}
