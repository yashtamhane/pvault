//! The custom-passphrase estimator child process (SI-51), end to end through
//! the real `pvault` binary.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use pvault_core::estimator::{self, Band, CHILD_ARG, TIMEOUT};
use pvault_core::passphrase::handle_custom;
use pvault_core::secrets::SecretBuf;

fn program() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_pvault"))
}

fn estimate(text: &str, context: &str) -> Result<estimator::Estimate, pvault_core::Error> {
    let custom = handle_custom(text.as_bytes()).unwrap();
    estimator::estimate_with(program(), custom.bytes(), context, TIMEOUT)
}

#[test]
fn weak_passphrases_are_estimated_weak() {
    for text in ["P@ssw0rd2026", "MyVaultPassword2026", "qwertyuiop123"] {
        let estimate = estimate(text, "").unwrap();
        assert_eq!(estimate.band(), Band::Weak, "{text}");
        assert!(estimate.log10_guesses() < 14.0);
    }
}

#[test]
fn medium_passphrases_need_the_typed_acknowledgment() {
    let estimate = estimate("Glimmerdale Orchard 77", "").unwrap();
    assert_eq!(estimate.band(), Band::Medium);
    assert_eq!(estimate.band().to_string(), "Estimated medium");
    assert_eq!(estimator::MEDIUM_ACKNOWLEDGMENT, "ACCEPT MEDIUM PASSPHRASE");
}

#[test]
fn famous_phrase_is_a_known_false_positive() {
    // Rated strong although it is famous. This is why every result carries
    // `ESTIMATE_WARNING`.
    let estimate = estimate("correct horse battery staple", "").unwrap();
    assert_eq!(estimate.band(), Band::Strong);
    assert!(estimator::ESTIMATE_WARNING.starts_with("Estimated only."));
}

#[test]
fn feedback_codes_round_trip() {
    let estimate = estimate("password", "").unwrap();
    assert_eq!(estimate.band(), Band::Weak);
    assert!(estimate.warning().is_some());
    assert!(!estimate.suggestions().is_empty());
}

#[test]
fn context_words_lower_the_estimate() {
    let text = "Glimmerdale Orchard 77";
    let without = estimate(text, "").unwrap();
    let with = estimate(text, "glimmerdale").unwrap();
    assert!(
        with.log10_guesses() < without.log10_guesses(),
        "{} vs {}",
        with.log10_guesses(),
        without.log10_guesses()
    );
}

/// Adversarial shapes at the 256-byte limit finish well inside the timeout.
#[test]
fn adversarial_inputs_at_the_limit_finish_in_time() {
    let shapes = [
        "a".repeat(256),
        "ab".repeat(128),
        "qwertyuiop".repeat(26)[..256].to_string(),
        "1234567890".repeat(26)[..256].to_string(),
        "19850101".repeat(32),
        "Password1!".repeat(26)[..256].to_string(),
        "correct horse battery staple ".repeat(9)[..256].to_string(),
        (0..256)
            .map(|i| char::from(b'!' + (i * 7 % 94) as u8))
            .collect(),
        "\u{e9}".repeat(128),
    ];
    for shape in &shapes {
        assert_eq!(shape.len(), 256);
        let started = std::time::Instant::now();
        let estimate = estimate(shape, "").unwrap();
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
        assert!(estimate.log10_guesses() >= 0.0);
    }
}

#[test]
fn a_timeout_refuses_the_estimate() {
    let custom = handle_custom(b"any passphrase at all").unwrap();
    let result = estimator::estimate_with(program(), custom.bytes(), "", Duration::ZERO);
    assert!(matches!(result, Err(pvault_core::Error::Estimator)));
}

#[test]
fn oversized_input_is_refused_before_any_process_starts() {
    // A program that does not exist: reaching spawn would also fail, but with
    // the same error, so the size check is also covered by a unit test.
    let mut big = vec![b'a'; 257];
    let secret = SecretBuf::take_from(&mut big);
    let missing = Path::new("/nonexistent/pvault-estimator");
    assert!(estimator::estimate_with(missing, &secret, "", TIMEOUT).is_err());
}

#[test]
fn a_missing_program_refuses_the_estimate() {
    let custom = handle_custom(b"any passphrase at all").unwrap();
    let missing = Path::new("/nonexistent/pvault-estimator");
    assert!(estimator::estimate_with(missing, custom.bytes(), "", TIMEOUT).is_err());
}

/// Runs the child directly with raw stdin and returns (exit code, stdout).
fn run_child(stdin: &[u8]) -> (Option<i32>, Vec<u8>) {
    let mut child = Command::new(program())
        .arg(CHILD_ARG)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(output.stderr.is_empty(), "the child never writes to stderr");
    (output.status.code(), output.stdout)
}

#[test]
fn the_child_rejects_malformed_requests_without_output() {
    for request in [
        &[][..],                             // nothing
        &[0x00][..],                         // truncated length
        &[0x00, 0x00, 0x00][..],             // empty secret
        &[0x01, 0x01, b'a'][..],             // declares 257 bytes
        &[0x00, 0x03, b'a', b'b'][..],       // truncated secret
        &[0x00, 0x01, 0xff, 0x00][..],       // invalid UTF-8
        &[0x00, 0x01, b'a', 0x02, b'x'][..], // truncated context
    ] {
        let (code, stdout) = run_child(request);
        assert_ne!(code, Some(0), "{request:?}");
        assert!(stdout.is_empty(), "{request:?}");
    }
}

#[test]
fn the_child_replies_with_numbers_only() {
    let secret = b"Glimmerdale Orchard 77";
    let mut request = vec![0x00, secret.len() as u8];
    request.extend_from_slice(secret);
    request.push(0);
    let (code, stdout) = run_child(&request);
    assert_eq!(code, Some(0));
    assert_eq!(stdout[0], 1, "reply version");
    assert!(stdout.len() <= 64);
    assert!(!stdout.windows(4).any(|w| secret.windows(4).any(|s| s == w)));
}

#[test]
fn the_marker_with_other_arguments_is_not_the_child() {
    let output = Command::new(program())
        .args([CHILD_ARG, "extra"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Usage"));
}
