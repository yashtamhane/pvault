//! Smoke tests for the `pvault` binary.

use assert_cmd::Command;

fn pvault() -> Command {
    Command::cargo_bin("pvault").unwrap()
}

#[test]
fn version_prints_name_and_version() {
    let output = pvault().arg("--version").output().unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("pvault {}\n", env!("CARGO_PKG_VERSION"))
    );
    // Core-dump disabling succeeded, so no warning was printed.
    assert_eq!(String::from_utf8(output.stderr).unwrap(), "");
}

#[test]
fn help_describes_the_tool() {
    let output = pvault().arg("--help").output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Offline encrypted file vault"), "{stdout}");
}

#[test]
fn no_arguments_shows_help_and_fails() {
    let output = pvault().output().unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Usage: pvault"), "{stderr}");
}
