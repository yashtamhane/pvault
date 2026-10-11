//! Tests that start processes run one at a time in a test process of their
//! own (`docs/M5_READINESS.md`, V2).
//!
//! The shared test process runs tests on parallel threads. Starting a process
//! (fork, then `exec`) briefly duplicates every descriptor of the test
//! process into the child, other tests' vault locks included, so a test that
//! releases a lock and takes it again could find it still held until the
//! child's `exec`. Every test that starts a process is therefore ignored in
//! the shared process and run by
//! [`tests_that_start_processes_run_in_their_own_process`] instead: one child
//! test process, one test thread, where no other test holds a lock while a
//! process starts. That runner is the only test in the shared process that
//! starts a process, once per run.
//!
//! Windows has no fork and opens files as non-inheritable handles, so its
//! Windows-only process starts (`icacls`, `subst`, `net`) are not affected
//! and stay where they are.

use std::process::Command;

/// Set in the isolated test process (and inherited by what it starts).
pub(crate) const ISOLATED_ENV: &str = "PVAULT_TEST_ISOLATED_PROCESS";

/// Refuses to start a process from the shared, parallel test process. Called
/// by every test helper that starts one.
pub(crate) fn assert_isolated() {
    assert!(
        std::env::var_os(ISOLATED_ENV).is_some(),
        "this test starts processes and runs only in its own test process: run \
         test_process::tests_that_start_processes_run_in_their_own_process, or set \
         {ISOLATED_ENV}=1 with --ignored --exact <name> --test-threads=1"
    );
}

/// The tests the runner runs, by exact name. Each is
/// `#[ignore = "starts processes: runs in its own test process (test_process)"]`.
fn isolated() -> Vec<&'static str> {
    // Extended below on Unix only.
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut names = vec![
        "test_process::the_isolated_set_is_complete",
        "lock::tests::concurrent_processes_and_crash_release",
        "store::tests::crash_before_replacement_stays_old",
        "store::tests::missing_tracking_header_temp_blocks_without_cleanup",
        "store::tests::new_side_restart_after_commit",
        "store::tests::reencrypted_tracking_keytable_is_indeterminate",
        "store::tests::replaced_tracking_keytable_blocks",
        "store::tests::tracking_crash_restart_matrix",
        "vault::tests::source_kinds_are_refused",
    ];
    #[cfg(unix)]
    names.extend([
        "platform::terminal::tests::restored_after_sighup",
        "platform::terminal::tests::restored_after_sigint",
        "platform::terminal::tests::restored_after_sigquit",
        "platform::terminal::tests::restored_after_sigterm",
    ]);
    #[cfg(all(target_os = "linux", feature = "tpm"))]
    names.extend([
        "tpm::tests::emulator::capability_setups",
        "tpm::tests::emulator::define_write_read_undefine",
        "tpm::tests::emulator::h2_template_is_built_by_pvault",
        "tpm::tests::emulator::parameter_encryption_on_the_wire",
        "tpm::tests::emulator::raced_handle_is_reported_and_untouched",
        "tpm::tests::emulator::response_codes_are_classified_by_layer",
        "tpm::tests::emulator::wrong_auth_counts_and_locks_out",
        "vault::tests::bound::bound_duress_set_and_disable",
        "vault::tests::bound::bound_init_unlock_and_everyday_commands",
        "vault::tests::bound::bound_vault_needs_its_index",
        "vault::tests::bound::decoy_public_areas",
        "vault::tests::bound::digital_bound_card_and_check",
        "vault::tests::bound::duress_availability",
        "vault::tests::bound::interrupted_after_the_header",
        "vault::tests::bound::interrupted_before_the_header",
        "vault::tests::bound::owner_authorization",
        "vault::tests::bound::raced_handle_starts_over",
        "vault::tests::bound::unknown_define_outcome_is_resolved_by_the_resume",
        "vault::tests::bound::unmeasurable_identity_refuses_bound_init",
        "vault::tests::bound::wrong_passphrase_and_lockout",
    ]);
    names
}

/// Ignored tests the runner does not run: helper processes started by the
/// tests above, and measurements or probes run explicitly.
fn other_ignored() -> Vec<&'static str> {
    let mut names = vec![
        "card::tests::qr_reliability_measurement",
        "fuzz_seeds::fuzz_seeds",
        "lock::tests::lock_holder_child",
        "store::tests::crash_child",
    ];
    #[cfg(unix)]
    names.push("platform::terminal::tests::signal_helper_reads_from_pty");
    #[cfg(windows)]
    names.push("platform::fs::tests::windows_native_locality_probe_mappings");
    names
}

/// Runs every test in [`isolated`] in one child test process, one at a time,
/// and fails unless the child succeeded and each of them ran and passed.
#[test]
fn tests_that_start_processes_run_in_their_own_process() {
    // The child selects only ignored tests by exact name, so it cannot
    // select this test; this check also stops a run with --include-ignored.
    assert!(
        std::env::var_os(ISOLATED_ENV).is_none(),
        "the runner does not run inside the isolated test process"
    );
    let names = isolated();
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "--test-threads=1"])
        .args(&names)
        .env(ISOLATED_ENV, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let report = format!("{stdout}{}", String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "the isolated tests failed:\n{report}");
    assert!(
        stdout.contains(&format!("running {} tests\n", names.len())),
        "expected {} tests:\n{report}",
        names.len()
    );
    for name in &names {
        assert!(
            stdout.contains(&format!("test {name} ... ok\n")),
            "{name} did not run and pass:\n{report}"
        );
    }
    // Shown with --nocapture; CI checks it (`.github/workflows/ci.yml`).
    eprintln!(
        "{} isolated tests passed in their own process:",
        names.len()
    );
    for name in &names {
        eprintln!("  {name}");
    }
}

/// Every ignored test is either run by the runner or a known helper or
/// probe, and every name the runner expects is an ignored test. Runs in the
/// isolated process (it starts one to list the tests).
#[test]
#[ignore = "starts processes: runs in its own test process (test_process)"]
fn the_isolated_set_is_complete() {
    assert_isolated();
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--list", "--ignored"])
        .output()
        .unwrap();
    assert!(out.status.success(), "listing the ignored tests failed");
    let listed: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.strip_suffix(": test"))
        .map(str::to_owned)
        .collect();
    let (isolated, other) = (isolated(), other_ignored());
    for name in &listed {
        assert!(
            isolated.contains(&name.as_str()) || other.contains(&name.as_str()),
            "{name} is ignored but neither run by the isolated runner nor a known helper"
        );
    }
    for name in isolated.iter().chain(&other) {
        assert!(
            listed.iter().any(|l| l == name),
            "{name} is not an ignored test"
        );
    }
}
