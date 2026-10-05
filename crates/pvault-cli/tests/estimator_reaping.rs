//! A failed estimate leaves no estimator process behind (SI-51). Runs in its
//! own test process, so no other test's children can interfere.

#[cfg(unix)]
#[test]
#[allow(unsafe_code)]
fn timed_out_children_are_killed_and_reaped() {
    use std::path::Path;
    use std::time::Duration;

    use pvault_core::estimator;
    use pvault_core::passphrase::handle_custom;

    let custom = handle_custom(b"any passphrase at all").unwrap();
    let program = Path::new(env!("CARGO_BIN_EXE_pvault"));
    for _ in 0..5 {
        let result = estimator::estimate_with(program, custom.bytes(), "", Duration::ZERO);
        assert!(result.is_err());
    }
    // No child of this process remains, running or as a zombie.
    // SAFETY: `waitpid` with a null status pointer and `WNOHANG` only
    // queries this process's children.
    let rc = unsafe { libc::waitpid(-1, core::ptr::null_mut(), libc::WNOHANG) };
    assert_eq!(rc, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}
