//! Estimator child hardening (SI-51). Runs in its own test process, because
//! the limits apply to the whole process.

#[cfg(unix)]
#[test]
#[allow(unsafe_code)]
fn hardening_sets_the_child_limits() {
    pvault_core::platform::harden_estimator_child().unwrap();

    let get = |resource| {
        let mut limit = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        // SAFETY: `limit` is a valid, writable `rlimit` that outlives the call.
        assert_eq!(unsafe { libc::getrlimit(resource, &mut limit) }, 0);
        (limit.rlim_cur, limit.rlim_max)
    };
    assert_eq!(get(libc::RLIMIT_CORE), (0, 0));
    assert_eq!(get(libc::RLIMIT_CPU), (5, 5));
    #[cfg(target_os = "linux")]
    assert_eq!(get(libc::RLIMIT_AS), (512 << 20, 512 << 20));
}
