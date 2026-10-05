//! Core-dump disabling (spec Section 10.3). Runs in its own test process.

use pvault_core::platform::{CoreDumpProtection, disable_core_dumps};

#[cfg(unix)]
#[test]
#[allow(unsafe_code)]
fn core_dumps_are_disabled() {
    assert_eq!(disable_core_dumps().unwrap(), CoreDumpProtection::Disabled);

    let mut limit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: `limit` is a valid, writable `rlimit` that outlives the call.
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
    assert_eq!(limit.rlim_cur, 0);
    assert_eq!(limit.rlim_max, 0);

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let zero: libc::c_ulong = 0;
        // SAFETY: `PR_GET_DUMPABLE` takes no pointer arguments.
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, zero, zero, zero, zero) };
        assert_eq!(dumpable, 0);
    }

    // Calling it again is harmless.
    assert_eq!(disable_core_dumps().unwrap(), CoreDumpProtection::Disabled);
}

#[cfg(windows)]
#[test]
#[allow(unsafe_code)]
fn core_dumps_are_suppressed_best_effort() {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        GetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX,
    };

    assert_eq!(
        disable_core_dumps().unwrap(),
        CoreDumpProtection::BestEffort
    );

    // SAFETY: `GetErrorMode` takes no arguments and returns a flag value.
    let mode = unsafe { GetErrorMode() };
    let wanted = SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX;
    assert_eq!(mode & wanted, wanted);
}
