//! Platform FFI (spec Section 7.6a).
//!
//! Every call into `libc` or `windows-sys` lives under this module, and each
//! `unsafe` block carries a reviewed `// SAFETY:` comment.

use crate::errors::Error;

/// How well [`disable_core_dumps`] could protect this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreDumpProtection {
    /// Core dumps are off, and this process cannot turn them back on (Unix).
    /// On Linux the process is also marked non-dumpable, which additionally
    /// blocks `ptrace` attachment by other unprivileged processes of the same
    /// user.
    Disabled,
    /// Windows Error Reporting will not show a crash dialog and will not
    /// collect heap memory. A system-wide dump policy or an attached debugger
    /// can still capture memory.
    BestEffort,
}

/// Stops this process from writing its memory to disk if it crashes
/// (spec Section 10.3). Call once at startup, before handling any secret.
pub fn disable_core_dumps() -> Result<CoreDumpProtection, Error> {
    imp::disable_core_dumps().map_err(Error::CoreDumps)
}

#[cfg(unix)]
#[allow(unsafe_code)]
mod imp {
    use std::io;

    use super::CoreDumpProtection;

    pub(super) fn disable_core_dumps() -> io::Result<CoreDumpProtection> {
        // Lower the hard limit as well, so nothing later in this process can
        // raise the soft limit again.
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a fully initialized `rlimit` that outlives the
        // call, and `setrlimit` only reads through the pointer.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
            return Err(io::Error::last_os_error());
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let zero: libc::c_ulong = 0;
            // SAFETY: `PR_SET_DUMPABLE` reads only its integer arguments; no
            // pointers are passed.
            if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, zero, zero, zero, zero) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(CoreDumpProtection::Disabled)
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod imp {
    use std::io;

    use windows_sys::Win32::System::Diagnostics::Debug::{
        SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetErrorMode,
    };
    use windows_sys::Win32::System::ErrorReporting::{
        WER_FAULT_REPORTING_FLAG_NOHEAP, WerSetFlags,
    };

    use super::CoreDumpProtection;

    pub(super) fn disable_core_dumps() -> io::Result<CoreDumpProtection> {
        let wanted = SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX;
        // SAFETY: `SetErrorMode` takes and returns plain flag values and has
        // no pointer arguments. The second call keeps any flags that were
        // already set.
        unsafe {
            let previous = SetErrorMode(wanted);
            SetErrorMode(previous | wanted);
        }

        // SAFETY: `WerSetFlags` takes a plain flag value and has no pointer
        // arguments.
        let hr = unsafe { WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP) };
        if hr < 0 {
            return Err(io::Error::other(format!(
                "WerSetFlags failed with HRESULT {hr:#010x}"
            )));
        }

        Ok(CoreDumpProtection::BestEffort)
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use std::io;

    use super::CoreDumpProtection;

    pub(super) fn disable_core_dumps() -> io::Result<CoreDumpProtection> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}
