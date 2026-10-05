//! Memory queries and best-effort memory locking (spec 4.3, 10.2; 7.6a;
//! D8).
//!
//! | Platform | Total RAM | Available memory |
//! | --- | --- | --- |
//! | Linux | `sysinfo(2)`: `totalram × mem_unit` | `MemAvailable` in `/proc/meminfo`; absent or malformed is an error |
//! | macOS | `sysctlbyname("hw.memsize")` | `sysconf(_SC_PAGESIZE) × (free_count + inactive_count)` from `host_statistics64(HOST_VM_INFO64)` |
//! | Windows | `GlobalMemoryStatusEx`: `ullTotalPhys` | `GlobalMemoryStatusEx`: `ullAvailPhys` |
//!
//! Every failure is an error. Callers turn it into the 4.3 resource refusal,
//! before any allocation; nothing falls back to a weaker estimate.

use std::io;

/// Total physical memory, in bytes.
pub fn total_memory() -> io::Result<u64> {
    imp::total_memory()
}

/// Currently available memory, in bytes (definition per platform above).
pub fn available_memory() -> io::Result<u64> {
    imp::available_memory()
}

/// Locks `len` bytes at `ptr` into RAM, best effort. Returns whether the
/// lock succeeded. A failure is reported by the caller, never fatal unless
/// strict mode is on (10.2, Milestone 7).
pub(crate) fn lock_region(ptr: *const u8, len: usize) -> bool {
    len == 0 || imp::lock_region(ptr, len)
}

/// Undoes [`lock_region`].
pub(crate) fn unlock_region(ptr: *const u8, len: usize) {
    if len != 0 {
        imp::unlock_region(ptr, len);
    }
}

/// Parses the `MemAvailable` line of `/proc/meminfo`, in bytes.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn parse_mem_available(meminfo: &str) -> Option<u64> {
    let line = meminfo.lines().find(|l| l.starts_with("MemAvailable:"))?;
    let mut fields = line["MemAvailable:".len()..].split_whitespace();
    let kib: u64 = fields.next()?.parse().ok()?;
    if fields.next()? != "kB" || fields.next().is_some() {
        return None;
    }
    kib.checked_mul(1024)
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod imp {
    use std::io;

    pub(super) fn total_memory() -> io::Result<u64> {
        let mut info = core::mem::MaybeUninit::<libc::sysinfo>::uninit();
        // SAFETY: `info` is a writable `sysinfo` struct that outlives the call.
        if unsafe { libc::sysinfo(info.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `sysinfo` succeeded and filled the struct.
        let info = unsafe { info.assume_init() };
        // `totalram` is `u64` on 64-bit targets and `u32` on 32-bit ones.
        #[allow(clippy::useless_conversion)]
        let total = u64::from(info.totalram);
        total
            .checked_mul(u64::from(info.mem_unit))
            .ok_or_else(|| io::Error::other("total memory overflows"))
    }

    pub(super) fn available_memory() -> io::Result<u64> {
        let text = std::fs::read_to_string("/proc/meminfo")?;
        super::parse_mem_available(&text)
            .ok_or_else(|| io::Error::other("MemAvailable is absent or malformed"))
    }

    pub(super) fn lock_region(ptr: *const u8, len: usize) -> bool {
        // SAFETY: the caller passes a live allocation of `len` bytes.
        unsafe { libc::mlock(ptr.cast(), len) == 0 }
    }

    pub(super) fn unlock_region(ptr: *const u8, len: usize) {
        // SAFETY: as in `lock_region`.
        unsafe { libc::munlock(ptr.cast(), len) };
    }
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod imp {
    use std::io;

    pub(super) fn total_memory() -> io::Result<u64> {
        let mut value: u64 = 0;
        let mut size = core::mem::size_of::<u64>();
        // SAFETY: the name is NUL-terminated; `value` and `size` are valid
        // and describe an 8-byte output buffer.
        let rc = unsafe {
            libc::sysctlbyname(
                c"hw.memsize".as_ptr(),
                (&raw mut value).cast(),
                &mut size,
                core::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 || size != core::mem::size_of::<u64>() {
            return Err(io::Error::last_os_error());
        }
        Ok(value)
    }

    pub(super) fn available_memory() -> io::Result<u64> {
        // SAFETY: `sysconf` has no memory-safety preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page = u64::try_from(page).map_err(|_| io::Error::other("page size"))?;
        if page == 0 {
            return Err(io::Error::other("page size"));
        }
        let mut stats = core::mem::MaybeUninit::<libc::vm_statistics64>::zeroed();
        let mut count = libc::HOST_VM_INFO64_COUNT;
        // SAFETY: `mach_host_self` has no preconditions. `libc` marks it
        // deprecated in favor of the unapproved `mach2` crate; the call is the
        // same Mach trap.
        #[allow(deprecated)]
        let host = unsafe { libc::mach_host_self() };
        // SAFETY: `stats` is a writable `vm_statistics64`, and `count` gives
        // its size in `integer_t` units, as the API requires.
        let kr = unsafe {
            libc::host_statistics64(
                host,
                libc::HOST_VM_INFO64,
                stats.as_mut_ptr().cast(),
                &mut count,
            )
        };
        if kr != libc::KERN_SUCCESS {
            return Err(io::Error::other("host_statistics64 failed"));
        }
        // The result must be long enough to include `inactive_count`
        // (the third 32-bit field).
        if count < 3 {
            return Err(io::Error::other("short HOST_VM_INFO64 result"));
        }
        // SAFETY: the call succeeded; the struct was zeroed beforehand, so
        // fields beyond `count` are zero rather than uninitialized.
        let stats = unsafe { stats.assume_init() };
        // `free_count` already includes speculative pages (vm_statistics.h).
        u64::from(stats.free_count)
            .checked_add(u64::from(stats.inactive_count))
            .and_then(|pages| pages.checked_mul(page))
            .ok_or_else(|| io::Error::other("available memory overflows"))
    }

    pub(super) fn lock_region(ptr: *const u8, len: usize) -> bool {
        // SAFETY: the caller passes a live allocation of `len` bytes.
        unsafe { libc::mlock(ptr.cast(), len) == 0 }
    }

    pub(super) fn unlock_region(ptr: *const u8, len: usize) {
        // SAFETY: as in `lock_region`.
        unsafe { libc::munlock(ptr.cast(), len) };
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod imp {
    use std::io;

    use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    fn status() -> io::Result<MEMORYSTATUSEX> {
        // SAFETY: an all-zero MEMORYSTATUSEX is valid; dwLength is set below.
        let mut s: MEMORYSTATUSEX = unsafe { core::mem::zeroed() };
        s.dwLength = core::mem::size_of::<MEMORYSTATUSEX>() as u32;
        // SAFETY: `s` is a writable MEMORYSTATUSEX with dwLength set.
        if unsafe { GlobalMemoryStatusEx(&mut s) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(s)
    }

    pub(super) fn total_memory() -> io::Result<u64> {
        Ok(status()?.ullTotalPhys)
    }

    pub(super) fn available_memory() -> io::Result<u64> {
        Ok(status()?.ullAvailPhys)
    }

    pub(super) fn lock_region(ptr: *const u8, len: usize) -> bool {
        // SAFETY: the caller passes a live allocation of `len` bytes.
        unsafe { VirtualLock(ptr as *const core::ffi::c_void, len) != 0 }
    }

    pub(super) fn unlock_region(ptr: *const u8, len: usize) {
        // SAFETY: as in `lock_region`.
        unsafe { VirtualUnlock(ptr as *const core::ffi::c_void, len) };
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod imp {
    use std::io;

    pub(super) fn total_memory() -> io::Result<u64> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    pub(super) fn available_memory() -> io::Result<u64> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    pub(super) fn lock_region(_: *const u8, _: usize) -> bool {
        false
    }

    pub(super) fn unlock_region(_: *const u8, _: usize) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meminfo_parsing_is_strict() {
        let ok = "MemTotal:  100 kB\nMemAvailable:    2048 kB\n";
        assert_eq!(parse_mem_available(ok), Some(2048 * 1024));
        for bad in [
            "MemTotal: 100 kB\n",
            "MemAvailable: x kB\n",
            "MemAvailable: 10 MB\n",
            "MemAvailable: 10\n",
            "MemAvailable: 10 kB extra\n",
            "MemAvailable: 18446744073709551615 kB\n",
        ] {
            assert_eq!(parse_mem_available(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_running_system_answers_plausibly() {
        let total = total_memory().unwrap();
        let available = available_memory().unwrap();
        assert!(total >= 256 << 20, "{total}");
        assert!(available <= total, "{available} {total}");
    }

    #[test]
    fn locking_a_small_region_works_or_reports_failure() {
        let buf = vec![0u8; 4096];
        if lock_region(buf.as_ptr(), buf.len()) {
            unlock_region(buf.as_ptr(), buf.len());
        }
    }
}
