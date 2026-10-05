//! Argon2 memory policy and resource checks (spec 4.3; SI-16; D8).
//!
//! The order is fixed, and every check runs before any Argon2 allocation:
//! 1. hard caps (format validity, checked when the header is parsed): out of
//!    range is `Unlock failed.`;
//! 2. policy: `argon2_m` must be at most 50% of **total** RAM;
//! 3. resource: **available** memory must cover `argon2_m` + 64 MiB.
//!
//! Stored parameters are never lowered. A failed memory query is the
//! resource refusal; nothing falls back to a weaker estimate.

use crate::crypto::kdf::Argon2Params;
use crate::errors::Error;

/// The 4.3 resource margin.
pub const MARGIN_BYTES: u64 = 64 << 20;

/// Source of memory figures. Production uses [`SystemMemory`]; tests mock
/// it (F76).
pub trait MemoryProbe {
    /// Total physical memory, in bytes.
    fn total(&self) -> Option<u64>;
    /// Available memory, in bytes.
    fn available(&self) -> Option<u64>;
}

/// The platform queries of [`crate::platform::memory`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemMemory;

impl MemoryProbe for SystemMemory {
    fn total(&self) -> Option<u64> {
        crate::platform::memory::total_memory().ok()
    }

    fn available(&self) -> Option<u64> {
        crate::platform::memory::available_memory().ok()
    }
}

fn mib(bytes: u64) -> u64 {
    bytes.div_ceil(1 << 20)
}

/// Runs the 4.3 checks for `params`, in order. The hard caps come first,
/// as defense in depth (the header parser already enforces them).
pub fn check_argon2(params: &Argon2Params, probe: &dyn MemoryProbe) -> Result<(), Error> {
    params.check_hard_caps()?;
    let m_bytes = u64::from(params.m_kib) * 1024;
    // Policy: m ≤ 50% of total RAM. An unknown total refuses with the
    // resource message, before any allocation.
    let total = probe.total().ok_or(Error::MemoryResource {
        needed_mib: mib(m_bytes),
    })?;
    if m_bytes > total / 2 {
        return Err(Error::MemoryPolicy {
            needed_mib: mib(m_bytes),
        });
    }
    check_available(m_bytes + MARGIN_BYTES, probe)
}

/// The resource check alone: `needed` bytes must be available.
pub fn check_available(needed: u64, probe: &dyn MemoryProbe) -> Result<(), Error> {
    match probe.available() {
        Some(a) if a >= needed => Ok(()),
        _ => Err(Error::MemoryResource {
            needed_mib: mib(needed),
        }),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) struct Fake(pub Option<u64>, pub Option<u64>);

    impl MemoryProbe for Fake {
        fn total(&self) -> Option<u64> {
            self.0
        }
        fn available(&self) -> Option<u64> {
            self.1
        }
    }

    const GIB: u64 = 1 << 30;

    /// F76: within the caps but above policy or available memory gives the
    /// specific messages; F13: outside the caps fails first.
    #[test]
    fn checks_run_in_order_f13_f76() {
        let p = Argon2Params::DEFAULT; // 1 GiB
        assert!(check_argon2(&p, &Fake(Some(8 * GIB), Some(4 * GIB))).is_ok());
        // Exactly at the boundaries.
        assert!(check_argon2(&p, &Fake(Some(2 * GIB), Some(GIB + MARGIN_BYTES))).is_ok());
        // Policy: more than half of total RAM.
        assert!(matches!(
            check_argon2(&p, &Fake(Some(2 * GIB - 1), Some(8 * GIB))),
            Err(Error::MemoryPolicy { needed_mib: 1024 })
        ));
        // Resource: one byte short of m + 64 MiB.
        assert!(matches!(
            check_argon2(&p, &Fake(Some(8 * GIB), Some(GIB + MARGIN_BYTES - 1))),
            Err(Error::MemoryResource { .. })
        ));
        // Query failures refuse; they never skip the check.
        assert!(matches!(
            check_argon2(&p, &Fake(None, Some(8 * GIB))),
            Err(Error::MemoryResource { .. })
        ));
        assert!(matches!(
            check_argon2(&p, &Fake(Some(8 * GIB), None)),
            Err(Error::MemoryResource { .. })
        ));
        // Hard caps come before any query.
        let huge = Argon2Params {
            m_kib: 1 << 30,
            ..p
        };
        assert!(matches!(
            check_argon2(&huge, &Fake(None, None)),
            Err(Error::KdfParams)
        ));
        // The messages name only public quantities.
        let msg = Error::MemoryPolicy { needed_mib: 1024 }.to_string();
        assert_eq!(
            msg,
            "This vault needs 1024 MiB of memory, more than this computer can provide."
        );
    }
}
