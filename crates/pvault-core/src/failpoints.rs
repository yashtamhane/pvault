//! Test-only crash injection (spec 11; SI-48; F85).
//!
//! - `failpoint!("name")` aborts the process when the environment variable
//!   `PVAULT_FAILPOINT` equals `name`. Crash tests run a child process with
//!   that variable and restart in the parent.
//! - `fail_io!("name")` does the same, and can instead return an injected
//!   I/O error: in unit tests through [`inject`], for the 8.5
//!   failure-boundary tests; in a child process when `PVAULT_FAILPOINT` is
//!   `name!io`, or a comma-separated list of such entries (several reported
//!   failures in one run), for scenario tests of reported failures.
//!
//! Both exist only in unit-test builds and in builds with the non-default
//! `fault-injection` feature. Everywhere else they expand to nothing, so no
//! failpoint name or the variable's name reaches a release artifact. A
//! release build that requests the feature is refused at compile time.

#[cfg(all(feature = "fault-injection", not(debug_assertions)))]
compile_error!("the `fault-injection` feature is test-only and is refused in release builds (F85)");

/// Aborts if `name` is the selected failpoint. `PVAULT_FAILPOINT=name#n`
/// selects the `n`-th hit (default 1).
#[cfg(any(test, feature = "fault-injection"))]
pub(crate) fn hit(name: &str) {
    use std::sync::atomic::{AtomicU32, Ordering};
    static HITS: AtomicU32 = AtomicU32::new(0);
    let Some(v) = std::env::var_os("PVAULT_FAILPOINT") else {
        return;
    };
    let v = v.to_string_lossy();
    let (selected, nth) = match v.split_once('#') {
        Some((n, k)) => (n, k.parse().unwrap_or(1)),
        None => (&*v, 1),
    };
    if selected == name && HITS.fetch_add(1, Ordering::SeqCst) + 1 == nth {
        std::process::abort();
    }
}

#[cfg(test)]
thread_local! {
    static INJECTED: std::cell::RefCell<Vec<&'static str>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Makes the next `fail_io!(name)` on this thread return an error.
#[cfg(test)]
pub(crate) fn inject(name: &'static str) {
    INJECTED.with(|i| i.borrow_mut().push(name));
}

/// Aborts like [`hit`], or returns an injected error.
#[cfg(any(test, feature = "fault-injection"))]
pub(crate) fn hit_io(name: &str) -> std::io::Result<()> {
    if std::env::var_os("PVAULT_FAILPOINT").is_some_and(|v| {
        v.to_str()
            .is_some_and(|v| v.split(',').any(|e| e.strip_suffix("!io") == Some(name)))
    }) {
        return Err(std::io::Error::other("injected failure"));
    }
    hit(name);
    #[cfg(test)]
    {
        let found = INJECTED.with(|i| {
            let mut i = i.borrow_mut();
            let pos = i.iter().position(|n| *n == name);
            pos.map(|p| i.remove(p)).is_some()
        });
        if found {
            return Err(std::io::Error::other("injected failure"));
        }
    }
    Ok(())
}

/// A named crash-injection point.
#[cfg(any(test, feature = "fault-injection"))]
macro_rules! failpoint {
    ($name:literal) => {
        $crate::failpoints::hit($name)
    };
}

/// A named crash-injection point (compiled out).
#[cfg(not(any(test, feature = "fault-injection")))]
macro_rules! failpoint {
    ($name:literal) => {};
}

/// A named crash or I/O-error injection point; evaluates to
/// `std::io::Result<()>`.
#[cfg(any(test, feature = "fault-injection"))]
macro_rules! fail_io {
    ($name:literal) => {
        $crate::failpoints::hit_io($name)
    };
}

/// A named crash or I/O-error injection point (compiled out).
#[cfg(not(any(test, feature = "fault-injection")))]
macro_rules! fail_io {
    ($name:literal) => {
        ::std::io::Result::<()>::Ok(())
    };
}
