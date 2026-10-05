//! Vault locking: the gate-lock protocol (spec 8.4; SI-14; D4).
//!
//! | File | Mode | Role |
//! | --- | --- | --- |
//! | `vault.gate` (G) | exclusive only | Held only while the mode of L changes; never held while waiting |
//! | `vault.lock` (L) | shared or exclusive | The vault lock |
//!
//! - **Lock files:** zero-length regular files, created without following
//!   symlinks, owner-only, never deleted, and opened at most once per process.
//! - **Waiting:** every attempt is non-blocking. The one bounded wait (2 s)
//!   is a holder of L retrying G.
//! - **No re-locking:** a handle that holds a lock is never locked again;
//!   conversion is unlock-then-lock on the same handle, under G.
//! - **Crashes:** the OS releases advisory locks when a process dies, so
//!   there is no stale-lock cleanup.
//!
//! The mount lock (`vault.mount`) and upgrade-for-commit belong to SI-45
//! (Milestone 11).

use std::fs::File;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::errors::Error;
use crate::platform::fs::{Dir, FileIdentity};

const GATE: &str = "vault.gate";
const LOCK: &str = "vault.lock";
/// The bounded wait for G while holding L.
pub const GATE_RETRY: Duration = Duration::from_secs(2);

/// Lock files currently open in this process (the once-per-process rule).
static OPEN: Mutex<Vec<FileIdentity>> = Mutex::new(Vec::new());

/// One lock file, registered for the life of the handle.
#[derive(Debug)]
struct LockFile {
    file: File,
    id: FileIdentity,
}

impl LockFile {
    fn open(dir: &Dir, name: &'static str) -> Result<Self, Error> {
        let file = match dir.open_regular(name, true).map_err(Error::Io)? {
            Some(f) => f,
            None => match dir.create_new(name) {
                Ok(f) => {
                    dir.flush().map_err(Error::Io)?;
                    f
                }
                // A concurrent process created it first.
                Err(_) => dir
                    .open_regular(name, true)
                    .map_err(Error::Io)?
                    .ok_or(Error::Blocked("lock file"))?,
            },
        };
        if file.metadata().map_err(Error::Io)?.len() != 0 {
            return Err(Error::Blocked("a lock file is not empty"));
        }
        let id = dir.identity(&file).map_err(Error::Io)?;
        let mut open = OPEN.lock().unwrap_or_else(|e| e.into_inner());
        if open.contains(&id) {
            return Err(Error::Unsupported(
                "a vault lock file is already open in this process",
            ));
        }
        open.push(id);
        Ok(Self { file, id })
    }
}

impl Drop for LockFile {
    fn drop(&mut self) {
        let mut open = OPEN.lock().unwrap_or_else(|e| e.into_inner());
        open.retain(|i| *i != self.id);
    }
}

/// The mode L is held in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    /// Every mutation and the start of every ordinary unlock.
    Exclusive,
    /// Read-only work after an unlock (`list`, `get`).
    Shared,
}

/// A held vault lock.
#[derive(Debug)]
pub struct VaultLock {
    gate: LockFile,
    lock: LockFile,
    mode: LockMode,
}

fn try_exclusive(f: &File) -> Result<bool, Error> {
    match f.try_lock() {
        Ok(()) => Ok(true),
        Err(std::fs::TryLockError::WouldBlock) => Ok(false),
        Err(std::fs::TryLockError::Error(e)) => Err(Error::Io(e)),
    }
}

fn try_shared(f: &File) -> Result<bool, Error> {
    match f.try_lock_shared() {
        Ok(()) => Ok(true),
        Err(std::fs::TryLockError::WouldBlock) => Ok(false),
        Err(std::fs::TryLockError::Error(e)) => Err(Error::Io(e)),
    }
}

impl VaultLock {
    /// Exclusive acquire:
    /// 1. try G; busy means "in use";
    /// 2. try L exclusive; busy means release G, then "in use";
    /// 3. release G and keep L.
    pub fn exclusive(dir: &Dir) -> Result<Self, Error> {
        let gate = LockFile::open(dir, GATE)?;
        let lock = LockFile::open(dir, LOCK)?;
        if !try_exclusive(&gate.file)? {
            return Err(Error::VaultInUse);
        }
        let got = try_exclusive(&lock.file);
        let _ = gate.file.unlock();
        if !got? {
            // The mount probe (`vault.mount`) is part of SI-45.
            return Err(Error::VaultInUse);
        }
        Ok(Self {
            gate,
            lock,
            mode: LockMode::Exclusive,
        })
    }

    /// Downgrade to shared: take G (bounded retry), unlock L, take L shared,
    /// release G. Against cooperating processes the shared attempt cannot
    /// fail, because every exclusive acquirer needs G.
    pub fn downgrade(&mut self) -> Result<(), Error> {
        if self.mode == LockMode::Shared {
            return Ok(());
        }
        let started = Instant::now();
        while !try_exclusive(&self.gate.file)? {
            if started.elapsed() >= GATE_RETRY {
                return Err(Error::VaultInUse);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let result = self
            .lock
            .file
            .unlock()
            .map_err(Error::Io)
            .and_then(|()| try_shared(&self.lock.file));
        let _ = self.gate.file.unlock();
        match result {
            Ok(true) => {
                self.mode = LockMode::Shared;
                Ok(())
            }
            Ok(false) => Err(Error::VaultInUse),
            Err(e) => Err(e),
        }
    }

    /// The current mode.
    pub fn mode(&self) -> LockMode {
        self.mode
    }
}

/// `status`: L shared only, never G. `Ok(None)` if L is held exclusively.
pub fn status_shared(dir: &Dir) -> Result<Option<StatusLock>, Error> {
    let lock = LockFile::open(dir, LOCK)?;
    if try_shared(&lock.file)? {
        Ok(Some(StatusLock { _lock: lock }))
    } else {
        Ok(None)
    }
}

/// A shared lock held by `status`.
#[derive(Debug)]
pub struct StatusLock {
    _lock: LockFile,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::fs::tests::tempdir;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    /// Child half of F56a: takes the lock in the requested mode, signals
    /// readiness with a file, then waits to be killed.
    #[test]
    #[ignore = "run by lock tests in a child process"]
    fn lock_holder_child() {
        let Some(path) = std::env::var_os("PVAULT_LOCK_DIR") else {
            return;
        };
        let path = Path::new(&path);
        let dir = Dir::open(path).unwrap();
        let mut lock = VaultLock::exclusive(&dir).unwrap();
        if std::env::var("PVAULT_LOCK_MODE").as_deref() == Ok("shared") {
            lock.downgrade().unwrap();
        }
        std::fs::write(path.join("ready"), b"").unwrap();
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    fn holder(path: &Path, mode: &str) -> Child {
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "lock::tests::lock_holder_child",
                "--ignored",
                "--test-threads=1",
            ])
            .env("PVAULT_LOCK_DIR", path)
            .env("PVAULT_LOCK_MODE", mode)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let start = Instant::now();
        while !path.join("ready").exists() {
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "child never locked"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        std::fs::remove_file(path.join("ready")).unwrap();
        child
    }

    /// F56a: a second mutating process is refused; a crashed holder's lock
    /// is released by the OS.
    #[test]
    fn concurrent_processes_and_crash_release() {
        let tmp = tempdir();
        let dir = Dir::open(&tmp).unwrap();
        let mut child = holder(&tmp, "exclusive");
        assert!(matches!(VaultLock::exclusive(&dir), Err(Error::VaultInUse)));
        assert!(
            status_shared(&dir).unwrap().is_none(),
            "status sees an exclusive holder"
        );
        // Crash the holder (SIGKILL / TerminateProcess): no cleanup runs.
        child.kill().unwrap();
        child.wait().unwrap();
        let lock = VaultLock::exclusive(&dir).unwrap();
        assert_eq!(lock.mode(), LockMode::Exclusive);
        drop(lock);

        // A shared holder (after downgrade) blocks mutation but not status.
        let mut child = holder(&tmp, "shared");
        assert!(matches!(VaultLock::exclusive(&dir), Err(Error::VaultInUse)));
        let status = status_shared(&dir).unwrap();
        assert!(status.is_some());
        drop(status);
        child.kill().unwrap();
        child.wait().unwrap();
        VaultLock::exclusive(&dir).unwrap();
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn downgrade_and_once_per_process() {
        let tmp = tempdir();
        let dir = Dir::open(&tmp).unwrap();
        let mut lock = VaultLock::exclusive(&dir).unwrap();
        // The same lock file is never opened twice in one process.
        assert!(matches!(
            VaultLock::exclusive(&dir),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(status_shared(&dir), Err(Error::Unsupported(_))));
        lock.downgrade().unwrap();
        assert_eq!(lock.mode(), LockMode::Shared);
        lock.downgrade().unwrap();
        drop(lock);
        // Released handles leave the registry.
        let lock = VaultLock::exclusive(&dir).unwrap();
        drop(lock);
        for name in [GATE, LOCK] {
            assert_eq!(
                std::fs::metadata(tmp.join(name)).unwrap().len(),
                0,
                "{name}"
            );
        }
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn unusual_lock_files_are_refused() {
        let tmp = tempdir();
        let dir = Dir::open(&tmp).unwrap();
        std::fs::write(tmp.join(LOCK), b"x").unwrap();
        assert!(matches!(VaultLock::exclusive(&dir), Err(Error::Blocked(_))));
        std::fs::remove_file(tmp.join(LOCK)).unwrap();
        std::fs::create_dir(tmp.join(LOCK)).unwrap();
        assert!(VaultLock::exclusive(&dir).is_err());
        #[cfg(unix)]
        {
            std::fs::remove_dir(tmp.join(LOCK)).unwrap();
            std::fs::write(tmp.join("elsewhere"), b"").unwrap();
            std::os::unix::fs::symlink(tmp.join("elsewhere"), tmp.join(LOCK)).unwrap();
            assert!(VaultLock::exclusive(&dir).is_err());
        }
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn lock_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempdir();
        let dir = Dir::open(&tmp).unwrap();
        drop(VaultLock::exclusive(&dir).unwrap());
        for name in [GATE, LOCK] {
            let mode = std::fs::metadata(tmp.join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "{name}: {mode:o}");
        }
        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
