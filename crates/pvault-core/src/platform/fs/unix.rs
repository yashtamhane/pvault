//! Unix file-system primitives: every child operation is relative to the held
//! directory descriptor (`openat`, `mkdirat`, `renameat`, `unlinkat`) and
//! never follows a symlink.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

use super::{FileIdentity, Ownership, Volume};

#[derive(Debug)]
pub(super) struct Dir {
    fd: OwnedFd,
}

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in name"))
}

fn check(rc: libc::c_int) -> io::Result<libc::c_int> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

impl Dir {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        use std::os::unix::ffi::OsStrExt;
        let p = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))?;
        // SAFETY: `p` is a valid NUL-terminated path.
        let fd = check(unsafe {
            libc::open(
                p.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        // SAFETY: `fd` was just opened and is owned by nothing else.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self { fd })
    }

    fn raw(&self) -> libc::c_int {
        self.fd.as_raw_fd()
    }

    pub(super) fn open_dir(&self, name: &str) -> io::Result<Self> {
        let n = cstr(name)?;
        // SAFETY: valid directory fd and NUL-terminated name.
        let fd = check(unsafe {
            libc::openat(
                self.raw(),
                n.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        // SAFETY: `fd` was just opened and is owned by nothing else.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self { fd })
    }

    pub(super) fn create_dir(&self, name: &str) -> io::Result<()> {
        let n = cstr(name)?;
        // SAFETY: valid directory fd and NUL-terminated name.
        check(unsafe { libc::mkdirat(self.raw(), n.as_ptr(), 0o700) }).map(|_| ())
    }

    pub(super) fn create_new(&self, name: &str) -> io::Result<File> {
        let n = cstr(name)?;
        // SAFETY: valid directory fd and NUL-terminated name; the mode is
        // passed as the variadic argument `openat` expects with O_CREAT.
        let fd = check(unsafe {
            libc::openat(
                self.raw(),
                n.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        })?;
        // SAFETY: `fd` was just opened and is owned by nothing else.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    pub(super) fn open_regular(&self, name: &str, write: bool) -> io::Result<Option<File>> {
        let n = cstr(name)?;
        let mode = if write { libc::O_RDWR } else { libc::O_RDONLY };
        // O_NONBLOCK keeps a FIFO from blocking the open; the type is
        // checked right after.
        // SAFETY: valid directory fd and NUL-terminated name.
        let fd = unsafe {
            libc::openat(
                self.raw(),
                n.as_ptr(),
                mode | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            let e = io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(libc::ENOENT) => Ok(None),
                // A symlink (O_NOFOLLOW) or a directory opened for writing.
                Some(libc::ELOOP) | Some(libc::EISDIR) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "not a regular file",
                )),
                _ => Err(e),
            };
        }
        // SAFETY: `fd` was just opened and is owned by nothing else.
        let file = unsafe { File::from_raw_fd(fd) };
        if !file.metadata()?.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a regular file",
            ));
        }
        // Back to blocking mode for ordinary reads and writes.
        // SAFETY: plain flag changes on an open descriptor.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
        Ok(Some(file))
    }

    pub(super) fn exists(&self, name: &str) -> io::Result<bool> {
        let n = cstr(name)?;
        let mut st = core::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: valid directory fd, NUL-terminated name, writable stat.
        let rc = unsafe {
            libc::fstatat(
                self.raw(),
                n.as_ptr(),
                st.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc == 0 {
            return Ok(true);
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOENT) {
            Ok(false)
        } else {
            Err(e)
        }
    }

    pub(super) fn rename(&self, from: &str, to: &str, replace: bool) -> io::Result<()> {
        let (f, t) = (cstr(from)?, cstr(to)?);
        let rc = if replace {
            // SAFETY: valid directory fds and NUL-terminated names.
            unsafe { libc::renameat(self.raw(), f.as_ptr(), self.raw(), t.as_ptr()) }
        } else {
            noreplace(self.raw(), &f, &t)
        };
        check(rc).map(|_| ())
    }

    pub(super) fn unlink(&self, name: &str) -> io::Result<()> {
        let n = cstr(name)?;
        // SAFETY: valid directory fd and NUL-terminated name.
        check(unsafe { libc::unlinkat(self.raw(), n.as_ptr(), 0) }).map(|_| ())
    }

    /// Removes `name` only if it is a regular file with identity
    /// `expected`. `unlinkat` removes by name, so a non-cooperating writer
    /// could swap the entry between the check and the unlink; 8.4 puts such
    /// writers out of scope.
    pub(super) fn remove_owned(
        &self,
        name: &str,
        expected: &FileIdentity,
    ) -> io::Result<Ownership> {
        let file = match self.open_regular(name, false) {
            Ok(Some(f)) => f,
            Ok(None) => return Ok(Ownership::Absent),
            Err(e) if e.kind() == io::ErrorKind::InvalidData => return Ok(Ownership::NotOwned),
            Err(e) => return Err(e),
        };
        match self.identity(&file) {
            Ok(id) if id == *expected => {}
            _ => return Ok(Ownership::NotOwned),
        }
        drop(file);
        self.unlink(name)?;
        Ok(Ownership::Removed)
    }

    pub(super) fn flush(&self) -> io::Result<()> {
        // SAFETY: `fsync` on an open descriptor.
        check(unsafe { libc::fsync(self.raw()) })?;
        #[cfg(target_os = "macos")]
        // SAFETY: `F_FULLFSYNC` takes no argument.
        check(unsafe { libc::fcntl(self.raw(), libc::F_FULLFSYNC) })?;
        Ok(())
    }

    pub(super) fn identity(&self, file: &File) -> io::Result<FileIdentity> {
        let (dev, id) = identity_of(file.as_raw_fd())?;
        let (dir_dev, _) = identity_of(self.raw())?;
        if dev != dir_dev {
            return Err(io::Error::other("file is on another device"));
        }
        Ok(FileIdentity::Unix(id))
    }

    pub(super) fn self_identity(&self) -> io::Result<()> {
        identity_of(self.raw()).map(|_| ())
    }

    pub(super) fn volume(&self) -> io::Result<Volume> {
        volume_of(self.raw())
    }
}

pub(super) fn flush_file(file: &File) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: `F_FULLFSYNC` takes no argument.
        check(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) }).map(|_| ())
    }
    #[cfg(not(target_os = "macos"))]
    {
        file.sync_all()
    }
}

fn pack(ino: u64, sec: i64, nsec: u32) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[..8].copy_from_slice(&ino.to_be_bytes());
    out[8..16].copy_from_slice(&sec.to_be_bytes());
    out[16..].copy_from_slice(&nsec.to_be_bytes());
    out
}

/// (device, identity bytes). Fails if birth time is unavailable.
#[cfg(target_os = "linux")]
fn identity_of(fd: libc::c_int) -> io::Result<(u64, [u8; 20])> {
    let mut stx = core::mem::MaybeUninit::<libc::statx>::zeroed();
    // SAFETY: valid fd, empty NUL-terminated path with AT_EMPTY_PATH, and a
    // writable statx buffer.
    check(unsafe {
        libc::statx(
            fd,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_INO | libc::STATX_BTIME,
            stx.as_mut_ptr(),
        )
    })?;
    // SAFETY: statx succeeded and the buffer was zeroed beforehand.
    let stx = unsafe { stx.assume_init() };
    let need = libc::STATX_INO | libc::STATX_BTIME;
    if stx.stx_mask & need != need {
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    }
    let dev = (u64::from(stx.stx_dev_major) << 32) | u64::from(stx.stx_dev_minor);
    Ok((
        dev,
        pack(stx.stx_ino, stx.stx_btime.tv_sec, stx.stx_btime.tv_nsec),
    ))
}

#[cfg(target_os = "macos")]
fn identity_of(fd: libc::c_int) -> io::Result<(u64, [u8; 20])> {
    let mut st = core::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid fd and writable stat buffer.
    check(unsafe { libc::fstat(fd, st.as_mut_ptr()) })?;
    // SAFETY: fstat succeeded.
    let st = unsafe { st.assume_init() };
    if st.st_birthtime == 0 && st.st_birthtime_nsec == 0 {
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    }
    let nsec = u32::try_from(st.st_birthtime_nsec).map_err(|_| io::Error::other("nsec"))?;
    Ok((st.st_dev as u64, pack(st.st_ino, st.st_birthtime, nsec)))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn identity_of(_: libc::c_int) -> io::Result<(u64, [u8; 20])> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

#[cfg(target_os = "linux")]
fn volume_of(fd: libc::c_int) -> io::Result<Volume> {
    let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))?;
    let mnt_id =
        super::parse_fdinfo_mnt_id(&fdinfo).ok_or_else(|| io::Error::other("mount ID unknown"))?;
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")?;
    let fs_type = super::parse_mountinfo_type(&mountinfo, mnt_id)
        .ok_or_else(|| io::Error::other("mount record unknown"))?;
    Ok(Volume {
        fs_type,
        key: mnt_id,
    })
}

#[cfg(target_os = "macos")]
fn volume_of(fd: libc::c_int) -> io::Result<Volume> {
    let mut sf = core::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: valid fd and writable statfs buffer.
    check(unsafe { libc::fstatfs(fd, sf.as_mut_ptr()) })?;
    // SAFETY: fstatfs succeeded.
    let sf = unsafe { sf.assume_init() };
    let name: Vec<u8> = sf
        .f_fstypename
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    let fs_type = String::from_utf8(name).map_err(|_| io::Error::other("type"))?;
    // SAFETY: `fsid_t` is two 32-bit integers with no padding.
    let fsid: [i32; 2] = unsafe { core::mem::transmute(sf.f_fsid) };
    let key = (u64::from(fsid[0] as u32) << 32) | u64::from(fsid[1] as u32);
    Ok(Volume { fs_type, key })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn volume_of(_: libc::c_int) -> io::Result<Volume> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

#[cfg(target_os = "linux")]
fn noreplace(dirfd: libc::c_int, from: &CString, to: &CString) -> libc::c_int {
    // SAFETY: valid directory fds and NUL-terminated names.
    unsafe {
        libc::renameat2(
            dirfd,
            from.as_ptr(),
            dirfd,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    }
}

#[cfg(target_os = "macos")]
fn noreplace(dirfd: libc::c_int, from: &CString, to: &CString) -> libc::c_int {
    // SAFETY: valid directory fds and NUL-terminated names.
    unsafe { libc::renameatx_np(dirfd, from.as_ptr(), dirfd, to.as_ptr(), libc::RENAME_EXCL) }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn noreplace(_: libc::c_int, _: &CString, _: &CString) -> libc::c_int {
    // SAFETY: setting errno is always safe; refuse rather than weaken.
    -1
}
