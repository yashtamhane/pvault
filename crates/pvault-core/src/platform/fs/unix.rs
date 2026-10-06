//! Unix file-system primitives: every child operation is relative to the held
//! directory descriptor (`openat`, `mkdirat`, `renameat`, `unlinkat`) and
//! never follows a symlink.

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;

use super::{FileIdentity, IdKind, Ownership, RecordIdentity, SourceError, SourceMeta, Volume};

#[derive(Debug)]
pub(super) struct Dir {
    fd: OwnedFd,
}

fn cstr(s: &OsStr) -> io::Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(s.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in name"))
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

    pub(super) fn open_dir(&self, name: &OsStr) -> io::Result<Self> {
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

    pub(super) fn create_dir(&self, name: &OsStr) -> io::Result<()> {
        let n = cstr(name)?;
        // SAFETY: valid directory fd and NUL-terminated name.
        check(unsafe { libc::mkdirat(self.raw(), n.as_ptr(), 0o700) }).map(|_| ())
    }

    pub(super) fn create_new(&self, name: &OsStr) -> io::Result<File> {
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

    pub(super) fn open_regular(&self, name: &OsStr, write: bool) -> io::Result<Option<File>> {
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

    pub(super) fn exists(&self, name: &OsStr) -> io::Result<bool> {
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

    pub(super) fn rename(&self, from: &OsStr, to: &OsStr, replace: bool) -> io::Result<()> {
        let (f, t) = (cstr(from)?, cstr(to)?);
        let rc = if replace {
            // SAFETY: valid directory fds and NUL-terminated names.
            unsafe { libc::renameat(self.raw(), f.as_ptr(), self.raw(), t.as_ptr()) }
        } else {
            noreplace(self.raw(), &f, &t)
        };
        check(rc).map(|_| ()).map_err(|e| {
            // The file system refused the no-replace flag itself (macOS
            // exFAT: ENOTSUP; Linux: EINVAL for an unsupported flag; ENOSYS
            // without the call). There is no check-then-rename fallback
            // (7.6a), so this is reported as unsupported.
            // ENOTSUP and EOPNOTSUPP are equal on some platforms.
            let refused = !replace
                && e.raw_os_error().is_some_and(|c| {
                    [libc::ENOTSUP, libc::EOPNOTSUPP, libc::EINVAL, libc::ENOSYS].contains(&c)
                });
            if refused {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "this file system cannot rename without replacing",
                )
            } else {
                e
            }
        })
    }

    pub(super) fn unlink(&self, name: &OsStr) -> io::Result<()> {
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
        name: &OsStr,
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

    /// The names in this directory, without `.` and `..`.
    pub(super) fn list(&self) -> io::Result<Vec<OsString>> {
        // SAFETY: duplicating an open descriptor has no other preconditions.
        let dup = check(unsafe { libc::fcntl(self.raw(), libc::F_DUPFD_CLOEXEC, 0) })?;
        // SAFETY: `dup` is a new directory descriptor; `fdopendir` takes
        // ownership of it on success.
        let dirp = unsafe { libc::fdopendir(dup) };
        if dirp.is_null() {
            let e = io::Error::last_os_error();
            // SAFETY: `dup` is still owned by us after a failed `fdopendir`.
            unsafe { libc::close(dup) };
            return Err(e);
        }
        // SAFETY: `dirp` is a valid stream; rewinding has no preconditions.
        unsafe { libc::rewinddir(dirp) };
        let mut names = Vec::new();
        loop {
            // SAFETY: `dirp` is a valid directory stream.
            let entry = unsafe { libc::readdir(dirp) };
            if entry.is_null() {
                break;
            }
            // SAFETY: `readdir` returned a valid entry whose `d_name` is
            // NUL-terminated and valid until the next call on `dirp`.
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
            let bytes = name.to_bytes();
            if bytes != b"." && bytes != b".." {
                names.push(OsString::from_vec(bytes.to_vec()));
            }
        }
        // SAFETY: `dirp` came from `fdopendir` and is closed exactly once.
        unsafe { libc::closedir(dirp) };
        Ok(names)
    }

    /// Whether `other` is this directory or lies below it: walks from
    /// `other` through `..` handles, comparing device and inode.
    pub(super) fn contains(&self, other: &Dir) -> io::Result<bool> {
        let target = dev_ino(self.raw())?;
        // SAFETY: duplicating an open descriptor.
        let fd = check(unsafe { libc::fcntl(other.raw(), libc::F_DUPFD_CLOEXEC, 0) })?;
        // SAFETY: `fd` is new and owned by nothing else.
        let mut current = unsafe { OwnedFd::from_raw_fd(fd) };
        for _ in 0..4096 {
            let here = dev_ino(current.as_raw_fd())?;
            if here == target {
                return Ok(true);
            }
            // SAFETY: valid directory fd and a NUL-terminated name.
            let parent = check(unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    c"..".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            })?;
            // SAFETY: `parent` was just opened and is owned by nothing else.
            let parent = unsafe { OwnedFd::from_raw_fd(parent) };
            if dev_ino(parent.as_raw_fd())? == here {
                return Ok(false); // reached the root
            }
            current = parent;
        }
        Err(io::Error::other("directory nesting too deep"))
    }

    /// `Some(true)` if `name` (not followed) is the file open as `file`;
    /// `Some(false)` if it is something else; `None` if absent.
    pub(super) fn held_at(&self, name: &OsStr, file: &File) -> io::Result<Option<bool>> {
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
        if rc != 0 {
            let e = io::Error::last_os_error();
            return if e.raw_os_error() == Some(libc::ENOENT) {
                Ok(None)
            } else {
                Err(e)
            };
        }
        // SAFETY: `fstatat` succeeded.
        let st = unsafe { st.assume_init() };
        let held = dev_ino(file.as_raw_fd())?;
        Ok(Some(stat_dev_ino(&st) == held))
    }

    /// Deletes `name` only if it is the file open as `file`. An open file
    /// cannot be freed, so its inode number cannot be reused meanwhile.
    pub(super) fn delete_held(&self, name: &OsStr, file: &File) -> io::Result<bool> {
        if self.held_at(name, file)? != Some(true) {
            return Ok(false);
        }
        self.unlink(name)?;
        Ok(true)
    }

    /// Owned by the effective user, and no group or other permission.
    pub(super) fn is_private(&self) -> io::Result<bool> {
        let mut st = core::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: valid fd and writable stat buffer.
        check(unsafe { libc::fstat(self.raw(), st.as_mut_ptr()) })?;
        // SAFETY: `fstat` succeeded.
        let st = unsafe { st.assume_init() };
        // SAFETY: `geteuid` has no preconditions.
        let uid = unsafe { libc::geteuid() };
        Ok((st.st_mode & libc::S_IFMT) == libc::S_IFDIR
            && st.st_uid == uid
            && st.st_mode & 0o077 == 0)
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

fn dev_ino(fd: libc::c_int) -> io::Result<(u64, u64)> {
    let mut st = core::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid fd and writable stat buffer.
    check(unsafe { libc::fstat(fd, st.as_mut_ptr()) })?;
    // SAFETY: `fstat` succeeded.
    let st = unsafe { st.assume_init() };
    Ok(stat_dev_ino(&st))
}

/// `(st_dev, st_ino)` as u64; the field types differ by platform.
#[allow(clippy::unnecessary_cast)]
fn stat_dev_ino(st: &libc::stat) -> (u64, u64) {
    (st.st_dev as u64, st.st_ino as u64)
}

/// Birth time `(sec, nsec)` if the file system provides one.
#[cfg(target_os = "linux")]
fn birth_time(fd: libc::c_int) -> io::Result<Option<(i64, u32)>> {
    let mut stx = core::mem::MaybeUninit::<libc::statx>::zeroed();
    // SAFETY: valid fd, empty path with AT_EMPTY_PATH, writable buffer.
    check(unsafe {
        libc::statx(
            fd,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_BTIME,
            stx.as_mut_ptr(),
        )
    })?;
    // SAFETY: statx succeeded and the buffer was zeroed beforehand.
    let stx = unsafe { stx.assume_init() };
    if stx.stx_mask & libc::STATX_BTIME == 0 {
        return Ok(None);
    }
    Ok(Some((stx.stx_btime.tv_sec, stx.stx_btime.tv_nsec)))
}

#[cfg(target_os = "macos")]
fn birth_time(fd: libc::c_int) -> io::Result<Option<(i64, u32)>> {
    let mut st = core::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid fd and writable stat buffer.
    check(unsafe { libc::fstat(fd, st.as_mut_ptr()) })?;
    // SAFETY: fstat succeeded.
    let st = unsafe { st.assume_init() };
    if st.st_birthtime == 0 && st.st_birthtime_nsec == 0 {
        return Ok(None);
    }
    Ok(Some((st.st_birthtime, st.st_birthtime_nsec as u32)))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn birth_time(_: libc::c_int) -> io::Result<Option<(i64, u32)>> {
    Ok(None)
}

pub(super) fn record_identity(file: &File) -> io::Result<RecordIdentity> {
    let (dev, ino) = dev_ino(file.as_raw_fd())?;
    let btime = birth_time(file.as_raw_fd())?.map(|(sec, nsec)| {
        let mut b = sec.to_be_bytes().to_vec();
        b.extend_from_slice(&nsec.to_be_bytes());
        b
    });
    Ok(RecordIdentity {
        kind: IdKind::Unix,
        dev,
        ino: ino.to_be_bytes().to_vec(),
        btime,
    })
}

pub(super) fn open_source(path: &Path) -> Result<File, SourceError> {
    use std::os::unix::ffi::OsStrExt;
    let p = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| SourceError::Io(io::Error::new(io::ErrorKind::InvalidInput, "NUL in path")))?;
    // SAFETY: `p` is a valid NUL-terminated path. O_NONBLOCK keeps a FIFO
    // from blocking the open; the type is checked on the handle below.
    let fd = unsafe {
        libc::open(
            p.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let e = io::Error::last_os_error();
        return Err(match e.raw_os_error() {
            Some(libc::ELOOP) => SourceError::Link,
            _ => SourceError::Io(e),
        });
    }
    // SAFETY: `fd` was just opened and is owned by nothing else.
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata().map_err(SourceError::Io)?;
    if !meta.file_type().is_file() {
        return Err(SourceError::NotRegular);
    }
    // SAFETY: plain flag changes on an open descriptor.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
    }
    Ok(file)
}

pub(super) fn source_meta(file: &File) -> io::Result<SourceMeta> {
    let mut st = core::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid fd and writable stat buffer.
    check(unsafe { libc::fstat(file.as_raw_fd(), st.as_mut_ptr()) })?;
    // SAFETY: fstat succeeded.
    let st = unsafe { st.assume_init() };
    let (mtime, ctime) = (
        (st.st_mtime, st.st_mtime_nsec as u32),
        (st.st_ctime, st.st_ctime_nsec as u32),
    );
    let (dev, ino) = stat_dev_ino(&st);
    Ok(SourceMeta {
        size: u64::try_from(st.st_size).map_err(|_| io::Error::other("negative size"))?,
        mtime,
        ctime,
        dev,
        ino: ino.to_be_bytes().to_vec(),
    })
}
