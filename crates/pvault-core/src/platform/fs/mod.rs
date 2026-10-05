//! File-system primitives (spec 4.3, 8.1, 8.5; 7.6a; D5, D6).
//!
//! - [`Dir`]: an open directory handle. Every child operation is relative to
//!   it (Unix `openat`, `mkdirat`, `renameat`, `unlinkat`; Windows
//!   `NtCreateFile` with `RootDirectory`) and never follows a symlink or
//!   reparse point.
//! - **File identity** ([`FileIdentity`], spec 8.1): Unix
//!   `st_ino || birth time`, verified on the same device as the held
//!   directory; Windows `VolumeSerialNumber || FileId || CreationTime`.
//!   Support is decided from what the system returns, never from a version
//!   table.
//! - **Durability** (8.5): Linux `fsync`; macOS `F_FULLFSYNC` for files and
//!   both `fsync` and `F_FULLFSYNC` for directories; Windows write-through
//!   data handles, `FlushFileBuffers`, and handle-relative
//!   `NtSetInformationFile(FileRenameInformation)` renames. Microsoft does
//!   documents NTFS metadata flush for rename requests made write-through,
//!   but not ReFS behavior, old-or-new crash atomicity, power-loss safety or
//!   equivalence to `MoveFileExW(MOVEFILE_WRITE_THROUGH)`; amended W1 states
//!   the remaining assumption explicitly.
//!   Windows has no directory flush without administrator rights; the
//!   ordering assumptions WO-1 to WO-3 and W1 (8.5, N1) cover it, and they
//!   are documented as unverified.
//! - **Identification** (8.5): Linux mount type from `/proc/self/mountinfo`
//!   through the handle's mount ID; macOS `f_fstypename`; Windows Q1–Q4
//!   (local volume, NTFS or ReFS). Unknown or ambiguous refuses mutation.
//!
//! Each platform's FFI is isolated in its own module: `fs/unix.rs` uses
//! the `*at` calls; `fs/windows.rs` uses `NtCreateFile` relative to the
//! held directory handle and `NtSetInformationFile` on verified handles (no
//! path-based child operation; M3-F2 resolved). Windows runtime behavior is
//! validated only by native CI.

use std::fs::File;
use std::io;
use std::path::Path;

pub use crate::journal::FileIdentity;

/// Checks that `name` is one plain path component.
fn component(name: &str) -> io::Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\\') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a single component",
        ));
    }
    Ok(())
}

/// An open directory.
#[derive(Debug)]
pub struct Dir {
    inner: imp::Dir,
}

/// Identity of a mount or volume, for same-mount checks (8.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volume {
    /// The file-system type as the system reports it.
    pub fs_type: String,
    /// Linux mount ID, macOS `f_fsid`, or Windows volume serial number.
    pub key: u64,
}

impl Dir {
    /// Opens a directory without following a symlink in its last component.
    pub fn open(path: &Path) -> io::Result<Self> {
        Ok(Self {
            inner: imp::Dir::open(path)?,
        })
    }

    /// Opens child directory `name` (no-follow).
    pub fn open_dir(&self, name: &str) -> io::Result<Self> {
        component(name)?;
        Ok(Self {
            inner: self.inner.open_dir(name)?,
        })
    }

    /// Creates child directory `name`, owner-only.
    pub fn create_dir(&self, name: &str) -> io::Result<()> {
        component(name)?;
        self.inner.create_dir(name)
    }

    /// Creates `name` exclusively (no-follow, owner-only, write-through on
    /// Windows). Fails if anything exists at that name.
    pub fn create_new(&self, name: &str) -> io::Result<File> {
        component(name)?;
        self.inner.create_new(name)
    }

    /// Opens an existing **regular file** without following symlinks.
    /// Returns `Ok(None)` if nothing exists at `name`; any other kind of
    /// entry is an error.
    pub fn open_regular(&self, name: &str, write: bool) -> io::Result<Option<File>> {
        component(name)?;
        self.inner.open_regular(name, write)
    }

    /// Whether any entry exists at `name` (without following it).
    pub fn exists(&self, name: &str) -> io::Result<bool> {
        component(name)?;
        self.inner.exists(name)
    }

    /// Atomically replaces `to` with `from`.
    pub fn rename_replace(&self, from: &str, to: &str) -> io::Result<()> {
        component(from)?;
        component(to)?;
        self.inner.rename(from, to, true)
    }

    /// Renames `from` to `to`, failing if `to` exists. There is no
    /// check-then-rename fallback (7.6a).
    pub fn rename_noreplace(&self, from: &str, to: &str) -> io::Result<()> {
        component(from)?;
        component(to)?;
        self.inner.rename(from, to, false)
    }

    /// Removes the directory entry `name`.
    pub fn unlink(&self, name: &str) -> io::Result<()> {
        component(name)?;
        self.inner.unlink(name)
    }

    /// Makes directory-entry changes durable (8.5). A no-op on Windows,
    /// where WO-1 to WO-3 are documented assumptions.
    pub fn flush(&self) -> io::Result<()> {
        self.inner.flush()
    }

    /// The identity of `file`, which must live on this directory's device.
    pub fn identity(&self, file: &File) -> io::Result<FileIdentity> {
        self.inner.identity(file)
    }

    /// Identifies the volume of this directory (8.5).
    pub fn volume(&self) -> io::Result<Volume> {
        self.inner.volume()
    }
}

/// Flushes a file's data durably (Linux `fsync`, macOS `F_FULLFSYNC`,
/// Windows `FlushFileBuffers`).
pub fn flush_file(file: &File) -> io::Result<()> {
    imp::flush_file(file)
}

/// The 8.5 allowlist for this platform. Exact strings only.
pub fn is_allowed(fs_type: &str) -> bool {
    if cfg!(target_os = "linux") {
        matches!(fs_type, "ext4" | "xfs" | "btrfs")
    } else if cfg!(target_os = "macos") {
        matches!(fs_type, "apfs" | "hfs")
    } else if cfg!(windows) {
        matches!(fs_type, "NTFS" | "ReFS")
    } else {
        false
    }
}

/// The 8.5 support check and durability preflight, run on a held directory
/// before the first side effect of a mutating operation:
/// - the volume is identified and on the allowlist (on Windows: Q1–Q4);
/// - the directory flush succeeds;
/// - the file-identity primitives work on the directory itself (on Unix,
///   including birth time).
///
/// Passing it never weakens the post-replacement failure boundary.
pub fn preflight(dir: &Dir) -> Result<Volume, crate::Error> {
    let refuse = |what: &str| crate::Error::UnsupportedFileSystem(what.to_owned());
    let volume = dir.volume().map_err(|_| refuse("unknown"))?;
    if !is_allowed(&volume.fs_type) {
        return Err(refuse(&volume.fs_type));
    }
    dir.flush()
        .map_err(|_| refuse("no durable directory flush"))?;
    dir.inner
        .self_identity()
        .map_err(|_| refuse("no file identity with birth time"))?;
    Ok(volume)
}

/// Requires `child` to be on the same mount or volume as `parent` (8.5:
/// every directory pvault writes in).
pub fn same_volume(parent: &Volume, child: &Dir) -> Result<(), crate::Error> {
    let v = child
        .volume()
        .map_err(|_| crate::Error::UnsupportedFileSystem("unknown".to_owned()))?;
    if v == *parent {
        Ok(())
    } else {
        Err(crate::Error::UnsupportedFileSystem(
            "a different mount inside the vault".to_owned(),
        ))
    }
}

/// What [`remove_if_owned`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ownership {
    /// The file matched the recorded identity and was removed.
    Removed,
    /// Nothing exists at the name.
    Absent,
    /// Something exists, but it is not the recorded file (different
    /// identity, a different volume, not a regular file, or unverifiable).
    /// Nothing was touched.
    NotOwned,
}

/// Opens `name` and returns it only if it is a regular file whose identity
/// equals `expected` (spec 8.1). `Ok(None)` if absent.
pub fn open_owned(
    dir: &Dir,
    name: &str,
    expected: &FileIdentity,
    write: bool,
) -> io::Result<Result<Option<File>, Ownership>> {
    let file = match dir.open_regular(name, write) {
        Ok(Some(f)) => f,
        Ok(None) => return Ok(Ok(None)),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => return Ok(Err(Ownership::NotOwned)),
        Err(e) => return Err(e),
    };
    match dir.identity(&file) {
        Ok(id) if id == *expected => Ok(Ok(Some(file))),
        _ => Ok(Err(Ownership::NotOwned)),
    }
}

/// Removes `name` only if it is the recorded file (spec 8.1). On Windows the
/// delete acts on the very handle whose identity was verified. The caller
/// flushes the directory afterwards.
pub fn remove_if_owned(dir: &Dir, name: &str, expected: &FileIdentity) -> io::Result<Ownership> {
    component(name)?;
    dir.inner.remove_owned(name, expected)
}

/// The mount ID in a `/proc/self/fdinfo/<fd>` text.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn parse_fdinfo_mnt_id(text: &str) -> Option<u64> {
    let mut found = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("mnt_id:") {
            if found.is_some() {
                return None;
            }
            found = Some(v.trim().parse().ok()?);
        }
    }
    found
}

/// The file-system type of mount `mnt_id` in `/proc/self/mountinfo` (D5):
/// - the record is found by field 1;
/// - it needs six fixed fields, then the first token exactly `-`, then at
///   least three fields;
/// - the type is the token right after `-`.
///
/// No record, several records or a malformed record gives `None`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn parse_mountinfo_type(text: &str, mnt_id: u64) -> Option<String> {
    let mut result = None;
    for line in text.lines() {
        let tokens: Vec<&str> = line.split(' ').collect();
        let Some(id) = tokens.first().and_then(|t| t.parse::<u64>().ok()) else {
            if line.trim().is_empty() {
                continue;
            }
            return None; // a malformed record makes the whole answer unknown
        };
        if id != mnt_id {
            continue;
        }
        if tokens.len() < 6 + 1 + 3 {
            return None;
        }
        let sep = tokens[6..].iter().position(|t| *t == "-")? + 6;
        if tokens.len() < sep + 1 + 3 {
            return None;
        }
        if result.is_some() {
            return None; // ambiguous
        }
        result = Some(tokens[sep + 1].to_owned());
    }
    result
}

#[cfg(unix)]
#[allow(unsafe_code)]
#[path = "unix.rs"]
mod imp;

#[cfg(windows)]
#[allow(unsafe_code)]
#[path = "windows.rs"]
mod imp;

/// Raw Windows Q1–Q4 results.
#[cfg(windows)]
pub use imp::Probe as WindowsProbe;

/// Windows Q1–Q4 raw results and the decision for `dir`, for the native
/// locality probe (spec 8.5 evidence). The decision is the same one
/// [`preflight`] uses.
#[cfg(windows)]
pub fn windows_locality_probe(dir: &Dir) -> (WindowsProbe, Result<Volume, String>) {
    let p = imp::probe_dir(&dir.inner);
    let verdict = imp::decide(&p).map_err(|e| e.to_string());
    (p, verdict)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn mountinfo_uses_the_separator_not_a_field_number() {
        let text = "\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
23 22 8:2 / /data rw - ext2 /dev/sda2 rw
24 22 0:5 / /opt rw shared:2 master:3 - xfs /dev/sdb1 rw,x - y
25 22 0:6 / /net rw - nfs4 server:/x rw
";
        assert_eq!(parse_mountinfo_type(text, 22).as_deref(), Some("ext4"));
        assert_eq!(parse_mountinfo_type(text, 23).as_deref(), Some("ext2"));
        assert_eq!(parse_mountinfo_type(text, 24).as_deref(), Some("xfs"));
        assert_eq!(parse_mountinfo_type(text, 25).as_deref(), Some("nfs4"));
        assert_eq!(parse_mountinfo_type(text, 99), None);
        // Duplicate IDs, no separator, too few fields, overflowing IDs.
        assert_eq!(
            parse_mountinfo_type(
                "22 1 8:1 / / rw - ext4 a b\n22 1 8:1 / / rw - xfs a b\n",
                22
            ),
            None
        );
        assert_eq!(parse_mountinfo_type("22 1 8:1 / / rw ext4 a b\n", 22), None);
        assert_eq!(parse_mountinfo_type("22 1 8:1 / / rw - ext4\n", 22), None);
        assert_eq!(
            parse_mountinfo_type("99999999999999999999 1 8:1 / / rw - ext4 a b\n", 22),
            None
        );
        // ext2 and ext3 are never accepted, even though statfs magic says 0xEF53.
        assert!(!is_allowed("ext2") && !is_allowed("ext3"));
    }

    #[test]
    fn fdinfo_mount_id() {
        assert_eq!(
            parse_fdinfo_mnt_id("pos:\t0\nflags:\t0100000\nmnt_id:\t31\n"),
            Some(31)
        );
        assert_eq!(parse_fdinfo_mnt_id("pos:\t0\n"), None);
        assert_eq!(parse_fdinfo_mnt_id("mnt_id:\t1\nmnt_id:\t2\n"), None);
    }

    /// F74 (detection part): a mocked unsupported type refuses.
    #[test]
    fn allowlists_are_exact() {
        for t in [
            "exfat", "msdos", "vfat", "fuse", "cifs", "smbfs", "nfs", "overlay", "Ext4", "APFS",
        ] {
            assert!(!is_allowed(t), "{t}");
        }
        if cfg!(target_os = "macos") {
            assert!(is_allowed("apfs") && is_allowed("hfs"));
        }
    }

    #[test]
    fn identity_rename_and_owned_removal() {
        let tmp = tempdir();
        let dir = Dir::open(&tmp).unwrap();
        let vol = preflight(&dir).unwrap();
        assert!(is_allowed(&vol.fs_type));
        let mut f = dir.create_new("a.tmp").unwrap();
        let id = dir.identity(&f).unwrap();
        f.write_all(b"x").unwrap();
        flush_file(&f).unwrap();
        drop(f);
        assert!(dir.create_new("a.tmp").is_err(), "exclusive create");
        dir.rename_noreplace("a.tmp", "a").unwrap();
        dir.flush().unwrap();
        // The identity survives the rename.
        let f = dir.open_regular("a", false).unwrap().unwrap();
        assert_eq!(dir.identity(&f).unwrap(), id);
        drop(f);
        // A different file at a recorded name is never removed.
        dir.create_new("b").unwrap();
        assert_eq!(
            remove_if_owned(&dir, "b", &id).unwrap(),
            Ownership::NotOwned
        );
        assert!(dir.exists("b").unwrap());
        assert_eq!(remove_if_owned(&dir, "a", &id).unwrap(), Ownership::Removed);
        assert_eq!(remove_if_owned(&dir, "a", &id).unwrap(), Ownership::Absent);
        // No-replace refuses an existing target.
        dir.create_new("c").unwrap();
        assert!(dir.rename_noreplace("b", "c").is_err());
        dir.rename_replace("b", "c").unwrap();
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    /// An inode reused for a new file at the same name has another birth
    /// time, so it is not owned (best effort: a coarse clock could repeat the
    /// time, which the spec documents).
    #[cfg(unix)]
    #[test]
    fn reused_names_are_not_owned() {
        let tmp = tempdir();
        let dir = Dir::open(&tmp).unwrap();
        let f = dir.create_new("x").unwrap();
        let id = dir.identity(&f).unwrap();
        drop(f);
        dir.unlink("x").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let f = dir.create_new("x").unwrap();
        assert_ne!(dir.identity(&f).unwrap(), id);
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_and_special_files_are_refused() {
        let tmp = tempdir();
        let dir = Dir::open(&tmp).unwrap();
        std::fs::write(tmp.join("target"), b"t").unwrap();
        std::os::unix::fs::symlink(tmp.join("target"), tmp.join("link")).unwrap();
        assert!(dir.open_regular("link", false).is_err());
        assert!(dir.create_new("link").is_err());
        std::fs::create_dir(tmp.join("sub")).unwrap();
        assert!(dir.open_regular("sub", false).is_err());
        std::os::unix::fs::symlink(tmp.join("sub"), tmp.join("dirlink")).unwrap();
        assert!(Dir::open(&tmp.join("dirlink")).is_err());
        assert!(dir.open_dir("dirlink").is_err());
        let fifo = std::ffi::CString::new(tmp.join("fifo").to_str().unwrap()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) };
        assert_eq!(rc, 0);
        assert!(dir.open_regular("fifo", false).is_err());
        let id = FileIdentity::Unix([0; 20]);
        assert_eq!(
            remove_if_owned(&dir, "link", &id).unwrap(),
            Ownership::NotOwned
        );
        assert_eq!(
            remove_if_owned(&dir, "fifo", &id).unwrap(),
            Ownership::NotOwned
        );
        assert!(dir.exists("fifo").unwrap() && dir.exists("link").unwrap());
        assert!(dir.create_dir("..").is_err() && dir.create_new("a/b").is_err());
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    /// The Q1–Q4 decision on synthetic answers: only all-accepting answers
    /// pass; every unexpected answer refuses (spec 8.5).
    #[cfg(windows)]
    #[test]
    fn windows_decision_fails_closed() {
        use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER};
        use windows_sys::Win32::System::WindowsProgramming::{
            DRIVE_CDROM, DRIVE_FIXED, DRIVE_RAMDISK, DRIVE_REMOTE, DRIVE_REMOVABLE,
        };
        let good = WindowsProbe {
            q1: Err(ERROR_INVALID_PARAMETER),
            q2: Ok("\\\\?\\Volume{0a1b2c3d-0000-0000-0000-100000000000}\\Users\\x".into()),
            q3: Some(DRIVE_FIXED),
            q4: Ok(("NTFS".into(), 0x1234)),
        };
        assert_eq!(imp::decide(&good).unwrap().fs_type, "NTFS");
        let removable = WindowsProbe {
            q3: Some(DRIVE_REMOVABLE),
            ..good.clone()
        };
        assert!(imp::decide(&removable).is_ok());
        let bad = [
            WindowsProbe {
                q1: Ok(()),
                ..good.clone()
            },
            WindowsProbe {
                q1: Err(ERROR_ACCESS_DENIED),
                ..good.clone()
            },
            WindowsProbe {
                q2: Ok("\\\\?\\UNC\\server\\share\\x".into()),
                ..good.clone()
            },
            WindowsProbe {
                q2: Ok("\\\\?\\Volume{abc".into()),
                ..good.clone()
            },
            WindowsProbe {
                q2: Err(1),
                q3: None,
                ..good.clone()
            },
            WindowsProbe {
                q3: Some(DRIVE_REMOTE),
                ..good.clone()
            },
            WindowsProbe {
                q3: Some(DRIVE_CDROM),
                ..good.clone()
            },
            WindowsProbe {
                q3: Some(DRIVE_RAMDISK),
                ..good.clone()
            },
            WindowsProbe {
                q3: None,
                ..good.clone()
            },
            WindowsProbe {
                q4: Err(5),
                ..good.clone()
            },
        ];
        for p in &bad {
            assert!(imp::decide(p).is_err(), "{p:?}");
        }
        // The decision accepts a type only through the allowlist afterwards.
        let fat = WindowsProbe {
            q4: Ok(("FAT32".into(), 1)),
            ..good.clone()
        };
        assert!(!is_allowed(&imp::decide(&fat).unwrap().fs_type));
    }

    /// Native locality probe, part 1 (runs in every Windows CI job): the
    /// runner's local NTFS temp directory is accepted, and a loopback UNC
    /// path to the same directory is refused. Raw answers are printed as
    /// evidence for spec 8.5.
    #[cfg(windows)]
    #[test]
    fn windows_native_locality_probe() {
        let tmp = tempdir();
        let dir = Dir::open(&tmp).unwrap();
        let (probe, verdict) = windows_locality_probe(&dir);
        println!("local temp {}: {probe:?} -> {verdict:?}", tmp.display());
        let volume = verdict.expect("local NTFS must be accepted");
        assert!(is_allowed(&volume.fs_type), "{volume:?}");
        preflight(&dir).unwrap();

        // \\localhost\C$\... reaches the same files through SMB.
        let abs = std::path::absolute(&tmp).unwrap();
        let s = abs.to_string_lossy().into_owned();
        let (drive, rest) = s.split_at(2);
        let unc = format!("\\\\localhost\\{}${}", &drive[..1], rest);
        match Dir::open(std::path::Path::new(&unc)) {
            Ok(remote) => {
                let (probe, verdict) = windows_locality_probe(&remote);
                println!("loopback UNC {unc}: {probe:?} -> {verdict:?}");
                assert!(verdict.is_err(), "a UNC path must refuse mutation");
                assert!(preflight(&remote).is_err());
            }
            Err(e) => println!("loopback UNC {unc}: unavailable ({e})"),
        }
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    /// Native locality probe, part 2 (CI only, `--ignored`): a `subst`
    /// drive and an SMB-mapped drive letter. These change the runner's
    /// drive mappings, so they never run in an ordinary `cargo test`; the
    /// mappings are removed afterwards.
    #[cfg(windows)]
    #[test]
    #[ignore = "changes drive mappings; run explicitly on a CI runner"]
    fn windows_native_locality_probe_mappings() {
        use std::process::Command;
        let tmp = tempdir();
        let abs = std::path::absolute(&tmp).unwrap();
        let local = windows_locality_probe(&Dir::open(&tmp).unwrap()).1;
        let free = ('P'..='Y')
            .rev()
            .filter(|c| !std::path::Path::new(&format!("{c}:\\")).exists())
            .take(2)
            .collect::<Vec<_>>();
        assert_eq!(free.len(), 2, "no free drive letters");
        let (subst, mapped) = (format!("{}:", free[0]), format!("{}:", free[1]));

        // subst: a local alias; the decision must match the real path.
        assert!(
            Command::new("subst")
                .args([subst.as_str(), &abs.to_string_lossy()])
                .status()
                .unwrap()
                .success()
        );
        let result = Dir::open(std::path::Path::new(&format!("{subst}\\")))
            .map(|d| windows_locality_probe(&d));
        let _ = Command::new("subst").args([&subst, "/D"]).status();
        let (probe, verdict) = result.unwrap();
        println!("subst {subst}: {probe:?} -> {verdict:?}");
        assert_eq!(
            verdict.is_ok(),
            local.is_ok(),
            "subst must match the underlying volume"
        );

        // A mapped SMB drive (loopback share): must refuse.
        let s = abs.to_string_lossy().into_owned();
        let share = format!("\\\\localhost\\{}$", &s[..1]);
        let ok = Command::new("net")
            .args(["use", &mapped, &share, "/persistent:no"])
            .status()
            .is_ok_and(|s| s.success());
        if ok {
            let path = format!("{mapped}{}", &s[2..]);
            let result = Dir::open(std::path::Path::new(&path)).map(|d| windows_locality_probe(&d));
            let _ = Command::new("net")
                .args(["use", &mapped, "/delete", "/y"])
                .status();
            match result {
                Ok((probe, verdict)) => {
                    println!("mapped SMB {mapped}: {probe:?} -> {verdict:?}");
                    assert!(verdict.is_err(), "a mapped SMB drive must refuse mutation");
                }
                Err(e) => println!("mapped SMB {mapped}: open failed ({e})"),
            }
        } else {
            println!("mapped SMB {mapped}: net use unavailable");
        }
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    /// Makes `link` a symlink (Windows: a file symlink, which is a reparse
    /// point) to the file `target`.
    fn file_link(target: &std::path::Path, link: &std::path::Path) {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(target, link)
            .expect("creating a file symlink needs the symlink privilege (CI runners have it)");
    }

    /// Makes `link` a link to the directory `target`: a symlink on Unix; on
    /// Windows a directory symlink and, at `link` + "-junction", a junction.
    fn dir_links(target: &std::path::Path, link: &std::path::Path) -> Vec<std::path::PathBuf> {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link).unwrap();
            vec![link.to_path_buf()]
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_dir(target, link).expect(
                "creating a directory symlink needs the symlink privilege (CI runners have it)",
            );
            let junction = link.with_file_name(format!(
                "{}-junction",
                link.file_name().unwrap().to_string_lossy()
            ));
            let ok = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&junction)
                .arg(target)
                .stdout(std::process::Stdio::null())
                .status()
                .unwrap()
                .success();
            assert!(ok, "mklink /J failed");
            vec![link.to_path_buf(), junction]
        }
    }

    /// Every child operation is relative to the held handle: after the
    /// vault directory's path is renamed and replaced (by a new directory,
    /// or by a link to another directory) between inspection and creation,
    /// operations still act on the original directory, and nothing appears
    /// at the replacement.
    #[test]
    fn held_directory_survives_replacement() {
        for replace_with_link in [false, true] {
            let tmp = tempdir();
            let v = tmp.join("v");
            let moved = tmp.join("moved");
            let outside = tmp.join("outside");
            std::fs::create_dir(&v).unwrap();
            std::fs::create_dir(&outside).unwrap();
            let dir = Dir::open(&v).unwrap();
            assert!(!dir.exists("a").unwrap()); // inspection
            std::fs::rename(&v, &moved).unwrap();
            if replace_with_link {
                dir_links(&outside, &v);
            } else {
                std::fs::create_dir(&v).unwrap();
            }
            let mut f = dir.create_new("a").unwrap();
            f.write_all(b"x").unwrap();
            let id = dir.identity(&f).unwrap();
            drop(f);
            dir.create_dir("sub").unwrap();
            drop(dir.open_dir("sub").unwrap());
            dir.rename_noreplace("a", "b").unwrap();
            assert!(dir.open_regular("b", false).unwrap().is_some());
            assert_eq!(std::fs::read(moved.join("b")).unwrap(), b"x");
            assert!(moved.join("sub").is_dir());
            assert_eq!(remove_if_owned(&dir, "b", &id).unwrap(), Ownership::Removed);
            assert!(!moved.join("b").exists());
            for p in [&v, &outside] {
                assert_eq!(std::fs::read_dir(p).unwrap().count(), 0, "{}", p.display());
            }
            drop(dir);
            remove_tree(&tmp);
        }
    }

    /// A link (Windows: reparse point) substituted at a child name between
    /// inspection and creation is never followed: creation fails, opens are
    /// refused, ownership removal does not touch it, and the link target is
    /// unchanged. The same holds for a directory link (and a Windows
    /// junction) at a child-directory name.
    #[test]
    fn link_substitution_between_inspection_and_creation() {
        let tmp = tempdir();
        let v = tmp.join("v");
        let outside = tmp.join("outside");
        std::fs::create_dir(&v).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("target"), b"keep").unwrap();
        let dir = Dir::open(&v).unwrap();

        assert!(!dir.exists("x").unwrap()); // inspection
        file_link(&outside.join("target"), &v.join("x")); // substitution
        let err = dir.create_new("x").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{err}");
        assert_eq!(
            dir.open_regular("x", true).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            dir.open_regular("x", false).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let any = dir.identity(&dir.create_new("probe").unwrap()).unwrap();
        assert_eq!(
            remove_if_owned(&dir, "x", &any).unwrap(),
            Ownership::NotOwned
        );
        assert!(dir.rename_noreplace("probe", "x").is_err());
        assert!(dir.exists("x").unwrap());
        assert_eq!(std::fs::read(outside.join("target")).unwrap(), b"keep");

        assert!(!dir.exists("objects").unwrap()); // inspection
        for link in dir_links(&outside, &v.join("objects")) {
            let name = link.file_name().unwrap().to_str().unwrap();
            assert!(dir.open_dir(name).is_err(), "{name}");
            assert!(dir.create_dir(name).is_err(), "{name}");
            assert!(dir.create_new(name).is_err(), "{name}");
            assert!(dir.open_regular(name, false).is_err(), "{name}");
        }
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 1);
        assert_eq!(std::fs::read(outside.join("target")).unwrap(), b"keep");
        drop(dir);
        remove_tree(&tmp);
    }

    /// Removes a test tree without following links (junctions and
    /// directory symlinks are removed as links).
    fn remove_tree(p: &std::path::Path) {
        for entry in std::fs::read_dir(p).unwrap() {
            let path = entry.unwrap().path();
            let meta = std::fs::symlink_metadata(&path).unwrap();
            if meta.file_type().is_symlink() {
                // A Windows directory symlink or junction is a directory entry.
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if meta.file_attributes() & 0x10 != 0 {
                        std::fs::remove_dir(&path).unwrap();
                        continue;
                    }
                }
                std::fs::remove_file(&path).unwrap();
            } else if meta.is_dir() {
                remove_tree(&path);
            } else {
                std::fs::remove_file(&path).unwrap();
            }
        }
        std::fs::remove_dir(p).unwrap();
    }

    pub(crate) fn tempdir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "pvault-fs-{}-{}",
            std::process::id(),
            crate::crypto::random::array::<8>()
                .unwrap()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        std::fs::create_dir(&p).unwrap();
        p
    }
}
