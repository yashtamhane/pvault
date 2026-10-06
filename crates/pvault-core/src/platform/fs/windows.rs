//! Windows file-system primitives (spec 7.6a, 8.1, 8.5; M3-F2).
//!
//! **Handle-relative, like `openat`.** Every child operation opens its target
//! with `NtCreateFile`, with `OBJECT_ATTRIBUTES.RootDirectory` = the held
//! directory handle and `ObjectName` = one validated path component. No path
//! string of the vault directory is ever re-resolved, so renaming or
//! replacing the directory after it was opened cannot redirect an operation.
//!
//! **No reparse points.** Every open uses `FILE_OPEN_REPARSE_POINT`, so a
//! symlink, junction or other reparse point at the name is opened as itself
//! instead of being followed. The attributes of the opened handle are then
//! checked, and any `FILE_ATTRIBUTE_REPARSE_POINT` is refused. Creation uses
//! `FILE_CREATE`, which fails if anything exists at the name, a reparse point
//! included.
//!
//! **Rename and delete act on a verified handle.** The source is opened
//! relative to the held directory, checked, and renamed with
//! `NtSetInformationFile(FileRenameInformation)` whose `RootDirectory` is the
//! held handle; deletion sets the delete disposition on the same handle whose
//! identity was verified. There is no path-based fallback: if an NT call
//! fails, the operation fails.
//!
//! **Durability boundary.** File data is written through handles opened with
//! `FILE_WRITE_THROUGH` and is explicitly flushed. Rename is the
//! handle-relative `NtSetInformationFile(FileRenameInformation)` operation.
//! The source rename handle also requests `FILE_WRITE_THROUGH`: Microsoft's
//! Win32 flag documentation says an NTFS write-through request flushes
//! metadata changes such as a rename that results from the request. That is
//! narrower than W1: it does not establish ReFS behavior, old-or-new crash
//! atomicity, power-loss safety, or equivalence to
//! `MoveFileExW(MOVEFILE_WRITE_THROUGH)`. The amended W1 assumption and its
//! limits are explicit in spec 8.5 and `docs/SPEC_ISSUES.md` SI-12.

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_DISPOSITION_DELETE, FILE_DISPOSITION_INFORMATION,
    FILE_DISPOSITION_INFORMATION_EX, FILE_DISPOSITION_POSIX_SEMANTICS, FILE_NON_DIRECTORY_FILE,
    FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT,
    FILE_WRITE_THROUGH, FileDispositionInformation, FileDispositionInformationEx,
    FileRenameInformation, NtCreateFile, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    ERROR_INVALID_PARAMETER, ERROR_NOACCESS, GetLastError, HANDLE, NTSTATUS, OBJ_CASE_INSENSITIVE,
    RtlNtStatusToDosError, STATUS_FILE_IS_A_DIRECTORY, STATUS_INVALID_INFO_CLASS,
    STATUS_INVALID_PARAMETER, STATUS_NOT_A_DIRECTORY, STATUS_NOT_SUPPORTED, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_ID_INFO,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_REMOTE_PROTOCOL_INFO, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FileAttributeTagInfo, FileBasicInfo,
    FileIdInfo, FileRemoteProtocolInfo, FlushFileBuffers, GetDriveTypeW,
    GetFileInformationByHandleEx, GetFinalPathNameByHandleW, GetVolumeInformationByHandleW,
    READ_CONTROL, SYNCHRONIZE, VOLUME_NAME_GUID,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::WindowsProgramming::{DRIVE_FIXED, DRIVE_REMOVABLE};

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_NO_MORE_FILES, ERROR_SHARING_VIOLATION, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, AclSizeInformation,
    AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetAclInformation, GetLengthSid, GetSecurityDescriptorControl, GetTokenInformation,
    InitializeAcl, InitializeSecurityDescriptor, IsWellKnownSid, OBJECT_INHERIT_ACE,
    OWNER_SECURITY_INFORMATION, PSID, SE_DACL_PROTECTED, SECURITY_DESCRIPTOR,
    SetSecurityDescriptorControl, SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
    TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ALL_ACCESS, FILE_FLAG_SEQUENTIAL_SCAN, FILE_ID_BOTH_DIR_INFO,
    FILE_STANDARD_INFO, FILE_TYPE_DISK, FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo,
    FileStandardInfo, GetFileInformationByHandle, GetFileType,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::{FileIdentity, IdKind, Ownership, RecordIdentity, SourceError, SourceMeta, Volume};

/// `ACCESS_ALLOWED_ACE_TYPE` and `SECURITY_DESCRIPTOR_REVISION` (their
/// `windows-sys` feature is not otherwise needed).
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

/// Every pvault open shares read, write and delete, as `std::fs` does, so
/// pvault's own handles never block each other's rename or delete.
const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

#[derive(Debug)]
pub(super) struct Dir {
    handle: File,
}

/// An `NtCreateFile` failure, keeping the NTSTATUS for exact classification.
struct NtError(NTSTATUS);

impl NtError {
    fn into_io(self) -> io::Error {
        // SAFETY: a pure status-code translation with no pointer arguments.
        let code = unsafe { RtlNtStatusToDosError(self.0) };
        io::Error::from_raw_os_error(code as i32)
    }

    fn not_found(&self) -> bool {
        NtError(self.0).into_io().kind() == io::ErrorKind::NotFound
    }
}

fn not_regular() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "not a regular file")
}

/// Opens or creates `name`, one component, relative to `root`.
fn nt_open(
    root: HANDLE,
    name: &OsStr,
    access: u32,
    disposition: u32,
    options: u32,
) -> Result<OwnedHandle, NtError> {
    nt_open_sd(root, name, access, disposition, options, None)
}

/// [`nt_open`] with an explicit security descriptor for creation.
fn nt_open_sd(
    root: HANDLE,
    name: &OsStr,
    access: u32,
    disposition: u32,
    options: u32,
    sd: Option<&OwnerOnly>,
) -> Result<OwnedHandle, NtError> {
    let wide: Vec<u16> = name.encode_wide().collect();
    let bytes = u16::try_from(wide.len() * 2).map_err(|_| NtError(STATUS_INVALID_PARAMETER))?;
    let object_name = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        // The NT API type predates const-correctness; NtCreateFile treats
        // ObjectName as input and does not mutate this buffer.
        Buffer: wide.as_ptr().cast_mut(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: core::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root,
        ObjectName: &object_name,
        // Win32 name semantics (CreateFileW is case-insensitive).
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: sd.map_or(core::ptr::null(), |d| d.as_ptr()),
        SecurityQualityOfService: core::ptr::null(),
    };
    let mut handle: HANDLE = core::ptr::null_mut();
    // SAFETY: an all-zero IO_STATUS_BLOCK is a valid output buffer.
    let mut iosb: IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
    // SAFETY: every pointer refers to a live local for the duration of the
    // call: `handle` and `iosb` are writable outputs; `attributes` points to
    // `object_name`, whose buffer `wide` outlives the call; `root` is a
    // directory handle owned by the caller. No EA buffer is passed.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            &mut iosb,
            core::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            SHARE_ALL,
            disposition,
            options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            core::ptr::null(),
            0,
        )
    };
    if status < 0 {
        return Err(NtError(status));
    }
    // SAFETY: NtCreateFile succeeded, so `handle` is a new handle that
    // nothing else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as _) })
}

/// `FileAttributes` of an open handle.
fn attributes(h: HANDLE) -> io::Result<u32> {
    // SAFETY: an all-zero FILE_ATTRIBUTE_TAG_INFO is a valid output buffer.
    let mut info: FILE_ATTRIBUTE_TAG_INFO = unsafe { core::mem::zeroed() };
    // SAFETY: `h` is open; the buffer has the size passed.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            h,
            FileAttributeTagInfo,
            (&raw mut info).cast(),
            core::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info.FileAttributes)
}

/// Refuses a reparse point, and anything but a regular file (or, with
/// `dir`, a directory).
fn check_kind(h: HANDLE, dir: bool) -> io::Result<()> {
    let a = attributes(h)?;
    if a & FILE_ATTRIBUTE_REPARSE_POINT != 0 || (a & FILE_ATTRIBUTE_DIRECTORY != 0) != dir {
        return Err(not_regular());
    }
    Ok(())
}

fn raw(h: &impl AsRawHandle) -> HANDLE {
    h.as_raw_handle() as HANDLE
}

/// Sets the delete disposition on an open handle: POSIX semantics (the name
/// disappears at once) where the file system supports them, otherwise the
/// classic disposition (the name disappears when the last handle closes).
/// Both act on the handle, never on a name.
fn delete_by_handle(h: HANDLE) -> io::Result<()> {
    let ex = FILE_DISPOSITION_INFORMATION_EX {
        Flags: FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS,
    };
    // SAFETY: an all-zero IO_STATUS_BLOCK is a valid output buffer.
    let mut iosb: IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
    // SAFETY: `h` is open with DELETE access; `ex` and `iosb` are live
    // locals of the sizes passed.
    let status = unsafe {
        NtSetInformationFile(
            h,
            &mut iosb,
            (&raw const ex).cast(),
            core::mem::size_of::<FILE_DISPOSITION_INFORMATION_EX>() as u32,
            FileDispositionInformationEx,
        )
    };
    if status >= 0 {
        return Ok(());
    }
    if ![
        STATUS_INVALID_PARAMETER,
        STATUS_INVALID_INFO_CLASS,
        STATUS_NOT_SUPPORTED,
    ]
    .contains(&status)
    {
        return Err(NtError(status).into_io());
    }
    let classic = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
    // SAFETY: as above, with the classic structure.
    let status = unsafe {
        NtSetInformationFile(
            h,
            &mut iosb,
            (&raw const classic).cast(),
            core::mem::size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
            FileDispositionInformation,
        )
    };
    if status < 0 {
        return Err(NtError(status).into_io());
    }
    Ok(())
}

impl Dir {
    /// The first handle is necessarily path-based: the final component is
    /// opened without following a reparse point and must be a plain
    /// directory.
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        let handle = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        check_kind(raw(&handle), true)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not a plain directory"))?;
        Ok(Self { handle })
    }

    fn root(&self) -> HANDLE {
        raw(&self.handle)
    }

    pub(super) fn open_dir(&self, name: &OsStr) -> io::Result<Self> {
        // READ_CONTROL: `is_private` reads the owner and DACL of this handle
        // (`GetSecurityInfo`), as `Dir::open` (GENERIC_READ) already allows.
        let h = nt_open(
            self.root(),
            name,
            FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_OPEN,
            FILE_DIRECTORY_FILE,
        )
        .map_err(|e| {
            if e.0 == STATUS_NOT_A_DIRECTORY {
                io::Error::new(io::ErrorKind::InvalidInput, "not a directory")
            } else {
                e.into_io()
            }
        })?;
        check_kind(raw(&h), true)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not a plain directory"))?;
        Ok(Self {
            handle: File::from(h),
        })
    }

    pub(super) fn create_dir(&self, name: &OsStr) -> io::Result<()> {
        let sd = OwnerOnly::new(true)?;
        let h = nt_open_sd(
            self.root(),
            name,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_CREATE,
            FILE_DIRECTORY_FILE,
            Some(&sd),
        )
        .map_err(NtError::into_io)?;
        check_kind(raw(&h), true)
    }

    pub(super) fn create_new(&self, name: &OsStr) -> io::Result<File> {
        let sd = OwnerOnly::new(false)?;
        let h = nt_open_sd(
            self.root(),
            name,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH,
            Some(&sd),
        )
        .map_err(NtError::into_io)?;
        check_kind(raw(&h), false)?;
        Ok(File::from(h))
    }

    pub(super) fn open_regular(&self, name: &OsStr, write: bool) -> io::Result<Option<File>> {
        let (access, extra) = if write {
            (FILE_GENERIC_READ | FILE_GENERIC_WRITE, FILE_WRITE_THROUGH)
        } else {
            (FILE_GENERIC_READ, 0)
        };
        let h = match nt_open(
            self.root(),
            name,
            access,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | extra,
        ) {
            Ok(h) => h,
            Err(e) if e.not_found() => return Ok(None),
            Err(e) if e.0 == STATUS_FILE_IS_A_DIRECTORY => return Err(not_regular()),
            Err(e) => return Err(e.into_io()),
        };
        check_kind(raw(&h), false)?;
        Ok(Some(File::from(h)))
    }

    pub(super) fn exists(&self, name: &OsStr) -> io::Result<bool> {
        match nt_open(
            self.root(),
            name,
            FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_OPEN,
            0,
        ) {
            Ok(_) => Ok(true),
            Err(e) if e.not_found() => Ok(false),
            Err(e) => Err(e.into_io()),
        }
    }

    pub(super) fn rename(&self, from: &OsStr, to: &OsStr, replace: bool) -> io::Result<()> {
        let source = nt_open(
            self.root(),
            from,
            DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH,
        )
        .map_err(|e| {
            if e.0 == STATUS_FILE_IS_A_DIRECTORY {
                not_regular()
            } else {
                e.into_io()
            }
        })?;
        check_kind(raw(&source), false)?;

        let name: Vec<u16> = to.encode_wide().collect();
        let name_bytes = name
            .len()
            .checked_mul(2)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "name is too long"))?;
        let name_len = u32::try_from(name_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name is too long"))?;
        let offset = core::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
        let size = offset
            .checked_add(name_bytes)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "name is too long"))?
            .max(core::mem::size_of::<FILE_RENAME_INFORMATION>());
        let info_len = u32::try_from(size)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name is too long"))?;
        // u64 storage gives the structure its 8-byte alignment.
        let mut buf = vec![0u64; size.div_ceil(8)];
        let info = buf.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        // SAFETY: `buf` is zeroed, 8-byte aligned and at least `size` bytes,
        // which covers the fixed fields and `name_bytes` of file name from
        // `offset`. The writes stay inside it.
        unsafe {
            (*info).Anonymous.ReplaceIfExists = replace;
            (*info).RootDirectory = self.root();
            (*info).FileNameLength = name_len;
            core::ptr::copy_nonoverlapping(
                name.as_ptr(),
                buf.as_mut_ptr().cast::<u8>().add(offset).cast::<u16>(),
                name.len(),
            );
        }
        // SAFETY: an all-zero IO_STATUS_BLOCK is a valid output buffer.
        let mut iosb: IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
        // SAFETY: `source` is open with DELETE access; `buf` holds a complete
        // FILE_RENAME_INFORMATION of `size` bytes whose RootDirectory is the
        // held directory handle, alive for the call.
        let status = unsafe {
            NtSetInformationFile(
                raw(&source),
                &mut iosb,
                buf.as_ptr().cast(),
                info_len,
                FileRenameInformation,
            )
        };
        if status < 0 {
            return Err(NtError(status).into_io());
        }
        Ok(())
    }

    pub(super) fn unlink(&self, name: &OsStr) -> io::Result<()> {
        // Like `unlinkat`: removes the entry itself, never a link target.
        let h = nt_open(
            self.root(),
            name,
            DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
        )
        .map_err(NtError::into_io)?;
        delete_by_handle(raw(&h))
    }

    /// Opens `name` for deletion, verifies that it is a regular file with
    /// identity `expected`, and deletes that same handle.
    pub(super) fn remove_owned(
        &self,
        name: &OsStr,
        expected: &FileIdentity,
    ) -> io::Result<Ownership> {
        let h = match nt_open(
            self.root(),
            name,
            DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
        ) {
            Ok(h) => h,
            Err(e) if e.not_found() => return Ok(Ownership::Absent),
            Err(e) if e.0 == STATUS_FILE_IS_A_DIRECTORY => return Ok(Ownership::NotOwned),
            Err(e) => return Err(e.into_io()),
        };
        if check_kind(raw(&h), false).is_err() {
            return Ok(Ownership::NotOwned);
        }
        match self.identity_of(raw(&h)) {
            Ok(id) if id == *expected => {}
            _ => return Ok(Ownership::NotOwned),
        }
        delete_by_handle(raw(&h))?;
        Ok(Ownership::Removed)
    }

    /// The names in this directory, without `.` and `..`.
    pub(super) fn list(&self) -> io::Result<Vec<OsString>> {
        let mut names = Vec::new();
        // u64 storage keeps the entries 8-byte aligned.
        let mut buf = vec![0u64; 8192];
        let mut class = FileIdBothDirectoryRestartInfo;
        loop {
            // SAFETY: the directory handle is open with list access; `buf` is
            // writable for the size passed.
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    self.root(),
                    class,
                    buf.as_mut_ptr().cast(),
                    (buf.len() * 8) as u32,
                )
            };
            if ok == 0 {
                // SAFETY: reads the calling thread's last-error value.
                let e = unsafe { GetLastError() };
                if e == ERROR_NO_MORE_FILES {
                    return Ok(names);
                }
                return Err(io::Error::from_raw_os_error(e as i32));
            }
            class = FileIdBothDirectoryInfo;
            let base = buf.as_ptr().cast::<u8>();
            let total = buf.len() * 8;
            let mut offset = 0usize;
            loop {
                let name_at = core::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
                if offset + name_at > total {
                    return Err(io::Error::other("malformed directory listing"));
                }
                // SAFETY: `offset` is within `buf`, and the system wrote a
                // FILE_ID_BOTH_DIR_INFO there (8-byte aligned per its rules).
                let entry = unsafe { &*base.add(offset).cast::<FILE_ID_BOTH_DIR_INFO>() };
                let len = entry.FileNameLength as usize;
                if offset + name_at + len > total || !len.is_multiple_of(2) {
                    return Err(io::Error::other("malformed directory listing"));
                }
                // SAFETY: the name lies within `buf` (checked above); u16
                // reads are aligned because the struct is 8-byte aligned and
                // the name offset is even.
                let units = unsafe {
                    core::slice::from_raw_parts(base.add(offset + name_at).cast::<u16>(), len / 2)
                };
                let name = OsString::from_wide(units);
                if name != "." && name != ".." {
                    names.push(name);
                }
                if entry.NextEntryOffset == 0 {
                    break;
                }
                offset += entry.NextEntryOffset as usize;
            }
        }
    }

    /// Whether `other` is this directory or lies below it, by comparing
    /// volume GUID paths of the two handles.
    pub(super) fn contains(&self, other: &Dir) -> io::Result<bool> {
        let mine = final_path(self.root())?.to_lowercase();
        let theirs = final_path(other.root())?.to_lowercase();
        let mine = mine.trim_end_matches('\\');
        Ok(theirs == mine || theirs.starts_with(&format!("{mine}\\")))
    }

    pub(super) fn held_at(&self, name: &OsStr, file: &File) -> io::Result<Option<bool>> {
        let h = match nt_open(
            self.root(),
            name,
            FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_OPEN,
            0,
        ) {
            Ok(h) => h,
            Err(e) if e.not_found() => return Ok(None),
            Err(e) => return Err(e.into_io()),
        };
        Ok(Some(file_id(raw(&h))? == file_id(raw(file))?))
    }

    /// Opens `name` for deletion and deletes that handle only if it is the
    /// same file as `file` (which this process holds open).
    pub(super) fn delete_held(&self, name: &OsStr, file: &File) -> io::Result<bool> {
        let h = match nt_open(
            self.root(),
            name,
            DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
        ) {
            Ok(h) => h,
            Err(e) if e.not_found() => return Ok(false),
            Err(e) => return Err(e.into_io()),
        };
        if file_id(raw(&h))? != file_id(raw(file))? {
            return Ok(false);
        }
        delete_by_handle(raw(&h))?;
        Ok(true)
    }

    /// Owner is the current user; the DACL is protected and allows only the
    /// user, SYSTEM and Administrators (`docs/M4_READINESS.md` 7.1).
    pub(super) fn is_private(&self) -> io::Result<bool> {
        let user = TokenUserSid::current()?;
        let mut owner: PSID = core::ptr::null_mut();
        let mut dacl: *mut ACL = core::ptr::null_mut();
        let mut sd: *mut core::ffi::c_void = core::ptr::null_mut();
        // SAFETY: the handle is open; every out-pointer is a valid local.
        let rc = unsafe {
            GetSecurityInfo(
                self.root(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                core::ptr::null_mut(),
                &mut dacl,
                core::ptr::null_mut(),
                &mut sd,
            )
        };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let verdict = (|| {
            // SAFETY: `owner` and `user` point to valid SIDs.
            if owner.is_null() || unsafe { EqualSid(owner, user.sid()) } == 0 {
                return false;
            }
            let (mut control, mut revision) = (0u16, 0u32);
            // SAFETY: `sd` is the descriptor GetSecurityInfo returned.
            if unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) } == 0
                || control & SE_DACL_PROTECTED == 0
                || dacl.is_null()
            {
                return false;
            }
            // SAFETY: an all-zero ACL_SIZE_INFORMATION is a valid output buffer.
            let mut info: ACL_SIZE_INFORMATION = unsafe { core::mem::zeroed() };
            // SAFETY: `dacl` is valid; the buffer has the size passed.
            if unsafe {
                GetAclInformation(
                    dacl,
                    (&raw mut info).cast(),
                    core::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
            } == 0
            {
                return false;
            }
            for i in 0..info.AceCount {
                let mut ace: *mut core::ffi::c_void = core::ptr::null_mut();
                // SAFETY: `i` is below the ACE count of the valid `dacl`.
                if unsafe { GetAce(dacl, i, &mut ace) } == 0 {
                    return false;
                }
                // SAFETY: `GetAce` returned a pointer to an ACE header.
                let header = unsafe { &*ace.cast::<ACE_HEADER>() };
                if header.AceType != ACCESS_ALLOWED_ACE_TYPE {
                    continue; // deny and other ACE types grant nothing
                }
                // SAFETY: an access-allowed ACE starts with this layout, and
                // its SID begins at `SidStart`.
                let sid = unsafe { (&raw mut (*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart).cast() };
                // SAFETY: `sid` and `user.sid()` are valid SIDs.
                let allowed = unsafe {
                    EqualSid(sid, user.sid()) != 0
                        || IsWellKnownSid(sid, WinLocalSystemSid) != 0
                        || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
                };
                if !allowed {
                    return false;
                }
            }
            true
        })();
        // SAFETY: `sd` was allocated by GetSecurityInfo and is freed once.
        unsafe { LocalFree(sd) };
        Ok(verdict)
    }

    pub(super) fn flush(&self) -> io::Result<()> {
        // No directory flush without administrator rights: WO-1 to WO-3.
        Ok(())
    }

    fn identity_of(&self, h: HANDLE) -> io::Result<FileIdentity> {
        let id = file_id(h)?;
        let dir = file_id(self.root())?;
        if id[..8] != dir[..8] {
            return Err(io::Error::other("file is on another volume"));
        }
        Ok(FileIdentity::Windows(id))
    }

    pub(super) fn identity(&self, file: &File) -> io::Result<FileIdentity> {
        self.identity_of(raw(file))
    }

    pub(super) fn self_identity(&self) -> io::Result<()> {
        file_id(self.root()).map(|_| ())
    }

    pub(super) fn volume(&self) -> io::Result<Volume> {
        volume_of(self.root())
    }
}

pub(super) fn flush_file(file: &File) -> io::Result<()> {
    // SAFETY: an open file handle.
    if unsafe { FlushFileBuffers(raw(file)) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn file_id(h: HANDLE) -> io::Result<[u8; 32]> {
    // SAFETY: an all-zero FILE_ID_INFO is a valid plain-data value.
    let mut id: FILE_ID_INFO = unsafe { core::mem::zeroed() };
    // SAFETY: an all-zero FILE_BASIC_INFO is a valid plain-data value.
    let mut basic: FILE_BASIC_INFO = unsafe { core::mem::zeroed() };
    // SAFETY: `h` is open; the buffers have the sizes passed.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            h,
            FileIdInfo,
            (&raw mut id).cast(),
            core::mem::size_of::<FILE_ID_INFO>() as u32,
        ) != 0
            && GetFileInformationByHandleEx(
                h,
                FileBasicInfo,
                (&raw mut basic).cast(),
                core::mem::size_of::<FILE_BASIC_INFO>() as u32,
            ) != 0
    };
    if !ok {
        return Err(io::Error::last_os_error());
    }
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&id.VolumeSerialNumber.to_be_bytes());
    out[8..24].copy_from_slice(&id.FileId.Identifier);
    out[24..].copy_from_slice(&basic.CreationTime.to_be_bytes());
    Ok(out)
}

/// Raw Q1–Q4 results for one handle (spec 8.5), recorded for the native
/// probe. Every query runs, so the report shows each answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// Q1: `Ok(())` if `FileRemoteProtocolInfo` succeeded (remote),
    /// otherwise the error code.
    pub q1: Result<(), u32>,
    /// Q2: the `VOLUME_NAME_GUID` path, or the error code.
    pub q2: Result<String, u32>,
    /// Q3: `GetDriveTypeW` on the Q2 volume root, if Q2 gave one.
    pub q3: Option<u32>,
    /// Q4: (file-system name, volume serial number), or the error code.
    pub q4: Result<(String, u32), u32>,
}

/// Runs Q1 to Q4 on `h` without deciding.
pub(super) fn probe(h: HANDLE) -> Probe {
    // Q1: FileRemoteProtocolInfo.
    // SAFETY: zeroed plain-data output buffer of the size passed.
    let mut rp: FILE_REMOTE_PROTOCOL_INFO = unsafe { core::mem::zeroed() };
    // SAFETY: `h` is open; the buffer has the size passed.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            h,
            FileRemoteProtocolInfo,
            (&raw mut rp).cast(),
            core::mem::size_of::<FILE_REMOTE_PROTOCOL_INFO>() as u32,
        )
    };
    // SAFETY: reads the calling thread's last-error value.
    let error = unsafe { GetLastError() };
    let q1 = if ok != 0 { Ok(()) } else { Err(error) };

    // Q2: the volume GUID path.
    let mut buf = [0u16; 1024];
    // SAFETY: `h` is open; `buf` has the length passed.
    let n = unsafe {
        GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), buf.len() as u32, VOLUME_NAME_GUID)
    } as usize;
    let q2 = if n == 0 {
        // SAFETY: reads the calling thread's last-error value.
        Err(unsafe { GetLastError() })
    } else if n >= buf.len() {
        Err(u32::MAX) // truncated
    } else {
        // Native names may hold unpaired surrogates; only the ASCII
        // `\\?\Volume{GUID}\` prefix is used, which lossy decoding keeps exact.
        Ok(String::from_utf16_lossy(&buf[..n]))
    };

    // Q3: the drive type of the volume root from Q2.
    let q3 = q2.as_ref().ok().and_then(|path| {
        let close = path.find("}\\")?;
        let root: Vec<u16> = path[..close + 2].encode_utf16().chain(Some(0)).collect();
        // SAFETY: a NUL-terminated wide string.
        Some(unsafe { GetDriveTypeW(root.as_ptr()) })
    });

    // Q4: file-system name and serial number.
    let mut serial = 0u32;
    let mut name = [0u16; 64];
    // SAFETY: `h` is open; the buffers have the sizes passed.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            h,
            core::ptr::null_mut(),
            0,
            &mut serial,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            name.as_mut_ptr(),
            name.len() as u32,
        )
    };
    let q4 = if ok == 0 {
        // SAFETY: reads the calling thread's last-error value.
        Err(unsafe { GetLastError() })
    } else {
        let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        String::from_utf16(&name[..len])
            .map(|n| (n, serial))
            .map_err(|_| u32::MAX - 1)
    };
    Probe { q1, q2, q3, q4 }
}

/// The Q1–Q4 decision (spec 8.5), in order; the first non-accepting
/// answer refuses. Nothing is retried with a weaker check.
pub(super) fn decide(p: &Probe) -> io::Result<Volume> {
    let refuse = |what: &str| Err(io::Error::other(what.to_owned()));
    match p.q1 {
        Ok(()) => return refuse("remote volume"),
        // Microsoft does not document the local-volume error. Native Windows
        // CI observes ERROR_NOACCESS on local NTFS; ERROR_INVALID_PARAMETER
        // remains the older expected result. Q2 and Q3 must still prove a
        // local volume GUID and a local drive type.
        Err(code) if !matches!(code, ERROR_INVALID_PARAMETER | ERROR_NOACCESS) => {
            return refuse("remote-protocol query gave an unexpected error");
        }
        Err(_) => {}
    }
    match &p.q2 {
        Ok(path) if path.starts_with("\\\\?\\Volume{") && path.contains("}\\") => {}
        _ => return refuse("not a local volume GUID path"),
    }
    if !matches!(p.q3, Some(DRIVE_FIXED) | Some(DRIVE_REMOVABLE)) {
        return refuse("not a fixed or removable drive");
    }
    match &p.q4 {
        Ok((fs_type, serial)) => Ok(Volume {
            fs_type: fs_type.clone(),
            key: u64::from(*serial),
        }),
        Err(_) => refuse("volume information unavailable"),
    }
}

fn volume_of(h: HANDLE) -> io::Result<Volume> {
    decide(&probe(h))
}

/// The raw probe of a directory handle.
pub(super) fn probe_dir(dir: &Dir) -> Probe {
    probe(dir.handle.as_raw_handle() as HANDLE)
}

/// The current process user's SID, from its token.
struct TokenUserSid {
    buf: Vec<u64>,
}

impl TokenUserSid {
    fn current() -> io::Result<Self> {
        let mut token: HANDLE = core::ptr::null_mut();
        // SAFETY: the pseudo-handle of the current process; `token` is a
        // writable out-pointer.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut len = 0u32;
        // SAFETY: a size query with a null buffer is permitted.
        unsafe { GetTokenInformation(token, TokenUser, core::ptr::null_mut(), 0, &mut len) };
        let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
        // SAFETY: `buf` is writable for `len` bytes and 8-byte aligned.
        let ok = unsafe {
            GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len)
        };
        let err = io::Error::last_os_error();
        // SAFETY: `token` was opened above and is closed once.
        unsafe { CloseHandle(token) };
        if ok == 0 {
            return Err(err);
        }
        Ok(Self { buf })
    }

    fn sid(&self) -> PSID {
        // SAFETY: `buf` holds a TOKEN_USER written by GetTokenInformation.
        unsafe { (*self.buf.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
}

/// A security descriptor whose protected DACL grants full access to the
/// current user only (inheritable for directories). Used at creation, so the
/// object is never visible with inherited permissions (spec 7.4b, 7.9, 8.3).
struct OwnerOnly {
    _user: TokenUserSid,
    _acl: Vec<u64>,
    sd: Box<SECURITY_DESCRIPTOR>,
}

impl OwnerOnly {
    fn new(dir: bool) -> io::Result<Self> {
        let user = TokenUserSid::current()?;
        // SAFETY: `user.sid()` is a valid SID.
        let sid_len = unsafe { GetLengthSid(user.sid()) } as usize;
        let size =
            core::mem::size_of::<ACL>() + core::mem::size_of::<ACCESS_ALLOWED_ACE>() + sid_len;
        let size = size.div_ceil(4) * 4;
        let mut acl = vec![0u64; size.div_ceil(8)];
        let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
        let flags = if dir {
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        } else {
            0
        };
        // SAFETY: an all-zero SECURITY_DESCRIPTOR is valid storage for
        // InitializeSecurityDescriptor.
        let mut sd: Box<SECURITY_DESCRIPTOR> = Box::new(unsafe { core::mem::zeroed() });
        let sd_ptr: *mut SECURITY_DESCRIPTOR = &mut *sd;
        // SAFETY: `acl` is writable for `size` bytes and 8-byte aligned;
        // `sd` is writable; `user.sid()` is valid for the calls.
        let ok = unsafe {
            InitializeAcl(acl_ptr, size as u32, ACL_REVISION) != 0
                && AddAccessAllowedAceEx(acl_ptr, ACL_REVISION, flags, FILE_ALL_ACCESS, user.sid())
                    != 0
                && InitializeSecurityDescriptor(sd_ptr.cast(), SECURITY_DESCRIPTOR_REVISION) != 0
                // The owner is the user explicitly: an elevated administrator's
                // default owner would be the Administrators group.
                && SetSecurityDescriptorOwner(sd_ptr.cast(), user.sid(), 0) != 0
                && SetSecurityDescriptorDacl(sd_ptr.cast(), 1, acl_ptr, 0) != 0
                && SetSecurityDescriptorControl(sd_ptr.cast(), SE_DACL_PROTECTED, SE_DACL_PROTECTED)
                    != 0
        };
        if !ok {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            _user: user,
            _acl: acl,
            sd,
        })
    }

    fn as_ptr(&self) -> *const SECURITY_DESCRIPTOR {
        &*self.sd
    }
}

fn final_path(h: HANDLE) -> io::Result<String> {
    let mut buf = vec![0u16; 32768];
    // SAFETY: `h` is open; `buf` has the length passed.
    let n = unsafe {
        GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), buf.len() as u32, VOLUME_NAME_GUID)
    } as usize;
    if n == 0 || n >= buf.len() {
        return Err(io::Error::last_os_error());
    }
    // Native names may hold unpaired surrogates (replaced here). `contains`
    // compares these paths: a replacement can only make two different paths
    // look equal, which refuses (fails safe), never the reverse.
    Ok(String::from_utf16_lossy(&buf[..n]))
}

/// FILETIME (100 ns since 1601) to `(sec, nsec)` since 1970.
fn filetime(t: i64) -> (i64, u32) {
    let since_1970 = t - 116_444_736_000_000_000;
    (
        since_1970.div_euclid(10_000_000),
        (since_1970.rem_euclid(10_000_000) * 100) as u32,
    )
}

fn basic_info(h: HANDLE) -> io::Result<FILE_BASIC_INFO> {
    // SAFETY: an all-zero FILE_BASIC_INFO is a valid output buffer.
    let mut basic: FILE_BASIC_INFO = unsafe { core::mem::zeroed() };
    // SAFETY: `h` is open; the buffer has the size passed.
    if unsafe {
        GetFileInformationByHandleEx(
            h,
            FileBasicInfo,
            (&raw mut basic).cast(),
            core::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(basic)
}

/// `(volume serial, 16-byte file ID)`, with the 64-bit index fallback.
fn volume_and_id(h: HANDLE) -> io::Result<(u64, Vec<u8>)> {
    // SAFETY: an all-zero FILE_ID_INFO is a valid output buffer.
    let mut id: FILE_ID_INFO = unsafe { core::mem::zeroed() };
    // SAFETY: `h` is open; the buffer has the size passed.
    if unsafe {
        GetFileInformationByHandleEx(
            h,
            FileIdInfo,
            (&raw mut id).cast(),
            core::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } != 0
    {
        return Ok((id.VolumeSerialNumber, id.FileId.Identifier.to_vec()));
    }
    // SAFETY: an all-zero BY_HANDLE_FILE_INFORMATION is a valid output buffer.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { core::mem::zeroed() };
    // SAFETY: `h` is open and `info` is writable.
    if unsafe { GetFileInformationByHandle(h, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    let mut ino = vec![0u8; 8];
    ino.extend_from_slice(&index.to_be_bytes());
    Ok((u64::from(info.dwVolumeSerialNumber), ino))
}

pub(super) fn record_identity(file: &File) -> io::Result<RecordIdentity> {
    let h = raw(file);
    let (dev, ino) = volume_and_id(h)?;
    let created = basic_info(h)?.CreationTime;
    Ok(RecordIdentity {
        kind: IdKind::Windows,
        dev,
        ino,
        btime: (created != 0).then(|| (created as u64).to_be_bytes().to_vec()),
    })
}

pub(super) fn open_source(path: &Path) -> Result<File, SourceError> {
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ as SHARE_READ_ONLY;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(SHARE_READ_ONLY)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) {
                SourceError::InUse
            } else if std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
                // A directory cannot be opened without backup semantics; it
                // is not a regular file either way (10.1).
                SourceError::NotRegular
            } else {
                SourceError::Io(e)
            }
        })?;
    let attrs = attributes(raw(&file)).map_err(SourceError::Io)?;
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(SourceError::Link);
    }
    // SAFETY: an open file handle.
    if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 || unsafe { GetFileType(raw(&file)) } != FILE_TYPE_DISK
    {
        return Err(SourceError::NotRegular);
    }
    Ok(file)
}

pub(super) fn source_meta(file: &File) -> io::Result<SourceMeta> {
    let h = raw(file);
    // SAFETY: an all-zero FILE_STANDARD_INFO is a valid output buffer.
    let mut standard: FILE_STANDARD_INFO = unsafe { core::mem::zeroed() };
    // SAFETY: `h` is open; the buffer has the size passed.
    if unsafe {
        GetFileInformationByHandleEx(
            h,
            FileStandardInfo,
            (&raw mut standard).cast(),
            core::mem::size_of::<FILE_STANDARD_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let basic = basic_info(h)?;
    let (dev, ino) = volume_and_id(h)?;
    Ok(SourceMeta {
        size: u64::try_from(standard.EndOfFile).map_err(|_| io::Error::other("negative size"))?,
        mtime: filetime(basic.LastWriteTime),
        ctime: filetime(basic.ChangeTime),
        dev,
        ino,
    })
}
