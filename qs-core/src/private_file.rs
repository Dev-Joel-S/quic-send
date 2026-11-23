//! Files that only the user may read: the identity key and the saved peers.
//!
//! DONE: on Unix a file is created with mode 0600, and [restrict] sets that mode on a file
//!       that has more.
//! DONE: on Windows a file gets an access list of its own with a single entry, full access
//!       for the user the program runs as, and inheritance from the directory is switched
//!       off. Without that, a file takes over whatever its directory allows.
//! DONE: the access rights are set on the empty file, before the secret is written into it
//!       ([write]). [is_private] reads them back, the tests check a written file with it.
//!       That check needs real Windows, which CI has. Wine keeps no access lists.
//! DONE: this is one layer, not the whole protection: an administrator, a backup that runs
//!       with the user's rights or another system that mounts the disk still read the file.
//!       For that the identity key can be sealed with a passphrase, see `crate::peers`.

use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    path::Path,
};

/// Write `data` to `path` so that only the user can read it, replacing the file in one step
pub fn write(path: &Path, data: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }

    let temporary = path.with_extension("tmp");
    let _ = std::fs::remove_file(&temporary);

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.access_mode(windows::WRITE_AND_SET_ACCESS);
    }

    let mut file = options.open(&temporary)?;
    let written = (|| {
        // First the access rights, then the content
        #[cfg(windows)]
        windows::restrict(&file)?;
        file.write_all(data)?;
        file.sync_all()
    })();
    drop(file);

    if let Err(e) = written {
        let _ = std::fs::remove_file(&temporary);
        return Err(e);
    }
    std::fs::rename(&temporary, path)
}

/// Take away every access to `path` except the user's own
pub fn restrict(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        let file = OpenOptions::new()
            .access_mode(windows::READ_AND_SET_ACCESS)
            .open(path)?;
        windows::restrict(&file)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Ok(())
    }
}

/// Whether the access rights of a file can be read back here. Wine reports a made up
/// access list for every file and keeps none, so tests cannot check one under it.
#[cfg(test)]
pub(crate) fn can_check() -> bool {
    !(cfg!(windows) && std::env::var_os("WINEPREFIX").is_some())
}

/// Whether nobody but the user has access to `path`
pub fn is_private(path: &Path) -> io::Result<bool> {
    let file = File::open(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(file.metadata()?.permissions().mode() & 0o077 == 0)
    }
    #[cfg(windows)]
    {
        windows::is_private(&file)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Ok(true)
    }
}

#[cfg(windows)]
mod windows {
    use std::{ffi::c_void, fs::File, io, os::windows::io::AsRawHandle, ptr};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE},
        Security::{
            AclSizeInformation,
            Authorization::{
                GetSecurityInfo, SetEntriesInAclW, SetSecurityInfo, EXPLICIT_ACCESS_W,
                NO_MULTIPLE_TRUSTEE, SET_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
                TRUSTEE_W,
            },
            EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl, GetTokenInformation,
            TokenUser, ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
            NO_INHERITANCE, PROTECTED_DACL_SECURITY_INFORMATION, PSID, SE_DACL_PROTECTED,
            TOKEN_QUERY, TOKEN_USER,
        },
        Storage::FileSystem::{
            FILE_ALL_ACCESS, FILE_GENERIC_READ, FILE_GENERIC_WRITE, READ_CONTROL, WRITE_DAC,
        },
        System::{
            SystemServices::ACCESS_ALLOWED_ACE_TYPE,
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
    };

    /// Access to ask for when a file is created: write it, and change who may access it
    pub const WRITE_AND_SET_ACCESS: u32 = FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC;
    /// Access to ask for to change who may access an existing file
    pub const READ_AND_SET_ACCESS: u32 = FILE_GENERIC_READ | WRITE_DAC;

    fn check(status: u32) -> io::Result<()> {
        match status {
            ERROR_SUCCESS => Ok(()),
            code => Err(io::Error::from_raw_os_error(code as i32)),
        }
    }

    /// The security identifier (SID) of the user this process runs as
    struct OwnSid {
        /// A `TOKEN_USER` as Windows filled it in, with the SID behind it. Kept as `u64`
        /// so the memory is aligned for the pointer the structure starts with.
        buffer: Vec<u64>,
    }

    impl OwnSid {
        fn current() -> io::Result<Self> {
            let mut token: HANDLE = ptr::null_mut();
            // SAFETY: the process handle is a pseudo handle that is always valid, and
            // `token` is a valid place to write the new handle to.
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
                return Err(io::Error::last_os_error());
            }

            let sid = Self::of(token);
            // SAFETY: `token` was opened above and is closed exactly once.
            unsafe { CloseHandle(token) };
            sid
        }

        fn of(token: HANDLE) -> io::Result<Self> {
            // Ask for the size first. This call is expected to fail and say how much.
            let mut needed = 0u32;
            // SAFETY: an empty buffer is allowed, `needed` is a valid place to write to.
            unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed) };
            if (needed as usize) < size_of::<TOKEN_USER>() {
                return Err(io::Error::last_os_error());
            }

            let mut buffer = vec![0u64; (needed as usize).div_ceil(size_of::<u64>())];
            // SAFETY: `buffer` is writable for at least `needed` bytes.
            let filled = unsafe {
                GetTokenInformation(
                    token,
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    needed,
                    &mut needed,
                )
            };
            if filled == 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(Self { buffer })
        }

        /// Valid for as long as `self` lives: it points into the buffer
        fn sid(&self) -> PSID {
            // SAFETY: Windows wrote a `TOKEN_USER` to the start of the buffer, which is
            // large enough and aligned for one.
            unsafe { (*self.buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid }
        }
    }

    /// Give `file` an access list with one entry, full access for the own user, and
    /// stop it from inheriting entries from its directory
    pub fn restrict(file: &File) -> io::Result<()> {
        let owner = OwnSid::current()?;

        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_ALL_ACCESS,
            grfAccessMode: SET_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                // With TRUSTEE_IS_SID this field holds the SID, not a name
                ptstrName: owner.sid().cast(),
            },
        };

        let mut list: *mut ACL = ptr::null_mut();
        // SAFETY: `entry` is one valid entry whose SID lives in `owner`, there is no
        // old list, and `list` is a valid place for the pointer to the new one.
        check(unsafe { SetEntriesInAclW(1, &entry, ptr::null(), &mut list) })?;

        // SAFETY: the handle belongs to `file`, which is open, and `list` is the list
        // made above. Owner, group and audit list are left as they are.
        let status = unsafe {
            SetSecurityInfo(
                file.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                list,
                ptr::null(),
            )
        };
        // SAFETY: `list` was allocated by SetEntriesInAclW and is freed exactly once.
        unsafe { LocalFree(list.cast()) };

        check(status)
    }

    /// Whether the access list of `file` is its own and has the own user as its only entry
    pub fn is_private(file: &File) -> io::Result<bool> {
        let owner = OwnSid::current()?;

        let mut list: *mut ACL = ptr::null_mut();
        let mut descriptor: *mut c_void = ptr::null_mut();
        // SAFETY: the handle belongs to `file`, which is open. Only the access list is
        // asked for, `list` and `descriptor` are valid places for the two pointers.
        check(unsafe {
            GetSecurityInfo(
                file.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut list,
                ptr::null_mut(),
                &mut descriptor,
            )
        })?;

        let private = only_entry_is(descriptor, list, owner.sid());
        // SAFETY: `descriptor` was allocated by GetSecurityInfo and is freed exactly
        // once. `list` points into it and is not used after this.
        unsafe { LocalFree(descriptor) };
        private
    }

    /// `list` has to be the access list of `descriptor`, both valid
    fn only_entry_is(descriptor: *mut c_void, list: *mut ACL, owner: PSID) -> io::Result<bool> {
        let failed = |ok: i32| match ok {
            0 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        };

        let (mut control, mut revision) = (0u16, 0u32);
        // SAFETY: `descriptor` is a valid security descriptor, the other two are valid
        // places to write to.
        failed(unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) })?;
        // Entries from the directory are still let in
        if control & SE_DACL_PROTECTED == 0 {
            return Ok(false);
        }
        // No list at all means everybody has access
        if list.is_null() {
            return Ok(false);
        }

        let mut size = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0,
        };
        // SAFETY: `list` is a valid access list, `size` is the structure this
        // information class fills in and has the length that is passed.
        failed(unsafe {
            GetAclInformation(
                list,
                ptr::from_mut(&mut size).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        })?;
        if size.AceCount != 1 {
            return Ok(false);
        }

        let mut entry: *mut c_void = ptr::null_mut();
        // SAFETY: `list` has exactly one entry, so index 0 exists.
        failed(unsafe { GetAce(list, 0, &mut entry) })?;
        let entry = entry.cast::<ACCESS_ALLOWED_ACE>();

        // SAFETY: every entry starts with the header that is read here.
        if u32::from(unsafe { (*entry).Header.AceType }) != ACCESS_ALLOWED_ACE_TYPE {
            return Ok(false);
        }
        // SAFETY: in an entry that allows access the SID starts at `SidStart`, and both
        // SIDs are valid.
        let same = unsafe { EqualSid(ptr::addr_of_mut!((*entry).SidStart).cast(), owner) };
        Ok(same != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_written_file_is_only_for_the_user() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");

        write(&path, b"one").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"one");
        assert!(!can_check() || is_private(&path).unwrap());

        // Replacing it keeps it that way, and leaves no temporary file behind
        write(&path, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert!(!can_check() || is_private(&path).unwrap());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn a_file_with_more_access_is_noticed_and_fixed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");

        // An ordinary file: on Unix made readable for everybody, on Windows it takes
        // over the access list of its directory
        std::fs::write(&path, b"secret").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert!(!can_check() || !is_private(&path).unwrap());

        restrict(&path).unwrap();
        assert!(!can_check() || is_private(&path).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"secret");
    }
}
