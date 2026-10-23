//! Operating-system calls of voleith-prove: no crash dumps or crash
//! reports, locked memory (Linux, `--require-mlock`), and publishing a file
//! under a name without ever replacing an existing file.
//!
//! This is the only module of the tools with unsafe code: the system calls
//! themselves, with arguments that are plain integers, pointers to local
//! buffers or NUL-terminated paths.

#![allow(unsafe_code)]

use std::io;
use std::path::Path;

/// Turns off crash dumps and crash reporting for this process.
///
/// - Linux: `prctl(PR_SET_DUMPABLE, 0)` (no core dump, whatever
///   `core_pattern` says unless `fs.suid_dumpable` is 2; no ptrace attach or
///   `/proc/<pid>/mem` access by other processes of the same user) and
///   `setrlimit(RLIMIT_CORE, 0)`.
/// - Other Unix: `setrlimit(RLIMIT_CORE, 0)`.
/// - Windows: `SetErrorMode` with `SEM_FAILCRITICALERRORS |
///   SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX` (no error dialogs);
///   `WerAddExcludedApplication(<this .exe name>, FALSE)`, which excludes
///   the program from Windows Error Reporting for the current user (a
///   persistent per-user registry setting; whether WER's LocalDumps honour
///   it is not verified); `SetUnhandledExceptionFilter` with a filter that
///   calls `TerminateProcess`, so that an unhandled exception (including a
///   stack overflow, which std reports and passes on) never reaches WER or a
///   just-in-time debugger; and a panic hook that ends the process with
///   `TerminateProcess` after printing the panic message, instead of the
///   `__fastfail` of `abort`, which goes to WER. What still goes to WER is
///   a `__fastfail` from elsewhere (e.g. `abort` on an allocation failure),
///   which only the exclusion covers.
///
/// Any failure is an error.
pub fn no_crash_dumps() -> Result<(), String> {
    #[cfg(unix)]
    {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: prctl with integer arguments only.
            let r = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
            if r != 0 {
                return Err(format!(
                    "prctl(PR_SET_DUMPABLE, 0) failed: {}",
                    io::Error::last_os_error()
                ));
            }
        }
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: a pointer to a local struct of the right type.
        let r = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) };
        if r != 0 {
            return Err(format!(
                "setrlimit(RLIMIT_CORE, 0) failed: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        win::no_crash_dumps()
    }
}

/// `mlockall(MCL_CURRENT | MCL_FUTURE)` (Linux): no page of this process,
/// present or future, is written to swap. Refuses first if RLIMIT_MEMLOCK
/// is below 128 MiB and the process is not root, since a later allocation
/// beyond the limit would then fail (the prover needs about 20 MB).
#[cfg(target_os = "linux")]
pub fn lock_all_memory() -> Result<(), String> {
    const NEED: u64 = 128 << 20;
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: a pointer to a local struct of the right type.
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) } != 0 {
        return Err(format!(
            "getrlimit(RLIMIT_MEMLOCK) failed: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: no arguments.
    let root = unsafe { libc::geteuid() } == 0;
    if lim.rlim_cur != libc::RLIM_INFINITY && lim.rlim_cur < NEED as libc::rlim_t && !root {
        return Err(format!(
            "RLIMIT_MEMLOCK is {} bytes; --require-mlock needs at least {NEED} (ulimit -l)",
            lim.rlim_cur
        ));
    }
    // SAFETY: integer flags only.
    if unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) } != 0 {
        return Err(format!(
            "mlockall(MCL_CURRENT | MCL_FUTURE) failed: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Gives the complete file `tmp` the name `dest`, failing if `dest` exists:
/// an existing file is never replaced. Linux: `renameat2` with
/// `RENAME_NOREPLACE`, or, where the file system does not support it, a hard
/// link and an unlink; other Unix: a hard link and an unlink; Windows:
/// `MoveFileExW` with `MOVEFILE_WRITE_THROUGH` and without
/// `MOVEFILE_REPLACE_EXISTING`. On success `tmp` no longer exists, except
/// in the link-and-unlink path when the unlink fails, which is reported as
/// `Ok(Some(error))`.
pub fn publish_no_replace(tmp: &Path, dest: &Path) -> io::Result<Option<io::Error>> {
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c = |p: &Path| {
            CString::new(p.as_os_str().as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))
        };
        let (from, to) = (c(tmp)?, c(dest)?);
        // SAFETY: two NUL-terminated paths that outlive the call.
        let r = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if r == 0 {
            return Ok(None);
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EINVAL) | Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP) => {}
            _ => return Err(e),
        }
    }
    #[cfg(unix)]
    {
        // link(2) fails with EEXIST rather than replace `dest`.
        std::fs::hard_link(tmp, dest)?;
        Ok(std::fs::remove_file(tmp).err())
    }
    #[cfg(windows)]
    {
        win::move_no_replace(tmp, dest).map(|()| None)
    }
}

/// Makes a completed rename or link durable (Unix: fsync of the directory;
/// Windows: MOVEFILE_WRITE_THROUGH already did it).
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    #[cfg(windows)]
    {
        let _ = dir;
        Ok(())
    }
}

#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    const SEM_FAILCRITICALERRORS: u32 = 0x0001;
    const SEM_NOGPFAULTERRORBOX: u32 = 0x0002;
    const SEM_NOOPENFILEERRORBOX: u32 = 0x8000;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0008;
    const EXIT_CODE: u32 = 3;

    type Filter = Option<unsafe extern "system" fn(*const c_void) -> i32>;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetErrorMode() -> u32;
        fn SetErrorMode(mode: u32) -> u32;
        fn SetUnhandledExceptionFilter(filter: Filter) -> Filter;
        fn GetCurrentProcess() -> *mut c_void;
        fn TerminateProcess(process: *mut c_void, code: u32) -> i32;
        fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
    }

    #[link(name = "wer")]
    extern "system" {
        fn WerAddExcludedApplication(exe: *const u16, all_users: i32) -> i32;
    }

    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    }

    fn terminate() -> ! {
        // SAFETY: the pseudo-handle of this process and an exit code.
        unsafe {
            TerminateProcess(GetCurrentProcess(), EXIT_CODE);
        }
        // TerminateProcess on the current process does not return.
        std::process::abort()
    }

    unsafe extern "system" fn on_unhandled_exception(_info: *const c_void) -> i32 {
        terminate()
    }

    pub fn no_crash_dumps() -> Result<(), String> {
        // SAFETY: integer flags only.
        unsafe {
            SetErrorMode(
                GetErrorMode()
                    | SEM_FAILCRITICALERRORS
                    | SEM_NOGPFAULTERRORBOX
                    | SEM_NOOPENFILEERRORBOX,
            );
        }
        let exe = std::env::current_exe()
            .map_err(|e| format!("cannot find the path of this program: {e}"))?;
        let name = exe
            .file_name()
            .ok_or("cannot find the file name of this program")?;
        let w = wide(name);
        // SAFETY: a NUL-terminated wide string that outlives the call.
        let hr = unsafe { WerAddExcludedApplication(w.as_ptr(), 0) };
        if hr < 0 {
            return Err(format!(
                "WerAddExcludedApplication failed: HRESULT 0x{:08x}",
                hr as u32
            ));
        }
        // SAFETY: a function with the signature of a top-level exception
        // filter, valid for the life of the process.
        unsafe {
            SetUnhandledExceptionFilter(Some(on_unhandled_exception));
        }
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            default_hook(info);
            terminate();
        }));
        Ok(())
    }

    pub fn move_no_replace(from: &Path, to: &Path) -> io::Result<()> {
        let (f, t) = (wide(from.as_os_str()), wide(to.as_os_str()));
        // SAFETY: two NUL-terminated wide strings that outlive the call.
        if unsafe { MoveFileExW(f.as_ptr(), t.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
