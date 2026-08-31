//! `LD_PRELOAD` symbol interposition — the actual deployed mechanism.
//!
//! No libc rebuild, musl or glibc: `LD_PRELOAD` is a plain environment
//! variable this musl fork already honors (confirmed directly from its
//! source, `ldso/dynlink.c`: `getenv("LD_PRELOAD")`). `/etc/ld.so.preload`
//! (a *file*-based, always-on preload list) is a glibc-only mechanism —
//! grepped this musl's `ldso/dynlink.c` for it and it isn't there, so
//! writing to that file would silently do nothing here. The zero-manual-
//! export delivery this project needs is instead: export `LD_PRELOAD=` in
//! `/etc/environment` (already sourced for every login-shell-descended
//! process, same as `PATH`/`CC` already are there) — no rebuild, just a
//! config line, and it's the same mechanism for a musl-linked or a future
//! glibc-linked process, so there's no "do it twice" problem at all.
//!
//! Each exported function here: try the real, underlying libc function
//! first (via `dlsym(RTLD_NEXT, ...)`, so this never depends on which
//! libc — musl today, glibc later — actually implements it). Only on a
//! genuine `ENOENT`, and only for an in-scope path, fall back to
//! [`crate::remap::candidates`] and retry each candidate with that same
//! real function, in order, until one succeeds. The common case (path
//! already resolves) costs nothing extra beyond the one real call.
//!
//! **Known, deliberate scope limit:** only `open`, `openat`, `access`,
//! `faccessat`, `stat`, `lstat`, `fstatat`, and `execve` are interposed.
//! `execl`/`execlp`/`execle` (true C variadics — an unbounded `...`
//! argument list) cannot be implemented as a matching-ABI function on
//! stable Rust at all (that needs the nightly-only `c_variadic` feature),
//! and musl's own `execvp`/`execl*` call `execve` as a *local* call inside
//! its own compiled object, which bypasses `LD_PRELOAD` interposition
//! entirely (interposition only catches calls that cross the dynamic
//! symbol table, not a library's calls to its own already-resolved
//! internal symbols) — so code that reaches an absolute FHS path only via
//! `execvp`/`execl*` is not covered by this preload library. Everything
//! that calls `execve` directly (confirmed: musl's own `execvp` does, for
//! any name already containing a `/`, which is exactly the hardcoded-
//! absolute-path case this project exists for) is unaffected by that gap.

use crate::remap::{self, Roots};
use libc::{c_char, c_int};
use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::OnceLock;

fn roots() -> &'static Roots {
    static ROOTS: OnceLock<Roots> = OnceLock::new();
    ROOTS.get_or_init(Roots::from_env)
}

/// Look up the real, underlying libc symbol once and cache the address —
/// `RTLD_NEXT` means "whatever the next object in load order provides",
/// i.e. the actual musl (or glibc) implementation, never ourselves again.
unsafe fn dlsym_next(name: &[u8]) -> *mut libc::c_void {
    let p = libc::dlsym(libc::RTLD_NEXT, name.as_ptr() as *const c_char);
    if p.is_null() {
        // Nothing sane to do if libc itself doesn't have this symbol —
        // abort rather than dereference a null function pointer later.
        libc::abort();
    }
    p
}

macro_rules! real_fn {
    ($cache:ident, $name:expr, $ty:ty) => {{
        static CELL: OnceLock<usize> = OnceLock::new();
        let addr = *CELL.get_or_init(|| unsafe { dlsym_next($name) as usize });
        unsafe { std::mem::transmute::<usize, $ty>(addr) }
    }};
}

/// Build the ordered candidate paths for a raw C path, as CStrings ready
/// to hand back to a real libc call. Empty if out of scope / not a valid
/// UTF-8 path / malformed.
unsafe fn candidate_cstrings(path: *const c_char) -> Vec<CString> {
    if path.is_null() {
        return Vec::new();
    }
    let Ok(s) = CStr::from_ptr(path).to_str() else {
        return Vec::new();
    };
    remap::candidates(Path::new(s), roots())
        .into_iter()
        .filter_map(|p| CString::new(p.as_os_str().as_bytes()).ok())
        .collect()
}

// ---------------------------------------------------------------------
// open / openat
// ---------------------------------------------------------------------

type OpenFn = unsafe extern "C" fn(*const c_char, c_int, libc::mode_t) -> c_int;
type OpenatFn = unsafe extern "C" fn(c_int, *const c_char, c_int, libc::mode_t) -> c_int;

#[no_mangle]
pub unsafe extern "C" fn open(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    let real: OpenFn = real_fn!(cell, b"open\0", OpenFn);
    let rc = real(path, flags, mode);
    if rc >= 0 || *libc::__errno_location() != libc::ENOENT {
        return rc;
    }
    for cand in candidate_cstrings(path) {
        let rc2 = real(cand.as_ptr(), flags, mode);
        if rc2 >= 0 {
            return rc2;
        }
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn openat(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: libc::mode_t,
) -> c_int {
    let real: OpenatFn = real_fn!(cell, b"openat\0", OpenatFn);
    let rc = real(dirfd, path, flags, mode);
    // Only meaningful to resolve absolute paths (dirfd is irrelevant
    // then) — relative lookups are left completely alone.
    if rc >= 0 || *libc::__errno_location() != libc::ENOENT {
        return rc;
    }
    for cand in candidate_cstrings(path) {
        let rc2 = real(dirfd, cand.as_ptr(), flags, mode);
        if rc2 >= 0 {
            return rc2;
        }
    }
    rc
}

// ---------------------------------------------------------------------
// access / faccessat
// ---------------------------------------------------------------------

type AccessFn = unsafe extern "C" fn(*const c_char, c_int) -> c_int;
type FaccessatFn = unsafe extern "C" fn(c_int, *const c_char, c_int, c_int) -> c_int;

#[no_mangle]
pub unsafe extern "C" fn access(path: *const c_char, mode: c_int) -> c_int {
    let real: AccessFn = real_fn!(cell, b"access\0", AccessFn);
    let rc = real(path, mode);
    if rc >= 0 || *libc::__errno_location() != libc::ENOENT {
        return rc;
    }
    for cand in candidate_cstrings(path) {
        let rc2 = real(cand.as_ptr(), mode);
        if rc2 >= 0 {
            return rc2;
        }
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn faccessat(
    dirfd: c_int,
    path: *const c_char,
    mode: c_int,
    flag: c_int,
) -> c_int {
    let real: FaccessatFn = real_fn!(cell, b"faccessat\0", FaccessatFn);
    let rc = real(dirfd, path, mode, flag);
    if rc >= 0 || *libc::__errno_location() != libc::ENOENT {
        return rc;
    }
    for cand in candidate_cstrings(path) {
        let rc2 = real(dirfd, cand.as_ptr(), mode, flag);
        if rc2 >= 0 {
            return rc2;
        }
    }
    rc
}

// ---------------------------------------------------------------------
// stat / lstat / fstatat
// ---------------------------------------------------------------------

type StatFn = unsafe extern "C" fn(*const c_char, *mut libc::stat) -> c_int;
type FstatatFn = unsafe extern "C" fn(c_int, *const c_char, *mut libc::stat, c_int) -> c_int;

#[no_mangle]
pub unsafe extern "C" fn stat(path: *const c_char, buf: *mut libc::stat) -> c_int {
    let real: StatFn = real_fn!(cell, b"stat\0", StatFn);
    let rc = real(path, buf);
    if rc >= 0 || *libc::__errno_location() != libc::ENOENT {
        return rc;
    }
    for cand in candidate_cstrings(path) {
        let rc2 = real(cand.as_ptr(), buf);
        if rc2 >= 0 {
            return rc2;
        }
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn lstat(path: *const c_char, buf: *mut libc::stat) -> c_int {
    let real: StatFn = real_fn!(cell, b"lstat\0", StatFn);
    let rc = real(path, buf);
    if rc >= 0 || *libc::__errno_location() != libc::ENOENT {
        return rc;
    }
    for cand in candidate_cstrings(path) {
        let rc2 = real(cand.as_ptr(), buf);
        if rc2 >= 0 {
            return rc2;
        }
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn fstatat(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
    flag: c_int,
) -> c_int {
    let real: FstatatFn = real_fn!(cell, b"fstatat\0", FstatatFn);
    let rc = real(dirfd, path, buf, flag);
    if rc >= 0 || *libc::__errno_location() != libc::ENOENT {
        return rc;
    }
    for cand in candidate_cstrings(path) {
        let rc2 = real(dirfd, cand.as_ptr(), buf, flag);
        if rc2 >= 0 {
            return rc2;
        }
    }
    rc
}

// ---------------------------------------------------------------------
// execve — the shebang-aware one
// ---------------------------------------------------------------------

type ExecveFn =
    unsafe extern "C" fn(*const c_char, *const *const c_char, *const *const c_char) -> c_int;

/// Peek a real file's first two bytes via the *real* open/read (never our
/// own interposed `open`, to keep this a plain, direct read with no
/// resolution logic recursing into itself) — `Some(true)` if it starts
/// with `#!`, `Some(false)` if it opened fine but doesn't, `None` if it
/// couldn't be opened/read at all.
unsafe fn starts_with_shebang(real_open: OpenFn, path: &CStr) -> Option<bool> {
    let fd = real_open(path.as_ptr(), libc::O_RDONLY, 0);
    if fd < 0 {
        return None;
    }
    let mut buf = [0u8; 2];
    let n = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 2);
    libc::close(fd);
    if n < 2 {
        return Some(false);
    }
    Some(&buf == b"#!")
}

/// Read a shebang line's full content (after the `#!`), via the real
/// open/read — up to a generous fixed cap, matching the kernel's own
/// `BINPRM_BUF_SIZE`-style bound instead of reading unboundedly.
unsafe fn read_shebang_line(real_open: OpenFn, path: &CStr) -> Option<String> {
    let fd = real_open(path.as_ptr(), libc::O_RDONLY, 0);
    if fd < 0 {
        return None;
    }
    let mut buf = [0u8; 256];
    let n = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
    libc::close(fd);
    if n <= 2 {
        return None;
    }
    let n = n as usize;
    let line_end = buf[..n].iter().position(|&b| b == b'\n').unwrap_or(n);
    let line = &buf[2..line_end.max(2)]; // skip the leading "#!"
    std::str::from_utf8(line).ok().map(|s| s.trim().to_string())
}

/// Resolve one path (as given on a shebang line, or as the exec target
/// itself) to a real, existing absolute path if it isn't one already.
unsafe fn resolve_if_needed(real_open: OpenFn, path: &str) -> Option<CString> {
    let as_cstring = CString::new(path).ok()?;
    if real_exists(real_open, &as_cstring) {
        return Some(as_cstring);
    }
    remap::candidates(Path::new(path), roots())
        .into_iter()
        .filter_map(|p| CString::new(p.as_os_str().as_bytes()).ok())
        .find(|c| real_exists(real_open, c))
}

unsafe fn real_exists(real_open: OpenFn, path: &CStr) -> bool {
    let fd = real_open(path.as_ptr(), libc::O_RDONLY, 0);
    if fd >= 0 {
        libc::close(fd);
        true
    } else {
        false
    }
}

#[no_mangle]
pub unsafe extern "C" fn execve(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    let real: ExecveFn = real_fn!(cell, b"execve\0", ExecveFn);
    let real_open: OpenFn = real_fn!(cell2, b"open\0", OpenFn);

    if path.is_null() {
        return real(path, argv, envp);
    }
    let Ok(path_str) = CStr::from_ptr(path).to_str() else {
        return real(path, argv, envp);
    };

    // Find where the exec target actually lives (itself, or a resolved
    // candidate if the given path doesn't exist).
    let effective = if real_exists(real_open, CStr::from_ptr(path)) {
        CString::new(path_str).ok()
    } else {
        resolve_if_needed(real_open, path_str)
    };
    let Some(effective) = effective else {
        // Nothing real anywhere — genuine ENOENT, unchanged from today.
        return real(path, argv, envp);
    };

    if starts_with_shebang(real_open, &effective) == Some(true) {
        if let Some(line) = read_shebang_line(real_open, &effective) {
            // Standard shebang grammar: interpreter, then at most one
            // optional argument, split on the first run of whitespace.
            let mut parts = line.splitn(2, char::is_whitespace);
            let interp = parts.next().unwrap_or("").trim();
            let interp_arg = parts.next().map(|s| s.trim().to_string());
            if !interp.is_empty() {
                if let Some(resolved_interp) = resolve_if_needed(real_open, interp) {
                    // argv[0] = interpreter, [optional arg], original
                    // script path exactly as the caller passed it, then
                    // the caller's original argv[1..] — same convention
                    // the kernel's own binfmt_script uses.
                    let orig_argv0 = CString::new(path_str).unwrap();
                    let mut new_argv: Vec<*const c_char> =
                        vec![resolved_interp.as_ptr()];
                    let interp_arg_c = interp_arg.and_then(|a| CString::new(a).ok());
                    if let Some(a) = &interp_arg_c {
                        new_argv.push(a.as_ptr());
                    }
                    new_argv.push(orig_argv0.as_ptr());
                    if !argv.is_null() {
                        let mut i = 1isize;
                        loop {
                            let p = *argv.offset(i);
                            if p.is_null() {
                                break;
                            }
                            new_argv.push(p);
                            i += 1;
                        }
                    }
                    new_argv.push(std::ptr::null());
                    return real(resolved_interp.as_ptr(), new_argv.as_ptr(), envp);
                }
            }
        }
    }

    if effective.as_c_str() != CStr::from_ptr(path) {
        return real(effective.as_ptr(), argv, envp);
    }
    real(path, argv, envp)
}
