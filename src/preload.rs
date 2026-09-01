//! `LD_PRELOAD` interposition of open/openat/access/faccessat/stat/lstat/fstatat/execve/fopen/dlopen — real function first via `dlsym(RTLD_NEXT,...)`, fallback to `remap::candidates` only on genuine ENOENT.
//! Not covered: `execl`/`execlp`/`execle` (true C variadics, and musl's own exec* internals bypass LD_PRELOAD for these anyway); `fopen64` (musl exposes it as a `#define fopen64 fopen` macro, not a distinct symbol).

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

unsafe fn dlsym_next(name: &[u8]) -> *mut libc::c_void { unsafe {
    let p = libc::dlsym(libc::RTLD_NEXT, name.as_ptr() as *const c_char);
    if p.is_null() {
        libc::abort();
    }
    p
}}

macro_rules! real_fn {
    ($cache:ident, $name:expr, $ty:ty) => {{
        static CELL: OnceLock<usize> = OnceLock::new();
        let addr = *CELL.get_or_init(|| dlsym_next($name) as usize);
        std::mem::transmute::<usize, $ty>(addr)
    }};
}

unsafe fn candidate_cstrings(path: *const c_char) -> Vec<CString> { unsafe {
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
}}

type OpenFn = unsafe extern "C" fn(*const c_char, c_int, libc::mode_t) -> c_int;
type OpenatFn = unsafe extern "C" fn(c_int, *const c_char, c_int, libc::mode_t) -> c_int;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn open(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int { unsafe {
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
}}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn openat(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: libc::mode_t,
) -> c_int { unsafe {
    let real: OpenatFn = real_fn!(cell, b"openat\0", OpenatFn);
    let rc = real(dirfd, path, flags, mode);
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
}}

type AccessFn = unsafe extern "C" fn(*const c_char, c_int) -> c_int;
type FaccessatFn = unsafe extern "C" fn(c_int, *const c_char, c_int, c_int) -> c_int;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn access(path: *const c_char, mode: c_int) -> c_int { unsafe {
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
}}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn faccessat(
    dirfd: c_int,
    path: *const c_char,
    mode: c_int,
    flag: c_int,
) -> c_int { unsafe {
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
}}

type StatFn = unsafe extern "C" fn(*const c_char, *mut libc::stat) -> c_int;
type FstatatFn = unsafe extern "C" fn(c_int, *const c_char, *mut libc::stat, c_int) -> c_int;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stat(path: *const c_char, buf: *mut libc::stat) -> c_int { unsafe {
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
}}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lstat(path: *const c_char, buf: *mut libc::stat) -> c_int { unsafe {
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
}}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fstatat(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
    flag: c_int,
) -> c_int { unsafe {
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
}}

type ExecveFn =
    unsafe extern "C" fn(*const c_char, *const *const c_char, *const *const c_char) -> c_int;

/// `Some(true)` if `path` starts with `#!`, via the real open/read (never our own `open`).
unsafe fn starts_with_shebang(real_open: OpenFn, path: &CStr) -> Option<bool> { unsafe {
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
}}

unsafe fn read_shebang_line(real_open: OpenFn, path: &CStr) -> Option<String> { unsafe {
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
    let line = &buf[2..line_end.max(2)];
    std::str::from_utf8(line).ok().map(|s| s.trim().to_string())
}}

unsafe fn resolve_if_needed(real_open: OpenFn, path: &str) -> Option<CString> { unsafe {
    let as_cstring = CString::new(path).ok()?;
    if real_exists(real_open, &as_cstring) {
        return Some(as_cstring);
    }
    remap::candidates(Path::new(path), roots())
        .into_iter()
        .filter_map(|p| CString::new(p.as_os_str().as_bytes()).ok())
        .find(|c| real_exists(real_open, c))
}}

unsafe fn real_exists(real_open: OpenFn, path: &CStr) -> bool { unsafe {
    let fd = real_open(path.as_ptr(), libc::O_RDONLY, 0);
    if fd >= 0 {
        libc::close(fd);
        true
    } else {
        false
    }
}}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn execve(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int { unsafe {
    let real: ExecveFn = real_fn!(cell, b"execve\0", ExecveFn);
    let real_open: OpenFn = real_fn!(cell2, b"open\0", OpenFn);

    if path.is_null() {
        return real(path, argv, envp);
    }
    let Ok(path_str) = CStr::from_ptr(path).to_str() else {
        return real(path, argv, envp);
    };

    let effective = if real_exists(real_open, CStr::from_ptr(path)) {
        CString::new(path_str).ok()
    } else {
        resolve_if_needed(real_open, path_str)
    };
    let Some(effective) = effective else {
        return real(path, argv, envp);
    };

    if starts_with_shebang(real_open, &effective) == Some(true) {
        if let Some(line) = read_shebang_line(real_open, &effective) {
            let mut parts = line.splitn(2, char::is_whitespace);
            let interp = parts.next().unwrap_or("").trim();
            let interp_arg = parts.next().map(|s| s.trim().to_string());
            if !interp.is_empty() {
                if let Some(resolved_interp) = resolve_if_needed(real_open, interp) {
                    let orig_argv0 = CString::new(path_str).unwrap();
                    let mut new_argv: Vec<*const c_char> = vec![resolved_interp.as_ptr()];
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
}}

type FopenFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut libc::FILE;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fopen(path: *const c_char, mode: *const c_char) -> *mut libc::FILE { unsafe {
    let real: FopenFn = real_fn!(cell, b"fopen\0", FopenFn);
    let f = real(path, mode);
    if !f.is_null() || *libc::__errno_location() != libc::ENOENT {
        return f;
    }
    for cand in candidate_cstrings(path) {
        let f2 = real(cand.as_ptr(), mode);
        if !f2.is_null() {
            return f2;
        }
    }
    f
}}

type DlopenFn = unsafe extern "C" fn(*const c_char, c_int) -> *mut libc::c_void;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlopen(path: *const c_char, flags: c_int) -> *mut libc::c_void { unsafe {
    let real: DlopenFn = real_fn!(cell, b"dlopen\0", DlopenFn);
    let handle = real(path, flags);
    if !handle.is_null() || path.is_null() {
        return handle;
    }
    for cand in candidate_cstrings(path) {
        let h2 = real(cand.as_ptr(), flags);
        if !h2.is_null() {
            return h2;
        }
    }
    handle
}}
