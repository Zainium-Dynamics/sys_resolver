//! `LD_PRELOAD` interposition. Every hook calls the real function first (looked up with
//! `dlsym(RTLD_NEXT, ...)`) and falls back to `remap::candidates`/`nss` only on a genuine
//! ENOENT / not-found, so a path that exists is never touched.
//!
//! Hooked: open openat creat access eaccess euidaccess faccessat stat lstat fstatat statx statfs
//! statvfs fopen freopen opendir scandir ftw nftw readlink readlinkat realpath
//! canonicalize_file_name pathconf getxattr lgetxattr listxattr llistxattr inotify_add_watch chdir
//! dlopen (+ the `*64` names, glibc's `__open_2`/`__openat_2` fortify entries and its old
//! `__xstat` family), execve execv execvp execvpe execveat posix_spawn posix_spawnp (and execl
//! execlp execle in `execl.c`), getpwnam getpwuid getgrnam getgrgid (+ `_r`), and unlink unlinkat rmdir
//! (see [`refuses_delete`]).
//!
//! musl calls its own functions directly, never through the PLT, so `execv`, `execvp` and
//! `posix_spawn` (which Rust's `Command`, Python's `subprocess` and most launchers use) never
//! reach the `execve` hook: each gets its own hook. musl's `getpwnam()` reads the passwd file
//! through an internal `fopen()` for the same reason, hence the `getpw*`/`getgr*` hooks.
//! The same goes for a program's own check before it runs something: GNU make (gnulib's
//! `find_in_given_path`) tests its `/bin/sh` with `eaccess()`, which in musl calls the internal
//! `faccessat`, so `eaccess`/`euidaccess` are hooked too.
//! A prebuilt program whose loader isn't on this system (`/lib64/ld-linux-x86-64.so.2`,
//! `/lib/ld-musl-x86_64.so.1`) is started through this system's copy of it, given the program.
//! Not covered: static and setuid programs (the loader preloads nothing into them), and the
//! loader of a program they start (the kernel reads `PT_INTERP`).
//!
//! The library is linked without a libc of its own (see `build-so.sh`): its libc calls bind to
//! the libc of the program it is loaded into, so it works the same in musl and glibc programs.
//! Code that can run in a `vfork()` child (the exec hooks) does not allocate unless a path
//! actually has to be remapped, and every real function is looked up when the library loads.

// C's `open`/`openat` are variadic and stable Rust can't define a variadic function; newer
// rustc denies exporting them with a fixed signature. On x86_64 the fixed (path, flags, mode)
// form receives exactly what a variadic call passes: mode is in the same register either way.
#![allow(unknown_lints, invalid_runtime_symbol_definitions)]

use crate::nss;
use crate::remap::{self, Roots};
use libc::{c_char, c_int, c_void};
use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

fn roots() -> &'static Roots {
    static ROOTS: OnceLock<Roots> = OnceLock::new();
    ROOTS.get_or_init(Roots::from_env)
}

unsafe extern "C" {
    static environ: *const *const c_char;
}

unsafe fn errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

unsafe fn set_errno(e: c_int) {
    unsafe { *libc::__errno_location() = e }
}

// ── The real functions ───────────────────────────────────────────────────────

type OpenFn = unsafe extern "C" fn(*const c_char, c_int, libc::mode_t) -> c_int;
type OpenatFn = unsafe extern "C" fn(c_int, *const c_char, c_int, libc::mode_t) -> c_int;
type CreatFn = unsafe extern "C" fn(*const c_char, libc::mode_t) -> c_int;
type AccessFn = unsafe extern "C" fn(*const c_char, c_int) -> c_int;
type FaccessatFn = unsafe extern "C" fn(c_int, *const c_char, c_int, c_int) -> c_int;
type StatFn = unsafe extern "C" fn(*const c_char, *mut libc::stat) -> c_int;
type FstatatFn = unsafe extern "C" fn(c_int, *const c_char, *mut libc::stat, c_int) -> c_int;
type StatxFn = unsafe extern "C" fn(c_int, *const c_char, c_int, libc::c_uint, *mut c_void) -> c_int;
type FopenFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut libc::FILE;
type FreopenFn =
    unsafe extern "C" fn(*const c_char, *const c_char, *mut libc::FILE) -> *mut libc::FILE;
type OpendirFn = unsafe extern "C" fn(*const c_char) -> *mut libc::DIR;
type ReadlinkFn = unsafe extern "C" fn(*const c_char, *mut c_char, usize) -> isize;
type RealpathFn = unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut c_char;
type ChdirFn = unsafe extern "C" fn(*const c_char) -> c_int;
type DlopenFn = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
type ExecveFn =
    unsafe extern "C" fn(*const c_char, *const *const c_char, *const *const c_char) -> c_int;
type SpawnFn = unsafe extern "C" fn(
    *mut libc::pid_t,
    *const c_char,
    *const c_void,
    *const c_void,
    *const *const c_char,
    *const *const c_char,
) -> c_int;
type UnlinkFn = unsafe extern "C" fn(*const c_char) -> c_int;
type XstatFn = unsafe extern "C" fn(c_int, *const c_char, *mut libc::stat) -> c_int;
type FxstatatFn = unsafe extern "C" fn(c_int, c_int, *const c_char, *mut libc::stat, c_int) -> c_int;
type StatfsFn = unsafe extern "C" fn(*const c_char, *mut c_void) -> c_int;
type Open2Fn = unsafe extern "C" fn(*const c_char, c_int) -> c_int;
type Openat2Fn = unsafe extern "C" fn(c_int, *const c_char, c_int) -> c_int;
type ReadlinkatFn = unsafe extern "C" fn(c_int, *const c_char, *mut c_char, usize) -> isize;
type ScandirFn = unsafe extern "C" fn(*const c_char, *mut c_void, *const c_void, *const c_void) -> c_int;
type CanonicalizeFn = unsafe extern "C" fn(*const c_char) -> *mut c_char;
type InotifyAddFn = unsafe extern "C" fn(c_int, *const c_char, u32) -> c_int;
type FtwFn = unsafe extern "C" fn(*const c_char, *const c_void, c_int) -> c_int;
type NftwFn = unsafe extern "C" fn(*const c_char, *const c_void, c_int, c_int) -> c_int;
type ExecveatFn =
    unsafe extern "C" fn(c_int, *const c_char, *const *const c_char, *const *const c_char, c_int) -> c_int;
type PathconfFn = unsafe extern "C" fn(*const c_char, c_int) -> libc::c_long;
type GetxattrFn = unsafe extern "C" fn(*const c_char, *const c_char, *mut c_void, usize) -> isize;
type ListxattrFn = unsafe extern "C" fn(*const c_char, *mut c_char, usize) -> isize;
type UnlinkatFn = unsafe extern "C" fn(c_int, *const c_char, c_int) -> c_int;
type GetpwnamRFn = unsafe extern "C" fn(
    *const c_char,
    *mut libc::passwd,
    *mut c_char,
    usize,
    *mut *mut libc::passwd,
) -> c_int;
type GetpwuidRFn = unsafe extern "C" fn(
    libc::uid_t,
    *mut libc::passwd,
    *mut c_char,
    usize,
    *mut *mut libc::passwd,
) -> c_int;
type GetgrnamRFn = unsafe extern "C" fn(
    *const c_char,
    *mut libc::group,
    *mut c_char,
    usize,
    *mut *mut libc::group,
) -> c_int;
type GetgrgidRFn = unsafe extern "C" fn(
    libc::gid_t,
    *mut libc::group,
    *mut c_char,
    usize,
    *mut *mut libc::group,
) -> c_int;

/// The next definition of every hooked function. `None` when the libc has no such symbol
/// (musl has no `open64`, older libcs no `statx`): the `*64` hooks then use the plain one.
struct Real {
    open: Option<OpenFn>,
    open64: Option<OpenFn>,
    openat: Option<OpenatFn>,
    openat64: Option<OpenatFn>,
    creat: Option<CreatFn>,
    access: Option<AccessFn>,
    eaccess: Option<AccessFn>,
    euidaccess: Option<AccessFn>,
    faccessat: Option<FaccessatFn>,
    open_2: Option<Open2Fn>,
    open64_2: Option<Open2Fn>,
    openat_2: Option<Openat2Fn>,
    openat64_2: Option<Openat2Fn>,
    xstat: Option<XstatFn>,
    xstat64: Option<XstatFn>,
    lxstat: Option<XstatFn>,
    lxstat64: Option<XstatFn>,
    fxstatat: Option<FxstatatFn>,
    fxstatat64: Option<FxstatatFn>,
    statfs: Option<StatfsFn>,
    statfs64: Option<StatfsFn>,
    statvfs: Option<StatfsFn>,
    statvfs64: Option<StatfsFn>,
    freopen64: Option<FreopenFn>,
    scandir: Option<ScandirFn>,
    readlinkat: Option<ReadlinkatFn>,
    canonicalize_file_name: Option<CanonicalizeFn>,
    inotify_add_watch: Option<InotifyAddFn>,
    ftw: Option<FtwFn>,
    ftw64: Option<FtwFn>,
    nftw: Option<NftwFn>,
    nftw64: Option<NftwFn>,
    execveat: Option<ExecveatFn>,
    pathconf: Option<PathconfFn>,
    getxattr: Option<GetxattrFn>,
    lgetxattr: Option<GetxattrFn>,
    listxattr: Option<ListxattrFn>,
    llistxattr: Option<ListxattrFn>,
    stat: Option<StatFn>,
    stat64: Option<StatFn>,
    lstat: Option<StatFn>,
    lstat64: Option<StatFn>,
    fstatat: Option<FstatatFn>,
    fstatat64: Option<FstatatFn>,
    statx: Option<StatxFn>,
    fopen: Option<FopenFn>,
    fopen64: Option<FopenFn>,
    freopen: Option<FreopenFn>,
    opendir: Option<OpendirFn>,
    readlink: Option<ReadlinkFn>,
    realpath: Option<RealpathFn>,
    chdir: Option<ChdirFn>,
    dlopen: Option<DlopenFn>,
    execve: Option<ExecveFn>,
    posix_spawn: Option<SpawnFn>,
    posix_spawnp: Option<SpawnFn>,
    unlink: Option<UnlinkFn>,
    rmdir: Option<UnlinkFn>,
    unlinkat: Option<UnlinkatFn>,
    getpwnam_r: Option<GetpwnamRFn>,
    getpwuid_r: Option<GetpwuidRFn>,
    getgrnam_r: Option<GetgrnamRFn>,
    getgrgid_r: Option<GetgrgidRFn>,
}

unsafe fn next<T>(name: &CStr) -> Option<T> {
    unsafe {
        let p = libc::dlsym(libc::RTLD_NEXT, name.as_ptr());
        // SAFETY: T is always the `Option<fn>` matching `name`; null maps to None.
        (!p.is_null()).then(|| std::mem::transmute_copy::<*mut c_void, T>(&p))
    }
}

impl Real {
    unsafe fn load() -> Self {
        unsafe {
            Real {
                open: next(c"open"),
                open64: next(c"open64"),
                openat: next(c"openat"),
                openat64: next(c"openat64"),
                creat: next(c"creat"),
                access: next(c"access"),
                eaccess: next(c"eaccess"),
                euidaccess: next(c"euidaccess"),
                faccessat: next(c"faccessat"),
                open_2: next(c"__open_2"),
                open64_2: next(c"__open64_2"),
                openat_2: next(c"__openat_2"),
                openat64_2: next(c"__openat64_2"),
                xstat: next(c"__xstat"),
                xstat64: next(c"__xstat64"),
                lxstat: next(c"__lxstat"),
                lxstat64: next(c"__lxstat64"),
                fxstatat: next(c"__fxstatat"),
                fxstatat64: next(c"__fxstatat64"),
                statfs: next(c"statfs"),
                statfs64: next(c"statfs64"),
                statvfs: next(c"statvfs"),
                statvfs64: next(c"statvfs64"),
                freopen64: next(c"freopen64"),
                scandir: next(c"scandir"),
                readlinkat: next(c"readlinkat"),
                canonicalize_file_name: next(c"canonicalize_file_name"),
                inotify_add_watch: next(c"inotify_add_watch"),
                ftw: next(c"ftw"),
                ftw64: next(c"ftw64"),
                nftw: next(c"nftw"),
                nftw64: next(c"nftw64"),
                execveat: next(c"execveat"),
                pathconf: next(c"pathconf"),
                getxattr: next(c"getxattr"),
                lgetxattr: next(c"lgetxattr"),
                listxattr: next(c"listxattr"),
                llistxattr: next(c"llistxattr"),
                stat: next(c"stat"),
                stat64: next(c"stat64"),
                lstat: next(c"lstat"),
                lstat64: next(c"lstat64"),
                fstatat: next(c"fstatat"),
                fstatat64: next(c"fstatat64"),
                statx: next(c"statx"),
                fopen: next(c"fopen"),
                fopen64: next(c"fopen64"),
                freopen: next(c"freopen"),
                opendir: next(c"opendir"),
                readlink: next(c"readlink"),
                realpath: next(c"realpath"),
                chdir: next(c"chdir"),
                dlopen: next(c"dlopen"),
                execve: next(c"execve"),
                posix_spawn: next(c"posix_spawn"),
                posix_spawnp: next(c"posix_spawnp"),
                unlink: next(c"unlink"),
                rmdir: next(c"rmdir"),
                unlinkat: next(c"unlinkat"),
                getpwnam_r: next(c"getpwnam_r"),
                getpwuid_r: next(c"getpwuid_r"),
                getgrnam_r: next(c"getgrnam_r"),
                getgrgid_r: next(c"getgrgid_r"),
            }
        }
    }
}

fn real() -> &'static Real {
    static REAL: OnceLock<Real> = OnceLock::new();
    REAL.get_or_init(|| unsafe { Real::load() })
}

/// Look everything up while the library loads, never later from inside a hook: a hook can
/// run in a `vfork()` child, where taking the loader's or the allocator's lock can hang.
#[used]
#[unsafe(link_section = ".init_array")]
static INIT: unsafe extern "C" fn() = init;

unsafe extern "C" fn init() {
    real();
    roots();
    caller_is_zex();
}

/// Call `f(path)`; on ENOENT retry it with each remapped candidate, keeping the first
/// errno when none works. `failed` tells a failed return value from a good one.
unsafe fn with_fallback<T>(path: *const c_char, failed: fn(&T) -> bool, f: impl Fn(*const c_char) -> T) -> T {
    unsafe {
        let r = f(path);
        if !failed(&r) || errno() != libc::ENOENT {
            return r;
        }
        let first = errno();
        for cand in candidate_cstrings(path) {
            let r2 = f(cand.as_ptr());
            if !failed(&r2) {
                return r2;
            }
        }
        set_errno(first);
        r
    }
}

fn neg_int(r: &c_int) -> bool {
    *r < 0
}

fn neg_isize(r: &isize) -> bool {
    *r < 0
}

fn null_ptr<T>(r: &*mut T) -> bool {
    r.is_null()
}

unsafe fn missing<T>(fail: T) -> T {
    unsafe { set_errno(libc::ENOSYS) };
    fail
}

unsafe fn candidate_cstrings(path: *const c_char) -> Vec<CString> {
    unsafe {
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
}

// ── Files ────────────────────────────────────────────────────────────────────

unsafe fn open_with(real: Option<OpenFn>, path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    unsafe {
        let Some(real) = real else { return missing(-1) };
        with_fallback(path, neg_int, |p| real(p, flags, mode))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn open(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    unsafe { open_with(real().open, path, flags, mode) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn open64(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    unsafe { open_with(real().open64.or(real().open), path, flags, mode) }
}

unsafe fn openat_with(
    real: Option<OpenatFn>,
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: libc::mode_t,
) -> c_int {
    unsafe {
        let Some(real) = real else { return missing(-1) };
        with_fallback(path, neg_int, |p| real(dirfd, p, flags, mode))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn openat(dirfd: c_int, path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    unsafe { openat_with(real().openat, dirfd, path, flags, mode) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn openat64(dirfd: c_int, path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    unsafe { openat_with(real().openat64.or(real().openat), dirfd, path, flags, mode) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn creat(path: *const c_char, mode: libc::mode_t) -> c_int {
    unsafe {
        let Some(real) = real().creat else { return missing(-1) };
        with_fallback(path, neg_int, |p| real(p, mode))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn access(path: *const c_char, mode: c_int) -> c_int {
    unsafe {
        let Some(real) = real().access else { return missing(-1) };
        with_fallback(path, neg_int, |p| real(p, mode))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn faccessat(dirfd: c_int, path: *const c_char, mode: c_int, flag: c_int) -> c_int {
    unsafe {
        let Some(real) = real().faccessat else { return missing(-1) };
        with_fallback(path, neg_int, |p| real(dirfd, p, mode, flag))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn eaccess(path: *const c_char, mode: c_int) -> c_int {
    unsafe {
        let Some(real) = real().eaccess.or(real().euidaccess) else { return missing(-1) };
        with_fallback(path, neg_int, |p| real(p, mode))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn euidaccess(path: *const c_char, mode: c_int) -> c_int {
    unsafe {
        let Some(real) = real().euidaccess.or(real().eaccess) else { return missing(-1) };
        with_fallback(path, neg_int, |p| real(p, mode))
    }
}

// glibc's fortified `open`/`openat` (`_FORTIFY_SOURCE` builds call these instead)

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __open_2(path: *const c_char, flags: c_int) -> c_int {
    unsafe {
        let Some(real) = real().open_2 else { return open(path, flags, 0) };
        with_fallback(path, neg_int, |p| real(p, flags))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __open64_2(path: *const c_char, flags: c_int) -> c_int {
    unsafe {
        let Some(real) = real().open64_2.or(real().open_2) else { return open64(path, flags, 0) };
        with_fallback(path, neg_int, |p| real(p, flags))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __openat_2(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
    unsafe {
        let Some(real) = real().openat_2 else { return openat(dirfd, path, flags, 0) };
        with_fallback(path, neg_int, |p| real(dirfd, p, flags))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __openat64_2(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
    unsafe {
        let Some(real) = real().openat64_2.or(real().openat_2) else {
            return openat64(dirfd, path, flags, 0);
        };
        with_fallback(path, neg_int, |p| real(dirfd, p, flags))
    }
}

unsafe fn stat_with(real: Option<StatFn>, path: *const c_char, buf: *mut libc::stat) -> c_int {
    unsafe {
        let Some(real) = real else { return missing(-1) };
        with_fallback(path, neg_int, |p| real(p, buf))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stat(path: *const c_char, buf: *mut libc::stat) -> c_int {
    unsafe { stat_with(real().stat, path, buf) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stat64(path: *const c_char, buf: *mut libc::stat) -> c_int {
    unsafe { stat_with(real().stat64.or(real().stat), path, buf) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lstat(path: *const c_char, buf: *mut libc::stat) -> c_int {
    unsafe { stat_with(real().lstat, path, buf) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lstat64(path: *const c_char, buf: *mut libc::stat) -> c_int {
    unsafe { stat_with(real().lstat64.or(real().lstat), path, buf) }
}

unsafe fn fstatat_with(
    real: Option<FstatatFn>,
    dirfd: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
    flag: c_int,
) -> c_int {
    unsafe {
        let Some(real) = real else { return missing(-1) };
        with_fallback(path, neg_int, |p| real(dirfd, p, buf, flag))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fstatat(dirfd: c_int, path: *const c_char, buf: *mut libc::stat, flag: c_int) -> c_int {
    unsafe { fstatat_with(real().fstatat, dirfd, path, buf, flag) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fstatat64(dirfd: c_int, path: *const c_char, buf: *mut libc::stat, flag: c_int) -> c_int {
    unsafe { fstatat_with(real().fstatat64.or(real().fstatat), dirfd, path, buf, flag) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn statx(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mask: libc::c_uint,
    buf: *mut c_void,
) -> c_int {
    unsafe {
        let Some(real) = real().statx else { return missing(-1) };
        with_fallback(path, neg_int, |p| real(dirfd, p, flags, mask, buf))
    }
}

// glibc before 2.33 compiled `stat()` into calls to these

unsafe fn xstat_with(real: Option<XstatFn>, ver: c_int, path: *const c_char, buf: *mut libc::stat) -> c_int {
    unsafe {
        let Some(real) = real else { return missing(-1) };
        with_fallback(path, neg_int, |p| real(ver, p, buf))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __xstat(ver: c_int, path: *const c_char, buf: *mut libc::stat) -> c_int {
    unsafe { xstat_with(real().xstat, ver, path, buf) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __xstat64(ver: c_int, path: *const c_char, buf: *mut libc::stat) -> c_int {
    unsafe { xstat_with(real().xstat64.or(real().xstat), ver, path, buf) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __lxstat(ver: c_int, path: *const c_char, buf: *mut libc::stat) -> c_int {
    unsafe { xstat_with(real().lxstat, ver, path, buf) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __lxstat64(ver: c_int, path: *const c_char, buf: *mut libc::stat) -> c_int {
    unsafe { xstat_with(real().lxstat64.or(real().lxstat), ver, path, buf) }
}

unsafe fn fxstatat_with(
    real: Option<FxstatatFn>,
    ver: c_int,
    dirfd: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
    flag: c_int,
) -> c_int {
    unsafe {
        let Some(real) = real else { return missing(-1) };
        with_fallback(path, neg_int, |p| real(ver, dirfd, p, buf, flag))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __fxstatat(
    ver: c_int,
    dirfd: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
    flag: c_int,
) -> c_int {
    unsafe { fxstatat_with(real().fxstatat, ver, dirfd, path, buf, flag) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __fxstatat64(
    ver: c_int,
    dirfd: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
    flag: c_int,
) -> c_int {
    unsafe { fxstatat_with(real().fxstatat64.or(real().fxstatat), ver, dirfd, path, buf, flag) }
}

unsafe fn statfs_with(real: Option<StatfsFn>, path: *const c_char, buf: *mut c_void) -> c_int {
    unsafe {
        let Some(real) = real else { return missing(-1) };
        with_fallback(path, neg_int, |p| real(p, buf))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn statfs(path: *const c_char, buf: *mut c_void) -> c_int {
    unsafe { statfs_with(real().statfs, path, buf) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn statfs64(path: *const c_char, buf: *mut c_void) -> c_int {
    unsafe { statfs_with(real().statfs64.or(real().statfs), path, buf) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn statvfs(path: *const c_char, buf: *mut c_void) -> c_int {
    unsafe { statfs_with(real().statvfs, path, buf) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn statvfs64(path: *const c_char, buf: *mut c_void) -> c_int {
    unsafe { statfs_with(real().statvfs64.or(real().statvfs), path, buf) }
}

unsafe fn fopen_with(real: Option<FopenFn>, path: *const c_char, mode: *const c_char) -> *mut libc::FILE {
    unsafe {
        let Some(real) = real else { return missing(std::ptr::null_mut()) };
        with_fallback(path, null_ptr, |p| real(p, mode))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fopen(path: *const c_char, mode: *const c_char) -> *mut libc::FILE {
    unsafe { fopen_with(real().fopen, path, mode) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fopen64(path: *const c_char, mode: *const c_char) -> *mut libc::FILE {
    unsafe { fopen_with(real().fopen64.or(real().fopen), path, mode) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn freopen(
    path: *const c_char,
    mode: *const c_char,
    stream: *mut libc::FILE,
) -> *mut libc::FILE {
    unsafe { freopen_with(real().freopen, path, mode, stream) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn freopen64(
    path: *const c_char,
    mode: *const c_char,
    stream: *mut libc::FILE,
) -> *mut libc::FILE {
    unsafe { freopen_with(real().freopen64.or(real().freopen), path, mode, stream) }
}

unsafe fn freopen_with(
    real: Option<FreopenFn>,
    path: *const c_char,
    mode: *const c_char,
    stream: *mut libc::FILE,
) -> *mut libc::FILE {
    unsafe {
        let Some(real) = real else { return missing(std::ptr::null_mut()) };
        // freopen closes `stream` even when the open fails, so only one attempt is possible:
        // pick the path that exists first.
        if !path.is_null() && !exists(path) {
            if let Some(cand) = candidate_cstrings(path).into_iter().find(|c| exists(c.as_ptr())) {
                return real(cand.as_ptr(), mode, stream);
            }
        }
        real(path, mode, stream)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn opendir(path: *const c_char) -> *mut libc::DIR {
    unsafe {
        let Some(real) = real().opendir else { return missing(std::ptr::null_mut()) };
        with_fallback(path, null_ptr, |p| real(p))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn scandir(
    path: *const c_char,
    namelist: *mut c_void,
    filter: *const c_void,
    compar: *const c_void,
) -> c_int {
    unsafe {
        let Some(real) = real().scandir else { return missing(-1) };
        with_fallback(path, neg_int, |p| real(p, namelist, filter, compar))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn readlink(path: *const c_char, buf: *mut c_char, size: usize) -> isize {
    unsafe {
        let Some(real) = real().readlink else { return missing(-1) };
        with_fallback(path, neg_isize, |p| real(p, buf, size))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn readlinkat(dirfd: c_int, path: *const c_char, buf: *mut c_char, size: usize) -> isize {
    unsafe {
        let Some(real) = real().readlinkat else { return missing(-1) };
        with_fallback(path, neg_isize, |p| real(dirfd, p, buf, size))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn realpath(path: *const c_char, resolved: *mut c_char) -> *mut c_char {
    unsafe {
        let Some(real) = real().realpath else { return missing(std::ptr::null_mut()) };
        with_fallback(path, null_ptr, |p| real(p, resolved))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn canonicalize_file_name(path: *const c_char) -> *mut c_char {
    unsafe {
        let Some(real) = real().canonicalize_file_name else { return realpath(path, std::ptr::null_mut()) };
        with_fallback(path, null_ptr, |p| real(p))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn inotify_add_watch(fd: c_int, path: *const c_char, mask: u32) -> c_int {
    unsafe {
        let Some(real) = real().inotify_add_watch else { return missing(-1) };
        with_fallback(path, neg_int, |p| real(fd, p, mask))
    }
}

// ftw/nftw walk the tree with libc's own opendir/stat, so only the starting point is ours

unsafe fn ftw_with(real: Option<FtwFn>, path: *const c_char, f: *const c_void, fds: c_int) -> c_int {
    unsafe {
        let Some(real) = real else { return missing(-1) };
        with_fallback(path, neg_int, |p| real(p, f, fds))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftw(path: *const c_char, f: *const c_void, fds: c_int) -> c_int {
    unsafe { ftw_with(real().ftw, path, f, fds) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftw64(path: *const c_char, f: *const c_void, fds: c_int) -> c_int {
    unsafe { ftw_with(real().ftw64.or(real().ftw), path, f, fds) }
}

unsafe fn nftw_with(
    real: Option<NftwFn>,
    path: *const c_char,
    f: *const c_void,
    fds: c_int,
    flags: c_int,
) -> c_int {
    unsafe {
        let Some(real) = real else { return missing(-1) };
        with_fallback(path, neg_int, |p| real(p, f, fds, flags))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn nftw(path: *const c_char, f: *const c_void, fds: c_int, flags: c_int) -> c_int {
    unsafe { nftw_with(real().nftw, path, f, fds, flags) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn nftw64(path: *const c_char, f: *const c_void, fds: c_int, flags: c_int) -> c_int {
    unsafe { nftw_with(real().nftw64.or(real().nftw), path, f, fds, flags) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pathconf(path: *const c_char, name: c_int) -> libc::c_long {
    unsafe {
        let Some(real) = real().pathconf else { return missing(-1) };
        with_fallback(path, |r: &libc::c_long| *r < 0, |p| real(p, name))
    }
}

unsafe fn getxattr_with(
    real: Option<GetxattrFn>,
    path: *const c_char,
    name: *const c_char,
    value: *mut c_void,
    size: usize,
) -> isize {
    unsafe {
        let Some(real) = real else { return missing(-1) };
        with_fallback(path, neg_isize, |p| real(p, name, value, size))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getxattr(path: *const c_char, name: *const c_char, value: *mut c_void, size: usize) -> isize {
    unsafe { getxattr_with(real().getxattr, path, name, value, size) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lgetxattr(path: *const c_char, name: *const c_char, value: *mut c_void, size: usize) -> isize {
    unsafe { getxattr_with(real().lgetxattr, path, name, value, size) }
}

unsafe fn listxattr_with(real: Option<ListxattrFn>, path: *const c_char, list: *mut c_char, size: usize) -> isize {
    unsafe {
        let Some(real) = real else { return missing(-1) };
        with_fallback(path, neg_isize, |p| real(p, list, size))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn listxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize {
    unsafe { listxattr_with(real().listxattr, path, list, size) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn llistxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize {
    unsafe { listxattr_with(real().llistxattr, path, list, size) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn chdir(path: *const c_char) -> c_int {
    unsafe {
        let Some(real) = real().chdir else { return missing(-1) };
        with_fallback(path, neg_int, |p| real(p))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlopen(path: *const c_char, flags: c_int) -> *mut c_void {
    unsafe {
        let Some(real) = real().dlopen else { return std::ptr::null_mut() };
        let handle = real(path, flags);
        // dlopen reports failure through dlerror(), not errno: retry on any failure
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
    }
}

// ── Running programs ─────────────────────────────────────────────────────────

/// Longest `#!` line read, as the kernel does.
const SHEBANG_MAX: usize = 256;

unsafe fn exists(path: *const c_char) -> bool {
    unsafe {
        let Some(access) = real().access else { return false };
        access(path, libc::F_OK) == 0
    }
}

/// What to run instead of what the caller asked for. Owns the strings `argv` points into.
struct Exec {
    file: CString,
    _keep: Vec<CString>,
    argv: Option<Vec<*const c_char>>,
}

impl Exec {
    fn argv(&self, original: *const *const c_char) -> *const *const c_char {
        self.argv.as_ref().map_or(original, |v| v.as_ptr())
    }
}

/// `(interpreter, optional argument)` of a `#!` line, the way the kernel splits it.
fn parse_shebang(head: &[u8]) -> Option<(&[u8], Option<&[u8]>)> {
    let line = head.strip_prefix(b"#!")?;
    let line = &line[..line.iter().position(|&b| b == b'\n').unwrap_or(line.len())];
    let blank = |b: &u8| matches!(b, b' ' | b'\t' | b'\r');
    let start = line.iter().position(|b| !blank(b))?;
    let line = &line[start..];
    let end = line.iter().position(blank).unwrap_or(line.len());
    let (interp, rest) = line.split_at(end);
    let rest = match rest.iter().position(|b| !blank(b)) {
        Some(s) => &rest[s..rest.iter().rposition(|b| !blank(b)).map_or(rest.len(), |e| e + 1)],
        None => &rest[rest.len()..],
    };
    Some((interp, (!rest.is_empty()).then_some(rest)))
}

const PT_INTERP: u32 = 3;

/// The `PT_INTERP` path of the 64-bit ELF program open on `fd`, NUL-terminated in `buf`; its
/// length, or `None` for a static program.
unsafe fn elf_interp(fd: c_int, buf: &mut [u8; libc::PATH_MAX as usize]) -> Option<usize> {
    unsafe {
        let read_at = |dst: &mut [u8], off: u64| {
            libc::pread(fd, dst.as_mut_ptr() as *mut c_void, dst.len(), off as libc::off_t)
        };
        let u16_at = |b: &[u8], i: usize| u16::from_le_bytes([b[i], b[i + 1]]) as u64;
        let u64_at = |b: &[u8], i: usize| {
            let mut v = [0u8; 8];
            v.copy_from_slice(&b[i..i + 8]);
            u64::from_le_bytes(v)
        };
        let mut eh = [0u8; 64];
        // ELFCLASS64, little-endian
        if read_at(&mut eh, 0) != 64 || eh[..4] != *b"\x7fELF" || eh[4] != 2 || eh[5] != 1 {
            return None;
        }
        let (phoff, phentsize, phnum) = (u64_at(&eh, 32), u16_at(&eh, 54), u16_at(&eh, 56));
        if phentsize < 56 {
            return None;
        }
        for i in 0..phnum {
            let mut ph = [0u8; 56];
            if read_at(&mut ph, phoff + i * phentsize) != 56 {
                return None;
            }
            if u32::from_le_bytes([ph[0], ph[1], ph[2], ph[3]]) != PT_INTERP {
                continue;
            }
            let size = (u64_at(&ph, 32) as usize).min(buf.len() - 1);
            let n = read_at(&mut buf[..size], u64_at(&ph, 8));
            if n <= 0 {
                return None;
            }
            let len = buf[..n as usize].iter().position(|&b| b == 0).unwrap_or(n as usize);
            buf[len] = 0;
            return Some(len);
        }
        None
    }
}

/// This system's copy of the loader a prebuilt program names (`/lib64/ld-linux-x86-64.so.2`,
/// `/lib/ld-musl-x86_64.so.1`): glibc's lives in its own directory in the userland, musl's in
/// the base. There is no `/lib64` or `/lib`.
fn system_loader(interp: &[u8]) -> Option<CString> {
    let name = &interp[interp.iter().rposition(|&b| b == b'/').map_or(0, |i| i + 1)..];
    let dir = if name.starts_with(b"ld-linux") {
        roots().union.join("x86_64-zainium-linux-gnu/lib")
    } else if name.starts_with(b"ld-musl") {
        roots().musl_sysdir.join("lib")
    } else {
        return None;
    };
    CString::new(dir.join(std::ffi::OsStr::from_bytes(name)).as_os_str().as_bytes()).ok()
}

/// Find where `path` really is and, for a script whose `#!` interpreter isn't where the line
/// says (`#!/bin/sh`, `#!/usr/bin/env python3`) or a program whose loader isn't
/// (`/lib64/ld-linux-x86-64.so.2`), the argv that starts it through the real one.
/// `None` means run it unchanged. That common case allocates nothing.
unsafe fn prepare_exec(path: *const c_char, argv: *const *const c_char) -> Option<Exec> {
    unsafe {
        if path.is_null() {
            return None;
        }
        let mut file: Option<CString> = None;
        if !exists(path) {
            file = Some(candidate_cstrings(path).into_iter().find(|c| exists(c.as_ptr()))?);
        }
        let target = file.as_ref().map_or(path, |c| c.as_ptr());

        let mut head = [0u8; SHEBANG_MAX];
        let mut n = 0isize;
        let mut interp = [0u8; libc::PATH_MAX as usize];
        let mut interp_len = None;
        if let Some(open) = real().open {
            let fd = open(target, libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK, 0);
            if fd >= 0 {
                n = libc::read(fd, head.as_mut_ptr() as *mut c_void, head.len());
                if n >= 4 && head[..4] == *b"\x7fELF" {
                    interp_len = elf_interp(fd, &mut interp);
                }
                libc::close(fd);
            }
        }
        if let Some(len) = interp_len {
            if !exists(interp.as_ptr() as *const c_char) {
                if let Some(loader) = system_loader(&interp[..len]).filter(|l| exists(l.as_ptr())) {
                    let program = file.unwrap_or_else(|| CStr::from_ptr(path).to_owned());
                    let has_argv = !argv.is_null() && !(*argv).is_null();
                    let argv0 = if has_argv { *argv } else { program.as_ptr() };
                    // what the kernel would have run: the loader, given the program
                    let mut v = vec![loader.as_ptr(), c"--argv0".as_ptr(), argv0, program.as_ptr()];
                    if has_argv {
                        let mut i = 1;
                        while !(*argv.add(i)).is_null() {
                            v.push(*argv.add(i));
                            i += 1;
                        }
                    }
                    v.push(std::ptr::null());
                    return Some(Exec { file: loader, _keep: vec![program], argv: Some(v) });
                }
            }
        }
        if n > 0 {
            if let Some((interp, arg)) = parse_shebang(&head[..n as usize]) {
                let mut name = [0u8; SHEBANG_MAX + 1];
                name[..interp.len()].copy_from_slice(interp);
                let name_ptr = name.as_ptr() as *const c_char;
                if !exists(name_ptr) {
                    if let Some(real_interp) =
                        candidate_cstrings(name_ptr).into_iter().find(|c| exists(c.as_ptr()))
                    {
                        let script = file.unwrap_or_else(|| CStr::from_ptr(path).to_owned());
                        let arg = arg.and_then(|a| CString::new(a).ok());
                        // the kernel's order: interpreter, its argument, the script, argv[1..]
                        let mut v = vec![real_interp.as_ptr()];
                        if let Some(a) = &arg {
                            v.push(a.as_ptr());
                        }
                        v.push(script.as_ptr());
                        if !argv.is_null() && !(*argv).is_null() {
                            let mut i = 1;
                            while !(*argv.add(i)).is_null() {
                                v.push(*argv.add(i));
                                i += 1;
                            }
                        }
                        v.push(std::ptr::null());
                        let mut keep = vec![script];
                        keep.extend(arg);
                        return Some(Exec { file: real_interp, _keep: keep, argv: Some(v) });
                    }
                }
            }
        }
        file.map(|file| Exec { file, _keep: Vec::new(), argv: None })
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn execve(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    unsafe {
        let Some(real) = real().execve else { return missing(-1) };
        match prepare_exec(path, argv) {
            Some(e) => real(e.file.as_ptr(), e.argv(argv), envp),
            None => real(path, argv, envp),
        }
    }
}

/// A path relative to a directory fd is the caller's own business; absolute paths and ones
/// relative to the cwd (the forms an FHS path takes) go through the same remapping as execve.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn execveat(
    dirfd: c_int,
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
    flags: c_int,
) -> c_int {
    unsafe {
        let Some(real) = real().execveat else { return missing(-1) };
        let fhs_form = !path.is_null() && (*path == b'/' as c_char || dirfd == libc::AT_FDCWD);
        match if fhs_form { prepare_exec(path, argv) } else { None } {
            Some(e) => real(dirfd, e.file.as_ptr(), e.argv(argv), envp, flags),
            None => real(dirfd, path, argv, envp, flags),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn execv(path: *const c_char, argv: *const *const c_char) -> c_int {
    unsafe { execve(path, argv, environ) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn execvp(file: *const c_char, argv: *const *const c_char) -> c_int {
    unsafe { execvpe(file, argv, environ) }
}

/// Each `dir/name` on `$PATH` in order, built on the stack (this runs in `vfork()` children).
unsafe fn for_each_on_path(name: &[u8], mut f: impl FnMut(*const c_char) -> bool) {
    unsafe {
        let path = libc::getenv(c"PATH".as_ptr());
        let path: &[u8] = if path.is_null() {
            b"/usr/local/bin:/bin:/usr/bin"
        } else {
            CStr::from_ptr(path).to_bytes()
        };
        let mut buf = [0u8; libc::PATH_MAX as usize];
        for dir in path.split(|&b| b == b':') {
            let sep = usize::from(!dir.is_empty());
            let len = dir.len() + sep + name.len();
            if len >= buf.len() {
                continue;
            }
            buf[..dir.len()].copy_from_slice(dir);
            if sep == 1 {
                buf[dir.len()] = b'/';
            }
            buf[dir.len() + sep..len].copy_from_slice(name);
            buf[len] = 0;
            if f(buf.as_ptr() as *const c_char) {
                return;
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn execvpe(
    file: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    unsafe {
        if file.is_null() || *file == 0 {
            set_errno(libc::ENOENT);
            return -1;
        }
        let name = CStr::from_ptr(file).to_bytes();
        if name.contains(&b'/') {
            return execve(file, argv, envp);
        }
        // musl's own search, through the execve hook: EACCES is remembered, ENOENT and ENOTDIR
        // move on, anything else stops
        let mut seen_eacces = false;
        let mut stop = false;
        for_each_on_path(name, |cand| {
            execve(cand, argv, envp);
            match errno() {
                libc::EACCES => seen_eacces = true,
                libc::ENOENT | libc::ENOTDIR => {}
                _ => stop = true,
            }
            stop
        });
        if !stop && seen_eacces {
            set_errno(libc::EACCES);
        }
        -1
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_spawn(
    pid: *mut libc::pid_t,
    path: *const c_char,
    actions: *const c_void,
    attr: *const c_void,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    unsafe {
        let Some(real) = real().posix_spawn else { return libc::ENOSYS };
        match prepare_exec(path, argv) {
            Some(e) => real(pid, e.file.as_ptr(), actions, attr, e.argv(argv), envp),
            None => real(pid, path, actions, attr, argv, envp),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_spawnp(
    pid: *mut libc::pid_t,
    file: *const c_char,
    actions: *const c_void,
    attr: *const c_void,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    unsafe {
        let Some(spawnp) = real().posix_spawnp else { return libc::ENOSYS };
        let Some(spawn) = real().posix_spawn else { return libc::ENOSYS };
        if file.is_null() {
            return spawnp(pid, file, actions, attr, argv, envp);
        }
        let name = CStr::from_ptr(file).to_bytes();
        if name.contains(&b'/') {
            return posix_spawn(pid, file, actions, attr, argv, envp);
        }
        // find the program the way the real search would; when it is a script whose
        // interpreter needs remapping, or sits in a remapped PATH dir, start the fixed form
        let mut fixed: Option<Exec> = None;
        for_each_on_path(name, |cand| {
            let Some(access) = real().access else { return true };
            if access(cand, libc::X_OK) == 0 {
                fixed = prepare_exec(cand, argv);
                return true;
            }
            if errno() == libc::ENOENT {
                fixed = prepare_exec(cand, argv);
            }
            fixed.is_some()
        });
        match fixed {
            Some(e) => spawn(pid, e.file.as_ptr(), actions, attr, e.argv(argv), envp),
            None => spawnp(pid, file, actions, attr, argv, envp),
        }
    }
}

// ── Deleting ─────────────────────────────────────────────────────────────────

fn caller_is_zex() -> bool {
    static ZEX: OnceLock<bool> = OnceLock::new();
    *ZEX.get_or_init(|| {
        std::fs::read_link("/proc/self/exe").is_ok_and(|exe| exe == roots().syshub.join("bin/zex"))
    })
}

/// `..` and `.` folded away without touching the disk.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            c => out.push(c),
        }
    }
    out
}

/// A safety net against a stray `rm -rf` under `/overlayer/syshub`, not a security boundary:
/// only zex may delete a file that belongs to the base itself. Still deletable by anyone:
/// - `var/` and `etc/`, the running system's state and configuration (logs, caches,
///   NetworkManager connections, systemd links);
/// - anything stored in the userland layer (`zexlib/union`): installed packages and every file
///   a program created there.
fn refuses_delete(path: &Path) -> bool {
    let roots = roots();
    let path = lexical(path);
    let Ok(rel) = path.strip_prefix(&roots.syshub) else {
        return false;
    };
    match rel.components().next() {
        Some(Component::Normal(top)) if top == "var" || top == "etc" => return false,
        None => {}
        _ => {
            if std::fs::symlink_metadata(roots.union.join(rel)).is_ok() {
                return false;
            }
        }
    }
    !caller_is_zex()
}

/// `dirfd` + a possibly relative name as an absolute path. `rm -rf` opens each directory once
/// and then unlinks entries relative to it, so the dirfd case matters.
fn absolute(dirfd: c_int, name: &Path) -> Option<PathBuf> {
    if name.is_absolute() {
        return Some(name.to_path_buf());
    }
    let base = if dirfd == libc::AT_FDCWD {
        std::env::current_dir().ok()?
    } else {
        std::fs::read_link(format!("/proc/self/fd/{dirfd}")).ok()?
    };
    Some(base.join(name))
}

unsafe fn refuses(dirfd: c_int, path: *const c_char) -> bool {
    unsafe {
        if path.is_null() {
            return false;
        }
        let name = Path::new(std::ffi::OsStr::from_bytes(CStr::from_ptr(path).to_bytes()));
        absolute(dirfd, name).is_some_and(|p| refuses_delete(&p))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn unlink(path: *const c_char) -> c_int {
    unsafe {
        if refuses(libc::AT_FDCWD, path) {
            set_errno(libc::EPERM);
            return -1;
        }
        let Some(real) = real().unlink else { return missing(-1) };
        real(path)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rmdir(path: *const c_char) -> c_int {
    unsafe {
        if refuses(libc::AT_FDCWD, path) {
            set_errno(libc::EPERM);
            return -1;
        }
        let Some(real) = real().rmdir else { return missing(-1) };
        real(path)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn unlinkat(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
    unsafe {
        if refuses(dirfd, path) {
            set_errno(libc::EPERM);
            return -1;
        }
        let Some(real) = real().unlinkat else { return missing(-1) };
        real(dirfd, path, flags)
    }
}

// ── Users and groups ─────────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpwnam_r(
    name: *const c_char,
    pwd: *mut libc::passwd,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut libc::passwd,
) -> c_int {
    unsafe {
        let Some(real) = real().getpwnam_r else { return libc::ENOSYS };
        let rc = real(name, pwd, buf, buflen, result);
        if rc == 0 && !(*result).is_null() {
            return rc;
        }
        let Ok(name_str) = CStr::from_ptr(name).to_str() else {
            return rc;
        };
        match nss::lookup_passwd_by_name(name_str) {
            Some(entry) => match nss::fill_passwd(&entry, pwd, buf, buflen) {
                Ok(()) => {
                    *result = pwd;
                    0
                }
                Err(errno) => errno,
            },
            None => {
                *result = std::ptr::null_mut();
                0
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpwuid_r(
    uid: libc::uid_t,
    pwd: *mut libc::passwd,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut libc::passwd,
) -> c_int {
    unsafe {
        let Some(real) = real().getpwuid_r else { return libc::ENOSYS };
        let rc = real(uid, pwd, buf, buflen, result);
        if rc == 0 && !(*result).is_null() {
            return rc;
        }
        match nss::lookup_passwd_by_uid(uid) {
            Some(entry) => match nss::fill_passwd(&entry, pwd, buf, buflen) {
                Ok(()) => {
                    *result = pwd;
                    0
                }
                Err(errno) => errno,
            },
            None => {
                *result = std::ptr::null_mut();
                0
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getgrnam_r(
    name: *const c_char,
    grp: *mut libc::group,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut libc::group,
) -> c_int {
    unsafe {
        let Some(real) = real().getgrnam_r else { return libc::ENOSYS };
        let rc = real(name, grp, buf, buflen, result);
        if rc == 0 && !(*result).is_null() {
            return rc;
        }
        let Ok(name_str) = CStr::from_ptr(name).to_str() else {
            return rc;
        };
        match nss::lookup_group_by_name(name_str) {
            Some(entry) => match nss::fill_group(&entry, grp, buf, buflen) {
                Ok(()) => {
                    *result = grp;
                    0
                }
                Err(errno) => errno,
            },
            None => {
                *result = std::ptr::null_mut();
                0
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getgrgid_r(
    gid: libc::gid_t,
    grp: *mut libc::group,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut libc::group,
) -> c_int {
    unsafe {
        let Some(real) = real().getgrgid_r else { return libc::ENOSYS };
        let rc = real(gid, grp, buf, buflen, result);
        if rc == 0 && !(*result).is_null() {
            return rc;
        }
        match nss::lookup_group_by_gid(gid) {
            Some(entry) => match nss::fill_group(&entry, grp, buf, buflen) {
                Ok(()) => {
                    *result = grp;
                    0
                }
                Err(errno) => errno,
            },
            None => {
                *result = std::ptr::null_mut();
                0
            }
        }
    }
}

// Non-reentrant getpwnam/getpwuid/getgrnam/getgrgid return a pointer into
// a static buffer owned by libc -- matched here with our own thread-local
// static storage, filled via the same _r logic above.
std::thread_local! {
    static PW_BUF: std::cell::RefCell<(libc::passwd, Vec<c_char>)> = std::cell::RefCell::new((
        unsafe { std::mem::zeroed() },
        vec![0; 4096],
    ));
    static GR_BUF: std::cell::RefCell<(libc::group, Vec<c_char>)> = std::cell::RefCell::new((
        unsafe { std::mem::zeroed() },
        vec![0; 4096],
    ));
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpwnam(name: *const c_char) -> *mut libc::passwd {
    unsafe {
        PW_BUF.with(|cell| {
            let mut b = cell.borrow_mut();
            let (pwd, buf) = &mut *b;
            let mut result: *mut libc::passwd = std::ptr::null_mut();
            let rc = getpwnam_r(name, pwd as *mut _, buf.as_mut_ptr(), buf.len(), &mut result);
            if rc == 0 { result } else { std::ptr::null_mut() }
        })
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpwuid(uid: libc::uid_t) -> *mut libc::passwd {
    unsafe {
        PW_BUF.with(|cell| {
            let mut b = cell.borrow_mut();
            let (pwd, buf) = &mut *b;
            let mut result: *mut libc::passwd = std::ptr::null_mut();
            let rc = getpwuid_r(uid, pwd as *mut _, buf.as_mut_ptr(), buf.len(), &mut result);
            if rc == 0 { result } else { std::ptr::null_mut() }
        })
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getgrnam(name: *const c_char) -> *mut libc::group {
    unsafe {
        GR_BUF.with(|cell| {
            let mut b = cell.borrow_mut();
            let (grp, buf) = &mut *b;
            let mut result: *mut libc::group = std::ptr::null_mut();
            let rc = getgrnam_r(name, grp as *mut _, buf.as_mut_ptr(), buf.len(), &mut result);
            if rc == 0 { result } else { std::ptr::null_mut() }
        })
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getgrgid(gid: libc::gid_t) -> *mut libc::group {
    unsafe {
        GR_BUF.with(|cell| {
            let mut b = cell.borrow_mut();
            let (grp, buf) = &mut *b;
            let mut result: *mut libc::group = std::ptr::null_mut();
            let rc = getgrgid_r(gid, grp as *mut _, buf.as_mut_ptr(), buf.len(), &mut result);
            if rc == 0 { result } else { std::ptr::null_mut() }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shebang_split_matches_the_kernel() {
        assert_eq!(parse_shebang(b"#!/bin/sh\necho"), Some((&b"/bin/sh"[..], None)));
        assert_eq!(
            parse_shebang(b"#! /usr/bin/env  python3 \r\nx"),
            Some((&b"/usr/bin/env"[..], Some(&b"python3"[..])))
        );
        assert_eq!(
            parse_shebang(b"#!/bin/sh -e -x\n"),
            Some((&b"/bin/sh"[..], Some(&b"-e -x"[..])))
        );
        assert_eq!(parse_shebang(b"\x7fELF"), None);
        assert_eq!(parse_shebang(b"#!   \n"), None);
    }

    #[test]
    fn lexical_folds_parent_dirs() {
        assert_eq!(
            lexical(Path::new("/overlayer/syshub/var/../bin/ls")),
            Path::new("/overlayer/syshub/bin/ls")
        );
    }
}
