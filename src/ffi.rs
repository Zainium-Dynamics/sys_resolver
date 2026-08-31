//! C ABI surface — what a patched libc actually links against and calls.
//!
//! This is the answer to "if we patch musl, do we have to redo the same
//! work in glibc?" — no: the resolution algorithm lives exactly once, as
//! compiled Rust, right here. A libc's patch (musl today, glibc later,
//! for third-party prebuilt glibc-linked binaries) becomes a tiny call
//! site — a few lines in `open`/`access`/`stat`-family/`execve` — not a
//! second implementation of the algorithm.
//!
//! Deliberately I/O-free: [`sys_resolver_candidates`] only computes
//! candidate path *strings*. It never calls `open()`/`stat()` itself — the
//! calling libc already knows how to make raw syscalls without depending
//! on anything else, so it keeps doing the actual existence check/open
//! itself, trying each returned candidate in order until one succeeds.
//! Keeping this side of the boundary free of any filesystem I/O (and, in
//! particular, free of any dependency on the libc that ends up calling
//! it) avoids a circular dependency between this library and the libc
//! being patched.
//!
//! C-side declaration (for whoever writes the musl/glibc call site):
//!
//! ```c
//! /* Returns the number of candidates written (0 if `path` is out of
//!  * scope or malformed — nothing to try), or -1 if `out_buf` was too
//!  * small (nothing is written in that case; caller should retry with a
//!  * bigger buffer). On success, `out_buf` holds that many NUL-terminated
//!  * strings back to back (an `argv`/`environ`-style multi-string). */
//! int sys_resolver_candidates(const char *path,
//!                              char *out_buf, size_t out_buf_len);
//! ```

use crate::remap::{candidates, Roots};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::Path;

/// See the module-level C declaration above for the contract.
///
/// # Safety
/// `path` must be a valid, NUL-terminated C string. `out_buf` must be
/// valid for `out_buf_len` writable bytes (or `out_buf_len == 0`, in which
/// case `out_buf` is never dereferenced).
#[no_mangle]
pub unsafe extern "C" fn sys_resolver_candidates(
    path: *const c_char,
    out_buf: *mut c_char,
    out_buf_len: usize,
) -> i32 {
    if path.is_null() {
        return 0;
    }
    let Ok(path_str) = CStr::from_ptr(path).to_str() else {
        return 0;
    };

    let roots = Roots::from_env();
    let cands = candidates(Path::new(path_str), &roots);
    if cands.is_empty() {
        return 0;
    }

    let mut blob = Vec::new();
    for c in &cands {
        let Some(s) = c.to_str() else { continue };
        blob.extend_from_slice(s.as_bytes());
        blob.push(0);
    }
    if blob.is_empty() {
        return 0;
    }
    if blob.len() > out_buf_len || out_buf.is_null() {
        return -1;
    }
    std::ptr::copy_nonoverlapping(blob.as_ptr(), out_buf as *mut u8, blob.len());
    cands.len() as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn ffi_round_trip_matches_the_pure_rust_candidates() {
        std::env::set_var(
            crate::remap::ZAIROOT_ENV,
            "/run/media/alizain/ZAINIUM_DRIVE/zairoot",
        );

        let path = CString::new("/usr/bin/env").unwrap();
        let mut buf = vec![0u8; 4096];
        let n = unsafe {
            sys_resolver_candidates(
                path.as_ptr(),
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
            )
        };
        assert_eq!(n, 3, "expected 3 ordered candidates for /usr/bin/env");

        // Parse the NUL-separated blob back out and compare against the
        // pure Rust candidates() for the same path/roots.
        let roots = Roots::from_env();
        let expected = candidates(Path::new("/usr/bin/env"), &roots);

        let mut got = Vec::new();
        let mut rest = &buf[..];
        for _ in 0..n {
            let end = rest.iter().position(|&b| b == 0).unwrap();
            got.push(String::from_utf8(rest[..end].to_vec()).unwrap());
            rest = &rest[end + 1..];
        }
        let expected_strs: Vec<String> =
            expected.iter().map(|p| p.to_string_lossy().into_owned()).collect();
        assert_eq!(got, expected_strs);

        // The first candidate is the real one that actually exists.
        assert!(Path::new(&got[0]).exists());
    }

    #[test]
    fn ffi_reports_buffer_too_small_instead_of_writing_garbage() {
        std::env::set_var(
            crate::remap::ZAIROOT_ENV,
            "/run/media/alizain/ZAINIUM_DRIVE/zairoot",
        );
        let path = CString::new("/usr/bin/env").unwrap();
        let mut buf = vec![0u8; 1]; // far too small
        let n = unsafe {
            sys_resolver_candidates(path.as_ptr(), buf.as_mut_ptr() as *mut c_char, buf.len())
        };
        assert_eq!(n, -1);
    }

    #[test]
    fn ffi_returns_zero_for_out_of_scope_path() {
        std::env::set_var(
            crate::remap::ZAIROOT_ENV,
            "/run/media/alizain/ZAINIUM_DRIVE/zairoot",
        );
        let path = CString::new("/home/alizain/whatever").unwrap();
        let mut buf = vec![0u8; 4096];
        let n = unsafe {
            sys_resolver_candidates(path.as_ptr(), buf.as_mut_ptr() as *mut c_char, buf.len())
        };
        assert_eq!(n, 0);
    }
}
