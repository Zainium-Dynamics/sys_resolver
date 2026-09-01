//! C ABI: `int sys_resolver_candidates(const char *path, char *out_buf, size_t out_buf_len)` — returns candidate count (0 = out of scope, -1 = buffer too small), never touches the filesystem itself.

use crate::remap::{candidates, Roots};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::Path;

/// # Safety: `path` must be NUL-terminated; `out_buf` valid for `out_buf_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sys_resolver_candidates(
    path: *const c_char,
    out_buf: *mut c_char,
    out_buf_len: usize,
) -> i32 { unsafe {
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
}}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn ffi_round_trip_matches_the_pure_rust_candidates() {
        unsafe {
            std::env::set_var(crate::remap::ZAIROOT_ENV, "/run/media/alizain/ZAINIUM_DRIVE/zairoot");
        }

        let path = CString::new("/usr/bin/env").unwrap();
        let mut buf = vec![0u8; 4096];
        let n = unsafe {
            sys_resolver_candidates(path.as_ptr(), buf.as_mut_ptr() as *mut c_char, buf.len())
        };
        assert_eq!(n, 4, "expected 4 ordered candidates for /usr/bin/env");

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
        assert!(Path::new(&got[0]).exists());
    }

    #[test]
    fn ffi_reports_buffer_too_small_instead_of_writing_garbage() {
        unsafe {
            std::env::set_var(crate::remap::ZAIROOT_ENV, "/run/media/alizain/ZAINIUM_DRIVE/zairoot");
        }
        let path = CString::new("/usr/bin/env").unwrap();
        let mut buf = vec![0u8; 1];
        let n = unsafe {
            sys_resolver_candidates(path.as_ptr(), buf.as_mut_ptr() as *mut c_char, buf.len())
        };
        assert_eq!(n, -1);
    }

    #[test]
    fn ffi_returns_zero_for_out_of_scope_path() {
        unsafe {
            std::env::set_var(crate::remap::ZAIROOT_ENV, "/run/media/alizain/ZAINIUM_DRIVE/zairoot");
        }
        let path = CString::new("/home/alizain/whatever").unwrap();
        let mut buf = vec![0u8; 4096];
        let n = unsafe {
            sys_resolver_candidates(path.as_ptr(), buf.as_mut_ptr() as *mut c_char, buf.len())
        };
        assert_eq!(n, 0);
    }
}
