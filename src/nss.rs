//! Fallback `getpwnam`/`getpwuid`/`getgrnam`/`getgrgid` (+ `_r` variants)
//! implementations, parsing Zainium's real passwd/group files directly.
//!
//! Why this exists: unlike `open`/`fopen`/etc., which this crate
//! successfully intercepts for callers *outside* libc, musl's own
//! `getpwnam()`/`getgrnam()` open `/overlayer/syshub/etc/passwd` (or, on
//! an older unpatched musl build, the bare `/etc/passwd`) via an internal,
//! non-interposable call chain -- musl compiles calls between its own
//! functions directly, bypassing the PLT/GOT that LD_PRELOAD relies on
//! (same reason this crate's own `execve` doc comment already notes
//! musl's `exec*` internals aren't interposable either). So even with
//! `fopen` successfully hooked, musl's *internal* fopen-from-getpwnam call
//! never reaches this crate's override.
//!
//! The fix: export `getpwnam`/`getpwnam_r`/etc. themselves. A caller's
//! call to the public `getpwnam` symbol *does* go through normal dynamic
//! symbol resolution (this isn't an internal-to-libc call), so it reaches
//! this crate's version first, same as `open`/`fopen`/etc. already do.

use crate::remap::Roots;
use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::OnceLock;

fn roots() -> &'static Roots {
    static ROOTS: OnceLock<Roots> = OnceLock::new();
    ROOTS.get_or_init(Roots::from_env)
}

pub struct PwEntry {
    pub name: String,
    pub passwd: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub dir: String,
    pub shell: String,
}

pub struct GrEntry {
    pub name: String,
    pub passwd: String,
    pub gid: u32,
    pub members: Vec<String>,
}

fn read_file(rel: &str) -> Option<String> {
    std::fs::read_to_string(roots().syshub.join(rel)).ok()
}

pub fn lookup_passwd_by_name(name: &str) -> Option<PwEntry> {
    parse_passwd(&read_file("etc/passwd")?).into_iter().find(|e| e.name == name)
}

pub fn lookup_passwd_by_uid(uid: u32) -> Option<PwEntry> {
    parse_passwd(&read_file("etc/passwd")?).into_iter().find(|e| e.uid == uid)
}

pub fn lookup_group_by_name(name: &str) -> Option<GrEntry> {
    parse_group(&read_file("etc/group")?).into_iter().find(|e| e.name == name)
}

pub fn lookup_group_by_gid(gid: u32) -> Option<GrEntry> {
    parse_group(&read_file("etc/group")?).into_iter().find(|e| e.gid == gid)
}

fn parse_passwd(text: &str) -> Vec<PwEntry> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.splitn(7, ':').collect();
            if f.len() < 7 {
                return None;
            }
            Some(PwEntry {
                name: f[0].to_string(),
                passwd: f[1].to_string(),
                uid: f[2].parse().ok()?,
                gid: f[3].parse().ok()?,
                gecos: f[4].to_string(),
                dir: f[5].to_string(),
                shell: f[6].to_string(),
            })
        })
        .collect()
}

fn parse_group(text: &str) -> Vec<GrEntry> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.splitn(4, ':').collect();
            if f.len() < 4 {
                return None;
            }
            Some(GrEntry {
                name: f[0].to_string(),
                passwd: f[1].to_string(),
                gid: f[2].parse().ok()?,
                members: f[3].split(',').filter(|s| !s.is_empty()).map(str::to_string).collect(),
            })
        })
        .collect()
}

/// Write `entry` into `*pwd`, with string fields carved out of `buf`.
/// Returns `Err(libc::ERANGE)` if `buf` is too small, matching the real
/// `getpwnam_r` contract.
///
/// # Safety
/// `pwd` and `buf` must be valid for writes of `size_of::<libc::passwd>()`
/// and `buflen` bytes respectively.
pub unsafe fn fill_passwd(
    entry: &PwEntry,
    pwd: *mut libc::passwd,
    buf: *mut c_char,
    buflen: usize,
) -> Result<(), i32> {
    unsafe {
        let strs = [
            &entry.name,
            &entry.passwd,
            &entry.gecos,
            &entry.dir,
            &entry.shell,
        ];
        let cstrs: Vec<CString> = strs
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap_or_default())
            .collect();
        let needed: usize = cstrs.iter().map(|c| c.as_bytes_with_nul().len()).sum();
        if needed > buflen {
            return Err(libc::ERANGE);
        }
        let mut off = 0usize;
        let mut ptrs = [std::ptr::null_mut::<c_char>(); 5];
        for (i, c) in cstrs.iter().enumerate() {
            let bytes = c.as_bytes_with_nul();
            std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, buf.add(off), bytes.len());
            ptrs[i] = buf.add(off);
            off += bytes.len();
        }
        (*pwd).pw_name = ptrs[0];
        (*pwd).pw_passwd = ptrs[1];
        (*pwd).pw_uid = entry.uid;
        (*pwd).pw_gid = entry.gid;
        (*pwd).pw_gecos = ptrs[2];
        (*pwd).pw_dir = ptrs[3];
        (*pwd).pw_shell = ptrs[4];
        Ok(())
    }
}

/// Write `entry` into `*grp`, with string fields (name, passwd, and the
/// NULL-terminated `gr_mem` array) carved out of `buf`.
///
/// # Safety
/// `grp` and `buf` must be valid for writes of `size_of::<libc::group>()`
/// and `buflen` bytes respectively.
pub unsafe fn fill_group(
    entry: &GrEntry,
    grp: *mut libc::group,
    buf: *mut c_char,
    buflen: usize,
) -> Result<(), i32> {
    unsafe {
        let name_c = CString::new(entry.name.as_str()).unwrap_or_default();
        let passwd_c = CString::new(entry.passwd.as_str()).unwrap_or_default();
        let member_cs: Vec<CString> = entry
            .members
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap_or_default())
            .collect();

        let strings_len: usize = name_c.as_bytes_with_nul().len()
            + passwd_c.as_bytes_with_nul().len()
            + member_cs.iter().map(|c| c.as_bytes_with_nul().len()).sum::<usize>();
        // gr_mem pointer array (including the NULL terminator), pointer-aligned.
        let ptr_array_len = (member_cs.len() + 1) * std::mem::size_of::<*mut c_char>();
        let align = std::mem::align_of::<*mut c_char>();
        let aligned_strings_len = strings_len.div_ceil(align) * align;
        let needed = aligned_strings_len + ptr_array_len;
        if needed > buflen {
            return Err(libc::ERANGE);
        }

        let mut off = 0usize;
        let mut write_str = |c: &CString| -> *mut c_char {
            let bytes = c.as_bytes_with_nul();
            let p = buf.add(off);
            std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, p, bytes.len());
            off += bytes.len();
            p
        };
        let name_ptr = write_str(&name_c);
        let passwd_ptr = write_str(&passwd_c);
        let member_ptrs: Vec<*mut c_char> = member_cs.iter().map(&mut write_str).collect();

        let array_base = buf.add(aligned_strings_len) as *mut *mut c_char;
        for (i, p) in member_ptrs.iter().enumerate() {
            *array_base.add(i) = *p;
        }
        *array_base.add(member_ptrs.len()) = std::ptr::null_mut();

        (*grp).gr_name = name_ptr;
        (*grp).gr_passwd = passwd_ptr;
        (*grp).gr_gid = entry.gid;
        (*grp).gr_mem = array_base;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    fn set_fixture_root() {
        unsafe {
            std::env::set_var(
                crate::remap::ZAIROOT_ENV,
                "/run/media/alizain/ZAINIUM_DRIVE/zairoot",
            );
        }
    }

    #[test]
    fn parses_real_fixture_passwd_and_group() {
        set_fixture_root();
        let root = lookup_passwd_by_name("root").expect("root must exist in fixture");
        assert_eq!(root.uid, 0);
        assert_eq!(root.gid, 0);
        assert_eq!(root.shell, "/bin/sh");

        let by_uid = lookup_passwd_by_uid(0).expect("uid 0 must resolve");
        assert_eq!(by_uid.name, "root");

        assert!(lookup_passwd_by_name("no-such-user-here").is_none());

        let wheel = lookup_group_by_name("wheel").expect("wheel must exist in fixture");
        assert_eq!(wheel.gid, 10);
        assert_eq!(wheel.members, vec!["root".to_string()]);

        let by_gid = lookup_group_by_gid(10).expect("gid 10 must resolve");
        assert_eq!(by_gid.name, "wheel");
    }

    #[test]
    fn fill_passwd_round_trips_through_the_c_struct() {
        let entry = PwEntry {
            name: "cosmic-greeter".to_string(),
            passwd: "x".to_string(),
            uid: 199,
            gid: 199,
            gecos: "Cosmic Greeter Account".to_string(),
            dir: "/overlayer/syshub/var/lib/cosmic-greeter".to_string(),
            shell: "/overlayer/syshub/bin/nologin".to_string(),
        };
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0 as c_char; 4096];
        unsafe { fill_passwd(&entry, &mut pwd, buf.as_mut_ptr(), buf.len()) }
            .expect("buffer is large enough");

        assert_eq!(pwd.pw_uid, 199);
        assert_eq!(pwd.pw_gid, 199);
        unsafe {
            assert_eq!(CStr::from_ptr(pwd.pw_name).to_str().unwrap(), "cosmic-greeter");
            assert_eq!(
                CStr::from_ptr(pwd.pw_dir).to_str().unwrap(),
                "/overlayer/syshub/var/lib/cosmic-greeter"
            );
            assert_eq!(
                CStr::from_ptr(pwd.pw_shell).to_str().unwrap(),
                "/overlayer/syshub/bin/nologin"
            );
        }
    }

    #[test]
    fn fill_passwd_reports_erange_instead_of_overflowing() {
        let entry = PwEntry {
            name: "someone-with-a-long-enough-name".to_string(),
            passwd: "x".to_string(),
            uid: 1,
            gid: 1,
            gecos: String::new(),
            dir: "/home/someone".to_string(),
            shell: "/bin/sh".to_string(),
        };
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0 as c_char; 4];
        let err = unsafe { fill_passwd(&entry, &mut pwd, buf.as_mut_ptr(), buf.len()) }
            .expect_err("4 bytes can't fit these strings");
        assert_eq!(err, libc::ERANGE);
    }

    #[test]
    fn fill_group_round_trips_members_and_null_terminates() {
        let entry = GrEntry {
            name: "wheel".to_string(),
            passwd: "x".to_string(),
            gid: 10,
            members: vec!["root".to_string(), "zainium".to_string()],
        };
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0 as c_char; 4096];
        unsafe { fill_group(&entry, &mut grp, buf.as_mut_ptr(), buf.len()) }
            .expect("buffer is large enough");

        assert_eq!(grp.gr_gid, 10);
        unsafe {
            assert_eq!(CStr::from_ptr(grp.gr_name).to_str().unwrap(), "wheel");
            let m0 = CStr::from_ptr(*grp.gr_mem).to_str().unwrap();
            let m1 = CStr::from_ptr(*grp.gr_mem.add(1)).to_str().unwrap();
            assert_eq!(m0, "root");
            assert_eq!(m1, "zainium");
            assert!((*grp.gr_mem.add(2)).is_null(), "gr_mem must be NULL-terminated");
        }
    }

    #[test]
    fn fill_group_reports_erange_instead_of_overflowing() {
        let entry = GrEntry {
            name: "wheel".to_string(),
            passwd: "x".to_string(),
            gid: 10,
            members: vec!["root".to_string(), "zainium".to_string()],
        };
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0 as c_char; 4];
        let err = unsafe { fill_group(&entry, &mut grp, buf.as_mut_ptr(), buf.len()) }
            .expect_err("4 bytes can't fit name + passwd + 2 members + NULL");
        assert_eq!(err, libc::ERANGE);
    }
}
