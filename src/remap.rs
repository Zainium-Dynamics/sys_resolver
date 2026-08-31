//! Dynamic FHS-path resolution — sys_resolver's own logic, independent of
//! `zex` (no crate dependency on it; see the plan for why).
//!
//! Zainium OS has no FHS (`ZAI_NO_FHS=1`): there is no real `/usr`, `/bin`,
//! `/sbin`, `/lib` on this system. Real files live under three roots:
//!
//!   - `<sysroot>/overlayer/syshub`                              (base OS)
//!   - `<sysroot>/overlayer/syshub/x86_64-zainium-linux-musl`    (musl sysroot)
//!   - `<sysroot>/overlayer/zexlib/union`                        (zex userland)
//!
//! `resolve()` takes a legacy FHS-shaped absolute path that failed to open
//! and finds where it *really* lives, live against the real filesystem —
//! no hardcoded per-category table, no snapshot of "what packages exist".
//! It only ever reports paths that actually exist; it never invents one.
//!
//! `zex` itself is never affected by any of this: `zex` writes files
//! straight to their real `/overlayer/...` location when it installs a
//! package, so its own reads/writes never hit the `ENOENT` fallback this
//! module exists for. This module exists purely for processes that don't
//! know Zainium has no FHS in the first place (a plain `./configure &&
//! make`, a script with an unmodified `#!/usr/bin/env python3`, a random
//! downloaded binary expecting `/lib` or `/opt`).

use std::path::{Component, Path, PathBuf};

/// Env var used to point every root at an alternate system root — the real
/// system root in production is `/` (this OS *is* `/overlayer/...`), but
/// during development/testing (this tool isn't running on ZainiumOS
/// itself) it points at the real, live `zairoot` tree instead. Same
/// convention `carve` already uses for `ZAINIUM_ZAIROOT`.
pub const ZAIROOT_ENV: &str = "ZAINIUM_ZAIROOT";

/// Legacy FHS top-level prefixes this resolver is allowed to even look at.
/// Not a destination table — it never says *where* something lives, only
/// which prefixes are in scope, so an unrelated missing path (`/home/...`,
/// `/etc/...`, `/proc/...`, ...) is left alone and fails exactly as it
/// does today instead of being silently redirected by coincidence.
const SCOPE_GUARD: &[&str] = &["bin", "sbin", "lib", "usr", "opt"];

/// The three real base roots, in the same priority order
/// `/etc/profile`'s `PATH`/`LD_LIBRARY_PATH` already use.
#[derive(Debug, Clone)]
pub struct Roots {
    pub syshub: PathBuf,
    pub musl_sysdir: PathBuf,
    pub union: PathBuf,
}

impl Roots {
    /// Build the three roots under a given system root.
    pub fn under(sysroot: &Path) -> Self {
        let overlayer = sysroot.join("overlayer");
        Roots {
            syshub: overlayer.join("syshub"),
            musl_sysdir: overlayer.join("syshub/x86_64-zainium-linux-musl"),
            union: overlayer.join("zexlib/union"),
        }
    }

    /// Roots as read from `ZAINIUM_ZAIROOT`, falling back to the real `/`.
    pub fn from_env() -> Self {
        Self::under(&system_root())
    }

    fn probe_order(&self) -> [&Path; 3] {
        [&self.syshub, &self.musl_sysdir, &self.union]
    }
}

/// The system root: `ZAINIUM_ZAIROOT` if set and non-empty, else `/`.
pub fn system_root() -> PathBuf {
    match std::env::var_os(ZAIROOT_ENV) {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => PathBuf::from("/"),
    }
}

/// Does `path` start with one of the [`SCOPE_GUARD`] prefixes?
pub fn in_scope(path: &Path) -> bool {
    let mut comps = path.components();
    if !matches!(comps.next(), Some(Component::RootDir)) {
        return false;
    }
    match comps.next() {
        Some(Component::Normal(first)) => {
            SCOPE_GUARD.contains(&first.to_string_lossy().as_ref())
        }
        _ => false,
    }
}

/// Strip the standard legacy segments down to a root-relative remainder.
///
/// `/usr/bin/foo` -> `bin/foo`, `/usr/local/lib/x` -> `lib/x`,
/// `/lib64/foo` -> `lib/foo`, `/bin/foo` -> `bin/foo` (already
/// root-relative, left as-is), `/usr/libexec/foo` -> `libexec/foo` (no
/// `libexec`-specific rule needed — it just falls out of the `usr/` strip).
pub fn strip_legacy(path: &Path) -> Option<PathBuf> {
    let s = path.to_str()?.strip_prefix('/')?;
    let s = s
        .strip_prefix("usr/local/")
        .or_else(|| s.strip_prefix("usr/"))
        .unwrap_or(s);
    let s = match s.strip_prefix("lib64/") {
        Some(rest) => format!("lib/{rest}"),
        None if s == "lib64" => "lib".to_string(),
        None => s.to_string(),
    };
    if s.is_empty() {
        None
    } else {
        Some(PathBuf::from(s))
    }
}

/// The ordered candidate paths for `path` — no existence check, no I/O at
/// all. Pure string/path construction only.
///
/// This is deliberately the boundary a C caller (a patched `open`/`access`/
/// `stat`-family/`execve` in musl, and later glibc) calls into: the caller
/// already knows how to make raw syscalls without depending on anything
/// else, so it keeps doing the actual existence check/open itself, trying
/// each returned candidate in order until one succeeds. Keeping this side
/// I/O-free avoids any circular dependency on the libc that ends up
/// calling it, and means the *exact same compiled logic* backs both the
/// Rust CLI/tests here and every C call site — never reimplemented twice.
pub fn candidates(path: &Path, roots: &Roots) -> Vec<PathBuf> {
    if !path.is_absolute() || !in_scope(path) {
        return Vec::new();
    }
    let Some(remainder) = strip_legacy(path) else {
        return Vec::new();
    };
    roots
        .probe_order()
        .into_iter()
        .map(|root| root.join(&remainder))
        .collect()
}

/// Resolve a legacy FHS-shaped absolute path to where it really lives on
/// this ZainiumOS system, if anywhere.
///
/// Read-only: only ever checks whether real files exist, never creates,
/// moves, or modifies anything, and never invents a path that isn't real.
pub fn resolve(path: &Path, roots: &Roots) -> Option<PathBuf> {
    candidates(path, roots).into_iter().find(|c| c.exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Roots pointed at the real, live zairoot tree on this drive — no
    /// mocking, these are real on-disk paths.
    fn live_roots() -> Roots {
        Roots::under(Path::new("/run/media/alizain/ZAINIUM_DRIVE/zairoot"))
    }

    #[test]
    fn resolves_env_under_syshub_bin() {
        let got = resolve(Path::new("/usr/bin/env"), &live_roots()).unwrap();
        assert_eq!(
            got,
            Path::new(
                "/run/media/alizain/ZAINIUM_DRIVE/zairoot/overlayer/syshub/bin/env"
            )
        );
    }

    #[test]
    fn resolves_bare_bin_path_without_usr_prefix() {
        // `/bin/env` (no `/usr` prefix at all) must resolve identically.
        let got = resolve(Path::new("/bin/env"), &live_roots()).unwrap();
        assert_eq!(
            got,
            Path::new(
                "/run/media/alizain/ZAINIUM_DRIVE/zairoot/overlayer/syshub/bin/env"
            )
        );
    }

    #[test]
    fn resolves_header_that_only_exists_under_zexlib_union() {
        // Proves the *dynamic* discovery case: dav1d's headers live only
        // under zexlib/union/include — no static per-category table would
        // have had to special-case this package, and none is needed here
        // either, since this is a live filesystem check, not a lookup
        // against a fixed list.
        let got = resolve(
            Path::new("/usr/include/dav1d/dav1d.h"),
            &live_roots(),
        )
        .unwrap();
        assert_eq!(
            got,
            Path::new(
                "/run/media/alizain/ZAINIUM_DRIVE/zairoot/overlayer/zexlib/union/include/dav1d/dav1d.h"
            )
        );
    }

    #[test]
    fn scope_guard_refuses_unrelated_prefixes() {
        let roots = live_roots();
        for p in ["/home/alizain/whatever", "/etc/passwd", "/proc/self", "/tmp/x", "/root/x"] {
            assert_eq!(resolve(Path::new(p), &roots), None, "should refuse {p}");
        }
    }

    #[test]
    fn never_invents_a_path_that_does_not_exist() {
        let got = resolve(
            Path::new("/usr/bin/this-binary-does-not-exist-anywhere"),
            &live_roots(),
        );
        assert_eq!(got, None);
    }

    #[test]
    fn strip_legacy_folds_lib64_into_lib() {
        assert_eq!(
            strip_legacy(Path::new("/lib64/ld-linux-x86-64.so.2")),
            Some(PathBuf::from("lib/ld-linux-x86-64.so.2"))
        );
        assert_eq!(
            strip_legacy(Path::new("/usr/lib64/foo.so")),
            Some(PathBuf::from("lib/foo.so"))
        );
    }

    #[test]
    fn candidates_are_pure_and_ordered_no_io() {
        // Pure string construction — must return the 3 ordered candidates
        // even for a path that doesn't exist anywhere, since it does no
        // existence checking at all (that's the caller's job in the FFI
        // boundary this function exists for).
        let roots = live_roots();
        let got = candidates(Path::new("/usr/bin/definitely-not-real"), &roots);
        assert_eq!(
            got,
            vec![
                roots.syshub.join("bin/definitely-not-real"),
                roots.musl_sysdir.join("bin/definitely-not-real"),
                roots.union.join("bin/definitely-not-real"),
            ]
        );
    }

    #[test]
    fn strip_legacy_leaves_non_usr_subdirs_alone() {
        // /usr/libexec/foo -> libexec/foo, no special-casing required.
        assert_eq!(
            strip_legacy(Path::new("/usr/libexec/foo")),
            Some(PathBuf::from("libexec/foo"))
        );
    }
}
