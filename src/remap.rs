//! Dynamic FHS-path resolution against syshub / MUSL_SYSDIR / zexlib-union.

use std::path::{Component, Path, PathBuf};

/// Alternate system root for dev/test; production default is `/`.
pub const ZAIROOT_ENV: &str = "ZAINIUM_ZAIROOT";

/// Top-level prefixes this resolver ever touches; `/home` and `/tmp` are real, already-present, and excluded on purpose.
const SCOPE_GUARD: &[&str] = &["bin", "sbin", "lib", "usr", "opt", "var", "etc", "boot"];

/// The four real base roots, probed in this order.
#[derive(Debug, Clone)]
pub struct Roots {
    pub syshub: PathBuf,
    pub musl_sysdir: PathBuf,
    pub union: PathBuf,
    pub zaisys: PathBuf,
}

impl Roots {
    pub fn under(sysroot: &Path) -> Self {
        let overlayer = sysroot.join("overlayer");
        Roots {
            syshub: overlayer.join("syshub"),
            musl_sysdir: overlayer.join("syshub/x86_64-zainium-linux-musl"),
            union: overlayer.join("zexlib/union"),
            zaisys: overlayer.join("zaisys"),
        }
    }

    pub fn from_env() -> Self {
        Self::under(&system_root())
    }

    fn probe_order(&self) -> [&Path; 4] {
        [&self.syshub, &self.musl_sysdir, &self.union, &self.zaisys]
    }
}

pub fn system_root() -> PathBuf {
    match std::env::var_os(ZAIROOT_ENV) {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => PathBuf::from("/"),
    }
}

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

/// `/usr/bin/foo` -> `bin/foo`, `/lib64/x` -> `lib/x`, `/bin/foo` unchanged.
/// `/lib/modules` -> `drivers/modules`, `/lib/firmware` -> `drivers/hardware/firmwares`, `/boot` -> `kernel` (all real locations on this OS, not under `lib/`/root).
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
    let s = if let Some(rest) = s.strip_prefix("lib/modules/") {
        format!("drivers/modules/{rest}")
    } else if s == "lib/modules" {
        "drivers/modules".to_string()
    } else if let Some(rest) = s.strip_prefix("lib/firmware/") {
        format!("drivers/hardware/firmwares/{rest}")
    } else if s == "lib/firmware" {
        "drivers/hardware/firmwares".to_string()
    } else if let Some(rest) = s.strip_prefix("boot/") {
        format!("kernel/{rest}")
    } else if s == "boot" {
        "kernel".to_string()
    } else {
        s
    };
    if s.is_empty() {
        None
    } else {
        Some(PathBuf::from(s))
    }
}

/// Ordered candidate paths, no existence check — pure string construction.
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

/// Resolve a legacy FHS-shaped path to where it really lives, if anywhere.
pub fn resolve(path: &Path, roots: &Roots) -> Option<PathBuf> {
    candidates(path, roots).into_iter().find(|c| c.exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live_roots() -> Roots {
        Roots::under(Path::new("/run/media/alizain/ZAINIUM_DRIVE/zairoot"))
    }

    #[test]
    fn resolves_env_under_syshub_bin() {
        let got = resolve(Path::new("/usr/bin/env"), &live_roots()).unwrap();
        assert_eq!(
            got,
            Path::new("/run/media/alizain/ZAINIUM_DRIVE/zairoot/overlayer/syshub/bin/env")
        );
    }

    #[test]
    fn resolves_bare_bin_path_without_usr_prefix() {
        let got = resolve(Path::new("/bin/env"), &live_roots()).unwrap();
        assert_eq!(
            got,
            Path::new("/run/media/alizain/ZAINIUM_DRIVE/zairoot/overlayer/syshub/bin/env")
        );
    }

    #[test]
    fn resolves_header_that_only_exists_under_zexlib_union() {
        let got = resolve(Path::new("/usr/include/dav1d/dav1d.h"), &live_roots()).unwrap();
        assert_eq!(
            got,
            Path::new("/run/media/alizain/ZAINIUM_DRIVE/zairoot/overlayer/zexlib/union/include/dav1d/dav1d.h")
        );
    }

    #[test]
    fn scope_guard_refuses_unrelated_prefixes() {
        let roots = live_roots();
        for p in ["/home/alizain/whatever", "/proc/self", "/tmp/x", "/root/x"] {
            assert_eq!(resolve(Path::new(p), &roots), None, "should refuse {p}");
        }
    }

    #[test]
    fn resolves_var_and_etc_under_syshub() {
        let roots = live_roots();
        assert_eq!(resolve(Path::new("/var"), &roots), Some(roots.syshub.join("var")));
        assert_eq!(
            resolve(Path::new("/etc/passwd"), &roots),
            Some(roots.syshub.join("etc/passwd"))
        );
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
        let roots = live_roots();
        let got = candidates(Path::new("/usr/bin/definitely-not-real"), &roots);
        assert_eq!(
            got,
            vec![
                roots.syshub.join("bin/definitely-not-real"),
                roots.musl_sysdir.join("bin/definitely-not-real"),
                roots.union.join("bin/definitely-not-real"),
                roots.zaisys.join("bin/definitely-not-real"),
            ]
        );
    }

    #[test]
    fn strip_legacy_maps_modules_firmware_and_boot() {
        assert_eq!(
            strip_legacy(Path::new("/lib/modules/6.1.0/foo.ko")),
            Some(PathBuf::from("drivers/modules/6.1.0/foo.ko"))
        );
        assert_eq!(
            strip_legacy(Path::new("/lib/firmware/some-device.bin")),
            Some(PathBuf::from("drivers/hardware/firmwares/some-device.bin"))
        );
        assert_eq!(
            strip_legacy(Path::new("/boot/some-kernel-image")),
            Some(PathBuf::from("kernel/some-kernel-image"))
        );
    }

    #[test]
    fn resolves_real_firmware_dir_under_drivers() {
        let roots = live_roots();
        let got = resolve(Path::new("/lib/firmware"), &roots).unwrap();
        assert_eq!(got, roots.syshub.join("drivers/hardware/firmwares"));
    }

    #[test]
    fn resolves_boot_dir_under_zaisys_kernel() {
        let roots = live_roots();
        let got = resolve(Path::new("/boot"), &roots).unwrap();
        assert_eq!(got, roots.zaisys.join("kernel"));
    }

    #[test]
    fn strip_legacy_leaves_non_usr_subdirs_alone() {
        assert_eq!(
            strip_legacy(Path::new("/usr/libexec/foo")),
            Some(PathBuf::from("libexec/foo"))
        );
    }
}
