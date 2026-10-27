//! Which libc programs are built for: musl (the base, the default) or glibc (the
//! `glibc-toolchain` package, in its own directory). `sys-resolver set` picks the system's
//! default, `ZAINIUM_LIBC` overrides it for one environment. Only building changes: every
//! program keeps running with the libc it was linked against.

use crate::remap::Roots;
use std::path::PathBuf;

pub const GNU: &str = "x86_64-zainium-linux-gnu";
pub const MUSL: &str = "x86_64-zainium-linux-musl";

/// The variable that overrides the system's setting (`musl` or `glibc`).
pub const ENV: &str = "ZAINIUM_LIBC";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Libc {
    Musl,
    Glibc,
}

impl Libc {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "musl" => Some(Self::Musl),
            "glibc" | "gnu" => Some(Self::Glibc),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Musl => "musl",
            Self::Glibc => "glibc",
        }
    }
}

/// The file `sys-resolver set` writes.
pub fn setting_path(r: &Roots) -> PathBuf {
    r.syshub.join("etc/sys-resolver/toolchain")
}

/// glibc's own directory: loader, libraries, headers.
pub fn glibc_dir(r: &Roots) -> PathBuf {
    r.union.join(GNU)
}

pub fn glibc_toolchain_installed(r: &Roots) -> bool {
    r.union.join(format!("bin/{GNU}-gcc")).exists()
}

/// The system's setting; musl when none was made.
pub fn system_setting(r: &Roots) -> Libc {
    std::fs::read_to_string(setting_path(r))
        .ok()
        .and_then(|s| Libc::parse(&s))
        .unwrap_or(Libc::Musl)
}

/// The glibc driver that stands in for one of the base's compiler drivers.
pub fn gnu_driver(name: &[u8]) -> Option<&'static str> {
    match name {
        b"gcc" | b"cc" => Some("gcc"),
        b"g++" | b"c++" => Some("g++"),
        b"cpp" => Some("cpp"),
        _ => None,
    }
}

/// glibc's `.pc` directories: with glibc picked, pkg-config sees only libraries built for it.
pub fn glibc_pkg_config_libdir(r: &Roots) -> String {
    let g = glibc_dir(r);
    format!("{}/lib/pkgconfig:{}/share/pkgconfig", g.display(), g.display())
}

fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Shell lines that make a build use `libc`'s toolchain: `eval "$(sys-resolver env glibc)"`.
/// The musl compilers are named by their full name, so a system set to glibc never turns
/// them into glibc's.
pub fn env(r: &Roots, libc: Libc) -> String {
    let mut out = Vec::new();
    let mut export = |k: &str, v: &str| out.push(format!("export {k}={}", quote(v)));
    match libc {
        Libc::Glibc => {
            export(ENV, "glibc");
            export("CHOST", GNU);
            export("CC", &format!("{GNU}-gcc"));
            export("CXX", &format!("{GNU}-g++"));
            export("CPP", &format!("{GNU}-gcc -E"));
            export("PKG_CONFIG_LIBDIR", &glibc_pkg_config_libdir(r));
            export("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER", &format!("{GNU}-gcc"));
            out.push("unset PKG_CONFIG_PATH".into());
            // the musl loader and library path in LDFLAGS are for musl programs
            out.push("unset LDFLAGS".into());
        }
        Libc::Musl => {
            export(ENV, "musl");
            export("CHOST", MUSL);
            export("CC", &format!("{MUSL}-gcc"));
            export("CXX", &format!("{MUSL}-g++"));
            export("CPP", &format!("{MUSL}-gcc -E"));
            out.push("unset PKG_CONFIG_LIBDIR CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER".into());
        }
    }
    out.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_names() {
        assert_eq!(Libc::parse("glibc\n"), Some(Libc::Glibc));
        assert_eq!(Libc::parse("gnu"), Some(Libc::Glibc));
        assert_eq!(Libc::parse(" musl "), Some(Libc::Musl));
        assert_eq!(Libc::parse("relibc"), None);
    }

    #[test]
    fn drivers_map_to_glibcs() {
        assert_eq!(gnu_driver(b"cc"), Some("gcc"));
        assert_eq!(gnu_driver(b"c++"), Some("g++"));
        assert_eq!(gnu_driver(b"x86_64-zainium-linux-musl-gcc"), None);
        assert_eq!(gnu_driver(b"ld"), None);
    }

    #[test]
    fn env_names_full_compilers() {
        let r = Roots::under(std::path::Path::new("/"));
        let g = env(&r, Libc::Glibc);
        assert!(g.contains("export CC='x86_64-zainium-linux-gnu-gcc'"));
        assert!(g.contains("/overlayer/zexlib/union/x86_64-zainium-linux-gnu/lib/pkgconfig"));
        assert!(g.contains("unset LDFLAGS"));
        let m = env(&r, Libc::Musl);
        assert!(m.contains("export CC='x86_64-zainium-linux-musl-gcc'"));
        assert!(m.contains("export ZAINIUM_LIBC='musl'"));
    }
}
