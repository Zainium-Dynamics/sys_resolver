//! A small system tree for the tests, so they run on any machine.

use crate::remap::Roots;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/target/test-fixture");

/// Every regular file in the tree, with its content.
pub const FILES: &[(&str, &str)] = &[
    ("overlayer/syshub/bin/env", ""),
    (
        "overlayer/syshub/etc/passwd",
        "root:x:0:0:root:/root:/bin/sh\n",
    ),
    (
        "overlayer/syshub/etc/group",
        "root:x:0:root\nwheel:x:10:root\n",
    ),
    ("overlayer/syshub/var/lib/.keep", ""),
    (
        "overlayer/syshub/drivers/hardware/firmwares/some-device.bin",
        "",
    ),
    ("overlayer/syshub/x86_64-zainium-linux-musl/lib/libc.so", ""),
    ("overlayer/zexlib/union/include/dav1d/dav1d.h", ""),
    ("overlayer/zaisys/kernel/linux-zainium", ""),
];

/// Builds the tree once per test run and returns its root.
pub fn root() -> &'static Path {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT.get_or_init(|| {
        let root = PathBuf::from(ROOT);
        for (rel, content) in FILES {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
        let dangling = root.join("overlayer/syshub/bin/dangling");
        let _ = std::fs::remove_file(&dangling);
        symlink("/no/such/target", dangling).unwrap();
        root
    })
}

pub fn roots() -> Roots {
    Roots::under(root())
}

/// Points the code that reads the environment at the tree.
pub fn use_for_env() {
    unsafe {
        std::env::set_var(crate::remap::ZAIROOT_ENV, root());
    }
}
