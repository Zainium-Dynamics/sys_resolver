# sys_resolver

Dynamic FHS-path resolution for ZainiumOS — no real `/usr`, `/bin`, `/lib`; real files live under `/overlayer/syshub`, `/overlayer/syshub/x86_64-zainium-linux-musl`, `/overlayer/zexlib/union`, `/overlayer/zaisys`.

No mount, no symlink, no kernel patch, no libc rebuild, no editing scripts/binaries.

## Files

- `src/remap.rs` — scope guard (`bin sbin lib usr opt var etc boot`), path transform, 4-root probe.
- `src/preload.rs` — `LD_PRELOAD` interposition: `open openat creat access eaccess euidaccess faccessat stat lstat fstatat statx statfs statvfs fopen freopen opendir scandir ftw nftw readlink readlinkat realpath canonicalize_file_name pathconf getxattr lgetxattr listxattr llistxattr inotify_add_watch chdir dlopen` (+ the `*64` names, glibc's `__open_2`/`__openat_2` fortify entries and its old `__xstat` family), `execve execveat execv execvp execvpe posix_spawn posix_spawnp`, `getpw*`/`getgr*`, and the delete guard on `unlink unlinkat rmdir`.
- `src/execl.c` — `execl execlp execle` (C variadics), through the same exec hooks.
- `src/nss.rs` — passwd/group fallback for the `getpw*`/`getgr*` hooks.
- `src/audit.rs`, `src/main.rs` — `sys-resolver doctor` / `sys-resolver resolve <path>`.
- `src/ffi.rs` — C ABI export.
- `build-so.sh`, `exports.map` — link `libsys_resolver.so`.

## Behaviour

- A path that exists is never touched; only an ENOENT is retried under the real roots.
- Scripts whose `#!` interpreter isn't where the line says (`#!/bin/sh`, `#!/usr/bin/env python3`) are started through the real interpreter, whichever way they are run: `execve`, `execv`, `execvp`, `posix_spawn` (Rust's `Command`, Python's `subprocess`).
- Deleting under `/overlayer/syshub` is refused only for files of the base itself, and only for programs other than zex. `var/`, `etc/` and everything in the userland layer (`zexlib/union`) can be deleted by anyone. A safety net against a stray `rm -rf`, not a security boundary.
- The library has no libc of its own: its libc calls bind to the libc of the program it is loaded into, so it works the same in musl and glibc programs, and a glibc program never gets musl loaded next to glibc.

## Not covered

- File lookups libc makes internally (musl's timezone search, for one): no call reaches a hook.
- Static and setuid programs — the loader preloads nothing into them.
- A prebuilt binary's `PT_INTERP` — read by the kernel before any userspace code runs.

## Building

```sh
cargo test --release
./build-so.sh        # writes target/libsys_resolver.so; CC=x86_64-zainium-linux-musl-gcc on Zainium
```

`build-so.sh` links with `-nostdlib`: no `NEEDED` entry at all (it fails if one appears), only the hooks exported, the unwinder linked in statically.

## Deployed

- `/overlayer/syshub/lib/libsys_resolver.so`
- `LD_PRELOAD=/overlayer/syshub/lib/libsys_resolver.so` in `oxidized-environment/oxienv.toml`, `oxienv.toml`, `environment`.
