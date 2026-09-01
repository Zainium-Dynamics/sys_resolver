# sys_resolver

Dynamic FHS-path resolution for ZainiumOS.

ZainiumOS has no real `/usr`, `/bin`, `/sbin`, `/lib` — real files live
under `/overlayer/syshub`, `/overlayer/syshub/x86_64-zainium-linux-musl`,
and `/overlayer/zexlib/union`. Anything with a hardcoded FHS path
(compiler header probes, `#!/usr/bin/env python3` shebangs, absolute exec
paths in prebuilt binaries) breaks, since `$PATH` only helps with
searches, never a literal path.

`sys_resolver` fixes this transparently — no mount, no symlink, no kernel
patch, no libc rebuild, no editing the affected scripts or binaries.

## How it works

- `src/remap.rs` — the algorithm: a scope guard (`/bin /sbin /lib /usr
  /opt /var /etc` only — `/home` and `/tmp` are real, already-present
  top-level dirs, deliberately excluded), a strip-legacy-segments
  transform, a 3-root probe (`syshub` → `MUSL_SYSDIR` → `zexlib/union`).
- `src/preload.rs` — `LD_PRELOAD` interposition of `open` / `openat` /
  `access` / `faccessat` / `stat` / `lstat` / `fstatat` / `execve`. Real
  function tried first via `dlsym(RTLD_NEXT, ...)`; only on a genuine
  `ENOENT` does it retry resolved candidates. `execve` also peeks `#!`
  shebangs and redirects before the kernel ever sees a broken path.
- `src/audit.rs`, `src/main.rs` — `sys-resolver doctor` (full-tree audit)
  and `sys-resolver resolve <path>`.
- `src/ffi.rs` — a plain C ABI export for any other consumer.

`zex` is untouched by this — it writes real paths directly on install, so
it never hits the fallback.

## Known gaps

- `execl`/`execlp`/`execle` are true C variadics and can't be wrapped on
  stable Rust; musl's own `exec*` internals also bypass `LD_PRELOAD` for
  these. Direct `execve` calls — the hardcoded-absolute-path case this
  exists for — are unaffected.
- A prebuilt binary's `PT_INTERP` is read by the kernel before any
  userspace code runs, so no `LD_PRELOAD` mechanism can touch it. Anything
  built by ZainiumOS's own toolchain is unaffected.

## Building

Musl only — one `.so` can't serve musl and glibc at once (different
`libc.so` SONAMEs each expects), but there's no glibc anywhere on
ZainiumOS today, so that isn't a real gap.

```sh
cargo test --release
cargo build --release --target x86_64-unknown-linux-musl --lib
/overlayer/syshub/x86_64-zainium-linux-musl/bin/gcc -shared \
  -o libsys_resolver.so \
  -Wl,--whole-archive target/x86_64-unknown-linux-musl/release/libsys_resolver.a -Wl,--no-whole-archive \
  -lpthread -ldl
```

Rust's musl target doesn't emit `cdylib` directly, hence the manual link
step. A glibc build, if ever needed: `cargo build --target
x86_64-unknown-linux-gnu --lib` — same source, `cdylib` native, no code
changes.

## Deployed

- `/overlayer/syshub/lib/libsys_resolver.so`
- `LD_PRELOAD=/overlayer/syshub/lib/libsys_resolver.so`, in
  `/overlayer/syshub/etc/oxidized-environment/oxienv.toml` (what `quantra`
  actually reads), plus the older `oxienv.toml`/`environment` as a safety
  net during the migration.

## Tests

`cargo test --release` — 12/12.
