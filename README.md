# sys_resolver

Dynamic FHS-path resolution for ZainiumOS — no real `/usr`, `/bin`, `/lib`; real files live under `/overlayer/syshub`, `/overlayer/syshub/x86_64-zainium-linux-musl`, `/overlayer/zexlib/union`, `/overlayer/zaisys`.

No mount, no symlink, no kernel patch, no libc rebuild, no editing scripts/binaries.

## Files

- `src/remap.rs` — scope guard (`bin sbin lib usr opt var etc boot`), path transform, 4-root probe.
- `src/preload.rs` — `LD_PRELOAD` interposition: `open openat access faccessat stat lstat fstatat execve fopen dlopen`.
- `src/audit.rs`, `src/main.rs` — `sys-resolver doctor` / `sys-resolver resolve <path>`.
- `src/ffi.rs` — C ABI export.

## Not covered

- `execl`/`execlp`/`execle`/`fopen64` — no distinct symbol or can't wrap on stable Rust.
- A prebuilt binary's `PT_INTERP` — read by the kernel before any userspace code runs.

## Building

```sh
cargo test --release
cargo build --release --target x86_64-unknown-linux-musl --lib
/overlayer/syshub/x86_64-zainium-linux-musl/bin/gcc -shared \
  -o libsys_resolver.so \
  -Wl,--whole-archive target/x86_64-unknown-linux-musl/release/libsys_resolver.a -Wl,--no-whole-archive \
  -lpthread -ldl
```

Musl only — one `.so` can't serve musl and glibc at once, but there's no glibc on ZainiumOS today.

## Deployed

- `/overlayer/syshub/lib/libsys_resolver.so`
- `LD_PRELOAD=/overlayer/syshub/lib/libsys_resolver.so` in `oxidized-environment/oxienv.toml`, `oxienv.toml`, `environment`.
