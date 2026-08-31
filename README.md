# sys_resolver

Dynamic FHS-path resolution for ZainiumOS.

ZainiumOS has no FHS (`ZAI_NO_FHS=1` — no real `/usr`, `/bin`, `/sbin`,
`/lib`). Real files live under `/overlayer/syshub`, the musl cross sysroot
(`/overlayer/syshub/x86_64-zainium-linux-musl`), and `/overlayer/zexlib/union`.
Anything that hardcodes an FHS path breaks as a result — a compiler's own
header/lib probes, a script's `#!/usr/bin/env python3` shebang, a prebuilt
binary's absolute `open()`/`exec()` calls — because `$PATH` only helps with
*searches*, never a literal path.

`sys_resolver` fixes this transparently: no mount, no symlink, no kernel
patch, no rebuilding musl or glibc, no editing the affected scripts or
binaries.

## How it works

1. **`src/remap.rs`** — the resolution algorithm. Pure and stateless, no
   I/O beyond existence checks: a scope guard (only `/bin`, `/sbin`,
   `/lib`, `/usr`, `/opt` are ever touched — everything else is left
   alone), a strip-legacy-segments transform (`/usr/bin/foo` → `bin/foo`,
   etc.), and an ordered 3-root probe (`syshub` → `MUSL_SYSDIR` →
   `zexlib/union`, matching `/etc/profile`'s own `PATH`/`LD_LIBRARY_PATH`
   priority). Independent of `zex`'s own similar install-time transform —
   no crate dependency between the two.
2. **`src/preload.rs`** — the deployed mechanism: an `LD_PRELOAD` shared
   object that interposes `open`, `openat`, `access`, `faccessat`, `stat`,
   `lstat`, `fstatat`, and `execve`. Each tries the real libc function
   first (via `dlsym(RTLD_NEXT, ...)` — libc-agnostic by construction);
   only on a genuine `ENOENT`, for an in-scope path, does it retry against
   `remap`'s resolved candidates. `execve` additionally peeks a target's
   first two bytes for `#!` and redirects to the resolved interpreter
   *before* the kernel ever sees a broken path — this is what makes
   shebangs resolve without editing them.
3. **`src/audit.rs` / `src/main.rs`** — the full-tree reachability audit
   (`sys-resolver doctor`) and the CLI (`sys-resolver resolve <path>`).
4. **`src/ffi.rs`** — a plain C ABI export of the resolution algorithm,
   for any future consumer that isn't the preload library itself.

`zex` is untouched by any of this — it already writes straight to real
`/overlayer/...` paths on install, so it never hits the `ENOENT` fallback
this project exists for.

## Known, deliberate gaps

- **`execl`/`execlp`/`execle`** are true C variadics (an unbounded `...`
  argument list), which can't be implemented as a matching-ABI function on
  stable Rust. musl's own `execvp`/`execl*` also call `execve` as a local
  (non-PLT) call inside its own compiled object, which bypasses
  `LD_PRELOAD` interposition regardless of language. Anything that reaches
  an absolute FHS path via a direct `execve` call — confirmed: musl's
  `execvp` does exactly this for any name already containing a `/`, which
  is the hardcoded-absolute-path case this project exists for — is
  unaffected.
- **A prebuilt third-party binary's `PT_INTERP`** is read by the kernel
  directly from the ELF file during its own internal load, before any of
  that process's own code (preloaded or not) has run. No userspace
  mechanism can touch this. Anything built by ZainiumOS's own toolchain is
  unaffected, since its `PT_INTERP` is already the real musl loader path.

## Building

**Single build, musl only.** One physical `.so` can't serve both musl and
glibc at once — a musl-built `.so` declares `NEEDED: libc.so`; glibc's
loader looks for `libc.so.6` and won't find it. That's a hard ELF
constraint, not a design choice. It doesn't matter today, though: ZainiumOS
has no glibc anywhere — every `zex` package tier is a musl-based distro —
so no glibc process can start on this system regardless. One musl build
covers everything that actually runs today.

```sh
cargo test --release

# Rust's musl target doesn't support cdylib output directly, so build the
# staticlib and link the real .so with ZainiumOS's own musl cross-gcc:
cargo build --release --target x86_64-unknown-linux-musl --lib
/overlayer/syshub/x86_64-zainium-linux-musl/bin/gcc -shared \
  -o libsys_resolver.so \
  -Wl,--whole-archive target/x86_64-unknown-linux-musl/release/libsys_resolver.a -Wl,--no-whole-archive \
  -lpthread -ldl
```

If glibc ever becomes bootable on ZainiumOS (a separate, much larger
undertaking), the same unchanged source builds for it too —
`cargo build --release --target x86_64-unknown-linux-gnu --lib` supports
`cdylib` natively, no manual link step required.

## Deployed

- `/overlayer/syshub/lib/libsys_resolver.so` — the musl-linked build.
- `LD_PRELOAD=/overlayer/syshub/lib/libsys_resolver.so`, set in:
  - `/overlayer/syshub/etc/oxidized-environment/oxienv.toml` — the
    canonical config `oxidized-environment-core::resolve()` reads (what
    `quantra`/PID 1 links directly and applies before spawning anything).
  - `/overlayer/syshub/etc/oxienv.toml` and `/overlayer/syshub/etc/environment`
    — the prior `zai-env`-generated config, kept in sync as a safety net
    during the migration to `oxidized-environment`.

## Verified

- `cargo test --release`: 12/12, including a full-tree audit against every
  real file currently under `syshub`/`MUSL_SYSDIR`/`zexlib/union` (0
  genuine resolver gaps; a handful of pre-existing dangling symlinks were
  found in the installed tree — a real, separate issue, not a resolver
  bug).
- A real C program, `LD_PRELOAD`'d against the live `zairoot` tree:
  `open()`/`access()` fail with a genuine `ENOENT` without the preload,
  and succeed with real file content read back with it.
- A real C program cross-compiled with ZainiumOS's own musl gcc, run
  through the real musl loader (musl binaries are syscall-portable across
  any Linux kernel): `execve` + shebang resolution end-to-end, the target
  script actually executed with arguments passed through correctly.
- The `oxidized-environment/oxienv.toml` config was validated against the
  real `oxidized-environment-core::verify()`/`resolve()` functions, not
  just read by eye — confirmed well-formed and confirmed `LD_PRELOAD`
  resolves correctly.
