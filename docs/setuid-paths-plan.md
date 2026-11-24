# Plan: handle classic paths for setuid/setgid (and static) programs

## Problem
sys_resolver works through `LD_PRELOAD` of `libsys_resolver.so`. The dynamic
loader sets `AT_SECURE` for setuid/setgid binaries and **drops LD_PRELOAD and
LD_LIBRARY_PATH**, so the resolver is never loaded into them. The same is true
for any program a setuid or static program execs. On Zainium there is no
`/usr`, `/bin`, `/lib` at the root, so such a program's classic-path lookups
return ENOENT and it fails. README already lists this under "Not covered".

## Scope
The sealed base has only a few setuid/setgid binaries (elevate helper /
unix_chkpwd, mount, ping, passwd, fusermount3, su-like tools, etc.). First step
is to enumerate them, not guess.

## Approach (in order)
1. **Enumerate** every setuid/setgid binary in the sealed base
   (`find /overlayer -perm /6000`); extend `sys-resolver doctor` to list them
   and flag any whose classic-path opens would fail. This is the test harness.

2. **Bake the path fallback into the system libc** (the real fix for setuid
   *dynamic* programs). Port `remap.rs` logic (on ENOENT, retry under
   /overlayer/syshub, the musl triplet, zexlib/union, zaisys; only for
   bin/sbin/lib/usr/opt/var/etc/boot prefixes) into Zainium's musl at the
   path-resolution layer, so it runs without any preload. Setuid dynamic
   programs use the system libc.so, so they get resolution automatically.
   - Do musl first (most base tools are musl), glibc second.
   - SECURITY: under `AT_SECURE`, restrict the fallback roots to the
     fs-verity-sealed, read-only base only (syshub + triplet). Never fall back
     to a mutable root (zexlib/union, var) when AT_SECURE, so a setuid program
     cannot be steered to load an attacker-planted file.

3. **Guarantee interp + runpath via replant** (belt-and-suspenders for library
   loading). Ensure every setuid ELF in the base has its `PT_INTERP` and
   `DT_RUNPATH` rewritten to absolute /overlayer/syshub paths (no $ORIGIN, so
   the loader honors them under AT_SECURE). replant already rewrites paths;
   make setuid ELFs a checked case.

4. **Static setuid**: a static binary carries its own libc, so step 2 does not
   reach it. For these, rely on replant to rewrite embedded paths, or prefer a
   dynamic build for base setuid tools. `doctor` should flag static+setuid.

5. **Child of a setuid/static program**: the child again has no preload. Step 2
   covers it if the child is dynamic and uses the system libc.

## Decision
Primary fix = step 2 (libc-level fallback, AT_SECURE-restricted to the sealed
base). Steps 3-4 cover library loading and static binaries. Keep LD_PRELOAD
resolver for the normal (non-setuid) case; libc fallback only has to carry the
AT_SECURE path.

Related: sealed-overlay-and-setuid, static-binaries-zainium-paths.
