#!/bin/sh
# Builds target/libsys_resolver.so.
#
# The library is linked with no libc of its own (no NEEDED libc.so, no libgcc_s): its libc
# calls bind to the libc of the program it is preloaded into, musl or glibc. A glibc program
# never gets musl's libc loaded next to its own. Only the hooks are exported (exports.map),
# and the unwinder Rust's std needs is linked in statically.
set -eu
cd "$(dirname "$0")"
target=x86_64-unknown-linux-musl
cargo build --release --lib --target "$target" --features preload
# execl/execlp/execle are variadic: C, also without a libc
${CC:-cc} -c -O2 -fPIC -ffreestanding -fno-stack-protector -o target/execl.o src/execl.c
sc="$(rustc --print sysroot)/lib/rustlib/$target/lib/self-contained"
${CC:-cc} -shared -nostdlib -o target/libsys_resolver.so \
  -Wl,-soname,libsys_resolver.so -Wl,--version-script=exports.map \
  -Wl,--gc-sections -Wl,-z,noexecstack -Wl,-O1 -s \
  "$sc/crtbeginS.o" \
  target/execl.o \
  -Wl,--whole-archive "target/$target/release/libsys_resolver.a" -Wl,--no-whole-archive \
  "$sc/libunwind.a" \
  "$sc/crtendS.o"
if command -v "${READELF:-readelf}" >/dev/null &&
  "${READELF:-readelf}" -d target/libsys_resolver.so | grep -q NEEDED; then
  echo "build-so.sh: libsys_resolver.so must not depend on any library" >&2
  exit 1
fi
echo target/libsys_resolver.so
