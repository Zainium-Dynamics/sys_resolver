//! `sys_resolver` — dynamic FHS-path resolution logic for ZainiumOS.
//!
//! Exposed two ways from the exact same compiled code:
//!   - as a normal Rust library (`remap`, `audit`) — used by the CLI
//!     binary (`src/main.rs`) and by this crate's own tests, always
//!     against the real, live filesystem.
//!   - as a small C ABI (`ffi`) — the boundary a patched libc calls into.
//!     `musl`'s patch and a later `glibc` patch both link against this
//!     same compiled library and call the same function; the resolution
//!     *algorithm* is written and tested exactly once, here, never
//!     reimplemented per-libc.

pub mod audit;
pub mod ffi;
pub mod preload;
pub mod remap;
