//! `sys_resolver` — dynamic FHS-path resolution logic for ZainiumOS.

pub mod audit;
pub mod ffi;
pub mod nss;
#[cfg(feature = "preload")]
pub mod preload;
pub mod remap;
#[cfg(test)]
mod test_fixture;
pub mod toolchain;
