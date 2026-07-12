//! aarch64 intrinsic transcriptions, organised by `target_feature`.
//!
//! Per-extension files are declared regardless of host architecture: the
//! verify build is the *abstract* model, not a native build, so the
//! transcriptions must be available everywhere. (The differential tests
//! in `tests/aarch64_*_hw.rs` are themselves `#[cfg(target_arch = "aarch64")]`,
//! since they cross-check against `core::arch::aarch64::*`.)
//!
//! `lanes` lives at the parent (`crate::verify::intrinsics::lanes`)
//! since x86_64 SSE/AES also consume the same little-endian bitcasts.
//! Similarly for `lanewise` (lane-wise scalar primitives). We re-export
//! both here as `aarch64::{lanes,lanewise}` so that the existing
//! `super::{lanes,lanewise}::*` imports inside each sibling shim file
//! keep resolving correctly, both in the lib build and in
//! `#[path]`-loaded test binaries (where the test crate root has no
//! `crate::verify::...` path).

pub use super::lanes;
pub use super::lanewise;

pub mod neon;
pub mod aes;
// pub mod sha2;
