//
// mod.rs   Submodules for SHA3
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#[cfg(any(feature = "benchmarking", test))]
pub mod sha3_impl;
#[cfg(not(any(feature = "benchmarking", test)))]
pub(crate) mod sha3_impl;

#[cfg(not(feature = "verify"))]
mod ffi;

pub mod sha3_variants;
pub use sha3_variants::{Sha3_224State, Sha3_256State, Sha3_384State, Sha3_512State};
pub use sha3_variants::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
pub(crate) use sha3_variants::SHA3_PADDING_VALUE;

pub mod shake_variants;
pub use shake_variants::{Shake128State, Shake256State};
pub use shake_variants::{Shake128, Shake256};
pub(crate) use shake_variants::SHAKE_PADDING_VALUE;

// Optimised scalar Keccak-f[1600]: fused θ+ρ+π, interleaved χ, locals.
// The production permutation is `sha3_impl::keccak_permute`, which routes
// through the textbook variant (matching `feature/verifiedcrypto`); this
// optimised variant is kept and proved equivalent in the SHA-3 verification.
#[cfg(any(feature = "benchmarking", test))]
pub mod keccak_opt;
#[cfg(not(any(feature = "benchmarking", test)))]
pub(crate) mod keccak_opt;

// 4-way data-parallel Keccak in safe auto-vectorising Rust.  Used by `shake4x`
// and `shake1x` for the bulk MLKEM/MLDSA sampling paths.
#[cfg(any(feature = "benchmarking", test))]
pub mod keccak4x;
#[cfg(not(any(feature = "benchmarking", test)))]
pub(crate) mod keccak4x;

// Hybrid 4-way: auto-vectorised θ/χ/π + AVX2 intrinsics for ρ rotations.
// Currently the fastest 4-way path on x86_64; consumed by `shake4x`.
#[cfg(target_arch = "x86_64")]
#[cfg(any(feature = "benchmarking", test))]
pub mod keccak4x_hybrid;
#[cfg(target_arch = "x86_64")]
#[cfg(not(any(feature = "benchmarking", test)))]
pub(crate) mod keccak4x_hybrid;

// `shake4x` depends on `keccak4x_hybrid` (its 4-way Keccak backend), which is
// only available on `x86_64`.  Gating the module mirrors that dependency so the
// crate builds cleanly on non-x86_64 targets (e.g. `aarch64-*`).
#[cfg(target_arch = "x86_64")]
pub(crate) mod shake4x;
pub(crate) mod shake1x;

#[cfg(all(test, not(feature = "benchmarking")))]
mod tests;
