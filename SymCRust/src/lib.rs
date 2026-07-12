//
// lib.rs   SymCRust lib file
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#![cfg_attr(not(feature = "std"), no_std)]

// Enable pedantic lints (more strict)
#![warn(clippy::pedantic)]

// Enable all clippy lints
#![warn(clippy::all)]

// Activate attributes specific to verification such as #[verify::opaque] and #[verify::exclude].
// Gated on `feature = "verify"`, so the production (ms-prod) build never requests this nightly feature.
#![cfg_attr(feature = "verify", feature(register_tool), register_tool(verify))]

extern crate alloc;
extern crate core;

// Verify-only scaffolding (intrinsic shims, hand-rolled trait impls, opaque
// stubs). Compiled exclusively under `--features verify`; production builds
// are bit-identical with this directory removed. See INTRINSICS.md.
#[cfg(feature = "verify")]
pub mod verify;

#[cfg(feature = "aes")]
#[path = "aes/aes.rs"]
pub mod aes;

pub mod block_cipher;

mod common;

#[path = "sha3/sha3.rs"]
pub mod sha3;

pub mod hash;

// For pure Rust benchmarking, we want to mock calls to SymCrypt callbacks for now
#[cfg(not(feature = "benchmarking"))]
mod symcryptcommon;

#[cfg(feature = "benchmarking")]
#[path = "mock/symcryptcommon.rs"]
mod symcryptcommon;

#[path = "mlkem/mlkem.rs"]
pub mod mlkem;

#[cfg(all(test, not(feature = "benchmarking")))]
mod test_helpers;

#[cfg(feature = "kernel")]
mod kernel_stubs;
