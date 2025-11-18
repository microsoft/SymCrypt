//
// lib.rs   SymCRust lib file
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// FIXME: figure out how to build with stable Rust and also have Charon based on build config
// // Allows using the `charon` attributes
// #![feature(register_tool)]
// #![register_tool(charon)]

#![cfg_attr(not(feature = "std"), no_std)]

// Enable pedantic lints (more strict)
#![warn(clippy::pedantic)]

// Enable all clippy lints
#![warn(clippy::all)]

extern crate alloc;
extern crate core;

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