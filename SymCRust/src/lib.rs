//
// lib.rs   SymCRust lib file
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// Allows using the `charon` attributes
#![feature(register_tool)]
#![register_tool(charon)]
// To hook up box::try_new_in to the client-provided SymCrypt allocation callback.
#![feature(allocator_api)]
// To catch allocation failures when creating TEMPORARIES.
#![feature(try_with_capacity)]
// Make crate::common::ERROR compose with the ? operator and the core::result::Result type.
#![feature(try_trait_v2)]
// suppress warning: the feature `lang_items` is internal to the compiler or standard library
#![allow(internal_features)]
// To build with no_std and panic="abort" in debug build, we need to define our own empty #[lang = "eh_personality"]
#![feature(lang_items)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
extern crate core;

mod common;
pub mod ffi;
mod ghash;
#[cfg(not(feature = "benchmarking"))]
mod hash;
mod key;
mod mlkem;
#[cfg(not(feature = "benchmarking"))]
mod ntt;
#[cfg(not(feature = "benchmarking"))]
mod symcryptcommon;

#[cfg(test)]
mod test;

// For pure Rust benchmarking, we want to mock calls to SymCrypt callbacks for now
#[cfg(feature = "benchmarking")]
#[path = "mock/hash.rs"]
mod hash;

#[cfg(feature = "benchmarking")]
#[path = "mock/symcryptcommon.rs"]
mod symcryptcommon;

// For pure Rust benchmarking, we want to make NTT APIs public
#[cfg(feature = "benchmarking")]
pub mod ntt;
