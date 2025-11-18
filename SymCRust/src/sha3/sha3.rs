//
// mod.rs   Submodules for SHA3
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

pub mod sha3_224;

#[cfg(feature = "benchmarking")]
pub mod sha3_impl;
#[cfg(not(feature="benchmarking"))]
pub(crate) mod sha3_impl;

mod ffi;