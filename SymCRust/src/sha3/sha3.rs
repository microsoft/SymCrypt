//
// mod.rs   Submodules for SHA3
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#[cfg(feature = "benchmarking")]
pub mod sha3_impl;
#[cfg(not(feature="benchmarking"))]
pub(crate) mod sha3_impl;

mod ffi;

pub mod sha3_variants;
pub use sha3_variants::{Sha3_224State, Sha3_256State, Sha3_384State, Sha3_512State};
pub use sha3_variants::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
pub(crate) use sha3_variants::SHA3_PADDING_VALUE;

pub mod shake_variants;
pub use shake_variants::{Shake128State, Shake256State};
pub use shake_variants::{Shake128, Shake256};
pub(crate) use shake_variants::SHAKE_PADDING_VALUE;

#[cfg(all(test, not(feature = "benchmarking")))]
mod tests;