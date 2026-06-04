//
// symcryptcommon.rs mocks for common functionality for criterion benchmarking
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

use crate::common::Error;
use core::sync::atomic::AtomicU32;

// Mocks for SymCrypt callbacks for pure Rust test and benchmarking

// currently assert that all CPU features are present
#[allow(non_snake_case, dead_code)]
pub unsafe extern "C" fn SymCryptCpuFeaturesNeverPresent() -> u32 {
    0u32
}

#[allow(non_upper_case_globals)]
pub static g_SymCryptCpuFeaturesNotPresent: u32 = 0;
#[allow(non_upper_case_globals)]
pub static g_SymCryptFipsSelftestsPerformed: AtomicU32 = AtomicU32::new(0);

/// Magic value not used in benchmarking/tests
macro_rules! symcrypt_magic_value {
    ($p:expr) => { 0usize };
}

pub(crate) use symcrypt_magic_value;

#[allow(non_snake_case, dead_code)]
pub unsafe extern "C" fn SymCryptInit() {
    panic!("SymCryptInit not implemented in mock");
}

// currently assert that we never need random
#[allow(non_snake_case, dead_code)]
pub unsafe extern "C" fn SymCryptCallbackRandom(_pb_buffer: *mut u8, _cb_buffer: usize) -> Error {
    panic!("SymCryptCallbackRandom not implemented in mock");
}

#[allow(non_snake_case)]
pub unsafe extern "C" fn SymCryptWipe(_pb_data: *mut u8, _cb_data: usize) {
    // No-op for mock
}
