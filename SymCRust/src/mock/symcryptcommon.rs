//
// symcryptcommon.rs mocks for common functionality for criterion benchmarking
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

use crate::common::Error;

// Mocks for SymCrypt callbacks for pure Rust test and benchmarking

#[allow(non_snake_case)]
pub unsafe fn SymCryptInit() {
    panic!("SymCryptInit not implemented in mock");
}

#[allow(non_snake_case)]
pub unsafe fn SymCryptCallbackRandom(_pb_buffer: *mut u8, _cb_buffer: usize) -> Error {
    panic!("SymCryptCallbackRandom not implemented in mock");
}

#[allow(non_snake_case)]
pub unsafe fn SymCryptWipe(_pb_data: *mut u8, _cb_data: usize) {
    panic!("SymCryptWipe not implemented in mock");
}
