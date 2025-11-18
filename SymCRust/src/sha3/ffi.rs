
//
// ffi.rs   Reverse bindings to expose SymCRust SHA3 implementations to C callers
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#![cfg_attr(test, allow(unused_macros), allow(unused_imports))]
#![cfg_attr(feature = "benchmarking", allow(unused_macros), allow(unused_imports))]

use core::slice::from_raw_parts;
use core::slice::from_raw_parts_mut;

use crate::sha3::sha3_impl::*;
use crate::hash::Hash;
use crate::sha3::sha3_224::*;

#[cfg(all(not(test), not(feature = "benchmarking")))]
use crate::symcryptcommon::{symcrypt_magic_value, symcrypt_check_magic};

macro_rules! define_c_sha3_hash_struct {
    ($name:ident) => {
        #[repr(C)]
        #[cfg_attr(any(target_arch = "x86"), repr(align(4)))]
        #[cfg_attr(any(target_arch = "arm"), repr(align(8)))]
        #[cfg_attr(any(target_arch = "x86_64", target_arch = "aarch64"), repr(align(16)))]
        #[derive(Clone, Default)]
        pub struct $name {
            pub(crate) state: KeccakState,
            pub(crate) magic: usize,
        }
    };
}

define_c_sha3_hash_struct!(CSha3_224State);

// TODO: Import, export, selftest

//
// Our FFI functions are configured out of test/benchmarking
// code since we want to compare against the native C implementation.
//

#[cfg(all(not(test), not(feature = "benchmarking")))]
#[no_mangle]
pub unsafe extern "C" fn SymCryptSha3_224(
    pb_data: *const u8,
    cb_data: usize,
    pb_result: *mut u8
) {
    let mut internal_sha3_state = Sha3_224HashState::default();
    let data = if cb_data > 0 { unsafe { from_raw_parts(pb_data, cb_data) } } else { &[] };
    let result = unsafe { from_raw_parts_mut(pb_result, SHA3_224_RESULT_SIZE) };

    internal_sha3_state.hash(data, result);
}

#[cfg(all(not(test), not(feature = "benchmarking")))]
#[no_mangle]
pub unsafe extern "C" fn SymCryptSha3_224StateCopy(
    p_src: *const CSha3_224State,
    p_dst: *mut CSha3_224State
) {
    symcrypt_check_magic!(p_src.as_ref().unwrap());
    *p_dst = (*p_src).clone();
    (*p_dst).magic = symcrypt_magic_value!(p_dst.as_ref().unwrap());
}

#[cfg(all(not(test), not(feature = "benchmarking")))]
#[no_mangle]
pub unsafe extern "C" fn SymCryptSha3_224Init(p_state: *mut CSha3_224State) {
    let mut internal_sha3_state = Sha3_224HashState::default();

    internal_sha3_state.init();
    (*p_state).state = internal_sha3_state.state;
    (*p_state).magic = symcrypt_magic_value!(p_state.as_ref().unwrap());
}

#[cfg(all(not(test), not(feature = "benchmarking")))]
#[no_mangle]
pub unsafe extern "C" fn SymCryptSha3_224Append(
    p_state: *mut CSha3_224State,
    pb_data: *const u8,
    cb_data: usize
) {
    let mut internal_sha3_state = Sha3_224HashState::default();
    let data = if cb_data > 0 { unsafe { from_raw_parts(pb_data, cb_data) } } else { &[] };

    internal_sha3_state.state = (*p_state).state.clone();
    internal_sha3_state.append(data);
    (*p_state).state = internal_sha3_state.state;
}

#[cfg(all(not(test), not(feature = "benchmarking")))]
#[no_mangle]
pub unsafe extern "C" fn SymCryptSha3_224Result(
    p_state: *mut CSha3_224State,
    pb_result: *mut u8
) {
    let mut internal_sha3_state = Sha3_224HashState::default();
    let result = unsafe {from_raw_parts_mut(pb_result, SHA3_224_RESULT_SIZE)};

    internal_sha3_state.state = (*p_state).state.clone();
    internal_sha3_state.result(result);
    (*p_state).state = internal_sha3_state.state.clone();
}