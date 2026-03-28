
//
// ffi.rs   Reverse bindings to expose SymCRust SHA3 implementations to C callers
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#![cfg_attr(test, allow(unused_macros), allow(unused_imports))]
#![cfg_attr(feature = "benchmarking", allow(unused_macros), allow(unused_imports), allow(dead_code))]

use core::slice::from_raw_parts;
use core::slice::from_raw_parts_mut;

use crate::sha3::sha3_impl::*;
use crate::hash::{OneShotHash, OneShotXof, StatefulHash, StatefulXof};
use crate::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256};
use crate::sha3::{Sha3_224State, Sha3_256State, Sha3_384State, Sha3_512State, Shake128State, Shake256State};

#[cfg(all(not(test), not(feature = "benchmarking")))]
use crate::symcryptcommon::{symcrypt_magic_value, symcrypt_check_magic};

macro_rules! define_c_sha3_state_struct {
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

define_c_sha3_state_struct!(CFfiSha3_224State);
define_c_sha3_state_struct!(CFfiSha3_256State);
define_c_sha3_state_struct!(CFfiSha3_384State);
define_c_sha3_state_struct!(CFfiSha3_512State);

define_c_sha3_state_struct!(CFfiShake128State);
define_c_sha3_state_struct!(CFfiShake256State);

//
// Our FFI functions are configured out of test/benchmarking
// code since we want to compare against the native C implementation.
//

// TODO: Import, export, selftest

macro_rules! define_state_copy_ffi {
    ($fn_name:ident, $c_state:ty) => {
        #[cfg(all(not(test), not(feature = "benchmarking")))]
        #[no_mangle]
        pub unsafe extern "C" fn $fn_name(p_src: *const $c_state, p_dst: *mut $c_state) {
            symcrypt_check_magic!(p_src.as_ref().unwrap());
            *p_dst = (*p_src).clone();
            (*p_dst).magic = symcrypt_magic_value!(p_dst.as_ref().unwrap());
        }
    };
}

macro_rules! define_init_ffi {
    ($fn_name:ident, $c_state:ty, $rust_state:ty) => {
        #[cfg(all(not(test), not(feature = "benchmarking")))]
        #[no_mangle]
        pub unsafe extern "C" fn $fn_name(p_state: *mut $c_state) {
            (*p_state).state = <$rust_state>::new().state;
            (*p_state).magic = symcrypt_magic_value!(p_state.as_ref().unwrap());
        }
    };
}

macro_rules! define_append_ffi {
    ($fn_name:ident, $c_state:ty, $rust_state:ty) => {
        #[cfg(all(not(test), not(feature = "benchmarking")))]
        #[no_mangle]
        pub unsafe extern "C" fn $fn_name(p_state: *mut $c_state, pb_data: *const u8, cb_data: usize) {
            let data = if cb_data > 0 { from_raw_parts(pb_data, cb_data) } else { &[] };

            (*p_state).state.append(data);
        }
    };
}

macro_rules! define_result_ffi {
    ($fn_name:ident, $c_state:ty, $rust_state:ty) => {
        #[cfg(all(not(test), not(feature = "benchmarking")))]
        #[no_mangle]
        pub unsafe extern "C" fn $fn_name(p_state: *mut $c_state, pb_result: *mut u8) {
            let result = from_raw_parts_mut(pb_result, <$rust_state>::RESULT_SIZE);

            (*p_state).state.extract(result, true);
        }
    };
}

macro_rules! define_hash_ffi {
    ($fn_name:ident, $rust_state:ty) => {
        #[cfg(all(not(test), not(feature = "benchmarking")))]
        #[no_mangle]
        pub unsafe extern "C" fn $fn_name(pb_data: *const u8, cb_data: usize, pb_result: *mut u8) {
            let data = if cb_data > 0 { from_raw_parts(pb_data, cb_data) } else { &[] };
            let result = from_raw_parts_mut(pb_result, <$rust_state>::RESULT_SIZE);

            <$rust_state>::hash(data, result.try_into().unwrap());
        }
    };
}

//
// SHAKE specific FFI macros
//

macro_rules! define_xof_ffi {
    ($fn_name:ident, $rust_state:ty) => {
        #[cfg(all(not(test), not(feature = "benchmarking")))]
        #[no_mangle]
        pub unsafe extern "C" fn $fn_name(pb_data: *const u8, cb_data: usize, pb_result: *mut u8, cb_result: usize) {
            let data = if cb_data > 0 { from_raw_parts(pb_data, cb_data) } else { &[] };
            let result = from_raw_parts_mut(pb_result, cb_result);

            <$rust_state>::xof(data, result);
        }
    };
}

macro_rules! define_default_xof_ffi {
    ($fn_name:ident, $rust_state:ty) => {
        #[cfg(all(not(test), not(feature = "benchmarking")))]
        #[no_mangle]
        pub unsafe extern "C" fn $fn_name(pb_data: *const u8, cb_data: usize, pb_result: *mut u8) {
            let data = if cb_data > 0 { from_raw_parts(pb_data, cb_data) } else { &[] };
            let result = from_raw_parts_mut(pb_result, <$rust_state>::RESULT_SIZE);

            <$rust_state>::xof(data, result);
        }
    };
}

macro_rules! define_shake_extract_ffi {
    ($fn_name:ident, $c_state:ty, $rust_state:ty) => {
        #[cfg(all(not(test), not(feature = "benchmarking")))]
        #[no_mangle]
        pub unsafe extern "C" fn $fn_name(p_state: *mut $c_state, pb_result: *mut u8, cb_result: usize, b_wipe: bool) {
            let result = from_raw_parts_mut(pb_result, cb_result);

            (*p_state).state.extract(result, b_wipe);
        }
    };
}

//
// Macros to define the different SHA3/SHAKE API sets
//

macro_rules! define_sha3_api_set {
    (
        $hash_fn:ident,
        $copy_fn:ident,
        $init_fn:ident,
        $append_fn:ident,
        $result_fn:ident,
        $rust_one_shot:ty,
        $rust_state:ty,
        $c_state:ty
    ) => {
        define_hash_ffi!($hash_fn, $rust_one_shot);
        define_state_copy_ffi!($copy_fn, $c_state);
        define_init_ffi!($init_fn, $c_state, $rust_state);
        define_append_ffi!($append_fn, $c_state, $rust_state);
        define_result_ffi!($result_fn, $c_state, $rust_state);
    };
}

macro_rules! define_shake_api_set {
    (
        $default_xof_fn:ident,
        $xof_fn:ident,
        $copy_fn:ident,
        $init_fn:ident,
        $append_fn:ident,
        $extract_fn:ident,
        $result_fn:ident,
        $rust_one_shot:ty,
        $rust_state:ty,
        $c_state:ty
    ) => {
        define_default_xof_ffi!($default_xof_fn, $rust_one_shot);
        define_xof_ffi!($xof_fn, $rust_one_shot);
        define_state_copy_ffi!($copy_fn, $c_state);
        define_init_ffi!($init_fn, $c_state, $rust_state);
        define_append_ffi!($append_fn, $c_state, $rust_state);
        define_shake_extract_ffi!($extract_fn, $c_state, $rust_state);
        define_result_ffi!($result_fn, $c_state, $rust_state);
    };
}

//
// Sha3-224 FFIs
//

define_sha3_api_set!(
    SymCryptSha3_224,
    SymCryptSha3_224StateCopy,
    SymCryptSha3_224Init,
    SymCryptSha3_224Append,
    SymCryptSha3_224Result,
    Sha3_224,
    Sha3_224State,
    CFfiSha3_224State
);

//
// Sha3-256 FFIs
//

define_sha3_api_set!(
    SymCryptSha3_256,
    SymCryptSha3_256StateCopy,
    SymCryptSha3_256Init,
    SymCryptSha3_256Append,
    SymCryptSha3_256Result,
    Sha3_256,
    Sha3_256State,
    CFfiSha3_256State
);

//
// Sha3-384 FFIs
//

define_sha3_api_set!(
    SymCryptSha3_384,
    SymCryptSha3_384StateCopy,
    SymCryptSha3_384Init,
    SymCryptSha3_384Append,
    SymCryptSha3_384Result,
    Sha3_384,
    Sha3_384State,
    CFfiSha3_384State
);

//
// Sha3-512 FFIs
//

define_sha3_api_set!(
    SymCryptSha3_512,
    SymCryptSha3_512StateCopy,
    SymCryptSha3_512Init,
    SymCryptSha3_512Append,
    SymCryptSha3_512Result,
    Sha3_512,
    Sha3_512State,
    CFfiSha3_512State
);

//
// Shake128 FFIs
//

define_shake_api_set!(
    SymCryptShake128Default,
    SymCryptShake128,
    SymCryptShake128StateCopy,
    SymCryptShake128Init,
    SymCryptShake128Append,
    SymCryptShake128Extract,
    SymCryptShake128Result,
    Shake128,
    Shake128State,
    CFfiShake128State
);

//
// Shake256 FFIs
//

define_shake_api_set!(
    SymCryptShake256Default,
    SymCryptShake256,
    SymCryptShake256StateCopy,
    SymCryptShake256Init,
    SymCryptShake256Append,
    SymCryptShake256Extract,
    SymCryptShake256Result,
    Shake256,
    Shake256State,
    CFfiShake256State
);