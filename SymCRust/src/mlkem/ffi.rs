//
// ffi.rs   Reverse bindings to expose SymCRust implementations to C callers
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// SymCrypt enforces abstraction by using an incomplete struct type for the PMLKEMKEY object,
// and the test driver uses only the public API, meaning we can lie and use another (Rust) type for
// the key as long as it's behind a pointer.

use crate::common::Error;
use alloc::boxed::Box;
use core::ptr;
use core::slice;
use libc::{c_int, size_t};

use super::*;

// TYPE DEFINITIONS
// ----------------

// C11 enums are `int`, per the C standard
type CParams = c_int;
type CFormat = c_int;

// We directly expose pointer to the Rust key type over the SymCrypt FFI.
// Now the key type is fixed-size, we can use a thin pointer in the FFI without issues.
type CMlKemKey = *mut key::Key;

// CONVERSIONS
// -----------

impl TryFrom<c_int> for key::Params {
    type Error = Error;
    fn try_from(params: c_int) -> Result<key::Params, Error> {
        match params {
            0 => Result::Err(Error::IncompatibleFormat),
            1 => Result::Ok(key::Params::MlKem512),
            2 => Result::Ok(key::Params::MlKem768),
            3 => Result::Ok(key::Params::MlKem1024),
            _ => Result::Err(Error::InvalidArgument),
        }
    }
}

impl TryFrom<c_int> for key::Format {
    type Error = Error;
    fn try_from(format: c_int) -> Result<key::Format, Error> {
        match format {
            0 => Result::Err(Error::IncompatibleFormat),
            1 => Result::Ok(key::Format::PrivateSeed),
            2 => Result::Ok(key::Format::DecapsulationKey),
            3 => Result::Ok(key::Format::EncapsulationKey),
            _ => Result::Err(Error::InvalidArgument),
        }
    }
}

// API
// ---

#[no_mangle]
pub extern "C" fn SymCryptMlKemkeyAllocate(params: c_int) -> CMlKemKey {
    match key::Params::try_from(params) {
        Result::Err(_) => ptr::null_mut(),
        Result::Ok(params) => match key::key_allocate(params) {
            Result::Err(_) => ptr::null_mut(),
            Result::Ok(k) => Box::into_raw(k),
        },
    }
}

#[no_mangle]
pub extern "C" fn SymCryptMlKemkeyFree(k: CMlKemKey) {
    unsafe { drop(Box::from_raw(k)) };
}

#[no_mangle]
pub extern "C" fn SymCryptMlKemSizeofKeyFormatFromParams(
    params: CParams,
    format: CFormat,
    sz: &mut size_t,
) -> Error {
    let params = match params.try_into() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let format = match format.try_into() {
        Ok(f) => f,
        Err(e) => return e,
    };
    *sz = sizeof_key_format_from_params(params, format);
    Error::NoError
}

#[no_mangle]
pub extern "C" fn SymCryptMlKemSizeofCiphertextFromParams(
    params: CParams,
    sz: &mut size_t,
) -> Error {
    let params = match params.try_into() {
        Ok(p) => p,
        Err(e) => return e,
    };
    *sz = sizeof_ciphertext_from_params(params);
    Error::NoError
}

#[no_mangle]
pub extern "C" fn SymCryptMlKemkeyGenerate(k: CMlKemKey, flags: u32) -> Error {
    let k = unsafe { &mut *k };

    key_generate(k, flags)
}

#[no_mangle]
pub extern "C" fn SymCryptMlKemkeySetValue(
    pb_src: *const u8,
    cb_src: size_t,
    format: CFormat,
    flags: u32,
    k: CMlKemKey,
) -> Error {
    let k = unsafe { &mut *k };
    let src = unsafe { slice::from_raw_parts(pb_src, cb_src) };
    let format = match format.try_into() {
        Ok(f) => f,
        Err(e) => return e,
    };

    key_set_value(src, format, flags, k)
}

#[no_mangle]
pub extern "C" fn SymCryptMlKemkeyGetValue(
    k: CMlKemKey,
    pb_dst: *mut u8,
    cb_dst: size_t,
    format: CFormat,
    flags: u32,
) -> Error {
    let k = unsafe { &mut *k };
    let dst = unsafe { slice::from_raw_parts_mut(pb_dst, cb_dst) };
    let format = match format.try_into() {
        Ok(f) => f,
        Err(e) => return e,
    };

    key_get_value(k, dst, format, flags)
}

#[no_mangle]
pub extern "C" fn SymCryptMlKemEncapsulate(
    k: CMlKemKey,
    pb_agreed_secret: *mut u8,
    cb_agreed_secret: size_t,
    pb_ciphertext: *mut u8,
    cb_ciphertext: size_t,
) -> Error {
    let k = unsafe { &mut *k };
    let agreed_secret = unsafe { slice::from_raw_parts_mut(pb_agreed_secret, cb_agreed_secret) };
    let ciphertext = unsafe { slice::from_raw_parts_mut(pb_ciphertext, cb_ciphertext) };

    encapsulate(k, agreed_secret, ciphertext)
}

#[no_mangle]
pub extern "C" fn SymCryptMlKemEncapsulateEx(
    k: CMlKemKey,
    pb_random: *const u8,
    cb_random: size_t,
    pb_agreed_secret: *mut u8,
    cb_agreed_secret: size_t,
    pb_ciphertext: *mut u8,
    cb_ciphertext: size_t,
) -> Error {
    let k = unsafe { &mut *k };
    let random = unsafe { slice::from_raw_parts(pb_random, cb_random) };
    let agreed_secret = unsafe { slice::from_raw_parts_mut(pb_agreed_secret, cb_agreed_secret) };
    let ciphertext = unsafe { slice::from_raw_parts_mut(pb_ciphertext, cb_ciphertext) };

    if cb_random != SIZEOF_ENCAPS_RANDOM {
        return Error::InvalidArgument;
    }

    encapsulate_ex(k, random.try_into().unwrap(), agreed_secret, ciphertext)
}

#[no_mangle]
pub extern "C" fn SymCryptMlKemDecapsulate(
    k: CMlKemKey,
    pb_ciphertext: *const u8,
    cb_ciphertext: size_t,
    pb_agreed_secret: *mut u8,
    cb_agreed_secret: size_t,
) -> Error {
    let k = unsafe { &mut *k };
    let agreed_secret = unsafe { slice::from_raw_parts_mut(pb_agreed_secret, cb_agreed_secret) };
    let ciphertext = unsafe { slice::from_raw_parts(pb_ciphertext, cb_ciphertext) };

    decapsulate(k, ciphertext, agreed_secret)
}

#[no_mangle]
pub extern "C" fn SymCryptMlKemkeyWipePrivateState(k: CMlKemKey) {
    let k = unsafe { &mut *k };
    k.wipe_private_state();
}