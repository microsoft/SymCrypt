//
// ffi.rs   Reverse bindings to expose SymCRust implementations to C callers
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// This module contains reverse-bindings that expose our Rust implementations with a C ABI,
// identical to that exposed in symcrypt.h
//
// SymCrypt enforces abstraction by using an incomplete struct type for the PMLKEMKEY object,
// and the test driver uses only the public API, meaning we can lie and use another (Rust) type for
// the key as long as it's behind a pointer.

use crate::common::Error;
use alloc::boxed::Box;
use core::ptr;
use core::slice;
use libc::{c_int, size_t};

// TYPE DEFINITIONS
// ----------------

// C11 enums are `int`, per the C standard
type CParams = c_int;
type CFormat = c_int;

// So the dynamically-sized type (DST) comes back to bite us. The KEY type is a DST, meaning that
// in Rust it's a fat pointer -- it does not implement the Thin trait, and as such cannot be passed
// via the FFI. We add another layer of indirection.
type CKey = *mut Box<crate::key::Key>;

// We could, however, decompose it into raw parts:
// https://doc.rust-lang.org/std/primitive.pointer.html#method.to_raw_parts and, in the FFI layer,
// query the ML-KEM variant to deduce the size of the underlying allocation and reconstruct the
// fat pointer.

// CONVERSIONS
// -----------

impl TryFrom<c_int> for crate::key::Params {
    type Error = Error;
    fn try_from(params: c_int) -> Result<crate::key::Params, Error> {
        match params {
            0 => Result::Err(Error::IncompatibleFormat),
            1 => Result::Ok(crate::key::Params::MlKem512),
            2 => Result::Ok(crate::key::Params::MlKem768),
            3 => Result::Ok(crate::key::Params::MlKem1024),
            _ => Result::Err(Error::InvalidArgument),
        }
    }
}

impl TryFrom<c_int> for crate::key::Format {
    type Error = Error;
    fn try_from(format: c_int) -> Result<crate::key::Format, Error> {
        match format {
            0 => Result::Err(Error::IncompatibleFormat),
            1 => Result::Ok(crate::key::Format::PrivateSeed),
            2 => Result::Ok(crate::key::Format::DecapsulationKey),
            3 => Result::Ok(crate::key::Format::EncapsulationKey),
            _ => Result::Err(Error::InvalidArgument),
        }
    }
}

// API
// ---

#[no_mangle]
pub extern "C" fn SymCryptMlKemkeyAllocate(params: c_int) -> CKey {
    // FIXME: there is probably a better idiomatic way to handle this pattern
    match crate::key::Params::try_from(params) {
        Result::Err(_) => ptr::null_mut(),
        Result::Ok(params) => match crate::key::key_allocate(params) {
            Result::Err(_) => ptr::null_mut(),
            Result::Ok(k) => match Box::try_new(k) {
                Result::Err(_) => ptr::null_mut(),
                Result::Ok(k) => Box::into_raw(k),
            },
        },
    }
}

#[no_mangle]
pub extern "C" fn SymCryptMlKemkeyFree(k: CKey) {
    unsafe { drop(Box::from_raw(k)) };
}

#[no_mangle]
pub extern "C" fn SymCryptMlKemSizeofKeyFormatFromParams(
    params: CParams,
    format: CFormat,
    sz: &mut size_t,
) -> Error {
    *sz = crate::mlkem::sizeof_key_format_from_params(params.try_into()?, format.try_into()?);
    Error::NoError
}

#[no_mangle]
pub extern "C" fn SymCryptMlKemSizeofCiphertextFromParams(
    params: CParams,
    sz: &mut size_t,
) -> Error {
    *sz = crate::mlkem::sizeof_ciphertext_from_params(params.try_into()?);
    Error::NoError
}

#[no_mangle]
pub extern "C" fn SymCryptMlKemkeyGenerate(k: CKey, flags: u32) -> Error {
    let k = unsafe { &mut *k };

    crate::mlkem::key_generate(k, flags)
}

#[no_mangle]
pub extern "C" fn SymCryptMlKemkeySetValue(
    pb_src: *const u8,
    cb_src: size_t,
    format: CFormat,
    flags: u32,
    k: CKey,
) -> Error {
    let k = unsafe { &mut *k };
    let src = unsafe { slice::from_raw_parts(pb_src, cb_src) };

    crate::mlkem::key_set_value(src, format.try_into()?, flags, k)
}

#[no_mangle]
pub extern "C" fn SymCryptMlKemkeyGetValue(
    k: CKey,
    pb_dst: *mut u8,
    cb_dst: size_t,
    format: CFormat,
    flags: u32,
) -> Error {
    let k = unsafe { &mut *k };
    let dst = unsafe { slice::from_raw_parts_mut(pb_dst, cb_dst) };

    crate::mlkem::key_get_value(k, dst, format.try_into()?, flags)
}

#[no_mangle]
pub extern "C" fn SymCryptMlKemEncapsulate(
    k: CKey,
    pb_agreed_secret: *mut u8,
    cb_agreed_secret: size_t,
    pb_ciphertext: *mut u8,
    cb_ciphertext: size_t,
) -> Error {
    let k = unsafe { &mut *k };
    let agreed_secret = unsafe { slice::from_raw_parts_mut(pb_agreed_secret, cb_agreed_secret) };
    let ciphertext = unsafe { slice::from_raw_parts_mut(pb_ciphertext, cb_ciphertext) };

    crate::mlkem::encapsulate(k, agreed_secret, ciphertext)
}

#[no_mangle]
pub extern "C" fn SymCryptMlKemEncapsulateEx(
    k: CKey,
    pb_random: *mut u8,
    cb_random: size_t,
    pb_agreed_secret: *mut u8,
    cb_agreed_secret: size_t,
    pb_ciphertext: *mut u8,
    cb_ciphertext: size_t,
) -> Error {
    let k = unsafe { &mut *k };
    let random = unsafe { slice::from_raw_parts_mut(pb_random, cb_random) };
    let agreed_secret = unsafe { slice::from_raw_parts_mut(pb_agreed_secret, cb_agreed_secret) };
    let ciphertext = unsafe { slice::from_raw_parts_mut(pb_ciphertext, cb_ciphertext) };

    crate::mlkem::encapsulate_ex(k, random, agreed_secret, ciphertext)
}

#[no_mangle]
pub extern "C" fn SymCryptMlKemDecapsulate(
    k: CKey,
    pb_ciphertext: *const u8,
    cb_ciphertext: size_t,
    pb_agreed_secret: *mut u8,
    cb_agreed_secret: size_t,
) -> Error {
    let k = unsafe { &mut *k };
    let agreed_secret = unsafe { slice::from_raw_parts_mut(pb_agreed_secret, cb_agreed_secret) };
    let ciphertext = unsafe { slice::from_raw_parts(pb_ciphertext, cb_ciphertext) };

    crate::mlkem::decapsulate(k, ciphertext, agreed_secret)
}
