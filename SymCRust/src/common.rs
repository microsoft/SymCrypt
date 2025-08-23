//
// common.rs   Common definitions that set up SymCRust environment
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// The SYMCRYPT_ERROR C enum, mapped to Rust
//
// FIXME: for now, this is manually kept in sync between Rust and C -- can we automate?

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, Ordering};

#[derive(PartialEq, Debug, Clone)]
#[repr(C)]
pub enum Error {
    NoError = 0,
    Unused = 0x8000, // Start our error codes here so they're easier to distinguish
    WrongKeySize,
    WrongBlockSize,
    WrongDataSize,
    WrongNonceSize,
    WrongTagSize,
    WrongIterationCount,
    AuthenticationFailure,
    ExternalFailure,
    FipsFailure,
    HardwareFailure,
    NotImplemented,
    InvalidBlob,
    BufferTooSmall,
    InvalidArgument,
    MemoryAllocationFailure,
    SignatureVerificationFailure,
    IncompatibleFormat,
    ValueTooLarge,
    SessionReplayFailure,
    HbsNoOtsKeysLeft,
    HbsPublicRootMismatch,
}

const SYMCRYPT_MODULE_VERSION_MAJOR : u32 = 103;
const SYMCRYPT_MODULE_VERSION_MINOR : u32 = 8;

// Allows printing errors, which is a prerequisite for using ERROR as an argument to
// core::result::Result.
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?} ({:x})", self, self.clone() as u16)
    }
}

// Allows using errors within core::result::Result.
impl core::error::Error for Error {}

// Allows using the ? operator to early-return in functions that return MLKEM_ERROR, capturing the
// fact that NO_ERROR is the success case.
impl core::ops::FromResidual<Result<core::convert::Infallible, Error>> for Error {
    fn from_residual(r: Result<core::convert::Infallible, Error>) -> Error {
        match r {
            Result::Ok(_) => Error::NoError,
            Result::Err(e) => e,
        }
    }
}

use crate::symcryptcommon::*;

pub(crate) fn init() {

    static INITIALIZED: AtomicBool = AtomicBool::new(false);

    if INITIALIZED.load(Ordering::Relaxed) {
        return;
    }

    unsafe { 
        SymCryptModuleInit(SYMCRYPT_MODULE_VERSION_MAJOR, SYMCRYPT_MODULE_VERSION_MINOR)
    };

    INITIALIZED.store(true, Ordering::Relaxed);
}

pub(crate) fn random(dst: &mut [u8]) -> Error {
    unsafe { SymCryptRandom(dst.as_mut_ptr(), dst.len()) }
}

pub fn wipe(pb_data: *mut u8, cb_data: usize) {
    unsafe { SymCryptWipe(pb_data, cb_data) }
}

pub fn wipe_slice<T>(pb_dst: &mut [T]) {
    wipe(
        pb_dst.as_mut_ptr() as *mut u8,
        pb_dst.len() * size_of::<T>(),
    );
}