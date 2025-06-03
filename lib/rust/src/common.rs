//
// common.rs   Common definitions that wrap SymCrypt FFI and set up SymCRust environment
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// The SYMCRYPT_ERROR C enum, mapped to Rust
//
// FIXME: for now, this is manually kept in sync between Rust and C -- can we automate?

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

// General-purpose functions that for now, remain implemented in C within SymCrypt.
//

extern "C" {
    fn SymCryptCallbackRandom(pbBuffer: *mut u8, cbBuffer: usize) -> Error;
    fn SymCryptWipe(pb_data: *mut u8, cb_data: usize);

    fn SymCryptCallbackAlloc(nBytes: usize) -> *mut u8;
    fn SymCryptCallbackFree(pMem: *mut u8);

    fn SymCryptFatal(fatalCode: u32) -> !;
}

pub(crate) fn random(dst: &mut [u8]) -> Error {
    unsafe { SymCryptCallbackRandom(dst.as_mut_ptr(), dst.len()) }
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

// Hooks required for building with no_std
// We make SymCRust use the SymCrypt callbacks for allocation and panics

struct SymCRustAllocator;

unsafe impl core::alloc::GlobalAlloc for SymCRustAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        // FIXME: hack on alignment given SymCryptCallbackAlloc
        //        is always at least 16 byte aligned for now
        if layout.align() > 16 {
            return core::ptr::null_mut();
        }
        unsafe { SymCryptCallbackAlloc(layout.size()) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        wipe(ptr, layout.size());
        unsafe { SymCryptCallbackFree(ptr) }
    }
}

#[global_allocator]
static GLOBAL: SymCRustAllocator = SymCRustAllocator;

#[lang = "eh_personality"]
fn rust_eh_personality() {}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Just drop panic info and call SymCryptFatal for now
    unsafe { SymCryptFatal(u32::from_be_bytes([b'S', b'c', b'P', b'a'])) }
}
