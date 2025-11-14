//
// common.rs   Common definitions that set up SymCRust environment
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// The SYMCRYPT_ERROR C enum, mapped to Rust
//
// FIXME: for now, this is manually kept in sync between Rust and C -- can we automate?

#![allow(dead_code)]

use crate::symcryptcommon::*;
use alloc::boxed::Box;
use core::alloc::Layout;
use core::ptr;
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

#[derive(PartialEq, Debug, Clone)]
#[repr(C)]
pub enum SelftestAlgorithm {
    NONE    =   0x0,
    STARTUP =   0x1,
    DSA     =   0x2,
    ECDSA   =   0x4,
    RSA     =   0x8,
    DH      =  0x10,
    ECDH    =  0x20,
    MLKEM   =  0x40,
    XMSS    =  0x80,
    LMS     = 0x100,
    MLDSA   = 0x200,
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub const SYMCRYPT_CPU_FEATURE_SSE2: u32 = 1;
#[cfg(target_arch = "aarch64")]
pub const SYMCRYPT_CPU_FEATURE_NEON: u32 = 1;

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

pub(crate) fn init() {

    static INITIALIZED: AtomicBool = AtomicBool::new(false);

    if INITIALIZED.load(Ordering::Relaxed) {
        return;
    }

    unsafe { SymCryptInit(); }

    INITIALIZED.store(true, Ordering::Relaxed);
}

pub fn cpu_features_present(feature_mask: u32) -> bool {
    unsafe {
        ((SymCryptCpuFeaturesNeverPresent() & feature_mask) == 0)
            && ((g_SymCryptCpuFeaturesNotPresent & feature_mask) == 0)
    }
}

pub fn run_selftest_once(selftest_fn: unsafe extern "C" fn(), selftest_flag: u32) {
    unsafe {
        if (g_SymCryptFipsSelftestsPerformed.load(Ordering::Relaxed) & selftest_flag) == 0 {
            selftest_fn();
            g_SymCryptFipsSelftestsPerformed.fetch_or(selftest_flag, Ordering::Relaxed);
        }
    }
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
        core::mem::size_of_val(pb_dst),
    );
}

// Workaround for lack of Box::try_new in stable Rust
// FIXME: remove when Box::try_new is stabilized
pub fn try_new_box<T>(value: T) -> Result<Box<T>, Error> {
    unsafe {
        let layout = Layout::new::<T>();
        let ptr = alloc::alloc::alloc(layout) as *mut T;
        
        if ptr.is_null() {
            return Err(Error::MemoryAllocationFailure);
        }
        
        ptr::write(ptr, value);
        Ok(Box::from_raw(ptr))
    }
}

/// Constant-time memory comparison.
/// 
/// Compares two byte slices in constant time, ensuring that:
/// - All bytes from both slices are read
/// - The comparison time does not depend on where the first difference occurs
/// - Returns true if all bytes match, false otherwise

/// Wrapper function for static-length arrays, with length equality enforced at compile time.
pub fn const_time_arrays_equal<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    const_time_slices_equal_impl(a.as_slice(), b.as_slice())
}

/// Wrapper function for runtime-sized slices, with length equality checked at runtime, generating a panic if lengths differ.
pub fn const_time_slices_equal(a: &[u8], b: &[u8]) -> bool {
    assert_eq!(a.len(), b.len());
    const_time_slices_equal_impl(a, b)
}

#[inline(never)] // Prevent inlining to help ensure constant-time behavior
fn const_time_slices_equal_impl(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());

    let len = a.len();
    let mut diff: u8 = 0;

    // TODO: consider wider reads for performance (may require explicit alignment)

    // Accumulate all differences without short-circuiting
    for i in 0..len {
        let ai = unsafe{ core::ptr::read_volatile(a.as_ptr().add(i)) };
        let bi = unsafe{ core::ptr::read_volatile(b.as_ptr().add(i)) };
        diff |= ai ^ bi;
    }
    
    // Return true if no differences were found
    diff == 0
}

/// Constant-time memory copy based on a copy size.
/// 
/// Copies bytes from source `a` to destination `b` in constant time,
/// based on the specified `copy_size`. The function ensures that:
/// - All bytes from both source and destination are read and all bytes in the destination slice are written
/// - The copy operation time does not depend on the `copy_size`
/// - Only the first `copy_size` bytes are copied from `a` to `b`
/// - If `copy_size` is greater than the slice length, all source bytes are copied, but this will panic in debug builds

/// Wrapper function for static-length arrays, with length equality enforced at compile time.
pub fn const_time_array_copy<const N: usize>(a: &[u8; N], b: &mut [u8; N], copy_size: u32) {
    const { assert!( N <= u32::MAX as usize, "Array length exceeds u32::MAX" ); }
    const_time_slice_copy_impl(a.as_slice(), b.as_mut_slice(), copy_size)
}

/// Wrapper function for runtime-sized slices, with length equality checked at runtime, generating a panic if lengths differ.
pub fn const_time_slice_copy(a: &[u8], b: &mut [u8], copy_size: u32) {
    assert_eq!(a.len(), b.len());
    const_time_slice_copy_impl(a, b, copy_size)
}

#[inline(never)] // Prevent inlining to help ensure constant-time behavior
fn const_time_slice_copy_impl(a: &[u8], b: &mut [u8], copy_size: u32) {
    debug_assert_eq!(a.len(), b.len());
    debug_assert!(a.len() <= u32::MAX as usize, "Slices length exceeds u32::MAX");
    debug_assert!(a.len() >= copy_size as usize, "Slices are too small for copy");

    let len = a.len();

    // TODO: consider wider reads/writes for performance (may require explicit alignment)
    
    for i in 0..len {
        let ai = unsafe{ core::ptr::read_volatile(a.as_ptr().add(i)) };
        let mut bi = unsafe{ core::ptr::read_volatile(b.as_ptr().add(i)) };
        let mask = (((i as u32).wrapping_sub(copy_size) as i32) >> 31) as u8;
        bi ^= (ai ^ bi) & mask;
        unsafe{ core::ptr::write_volatile(b.as_mut_ptr().add(i), bi) };
    }
}

// For Pure Rust testing, supply mock implementations of SymCrypt C functions we depend on.

#[cfg(test)]
use core::slice;

#[cfg(test)]
#[no_mangle]
pub unsafe extern "C" fn SymCryptInit()
{
    // Nothing to do here
}

#[cfg(test)]
#[no_mangle]
pub unsafe extern "C" fn SymCryptFatal(fatal_code: u32) -> ! {
    panic!("SymCryptFatal called with code {:x}", fatal_code);
}

#[cfg(test)]
#[no_mangle]
pub unsafe extern "C" fn SymCryptInjectError(_pb_buf: *mut u8, _cb_buf: usize)
{
    // Not used for now, just required for linking
}

#[cfg(test)]
#[no_mangle]
pub unsafe extern "C" fn SymCryptCallbackRandom(pb_buffer: *mut u8, cb_buffer: usize) -> Error {
    use rand::rand_core::{TryRngCore, OsRng};
    unsafe {
        match OsRng.try_fill_bytes(slice::from_raw_parts_mut(pb_buffer, cb_buffer)) {
            Ok(()) => Error::NoError,
            Err(_) => Error::ExternalFailure,
        }
    }
}

#[cfg(test)]
#[no_mangle]
pub unsafe extern "C" fn SymCryptCpuFeaturesNeverPresent() -> u32 {
    // currently assert that all CPU features are present
    0u32
}
