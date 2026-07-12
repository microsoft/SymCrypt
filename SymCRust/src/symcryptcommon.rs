//
// symcryptcommon.rs   Common definitions that wrap SymCrypt FFI
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

//
// General-purpose functions that for now, remain implemented in C within SymCrypt.
//

#![cfg_attr(test, allow(unused_macros), allow(dead_code), allow(unused_imports))]

use core::sync::atomic::AtomicU32;

use crate::common::Error;

// TODO! These have to be kept in sync manually. Need to find a way to pull them from version.json,
// ideally without adding a dependency like serde.
pub(crate) const SYMCRYPT_VERSION_MAJOR: usize = 103;
pub(crate) const SYMCRYPT_VERSION_MINOR: usize = 13;
pub(crate) const SYMCRYPT_API_VERSION: usize =
    (SYMCRYPT_VERSION_MAJOR << 16) | SYMCRYPT_VERSION_MINOR;

/// Macro to compute the magic value for a structure pointer
macro_rules! symcrypt_magic_value {
    ($p:expr) => {
        (core::ptr::from_ref($p) as usize)
            .wrapping_add(u32::from_be_bytes([b'S', b'1', b'm', b'v']) as usize)
            .wrapping_add(crate::symcryptcommon::SYMCRYPT_API_VERSION)
    };
}

macro_rules! symcrypt_check_magic {
    ($p:expr) => {
        if symcrypt_magic_value!($p) != (*($p)).magic {
            panic!("Invalid magic value");
        }
    };
}

pub(crate) use symcrypt_check_magic;
pub(crate) use symcrypt_magic_value;

unsafe extern "C" {
    #[cfg_attr(feature = "verify", verify::exclude)]
    pub fn SymCryptInit();

    #[cfg_attr(feature = "verify", verify::exclude)]
    pub fn SymCryptWipe(pb_data: *mut u8, cb_data: usize);

    #[cfg_attr(feature = "verify", verify::exclude)]
    pub fn SymCryptCallbackRandom(pbBuffer: *mut u8, cbBuffer: usize) -> Error;

    #[cfg(not(feature = "std"))]
    fn SymCryptCallbackAlloc(nBytes: usize) -> *mut u8;
    #[cfg(not(feature = "std"))]
    fn SymCryptCallbackFree(pMem: *mut u8);

    #[cfg(not(feature = "std"))]
    fn SymCryptFatal(fatalCode: u32) -> !;

    #[cfg_attr(feature = "verify", verify::exclude)]
    pub fn SymCryptCpuFeaturesNeverPresent() -> u32;

    #[cfg_attr(feature = "verify", verify::exclude)]
    pub static g_SymCryptCpuFeaturesNotPresent: u32;

    #[cfg_attr(feature = "verify", verify::exclude)]
    pub static g_SymCryptFipsSelftestsPerformed: AtomicU32;
}

// Hooks required for building with no_std
// We make SymCRust use the SymCrypt callbacks for allocation and panics

#[cfg(not(feature = "std"))]
struct SymCRustAllocator;

#[cfg(not(feature = "std"))]
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
        crate::common::wipe(ptr, layout.size());
        unsafe { SymCryptCallbackFree(ptr) }
    }
}

#[cfg(not(feature = "std"))]
#[global_allocator]
static GLOBAL: SymCRustAllocator = SymCRustAllocator;

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Just drop panic info and call SymCryptFatal for now
    unsafe { SymCryptFatal(u32::from_be_bytes([b'S', b'c', b'P', b'a'])) }
}
