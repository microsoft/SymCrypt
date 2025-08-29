//
// symcryptcommon.rs   Common definitions that wrap SymCrypt FFI
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// General-purpose functions that for now, remain implemented in C within SymCrypt.
//

use crate::common::Error;

extern "C" {
    pub fn SymCryptInit();
    pub fn SymCryptWipe(pb_data: *mut u8, cb_data: usize);
    pub fn SymCryptCallbackRandom(pbBuffer: *mut u8, cbBuffer: usize) -> Error;

    #[cfg(not(feature = "std"))]
    fn SymCryptCallbackAlloc(nBytes: usize) -> *mut u8;
    #[cfg(not(feature = "std"))]
    fn SymCryptCallbackFree(pMem: *mut u8);

    #[cfg(not(feature = "std"))]
    fn SymCryptFatal(fatalCode: u32) -> !;
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
#[lang = "eh_personality"]
fn rust_eh_personality() {}

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Just drop panic info and call SymCryptFatal for now
    unsafe { SymCryptFatal(u32::from_be_bytes([b'S', b'c', b'P', b'a'])) }
}
