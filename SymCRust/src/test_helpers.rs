//
// test_helpers.rs   FFI functions to facilitate linking with symcryptunittest
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#[cfg(test)]
use core::ffi::c_uchar;

use crate::common::Error;

extern "C" {
    fn SymCryptInitEnvUnittest(version: u32);
    fn SymCryptCpuFeaturesNeverPresentEnvUnittest() -> u32;
    fn SymCryptTestInjectErrorEnvUnittest(pb_buf: *mut u8, cb_buf: usize);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
extern "C" {
    fn SymCryptSaveXmmEnvUnittest(save_data: *mut u8);
    fn SymCryptRestoreXmmEnvUnittest(save_data: *const u8);
    fn SymCryptSaveYmmEnvUnittest(save_data: *mut u8);
    fn SymCryptRestoreYmmEnvUnittest(save_data: *const u8);
    fn SymCryptSaveZmmEnvUnittest(save_data: *mut u8);
    fn SymCryptRestoreZmmEnvUnittest(save_data: *const u8);
    fn SymCryptCpuidExFuncEnvUnittest(cpu_info: *mut i32, function_id: i32, subfunction_id: i32);
}

#[cfg(test)]
#[no_mangle]
pub unsafe extern "C" fn SymCryptCallbackRandom(pb_buffer: *mut u8, cb_buffer: usize) -> Error {
    use core::slice;
    use rand::rand_core::{OsRng, TryRngCore};
    unsafe {
        match OsRng.try_fill_bytes(slice::from_raw_parts_mut(pb_buffer, cb_buffer)) {
            Ok(()) => Error::NoError,
            Err(_) => Error::ExternalFailure,
        }
    }
}

#[cfg(test)]
#[no_mangle]
unsafe extern "C" fn SymCryptInit() {
    use crate::symcryptcommon::SYMCRYPT_API_VERSION;

    SymCryptInitEnvUnittest(SYMCRYPT_API_VERSION as u32);
}

#[cfg(test)]
#[no_mangle]
unsafe extern "C" fn SymCryptFatal(fatal_code: u32) -> ! {
    panic!("SymCryptFatal called with code {:x}", fatal_code);
}

#[cfg(test)]
#[no_mangle]
unsafe extern "C" fn SymCryptInjectError(pb_buf: *mut u8, cb_buf: usize) {
    SymCryptTestInjectErrorEnvUnittest(pb_buf, cb_buf);
}

#[cfg(test)]
#[no_mangle]
unsafe extern "C" fn SymCryptCpuFeaturesNeverPresent() -> u32 {
    SymCryptCpuFeaturesNeverPresentEnvUnittest()
}
#[cfg(test)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[no_mangle]
unsafe extern "C" fn SymCryptSaveXmm(save_data: *mut u8) {
    SymCryptSaveXmmEnvUnittest(save_data);
}

#[cfg(test)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[no_mangle]
unsafe extern "C" fn SymCryptRestoreXmm(save_data: *const u8) {
    SymCryptRestoreXmmEnvUnittest(save_data);
}

#[cfg(test)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[no_mangle]
unsafe extern "C" fn SymCryptSaveYmm(save_data: *mut u8) {
    SymCryptSaveYmmEnvUnittest(save_data);
}

#[cfg(test)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[no_mangle]
unsafe extern "C" fn SymCryptRestoreYmm(save_data: *const u8) {
    SymCryptRestoreYmmEnvUnittest(save_data);
}

#[cfg(test)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[no_mangle]
unsafe extern "C" fn SymCryptSaveZmm(save_data: *mut u8) {
    SymCryptSaveZmmEnvUnittest(save_data);
}

#[cfg(test)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[no_mangle]
unsafe extern "C" fn SymCryptRestoreZmm(save_data: *const u8) {
    SymCryptRestoreZmmEnvUnittest(save_data);
}

#[cfg(test)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[no_mangle]
unsafe extern "C" fn SymCryptCpuidExFunc(
    cpu_info: *mut i32,
    function_id: i32,
    subfunction_id: i32,
) {
    SymCryptCpuidExFuncEnvUnittest(cpu_info, function_id, subfunction_id);
}

#[cfg(test)]
#[no_mangle]
unsafe extern "C" fn fatalImpl(message: *const c_uchar) -> ! {
    panic!(
        "FATAL ERROR: {}",
        core::ffi::CStr::from_ptr(message as *const i8)
            .to_str()
            .unwrap()
    );
}
