//
// ffi.rs   Reverse bindings to expose SymCRust AES implementations to C callers
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

use core::slice;

use crate::common::Error;

use super::{AES_BLOCK_SIZE, AesImpl, AesImplType, AesKeyUsage, CSymCryptAesExpandedKey};

#[no_mangle]
pub unsafe extern "C" fn SymCryptAesExpandKey(
    key: *mut CSymCryptAesExpandedKey,
    pb_key: *const u8,
    cb_key: usize,
) -> Error {
    // SAFETY: The caller must ensure that all parameters point to valid memory. `key` does not
    // need to be initialized, as this function initializes it.
    let expanded_key = &mut *key;

    // Ensures the key length is valid (and readable via num_rounds) or returns an error
    match expanded_key.set_pointers_and_magic(cb_key) {
        Err(e) => return e,
        Ok(()) => {}
    };

    let key = unsafe { slice::from_raw_parts(pb_key, cb_key) };

    match key.len() {
        16 => { 
            expanded_key.expand_key::<16>(key.try_into().unwrap(), AesKeyUsage::EncryptAndDecrypt);
            Error::NoError
        },
        24 => {
            expanded_key.expand_key::<24>(key.try_into().unwrap(), AesKeyUsage::EncryptAndDecrypt);
            Error::NoError
        },
        32 => {
            expanded_key.expand_key::<32>(key.try_into().unwrap(), AesKeyUsage::EncryptAndDecrypt);
            Error::NoError
        },
        _ => Error::WrongKeySize
    }
}

/// Helper function for AES encryption via FFI. This function is the same for both XMM and NEON,
/// but the C FFI functions have different names depending on the architecture, so instead of
/// duplicating the code, each one can call this helper.
// #[cfg(not(test))]
#[inline]
unsafe fn symcrypt_aes_encrypt_helper(
    key: *const CSymCryptAesExpandedKey,
    pb_src: *const u8,
    pb_dst: *mut u8,
) {
    // SAFETY: The caller must ensure that all parameters point to valid memory.
    // `key` must be a valid, initialized, expanded CSymCryptAesExpandedKey.
    // `pb_src` and `pb_dst` must be pointers to buffers of at least 16 bytes (the AES block size).
    // The buffers may be the same for in-place encryption, but otherwise must not overlap.
    let expanded_key = &*key;
    let dst_block = slice::from_raw_parts_mut(pb_dst, AES_BLOCK_SIZE).try_into().unwrap();

    let src_block: Option<&[u8; AES_BLOCK_SIZE]> = match pb_src == pb_dst {
        true => None,
        false => Some(slice::from_raw_parts(pb_src, AES_BLOCK_SIZE).try_into().unwrap()),
    };

    match expanded_key.key_size() {
        16 => AesImplType::encrypt_block::<11>(expanded_key, src_block, dst_block),
        24 => AesImplType::encrypt_block::<13>(expanded_key, src_block, dst_block),
        32 => AesImplType::encrypt_block::<15>(expanded_key, src_block, dst_block),
        _ => unreachable!("Invalid AES key size"),
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#[no_mangle]
pub unsafe extern "C" fn SymCryptAesEncryptXmm(
    key: *const CSymCryptAesExpandedKey,
    pb_src: *const u8,
    pb_dst: *mut u8,
) {
    symcrypt_aes_encrypt_helper(key, pb_src, pb_dst);
}

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn SymCryptAesEncryptNeon(
    key: *const CSymCryptAesExpandedKey,
    pb_src: *const u8,
    pb_dst: *mut u8,
) {
    symcrypt_aes_encrypt_helper(key, pb_src, pb_dst);
}

/// Helper function for AES decryption via FFI. This function is the same for both XMM and NEON,
/// but the C FFI functions have different names depending on the architecture, so instead of
/// duplicating the code, each one can call this helper.
//#[cfg(not(test))]
#[inline]
unsafe fn symcrypt_aes_decrypt_helper(
    key: *const CSymCryptAesExpandedKey,
    pb_src: *const u8,
    pb_dst: *mut u8,
) {
    // SAFETY: The caller must ensure that all parameters point to valid memory.
    // `key` must be a valid, initialized CSymCryptAesExpandedKey.
    // `pb_src` and `pb_dst` must be pointers to buffers of at least 16 bytes (the AES block size).
    // The buffers may be the same for in-place encryption, but otherwise must not overlap.
    let expanded_key = &*key;
    let dst_block = slice::from_raw_parts_mut(pb_dst, 16).try_into().unwrap();

    let src_block: Option<&[u8; AES_BLOCK_SIZE]> = match pb_src == pb_dst {
        true => None,
        false => Some(slice::from_raw_parts(pb_src, AES_BLOCK_SIZE).try_into().unwrap()),
    };

    match expanded_key.key_size() {
        16 => AesImplType::decrypt_block::<11>(expanded_key, src_block, dst_block),
        24 => AesImplType::decrypt_block::<13>(expanded_key, src_block, dst_block),
        32 => AesImplType::decrypt_block::<15>(expanded_key, src_block, dst_block),
        _ => unreachable!("Invalid AES key size"),
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#[no_mangle]
pub unsafe extern "C" fn SymCryptAesDecryptXmm(
    key: *const CSymCryptAesExpandedKey,
    pb_src: *const u8,
    pb_dst: *mut u8,
) {
    symcrypt_aes_decrypt_helper(key, pb_src, pb_dst);
}

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn SymCryptAesDecryptNeon(
    key: *const CSymCryptAesExpandedKey,
    pb_src: *const u8,
    pb_dst: *mut u8,
) {
    symcrypt_aes_decrypt_helper(key, pb_src, pb_dst);
}
