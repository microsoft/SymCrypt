//
// ffi.rs   Reverse bindings to expose SymCRust AES implementations to C callers
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

use core::slice;

use crate::common::{Error, InPlaceOrDisjointBuffer};

use super::{
    ghash, AesGcmImpl, AesImpl, AesImplType, AesKeyUsage, CSymCryptAesExpandedKey, AES_BLOCK_SIZE,
};

/// FFI wrapper for AES key expansion. Expands an AES key for use with encryption/decryption.
/// This function is called from C code.
///
/// # Safety
/// * `key` must point to valid, writable memory for a `CSymCryptAesExpandedKey` structure
/// * `pb_key` must point to a valid buffer of `cb_key` bytes
/// * `cb_key` must be 16, 24, or 32 (for AES-128, AES-192, or AES-256)
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
    if let Err(e) = expanded_key.set_pointers_and_magic(cb_key) {
        return e;
    }

    let key = unsafe { slice::from_raw_parts(pb_key, cb_key) };

    match key.len() {
        16 => {
            expanded_key.expand_key::<16>(key.try_into().unwrap(), AesKeyUsage::EncryptAndDecrypt);
            Error::NoError
        }
        24 => {
            expanded_key.expand_key::<24>(key.try_into().unwrap(), AesKeyUsage::EncryptAndDecrypt);
            Error::NoError
        }
        32 => {
            expanded_key.expand_key::<32>(key.try_into().unwrap(), AesKeyUsage::EncryptAndDecrypt);
            Error::NoError
        }
        _ => Error::WrongKeySize,
    }
}

/// Helper function for AES encryption via FFI. This function is the same for both XMM and NEON,
/// but the C FFI functions have different names depending on the architecture, so instead of
/// duplicating the code, each one can call this helper.
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
    let dst_block = slice::from_raw_parts_mut(pb_dst, AES_BLOCK_SIZE)
        .try_into()
        .unwrap();

    let src_block: Option<&[u8; AES_BLOCK_SIZE]> = if pb_src == pb_dst {
        None
    } else {
        Some(
            slice::from_raw_parts(pb_src, AES_BLOCK_SIZE)
                .try_into()
                .unwrap(),
        )
    };

    match expanded_key.key_size() {
        16 => AesImplType::encrypt_block::<11>(expanded_key, src_block, dst_block),
        24 => AesImplType::encrypt_block::<13>(expanded_key, src_block, dst_block),
        32 => AesImplType::encrypt_block::<15>(expanded_key, src_block, dst_block),
        _ => unreachable!("Invalid AES key size"),
    }
}

/// FFI wrapper for XMM (AES-NI) accelerated AES encryption.
/// This function is called from C code on x86/x86_64 platforms.
///
/// # Safety
/// * `key` must point to a valid, initialized `CSymCryptAesExpandedKey`
/// * `pb_src` and `pb_dst` must point to buffers of at least 16 bytes
/// * Buffers may be the same for in-place encryption, but otherwise must not overlap
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#[no_mangle]
pub unsafe extern "C" fn SymCryptAesEncryptXmm(
    key: *const CSymCryptAesExpandedKey,
    pb_src: *const u8,
    pb_dst: *mut u8,
) {
    symcrypt_aes_encrypt_helper(key, pb_src, pb_dst);
}

/// FFI wrapper for NEON accelerated AES encryption.
/// This function is called from C code on ARM64 (AArch64) platforms.
///
/// # Safety
/// * `key` must point to a valid, initialized `CSymCryptAesExpandedKey`
/// * `pb_src` and `pb_dst` must point to buffers of at least 16 bytes
/// * Buffers may be the same for in-place encryption, but otherwise must not overlap
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

    let src_block: Option<&[u8; AES_BLOCK_SIZE]> = if pb_src == pb_dst {
        None
    } else {
        Some(
            slice::from_raw_parts(pb_src, AES_BLOCK_SIZE)
                .try_into()
                .unwrap(),
        )
    };

    match expanded_key.key_size() {
        16 => AesImplType::decrypt_block::<11>(expanded_key, src_block, dst_block),
        24 => AesImplType::decrypt_block::<13>(expanded_key, src_block, dst_block),
        32 => AesImplType::decrypt_block::<15>(expanded_key, src_block, dst_block),
        _ => unreachable!("Invalid AES key size"),
    }
}

/// FFI wrapper for XMM (AES-NI) accelerated AES decryption.
/// This function is called from C code on x86/x86_64 platforms.
///
/// # Safety
/// * `key` must point to a valid, initialized `CSymCryptAesExpandedKey`
/// * `pb_src` and `pb_dst` must point to buffers of at least 16 bytes
/// * Buffers may be the same for in-place decryption, but otherwise must not overlap
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#[no_mangle]
pub unsafe extern "C" fn SymCryptAesDecryptXmm(
    key: *const CSymCryptAesExpandedKey,
    pb_src: *const u8,
    pb_dst: *mut u8,
) {
    symcrypt_aes_decrypt_helper(key, pb_src, pb_dst);
}

/// FFI wrapper for NEON accelerated AES decryption.
/// This function is called from C code on ARM64 (AArch64) platforms.
///
/// # Safety
/// * `key` must point to a valid, initialized `CSymCryptAesExpandedKey`
/// * `pb_src` and `pb_dst` must point to buffers of at least 16 bytes
/// * Buffers may be the same for in-place decryption, but otherwise must not overlap
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn SymCryptAesDecryptNeon(
    key: *const CSymCryptAesExpandedKey,
    pb_src: *const u8,
    pb_dst: *mut u8,
) {
    symcrypt_aes_decrypt_helper(key, pb_src, pb_dst);
}

/// FFI wrapper for AES-GCM stitched encryption (XMM implementation).
/// This exposes our Rust implementation to C callers for performance testing.
///
/// # Safety
/// The caller must ensure that all parameters point to valid memory.
/// - `key` must be a valid, initialized `CSymCryptAesExpandedKey`
/// - `chaining_value` must point to a 16-byte buffer for the AES-GCM counter
/// - `expanded_key_table` must point to a valid `GHashExpandedKey` (cast from u128 array)
/// - `state` must point to a valid u128 for the GHASH state
/// - `src` and `dst` must point to buffers of at least `byte_count` bytes
/// - `byte_count` must be a multiple of 16 (GCM block size)
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#[no_mangle]
pub unsafe extern "C" fn SymCryptAesGcmEncryptStitchedXmm(
    key: *const CSymCryptAesExpandedKey,
    chaining_value: *mut u8,
    expanded_key_table: *const u128,
    state: *mut u128,
    src: *const u8,
    dst: *mut u8,
    byte_count: usize,
) {
    let expanded_key = key.as_ref().unwrap();
    let chaining_value: &mut [u8; AES_BLOCK_SIZE] =
        slice::from_raw_parts_mut(chaining_value, AES_BLOCK_SIZE)
            .try_into()
            .unwrap();

    // Cast the u128 pointer back to GHashExpandedKey
    let ghash_expanded_key = &*expanded_key_table.cast::<ghash::GHashExpandedKey>();

    let ghash_state = &mut *state;

    let buffer = InPlaceOrDisjointBuffer::from_raw_parts(src, dst, byte_count);

    match expanded_key.key_size() {
        16 => AesImplType::gcm_encrypt_stitched::<11>(
            expanded_key,
            chaining_value,
            ghash_expanded_key,
            ghash_state,
            buffer,
        ),
        24 => AesImplType::gcm_encrypt_stitched::<13>(
            expanded_key,
            chaining_value,
            ghash_expanded_key,
            ghash_state,
            buffer,
        ),
        32 => AesImplType::gcm_encrypt_stitched::<15>(
            expanded_key,
            chaining_value,
            ghash_expanded_key,
            ghash_state,
            buffer,
        ),
        _ => unreachable!("Invalid AES key size"),
    }
}

/// FFI wrapper for AES-GCM stitched decryption (XMM implementation).
/// This exposes our Rust implementation to C callers for performance testing.
///
/// # Safety
/// The caller must ensure that all parameters point to valid memory.
/// - `key` must be a valid, initialized `CSymCryptAesExpandedKey`
/// - `chaining_value` must point to a 16-byte buffer for the AES-GCM counter
/// - `expanded_key_table` must point to a valid `GHashExpandedKey` (cast from u128 array)
/// - `state` must point to a valid u128 for the GHASH state
/// - `src` and `dst` must point to buffers of at least `byte_count` bytes
/// - `byte_count` must be a multiple of 16 (GCM block size)
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#[no_mangle]
pub unsafe extern "C" fn SymCryptAesGcmDecryptStitchedXmm(
    key: *const CSymCryptAesExpandedKey,
    chaining_value: *mut u8,
    expanded_key_table: *const u128,
    state: *mut u128,
    src: *const u8,
    dst: *mut u8,
    byte_count: usize,
) {
    let expanded_key = key.as_ref().unwrap();
    let chaining_value: &mut [u8; AES_BLOCK_SIZE] =
        slice::from_raw_parts_mut(chaining_value, AES_BLOCK_SIZE)
            .try_into()
            .unwrap();

    // Cast the u128 pointer back to GHashExpandedKey
    let ghash_expanded_key = &*expanded_key_table.cast::<ghash::GHashExpandedKey>();

    let ghash_state = &mut *state;

    let buffer = InPlaceOrDisjointBuffer::from_raw_parts(src, dst, byte_count);

    match expanded_key.key_size() {
        16 => AesImplType::gcm_decrypt_stitched::<11>(
            expanded_key,
            chaining_value,
            ghash_expanded_key,
            ghash_state,
            buffer,
        ),
        24 => AesImplType::gcm_decrypt_stitched::<13>(
            expanded_key,
            chaining_value,
            ghash_expanded_key,
            ghash_state,
            buffer,
        ),
        32 => AesImplType::gcm_decrypt_stitched::<15>(
            expanded_key,
            chaining_value,
            ghash_expanded_key,
            ghash_state,
            buffer,
        ),
        _ => unreachable!("Invalid AES key size"),
    }
}
