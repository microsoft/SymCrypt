//
// aes.rs  SymCrypt Rust AES-GCM implementation
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

use libc::c_void;

use crate::block_cipher::BlockCipher;
use crate::common::wipe_slice;

use super::{ghash::GHashExpandedKey, CSymCryptAesExpandedKey};

/// GCM block size in bytes.
pub(super) const GCM_BLOCK_SIZE: usize = 16;

/// Maximum key size for GCM in bytes.
pub(super) const GCM_KEY_MAX_SIZE: usize = 32;

/// C-compatible representation of an expanded GCM key.
/// Used for FFI compatibility with C code.
#[derive(Debug, Default)]
#[cfg_attr(any(target_arch = "x86_64", target_arch = "aarch64"), repr(align(16)))]
#[cfg_attr(any(target_arch = "arm"), repr(align(8)))]
#[cfg_attr(any(target_arch = "x86"), repr(align(4)))]
#[repr(C)]
struct CSymCryptGcmExpandedKey {
    ghash_key: GHashExpandedKey,
    p_block_cipher: *const c_void, // Don't dereference from Rust
    blockcipher_key: CSymCryptAesExpandedKey,
    cb_key: usize,
    ab_key: [u8; GCM_KEY_MAX_SIZE],
    magic: usize,
}

/// C-compatible representation of a GCM computation state.
/// Tracks the current state of a GCM encryption/decryption operation,
/// including the authentication tag computation.
#[derive(Debug, Default)]
#[cfg_attr(any(target_arch = "x86_64", target_arch = "aarch64"), repr(align(16)))]
#[cfg_attr(any(target_arch = "arm"), repr(align(8)))]
#[cfg_attr(any(target_arch = "x86"), repr(align(4)))]
#[repr(C)]
struct CSymCryptGcmState {
    p_key: *const CSymCryptGcmExpandedKey,
    cb_data: u64,
    cb_auth_data: u64,
    bytes_in_mac_block: usize,
    ghash_state: u128, // SYMCRYPT_GF128_ELEMENT
    counter_block: [u8; GCM_BLOCK_SIZE],
    mac_block: [u8; GCM_BLOCK_SIZE],
    keystream_block: [u8; GCM_BLOCK_SIZE],
    magic: usize,
}

/// This function implements the CTR cipher mode.
/// It is not intended to be used as-is, rather it is a building block for modes like CCM.
/// Note that in CTR mode encryption and decryption are the same operation.
///
/// For now, this function is only intended for use with GCM, which specifies the use a
/// 32-bit increment function.
pub(super) fn ctr_msb_32<
    const BLOCK_SIZE: usize,
    const KEY_SIZE: usize,
    Cipher: BlockCipher<BLOCK_SIZE, KEY_SIZE>,
>(
    key: &Cipher::Key,
    chaining_value: &mut [u8; BLOCK_SIZE],
    src: &[u8],
    dst: &mut [u8],
) {
    assert_eq!(
        src.len(),
        dst.len(),
        "Source and destination buffers must be the same length"
    );

    let num_bytes = src.len() & !(BLOCK_SIZE - 1);

    // We keep the chaining state in a local buffer to enforce the read-once write-once rule.
    // It also improves memory locality.
    let mut counter_block = *chaining_value;
    let mut keystream_block = [0u8; BLOCK_SIZE];

    for (src_chunk, dst_chunk) in src[..num_bytes]
        .chunks_exact(BLOCK_SIZE)
        .zip(dst[..num_bytes].chunks_exact_mut(BLOCK_SIZE))
    {
        Cipher::encrypt_block(key, &counter_block, &mut keystream_block);
        // TODO: SymCryptXorBytes
        for i in 0..BLOCK_SIZE {
            dst_chunk[i] = src_chunk[i] ^ keystream_block[i];
        }

        // We only need to increment the last 32 bits of the counter value.
        let count =
            u32::from_be_bytes(counter_block[BLOCK_SIZE - 4..].try_into().unwrap()).wrapping_add(1);
        counter_block[BLOCK_SIZE - 4..].copy_from_slice(&count.to_be_bytes());
    }

    chaining_value.copy_from_slice(&counter_block);

    wipe_slice(&mut counter_block);
    wipe_slice(&mut keystream_block);
}
