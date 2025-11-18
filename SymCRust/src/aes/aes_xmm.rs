//
// aes_xmm.rs  SymCrypt Rust AES implementation with XMM intrinsics
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#[allow(clippy::wildcard_imports)]
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[allow(clippy::wildcard_imports)]
#[cfg(target_arch = "x86")]
use core::arch::x86::*;

use super::{AesImpl, CSymCryptAesExpandedKey, AES_BLOCK_SIZE};

pub(super) struct AesXmmImpl;

impl AesXmmImpl {
    /// Helper function for encryption of a single AES block. Corresponds to `AES_ENCRYPT_1` in
    /// the SymCrypt C implementation.
    /// SAFETY: The use of intrinsics requires unsafe. `expanded_key` and `c0` must be valid
    /// references.
    #[allow(clippy::needless_range_loop)]
    #[inline]
    unsafe fn encrypt_block_impl<const KEY_ROUNDS: usize>(
        round_keys: &[[u8; AES_BLOCK_SIZE]; KEY_ROUNDS],
        c0: &mut __m128i,
    ) {
        let mut round_key = _mm_loadu_si128(round_keys[0].as_ptr().cast());

        *c0 = _mm_xor_si128(*c0, round_key);

        for r in 1..KEY_ROUNDS - 1 {
            round_key = _mm_loadu_si128(round_keys[r].as_ptr().cast());
            *c0 = _mm_aesenc_si128(*c0, round_key);
        }

        round_key = _mm_loadu_si128(round_keys[KEY_ROUNDS - 1].as_ptr().cast());
        *c0 = _mm_aesenclast_si128(*c0, round_key);
    }

    /// Helper function for decryption of a single AES block. Corresponds to `AES_DECRYPT_1` in
    /// the SymCrypt C implementation.
    /// SAFETY: The use of intrinsics requires unsafe. `expanded_key` and `c0` must be valid
    /// references.
    #[allow(clippy::needless_range_loop)]
    #[inline]
    unsafe fn decrypt_block_impl<const KEY_ROUNDS: usize>(
        round_keys: &[[u8; AES_BLOCK_SIZE]; KEY_ROUNDS],
        c0: &mut __m128i,
    ) {
        let mut round_key = _mm_loadu_si128(round_keys[0].as_ptr().cast());

        *c0 = _mm_xor_si128(*c0, round_key);

        for r in 1..KEY_ROUNDS - 1 {
            round_key = _mm_loadu_si128(round_keys[r].as_ptr().cast());
            *c0 = _mm_aesdec_si128(*c0, round_key);
        }

        round_key = _mm_loadu_si128(round_keys[KEY_ROUNDS - 1].as_ptr().cast());
        *c0 = _mm_aesdeclast_si128(*c0, round_key);
    }
}

impl AesImpl for AesXmmImpl {
    #[inline]
    fn sbox_lookup_u32(input: u32) -> u32 {
        // SAFETY: Intrinsics
        unsafe {
            let x = _mm_set1_epi32(input.cast_signed());
            let x = _mm_aeskeygenassist_si128::<0>(x);
            _mm_cvtsi128_si32(x).cast_unsigned()
        }
    }

    #[inline]
    fn create_decryption_round_key(enc_round_key: &[u8; AES_BLOCK_SIZE]) -> [u8; AES_BLOCK_SIZE] {
        let mut output = [0u8; AES_BLOCK_SIZE];

        // SAFETY: Intrinsics
        unsafe {
            let mut x = _mm_loadu_si128(enc_round_key.as_ptr().cast());
            x = _mm_aesimc_si128(x);
            _mm_storeu_si128(output.as_mut_ptr().cast(), x);
        }

        output
    }

    #[inline]
    fn encrypt_block<const KEY_ROUNDS: usize>(
        expanded_key: &CSymCryptAesExpandedKey,
        input_buffer: Option<&[u8; AES_BLOCK_SIZE]>,
        output_buffer: &mut [u8; AES_BLOCK_SIZE],
    ) {
        let keys = expanded_key.enc_round_keys::<KEY_ROUNDS>();

        // SAFETY: Intrinsics
        unsafe {
            let mut c = match input_buffer {
                Some(plain) => _mm_loadu_si128(plain.as_ptr().cast()),
                None => _mm_loadu_si128(output_buffer.as_ptr().cast()),
            };
            AesXmmImpl::encrypt_block_impl::<KEY_ROUNDS>(keys, &mut c);
            _mm_storeu_si128(output_buffer.as_mut_ptr().cast(), c);
        }
    }

    #[inline]
    fn decrypt_block<const KEY_ROUNDS: usize>(
        expanded_key: &CSymCryptAesExpandedKey,
        input_buffer: Option<&[u8; AES_BLOCK_SIZE]>,
        output_buffer: &mut [u8; AES_BLOCK_SIZE],
    ) {
        let keys = expanded_key.dec_round_keys::<KEY_ROUNDS>();

        // SAFETY: Intrinsics
        unsafe {
            let mut c = match input_buffer {
                Some(cipher) => _mm_loadu_si128(cipher.as_ptr().cast()),
                None => _mm_loadu_si128(output_buffer.as_ptr().cast()),
            };
            AesXmmImpl::decrypt_block_impl::<KEY_ROUNDS>(keys, &mut c);
            _mm_storeu_si128(output_buffer.as_mut_ptr().cast(), c);
        }
    }
}
