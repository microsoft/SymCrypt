//
// aes_neon.rs  SymCrypt Rust AES implementation with NEON intrinsics
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#[allow(clippy::wildcard_imports)]
#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

use super::{AesImpl, CSymCryptAesExpandedKey, AES_BLOCK_SIZE};

/// NEON-accelerated AES implementation for ARM64 (AArch64) platforms.
/// Uses ARM NEON crypto extensions for hardware-accelerated AES operations.
pub(super) struct AesNeonImpl;

impl AesNeonImpl {
    /// Helper function for encryption of a single AES block. Corresponds to `AES_ENCRYPT_1` in
    /// the SymCrypt C implementation.
    /// SAFETY: The use of intrinsics requires unsafe. `expanded_key` and `c0` must be valid
    /// references.
    #[allow(clippy::needless_range_loop)]
    #[inline]
    unsafe fn encrypt_block_impl<const KEY_ROUNDS: usize>(
        round_keys: &[[u8; 16]; KEY_ROUNDS],
        c0: &mut uint8x16_t, // initial state (plaintext block)
    ) {
        let mut round_key: uint8x16_t;

        for r in 0..KEY_ROUNDS - 2 {
            round_key = vld1q_u8(round_keys[r].as_ptr());

            *c0 = vaeseq_u8(*c0, round_key); // ShiftRows(SubBytes(state ⊕ round_key[r]))
            *c0 = vaesmcq_u8(*c0); // MixColumns(state)
        }

        // Final round: SubBytes → ShiftRows → AddRoundKey
        round_key = vld1q_u8(round_keys[KEY_ROUNDS - 2].as_ptr());
        *c0 = vaeseq_u8(*c0, round_key); // ShiftRows(SubBytes(state ⊕ round_key[KEY_ROUNDS-2]))

        round_key = vld1q_u8(round_keys[KEY_ROUNDS - 1].as_ptr());
        *c0 = veorq_u8(*c0, round_key); // state ⊕ round_key[KEY_ROUNDS-1]
    }

    /// Helper function for decryption of a single AES block. Corresponds to `AES_DECRYPT_1` in
    /// the SymCrypt C implementation.
    /// SAFETY: The use of intrinsics requires unsafe. `expanded_key` and `c0` must be valid
    /// references.
    #[allow(clippy::needless_range_loop)]
    #[inline]
    unsafe fn decrypt_block_impl<const KEY_ROUNDS: usize>(
        round_keys: &[[u8; 16]; KEY_ROUNDS],
        c0: &mut uint8x16_t, // initial state (ciphertext block)
    ) {
        let mut round_key: uint8x16_t;

        for r in 0..KEY_ROUNDS - 2 {
            round_key = vld1q_u8(round_keys[r].as_ptr());
            *c0 = vaesdq_u8(*c0, round_key); // InvShiftRows(InvSubBytes(state ⊕ round_key[r]))
            *c0 = vaesimcq_u8(*c0); // InvMixColumns(state)
        }

        round_key = vld1q_u8(round_keys[KEY_ROUNDS - 2].as_ptr());
        *c0 = vaesdq_u8(*c0, round_key); // InvShiftRows(InvSubBytes(state)) ⊕ round_key[KEY_ROUNDS - 2]

        round_key = vld1q_u8(round_keys[KEY_ROUNDS - 1].as_ptr());
        *c0 = veorq_u8(*c0, round_key); // state ⊕ round_key[KEY_ROUNDS - 1]
    }
}

impl AesImpl for AesNeonImpl {
    #[inline]
    fn sbox_lookup_u32(input: u32) -> u32 {
        // SAFETY: Intrinsics
        unsafe {
            // There is no pure S-box lookup instruction, but the AESE instruction
            // does a ShiftRow followed by a SubBytes.
            // If we duplicate the input value to all 4 lanes, then the ShiftRow does nothing
            // and the SubBytes will do the S-box lookup.
            let x = vreinterpretq_u8_u32(vdupq_n_u32(input));
            let x = vaeseq_u8(x, vreinterpretq_u8_u64(vdupq_n_u64(0)));
            vgetq_lane_u32::<0>(vreinterpretq_u32_u8(x))
        }
    }

    #[inline]
    fn create_decryption_round_key(enc_round_key: &[u8; 16]) -> [u8; 16] {
        let mut output = [0u8; 16];

        // SAFETY: Intrinsics
        unsafe {
            let mut x = vld1q_u8(enc_round_key.as_ptr());
            x = vaesimcq_u8(x);
            vst1q_u8(output.as_mut_ptr(), x);
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
                Some(plain) => vld1q_u8(plain.as_ptr()),
                None => vld1q_u8(output_buffer.as_ptr()),
            };
            AesNeonImpl::encrypt_block_impl::<KEY_ROUNDS>(keys, &mut c);
            vst1q_u8(output_buffer.as_mut_ptr(), c);
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
                Some(cipher) => vld1q_u8(cipher.as_ptr()),
                None => vld1q_u8(output_buffer.as_ptr()),
            };
            AesNeonImpl::decrypt_block_impl::<KEY_ROUNDS>(keys, &mut c);
            vst1q_u8(output_buffer.as_mut_ptr(), c);
        }
    }
}
