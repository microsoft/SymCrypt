//
// aes_xmm.rs  SymCrypt Rust AES implementation with XMM intrinsics
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

use core::cmp;

#[allow(clippy::wildcard_imports)]
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[allow(clippy::wildcard_imports)]
#[cfg(target_arch = "x86")]
use core::arch::x86::*;

use crate::common::InPlaceOrDisjointBuffer;

use super::ghash::{self, ghash_xmm};
use super::{aes_gcm, AesGcmImpl, AesImpl, CSymCryptAesExpandedKey, AES_BLOCK_SIZE};

/// XMM (SSE/AES-NI) accelerated AES implementation for x86/x86_64 platforms.
/// Uses Intel AES-NI instructions for hardware-accelerated AES operations.
pub(super) struct AesXmmImpl;

impl AesXmmImpl {
    /// Helper function for encryption of a single AES block. Corresponds to the `AES_ENCRYPT_N`
    /// macros in the SymCrypt C implementation, where N is the number of blocks.
    #[allow(clippy::needless_range_loop)]
    #[inline]
    fn encrypt_blocks_impl<const KEY_ROUNDS: usize, const NUM_BLOCKS: usize>(
        round_keys: &[[u8; AES_BLOCK_SIZE]; KEY_ROUNDS],
        blocks: &mut [__m128i; NUM_BLOCKS],
    ) {
        // SAFETY: Intrinsics
        unsafe {
            let mut round_key = _mm_loadu_si128(round_keys[0].as_ptr().cast());

            for block in blocks.iter_mut() {
                *block = _mm_xor_si128(*block, round_key);
            }

            for r in 1..KEY_ROUNDS - 1 {
                round_key = _mm_loadu_si128(round_keys[r].as_ptr().cast());
                for block in blocks.iter_mut() {
                    *block = _mm_aesenc_si128(*block, round_key);
                }
            }

            round_key = _mm_loadu_si128(round_keys[KEY_ROUNDS - 1].as_ptr().cast());

            for block in blocks.iter_mut() {
                *block = _mm_aesenclast_si128(*block, round_key);
            }
        }
    }

    /// Helper function for decryption of a single AES block. Corresponds to the `AES_DECRYPT_N`
    /// macros in the SymCrypt C implementation, where N is the number of blocks.
    #[allow(clippy::needless_range_loop)]
    #[inline]
    fn decrypt_blocks_impl<const KEY_ROUNDS: usize, const NUM_BLOCKS: usize>(
        round_keys: &[[u8; AES_BLOCK_SIZE]; KEY_ROUNDS],
        blocks: &mut [__m128i; NUM_BLOCKS],
    ) {
        // SAFETY: Intrinsics
        unsafe {
            let mut round_key = _mm_loadu_si128(round_keys[0].as_ptr().cast());

            for block in blocks.iter_mut() {
                *block = _mm_xor_si128(*block, round_key);
            }

            for r in 1..KEY_ROUNDS - 1 {
                round_key = _mm_loadu_si128(round_keys[r].as_ptr().cast());
                for block in blocks.iter_mut() {
                    *block = _mm_aesdec_si128(*block, round_key);
                }
            }

            round_key = _mm_loadu_si128(round_keys[KEY_ROUNDS - 1].as_ptr().cast());

            for block in blocks.iter_mut() {
                *block = _mm_aesdeclast_si128(*block, round_key);
            }
        }
    }

    /// Performs one full AES round of `NUM_BLOCKS`, with stitched GHASH operation on one block from
    /// `ghash_src`. This corresponds to `AES_FULLROUND_N_GHASH_1` macros in the C implementation.
    /// SAFETY: The use of intrinsics requires unsafe. `ghash_src` must be a valid pointer into the
    /// GHASH source buffer, with at least one block remaining before the end of the buffer.
    #[inline]
    unsafe fn aes_fullround_ghash_1<const NUM_BLOCKS: usize>(
        blocks: &mut [__m128i; NUM_BLOCKS],
        round_key: __m128i,
        ghash_val: __m128i,
        byte_reverse_order: __m128i,
        h_power: __m128i,
        acc_low: __m128i,
        acc_med: __m128i,
        acc_high: __m128i,
    ) -> (__m128i, __m128i, __m128i) {
        // Perform AES encryption round on all blocks
        for block in blocks.iter_mut() {
            *block = _mm_aesenc_si128(*block, round_key);
        }

        // Load and prepare GHASH data
        let r0 = _mm_shuffle_epi8(ghash_val, byte_reverse_order);

        // Perform GHASH multiplication (CLMUL_4)
        let mut t0 = _mm_clmulepi64_si128(r0, h_power, 0x00);
        let mut t1 = _mm_clmulepi64_si128(r0, h_power, 0x11);

        let acc_low = _mm_xor_si128(acc_low, t0);
        let acc_high = _mm_xor_si128(acc_high, t1);

        t0 = _mm_clmulepi64_si128(r0, h_power, 0x01);
        t1 = _mm_clmulepi64_si128(r0, h_power, 0x10);

        let acc_med = _mm_xor_si128(acc_med, t0);
        let acc_med = _mm_xor_si128(acc_med, t1);

        (acc_low, acc_med, acc_high)
    }

    /// Generic AES-GCM encryption with stitched GHASH for N blocks.
    /// This corresponds to `AES_GCM_ENCRYPT_4` and `AES_GCM_ENCRYPT_8` macros in the C
    /// implementation.
    ///
    /// Note: We could determine the number of GHASH rounds at runtime based on the number of blocks
    /// in `ghash_src`, but since it is statically known in most cases, the compiler can optimize
    /// much better if we pass it explicitly.
    #[inline]
    unsafe fn aes_gcm_encrypt_n<const KEY_ROUNDS: usize, const NUM_BLOCKS: usize>(
        round_keys: &[[u8; AES_BLOCK_SIZE]; KEY_ROUNDS],
        blocks: &mut [__m128i; NUM_BLOCKS],
        ghash_src: &[u8],
        ghash_rounds: usize,
        byte_reverse_order: __m128i,
        ghash_expanded_key: &ghash::GHashExpandedKey,
        mut todo: usize,
        mut acc_low: __m128i,
        mut acc_med: __m128i,
        mut acc_high: __m128i,
    ) -> (usize, __m128i, __m128i, __m128i) {
        // Initial round - XOR with first round key
        let mut round_key = _mm_loadu_si128(round_keys[0].as_ptr().cast());
        for block in blocks.iter_mut() {
            *block = _mm_xor_si128(*block, round_key);
        }

        // Perform ghash_rounds AES rounds with stitched GHASH
        for (round, ghash_chunk) in (1..=ghash_rounds).zip(ghash_src.chunks_exact(AES_BLOCK_SIZE)) {
            let ghash_val = _mm_loadu_si128(ghash_chunk.as_ptr().cast());
            round_key = _mm_loadu_si128(round_keys[round].as_ptr().cast());

            let h_power: __m128i = core::mem::transmute(ghash_expanded_key.h_power(todo));

            let result = Self::aes_fullround_ghash_1(
                blocks,
                round_key,
                ghash_val,
                byte_reverse_order,
                h_power,
                acc_low,
                acc_med,
                acc_high,
            );

            acc_low = result.0;
            acc_med = result.1;
            acc_high = result.2;
            todo -= 1;
        }

        // Remaining AES rounds without GHASH
        for round in (ghash_rounds + 1)..(KEY_ROUNDS - 1) {
            round_key = _mm_loadu_si128(round_keys[round].as_ptr().cast());
            for block in blocks.iter_mut() {
                *block = _mm_aesenc_si128(*block, round_key);
            }
        }

        // Final round
        round_key = _mm_loadu_si128(round_keys[KEY_ROUNDS - 1].as_ptr().cast());
        for block in blocks.iter_mut() {
            *block = _mm_aesenclast_si128(*block, round_key);
        }

        (todo, acc_low, acc_med, acc_high)
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
            let mut block: [__m128i; 1] = match input_buffer {
                Some(plain) => [_mm_loadu_si128(plain.as_ptr().cast())],
                None => [_mm_loadu_si128(output_buffer.as_ptr().cast())],
            };
            AesXmmImpl::encrypt_blocks_impl::<KEY_ROUNDS, 1>(keys, &mut block);
            _mm_storeu_si128(output_buffer.as_mut_ptr().cast(), block[0]);
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
            let mut block: [__m128i; 1] = match input_buffer {
                Some(cipher) => [_mm_loadu_si128(cipher.as_ptr().cast())],
                None => [_mm_loadu_si128(output_buffer.as_ptr().cast())],
            };

            AesXmmImpl::decrypt_blocks_impl::<KEY_ROUNDS, 1>(keys, &mut block);
            _mm_storeu_si128(output_buffer.as_mut_ptr().cast(), block[0]);
        }
    }
}

impl AesGcmImpl for AesXmmImpl {
    fn gcm_encrypt_stitched<const KEY_ROUNDS: usize>(
        expanded_key: &CSymCryptAesExpandedKey,
        chaining_value: &mut [u8; AES_BLOCK_SIZE],
        ghash_expanded_key: &ghash::GHashExpandedKey,
        ghash_state: &mut u128,
        mut buffer: InPlaceOrDisjointBuffer<u8>,
    ) {
        // SAFETY: Intrinsics
        unsafe {
            let byte_reverse_order =
                _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            let v_multiplication_constant =
                _mm_set_epi32(0, 0, ghash::V_MULTIPLICATION_CONSTANT, 0);

            let chain_increment_1 = _mm_set_epi32(0, 0, 0, 1);
            let chain_increment_2 = _mm_set_epi32(0, 0, 0, 2);
            let chain_increment_8 = _mm_set_epi32(0, 0, 0, 8);

            let buffer_len = buffer.len();
            debug_assert!(
                buffer_len.is_multiple_of(aes_gcm::GCM_BLOCK_SIZE),
                "Buffer length must be a multiple of GCM block size"
            );

            let mut num_blocks = buffer_len / aes_gcm::GCM_BLOCK_SIZE;
            let mut byte_offset: usize = 0;
            let mut ghash_byte_offset: usize = 0;

            // Early return if no blocks to process
            if num_blocks == 0 {
                return;
            }

            let mut todo = cmp::min(num_blocks, ghash::GHASH_OPTIMIZED_HPOWERS);

            let mut chain = _mm_shuffle_epi8(
                _mm_loadu_si128(chaining_value.as_ptr().cast()),
                byte_reverse_order,
            );
            let mut state = _mm_loadu_si128(core::ptr::from_ref(ghash_state).cast());

            // Initialize GHASH accumulators with state * H^todo
            let (mut a0, mut a1, mut a2) = ghash_xmm::clmul_4(
                state,
                core::mem::transmute(ghash_expanded_key.h_power(todo)),
            );

            // Do 8 blocks of CTR either for tail (if total blocks <8) or for encryption of first 8 blocks
            let mut blocks: [__m128i; 8] = [_mm_setzero_si128(); 8];
            blocks[0] = chain;
            blocks[1] = _mm_add_epi32(chain, chain_increment_1);
            blocks[2] = _mm_add_epi32(chain, chain_increment_2);
            blocks[3] = _mm_add_epi32(blocks[1], chain_increment_2);
            blocks[4] = _mm_add_epi32(blocks[2], chain_increment_2);
            blocks[5] = _mm_add_epi32(blocks[3], chain_increment_2);
            blocks[6] = _mm_add_epi32(blocks[4], chain_increment_2);
            blocks[7] = _mm_add_epi32(blocks[5], chain_increment_2);

            blocks[0] = _mm_shuffle_epi8(blocks[0], byte_reverse_order);
            blocks[1] = _mm_shuffle_epi8(blocks[1], byte_reverse_order);
            blocks[2] = _mm_shuffle_epi8(blocks[2], byte_reverse_order);
            blocks[3] = _mm_shuffle_epi8(blocks[3], byte_reverse_order);
            blocks[4] = _mm_shuffle_epi8(blocks[4], byte_reverse_order);
            blocks[5] = _mm_shuffle_epi8(blocks[5], byte_reverse_order);
            blocks[6] = _mm_shuffle_epi8(blocks[6], byte_reverse_order);
            blocks[7] = _mm_shuffle_epi8(blocks[7], byte_reverse_order);

            Self::encrypt_blocks_impl::<KEY_ROUNDS, 8>(
                expanded_key.enc_round_keys::<KEY_ROUNDS>(),
                &mut blocks,
            );

            if num_blocks >= 8 {
                // Encrypt first 8 blocks - update chain
                chain = _mm_add_epi32(chain, chain_increment_8);

                buffer.storeu_si128(
                    byte_offset + AES_BLOCK_SIZE * 0,
                    _mm_xor_si128(
                        blocks[0],
                        buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 0),
                    ),
                );
                buffer.storeu_si128(
                    byte_offset + AES_BLOCK_SIZE * 1,
                    _mm_xor_si128(
                        blocks[1],
                        buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 1),
                    ),
                );
                buffer.storeu_si128(
                    byte_offset + AES_BLOCK_SIZE * 2,
                    _mm_xor_si128(
                        blocks[2],
                        buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 2),
                    ),
                );
                buffer.storeu_si128(
                    byte_offset + AES_BLOCK_SIZE * 3,
                    _mm_xor_si128(
                        blocks[3],
                        buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 3),
                    ),
                );
                buffer.storeu_si128(
                    byte_offset + AES_BLOCK_SIZE * 4,
                    _mm_xor_si128(
                        blocks[4],
                        buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 4),
                    ),
                );
                buffer.storeu_si128(
                    byte_offset + AES_BLOCK_SIZE * 5,
                    _mm_xor_si128(
                        blocks[5],
                        buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 5),
                    ),
                );
                buffer.storeu_si128(
                    byte_offset + AES_BLOCK_SIZE * 6,
                    _mm_xor_si128(
                        blocks[6],
                        buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 6),
                    ),
                );
                buffer.storeu_si128(
                    byte_offset + AES_BLOCK_SIZE * 7,
                    _mm_xor_si128(
                        blocks[7],
                        buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 7),
                    ),
                );

                byte_offset += AES_BLOCK_SIZE * 8;
                // ghash_byte_offset stays at 0 - we GHASH the first 8 blocks that were just encrypted

                while num_blocks >= 16 {
                    // In this loop we always have 8 blocks to encrypt and we have already encrypted the previous 8 blocks ready for GHASH
                    blocks[0] = chain;
                    blocks[1] = _mm_add_epi32(chain, chain_increment_1);
                    blocks[2] = _mm_add_epi32(chain, chain_increment_2);
                    blocks[3] = _mm_add_epi32(blocks[1], chain_increment_2);
                    blocks[4] = _mm_add_epi32(blocks[2], chain_increment_2);
                    blocks[5] = _mm_add_epi32(blocks[3], chain_increment_2);
                    blocks[6] = _mm_add_epi32(blocks[4], chain_increment_2);
                    blocks[7] = _mm_add_epi32(blocks[5], chain_increment_2);
                    chain = _mm_add_epi32(blocks[6], chain_increment_2);

                    blocks[0] = _mm_shuffle_epi8(blocks[0], byte_reverse_order);
                    blocks[1] = _mm_shuffle_epi8(blocks[1], byte_reverse_order);
                    blocks[2] = _mm_shuffle_epi8(blocks[2], byte_reverse_order);
                    blocks[3] = _mm_shuffle_epi8(blocks[3], byte_reverse_order);
                    blocks[4] = _mm_shuffle_epi8(blocks[4], byte_reverse_order);
                    blocks[5] = _mm_shuffle_epi8(blocks[5], byte_reverse_order);
                    blocks[6] = _mm_shuffle_epi8(blocks[6], byte_reverse_order);
                    blocks[7] = _mm_shuffle_epi8(blocks[7], byte_reverse_order);

                    let result = Self::aes_gcm_encrypt_n::<KEY_ROUNDS, 8>(
                        expanded_key.enc_round_keys::<KEY_ROUNDS>(),
                        &mut blocks,
                        &buffer.dst()[ghash_byte_offset..ghash_byte_offset + 8 * AES_BLOCK_SIZE],
                        8, // ghash_rounds
                        byte_reverse_order,
                        ghash_expanded_key,
                        todo,
                        a0,
                        a1,
                        a2,
                    );

                    ghash_byte_offset += AES_BLOCK_SIZE * 8; // Move GHASH index forward by ghash_rounds (8 blocks)
                    todo = result.0;
                    a0 = result.1;
                    a1 = result.2;
                    a2 = result.3;

                    buffer.storeu_si128(
                        byte_offset + AES_BLOCK_SIZE * 0,
                        _mm_xor_si128(
                            blocks[0],
                            buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 0),
                        ),
                    );
                    buffer.storeu_si128(
                        byte_offset + AES_BLOCK_SIZE * 1,
                        _mm_xor_si128(
                            blocks[1],
                            buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 1),
                        ),
                    );
                    buffer.storeu_si128(
                        byte_offset + AES_BLOCK_SIZE * 2,
                        _mm_xor_si128(
                            blocks[2],
                            buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 2),
                        ),
                    );
                    buffer.storeu_si128(
                        byte_offset + AES_BLOCK_SIZE * 3,
                        _mm_xor_si128(
                            blocks[3],
                            buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 3),
                        ),
                    );
                    buffer.storeu_si128(
                        byte_offset + AES_BLOCK_SIZE * 4,
                        _mm_xor_si128(
                            blocks[4],
                            buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 4),
                        ),
                    );
                    buffer.storeu_si128(
                        byte_offset + AES_BLOCK_SIZE * 5,
                        _mm_xor_si128(
                            blocks[5],
                            buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 5),
                        ),
                    );
                    buffer.storeu_si128(
                        byte_offset + AES_BLOCK_SIZE * 6,
                        _mm_xor_si128(
                            blocks[6],
                            buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 6),
                        ),
                    );
                    buffer.storeu_si128(
                        byte_offset + AES_BLOCK_SIZE * 7,
                        _mm_xor_si128(
                            blocks[7],
                            buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 7),
                        ),
                    );

                    byte_offset += AES_BLOCK_SIZE * 8;
                    num_blocks -= 8;

                    if todo == 0 {
                        state = ghash_xmm::modreduce(v_multiplication_constant, a0, a1, a2);

                        todo = cmp::min(num_blocks, ghash::GHASH_OPTIMIZED_HPOWERS);
                        let result = ghash_xmm::clmul_4(
                            state,
                            core::mem::transmute(ghash_expanded_key.h_power(todo)),
                        );
                        a0 = result.0;
                        a1 = result.1;
                        a2 = result.2;
                    }
                }

                // We now have at least 8 blocks of encrypted data to GHASH and at most 7 blocks left to encrypt
                // Do 8 blocks of GHASH in parallel with generating 0, 4, or 8 AES-CTR blocks for tail encryption
                num_blocks -= 8;
                if num_blocks > 0 {
                    // Generate CTR blocks for tail
                    blocks[0] = chain;
                    blocks[1] = _mm_add_epi32(chain, chain_increment_1);
                    blocks[2] = _mm_add_epi32(chain, chain_increment_2);
                    blocks[3] = _mm_add_epi32(blocks[1], chain_increment_2);
                    blocks[4] = _mm_add_epi32(blocks[2], chain_increment_2);

                    blocks[0] = _mm_shuffle_epi8(blocks[0], byte_reverse_order);
                    blocks[1] = _mm_shuffle_epi8(blocks[1], byte_reverse_order);
                    blocks[2] = _mm_shuffle_epi8(blocks[2], byte_reverse_order);
                    blocks[3] = _mm_shuffle_epi8(blocks[3], byte_reverse_order);

                    if num_blocks > 4 {
                        // Generate 8 blocks for tail
                        blocks[5] = _mm_add_epi32(blocks[4], chain_increment_1);
                        blocks[6] = _mm_add_epi32(blocks[4], chain_increment_2);
                        blocks[4] = _mm_shuffle_epi8(blocks[4], byte_reverse_order);
                        blocks[5] = _mm_shuffle_epi8(blocks[5], byte_reverse_order);
                        blocks[6] = _mm_shuffle_epi8(blocks[6], byte_reverse_order);

                        let result = Self::aes_gcm_encrypt_n::<KEY_ROUNDS, 8>(
                            expanded_key.enc_round_keys::<KEY_ROUNDS>(),
                            &mut blocks,
                            &buffer.dst()
                                [ghash_byte_offset..ghash_byte_offset + 8 * AES_BLOCK_SIZE],
                            8,
                            byte_reverse_order,
                            ghash_expanded_key,
                            todo,
                            a0,
                            a1,
                            a2,
                        );

                        todo = result.0;
                        a0 = result.1;
                        a1 = result.2;
                        a2 = result.3;
                    } else {
                        // Generate 4 blocks for tail
                        let (blocks_4, _) = blocks.split_at_mut(4);
                        let result = Self::aes_gcm_encrypt_n::<KEY_ROUNDS, 4>(
                            expanded_key.enc_round_keys::<KEY_ROUNDS>(),
                            blocks_4.try_into().unwrap(),
                            &buffer.dst()
                                [ghash_byte_offset..ghash_byte_offset + 8 * AES_BLOCK_SIZE],
                            8,
                            byte_reverse_order,
                            ghash_expanded_key,
                            todo,
                            a0,
                            a1,
                            a2,
                        );

                        todo = result.0;
                        a0 = result.1;
                        a1 = result.2;
                        a2 = result.3;
                    }

                    if todo == 0 {
                        state = ghash_xmm::modreduce(v_multiplication_constant, a0, a1, a2);

                        todo = cmp::min(num_blocks, ghash::GHASH_OPTIMIZED_HPOWERS);
                        let result = ghash_xmm::clmul_4(
                            state,
                            core::mem::transmute(ghash_expanded_key.h_power(todo)),
                        );
                        a0 = result.0;
                        a1 = result.1;
                        a2 = result.2;
                    }
                } else {
                    for i in (1..=8).rev() {
                        let r0 = _mm_shuffle_epi8(
                            buffer.loadu_si128_dst(ghash_byte_offset),
                            byte_reverse_order,
                        );
                        ghash_byte_offset += AES_BLOCK_SIZE;

                        let result = ghash_xmm::clmul_acc_4(
                            r0,
                            core::mem::transmute(ghash_expanded_key.h_power(i)),
                            a0,
                            a1,
                            a2,
                        );
                        a0 = result.0;
                        a1 = result.1;
                        a2 = result.2;
                    }

                    state = ghash_xmm::modreduce(v_multiplication_constant, a0, a1, a2);
                }
            }

            // Tail processing: Encrypt 1-7 blocks with pre-generated AES-CTR blocks and GHASH the results
            if num_blocks > 0 {
                // Process blocks in pairs where possible
                while num_blocks >= 2 {
                    chain = _mm_add_epi32(chain, chain_increment_2);

                    let r0 = _mm_xor_si128(
                        blocks[0],
                        buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 0),
                    );
                    let r1 = _mm_xor_si128(
                        blocks[1],
                        buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 1),
                    );

                    buffer.storeu_si128(byte_offset + AES_BLOCK_SIZE * 0, r0);
                    buffer.storeu_si128(byte_offset + AES_BLOCK_SIZE * 1, r1);

                    let r0 = _mm_shuffle_epi8(r0, byte_reverse_order);
                    let r1 = _mm_shuffle_epi8(r1, byte_reverse_order);

                    let result = ghash_xmm::clmul_acc_4(
                        r0,
                        core::mem::transmute(ghash_expanded_key.h_power(todo)),
                        a0,
                        a1,
                        a2,
                    );
                    a0 = result.0;
                    a1 = result.1;
                    a2 = result.2;

                    let result = ghash_xmm::clmul_acc_4(
                        r1,
                        core::mem::transmute(ghash_expanded_key.h_power(todo - 1)),
                        a0,
                        a1,
                        a2,
                    );
                    a0 = result.0;
                    a1 = result.1;
                    a2 = result.2;

                    byte_offset += 2 * AES_BLOCK_SIZE;
                    todo -= 2;
                    num_blocks -= 2;

                    // Shift blocks for next iteration
                    blocks[0] = blocks[2];
                    blocks[1] = blocks[3];
                    blocks[2] = blocks[4];
                    blocks[3] = blocks[5];
                    blocks[4] = blocks[6];
                }

                // Process final block if odd number remains
                if num_blocks > 0 {
                    chain = _mm_add_epi32(chain, chain_increment_1);

                    let r0 =
                        _mm_xor_si128(blocks[0], buffer.loadu_si128_src(byte_offset));

                    buffer.storeu_si128(byte_offset, r0);

                    let r0 = _mm_shuffle_epi8(r0, byte_reverse_order);

                    let result = ghash_xmm::clmul_acc_4(
                        r0,
                        core::mem::transmute(ghash_expanded_key.h_power(1)),
                        a0,
                        a1,
                        a2,
                    );
                    a0 = result.0;
                    a1 = result.1;
                    a2 = result.2;
                }

                // Finalize GHASH for tail blocks
                state = ghash_xmm::modreduce(v_multiplication_constant, a0, a1, a2);
            }

            chain = _mm_shuffle_epi8(chain, byte_reverse_order);
            _mm_storeu_si128(chaining_value.as_mut_ptr().cast(), chain);
            _mm_storeu_si128(core::ptr::from_mut(ghash_state).cast(), state);
        }
    }

    fn gcm_decrypt_stitched<const KEY_ROUNDS: usize>(
        expanded_key: &CSymCryptAesExpandedKey,
        chaining_value: &mut [u8; AES_BLOCK_SIZE],
        ghash_expanded_key: &ghash::GHashExpandedKey,
        ghash_state: &mut u128,
        mut buffer: InPlaceOrDisjointBuffer<u8>,
    ) {
        // SAFETY: Intrinsics
        unsafe {
            let byte_reverse_order =
                _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            let v_multiplication_constant =
                _mm_set_epi32(0, 0, ghash::V_MULTIPLICATION_CONSTANT, 0);

            let chain_increment_1 = _mm_set_epi32(0, 0, 0, 1);
            let chain_increment_2 = _mm_set_epi32(0, 0, 0, 2);

            let buffer_len = buffer.len();
            debug_assert!(
                buffer_len.is_multiple_of(aes_gcm::GCM_BLOCK_SIZE),
                "Buffer length must be a multiple of GCM block size"
            );

            let mut num_blocks = buffer_len / aes_gcm::GCM_BLOCK_SIZE;
            let mut byte_offset: usize = 0;
            let mut ghash_byte_offset: usize = 0;

            // Early return if no blocks to process
            if num_blocks == 0 {
                return;
            }

            let mut todo = cmp::min(num_blocks, ghash::GHASH_OPTIMIZED_HPOWERS);

            let mut chain = _mm_shuffle_epi8(
                _mm_loadu_si128(chaining_value.as_ptr().cast()),
                byte_reverse_order,
            );
            let mut state = _mm_loadu_si128(core::ptr::from_ref(ghash_state).cast());

            // Initialize GHASH accumulators with state * H^todo
            let (mut a0, mut a1, mut a2) = ghash_xmm::clmul_4(
                state,
                core::mem::transmute(ghash_expanded_key.h_power(todo)),
            );

            let mut blocks: [__m128i; 8] = [_mm_setzero_si128(); 8];

            // Main loop: Process 8 blocks at a time
            while num_blocks >= 8 {
                // In this loop we always have 8 blocks to decrypt and GHASH
                blocks[0] = chain;
                blocks[1] = _mm_add_epi32(chain, chain_increment_1);
                blocks[2] = _mm_add_epi32(chain, chain_increment_2);
                blocks[3] = _mm_add_epi32(blocks[1], chain_increment_2);
                blocks[4] = _mm_add_epi32(blocks[2], chain_increment_2);
                blocks[5] = _mm_add_epi32(blocks[3], chain_increment_2);
                blocks[6] = _mm_add_epi32(blocks[4], chain_increment_2);
                blocks[7] = _mm_add_epi32(blocks[5], chain_increment_2);
                chain = _mm_add_epi32(blocks[6], chain_increment_2);

                blocks[0] = _mm_shuffle_epi8(blocks[0], byte_reverse_order);
                blocks[1] = _mm_shuffle_epi8(blocks[1], byte_reverse_order);
                blocks[2] = _mm_shuffle_epi8(blocks[2], byte_reverse_order);
                blocks[3] = _mm_shuffle_epi8(blocks[3], byte_reverse_order);
                blocks[4] = _mm_shuffle_epi8(blocks[4], byte_reverse_order);
                blocks[5] = _mm_shuffle_epi8(blocks[5], byte_reverse_order);
                blocks[6] = _mm_shuffle_epi8(blocks[6], byte_reverse_order);
                blocks[7] = _mm_shuffle_epi8(blocks[7], byte_reverse_order);

                let result = Self::aes_gcm_encrypt_n::<KEY_ROUNDS, 8>(
                    expanded_key.enc_round_keys::<KEY_ROUNDS>(),
                    &mut blocks,
                    &buffer.src()[ghash_byte_offset..ghash_byte_offset + 8 * AES_BLOCK_SIZE],
                    8, // ghash_rounds
                    byte_reverse_order,
                    ghash_expanded_key,
                    todo,
                    a0,
                    a1,
                    a2,
                );

                ghash_byte_offset += AES_BLOCK_SIZE * 8; // Move GHASH index forward by ghash_rounds (8 blocks)
                todo = result.0;
                a0 = result.1;
                a1 = result.2;
                a2 = result.3;

                buffer.storeu_si128(
                    byte_offset + AES_BLOCK_SIZE * 0,
                    _mm_xor_si128(
                        blocks[0],
                        buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 0),
                    ),
                );
                buffer.storeu_si128(
                    byte_offset + AES_BLOCK_SIZE * 1,
                    _mm_xor_si128(
                        blocks[1],
                        buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 1),
                    ),
                );
                buffer.storeu_si128(
                    byte_offset + AES_BLOCK_SIZE * 2,
                    _mm_xor_si128(
                        blocks[2],
                        buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 2),
                    ),
                );
                buffer.storeu_si128(
                    byte_offset + AES_BLOCK_SIZE * 3,
                    _mm_xor_si128(
                        blocks[3],
                        buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 3),
                    ),
                );
                buffer.storeu_si128(
                    byte_offset + AES_BLOCK_SIZE * 4,
                    _mm_xor_si128(
                        blocks[4],
                        buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 4),
                    ),
                );
                buffer.storeu_si128(
                    byte_offset + AES_BLOCK_SIZE * 5,
                    _mm_xor_si128(
                        blocks[5],
                        buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 5),
                    ),
                );
                buffer.storeu_si128(
                    byte_offset + AES_BLOCK_SIZE * 6,
                    _mm_xor_si128(
                        blocks[6],
                        buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 6),
                    ),
                );
                buffer.storeu_si128(
                    byte_offset + AES_BLOCK_SIZE * 7,
                    _mm_xor_si128(
                        blocks[7],
                        buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 7),
                    ),
                );

                byte_offset += AES_BLOCK_SIZE * 8;
                num_blocks -= 8;

                if todo == 0 {
                    state = ghash_xmm::modreduce(v_multiplication_constant, a0, a1, a2);

                    if num_blocks > 0 {
                        todo = cmp::min(num_blocks, ghash::GHASH_OPTIMIZED_HPOWERS);
                        let result = ghash_xmm::clmul_4(
                            state,
                            core::mem::transmute(ghash_expanded_key.h_power(todo)),
                        );
                        a0 = result.0;
                        a1 = result.1;
                        a2 = result.2;
                    }
                }
            }

            // Tail processing: 1-7 blocks remain
            if num_blocks > 0 {
                // We have 1-7 blocks to GHASH and decrypt
                // Do the exact number of GHASH blocks we need in parallel with generating either 4 or 8 blocks of AES-CTR
                blocks[0] = chain;
                blocks[1] = _mm_add_epi32(chain, chain_increment_1);
                blocks[2] = _mm_add_epi32(chain, chain_increment_2);
                blocks[3] = _mm_add_epi32(blocks[1], chain_increment_2);
                blocks[4] = _mm_add_epi32(blocks[2], chain_increment_2);

                blocks[0] = _mm_shuffle_epi8(blocks[0], byte_reverse_order);
                blocks[1] = _mm_shuffle_epi8(blocks[1], byte_reverse_order);
                blocks[2] = _mm_shuffle_epi8(blocks[2], byte_reverse_order);
                blocks[3] = _mm_shuffle_epi8(blocks[3], byte_reverse_order);

                if num_blocks > 4 {
                    blocks[5] = _mm_add_epi32(blocks[4], chain_increment_1);
                    blocks[6] = _mm_add_epi32(blocks[4], chain_increment_2);

                    blocks[4] = _mm_shuffle_epi8(blocks[4], byte_reverse_order);
                    blocks[5] = _mm_shuffle_epi8(blocks[5], byte_reverse_order);
                    blocks[6] = _mm_shuffle_epi8(blocks[6], byte_reverse_order);

                    let result = Self::aes_gcm_encrypt_n::<KEY_ROUNDS, 8>(
                        expanded_key.enc_round_keys::<KEY_ROUNDS>(),
                        &mut blocks,
                        &buffer.src()
                            [ghash_byte_offset..ghash_byte_offset + num_blocks * AES_BLOCK_SIZE],
                        num_blocks,
                        byte_reverse_order,
                        ghash_expanded_key,
                        todo,
                        a0,
                        a1,
                        a2,
                    );

                    a0 = result.1;
                    a1 = result.2;
                    a2 = result.3;
                } else {
                    let (blocks_4, _) = blocks.split_at_mut(4);
                    let result = Self::aes_gcm_encrypt_n::<KEY_ROUNDS, 4>(
                        expanded_key.enc_round_keys::<KEY_ROUNDS>(),
                        blocks_4.try_into().unwrap(),
                        &buffer.src()
                            [ghash_byte_offset..ghash_byte_offset + num_blocks * AES_BLOCK_SIZE],
                        num_blocks,
                        byte_reverse_order,
                        ghash_expanded_key,
                        todo,
                        a0,
                        a1,
                        a2,
                    );

                    a0 = result.1;
                    a1 = result.2;
                    a2 = result.3;
                }

                state = ghash_xmm::modreduce(v_multiplication_constant, a0, a1, a2);

                // Decrypt 1-7 blocks with pre-generated AES-CTR blocks
                while num_blocks >= 2 {
                    chain = _mm_add_epi32(chain, chain_increment_2);

                    buffer.storeu_si128(
                        byte_offset + AES_BLOCK_SIZE * 0,
                        _mm_xor_si128(
                            blocks[0],
                            buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 0),
                        ),
                    );
                    buffer.storeu_si128(
                        byte_offset + AES_BLOCK_SIZE * 1,
                        _mm_xor_si128(
                            blocks[1],
                            buffer.loadu_si128_src(byte_offset + AES_BLOCK_SIZE * 1),
                        ),
                    );

                    byte_offset += 2 * AES_BLOCK_SIZE;
                    num_blocks -= 2;

                    // Shift blocks for next iteration
                    blocks[0] = blocks[2];
                    blocks[1] = blocks[3];
                    blocks[2] = blocks[4];
                    blocks[3] = blocks[5];
                    blocks[4] = blocks[6];
                }

                if num_blocks > 0 {
                    chain = _mm_add_epi32(chain, chain_increment_1);

                    buffer.storeu_si128(
                        byte_offset,
                        _mm_xor_si128(blocks[0], buffer.loadu_si128_src(byte_offset)),
                    );
                }
            }

            chain = _mm_shuffle_epi8(chain, byte_reverse_order);
            _mm_storeu_si128(chaining_value.as_mut_ptr().cast(), chain);
            _mm_storeu_si128(core::ptr::from_mut(ghash_state).cast(), state);
        }
    }
}
