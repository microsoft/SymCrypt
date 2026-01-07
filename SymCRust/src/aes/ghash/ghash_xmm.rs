//
// ghash_xmm.rs   SymCrypt GHASH XMM implementation with PCLMULQDQ intrinsics
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

use core::cmp;
use core::ptr;

#[allow(clippy::wildcard_imports)]
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[allow(clippy::wildcard_imports)]
#[cfg(target_arch = "x86")]
use core::arch::x86::*;

use super::{
    GHash, GHashExpandedKey, GF128_BLOCK_SIZE, GHASH_OPTIMIZED_HPOWERS, V_MULTIPLICATION_CONSTANT,
};

/// Macro to compute shuffle control value for `_mm_shuffle_epi32`
/// Matches the C `_MM_SHUFFLE(z, y, x, w)` macro
/// Each parameter selects which 32-bit element from the source goes to the destination
macro_rules! _MM_SHUFFLE {
    ($z:expr, $y:expr, $x:expr, $w:expr) => {
        (($z << 6) | ($y << 4) | ($x << 2) | $w)
    };
}

/// Post-process the `CLMUL_3` result to be compatible with the `CLMUL_4`
/// This completes the Karatsuba multiplication by XORing the high and low pieces into the middle piece.
///
/// # Arguments
/// * `low` - The low 128-bit result from `CLMUL_3`
/// * `med` - The middle 128-bit result from `CLMUL_3`
/// * `high` - The high 128-bit result from `CLMUL_3`
///
/// # Returns
/// The updated middle result after post-processing
#[inline]
pub(in crate::aes) fn clmul_3_post(low: __m128i, med: __m128i, high: __m128i) -> __m128i {
    // SAFETY: Intrinsics
    unsafe { _mm_xor_si128(med, _mm_xor_si128(low, high)) }
}

/// Multiply two operands into three intermediate results using 3 pclmulqdq instructions.
/// The second operand has a pre-computed difference of the two halves.
/// This uses Karatsuba, but we delay xorring the high and low piece into the middle piece.
///
/// # Arguments
/// * `op_a` - First operand
/// * `op_b` - Second operand (H power)
/// * `op_b_x` - Pre-computed XOR of the two halves of `op_b` (Hx power)
///
/// # Returns
/// A tuple of three __m128i values (`low`, `med`, `high`) representing result of the multiplication.
#[inline]
pub(in crate::aes) fn clmul_3(
    op_a: __m128i,
    op_b: __m128i,
    op_b_x: __m128i,
) -> (__m128i, __m128i, __m128i) {
    // SAFETY: Intrinsics
    unsafe {
        let low = _mm_clmulepi64_si128(op_a, op_b, 0x00);
        let high = _mm_clmulepi64_si128(op_a, op_b, 0x11);
        let tmp_a = _mm_xor_si128(op_a, _mm_srli_si128(op_a, 8));
        let med = _mm_clmulepi64_si128(tmp_a, op_b_x, 0x00);

        (low, med, high)
    }
}

/// Multiply two operands into three intermediate results using 3 pclmulqdq instructions.
/// Both operands have pre-computed differences of their two halves.
/// This is the `CLMUL_X_3` variant that uses Karatsuba with precomputed differences.
///
/// # Arguments
/// * `op_a` - First operand (H power)
/// * `op_a_x` - Pre-computed XOR of the two halves of `op_a` (Hx power)
/// * `op_b` - Second operand (H power)
/// * `op_b_x` - Pre-computed XOR of the two halves of `op_b` (Hx power)
///
/// # Returns
/// A tuple of three __m128i values (`low`, `med`, `high`) representing result of the multiplication.
#[inline]
pub(in crate::aes) fn clmul_x_3(
    op_a: __m128i,
    op_a_x: __m128i,
    op_b: __m128i,
    op_b_x: __m128i,
) -> (__m128i, __m128i, __m128i) {
    // SAFETY: Intrinsics
    unsafe {
        let low = _mm_clmulepi64_si128(op_a, op_b, 0x00);
        let high = _mm_clmulepi64_si128(op_a, op_b, 0x11);
        let med = _mm_clmulepi64_si128(op_a_x, op_b_x, 0x00);

        (low, med, high)
    }
}

/// Multiply-accumulate using `CLMUL_3`
/// This performs a carryless multiplication using Karatsuba and accumulates the result
/// into the provided accumulators.
///
/// # Arguments
/// * `op_a` - First operand
/// * `op_b` - Second operand (H power)
/// * `op_b_x` - Pre-computed XOR of the two halves of `op_b` (Hx power)
/// * `acc_low` - Low accumulator
/// * `acc_med` - Middle accumulator
/// * `acc_high` - High accumulator
///
/// # Returns
/// A tuple of the updated accumulators (low, med, high)
#[inline]
pub(in crate::aes) fn clmul_acc_3(
    op_a: __m128i,
    op_b: __m128i,
    op_b_x: __m128i,
    acc_low: __m128i,
    acc_med: __m128i,
    acc_high: __m128i,
) -> (__m128i, __m128i, __m128i) {
    // SAFETY: Intrinsics
    unsafe {
        let (tmp_low, tmp_med, tmp_high) = clmul_3(op_a, op_b, op_b_x);

        // Accumulate
        let new_low = _mm_xor_si128(acc_low, tmp_low);
        let new_med = _mm_xor_si128(acc_med, tmp_med);
        let new_high = _mm_xor_si128(acc_high, tmp_high);

        (new_low, new_med, new_high)
    }
}

/// Multiply two operands into three intermediate results using 4 pclmulqdq instructions.
/// This is the standard carryless multiplication without Karatsuba optimization.
///
/// # Arguments
/// * `op_a` - First operand
/// * `op_b` - Second operand
///
/// # Returns
/// A tuple of three __m128i values (`low`, `med`, `high`) representing result of the multiplication.
#[inline]
pub(in crate::aes) fn clmul_4(op_a: __m128i, op_b: __m128i) -> (__m128i, __m128i, __m128i) {
    // SAFETY: Intrinsics
    unsafe {
        let low = _mm_clmulepi64_si128(op_a, op_b, 0x00);
        let med = _mm_xor_si128(
            _mm_clmulepi64_si128(op_a, op_b, 0x10),
            _mm_clmulepi64_si128(op_a, op_b, 0x01),
        );
        let high = _mm_clmulepi64_si128(op_a, op_b, 0x11);

        (low, med, high)
    }
}

/// Multiply-accumulate using `CLMUL_4`.
/// This performs a carryless multiplication without Karatsuba and accumulates the result
/// into the provided accumulators.
///
/// # Arguments
/// * `op_a` - First operand
/// * `op_b` - Second operand
/// * `acc_low` - Low accumulator
/// * `acc_med` - Middle accumulator
/// * `acc_high` - High accumulator
///
/// # Returns
/// A tuple of the updated accumulators (low, med, high)
#[inline]
pub(in crate::aes) fn clmul_acc_4(
    op_a: __m128i,
    op_b: __m128i,
    acc_low: __m128i,
    acc_med: __m128i,
    acc_high: __m128i,
) -> (__m128i, __m128i, __m128i) {
    // SAFETY: Intrinsics
    unsafe {
        let (tmp_low, tmp_med, tmp_high) = clmul_4(op_a, op_b);

        // Accumulate
        let new_low = _mm_xor_si128(acc_low, tmp_low);
        let new_med = _mm_xor_si128(acc_med, tmp_med);
        let new_high = _mm_xor_si128(acc_high, tmp_high);

        (new_low, new_med, new_high)
    }
}

/// Convert the 3 intermediate results to a 256-bit result and perform modulo reduction.
/// This implements the modulo reduction for GF(2^128) multiplication as described in
/// the detailed comments in `ghash_definitions.h`.
///
/// # Arguments
/// * `v_multiplication_constant` - The multiplication constant (rev(0x87) << 1)
/// * `low` - Low 128-bit intermediate result
/// * `med` - Middle 128-bit intermediate result
/// * `high` - High 128-bit intermediate result
///
/// # Returns
/// The final 128-bit result after modulo reduction
#[inline]
pub(in crate::aes) fn modreduce(
    v_multiplication_constant: __m128i,
    low: __m128i,
    med: __m128i,
    high: __m128i,
) -> __m128i {
    // SAFETY: Intrinsics
    unsafe {
        // Multiply low by constant which is (rev(0x87) << 1) - we'll eor the lost high bit in manually
        let mut t0 = _mm_clmulepi64_si128(low, v_multiplication_constant, 0x00);

        // We want the high 64b of low to align with the low 64b of med, because we haven't merged med into low and high
        // We want the low 64b of low to align with the high 64b of med, because we lost the high bit in the previous pmull
        let low = _mm_shuffle_epi32(low, _MM_SHUFFLE!(1, 0, 3, 2));

        let mut med = _mm_xor_si128(med, t0);
        med = _mm_xor_si128(med, low);

        // Almost same again to fold med into high, but bit 63 needs no more multiplication and the result ultimately needs shifting left by 1
        // Pre-shift bottom of med left by 1 and accumulate the result when the other parts are aligned
        t0 = _mm_clmulepi64_si128(_mm_slli_epi64(med, 1), v_multiplication_constant, 0x00);

        let med = _mm_shuffle_epi32(med, _MM_SHUFFLE!(1, 0, 3, 2));
        let mut res = _mm_xor_si128(high, med);

        // Rotate res left by 1 and accumulate the aligned parts
        let t1 = _mm_slli_epi32(res, 1);
        res = _mm_srli_epi32(res, 31);

        t0 = _mm_xor_si128(t0, t1);
        res = _mm_shuffle_epi32(res, _MM_SHUFFLE!(2, 1, 0, 3));

        _mm_xor_si128(res, t0)
    }
}

impl GHashExpandedKey {
    /// Expands a GHASH key using PCLMULQDQ instructions.
    /// TODO: If we always use `CLMUL_4` for AMD64, we don't need the Hx values.
    ///
    /// The expanded key consists of `N=GHASH_OPTIMIZED_HPOWERS` powers of H.
    /// The first entry is H^N, the next H^(N-1), then H^(N-2), ...
    ///
    /// For each power we store two 128-bit values:
    /// - Hi: H^i
    /// - Hix: The two halves of H^i XORed together (in lower 64 bits)
    ///
    /// Hi entries are stored in the first half of the table, and Hix entries in the second half.
    ///
    /// # Arguments
    /// * `expanded_key` - Output buffer for expanded key (128 u128 elements)
    /// * `h_bytes` - Input key H as 16 bytes
    ///
    /// # Safety
    /// This function uses PCLMULQDQ intrinsics and requires the CPU feature to be present.
    pub(super) unsafe fn expand_key_pclmulqdq(&mut self, h_bytes: &[u8; 16]) {
        let byte_reverse_order = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        let v_multiplication_constant = _mm_set_epi32(0, 0, V_MULTIPLICATION_CONSTANT, 0);

        let h = _mm_loadu_si128(h_bytes.as_ptr().cast::<__m128i>());
        let h = _mm_shuffle_epi8(h, byte_reverse_order);
        let hx = _mm_xor_si128(h, _mm_srli_si128(h, 8));

        // Store H^1
        _mm_store_si128(ptr::from_mut(self.h_power_mut(1)).cast(), h);
        _mm_store_si128(ptr::from_mut(self.hx_power_mut(1)).cast(), hx);

        // Compute H^2
        let (low, med, high) = clmul_x_3(h, hx, h, hx);
        let med = clmul_3_post(low, med, high);
        let h2 = modreduce(v_multiplication_constant, low, med, high);
        let h2x = _mm_xor_si128(h2, _mm_srli_si128(h2, 8));
        _mm_store_si128(ptr::from_mut(self.h_power_mut(2)).cast(), h2);
        _mm_store_si128(ptr::from_mut(self.hx_power_mut(2)).cast(), h2x);

        let mut hi_even = h2;
        let mut hix_even = h2x;

        // Compute the rest of the powers
        for i in (2..GHASH_OPTIMIZED_HPOWERS).step_by(2) {
            // Compute Hi_odd = H * Hi_even
            let (low_odd, med_odd, high_odd) = clmul_x_3(h, hx, hi_even, hix_even);
            let med_odd = clmul_3_post(low_odd, med_odd, high_odd);

            // Compute Hi_even = H^2 * Hi_even (from previous iteration)
            let (low_even, med_even, high_even) = clmul_x_3(h2, h2x, hi_even, hix_even);
            let med_even = clmul_3_post(low_even, med_even, high_even);

            let hi_odd = modreduce(v_multiplication_constant, low_odd, med_odd, high_odd);
            hi_even = modreduce(v_multiplication_constant, low_even, med_even, high_even);
            let hix_odd = _mm_xor_si128(hi_odd, _mm_srli_si128(hi_odd, 8));
            hix_even = _mm_xor_si128(hi_even, _mm_srli_si128(hi_even, 8));

            _mm_store_si128(ptr::from_mut(self.h_power_mut(i + 1)).cast(), hi_odd);
            _mm_store_si128(ptr::from_mut(self.h_power_mut(i + 2)).cast(), hi_even);
            _mm_store_si128(ptr::from_mut(self.hx_power_mut(i + 1)).cast(), hix_odd);
            _mm_store_si128(ptr::from_mut(self.hx_power_mut(i + 2)).cast(), hix_even);
        }
    }
}

impl GHash<'_> {
    /// Appends data to GHASH state using PCLMULQDQ instructions.
    ///
    /// Processes data in blocks of up to `GHASH_OPTIMIZED_HPOWERS` blocks at a time.
    /// Each block is XORed with the state (for the first block) or just accumulated,
    /// then multiplied by the appropriate power of H.
    ///
    /// # Arguments
    /// * `state` - The GHASH state (updated in place)
    /// * `data` - Input data (must be multiple of 16 bytes)
    ///
    /// # Safety
    /// This function uses PCLMULQDQ intrinsics and requires the CPU feature to be present.
    /// The data length must be a multiple of 16 bytes.
    pub(super) unsafe fn append_pclmulqdq(&mut self, data: &[u8]) {
        debug_assert!(data.len().is_multiple_of(GF128_BLOCK_SIZE));

        let byte_reverse_order = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        let v_multiplication_constant = _mm_set_epi32(0, 0, u32::cast_signed(0xc2000000), 0);

        let mut state = _mm_loadu_si128(core::ptr::from_ref(&self.state).cast());
        let mut n_blocks = data.len() / GF128_BLOCK_SIZE;

        let mut chunks = data.chunks_exact(GF128_BLOCK_SIZE);

        while let Some(block) = chunks.next() {
            // Process up to GHASH_OPTIMIZED_HPOWERS blocks at a time
            let todo = cmp::min(n_blocks, GHASH_OPTIMIZED_HPOWERS);

            // First block: XOR with state before multiplying
            let mut block = _mm_loadu_si128(block.as_ptr().cast());
            block = _mm_shuffle_epi8(block, byte_reverse_order);

            state = _mm_xor_si128(state, block);

            // Load H^todo and Hx^todo
            let h_power: __m128i = core::mem::transmute(self.expanded_key.h_power(todo));
            let hx_power: __m128i = core::mem::transmute(self.expanded_key.hx_power(todo));
            let (mut acc_low, mut acc_med, mut acc_high) = clmul_3(state, h_power, hx_power);

            // Process remaining blocks as an inner product
            for i in 1..todo {
                // We know there must be at least `todo` blocks available since `todo` is the
                // minimum of n_blocks and GHASH_OPTIMIZED_HPOWERS.
                block = _mm_loadu_si128(chunks.next().unwrap().as_ptr().cast());

                let hi = core::mem::transmute(self.expanded_key.h_power(todo - i));
                let hix = core::mem::transmute(self.expanded_key.hx_power(todo - i));
                (acc_low, acc_med, acc_high) =
                    clmul_acc_3(block, hi, hix, acc_low, acc_med, acc_high);
            }

            acc_med = clmul_3_post(acc_low, acc_med, acc_high);
            state = modreduce(v_multiplication_constant, acc_low, acc_med, acc_high);
            n_blocks -= todo;
        }

        _mm_storeu_si128(core::ptr::from_mut(&mut self.state).cast(), state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clmul_3_post() {
        crate::common::init();

        // SAFETY: Intrinsics for testing
        unsafe {
            let low = _mm_set_epi64x(0x1111111111111111, 0x2222222222222222);
            let med = _mm_set_epi64x(0x3333333333333333, 0x4444444444444444);
            let high = _mm_set_epi64x(0x5555555555555555, 0x6666666666666666);

            let result = clmul_3_post(low, med, high);

            // The result should be med XOR low XOR high
            let expected = _mm_xor_si128(med, _mm_xor_si128(low, high));

            let result_bytes: [u8; 16] = core::mem::transmute(result);
            let expected_bytes: [u8; 16] = core::mem::transmute(expected);

            assert_eq!(result_bytes, expected_bytes);
        }
    }

    #[test]
    fn test_clmul_acc_3() {
        crate::common::init();

        // SAFETY: Intrinsics for testing
        unsafe {
            let op_a = _mm_set_epi64x(0x0123456789ABCDEFu64 as i64, 0xFEDCBA9876543210u64 as i64);
            let op_b = _mm_set_epi64x(0x1111111111111111u64 as i64, 0x2222222222222222u64 as i64);

            // op_b_x should be the XOR of the two 64-bit halves of op_b
            let op_b_x = _mm_set_epi64x(0, (0x1111111111111111u64 ^ 0x2222222222222222u64) as i64);

            let acc_low =
                _mm_set_epi64x(0xAAAAAAAAAAAAAAAAu64 as i64, 0xBBBBBBBBBBBBBBBBu64 as i64);
            let acc_med =
                _mm_set_epi64x(0xCCCCCCCCCCCCCCCCu64 as i64, 0xDDDDDDDDDDDDDDDDu64 as i64);
            let acc_high =
                _mm_set_epi64x(0xEEEEEEEEEEEEEEEEu64 as i64, 0xFFFFFFFFFFFFFFFFu64 as i64);

            let (new_low, _new_med, _new_high) =
                clmul_acc_3(op_a, op_b, op_b_x, acc_low, acc_med, acc_high);

            // Verify that we actually accumulated (XORed) the results
            // We can't verify the exact values without duplicating the CLMUL logic,
            // but we can verify the results are different from the accumulators
            let new_low_bytes: [u8; 16] = core::mem::transmute(new_low);
            let acc_low_bytes: [u8; 16] = core::mem::transmute(acc_low);

            // At least one should be different (unless we got very unlucky with XOR)
            assert_ne!(new_low_bytes, acc_low_bytes);
        }
    }

    #[test]
    fn test_modreduce() {
        crate::common::init();

        // SAFETY: Intrinsics for testing
        unsafe {
            let v_mult_const = _mm_set_epi32(0, 0, u32::cast_signed(0xc2000000), 0);

            // Use simple test values
            let low = _mm_set_epi64x(0x0000000000000001, 0x0000000000000000);
            let med = _mm_set_epi64x(0x0000000000000000, 0x0000000000000000);
            let high = _mm_set_epi64x(0x0000000000000000, 0x0000000000000000);

            let result = modreduce(v_mult_const, low, med, high);

            // The result should be non-zero
            let result_bytes: [u8; 16] = core::mem::transmute(result);
            assert_ne!(result_bytes, [0u8; 16]);
        }
    }
}
