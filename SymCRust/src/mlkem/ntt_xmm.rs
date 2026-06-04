//
// ntt_xmm.rs  ML-KEM NTT/INTT implementations using SSE2 intrinsics
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
#[cfg(target_arch = "x86")]
use core::arch::x86::*;

use super::Q;
use super::PolyElement;
use super::NttIntrinsicsInterface;
pub(super) struct NttIntrinsicsXmm;

impl NttIntrinsicsInterface for NttIntrinsicsXmm {
    #[inline(always)]
    fn vec128_load_u16x8(elem: &PolyElement, index: usize) -> __m128i {
        unsafe {
            let addr = elem.as_ptr().add(index);
            _mm_loadu_si128(addr as *const __m128i)
        }
    }

    #[inline(always)]
    fn vec64_load_u16x4(elem: &PolyElement, index: usize) -> __m128i {
        unsafe {
            let addr = elem.as_ptr().add(index);
            _mm_loadu_si64(addr as *const u8)
        }
    }

    #[inline(always)]
    fn vec32_load_u16x2(elem: &PolyElement, index: usize) -> __m128i {
        unsafe {
            let addr = elem.as_ptr().add(index);
            let val: u32 = (*addr as u32) | ((*(addr.add(1)) as u32) << 16);
            _mm_cvtsi32_si128(val as i32)
        }
    }

    #[inline(always)]
    fn vec128_store_u16x8(elem: &mut PolyElement, index: usize, val: __m128i) {
        unsafe {
            let addr = elem.as_mut_ptr().add(index);
            _mm_storeu_si128(addr as *mut __m128i, val);
        }
    }

    #[inline(always)]
    fn vec64_store_u16x4(elem: &mut PolyElement, index: usize, val: __m128i) {
        unsafe {
            let addr = elem.as_mut_ptr().add(index);
            _mm_storeu_si64(addr as *mut u8, val);
        }
    }

    #[inline(always)]
    fn vec32_store_u16x2(elem: &mut PolyElement, index: usize, val: __m128i) {
        unsafe {
            let addr = elem.as_mut_ptr().add(index);
            let val: u32 = _mm_cvtsi128_si32(val) as u32;
            *addr = val as u16;
            *(addr.add(1)) = (val >> 16) as u16;
        }
    }

    #[inline(always)]
    fn vec128_set_u16x8(val: u16) -> __m128i {
        unsafe { _mm_set1_epi16(val as i16) }
    }

    #[inline(always)]
    fn vec128_mod_sub(a: __m128i, b: __m128i) -> __m128i {
        unsafe {
            let v_q = Self::vec128_set_u16x8(Q as u16);
            let v_zero = Self::vec128_set_u16x8(0);

            /* res = a - b */
            let v_res = _mm_sub_epi16(a, b);
            /* tmp1 = (a - b) < 0 ? -1 : 0 */
            let mut v_tmp1 = _mm_cmpgt_epi16(v_zero, v_res);
            /* tmp1 = (a - b) < 0 ? Q : 0 */
            v_tmp1 = _mm_and_si128(v_tmp1, v_q);
            /* return (a - b) mod Q */
            _mm_add_epi16(v_res, v_tmp1)
        }
    }

    #[inline(always)]
    fn vec128_mod_add(a: __m128i, b: __m128i) -> __m128i {
        unsafe {
            let v_q = Self::vec128_set_u16x8(Q as u16);

            /* res = a + b */
            let v_res = _mm_add_epi16(a, b);
            /* tmp1 = (a + b) < Q ? -1 : 0 */
            let mut v_tmp1 = _mm_cmpgt_epi16(v_q, v_res);
            /* tmp1 = (a + b) < Q ? 0 : Q */
            v_tmp1 = _mm_andnot_si128(v_tmp1, v_q);
            /* return (a + b) mod Q */
            _mm_sub_epi16(v_res, v_tmp1)
        }
    }

    #[inline(always)]
    fn vec128_mont_mul(a: __m128i, b: __m128i, b_mont: __m128i) -> __m128i {
        unsafe {
            let v_q = Self::vec128_set_u16x8(Q as u16);
            let v_zero = Self::vec128_set_u16x8(0);
            let v_one = Self::vec128_set_u16x8(1);

            /* tmp1 = a *low  b_mont */
            let mut v_tmp1 = _mm_mullo_epi16(a, b_mont);
            /* res  = a *high b */
            let mut v_res = _mm_mulhi_epu16(a, b);
            /* tmp2 = (tmp1 == 0) ? -1 : 0 */
            let v_tmp2 = _mm_cmpeq_epi16(v_tmp1, v_zero);
            /* tmp1 = (a *low b_mont) *high Q */
            v_tmp1 = _mm_mulhi_epu16(v_tmp1, v_q);
            /* res = a *high b + 1 */
            v_res = _mm_add_epi16(v_res, v_one);
            /* res  = a *high b (+ 1 if a != 0) */
            v_res = _mm_add_epi16(v_res, v_tmp2);
            /* res  = a *high b + inv*Q (+ 1 if a != 0) */
            v_res = _mm_add_epi16(v_res, v_tmp1);
            /* res  = (a*b + inv*Q >> 16) mod Q */
            Self::vec128_mod_sub(v_res, v_q)
        }
    }
}