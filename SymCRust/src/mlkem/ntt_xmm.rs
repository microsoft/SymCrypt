//
// ntt_xmm.rs  ML-KEM NTT/INTT implementations using SSE2 intrinsics
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// ----------------------------------------------------------------------------
// Single-body cfg-swap redirect (see INTRINSICS.md §0 P6 and
// `crate::verify::intrinsics::swap_poc`).
//
// The lane ops (`vec128_set_u16x8`, `vec128_mod_sub`, `vec128_mod_add`,
// `vec128_mont_mul`) are written ONCE — a near-verbatim copy of the upstream
// production source — over `__m128i` and the `_mm_*` intrinsic names. Two
// cfg-gated `use` blocks bind those names to one of two backends:
//
//   * production (`not(feature = "verify")`): the real `core::arch` register
//     type and intrinsics.
//
//   * verify (`feature = "verify"`): `__m128i` becomes the canonical concrete
//     byte carrier and each `_mm_*` lane op becomes the matching modelled shim
//     in `crate::verify::intrinsics::x86_64::xmm`. ALL lane-op modelling lives
//     there, so `Array U16 8` never appears in this file and Aeneas extracts
//     the lane ops as theorems over those shims, not opaque silicon axioms.
//
// The load/store/cvt methods index a `PolyElement` and, in production, do so
// through raw pointers. The verify arm does NOT use raw pointers: it loads the
// contiguous coefficients into a `[u16; 8]` word group and re-views them as the
// `__m128i` byte carrier through the modelled `words_to_bytes` / `bytes_to_words`
// (and back for stores). Aeneas therefore extracts the verify load/store as
// transparent `def`s (not opaque silicon axioms), like the AES byte-carrier
// redirect.
// ----------------------------------------------------------------------------

// Production: real silicon register + intrinsics.
#[cfg(all(target_arch = "x86_64", not(feature = "verify")))]
use core::arch::x86_64::*;
#[cfg(all(target_arch = "x86", not(feature = "verify")))]
use core::arch::x86::*;

// Verify: `__m128i` is the byte carrier and each `_mm_*` lane op is the
// matching modelled shim. The load/store methods re-view the `[u16; 8]` word
// group through `words_to_bytes` / `bytes_to_words` (no raw pointer).
#[cfg(feature = "verify")]
use crate::verify::intrinsics::lanes::{bytes_to_words, words_to_bytes};
#[cfg(feature = "verify")]
use crate::verify::intrinsics::x86_64::xmm::{
    M128 as __m128i,
    add_epi16 as _mm_add_epi16,
    and_si128 as _mm_and_si128,
    andnot_si128 as _mm_andnot_si128,
    cmpeq_epi16 as _mm_cmpeq_epi16,
    cmpgt_epi16 as _mm_cmpgt_epi16,
    mulhi_epu16 as _mm_mulhi_epu16,
    mullo_epi16 as _mm_mullo_epi16,
    set1_epi16 as _mm_set1_epi16,
    sub_epi16 as _mm_sub_epi16,
};

use super::Q;
use super::PolyElement;
use super::NttIntrinsicsInterface;
pub(super) struct NttIntrinsicsXmm;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl NttIntrinsicsInterface for NttIntrinsicsXmm {
    type Vec128 = __m128i;

    // --- Raw-pointer load/store/cvt: cfg-split (real prod / opaque verify) ----

    #[cfg(not(feature = "verify"))]
    #[inline(always)]
    fn vec128_load_u16x8(elem: &PolyElement, index: usize) -> __m128i {
        unsafe {
            let addr = elem.as_ptr().add(index);
            _mm_loadu_si128(addr as *const __m128i)
        }
    }
    #[cfg(feature = "verify")]
    #[inline(always)]
    fn vec128_load_u16x8(elem: &PolyElement, index: usize) -> __m128i {
        // Modelled (not opaque): load the 8 contiguous coefficients
        // `elem[index .. index+8]` and re-view as the `__m128i` byte carrier.
        words_to_bytes([
            elem[index], elem[index + 1], elem[index + 2], elem[index + 3],
            elem[index + 4], elem[index + 5], elem[index + 6], elem[index + 7],
        ])
    }

    #[cfg(not(feature = "verify"))]
    #[inline(always)]
    fn vec64_load_u16x4(elem: &PolyElement, index: usize) -> __m128i {
        unsafe {
            let addr = elem.as_ptr().add(index);
            _mm_loadu_si64(addr as *const u8)
        }
    }
    #[cfg(feature = "verify")]
    #[inline(always)]
    fn vec64_load_u16x4(elem: &PolyElement, index: usize) -> __m128i {
        // Modelled: `_mm_loadu_si64` loads 8 bytes (4 u16 = `elem[index..index+4]`)
        // into the low 64 bits; the high 64 bits are zero.
        words_to_bytes([
            elem[index], elem[index + 1], elem[index + 2], elem[index + 3],
            0, 0, 0, 0,
        ])
    }

    #[cfg(not(feature = "verify"))]
    #[inline(always)]
    fn vec32_load_u16x2(elem: &PolyElement, index: usize) -> __m128i {
        unsafe {
            let addr = elem.as_ptr().add(index);
            let val: u32 = (*addr as u32) | ((*(addr.add(1)) as u32) << 16);
            _mm_cvtsi32_si128(val as i32)
        }
    }
    #[cfg(feature = "verify")]
    #[inline(always)]
    fn vec32_load_u16x2(elem: &PolyElement, index: usize) -> __m128i {
        // Modelled: `_mm_cvtsi32_si128` loads 4 bytes (2 u16 = `elem[index..index+2]`)
        // into the low 32 bits; the rest is zero.
        words_to_bytes([
            elem[index], elem[index + 1],
            0, 0, 0, 0, 0, 0,
        ])
    }

    #[cfg(not(feature = "verify"))]
    #[inline(always)]
    fn vec128_store_u16x8(elem: &mut PolyElement, index: usize, val: __m128i) {
        unsafe {
            let addr = elem.as_mut_ptr().add(index);
            _mm_storeu_si128(addr as *mut __m128i, val);
        }
    }
    #[cfg(feature = "verify")]
    #[inline(always)]
    fn vec128_store_u16x8(elem: &mut PolyElement, index: usize, val: __m128i) {
        // Modelled: `_mm_storeu_si128` writes all 8 lanes to `elem[index..index+8]`.
        let w = bytes_to_words(val);
        elem[index] = w[0];
        elem[index + 1] = w[1];
        elem[index + 2] = w[2];
        elem[index + 3] = w[3];
        elem[index + 4] = w[4];
        elem[index + 5] = w[5];
        elem[index + 6] = w[6];
        elem[index + 7] = w[7];
    }

    #[cfg(not(feature = "verify"))]
    #[inline(always)]
    fn vec64_store_u16x4(elem: &mut PolyElement, index: usize, val: __m128i) {
        unsafe {
            let addr = elem.as_mut_ptr().add(index);
            _mm_storeu_si64(addr as *mut u8, val);
        }
    }
    #[cfg(feature = "verify")]
    #[inline(always)]
    fn vec64_store_u16x4(elem: &mut PolyElement, index: usize, val: __m128i) {
        // Modelled: `_mm_storeu_si64` writes the low 8 bytes (4 u16 = lanes 0..3)
        // to `elem[index..index+4]`.
        let w = bytes_to_words(val);
        elem[index] = w[0];
        elem[index + 1] = w[1];
        elem[index + 2] = w[2];
        elem[index + 3] = w[3];
    }

    #[cfg(not(feature = "verify"))]
    #[inline(always)]
    fn vec32_store_u16x2(elem: &mut PolyElement, index: usize, val: __m128i) {
        unsafe {
            let addr = elem.as_mut_ptr().add(index);
            let val: u32 = _mm_cvtsi128_si32(val) as u32;
            *addr = val as u16;
            *(addr.add(1)) = (val >> 16) as u16;
        }
    }
    #[cfg(feature = "verify")]
    #[inline(always)]
    fn vec32_store_u16x2(elem: &mut PolyElement, index: usize, val: __m128i) {
        // Modelled: `_mm_cvtsi128_si32` writes the low 32 bits (2 u16 = lanes 0..1)
        // to `elem[index..index+2]`.
        let w = bytes_to_words(val);
        elem[index] = w[0];
        elem[index + 1] = w[1];
    }

    // --- Lane ops: modelled in both builds (single body over the `_mm_*`
    //     names; the `unsafe` is redundant in the verify build, where the
    //     shims are safe — hence `allow(unused_unsafe)`). ----------------------

    #[allow(unused_unsafe)]
    #[inline(always)]
    fn vec128_set_u16x8(val: u16) -> __m128i {
        unsafe { _mm_set1_epi16(val as i16) }
    }

    #[allow(unused_unsafe)]
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

    #[allow(unused_unsafe)]
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

    #[allow(unused_unsafe)]
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
