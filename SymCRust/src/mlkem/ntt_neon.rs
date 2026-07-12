//
// ntt_neon.rs  ML-KEM NTT/INTT implementations using NEON intrinsics
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// ----------------------------------------------------------------------------
// Single-body cfg-swap redirect (see INTRINSICS.md §0 P6, cf. `ntt_xmm.rs` for
// SSE2). The lane ops (`vec128_set_u16x8`, `vec128_mod_sub`, `vec128_mod_add`,
// `vec128_mont_mul`) are written ONCE — a near-verbatim copy of the upstream
// production source — over the NEON vector types and the `v*` intrinsic names.
// Two cfg-gated `use` blocks bind those names to one of two backends:
//
//   * production (`not(feature = "verify")`): the real `core::arch::aarch64`
//     vector types and intrinsics (via the glob below).
//
//   * verify (`feature = "verify"`): each NEON vector type becomes the matching
//     concrete lane carrier (`uint16x8_t = [u16; 8]`, …) and each `v*` lane op
//     becomes the matching modelled shim in
//     `crate::verify::intrinsics::aarch64::neon`. ALL lane-op modelling lives
//     there, so Aeneas extracts the lane ops as theorems over those shims, not
//     opaque silicon axioms.
//
// The load/store methods index a `PolyElement` and, in production, do so
// through raw pointers (the real silicon load/store). The verify arm does NOT
// use raw pointers: on the concrete word carrier `uint16x8_t = [u16; 8]`, a
// load/store of contiguous coefficients is plain array indexing/assignment over
// `elem[index .. index+n]`. Aeneas therefore extracts the verify load/store as
// transparent `def`s (not opaque silicon axioms), exactly like the AES
// `loadu_round_key` byte-carrier redirect.
// ----------------------------------------------------------------------------

// Production: real silicon vector types + intrinsics.
#[cfg(all(target_arch = "aarch64", not(feature = "verify")))]
use core::arch::aarch64::*;

// Verify: the NEON vector types are concrete lane carriers and each `v*` lane op
// is the matching modelled shim. The load/store methods index the `[u16; 8]`
// carrier directly (no raw pointers), so `vget_low_u16` is imported for the
// `vec64_store_u16x4` low-half projection.
#[cfg(feature = "verify")]
use crate::verify::intrinsics::aarch64::neon::{
    Int16x8 as int16x8_t,
    Uint16x4 as uint16x4_t,
    Uint16x8 as uint16x8_t,
    Uint32x4 as uint32x4_t,
    vaddq_u16, vandq_u16, vcgeq_u16, vcltzq_s16, vdupq_n_u16, vget_low_u16,
    vmlal_high_u16, vmlal_u16, vmull_high_u16, vmull_u16, vmulq_u16,
    vreinterpretq_s16_u16, vreinterpretq_u16_u32, vsubq_u16, vuzp2q_u16,
};

use super::Q;
use super::PolyElement;
use super::NttIntrinsicsInterface;

pub(super) struct NttIntrinsicsNeon;

#[cfg(target_arch = "aarch64")]
impl NttIntrinsicsInterface for NttIntrinsicsNeon {
    type Vec128 = uint16x8_t;
    #[cfg(not(feature = "verify"))]
    #[inline(always)]
    fn vec128_load_u16x8(elem: &PolyElement, index: usize) -> uint16x8_t {
        unsafe {
            let addr = elem.as_ptr().add(index);
            vld1q_u16(addr)
        }
    }
    #[cfg(feature = "verify")]
    #[inline(always)]
    fn vec128_load_u16x8(elem: &PolyElement, index: usize) -> uint16x8_t {
        // Modelled (not opaque): on the word carrier `uint16x8_t = [u16; 8]`,
        // `vld1q_u16(elem + index)` reads the 8 contiguous coefficients
        // `elem[index .. index+8]` into lanes 0..7 — array indexing, no raw
        // pointer. Mirrors the AES `loadu_round_key` byte-carrier redirect.
        [elem[index], elem[index + 1], elem[index + 2], elem[index + 3],
         elem[index + 4], elem[index + 5], elem[index + 6], elem[index + 7]]
    }


    #[cfg(not(feature = "verify"))]
    #[inline(always)]
    fn vec64_load_u16x4(elem: &PolyElement, index: usize) -> uint16x8_t {
        unsafe {
            let addr = elem.as_ptr().add(index);
            vreinterpretq_u16_u64(vld1q_dup_u64(addr as *const u64))
        }
    }
    #[cfg(feature = "verify")]
    #[inline(always)]
    fn vec64_load_u16x4(elem: &PolyElement, index: usize) -> uint16x8_t {
        // Modelled: `vld1q_dup_u64` reads 8 bytes (4 u16 = `elem[index..index+4]`)
        // and broadcasts that 64-bit group across both halves; reinterpret to u16.
        // Lanes 0..3 carry the loaded coefficients (the spec-relevant half).
        [elem[index], elem[index + 1], elem[index + 2], elem[index + 3],
         elem[index], elem[index + 1], elem[index + 2], elem[index + 3]]
    }

    #[cfg(not(feature = "verify"))]
    #[inline(always)]
    fn vec32_load_u16x2(elem: &PolyElement, index: usize) -> uint16x8_t {
        unsafe {
            let addr = elem.as_ptr().add(index);
            vreinterpretq_u16_u32(vld1q_dup_u32(addr as *const u32))
        }
    }
    #[cfg(feature = "verify")]
    #[inline(always)]
    fn vec32_load_u16x2(elem: &PolyElement, index: usize) -> uint16x8_t {
        // Modelled: `vld1q_dup_u32` reads 4 bytes (2 u16 = `elem[index..index+2]`)
        // and broadcasts that 32-bit group across all four u32 lanes; reinterpret
        // to u16. Lanes 0..1 carry the loaded coefficients (the spec-relevant pair).
        [elem[index], elem[index + 1], elem[index], elem[index + 1],
         elem[index], elem[index + 1], elem[index], elem[index + 1]]
    }

    #[cfg(not(feature = "verify"))]
    #[inline(always)]
    fn vec128_store_u16x8(elem: &mut PolyElement, index: usize, val: uint16x8_t) {
        unsafe {
            let addr = elem.as_mut_ptr().add(index);
            vst1q_u16(addr, val);
        }
    }
    #[cfg(feature = "verify")]
    #[inline(always)]
    fn vec128_store_u16x8(elem: &mut PolyElement, index: usize, val: uint16x8_t) {
        // Modelled: `vst1q_u16` writes lanes 0..7 to `elem[index..index+8]` —
        // array assignment, no raw pointer.
        elem[index] = val[0];
        elem[index + 1] = val[1];
        elem[index + 2] = val[2];
        elem[index + 3] = val[3];
        elem[index + 4] = val[4];
        elem[index + 5] = val[5];
        elem[index + 6] = val[6];
        elem[index + 7] = val[7];
    }

    #[cfg(not(feature = "verify"))]
    #[inline(always)]
    fn vec64_store_u16x4(elem: &mut PolyElement, index: usize, val: uint16x8_t) {
        unsafe {
            let addr = elem.as_mut_ptr().add(index);
            vst1_u16(addr, vget_low_u16(val));
        }
    }
    #[cfg(feature = "verify")]
    #[inline(always)]
    fn vec64_store_u16x4(elem: &mut PolyElement, index: usize, val: uint16x8_t) {
        // Modelled: `vst1_u16(.., vget_low_u16 val)` writes the low 4 lanes to
        // `elem[index..index+4]`.
        let lo = vget_low_u16(val);
        elem[index] = lo[0];
        elem[index + 1] = lo[1];
        elem[index + 2] = lo[2];
        elem[index + 3] = lo[3];
    }

    #[cfg(not(feature = "verify"))]
    #[inline(always)]
    fn vec32_store_u16x2(elem: &mut PolyElement, index: usize, val: uint16x8_t) {
        unsafe {
            let addr = elem.as_mut_ptr().add(index);
            vst1_lane_u32(
                addr as *mut u32,
                vget_low_u32(vreinterpretq_u32_u16(val)),
                0,
            );
        }
    }
    #[cfg(feature = "verify")]
    #[inline(always)]
    fn vec32_store_u16x2(elem: &mut PolyElement, index: usize, val: uint16x8_t) {
        // Modelled: `vst1_lane_u32(.., 0)` writes the low 32-bit group (2 u16 =
        // lanes 0..1) to `elem[index..index+2]`.
        elem[index] = val[0];
        elem[index + 1] = val[1];
    }

    #[allow(unused_unsafe)]
    #[inline(always)]
    fn vec128_set_u16x8(val: u16) -> uint16x8_t {
        unsafe { vdupq_n_u16(val) }
    }

    #[allow(unused_unsafe)]
    #[inline(always)]
    fn vec128_mod_sub(a: uint16x8_t, b: uint16x8_t) -> uint16x8_t {
        unsafe {
            let v_q = Self::vec128_set_u16x8(Q as u16);
    
            /* res = a - b */
            let v_res = vsubq_u16(a, b);
            /* tmp1 = (a - b) < 0 ? -1 : 0 */
            let mut v_tmp1 = vcltzq_s16(vreinterpretq_s16_u16(v_res));
            /* tmp1 = (a - b) < 0 ? Q : 0 */
            v_tmp1 = vandq_u16(v_tmp1, v_q);
            /* return (a - b) mod Q */
            vaddq_u16(v_res, v_tmp1)
        }
    }
    
    #[allow(unused_unsafe)]
    #[inline(always)]
    fn vec128_mod_add(a: uint16x8_t, b: uint16x8_t) -> uint16x8_t {
        unsafe {
            let v_q = Self::vec128_set_u16x8(Q as u16);
    
            /* res = a + b */
            let v_res = vaddq_u16(a, b);
            /* tmp1 = (a + b) >= Q ? -1 : 0 */
            let mut v_tmp1 = vcgeq_u16(v_res, v_q);
            /* tmp1 = (a + b) >= Q ? Q : 0 */
            v_tmp1 = vandq_u16(v_tmp1, v_q);
            /* return (a + b) mod Q */
            vsubq_u16(v_res, v_tmp1)
        }
    }
    
    #[allow(unused_unsafe)]
    #[inline(always)]
    fn vec128_mont_mul(a: uint16x8_t, b: uint16x8_t, b_mont: uint16x8_t) -> uint16x8_t {
        unsafe {
            let v_q = Self::vec128_set_u16x8(Q as u16);
    
            /* tmp1 = a *low  b_mont */
            let mut v_tmp1 = vmulq_u16(a, b_mont);
            /* tmp2 = a*b [0-3]*/
            let mut v_tmp2 = vmull_u16(vget_low_u16(a), vget_low_u16(b));
            /* res  = a*b [4-7]*/
            let mut v_res = vmull_high_u16(a, b);
            /* tmp2 = a*b + inv*Q [0-3]*/
            v_tmp2 = vmlal_u16(v_tmp2, vget_low_u16(v_tmp1), vget_low_u16(v_q));
            /* res  = a*b + inv*Q [4-7]*/
            v_res = vmlal_high_u16(v_res, v_tmp1, v_q);
            /* res  = a*b + inv*Q >> 16 */
            v_tmp1 = vuzp2q_u16(vreinterpretq_u16_u32(v_tmp2), vreinterpretq_u16_u32(v_res));
            /* return (a*b + inv*Q >> 16) mod Q */
            Self::vec128_mod_sub(v_tmp1, v_q)
        }
    }
}
