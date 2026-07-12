// EXPERIMENTAL CODE --- NOT YET INTEGRATED WITH SYMCRYPT
//
// ntt_avx2.rs  ML-KEM NTT/INTT butterfly using AVX2 (16 × u16 per operation)
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Processes 16 coefficients per butterfly using 256-bit YMM registers.
// Falls through to the existing SSE2 path for inner layers (len < 16).
//

// ----------------------------------------------------------------------------
// Single-body cfg-swap redirect (see INTRINSICS.md §0 P6, cf. `ntt_xmm.rs` for
// SSE2 and `sha3/keccak4x_hybrid.rs` for the sibling AVX2/`ymm` redirect).
//
// The lane-op bodies (`mont_mul_avx2`, `mod_add_avx2`, `mod_sub_avx2`) and the
// butterfly loops (`ntt_layer_avx2`, `intt_layer_avx2`) are written ONCE — a
// near-verbatim copy of the upstream production source — over `__m256i` and the
// `_mm256_*` intrinsic names. Two cfg-gated `use` blocks bind those names to one
// of two backends:
//
//   * production (`not(feature = "verify")`): the real `core::arch::x86_64`
//     register type and AVX2 intrinsics (via the glob below). The shared bodies
//     carry no `#[target_feature]`; the AVX2 intrinsics are reached through the
//     runtime `is_x86_feature_detected!("avx2")` dispatch gate in `ntt.rs`.
//
//   * verify (`feature = "verify"`): `__m256i` becomes the canonical concrete
//     byte carrier (`M256 = [u8; 32]`) and each `_mm256_*` lane op becomes the
//     matching modelled shim in `crate::verify::intrinsics::x86_64::ymm`. ALL
//     lane-op modelling lives there, so `[u16; 16]` never appears in this file
//     and Aeneas extracts the lane ops as theorems over those shims, not opaque
//     silicon axioms.
//
// The raw-pointer `mm256_load`/`mm256_store` methods are the one exception: they
// index a `PolyElement` through raw pointers (outside Aeneas's model of Rust),
// so — exactly as `ntt_xmm.rs` cfg-splits its load/store — they are cfg-split
// here: the production arm does the real load/store; the verify arm is
// `#[verify::opaque]` (axiomatised by its `PolyElement` signature, with no raw
// pointers in the extracted model).
// ----------------------------------------------------------------------------

#![allow(dead_code)]

// Production: real silicon register + intrinsics.
#[cfg(all(target_arch = "x86_64", not(feature = "verify")))]
use core::arch::x86_64::*;

// Verify: `__m256i` is the byte carrier and each `_mm256_*` lane op is the
// matching modelled shim. The load/store methods index the coefficient slice
// via the modelled `loadu_si256_u16` / `storeu_si256_u16` (u16-view, no raw
// pointer) and re-view as the `__m256i` byte carrier through
// `words16x16_to_bytes256` / `bytes256_to_words16x16`.
#[cfg(feature = "verify")]
use crate::verify::intrinsics::x86_64::ymm::{
    M256 as __m256i,
    add_epi16 as _mm256_add_epi16,
    and_si256 as _mm256_and_si256,
    andnot_si256 as _mm256_andnot_si256,
    cmpeq_epi16 as _mm256_cmpeq_epi16,
    cmpgt_epi16 as _mm256_cmpgt_epi16,
    mulhi_epu16 as _mm256_mulhi_epu16,
    mullo_epi16 as _mm256_mullo_epi16,
    set1_epi16 as _mm256_set1_epi16,
    setzero_si256 as _mm256_setzero_si256,
    sub_epi16 as _mm256_sub_epi16,
};
#[cfg(feature = "verify")]
use crate::verify::intrinsics::x86_64::avx2::{
    bytes256_to_words16x16, loadu_si256_u16, storeu_si256_u16, words16x16_to_bytes256,
};

use super::Q;
use super::PolyElement;
use super::{ZETA_BIT_REV_TIMES_R, ZETA_BIT_REV_TIMES_R_TIMES_NEG_Q_INV_MOD_R};

/// AVX2 Montgomery multiply: (a * b) / R mod Q for 16 × u16 lanes.
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn mont_mul_avx2(a: __m256i, b: __m256i, b_mont: __m256i) -> __m256i {
    let v_q = _mm256_set1_epi16(Q as i16);
    let v_zero = _mm256_setzero_si256();
    let v_one = _mm256_set1_epi16(1);

    let v_tmp1 = _mm256_mullo_epi16(a, b_mont);
    let mut v_res = _mm256_mulhi_epu16(a, b);
    let v_tmp2 = _mm256_cmpeq_epi16(v_tmp1, v_zero);
    let v_tmp1 = _mm256_mulhi_epu16(v_tmp1, v_q);
    v_res = _mm256_add_epi16(v_res, v_one);
    v_res = _mm256_add_epi16(v_res, v_tmp2);
    v_res = _mm256_add_epi16(v_res, v_tmp1);

    // mod_sub(v_res, v_q)
    let v_diff = _mm256_sub_epi16(v_res, v_q);
    let v_mask = _mm256_cmpgt_epi16(v_zero, v_diff);
    let v_fixup = _mm256_and_si256(v_mask, v_q);
    _mm256_add_epi16(v_diff, v_fixup)
}

/// AVX2 modular add: (a + b) mod Q
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn mod_add_avx2(a: __m256i, b: __m256i) -> __m256i {
    let v_q = _mm256_set1_epi16(Q as i16);
    let v_res = _mm256_add_epi16(a, b);
    let v_mask = _mm256_cmpgt_epi16(v_q, v_res);
    let v_fixup = _mm256_andnot_si256(v_mask, v_q);
    _mm256_sub_epi16(v_res, v_fixup)
}

/// AVX2 modular sub: (a - b) mod Q
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn mod_sub_avx2(a: __m256i, b: __m256i) -> __m256i {
    let v_q = _mm256_set1_epi16(Q as i16);
    let v_zero = _mm256_setzero_si256();
    let v_res = _mm256_sub_epi16(a, b);
    let v_mask = _mm256_cmpgt_epi16(v_zero, v_res);
    let v_fixup = _mm256_and_si256(v_mask, v_q);
    _mm256_add_epi16(v_res, v_fixup)
}

#[inline]
#[cfg(all(target_arch = "x86_64", not(feature = "verify")))]
#[target_feature(enable = "avx2")]
unsafe fn mm256_load(p : &PolyElement, i : usize) -> __m256i {
    let p = p.as_ptr().add(i) as *const __m256i;
    _mm256_loadu_si256(p)
}

#[cfg(all(target_arch = "x86_64", feature = "verify"))]
#[inline]
fn mm256_load(p : &PolyElement, i : usize) -> __m256i {
    // Modelled (not opaque): load the 16 contiguous coefficients
    // `p[i .. i+16]` through the u16-view shim, then re-view as the `__m256i`
    // byte carrier. No raw pointer.
    words16x16_to_bytes256(loadu_si256_u16(p, i))
}

#[inline]
#[cfg(all(target_arch = "x86_64", not(feature = "verify")))]
#[target_feature(enable = "avx2")]
unsafe fn mm256_store(p : &mut PolyElement, i : usize, x : __m256i) {
    let p = p.as_mut_ptr().add(i) as *mut __m256i;
    _mm256_storeu_si256(p, x);
}

#[cfg(all(target_arch = "x86_64", feature = "verify"))]
#[inline]
fn mm256_store(p : &mut PolyElement, i : usize, x : __m256i) {
    // Modelled (not opaque): store the 16 coefficients of `x` (re-viewed from
    // the byte carrier) to `p[i .. i+16]` through the u16-view shim. No raw
    // pointer.
    storeu_si256_u16(p, i, bytes256_to_words16x16(x))
}

/// AVX2 NTT butterfly layer for len >= 16.
#[cfg(target_arch = "x86_64")]
pub(super) unsafe fn ntt_layer_avx2(pe: &mut PolyElement, mut k: usize, len: usize) {
    debug_assert!(len >= 16);
    for start in (0..256).step_by(2 * len) {
        let v_tw = _mm256_set1_epi16(ZETA_BIT_REV_TIMES_R[k] as i16);
        let v_tw_mont = _mm256_set1_epi16(ZETA_BIT_REV_TIMES_R_TIMES_NEG_Q_INV_MOD_R[k] as i16);
        k += 1;

        let mut j = 0;
        while j + 16 <= len {
            let v_c0 = mm256_load(pe, start + j);
            let v_c1 = mm256_load(pe, start + j + len);

            let v_t = mont_mul_avx2(v_c1, v_tw, v_tw_mont);
            let v_new_c0 = mod_add_avx2(v_c0, v_t);
            let v_new_c1 = mod_sub_avx2(v_c0, v_t);

            mm256_store(pe, start + j, v_new_c0);
            mm256_store(pe, start + j + len, v_new_c1);
            j += 16;
        }
        // Remainder (if len is not a multiple of 16) — shouldn't happen for ML-KEM
    }
}

/// AVX2 INTT butterfly layer for len >= 16.
#[cfg(target_arch = "x86_64")]
pub(super) unsafe fn intt_layer_avx2(pe: &mut PolyElement, mut k: usize, len: usize) {
    debug_assert!(len >= 16);
    for start in (0..256).step_by(2 * len) {
        let v_tw = _mm256_set1_epi16(ZETA_BIT_REV_TIMES_R[k] as i16);
        let v_tw_mont = _mm256_set1_epi16(ZETA_BIT_REV_TIMES_R_TIMES_NEG_Q_INV_MOD_R[k] as i16);
        k -= 1;

        let mut j = 0;
        while j + 16 <= len {
            let v_c0 = mm256_load(pe, start + j);
            let v_c1 = mm256_load(pe, start + j + len);

            let v_new_c0 = mod_add_avx2(v_c0, v_c1);
            // INTT butterfly: c1' = (c1 - c0) * twiddle (NOT (c0 - c1) — that
            // sign flip silently broke decapsulation; matches the generic and
            // SSE2/NEON paths in `ntt.rs`).
            let v_diff = mod_sub_avx2(v_c1, v_c0);
            let v_new_c1 = mont_mul_avx2(v_diff, v_tw, v_tw_mont);

            mm256_store(pe, start + j, v_new_c0);
            mm256_store(pe, start + j + len, v_new_c1);
            j += 16;
        }
    }
}
