//! Transcribed shims for AVX2 (`target_feature = "avx2"`) intrinsics used
//! by ML-KEM (NTT) and SHA-3 (Keccak-f permutation).
//!
//! Every function below is a plain Rust transcription of the Intel SDM
//! "Operation:" pseudocode for the corresponding `core::arch::x86_64::_mm256_*`
//! intrinsic. The 256-bit YMM register is viewed via the lane-typed aliases
//! defined at the top of this file (`Words16x16`, `Dwords256`, `Qwords256`,
//! `Bytes256`); each AVX2 op is a pure lane-doubling of the corresponding
//! SSE2 op on 128-bit lanes (mechanically derived from `super::sse2`).
//!
//! ## Call-site closure (post-M2 audit, 2026-05-22)
//!
//! `mlkem/ntt_avx2.rs`             : `_mm256_loadu_si256` (u16 view),
//!                                   `_mm256_storeu_si256` (u16 view),
//!                                   `_mm256_setzero_si256`, `_mm256_set1_epi16`,
//!                                   `_mm256_add_epi16`, `_mm256_sub_epi16`,
//!                                   `_mm256_mullo_epi16`, `_mm256_mulhi_epu16`,
//!                                   `_mm256_cmpeq_epi16`, `_mm256_cmpgt_epi16`,
//!                                   `_mm256_and_si256`, `_mm256_andnot_si256`.
//! `sha3/{keccak4x_hybrid,keccak4x,shake4x}.rs` :
//!                                   `_mm256_load_si256`, `_mm256_store_si256`
//!                                   (u64 view), `_mm256_or_si256`,
//!                                   `_mm256_slli_epi64`, `_mm256_srli_epi64`.
//!
//! Intrinsics deliberately NOT shimmed (confirmed not called by any driver):
//! lane-crossing shuffles / permutes / blends (`_mm256_shuffle_epi8`,
//! `_mm256_permute2x128_si256`, `_mm256_permute4x64_epi64`,
//! `_mm256_unpack{lo,hi}_epi*`, `_mm256_blend_epi*`, `_mm256_alignr_epi8`,
//! `_mm256_{extract,insert}i128_si256`) — the AVX2 ML-KEM NTT is purely
//! lane-wise, and the 4-way Keccak permutation broadcasts state across
//! lanes without needing in-lane reordering. `_mm256_mulhi_epi16` (signed)
//! is also not called — only the unsigned half is needed (centred residues
//! are kept in `[0, q)` and reduced via `_mm256_mulhi_epu16`).
//!
//! Status: 17 transcribed shims, 0 axioms.
//!
//! Coverage map (intrinsic ↔ shim):
//! ```text
//! _mm256_load_si256   /  _mm256_loadu_si256    ←→ load_si256_u64 / loadu_si256_u64
//! _mm256_store_si256  /  _mm256_storeu_si256   ←→ store_si256_u64 / storeu_si256_u64
//! _mm256_loadu_si256  (u16 view)               ←→ loadu_si256_u16
//! _mm256_storeu_si256 (u16 view)               ←→ storeu_si256_u16
//! _mm256_setzero_si256                         ←→ setzero_si256
//! _mm256_set1_epi16                            ←→ set1_epi16
//! _mm256_add_epi16 / _mm256_sub_epi16          ←→ add_epi16 / sub_epi16
//! _mm256_mullo_epi16 / _mm256_mulhi_epu16      ←→ mullo_epi16 / mulhi_epu16
//! _mm256_cmpeq_epi16 / _mm256_cmpgt_epi16      ←→ cmpeq_epi16 / cmpgt_epi16
//! _mm256_and_si256 / _mm256_andnot_si256 /     ←→ and_si256 / andnot_si256 /
//!   _mm256_or_si256                                or_si256
//! _mm256_slli_epi64 / _mm256_srli_epi64        ←→ slli_epi64 / srli_epi64
//! ```

#![allow(dead_code)]

use super::lanewise::{
    lanewise_and_u8, lanewise_andnot_u8, lanewise_or_u8,
    lanewise_wrapping_add_u16, lanewise_wrapping_sub_u16,
    lanewise_wrapping_mul_u16, lanewise_mulhi_u16,
    lanewise_eq_mask_u16, lanewise_sgt_mask_i16,
};

/// 256-bit YMM viewed as sixteen 16-bit words; lane 0 is the low word.
///
/// Back-compat alias — new code SHOULD use `super::lanes::u16x16`.
pub type Words16x16 = super::lanes::u16x16;

/// 256-bit YMM viewed as eight 32-bit dwords; lane 0 is the low dword.
///
/// Back-compat alias — new code SHOULD use `super::lanes::u32x8`.
pub type Dwords256 = super::lanes::u32x8;

/// 256-bit YMM viewed as four 64-bit qwords; lane 0 is the low qword.
///
/// Back-compat alias — new code SHOULD use `super::lanes::u64x4`.
pub type Qwords256 = super::lanes::u64x4;

/// 256-bit YMM viewed as 32 bytes; lane 0 is the low byte.
///
/// Back-compat alias — new code SHOULD use `super::lanes::u8x32`.
pub type Bytes256 = super::lanes::u8x32;

/// `bytes256_to_words16x16(b)[k] := u16::from_le_bytes(b[2k..2k+2])`.
#[inline]
pub fn bytes256_to_words16x16(b: Bytes256) -> Words16x16 {
    let mut out = [0u16; 16];
    for i in 0..16 { out[i] = u16::from_le_bytes([b[2 * i], b[2 * i + 1]]); }
    out
}

/// Inverse of `bytes256_to_words16x16`.
#[inline]
pub fn words16x16_to_bytes256(w: Words16x16) -> Bytes256 {
    let mut out = [0u8; 32];
    for i in 0..16 {
        let p = w[i].to_le_bytes();
        out[2 * i]     = p[0];
        out[2 * i + 1] = p[1];
    }
    out
}

/// `bytes256_to_qwords256(b)[k] := u64::from_le_bytes(b[8k..8k+8])`.
#[inline]
pub fn bytes256_to_qwords256(b: Bytes256) -> Qwords256 {
    let mut out = [0u64; 4];
    for i in 0..4 {
        out[i] = u64::from_le_bytes([
            b[8 * i],     b[8 * i + 1], b[8 * i + 2], b[8 * i + 3],
            b[8 * i + 4], b[8 * i + 5], b[8 * i + 6], b[8 * i + 7],
        ]);
    }
    out
}

/// Inverse of `bytes256_to_qwords256`.
#[inline]
pub fn qwords256_to_bytes256(q: Qwords256) -> Bytes256 {
    let mut out = [0u8; 32];
    for i in 0..4 {
        let p = q[i].to_le_bytes();
        out[8 * i..8 * i + 8].copy_from_slice(&p);
    }
    out
}

// ----------------------------------------------------------------------------
// _mm256_load_si256 / _mm256_loadu_si256 / store / storeu  (AVX2)
// ----------------------------------------------------------------------------
// Operation (load):  DEST[255:0] := MEM[mem_addr+255:mem_addr]
// Operation (store): MEM[mem_addr+255:mem_addr] := SRC[255:0]
// (Aligned vs unaligned: identical bytes-in/out; alignment is an HW runtime
// contract irrelevant to the lane-typed shim.)
// ----------------------------------------------------------------------------

/// Load 4 contiguous u64s from `arr` starting at u64 index `at`.
/// Panics if `at + 4 > arr.len()`.
#[inline]
pub fn loadu_si256_u64(arr: &[u64], at: usize) -> Qwords256 {
    [arr[at], arr[at + 1], arr[at + 2], arr[at + 3]]
}

/// Aligned-load form; bytes-out identical to `loadu_si256_u64`.
#[inline]
pub fn load_si256_u64(arr: &[u64], at: usize) -> Qwords256 {
    loadu_si256_u64(arr, at)
}

/// Store 4 contiguous u64s into `arr` starting at u64 index `at`.
/// Panics if `at + 4 > arr.len()`.
#[inline]
pub fn storeu_si256_u64(arr: &mut [u64], at: usize, v: Qwords256) {
    arr[at]     = v[0];
    arr[at + 1] = v[1];
    arr[at + 2] = v[2];
    arr[at + 3] = v[3];
}

/// Aligned-store form; bytes-in identical to `storeu_si256_u64`.
#[inline]
pub fn store_si256_u64(arr: &mut [u64], at: usize, v: Qwords256) {
    storeu_si256_u64(arr, at, v)
}

/// Load 16 contiguous u16s from `arr` starting at u16 index `at`.
/// Panics if `at + 16 > arr.len()`.
#[inline]
pub fn loadu_si256_u16(arr: &[u16], at: usize) -> Words16x16 {
    let mut out = [0u16; 16];
    for i in 0..16 { out[i] = arr[at + i]; }
    out
}

/// Store 16 contiguous u16s into `arr` starting at u16 index `at`.
/// Panics if `at + 16 > arr.len()`.
#[inline]
pub fn storeu_si256_u16(arr: &mut [u16], at: usize, v: Words16x16) {
    for i in 0..16 { arr[at + i] = v[i]; }
}

// ----------------------------------------------------------------------------
// _mm256_setzero_si256 / _mm256_set1_epi16  (AVX2)
// ----------------------------------------------------------------------------

/// `dst[255:0] := 0`. View-agnostic; returned as `Bytes256`.
#[inline]
pub fn setzero_si256() -> Bytes256 {
    [0u8; 32]
}

/// Broadcast `a` to every 16-bit lane.
#[inline]
pub fn set1_epi16(a: i16) -> Words16x16 {
    let v = a as u16;
    [v; 16]
}

// ----------------------------------------------------------------------------
// _mm256_add_epi16 / _mm256_sub_epi16  (AVX2)
// ----------------------------------------------------------------------------
// FOR j := 0 to 15 ; i := j*16 ;
//   dst[i+15:i] := a[i+15:i] ± b[i+15:i]   ; modulo 2^16
// ----------------------------------------------------------------------------

/// Lane-wise wrapping `u16` addition over 16 lanes.
#[inline]
pub fn add_epi16(a: Words16x16, b: Words16x16) -> Words16x16 {
    lanewise_wrapping_add_u16(a, b)
}

/// Lane-wise wrapping `u16` subtraction over 16 lanes.
#[inline]
pub fn sub_epi16(a: Words16x16, b: Words16x16) -> Words16x16 {
    lanewise_wrapping_sub_u16(a, b)
}

// ----------------------------------------------------------------------------
// _mm256_mullo_epi16 / _mm256_mulhi_epu16  (AVX2)
// ----------------------------------------------------------------------------
// mullo: lane-wise low 16 bits of i16*i16 (signed/unsigned agree on low half).
// mulhi (epu16): lane-wise high 16 bits of u16*u16.
// ----------------------------------------------------------------------------

/// Lane-wise low 16 bits of `a * b`.
#[inline]
pub fn mullo_epi16(a: Words16x16, b: Words16x16) -> Words16x16 {
    lanewise_wrapping_mul_u16(a, b)
}

/// Lane-wise high 16 bits of unsigned `a * b`.
#[inline]
pub fn mulhi_epu16(a: Words16x16, b: Words16x16) -> Words16x16 {
    lanewise_mulhi_u16(a, b)
}

// ----------------------------------------------------------------------------
// _mm256_cmpeq_epi16 / _mm256_cmpgt_epi16  (AVX2)
// ----------------------------------------------------------------------------
// Lanes 0xFFFF on TRUE, 0x0000 on FALSE; cmpgt is the SIGNED i16 compare.
// ----------------------------------------------------------------------------

/// Lane-wise equality; result is 0xFFFF on equal, 0x0000 otherwise.
#[inline]
pub fn cmpeq_epi16(a: Words16x16, b: Words16x16) -> Words16x16 {
    lanewise_eq_mask_u16(a, b)
}

/// Lane-wise SIGNED greater-than; result is 0xFFFF on `a > b`, else 0x0000.
#[inline]
pub fn cmpgt_epi16(a: Words16x16, b: Words16x16) -> Words16x16 {
    lanewise_sgt_mask_i16(a, b)
}

// ----------------------------------------------------------------------------
// _mm256_and_si256 / _mm256_andnot_si256 / _mm256_or_si256  (AVX2)
// ----------------------------------------------------------------------------
// 256-bit bitwise ops; view-agnostic. Stated on `Bytes256` for generality.
// andnot: dst := (NOT a) AND b.
// ----------------------------------------------------------------------------

/// `dst := a AND b`.
#[inline]
pub fn and_si256(a: Bytes256, b: Bytes256) -> Bytes256 {
    lanewise_and_u8(a, b)
}

/// `dst := (NOT a) AND b`.
#[inline]
pub fn andnot_si256(a: Bytes256, b: Bytes256) -> Bytes256 {
    lanewise_andnot_u8(a, b)
}

/// `dst := a OR b`.
#[inline]
pub fn or_si256(a: Bytes256, b: Bytes256) -> Bytes256 {
    lanewise_or_u8(a, b)
}

// ----------------------------------------------------------------------------
// _mm256_slli_epi64 / _mm256_srli_epi64  (AVX2)
// ----------------------------------------------------------------------------
// Per-64-bit-lane logical shifts. `count >= 64` zeros the lane.
// ----------------------------------------------------------------------------

/// Lane-wise logical shift left of 64-bit lanes by `count` bits.
#[inline]
pub fn slli_epi64(a: Qwords256, count: i32) -> Qwords256 {
    let mut out = [0u64; 4];
    if 0 <= count && count < 64 {
        let c = count as u32;
        for i in 0..4 { out[i] = a[i] << c; }
    }
    out
}

/// Lane-wise logical shift right of 64-bit lanes by `count` bits.
#[inline]
pub fn srli_epi64(a: Qwords256, count: i32) -> Qwords256 {
    let mut out = [0u64; 4];
    if 0 <= count && count < 64 {
        let c = count as u32;
        for i in 0..4 { out[i] = a[i] >> c; }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_views() {
        let w: Words16x16 = core::array::from_fn(|i| (i as u16) * 0x1111);
        assert_eq!(bytes256_to_words16x16(words16x16_to_bytes256(w)), w);
        let q: Qwords256 = [0x0123_4567_89AB_CDEF, !0, 0, 0x8000_0000_0000_0000];
        assert_eq!(bytes256_to_qwords256(qwords256_to_bytes256(q)), q);
    }

    #[test]
    fn setzero_set1() {
        assert_eq!(setzero_si256(), [0u8; 32]);
        assert_eq!(set1_epi16(0x1234), [0x1234u16; 16]);
        assert_eq!(set1_epi16(-1),     [0xFFFFu16; 16]);
    }

    #[test]
    fn arith_epi16_lane_doubling() {
        let a: Words16x16 = core::array::from_fn(|i| i as u16);
        let b: Words16x16 = core::array::from_fn(|i| (15 - i) as u16);
        let s = add_epi16(a, b);
        assert!(s.iter().all(|&x| x == 15));
        let d = sub_epi16(a, b);
        for i in 0..16 {
            assert_eq!(d[i], (i as u16).wrapping_sub((15 - i) as u16));
        }
    }

    #[test]
    fn mul_epi16_high_low() {
        let a: Words16x16 = [0xFFFF; 16];
        let b: Words16x16 = [0xFFFF; 16];
        assert_eq!(mullo_epi16(a, b), [0x0001u16; 16]);
        assert_eq!(mulhi_epu16(a, b), [0xFFFEu16; 16]);
    }

    #[test]
    fn cmp_epi16_masks() {
        let a: Words16x16 = core::array::from_fn(|i| i as u16);
        let b: Words16x16 = [5u16; 16];
        let gt = cmpgt_epi16(a, b);
        for i in 0..16 {
            assert_eq!(gt[i], if i > 5 { 0xFFFF } else { 0 });
        }
        assert_eq!(cmpeq_epi16(a, a), [0xFFFFu16; 16]);
    }

    #[test]
    fn bitwise_si256() {
        let a: Bytes256 = [0xAA; 32];
        let b: Bytes256 = [0xCC; 32];
        assert_eq!(and_si256(a, b),    [0x88u8; 32]);
        assert_eq!(or_si256(a, b),     [0xEEu8; 32]);
        assert_eq!(andnot_si256(a, b), [0x44u8; 32]);
    }

    #[test]
    fn shifts_epi64() {
        let q: Qwords256 = [1, 0x100, 1u64 << 63, 0xFFFF_FFFF_FFFF_FFFF];
        assert_eq!(slli_epi64(q, 1)[2], 0);                           // overflow → 0
        assert_eq!(slli_epi64(q, 4),    [16, 0x1000, 0, 0xFFFF_FFFF_FFFF_FFF0]);
        assert_eq!(srli_epi64(q, 60),   [0, 0, 8, 0xF]);
        assert_eq!(slli_epi64(q, 64),   [0; 4]);
        assert_eq!(srli_epi64(q, -1),   [0; 4]);
    }

    #[test]
    fn load_store_round_trip() {
        let arr: [u64; 6] = [1, 2, 3, 4, 5, 6];
        let v = loadu_si256_u64(&arr, 1);
        assert_eq!(v, [2, 3, 4, 5]);
        let mut out = [0u64; 6];
        storeu_si256_u64(&mut out, 1, v);
        assert_eq!(out, [0, 2, 3, 4, 5, 0]);

        let warr: [u16; 20] = core::array::from_fn(|i| i as u16);
        let wv = loadu_si256_u16(&warr, 2);
        assert_eq!(wv, core::array::from_fn::<u16, 16, _>(|i| (i + 2) as u16));
        let mut wout = [0u16; 20];
        storeu_si256_u16(&mut wout, 2, wv);
        assert_eq!(&wout[2..18], &wv);
    }
}
