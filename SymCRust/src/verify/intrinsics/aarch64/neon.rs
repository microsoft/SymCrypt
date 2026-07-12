//! Transcribed shims for Armv8-A NEON (`target_feature = "neon"`) intrinsics
//! used by SymCrypt's ML-KEM driver `ntt_neon.rs` and AES driver
//! `aes_neon.rs`.
//!
//! Every function below is a plain Rust transcription of the Arm Architecture
//! Reference Manual ("Arm ARM") pseudocode for the corresponding
//! `core::arch::aarch64::*` intrinsic.  Lane types are NEON-specific arrays
//! defined at the top of this file (one per ACLE vector type that ML-KEM
//! and AES need).
//!
//! ## Endianness assumption
//!
//! All `vreinterpretq_*` shims route through the shared little-endian
//! bitcast helpers in `crate::verify::intrinsics::lanes`, which are
//! implemented as byte-array round trips using
//! `to_le_bytes`/`from_le_bytes`. This is bit-identical to the
//! architectural reinterpret (which is a true register-level no-op) **only
//! on little-endian aarch64** (the default for `aarch64-unknown-linux-gnu`,
//! `aarch64-apple-darwin`, Windows-on-ARM, …). On big-endian aarch64 (BE8)
//! the architectural vreinterpret leaves the register unchanged but a
//! subsequent `vst1q_u8` after `vreinterpretq_u8_u16` would emit the bytes
//! in a different order from these shims. Charon extraction is currently
//! pinned to LE targets (`--targets aarch64-unknown-linux-gnu`), so this
//! is safe; the LE assumption is recorded once in `lanes.rs` for both arch
//! families, and re-stated here so future BE retargeting flags it.
//!
//! ## Call-site closure (post-M2 audit, 2026-05-22)
//!
//! `ntt_neon.rs` uses (NEON-side): `vaddq_u16`, `vandq_u16`, `vcgeq_u16`,
//! `vcltzq_s16`, `vdupq_n_u16`, `vget_low_u16`, `vget_low_u32`, `vld1q_u16`,
//! `vld1q_dup_u32`, `vld1q_dup_u64`, `vmlal_high_u16`, `vmlal_u16`,
//! `vmull_high_u16`, `vmull_u16`, `vmulq_u16`, `vreinterpretq_s16_u16`,
//! `vreinterpretq_u16_u32`, `vreinterpretq_u16_u64`, `vreinterpretq_u32_u16`,
//! `vst1_lane_u32`, `vst1_u16`, `vst1q_u16`, `vsubq_u16`.
//!
//! `aes_neon.rs` uses (NEON-side): `vdupq_n_u32`, `vdupq_n_u64`, `veorq_u8`,
//! `vgetq_lane_u32`, `vld1q_u8`, `vreinterpretq_u32_u8`,
//! `vreinterpretq_u8_u32`, `vreinterpretq_u8_u64`, `vst1q_u8`. (AES round
//! intrinsics are in `aarch64/aes.rs`.)
//!
//! Intrinsics deliberately NOT shimmed (confirmed not called by any driver):
//! NEON shifts (`vshlq_n_*`, `vshrq_n_*`), trn/zip lane shuffles
//! (`vtrn1q_*`, `vzip1q_*`), `vextq_*`, `vqdmulhq_s16`, `vrshrq_n_*`.
//!
//! Status: 30 transcribed shims, 0 axioms.
//!
//! Coverage map (intrinsic ↔ shim):
//! ```text
//! Arithmetic on 16-bit lanes (Uint16x8 = [u16; 8]):
//!   vaddq_u16 / vsubq_u16 / vmulq_u16          ←→ vaddq_u16 / vsubq_u16 / vmulq_u16
//!   vmull_u16 / vmull_high_u16                 ←→ vmull_u16 / vmull_high_u16
//!   vmlal_u16 / vmlal_high_u16                 ←→ vmlal_u16 / vmlal_high_u16
//! Bitwise:
//!   vandq_u16 / veorq_u8                       ←→ vandq_u16 / veorq_u8
//! Compares:
//!   vcgeq_u16 / vcltzq_s16                     ←→ vcgeq_u16 / vcltzq_s16
//! Broadcasts:
//!   vdupq_n_u16 / vdupq_n_u32 / vdupq_n_u64    ←→ vdupq_n_u16 / vdupq_n_u32 / vdupq_n_u64
//! Load / store:
//!   vld1q_u8 / vld1q_u16                       ←→ vld1q_u8 / vld1q_u16
//!   vld1q_dup_u32 / vld1q_dup_u64              ←→ vld1q_dup_u32 / vld1q_dup_u64
//!   vst1q_u8 / vst1q_u16 / vst1_u16            ←→ vst1q_u8 / vst1q_u16 / vst1_u16
//!   vst1_lane_u32::<LANE> / vgetq_lane_u32::<LANE>
//! Lane shuffles:
//!   vget_low_u16 / vget_low_u32 / vuzp2q_u16   ←→ vget_low_u16 / vget_low_u32 / vuzp2q_u16
//! Reinterprets (all pure bit-casts via LE byte-array round trip):
//!   vreinterpretq_u8_u16 / _u16_u8 / _s16_u16 / _u16_s16 /
//!   _u32_u16 / _u16_u32 / _u64_u16 / _u16_u64 / _u8_s16 / _s16_u8 /
//!   _u8_u32 / _u32_u8 / _u8_u64
//! ```

#![allow(dead_code, non_camel_case_types)]

// ----------------------------------------------------------------------------
// Lane-typed views of NEON vectors used by ML-KEM. Naming mirrors ACLE.
// ----------------------------------------------------------------------------

/// 128-bit Q-register as 16 bytes.
pub type Uint8x16 = [u8; 16];
/// 128-bit Q-register as eight `u16` lanes.
pub type Uint16x8 = [u16; 8];
/// 128-bit Q-register as four `u32` lanes.
pub type Uint32x4 = [u32; 4];
/// 128-bit Q-register as two `u64` lanes.
pub type Uint64x2 = [u64; 2];
/// 128-bit Q-register as eight signed `i16` lanes.
pub type Int16x8 = [i16; 8];
/// 64-bit D-register as four `u16` lanes (low half of a Q-reg).
pub type Uint16x4 = [u16; 4];
/// 64-bit D-register as two `u32` lanes (low half of a Q-reg).
pub type Uint32x2 = [u32; 2];

// ----------------------------------------------------------------------------
// Lane-wise arithmetic on u16 (Q-form).
// ----------------------------------------------------------------------------

/// `vaddq_u16(a, b)`: lane-wise wrapping `u16` addition.
#[inline]
pub fn vaddq_u16(a: Uint16x8, b: Uint16x8) -> Uint16x8 {
    lanewise_wrapping_add_u16(a, b)
}

/// `vsubq_u16(a, b)`: lane-wise wrapping `u16` subtraction.
#[inline]
pub fn vsubq_u16(a: Uint16x8, b: Uint16x8) -> Uint16x8 {
    lanewise_wrapping_sub_u16(a, b)
}

/// `vmulq_u16(a, b)`: lane-wise wrapping `u16` multiplication (low half).
#[inline]
pub fn vmulq_u16(a: Uint16x8, b: Uint16x8) -> Uint16x8 {
    lanewise_wrapping_mul_u16(a, b)
}

// ----------------------------------------------------------------------------
// Widening multiplies and multiply-accumulates (u16 × u16 → u32).
// vmull_u16        : multiply LOW 64 bits of two u16x8 vectors,
//                    producing 4 u32 lanes.
// vmull_high_u16   : same on HIGH 64 bits.
// vmlal_u16        : accumulate vmull_u16 into a `u32x4`.
// vmlal_high_u16   : accumulate vmull_high_u16 into a `u32x4`.
// (Arm ARM §C7.2 vector-multiply-long instructions.)
// ----------------------------------------------------------------------------

/// `vmull_u16(a, b)`: widen-multiply low 4 lanes; result is u32x4.
#[inline]
pub fn vmull_u16(a: Uint16x4, b: Uint16x4) -> Uint32x4 {
    let mut out = [0u32; 4];
    for i in 0..4 { out[i] = (a[i] as u32) * (b[i] as u32); }
    out
}

/// `vmull_high_u16(a, b)`: widen-multiply high 4 lanes of u16x8 inputs.
#[inline]
pub fn vmull_high_u16(a: Uint16x8, b: Uint16x8) -> Uint32x4 {
    let mut out = [0u32; 4];
    for i in 0..4 { out[i] = (a[i + 4] as u32) * (b[i + 4] as u32); }
    out
}

/// `vmlal_u16(acc, a, b)`: `acc + vmull_u16(a, b)`, lane-wise wrapping `u32`.
#[inline]
pub fn vmlal_u16(acc: Uint32x4, a: Uint16x4, b: Uint16x4) -> Uint32x4 {
    let mut out = [0u32; 4];
    for i in 0..4 {
        out[i] = acc[i].wrapping_add((a[i] as u32) * (b[i] as u32));
    }
    out
}

/// `vmlal_high_u16(acc, a, b)`: `acc + vmull_high_u16(a, b)`, lane-wise wrapping `u32`.
#[inline]
pub fn vmlal_high_u16(acc: Uint32x4, a: Uint16x8, b: Uint16x8) -> Uint32x4 {
    let mut out = [0u32; 4];
    for i in 0..4 {
        out[i] = acc[i].wrapping_add((a[i + 4] as u32) * (b[i + 4] as u32));
    }
    out
}

// ----------------------------------------------------------------------------
// Bitwise.
// ----------------------------------------------------------------------------

/// `vandq_u16(a, b)`: lane-wise bitwise AND on u16x8.
#[inline]
pub fn vandq_u16(a: Uint16x8, b: Uint16x8) -> Uint16x8 {
    lanewise_and_u16(a, b)
}

/// `veorq_u8(a, b)`: lane-wise bitwise XOR on u8x16.
#[inline]
pub fn veorq_u8(a: Uint8x16, b: Uint8x16) -> Uint8x16 {
    lanewise_xor_u8(a, b)
}

// ----------------------------------------------------------------------------
// Compares. NEON returns an all-ones (0xFFFF) lane on TRUE, zero on FALSE.
// ----------------------------------------------------------------------------

/// `vcgeq_u16(a, b)`: lane-wise unsigned `a >= b`; 0xFFFF if TRUE else 0.
#[inline]
pub fn vcgeq_u16(a: Uint16x8, b: Uint16x8) -> Uint16x8 {
    let mut out = [0u16; 8];
    for i in 0..8 { out[i] = if a[i] >= b[i] { 0xFFFF } else { 0 }; }
    out
}

/// `vcltzq_s16(a)`: lane-wise signed `a < 0`; 0xFFFF if TRUE else 0.
#[inline]
pub fn vcltzq_s16(a: Int16x8) -> Uint16x8 {
    let mut out = [0u16; 8];
    for i in 0..8 { out[i] = if a[i] < 0 { 0xFFFF } else { 0 }; }
    out
}

// ----------------------------------------------------------------------------
// Broadcasts (DUP).
// ----------------------------------------------------------------------------

/// `vdupq_n_u16(a)`: broadcast scalar to all 8 u16 lanes.
#[inline]
pub fn vdupq_n_u16(a: u16) -> Uint16x8 { [a; 8] }

/// `vdupq_n_u32(a)`: broadcast scalar to all 4 u32 lanes.
#[inline]
pub fn vdupq_n_u32(a: u32) -> Uint32x4 { [a; 4] }

/// `vdupq_n_u64(a)`: broadcast scalar to both u64 lanes.
#[inline]
pub fn vdupq_n_u64(a: u64) -> Uint64x2 { [a; 2] }

// ----------------------------------------------------------------------------
// Loads / stores. NEON contiguous Q-form load (16 bytes); D-form (8 bytes);
// load-and-replicate (`vld1q_dup_*`) reads one scalar from memory and
// broadcasts it to every lane of the destination.
// ----------------------------------------------------------------------------

/// `vld1q_u8(p)`: load 16 contiguous bytes from `bytes[at..at+16]`.
/// Panics if `at + 16 > bytes.len()`.
#[inline]
pub fn vld1q_u8(bytes: &[u8], at: usize) -> Uint8x16 {
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[at..at + 16]);
    out
}

/// `vld1q_u16(p)`: load 8 contiguous u16s from `arr[at..at+8]`.
/// Panics if `at + 8 > arr.len()`.
#[inline]
pub fn vld1q_u16(arr: &[u16], at: usize) -> Uint16x8 {
    let mut out = [0u16; 8];
    for i in 0..8 { out[i] = arr[at + i]; }
    out
}

/// `vld1q_dup_u32(p)`: load one u32 from `arr[at]` and broadcast to all 4 lanes.
#[inline]
pub fn vld1q_dup_u32(arr: &[u32], at: usize) -> Uint32x4 {
    [arr[at]; 4]
}

/// `vld1q_dup_u64(p)`: load one u64 from `arr[at]` and broadcast to both lanes.
#[inline]
pub fn vld1q_dup_u64(arr: &[u64], at: usize) -> Uint64x2 {
    [arr[at]; 2]
}

/// `vst1q_u8(p, v)`: store 16 bytes to `bytes[at..at+16]`.
#[inline]
pub fn vst1q_u8(bytes: &mut [u8], at: usize, v: Uint8x16) {
    bytes[at..at + 16].copy_from_slice(&v);
}

/// `vst1q_u16(p, v)`: store 8 u16s to `arr[at..at+8]`.
#[inline]
pub fn vst1q_u16(arr: &mut [u16], at: usize, v: Uint16x8) {
    for i in 0..8 { arr[at + i] = v[i]; }
}

/// `vst1_u16(p, v)`: D-form: store 4 u16s to `arr[at..at+4]`.
#[inline]
pub fn vst1_u16(arr: &mut [u16], at: usize, v: Uint16x4) {
    for i in 0..4 { arr[at + i] = v[i]; }
}

/// `vst1_lane_u32::<LANE>(p, v)`: store lane `LANE` of u32x2 to `arr[at]`.
/// Panics if `LANE >= 2`.
#[inline]
pub fn vst1_lane_u32<const LANE: i32>(arr: &mut [u32], at: usize, v: Uint32x2) {
    arr[at] = v[LANE as usize];
}

/// `vgetq_lane_u32::<LANE>(v)`: extract lane `LANE` from u32x4.
#[inline]
pub fn vgetq_lane_u32<const LANE: i32>(v: Uint32x4) -> u32 {
    v[LANE as usize]
}

// ----------------------------------------------------------------------------
// Lane shuffles.
// ----------------------------------------------------------------------------

/// `vget_low_u16(v)`: low 4 u16 lanes of a u16x8.
#[inline]
pub fn vget_low_u16(v: Uint16x8) -> Uint16x4 { [v[0], v[1], v[2], v[3]] }

/// `vget_low_u32(v)`: low 2 u32 lanes of a u32x4.
#[inline]
pub fn vget_low_u32(v: Uint32x4) -> Uint32x2 { [v[0], v[1]] }

/// `vuzp2q_u16(a, b)`: deinterleave-second of two u16x8 vectors.
/// Result lane k = a[2k+1] (k < 4) else b[2(k-4)+1].
/// (Arm ARM C7.2: UZP2 — "unzip vectors", returning the odd-indexed lanes.)
#[inline]
pub fn vuzp2q_u16(a: Uint16x8, b: Uint16x8) -> Uint16x8 {
    [
        a[1], a[3], a[5], a[7],
        b[1], b[3], b[5], b[7],
    ]
}

// ----------------------------------------------------------------------------
// Reinterprets. All NEON `vreinterpretq_*` intrinsics are pure bit casts of
// the same 128-bit value; we route them through the shared little-endian
// bitcast helpers in `crate::verify::intrinsics::lanes` so that a single
// pool of Lean step theorems covers both arch families. The shared
// helpers' lane type aliases (`Bytes` = `[u8; 16]`, `Words` = `[u16; 8]`,
// `Dwords` = `[u32; 4]`, `Qwords` = `[u64; 2]`) coincide pointwise with
// the NEON aliases declared above; Rust treats them as the same
// underlying type, and Aeneas erases the alias layer at extraction.
// ----------------------------------------------------------------------------

use super::lanes::{
    bytes_to_words, words_to_bytes,
    bytes_to_dwords, dwords_to_bytes,
    bytes_to_qwords, qwords_to_bytes,
};

use super::lanewise::{
    lanewise_and_u16, lanewise_xor_u8,
    lanewise_wrapping_add_u16, lanewise_wrapping_sub_u16,
    lanewise_wrapping_mul_u16,
};

#[inline] pub fn vreinterpretq_u8_u16(v: Uint16x8) -> Uint8x16 { words_to_bytes(v) }
#[inline] pub fn vreinterpretq_u16_u8(v: Uint8x16) -> Uint16x8 { bytes_to_words(v) }

#[inline] pub fn vreinterpretq_s16_u16(v: Uint16x8) -> Int16x8 {
    let mut out = [0i16; 8];
    for i in 0..8 { out[i] = v[i] as i16; }
    out
}

#[inline] pub fn vreinterpretq_u16_s16(v: Int16x8) -> Uint16x8 {
    let mut out = [0u16; 8];
    for i in 0..8 { out[i] = v[i] as u16; }
    out
}

#[inline] pub fn vreinterpretq_u32_u16(v: Uint16x8) -> Uint32x4 {
    bytes_to_dwords(words_to_bytes(v))
}

#[inline] pub fn vreinterpretq_u16_u32(v: Uint32x4) -> Uint16x8 {
    bytes_to_words(dwords_to_bytes(v))
}

#[inline] pub fn vreinterpretq_u64_u16(v: Uint16x8) -> Uint64x2 {
    bytes_to_qwords(words_to_bytes(v))
}

#[inline] pub fn vreinterpretq_u16_u64(v: Uint64x2) -> Uint16x8 {
    bytes_to_words(qwords_to_bytes(v))
}

#[inline] pub fn vreinterpretq_u8_s16(v: Int16x8) -> Uint8x16 {
    words_to_bytes(vreinterpretq_u16_s16(v))
}

#[inline] pub fn vreinterpretq_s16_u8(v: Uint8x16) -> Int16x8 {
    vreinterpretq_s16_u16(bytes_to_words(v))
}

// Reinterprets used by aes_neon.rs (post-M2 call-site audit).

#[inline] pub fn vreinterpretq_u8_u32(v: Uint32x4) -> Uint8x16 { dwords_to_bytes(v) }
#[inline] pub fn vreinterpretq_u32_u8(v: Uint8x16) -> Uint32x4 { bytes_to_dwords(v) }
#[inline] pub fn vreinterpretq_u8_u64(v: Uint64x2) -> Uint8x16 { qwords_to_bytes(v) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arith_u16() {
        let a: Uint16x8 = [1, 2, 3, 4, 5, 6, 7, 8];
        let b: Uint16x8 = [u16::MAX, 0, 1, 1, 1, 1, 1, 1];
        assert_eq!(vaddq_u16(a, b), [0, 2, 4, 5, 6, 7, 8, 9]);
        assert_eq!(vsubq_u16(a, b)[0], 2);
        assert_eq!(vmulq_u16(a, [2; 8]), [2, 4, 6, 8, 10, 12, 14, 16]);
    }

    #[test]
    fn widen_and_accumulate() {
        let a: Uint16x4 = [0xFFFF, 1, 2, 3];
        let b: Uint16x4 = [0xFFFF, 4, 5, 6];
        assert_eq!(vmull_u16(a, b), [0xFFFE_0001, 4, 10, 18]);
        assert_eq!(vmlal_u16([1; 4], a, b), [0xFFFE_0002, 5, 11, 19]);

        let ah: Uint16x8 = [0, 0, 0, 0, 0xFFFF, 1, 2, 3];
        let bh: Uint16x8 = [0, 0, 0, 0, 0xFFFF, 4, 5, 6];
        assert_eq!(vmull_high_u16(ah, bh), [0xFFFE_0001, 4, 10, 18]);
        assert_eq!(vmlal_high_u16([1; 4], ah, bh), [0xFFFE_0002, 5, 11, 19]);
    }

    #[test]
    fn bitwise_and_xor() {
        assert_eq!(vandq_u16([0xAAAA; 8], [0xCCCC; 8]), [0x8888u16; 8]);
        assert_eq!(veorq_u8([0xAA; 16], [0xCC; 16]), [0x66u8; 16]);
    }

    #[test]
    fn compares() {
        let a: Uint16x8 = [0, 1, 2, 3, 4, 5, 6, 7];
        let b: Uint16x8 = [4, 4, 4, 4, 4, 4, 4, 4];
        let want: Uint16x8 = [0, 0, 0, 0, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF];
        assert_eq!(vcgeq_u16(a, b), want);

        let s: Int16x8 = [-1, 0, -32768, 32767, 1, -2, 3, -4];
        let zw: Uint16x8 = [0xFFFF, 0, 0xFFFF, 0, 0, 0xFFFF, 0, 0xFFFF];
        assert_eq!(vcltzq_s16(s), zw);
    }

    #[test]
    fn dup_and_load_store() {
        assert_eq!(vdupq_n_u16(7), [7u16; 8]);
        assert_eq!(vdupq_n_u32(7), [7u32; 4]);
        assert_eq!(vdupq_n_u64(7), [7u64; 2]);

        let arr_u16: [u16; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        assert_eq!(vld1q_u16(&arr_u16, 2), [3, 4, 5, 6, 7, 8, 9, 10]);

        let arr_u32: [u32; 3] = [10, 20, 30];
        assert_eq!(vld1q_dup_u32(&arr_u32, 1), [20; 4]);

        let mut out_u16 = [0u16; 12];
        vst1q_u16(&mut out_u16, 1, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&out_u16[1..9], &[1u16, 2, 3, 4, 5, 6, 7, 8]);

        let mut out_u32 = [0u32; 4];
        vst1_lane_u32::<1>(&mut out_u32, 3, [99, 77]);
        assert_eq!(out_u32, [0, 0, 0, 77]);

        assert_eq!(vgetq_lane_u32::<2>([10, 20, 30, 40]), 30);
    }

    #[test]
    fn shuffles_and_lows() {
        assert_eq!(vget_low_u16([1, 2, 3, 4, 5, 6, 7, 8]), [1, 2, 3, 4]);
        assert_eq!(vget_low_u32([10, 20, 30, 40]), [10, 20]);
        assert_eq!(
            vuzp2q_u16([1, 2, 3, 4, 5, 6, 7, 8], [11, 22, 33, 44, 55, 66, 77, 88]),
            [2, 4, 6, 8, 22, 44, 66, 88]
        );
    }

    #[test]
    fn reinterprets_round_trip() {
        let v: Uint16x8 = [0x0102, 0x0304, 0x0506, 0x0708, 0x090A, 0x0B0C, 0x0D0E, 0x0F10];
        assert_eq!(vreinterpretq_u16_u8(vreinterpretq_u8_u16(v)), v);
        assert_eq!(vreinterpretq_u16_u32(vreinterpretq_u32_u16(v)), v);
        assert_eq!(vreinterpretq_u16_u64(vreinterpretq_u64_u16(v)), v);
        assert_eq!(vreinterpretq_u16_s16(vreinterpretq_s16_u16(v)), v);

        let b: Uint8x16 = [
            0x02, 0x01, 0x04, 0x03, 0x06, 0x05, 0x08, 0x07,
            0x0A, 0x09, 0x0C, 0x0B, 0x0E, 0x0D, 0x10, 0x0F,
        ];
        assert_eq!(vreinterpretq_u8_u16(v), b);
    }

    #[test]
    fn reinterprets_u8_u32_u64_round_trip() {
        // u32 ↔ u8: LE pack/unpack
        let w: Uint32x4 = [0x0403_0201, 0x0807_0605, 0x0C0B_0A09, 0x100F_0E0D];
        let wb: Uint8x16 = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        assert_eq!(vreinterpretq_u8_u32(w), wb);
        assert_eq!(vreinterpretq_u32_u8(wb), w);
        assert_eq!(vreinterpretq_u32_u8(vreinterpretq_u8_u32(w)), w);

        // u64 → u8: LE pack (one-way; aes_neon only needs this direction)
        let q: Uint64x2 = [0x0807_0605_0403_0201, 0x100F_0E0D_0C0B_0A09];
        assert_eq!(vreinterpretq_u8_u64(q), wb);
    }
}
