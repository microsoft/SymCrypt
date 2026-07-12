//! Transcribed shims for SSE2 (`target_feature = "sse2"`) intrinsics used by
//! SymCrypt's SHA-2 (`sha2_impl.rs`), GHASH (`ghash_xmm.rs`), AES
//! (`aes_xmm.rs`), and ML-KEM NTT (`ntt_xmm.rs`) drivers.
//!
//! Every function below is a plain Rust transcription of the Intel SDM
//! "Operation:" pseudocode for the corresponding `core::arch::x86_64::_mm_*`
//! intrinsic. Aeneas extracts them as ordinary Lean `def`s in
//! `lean/Intrinsics/Code/Funs.lean`; the per-intrinsic step specs and
//! citations live in `lean/Intrinsics/X86_64/Sse2.lean`. Fidelity to silicon
//! is enforced by `tests/x86_64_sse2_hw_extras.rs` (differential against
//! `core::arch::x86_64::_mm_*`).
//!
//! ## Shift-count contract
//!
//! The legacy Rust signatures `_mm_slli_epi32(a, count: i32)`,
//! `_mm_slli_epi64`, `_mm_srli_epi32`, `_mm_srli_si128` accept an `i32`
//! count for historical reasons (modern code uses the const-generic
//! `::<IMM8>` form). Per Intel SDM, the hardware reads `count` as an
//! unsigned value (low 8 bits of an immediate, or the low 64 bits of an
//! XMM source); if the value exceeds the lane width then every destination
//! lane is set to zero. Our shims reproduce this faithfully:
//!
//! * For non-negative `count` strictly less than the lane width, we shift
//!   normally.
//! * For any other `i32` input (including all negative values, which silicon
//!   would reinterpret as unsigned and therefore see as huge), we return
//!   zero — matching silicon's overflow rule.
//!
//! Call sites in `ghash_xmm.rs` always pass non-negative compile-time
//! constants in `[0, lane_bits)`, so the "else zero" branch is never
//! actually entered by extracted code. The Lean step theorem may therefore
//! attach `0 ≤ count < lane_bits` as a precondition and prove a pure
//! lane-wise shift equality; the broader fall-through behaviour is here as
//! a defensive total-function definition (Aeneas extracts total Rust
//! functions; we cannot rely on `unreachable!` for unreached branches).
//!
//! ## Call-site closure (post-M2 audit, 2026-05-22)
//!
//! `sha2/sha2_impl.rs`  : `_mm_loadu_si128`, `_mm_storeu_si128`,
//!                        `_mm_set_epi8`, `_mm_add_epi32`,
//!                        `_mm_shuffle_epi32`,
//!                        `_mm_unpacklo_epi64`, `_mm_unpackhi_epi64`.
//! `aes/aes_xmm.rs`     : `_mm_loadu_si128`, `_mm_storeu_si128`,
//!                        `_mm_setzero_si128`, `_mm_set1_epi32`,
//!                        `_mm_set_epi32`, `_mm_set_epi8`, `_mm_xor_si128`,
//!                        `_mm_add_epi32`, `_mm_cvtsi128_si32`. (AES round
//!                        / keygen / clmul / shuffle_epi8 are in
//!                        `x86_64/aes.rs`, `pclmulqdq.rs`, `ssse3.rs`.)
//! `aes/ghash/ghash_xmm.rs` : `_mm_loadu_si128`, `_mm_store_si128`,
//!                            `_mm_storeu_si128`, `_mm_set_epi32`,
//!                            `_mm_set_epi64x`, `_mm_set_epi8`,
//!                            `_mm_xor_si128`, `_mm_shuffle_epi32`,
//!                            `_mm_slli_epi32`, `_mm_slli_epi64`,
//!                            `_mm_srli_epi32`, `_mm_srli_si128`.
//!                            (clmul and shuffle_epi8 elsewhere.)
//! `mlkem/ntt_xmm.rs`   : `_mm_loadu_si128`, `_mm_storeu_si128`,
//!                        `_mm_loadu_si64`, `_mm_storeu_si64`,
//!                        `_mm_cvtsi128_si32`, `_mm_cvtsi32_si128`,
//!                        `_mm_set1_epi16`, `_mm_add_epi16`,
//!                        `_mm_sub_epi16`, `_mm_mullo_epi16`,
//!                        `_mm_mulhi_epu16`, `_mm_cmpeq_epi16`,
//!                        `_mm_cmpgt_epi16`, `_mm_and_si128`,
//!                        `_mm_andnot_si128`.
//!
//! Intrinsics deliberately NOT shimmed (confirmed not called by any driver):
//! signed-half multiply `_mm_mulhi_epi16` (ML-KEM uses centred residues but
//! keeps them in `[0, q)` and reduces with `_mm_mulhi_epu16`); other shuffle
//! / permute / blend / unpack8/16/32 ops; the saturating `_mm_adds_*` family.
//!
//! Status: 30 transcribed shims, 0 axioms.
//!
//! Coverage map (intrinsic ↔ shim):
//! ```text
//! _mm_loadu_si128   (u32 view)  ←→ loadu_si128_u32
//! _mm_loadu_si128   (u8  view)  ←→ loadu_si128_u8
//! _mm_storeu_si128  (u32 view)  ←→ storeu_si128_u32
//! _mm_set_epi8                  ←→ set_epi8
//! _mm_add_epi32                 ←→ add_epi32
//! _mm_shuffle_epi32             ←→ shuffle_epi32
//! _mm_unpacklo_epi64            ←→ unpacklo_epi64
//! _mm_unpackhi_epi64            ←→ unpackhi_epi64
//! ```

#![allow(dead_code)]

pub use super::lanes::{
    Bytes, Dwords, Qwords, Words,
    bytes_to_dwords
};

use super::lanewise::{
    lanewise_and_u8, lanewise_andnot_u8, lanewise_or_u8, lanewise_xor_u8,
    lanewise_wrapping_add_u16, lanewise_wrapping_sub_u16,
    lanewise_wrapping_mul_u16, lanewise_mulhi_u16,
    lanewise_wrapping_add_u32,
    lanewise_eq_mask_u16, lanewise_sgt_mask_i16,
};

// ----------------------------------------------------------------------------
// _mm_loadu_si128 / _mm_storeu_si128  (SSE2)
// ----------------------------------------------------------------------------
// Operation (load):  DEST[127:0] := MEM[mem_addr+127:mem_addr]
// Operation (store): MEM[mem_addr+127:mem_addr] := SRC[127:0]
// ----------------------------------------------------------------------------

/// Load 4 contiguous u32s from `arr` starting at u32 index `at`.
/// Equivalent to `_mm_loadu_si128(arr.as_ptr().add(at) as *const __m128i)`
/// with the result reinterpreted as `[u32; 4]`.
///
/// Panics if `at + 4 > arr.len()`.
#[inline]
pub fn loadu_si128_u32(arr: &[u32], at: usize) -> Dwords {
    [arr[at], arr[at + 1], arr[at + 2], arr[at + 3]]
}

/// Store 4 contiguous u32s into `arr` starting at u32 index `at`.
/// Equivalent to `_mm_storeu_si128(arr.as_mut_ptr().add(at) as *mut __m128i, v)`
/// after reinterpreting `v` as `[u32; 4]`.
///
/// Panics if `at + 4 > arr.len()`.
#[inline]
pub fn storeu_si128_u32(arr: &mut [u32], at: usize, v: Dwords) {
    arr[at] = v[0];
    arr[at + 1] = v[1];
    arr[at + 2] = v[2];
    arr[at + 3] = v[3];
}

/// Load 16 contiguous bytes from `bytes` starting at byte offset `at`,
/// and present them as four little-endian dwords (the `Dwords` view).
/// Equivalent to `_mm_loadu_si128(bytes.as_ptr().add(at) as *const __m128i)`.
///
/// Panics if `at + 16 > bytes.len()`.
#[inline]
pub fn loadu_si128_u8(bytes: &[u8], at: usize) -> Dwords {
    let mut b: Bytes = [0; 16];
    b.copy_from_slice(&bytes[at..at + 16]);
    bytes_to_dwords(b)
}

// ----------------------------------------------------------------------------
// _mm_set_epi8  (SSE2)
// ----------------------------------------------------------------------------
// Operation: arguments are listed HIGH byte first.
//   dst[127:120] := b15
//   dst[119:112] := b14
//   ...
//   dst[7:0]     := b0
// ----------------------------------------------------------------------------

/// Build a 128-bit byte vector from 16 explicit bytes, with `b15` as the
/// HIGH byte and `b0` as the LOW byte. Argument order matches Intel's
/// `_mm_set_epi8(b15, b14, …, b1, b0)`.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn set_epi8(
    b15: i8, b14: i8, b13: i8, b12: i8,
    b11: i8, b10: i8, b9:  i8, b8:  i8,
    b7:  i8, b6:  i8, b5:  i8, b4:  i8,
    b3:  i8, b2:  i8, b1:  i8, b0:  i8,
) -> Bytes {
    [
        b0  as u8, b1  as u8, b2  as u8, b3  as u8,
        b4  as u8, b5  as u8, b6  as u8, b7  as u8,
        b8  as u8, b9  as u8, b10 as u8, b11 as u8,
        b12 as u8, b13 as u8, b14 as u8, b15 as u8,
    ]
}

// ----------------------------------------------------------------------------
// _mm_add_epi32  (SSE2)
// ----------------------------------------------------------------------------
// Operation:
//   FOR j := 0 to 3
//     i := j*32
//     dst[i+31:i] := a[i+31:i] + b[i+31:i]   ; modulo 2^32
//   ENDFOR
// ----------------------------------------------------------------------------

/// Lane-wise wrapping `u32` addition.
#[inline]
pub fn add_epi32(a: Dwords, b: Dwords) -> Dwords {
    lanewise_wrapping_add_u32(a, b)
}

// ----------------------------------------------------------------------------
// _mm_shuffle_epi32  (SSE2)
// ----------------------------------------------------------------------------
// Operation (PSHUFD with 128-bit form):
//   FOR j := 0 to 3
//     k_lo := (imm8 >> (2*j))     AND 1
//     k_hi := (imm8 >> (2*j + 1)) AND 1
//     k := k_lo | (k_hi << 1)
//     dst[32*j + 31 : 32*j] := a[32*k + 31 : 32*k]
//   ENDFOR
//
// I.e. each pair of bits in imm8, low pair first, picks the source dword
// for one destination dword.
// ----------------------------------------------------------------------------

/// Permute four dwords of `a` according to the compile-time control byte
/// `IMM8` (mirrors `_mm_shuffle_epi32::<IMM8>`). Each pair of bits in `IMM8`
/// (low pair first) selects a source lane for the corresponding destination
/// lane.
///
/// The immediate is a `const` generic, *exactly as on silicon* — the real
/// intrinsic is `_mm_shuffle_epi32<const IMM8: i32>(a)` and only accepts a
/// positional literal via `#[rustc_legacy_const_generics]`. A single shim
/// therefore covers every control byte: Aeneas threads `IMM8` as a Lean
/// parameter (the same mechanism that carries the `const R`/`const B`
/// generics on `hkdf`/`hmac`), so no per-immediate specialisation is needed.
#[inline]
pub fn shuffle_epi32<const IMM8: i32>(a: Dwords) -> Dwords {
    let imm = IMM8 as u32;
    [
        a[((imm >> 0) & 0b11) as usize],
        a[((imm >> 2) & 0b11) as usize],
        a[((imm >> 4) & 0b11) as usize],
        a[((imm >> 6) & 0b11) as usize],
    ]
}

// ----------------------------------------------------------------------------
// _mm_unpacklo_epi64 / _mm_unpackhi_epi64  (SSE2)
// ----------------------------------------------------------------------------
// Operation (unpacklo):
//   dst[63:0]   := a[63:0]      ; a low qword
//   dst[127:64] := b[63:0]      ; b low qword
//
// Operation (unpackhi):
//   dst[63:0]   := a[127:64]    ; a high qword
//   dst[127:64] := b[127:64]    ; b high qword
//
// In dword-lane view, a qword spans two consecutive dwords:
//   low qword  = lanes 0,1   high qword = lanes 2,3
// ----------------------------------------------------------------------------

/// Interleave the LOW qwords of `a` and `b`. Result lane layout:
/// `[a[0], a[1], b[0], b[1]]`.
#[inline]
pub fn unpacklo_epi64(a: Dwords, b: Dwords) -> Dwords {
    [a[0], a[1], b[0], b[1]]
}

/// Interleave the HIGH qwords of `a` and `b`. Result lane layout:
/// `[a[2], a[3], b[2], b[3]]`.
#[inline]
pub fn unpackhi_epi64(a: Dwords, b: Dwords) -> Dwords {
    [a[2], a[3], b[2], b[3]]
}

// ----------------------------------------------------------------------------
// _mm_setzero_si128 / set1 / set_epi32 / set_epi64x  (SSE2)
// ----------------------------------------------------------------------------
// Constants: produce a 128-bit register pre-loaded with a specific lane
// pattern. Argument-order convention is HIGH lane first (matches Intel).
// ----------------------------------------------------------------------------

/// `dst[127:0] := 0`. View-agnostic; returned as `Bytes` for generality.
#[inline]
pub fn setzero_si128() -> Bytes {
    [0u8; 16]
}

/// `_mm_set1_epi16(a)`: broadcast `a` to every word lane.
#[inline]
pub fn set1_epi16(a: i16) -> Words {
    let v = a as u16;
    [v; 8]
}

/// `_mm_set1_epi32(a)`: broadcast `a` to every dword lane.
#[inline]
pub fn set1_epi32(a: i32) -> Dwords {
    let v = a as u32;
    [v; 4]
}

/// `_mm_set_epi32(e3, e2, e1, e0)`: HIGH lane first.
/// Result lane layout: `[e0, e1, e2, e3]`.
#[inline]
pub fn set_epi32(e3: i32, e2: i32, e1: i32, e0: i32) -> Dwords {
    [e0 as u32, e1 as u32, e2 as u32, e3 as u32]
}

/// `_mm_set_epi64x(e1, e0)`: HIGH qword first.
/// Result lane layout: `[e0, e1]`.
#[inline]
pub fn set_epi64x(e1: i64, e0: i64) -> Qwords {
    [e0 as u64, e1 as u64]
}

// ----------------------------------------------------------------------------
// _mm_add_epi16 / _mm_sub_epi16  (SSE2)
// ----------------------------------------------------------------------------
// Operation: FOR j := 0 to 7 ; i := j*16 ;
//   dst[i+15:i] := a[i+15:i] ± b[i+15:i]   ; modulo 2^16
// ----------------------------------------------------------------------------

/// Lane-wise wrapping `u16` addition.
#[inline]
pub fn add_epi16(a: Words, b: Words) -> Words {
    lanewise_wrapping_add_u16(a, b)
}

/// Lane-wise wrapping `u16` subtraction.
#[inline]
pub fn sub_epi16(a: Words, b: Words) -> Words {
    lanewise_wrapping_sub_u16(a, b)
}

// ----------------------------------------------------------------------------
// _mm_mullo_epi16 / _mm_mulhi_epu16  (SSE2)
// ----------------------------------------------------------------------------
// mullo: lane-wise SIGNED OR UNSIGNED low 16 bits of i16 * i16 product
//        (low half is identical for signed/unsigned).
// mulhi (epu16): lane-wise high 16 bits of u16 * u16 product.
// ----------------------------------------------------------------------------

/// Lane-wise low 16 bits of `a * b`. View on `i16` and `u16` agree.
#[inline]
pub fn mullo_epi16(a: Words, b: Words) -> Words {
    lanewise_wrapping_mul_u16(a, b)
}

/// Lane-wise high 16 bits of unsigned `a * b`.
#[inline]
pub fn mulhi_epu16(a: Words, b: Words) -> Words {
    lanewise_mulhi_u16(a, b)
}

// ----------------------------------------------------------------------------
// _mm_cmpeq_epi16 / _mm_cmpgt_epi16  (SSE2)
// ----------------------------------------------------------------------------
// Result lanes are 0xFFFF (all-ones) on TRUE, 0x0000 on FALSE.
// cmpgt is the SIGNED greater-than (i16); cmpeq is bit-equality.
// ----------------------------------------------------------------------------

/// Lane-wise equality; result is 0xFFFF on equal, 0x0000 otherwise.
#[inline]
pub fn cmpeq_epi16(a: Words, b: Words) -> Words {
    lanewise_eq_mask_u16(a, b)
}

/// Lane-wise SIGNED greater-than; result is 0xFFFF on `a > b`, else 0x0000.
#[inline]
pub fn cmpgt_epi16(a: Words, b: Words) -> Words {
    lanewise_sgt_mask_i16(a, b)
}

// ----------------------------------------------------------------------------
// _mm_and_si128 / _mm_andnot_si128 / _mm_or_si128 / _mm_xor_si128  (SSE2)
// ----------------------------------------------------------------------------
// 128-bit bitwise ops; view-agnostic. Stated on `Bytes` for generality.
// andnot: dst := (NOT a) AND b  (matches Intel order).
// ----------------------------------------------------------------------------

/// `dst := a AND b`.
#[inline]
pub fn and_si128(a: Bytes, b: Bytes) -> Bytes {
    lanewise_and_u8(a, b)
}

/// `dst := (NOT a) AND b`.
#[inline]
pub fn andnot_si128(a: Bytes, b: Bytes) -> Bytes {
    lanewise_andnot_u8(a, b)
}

/// `dst := a OR b`.
#[inline]
pub fn or_si128(a: Bytes, b: Bytes) -> Bytes {
    lanewise_or_u8(a, b)
}

/// `dst := a XOR b`.
#[inline]
pub fn xor_si128(a: Bytes, b: Bytes) -> Bytes {
    lanewise_xor_u8(a, b)
}

// ----------------------------------------------------------------------------
// _mm_slli_epi32 / _mm_slli_epi64 / _mm_srli_epi32  (SSE2)
// ----------------------------------------------------------------------------
// Per-lane logical shift by `count`. If `count >= lane_bits`, dst lane := 0.
// (Matches the Intel SDM "Operation:" pseudocode for the *immediate*-count
// forms; the variable-count `*_si128` shifts have the same overflow rule.)
// ----------------------------------------------------------------------------

/// Lane-wise logical shift left of 32-bit lanes by `count` bits.
#[inline]
pub fn slli_epi32(a: Dwords, count: i32) -> Dwords {
    let mut out = [0u32; 4];
    if 0 <= count && count < 32 {
        let c = count as u32;
        for i in 0..4 { out[i] = a[i] << c; }
    }
    out
}

/// Lane-wise logical shift left of 64-bit lanes by `count` bits.
#[inline]
pub fn slli_epi64(a: Qwords, count: i32) -> Qwords {
    let mut out = [0u64; 2];
    if 0 <= count && count < 64 {
        let c = count as u32;
        for i in 0..2 { out[i] = a[i] << c; }
    }
    out
}

/// Lane-wise logical shift right of 32-bit lanes by `count` bits.
#[inline]
pub fn srli_epi32(a: Dwords, count: i32) -> Dwords {
    let mut out = [0u32; 4];
    if 0 <= count && count < 32 {
        let c = count as u32;
        for i in 0..4 { out[i] = a[i] >> c; }
    }
    out
}

// ----------------------------------------------------------------------------
// _mm_srli_si128  (SSE2, PSRLDQ)
// ----------------------------------------------------------------------------
// 128-bit byte-granular right shift. `count` is an unsigned byte count;
// if `count >= 16`, dst := 0. Equivalent to alignr_epi8 with `a := 0`.
// ----------------------------------------------------------------------------

/// Shift the whole 128-bit value right by `count` BYTES, zero-filling.
#[inline]
pub fn srli_si128(a: Bytes, count: i32) -> Bytes {
    let mut out = [0u8; 16];
    if 0 <= count && count < 16 {
        let c = count as usize;
        for i in 0..(16 - c) { out[i] = a[i + c]; }
    }
    out
}

// ----------------------------------------------------------------------------
// _mm_store_si128  (SSE2)
// ----------------------------------------------------------------------------
// Aligned-store companion to `_mm_storeu_si128` already covered above.
// Operation is identical bytes-out; alignment is a runtime contract for the
// hardware form and irrelevant to the lane-typed shim.
// ----------------------------------------------------------------------------

/// Store 16 contiguous bytes into `bytes` starting at byte offset `at`.
/// Panics if `at + 16 > bytes.len()`.
#[inline]
pub fn store_si128(bytes: &mut [u8], at: usize, v: Bytes) {
    bytes[at..at + 16].copy_from_slice(&v);
}

// ----------------------------------------------------------------------------
// _mm_cvtsi128_si32 / _mm_cvtsi32_si128  (SSE2)
// ----------------------------------------------------------------------------
// cvtsi128_si32: return the LOW 32 bits of the XMM as a signed i32.
// cvtsi32_si128: pack an i32 into the LOW 32 bits of an XMM; high 96 := 0.
// ----------------------------------------------------------------------------

/// Extract the low 32 bits of `a` as a signed `i32`.
#[inline]
pub fn cvtsi128_si32(a: Dwords) -> i32 {
    a[0] as i32
}

/// Build an XMM holding `a` in the low 32 bits; upper 96 bits := 0.
#[inline]
pub fn cvtsi32_si128(a: i32) -> Dwords {
    [a as u32, 0, 0, 0]
}

// ----------------------------------------------------------------------------
// _mm_loadu_si64 / _mm_storeu_si64  (SSE2, partial 64-bit memory ops)
// ----------------------------------------------------------------------------
// loadu_si64:  read 8 bytes from `bytes[at..at+8]`; high 64 bits := 0.
// storeu_si64: write the LOW 8 bytes of `v` to `bytes[at..at+8]`.
// ----------------------------------------------------------------------------

/// Load 8 bytes from `bytes[at..at+8]` into the LOW qword of an XMM;
/// upper qword := 0. Panics if `at + 8 > bytes.len()`.
#[inline]
pub fn loadu_si64(bytes: &[u8], at: usize) -> Qwords {
    [
        u64::from_le_bytes([
            bytes[at    ], bytes[at + 1], bytes[at + 2], bytes[at + 3],
            bytes[at + 4], bytes[at + 5], bytes[at + 6], bytes[at + 7],
        ]),
        0,
    ]
}

/// Store the LOW qword of `v` into `bytes[at..at+8]`.
/// Panics if `at + 8 > bytes.len()`.
#[inline]
pub fn storeu_si64(bytes: &mut [u8], at: usize, v: Qwords) {
    bytes[at..at + 8].copy_from_slice(&v[0].to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arb()  -> Dwords { [0xDEAD_BEEFu32, 0xCAFE_F00D, 0x1234_5678, 0x9ABC_DEF0] }
    fn arb2() -> Dwords { [0x1111_2222u32, 0x3333_4444, 0x5555_6666, 0x7777_8888] }

    #[test]
    fn add_epi32_wraps() {
        let a: Dwords = [u32::MAX, 0, 1, 2];
        let b: Dwords = [1, 0, u32::MAX, 3];
        assert_eq!(add_epi32(a, b), [0, 0, 0, 5]);
    }

    #[test]
    fn unpack_epi64_matches_dword_layout() {
        let a = arb();
        let b = arb2();
        assert_eq!(unpacklo_epi64(a, b), [a[0], a[1], b[0], b[1]]);
        assert_eq!(unpackhi_epi64(a, b), [a[2], a[3], b[2], b[3]]);
    }

    #[test]
    fn loadu_storeu_round_trip() {
        let mut buf = [0u32; 8];
        let v: Dwords = [10, 20, 30, 40];
        storeu_si128_u32(&mut buf, 2, v);
        assert_eq!(loadu_si128_u32(&buf, 2), v);
        assert_eq!(buf, [0, 0, 10, 20, 30, 40, 0, 0]);
    }

    #[test]
    fn loadu_si128_u8_is_little_endian() {
        let bytes: [u8; 16] = [
            0x78, 0x56, 0x34, 0x12,
            0xEF, 0xCD, 0xAB, 0x90,
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
        ];
        let d = loadu_si128_u8(&bytes, 0);
        assert_eq!(d, [0x12345678, 0x90ABCDEF, 0x04030201, 0x08070605]);
    }

    #[test]
    fn setzero_set1_set_constructors() {
        assert_eq!(setzero_si128(), [0u8; 16]);
        assert_eq!(set1_epi16(-1), [0xFFFFu16; 8]);
        assert_eq!(set1_epi32(0x1234_5678), [0x1234_5678u32; 4]);
        assert_eq!(set_epi32(3, 2, 1, 0), [0, 1, 2, 3]);
        assert_eq!(set_epi64x(0x77, 0x33), [0x33u64, 0x77u64]);
    }

    #[test]
    fn arith_epi16_wraps_correctly() {
        let a: Words = [1, 2, 3, 4, 5, 6, 7, 8];
        let b: Words = [u16::MAX, 0, 1, 1, 1, 1, 1, 1];
        // add: lane 0 wraps to 0; lane 1 is 2; rest: 4,5,6,7,8,9.
        assert_eq!(add_epi16(a, b), [0, 2, 4, 5, 6, 7, 8, 9]);
        // sub: lane 0 = 1 - 0xFFFF = 2 (wrapping); lane 1 = 2 - 0 = 2.
        assert_eq!(sub_epi16(a, b)[0], 2);
    }

    #[test]
    fn mulhi_mullo_round_trip() {
        let a: Words = [0xFFFF, 0x1000, 0x0100, 1, 2, 3, 4, 5];
        let b: Words = [0xFFFF, 0x0010, 0x0001, 1, 1, 1, 1, 1];
        // 0xFFFF * 0xFFFF = 0xFFFE_0001 → mullo=0x0001, mulhi=0xFFFE
        let lo = mullo_epi16(a, b);
        let hi = mulhi_epu16(a, b);
        assert_eq!(lo[0], 0x0001);
        assert_eq!(hi[0], 0xFFFE);
        // 0x1000 * 0x0010 = 0x0001_0000 → mullo=0, mulhi=1
        assert_eq!(lo[1], 0x0000);
        assert_eq!(hi[1], 0x0001);
        // small case: 5 * 1 = 5
        assert_eq!(lo[7], 5);
        assert_eq!(hi[7], 0);
    }

    #[test]
    fn cmp_epi16_returns_lane_masks() {
        let a: Words = [1, 2, 3, 4, 5, 6, 7, 8];
        let b: Words = [1, 0, 3, 0, 5, 0, 7, 0];
        let eq = cmpeq_epi16(a, b);
        assert_eq!(eq, [0xFFFF, 0, 0xFFFF, 0, 0xFFFF, 0, 0xFFFF, 0]);
        let gt = cmpgt_epi16(a, b);
        // a strictly > b iff b is the 0 lanes: lanes 1,3,5,7
        assert_eq!(gt, [0, 0xFFFF, 0, 0xFFFF, 0, 0xFFFF, 0, 0xFFFF]);
        // signed semantics: -1 (0xFFFF) is NOT greater than 0
        let neg: Words = [0xFFFF; 8];
        let zero: Words = [0; 8];
        assert_eq!(cmpgt_epi16(neg, zero), [0; 8]);
    }

    #[test]
    fn bitwise_si128_identities() {
        let a: Bytes = [0xAA; 16];
        let b: Bytes = [0xCC; 16];
        assert_eq!(and_si128(a, b),    [0x88; 16]);
        assert_eq!(or_si128(a, b),     [0xEE; 16]);
        assert_eq!(xor_si128(a, b),    [0x66; 16]);
        // andnot(a, b) = (NOT 0xAA) AND 0xCC = 0x55 AND 0xCC = 0x44
        assert_eq!(andnot_si128(a, b), [0x44; 16]);
    }

    #[test]
    fn shifts_zero_when_count_out_of_range() {
        let d: Dwords = [1, 2, 3, 4];
        assert_eq!(slli_epi32(d, 1),  [2, 4, 6, 8]);
        assert_eq!(slli_epi32(d, 32), [0, 0, 0, 0]);
        assert_eq!(slli_epi32(d, -1), [0, 0, 0, 0]);
        assert_eq!(srli_epi32([8, 0x1000, 0, 0xFFFF_FFFF], 4), [0, 0x100, 0, 0x0FFF_FFFF]);

        let q: Qwords = [1u64, 1u64 << 63];
        assert_eq!(slli_epi64(q, 1),  [2, 0]);          // lane 1 wraps to 0
        assert_eq!(slli_epi64(q, 64), [0, 0]);

        let b: Bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        assert_eq!(srli_si128(b, 3)[0..13], [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        assert_eq!(srli_si128(b, 3)[13..], [0, 0, 0]);
        assert_eq!(srli_si128(b, 16), [0u8; 16]);
    }

    #[test]
    fn store_si128_and_cvts_round_trip() {
        let mut buf = [0u8; 24];
        let v: Bytes = [
            10, 20, 30, 40, 50, 60, 70, 80,
            90, 100, 110, 120, 130, 140, 150, 160,
        ];
        store_si128(&mut buf, 4, v);
        assert_eq!(&buf[4..20], &v);
        // cvtsi32_si128 / cvtsi128_si32: low 32 bits round-trip; upper 96 := 0.
        let d = cvtsi32_si128(-1);
        assert_eq!(d, [0xFFFF_FFFFu32, 0, 0, 0]);
        assert_eq!(cvtsi128_si32(d), -1);
    }

    #[test]
    fn loadu_storeu_si64_partial() {
        let bytes: [u8; 12] = [0,1,2,3,4,5,6,7,8,9,10,11];
        let q = loadu_si64(&bytes, 1);
        assert_eq!(q[1], 0); // high qword zero-fill
        assert_eq!(q[0], u64::from_le_bytes([1,2,3,4,5,6,7,8]));
        let mut out = [0u8; 12];
        storeu_si64(&mut out, 2, [0x0807_0605_0403_0201u64, 0xDEAD_BEEFu64]);
        assert_eq!(&out[2..10], &[1u8, 2, 3, 4, 5, 6, 7, 8]); // only low qword stored
        assert_eq!(out[10..], [0u8, 0]);
    }
}
