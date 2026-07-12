//! Lane-type views and packing helpers shared across x86_64 intrinsic shims.
//!
//! The 128-bit XMM register is viewed two ways: as four 32-bit dwords (lane
//! 0 = LOW dword, matching Intel `dst[31:0]`) and as sixteen bytes (lane 0
//! = LOW byte). The two views agree under little-endian dword packing
//! (x86-64 is itself little-endian), so for any `d : Dwords` and
//! `b : Bytes`:
//!
//!     d == bytes_to_dwords(b)   iff   b == dwords_to_bytes(d)
//!
//! These types and helpers are `pub use`-re-exported by `sse2`, `ssse3`,
//! and `sha` so every per-extension file presents a flat surface to its
//! callers and to the differential test harness.
//!
//! Status: 6 transcribed lane-view helpers, 0 axioms (all bodies are pure
//! Rust; Phase-3 step theorems equate each to its little-endian byte/lane
//! round-trip).
//!
//! ## Naming
//!
//! Lane-array types use the `core::simd` lowercase convention
//! (`u8x16`, `u16x8`, `u32x4`, `u64x2`, `u8x32`, `u16x16`, `u32x8`,
//! `u64x4`) so this module can later be lifted into a standalone
//! intrinsics-shim crate without renaming.  The pre-existing PascalCase
//! aliases (`Bytes`, `Words`, `Dwords`, `Qwords`, …) are kept as
//! transparent type aliases for backward compatibility — new code SHOULD
//! prefer the lowercase names.

#![allow(dead_code)]
#![allow(non_camel_case_types)]

// LE-only assumption — see lean/Intrinsics/SYMMETRY-AUDIT.md §4.D.
// Every `vreinterpretq_*` helper in this module routes through
// `to_le_bytes`/`from_le_bytes`, which is bit-identical to the
// architectural vreinterpret only on little-endian targets.  Fail the
// build loudly rather than silently producing a model-vs-silicon
// disagreement under a future big-endian retarget.
#[cfg(target_endian = "big")]
compile_error!(
    "crate::verify::intrinsics is little-endian-only; see \
     lean/Intrinsics/SYMMETRY-AUDIT.md §4.D for the policy."
);

// ----------------------------------------------------------------------------
// Lane-array types (`core::simd`-style names).
// ----------------------------------------------------------------------------

/// 128-bit XMM viewed as sixteen bytes; lane 0 is the low byte.
pub type u8x16 = [u8; 16];

/// 128-bit XMM viewed as eight 16-bit words; lane 0 is the low word.
pub type u16x8 = [u16; 8];

/// 128-bit XMM viewed as four 32-bit dwords; lane 0 is the low dword.
pub type u32x4 = [u32; 4];

/// 128-bit XMM viewed as two 64-bit qwords; lane 0 is the low qword.
pub type u64x2 = [u64; 2];

/// 256-bit YMM viewed as thirty-two bytes; lane 0 is the low byte.
pub type u8x32 = [u8; 32];

/// 256-bit YMM viewed as sixteen 16-bit words; lane 0 is the low word.
pub type u16x16 = [u16; 16];

/// 256-bit YMM viewed as eight 32-bit dwords; lane 0 is the low dword.
pub type u32x8 = [u32; 8];

/// 256-bit YMM viewed as four 64-bit qwords; lane 0 is the low qword.
pub type u64x4 = [u64; 4];

// ----------------------------------------------------------------------------
// Back-compat PascalCase aliases (kept transparent — new code prefers
// the lowercase `uNxM` names above).
// ----------------------------------------------------------------------------

/// Back-compat alias for `u32x4`.
pub type Dwords = u32x4;

/// Back-compat alias for `u16x8`.
pub type Words = u16x8;

/// Back-compat alias for `u64x2`.
pub type Qwords = u64x2;

/// Back-compat alias for `u8x16`.
pub type Bytes = u8x16;

/// `bytes_to_dwords(b)[k] := u32::from_le_bytes(b[4k..4k+4])`.
#[inline]
pub fn bytes_to_dwords(b: Bytes) -> Dwords {
    [
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
        u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
    ]
}

/// Inverse of `bytes_to_dwords`.
#[inline]
pub fn dwords_to_bytes(d: Dwords) -> Bytes {
    let b0 = d[0].to_le_bytes();
    let b1 = d[1].to_le_bytes();
    let b2 = d[2].to_le_bytes();
    let b3 = d[3].to_le_bytes();
    [
        b0[0], b0[1], b0[2], b0[3],
        b1[0], b1[1], b1[2], b1[3],
        b2[0], b2[1], b2[2], b2[3],
        b3[0], b3[1], b3[2], b3[3],
    ]
}

/// `bytes_to_words(b)[k] := u16::from_le_bytes(b[2k..2k+2])`.
#[inline]
pub fn bytes_to_words(b: Bytes) -> Words {
    [
        u16::from_le_bytes([b[0],  b[1]]),
        u16::from_le_bytes([b[2],  b[3]]),
        u16::from_le_bytes([b[4],  b[5]]),
        u16::from_le_bytes([b[6],  b[7]]),
        u16::from_le_bytes([b[8],  b[9]]),
        u16::from_le_bytes([b[10], b[11]]),
        u16::from_le_bytes([b[12], b[13]]),
        u16::from_le_bytes([b[14], b[15]]),
    ]
}

/// Inverse of `bytes_to_words`.
#[inline]
pub fn words_to_bytes(w: Words) -> Bytes {
    let mut out = [0u8; 16];
    for i in 0..8 {
        let p = w[i].to_le_bytes();
        out[2 * i]     = p[0];
        out[2 * i + 1] = p[1];
    }
    out
}

/// `bytes_to_qwords(b)[k] := u64::from_le_bytes(b[8k..8k+8])`.
#[inline]
pub fn bytes_to_qwords(b: Bytes) -> Qwords {
    [
        u64::from_le_bytes([b[0], b[1], b[2],  b[3],  b[4],  b[5],  b[6],  b[7]]),
        u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
    ]
}

/// Inverse of `bytes_to_qwords`.
#[inline]
pub fn qwords_to_bytes(q: Qwords) -> Bytes {
    let lo = q[0].to_le_bytes();
    let hi = q[1].to_le_bytes();
    [
        lo[0], lo[1], lo[2], lo[3], lo[4], lo[5], lo[6], lo[7],
        hi[0], hi[1], hi[2], hi[3], hi[4], hi[5], hi[6], hi[7],
    ]
}

// ----------------------------------------------------------------------------
// `u128` ↔ `__m128i` reinterpret (`core::mem::transmute`).
// ----------------------------------------------------------------------------

/// Byte view of `core::mem::transmute::<u128, __m128i>(x)`.
///
/// `transmute` is a bit-preserving reinterpret; on little-endian x86-64 the
/// resulting register's `u8x16` view equals `x.to_le_bytes()` (lane 0 = low
/// byte = LSB of `x`).  This is the model for the Rust intrinsic helper
/// `aes::ghash::ghash_xmm::u128_to_m128i` (`= transmute(x)`), and the basis
/// of the Lean axiom `core.intrinsics.transmute (Dst := __m128i)`.
///
/// The `compile_error!` big-endian guard at the top of this module keeps the
/// model honest under any future architecture retarget.
#[inline]
pub fn u128_to_m128i_bytes(x: u128) -> u8x16 {
    x.to_le_bytes()
}

/// Inverse of [`u128_to_m128i_bytes`]: the `u128` whose `__m128i`
/// reinterpret has byte view `b` (`= u128::from_le_bytes(b)`).
#[inline]
pub fn m128i_bytes_to_u128(b: u8x16) -> u128 {
    u128::from_le_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_views() {
        let d: Dwords = [0xDEAD_BEEFu32, 0xCAFE_F00D, 0x1234_5678, 0x9ABC_DEF0];
        assert_eq!(bytes_to_dwords(dwords_to_bytes(d)), d);
        let b: Bytes = [3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12];
        assert_eq!(dwords_to_bytes(bytes_to_dwords(b)), b);
    }

    #[test]
    fn round_trip_words() {
        let w: Words = [0x0001, 0x0203, 0x0405, 0x0607, 0x0809, 0x0A0B, 0x0C0D, 0x0E0F];
        assert_eq!(bytes_to_words(words_to_bytes(w)), w);
    }

    #[test]
    fn round_trip_qwords() {
        let q: Qwords = [0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210];
        assert_eq!(bytes_to_qwords(qwords_to_bytes(q)), q);
    }

    #[test]
    fn dword_word_view_agreement() {
        // The same 16 bytes seen as Dwords and Words must agree under little-endian packing.
        let b: Bytes = [
            0x78, 0x56, 0x34, 0x12,  0xEF, 0xCD, 0xAB, 0x90,
            0x01, 0x02, 0x03, 0x04,  0x05, 0x06, 0x07, 0x08,
        ];
        let d = bytes_to_dwords(b);
        let w = bytes_to_words(b);
        // Each dword spans two consecutive words: d[k] = w[2k+1] << 16 | w[2k]
        for k in 0..4 {
            let lo = w[2 * k] as u32;
            let hi = w[2 * k + 1] as u32;
            assert_eq!(d[k], (hi << 16) | lo);
        }
    }
}
