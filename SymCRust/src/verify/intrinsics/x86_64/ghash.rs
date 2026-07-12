//! `__m128i` byte-carrier view for the GHASH (GCM) PCLMULQDQ driver —
//! the verify-side model of the 128-bit XMM register and the lane
//! intrinsics `src/aes/ghash/ghash_xmm.rs` calls on it.
//!
//! This is the verify half of the single-body cfg-swap redirect for the
//! GHASH SIMD path (see `../swap_poc.rs`, `../sha.rs`, and
//! `SymCRust/lean/Intrinsics/INTRINSICS.md` §0 P6). The GHASH driver body is written ONCE
//! over `__m128i` and a flat set of named ops; two cfg-gated `use` blocks
//! bind those names to either `core::arch` (production) or this module
//! (verify). All lane-op modelling lives here, so `ghash_xmm.rs` stays a
//! near-verbatim copy of the upstream production source.
//!
//! ## Carrier
//!
//! `M128 = Bytes = [u8; 16]` is the canonical concrete representation of
//! `__m128i` — its `u8x16` lane view. Every op presents a uniform
//! `M128 -> M128` face; the dword / qword lane views used by the shift,
//! shuffle and carry-less-multiply ops are reinterpreted *internally* via
//! `bytes_to_{dwords,qwords}` / `{dwords,qwords}_to_bytes`, so the consumer
//! never converts at a call site and `Array U32 4` / `Array U64 2` appear
//! only inside these models. GHASH freely mixes the byte view (xor, byte
//! reverse, byte-granular `srli_si128`), the dword view (`shuffle_epi32`,
//! `slli_epi32`, `srli_epi32`, `set_epi32`) and the qword view
//! (`clmulepi64`, `slli_epi64`) on the SAME register, exactly the multi-view
//! shape `swap_poc::poc_multiview` motivates.
//!
//! ## Trust ledger
//!
//! The lane ops below delegate to the transcribed `sse2` / `ssse3` shims
//! (theorem-eligible; their `.spec` theorems live in
//! `lean/Intrinsics/Properties/X86_64/{Sse2,Ssse3}.lean`). The four
//! `clmul_*` wrappers delegate to the single **axiomatised** PCLMULQDQ
//! opcode `pclmulqdq::clmulepi64_si128` (the irreducible GF(2) carry-less
//! multiply — NIST SP 800-38D §6.3, pinned in
//! `lean/Intrinsics/Axioms/X86_64/Pclmulqdq.lean`); only the imm8 operand
//! selection is baked into the wrapper name. The raw-pointer load/store and
//! the `u128 -> __m128i` transmute are NOT modelled here: they are
//! `#[verify::opaque]` cfg-split methods in `ghash_xmm.rs` with clean,
//! pointer-free signatures — see that file.

#![allow(dead_code)]

use super::lanes::{
    bytes_to_dwords, bytes_to_qwords, dwords_to_bytes, qwords_to_bytes, Bytes,
};
use super::{pclmulqdq, sse2, ssse3};

/// Canonical carrier for `__m128i` in the verify model: its `u8x16` byte view.
pub type M128 = Bytes;

/// The GHASH byte-reverse mask `_mm_set_epi8(0, 1, …, 15)`.
///
/// `sse2::set_epi8` takes its arguments high-byte first and returns the
/// `Bytes` low-byte first, so `set_epi8(0, 1, …, 15)` is the fully reversed
/// identity `[15, 14, …, 1, 0]`: `shuffle_epi8` with it reverses all 16 bytes
/// (the big-endian ↔ little-endian swap GHASH applies to H and to every data
/// block).
const BYTE_REVERSE_ORDER: Bytes = [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0];

// ============================================================================
// Byte-view ops (operate on `Bytes` directly; no reinterpretation).
// ============================================================================

/// `_mm_shuffle_epi8(a, _mm_set_epi8(0, 1, …, 15))` — reverse all 16 bytes.
#[inline]
pub fn byte_reverse(a: M128) -> M128 {
    ssse3::shuffle_epi8(a, BYTE_REVERSE_ORDER)
}

/// `_mm_xor_si128` — 128-bit bitwise XOR (byte-view native).
#[inline]
pub fn xor(a: M128, b: M128) -> M128 {
    sse2::xor_si128(a, b)
}

/// `_mm_srli_si128(a, 8)` — shift the whole 128-bit value right by 8 bytes,
/// zero-filling (pull the high qword down into the low qword).
#[inline]
pub fn srli_si128_8(a: M128) -> M128 {
    sse2::srli_si128(a, 8)
}

// ============================================================================
// Dword-view ops (reinterpret to `Dwords` internally).
// ============================================================================

/// `_mm_shuffle_epi32(a, _MM_SHUFFLE(1, 0, 3, 2))` = imm8 `0x4E` — swap the
/// two 64-bit halves (dword lanes `[0,1,2,3] -> [2,3,0,1]`).
#[inline]
pub fn shuffle_epi32_0x4e(a: M128) -> M128 {
    dwords_to_bytes(sse2::shuffle_epi32::<0x4E>(bytes_to_dwords(a)))
}

/// `_mm_shuffle_epi32(a, _MM_SHUFFLE(2, 1, 0, 3))` = imm8 `0x93` — rotate the
/// dword lanes (`[0,1,2,3] -> [3,0,1,2]`).
#[inline]
pub fn shuffle_epi32_0x93(a: M128) -> M128 {
    dwords_to_bytes(sse2::shuffle_epi32::<0x93>(bytes_to_dwords(a)))
}

/// `_mm_slli_epi32(a, 1)` — lane-wise logical shift left of the four 32-bit
/// lanes by one bit.
#[inline]
pub fn slli_epi32_1(a: M128) -> M128 {
    dwords_to_bytes(sse2::slli_epi32(bytes_to_dwords(a), 1))
}

/// `_mm_srli_epi32(a, 31)` — lane-wise logical shift right of the four 32-bit
/// lanes by 31 bits (extract each lane's top bit into bit 0).
#[inline]
pub fn srli_epi32_31(a: M128) -> M128 {
    dwords_to_bytes(sse2::srli_epi32(bytes_to_dwords(a), 31))
}

/// `_mm_set_epi32(e3, e2, e1, e0)` — build a register from four dword lanes
/// (high lane first), used for the GF(2^128) reduction constant.
#[inline]
pub fn set_epi32(e3: i32, e2: i32, e1: i32, e0: i32) -> M128 {
    dwords_to_bytes(sse2::set_epi32(e3, e2, e1, e0))
}

// ============================================================================
// Qword-view ops (reinterpret to `Qwords` internally).
// ============================================================================

/// `_mm_slli_epi64(a, 1)` — lane-wise logical shift left of the two 64-bit
/// lanes by one bit.
#[inline]
pub fn slli_epi64_1(a: M128) -> M128 {
    qwords_to_bytes(sse2::slli_epi64(bytes_to_qwords(a), 1))
}

// ============================================================================
// PCLMULQDQ carry-less multiply (axiomatised; imm8 baked into the name).
// ----------------------------------------------------------------------------
// Each wrapper selects the 64-bit operand halves via the imm8 immediate and
// delegates to the single axiomatised `clmulepi64_si128` opcode. The carrier
// reinterpretation to/from `Qwords` is the only modelled (theorem-eligible)
// part; the carry-less multiply itself is the irreducible FIPS axiom.
// ============================================================================

/// `_mm_clmulepi64_si128(a, b, 0x00)` — clmul of `a`'s low qword by `b`'s low.
#[inline]
pub fn clmul_00(a: M128, b: M128) -> M128 {
    qwords_to_bytes(pclmulqdq::clmulepi64_si128(bytes_to_qwords(a), bytes_to_qwords(b), 0x00))
}

/// `_mm_clmulepi64_si128(a, b, 0x11)` — clmul of `a`'s high qword by `b`'s high.
#[inline]
pub fn clmul_11(a: M128, b: M128) -> M128 {
    qwords_to_bytes(pclmulqdq::clmulepi64_si128(bytes_to_qwords(a), bytes_to_qwords(b), 0x11))
}

/// `_mm_clmulepi64_si128(a, b, 0x10)` — clmul of `a`'s low qword by `b`'s high.
#[inline]
pub fn clmul_10(a: M128, b: M128) -> M128 {
    qwords_to_bytes(pclmulqdq::clmulepi64_si128(bytes_to_qwords(a), bytes_to_qwords(b), 0x10))
}

/// `_mm_clmulepi64_si128(a, b, 0x01)` — clmul of `a`'s high qword by `b`'s low.
#[inline]
pub fn clmul_01(a: M128, b: M128) -> M128 {
    qwords_to_bytes(pclmulqdq::clmulepi64_si128(bytes_to_qwords(a), bytes_to_qwords(b), 0x01))
}
