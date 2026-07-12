//! `__m128i` byte-carrier SSE2 view — the verify-side model of the 128-bit
//! XMM register and the individual lane intrinsics ML-KEM's NTT calls on it.
//!
//! This is the verify half of the `swap_poc` redirect for `src/mlkem/ntt_xmm.rs`
//! (see `../swap_poc.rs` and `SymCRust/lean/Intrinsics/INTRINSICS.md` §0 P6). The consumer's
//! lane-op body is written ONCE over `__m128i` and the `_mm_*` intrinsic names;
//! two cfg-gated `use` blocks bind those names to either `core::arch`
//! (production) or this module (verify). All lane-op modelling lives here, so
//! `ntt_xmm.rs` stays a near-verbatim copy of the upstream production source.
//!
//! ## Carrier
//!
//! `M128 = Bytes = [u8; 16]` is the canonical concrete representation of
//! `__m128i` — its `u8x16` lane view. Every op presents a uniform
//! `M128 -> M128` (i.e. `__m128i -> __m128i`) face; the u16×8 lane view used
//! by the arithmetic ops is reinterpreted *internally* via
//! `bytes_to_words`/`words_to_bytes`, so the consumer never converts at a call
//! site and `Array U16 8` appears only inside these models.
//!
//! The nine lane ops delegate to the transcribed `sse2` shims; their Lean
//! `.spec` theorems live in `lean/Intrinsics/Properties/X86_64/Sse2.lean`. The
//! byte-view bitwise ops (`and/andnot`) are `Bytes`-native and pass straight
//! through. The raw-pointer load/store/cvt intrinsics are NOT modelled here:
//! they index a `PolyElement` through raw pointers (outside Aeneas's model of
//! Rust), so the methods that use them are `#[verify::opaque]` in `ntt_xmm.rs`
//! with cfg-split bodies — see that file.

#![allow(dead_code)]

use super::lanes::{bytes_to_words, words_to_bytes, Bytes};
use super::sse2;

/// Canonical carrier for `__m128i` in the verify model: its `u8x16` byte view.
pub type M128 = Bytes;

// ============================================================================
// Modelled lane ops (`M128 -> M128`, u16×8 view reinterpreted internally).
// ============================================================================

/// `_mm_set1_epi16` — broadcast `v` to all eight u16 lanes.
#[inline]
pub fn set1_epi16(v: i16) -> M128 {
    words_to_bytes(sse2::set1_epi16(v))
}

/// `_mm_add_epi16` — lane-wise wrapping u16 add.
#[inline]
pub fn add_epi16(a: M128, b: M128) -> M128 {
    words_to_bytes(sse2::add_epi16(bytes_to_words(a), bytes_to_words(b)))
}

/// `_mm_sub_epi16` — lane-wise wrapping u16 subtract.
#[inline]
pub fn sub_epi16(a: M128, b: M128) -> M128 {
    words_to_bytes(sse2::sub_epi16(bytes_to_words(a), bytes_to_words(b)))
}

/// `_mm_cmpgt_epi16` — lane-wise signed `>`; 0xFFFF on true, else 0x0000.
#[inline]
pub fn cmpgt_epi16(a: M128, b: M128) -> M128 {
    words_to_bytes(sse2::cmpgt_epi16(bytes_to_words(a), bytes_to_words(b)))
}

/// `_mm_cmpeq_epi16` — lane-wise equality; 0xFFFF on equal, else 0x0000.
#[inline]
pub fn cmpeq_epi16(a: M128, b: M128) -> M128 {
    words_to_bytes(sse2::cmpeq_epi16(bytes_to_words(a), bytes_to_words(b)))
}

/// `_mm_mullo_epi16` — lane-wise low 16 bits of the u16 product.
#[inline]
pub fn mullo_epi16(a: M128, b: M128) -> M128 {
    words_to_bytes(sse2::mullo_epi16(bytes_to_words(a), bytes_to_words(b)))
}

/// `_mm_mulhi_epu16` — lane-wise high 16 bits of the unsigned u16 product.
#[inline]
pub fn mulhi_epu16(a: M128, b: M128) -> M128 {
    words_to_bytes(sse2::mulhi_epu16(bytes_to_words(a), bytes_to_words(b)))
}

/// `_mm_and_si128` — 128-bit bitwise AND (byte-view native).
#[inline]
pub fn and_si128(a: M128, b: M128) -> M128 {
    sse2::and_si128(a, b)
}

/// `_mm_andnot_si128` — `(NOT a) AND b` (byte-view native).
#[inline]
pub fn andnot_si128(a: M128, b: M128) -> M128 {
    sse2::andnot_si128(a, b)
}
