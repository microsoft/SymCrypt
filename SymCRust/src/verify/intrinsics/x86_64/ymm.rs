//! `__m256i` byte-carrier AVX2 view — the verify-side model of the 256-bit
//! YMM register and the individual lane intrinsics the SHA-3 4-way Keccak
//! permutation (`sha3/keccak4x_hybrid.rs`) calls on it inside `rol4!`.
//!
//! This is the AVX2 analogue of `xmm.rs` and the verify half of the
//! `swap_poc` redirect (see `../swap_poc.rs` and `SymCRust/lean/Intrinsics/INTRINSICS.md`
//! §0 P6). The consumer's lane-op body is written ONCE over a neutral
//! `__m256i` and the `_mm256_*` intrinsic names; two cfg-gated `use` blocks
//! bind those names to either `core::arch` (production) or this module
//! (verify). All lane-op modelling lives here, so `keccak4x_hybrid.rs` stays
//! a near-verbatim copy of the upstream production source.
//!
//! ## Carrier
//!
//! `M256 = [u8; 32]` is the canonical concrete representation of `__m256i` —
//! its `u8x32` lane view. Every op presents a uniform `M256 -> M256` (i.e.
//! `__m256i -> __m256i`) face; the u64×4 lane view used by the shift ops is
//! reinterpreted *internally* via `bytes256_to_qwords256`/
//! `qwords256_to_bytes256`, so the consumer never converts at a call site and
//! `[u64; 4]` appears only inside these models. The 256-bit bitwise `or` is
//! byte-view native and passes straight through.
//!
//! The shift ops delegate to the transcribed `avx2` shims; their Lean
//! `.spec` theorems live in `lean/Intrinsics/Properties/X86_64/Avx2.lean`.
//! The raw-pointer `load_lane`/`store_lane` intrinsics are NOT modelled here:
//! they reinterpret a `&Lane4` through raw pointers (outside Aeneas's model
//! of Rust), so the functions that use them are `#[verify::opaque]` in
//! `keccak4x_hybrid.rs` with cfg-split bodies — see that file.
//!
//! This `m256` backend is shared by the ML-KEM AVX2 NTT (`ntt_avx2.rs`) via
//! the `u16×16` lane view: the SHA-3 rotate set (`slli_epi64`, `srli_epi64`,
//! `or_si256`) plus the twelve ML-KEM u16×16 lane ops (`set1_epi16`,
//! `setzero_si256`, `add_epi16`, `sub_epi16`, `mullo_epi16`, `mulhi_epu16`,
//! `cmpeq_epi16`, `cmpgt_epi16`, `and_si256`, `andnot_si256`), all delegating
//! to the transcribed `avx2` shims with the u16×16 reinterpret applied
//! internally (`avx2::bytes256_to_words16x16` / `words16x16_to_bytes256`).

#![allow(dead_code)]

use super::avx2;

/// Canonical carrier for `__m256i` in the verify model: its `u8x32` byte view.
pub type M256 = avx2::Bytes256;

// ============================================================================
// Modelled lane ops (`M256 -> M256`, lane view reinterpreted internally).
// ============================================================================

/// `_mm256_slli_epi64::<N>` — lane-wise logical shift left of the four
/// 64-bit lanes by the compile-time count `N` (`N ∉ [0, 64)` zeros the lane).
#[inline]
pub fn slli_epi64<const N: i32>(a: M256) -> M256 {
    avx2::qwords256_to_bytes256(avx2::slli_epi64(avx2::bytes256_to_qwords256(a), N))
}

/// `_mm256_srli_epi64::<N>` — lane-wise logical shift right of the four
/// 64-bit lanes by the compile-time count `N` (`N ∉ [0, 64)` zeros the lane).
#[inline]
pub fn srli_epi64<const N: i32>(a: M256) -> M256 {
    avx2::qwords256_to_bytes256(avx2::srli_epi64(avx2::bytes256_to_qwords256(a), N))
}

/// `_mm256_or_si256` — 256-bit bitwise OR (byte-view native).
#[inline]
pub fn or_si256(a: M256, b: M256) -> M256 {
    avx2::or_si256(a, b)
}

// ============================================================================
// ML-KEM u16×16 lane ops (mirror of `xmm.rs` at 256-bit width). The u16×16
// view used by the arithmetic ops is reinterpreted internally via
// `bytes256_to_words16x16`/`words16x16_to_bytes256`, so the consumer never
// converts at a call site and `[u16; 16]` appears only inside these models.
// ============================================================================

/// `_mm256_setzero_si256` — all 256 bits zero (byte-view native).
#[inline]
pub fn setzero_si256() -> M256 {
    avx2::setzero_si256()
}

/// `_mm256_set1_epi16` — broadcast `v` to all sixteen u16 lanes.
#[inline]
pub fn set1_epi16(v: i16) -> M256 {
    avx2::words16x16_to_bytes256(avx2::set1_epi16(v))
}

/// `_mm256_add_epi16` — lane-wise wrapping u16 add.
#[inline]
pub fn add_epi16(a: M256, b: M256) -> M256 {
    avx2::words16x16_to_bytes256(avx2::add_epi16(
        avx2::bytes256_to_words16x16(a),
        avx2::bytes256_to_words16x16(b),
    ))
}

/// `_mm256_sub_epi16` — lane-wise wrapping u16 subtract.
#[inline]
pub fn sub_epi16(a: M256, b: M256) -> M256 {
    avx2::words16x16_to_bytes256(avx2::sub_epi16(
        avx2::bytes256_to_words16x16(a),
        avx2::bytes256_to_words16x16(b),
    ))
}

/// `_mm256_mullo_epi16` — lane-wise low 16 bits of the u16 product.
#[inline]
pub fn mullo_epi16(a: M256, b: M256) -> M256 {
    avx2::words16x16_to_bytes256(avx2::mullo_epi16(
        avx2::bytes256_to_words16x16(a),
        avx2::bytes256_to_words16x16(b),
    ))
}

/// `_mm256_mulhi_epu16` — lane-wise high 16 bits of the unsigned u16 product.
#[inline]
pub fn mulhi_epu16(a: M256, b: M256) -> M256 {
    avx2::words16x16_to_bytes256(avx2::mulhi_epu16(
        avx2::bytes256_to_words16x16(a),
        avx2::bytes256_to_words16x16(b),
    ))
}

/// `_mm256_cmpeq_epi16` — lane-wise equality; 0xFFFF on equal, else 0x0000.
#[inline]
pub fn cmpeq_epi16(a: M256, b: M256) -> M256 {
    avx2::words16x16_to_bytes256(avx2::cmpeq_epi16(
        avx2::bytes256_to_words16x16(a),
        avx2::bytes256_to_words16x16(b),
    ))
}

/// `_mm256_cmpgt_epi16` — lane-wise signed `>`; 0xFFFF on true, else 0x0000.
#[inline]
pub fn cmpgt_epi16(a: M256, b: M256) -> M256 {
    avx2::words16x16_to_bytes256(avx2::cmpgt_epi16(
        avx2::bytes256_to_words16x16(a),
        avx2::bytes256_to_words16x16(b),
    ))
}

/// `_mm256_and_si256` — 256-bit bitwise AND (byte-view native).
#[inline]
pub fn and_si256(a: M256, b: M256) -> M256 {
    avx2::and_si256(a, b)
}

/// `_mm256_andnot_si256` — `(NOT a) AND b` (byte-view native).
#[inline]
pub fn andnot_si256(a: M256, b: M256) -> M256 {
    avx2::andnot_si256(a, b)
}
