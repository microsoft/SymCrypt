//! SHA-2-specialised SSE wrappers and axiomatised SHA-NI
//! (`target_feature = "sha"`) opcodes.
//!
//! This file holds two kinds of declarations:
//!
//! 1. **Transcribed specialised wrappers (§A, 3 declarations).** Each one
//!    inlines the exact immediate / mask used by the SHA-256 SHA-NI driver
//!    (`append_blocks_256_shani` in `src/sha2/sha2_impl.rs`). Provably
//!    equal to the general-form `super::sse2`/`super::ssse3` shims; the
//!    cross-equation is exercised by the unit-test submodule below.
//!
//! 2. **Axiomatised SHA-NI opcodes (§B, 3 `#[verify::opaque]` stubs).**
//!    `_mm_sha256rnds2_epu32`, `_mm_sha256msg1_epu32`,
//!    `_mm_sha256msg2_epu32`. Aeneas extracts the signatures to
//!    `Code/FunsExternal.lean`; behaviour is pinned in
//!    `lean/Intrinsics/X86_64/Sha.lean` by 3 axioms stated as direct
//!    equations against FIPS-180-4 §6.2 (round) / §6.2.2 step 1
//!    (schedule). This is the irreducible case from INTRINSICS.md §0:
//!    the vendor pseudocode would only re-state the FIPS equation, so
//!    we equate against the FIPS equation directly. Fidelity to silicon
//!    is enforced by `tests/x86_64_sha_hw.rs`.
//!
//! Total trust footprint: **3 algebraic axioms** (plus 1 opaque-type
//! axiom for `__m128i` if not eliminated by the lane-typed shim).
//!
//! Re-exports `sse2` and `ssse3` shims (and `lanes` helpers) so callers
//! see a single flat `sha as ix` namespace, matching the pre-migration
//! `super::intrinsics as ix` shape used by `sha2_impl.rs`.
//!
//! Status: 3 transcribed specialised declarations (§A; theorem-eligible, each
//!  provably equal to its general-form `super::sse2`/`super::ssse3`
//! counterpart) + 3 axiomatised SHA-NI opcodes (§B; irreducible against
//! FIPS-180-4 §6.2 / §6.2.2).

#![allow(dead_code)]

pub use super::lanes::{Bytes, Dwords, bytes_to_dwords, dwords_to_bytes};
pub use super::sse2::{
    add_epi32, loadu_si128_u32, loadu_si128_u8, set_epi8, shuffle_epi32,
    storeu_si128_u32, unpackhi_epi64, unpacklo_epi64,
};
pub use super::ssse3::{alignr_epi8, shuffle_epi8};

// ============================================================================
// § A. SHA-2-specialised wrappers (3 declarations over §sse2/§ssse3).
// ----------------------------------------------------------------------------
// Specialisations matching the exact immediates / masks used by the SHA-NI
// driver. Each wrapper is provably equal to its general-form counterpart
// in `super::sse2` / `super::ssse3`; the `tests` submodule cross-checks
// these equalities, and `tests/x86_64_sha_hw.rs` additionally checks each
// wrapper against silicon.
// ============================================================================

/// `_mm_alignr_epi8(a, b, 4)` reduced to dword granularity — equivalent
/// to `bytes_to_dwords(alignr_epi8(dwords_to_bytes(a), dwords_to_bytes(b), 4))`.
/// Concatenation `(a:b)` shifted right by exactly one dword yields the
/// "middle three dwords of `b` followed by the low dword of `a`".
#[inline]
pub fn alignr_epi8_4(a: Dwords, b: Dwords) -> Dwords {
    [b[1], b[2], b[3], a[0]]
}

/// The byte-reverse mask used by `shani_load_block`:
/// `_mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3)`.
///
/// In `Bytes` view (low byte first) this is
/// `[3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12]` — i.e. each
/// 4-byte group is reversed in place, swapping LE ↔ BE for each dword.
pub const BYTE_REVERSE_MASK: Bytes = [
    3, 2, 1, 0,
    7, 6, 5, 4,
    11, 10, 9, 8,
    15, 14, 13, 12,
];

/// `shuffle_epi8(a, BYTE_REVERSE_MASK)` reduced — swap the byte order of
/// each dword lane (LE ↔ BE for that lane).
#[inline]
pub fn byte_reverse_lanes(a: Dwords) -> Dwords {
    // Per-lane byte reversal. Equivalent to `w.swap_bytes()` on `u32`,
    // but Aeneas.Std does not yet bind `core::num::U32::swap_bytes`, so
    // we open-code the four-byte rotation with shifts and masks. The
    // differential test in `tests/x86_64_sha_hw.rs` cross-checks this
    // against `core::arch::x86_64::_mm_shuffle_epi8` with `BYTE_REVERSE_MASK`.
    #[inline]
    fn swap_bytes_u32(w: u32) -> u32 {
        ((w & 0x000000ff) << 24)
            | ((w & 0x0000ff00) << 8)
            | ((w & 0x00ff0000) >> 8)
            | ((w & 0xff000000) >> 24)
    }
    [
        swap_bytes_u32(a[0]),
        swap_bytes_u32(a[1]),
        swap_bytes_u32(a[2]),
        swap_bytes_u32(a[3]),
    ]
}

// ============================================================================
// § B. Axiomatised SHA-NI opcodes (3 stubs, 3 axioms vs FIPS-180-4 §6.2).
// ----------------------------------------------------------------------------
// `#[verify::opaque]` declarations over `[u32; 4]` lanes. Aeneas extracts
// the declarations to `Intrinsics/Code/FunsExternal.lean`; behaviour is
// pinned by the 3 axioms in `lean/Intrinsics/X86_64/Sha.lean`, each stated
// as a direct equation against FIPS-180-4 §6.2 (round) / §6.2.2 step 1
// (schedule) — NOT against the Intel SDM (which would just transcribe
// pseudocode rather than the cryptographic primitive).
//
// Cross-checked against real silicon in `tests/x86_64_sha_hw.rs`
// (any drift between Lean axiom and Intel silicon fails `cargo test`).
//
// Signatures (Intel reference):
//
//   __m128i _mm_sha256rnds2_epu32(__m128i cdgh, __m128i abef, __m128i mk)
//   __m128i _mm_sha256msg1_epu32 (__m128i m_dst, __m128i m_src)
//   __m128i _mm_sha256msg2_epu32 (__m128i m_dst, __m128i m_src)
// ============================================================================
// The `#[verify::opaque]` attribute is registered (in `src/lib.rs`) only
// when `feature = "verify"` is enabled. The three stubs below are also
// guarded by the same cfg so they are *absent* from the differential test
// crate (`tests/x86_64_sha_hw.rs`) which `#[path]`-includes this file
// without the feature.

/// 2 SHA-256 compression rounds in the `(abef, cdgh)` register pair
/// convention (Intel® Intrinsics Guide: `_mm_sha256rnds2_epu32`).
///
/// `cdgh` and `abef` are the two halves of the 8-word working state;
/// after the call, the **return value is the new `cdgh` after rounds
/// `t` and `t+1`** while `abef` is unchanged on the call but the
/// driver subsequently updates it with the new `cdgh` (see the
/// SHA-NI fast-path body, where two `_mm_sha256rnds2_epu32` calls in
/// sequence rotate `(abef, cdgh)`).
///
/// `mk` carries `(W[t+1] + K256[t+1])` in the high dword pair and
/// `(W[t] + K256[t])` in the low dword pair, both repeated:
///
///   `mk = [W[t]+K[t], W[t]+K[t], W[t+1]+K[t+1], W[t+1]+K[t+1]]`
///   (Intel SDM: only the **low 64 bits** of `mk` are read; the high
///   64 bits are ignored. The driver still passes the full 4-dword
///   value because the K-schedule produces 4 dwords at a time and
///   the unused high half is harmless.)
///
/// The Lean axiom for this stub equates the result to two iterations
/// of `Spec.SHA2.iterRounds256` starting from the FIPS-formed
/// `(a..h)` state derived from `(abef, cdgh)`. See the axiom
/// docstring for the precise lane↔FIPS-state correspondence.
#[cfg(feature = "verify")]
#[verify::opaque]
pub(crate) fn sha256rnds2_epu32(cdgh: Dwords, abef: Dwords, mk: Dwords) -> Dwords {
    let _ = (cdgh, abef, mk);
    unimplemented!()
}

/// Partial message-schedule update — σ₀ stage
/// (Intel® Intrinsics Guide: `_mm_sha256msg1_epu32`).
///
/// Given the previous 4 schedule words in `m_dst` (lanes
/// `[W[t-15], W[t-14], W[t-13], W[t-12]]` for the current schedule
/// position `t`) and a single dword from the next chunk in the
/// LOW lane of `m_src` (`W[t-11]` — the others are unused), produces:
///
///   `result[i] = m_dst[i] + sigma0_256(m_src_extracted[i])`
///
/// where `m_src_extracted` aligns the σ₀-source with `m_dst` per the
/// FIPS-180-4 §6.2.2 recurrence
/// `W[t] = σ₁(W[t-2]) + W[t-7] + σ₀(W[t-15]) + W[t-16]`. The
/// `_mm_sha256msg1_epu32` call provides the σ₀ contribution; the
/// remaining `σ₁(W[t-2]) + W[t-7]` contributions are added by the
/// driver around the `_mm_sha256msg2_epu32` call.
///
/// The Lean axiom for this stub asserts the lane-wise equation
/// `result[i] = m_dst[i] + Spec.SHA2.sigma0_256 (m_src_extracted[i])`
/// at each lane index, where `sigma0_256` is the FIPS-180-4 §4.1.2
/// pure function.
#[cfg(feature = "verify")]
#[verify::opaque]
pub(crate) fn sha256msg1_epu32(m_dst: Dwords, m_src: Dwords) -> Dwords {
    let _ = (m_dst, m_src);
    unimplemented!()
}

/// Final message-schedule update — σ₁ stage with carry
/// (Intel® Intrinsics Guide: `_mm_sha256msg2_epu32`).
///
/// Given the partial schedule in `m_dst` (lanes
/// `[W[t-16] + σ₀(W[t-15]) + W[t-7], …]` already accumulated by
/// `_mm_sha256msg1_epu32` and the surrounding `_mm_alignr_epi8` /
/// `_mm_add_epi32` algebra) and the **previous** 4 schedule words in
/// `m_src` (lanes `[W[t-4], W[t-3], W[t-2], W[t-1]]`), produces the
/// next 4 schedule words `[W[t], W[t+1], W[t+2], W[t+3]]` by
/// completing the FIPS recurrence:
///
///   `result[0] = m_dst[0] + sigma1_256(m_src[2])`
///   `result[1] = m_dst[1] + sigma1_256(m_src[3])`
///   `result[2] = m_dst[2] + sigma1_256(result[0])`
///   `result[3] = m_dst[3] + sigma1_256(result[1])`
///
/// The cross-lane data dependency in the high two lanes
/// (`result[2]` reads `result[0]`; `result[3]` reads `result[1]`) is
/// what makes this intrinsic non-decomposable into safe lane
/// arithmetic — it captures the recurrence's σ₁ stage including the
/// "look one quad back" carry that completes the schedule update.
///
/// The Lean axiom for this stub asserts the lane-wise equation
/// matching the four cases above, with `sigma1_256` the FIPS-180-4
/// §4.1.2 pure function.
#[cfg(feature = "verify")]
#[verify::opaque]
pub(crate) fn sha256msg2_epu32(m_dst: Dwords, m_src: Dwords) -> Dwords {
    let _ = (m_dst, m_src);
    unimplemented!()
}

// ============================================================================
// Sanity tests — cross-check §A specialised wrappers against general forms.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn arb()  -> Dwords { [0xDEAD_BEEFu32, 0xCAFE_F00D, 0x1234_5678, 0x9ABC_DEF0] }
    fn arb2() -> Dwords { [0x1111_2222u32, 0x3333_4444, 0x5555_6666, 0x7777_8888] }

    #[test]
    fn shuffle_epi32_immediates() {
        let a = arb();
        // 0x1B = 0b00_01_10_11 selects sources (3, 2, 1, 0): reverse the dwords.
        assert_eq!(shuffle_epi32::<0x1B>(a), [a[3], a[2], a[1], a[0]]);
        // 0x0E = 0b00_00_11_10 selects sources (2, 3, 0, 0): pull the high
        // qword down; the upper two lanes are don't-care duplicates of a[0].
        assert_eq!(shuffle_epi32::<0x0E>(a), [a[2], a[3], a[0], a[0]]);
    }

    #[test]
    fn alignr_epi8_4_matches_general() {
        let a = arb();
        let b = arb2();
        let general = bytes_to_dwords(alignr_epi8(
            dwords_to_bytes(a),
            dwords_to_bytes(b),
            4,
        ));
        assert_eq!(general, alignr_epi8_4(a, b));
    }

    #[test]
    fn byte_reverse_mask_matches_set_epi8() {
        let m = set_epi8(
            12, 13, 14, 15,
            8,  9,  10, 11,
            4,  5,  6,  7,
            0,  1,  2,  3,
        );
        assert_eq!(m, BYTE_REVERSE_MASK);
    }

    #[test]
    fn byte_reverse_lanes_matches_shuffle_epi8() {
        let a = arb();
        let general = bytes_to_dwords(shuffle_epi8(
            dwords_to_bytes(a),
            BYTE_REVERSE_MASK,
        ));
        assert_eq!(general, byte_reverse_lanes(a));
    }
}
