//! Shims for AES-NI (`target_feature = "aes"`) intrinsics used by
//! SymCrypt's `aes_xmm.rs` driver.
//!
//! ## Layout
//!
//! - **Transcribed** (1):  `_mm_aeskeygenassist_si128`. Pure SubWord/RotWord
//!   table lookup; no round structure to elide. Body is `const SBOX` indexing
//!   + a rotate + a Rcon XOR — small enough that transcription is preferable
//!   to a Lean axiom (saves one trust-boundary entry).
//!
//! - **Axiomatised opaque stubs** (5):  `_mm_aesenc_si128`,
//!   `_mm_aesenclast_si128`, `_mm_aesdec_si128`, `_mm_aesdeclast_si128`,
//!   `_mm_aesimc_si128`. Each is a hardware-accelerated AES round; the Lean
//!   axiom for each (Phase 4 — not in this file) will equate the shim's
//!   semantics to the spec's `Spec.AES.aes_round` / `aes_inv_round` /
//!   `aes_invmixcolumns`. The Rust body is `unimplemented!()` — production
//!   builds never see these stubs (cfg-gated on `feature = "verify"`); verify
//!   builds replace each call site with a per-step spec equality.
//!
//! ## Axiom direction (CRITICAL — match Intel SDM, not FIPS-197 textbook)
//!
//! Intel's AES-NI instructions apply the round-key XOR **at the end** of
//! every round, NOT at the beginning as in the FIPS-197 §5.1 textbook
//! presentation. Concretely, AESENC/AESENCLAST compute
//!
//!     state  := SubBytes(state)
//!     state  := ShiftRows(state)
//!     state  := MixColumns(state)             // AESENC only; AESENCLAST skips
//!     return   state  XOR  round_key
//!
//! and AESDEC/AESDECLAST apply the inverse-cipher (equivalent-inverse) form
//! with InvShiftRows ∘ InvSubBytes ∘ InvMixColumns then XOR with round_key.
//! Writing the Phase-4 Lean axiom in textbook order (XOR first) would invert
//! the call-site dataflow and the proof of `aes_xmm.rs` would fail at the
//! very first round. The skeleton each axiom must follow is therefore:
//!
//! ```lean
//! /-- AESENC: SubBytes ∘ ShiftRows ∘ MixColumns then XOR round_key. -/
//! axiom aesenc_si128_spec (s k : Bytes) :
//!   aesenc_si128 s k =
//!   Spec.AES.xor128 (Spec.AES.mixColumns (Spec.AES.shiftRows (Spec.AES.subBytes s))) k
//!
//! /-- AESENCLAST: SubBytes ∘ ShiftRows then XOR round_key (no MixColumns). -/
//! axiom aesenclast_si128_spec (s k : Bytes) :
//!   aesenclast_si128 s k =
//!   Spec.AES.xor128 (Spec.AES.shiftRows (Spec.AES.subBytes s)) k
//!
//! /-- AESDEC: InvShiftRows ∘ InvSubBytes ∘ InvMixColumns then XOR round_key. -/
//! axiom aesdec_si128_spec (s k : Bytes) :
//!   aesdec_si128 s k =
//!   Spec.AES.xor128
//!     (Spec.AES.invMixColumns
//!       (Spec.AES.invSubBytes (Spec.AES.invShiftRows s))) k
//!
//! /-- AESDECLAST: InvShiftRows ∘ InvSubBytes then XOR round_key (no InvMixColumns). -/
//! axiom aesdeclast_si128_spec (s k : Bytes) :
//!   aesdeclast_si128 s k =
//!   Spec.AES.xor128 (Spec.AES.invSubBytes (Spec.AES.invShiftRows s)) k
//!
//! /-- AESIMC: InvMixColumns; no key, no other steps. -/
//! axiom aesimc_si128_spec (s : Bytes) :
//!   aesimc_si128 s = Spec.AES.invMixColumns s
//! ```
//!
//! The witness that this is the right order is `tests/x86_64_aes_hw.rs`,
//! whose `fips_aesenc` / `fips_aesenclast` / `fips_aesdec` / `fips_aesdeclast`
//! helpers transcribe exactly the formulas above and the test asserts
//! silicon equality on 16 random inputs each. Any axiom that disagrees with
//! those helpers will fail the silicon ↔ FIPS-197 differential test as
//! well; the two checks are decoupled witnesses of the same convention.
//!
//! Differential tests live in `tests/x86_64_aes_hw.rs`: silicon ↔ shim for
//! `aeskeygenassist`, and silicon ↔ FIPS-197 transcription for the round
//! intrinsics, on the standard NIST test vectors.
//!
//! Status: 1 transcribed shim, 5 axiomatised shims.

#![allow(dead_code, unused_variables)]

pub use super::lanes::{
    bytes_to_dwords, bytes_to_qwords, dwords_to_bytes, qwords_to_bytes, Bytes, Dwords,
};
use super::{pclmulqdq, sse2, ssse3};

/// Canonical carrier for `__m128i` in the verify model of `aes_xmm.rs`: its
/// `u8x16` byte view. The AES-GCM x86 driver mixes the byte view (xor,
/// `shuffle_epi8`, AES rounds), the dword view (counter arithmetic
/// `add_epi32` / `set_epi32`) and the qword view (`clmulepi64`) on the same
/// register; every op below presents a uniform `M128 -> M128` face and
/// reinterprets internally, so the driver is byte-identical to production.
pub type M128 = Bytes;

// ============================================================================
// M128 uniform-carrier face for `src/aes/aes_xmm.rs` (the cfg-swap redirect).
// The byte-view ops are `Bytes`-native; the dword / qword ops reinterpret via
// `bytes_to_*` / `*_to_bytes`. AES-NI round ops are the `aesenc_si128` … etc.
// declared below; `clmulepi64_si128` delegates to the PCLMULQDQ axiom.
// ============================================================================

/// `_mm_xor_si128` — 128-bit bitwise XOR (byte-view native).
#[inline]
pub fn xor_si128(a: M128, b: M128) -> M128 {
    sse2::xor_si128(a, b)
}

/// `_mm_setzero_si128` — all-zero register.
#[inline]
pub fn setzero_si128() -> M128 {
    sse2::setzero_si128()
}

/// `_mm_set_epi8(…)` — build a register from sixteen byte lanes (high first).
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn set_epi8(
    b15: i8, b14: i8, b13: i8, b12: i8, b11: i8, b10: i8, b9: i8, b8: i8, b7: i8, b6: i8, b5: i8,
    b4: i8, b3: i8, b2: i8, b1: i8, b0: i8,
) -> M128 {
    sse2::set_epi8(
        b15, b14, b13, b12, b11, b10, b9, b8, b7, b6, b5, b4, b3, b2, b1, b0,
    )
}

/// `_mm_shuffle_epi8` — byte permute by `mask` (byte-view native).
#[inline]
pub fn shuffle_epi8(a: M128, mask: M128) -> M128 {
    ssse3::shuffle_epi8(a, mask)
}

/// `_mm_add_epi32` — lane-wise wrapping u32 add (dword view).
#[inline]
pub fn add_epi32(a: M128, b: M128) -> M128 {
    dwords_to_bytes(sse2::add_epi32(bytes_to_dwords(a), bytes_to_dwords(b)))
}

/// `_mm_set_epi32(e3, e2, e1, e0)` — build a register from four dword lanes.
#[inline]
pub fn set_epi32(e3: i32, e2: i32, e1: i32, e0: i32) -> M128 {
    dwords_to_bytes(sse2::set_epi32(e3, e2, e1, e0))
}

/// `_mm_set1_epi32(a)` — broadcast `a` to all four dword lanes.
#[inline]
pub fn set1_epi32(a: i32) -> M128 {
    dwords_to_bytes(sse2::set1_epi32(a))
}

/// `_mm_cvtsi128_si32(a)` — the low 32 bits of the register as `i32`.
#[inline]
pub fn cvtsi128_si32(a: M128) -> i32 {
    sse2::cvtsi128_si32(bytes_to_dwords(a))
}

/// `_mm_aeskeygenassist_si128::<IMM8>(a)` — M128 face of the transcribed
/// AES key-schedule assist (const-generic immediate, as on silicon).
#[inline]
pub fn aeskeygenassist_si128_m128<const IMM8: i32>(a: M128) -> M128 {
    dwords_to_bytes(aeskeygenassist_si128(bytes_to_dwords(a), IMM8 as u8))
}

/// `_mm_clmulepi64_si128(a, b, imm8)` — M128 face of the axiomatised PCLMULQDQ
/// carry-less multiply (imm8 operand selection passed as a runtime value, as in
/// the extracted model).
#[inline]
pub fn clmulepi64_si128(a: M128, b: M128, imm8: i32) -> M128 {
    qwords_to_bytes(pclmulqdq::clmulepi64_si128(
        bytes_to_qwords(a),
        bytes_to_qwords(b),
        imm8 as u8,
    ))
}

// ----------------------------------------------------------------------------
// FIPS-197 §5.1.1 S-box (forward).  Reproduced verbatim from the standard.
// ----------------------------------------------------------------------------
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

#[inline]
fn sub_word(w: u32) -> u32 {
    let b = w.to_le_bytes();
    u32::from_le_bytes([
        SBOX[b[0] as usize],
        SBOX[b[1] as usize],
        SBOX[b[2] as usize],
        SBOX[b[3] as usize],
    ])
}

#[inline]
fn rot_word(w: u32) -> u32 {
    // FIPS-197 §5.2: cyclic LEFT shift by ONE BYTE of the 4-byte word, i.e.
    // (a0,a1,a2,a3) → (a1,a2,a3,a0). In little-endian word layout that is
    // a logical RIGHT rotation by 8 bits.
    w.rotate_right(8)
}

// ----------------------------------------------------------------------------
// _mm_aeskeygenassist_si128  (AES-NI; transcribed)
// ----------------------------------------------------------------------------
// Intel SDM "Operation:"
//   X3 := SRC[127:96] ; X2 := SRC[95:64] ; X1 := SRC[63:32] ; X0 := SRC[31:0]
//   RCON  := ZeroExtend32(imm8)
//   DEST[31:0]    := SubWord(X1)
//   DEST[63:32]   := RotWord(SubWord(X1)) XOR RCON
//   DEST[95:64]   := SubWord(X3)
//   DEST[127:96]  := RotWord(SubWord(X3)) XOR RCON
// ----------------------------------------------------------------------------

/// Transcription of `_mm_aeskeygenassist_si128(a, imm8)`.
///
/// Note: the operation is defined on FIPS-197 SubWord/RotWord ONLY, so
/// transcribing here (rather than axiomatising) eliminates one trust-boundary
/// entry without expanding the proof obligations.
#[inline]
pub fn aeskeygenassist_si128(a: Dwords, imm8: u8) -> Dwords {
    let rcon = imm8 as u32;
    let s1 = sub_word(a[1]);
    let s3 = sub_word(a[3]);
    [
        s1,
        rot_word(s1) ^ rcon,
        s3,
        rot_word(s3) ^ rcon,
    ]
}

// ----------------------------------------------------------------------------
// _mm_aesenc_si128 / _mm_aesenclast_si128 / _mm_aesdec_si128 /
// _mm_aesdeclast_si128 / _mm_aesimc_si128   (AES-NI; axiomatised)
// ----------------------------------------------------------------------------
// Each performs one AES round (or the inverse MixColumns) on a 128-bit state
// XORed with a 128-bit round key. The Phase-4 Lean axioms equate each shim
// to the corresponding FIPS-197 §5 round function:
//   aesenc      ↔ Spec.AES.aes_round           (SubBytes ∘ ShiftRows ∘ MixColumns ∘ AddRoundKey)
//   aesenclast  ↔ Spec.AES.aes_round_last      (SubBytes ∘ ShiftRows ∘ AddRoundKey)
//   aesdec      ↔ Spec.AES.aes_dec_round       (InvShiftRows ∘ InvSubBytes ∘ InvMixColumns ∘ AddRoundKey)
//   aesdeclast  ↔ Spec.AES.aes_dec_round_last  (InvShiftRows ∘ InvSubBytes ∘ AddRoundKey)
//   aesimc      ↔ Spec.AES.aes_inv_mix_columns
// ----------------------------------------------------------------------------

/// One AES encryption round on `state` XORed with `round_key`.
/// FIPS-197 §5.1: SubBytes → ShiftRows → MixColumns → AddRoundKey(round_key).
#[cfg(feature = "verify")]
#[verify::opaque]
pub fn aesenc_si128(state: Bytes, round_key: Bytes) -> Bytes {
    let _ = (state, round_key);
    unimplemented!()
}

/// Final AES encryption round on `state` XORed with `round_key`.
/// FIPS-197 §5.1: SubBytes → ShiftRows → AddRoundKey(round_key); no MixColumns.
///
/// Reduced to the architecture-neutral keyless core: `aesenclast_si128(s, rk)
/// = subbytes_shiftrows(s) ⊕ rk` (see `verify::intrinsics::aes`), so x86 and
/// Armv8 share one `subbytes_shiftrows` axiom.
#[cfg(feature = "verify")]
pub fn aesenclast_si128(state: Bytes, round_key: Bytes) -> Bytes {
    xor_si128(crate::verify::intrinsics::aes::subbytes_shiftrows(state), round_key)
}

/// One AES decryption round on `state` XORed with `round_key`.
/// FIPS-197 §5.3 (equivalent inverse cipher form):
/// InvShiftRows → InvSubBytes → InvMixColumns → AddRoundKey(round_key).
#[cfg(feature = "verify")]
#[verify::opaque]
pub fn aesdec_si128(state: Bytes, round_key: Bytes) -> Bytes {
    let _ = (state, round_key);
    unimplemented!()
}

/// Final AES decryption round on `state` XORed with `round_key`.
/// FIPS-197 §5.3: InvShiftRows → InvSubBytes → AddRoundKey(round_key); no InvMixColumns.
#[cfg(feature = "verify")]
#[verify::opaque]
pub fn aesdeclast_si128(state: Bytes, round_key: Bytes) -> Bytes {
    let _ = (state, round_key);
    unimplemented!()
}

/// AES inverse MixColumns applied to `state` (no key XOR, no other steps).
/// Used to pre-compute equivalent-inverse-cipher round keys (FIPS-197 §5.3.5).
///
/// Reduced to the architecture-neutral `verify::intrinsics::aes::imc`, shared
/// with Armv8 `vaesimcq_u8`.
#[cfg(feature = "verify")]
pub fn aesimc_si128(state: Bytes) -> Bytes {
    crate::verify::intrinsics::aes::imc(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sub_word_matches_byte_sbox() {
        // SubWord is a bytewise SBOX lookup.
        let w = 0x0001_5363u32;
        let got = sub_word(w);
        let b = w.to_le_bytes();
        let want = u32::from_le_bytes([
            SBOX[b[0] as usize],
            SBOX[b[1] as usize],
            SBOX[b[2] as usize],
            SBOX[b[3] as usize],
        ]);
        assert_eq!(got, want);
    }

    #[test]
    fn rot_word_is_cyclic_left_byte_rotate() {
        // FIPS-197 example: RotWord(09cf4f3c) = cf4f3c09
        let w = 0x09cf_4f3cu32;
        // Byte order in little-endian u32 layout: a0=0x3c, a1=0x4f, a2=0xcf, a3=0x09
        // Expected output bytes: a1, a2, a3, a0 = 0x4f, 0xcf, 0x09, 0x3c
        let expected = u32::from_le_bytes([0x4f, 0xcf, 0x09, 0x3c]);
        assert_eq!(rot_word(w), expected);
    }

    #[test]
    fn aeskeygenassist_intel_sdm_example() {
        // SDM Vol.2 example: AESKEYGENASSIST xmm1 := 0, imm8 := 0
        let zero: Dwords = [0; 4];
        let r = aeskeygenassist_si128(zero, 0);
        // SubWord(0) = 0x63636363, RotWord stays 0x63636363, XOR 0 unchanged.
        assert_eq!(r, [0x6363_6363, 0x6363_6363, 0x6363_6363, 0x6363_6363]);
    }

    #[test]
    fn aeskeygenassist_imm_xor_only_at_lanes_1_3() {
        // RCON XOR only affects DEST[63:32] (lane 1) and DEST[127:96] (lane 3).
        let a: Dwords = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];
        let r0 = aeskeygenassist_si128(a, 0);
        let r1 = aeskeygenassist_si128(a, 0x1B);
        assert_eq!(r0[0], r1[0]);
        assert_eq!(r0[2], r1[2]);
        assert_eq!(r0[1] ^ r1[1], 0x1B);
        assert_eq!(r0[3] ^ r1[3], 0x1B);
    }
}
