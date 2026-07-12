//! Shim for the PCLMULQDQ (`target_feature = "pclmulqdq"`) intrinsic used by
//! SymCrypt's `ghash_xmm.rs` driver.
//!
//! Only one mnemonic exists in this extension: `_mm_clmulepi64_si128`.
//!
//! ## Trust ledger
//!
//! Axiomatised (1):  `clmulepi64_si128`. The Phase-4 Lean axiom equates this
//! shim to the spec-level carry-less 64×64→128 multiplication over GF(2),
//! `Spec.GHash.clmul64` — i.e. the polynomial-multiplication building block
//! of GCM (NIST SP 800-38D §6).  The Rust body is `unimplemented!()` —
//! production builds never see this stub (cfg-gated on `feature = "verify"`).
//!
//! ## Axiom skeleton (Phase 4)
//!
//! ```lean
//! /-- Carry-less 64×64→128 over GF(2), with operand selection by imm8. -/
//! axiom clmulepi64_si128_spec (a b : Qwords) (imm8 : UInt8) :
//!   clmulepi64_si128 a b imm8 =
//!   let lo := Spec.GHash.clmul64
//!               (if (imm8.toNat &&& 0x01) = 0 then a.lo else a.hi)
//!               (if (imm8.toNat &&& 0x10) = 0 then b.lo else b.hi)
//!   -- lo : UInt128, low 127 bits are the GF(2)[X] product, bit 127 = 0.
//!   ⟨lo.low64, lo.high64⟩
//! ```
//!
//! Witness: `tests/x86_64_pclmulqdq_hw.rs::clmul64_ref` is a plain
//! for-loop XOR-shift transcription of the Intel SDM "Operation:" block
//! below; the test asserts silicon = `clmul64_ref` on 32 random inputs
//! across all four `imm8` operand selections, plus the bit-127 = 0 corner
//! property.
//!
//! ## Call-site closure (post-M2 audit, 2026-05-22)
//!
//! `aes/aes_xmm.rs` and `aes/ghash/ghash_xmm.rs` are the only consumers,
//! both via `_mm_clmulepi64_si128`. AES-GCM exclusively uses this
//! intrinsic for GHASH multiplication and the keystream-counter
//! multiplication step.
//!
//! Status: 0 transcribed shims, 1 axiomatised shim.

#![allow(dead_code, unused_variables)]

pub use super::lanes::{Bytes, Qwords, bytes_to_qwords, qwords_to_bytes};

// ----------------------------------------------------------------------------
// _mm_clmulepi64_si128  (PCLMULQDQ; axiomatised)
// ----------------------------------------------------------------------------
// Intel SDM "Operation:"  (NIST SP 800-38D §6.3 polynomial multiplication.)
//   TEMP1 := (imm8[0] == 0) ? a[63:0]    : a[127:64]
//   TEMP2 := (imm8[4] == 0) ? b[63:0]    : b[127:64]
//   FOR i := 0 to 63 :
//       TMP[i] := (TEMP1[0] AND TEMP2[i])
//       FOR j := 1 to i:
//           TMP[i] := TMP[i] XOR (TEMP1[j] AND TEMP2[i-j])
//   FOR i := 64 to 126 :
//       TMP[i] := 0
//       FOR j := i-63 to 63:
//           TMP[i] := TMP[i] XOR (TEMP1[j] AND TEMP2[i-j])
//   TMP[127] := 0
//   DEST[127:0] := TMP[127:0]
// ----------------------------------------------------------------------------

/// Carry-less multiply of one 64-bit half of `a` by one 64-bit half of `b`,
/// selected by `imm8`:
///   - `imm8 & 0x01`: 0 ⇒ a[63:0], 1 ⇒ a[127:64].
///   - `imm8 & 0x10`: 0 ⇒ b[63:0], 1 ⇒ b[127:64].
///
/// The product is the 128-bit polynomial multiplication over GF(2) of the two
/// selected 64-bit operands; bit 127 of the result is 0 by construction.
#[cfg(feature = "verify")]
#[verify::opaque]
pub fn clmulepi64_si128(a: Qwords, b: Qwords, imm8: u8) -> Qwords {
    let _ = (a, b, imm8);
    unimplemented!()
}
