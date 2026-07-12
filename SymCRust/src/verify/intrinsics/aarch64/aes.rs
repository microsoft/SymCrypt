//! Shims for Armv8-A AES (`target_feature = "aes"`) intrinsics used by
//! SymCrypt's `aes_neon.rs` driver.
//!
//! ## Trust ledger
//!
//! Axiomatised opaque stubs (4):  `vaeseq_u8`, `vaesdq_u8`, `vaesmcq_u8`,
//! `vaesimcq_u8`.  Each is a hardware-accelerated AES primitive; the Phase-4
//! Lean axiom (not in this file) equates each shim to a fragment of
//! FIPS-197 §5:
//!
//! ```text
//! vaeseq_u8(d, k)  ↔ ShiftRows(SubBytes(d ⊕ k))            (encrypt: pre-MC)
//! vaesdq_u8(d, k)  ↔ InvShiftRows(InvSubBytes(d ⊕ k))      (decrypt: pre-IMC)
//! vaesmcq_u8(d)    ↔ MixColumns(d)
//! vaesimcq_u8(d)   ↔ InvMixColumns(d)
//! ```
//!
//! ## Axiom direction (CRITICAL — key XOR happens FIRST, opposite to Intel)
//!
//! The Armv8 ISA partitions one FIPS-197 round differently from Intel AES-NI:
//! the round-key XOR + S-box + ShiftRows are fused into one instruction
//! (`AESE` / `AESD`) with the XOR happening **first**, and MixColumns is a
//! separate instruction (`AESMC` / `AESIMC`). One full FIPS-197 encryption
//! round on Armv8 is therefore the composition
//!
//!     vaesmcq_u8(vaeseq_u8(state, round_key))
//!     = MixColumns(ShiftRows(SubBytes(state ⊕ round_key)))
//!
//! whereas on Intel one AES-NI round is
//!
//!     aesenc_si128(state, round_key)
//!     = MixColumns(ShiftRows(SubBytes(state))) ⊕ round_key
//!
//! The two are equivalent FIPS-197 rounds modulo a *shift* in which round
//! key XOR's first (initial whitening AddRoundKey vs final XOR). The
//! `aes_neon.rs` driver compensates by treating `round_keys[0]` as the
//! initial-whitening key and shifting subsequent indices by one — Phase-4
//! correctness proofs must mirror that bookkeeping. The skeleton for each
//! Lean axiom is:
//!
//! ```lean
//! /-- AESE: XOR round_key first, then SubBytes ∘ ShiftRows. -/
//! axiom vaeseq_u8.spec (d k : Uint8x16) :
//!   vaeseq_u8 d k =
//!   Spec.AES.shiftRows (Spec.AES.subBytes (Spec.AES.xor128 d k))
//!
//! /-- AESD: XOR round_key first, then InvSubBytes ∘ InvShiftRows. -/
//! axiom vaesdq_u8.spec (d k : Uint8x16) :
//!   vaesdq_u8 d k =
//!   Spec.AES.invShiftRows (Spec.AES.invSubBytes (Spec.AES.xor128 d k))
//!
//! /-- AESMC: MixColumns, no key. -/
//! axiom vaesmcq_u8.spec (d : Uint8x16) :
//!   vaesmcq_u8 d = Spec.AES.mixColumns d
//!
//! /-- AESIMC: InvMixColumns, no key. -/
//! axiom vaesimcq_u8.spec (d : Uint8x16) :
//!   vaesimcq_u8 d = Spec.AES.invMixColumns d
//! ```
//!
//! Witness: `tests/aarch64_aes_hw.rs` defines `fips_aese`/`fips_aesd`/
//! `fips_aesmc`/`fips_aesimc` matching the formulas above and on aarch64
//! silicon asserts equality with the intrinsic outputs across 16 random
//! inputs each. Writing the axiom in Intel order (key XOR LAST) would
//! invert the call-site dataflow and the proof of `aes_neon.rs` would fail
//! at the very first round.
//!
//! The Rust body is `unimplemented!()` — production builds never see these
//! stubs (cfg-gated on `feature = "verify"`).
//!
//! Status: 0 transcribed shims, 4 axiomatised shims.

#![allow(dead_code, unused_variables)]

pub use super::neon::Uint8x16;

/// One AES round-key XOR + SubBytes + ShiftRows (encrypt).
/// Arm ARM C7.2: `AESE Vd, Vn` — `state := ShiftRows(SubBytes(state ⊕ key))`.
///
/// Reduced to the architecture-neutral keyless core
/// `subbytes_shiftrows(state ⊕ key)` (see `verify::intrinsics::aes`), shared
/// with x86 `aesenclast_si128` — one `subbytes_shiftrows` axiom serves both.
#[cfg(feature = "verify")]
pub fn vaeseq_u8(data: Uint8x16, key: Uint8x16) -> Uint8x16 {
    crate::verify::intrinsics::aes::subbytes_shiftrows(super::neon::veorq_u8(data, key))
}

/// One AES round-key XOR + InvSubBytes + InvShiftRows (decrypt).
/// Arm ARM C7.2: `AESD Vd, Vn` — `state := InvShiftRows(InvSubBytes(state ⊕ key))`.
///
/// Reduced to the architecture-neutral keyless core
/// `inv_subbytes_shiftrows(state ⊕ key)` (see `verify::intrinsics::aes`), the
/// decrypt analogue of `vaeseq_u8` / `subbytes_shiftrows`.
#[cfg(feature = "verify")]
pub fn vaesdq_u8(data: Uint8x16, key: Uint8x16) -> Uint8x16 {
    crate::verify::intrinsics::aes::inv_subbytes_shiftrows(super::neon::veorq_u8(data, key))
}

/// AES MixColumns on a 128-bit state.
/// Arm ARM C7.2: `AESMC Vd, Vn`.
///
/// Reduced to the architecture-neutral `verify::intrinsics::aes::mc` (forward
/// MixColumns); ARM-only on the consumer side (x86 has no standalone AESMC).
#[cfg(feature = "verify")]
pub fn vaesmcq_u8(data: Uint8x16) -> Uint8x16 {
    crate::verify::intrinsics::aes::mc(data)
}

/// AES InvMixColumns on a 128-bit state.
/// Arm ARM C7.2: `AESIMC Vd, Vn`.
///
/// Reduced to the architecture-neutral `verify::intrinsics::aes::imc`, shared
/// with x86 `aesimc_si128` — one `imc` axiom serves both.
#[cfg(feature = "verify")]
pub fn vaesimcq_u8(data: Uint8x16) -> Uint8x16 {
    crate::verify::intrinsics::aes::imc(data)
}
