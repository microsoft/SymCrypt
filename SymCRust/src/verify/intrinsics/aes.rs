//! Architecture-neutral AES round transforms over the `[u8; 16]` byte carrier.
//!
//! Both the x86 (`x86_64::aes`) and Armv8 (`aarch64::aes`) AES shims reduce to
//! these two primitives, so a single axiom / step-spec per transform serves
//! *both* ISAs — there is no per-architecture AES trust base to keep in sync.
//! Declared at the top level (like `lanes` / `lanewise`) for exactly that
//! one-spec-covers-both reason, and self-contained (it never reaches into a
//! sibling `x86_64` / `aarch64` module), so the shared definition does not
//! depend on any particular arch being part of a given extraction.
//!
//! `imc`, `mc`, `subbytes_shiftrows`, and `inv_subbytes_shiftrows` are the
//! keyless FIPS-197 building blocks the AES drivers need on the byte carrier.
//! They are axiomatised: the SBOX / ShiftRows / (Inv)MixColumns transforms are
//! the trust boundary, specified in Lean against the FIPS-197 reference (see
//! `Intrinsics/Axioms/Aes.lean`).

use super::lanes::Bytes;

/// FIPS-197 §5.3.3 InvMixColumns applied to a 16-byte AES state (column-major),
/// with no key XOR and no other step.
///
/// Both `x86_64::aes::aesimc_si128` and `aarch64::aes::vaesimcq_u8` reduce to
/// this (`AESIMC` on Armv8, `AESIMC` on x86 — identical transform).
#[cfg(feature = "verify")]
#[verify::opaque]
pub fn imc(state: Bytes) -> Bytes {
    let _ = state;
    unimplemented!()
}

/// SubBytes ∘ ShiftRows on a 16-byte AES state, with no key XOR. SubBytes
/// (bytewise) and ShiftRows (a byte permutation) commute, so the two FIPS-197
/// orderings agree; this is the keyless core of the AES last round.
///
/// Both ISAs reduce to this once the key XOR is factored out:
/// * x86  `aesenclast_si128(s, rk) = subbytes_shiftrows(s) ⊕ rk`,
/// * Armv8 `vaeseq_u8(d, k)        = subbytes_shiftrows(d ⊕ k)`.
#[cfg(feature = "verify")]
#[verify::opaque]
pub fn subbytes_shiftrows(state: Bytes) -> Bytes {
    let _ = state;
    unimplemented!()
}

/// FIPS-197 §5.1.3 forward MixColumns applied to a 16-byte AES state (no key
/// XOR). The Armv8 `AESMC` instruction (`vaesmcq_u8`) reduces to this; x86 has
/// no standalone forward-MixColumns instruction, so this is ARM-only on the
/// consumer side but lives in the neutral module for consistency with `imc`.
#[cfg(feature = "verify")]
#[verify::opaque]
pub fn mc(state: Bytes) -> Bytes {
    let _ = state;
    unimplemented!()
}

/// InvSubBytes ∘ InvShiftRows on a 16-byte AES state, with no key XOR — the
/// keyless core of the AES last *decryption* round (the inverse of
/// `subbytes_shiftrows`). InvSubBytes (bytewise) and InvShiftRows (a byte
/// permutation) commute, so the two FIPS-197 orderings agree.
///
/// Both ISAs reduce to this once the key XOR is factored out:
/// * x86  `aesdeclast_si128(s, rk) = inv_subbytes_shiftrows(s) ⊕ rk`,
/// * Armv8 `vaesdq_u8(d, k)        = inv_subbytes_shiftrows(d ⊕ k)`.
/// (x86 routes `aesdeclast` directly; ARM `vaesdq_u8` is the consumer here.)
#[cfg(feature = "verify")]
#[verify::opaque]
pub fn inv_subbytes_shiftrows(state: Bytes) -> Bytes {
    let _ = state;
    unimplemented!()
}
