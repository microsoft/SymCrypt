/-
  Architecture-neutral AES transforms operating on a 16-byte state, shared by
  the x86 (`aes_xmm`) and Armv8 (`aes_neon`) shims
  (`src/verify/intrinsics/aes.rs`). Hosting them once serves both ISAs.

  ## Sources of truth
  FIPS-197 §5 (SubBytes / ShiftRows / MixColumns and inverses). Differential
  tests: `src/verify/tests/{x86_64,aarch64}_aes_hw.rs`.

  ## Trust ledger
  Axioms (standardised S-box and GF(2⁸) MixColumns matrices):
  - `imc` / `imc.spec` — InvMixColumns.
  - `mc` / `mc.spec` — MixColumns.
  - `subbytes_shiftrows` / `.spec` — ShiftRows ∘ SubBytes.
  - `inv_subbytes_shiftrows` / `.spec` — InvShiftRows ∘ InvSubBytes.
-/
import Aeneas
import Symcrust.Code.Types
import Spec.AES.Spec
import Spec.AES.ArrayBridge

open Aeneas Aeneas.Std Result Spec
open symcrust.aesgcm

set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false

/-- Model of FIPS-197 §5.3.3 InvMixColumns operating on a 16-byte AES state (no
    key XOR). Both `aesimc_si128` (x86 `AESIMC`) and `vaesimcq_u8` (Armv8
    `AESIMC`) reduce to this. -/
@[rust_fun "symcrust::verify::intrinsics::aes::imc"]
axiom verify.intrinsics.aes.imc
  : Array Std.U8 16#usize → Result (Array Std.U8 16#usize)

/-- **FIPS-197 §5.3.3** InvMixColumns on a 16-byte AES state, no key XOR. -/
@[step]
axiom verify.intrinsics.aes.imc.spec (a : Array Std.U8 16#usize) :
    verify.intrinsics.aes.imc a
    ⦃ (r : Array Std.U8 16#usize) =>
      arrayToAesBlock r =
        AES.stateToBlock (AES.invMixColumns
          (AES.blockToState (arrayToAesBlock a))) ⦄

/-- FIPS-197 §5.1.3 MixColumns on a 16-byte AES state, no key XOR. The Armv8
    `AESMC` instruction (`vaesmcq_u8`) reduces to this; x86 has no standalone
    forward-MixColumns instruction. -/
@[rust_fun "symcrust::verify::intrinsics::aes::mc"]
axiom verify.intrinsics.aes.mc
  : Array Std.U8 16#usize → Result (Array Std.U8 16#usize)

/-- **FIPS-197 §5.1.3** forward MixColumns on a 16-byte AES state, no key XOR. -/
@[step]
axiom verify.intrinsics.aes.mc.spec (a : Array Std.U8 16#usize) :
    verify.intrinsics.aes.mc a
    ⦃ (r : Array Std.U8 16#usize) =>
      arrayToAesBlock r =
        AES.stateToBlock (AES.mixColumns
          (AES.blockToState (arrayToAesBlock a))) ⦄

/-- Model of SubBytes ∘ ShiftRows operating on a 16-byte AES state (no key XOR),
    the keyless core of the AES last round.
    `aesenclast_si128(s,rk) = subbytes_shiftrows(s) ⊕ rk` (x86) and
    `vaeseq_u8(d,k) = subbytes_shiftrows(d ⊕ k)` (Armv8) both reduce to this. -/
@[rust_fun "symcrust::verify::intrinsics::aes::subbytes_shiftrows"]
axiom verify.intrinsics.aes.subbytes_shiftrows
  : Array Std.U8 16#usize → Result (Array Std.U8 16#usize)

/-- **FIPS-197 §5.1** `ShiftRows ∘ SubBytes` on a 16-byte AES state (key XOR
    factored out). SubBytes and ShiftRows commute
    (`Spec.AES.subBytes_shiftRows_comm`), so the two FIPS orderings agree. -/
@[step]
axiom verify.intrinsics.aes.subbytes_shiftrows.spec (a : Array Std.U8 16#usize) :
    verify.intrinsics.aes.subbytes_shiftrows a
    ⦃ (r : Array Std.U8 16#usize) =>
      arrayToAesBlock r =
        AES.stateToBlock (AES.shiftRows (AES.subBytes
          (AES.blockToState (arrayToAesBlock a)))) ⦄

/-- Model of InvSubBytes ∘ InvShiftRows operating on a 16-byte AES state (no key
    XOR), the keyless core of the AES last decryption round (inverse of
    `subbytes_shiftrows`). `aesdeclast_si128(s,rk) = inv_subbytes_shiftrows(s) ⊕ rk`
    (x86) and `vaesdq_u8(d,k) = inv_subbytes_shiftrows(d ⊕ k)` (Armv8) both reduce
    to this. -/
@[rust_fun "symcrust::verify::intrinsics::aes::inv_subbytes_shiftrows"]
axiom verify.intrinsics.aes.inv_subbytes_shiftrows
  : Array Std.U8 16#usize → Result (Array Std.U8 16#usize)

/-- **FIPS-197 §5.3** `InvShiftRows ∘ InvSubBytes` on a 16-byte AES state (key
    XOR factored out). InvSubBytes and InvShiftRows commute, so the two FIPS
    orderings agree. -/
@[step]
axiom verify.intrinsics.aes.inv_subbytes_shiftrows.spec (a : Array Std.U8 16#usize) :
    verify.intrinsics.aes.inv_subbytes_shiftrows a
    ⦃ (r : Array Std.U8 16#usize) =>
      arrayToAesBlock r =
        AES.stateToBlock (AES.invShiftRows (AES.invSubBytes
          (AES.blockToState (arrayToAesBlock a)))) ⦄
