/-
  X86_64 AES-NI silicon intrinsics.

  ## Sources of truth
  Intel SDM Vol.2A (`AESENC`, `AESDEC`, `AESDECLAST`, …); FIPS-197 §5.
  Differential test: `tests/x86_64_aes_hw.rs`. On Intel the round-key XOR
  happens LAST (opposite of Arm — see `Axioms/Aarch64/Aes.lean`).

  ## Trust ledger
  For each (P4b crypto accelerators) we axiomatize a model + its `@[step]` spec,
  operating on `[u8;16]`:
  - `aesenc_si128` (+ `.spec`) — `MixColumns∘ShiftRows∘SubBytes; ⊕ key`.
  - `aesdec_si128` (+ `.spec`) — `InvMixColumns∘InvShiftRows∘InvSubBytes; ⊕ key`.
  - `aesdeclast_si128` (+ `.spec`) — `InvShiftRows∘InvSubBytes; ⊕ key`.

  `aesimc_si128` / `aesenclast_si128` are trusted models defined by using
  `verify.intrinsics.aes.{imc,subbytes_shiftrows}` (`Axioms/Aes.lean`).
  `aeskeygenassist_si128` is in `Properties/X86_64/Aes.lean`.
-/
import Aeneas
import Symcrust.Code.Types
import Intrinsics.Axioms.X86_64.Common
import Spec.AES.Spec
import Spec.AES.ArrayBridge

open Aeneas Aeneas.Std Result Spec
open core.core_arch.x86
open Intrinsics
open symcrust.aesgcm

set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false

/-- Axiomatized model of `AESENC`, operating on `[u8;16]`. -/
@[rust_fun "symcrust::verify::intrinsics::x86_64::aes::aesenc_si128"]
axiom verify.intrinsics.x86_64.aes.aesenc_si128
  : Array Std.U8 16#usize → Array Std.U8 16#usize → Result (Array Std.U8 16#usize)

/-- `aesenc_si128.spec` — `MixColumns ∘ ShiftRows ∘ SubBytes(state); ⊕ key` on
    `[u8;16]` (Intel SDM `AESENC`, FIPS-197 §5.1). -/
@[step]
axiom verify.intrinsics.x86_64.aes.aesenc_si128.spec
    (a key : Array Std.U8 16#usize) :
    verify.intrinsics.x86_64.aes.aesenc_si128 a key
    ⦃ (r : Array Std.U8 16#usize) =>
      arrayToAesBlock r =
        blockXor
          (AES.stateToBlock (AES.mixColumns (AES.shiftRows (AES.subBytes
            (AES.blockToState (arrayToAesBlock a))))))
          (arrayToAesBlock key) ⦄

/-- Axiomatized model of `AESDEC`, operating on `[u8;16]`. -/
@[rust_fun "symcrust::verify::intrinsics::x86_64::aes::aesdec_si128"]
axiom verify.intrinsics.x86_64.aes.aesdec_si128
  : Array Std.U8 16#usize → Array Std.U8 16#usize → Result (Array Std.U8 16#usize)

/-- `aesdec_si128.spec` — `InvMixColumns ∘ InvShiftRows ∘ InvSubBytes(state); ⊕ key`
    on `[u8;16]` (Intel SDM `AESDEC`, FIPS-197 §5.3.5). -/
@[step]
axiom verify.intrinsics.x86_64.aes.aesdec_si128.spec
    (a key : Array Std.U8 16#usize) :
    verify.intrinsics.x86_64.aes.aesdec_si128 a key
    ⦃ (r : Array Std.U8 16#usize) =>
      arrayToAesBlock r =
        blockXor
          (AES.stateToBlock (AES.invMixColumns (AES.invShiftRows (AES.invSubBytes
            (AES.blockToState (arrayToAesBlock a))))))
          (arrayToAesBlock key) ⦄

/-- Axiomatized model of `AESDECLAST`, operating on `[u8;16]`. -/
@[rust_fun "symcrust::verify::intrinsics::x86_64::aes::aesdeclast_si128"]
axiom verify.intrinsics.x86_64.aes.aesdeclast_si128
  : Array Std.U8 16#usize → Array Std.U8 16#usize → Result (Array Std.U8 16#usize)

/-- `aesdeclast_si128.spec` — `InvShiftRows ∘ InvSubBytes(state); ⊕ key` on
    `[u8;16]` (Intel SDM `AESDECLAST`, FIPS-197 §5.3.5). -/
@[step]
axiom verify.intrinsics.x86_64.aes.aesdeclast_si128.spec
    (a key : Array Std.U8 16#usize) :
    verify.intrinsics.x86_64.aes.aesdeclast_si128 a key
    ⦃ (r : Array Std.U8 16#usize) =>
      arrayToAesBlock r =
        blockXor
          (AES.stateToBlock (AES.invShiftRows (AES.invSubBytes
            (AES.blockToState (arrayToAesBlock a)))))
          (arrayToAesBlock key) ⦄
