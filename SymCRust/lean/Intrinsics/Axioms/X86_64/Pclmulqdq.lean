/-
  X86_64 `pclmulqdq` silicon intrinsic.

  ## Sources of truth
  Intel SDM Vol.2B `PCLMULQDQ`. Differential test:
  `tests/x86_64_pclmulqdq_hw.rs`.

  ## Trust ledger
  Axioms (the GF(2)[X] carry-less multiply IS the spec):
  - `verify.intrinsics.x86_64.pclmulqdq.clmulepi64_si128` (+ `.spec`) —
    `PCLMULQDQ` on `[u64; 2]`, product `Spec.AESGCM.clmul64`.
-/
import Aeneas
import Symcrust.Code.Types
import Intrinsics.Axioms.X86_64.Common
import Spec.AESGCM.Clmul

open Aeneas Aeneas.Std Result
open core.core_arch.x86

set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false

/-! ## `clmulepi64_si128`

Model of `PCLMULQDQ` operating on `[u64; 2]`: `imm8` bit 0 selects the half of
`a`, bit 4 the half of `b`; result lanes are the low/high 64-bit halves of the
GF(2)[X] product `Spec.AESGCM.clmul64`. -/

/-- Axiomatized model of `PCLMULQDQ`, operating on `[u64; 2]`
    (`src/verify/intrinsics/x86_64/pclmulqdq.rs::clmulepi64_si128`). -/
@[rust_fun "symcrust::verify::intrinsics::x86_64::pclmulqdq::clmulepi64_si128"]
axiom verify.intrinsics.x86_64.pclmulqdq.clmulepi64_si128
  : Array Std.U64 2#usize → Array Std.U64 2#usize → Std.U8 → Result (Array
    Std.U64 2#usize)

/-- `clmulepi64_si128.spec` — the `[u64; 2]` counterpart of
    `_mm_clmulepi64_si128.spec`. -/
@[step]
axiom verify.intrinsics.x86_64.pclmulqdq.clmulepi64_si128.spec
    (a b : Array Std.U64 2#usize) (imm8 : Std.U8) :
    verify.intrinsics.x86_64.pclmulqdq.clmulepi64_si128 a b imm8
    ⦃ (r : Array Std.U64 2#usize) =>
      let lane_a : BitVec 64 := if imm8.bv.getLsbD 0 then a[1].bv else a[0].bv
      let lane_b : BitVec 64 := if imm8.bv.getLsbD 4 then b[1].bv else b[0].bv
      let prod : BitVec 128 := Spec.AESGCM.clmul64 lane_a lane_b
      r[0].bv = prod.extractLsb' 0 64 ∧
      r[1].bv = prod.extractLsb' 64 64 ⦄
