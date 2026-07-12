/-
  Models for the Armv8-A NEON intrinsics consumed by
  `src/verify/intrinsics/aarch64/{neon,aes}.rs`.

  ## Sources of truth
  Arm ARM (DDI 0487 K.a) §C7.2 (NEON). The FIPS-197 AES round intrinsics use
  the Arm AES layer.

  ## Trust ledger
  Trusted model: `Clone` for `uint16x8_t` (the identity).
-/
import Aeneas
import Symcrust.Code.Types
import Intrinsics.Axioms.Aarch64.Common

open Aeneas Aeneas.Std Result
open core.core_arch.arm_shared.neon

set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false

/-! ## `Clone` for `uint16x8_t`

Trusted model for the auto-derived `core::clone::Clone`. -/

/-- `Clone::clone` on `uint16x8_t` is the identity. -/
@[rust_fun
  "core::core_arch::arm_shared::neon::{core::clone::Clone<core::core_arch::arm_shared::neon::uint16x8_t>}::clone"]
def core.core_arch.arm_shared.neon.uint16x8_t.Insts.CoreCloneClone.clone
  (a : uint16x8_t) : Result uint16x8_t :=
  ok a
