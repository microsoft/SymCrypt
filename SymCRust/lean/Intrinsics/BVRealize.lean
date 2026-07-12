import Lean.Elab.Tactic.BVDecide.Frontend.Normalize.Enums
import Aeneas.Std.Scalar.Core

/-!
  defensive `<Enum>.enumToBitVec` realiser.

  ## What this file does

  `bv_decide` (and `bv_tac`) lazily synthesise a *public* aux def
  `<Enum>.enumToBitVec` whenever a goal mentions an enum value.  When
  two oleans on the same import chain each realise the constant for
  the same enum, Lean refuses the second one ("environment already
  contains 'Foo.enumToBitVec' from <other olean>").  Centralising the
  realisation here ensures every downstream olean reuses one copy.

  ## Defensive enum list

  The list below is the set of enums known to clash on the SIMD-NTT
  build closure.  Each is realised here ONLY if no upstream module
  has already realised it — `getEnumToBitVecFor` would itself create
  a new copy and re-trigger the clash if called unconditionally.

  The `unless` guards reuse upstream realisations when they exist and create
  only the missing enum realisers. `PUnit` is a Lean stdlib type and is realised
  locally when absent.
-/

open Lean Elab Tactic BVDecide.Frontend.Normalize in
run_meta do
  let env ← getEnv
  for n in [``PUnit, ``Aeneas.Std.UScalarTy, ``Aeneas.Std.IScalarTy] do
    unless env.contains (n.str "enumToBitVec") do
      Lean.enableRealizationsForConst n
      let _ ← getEnumToBitVecFor n
