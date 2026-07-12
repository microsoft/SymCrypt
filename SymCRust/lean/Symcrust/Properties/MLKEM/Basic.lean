/-
  Foundation for the ML-KEM implementation correctness proofs.

  This file is the bridge between the Aeneas-extracted Rust code in
  `Symcrust/Code/Funs.lean` and the FIPS 203 spec in
  `Symcrust/Spec/MLKEM/Spec.lean`.  Every other proof file under
  `Properties/MLKEM/` builds on the conversion functions, well-formedness
  predicates, and bridge lemmas declared here.

  ## Layout

  Split into three sub-files that can compile in parallel; this file
  re-exports them so existing `import Symcrust.Properties.MLKEM.Basic`
  consumers don't need to change.

  * `Basic/Params.lean`      — Parameter sets, `wfInternalParams`,
    `cipherlength`, `lengthInvalidArg`, `MLWE_POLYNOMIAL_COEFFICIENTS_val`,
    `mlkem_M_lt_A`, `mlkem.key.Params.ne.spec` axiom.
    **No Mathlib.**
  * `Basic/Conversions.lean` — Coefficient / polynomial / vector / matrix
    bridges (`u16ToZq`, `R`, `Rinv`, `toPoly`, `toMontPoly`, `wfPoly`,
    `toPolyVecOfLen`, …, `mulVecNTTRow`).
    **Imports Mathlib.Data.ZMod.Basic.**
  * `Basic/Bytes.lean`       — Byte bridges (`arrayToSpecBytes`,
    `sliceToSpecBytes`, `listToSpecBytes`, `sliceWindowToSpecBytes` and
    dot-notation aliases) plus generic loop helpers (`Vector_get_ofFn`,
    `List.forIn'_id_invariant{,_indexed}`, `forIn'_getElem_indexed`,
    `forIn'_mprod_snd_indexed`).
    **No Mathlib.**

  New files that only need parameter metadata or byte bridges should
  import the relevant sub-file directly to avoid pulling in ZMod.

  ## Conventions

  * **No `sorry` in `def` bodies, ever.** Every bridge here has a
    concrete body; a `sorry`'d definition would make every dependent
    theorem vacuously true (see `aeneas-lean-core`, "Sorry'd definitions
    vs sorry'd theorems").
  * **Spec helpers only — no theorem statements about Rust functions.**
    Those live next to their proofs (`Ntt/`, `Encoding/`, …). The only
    theorems here are arithmetic identities about `R`, `R⁻¹`, and the
    bridge functions themselves.
-/
import Symcrust.Properties.MLKEM.Basic.Params
import Symcrust.Properties.MLKEM.Basic.Conversions
import Symcrust.Properties.MLKEM.Basic.Bytes
