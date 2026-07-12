/-
  Specs for `common::try_new_box_default` at the three `BoxDefault`
  instances used by MLKEM:

  * `mlkem.key.Key.Insts.SymcrustCommonBoxDefault`              (key_allocate)
  * `mlkem.ntt.InternalComputationTemporaries.Insts.SymcrustCommonBoxDefault`
                                                                (encapsulate / decapsulate)
  * `mlkem.DecapsulateTemps.Insts.SymcrustCommonBoxDefault`      (decapsulate)

  ## What is asserted

  Each axiom says the relevant polynomial-buffer fields come back
  **all-zero**, stated as value equalities over `Array U16` buffers
  (`ZeroPoly`, `ZeroPolyVec`; see `Basic/Conversions.lean`).  This
  is deliberately representation-agnostic: it talks about initialized
  arrays of integers, not about `Polynomial q`, and asserts nothing
  about other workspace fields.  Callers convert zero ⇒ `wf` on
  demand via `wfPoly_zeroPoly` / `wfPolyVec_zeroPolyVec` lemmas.

  ## Soundness

  `try_new_box_default` (common.rs:395) obtains its backing store from
  `try_alloc_zeroed` (common.rs:366), i.e. `alloc::alloc::alloc_zeroed`,
  which returns memory in which **every byte is `0`**
  (https://doc.rust-lang.org/std/alloc/fn.alloc_zeroed.html).  All
  polynomial buffers are `Array U16`, for which the zero bitpattern is
  the integer `0`, so each comes back equal to `ZeroPoly` /
  `ZeroPolyVec`.  The `box_default` hook only re-initialises non-buffer
  scalar fields (or is a no-op), so it does not disturb these
  equalities; modelling that hook is outside the Aeneas pointer model,
  hence the axiom (same pattern as `wipe_slice` in
  `Properties/Axioms/Wipe.lean`).

  The `Err` branch is uniform: the only error `try_alloc_zeroed` can
  emit is `Error.MemoryAllocationFailure` (allocation returned null).
-/
import Mathlib.Data.ZMod.Basic
import Symcrust.Code
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.Axioms.System

open Aeneas Aeneas.Std Result
open Symcrust.Properties.MLKEM
open symcrust

open symcrust.common
namespace Symcrust.Properties.MLKEM.Axioms

/-- **Spec for `try_new_box_default` at `mlkem.key.Key`**.

The freshly allocated key's `data` buffer comes back all-zero
(`ZeroPolyVec 24`), because `try_alloc_zeroed` zeroes every byte and
`data : Array (Array U16 256) 24` reads the zero bitpattern as `0`.
Every other `Key` field is left unconstrained: `key_allocate`
overwrites `params`/`n_rows` (and never populates the seed/key
material) before any observation.  See the module header for the
`alloc_zeroed` soundness argument. -/
@[step]
axiom try_new_box_default.Key.spec :
    common.try_new_box_default mlkem.key.Key.Insts.SymcrustCommonBoxDefault
    ⦃ (r : core.result.Result mlkem.key.Key common.Error) =>
        match r with
        | .Ok key => key.data = ZeroPolyVec 24#usize
        | .Err e  => e = Error.MemoryAllocationFailure ∧ out_of_memory ⦄

/-- **Spec for `try_new_box_default` at `InternalComputationTemporaries`**.

All four polynomial workspaces come back all-zero: the two
`max_size_vector` slots are `ZeroPolyVec 4` and the two `poly_element`
slots are `ZeroPoly`, because `try_alloc_zeroed` zeroes every byte (the
`box_default` hook for this struct is a no-op).  The remaining fields
(`poly_element_accumulator`, `hash_state0/1`) are write-before-read
workspaces and are left unconstrained.  Callers that need a `wf`
destination buffer obtain it via `wfPoly_zeroPoly` /
`wfPolyVec_zeroPolyVec`. -/

@[step]
axiom try_new_box_default.ICT.spec :
    common.try_new_box_default
        mlkem.ntt.InternalComputationTemporaries.Insts.SymcrustCommonBoxDefault
    ⦃ (r : core.result.Result mlkem.ntt.InternalComputationTemporaries
                              common.Error) =>
        match r with
        | .Ok temps =>
            temps.max_size_vector0 = ZeroPolyVec 4#usize ∧
            temps.max_size_vector1 = ZeroPolyVec 4#usize ∧
            temps.poly_element0 = ZeroPoly ∧
            temps.poly_element1 = ZeroPoly
        | .Err e =>
            e = Error.MemoryAllocationFailure /\
            out_of_memory ⦄

/-- **Spec for `try_new_box_default` at `DecapsulateTemps`**.

Same shape as the `InternalComputationTemporaries` spec, lifted through
the `comp_temps` field: the four polynomial workspaces under
`comp_temps` come back all-zero (`ZeroPolyVec 4` / `ZeroPoly`) from
`try_alloc_zeroed`.  The `box_default` hook only delegates to the inner
`InternalComputationTemporaries` no-op hook, so it leaves the zero-fill
intact.  Other workspace fields (`read_ciphertext`,
`reencapsulated_ciphertext`, accumulators, hash states) are
write-before-read and unconstrained. -/
@[step]
axiom try_new_box_default.DecapsulateTemps.spec :
    common.try_new_box_default mlkem.DecapsulateTemps.Insts.SymcrustCommonBoxDefault
    ⦃ (r : core.result.Result mlkem.DecapsulateTemps common.Error) =>
        match r with
        | .Ok temps =>
            temps.comp_temps.max_size_vector0 = ZeroPolyVec 4#usize ∧
            temps.comp_temps.max_size_vector1 = ZeroPolyVec 4#usize ∧
            temps.comp_temps.poly_element0 = ZeroPoly ∧
            temps.comp_temps.poly_element1 = ZeroPoly
        | .Err e =>
            e = Error.MemoryAllocationFailure ∧
            out_of_memory ⦄

end Symcrust.Properties.MLKEM.Axioms
