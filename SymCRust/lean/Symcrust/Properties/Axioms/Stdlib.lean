/-
  Stdlib.lean — generic Rust stdlib / FFI axioms used across the proofs.

  Most generic stdlib operations are MODELLED (def + `@[step]` theorem) in
  the Aeneas stdlib, so they need no project-local `@[step]` axioms:
    * `Array.as_ref` / `Array.as_mut`  — `Aeneas/Std/Array/ArraySlice.lean`
    * `core.slice.Slice.fill`          — `Aeneas/Std/Slice.lean`
    * `core.num.{U,I}{32,128}.cast_{signed,unsigned}` — `Aeneas/Std/Scalar/CoreConvertNum.lean`
  After re-extraction the call sites in `Code/Funs.lean` resolve directly to the
  aeneas models, whose theorems fire via `@[step]`.

  The only remaining declaration here is `common.Error.ne`, which is about the
  project-specific `common.Error` enum and therefore cannot live in the generic
  aeneas stdlib.
-/
import Symcrust.Code

open Aeneas Aeneas.Std Result

namespace symcrust

/-! ## `common.Error.ne` — error code inequality

`common.Error` is auto-generated without a `DecidableEq` instance;
declare one here so we can phrase the spec via `decide (e1 ≠ e2)`. -/

deriving instance DecidableEq for symcrust.common.Error

/-- **Step spec for `Error::eq`** (discriminant comparison ⇔ structural equality). -/
@[step]
theorem common.Error.eq.step.spec (a b : common.Error) :
    common.Error.Insts.CoreCmpPartialEqError.eq a b ⦃ (r : Bool) => r ↔ a = b ⦄ := by
  unfold common.Error.Insts.CoreCmpPartialEqError.eq
  simp only [WP.spec_ok, decide_eq_true_eq]
  constructor
  · intro h; cases a <;> cases b <;> simp_all [common.Error.read_discriminant]
  · intro h; subst h; rfl

/-- **Step spec for `Error::ne`** as seen in the extracted code
(`PartialEq.ne.trait_default` at the `Error` instance): returns
`decide (e1 ≠ e2)`.  Unconditional, so `step` applies it directly. -/
@[step]
theorem common.Error.ne.trait_default.spec (e1 e2 : common.Error) :
    Aeneas.Std.core.cmp.PartialEq.ne.trait_default
      common.Error.Insts.CoreCmpPartialEqError e1 e2
    ⦃ (b : Bool) => b = decide (e1 ≠ e2) ⦄ := by
  apply WP.spec_mono
    (Aeneas.Std.core.cmp.PartialEq.ne.trait_default.spec
      common.Error.Insts.CoreCmpPartialEqError e1 e2
      (common.Error.eq.step.spec e1 e2))
  intro b hb
  cases b <;> simp_all

/-! ## Opaque constant-time helpers

`const_time_slices_equal_impl` and `const_time_slice_copy_impl` are marked
`#[verify::opaque]` in Rust: their bodies perform constant-time comparison /
conditional copy through raw-pointer volatile reads and writes, which Aeneas
cannot translate faithfully. They are therefore extracted as opaque axioms in
`Code/FunsExternal.lean`; here we postulate their functional (value-level)
behaviour. The constant-time property itself is out of scope for the
functional-correctness proofs. -/

/-- `const_time_slices_equal_impl a b` returns `true` iff the two equal-length
    byte slices are equal.  (The Rust body asserts `a.len() == b.len()`.) -/
@[step]
axiom common.const_time_slices_equal_impl.spec
    (a b : Slice U8) (h_len : a.length = b.length) :
    common.const_time_slices_equal_impl a b
    ⦃ (result : Bool) =>
      result = true ↔ a.val = b.val ⦄

/-- `const_time_slice_copy_impl a b copy_size` returns a slice of `b`'s length
    that equals `a` when `copy_size = a.len()` and equals `b` when
    `copy_size = 0` (the only two values the callers ever pass).  Requires
    `a.len() ≤ I32::MAX` for the constant-time mask arithmetic. -/
@[step]
axiom common.const_time_slice_copy_impl.spec
    (a b : Slice U8) (copy_size : U32)
    (h_len : a.length = b.length)
    (hN : a.length ≤ I32.max)
    (hcopy : copy_size.val = 0 ∨ copy_size.val = a.length) :
    common.const_time_slice_copy_impl a b copy_size
    ⦃ (result : Slice U8) =>
      result.length = b.length ∧
      (copy_size.val = a.length → result.val = a.val) ∧
      (copy_size.val = 0 → result.val = b.val) ⦄

end symcrust
