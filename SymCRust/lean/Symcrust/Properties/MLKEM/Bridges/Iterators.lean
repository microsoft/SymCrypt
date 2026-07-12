/-
  # MLKEM/Bridges/Iterators.lean — `IteratorRange.next` step specs.

  Provides curried `@[step]` specifications for
  `core.iter.range.IteratorRange.next core.iter.range.StepUsize` (the
  Rust `for i in start..end` iterator step) on `Range Usize`, in both
  the `some` (cursor still in range) and `none` (exhausted) forms.

  The specs are duplicated locally to keep MlKem proofs self-contained:
  pulling in the shared `Symcrust.Properties.Iterators` module would
  also drag in the Keccak permutation infrastructure that several of
  its specs transitively depend on.  Curried-postcondition shape matches
  the surrounding MlKem proof style
  (`step as ⟨ o, iter1, ho, hstart, hend ⟩`).
-/
import Symcrust.Code
import Aeneas

open Aeneas Aeneas.Std Result

namespace Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 1000000

/-- `IteratorRange.next` on `Range Usize`, `some` case: cursor still
in range, yields `some range.start` and advances cursor by one. -/
@[step]
theorem IteratorRange_next_Usize_some
    (range : core.ops.range.Range Usize)
    (h : range.start.val < range.«end».val) :
    core.iter.range.IteratorRange.next core.iter.range.StepUsize range
    ⦃ (o : Option Usize) (iter1 : core.ops.range.Range Usize) =>
      o = some range.start ∧
      iter1.start.val = range.start.val + 1 ∧
      iter1.«end» = range.«end» ⦄ := by
  exact core.iter.range.IteratorRange.next_Usize_some_spec range h

/-- `IteratorRange.next` on `Range Usize`, `none` case: cursor at or
past `end`, yields `none` and leaves the range untouched. -/
@[step]
theorem IteratorRange_next_Usize_none
    (range : core.ops.range.Range Usize)
    (h : range.start.val ≥ range.«end».val) :
    core.iter.range.IteratorRange.next core.iter.range.StepUsize range
    ⦃ (o : Option Usize) (iter1 : core.ops.range.Range Usize) =>
      o = none ∧ iter1 = range ⦄ := by
  simp only [core.iter.range.IteratorRange.next,
    core.iter.range.UScalarStep, core.iter.range.UScalarStep.forward_checked,
    core.cmp.impls.PartialOrdUsize.lt, liftFun2,
    show ¬ (range.start.val < range.«end».val) from by omega]
  simp [WP.spec_ok]

/-! ### `setAtNat` helpers — thin aliases to the upstream
`Aeneas.Std.Slice` API.

`xs.val[i]!` (= `xs.val[i].getD default`) is *partial*: when `i ≥ length`
it silently returns `Inhabited.default`, making postconditions "vacuous on
overflow".  Therefore:

  * In **statements** (preconditions, postconditions, helper
    predicates), prefer total `xs.val[i]'h_i_lt_length`.
  * Inside **proof bodies**, `[i]!` may still appear *transiently* —
    e.g. immediately after `Slice.index_usize_spec` — but should be
    rewritten back to `'h` form via `getElem!_pos` before propagating
    through `have`s or into postconditions of lemmas. -/

theorem setAtNat_length {α : Type} (s : Slice α) (i : ℕ) (x : α) :
    (s.setAtNat i x).length = s.length :=
  Slice.setAtNat_length s i x

/-! ### Total-form `setAtNat` accessors -/

theorem setAtNat_getElem_eq {α : Type} (s : Slice α)
    (i : ℕ) (x : α) (h : i < s.length) :
    (s.setAtNat i x).val[i]'(by have := Slice.setAtNat_length s i x; scalar_tac) = x :=
  Slice.getElem_Nat_setAtNat_eq s i x h

theorem setAtNat_getElem_ne {α : Type} (s : Slice α)
    (i j : ℕ) (x : α) (hij : i ≠ j) (hj : j < s.length) :
    (s.setAtNat i x).val[j]'(by have := Slice.setAtNat_length s i x; scalar_tac)
      = s.val[j]'hj :=
  Slice.getElem_Nat_setAtNat_ne s i j x ⟨hij, hj⟩

/-! ### `!`-form accessors (deprecated; prefer the total-form accessors above) -/

@[deprecated setAtNat_getElem_eq (since := "2026-05-22")]
theorem setAtNat_getElem!_eq {α : Type} [Inhabited α] (s : Slice α)
    (i : ℕ) (x : α) (h : i < s.length) :
    (s.setAtNat i x).val[i]! = x :=
  Slice.getElem!_Nat_setAtNat_eq s i x h

@[deprecated setAtNat_getElem_ne (since := "2026-05-22")]
theorem setAtNat_getElem!_ne {α : Type} [Inhabited α] (s : Slice α)
    (i j : ℕ) (x : α) (h : i ≠ j) :
    (s.setAtNat i x).val[j]! = s.val[j]! :=
  Slice.getElem!_Nat_setAtNat_ne s i j x h

/-! ### `Slice.swap` — total-access wrapper.

`core.slice.Slice.swap_spec` (Aeneas stdlib) returns its postcondition in
`[i]!` form. For downstream proofs that prefer to thread the length
hypothesis structurally, this wrapper re-states the same swap with
`[i]'h` equalities. -/

theorem Slice.swap_total.spec {T : Type} [Inhabited T] (s : Slice T)
    (a b : Usize) (ha : a.val < s.length) (hb : b.val < s.length) :
    core.slice.Slice.swap s a b ⦃ s' =>
      ∃ (h_len : s'.length = s.length),
        s'.val[a.val]'(by scalar_tac) = s.val[b.val]'hb ∧
        s'.val[b.val]'(by scalar_tac) = s.val[a.val]'ha ∧
        (∀ i (hi : i < s.length), i ≠ a.val → i ≠ b.val →
          s'.val[i]'(by scalar_tac) = s.val[i]'hi) ⦄ := by
  apply WP.spec_mono (core.slice.Slice.swap_spec s a b ha hb)
  rintro s' ⟨h_len, h_ab, h_ba, h_other⟩
  refine ⟨h_len, ?_, ?_, ?_⟩
  · rw [show s'.val[a.val]'(by scalar_tac) = s'.val[a.val]! from
          (getElem!_pos s'.val a.val (by scalar_tac)).symm,
        show s.val[b.val]'hb = s.val[b.val]! from
          (getElem!_pos s.val b.val hb).symm]
    exact h_ab
  · rw [show s'.val[b.val]'(by scalar_tac) = s'.val[b.val]! from
          (getElem!_pos s'.val b.val (by scalar_tac)).symm,
        show s.val[a.val]'ha = s.val[a.val]! from
          (getElem!_pos s.val a.val ha).symm]
    exact h_ba
  · intro i hi hia hib
    rw [show s'.val[i]'(by scalar_tac) = s'.val[i]! from
          (getElem!_pos s'.val i (by scalar_tac)).symm,
        show s.val[i]'hi = s.val[i]! from
          (getElem!_pos s.val i hi).symm]
    exact h_other i hia hib

end Symcrust.Properties.MLKEM.Bridges
