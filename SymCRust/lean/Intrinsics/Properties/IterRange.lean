/-
  Shared step helpers for `core.iter.range.IteratorRange.next` over `Usize`
  Range iterators.

  These two `@[step]` theorems are used by every layer-1 `_loop` proof
  that iterates over a `core.ops.range.Range Std.Usize`.  They were
  initially copied from `Symcrust/Properties/SHA3/Keccak/Loop.lean`
  into each `*Specs.lean` file; this module centralizes them so the
  Sse2/Ssse3/Avx2/Sha/Aes spec files can share the same step lemmas
  without per-file duplication.
-/
import Symcrust.Code.Funs

open Aeneas Aeneas.Std

namespace symcrust

/-- `IteratorRange.next` returns `some range.start` when the range is
    non-empty and advances `range.start` by 1, leaving `end` unchanged. -/
@[step]
theorem iter_next_some
    (range : core.ops.range.Range Std.Usize)
    (h : range.start.val < range.«end».val) :
    core.iter.range.IteratorRange.next core.iter.range.StepUsize range
    ⦃ (o : Option Std.Usize) (iter1 : core.ops.range.Range Std.Usize) =>
      o = some range.start ∧
      iter1.start.val = range.start.val + 1 ∧
      iter1.«end» = range.«end» ⦄ := by
  exact core.iter.range.IteratorRange.next_Usize_some_spec range h

/-- `IteratorRange.next` returns `none` and leaves the range unchanged
    when the range is empty. -/
@[step]
theorem iter_next_none
    (range : core.ops.range.Range Std.Usize)
    (h : range.start.val ≥ range.«end».val) :
    core.iter.range.IteratorRange.next core.iter.range.StepUsize range
    ⦃ (o : Option Std.Usize) (iter1 : core.ops.range.Range Std.Usize) =>
      o = none ∧ iter1 = range ⦄ := by
  simp only [core.iter.range.IteratorRange.next,
    core.iter.range.UScalarStep, core.iter.range.UScalarStep.forward_checked,
    core.cmp.impls.PartialOrdUsize.lt, liftFun2,
    show ¬ (range.start.val < range.«end».val) from by omega]
  simp [WP.spec_ok]

end symcrust
