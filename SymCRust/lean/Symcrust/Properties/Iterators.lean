import Aeneas
import Aeneas.Std.SliceIter
import Init.Internal.Order.While
import Symcrust.Code.Funs

set_option linter.unusedSimpArgs false

/-!
# Iterator Progress Specs

Progress specifications for iterators used by the ML-KEM model. Aeneas defines
the iterator operations but provides no @[step] theorems — we supply them here.

## Patterns covered:
- `Range<Usize>` next (bounded loop counter)
- `Slice.iter` next (shared iteration over slice elements)
- `Slice.iter_mut` next + back (mutable iteration with back-patching)
- `Slice.iter` / `Slice.iter_mut` construction
- `StepBy` next (strided iteration)
-/

namespace Aeneas.Std

open Result Error core.ops.range

/-! ## Range<Usize> iterator -/

@[step]
theorem core.iter.range.IteratorRange.next_Usize.spec
  (range : core.ops.range.Range Usize)
  (h : range.start.val < range.end.val) :
  core.iter.range.IteratorRange.next core.iter.range.StepUsize range
  ⦃ p =>
    p.1 = some range.start ∧
    p.2.start.val = range.start.val + 1 ∧
    p.2.end = range.end
  ⦄ := by
  -- Delegate to the Aeneas stdlib spec (sp5 `Aeneas.Std.RangeIter`).
  exact core.iter.range.IteratorRange.next_Usize_some_spec range h

@[step]
theorem core.iter.range.IteratorRange.next_Usize_spec_none
  (range : core.ops.range.Range Usize)
  (h : range.start.val ≥ range.end.val) :
  core.iter.range.IteratorRange.next core.iter.range.StepUsize range
  ⦃ p =>
    p.1 = none ∧ p.2 = range
  ⦄ := by
  simp only [core.iter.range.IteratorRange.next,
    core.iter.range.UScalarStep, core.iter.range.UScalarStep.forward_checked,
    core.cmp.impls.PartialOrdUsize.lt, liftFun2,
    show ¬ (range.start.val < range.end.val) from by omega]
  simp [WP.spec_ok]

/-- Curried-postcondition variant of `next_Usize_some_spec` enabling
`let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← IteratorRange_next_some` in
`partial_fixpoint` recursive-loop proofs. -/
@[step]
theorem IteratorRange_next_some
    (range : core.ops.range.Range Usize)
    (h : range.start.val < range.end.val) :
    core.iter.range.IteratorRange.next core.iter.range.StepUsize range
    ⦃ (o : Option Usize) (iter1 : core.ops.range.Range Usize) =>
      o = some range.start ∧
      iter1.start.val = range.start.val + 1 ∧
      iter1.end = range.end ⦄ := by
  apply WP.spec_mono (core.iter.range.IteratorRange.next_Usize.spec range h)
  rintro ⟨o, iter1⟩ ⟨h1, h2, h3⟩
  simp only [WP.uncurry'_pair]
  exact ⟨h1, h2, h3⟩

/-- Curried-postcondition variant of `next_Usize_spec_none`. -/
@[step]
theorem IteratorRange_next_none
    (range : core.ops.range.Range Usize)
    (h : range.start.val ≥ range.end.val) :
    core.iter.range.IteratorRange.next core.iter.range.StepUsize range
    ⦃ (o : Option Usize) (iter1 : core.ops.range.Range Usize) =>
      o = none ∧ iter1 = range ⦄ := by
  apply WP.spec_mono (core.iter.range.IteratorRange.next_Usize_spec_none range h)
  rintro ⟨o, iter1⟩ ⟨h1, h2⟩
  simp only [WP.uncurry'_pair]
  exact ⟨h1, h2⟩

@[step]
theorem core.slice.Slice.iter.spec {T : Type} (s : Slice T) :
  core.slice.Slice.iter s ⦃ it =>
    it.slice = s ∧ it.i = 0 ⦄ := by
  simp [core.slice.Slice.iter]

@[step]
theorem core.slice.iter.IteratorSliceIter.next.spec {T : Type}
  (it : core.slice.iter.Iter T)
  (h : it.i < it.slice.len) :
  core.slice.iter.IteratorSliceIter.next it
  ⦃ p =>
    p.1 = some (it.slice[it.i]) ∧ p.2.slice = it.slice ∧ p.2.i = it.i + 1
  ⦄ := by
  simp only [core.slice.iter.IteratorSliceIter.next, h, ↓reduceDIte]
  simp

@[step]
theorem core.slice.iter.IteratorSliceIter.next_spec_none {T : Type}
  (it : core.slice.iter.Iter T)
  (h : it.i ≥ it.slice.len) :
  core.slice.iter.IteratorSliceIter.next it
  ⦃ p =>
    p.1 = none ∧ p.2 = it
  ⦄ := by
  simp only [core.slice.iter.IteratorSliceIter.next]
  split
  · agrind
  · simp

/-! ## `Enumerate (Iter T)` iterator — derived `@[step]` specs

These wrap the Aeneas-generated `Enumerate::next` equation lemma, which
encodes Rust stdlib semantics for `Enumerate::next` verbatim. Below we
specialise to the concrete `Iterator` instance used by MLKEM call sites:
`IteratorSliceIter T` (over `slice::Iter T`). Two specs (`some` and
`none`), both derived from the underlying `IteratorSliceIter.next`
specs above plus the `_def` axiom — i.e. *no new trust* beyond the
single Rust-bridge axiom.

The iterator state has two fields:
  - `iter.iter : Iter T` — the wrapped slice iterator (with its own
    `slice` and cursor `i`).
  - `iter.count : Usize` — the current count, incremented on each
    successful `next`. Initialised to `0#usize` by
    `IteratorSliceIter.enumerate` (Aeneas, `SliceIter.lean:76-79`).

Pattern invariant maintained by call sites: `iter.count.val = iter.iter.i`,
i.e. the count tracks the cursor 1:1 (true for `enumerate(slice.iter
s)` chains because both start at 0 and advance in lock-step).

Used by `Ntt/MatVec.lean` inner loop, `Encoding/Compress.lean` vector
loop, and any other `enumerate(slice.iter …)` consumer. -/

@[step]
theorem core.iter.adapters.enumerate.Enumerate.Insts.next_SliceIter.spec
    {T : Type}
    (iter : core.iter.adapters.enumerate.Enumerate (core.slice.iter.Iter T))
    (h_lt : iter.iter.i < iter.iter.slice.len)
    (h_no_overflow : iter.count.val + 1 ≤ Usize.max) :
    core.iter.adapters.enumerate.IteratorEnumerate.next
      (core.iter.traits.iterator.IteratorSliceIter T) iter
    ⦃ p =>
      p.1 = some (iter.count, iter.iter.slice[iter.iter.i]) ∧
      p.2.iter.slice = iter.iter.slice ∧
      p.2.iter.i = iter.iter.i + 1 ∧
      p.2.count.val = iter.count.val + 1
    ⦄ := by
  have h_inner :
      (core.iter.traits.iterator.IteratorSliceIter T).next iter.iter
      ⦃ p => p.1 = some (iter.iter.slice[iter.iter.i]) ∧
             p.2 = { slice := iter.iter.slice, i := iter.iter.i + 1 } ⦄ := by
    apply WP.spec_mono (core.slice.iter.IteratorSliceIter.next.spec iter.iter h_lt)
    rintro ⟨o, it'⟩ ⟨ho, hs, hi⟩
    exact ⟨ho, by cases it'; simp_all⟩
  apply WP.spec_mono
    (core.iter.adapters.enumerate.IteratorEnumerate.next_some_spec
      (core.iter.traits.iterator.IteratorSliceIter T) iter
      (iter.iter.slice[iter.iter.i])
      { slice := iter.iter.slice, i := iter.iter.i + 1 }
      h_inner h_no_overflow)
  rintro ⟨opt, self'⟩ ⟨hopt, hiter, hcount⟩
  exact ⟨hopt, by rw [hiter], by rw [hiter], hcount⟩

@[step]
theorem core.iter.adapters.enumerate.Enumerate.Insts.next_SliceIter_spec_none
    {T : Type}
    (iter : core.iter.adapters.enumerate.Enumerate (core.slice.iter.Iter T))
    (h_ge : iter.iter.i ≥ iter.iter.slice.len) :
    core.iter.adapters.enumerate.IteratorEnumerate.next
      (core.iter.traits.iterator.IteratorSliceIter T) iter
    ⦃ p =>
      p.1 = none ∧
      p.2.iter = iter.iter ∧
      p.2.count = iter.count
    ⦄ := by
  have h_inner :
      (core.iter.traits.iterator.IteratorSliceIter T).next iter.iter
      ⦃ p => p.1 = none ∧ p.2 = iter.iter ⦄ :=
    core.slice.iter.IteratorSliceIter.next_spec_none iter.iter h_ge
  apply WP.spec_mono
    (core.iter.adapters.enumerate.IteratorEnumerate.next_none_spec
      (core.iter.traits.iterator.IteratorSliceIter T) iter iter.iter h_inner)
  rintro ⟨opt, self'⟩ ⟨hopt, hiter, hcount⟩
  exact ⟨hopt, hiter, hcount⟩

/-- Curried-postcondition variant of `next_SliceIter_spec` enabling
`let* ⟨ o, iter1, ho, hslice, hi, hcount ⟩ ← Enumerate_SliceIter_next_some`
in `partial_fixpoint` recursive-loop proofs over `Enumerate (Iter T)`. -/
@[step]
theorem Enumerate_SliceIter_next_some {T : Type}
    (iter : core.iter.adapters.enumerate.Enumerate (core.slice.iter.Iter T))
    (h_lt : iter.iter.i < iter.iter.slice.len)
    (h_no_overflow : iter.count.val + 1 ≤ Usize.max) :
    core.iter.adapters.enumerate.IteratorEnumerate.next
      (core.iter.traits.iterator.IteratorSliceIter T) iter
    ⦃ (o : Option (Usize × T))
      (iter1 : core.iter.adapters.enumerate.Enumerate (core.slice.iter.Iter T)) =>
      o = some (iter.count, iter.iter.slice[iter.iter.i]) ∧
      iter1.iter.slice = iter.iter.slice ∧
      iter1.iter.i = iter.iter.i + 1 ∧
      iter1.count.val = iter.count.val + 1 ⦄ := by
  apply WP.spec_mono
    (core.iter.adapters.enumerate.Enumerate.Insts.next_SliceIter.spec iter h_lt h_no_overflow)
  rintro ⟨o, iter1⟩ ⟨ho, hs, hi, hc⟩
  exact ⟨ho, hs, hi, hc⟩

@[step]
theorem Enumerate_SliceIter_next_none {T : Type}
    (iter : core.iter.adapters.enumerate.Enumerate (core.slice.iter.Iter T))
    (h_ge : iter.iter.i ≥ iter.iter.slice.len) :
    core.iter.adapters.enumerate.IteratorEnumerate.next
      (core.iter.traits.iterator.IteratorSliceIter T) iter
    ⦃ (o : Option (Usize × T))
      (iter1 : core.iter.adapters.enumerate.Enumerate (core.slice.iter.Iter T)) =>
      o = none ∧ iter1 = iter ⦄ := by
  apply WP.spec_mono
    (core.iter.adapters.enumerate.Enumerate.Insts.next_SliceIter_spec_none iter h_ge)
  rintro ⟨o, iter1⟩ ⟨ho, h_iter, h_count⟩
  refine ⟨ho, ?_⟩
  cases iter1; cases iter
  simp_all


/-! ## Slice.iter_mut and its back closure -/

@[step]
theorem core.slice.Slice.iter_mut.spec {T : Type} (s : Slice T) :
  core.slice.Slice.iter_mut s ⦃ p =>
    p.1.slice = s ∧ p.1.i = 0 ∧ ∀ it', p.2 it' = it'.slice ⦄ := by
  simp [core.slice.Slice.iter_mut]

@[step]
theorem core.slice.iter.IteratorIterMut.next.spec {T : Type}
  (it : core.slice.iter.IterMut T)
  (h : it.i < it.slice.len) :
  core.slice.iter.IteratorIterMut.next it
  ⦃ p =>
    let (o, it', back) := p
    o = some (it.slice[it.i]) ∧
    it'.slice = it.slice ∧
    it'.i = it.i + 1 ∧
    (∀ it'', back it'' none = it'') ∧
    (∀ it'' x, back it'' (some x) = { it'' with slice := it''.slice.setAtNat it.i x })
  ⦄ := by
  simp only [core.slice.iter.IteratorIterMut.next, h, ↓reduceDIte]
  simp

@[step]
theorem core.slice.iter.IteratorIterMut.next_spec_none {T : Type}
  (it : core.slice.iter.IterMut T)
  (h : it.i ≥ it.slice.len) :
  core.slice.iter.IteratorIterMut.next it
  ⦃ p =>
    let (o, it', back) := p
    o = none ∧ it' = it ∧ ∀ it'' ox, back it'' ox = it''
  ⦄ := by
  simp only [core.slice.iter.IteratorIterMut.next]
  split
  · agrind
  · simp

/-! ## `ChunksExact T` iterator: `next` step specs.

The Aeneas-provided definition (`Aeneas/Std/SliceIter.lean`) pattern-matches
on `self.chunks`:
- `[]` → `(none, self)` (exhausted; remainder unchanged)
- `chunk :: rest` → `(some chunk, { chunks := rest, remainder := self.remainder })`

Two `@[step]` specs mirror the `IteratorSliceIter.next_spec` /
`...next_spec_none` pattern above, proved by `unfold` + case-split on
`self.chunks` (no new axioms). -/

@[step]
theorem core.slice.iter.IteratorChunksExact.next_spec_some
    {T : Type} (self : core.slice.iter.ChunksExact T)
    (chunk : Aeneas.Std.Slice T) (rest : List (Aeneas.Std.Slice T))
    (h : self.chunks = chunk :: rest) :
    core.slice.iter.IteratorChunksExact.next self
    ⦃ p =>
      p.1 = some chunk ∧
      p.2.chunks = rest ∧
      p.2.remainder = self.remainder ⦄ := by
  simp only [core.slice.iter.IteratorChunksExact.next, h]
  simp

@[step]
theorem core.slice.iter.IteratorChunksExact.next_spec_none
    {T : Type} (self : core.slice.iter.ChunksExact T)
    (h : self.chunks = []) :
    core.slice.iter.IteratorChunksExact.next self
    ⦃ p =>
      p.1 = none ∧ p.2 = self ⦄ := by
  simp only [core.slice.iter.IteratorChunksExact.next, h]
  simp
/-- Step spec for `core.slice.Slice.chunks_exact`: characterizes the resulting
    `ChunksExact` iterator's `chunks` field as the `.fst` of `List.toChunksExact`,
    modulo the `Slice` wrapper. (No alignment hypothesis needed; consumers can
    compose with prefix lemmas elsewhere.) -/
@[step]
theorem core.slice.Slice.chunks_exact.spec
    {T : Type} (s : Aeneas.Std.Slice T) (chunk_size : Usize)
    (h : 0 < chunk_size.val) :
    core.slice.Slice.chunks_exact s chunk_size
    ⦃ (ce : core.slice.iter.ChunksExact T) =>
      ce.chunks.map (fun c => c.val) =
        (List.toChunksExact chunk_size.val h s.val).1 ⦄ := by
  unfold core.slice.Slice.chunks_exact
  simp only [dif_pos h, WP.spec_ok]
  rw [List.map_map]
  show List.unattach (List.toChunksExact chunk_size.val h s.val).1.attach = _
  rw [List.unattach_attach]
end Aeneas.Std

/-! ## Range<U8> iterator (project-local `Step` instance)

For loops in FrodoKEM's `reverse_byte_bits` / `reverse_low_bits` helpers,
the `Step` instance for `U8`/`I32` is generated by Aeneas in
`Symcrust.Code.Funs` (under the `symcrust` namespace) and backed by the
concrete bodies in `Symcrust.Code.FunsExternal`. These curried `@[step]`
specs let `let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← …` destructure the
iterator pair inside `partial_fixpoint` loop bodies, exactly like the
`Usize` variants above. -/

namespace Aeneas.Std

open Result Error core.ops.range

private theorem range_next_U8 (range : core.ops.range.Range Std.U8) :
    core.iter.range.IteratorRange.next core.iter.range.StepU8 range
    ⦃ fun p =>
      if range.start.val < range.«end».val then
        p.1 = some range.start ∧
        p.2.start.val = range.start.val + 1 ∧
        p.2.«end» = range.«end»
      else
        p.1 = none ∧ p.2 = range ⦄ := by
  by_cases h : range.start.val < range.«end».val
  · apply WP.spec_mono (core.iter.range.IteratorRange.next_U8_some_spec range h)
    rintro ⟨o, iter1⟩ ⟨h1, h2, h3⟩
    simp only [h, ↓reduceIte]; exact ⟨h1, h2, h3⟩
  · apply WP.spec_mono (core.iter.range.IteratorRange.next_U8_none_spec range (by agrind))
    rintro ⟨o, iter1⟩ ⟨h1, h2⟩
    simp only [h, ↓reduceIte]; exact ⟨h1, h2⟩

@[step]
theorem IteratorRange_U8_next_some
    (range : core.ops.range.Range Std.U8)
    (h : range.start.val < range.«end».val) :
    core.iter.range.IteratorRange.next core.iter.range.StepU8 range
    ⦃ (o : Option Std.U8) (iter1 : core.ops.range.Range Std.U8) =>
      o = some range.start ∧
      iter1.start.val = range.start.val + 1 ∧
      iter1.«end» = range.«end» ⦄ := by
  apply WP.spec_mono (range_next_U8 range)
  rintro ⟨o, iter1⟩ h'
  simp only [WP.uncurry'_pair]
  simp [h] at h'
  exact h'

@[step]
theorem IteratorRange_U8_next_none
    (range : core.ops.range.Range Std.U8)
    (h : range.start.val ≥ range.«end».val) :
    core.iter.range.IteratorRange.next core.iter.range.StepU8 range
    ⦃ (o : Option Std.U8) (iter1 : core.ops.range.Range Std.U8) =>
      o = none ∧ iter1 = range ⦄ := by
  apply WP.spec_mono (range_next_U8 range)
  rintro ⟨o, iter1⟩ h'
  simp only [WP.uncurry'_pair]
  have hlt : ¬ range.start.val < range.«end».val := by agrind
  simp [hlt] at h'
  exact h'

/-! ## Range<I32> iterator -/

private theorem range_next_I32 (range : core.ops.range.Range Std.I32)
    (hend : range.«end».val ≤ Std.I32.max) :
    core.iter.range.IteratorRange.next core.iter.range.StepI32 range
    ⦃ fun p =>
      if range.start.val < range.«end».val then
        p.1 = some range.start ∧
        p.2.start.val = range.start.val + 1 ∧
        p.2.«end» = range.«end»
      else
        p.1 = none ∧ p.2 = range ⦄ := by
  simp only [core.iter.range.IteratorRange.next, core.iter.range.StepI32,
    core.iter.range.IScalarStep, core.cmp.PartialOrdI32,
    core.cmp.impls.PartialOrdI32.lt, core.clone.CloneI32,
    core.clone.impls.CloneI32.clone, liftFun1, liftFun2,
    core.iter.range.IScalarStep.forward_checked]
  by_cases h : range.start.val < range.«end».val
  · -- `start < end` ⇒ `lt` is `true`; `forward_checked start 1` succeeds because
    -- `start.val < end.val ≤ I32.max` gives `start.val + 1 ≤ I32.max`.
    have hfwd : range.start.val + (1#usize).val ≤ IScalar.max .I32 := by
      simp only [IScalar.max_IScalarTy_I32_eq]; scalar_tac
    simp only [bind_tc_ok]
    simp only [h, hfwd, WP.spec_ok, IScalar.ofInt_val_eq, decide_true, if_true,
      dif_pos, ↓reduceIte]
    simp only [bind_tc_ok]
    simp only [WP.spec_ok, IScalar.ofInt_val_eq]
    refine ⟨trivial, ?_, trivial⟩
    scalar_tac
  · simp [h, WP.spec_ok]

@[step]
theorem IteratorRange_I32_next_some
    (range : core.ops.range.Range Std.I32)
    (h : range.start.val < range.«end».val)
    (hend : range.«end».val ≤ Std.I32.max) :
    core.iter.range.IteratorRange.next core.iter.range.StepI32 range
    ⦃ (o : Option Std.I32) (iter1 : core.ops.range.Range Std.I32) =>
      o = some range.start ∧
      iter1.start.val = range.start.val + 1 ∧
      iter1.«end» = range.«end» ⦄ := by
  apply WP.spec_mono (range_next_I32 range hend)
  rintro ⟨o, iter1⟩ h'
  simp only [WP.uncurry'_pair]
  simp [h] at h'
  exact h'

@[step]
theorem IteratorRange_I32_next_none
    (range : core.ops.range.Range Std.I32)
    (h : range.start.val ≥ range.«end».val)
    (hend : range.«end».val ≤ Std.I32.max) :
    core.iter.range.IteratorRange.next core.iter.range.StepI32 range
    ⦃ (o : Option Std.I32) (iter1 : core.ops.range.Range Std.I32) =>
      o = none ∧ iter1 = range ⦄ := by
  apply WP.spec_mono (range_next_I32 range hend)
  rintro ⟨o, iter1⟩ h'
  simp only [WP.uncurry'_pair]
  have hlt : ¬ range.start.val < range.«end».val := by agrind
  simp [hlt] at h'
  exact h'

end Aeneas.Std

namespace symcrust

/-- `Lean.Loop.forIn` in `Id` unfolds one iteration.

`Lean.Loop.forIn` (what `while` / `repeat` desugar to) is defined via the
order-theoretic fixed point `whileM`, so it has no definitional equation
lemma. Its one-step unfolding is the upstream `Lean.Loop.forIn_eq_of_monadTail`
(for any `[LawfulMonad m] [Lean.Order.MonadTail m]`); here we specialise it to
`Id`, where the upstream `do`/`pure` right-hand side reduces definitionally to
the plain `match` — the shape the spec-side rejection-sampling bridges (MlKem
`SampleNTT`, MLDSA `RejNTTPoly` / `SampleInBall` / sign loops) rewrite with.

Equational lemma used with `rw`/`simp`, not `@[step]`. -/
theorem Loop_forIn_Id_unfold {β : Type} (b : β) (f : Unit → β → ForInStep β) :
    @Lean.Loop.forIn β Id _ Lean.Loop.mk b f =
    match f () b with
    | .done r => r
    | .yield r => @Lean.Loop.forIn β Id _ Lean.Loop.mk r f := by
  rw [Lean.Loop.forIn_eq_of_monadTail]; rfl

end symcrust
