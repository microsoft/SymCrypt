/-
  Stdlib.lean — `@[step]` specs for Aeneas-emitted Rust stdlib functions.

  Shared step database for stdlib surface that lacks built-in
  Aeneas step theorems: Array/Slice indexing on full `Range Usize`,
  `Error` `PartialEq`, const-time slice comparisons, integer multiple-of,
  etc.  Used by ML-KEM, ML-DSA, SHA3, SHA2, and AES proof closures.

  See sibling `Properties/Axioms/Stdlib.lean` for the opaque-axiom version
  (Aeneas-emitted FFI stubs for `as_ref`, `as_mut`, `Slice.fill`, etc.).
-/
import Symcrust.Code.Funs
import Symcrust.Properties.Iterators
import Symcrust.Properties.Axioms.Stdlib
import Symcrust.Properties.MLKEM.AeneasExtras

open Aeneas Aeneas.Std Result WP

namespace symcrust

/- Override get_elem_tactic so that a[i] auto-discharges bounds with agrind -/
scoped macro_rules
| `(tactic| get_elem_tactic) => `(tactic| agrind)

section ArrayRangeSpecs
/-! ## Array index/index_mut with Range Usize

  The Aeneas stdlib has step specs for `RangeTo` and `RangeFrom` on arrays,
  but NOT for full `Range Usize`. We prove them here by delegating to the
  existing slice-level specs. -/

/-- **Step spec for `Array.index_mut` with `Range Usize`**
    Mutable range slicing on arrays. Returns a slice and backward function. -/
@[step]
theorem Array.index_mut_SliceIndexRangeUsizeSlice
    {T : Type} {N : Usize} [Inhabited T]
    (a : Array T N) (r : core.ops.range.Range Usize)
    (h0 : r.start ≤ r.end) (h1 : r.end ≤ N) :
    core.array.Array.index_mut
      (core.ops.index.IndexMutSlice
        (core.slice.index.SliceIndexRangeUsizeSlice T))
      a r
    ⦃ (s : Slice T) (back : Slice T → Array T N) =>
      s.val = a.val.slice r.start r.end ∧
      s.length = r.end.val - r.start.val ∧
      ∀ s', (back s').val = a.val.setSlice! r.start.val s'.val ⦄ := by
  simp only [core.array.Array.index_mut, core.ops.index.IndexMutSlice,
    core.slice.index.Slice.index_mut]
  have hts : a.to_slice.length = N := by simp [Array.to_slice, Slice.length]
  simp only [core.slice.index.SliceIndexRangeUsizeSlice.index_mut,
    UScalar.le_equiv, Slice.length]
  split
  · simp [spec_ok, Array.from_slice, Array.to_slice]
    simp_lists; scalar_tac
  · scalar_tac

/-- **Step spec for `Array.index` with `Range Usize`**
    Immutable range slicing on arrays. -/
@[step]
theorem Array.index_SliceIndexRangeUsizeSlice.step.spec
    {T : Type} {N : Usize} [Inhabited T]
    (a : Array T N) (r : core.ops.range.Range Usize)
    (h0 : r.start ≤ r.end) (h1 : r.end ≤ N) :
    core.array.Array.index
      (core.ops.index.IndexSlice
        (core.slice.index.SliceIndexRangeUsizeSlice T))
      a r
    ⦃ (s : Slice T) =>
      s.val = a.val.slice r.start r.end ∧
      s.length = r.end.val - r.start.val ⦄ := by
  simp only [Std.Array.index_SliceIndexRangeUsizeSlice]
  have hts : a.to_slice.length = N := by simp [Array.to_slice, Slice.length]
  step
  simp_all [Array.to_slice]

end ArrayRangeSpecs

section CopyFromSliceSpec
/-! ## copy_from_slice with explicit postconditions

  The stdlib has `copy_from_slice.step.spec` with postcondition `s1 = s1'`.
  The proof files need explicit `length` and `val` postconditions. -/

/-- **Step spec for `copy_from_slice`**
    Copies source slice into destination. Postcondition: output has dst's length
    and src's values. -/
@[step]
theorem copy_from_slice.step.spec
    {T : Type} (copyInst : core.marker.Copy T)
    (dst src : Slice T)
    (hlen : dst.length = src.length) :
    core.slice.Slice.copy_from_slice copyInst dst src
    ⦃ (dst' : Slice T) =>
      dst'.length = dst.length ∧
      dst'.val = src.val ⦄ := by
  simp only [core.slice.Slice.copy_from_slice, Slice.len]
  simp only [show dst.length = src.length from hlen, ↓reduceIte]
  simp [spec_ok, Slice.length]

end CopyFromSliceSpec

section TryFromArrayCopySliceSpec
/-! ## TryFromArrayCopySlice.try_from

  Converts a Slice to a fixed-size Array. Succeeds when slice length = N. -/

/-- **Step spec for `TryFromArrayCopySlice.try_from`**
    When `s.length = N`, returns `Ok a` where `a.val = s.val`. -/
@[step]
theorem TryFromArrayCopySlice_try_from.step.spec
    {T : Type} (N : Usize) (copyInst : core.marker.Copy T) (s : Slice T)
    (h : s.length = N.val)
    (hclone : ∀ x : T, copyInst.cloneInst.clone x = ok x) :
    core.array.TryFromArrayCopySlice.try_from N copyInst s
    ⦃ (result : core.result.Result (Array T N)
        core.array.TryFromSliceError) =>
      ∃ a, result = core.result.Result.Ok a ∧ a.val = s.val ⦄ := by
  simp only [core.array.TryFromArrayCopySlice.try_from, h, ↓reduceDIte]
  have hmapM : List.mapM copyInst.cloneInst.clone s.val = ok s.val := by
    apply List.mapM_clone_eq
    intro x _
    exact hclone x
  -- After `simp only [↓reduceDIte]` the `List.mapM` has already been folded away
  -- (Lean 4.30 reduces it via the `hclone`-driven rewrite path), leaving the goal
  -- in `ok (Result.Ok ⟨s, _⟩) ⦃ … ⦄` form. (`hmapM` is kept for reference.)
  simp only [WP.spec_ok]; exact ⟨_, rfl, rfl⟩

end TryFromArrayCopySliceSpec

section TryFromSharedArraySliceSpec
/-! ## TryFromSharedArraySlice.try_from

  Converts a shared slice reference to a fixed-size array. Succeeds when
  `s.len = N`. Unlike `TryFromArrayCopySlice.try_from`, the body just
  re-views the slice's underlying list (no `clone` chain), so the spec
  has no clone-instance precondition. -/

/-- **Step spec for `TryFromSharedArraySlice.try_from`**

  When `s.len = N`, the result is `Ok a` with `a.val = s.val`.
  Symmetric to `TryFromArrayCopySlice_try_from.step.spec` above; both
  bridge to `core.array.TryFromSliceError`. -/
@[step]
theorem TryFromSharedArraySlice_try_from.step.spec
    {T : Type} (N : Usize) (s : Slice T)
    (h : s.length = N.val) :
    core.array.TryFromSharedArraySlice.try_from N s
    ⦃ (result : core.result.Result (Array T N)
        core.array.TryFromSliceError) =>
      ∃ a, result = core.result.Result.Ok a ∧ a.val = s.val ⦄ := by
  have hlen : s.len = N := by
    have : s.len.val = N.val := by simp [Std.Slice.len]; exact h
    apply Std.UScalar.eq_of_val_eq; exact this
  simp only [core.array.TryFromSharedArraySlice.try_from, hlen, ↓reduceDIte]
  simp only [WP.spec_ok]; exact ⟨_, rfl, rfl⟩

end TryFromSharedArraySliceSpec

section ResultUnwrapSpec
/-! ## Result.unwrap

  Extracts the Ok value from a Result. Panics on Err. -/

/-- **Step spec for `Result.unwrap`**
    When the input is `Ok v`, returns `v`. -/
@[step]
theorem Result_unwrap.step.spec
    {T E : Type} (inst : core.fmt.Debug E)
    (r : core.result.Result T E)
    (h : ∃ v, r = core.result.Result.Ok v) :
    core.result.Result.unwrap inst r
    ⦃ (result : T) =>
      r = core.result.Result.Ok result ⦄ := by
  match r, h with
  | .Ok v, ⟨_, rfl⟩ =>
    simp [core.result.Result.unwrap, spec_ok]

end ResultUnwrapSpec

section ResultTryBranchSpec
/-! ## `Try::branch` and `FromResidual::from_residual` for `Result`

  The `@[step]` specs are now provided by the Aeneas stdlib
  (`Aeneas/Std/Core/Convert.lean`:
  `core.result.Result.Insts.CoreOpsTry_traitTry.branch_{Ok,Err}.step_spec`,
  `…FromResidualResultInfallibleE.from_residual_Err.step_spec`), alongside the
  models themselves, and are found automatically by `step`.

  The three named lemmas below (NOT `@[step]`) are kept only as stable handles
  for dormant `step with …` call sites (e.g. `Properties/FrodoKEM/Decaps.lean`);
  they restate the Aeneas specs and carry self-contained proofs. -/

theorem Result_branch_Ok.step.spec
    {T E : Type} (v : T) :
    core.result.Result.Insts.CoreOpsTry.branch
      (T := T) (E := E) (.Ok v)
    ⦃ (cf : core.ops.control_flow.ControlFlow
              (core.result.Result core.convert.Infallible E) T) =>
        cf = .Continue v ⦄ := by
  exact (spec_ok _).mpr rfl

theorem Result_branch_Err.step.spec
    {T E : Type} (e : E) :
    core.result.Result.Insts.CoreOpsTry.branch
      (T := T) (E := E) (.Err e)
    ⦃ (cf : core.ops.control_flow.ControlFlow
              (core.result.Result core.convert.Infallible E) T) =>
        cf = .Break (.Err e) ⦄ := by
  exact (spec_ok _).mpr rfl

theorem Result_from_residual_Err.step.spec
    (T : Type) {E F : Type} (convertFromInst : core.convert.From F E)
    (e : E) (v : F) (hfrom : convertFromInst.from e = ok v) :
    core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
      T convertFromInst (.Err e)
    ⦃ (out : core.result.Result T F) => out = .Err v ⦄ := by
  show Aeneas.Std.WP.spec
    ((do let w ← convertFromInst.from e; ok ((.Err w : core.result.Result T F))) : Result _) _
  rw [hfrom]
  simp

end ResultTryBranchSpec

section IsMultipleOfSpec
/-! ## `core.num.Usize.is_multiple_of`

The model and its `@[step]` spec
(`core.num.Usize.is_multiple_of.step_spec`) now live in the Aeneas stdlib
(`Aeneas/Std/Scalar/CoreConvertNum.lean`).  No project-local spec needed. -/

end IsMultipleOfSpec

/-! ## `lift (alloc.vec.Vec.deref_mut v)`

`Vec.deref_mut` returns a pure pair `(slice, back)` that is wrapped in
`lift` (i.e., `ok`) at every call site. There is no `@[step]` for the
combined form in the Aeneas stdlib, forcing every proof to manually
`simp only [lift, alloc.vec.Vec.deref_mut]` before destructuring. This
step spec gives the curried postcondition so `step` / `step*` can
process `let (s, back) ← lift t.deref_mut` directly. -/

@[step]
theorem alloc.vec.Vec.deref_mut.step.spec {T : Type} (v : alloc.vec.Vec T) :
    lift (alloc.vec.Vec.deref_mut v)
    ⦃ (s : Slice T) (back : Slice T → alloc.vec.Vec T) =>
      s.val = v.val ∧
      s.length = v.length ∧
      (∀ s', (back s').val = s'.val) ∧
      (∀ s', (back s').length = s'.length) ⦄ := by
  simp [lift, alloc.vec.Vec.deref_mut, alloc.vec.Vec.length]

/-- `with_capacity` evaluates to the empty vector. -/
@[simp, step_simps, grind =, agrind =, scalar_tac_simps]
theorem alloc.vec.Vec.with_capacity_eq (T : Type) (n : Usize) :
    alloc.vec.Vec.with_capacity T n = alloc.vec.Vec.new T := by
  rfl

/-- Length of `with_capacity` is 0. -/
@[simp, grind =, agrind =, scalar_tac_simps]
theorem alloc.vec.Vec.with_capacity_length (T : Type) (n : Usize) :
    (alloc.vec.Vec.with_capacity T n).length = 0 := by
  rfl

/-- Val of `with_capacity` is empty. -/
@[simp, grind =, agrind =, scalar_tac_simps]
theorem alloc.vec.Vec.with_capacity_val (T : Type) (n : Usize) :
    (alloc.vec.Vec.with_capacity T n).val = [] := by
  rfl

/-- Coercion length of `with_capacity` is 0 (for `(↑v).length` form). -/
@[simp, grind =, agrind =, scalar_tac_simps]
theorem alloc.vec.Vec.with_capacity_val_length (T : Type) (n : Usize) :
    (↑(alloc.vec.Vec.with_capacity T n) : List T).length = 0 := by
  rfl

/-- `CloneU8.clone` is the identity on `U8`. -/
@[simp, step_simps]
theorem core.clone.CloneU8.clone_eq (x : U8) : core.clone.CloneU8.clone x = ok x := by
  simp [liftFun1, core.clone.impls.CloneU8.clone]

/-- **Spec for `alloc.vec.Vec.extend_from_slice`** — appends a clone of a slice. -/
@[step]
theorem alloc.vec.Vec.extend_from_slice.spec {T : Type}
    (cloneInst : core.clone.Clone T)
    (v : alloc.vec.Vec T) (s : Slice T)
    (h_clone : ∀ x, cloneInst.clone x = ok x)
    (h_len : v.length + s.length ≤ Usize.max) :
    alloc.vec.Vec.extend_from_slice cloneInst v s
    ⦃ (result : alloc.vec.Vec T) =>
      result.val = v.val ++ s.val ∧
      result.length = v.length + s.length ⦄ := by
  have h_mapM : List.mapM cloneInst.clone s.val = ok s.val := by
    suffices ∀ (l acc : List T), List.mapM.loop cloneInst.clone l acc = ok (acc.reverse ++ l) by
      simp [List.mapM, this s.val []]
    intro l; induction l with
    | nil => intro acc; simp [List.mapM.loop, pure]
    | cons hd tl ih =>
      intro acc
      simp [List.mapM.loop, h_clone, ih]
  have h_clone_ok : Slice.clone cloneInst.clone s = ok s := by
    unfold Slice.clone List.clone
    split <;> simp_all
  simp only [alloc.vec.Vec.extend_from_slice, h_len, ↓reduceDIte]
  split <;> simp_all [alloc.vec.Vec.length, Slice.length, List.length_append]

end symcrust


namespace symcrust


section ErrorPartialEqSpecs

/-- **Step spec for `Error PartialEq.eq`**
    Returns true iff the two errors are equal. -/
@[step]
theorem Error_PartialEq_eq.step.spec
    (a b : common.Error) :
    common.Error.Insts.CoreCmpPartialEqError.eq a b
    ⦃ (result : Bool) =>
      result = true ↔ a = b ⦄ := by
  unfold common.Error.Insts.CoreCmpPartialEqError.eq
  simp only [spec_ok, decide_eq_true_eq]
  constructor
  · intro h
    cases a <;> cases b <;> simp_all [common.Error.read_discriminant]
  · intro h
    subst h; rfl

private lemma eq_of_bne_false {α : Type*} [BEq α] [LawfulBEq α] {a b : α}
    (h : (a != b) = false) : a = b := by
  have : (a == b) = true := by
    cases hab : (a == b) with
    | true => rfl
    | false => simp [bne, hab] at h
  exact eq_of_beq this

end ErrorPartialEqSpecs



/- ============================================================
   Constant-time utility specs
   ============================================================ -/

section ConstTimeSpecs

/-! ### `try_from` (usize → u32) and `Result::is_ok`

The models and their `@[step]` specs now live in the Aeneas stdlib:
`core.result.Result.is_ok.step_spec` (`Aeneas/Std/Core/Convert.lean`) and
`core.convert.num.ptr_try_from_impls.TryFromU32Usize.try_from.step_spec`
(`Aeneas/Std/Scalar/CoreConvertNum.lean`).  No project-local specs needed. -/

/-- **Spec for `common::const_time_slices_equal`**
    Constant-time byte-equality comparison. Returns `true` iff
    the underlying lists are equal. Requires equal-length slices
    (the function panics on mismatched lengths). -/
@[step]
theorem const_time_slices_equal.spec
    (a b : Slice Std.U8)
    (h_len : a.length = b.length) :
    common.const_time_slices_equal a b
    ⦃ (result : Bool) =>
      result = true ↔ a.val = b.val ⦄ := by
  unfold common.const_time_slices_equal
  have h_lens : a.len = b.len := by
    simp only [Slice.len]; scalar_tac
  simp only [h_lens, massert_True, bind_tc_ok]
  exact common.const_time_slices_equal_impl.spec a b h_len

/-- **Spec for `common::const_time_array_copy`**
    Constant-time conditional copy: when `copy_size = N.val`, result = src;
    when `copy_size = 0`, result = dst.
    Requires `N ≤ I32.max` for the mask computation to be correct. -/
@[step]
theorem const_time_array_copy.spec
    {N : Std.Usize} (src dst : Array Std.U8 N)
    (copy_size : Std.U32)
    (hcopy : copy_size.val = 0 ∨ copy_size.val = N.val)
    (hN : N.val ≤ Std.I32.max) :
    common.const_time_array_copy src dst copy_size
    ⦃ (result : Array Std.U8 N) =>
      (copy_size.val = N.val → result = src) ∧
      (copy_size.val = 0 → result = dst) ⦄ := by
  unfold common.const_time_array_copy
  simp only [core.array.Array.as_slice, core.array.Array.as_mut_slice, bind_tc_ok]
  step
  have hNi : N ≤ i := by
    simp only [i_post, UScalar.le_equiv, UScalar.cast_val_eq]
    have h1 : (core.num.U32.MAX : U32).val = U32.rMax := rfl
    have h2 : U32.rMax ≤ Usize.max := by native_decide
    have h3 : core.num.U32.MAX.val % 2 ^ UScalarTy.Usize.numBits = core.num.U32.MAX.val := by
      apply Nat.mod_eq_of_lt; have := h1 ▸ h2; scalar_tac
    rw [h3, h1]; have : U32.rMax = 4294967295 := rfl; scalar_tac
  simp only [massert, hNi, ↑reduceIte, bind_tc_ok]
  step with common.const_time_slice_copy_impl.spec as ⟨s2, hs2_len, hs2_copy, hs2_nocopy⟩
  have hs2N : (↑s2 : List U8).length = (↑N : Nat) := by
    simp only [Slice.length] at hs2_len; agrind
  constructor
  · intro hcp; simp only [hs2N, ↑reduceDIte]
    exact Subtype.ext (hs2_copy (by simp only [Slice.length]; agrind))
  · intro hcp
    simp only [hs2N, ↑reduceDIte]
    exact Subtype.ext (hs2_nocopy hcp)

/-- **Spec for `common::const_time_arrays_equal`**
    Constant-time byte comparison. Returns true iff arrays are equal. -/
@[step]
theorem const_time_arrays_equal.spec
    {N : Std.Usize} (a b : Array Std.U8 N) :
    common.const_time_arrays_equal a b
    ⦃ (result : Bool) =>
      result = true ↔ a = b ⦄ := by
  unfold common.const_time_arrays_equal
  simp only [core.array.Array.as_slice, bind_tc_ok]
  step with common.const_time_slices_equal_impl.spec as ⟨res, hres⟩
  rw [hres]
  constructor
  · exact fun h => Subtype.ext h
  · exact fun h => h ▸ rfl

end ConstTimeSpecs

end symcrust
