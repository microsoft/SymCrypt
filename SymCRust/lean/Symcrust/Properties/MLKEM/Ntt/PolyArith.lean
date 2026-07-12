/-
  # Ntt/PolyArith.lean — Step-specs for in-place polynomial arithmetic.

  Covers the impl functions:

      mlkem.ntt.poly_element_add_in_place        -- pe_dst += pe_src2 mod q
      mlkem.ntt.poly_element_sub_from_in_place   -- pe_dst := pe_src1 - pe_dst mod q
      mlkem.ntt.poly_element_mul_r               -- pe_dst := pe_src · R   (Mont lift)
      mlkem.ntt.vector_mul_r                     -- componentwise mul_r over a slice

  Each function preserves `wfPoly` (every output < q) and ties the
  output `toPoly`/`toMontPoly` to a spec-level pointwise operation.

  ## Postcondition shape

  * Element-wise operations (`add`, `sub`) export both
    `wfPoly result ∧ toPoly result = toPoly src + toPoly dst` (and similar
    for `sub`).
  * `mul_r` exports
    `wfPoly result ∧ toPoly result = (toPoly src).map (R * ·)`,
    matching the impl's "scale each coeff by R via `mont_mul x RSQR` =
    `x · R² · Rinv = x · R`". This is the bridge between the impl's
    Montgomery storage and the spec's `Polynomial.scalarMul`.
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.Iterators
import Symcrust.Properties.MLKEM.Bridges.MontArith
import Symcrust.Properties.MLKEM.Ntt.ModArith

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust

namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

attribute [local step] UScalar.cast_inBounds_spec

private theorem Vector_get_ofFn_aux {n : Nat} {α : Type*} (f : Fin n → α) (i : Fin n) :
    (Vector.ofFn f).get i = f i := by
  obtain ⟨i, hi⟩ := i
  show (Vector.ofFn f)[i] = _
  rw [Vector.getElem_ofFn]

set_option maxHeartbeats 1000000

/-! ## `poly_element_add_in_place`

Impl iterates `i ∈ [0, 256)`, sets `pe_dst[i] := mod_add pe_dst[i]
pe_src2[i]`. Both inputs assumed `< q` per element; output `< q`. -/

/-- **Loop spec** for `poly_element_add_in_place_loop`.

Invariant: at iteration `i`, indices `[0, i)` of `pe_dst` hold the
final (added) values; `[i, 256)` hold the original values.

Informal proof. Template: Range-loop induction per `proof-patterns` §1.
Symmetric to `poly_element_ntt_layer_generic_loop0_loop0.spec` but with
a single-slot read-modify-write per iteration (no twiddle, no
butterfly).  Unfold `mlkem.ntt.poly_element_add_in_place_loop`; the body
first calls `IteratorRange.next`, returns `ok pe_dst` on `none`, and in
the `some i` branch reads `pe_dst[i]` then `pe_src2[i]` (both widened
U16→U32 via `IntoFrom`), calls `mod_add` to get the sum in `< q`,
casts the result back to U16, writes it back, and recurses on `iter1`.

1. `step with IteratorRange_next_some` / `IteratorRange_next_none` —
   split the range iterator (`hsome : o = some iter.start`,
   `iter1.start = iter.start + 1`, `iter1.end = iter.end`).
2. In the `some` branch, step `Array.index_usize.spec` (pe_dst[i]),
   then `core.convert.IntoFrom.into` with `FromU32U16`.
3. Step `Array.index_usize.spec` (pe_src2[i]), then
   `core.convert.IntoFrom.into`.
4. Step `mlkem.ntt.mod_add.spec`; preconditions are `pe_dst[i].val < q`
   and `pe_src2[i].val < q`, supplied by `h_dst` / `h_src` at
   `i = iter.start.val`.  The post gives `i5.val < q` and
   `u32ToZq i5 = u32ToZq i2 + u32ToZq i4`.
5. Step `UScalar.cast .U16` (the `lift` succeeds since `i5.val < q < 2^16`),
   then `Array.update.spec` for the slot write.
6. Step the recursive call with this theorem.  The IH gives the loop
   post at `iter1.start = iter.start + 1`; combined with the
   single-slot equation from step 4 it rebuilds the post at `iter.start`.

Case analysis: `none` case closes immediately — `iter.start.val ≥
iter.«end».val = 256`, so the conditional in the post is `j.val <
iter.start.val` for every `j : Fin 256`; the post collapses to
`toPoly pe_dst = Vector.ofFn (fun j => toPoly pe_dst |>.get j)` which
is `rfl` after `Vector.get_ofFn`.  `some` case: peel one slot from the
`Vector.ofFn`; for `j = iter.start.val` use step 4 (with
`tbd_u16ToZq_cast_u32_lt_q` to bridge the U16-cast write back to the
Zq equation); for `j ≠ iter.start.val`, either `j < iter.start.val`
(unchanged by the write, supplied by the IH at `iter1.start`) or
`j > iter.start.val` (frame: read returns original `pe_dst[j]`).

Close with `split_conjs`; `agrind` handles `wfPoly` threading
(`r.val[j].val < q` from `mod_add`'s `< q` for the written slot,
preserved for the rest), iterator arithmetic, and the `Vector.ofFn`
index-by-index rewrite.  For the Zq equation use
`simp [Vector.get_ofFn, mlkem.ntt.mod_add.spec post, h_dst, h_src]`
then `agrind`. -/
@[step]
theorem mlkem.ntt.poly_element_add_in_place_loop.spec
    (iter : core.ops.range.Range Usize)
    (pe_src2 pe_dst : PolyElement)
    (h_src : wfPoly pe_src2) (h_dst : wfPoly pe_dst)
    (h_start : iter.start.val ≤ 256) (h_end : iter.«end».val = 256) :
    mlkem.ntt.poly_element_add_in_place_loop iter pe_src2 pe_dst
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r = Vector.ofFn fun (j : Fin 256) =>
            if j.val < iter.start.val then toPoly pe_dst |>.get j
            else (toPoly pe_dst).get j + (toPoly pe_src2).get j ⦄ := by
  unfold mlkem.ntt.poly_element_add_in_place_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · -- Some branch: iterator yields `some iter.start`
    let* ⟨ o, iter1, ho, hstart', hend' ⟩ ← IteratorRange_next_Usize_some
    rw [ho]
    simp only
    have hi_lt : iter.start.val < 256 := by scalar_tac
    -- Body: Array.index_usize on pe_dst → i1
    let* ⟨ i1, hi1 ⟩ ← Array.index_usize_spec
    have hi1_lt_q : i1.val < q := by grind [wfPoly]
    -- The `core.convert.IntoFrom.into` step reduces silently via step_simps.
    -- The next concrete `@[step]` spec is the second Array.index_usize on pe_src2.
    let* ⟨ i3, hi3 ⟩ ← Array.index_usize_spec
    have hi3_lt_q : i3.val < q := by grind [wfPoly]
    -- Provide bounds for mod_add preconditions
    have hi2_lt_q : (core.convert.num.FromU32U16.from i1).val < q := by simp; exact hi1_lt_q
    have hi4_lt_q : (core.convert.num.FromU32U16.from i3).val < q := by simp; exact hi3_lt_q
    -- mod_add: result = i5 with i5.val < q ∧ u32ToZq i5 = u32ToZq i2 + u32ToZq i4
    let* ⟨ i5, hi5_lt, hi5_eq ⟩ ← mlkem.ntt.mod_add.spec
    -- Cast U32 → U16 (succeeds since i5.val < q < 2^16)
    have hi5_le_u16max : i5.val ≤ UScalar.max .U16 := by
      simp only [UScalar.max_UScalarTy_U16_eq, U16.max_eq]
      have h1 : i5.val < q := hi5_lt
      have h2 : (q : Nat) = 3329 := rfl
      rw [h2] at h1
      scalar_tac
    let* ⟨ i6, hi6 ⟩ ← UScalar.cast_inBounds_spec
    -- Array.update pe_dst iter.start i6 → a with a = pe_dst.set iter.start i6
    let* ⟨ a, ha_eq ⟩ ← Array.update_spec
    -- Compute the new wfPoly
    have hi6_val : i6.val = i5.val := hi6
    have hi6_lt_q : i6.val < q := by rw [hi6_val]; exact hi5_lt
    have h_dst_new : wfPoly a := by
      intro j hj
      rw [ha_eq]
      simp only [Array.set_val_eq]
      by_cases hji : j = iter.start.val
      · subst hji
        rw [List.getElem_set_self]
        exact hi6_lt_q
      · rw [List.getElem_set_ne (Ne.symm hji)]
        exact h_dst j hj
    -- IH preconditions
    have h_start_new : iter1.start.val ≤ 256 := by rw [hstart']; scalar_tac
    have h_end_new : iter1.«end».val = 256 := by rw [hend']; exact h_end
    -- Recursive call
    apply WP.spec_mono
      (mlkem.ntt.poly_element_add_in_place_loop.spec iter1 pe_src2 a
        h_src h_dst_new h_start_new h_end_new)
    rintro r ⟨ hwf_r, h_eq_r ⟩
    refine ⟨ hwf_r, ?_ ⟩
    rw [h_eq_r]
    apply Vector.ext
    intro j hj
    rw [Vector.getElem_ofFn, Vector.getElem_ofFn]
    show (if ↑(⟨j, hj⟩ : Fin 256) < iter1.start.val then _ else _) = _
    rw [hstart']
    by_cases hj_lt_new : j < iter.start.val + 1
    · rw [if_pos hj_lt_new]
      by_cases hj_eq : j = iter.start.val
      · -- j = iter.start.val: freshly-written slot
        subst hj_eq
        rw [if_neg (Nat.lt_irrefl _)]
        unfold toPoly
        simp only [Vector_get_ofFn_aux]
        rw [ha_eq]
        simp only [Array.set_val_eq]
        rw [List.getElem_set_self]
        unfold u16ToZq
        rw [hi6_val]
        change (u32ToZq i5) = _
        rw [hi5_eq]
        simp only [u32ToZq, core.convert.num.FromU32U16.from_val_eq]
        rw [hi1, hi3]
      · have hj_lt : j < iter.start.val := by scalar_tac
        rw [if_pos hj_lt]
        unfold toPoly
        simp only [Vector_get_ofFn_aux]
        rw [ha_eq]
        simp only [Array.set_val_eq]
        rw [List.getElem_set_ne (Ne.symm hj_eq)]
    · push Not at hj_lt_new
      rw [if_neg (by scalar_tac : ¬ j < iter.start.val + 1)]
      rw [if_neg (by scalar_tac : ¬ j < iter.start.val)]
      unfold toPoly
      simp only [Vector_get_ofFn_aux]
      rw [ha_eq]
      simp only [Array.set_val_eq]
      rw [List.getElem_set_ne (by scalar_tac : iter.start.val ≠ j)]
  · -- None branch: iterator empty, return pe_dst untouched
    have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    have h_start_eq : iter.start.val = 256 := by scalar_tac
    let* ⟨ o, iter1, hnone, _ ⟩ ← IteratorRange_next_Usize_none
    rw [hnone]
    simp only [WP.spec_ok]
    refine ⟨ h_dst, ?_ ⟩
    rw [h_start_eq]
    -- Since iter.start.val = 256 and all j < 256, the `if` always picks `then`
    conv_rhs =>
      rw [show (fun (j : Fin 256) =>
              if j.val < 256 then Vector.get (toPoly pe_dst) j
              else Vector.get (toPoly pe_dst) j + Vector.get (toPoly pe_src2) j) =
            (fun (j : Fin 256) => (toPoly pe_dst)[j.val]) from
          funext (fun j => if_pos j.isLt)]
    exact Vector.ofFn_getElem.symm
termination_by iter.«end».val - iter.start.val
decreasing_by scalar_decr_tac

/-- **Wrapper spec** for `poly_element_add_in_place`.

Postcondition: `toPoly pe_dst' = toPoly pe_dst + toPoly pe_src2`
(componentwise add in `Zq`), and `wfPoly pe_dst'`.

Informal proof. Template: leaf wrapper that delegates to the `_loop`
spec at `iter.start = 0`.  Analogue: `vector_ntt.spec`'s second half
(after the row-count guards).  Unfold
`mlkem.ntt.poly_element_add_in_place`; the body is a single call
`poly_element_add_in_place_loop { start := 0, end :=
MLWE_POLYNOMIAL_COEFFICIENTS } pe_src2 pe_dst`.

1. Step with `mlkem.ntt.poly_element_add_in_place_loop.spec`,
   instantiating `iter.start = 0` and `iter.«end» = 256` (via
   `MLWE_POLYNOMIAL_COEFFICIENTS_val`).  Preconditions: `h_src`,
   `h_dst` are passed through; `h_start : 0 ≤ 256` and
   `h_end : 256 = 256` are `decide` / `agrind`.

The loop post becomes
`toPoly r = Vector.ofFn (fun j => if j.val < 0 then … else
(toPoly pe_dst).get j + (toPoly pe_src2).get j)`; the `if`-branch is
vacuous so the conditional collapses to the `else`-branch.

There is no wrapper-level algorithmic case split.  Close with
`split_conjs`; `agrind` rewrites the `Vector.ofFn` (the `j.val < 0`
guard is `False`) and discharges `wfPoly r`. -/
@[step]
theorem mlkem.ntt.poly_element_add_in_place.spec
    (pe_src2 pe_dst : PolyElement)
    (h_src : wfPoly pe_src2) (h_dst : wfPoly pe_dst) :
    mlkem.ntt.poly_element_add_in_place pe_src2 pe_dst
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r = Vector.ofFn fun (j : Fin 256) =>
            (toPoly pe_dst).get j + (toPoly pe_src2).get j ⦄ := by
  unfold mlkem.ntt.poly_element_add_in_place
  step*

/-! ## `poly_element_sub_from_in_place`

Impl iterates `i ∈ [0, 256)`, sets `pe_dst[i] := mod_sub pe_src1[i] pe_dst[i]`
(note: spec is `dst := src - dst`, NOT `dst := dst - src`). -/

/-- **Loop spec** for `poly_element_sub_from_in_place_loop`.

Invariant: at iteration `i`, indices `[0, i)` of `pe_dst` hold
`pe_src1[j] - pe_dst_orig[j]`; `[i, 256)` hold the original `pe_dst`.

Note the read order: the body reads `pe_src1[i]` *first*, then
`pe_dst[i]`, and calls `mod_sub i2 i4`, i.e. computes `src1 - dst`
(NOT `dst - src`).  This is what makes the operation
`dst ← src1 - dst`.

Informal proof. Template: Range-loop induction per `proof-patterns` §1.
Same skeleton as `poly_element_add_in_place_loop.spec`, with
`mod_sub.spec` in place of `mod_add.spec`.  Unfold
`mlkem.ntt.poly_element_sub_from_in_place_loop`; the body calls
`IteratorRange.next`, returns `ok pe_dst` on `none`, and on `some i`
reads `pe_src1[i]` (widen U16→U32), `pe_dst[i]` (widen U16→U32),
applies `mod_sub`, casts back to U16, writes the slot, and recurses.

1. `step with IteratorRange_next_some` / `IteratorRange_next_none`.
2. `Array.index_usize.spec` (pe_src1[i]) + `IntoFrom.into`.
3. `Array.index_usize.spec` (pe_dst[i]) + `IntoFrom.into`.
4. `mlkem.ntt.mod_sub.spec`: preconditions `< q` from `h_src` / `h_dst`
   at `iter.start.val`; post `i5.val < q ∧ u32ToZq i5 = u32ToZq i2 -
   u32ToZq i4`.
5. `UScalar.cast .U16`, then `Array.update.spec`.
6. Step the recursive call (this theorem).  IH rebuilds the post at
   `iter1.start.val = iter.start.val + 1`.

Case analysis: `none` collapses via the conditional (every `j`
satisfies `j.val < 256 = iter.start.val`); the post becomes
`toPoly pe_dst = Vector.ofFn fun j => (toPoly pe_dst).get j` — `rfl`
after `Vector.get_ofFn`.  `some` peels slot `iter.start.val` from the
`Vector.ofFn`; the written slot uses step 4 (plus
`tbd_u16ToZq_cast_u32_lt_q`); the frame uses IH or unchanged-read.

Close with `split_conjs`; `agrind` for `wfPoly` threading and the
per-index `Vector.ofFn` rewrite; `simp [mod_sub post]; agrind` for the
Zq equation at the fresh slot. -/
@[step]
theorem mlkem.ntt.poly_element_sub_from_in_place_loop.spec
    (iter : core.ops.range.Range Usize)
    (pe_src1 pe_dst : PolyElement)
    (h_src : wfPoly pe_src1) (h_dst : wfPoly pe_dst)
    (h_start : iter.start.val ≤ 256) (h_end : iter.«end».val = 256) :
    mlkem.ntt.poly_element_sub_from_in_place_loop iter pe_src1 pe_dst
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r = Vector.ofFn fun (j : Fin 256) =>
            if j.val < iter.start.val then toPoly pe_dst |>.get j
            else (toPoly pe_src1).get j - (toPoly pe_dst).get j ⦄ := by
  unfold mlkem.ntt.poly_element_sub_from_in_place_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, ho, hstart', hend' ⟩ ← IteratorRange_next_Usize_some
    rw [ho]
    simp only
    have hi_lt : iter.start.val < 256 := by scalar_tac
    let* ⟨ i1, hi1 ⟩ ← Array.index_usize_spec
    have hi1_lt_q : i1.val < q := by grind [wfPoly]
    let* ⟨ i3, hi3 ⟩ ← Array.index_usize_spec
    have hi3_lt_q : i3.val < q := by grind [wfPoly]
    have hi2_lt_q : (core.convert.num.FromU32U16.from i1).val < q := by simp; exact hi1_lt_q
    have hi4_lt_q : (core.convert.num.FromU32U16.from i3).val < q := by simp; exact hi3_lt_q
    let* ⟨ i5, hi5_lt, hi5_eq ⟩ ← mlkem.ntt.mod_sub.spec
    have hi5_le_u16max : i5.val ≤ UScalar.max .U16 := by
      simp only [UScalar.max_UScalarTy_U16_eq, U16.max_eq]
      have h1 : i5.val < q := hi5_lt
      have h2 : (q : Nat) = 3329 := rfl
      rw [h2] at h1
      scalar_tac
    let* ⟨ i6, hi6 ⟩ ← UScalar.cast_inBounds_spec
    let* ⟨ a, ha_eq ⟩ ← Array.update_spec
    have hi6_val : i6.val = i5.val := hi6
    have hi6_lt_q : i6.val < q := by rw [hi6_val]; exact hi5_lt
    have h_dst_new : wfPoly a := by
      intro j hj
      rw [ha_eq]
      simp only [Array.set_val_eq]
      by_cases hji : j = iter.start.val
      · subst hji
        rw [List.getElem_set_self]
        exact hi6_lt_q
      · rw [List.getElem_set_ne (Ne.symm hji)]
        exact h_dst j hj
    have h_start_new : iter1.start.val ≤ 256 := by rw [hstart']; scalar_tac
    have h_end_new : iter1.«end».val = 256 := by rw [hend']; exact h_end
    apply WP.spec_mono
      (mlkem.ntt.poly_element_sub_from_in_place_loop.spec iter1 pe_src1 a
        h_src h_dst_new h_start_new h_end_new)
    rintro r ⟨ hwf_r, h_eq_r ⟩
    refine ⟨ hwf_r, ?_ ⟩
    rw [h_eq_r]
    apply Vector.ext
    intro j hj
    rw [Vector.getElem_ofFn, Vector.getElem_ofFn]
    show (if ↑(⟨j, hj⟩ : Fin 256) < iter1.start.val then _ else _) = _
    rw [hstart']
    by_cases hj_lt_new : j < iter.start.val + 1
    · rw [if_pos hj_lt_new]
      by_cases hj_eq : j = iter.start.val
      · subst hj_eq
        rw [if_neg (Nat.lt_irrefl _)]
        unfold toPoly
        simp only [Vector_get_ofFn_aux]
        rw [ha_eq]
        simp only [Array.set_val_eq]
        rw [List.getElem_set_self]
        unfold u16ToZq
        rw [hi6_val]
        change (u32ToZq i5) = _
        rw [hi5_eq]
        simp only [u32ToZq, core.convert.num.FromU32U16.from_val_eq]
        rw [hi1, hi3]
      · have hj_lt : j < iter.start.val := by scalar_tac
        rw [if_pos hj_lt]
        unfold toPoly
        simp only [Vector_get_ofFn_aux]
        rw [ha_eq]
        simp only [Array.set_val_eq]
        rw [List.getElem_set_ne (Ne.symm hj_eq)]
    · push Not at hj_lt_new
      rw [if_neg (by scalar_tac : ¬ j < iter.start.val + 1)]
      rw [if_neg (by scalar_tac : ¬ j < iter.start.val)]
      unfold toPoly
      simp only [Vector_get_ofFn_aux]
      rw [ha_eq]
      simp only [Array.set_val_eq]
      rw [List.getElem_set_ne (by scalar_tac : iter.start.val ≠ j)]
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    have h_start_eq : iter.start.val = 256 := by scalar_tac
    let* ⟨ o, iter1, hnone, _ ⟩ ← IteratorRange_next_Usize_none
    rw [hnone]
    simp only [WP.spec_ok]
    refine ⟨ h_dst, ?_ ⟩
    rw [h_start_eq]
    conv_rhs =>
      rw [show (fun (j : Fin 256) =>
              if j.val < 256 then Vector.get (toPoly pe_dst) j
              else Vector.get (toPoly pe_src1) j - Vector.get (toPoly pe_dst) j) =
            (fun (j : Fin 256) => (toPoly pe_dst)[j.val]) from
          funext (fun j => if_pos j.isLt)]
    exact Vector.ofFn_getElem.symm
termination_by iter.«end».val - iter.start.val
decreasing_by scalar_decr_tac

/-- **Wrapper spec** for `poly_element_sub_from_in_place`.

Postcondition: `toPoly pe_dst' = Vector.ofFn (fun j =>
(toPoly pe_src1).get j - (toPoly pe_dst).get j)`, i.e. componentwise
`src1 - dst` in `Zq`, and `wfPoly pe_dst'`.

Informal proof. Template: leaf wrapper around `_loop` at
`iter.start = 0`.  Analogue: `poly_element_add_in_place.spec`.  Unfold
`mlkem.ntt.poly_element_sub_from_in_place`; the body is a single call
to the loop with `{ start := 0, end := MLWE_POLYNOMIAL_COEFFICIENTS }`.

1. Step with `mlkem.ntt.poly_element_sub_from_in_place_loop.spec` at
   `iter.start = 0`, `iter.«end» = 256`.  `h_src`, `h_dst` pass
   through; `h_start`, `h_end` discharged by
   `MLWE_POLYNOMIAL_COEFFICIENTS_val` + `agrind`.

The loop post's conditional `if j.val < 0 then … else (toPoly
pe_src1).get j - (toPoly pe_dst).get j` collapses to the `else`-branch.

No wrapper-level case split.  Close with `split_conjs`; `agrind` to
rewrite the `Vector.ofFn` and discharge `wfPoly r`. -/
@[step]
theorem mlkem.ntt.poly_element_sub_from_in_place.spec
    (pe_src1 pe_dst : PolyElement)
    (h_src : wfPoly pe_src1) (h_dst : wfPoly pe_dst) :
    mlkem.ntt.poly_element_sub_from_in_place pe_src1 pe_dst
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r = Vector.ofFn fun (j : Fin 256) =>
            (toPoly pe_src1).get j - (toPoly pe_dst).get j ⦄ := by
  unfold mlkem.ntt.poly_element_sub_from_in_place
  step*

/-! ## `poly_element_mul_r`

Impl iterates `i ∈ [0, 256)`, sets
  `pe_dst[i] := mont_mul pe_src[i] RSQR RSQR_TIMES_NEG_Q_INV_MOD_R`.

By `mont_mul.spec` (Ntt/ModArith.lean) and M3 from `Bridges/MontArith.lean`
(`mont_mul_RSQR_zq`: `mont_mul x RSQR _ = R · x` in Zq), this scales
every coefficient by `R`. -/

/-- **Loop spec** for `poly_element_mul_r_loop`.

Invariant: at iteration `i`, indices `[0, i)` of `pe_dst` hold
`R * pe_src[j]` (in Zq); `[i, 256)` hold the original `pe_dst`.

Informal proof. Template: Range-loop induction per `proof-patterns` §1.
Same skeleton as the add/sub loops, with `mont_mul.spec` plus bridge
**M3** (`mont_mul_RSQR`) supplying the per-slot Zq equation.  Unfold
`mlkem.ntt.poly_element_mul_r_loop`; the body calls
`IteratorRange.next`, returns `ok pe_dst` on `none`, and on `some i`
reads `pe_src[i]` (widen U16→U32), calls
`mont_mul i2 RSQR RSQR_TIMES_NEG_Q_INV_MOD_R`, casts back to U16,
writes the slot, and recurses.

1. `step with IteratorRange_next_some` / `IteratorRange_next_none`.
2. `Array.index_usize.spec` (pe_src[i]) + `IntoFrom.into`.
3. `mlkem.ntt.mont_mul.spec`: preconditions
   - `ha : i2.val < q` from `h_src` at `iter.start.val`,
   - `hb : RSQR.val < q` from `ntt_RSQR_val` (1353 < 3329),
   - `hbm : RSQR_TIMES_NEG_Q_INV_MOD_R.val ≤ 65535` and `hbm_eq` from
     `ntt_RSQR_TIMES_NEG_Q_INV_MOD_R_val` + `decide` (or `agrind`).
   Post: `i3.val < q ∧ u32ToZq i3 = u32ToZq i2 * u32ToZq RSQR * Rinv`.
4. Rewrite the post with bridge **M3** `mont_mul_RSQR`:
   `u32ToZq RSQR * a * Rinv = R * a`, yielding
   `u32ToZq i3 = R * u32ToZq i2`.
5. `UScalar.cast .U16` (lift succeeds, `i3.val < q < 2^16`), then
   `Array.update.spec`.
6. Step the recursive call (this theorem).  IH rebuilds the post at
   `iter1.start = iter.start + 1`.

Case analysis: `none` collapses the `Vector.ofFn` conditional to
`(toPoly pe_dst).get j` for all `j` (since `iter.start.val = 256`);
post is `rfl` after `Vector.get_ofFn`.  `some`: peel slot
`iter.start.val`; the written slot uses step 4 (with
`tbd_u16ToZq_cast_u32_lt_q`); the frame uses IH or unchanged-read.

Close with `split_conjs`; `agrind` for `wfPoly`, iterator arithmetic,
and the per-index `Vector.ofFn` rewrite; `simp [mont_mul_RSQR,
mlkem.ntt.mont_mul.spec post]; agrind` for the Zq equation at the
fresh slot. -/
@[step]
theorem mlkem.ntt.poly_element_mul_r_loop.spec
    (iter : core.ops.range.Range Usize)
    (pe_src pe_dst : PolyElement)
    (h_src : wfPoly pe_src) (h_dst : wfPoly pe_dst)
    (h_start : iter.start.val ≤ 256) (h_end : iter.«end».val = 256) :
    mlkem.ntt.poly_element_mul_r_loop iter pe_src pe_dst
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r = Vector.ofFn fun (j : Fin 256) =>
            if j.val < iter.start.val then toPoly pe_dst |>.get j
            else R * (toPoly pe_src).get j ⦄ := by
  unfold mlkem.ntt.poly_element_mul_r_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, ho, hstart', hend' ⟩ ← IteratorRange_next_Usize_some
    rw [ho]
    simp only
    have hi_lt : iter.start.val < 256 := by scalar_tac
    let* ⟨ i1, hi1 ⟩ ← Array.index_usize_spec
    have hi1_lt_q : i1.val < q := by
      rw [hi1]
      exact h_src iter.start.val hi_lt
    have hi2_lt_q : (core.convert.num.FromU32U16.from i1).val < q := by simp; exact hi1_lt_q
    have h_RSQR_lt_q : mlkem.ntt.RSQR.val < q := by rw [ntt_RSQR_val]; decide
    have h_RSQR_TIMES_le : mlkem.ntt.RSQR_TIMES_NEG_Q_INV_MOD_R.val ≤ 65535 := by
      rw [ntt_RSQR_TIMES_NEG_Q_INV_MOD_R_val]; decide
    have h_RSQR_TIMES_eq :
        mlkem.ntt.RSQR_TIMES_NEG_Q_INV_MOD_R.val =
          (mlkem.ntt.RSQR.val * 3327) % 65536 := by
      rw [ntt_RSQR_val, ntt_RSQR_TIMES_NEG_Q_INV_MOD_R_val]
    let* ⟨ i3, hi3_lt, hi3_eq ⟩ ← mlkem.ntt.mont_mul.spec
    have hi3_le_u16max : i3.val ≤ UScalar.max .U16 := by
      simp only [UScalar.max_UScalarTy_U16_eq, U16.max_eq]
      have h1 : i3.val < q := hi3_lt
      have h2 : (q : Nat) = 3329 := rfl
      rw [h2] at h1
      scalar_tac
    let* ⟨ i4, hi4 ⟩ ← UScalar.cast_inBounds_spec
    let* ⟨ a, ha_eq ⟩ ← Array.update_spec
    have hi4_val : i4.val = i3.val := hi4
    have hi4_lt_q : i4.val < q := by rw [hi4_val]; exact hi3_lt
    have h_dst_new : wfPoly a := by
      intro j hj
      rw [ha_eq]
      simp only [Array.set_val_eq]
      by_cases hji : j = iter.start.val
      · subst hji
        rw [List.getElem_set_self]
        exact hi4_lt_q
      · rw [List.getElem_set_ne (Ne.symm hji)]
        exact h_dst j hj
    have h_start_new : iter1.start.val ≤ 256 := by rw [hstart']; scalar_tac
    have h_end_new : iter1.«end».val = 256 := by rw [hend']; exact h_end
    apply WP.spec_mono
      (mlkem.ntt.poly_element_mul_r_loop.spec iter1 pe_src a
        h_src h_dst_new h_start_new h_end_new)
    rintro r ⟨ hwf_r, h_eq_r ⟩
    refine ⟨ hwf_r, ?_ ⟩
    rw [h_eq_r]
    apply Vector.ext
    intro j hj
    rw [Vector.getElem_ofFn, Vector.getElem_ofFn]
    show (if ↑(⟨j, hj⟩ : Fin 256) < iter1.start.val then _ else _) = _
    rw [hstart']
    by_cases hj_lt_new : j < iter.start.val + 1
    · rw [if_pos hj_lt_new]
      by_cases hj_eq : j = iter.start.val
      · subst hj_eq
        rw [if_neg (Nat.lt_irrefl _)]
        unfold toPoly
        simp only [Vector_get_ofFn_aux]
        rw [ha_eq]
        simp only [Array.set_val_eq]
        rw [List.getElem_set_self]
        unfold u16ToZq
        rw [hi4_val]
        change (u32ToZq i3) = _
        rw [hi3_eq]
        rw [show u32ToZq (core.convert.num.FromU32U16.from i1) * u32ToZq mlkem.ntt.RSQR * Rinv
              = u32ToZq mlkem.ntt.RSQR * u32ToZq (core.convert.num.FromU32U16.from i1) * Rinv
            from by ring]
        rw [mont_mul_RSQR]
        simp only [u32ToZq, core.convert.num.FromU32U16.from_val_eq]
        rw [hi1]
      · have hj_lt : j < iter.start.val := by scalar_tac
        rw [if_pos hj_lt]
        unfold toPoly
        simp only [Vector_get_ofFn_aux]
        rw [ha_eq]
        simp only [Array.set_val_eq]
        rw [List.getElem_set_ne (Ne.symm hj_eq)]
    · push Not at hj_lt_new
      rw [if_neg (by scalar_tac : ¬ j < iter.start.val + 1)]
      rw [if_neg (by scalar_tac : ¬ j < iter.start.val)]
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    have h_start_eq : iter.start.val = 256 := by scalar_tac
    let* ⟨ o, iter1, hnone, _ ⟩ ← IteratorRange_next_Usize_none
    rw [hnone]
    simp only [WP.spec_ok]
    refine ⟨ h_dst, ?_ ⟩
    rw [h_start_eq]
    conv_rhs =>
      rw [show (fun (j : Fin 256) =>
              if j.val < 256 then Vector.get (toPoly pe_dst) j
              else R * Vector.get (toPoly pe_src) j) =
            (fun (j : Fin 256) => (toPoly pe_dst)[j.val]) from
          funext (fun j => if_pos j.isLt)]
    exact Vector.ofFn_getElem.symm
termination_by iter.«end».val - iter.start.val
decreasing_by scalar_decr_tac

/-- **Wrapper spec** for `poly_element_mul_r`.

Top-level postcondition: `toPoly pe_dst' = (toPoly pe_src).map (R * ·)`.

This is the bridge that turns a standard-form polynomial into a
Montgomery-form polynomial *as a value*: same underlying buffer
representation as `toPoly pe_dst'`, but each spec coefficient is
multiplied by `R`.

Equivalently: `toMontPoly pe_dst' = toPoly pe_src`, since
`toMontPoly a = (toPoly a).map (· * Rinv)` and `R * Rinv = 1`.

Informal proof. Template: leaf wrapper around `_loop` at
`iter.start = 0`.  Analogue: `poly_element_add_in_place.spec`.  Unfold
`mlkem.ntt.poly_element_mul_r`; the body is a single call
`poly_element_mul_r_loop { start := 0, end :=
MLWE_POLYNOMIAL_COEFFICIENTS } pe_src pe_dst`.

1. Step with `mlkem.ntt.poly_element_mul_r_loop.spec` at
   `iter.start = 0`, `iter.«end» = 256` (via
   `MLWE_POLYNOMIAL_COEFFICIENTS_val`).  `h_src` and `h_dst` pass
   through; `h_start`, `h_end` are `decide` / `agrind`.

The loop post's `if j.val < 0` branch is vacuous, so it collapses to
`R * (toPoly pe_src).get j`.  Rewrite the `Vector.ofFn` as
`(toPoly pe_src).map (R * ·)` via `Vector.map_ofFn` (or `Vector.ext`
with `Vector.get_ofFn` + `Vector.get_map`).

No wrapper-level case split.  Close with `split_conjs`; `agrind`
handles `wfPoly r` and the `Vector.ofFn` ↔ `.map` rewrite. -/
@[step]
theorem mlkem.ntt.poly_element_mul_r.spec
    (pe_src pe_dst : PolyElement)
    (h_src : wfPoly pe_src) (h_dst : wfPoly pe_dst) :
    mlkem.ntt.poly_element_mul_r pe_src pe_dst
      ⦃ (r : PolyElement) =>
          wfPoly r ∧ toPoly r = (toPoly pe_src).map (R * ·) ⦄ := by
  unfold mlkem.ntt.poly_element_mul_r
  step*
  refine ⟨by assumption, ?_⟩
  rw [show (toPoly _ : MLKEM.Polynomial) = _ from by assumption]
  apply Vector.ext
  intro i hi
  rw [Vector.getElem_ofFn, Vector.getElem_map]
  rfl

/-! ## `vector_mul_r`

Slice-level wrapper over `poly_element_mul_r`: applies `mul_r` to every
poly in `pv_src`, writing into `pv_dst` of the same length. -/

/-- **Loop spec** for `vector_mul_r_loop`.

Invariant: at index `i ≥ iter.start.val`, `r[i] = pv_dst[i]` (frame);
at `i < iter.start.val`, `toPoly r[i] = (toPoly pv_src[i]).map (R * ·)`.

Informal proof. Template: Range-loop induction per `proof-patterns` §1
(slice-index variant, analogue:
`Properties/MLDSA/Vectors.lean :: vector_ntt_loop.spec` but with a
*Range* iterator and `index_mut_back` instead of `IterMut`).  Unfold
`mlkem.ntt.vector_mul_r_loop`; the body calls `IteratorRange.next`,
returns `ok pv_dst` on `none`, and on `some i` calls
`Slice.index_usize pv_src i`, `Slice.index_mut_usize pv_dst i`
(returns `(a1, index_mut_back)`), then `poly_element_mul_r a a1`,
reseats `s := index_mut_back a2`, and recurses.

1. `step with IteratorRange_next_some` / `IteratorRange_next_none`.
2. `Slice.index_usize.spec` for `pv_src[iter.start.val]`; provides
   `a = pv_src.val[iter.start.val]` and the length-bounds witness.
3. `Slice.index_mut_usize.spec` for `pv_dst[iter.start.val]`; provides
   `a1 = pv_dst.val[iter.start.val]`, an `index_mut_back` continuation
   with the standard set-equation and length-preservation properties.
4. Step with `mlkem.ntt.poly_element_mul_r.spec`: precondition
   `wfPoly a` comes from `h_src` at `iter.start.val`
   (`a = pv_src.val[iter.start.val]`, and `wfPolyVec pv_src` says
   `wfPoly pv_src.val[i]` for every `i < pv_src.length`).  Similarly,
   `wfPoly a1` from `h_dst`.  Post: `wfPoly a2 ∧ toPoly a2 =
   (toPoly a).map (R * ·)`.
5. The reseat `s := index_mut_back a2` writes `a2` at slot
   `iter.start.val` of `pv_dst`; combined with the `index_mut_back`
   set-equation: `s.val[i] = if i = iter.start.val then a2 else
   pv_dst.val[i]`, and `s.length = pv_dst.length`.
6. Step the recursive call (this theorem).  Preconditions:
   `wfPolyVec s` (from `wfPolyVec pv_dst` plus the new slot
   satisfying `wfPoly a2`), `s.length = pv_dst.length = pv_src.length`,
   `iter1.start.val ≤ pv_src.length`,
   `iter1.«end».val = pv_src.length`.  IH gives the per-index post at
   `iter1.start.val = iter.start.val + 1`.

Case analysis: `none` (`iter.start.val ≥ pv_src.length`): every
`i < pv_src.length` satisfies `i < iter.start.val`, so the conditional
takes the frame branch `toPoly r[i] = toPoly pv_dst[i]` — provable by
`rfl` since `r = pv_dst`.  `some`: for each `i < pv_src.length`,
- `i < iter.start.val` (already-processed prefix): use IH applied to
  the reseated slice `s`;
- `i = iter.start.val` (the fresh slot): use step 4 plus the
  `index_mut_back` set-equation;
- `i > iter.start.val` (untouched suffix): frame via `index_mut_back`.

Close with `split_conjs`; `agrind` for `wfPolyVec r`, length
preservation, and the per-index conditional;
`simp [poly_element_mul_r post, index_mut_back set-equation]; agrind`
for the fresh-slot equality. -/
@[step]
theorem mlkem.ntt.vector_mul_r_loop.spec
    (iter : core.ops.range.Range Usize)
    (pv_src pv_dst : Slice (PolyElement))
    (h_src : wfPolyVec pv_src) (h_dst : wfPolyVec pv_dst)
    (h_lens : pv_src.length = pv_dst.length)
    (h_start : iter.start.val ≤ pv_src.length) (h_end : iter.«end».val = pv_src.length) :
    mlkem.ntt.vector_mul_r_loop iter pv_src pv_dst
      ⦃ (r : Slice (PolyElement)) =>
          wfPolyVec r ∧
          ∃ (h_len : r.length = pv_src.length),
          ∀ (i : Nat) (h_i : i < pv_src.length),
            (if i < iter.start.val then
              toPoly (r.val[i]'(by have := r.property; grind))
                = toPoly (pv_dst.val[i]'(by have := h_lens; grind))
            else
              toPoly (r.val[i]'(by have := r.property; grind))
                = (toPoly pv_src.val[i]).map (R * ·)) ⦄ := by
  unfold mlkem.ntt.vector_mul_r_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, ho, hstart', hend' ⟩ ← IteratorRange_next_Usize_some
    rw [ho]
    simp only
    have hi_lt_src : iter.start.val < pv_src.length := by scalar_tac
    have hi_lt_dst : iter.start.val < pv_dst.length := by rw [← h_lens]; exact hi_lt_src
    -- a ← Slice.index_usize pv_src iter.start
    step as ⟨ a, ha ⟩
    have ha_eq : a = pv_src.val[iter.start.val]! := by grind
    have ha_wf : wfPoly a := by
      rw [ha_eq]
      rw [show pv_src.val[iter.start.val]! = pv_src.val[iter.start.val]'hi_lt_src
            from getElem!_pos pv_src.val iter.start.val hi_lt_src]
      exact h_src iter.start.val hi_lt_src
    -- (a1, idx_back) ← Slice.index_mut_usize pv_dst iter.start
    step as ⟨a1, idx_back, hpair⟩
    have ha1_eq : a1 = pv_dst.val[iter.start.val]! := by grind
    have hidx_eq : idx_back = Slice.set pv_dst iter.start := by grind
    have ha1_wf : wfPoly a1 := by
      rw [ha1_eq]
      rw [show pv_dst.val[iter.start.val]! = pv_dst.val[iter.start.val]'hi_lt_dst
            from getElem!_pos pv_dst.val iter.start.val hi_lt_dst]
      exact h_dst iter.start.val hi_lt_dst
    -- a2 ← poly_element_mul_r a a1
    let* ⟨ a2, ha2_wf, ha2_eq ⟩ ← mlkem.ntt.poly_element_mul_r.spec
    -- s := idx_back a2 = pv_dst.set iter.start a2
    have hidx_back_def : idx_back a2 = Slice.set pv_dst iter.start a2 := by rw [hidx_eq]
    rw [hidx_back_def]
    -- Prepare preconditions for IH
    set s := Slice.set pv_dst iter.start a2 with hs_def
    have hs_len : s.length = pv_dst.length := by
      simp [s, Slice.set, Slice.length]
    have hs_lens : pv_src.length = s.length := by rw [hs_len]; exact h_lens
    have hs_wf : wfPolyVec s := by
      intro j hj
      simp only [s, Slice.set_val_eq]
      rw [Slice.length, Slice.set_val_eq, List.length_set] at hj
      by_cases hji : j = iter.start.val
      · subst hji
        rw [List.getElem_set_self]
        exact ha2_wf
      · rw [List.getElem_set_ne (Ne.symm hji)]
        exact h_dst j hj
    have hs_start_new : iter1.start.val ≤ pv_src.length := by rw [hstart']; scalar_tac
    have hs_end_new : iter1.«end».val = pv_src.length := by rw [hend']; exact h_end
    -- IH
    apply WP.spec_mono
      (mlkem.ntt.vector_mul_r_loop.spec iter1 pv_src s h_src hs_wf hs_lens hs_start_new hs_end_new)
    rintro r ⟨ hwf_r, hlen_r, hpost ⟩
    refine ⟨ hwf_r, ?_ ⟩
    have hlen_r' : r.length = pv_src.length := hlen_r
    refine ⟨ hlen_r', ?_ ⟩
    intro i h_i
    by_cases h_i_lt : i < iter.start.val
    · -- frame: i < iter.start ≤ iter1.start (so IH gives r.val[i] = s.val[i] = pv_dst.val[i])
      rw [if_pos h_i_lt]
      have h_i_lt_iter1 : i < iter1.start.val := by rw [hstart']; scalar_tac
      have h_ne : iter.start.val ≠ i := by scalar_tac
      have ih := hpost i h_i
      rw [if_pos h_i_lt_iter1] at ih
      rw [ih]
      simp only [s, Slice.set_val_eq]
      fcongr 1
      exact List.getElem_set_ne h_ne _
    · rw [if_neg h_i_lt]
      by_cases h_i_eq : i = iter.start.val
      · -- fresh slot: i = iter.start.val; IH gives r.val[i] = s.val[i] = a2
        subst h_i_eq
        have h_i_lt_iter1 : iter.start.val < iter1.start.val := by rw [hstart']; scalar_tac
        have ih := hpost iter.start.val h_i
        rw [if_pos h_i_lt_iter1] at ih
        rw [ih]
        simp only [s, Slice.set_val_eq]
        rw [List.getElem_set_self]
        rw [ha2_eq, ha_eq, getElem!_pos pv_src.val iter.start.val hi_lt_src]
      · -- i > iter.start: IH applies via else-branch since i ≥ iter1.start = iter.start+1
        have h_i_ge_iter1 : ¬ i < iter1.start.val := by
          rw [hstart']; push Not; scalar_tac
        have ih := hpost i h_i
        rw [if_neg h_i_ge_iter1] at ih
        exact ih
  · -- None branch: iter.start ≥ iter.end = pv_src.length, so iter empty.
    have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    have h_start_eq : iter.start.val = pv_src.length := by scalar_tac
    let* ⟨ o, iter1, hnone, _ ⟩ ← IteratorRange_next_Usize_none
    rw [hnone]
    simp only [WP.spec_ok]
    refine ⟨ h_dst, h_lens.symm, ?_ ⟩
    intro i h_i
    have h_i_lt_start : i < iter.start.val := by rw [h_start_eq]; exact h_i
    rw [if_pos h_i_lt_start]
    trivial
termination_by iter.«end».val - iter.start.val
decreasing_by scalar_decr_tac

/-- **Wrapper spec** for `vector_mul_r`.

Postcondition: every output poly satisfies
`toPoly r[i] = (toPoly pv_src[i]).map (R * ·)`; `wfPolyVec r`;
`r.length = pv_src.length`.

Informal proof. Template: leaf wrapper around a Range-loop with
runtime size guards.  Analogue: `vector_ntt.spec` (same row-count
guards `> 0` and `≤ MATRIX_MAX_NROWS = 4`, then delegation), but with
a *Range* iterator (here) rather than an `IterMut` (there).  Unfold
`mlkem.ntt.vector_mul_r`; the body computes `n_rows := Slice.len
pv_src`, asserts `n_rows > 0`, `n_rows ≤ MATRIX_MAX_NROWS`,
`Slice.len pv_dst = n_rows`, and calls `vector_mul_r_loop { start :=
0, end := n_rows } pv_src pv_dst`.

1. Step `Slice.len.spec` for `n_rows`; provides
   `n_rows.val = pv_src.length`.
2. Discharge `massert (n_rows > 0#usize)` using `h_n.1`.
3. Discharge `massert (n_rows ≤ MATRIX_MAX_NROWS)` using `h_n.2`
   together with `MATRIX_MAX_NROWS_val` (= 4).
4. Step `Slice.len.spec` for `pv_dst.len`; discharge
   `massert (… = n_rows)` using `h_lens`.
5. Step with `mlkem.ntt.vector_mul_r_loop.spec` at `iter.start = 0`,
   `iter.«end» = n_rows` (i.e. `pv_src.length`).  Preconditions:
   `h_src`, `h_dst`, `h_lens` pass through;
   `h_start : 0 ≤ pv_src.length` is `agrind`;
   `h_end : pv_src.length = pv_src.length` is `rfl`.

The loop post's `if i < 0` branch is vacuous, so the conditional
collapses to `toPoly r[i] = (toPoly pv_src[i]).map (R * ·)` for every
`i < pv_src.length`.  Existential length witness comes from the loop
post.

No wrapper-level algorithmic case split — guards are discharged
before the loop call.  Close with `split_conjs`; `agrind` for
`wfPolyVec r`, the existential length witness, and the per-index
forall. -/
@[step]
theorem mlkem.ntt.vector_mul_r.spec
    (pv_src pv_dst : Slice (PolyElement))
    (h_src : wfPolyVec pv_src) (h_dst : wfPolyVec pv_dst)
    (h_lens : pv_src.length = pv_dst.length)
    (h_n : pv_src.length > 0 ∧ pv_src.length ≤ 4) :
    mlkem.ntt.vector_mul_r pv_src pv_dst
      ⦃ (r : Slice (PolyElement)) =>
          wfPolyVec r ∧
          ∃ (h_len : r.length = pv_src.length),
          ∀ (i : Nat) (h_i : i < pv_src.length),
            toPoly (r.val[i]'(by have := r.property; grind))
              = (toPoly pv_src.val[i]).map (R * ·) ⦄ := by
  unfold mlkem.ntt.vector_mul_r
  step*
  case _ =>
    unfold mlkem.ntt.MATRIX_MAX_NROWS
    show pv_src.length ≤ 4
    exact h_n.2

end Symcrust.Properties.MLKEM
