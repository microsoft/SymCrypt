/-
  # Ntt/MatVec.lean — Step-specs for `matrix_vector_mont_mul_and_add`.

  This is the heart of ML-KEM's encapsulation and decapsulation:
  computing the product of an NTT-domain `k × k` matrix `A` with an
  NTT-domain `k`-vector `s`, adding the result to a `k`-vector `t`:

      pv_dst[i] += Σ_{j=0..k} A[i,j] * pv_src[j]   (in NTT domain)

  where `A` is stored row-major as a flat slice of `k²` polynomials.

  The pointwise NTT multiply uses `BaseCaseMultiply` (`MulAccum.lean`)
  and accumulates into a U32 buffer `pa_tmp`, finalized with one
  Montgomery reduction per coefficient. The net effect is one
  Montgomery factor: per row,
      `pv_dst'[i] = pv_dst[i] + Rinv · Σ_j A[i,j] * pv_src[j]`

  Bridge to spec: by G2/G3 from `Bridges/MatrixVectorMul.lean`,
  composing this with the `vector_mul_r` that scales `s` by `R`
  produces `pv_dst + A · s` in standard form. The standalone form
  exported here carries the `Rinv` factor explicitly.

  Covered functions:

      mlkem.ntt.matrix_vector_mont_mul_and_add_loop0_loop0   -- inner j loop (over k cols)
      mlkem.ntt.matrix_vector_mont_mul_and_add_loop0         -- outer i loop (over k rows)
      mlkem.ntt.matrix_vector_mont_mul_and_add               -- top wrapper

  The top-level postcondition references `MLKEM.PolyMatrix.MulVectorNTT`
  (FIPS 203 §2.4.7 / `Spec.lean` line 470) with the appropriate `Rinv`
  factor.
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.MontArith
import Symcrust.Properties.MLKEM.Bridges.MatrixVectorMul
import Symcrust.Properties.MLKEM.Ntt.MulAccumMontReduce
import Symcrust.Properties.MLKEM.Ntt.MulAccumDotProduct
import Symcrust.Properties.Iterators

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust

namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

private lemma matrix_idx_lt {n k l : Nat} (h_k : k < n) (h_l : l < n) :
    k * n + l < n * n := by
  have h1 : k * n + l < k * n + n := Nat.add_lt_add_left h_l _
  have h2 : k * n + n = (k + 1) * n := by ring
  have h3 : (k + 1) * n ≤ n * n := by
    apply Nat.mul_le_mul_right
    omega
  omega

set_option maxHeartbeats 1000000

/-- Bridge: a zero accumulator interprets to the zero polynomial. -/
private theorem accZero_imp_accToPoly_zero (pa : PolyAccumulator)
    (h : accZero pa) : accToPoly pa = 0 := by
  unfold accToPoly
  apply Vector.ext
  intro k hk
  rw [Vector.getElem_ofFn]
  rw [show (0 : MLKEM.Polynomial)[k]'hk = 0 by
        show (Vector.replicate _ (0 : Zq))[k]'hk = 0
        rw [Vector.getElem_replicate]]
  have := h ⟨k, hk⟩
  simp only [accToZq]
  rw [this]
  rfl


/-! ## Inner column loop

`matrix_vector_mont_mul_and_add_loop0_loop0` iterates `j ∈ [0, k)`
with an `Enumerate(Iter pv_src2)`, accumulating
`A[i, j] * pv_src2[j]` into `pa_tmp`. After all `k` iterations, the
accumulator holds `Σ_j A[i,j] * pv_src2[j]` (unreduced, pre-Mont).
-/

/-! ## Helper: partial column sum (R-scaled MultiplyNTTs over remaining columns) -/

/-- Polynomial-level partial sum of `MultiplyNTTs(A[i, j_start + kp], pv_src2[j_start + kp])`
over `kp ∈ [0, remaining.length)`, where `remaining` is the suffix of `pv_src2`'s
polynomials that the enumerate-iterator has not yet consumed.  Mirrors
`vectorDotPartial` in `Ntt/MulAccum.lean`: each summand is the bare
`MultiplyNTTs(...)` because the per-step `poly_element_mul_and_accumulate`
body produces it without any `R` factor (the `R⁻¹` from the eager Mont
reduction on `a₁·b₁` cancels the `R` stored in the ζ-table — see
`MulAccum.lean` line 182).  The single `R⁻¹` factor seen at the wrapper
output comes from the final `montgomery_reduce_and_add_*` step.

The bound `i * n_rows + j_start + kp < pm_src1.length` is discharged by `dif`,
returning `0` on out-of-bound (vacuous case the caller never hits). -/
noncomputable def matVecPartialSum
    (pm_src1 : Slice PolyElement)
    (n_rows i : Nat) : Nat → List PolyElement → MLKEM.Polynomial
  | _, [] => 0
  | j_start, p :: rest =>
      (if h : i * n_rows + j_start < pm_src1.length then
        MLKEM.MultiplyNTTs
          (toPoly (pm_src1.val[i * n_rows + j_start]'h))
          (toPoly p)
       else 0) +
      matVecPartialSum pm_src1 n_rows i (j_start + 1) rest

/-- **Bridge 1 of 2** — collapse the full column-partial sum into the
spec-level `mulVecNTTRow` row component, modulo `Rinv` (i.e.,
`mulVecNTTRowRinv`).

For full column coverage (`j_start = 0`, `remaining = pv_src2.val`),
applying `.map (Rinv * ·)` to `matVecPartialSum pm n_rows i 0 pv_src2.val`
yields the spec's `mulVecNTTRowRinv pm pv_src2 kn h_pm h_pv ⟨i, _⟩`.

Proof sketch: by `congrArg`, reduces to
`matVecPartialSum … = mulVecNTTRow …`.  Unfold `mulVecNTTRow` and
rewrite via `MulVectorNTT_get_eq` to obtain a `foldl` over
`List.finRange kn`.  Case-split `kn ∈ {2, 3, 4}` (3 cases, each with
its own per-`k` helper to manage the heartbeat budget — same pattern
as `MulVectorNTT_get_eq_{2,3,4}` in `Bridges/NttLinearity.lean`),
destructure `pv_src2.val` to the corresponding fixed length, then
unfold both sides and close by `simp` + `abel` (associativity-
commutativity of `Polynomial` addition). -/
theorem mulVecNTTRowRinv_eq_matVecPartialSum
    (pm_src1 pv_src2 : Slice PolyElement) (n_rows : Nat) (i : Nat)
    (kn : MLKEM.K) (h_kn : (kn : ℕ) = n_rows)
    (h_pm : pm_src1.length = n_rows * n_rows)
    (h_pv : pv_src2.length = n_rows)
    (h_i : i < n_rows) :
    haveI h_pm' : pm_src1.length = (kn : ℕ) * (kn : ℕ) := by rw [h_kn]; exact h_pm
    haveI h_pv' : pv_src2.length = (kn : ℕ) := by rw [h_kn]; exact h_pv
    haveI h_i' : i < (kn : ℕ) := by rw [h_kn]; exact h_i
    (matVecPartialSum pm_src1 n_rows i 0 pv_src2.val).map (Rinv * ·)
      = mulVecNTTRowRinv pm_src1 pv_src2 kn h_pm' h_pv' ⟨i, h_i'⟩ := by
  subst h_kn
  unfold mulVecNTTRowRinv mulVecNTTRow
  rw [MulVectorNTT_get_eq]
  fcongr 1
  simp only [toPolyMatrixOfLen, toPolyVecOfLen, Matrix.of_apply,
             Fin.getElem_fin, Vector.getElem_ofFn]
  -- Destructure pv_src2 to expose its underlying List
  obtain ⟨L, hL⟩ := pv_src2
  -- After destructuring, pv_src2.val = L and pv_src2.length = L.length.
  -- Unfold the .val coercion to expose L in the goal.
  show matVecPartialSum pm_src1 _ i 0 L = _
  obtain ⟨kv, hkv⟩ := kn
  simp only [Set.mem_insert_iff, Set.mem_singleton_iff] at hkv
  change L.length = _ at h_pv
  rcases hkv with rfl | rfl | rfl
  · -- kv = 2
    match h_eq : L, h_pv with
    | [p0, p1], _ =>
      have hpm2 : pm_src1.length = 4 := h_pm
      have hi2 : i < 2 := h_i
      have h0 : i * 2 + 0 < pm_src1.length := by omega
      have h1 : i * 2 + (0 + 1) < pm_src1.length := by omega
      simp only [matVecPartialSum, List.finRange, List.ofFn, Fin.foldr, Fin.foldr.loop,
                 List.foldl_cons, List.foldl_nil,
                 List.getElem_cons_zero, List.getElem_cons_succ]
      rw [dif_pos h0, dif_pos h1]
      rw [Polynomial.eq_iff]; intro k hk
      simp only [Polynomial.getElem!_add, Polynomial.zero_getElem!,
                 show (0 : MLKEM.Polynomial)[k]! = 0 from Polynomial.zero_getElem! k,
                 Nat.add_zero, Nat.zero_add]
      ring
  · -- kv = 3
    match h_eq : L, h_pv with
    | [p0, p1, p2], _ =>
      have hpm3 : pm_src1.length = 9 := h_pm
      have hi3 : i < 3 := h_i
      have h0 : i * 3 + 0 < pm_src1.length := by omega
      have h1 : i * 3 + (0 + 1) < pm_src1.length := by omega
      have h2' : i * 3 + (0 + 1 + 1) < pm_src1.length := by omega
      simp only [matVecPartialSum, List.finRange, List.ofFn, Fin.foldr, Fin.foldr.loop,
                 List.foldl_cons, List.foldl_nil,
                 List.getElem_cons_zero, List.getElem_cons_succ]
      rw [dif_pos h0, dif_pos h1, dif_pos h2']
      rw [Polynomial.eq_iff]; intro k hk
      simp only [Polynomial.getElem!_add, Polynomial.zero_getElem!,
                 show (0 : MLKEM.Polynomial)[k]! = 0 from Polynomial.zero_getElem! k,
                 Nat.add_zero, Nat.zero_add]
      ring
  · -- kv = 4
    match h_eq : L, h_pv with
    | [p0, p1, p2, p3], _ =>
      have hpm4 : pm_src1.length = 16 := h_pm
      have hi4 : i < 4 := h_i
      have h0 : i * 4 + 0 < pm_src1.length := by omega
      have h1 : i * 4 + (0 + 1) < pm_src1.length := by omega
      have h2' : i * 4 + (0 + 1 + 1) < pm_src1.length := by omega
      have h3' : i * 4 + (0 + 1 + 1 + 1) < pm_src1.length := by omega
      simp only [matVecPartialSum, List.finRange, List.ofFn, Fin.foldr, Fin.foldr.loop,
                 List.foldl_cons, List.foldl_nil,
                 List.getElem_cons_zero, List.getElem_cons_succ]
      rw [dif_pos h0, dif_pos h1, dif_pos h2', dif_pos h3']
      rw [Polynomial.eq_iff]; intro k hk
      simp only [Polynomial.getElem!_add, Polynomial.zero_getElem!,
                 show (0 : MLKEM.Polynomial)[k]! = 0 from Polynomial.zero_getElem! k,
                 Nat.add_zero, Nat.zero_add]
      ring

/-- **Bridge 2 of 2** — `mulVecNTTRowRinv` is `MulVectorNTT` per-coeff
scaled then projected to row `i`.

By definition `mulVecNTTRowRinv = mulVecNTTRow.map (Rinv * ·)` and
`mulVecNTTRow = (MulVectorNTT pm pv).get i`.  The bridge swaps the
`.map` and `.get` via `Vector.get_map`:

    ((MulVectorNTT pm pv).get i).map (Rinv * ·)
      = ((MulVectorNTT pm pv).map (fun p => p.map (Rinv * ·))).get i

Informal proof: by `Vector.get_map` (or `simp [mulVecNTTRowRinv,
mulVecNTTRow]`). -/
theorem mulVecNTTRowRinv_eq_MulVectorNTT_map_get
    (pm pv : Slice PolyElement) (kn : MLKEM.K)
    (h_pm : pm.length = (kn : ℕ) * (kn : ℕ))
    (h_pv : pv.length = (kn : ℕ))
    (i : Fin kn) :
    mulVecNTTRowRinv pm pv kn h_pm h_pv i
      = ((MLKEM.PolyMatrix.MulVectorNTT
          (toPolyMatrixOfLen pm kn h_pm)
          (toPolyVecOfLen pv kn h_pv)).map
            (fun p => p.map (Rinv * ·))).get i := by
  unfold mulVecNTTRowRinv mulVecNTTRow
  generalize (toPolyMatrixOfLen pm kn h_pm).MulVectorNTT (toPolyVecOfLen pv kn h_pv) = V
  simp only [Vector.get, Vector.map, Vector.toArray_mk]
  rw [Array.getElem_map]
  rfl

/-! ## Inner column loop spec -/

/-- **Loop spec** for the inner column loop — cursor-based invariant.

The `Enumerate (Iter pv_src2)` iterator has two synchronised cursors:
`iter.iter.i` (slice cursor) and `iter.count.val` (count of yielded
items).  Both start at 0 (set by `IteratorSliceIter.enumerate`) and
advance in lock-step by the Aeneas-generated `Enumerate::next` equation
(Rust-faithful; derived `@[step]` lemmas in `Properties/Iterators.lean`).
We expose this state via the hypotheses `h_iter_slice` / `h_iter_link`.

The bound invariant `pa_tmp[k] ≤ iter.count.val * (M+A)` grows by
`(M+A)` per body call (from `_accumulate_aux.spec`'s additive
post).  At loop exit, `iter.count.val = n_rows.val`, so the post
gives the canonical `n_rows.val * (M+A)` bound.

Proof structure mirrors `vector_mont_dot_product_loop.spec` at
`MulAccum.lean:1379` line-by-line; the only differences are:
1. Enumerate-style iterator step (`Enumerate_SliceIter_next_some/none`
   replace `IteratorRange_next_Usize_some/none`).
2. Inner body `poly_element_mul_and_accumulate_aux` indexes
   `pm_src1[i.val * n_rows.val + j]` (where `j = iter.count`),
   producing `MultiplyNTTs (toPoly pm_src1[i*n+j]) (toPoly pv_src2[j])`.
3. Sum is `matVecPartialSum` (LIST-driven recursion) rather than
   `vectorDotPartial` (NAT-driven recursion).
4. The element extracted from the iterator is
   `iter.iter.slice[iter.iter.i] = pv_src2[iter.count.val]`
   modulo `h_iter_slice` and `h_iter_link`. -/
@[step]
theorem mlkem.ntt.matrix_vector_mont_mul_and_add_loop0_loop0.spec
    (iter : core.iter.adapters.enumerate.Enumerate
              (core.slice.iter.Iter PolyElement))
    (pm_src1 pv_src2 : Slice PolyElement)
    (pa_tmp : PolyAccumulator)
    (n_rows i : Usize)
    (h_wf_pm : wfPolyVec pm_src1)
    (h_wf_src2 : wfPolyVec pv_src2)
    -- LOOSE uniform invariant on all slots.
    (h_acc : ∀ k (hk : k < 256),
      (pa_tmp.val[k]'(by have := pa_tmp.property; scalar_tac)).val
        ≤ iter.count.val * (3328 * 3328 + 3494 * 3254))
    -- TIGHT-ODD parallel invariant: odd slots are bounded by
    -- iter.count·2M, which yields the STRICT c1 precondition
    -- `pa_tmp[2j+1] < 3·(M+A)` for K ≤ 3 via `mlkem_M_lt_A`.
    (h_acc_tight_odd : ∀ j (hj : j < 128),
      (pa_tmp.val[2*j+1]'(by have := pa_tmp.property; scalar_tac)).val
        ≤ iter.count.val * (2 * (3328 * 3328)))
    (h_i : i.val < n_rows.val)
    (h_nrows : 0 < n_rows.val ∧ n_rows.val ≤ 4)
    (h_pm_len : pm_src1.length = n_rows.val * n_rows.val)
    (h_src2_len : pv_src2.length = n_rows.val)
    (h_iter_slice : iter.iter.slice = pv_src2)
    (h_iter_link : iter.iter.i = iter.count.val)
    (h_iter_le : iter.count.val ≤ n_rows.val) :
    mlkem.ntt.matrix_vector_mont_mul_and_add_loop0_loop0
        iter pm_src1 pa_tmp n_rows i
      ⦃ (pa_tmp' : PolyAccumulator) =>
          accToPoly pa_tmp' = accToPoly pa_tmp +
            matVecPartialSum pm_src1 n_rows.val i.val iter.count.val
              (pv_src2.val.drop iter.count.val) ∧
          (∀ k (hk : k < 256),
            (pa_tmp'.val[k]'(by have := pa_tmp'.property; scalar_tac)).val
              ≤ n_rows.val * (3328 * 3328 + 3494 * 3254)) ∧
          (∀ j (hj : j < 128),
            (pa_tmp'.val[2*j+1]'(by have := pa_tmp'.property; scalar_tac)).val
              ≤ n_rows.val * (2 * (3328 * 3328))) ⦄ := by
  unfold mlkem.ntt.matrix_vector_mont_mul_and_add_loop0_loop0
  by_cases hlt : iter.iter.i < iter.iter.slice.len
  · -- Some branch: iterator yields (iter.count, pv_src2[iter.count])
    have h_count_lt : iter.count.val < n_rows.val := by
      rw [h_iter_link] at hlt
      have hsl : iter.iter.slice.len.val = pv_src2.length := by
        rw [h_iter_slice]; rfl
      rw [hsl, h_src2_len] at hlt
      exact hlt
    have h_no_overflow : iter.count.val + 1 ≤ Usize.max := by scalar_tac
    let* ⟨ o, iter1, ho, hslice', hi', hcount' ⟩ ← Enumerate_SliceIter_next_some
    rw [ho]
    simp only
    -- ═══════════════════════════════════════════════════════════════
    -- strict-c1 dispatch (Tier 0, closed via tight-odd invariant)
    -- ───────────────────────────────────────────────────────────────
    -- `_accumulate_aux.spec` requires asymmetric preconditions: LOOSE
    -- `≤ 3·(M+A)` on even slots, STRICT `< 3·(M+A)` on odd slots.
    -- Loose case: from `h_acc` + `iter.count.val ≤ 3`.
    -- Strict case: from `h_acc_tight_odd` + `mlkem_M_lt_A` (registered
    -- `@[scalar_tac_simps]`): K·2M ≤ 3·2M = 6M < 3·(M+A) = 3M+3A.
    have hK_le_3 : iter.count.val ≤ 3 := by scalar_tac
    have h_even_loose : ∀ j (hj : j < 128),
        (pa_tmp.val[2*j]'(by have := pa_tmp.property; scalar_tac)).val
          ≤ 3 * (3328 * 3328 + 3494 * 3254) := by
      intro j hj
      have h := h_acc (2*j) (by scalar_tac)
      scalar_tac
    have h_odd_strict : ∀ j (hj : j < 128),
        (pa_tmp.val[2*j+1]'(by have := pa_tmp.property; scalar_tac)).val
          < 3 * (3328 * 3328 + 3494 * 3254) := by
      intro j hj
      have h := h_acc_tight_odd j hj
      scalar_tac
    -- Index bounds for pm_src1 at row i, column iter.count.val.
    have h_idx : i.val * n_rows.val + iter.count.val < pm_src1.length := by
      rw [h_pm_len]; exact matrix_idx_lt h_i h_count_lt
    -- pe_src2 (the iterator element) is pv_src2[iter.count.val].
    have h_count_lt' : iter.count.val < pv_src2.val.length := by
      have := h_src2_len; scalar_tac
    have h_pe_src2 : iter.iter.slice[iter.iter.i] =
        pv_src2.val[iter.count.val]'h_count_lt' := by
      simp only [h_iter_slice, h_iter_link]
      rfl
    have h_pe_wf : wfPoly (iter.iter.slice[iter.iter.i]) := by
      rw [h_pe_src2]
      exact h_wf_src2 iter.count.val h_count_lt'
    -- Body call: pa_tmp1 with aux's rich postcondition.
    let* ⟨ pa_tmp1, hZq, hBound, hAdd, hAddTight ⟩ ←
      mlkem.ntt.poly_element_mul_and_accumulate_aux.spec
        pm_src1 n_rows i iter.count (iter.iter.slice[iter.iter.i])
        pa_tmp h_wf_pm h_pe_wf h_even_loose h_odd_strict h_idx
    -- Build IH bounds: pa_tmp1[k] ≤ iter1.count.val * (M+A), and
    --                  pa_tmp1[2j+1] ≤ iter1.count.val * 2M.
    have h_acc1 : ∀ k (hk : k < 256),
        (pa_tmp1.val[k]'(by have := pa_tmp1.property; scalar_tac)).val
          ≤ iter1.count.val * (3328 * 3328 + 3494 * 3254) := by
      intro k hk
      have ha := hAdd k hk
      have hi_b := h_acc k hk
      rw [hcount']; scalar_tac
    have h_acc1_tight_odd : ∀ j (hj : j < 128),
        (pa_tmp1.val[2*j+1]'(by have := pa_tmp1.property; scalar_tac)).val
          ≤ iter1.count.val * (2 * (3328 * 3328)) := by
      intro j hj
      have ha := hAddTight j hj
      have hi_b := h_acc_tight_odd j hj
      rw [hcount']; scalar_tac
    have h_link1 : iter1.iter.i = iter1.count.val := by
      rw [hi', hcount', h_iter_link]
    have h_slice1 : iter1.iter.slice = pv_src2 := by rw [hslice', h_iter_slice]
    have h_le1 : iter1.count.val ≤ n_rows.val := by rw [hcount']; scalar_tac
    -- Recursive call
    apply WP.spec_mono
      (mlkem.ntt.matrix_vector_mont_mul_and_add_loop0_loop0.spec iter1 pm_src1 pv_src2
        pa_tmp1 n_rows i h_wf_pm h_wf_src2 h_acc1 h_acc1_tight_odd h_i h_nrows
        h_pm_len h_src2_len h_slice1 h_link1 h_le1)
    rintro pa_tmp' ⟨h_eq, h_bound, h_tight⟩
    refine ⟨?_, h_bound, h_tight⟩
    -- accToPoly bridge (unchanged from original proof body)
    rw [h_eq]
    have h_pa1_eq : accToPoly pa_tmp1 = accToPoly pa_tmp
        + MLKEM.MultiplyNTTs
            (toPoly (pm_src1.val[i.val * n_rows.val + iter.count.val]'h_idx))
            (toPoly (iter.iter.slice[iter.iter.i])) :=
      accToPoly_after_accumulate pa_tmp pa_tmp1 _ _ hZq
    rw [h_pa1_eq]
    rw [Polynomial.add_assoc]
    fcongr 1
    rw [hcount']
    have h_drop_cons : pv_src2.val.drop iter.count.val =
        (pv_src2.val[iter.count.val]'h_count_lt')
          :: pv_src2.val.drop (iter.count.val + 1) := by
      rw [List.drop_eq_getElem_cons h_count_lt']
    rw [h_drop_cons]
    simp only [matVecPartialSum]
    rw [dif_pos h_idx]
    rw [h_pe_src2]
  · -- None branch: iterator exhausted
    let* ⟨ o, iter1, hnone, _ ⟩ ← Enumerate_SliceIter_next_none
    rw [hnone]
    simp only [WP.spec_ok]
    have h_count_eq : iter.count.val = n_rows.val := by
      rw [h_iter_link] at hlt
      have hsl : iter.iter.slice.len.val = pv_src2.length := by
        rw [h_iter_slice]; rfl
      rw [hsl, h_src2_len] at hlt
      scalar_tac
    have h_drop_empty : pv_src2.val.drop iter.count.val = [] := by
      apply List.drop_eq_nil_of_le
      rw [h_count_eq, ← h_src2_len]
    refine ⟨?_, ?_, ?_⟩
    · rw [h_drop_empty]
      simp only [matVecPartialSum]
      rw [show (0 : MLKEM.Polynomial) = Polynomial.zero from rfl,
          Polynomial.add_zero]
    · intro k hk
      have := h_acc k hk
      rw [h_count_eq] at this
      exact this
    · intro j hj
      have := h_acc_tight_odd j hj
      rw [h_count_eq] at this
      exact this

/-! ## Outer row loop

`matrix_vector_mont_mul_and_add_loop0` iterates `i ∈ [0, k)`. For
each `i`, it:
1. Acquires a mutable reference to `pv_dst[i]`.
2. Runs the inner loop to accumulate `Σ_j A[i,j] · pv_src2[j]`.
3. Calls the Mont reduction + add to fold the accumulator into `pv_dst[i]`.
4. Writes `pv_dst[i]` back via `index_mut_back`.
-/

/-- **Loop spec** for the outer row loop.

Per-row FC over the Range cursor `iter.start.val`: rows
`[iter.start.val, n_rows.val)` get the row-i component of
`MulVectorNTT(A, pv_src2)` with `Rinv` scaling added; rows
`[0, iter.start.val)` are unchanged.  The accumulator `pa_tmp` is
zero at exit (each iteration of the outer loop ends with a call to
`montgomery_reduce_and_add_..._loop` that zeroes every slot).

Informal proof. `partial_fixpoint`; `loop.spec_decr_nat` with measure
`iter.«end».val - iter.start.val`; `unfold`; `by_cases`.

- None case (`iter.start = n_rows`): returns `(pv_dst, pa_tmp)`; all
  rows fall in the unchanged branch; `accZero pa_tmp` from precond.
  Close with `WP.spec_ok` + `split_conjs` + `agrind`.
- Some case (`i = iter.start`):
  1. `IteratorRange.next` → `i = iter.start`, `iter1.start = i + 1`.
  2. `Slice.index_mut_usize.spec` at index `i` (in bounds via
     `pv_dst.length = n_rows`): yields `(pe_dst, back)` with the
     standard mutable-borrow shape.
  3. Build witness for `loop0_loop0`: `⟨0, pv_src2.val, by grind,
     by simp⟩` (full slice from column 0). Apply `loop0_loop0.spec`
     with `h_acc_zero` lifted via `accZero_iff_accToPoly_zero`;
     yields `accToPoly pa_tmp1 = 0 +
       matVecPartialSum pm_src1 n_rows.val i.val 0 pv_src2.val`.
  4. Apply
     `montgomery_reduce_and_add_poly_element_accumulator_to_poly_element.spec`
     (MulAccum); yields `toPoly pe_dst1 = toPoly pe_dst +
       Rinv · accToPoly pa_tmp1` and `accZero pa_tmp2`. The algebra
     `Rinv · matVecPartialSum … = mulVecNTTRowRinv …` follows from
     `R · Rinv = 1` in `Zq` plus the bridge
     `mulVecNTTRowRinv_eq_matVecPartialSum` (declared above at
     line 104 in this file; CLOSED commit `ed9ca68c`).
  5. `index_mut_back pe_dst1` writes the new row in place.
  6. Apply outer IH (via `step*`) with cursor `i+1`,
     `h_acc_zero := accZero pa_tmp2`.
  Invariant update by row:
  - `j < i`: untouched at both layers ⇒ frame holds.
  - `j = i`: equals the just-computed `pe_dst1`.
  - `j > i`: from outer IH directly.
  Close with `step*` + `split_conjs` + `agrind`. -/
@[step]
theorem mlkem.ntt.matrix_vector_mont_mul_and_add_loop0.spec
    (iter : core.ops.range.Range Usize)
    (pm_src1 pv_src2 pv_dst : Slice PolyElement)
    (pa_tmp : PolyAccumulator)
    (n_rows : Usize)
    (kn : K) (h_kn : (kn : ℕ) = n_rows.val)
    (h_wf_pm : wfPolyVec pm_src1) (h_wf_src2 : wfPolyVec pv_src2)
    (h_wf_dst : wfPolyVec pv_dst)
    (h_nrows : 0 < n_rows.val ∧ n_rows.val ≤ 4)
    (h_pm_len : pm_src1.length = n_rows.val * n_rows.val)
    (h_src2_len : pv_src2.length = n_rows.val)
    (h_dst_len : pv_dst.length = n_rows.val)
    (h_start : iter.start.val ≤ n_rows.val) (h_end : iter.«end».val = n_rows.val)
    (h_acc_zero : accZero pa_tmp) :
    mlkem.ntt.matrix_vector_mont_mul_and_add_loop0
        iter pm_src1 pv_src2 pv_dst pa_tmp n_rows
      ⦃ pv_dst' pa_tmp' =>
          wfPolyVec pv_dst' ∧
          (∃ (h_dst' : pv_dst'.length = (kn : ℕ)),
            ∀ (i : Nat) (h_i : i < n_rows.val),
              if i < iter.start.val then
                toPoly (pv_dst'.val[i]'(by have := pv_dst'.property; grind))
                  = toPoly (pv_dst.val[i]'(by have := h_dst_len; grind))
              else
                toPoly (pv_dst'.val[i]'(by have := pv_dst'.property; grind))
                  = toPoly (pv_dst.val[i]'(by have := h_dst_len; grind)) +
                    mulVecNTTRowRinv pm_src1 pv_src2 kn
                      (by rw [h_kn]; exact h_pm_len)
                      (by rw [h_kn]; exact h_src2_len)
                      ⟨i, by have := h_kn; grind⟩) ∧
          accZero pa_tmp' ⦄ := by
  unfold mlkem.ntt.matrix_vector_mont_mul_and_add_loop0
  by_cases hlt : iter.start.val < iter.«end».val
  · -- Some branch: i = iter.start, process row iter.start
    let* ⟨ o, iter1, ho, hstart', hend' ⟩ ← IteratorRange_next_Usize_some
    rw [ho]
    simp only
    have h_i_lt : iter.start.val < n_rows.val := by rw [← h_end]; exact hlt
    have h_start_lt_len : iter.start.val < pv_dst.val.length := by
      have := h_dst_len; scalar_tac
    -- index_mut_usize at iter.start
    let* ⟨ pe_dst, back_dst, hp ⟩ ← Slice.index_mut_usize_spec pv_dst iter.start
      (by rw [h_dst_len]; exact h_i_lt)
    have hp_dst : pe_dst = pv_dst.val[iter.start.val]'h_start_lt_len := by
      grind
    have hp_back : back_dst = Slice.set pv_dst iter.start := by grind
    -- core.slice.Slice.iter pv_src2 returns ⟨pv_src2, 0⟩
    let* ⟨ it_inner, h_it_slice, h_it_i ⟩ ← core.slice.Slice.iter.spec
    -- enumerate the slice iter
    let* ⟨ iter2, hiter2_inner, hiter2_count ⟩ ←
      core.iter.traits.iterator.Iterator.enumerate.trait_default.spec
    have h_acc_pre : ∀ k (hk : k < 256),
        (pa_tmp.val[k]'(by have := pa_tmp.property; scalar_tac)).val
          ≤ iter2.count.val * (3328 * 3328 + 3494 * 3254) := by
      intro k hk
      have := h_acc_zero ⟨k, hk⟩
      simp at this
      rw [hiter2_count]
      show (pa_tmp.val[k]'_).val ≤ 0
      omega
    -- Tight-odd precondition is vacuous at entry (pa_tmp = 0, iter2.count = 0).
    have h_acc_pre_tight_odd : ∀ j (hj : j < 128),
        (pa_tmp.val[2*j+1]'(by have := pa_tmp.property; scalar_tac)).val
          ≤ iter2.count.val * (2 * (3328 * 3328)) := by
      intro j hj
      have := h_acc_zero ⟨2*j+1, by scalar_tac⟩
      simp at this
      rw [hiter2_count]
      show (pa_tmp.val[2*j+1]'_).val ≤ 0
      omega
    have h_iter2_slice : iter2.iter.slice = pv_src2 := by
      rw [hiter2_inner]; exact h_it_slice
    have h_iter2_link : iter2.iter.i = iter2.count.val := by
      rw [hiter2_inner, hiter2_count, h_it_i]; rfl
    have h_iter2_le : iter2.count.val ≤ n_rows.val := by rw [hiter2_count]; scalar_tac
    -- Inner loop: pa_tmp1 = pa_tmp + Σ_j A[i,j]·pv_src2[j]
    let* ⟨ pa_tmp1, h_acc_eq, h_acc_bnd, h_acc_bnd_tight_odd ⟩ ←
      mlkem.ntt.matrix_vector_mont_mul_and_add_loop0_loop0.spec iter2 pm_src1 pv_src2
        pa_tmp n_rows iter.start h_wf_pm h_wf_src2 h_acc_pre h_acc_pre_tight_odd
        h_i_lt h_nrows h_pm_len h_src2_len h_iter2_slice h_iter2_link h_iter2_le
    -- montgomery_reduce: fold pa_tmp1 into pe_dst with Rinv scaling
    have h_wf_acc : wfAcc pa_tmp1 := by
      intro k hk
      have h := h_acc_bnd k hk
      calc (pa_tmp1.val[k]'_).val
          ≤ n_rows.val * (3328 * 3328 + 3494 * 3254) := h
        _ ≤ 4 * (3328 * 3328 + 3494 * 3254) :=
            Nat.mul_le_mul_right _ h_nrows.2
    have h_wf_pe_dst : wfPoly pe_dst := by
      rw [hp_dst]
      exact h_wf_dst iter.start.val h_start_lt_len
    let* ⟨ pa_tmp2, pe_dst1, h_wf_pe1, h_pe1_eq, h_pa2_zero ⟩ ←
      mlkem.ntt.montgomery_reduce_and_add_poly_element_accumulator_to_poly_element.spec
        pa_tmp1 pe_dst h_wf_acc h_wf_pe_dst
    rw [hp_back]
    -- Properties of the updated slice s = pv_dst.set iter.start pe_dst1:
    have h_s_len : (pv_dst.set iter.start pe_dst1).length = n_rows.val := by
      rw [Slice.length, Slice.set_val_eq, List.length_set]
      exact h_dst_len
    have h_wf_s : wfPolyVec (pv_dst.set iter.start pe_dst1) := by
      intro k hk
      have hk_lt : k < pv_dst.val.length := by
        have hk' := hk
        rw [h_s_len] at hk'
        rw [← h_dst_len] at hk'
        exact hk'
      have hk_lt_set : k < (pv_dst.val.set iter.start.val pe_dst1).length := by
        rw [List.length_set]; exact hk_lt
      show wfPoly ((pv_dst.val.set iter.start.val pe_dst1)[k]'hk_lt_set)
      by_cases h_eq : k = iter.start.val
      · subst h_eq
        rw [List.getElem_set_self]
        exact h_wf_pe1
      · rw [List.getElem_set_ne (Ne.symm h_eq)]
        exact h_wf_dst k hk_lt
    -- Recursive call to outer loop with iter1
    have h_start1_le : iter1.start.val ≤ n_rows.val := by rw [hstart']; scalar_tac
    have h_end1 : iter1.«end».val = n_rows.val := by rw [hend']; exact h_end
    apply WP.spec_mono
      (mlkem.ntt.matrix_vector_mont_mul_and_add_loop0.spec
        iter1 pm_src1 pv_src2 (pv_dst.set iter.start pe_dst1) pa_tmp2 n_rows kn h_kn
        h_wf_pm h_wf_src2 h_wf_s h_nrows h_pm_len h_src2_len h_s_len
        h_start1_le h_end1 h_pa2_zero)
    rintro ⟨pv_dst', pa_tmp'⟩ ⟨h_wf_dst', ⟨h_dst'_len, h_dst'_eq⟩, h_pa'_zero⟩
    refine ⟨h_wf_dst', ⟨h_dst'_len, ?_⟩, h_pa'_zero⟩
    intro j h_j
    -- Three cases on j vs iter.start.val
    by_cases h_j_lt : j < iter.start.val
    · -- j < iter.start: unchanged from pv_dst
      have h_j_lt1 : j < iter1.start.val := by rw [hstart']; omega
      rw [if_pos h_j_lt]
      have hd := h_dst'_eq j h_j
      rw [if_pos h_j_lt1] at hd
      rw [hd]
      simp only [Slice.set_val_eq]
      rw [List.getElem_set_ne (by omega : iter.start.val ≠ j)]
    · -- j ≥ iter.start
      push Not at h_j_lt
      rw [if_neg (by omega : ¬ j < iter.start.val)]
      have hd := h_dst'_eq j h_j
      by_cases h_j_eq : j = iter.start.val
      · -- j = iter.start: row just written this iteration
        subst h_j_eq
        have h_j_lt1 : iter.start.val < iter1.start.val := by rw [hstart']; omega
        rw [if_pos h_j_lt1] at hd
        rw [hd]
        simp only [Slice.set_val_eq]
        rw [List.getElem_set_self]
        rw [h_pe1_eq, hp_dst, h_acc_eq]
        rw [accZero_imp_accToPoly_zero pa_tmp h_acc_zero]
        rw [show (0 : MLKEM.Polynomial) = Polynomial.zero from rfl, Polynomial.zero_add]
        have h_count_zero : iter2.count.val = 0 := by
          rw [hiter2_count]; rfl
        rw [h_count_zero, List.drop_zero]
        rw [mulVecNTTRowRinv_eq_matVecPartialSum pm_src1 pv_src2 n_rows.val iter.start.val
              kn h_kn h_pm_len h_src2_len h_i_lt]
      · -- j > iter.start: IH gave new equation (j ≥ iter1.start.val)
        have h_j_ge1 : iter1.start.val ≤ j := by rw [hstart']; omega
        rw [if_neg (by omega : ¬ j < iter1.start.val)] at hd
        rw [hd]
        simp only [Slice.set_val_eq]
        rw [List.getElem_set_ne (Ne.symm h_j_eq)]
  · -- None branch: iterator exhausted, iter.start = iter.end = n_rows.
    push Not at hlt
    let* ⟨ o, iter1, hnone, hiter1 ⟩ ← IteratorRange_next_Usize_none iter hlt
    subst hnone
    subst hiter1
    simp only [WP.spec_ok]
    refine ⟨h_wf_dst, ⟨by rw [h_kn]; exact h_dst_len, ?_⟩, h_acc_zero⟩
    intro j h_j
    rw [if_pos (by rw [h_end] at hlt; omega)]

/-! ## Top wrapper

`matrix_vector_mont_mul_and_add` wipes the accumulator, then runs the
outer loop with the full range.  Postcondition: per-row Mont matrix-
vector product with `Rinv` scaling.

The bridge to the spec's `MLKEM.PolyMatrix.MulVectorNTT`:

  `toPolyVec result = toPolyVec pv_dst
                    + (MLKEM.PolyMatrix.MulVectorNTT Ah sh).map (Rinv * ·)`

where `Ah = toPolyMatrixOfLen pm_src1 kn` and `sh = toPolyVecOfLen pv_src2 kn`.

Callers compose this with `Bridges.matrix_vector_mont_cancel` (G2)
to absorb the `Rinv` factor by feeding `pv_src2 := poly_mul_r s_std`
(i.e., `pv_src2 = Mont-form s`). -/

/-- **Top spec for `matrix_vector_mont_mul_and_add`** — FC to
`MLKEM.PolyMatrix.MulVectorNTT` with explicit `Rinv` scaling.

Informal proof.
1. `lift (UScalar.cast .Usize n_rows)`: no overflow since
   `n_rows.val ≤ 4 ≤ Usize.max`. Step with `scalar_cast_spec` +
   `agrind`.
2. Step through the four `massert` checks (`n_rows1 > 0`,
   `n_rows1 ≤ MATRIX_MAX_NROWS`, length equalities) — all from
   `h_nrows`, `h_src2_len`, `h_dst_len`.
3. `Array.to_slice_mut pa_tmp` + `common.wipe_slice s`: apply
   `wipe_slice.spec` (Basic.lean) yielding `accZero pa_tmp1`.
4. Apply `matrix_vector_mont_mul_and_add_loop0.spec` with cursor
   `0..n_rows1` and `h_acc_zero := accZero pa_tmp1`. Get per-row
   equation `toPoly pv_dst'[i] = toPoly pv_dst[i] +
     mulVecNTTRowRinv …`.
5. Lift per-row to vector equality via `toPolyVecOfLen_ext` (or
   `Vector.ext`). Bridge to spec via
   `mulVecNTTRowRinv_eq_MulVectorNTT_map_get` (declared above at
   line 194 in this file — CLOSED): unfolds `mulVecNTTRowRinv` into
   `((MulVectorNTT Ah sh).map (fun p => p.map (Rinv · ·))).get i`.
Close with `step*` + `simp [toPolyVecOfLen, mulVecNTTRowRinv,
  mulVecNTTRowRinv_eq_MulVectorNTT_map_get, Vector.ext_iff]` + `agrind`.

This top spec is *transitively blocked* on `loop0.spec` →
`loop0_loop0.spec` → upstream `Enumerate.Insts.next` `@[step]`.  Once
the inner loop unblocks, this proof reduces to the orchestration
described above. -/
@[step]
theorem mlkem.ntt.matrix_vector_mont_mul_and_add.spec
    (pm_src1 pv_src2 pv_dst : Slice PolyElement)
    (pa_tmp : PolyAccumulator)
    (n_rows : U8)
    (kn : K) (h_kn : (kn : ℕ) = n_rows.val)
    (h_wf_pm : wfPolyVec pm_src1) (h_wf_src2 : wfPolyVec pv_src2)
    (h_wf_dst : wfPolyVec pv_dst)
    (h_nrows : 0 < n_rows.val ∧ n_rows.val ≤ 4)
    (h_pm_len : pm_src1.length = n_rows.val * n_rows.val)
    (h_src2_len : pv_src2.length = n_rows.val)
    (h_dst_len : pv_dst.length = n_rows.val) :
    mlkem.ntt.matrix_vector_mont_mul_and_add pm_src1 pv_src2 pv_dst pa_tmp n_rows
      ⦃ pv_dst' pa_tmp' =>
          wfPolyVec pv_dst' ∧
          accZero pa_tmp' ∧
          ∃ (h_dst' : pv_dst'.length = (kn : ℕ)),
          toPolyVecOfLen pv_dst' kn h_dst'
            = toPolyVecOfLen pv_dst kn (by rw [h_kn]; exact h_dst_len)
              + (MLKEM.PolyMatrix.MulVectorNTT
                  (toPolyMatrixOfLen pm_src1 kn (by rw [h_kn]; exact h_pm_len))
                  (toPolyVecOfLen pv_src2 kn (by rw [h_kn]; exact h_src2_len))).map
                  (fun p => p.map (Rinv * ·)) ⦄ := by
  unfold mlkem.ntt.matrix_vector_mont_mul_and_add
  step*
  case kn => exact kn
  case h =>
    unfold mlkem.ntt.MATRIX_MAX_NROWS
    have : n_rows1.val = n_rows.val := by
      rw [n_rows1_post]; exact U8.cast_Usize_val_eq n_rows
    scalar_tac
  case h_kn =>
    rw [n_rows1_post, U8.cast_Usize_val_eq]; exact h_kn
  case h_acc_zero =>
    rw [s_post2]
    have h_s1_len_256 : s1.val.length = 256 := by
      have h1 : s1.length = s.length := s1_post1
      have h2 : s.length = pa_tmp.val.length := by simp [Slice.length, s_post1]
      have h3 : pa_tmp.val.length = 256 := pa_tmp.property
      simp only [Slice.length] at h1
      grind
    have h_back_val : (Array.from_slice pa_tmp s1).val = s1.val :=
      Array.from_slice_val pa_tmp s1 h_s1_len_256
    intro k
    show ((Array.from_slice pa_tmp s1).val[k.val]'_).val = 0
    have h_k_in : k.val < s1.val.length := by rw [h_s1_len_256]; exact k.isLt
    have h_back_k : (Array.from_slice pa_tmp s1).val[k.val]'(by rw [h_back_val]; exact h_k_in)
                      = s1.val[k.val]'h_k_in := by fcongr 1
    rw [h_back_k]
    have hz : s1.val[k.val]'h_k_in = 0#u32 := s1_post2 k.val h_k_in
    rw [hz]
    rfl
  have h_pv'_len := pv_dst'_post2
  have h_pv'_eq := pv_dst'_post3
  have h_pv'_len_kn : pv_dst'.length = (kn : ℕ) := h_pv'_len
  refine ⟨pv_dst'_post1, pv_dst'_post4, h_pv'_len_kn, ?_⟩
  have h_n_eq : n_rows1.val = n_rows.val := by
    rw [n_rows1_post]; exact U8.cast_Usize_val_eq n_rows
  apply Vector.ext
  intro i hi
  have h_i_n : i < n_rows1.val := by rw [h_n_eq, ← h_kn]; exact hi
  have heq := h_pv'_eq i h_i_n
  rw [if_neg (by scalar_tac : ¬ i < 0)] at heq
  have h_i_kn : i < (kn : ℕ) := hi
  rw [mulVecNTTRowRinv_eq_MulVectorNTT_map_get pm_src1 pv_src2 kn
        (by rw [h_kn]; exact h_pm_len) (by rw [h_kn]; exact h_src2_len) ⟨i, h_i_kn⟩] at heq
  -- LHS: (toPolyVecOfLen pv_dst' kn h_pv'_len_kn)[i] = toPoly pv_dst'.val[i]
  -- RHS: (toPolyVecOfLen pv_dst kn _ + (MulVectorNTT _).map _)[i]
  --      = (toPolyVecOfLen pv_dst kn _)[i] + ((MulVectorNTT _).map _).get ⟨i, _⟩
  simp only [toPolyVecOfLen, Vector.getElem_ofFn]
  -- After simp, LHS is toPoly pv_dst'.val[i]; RHS needs additivity of `+`.
  show toPoly _ = (_ + _)[i]'_
  -- Unfold PolyVector.add (which is HAdd of Vector via Add instance).
  rw [show ∀ (v w : PolyVector q kn), (v + w)[i]'hi = v[i]'hi + w[i]'hi from
        fun v w => by
          show (Vector.ofFn fun j : Fin (kn : ℕ) => v[j] + w[j])[i] = _
          rw [Vector.getElem_ofFn]; rfl]
  -- Now: toPoly pv_dst'.val[i] = toPoly pv_dst.val[i] + (.map _).get ⟨i, _⟩
  simp only [Vector.getElem_ofFn]
  rw [heq]
  -- Both sides equal — check `Vector.get` vs `[i]`.
  rfl

end Symcrust.Properties.MLKEM
