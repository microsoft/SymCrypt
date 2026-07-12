/-
  # Ntt/Transpose.lean — Step-spec for in-place matrix transpose.

  `matrix_transpose` swaps `pm_src[i*n + j]` with `pm_src[j*n + i]`
  for `i < j` (`i ∈ [0, n)`, `j ∈ [i+1, n)`), producing the
  transposed matrix in place. Used in `key_compute_key_from_decoded`
  to convert `A` (sampled) to `A^T` (stored).

  Spec bridge: if `pm_src` represents a `n × n` matrix `M`, then
  `pm_src_after` represents `M^T`. We use a flat-index conversion
  function `slice_to_matrix` (defined in `Bridges/MatrixVectorMul.lean`
  or here as a helper if needed).

  Covered functions:

      mlkem.ntt.matrix_transpose_loop0_loop0   -- inner j loop
      mlkem.ntt.matrix_transpose_loop0         -- outer i loop
      mlkem.ntt.matrix_transpose               -- top wrapper
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.Iterators
import Symcrust.Properties.MLKEM.Bridges.MontArith

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust

namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 1000000

attribute [local step] UScalar.cast_inBounds_spec

/-! ## Helper: row-major index bound

If `k, l < n`, then `k * n + l < n * n`. Used pervasively in matrix
index proofs below. -/

private lemma matrix_idx_lt {n k l : Nat} (h_k : k < n) (h_l : l < n) :
    k * n + l < n * n := by
  calc k * n + l
      < k * n + n := by grind
    _ = (k + 1) * n := by grind
    _ ≤ n * n := Nat.mul_le_mul_right _ h_k

/-- Row-major index decomposition: `k * n + l = i * n + j ↔ k = i ∧ l = j`
when both `(k, l)` and `(i, j)` are valid coordinates. -/
private lemma matrix_idx_inj {n k l i j : Nat}
    (_h_k : k < n) (h_l : l < n) (h_i : i < n) (h_j : j < n) :
    k * n + l = i * n + j ↔ k = i ∧ l = j := by
  constructor
  · intro heq
    have hn_pos : 0 < n := by omega
    have h_l_eq : l = j := by
      have h1 : (k * n + l) % n = l := by
        rw [Nat.add_comm]
        rw [Nat.add_mul_mod_self_right]
        exact Nat.mod_eq_of_lt h_l
      have h2 : (i * n + j) % n = j := by
        rw [Nat.add_comm]
        rw [Nat.add_mul_mod_self_right]
        exact Nat.mod_eq_of_lt h_j
      rw [heq] at h1; rw [← h1]; exact h2
    refine ⟨?_, h_l_eq⟩
    rw [h_l_eq] at heq
    exact Nat.eq_of_mul_eq_mul_right hn_pos (Nat.add_right_cancel heq)
  · rintro ⟨rfl, rfl⟩; rfl

/-- A `Slice.swap` preserves `wfPolyVec` provided both endpoints
were already well-formed. -/
private lemma wfPolyVec_swap (pm pm' : Slice (PolyElement)) (a b : Nat)
    (h_a_lt : a < pm.length) (h_b_lt : b < pm.length)
    (h_wf : wfPolyVec pm)
    (h_len : pm'.length = pm.length)
    (h_a : pm'.val[a]'(by scalar_tac) = pm.val[b]'h_b_lt)
    (h_b : pm'.val[b]'(by scalar_tac) = pm.val[a]'h_a_lt)
    (h_other : ∀ i (hi : i < pm.length), i ≠ a → i ≠ b →
                  pm'.val[i]'(by scalar_tac) = pm.val[i]'hi) :
    wfPolyVec pm' := by
  intro m hm
  have hm_in_pm : m < pm.length := by scalar_tac
  by_cases ha : m = a
  · subst ha; rw [h_a]; exact h_wf b h_b_lt
  · by_cases hb : m = b
    · subst hb; rw [h_b]; exact h_wf a h_a_lt
    · rw [h_other m hm_in_pm ha hb]; exact h_wf m hm_in_pm

/-! ## Helpers: partial transpose

For an n×n matrix `M` stored row-major in a flat slice, we describe
the loops' partial state via two predicates expressing exactly which
cells have been swapped.

`innerLoopSwap n i lo k l`  holds when (k, l) is in the set of cells
that the inner j loop swaps when running from `j = lo` to `j = n`
on row `i`: namely, the (i, j) and (j, i) cells for `j ∈ [lo, n)`.

`outerLoopSwap n istart k l` holds when (k, l) is in the set of cells
the outer i loop swaps when running from `i = istart` to `i = n - 1`:
the (i, j) and (j, i) cells for `i ∈ [istart, n)` and `j ∈ [i+1, n)`. -/

@[reducible]
def innerLoopSwapped (n i lo k l : Nat) : Bool :=
  (decide (k = i) && decide (lo ≤ l) && decide (l < n))
    || (decide (l = i) && decide (lo ≤ k) && decide (k < n))

@[reducible]
def outerLoopSwapped (n istart k l : Nat) : Bool :=
  decide (istart ≤ min k l) && decide (max k l < n) && decide (k ≠ l)

/-! ## `matrix_transpose_loop0_loop0` -/

/-- **Loop spec** for the inner j loop.

For fixed row `i`, iterates `j ∈ [iter.start, n_rows)`, swapping
`pm_src[i * n_rows + j]` with `pm_src[j * n_rows + i]`. The resulting
slice equals `pm_src` everywhere except on cells flagged by
`innerLoopSwapped`, which are swapped with their transpose partner.

Informal proof. `partial_fixpoint`; `apply loop.spec_decr_nat` with
measure `iter.«end».val - iter.start.val`, then `unfold` and `by_cases`
on `iter.start.val < iter.«end».val`.

- None case (`iter.start = n_rows`): `IteratorRange.next` yields
  `none`; returns `pm_src` unchanged. For all `(k, l)` with
  `k, l < n_rows`, `innerLoopSwapped n_rows i n_rows k l = false`
  (the `lo ≤ l < n_rows` condition fails when `lo = n_rows`); the
  `if` collapses to the else branch. Close with `WP.spec_ok` + `agrind`.
- Some case (`j = iter.start`, `iter1.start = j + 1`): step through
  `IteratorRange.next`. The body computes `i2 = i·n+j`, `i4 = j·n+i`;
  both in-bounds by `matrix_idx_lt` applied to `(h_i, h_j)` /
  `(h_j, h_i)`. Step through `Slice.swap` to obtain `pm_src1` with
  `pm_src1[i2] = pm_src[i4]`, `pm_src1[i4] = pm_src[i2]`, others
  unchanged. Apply IH (via `step*`) with `pm_src := pm_src1` and
  cursor `j+1`. Invariant update:
  `innerLoopSwapped n_rows i j k l ↔
   (k = i ∧ l = j) ∨ (l = i ∧ k = j) ∨ innerLoopSwapped n_rows i (j+1) k l`.
  Case-split on `(k, l)`; the just-swapped cell matches via the swap
  equations; other cells go through unchanged. Close with
  `simp [innerLoopSwapped]` + `agrind`. -/
@[step]
theorem mlkem.ntt.matrix_transpose_loop0_loop0.spec
    (iter : core.ops.range.Range Usize)
    (pm_src : Slice (PolyElement))
    (n_rows i : Usize)
    (h_n : 2 ≤ n_rows.val ∧ n_rows.val ≤ 4)
    (h_len : pm_src.length = n_rows.val * n_rows.val)
    (h_wf : wfPolyVec pm_src)
    (h_i : i.val < n_rows.val)
    (h_start : i.val < iter.start.val ∨ iter.start.val = i.val + 1)
    (h_start_le : iter.start.val ≤ n_rows.val)
    (h_end : iter.«end».val = n_rows.val) :
    mlkem.ntt.matrix_transpose_loop0_loop0 iter pm_src n_rows i
      ⦃ (r : Slice (PolyElement)) =>
          wfPolyVec r ∧
          ∃ (h_r_len : r.length = pm_src.length),
          ∀ (k l : Nat) (h_k : k < n_rows.val) (h_l : l < n_rows.val),
            toPoly (r.val[k * n_rows.val + l]'(by
                    have := h_len; have := h_r_len; have := matrix_idx_lt h_k h_l; grind))
              = if innerLoopSwapped n_rows.val i.val iter.start.val k l then
                  toPoly (pm_src.val[l * n_rows.val + k]'(by
                    have := h_len; have := matrix_idx_lt h_l h_k; grind))
                else
                  toPoly (pm_src.val[k * n_rows.val + l]'(by
                    have := h_len; have := matrix_idx_lt h_k h_l; grind)) ⦄ := by
  unfold mlkem.ntt.matrix_transpose_loop0_loop0
  by_cases hlt : iter.start.val < iter.«end».val
  · -- Some branch: j = iter.start
    let* ⟨ o, iter1, ho, hstart', hend' ⟩ ← IteratorRange_next_Usize_some
    rw [ho]
    simp only
    have hj_lt : iter.start.val < n_rows.val := by rw [← h_end]; exact hlt
    have h_n_le : n_rows.val ≤ 4 := h_n.2
    have h_ij_lt : i.val * n_rows.val < 16 := by
      have h_i_le : i.val ≤ 3 := by scalar_tac
      have : i.val * n_rows.val ≤ 3 * 4 := Nat.mul_le_mul h_i_le h_n_le
      scalar_tac
    have h_ij_le : i.val * n_rows.val ≤ Usize.max := by
      have : (16:Nat) ≤ Usize.max := by scalar_tac
      scalar_tac
    have h_jj_lt : iter.start.val * n_rows.val < 16 := by
      have h_j_le : iter.start.val ≤ 3 := by scalar_tac
      have : iter.start.val * n_rows.val ≤ 3 * 4 := Nat.mul_le_mul h_j_le h_n_le
      scalar_tac
    have h_jj_le : iter.start.val * n_rows.val ≤ Usize.max := by scalar_tac
    -- Four arithmetic steps (overflow preconds auto-discharged from above)
    let* ⟨ i1, hi1 ⟩ ← Usize.mul_spec
    let* ⟨ i2, hi2 ⟩ ← Usize.add_spec
    let* ⟨ i3, hi3 ⟩ ← Usize.mul_spec
    let* ⟨ i4, hi4 ⟩ ← Usize.add_spec
    -- Index bounds for swap
    have hi2_val : i2.val = i.val * n_rows.val + iter.start.val := by rw [hi2, hi1]
    have hi4_val : i4.val = iter.start.val * n_rows.val + i.val := by rw [hi4, hi3]
    have hi2_lt : i2.val < pm_src.length := by
      rw [hi2_val, h_len]; exact matrix_idx_lt h_i hj_lt
    have hi4_lt : i4.val < pm_src.length := by
      rw [hi4_val, h_len]; exact matrix_idx_lt hj_lt h_i
    -- Slice.swap (total-form wrapper hides partiality at the call-site
    -- interface; the internal arithmetic case-split below still uses
    -- `[_]!` as algebraic shorthand)
    let* ⟨ pm_src1, hsw_len, hsw_a, hsw_b, hsw_other ⟩ ← Bridges.Slice.swap_total.spec
    -- IH preconditions
    have h_len_new : pm_src1.length = n_rows.val * n_rows.val := by
      rw [hsw_len]; exact h_len
    have h_wf_new : wfPolyVec pm_src1 :=
      wfPolyVec_swap pm_src pm_src1 i2.val i4.val hi2_lt hi4_lt h_wf hsw_len hsw_a hsw_b hsw_other
    -- Restate the swap effect in the partial-access form used by the
    -- arithmetic case-split below.
    have hsw_a!  : pm_src1.val[i2.val]! = pm_src.val[i4.val]! := by
      rw [getElem!_pos pm_src1.val i2.val (by scalar_tac),
          getElem!_pos pm_src.val i4.val hi4_lt]; exact hsw_a
    have hsw_b!  : pm_src1.val[i4.val]! = pm_src.val[i2.val]! := by
      rw [getElem!_pos pm_src1.val i4.val (by scalar_tac),
          getElem!_pos pm_src.val i2.val hi2_lt]; exact hsw_b
    have hsw_other! : ∀ m, m ≠ i2.val → m ≠ i4.val →
        m < pm_src.length → pm_src1.val[m]! = pm_src.val[m]! := by
      intro m h_ne2 h_ne4 hm
      rw [getElem!_pos pm_src1.val m (by scalar_tac),
          getElem!_pos pm_src.val m hm]
      exact hsw_other m hm h_ne2 h_ne4
    -- General "swap-effect" equation for pm_src1
    have h_pm1_at : ∀ m, m < pm_src.length →
        pm_src1.val[m]! = if m = i2.val then pm_src.val[i4.val]!
                          else if m = i4.val then pm_src.val[i2.val]!
                          else pm_src.val[m]! := by
      intro m hm
      by_cases ha : m = i2.val
      · subst ha; simp [hsw_a!]
      · by_cases hb : m = i4.val
        · subst hb; simp [hsw_b!, ha]
        · simp [hsw_other! m ha hb hm, ha, hb]
    have h_start_new : i.val < iter1.start.val ∨ iter1.start.val = i.val + 1 := by
      rw [hstart']
      rcases h_start with h | h
      · left; scalar_tac
      · left; scalar_tac
    have h_start_le_new : iter1.start.val ≤ n_rows.val := by
      rw [hstart']; scalar_tac
    have h_end_new : iter1.«end».val = n_rows.val := by
      rw [hend']; exact h_end
    -- Recursive call
    apply WP.spec_mono
      (mlkem.ntt.matrix_transpose_loop0_loop0.spec iter1 pm_src1 n_rows i
        h_n h_len_new h_wf_new h_i h_start_new h_start_le_new h_end_new)
    rintro r ⟨ hwf_r, hr_len, hr_eq ⟩
    refine ⟨ hwf_r, ?_, ?_ ⟩
    · rw [hr_len]; exact hsw_len
    -- The big invariant: for each (k, l), the swap effect.
    intro k l h_k h_l
    have h_iter1_start_val : iter1.start.val = iter.start.val + 1 := hstart'
    have hr_eq_kl := hr_eq k l h_k h_l
    rw [h_iter1_start_val] at hr_eq_kl
    -- Index bounds for pm_src1 and pm_src
    have h_pos1_lt : k * n_rows.val + l < pm_src.length := by
      rw [h_len]; exact matrix_idx_lt h_k h_l
    have h_pos2_lt : l * n_rows.val + k < pm_src.length := by
      rw [h_len]; exact matrix_idx_lt h_l h_k
    have h_pos1_lt1 : k * n_rows.val + l < pm_src1.length := by
      rw [hsw_len]; exact h_pos1_lt
    have h_pos2_lt1 : l * n_rows.val + k < pm_src1.length := by
      rw [hsw_len]; exact h_pos2_lt
    -- Reduce pm_src1-indexed reads inside IH to pm_src-indexed (swap effect)
    have h_pm1_at_pos1 := h_pm1_at (k * n_rows.val + l) h_pos1_lt
    have h_pm1_at_pos2 := h_pm1_at (l * n_rows.val + k) h_pos2_lt
    -- The IH RHS reads pm_src1 at one of the two positions, rewrite to pm_src
    -- via h_pm1_at_*. Convert the [_]'_ form to [_]! form first.
    rw [show pm_src1.val[k * n_rows.val + l]'h_pos1_lt1 =
          pm_src1.val[k * n_rows.val + l]! from
          (getElem!_pos pm_src1.val (k * n_rows.val + l) h_pos1_lt1).symm,
        show pm_src1.val[l * n_rows.val + k]'h_pos2_lt1 =
          pm_src1.val[l * n_rows.val + k]! from
          (getElem!_pos pm_src1.val (l * n_rows.val + k) h_pos2_lt1).symm] at hr_eq_kl
    rw [h_pm1_at_pos1, h_pm1_at_pos2] at hr_eq_kl
    -- Convert pm_src.val[_]! back to .val[_]' on the goal
    rw [show pm_src.val[k * n_rows.val + l]'h_pos1_lt =
          pm_src.val[k * n_rows.val + l]! from
          (getElem!_pos pm_src.val (k * n_rows.val + l) h_pos1_lt).symm,
        show pm_src.val[l * n_rows.val + k]'h_pos2_lt =
          pm_src.val[l * n_rows.val + k]! from
          (getElem!_pos pm_src.val (l * n_rows.val + k) h_pos2_lt).symm]
    -- Now both sides are in [_]! form. Do the case analysis on
    -- innerLoopSwapped, the cell-equality conditions, and combine.
    have hi2_idx : i.val * n_rows.val + iter.start.val = i2.val := hi2_val.symm
    have hi4_idx : iter.start.val * n_rows.val + i.val = i4.val := hi4_val.symm
    have h_inj_i2 : ∀ (a b : Nat), a < n_rows.val → b < n_rows.val →
        (a * n_rows.val + b = i2.val ↔ (a = i.val ∧ b = iter.start.val)) := by
      intro a b ha hb
      rw [hi2_val]
      exact matrix_idx_inj ha hb h_i hj_lt
    have h_inj_i4 : ∀ (a b : Nat), a < n_rows.val → b < n_rows.val →
        (a * n_rows.val + b = i4.val ↔ (a = iter.start.val ∧ b = i.val)) := by
      intro a b ha hb
      rw [hi4_val]
      exact matrix_idx_inj ha hb hj_lt h_i
    -- Drive everything via grind: it can navigate the boolean if-then-else's
    -- and the iff equivalences.
    have h_inner_lo : innerLoopSwapped n_rows.val i.val iter.start.val k l = true ↔
        (k = i.val ∧ iter.start.val ≤ l ∧ l < n_rows.val) ∨
        (l = i.val ∧ iter.start.val ≤ k ∧ k < n_rows.val) := by
      simp only [innerLoopSwapped, Bool.or_eq_true, Bool.and_eq_true,
                 decide_eq_true_eq]
      grind
    have h_inner_hi : innerLoopSwapped n_rows.val i.val (iter.start.val + 1) k l = true ↔
        (k = i.val ∧ iter.start.val + 1 ≤ l ∧ l < n_rows.val) ∨
        (l = i.val ∧ iter.start.val + 1 ≤ k ∧ k < n_rows.val) := by
      simp only [innerLoopSwapped, Bool.or_eq_true, Bool.and_eq_true,
                 decide_eq_true_eq]
      grind
    -- The actual cell equation: derive from hr_eq_kl + cases.
    -- All the bookkeeping is purely propositional combinatorics on k, l ∈ [0, n_rows),
    -- pm_src values are abstract atoms. We package both LHS = RHS with grind.
    have h_eq : pm_src1.val[k * n_rows.val + l]! = pm_src.val[k * n_rows.val + l]! ∨
                pm_src1.val[k * n_rows.val + l]! = pm_src.val[l * n_rows.val + k]! := by
      rw [h_pm1_at_pos1]
      by_cases ha : k * n_rows.val + l = i2.val
      · simp [ha]; right
        rw [(h_inj_i2 k l h_k h_l).mp ha |>.1, (h_inj_i2 k l h_k h_l).mp ha |>.2]
        rw [hi4_idx]
      · simp [ha]
        by_cases hb : k * n_rows.val + l = i4.val
        · simp [hb]; right
          rw [(h_inj_i4 k l h_k h_l).mp hb |>.1, (h_inj_i4 k l h_k h_l).mp hb |>.2]
          rw [hi2_idx]
        · simp [hb]
    -- After rewrites:
    --   hr_eq_kl LHS: toPoly r[k*n+l]
    --   hr_eq_kl RHS: nested ifs over (hsw_hi, pos1=i2, pos1=i4, pos2=i2, pos2=i4)
    --   goal RHS: if hsw_lo then toPoly pm_src[l*n+k]! else toPoly pm_src[k*n+l]!
    have h_si : i.val < iter.start.val := by
      rcases h_start with h | h
      · exact h
      · scalar_tac
    have h_hi_imp_lo : innerLoopSwapped n_rows.val i.val (iter.start.val + 1) k l = true →
        innerLoopSwapped n_rows.val i.val iter.start.val k l = true := by
      intro hhi
      rw [h_inner_lo]
      rw [h_inner_hi] at hhi
      rcases hhi with ⟨a, b, c⟩ | ⟨a, b, c⟩
      · left; exact ⟨a, by omega, c⟩
      · right; exact ⟨a, by omega, c⟩
    have h_lo_not_hi : innerLoopSwapped n_rows.val i.val iter.start.val k l = true →
        innerLoopSwapped n_rows.val i.val (iter.start.val + 1) k l = false →
        (k = i.val ∧ l = iter.start.val) ∨ (l = i.val ∧ k = iter.start.val) := by
      intro hlo hhi
      rw [h_inner_lo] at hlo
      have hhi' : ¬ innerLoopSwapped n_rows.val i.val (iter.start.val + 1) k l = true := by
        rw [hhi]; decide
      rw [h_inner_hi] at hhi'
      push Not at hhi'
      rcases hlo with ⟨hk, hge, _⟩ | ⟨hl, hge, _⟩
      · left; refine ⟨hk, ?_⟩
        by_contra hne
        have hl_ge : n_rows.val ≤ l := hhi'.1 hk (by omega)
        omega
      · right; refine ⟨hl, ?_⟩
        by_contra hne
        have hk_ge : n_rows.val ≤ k := hhi'.2 hl (by omega)
        omega
    rw [hr_eq_kl]
    by_cases hsw_lo : innerLoopSwapped n_rows.val i.val iter.start.val k l = true
    · -- hsw_lo = true
      rw [if_pos hsw_lo]
      by_cases hsw_hi : innerLoopSwapped n_rows.val i.val (iter.start.val + 1) k l = true
      · -- hsw_hi = true: hr_eq_kl picks pos2 branch with the nested ifs
        rw [if_pos hsw_hi]
        apply congrArg toPoly
        -- Goal: nested-if over (pos2=i2, pos2=i4) = pm_src[l*n+k]!
        rw [h_inner_hi] at hsw_hi
        have h_ne_i2 : l * n_rows.val + k ≠ i2.val := by
          intro heq
          have ⟨ha, hb⟩ := (h_inj_i2 l k h_l h_k).mp heq
          rcases hsw_hi with ⟨c, d, _⟩ | ⟨c, d, _⟩ <;> omega
        have h_ne_i4 : l * n_rows.val + k ≠ i4.val := by
          intro heq
          have ⟨ha, hb⟩ := (h_inj_i4 l k h_l h_k).mp heq
          rcases hsw_hi with ⟨c, d, _⟩ | ⟨c, d, _⟩ <;> omega
        rw [if_neg h_ne_i2, if_neg h_ne_i4]
      · -- hsw_lo = true, hsw_hi = false: swap row case
        have hsw_hi_false :
            innerLoopSwapped n_rows.val i.val (iter.start.val + 1) k l = false := by
          cases hh : innerLoopSwapped n_rows.val i.val (iter.start.val + 1) k l with
          | true => exact absurd hh hsw_hi
          | false => rfl
        rw [if_neg hsw_hi]
        apply congrArg toPoly
        -- Goal: nested-if over (pos1=i2, pos1=i4) = pm_src[l*n+k]!
        rcases h_lo_not_hi hsw_lo hsw_hi_false with ⟨hk_eq, hl_eq⟩ | ⟨hl_eq, hk_eq⟩
        · subst hk_eq; subst hl_eq
          have h_pos1_eq : i.val * n_rows.val + iter.start.val = i2.val := hi2_idx
          rw [if_pos h_pos1_eq]
          rw [hi4_idx]
        · subst hl_eq; subst hk_eq
          have h_pos1_eq : iter.start.val * n_rows.val + i.val = i4.val := hi4_idx
          have h_pos1_ne_i2 : iter.start.val * n_rows.val + i.val ≠ i2.val := by
            intro heq
            have ⟨ha, hb⟩ := (h_inj_i2 iter.start.val i.val hj_lt h_i).mp heq
            omega
          rw [if_neg h_pos1_ne_i2, if_pos h_pos1_eq]
          rw [hi2_idx]
    · -- hsw_lo = false
      have hsw_lo_false :
          innerLoopSwapped n_rows.val i.val iter.start.val k l = false := by
        cases hh : innerLoopSwapped n_rows.val i.val iter.start.val k l with
        | true => exact absurd hh hsw_lo
        | false => rfl
      have hsw_hi_false :
          innerLoopSwapped n_rows.val i.val (iter.start.val + 1) k l = false := by
        cases hh : innerLoopSwapped n_rows.val i.val (iter.start.val + 1) k l with
        | true => exact absurd (h_hi_imp_lo hh) hsw_lo
        | false => rfl
      have hsw_hi_ne :
          ¬ innerLoopSwapped n_rows.val i.val (iter.start.val + 1) k l = true := by
        rw [hsw_hi_false]; decide
      rw [if_neg hsw_lo, if_neg hsw_hi_ne]
      apply congrArg toPoly
      -- Goal: nested-if over (pos1=i2, pos1=i4) = pm_src[k*n+l]!
      have h_ne_i2 : k * n_rows.val + l ≠ i2.val := by
        intro heq
        have ⟨ha, hb⟩ := (h_inj_i2 k l h_k h_l).mp heq
        rw [h_inner_lo] at hsw_lo
        apply hsw_lo
        left; exact ⟨ha, by omega, h_l⟩
      have h_ne_i4 : k * n_rows.val + l ≠ i4.val := by
        intro heq
        have ⟨ha, hb⟩ := (h_inj_i4 k l h_k h_l).mp heq
        rw [h_inner_lo] at hsw_lo
        apply hsw_lo
        right; exact ⟨hb, by omega, h_k⟩
      rw [if_neg h_ne_i2, if_neg h_ne_i4]
  · -- None branch
    have h_start_eq : iter.start.val = n_rows.val := by
      have := h_end; have := h_start_le; scalar_tac
    let* ⟨ o, iter1, hnone, _ ⟩ ← IteratorRange_next_Usize_none
    rw [hnone]
    simp only [WP.spec_ok]
    refine ⟨ h_wf, ?_ ⟩
    refine ⟨ trivial, ?_ ⟩
    intro k l h_k h_l
    have h_inner_false : innerLoopSwapped n_rows.val i.val iter.start.val k l = false := by
      simp only [innerLoopSwapped, h_start_eq]
      grind
    rw [h_inner_false]; simp
termination_by iter.«end».val - iter.start.val
decreasing_by scalar_decr_tac

/-! ## `matrix_transpose_loop0` -/

/-- **Loop spec** for the outer i loop. Completes all swaps with row
index `≥ iter.start`.

Informal proof. `partial_fixpoint`; `apply loop.spec_decr_nat` with
measure `iter.«end».val - iter.start.val`; `unfold`; `by_cases`.

- None case (`iter.start = n_rows`): returns `pm_src`. For all
  `k, l < n_rows`, `outerLoopSwapped n_rows n_rows k l = false`
  (`n_rows ≤ min(k,l)` fails). The conditional collapses; close with
  `WP.spec_ok` + `agrind`.
- Some case (`i = iter.start`, `iter1.start = i + 1`): step through
  `IteratorRange.next`. Apply `matrix_transpose_loop0_loop0.spec`
  with inner cursor `i+1` to obtain `pm_src1` with the
  inner-swap-flag conjunction. Apply outer IH (via `step*`) with
  `pm_src := pm_src1` and cursor `i+1`. Decompose
  `outerLoopSwapped n_rows i k l ↔
   (min(k,l) = i ∧ max(k,l) < n_rows ∧ k ≠ l) ∨
   outerLoopSwapped n_rows (i+1) k l`. Three sub-cases:
  - `min(k,l) = i`, `k ≠ l`: inner-swapped at this row; outer-IH
    sees `outerLoopSwapped n_rows (i+1) k l = false`, so reads
    `pm_src1[k·n+l] = pm_src[l·n+k]`. ✓
  - `min(k,l) > i`: untouched by inner; outer-IH handles directly. ✓
  - `k = l` (diagonal): `outerLoopSwapped n_rows i k k = false`,
    diagonal never swapped. ✓
  Close with `simp [outerLoopSwapped, innerLoopSwapped]` + `agrind`. -/
theorem mlkem.ntt.matrix_transpose_loop0.spec
    (iter : core.ops.range.Range Usize)
    (pm_src : Slice (PolyElement))
    (n_rows : Usize)
    (h_n : 2 ≤ n_rows.val ∧ n_rows.val ≤ 4)
    (h_len : pm_src.length = n_rows.val * n_rows.val)
    (h_wf : wfPolyVec pm_src)
    (h_start : iter.start.val ≤ n_rows.val) (h_end : iter.«end».val = n_rows.val) :
    mlkem.ntt.matrix_transpose_loop0 iter pm_src n_rows
      ⦃ (r : Slice (PolyElement)) =>
          wfPolyVec r ∧
          ∃ (h_r_len : r.length = pm_src.length),
          ∀ (k l : Nat) (h_k : k < n_rows.val) (h_l : l < n_rows.val),
            toPoly (r.val[k * n_rows.val + l]'(by
                    have := h_len; have := h_r_len; have := matrix_idx_lt h_k h_l; grind))
              = if outerLoopSwapped n_rows.val iter.start.val k l then
                  toPoly (pm_src.val[l * n_rows.val + k]'(by
                    have := h_len; have := matrix_idx_lt h_l h_k; grind))
                else
                  toPoly (pm_src.val[k * n_rows.val + l]'(by
                    have := h_len; have := matrix_idx_lt h_k h_l; grind)) ⦄ := by
  unfold mlkem.ntt.matrix_transpose_loop0
  by_cases hlt : iter.start.val < iter.«end».val
  · -- Some branch: i = iter.start
    let* ⟨ o, iter1, ho, hstart', hend' ⟩ ← IteratorRange_next_Usize_some
    rw [ho]
    simp only
    have h_i_lt : iter.start.val < n_rows.val := by rw [← h_end]; exact hlt
    have h_i_succ_le : iter.start.val + 1 ≤ n_rows.val := by omega
    have h_i_succ_le_max : iter.start.val + 1 ≤ Usize.max := by
      have : (4:Nat) ≤ Usize.max := by scalar_tac
      omega
    -- i1 = i + 1
    let* ⟨ i1, hi1 ⟩ ← Usize.add_spec
    -- Inner loop: process row iter.start with cursor j ∈ [i+1, n_rows)
    have h_inner_start : iter.start.val < i1.val ∨ i1.val = iter.start.val + 1 := by
      right; rw [hi1]
    have h_inner_start_le : i1.val ≤ n_rows.val := by rw [hi1]; exact h_i_succ_le
    let* ⟨ pm_src1, h_wf1, h_r_len1, h_inner_eq ⟩ ←
      mlkem.ntt.matrix_transpose_loop0_loop0.spec
    -- IH preconditions
    have h_len_new : pm_src1.length = n_rows.val * n_rows.val := by
      rw [h_r_len1]; exact h_len
    have h_start_new_le : iter1.start.val ≤ n_rows.val := by
      rw [hstart']; scalar_tac
    have h_end_new : iter1.«end».val = n_rows.val := by
      rw [hend']; exact h_end
    -- Recursive call: outer loop continues from iter1.start
    apply WP.spec_mono
      (mlkem.ntt.matrix_transpose_loop0.spec iter1 pm_src1 n_rows
        h_n h_len_new h_wf1 h_start_new_le h_end_new)
    rintro r ⟨ hwf_r, hr_len, hr_eq ⟩
    refine ⟨ hwf_r, ?_, ?_ ⟩
    · rw [hr_len]; exact h_r_len1
    intro k l h_k h_l
    -- hr_eq gives r[k*n+l] in terms of pm_src1 via outerLoopSwapped at iter1.start
    rw [hr_eq k l h_k h_l]
    -- h_inner_eq gives pm_src1 in terms of pm_src via innerLoopSwapped at i1 = iter.start+1
    have h_i1_eq : i1.val = iter.start.val + 1 := hi1
    rw [show iter1.start.val = iter.start.val + 1 from by rw [hstart']]
    -- Goal: ... outerLoopSwapped n_rows (iter.start+1) k l ... = ... outerLoopSwapped n_rows iter.start k l ...
    -- Both branches of outer involve pm_src1, which we rewrite via h_inner_eq
    rw [h_inner_eq l k h_l h_k, h_inner_eq k l h_k h_l]
    rw [h_i1_eq]
    -- Now everything is in terms of pm_src.
    -- The key arithmetic facts:
    have h_outer_iff : ∀ (s k l : Nat),
        outerLoopSwapped n_rows.val s k l = true ↔
        s ≤ min k l ∧ max k l < n_rows.val ∧ k ≠ l := by
      intro s k l
      simp only [outerLoopSwapped, Bool.and_eq_true, decide_eq_true_eq]
      constructor
      · rintro ⟨⟨a, b⟩, c⟩; exact ⟨a, b, c⟩
      · rintro ⟨a, b, c⟩; exact ⟨⟨a, b⟩, c⟩
    have h_inner_iff : ∀ (s lo k l : Nat),
        innerLoopSwapped n_rows.val s lo k l = true ↔
        (k = s ∧ lo ≤ l ∧ l < n_rows.val) ∨ (l = s ∧ lo ≤ k ∧ k < n_rows.val) := by
      intro s lo k l
      simp only [innerLoopSwapped, Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq]
      constructor
      · rintro (⟨⟨a, b⟩, c⟩ | ⟨⟨a, b⟩, c⟩) <;> [left; right] <;> exact ⟨a, b, c⟩
      · rintro (⟨a, b, c⟩ | ⟨a, b, c⟩) <;> [left; right] <;> exact ⟨⟨a, b⟩, c⟩
    by_cases h_new : outerLoopSwapped n_rows.val (iter.start.val + 1) k l = true
    · -- outer_new = true ⇒ k, l ≥ iter.start+1, k ≠ l
      have h_new' := (h_outer_iff _ _ _).mp h_new
      have h_old : outerLoopSwapped n_rows.val iter.start.val k l = true := by
        apply (h_outer_iff _ _ _).mpr
        exact ⟨by omega, h_new'.2.1, h_new'.2.2⟩
      have h_inn_lk : innerLoopSwapped n_rows.val iter.start.val (iter.start.val + 1) l k = false := by
        cases hh : innerLoopSwapped n_rows.val iter.start.val (iter.start.val + 1) l k with
        | true =>
          exfalso
          have := (h_inner_iff _ _ _ _).mp hh
          rcases this with ⟨a, _, _⟩ | ⟨a, _, _⟩ <;> omega
        | false => rfl
      rw [if_pos h_new, if_pos h_old, h_inn_lk]
      simp
    · -- outer_new = false
      have h_new_false : outerLoopSwapped n_rows.val (iter.start.val + 1) k l = false := by
        cases hh : outerLoopSwapped n_rows.val (iter.start.val + 1) k l with
        | true => exact absurd hh h_new
        | false => rfl
      rw [if_neg h_new]
      by_cases h_old : outerLoopSwapped n_rows.val iter.start.val k l = true
      · rw [if_pos h_old]
        have h_old' := (h_outer_iff _ _ _).mp h_old
        have h_new_false' : ¬ (iter.start.val + 1 ≤ min k l ∧ max k l < n_rows.val ∧ k ≠ l) := by
          intro h
          exact h_new ((h_outer_iff _ _ _).mpr h)
        have h_min_eq : min k l = iter.start.val := by
          have : iter.start.val ≤ min k l := h_old'.1
          by_contra hne
          exact h_new_false' ⟨by omega, h_old'.2.1, h_old'.2.2⟩
        by_cases hkl : k ≤ l
        · have hk_eq : k = iter.start.val := by omega
          have hl_gt : iter.start.val + 1 ≤ l := by
            have := h_old'.2.2; omega
          have hl_lt : l < n_rows.val := by have := h_old'.2.1; omega
          have h_inn_kl : innerLoopSwapped n_rows.val iter.start.val (iter.start.val + 1) k l = true := by
            apply (h_inner_iff _ _ _ _).mpr; left; exact ⟨hk_eq, hl_gt, hl_lt⟩
          rw [h_inn_kl]; simp
        · have hl_eq : l = iter.start.val := by omega
          have hk_gt : iter.start.val + 1 ≤ k := by
            have := h_old'.2.2; omega
          have hk_lt : k < n_rows.val := by have := h_old'.2.1; omega
          have h_inn_kl : innerLoopSwapped n_rows.val iter.start.val (iter.start.val + 1) k l = true := by
            apply (h_inner_iff _ _ _ _).mpr; right; exact ⟨hl_eq, hk_gt, hk_lt⟩
          rw [h_inn_kl]; simp
      · rw [if_neg h_old]
        have h_inn_kl : innerLoopSwapped n_rows.val iter.start.val (iter.start.val + 1) k l = false := by
          cases hh : innerLoopSwapped n_rows.val iter.start.val (iter.start.val + 1) k l with
          | true =>
            exfalso
            apply h_old
            apply (h_outer_iff _ _ _).mpr
            rcases (h_inner_iff _ _ _ _).mp hh with ⟨a, b, c⟩ | ⟨a, b, c⟩
            · refine ⟨?_, ?_, ?_⟩
              · rw [a]; omega
              · omega
              · omega
            · refine ⟨?_, ?_, ?_⟩
              · rw [a]; omega
              · omega
              · omega
          | false => rfl
        rw [h_inn_kl]; simp
  · -- None branch
    have h_start_eq : iter.start.val = n_rows.val := by
      have := h_end; scalar_tac
    let* ⟨ o, iter1, hnone, _ ⟩ ← IteratorRange_next_Usize_none
    rw [hnone]
    simp only [WP.spec_ok]
    refine ⟨ h_wf, ?_ ⟩
    refine ⟨ trivial, ?_ ⟩
    intro k l h_k h_l
    have h_outer_false : outerLoopSwapped n_rows.val iter.start.val k l = false := by
      unfold outerLoopSwapped
      have h_not : ¬ iter.start.val ≤ min k l := by
        rw [h_start_eq]
        have hmin_le : min k l ≤ k := Nat.min_le_left _ _
        omega
      have hdec : decide (iter.start.val ≤ min k l) = false := by
        rw [decide_eq_false_iff_not]
        exact h_not
      rw [hdec]
      rfl
    rw [h_outer_false]
    simp only [Bool.false_eq_true, if_false]
termination_by iter.«end».val - iter.start.val
decreasing_by scalar_decr_tac

/-! ## Top wrapper -/

/-- **Top spec for `matrix_transpose`**.

Postcondition: the resulting matrix is the transpose:
`r[i * n + j] = pm_src[j * n + i]` for all `i, j ∈ [0, n)`.

Informal proof.
1. Cast `n_rows : U8` to `n_rows1 : Usize` via `lift (UScalar.cast .Usize n_rows)`;
   no overflow since `n_rows.val ≤ 4`. Step through the cast + `massert` checks.
2. Apply `matrix_transpose_loop0.spec` with cursor `0..n_rows1`,
   yielding the per-cell equation gated by
   `outerLoopSwapped n_rows1 0 k l`.
3. Simplify the gate: for `k, l < n_rows1`,
   `outerLoopSwapped n_rows1 0 k l = (k ≠ l)`. Two sub-cases:
   - `k ≠ l`: `outerLoopSwapped = true` ⇒ `r[k·n+l] = pm_src[l·n+k]`. ✓
   - `k = l`: `outerLoopSwapped = false` ⇒ `r[k·n+k] = pm_src[k·n+k]`
     (both sides identical). ✓
Close with `step*` + `simp [outerLoopSwapped]` + `agrind`. -/
@[step]
theorem mlkem.ntt.matrix_transpose.spec
    (pm_src : Slice (PolyElement))
    (n_rows : U8)
    (h_n : 2 ≤ n_rows.val ∧ n_rows.val ≤ 4)
    (h_len : pm_src.length = n_rows.val * n_rows.val)
    (h_wf : wfPolyVec pm_src) :
    mlkem.ntt.matrix_transpose pm_src n_rows
      ⦃ (r : Slice (PolyElement)) =>
          wfPolyVec r ∧
          ∃ (h_r_len : r.length = pm_src.length),
          ∀ (i j : Nat) (h_i : i < n_rows.val) (h_j : j < n_rows.val),
            toPoly (r.val[i * n_rows.val + j]'(by
                    have := h_len; have := h_r_len; have := matrix_idx_lt h_i h_j; grind))
              = toPoly (pm_src.val[j * n_rows.val + i]'(by
                    have := h_len; have := matrix_idx_lt h_j h_i; grind)) ⦄ := by
  unfold mlkem.ntt.matrix_transpose
  step*
  · unfold mlkem.ntt.MATRIX_MIN_NROWS; scalar_tac
  · unfold mlkem.ntt.MATRIX_MAX_NROWS; scalar_tac
  step with matrix_transpose_loop0.spec as ⟨r, r_post1, r_post2, r_post3⟩
  have h_r_len := r_post2
  have hr_eq := r_post3
  refine ⟨ r_post1, h_r_len, ?_ ⟩
  intro i j h_i h_j
  have h_i' : i < n_rows1.val := by rw [n_rows1_post]; exact h_i
  have h_j' : j < n_rows1.val := by rw [n_rows1_post]; exact h_j
  have hr := hr_eq i j h_i' h_j'
  have h_ij_lt : i * n_rows.val + j < r.val.length := by
    have := h_r_len; have := h_len; have := matrix_idx_lt h_i h_j
    grind
  have h_ji_lt : j * n_rows.val + i < pm_src.val.length := by
    have := h_len; have := matrix_idx_lt h_j h_i; grind
  have h_ii_lt : i * n_rows.val + j < pm_src.val.length := by
    have := h_len; have := matrix_idx_lt h_i h_j; grind
  by_cases hij : i = j
  · have h_outer_false : outerLoopSwapped (↑n_rows1) 0 i j = false := by
      unfold outerLoopSwapped
      rw [hij]
      simp only [ne_eq, not_true_eq_false, decide_false, Bool.and_false]
    rw [h_outer_false] at hr
    rw [if_neg (by decide)] at hr
    subst hij
    convert hr using 3 <;> first | rfl | (simp only [n_rows1_post])
  · have h_outer_true : outerLoopSwapped (↑n_rows1) 0 i j = true := by
      unfold outerLoopSwapped
      have hdec0 : decide (0 ≤ min i j) = true := by
        rw [decide_eq_true_eq]
        exact Nat.zero_le _
      have hdec1 : decide (max i j < ↑n_rows1) = true := by
        rw [decide_eq_true_eq]
        omega
      have hdec2 : decide (i ≠ j) = true := by
        rw [decide_eq_true_eq]
        exact hij
      rw [hdec0, hdec1, hdec2]
      rfl
    rw [h_outer_true] at hr
    rw [if_pos (by decide)] at hr
    convert hr using 3 <;> first | rfl | (simp only [n_rows1_post])

end Symcrust.Properties.MLKEM
