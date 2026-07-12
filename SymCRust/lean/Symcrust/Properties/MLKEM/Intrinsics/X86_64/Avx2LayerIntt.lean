/-
  # Intrinsics/X86_64/Avx2LayerIntt.lean — INTT AVX2 layer specs.

  Split out of `Avx2LayerNtt.lean`, which exposes the shared
  helper specs (mod_add, mod_sub, mont_mul, mm256_load, mm256_store).
-/
import Symcrust.Properties.MLKEM.Intrinsics.X86_64.Avx2LayerNtt

open Aeneas Aeneas.Std Result
open Symcrust Spec.MLKEM
open symcrust
open Symcrust.Properties.MLKEM
open Symcrust.Properties.MLKEM.Bridges
open Intrinsics.X86_64 (m256)

namespace Symcrust.Properties.MLKEM.Intrinsics

/-! ## §4.  INTT loop layer specs.

    Symmetric to NTT: same three-level recursion, Gentleman-Sande
    butterfly (multiply happens **after** subtraction).  Posts use
    `inttButterflies` / `inttMidLayer`. -/

/-! ### `#decompose` carve-out: AVX2 INTT inner-loop per-iteration body

Mirror of the AVX2 NTT cascade above (§3).  Two-stage `#decompose`:
extract the trailing ite as `_step`, then extract the first 10 bindings
of the then-branch (load×2 + mod_add + mod_sub + mont_mul + store×2 +
arithmetic — note Gentleman-Sande's add-sub-then-mul order) as
`_butterfly`, leaving the recursive call outside the helper. -/

set_option maxRecDepth 2048 in
#decompose mlkem.ntt.ntt_avx2.intt_layer_avx2_loop0_loop0
    intt_layer_avx2_loop0_loop0.fold
  letRange 1 1 => intt_layer_avx2_loop0_loop0_step

set_option maxRecDepth 2048 in
#decompose intt_layer_avx2_loop0_loop0_step
    intt_layer_avx2_loop0_loop0_step.fold
  branch 0 (letRange 0 10) => intt_layer_avx2_loop0_loop0_butterfly

/-- INFORMAL PROOF.  Per-iteration AVX2 INTT (Gentleman-Sande) butterfly,
    16 lanes.  Pure SIMD body (no recursion) extracted by the
    `#decompose` cascade above.  Body order:
    ```
    let i1 ← start + j
    let v_c0 ← mm256_load pe i1
    let i2 ← i1 + len
    let v_c1 ← mm256_load pe i2
    let v_new_c0 ← mod_add_avx2 v_c0 v_c1
    let v_diff   ← mod_sub_avx2 v_c1 v_c0
    let v_new_c1 ← mont_mul_avx2 v_diff v_tw v_tw_mont
    let pe1 ← mm256_store pe i1 v_new_c0
    let i3 ← i1 + len
    mm256_store pe1 i3 v_new_c1
    ```
    Spec: post equates `toPoly r` to `inttButterflies` applied once at
    indices `[start+j .. start+j+16)` and `[start+j+len .. start+j+len+16)`.
    Frame and `wfPoly` as for the NTT butterfly. -/
@[local step]
theorem intt_layer_avx2_loop0_loop0_butterfly.spec
    (pe : PolyElement)
    (len start : Std.Usize)
    (v_tw v_tw_mont : m256)
    (j : Std.Usize)
    (h_wf : wfPoly pe)
    (h_len_pos : 16 ≤ len.val)
    (h_len_le : len.val ≤ 128)
    (h_bound : start.val + 2 * len.val ≤ 256)
    (h_j_lt : j.val + 16 ≤ len.val)
    (h_j_step : j.val % 16 = 0)
    (h_len_step : len.val % 16 = 0)
    (tw : Std.U16) (_h_tw_lt : tw.val < q)
    (h_v_tw_wf : wfVecYmm v_tw)
    (h_v_tw_lane : ∀ i : Fin 16, (toLanesYmm v_tw)[i.val] = tw)
    (tw_mont : Std.U16) (h_tw_mont_eq : tw_mont.val = (tw.val * 3327) % 65536)
    (h_v_tw_mont_lane : ∀ i : Fin 16,
      ((toLanesYmm v_tw_mont)[i.val].val : ℕ) = tw_mont.val) :
    intt_layer_avx2_loop0_loop0_butterfly pe len start v_tw v_tw_mont j
    ⦃ (r : PolyElement) =>
        wfPoly r ∧
        toPoly r =
          inttButterflies (u16ToZq tw * Rinv)
              (toPoly pe) len.val
              (start.val + j.val)
              (start.val + j.val + 16)
              (by have := h_bound; have := h_j_lt; grind) ⦄ := by
  unfold intt_layer_avx2_loop0_loop0_butterfly
  -- start + j : Usize
  step as ⟨i1, h_i1⟩
  -- v_c0 ← mm256_load pe i1
  step as ⟨v_c0, h_v_c0_wf, h_v_c0_lane⟩
  -- i1 + len : Usize → i2 = start + j + len
  step as ⟨i2, h_i2⟩
  -- v_c1 ← mm256_load pe i2
  step as ⟨v_c1, h_v_c1_wf, h_v_c1_lane⟩
  -- v_new_c0 ← mod_add_avx2 v_c0 v_c1  (Gentleman-Sande sum, no twiddle)
  step as ⟨v_new_c0, h_v_new_c0_wf, h_v_new_c0_lane⟩
  -- v_diff ← mod_sub_avx2 v_c1 v_c0    (Gentleman-Sande diff, NOTE order: c1 first)
  step as ⟨v_diff, h_v_diff_wf, h_v_diff_lane⟩
  -- v_new_c1 ← mont_mul_avx2 v_diff v_tw v_tw_mont
  step as ⟨v_new_c1, h_v_new_c1_wf, h_v_new_c1_lane⟩
  -- pe1 ← mm256_store pe i1 v_new_c0
  step as ⟨pe1, h_pe1_len, h_pe1_wf, h_pe1_lane⟩
  -- i3 ← i1 + len (= i2)
  step as ⟨i3, h_i3⟩
  -- mm256_store pe1 i3 v_new_c1
  step as ⟨pe2, h_pe2_len, h_pe2_wf, h_pe2_lane⟩
  refine ⟨h_pe2_wf, ?_⟩
  -- Bridge via `inttButterflies_eq_parallel` with `W = 16`.
  have h_i3_val : i3.val = start.val + j.val + len.val := by
    rw [h_i3, h_i1]
  have h_i2_val : i2.val = start.val + j.val + len.val := by
    rw [h_i2, h_i1]
  have h_i1_val : i1.val = start.val + j.val := h_i1
  have h_i3_ge : i3.val ≥ start.val + j.val + 16 := by
    rw [h_i3_val]; have := h_j_lt; omega
  have h_pe_arr_len : pe.val.length = 256 := by
    have := pe.property; grind
  have h_pe1_arr_len : pe1.val.length = 256 := h_pe1_len
  have h_pe2_arr_len : pe2.val.length = 256 := h_pe2_len
  have h_toPoly_get : ∀ (a : PolyElement) (k : Nat) (hk : k < 256)
      (hl : a.val.length = 256),
      (toPoly a)[k]'hk = u16ToZq (a.val[k]'(by rw [hl]; exact hk)) := by
    intros a k hk hl
    unfold toPoly
    simp [Vector.getElem_ofFn]
  apply inttButterflies_eq_parallel
    (u16ToZq tw * Rinv) len.val (by omega) (toPoly pe) (toPoly pe2)
    (start.val + j.val) (start.val + j.val + 16)
    (by have := h_bound; have := h_j_lt; omega)
    (by omega) (by have := h_j_lt; omega)
  · -- h_pair_lo: for k ∈ [start+j, start+j+16),
    --   (toPoly pe2)[k] = (toPoly pe)[k] + (toPoly pe)[k+len]
    intro k hk_lo hk_hi
    have hk : k < 256 := by have := h_bound; have := h_j_lt; omega
    have hk_len : k + len.val < 256 := by have := h_bound; have := h_j_lt; omega
    -- pe2[k] = pe1[k] (since k < i3)
    have h_pe2_at_k :
        pe2.val[k]'(by rw [h_pe2_len]; exact hk) =
          pe1.val[k]'(by rw [h_pe1_len]; exact hk) := by
      have := h_pe2_lane ⟨k, hk⟩
      simp at this
      rw [this]
      split_ifs with h
      · exfalso
        have : i3.val ≤ k := h.1
        have := h_i3_ge
        omega
      · rfl
    -- pe1[k] = (toLanesYmm v_new_c0)[k - i1]
    have hk_ge_i1 : i1.val ≤ k := by rw [h_i1_val]; exact hk_lo
    have hk_lt_i1_16 : k < i1.val + 16 := by rw [h_i1_val]; exact hk_hi
    have h_kdiff_lt : k - i1.val < 16 := by omega
    have h_pe1_at_k :
        pe1.val[k]'(by rw [h_pe1_len]; exact hk) =
          (toLanesYmm v_new_c0)[k - i1.val]'h_kdiff_lt := by
      have := h_pe1_lane ⟨k, hk⟩
      simp at this
      rw [this]
      split_ifs with h
      · rfl
      · exfalso; exact h ⟨hk_ge_i1, hk_lt_i1_16⟩
    rw [h_toPoly_get pe2 k hk h_pe2_arr_len,
        h_toPoly_get pe k hk h_pe_arr_len,
        h_toPoly_get pe (k + len.val) hk_len h_pe_arr_len]
    rw [h_pe2_at_k, h_pe1_at_k]
    -- v_new_c0[k-i1] = v_c0[k-i1] + v_c1[k-i1]
    have h_new_c0_eq :
        u16ToZq ((toLanesYmm v_new_c0)[k - i1.val]'h_kdiff_lt) =
          u16ToZq ((toLanesYmm v_c0)[k - i1.val]'h_kdiff_lt) +
          u16ToZq ((toLanesYmm v_c1)[k - i1.val]'h_kdiff_lt) := by
      have := h_v_new_c0_lane ⟨k - i1.val, h_kdiff_lt⟩
      simp at this
      unfold u16ToZq
      exact_mod_cast this
    rw [h_new_c0_eq]
    have h_v_c0_at : (toLanesYmm v_c0)[k - i1.val]'h_kdiff_lt =
        pe.val[i1.val + (k - i1.val)]'(by rw [h_pe_arr_len]; omega) := by
      have := h_v_c0_lane ⟨k - i1.val, h_kdiff_lt⟩
      simp at this
      exact this
    have h_v_c1_at : (toLanesYmm v_c1)[k - i1.val]'h_kdiff_lt =
        pe.val[i2.val + (k - i1.val)]'(by rw [h_pe_arr_len]; omega) := by
      have := h_v_c1_lane ⟨k - i1.val, h_kdiff_lt⟩
      simp at this
      exact this
    have h_i1_plus : i1.val + (k - i1.val) = k := by omega
    have h_i2_plus : i2.val + (k - i1.val) = k + len.val := by
      rw [h_i2_val]; rw [h_i1_val] at hk_ge_i1; omega
    rw [h_v_c0_at, h_v_c1_at]
    simp only [h_i1_plus, h_i2_plus]
  · -- h_pair_hi: for k ∈ [start+j, start+j+16),
    --   (toPoly pe2)[k+len] = (u16ToZq tw * Rinv) * ((toPoly pe)[k+len] - (toPoly pe)[k])
    intro k hk_lo hk_hi
    have hk : k < 256 := by have := h_bound; have := h_j_lt; omega
    have hk_len : k + len.val < 256 := by have := h_bound; have := h_j_lt; omega
    -- pe2[k+len] = (toLanesYmm v_new_c1)[(k+len) - i3]
    have hkl_ge_i3 : i3.val ≤ k + len.val := by rw [h_i3_val]; have := h_i1_val; omega
    have hkl_lt_i3_16 : k + len.val < i3.val + 16 := by rw [h_i3_val]; have := h_i1_val; omega
    have h_kdiff_lt : (k + len.val) - i3.val < 16 := by omega
    have h_pe2_at_kl :
        pe2.val[k + len.val]'(by rw [h_pe2_len]; exact hk_len) =
          (toLanesYmm v_new_c1)[(k + len.val) - i3.val]'h_kdiff_lt := by
      have := h_pe2_lane ⟨k + len.val, hk_len⟩
      simp at this
      rw [this]
      split_ifs with h
      · rfl
      · exfalso; exact h ⟨hkl_ge_i3, hkl_lt_i3_16⟩
    -- Convert (k+len)-i3 = k-i1 since i3 = i1+len.
    have h_kdiff_eq : (k + len.val) - i3.val = k - i1.val := by
      rw [h_i3_val]; rw [h_i1_val] at *; omega
    have hk_ge_i1 : i1.val ≤ k := by rw [h_i1_val]; exact hk_lo
    have hk_lt_i1_16 : k < i1.val + 16 := by rw [h_i1_val]; exact hk_hi
    have h_kdiff_lt' : k - i1.val < 16 := by omega
    rw [h_toPoly_get pe2 (k + len.val) hk_len h_pe2_arr_len,
        h_toPoly_get pe k hk h_pe_arr_len,
        h_toPoly_get pe (k + len.val) hk_len h_pe_arr_len]
    rw [h_pe2_at_kl]
    simp only [h_kdiff_eq]
    -- v_new_c1[k-i1] = v_diff[k-i1] * tw * Rinv  (from mont_mul post)
    have h_new_c1_eq :
        u16ToZq ((toLanesYmm v_new_c1)[k - i1.val]'h_kdiff_lt') =
          u16ToZq ((toLanesYmm v_diff)[k - i1.val]'h_kdiff_lt') *
          u16ToZq ((toLanesYmm v_tw)[k - i1.val]'h_kdiff_lt') * Rinv := by
      have := h_v_new_c1_lane ⟨k - i1.val, h_kdiff_lt'⟩
      simp at this
      unfold u16ToZq
      exact_mod_cast this
    rw [h_new_c1_eq]
    -- v_diff[k-i1] = v_c1[k-i1] - v_c0[k-i1]  (from mod_sub post)
    have h_diff_eq :
        u16ToZq ((toLanesYmm v_diff)[k - i1.val]'h_kdiff_lt') =
          u16ToZq ((toLanesYmm v_c1)[k - i1.val]'h_kdiff_lt') -
          u16ToZq ((toLanesYmm v_c0)[k - i1.val]'h_kdiff_lt') := by
      have := h_v_diff_lane ⟨k - i1.val, h_kdiff_lt'⟩
      simp at this
      unfold u16ToZq
      exact_mod_cast this
    rw [h_diff_eq]
    have h_v_c0_at : (toLanesYmm v_c0)[k - i1.val]'h_kdiff_lt' =
        pe.val[i1.val + (k - i1.val)]'(by rw [h_pe_arr_len]; omega) := by
      have := h_v_c0_lane ⟨k - i1.val, h_kdiff_lt'⟩
      simp at this
      exact this
    have h_v_c1_at : (toLanesYmm v_c1)[k - i1.val]'h_kdiff_lt' =
        pe.val[i2.val + (k - i1.val)]'(by rw [h_pe_arr_len]; omega) := by
      have := h_v_c1_lane ⟨k - i1.val, h_kdiff_lt'⟩
      simp at this
      exact this
    have h_v_tw_at : (toLanesYmm v_tw)[k - i1.val]'h_kdiff_lt' = tw := by
      have := h_v_tw_lane ⟨k - i1.val, h_kdiff_lt'⟩
      simp at this
      exact this
    have h_i1_plus : i1.val + (k - i1.val) = k := by omega
    have h_i2_plus : i2.val + (k - i1.val) = k + len.val := by
      rw [h_i2_val]; rw [h_i1_val] at hk_ge_i1; omega
    rw [h_v_c0_at, h_v_c1_at, h_v_tw_at]
    simp only [h_i1_plus, h_i2_plus]
    ring
  · -- h_frame: outside windows, pe2[i] = pe[i]
    intro i hi h_not_lo h_not_hi
    have h_i_notin_i1 : ¬(i1.val ≤ i ∧ i < i1.val + 16) := by
      rw [h_i1_val]; exact h_not_lo
    have h_i_notin_i3 : ¬(i3.val ≤ i ∧ i < i3.val + 16) := by
      rw [h_i3_val]
      intro ⟨h1, h2⟩
      apply h_not_hi
      refine ⟨?_, ?_⟩
      · have := h_i1_val; omega
      · have := h_i1_val; omega
    have h_pe2_at_i :
        pe2.val[i]'(by rw [h_pe2_len]; exact hi) =
          pe1.val[i]'(by rw [h_pe1_len]; exact hi) := by
      have := h_pe2_lane ⟨i, hi⟩
      simp at this
      rw [this]
      split_ifs
      rfl
    have h_pe1_at_i :
        pe1.val[i]'(by rw [h_pe1_len]; exact hi) =
          pe.val[i]'(by rw [h_pe_arr_len]; exact hi) := by
      have := h_pe1_lane ⟨i, hi⟩
      simp at this
      rw [this]
      split_ifs
      rfl
    rw [h_toPoly_get pe2 i hi h_pe2_arr_len, h_toPoly_get pe i hi h_pe_arr_len]
    rw [h_pe2_at_i, h_pe1_at_i]

/-- INFORMAL PROOF.  16-lane Gentleman-Sande inner loop.  Mirror of
    `mlkem.ntt.poly_element_intt_layer_vec128_loop0_loop0.spec`
    (Vec128Layer.lean inverse-NTT section) with step 16.

    Proof structure (post-`#decompose`): mirror of
    `ntt_layer_avx2_loop0_loop0.spec` above — `rw` with both fold
    equations, `step` the prefix `let i ← j + 16`, `by_cases` on
    `i ≤ len`, then for the true arm `step` consumes `_butterfly`
    via its `@[local step]` spec and the loop recursion is handled
    by induction hypothesis; false arm closes via `inttButterflies_nil`
    after deriving `j = len` from `h_j_step % 16 = 0` and the
    contradiction with `i ≤ len`. -/
@[step]
theorem mlkem.ntt.ntt_avx2.intt_layer_avx2_loop0_loop0.spec
    (pe_src : PolyElement)
    (len start : Std.Usize)
    (v_tw v_tw_mont : m256)
    (j : Std.Usize)
    (h_wf : wfPoly pe_src)
    (h_len_pos : 16 ≤ len.val)
    (h_len_le : len.val ≤ 128)
    (h_bound : start.val + 2 * len.val ≤ 256)
    (h_j_le : j.val ≤ len.val)
    (h_j_step : j.val % 16 = 0)
    (h_len_step : len.val % 16 = 0)
    (tw : Std.U16) (h_tw_lt : tw.val < q)
    (h_v_tw_wf : wfVecYmm v_tw)
    (h_v_tw_lane : ∀ i : Fin 16, (toLanesYmm v_tw)[i.val] = tw)
    (tw_mont : Std.U16) (h_tw_mont_eq : tw_mont.val = (tw.val * 3327) % 65536)
    (h_v_tw_mont_lane : ∀ i : Fin 16,
      ((toLanesYmm v_tw_mont)[i.val].val : ℕ) = tw_mont.val) :
    mlkem.ntt.ntt_avx2.intt_layer_avx2_loop0_loop0 pe_src len start v_tw v_tw_mont j
    ⦃ (r : PolyElement) =>
        wfPoly r ∧
        toPoly r =
          inttButterflies (u16ToZq tw * Rinv)
              (toPoly pe_src) len.val
              (start.val + j.val)
              (start.val + len.val)
              (by have := h_bound; have := h_j_le; grind) ⦄ := by
  rw [intt_layer_avx2_loop0_loop0.fold]
  /- step the `let i ← j + 16` prefix. -/
  step as ⟨i, h_i⟩
  rw [intt_layer_avx2_loop0_loop0_step.fold]
  by_cases hlt : i ≤ len
  · /- ACTIVE BRANCH: j + 16 ≤ len. -/
    simp only [hlt, ↓reduceIte]
    have h_i_val : i.val = j.val + 16 := h_i
    have h_i_le : i.val ≤ len.val := hlt
    have h_j16_le : j.val + 16 ≤ len.val := by scalar_tac
    /- step the butterfly. -/
    step as ⟨pe2, h_pe2_wf, h_pe2_toPoly⟩
    /- Recursive call: build preconditions and apply WP.spec_mono. -/
    have h_i_step : i.val % 16 = 0 := by scalar_tac
    apply WP.spec_mono
      (mlkem.ntt.ntt_avx2.intt_layer_avx2_loop0_loop0.spec pe2 len start v_tw v_tw_mont i
        h_pe2_wf h_len_pos h_len_le h_bound h_i_le h_i_step h_len_step
        tw h_tw_lt h_v_tw_wf h_v_tw_lane tw_mont h_tw_mont_eq h_v_tw_mont_lane)
    rintro r ⟨h_r_wf, h_r_toPoly⟩
    refine ⟨h_r_wf, ?_⟩
    rw [h_r_toPoly]
    /- Compose: split RHS at mid = start+j+16, then rewrite
       `inttButterflies z (toPoly pe_src) len (start+j) (start+j+16) = toPoly pe2`,
       then use `start+i = start+j+16` to align. -/
    conv_rhs =>
      rw [inttButterflies_split _ _ _ (start.val + j.val) (start.val + j.val + 16)
          (start.val + len.val) (by scalar_tac) (by scalar_tac)]
      rw [← h_pe2_toPoly]
    /- Goal: inttB z (toPoly pe2) len (start+i) (start+len) _
           = inttB z (toPoly pe2) len (start+j+16) (start+len) _ -/
    fcongr 1
    scalar_tac
  · /- EMPTY BRANCH: ¬ (i ≤ len), so j = len. -/
    simp only [hlt, ↓reduceIte, WP.spec_ok]
    refine ⟨h_wf, ?_⟩
    have h_i_val : i.val = j.val + 16 := h_i
    have h_not_i_le : ¬ i.val ≤ len.val := hlt
    have h_j_eq_len : j.val = len.val := by scalar_tac
    rw [inttButterflies_nil _ _ _ _ _ _ (by scalar_tac)]
termination_by len.val - j.val
decreasing_by scalar_decr_tac

/-- INFORMAL PROOF.  Mirror of `_ntt_layer_avx2_loop0.spec`, with
    the INTT post (`inttMidLayer.1`) and decrementing twiddle counter. -/
@[step]
theorem mlkem.ntt.ntt_avx2.intt_layer_avx2_loop0.spec
    (iter : core.iter.adapters.step_by.StepBy
              (core.ops.range.Range Std.Usize))
    (pe_src : PolyElement) (k len : Std.Usize)
    (h_wf : wfPoly pe_src) (h_len : 16 ≤ len.val) (h_lend : len.val ≤ 128)
    (h_div : 256 % (2 * len.val) = 0)
    (h_len_step : len.val % 16 = 0)
    (h_inv : 2 * (k.val + 1) * len.val + iter.iter.start.val = 512)
    (h_iter_end : iter.iter.«end».val = 256)
    (h_iter_step : iter.step_by.val = 2 * len.val)
    (h_iter_start : iter.iter.start.val ≤ 256 ∧
                    iter.iter.start.val % (2 * len.val) = 0) :
    mlkem.ntt.ntt_avx2.intt_layer_avx2_loop0 iter pe_src k len
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r =
            (inttMidLayer len.val (by grind) iter.iter.start.val k.val
                (toPoly pe_src)).1 ⦄ := by
  unfold mlkem.ntt.ntt_avx2.intt_layer_avx2_loop0
  obtain ⟨h_start_le, h_start_mod⟩ := h_iter_start
  have h_2len_pos : 0 < 2 * len.val := by scalar_tac
  have h_2len_le : 2 * len.val ≤ 256 := by scalar_tac
  by_cases hlt : iter.iter.start.val < iter.iter.«end».val
  · have h_start_lt : iter.iter.start.val < 256 := by omega
    have h_sub_dvd : 2 * len.val ∣ (256 - iter.iter.start.val) :=
      Nat.dvd_sub (Nat.dvd_of_mod_eq_zero h_div)
                  (Nat.dvd_of_mod_eq_zero h_start_mod)
    have h_sub_mod : (256 - iter.iter.start.val) % (2 * len.val) = 0 :=
      Nat.dvd_iff_mod_eq_zero.mp h_sub_dvd
    have h_sub_pos : 0 < 256 - iter.iter.start.val := by omega
    have h_sub_ge_2len : 2 * len.val ≤ 256 - iter.iter.start.val := by
      rcases Nat.lt_or_ge (256 - iter.iter.start.val) (2 * len.val) with hlt2 | hge2
      · exfalso
        have := Nat.eq_zero_of_dvd_of_lt (Nat.dvd_of_mod_eq_zero h_sub_mod) hlt2
        omega
      · exact hge2
    have h_start_bound : iter.iter.start.val + 2 * len.val ≤ 256 := by omega
    have h_k_lt : k.val < 128 := by
      by_contra hge
      push Not at hge
      have hterm_le : 2 * (k.val + 1) * len.val ≤ 512 := by omega
      have h1 : 2 * 129 ≤ 2 * (k.val + 1) := by omega
      have h2 : 2 * 129 * len.val ≤ 2 * (k.val + 1) * len.val :=
        Nat.mul_le_mul_right _ h1
      have h3 : 2 * 129 * 16 ≤ 2 * 129 * len.val :=
        Nat.mul_le_mul_left _ h_len
      omega
    have h_k_ge1 : 1 ≤ k.val := by
      by_contra hk0
      push Not at hk0
      interval_cases k.val
      omega
    have h_step_pos : iter.step_by.val > 0 := by omega
    have h_no_overflow : iter.iter.start.val + iter.step_by.val ≤ Std.Usize.max := by
      rw [h_iter_step]; scalar_tac
    let* ⟨o, iter1, ho, hiter1_start, hiter1_end, hiter1_step⟩ ←
      core.iter.adapters.step_by.IteratorStepBy.next_Range_Usize_some_spec
    rw [ho]
    simp only
    step as ⟨tw_u16, htw_zq, htw_bv, htw_lt⟩
    step as ⟨i1, h_i1_eq⟩
    step as ⟨v_tw, h_v_tw_lane_bv⟩
    step as ⟨tw_mont_u16, htw_mont_bv, htw_mont_le, htw_mont_eq⟩
    step as ⟨i3, h_i3_eq⟩
    step as ⟨v_tw_mont, h_v_tw_mont_lane_bv⟩
    step as ⟨k1, hk1_eq⟩
    have h_v_tw_lane : ∀ i : Fin 16, (toLanesYmm v_tw)[i.val] = tw_u16 := by
      intro i
      apply Std.U16.bv_eq_imp_eq
      have h := h_v_tw_lane_bv i
      rw [h_i1_eq] at h
      exact h
    have h_v_tw_wf : wfVecYmm v_tw := by
      intro i
      rw [h_v_tw_lane i]
      exact htw_lt
    have h_v_tw_mont_lane :
        ∀ i : Fin 16, ((toLanesYmm v_tw_mont)[i.val].val : ℕ) = tw_mont_u16.val := by
      intro i
      have h := h_v_tw_mont_lane_bv i
      rw [h_i3_eq] at h
      have := congrArg BitVec.toNat h
      exact this
    have h_twm_eq_inner : tw_mont_u16.val = (tw_u16.val * 3327) % 65536 := by
      rw [htw_mont_eq]
      have h_tw_val : tw_u16.val = (17 ^ _root_.bitRev 7 k.val * 65536) % 3329 := by
        have h := congrArg BitVec.toNat htw_bv
        simp only [BitVec.toNat_setWidth, BitVec.toNat_ofNat] at h
        have h_lt : (17 ^ _root_.bitRev 7 k.val * 65536) % 3329 < 2 ^ 32 := by
          have := Nat.mod_lt (17 ^ _root_.bitRev 7 k.val * 65536) (by decide : (0 : Nat) < 3329)
          omega
        have h_bnd : tw_u16.bv.toNat < 2 ^ 32 := by
          have : tw_u16.bv.toNat < 2 ^ 16 := tw_u16.bv.isLt
          omega
        rw [Nat.mod_eq_of_lt h_bnd, Nat.mod_eq_of_lt h_lt] at h
        show tw_u16.bv.toNat = _
        exact h
      rw [h_tw_val]
    let* ⟨pe_src1, hwf1, hto_poly1⟩ ←
      mlkem.ntt.ntt_avx2.intt_layer_avx2_loop0_loop0.spec pe_src len iter.iter.start
        v_tw v_tw_mont 0#usize
        h_wf h_len h_lend h_start_bound (by simp) (by simp) h_len_step
        tw_u16 htw_lt h_v_tw_wf h_v_tw_lane
        tw_mont_u16 h_twm_eq_inner h_v_tw_mont_lane
    have h_u16ToZq_tw : u16ToZq tw_u16 = ζ ^ _root_.bitRev 7 k.val * 65536 := by
      simp [u16ToZq]
      exact_mod_cast htw_zq
    have h_tw_Rinv : u16ToZq tw_u16 * Rinv = ζ ^ _root_.bitRev 7 k.val := by
      rw [h_u16ToZq_tw, show (65536 : Zq) = R from by unfold R; decide]
      rw [mul_assoc, R_mul_Rinv, mul_one]
    have hk1v : k1.val = k.val - 1 := hk1_eq
    have hs1v : iter1.iter.start.val = iter.iter.start.val + 2 * len.val := by
      rw [hiter1_start, h_iter_step]
    have h_inv1 : 2 * (k1.val + 1) * len.val + iter1.iter.start.val = 512 := by
      rw [hk1v, hs1v]
      have : k.val - 1 + 1 = k.val := by omega
      rw [this]
      have : 2 * k.val * len.val + (iter.iter.start.val + 2 * len.val)
           = 2 * (k.val + 1) * len.val + iter.iter.start.val := by ring
      rw [this]; exact h_inv
    have h_iter_end1 : iter1.iter.«end».val = 256 := by
      rw [show iter1.iter.«end» = iter.iter.«end» from hiter1_end]; exact h_iter_end
    have h_iter_step1 : iter1.step_by.val = 2 * len.val := by
      rw [show iter1.step_by = iter.step_by from hiter1_step]; exact h_iter_step
    have h_iter_start1 : iter1.iter.start.val ≤ 256 ∧
        iter1.iter.start.val % (2 * len.val) = 0 := by
      refine ⟨?_, ?_⟩
      · rw [hs1v]; omega
      · rw [hs1v]; rw [Nat.add_mod_right]; exact h_start_mod
    apply WP.spec_mono
      (mlkem.ntt.ntt_avx2.intt_layer_avx2_loop0.spec iter1 pe_src1 k1 len
        hwf1 h_len h_lend h_div h_len_step h_inv1 h_iter_end1 h_iter_step1 h_iter_start1)
    intro r hr
    obtain ⟨hwf_r, hto_r⟩ := hr
    refine ⟨hwf_r, ?_⟩
    rw [hto_r]
    conv_rhs => rw [inttMidLayer]
    rw [dif_pos h_start_bound]
    simp only [inttMidStep]
    rw [hto_poly1, h_tw_Rinv]
    simp only [Nat.add_zero] at hto_poly1 ⊢
    rw [hs1v, hk1v]
  · have hge : iter.iter.start.val ≥ iter.iter.«end».val := by omega
    let* ⟨o, iter1, ho, _⟩ ← core.iter.adapters.step_by.IteratorStepBy.next_Range_Usize_none_spec
    rw [ho]
    simp only [WP.spec_ok]
    refine ⟨h_wf, ?_⟩
    have h_start_eq : iter.iter.start.val = 256 := by omega
    conv_rhs => rw [inttMidLayer]
    rw [dif_neg (by rw [h_start_eq]; omega)]
termination_by 256 - iter.iter.start.val
decreasing_by
  rw [hiter1_start, h_iter_step]
  omega

/-- INFORMAL PROOF.  Top wrapper for INTT.  Asserts `len ≥ 16`,
    delegates to `_loop0`.  Post identical to
    `poly_element_intt_layer_generic.spec`. -/
@[step]
theorem mlkem.ntt.ntt_avx2.intt_layer_avx2.spec
    (pe_src : PolyElement) (k len : Std.Usize)
    (h_wf : wfPoly pe_src) (h_len : 16 ≤ len.val) (h_lend : len.val ≤ 128)
    (h_div : 256 % (2 * len.val) = 0)
    (h_len_step : len.val % 16 = 0)
    (h_k_top : 2 * (k.val + 1) * len.val = 512) :
    mlkem.ntt.ntt_avx2.intt_layer_avx2 pe_src k len
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r =
            (inttMidLayer len.val (by grind) 0 k.val (toPoly pe_src)).1 ⦄ := by
  unfold mlkem.ntt.ntt_avx2.intt_layer_avx2
  step
  step as ⟨i, hi⟩
  simp only [core.iter.traits.iterator.Iterator.step_by.trait_default, core.iter.traits.iterator.Iterator.step_by.default,
    show ¬ (i.val = 0) from by agrind, if_false]
  apply WP.spec_mono
  · apply mlkem.ntt.ntt_avx2.intt_layer_avx2_loop0.spec
      (iter := ⟨{ start := 0#usize, «end» := 256#usize }, i ⟩)
    · exact h_wf
    · exact h_len
    · exact h_lend
    · exact h_div
    · exact h_len_step
    · show 2 * (k.val + 1) * len.val + (0#usize).val = 512
      simp; exact h_k_top
    · rfl
    · show i.val = 2 * len.val; agrind
    · refine ⟨by simp, by simp⟩
  · rintro r ⟨hwf, heq⟩
    exact ⟨hwf, heq⟩

end Symcrust.Properties.MLKEM.Intrinsics
