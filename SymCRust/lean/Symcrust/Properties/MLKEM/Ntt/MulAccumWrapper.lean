/-
  # Ntt/MulAccumWrapper.lean — Top wrapper for `vector_mont_dot_product`.

  This file is split out from `Ntt/MulAccum.lean` to keep the elaboration
  budget for the wrapper independent (the parent file is over 1500 LOC and
  was starving the wrapper of heartbeats).

  Contents:

    * 4 hoisted helper lemmas factoring the "wipe then back-continuation"
      reasoning (`accToPoly_back_wipe_zero`, `back_wipe_u32_val_le_zero`,
      `wfPoly_back_wipe_u16`, `toPoly_back_wipe_u16_zero`).
    * The top step-spec
      `mlkem.ntt.vector_mont_dot_product.spec`.
-/
import Symcrust.Properties.MLKEM.Ntt.MulAccumMontReduce
import Symcrust.Properties.MLKEM.Ntt.MulAccumDotProduct

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust

namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

/-! ## Helper lemmas for the top wrapper (hoisted to keep budgets independent)

These four lemmas factor out the "wipe then back-continuation" reasoning that
otherwise blows the wrapper's heartbeat budget. -/

theorem accToPoly_back_wipe_zero
    (pa_tmp : PolyAccumulator) (s_acc s_acc' : Slice U32)
    (hs_acc_val : s_acc.val = pa_tmp.val)
    (hs_acc'_len : s_acc'.length = s_acc.length)
    (hs_acc'_zero : ∀ i, (h : i < s_acc'.length) → s_acc'[i] = (default : U32)) :
    accToPoly (Array.from_slice pa_tmp s_acc') = (0 : MLKEM.Polynomial) := by
  have h_pa_len : pa_tmp.val.length = 256 := pa_tmp.property
  have h_s_acc_len : s_acc.length = 256 := by
    simp only [Slice.length, hs_acc_val]; exact h_pa_len
  have h_s_acc'_len_256 : s_acc'.length = 256 := by
    rw [hs_acc'_len]; exact h_s_acc_len
  have h_s_acc'_val_len : s_acc'.val.length = 256 := by
    simp only [Slice.length] at h_s_acc'_len_256; exact h_s_acc'_len_256
  have h_back_val : (Array.from_slice pa_tmp s_acc').val = s_acc'.val :=
    Array.from_slice_val pa_tmp s_acc' h_s_acc'_val_len
  unfold accToPoly
  apply Vector.ext
  intro i hi
  rw [Vector.getElem_ofFn]
  rw [show (0 : MLKEM.Polynomial)[i]'hi = 0 by
        show (Vector.replicate _ (0 : Zq))[i]'hi = 0
        rw [Vector.getElem_replicate]]
  have h_i_in : i < s_acc'.val.length := by rw [h_s_acc'_val_len]; exact hi
  have h_acc : (Array.from_slice pa_tmp s_acc').val[i]'(by rw [h_back_val]; exact h_i_in)
                = s_acc'.val[i]'h_i_in := by fcongr 1
  rw [h_acc]
  have hz : s_acc'.val[i]'h_i_in = 0#u32 := hs_acc'_zero i h_i_in
  rw [hz]
  rfl

theorem back_wipe_u32_val_le_zero
    (pa_tmp : PolyAccumulator) (s_acc s_acc' : Slice U32)
    (hs_acc_val : s_acc.val = pa_tmp.val)
    (hs_acc'_len : s_acc'.length = s_acc.length)
    (hs_acc'_zero : ∀ i, (h : i < s_acc'.length) → s_acc'[i] = (default : U32)) :
    ∀ (k : ℕ) (hk : k < 256),
      ((Array.from_slice pa_tmp s_acc').val[k]'(by
          have := (Array.from_slice pa_tmp s_acc').property; scalar_tac)).val
        ≤ 0 * (3328 * 3328 + 3494 * 3254) := by
  have h_pa_len : pa_tmp.val.length = 256 := pa_tmp.property
  have h_s_acc_len : s_acc.length = 256 := by
    simp only [Slice.length, hs_acc_val]; exact h_pa_len
  have h_s_acc'_len_256 : s_acc'.length = 256 := by
    rw [hs_acc'_len]; exact h_s_acc_len
  have h_s_acc'_val_len : s_acc'.val.length = 256 := by
    simp only [Slice.length] at h_s_acc'_len_256; exact h_s_acc'_len_256
  have h_back_val : (Array.from_slice pa_tmp s_acc').val = s_acc'.val :=
    Array.from_slice_val pa_tmp s_acc' h_s_acc'_val_len
  intro k hk
  rw [Nat.zero_mul]
  have h_k_in : k < s_acc'.val.length := by rw [h_s_acc'_val_len]; exact hk
  have h_back_k : (Array.from_slice pa_tmp s_acc').val[k]'(by
      have := (Array.from_slice pa_tmp s_acc').property; scalar_tac)
        = s_acc'.val[k]'h_k_in := by fcongr 1
  rw [h_back_k]
  have hz : s_acc'.val[k]'h_k_in = 0#u32 := hs_acc'_zero k h_k_in
  rw [hz]
  exact Nat.le_refl 0

theorem wfPoly_back_wipe_u16
    (pe_dst : PolyElement) (s_dst s_dst' : Slice U16)
    (hs_dst_val : s_dst.val = pe_dst.val)
    (hs_dst'_len : s_dst'.length = s_dst.length)
    (hs_dst'_zero : ∀ i, (h : i < s_dst'.length) → s_dst'[i] = (default : U16)) :
    wfPoly (Array.from_slice pe_dst s_dst') := by
  have h_pe_len : pe_dst.val.length = 256 := pe_dst.property
  have h_s_dst_len : s_dst.length = 256 := by
    simp only [Slice.length, hs_dst_val]; exact h_pe_len
  have h_s_dst'_len_256 : s_dst'.length = 256 := by
    rw [hs_dst'_len]; exact h_s_dst_len
  have h_s_dst'_val_len : s_dst'.val.length = 256 := by
    simp only [Slice.length] at h_s_dst'_len_256; exact h_s_dst'_len_256
  have h_back_val : (Array.from_slice pe_dst s_dst').val = s_dst'.val :=
    Array.from_slice_val pe_dst s_dst' h_s_dst'_val_len
  intro i hi
  have h_i_in : i < s_dst'.val.length := by rw [h_s_dst'_val_len]; exact hi
  have h_acc : (Array.from_slice pe_dst s_dst').val[i]'(by rw [h_back_val]; exact h_i_in)
                = s_dst'.val[i]'h_i_in := by fcongr 1
  rw [h_acc]
  have hz : s_dst'.val[i]'h_i_in = 0#u16 := hs_dst'_zero i h_i_in
  rw [hz]
  decide

theorem toPoly_back_wipe_u16_zero
    (pe_dst : PolyElement) (s_dst s_dst' : Slice U16)
    (hs_dst_val : s_dst.val = pe_dst.val)
    (hs_dst'_len : s_dst'.length = s_dst.length)
    (hs_dst'_zero : ∀ i, (h : i < s_dst'.length) → s_dst'[i] = (default : U16)) :
    toPoly (Array.from_slice pe_dst s_dst') = (0 : MLKEM.Polynomial) := by
  have h_pe_len : pe_dst.val.length = 256 := pe_dst.property
  have h_s_dst_len : s_dst.length = 256 := by
    simp only [Slice.length, hs_dst_val]; exact h_pe_len
  have h_s_dst'_len_256 : s_dst'.length = 256 := by
    rw [hs_dst'_len]; exact h_s_dst_len
  have h_s_dst'_val_len : s_dst'.val.length = 256 := by
    simp only [Slice.length] at h_s_dst'_len_256; exact h_s_dst'_len_256
  have h_back_val : (Array.from_slice pe_dst s_dst').val = s_dst'.val :=
    Array.from_slice_val pe_dst s_dst' h_s_dst'_val_len
  unfold toPoly
  apply Vector.ext
  intro i hi
  rw [Vector.getElem_ofFn]
  rw [show (0 : MLKEM.Polynomial)[i]'hi = 0 by
        show (Vector.replicate _ (0 : Zq))[i]'hi = 0
        rw [Vector.getElem_replicate]]
  have h_i_in : i < s_dst'.val.length := by rw [h_s_dst'_val_len]; exact hi
  have h_acc : (Array.from_slice pe_dst s_dst').val[i]'(by rw [h_back_val]; exact h_i_in)
                = s_dst'.val[i]'h_i_in := by fcongr 1
  rw [h_acc]
  have hz : s_dst'.val[i]'h_i_in = 0#u16 := hs_dst'_zero i h_i_in
  rw [hz]
  rfl

set_option maxHeartbeats 4000000 in
set_option maxRecDepth 2048 in
/-- **Top spec for `vector_mont_dot_product`** — full FC to
`PolyVector.innerProductNTT` with one `Rinv` factor.

`pe_dst` is wiped before the accumulation, so its prior contents are
irrelevant; `pa_tmp` exits zeroed (the final Mont reduction zeroes
every slot it processes).

Informal proof. Unfold the impl body: (1) discharge the 3 masserts;
(2) step through the two `lift (Array.to_slice_mut)` calls and the
two `wipe_slice` calls; (3) apply `vector_mont_dot_product_loop.spec`
with cursor `0..n_rows` (the LOOSE accumulator-bound precondition is
discharged by `back_wipe_u32_val_le_zero`); (4) apply
`montgomery_reduce_and_add_..._.spec` (the `wfAcc` precondition follows
from the loop's bound conjunct + `pv_src1.length ≤ 4`, the `wfPoly`
precondition follows from `wfPoly_back_wipe_u16`); (5) bridge the
final equation using `toPoly_back_wipe_u16_zero` (wiped dst contributes
`0`), `accToPoly_back_wipe_zero` (wiped acc contributes `0`), and
`vectorDotPartial_eq_innerProductNTT`. -/
@[step]
theorem mlkem.ntt.vector_mont_dot_product.spec
    (pv_src1 pv_src2 : Slice PolyElement)
    (pe_dst : PolyElement) (pa_tmp : PolyAccumulator)
    (kn : K) (h_kn : (kn : ℕ) = pv_src1.length)
    (h_wf1 : wfPolyVec pv_src1) (h_wf2 : wfPolyVec pv_src2)
    (h_len : pv_src1.length = pv_src2.length)
    (h_nrows : 0 < pv_src1.length ∧ pv_src1.length ≤ 4) :
    mlkem.ntt.vector_mont_dot_product pv_src1 pv_src2 pe_dst pa_tmp
      ⦃ (pe_dst' : PolyElement) (pa_tmp' : PolyAccumulator) =>
          wfPoly pe_dst' ∧
          accZero pa_tmp' ∧
          toPoly pe_dst' =
            (PolyVector.innerProductNTT
              (toPolyVecOfLen pv_src1 kn h_kn.symm)
              (toPolyVecOfLen pv_src2 kn (by rw [h_kn]; exact h_len.symm))).map
              (Rinv * ·) ⦄ := by
  unfold mlkem.ntt.vector_mont_dot_product
  simp only []
  step
  simp only [mlkem.ntt.MATRIX_MAX_NROWS]
  step
  step
  step as ⟨s_acc, back_acc, hs_acc, hback_acc⟩
  step as ⟨s_acc', hs_acc'_len, hs_acc'_zero⟩
  step as ⟨s_dst, back_dst, hs_dst, hback_dst⟩
  step as ⟨s_dst', hs_dst'_len, hs_dst'_zero⟩
  have hs_acc_val : s_acc.val = pa_tmp.val := hs_acc
  have hs_dst_val : s_dst.val = pe_dst.val := hs_dst
  rw [hback_acc, hback_dst]
  have h_acc_pre := back_wipe_u32_val_le_zero pa_tmp s_acc s_acc'
    hs_acc_val hs_acc'_len hs_acc'_zero
  -- Tight-odd vacuity: at iter.start = 0 the precondition is `≤ 0 * 2M = 0`,
  -- which follows from `h_acc_pre` (every slot ≤ 0 * (M+A) = 0).
  have h_from_len : (Array.from_slice pa_tmp s_acc').val.length = 256 :=
    (Array.from_slice pa_tmp s_acc').property
  have h_acc_pre_tight_odd :
      ∀ j (hj : j < 128),
        ((Array.from_slice pa_tmp s_acc').val[2*j+1]'(by
            rw [h_from_len]; omega)).val
          ≤ (0 : Nat) * (2 * (3328 * 3328)) := by
    intro j hj
    have h := h_acc_pre (2*j+1) (by omega)
    rw [Nat.zero_mul] at h ⊢
    exact h
  have h_start_pre : (0 : Nat) ≤ pv_src1.length := Nat.zero_le _
  have h_end_pre : pv_src1.len.val = pv_src1.length := rfl
  step with mlkem.ntt.vector_mont_dot_product_loop.spec
    { start := 0#usize, «end» := pv_src1.len } pv_src1 pv_src2
    (Array.from_slice pa_tmp s_acc') h_wf1 h_wf2 h_acc_pre h_acc_pre_tight_odd
    h_len h_nrows h_start_pre h_end_pre
    as ⟨pa_tmp2, h_acc_eq, h_acc_bnd, _h_acc_tight_odd_out⟩
  have h_wf_acc : wfAcc pa_tmp2 := by
    intro k hk
    have h := h_acc_bnd k hk
    have h4 : pv_src1.length ≤ 4 := h_nrows.2
    calc (pa_tmp2.val[k]'_).val
        ≤ pv_src1.length * (3328 * 3328 + 3494 * 3254) := h
      _ ≤ 4 * (3328 * 3328 + 3494 * 3254) :=
          Nat.mul_le_mul_right _ h4
  have h_wf_dst' : wfPoly (Array.from_slice pe_dst s_dst') :=
    wfPoly_back_wipe_u16 pe_dst s_dst s_dst' hs_dst_val hs_dst'_len hs_dst'_zero
  step with mlkem.ntt.montgomery_reduce_and_add_poly_element_accumulator_to_poly_element.spec
    pa_tmp2 (Array.from_slice pe_dst s_dst') h_wf_acc h_wf_dst'
    as ⟨pa_tmp3, pe_dst2, hwf_dst2, htp_dst2_eq, haz_pa3⟩
  refine ⟨hwf_dst2, haz_pa3, ?_⟩
  rw [htp_dst2_eq]
  rw [toPoly_back_wipe_u16_zero pe_dst s_dst s_dst' hs_dst_val hs_dst'_len hs_dst'_zero]
  rw [show (0 : MLKEM.Polynomial) = Polynomial.zero from rfl, Polynomial.zero_add]
  rw [h_acc_eq]
  rw [accToPoly_back_wipe_zero pa_tmp s_acc s_acc' hs_acc_val hs_acc'_len hs_acc'_zero]
  rw [show (0 : MLKEM.Polynomial) = Polynomial.zero from rfl, Polynomial.zero_add]
  rw [Nat.sub_zero]
  conv_lhs => rw [← h_kn]
  rw [vectorDotPartial_eq_innerProductNTT pv_src1 pv_src2 kn h_kn.symm
        (by rw [h_kn]; exact h_len.symm)]

end Symcrust.Properties.MLKEM
