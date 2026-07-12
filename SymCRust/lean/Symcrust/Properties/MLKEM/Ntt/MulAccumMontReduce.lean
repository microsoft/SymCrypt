/-
  # Ntt/MulAccumMontReduce.lean — Montgomery reduce-and-add step-specs.

  Split from `Ntt/MulAccum.lean` so that this section can elaborate in
  parallel with `Ntt/MulAccumDotProduct.lean` (neither depends on the
  other; both depend only on the base file `Ntt/MulAccum.lean`).

  Contents:

    * `montgomery_reduce_and_add_poly_element_accumulator_to_poly_element_loop.spec`
    * `montgomery_reduce_and_add_poly_element_accumulator_to_poly_element.spec`
-/
import Symcrust.Properties.MLKEM.Ntt.MulAccum

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust

namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

local macro_rules
| `(tactic| get_elem_tactic) => `(tactic| grind)

/-! ## `MAX_*` constant `.eq` lemmas (re-declared locally)

The Aeneas extraction emits `MAX_*` constants as `@[irreducible]` opaque
defs.  These local `.eq` lemmas unfold them to concrete numerals so the
body proof can do bit-vector / scalar arithmetic on them.

Re-declared here because the original declarations in `MulAccum.lean` are
`private` / `@[local …]` and therefore not visible across files. -/

@[local simp, local scalar_tac_simps, local grind =, local agrind =]
private theorem ntt_MAX_COEFF_PRODUCT_eq :
    mlkem.ntt.MAX_COEFF_PRODUCT = ok 11075584#u32 := by
  unfold mlkem.ntt.MAX_COEFF_PRODUCT
  simp [global_simps]; rfl

@[local simp, local scalar_tac_simps, local grind =, local agrind =]
private theorem ntt_MAX_A1_B1_ZETA_POW_eq :
    mlkem.ntt.MAX_A1_B1_ZETA_POW = ok 11369476#u32 := by
  unfold mlkem.ntt.MAX_A1_B1_ZETA_POW
  simp [global_simps]; rfl

set_option maxHeartbeats 4000000 in
set_option maxRecDepth 2048 in
/-- **Loop spec** for the inner reduce-and-add body.

Per-iteration FC over the Range cursor `iter.start.val`: indices
`[0, iter.start.val)` are untouched by THIS call (they were processed
by callers further up the chain — the loop is initialized at
`iter.start.val = 0`, so this branch is "history"); indices
`[iter.start.val, 256)` get one Mont reduction applied to the accumulator
value and added into the destination, with the accumulator slot zeroed.

Informal proof. Canonical Range-loop induction (proof-patterns §1)
on the cursor, decreasing `256 - iter.start.val`. Body per iteration
`j = iter.start.val`: read `acc := pa_src[j]` (U32) and
`dst := pe_dst[j]` (U16); apply `mont_reduce.spec` (from
`Ntt/ModArith.lean`) — `mont_reduce(acc) = acc · R⁻¹ mod q` — then
`add_mod_q.spec` to merge with `dst`; write back into `pe_dst[j]`
and zero `pa_src[j]`. Two conjuncts: (i) the `toPoly pe_dst'`
equation falls out by `Vector.ofFn` destructuring at `j` (case-split
on `j < iter.start.val` vs `≥`); (ii) the slot-by-slot accumulator
zeroing claim follows from `Array.update` semantics. The two parallel
output structures share the cursor, so the loop body returns a pair
via Aeneas's standard `(pa_src', pe_dst')` tuple-threading; the spec
post mirrors that shape. `agrind` discharges arithmetic. -/
@[step]
theorem mlkem.ntt.montgomery_reduce_and_add_poly_element_accumulator_to_poly_element_loop.spec
    (iter : core.ops.range.Range Usize)
    (pa_src : PolyAccumulator)
    (pe_dst : PolyElement)
    (h_wf_dst : wfPoly pe_dst)
    (hAccBound : ∀ k, (_ : k < 256) →
      pa_src.val[k].val ≤ 4 * (3328 * 3328 + 3494 * 3254))
    (h_end : iter.«end».val = 256) (h_start : iter.start.val ≤ 256)
    (hZeroed : ∀ k, (_ : k < iter.start.val) → pa_src.val[k].val = 0) :
    mlkem.ntt.montgomery_reduce_and_add_poly_element_accumulator_to_poly_element_loop
        iter pa_src pe_dst
      ⦃ result =>
          let pa_src' := result.fst
          let pe_dst' := result.snd
          (∀ k, (_ : k < iter.start.val) →
            pe_dst'.val[k] = pe_dst.val[k] ∧ pa_src'.val[k].val = 0) ∧
          (∀ k, (_ : iter.start.val ≤ k) → (_ : k < 256) →
            (pe_dst'.val[k].val : Zq) =
              (pe_dst.val[k].val : Zq) + (pa_src.val[k].val : Zq) * Rinv ∧
            pe_dst'.val[k].val < q ∧
            pa_src'.val[k].val = 0) ∧
          wfPoly pe_dst' ⦄ := by
  unfold mlkem.ntt.montgomery_reduce_and_add_poly_element_accumulator_to_poly_element_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · -- some branch
    let* ⟨ o, iter1, ho_some, hiter1_start, hiter1_end ⟩ ←
      IteratorRange_next_Usize_some
    simp only [ho_some]
    have hi_lt : iter.start.val < 256 := by grind
    simp only [ntt_MAX_COEFF_PRODUCT_eq, ntt_MAX_A1_B1_ZETA_POW_eq]
    have hdst_a : (pe_dst.val[iter.start.val]! : U16).val < q := by
      have hwf := h_wf_dst iter.start.val hi_lt
      have hlen : pe_dst.val.length = 256 := pe_dst.property
      rw [getElem!_pos pe_dst.val iter.start.val (by omega)]
      exact hwf
    step as ⟨ a, ha_eq ⟩
    have hsrc_a : a.val ≤ 4 * (3328 * 3328 + 3494 * 3254) := by grind
    step*
    · grind
    · -- a2 ≤ 4698 (Montgomery reduction bound)
      bv_tac 32
    · -- c2 ≥ i12 ∨ c2 ≤ 1368
      have hi10_bv : i10.bv = 3329#32 := by rw [i10_post]; native_decide
      have hi11_bv : i11.bv = 4294960638#32 := by
        have h11 : i11.val = -6658 := by rw [i11_post, i10_post]; native_decide
        apply BitVec.eq_of_toInt_eq
        show i11.val = _; rw [h11]; decide
      have hi12_bv : i12.bv = 4294960638#32 := by
        rw [i12_post]
        show i11.bv.signExtend 32 = _
        rw [hi11_bv]; native_decide
      bv_tac 32
    · -- main continuation
      have hi15_val : i15.val = 3329 := by rw [i15_post]; native_decide
      have hi10_bv : i10.bv = 3329#32 := by rw [i10_post]; native_decide
      have hi11_bv : i11.bv = 4294960638#32 := by
        have h11 : i11.val = -6658 := by rw [i11_post, i10_post]; native_decide
        apply BitVec.eq_of_toInt_eq
        show i11.val = _; rw [h11]; decide
      have hi12_bv : i12.bv = 4294960638#32 := by
        rw [i12_post]
        show i11.bv.signExtend 32 = _
        rw [hi11_bv]; native_decide
      have hi16_bv : i16.bv = 4294963967#32 := by
        apply BitVec.eq_of_toInt_eq
        show i16.val = _
        rw [i16_post, i15_post]; native_decide
      have hi17_bv : i17.bv = 4294963967#32 := by
        rw [i17_post]
        show i16.bv.signExtend 32 = _
        rw [hi16_bv]; native_decide
      have hRinv : Rinv = ((U16.size : ZMod q) : Zq)⁻¹ := by
        simp [U16.size, U16.numBits]; decide
      by_cases hc3 : c3 ≥ i17
      · simp only [hc3, if_true]
        step*
        · -- c4 < Q
          bv_tac 32
        · -- wfPoly a3
          have hi20 : i20.val < 3329 := by
            simp [i20_post, UScalar.cast]; bv_tac 32
          intro k hk
          have hlen2 : a3.val.length = 256 := a3.property
          rw [show a3.val[k] = a3.val[k]! from
                (getElem!_pos a3.val k (by rw [hlen2]; exact hk)).symm]
          rw [a3_post, Std.Array.set_val_eq]
          by_cases hkeq : k = iter.start.val
          · subst hkeq; simp_lists; exact hi20
          · have hne : iter.start.val ≠ k := fun h => hkeq h.symm
            simp_lists [hne]
            have hlen_dst : pe_dst.val.length = 256 := pe_dst.property
            have := h_wf_dst k hk
            grind
        · -- IH precond hAccBound
          intro k hk
          rw [a1_post]
          by_cases hkeq : k = iter.start.val
          · subst hkeq; simp_lists at *; decide
          · have hne : iter.start.val ≠ k := fun h => hkeq h.symm
            simp_lists [hne]
            exact hAccBound k hk
        · -- IH precond hZeroed
          intro k hk
          rw [a1_post]
          have hk_le : k < iter.start.val + 1 := by rw [hiter1_start] at hk; grind
          by_cases hkeq : k = iter.start.val
          · subst hkeq; simp_lists; decide
          · have hne : iter.start.val ≠ k := fun h => hkeq h.symm
            simp_lists [hne]
            exact hZeroed k (by grind)
        · -- final combine
          have hc4_mod : c4.val % 3329 = c1.val % 3329 := by bv_tac 32
          have hi20_val : i20.val = c4.val := by
            simp [i20_post, UScalar.cast]; bv_tac 32
          have hi7_bv : i7.bv = inv.bv * mlkem.ntt.Q.bv := by natify; grind
          have hi8_bv : i8.bv = a.bv + i7.bv := by natify; grind
          have ha1_bv : a2.bv = i8.bv >>> 16 := by natify; grind
          have hi6_bv : i6.bv = (core.num.U32.wrapping_mul a mlkem.ntt.NEG_Q_INV_MOD_R).bv := by
            rw [i6_post]
          have hMR := mont_reduce_single_u32.spec a i6 inv i7 i8 a2
            hsrc_a hi6_bv inv_post2 hi7_bv hi8_bv ha1_bv
          have ha1_zq : (a2.val : Zq) = (a.val : Zq) * (U16.size : Zq)⁻¹ := hMR.1
          have hc4_zq : (c4.val : Zq) = (c1.val : Zq) :=
            (ZMod.natCast_eq_natCast_iff _ _ _).mpr hc4_mod
          have hi5_val : (core.convert.num.FromU32U16.from i5).val = i5.val := rfl
          refine ⟨ ?_, ?_, result_post3 ⟩
          · intro k hk
            have hk_iter1 : k < iter1.start.val := by rw [hiter1_start]; grind
            obtain ⟨ heq, hzero ⟩ := result_post1 k hk_iter1
            refine ⟨ ?_, hzero ⟩
            rw [heq, a3_post]
            have hne : iter.start.val ≠ k := by grind
            simp_lists [hne]
          · intro k hk_ge hk_lt
            by_cases hkeq : k = iter.start.val
            · subst hkeq
              have hk_iter1 : iter.start.val < iter1.start.val := by
                rw [hiter1_start]; grind
              obtain ⟨ heq, hzero ⟩ := result_post1 iter.start.val hk_iter1
              refine ⟨ ?_, ?_, hzero ⟩
              · rw [heq, a3_post]
                simp_lists
                rw [show ((i20.val : ℕ) : Zq) = ((c4.val : ℕ) : Zq) by
                    exact_mod_cast congrArg ((↑) : ℕ → Zq) hi20_val]
                rw [hc4_zq, c1_post, hi5_val]
                push_cast
                rw [ha1_zq, i5_post, ha_eq, hRinv]
              · rw [heq, a3_post]
                simp_lists
                rw [hi20_val]
                grind
            · have hk_iter1 : iter1.start.val ≤ k := by
                rw [hiter1_start]; grind
              obtain ⟨ hzqeq, hlt2, hzero ⟩ := result_post2 k hk_iter1 hk_lt
              have hne : iter.start.val ≠ k := fun h => hkeq h.symm
              refine ⟨ ?_, hlt2, hzero ⟩
              rw [hzqeq, a3_post, a1_post]
              simp_lists [hne]
      · -- else branch of by_cases hc3 : ¬ c3 ≥ i17
        simp only [hc3, if_false]
        step*
        · -- c3 < Q
          bv_tac 32
        · -- c4 < Q
          bv_tac 32
        · -- wfPoly a3
          have hi20 : i20.val < 3329 := by
            simp [i20_post, UScalar.cast]; bv_tac 32
          intro k hk
          have hlen2 : a3.val.length = 256 := a3.property
          rw [show a3.val[k] = a3.val[k]! from
                (getElem!_pos a3.val k (by rw [hlen2]; exact hk)).symm]
          rw [a3_post, Std.Array.set_val_eq]
          by_cases hkeq : k = iter.start.val
          · subst hkeq; simp_lists; exact hi20
          · have hne : iter.start.val ≠ k := fun h => hkeq h.symm
            simp_lists [hne]
            have hlen_dst : pe_dst.val.length = 256 := pe_dst.property
            have := h_wf_dst k hk
            grind
        · -- IH precond hAccBound
          intro k hk
          --rw [__post1, Std.Array.set_val_eq]
          by_cases hkeq : k = iter.start.val
          · subst hkeq; simp_lists [a1_post]; decide
          · have hne : iter.start.val ≠ k := fun h => hkeq h.symm
            simp_lists [hne]
            have := hAccBound k hk
            simp_lists [a1_post] at *
            grind
        · -- IH precond hZeroed
          intro k hk
          rw [a1_post]
          have hk_le : k < iter.start.val + 1 := by rw [hiter1_start] at hk; grind
          by_cases hkeq : k = iter.start.val
          · subst hkeq; simp_lists; decide
          · have hne : iter.start.val ≠ k := fun h => hkeq h.symm
            simp_lists [hne]
            exact hZeroed k (by grind)
        · -- final combine (else)
          have hc4_mod : c4.val % 3329 = c1.val % 3329 := by bv_tac 32
          have hi20_val : i20.val = c4.val := by
            simp [i20_post, UScalar.cast]; bv_tac 32
          have hi7_bv : i7.bv = inv.bv * mlkem.ntt.Q.bv := by natify; grind
          have hi8_bv : i8.bv = a.bv + i7.bv := by natify; grind
          have ha1_bv : a2.bv = i8.bv >>> 16 := by natify; grind
          have hi6_bv : i6.bv = (core.num.U32.wrapping_mul a mlkem.ntt.NEG_Q_INV_MOD_R).bv := by
            rw [i6_post]
          have hMR := mont_reduce_single_u32.spec a i6 inv i7 i8 a2
            hsrc_a hi6_bv inv_post2 hi7_bv hi8_bv ha1_bv
          have ha1_zq : (a2.val : Zq) = (a.val : Zq) * (U16.size : Zq)⁻¹ := hMR.1
          have hc4_zq : (c4.val : Zq) = (c1.val : Zq) :=
            (ZMod.natCast_eq_natCast_iff _ _ _).mpr hc4_mod
          have hi5_val : (core.convert.num.FromU32U16.from i5).val = i5.val := rfl
          refine ⟨ ?_, ?_, result_post3 ⟩
          · intro k hk
            have hk_iter1 : k < iter1.start.val := by rw [hiter1_start]; grind
            obtain ⟨ heq, hzero ⟩ := result_post1 k hk_iter1
            refine ⟨ ?_, hzero ⟩
            rw [heq, a3_post]
            have hne : iter.start.val ≠ k := by grind
            simp_lists [hne]
          · intro k hk_ge hk_lt
            by_cases hkeq : k = iter.start.val
            · subst hkeq
              have hk_iter1 : iter.start.val < iter1.start.val := by
                rw [hiter1_start]; grind
              obtain ⟨ heq, hzero ⟩ := result_post1 iter.start.val hk_iter1
              refine ⟨ ?_, ?_, hzero ⟩
              · rw [heq, a3_post]
                simp_lists
                rw [show ((i20.val : ℕ) : Zq) = ((c4.val : ℕ) : Zq) by
                    exact_mod_cast congrArg ((↑) : ℕ → Zq) hi20_val]
                rw [hc4_zq, c1_post, hi5_val]
                grind
              · simp_lists [*]
                grind
            · have hk_iter1 : iter1.start.val ≤ k := by
                rw [hiter1_start]; grind
              obtain ⟨ hzqeq, hlt2, hzero ⟩ := result_post2 k hk_iter1 hk_lt
              have hne : iter.start.val ≠ k := fun h => hkeq h.symm
              refine ⟨ ?_, hlt2, hzero ⟩
              simp_lists [*]
  · -- none branch
    have hge : iter.start.val ≥ iter.«end».val := by grind
    let* ⟨ o, iter1, ho_none, hiter1_eq ⟩ ←
      IteratorRange_next_Usize_none
    simp only [ho_none, WP.spec_ok]
    refine ⟨ ?_, ?_, h_wf_dst ⟩
    · intro j hj
      refine ⟨ trivial, hZeroed j hj ⟩
    · intro j hj_ge hj_lt
      have hi256 : iter.start.val = 256 := by grind
      rw [hi256] at hj_ge; grind
  termination_by iter.«end».val - iter.start.val
  decreasing_by
    all_goals decreasing_by_preprocess; agrind

/-- **Wrapper spec** for the reduce-and-add.

Informal proof. Leaf wrapper: `unfold` the function body to a
`Range 0 256` construction + delegate call. Apply the `_loop.spec`
with `iter.start.val = 0`, `iter.«end».val = 256`; the cursor-zero
collapses the `if j < 0` conditionals everywhere, leaving
`toPoly pe_dst' = toPoly pe_dst + (accToPoly pa_src).map (Rinv · ·)`
and `accZero pa_src'`. Rewrite the per-index `Vector.ofFn`
equality with `Vector.ext` / `agrind`; the `accZero` conjunct
collapses by the inner `∀ j, _ = 0` claim with the cursor at zero. -/
@[step]
theorem mlkem.ntt.montgomery_reduce_and_add_poly_element_accumulator_to_poly_element.spec
    (pa_src : PolyAccumulator)
    (pe_dst : PolyElement)
    (h_acc : wfAcc pa_src) (h_wf_dst : wfPoly pe_dst) :
    mlkem.ntt.montgomery_reduce_and_add_poly_element_accumulator_to_poly_element
        pa_src pe_dst
      ⦃ pa_src' pe_dst' =>
          wfPoly pe_dst' ∧
          toPoly pe_dst' = toPoly pe_dst + (accToPoly pa_src).map (Rinv * ·) ∧
          accZero pa_src' ⦄ := by
  unfold mlkem.ntt.montgomery_reduce_and_add_poly_element_accumulator_to_poly_element
  apply WP.spec_mono <|
    mlkem.ntt.montgomery_reduce_and_add_poly_element_accumulator_to_poly_element_loop.spec
      { start := 0#usize, «end» := mlkem.key.MLWE_POLYNOMIAL_COEFFICIENTS }
      pa_src pe_dst h_wf_dst
      (by intro k hk
          have h := h_acc k hk
          grind)
      (by simp [mlkem.key.MLWE_POLYNOMIAL_COEFFICIENTS])
      (by simp)
      (by intros _ hk; simp at hk)
  rintro ⟨pa_src', pe_dst'⟩ ⟨_hBelow, hAbove, hWf⟩
  refine ⟨hWf, ?_, ?_⟩
  · -- toPoly pe_dst' = toPoly pe_dst + (accToPoly pa_src).map (Rinv * ·)
    apply Vector.ext
    intro i hi
    have h := (hAbove i (Nat.zero_le _) hi).1
    have hadd :
      (toPoly pe_dst + (accToPoly pa_src).map (Rinv * ·))[i]'hi
        = (toPoly pe_dst)[i]'hi + Rinv * (accToPoly pa_src)[i]'hi := by
      show (Vector.zipWith (· + ·) (toPoly pe_dst)
              ((accToPoly pa_src).map (Rinv * ·)))[i]'hi = _
      rw [Vector.getElem_zipWith, Vector.getElem_map]
    rw [hadd]
    rw [show (toPoly pe_dst')[i]'hi = (toPoly pe_dst')[i]! from
          (getElem!_pos _ i hi).symm,
        getElem!_toPoly pe_dst' i hi]
    rw [show (toPoly pe_dst)[i]'hi = (toPoly pe_dst)[i]! from
          (getElem!_pos _ i hi).symm,
        getElem!_toPoly pe_dst i hi]
    rw [show (accToPoly pa_src)[i]'hi = accToZq (pa_src.val[i]!) by
          unfold accToPoly
          rw [Vector.getElem_ofFn]
          rw [getElem!_pos pa_src.val i (by rw [pa_src.property]; exact hi)]]
    unfold u16ToZq accToZq
    rw [mul_comm Rinv _]
    grind
  · -- accZero pa_src'
    intro k
    have h := (hAbove k.val (Nat.zero_le _) k.isLt).2.2
    grind

end Symcrust.Properties.MLKEM
