/-
  # Ntt/Intt.lean — Step-specs for the inverse NTT (with `*R` fixup baked in).

  Covers (bottom-up):

      mlkem.ntt.poly_element_intt_layer_generic_loop0_loop0   -- GS inner butterfly
      mlkem.ntt.poly_element_intt_layer_generic_loop0         -- middle (start) loop
      mlkem.ntt.poly_element_intt_layer_generic               -- one INTT layer
      mlkem.ntt.poly_element_intt_layer                       -- dispatch wrapper
      mlkem.ntt.poly_element_intt_and_mul_r_loop              -- IterMut fixup
      mlkem.ntt.poly_element_intt_and_mul_r                   -- 7 layers + fixup
      mlkem.ntt.vector_intt_and_mul_r_loop                    -- IterMut over slice
      mlkem.ntt.vector_intt_and_mul_r                         -- top-level vector INTT

  ## Postcondition shape — what the fixup does

  After 7 Gentleman–Sande layers, each coefficient is
  `2^7 · ζ^... · original = 128 · NTTInv-without-fixup`.  The fixup
  IterMut applies `mont_mul coeff INTT_FIXUP_TIMES_RSQR _` per
  coefficient, where `INTT_FIXUP_TIMES_RSQR = 1441 = 128⁻¹ · R² mod q`.
  By `mont_mul.spec` + Bridge M3,
      `mont_mul x INTT_FIXUP_TIMES_RSQR _ = x · 128⁻¹ · R   (in Zq)`.
  Composed with the GS output `c_GS = 128 · c_NTTInv` (in Zq), the
  fixup yields `c_GS · 128⁻¹ · R = c_NTTInv · R` — i.e., the
  Montgomery-storage representation of the spec's `NTTInv`.

  Hence the top postcondition is
      `toPoly result = (MLKEM.NTTInv (toPoly pe_src)).map (R * ·)`
  equivalently `toMontPoly result = MLKEM.NTTInv (toPoly pe_src)`.

  Bridge: this is the **canonical place where standard form becomes
  Montgomery form** in the decapsulation pipeline (see G4 in
  `Bridges/MatrixVectorMul.lean`, `vector_intt_and_mul_r`).
-/
import Symcrust.Properties.Iterators
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.Iterators
import Symcrust.Properties.MLKEM.Bridges.MontArith
import Symcrust.Properties.MLKEM.Bridges.NttLoops
import Symcrust.Properties.MLKEM.Ntt.ModArith
import Symcrust.Properties.MLKEM.Ntt.Twiddles
import Symcrust.Properties.Axioms.System
import Symcrust.Properties.MLKEM.Intrinsics.Vec128LayerIntt
import Symcrust.Properties.MLKEM.Intrinsics.X86_64.Avx2LayerIntt
import Symcrust.Properties.MLKEM.Intrinsics.X86_64.Sse2
import Symcrust.Properties.MLKEM.Intrinsics.Aarch64.Neon

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust

namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges
open Symcrust.Properties.MLKEM.Intrinsics
open Symcrust.Properties.MLKEM.Intrinsics.X86_64
open Symcrust.Properties.MLKEM.Intrinsics.Aarch64

set_option maxHeartbeats 1000000

/-! ## Inner GS butterfly loop -/

/-- **Loop spec** for the inverse inner butterfly.

GS butterfly: `t := pe_src[j]`, `pe_src[j] := mod_add t pe_src[j+len]`,
`pe_src[j+len] := mont_mul (mod_sub t pe_src[j+len]) z z_mont` —
i.e., `(a, b) ↦ (a + b, z · (a - b))`.

Bridge to spec via `inttButterflyAt` from `Bridges/NttLoops.lean`.

Informal proof. Template: Range-loop induction per `proof-patterns` §1,
symmetric to the forward inner-loop proof but using Gentleman–Sande
butterflies. Unfold
`mlkem.ntt.poly_element_intt_layer_generic_loop0_loop0`; the body calls
`IteratorRange.next`, returns on `none`, and in the `some j` branch reads
`a = pe_src[start+j]` and `b = pe_src[start+j+len]`, computes the GS sum
and twiddled difference, writes both locations, and recurses.

1. `step with IteratorRange_next_some` / `IteratorRange_next_none`.
2. Step `Usize.add.spec`, `Array.index_usize.spec`,
   `core.convert.IntoFrom.into`, and the first `< q` `massert`.
3. Step `Usize.add.spec`, `Array.index_usize.spec`,
   `core.convert.IntoFrom.into`, and the second `< q` `massert`.
4. Step `mlkem.ntt.mod_add.spec` for the upper coefficient `a + b`,
   then `mlkem.ntt.mod_sub.spec` for the lower difference `b - a`
   (or `a - b`, matching the extracted body).
5. Step `mlkem.ntt.mont_mul.spec`; use `h_tw` and the Montgomery
   cancellation lemmas (`mont_mul_R_right`, `R_mul_Rinv`), with the
   companion bound/equality, to identify the lower write with
   `z * (a - b)`.
6. Step `UScalar.cast` and `Array.update.spec` for the write at `j`,
   then `Usize.add.spec`, `UScalar.cast`, and `Array.update.spec` for
   the write at `j + len`.
7. Step the recursive call with this theorem; the IH gives the tail
   `inttButterflies` from `iter.start + 1` to `iter.end`.

Case analysis: in the `none` branch, `inttButterflies` is at its base
case. In the `some` branch, peel `inttButterflies`; identify the two
writes with `inttButterflyAt` using `tbd_toPoly_intt_butterfly_step`,
then compose with the recursive IH.

Close with `split_conjs`; `agrind` handles bounds / well-formedness, and
targeted `simp [*]` followed by `agrind` closes the `inttButterflies`
peel. -/
@[step]
theorem mlkem.ntt.poly_element_intt_layer_generic_loop0_loop0.spec
    (iter : core.ops.range.Range Usize)
    (pe_src : PolyElement)
    (len start : Usize)
    (twiddle_factor twiddle_factor_mont : U32)
    (h_wf : wfPoly pe_src)
    (h_start : iter.start.val ≤ iter.«end».val)
    (h_end : iter.«end».val ≤ len.val)
    (h_bound : start.val + 2 * len.val ≤ 256)
    (h_len_pos : 0 < len.val)
    (h_tw_lt_q : twiddle_factor.val < q)
    (h_tw_mont_bound : twiddle_factor_mont.val ≤ 65535)
    (h_tw_mont_eq : twiddle_factor_mont.val = (twiddle_factor.val * 3327) % 65536) :
    mlkem.ntt.poly_element_intt_layer_generic_loop0_loop0
        iter pe_src len start twiddle_factor twiddle_factor_mont
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r =
            inttButterflies (u32ToZq twiddle_factor * Rinv)
                (toPoly pe_src) len.val
                (start.val + iter.start.val)
                (start.val + iter.«end».val)
                (by have := h_bound; have := h_end; grind) ⦄ := by
  unfold mlkem.ntt.poly_element_intt_layer_generic_loop0_loop0
  by_cases hlt : iter.start.val < iter.«end».val
  · -- SOME branch
    let* ⟨ o, iter1, ho, hstart', hend' ⟩ ← IteratorRange_next_Usize_some
    rw [ho]
    simp only
    have hj_lt_len : iter.start.val < len.val := by scalar_tac
    have h_lo_lt : start.val + iter.start.val < 256 := by scalar_tac
    have h_hi_lt : start.val + iter.start.val + len.val < 256 := by scalar_tac
    -- i ← start + j
    let* ⟨ i, hi_eq ⟩ ← Usize.add_spec
    have hi_val : i.val = start.val + iter.start.val := hi_eq
    -- i1 ← Array.index_usize pe_src i  (returns U16)
    let* ⟨ i1, hi1 ⟩ ← Array.index_usize_spec
    have h_pe_len : pe_src.val.length = 256 := by have := pe_src.property; grind
    have h_i_lt : i.val < pe_src.val.length := by rw [h_pe_len]; scalar_tac
    have h_i_lt_256 : i.val < 256 := by scalar_tac
    have hi1_lt_q : i1.val < q := by
      have := h_wf i.val h_i_lt_256
      grind
    have h_pe_i_lt_q : (pe_src.val[i.val]'h_i_lt).val < q :=
      h_wf i.val h_i_lt_256
    -- c0 ← FromU32U16.from i1 (silent); massert c0 < Q
    step
    -- i2 ← i + len
    step as ⟨i2, hi2_eq⟩
    -- i3 ← Array.index_usize pe_src i2
    let* ⟨ i3, hi3 ⟩ ← Array.index_usize_spec
    have h_i2_lt_256 : i2.val < 256 := by rw [hi2_eq, hi_val]; scalar_tac
    have h_i2_lt : i2.val < pe_src.val.length := by rw [h_pe_len]; exact h_i2_lt_256
    have hi3_lt_q : i3.val < q := by
      have := h_wf i2.val h_i2_lt_256
      grind
    have h_pe_i2_lt_q : (pe_src.val[i2.val]'h_i2_lt).val < q :=
      h_wf i2.val h_i2_lt_256
    -- c1 ← FromU32U16.from i3 (silent); massert c1 < Q
    step
    have h_c0_lt_q : (core.convert.num.FromU32U16.from i1).val < q := by
      simp only [core.convert.num.FromU32U16.from_val_eq]; exact hi1_lt_q
    have h_c1_lt_q : (core.convert.num.FromU32U16.from i3).val < q := by
      simp only [core.convert.num.FromU32U16.from_val_eq]; exact hi3_lt_q
    -- tmp ← mod_add c0 c1  (sum, no twiddle)
    let* ⟨tmp, h_tmp_lt, h_tmp_eq⟩ ←
      mlkem.ntt.mod_add.spec (core.convert.num.FromU32U16.from i1)
        (core.convert.num.FromU32U16.from i3) h_c0_lt_q h_c1_lt_q
    -- c11 ← mod_sub c1 c0  (difference, NOTE order: c1 - c0)
    let* ⟨c11, h_c11_lt, h_c11_eq⟩ ←
      mlkem.ntt.mod_sub.spec (core.convert.num.FromU32U16.from i3)
        (core.convert.num.FromU32U16.from i1) h_c1_lt_q h_c0_lt_q
    -- c12 ← mont_mul c11 tw tw_mont
    let* ⟨c12, h_c12_lt, h_c12_eq⟩ ←
      mlkem.ntt.mont_mul.spec c11 twiddle_factor twiddle_factor_mont
        h_c11_lt h_tw_lt_q h_tw_mont_bound h_tw_mont_eq
    -- i4 ← UScalar.cast .U16 tmp
    have h_tmp_u16 : tmp.val ≤ UScalar.max .U16 := by
      simp only [UScalar.max_UScalarTy_U16_eq, U16.max_eq]
      have : (q : Nat) = 3329 := rfl
      have h := h_tmp_lt; rw [this] at h; scalar_tac
    let* ⟨i4, hi4_eq⟩ ← UScalar.cast_inBounds_spec
    -- pe_src1 ← Array.update pe_src i i4
    let* ⟨pe_src1, h_pe_src1⟩ ← Array.update_spec
    -- i5 ← i + len
    step as ⟨i5, hi5_eq⟩
    -- i6 ← UScalar.cast .U16 c12
    have h_c12_u16 : c12.val ≤ UScalar.max .U16 := by
      simp only [UScalar.max_UScalarTy_U16_eq, U16.max_eq]
      have : (q : Nat) = 3329 := rfl
      have h := h_c12_lt; rw [this] at h; scalar_tac
    let* ⟨i6, hi6_eq⟩ ← UScalar.cast_inBounds_spec
    -- a ← Array.update pe_src1 i5 i6
    let* ⟨a, ha_eq⟩ ← Array.update_spec
    -- Build wfPoly a for the recursive call.
    have hi4_val : i4.val = tmp.val := hi4_eq
    have hi6_val : i6.val = c12.val := hi6_eq
    have hi4_lt_q : i4.val < q := by rw [hi4_val]; exact h_tmp_lt
    have hi6_lt_q : i6.val < q := by rw [hi6_val]; exact h_c12_lt
    have h_a_wf : wfPoly a := by
      intro w hw
      have h_aval : a.val = (pe_src.val.set i.val i4).set i5.val i6 := by
        have h1 : a.val = pe_src1.val.set i5.val i6 := by rw [ha_eq]; rfl
        have h2 : pe_src1.val = pe_src.val.set i.val i4 := by rw [h_pe_src1]; rfl
        rw [h1, h2]
      have h_len_set : ((pe_src.val.set i.val i4).set i5.val i6).length = pe_src.val.length := by
        simp [List.length_set]
      have h_w_lt : w < ((pe_src.val.set i.val i4).set i5.val i6).length := by
        rw [h_len_set, h_pe_len]; exact hw
      have heq : (a.val[w]'(by rw [h_aval]; exact h_w_lt)) =
                 ((pe_src.val.set i.val i4).set i5.val i6)[w]'h_w_lt :=
        List.getElem_of_eq h_aval _
      show (a.val[w]'_).val < q
      rw [heq]
      by_cases hw_hi : w = i5.val
      · subst hw_hi
        rw [List.getElem_set_self]
        exact hi6_lt_q
      · rw [List.getElem_set_ne (Ne.symm hw_hi)]
        by_cases hw_lo : w = i.val
        · subst hw_lo
          rw [List.getElem_set_self]
          exact hi4_lt_q
        · rw [List.getElem_set_ne (Ne.symm hw_lo)]
          exact h_wf w hw
    -- IH: recurse on iter1 with updated array
    have h_iter1_start_le : iter1.start.val ≤ iter1.«end».val := by
      rw [hstart', hend']; scalar_tac
    have h_iter1_end_le_len : iter1.«end».val ≤ len.val := by rw [hend']; exact h_end
    apply WP.spec_mono
      (mlkem.ntt.poly_element_intt_layer_generic_loop0_loop0.spec iter1 a len start
        twiddle_factor twiddle_factor_mont h_a_wf h_iter1_start_le h_iter1_end_le_len
        h_bound h_len_pos h_tw_lt_q h_tw_mont_bound h_tw_mont_eq)
    rintro r ⟨hwf_r, hto_r⟩
    refine ⟨hwf_r, ?_⟩
    rw [hto_r]
    have h_lo_lt_hi : start.val + iter.start.val < start.val + iter.«end».val := by
      have := h_start; scalar_tac
    -- Identify the current write with inttButterflyAt via tbd_toPoly_intt_butterfly_step
    have h_butterfly :
        toPoly a = inttButterflyAt (u32ToZq twiddle_factor * Rinv)
            (toPoly pe_src) (start.val + iter.start.val) len.val h_lo_lt h_hi_lt := by
      apply tbd_toPoly_intt_butterfly_step pe_src
        (u32ToZq twiddle_factor * Rinv)
        (start.val + iter.start.val) len.val h_lo_lt h_hi_lt h_len_pos i4 i6
      · -- u16ToZq i4 = u16ToZq pe_src[j] + u16ToZq pe_src[j+len]
        have h_i_eq : i.val = start.val + iter.start.val := hi_val
        have h_i2_eq : i2.val = start.val + iter.start.val + len.val := by
          rw [hi2_eq, hi_val]
        have step1 : u16ToZq i4 = u32ToZq tmp := by
          unfold u16ToZq u32ToZq; rw [hi4_val]
        rw [step1, h_tmp_eq]
        have h_c0_to_pe : u32ToZq (core.convert.num.FromU32U16.from i1) =
            u16ToZq (pe_src.val[start.val + iter.start.val]'(by rw [← h_i_eq]; exact h_i_lt)) := by
          grind
        have h_c1_to_pe : u32ToZq (core.convert.num.FromU32U16.from i3) =
            u16ToZq (pe_src.val[start.val + iter.start.val + len.val]'(by
              rw [← h_i2_eq]; exact h_i2_lt)) := by
          grind
        rw [h_c0_to_pe, h_c1_to_pe]
      · -- u16ToZq i6 = z * (u16ToZq pe_src[j+len] - u16ToZq pe_src[j])
        have h_i_eq : i.val = start.val + iter.start.val := hi_val
        have h_i2_eq : i2.val = start.val + iter.start.val + len.val := by
          rw [hi2_eq, hi_val]
        have step1 : u16ToZq i6 = u32ToZq c12 := by
          unfold u16ToZq u32ToZq; rw [hi6_val]
        rw [step1, h_c12_eq, h_c11_eq]
        have h_c0_to_pe : u32ToZq (core.convert.num.FromU32U16.from i1) =
            u16ToZq (pe_src.val[start.val + iter.start.val]'(by rw [← h_i_eq]; exact h_i_lt)) := by
          grind
        have h_c1_to_pe : u32ToZq (core.convert.num.FromU32U16.from i3) =
            u16ToZq (pe_src.val[start.val + iter.start.val + len.val]'(by
              rw [← h_i2_eq]; exact h_i2_lt)) := by
          grind
        rw [h_c0_to_pe, h_c1_to_pe]
        ring
      · -- a.val = pe_src.val.set j i4.set (j+len) i6
        have h1 : a.val = pe_src1.val.set i5.val i6 := by rw [ha_eq]; rfl
        have h2 : pe_src1.val = pe_src.val.set i.val i4 := by rw [h_pe_src1]; rfl
        rw [h1, h2, hi5_eq, hi_val]
    rw [h_butterfly]
    -- Peel one inttButterflies step on the RHS
    conv_rhs => rw [inttButterflies, dif_pos h_lo_lt_hi]
    have h_iter1_start_val : iter1.start.val = iter.start.val + 1 := hstart'
    have h_iter1_end_val : iter1.«end».val = iter.«end».val := by rw [hend']
    fcongr 1
    · rw [h_iter1_start_val]; ring
    · exact h_iter1_end_val ▸ rfl
  · -- NONE branch: iter exhausted
    let* ⟨ o, iter1, ho, _ ⟩ ← IteratorRange_next_Usize_none
    rw [ho]
    simp only [WP.spec_ok]
    refine ⟨h_wf, ?_⟩
    have h_eq : iter.start.val = iter.«end».val := by omega
    show toPoly pe_src = inttButterflies _ _ _ _ _ _
    rw [inttButterflies]
    rw [dif_neg (by rw [h_eq]; omega)]

/-! ## Middle loop (start range)

Note: the INTT iterates the twiddle counter `k` **downward** (k--), so
the spec-side index `m` corresponds to `127 - k`, via the
`ZETA_BIT_REV_TIMES_R` layout. -/

/-- **Loop spec** for the inverse middle loop — opaque-iterator witness.

Like the forward NTT middle loop, the `StepBy (Range Usize)` iterator
is opaque, so we parameterize by an existential witness `start_curr`.
Pre/post symmetry.

Informal proof. Template: opaque `StepBy` iterator recursion, symmetric
to `poly_element_ntt_layer_generic_loop0.spec`, but the twiddle counter
decreases and the layer helper is `inttMidLayer`. Unfold
`mlkem.ntt.poly_element_intt_layer_generic_loop0`; the body calls
`IteratorStepBy.next`, returns on `none`, and on `some start` reads the
two twiddle-table entries at `k`, computes `k - 1`, runs the inner GS
loop, and recurses.

1. `step with core.iter.adapters.step_by.IteratorStepBy.next_Range_Usize_some_spec` / `core.iter.adapters.step_by.IteratorStepBy.next_Range_Usize_none_spec`.
2. Step `Array.index_usize mlkem.ntt.ZETA_BIT_REV_TIMES_R k`, using
   `tbd_ZETA_BIT_REV_TIMES_R_spec` to identify the logical twiddle
   `ζ ^ bitRev 7 k.val` expected by `inttMidStep`.
3. Step `core.convert.IntoFrom.into`.
4. Step `Array.index_usize mlkem.ntt.ZETA_BIT_REV_TIMES_R_TIMES_NEG_Q_INV_MOD_R k`,
   using `tbd_ZETA_BIT_REV_TIMES_R_TIMES_NEG_Q_INV_MOD_R_spec` for the
   Montgomery companion side conditions.
5. Step `core.convert.IntoFrom.into`, then `Usize.sub.spec` for `k - 1`.
6. Step with
   `mlkem.ntt.poly_element_intt_layer_generic_loop0_loop0.spec`; its
   post is the current `inttMidStep` / `inttButterflies` application.
7. Step the recursive call with this theorem; the IH gives the
   remaining `inttMidLayer` computation with the decremented counter.

Case analysis: the `none` branch closes by the base branch of
`inttMidLayer`. In the `some` branch, peel `inttMidLayer`: the current
inner-loop result is the head `inttMidStep`, and the recursive call
gives the tail.

Close with `split_conjs`; `agrind` discharges stride, bounds, `wfPoly`,
and the counter arithmetic. -/
@[step]
theorem mlkem.ntt.poly_element_intt_layer_generic_loop0.spec
    (iter : core.iter.adapters.step_by.StepBy (core.ops.range.Range Usize))
    (pe_src : PolyElement) (k len : Usize)
    (h_wf : wfPoly pe_src) (h_len : 0 < len.val) (h_lend : len.val ≤ 128)
    (h_div : 256 % (2 * len.val) = 0)
    (h_k_le : k.val ≤ 127)
    (h_inv : 2 * (k.val + 1) * len.val + iter.iter.start.val = 512)
    (h_iter_end : iter.iter.«end».val = 256)
    (h_iter_step : iter.step_by.val = 2 * len.val)
    (h_iter_start : iter.iter.start.val ≤ 256 ∧
                    iter.iter.start.val % (2 * len.val) = 0) :
    mlkem.ntt.poly_element_intt_layer_generic_loop0 iter pe_src k len
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r =
            (inttMidLayer len.val h_len iter.iter.start.val k.val (toPoly pe_src)).1 ⦄ := by
  unfold mlkem.ntt.poly_element_intt_layer_generic_loop0
  obtain ⟨h_start_le, h_start_mod⟩ := h_iter_start
  have h_2len_pos : 0 < 2 * len.val := by omega
  have h_2len_le : 2 * len.val ≤ 256 := by omega
  by_cases hlt : iter.iter.start.val < iter.iter.«end».val
  · -- SOME branch.
    have h_start_lt : iter.iter.start.val < 256 := by omega
    -- Derive start + 2*len ≤ 256 via divisibility.
    have h_sub_dvd : 2 * len.val ∣ (256 - iter.iter.start.val) :=
      Nat.dvd_sub (Nat.dvd_of_mod_eq_zero h_div)
                  (Nat.dvd_of_mod_eq_zero h_start_mod)
    have h_sub_pos : 0 < 256 - iter.iter.start.val := by omega
    have h_sub_ge_2len : 2 * len.val ≤ 256 - iter.iter.start.val :=
      Nat.le_of_dvd h_sub_pos h_sub_dvd
    have h_start_bound : iter.iter.start.val + 2 * len.val ≤ 256 := by omega
    -- Derive k ≥ 1 from invariant + start_bound.
    have h_k_ge1 : 1 ≤ k.val := by
      -- 2*(k+1)*len + start = 512, start + 2*len ≤ 256, so 2*(k+1)*len ≥ 256 + 2*len.
      -- ⟹ (k+1)*len ≥ 128 + len ⟹ k*len ≥ 128 ⟹ k ≥ 128/len ≥ 1.
      by_contra hk0
      push Not at hk0
      interval_cases k.val
      -- k = 0: 2*1*len + start = 512 ⟹ start = 512 - 2*len ≥ 512 - 256 = 256. Contradiction.
      omega
    -- Iterator step.
    have h_step_pos : iter.step_by.val > 0 := by omega
    have h_no_overflow : iter.iter.start.val + iter.step_by.val ≤ Usize.max := by
      rw [h_iter_step]; scalar_tac
    let* ⟨o, iter1, ho, hiter1_start, hiter1_end, hiter1_step⟩ ←
      core.iter.adapters.step_by.IteratorStepBy.next_Range_Usize_some_spec
    rw [ho]
    simp only
    step as ⟨tw_u16, htw_zq, htw_bv, htw_lt⟩
    step  -- companion ZETA_NEG[k]; auto-names i1, i1_post1..3
    step as ⟨k1, hk1_eq⟩
    -- Bridge BV ⇒ Nat for tw_u16.val.
    have htw_val : tw_u16.val = (17 ^ _root_.bitRev 7 k.val * 65536) % 3329 := by
      have h := congrArg BitVec.toNat htw_bv
      have hmod : (17 ^ _root_.bitRev 7 k.val * 65536) % 3329 < 2 ^ 32 := by
        have := Nat.mod_lt (17 ^ _root_.bitRev 7 k.val * 65536) (by decide : (0 : Nat) < 3329)
        omega
      simp only [BitVec.toNat_setWidth, BitVec.toNat_ofNat,
                 Nat.mod_eq_of_lt hmod] at h
      have hbnd : tw_u16.bv.toNat < 2 ^ 32 := by
        have : tw_u16.bv.toNat < 2 ^ 16 := tw_u16.bv.isLt
        omega
      rw [Nat.mod_eq_of_lt hbnd] at h
      show tw_u16.bv.toNat = _
      exact h
    -- Inner butterfly preconditions.
    have h_tw_lt_q : (core.convert.num.FromU32U16.from tw_u16).val < q := by
      simp only [core.convert.num.FromU32U16.from_val_eq, q]; exact htw_lt
    have h_twm_le : (core.convert.num.FromU32U16.from i1).val ≤ 65535 := by
      simp only [core.convert.num.FromU32U16.from_val_eq]; exact i1_post2
    have h_twm_eq :
        (core.convert.num.FromU32U16.from i1).val =
          ((core.convert.num.FromU32U16.from tw_u16).val * 3327) % 65536 := by
      simp only [core.convert.num.FromU32U16.from_val_eq]
      rw [htw_val]; exact i1_post3
    let* ⟨pe_src1, hwf1, hto_poly1⟩ ←
      mlkem.ntt.poly_element_intt_layer_generic_loop0_loop0.spec
        ({ start := 0#usize, «end» := len } : core.ops.range.Range Usize)
        pe_src len iter.iter.start
        (core.convert.num.FromU32U16.from tw_u16)
        (core.convert.num.FromU32U16.from i1)
        h_wf
        (by simp)
        (by simp)
        h_start_bound
        h_len
        h_tw_lt_q h_twm_le h_twm_eq
    -- Convert (u32ToZq tw * Rinv) to ζ^bitRev_7 k.
    have h_u32ToZq_tw : u32ToZq (core.convert.num.FromU32U16.from tw_u16) =
        ζ ^ _root_.bitRev 7 k.val * 65536 := by
      simp only [u32ToZq, core.convert.num.FromU32U16.from_val_eq]
      exact_mod_cast htw_zq
    have h_tw_Rinv : u32ToZq (core.convert.num.FromU32U16.from tw_u16) * Rinv =
        ζ ^ _root_.bitRev 7 k.val := by
      rw [h_u32ToZq_tw, show (65536 : Zq) = R from by unfold R; decide]
      rw [mul_assoc, R_mul_Rinv, mul_one]
    -- Recurse with k1 = k - 1.
    have hk1v : k1.val = k.val - 1 := hk1_eq
    have hs1v : iter1.iter.start.val = iter.iter.start.val + 2 * len.val := by
      rw [hiter1_start, h_iter_step]
    have h_k_le1 : k1.val ≤ 127 := by omega
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
      (mlkem.ntt.poly_element_intt_layer_generic_loop0.spec iter1 pe_src1 k1 len
        hwf1 h_len h_lend h_div h_k_le1 h_inv1 h_iter_end1 h_iter_step1 h_iter_start1)
    rintro r ⟨hwf_r, hto_r⟩
    refine ⟨hwf_r, ?_⟩
    rw [hto_r]
    conv_rhs => rw [inttMidLayer]
    rw [dif_pos h_start_bound]
    simp only [inttMidStep]
    rw [hto_poly1, h_tw_Rinv]
    simp only [Nat.add_zero] at hto_poly1 ⊢
    rw [hs1v, hk1v]
  · -- NONE branch: iter exhausted.
    have hge : iter.iter.start.val ≥ iter.iter.«end».val := by omega
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

/-! ## Layer wrapper -/

/-- **Layer wrapper spec** (`_generic`).

Informal proof. Template: leaf wrapper with `step*`, symmetric to
`poly_element_ntt_layer_generic.spec`. Unfold
`mlkem.ntt.poly_element_intt_layer_generic`; the body computes stride
`2 * len`, constructs the stepped range `0, 2*len, ...`, and delegates
to `poly_element_intt_layer_generic_loop0`.

1. Step `Usize.mul.spec` for `2#usize * len`.
2. Step `core.iter.traits.iterator.Iterator.step_by.trait_default.spec`; positivity follows
   from `h_len`, and `h_div` / `h_lend` provide the stride/range facts.
3. Step with `mlkem.ntt.poly_element_intt_layer_generic_loop0.spec` at
   iterator start `0`, end `256`, and current counter `k`.

There is no wrapper-level case split. Close by simplifying the
zero-start middle-loop postcondition to
`(inttMidLayer len.val h_len 0 k.val (toPoly pe_src)).1`; `agrind`
closes the stride, divisibility, and bounds obligations. -/
@[step]
theorem mlkem.ntt.poly_element_intt_layer_generic.spec
    (pe_src : PolyElement) (k len : Usize)
    (h_wf : wfPoly pe_src) (h_len : 0 < len.val) (h_lend : len.val ≤ 128)
    (h_div : 256 % (2 * len.val) = 0)
    (h_k_le : k.val ≤ 127)
    (h_k_top : 2 * (k.val + 1) * len.val = 512) :
    mlkem.ntt.poly_element_intt_layer_generic pe_src k len
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r =
            (inttMidLayer len.val h_len 0 k.val (toPoly pe_src)).1 ⦄ := by
  unfold mlkem.ntt.poly_element_intt_layer_generic
  step as ⟨i, hi⟩
  simp only [core.iter.traits.iterator.Iterator.step_by.trait_default, core.iter.traits.iterator.Iterator.step_by.default,
    show ¬ (i.val = 0) from by agrind, if_false]
  apply WP.spec_mono
  · apply mlkem.ntt.poly_element_intt_layer_generic_loop0.spec
      (iter := ⟨{ start := 0#usize, «end» := 256#usize }, i ⟩)
    · exact h_wf
    · exact h_len
    · exact h_lend
    · exact h_div
    · exact h_k_le
    · show 2 * (k.val + 1) * len.val + (0#usize).val = 512
      simp; exact h_k_top
    · rfl
    · show i.val = 2 * len.val; agrind
    · refine ⟨by simp, by simp⟩
  · rintro r ⟨hwf, heq⟩
    exact ⟨hwf, heq⟩

/-! ## SIMD intrinsic-layer specs (per-target dispatch)

Intrinsics-based inverse-NTT layers sit alongside the portable `_generic` path:

  * `mlkem.ntt.poly_element_intt_layer_vec128` — parametric on
    `NttIntrinsicsInterface T Vec128`.
  * `mlkem.ntt.ntt_avx2.intt_layer_avx2` — direct AVX2 (`__m256i`) path.

The strong `@[step]` specs live in:

  * `Symcrust.Properties.MLKEM.Intrinsics.mlkem.ntt.poly_element_intt_layer_vec128.spec`
    (file `Properties/MLKEM/Intrinsics/Vec128LayerIntt.lean`) — parametric in
    `[NttIntrinsicsSpec V Inst]`.
  * `Symcrust.Properties.MLKEM.Intrinsics.mlkem.ntt.ntt_avx2.intt_layer_avx2.spec`
    (file `Properties/MLKEM/Intrinsics/X86_64/Avx2LayerIntt.lean`) — concrete on `__m256i`.

Both produce `(inttMidLayer len h_len 0 k (toPoly pe_src)).1`.  `step*`
in the dispatcher proofs below picks up the strong specs directly from
`Intrinsics/`. See the forward analogue in `Ntt/Ntt.lean`. -/

/-- **Per-target dispatcher (x86_64)** — selects SSE2 (`_vec128` on
`XmmNttInst`) / generic based on `cpu_features_present`.

## Informal proof

Mirrors the forward `Ntt.lean` x86_64 dispatcher.  Body:

```
let b ← cpu_features_present SSE2
if b then poly_element_intt_layer_vec128 XmmNttInst pe k len
else      poly_element_intt_layer_generic pe k len
```

(The AVX2 arm and the `len ≥ 16` gate were removed when the verify-simd
config was dropped; the x86_64 dispatcher is now identical in shape to i686.)

Proof steps:
1. `step` past `cpu_features_present SSE2` (axiomatised `@[step]` in
   `Properties/Axioms/System.lean`).
2. `split_ifs` on the SSE2 bit:
   - `true`: `apply`
     `Symcrust.Properties.MLKEM.Intrinsics.mlkem.ntt.poly_element_intt_layer_vec128.spec`
     with `XmmNttInst` (instance `xmmNttIntrinsicsSpec`).
   - `false`: `apply` `_generic.spec`.

Both arms produce `(inttMidLayer len.val h_len 0 k.val (toPoly pe_src)).1`. -/
@[step]
theorem mlkem.ntt.poly_element_intt_layer.x86_64_unknown_linux_gnu.spec
    (pe_src : PolyElement) (k len : Usize)
    (h_wf : wfPoly pe_src) (h_len : 2 ≤ len.val) (h_lend : len.val ≤ 128)
    (h_div : 256 % (2 * len.val) = 0)
    (h_k_le : k.val ≤ 127)
    (h_k_top : 2 * (k.val + 1) * len.val = 512) :
    mlkem.ntt.poly_element_intt_layer.«x86_64-unknown-linux-gnu» pe_src k len
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r =
            (inttMidLayer len.val (by omega) 0 k.val (toPoly pe_src)).1 ⦄ := by
  have h_dvd : 2 * len.val ∣ 256 := Nat.dvd_of_mod_eq_zero h_div
  have h_step8 : 8 ≤ len.val → len.val % 8 = 0 := by
    intro h; interval_cases len.val <;> omega
  unfold mlkem.ntt.poly_element_intt_layer.«x86_64-unknown-linux-gnu»
  step as ⟨bSse, _⟩
  split_ifs with hSse
  · apply (mlkem.ntt.poly_element_intt_layer_vec128.spec
      (Inst := XmmNttInst) (s := xmmNttIntrinsicsSpec))
      pe_src k len h_wf h_len h_lend h_div h_step8 h_k_top
  · apply mlkem.ntt.poly_element_intt_layer_generic.spec pe_src k len h_wf
      (by omega) h_lend h_div h_k_le h_k_top

/-- **Per-target dispatcher (i686)** — SSE2 / generic dispatch.

## Informal proof

Same shape as the x86_64 dispatcher without the AVX2 arm.  Body:
```
let b ← cpu_features_present SSE2
if b then poly_element_intt_layer_vec128 XmmNttInst pe k len
else      poly_element_intt_layer_generic pe k len
```

`cases b`:
- `true`: `apply`
  `Symcrust.Properties.MLKEM.Intrinsics.mlkem.ntt.poly_element_intt_layer_vec128.spec`
  with `XmmNttInst` (instance `xmmNttIntrinsicsSpec`).
- `false`: `apply` `_generic.spec`. -/
@[step]
theorem mlkem.ntt.poly_element_intt_layer.i686_unknown_linux_gnu.spec
    (pe_src : PolyElement) (k len : Usize)
    (h_wf : wfPoly pe_src) (h_len : 2 ≤ len.val) (h_lend : len.val ≤ 128)
    (h_div : 256 % (2 * len.val) = 0)
    (h_k_le : k.val ≤ 127)
    (h_k_top : 2 * (k.val + 1) * len.val = 512) :
    mlkem.ntt.poly_element_intt_layer.«i686-unknown-linux-gnu» pe_src k len
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r =
            (inttMidLayer len.val (by omega) 0 k.val (toPoly pe_src)).1 ⦄ := by
  have h_dvd : 2 * len.val ∣ 256 := Nat.dvd_of_mod_eq_zero h_div
  have h_step8 : 8 ≤ len.val → len.val % 8 = 0 := by
    intro h; interval_cases len.val <;> omega
  unfold mlkem.ntt.poly_element_intt_layer.«i686-unknown-linux-gnu»
  step as ⟨bSse, _⟩
  split_ifs with hSse
  · apply (mlkem.ntt.poly_element_intt_layer_vec128.spec
      (Inst := XmmNttInst) (s := xmmNttIntrinsicsSpec))
      pe_src k len h_wf h_len h_lend h_div h_step8 h_k_top
  · apply mlkem.ntt.poly_element_intt_layer_generic.spec pe_src k len h_wf
      (by omega) h_lend h_div h_k_le h_k_top

/-- **Per-target dispatcher (aarch64)** — NEON / generic dispatch.

## Informal proof

Body:
```
let b ← cpu_features_present NEON
if b then poly_element_intt_layer_vec128 NeonNttInst pe k len
else      poly_element_intt_layer_generic pe k len
```

`cases b`:
- `true`: `apply`
  `Symcrust.Properties.MLKEM.Intrinsics.mlkem.ntt.poly_element_intt_layer_vec128.spec`
  with `NeonNttInst` (instance `neonNttIntrinsicsSpec`).
- `false`: `apply` `_generic.spec`. -/
@[step]
theorem mlkem.ntt.poly_element_intt_layer.aarch64_unknown_linux_gnu.spec
    (pe_src : PolyElement) (k len : Usize)
    (h_wf : wfPoly pe_src) (h_len : 2 ≤ len.val) (h_lend : len.val ≤ 128)
    (h_div : 256 % (2 * len.val) = 0)
    (h_k_le : k.val ≤ 127)
    (h_k_top : 2 * (k.val + 1) * len.val = 512) :
    mlkem.ntt.poly_element_intt_layer.«aarch64-unknown-linux-gnu» pe_src k len
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r =
            (inttMidLayer len.val (by omega) 0 k.val (toPoly pe_src)).1 ⦄ := by
  have h_dvd : 2 * len.val ∣ 256 := Nat.dvd_of_mod_eq_zero h_div
  have h_step8 : 8 ≤ len.val → len.val % 8 = 0 := by
    intro h; interval_cases len.val <;> omega
  unfold mlkem.ntt.poly_element_intt_layer.«aarch64-unknown-linux-gnu»
  step as ⟨bNeon, _⟩
  split_ifs with hNeon
  · apply (mlkem.ntt.poly_element_intt_layer_vec128.spec
      (Inst := NeonNttInst) (s := neonNttIntrinsicsSpec))
      pe_src k len h_wf h_len h_lend h_div h_step8 h_k_top
  · apply mlkem.ntt.poly_element_intt_layer_generic.spec pe_src k len h_wf
      (by omega) h_lend h_div h_k_le h_k_top

/-- **Layer dispatch wrapper** — top-level `get_target` dispatcher. -/
@[step]
theorem mlkem.ntt.poly_element_intt_layer.spec
    (pe_src : PolyElement) (k len : Usize)
    (h_wf : wfPoly pe_src) (h_len : 2 ≤ len.val) (h_lend : len.val ≤ 128)
    (h_div : 256 % (2 * len.val) = 0)
    (h_k_le : k.val ≤ 127)
    (h_k_top : 2 * (k.val + 1) * len.val = 512) :
    mlkem.ntt.poly_element_intt_layer pe_src k len
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r =
            (inttMidLayer len.val (by omega) 0 k.val (toPoly pe_src)).1 ⦄ := by
  unfold mlkem.ntt.poly_element_intt_layer
  step*

/-! ## Fixup IterMut

`poly_element_intt_and_mul_r_loop` walks a `Slice U16` (= the
polynomial coefficients viewed as a flat slice) and applies
`mont_mul coeff INTT_FIXUP_TIMES_RSQR _` to each — multiplying each
coefficient by `128⁻¹ · R` (in Zq). -/

/-- **Loop spec** for the fixup IterMut.

IterMut over individual coefficients (not whole polys): each U16 is
multiplied by `128⁻¹ · R = INTT_FIXUP · R` in Zq. Canonical IterMut
framing pattern; NOT tagged `@[step]`.

Informal proof. Template: canonical IterMut loop from
`aeneas-postconditions`, with a scalar Montgomery fixup as the element
step. Unfold `mlkem.ntt.poly_element_intt_and_mul_r_loop`; the body
calls `IteratorIterMut.next`, returns `back (next_back iter1 none)` on
`none`, and on `some coeff` converts it to `U32`, applies the INTT
fixup Montgomery multiplication, casts back to `U16`, and recurses with
an updated back continuation.

1. In the `some` branch, step with
   `core.slice.iter.IteratorIterMut.next.spec`.
2. Step `core.convert.IntoFrom.into` for `coeff : U16` to `U32`.
3. Step `mlkem.ntt.mont_mul.spec` with
   `mlkem.ntt.INTT_FIXUP_TIMES_RSQR` and
   `mlkem.ntt.INTT_FIXUP_TIMES_RSQR_TIMES_NEQ_Q_INV_MOD_R`; use
   `ntt_INTT_FIXUP_TIMES_RSQR_zq`, `mont_mul_intt_fixup`, and
   `ntt_INTT_FIXUP_TIMES_RSQR_TIMES_NEQ_Q_INV_MOD_R_val` for the
   precomputed companion side condition.
4. Step `UScalar.cast` back to `U16`.
5. Step the recursive call with this theorem, passing the continuation
   `fun im => back (next_back im (some coeff1))`.

Case analysis: split on `iter.i < iter.slice.len`. In the `some`
branch, rebuild the four back-framing hypotheses. For a queried index
`j`, split into `j = iter.i` (fresh coefficient; use the
`mont_mul_intt_fixup` equation) or `j < iter.i` (old coefficient; use
`hback_writes` / `hback_bound`). For `j ≥ iter.i + 1`, use
`hback_rest`. In the `none` branch, use
`core.slice.iter.IteratorIterMut.next_spec_none` and the existing
`hback_*` hypotheses.

Close with `split_conjs`; use `agrind` for length / index / bound goals
and `simp [Slice.setAtNat]` plus `agrind` for current-slot equations. -/
@[step]
theorem mlkem.ntt.poly_element_intt_and_mul_r_loop.spec
    (iter : core.slice.iter.IterMut U16)
    (back : core.slice.iter.IterMut U16 → core.slice.iter.IterMut U16)
    (orig_slice : Slice U16)
    (h_slice : iter.slice = orig_slice)
    (h_orig_wf : ∀ (i : Nat) (h_i : i < orig_slice.length),
                   (orig_slice.val[i]'(by have := orig_slice.property; grind)).val < q)
    (h_iter_i : iter.i ≤ orig_slice.length)
    (hback_len : ∀ im : core.slice.iter.IterMut U16,
      im.slice.length = orig_slice.length →
      (back im).slice.length = orig_slice.length)
    (hback_writes : ∀ (im : core.slice.iter.IterMut U16)
      (him : im.slice.length = orig_slice.length)
      (j : Nat) (hj : j < iter.i),
        u16ToZq ((back im).slice.val[j]'(by
          have := hback_len im him; have := h_iter_i; scalar_tac)) =
          u16ToZq (orig_slice.val[j]'(by have := h_iter_i; scalar_tac))
            * (128 : Zq)⁻¹ * R)
    (hback_rest : ∀ (im : core.slice.iter.IterMut U16)
      (him : im.slice.length = orig_slice.length)
      (j : Nat) (_ : iter.i ≤ j) (hj_lt : j < orig_slice.length),
        (back im).slice.val[j]'(by have := hback_len im him; scalar_tac) =
          im.slice.val[j]'(by scalar_tac))
    (hback_bound : ∀ (im : core.slice.iter.IterMut U16)
      (him : im.slice.length = orig_slice.length)
      (j : Nat) (hj : j < iter.i),
        ((back im).slice.val[j]'(by
          have := hback_len im him; have := h_iter_i; scalar_tac)).val < q) :
    mlkem.ntt.poly_element_intt_and_mul_r_loop iter back
      ⦃ (r : core.slice.iter.IterMut U16) =>
          ∃ (h_len : r.slice.length = orig_slice.length),
          (∀ j (hj : j < orig_slice.length),
            (r.slice.val[j]'(by have := h_len; scalar_tac)).val < q) ∧
          (∀ j (hj : j < orig_slice.length),
            u16ToZq (r.slice.val[j]'(by have := h_len; scalar_tac)) =
              u16ToZq (orig_slice.val[j]'hj) * (128 : Zq)⁻¹ * R) ⦄ := by
  unfold mlkem.ntt.poly_element_intt_and_mul_r_loop
  by_cases hlt : iter.i < iter.slice.len
  · -- SOME branch: process one coefficient
    let* ⟨ o, iter1, next_back, h_all ⟩ ←
      core.slice.iter.IteratorIterMut.next.spec
    obtain ⟨ho, hit2_slice, hit2_i, _, hsome_set⟩ := h_all
    rw [ho]
    have hLen_eq : (↑iter.slice.len : ℕ) = iter.slice.length := by
      simp [Slice.len, Slice.length]
    have hi_pe : iter.slice.length = orig_slice.length := by rw [h_slice]
    have hi_lt : iter.i < orig_slice.length := by rw [← hi_pe]; scalar_tac
    -- The element extracted is iter.slice[iter.i] = orig_slice[iter.i]
    have hCoeff_val : (iter.slice[iter.i]'(by scalar_tac)).val =
        (orig_slice.val[iter.i]'(by have := orig_slice.property; grind)).val := by
      simp only [h_slice]; rfl
    have h_orig_at_i : (orig_slice.val[iter.i]'(by
        have := orig_slice.property; grind)).val < q :=
      h_orig_wf iter.i hi_lt
    have hCoeff_lt : (iter.slice[iter.i]'(by scalar_tac)).val < q := by
      rw [hCoeff_val]; exact h_orig_at_i
    have hCoeff_le_u16 : (iter.slice[iter.i]'(by scalar_tac)).val ≤ UScalar.max .U16 := by
      simp only [UScalar.max_UScalarTy_U16_eq, U16.max_eq]
      have : (q : Nat) = 3329 := rfl
      have h := hCoeff_lt; rw [this] at h; scalar_tac
    -- Step: into i ← FromU32U16.from coeff, then mont_mul, then cast
    have h_i_lt_q : (core.convert.num.FromU32U16.from
        (iter.slice[iter.i]'(by scalar_tac))).val < q := by
      simp only [core.convert.num.FromU32U16.from_val_eq]; exact hCoeff_lt
    have h_q_eq : (q : Nat) = 3329 := rfl
    have h_INTT_FIXUP_lt : mlkem.ntt.INTT_FIXUP_TIMES_RSQR.val < q := by
      rw [h_q_eq, ntt_INTT_FIXUP_TIMES_RSQR_val]; decide
    have h_INTT_FIXUP_mont_lt :
        mlkem.ntt.INTT_FIXUP_TIMES_RSQR_TIMES_NEQ_Q_INV_MOD_R.val ≤ 65535 := by
      rw [ntt_INTT_FIXUP_TIMES_RSQR_TIMES_NEQ_Q_INV_MOD_R_val]; decide
    have h_INTT_FIXUP_mont_eq :
        mlkem.ntt.INTT_FIXUP_TIMES_RSQR_TIMES_NEQ_Q_INV_MOD_R.val =
          (mlkem.ntt.INTT_FIXUP_TIMES_RSQR.val * 3327) % 65536 := by
      rw [ntt_INTT_FIXUP_TIMES_RSQR_TIMES_NEQ_Q_INV_MOD_R_val,
          ntt_INTT_FIXUP_TIMES_RSQR_val]
    simp only []
    let* ⟨i1, hi1_lt, hi1_zq⟩ ←
      mlkem.ntt.mont_mul.spec
        (core.convert.num.FromU32U16.from iter.slice[iter.i])
        mlkem.ntt.INTT_FIXUP_TIMES_RSQR mlkem.ntt.INTT_FIXUP_TIMES_RSQR_TIMES_NEQ_Q_INV_MOD_R
        h_i_lt_q h_INTT_FIXUP_lt h_INTT_FIXUP_mont_lt h_INTT_FIXUP_mont_eq
    have h_i1_u16 : i1.val ≤ UScalar.max .U16 := by
      simp only [UScalar.max_UScalarTy_U16_eq, U16.max_eq]
      have h := hi1_lt; rw [h_q_eq] at h; scalar_tac
    let* ⟨coeff1, hcoeff1_val⟩ ← UScalar.cast_inBounds_spec
    have hCoeff1_val : coeff1.val = i1.val := hcoeff1_val
    have hCoeff1_lt : coeff1.val < q := by rw [hCoeff1_val]; exact hi1_lt
    -- Establish the Zq equation for the new coefficient
    have h_u16_coeff1 :
        u16ToZq coeff1 =
          u16ToZq (iter.slice[iter.i]'(by scalar_tac)) * (128 : Zq)⁻¹ * R := by
      unfold u16ToZq
      rw [hCoeff1_val]
      have h1 : ((i1.val : Zq)) = u32ToZq i1 := by unfold u32ToZq; rfl
      rw [h1, hi1_zq]
      have h3 : u32ToZq (core.convert.num.FromU32U16.from
                  iter.slice[iter.i]) =
                ((iter.slice[iter.i]'(by scalar_tac)).val : Zq) := by
        unfold u32ToZq
        rw [core.convert.num.FromU32U16.from_val_eq]
        rfl
      rw [h3]
      have hfix := mont_mul_intt_fixup
        ((iter.slice[iter.i]'(by scalar_tac)).val : Zq)
      linear_combination hfix
    -- Recursive call
    apply WP.spec_mono
      (mlkem.ntt.poly_element_intt_and_mul_r_loop.spec iter1
        (fun im => back (next_back im (some coeff1)))
        orig_slice (by rw [hit2_slice, h_slice]) h_orig_wf
        (by rw [hit2_i]; scalar_tac) ?len ?writes ?rest ?bound)
    case len =>
      intro im him
      have him_set : (next_back im (some coeff1)).slice.length = orig_slice.length := by
        rw [hsome_set]; simp only; rw [setAtNat_length]; exact him
      exact hback_len _ him_set
    case writes =>
      intro im him j hj
      rw [hit2_i] at hj
      have him_set : (next_back im (some coeff1)).slice.length = orig_slice.length := by
        rw [hsome_set]; simp only; rw [setAtNat_length]; exact him
      by_cases hji : j = iter.i
      · subst hji
        have hbound : iter.i < im.slice.length := by rw [him]; exact hi_lt
        have hrest := hback_rest (next_back im (some coeff1)) him_set iter.i
          (le_refl _) hi_lt
        have hkey : (back (next_back im (some coeff1))).slice.val[iter.i]'(by
            have := hback_len _ him_set; scalar_tac) = coeff1 := by
          apply hrest.trans
          simp only [hsome_set]
          simp_lists [Slice.getElem_Nat_setAtNat_eq]
        rw [hkey, h_u16_coeff1]
        unfold u16ToZq
        rw [hCoeff_val]
      · have hjlt : j < iter.i := by scalar_tac
        exact hback_writes (next_back im (some coeff1)) him_set j hjlt
    case rest =>
      intro im him j hj_ge hj_lt
      rw [hit2_i] at hj_ge
      have him_set : (next_back im (some coeff1)).slice.length = orig_slice.length := by
        rw [hsome_set]; simp only; rw [setAtNat_length]; exact him
      have hrest := hback_rest (next_back im (some coeff1)) him_set j
        (by scalar_tac) hj_lt
      have hkey : (next_back im (some coeff1)).slice.val[j]'(by
          have := him_set; scalar_tac) = im.slice.val[j]'(by scalar_tac) := by
        simp only [hsome_set]
        simp_lists [Slice.getElem_Nat_setAtNat_ne]
      exact hrest.trans hkey
    case bound =>
      intro im him j hj
      rw [hit2_i] at hj
      have him_set : (next_back im (some coeff1)).slice.length = orig_slice.length := by
        rw [hsome_set]; simp only; rw [setAtNat_length]; exact him
      by_cases hji : j = iter.i
      · subst hji
        have hbound : iter.i < im.slice.length := by rw [him]; exact hi_lt
        have hrest := hback_rest (next_back im (some coeff1)) him_set iter.i
          (le_refl _) hi_lt
        have hkey : (back (next_back im (some coeff1))).slice.val[iter.i]'(by
            have := hback_len _ him_set; scalar_tac) = coeff1 := by
          apply hrest.trans
          simp only [hsome_set]
          simp_lists [Slice.getElem_Nat_setAtNat_eq]
        rw [hkey]; exact hCoeff1_lt
      · have hjlt : j < iter.i := by scalar_tac
        exact hback_bound (next_back im (some coeff1)) him_set j hjlt
    intro r hpost; exact hpost
  · -- NONE branch: iterator exhausted
    have hge : iter.i ≥ iter.slice.len := by scalar_tac
    have hLen_eq : (↑iter.slice.len : ℕ) = iter.slice.length := by
      simp [Slice.len, Slice.length]
    have hi_eq : iter.i = orig_slice.length := by
      have hpe : iter.slice.length = orig_slice.length := by rw [h_slice]
      have : iter.slice.len.val = orig_slice.length := by rw [← hpe]; simp [Slice.len, Slice.length]
      scalar_tac
    let* ⟨o, iter1, next_back, h_all⟩ ←
      core.slice.iter.IteratorIterMut.next_spec_none
    obtain ⟨ho, hit2_eq, hsome_back⟩ := h_all
    rw [ho]
    show (Result.ok (back (next_back iter1 none))) ⦃ _ ⦄
    rw [hsome_back, hit2_eq]
    have hit_pe : iter.slice.length = orig_slice.length := by rw [h_slice]
    refine ⟨hback_len iter hit_pe, ?_, ?_⟩
    · intro j hj
      exact hback_bound iter hit_pe j (hi_eq ▸ hj)
    · intro j hj
      exact hback_writes iter hit_pe j (hi_eq ▸ hj)
  termination_by iter.slice.len.val - iter.i
  decreasing_by scalar_decr_tac

/-! ## Top wrapper `poly_element_intt_and_mul_r`

Composes 7 GS layers + fixup IterMut.

Postcondition: `toPoly result = (MLKEM.NTTInv (toPoly pe_src)).map (R * ·)`.

Informal proof: chain 7 `poly_element_intt_layer.spec` applications
(yielding `c_GS = 128 · NTTInv-prefixup` per coefficient via
`NTTInv_unfold_layers` from `Bridges/NttLoops.lean`).  Then apply the
fixup IterMut spec, which multiplies each coefficient by `128⁻¹ · R`
in Zq.  Combine: `c_final = c_GS · 128⁻¹ · R = NTTInv(input) · R`. -/

/-- **Top spec for `poly_element_intt_and_mul_r`**.

Lands on `MLKEM.NTTInv` with the `R` factor explicit (Montgomery
storage).

Informal proof. Template: leaf wrapper composing seven inverse layers
plus an IterMut fixup; analogue is `poly_element_ntt.spec`, with inverse
bridge `inttFixup_inttOuter_eq_NTTInv`. Unfold
`mlkem.ntt.poly_element_intt_and_mul_r`; the body applies seven
`poly_element_intt_layer` calls, converts the resulting array to a
mutable slice, runs the coefficient fixup loop, and closes the slice
back to an array.

1. Step with `mlkem.ntt.poly_element_intt_layer.spec` at
   `(k, len) = (127, 2)`.
2. Step with `mlkem.ntt.poly_element_intt_layer.spec` at `(63, 4)`.
3. Step with `mlkem.ntt.poly_element_intt_layer.spec` at `(31, 8)`.
4. Step with `mlkem.ntt.poly_element_intt_layer.spec` at `(15, 16)`.
5. Step with `mlkem.ntt.poly_element_intt_layer.spec` at `(7, 32)`.
6. Step with `mlkem.ntt.poly_element_intt_layer.spec` at `(3, 64)`.
7. Step with `mlkem.ntt.poly_element_intt_layer.spec` at `(1, 128)`.
   These posts reconstruct `inttOuter 2 (by decide) 127 (toPoly pe_src)`.
8. Step `Array.to_slice_mut.spec`; it exposes the coefficient slice and
   the back closure to rebuild the array.
9. Step `core.slice.Slice.iter_mut.spec`.
10. Step with `mlkem.ntt.poly_element_intt_and_mul_r_loop.spec`; it
    multiplies every coefficient by `128⁻¹ · R` in `Zq`.
11. Step the final `ok` / back closures from `iter_mut_back` and
    `to_slice_mut_back`.

No wrapper-level match remains after the seven layer calls. Use
`NTTInv_unfold_layers` and `inttFixup_inttOuter_eq_NTTInv` to identify
the seven GS layers plus spec fixup with `MLKEM.NTTInv`; combine this
with the loop's Montgomery fixup equation (`mont_mul_intt_fixup`) to
obtain `(MLKEM.NTTInv (toPoly pe_src)).map (R * ·)`.

Close with `split_conjs`; `agrind` handles layer preconditions,
slice / array lengths, and `wfPoly`, while targeted
`simp [NTTInv_unfold_layers]` followed by `agrind` closes the FC
equality. -/
@[step]
theorem mlkem.ntt.poly_element_intt_and_mul_r.spec
    (pe_src : PolyElement) (h_wf : wfPoly pe_src) :
    mlkem.ntt.poly_element_intt_and_mul_r pe_src
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r = (MLKEM.NTTInv (toPoly pe_src)).map (R * ·) ⦄ := by
  unfold mlkem.ntt.poly_element_intt_and_mul_r
  step*
  case _ =>
    -- h_orig_wf precondition for the fixup loop
    intro i hi
    have h_pe7_len : pe_src7.val.length = 256 := pe_src7.property
    have hi_s : i < s.val.length := hi
    have hi256 : i < 256 := by rw [s_post1] at hi_s; rw [h_pe7_len] at hi_s; exact hi_s
    have h_pe := pe_src7_post1 i hi256
    have h_eq : (↑s : List _)[i] = pe_src7.val[i]'(by rw [h_pe7_len]; exact hi256) := by
      fcongr 1
    rw [h_eq]; exact h_pe
  rw [iter_post3, s_post2]
  have h_pe7_len : pe_src7.val.length = 256 := pe_src7.property
  have h_s_len : s.val.length = 256 := by rw [s_post1]; exact h_pe7_len
  have h_back_len : back.slice.val.length = 256 := by
    show back.slice.length = 256; rw [back_post1]; exact h_s_len
  have h_from_val : (pe_src7.from_slice back.slice).val = back.slice.val :=
    Aeneas.Std.Array.from_slice_val pe_src7 back.slice h_back_len
  refine ⟨?_, ?_⟩
  · -- wfPoly result
    intro i hi
    have hi_s : i < s.val.length := by rw [h_s_len]; exact hi
    have hi_back : i < back.slice.val.length := by rw [h_back_len]; exact hi
    have hi_fs : i < (pe_src7.from_slice back.slice).val.length := by
      rw [h_from_val]; exact hi_back
    have h_bp := back_post2 i hi_s
    show ((pe_src7.from_slice back.slice).val[i]'hi_fs).val < q
    have h_idx : (pe_src7.from_slice back.slice).val[i]'hi_fs = back.slice.val[i]'hi_back := by
      fcongr 1
    rw [h_idx]; exact h_bp
  · -- toPoly equality
    rw [NTTInv_unfold_layers]
    simp only [← pe_src7_post2, ← pe_src6_post2, ← pe_src5_post2,
               ← pe_src4_post2, ← pe_src3_post2, ← pe_src2_post2,
               ← pe_src1_post2]
    show toPoly (pe_src7.from_slice back.slice) = _
    apply Vector.ext
    intro j hj
    unfold toPoly inttFixup
    simp only [Vector.getElem_ofFn, Vector.getElem_map]
    have hj_s : j < s.val.length := by rw [h_s_len]; exact hj
    have hj_back : j < back.slice.val.length := by rw [h_back_len]; exact hj
    have hj_pe7 : j < pe_src7.val.length := by rw [h_pe7_len]; exact hj
    have hj_fs : j < (pe_src7.from_slice back.slice).val.length := by
      rw [h_from_val]; exact hj_back
    have h_eq := back_post3 j hj_s
    have h_orig_get : u16ToZq (s.val[j]'hj_s) = u16ToZq (pe_src7.val[j]'hj_pe7) := by
      simp only [s_post1, u16ToZq]
    rw [h_orig_get] at h_eq
    have h_idx : (pe_src7.from_slice back.slice).val[j]'hj_fs
        = back.slice.val[j]'hj_back := by fcongr 1
    rw [h_idx, h_eq]
    have h_inv : (128 : Zq)⁻¹ = (3303 : Zq) :=
      ZMod.inv_eq_of_mul_eq_one q 128 3303 (by decide)
    rw [h_inv]; ring

/-! ## Vector wrapper -/

/-- **Loop spec** for `vector_intt_and_mul_r_loop` (IterMut over polys).

Canonical IterMut framing pattern; NOT tagged `@[step]`.

Informal proof. Template: canonical IterMut loop from
`aeneas-postconditions`, symmetric to `vector_ntt_loop.spec`, with
`poly_element_intt_and_mul_r.spec` as the element step. Unfold
`mlkem.ntt.vector_intt_and_mul_r_loop`; the body calls
`IteratorIterMut.next`, returns through `back` on `none`, and on
`some pe_src` computes `poly_element_intt_and_mul_r pe_src` before
recursing with the updated back continuation.

1. In the `some` branch, step with
   `core.slice.iter.IteratorIterMut.next.spec`.
2. Step with `mlkem.ntt.poly_element_intt_and_mul_r.spec`; the input
   `wfPoly` comes from `h_orig_wf` and the current cursor.
3. Step the recursive call with this theorem using
   `fun im => back (next_back im (some pe_src1))`. The IH states that
   all entries before the new cursor have been transformed by
   `(MLKEM.NTTInv ...).map (R * ·)`, rest entries are framed, length is
   preserved, and processed entries remain `wfPoly`.
4. In the `none` branch, step with
   `core.slice.iter.IteratorIterMut.next_spec_none` and close from the
   existing `hback_*` hypotheses.

Case analysis: split on `iter.i < iter.slice.len`. In the `some`
branch, for each index `j`, split `j = iter.i` (fresh element; use
`poly_element_intt_and_mul_r.spec` and the `next_back` set equation)
from `j < iter.i` (old processed element; use `hback_writes` /
`hback_inv`) and the rest frame (`hback_rest`).

Close with `split_conjs`; use `agrind` for index and length facts and
`simp [Slice.setAtNat]` plus `agrind` for the current-slot equality. -/
@[step]
theorem mlkem.ntt.vector_intt_and_mul_r_loop.spec
    (iter : core.slice.iter.IterMut (PolyElement))
    (back : core.slice.iter.IterMut (PolyElement) →
            core.slice.iter.IterMut (PolyElement))
    (orig_slice : Slice (PolyElement))
    (h_slice : iter.slice = orig_slice)
    (h_orig_wf : wfPolyVec orig_slice)
    (h_iter_i : iter.i ≤ orig_slice.length)
    (hback_len : ∀ im : core.slice.iter.IterMut (PolyElement),
      im.slice.length = orig_slice.length →
      (back im).slice.length = orig_slice.length)
    (hback_writes : ∀ (im : core.slice.iter.IterMut (PolyElement))
      (him : im.slice.length = orig_slice.length)
      (j : Nat) (hj : j < iter.i),
        toPoly ((back im).slice.val[j]'(by
          have := hback_len im him; have := h_iter_i; scalar_tac))
        = (MLKEM.NTTInv (toPoly (orig_slice.val[j]'(by
            have := h_iter_i; scalar_tac)))).map (R * ·))
    (hback_rest : ∀ (im : core.slice.iter.IterMut (PolyElement))
      (him : im.slice.length = orig_slice.length)
      (j : Nat) (_ : iter.i ≤ j) (hj_lt : j < orig_slice.length),
        (back im).slice.val[j]'(by
          have := hback_len im him; scalar_tac)
          = im.slice.val[j]'(by scalar_tac))
    (hback_inv : ∀ (im : core.slice.iter.IterMut (PolyElement))
      (him : im.slice.length = orig_slice.length)
      (j : Nat) (hj : j < iter.i),
        wfPoly ((back im).slice.val[j]'(by
          have := hback_len im him; have := h_iter_i; scalar_tac))) :
    mlkem.ntt.vector_intt_and_mul_r_loop iter back
      ⦃ (r : core.slice.iter.IterMut (PolyElement)) =>
          ∃ (h_len : r.slice.length = orig_slice.length),
          (∀ j (hj : j < orig_slice.length),
            wfPoly (r.slice.val[j]'(by have := h_len; scalar_tac))) ∧
          (∀ j (hj : j < orig_slice.length),
            toPoly (r.slice.val[j]'(by have := h_len; scalar_tac))
              = (MLKEM.NTTInv (toPoly (orig_slice.val[j]'hj))).map (R * ·)) ⦄ := by
  unfold mlkem.ntt.vector_intt_and_mul_r_loop
  by_cases hlt : iter.i < iter.slice.len
  · -- SOME branch
    let* ⟨ o, iter1, next_back, h_all ⟩ ←
      core.slice.iter.IteratorIterMut.next.spec
    obtain ⟨ho, hit2_slice, hit2_i, _, hsome_set⟩ := h_all
    rw [ho]
    have hLen_eq : (↑iter.slice.len : ℕ) = iter.slice.length := by
      simp [Slice.len, Slice.length]
    have hi_pe : iter.slice.length = orig_slice.length := by rw [h_slice]
    have hi_lt : iter.i < orig_slice.length := by rw [← hi_pe]; scalar_tac
    have hCoeff_eq : iter.slice[iter.i]'(by scalar_tac) =
        orig_slice.val[iter.i]'(by have := orig_slice.property; grind) := by
      simp only [h_slice]; rfl
    have h_pe_wf : wfPoly (iter.slice[iter.i]'(by scalar_tac)) := by
      rw [hCoeff_eq]; exact h_orig_wf iter.i hi_lt
    simp only []
    let* ⟨pe_src1, hwf_new, hntt_eq⟩ ←
      mlkem.ntt.poly_element_intt_and_mul_r.spec _ h_pe_wf
    -- Recursive call
    apply WP.spec_mono
      (mlkem.ntt.vector_intt_and_mul_r_loop.spec iter1
        (fun im => back (next_back im (some pe_src1)))
        orig_slice (by rw [hit2_slice, h_slice]) h_orig_wf
        (by rw [hit2_i]; scalar_tac) ?len ?writes ?rest ?inv)
    case len =>
      intro im him
      have him_set : (next_back im (some pe_src1)).slice.length = orig_slice.length := by
        rw [hsome_set]; simp only; rw [Bridges.setAtNat_length]; exact him
      exact hback_len _ him_set
    case writes =>
      intro im him j hj
      rw [hit2_i] at hj
      have him_set : (next_back im (some pe_src1)).slice.length = orig_slice.length := by
        rw [hsome_set]; simp only; rw [Bridges.setAtNat_length]; exact him
      by_cases hji : j = iter.i
      · subst hji
        have hbound : iter.i < im.slice.length := by rw [him]; exact hi_lt
        have hrest := hback_rest (next_back im (some pe_src1)) him_set iter.i
          (le_refl _) hi_lt
        have hkey : (back (next_back im (some pe_src1))).slice.val[iter.i]'(by
            have := hback_len _ him_set; scalar_tac) = pe_src1 := by
          apply hrest.trans
          simp only [hsome_set]
          simp_lists [Slice.getElem_Nat_setAtNat_eq]
        rw [hkey, hntt_eq, hCoeff_eq]
      · have hjlt : j < iter.i := by scalar_tac
        exact hback_writes (next_back im (some pe_src1)) him_set j hjlt
    case rest =>
      intro im him j hj_ge hj_lt
      rw [hit2_i] at hj_ge
      have him_set : (next_back im (some pe_src1)).slice.length = orig_slice.length := by
        rw [hsome_set]; simp only; rw [Bridges.setAtNat_length]; exact him
      have hrest := hback_rest (next_back im (some pe_src1)) him_set j
        (by scalar_tac) hj_lt
      have hkey : (next_back im (some pe_src1)).slice.val[j]'(by
          have := him_set; scalar_tac) = im.slice.val[j]'(by scalar_tac) := by
        simp only [hsome_set]
        simp_lists [Slice.getElem_Nat_setAtNat_ne]
      exact hrest.trans hkey
    case inv =>
      intro im him j hj
      rw [hit2_i] at hj
      have him_set : (next_back im (some pe_src1)).slice.length = orig_slice.length := by
        rw [hsome_set]; simp only; rw [Bridges.setAtNat_length]; exact him
      by_cases hji : j = iter.i
      · subst hji
        have hbound : iter.i < im.slice.length := by rw [him]; exact hi_lt
        have hrest := hback_rest (next_back im (some pe_src1)) him_set iter.i
          (le_refl _) hi_lt
        have hkey : (back (next_back im (some pe_src1))).slice.val[iter.i]'(by
            have := hback_len _ him_set; scalar_tac) = pe_src1 := by
          apply hrest.trans
          simp only [hsome_set]
          simp_lists [Slice.getElem_Nat_setAtNat_eq]
        rw [hkey]; exact hwf_new
      · have hjlt : j < iter.i := by scalar_tac
        exact hback_inv (next_back im (some pe_src1)) him_set j hjlt
    intro r hpost; exact hpost
  · -- NONE branch
    have hge : iter.i ≥ iter.slice.len := by scalar_tac
    have hLen_eq : (↑iter.slice.len : ℕ) = iter.slice.length := by
      simp [Slice.len, Slice.length]
    have hi_eq : iter.i = orig_slice.length := by
      have hpe : iter.slice.length = orig_slice.length := by rw [h_slice]
      have : iter.slice.len.val = orig_slice.length := by
        rw [← hpe]; simp [Slice.len, Slice.length]
      scalar_tac
    let* ⟨ o, iter1, next_back, h_all ⟩ ←
      core.slice.iter.IteratorIterMut.next_spec_none
    obtain ⟨ho, hit2_eq, hsome_back⟩ := h_all
    rw [ho]
    show (Result.ok (back (next_back iter1 none))) ⦃ _ ⦄
    rw [hsome_back, hit2_eq]
    have hit_pe : iter.slice.length = orig_slice.length := by rw [h_slice]
    refine ⟨hback_len iter hit_pe, ?_, ?_⟩
    · intro j hj; exact hback_inv iter hit_pe j (hi_eq ▸ hj)
    · intro j hj; exact hback_writes iter hit_pe j (hi_eq ▸ hj)
  termination_by iter.slice.len.val - iter.i
  decreasing_by scalar_decr_tac

/-- **Top spec for `vector_intt_and_mul_r`**.

Postcondition: every output poly is the Montgomery-form NTTInv of the
input.

Informal proof. Template: leaf wrapper around an IterMut loop,
symmetric to `vector_ntt.spec`. Unfold
`mlkem.ntt.vector_intt_and_mul_r`; the body checks the row count,
obtains a mutable iterator, calls `vector_intt_and_mul_r_loop`, and
applies the iterator-back closure.

1. Step `Slice.len` / `Usize` comparisons for `n_rows > 0` and
   `n_rows ≤ MATRIX_MAX_NROWS`; discharge the two `massert`s from
   `h_n`.
2. Step with `core.slice.Slice.iter_mut.spec`; it gives
   `iter.slice = pv_src`, `iter.i = 0`, and the final back-closure
   equation.
3. Step with `mlkem.ntt.vector_intt_and_mul_r_loop.spec`, instantiating
   `back = id`. The initial processed-prefix hypotheses are vacuous;
   rest, length, and well-formedness framing follow from identity and
   `h_wf`.
4. Step the final `ok (iter_mut_back back)` and rewrite using the
   `iter_mut_back` postcondition.

No wrapper-level algorithmic case split remains. Close with
`split_conjs`; `agrind` proves `wfPolyVec`, supplies the existential
length witness, and transfers the loop's per-index equality into the
theorem's indexed postcondition. -/
@[step]
theorem mlkem.ntt.vector_intt_and_mul_r.spec
    (pv_src : Slice (PolyElement))
    (h_wf : wfPolyVec pv_src)
    (h_n : pv_src.length > 0 ∧ pv_src.length ≤ 4) :
    mlkem.ntt.vector_intt_and_mul_r pv_src
      ⦃ (r : Slice (PolyElement)) =>
          wfPolyVec r ∧
          ∃ (h_len : r.length = pv_src.length),
          ∀ (i : Nat) (h_i : i < r.length),
            toPoly (r.val[i])
              = (MLKEM.NTTInv (toPoly pv_src.val[i])).map (R * ·) ⦄ := by
  unfold mlkem.ntt.vector_intt_and_mul_r
  step*
  case _ =>
    unfold mlkem.ntt.MATRIX_MAX_NROWS
    show pv_src.length ≤ 4
    exact h_n.2
  rw [iter_post3]
  refine ⟨?_, back_post1, ?_⟩
  · intro i hi
    have hi' : i < pv_src.length := by rw [← back_post1]; exact hi
    exact back_post2 i hi'
  · intro i hi
    have hi' : i < pv_src.length := by rw [← back_post1]; exact hi
    exact back_post3 i hi'

end Symcrust.Properties.MLKEM
