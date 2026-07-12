/-
  # Ntt/Ntt.lean — Step-specs for the forward NTT.

  Covers (bottom-up):

      mlkem.ntt.poly_element_ntt_layer_generic_loop0_loop0  -- inner butterfly loop
      mlkem.ntt.poly_element_ntt_layer_generic_loop0        -- middle (start) loop
      mlkem.ntt.poly_element_ntt_layer_generic              -- one NTT layer
      mlkem.ntt.poly_element_ntt_layer                      -- dispatch wrapper (trivial)
      mlkem.ntt.poly_element_ntt                            -- 7-layer composition
      mlkem.ntt.vector_ntt_loop                             -- IterMut over a slice
      mlkem.ntt.vector_ntt                                  -- top-level vector NTT

  Bridge to spec: by `nttOuter_eq_NTT` (and `NTT_unfold_layers`),
  the 7 sequential `poly_element_ntt_layer` calls equal
  `MLKEM.NTT` on the underlying polynomial.

  ## Postcondition shape

  * **Inner butterfly loop** (`_loop0_loop0`):
    `toPoly result = nttButterflies (u32ToZq twiddle_factor) (toPoly pe_src)
                       len iter.start (iter.«end») ...`
    Preconditions tie `twiddle_factor < q`, `twiddle_factor_mont` to the
    Mont companion of `twiddle_factor` (per `mont_mul.spec` + M3), and
    `start + 2·len ≤ 256` for the index bound.
  * **Middle loop** (`_loop0`): postcondition uses `nttMidLayer` over
    the `start` range; threads twiddle counter `k`.
  * **Layer wrapper** (`_layer_generic`, `_layer`):
    `toPoly result = (nttMidLayer len (by omega) 0 k (toPoly pe_src)).1`.
  * **Top wrapper** (`poly_element_ntt`):
    `toPoly result = MLKEM.NTT (toPoly pe_src)` (via 7 layer
    compositions + `NTT_unfold_layers`).
  * **Vector wrapper** (`vector_ntt`):
    `toPolyVec result = (toPolyVec pv_src).map MLKEM.NTT`.

  ## Key bridge: twiddle factor in Montgomery storage

  `ZETA_BIT_REV_TIMES_R[k]` stores `ζ^{bitRev 7 k} · R mod q`, and
  `ZETA_BIT_REV_TIMES_R_TIMES_NEG_Q_INV_MOD_R[k]` stores its `-q⁻¹ mod R`
  companion (used for Montgomery reduction).  The product
  `mont_mul c1 twiddle_factor twiddle_factor_mont` therefore equals
  `c1 · twiddle_factor · Rinv = c1 · ζ^{bitRev 7 k}` in Zq — exactly the
  spec-side multiplication.  This is the bridge that links impl-storage
  to `nttButterflyAt`'s pure-Zq update.
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.MontArith
import Symcrust.Properties.MLKEM.Bridges.NttLoops
import Symcrust.Properties.MLKEM.Bridges.NttLinearity
import Symcrust.Properties.MLKEM.Ntt.ModArith
import Symcrust.Properties.MLKEM.Ntt.Twiddles
import Symcrust.Properties.MLKEM.Bridges.Iterators
import Symcrust.Properties.Iterators
import Symcrust.Properties.Axioms.System
import Symcrust.Properties.MLKEM.Intrinsics.Vec128LayerNtt
import Symcrust.Properties.MLKEM.Intrinsics.X86_64.Avx2LayerNtt
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

/-! ## Inner butterfly loop

`poly_element_ntt_layer_generic_loop0_loop0` iterates `j` over
`[iter.start, iter.«end»)`, performing one Cooley–Tukey butterfly per
`j`:
    `t := mont_mul pe_src[j+len] twiddle_factor twiddle_factor_mont`
    `pe_src[j]      := mod_add pe_src[j] t`
    `pe_src[j+len]  := mod_sub pe_src[j] t`

The twiddle factor is `ζ^{bitRev 7 k}`; in storage,
`twiddle_factor = ζ^{bitRev 7 k} · R mod q` (Montgomery-form constant
read from `ZETA_BIT_REV_TIMES_R[k]`) and `twiddle_factor_mont` is the
matching `-q⁻¹·R⁻¹` companion.  By `mont_mul.spec` + Bridge M3, the
runtime product `mont_mul c1 twiddle_factor twiddle_factor_mont`
equals `c1 · ζ^{bitRev 7 k}` in Zq — which is exactly the spec-side
`t = z · f̂[j+len]` of one CT butterfly. -/

/-- **Loop spec** for the inner butterfly.

Informal proof. Template: Range-loop induction per `proof-patterns` §1, with
the per-butterfly bridge `toPoly_ntt_butterfly_step` from
`Bridges/NttLoops.lean`. Unfold
`mlkem.ntt.poly_element_ntt_layer_generic_loop0_loop0`; the body first calls
`IteratorRange.next`, returns immediately on `none`, and in the `some j`
branch computes indices `start + j` and `start + j + len`, reads the two
coefficients, performs one Cooley–Tukey butterfly, writes both slots, and
recurses on `iter1`.

1. `step with IteratorRange_next_some` / `IteratorRange_next_none` — split
   the range iterator.
2. In the `some` branch, step `Usize.add.spec` for `i = start + j`,
   `Array.index_usize.spec`, `core.convert.IntoFrom.into`, and the `massert`
   proving the first coefficient is `< q`.
3. Step `Usize.add.spec` for `i + len`, `Array.index_usize.spec`,
   `core.convert.IntoFrom.into`, and the second `< q` `massert`.
4. Step `mlkem.ntt.mont_mul.spec`, then `mlkem.ntt.mod_sub.spec` and
   `mlkem.ntt.mod_add.spec`; use the caller-supplied twiddle calibration
   `h_tw`, the Montgomery cancellation lemmas `mont_mul_R_right` /
   `R_mul_Rinv`, and the bounds hypotheses to obtain the two `Zq` equations
   expected by `toPoly_ntt_butterfly_step`.
5. Step `UScalar.cast` and `Array.update.spec` for the write at `i`, then
   `Usize.add.spec`, `UScalar.cast`, and `Array.update.spec` for the write
   at `i + len`.
6. Step the recursive call with this theorem; the IH states that from
   `iter1.start = iter.start + 1` to `iter.end` the result equals
   `nttButterflies` applied to the polynomial after the current butterfly.

Case analysis: the `none` case closes because `iter.start ≥ iter.end`, so
`nttButterflies` takes its base branch. In the `some` case, rewrite the
postcondition using one peel of `nttButterflies`; the current write is
identified with `nttButterflyAt` by `toPoly_ntt_butterfly_step`, and the
recursive call supplies the tail.

Close with `split_conjs`; use `agrind` for bounds / well-formedness and
targeted `simp [*]` followed by `agrind` for the `nttButterflies` peel. -/
@[step]
theorem mlkem.ntt.poly_element_ntt_layer_generic_loop0_loop0.spec
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
    mlkem.ntt.poly_element_ntt_layer_generic_loop0_loop0
        iter pe_src len start twiddle_factor twiddle_factor_mont
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r =
            nttButterflies (u32ToZq twiddle_factor * Rinv)
                (toPoly pe_src) len.val
                (start.val + iter.start.val)
                (start.val + iter.«end».val)
                (by have := h_bound; have := h_end; grind) ⦄ := by
  unfold mlkem.ntt.poly_element_ntt_layer_generic_loop0_loop0
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
    -- Precondition for the upcoming massert: the dependent-index read.
    have h_pe_i_lt_q : (pe_src.val[i.val]'h_i_lt).val < q :=
      h_wf i.val h_i_lt_256
    -- c0 ← FromU32U16.from i1 (silent); massert c0 < Q (auto via h_pe_i_lt_q)
    -- i2 ← i + len  (auto via h_hi_lt)
    -- i3 ← Array.index_usize pe_src i2  (need pe_src.val[i+len] < q)
    -- Build i2 = i + len, i3 = pe_src.val[i+len]
    step  -- IntoFrom.into (silent) + massert (discharged by h_pe_i_lt_q)
    step as ⟨i2, hi2_eq⟩
    let* ⟨ i3, hi3 ⟩ ← Array.index_usize_spec
    have h_i2_lt_256 : i2.val < 256 := by rw [hi2_eq, hi_val]; scalar_tac
    have h_i2_lt : i2.val < pe_src.val.length := by rw [h_pe_len]; exact h_i2_lt_256
    have hi3_lt_q : i3.val < q := by
      have := h_wf i2.val h_i2_lt_256
      grind
    have h_pe_i2_lt_q : (pe_src.val[i2.val]'h_i2_lt).val < q :=
      h_wf i2.val h_i2_lt_256
    -- c1 ← FromU32U16.from i3 (silent); massert c1 < Q
    step  -- IntoFrom.into i3 + massert
    -- c1_times_twiddle ← mont_mul c1 tw tw_mont  — use mont_mul.spec (NOT _twiddle)
    have h_c1_lt_q : (core.convert.num.FromU32U16.from i3).val < q := by
      simp only [core.convert.num.FromU32U16.from_val_eq]; exact hi3_lt_q
    let* ⟨c1tw, h_c1tw_lt, h_c1tw_eq⟩ ←
      mlkem.ntt.mont_mul.spec (core.convert.num.FromU32U16.from i3)
        twiddle_factor twiddle_factor_mont h_c1_lt_q h_tw_lt_q
        h_tw_mont_bound h_tw_mont_eq
    -- c11 ← mod_sub c0 c1tw
    have h_c0_lt_q : (core.convert.num.FromU32U16.from i1).val < q := by
      simp only [core.convert.num.FromU32U16.from_val_eq]; exact hi1_lt_q
    let* ⟨c11, h_c11_lt, h_c11_eq⟩ ←
      mlkem.ntt.mod_sub.spec (core.convert.num.FromU32U16.from i1) c1tw h_c0_lt_q h_c1tw_lt
    -- c01 ← mod_add c0 c1tw
    let* ⟨c01, h_c01_lt, h_c01_eq⟩ ←
      mlkem.ntt.mod_add.spec (core.convert.num.FromU32U16.from i1) c1tw h_c0_lt_q h_c1tw_lt
    -- i4 ← UScalar.cast .U16 c01  (with c01.val < q < 2^16)
    have h_c01_u16 : c01.val ≤ UScalar.max .U16 := by
      simp only [UScalar.max_UScalarTy_U16_eq, U16.max_eq]
      have : (q : Nat) = 3329 := rfl
      have h := h_c01_lt; rw [this] at h; scalar_tac
    let* ⟨i4, hi4_eq⟩ ← UScalar.cast_inBounds_spec
    -- pe_src1 ← Array.update pe_src i i4
    let* ⟨pe_src1, h_pe_src1⟩ ← Array.update_spec
    -- i5 ← i + len  (auto)
    step as ⟨i5, hi5_eq⟩
    -- i6 ← UScalar.cast .U16 c11
    have h_c11_u16 : c11.val ≤ UScalar.max .U16 := by
      simp only [UScalar.max_UScalarTy_U16_eq, U16.max_eq]
      have : (q : Nat) = 3329 := rfl
      have h := h_c11_lt; rw [this] at h; scalar_tac
    let* ⟨i6, hi6_eq⟩ ← UScalar.cast_inBounds_spec
    -- a ← Array.update pe_src1 i5 i6
    let* ⟨a, ha_eq⟩ ← Array.update_spec
    -- Build wfPoly a for the recursive call.
    have hi4_val : i4.val = c01.val := hi4_eq
    have hi6_val : i6.val = c11.val := hi6_eq
    have hi4_lt_q : i4.val < q := by rw [hi4_val]; exact h_c01_lt
    have hi6_lt_q : i6.val < q := by rw [hi6_val]; exact h_c11_lt
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
      (mlkem.ntt.poly_element_ntt_layer_generic_loop0_loop0.spec iter1 a len start
        twiddle_factor twiddle_factor_mont h_a_wf h_iter1_start_le h_iter1_end_le_len
        h_bound h_len_pos h_tw_lt_q h_tw_mont_bound h_tw_mont_eq)
    rintro r ⟨hwf_r, hto_r⟩
    refine ⟨hwf_r, ?_⟩
    -- Peel one nttButterflies step on the RHS.
    rw [hto_r]
    have h_lo_lt_hi : start.val + iter.start.val < start.val + iter.«end».val := by
      have := h_start; scalar_tac
    -- Identify the current write with nttButterflyAt via toPoly_ntt_butterfly_step
    have h_butterfly :
        toPoly a = nttButterflyAt (u32ToZq twiddle_factor * Rinv)
            (toPoly pe_src) (start.val + iter.start.val) len.val h_lo_lt h_hi_lt := by
      apply toPoly_ntt_butterfly_step pe_src
        (u32ToZq twiddle_factor * Rinv)
        (start.val + iter.start.val) len.val h_lo_lt h_hi_lt h_len_pos i4 i6
      · -- u16ToZq i4 = u16ToZq pe_src[j] + z * u16ToZq pe_src[j+len]
        have h_i_eq : i.val = start.val + iter.start.val := hi_val
        have h_i2_eq : i2.val = start.val + iter.start.val + len.val := by
          rw [hi2_eq, hi_val]
        -- Convert u16ToZq i4 to u32ToZq c01 through hi4_val
        have step1 : u16ToZq i4 = u32ToZq c01 := by
          unfold u16ToZq u32ToZq; rw [hi4_val]
        rw [step1, h_c01_eq, h_c1tw_eq]
        -- Now goal: u32ToZq c0 + u32ToZq c1 * u32ToZq tw * Rinv = u16ToZq pe[j] + z * u16ToZq pe[j+len]
        -- where c0 = FromU32U16.from i1, c1 = FromU32U16.from i3, z = u32ToZq tw * Rinv
        have h_c0_to_pe : u32ToZq (core.convert.num.FromU32U16.from i1) =
            u16ToZq (pe_src.val[start.val + iter.start.val]'(by rw [← h_i_eq]; exact h_i_lt)) := by
          grind
        have h_c1_to_pe : u32ToZq (core.convert.num.FromU32U16.from i3) =
            u16ToZq (pe_src.val[start.val + iter.start.val + len.val]'(by
              rw [← h_i2_eq]; exact h_i2_lt)) := by
          grind
        rw [h_c0_to_pe, h_c1_to_pe]
        ring
      · -- u16ToZq i6 = u16ToZq pe_src[j] - z * u16ToZq pe_src[j+len]
        have h_i_eq : i.val = start.val + iter.start.val := hi_val
        have h_i2_eq : i2.val = start.val + iter.start.val + len.val := by
          rw [hi2_eq, hi_val]
        have step1 : u16ToZq i6 = u32ToZq c11 := by
          unfold u16ToZq u32ToZq; rw [hi6_val]
        rw [step1, h_c11_eq, h_c1tw_eq]
        have h_c0_to_pe : u32ToZq (core.convert.num.FromU32U16.from i1) =
            u16ToZq (pe_src.val[start.val + iter.start.val]'(by rw [← h_i_eq]; exact h_i_lt)) := by
          grind
        have h_c1_to_pe : u32ToZq (core.convert.num.FromU32U16.from i3) =
            u16ToZq (pe_src.val[start.val + iter.start.val + len.val]'(by
              rw [← h_i2_eq]; exact h_i2_lt)) := by
          grind
        rw [h_c0_to_pe, h_c1_to_pe]
        ring
      · -- a.val = pe_src.val.set j i4.set (j+len) i6 (with proper indices)
        have h1 : a.val = pe_src1.val.set i5.val i6 := by rw [ha_eq]; rfl
        have h2 : pe_src1.val = pe_src.val.set i.val i4 := by rw [h_pe_src1]; rfl
        rw [h1, h2, hi5_eq, hi_val]
    rw [h_butterfly]
    -- Now LHS: nttButterflies z (nttButterflyAt z (toPoly pe_src) lo len _) len
    --              (start+iter1.start) (start+iter1.end) _
    -- RHS: nttButterflies z (toPoly pe_src) len (start+iter.start) (start+iter.end) _
    -- Peel RHS once
    conv_rhs => rw [nttButterflies, dif_pos h_lo_lt_hi]
    -- Both sides now have `nttButterflies z (nttButterflyAt z (toPoly pe_src) lo len _ _) ... `
    -- LHS indices: (start+iter1.start), (start+iter1.end)
    -- RHS indices: (start+iter.start)+1, (start+iter.end)
    -- They're equal via hstart' and hend'.
    have h_iter1_start_val : iter1.start.val = iter.start.val + 1 := hstart'
    have h_iter1_end_val : iter1.«end».val = iter.«end».val := by rw [hend']
    -- Use fcongr to align without rewriting through dependent proofs
    fcongr 1
    · rw [h_iter1_start_val]; ring
    · exact h_iter1_end_val ▸ rfl
  · -- NONE branch: iter exhausted
    let* ⟨ o, iter1, ho, _ ⟩ ← IteratorRange_next_Usize_none
    rw [ho]
    simp only [WP.spec_ok]
    refine ⟨h_wf, ?_⟩
    -- nttButterflies z p len lo hi where lo ≥ hi
    have h_eq : iter.start.val = iter.«end».val := by omega
    -- Both bounds equal; nttButterflies returns p
    show toPoly pe_src = nttButterflies _ _ _ _ _ _
    rw [nttButterflies]
    rw [dif_neg (by rw [h_eq]; omega)]

/-! ## Middle loop (start range, stepped by `2*len`)

`poly_element_ntt_layer_generic_loop0` iterates `start ∈
[0, 256)` step `2*len`, on each iteration reads
`ZETA_BIT_REV_TIMES_R[k]` and runs the inner loop with `k++`. -/

/-- **Loop spec** for the middle (start) loop — opaque-iterator witness.

The `StepBy (Range Usize)` iterator is opaque, so we parameterize by
an existential witness `start_curr : Nat` representing the iterator's
current cursor (the next `start` it would yield).  Pre/post symmetry:
both have `∃ start_curr, …`.

At exit (iter exhausted), the polynomial equals the full `nttMidLayer`
applied from `start_curr` onwards with threading `k.val`.

Informal proof. Template: opaque `StepBy` iterator recursion, using
`core.iter.adapters.step_by.IteratorStepBy.next_Range_Usize_some_spec` / `core.iter.adapters.step_by.IteratorStepBy.next_Range_Usize_none_spec`; analogue:
`MulAccum.lean :: vector_mont_dot_product_loop.spec`, but with a strided
iterator and an inner butterfly-loop call. Unfold
`mlkem.ntt.poly_element_ntt_layer_generic_loop0`; the body calls
`IteratorStepBy.next`, returns on `none`, and on `some start` reads the
twiddle-table entries, increments `k`, runs the inner butterfly loop over
`Range 0 len`, then recurses on `iter1`.

1. `step with core.iter.adapters.step_by.IteratorStepBy.next_Range_Usize_some_spec` / `core.iter.adapters.step_by.IteratorStepBy.next_Range_Usize_none_spec`.
2. In the `some` branch, step the table read
   `Array.index_usize mlkem.ntt.ZETA_BIT_REV_TIMES_R k`; use
   `tbd_ZETA_BIT_REV_TIMES_R_spec` to get the logical twiddle
   `ζ ^ bitRev 7 (k.val + 1)` in the form required by the inner-loop
   `h_tw`.
3. Step `core.convert.IntoFrom.into`.
4. Step the companion table read
   `Array.index_usize mlkem.ntt.ZETA_BIT_REV_TIMES_R_TIMES_NEG_Q_INV_MOD_R k`;
   use `tbd_ZETA_BIT_REV_TIMES_R_TIMES_NEG_Q_INV_MOD_R_spec` for the
   `twiddle_factor_mont` bound and equality required by `mont_mul.spec`.
5. Step `core.convert.IntoFrom.into`, then `Usize.add.spec` for `k + 1`.
6. Step with
   `mlkem.ntt.poly_element_ntt_layer_generic_loop0_loop0.spec`; its post is
   exactly one `nttMidStep` / inner-loop application for the current `start`.
7. Step the recursive call with this theorem.  The IH says the recursive
   result equals `nttMidLayer len h_len iter1.iter.start k1.val` applied to
   the polynomial produced by the current mid-step.

Case analysis: `none` closes by the base branch of `nttMidLayer`
(`start + 2 * len > 256`).  In `some`, peel `nttMidLayer`: the current
table lookup and inner-loop result form `nttMidStep`, and the recursive
call gives the rest of the strided starts.

Close with `split_conjs`; `agrind` discharges iterator arithmetic,
`wfPoly` threading, `k ≤ 128`, and the modular / stride side conditions. -/
@[step]
theorem mlkem.ntt.poly_element_ntt_layer_generic_loop0.spec
    (iter : core.iter.adapters.step_by.StepBy (core.ops.range.Range Usize))
    (pe_src : PolyElement) (k len : Usize)
    (h_wf : wfPoly pe_src) (h_len : 0 < len.val) (h_lend : len.val ≤ 128)
    (h_div : 256 % (2 * len.val) = 0)
    (h_inv : 2 * k.val * len.val + 256 ≤ 256 * len.val + iter.iter.start.val)
    (h_iter_end : iter.iter.«end».val = 256)
    (h_iter_step : iter.step_by.val = 2 * len.val)
    (h_iter_start : iter.iter.start.val ≤ 256 ∧
                    iter.iter.start.val % (2 * len.val) = 0) :
    mlkem.ntt.poly_element_ntt_layer_generic_loop0 iter pe_src k len
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r =
            (nttMidLayer len.val h_len iter.iter.start.val k.val (toPoly pe_src)).1 ⦄ := by
  unfold mlkem.ntt.poly_element_ntt_layer_generic_loop0
  obtain ⟨h_start_le, h_start_mod⟩ := h_iter_start
  have h_2len_pos : 0 < 2 * len.val := by scalar_tac
  have h_2len_le : 2 * len.val ≤ 256 := by scalar_tac
  by_cases hlt : iter.iter.start.val < iter.iter.«end».val
  · -- SOME branch: read twiddles, run inner loop, recurse.
    have h_start_lt : iter.iter.start.val < 256 := by omega
    -- Divisibility: (256 - start) is a positive multiple of 2*len.
    have h_sub_dvd : 2 * len.val ∣ (256 - iter.iter.start.val) :=
      Nat.dvd_sub (Nat.dvd_of_mod_eq_zero h_div)
                  (Nat.dvd_of_mod_eq_zero h_start_mod)
    have h_sub_mod : (256 - iter.iter.start.val) % (2 * len.val) = 0 :=
      Nat.dvd_iff_mod_eq_zero.mp h_sub_dvd
    have h_sub_pos : 0 < 256 - iter.iter.start.val := by omega
    have h_sub_ge_2len : 2 * len.val ≤ 256 - iter.iter.start.val := by
      -- 2*len ∣ (256 - start) and 256 - start > 0 ⇒ 256 - start ≥ 2*len.
      rcases Nat.lt_or_ge (256 - iter.iter.start.val) (2 * len.val) with hlt2 | hge2
      · -- impossible: if 0 < x < 2*len and 2*len ∣ x, then x = 0.
        exfalso
        have := Nat.eq_zero_of_dvd_of_lt (Nat.dvd_of_mod_eq_zero h_sub_mod) hlt2
        omega
      · exact hge2
    have h_start_bound : iter.iter.start.val + 2 * len.val ≤ 256 := by omega
    -- k.val < 128 in SOME (so ZETA[k] is valid).
    have h_k_lt : k.val < 128 := by
      by_contra hge
      push Not at hge
      have h_ge : 256 * len.val ≤ 2 * k.val * len.val := by
        have h1 : 2 * 128 ≤ 2 * k.val := by omega
        calc 256 * len.val
            = 2 * 128 * len.val := by ring
          _ ≤ 2 * k.val * len.val := Nat.mul_le_mul_right _ h1
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
    -- Bridge the BV-form of htw_bv to a Nat equation for tw_u16.val.
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
    -- Inner butterfly loop preconditions.
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
      mlkem.ntt.poly_element_ntt_layer_generic_loop0_loop0.spec
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
    -- Convert inner-loop twiddle (u32ToZq tw * Rinv) to ζ^bitRev_7 k.
    have h_u32ToZq_tw : u32ToZq (core.convert.num.FromU32U16.from tw_u16) =
        ζ ^ _root_.bitRev 7 k.val * 65536 := by
      simp [u32ToZq, core.convert.num.FromU32U16.from]
      exact_mod_cast htw_zq
    have h_R_eq : ((65536 : Zq) : Zq) = R := by unfold R; decide
    have h_tw_Rinv : u32ToZq (core.convert.num.FromU32U16.from tw_u16) * Rinv =
        ζ ^ _root_.bitRev 7 k.val := by
      rw [h_u32ToZq_tw, show (65536 : Zq) = R from by unfold R; decide]
      rw [mul_assoc, R_mul_Rinv, mul_one]
    -- Recurse.
    have h_inv1 : 2 * k1.val * len.val + 256 ≤ 256 * len.val + iter1.iter.start.val := by
      have hk1v : k1.val = k.val + 1 := hk1_eq
      have hs1v : iter1.iter.start.val = iter.iter.start.val + 2 * len.val := by
        rw [hiter1_start, h_iter_step]
      rw [hk1v, hs1v]; ring_nf; ring_nf at h_inv; omega
    have h_iter_end1 : iter1.iter.«end».val = 256 := by
      rw [show iter1.iter.«end» = iter.iter.«end» from hiter1_end]; exact h_iter_end
    have h_iter_step1 : iter1.step_by.val = 2 * len.val := by
      rw [show iter1.step_by = iter.step_by from hiter1_step]; exact h_iter_step
    have h_iter_start1 : iter1.iter.start.val ≤ 256 ∧
        iter1.iter.start.val % (2 * len.val) = 0 := by
      refine ⟨?_, ?_⟩
      · rw [hiter1_start, h_iter_step]; omega
      · rw [hiter1_start, h_iter_step]
        rw [Nat.add_mod_right]; exact h_start_mod
    apply WP.spec_mono
      (mlkem.ntt.poly_element_ntt_layer_generic_loop0.spec iter1 pe_src1 k1 len
        hwf1 h_len h_lend h_div h_inv1 h_iter_end1 h_iter_step1 h_iter_start1)
    rintro r ⟨hwf_r, hto_r⟩
    refine ⟨hwf_r, ?_⟩
    -- Peel one nttMidLayer step.
    rw [hto_r]
    conv_rhs => rw [nttMidLayer]
    rw [dif_pos h_start_bound]
    simp only [nttMidStep]
    rw [hto_poly1, h_tw_Rinv]
    -- Goal: nttMidLayer .. iter1.start k1 .. = nttMidLayer .. (start + 2*len) (k+1) ..
    have hs1v : iter1.iter.start.val = iter.iter.start.val + 2 * len.val := by
      rw [hiter1_start, h_iter_step]
    have hk1v : k1.val = k.val + 1 := hk1_eq
    simp only [Nat.add_zero] at hto_poly1 ⊢
    rw [hs1v, hk1v]
  · -- NONE branch: iter exhausted.
    have hge : iter.iter.start.val ≥ iter.iter.«end».val := by omega
    let* ⟨o, iter1, ho, _⟩ ← core.iter.adapters.step_by.IteratorStepBy.next_Range_Usize_none_spec
    rw [ho]
    simp only [WP.spec_ok]
    refine ⟨h_wf, ?_⟩
    have h_start_eq : iter.iter.start.val = 256 := by omega
    rw [show (nttMidLayer len.val h_len iter.iter.start.val k.val (toPoly pe_src)).1 =
            toPoly pe_src from ?_]
    · conv_lhs => rw [nttMidLayer]
      rw [dif_neg (by rw [h_start_eq]; omega)]
termination_by 256 - iter.iter.start.val
decreasing_by
  rw [hiter1_start, h_iter_step]
  omega

/-! ## Layer wrapper

`poly_element_ntt_layer_generic` runs the middle loop with the full
range `start ∈ [0, 256)` step `2*len`. -/

/-- **Layer wrapper spec** (`_generic`).

Informal proof. Template: leaf wrapper with `step*`; analogue:
`Encaps.lean :: encode_bytes_spec` family.  Unfold
`mlkem.ntt.poly_element_ntt_layer_generic`; the body computes
`stride := 2 * len`, builds the `StepBy (Range 0 256) stride` iterator,
and delegates to `poly_element_ntt_layer_generic_loop0` with that iterator
and the supplied `k`.

1. Step `Usize.mul.spec` for `2#usize * len` (use `h_lend` for the
   `Usize` overflow bound; result is `≤ 256`).
2. Step `core.iter.traits.iterator.Iterator.step_by.trait_default.spec`; positivity is given
   by `h_len`, and `h_div` / `h_lend` discharge the resulting stride
   facts.
3. Step with `mlkem.ntt.poly_element_ntt_layer_generic_loop0.spec` at
   iterator start `0`, end `256`, step `2 * len`, counter `k`.

There is no wrapper-level case split.  Close by simplifying the
middle-loop postcondition with `iter.iter.start.val = 0` to obtain
`nttMidLayer len.val h_len 0 k.val (toPoly pe_src) .1`; `agrind` closes
stride, divisibility, and bounds obligations. -/
@[step]
theorem mlkem.ntt.poly_element_ntt_layer_generic.spec
    (pe_src : PolyElement) (k len : Usize)
    (h_wf : wfPoly pe_src) (h_len : 0 < len.val) (h_lend : len.val ≤ 128)
    (h_div : 256 % (2 * len.val) = 0)
    (h_k : 2 * k.val * len.val + 256 ≤ 256 * len.val) :
    mlkem.ntt.poly_element_ntt_layer_generic pe_src k len
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r =
            (nttMidLayer len.val h_len 0 k.val (toPoly pe_src)).1 ⦄ := by
  unfold mlkem.ntt.poly_element_ntt_layer_generic
  step as ⟨i, hi⟩
  simp only [core.iter.traits.iterator.Iterator.step_by.trait_default, core.iter.traits.iterator.Iterator.step_by.default,
    show ¬ (i.val = 0) from by agrind, if_false]
  apply WP.spec_mono
  · apply mlkem.ntt.poly_element_ntt_layer_generic_loop0.spec
      (iter := ⟨{ start := 0#usize, «end» := 256#usize }, i ⟩)
    · exact h_wf
    · exact h_len
    · exact h_lend
    · exact h_div
    · show 2 * k.val * len.val + 256 ≤ 256 * len.val + 0; omega
    · rfl
    · show i.val = 2 * len.val; agrind
    · refine ⟨by simp, by simp⟩
  · rintro r ⟨hwf, heq⟩
    exact ⟨hwf, heq⟩

/-! ## SIMD intrinsic-layer specs (per-target dispatch)

The extraction emits two intrinsics-based forward-NTT layer implementations
alongside the portable `_generic` path:

  * `mlkem.ntt.poly_element_ntt_layer_vec128` — trait-parametric on
    `NttIntrinsicsInterface T Vec128`; instantiated at
    `(ntt_xmm.NttIntrinsicsXmm, __m128i)` and
    `(ntt_neon.NttIntrinsicsNeon, uint16x8_t)`.
  * `mlkem.ntt.ntt_avx2.ntt_layer_avx2` — direct AVX2 (`__m256i`) path,
    selected when `len >= 16` and `cpu_features_present AVX2` succeeds.

The strong `@[step]` specs live in:

  * `Symcrust.Properties.MLKEM.Intrinsics.mlkem.ntt.poly_element_ntt_layer_vec128.spec`
    (file `Properties/MLKEM/Intrinsics/Vec128LayerNtt.lean`) — parametric in
    `[NttIntrinsicsSpec V Inst]`.
  * `Symcrust.Properties.MLKEM.Intrinsics.mlkem.ntt.ntt_avx2.ntt_layer_avx2.spec`
    (file `Properties/MLKEM/Intrinsics/X86_64/Avx2LayerNtt.lean`) — concrete on `__m256i`.

Both specs are functionally equivalent to `_generic.spec` and produce
`(nttMidLayer len h_len 0 k (toPoly pe_src)).1`. The dispatcher proofs below
pick up these strong specs directly from the `Intrinsics/` files. -/

/-- **Per-target dispatcher (x86_64)** — selects SSE2 (`_vec128`
on `XmmNttInst`) / `_generic` based on `cpu_features_present`.

## Informal proof

Unfold `poly_element_ntt_layer.«x86_64-unknown-linux-gnu»`:

```
let b ← cpu_features_present SSE2
if b then poly_element_ntt_layer_vec128 XmmNttInst pe k len
else      poly_element_ntt_layer_generic pe k len
```

(The AVX2 arm and the `len ≥ 16` gate were removed when the verify-simd
config was dropped; the x86_64 dispatcher is now identical in shape to i686.)

Proof structure:
1. `step` past `cpu_features_present SSE2` (its spec is in
   `Properties/Axioms/System.lean` — `@[step] axiom` yielding a `Bool`,
   hence the case-split below).
2. `split_ifs` on the SSE2 detection bit:
   - `true`: `apply`
     `Symcrust.Properties.MLKEM.Intrinsics.mlkem.ntt.poly_element_ntt_layer_vec128.spec`
     instantiated with `XmmNttInst` (instance
     `Symcrust.Properties.MLKEM.Intrinsics.xmmNttIntrinsicsSpec` from
     `Properties/MLKEM/Intrinsics/X86_64/Sse2.lean`).
   - `false`: `apply` `_generic.spec`.

Both terminal arms produce
`(nttMidLayer len.val h_len 0 k.val (toPoly pe_src)).1`, satisfying
the dispatcher's post.  The instance application discharges the
`[NttIntrinsicsSpec V Inst]` requirement via the per-arch instance
from `Sse2.lean`. -/
@[step]
theorem mlkem.ntt.poly_element_ntt_layer.x86_64_unknown_linux_gnu.spec
    (pe_src : PolyElement) (k len : Usize)
    (h_wf : wfPoly pe_src) (h_len : 2 ≤ len.val) (h_lend : len.val ≤ 128)
    (h_div : 256 % (2 * len.val) = 0)
    (h_k : 2 * k.val * len.val + 256 ≤ 256 * len.val) :
    mlkem.ntt.poly_element_ntt_layer.«x86_64-unknown-linux-gnu» pe_src k len
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r =
            (nttMidLayer len.val (by omega) 0 k.val (toPoly pe_src)).1 ⦄ := by
  have h_dvd : 2 * len.val ∣ 256 := Nat.dvd_of_mod_eq_zero h_div
  have h_step8 : 8 ≤ len.val → len.val % 8 = 0 := by
    intro h; interval_cases len.val <;> omega
  unfold mlkem.ntt.poly_element_ntt_layer.«x86_64-unknown-linux-gnu»
  step as ⟨bSse, _⟩
  split_ifs with hSse
  · apply (mlkem.ntt.poly_element_ntt_layer_vec128.spec
      (Inst := XmmNttInst) (s := xmmNttIntrinsicsSpec))
      pe_src k len h_wf h_len h_lend h_div h_step8 h_k
  · apply mlkem.ntt.poly_element_ntt_layer_generic.spec pe_src k len h_wf
      (by omega) h_lend h_div h_k

/-- **Per-target dispatcher (i686)** — selects SSE2 (`_vec128` on
`XmmNttInst`) / `_generic` based on `cpu_features_present`.

## Informal proof

Same structure as the x86_64 dispatcher but without the AVX2 arm.
Body:
```
let b ← cpu_features_present SSE2
if b then poly_element_ntt_layer_vec128 XmmNttInst pe k len
else      poly_element_ntt_layer_generic pe k len
```

`cases b`:
- `true`: `apply`
  `Symcrust.Properties.MLKEM.Intrinsics.mlkem.ntt.poly_element_ntt_layer_vec128.spec`
  with `XmmNttInst` (instance `xmmNttIntrinsicsSpec`).
- `false`: `apply` `_generic.spec`. -/
@[step]
theorem mlkem.ntt.poly_element_ntt_layer.i686_unknown_linux_gnu.spec
    (pe_src : PolyElement) (k len : Usize)
    (h_wf : wfPoly pe_src) (h_len : 2 ≤ len.val) (h_lend : len.val ≤ 128)
    (h_div : 256 % (2 * len.val) = 0)
    (h_k : 2 * k.val * len.val + 256 ≤ 256 * len.val) :
    mlkem.ntt.poly_element_ntt_layer.«i686-unknown-linux-gnu» pe_src k len
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r =
            (nttMidLayer len.val (by omega) 0 k.val (toPoly pe_src)).1 ⦄ := by
  have h_dvd : 2 * len.val ∣ 256 := Nat.dvd_of_mod_eq_zero h_div
  have h_step8 : 8 ≤ len.val → len.val % 8 = 0 := by
    intro h; interval_cases len.val <;> omega
  unfold mlkem.ntt.poly_element_ntt_layer.«i686-unknown-linux-gnu»
  step as ⟨bSse, _⟩
  split_ifs with hSse
  · apply (mlkem.ntt.poly_element_ntt_layer_vec128.spec
      (Inst := XmmNttInst) (s := xmmNttIntrinsicsSpec))
      pe_src k len h_wf h_len h_lend h_div h_step8 h_k
  · apply mlkem.ntt.poly_element_ntt_layer_generic.spec pe_src k len h_wf
      (by omega) h_lend h_div h_k

/-- **Per-target dispatcher (aarch64)** — selects NEON (`_vec128` on
`NeonNttInst`) / `_generic` based on `cpu_features_present`.

## Informal proof

Same structure as the i686 dispatcher.  Body:
```
let b ← cpu_features_present NEON
if b then poly_element_ntt_layer_vec128 NeonNttInst pe k len
else      poly_element_ntt_layer_generic pe k len
```

`cases b`:
- `true`: `apply`
  `Symcrust.Properties.MLKEM.Intrinsics.mlkem.ntt.poly_element_ntt_layer_vec128.spec`
  with `NeonNttInst` (instance `neonNttIntrinsicsSpec` from
  `Properties/MLKEM/Intrinsics/Aarch64/Neon.lean`).
- `false`: `apply` `_generic.spec`. -/
@[step]
theorem mlkem.ntt.poly_element_ntt_layer.aarch64_unknown_linux_gnu.spec
    (pe_src : PolyElement) (k len : Usize)
    (h_wf : wfPoly pe_src) (h_len : 2 ≤ len.val) (h_lend : len.val ≤ 128)
    (h_div : 256 % (2 * len.val) = 0)
    (h_k : 2 * k.val * len.val + 256 ≤ 256 * len.val) :
    mlkem.ntt.poly_element_ntt_layer.«aarch64-unknown-linux-gnu» pe_src k len
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r =
            (nttMidLayer len.val (by omega) 0 k.val (toPoly pe_src)).1 ⦄ := by
  have h_dvd : 2 * len.val ∣ 256 := Nat.dvd_of_mod_eq_zero h_div
  have h_step8 : 8 ≤ len.val → len.val % 8 = 0 := by
    intro h; interval_cases len.val <;> omega
  unfold mlkem.ntt.poly_element_ntt_layer.«aarch64-unknown-linux-gnu»
  step as ⟨bNeon, _⟩
  split_ifs with hNeon
  · apply (mlkem.ntt.poly_element_ntt_layer_vec128.spec
      (Inst := NeonNttInst) (s := neonNttIntrinsicsSpec))
      pe_src k len h_wf h_len h_lend h_div h_step8 h_k
  · apply mlkem.ntt.poly_element_ntt_layer_generic.spec pe_src k len h_wf
      (by omega) h_lend h_div h_k

/-- **Layer dispatch wrapper** (`_layer`) — top-level `get_target`
dispatcher.

The body dispatches
on `get_target` over three target triples, each delegating to its
per-target spec above.  All three per-target dispatchers ultimately produce
`(nttMidLayer len.val h_len 0 k.val (toPoly pe_src)).1`. -/
@[step]
theorem mlkem.ntt.poly_element_ntt_layer.spec
    (pe_src : PolyElement) (k len : Usize)
    (h_wf : wfPoly pe_src) (h_len : 2 ≤ len.val) (h_lend : len.val ≤ 128)
    (h_div : 256 % (2 * len.val) = 0)
    (h_k : 2 * k.val * len.val + 256 ≤ 256 * len.val) :
    mlkem.ntt.poly_element_ntt_layer pe_src k len
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r =
            (nttMidLayer len.val (by omega) 0 k.val (toPoly pe_src)).1 ⦄ := by
  unfold mlkem.ntt.poly_element_ntt_layer
  step*

/-! ## Top wrapper `poly_element_ntt`

Composes 7 layers with `(k, len) = (1, 128), (2, 64), (4, 32), (8, 16),
(16, 8), (32, 4), (64, 2)`.

Informal proof: chain seven `poly_element_ntt_layer.spec` applications;
each consumes `wfPoly` and produces `wfPoly` + the `nttMidLayer`
equation; combine with `NTT_unfold_layers` to collapse the chain into
`MLKEM.NTT (toPoly pe_src)`. -/

/-- **Top spec for `poly_element_ntt`** — lands directly on `MLKEM.NTT`.

Informal proof. Template: leaf wrapper composing seven layers, as in
"Composes 7 layers …" above.  Unfold `mlkem.ntt.poly_element_ntt`; the
body issues seven `poly_element_ntt_layer` calls with
`(k, len) = (1, 128), (2, 64), (4, 32), (8, 16), (16, 8), (32, 4),
(64, 2)`, threading the polynomial and `k` through each call.

1. Step with `mlkem.ntt.poly_element_ntt_layer.spec` at `(k, len) = (1, 128)`;
   discharge `wfPoly`, `0 < len.val`, `len.val ≤ 128`, `256 % (2*len.val) = 0`,
   `k.val < 128` via `agrind`.
2. Step with `mlkem.ntt.poly_element_ntt_layer.spec` at `(2, 64)`.
3. Step with `mlkem.ntt.poly_element_ntt_layer.spec` at `(4, 32)`.
4. Step with `mlkem.ntt.poly_element_ntt_layer.spec` at `(8, 16)`.
5. Step with `mlkem.ntt.poly_element_ntt_layer.spec` at `(16, 8)`.
6. Step with `mlkem.ntt.poly_element_ntt_layer.spec` at `(32, 4)`.
7. Step with `mlkem.ntt.poly_element_ntt_layer.spec` at `(64, 2)`.

After the seventh step, the polynomial equals the iterated composition
of seven `nttMidLayer` calls at decreasing `len`.  Use
`NTT_unfold_layers` from `Bridges/NttLoops.lean` to identify this
composition with the spec `MLKEM.NTT (toPoly pe_src)`, and
`nttOuter_eq_NTT` to collapse the residual outer-loop wrapper.

There is no wrapper-level algorithmic case split (seven straight-line
calls).  Close with `split_conjs`; `agrind` covers `wfPoly` threading
and all layer side conditions, then `simp [NTT_unfold_layers]`
plus `agrind` closes the FC equality. -/
@[step]
theorem mlkem.ntt.poly_element_ntt.spec
    (pe_src : PolyElement) (h_wf : wfPoly pe_src) :
    mlkem.ntt.poly_element_ntt pe_src
      ⦃ (r : PolyElement) =>
          wfPoly r ∧ toPoly r = MLKEM.NTT (toPoly pe_src) ⦄ := by
  unfold mlkem.ntt.poly_element_ntt
  step*
  refine ⟨by assumption, ?_⟩
  rw [NTT_unfold_layers]
  simp only [*]

/-! ## Vector wrapper

`vector_ntt` applies `poly_element_ntt` to every polynomial in a slice
via `IterMut`. -/

/-- **Loop spec** for `vector_ntt_loop` (IterMut over polynomials).

Canonical IterMut framing pattern: `iter.slice = orig_slice` initially,
`back` accumulates writes, plus four framing predicates on `back`
(writes done so far / rest unchanged / length preserved / wf preserved).
See the `aeneas-postconditions` skill, "IterMut loops" section, and the
template in `Properties/MLDSA/Vectors.lean :: vector_ntt_loop.spec`.

NOT tagged `@[step]` — callers use `step with` or `apply` explicitly.

Informal proof. Template: canonical IterMut loop from
`aeneas-postconditions`, with `poly_element_ntt.spec` as the
element step.  Unfold `mlkem.ntt.vector_ntt_loop`; the body calls
`IteratorIterMut.next`, returns `back (next_back iter1 none)` on
`none`, and on `some pe_src` runs `poly_element_ntt pe_src` before
recursing with the updated back continuation.

1. In the `some` branch, step with
   `core.slice.iter.IteratorIterMut.next.spec`.  This gives the fresh
   element `pe_src1` and the new iterator `iter1` with
   `iter1.i = iter.i + 1`, `iter1.slice.length = orig_slice.length`,
   and the `next_back` write equation.
2. Step with `mlkem.ntt.poly_element_ntt.spec`; the input `wfPoly`
   comes from `h_orig_wf` (current row, since `iter.i < length`) and the
   cursor-frame hypothesis (via `hback_rest`).
3. Step the recursive call with this theorem using
   `fun im => back (next_back im (some pe_src1))`.  The IH says all
   entries before the new cursor have been transformed by `MLKEM.NTT`,
   rest entries are framed, length is preserved, and processed entries
   are `wfPoly`.
4. In the `none` branch, step with
   `core.slice.iter.IteratorIterMut.next_spec_none`; combine with the
   existing `hback_*` to discharge the postcondition directly.

Case analysis: split on `iter.i < iter.slice.len`.  In the `some`
branch, for each queried index `j`, split into:
- `j = iter.i` (the fresh element; use the `poly_element_ntt.spec`
  result and the `next_back` set equation),
- `j < iter.i` (old processed element; use `hback_writes` and
  `hback_inv` from the original `back`),
- the rest frame (uses `hback_rest`).
In the `none` branch, all writes are already in `back`.

Close with `split_conjs`; use `agrind` for index and length facts and
`simp [Slice.setAtNat]` plus `agrind` for the current-slot equality. -/
@[step]
theorem mlkem.ntt.vector_ntt_loop.spec
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
        = MLKEM.NTT (toPoly (orig_slice.val[j]'(by
          have := h_iter_i; scalar_tac))))
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
    mlkem.ntt.vector_ntt_loop iter back
      ⦃ (r : core.slice.iter.IterMut (PolyElement)) =>
          ∃ (h_len : r.slice.length = orig_slice.length),
          (∀ j (hj : j < orig_slice.length),
            wfPoly (r.slice.val[j]'(by have := h_len; scalar_tac))) ∧
          (∀ j (hj : j < orig_slice.length),
            toPoly (r.slice.val[j]'(by have := h_len; scalar_tac))
              = MLKEM.NTT (toPoly (orig_slice.val[j]'hj))) ⦄ := by
  unfold mlkem.ntt.vector_ntt_loop
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
      mlkem.ntt.poly_element_ntt.spec _ h_pe_wf
    -- Recursive call
    apply WP.spec_mono
      (mlkem.ntt.vector_ntt_loop.spec iter1
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

/-- **Top spec for `vector_ntt`** — per-row NTT over a polynomial vector.

Informal proof. Template: leaf wrapper around an IterMut loop.
Analogue: `MatVec.lean :: matrix_vector_mul.spec` (slice-len assertion +
`iter_mut_spec` + delegating loop).  Unfold `mlkem.ntt.vector_ntt`; the
body checks the row count (`> 0` and `≤ MATRIX_MAX_NROWS = 4`),
obtains a mutable iterator on `pv_src` via `iter_mut_spec`, runs
`vector_ntt_loop` with `back = id`, and applies the iterator-back
closure.

1. Step `Slice.len` / `Usize` comparisons for `n_rows > 0` and
   `n_rows ≤ MATRIX_MAX_NROWS`; discharge the two `massert`s using
   `h_n`.
2. Step with `core.slice.Slice.iter_mut.spec`; it gives
   `iter.slice = pv_src`, `iter.i = 0`, and the final back-closure
   equation.
3. Step with `mlkem.ntt.vector_ntt_loop.spec`, instantiating
   `back = id`.  The initial processed-prefix hypotheses
   (`hback_writes`, `hback_inv`) are vacuous (`j < 0`); `hback_rest`
   and `hback_len` are immediate for identity.  `h_orig_wf` is `h_wf`.
4. Step the final `ok (iter_mut_back back)` and rewrite using the
   `iter_mut_back` postcondition.

There is no wrapper-level algorithmic case split — the row-count guards
are discharged before the loop.  Close with `split_conjs`; `agrind`
proves `wfPolyVec` and supplies the existential length witness, then
transfers the loop's per-index `MLKEM.NTT` equality into the theorem's
indexed postcondition. -/
@[step]
theorem mlkem.ntt.vector_ntt.spec
    (pv_src : Slice (PolyElement))
    (h_wf : wfPolyVec pv_src)
    (h_n : pv_src.length > 0 ∧ pv_src.length ≤ 4) :
    mlkem.ntt.vector_ntt pv_src
      ⦃ (r : Slice (PolyElement)) =>
          wfPolyVec r ∧
          ∃ (h_len : r.length = pv_src.length),
          ∀ (i : Nat) (h_i : i < pv_src.length),
            toPoly (r.val[i]'(by agrind))
              = MLKEM.NTT (toPoly pv_src.val[i]) ⦄ := by
  unfold mlkem.ntt.vector_ntt
  step*
  case _ =>
    unfold mlkem.ntt.MATRIX_MAX_NROWS
    show pv_src.length ≤ 4
    exact h_n.2
  -- Final postcondition
  rw [iter_post3]
  refine ⟨?_, back_post1, ?_⟩
  · intro i hi
    have hi' : i < pv_src.length := by rw [← back_post1]; exact hi
    exact back_post2 i hi'
  · intro i hi
    exact back_post3 i hi

end Symcrust.Properties.MLKEM
