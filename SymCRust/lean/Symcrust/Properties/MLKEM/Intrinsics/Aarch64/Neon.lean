/-
  Symcrust/Properties/MLKEM/Intrinsics/Aarch64/Neon.lean — `NttIntrinsicsSpec`
  instance for the AArch64 NEON (`uint16x8_t`) target.

  ## Surface

  Provides
  `instance neonNttIntrinsicsSpec : NttIntrinsicsSpec NeonVec NeonNttInst`,
  bundling the 10 method specs + 3 abstractions of
  `Properties/MLKEM/Intrinsics/TraitSpec.lean`
  for the extracted Aeneas `NeonNttInst` .

  ## Status

  **PROVEN on top of Rust intrinsics models — no algorithm-specific axioms.**  All 10 instance fields are
  theorems in this file: the 4 composite arithmetic ops compose the generic
  `verify.intrinsics.aarch64.neon.*` lane-op step specs from
  `Intrinsics/Properties/Aarch64/Neon.lean`, and the 6 load/store ops are
  proved by `unfold + step*` over their now-transparent extracted bodies
  (the verify shims index the `[u16; 8]` word carrier — see
  `src/mlkem/ntt_neon.rs`).  Mirrors the SSE2 sibling
  `Intrinsics/X86_64/Sse2.lean`.

  ## Trust layering

  See `TraitSpec.lean` § "Trust model" for the shared trust story (it
  applies verbatim to all three SIMD-NTT instance files).  NEON-specific
  note: `uint16x8_t` is modeled as an 8-lane `u16` vector, so `toLanes`
  needs no byte-reinterpret — the lane view is the generic carrier axiom
  `uint16x8_t.u16x8` in `Intrinsics/Axioms/Aarch64/Common.lean`.

  ## Proof shape (per field)

  Each `_spec` field is proved by `unfold`ing the Aeneas-extracted
  body (`NeonNttInst.vec128_<op>`), peeling `step` through the named
  ACLE-intrinsic calls cited in the per-field informal proof, and
  closing the arithmetic with `bv_decide` / `agrind`.  The Montgomery
  field (`vec128_mont_mul_spec`) mirrors the scalar `mont_mul` spec
  lane-by-lane through `vmull_u16` / `vshrn_n_u32`-shaped intrinsics.

  See `Properties/MLKEM/Intrinsics/TraitSpec.lean` for the canonical
  field signatures (and the shared trust model) and
  `Properties/MLKEM/Intrinsics/Vec128LayerNtt.lean` /
  `Vec128LayerIntt.lean` for the parametric `_vec128` loop specs that
  consume this instance.
-/
import Symcrust.Code.Funs
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Intrinsics.TraitSpec
-- Native `Array U16 8` lane carrier:
import Intrinsics.Axioms.Aarch64.Common
-- Layer-1 `verify.intrinsics.aarch64.neon.*` lane-op `@[step]` theorems:
import Intrinsics.Properties.Aarch64.Neon
-- Generic per-lane modular-arithmetic cores (shared with SSE2 / AVX2):
import Symcrust.Properties.MLKEM.Bridges.ModArithLanes

open Aeneas Aeneas.Std Result
open Symcrust Spec.MLKEM
open symcrust
open Symcrust.Properties.MLKEM
open Symcrust.Properties.MLKEM.Bridges.ModArithLanes

namespace Symcrust.Properties.MLKEM.Intrinsics.Aarch64

/- Align `get_elem_tactic` with `Intrinsics/Properties/Aarch64/Neon.lean` so
   `rw`/`simp only [post]` fire through matching getElem bound-proof terms. -/
local macro_rules
| `(tactic| get_elem_tactic) => `(tactic| agrind)

/-- Carrier for the extracted ML-KEM NEON register: a native 8-lane `u16`
    array (`[u16; 8]`).  The verify NEON backend models `uint16x8_t` as this
    word array, so the Aeneas-extracted `NttIntrinsicsNeon` instance is over
    `Array U16 8` rather than the silicon `uint16x8_t`. -/
abbrev NeonVec : Type := Std.Array Std.U16 8#usize

/-- The Aeneas-extracted NEON trait dictionary; alias for clarity.
    Definition in `Code/Funs.lean:12970` — a `NttIntrinsicsInterface
    NttIntrinsicsNeon NeonVec`. -/
@[reducible]
noncomputable def NeonNttInst :
    mlkem.ntt.NttIntrinsicsInterface
      mlkem.ntt.ntt_neon.NttIntrinsicsNeon
      NeonVec :=
  mlkem.ntt.ntt_neon.NttIntrinsicsNeon.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU168

/-- Lane projection for the `Array U16 8` byte-carrier NEON register.
    The extracted ML-KEM NEON carrier is natively an 8-lane `u16` array
    (`[u16; 8]`), so the projection reads the lanes directly off the array.
    Lane 0 is the low 16 bits. -/
@[reducible]
noncomputable def toLanesNeon (v : NeonVec) :
    Vector Std.U16 8 := Vector.ofFn (fun (i : Fin 8) => v.val[i.val])

/-- Well-formedness on `uint16x8_t`: every lane is `< q`. -/
def wfVecNeon (v : NeonVec) : Prop :=
  ∀ i : Fin 8, (toLanesNeon v)[i.val].val < q

/-- `toLanesNeon` lane `i` is exactly the native `Array U16 8` lane (used by
    the `Intrinsics/Properties/Aarch64/Neon.lean` lane-op step specs). -/
theorem toLanesNeon_getElem (v : NeonVec) (i : Fin 8) :
    (toLanesNeon v)[i.val] = v.val[i.val] := by
  unfold toLanesNeon
  simp only [Vector.getElem_ofFn]

/-! ## NEON NTT load/store specs on `uint16x8_t` (byte-carrier redirect)

The load/store methods are now **transparent `def`s** (the verify shims index
the `[u16; 8]` word carrier directly — no raw pointers; see
`src/mlkem/ntt_neon.rs`).  Each spec is proved by `unfold + step*` over the
extracted array-index/update body — no silicon axiom.  The composite arithmetic
ops (`vec128_mod_add/sub`, `vec128_mont_mul`) are likewise theorems below. -/

/-- **Spec for `vec128_load_u16x8`** (loads 8 contiguous coefficients). -/
theorem vec128_load_u16x8_spec_neon :
    ∀ (pe : PolyElement) (idx : Std.Usize)
      (_h_wf : wfPoly pe) (h_idx : idx.val + 8 ≤ 256),
      NeonNttInst.vec128_load_u16x8 pe idx ⦃ v =>
        wfVecNeon v ∧
        ∀ i : Fin 8, (toLanesNeon v)[i.val] = pe.val[idx.val + i.val] ⦄ := by
  intro pe idx hwf hidx
  simp only [
    mlkem.ntt.ntt_neon.NttIntrinsicsNeon.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU168.vec128_load_u16x8]
  step*
  have hlane : ∀ j : Fin 8,
      (toLanesNeon (Array.make 8#usize [i, i2, i4, i6, i8, i10, i12, i14] (by simp)))[j.val]
        = pe.val[idx.val + j.val] := by
    intro j; rw [toLanesNeon_getElem]; fin_cases j <;> simp_all [Std.Array.make]
  refine ⟨?_, hlane⟩
  intro j; rw [hlane j]; exact hwf _ (by have := j.isLt; grind)

/-- **Spec for `vec64_load_u16x4`** (loads 4 contiguous coefficients into the
    low half; the high half duplicates them). -/
theorem vec64_load_u16x4_spec_neon :
    ∀ (pe : PolyElement) (idx : Std.Usize)
      (_h_wf : wfPoly pe) (h_idx : idx.val + 4 ≤ 256),
      NeonNttInst.vec64_load_u16x4 pe idx ⦃ v =>
        wfVecNeon v ∧
        ∀ i : Fin 4, (toLanesNeon v)[i.val] = pe.val[idx.val + i.val] ⦄ := by
  intro pe idx hwf hidx
  simp only [
    mlkem.ntt.ntt_neon.NttIntrinsicsNeon.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU168.vec64_load_u16x4]
  step*
  refine ⟨?_, ?_⟩
  · intro j; rw [toLanesNeon_getElem]; fin_cases j <;>
      simp_all [Std.Array.make] <;> (apply hwf; grind)
  · intro j; rw [toLanesNeon_getElem _ ⟨j.val, by have := j.isLt; omega⟩]
    fin_cases j <;> simp_all [Std.Array.make]

/-- **Spec for `vec32_load_u16x2`** (loads 2 contiguous coefficients; the rest
    duplicate them). -/
theorem vec32_load_u16x2_spec_neon :
    ∀ (pe : PolyElement) (idx : Std.Usize)
      (_h_wf : wfPoly pe) (h_idx : idx.val + 2 ≤ 256),
      NeonNttInst.vec32_load_u16x2 pe idx ⦃ v =>
        wfVecNeon v ∧
        ∀ i : Fin 2, (toLanesNeon v)[i.val] = pe.val[idx.val + i.val] ⦄ := by
  intro pe idx hwf hidx
  simp only [
    mlkem.ntt.ntt_neon.NttIntrinsicsNeon.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU168.vec32_load_u16x2]
  step*
  refine ⟨?_, ?_⟩
  · intro j; rw [toLanesNeon_getElem]; fin_cases j <;>
      simp_all [Std.Array.make] <;> (apply hwf; grind)
  · intro j; rw [toLanesNeon_getElem _ ⟨j.val, by have := j.isLt; omega⟩]
    fin_cases j <;> simp_all [Std.Array.make]

set_option maxHeartbeats 1000000 in
/-- **Spec for `vec128_store_u16x8`** (writes 8 coefficients to `pe[idx..idx+8]`). -/
theorem vec128_store_u16x8_spec_neon :
    ∀ (pe : PolyElement) (idx : Std.Usize)
      (v : NeonVec)
      (_h_wf : wfPoly pe) (_h_idx : idx.val + 8 ≤ 256) (_h_v : wfVecNeon v),
      NeonNttInst.vec128_store_u16x8 pe idx v ⦃ pe' =>
        pe'.val.length = 256 ∧
        wfPoly pe' ∧
        ∀ k : Fin 256,
          pe'.val[k.val] =
            if h : idx.val ≤ k.val ∧ k.val < idx.val + 8
              then (toLanesNeon v)[k.val - idx.val]
              else pe.val[k.val] ⦄ := by
  intro pe idx v hwf hidx hv
  simp only [
    mlkem.ntt.ntt_neon.NttIntrinsicsNeon.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU168.vec128_store_u16x8]
  step*
  have hval : ∀ k : Fin 256,
      pe'.val[k.val] =
        if h : idx.val ≤ k.val ∧ k.val < idx.val + 8
          then (toLanesNeon v)[k.val - idx.val]
          else pe.val[k.val] := by
    intro k
    have hkb := k.isLt
    simp only [pe'_post, elem7_post, elem6_post, elem5_post, elem4_post, elem3_post,
      elem2_post, elem1_post, Std.Array.set_val_eq,
      i_post, i1_post, i3_post, i5_post, i7_post, i9_post, i11_post, i13_post,
      i2_post, i4_post, i6_post, i8_post, i10_post, i12_post, i14_post]
    by_cases hrange : idx.val ≤ k.val ∧ k.val < idx.val + 8
    · rw [dif_pos hrange, toLanesNeon_getElem v ⟨k.val - idx.val, by omega⟩]
      simp only [List.getElem_set]
      split_ifs <;> first | omega | (fcongr 1; omega)
    · rw [dif_neg hrange]
      simp only [List.getElem_set]
      split_ifs <;> first | rfl | omega
  refine ⟨by have := pe'.property; grind, ?_, hval⟩
  intro k hk
  rw [hval ⟨k, hk⟩]
  by_cases hrange : idx.val ≤ k ∧ k < idx.val + 8
  · rw [dif_pos hrange]; have := hv ⟨k - idx.val, by omega⟩; simpa using this
  · rw [dif_neg hrange]; exact hwf k hk

set_option maxHeartbeats 1000000 in
/-- **Spec for `vec64_store_u16x4`** (writes 4 coefficients to `pe[idx..idx+4]`). -/
theorem vec64_store_u16x4_spec_neon :
    ∀ (pe : PolyElement) (idx : Std.Usize)
      (v : NeonVec)
      (_h_wf : wfPoly pe) (_h_idx : idx.val + 4 ≤ 256)
      (_h_v : ∀ i : Fin 4, (toLanesNeon v)[i.val].val < q),
      NeonNttInst.vec64_store_u16x4 pe idx v ⦃ pe' =>
        pe'.val.length = 256 ∧
        wfPoly pe' ∧
        ∀ k : Fin 256,
          pe'.val[k.val] =
            if h : idx.val ≤ k.val ∧ k.val < idx.val + 4
              then (toLanesNeon v)[k.val - idx.val]
              else pe.val[k.val] ⦄ := by
  intro pe idx v hwf hidx hv
  simp only [
    mlkem.ntt.ntt_neon.NttIntrinsicsNeon.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU168.vec64_store_u16x4]
  step*
  have hval : ∀ k : Fin 256,
      pe'.val[k.val] =
        if h : idx.val ≤ k.val ∧ k.val < idx.val + 4
          then (toLanesNeon v)[k.val - idx.val]
          else pe.val[k.val] := by
    intro k
    have hkb := k.isLt
    /- The four stored values are `lo[0..3]`; `lo[j] = v[j]` (vget_low). Bridge
       to the `v` lanes (List form) so the nested-set mirrors `vec128_store`. -/
    have hloL : ∀ j, (hj : j < 4) →
        (lo.val[j]) = v.val[j] := by
      intro j hj; exact lo_post j hj
    simp only [pe'_post, elem3_post, elem2_post, elem1_post, Std.Array.set_val_eq,
      i_post, i1_post, i3_post, i5_post, i2_post, i4_post, i6_post]
    by_cases hrange : idx.val ≤ k.val ∧ k.val < idx.val + 4
    · rw [dif_pos hrange, toLanesNeon_getElem v ⟨k.val - idx.val, by omega⟩]
      simp only [List.getElem_set]
      split_ifs <;> rename_i hc <;>
        first | omega | (rw [hloL _ (by omega)]; fcongr 1; omega)
    · rw [dif_neg hrange]
      simp only [List.getElem_set]
      split_ifs <;> first | rfl | omega
  refine ⟨by have := pe'.property; grind, ?_, hval⟩
  intro k hk
  rw [hval ⟨k, hk⟩]
  by_cases hrange : idx.val ≤ k ∧ k < idx.val + 4
  · rw [dif_pos hrange]; have := hv ⟨k - idx.val, by omega⟩; simpa using this
  · rw [dif_neg hrange]; exact hwf k hk

set_option maxHeartbeats 1000000 in
/-- **Spec for `vec32_store_u16x2`** (writes 2 coefficients to `pe[idx..idx+2]`). -/
theorem vec32_store_u16x2_spec_neon :
    ∀ (pe : PolyElement) (idx : Std.Usize)
      (v : NeonVec)
      (_h_wf : wfPoly pe) (_h_idx : idx.val + 2 ≤ 256)
      (_h_v : ∀ i : Fin 2, (toLanesNeon v)[i.val].val < q),
      NeonNttInst.vec32_store_u16x2 pe idx v ⦃ pe' =>
        pe'.val.length = 256 ∧
        wfPoly pe' ∧
        ∀ k : Fin 256,
          pe'.val[k.val] =
            if h : idx.val ≤ k.val ∧ k.val < idx.val + 2
              then (toLanesNeon v)[k.val - idx.val]
              else pe.val[k.val] ⦄ := by
  intro pe idx v hwf hidx hv
  simp only [
    mlkem.ntt.ntt_neon.NttIntrinsicsNeon.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU168.vec32_store_u16x2]
  step*
  have hval : ∀ k : Fin 256,
      pe'.val[k.val] =
        if h : idx.val ≤ k.val ∧ k.val < idx.val + 2
          then (toLanesNeon v)[k.val - idx.val]
          else pe.val[k.val] := by
    intro k
    have hkb := k.isLt
    simp only [pe'_post, elem1_post, Std.Array.set_val_eq,
      i_post, i1_post, i2_post]
    by_cases hrange : idx.val ≤ k.val ∧ k.val < idx.val + 2
    · rw [dif_pos hrange, toLanesNeon_getElem v ⟨k.val - idx.val, by omega⟩]
      simp only [List.getElem_set]
      split_ifs <;> first | omega | (fcongr 1; omega)
    · rw [dif_neg hrange]
      simp only [List.getElem_set]
      split_ifs <;> first | rfl | omega
  refine ⟨by have := pe'.property; grind, ?_, hval⟩
  intro k hk
  rw [hval ⟨k, hk⟩]
  by_cases hrange : idx.val ≤ k ∧ k < idx.val + 2
  · rw [dif_pos hrange]; have := hv ⟨k - idx.val, by omega⟩; simpa using this
  · rw [dif_neg hrange]; exact hwf k hk

/-- **Spec for `vec128_set_u16x8`** (NEON broadcast via `vdupq_n_u16`). -/
theorem vec128_set_u16x8_spec_neon :
    ∀ (x : Std.U16),
      NeonNttInst.vec128_set_u16x8 x ⦃ v =>
        ∀ i : Fin 8, (toLanesNeon v)[i.val] = x ⦄ := by
  intro x
  simp only [
    mlkem.ntt.ntt_neon.NttIntrinsicsNeon.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU168.vec128_set_u16x8]
  step*
  rename_i j
  rw [toLanesNeon_getElem v j]
  exact v_post j.val j.isLt

/-- **Spec for `vec128_mod_add`** (composes the modelled NEON lane ops;
    uses the unsigned `vcgeq_u16` mask, core `mod_add_lane_neon`). -/
theorem vec128_mod_add_spec_neon :
    ∀ (a b : NeonVec),
      wfVecNeon a → wfVecNeon b →
      NeonNttInst.vec128_mod_add a b ⦃ r =>
        wfVecNeon r ∧
        ∀ i : Fin 8,
          ((toLanesNeon r)[i.val].val : Zq) =
            ((toLanesNeon a)[i.val].val : Zq) + ((toLanesNeon b)[i.val].val : Zq) ⦄ := by
  intro a b ha hb
  simp only [wfVecNeon] at ha hb ⊢
  simp only [
    mlkem.ntt.ntt_neon.NttIntrinsicsNeon.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU168.vec128_mod_add,
    mlkem.ntt.ntt_neon.NttIntrinsicsNeon.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU168.vec128_set_u16x8]
  step*
  have hibv : i.bv = 3329#16 := by
    rw [i_post]
    simp only [UScalar.cast, UScalar.bv_mk_apply,
      show mlkem.ntt.Q.bv = 3329#32 from by unfold mlkem.ntt.Q; rfl]
    decide
  have hival : i.val = 3329 := by
    show i.bv.toNat = 3329; rw [hibv]; decide
  have key : ∀ k, (hk : k < 8) →
      (r.val[k]).val < 3329 ∧
      ((r.val[k]).val : ZMod 3329) =
        ((a.val[k]).val : ZMod 3329) +
        ((b.val[k]).val : ZMod 3329) := by
    intro k hk
    have hA : (a.val[k]).bv.toNat < 3329 := by
      have h := ha ⟨k, hk⟩; rw [toLanesNeon_getElem a ⟨k, hk⟩] at h; exact h
    have hB : (b.val[k]).bv.toNat < 3329 := by
      have h := hb ⟨k, hk⟩; rw [toLanesNeon_getElem b ⟨k, hk⟩] at h; exact h
    have hvqk : (v_q.val[k]) = i := by
      exact v_q_post k hk
    have hvqval : (v_q.val[k]).val = 3329 := by
      rw [hvqk, hival]
    have hvqbv : (v_q.val[k]).bv = 3329#16 := by
      rw [hvqk, hibv]
    have hwv : ∀ (x y : Std.U16), (core.num.U16.wrapping_add x y).val = (x.bv + y.bv).toNat := by
      intro x y
      show (core.num.U16.wrapping_add x y).bv.toNat = _
      rw [core.num.U16.wrapping_add_bv_eq]
    have hR : (r.val[k]).bv =
        ((a.val[k]).bv + (b.val[k]).bv) -
        ((if 3329 ≤ ((a.val[k]).bv +
                     (b.val[k]).bv).toNat
            then 65535#16 else 0#16) &&& 3329#16) := by
      have hr : (r.val[k]) =
          core.num.U16.wrapping_sub
            (v_res.val[k])
            (v_tmp11.val[k]) := by
        exact r_post k hk
      have hres : (v_res.val[k]) =
          core.num.U16.wrapping_add
            (a.val[k])
            (b.val[k]) := by
        exact v_res_post k hk
      have htmp1 : (v_tmp1.val[k]) =
          (if (v_res.val[k]).val ≥
                (v_q.val[k]).val
            then 65535#u16 else 0#u16) := by
        exact v_tmp1_post k hk
      have htmp11 : (v_tmp11.val[k]) =
          (v_tmp1.val[k]) &&&
          (v_q.val[k]) := by
        exact v_tmp11_post k hk
      have hvresval : (v_res.val[k]).val =
          ((a.val[k]).bv +
            (b.val[k]).bv).toNat := by
        rw [hres, hwv]
      rw [hr, hres, htmp11, htmp1, hvresval]
      simp only [hvqval, hvqbv,
        core.num.U16.wrapping_sub_bv_eq, core.num.U16.wrapping_add_bv_eq,
        UScalar.bv_and, apply_ite (fun u : U16 => u.bv),
        show (65535#u16 : U16).bv = 65535#16 from rfl,
        show (0#u16 : U16).bv = 0#16 from rfl]
    have hlane := mod_add_lane_neon _ _ _ hA hB hR
    exact ⟨hlane.1, hlane.2⟩
  refine ⟨fun i => ?_, fun i => ?_⟩
  · rw [toLanesNeon_getElem r i]; exact (key i.val i.isLt).1
  · rw [toLanesNeon_getElem r i, toLanesNeon_getElem a i, toLanesNeon_getElem b i]
    exact (key i.val i.isLt).2

/-- **Spec for `vec128_mod_sub`** (composes the modelled NEON lane ops;
    uses the signed `vcltzq_s16` mask, shared core `mod_sub_lane`). -/
theorem vec128_mod_sub_spec_neon :
    ∀ (a b : NeonVec),
      wfVecNeon a → wfVecNeon b →
      NeonNttInst.vec128_mod_sub a b ⦃ r =>
        wfVecNeon r ∧
        ∀ i : Fin 8,
          ((toLanesNeon r)[i.val].val : Zq) =
            ((toLanesNeon a)[i.val].val : Zq) - ((toLanesNeon b)[i.val].val : Zq) ⦄ := by
  intro a b ha hb
  simp only [wfVecNeon] at ha hb ⊢
  simp only [
    mlkem.ntt.ntt_neon.NttIntrinsicsNeon.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU168.vec128_mod_sub,
    mlkem.ntt.ntt_neon.NttIntrinsicsNeon.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU168.vec128_set_u16x8]
  step*
  have hibv : i.bv = 3329#16 := by
    rw [i_post]
    simp only [UScalar.cast, UScalar.bv_mk_apply,
      show mlkem.ntt.Q.bv = 3329#32 from by unfold mlkem.ntt.Q; rfl]
    decide
  have hival : i.val = 3329 := by
    show i.bv.toNat = 3329; rw [hibv]; decide
  have key : ∀ k, (hk : k < 8) →
      (r.val[k]).val < 3329 ∧
      ((r.val[k]).val : ZMod 3329) =
        ((a.val[k]).val : ZMod 3329) -
        ((b.val[k]).val : ZMod 3329) := by
    intro k hk
    have hA : (a.val[k]).bv.toNat < 3329 := by
      have h := ha ⟨k, hk⟩; rw [toLanesNeon_getElem a ⟨k, hk⟩] at h; exact h
    have hB : (b.val[k]).bv.toNat < 3329 := by
      have h := hb ⟨k, hk⟩; rw [toLanesNeon_getElem b ⟨k, hk⟩] at h; exact h
    have hvqk : (v_q.val[k]) = i := by
      exact v_q_post k hk
    have hvqval : (v_q.val[k]).val = 3329 := by
      rw [hvqk, hival]
    have hvqbv : (v_q.val[k]).bv = 3329#16 := by
      rw [hvqk, hibv]
    have ha1cond : (a1.val[k]).val =
        ((a.val[k]).bv - (b.val[k]).bv).toInt := by
      show (a1.val[k]).bv.toInt = _
      have ha1bv : (a1.val[k]).bv =
          (v_res.val[k]).bv := by
        exact a1_post k hk
      have hvres : (v_res.val[k]) =
          core.num.U16.wrapping_sub
            (a.val[k])
            (b.val[k]) := by
        exact v_res_post k hk
      have hvresbv := congrArg UScalar.bv hvres
      simp only [core.num.U16.wrapping_sub_bv_eq] at hvresbv
      have hvresbv_toInt := congrArg _root_.BitVec.toInt hvresbv
      rw [ha1bv]
      exact hvresbv_toInt
    have hcond0 : ∀ (X : _root_.BitVec 16), (X.toInt < 0) = ((0#16).toInt > X.toInt) := by
      intro X; apply propext; simp only [gt_iff_lt]; rw [show (0#16 : _root_.BitVec 16).toInt = 0 from by decide]
    have hR : (r.val[k]).bv =
        ((a.val[k]).bv - (b.val[k]).bv) +
        ((if (0#16).toInt >
              ((a.val[k]).bv -
               (b.val[k]).bv).toInt
            then 65535#16 else 0#16) &&& 3329#16) := by
      have hr : (r.val[k]) =
          core.num.U16.wrapping_add
            (v_res.val[k])
            (v_tmp11.val[k]) := by
        exact r_post k hk
      have htmp1 : (v_tmp1.val[k]) =
          (if (a1.val[k]).val < 0
            then 65535#u16 else 0#u16) := by
        exact v_tmp1_post k hk
      have htmp11 : (v_tmp11.val[k]) =
          (v_tmp1.val[k]) &&&
          (v_q.val[k]) := by
        exact v_tmp11_post k hk
      have hvres : (v_res.val[k]) =
          core.num.U16.wrapping_sub
            (a.val[k])
            (b.val[k]) := by
        exact v_res_post k hk
      rw [hr, htmp11, htmp1, hvres]
      simp only [ha1cond, hcond0, hvqbv,
        core.num.U16.wrapping_add_bv_eq, core.num.U16.wrapping_sub_bv_eq,
        UScalar.bv_and, apply_ite (fun u : U16 => u.bv),
        show (65535#u16 : U16).bv = 65535#16 from rfl,
        show (0#u16 : U16).bv = 0#16 from rfl]
    have hlane := mod_sub_lane _ _ _ hA hB hR
    exact ⟨hlane.1, hlane.2⟩
  refine ⟨fun i => ?_, fun i => ?_⟩
  · rw [toLanesNeon_getElem r i]; exact (key i.val i.isLt).1
  · rw [toLanesNeon_getElem r i, toLanesNeon_getElem a i, toLanesNeon_getElem b i]
    exact (key i.val i.isLt).2

set_option maxHeartbeats 1000000 in
/-- **Spec for `vec128_mont_mul` (composite NEON — Montgomery multiplication).**
    `b_mont = b · 3327 mod 2^16` is the companion of `b`; result `= a·b·R⁻¹` in `Zq`.
    Proved by composing the modelled NEON widening-multiply core
    (`vmull`/`vmlal`/`vuzp2q`/reinterpret) lane specs with the shared Montgomery
    lane cores (`mont_mul_lane`, `mont_final_lane`); 8-lane analogue of the AVX2
    `mont_mul_avx2_spec_avx2` theorem. -/
theorem vec128_mont_mul_spec_neon :
    ∀ (a b b_mont : NeonVec),
      wfVecNeon a → wfVecNeon b →
      (∀ i : Fin 8,
        ((toLanesNeon b_mont)[i.val].val : ℕ) =
          ((toLanesNeon b)[i.val].val * 3327) % 65536) →
      NeonNttInst.vec128_mont_mul a b b_mont ⦃ r =>
        wfVecNeon r ∧
        ∀ i : Fin 8,
          ((toLanesNeon r)[i.val].val : Zq) =
            ((toLanesNeon a)[i.val].val : Zq) *
            ((toLanesNeon b)[i.val].val : Zq) * Rinv ⦄ := by
  intro a b b_mont ha hb hbm
  simp only [wfVecNeon] at ha hb ⊢
  simp only [
    mlkem.ntt.ntt_neon.NttIntrinsicsNeon.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU168.vec128_mont_mul,
    mlkem.ntt.ntt_neon.NttIntrinsicsNeon.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU168.vec128_mod_sub,
    mlkem.ntt.ntt_neon.NttIntrinsicsNeon.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU168.vec128_set_u16x8]
  /- Montgomery body: widening-multiply core assembling `(A·B + m·q) / 2^16`. -/
  let* ⟨ qcast, qcast_post ⟩ ← UScalar.cast.step_spec
  let* ⟨ vQ, vQ_post ⟩ ← verify.intrinsics.aarch64.neon.vdupq_n_u16.spec
  let* ⟨ mLanes, mLanes_post ⟩ ← verify.intrinsics.aarch64.neon.vmulq_u16.spec
  let* ⟨ aLo, aLo_post ⟩ ← verify.intrinsics.aarch64.neon.vget_low_u16.spec
  let* ⟨ bLo, bLo_post ⟩ ← verify.intrinsics.aarch64.neon.vget_low_u16.spec
  let* ⟨ prodLo, prodLo_post ⟩ ← verify.intrinsics.aarch64.neon.vmull_u16.spec
  let* ⟨ prodHi, prodHi_post ⟩ ← verify.intrinsics.aarch64.neon.vmull_high_u16.spec
  let* ⟨ mLo, mLo_post ⟩ ← verify.intrinsics.aarch64.neon.vget_low_u16.spec
  let* ⟨ qLo, qLo_post ⟩ ← verify.intrinsics.aarch64.neon.vget_low_u16.spec
  let* ⟨ accLo, accLo_post ⟩ ← verify.intrinsics.aarch64.neon.vmlal_u16.spec
  let* ⟨ accHi, accHi_post ⟩ ← verify.intrinsics.aarch64.neon.vmlal_high_u16.spec
  let* ⟨ reLo, reLo_post ⟩ ← verify.intrinsics.aarch64.neon.vreinterpretq_u16_u32.spec
  let* ⟨ reHi, reHi_post ⟩ ← verify.intrinsics.aarch64.neon.vreinterpretq_u16_u32.spec
  let* ⟨ mulhi, mulhi_post1, mulhi_post2 ⟩ ← verify.intrinsics.aarch64.neon.vuzp2q_u16.spec
  /- Canonical reduction `vec128_mod_sub mulhi vQ`. -/
  let* ⟨ qcast2, qcast2_post ⟩ ← UScalar.cast.step_spec
  let* ⟨ vQ2, vQ2_post ⟩ ← verify.intrinsics.aarch64.neon.vdupq_n_u16.spec
  let* ⟨ sub, sub_post ⟩ ← verify.intrinsics.aarch64.neon.vsubq_u16.spec
  let* ⟨ subS, subS_post ⟩ ← verify.intrinsics.aarch64.neon.vreinterpretq_s16_u16.spec
  let* ⟨ mask, mask_post ⟩ ← verify.intrinsics.aarch64.neon.vcltzq_s16.spec
  let* ⟨ maskQ, maskQ_post ⟩ ← verify.intrinsics.aarch64.neon.vandq_u16.spec
  let* ⟨ r, r_post ⟩ ← verify.intrinsics.aarch64.neon.vaddq_u16.spec
  /- The `q` broadcast vectors (`vQ`, `vQ2`) are all-lanes `3329`. -/
  have hQbv : qcast.bv = 3329#16 := by
    rw [qcast_post]; simp only [UScalar.cast, UScalar.bv_mk_apply,
      show mlkem.ntt.Q.bv = 3329#32 from by unfold mlkem.ntt.Q; rfl]; decide
  have hQval : qcast.val = 3329 := by show qcast.bv.toNat = 3329; rw [hQbv]; decide
  have hQ2bv : qcast2.bv = 3329#16 := by
    rw [qcast2_post]; simp only [UScalar.cast, UScalar.bv_mk_apply,
      show mlkem.ntt.Q.bv = 3329#32 from by unfold mlkem.ntt.Q; rfl]; decide
  /- `key` : the mulhi lane `mulhi[k]` is the Montgomery reduction value
     `(A·B + m·q)/2^16` (`m = A·B·3327 mod 2^16`), hence `< 2q` and `= A·B·R⁻¹`. -/
  have key : ∀ k, (hk : k < 8) →
      (mulhi[k]).val < 6658 ∧
      ((mulhi[k]).val : ZMod 3329) =
        ((a[k]).val : ZMod 3329) * ((b[k]).val : ZMod 3329) * Rinv := by
    intro k hk
    have hAlt : a[k].val < 3329 := by
      have h := ha ⟨k, hk⟩; rw [toLanesNeon_getElem a ⟨k, hk⟩] at h; exact h
    have hBlt : b[k].val < 3329 := by
      have h := hb ⟨k, hk⟩; rw [toLanesNeon_getElem b ⟨k, hk⟩] at h; exact h
    -- m-lane value `m = (A·B·3327) mod 2^16`.
    have hm : mLanes[k].val = (a[k].val * b[k].val * 3327) % 65536 := by
      have hbmk : b_mont[k].val = (b[k].val * 3327) % 65536 := by
        have h := hbm ⟨k, hk⟩
        rw [toLanesNeon_getElem b_mont ⟨k, hk⟩, toLanesNeon_getElem b ⟨k, hk⟩] at h; exact h
      rw [mLanes_post k hk, u16_wmul_val, hbmk]
      conv_lhs => rw [Nat.mul_mod, Nat.mod_mod_of_dvd _ (dvd_refl 65536), ← Nat.mul_mod]
      rw [show a[k].val * (b[k].val * 3327) = a[k].val * b[k].val * 3327 from by ring]
    have hmlt : mLanes[k].val < 65536 := by rw [hm]; exact Nat.mod_lt _ (by decide)
    have hno : a[k].val * b[k].val + mLanes[k].val * 3329 < 2^32 := by
      have hABle : a[k].val * b[k].val ≤ 3328 * 3328 := Nat.mul_le_mul (by omega) (by omega)
      omega
    -- mulhi lane value `(A·B + m·q)/2^16` (case split low/high half).
    have hmulhi : mulhi[k].val =
        (a[k].val * b[k].val + mLanes[k].val * 3329) / 65536 := by
      by_cases hk4 : k < 4
      · have hprodLo : prodLo[k].val = a[k].val * b[k].val := by
          rw [prodLo_post k hk4, aLo_post k hk4, bLo_post k hk4]
        have hmLo : mLo[k].val = mLanes[k].val := by rw [mLo_post k hk4]
        have hqLo : qLo[k].val = 3329 := by rw [qLo_post k hk4, vQ_post k (by omega), hQval]
        have hmh : mulhi[k].val = accLo[k].val / 65536 := by
          rw [mulhi_post1 k hk4, (reLo_post k hk4).2]
        rw [hmh, accLo_post k hk4, hprodLo, hmLo, hqLo, Nat.mod_eq_of_lt hno]
      · obtain ⟨j, rfl⟩ : ∃ j, k = j + 4 := ⟨k - 4, by omega⟩
        have hj : j < 4 := by omega
        have hprodHi : prodHi[j].val = a[j+4].val * b[j+4].val := by
          rw [prodHi_post j hj]
        have hvQ : vQ[j+4].val = 3329 := by rw [vQ_post (j+4) (by omega), hQval]
        have hmh : mulhi[j+4].val = accHi[j].val / 65536 := by
          rw [mulhi_post2 j hj, (reHi_post j hj).2]
        rw [hmh, accHi_post j hj, hprodHi, hvQ, Nat.mod_eq_of_lt hno]
    rw [hmulhi, hm]
    exact mont_mul_lane a[k].val b[k].val hAlt hBlt
  /- Final canonical reduction `mod_sub mulhi vQ` per lane via `mont_final_lane`. -/
  have keyfin : ∀ k, (hk : k < 8) →
      (r[k]).val < 3329 ∧
      ((r[k]).val : ZMod 3329) =
        ((a[k]).val : ZMod 3329) * ((b[k]).val : ZMod 3329) * Rinv := by
    intro k hk
    have hX : (mulhi[k]).bv.toNat < 6658 := (key k hk).1
    have hvQbv : vQ[k].bv = 3329#16 := by rw [vQ_post k hk, hQbv]
    have hvQ2bv : vQ2[k].bv = 3329#16 := by rw [vQ2_post k hk, hQ2bv]
    -- the signed sign-bit predicate equals the `mod_sub` mask condition
    have hsubval : (subS[k]).val = (mulhi[k].bv - 3329#16).toInt := by
      show (subS[k]).bv.toInt = _
      rw [subS_post k hk, sub_post k hk, core.num.U16.wrapping_sub_bv_eq, hvQbv]
    have hcond0 : ∀ (X : _root_.BitVec 16), (X.toInt < 0) = ((0#16).toInt > X.toInt) := by
      intro X; apply propext; simp only [gt_iff_lt]
      rw [show (0#16 : _root_.BitVec 16).toInt = 0 from by decide]
    have hR : (r[k]).bv =
        ((mulhi[k]).bv - 3329#16) +
        ((if (0#16).toInt > ((mulhi[k]).bv - 3329#16).toInt then 65535#16 else 0#16) &&& 3329#16) := by
      rw [r_post k hk, maskQ_post k hk, mask_post k hk, sub_post k hk]
      simp only [hsubval, hcond0, hvQbv, hvQ2bv,
        core.num.U16.wrapping_add_bv_eq, core.num.U16.wrapping_sub_bv_eq,
        UScalar.bv_and, apply_ite (fun u : U16 => u.bv),
        show (65535#u16 : U16).bv = 65535#16 from rfl, show (0#u16 : U16).bv = 0#16 from rfl]
    have hlane := mont_final_lane _ _ hX hR
    exact ⟨hlane.1, hlane.2.trans (key k hk).2⟩
  refine ⟨fun i => ?_, fun i => ?_⟩
  · rw [toLanesNeon_getElem r i]; exact (keyfin i.val i.isLt).1
  · rw [toLanesNeon_getElem r i, toLanesNeon_getElem a i, toLanesNeon_getElem b i]
    exact (keyfin i.val i.isLt).2

/-- The `NttIntrinsicsSpec` instance for AArch64 NEON.

    Each field is discharged by the corresponding `vec128_*_spec_neon`
    theorem proved above. -/
noncomputable instance neonNttIntrinsicsSpec :
    NttIntrinsicsSpec
      NeonVec
      NeonNttInst where

  toLanes := toLanesNeon
  wfVec := wfVecNeon

  /- INFORMAL PROOF.  Definitional: `wfVecNeon v` is defined to be
     `∀ i, (toLanesNeon v)[i.val].val < q`, which is the RHS of the
     iff.  Proof: `Iff.rfl`. -/
  wfVec_iff := fun _ => Iff.rfl

  /- INFORMAL PROOF.  Unfold `NeonNttInst.vec128_load_u16x8` (now a
     transparent `def` in `Code/Funs.lean` for the NEON dict — the verify
     shim indexes the `[u16; 8]` word carrier).  ACLE `vld1q_u16(ptr)` loads
     8 `u16` values into lanes 0-7.  Combined with
     `wfPoly pe ∧ idx + 8 ≤ 256`, the post follows: `toLanesNeon v
     [i] = pe.val[idx + i]` for each `i : Fin 8`, and `wfVecNeon v`
     follows pointwise from `wfPoly pe`. -/
  vec128_load_u16x8_spec := vec128_load_u16x8_spec_neon

  /- INFORMAL PROOF.  Analog with ACLE `vld1_u16` (loads 4 lanes into
     the low 64 bits).  The result is widened to a `uint16x8_t` by
     `vcombine_u16` / `vget_low_u16`-shaped combinators in the shim
     transcription (`src/verify/intrinsics/aarch64/neon.rs`).  Lanes
     4-7 are unspecified — post quantifies only `i : Fin 4`. -/
  vec64_load_u16x4_spec := vec64_load_u16x4_spec_neon

  /- INFORMAL PROOF.  Analog with ACLE `vld1_dup_u32` + reinterpret
     (loads 4 bytes = 2 `u16` lanes into the low 32 bits, duplicated
     across the upper half — but only lanes 0-1 are spec-relevant). -/
  vec32_load_u16x2_spec := vec32_load_u16x2_spec_neon

  /- INFORMAL PROOF.  Unfold `NeonNttInst.vec128_store_u16x8` (one-line
     shim around `vst1q_u16`).  ACLE `vst1q_u16(ptr, v)` writes 8 `u16`
     values to `ptr[0..16]`.  The frame conjunct follows from the byte
     window argument (in-window: store; out-of-window: bytes
     untouched).  `wfPoly pe'` follows from `wfPoly pe` (untouched
     lanes) + `wfVecNeon v` (touched lanes). -/
  vec128_store_u16x8_spec := vec128_store_u16x8_spec_neon

  /- INFORMAL PROOF.  Analog with ACLE `vst1_u16` (writes 4 lanes from
     the low 64 bits).  Only lanes 0-3 of `v` are read; precondition
     needs only the partial `wfVec`. -/
  vec64_store_u16x4_spec := vec64_store_u16x4_spec_neon

  /- INFORMAL PROOF.  Analog with ACLE `vst1_lane_u32` + reinterpret
     (writes 4 bytes = 2 `u16` lanes). -/
  vec32_store_u16x2_spec := vec32_store_u16x2_spec_neon

  /- INFORMAL PROOF.  Unfold `NeonNttInst.vec128_set_u16x8` (one-line
     shim around `vdupq_n_u16`).  ACLE `vdupq_n_u16(x)` broadcasts `x`
     to all 8 lanes.  `wfVecNeon` follows from `x.val < q`. -/
  vec128_set_u16x8_spec := vec128_set_u16x8_spec_neon

  /- INFORMAL PROOF.  Body composition (from the NEON driver,
     `src/mlkem/ntt_neon.rs`):

     ```
     vec128_mod_add a b =
       let q_vec ← vdupq_n_u16 q
       let sum   ← vaddq_u16 a b            -- lane-wise u16 add (mod 2^16)
       let mask  ← vcgtq_u16 sum q_vec      -- 0xFFFF where sum > q
       let corr  ← vandq_u16 mask q_vec
       vsubq_u16 sum corr
     ```

     Algebra: identical to the x86 SSE2 chain.  Lane k:
       `result[k] = (a[k] + b[k]) - (if a[k]+b[k] > q then q else 0)`
       `         ≡ (a[k] + b[k]) (mod q)` in Zq.
     Bounds: `wfVec a ∧ wfVec b ⇒ a[k]+b[k] < 2q < 2^16`, no overflow;
     correction lifts result into `[0, q)`, establishing `wfVecNeon`.

     ACLE intrinsics invoked: `vdupq_n_u16`, `vaddq_u16`, `vcgtq_u16`,
     `vandq_u16`, `vsubq_u16`. -/
  vec128_mod_add_spec := vec128_mod_add_spec_neon

  /- INFORMAL PROOF.  Symmetric to `vec128_mod_add_spec`:

     ```
     vec128_mod_sub a b =
       let q_vec  ← vdupq_n_u16 q
       let zero   ← vdupq_n_u16 0
       let diff   ← vsubq_u16 a b           -- 2's-complement wrap
       let mask   ← vcgtq_u16 zero diff     -- 0xFFFF where diff < 0
       let corr   ← vandq_u16 mask q_vec
       vaddq_u16 diff corr
     ```

     Lane k: `(a[k] - b[k]) + (if a[k]<b[k] then q else 0)` in
     `u16` arithmetic, canonicalised into `[0, q)`.  Same ACLE
     palette as `vec128_mod_add_spec`. -/
  vec128_mod_sub_spec := vec128_mod_sub_spec_neon

  /- INFORMAL PROOF.  Montgomery reduction (NEON variant).  Body:

     ```
     vec128_mont_mul a b b_mont =
       let q_vec ← vdupq_n_u16 q
       let hi    ← vqdmulh_high_u16 a b          -- saturating-doubling-mul-high
                                                  -- on aarch64; alternative shape:
                                                  --   vmull_u16 (low/high) + vshrn_n_u32
       let lo    ← vmulq_u16 a b_mont            -- (a · b_mont) mod 2^16
       let m     ← vqdmulh_high_u16 lo q_vec     -- ⌊lo·q / 2^16⌋
       let res1  ← vsubq_u16 hi m
       -- conditional correction by q:
       let zero  ← vdupq_n_u16 0
       let mask  ← vcgtq_u16 zero res1
       let corr  ← vandq_u16 mask q_vec
       vaddq_u16 res1 corr
     ```

     Algebra (lane k): given `b_mont[k] ≡ b[k] · (−q⁻¹) (mod 2^16)`,
     standard Montgomery gives
       `(hi[k] − m[k]) mod q = a[k] · b[k] · R⁻¹ mod q`  with `R = 2^16`.

     This proof mirrors the SCALAR `mont_mul.spec` proof in
     `Properties/MLKEM/Ntt/ModArith.lean` lane-by-lane, and is
     structurally identical to `xmmNttIntrinsicsSpec.vec128_mont_mul_spec`
     in `X86_64/Sse2.lean` (only the intrinsic names differ).

     Plan: factor a private `mont_mul_lane_eq` lemma (or share with
     SSE2 via a shared lane lemma) and reuse 8 times. -/
  vec128_mont_mul_spec := vec128_mont_mul_spec_neon

end Symcrust.Properties.MLKEM.Intrinsics.Aarch64
