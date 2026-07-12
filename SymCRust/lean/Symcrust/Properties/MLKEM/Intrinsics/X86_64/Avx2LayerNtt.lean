/-
  Symcrust/Properties/MLKEM/Intrinsics/X86_64/Avx2LayerNtt.lean — `@[step]` specs
  for the AVX2 (`__m256i`, 16 `u16` lanes) NTT layer.

  The shared leaf specs (`mod_{add,sub}_avx2_spec_avx2`,
  `mont_mul_avx2_spec_avx2`, `mm256_{load,store}_spec_avx2`,
  `_mm256_set1_epi16_spec_avx2`) live here; `Avx2LayerIntt.lean`
  imports this file and adds the INTT loop specs.

  ## Surface

  Unlike the SSE2/NEON paths, AVX2 is **not** trait-parametric in the
  Aeneas extraction.  `Code/Funs.lean` exposes concrete `__m256i` defs
  for `mod_sub_avx2`, `mod_add_avx2`, `mont_mul_avx2`, plus the loop
  triple `ntt_layer_avx2_loop0_loop0` / `_loop0` / top, and the
  symmetric INTT triple.  This file provides:

  * 2 lane-projection abstractions (`toLanesYmm`, `wfVecYmm`)
  * 3 arithmetic helper specs (`mod_add_avx2`, `mod_sub_avx2`,
    `mont_mul_avx2`)
  * 2 memory helper specs (`mm256_load`, `mm256_store`)
  * 3 NTT loop specs (`_loop0_loop0`, `_loop0`, top)
  * 3 INTT loop specs (`_loop0_loop0`, `_loop0`, top)

  Total: 11 `@[step]` theorems + 2 helper defs (all proven; zero axioms).

  ## Status

  **PROVEN — zero algorithm-specific axioms.**  The six leaf
  `@[step]` theorems (`mod_add_avx2`, `mod_sub_avx2`, `mont_mul_avx2`,
  `mm256_load`, `mm256_store`, `_mm256_set1_epi16`) compose the generic
  modelled AVX2 `ymm` lane-op step specs from
  `Intrinsics/Properties/X86_64/Avx2.lean` — mirror of the SSE2/NEON
  `vec128_*_spec_xmm/neon` pattern in
  `Properties/MLKEM/Intrinsics/X86_64/Sse2.lean`.  The `mm256_load`/
  `mm256_store` specs reach lanes through the byte→lane bridges
  `bytes256_to_words16x16` / `words16x16_to_bytes256` (the verify shims
  index the coefficient slice — no raw pointers, see
  `src/mlkem/ntt_avx2.rs`).  The 5 loop/butterfly specs above them
  (`butterfly`, `_loop0_loop0`, `_loop0`, top NTT, top INTT) are PROVED
  outright.

  `toLanesYmm` is a derived `def` over the canonical
  `M256.u16x16` view defined in
  `Intrinsics/Axioms/X86_64/Common.lean`, marked `@[irreducible]` to
  keep downstream `whnf` cheap.

  Loop-spec post shapes mirror `Properties/MLKEM/Intrinsics/Vec128LayerNtt.lean`
  / `Vec128LayerIntt.lean` verbatim (same `nttButterflies` / `nttMidLayer.1`
  / `inttButterflies` / `inttMidLayer.1` formulae) — only the lane width (16 vs 8) and the
  iterator step (`step_by.val = 16` vs `8`) differ.  This alignment
  enables the dispatcher in `Ntt.lean` / `Intt.lean` to collapse to a
  case-split on `cpu_features_present AVX2` whose three arms share
  the same FC postcondition shape.

  ## Trust layering

  See `TraitSpec.lean` § "Trust model" for the shared trust story (it
  covers this AVX2 file too).  AVX2-specific: the extracted bodies call
  `_mm256_{set1_epi16,add_epi16,sub_epi16,mullo_epi16,mulhi_epu16,
  cmpeq_epi16,cmpgt_epi16,and_si256,andnot_si256}` plus the transparent
  `mm256_load`/`mm256_store` shims; their generic Layer-1 specs are
  theorems in `Intrinsics/Properties/X86_64/Avx2.lean`, so this path
  carries no opcode axioms.

  See `Properties/MLKEM/Intrinsics/Vec128LayerNtt.lean` /
  `Vec128LayerIntt.lean` for the analogous 8-lane (SSE2/NEON) layer and
  `Properties/MLKEM/Intrinsics/TraitSpec.lean` for the trait-parametric layer.
-/
import Symcrust.Code.Funs
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.MontArith
import Symcrust.Properties.MLKEM.Bridges.NttLoops
import Symcrust.Properties.MLKEM.Bridges.NttLinearity
import Symcrust.Properties.MLKEM.Ntt.Twiddles
import Symcrust.Properties.MLKEM.Bridges.Iterators
import Symcrust.Properties.Iterators
-- `__m256i.u16x16` lane projection (derived from primitive `u8x32` + `bytesToU16x16`):
import Intrinsics.Axioms.X86_64.Common
-- `M256.u16x16` byte-carrier lane view (from Simd.lean):
import Intrinsics.Simd
-- Layer-1 `verify.intrinsics.x86_64.ymm.*` u16×16 lane-op `@[step]` theorems:
import Intrinsics.Properties.X86_64.Avx2
-- Generic per-lane modular-arithmetic cores (shared with SSE2 / NEON):
import Symcrust.Properties.MLKEM.Bridges.ModArithLanes

open Aeneas Aeneas.Std Result
open Symcrust Spec.MLKEM
open symcrust
open Symcrust.Properties.MLKEM
open Symcrust.Properties.MLKEM.Bridges
open Symcrust.Properties.MLKEM.Bridges.ModArithLanes
open Intrinsics.X86_64
open Intrinsics

namespace Symcrust.Properties.MLKEM.Intrinsics

/- Align `get_elem_tactic` with `Intrinsics/Properties/X86_64/Avx2.lean`
   (its `ymm.*` step specs elaborate getElem bound-proofs via `agrind`), so
   `rw`/`simp only [post]` fire through matching proof terms in the gadget
   proofs below. Mirrors the SSE2 sibling in `X86_64/Sse2.lean`. -/
local macro_rules
| `(tactic| get_elem_tactic) => `(tactic| agrind)

/-- Lane projection for `__m256i`.  Reuses the canonical
    `M256.u16x16` view defined in
    `Intrinsics/Simd.lean` (16 LE `u16` lanes obtained
    from the byte-view `u8x32`).  Lane 0 is the low 16 bits.  Mirrors
    the SSE2 sibling `toLanesXmm` (8 lanes) in
    `Properties/MLKEM/Intrinsics/X86_64/Sse2.lean`.

    Marked `@[irreducible]` so the downstream loop proofs (whose
    contexts hold many `(toLanesYmm v)[i] = …` hypotheses) don't
    explode `whnf` trying to reduce through the lane projection. -/
@[irreducible]
noncomputable def toLanesYmm (v : m256) :
    Vector Std.U16 16 :=
  Vector.ofFn (fun (i : Fin 16) =>
    ((M256.u16x16 v)[i.val]))

/-- Well-formedness: all 16 lanes `< q`. -/
def wfVecYmm (v : m256) : Prop :=
  ∀ i : Fin 16, (toLanesYmm v)[i.val].val < q

/-- `toLanesYmm` lane `i` is exactly the `M256.u16x16` lane projection used by
    the `Intrinsics/Properties/X86_64/Avx2.lean` ymm step specs.  Mirrors the
    SSE2 sibling `toLanesXmm_getElem`. -/
theorem toLanesYmm_getElem (v : m256) (i : Fin 16) :
    (toLanesYmm v)[i.val] =
      (M256.u16x16 v)[i.val] := by
  unfold toLanesYmm
  simp only [Vector.getElem_ofFn]

/-! ## §0.  Leaf `@[step]` specs for the AVX2 NTT free-function intrinsics

Each of the 6 free functions called by the AVX2 NTT loop bodies is
extracted by Aeneas as a composite over the modelled AVX2 lane ops
(`mod_add_avx2`, `mod_sub_avx2`, `mont_mul_avx2`; bodies at
`Code/Funs.lean:13462+`) or as a transparent memory shim
(`mm256_load`, `mm256_store`; the `_mm256_set1_epi16` lane broadcast).
We prove the **Hoare spec** of each as a theorem here, composing the
generic `verify.intrinsics.x86_64.ymm.*` layer-1 specs from
`Intrinsics/Properties/X86_64/Avx2.lean`, mirroring the SSE2/NEON
treatment in `Properties/MLKEM/Intrinsics/X86_64/Sse2.lean` /
`Aarch64/Neon.lean` (see the `vec128_*_spec_xmm` theorems there).

The layer-1 `verify.intrinsics.x86_64.ymm.*` specs are themselves
theorems, so this path carries no silicon axioms — no ML-KEM-specific
axioms either. -/

/-- **Spec for `mod_add_avx2`** (composes the modelled AVX2 `ymm` lane ops).
    16-lane analogue of `vec128_mod_add_spec_xmm`. -/
theorem mod_add_avx2_spec_avx2 :
    ∀ (a b : m256), wfVecYmm a → wfVecYmm b →
      mlkem.ntt.ntt_avx2.mod_add_avx2 a b ⦃ r =>
        wfVecYmm r ∧
        ∀ i : Fin 16,
          ((toLanesYmm r)[i.val].val : Zq) =
            ((toLanesYmm a)[i.val].val : Zq) +
            ((toLanesYmm b)[i.val].val : Zq) ⦄ := by
  intro a b ha hb
  simp only [wfVecYmm] at ha hb ⊢
  unfold mlkem.ntt.ntt_avx2.mod_add_avx2
  step*
  have hx : i.bv = 3329#16 := by
    rw [i_post]
    simp only [UScalar.hcast, IScalar.bv_mk_apply,
      show mlkem.ntt.Q.bv = 3329#32 from by unfold mlkem.ntt.Q; rfl]
    decide
  have key : ∀ k, (hk : k < 16) →
      ((M256.u16x16 r)[k]).val < 3329 ∧
      (((M256.u16x16 r)[k]).val : ZMod 3329) =
        (((M256.u16x16 a)[k]).val : ZMod 3329) +
        (((M256.u16x16 b)[k]).val : ZMod 3329) := by
    intro k hk
    have hA : ((M256.u16x16 a)[k]).bv.toNat < 3329 := by
      have h := ha ⟨k, hk⟩; rw [toLanesYmm_getElem a ⟨k, hk⟩] at h; exact h
    have hB : ((M256.u16x16 b)[k]).bv.toNat < 3329 := by
      have h := hb ⟨k, hk⟩; rw [toLanesYmm_getElem b ⟨k, hk⟩] at h; exact h
    have hR : ((M256.u16x16 r)[k]).bv =
        (((M256.u16x16 a)[k]).bv +
          ((M256.u16x16 b)[k]).bv) -
        (~~~(if (3329#16).toInt >
              (((M256.u16x16 a)[k]).bv +
               ((M256.u16x16 b)[k]).bv).toInt
            then 65535#16 else 0#16) &&& 3329#16) := by
      simp only [r_post k hk, v_res_post k hk, v_fixup_post k hk, v_mask_post, cmpgt_epi16.pure_getElem, hk, v_q_post k hk,
        hx, core.num.U16.wrapping_sub_bv_eq, core.num.U16.wrapping_add_bv_eq,
        UScalar.bv_and, UScalar.bv_not, apply_ite (fun u : U16 => u.bv),
        show (65535#u16 : U16).bv = 65535#16 from rfl, show (0#u16 : U16).bv = 0#16 from rfl]
    have hlane := mod_add_lane _ _ _ hA hB hR
    exact ⟨hlane.1, hlane.2⟩
  refine ⟨fun i => ?_, fun i => ?_⟩
  · rw [toLanesYmm_getElem r i]; exact (key i.val i.isLt).1
  · rw [toLanesYmm_getElem r i, toLanesYmm_getElem a i, toLanesYmm_getElem b i]
    exact (key i.val i.isLt).2

/-- **Spec for `mod_sub_avx2`** (composes the modelled AVX2 `ymm` lane ops).
    16-lane analogue of `vec128_mod_sub_spec_xmm`. -/
theorem mod_sub_avx2_spec_avx2 :
    ∀ (a b : m256), wfVecYmm a → wfVecYmm b →
      mlkem.ntt.ntt_avx2.mod_sub_avx2 a b ⦃ r =>
        wfVecYmm r ∧
        ∀ i : Fin 16,
          ((toLanesYmm r)[i.val].val : Zq) =
            ((toLanesYmm a)[i.val].val : Zq) -
            ((toLanesYmm b)[i.val].val : Zq) ⦄ := by
  intro a b ha hb
  simp only [wfVecYmm] at ha hb ⊢
  unfold mlkem.ntt.ntt_avx2.mod_sub_avx2
  step*
  have hx : i.bv = 3329#16 := by
    rw [i_post]
    simp only [UScalar.hcast, IScalar.bv_mk_apply,
      show mlkem.ntt.Q.bv = 3329#32 from by unfold mlkem.ntt.Q; rfl]
    decide
  have key : ∀ k, (hk : k < 16) →
      ((M256.u16x16 r)[k]).val < 3329 ∧
      (((M256.u16x16 r)[k]).val : ZMod 3329) =
        (((M256.u16x16 a)[k]).val : ZMod 3329) -
        (((M256.u16x16 b)[k]).val : ZMod 3329) := by
    intro k hk
    have hA : ((M256.u16x16 a)[k]).bv.toNat < 3329 := by
      have h := ha ⟨k, hk⟩; rw [toLanesYmm_getElem a ⟨k, hk⟩] at h; exact h
    have hB : ((M256.u16x16 b)[k]).bv.toNat < 3329 := by
      have h := hb ⟨k, hk⟩; rw [toLanesYmm_getElem b ⟨k, hk⟩] at h; exact h
    have hR : ((M256.u16x16 r)[k]).bv =
        (((M256.u16x16 a)[k]).bv -
          ((M256.u16x16 b)[k]).bv) +
        ((if (0#16).toInt >
              (((M256.u16x16 a)[k]).bv -
               ((M256.u16x16 b)[k]).bv).toInt
            then 65535#16 else 0#16) &&& 3329#16) := by
      simp only [r_post k hk, v_res_post k hk, v_fixup_post k hk, v_mask_post, cmpgt_epi16.pure_getElem, hk, v_q_post k hk,
        v_zero_post k hk, hx, core.num.U16.wrapping_add_bv_eq, core.num.U16.wrapping_sub_bv_eq,
        UScalar.bv_and, apply_ite (fun u : U16 => u.bv),
        show (65535#u16 : U16).bv = 65535#16 from rfl, show (0#u16 : U16).bv = 0#16 from rfl]
    have hlane := mod_sub_lane _ _ _ hA hB hR
    exact ⟨hlane.1, hlane.2⟩
  refine ⟨fun i => ?_, fun i => ?_⟩
  · rw [toLanesYmm_getElem r i]; exact (key i.val i.isLt).1
  · rw [toLanesYmm_getElem r i, toLanesYmm_getElem a i, toLanesYmm_getElem b i]
    exact (key i.val i.isLt).2

set_option maxHeartbeats 1600000 in
/-- **Spec for `mont_mul_avx2`** (lane-wise 16-lane Montgomery multiplication).
    16-lane analogue of `vec128_mont_mul_spec_xmm`; the final canonical
    reduction is inlined in the AVX2 body (no `mod_sub` call), so it is
    discharged per-lane via `mont_final_lane`. -/
theorem mont_mul_avx2_spec_avx2 :
    ∀ (a b b_mont : m256),
      wfVecYmm a → wfVecYmm b →
      (∀ i : Fin 16,
        ((toLanesYmm b_mont)[i.val].val : ℕ) =
          ((toLanesYmm b)[i.val].val * 3327) % 65536) →
      mlkem.ntt.ntt_avx2.mont_mul_avx2 a b b_mont ⦃ r =>
        wfVecYmm r ∧
        ∀ i : Fin 16,
          ((toLanesYmm r)[i.val].val : Zq) =
            ((toLanesYmm a)[i.val].val : Zq) *
            ((toLanesYmm b)[i.val].val : Zq) * Rinv ⦄ := by
  intro a b b_mont ha hb hbm
  simp only [wfVecYmm] at ha hb ⊢
  unfold mlkem.ntt.ntt_avx2.mont_mul_avx2
  step*
  have hQbv : mlkem.ntt.Q.bv = 3329#32 := by unfold mlkem.ntt.Q; rfl
  have hvq_all : ∀ k, (hk : k < 16) → (M256.u16x16 v_q)[k].val = 3329 := by
    intro k hk
    have h := v_q_post k hk; rw [i_post] at h
    have hbv : (M256.u16x16 v_q)[k].bv = 3329#16 := by
      rw [h]; simp only [UScalar.hcast, IScalar.bv_mk_apply, hQbv]; decide
    show (M256.u16x16 v_q)[k].bv.toNat = 3329
    rw [hbv]; decide
  have hvzero_all : ∀ k, (hk : k < 16) → (M256.u16x16 v_zero)[k].val = 0 := by
    intro k hk
    have h := v_zero_post k hk
    show (M256.u16x16 v_zero)[k].bv.toNat = 0
    rw [h]; decide
  -- `key` : the high/low Montgomery assembly value `v_res3` is `< 2q` and `= a·b·R⁻¹`.
  have key : ∀ k, (hk : k < 16) →
      (M256.u16x16 v_res3)[k].val < 6658 ∧
      ((M256.u16x16 v_res3)[k].val : ZMod 3329) =
        ((M256.u16x16 a)[k].val : ZMod 3329) * ((M256.u16x16 b)[k].val : ZMod 3329) * Rinv := by
    intro k hk
    set A := (M256.u16x16 a)[k].val with hA_def
    set B := (M256.u16x16 b)[k].val with hB_def
    have hAlt : A < 3329 := by
      have h := ha ⟨k, hk⟩; rwa [toLanesYmm_getElem a ⟨k, hk⟩] at h
    have hBlt : B < 3329 := by
      have h := hb ⟨k, hk⟩; rwa [toLanesYmm_getElem b ⟨k, hk⟩] at h
    have hBM : (M256.u16x16 b_mont)[k].val = (B * 3327) % 65536 := by
      have h := hbm ⟨k, hk⟩
      rw [toLanesYmm_getElem b_mont ⟨k, hk⟩, toLanesYmm_getElem b ⟨k, hk⟩] at h; exact h
    have hvq_k : (M256.u16x16 v_q)[k].val = 3329 := hvq_all k hk
    have hvzero_k : (M256.u16x16 v_zero)[k].val = 0 := hvzero_all k hk
    have hvone_k : (M256.u16x16 v_one)[k].val = 1 := by
      have h := v_one_post k hk
      have hbv : (M256.u16x16 v_one)[k].bv = 1#16 := by
        rw [h]; decide
      show (M256.u16x16 v_one)[k].bv.toNat = 1
      rw [hbv]; decide
    have hvres : (M256.u16x16 v_res)[k].val = A * B / 65536 := v_res_post k hk
    have hvtmp1 : (M256.u16x16 v_tmp1)[k].val = (A * B * 3327) % 65536 := by
      rw [v_tmp1_post k hk, u16_wmul_val, hBM]
      conv_lhs => rw [Nat.mul_mod, Nat.mod_mod_of_dvd _ (dvd_refl 65536), ← Nat.mul_mod]
      rw [show A * (B * 3327) = A * B * 3327 from by ring]
    have hvtmp2 : (M256.u16x16 v_tmp2)[k].val =
        if (A * B * 3327) % 65536 = 0 then 65535 else 0 := by
      simp only [v_tmp2_post, cmpeq_epi16.pure_getElem, hk]
      by_cases hc : (M256.u16x16 v_tmp1)[k] = (M256.u16x16 v_zero)[k]
      · rw [if_pos hc]
        have hm0 : (A * B * 3327) % 65536 = 0 := by rw [← hvtmp1, hc, hvzero_k]
        rw [if_pos hm0]; decide
      · rw [if_neg hc]
        have hm0 : (A * B * 3327) % 65536 ≠ 0 := by
          intro h; apply hc; apply UScalar.eq_of_val_eq
          rw [hvzero_k, hvtmp1]; exact h
        rw [if_neg hm0]; decide
    have hvtmp11 : (M256.u16x16 v_tmp11)[k].val = ((A * B * 3327) % 65536) * 3329 / 65536 := by
      rw [v_tmp11_post k hk, hvtmp1, hvq_k]
    have hhab : A * B / 65536 ≤ 169 := by
      have hABle : A * B ≤ 3328 * 3328 := Nat.mul_le_mul (by grind) (by grind)
      calc A * B / 65536 ≤ 3328 * 3328 / 65536 := Nat.div_le_div_right hABle
        _ = 169 := by decide
    have hhmq : ((A * B * 3327) % 65536) * 3329 / 65536 ≤ 3328 := by
      have hmle : (A * B * 3327) % 65536 ≤ 65535 := Nat.le_of_lt_succ (Nat.mod_lt _ (by decide))
      calc ((A * B * 3327) % 65536) * 3329 / 65536 ≤ 65535 * 3329 / 65536 :=
              Nat.div_le_div_right (Nat.mul_le_mul_right _ hmle)
        _ = 3328 := by decide
    have hvres3 : (M256.u16x16 v_res3)[k].val =
        A * B / 65536 + ((A * B * 3327) % 65536) * 3329 / 65536
          + (if (A * B * 3327) % 65536 = 0 then 0 else 1) := by
      rw [v_res3_post k hk, u16_wadd_val, v_res2_post k hk, u16_wadd_val,
          v_res1_post k hk, u16_wadd_val, hvres, hvone_k, hvtmp2, hvtmp11]
      rw [mont_res3_collapse _ _ _ hhab hhmq (by by_cases h : (A*B*3327)%65536 = 0 <;> simp [h])]
      by_cases hm0 : (A * B * 3327) % 65536 = 0 <;> simp [hm0]
    rw [hvres3, mont_carry_nat A B]
    exact mont_mul_lane A B hAlt hBlt
  -- Final inlined canonical reduction `mod_sub(v_res3, v_q)` per lane via `mont_final_lane`.
  have keyfin : ∀ k, (hk : k < 16) →
      (M256.u16x16 r)[k].val < 3329 ∧
      ((M256.u16x16 r)[k].val : ZMod 3329) =
        ((M256.u16x16 a)[k].val : ZMod 3329) * ((M256.u16x16 b)[k].val : ZMod 3329) * Rinv := by
    intro k hk
    have hX : (M256.u16x16 v_res3)[k].bv.toNat < 6658 := (key k hk).1
    have hvqbv : (M256.u16x16 v_q)[k].bv = 3329#16 := by
      apply _root_.BitVec.eq_of_toNat_eq
      show (M256.u16x16 v_q)[k].val = (3329#16).toNat
      rw [hvq_all k hk]; decide
    have hvzbv : (M256.u16x16 v_zero)[k].bv = 0#16 := by
      apply _root_.BitVec.eq_of_toNat_eq
      show (M256.u16x16 v_zero)[k].val = (0#16).toNat
      rw [hvzero_all k hk]; decide
    have hR : (M256.u16x16 r)[k].bv =
        ((M256.u16x16 v_res3)[k].bv - 3329#16) +
        ((if (0#16).toInt > ((M256.u16x16 v_res3)[k].bv - 3329#16).toInt
            then 65535#16 else 0#16) &&& 3329#16) := by
      simp only [r_post k hk, v_fixup_post k hk, v_mask_post, cmpgt_epi16.pure_getElem, hk, v_diff_post k hk,
        hvqbv, hvzbv, core.num.U16.wrapping_add_bv_eq, core.num.U16.wrapping_sub_bv_eq,
        UScalar.bv_and, apply_ite (fun u : U16 => u.bv),
        show (65535#u16 : U16).bv = 65535#16 from rfl, show (0#u16 : U16).bv = 0#16 from rfl]
    have hlane := mont_final_lane _ _ hX hR
    exact ⟨hlane.1, hlane.2.trans (key k hk).2⟩
  refine ⟨fun i => ?_, fun i => ?_⟩
  · rw [toLanesYmm_getElem r i]; exact (keyfin i.val i.isLt).1
  · rw [toLanesYmm_getElem r i, toLanesYmm_getElem a i, toLanesYmm_getElem b i]
    exact (keyfin i.val i.isLt).2

/-- **Spec for `mm256_load`** (AVX2 16-lane load — byte-carrier redirect).
    The verify shim now loads 16 contiguous coefficients through
    `loadu_si256_u16` and re-views them as the `__m256i` byte carrier via
    `words16x16_to_bytes256` (no raw pointer — see `src/mlkem/ntt_avx2.rs`); the
    spec is a theorem composing those Layer-1 specs with `words16x16_to_bytes256_u16x16`. -/
theorem mm256_load_spec_avx2 :
    ∀ (pe : PolyElement) (idx : Std.Usize)
      (_h_wf : wfPoly pe) (h_idx : idx.val + 16 ≤ 256),
      mlkem.ntt.ntt_avx2.mm256_load pe idx ⦃ v =>
        wfVecYmm v ∧
        ∀ i : Fin 16, (toLanesYmm v)[i.val] = pe.val[idx.val + i.val]'(by
          have := pe.property; have := i.isLt; grind) ⦄ := by
  intro pe idx hwf hidx
  unfold mlkem.ntt.ntt_avx2.mm256_load
  step as ⟨s, s_post⟩
  step as ⟨a, a_post⟩
  step with words16x16_to_bytes256_u16x16 as ⟨v, hv⟩
  have hlane : ∀ j : Fin 16, (toLanesYmm v)[j.val]
      = pe.val[idx.val + j.val]'(by have := pe.property; have := j.isLt; grind) := by
    intro j
    rw [toLanesYmm_getElem]; simp only [hv]
    rw [a_post j.val j.isLt]
    have hsv : s.val = pe.val := by rw [s_post, Array.val_to_slice]
    grind
  refine ⟨?_, hlane⟩
  intro j; rw [hlane j]; exact hwf _ (by have := j.isLt; grind)

set_option maxHeartbeats 1000000 in
/-- **Spec for `mm256_store`** (AVX2 16-lane store — byte-carrier redirect).
    The verify shim re-views `x` via `bytes256_to_words16x16` and writes the 16
    coefficients through `storeu_si256_u16` (no raw pointer); the spec is a
    theorem composing those Layer-1 specs with the `to_slice_mut` framing. -/
theorem mm256_store_spec_avx2 :
    ∀ (pe : PolyElement) (idx : Std.Usize) (v : m256)
      (_h_wf : wfPoly pe) (_h_idx : idx.val + 16 ≤ 256) (_h_v : wfVecYmm v),
      mlkem.ntt.ntt_avx2.mm256_store pe idx v ⦃ pe' =>
        pe'.val.length = 256 ∧
        wfPoly pe' ∧
        ∀ k : Fin 256,
          pe'.val[k.val]'(by have := pe'.property; have := k.isLt; grind) =
            if h : idx.val ≤ k.val ∧ k.val < idx.val + 16
              then (toLanesYmm v)[k.val - idx.val]'(by have := h.2; grind)
              else pe.val[k.val]'(by have := pe.property; have := k.isLt; grind) ⦄ := by
  intro pe idx v hwf hidx hv
  unfold mlkem.ntt.ntt_avx2.mm256_store
  step as ⟨s, sback, s_post⟩
  step with bytes256_to_words16x16_eq as ⟨a, ha⟩
  step as ⟨s1, hlen, hs1⟩
  have hsl : s.length = 256 := by
    rw [show s.length = s.val.length from rfl, s_post]; exact pe.property
  have hs1len : s1.val.length = 256 := by
    rw [show s1.val.length = s1.length from rfl, hlen, hsl]
  have hfs : (sback s1).val = s1.val := by
    rw [‹sback = Array.from_slice pe›]; exact Array.from_slice_val pe s1 hs1len
  have hval : ∀ k : Fin 256,
      (sback s1).val[k.val]'(by rw [hfs, hs1len]; exact k.isLt) =
        if h : idx.val ≤ k.val ∧ k.val < idx.val + 16
          then (toLanesYmm v)[k.val - idx.val]'(by have := h.2; grind)
          else pe.val[k.val]'(by have := pe.property; have := k.isLt; grind) := by
    intro k
    have hks : k.val < s.length := by rw [hsl]; exact k.isLt
    have e1 : (sback s1).val[k.val]'(by rw [hfs, hs1len]; exact k.isLt) = s1[k.val] := by
      simp only [hfs]; rfl
    rw [e1, hs1 k.val hks]
    split
    · rename_i hr
      rw [ha, toLanesYmm_getElem v ⟨k.val - idx.val, by omega⟩]
    · rename_i hr
      have hsk : s[k.val] = s.val[k.val]'hks := rfl
      rw [hsk]
      exact getElem_congr_coll s_post
  refine ⟨by rw [hfs, hs1len], ?_, hval⟩
  intro k hk
  rw [hval ⟨k, hk⟩]
  by_cases hrange : idx.val ≤ k ∧ k < idx.val + 16
  · rw [dif_pos hrange]; have := hv ⟨k - idx.val, by omega⟩; simpa using this
  · rw [dif_neg hrange]; exact hwf k hk

/-- **Spec for the modelled `verify.intrinsics.x86_64.ymm.set1_epi16`
    broadcast** (now a theorem composing the proven
    `Intrinsics/Properties/X86_64/Avx2` ymm step spec).  All 16 lanes receive
    the same 16-bit pattern as the input. -/
theorem _mm256_set1_epi16_spec_avx2 :
    ∀ (a : Std.I16),
      verify.intrinsics.x86_64.ymm.set1_epi16 a ⦃ (r : m256) =>
        ∀ i : Fin 16, (toLanesYmm r)[i.val].bv = a.bv ⦄ := by
  intro a
  apply WP.exists_imp_spec
  obtain ⟨r, hr_eq, hr_post⟩ :=
    WP.spec_imp_exists (verify.intrinsics.x86_64.ymm.set1_epi16.spec a)
  refine ⟨r, hr_eq, fun i => ?_⟩
  rw [toLanesYmm_getElem r i]
  exact hr_post i.val i.isLt

/-! ## §1.  Helper specs (mod_add / mod_sub / mont_mul over `__m256i`).
    These are shared between the NTT and INTT layers (same Rust defs).
    Each delegates to the corresponding leaf theorem above. -/

/-- Lane-wise modular addition.  See `mod_add_avx2_spec_avx2` for the
    underlying statement; structurally identical to the SSE2/NEON
    `vec128_mod_add` instances. -/
@[step]
theorem mod_add_avx2.spec (a b : m256)
    (h_a : wfVecYmm a) (h_b : wfVecYmm b) :
    mlkem.ntt.ntt_avx2.mod_add_avx2 a b ⦃ r =>
      wfVecYmm r ∧
      ∀ i : Fin 16,
        ((toLanesYmm r)[i.val].val : Zq) =
          ((toLanesYmm a)[i.val].val : Zq) +
          ((toLanesYmm b)[i.val].val : Zq) ⦄ :=
  mod_add_avx2_spec_avx2 a b h_a h_b

/-- Lane-wise modular subtraction.  See `mod_sub_avx2_spec_avx2`. -/
@[step]
theorem mod_sub_avx2.spec (a b : m256)
    (h_a : wfVecYmm a) (h_b : wfVecYmm b) :
    mlkem.ntt.ntt_avx2.mod_sub_avx2 a b ⦃ r =>
      wfVecYmm r ∧
      ∀ i : Fin 16,
        ((toLanesYmm r)[i.val].val : Zq) =
          ((toLanesYmm a)[i.val].val : Zq) -
          ((toLanesYmm b)[i.val].val : Zq) ⦄ :=
  mod_sub_avx2_spec_avx2 a b h_a h_b

/-- 16-lane Montgomery multiplication.  See `mont_mul_avx2_spec_avx2`;
    structurally identical to the SSE2/NEON `vec128_mont_mul` instances. -/
@[step]
theorem mont_mul_avx2.spec
    (a b b_mont : m256)
    (h_a : wfVecYmm a) (h_b : wfVecYmm b)
    (h_bm : ∀ i : Fin 16,
      ((toLanesYmm b_mont)[i.val].val : ℕ) =
        ((toLanesYmm b)[i.val].val * 3327) % 65536) :
    mlkem.ntt.ntt_avx2.mont_mul_avx2 a b b_mont ⦃ r =>
      wfVecYmm r ∧
      ∀ i : Fin 16,
        ((toLanesYmm r)[i.val].val : Zq) =
          ((toLanesYmm a)[i.val].val : Zq) *
          ((toLanesYmm b)[i.val].val : Zq) * Rinv ⦄ :=
  mont_mul_avx2_spec_avx2 a b b_mont h_a h_b h_bm

/-! ## §2.  Memory helpers (`mm256_load` / `mm256_store`).
    Each delegates to the corresponding leaf theorem above. -/

/-- `mm256_load pe idx` loads 16 `u16` lanes from `pe.val[idx .. idx+16)`. -/
@[step]
theorem mm256_load.spec (pe : PolyElement) (idx : Std.Usize)
    (h_wf : wfPoly pe) (h_idx : idx.val + 16 ≤ 256) :
    mlkem.ntt.ntt_avx2.mm256_load pe idx ⦃ v =>
      wfVecYmm v ∧
      ∀ i : Fin 16, (toLanesYmm v)[i.val] = pe.val[idx.val + i.val]'(by
        have := pe.property; have := i.isLt; grind) ⦄ :=
  mm256_load_spec_avx2 pe idx h_wf h_idx

/-- `mm256_store pe idx v` writes 16 `u16` lanes to `pe.val[idx .. idx+16)`. -/
@[step]
theorem mm256_store.spec
    (pe : PolyElement) (idx : Std.Usize) (v : m256)
    (h_wf : wfPoly pe) (h_idx : idx.val + 16 ≤ 256) (h_v : wfVecYmm v) :
    mlkem.ntt.ntt_avx2.mm256_store pe idx v ⦃ pe' =>
      pe'.val.length = 256 ∧
      wfPoly pe' ∧
      ∀ k : Fin 256,
        pe'.val[k.val]'(by have := pe'.property; have := k.isLt; grind) =
          if h : idx.val ≤ k.val ∧ k.val < idx.val + 16
            then (toLanesYmm v)[k.val - idx.val]'(by have := h.2; grind)
            else pe.val[k.val]'(by have := pe.property; have := k.isLt; grind) ⦄
    :=
  mm256_store_spec_avx2 pe idx v h_wf h_idx h_v

/-- Broadcast spec for the modelled AVX2 `ymm.set1_epi16` shim.
    Every lane receives the same 16-bit pattern as the input. -/
@[step]
theorem _root_.verify.intrinsics.x86_64.ymm.set1_epi16.spec (a : Std.I16) :
    verify.intrinsics.x86_64.ymm.set1_epi16 a ⦃ (r : m256) =>
      ∀ i : Fin 16, (toLanesYmm r)[i.val].bv = a.bv ⦄ :=
  _mm256_set1_epi16_spec_avx2 a

/-! ## §3.  NTT loop layer specs.

    Post shapes mirror `Vec128Layer.lean:158-189` (`nttButterflies` on
    the inner loop, `nttMidLayer.1` on the outer loop and top), only
    the iterator step (`step_by.val = 16` vs `8`) differs.  The
    16-lane butterfly per iteration is structurally identical to the
    8-lane vec128 butterfly. -/

/-! ### `#decompose` carve-out: AVX2 NTT inner-loop per-iteration body

The Aeneas-extracted `ntt_layer_avx2_loop0_loop0` body has 12 monadic
bindings and the recursive call buried inside an `if i ≤ len then …`
arm.  Per `aeneas-fold-decomposition`'s 10-binding heuristic, we
carve out the non-recursive per-iteration butterfly via a two-stage
`#decompose` cascade:

  * Stage 1 (`ntt_layer_avx2_loop0_loop0.fold`): extract the trailing
    ite (still containing the recursive call) as `_step`.
  * Stage 2 (`*_step.fold`): inside `_step`'s then-branch, extract the
    first 10 bindings (load×2 + mont_mul + mod_add + mod_sub + store×2 +
    arithmetic) as `_butterfly` — a **non-recursive** SIMD body.

The parent `*_loop0_loop0.spec` proof rewrites with both fold equations,
`by_cases` on `i ≤ len`, then `step`s through `_butterfly` via its own
`@[local step]` spec (below) and recurses via the loop's induction
hypothesis on the trailing recursive call. -/

set_option maxRecDepth 2048 in
#decompose mlkem.ntt.ntt_avx2.ntt_layer_avx2_loop0_loop0
    ntt_layer_avx2_loop0_loop0.fold
  letRange 1 1 => ntt_layer_avx2_loop0_loop0_step

set_option maxRecDepth 2048 in
#decompose ntt_layer_avx2_loop0_loop0_step
    ntt_layer_avx2_loop0_loop0_step.fold
  branch 0 (letRange 0 10) => ntt_layer_avx2_loop0_loop0_butterfly

/-- INFORMAL PROOF.  Per-iteration AVX2 NTT butterfly (Cooley-Tukey,
    16 lanes).  Pure SIMD body (no recursion) extracted by the
    `#decompose` cascade above.  Body:
    ```
    let i1 ← start + j
    let v_c0 ← mm256_load pe i1
    let i2 ← i1 + len
    let v_c1 ← mm256_load pe i2
    let v_t ← mont_mul_avx2 v_c1 v_tw v_tw_mont
    let v_new_c0 ← mod_add_avx2 v_c0 v_t
    let v_new_c1 ← mod_sub_avx2 v_c0 v_t
    let pe1 ← mm256_store pe i1 v_new_c0
    let i3 ← i1 + len
    mm256_store pe1 i3 v_new_c1
    ```
    Spec: post equates `toPoly r` to `nttButterflies` applied once at
    indices `[start+j .. start+j+16)` and `[start+j+len .. start+j+len+16)`
    with twiddle `u16ToZq tw * Rinv`.  Frame: lanes outside the two
    16-element windows preserved; `wfPoly r` from `wfPoly pe` (untouched
    lanes) + per-lane `wfVec` post of `mod_add_avx2` / `mod_sub_avx2` /
    `mont_mul_avx2` (touched lanes). -/
@[local step]
theorem ntt_layer_avx2_loop0_loop0_butterfly.spec
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
    ntt_layer_avx2_loop0_loop0_butterfly pe len start v_tw v_tw_mont j
    ⦃ (r : PolyElement) =>
        wfPoly r ∧
        toPoly r =
          nttButterflies (u16ToZq tw * Rinv)
              (toPoly pe) len.val
              (start.val + j.val)
              (start.val + j.val + 16)
              (by have := h_bound; have := h_j_lt; grind) ⦄ := by
  unfold ntt_layer_avx2_loop0_loop0_butterfly
  -- start + j : Usize
  step as ⟨i1, h_i1⟩
  -- v_c0 ← mm256_load pe i1
  step as ⟨v_c0, h_v_c0_wf, h_v_c0_lane⟩
  -- i1 + len : Usize  → i2 = start + j + len
  step as ⟨i2, h_i2⟩
  -- v_c1 ← mm256_load pe i2
  step as ⟨v_c1, h_v_c1_wf, h_v_c1_lane⟩
  -- v_t ← mont_mul_avx2 v_c1 v_tw v_tw_mont
  step as ⟨v_t, h_v_t_wf, h_v_t_lane⟩
  -- v_new_c0 ← mod_add_avx2 v_c0 v_t
  step as ⟨v_new_c0, h_v_new_c0_wf, h_v_new_c0_lane⟩
  -- v_new_c1 ← mod_sub_avx2 v_c0 v_t
  step as ⟨v_new_c1, h_v_new_c1_wf, h_v_new_c1_lane⟩
  -- pe1 ← mm256_store pe i1 v_new_c0
  step as ⟨pe1, h_pe1_len, h_pe1_wf, h_pe1_lane⟩
  -- i3 ← i1 + len (= i2)
  step as ⟨i3, h_i3⟩
  -- mm256_store pe1 i3 v_new_c1
  step as ⟨pe2, h_pe2_len, h_pe2_wf, h_pe2_lane⟩
  refine ⟨h_pe2_wf, ?_⟩
  -- Bridge via `nttButterflies_eq_parallel` with `W = 16`.
  -- Setup: useful facts about indices and `toPoly`.
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
  -- Apply the bridge.
  apply nttButterflies_eq_parallel
    (u16ToZq tw * Rinv) len.val (by omega) (toPoly pe) (toPoly pe2)
    (start.val + j.val) (start.val + j.val + 16)
    (by have := h_bound; have := h_j_lt; omega)
    (by omega) (by have := h_j_lt; omega)
  · -- h_pair_lo: for k ∈ [start+j, start+j+16),
    --   (toPoly pe2)[k] = (toPoly pe)[k] + (u16ToZq tw * Rinv) * (toPoly pe)[k+len]
    intro k hk_lo hk_hi
    have hk : k < 256 := by have := h_bound; have := h_j_lt; omega
    have hk_len : k + len.val < 256 := by have := h_bound; have := h_j_lt; omega
    -- Step 1: pe2.val[k] = pe1.val[k] (since k < i3)
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
    -- Step 2: pe1.val[k] = (toLanesYmm v_new_c0)[k - i1.val]   (since k ∈ [i1, i1+16))
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
    -- Step 3: Express LHS as u16ToZq of the chain.
    rw [h_toPoly_get pe2 k hk h_pe2_arr_len,
        h_toPoly_get pe k hk h_pe_arr_len,
        h_toPoly_get pe (k + len.val) hk_len h_pe_arr_len]
    rw [h_pe2_at_k, h_pe1_at_k]
    -- Cast to Zq: u16ToZq (toLanesYmm v_new_c0)[k-i1] = ↑↑(toLanesYmm v_new_c0)[k-i1]
    have h_new_c0_eq :
        u16ToZq ((toLanesYmm v_new_c0)[k - i1.val]'h_kdiff_lt) =
          u16ToZq ((toLanesYmm v_c0)[k - i1.val]'h_kdiff_lt) +
          u16ToZq ((toLanesYmm v_t)[k - i1.val]'h_kdiff_lt) := by
      have := h_v_new_c0_lane ⟨k - i1.val, h_kdiff_lt⟩
      simp at this
      unfold u16ToZq
      exact_mod_cast this
    rw [h_new_c0_eq]
    -- Now expand v_c0[k-i1] = pe[i1 + (k-i1)] = pe[k]
    have h_v_c0_at : (toLanesYmm v_c0)[k - i1.val]'h_kdiff_lt =
        pe.val[i1.val + (k - i1.val)]'(by rw [h_pe_arr_len]; omega) := by
      have := h_v_c0_lane ⟨k - i1.val, h_kdiff_lt⟩
      simp at this
      exact this
    have h_i1_plus : i1.val + (k - i1.val) = k := by omega
    -- Expand v_t[k-i1] = v_c1[k-i1] * v_tw[k-i1] * Rinv
    have h_v_t_at :
        u16ToZq ((toLanesYmm v_t)[k - i1.val]'h_kdiff_lt) =
          u16ToZq ((toLanesYmm v_c1)[k - i1.val]'h_kdiff_lt) *
          u16ToZq ((toLanesYmm v_tw)[k - i1.val]'h_kdiff_lt) * Rinv := by
      have := h_v_t_lane ⟨k - i1.val, h_kdiff_lt⟩
      simp at this
      unfold u16ToZq
      exact_mod_cast this
    have h_v_c1_at : (toLanesYmm v_c1)[k - i1.val]'h_kdiff_lt =
        pe.val[i2.val + (k - i1.val)]'(by rw [h_pe_arr_len]; omega) := by
      have := h_v_c1_lane ⟨k - i1.val, h_kdiff_lt⟩
      simp at this
      exact this
    have h_v_tw_at : (toLanesYmm v_tw)[k - i1.val]'h_kdiff_lt = tw := by
      have := h_v_tw_lane ⟨k - i1.val, h_kdiff_lt⟩
      simp at this
      exact this
    have h_i2_plus : i2.val + (k - i1.val) = k + len.val := by
      rw [h_i2_val]; rw [h_i1_val] at hk_ge_i1; omega
    rw [h_v_t_at, h_v_c0_at, h_v_c1_at, h_v_tw_at]
    simp only [h_i1_plus, h_i2_plus]
    ring
  · -- h_pair_hi: for k ∈ [start+j, start+j+16),
    --   (toPoly pe2)[k+len] = (toPoly pe)[k] - (u16ToZq tw * Rinv) * (toPoly pe)[k+len]
    intro k hk_lo hk_hi
    have hk : k < 256 := by have := h_bound; have := h_j_lt; omega
    have hk_len : k + len.val < 256 := by have := h_bound; have := h_j_lt; omega
    -- pe2.val[k+len] = (toLanesYmm v_new_c1)[(k+len) - i3]   (since k+len ∈ [i3, i3+16))
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
    -- Now also need to convert (k+len)-i3 = k-i1 since i3 = i1+len
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
    have h_new_c1_eq :
        u16ToZq ((toLanesYmm v_new_c1)[k - i1.val]'h_kdiff_lt') =
          u16ToZq ((toLanesYmm v_c0)[k - i1.val]'h_kdiff_lt') -
          u16ToZq ((toLanesYmm v_t)[k - i1.val]'h_kdiff_lt') := by
      have := h_v_new_c1_lane ⟨k - i1.val, h_kdiff_lt'⟩
      simp at this
      unfold u16ToZq
      exact_mod_cast this
    rw [h_new_c1_eq]
    have h_v_c0_at : (toLanesYmm v_c0)[k - i1.val]'h_kdiff_lt' =
        pe.val[i1.val + (k - i1.val)]'(by rw [h_pe_arr_len]; omega) := by
      have := h_v_c0_lane ⟨k - i1.val, h_kdiff_lt'⟩
      simp at this
      exact this
    have h_i1_plus : i1.val + (k - i1.val) = k := by omega
    have h_v_t_at :
        u16ToZq ((toLanesYmm v_t)[k - i1.val]'h_kdiff_lt') =
          u16ToZq ((toLanesYmm v_c1)[k - i1.val]'h_kdiff_lt') *
          u16ToZq ((toLanesYmm v_tw)[k - i1.val]'h_kdiff_lt') * Rinv := by
      have := h_v_t_lane ⟨k - i1.val, h_kdiff_lt'⟩
      simp at this
      unfold u16ToZq
      exact_mod_cast this
    have h_v_c1_at : (toLanesYmm v_c1)[k - i1.val]'h_kdiff_lt' =
        pe.val[i2.val + (k - i1.val)]'(by rw [h_pe_arr_len]; omega) := by
      have := h_v_c1_lane ⟨k - i1.val, h_kdiff_lt'⟩
      simp at this
      exact this
    have h_v_tw_at : (toLanesYmm v_tw)[k - i1.val]'h_kdiff_lt' = tw := by
      have := h_v_tw_lane ⟨k - i1.val, h_kdiff_lt'⟩
      simp at this
      exact this
    have h_i2_plus : i2.val + (k - i1.val) = k + len.val := by
      rw [h_i2_val]; rw [h_i1_val] at hk_ge_i1; omega
    rw [h_v_t_at, h_v_c0_at, h_v_c1_at, h_v_tw_at]
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

/-- INFORMAL PROOF.  16-lane butterfly inner loop, mirror of
    `mlkem.ntt.poly_element_ntt_layer_vec128_loop0_loop0.spec`
    (Vec128Layer.lean:158) with step 16.

    Proof structure (post-`#decompose`):
    1. `rw [ntt_layer_avx2_loop0_loop0.fold,
            ntt_layer_avx2_loop0_loop0_step.fold]` to expose the
       `if i ≤ len then (butterfly + recursion) else ok pe` shape.
    2. `step` the prefix `let i ← j + 16`.
    3. `by_cases hlt : i ≤ len`:
       - **true**: `step` consumes `_butterfly` via its `@[local step]`
         spec (yields the per-iteration `nttButterflies` post), then
         `apply WP.spec_mono (mlkem.ntt.ntt_avx2.ntt_layer_avx2_loop0_loop0.spec …)`
         with `j' := i = j + 16` for the recursive call;
         compose the two `nttButterflies` calls via `nttButterflies_split`.
       - **false**: `simp only [WP.spec_ok]`; the post is
         `nttButterflies … (start+j) (start+len) _`, and `hlt` implies
         `j + 16 > len`, combined with `h_j_step % 16 = 0` and
         `h_len_step % 16 = 0` forces `j = len`, making the
         `nttButterflies` range empty (`nttButterflies_nil`).

    Termination: `len.val - j.val` decreases by 16 per iteration.

    Lemmas: `nttButterflies_split`, `nttButterflies_one`,
    `nttButterflies_nil`; per-lane FC
    of `mod_add_avx2.spec` / `mod_sub_avx2.spec` / `mont_mul_avx2.spec`
    composed via the 16-lane sum-over-`Fin 16` unfold. -/
@[step]
theorem mlkem.ntt.ntt_avx2.ntt_layer_avx2_loop0_loop0.spec
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
    mlkem.ntt.ntt_avx2.ntt_layer_avx2_loop0_loop0 pe_src len start v_tw v_tw_mont j
    ⦃ (r : PolyElement) =>
        wfPoly r ∧
        toPoly r =
          nttButterflies (u16ToZq tw * Rinv)
              (toPoly pe_src) len.val
              (start.val + j.val)
              (start.val + len.val)
              (by have := h_bound; have := h_j_le; grind) ⦄ := by
  rw [ntt_layer_avx2_loop0_loop0.fold]
  /- step the `let i ← j + 16` prefix. -/
  step as ⟨i, h_i⟩
  rw [ntt_layer_avx2_loop0_loop0_step.fold]
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
      (mlkem.ntt.ntt_avx2.ntt_layer_avx2_loop0_loop0.spec pe2 len start v_tw v_tw_mont i
        h_pe2_wf h_len_pos h_len_le h_bound h_i_le h_i_step h_len_step
        tw h_tw_lt h_v_tw_wf h_v_tw_lane tw_mont h_tw_mont_eq h_v_tw_mont_lane)
    rintro r ⟨h_r_wf, h_r_toPoly⟩
    refine ⟨h_r_wf, ?_⟩
    rw [h_r_toPoly]
    /- Compose: split RHS at mid = start+j+16, then rewrite
       `nttButterflies z (toPoly pe_src) len (start+j) (start+j+16) = toPoly pe2`,
       then use `start+i = start+j+16` to align. -/
    conv_rhs =>
      rw [nttButterflies_split _ _ _ (start.val + j.val) (start.val + j.val + 16)
          (start.val + len.val) (by scalar_tac) (by scalar_tac)]
      rw [← h_pe2_toPoly]
    /- Goal: nttB z (toPoly pe2) len (start+i) (start+len) _
           = nttB z (toPoly pe2) len (start+j+16) (start+len) _ -/
    fcongr 1
    scalar_tac
  · /- EMPTY BRANCH: ¬ (i ≤ len), so j = len. -/
    simp only [hlt, ↓reduceIte, WP.spec_ok]
    refine ⟨h_wf, ?_⟩
    have h_i_val : i.val = j.val + 16 := h_i
    have h_not_i_le : ¬ i.val ≤ len.val := hlt
    have h_j_eq_len : j.val = len.val := by scalar_tac
    rw [nttButterflies_nil _ _ _ _ _ _ (by scalar_tac)]
termination_by len.val - j.val
decreasing_by scalar_decr_tac

/-- INFORMAL PROOF.  Outer twiddle loop (AVX2).  Mirror of
    `mlkem.ntt.poly_element_ntt_layer_vec128_loop0.spec`
    (Vec128Layer.lean:231) with two changes:
    1. Twiddle broadcast uses `_mm256_set1_epi16` (16 lanes) instead of
       `vec128_set_u16x8`.
    2. Inner call invokes `_loop0_loop0` with starting `j = 0`.

    Same `nttMidLayer.1` post shape; same `nttMidLayer_step`
    composition argument. -/
@[step]
theorem mlkem.ntt.ntt_avx2.ntt_layer_avx2_loop0.spec
    (iter : core.iter.adapters.step_by.StepBy
              (core.ops.range.Range Std.Usize))
    (pe_src : PolyElement) (k len : Std.Usize)
    (h_wf : wfPoly pe_src) (h_len : 16 ≤ len.val) (h_lend : len.val ≤ 128)
    (h_div : 256 % (2 * len.val) = 0)
    (h_len_step : len.val % 16 = 0)
    (h_inv : 2 * k.val * len.val + 256 ≤ 256 * len.val + iter.iter.start.val)
    (h_iter_end : iter.iter.«end».val = 256)
    (h_iter_step : iter.step_by.val = 2 * len.val)
    (h_iter_start : iter.iter.start.val ≤ 256 ∧
                    iter.iter.start.val % (2 * len.val) = 0) :
    mlkem.ntt.ntt_avx2.ntt_layer_avx2_loop0 iter pe_src k len
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r =
            (nttMidLayer len.val (by grind) iter.iter.start.val k.val
                (toPoly pe_src)).1 ⦄ := by
  unfold mlkem.ntt.ntt_avx2.ntt_layer_avx2_loop0
  obtain ⟨h_start_le, h_start_mod⟩ := h_iter_start
  have h_2len_pos : 0 < 2 * len.val := by scalar_tac
  have h_2len_le : 2 * len.val ≤ 256 := by scalar_tac
  by_cases hlt : iter.iter.start.val < iter.iter.«end».val
  · -- SOME branch: read twiddles, broadcast, run inner loop, recurse.
    have h_start_lt : iter.iter.start.val < 256 := by omega
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
      have h_ge : 256 * len.val ≤ 2 * k.val * len.val := by
        have h1 : 2 * 128 ≤ 2 * k.val := by omega
        calc 256 * len.val
            = 2 * 128 * len.val := by ring
          _ ≤ 2 * k.val * len.val := Nat.mul_le_mul_right _ h1
      omega
    have h_step_pos : iter.step_by.val > 0 := by omega
    have h_no_overflow : iter.iter.start.val + iter.step_by.val ≤ Std.Usize.max := by
      rw [h_iter_step]; scalar_tac
    let* ⟨o, iter1, ho, hiter1_start, hiter1_end, hiter1_step⟩ ←
      core.iter.adapters.step_by.IteratorStepBy.next_Range_Usize_some_spec
    rw [ho]
    simp only
    -- Index ZETA_BIT_REV_TIMES_R: produces tw_u16 with htw_zq, htw_bv, htw_lt
    step as ⟨tw_u16, htw_zq, htw_bv, htw_lt⟩
    -- hcast u16 → i16: pure-step yields i1 = UScalar.hcast .I16 tw_u16 (bv preserved)
    step as ⟨i1, h_i1_eq⟩
    -- Broadcast: v_tw with lane.bv = i1.bv
    step as ⟨v_tw, h_v_tw_lane_bv⟩
    -- Index ZETA_NEG: produces tw_mont_u16 with htw_mont_bv, htw_mont_le, htw_mont_eq
    step as ⟨tw_mont_u16, htw_mont_bv, htw_mont_le, htw_mont_eq⟩
    -- hcast u16 → i16
    step as ⟨i3, h_i3_eq⟩
    step as ⟨v_tw_mont, h_v_tw_mont_lane_bv⟩
    step as ⟨k1, hk1_eq⟩
    -- Derive U16 lane equalities from bv equalities (cast preserves bv).
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
    -- Bridge htw_mont_eq into the inner-loop's expected form.
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
    -- Inner-loop preconditions assembled; apply.
    let* ⟨pe_src1, hwf1, hto_poly1⟩ ←
      mlkem.ntt.ntt_avx2.ntt_layer_avx2_loop0_loop0.spec pe_src len iter.iter.start
        v_tw v_tw_mont 0#usize
        h_wf h_len h_lend h_start_bound (by simp) (by simp) h_len_step
        tw_u16 htw_lt h_v_tw_wf h_v_tw_lane
        tw_mont_u16 h_twm_eq_inner h_v_tw_mont_lane
    -- Convert inner loop's `u16ToZq tw_u16 * Rinv` to `ζ^(bitRev 7 k.val)`.
    have h_u16ToZq_tw : u16ToZq tw_u16 = ζ ^ _root_.bitRev 7 k.val * 65536 := by
      simp [u16ToZq]
      exact_mod_cast htw_zq
    have h_R_eq : ((65536 : Zq) : Zq) = R := by unfold R; decide
    have h_tw_Rinv : u16ToZq tw_u16 * Rinv = ζ ^ _root_.bitRev 7 k.val := by
      rw [h_u16ToZq_tw, show (65536 : Zq) = R from by unfold R; decide]
      rw [mul_assoc, R_mul_Rinv, mul_one]
    -- Build preconditions for the recursive call.
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
      (mlkem.ntt.ntt_avx2.ntt_layer_avx2_loop0.spec iter1 pe_src1 k1 len
        hwf1 h_len h_lend h_div h_len_step h_inv1 h_iter_end1 h_iter_step1 h_iter_start1)
    intro r hr
    obtain ⟨hwf_r, hto_r⟩ := hr
    refine ⟨hwf_r, ?_⟩
    -- Peel one nttMidLayer step.
    rw [hto_r]
    conv_rhs => rw [nttMidLayer]
    rw [dif_pos h_start_bound]
    simp only [nttMidStep]
    rw [hto_poly1, h_tw_Rinv]
    -- Align iter1.start and k1 with the peeled mid-step.
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
    rw [show (nttMidLayer len.val (by grind) iter.iter.start.val k.val (toPoly pe_src)).1 =
            toPoly pe_src from ?_]
    · conv_lhs => rw [nttMidLayer]
      rw [dif_neg (by rw [h_start_eq]; omega)]
termination_by 256 - iter.iter.start.val
decreasing_by
  rw [hiter1_start, h_iter_step]
  omega

/-- INFORMAL PROOF.  Top wrapper.  Asserts `len ≥ 16`, builds the
    step-by-`2*len` iterator over `[0, 256)`, delegates to `_loop0`.
    Post identical to `poly_element_ntt_layer_generic.spec`. -/
@[step]
theorem mlkem.ntt.ntt_avx2.ntt_layer_avx2.spec
    (pe_src : PolyElement) (k len : Std.Usize)
    (h_wf : wfPoly pe_src) (h_len : 16 ≤ len.val) (h_lend : len.val ≤ 128)
    (h_div : 256 % (2 * len.val) = 0)
    (h_len_step : len.val % 16 = 0)
    (h_k : 2 * k.val * len.val + 256 ≤ 256 * len.val) :
    mlkem.ntt.ntt_avx2.ntt_layer_avx2 pe_src k len
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r =
            (nttMidLayer len.val (by grind) 0 k.val (toPoly pe_src)).1 ⦄ := by
  unfold mlkem.ntt.ntt_avx2.ntt_layer_avx2
  step
  step as ⟨i, hi⟩
  simp only [core.iter.traits.iterator.Iterator.step_by.trait_default, core.iter.traits.iterator.Iterator.step_by.default,
    show ¬ (i.val = 0) from by agrind, if_false]
  apply WP.spec_mono
  · apply mlkem.ntt.ntt_avx2.ntt_layer_avx2_loop0.spec
      (iter := ⟨{ start := 0#usize, «end» := 256#usize }, i ⟩)
    · exact h_wf
    · exact h_len
    · exact h_lend
    · exact h_div
    · exact h_len_step
    · show 2 * k.val * len.val + 256 ≤ 256 * len.val + 0; omega
    · rfl
    · show i.val = 2 * len.val; agrind
    · refine ⟨by simp, by simp⟩
  · rintro r ⟨hwf, heq⟩
    exact ⟨hwf, heq⟩


end Symcrust.Properties.MLKEM.Intrinsics
