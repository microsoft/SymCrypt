/-
  Symcrust/Properties/MLKEM/Intrinsics/X86_64/Sse2.lean — `NttIntrinsicsSpec`
  instance for the x86_64 SSE2 (`__m128i`) target.

  ## Surface

  Provides `instance xmmNttIntrinsicsSpec :
    NttIntrinsicsSpec M128 XmmNttInst`,
  bundling the 10 method specs + 3 abstractions of
  `Properties/MLKEM/Intrinsics/TraitSpec.lean` for the extracted
  Aeneas dict `XmmNttInst` (defined in `Code/Funs.lean:13415`).

  ## Status

  **PROVEN — zero algorithm-specific axioms.**  All 10 instance fields
  are theorems.  `vec128_set_u16x8`, `vec128_mod_add`, `vec128_mod_sub`,
  and `vec128_mont_mul` compose the modelled SSE2 lane-op step specs from
  `Intrinsics/Properties/X86_64/Xmm.lean` (zero new silicon axioms).  The
  per-lane modular-arithmetic cores (`mod_add_lane`/`mod_sub_lane`) and the
  Montgomery cores
  (`mont_div_nat`/`mont_carry_nat`/`mont_mul_lane`/`mont_final_lane`) are
  proved by `bv_decide` + Nat/`ZMod` arithmetic.  The 6 load/store methods
  are likewise theorems over their now-transparent extracted bodies (the
  verify shims index the coefficient slice and re-view through
  `words_to_bytes` / `bytes_to_words` — see `src/mlkem/ntt_xmm.rs`).

  ## Trust layering

  See `TraitSpec.lean` § "Trust model" for the shared trust story.
  SSE2-specific: the extracted bodies call `_mm_set1_epi16`,
  `_mm_add_epi16`, `_mm_sub_epi16`, `_mm_loadu_si128`, `_mm_storeu_si128`,
  `_mm_mullo_epi16`, `_mm_mulhi_epu16`, `_mm_cmpgt_epi16`,
  `_mm_andnot_si128`; their generic Layer-1 specs are theorems in
  `Intrinsics/Properties/X86_64/{Sse2,Xmm}.lean`, so they carry no opcode
  axioms.

  ## Proof shape (per field)

  Each `_spec` field is proved by `unfold`ing the Aeneas-extracted
  body (`XmmNttInst.vec128_<op>`), peeling `step` through the named
  silicon calls cited in the per-field informal proof, and closing
  the arithmetic with `bv_decide` / `agrind` per
  `aeneas-tactics-quickref`.  The Montgomery field
  (`vec128_mont_mul_spec`) additionally invokes the scalar `mont_mul`
  spec in `Properties/MLKEM/Ntt/ModArith.lean` lane-by-lane via the
  layer-1 `_mm_mullo_epi16` + `_mm_mulhi_epu16` specs.

  See `Properties/MLKEM/Intrinsics/TraitSpec.lean` for the canonical
  field signatures (and the shared trust model) and
  `Properties/MLKEM/Intrinsics/Vec128LayerNtt.lean` /
  `Vec128LayerIntt.lean` for the parametric `_vec128` loop specs that
  consume this instance.
-/
import Symcrust.Code.Funs
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Intrinsics.TraitSpec
-- `__m128i.u16x8` lane-projection carrier `def`:
import Intrinsics.Axioms.X86_64.Common
-- Layer-1 silicon specs (`verify.intrinsics.x86_64.sse2.*`).  Both
-- the `Intrinsics.Properties.X86_64.Sse2` olean and the
-- transitively-imported `Symcrust.Properties.MLKEM.Bridges.MontArith`
-- olean call `bv_decide`, which auto-emits a public
-- `Aeneas.Std.UScalarTy.enumToBitVec` per olean.  This clash is
-- mitigated by the central realiser `Intrinsics/BVRealize.lean`,
-- which both files import.
import Intrinsics.Properties.X86_64.Sse2
import Intrinsics.Properties.X86_64.Xmm

open Aeneas Aeneas.Std Result
open Symcrust Spec.MLKEM
open symcrust
open Symcrust.Properties.MLKEM
open Intrinsics

namespace Symcrust.Properties.MLKEM.Intrinsics.X86_64

/- Align `get_elem_tactic` with `Intrinsics/Properties/X86_64/{Sse2,Xmm}.lean`
   so the `(↑·.u16x8)[k]` bound proofs in this file's `@[step]` helpers match
   the ones baked into the imported lane-op specs (lets `simp [post]` fire). -/
local macro_rules
| `(tactic| get_elem_tactic) => `(tactic| agrind)

/-- The Aeneas-extracted XMM trait dictionary; alias for clarity.
    Since `src/mlkem/ntt_xmm.rs` redirects the SSE2 lane intrinsics through
    `crate::verify::intrinsics::x86_64::xmm` under `feature = "verify"`
    (the `swap_poc` single-body redirect — see `SymCRust/lean/Intrinsics/INTRINSICS.md` §0 P6),
    the verify carrier is the concrete byte view `M128 = U8x16 = Array U8 16`
    (NOT the opaque silicon `M128`). The dict is a
    `NttIntrinsicsInterface NttIntrinsicsXmm M128` whose lane-op fields are
    the Aeneas-extracted `def`s under
    `...SymcrustMlkemNttNttIntrinsicsInterfaceArrayU816.*` (the three composite
    ops + `set` call the modelled `verify.intrinsics.x86_64.xmm.*` shims; the
    six load/store methods index the coefficient slice and re-view through
    `words_to_bytes` / `bytes_to_words` — transparent `def`s (not
    `#[verify::opaque]`)). -/
@[reducible]
noncomputable def XmmNttInst :
    mlkem.ntt.NttIntrinsicsInterface
      mlkem.ntt.ntt_xmm.NttIntrinsicsXmm
      M128 :=
  mlkem.ntt.ntt_xmm.NttIntrinsicsXmm.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU816

/-- Lane projection for the `M128` byte carrier.  Reuses the canonical
    `Intrinsics.M128.u16x8` lane view (defined in `Intrinsics/Simd.lean`).
    Lane 0 is the low 16 bits. -/
noncomputable def toLanesXmm (v : M128) :
    Vector Std.U16 8 :=
  Vector.ofFn (fun (i : Fin 8) => (M128.u16x8 v)[i.val])

/-- Well-formedness on an `M128`: every `u16` lane is `< q`.  Recast in
    terms of the trait abstraction `toLanesXmm` for direct use in
    `NttIntrinsicsSpec.wfVec_iff`. -/
def wfVecXmm (v : M128) : Prop :=
  ∀ i : Fin 8, (toLanesXmm v)[i.val].val < q

/-- `toLanesXmm` lane `i` is exactly the `M128.u16x8` lane projection used by
    the `Intrinsics/Properties/X86_64/Xmm.lean` step specs. -/
theorem toLanesXmm_getElem (v : M128) (i : Fin 8) :
    (toLanesXmm v)[i.val] = (M128.u16x8 v)[i.val] := by
  simp only [toLanesXmm, Vector.getElem_ofFn]

/-! ### Per-lane modular-arithmetic cores (bit-vector level)

These capture the lane-wise computation of the composite `vec128_mod_*`
SSE2 gadgets over `BitVec 16`, given the `< q` lane bounds.  `mod_add`
uses `cmpgt`+`andnot`; `mod_sub` uses `cmpgt`+`and`. -/

private theorem mod_add_lane (A B R : _root_.BitVec 16)
    (hA : A.toNat < 3329) (hB : B.toNat < 3329)
    (hR : R = (A + B) -
      (~~~(if (3329#16).toInt > (A + B).toInt then 65535#16 else 0#16) &&& 3329#16)) :
    R.toNat < 3329 ∧
    ((R.toNat : ZMod 3329) = (A.toNat : ZMod 3329) + (B.toNat : ZMod 3329)) := by
  have h3329 : (3329#16 : _root_.BitVec 16).toNat = 3329 := by decide
  have hA' : A < 3329#16 := by rw [_root_.BitVec.lt_def, h3329]; exact hA
  have hB' : B < 3329#16 := by rw [_root_.BitVec.lt_def, h3329]; exact hB
  simp only [gt_iff_lt, ← _root_.BitVec.slt_iff_toInt_lt] at hR
  have hboundbv : R < 3329#16 := by rw [hR]; bv_decide
  have hbound : R.toNat < 3329 := by
    have := _root_.BitVec.lt_def.mp hboundbv; rw [h3329] at this; exact this
  have hbv : R = A + B ∨ R + 3329#16 = A + B := by rw [hR]; bv_decide
  have hABnat : A.toNat + B.toNat < 65536 := by scalar_tac
  refine ⟨hbound, ?_⟩
  rcases hbv with h | h
  · have hRnat : R.toNat = A.toNat + B.toNat := by
      rw [h, _root_.BitVec.toNat_add, Nat.mod_eq_of_lt hABnat]
    rw [hRnat]; push_cast; ring
  · have hRnat : R.toNat + 3329 = A.toNat + B.toNat := by
      have hc := congrArg _root_.BitVec.toNat h
      rw [_root_.BitVec.toNat_add, _root_.BitVec.toNat_add, h3329,
        Nat.mod_eq_of_lt (by scalar_tac), Nat.mod_eq_of_lt hABnat] at hc
      exact hc
    have hcast : (R.toNat : ZMod 3329) = ((A.toNat + B.toNat : ℕ) : ZMod 3329) := by
      have h0 : ((3329 : ℕ) : ZMod 3329) = 0 := by decide
      calc (R.toNat : ZMod 3329)
            = ((R.toNat + 3329 : ℕ) : ZMod 3329) := by push_cast [h0]; ring
        _ = ((A.toNat + B.toNat : ℕ) : ZMod 3329) := by rw [hRnat]
    rw [hcast]; push_cast; ring

private theorem mod_sub_lane (A B R : _root_.BitVec 16)
    (hA : A.toNat < 3329) (hB : B.toNat < 3329)
    (hR : R = (A - B) +
      ((if (0#16).toInt > (A - B).toInt then 65535#16 else 0#16) &&& 3329#16)) :
    R.toNat < 3329 ∧
    ((R.toNat : ZMod 3329) = (A.toNat : ZMod 3329) - (B.toNat : ZMod 3329)) := by
  have h3329 : (3329#16 : _root_.BitVec 16).toNat = 3329 := by decide
  have hA' : A < 3329#16 := by rw [_root_.BitVec.lt_def, h3329]; exact hA
  have hB' : B < 3329#16 := by rw [_root_.BitVec.lt_def, h3329]; exact hB
  simp only [gt_iff_lt, ← _root_.BitVec.slt_iff_toInt_lt] at hR
  have hboundbv : R < 3329#16 := by rw [hR]; bv_decide
  have hbound : R.toNat < 3329 := by
    have := _root_.BitVec.lt_def.mp hboundbv; rw [h3329] at this; exact this
  have hbv : R + B = A ∨ R + B = A + 3329#16 := by rw [hR]; bv_decide
  have hRBnat : R.toNat + B.toNat < 65536 := by scalar_tac
  refine ⟨hbound, ?_⟩
  have hkey : (R.toNat : ZMod 3329) + (B.toNat : ZMod 3329) = (A.toNat : ZMod 3329) := by
    rcases hbv with h | h
    · have hn : R.toNat + B.toNat = A.toNat := by
        have hc := congrArg _root_.BitVec.toNat h
        rw [_root_.BitVec.toNat_add, Nat.mod_eq_of_lt hRBnat] at hc; exact hc
      rw [← Nat.cast_add, hn]
    · have hn : R.toNat + B.toNat = A.toNat + 3329 := by
        have hc := congrArg _root_.BitVec.toNat h
        rw [_root_.BitVec.toNat_add, _root_.BitVec.toNat_add, h3329,
          Nat.mod_eq_of_lt hRBnat, Nat.mod_eq_of_lt (by scalar_tac)] at hc
        exact hc
      have h0 : ((3329 : ℕ) : ZMod 3329) = 0 := by decide
      rw [← Nat.cast_add, hn]; push_cast [h0]; ring
  rw [eq_sub_iff_add_eq]; exact hkey

/-! ## Lane-arithmetic specs for the SSE2 NTT intrinsics on `__m128i`

The composite arithmetic ops (`vec128_mod_add`, `vec128_mod_sub`,
`vec128_mont_mul`) have extracted bodies; they are **theorems** here that
compose the proven layer-1 `verify.intrinsics.x86_64.sse2.*` step specs
(`Intrinsics/Properties/X86_64/Sse2.lean`) with the per-lane modular cores
above.  The layer-1 `_mm_*` opcode specs are themselves theorems, so this
path carries no silicon axioms.

The load/store ops (`vec{128,64,32}_{load,store}_u16x*`) are NOT axioms: their
verify shims index the coefficient slice and re-view through
`words_to_bytes` / `bytes_to_words` (no raw pointers — see
`src/mlkem/ntt_xmm.rs`), so Aeneas extracts them as transparent `def`s and the
specs below are theorems over the `M128.u16x8_of_bv` byte→lane bridge (§ below).
The carrier is `__m128i = M128 = [u8; 16]` and the trait shape is
`NttIntrinsicsSpec` (`toLanesXmm`, `wfVecXmm`). -/

private theorem w8_idx_bound (w : Std.Array Std.U16 8#usize) (m : Fin 8) :
    m.val < w.val.length := by
  have h : w.val.length = 8 := w.property; have := m.isLt; omega

/-! ## SSE2 NTT load/store specs on `M128` (byte-carrier redirect)

The load/store methods are now **transparent `def`s** (the verify shims index
the coefficient slice and re-view through `words_to_bytes` / `bytes_to_words`;
no raw pointers — see `src/mlkem/ntt_xmm.rs`).  Each spec is proved by
`unfold + step*` over the extracted body, using `M128.u16x8_of_bv` to upgrade
the `words_to_bytes` / `bytes_to_words` packed-bit-vector post to the
`M128.u16x8` lane view — no silicon axiom. -/

/-- **Spec for `vec128_load_u16x8`** (loads 8 contiguous coefficients). -/
theorem vec128_load_u16x8_spec_xmm :
    ∀ (pe : PolyElement) (idx : Std.Usize)
      (_h_wf : wfPoly pe) (h_idx : idx.val + 8 ≤ 256),
      XmmNttInst.vec128_load_u16x8 pe idx ⦃ v =>
        wfVecXmm v ∧
        ∀ i : Fin 8, (toLanesXmm v)[i.val] = pe.val[idx.val + i.val] ⦄ := by
  intro pe idx hwf hidx
  simp only [
    mlkem.ntt.ntt_xmm.NttIntrinsicsXmm.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU816.vec128_load_u16x8]
  step*
  have hu : M128.u16x8 v = Array.make 8#usize [i, i2, i4, i6, i8, i10, i12, i14] (by simp) :=
    M128.u16x8_of_bv ‹Array.bv v _ = _›
  have hlane : ∀ j : Fin 8, (toLanesXmm v)[j.val]
      = pe.val[idx.val + j.val] := by
    intro j; rw [toLanesXmm_getElem]; simp only [hu]; fin_cases j <;> simp_all [Std.Array.make]
  refine ⟨?_, hlane⟩
  intro j; rw [hlane j]; exact hwf _ (by grind)

/-- **Spec for `vec64_load_u16x4`** (loads 4 coefficients; lanes 4–7 hardware-zeroed). -/
theorem vec64_load_u16x4_spec_xmm :
    ∀ (pe : PolyElement) (idx : Std.Usize)
      (_h_wf : wfPoly pe) (h_idx : idx.val + 4 ≤ 256),
      XmmNttInst.vec64_load_u16x4 pe idx ⦃ v =>
        wfVecXmm v ∧
        ∀ i : Fin 4, (toLanesXmm v)[i.val] = pe.val[idx.val + i.val] ⦄ := by
  intro pe idx hwf hidx
  simp only [
    mlkem.ntt.ntt_xmm.NttIntrinsicsXmm.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU816.vec64_load_u16x4]
  step*
  have hu : M128.u16x8 v = Array.make 8#usize [i, i2, i4, i6, 0#u16, 0#u16, 0#u16, 0#u16] (by simp) :=
    M128.u16x8_of_bv ‹Array.bv v _ = _›
  refine ⟨?_, ?_⟩
  · intro j; rw [toLanesXmm_getElem]; simp only [hu]; fin_cases j <;>
      simp_all [Std.Array.make] <;> first | (apply hwf; grind)
  · intro j; rw [toLanesXmm_getElem _ ⟨j.val, by have := j.isLt; omega⟩]; simp only [hu]
    fin_cases j <;> simp_all [Std.Array.make]

/-- **Spec for `vec32_load_u16x2`** (loads 2 coefficients; lanes 2–7 hardware-zeroed). -/
theorem vec32_load_u16x2_spec_xmm :
    ∀ (pe : PolyElement) (idx : Std.Usize)
      (_h_wf : wfPoly pe) (h_idx : idx.val + 2 ≤ 256),
      XmmNttInst.vec32_load_u16x2 pe idx ⦃ v =>
        wfVecXmm v ∧
        ∀ i : Fin 2, (toLanesXmm v)[i.val] = pe.val[idx.val + i.val] ⦄ := by
  intro pe idx hwf hidx
  simp only [
    mlkem.ntt.ntt_xmm.NttIntrinsicsXmm.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU816.vec32_load_u16x2]
  step*
  have hu : M128.u16x8 v = Array.make 8#usize [i, i2, 0#u16, 0#u16, 0#u16, 0#u16, 0#u16, 0#u16] (by simp) :=
    M128.u16x8_of_bv ‹Array.bv v _ = _›
  refine ⟨?_, ?_⟩
  · intro j; rw [toLanesXmm_getElem]; simp only [hu]; fin_cases j <;>
      simp_all [Std.Array.make] <;> first | (apply hwf; grind)
  · intro j; rw [toLanesXmm_getElem _ ⟨j.val, by have := j.isLt; omega⟩]; simp only [hu]
    fin_cases j <;> simp_all [Std.Array.make]

set_option maxHeartbeats 1000000 in
/-- **Spec for `vec128_store_u16x8`** (writes 8 coefficients to `pe[idx..idx+8]`). -/
theorem vec128_store_u16x8_spec_xmm :
    ∀ (pe : PolyElement) (idx : Std.Usize) (v : M128)
      (_h_wf : wfPoly pe) (_h_idx : idx.val + 8 ≤ 256) (_h_v : wfVecXmm v),
      XmmNttInst.vec128_store_u16x8 pe idx v ⦃ pe' =>
        pe'.val.length = 256 ∧
        wfPoly pe' ∧
        ∀ k : Fin 256,
          pe'.val[k.val] =
            if h : idx.val ≤ k.val ∧ k.val < idx.val + 8
              then (toLanesXmm v)[k.val - idx.val]
              else pe.val[k.val] ⦄ := by
  intro pe idx v hwf hidx hv
  simp only [
    mlkem.ntt.ntt_xmm.NttIntrinsicsXmm.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU816.vec128_store_u16x8]
  step*
  have hu : M128.u16x8 v = w := M128.u16x8_of_bv (by symm; assumption)
  have huw : ∀ m : Fin 8,
      (toLanesXmm v)[m.val] = w.val[m.val]'(w8_idx_bound w m) := by
    intro m
    rw [toLanesXmm_getElem v m]; simp only [hu]; rfl
  have hval : ∀ k : Fin 256,
      pe'.val[k.val] =
        if h : idx.val ≤ k.val ∧ k.val < idx.val + 8
          then (toLanesXmm v)[k.val - idx.val]
          else pe.val[k.val] := by
    intro k
    have hkb := k.isLt
    simp only [pe'_post, elem7_post, elem6_post, elem5_post, elem4_post, elem3_post,
      elem2_post, elem1_post, Std.Array.set_val_eq,
      i_post, i1_post, i3_post, i5_post, i7_post, i9_post, i11_post, i13_post,
      i2_post, i4_post, i6_post, i8_post, i10_post, i12_post, i14_post]
    by_cases hrange : idx.val ≤ k.val ∧ k.val < idx.val + 8
    · rw [dif_pos hrange, huw ⟨k.val - idx.val, by omega⟩]
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
theorem vec64_store_u16x4_spec_xmm :
    ∀ (pe : PolyElement) (idx : Std.Usize) (v : M128)
      (_h_wf : wfPoly pe) (_h_idx : idx.val + 4 ≤ 256)
      (_h_v : ∀ i : Fin 4, (toLanesXmm v)[i.val].val < q),
      XmmNttInst.vec64_store_u16x4 pe idx v ⦃ pe' =>
        pe'.val.length = 256 ∧
        wfPoly pe' ∧
        ∀ k : Fin 256,
          pe'.val[k.val] =
            if h : idx.val ≤ k.val ∧ k.val < idx.val + 4
              then (toLanesXmm v)[k.val - idx.val]
              else pe.val[k.val] ⦄ := by
  intro pe idx v hwf hidx hv
  simp only [
    mlkem.ntt.ntt_xmm.NttIntrinsicsXmm.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU816.vec64_store_u16x4]
  step*
  have hu : M128.u16x8 v = w := M128.u16x8_of_bv (by symm; assumption)
  have huw : ∀ m : Fin 8,
      (toLanesXmm v)[m.val] = w.val[m.val]'(w8_idx_bound w m) := by
    intro m
    rw [toLanesXmm_getElem v m]; simp only [hu]; rfl
  have hval : ∀ k : Fin 256,
      pe'.val[k.val] =
        if h : idx.val ≤ k.val ∧ k.val < idx.val + 4
          then (toLanesXmm v)[k.val - idx.val]
          else pe.val[k.val] := by
    intro k
    have hkb := k.isLt
    simp only [pe'_post, elem3_post, elem2_post, elem1_post, Std.Array.set_val_eq,
      i_post, i1_post, i3_post, i5_post, i2_post, i4_post, i6_post]
    by_cases hrange : idx.val ≤ k.val ∧ k.val < idx.val + 4
    · rw [dif_pos hrange, huw ⟨k.val - idx.val, by omega⟩]
      simp only [List.getElem_set]
      split_ifs <;> first | omega | (fcongr 1; omega)
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
theorem vec32_store_u16x2_spec_xmm :
    ∀ (pe : PolyElement) (idx : Std.Usize) (v : M128)
      (_h_wf : wfPoly pe) (_h_idx : idx.val + 2 ≤ 256)
      (_h_v : ∀ i : Fin 2, (toLanesXmm v)[i.val].val < q),
      XmmNttInst.vec32_store_u16x2 pe idx v ⦃ pe' =>
        pe'.val.length = 256 ∧
        wfPoly pe' ∧
        ∀ k : Fin 256,
          pe'.val[k.val] =
            if h : idx.val ≤ k.val ∧ k.val < idx.val + 2
              then (toLanesXmm v)[k.val - idx.val]
              else pe.val[k.val] ⦄ := by
  intro pe idx v hwf hidx hv
  simp only [
    mlkem.ntt.ntt_xmm.NttIntrinsicsXmm.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU816.vec32_store_u16x2]
  step*
  have hu : M128.u16x8 v = w := M128.u16x8_of_bv (by symm; assumption)
  have huw : ∀ m : Fin 8,
      (toLanesXmm v)[m.val] = w.val[m.val]'(w8_idx_bound w m) := by
    intro m
    rw [toLanesXmm_getElem v m]; simp only [hu]; rfl
  have hval : ∀ k : Fin 256,
      pe'.val[k.val] =
        if h : idx.val ≤ k.val ∧ k.val < idx.val + 2
          then (toLanesXmm v)[k.val - idx.val]
          else pe.val[k.val] := by
    intro k
    have hkb := k.isLt
    simp only [pe'_post, elem1_post, Std.Array.set_val_eq,
      i_post, i1_post, i2_post]
    by_cases hrange : idx.val ≤ k.val ∧ k.val < idx.val + 2
    · rw [dif_pos hrange, huw ⟨k.val - idx.val, by omega⟩]
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

/-- **Spec for `vec128_set_u16x8`** (composes the modelled SSE2 `set1_epi16`). -/
theorem vec128_set_u16x8_spec_xmm :
    ∀ (x : Std.U16),
      XmmNttInst.vec128_set_u16x8 x ⦃ v =>
        ∀ i : Fin 8, (toLanesXmm v)[i.val] = x ⦄ := by
  intro x
  simp only [
    mlkem.ntt.ntt_xmm.NttIntrinsicsXmm.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU816.vec128_set_u16x8]
  step*
  rename_i j
  rw [toLanesXmm_getElem v j]
  apply U16.bv_eq_imp_eq
  have pj : j.val < (M128.u16x8 v).val.length := by have := (M128.u16x8 v).property; grind
  change ((M128.u16x8 v).val[j.val]'pj).bv = x.bv
  have hv : ((M128.u16x8 v).val[j.val]'pj).bv = i.bv := v_post j.val j.isLt
  rw [hv, i_post]
  simp only [UScalar.hcast, IScalar.bv_mk_apply, _root_.BitVec.zeroExtend_eq_setWidth]
  exact _root_.BitVec.setWidth_eq x.bv

/-- **Lane-lift (binary).** Lift a per-lane binary-op correctness fact stated in
    the `M128.u16x8` lane view to the `toLanesXmm` postcondition shared by
    `vec128_mod_add` / `vec128_mod_sub` (factored to avoid copy-pasting the
    `toLanesXmm_getElem` bridging across the gadget proofs). -/
private theorem lift_lanes_binop {a b r : M128} (op : Zq → Zq → Zq)
    (key : ∀ k, (hk : k < 8) →
       (M128.u16x8 r)[k].val < 3329 ∧
       (((M128.u16x8 r)[k].val : Zq) =
         op ((M128.u16x8 a)[k].val : Zq) ((M128.u16x8 b)[k].val : Zq))) :
    wfVecXmm r ∧
    ∀ i : Fin 8, ((toLanesXmm r)[i.val].val : Zq) =
      op ((toLanesXmm a)[i.val].val : Zq) ((toLanesXmm b)[i.val].val : Zq) := by
  refine ⟨fun i => ?_, fun i => ?_⟩
  · rw [toLanesXmm_getElem r i]; exact (key i.val i.isLt).1
  · rw [toLanesXmm_getElem r i, toLanesXmm_getElem a i, toLanesXmm_getElem b i]
    exact (key i.val i.isLt).2

/-- **Lane-lift (unary).** Unary analogue of `lift_lanes_binop`, used by the
    relaxed `vec128_mod_sub_2q` final-reduction spec (result depends only on `a`). -/
private theorem lift_lanes_unop {a r : M128} (op : Zq → Zq)
    (key : ∀ k, (hk : k < 8) →
       (M128.u16x8 r)[k].val < 3329 ∧
       (((M128.u16x8 r)[k].val : Zq) = op ((M128.u16x8 a)[k].val : Zq))) :
    wfVecXmm r ∧
    ∀ i : Fin 8, ((toLanesXmm r)[i.val].val : Zq) = op ((toLanesXmm a)[i.val].val : Zq) := by
  refine ⟨fun i => ?_, fun i => ?_⟩
  · rw [toLanesXmm_getElem r i]; exact (key i.val i.isLt).1
  · rw [toLanesXmm_getElem r i, toLanesXmm_getElem a i]
    exact (key i.val i.isLt).2

/-- **Spec for `vec128_mod_add`** (composes the modelled SSE2 lane ops). -/
theorem vec128_mod_add_spec_xmm :
    ∀ (a b : M128), wfVecXmm a → wfVecXmm b →
      XmmNttInst.vec128_mod_add a b ⦃ r =>
        wfVecXmm r ∧
        ∀ i : Fin 8,
          ((toLanesXmm r)[i.val].val : Zq) =
            ((toLanesXmm a)[i.val].val : Zq) + ((toLanesXmm b)[i.val].val : Zq) ⦄ := by
  intro a b ha hb
  simp only [
    mlkem.ntt.ntt_xmm.NttIntrinsicsXmm.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU816.vec128_mod_add,
    mlkem.ntt.ntt_xmm.NttIntrinsicsXmm.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU816.vec128_set_u16x8]
  step*
  have hQbv : mlkem.ntt.Q.bv = 3329#32 := by unfold mlkem.ntt.Q; rfl
  have hx : x.bv = 3329#16 := by
    rw [x_post, i_post]
    simp only [UScalar.hcast, UScalar.cast, IScalar.bv_mk_apply, UScalar.bv_mk_apply, hQbv]
    decide
  let a' := M128.u16x8 a
  let b' := M128.u16x8 b
  let r' := M128.u16x8 r
  have key : ∀ k, (hk : k < 8) →
      r'[k].val < 3329 ∧
      (r'[k].val : ZMod 3329) = (a'[k].val : ZMod 3329) + (b'[k].val : ZMod 3329) := by
    intro k hk
    have hA : a'[k].val < 3329 := by
      have h := ha ⟨k, hk⟩; rw [toLanesXmm_getElem a ⟨k, hk⟩] at h; exact h
    have hB : b'[k].val < 3329 := by
      have h := hb ⟨k, hk⟩; rw [toLanesXmm_getElem b ⟨k, hk⟩] at h; exact h
    have hR : r'[k].bv =
        (a'[k].bv + b'[k].bv) -
        (~~~(if (3329#16).toInt > (a'[k].bv + b'[k].bv).toInt
            then 65535#16 else 0#16) &&& 3329#16) := by
      simp only [a', b', r', r_post k hk, v_res_post k hk, v_tmp11_post k hk, v_tmp1_post k hk,
        v_q_post k hk, hx, core.num.U16.wrapping_sub_bv_eq, core.num.U16.wrapping_add_bv_eq,
        UScalar.bv_and, UScalar.bv_not, apply_ite (fun u : U16 => u.bv),
        show (65535#u16 : U16).bv = 65535#16 from rfl, show (0#u16 : U16).bv = 0#16 from rfl]
    have hlane := mod_add_lane _ _ _ hA hB hR
    exact ⟨hlane.1, hlane.2⟩
  exact lift_lanes_binop (· + ·) key

/-- A `@[step]`-usable spec for the extracted `vec128_set_u16x8` dict method,
    in the `M128.u16x8` lane-bv form (so composite proofs need not unfold it
    nor name its internal `hcast` variable). -/
@[step] theorem vec128_set_u16x8_bv (val : Std.U16) :
    mlkem.ntt.ntt_xmm.NttIntrinsicsXmm.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU816.vec128_set_u16x8 val
    ⦃ (v : M128) => ∀ k, (hk : k < 8) →
        (M128.u16x8 v)[k].bv = (UScalar.hcast IScalarTy.I16 val).bv ⦄ := by
  unfold mlkem.ntt.ntt_xmm.NttIntrinsicsXmm.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU816.vec128_set_u16x8
  step*
  rename_i k
  have h := v_post1 k v_post2
  rw [i_post] at h
  exact h

/-- **Spec for `vec128_mod_sub`** (composes the modelled SSE2 lane ops). -/
theorem vec128_mod_sub_spec_xmm :
    ∀ (a b : M128), wfVecXmm a → wfVecXmm b →
      XmmNttInst.vec128_mod_sub a b ⦃ r =>
        wfVecXmm r ∧
        ∀ i : Fin 8,
          ((toLanesXmm r)[i.val].val : Zq) =
            ((toLanesXmm a)[i.val].val : Zq) - ((toLanesXmm b)[i.val].val : Zq) ⦄ := by
  intro a b ha hb
  simp only [
    mlkem.ntt.ntt_xmm.NttIntrinsicsXmm.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU816.vec128_mod_sub]
  step*
  have hQbv : mlkem.ntt.Q.bv = 3329#32 := by unfold mlkem.ntt.Q; rfl
  have hx : (UScalar.hcast IScalarTy.I16 i).bv = 3329#16 := by
    rw [i_post]
    simp only [UScalar.hcast, UScalar.cast, IScalar.bv_mk_apply, UScalar.bv_mk_apply, hQbv]
    decide
  have hx0 : (UScalar.hcast IScalarTy.I16 0#u16).bv = 0#16 := by
    simp only [UScalar.hcast, IScalar.bv_mk_apply]; decide
  let a' := M128.u16x8 a
  let b' := M128.u16x8 b
  let r' := M128.u16x8 r
  have key : ∀ k, (hk : k < 8) →
      r'[k].val < 3329 ∧
      (r'[k].val : ZMod 3329) =
        (a'[k].val : ZMod 3329) -
        (b'[k].val : ZMod 3329) := by
    intro k hk
    have hA : a'[k].val < 3329 := by
      have h := ha ⟨k, hk⟩; rw [toLanesXmm_getElem a ⟨k, hk⟩] at h; exact h
    have hB : (b'[k]).bv.toNat < 3329 := by
      have h := hb ⟨k, hk⟩; rw [toLanesXmm_getElem b ⟨k, hk⟩] at h; exact h
    have hR : (r'[k]).bv =
        (a'[k].bv - b'[k].bv) +
        ((if (0#16).toInt > (a'[k].bv - b'[k].bv).toInt
            then 65535#16 else 0#16) &&& 3329#16) := by
      simp only [a', b', r', r_post k hk, v_res_post k hk, v_tmp11_post k hk, v_tmp1_post k hk,
        v_q_post k hk, v_zero_post k hk, hx, hx0, core.num.U16.wrapping_add_bv_eq,
        core.num.U16.wrapping_sub_bv_eq, UScalar.bv_and, apply_ite (fun u : U16 => u.bv),
        show (65535#u16 : U16).bv = 65535#16 from rfl, show (0#u16 : U16).bv = 0#16 from rfl]
    have hlane := mod_sub_lane _ _ _ hA hB hR
    exact ⟨hlane.1, hlane.2⟩
  exact lift_lanes_binop (· - ·) key

/-! ### Per-lane Montgomery-multiplication arithmetic cores -/

/-- Montgomery divisibility at the Nat level: `A·B + m·q ≡ 0 (mod 2^16)` where
    `m = (A·B·3327) mod 2^16` (companion `1 + 3327·3329 = 169·2^16`). -/
private theorem mont_div_nat (A B : Nat) :
    (A * B + (A * B * 3327 % 65536) * 3329) % 65536 = 0 := by
  conv_lhs => rw [Nat.add_mod]
  have hinner : (A * B * 3327 % 65536 * 3329) % 65536 = (A * B * 3327 * 3329) % 65536 := by
    conv_lhs => rw [Nat.mul_mod, Nat.mod_mod_of_dvd _ (dvd_refl 65536), ← Nat.mul_mod]
  rw [hinner, ← Nat.add_mod]
  have h : A * B + A * B * 3327 * 3329 = A * B * 169 * 65536 := by ring
  rw [h]; simp [Nat.mul_mod_left]

/-- The SIMD high/low-split result equals the Montgomery reduction value:
    `mulhi(A·B) + mulhi(m·q) + [m ≠ 0] = (A·B + m·q) / 2^16` (`m` as above). -/
private theorem mont_carry_nat (A B : Nat) :
    A * B / 65536 + (A * B * 3327 % 65536) * 3329 / 65536
      + (if A * B * 3327 % 65536 = 0 then 0 else 1)
      = (A * B + (A * B * 3327 % 65536) * 3329) / 65536 := by
  set m := A * B * 3327 % 65536 with hm
  have hdiv : (A * B + m * 3329) % 65536 = 0 := mont_div_nat A B
  have hsum : (A * B % 65536 + m * 3329 % 65536) % 65536 = 0 := by
    rw [← Nat.add_mod]; exact hdiv
  have hrab : A * B % 65536 < 65536 := Nat.mod_lt _ (by decide)
  have hrmq : m * 3329 % 65536 < 65536 := Nat.mod_lt _ (by decide)
  have hAB := Nat.div_add_mod (A * B) 65536
  have hmq := Nat.div_add_mod (m * 3329) 65536
  by_cases hm0 : m = 0
  · simp only [hm0]; grind
  · simp only [hm0, if_neg, not_false_iff]
    have hmlt : m < 65536 := by rw [hm]; exact Nat.mod_lt _ (by decide)
    have hrmq_ne : m * 3329 % 65536 ≠ 0 := by
      intro hz
      have hdvd : (65536 : Nat) ∣ m * 3329 := Nat.dvd_of_mod_eq_zero hz
      have hcop : Nat.Coprime 65536 3329 := by decide
      have hmd : (65536 : Nat) ∣ m := Nat.Coprime.dvd_of_dvd_mul_right hcop hdvd
      have := Nat.le_of_dvd (by grind) hmd
      grind
    -- residue sum is divisible by 65536, positive, and < 2·65536 ⟹ equals 65536
    have hrsum : A * B % 65536 + m * 3329 % 65536 = 65536 := by grind
    grind

/-- Per-lane Montgomery correctness: the reduction value `t = (A·B + m·q)/2^16`
    (`m = A·B·3327 mod 2^16`) is `< 2q` and equals `A·B·R⁻¹` in `Z_q`. -/
private theorem mont_mul_lane (A B : Nat) (hA : A < 3329) (hB : B < 3329) :
    (A * B + (A * B * 3327 % 65536) * 3329) / 65536 < 6658 ∧
    (((A * B + (A * B * 3327 % 65536) * 3329) / 65536 : ℕ) : ZMod 3329)
      = (A : ZMod 3329) * (B : ZMod 3329) * Rinv := by
  set m := A * B * 3327 % 65536 with hm_def
  set N := A * B + m * 3329 with hN_def
  have hdvd : (65536 : ℕ) ∣ N := Nat.dvd_of_mod_eq_zero (by rw [hN_def, hm_def]; exact mont_div_nat A B)
  obtain ⟨t, hNt⟩ := hdvd
  have ht : N / 65536 = t := by rw [hNt]; exact Nat.mul_div_cancel_left t (by decide)
  rw [ht]
  have hmle : m ≤ 65535 := by rw [hm_def]; exact Nat.le_of_lt_succ (Nat.mod_lt _ (by decide))
  have hABle : A * B ≤ 3328 * 3328 := Nat.mul_le_mul (by grind) (by grind)
  refine ⟨?_, ?_⟩
  · have hNlt : 65536 * t < 65536 * 6658 := by
      rw [← hNt, hN_def]
      calc A * B + m * 3329 ≤ 3328 * 3328 + 65535 * 3329 :=
              Nat.add_le_add hABle (Nat.mul_le_mul_right _ hmle)
        _ < 65536 * 6658 := by decide
    exact Nat.lt_of_mul_lt_mul_left hNlt
  · have hNcast_q : ((N : ℕ) : ZMod 3329) = (A : ZMod 3329) * (B : ZMod 3329) := by
      rw [hN_def]; push_cast; ring
    have hNcast_R : ((N : ℕ) : ZMod 3329) = (65536 : ZMod 3329) * (t : ZMod 3329) := by
      rw [hNt]; push_cast; ring
    have hR1 : (65536 : ZMod 3329) * Rinv = 1 := by unfold Rinv; decide
    rw [hNcast_R] at hNcast_q
    calc (t : ZMod 3329)
        = (65536 * Rinv) * t := by rw [hR1]; ring
      _ = Rinv * (65536 * t) := by ring
      _ = Rinv * ((A : ZMod 3329) * (B : ZMod 3329)) := by rw [hNcast_q]
      _ = (A : ZMod 3329) * (B : ZMod 3329) * Rinv := by ring

/-- Final canonical reduction lane: for `X ∈ [0, 2q)`, the `mod_sub`-by-`q`
    gadget yields `X mod q` (in `[0, q)`, congruent to `X`). -/
private theorem mont_final_lane (X R : _root_.BitVec 16) (hX : X.toNat < 6658)
    (hR : R = (X - 3329#16) +
      ((if (0#16).toInt > (X - 3329#16).toInt then 65535#16 else 0#16) &&& 3329#16)) :
    R.toNat < 3329 ∧ ((R.toNat : ZMod 3329) = (X.toNat : ZMod 3329)) := by
  have h6658 : (6658#16 : _root_.BitVec 16).toNat = 6658 := by decide
  have hX' : X < 6658#16 := by rw [_root_.BitVec.lt_def, h6658]; exact hX
  simp only [gt_iff_lt, ← _root_.BitVec.slt_iff_toInt_lt] at hR
  have h3329 : (3329#16 : _root_.BitVec 16).toNat = 3329 := by decide
  have hbound : R < 3329#16 := by rw [hR]; bv_decide
  have hRlt : R.toNat < 3329 := by
    have := _root_.BitVec.lt_def.mp hbound; rw [h3329] at this; exact this
  refine ⟨hRlt, ?_⟩
  have hcase : R = X ∨ R + 3329#16 = X := by rw [hR]; bv_decide
  rcases hcase with h | h
  · rw [h]
  · have hn : R.toNat + 3329 = X.toNat := by
      have hc := congrArg _root_.BitVec.toNat h
      rw [_root_.BitVec.toNat_add, h3329, Nat.mod_eq_of_lt (by scalar_tac)] at hc
      exact hc
    have h0 : ((3329 : ℕ) : ZMod 3329) = 0 := ZMod.natCast_self 3329
    calc ((R.toNat : ℕ) : ZMod 3329)
        = ((R.toNat + 3329 : ℕ) : ZMod 3329) := by push_cast [h0]; ring
      _ = ((X.toNat : ℕ) : ZMod 3329) := by rw [hn]

/-- No-wrap collapse of the three `add_epi16` lanes in `vec128_mont_mul`:
    `hab ≤ 169`, `hmq ≤ 3328`, mask `tmp2 ∈ {0, 65535}`. -/
private theorem mont_res3_collapse (hab hmq tmp2 : Nat)
    (hhab : hab ≤ 169) (hhmq : hmq ≤ 3328) (htmp2 : tmp2 = 65535 ∨ tmp2 = 0) :
    (((hab + 1) % 65536 + tmp2) % 65536 + hmq) % 65536
      = hab + hmq + (if tmp2 = 0 then 1 else 0) := by
  rcases htmp2 with h | h <;> subst h <;> grind

private theorem u16_wadd_val (x y : Std.U16) :
    (core.num.U16.wrapping_add x y).val = (x.val + y.val) % 65536 := by
  show (core.num.U16.wrapping_add x y).bv.toNat = _
  rw [core.num.U16.wrapping_add_bv_eq, _root_.BitVec.toNat_add]; rfl

private theorem u16_wmul_val (x y : Std.U16) :
    (core.num.U16.wrapping_mul x y).val = (x.val * y.val) % 65536 := by
  show (core.num.U16.wrapping_mul x y).bv.toNat = _
  rw [core.num.U16.wrapping_mul_bv_eq, _root_.BitVec.toNat_mul]; rfl

/- Note: the store proof is triplicated — the
   nested-`set` → range-conditional + `wfPoly` + length logic is copy-pasted
   across `vec128/64/32_store` here (and again in the NEON / AVX2 siblings).
   The real dedup would be one generic `Intrinsics/`-level lemma — "writing
   values `f 0 .. f (n-1)` into `l[idx .. idx+n]` yields the range-conditional
   `fun k => if idx ≤ k < idx+n then f (k-idx) else l[k]`" — invoked by all
   three. -/

/-- Relaxed `vec128_mod_sub`: with `a` lanes in `[0, 2q)` and `b` lanes `= q`,
    the gadget canonicalises `a` into `[0, q)` (the final Montgomery reduction). -/
private theorem vec128_mod_sub_2q.spec (a b : M128)
    (ha : ∀ i : Fin 8, (toLanesXmm a)[i.val].val < 6658)
    (hb : ∀ i : Fin 8, (toLanesXmm b)[i.val].val = 3329) :
    XmmNttInst.vec128_mod_sub a b ⦃ r =>
      wfVecXmm r ∧
      ∀ i : Fin 8,
        ((toLanesXmm r)[i.val].val : ZMod 3329) =
          ((toLanesXmm a)[i.val].val : ZMod 3329) ⦄ := by
  simp only [
    mlkem.ntt.ntt_xmm.NttIntrinsicsXmm.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU816.vec128_mod_sub]
  step*
  have hQbv : mlkem.ntt.Q.bv = 3329#32 := by unfold mlkem.ntt.Q; rfl
  have hx : (UScalar.hcast IScalarTy.I16 i).bv = 3329#16 := by
    rw [i_post]
    simp only [UScalar.hcast, UScalar.cast, IScalar.bv_mk_apply, UScalar.bv_mk_apply, hQbv]
    decide
  have hx0 : (UScalar.hcast IScalarTy.I16 0#u16).bv = 0#16 := by
    simp only [UScalar.hcast, IScalar.bv_mk_apply]; decide
  let a' := M128.u16x8 a
  let b' := M128.u16x8 b
  let r' := M128.u16x8 r
  have key : ∀ k, (hk : k < 8) →
      r'[k].val < 3329 ∧
      (r'[k].val : ZMod 3329) = (a'[k].val : ZMod 3329) := by
    intro k hk
    have hX : (a'[k]).bv.toNat < 6658 := by
      have h := ha ⟨k, hk⟩; rw [toLanesXmm_getElem a ⟨k, hk⟩] at h; exact h
    have hBbv : (b'[k]).bv = 3329#16 := by
      have h := hb ⟨k, hk⟩; rw [toLanesXmm_getElem b ⟨k, hk⟩] at h
      have hBeq : b'[k] = (3329#u16 : Std.U16) := by
        apply UScalar.eq_of_val_eq; rw [h]; decide
      rw [hBeq]; decide
    have hR : (r'[k]).bv =
        (a'[k].bv - 3329#16) + ((if (0#16).toInt >
              (a'[k].bv - 3329#16).toInt
            then 65535#16 else 0#16) &&& 3329#16) := by
      simp only [a', b', r', r_post k hk, v_res_post k hk, v_tmp11_post k hk, v_tmp1_post k hk,
        v_q_post k hk, v_zero_post k hk, hx, hx0, hBbv, core.num.U16.wrapping_add_bv_eq,
        core.num.U16.wrapping_sub_bv_eq, UScalar.bv_and, apply_ite (fun u : U16 => u.bv),
        show (65535#u16 : U16).bv = 65535#16 from rfl, show (0#u16 : U16).bv = 0#16 from rfl]
    have hlane := mont_final_lane _ _ hX hR
    exact ⟨hlane.1, hlane.2⟩
  exact lift_lanes_unop id key

set_option maxHeartbeats 1600000 in
/-- **Spec for `vec128_mont_mul`** (lane-wise Montgomery multiplication).

    Proved lane-by-lane: the SIMD high/low-split (`mulhi`/`mullo`) Montgomery
    reduction is connected to the pure `mont_reduce.spec` via `mont_carry_nat`. -/
theorem vec128_mont_mul_spec_xmm :
    ∀ (a b b_mont : M128),
      wfVecXmm a → wfVecXmm b →
      (∀ i : Fin 8,
        ((toLanesXmm b_mont)[i.val].val : ℕ) =
          ((toLanesXmm b)[i.val].val * 3327) % 65536) →
      XmmNttInst.vec128_mont_mul a b b_mont ⦃ r =>
        wfVecXmm r ∧
        ∀ i : Fin 8,
          ((toLanesXmm r)[i.val].val : Zq) =
            ((toLanesXmm a)[i.val].val : Zq) *
            ((toLanesXmm b)[i.val].val : Zq) * Rinv ⦄ := by
  intro a b b_mont ha hb hbm
  simp only [
    mlkem.ntt.ntt_xmm.NttIntrinsicsXmm.Insts.SymcrustMlkemNttNttIntrinsicsInterfaceArrayU816.vec128_mont_mul]
  step*
  have hQbv : mlkem.ntt.Q.bv = 3329#32 := by unfold mlkem.ntt.Q; rfl
  have hvq_all : ∀ k, (hk : k < 8) → (M128.u16x8 v_q)[k].val = 3329 := by
    intro k hk
    have h := v_q_post k hk; rw [i_post] at h
    have hbv : (M128.u16x8 v_q)[k].bv = 3329#16 := by
      rw [h]; simp only [UScalar.hcast, UScalar.cast, IScalar.bv_mk_apply, UScalar.bv_mk_apply, hQbv]; decide
    show (M128.u16x8 v_q)[k].bv.toNat = 3329
    rw [hbv]; decide
  let a' := M128.u16x8 a
  let b' := M128.u16x8 b
  have key : ∀ k, (hk : k < 8) →
      (M128.u16x8 v_res3)[k].val < 6658 ∧
      ((M128.u16x8 v_res3)[k].val : ZMod 3329) =
        (a'[k].val : ZMod 3329) * (b'[k].val : ZMod 3329) * Rinv := by
    intro k hk
    set A := a'[k].val with hA_def
    set B := b'[k].val with hB_def
    have hAlt : A < 3329 := by
      have h := ha ⟨k, hk⟩; rwa [toLanesXmm_getElem a ⟨k, hk⟩] at h
    have hBlt : B < 3329 := by
      have h := hb ⟨k, hk⟩; rwa [toLanesXmm_getElem b ⟨k, hk⟩] at h
    have hBM : (M128.u16x8 b_mont)[k].val = (B * 3327) % 65536 := by
      have h := hbm ⟨k, hk⟩
      rw [toLanesXmm_getElem b_mont ⟨k, hk⟩, toLanesXmm_getElem b ⟨k, hk⟩] at h; exact h
    have hvq_k : (M128.u16x8 v_q)[k].val = 3329 := hvq_all k hk
    have hvzero_k : (M128.u16x8 v_zero)[k].val = 0 := by
      have h := v_zero_post k hk
      have hbv : (M128.u16x8 v_zero)[k].bv = 0#16 := by
        rw [h]; simp only [UScalar.hcast, IScalar.bv_mk_apply]; decide
      show (M128.u16x8 v_zero)[k].bv.toNat = 0
      rw [hbv]; decide
    have hvone_k : (M128.u16x8 v_one)[k].val = 1 := by
      have h := v_one_post k hk
      have hbv : (M128.u16x8 v_one)[k].bv = 1#16 := by
        rw [h]; simp only [UScalar.hcast, IScalar.bv_mk_apply]; decide
      show (M128.u16x8 v_one)[k].bv.toNat = 1
      rw [hbv]; decide
    have hvres : (M128.u16x8 v_res)[k].val = A * B / 65536 := v_res_post k hk
    have hvtmp1 : (M128.u16x8 v_tmp1)[k].val = (A * B * 3327) % 65536 := by
      rw [v_tmp1_post k hk, u16_wmul_val, hBM]
      conv_lhs => rw [Nat.mul_mod, Nat.mod_mod_of_dvd _ (dvd_refl 65536), ← Nat.mul_mod]
      rw [show A * (B * 3327) = A * B * 3327 from by ring]
    have hvtmp2 : (M128.u16x8 v_tmp2)[k].val =
        if (A * B * 3327) % 65536 = 0 then 65535 else 0 := by
      rw [v_tmp2_post k hk]
      by_cases hc : (M128.u16x8 v_tmp1)[k] = (M128.u16x8 v_zero)[k]
      · rw [if_pos hc]
        have hm0 : (A * B * 3327) % 65536 = 0 := by rw [← hvtmp1, hc, hvzero_k]
        rw [if_pos hm0]; decide
      · rw [if_neg hc]
        have hm0 : (A * B * 3327) % 65536 ≠ 0 := by
          intro h; apply hc; apply UScalar.eq_of_val_eq
          rw [hvzero_k, hvtmp1]; exact h
        rw [if_neg hm0]; decide
    have hvtmp11 : (M128.u16x8 v_tmp11)[k].val = ((A * B * 3327) % 65536) * 3329 / 65536 := by
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
    have hvres3 : (M128.u16x8 v_res3)[k].val =
        A * B / 65536 + ((A * B * 3327) % 65536) * 3329 / 65536
          + (if (A * B * 3327) % 65536 = 0 then 0 else 1) := by
      rw [v_res3_post k hk, u16_wadd_val, v_res2_post k hk, u16_wadd_val,
          v_res1_post k hk, u16_wadd_val, hvres, hvone_k, hvtmp2, hvtmp11]
      rw [mont_res3_collapse _ _ _ hhab hhmq (by by_cases h : (A*B*3327)%65536 = 0 <;> simp [h])]
      by_cases hm0 : (A * B * 3327) % 65536 = 0 <;> simp [hm0]
    rw [hvres3, mont_carry_nat A B]
    exact mont_mul_lane A B hAlt hBlt
  have hvq_fin : ∀ i : Fin 8, (toLanesXmm v_q)[i.val].val = 3329 := by
    intro i; rw [toLanesXmm_getElem v_q i]; exact hvq_all i.val i.isLt
  have hv3_fin : ∀ i : Fin 8, (toLanesXmm v_res3)[i.val].val < 6658 := by
    intro i; rw [toLanesXmm_getElem v_res3 i]; exact (key i.val i.isLt).1
  have hfin := vec128_mod_sub_2q.spec v_res3 v_q hv3_fin hvq_fin
  obtain ⟨y, hy_eq, hy_wf, hy_zq⟩ := WP.spec_imp_exists hfin
  apply WP.exists_imp_spec
  refine ⟨y, hy_eq, hy_wf, fun i => ?_⟩
  rw [hy_zq i, toLanesXmm_getElem v_res3 i, toLanesXmm_getElem a i, toLanesXmm_getElem b i]
  exact (key i.val i.isLt).2

/-- The `NttIntrinsicsSpec` instance for x86_64 SSE2.

    Each field is discharged by the corresponding `vec128_*_spec_xmm`
    theorem proved above. -/
noncomputable instance xmmNttIntrinsicsSpec :
    NttIntrinsicsSpec M128 XmmNttInst where

  toLanes := toLanesXmm
  wfVec := wfVecXmm

  /- INFORMAL PROOF.  Definitional unfolding: `wfVecXmm` is defined
     exactly as `∀ i : Fin 8, (toLanesXmm v)[i.val].val < q`, which is
     the RHS of the iff.  Proof: `Iff.rfl` or `by intro v; rfl`. -/
  wfVec_iff := fun _ => Iff.rfl

  /- INFORMAL PROOF.  Unfold `XmmNttInst.vec128_load_u16x8` (now a
     transparent `def` in `Code/Funs.lean` — the verify shim indexes the
     coefficient slice and re-views the 16-byte window as a `__m128i`).
     Apply the layer-1 spec
     `verify.intrinsics.x86_64.sse2.loadu_si128_u8.spec` from
     `Intrinsics/Properties/X86_64/Sse2.lean` (it converts a
     16-byte window starting at `&pe.val[idx]` into a `__m128i` whose
     `u8x16` view equals those bytes LE-packed).  The `toLanesXmm`
     equality follows by `__m128i.u16x8`'s definition (reinterpret
     bytes 2k..2k+1 as the k-th `u16` lane, LE).  `wfVec` follows
     pointwise from `wfPoly pe ∧ idx + 8 ≤ 256`. -/
  vec128_load_u16x8_spec := vec128_load_u16x8_spec_xmm

  /- INFORMAL PROOF.  Same as `vec128_load_u16x8_spec` but on a
     64-bit window (4 lanes).  Layer-1 spec:
     `verify.intrinsics.x86_64.sse2.loadu_si64.spec` (loads lanes 0-3 from `pe[idx..]`;
     lanes 4-7 of the result are unspecified, so post quantifies only
     over `i : Fin 4`).  The `< q` bound on lanes 0-3 comes from
     `wfPoly pe`. -/
  vec64_load_u16x4_spec := vec64_load_u16x4_spec_xmm

  /- INFORMAL PROOF.  Analogous to `vec64_load_u16x4_spec` for 2 lanes.
     Underlying intrinsic: `_mm_loadu_si32` (loads 4 bytes = 2 `u16`
     lanes).  Layer-1 spec: `verify.intrinsics.x86_64.sse2.loadu_si128_u32.spec`
     specialised to width 32. -/
  vec32_load_u16x2_spec := vec32_load_u16x2_spec_xmm

  /- INFORMAL PROOF.  Unfold `XmmNttInst.vec128_store_u16x8` (one-line
     shim around `_mm_storeu_si128`).  Layer-1 spec:
     `verify.intrinsics.x86_64.sse2.store_si128.spec` — writes 16 bytes at
     `&pe.val[idx]`.  The `pe.val.length = 256` invariant is preserved
     (length-zip).  The frame conjunct (`if k in [idx, idx+8) then
     toLanesXmm v else pe.val[k]`) follows by case-split on `k`:
     in-window — by the layer-1 store spec; out-of-window — bytes
     untouched.  `wfPoly pe'` follows from `wfPoly pe` (untouched
     lanes) + `wfVec v` (touched lanes). -/
  vec128_store_u16x8_spec := vec128_store_u16x8_spec_xmm

  /- INFORMAL PROOF.  Analogous to `vec128_store_u16x8_spec` for a
     64-bit window (4 lanes).  Layer-1 spec:
     `verify.intrinsics.x86_64.sse2.storeu_si64.spec` writes 8 bytes (lanes 0-3 of
     `v`).  Lanes 4-7 of `v` are NOT read, so the precondition needs
     only the partial `wfVec` (`∀ i : Fin 4, …`). -/
  vec64_store_u16x4_spec := vec64_store_u16x4_spec_xmm

  /- INFORMAL PROOF.  Analogous to `vec64_store_u16x4_spec` for 2 lanes.
     Underlying intrinsic: `_mm_storeu_si32` (writes 4 bytes). -/
  vec32_store_u16x2_spec := vec32_store_u16x2_spec_xmm

  /- INFORMAL PROOF.  Unfold `XmmNttInst.vec128_set_u16x8` (one-line
     shim around `_mm_set1_epi16`).  Layer-1 spec:
     `verify.intrinsics.x86_64.sse2.set1_epi16.spec` — all 8 `u16` lanes equal `x`.
     `wfVec` then follows from `x.val < q` (the precondition). -/
  vec128_set_u16x8_spec := vec128_set_u16x8_spec_xmm

  /- INFORMAL PROOF.  Body composition (from `Code/Funs.lean:13351`
     for the legacy NttIntrinsicsInterface__m128i.vec128_mod_add):

     ```
     vec128_mod_add a b =
       let q_vec ← set1_epi16 q
       let sum   ← add_epi16 a b
       let mask  ← cmpgt_epi16 sum q_vec   -- 0xFFFF where sum > q
       let corr  ← and_si128 mask q_vec
       sub_epi16 sum corr
     ```

     Composition chain (lane-wise, using layer-1 specs from
     `Sse2.lean`):
       lane k of `result`
         = (a[k].val + b[k].val) - (if a[k]+b[k] > q then q else 0)  (mod 2^16)
         = (a[k].val + b[k].val) mod q                                (in Zq)

     Bounds: since `wfVec a ∧ wfVec b`, `a[k]+b[k] < 2q < 2^16`, so
     the `+` doesn't overflow; the corrective subtract gives a result
     in `[0, q)`, establishing `wfVec result`.

     Layer-1 specs invoked: `verify.intrinsics.x86_64.sse2.set1_epi16.spec`, `verify.intrinsics.x86_64.sse2.add_epi16.spec`,
     `verify.intrinsics.x86_64.sse2.cmpgt_epi16.spec`, `verify.intrinsics.x86_64.sse2.and_si128.spec`, `verify.intrinsics.x86_64.sse2.sub_epi16.spec`. -/
  vec128_mod_add_spec := vec128_mod_add_spec_xmm

  /- INFORMAL PROOF.  Symmetric to `vec128_mod_add_spec`, body:

     ```
     vec128_mod_sub a b =
       let q_vec  ← set1_epi16 q
       let zero   ← set1_epi16 0
       let diff   ← sub_epi16 a b           -- in 2's complement: may wrap
       let mask   ← cmpgt_epi16 zero diff   -- 0xFFFF where diff < 0
       let corr   ← and_si128 mask q_vec
       add_epi16 diff corr
     ```

     Lane-wise: `(a[k] - b[k]) + (if a[k]<b[k] then q else 0)` in
     2's-complement `u16` arithmetic.  Since `wfVec a ∧ wfVec b`, the
     "if" branch lifts the result into `[0, q)`.  Same layer-1 spec
     palette as `vec128_mod_add_spec`. -/
  vec128_mod_sub_spec := vec128_mod_sub_spec_xmm

  /- INFORMAL PROOF.  Montgomery reduction, lane-wise.  Body (from
     `Code/Funs.lean` Aeneas extraction):

     ```
     vec128_mont_mul a b b_mont =
       let q_vec ← set1_epi16 q
       let hi    ← mulhi_epu16 a b           -- ⌊a·b / 2^16⌋  (lane-wise)
       let lo    ← mullo_epi16 a b_mont      -- (a · b_mont) mod 2^16
       let m     ← mulhi_epu16 lo q_vec      -- ⌊lo·q / 2^16⌋
       let res1  ← sub_epi16 hi m            -- = hi - m
       -- conditional correction by q:
       let zero  ← set1_epi16 0
       let mask  ← cmpgt_epi16 zero res1
       let corr  ← and_si128 mask q_vec
       add_epi16 res1 corr
     ```

     Algebra (lane k): given `b_mont[k] ≡ b[k] · (−q⁻¹) (mod 2^16)`
     (the precondition), the standard Montgomery argument gives
       `(hi[k] − m[k]) mod q = a[k] · b[k] · R⁻¹ mod q`
     where `R = 2^16`.  The final corrective add makes the result
     canonical in `[0, q)`, establishing `wfVec result`.

     This proof mirrors the SCALAR `mont_mul.spec` proof in
     `Properties/MLKEM/Ntt/ModArith.lean` lane-by-lane.  Layer-1 specs
     invoked: `verify.intrinsics.x86_64.sse2.mullo_epi16.spec`, `verify.intrinsics.x86_64.sse2.mulhi_epu16.spec`,
     `verify.intrinsics.x86_64.sse2.set1_epi16.spec`, `verify.intrinsics.x86_64.sse2.sub_epi16.spec`, `verify.intrinsics.x86_64.sse2.cmpgt_epi16.spec`,
     `verify.intrinsics.x86_64.sse2.and_si128.spec`, `verify.intrinsics.x86_64.sse2.add_epi16.spec`.

     The arithmetic is heavy — the lane-wise proof uses `bv_decide` to
     discharge each `u16` bit-level equality, then sums across lanes
     by `Fin.forall_fin_succ` unfolding.  Plan: factor a private
     `mont_mul_lane_eq` lemma stating the per-lane equality and reuse
     it 8 times. -/
  vec128_mont_mul_spec := vec128_mont_mul_spec_xmm

end Symcrust.Properties.MLKEM.Intrinsics.X86_64
