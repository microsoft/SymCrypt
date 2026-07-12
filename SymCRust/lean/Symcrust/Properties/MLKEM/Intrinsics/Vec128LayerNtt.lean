/-
  Symcrust/Properties/MLKEM/Intrinsics/Vec128LayerNtt.lean — Trait-parametric
  step specs for the `_vec128` forward-NTT layer implementation
  (the INTT half lives in `Vec128LayerIntt.lean`).

  These specs cover the three-level recursion at

      mlkem.ntt.poly_element_ntt_layer_vec128_loop0_loop0   -- inner butterfly
      mlkem.ntt.poly_element_ntt_layer_vec128_loop0         -- outer (k, start) loop
      mlkem.ntt.poly_element_ntt_layer_vec128               -- top wrapper

  and their `intt` counterparts.  Each is parametric over

      `[s : NttIntrinsicsSpec V Inst]`

  — the abstract method-spec class from `TraitSpec.lean` — so the proofs
  apply uniformly at every concrete instantiation
  (`XmmNttInst : NttIntrinsicsInterface … __m128i`,
   `NeonNttInst : NttIntrinsicsInterface … uint16x8_t`).

  ## Algorithmic equivalence with `_generic`

  The Rust body at `src/mlkem/ntt.rs:265-339` (the `_vec128` family)
  computes the same butterflies as the portable `_generic` family, only
  packed into SIMD registers:

  * `_vec128_loop0_loop0` walks `j ∈ [0, len)` with **step 8**, dispatching:
      - `len ≥ 8`: process 8 consecutive butterfly pairs per j-step using
        `vec128_load_u16x8` / `vec128_store_u16x8`.
      - `len = 4`: only `j = 0` is visited (the step-by-8 iterator over
        `[0, 4)` yields the singleton `{0}`); processes 4 butterfly pairs
        via `vec64_load_u16x4` / `vec64_store_u16x4`.
      - `len ∈ {1, 2}`: only `j = 0` is visited; processes `len` butterfly
        pairs via `vec32_load_u16x2` / `vec32_store_u16x2`.

  In every branch the per-iteration computation is
      `v_c1' = mont_mul v_c1 twiddle twiddle_mont`
      `v_c0'  = mod_add v_c0 v_c1'`
      `v_c1'' = mod_sub v_c0 v_c1'`
  applied lane-wise to the loaded register pair.  Per the `mont_mul`
  spec, each lane satisfies `v_c1'[i] = v_c1[i] · twiddle[i] · Rinv` in
  `Zq`; `mod_add`/`mod_sub` are lane-wise `+`/`-` in `Zq`.  Crossed with
  the abstract `toLanes` projection from `NttIntrinsicsSpec`, this yields
  exactly `nttButterflyAt twiddle pe_src len i` for each `i ∈
  [start + j, start + j + len)`, mirroring the `_generic` loop body.

  ## Postcondition shape

  Each spec mirrors the corresponding `_generic` spec post verbatim:

  * `_loop0_loop0`:
      `toPoly r = nttButterflies (u32ToZq tw * Rinv)
                    (toPoly pe_src) len
                    (start + iter.start) (start + iter.«end») _`.
  * `_loop0`:
      `toPoly r = (nttMidLayer len _ iter.iter.start k (toPoly pe_src)).1`.
  * `_vec128` (top):
      `toPoly r = (nttMidLayer len _ 0 k (toPoly pe_src)).1`.

  This is intentional: the dispatcher in `Ntt.lean` /
  `Intt.lean` proves
  `poly_element_(i)ntt_layer.<target>.spec` by case-splitting on the
  hardware-feature flag and routing the SIMD arm to `_vec128.spec` and
  the fallback arm to `_generic.spec`.  Identical posts let the
  dispatcher collapse to a single `cases hf with | true => ... | false => ...`
  pattern.

  See `Properties/MLKEM/Intrinsics/X86_64/Avx2LayerNtt.lean` for the analogous
  16-lane (AVX2) layer and `Properties/MLKEM/Intrinsics/TraitSpec.lean`
  for the trait-parametric layer.
-/
import Aeneas
import Symcrust.Code.Funs
import Spec.MLKEM.Spec
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.MontArith
import Symcrust.Properties.MLKEM.Bridges.NttLoops
import Symcrust.Properties.MLKEM.Bridges.NttLinearity
import Symcrust.Properties.MLKEM.Intrinsics.TraitSpec
import Symcrust.Properties.MLKEM.Ntt.Twiddles
import Symcrust.Properties.MLKEM.Bridges.Iterators
import Symcrust.Properties.Iterators

open Aeneas Aeneas.Std Result
open Symcrust Spec.MLKEM
open symcrust

namespace Symcrust.Properties.MLKEM.Intrinsics

open Symcrust.Properties.MLKEM
open Symcrust.Properties.MLKEM.Bridges

variable {T V : Type}
  {Inst : symcrust.mlkem.ntt.NttIntrinsicsInterface T V}
  [s : NttIntrinsicsSpec V Inst]

/-! ## Forward NTT vec128 layer -/

/-! ### `#decompose` carve-out: vec128 NTT inner-loop per-iteration body

The Aeneas-extracted `poly_element_ntt_layer_vec128_loop0_loop0` body
has ~32 monadic bindings in the `some j` arm (one size-class dispatch
for load width, three trait-method arithmetic operations, another
size-class dispatch for store width with stores+recursion).  Per
`aeneas-fold-decomposition`'s 10-binding heuristic, we carve out the
pure SIMD arithmetic via a two-stage `#decompose` cascade:

  * Stage 1 (`*.fold`): extract the whole match-body (`none => ok ;
    some j => ...`) as `_step`, still containing the recursive call.
  * Stage 2 (`*_step.fold`): inside `_step`'s `some j` branch, extract
    the **first 4 bindings** (load-by-width + mont_mul + mod_sub +
    mod_add) as `_butterfly` — a **non-recursive** function returning
    `(iter2, v_c11, v_c01)`.  The trailing size-class dispatch for
    stores (which contains the recursive call) is left in the parent.

After the cascade, the parent's per-iteration body structure becomes:
```
some j => do
  let (iter2, v_c11, v_c01) ← _butterfly Inst pe_src len start v_tw v_tw_mont iter1 j
  if len ≥ 8 then store_8 + recursive_call
  else if len = 4 then store_4 + recursive_call
  else                store_2 + recursive_call
```

The parent `_loop0_loop0.spec` proof uses `rw [*.fold, *_step.fold]`,
then `match` on the iterator option, `step` consumes `_butterfly` via
its `@[local step]` spec, and a case-split on the store-width
dispatch closes each arm with an IH application on the recursive call.

(Note: the helpers are parametric over the trait instance — they
inherit the file's `variable` block. The trait postcondition strengths
in `TraitSpec.lean` are sufficient to discharge the helper's FC post.) -/

set_option maxRecDepth 4096 in
#decompose mlkem.ntt.poly_element_ntt_layer_vec128_loop0_loop0
    poly_element_ntt_layer_vec128_loop0_loop0.fold
  letRange 1 1 => poly_element_ntt_layer_vec128_loop0_loop0_step

set_option maxRecDepth 4096 in
set_option maxHeartbeats 800000 in
#decompose poly_element_ntt_layer_vec128_loop0_loop0_step
    poly_element_ntt_layer_vec128_loop0_loop0_step.fold
  branch 1 (letRange 0 4) => poly_element_ntt_layer_vec128_loop0_loop0_butterfly

/-- INFORMAL PROOF.  Per-iteration vec128 NTT butterfly (Cooley-Tukey),
    parametric in the lane width (8 / 4 / 2 by size-class on `len`).
    Pure SIMD body extracted by the `#decompose` cascade above;
    returns the updated step-by iterator alongside the two output
    lane vectors `(v_c11, v_c01)`.  Body:
    ```
    let (iter2, v_c0, v_c1) ←
      if len ≥ 8 then vec128_load_u16x8 ×2 at (start+j, start+j+len)
      else if len = 4 then vec64_load_u16x4 ×2
      else                  vec32_load_u16x2 ×2
    let v_c1_times_twiddle ← vec128_mont_mul v_c1 v_tw v_tw_mont
    let v_c11 ← vec128_mod_sub v_c0 v_c1_times_twiddle
    let v_c01 ← vec128_mod_add v_c0 v_c1_times_twiddle
    ok (iter2, v_c11, v_c01)
    ```
    Spec: post equates lane projections of `v_c01` and `v_c11` to the
    pure-spec butterfly applied to `pe_src` at the relevant indices
    (with twiddle `u16ToZq tw * Rinv`).  The store-and-recurse phase
    is left to the parent.

    Note: the iterator-`next` call is in the parent (`iter1` is bound
    by the outer `match`); this helper only consumes `iter1` and
    returns it as `iter2` (which the parent threads through to the
    recursive call).  This is why `iter2 = iter1` in the helper's
    spec — the iterator is just plumbed through. -/
@[local step]
theorem poly_element_ntt_layer_vec128_loop0_loop0_butterfly.spec
    (pe_src : PolyElement)
    (len start : Std.Usize)
    (v_tw v_tw_mont : V)
    (iter1 : core.iter.adapters.step_by.StepBy
              (core.ops.range.Range Std.Usize))
    (j : Std.Usize)
    (h_wf : wfPoly pe_src)
    (h_len_pos : 2 ≤ len.val)
    (h_len_le : len.val ≤ 128)
    (h_bound : start.val + 2 * len.val ≤ 256)
    (h_j_lt : j.val < len.val)
    (h_j_step : j.val + 8 ≤ len.val ∨ j.val = 0)
    (tw : Std.U16) (_h_tw_lt : tw.val < q)
    (h_v_tw_wf : s.wfVec v_tw)
    (h_v_tw_lane : ∀ i : Fin 8, (s.toLanes v_tw)[i.val] = tw)
    (tw_mont : Std.U16) (h_tw_mont_eq : tw_mont.val = (tw.val * 3327) % 65536)
    (h_v_tw_mont_lane : ∀ i : Fin 8,
      ((s.toLanes v_tw_mont)[i.val].val : ℕ) = tw_mont.val) :
    poly_element_ntt_layer_vec128_loop0_loop0_butterfly
        Inst pe_src len start v_tw v_tw_mont iter1 j
    ⦃ (r : core.iter.adapters.step_by.StepBy
              (core.ops.range.Range Std.Usize) × V × V) =>
        -- Frame on iterator: plumbed through unchanged (advance happens in parent).
        r.1 = iter1 ∧
        -- Output vectors well-formed (lanes < q).
        s.wfVec r.2.1 ∧ s.wfVec r.2.2 ∧
        -- Per-lane FC (Cooley-Tukey butterfly), width-dispatched on `len`:
        -- the W active lanes of (v_c01, v_c11) equal the butterfly applied
        -- to pe_src at coordinates (start+j+k, start+j+len+k) for k < W.
        -- Width W ∈ {8, 4, 2} per size class.  The `if`-chain encodes the
        -- Rust dispatch; bounds `start+j+len+k < 256` for k < W follow
        -- from h_bound, h_j_lt, h_len_pos, h_len_le.
        (∀ k : Fin 8, 8 ≤ len.val → j.val + 8 ≤ len.val →
          (((s.toLanes r.2.2)[k.val]).val : Zq) =
            (((pe_src.val.getD (start.val + j.val + k.val) 0#u16)).val : Zq) +
            (((pe_src.val.getD (start.val + j.val + len.val + k.val) 0#u16)).val : Zq) *
              (u16ToZq tw) * Rinv ∧
          (((s.toLanes r.2.1)[k.val]).val : Zq) =
            (((pe_src.val.getD (start.val + j.val + k.val) 0#u16)).val : Zq) -
            (((pe_src.val.getD (start.val + j.val + len.val + k.val) 0#u16)).val : Zq) *
              (u16ToZq tw) * Rinv) ∧
        (∀ k : Fin 4, len.val = 4 → j.val + 4 ≤ len.val →
          (((s.toLanes r.2.2)[k.val]'(by have := k.isLt; scalar_tac)).val : Zq) =
            (((pe_src.val.getD (start.val + j.val + k.val) 0#u16)).val : Zq) +
            (((pe_src.val.getD (start.val + j.val + len.val + k.val) 0#u16)).val : Zq) *
              (u16ToZq tw) * Rinv ∧
          (((s.toLanes r.2.1)[k.val]'(by have := k.isLt; scalar_tac)).val : Zq) =
            (((pe_src.val.getD (start.val + j.val + k.val) 0#u16)).val : Zq) -
            (((pe_src.val.getD (start.val + j.val + len.val + k.val) 0#u16)).val : Zq) *
              (u16ToZq tw) * Rinv) ∧
        (∀ k : Fin 2, len.val < 4 → j.val + 2 ≤ len.val →
          (((s.toLanes r.2.2)[k.val]'(by have := k.isLt; scalar_tac)).val : Zq) =
            (((pe_src.val.getD (start.val + j.val + k.val) 0#u16)).val : Zq) +
            (((pe_src.val.getD (start.val + j.val + len.val + k.val) 0#u16)).val : Zq) *
              (u16ToZq tw) * Rinv ∧
          (((s.toLanes r.2.1)[k.val]'(by have := k.isLt; scalar_tac)).val : Zq) =
            (((pe_src.val.getD (start.val + j.val + k.val) 0#u16)).val : Zq) -
            (((pe_src.val.getD (start.val + j.val + len.val + k.val) 0#u16)).val : Zq) *
              (u16ToZq tw) * Rinv) ⦄ := by
  unfold poly_element_ntt_layer_vec128_loop0_loop0_butterfly
  split_ifs with h_ge8 h_eq4
  · -- Case (a): len ≥ 8.
    step as ⟨i_a, h_i_a⟩
    step as ⟨v_c0, h_wf_c0, h_lane_c0⟩
    step as ⟨i_b, h_i_b⟩
    step as ⟨v_c1, h_wf_c1, h_lane_c1⟩
    · -- discharge side goal: i_b + 8 ≤ 256
      obtain h | h := h_j_step <;> scalar_tac
    step as ⟨v_c1t, h_wf_c1t, h_lane_c1t⟩
    step as ⟨v_c11, h_wf_c11, h_lane_c11⟩
    step as ⟨v_c01, h_wf_c01, h_lane_c01⟩
    refine ⟨h_wf_c11, h_wf_c01, ?_, ?_, ?_⟩
    · -- Active: ∀ k : Fin 8, lane FC equality
      intro k _ _
      have hlen : pe_src.val.length = 256 := by have := pe_src.property; grind
      have hk_a : start.val + j.val + k.val < 256 := by
        have := k.isLt; obtain h | h := h_j_step <;> scalar_tac
      have hk_b : start.val + j.val + len.val + k.val < 256 := by
        have := k.isLt; obtain h | h := h_j_step <;> scalar_tac
      have h_getD_a : pe_src.val.getD (start.val + j.val + k.val) 0#u16
                    = pe_src.val[start.val + j.val + k.val]'(by rw [hlen]; exact hk_a) :=
        List.getD_eq_getElem _ _ _
      have h_getD_b : pe_src.val.getD (start.val + j.val + len.val + k.val) 0#u16
                    = pe_src.val[start.val + j.val + len.val + k.val]'(by rw [hlen]; exact hk_b) :=
        List.getD_eq_getElem _ _ _
      have h_ib_val : i_b.val = start.val + j.val + len.val := by
        rw [h_i_b, h_i_a]
      refine ⟨?_, ?_⟩
      · simp only [h_lane_c01 k, h_lane_c0 k, h_lane_c1t k, h_lane_c1 k, h_v_tw_lane k,
                   h_getD_a, h_getD_b, h_i_a, h_ib_val, u16ToZq]
      · simp only [h_lane_c11 k, h_lane_c0 k, h_lane_c1t k, h_lane_c1 k, h_v_tw_lane k,
                   h_getD_a, h_getD_b, h_i_a, h_ib_val, u16ToZq]
    · -- Vacuous: len = 4 contradicts len ≥ 8.
      intro k h_eq4 _
      exfalso; scalar_tac
    · -- Vacuous: len < 4 contradicts len ≥ 8.
      intro k h_lt4 _
      exfalso; scalar_tac
  · -- Case (b): ¬(len ≥ 8) ∧ len = 4.
    have hj0 : j.val = 0 := by
      obtain h | h := h_j_step <;> scalar_tac
    step as ⟨i_a, h_i_a⟩
    step as ⟨v_c0, h_wf_c0, h_lane_c0⟩
    step as ⟨i_b, h_i_b⟩
    step as ⟨v_c1, h_wf_c1, h_lane_c1⟩
    step as ⟨v_c1t, h_wf_c1t, h_lane_c1t⟩
    step as ⟨v_c11, h_wf_c11, h_lane_c11⟩
    step as ⟨v_c01, h_wf_c01, h_lane_c01⟩
    refine ⟨h_wf_c11, h_wf_c01, ?_, ?_, ?_⟩
    · -- Vacuous: 8 ≤ len contradicts ¬(len ≥ 8).
      intro k h_len8 _
      exfalso; scalar_tac
    · -- Active: ∀ k : Fin 4, lane FC equality
      intro k h_len4 h_jb4
      have hlen : pe_src.val.length = 256 := by have := pe_src.property; grind
      have hk_a : start.val + j.val + k.val < 256 := by
        have := k.isLt; omega
      have hk_b : start.val + j.val + len.val + k.val < 256 := by
        have := k.isLt; omega
      have h_getD_a : pe_src.val.getD (start.val + j.val + k.val) 0#u16
                    = pe_src.val[start.val + j.val + k.val]'(by rw [hlen]; exact hk_a) :=
        List.getD_eq_getElem _ _ _
      have h_getD_b : pe_src.val.getD (start.val + j.val + len.val + k.val) 0#u16
                    = pe_src.val[start.val + j.val + len.val + k.val]'(by rw [hlen]; exact hk_b) :=
        List.getD_eq_getElem _ _ _
      have h_ib_val : i_b.val = start.val + j.val + len.val := by
        rw [h_i_b, h_i_a]
      have h_kk : k.val < 8 := by have := k.isLt; omega
      have h01 := h_lane_c01 ⟨k.val, h_kk⟩
      have h11 := h_lane_c11 ⟨k.val, h_kk⟩
      have h1t := h_lane_c1t ⟨k.val, h_kk⟩
      have htw := h_v_tw_lane ⟨k.val, h_kk⟩
      have h0 := h_lane_c0 k
      have h1 := h_lane_c1 k
      refine ⟨?_, ?_⟩
      · simp only [h01, h0, h1t, h1, htw, h_getD_a, h_getD_b, h_i_a, h_ib_val, u16ToZq]
      · simp only [h11, h0, h1t, h1, htw, h_getD_a, h_getD_b, h_i_a, h_ib_val, u16ToZq]
    · -- Vacuous: len < 4 contradicts len = 4.
      intro k h_lt _
      exfalso; scalar_tac
  · -- Case (c): ¬(len ≥ 8) ∧ ¬(len = 4); len ∈ {2, 3} (recall 2 ≤ len).
    have hj0 : j.val = 0 := by
      obtain h | h := h_j_step <;> scalar_tac
    step as ⟨i_a, h_i_a⟩
    step as ⟨v_c0, h_wf_c0, h_lane_c0⟩
    step as ⟨i_b, h_i_b⟩
    step as ⟨v_c1, h_wf_c1, h_lane_c1⟩
    step as ⟨v_c1t, h_wf_c1t, h_lane_c1t⟩
    step as ⟨v_c11, h_wf_c11, h_lane_c11⟩
    step as ⟨v_c01, h_wf_c01, h_lane_c01⟩
    refine ⟨h_wf_c11, h_wf_c01, ?_, ?_, ?_⟩
    · -- Vacuous: 8 ≤ len contradicts ¬(len ≥ 8).
      intro k h_len8 _
      exfalso; scalar_tac
    · -- Vacuous: len = 4 contradicts ¬(len = 4).
      intro k h_len4 _
      exfalso; scalar_tac
    · -- Active: ∀ k : Fin 2, lane FC equality
      intro k h_lt4 h_jb2
      have hlen : pe_src.val.length = 256 := by have := pe_src.property; grind
      have hk_a : start.val + j.val + k.val < 256 := by
        have := k.isLt; omega
      have hk_b : start.val + j.val + len.val + k.val < 256 := by
        have := k.isLt; omega
      have h_getD_a : pe_src.val.getD (start.val + j.val + k.val) 0#u16
                    = pe_src.val[start.val + j.val + k.val]'(by rw [hlen]; exact hk_a) :=
        List.getD_eq_getElem _ _ _
      have h_getD_b : pe_src.val.getD (start.val + j.val + len.val + k.val) 0#u16
                    = pe_src.val[start.val + j.val + len.val + k.val]'(by rw [hlen]; exact hk_b) :=
        List.getD_eq_getElem _ _ _
      have h_ib_val : i_b.val = start.val + j.val + len.val := by
        rw [h_i_b, h_i_a]
      have h_kk : k.val < 8 := by have := k.isLt; omega
      have h01 := h_lane_c01 ⟨k.val, h_kk⟩
      have h11 := h_lane_c11 ⟨k.val, h_kk⟩
      have h1t := h_lane_c1t ⟨k.val, h_kk⟩
      have htw := h_v_tw_lane ⟨k.val, h_kk⟩
      have h0 := h_lane_c0 k
      have h1 := h_lane_c1 k
      refine ⟨?_, ?_⟩
      · simp only [h01, h0, h1t, h1, htw, h_getD_a, h_getD_b, h_i_a, h_ib_val, u16ToZq]
      · simp only [h11, h0, h1t, h1, htw, h_getD_a, h_getD_b, h_i_a, h_ib_val, u16ToZq]

set_option maxHeartbeats 1600000 in
/-- **Inner butterfly loop (vec128, parametric).** Mirrors
`poly_element_ntt_layer_generic_loop0_loop0.spec` (Ntt.lean:127):
applies `nttButterflies` over the iterator's `start..end` range, using
the trait's SIMD load/store/mod-add/mod-sub/mont-mul primitives.
-/
@[step]
theorem mlkem.ntt.poly_element_ntt_layer_vec128_loop0_loop0.spec
    (iter : core.iter.adapters.step_by.StepBy
              (core.ops.range.Range Std.Usize))
    (pe_src : PolyElement)
    (len start : Std.Usize)
    (v_tw v_tw_mont : V)
    (h_wf : wfPoly pe_src)
    (h_len_pos : 2 ≤ len.val)
    (h_len_le : len.val ≤ 128)
    (h_bound : start.val + 2 * len.val ≤ 256)
    (h_iter_end : iter.iter.«end».val = len.val)
    (h_iter_step : iter.step_by.val = 8)
    (h_iter_start_step : iter.iter.start.val < iter.iter.«end».val → iter.iter.start.val % 8 = 0)
    (h_len_step : 8 ≤ len.val → len.val % 8 = 0)
    (h_len_form : 8 ≤ len.val ∨ len.val = 4 ∨ len.val = 2)
    -- Twiddle factor broadcast: every lane carries the same `tw`
    (tw : Std.U16) (h_tw_lt : tw.val < q)
    (h_v_tw_wf : s.wfVec v_tw)
    (h_v_tw_lane : ∀ i : Fin 8, (s.toLanes v_tw)[i.val] = tw)
    -- Montgomery companion broadcast
    (tw_mont : Std.U16) (h_tw_mont_eq : tw_mont.val = (tw.val * 3327) % 65536)
    (h_v_tw_mont_lane : ∀ i : Fin 8,
      ((s.toLanes v_tw_mont)[i.val].val : ℕ) = tw_mont.val) :
    mlkem.ntt.poly_element_ntt_layer_vec128_loop0_loop0
        Inst iter pe_src len start v_tw v_tw_mont
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r =
            nttButterflies (u16ToZq tw * Rinv)
                (toPoly pe_src) len.val
                (start.val + iter.iter.start.val)
                (start.val + iter.iter.«end».val)
                (by have := h_bound; have := h_iter_end; grind) ⦄ := by
  rw [poly_element_ntt_layer_vec128_loop0_loop0.fold]
  by_cases hlt : iter.iter.start.val < iter.iter.«end».val
  · -- SOME branch: more butterflies to apply
    have h_step_pos : iter.step_by.val > 0 := by rw [h_iter_step]; decide
    have h_no_overflow : iter.iter.start.val + iter.step_by.val ≤ Usize.max := by
      rw [h_iter_step]; have := h_iter_end; have := h_len_le; scalar_tac
    let* ⟨ o, iter1, hcond, hend1, hstep1 ⟩ ← core.iter.adapters.step_by.IteratorStepBy.next_Range_Usize_spec
    simp only [hlt, ↓reduceIte] at hcond
    obtain ⟨ho, hstart1⟩ := hcond
    rw [ho]
    rw [poly_element_ntt_layer_vec128_loop0_loop0_step.fold]
    simp only
    -- iter1 properties (used for the IH and for the j-window bounds)
    have h_iter1_start : iter1.iter.start.val = min (iter.iter.start.val + 8) len.val := by
      rw [hstart1, h_iter_step, h_iter_end]
    have h_iter1_end : iter1.iter.«end».val = len.val := by
      have : iter1.iter.«end» = iter.iter.«end» := hend1
      rw [this]; exact h_iter_end
    have h_iter1_step : iter1.step_by.val = 8 := by
      have : iter1.step_by = iter.step_by := hstep1
      rw [this]; exact h_iter_step
    -- j-bounds for the butterfly call
    have h_j_lt : iter.iter.start.val < len.val := by rw [← h_iter_end]; exact hlt
    have h_j_step : iter.iter.start.val + 8 ≤ len.val ∨ iter.iter.start.val = 0 := by
      by_cases hl8 : 8 ≤ len.val
      · left
        have hm := h_len_step hl8
        have := h_iter_start_step hlt
        omega
      · right
        have := h_iter_start_step hlt
        omega
    -- step the butterfly: returns (iter1, v_c11, v_c01) with lane equalities
    let* ⟨ rb_iter, rb_v_c11, rb_v_c01,
           rb_h_iter_eq, rb_h_wf_c11, rb_h_wf_c01,
           rb_h_lane8, rb_h_lane4, rb_h_lane2 ⟩ ←
      poly_element_ntt_layer_vec128_loop0_loop0_butterfly.spec
        pe_src len start v_tw v_tw_mont iter1 iter.iter.start
        h_wf h_len_pos h_len_le h_bound h_j_lt h_j_step
        tw h_tw_lt h_v_tw_wf h_v_tw_lane tw_mont h_tw_mont_eq h_v_tw_mont_lane
    -- The butterfly plumbs iter1 through unchanged; substitute it away.
    subst rb_h_iter_eq
    -- Useful: pe_src has length 256
    have h_pe_len : pe_src.val.length = 256 := by have := pe_src.property; grind
    have h_toPoly_get : ∀ (a : PolyElement) (k : Nat) (hk : k < 256)
        (hl : a.val.length = 256),
        (toPoly a)[k]'hk = u16ToZq (a.val[k]'(by rw [hl]; exact hk)) := by
      intros a k hk hl
      unfold toPoly
      simp [Vector.getElem_ofFn]
    -- Iter1's start may exceed end (when len < 8 and start was 0) — fine for IH
    have h_iter1_start_step : rb_iter.iter.start.val < rb_iter.iter.«end».val →
        rb_iter.iter.start.val % 8 = 0 := by
      intro h_rb_lt
      rw [h_iter1_start, h_iter1_end] at h_rb_lt
      simp [Nat.min_eq_left (by omega : iter.iter.start.val + 8 ≤ len.val)] at *
      have := h_iter_start_step hlt
      omega
    -- 3-way size-class dispatch on store width
    by_cases h_ge8 : 8#usize ≤ len
    · -- W = 8 case
      simp only [h_ge8, ↓reduceIte]
      have h_len_ge8 : 8 ≤ len.val := by scalar_tac
      have h_len_mod8 : len.val % 8 = 0 := h_len_step h_len_ge8
      have h_j_step_8 : iter.iter.start.val + 8 ≤ len.val := by
        obtain h | h := h_j_step
        · exact h
        · rw [h]; exact h_len_ge8
      -- step the address i = start + iter.iter.start
      step as ⟨i_a, h_i_a⟩
      -- step first store: pe_src1 ← vec128_store_u16x8 pe_src i_a rb_v_c01
      step as ⟨pe_src1, h_pe1_len, h_pe1_wf, h_pe1_lane⟩
      -- step the address i1 = i_a + len
      step as ⟨i_b, h_i_b⟩
      -- step second store: pe_src2 ← vec128_store_u16x8 pe_src1 i_b rb_v_c11
      step as ⟨pe_src2, h_pe2_len, h_pe2_wf, h_pe2_lane⟩
      -- IH application on rb_iter, pe_src2
      apply WP.spec_mono
        (mlkem.ntt.poly_element_ntt_layer_vec128_loop0_loop0.spec
          rb_iter pe_src2 len start v_tw v_tw_mont
          h_pe2_wf h_len_pos h_len_le h_bound h_iter1_end h_iter1_step
          h_iter1_start_step h_len_step h_len_form
          tw h_tw_lt h_v_tw_wf h_v_tw_lane
          tw_mont h_tw_mont_eq h_v_tw_mont_lane)
      rintro r ⟨h_r_wf, h_r_toPoly⟩
      refine ⟨h_r_wf, ?_⟩
      rw [h_r_toPoly]
      -- Bridge: toPoly pe_src2 = nttButterflies on pe_src at [start+j, start+j+8)
      have h_i_a_val : i_a.val = start.val + iter.iter.start.val := h_i_a
      have h_i_b_val : i_b.val = start.val + iter.iter.start.val + len.val := by
        rw [h_i_b, h_i_a]
      have h_pe2_butterfly : toPoly pe_src2 =
          nttButterflies (u16ToZq tw * Rinv) (toPoly pe_src) len.val
            (start.val + iter.iter.start.val) (start.val + iter.iter.start.val + 8)
            (by scalar_tac) := by
        apply nttButterflies_eq_parallel (u16ToZq tw * Rinv) len.val (by omega)
          (toPoly pe_src) (toPoly pe_src2)
          (start.val + iter.iter.start.val) (start.val + iter.iter.start.val + 8)
          (by scalar_tac) (by omega) (by omega)
        · -- h_pair_lo
          intro j hj_lo hj_hi
          have hj : j < 256 := by scalar_tac
          have hj_len : j + len.val < 256 := by scalar_tac
          have hj_ge_ia : i_a.val ≤ j := by rw [h_i_a_val]; exact hj_lo
          have hj_lt_ia_8 : j < i_a.val + 8 := by rw [h_i_a_val]; exact hj_hi
          have hj_lt_ib : j < i_b.val := by rw [h_i_b_val]; omega
          have h_kdiff_lt : j - i_a.val < 8 := by omega
          -- pe_src2[j] = pe_src1[j] (since j < i_b)
          have h_pe2_at_j : pe_src2.val[j]'(by rw [h_pe2_len]; exact hj) =
              pe_src1.val[j]'(by rw [h_pe1_len]; exact hj) := by
            have hl := h_pe2_lane ⟨j, hj⟩
            simp at hl
            rw [hl, dif_neg (by rintro ⟨h1, _⟩; omega)]
          -- pe_src1[j] = (toLanes rb_v_c01)[j - i_a]
          have h_pe1_at_j : pe_src1.val[j]'(by rw [h_pe1_len]; exact hj) =
              (s.toLanes rb_v_c01)[j - i_a.val]'h_kdiff_lt := by
            have hl := h_pe1_lane ⟨j, hj⟩
            simp at hl
            rw [hl, dif_pos ⟨hj_ge_ia, hj_lt_ia_8⟩]
          rw [h_toPoly_get pe_src2 j hj h_pe2_len,
              h_toPoly_get pe_src j hj h_pe_len,
              h_toPoly_get pe_src (j + len.val) hj_len h_pe_len]
          rw [h_pe2_at_j, h_pe1_at_j]
          -- Use rb_h_lane8 (.1 = the low-half equation, for v_c01)
          have h_lane := (rb_h_lane8 ⟨j - i_a.val, h_kdiff_lt⟩ h_len_ge8 h_j_step_8).1
          simp only at h_lane
          have h_a : start.val + iter.iter.start.val + (j - i_a.val) = j := by
            rw [h_i_a_val] at hj_ge_ia ⊢; omega
          have h_b : start.val + iter.iter.start.val + len.val + (j - i_a.val) =
              j + len.val := by
            rw [h_i_a_val] at hj_ge_ia ⊢; omega
          rw [h_a, h_b] at h_lane
          have h_getD_a : pe_src.val.getD j 0#u16 =
              pe_src.val[j]'(by rw [h_pe_len]; exact hj) :=
            List.getD_eq_getElem _ _ (by rw [h_pe_len]; exact hj)
          have h_getD_b : pe_src.val.getD (j + len.val) 0#u16 =
              pe_src.val[j + len.val]'(by rw [h_pe_len]; exact hj_len) :=
            List.getD_eq_getElem _ _ (by rw [h_pe_len]; exact hj_len)
          rw [h_getD_a, h_getD_b] at h_lane
          unfold u16ToZq
          rw [h_lane]
          ring
        · -- h_pair_hi
          intro j hj_lo hj_hi
          have hj : j < 256 := by scalar_tac
          have hj_len : j + len.val < 256 := by scalar_tac
          have hj_ge_ia : i_a.val ≤ j := by rw [h_i_a_val]; exact hj_lo
          have hjl_ge_ib : i_b.val ≤ j + len.val := by rw [h_i_b_val]; omega
          have hjl_lt_ib_8 : j + len.val < i_b.val + 8 := by rw [h_i_b_val]; omega
          have h_kdiff_lt : (j + len.val) - i_b.val < 8 := by omega
          have h_kdiff_eq : (j + len.val) - i_b.val = j - i_a.val := by
            rw [h_i_a_val, h_i_b_val]; omega
          have h_kdiff_lt' : j - i_a.val < 8 := by rw [← h_kdiff_eq]; exact h_kdiff_lt
          -- pe_src2[j+len] = (toLanes rb_v_c11)[j - i_a]  (using h_kdiff_eq to align)
          have h_pe2_at_jl : pe_src2.val[j + len.val]'(by rw [h_pe2_len]; exact hj_len) =
              (s.toLanes rb_v_c11)[j - i_a.val]'h_kdiff_lt' := by
            have hl := h_pe2_lane ⟨j + len.val, hj_len⟩
            simp at hl
            rw [hl, dif_pos ⟨hjl_ge_ib, hjl_lt_ib_8⟩]
            fcongr 1
          rw [h_toPoly_get pe_src2 (j + len.val) hj_len h_pe2_len,
              h_toPoly_get pe_src j hj h_pe_len,
              h_toPoly_get pe_src (j + len.val) hj_len h_pe_len]
          rw [h_pe2_at_jl]
          -- Use rb_h_lane8 (.2 = high-half equation, for v_c11)
          have h_lane := (rb_h_lane8 ⟨j - i_a.val, h_kdiff_lt'⟩ h_len_ge8 h_j_step_8).2
          simp only at h_lane
          have h_a : start.val + iter.iter.start.val + (j - i_a.val) = j := by
            rw [h_i_a_val] at hj_ge_ia ⊢; omega
          have h_b : start.val + iter.iter.start.val + len.val + (j - i_a.val) =
              j + len.val := by
            rw [h_i_a_val] at hj_ge_ia ⊢; omega
          rw [h_a, h_b] at h_lane
          have h_getD_a : pe_src.val.getD j 0#u16 =
              pe_src.val[j]'(by rw [h_pe_len]; exact hj) :=
            List.getD_eq_getElem _ _ (by rw [h_pe_len]; exact hj)
          have h_getD_b : pe_src.val.getD (j + len.val) 0#u16 =
              pe_src.val[j + len.val]'(by rw [h_pe_len]; exact hj_len) :=
            List.getD_eq_getElem _ _ (by rw [h_pe_len]; exact hj_len)
          rw [h_getD_a, h_getD_b] at h_lane
          unfold u16ToZq
          rw [h_lane]
          ring
        · -- h_frame
          intro k hk h_not_lo h_not_hi
          have h_not_lo_k : ¬ (i_a.val ≤ k ∧ k < i_a.val + 8) := by
            rintro ⟨h1, h2⟩
            apply h_not_lo
            refine ⟨?_, ?_⟩ <;> (rw [h_i_a_val] at h1 h2; agrind)
          have h_not_hi_k : ¬ (i_b.val ≤ k ∧ k < i_b.val + 8) := by
            rintro ⟨h1, h2⟩
            apply h_not_hi
            refine ⟨?_, ?_⟩ <;> (rw [h_i_b_val] at h1 h2; agrind)
          have h_pe2_at_k : pe_src2.val[k]'(by rw [h_pe2_len]; exact hk) =
              pe_src1.val[k]'(by rw [h_pe1_len]; exact hk) := by
            have hl := h_pe2_lane ⟨k, hk⟩
            simp at hl
            rw [hl, dif_neg h_not_hi_k]
          have h_pe1_at_k : pe_src1.val[k]'(by rw [h_pe1_len]; exact hk) =
              pe_src.val[k]'(by rw [h_pe_len]; exact hk) := by
            have hl := h_pe1_lane ⟨k, hk⟩
            simp at hl
            rw [hl, dif_neg h_not_lo_k]
          rw [h_toPoly_get pe_src2 k hk h_pe2_len,
              h_toPoly_get pe_src k hk h_pe_len]
          rw [h_pe2_at_k, h_pe1_at_k]
      -- Now use h_pe2_butterfly + nttButterflies_split to compose with IH
      conv_rhs =>
        rw [nttButterflies_split (u16ToZq tw * Rinv) (toPoly pe_src) len.val
              (start.val + iter.iter.start.val)
              (start.val + iter.iter.start.val + 8)
              (start.val + iter.iter.«end».val)
              (by omega) (by have := hlt; rw [h_iter_end] at this ⊢; omega)
              (by have := h_iter_end; have := h_bound; omega)]
        rw [← h_pe2_butterfly]
      have h_lhs_lo : start.val + rb_iter.iter.start.val =
          start.val + iter.iter.start.val + 8 := by rw [h_iter1_start]; omega
      have h_lhs_hi : start.val + rb_iter.iter.«end».val =
          start.val + iter.iter.«end».val := by
        fcongr 1
        have : rb_iter.iter.«end» = iter.iter.«end» := hend1
        rw [this]
      rw [h_lhs_lo]
      fcongr 1
    · by_cases h_eq4 : len = 4#usize
      · -- W = 4 case (forces iter.iter.start = 0)
        rw [if_neg h_ge8, if_pos h_eq4]
        have h_len_4 : len.val = 4 := by
          have hh : len.val = (4#usize).val := by rw [h_eq4]
          simpa using hh
        have h_start_0 : iter.iter.start.val = 0 := by
          obtain h | h := h_j_step
          · exfalso; rw [h_len_4] at h; omega
          · exact h
        have h_lane_bound_c01 : ∀ i : Fin 4, (s.toLanes rb_v_c01)[i.val].val < q :=
          fun i => (s.wfVec_iff rb_v_c01).mp rb_h_wf_c01 ⟨i.val, by omega⟩
        have h_lane_bound_c11 : ∀ i : Fin 4, (s.toLanes rb_v_c11)[i.val].val < q :=
          fun i => (s.wfVec_iff rb_v_c11).mp rb_h_wf_c11 ⟨i.val, by omega⟩
        step as ⟨i_a, h_i_a⟩
        step as ⟨pe_src1, h_pe1_len, h_pe1_wf, h_pe1_lane⟩
        step as ⟨i_b, h_i_b⟩
        step as ⟨pe_src2, h_pe2_len, h_pe2_wf, h_pe2_lane⟩
        apply WP.spec_mono
          (mlkem.ntt.poly_element_ntt_layer_vec128_loop0_loop0.spec
            rb_iter pe_src2 len start v_tw v_tw_mont
            h_pe2_wf h_len_pos h_len_le h_bound h_iter1_end h_iter1_step
            h_iter1_start_step h_len_step h_len_form
            tw h_tw_lt h_v_tw_wf h_v_tw_lane
            tw_mont h_tw_mont_eq h_v_tw_mont_lane)
        rintro r ⟨h_r_wf, h_r_toPoly⟩
        refine ⟨h_r_wf, ?_⟩
        rw [h_r_toPoly]
        -- IH's range is empty: rb_iter.start = 8 > 4 = rb_iter.end
        have h_rb_empty : ¬ (start.val + rb_iter.iter.start.val) <
            (start.val + rb_iter.iter.«end».val) := by
          rw [h_iter1_start, h_iter1_end, h_len_4]; omega
        rw [nttButterflies_nil _ _ _ _ _ _ h_rb_empty]
        -- Build bridge for W = 4
        have h_i_a_val : i_a.val = start.val + iter.iter.start.val := h_i_a
        have h_i_b_val : i_b.val = start.val + iter.iter.start.val + len.val := by
          rw [h_i_b, h_i_a]
        have h_pe2_butterfly : toPoly pe_src2 =
            nttButterflies (u16ToZq tw * Rinv) (toPoly pe_src) len.val
              (start.val + iter.iter.start.val) (start.val + iter.iter.«end».val)
              (by rw [h_iter_end]; omega) := by
          apply nttButterflies_eq_parallel (u16ToZq tw * Rinv) len.val (by omega)
            (toPoly pe_src) (toPoly pe_src2)
            (start.val + iter.iter.start.val) (start.val + iter.iter.«end».val)
            (by rw [h_iter_end]; omega)
            (by rw [h_iter_end]; omega) (by rw [h_iter_end, h_len_4]; omega)
          · -- h_pair_lo
            intro j hj_lo hj_hi
            have hj_hi' : j < start.val + len.val := by rw [h_iter_end] at hj_hi; exact hj_hi
            have hj : j < 256 := by omega
            have hj_len : j + len.val < 256 := by omega
            have hj_ge_ia : i_a.val ≤ j := by rw [h_i_a_val]; exact hj_lo
            have hj_lt_ia_4 : j < i_a.val + 4 := by
              rw [h_i_a_val, ← h_len_4]; omega
            have hj_lt_ib : j < i_b.val := by
              rw [h_i_b_val]; omega
            have h_kdiff_lt : j - i_a.val < 4 := by omega
            have h_kdiff_lt8 : j - i_a.val < 8 := by omega
            have h_pe2_at_j : pe_src2.val[j]'(by rw [h_pe2_len]; exact hj) =
                pe_src1.val[j]'(by rw [h_pe1_len]; exact hj) := by
              have hl := h_pe2_lane ⟨j, hj⟩
              simp at hl
              rw [hl, dif_neg (by rintro ⟨h1, _⟩; omega)]
            have h_pe1_at_j : pe_src1.val[j]'(by rw [h_pe1_len]; exact hj) =
                (s.toLanes rb_v_c01)[j - i_a.val]'h_kdiff_lt8 := by
              have hl := h_pe1_lane ⟨j, hj⟩
              simp at hl
              rw [hl, dif_pos ⟨hj_ge_ia, hj_lt_ia_4⟩]
            rw [h_toPoly_get pe_src2 j hj h_pe2_len,
                h_toPoly_get pe_src j hj h_pe_len,
                h_toPoly_get pe_src (j + len.val) hj_len h_pe_len]
            rw [h_pe2_at_j, h_pe1_at_j]
            have h_lane := (rb_h_lane4 ⟨j - i_a.val, h_kdiff_lt⟩ h_len_4
              (by rw [h_len_4, h_start_0])).1
            simp only at h_lane
            have h_a : start.val + iter.iter.start.val + (j - i_a.val) = j := by
              rw [h_i_a_val] at hj_ge_ia ⊢; omega
            have h_b : start.val + iter.iter.start.val + len.val + (j - i_a.val) =
                j + len.val := by
              rw [h_i_a_val] at hj_ge_ia ⊢; omega
            rw [h_a, h_b] at h_lane
            have h_getD_a : pe_src.val.getD j 0#u16 =
                pe_src.val[j]'(by rw [h_pe_len]; exact hj) :=
              List.getD_eq_getElem _ _ (by rw [h_pe_len]; exact hj)
            have h_getD_b : pe_src.val.getD (j + len.val) 0#u16 =
                pe_src.val[j + len.val]'(by rw [h_pe_len]; exact hj_len) :=
              List.getD_eq_getElem _ _ (by rw [h_pe_len]; exact hj_len)
            rw [h_getD_a, h_getD_b] at h_lane
            unfold u16ToZq
            rw [h_lane]
            ring
          · -- h_pair_hi
            intro j hj_lo hj_hi
            have hj_hi' : j < start.val + len.val := by rw [h_iter_end] at hj_hi; exact hj_hi
            have hj : j < 256 := by omega
            have hj_len : j + len.val < 256 := by omega
            have hj_ge_ia : i_a.val ≤ j := by rw [h_i_a_val]; exact hj_lo
            have hjl_ge_ib : i_b.val ≤ j + len.val := by
              rw [h_i_b_val]; omega
            have hjl_lt_ib_4 : j + len.val < i_b.val + 4 := by
              rw [h_i_b_val, ← h_len_4]; omega
            have h_kdiff_lt : (j + len.val) - i_b.val < 4 := by
              rw [h_i_b_val, ← h_len_4]; omega
            have h_kdiff_lt' : j - i_a.val < 4 := by
              rw [h_i_a_val] at hj_ge_ia ⊢; omega
            have h_kdiff_lt'8 : j - i_a.val < 8 := by omega
            have h_pe2_at_jl : pe_src2.val[j + len.val]'(by rw [h_pe2_len]; exact hj_len) =
                (s.toLanes rb_v_c11)[j - i_a.val]'h_kdiff_lt'8 := by
              have hl := h_pe2_lane ⟨j + len.val, hj_len⟩
              simp at hl
              rw [hl, dif_pos ⟨hjl_ge_ib, hjl_lt_ib_4⟩]
              fcongr 1
              rw [h_i_a_val, h_i_b_val]; omega
            rw [h_toPoly_get pe_src2 (j + len.val) hj_len h_pe2_len,
                h_toPoly_get pe_src j hj h_pe_len,
                h_toPoly_get pe_src (j + len.val) hj_len h_pe_len]
            rw [h_pe2_at_jl]
            have h_lane := (rb_h_lane4 ⟨j - i_a.val, h_kdiff_lt'⟩ h_len_4
              (by rw [h_len_4, h_start_0])).2
            simp only at h_lane
            have h_a : start.val + iter.iter.start.val + (j - i_a.val) = j := by
              rw [h_i_a_val] at hj_ge_ia ⊢; omega
            have h_b : start.val + iter.iter.start.val + len.val + (j - i_a.val) =
                j + len.val := by
              rw [h_i_a_val] at hj_ge_ia ⊢; omega
            rw [h_a, h_b] at h_lane
            have h_getD_a : pe_src.val.getD j 0#u16 =
                pe_src.val[j]'(by rw [h_pe_len]; exact hj) :=
              List.getD_eq_getElem _ _ (by rw [h_pe_len]; exact hj)
            have h_getD_b : pe_src.val.getD (j + len.val) 0#u16 =
                pe_src.val[j + len.val]'(by rw [h_pe_len]; exact hj_len) :=
              List.getD_eq_getElem _ _ (by rw [h_pe_len]; exact hj_len)
            rw [h_getD_a, h_getD_b] at h_lane
            unfold u16ToZq
            rw [h_lane]
            ring
          · -- h_frame
            intro k hk h_not_lo h_not_hi
            have h_not_lo_k : ¬ (i_a.val ≤ k ∧ k < i_a.val + 4) := by
              rintro ⟨h1, h2⟩
              apply h_not_lo
              rw [h_i_a_val] at h1 h2
              refine ⟨h1, ?_⟩
              rw [h_iter_end, h_len_4]; omega
            have h_not_hi_k : ¬ (i_b.val ≤ k ∧ k < i_b.val + 4) := by
              rintro ⟨h1, h2⟩
              apply h_not_hi
              rw [h_i_b_val] at h1 h2
              rw [h_iter_end]
              refine ⟨by omega, by omega⟩
            have h_pe2_at_k : pe_src2.val[k]'(by rw [h_pe2_len]; exact hk) =
                pe_src1.val[k]'(by rw [h_pe1_len]; exact hk) := by
              have hl := h_pe2_lane ⟨k, hk⟩
              simp at hl
              rw [hl, dif_neg h_not_hi_k]
            have h_pe1_at_k : pe_src1.val[k]'(by rw [h_pe1_len]; exact hk) =
                pe_src.val[k]'(by rw [h_pe_len]; exact hk) := by
              have hl := h_pe1_lane ⟨k, hk⟩
              simp at hl
              rw [hl, dif_neg h_not_lo_k]
            rw [h_toPoly_get pe_src2 k hk h_pe2_len,
                h_toPoly_get pe_src k hk h_pe_len]
            rw [h_pe2_at_k, h_pe1_at_k]
        rw [h_pe2_butterfly]
      · -- W = 2 case (len = 2, forces iter.iter.start = 0)
        rw [if_neg h_ge8, if_neg h_eq4]
        have h_len_2 : len.val = 2 := by
          obtain h | h | h := h_len_form
          · exfalso; exact h_ge8 (by scalar_tac)
          · exfalso; apply h_eq4; scalar_tac
          · exact h
        have h_start_0 : iter.iter.start.val = 0 := by
          obtain h | h := h_j_step
          · exfalso; rw [h_len_2] at h; omega
          · exact h
        have h_lane_bound_c01 : ∀ i : Fin 2, (s.toLanes rb_v_c01)[i.val].val < q :=
          fun i => (s.wfVec_iff rb_v_c01).mp rb_h_wf_c01 ⟨i.val, by omega⟩
        have h_lane_bound_c11 : ∀ i : Fin 2, (s.toLanes rb_v_c11)[i.val].val < q :=
          fun i => (s.wfVec_iff rb_v_c11).mp rb_h_wf_c11 ⟨i.val, by omega⟩
        step as ⟨i_a, h_i_a⟩
        step as ⟨pe_src1, h_pe1_len, h_pe1_wf, h_pe1_lane⟩
        step as ⟨i_b, h_i_b⟩
        step as ⟨pe_src2, h_pe2_len, h_pe2_wf, h_pe2_lane⟩
        apply WP.spec_mono
          (mlkem.ntt.poly_element_ntt_layer_vec128_loop0_loop0.spec
            rb_iter pe_src2 len start v_tw v_tw_mont
            h_pe2_wf h_len_pos h_len_le h_bound h_iter1_end h_iter1_step
            h_iter1_start_step h_len_step h_len_form
            tw h_tw_lt h_v_tw_wf h_v_tw_lane
            tw_mont h_tw_mont_eq h_v_tw_mont_lane)
        rintro r ⟨h_r_wf, h_r_toPoly⟩
        refine ⟨h_r_wf, ?_⟩
        rw [h_r_toPoly]
        have h_rb_empty : ¬ (start.val + rb_iter.iter.start.val) <
            (start.val + rb_iter.iter.«end».val) := by
          rw [h_iter1_start, h_iter1_end, h_len_2]; omega
        rw [nttButterflies_nil _ _ _ _ _ _ h_rb_empty]
        have h_i_a_val : i_a.val = start.val + iter.iter.start.val := h_i_a
        have h_i_b_val : i_b.val = start.val + iter.iter.start.val + len.val := by
          rw [h_i_b, h_i_a]
        have h_pe2_butterfly : toPoly pe_src2 =
            nttButterflies (u16ToZq tw * Rinv) (toPoly pe_src) len.val
              (start.val + iter.iter.start.val) (start.val + iter.iter.«end».val)
              (by rw [h_iter_end]; omega) := by
          apply nttButterflies_eq_parallel (u16ToZq tw * Rinv) len.val (by omega)
            (toPoly pe_src) (toPoly pe_src2)
            (start.val + iter.iter.start.val) (start.val + iter.iter.«end».val)
            (by rw [h_iter_end]; omega)
            (by rw [h_iter_end]; omega) (by rw [h_iter_end, h_len_2]; omega)
          · -- h_pair_lo
            intro j hj_lo hj_hi
            have hj_hi' : j < start.val + len.val := by rw [h_iter_end] at hj_hi; exact hj_hi
            have hj : j < 256 := by omega
            have hj_len : j + len.val < 256 := by omega
            have hj_ge_ia : i_a.val ≤ j := by rw [h_i_a_val]; exact hj_lo
            have hj_lt_ia_2 : j < i_a.val + 2 := by
              rw [h_i_a_val, ← h_len_2]; omega
            have hj_lt_ib : j < i_b.val := by
              rw [h_i_b_val]; omega
            have h_kdiff_lt : j - i_a.val < 2 := by omega
            have h_kdiff_lt8 : j - i_a.val < 8 := by omega
            have h_pe2_at_j : pe_src2.val[j]'(by rw [h_pe2_len]; exact hj) =
                pe_src1.val[j]'(by rw [h_pe1_len]; exact hj) := by
              have hl := h_pe2_lane ⟨j, hj⟩
              simp at hl
              rw [hl, dif_neg (by rintro ⟨h1, _⟩; omega)]
            have h_pe1_at_j : pe_src1.val[j]'(by rw [h_pe1_len]; exact hj) =
                (s.toLanes rb_v_c01)[j - i_a.val]'h_kdiff_lt8 := by
              have hl := h_pe1_lane ⟨j, hj⟩
              simp at hl
              rw [hl, dif_pos ⟨hj_ge_ia, hj_lt_ia_2⟩]
            rw [h_toPoly_get pe_src2 j hj h_pe2_len,
                h_toPoly_get pe_src j hj h_pe_len,
                h_toPoly_get pe_src (j + len.val) hj_len h_pe_len]
            rw [h_pe2_at_j, h_pe1_at_j]
            have h_lane := (rb_h_lane2 ⟨j - i_a.val, h_kdiff_lt⟩ (by rw [h_len_2]; omega)
              (by rw [h_len_2, h_start_0])).1
            simp only at h_lane
            have h_a : start.val + iter.iter.start.val + (j - i_a.val) = j := by
              rw [h_i_a_val] at hj_ge_ia ⊢; omega
            have h_b : start.val + iter.iter.start.val + len.val + (j - i_a.val) =
                j + len.val := by
              rw [h_i_a_val] at hj_ge_ia ⊢; omega
            rw [h_a, h_b] at h_lane
            have h_getD_a : pe_src.val.getD j 0#u16 =
                pe_src.val[j]'(by rw [h_pe_len]; exact hj) :=
              List.getD_eq_getElem _ _ (by rw [h_pe_len]; exact hj)
            have h_getD_b : pe_src.val.getD (j + len.val) 0#u16 =
                pe_src.val[j + len.val]'(by rw [h_pe_len]; exact hj_len) :=
              List.getD_eq_getElem _ _ (by rw [h_pe_len]; exact hj_len)
            rw [h_getD_a, h_getD_b] at h_lane
            unfold u16ToZq
            rw [h_lane]
            ring
          · -- h_pair_hi
            intro j hj_lo hj_hi
            have hj_hi' : j < start.val + len.val := by rw [h_iter_end] at hj_hi; exact hj_hi
            have hj : j < 256 := by omega
            have hj_len : j + len.val < 256 := by omega
            have hj_ge_ia : i_a.val ≤ j := by rw [h_i_a_val]; exact hj_lo
            have hjl_ge_ib : i_b.val ≤ j + len.val := by
              rw [h_i_b_val]; omega
            have hjl_lt_ib_2 : j + len.val < i_b.val + 2 := by
              rw [h_i_b_val, ← h_len_2]; omega
            have h_kdiff_lt : (j + len.val) - i_b.val < 2 := by
              rw [h_i_b_val, ← h_len_2]; omega
            have h_kdiff_lt' : j - i_a.val < 2 := by
              rw [h_i_a_val] at hj_ge_ia ⊢; omega
            have h_kdiff_lt'8 : j - i_a.val < 8 := by omega
            have h_pe2_at_jl : pe_src2.val[j + len.val]'(by rw [h_pe2_len]; exact hj_len) =
                (s.toLanes rb_v_c11)[j - i_a.val]'h_kdiff_lt'8 := by
              have hl := h_pe2_lane ⟨j + len.val, hj_len⟩
              simp at hl
              rw [hl, dif_pos ⟨hjl_ge_ib, hjl_lt_ib_2⟩]
              fcongr 1
              rw [h_i_a_val, h_i_b_val]; omega
            rw [h_toPoly_get pe_src2 (j + len.val) hj_len h_pe2_len,
                h_toPoly_get pe_src j hj h_pe_len,
                h_toPoly_get pe_src (j + len.val) hj_len h_pe_len]
            rw [h_pe2_at_jl]
            have h_lane := (rb_h_lane2 ⟨j - i_a.val, h_kdiff_lt'⟩ (by rw [h_len_2]; omega)
              (by rw [h_len_2, h_start_0])).2
            simp only at h_lane
            have h_a : start.val + iter.iter.start.val + (j - i_a.val) = j := by
              rw [h_i_a_val] at hj_ge_ia ⊢; omega
            have h_b : start.val + iter.iter.start.val + len.val + (j - i_a.val) =
                j + len.val := by
              rw [h_i_a_val] at hj_ge_ia ⊢; omega
            rw [h_a, h_b] at h_lane
            have h_getD_a : pe_src.val.getD j 0#u16 =
                pe_src.val[j]'(by rw [h_pe_len]; exact hj) :=
              List.getD_eq_getElem _ _ (by rw [h_pe_len]; exact hj)
            have h_getD_b : pe_src.val.getD (j + len.val) 0#u16 =
                pe_src.val[j + len.val]'(by rw [h_pe_len]; exact hj_len) :=
              List.getD_eq_getElem _ _ (by rw [h_pe_len]; exact hj_len)
            rw [h_getD_a, h_getD_b] at h_lane
            unfold u16ToZq
            rw [h_lane]
            ring
          · -- h_frame
            intro k hk h_not_lo h_not_hi
            have h_not_lo_k : ¬ (i_a.val ≤ k ∧ k < i_a.val + 2) := by
              rintro ⟨h1, h2⟩
              apply h_not_lo
              rw [h_i_a_val] at h1 h2
              refine ⟨h1, ?_⟩
              rw [h_iter_end, h_len_2]; omega
            have h_not_hi_k : ¬ (i_b.val ≤ k ∧ k < i_b.val + 2) := by
              rintro ⟨h1, h2⟩
              apply h_not_hi
              rw [h_i_b_val] at h1 h2
              rw [h_iter_end]
              refine ⟨by omega, by omega⟩
            have h_pe2_at_k : pe_src2.val[k]'(by rw [h_pe2_len]; exact hk) =
                pe_src1.val[k]'(by rw [h_pe1_len]; exact hk) := by
              have hl := h_pe2_lane ⟨k, hk⟩
              simp at hl
              rw [hl, dif_neg h_not_hi_k]
            have h_pe1_at_k : pe_src1.val[k]'(by rw [h_pe1_len]; exact hk) =
                pe_src.val[k]'(by rw [h_pe_len]; exact hk) := by
              have hl := h_pe1_lane ⟨k, hk⟩
              simp at hl
              rw [hl, dif_neg h_not_lo_k]
            rw [h_toPoly_get pe_src2 k hk h_pe2_len,
                h_toPoly_get pe_src k hk h_pe_len]
            rw [h_pe2_at_k, h_pe1_at_k]
        rw [h_pe2_butterfly]
  · -- NONE branch: iter exhausted, identity
    have hge : iter.iter.start.val ≥ iter.iter.«end».val := by
      have := hlt; omega
    let* ⟨ o, iter1, ho, hiter1_eq ⟩ ← core.iter.adapters.step_by.IteratorStepBy.next_Range_Usize_none_spec
    rw [ho]
    rw [poly_element_ntt_layer_vec128_loop0_loop0_step.fold]
    simp only [WP.spec_ok]
    refine ⟨h_wf, ?_⟩
    rw [nttButterflies_nil _ _ _ _ _ _ (by have := hge; omega)]
termination_by iter.iter.«end».val - iter.iter.start.val
decreasing_by all_goals scalar_decr_tac

/-- **Outer twiddle loop (vec128, parametric).**

Mirrors `poly_element_ntt_layer_generic_loop0.spec` (Ntt.lean:393)
except that each k-iteration broadcasts the twiddle to all 8 lanes via
`vec128_set_u16x8` and invokes the SIMD inner loop.

### Informal proof

By induction over the step-by iterator (canonical loop template).

* **NONE arm.** Identity result.
* **SOME arm.**
  1. `let* ⟨start_j, iter1, ho, hiter1_start, hiter1_end, hiter1_step⟩ ←
     core.iter.adapters.step_by.IteratorStepBy.next_Range_Usize_some_spec`.
  2. Read twiddles `tw := ZETA_BIT_REV_TIMES_R[k]`,
     `tw_mont := ZETA_BIT_REV_TIMES_R_TIMES_NEG_Q_INV_MOD_R[k]` —
     identical to the generic loop's `step as ⟨tw_u16, ...⟩` bridge.
  3. `vec128_set_u16x8_spec tw h_tw_lt`: produces `v_tw : V` with
     `s.wfVec v_tw ∧ ∀ i, (s.toLanes v_tw)[i] = tw` — feeds the inner
     loop's `h_v_tw_lane`.  Same for `v_tw_mont`.
  4. Bind `k1 := k + 1`.
  5. Build the inner step-by-8 iterator `iter2 := {start := 0, «end» := len, step := 8}`.
  6. **Inner call:** apply `_vec128_loop0_loop0.spec` with witnesses
     above; postcondition gives
     `toPoly pe_src1 = nttButterflies (u16ToZq tw * Rinv) (toPoly pe_src) len start_j (start_j + len) _`.
     Note `iter2.iter.start.val = 0`, `iter2.iter.«end».val = len.val`.
  7. **IH recursion** on `iter1` (`iter1.iter.start = iter.iter.start + step`)
     with `pe_src1` and `k1`.
  8. **Post composition.** Like generic `_loop0.spec`, fold the current
     start-step into `nttMidLayer`'s recursive shape: each step
     processes `2 * len` coefficients starting at the current
     `start_j`, advancing `k` and the start index.  By
     `nttMidLayer_step` (cf. generic spec's
     `nttMidLayer_eq_nttButterflies_compose`), the composition reduces
     to `nttMidLayer len _ iter.iter.start.val k.val (toPoly pe_src)`.

The proof is structurally identical to the generic outer loop's; only
the inner-loop call site differs.
-/
@[step]
theorem mlkem.ntt.poly_element_ntt_layer_vec128_loop0.spec
    (iter : core.iter.adapters.step_by.StepBy
              (core.ops.range.Range Std.Usize))
    (pe_src : PolyElement) (k len : Std.Usize)
    (h_wf : wfPoly pe_src) (h_len : 2 ≤ len.val) (h_lend : len.val ≤ 128)
    (h_div : 256 % (2 * len.val) = 0)
    (h_len_step : 8 ≤ len.val → len.val % 8 = 0)
    (h_inv : 2 * k.val * len.val + 256 ≤ 256 * len.val + iter.iter.start.val)
    (h_iter_end : iter.iter.«end».val = 256)
    (h_iter_step : iter.step_by.val = 2 * len.val)
    (h_iter_start : iter.iter.start.val ≤ 256 ∧
                    iter.iter.start.val % (2 * len.val) = 0) :
    mlkem.ntt.poly_element_ntt_layer_vec128_loop0 Inst iter pe_src k len
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r =
            (nttMidLayer len.val (by omega) iter.iter.start.val k.val
                (toPoly pe_src)).1 ⦄ := by
  unfold mlkem.ntt.poly_element_ntt_layer_vec128_loop0
  obtain ⟨h_start_le, h_start_mod⟩ := h_iter_start
  have h_2len_pos : 0 < 2 * len.val := by scalar_tac
  have h_2len_le : 2 * len.val ≤ 256 := by scalar_tac
  -- Derive the discrete-len disjunction (needed by the inner-loop spec).
  have h_len_form : 8 ≤ len.val ∨ len.val = 4 ∨ len.val = 2 := by
    interval_cases len.val <;> omega
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
    -- Index ZETA_BIT_REV_TIMES_R: tw_u16 with htw_zq, htw_bv, htw_lt.
    step as ⟨tw_u16, htw_zq, htw_bv, htw_lt⟩
    -- Broadcast: lane-eq only (weakened trait spec).
    step as ⟨v_tw, h_v_tw_lane⟩
    -- Index ZETA_NEG: tw_mont_u16 with htw_mont_bv, htw_mont_le, htw_mont_eq.
    step as ⟨tw_mont_u16, htw_mont_bv, htw_mont_le, htw_mont_eq⟩
    -- Broadcast mont companion: lane-eq only.
    step as ⟨v_tw_mont, h_v_tw_mont_lane_eq⟩
    step as ⟨k1, hk1_eq⟩
    -- Build inner step-by-8 iterator from {start := 0, «end» := len} step 8.
    step as ⟨iter2, hiter2_iter, hiter2_step⟩
    have hiter2_start_val : iter2.iter.start.val = 0 := by rw [hiter2_iter]; rfl
    have hiter2_end_val : iter2.iter.«end».val = len.val := by rw [hiter2_iter]
    have hiter2_step_val : iter2.step_by.val = 8 := by rw [hiter2_step]; rfl
    -- Derive wfVec for v_tw from lane-eq + tw_u16.val < q.
    have h_v_tw_wf : s.wfVec v_tw := by
      rw [s.wfVec_iff]
      intro i
      rw [h_v_tw_lane i]; exact htw_lt
    -- Convert mont broadcast lane-eq into Nat-form for inner-loop spec.
    have h_v_tw_mont_lane :
        ∀ i : Fin 8, ((s.toLanes v_tw_mont)[i.val].val : ℕ) = tw_mont_u16.val := by
      intro i; rw [h_v_tw_mont_lane_eq i]
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
      mlkem.ntt.poly_element_ntt_layer_vec128_loop0_loop0.spec iter2 pe_src len
        iter.iter.start v_tw v_tw_mont
        h_wf h_len h_lend h_start_bound
        hiter2_end_val hiter2_step_val (by intro _; rw [hiter2_start_val])
        h_len_step h_len_form
        tw_u16 htw_lt h_v_tw_wf h_v_tw_lane
        tw_mont_u16 h_twm_eq_inner h_v_tw_mont_lane
    -- Convert inner loop's `u16ToZq tw_u16 * Rinv` to `ζ^(bitRev 7 k.val)`.
    have h_u16ToZq_tw : u16ToZq tw_u16 = ζ ^ _root_.bitRev 7 k.val * 65536 := by
      simp [u16ToZq]
      exact_mod_cast htw_zq
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
      (mlkem.ntt.poly_element_ntt_layer_vec128_loop0.spec iter1 pe_src1 k1 len
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
    -- Align iter1.start, iter2 bounds, and k1 with the peeled mid-step.
    have hs1v : iter1.iter.start.val = iter.iter.start.val + 2 * len.val := by
      rw [hiter1_start, h_iter_step]
    have hk1v : k1.val = k.val + 1 := hk1_eq
    simp only [hiter2_start_val, hiter2_end_val, Nat.add_zero] at hto_poly1 ⊢
    rw [hs1v, hk1v]
  · -- NONE branch: iter exhausted.
    have hge : iter.iter.start.val ≥ iter.iter.«end».val := by omega
    let* ⟨o, iter1, ho, _⟩ ← core.iter.adapters.step_by.IteratorStepBy.next_Range_Usize_none_spec
    rw [ho]
    simp only [WP.spec_ok]
    refine ⟨h_wf, ?_⟩
    have h_start_eq : iter.iter.start.val = 256 := by omega
    rw [show (nttMidLayer len.val (by omega) iter.iter.start.val k.val (toPoly pe_src)).1 =
            toPoly pe_src from ?_]
    · conv_lhs => rw [nttMidLayer]
      rw [dif_neg (by rw [h_start_eq]; omega)]
termination_by 256 - iter.iter.start.val
decreasing_by
  rw [hiter1_start, h_iter_step]
  omega

/-- **Top wrapper (vec128, parametric).**

Mirrors `poly_element_ntt_layer_generic.spec` (Ntt.lean:574) verbatim.

### Informal proof

Unfold `_vec128`; the body computes `i := 2 * len`, builds the
step-by-`i` iterator over `[0, 256)`, then calls `_loop0`.  The proof
is a one-step delegation:

1. `step as ⟨i, hi⟩` for the `i ← 2 * len` arithmetic.
2. `simp only [core.iter.traits.iterator.Iterator.step_by.trait_default, core.iter.traits.iterator.Iterator.step_by.default, ...]`.
3. `apply WP.spec_mono`; apply `_loop0.spec` with
   `iter := ⟨{ start := 0, «end» := 256 }, i ⟩`.
4. Discharge preconditions (all immediate from inputs).
5. Forward post: `nttMidLayer len _ 0 k (toPoly pe_src)`.
-/
@[step]
theorem mlkem.ntt.poly_element_ntt_layer_vec128.spec
    (pe_src : PolyElement) (k len : Std.Usize)
    (h_wf : wfPoly pe_src) (h_len : 2 ≤ len.val) (h_lend : len.val ≤ 128)
    (h_div : 256 % (2 * len.val) = 0)
    (h_len_step : 8 ≤ len.val → len.val % 8 = 0)
    (h_k : 2 * k.val * len.val + 256 ≤ 256 * len.val) :
    mlkem.ntt.poly_element_ntt_layer_vec128 Inst pe_src k len
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r =
            (nttMidLayer len.val (by omega) 0 k.val (toPoly pe_src)).1 ⦄ := by
  unfold mlkem.ntt.poly_element_ntt_layer_vec128
  step as ⟨i, hi⟩
  simp only [core.iter.traits.iterator.Iterator.step_by.trait_default, core.iter.traits.iterator.Iterator.step_by.default,
    show ¬ (i.val = 0) from by agrind, if_false]
  apply WP.spec_mono
  · apply mlkem.ntt.poly_element_ntt_layer_vec128_loop0.spec
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
