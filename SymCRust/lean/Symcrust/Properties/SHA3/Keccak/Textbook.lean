import Symcrust.Properties.SHA3.Keccak.Loop
import Mathlib.Tactic.IntervalCases

/-!
# Keccak-f[1600] Textbook Implementation — FIPS 202 §3.3 Direct Form

Proves the textbook Keccak permutation correct. Unlike `keccak_permute_opt`
(fused θ∘ρ∘π one-pass + interleaved χ), the textbook implementation in
`src/sha3/sha3_impl.rs` follows FIPS 202 §3.3 literally:

  for r in 0..24 { keccak_theta; keccak_rho; keccak_pi; keccak_chi; keccak_iota }

Both implementations exist in the Rust source. Production code routes through
`keccak_permute → keccak_permute_opt` (the fused, faster variant); the textbook
variant is reached only via the proof harness and the in-crate cross-validation
test `test_keccak_permute_textbook_matches_opt`.

This file proves `keccak_permute_textbook.spec` against the same FIPS-202
characterisation as `keccak_permute_opt.spec` (`toState result = iterateRnd
(toState state) 24`) and derives the equivalence corollary
`keccak_permute_textbook_eq_opt` by transitivity.

## Reuse from Core/Fold/Loop

The hard cryptographic algebra is done in `Keccak/Core.lean`:
- `thetaCore`, `rhoCore`, `piCore`, `chiCore` — Lanes25-form pure functions
- `*_toState` — bridges from `Lanes25` to FIPS 202 `State`
- `fusedCore_eq_composed : fusedCore s = chiCore (piCore (rhoCore (thetaCore s)))`
- `iterateRndCore`, `iterateRndCore_toState`, `iterateRndCore_succ`
- `iota_k_eq_RC`, `toState_iota`, `fusedRoundCore_toState'`

The textbook proofs reuse these directly. The only new content is:
- `@[step]` specs for the five extracted phase functions (`keccak_theta`, etc.),
  relating each Rust function on `Array U64 25` to its `*Core` counterpart on
  `Lanes25`;
- `@[step]` spec for `keccak_perm_round` composing the five via
  `fusedCore_eq_composed`;
- `@[step]` spec for `keccak_permute_textbook_loop` mirroring the
  `keccak_permute_opt_loop` skeleton (recursive-loop pattern: unfold, by_cases,
  let* iterator, manual IH via `WP.spec_mono`);
- wrapper `@[step]` spec and the equivalence corollary.

The textbook loop spec is structurally simpler than the opt loop spec because
the loop carries the state as a plain `Array U64 25#usize`, not unrolled into
25 individual U64s — no `body_fused`, no `#decompose` prefix, no Lanes25-tuple
constructor in `step*` binders.
-/

namespace symcrust

open Aeneas Aeneas.Std Result
open Spec
open Spec.SHA3 (w)
open sha3.sha3_impl
open scoped Spec.SHA3
open scoped Spec.Notations

/- Fast default for array bound goals: `scalar_tac` directly, else rewrite
   `arr.val.length` to the (statically known) type size via `Array.length_eq`
   and retry. Discharges `k < result.val.length` even for output arrays
   (length fixed by the `Array _ 25` type), so per-cell `[]` posts elaborate
   without the deprecated `]!` (provided the bound is a *named* hypothesis,
   e.g. `∀ k (hk : k < 25), …`). -/
local macro_rules | `(tactic| get_elem_tactic) => `(tactic| first | assumption | (simp only [Aeneas.Std.Array.length_eq, List.length_set]; assumption) | scalar_tac | (simp only [Aeneas.Std.Array.length_eq, List.length_set]; scalar_tac))

open symcrust (thetaCore rhoCore piCore chiCore fusedCore fusedRoundCore
  iterateRndCore)

/- File-level `maxRecDepth`: the `get_elem_tactic` override runs `scalar_tac`
   inside a nested `by`-block during elaboration; a per-theorem `set_option …
   in` does NOT propagate there, so we raise the default for the whole file. -/
set_option maxRecDepth 4096

/-! ## Bridge lemmas: `Lanes25.ofArray` through `Std.Array.set`

The textbook phase functions (`keccak_theta`, `keccak_rho`, `keccak_pi`,
`keccak_chi`) are extracted as long chains of `Std.Array.set` calls.
`step*` reduces a call to such a sequence of monadic `.set` and
`.index_usize` operations; the resulting goal is

  `Lanes25.ofArray ((...((state.set i₁ v₁).set i₂ v₂)...).set i₂₄ v₂₄)
    = piCore (Lanes25.ofArray state)`

To bridge the LHS (Aeneas `Std.Array.set` chain) into the structure form
used by `piCore` etc., we expose **25 specialized simp lemmas**, one per
constant index `0..24`. Each lemma reduces a single `.set` through
`Lanes25.ofArray` into a `Lanes25` field update. Stacked as simp lemmas,
they mechanically peel a chain of `.set`s into a `Lanes25.mk` literal —
fast and no whnf blowup.

Local to this file (private `scoped` attribute) because the `.set i#usize`
shape is specific to fully unrolled phase functions. -/

namespace sha3.sha3_impl

@[scoped simp]
private theorem Lanes25.ofArray_set_0 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 0#usize v) = { Lanes25.ofArray a with l0 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_1 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 1#usize v) = { Lanes25.ofArray a with l1 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_2 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 2#usize v) = { Lanes25.ofArray a with l2 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_3 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 3#usize v) = { Lanes25.ofArray a with l3 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_4 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 4#usize v) = { Lanes25.ofArray a with l4 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_5 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 5#usize v) = { Lanes25.ofArray a with l5 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_6 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 6#usize v) = { Lanes25.ofArray a with l6 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_7 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 7#usize v) = { Lanes25.ofArray a with l7 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_8 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 8#usize v) = { Lanes25.ofArray a with l8 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_9 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 9#usize v) = { Lanes25.ofArray a with l9 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_10 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 10#usize v) = { Lanes25.ofArray a with l10 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_11 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 11#usize v) = { Lanes25.ofArray a with l11 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_12 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 12#usize v) = { Lanes25.ofArray a with l12 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_13 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 13#usize v) = { Lanes25.ofArray a with l13 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_14 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 14#usize v) = { Lanes25.ofArray a with l14 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_15 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 15#usize v) = { Lanes25.ofArray a with l15 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_16 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 16#usize v) = { Lanes25.ofArray a with l16 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_17 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 17#usize v) = { Lanes25.ofArray a with l17 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_18 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 18#usize v) = { Lanes25.ofArray a with l18 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_19 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 19#usize v) = { Lanes25.ofArray a with l19 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_20 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 20#usize v) = { Lanes25.ofArray a with l20 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_21 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 21#usize v) = { Lanes25.ofArray a with l21 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_22 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 22#usize v) = { Lanes25.ofArray a with l22 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_23 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 23#usize v) = { Lanes25.ofArray a with l23 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

@[scoped simp]
private theorem Lanes25.ofArray_set_24 (a : Keccak1600) (v : U64) :
    Lanes25.ofArray (a.set 24#usize v) = { Lanes25.ofArray a with l24 := v } := by
  simp [Lanes25.ofArray, Aeneas.Std.Array.set_val_eq]

end sha3.sha3_impl

/-! ## Step specs for the five FIPS 202 phase functions

Each spec states that the Rust function, viewed as a transformation on
`Lanes25`, matches the corresponding `*Core` function from `Keccak/Core.lean`.
The proofs unfold the extracted body, `step*` through the per-lane reads
and writes, and close by extensionality on `Lanes25` (or equivalently by
`Fin5x5_cases` per `(x, y)`). -/

/-! ### Helper spec: column-sum -/

set_option maxRecDepth 2048 in
/-- `keccak_column_sum state c` returns the XOR of the five lanes in column `c`
(rows 0..4 at index `c + 5 * row`). Used by `keccak_theta`. -/
@[step]
theorem keccak_column_sum.spec (state : Keccak1600) (c : Usize) (hc : c.val < 5) :
    sha3.sha3_impl.keccak_column_sum state c
    ⦃ (r : U64) =>
      r.bv = state.val[c.val].bv ^^^ state.val[c.val + 5].bv ^^^
             state.val[c.val + 10].bv ^^^ state.val[c.val + 15].bv ^^^
             state.val[c.val + 20].bv ⦄ := by
  unfold sha3.sha3_impl.keccak_column_sum
  step*
  have hlen : state.val.length = 25 := by simp
  have h_i   : i.val   < state.val.length := by rw [hlen]; scalar_tac
  have h_i2  : i2.val  < state.val.length := by rw [hlen]; scalar_tac
  have h_i5  : i5.val  < state.val.length := by rw [hlen]; scalar_tac
  have h_i8  : i8.val  < state.val.length := by rw [hlen]; scalar_tac
  have h_i11 : i11.val < state.val.length := by rw [hlen]; scalar_tac
  simp only [show i.val   = c.val      from by scalar_tac] at i1_post
  simp only [show i2.val  = c.val + 5  from by scalar_tac] at i3_post
  simp only [show i5.val  = c.val + 10 from by scalar_tac] at i6_post
  simp only [show i8.val  = c.val + 15 from by scalar_tac] at i9_post
  simp only [show i11.val = c.val + 20 from by scalar_tac] at i12_post
  bv_tac 64

/-! ### Helper spec: column-update

`keccak_column_update state c w` XORs `w` into the five lanes of column `c`
(rows 0..4 at indices `c, c+5, c+10, c+15, c+20`). Used by `keccak_theta`.

The post is stated per-cell over the underlying list: for each k < 25,
`result.val[k] = state.val[k] ^^^ w` when `k % 5 = c.val`, else
`state.val[k]`. This formulation avoids materialising a 5-set chain at
symbolic `c+N` indices in the proof, and lets `keccak_theta.spec`
discharge the column structure with a per-lane `simp_lists`. -/

set_option maxHeartbeats 10000000 in
set_option maxRecDepth 2048 in
@[step]
theorem keccak_column_update.spec (state : Keccak1600) (c : Usize) (w : U64)
    (hc : c.val < 5) :
    sha3.sha3_impl.keccak_column_update state c w
    ⦃ (result : Keccak1600) =>
      result.val.length = 25 ∧
      ∀ k (hk : k < 25),
        result.val[k] =
          (if k % 5 = c.val then state.val[k] ^^^ w else state.val[k]) ⦄ := by
  unfold sha3.sha3_impl.keccak_column_update
  step*
  refine ⟨by simp, fun k hk => ?_⟩
  subst result_post state4_post state3_post state2_post state1_post
  simp only [Std.Array.set_val_eq] at *
  have hL : state.val.length = 25 := by simp
  have hi   : i.val   = c.val      := by scalar_tac
  have hi3  : i3.val  = c.val + 5  := by scalar_tac
  have hi6  : i6.val  = c.val + 10 := by scalar_tac
  have hi9  : i9.val  = c.val + 15 := by scalar_tac
  have hi12 : i12.val = c.val + 20 := by scalar_tac
  have h5_0   : c.val + 5  ≠ c.val      := by scalar_tac
  have h10_0  : c.val + 10 ≠ c.val      := by scalar_tac
  have h10_5  : c.val + 10 ≠ c.val + 5  := by scalar_tac
  have h15_0  : c.val + 15 ≠ c.val      := by scalar_tac
  have h15_5  : c.val + 15 ≠ c.val + 5  := by scalar_tac
  have h15_10 : c.val + 15 ≠ c.val + 10 := by scalar_tac
  have h20_0  : c.val + 20 ≠ c.val      := by scalar_tac
  have h20_5  : c.val + 20 ≠ c.val + 5  := by scalar_tac
  have h20_10 : c.val + 20 ≠ c.val + 10 := by scalar_tac
  have h20_15 : c.val + 20 ≠ c.val + 15 := by scalar_tac
  -- Reduce each chained read to a state.val[c.val + N] form
  have e1  : i1  = state.val[c.val]      := by
    simp only [i1_post, hi]
  have e4  : i4  = state.val[c.val + 5]  := by
    rw [i4_post]
    simp_lists [hi3, hi, h5_0]
  have e7  : i7  = state.val[c.val + 10] := by
    rw [i7_post]
    simp_lists [hi6, hi3, hi, h10_5, h10_0]
  have e10 : i10 = state.val[c.val + 15] := by
    rw [i10_post]
    simp_lists [hi9, hi6, hi3, hi, h15_10, h15_5, h15_0]
  have e13 : i13 = state.val[c.val + 20] := by
    rw [i13_post]
    simp_lists [hi12, hi9, hi6, hi3, hi, h20_15, h20_10, h20_5, h20_0]
  have v2  : i2  = state.val[c.val]      ^^^ w := by apply U64.bv_eq_imp_eq; simp [i2_post2, e1]
  have v5  : i5  = state.val[c.val + 5]  ^^^ w := by apply U64.bv_eq_imp_eq; simp [i5_post2, e4]
  have v8  : i8  = state.val[c.val + 10] ^^^ w := by apply U64.bv_eq_imp_eq; simp [i8_post2, e7]
  have v11 : i11 = state.val[c.val + 15] ^^^ w := by apply U64.bv_eq_imp_eq; simp [i11_post2, e10]
  have v14 : i14 = state.val[c.val + 20] ^^^ w := by apply U64.bv_eq_imp_eq; simp [i14_post2, e13]
  simp only [v2, v5, v8, v11, v14, hi, hi3, hi6, hi9, hi12]
  -- Goal: chain[k] = if k%5 = c.val then state.val[k] ^^^ w else state.val[k]
  by_cases hkmod : k % 5 = c.val
  · -- Hit case: k = c.val + 5*j for some j ∈ {0..4}
    rw [if_pos hkmod]
    have hjbnd : k / 5 < 5 := by scalar_tac
    have hkeq  : k = c.val + 5 * (k / 5) := by scalar_tac
    simp only [getElem_congr_idx hkeq]
    interval_cases (k / 5) <;>
      (simp only [Nat.mul_zero, Nat.mul_one, Nat.add_zero,
                  show (5:Nat) * 2 = 10 from rfl, show (5:Nat) * 3 = 15 from rfl,
                  show (5:Nat) * 4 = 20 from rfl];
       simp_lists [h5_0, h10_0, h15_0, h20_0, h10_5, h15_5, h20_5, h15_10, h20_10, h20_15])
  · -- Miss case: k is in a different column; 5 set_ne reductions
    rw [if_neg hkmod]
    have h0  : k ≠ c.val      := fun h => hkmod (by rw [h]; scalar_tac)
    have h5  : k ≠ c.val + 5  := fun h => hkmod (by rw [h]; scalar_tac)
    have h10 : k ≠ c.val + 10 := fun h => hkmod (by rw [h]; scalar_tac)
    have h15 : k ≠ c.val + 15 := fun h => hkmod (by rw [h]; scalar_tac)
    have h20 : k ≠ c.val + 20 := fun h => hkmod (by rw [h]; scalar_tac)
    simp_lists [h0, h5, h10, h15, h20]

set_option maxHeartbeats 10000000 in
set_option maxRecDepth 2048 in
@[step]
theorem keccak_theta.spec (state : Keccak1600) :
    keccak_theta state
    ⦃ (result : Keccak1600) =>
      Lanes25.ofArray result = thetaCore (Lanes25.ofArray state) ⦄ := by
  unfold keccak_theta
  step*
  have h_i5_eq  : i5  = i4 := by
    rw [i5_post];  simp_lists [col_sum5_post, col_sum4_post, col_sum3_post, col_sum2_post, col_sum1_post]
  have h_i6_eq  : i6  = i1 := by
    rw [i6_post];  simp_lists [col_sum5_post, col_sum4_post, col_sum3_post, col_sum2_post, col_sum1_post]
  have h_i9_eq  : i9  = i  := by
    rw [i9_post];  simp_lists [col_sum5_post, col_sum4_post, col_sum3_post, col_sum2_post, col_sum1_post]
  have h_i10_eq : i10 = i2 := by
    rw [i10_post]; simp_lists [col_sum5_post, col_sum4_post, col_sum3_post, col_sum2_post, col_sum1_post]
  have h_i13_eq : i13 = i3 := by
    rw [i13_post]; simp_lists [col_sum5_post, col_sum4_post, col_sum3_post, col_sum2_post, col_sum1_post]
  have h_i7_bv  : i7.bv  = i1.bv.rotateLeft 1 := by
    rw [i7_post, h_i6_eq]; rfl
  have h_i11_bv : i11.bv = i2.bv.rotateLeft 1 := by
    rw [i11_post, h_i10_eq]; rfl
  have h_i14_bv : i14.bv = i3.bv.rotateLeft 1 := by
    rw [i14_post, h_i13_eq]; rfl
  have h_i16_bv : i16.bv = i4.bv.rotateLeft 1 := by
    rw [i16_post, h_i5_eq]; rfl
  have h_i18_bv : i18.bv = i.bv.rotateLeft 1 := by
    rw [i18_post, h_i9_eq]; rfl
  apply Lanes25.ext <;>
    (dsimp only [Lanes25.ofArray, thetaCore]
     rw [result_post2 _ (by decide), state4_post2 _ (by decide),
         state3_post2 _ (by decide), state2_post2 _ (by decide),
         state1_post2 _ (by decide)]
     simp only [Nat.reduceMod, Nat.reduceEqDiff, ↓reduceIte]
     apply U64.bv_eq_imp_eq
     simp only [UScalar.bv_xor, i8_post2, i12_post2, i15_post2, i17_post2, i19_post2,
                h_i5_eq, h_i6_eq, h_i9_eq, h_i10_eq, h_i13_eq,
                h_i7_bv, h_i11_bv, h_i14_bv, h_i16_bv, h_i18_bv,
                i_post, i1_post, i2_post, i3_post, i4_post,
                core.num.U64.rotate_left, UScalar.rotate_left]
     bv_tac 64)

/-! ### Helper spec: ρ-row 0 (lane 0 unchanged, lanes 1..4 rotated) -/

set_option maxHeartbeats 4000000 in
@[local step]
private theorem keccak_rho_row0.spec (state : Keccak1600) :
    sha3.sha3_impl.keccak_rho_row0 state
    ⦃ (result : Keccak1600) =>
      Lanes25.ofArray result =
        { Lanes25.ofArray state with
          l1 := core.num.U64.rotate_left (Lanes25.ofArray state).l1 1#u32,
          l2 := core.num.U64.rotate_left (Lanes25.ofArray state).l2 62#u32,
          l3 := core.num.U64.rotate_left (Lanes25.ofArray state).l3 28#u32,
          l4 := core.num.U64.rotate_left (Lanes25.ofArray state).l4 27#u32 } ⦄ := by
  unfold sha3.sha3_impl.keccak_rho_row0
  step*
  have h_rho1 : (sha3.sha3_impl.KECCAK_RHO_K).val[1] = 1#u32 := by
    unfold sha3.sha3_impl.KECCAK_RHO_K; decide
  have h_rho2 : (sha3.sha3_impl.KECCAK_RHO_K).val[2] = 62#u32 := by
    unfold sha3.sha3_impl.KECCAK_RHO_K; decide
  have h_rho3 : (sha3.sha3_impl.KECCAK_RHO_K).val[3] = 28#u32 := by
    unfold sha3.sha3_impl.KECCAK_RHO_K; decide
  have h_rho4 : (sha3.sha3_impl.KECCAK_RHO_K).val[4] = 27#u32 := by
    unfold sha3.sha3_impl.KECCAK_RHO_K; decide
  have hL_state : state.val.length = 25 := by simp
  have h_i1  : i1  = 1#u32  := by rw [i1_post, h_rho1]
  have h_i4  : i4  = 62#u32 := by rw [i4_post, h_rho2]
  have h_i7  : i7  = 28#u32 := by rw [i7_post, h_rho3]
  have h_i10 : i10 = 27#u32 := by rw [i10_post, h_rho4]
  have h_i   : i = state.val[1] := by rw [i_post]
  have h_i3  : i3 = state.val[2] := by
    rw [i3_post, state1_post]; simp_lists
  have h_i6  : i6 = state.val[3] := by
    rw [i6_post, state2_post, state1_post]; simp_lists
  have h_i9  : i9 = state.val[4] := by
    rw [i9_post, state3_post, state2_post, state1_post]; simp_lists
  have e1 : i2  = core.num.U64.rotate_left (Lanes25.ofArray state).l1 1#u32 := by
    rw [i2_post, h_i, h_i1]; rfl
  have e2 : i5  = core.num.U64.rotate_left (Lanes25.ofArray state).l2 62#u32 := by
    rw [i5_post, h_i3, h_i4]; rfl
  have e3 : i8  = core.num.U64.rotate_left (Lanes25.ofArray state).l3 28#u32 := by
    rw [i8_post, h_i6, h_i7]; rfl
  have e4 : i11 = core.num.U64.rotate_left (Lanes25.ofArray state).l4 27#u32 := by
    rw [i11_post, h_i9, h_i10]; rfl
  subst result_post state3_post state2_post state1_post
  simp only [Lanes25.ofArray_set_4, Lanes25.ofArray_set_3, Lanes25.ofArray_set_2,
             Lanes25.ofArray_set_1, e1, e2, e3, e4]

/-! ### `keccak_rho_row` decomposed into 5 per-lane phases via `#decompose`

The naïve per-cell recipe (used for `keccak_rho_row0`, 11 bindings) does NOT
scale to `keccak_rho_row` (30+ bindings) — both `simp only [...] at *` (32768
maxRecDepth) and `simp_lists` (4096 maxRecDepth) overflow on the giant
context. Splitting into 5 phases (one per lane update) keeps each phase's
context small enough for the per-cell recipe to work cleanly.

After the prefix `i ← 5*r`, the body has 5 phases of 7 bindings each:
  phase j: read state[i+j], read K[i+j], rotate, update state at i+j

Each phase's helper spec is then small enough to prove via `unfold + step*
+ rfl/simp_lists`. The main `keccak_rho_row.spec` composes them via
`rw [fold5] + step*`. -/

set_option maxRecDepth 2048 in
#decompose sha3.sha3_impl.keccak_rho_row keccak_rho_row.fold5
  letRange 1 7 => rho_row_phase0
  letRange 2 7 => rho_row_phase1
  letRange 3 7 => rho_row_phase2
  letRange 4 7 => rho_row_phase3
  letRange 5 7 => rho_row_phase4

/-! ### Per-phase specs -/

@[local step]
private theorem rho_row_phase0.spec (state : Keccak1600) (i : Usize)
    (hi : i.val + 4 < 25) :
    rho_row_phase0 state i
    ⦃ (result : Keccak1600) =>
      result.val.length = 25 ∧
      ∀ k (hk : k < 25),
        result.val[k] =
          (if k = i.val
           then core.num.U64.rotate_left state.val[k]
                  (sha3.sha3_impl.KECCAK_RHO_K.val[k])
           else state.val[k]) ⦄ := by
  unfold rho_row_phase0
  step*
  have hi_lt : i.val < 25 := Nat.lt_of_add_right_lt hi
  have hi1 : i1.val = i.val := by simp [i1_post]
  have hi3 : i3.val = i.val := by simp [i3_post]
  have hi6 : i6.val = i.val := by simp [i6_post]
  have hL : state.val.length = 25 := Aeneas.Std.Array.length_eq state
  have hL_KECCAK : sha3.sha3_impl.KECCAK_RHO_K.val.length = 25 :=
    Aeneas.Std.Array.length_eq _
  have hLi : i.val < state.val.length := by rw [hL]; exact hi_lt
  have hLi1 : i1.val < state.val.length := by rw [hi1]; exact hLi
  have hLi3 : i3.val < sha3.sha3_impl.KECCAK_RHO_K.val.length := by
    rw [hL_KECCAK, hi3]; exact hi_lt
  have h_i2 : i2 = state.val[i.val] := by
    simp only [i2_post, hi1]
  have h_i4 : i4 = sha3.sha3_impl.KECCAK_RHO_K.val[i.val] := by
    simp only [i4_post, hi3]
  have h_e : i5 = core.num.U64.rotate_left state.val[i.val]
                     sha3.sha3_impl.KECCAK_RHO_K.val[i.val] := by
    rw [i5_post, h_i2, h_i4]
  refine ⟨?_, ?_⟩
  · rw [result_post]; simp [Aeneas.Std.Array.set_val_eq]
  intro k hk
  rw [result_post]
  simp only [Aeneas.Std.Array.set_val_eq, hi6]
  by_cases hk_eq : k = i.val
  · subst hk_eq
    have hLset : i.val < (state.val.set i.val i5).length := by
      rw [List.length_set]; exact hLi
    rw [if_pos rfl,
        
        List.getElem_set_self, h_e]
  · have hLk : k < (state.val.set i.val i5).length := by
      rw [List.length_set, hL]; exact hk
    rw [if_neg hk_eq,
        
        List.getElem_set_ne (Ne.symm hk_eq)
]

@[local step]
private theorem rho_row_phase1.spec (i : Usize) (state : Keccak1600)
    (hi : i.val + 4 < 25) :
    rho_row_phase1 i state
    ⦃ (result : Keccak1600) =>
      result.val.length = 25 ∧
      ∀ k (hk : k < 25),
        result.val[k] =
          (if k = i.val + 1
           then core.num.U64.rotate_left state.val[k]
                  (sha3.sha3_impl.KECCAK_RHO_K.val[k])
           else state.val[k]) ⦄ := by
  have hi_lt : i.val + 1 < 25 := by scalar_tac
  unfold rho_row_phase1
  step*
  have hi7  : i7.val  = i.val + 1 := by simp [i7_post]
  have hi9  : i9.val  = i.val + 1 := by simp [i9_post]
  have hi12 : i12.val = i.val + 1 := by simp [i12_post]
  have hL : state.val.length = 25 := Aeneas.Std.Array.length_eq state
  have hL_KECCAK : sha3.sha3_impl.KECCAK_RHO_K.val.length = 25 :=
    Aeneas.Std.Array.length_eq _
  have hLi : i.val + 1 < state.val.length := by rw [hL]; exact hi_lt
  have hLi7 : i7.val < state.val.length := by rw [hi7]; exact hLi
  have hLi9 : i9.val < sha3.sha3_impl.KECCAK_RHO_K.val.length := by
    rw [hL_KECCAK, hi9]; exact hi_lt
  have h_i8 : i8 = state.val[i.val + 1] := by
    simp only [i8_post, hi7]
  have h_i10 : i10 = sha3.sha3_impl.KECCAK_RHO_K.val[i.val + 1] := by
    simp only [i10_post, hi9]
  have h_e : i11 = core.num.U64.rotate_left state.val[i.val + 1]
                       sha3.sha3_impl.KECCAK_RHO_K.val[i.val + 1] := by
    rw [i11_post, h_i8, h_i10]
  refine ⟨?_, ?_⟩
  · rw [result_post]; simp [Aeneas.Std.Array.set_val_eq]
  intro k hk
  rw [result_post]
  simp only [Aeneas.Std.Array.set_val_eq, hi12]
  by_cases hk_eq : k = i.val + 1
  · subst hk_eq
    have hLset : (i.val + 1) < (state.val.set (i.val + 1) i11).length := by
      rw [List.length_set]; exact hLi
    rw [if_pos rfl,
        
        List.getElem_set_self, h_e]
  · have hLk : k < (state.val.set (i.val + 1) i11).length := by
      rw [List.length_set, hL]; exact hk
    rw [if_neg hk_eq,
        
        List.getElem_set_ne (Ne.symm hk_eq)
]

@[local step]
private theorem rho_row_phase2.spec (i : Usize) (state : Keccak1600)
    (hi : i.val + 4 < 25) :
    rho_row_phase2 i state
    ⦃ (result : Keccak1600) =>
      result.val.length = 25 ∧
      ∀ k (hk : k < 25),
        result.val[k] =
          (if k = i.val + 2
           then core.num.U64.rotate_left state.val[k]
                  (sha3.sha3_impl.KECCAK_RHO_K.val[k])
           else state.val[k]) ⦄ := by
  have hi_lt : i.val + 2 < 25 := by scalar_tac
  unfold rho_row_phase2
  step*
  have hi13 : i13.val = i.val + 2 := by simp [i13_post]
  have hi15 : i15.val = i.val + 2 := by simp [i15_post]
  have hi18 : i18.val = i.val + 2 := by simp [i18_post]
  have hL : state.val.length = 25 := Aeneas.Std.Array.length_eq state
  have hL_KECCAK : sha3.sha3_impl.KECCAK_RHO_K.val.length = 25 :=
    Aeneas.Std.Array.length_eq _
  have hLi : i.val + 2 < state.val.length := by rw [hL]; exact hi_lt
  have hLi13 : i13.val < state.val.length := by rw [hi13]; exact hLi
  have hLi15 : i15.val < sha3.sha3_impl.KECCAK_RHO_K.val.length := by
    rw [hL_KECCAK, hi15]; exact hi_lt
  have h_i14 : i14 = state.val[i.val + 2] := by
    simp only [i14_post, hi13]
  have h_i16 : i16 = sha3.sha3_impl.KECCAK_RHO_K.val[i.val + 2] := by
    simp only [i16_post, hi15]
  have h_e : i17 = core.num.U64.rotate_left state.val[i.val + 2]
                       sha3.sha3_impl.KECCAK_RHO_K.val[i.val + 2] := by
    rw [i17_post, h_i14, h_i16]
  refine ⟨?_, ?_⟩
  · rw [result_post]; simp [Aeneas.Std.Array.set_val_eq]
  intro k hk
  rw [result_post]
  simp only [Aeneas.Std.Array.set_val_eq, hi18]
  by_cases hk_eq : k = i.val + 2
  · subst hk_eq
    have hLset : (i.val + 2) < (state.val.set (i.val + 2) i17).length := by
      rw [List.length_set]; exact hLi
    rw [if_pos rfl,
        
        List.getElem_set_self, h_e]
  · have hLk : k < (state.val.set (i.val + 2) i17).length := by
      rw [List.length_set, hL]; exact hk
    rw [if_neg hk_eq,
        
        List.getElem_set_ne (Ne.symm hk_eq)
]

@[local step]
private theorem rho_row_phase3.spec (i : Usize) (state : Keccak1600)
    (hi : i.val + 4 < 25) :
    rho_row_phase3 i state
    ⦃ (result : Keccak1600) =>
      result.val.length = 25 ∧
      ∀ k (hk : k < 25),
        result.val[k] =
          (if k = i.val + 3
           then core.num.U64.rotate_left state.val[k]
                  (sha3.sha3_impl.KECCAK_RHO_K.val[k])
           else state.val[k]) ⦄ := by
  have hi_lt : i.val + 3 < 25 := by scalar_tac
  unfold rho_row_phase3
  step*
  have hi19 : i19.val = i.val + 3 := by simp [i19_post]
  have hi21 : i21.val = i.val + 3 := by simp [i21_post]
  have hi24 : i24.val = i.val + 3 := by simp [i24_post]
  have hL : state.val.length = 25 := Aeneas.Std.Array.length_eq state
  have hL_KECCAK : sha3.sha3_impl.KECCAK_RHO_K.val.length = 25 :=
    Aeneas.Std.Array.length_eq _
  have hLi : i.val + 3 < state.val.length := by rw [hL]; exact hi_lt
  have hLi19 : i19.val < state.val.length := by rw [hi19]; exact hLi
  have hLi21 : i21.val < sha3.sha3_impl.KECCAK_RHO_K.val.length := by
    rw [hL_KECCAK, hi21]; exact hi_lt
  have h_i20 : i20 = state.val[i.val + 3] := by
    simp only [i20_post, hi19]
  have h_i22 : i22 = sha3.sha3_impl.KECCAK_RHO_K.val[i.val + 3] := by
    simp only [i22_post, hi21]
  have h_e : i23 = core.num.U64.rotate_left state.val[i.val + 3]
                       sha3.sha3_impl.KECCAK_RHO_K.val[i.val + 3] := by
    rw [i23_post, h_i20, h_i22]
  refine ⟨?_, ?_⟩
  · rw [result_post]; simp [Aeneas.Std.Array.set_val_eq]
  intro k hk
  rw [result_post]
  simp only [Aeneas.Std.Array.set_val_eq, hi24]
  by_cases hk_eq : k = i.val + 3
  · subst hk_eq
    have hLset : (i.val + 3) < (state.val.set (i.val + 3) i23).length := by
      rw [List.length_set]; exact hLi
    rw [if_pos rfl,
        
        List.getElem_set_self, h_e]
  · have hLk : k < (state.val.set (i.val + 3) i23).length := by
      rw [List.length_set, hL]; exact hk
    rw [if_neg hk_eq,
        
        List.getElem_set_ne (Ne.symm hk_eq)
]

@[local step]
private theorem rho_row_phase4.spec (i : Usize) (state : Keccak1600)
    (hi : i.val + 4 < 25) :
    rho_row_phase4 i state
    ⦃ (result : Keccak1600) =>
      result.val.length = 25 ∧
      ∀ k (hk : k < 25),
        result.val[k] =
          (if k = i.val + 4
           then core.num.U64.rotate_left state.val[k]
                  (sha3.sha3_impl.KECCAK_RHO_K.val[k])
           else state.val[k]) ⦄ := by
  have hi_lt : i.val + 4 < 25 := hi
  unfold rho_row_phase4
  step*
  have hi25 : i25.val = i.val + 4 := by simp [i25_post]
  have hi27 : i27.val = i.val + 4 := by simp [i27_post]
  have hi30 : i30.val = i.val + 4 := by simp [i30_post]
  have hL : state.val.length = 25 := Aeneas.Std.Array.length_eq state
  have hL_KECCAK : sha3.sha3_impl.KECCAK_RHO_K.val.length = 25 :=
    Aeneas.Std.Array.length_eq _
  have hLi : i.val + 4 < state.val.length := by rw [hL]; exact hi_lt
  have hLi25 : i25.val < state.val.length := by rw [hi25]; exact hLi
  have hLi27 : i27.val < sha3.sha3_impl.KECCAK_RHO_K.val.length := by
    rw [hL_KECCAK, hi27]; exact hi_lt
  have h_i26 : i26 = state.val[i.val + 4] := by
    simp only [i26_post, hi25]
  have h_i28 : i28 = sha3.sha3_impl.KECCAK_RHO_K.val[i.val + 4] := by
    simp only [i28_post, hi27]
  have h_e : i29 = core.num.U64.rotate_left state.val[i.val + 4]
                       sha3.sha3_impl.KECCAK_RHO_K.val[i.val + 4] := by
    rw [i29_post, h_i26, h_i28]
  refine ⟨?_, ?_⟩
  · rw [result_post]; simp [Aeneas.Std.Array.set_val_eq]
  intro k hk
  rw [result_post]
  simp only [Aeneas.Std.Array.set_val_eq, hi30]
  by_cases hk_eq : k = i.val + 4
  · subst hk_eq
    have hLset : (i.val + 4) < (state.val.set (i.val + 4) i29).length := by
      rw [List.length_set]; exact hLi
    rw [if_pos rfl,
        
        List.getElem_set_self, h_e]
  · have hLk : k < (state.val.set (i.val + 4) i29).length := by
      rw [List.length_set, hL]; exact hk
    rw [if_neg hk_eq,
        
        List.getElem_set_ne (Ne.symm hk_eq)
]

/-! ### Composed spec for `keccak_rho_row` -/

set_option maxHeartbeats 4000000 in
@[local step]
private theorem keccak_rho_row.spec (state : Keccak1600) (r : Usize) (hr : r.val < 5) :
    sha3.sha3_impl.keccak_rho_row state r
    ⦃ (result : Keccak1600) =>
      result.val.length = 25 ∧
      ∀ k (hk : k < 25),
        result.val[k] =
          (if 5 * r.val ≤ k ∧ k < 5 * r.val + 5
           then core.num.U64.rotate_left state.val[k]
                  (sha3.sha3_impl.KECCAK_RHO_K.val[k])
           else state.val[k]) ⦄ := by
  rw [keccak_rho_row.fold5]
  step*
  refine ⟨result_post1, fun k hk => ?_⟩
  have hi : i.val = 5 * r.val := i_post
  have h1 := state1_post2 k hk
  have h2 := state2_post2 k hk
  have h3 := state3_post2 k hk
  have h4 := state4_post2 k hk
  have hres := result_post2 k hk
  by_cases hk0 : k = i.val
  · -- k = i+0 (hit)
    have h_win : 5 * r.val ≤ k ∧ k < 5 * r.val + 5 := by
      refine ⟨?_, ?_⟩ <;> (rw [← hi]; scalar_tac)
    have h_ne_1 : k ≠ i.val + 1 := by scalar_tac
    have h_ne_2 : k ≠ i.val + 2 := by scalar_tac
    have h_ne_3 : k ≠ i.val + 3 := by scalar_tac
    have h_ne_4 : k ≠ i.val + 4 := by scalar_tac
    rw [if_pos h_win]
    rw [if_pos hk0] at h1
    rw [if_neg h_ne_1] at h2
    rw [if_neg h_ne_2] at h3
    rw [if_neg h_ne_3] at h4
    rw [if_neg h_ne_4] at hres
    rw [hres, h4, h3, h2, h1]
  · by_cases hk1 : k = i.val + 1
    · have h_win : 5 * r.val ≤ k ∧ k < 5 * r.val + 5 := by
        refine ⟨?_, ?_⟩ <;> (rw [← hi]; scalar_tac)
      have h_ne_2 : k ≠ i.val + 2 := by scalar_tac
      have h_ne_3 : k ≠ i.val + 3 := by scalar_tac
      have h_ne_4 : k ≠ i.val + 4 := by scalar_tac
      rw [if_pos h_win]
      rw [if_neg hk0] at h1
      rw [if_pos hk1] at h2
      rw [if_neg h_ne_2] at h3
      rw [if_neg h_ne_3] at h4
      rw [if_neg h_ne_4] at hres
      rw [hres, h4, h3, h2, h1]
    · by_cases hk2 : k = i.val + 2
      · have h_win : 5 * r.val ≤ k ∧ k < 5 * r.val + 5 := by
          refine ⟨?_, ?_⟩ <;> (rw [← hi]; scalar_tac)
        have h_ne_3 : k ≠ i.val + 3 := by scalar_tac
        have h_ne_4 : k ≠ i.val + 4 := by scalar_tac
        rw [if_pos h_win]
        rw [if_neg hk0] at h1
        rw [if_neg hk1] at h2
        rw [if_pos hk2] at h3
        rw [if_neg h_ne_3] at h4
        rw [if_neg h_ne_4] at hres
        rw [hres, h4, h3, h2, h1]
      · by_cases hk3 : k = i.val + 3
        · have h_win : 5 * r.val ≤ k ∧ k < 5 * r.val + 5 := by
            refine ⟨?_, ?_⟩ <;> (rw [← hi]; scalar_tac)
          have h_ne_4 : k ≠ i.val + 4 := by scalar_tac
          rw [if_pos h_win]
          rw [if_neg hk0] at h1
          rw [if_neg hk1] at h2
          rw [if_neg hk2] at h3
          rw [if_pos hk3] at h4
          rw [if_neg h_ne_4] at hres
          rw [hres, h4, h3, h2, h1]
        · by_cases hk4 : k = i.val + 4
          · have h_win : 5 * r.val ≤ k ∧ k < 5 * r.val + 5 := by
              refine ⟨?_, ?_⟩ <;> (rw [← hi]; scalar_tac)
            rw [if_pos h_win]
            rw [if_neg hk0] at h1
            rw [if_neg hk1] at h2
            rw [if_neg hk2] at h3
            rw [if_neg hk3] at h4
            rw [if_pos hk4] at hres
            rw [hres, h4, h3, h2, h1]
          · -- k ≠ i+0..4 ⇒ outside window
            have h_out : ¬ (5 * r.val ≤ k ∧ k < 5 * r.val + 5) := by
              rintro ⟨hl, hu⟩
              rw [← hi] at hl hu
              scalar_tac
            rw [if_neg h_out]
            rw [if_neg hk0] at h1
            rw [if_neg hk1] at h2
            rw [if_neg hk2] at h3
            rw [if_neg hk3] at h4
            rw [if_neg hk4] at hres
            rw [hres, h4, h3, h2, h1]

set_option maxHeartbeats 4000000 in
@[step]
theorem keccak_rho.spec (state : Keccak1600) :
    keccak_rho state
    ⦃ (result : Keccak1600) =>
      Lanes25.ofArray result = rhoCore (Lanes25.ofArray state) ⦄ := by
  unfold keccak_rho
  step*
  -- Per-lane chain through the 4 per-cell posts; state1 (lanes 0..4) is handled
  -- by projecting from state1_post (which is in explicit Lanes25 form).
  apply Lanes25.ext <;> dsimp only [Lanes25.ofArray, rhoCore]
  case h0 =>
    rw [result_post2 0 (by decide), if_neg (by decide : ¬((5*4:Nat) ≤ 0 ∧ 0 < 5*4+5)),
        state4_post2 0 (by decide), if_neg (by decide : ¬((5*3:Nat) ≤ 0 ∧ 0 < 5*3+5)),
        state3_post2 0 (by decide), if_neg (by decide : ¬((5*2:Nat) ≤ 0 ∧ 0 < 5*2+5)),
        state2_post2 0 (by decide), if_neg (by decide : ¬((5*1:Nat) ≤ 0 ∧ 0 < 5*1+5))]
    have := congrArg Lanes25.l0 state1_post; simp only [Lanes25.ofArray] at this; exact this
  case h1 =>
    rw [result_post2 1 (by decide), if_neg (by decide : ¬((5*4:Nat) ≤ 1 ∧ 1 < 5*4+5)),
        state4_post2 1 (by decide), if_neg (by decide : ¬((5*3:Nat) ≤ 1 ∧ 1 < 5*3+5)),
        state3_post2 1 (by decide), if_neg (by decide : ¬((5*2:Nat) ≤ 1 ∧ 1 < 5*2+5)),
        state2_post2 1 (by decide), if_neg (by decide : ¬((5*1:Nat) ≤ 1 ∧ 1 < 5*1+5))]
    have := congrArg Lanes25.l1 state1_post; simp only [Lanes25.ofArray] at this; exact this
  case h2 =>
    rw [result_post2 2 (by decide), if_neg (by decide : ¬((5*4:Nat) ≤ 2 ∧ 2 < 5*4+5)),
        state4_post2 2 (by decide), if_neg (by decide : ¬((5*3:Nat) ≤ 2 ∧ 2 < 5*3+5)),
        state3_post2 2 (by decide), if_neg (by decide : ¬((5*2:Nat) ≤ 2 ∧ 2 < 5*2+5)),
        state2_post2 2 (by decide), if_neg (by decide : ¬((5*1:Nat) ≤ 2 ∧ 2 < 5*1+5))]
    have := congrArg Lanes25.l2 state1_post; simp only [Lanes25.ofArray] at this; exact this
  case h3 =>
    rw [result_post2 3 (by decide), if_neg (by decide : ¬((5*4:Nat) ≤ 3 ∧ 3 < 5*4+5)),
        state4_post2 3 (by decide), if_neg (by decide : ¬((5*3:Nat) ≤ 3 ∧ 3 < 5*3+5)),
        state3_post2 3 (by decide), if_neg (by decide : ¬((5*2:Nat) ≤ 3 ∧ 3 < 5*2+5)),
        state2_post2 3 (by decide), if_neg (by decide : ¬((5*1:Nat) ≤ 3 ∧ 3 < 5*1+5))]
    have := congrArg Lanes25.l3 state1_post; simp only [Lanes25.ofArray] at this; exact this
  case h4 =>
    rw [result_post2 4 (by decide), if_neg (by decide : ¬((5*4:Nat) ≤ 4 ∧ 4 < 5*4+5)),
        state4_post2 4 (by decide), if_neg (by decide : ¬((5*3:Nat) ≤ 4 ∧ 4 < 5*3+5)),
        state3_post2 4 (by decide), if_neg (by decide : ¬((5*2:Nat) ≤ 4 ∧ 4 < 5*2+5)),
        state2_post2 4 (by decide), if_neg (by decide : ¬((5*1:Nat) ≤ 4 ∧ 4 < 5*1+5))]
    have := congrArg Lanes25.l4 state1_post; simp only [Lanes25.ofArray] at this; exact this
  case h5 =>
    rw [result_post2 5 (by decide), if_neg (by decide : ¬((5*4:Nat) ≤ 5 ∧ 5 < 5*4+5)),
        state4_post2 5 (by decide), if_neg (by decide : ¬((5*3:Nat) ≤ 5 ∧ 5 < 5*3+5)),
        state3_post2 5 (by decide), if_neg (by decide : ¬((5*2:Nat) ≤ 5 ∧ 5 < 5*2+5)),
        state2_post2 5 (by decide), if_pos (by decide : (5*1:Nat) ≤ 5 ∧ 5 < 5*1+5)]
    have hs : state1.val[5] = state.val[5] := by
      have := congrArg Lanes25.l5 state1_post; simp only [Lanes25.ofArray] at this; exact this
    have hK : (sha3.sha3_impl.KECCAK_RHO_K).val[5] = 36#u32 := by
      unfold sha3.sha3_impl.KECCAK_RHO_K; decide
    rw [hs, hK]
  case h6 =>
    rw [result_post2 6 (by decide), if_neg (by decide : ¬((5*4:Nat) ≤ 6 ∧ 6 < 5*4+5)),
        state4_post2 6 (by decide), if_neg (by decide : ¬((5*3:Nat) ≤ 6 ∧ 6 < 5*3+5)),
        state3_post2 6 (by decide), if_neg (by decide : ¬((5*2:Nat) ≤ 6 ∧ 6 < 5*2+5)),
        state2_post2 6 (by decide), if_pos (by decide : (5*1:Nat) ≤ 6 ∧ 6 < 5*1+5)]
    have hs : state1.val[6] = state.val[6] := by
      have := congrArg Lanes25.l6 state1_post; simp only [Lanes25.ofArray] at this; exact this
    have hK : (sha3.sha3_impl.KECCAK_RHO_K).val[6] = 44#u32 := by
      unfold sha3.sha3_impl.KECCAK_RHO_K; decide
    rw [hs, hK]
  case h7 =>
    rw [result_post2 7 (by decide), if_neg (by decide : ¬((5*4:Nat) ≤ 7 ∧ 7 < 5*4+5)),
        state4_post2 7 (by decide), if_neg (by decide : ¬((5*3:Nat) ≤ 7 ∧ 7 < 5*3+5)),
        state3_post2 7 (by decide), if_neg (by decide : ¬((5*2:Nat) ≤ 7 ∧ 7 < 5*2+5)),
        state2_post2 7 (by decide), if_pos (by decide : (5*1:Nat) ≤ 7 ∧ 7 < 5*1+5)]
    have hs : state1.val[7] = state.val[7] := by
      have := congrArg Lanes25.l7 state1_post; simp only [Lanes25.ofArray] at this; exact this
    have hK : (sha3.sha3_impl.KECCAK_RHO_K).val[7] = 6#u32 := by
      unfold sha3.sha3_impl.KECCAK_RHO_K; decide
    rw [hs, hK]
  case h8 =>
    rw [result_post2 8 (by decide), if_neg (by decide : ¬((5*4:Nat) ≤ 8 ∧ 8 < 5*4+5)),
        state4_post2 8 (by decide), if_neg (by decide : ¬((5*3:Nat) ≤ 8 ∧ 8 < 5*3+5)),
        state3_post2 8 (by decide), if_neg (by decide : ¬((5*2:Nat) ≤ 8 ∧ 8 < 5*2+5)),
        state2_post2 8 (by decide), if_pos (by decide : (5*1:Nat) ≤ 8 ∧ 8 < 5*1+5)]
    have hs : state1.val[8] = state.val[8] := by
      have := congrArg Lanes25.l8 state1_post; simp only [Lanes25.ofArray] at this; exact this
    have hK : (sha3.sha3_impl.KECCAK_RHO_K).val[8] = 55#u32 := by
      unfold sha3.sha3_impl.KECCAK_RHO_K; decide
    rw [hs, hK]
  case h9 =>
    rw [result_post2 9 (by decide), if_neg (by decide : ¬((5*4:Nat) ≤ 9 ∧ 9 < 5*4+5)),
        state4_post2 9 (by decide), if_neg (by decide : ¬((5*3:Nat) ≤ 9 ∧ 9 < 5*3+5)),
        state3_post2 9 (by decide), if_neg (by decide : ¬((5*2:Nat) ≤ 9 ∧ 9 < 5*2+5)),
        state2_post2 9 (by decide), if_pos (by decide : (5*1:Nat) ≤ 9 ∧ 9 < 5*1+5)]
    have hs : state1.val[9] = state.val[9] := by
      have := congrArg Lanes25.l9 state1_post; simp only [Lanes25.ofArray] at this; exact this
    have hK : (sha3.sha3_impl.KECCAK_RHO_K).val[9] = 20#u32 := by
      unfold sha3.sha3_impl.KECCAK_RHO_K; decide
    rw [hs, hK]
  case h10 =>
    rw [result_post2 10 (by decide), if_neg (by decide : ¬((5*4:Nat) ≤ 10 ∧ 10 < 5*4+5)),
        state4_post2 10 (by decide), if_neg (by decide : ¬((5*3:Nat) ≤ 10 ∧ 10 < 5*3+5)),
        state3_post2 10 (by decide), if_pos (by decide : (5*2:Nat) ≤ 10 ∧ 10 < 5*2+5)]
    have hs2 : state2.val[10] = state1.val[10] := by
      have h := state2_post2 10 (by decide)
      rw [if_neg (by decide : ¬((5*1:Nat) ≤ 10 ∧ 10 < 5*1+5))] at h; exact h
    have hs1 : state1.val[10] = state.val[10] := by
      have := congrArg Lanes25.l10 state1_post; simp only [Lanes25.ofArray] at this; exact this
    have hK : (sha3.sha3_impl.KECCAK_RHO_K).val[10] = 3#u32 := by
      unfold sha3.sha3_impl.KECCAK_RHO_K; decide
    rw [hs2, hs1, hK]
  case h11 =>
    rw [result_post2 11 (by decide), if_neg (by decide : ¬((5*4:Nat) ≤ 11 ∧ 11 < 5*4+5)),
        state4_post2 11 (by decide), if_neg (by decide : ¬((5*3:Nat) ≤ 11 ∧ 11 < 5*3+5)),
        state3_post2 11 (by decide), if_pos (by decide : (5*2:Nat) ≤ 11 ∧ 11 < 5*2+5)]
    have hs2 : state2.val[11] = state1.val[11] := by
      have h := state2_post2 11 (by decide)
      rw [if_neg (by decide : ¬((5*1:Nat) ≤ 11 ∧ 11 < 5*1+5))] at h; exact h
    have hs1 : state1.val[11] = state.val[11] := by
      have := congrArg Lanes25.l11 state1_post; simp only [Lanes25.ofArray] at this; exact this
    have hK : (sha3.sha3_impl.KECCAK_RHO_K).val[11] = 10#u32 := by
      unfold sha3.sha3_impl.KECCAK_RHO_K; decide
    rw [hs2, hs1, hK]
  case h12 =>
    rw [result_post2 12 (by decide), if_neg (by decide : ¬((5*4:Nat) ≤ 12 ∧ 12 < 5*4+5)),
        state4_post2 12 (by decide), if_neg (by decide : ¬((5*3:Nat) ≤ 12 ∧ 12 < 5*3+5)),
        state3_post2 12 (by decide), if_pos (by decide : (5*2:Nat) ≤ 12 ∧ 12 < 5*2+5)]
    have hs2 : state2.val[12] = state1.val[12] := by
      have h := state2_post2 12 (by decide)
      rw [if_neg (by decide : ¬((5*1:Nat) ≤ 12 ∧ 12 < 5*1+5))] at h; exact h
    have hs1 : state1.val[12] = state.val[12] := by
      have := congrArg Lanes25.l12 state1_post; simp only [Lanes25.ofArray] at this; exact this
    have hK : (sha3.sha3_impl.KECCAK_RHO_K).val[12] = 43#u32 := by
      unfold sha3.sha3_impl.KECCAK_RHO_K; decide
    rw [hs2, hs1, hK]
  case h13 =>
    rw [result_post2 13 (by decide), if_neg (by decide : ¬((5*4:Nat) ≤ 13 ∧ 13 < 5*4+5)),
        state4_post2 13 (by decide), if_neg (by decide : ¬((5*3:Nat) ≤ 13 ∧ 13 < 5*3+5)),
        state3_post2 13 (by decide), if_pos (by decide : (5*2:Nat) ≤ 13 ∧ 13 < 5*2+5)]
    have hs2 : state2.val[13] = state1.val[13] := by
      have h := state2_post2 13 (by decide)
      rw [if_neg (by decide : ¬((5*1:Nat) ≤ 13 ∧ 13 < 5*1+5))] at h; exact h
    have hs1 : state1.val[13] = state.val[13] := by
      have := congrArg Lanes25.l13 state1_post; simp only [Lanes25.ofArray] at this; exact this
    have hK : (sha3.sha3_impl.KECCAK_RHO_K).val[13] = 25#u32 := by
      unfold sha3.sha3_impl.KECCAK_RHO_K; decide
    rw [hs2, hs1, hK]
  case h14 =>
    rw [result_post2 14 (by decide), if_neg (by decide : ¬((5*4:Nat) ≤ 14 ∧ 14 < 5*4+5)),
        state4_post2 14 (by decide), if_neg (by decide : ¬((5*3:Nat) ≤ 14 ∧ 14 < 5*3+5)),
        state3_post2 14 (by decide), if_pos (by decide : (5*2:Nat) ≤ 14 ∧ 14 < 5*2+5)]
    have hs2 : state2.val[14] = state1.val[14] := by
      have h := state2_post2 14 (by decide)
      rw [if_neg (by decide : ¬((5*1:Nat) ≤ 14 ∧ 14 < 5*1+5))] at h; exact h
    have hs1 : state1.val[14] = state.val[14] := by
      have := congrArg Lanes25.l14 state1_post; simp only [Lanes25.ofArray] at this; exact this
    have hK : (sha3.sha3_impl.KECCAK_RHO_K).val[14] = 39#u32 := by
      unfold sha3.sha3_impl.KECCAK_RHO_K; decide
    rw [hs2, hs1, hK]
  case h15 =>
    rw [result_post2 15 (by decide), if_neg (by decide : ¬((5*4:Nat) ≤ 15 ∧ 15 < 5*4+5)),
        state4_post2 15 (by decide), if_pos (by decide : (5*3:Nat) ≤ 15 ∧ 15 < 5*3+5)]
    have hs3 : state3.val[15] = state2.val[15] := by
      have h := state3_post2 15 (by decide)
      rw [if_neg (by decide : ¬((5*2:Nat) ≤ 15 ∧ 15 < 5*2+5))] at h; exact h
    have hs2 : state2.val[15] = state1.val[15] := by
      have h := state2_post2 15 (by decide)
      rw [if_neg (by decide : ¬((5*1:Nat) ≤ 15 ∧ 15 < 5*1+5))] at h; exact h
    have hs1 : state1.val[15] = state.val[15] := by
      have := congrArg Lanes25.l15 state1_post; simp only [Lanes25.ofArray] at this; exact this
    have hK : (sha3.sha3_impl.KECCAK_RHO_K).val[15] = 41#u32 := by
      unfold sha3.sha3_impl.KECCAK_RHO_K; decide
    rw [hs3, hs2, hs1, hK]
  case h16 =>
    rw [result_post2 16 (by decide), if_neg (by decide : ¬((5*4:Nat) ≤ 16 ∧ 16 < 5*4+5)),
        state4_post2 16 (by decide), if_pos (by decide : (5*3:Nat) ≤ 16 ∧ 16 < 5*3+5)]
    have hs3 : state3.val[16] = state2.val[16] := by
      have h := state3_post2 16 (by decide)
      rw [if_neg (by decide : ¬((5*2:Nat) ≤ 16 ∧ 16 < 5*2+5))] at h; exact h
    have hs2 : state2.val[16] = state1.val[16] := by
      have h := state2_post2 16 (by decide)
      rw [if_neg (by decide : ¬((5*1:Nat) ≤ 16 ∧ 16 < 5*1+5))] at h; exact h
    have hs1 : state1.val[16] = state.val[16] := by
      have := congrArg Lanes25.l16 state1_post; simp only [Lanes25.ofArray] at this; exact this
    have hK : (sha3.sha3_impl.KECCAK_RHO_K).val[16] = 45#u32 := by
      unfold sha3.sha3_impl.KECCAK_RHO_K; decide
    rw [hs3, hs2, hs1, hK]
  case h17 =>
    rw [result_post2 17 (by decide), if_neg (by decide : ¬((5*4:Nat) ≤ 17 ∧ 17 < 5*4+5)),
        state4_post2 17 (by decide), if_pos (by decide : (5*3:Nat) ≤ 17 ∧ 17 < 5*3+5)]
    have hs3 : state3.val[17] = state2.val[17] := by
      have h := state3_post2 17 (by decide)
      rw [if_neg (by decide : ¬((5*2:Nat) ≤ 17 ∧ 17 < 5*2+5))] at h; exact h
    have hs2 : state2.val[17] = state1.val[17] := by
      have h := state2_post2 17 (by decide)
      rw [if_neg (by decide : ¬((5*1:Nat) ≤ 17 ∧ 17 < 5*1+5))] at h; exact h
    have hs1 : state1.val[17] = state.val[17] := by
      have := congrArg Lanes25.l17 state1_post; simp only [Lanes25.ofArray] at this; exact this
    have hK : (sha3.sha3_impl.KECCAK_RHO_K).val[17] = 15#u32 := by
      unfold sha3.sha3_impl.KECCAK_RHO_K; decide
    rw [hs3, hs2, hs1, hK]
  case h18 =>
    rw [result_post2 18 (by decide), if_neg (by decide : ¬((5*4:Nat) ≤ 18 ∧ 18 < 5*4+5)),
        state4_post2 18 (by decide), if_pos (by decide : (5*3:Nat) ≤ 18 ∧ 18 < 5*3+5)]
    have hs3 : state3.val[18] = state2.val[18] := by
      have h := state3_post2 18 (by decide)
      rw [if_neg (by decide : ¬((5*2:Nat) ≤ 18 ∧ 18 < 5*2+5))] at h; exact h
    have hs2 : state2.val[18] = state1.val[18] := by
      have h := state2_post2 18 (by decide)
      rw [if_neg (by decide : ¬((5*1:Nat) ≤ 18 ∧ 18 < 5*1+5))] at h; exact h
    have hs1 : state1.val[18] = state.val[18] := by
      have := congrArg Lanes25.l18 state1_post; simp only [Lanes25.ofArray] at this; exact this
    have hK : (sha3.sha3_impl.KECCAK_RHO_K).val[18] = 21#u32 := by
      unfold sha3.sha3_impl.KECCAK_RHO_K; decide
    rw [hs3, hs2, hs1, hK]
  case h19 =>
    rw [result_post2 19 (by decide), if_neg (by decide : ¬((5*4:Nat) ≤ 19 ∧ 19 < 5*4+5)),
        state4_post2 19 (by decide), if_pos (by decide : (5*3:Nat) ≤ 19 ∧ 19 < 5*3+5)]
    have hs3 : state3.val[19] = state2.val[19] := by
      have h := state3_post2 19 (by decide)
      rw [if_neg (by decide : ¬((5*2:Nat) ≤ 19 ∧ 19 < 5*2+5))] at h; exact h
    have hs2 : state2.val[19] = state1.val[19] := by
      have h := state2_post2 19 (by decide)
      rw [if_neg (by decide : ¬((5*1:Nat) ≤ 19 ∧ 19 < 5*1+5))] at h; exact h
    have hs1 : state1.val[19] = state.val[19] := by
      have := congrArg Lanes25.l19 state1_post; simp only [Lanes25.ofArray] at this; exact this
    have hK : (sha3.sha3_impl.KECCAK_RHO_K).val[19] = 8#u32 := by
      unfold sha3.sha3_impl.KECCAK_RHO_K; decide
    rw [hs3, hs2, hs1, hK]
  case h20 =>
    rw [result_post2 20 (by decide), if_pos (by decide : (5*4:Nat) ≤ 20 ∧ 20 < 5*4+5)]
    have hs4 : state4.val[20] = state3.val[20] := by
      have h := state4_post2 20 (by decide)
      rw [if_neg (by decide : ¬((5*3:Nat) ≤ 20 ∧ 20 < 5*3+5))] at h; exact h
    have hs3 : state3.val[20] = state2.val[20] := by
      have h := state3_post2 20 (by decide)
      rw [if_neg (by decide : ¬((5*2:Nat) ≤ 20 ∧ 20 < 5*2+5))] at h; exact h
    have hs2 : state2.val[20] = state1.val[20] := by
      have h := state2_post2 20 (by decide)
      rw [if_neg (by decide : ¬((5*1:Nat) ≤ 20 ∧ 20 < 5*1+5))] at h; exact h
    have hs1 : state1.val[20] = state.val[20] := by
      have := congrArg Lanes25.l20 state1_post; simp only [Lanes25.ofArray] at this; exact this
    have hK : (sha3.sha3_impl.KECCAK_RHO_K).val[20] = 18#u32 := by
      unfold sha3.sha3_impl.KECCAK_RHO_K; decide
    rw [hs4, hs3, hs2, hs1, hK]
  case h21 =>
    rw [result_post2 21 (by decide), if_pos (by decide : (5*4:Nat) ≤ 21 ∧ 21 < 5*4+5)]
    have hs4 : state4.val[21] = state3.val[21] := by
      have h := state4_post2 21 (by decide)
      rw [if_neg (by decide : ¬((5*3:Nat) ≤ 21 ∧ 21 < 5*3+5))] at h; exact h
    have hs3 : state3.val[21] = state2.val[21] := by
      have h := state3_post2 21 (by decide)
      rw [if_neg (by decide : ¬((5*2:Nat) ≤ 21 ∧ 21 < 5*2+5))] at h; exact h
    have hs2 : state2.val[21] = state1.val[21] := by
      have h := state2_post2 21 (by decide)
      rw [if_neg (by decide : ¬((5*1:Nat) ≤ 21 ∧ 21 < 5*1+5))] at h; exact h
    have hs1 : state1.val[21] = state.val[21] := by
      have := congrArg Lanes25.l21 state1_post; simp only [Lanes25.ofArray] at this; exact this
    have hK : (sha3.sha3_impl.KECCAK_RHO_K).val[21] = 2#u32 := by
      unfold sha3.sha3_impl.KECCAK_RHO_K; decide
    rw [hs4, hs3, hs2, hs1, hK]
  case h22 =>
    rw [result_post2 22 (by decide), if_pos (by decide : (5*4:Nat) ≤ 22 ∧ 22 < 5*4+5)]
    have hs4 : state4.val[22] = state3.val[22] := by
      have h := state4_post2 22 (by decide)
      rw [if_neg (by decide : ¬((5*3:Nat) ≤ 22 ∧ 22 < 5*3+5))] at h; exact h
    have hs3 : state3.val[22] = state2.val[22] := by
      have h := state3_post2 22 (by decide)
      rw [if_neg (by decide : ¬((5*2:Nat) ≤ 22 ∧ 22 < 5*2+5))] at h; exact h
    have hs2 : state2.val[22] = state1.val[22] := by
      have h := state2_post2 22 (by decide)
      rw [if_neg (by decide : ¬((5*1:Nat) ≤ 22 ∧ 22 < 5*1+5))] at h; exact h
    have hs1 : state1.val[22] = state.val[22] := by
      have := congrArg Lanes25.l22 state1_post; simp only [Lanes25.ofArray] at this; exact this
    have hK : (sha3.sha3_impl.KECCAK_RHO_K).val[22] = 61#u32 := by
      unfold sha3.sha3_impl.KECCAK_RHO_K; decide
    rw [hs4, hs3, hs2, hs1, hK]
  case h23 =>
    rw [result_post2 23 (by decide), if_pos (by decide : (5*4:Nat) ≤ 23 ∧ 23 < 5*4+5)]
    have hs4 : state4.val[23] = state3.val[23] := by
      have h := state4_post2 23 (by decide)
      rw [if_neg (by decide : ¬((5*3:Nat) ≤ 23 ∧ 23 < 5*3+5))] at h; exact h
    have hs3 : state3.val[23] = state2.val[23] := by
      have h := state3_post2 23 (by decide)
      rw [if_neg (by decide : ¬((5*2:Nat) ≤ 23 ∧ 23 < 5*2+5))] at h; exact h
    have hs2 : state2.val[23] = state1.val[23] := by
      have h := state2_post2 23 (by decide)
      rw [if_neg (by decide : ¬((5*1:Nat) ≤ 23 ∧ 23 < 5*1+5))] at h; exact h
    have hs1 : state1.val[23] = state.val[23] := by
      have := congrArg Lanes25.l23 state1_post; simp only [Lanes25.ofArray] at this; exact this
    have hK : (sha3.sha3_impl.KECCAK_RHO_K).val[23] = 56#u32 := by
      unfold sha3.sha3_impl.KECCAK_RHO_K; decide
    rw [hs4, hs3, hs2, hs1, hK]
  case h24 =>
    rw [result_post2 24 (by decide), if_pos (by decide : (5*4:Nat) ≤ 24 ∧ 24 < 5*4+5)]
    have hs4 : state4.val[24] = state3.val[24] := by
      have h := state4_post2 24 (by decide)
      rw [if_neg (by decide : ¬((5*3:Nat) ≤ 24 ∧ 24 < 5*3+5))] at h; exact h
    have hs3 : state3.val[24] = state2.val[24] := by
      have h := state3_post2 24 (by decide)
      rw [if_neg (by decide : ¬((5*2:Nat) ≤ 24 ∧ 24 < 5*2+5))] at h; exact h
    have hs2 : state2.val[24] = state1.val[24] := by
      have h := state2_post2 24 (by decide)
      rw [if_neg (by decide : ¬((5*1:Nat) ≤ 24 ∧ 24 < 5*1+5))] at h; exact h
    have hs1 : state1.val[24] = state.val[24] := by
      have := congrArg Lanes25.l24 state1_post; simp only [Lanes25.ofArray] at this; exact this
    have hK : (sha3.sha3_impl.KECCAK_RHO_K).val[24] = 14#u32 := by
      unfold sha3.sha3_impl.KECCAK_RHO_K; decide
    rw [hs4, hs3, hs2, hs1, hK]

set_option maxHeartbeats 16000000 in
@[step]
theorem keccak_pi.spec (state : Keccak1600) :
    keccak_pi state
    ⦃ (result : Keccak1600) =>
      Lanes25.ofArray result = piCore (Lanes25.ofArray state) ⦄ := by
  unfold keccak_pi
  step*
  simp only [result_post, state23_post, state22_post, state21_post, state20_post,
    state19_post, state18_post, state17_post, state16_post, state15_post, state14_post,
    state13_post, state12_post, state11_post, state10_post, state9_post, state8_post,
    state7_post, state6_post, state5_post, state4_post, state3_post, state2_post,
    state1_post, Lanes25.ofArray_set_1, Lanes25.ofArray_set_2, Lanes25.ofArray_set_3,
    Lanes25.ofArray_set_4, Lanes25.ofArray_set_5, Lanes25.ofArray_set_6,
    Lanes25.ofArray_set_7, Lanes25.ofArray_set_8, Lanes25.ofArray_set_9,
    Lanes25.ofArray_set_10, Lanes25.ofArray_set_11, Lanes25.ofArray_set_12,
    Lanes25.ofArray_set_13, Lanes25.ofArray_set_14, Lanes25.ofArray_set_15,
    Lanes25.ofArray_set_16, Lanes25.ofArray_set_17, Lanes25.ofArray_set_18,
    Lanes25.ofArray_set_19, Lanes25.ofArray_set_20, Lanes25.ofArray_set_21,
    Lanes25.ofArray_set_22, Lanes25.ofArray_set_23, Lanes25.ofArray_set_24]
  simp only [piCore, Lanes25.ofArray]
  apply Lanes25.ext <;> dsimp only
  case h1 => simp_lists [i_post]
  case h2 => simp_lists [i6_post, state6_post, state5_post, state4_post, state3_post, state2_post, state1_post]
  case h3 => simp_lists [i18_post, state18_post, state17_post, state16_post, state15_post, state14_post, state13_post, state12_post, state11_post, state10_post, state9_post, state8_post, state7_post, state6_post, state5_post, state4_post, state3_post, state2_post, state1_post]
  case h4 => simp_lists [i12_post, state12_post, state11_post, state10_post, state9_post, state8_post, state7_post, state6_post, state5_post, state4_post, state3_post, state2_post, state1_post]
  case h5 => simp_lists [i17_post, state17_post, state16_post, state15_post, state14_post, state13_post, state12_post, state11_post, state10_post, state9_post, state8_post, state7_post, state6_post, state5_post, state4_post, state3_post, state2_post, state1_post]
  case h6 => simp_lists [i1_post, state1_post]
  case h7 => simp_lists [i22_post, state22_post, state21_post, state20_post, state19_post, state18_post, state17_post, state16_post, state15_post, state14_post, state13_post, state12_post, state11_post, state10_post, state9_post, state8_post, state7_post, state6_post, state5_post, state4_post, state3_post, state2_post, state1_post]
  case h8 => simp_lists [i15_post, state15_post, state14_post, state13_post, state12_post, state11_post, state10_post, state9_post, state8_post, state7_post, state6_post, state5_post, state4_post, state3_post, state2_post, state1_post]
  case h9 => simp_lists [i2_post, state2_post, state1_post]
  case h10 => simp_lists [t_post]
  case h11 => simp_lists [i21_post, state21_post, state20_post, state19_post, state18_post, state17_post, state16_post, state15_post, state14_post, state13_post, state12_post, state11_post, state10_post, state9_post, state8_post, state7_post, state6_post, state5_post, state4_post, state3_post, state2_post, state1_post]
  case h12 => simp_lists [i7_post, state7_post, state6_post, state5_post, state4_post, state3_post, state2_post, state1_post]
  case h13 => simp_lists [i8_post, state8_post, state7_post, state6_post, state5_post, state4_post, state3_post, state2_post, state1_post]
  case h14 => simp_lists [i4_post, state4_post, state3_post, state2_post, state1_post]
  case h15 => simp_lists [i11_post, state11_post, state10_post, state9_post, state8_post, state7_post, state6_post, state5_post, state4_post, state3_post, state2_post, state1_post]
  case h16 => simp_lists [i16_post, state16_post, state15_post, state14_post, state13_post, state12_post, state11_post, state10_post, state9_post, state8_post, state7_post, state6_post, state5_post, state4_post, state3_post, state2_post, state1_post]
  case h17 => simp_lists [i20_post, state20_post, state19_post, state18_post, state17_post, state16_post, state15_post, state14_post, state13_post, state12_post, state11_post, state10_post, state9_post, state8_post, state7_post, state6_post, state5_post, state4_post, state3_post, state2_post, state1_post]
  case h18 => simp_lists [i19_post, state19_post, state18_post, state17_post, state16_post, state15_post, state14_post, state13_post, state12_post, state11_post, state10_post, state9_post, state8_post, state7_post, state6_post, state5_post, state4_post, state3_post, state2_post, state1_post]
  case h19 => simp_lists [i9_post, state9_post, state8_post, state7_post, state6_post, state5_post, state4_post, state3_post, state2_post, state1_post]
  case h20 => simp_lists [i5_post, state5_post, state4_post, state3_post, state2_post, state1_post]
  case h21 => simp_lists [i14_post, state14_post, state13_post, state12_post, state11_post, state10_post, state9_post, state8_post, state7_post, state6_post, state5_post, state4_post, state3_post, state2_post, state1_post]
  case h22 => simp_lists [i3_post, state3_post, state2_post, state1_post]
  case h23 => simp_lists [i10_post, state10_post, state9_post, state8_post, state7_post, state6_post, state5_post, state4_post, state3_post, state2_post, state1_post]
  case h24 => simp_lists [i13_post, state13_post, state12_post, state11_post, state10_post, state9_post, state8_post, state7_post, state6_post, state5_post, state4_post, state3_post, state2_post, state1_post]

/-! ### `keccak_chi_row` 6-phase decomposition

Mirror of `keccak_rho_row` but tuned to chi's dataflow: `t1` and `t2`
are computed early and written last, so 6 phases (compute t1, compute
t2, three slot-writes, terminal two-write) rather than rho's 5 uniform
phases. -/

set_option maxRecDepth 2048 in
#decompose sha3.sha3_impl.keccak_chi_row keccak_chi_row.fold6
  letRange 1 9 => chi_row_t1
  letRange 2 9 => chi_row_t2
  letRange 3 10 => chi_row_w2
  letRange 4 10 => chi_row_w3
  letRange 5 10 => chi_row_w4
  letRange 6 4 => chi_row_w01

/-! ### Per-phase chi specs -/

@[local step]
private theorem chi_row_t1.spec (state : Keccak1600) (i : Usize) (hi : i.val + 4 < 25) :
    chi_row_t1 state i
    ⦃ (t1 : U64) =>
      t1 = state.val[i.val] ^^^ (~~~ state.val[i.val + 1] &&& state.val[i.val + 2]) ⦄ := by
  unfold chi_row_t1
  step*
  have hL : state.val.length = 25 := Aeneas.Std.Array.length_eq state
  have hi1 : i1.val = i.val     := by simp [i1_post]
  have hi3 : i3.val = i.val + 1 := by simp [i3_post]
  have hi6 : i6.val = i.val + 2 := by simp [i6_post]
  have hL_i1 : i1.val < state.val.length := by rw [hi1]; scalar_tac
  have hL_i3 : i3.val < state.val.length := by rw [hi3]; scalar_tac
  have hL_i6 : i6.val < state.val.length := by rw [hi6]; scalar_tac
  have h_i2 : i2 = state.val[i.val]     := by simp only [i2_post, hi1]
  have h_i4 : i4 = state.val[i.val + 1] := by simp only [i4_post, hi3]
  have h_i7 : i7 = state.val[i.val + 2] := by simp only [i7_post, hi6]
  have h_i8 : i8 = i5 &&& i7 := UScalar.eq_of_val_eq i8_post1
  have h_t1 : t1 = i2 ^^^ i8 := UScalar.eq_of_val_eq t1_post1
  rw [h_t1, h_i8, i5_post, h_i2, h_i4, h_i7]

@[local step]
private theorem chi_row_t2.spec (state : Keccak1600) (i : Usize) (hi : i.val + 4 < 25) :
    chi_row_t2 state i
    ⦃ (t2 : U64) =>
      t2 = state.val[i.val + 1] ^^^ (~~~ state.val[i.val + 2] &&& state.val[i.val + 3]) ⦄ := by
  unfold chi_row_t2
  step*
  have hL : state.val.length = 25 := Aeneas.Std.Array.length_eq state
  have hi9  : i9.val  = i.val + 1 := by simp [i9_post]
  have hi11 : i11.val = i.val + 2 := by simp [i11_post]
  have hi14 : i14.val = i.val + 3 := by simp [i14_post]
  have hL_i9  : i9.val  < state.val.length := by rw [hi9];  scalar_tac
  have hL_i11 : i11.val < state.val.length := by rw [hi11]; scalar_tac
  have hL_i14 : i14.val < state.val.length := by rw [hi14]; scalar_tac
  have h_i10 : i10 = state.val[i.val + 1] := by simp only [i10_post, hi9]
  have h_i12 : i12 = state.val[i.val + 2] := by simp only [i12_post, hi11]
  have h_i15 : i15 = state.val[i.val + 3] := by simp only [i15_post, hi14]
  have h_i16 : i16 = i13 &&& i15 := UScalar.eq_of_val_eq i16_post1
  have h_t2 : t2 = i10 ^^^ i16 := UScalar.eq_of_val_eq t2_post1
  rw [h_t2, h_i16, i13_post, h_i10, h_i12, h_i15]

@[local step]
private theorem chi_row_w2.spec (state : Keccak1600) (i : Usize) (hi : i.val + 4 < 25) :
    chi_row_w2 state i
    ⦃ (result : Keccak1600) =>
      result.val.length = 25 ∧
      ∀ k (hk : k < 25),
        result.val[k] =
          (if k = i.val + 2 then
            state.val[i.val + 2] ^^^ (~~~ state.val[i.val + 3] &&& state.val[i.val + 4])
           else state.val[k]) ⦄ := by
  unfold chi_row_w2
  step*
  have hL : state.val.length = 25 := Aeneas.Std.Array.length_eq state
  have hi17 : i17.val = i.val + 3 := by simp [i17_post]
  have hi20 : i20.val = i.val + 4 := by simp [i20_post]
  have hi23 : i23.val = i.val + 2 := by simp [i23_post]
  have hL_i17 : i17.val < state.val.length := by rw [hi17]; scalar_tac
  have hL_i20 : i20.val < state.val.length := by rw [hi20]; scalar_tac
  have hL_i23 : i23.val < state.val.length := by rw [hi23]; scalar_tac
  have h_i18 : i18 = state.val[i.val + 3] := by simp only [i18_post, hi17]
  have h_i21 : i21 = state.val[i.val + 4] := by simp only [i21_post, hi20]
  have h_i24 : i24 = state.val[i.val + 2] := by simp only [i24_post, hi23]
  have h_i22 : i22 = i19 &&& i21 := UScalar.eq_of_val_eq i22_post1
  have h_i25 : i25 = state.val[i.val + 2] ^^^ (~~~ state.val[i.val + 3] &&& state.val[i.val + 4]) := by
    have eq25 : i25 = i24 ^^^ i22 := UScalar.eq_of_val_eq i25_post1
    rw [eq25, h_i22, i19_post, h_i24, h_i18, h_i21]
  refine ⟨?_, ?_⟩
  · rw [result_post]; simp [Aeneas.Std.Array.set_val_eq]
  intro k hk
  rw [result_post]
  simp only [Aeneas.Std.Array.set_val_eq, hi23]
  by_cases hk_eq : k = i.val + 2
  · subst hk_eq
    have hLset : (i.val + 2) < (state.val.set (i.val + 2) i25).length := by
      rw [List.length_set, hL]; scalar_tac
    rw [if_pos rfl, List.getElem_set_self, h_i25]
  · have hLk : k < (state.val.set (i.val + 2) i25).length := by
      rw [List.length_set, hL]; exact hk
    rw [if_neg hk_eq, List.getElem_set_ne (Ne.symm hk_eq)
]

@[local step]
private theorem chi_row_w3.spec (i : Usize) (state : Keccak1600)
    (hi : i.val + 4 < 25) (hL : state.val.length = 25) :
    chi_row_w3 i state
    ⦃ (result : Keccak1600) =>
      result.val.length = 25 ∧
      ∀ k (hk : k < 25),
        result.val[k] =
          (if k = i.val + 3 then
            state.val[i.val + 3] ^^^ (~~~ state.val[i.val + 4] &&& state.val[i.val])
           else state.val[k]) ⦄ := by
  unfold chi_row_w3
  step*
  have hi26 : i26.val = i.val + 4 := by simp [i26_post]
  have hi29 : i29.val = i.val     := by simp [i29_post]
  have hi32 : i32.val = i.val + 3 := by simp [i32_post]
  have hL_i26 : i26.val < state.val.length := by rw [hi26]; scalar_tac
  have hL_i29 : i29.val < state.val.length := by rw [hi29]; scalar_tac
  have hL_i32 : i32.val < state.val.length := by rw [hi32]; scalar_tac
  have h_i27 : i27 = state.val[i.val + 4] := by simp only [i27_post, hi26]
  have h_i30 : i30 = state.val[i.val]     := by simp only [i30_post, hi29]
  have h_i33 : i33 = state.val[i.val + 3] := by simp only [i33_post, hi32]
  have h_i31 : i31 = i28 &&& i30 := UScalar.eq_of_val_eq i31_post1
  have h_i34 : i34 = state.val[i.val + 3] ^^^ (~~~ state.val[i.val + 4] &&& state.val[i.val]) := by
    have eq34 : i34 = i33 ^^^ i31 := UScalar.eq_of_val_eq i34_post1
    rw [eq34, h_i31, i28_post, h_i33, h_i27, h_i30]
  refine ⟨?_, ?_⟩
  · rw [result_post]; simp [Aeneas.Std.Array.set_val_eq]
  intro k hk
  rw [result_post]
  simp only [Aeneas.Std.Array.set_val_eq, hi32]
  by_cases hk_eq : k = i.val + 3
  · subst hk_eq
    have hLset : (i.val + 3) < (state.val.set (i.val + 3) i34).length := by
      rw [List.length_set, hL]; scalar_tac
    rw [if_pos rfl, List.getElem_set_self, h_i34]
  · have hLk : k < (state.val.set (i.val + 3) i34).length := by
      rw [List.length_set, hL]; exact hk
    rw [if_neg hk_eq, List.getElem_set_ne (Ne.symm hk_eq)
]

@[local step]
private theorem chi_row_w4.spec (i : Usize) (state : Keccak1600)
    (hi : i.val + 4 < 25) (hL : state.val.length = 25) :
    chi_row_w4 i state
    ⦃ (result : Keccak1600) =>
      result.val.length = 25 ∧
      ∀ k (hk : k < 25),
        result.val[k] =
          (if k = i.val + 4 then
            state.val[i.val + 4] ^^^ (~~~ state.val[i.val] &&& state.val[i.val + 1])
           else state.val[k]) ⦄ := by
  unfold chi_row_w4
  step*
  have hi35 : i35.val = i.val     := by simp [i35_post]
  have hi38 : i38.val = i.val + 1 := by simp [i38_post]
  have hi41 : i41.val = i.val + 4 := by simp [i41_post]
  have hL_i35 : i35.val < state.val.length := by rw [hi35]; scalar_tac
  have hL_i38 : i38.val < state.val.length := by rw [hi38]; scalar_tac
  have hL_i41 : i41.val < state.val.length := by rw [hi41]; scalar_tac
  have h_i36 : i36 = state.val[i.val]     := by simp only [i36_post, hi35]
  have h_i39 : i39 = state.val[i.val + 1] := by simp only [i39_post, hi38]
  have h_i42 : i42 = state.val[i.val + 4] := by simp only [i42_post, hi41]
  have h_i40 : i40 = i37 &&& i39 := UScalar.eq_of_val_eq i40_post1
  have h_i43 : i43 = state.val[i.val + 4] ^^^ (~~~ state.val[i.val] &&& state.val[i.val + 1]) := by
    have eq43 : i43 = i42 ^^^ i40 := UScalar.eq_of_val_eq i43_post1
    rw [eq43, h_i40, i37_post, h_i42, h_i36, h_i39]
  refine ⟨?_, ?_⟩
  · rw [result_post]; simp [Aeneas.Std.Array.set_val_eq]
  intro k hk
  rw [result_post]
  simp only [Aeneas.Std.Array.set_val_eq, hi41]
  by_cases hk_eq : k = i.val + 4
  · subst hk_eq
    have hLset : (i.val + 4) < (state.val.set (i.val + 4) i43).length := by
      rw [List.length_set, hL]; scalar_tac
    rw [if_pos rfl, List.getElem_set_self, h_i43]
  · have hLk : k < (state.val.set (i.val + 4) i43).length := by
      rw [List.length_set, hL]; exact hk
    rw [if_neg hk_eq, List.getElem_set_ne (Ne.symm hk_eq)
]

@[local step]
private theorem chi_row_w01.spec (i : Usize) (t1 t2 : U64) (state : Keccak1600)
    (hi : i.val + 4 < 25) (hL : state.val.length = 25) :
    chi_row_w01 i t1 t2 state
    ⦃ (result : Keccak1600) =>
      result.val.length = 25 ∧
      ∀ k (hk : k < 25),
        result.val[k] =
          (if k = i.val then t1
           else if k = i.val + 1 then t2
           else state.val[k]) ⦄ := by
  unfold chi_row_w01
  step*
  have hi44 : i44.val = i.val     := by simp [i44_post]
  have hi45 : i45.val = i.val + 1 := by simp [i45_post]
  have hi_lt : i.val < 25 := Nat.lt_of_add_right_lt hi
  have hi1_lt : i.val + 1 < 25 := by
    have := hi; exact Nat.lt_of_succ_lt (Nat.lt_of_succ_lt (Nat.lt_of_succ_lt this))
  refine ⟨?_, ?_⟩
  · rw [result_post, state4_post]
    show ((state.val.set i44.val t1).set i45.val t2).length = 25
    rw [List.length_set, List.length_set, hL]
  intro k hk
  rw [result_post, state4_post]
  show ((state.val.set i44.val t1).set i45.val t2)[k] = _
  rw [hi44, hi45]
  by_cases hk0 : k = i.val
  · subst hk0
    have hne1 : i.val + 1 ≠ i.val := Nat.succ_ne_self _
    rw [if_pos rfl, List.getElem_set_ne hne1, List.getElem_set_self]
  · by_cases hk1 : k = i.val + 1
    · subst hk1
      rw [if_neg hk0, if_pos rfl, List.getElem_set_self]
    · rw [if_neg hk0, if_neg hk1,
          List.getElem_set_ne (Ne.symm hk1),
          List.getElem_set_ne (Ne.symm hk0)]

/-! ### Composed spec for `keccak_chi_row` -/

set_option maxHeartbeats 8000000 in
@[local step]
private theorem keccak_chi_row.spec (state : Keccak1600) (r : Usize) (hr : r.val < 5) :
    sha3.sha3_impl.keccak_chi_row state r
    ⦃ (result : Keccak1600) =>
      result.val.length = 25 ∧
      ∀ k (hk : k < 25),
        result.val[k] =
          (if k = 5 * r.val then
            state.val[5 * r.val] ^^^ (~~~ state.val[5 * r.val + 1] &&& state.val[5 * r.val + 2])
           else if k = 5 * r.val + 1 then
            state.val[5 * r.val + 1] ^^^ (~~~ state.val[5 * r.val + 2] &&& state.val[5 * r.val + 3])
           else if k = 5 * r.val + 2 then
            state.val[5 * r.val + 2] ^^^ (~~~ state.val[5 * r.val + 3] &&& state.val[5 * r.val + 4])
           else if k = 5 * r.val + 3 then
            state.val[5 * r.val + 3] ^^^ (~~~ state.val[5 * r.val + 4] &&& state.val[5 * r.val])
           else if k = 5 * r.val + 4 then
            state.val[5 * r.val + 4] ^^^ (~~~ state.val[5 * r.val] &&& state.val[5 * r.val + 1])
           else state.val[k]) ⦄ := by
  rw [keccak_chi_row.fold6]
  step*
  have hi : i.val = 5 * r.val := i_post
  have h_state1 : ∀ X (hX : X < 25), X ≠ i.val + 2 → state1.val[X] = state.val[X] := by
    intro X hX hne
    have := state1_post2 X hX
    rwa [if_neg hne] at this
  have h_state2_to_1 : ∀ X (hX : X < 25), X ≠ i.val + 3 → state2.val[X] = state1.val[X] := by
    intro X hX hne
    have := state2_post2 X hX
    rwa [if_neg hne] at this
  have h_state3_to_2 : ∀ X (hX : X < 25), X ≠ i.val + 4 → state3.val[X] = state2.val[X] := by
    intro X hX hne
    have := state3_post2 X hX
    rwa [if_neg hne] at this
  have h_state2 : ∀ X (hX : X < 25), X ≠ i.val + 2 → X ≠ i.val + 3 → state2.val[X] = state.val[X] := by
    intro X hX hne2 hne3
    rw [h_state2_to_1 X hX hne3, h_state1 X hX hne2]
  have h_state3 : ∀ X (hX : X < 25), X ≠ i.val + 2 → X ≠ i.val + 3 → X ≠ i.val + 4 →
      state3.val[X] = state.val[X] := by
    intro X hX hne2 hne3 hne4
    rw [h_state3_to_2 X hX hne4, h_state2 X hX hne2 hne3]
  have hr0 : i.val ≠ i.val + 1 := Nat.ne_of_lt (Nat.lt_succ_self _)
  have hr0_2 : i.val ≠ i.val + 2 := Nat.ne_of_lt (Nat.lt_succ_of_lt (Nat.lt_succ_self _))
  have hr0_3 : i.val ≠ i.val + 3 :=
    Nat.ne_of_lt (Nat.lt_succ_of_lt (Nat.lt_succ_of_lt (Nat.lt_succ_self _)))
  have hr0_4 : i.val ≠ i.val + 4 := Nat.ne_of_lt
    (Nat.lt_succ_of_lt (Nat.lt_succ_of_lt (Nat.lt_succ_of_lt (Nat.lt_succ_self _))))
  have hr1_2 : i.val + 1 ≠ i.val + 2 := Nat.ne_of_lt (Nat.lt_succ_self _)
  have hr1_3 : i.val + 1 ≠ i.val + 3 :=
    Nat.ne_of_lt (Nat.lt_succ_of_lt (Nat.lt_succ_self _))
  have hr1_4 : i.val + 1 ≠ i.val + 4 :=
    Nat.ne_of_lt (Nat.lt_succ_of_lt (Nat.lt_succ_of_lt (Nat.lt_succ_self _)))
  have hr2_3 : i.val + 2 ≠ i.val + 3 := Nat.ne_of_lt (Nat.lt_succ_self _)
  have hr2_4 : i.val + 2 ≠ i.val + 4 :=
    Nat.ne_of_lt (Nat.lt_succ_of_lt (Nat.lt_succ_self _))
  have hr3_4 : i.val + 3 ≠ i.val + 4 := Nat.ne_of_lt (Nat.lt_succ_self _)
  have hr_le : r.val ≤ 4 := Nat.le_of_lt_succ hr
  have hi_lt0 : i.val < 25 := by
    rw [hi]; calc 5 * r.val ≤ 5 * 4 := Nat.mul_le_mul_left 5 hr_le
              _ = 20 := by decide
              _ < 25 := by decide
  have hi_lt1 : i.val + 1 < 25 := by
    rw [hi]; calc 5 * r.val + 1 ≤ 5 * 4 + 1 := Nat.add_le_add_right (Nat.mul_le_mul_left 5 hr_le) 1
                _ = 21 := by decide
                _ < 25 := by decide
  have hi_lt2 : i.val + 2 < 25 := by
    rw [hi]; calc 5 * r.val + 2 ≤ 5 * 4 + 2 := Nat.add_le_add_right (Nat.mul_le_mul_left 5 hr_le) 2
                _ = 22 := by decide
                _ < 25 := by decide
  have hi_lt3 : i.val + 3 < 25 := by
    rw [hi]; calc 5 * r.val + 3 ≤ 5 * 4 + 3 := Nat.add_le_add_right (Nat.mul_le_mul_left 5 hr_le) 3
                _ = 23 := by decide
                _ < 25 := by decide
  have hi_lt4 : i.val + 4 < 25 := by
    rw [hi]; calc 5 * r.val + 4 ≤ 5 * 4 + 4 := Nat.add_le_add_right (Nat.mul_le_mul_left 5 hr_le) 4
                _ = 24 := by decide
                _ < 25 := by decide
  refine ⟨result_post1, fun k hk => ?_⟩
  simp only [show (5 * r.val) = i.val from hi.symm]
  have h_w01_k := result_post2 k hk
  by_cases hk0 : k = i.val
  · subst hk0
    rw [if_pos rfl] at h_w01_k
    rw [if_pos rfl, h_w01_k, t1_post]
  · by_cases hk1 : k = i.val + 1
    · subst hk1
      rw [if_neg hr0.symm, if_pos rfl] at h_w01_k
      rw [if_neg hk0, if_pos rfl, h_w01_k, t2_post]
    · by_cases hk2 : k = i.val + 2
      · subst hk2
        rw [if_neg hr0_2.symm, if_neg hr1_2.symm] at h_w01_k
        have h_s3 : state3.val[i.val + 2] = state2.val[i.val + 2] :=
          h_state3_to_2 _ hi_lt2 hr2_4
        have h_s2 : state2.val[i.val + 2] = state1.val[i.val + 2] :=
          h_state2_to_1 _ hi_lt2 hr2_3
        have h_s1 := state1_post2 (i.val + 2) hi_lt2
        rw [if_pos rfl] at h_s1
        rw [if_neg hk0, if_neg hk1, if_pos rfl, h_w01_k, h_s3, h_s2, h_s1]
      · by_cases hk3 : k = i.val + 3
        · subst hk3
          rw [if_neg hr0_3.symm, if_neg hr1_3.symm] at h_w01_k
          have h_s3 : state3.val[i.val + 3] = state2.val[i.val + 3] :=
            h_state3_to_2 _ hi_lt3 hr3_4
          have h_s2 := state2_post2 (i.val + 3) hi_lt3
          rw [if_pos rfl] at h_s2
          have h_s1_3 : state1.val[i.val + 3] = state.val[i.val + 3] :=
            h_state1 _ hi_lt3 hr2_3.symm
          have h_s1_4 : state1.val[i.val + 4] = state.val[i.val + 4] :=
            h_state1 _ hi_lt4 hr2_4.symm
          have h_s1_0 : state1.val[i.val] = state.val[i.val] :=
            h_state1 _ hi_lt0 hr0_2
          rw [if_neg hk0, if_neg hk1, if_neg hk2, if_pos rfl,
              h_w01_k, h_s3, h_s2, h_s1_3, h_s1_4, h_s1_0]
        · by_cases hk4 : k = i.val + 4
          · subst hk4
            rw [if_neg hr0_4.symm, if_neg hr1_4.symm] at h_w01_k
            have h_s3 := state3_post2 (i.val + 4) hi_lt4
            rw [if_pos rfl] at h_s3
            have h_s2_4 : state2.val[i.val + 4] = state.val[i.val + 4] :=
              h_state2 _ hi_lt4 hr2_4.symm hr3_4.symm
            have h_s2_0 : state2.val[i.val] = state.val[i.val] :=
              h_state2 _ hi_lt0 hr0_2 hr0_3
            have h_s2_1 : state2.val[i.val + 1] = state.val[i.val + 1] :=
              h_state2 _ hi_lt1 hr1_2 hr1_3
            rw [if_neg hk0, if_neg hk1, if_neg hk2, if_neg hk3, if_pos rfl,
                h_w01_k, h_s3, h_s2_4, h_s2_0, h_s2_1]
          · rw [if_neg hk0, if_neg hk1] at h_w01_k
            rw [if_neg hk0, if_neg hk1, if_neg hk2, if_neg hk3, if_neg hk4,
                h_w01_k]
            exact h_state3 k hk hk2 hk3 hk4

set_option maxHeartbeats 4000000 in
@[step]
theorem keccak_chi.spec (state : Keccak1600) :
    keccak_chi state
    ⦃ (result : Keccak1600) =>
      Lanes25.ofArray result = chiCore (Lanes25.ofArray state) ⦄ := by
  unfold keccak_chi
  step*
  apply Lanes25.ext <;> dsimp only [Lanes25.ofArray, chiCore]
  case h0 =>
    rw [result_post2 0 (by decide), state4_post2 0 (by decide), state3_post2 0 (by decide),
        state2_post2 0 (by decide), state1_post2 0 (by decide)]; rfl
  case h1 =>
    rw [result_post2 1 (by decide), state4_post2 1 (by decide), state3_post2 1 (by decide),
        state2_post2 1 (by decide), state1_post2 1 (by decide)]; rfl
  case h2 =>
    rw [result_post2 2 (by decide), state4_post2 2 (by decide), state3_post2 2 (by decide),
        state2_post2 2 (by decide), state1_post2 2 (by decide)]; rfl
  case h3 =>
    rw [result_post2 3 (by decide), state4_post2 3 (by decide), state3_post2 3 (by decide),
        state2_post2 3 (by decide), state1_post2 3 (by decide)]; rfl
  case h4 =>
    rw [result_post2 4 (by decide), state4_post2 4 (by decide), state3_post2 4 (by decide),
        state2_post2 4 (by decide), state1_post2 4 (by decide)]; rfl
  case h5 =>
    rw [result_post2 5 (by decide), state4_post2 5 (by decide), state3_post2 5 (by decide),
        state2_post2 5 (by decide), state1_post2 5 (by decide),
        state1_post2 6 (by decide), state1_post2 7 (by decide)]; simp
  case h6 =>
    rw [result_post2 6 (by decide), state4_post2 6 (by decide), state3_post2 6 (by decide),
        state2_post2 6 (by decide), state1_post2 6 (by decide),
        state1_post2 7 (by decide), state1_post2 8 (by decide)]; simp
  case h7 =>
    rw [result_post2 7 (by decide), state4_post2 7 (by decide), state3_post2 7 (by decide),
        state2_post2 7 (by decide), state1_post2 7 (by decide),
        state1_post2 8 (by decide), state1_post2 9 (by decide)]; simp
  case h8 =>
    rw [result_post2 8 (by decide), state4_post2 8 (by decide), state3_post2 8 (by decide),
        state2_post2 8 (by decide), state1_post2 8 (by decide),
        state1_post2 9 (by decide), state1_post2 5 (by decide)]; simp
  case h9 =>
    rw [result_post2 9 (by decide), state4_post2 9 (by decide), state3_post2 9 (by decide),
        state2_post2 9 (by decide), state1_post2 9 (by decide),
        state1_post2 5 (by decide), state1_post2 6 (by decide)]; simp
  case h10 =>
    rw [result_post2 10 (by decide), state4_post2 10 (by decide), state3_post2 10 (by decide),
        state2_post2 10 (by decide), state2_post2 11 (by decide), state2_post2 12 (by decide),
        state1_post2 10 (by decide), state1_post2 11 (by decide), state1_post2 12 (by decide)]; simp
  case h11 =>
    rw [result_post2 11 (by decide), state4_post2 11 (by decide), state3_post2 11 (by decide),
        state2_post2 11 (by decide), state2_post2 12 (by decide), state2_post2 13 (by decide),
        state1_post2 11 (by decide), state1_post2 12 (by decide), state1_post2 13 (by decide)]; simp
  case h12 =>
    rw [result_post2 12 (by decide), state4_post2 12 (by decide), state3_post2 12 (by decide),
        state2_post2 12 (by decide), state2_post2 13 (by decide), state2_post2 14 (by decide),
        state1_post2 12 (by decide), state1_post2 13 (by decide), state1_post2 14 (by decide)]; simp
  case h13 =>
    rw [result_post2 13 (by decide), state4_post2 13 (by decide), state3_post2 13 (by decide),
        state2_post2 13 (by decide), state2_post2 14 (by decide), state2_post2 10 (by decide),
        state1_post2 13 (by decide), state1_post2 14 (by decide), state1_post2 10 (by decide)]; simp
  case h14 =>
    rw [result_post2 14 (by decide), state4_post2 14 (by decide), state3_post2 14 (by decide),
        state2_post2 14 (by decide), state2_post2 10 (by decide), state2_post2 11 (by decide),
        state1_post2 14 (by decide), state1_post2 10 (by decide), state1_post2 11 (by decide)]; simp
  case h15 =>
    rw [result_post2 15 (by decide), state4_post2 15 (by decide),
        state3_post2 15 (by decide), state3_post2 16 (by decide), state3_post2 17 (by decide),
        state2_post2 15 (by decide), state2_post2 16 (by decide), state2_post2 17 (by decide),
        state1_post2 15 (by decide), state1_post2 16 (by decide), state1_post2 17 (by decide)]; simp
  case h16 =>
    rw [result_post2 16 (by decide), state4_post2 16 (by decide),
        state3_post2 16 (by decide), state3_post2 17 (by decide), state3_post2 18 (by decide),
        state2_post2 16 (by decide), state2_post2 17 (by decide), state2_post2 18 (by decide),
        state1_post2 16 (by decide), state1_post2 17 (by decide), state1_post2 18 (by decide)]; simp
  case h17 =>
    rw [result_post2 17 (by decide), state4_post2 17 (by decide),
        state3_post2 17 (by decide), state3_post2 18 (by decide), state3_post2 19 (by decide),
        state2_post2 17 (by decide), state2_post2 18 (by decide), state2_post2 19 (by decide),
        state1_post2 17 (by decide), state1_post2 18 (by decide), state1_post2 19 (by decide)]; simp
  case h18 =>
    rw [result_post2 18 (by decide), state4_post2 18 (by decide),
        state3_post2 18 (by decide), state3_post2 19 (by decide), state3_post2 15 (by decide),
        state2_post2 18 (by decide), state2_post2 19 (by decide), state2_post2 15 (by decide),
        state1_post2 18 (by decide), state1_post2 19 (by decide), state1_post2 15 (by decide)]; simp
  case h19 =>
    rw [result_post2 19 (by decide), state4_post2 19 (by decide),
        state3_post2 19 (by decide), state3_post2 15 (by decide), state3_post2 16 (by decide),
        state2_post2 19 (by decide), state2_post2 15 (by decide), state2_post2 16 (by decide),
        state1_post2 19 (by decide), state1_post2 15 (by decide), state1_post2 16 (by decide)]; simp
  case h20 =>
    rw [result_post2 20 (by decide),
        state4_post2 20 (by decide), state4_post2 21 (by decide), state4_post2 22 (by decide),
        state3_post2 20 (by decide), state3_post2 21 (by decide), state3_post2 22 (by decide),
        state2_post2 20 (by decide), state2_post2 21 (by decide), state2_post2 22 (by decide),
        state1_post2 20 (by decide), state1_post2 21 (by decide), state1_post2 22 (by decide)]; simp
  case h21 =>
    rw [result_post2 21 (by decide),
        state4_post2 21 (by decide), state4_post2 22 (by decide), state4_post2 23 (by decide),
        state3_post2 21 (by decide), state3_post2 22 (by decide), state3_post2 23 (by decide),
        state2_post2 21 (by decide), state2_post2 22 (by decide), state2_post2 23 (by decide),
        state1_post2 21 (by decide), state1_post2 22 (by decide), state1_post2 23 (by decide)]; simp
  case h22 =>
    rw [result_post2 22 (by decide),
        state4_post2 22 (by decide), state4_post2 23 (by decide), state4_post2 24 (by decide),
        state3_post2 22 (by decide), state3_post2 23 (by decide), state3_post2 24 (by decide),
        state2_post2 22 (by decide), state2_post2 23 (by decide), state2_post2 24 (by decide),
        state1_post2 22 (by decide), state1_post2 23 (by decide), state1_post2 24 (by decide)]; simp
  case h23 =>
    rw [result_post2 23 (by decide),
        state4_post2 23 (by decide), state4_post2 24 (by decide), state4_post2 20 (by decide),
        state3_post2 23 (by decide), state3_post2 24 (by decide), state3_post2 20 (by decide),
        state2_post2 23 (by decide), state2_post2 24 (by decide), state2_post2 20 (by decide),
        state1_post2 23 (by decide), state1_post2 24 (by decide), state1_post2 20 (by decide)]; simp
  case h24 =>
    rw [result_post2 24 (by decide),
        state4_post2 24 (by decide), state4_post2 20 (by decide), state4_post2 21 (by decide),
        state3_post2 24 (by decide), state3_post2 20 (by decide), state3_post2 21 (by decide),
        state2_post2 24 (by decide), state2_post2 20 (by decide), state2_post2 21 (by decide),
        state1_post2 24 (by decide), state1_post2 20 (by decide), state1_post2 21 (by decide)]; simp

/-- `keccak_iota` requires `rnd < 24` so that `KECCAK_IOTA_K[rnd.val]` is in
range; on success it XORs the round constant into lane (0, 0). -/
@[step]
theorem keccak_iota.spec (state : Keccak1600) (rnd : Usize)
    (hrnd : rnd.val < 24) :
    keccak_iota state rnd
    ⦃ (result : Keccak1600) =>
      Lanes25.ofArray result =
        { Lanes25.ofArray state with
          l0 := (Lanes25.ofArray state).l0 ^^^ KECCAK_IOTA_K.val[rnd.val] } ⦄ := by
  unfold keccak_iota
  step*
  subst result_post
  simp [Lanes25.ofArray]
  rw [← i_post, ← i1_post]; bv_tac 64

/-! ## One round = `fusedRoundCore`

The textbook `keccak_perm_round` chains θ ∘ ρ ∘ π ∘ χ ∘ ι sequentially.
By `fusedCore_eq_composed`, the composition equals `fusedCore`, so the round
matches `fusedRoundCore`. This is the key bridge between the textbook
decomposition and the opt fused form, and lets us share `iterateRndCore`
end-to-end. -/

@[step]
theorem keccak_perm_round.spec (state : Keccak1600) (rnd : Usize)
    (hrnd : rnd.val < 24) :
    keccak_perm_round state rnd
    ⦃ (result : Keccak1600) =>
      Lanes25.ofArray result =
        fusedRoundCore (Lanes25.ofArray state) (KECCAK_IOTA_K.val[rnd.val]) ⦄ := by
  unfold keccak_perm_round
  step*
  rw [result_post, state4_post, state3_post, state2_post, state1_post]
  rw [show chiCore (piCore (rhoCore (thetaCore (Lanes25.ofArray state)))) =
        fusedCore (Lanes25.ofArray state) from (fusedCore_eq_composed _).symm]
  rfl

/-! ## 24-round loop

Mirrors `keccak_permute_opt_loop.spec` (in `Loop.lean`) but operates on
`Array U64 25#usize` rather than 25 unrolled U64s. The loop invariant is
`Lanes25.ofArray p_state = iterateRndCore A₀ iter.start.val`; the proof
follows the recursive-loop skeleton from `aeneas-lean-core` Pattern 4:

  1. `unfold` and `by_cases hlt : iter.start.val < iter.«end».val`.
  2. Some case: `let* IteratorRange_next_some`, then `step` through
     `keccak_perm_round.spec`, advance the invariant via
     `iterateRndCore_succ`, manual IH via `WP.spec_mono`.
  3. None case: `let* IteratorRange_next_none`, scalar_tac the bound,
     return `hinv` (with `iter.start.val = 24` substituted).

The iterator step lemmas (`IteratorRange_next_some/none`) are already in
scope from `Loop.lean`. -/

set_option maxHeartbeats 1000000 in
set_option maxRecDepth 8192 in
@[step]
theorem keccak_permute_textbook_loop.spec
    (iter : core.ops.range.Range Usize) (p_state : Keccak1600)
    (hend : iter.«end».val = 24)
    (hstart : iter.start.val ≤ 24)
    (A₀ : Lanes25)
    (hinv : Lanes25.ofArray p_state = iterateRndCore A₀ iter.start.val) :
    keccak_permute_textbook_loop iter p_state
    ⦃ (result : Keccak1600) =>
      Lanes25.ofArray result = iterateRndCore A₀ 24 ⦄ := by
  rw [keccak_permute_textbook_loop.eq_def]
  by_cases hlt : iter.start.val < iter.«end».val
  · -- some: iterator yields next round index r = iter.start.
    let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← IteratorRange_next_some
    rw [hsome]
    simp only []
    have hrnd : iter.start.val < 24 := by rw [← hend]; exact hlt
    let* ⟨ p_state1, p_state1_post ⟩ ← keccak_perm_round.spec
    have hend1 : iter1.«end».val = 24 := by rw [hend']; exact hend
    have hstart1 : iter1.start.val ≤ 24 := by scalar_tac
    have hinv1 : Lanes25.ofArray p_state1 = iterateRndCore A₀ iter1.start.val := by
      have h2 : iter.start.val + 1 ≤ 24 := by scalar_tac
      simp only [hstart']
      rw [iterateRndCore_succ A₀ iter.start.val h2, ← hinv, ← p_state1_post]
    apply WP.spec_mono
      (keccak_permute_textbook_loop.spec iter1 p_state1 hend1 hstart1 A₀ hinv1)
    intro p heq
    exact heq
  · -- None case: iterator exhausted.
    have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← IteratorRange_next_none
    rw [hnone]
    simp only [WP.spec_ok]
    have heq : iter.start.val = 24 := by scalar_tac
    simp only [heq] at hinv; exact hinv
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-! ## Wrapper

The wrapper `keccak_permute_textbook` just calls the loop on
`{ start := 0, end := 24 }`. The spec matches `keccak_permute_opt.spec`
exactly so that the equivalence corollary below is a direct transitivity. -/

@[step]
theorem keccak_permute_textbook.spec (state : Keccak1600) :
    keccak_permute_textbook state
    ⦃ (result : Keccak1600) =>
      toState result = iterateRnd (toState state) 24 ⦄ := by
  unfold keccak_permute_textbook
  have hstart : ((0#usize : Usize)).val ≤ 24 := by scalar_tac
  have hinv : Lanes25.ofArray state =
      iterateRndCore (Lanes25.ofArray state) ((0#usize : Usize)).val hstart := by
    simp [iterateRndCore]
  apply WP.spec_mono
    (keccak_permute_textbook_loop.spec _ _ (by scalar_tac) hstart
      (Lanes25.ofArray state) hinv)
  intro r hr
  unfold toState
  rw [hr, iterateRndCore_toState]

/-! ## Equivalence corollary

Both `keccak_permute_textbook` and `keccak_permute_opt` are characterised by
`toState result = iterateRnd (toState state) 24`. Since `iterateRnd` is a
function (and `toState = Lanes25.ofArray + toLane`, both bijective at length 25
and 64 respectively), the two implementations are equal as `Result`-valued
functions on `Keccak1600`.

The simplest finishing strategy is to use both `.spec`s, observe that they
share the same post, and conclude by `Lanes25.ofArray`-injectivity (the array
length is fixed to 25 by the type). Concretely, both `.spec`s actually pin
the post-state lane-by-lane via `iterateRndCore`, so the underlying arrays
must be equal element-by-element.

This corollary is what licenses swapping the production hot path: changing
the one-line forwarder
  `fn keccak_permute(p_state) { super::keccak_opt::keccak_permute_opt(p_state); }`
to call `keccak_permute_textbook` instead is provably semantics-preserving. -/

/-- `Lanes25.ofArray` is injective at type `Keccak1600 = Array U64 25#usize`:
the array length is pinned to 25 by the type, and `Lanes25.ofArray` reads the
first 25 elements via `[i]`, so it captures the full underlying data. -/
theorem Lanes25.ofArray_injective {a b : Keccak1600}
    (h : Lanes25.ofArray a = Lanes25.ofArray b) : a = b := by
  apply Subtype.ext
  rcases a with ⟨la, hla⟩
  rcases b with ⟨lb, hlb⟩
  simp only [Lanes25.ofArray, Lanes25.mk.injEq] at h
  have hla' : la.length = 25 := by simpa using hla
  have hlb' : lb.length = 25 := by simpa using hlb
  show la = lb
  obtain ⟨h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14,
         h15, h16, h17, h18, h19, h20, h21, h22, h23, h24⟩ := h
  apply List.ext_getElem (by rw [hla', hlb'])
  intro i hi hi'
  rw [hla'] at hi
  interval_cases i <;> assumption

/-- Sharper post for `keccak_permute_textbook`: pins the result at the
`Lanes25.ofArray` level rather than going through `toState`. This is the form
needed for the array-level equivalence corollary below; it follows directly
from the loop spec since the wrapper just invokes the loop. -/
theorem keccak_permute_textbook_strong (state : Keccak1600) :
    keccak_permute_textbook state
    ⦃ (result : Keccak1600) =>
      Lanes25.ofArray result = iterateRndCore (Lanes25.ofArray state) 24 ⦄ := by
  unfold keccak_permute_textbook
  have hstart : ((0#usize : Usize)).val ≤ 24 := by scalar_tac
  have hinv : Lanes25.ofArray state =
      iterateRndCore (Lanes25.ofArray state) ((0#usize : Usize)).val hstart := by
    simp [iterateRndCore]
  exact keccak_permute_textbook_loop.spec _ _ (by scalar_tac) hstart
    (Lanes25.ofArray state) hinv

/-- Sharper post for `keccak_permute_opt`: mirrors `keccak_permute_opt.spec`
in `Loop.lean` but lands at the `Lanes25.ofArray` level (using
`Lanes25.ofArray_toArray` to peel the `Array.make`/`Lanes25.toArray` repack)
rather than at `toState`. -/
theorem keccak_permute_opt_strong (state : Keccak1600) :
    sha3.keccak_opt.keccak_permute_opt state
    ⦃ (result : Keccak1600) =>
      Lanes25.ofArray result = iterateRndCore (Lanes25.ofArray state) 24 ⦄ := by
  rw [keccak_permute_opt_decomp_eq, keccak_permute_opt_prefix_eq]
  step*
  · exact Lanes25.ofArray state
  · rfl
  · show Lanes25.ofArray
      (Lanes25.mk _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _).toArray = _
    simp only [Lanes25.ofArray_toArray]
    assumption

theorem keccak_permute_textbook_eq_opt (state : Keccak1600) :
    sha3.sha3_impl.keccak_permute_textbook state
  = sha3.keccak_opt.keccak_permute_opt state := by
  have h_tb := keccak_permute_textbook_strong state
  have h_opt := keccak_permute_opt_strong state
  cases ht : sha3.sha3_impl.keccak_permute_textbook state with
  | ok rt =>
    cases ho : sha3.keccak_opt.keccak_permute_opt state with
    | ok ro =>
      rw [ht] at h_tb
      rw [ho] at h_opt
      simp only [Aeneas.Std.WP.spec_ok] at h_tb h_opt
      congr 1
      exact Lanes25.ofArray_injective (h_tb.trans h_opt.symm)
    | fail e => rw [ho] at h_opt; simp at h_opt
    | div => rw [ho] at h_opt; simp at h_opt
  | fail e => rw [ht] at h_tb; simp at h_tb
  | div => rw [ht] at h_tb; simp at h_tb

namespace sha3.sha3_impl

/-- Production `keccak_permute` forwards to `keccak_permute_textbook` (matching
    `feature/verifiedcrypto`); its spec delegates to `keccak_permute_textbook.spec`.
    Lives here (not `Loop.lean`) because it now depends on the textbook spec. -/
@[step]
theorem keccak_permute.spec
    (state : Keccak1600) :
    keccak_permute state
    ⦃ (result : Keccak1600) =>
      toState result = iterateRnd (toState state) 24 ⦄ := by
  unfold keccak_permute
  step
  assumption

end sha3.sha3_impl

end symcrust
