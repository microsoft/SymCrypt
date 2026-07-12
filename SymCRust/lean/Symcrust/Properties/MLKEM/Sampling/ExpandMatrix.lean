/-
  # Sampling/ExpandMatrix.lean — ExpandA and key-hash.

  Covers:

      mlkem.key_expand_public_matrix_from_public_seed_loop0_loop0  -- inner j (cols)
      mlkem.key_expand_public_matrix_from_public_seed_loop0        -- outer i (rows)
      mlkem.key_expand_public_matrix_from_public_seed              -- ExpandA wrapper
      mlkem.key_compute_encapsulation_key_hash                     -- H(ek) for FO

  ## Structure-vs-body decomposition

  Both loops follow the standard `next + match` shape and are
  decomposed via the two-clause cascade recipe into `<loop>_body`
  (one column / one row) and `<loop>_match.fold` (per-iteration
  dispatch).  The loop spec is then proved by induction, rewriting
  via the two `.fold` lemmas.

  ## ExpandA: FIPS 203 Algorithm 5

  Each matrix entry `Â[i, j]` is sampled via SampleNTT applied to a
  fresh SHAKE128 instance seeded with `ρ ‖ j ‖ i` (note the i,j order
  swap: the implementation stores `A^T`, so `Â^T[i, j] = Â[j, i]` is
  sampled with bytes `j ‖ i`).

  Postcondition (wrapper): every (i, j) ∈ [0, k)² satisfies
      toPoly pk_mlkem_key1.a_transpose[i * k + j]
        = MLKEM.SampleNTT (xofExtract (SHAKE128 (ρ ‖ j ‖ i)))
  i.e., `toMatrix pk_mlkem_key1.a_transpose = (Spec.ExpandA ρ)^T`.

  ## Key-hash: `key_compute_encapsulation_key_hash`

  Computes `H(encoded_t ‖ ρ)` (SHA3-256) and stores in
  `encaps_key_hash`. Direct chained `init/append/result`, no loops.

  Bridge to `MLKEM.ExpandA` uses the same
  `xofExtract` model as `Sampling/SampleNTT.lean`.
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Ffi
import Symcrust.Properties.MLKEM.Hash
import Symcrust.Properties.MLKEM.HashCalls
import Symcrust.Properties.MLKEM.Bridges.KeyView
import Symcrust.Properties.MLKEM.Bridges.Encoding
import Symcrust.Properties.MLKEM.Bridges.PrfShake
import Symcrust.Properties.MLKEM.Sampling.SampleNTT

open Aeneas Aeneas.Std Result
open scoped Spec.Notations
open Spec
open Spec.MLKEM
open symcrust

namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 4000000
set_option maxRecDepth 2048

/-! ## Spec hook: ExpandA matrix entry

The matrix `Â^T` returned by ExpandA satisfies, for each `(i, j) ∈
[0, k)²`,

    keyAHat key' p i j = MLKEM.SampleNTT (ρ ‖ #v[j] ‖ #v[i])

where `ρ : 𝔹 32` is the public seed.  We define `expandAEntry` as the
spec-side function producing the bytes seed for one entry. -/

/-- Spec-side bytes seed for entry `(i, j)` of `Â^T`.  `i, j < 256`. -/
noncomputable def expandAEntrySeed (ρ : 𝔹 32) (i j : ℕ)
    (_ : i < 256 := by grind) (_ : j < 256 := by grind) : 𝔹 34 :=
  (ρ ‖ #v[(j : Byte)]) ‖ #v[(i : Byte)]

/-! ## Streaming invariants

We use `MlKemHashState.absorbing/squeezing` ghost predicates from
`Hash.lean` (`g : sha3.sha3_impl.GhostState`) to thread the XOF state
through both loops. -/

/-- Non-data, non-public_seed fields of `key` equal those of `orig_key`.
The body of the ExpandMatrix loops only writes `key.data`, so every
other field is structurally preserved across the entire matrix sweep.
Threaded through `expandAInnerInv` and `expandAOuterInv` so the wrapper
can recover all 9 frame fields from the outer postcondition. -/
def keyStructFrame (key orig_key : mlkem.key.Key) : Prop :=
  key.public_seed = orig_key.public_seed ∧
  key.params = orig_key.params ∧
  key.n_rows = orig_key.n_rows ∧
  key.encoded_t = orig_key.encoded_t ∧
  key.encaps_key_hash = orig_key.encaps_key_hash ∧
  key.private_seed = orig_key.private_seed ∧
  key.private_random = orig_key.private_random ∧
  key.has_private_seed = orig_key.has_private_seed ∧
  key.has_private_key = orig_key.has_private_key

/-- **Inner-loop invariant** for the j-loop at row `i`.

After processing `j` columns of row `i`:
* `key.data[i*(k p) .. i*(k p) + j]` matches the spec via
  `SampleNTT (ρ ‖ [col, i])` for each `col < j`;
* `key.data[…]` outside `[i*(k p), i*(k p) + j)` is unchanged from
  `orig_key.data[…]`;
* the base hash state `p_shake_state_base` is in absorbing mode for
  the ghost `g_base` whose `absorbed = ρ.toList`;
* non-data fields of `key` equal those of `orig_key` (`keyStructFrame`).

`ρ` is the public seed (32 bytes). -/
def expandAInnerInv
    (p : ParameterSet)
    (ρ : 𝔹 32)
    (orig_key : mlkem.key.Key)
    (key : mlkem.key.Key)
    (coordinates : Std.Array U8 2#usize)
    (i j : U8)
    (p_shake_state_base : mlkem.hash.MlKemHashState)
    (g_base : sha3.sha3_impl.GhostState) : Prop :=
  wfKey key p ∧
  i.val < (k p : ℕ) ∧
  j.val ≤ (k p : ℕ) ∧
  mlkem.hash.MlKemHashState.absorbing p_shake_state_base g_base ∧
  g_base.absorbed.map (·.bv) = ρ.toList ∧
  p_shake_state_base.alg = mlkem.hash.MlKemHashAlg.Shake128 ∧
  coordinates.val[1]! = i ∧
  (∀ (col : ℕ) (_h_kpos : i.val < (k p : ℕ)) (_h_jk : j.val ≤ (k p : ℕ))
      (_h_col : col < j.val),
      toPoly (key.data.val[i.val * (k p : ℕ) + col]'(by
        have hl : key.data.val.length = 24 := key.data.property
        have hk : (k p : ℕ) ≤ 4 := k_le_4 p
        have hk2 : (k p : ℕ) * (k p : ℕ) + 2 * (k p : ℕ) ≤ 24 := k_sq_plus_2k_le_24 p
        scalar_tac)) =
      MLKEM.SampleNTT (expandAEntrySeed ρ i.val col)) ∧
  (∀ (slot : ℕ) (h_slot : slot < dataEnd p),
      ¬ (i.val * (k p : ℕ) ≤ slot ∧ slot < i.val * (k p : ℕ) + j.val) →
      key.data.val[slot]'(by
        have h1 : key.data.val.length = 24 := key.data.property
        unfold dataEnd matrixLen at h_slot; grind) =
      orig_key.data.val[slot]'(by
        have h1 : orig_key.data.val.length = 24 := orig_key.data.property
        unfold dataEnd matrixLen at h_slot; grind)) ∧
  keyStructFrame key orig_key

/-- **Outer-loop invariant** for the i-loop.

After processing `i` rows: all of rows `[0, i)` filled per the spec;
slots outside `[0, i*(k p))` unchanged from `orig_key`. -/
def expandAOuterInv
    (p : ParameterSet)
    (ρ : 𝔹 32)
    (orig_key : mlkem.key.Key)
    (key : mlkem.key.Key)
    (i : U8)
    (p_shake_state_base : mlkem.hash.MlKemHashState)
    (g_base : sha3.sha3_impl.GhostState) : Prop :=
  wfKey key p ∧
  i.val ≤ (k p : ℕ) ∧
  mlkem.hash.MlKemHashState.absorbing p_shake_state_base g_base ∧
  g_base.absorbed.map (·.bv) = ρ.toList ∧
  p_shake_state_base.alg = mlkem.hash.MlKemHashAlg.Shake128 ∧
  (∀ (row col : ℕ) (_h_ik : i.val ≤ (k p : ℕ))
      (_h_row : row < i.val) (_h_col : col < (k p : ℕ)),
      toPoly (key.data.val[row * (k p : ℕ) + col]'(by
        have hl : key.data.val.length = 24 := key.data.property
        have hk : (k p : ℕ) ≤ 4 := k_le_4 p
        have hk2 : (k p : ℕ) * (k p : ℕ) + 2 * (k p : ℕ) ≤ 24 := k_sq_plus_2k_le_24 p
        scalar_tac)) =
      MLKEM.SampleNTT (expandAEntrySeed ρ row col)) ∧
  (∀ (slot : ℕ) (h_slot : slot < dataEnd p),
      ¬ (slot < i.val * (k p : ℕ)) →
      key.data.val[slot]'(by
        have h1 : key.data.val.length = 24 := key.data.property
        unfold dataEnd matrixLen at h_slot; grind) =
      orig_key.data.val[slot]'(by
        have h1 : orig_key.data.val.length = 24 := orig_key.data.property
        unfold dataEnd matrixLen at h_slot; grind)) ∧
  keyStructFrame key orig_key

/-! ## Inner j loop: sample one column of `A^T[i, :]`

For each `j ∈ [0, n_rows)`:
1. Clone the base XOF state (ρ already absorbed).
2. Set `coordinates[0] := j`; absorb `coordinates` (= `[j, i]`).
3. Call `poly_element_sample_ntt_from_shake128` to fill
   `a_transpose[i * n_rows + j]`. -/

#decompose mlkem.key_expand_public_matrix_from_public_seed_loop0_loop0
  key_expand_public_matrix_from_public_seed_loop0_loop0.fold
  letRange 1 1 => key_expand_public_matrix_from_public_seed_loop0_loop0_match

#decompose key_expand_public_matrix_from_public_seed_loop0_loop0_match
  key_expand_public_matrix_from_public_seed_loop0_loop0_match.fold
  branch 1 (letRange 0 15) => key_expand_public_matrix_from_public_seed_loop0_loop0_body

/-! The `#decompose` declarations and `_loop0_loop0_match.fold` equation
above are consumed inside `mlkem.key_expand_public_matrix_from_public_seed_loop0_loop0.spec`'s
proof via the canonical Variant B pattern (see `proof-patterns` skill):
the loop dispatch and per-column `_loop0_loop0_body` step are inlined
there, so no standalone `@[step]` spec is needed for `_match`. -/

/-- **Body spec** for the inner column loop.

One column iteration: clone base state, absorb `[j, i]`, sample a
polynomial via `poly_element_sample_ntt_from_shake128`, store at
`a_transpose[i * n_rows + j]`.  Extends `expandAInnerInv` by one
column.  The body's output tuple is `(coords, state, key)` after
absorbing the trailing pure back-fn application that reconstructs the
key from its data slot.

Informal proof. Template: leaf step-spec with nested function call.
`unfold key_expand_public_matrix_from_public_seed_loop0_loop0_body`;
`step*` through:
1. `Array.index_usize_mut.spec` on `coordinates[0]` — write `j` into the
   first byte; yields `coordinates' = {val := [j.toU8, coordinates.val[1]]}`.
2. `MlKemHashState.clone.spec` on `p_shake_state_base` — yields an exact
   copy; `r = p_shake_state_base` preserving the absorbing ghost `g_base`.
3. `lift Array.to_slice.spec` on `coordinates'` — 2-element slice.
4. `MlKemHashState.append.spec` — absorbs `coordinates'` into the cloned
   work state; postcondition gives absorbing ghost `g_work` with
   `g_work.absorbed = g_base.absorbed ++ [j.toU8, i.toU8]`; since
   `g_base.absorbed.map (·.bv) = ρ.toList` (from `h_inv`), this equals
   `(expandAEntrySeed ρ i.val j.val).toList` by definition.
5. `mlkem.ntt.poly_element_sample_ntt_from_shake128.spec` with
   `h_absorbed : g_work.absorbed … = (expandAEntrySeed ρ i.val j.val).toList`
   and `h_alg : p_state_work.alg = Shake128`; yields `wfPoly poly` and
   `toPoly poly = MLKEM.SampleNTT (expandAEntrySeed ρ i.val j.val)`.
6. `Array.update.spec` (or `Array.index_usize_mut.spec`) on
   `key.data[i.val * (k p : ℕ) + j.val]` — bound `i*(k p)+j < 24` from
   `wfKey` + `k_sq_plus_2k_le_24 p`; back-fn stores `poly` at that slot.
Establish `expandAInnerInv … (j.val+1)`: the new FC entry at `i*(k p)+j`
uses `toPoly poly = MLKEM.SampleNTT (expandAEntrySeed ρ i.val j.val)` from
step 5; all other entries `col < j.val` unchanged (from step 6 back-fn
frame); `wfKey key' p` preserved because only `data[i*(k p)+j]` changed
and the new value satisfies `wfPoly`. `agrind` for index arithmetic. -/
@[step]
theorem key_expand_public_matrix_from_public_seed_loop0_loop0_body.spec
    (p : ParameterSet) (ρ : 𝔹 32) (orig_key : mlkem.key.Key)
    (g_base : sha3.sha3_impl.GhostState)
    (pk_mlkem_key : mlkem.key.Key)
    (coordinates : Array U8 2#usize)
    (p_shake_state_base : mlkem.hash.MlKemHashState)
    (n_rows i j : U8)
    (h_n_rows : n_rows.val = (k p : ℕ)) (h_i : i.val < n_rows.val)
    (h_j : j.val < n_rows.val)
    (h_inv : expandAInnerInv p ρ orig_key pk_mlkem_key coordinates i j
              p_shake_state_base g_base) :
    key_expand_public_matrix_from_public_seed_loop0_loop0_body
        pk_mlkem_key coordinates p_shake_state_base n_rows i j
      ⦃ _coords' _state' key' =>
          ∃ (j' : U8), j'.val = j.val + 1 ∧
            expandAInnerInv p ρ orig_key key' _coords' i j'
              p_shake_state_base g_base ⦄ := by
  obtain ⟨h_wf, _h_ik, _h_jk, h_abs, h_g_eq, h_alg, h_c1, h_fc, h_frame, h_kstruct⟩ := h_inv
  have h_k_le : (k p : ℕ) ≤ 4 := k_le_4 p
  have h_k2 := k_sq_plus_2k_le_24 p
  have h_i_lt_k : i.val < (k p : ℕ) := h_n_rows ▸ h_i
  have h_j_lt_k : j.val < (k p : ℕ) := h_n_rows ▸ h_j
  have _h_imul : i.val * (k p : ℕ) + j.val < (k p : ℕ) * (k p : ℕ) := by grind
  unfold key_expand_public_matrix_from_public_seed_loop0_loop0_body
  step*
  case g => exact g_base
  case h => exact Or.inl (p_shake_state_work1_post ▸ h_abs)
  step*
  case seed => exact expandAEntrySeed ρ i.val j.val
  case g => exact g_base.append s.val p_shake_state_work1.state.squeeze_mode
  case h_state => exact Or.inl p_shake_state_work2_post2
  case h_absorbed =>
    -- LHS = (g_base.append s.val p_shake_state_work1.state.squeeze_mode).absorbed.map (·.bv).
    -- p_shake_state_work1 = p_shake_state_base (clone), which is absorbing g_base, so its
    -- squeeze_mode = false; then absorbed.map = ρ.toList ++ s.val.map (·.bv).
    -- s.val = (coordinates.set 0 j).val and h_c1 forces coordinates.val = [_, i].
    rw [p_shake_state_work1_post, squeeze_mode_eq_false_of_absorbing h_abs,
        absorbed_bv_append, h_g_eq, s_post, coordinates1_post, Array.val_to_slice,
        Array.set_val_eq]
    unfold expandAEntrySeed
    have h_coord_form : coordinates.val = [coordinates.val[0]!, i] := by
      rcases coordinates with ⟨l, hl⟩
      match l, hl with
      | [_, _], _ =>
        simp at h_c1 ⊢
        rw [h_c1]
    rw [h_coord_form]
    simp [Vector.append, Vector.toList]
  case h_squeezed =>
    -- (g_base.append s.val p_shake_state_work1.state.squeeze_mode).squeezed = [].
    -- g_base is absorbing ⇒ g_base.squeezed = [] (from absorbingWeak).
    -- p_shake_state_work1's squeeze_mode (inherited from the absorbing g_base via clone)
    -- is false; the append branch with `wasSqueeze = false` extends `.absorbed`,
    -- leaving `.squeezed` unchanged at [].
    have h_g_sq : g_base.squeezed = [] := by
      unfold mlkem.hash.MlKemHashState.absorbing sha3.sha3_impl.absorbing
             sha3.sha3_impl.absorbingWeak at h_abs
      tauto
    rw [p_shake_state_work1_post, squeeze_mode_eq_false_of_absorbing h_abs]
    simp [sha3.sha3_impl.GhostState.append, h_g_sq]
  -- Final goal: rebuild expandAInnerInv at j+1.
  -- Witness: j' = (j.val+1 : U8). New column entry at i*(k p)+j uses sample_ntt postcondition;
  -- previous columns from h_fc; frame from h_frame extended to cover the new slot.
  -- wfKey preserved via a_transpose_post4 (using wfPoly a1 from sample_ntt post).
  -- coordinates'[1] = i preserved (set 0 doesn't touch index 1).
  refine ⟨⟨j.val + 1, by scalar_tac⟩, rfl, ?_⟩
  -- Index arithmetic: i3.val = i*(k p)+j.
  have h_i2_val : i2.val = i.val * (k p : ℕ) + j.val := by
    rw [i2_post, i1_post, h_n_rows]
  have h_cast : (UScalar.cast UScalarTy.Usize i2).val = i2.val := by
    simp
  have h_i3_val : i3.val = i.val * (k p : ℕ) + j.val := by
    rw [i3_post, h_cast, h_i2_val]
  have h_imul_lt : i.val * (k p : ℕ) + j.val < matrixLen p := by
    unfold matrixLen
    have : (i.val + 1) * (k p : ℕ) ≤ (k p : ℕ) * (k p : ℕ) :=
      Nat.mul_le_mul_right _ h_i_lt_k
    grind
  -- Convert index_mut_back a1 to a_transpose.set i3 a1.
  have h_imb_eq : index_mut_back = a_transpose.set i3 := by grind
  have h_imb_a1 : index_mut_back a1 = a_transpose.set i3 a1 := by rw [h_imb_eq]
  rw [h_imb_a1]
  -- Slice → list bridge: (a_transpose.set i3 a1).val = a_transpose.val.set i3.val a1.
  have h_set_val :
      (a_transpose.set i3 a1).val = a_transpose.val.set i3.val a1 := Slice.set_val_eq ..
  have h_a_len : a_transpose.length = matrixLen p := a_transpose_post1
  have h_a_val_len : a_transpose.val.length = matrixLen p := h_a_len
  have h_set_len : (a_transpose.set i3 a1).length = matrixLen p := by
    show (a_transpose.set i3 a1).val.length = matrixLen p
    rw [h_set_val, List.length_set]; exact h_a_val_len
  -- Pointwise wf for the set slice.
  have h_set_wf : ∀ idx (_ : idx < (a_transpose.set i3 a1).length),
      wfPoly (a_transpose.set i3 a1).val[idx] := by
    intro idx hidx
    have hidx_mat : idx < matrixLen p := by
      rw [show (a_transpose.set i3 a1).length = matrixLen p from h_set_len] at hidx
      exact hidx
    have hidx_a : idx < a_transpose.length := by rw [h_a_len]; exact hidx_mat
    simp only [Slice.set_val_eq]
    by_cases h_eq : idx = i3.val
    · subst h_eq
      rw [List.getElem_set_self]; exact p_shake_state_work3_post1
    · rw [List.getElem_set_ne (Ne.symm h_eq)]
      exact a_transpose_post2 idx hidx_a
  -- Apply the back-fn postcondition.
  have h_post := a_transpose_post4 (a_transpose.set i3 a1) h_set_len h_set_wf
  obtain ⟨h_wfK', h_par', h_nr', h_pub', h_enc', h_eh', h_pseed', h_prand',
          h_hps', h_hpk', h_data_set, h_data_frame⟩ := h_post
  refine ⟨h_wfK', h_i_lt_k, by show j.val + 1 ≤ (k p : ℕ); omega,
          h_abs, h_g_eq, h_alg, ?_, ?_, ?_, ?_⟩
  · -- coordinates'[1] = i preserved (set 0 doesn't touch index 1)
    show coordinates1.val[1]! = i
    rw [coordinates1_post, Array.set_val_eq]
    rcases coordinates with ⟨l, hl⟩
    match l, hl with
    | [_, _], _ =>
      simp at h_c1 ⊢
      exact h_c1
  · -- new fc: ∀ col < j+1, toPoly newKey.data[i*(k p)+col] = SampleNTT(...)
    intro col _ _ h_col_lt
    have h_col_lt' : col < j.val + 1 := h_col_lt
    have h_slot_lt_mat : i.val * (k p : ℕ) + col < matrixLen p := by
      unfold matrixLen
      have : (i.val + 1) * (k p : ℕ) ≤ (k p : ℕ) * (k p : ℕ) :=
        Nat.mul_le_mul_right _ h_i_lt_k
      grind
    rw [h_data_set (i.val * (k p : ℕ) + col) h_slot_lt_mat]
    -- Goal: toPoly (↑(a_transpose.set i3 a1))[i*(k p)+col] = SampleNTT (...).
    simp only [Slice.set_val_eq]
    by_cases h_eq : col = j.val
    · -- new entry: i*(k p)+col = i3.val, access gives a1.
      subst h_eq
      have h_idx_eq : (i3.val : ℕ) = i.val * (k p : ℕ) + j.val := h_i3_val
      rw [List.getElem_set, if_pos h_idx_eq]
      exact p_shake_state_work3_post2
    · -- col < j: unchanged from pk_mlkem_key.
      have h_col_lt_j : col < j.val := by omega
      have h_slot_ne : i3.val ≠ i.val * (k p : ℕ) + col := by
        rw [h_i3_val]; omega
      rw [List.getElem_set_ne h_slot_ne]
      rw [a_transpose_post3 (i.val * (k p : ℕ) + col) h_a_len h_slot_lt_mat]
      exact h_fc col h_i_lt_k (by omega) h_col_lt_j
  · -- frame: ∀ slot ∉ row_i[0..j+1], newKey.data[slot] = orig_key.data[slot]
    intro slot h_slot h_not_in
    have h_jp_val : ({ toFin := ⟨j.val + 1, by scalar_tac⟩ }#uscalar : U8).val
                    = j.val + 1 := rfl
    have h_not_in' : ¬ (i.val * (k p : ℕ) ≤ slot ∧ slot < i.val * (k p : ℕ) + (j.val + 1)) := by
      intro ⟨h_lo, h_hi⟩
      apply h_not_in
      exact ⟨h_lo, by rw [h_jp_val]; exact h_hi⟩
    have h_slot_24 : slot < 24 := by
      unfold dataEnd matrixLen at h_slot
      have := k_sq_plus_2k_le_24 p
      omega
    by_cases h_slot_mat : slot < matrixLen p
    · -- slot in matrix range
      have h_slot_ne_i3 : i3.val ≠ slot := by
        rw [h_i3_val]
        intro h_eq_slot
        apply h_not_in'
        refine ⟨?_, ?_⟩ <;> omega
      rw [h_data_set slot h_slot_mat]
      simp only [Slice.set_val_eq]
      rw [List.getElem_set_ne h_slot_ne_i3]
      rw [a_transpose_post3 slot h_a_len h_slot_mat]
      -- then h_frame to pull back to orig_key
      apply h_frame slot h_slot
      intro ⟨h_lo, h_hi⟩
      apply h_not_in'
      refine ⟨h_lo, ?_⟩; omega
    · -- slot ≥ matrixLen p
      push Not at h_slot_mat
      rw [h_data_frame slot h_slot_mat h_slot_24]
      apply h_frame slot h_slot
      intro ⟨h_lo, h_hi⟩
      have : i.val * (k p : ℕ) + j.val < matrixLen p := h_imul_lt
      omega
  · -- keyStructFrame newKey orig_key
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · exact h_pub'.trans h_kstruct.1
    · exact h_par'.trans h_kstruct.2.1
    · exact h_nr'.trans h_kstruct.2.2.1
    · exact h_enc'.trans h_kstruct.2.2.2.1
    · exact h_eh'.trans h_kstruct.2.2.2.2.1
    · exact h_pseed'.trans h_kstruct.2.2.2.2.2.1
    · exact h_prand'.trans h_kstruct.2.2.2.2.2.2.1
    · exact h_hps'.trans h_kstruct.2.2.2.2.2.2.2.1
    · exact h_hpk'.trans h_kstruct.2.2.2.2.2.2.2.2

/-- **Inner loop spec**: walk j ∈ [iter.start, n_rows) extending
`expandAInnerInv`.  On exit (`j = n_rows`), row `i` is fully sampled:
`toPoly key'.data[i * (k p) + col] = MLKEM.SampleNTT (expandAEntrySeed ρ
i.val col)` for all `col < n_rows`.

Informal proof. Canonical recursive Range-U8 loop (`proof-patterns`
"Loop — Canonical Template", Variant B). No separate `_loop0_loop0_match.spec`
is needed: the match dispatch is inlined.

- **Mandatory first step**: `rw [key_expand_public_matrix_from_public_seed_loop0_loop0.fold]`.
  Do NOT use `unfold
  mlkem.key_expand_public_matrix_from_public_seed_loop0_loop0` —
  `unfold` bypasses the `_body` helper.
  After the `(next iter)` step is consumed, `rw
  [key_expand_public_matrix_from_public_seed_loop0_loop0_match.fold]`
  to expose the `_body` call.
- `step` to consume `next iter` (Range-U8 → `o, iter1`).
- `cases o`:
  - **`none` arm** (`iter.start = n_rows`): the body is the trivial
    `ok (key, coordinates, state)`; close from `h_inv` directly
    (`expandAInnerInv … iter.start = expandAInnerInv … n_rows`); `agrind`.
  - **`some j'` arm**: extract `j'.val = iter.start.val` and `j'.val <
    n_rows.val`; `step with
    key_expand_public_matrix_from_public_seed_loop0_loop0_body.spec`
    (per-column leaf — supplies `h_j : j'.val < n_rows.val`, `h_inv`, and
    the wfKey/ghost obligations); the body post yields
    `expandAInnerInv … (j.val + 1)`; `step*` then closes the recursive
    inner-loop call via the IH (this very theorem at the smaller iterator).
- `termination_by n_rows.val - iter.start.val`; `decreasing_by agrind`. -/
@[step]
theorem mlkem.key_expand_public_matrix_from_public_seed_loop0_loop0.spec
    (p : ParameterSet) (ρ : 𝔹 32) (orig_key : mlkem.key.Key)
    (g_base : sha3.sha3_impl.GhostState)
    (iter : core.ops.range.Range U8)
    (pk_mlkem_key : mlkem.key.Key)
    (coordinates : Array U8 2#usize)
    (p_shake_state_base p_shake_state_work : mlkem.hash.MlKemHashState)
    (n_rows i : U8)
    (h_n_rows : n_rows.val = (k p : ℕ)) (h_i : i.val < n_rows.val)
    (h_start : iter.start.val ≤ n_rows.val)
    (h_end : iter.«end».val = n_rows.val)
    (h_inv : expandAInnerInv p ρ orig_key pk_mlkem_key coordinates i iter.start
              p_shake_state_base g_base) :
    mlkem.key_expand_public_matrix_from_public_seed_loop0_loop0
        iter pk_mlkem_key coordinates p_shake_state_base p_shake_state_work n_rows i
      ⦃ key' _coords' _state' =>
          expandAInnerInv p ρ orig_key key' _coords' i n_rows
            p_shake_state_base g_base ⦄ := by
  rw [key_expand_public_matrix_from_public_seed_loop0_loop0.fold]
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨o, iter1, ho, hstart1, hend1⟩ ← IteratorRange_U8_next_some
    rw [ho]
    rw [key_expand_public_matrix_from_public_seed_loop0_loop0_match.fold]
    have h_j_lt : iter.start.val < n_rows.val := by rw [← h_end]; exact hlt
    step with key_expand_public_matrix_from_public_seed_loop0_loop0_body.spec
      p ρ orig_key g_base pk_mlkem_key coordinates p_shake_state_base n_rows i iter.start
      h_n_rows h_i h_j_lt h_inv
      as ⟨coords', state', key', j_val, h_jeq, h_inv'⟩
    have h_x_eq : iter1.start.val = iter.start.val + 1 := hstart1
    have h_x_le : iter1.start.val ≤ n_rows.val := by rw [h_x_eq, ← h_end]; omega
    have h_inv'' : expandAInnerInv p ρ orig_key key' coords' i iter1.start p_shake_state_base g_base := by
      have h_j_eq_x : j_val = iter1.start := UScalar.eq_of_val_eq (by rw [h_jeq, h_x_eq])
      rw [← h_j_eq_x]; exact h_inv'
    apply mlkem.key_expand_public_matrix_from_public_seed_loop0_loop0.spec
      p ρ orig_key g_base iter1 key' coords' p_shake_state_base state' n_rows i
      h_n_rows h_i h_x_le (by rw [hend1]; exact h_end) h_inv''
  · let* ⟨o, iter1, ho, hiter1⟩ ← IteratorRange_U8_next_none
    rw [ho]
    rw [key_expand_public_matrix_from_public_seed_loop0_loop0_match.fold]
    simp only [WP.spec_ok]
    have h_eq : iter.start.val = n_rows.val := by omega
    have h_iter_eq : iter.start = n_rows := UScalar.eq_of_val_eq h_eq
    rw [h_iter_eq] at h_inv
    exact h_inv
termination_by iter.«end».val - iter.start.val
decreasing_by
  rw [h_x_eq]
  scalar_tac

/-! ## Outer i loop: walk rows of `A^T` -/

-- NOTE: `#decompose` cannot be used here.  Three patterns tried, all fail:
--   * `branch 1 (...)` errors "expression is not an ite, dite, or match"
--     (LCNF view of partial_fixpoint sees `do let ← next; match` — branch
--     cannot skip the leading bind).
--   * `letAt 1 (branch 1 ...)` errors "letAt 0: not a let or bind"
--     (LCNF representation of the terminal match is not a let-binding).
--   * `letRange 1 1 => ..._match` errors "Failed to find LCNF signature"
--     (the partial_fixpoint wrapper denies LCNF entry for `letRange`).
-- Workaround: prove the outer loop spec directly against the raw fixpoint
-- body via canonical Variant B (`rw [...fold]` if available, else `unfold`
-- + cases on iter progress + IH).  No further decomposition is needed
-- because the body has only 2 effectful binds (Array.update + inner loop
-- call) before the recursive tail — a single application of
-- `_loop0_loop0.spec` discharges it.

/-- **Outer loop spec**: walk `i ∈ [iter.start, n_rows)` extending
`expandAOuterInv`.  On exit, every row `i < n_rows` is fully sampled.

This loop has `partial_fixpoint` shape, so the proof unfolds the
fixpoint body directly rather than relying on fold lemmas.

Informal proof. Template: `partial_fixpoint` loop; well-founded induction
on `n_rows.val - iter.start.val`.
- `unfold mlkem.key_expand_public_matrix_from_public_seed_loop0`
  (partial_fixpoint exposes one step of the loop body).
- `by_cases hlt : iter.start.val < iter.«end».val`:
- **`false` arm** (done): `iter.start ≥ n_rows` contradicts `h_start`
  unless `iter.start = n_rows`; `expandAOuterInv … n_rows` is the
  postcondition; close by `agrind` + `WP.spec_ok`.
- **`true` arm** (progress): let `i = iter.start` (from the Range `next`):
  1. Establish `expandAInnerInv p ρ orig_key key i 0 g_base` at `j = 0`:
     vacuous — no columns sampled yet; the base-state absorption and `wfKey`
     come directly from `h_inv` (no `j` progress in `expandAOuterInv`).
  2. Apply `mlkem.key_expand_public_matrix_from_public_seed_loop0_loop0.spec`
     (inner column loop fills all `k` columns of row `i`); postcondition is
     `expandAInnerInv … n_rows`.
  3. Lift `expandAInnerInv p ρ orig_key key'' i n_rows` to
     `expandAOuterInv p ρ orig_key key'' (i+1)`: the new row `i` satisfies
     the FC clause; rows `< i` are unchanged by the inner loop (frame from
     `expandAInnerInv`'s frame clause + `expandAOuterInv`'s existing claim);
     `agrind` for the combined invariant conjuncts.
  4. Apply the outer loop IH with `iter' = {iter with start := i + 1}`.
- `termination_by n_rows.val - iter.start.val`; `decreasing_by agrind`. -/
@[step]
theorem mlkem.key_expand_public_matrix_from_public_seed_loop0.spec
    (p : ParameterSet) (ρ : 𝔹 32) (orig_key : mlkem.key.Key)
    (g_base : sha3.sha3_impl.GhostState)
    (iter : core.ops.range.Range U8)
    (pk_mlkem_key : mlkem.key.Key)
    (coordinates : Array U8 2#usize)
    (p_shake_state_base p_shake_state_work : mlkem.hash.MlKemHashState)
    (n_rows : U8)
    (h_n_rows : n_rows.val = (k p : ℕ))
    (h_start : iter.start.val ≤ n_rows.val)
    (h_end : iter.«end».val = n_rows.val)
    (h_inv : expandAOuterInv p ρ orig_key pk_mlkem_key iter.start
              p_shake_state_base g_base) :
    mlkem.key_expand_public_matrix_from_public_seed_loop0
        iter pk_mlkem_key coordinates p_shake_state_base p_shake_state_work n_rows
      ⦃ key' _state' =>
          expandAOuterInv p ρ orig_key key' n_rows
            p_shake_state_base g_base ⦄ := by
  unfold mlkem.key_expand_public_matrix_from_public_seed_loop0
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨o, iter1, ho, hstart1, hend1⟩ ← IteratorRange_U8_next_some
    rw [ho]
    obtain ⟨h_wf, h_i_le, h_abs, h_g_eq, h_alg, h_fc_outer, h_frame_outer, h_kstruct_outer⟩ := h_inv
    have h_i_lt_k : iter.start.val < (k p : ℕ) := by rw [← h_n_rows]; rw [← h_end]; exact hlt
    have h_k_le : (k p : ℕ) ≤ 4 := k_le_4 p
    have h_k_ge : 2 ≤ (k p : ℕ) := k_ge_2 p
    step*
    case orig_key => exact pk_mlkem_key
    case g_base => exact g_base
    case h_inv =>
      refine ⟨h_wf, h_i_lt_k, ?_, h_abs, h_g_eq, h_alg, ?_, ?_, ?_, ?_⟩
      · show (0#u8).val ≤ (k p : ℕ); simp
      · grind
      · intro col _ _ hc; change col < (0#u8).val at hc; simp at hc
      · intro slot h_slot _; rfl
      · exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩
    obtain ⟨h_wf1, _, _, h_abs1, h_g_eq1, h_alg1, _, h_fc_inner, h_frame_inner, h_kstruct_inner⟩ :=
      pk_mlkem_key1_post
    have h_x_eq : iter1.start.val = iter.start.val + 1 := hstart1
    have h_x_le_k : iter1.start.val ≤ (k p : ℕ) := by rw [h_x_eq]; omega
    have h_x_le : iter1.start.val ≤ n_rows.val := by rw [h_n_rows]; exact h_x_le_k
    have h_nrows_le_k : n_rows.val ≤ (k p : ℕ) := h_n_rows.le
    have h_x_mul : iter1.start.val * (k p : ℕ) = iter.start.val * (k p : ℕ) + (k p : ℕ) := by
      rw [h_x_eq, Nat.add_mul, Nat.one_mul]
    apply mlkem.key_expand_public_matrix_from_public_seed_loop0.spec
      p ρ orig_key g_base iter1 pk_mlkem_key1 coordinates1 p_shake_state_base
      p_shake_state_work1 n_rows h_n_rows h_x_le (by rw [hend1]; exact h_end)
    refine ⟨h_wf1, h_x_le_k, h_abs1, h_g_eq1, h_alg1, ?_, ?_, ?_⟩
    · intro row col _ h_row h_col
      change row < iter1.start.val at h_row
      by_cases h_row_lt : row < iter.start.val
      · have h_slot : row * (k p : ℕ) + col < iter.start.val * (k p : ℕ) := by
          have h1 : (row + 1) * (k p : ℕ) ≤ iter.start.val * (k p : ℕ) :=
            Nat.mul_le_mul_right _ h_row_lt
          rw [Nat.succ_mul] at h1
          omega
        have h_slot_dE : row * (k p : ℕ) + col < dataEnd p := by
          unfold dataEnd matrixLen; grind
        rw [h_frame_inner _ h_slot_dE (by intro ⟨h1, _⟩; omega)]
        exact h_fc_outer row col h_i_le h_row_lt h_col
      · have h_row_eq : row = iter.start.val := by omega
        subst h_row_eq
        have h_col_n : col < n_rows.val := by rw [h_n_rows]; exact h_col
        exact h_fc_inner col h_i_lt_k h_nrows_le_k h_col_n
    · intro slot h_slot h_slot_ge
      change ¬ slot < iter1.start.val * (k p : ℕ) at h_slot_ge
      have h_slot_ge_inner : iter.start.val * (k p : ℕ) + n_rows.val ≤ slot := by
        rw [h_n_rows]; omega
      rw [h_frame_inner slot h_slot (by intro ⟨_, h2⟩; omega)]
      apply h_frame_outer slot h_slot
      intro h_lt; omega
    · -- keyStructFrame pk_mlkem_key1 orig_key — compose inner + outer frames.
      obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9⟩ := h_kstruct_inner
      obtain ⟨g1, g2, g3, g4, g5, g6, g7, g8, g9⟩ := h_kstruct_outer
      exact ⟨h1.trans g1, h2.trans g2, h3.trans g3, h4.trans g4, h5.trans g5,
             h6.trans g6, h7.trans g7, h8.trans g8, h9.trans g9⟩
  · let* ⟨o, iter1, ho, hiter1⟩ ← IteratorRange_U8_next_none
    rw [ho]
    have h_eq : iter.start.val = n_rows.val := by omega
    have h_iter_eq : iter.start = n_rows := UScalar.eq_of_val_eq h_eq
    rw [h_iter_eq] at h_inv
    exact h_inv
termination_by iter.«end».val - iter.start.val
decreasing_by
  rw [h_x_eq]
  scalar_tac

/-! ## Wrapper `key_expand_public_matrix_from_public_seed`

Full functional correctness: every matrix entry equals
`MLKEM.SampleNTT (ρ ‖ j ‖ i)`.  The key invariant `wfKey` is
preserved; rows outside `[0, k)` (= unused tail of `data`) are
untouched (already vacuously true since `dataEnd p ≥ (k p)²`). -/
/-- **Spec for `mlkem.key_expand_public_matrix_from_public_seed`** —
ExpandA wrapper (FIPS 203 §5.1 Algorithm 13 / Algorithm 5 transposed):
populates `pk_mlkem_key.data[0..(k p)²)` with the NTT-domain matrix
`Â^T` by sampling each entry via SHAKE128(ρ ‖ j ‖ i).

Informal proof. Template: function-wrapper delegating to the outer loop.
`unfold mlkem.key_expand_public_matrix_from_public_seed`; `step*` through:
1. `Array.repeat.spec` for the 2-element `coordinates` buffer.
2. `MlKemHashState.set_alg.spec` (sets `hash_state0` to `Shake128`).
3. `MlKemHashState.init.spec` — fresh absorbing ghost `g0` for SHAKE128
   (rate = 168, pad = 31; `algParams Shake128 = some (168, 31#u8)`).
4. `lift Array.to_slice.spec` on `public_seed`.
5. `MlKemHashState.append.spec` absorbing `public_seed`; ghost `g_base`
   with `g_base.absorbed.map (·.bv) = ρ.toList` where `ρ =
   arrayToSpecBytes pk_mlkem_key.public_seed` (from `h_wf`).
6. Establish `expandAOuterInv p ρ pk_mlkem_key pk_mlkem_key 0#u8
   p_shake_state_base2 g_base` (vacuous at `i = 0`; `wfKey` from `h_wf`;
   `absorbing` from step 5).
7. Apply `mlkem.key_expand_public_matrix_from_public_seed_loop0.spec`
   (outer loop fills all `k p` rows); postcondition is
   `expandAOuterInv … n_rows`.
8. From `expandAOuterInv … n_rows` extract the per-entry FC equality
   `toPoly key'.data[row * (k p) + col] = MLKEM.SampleNTT (expandAEntrySeed
   ρ row col)` for all `row, col < k p`; this is the main claim.
9. `key'.public_seed = pk_mlkem_key.public_seed` (loop only modifies
   `data`); `wfKey key' p` from `expandAOuterInv`'s `wfKey` clause.
10. Unused-slot frame (`matrixLen p ≤ slot < 24`) from `expandAOuterInv`'s
    frame and `wfKey`'s layout invariant. `agrind` for all bounds. -/
@[step]
theorem mlkem.key_expand_public_matrix_from_public_seed.spec
    (p : ParameterSet)
    (pk_mlkem_key : mlkem.key.Key)
    (p_comp_temps : mlkem.ntt.InternalComputationTemporaries)
    (h_wf : wfKey pk_mlkem_key p) :
    mlkem.key_expand_public_matrix_from_public_seed pk_mlkem_key p_comp_temps
      ⦃ key' comp_temps' =>
          wfKey key' p ∧
          key'.public_seed = pk_mlkem_key.public_seed ∧
          (∀ (row col : ℕ) (_h_row : row < (k p : ℕ)) (_h_col : col < (k p : ℕ)),
            toPoly (key'.data.val[row * (k p : ℕ) + col]'(by
              have hl : key'.data.val.length = 24 := key'.data.property
              have hk : (k p : ℕ) ≤ 4 := k_le_4 p
              have hk2 : (k p : ℕ) * (k p : ℕ) + 2 * (k p : ℕ) ≤ 24 := k_sq_plus_2k_le_24 p
              scalar_tac)) =
            MLKEM.SampleNTT
              (expandAEntrySeed (arrayToSpecBytes pk_mlkem_key.public_seed) row col)) ∧
          /- Slots outside the a_transpose matrix (t and s vectors) are unchanged. -/
          (∀ (slot : ℕ) (h_slot : matrixLen p ≤ slot ∧ slot < dataEnd p),
              key'.data.val[slot]'(by
                have h1 : key'.data.val.length = 24 := key'.data.property
                unfold dataEnd matrixLen at h_slot; grind) =
              pk_mlkem_key.data.val[slot]'(by
                have h1 : pk_mlkem_key.data.val.length = 24 := pk_mlkem_key.data.property
                unfold dataEnd matrixLen at h_slot; grind)) ∧
          /- Non-data, non-public_seed fields are preserved.  The implementation
             only writes `data` (matrix slots) and `public_seed` (unchanged here);
             every other key field is structurally untouched. -/
          key'.params = pk_mlkem_key.params ∧
          key'.n_rows = pk_mlkem_key.n_rows ∧
          key'.encoded_t = pk_mlkem_key.encoded_t ∧
          key'.encaps_key_hash = pk_mlkem_key.encaps_key_hash ∧
          key'.private_seed = pk_mlkem_key.private_seed ∧
          key'.private_random = pk_mlkem_key.private_random ∧
          key'.has_private_seed = pk_mlkem_key.has_private_seed ∧
          key'.has_private_key = pk_mlkem_key.has_private_key ∧
          /- ComputationTemporaries preservation.  Only `hash_state0` /
             `hash_state1` are written; vector / poly_element scratch slots
             are structurally untouched, exposed here so callers can carry
             `wfPolyVec`-style invariants on these slots through the call. -/
          comp_temps'.max_size_vector0 = p_comp_temps.max_size_vector0 ∧
          comp_temps'.max_size_vector1 = p_comp_temps.max_size_vector1 ∧
          comp_temps'.poly_element_accumulator =
            p_comp_temps.poly_element_accumulator ⦄ := by
  unfold mlkem.key_expand_public_matrix_from_public_seed
  have h_k_le : (k p : ℕ) ≤ 4 := k_le_4 p
  have h_k_ge : 2 ≤ (k p : ℕ) := k_ge_2 p
  have h_nrows : pk_mlkem_key.params.n_rows.val = (k p : ℕ) :=
    wfInternalParams.n_rows_val (wfKey.params_ok (self := pk_mlkem_key) h_wf)
  have h_rate_ok : 0 < 168 ∧ 8 * 168 < Spec.SHA3.b ∧ 168 % 8 = 0 := by
    refine ⟨?_, ?_, ?_⟩ <;> decide
  set ρ : 𝔹 32 := arrayToSpecBytes pk_mlkem_key.public_seed with hρ_def
  step as ⟨sb, sb_post1, sb_post2⟩
  step (rate := 168) (padVal := 31#u8) as ⟨sb1, sb1_alg_eq, sb1_absorbing⟩
  case h_alg => rw [sb_post2]; rfl
  step as ⟨s, s_post⟩
  step as ⟨sb2, sb2_alg_eq, sb2_absorbing⟩
  case g => exact sha3.sha3_impl.GhostState.init 168 31#u8 h_rate_ok
  case h => left; exact sb1_absorbing
  set g_base : sha3.sha3_impl.GhostState :=
    (sha3.sha3_impl.GhostState.init 168 31#u8 h_rate_ok).append (↑s) sb1.state.squeeze_mode
    with hg_base_def
  change sb2.absorbing g_base at sb2_absorbing
  -- Public seed bytes ≡ ρ.toList. sb1 is absorbing the init ghost state, so
  -- sb1.state.squeeze_mode = false; then g_base.absorbed = [] ++ s.val and
  -- s.val = pk_mlkem_key.public_seed.val via to_slice.
  have h_g_absorbed : g_base.absorbed.map (·.bv) = ρ.toList := by
    rw [hg_base_def, squeeze_mode_eq_false_of_absorbing sb1_absorbing,
        absorbed_bv_append, s_post, Array.val_to_slice]
    have h_init : (sha3.sha3_impl.GhostState.init 168 31#u8 h_rate_ok).absorbed = [] := rfl
    rw [h_init, List.map_nil, List.nil_append, hρ_def]
    exact (arrayToSpecBytes_toList_bv _).symm
  step with mlkem.key_expand_public_matrix_from_public_seed_loop0.spec
    as ⟨pk_final, state_final, h_outer_final⟩
  case orig_key => exact pk_mlkem_key
  case h_inv =>
    refine ⟨h_wf, ?_, sb2_absorbing, h_g_absorbed, ?_, ?_, ?_, ?_⟩
    · show (0 : ℕ) ≤ (k p : ℕ); omega
    · rw [sb2_alg_eq, sb1_alg_eq, sb_post2]
    · intro row col _ h_row _; exact absurd h_row (by simp)
    · intro slot _ _; rfl
    · exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩
  obtain ⟨h_wf', _h_i_le, _h_abs, _h_g_eq, _h_alg', h_fc, _h_frame, h_kstruct'⟩ := h_outer_final
  obtain ⟨h_ps, h_params, h_n_rows, h_et, h_ekh, h_priv_seed, h_priv_rnd, h_hps, h_hpk⟩ :=
    h_kstruct'
  refine ⟨h_wf', h_ps, ?_, ?_, h_params, h_n_rows, h_et, h_ekh, h_priv_seed, h_priv_rnd,
    h_hps, h_hpk⟩
  · intro row col h_row h_col
    exact h_fc row col h_nrows.le (h_nrows ▸ h_row) h_col
  · intro slot ⟨h_lo, h_hi⟩
    have h_slot_dE : slot < dataEnd p := h_hi
    have h_not : ¬ slot < pk_mlkem_key.params.n_rows.val * (k p : ℕ) := by
      rw [h_nrows]; unfold matrixLen at h_lo; omega
    exact _h_frame slot h_slot_dE h_not

/-! ## `key_compute_encapsulation_key_hash` — H(ek) for FO-transform

Computes `H = SHA3-256(encoded_t[0..384*(k p)] ‖ public_seed)`
and stores in `encaps_key_hash`. No loops; direct hash chain.

The encoded `t` is in `pk_mlkem_key.encoded_t[0 .. 384 * (k p)]`; the
public seed is the 32 bytes of `pk_mlkem_key.public_seed`. -/

/-- Spec view of the encoded-t prefix in the key. -/
noncomputable def keyEncodedTPrefix (self : mlkem.key.Key) (p : ParameterSet) :
    𝔹 (384 * (k p : ℕ)) :=
  Vector.ofFn fun (i : Fin (384 * (k p : ℕ))) =>
    self.encoded_t.val[i.val]'(by
      have h1 : self.encoded_t.val.length = 1536 := self.encoded_t.property
      have hi := i.isLt; grind)

/-! ### Spec-side view of the encapsulation key

The encapsulation key `ek = ByteEncode 12 t̂ ‖ ρ : 𝔹 (384·k + 32)` is
materialized in the runtime key as the prefix of `encoded_t` plus
`public_seed`.  These definitions and projection lemmas live here
(alongside `keyEncodedTPrefix`, their only structural dependency)
so that consumers in `Encaps.lean`, `Decaps.lean`, and `KeyGen.lean`
all share one definition. -/

/-- Encapsulation key view: `ek = encoded_t[0..384·k] ‖ public_seed`. -/
noncomputable def encapsulationKey
    (self : mlkem.key.Key) (params : ParameterSet) :
    𝔹 (384 * (k params : ℕ) + 32) :=
  (keyEncodedTPrefix self params ‖ self.public_seed.toSpec)

/-- Dot-notation view of a runtime `Key` as its spec-level encapsulation
key: `key.toPubKey params = encapsulationKey key params`.  Reducible, so
it is interchangeable with `encapsulationKey` in all proofs; we use the
dotted form in spec statements for readability. -/
noncomputable abbrev _root_.symcrust.mlkem.key.Key.toPubKey
    (self : mlkem.key.Key) (params : ParameterSet) :
    𝔹 (384 * (k params : ℕ) + 32) :=
  encapsulationKey self params

/-- Alias of `toPubKey` under the `toEncapKey` name used by spec statements
in `Decaps.lean`, `KeyGen.lean`, and `Encoding/KeySetValue/Prelude.lean`.
Both are reducible views of `encapsulationKey`. -/
noncomputable abbrev _root_.symcrust.mlkem.key.Key.toEncapKey
    (self : mlkem.key.Key) (params : ParameterSet) :
    𝔹 (384 * (k params : ℕ) + 32) :=
  encapsulationKey self params

/-- Prefix projection of the assembled encapsulation key.  This is the
byte-side bridge used both by `Encaps.KeyCheck` and by the
`encapsulate_internal` c-equality: the first `384 * k` bytes of
`ByteEncode 12 t̂ ‖ ρ` are exactly the encoded-`t̂` prefix. -/
theorem encapsulationKey_prefix_eq
    (self : mlkem.key.Key) (params : ParameterSet)
    (_h_prefix : 384 * (k params : ℕ) ≤ 384 * (k params : ℕ) + 32 := by grind) :
    Spec.slice (encapsulationKey self params) 0 (384 * (k params : ℕ))
        (by simp) =
      keyEncodedTPrefix self params := by
  unfold encapsulationKey
  apply Vector.ext
  intro i hi
  unfold Spec.slice
  simp only [Vector.getElem_ofFn]
  change (Vector.append (keyEncodedTPrefix self params) self.public_seed.toSpec)[0 + i] = _
  rw [show Vector.append (keyEncodedTPrefix self params) self.public_seed.toSpec
          = keyEncodedTPrefix self params ++ self.public_seed.toSpec from rfl]
  rw [Vector.getElem_append (i := 0 + i)]
  simp [hi]

/-- Suffix projection of the assembled encapsulation key: the last 32
bytes of `ByteEncode 12 t̂ ‖ ρ` are exactly `ρ = public_seed`.

This is the byte-side bridge used by the `encapsulate_internal` outer
chain to identify the `ρ` argument of `K_PKE.Encrypt_pure`'s pure-form
`Â` matrix with the runtime-key `public_seed`. -/
theorem encapsulationKey_suffix_eq
    (self : mlkem.key.Key) (params : ParameterSet) :
    Spec.slice (encapsulationKey self params) (384 * (k params : ℕ)) 32
        (by simp) =
      self.public_seed.toSpec := by
  unfold encapsulationKey
  apply Vector.ext
  intro i hi
  unfold Spec.slice
  simp only [Vector.getElem_ofFn]
  change (Vector.append (keyEncodedTPrefix self params) self.public_seed.toSpec)[384 * ↑(k params) + i] = _
  rw [show Vector.append (keyEncodedTPrefix self params) self.public_seed.toSpec
          = keyEncodedTPrefix self params ++ self.public_seed.toSpec from rfl]
  rw [Vector.getElem_append (i := 384 * ↑(k params) + i)]
  have hge : ¬ 384 * (k params : ℕ) + i < (keyEncodedTPrefix self params).size := by
    show ¬ _ < 384 * (k params : ℕ)
    omega
  simp only [hge, ↓reduceDIte]
  simp only [Nat.add_sub_cancel_left]
  rfl

/-- Byte-decode the encapsulation-key prefix using the caller-provided
byte-form witness for `t̂`.  This is sub-bridge B3's reusable first half
(consumed by Encaps.lean `mlkem.encapsulate_internal.spec` and by the
deferred Decaps safe-path `decapsulateBody.spec`). -/
theorem encapsulationKey_prefix_byteDecode_eq_of_encodedT
    {self : mlkem.key.Key} {params : ParameterSet}
    (v_t : MLKEM.PolyVector q (k params))
    (h_t_form : keyEncodedTPrefix self params =
                (MLKEM.PolyVector.ByteEncode 12 v_t).cast
                  (polyVector_byteEncode_size_cast 12)) :
    MLKEM.PolyVector.ByteDecode 12
      (Spec.slice (encapsulationKey self params) 0 (384 * (k params : ℕ))
        (by grind)) = v_t := by
  rw [encapsulationKey_prefix_eq self params, h_t_form,
      polyVector_byteDecode_byteEncode 12 ⟨by decide, by decide⟩ v_t]

/- The local helper `arrayToSpecBytes_from_slice_extractOutput` was
   superseded by `HashCalls.arrayToSpecBytes_from_slice_eq_sha3_256`,
   which packages it directly into the `sha3_256 B` form used at the
   only call site (`key_compute_encapsulation_key_hash.spec`). -/


/- Helper: per-byte equality between the spec-side concatenation
   `keyEncodedTPrefix pk p ++ arrayToSpecBytes pk.public_seed` and the
   concrete absorbed list `s ++ s1`, where `s` is a `0..384*(k p)` slice
   of `encoded_t` and `s1 = public_seed.to_slice`. -/
private theorem keyEncodedTPrefix_append_pubseed_per_byte
    (pk : mlkem.key.Key) (p : ParameterSet)
    (s s1 : Aeneas.Std.Slice U8)
    (h_s_val : (↑s : List U8) = pk.encoded_t.val.slice 0 (384 * (k p : ℕ)))
    (h_s_len : s.length = 384 * (k p : ℕ))
    (h_s1 : s1 = pk.public_seed.to_slice)
    (h_kp : (k p : ℕ) ≤ 4)
    (i : Nat) (hi : i < 384 * (k p : ℕ) + 32)
    (hi_abs : i < ((↑s : List U8) ++ (↑s1 : List U8)).length) :
    (keyEncodedTPrefix pk p ++ arrayToSpecBytes pk.public_seed)[i]'hi =
      (((↑s : List U8) ++ (↑s1 : List U8))[i]'hi_abs).bv := by
  have h_s_val_len : (↑s : List U8).length = 384 * (k p : ℕ) := h_s_len
  have h_s1_val : (↑s1 : List U8) = pk.public_seed.val := by rw [h_s1]; rfl
  have h_s1_val_len : (↑s1 : List U8).length = 32 := by
    rw [h_s1_val]; exact pk.public_seed.property
  have h_et_len : pk.encoded_t.val.length = 1536 := pk.encoded_t.property
  rw [Vector.getElem_append]
  unfold keyEncodedTPrefix arrayToSpecBytes
  by_cases hii : i < 384 * (k p : ℕ)
  · simp only [hii, ↓reduceDIte, Vector.getElem_ofFn]
    have hi_s : i < (↑s : List U8).length := by rw [h_s_val_len]; exact hii
    have hi_et : i < pk.encoded_t.val.length := by grind
    have h_left : (((↑s : List U8) ++ (↑s1 : List U8))[i]'hi_abs) =
        (↑s : List U8)[i]'hi_s := List.getElem_append_left hi_s
    -- Bridge (↑s)[i] = pk.encoded_t.val[i] via List.getElem_of_eq + slice.
    have hi_slice : i < (pk.encoded_t.val.slice 0 (384 * (k p : ℕ))).length := by
      rw [← h_s_val]; exact hi_s
    have h_via_slice : (↑s : List U8)[i]'hi_s =
        (pk.encoded_t.val.slice 0 (384 * (k p : ℕ)))[i]'hi_slice :=
      List.getElem_of_eq h_s_val hi_s
    have h_slice_eq : (pk.encoded_t.val.slice 0 (384 * (k p : ℕ)))[i]'hi_slice =
        pk.encoded_t.val[0 + i]'(by rw [Nat.zero_add]; exact hi_et) :=
      List.getElem_slice 0 (384 * (k p : ℕ)) i pk.encoded_t.val
        (by refine ⟨by grind, by grind⟩)
    have h_zero_add : pk.encoded_t.val[0 + i]'(by rw [Nat.zero_add]; exact hi_et) =
        pk.encoded_t.val[i]'hi_et := by
      fcongr 1; exact Nat.zero_add i
    have h_full : (↑s : List U8)[i]'hi_s = pk.encoded_t.val[i]'hi_et :=
      (h_via_slice.trans h_slice_eq).trans h_zero_add
    rw [h_left, h_full]
    -- Bridge `↑↑x = x.bv` for U8.
    exact U8.Nat_cast_BitVec_val _
  · simp only [hii, ↓reduceDIte, Vector.getElem_ofFn]
    have h_ge : (↑s : List U8).length ≤ i := by rw [h_s_val_len]; omega
    have hi_s1 : i - (↑s : List U8).length < (↑s1 : List U8).length := by
      rw [h_s_val_len, h_s1_val_len]; omega
    have h_right : (((↑s : List U8) ++ (↑s1 : List U8))[i]'hi_abs) =
        (↑s1 : List U8)[i - (↑s : List U8).length]'hi_s1 :=
      List.getElem_append_right h_ge
    have hi_ps_via_s1 : i - (↑s : List U8).length < pk.public_seed.val.length := by
      rw [← h_s1_val]; exact hi_s1
    have h_via_s1 : (↑s1 : List U8)[i - (↑s : List U8).length]'hi_s1 =
        pk.public_seed.val[i - (↑s : List U8).length]'hi_ps_via_s1 :=
      List.getElem_of_eq h_s1_val hi_s1
    have h_idx_eq : i - (↑s : List U8).length = i - 384 * (k p : ℕ) := by
      rw [h_s_val_len]
    have hi_ps : i - 384 * (k p : ℕ) < pk.public_seed.val.length := by
      rw [← h_idx_eq]; exact hi_ps_via_s1
    have h_idx_swap : pk.public_seed.val[i - (↑s : List U8).length]'hi_ps_via_s1 =
        pk.public_seed.val[i - 384 * (k p : ℕ)]'hi_ps := by
      fcongr 1
    rw [h_right, h_via_s1, h_idx_swap]

/-- **Spec for `mlkem.key_compute_encapsulation_key_hash`** —
H(ek) computation for the FO transform (FIPS 203 §5.1): writes
`SHA3-256(encoded_t[0..384*(k p)] ‖ public_seed)` into
`pk_mlkem_key.encaps_key_hash`. No loops; direct hash chain
`set_alg → init → append(encoded_t_prefix) → append(public_seed) → result`.

Informal proof. Template: hash-chain wrapper (leaf, no loops).
`unfold mlkem.key_compute_encapsulation_key_hash`; `step*` through:
1. `UScalar.cast.spec` (U8 → Usize) for `n_rows = k p`.
2. `mlkem.sizeof_encoded_uncompressed_vector.spec` — yields
   `cb_encoded_vector.val = 384 * (k p)`.
3. `MlKemHashState.set_alg.spec` — sets `hash_state0` to `Sha3_256`.
4. `MlKemHashState.init.spec` — fresh absorbing ghost `g0` for SHA3-256
   (rate = 136, pad = 0x06; `algParams Sha3_256 = some (136, 6#u8)`).
5. `core.array.Array.index.spec` for `encoded_t[0..cb_encoded_vector]`
   — yields slice `s` with `s.val = pk_mlkem_key.encoded_t.val.take (384*(k p))`.
6. `MlKemHashState.append.spec` (absorbs encoded_t prefix); ghost `g1`
   with `g1.absorbed.map (·.bv) = (keyEncodedTPrefix pk_mlkem_key p).toList`
   (by definition of `keyEncodedTPrefix`).
7. `lift Array.to_slice.spec` for `public_seed` (32 bytes).
8. `MlKemHashState.append.spec` (absorbs `public_seed`); ghost `g2` with
   `g2.absorbed.map (·.bv) =
    (keyEncodedTPrefix pk_mlkem_key p ‖ arrayToSpecBytes pk_mlkem_key.public_seed).toList`.
9. `lift Array.to_slice_mut.spec` for `encaps_key_hash` (length 32 =
   `resultSize Sha3_256`).
10. `MlKemHashState.result.spec` — yields `out.val = (extractOutput g2 32).toList`.
11. Connect `extractOutput g2 32` to `Spec.SHA3.sha3_256 (keyEncodedTPrefix
    ‖ public_seed)` via the SHA3 sponge bridge lemma
    `sha3_256_extractOutput` (`Properties/MLKEM/Hash.lean:411`): for a
    `Sha3_256` ghost `g`, `(extractOutput g 32).map (·.bv) =
    Spec.SHA3.sha3_256 g.absorbed`.
12. Apply `to_slice_mut_back` — stores `out` into `key'.encaps_key_hash`.
Preservation: `key' = { pk_mlkem_key with encaps_key_hash := … }` so
`data`, `encoded_t`, `public_seed`, `params` are unchanged; `wfKey key' p`
from `wfKey pk_mlkem_key p` since `wfKey` does not constrain
`encaps_key_hash`. `agrind` for all bound and arithmetic goals. -/
@[step]
theorem mlkem.key_compute_encapsulation_key_hash.spec
    (p : ParameterSet)
    (pk_mlkem_key : mlkem.key.Key)
    (p_comp_temps : mlkem.ntt.InternalComputationTemporaries)
    (h_wf : wfKey pk_mlkem_key p) :
    mlkem.key_compute_encapsulation_key_hash pk_mlkem_key p_comp_temps
      ⦃ key' _comp_temps' =>
          wfKey key' p ∧
          key'.data = pk_mlkem_key.data ∧
          key'.encoded_t = pk_mlkem_key.encoded_t ∧
          key'.public_seed = pk_mlkem_key.public_seed ∧
          /- Non-hash, non-data fields are preserved by the struct update on
             `encaps_key_hash` only. -/
          key'.params = pk_mlkem_key.params ∧
          key'.n_rows = pk_mlkem_key.n_rows ∧
          key'.private_seed = pk_mlkem_key.private_seed ∧
          key'.private_random = pk_mlkem_key.private_random ∧
          key'.has_private_seed = pk_mlkem_key.has_private_seed ∧
          key'.has_private_key = pk_mlkem_key.has_private_key ∧
          /- The hash output equals SHA3-256 of (encoded_t prefix ‖ public_seed). -/
          arrayToSpecBytes key'.encaps_key_hash =
            Spec.SHA3.sha3_256
              (keyEncodedTPrefix pk_mlkem_key p
                ‖ arrayToSpecBytes pk_mlkem_key.public_seed) ⦄ := by
  unfold mlkem.key_compute_encapsulation_key_hash
  have h_nrows : pk_mlkem_key.params.n_rows.val = (k p : ℕ) :=
    wfInternalParams.n_rows_val (wfKey.params_ok (self := pk_mlkem_key) h_wf)
  have h_nrows_le4 : pk_mlkem_key.params.n_rows.val ≤ 4 := by
    rw [h_nrows]; exact k_le_4 p
  step
  have h_i_le4 : i.val ≤ 4 := by
    have := h_nrows_le4
    rw [i_post]; scalar_tac
  step  -- sizeof_encoded_uncompressed_vector
  step  -- set_alg
  -- init: provide rate=136, padVal=6#u8 (Sha3_256 params)
  step with mlkem.hash.MlKemHashState.init.spec _ 136 6#u8
    (by rw [p_state_post2]; decide)
    (by refine ⟨by decide, ?_, by decide⟩;
        show 8 * 136 < Spec.SHA3.b; decide)
  step  -- Array.index encoded_t [0..cb_encoded_vector] → slice s
  -- first append: absorbing carries from init
  step with mlkem.hash.MlKemHashState.append.spec _ _ _ (Or.inl p_state1_post2)
  step  -- Array.to_slice public_seed → s1
  -- second append: absorbing carries from p_state2
  step with mlkem.hash.MlKemHashState.append.spec _ _ _ (Or.inl p_state2_post2)
  step  -- Array.to_slice_mut encaps_key_hash → (s2, back)
  -- result: needs h_len : s2.length = resultSize Sha3_256 = 32
  step with mlkem.hash.MlKemHashState.result.spec _ s2 _ (Or.inl p_state3_post2)
    (by
      have halg : p_state3.alg = mlkem.hash.MlKemHashAlg.Sha3_256 := by
        rw [p_state3_post1, p_state2_post1, p_state1_post1, p_state_post2]
      simp [Slice.length, s2_post1, halg, mlkem.hash.MlKemHashState.resultSize])
  refine ⟨⟨wfKey.params_ok (self := pk_mlkem_key) h_wf,
          wfKey.n_rows_ok (self := pk_mlkem_key) h_wf,
          wfKey.data_wf (self := pk_mlkem_key) h_wf⟩, ?_⟩
  -- Bridge: arrayToSpecBytes (to_slice_mut_back s3) =
  --   sha3_256 (keyEncodedTPrefix pk_mlkem_key p ‖ arrayToSpecBytes public_seed)
  -- via `sha3_256_extractOutput` over the after-2-appends ghost state.
  -- Step 1: squeeze_mode = false at p_state1 and p_state2.
  have h_p1_no_sq : p_state1.state.squeeze_mode = false := by
    have hab := p_state1_post2
    simp only [mlkem.hash.MlKemHashState.absorbing] at hab
    have h := hab.1.1.2.1
    cases hsq : p_state1.state.squeeze_mode
    · rfl
    · rw [hsq] at h; exact absurd rfl h
  have h_p2_no_sq : p_state2.state.squeeze_mode = false := by
    have hab := p_state2_post2
    simp only [mlkem.hash.MlKemHashState.absorbing] at hab
    have h := hab.1.1.2.1
    cases hsq : p_state2.state.squeeze_mode
    · rfl
    · rw [hsq] at h; exact absurd rfl h
  -- Step 2: define G explicitly with squeeze_mode = false.
  have h_kp : (k p : ℕ) ≤ 4 := k_le_4 p
  have h_i_kp : i.val = (k p : ℕ) := by rw [i_post]; scalar_tac
  have h_s_len : s.length = 384 * (k p : ℕ) := by
    rw [s_post2, cb_encoded_vector_post, h_i_kp]; omega
  have h_s_val_len : (↑s : List U8).length = 384 * (k p : ℕ) := h_s_len
  have h_s1_val_len : (↑s1 : List U8).length = 32 := by
    rw [s1_post]; simp [Aeneas.Std.Array.to_slice]
  -- s2.val length = 32
  have h_s2_len : s2.length = 32 := by
    simp [Slice.length, s2_post1]
  -- p_state3.alg = Sha3_256
  have h_p3_alg : p_state3.alg = mlkem.hash.MlKemHashAlg.Sha3_256 := by
    rw [p_state3_post1, p_state2_post1, p_state1_post1, p_state_post2]
  -- s3.val = (extractOutput G 32).toList
  set G_init : sha3.sha3_impl.GhostState :=
    sha3.sha3_impl.GhostState.init 136 6#u8
      (by refine ⟨by decide, ?_, by decide⟩; show 8 * 136 < Spec.SHA3.b; decide)
    with hG_init_def
  -- Define G directly from p_state4_post3's expression.
  set G : sha3.sha3_impl.GhostState :=
    (G_init.append (↑s) p_state1.state.squeeze_mode).append (↑s1)
        p_state2.state.squeeze_mode with hG_def
  have h_s3_val : (↑s3 : List U8) =
      (sha3.sha3_impl.extractOutput G s2.length).toList := p_state4_post3
  -- Step 3: G.absorbed = s.val ++ s1.val, lengths.
  have h_G_absorbed : G.absorbed = (↑s : List U8) ++ (↑s1 : List U8) := by
    simp [hG_def, hG_init_def, sha3.sha3_impl.GhostState.append,
          sha3.sha3_impl.GhostState.init, h_p1_no_sq, h_p2_no_sq]
  have h_G_abs_len : G.absorbed.length = 384 * (k p : ℕ) + 32 := by
    rw [h_G_absorbed, List.length_append, h_s_val_len, h_s1_val_len]
  have h_G_rate : G.rate = 136 := by
    simp only [hG_def, hG_init_def, h_p1_no_sq, h_p2_no_sq,
               sha3.sha3_impl.GhostState.append, sha3.sha3_impl.GhostState.init,
               Bool.false_eq_true, ite_false]
  have h_G_padVal : G.padVal = 6#u8 := by
    simp only [hG_def, hG_init_def, h_p1_no_sq, h_p2_no_sq,
               sha3.sha3_impl.GhostState.append, sha3.sha3_impl.GhostState.init,
               Bool.false_eq_true, ite_false]
  have h_G_squeezed : G.squeezed = [] := by
    simp [hG_def, hG_init_def, sha3.sha3_impl.GhostState.append,
          sha3.sha3_impl.GhostState.init, h_p1_no_sq, h_p2_no_sq]
  -- Step 4: B and per-byte equality.
  set B : 𝔹 (384 * (k p : ℕ) + 32) :=
    keyEncodedTPrefix pk_mlkem_key p ++ arrayToSpecBytes pk_mlkem_key.public_seed
    with hB_def
  -- Step 5: rewrite LHS through `to_slice_mut_back` into `from_slice` form
  -- so the composite SHA3-256 bridge in HashCalls.lean applies directly.
  have h_s3_len : s3.length = 32 := p_state4_post2.trans h_s2_len
  have h_s3_val32 : (↑s3 : List U8) =
      (sha3.sha3_impl.extractOutput G 32).toList := by
    have := h_s3_val
    rw [h_s2_len] at this
    exact this
  rw [s2_post2]
  -- Step 6: per-byte equality `B[i] = G.absorbed[i].bv`.
  have h_s_val_eq : (↑s : List U8) =
      pk_mlkem_key.encoded_t.val.slice 0 (384 * (k p : ℕ)) := by
    have h_cb : (cb_encoded_vector.val : ℕ) = 384 * (k p : ℕ) := by
      rw [cb_encoded_vector_post, h_i_kp]
    rw [s_post1, h_cb]
    rfl
  have hlen_app : ((↑s : List U8) ++ (↑s1 : List U8)).length =
      384 * (k p : ℕ) + 32 := by
    rw [List.length_append, h_s_val_len, h_s1_val_len]
  have h_per_byte : ∀ (i : Fin (384 * (k p : ℕ) + 32)),
      B.get i = (G.absorbed[i.val]'(by rw [h_G_abs_len]; exact i.isLt)).bv := by
    intro i
    have hi_abs : i.val < ((↑s : List U8) ++ (↑s1 : List U8)).length := by
      rw [hlen_app]; exact i.isLt
    have hi_G : i.val < G.absorbed.length := by
      rw [h_G_abs_len]; exact i.isLt
    have h_abs_idx :
        ((↑s : List U8) ++ (↑s1 : List U8))[i.val]'hi_abs =
          G.absorbed[i.val]'hi_G := List.getElem_of_eq h_G_absorbed.symm hi_abs
    have h_lem := keyEncodedTPrefix_append_pubseed_per_byte pk_mlkem_key p s s1
      h_s_val_eq h_s_len s1_post h_kp i.val i.isLt hi_abs
    have h_B_unfold : B[i.val]'i.isLt =
        (keyEncodedTPrefix pk_mlkem_key p
          ++ arrayToSpecBytes pk_mlkem_key.public_seed)[i.val]'i.isLt := by
      show B[i.val]'i.isLt = _; rfl
    show B[i.val]'i.isLt = _
    exact h_B_unfold.trans (h_lem.trans (congrArg (·.bv) h_abs_idx))
  -- Step 7: apply the composite SHA3-256 bridge from HashCalls.
  exact arrayToSpecBytes_from_slice_eq_sha3_256 pk_mlkem_key.encaps_key_hash s3
    h_s3_len G h_s3_val32 B h_G_abs_len h_per_byte
    h_G_rate h_G_padVal h_G_squeezed

/-! ## Bundled cryptographic witnesses for a loaded key

`wfKey` (Bridges/KeyView.lean) is layout-only by design: it does NOT
carry the spec-side correspondences that depend on the values written
during key generation / key load.  Those correspondences — the
SHA3-256 hash cache, the byte-form of the encoded `t̂` prefix, and
the SampleNTT identity of every `Â^T` entry — are *transient*
postconditions of the key-load specs (`key_set_value.spec`,
`key_expand_from_private_seed.spec`) and need to flow into every
`@[step]` whose proof references the spec-level meaning of the
loaded key.

Rather than thread separate preconditions through every layer of
`mlkem.encapsulate*` (and analogous sites for `decapsulate`), bundle
them into one named structure per Format.  Consumers write
`(h_pub : wfEncapKey pk p)` (or `wfDecapKey` for decapsulation) and
reach `wfKey` via `h_pub.toWfKey`; the upstream `key_set_value` /
`key_expand` proofs discharge the new fields once at key-load time.

We use three monotone-stronger structures, aligned with the three
`MLKEM_BLOB_TYPE` Formats handled by `key_set_value` / `key_get_value`:

* `wfEncapKey` — bottom; established when an encapsulation-key blob is
  loaded (no `ŝ` material).  Carries `hash_pinned`, `byte_form_t`,
  `matrix_form_a`.
* `wfDecapKey extends wfEncapKey` — established when a
  decapsulation-key blob is loaded.  Adds `has_private_key = true` and
  the symmetric `byte_form_s` witness on the `ŝ` half.
* `wfPrivateSeed extends wfDecapKey` — top; established when a
  private-seed blob is loaded (or by `key_generate`).  Adds the
  K_PKE.KeyGen FC equalities pinning the key state to
  `K_PKE.KeyGen p (private_seed.toSpec)`, plus `has_private_seed = true`.

Ordering theorems (`wfEncapKey_of_wfDecapKey`,
`wfDecapKey_of_wfPrivateSeed`) are bare structure projections and are
defined where the strongest predicate lives
(`Encoding/KeySetValue/Prelude.lean`).

See `Properties/MLKEM/Encaps.lean` for the c-equality consumer and
`Properties/MLKEM/Key/Prelude.lean :: keyExpand.{Inv2, Inv4}` for the
producer-side conjuncts that feed the witnesses. -/

/-- Abbreviation for the SHA3-256 hash-pinning equation that the
key-load specs commit (`encaps_key_hash = H(ek)`).  Used by
`wfEncapKey` (and inherited by `wfDecapKey` / `wfPrivateSeed`), and
consumable directly by `mlkem.decapsulate.spec` (where the runtime
`H` is named `Spec.SHA3.sha3_256`; note `encapsulationKey self p` is
definitionally `keyEncodedTPrefix self p ‖ public_seed.toSpec`). -/
abbrev keyHashPinned (self : mlkem.key.Key) (p : ParameterSet) : Prop :=
  self.encaps_key_hash.toSpec =
    Spec.SHA3.sha3_256
      (keyEncodedTPrefix self p ‖ self.public_seed.toSpec)

/-- Crypto-level commitments a loaded *encapsulation* key carries
beyond layout (`wfKey`).  Produced by `key_set_value.spec`
(`EncapsulationKey` arm — and via `.toWfEncapKey` from the
`DecapsulationKey` and `PrivateSeed` arms); consumed by
`mlkem.encapsulate*.spec`. -/
structure wfEncapKey (self : mlkem.key.Key) (p : ParameterSet) : Prop extends Bridges.wfKey self p where
  /-- The cached encaps-key hash is exactly SHA3-256 over
      `ek = encoded_t[0..384·k] ‖ public_seed` (FIPS 203 §7.2 line 1's
      `H(ek)`). -/
  hash_pinned : keyHashPinned self p
  /-- The encoded-`t̂` prefix is the byte encoding of `keyT self p`
      — the decoded `t̂` witness materialised at key-load.  The
      existential's witness is pinned to `keyT self p` so consumers
      get both the byte-form and the poly-vector view in one shot. -/
  byte_form_t : ∃ v_t : MLKEM.PolyVector q (k p),
    keyEncodedTPrefix self p =
      (MLKEM.PolyVector.ByteEncode 12 v_t).cast
        (Bridges.polyVector_byteEncode_size_cast 12)
    ∧ Bridges.keyT self p = v_t
  /-- Every `keyAHat[i, j]` is `SampleNTT(ρ ‖ i ‖ j)` per FIPS 203
      Algorithm 13 line 6 (the implementation stores `Â^T`, so
      `keyAHat[i, j]` is sampled with bytes `i ‖ j`). -/
  matrix_form_a : ∀ (i j : ℕ)
                    (hi : i < (k p : ℕ)) (hj : j < (k p : ℕ)),
    Bridges.keyAHat self p ⟨i, hi⟩ ⟨j, hj⟩ =
      MLKEM.SampleNTT
        (self.public_seed.toSpec ‖
          #v[(i : Byte)] ‖ #v[(j : Byte)])

/-- Crypto-level commitments a *decapsulation* key carries beyond a
public key (`wfEncapKey`).  A decapsulation key is exactly a public
key plus the private half: the `has_private_key` flag is set so the
caller-side `mlkem.decapsulate` dispatcher does not short-circuit
with `InvalidArgument`.

Note on a deliberately omitted `byte_form_s` field.  A natural-looking
analogue to `byte_form_t` — `∃ v_s, keySEncoded self p =
(ByteEncode 12 v_s).cast _ ∧ keyS_std self p = v_s` — is
**tautological** for every key, because `keySEncoded` is *defined* as
`(ByteEncode 12 (keyS_std self p)).cast _` and `keyS_std` is itself
a pure projection from `self.data`.  Unlike the `t̂` side, the
runtime key does not store an independent `encoded_s` byte field
that we would need to bridge to a decoded witness.  Producers and
consumers therefore get the byte view of `s` directly from
`keySEncoded`'s definition; no `wfDecapKey` field is required.

Producers: `key_set_value.spec` (DecapsulationKey arm — and via
`.toWfDecapKey` from the PrivateSeed arm).  Consumer:
`mlkem.decapsulate.spec`. -/
structure wfDecapKey (self : mlkem.key.Key) (p : ParameterSet) : Prop extends wfEncapKey self p where
  /-- The Rust API requires a private key for decapsulation; the
      function short-circuits to `Error.InvalidArgument` when this
      flag is `false` (mlkem.rs L5074). -/
  has_private_key : self.has_private_key = true

end Symcrust.Properties.MLKEM
