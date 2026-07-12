/-
  # Key.lean — `key_expand_from_private_seed` and its two loops.

  `key_expand_from_private_seed` performs the deterministic part of
  `K-PKE.KeyGen` (FIPS 203 §4.2.2 / Alg. 13):

  1. Compute `(public_seed, private_seed_hash) := G(d ‖ k)`.
  2. **Loop 0**: sample `s ← SamplePolyCBD η₁(PRF η₁(σ, i))` for
     `i ∈ [0, k)` into `pk_mlkem_key.s`.
  3. **Loop 1**: sample `e ← SamplePolyCBD η₁(PRF η₁(σ, k + i))` for
     `i ∈ [0, k)` into `pk_mlkem_key.t` (in-place; later overwritten
     by `t̂ = Â · ŝ + ê`).
  4. NTT in place: `s ← ŝ`, `t ← ê`.
  5. `pv_tmp := ŝ ⊙ R` (Mont form, scratch in `max_size_vector0`).
  6. `t ← Â · (ŝ ⊙ R) ⊘ R + ê = Â · ŝ + ê = t̂`.
  7. `a_transpose ← Â^T` (in-place transpose).
  8. `encoded_t[0..384·k] := ByteEncode 12 t̂`.
  9. `encaps_key_hash := SHA3-256(encoded_t[0..384·k] ‖ public_seed)`.

  After the call, the key fields hold:
  * `public_seed = ρ = (G(d ‖ #v[k.byte])).1` (32 bytes).
  * `data[0 .. k²)` = `Â^T` (where `Â[i][j] = SampleNTT(ρ ‖ [j, i])`).
  * `data[k² .. k²+k)` = `t̂` (standard NTT form).
  * `data[k²+k .. k²+2k)` = `ŝ` (standard NTT form — see KeyView.lean
    convention note).
  * `encoded_t[0..384·k]` = `ByteEncode 12 t̂` (= prefix of `ekPKE`).
  * `encaps_key_hash` = `SHA3-256(ekPKE)`.

  These are tied to the **top-level** spec function `K_PKE.KeyGen p d`
  (FIPS 203 Alg. 13) whose outputs `(ekPKE, dkPKE)` are:
  * `ekPKE = ByteEncode 12 t̂ ‖ ρ`
  * `dkPKE = ByteEncode 12 ŝ`

  ## Loops

  Both loops iterate over `Range U8 [0, n_rows)` and stream a
  Shake256 ghost state.  `mkhs` is the **base** state (absorbing for
  σ); each iteration clones it into a fresh worker `mkhs'`, appends a
  one-byte index, and extracts 64·η₁ bytes that are then fed to
  `SamplePolyCBD η₁`.

  * `mlkem.key_expand_from_private_seed_loop0` — `s` sampling.
    Cascade: `letRange 1 1` + `branch 1 (letRange 0 20)`.
  * `mlkem.key_expand_from_private_seed_loop1` — `e` sampling.
    Cascade: `letRange 1 1` + `branch 1 (letRange 0 21)`.
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.KeyView
import Symcrust.Properties.MLKEM.Bridges.PrfShake
import Symcrust.Properties.MLKEM.Sampling.SampleCBD
import Symcrust.Properties.MLKEM.Sampling.ExpandMatrix
import Symcrust.Properties.SHA3.StatefulHash

open Aeneas Aeneas.Std Result
open scoped Spec.Notations
open Spec
open Spec.MLKEM
open symcrust

namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

@[reducible] def dataEnd (p : ParameterSet) : ℕ :=
  matrixLen p + (k p : ℕ) + (k p : ℕ)

/-! ## CBD loop invariant (shared between loop 0 and loop 1)

After `i` iterations of CBD sampling, the destination data slot
range `[dstStart, dstStart + i)` matches `SamplePolyCBD η₁
(PRF η₁ σ (offset + j).byte)` for each `j < i`, where:

* `σ : 𝔹 32` is the absorbed seed in the base ghost.
* `offset = 0` for loop 0 (s sampling) and `offset = k` for loop 1
  (e sampling).
* `dstStart = sOffset params` for loop 0, `tOffset params` for loop 1.

All other data slots are unchanged from the original key.  Public
fields (`public_seed`, `private_seed`, `encoded_t`, `encaps_key_hash`,
etc.) are unchanged. -/

/-- Per-coefficient bound check for a CBD-sampled polynomial: all 256
coefficients are `< q`. -/
private def cbdPolyMatches
    (a : PolyElement) (target : MLKEM.Polynomial q) : Prop :=
  wfPoly a ∧ toPoly a = target

/-- **CBD loop invariant**.

`offset` is the spec-side N-index offset: `0` for loop 0 (s), `k p`
for loop 1 (e).  `dstStart` is the data-slot offset: `sOffset p` for
loop 0, `tOffset p` for loop 1. -/
def cbdLoopInv
    (params : ParameterSet) (σ : 𝔹 32)
    (orig_key key : mlkem.key.Key)
    (offset : ℕ) (dstStart : ℕ)
    (h_dst : dstStart + (k params : ℕ) ≤ dataEnd params)
    (i : ℕ)
    (mkhs_base : mlkem.hash.MlKemHashState)
    (g_base : sha3.sha3_impl.GhostState) : Prop :=
  wfKey key params ∧
  i ≤ (k params : ℕ) ∧
  -- Base hash state untouched: still absorbing σ as Shake256.
  mlkem.hash.MlKemHashState.absorbing mkhs_base g_base ∧
  g_base.absorbed.map (·.bv) = σ.toList ∧
  mkhs_base.alg = mlkem.hash.MlKemHashAlg.Shake256 ∧
  -- Destination slots `[dstStart, dstStart + i)` match the CBD spec.
  -- The slot lookup uses total-form `[..]'h`, with the bound derived
  -- from `h_dst` plus `k_sq_plus_2k_le_24 params` (so
  -- `dstStart + j < dataEnd params ≤ 24`).
  (∀ (j : ℕ) (h_j : j < (k params : ℕ)), j < i →
      cbdPolyMatches
        (key.data.val[dstStart + j]'(by
          have h1 : key.data.val.length = 24 := key.data.property
          have := k_sq_plus_2k_le_24 params
          unfold dataEnd matrixLen at h_dst; grind))
        (MLKEM.SamplePolyCBD
          (MLKEM.PRF (η₁ params) σ ((offset + j : ℕ) : Byte)))) ∧
  -- All other data slots unchanged from the original key.
  (∀ (slot : ℕ) (h_slot : slot < dataEnd params),
      ¬ (dstStart ≤ slot ∧ slot < dstStart + i) →
      key.data.val[slot]'(by
        have h1 : key.data.val.length = 24 := key.data.property
        unfold dataEnd matrixLen at h_slot; grind) =
      orig_key.data.val[slot]'(by
        have h1 : orig_key.data.val.length = 24 := orig_key.data.property
        unfold dataEnd matrixLen at h_slot; grind)) ∧
  -- Non-data fields are unchanged from the original key.
  key.params = orig_key.params ∧
  key.n_rows = orig_key.n_rows ∧
  key.public_seed = orig_key.public_seed ∧
  key.encoded_t = orig_key.encoded_t ∧
  key.encaps_key_hash = orig_key.encaps_key_hash ∧
  key.has_private_seed = orig_key.has_private_seed ∧
  key.has_private_key = orig_key.has_private_key ∧
  key.private_seed = orig_key.private_seed ∧
  key.private_random = orig_key.private_random

/-! ## Loop 0 (`s` sampling) -/

#decompose mlkem.key_expand_from_private_seed_loop0
    key_expand_from_private_seed_loop0.fold
  letRange 1 1 => key_expand_from_private_seed_loop0_match

#decompose key_expand_from_private_seed_loop0_match
    key_expand_from_private_seed_loop0_match.fold
    branch 1 (letRange 0 20) => key_expand_from_private_seed_loop0_body

/-- **Body spec** for loop 0.  Advances `cbdLoopInv` by one s-slot.

Informal proof.  The decomposed body (branch 1, `letRange 0 21`)
performs a clone-append-extract-CBD chain on the base hash state:
(1) `step` with `MlKemHashState.clone.spec`: produces a worker state
`mkhs_w` sharing the same ghost state as `mkhs` (absorbing `g_base`
with `g_base.absorbed = σ`, guaranteed by `h_inv`).
(2) Cast `i` to a byte and append it to `mkhs_w` via `step` with
`MlKemHashState.append.spec`: worker ghost state advances to
`g_base ++ [(i : Byte)]`.
(3) Arithmetic steps for `n_bytes := 2 * n_eta1 * 64 = 64 * η₁
params`; overflow from `h_n_eta1 : n_eta1.val = η₁ params ≤ 2` and
`agrind`.
(4) `step` with `MlKemHashState.extract.spec` (wipe = true): gives
`out.val = SHAKE256(σ ++ [(i : Byte)], 64 * η₁) = PRF η₁ σ (i :
Byte)`; the worker is discarded (wipe path).
(5) `step` with `SamplePolyCBD.spec` on `out`: gives
`cbdPolyMatches result (MLKEM.SamplePolyCBD (PRF (η₁ params) σ
(i : Byte)))`.
(6) Mut-accessor step writing `result` into
`key.data[sOffset params + i.val]`; framing: all other data slots
unchanged from `h_inv`.
Residual: rebuild `cbdLoopInv` at `i.val + 1`.  Slot
`sOffset params + i.val` now holds the CBD sample (steps 4–5–6);
prior slots `[sOffset, sOffset + i.val)` are unchanged from `h_inv`;
`_mkhs'` = the original `mkhs` (unchanged by clone/extract, returned
as the base state); `wfKey key'` from `h_inv` + `wfPoly` of the new
slot.  Close by `agrind`. -/
@[step]
theorem key_expand_from_private_seed_loop0_body.spec
    (params : ParameterSet) (σ : 𝔹 32)
    (i : U8) (orig_key pk_mlkem_key : mlkem.key.Key)
    (mkhs : mlkem.hash.MlKemHashState)
    (cbd_sample_buffer : Array U8 193#usize) (n_eta1 : U8)
    (g_base : sha3.sha3_impl.GhostState)
    (h_inv : cbdLoopInv params σ orig_key pk_mlkem_key 0
              (sOffset params)
              (by unfold sOffset dataEnd matrixLen; grind)
              i.val mkhs g_base)
    (h_i : i.val < (k params : ℕ))
    (h_n_eta1 : n_eta1.val = (η₁ params : ℕ)) :
    key_expand_from_private_seed_loop0_body pk_mlkem_key mkhs
        cbd_sample_buffer n_eta1 i
      ⦃ _mkhs' _buf' key' =>
          cbdLoopInv params σ orig_key key' 0
            (sOffset params)
            (by unfold sOffset dataEnd matrixLen; grind)
            (i.val + 1) mkhs g_base ⦄ := by
  unfold key_expand_from_private_seed_loop0_body
  obtain ⟨h_wf, h_i_le, h_abs, h_g_abs, h_alg_eq, h_cbd, h_frame,
    h_params, h_nrows, h_pubseed, h_enct, h_kh, h_hpsd, h_hpkey, h_psd, h_prnd⟩ := h_inv
  step
  step as ⟨mkhs2, h_mkhs2⟩
  subst h_mkhs2
  step
  step
  step
  step as ⟨s, h_s_val, h_s_len⟩
  step with mlkem.hash.MlKemHashState.append.spec _ s g_base (Or.inl h_abs)
    as ⟨mkhs3, h_mkhs3_alg, h_mkhs3_abs⟩
  have h_n_eta1_le : n_eta1.val ≤ 3 := by
    rcases params <;> rw [h_n_eta1] <;> decide
  step  -- i1 ← cast n_eta1 to Usize
  step  -- i2 ← 64 * i1
  step  -- index_mut [0..i2)
  step with mlkem.hash.MlKemHashState.extract.spec _ _ _ _
    (Or.inl h_mkhs3_abs) (Or.inr (h_mkhs3_alg.trans h_alg_eq))
    as ⟨mkhs4, s2, h_mkhs4_alg, h_s2_len, h_s2_val, h_mkhs4_post⟩
  step  -- s3 ← lift (index_mut_back1 s2).to_slice
  step  -- i3 ← cast n_eta1 to U32
  step with mlkem.key.Key.s_mut.spec _ params h_wf
    as ⟨s4, h_s4_len, s_mut_back, h_s4_wf, h_s4_eq, h_s_mut_back⟩
  step  -- i4 ← cast i to Usize
  step  -- index_mut_usize s4 i4: gives (a, index_mut_back1)
  have h_i3_eta : i3.val = 2 ∨ i3.val = 3 := by
    have h_i3_n : i3.val = n_eta1.val := by simp [i3_post]
    rw [h_i3_n, h_n_eta1]
    rcases params <;> decide
  have h_s3_len : s3.length = 64 * 3 + 1 := by
    have h_idx_len : (↑(cbd_sample_buffer1) : List U8).length = 193 := by simp
    have h_s3_eq : (↑s3 : List U8) =
        (↑(cbd_sample_buffer1) : List U8).setSlice! 0 s2.val := by
      rw [s3_post]; simp only [Std.Array.to_slice]; exact s1_post3 s2
    show (↑s3 : List U8).length = 64 * 3 + 1
    rw [h_s3_eq, List.length_setSlice!, h_idx_len]
  step with mlkem.ntt.poly_element_sample_cbd_from_bytes.spec _ _ _
    h_i3_eta h_s3_len
    as ⟨a1, h_a1_wf, h_a1_eq⟩
  -- Decompose a_post into the two component equalities.
  obtain ⟨h_a_eq, h_imb2_eq⟩ : a = (s4.val)[i4.val]! ∧ index_mut_back1 = s4.set i4 := by grind
  -- Substitute index_mut_back1 = s4.set i4 throughout.
  subst h_imb2_eq
  -- The new slice `s4.set i4 a1`: same length as s4, wfPoly everywhere.
  have hs'_len : (s4.set i4 a1).length = (k params : ℕ) := by
    simp [Slice.set]; exact s_mut_back
  have hs'_wf : ∀ j (_ : j < (s4.set i4 a1).length), wfPoly (↑(s4.set i4 a1))[j] := by
    intro j hj
    have hj4 : j < s4.length := by simpa [Slice.set, Slice.setAtNat] using hj
    have h_val : (↑(s4.set i4 a1) : List _) = (↑s4 : List _).set i4.val a1 := by
      simp [Slice.set, Slice.setAtNat]
    have hbound : j < ((↑s4 : List _).set i4.val a1).length := by simp; exact hj4
    have heq : (↑(s4.set i4 a1) : List _)[j]'hj
        = ((↑s4 : List _).set i4.val a1)[j]'hbound := by
      apply Eq.symm; apply List.getElem_of_eq h_val.symm
    show wfPoly (↑(s4.set i4 a1) : List _)[j]
    rw [heq, List.getElem_set]
    split
    · exact h_a1_wf
    · exact h_s4_wf j hj4
  obtain ⟨⟨h_wf', h_params', h_nrows', h_hpsd', h_psd', h_prnd'⟩,
    h_ai', h_hpkey', h_pubseed', h_enct', h_kh',
    h_dlen', h_data_match, h_data_frame⟩ :=
    h_s_mut_back (s4.set i4 a1) hs'_len hs'_wf
  -- Reconstruct `cbdLoopInv` at index `i.val + 1`.
  unfold cbdLoopInv
  refine ⟨h_wf', by agrind, h_abs, h_g_abs, h_alg_eq,
          ?cbd_new, ?frame_new,
          h_params'.trans h_params, h_nrows'.trans h_nrows,
          h_pubseed'.trans h_pubseed, h_enct'.trans h_enct,
          h_kh'.trans h_kh, h_hpsd'.trans h_hpsd, h_hpkey'.trans h_hpkey,
          h_psd'.trans h_psd, h_prnd'.trans h_prnd⟩
  case cbd_new =>
    -- CBD match for slots `[sOffset, sOffset + i.val + 1)`.
    intro j h_j h_j_lt
    by_cases hji : j < i.val
    · -- Existing slot: use h_cbd + h_data_match + h_data_frame chain.
      have h_old := h_cbd j h_j hji
      have h_j_lt_k : j < (k params : ℕ) := h_j
      have h_j_ne : i4.val ≠ j := by simp [i4_post]; omega
      have h_dm := h_data_match j h_j_lt_k
      have h_se := h_s4_eq j h_j_lt_k
      have h_val : (↑(s4.set i4 a1) : List _) = (↑s4 : List _).set i4.val a1 := by
        simp [Slice.set, Slice.setAtNat]
      have h_pkey_len : (↑pk_mlkem_key.data : List (Std.Array U16 256#usize)).length = 24 := by
        have := pk_mlkem_key.data.property; simp
      have h_ksq := k_sq_plus_2k_le_24 params
      have h_k_le : (k params : ℕ) ≤ 4 := k_le_4 params
      have h_offset_j : sOffset params + j < 24 := by
        unfold sOffset matrixLen
        have : (k params : ℕ) * (k params : ℕ) ≤ 4 * 4 :=
          Nat.mul_le_mul h_k_le h_k_le
        omega
      have h_bnd_pkey : sOffset params + j < (↑pk_mlkem_key.data : List (Std.Array U16 256#usize)).length := by
        rw [h_pkey_len]; exact h_offset_j
      have h_bnd_new : sOffset params + j < (↑(h_s4_len (s4.set i4 a1)).data : List (Std.Array U16 256#usize)).length := by
        rw [h_dlen']; exact h_offset_j
      have h_old_eq :
        (↑pk_mlkem_key.data : List (Std.Array U16 256#usize))[sOffset params + j]'h_bnd_pkey
          = (↑(h_s4_len (s4.set i4 a1)).data : List (Std.Array U16 256#usize))[sOffset params + j]'h_bnd_new := by
        rw [h_dm]
        simp only [h_val, List.getElem_set_ne h_j_ne, ← h_se]
      show cbdPolyMatches ((↑(h_s4_len (s4.set i4 a1)).data : List (Std.Array U16 256#usize))[sOffset params + j]'h_bnd_new) _
      rw [← h_old_eq]; exact h_old
    · -- New slot: j = i.val. Use h_a1_wf + h_a1_eq.
      have hji' : j = i.val := by omega
      -- Step 1: identify the slot's polynomial as a1.
      have h_val : (↑(s4.set i4 a1) : List _) = (↑s4 : List _).set i4.val a1 := by
        simp [Slice.set, Slice.setAtNat]
      have h_i4_val : i4.val = i.val := by simp [i4_post]
      have h_j_lt_k : j < (k params : ℕ) := h_j
      have h_dm := h_data_match j h_j_lt_k
      have h_pkey_len : (↑pk_mlkem_key.data : List (Std.Array U16 256#usize)).length = 24 := by
        have := pk_mlkem_key.data.property; simp
      have h_ksq := k_sq_plus_2k_le_24 params
      have h_k_le : (k params : ℕ) ≤ 4 := k_le_4 params
      have h_offset_j : sOffset params + j < 24 := by
        unfold sOffset matrixLen
        have : (k params : ℕ) * (k params : ℕ) ≤ 4 * 4 :=
          Nat.mul_le_mul h_k_le h_k_le
        omega
      have h_bnd_new : sOffset params + j < (↑(h_s4_len (s4.set i4 a1)).data : List (Std.Array U16 256#usize)).length := by
        rw [h_dlen']; exact h_offset_j
      have h_s4_len_eq : s4.val.length = (k params : ℕ) := s_mut_back
      have h_set_len : (↑(s4.set i4 a1) : List (Std.Array U16 256#usize)).length = (k params : ℕ) := by
        rw [h_val]; simp [h_s4_len_eq]
      have h_j_set_bnd : j < (↑(s4.set i4 a1) : List (Std.Array U16 256#usize)).length := by
        rw [h_set_len]; exact h_j_lt_k
      have h_slot_a1 : (↑(s4.set i4 a1) : List (Std.Array U16 256#usize))[j]'h_j_set_bnd = a1 := by
        simp [Slice.set, Slice.setAtNat, h_i4_val, hji']
      have h_chain : (↑(h_s4_len (s4.set i4 a1)).data : List _)[sOffset params + j]'h_bnd_new = a1 := by
        rw [h_dm]
        exact h_slot_a1
      show cbdPolyMatches ((↑(h_s4_len (s4.set i4 a1)).data : List (Std.Array U16 256#usize))[sOffset params + j]'h_bnd_new) _
      rw [h_chain]
      refine ⟨h_a1_wf, ?_⟩
      -- Step 2: discharge the toPoly equality via the PRF↔SHAKE bridge.
      -- h_a1_eq : toPoly a1 = MLKEM.SamplePolyCBD (η := cbdEta i3 h_i3_eta)
      --                        (sliceWindowToSpecBytes s3 0 (64 * i3.val) _)
      -- Target  : toPoly a1 = MLKEM.SamplePolyCBD (η := η₁ params)
      --                        (MLKEM.PRF (η₁ params) σ ((0 + j : ℕ) : Byte))
      rw [h_a1_eq]
      have h_offset_zero_j : ((0 + j : ℕ) : Byte) = (i.bv : Byte) := by
        rw [hji']; simp
      rw [h_offset_zero_j]
      -- Bridge 5: turn `SamplePolyCBD (sliceWindow ...) = SamplePolyCBD (PRF ...)`
      have h_sm : mkhs2.state.squeeze_mode = false := by
        unfold mlkem.hash.MlKemHashState.absorbing at h_abs
        have h_weak : sha3.sha3_impl.absorbingWeak mkhs2.state g_base := h_abs.1.1
        simpa using h_weak.2.1
      have h_cbd_eta_val :
          (cbdEta i3 h_i3_eta : ℕ) = (η₁ params : ℕ) := by
        simp only [cbdEta]
        have : i3.val = n_eta1.val := by simp [i3_post]
        rw [this, h_n_eta1]
      apply prf_shake_samplePolyCBD_bridge_of_absorbing
        (cbdEta i3 h_i3_eta) (η₁ params) h_cbd_eta_val
        σ i mkhs2 g_base h_abs h_alg_eq h_g_abs
        mkhs2.state.squeeze_mode h_sm s3
      -- h_s3_extract: per-byte equality
      intro k hk
      have h_kk : k < 64 * (cbdEta i3 h_i3_eta : ℕ) := hk
      have h_s_eq : s.val = [i] := by
        have h1 : (↑(cbd_sample_buffer1) : List U8) =
            (↑cbd_sample_buffer : List U8).set 0 i := by
          simp [cbd_sample_buffer1_post]
        rw [h_s_val]
        simp only [Std.Array.to_slice]
        rw [h1]
        have hlen : 1 ≤ (↑cbd_sample_buffer : List U8).length := by simp
        rcases hcb : (↑cbd_sample_buffer : List U8) with _ | ⟨x, xs⟩
        · simp [hcb] at hlen
        · simp [List.slice, List.set]
      have h_i2_eq : i2.val = 64 * (cbdEta i3 h_i3_eta : ℕ) := by
        have h_i1_eq : i1.val = n_eta1.val := by simp [i1_post]
        rw [i2_post, h_i1_eq, h_n_eta1, ← h_cbd_eta_val]
      have h_s1_len_eq : s1.length = 64 * (cbdEta i3 h_i3_eta : ℕ) := by
        have := s1_post2; omega
      have h_s2_val_len : s2.val.length = 64 * (cbdEta i3 h_i3_eta : ℕ) := by
        rw [show s2.val.length = s2.length from rfl, h_s2_len, h_s1_len_eq]
      have h_idx_len : (↑(cbd_sample_buffer1) : List U8).length = 193 := by simp [cbd_sample_buffer1_post]
      have h_s3_val_eq : (↑s3 : List U8) =
          (↑(cbd_sample_buffer1) : List U8).setSlice! 0 s2.val := by
        rw [s3_post]
        simp only [Std.Array.to_slice]
        exact s1_post3 s2
      have hk_s2 : k < s2.val.length := by rw [h_s2_val_len]; exact h_kk
      have h_mid :
          ((↑(cbd_sample_buffer1) : List U8).setSlice! 0 (↑s2 : List U8))[k]'
              (by rw [List.length_setSlice!, h_idx_len]; omega)
            = (↑s2 : List U8)[k]'hk_s2 :=
        List.getElem_setSlice!_middle (↑(cbd_sample_buffer1) : List U8) (↑s2 : List U8) 0 k
          ⟨by omega, by simpa using hk_s2, by rw [h_idx_len]; omega⟩
      have h_ext_len :
          (sha3.sha3_impl.extractOutput
              (g_base.append (↑s) mkhs2.state.squeeze_mode) s1.length).toList.length
            = 64 * (cbdEta i3 h_i3_eta : ℕ) := by
        rw [Vector.toList_length, h_s1_len_eq]
      have h_args_eq :
          (sha3.sha3_impl.extractOutput
              (g_base.append (↑s) mkhs2.state.squeeze_mode) s1.length).toList
            = (sha3.sha3_impl.extractOutput
                (g_base.append [i] mkhs2.state.squeeze_mode)
                (64 * (cbdEta i3 h_i3_eta : ℕ))).toList := by
        rw [h_s_eq, h_s1_len_eq]
      calc (↑s3 : List U8)[k]
          = ((↑(cbd_sample_buffer1) : List U8).setSlice! 0 (↑s2 : List U8))[k]'
              (by rw [List.length_setSlice!, h_idx_len]; omega) := by
                fcongr 1
        _ = (↑s2 : List U8)[k]'hk_s2 := h_mid
        _ = (sha3.sha3_impl.extractOutput
              (g_base.append (↑s) mkhs2.state.squeeze_mode) s1.length).toList[k]'
              (by rw [h_ext_len]; exact h_kk) := by
                rw [List.getElem_of_eq h_s2_val]
        _ = (sha3.sha3_impl.extractOutput
              (g_base.append [i] mkhs2.state.squeeze_mode)
              (64 * (cbdEta i3 h_i3_eta : ℕ))).toList[k] := by
                fcongr 1
  case frame_new =>
    -- Frame for the (i.val+1)-th step.  Two sub-cases depending on whether
    -- `slot` lies inside `[sOffset, sOffset + k)` (the s-block):
    --   • outside: combine `h_data_frame` (gives `= pk_mlkem_key.data[slot]`)
    --     with `h_frame` (gives `= orig_key.data[slot]`).
    --   • inside: must be `slot ∈ [sOffset + i.val + 1, sOffset + k)`; let
    --     `j := slot - sOffset`; use `h_data_match j` (gives
    --     `= (s4.set i4 a1)[j]`), then `j ≠ i.val` to drop the `set`, then
    --     `h_s4_eq` to recover `pk_mlkem_key.data[slot]`, then `h_frame`.
    intro slot h_slot h_out
    have h_k_le : (k params : ℕ) ≤ 4 := k_le_4 params
    have h_ksq : (k params : ℕ) * (k params : ℕ) + 2 * (k params : ℕ) ≤ 24 :=
      k_sq_plus_2k_le_24 params
    have h_slot24 : slot < 24 := by
      have : slot < dataEnd params := h_slot
      unfold dataEnd matrixLen at this
      omega
    by_cases h_in : sOffset params ≤ slot ∧ slot < sOffset params + (k params : ℕ)
    · -- slot is in the s-block; must be ≥ sOffset + i.val + 1
      obtain ⟨h_ge, h_lt⟩ := h_in
      set j := slot - sOffset params with hj_def
      have h_j_k : j < (k params : ℕ) := by omega
      have h_j_lo : i.val + 1 ≤ j := by
        by_contra h_neg
        apply h_out
        refine ⟨h_ge, ?_⟩
        omega
      have h_j_ne : i4.val ≠ j := by simp [i4_post]; omega
      have h_slot_eq : sOffset params + j = slot := by omega
      have h_dm := h_data_match j h_j_k
      have h_se := h_s4_eq j h_j_k
      have h_val : (↑(s4.set i4 a1) : List _) = (↑s4 : List _).set i4.val a1 := by
        simp [Slice.set, Slice.setAtNat]
      have h_dlen_pk : (↑pk_mlkem_key.data : List (Std.Array U16 256#usize)).length = 24 := by
        have := pk_mlkem_key.data.property; simp
      have h_dlen_ok : (↑orig_key.data : List (Std.Array U16 256#usize)).length = 24 := by
        have := orig_key.data.property; simp
      have h_bnd_slot_new :
          slot < (↑(h_s4_len (s4.set i4 a1)).data : List (Std.Array U16 256#usize)).length := by
        rw [h_dlen']; exact h_slot24
      have h_bnd_off_new :
          sOffset params + j
            < (↑(h_s4_len (s4.set i4 a1)).data : List (Std.Array U16 256#usize)).length := by
        rw [h_dlen']; omega
      have h_bnd_slot_pk :
          slot < (↑pk_mlkem_key.data : List (Std.Array U16 256#usize)).length := by
        rw [h_dlen_pk]; exact h_slot24
      have h_bnd_off_pk :
          sOffset params + j
            < (↑pk_mlkem_key.data : List (Std.Array U16 256#usize)).length := by
        rw [h_dlen_pk]; omega
      have h_bnd_slot_orig :
          slot < (↑orig_key.data : List (Std.Array U16 256#usize)).length := by
        rw [h_dlen_ok]; exact h_slot24
      have h_lhs_idx :
          (↑(h_s4_len (s4.set i4 a1)).data : List (Std.Array U16 256#usize))[slot]'h_bnd_slot_new
            = (↑(h_s4_len (s4.set i4 a1)).data : List (Std.Array U16 256#usize))[sOffset params + j]'h_bnd_off_new :=
        getElem_congr_idx (by omega)
      have h_pk_idx :
          (↑pk_mlkem_key.data : List (Std.Array U16 256#usize))[sOffset params + j]'h_bnd_off_pk
            = (↑pk_mlkem_key.data : List (Std.Array U16 256#usize))[slot]'h_bnd_slot_pk :=
        getElem_congr_idx (by omega)
      have h_chain :
          (↑(h_s4_len (s4.set i4 a1)).data : List (Std.Array U16 256#usize))[sOffset params + j]'h_bnd_off_new
            = (↑pk_mlkem_key.data : List (Std.Array U16 256#usize))[sOffset params + j]'h_bnd_off_pk := by
        have h_dm' := h_dm
        rw [h_dm']
        simp only [h_val, List.getElem_set_ne h_j_ne, h_se]
      have h_frame_eq :
          (↑pk_mlkem_key.data : List (Std.Array U16 256#usize))[slot]'h_bnd_slot_pk
            = (↑orig_key.data : List (Std.Array U16 256#usize))[slot]'h_bnd_slot_orig :=
        h_frame slot h_slot (fun ⟨h1, h2⟩ => by omega)
      show (↑(h_s4_len (s4.set i4 a1)).data : List (Std.Array U16 256#usize))[slot]'h_bnd_slot_new
              = (↑orig_key.data : List (Std.Array U16 256#usize))[slot]'h_bnd_slot_orig
      rw [h_lhs_idx, h_chain, h_pk_idx, h_frame_eq]
    · -- slot is outside the s-block; chain h_data_frame with h_frame
      have h_d := h_data_frame slot h_slot24 h_in
      have h_f : (↑pk_mlkem_key.data : List (Std.Array U16 256#usize))[slot]
                   = (↑orig_key.data : List (Std.Array U16 256#usize))[slot] :=
        h_frame slot h_slot (fun ⟨h1, h2⟩ => by
          apply h_in
          refine ⟨h1, ?_⟩
          omega)
      rw [h_d, h_f]

/-! The `#decompose` declarations and `_loop0_match.fold` equation above
are consumed inside `mlkem.key_expand_from_private_seed_loop0.spec`'s
proof via the canonical Variant B pattern (see `proof-patterns` skill):
the loop dispatch and per-slot body step are inlined there, so no
standalone `@[step]` spec is needed for `_match`. -/

/-- **Loop spec** for loop 0.

Starting from `pk_mlkem_key` with the s-slots untouched (invariant at
`i = iter.start`), the loop runs until `iter.end = k params`, leaving
each `s` slot `j ∈ [iter.start, k params)` set to the CBD sample.

Informal proof. Canonical recursive Range-U8 loop (`proof-patterns`
"Loop — Canonical Template", Variant B). No separate
`_loop0_match.spec` is needed: the match dispatch is inlined.

- **Mandatory first step**: `rw [key_expand_from_private_seed_loop0.fold]`.
  (Do NOT use `unfold`.) After the `(next iter)` step is consumed, `rw
  [key_expand_from_private_seed_loop0_match.fold]` to expose the
  `_body` call.
- `step` to consume `next iter` (Range-U8 → `o, iter1`).
- `cases o`:
  - **`none` arm** (`iter.start = k params`): `_match`'s `none` body
    returns the current tuple unchanged; the post is `h_inv` at
    `iter.start.val = k params`; `agrind`.
  - **`some i` arm**: `i.val = iter.start.val`, `iter1.start.val =
    i.val + 1`; `step with key_expand_from_private_seed_loop0_body.spec`
    (discharging `h_i`, `h_n_eta1`, `h_inv`); body post advances
    `cbdLoopInv` by one s-slot; `step*` closes the recursive call via
    the IH at `iter1`.
- `termination_by iter.«end».val - iter.start.val`; `decreasing_by agrind`.
Close by `agrind`. -/
@[step]
theorem mlkem.key_expand_from_private_seed_loop0.spec
    (params : ParameterSet) (σ : 𝔹 32)
    (iter : core.ops.range.Range U8)
    (orig_key pk_mlkem_key : mlkem.key.Key)
    (mkhs mkhs1 : mlkem.hash.MlKemHashState)
    (cbd_sample_buffer : Array U8 193#usize) (n_eta1 : U8)
    (g_base : sha3.sha3_impl.GhostState)
    (h_inv : cbdLoopInv params σ orig_key pk_mlkem_key 0
              (sOffset params)
              (by unfold sOffset dataEnd matrixLen; grind)
              iter.start.val mkhs g_base)
    (h_iter_end : iter.«end».val = (k params : ℕ))
    (h_iter_start : iter.start.val ≤ (k params : ℕ))
    (h_n_eta1 : n_eta1.val = (η₁ params : ℕ)) :
    mlkem.key_expand_from_private_seed_loop0 iter pk_mlkem_key mkhs mkhs1
        cbd_sample_buffer n_eta1
      ⦃ key' _mkhs' _buf' =>
          cbdLoopInv params σ orig_key key' 0
            (sOffset params)
            (by unfold sOffset dataEnd matrixLen; grind)
            (k params : ℕ) mkhs g_base ⦄ := by
  rw [key_expand_from_private_seed_loop0.fold]
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨o, iter1, ho, hstart1, hend1⟩ ← IteratorRange_U8_next_some
    rw [ho]
    rw [key_expand_from_private_seed_loop0_match.fold]
    have h_i_lt : iter.start.val < (k params : ℕ) := by rw [← h_iter_end]; exact hlt
    step with key_expand_from_private_seed_loop0_body.spec params σ iter.start orig_key
      pk_mlkem_key mkhs cbd_sample_buffer n_eta1 g_base h_inv h_i_lt h_n_eta1
      as ⟨mkhs4, cbd_buf2, new_key, h_body_post⟩
    have hx_le : iter1.start.val ≤ (k params : ℕ) := by rw [hstart1, ← h_iter_end]; omega
    have h_inv' : cbdLoopInv params σ orig_key new_key 0 (sOffset params)
        (by unfold sOffset dataEnd matrixLen; grind) iter1.start.val mkhs g_base := by
      rw [hstart1]; exact h_body_post
    apply mlkem.key_expand_from_private_seed_loop0.spec
      params σ iter1 orig_key new_key mkhs mkhs4 cbd_buf2 n_eta1 g_base
      h_inv' (by rw [hend1]; exact h_iter_end) hx_le h_n_eta1
  · let* ⟨o, iter1, ho, hiter1⟩ ← IteratorRange_U8_next_none
    rw [ho]
    have h_eq : iter.start.val = (k params : ℕ) := by
      rw [h_iter_end] at hlt; omega
    rw [key_expand_from_private_seed_loop0_match.fold]
    simp only [WP.spec_ok]
    rw [h_eq] at h_inv; exact h_inv
termination_by iter.«end».val - iter.start.val
decreasing_by
  rw [hstart1]
  scalar_tac

/-! ## Loop 1 (`e` sampling, written into `t`) -/

#decompose mlkem.key_expand_from_private_seed_loop1
    key_expand_from_private_seed_loop1.fold
  letRange 1 1 => key_expand_from_private_seed_loop1_match

#decompose key_expand_from_private_seed_loop1_match
    key_expand_from_private_seed_loop1_match.fold
    branch 1 (letRange 0 21) => key_expand_from_private_seed_loop1_body

/-- **Body spec** for loop 1.  Advances `cbdLoopInv` by one t-slot.

Informal proof.  Structurally identical to
`key_expand_from_private_seed_loop0_body.spec`; the differences are:
* `offset = k params` (so the PRF index byte is
  `(k params + i.val : Byte)`; computed by an additional cast of
  `n_rows` to `Usize` and an addition step using
  `h_n_rows : n_rows.val = k params`).
* Target slot is `tOffset params + i.val` instead of
  `sOffset params + i.val`.
Steps (1)–(6) from loop0_body apply with these substitutions:
(1) `step` with `MlKemHashState.clone.spec`.
(2) Cast `n_rows + i` and append via `step` with
`MlKemHashState.append.spec`: worker advances to
`g_base ++ [(k params + i.val : Byte)]`.
(3) Arithmetic steps for `n_bytes = 64 * η₁ params`.
(4) `step` with `MlKemHashState.extract.spec` (wipe = true): gives
`PRF η₁ σ ((k params + i.val) : Byte)`.
(5) `step` with `SamplePolyCBD.spec`.
(6) Mut-accessor write into `key.data[tOffset params + i.val]`.
Residual: rebuild `cbdLoopInv` at `offset = k params`,
`dstStart = tOffset params`, `i.val + 1`; close by `agrind`. -/
@[step]
theorem key_expand_from_private_seed_loop1_body.spec
    (params : ParameterSet) (σ : 𝔹 32)
    (i : U8) (orig_key pk_mlkem_key : mlkem.key.Key)
    (mkhs : mlkem.hash.MlKemHashState)
    (cbd_sample_buffer : Array U8 193#usize)
    (n_rows n_eta1 : U8)
    (g_base : sha3.sha3_impl.GhostState)
    (h_inv : cbdLoopInv params σ orig_key pk_mlkem_key (k params : ℕ)
              (tOffset params)
              (by unfold tOffset dataEnd matrixLen; grind)
              i.val mkhs g_base)
    (h_i : i.val < (k params : ℕ))
    (h_n_rows : n_rows.val = (k params : ℕ))
    (h_n_eta1 : n_eta1.val = (η₁ params : ℕ)) :
    key_expand_from_private_seed_loop1_body pk_mlkem_key mkhs
        cbd_sample_buffer n_rows n_eta1 i
      ⦃ _mkhs' _buf' key' =>
          cbdLoopInv params σ orig_key key' (k params : ℕ)
            (tOffset params)
            (by unfold tOffset dataEnd matrixLen; grind)
            (i.val + 1) mkhs g_base ⦄ := by
  unfold key_expand_from_private_seed_loop1_body
  obtain ⟨h_wf, h_i_le, h_abs, h_g_abs, h_alg_eq, h_cbd, h_frame,
    h_params, h_nrows, h_pubseed, h_enct, h_kh, h_hpsd, h_hpkey, h_psd, h_prnd⟩ := h_inv
  -- Extra prefix: n_rows + i → i_byte (the PRF index byte for loop 1).
  have h_k_le : (k params : ℕ) ≤ 4 := by rcases params <;> decide
  step -- i1 ← n_rows + i (precondition: ≤ U8.max)
  step -- index_mut at 0 of cbd_sample_buffer
  step as ⟨mkhs2, h_mkhs2⟩
  subst h_mkhs2
  step
  step
  step
  step as ⟨s, h_s_val, h_s_len⟩
  step with mlkem.hash.MlKemHashState.append.spec _ s g_base (Or.inl h_abs)
    as ⟨mkhs3, h_mkhs3_alg, h_mkhs3_abs⟩
  have h_n_eta1_le : n_eta1.val ≤ 3 := by
    rcases params <;> rw [h_n_eta1] <;> decide
  step
  step
  step
  step with mlkem.hash.MlKemHashState.extract.spec _ _ _ _
    (Or.inl h_mkhs3_abs) (Or.inr (h_mkhs3_alg.trans h_alg_eq))
    as ⟨mkhs4, s2, h_mkhs4_alg, h_s2_len, h_s2_val, h_mkhs4_post⟩
  step
  step
  step with mlkem.key.Key.t_mut.spec _ params h_wf
    as ⟨s4, h_s4_len, t_mut_back, h_s4_wf, h_s4_eq, h_t_mut_back⟩
  step
  step
  have h_i4_eta : i4.val = 2 ∨ i4.val = 3 := by
    have h_i4_n : i4.val = n_eta1.val := by simp [i4_post]
    rw [h_i4_n, h_n_eta1]
    rcases params <;> decide
  have h_s3_len : s3.length = 64 * 3 + 1 := by
    have h_idx_len : (↑(cbd_sample_buffer1) : List U8).length = 193 := by simp
    have h_s3_eq : (↑s3 : List U8) =
        (↑(cbd_sample_buffer1) : List U8).setSlice! 0 s2.val := by
      rw [s3_post]; simp only [Std.Array.to_slice]; exact s1_post3 s2
    show (↑s3 : List U8).length = 64 * 3 + 1
    rw [h_s3_eq, List.length_setSlice!, h_idx_len]
  step with mlkem.ntt.poly_element_sample_cbd_from_bytes.spec _ _ _
    h_i4_eta h_s3_len
    as ⟨a1, h_a1_wf, h_a1_eq⟩
  obtain ⟨h_a_eq, h_imb2_eq⟩ : a = (s4.val)[i5.val]! ∧ index_mut_back1 = s4.set i5 := by grind
  subst h_imb2_eq
  have hs'_len : (s4.set i5 a1).length = (k params : ℕ) := by
    simp [Slice.set]; exact t_mut_back
  have hs'_wf : ∀ j (_ : j < (s4.set i5 a1).length), wfPoly (↑(s4.set i5 a1))[j] := by
    intro j hj
    have hj4 : j < s4.length := by simpa [Slice.set, Slice.setAtNat] using hj
    have h_val : (↑(s4.set i5 a1) : List _) = (↑s4 : List _).set i5.val a1 := by
      simp [Slice.set, Slice.setAtNat]
    have hbound : j < ((↑s4 : List _).set i5.val a1).length := by simp; exact hj4
    have heq : (↑(s4.set i5 a1) : List _)[j]'hj
        = ((↑s4 : List _).set i5.val a1)[j]'hbound := by
      apply Eq.symm; apply List.getElem_of_eq h_val.symm
    show wfPoly (↑(s4.set i5 a1) : List _)[j]
    rw [heq, List.getElem_set]
    split
    · exact h_a1_wf
    · exact h_s4_wf j hj4
  obtain ⟨⟨h_wf', h_params', h_nrows', h_hpsd', h_psd', h_prnd'⟩,
    h_ai', h_hpkey', h_pubseed', h_enct', h_kh',
    h_dlen', h_data_match, h_data_frame⟩ :=
    h_t_mut_back (s4.set i5 a1) hs'_len hs'_wf
  unfold cbdLoopInv
  refine ⟨h_wf', by agrind, h_abs, h_g_abs, h_alg_eq,
          ?cbd_new, ?frame_new,
          h_params'.trans h_params, h_nrows'.trans h_nrows,
          h_pubseed'.trans h_pubseed, h_enct'.trans h_enct,
          h_kh'.trans h_kh, h_hpsd'.trans h_hpsd, h_hpkey'.trans h_hpkey,
          h_psd'.trans h_psd, h_prnd'.trans h_prnd⟩
  case cbd_new =>
    intro j h_j h_j_lt
    by_cases hji : j < i.val
    · -- Existing slot: use h_cbd + h_data_match + h_data_frame chain.
      have h_old := h_cbd j h_j hji
      have h_j_lt_k : j < (k params : ℕ) := h_j
      have h_j_ne : i5.val ≠ j := by simp [i5_post]; omega
      have h_dm := h_data_match j h_j_lt_k
      have h_se := h_s4_eq j h_j_lt_k
      have h_val : (↑(s4.set i5 a1) : List _) = (↑s4 : List _).set i5.val a1 := by
        simp [Slice.set, Slice.setAtNat]
      have h_pkey_len : (↑pk_mlkem_key.data : List (Std.Array U16 256#usize)).length = 24 := by
        have := pk_mlkem_key.data.property; simp
      have h_ksq := k_sq_plus_2k_le_24 params
      have h_offset_j : tOffset params + j < 24 := by
        unfold tOffset matrixLen
        have : (k params : ℕ) * (k params : ℕ) ≤ 4 * 4 :=
          Nat.mul_le_mul h_k_le h_k_le
        omega
      have h_bnd_pkey : tOffset params + j
            < (↑pk_mlkem_key.data : List (Std.Array U16 256#usize)).length := by
        rw [h_pkey_len]; exact h_offset_j
      have h_bnd_new : tOffset params + j
            < (↑(h_s4_len (s4.set i5 a1)).data : List (Std.Array U16 256#usize)).length := by
        rw [h_dlen']; exact h_offset_j
      have h_old_eq :
        (↑pk_mlkem_key.data : List (Std.Array U16 256#usize))[tOffset params + j]'h_bnd_pkey
          = (↑(h_s4_len (s4.set i5 a1)).data : List (Std.Array U16 256#usize))[tOffset params + j]'h_bnd_new := by
        rw [h_dm]
        simp only [h_val, List.getElem_set_ne h_j_ne, ← h_se]
      show cbdPolyMatches ((↑(h_s4_len (s4.set i5 a1)).data : List (Std.Array U16 256#usize))[tOffset params + j]'h_bnd_new) _
      rw [← h_old_eq]
      exact h_old
    · -- New slot: j = i.val.
      have hji' : j = i.val := by omega
      -- Mirror of loop0_body cbd_new (L305+); differences:
      --   * write byte is i1 = n_rows + i = (k params + i.val : U8), not i;
      --   * variable rename i3↦i4, i4↦i5, i1↦i2, i2↦i3;
      --   * PRF byte arg is ((k params) + j : ℕ), discharged via i1.
      have h_val : (↑(s4.set i5 a1) : List _) = (↑s4 : List _).set i5.val a1 := by
        simp [Slice.set, Slice.setAtNat]
      have h_i5_val : i5.val = i.val := by simp [i5_post]
      have h_j_lt_k : j < (k params : ℕ) := h_j
      have h_dm := h_data_match j h_j_lt_k
      have h_pkey_len : (↑pk_mlkem_key.data : List (Std.Array U16 256#usize)).length = 24 := by
        have := pk_mlkem_key.data.property; simp
      have h_ksq := k_sq_plus_2k_le_24 params
      have h_offset_j : tOffset params + j < 24 := by
        unfold tOffset matrixLen
        have : (k params : ℕ) * (k params : ℕ) ≤ 4 * 4 :=
          Nat.mul_le_mul h_k_le h_k_le
        omega
      have h_bnd_new : tOffset params + j < (↑(h_s4_len (s4.set i5 a1)).data : List (Std.Array U16 256#usize)).length := by
        rw [h_dlen']; exact h_offset_j
      have h_s4_len_eq : s4.val.length = (k params : ℕ) := t_mut_back
      have h_set_len : (↑(s4.set i5 a1) : List (Std.Array U16 256#usize)).length = (k params : ℕ) := by
        rw [h_val]; simp [h_s4_len_eq]
      have h_j_set_bnd : j < (↑(s4.set i5 a1) : List (Std.Array U16 256#usize)).length := by
        rw [h_set_len]; exact h_j_lt_k
      have h_slot_a1 : (↑(s4.set i5 a1) : List (Std.Array U16 256#usize))[j]'h_j_set_bnd = a1 := by
        simp [Slice.set, Slice.setAtNat, h_i5_val, hji']
      have h_chain : (↑(h_s4_len (s4.set i5 a1)).data : List _)[tOffset params + j]'h_bnd_new = a1 := by
        rw [h_dm]
        exact h_slot_a1
      show cbdPolyMatches ((↑(h_s4_len (s4.set i5 a1)).data : List (Std.Array U16 256#usize))[tOffset params + j]'h_bnd_new) _
      rw [h_chain]
      refine ⟨h_a1_wf, ?_⟩
      -- Discharge the toPoly equality via Bridge 5.
      rw [h_a1_eq]
      have h_i1_val : i1.val = (k params : ℕ) + j := by
        rw [i1_post, h_n_rows, hji']
      have h_offset_kj : ((↑(k params) + j : ℕ) : Byte) = (i1.bv : Byte) := by
        have : ((i1.val : ℕ) : Byte) = (i1.bv : Byte) := by
          simp [Byte]
        rw [← h_i1_val]
        exact this
      rw [h_offset_kj]
      have h_sm : mkhs2.state.squeeze_mode = false := by
        unfold mlkem.hash.MlKemHashState.absorbing at h_abs
        have h_weak : sha3.sha3_impl.absorbingWeak mkhs2.state g_base := h_abs.1.1
        simpa using h_weak.2.1
      have h_cbd_eta_val :
          (cbdEta i4 h_i4_eta : ℕ) = (η₁ params : ℕ) := by
        simp only [cbdEta]
        have : i4.val = n_eta1.val := by simp [i4_post]
        rw [this, h_n_eta1]
      apply prf_shake_samplePolyCBD_bridge_of_absorbing
        (cbdEta i4 h_i4_eta) (η₁ params) h_cbd_eta_val
        σ i1 mkhs2 g_base h_abs h_alg_eq h_g_abs
        mkhs2.state.squeeze_mode h_sm s3
      -- h_s3_extract: per-byte equality.
      intro k hk
      have h_kk : k < 64 * (cbdEta i4 h_i4_eta : ℕ) := hk
      have h_s_eq : s.val = [i1] := by
        have h1 : (↑(cbd_sample_buffer1) : List U8) =
            (↑cbd_sample_buffer : List U8).set 0 i1 := by
          simp [cbd_sample_buffer1_post]
        rw [h_s_val]
        simp only [Std.Array.to_slice]
        rw [h1]
        have hlen : 1 ≤ (↑cbd_sample_buffer : List U8).length := by simp
        rcases hcb : (↑cbd_sample_buffer : List U8) with _ | ⟨x, xs⟩
        · simp [hcb] at hlen
        · simp [List.slice, List.set]
      have h_i3_eq : i3.val = 64 * (cbdEta i4 h_i4_eta : ℕ) := by
        have h_i2_eq : i2.val = n_eta1.val := by simp [i2_post]
        rw [i3_post, h_i2_eq, h_n_eta1, ← h_cbd_eta_val]
      have h_s1_len_eq : s1.length = 64 * (cbdEta i4 h_i4_eta : ℕ) := by
        have := s1_post2; omega
      have h_s2_val_len : s2.val.length = 64 * (cbdEta i4 h_i4_eta : ℕ) := by
        rw [show s2.val.length = s2.length from rfl, h_s2_len, h_s1_len_eq]
      have h_idx_len : (↑(cbd_sample_buffer1) : List U8).length = 193 := by simp
      have h_s3_val_eq : (↑s3 : List U8) =
          (↑(cbd_sample_buffer1) : List U8).setSlice! 0 s2.val := by
        rw [s3_post]
        simp only [Std.Array.to_slice]
        exact s1_post3 s2
      have hk_s2 : k < s2.val.length := by rw [h_s2_val_len]; exact h_kk
      have h_mid :
          ((↑(cbd_sample_buffer1) : List U8).setSlice! 0 (↑s2 : List U8))[k]'
              (by rw [List.length_setSlice!, h_idx_len]; omega)
            = (↑s2 : List U8)[k]'hk_s2 :=
        List.getElem_setSlice!_middle (↑(cbd_sample_buffer1) : List U8) (↑s2 : List U8) 0 k
          ⟨by omega, by simpa using hk_s2, by rw [h_idx_len]; omega⟩
      have h_ext_len :
          (sha3.sha3_impl.extractOutput
              (g_base.append (↑s) mkhs2.state.squeeze_mode) s1.length).toList.length
            = 64 * (cbdEta i4 h_i4_eta : ℕ) := by
        rw [Vector.toList_length, h_s1_len_eq]
      have h_args_eq :
          (sha3.sha3_impl.extractOutput
              (g_base.append (↑s) mkhs2.state.squeeze_mode) s1.length).toList
            = (sha3.sha3_impl.extractOutput
                (g_base.append [i1] mkhs2.state.squeeze_mode)
                (64 * (cbdEta i4 h_i4_eta : ℕ))).toList := by
        rw [h_s_eq, h_s1_len_eq]
      calc (↑s3 : List U8)[k]
          = ((↑(cbd_sample_buffer1) : List U8).setSlice! 0 (↑s2 : List U8))[k]'
              (by rw [List.length_setSlice!, h_idx_len]; omega) := by
                  fcongr 1
        _ = (↑s2 : List U8)[k]'hk_s2 := h_mid
        _ = (sha3.sha3_impl.extractOutput
              (g_base.append (↑s) mkhs2.state.squeeze_mode) s1.length).toList[k]'
              (by
                rw [h_ext_len]; exact h_kk) := by
                rw [List.getElem_of_eq h_s2_val]
        _ = (sha3.sha3_impl.extractOutput
              (g_base.append [i1] mkhs2.state.squeeze_mode)
              (64 * (cbdEta i4 h_i4_eta : ℕ))).toList[k] := by
                grind
  case frame_new =>
    intro slot h_slot h_out
    have h_ksq : (k params : ℕ) * (k params : ℕ) + 2 * (k params : ℕ) ≤ 24 :=
      k_sq_plus_2k_le_24 params
    have h_slot24 : slot < 24 := by
      have : slot < dataEnd params := h_slot
      unfold dataEnd matrixLen at this
      omega
    by_cases h_in : tOffset params ≤ slot ∧ slot < tOffset params + (k params : ℕ)
    · -- slot is in the t-block; must be ≥ tOffset + i.val + 1
      obtain ⟨h_ge, h_lt⟩ := h_in
      set j := slot - tOffset params with hj_def
      have h_j_k : j < (k params : ℕ) := by omega
      have h_j_lo : i.val + 1 ≤ j := by
        by_contra h_neg
        apply h_out
        refine ⟨h_ge, ?_⟩
        omega
      have h_j_ne : i5.val ≠ j := by simp [i5_post]; omega
      have h_slot_eq : tOffset params + j = slot := by omega
      have h_dm := h_data_match j h_j_k
      have h_se := h_s4_eq j h_j_k
      have h_val : (↑(s4.set i5 a1) : List _) = (↑s4 : List _).set i5.val a1 := by
        simp [Slice.set, Slice.setAtNat]
      have h_dlen_pk : (↑pk_mlkem_key.data : List (Std.Array U16 256#usize)).length = 24 := by
        have := pk_mlkem_key.data.property; simp
      have h_dlen_ok : (↑orig_key.data : List (Std.Array U16 256#usize)).length = 24 := by
        have := orig_key.data.property; simp
      have h_bnd_slot_new :
          slot < (↑(h_s4_len (s4.set i5 a1)).data : List (Std.Array U16 256#usize)).length := by
        rw [h_dlen']; exact h_slot24
      have h_bnd_off_new :
          tOffset params + j
            < (↑(h_s4_len (s4.set i5 a1)).data : List (Std.Array U16 256#usize)).length := by
        rw [h_dlen']; omega
      have h_bnd_slot_pk :
          slot < (↑pk_mlkem_key.data : List (Std.Array U16 256#usize)).length := by
        rw [h_dlen_pk]; exact h_slot24
      have h_bnd_off_pk :
          tOffset params + j
            < (↑pk_mlkem_key.data : List (Std.Array U16 256#usize)).length := by
        rw [h_dlen_pk]; omega
      have h_bnd_slot_orig :
          slot < (↑orig_key.data : List (Std.Array U16 256#usize)).length := by
        rw [h_dlen_ok]; exact h_slot24
      have h_lhs_idx :
          (↑(h_s4_len (s4.set i5 a1)).data : List (Std.Array U16 256#usize))[slot]'h_bnd_slot_new
            = (↑(h_s4_len (s4.set i5 a1)).data : List (Std.Array U16 256#usize))[tOffset params + j]'h_bnd_off_new :=
        getElem_congr_idx (by omega)
      have h_pk_idx :
          (↑pk_mlkem_key.data : List (Std.Array U16 256#usize))[tOffset params + j]'h_bnd_off_pk
            = (↑pk_mlkem_key.data : List (Std.Array U16 256#usize))[slot]'h_bnd_slot_pk :=
        getElem_congr_idx (by omega)
      have h_chain :
          (↑(h_s4_len (s4.set i5 a1)).data : List (Std.Array U16 256#usize))[tOffset params + j]'h_bnd_off_new
            = (↑pk_mlkem_key.data : List (Std.Array U16 256#usize))[tOffset params + j]'h_bnd_off_pk := by
        rw [h_dm]
        simp only [h_val, List.getElem_set_ne h_j_ne, h_se]
      have h_frame_eq :
          (↑pk_mlkem_key.data : List (Std.Array U16 256#usize))[slot]'h_bnd_slot_pk
            = (↑orig_key.data : List (Std.Array U16 256#usize))[slot]'h_bnd_slot_orig :=
        h_frame slot h_slot (fun ⟨h1, h2⟩ => by omega)
      show (↑(h_s4_len (s4.set i5 a1)).data : List (Std.Array U16 256#usize))[slot]'h_bnd_slot_new
              = (↑orig_key.data : List (Std.Array U16 256#usize))[slot]'h_bnd_slot_orig
      rw [h_lhs_idx, h_chain, h_pk_idx, h_frame_eq]
    · -- slot is outside the t-block; chain h_data_frame with h_frame
      have h_d := h_data_frame slot h_slot24 h_in
      have h_f : (↑pk_mlkem_key.data : List (Std.Array U16 256#usize))[slot]
                   = (↑orig_key.data : List (Std.Array U16 256#usize))[slot] :=
        h_frame slot h_slot (fun ⟨h1, h2⟩ => by
          apply h_in
          refine ⟨h1, ?_⟩
          omega)
      rw [h_d, h_f]

/-! The `#decompose` declarations and `_loop1_match.fold` equation above
are consumed inside `mlkem.key_expand_from_private_seed_loop1.spec`'s
proof via the canonical Variant B pattern (see `proof-patterns` skill):
the loop dispatch and per-slot body step are inlined there, so no
standalone `@[step]` spec is needed for `_match`. -/

/-- **Loop spec** for loop 1: drives the e-sampling loop from
`iter.start` to `k params`, populating t-slots with
`SamplePolyCBD(PRF η₁ σ (k params + j).byte)` for
`j ∈ [iter.start, k params)`.

Informal proof. Canonical recursive Range-U8 loop (`proof-patterns`
"Loop — Canonical Template", Variant B); mirror of `_loop0.spec` with
`offset = k params` and `dstStart = tOffset params`. No separate
`_loop1_match.spec` is needed: the dispatch is inlined.

- **Mandatory first step**: `rw [key_expand_from_private_seed_loop1.fold]`.
  (Do NOT use `unfold`.) After the `(next
  iter)` step is consumed, `rw [key_expand_from_private_seed_loop1_match.fold]`
  to expose the `_body` call.
- `step` to consume `next iter`; `cases o`:
  - **`none` arm** (`iter.start = k params`): post is `h_inv` at
    `iter.start.val = k params`; `agrind`.
  - **`some i` arm**: `step with key_expand_from_private_seed_loop1_body.spec`
    (discharging `h_i`, `h_n_rows`, `h_n_eta1`, `h_inv`); body post
    advances `cbdLoopInv` by one t-slot; `step*` closes the recursive
    call via the IH at `iter1`.
- `termination_by iter.«end».val - iter.start.val`; `decreasing_by agrind`.
Close by `agrind`. -/
@[step]
theorem mlkem.key_expand_from_private_seed_loop1.spec
    (params : ParameterSet) (σ : 𝔹 32)
    (iter : core.ops.range.Range U8)
    (orig_key pk_mlkem_key : mlkem.key.Key)
    (mkhs mkhs1 : mlkem.hash.MlKemHashState)
    (cbd_sample_buffer : Array U8 193#usize)
    (n_rows n_eta1 : U8)
    (g_base : sha3.sha3_impl.GhostState)
    (h_inv : cbdLoopInv params σ orig_key pk_mlkem_key (k params : ℕ)
              (tOffset params)
              (by unfold tOffset dataEnd matrixLen; grind)
              iter.start.val mkhs g_base)
    (h_iter_end : iter.«end».val = (k params : ℕ))
    (h_iter_start : iter.start.val ≤ (k params : ℕ))
    (h_n_rows : n_rows.val = (k params : ℕ))
    (h_n_eta1 : n_eta1.val = (η₁ params : ℕ)) :
    mlkem.key_expand_from_private_seed_loop1 iter pk_mlkem_key mkhs mkhs1
        cbd_sample_buffer n_rows n_eta1
      ⦃ key' _mkhs' _buf' =>
          cbdLoopInv params σ orig_key key' (k params : ℕ)
            (tOffset params)
            (by unfold tOffset dataEnd matrixLen; grind)
            (k params : ℕ) mkhs g_base ⦄ := by
  rw [key_expand_from_private_seed_loop1.fold]
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨o, iter1, ho, hstart1, hend1⟩ ← IteratorRange_U8_next_some
    rw [ho]
    rw [key_expand_from_private_seed_loop1_match.fold]
    have h_i_lt : iter.start.val < (k params : ℕ) := by rw [← h_iter_end]; exact hlt
    step with key_expand_from_private_seed_loop1_body.spec params σ iter.start orig_key
      pk_mlkem_key mkhs cbd_sample_buffer n_rows n_eta1 g_base h_inv h_i_lt h_n_rows h_n_eta1
      as ⟨mkhs4, cbd_buf2, new_key, h_body_post⟩
    have hx_le : iter1.start.val ≤ (k params : ℕ) := by rw [hstart1, ← h_iter_end]; omega
    have h_inv' : cbdLoopInv params σ orig_key new_key (k params : ℕ) (tOffset params)
        (by unfold tOffset dataEnd matrixLen; grind) iter1.start.val mkhs g_base := by
      rw [hstart1]; exact h_body_post
    apply mlkem.key_expand_from_private_seed_loop1.spec
      params σ iter1 orig_key new_key mkhs mkhs4 cbd_buf2 n_rows n_eta1 g_base
      h_inv' (by rw [hend1]; exact h_iter_end) hx_le h_n_rows h_n_eta1
  · let* ⟨o, iter1, ho, hiter1⟩ ← IteratorRange_U8_next_none
    rw [ho]
    have h_eq : iter.start.val = (k params : ℕ) := by
      rw [h_iter_end] at hlt; omega
    rw [key_expand_from_private_seed_loop1_match.fold]
    simp only [WP.spec_ok]
    rw [h_eq] at h_inv
    simp [WP.uncurry']
    grind
termination_by iter.«end».val - iter.start.val
decreasing_by grind


end Symcrust.Properties.MLKEM
