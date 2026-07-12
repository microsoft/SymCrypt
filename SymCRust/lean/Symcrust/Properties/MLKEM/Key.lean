/-
  # Key.lean — `mlkem.key_expand_from_private_seed.spec` (main theorem).

  This file proves the top-level `@[step]` spec for
  `mlkem.key_expand_from_private_seed`.  The two loops and the prelude
  (Phases 1..9, including `cbdLoopInv`, the loop specs, the
  `Inv1..Inv4` post-state invariants, and `keyExpand.prelude.spec`) live
  in:
    * `Symcrust.Properties.MLKEM.Key.Loops`   — CBD loops 0/1
    * `Symcrust.Properties.MLKEM.Key.Prelude` — invariants + prelude.spec

  This file owns Phases 10..23:
    * residual D helpers (`key_expand_residual_D_helper_t1_eq`,
      `_s19_eq`, `_Â_impl`, `_helper`),
    * D1 byte-chain helper (`key_expand_residual_D1_helper`),
    * the main `mlkem.key_expand_from_private_seed.spec` theorem.

  See the FIPS 203 algorithm description and post-state field map in
  `Key/Prelude.lean`'s header.
-/
import Symcrust.Properties.MLKEM.Key.Prelude

open Aeneas Aeneas.Std Result
open scoped Spec.Notations
open Spec
open Spec.MLKEM
open symcrust

namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 8000000
set_option maxRecDepth 4096


/-- D2-A sub-helper: bridges the impl `t1` window to the spec `e_spec` via
`h_b1_t_conj` (the rebuilt CBD-invariant on the back-key data) and `h_e_spec`
(KPKE_t_hat_explicit's e_spec characterisation).

Hoisted from `key_expand_residual_D_helper`; its own elaboration unit keeps
the body within the per-declaration heartbeat budget. -/
private theorem mlkem.key_expand_residual_D_helper_t1_eq
    (params : ParameterSet)
    (d_bytes : 𝔹 32)
    {t1 s18 : Aeneas.Std.Slice PolyElement}
    {s_mut_back1 : Aeneas.Std.Slice PolyElement → mlkem.key.Key}
    (_h_b1_dlen : (s_mut_back1 s18).data.val.length = 24)
    (h_t1_len_val : t1.val.length = (k params : ℕ))
    (a1_post8 : t1.val =
      ((s_mut_back1 s18).data.val.drop (matrixLen params)).take (k params : ℕ))
    (h_in_data : ∀ (i : ℕ), i < (k params : ℕ) →
        matrixLen params + i < (s_mut_back1 s18).data.val.length)
    (h_b1_t_conj : ∀ (i : ℕ) (h_i : i < (k params : ℕ)),
        toPoly ((s_mut_back1 s18).data.val[matrixLen params + i]'(h_in_data i h_i)) =
        MLKEM.NTT (MLKEM.SamplePolyCBD
          (MLKEM.PRF (η₁ params)
            (MLKEM.G (d_bytes ‖ #v[((k params : ℕ) : Byte)])).2
            ((k params + i) : Byte))))
    (e_spec : MLKEM.PolyVector q (k params))
    (h_e_spec : ∀ (i : ℕ) (_ : i < k params),
        e_spec[i] = MLKEM.SamplePolyCBD
          (MLKEM.PRF (η₁ params)
            (MLKEM.G (d_bytes ‖ #v[((k params : ℕ) : Byte)])).2
            ((((k params : ℕ) + i) : ℕ) : Byte))) :
    toPolyVecOfLen t1 (k params) h_t1_len_val = MLKEM.PolyVector.NTT e_spec := by
  apply Vector.ext
  intro i hi
  simp only [toPolyVecOfLen, MLKEM.PolyVector.NTT, Vector.getElem_ofFn,
             Vector.getElem_map]
  have h_t1_to_data :
      t1.val[i]'(by rw [h_t1_len_val]; exact hi) =
      (s_mut_back1 s18).data.val[matrixLen params + i]'(h_in_data i hi) := by
    simp only [a1_post8, List.getElem_take, List.getElem_drop]
  rw [h_t1_to_data, h_b1_t_conj i hi, h_e_spec i hi]
  push_cast
  ring_nf

/-- D2-B sub-helper: bridges the impl `s19` window to `(PolyVector.NTT s_spec).map (R·)`
via the chain `s19 → array-prefix → pv_tmp1 → s18`, then NTT s_spec via `h_s_spec`. -/
private theorem mlkem.key_expand_residual_D_helper_s19_eq
    (params : ParameterSet)
    (d_bytes : 𝔹 32)
    {pv_tmp1 s18 s19 : Aeneas.Std.Slice PolyElement}
    {i9 : Aeneas.Std.Usize}
    {_index_mut_back1 : Aeneas.Std.Slice PolyElement →
      Aeneas.Std.Array PolyElement 4#usize}
    (h_pv1_len : pv_tmp1.val.length = (k params : ℕ))
    (h_s18_len : s18.val.length = (k params : ℕ))
    (h_arr_len : (_index_mut_back1 pv_tmp1).to_slice.val.length = 4)
    (h_s19_len_val : s19.length = (k params : ℕ))
    (s19_post1 : s19.val = (_index_mut_back1 pv_tmp1).to_slice.val.slice 0 i9.val)
    (h_i9_val : (i9 : ℕ) = (k params : ℕ))
    (h_arr_prefix : ∀ (i : ℕ) (_h_i : i < (k params : ℕ)),
        (_index_mut_back1 pv_tmp1).to_slice.val[i]'(by
          rw [h_arr_len]; have := k_le_4 params; omega) =
        pv_tmp1.val[i]'(by rw [h_pv1_len]; exact _h_i))
    (pv_tmp1_post3 : ∀ (i : ℕ) (h_i : i < s18.val.length),
        toPoly (pv_tmp1.val[i]'(by rw [h_pv1_len]; rw [h_s18_len] at h_i; exact h_i)) =
        (toPoly (s18.val[i]'h_i)).map (R * ·))
    (h_s18_ntt : ∀ (i : ℕ) (h_i : i < (k params : ℕ)),
        toPoly (s18.val[i]'(by rw [h_s18_len]; exact h_i)) =
        MLKEM.NTT (MLKEM.SamplePolyCBD
          (MLKEM.PRF (η₁ params)
            (MLKEM.G (d_bytes ‖ #v[((k params : ℕ) : Byte)])).2
            ((i : ℕ) : Byte))))
    (s_spec : MLKEM.PolyVector q (k params))
    (h_s_spec : ∀ (i : ℕ) (_ : i < k params),
        s_spec[i] = MLKEM.SamplePolyCBD
          (MLKEM.PRF (η₁ params)
            (MLKEM.G (d_bytes ‖ #v[((k params : ℕ) : Byte)])).2
            ((i : ℕ) : Byte))) :
    toPolyVecOfLen s19 (k params) (by
        show s19.val.length = _
        have : s19.val.length = s19.length := rfl
        rw [this, h_s19_len_val]) =
      (MLKEM.PolyVector.NTT s_spec).map (fun p => p.map (R * ·)) := by
  apply Vector.ext
  intro i hi
  simp only [toPolyVecOfLen, MLKEM.PolyVector.NTT, Vector.getElem_ofFn,
             Vector.getElem_map]
  have h_in_s19 : i < s19.val.length := by
    change i < s19.length; rw [h_s19_len_val]; exact hi
  have h_in_arr : i < (_index_mut_back1 pv_tmp1).to_slice.val.length := by
    rw [h_arr_len]; have := k_le_4 params; omega
  have h_in_pv : i < pv_tmp1.val.length := by
    rw [h_pv1_len]; exact hi
  have h_in_s18 : i < s18.val.length := by
    rw [h_s18_len]; exact hi
  have h_s19_to_arr : s19.val[i]'h_in_s19 =
      (_index_mut_back1 pv_tmp1).to_slice.val[i]'h_in_arr := by
    have h_eq_? : s19.val[i]? = (_index_mut_back1 pv_tmp1).to_slice.val[i]? := by
      rw [s19_post1]
      unfold List.slice
      rw [List.getElem?_take, List.getElem?_drop]
      have : i < (i9 : ℕ) := by rw [h_i9_val]; exact hi
      simp [this]
    rw [List.getElem?_eq_getElem h_in_s19,
        List.getElem?_eq_getElem h_in_arr] at h_eq_?
    exact Option.some.inj h_eq_?
  rw [h_s19_to_arr]
  rw [h_arr_prefix i hi]
  rw [pv_tmp1_post3 i h_in_s18]
  rw [h_s18_ntt i hi]
  rw [h_s_spec i hi]

/-- D2-C sub-helper: entry-wise equality `toPolyMatrixOfLen a1 = Â_spec` via the
chain `a1 → impl-data (s_mut_back1 s18) → SampleNTT seed`. -/
private theorem mlkem.key_expand_residual_D_helper_Â_impl
    (params : ParameterSet)
    (d_bytes : 𝔹 32)
    {a1 s18 : Aeneas.Std.Slice PolyElement}
    {s_mut_back1 : Aeneas.Std.Slice PolyElement → mlkem.key.Key}
    (h_b1_dlen : (s_mut_back1 s18).data.val.length = 24)
    (h_a1_len_val : a1.val.length = matrixLen params)
    (a1_post7 : a1.val = (s_mut_back1 s18).data.val.take (matrixLen params))
    (h_b1_mat_conj : ∀ (row col : ℕ)
        (_h_row : row < (k params : ℕ)) (_h_col : col < (k params : ℕ)),
        toPoly ((s_mut_back1 s18).data.val[row * (k params : ℕ) + col]'(by
          rw [h_b1_dlen]
          have h_k4 := k_le_4 params
          have h_sq := k_sq_plus_2k_le_24 params
          have h1 : (row + 1) * (k params : ℕ) ≤ (k params : ℕ) * (k params : ℕ) :=
            Nat.mul_le_mul_right _ _h_row
          have h2 : row * (k params : ℕ) + (k params : ℕ) = (row + 1) * (k params : ℕ) := by
            ring
          omega)) =
        MLKEM.SampleNTT (expandAEntrySeed
          (MLKEM.G (d_bytes ‖ #v[((k params : ℕ) : Byte)])).1 row col))
    (Â_spec : MLKEM.PolyMatrix q (k params))
    (h_Â_spec : ∀ (i j : ℕ) (hi : i < k params) (hj : j < k params),
        Â_spec ⟨i, hi⟩ ⟨j, hj⟩ = MLKEM.SampleNTT
          ((MLKEM.G (d_bytes ‖ #v[((k params : ℕ) : Byte)])).1 ‖
            #v[((j : ℕ) : Byte)] ‖ #v[((i : ℕ) : Byte)]))
    (h_a1_len_mat : a1.length = (k params : ℕ) * (k params : ℕ)) :
    ∀ (i j : ℕ) (hi : i < (k params : ℕ)) (hj : j < (k params : ℕ)),
      toPolyMatrixOfLen a1 (k params) h_a1_len_mat ⟨i, hi⟩ ⟨j, hj⟩ =
        Â_spec ⟨i, hi⟩ ⟨j, hj⟩ := by
  intro i j hi hj
  simp only [toPolyMatrixOfLen, Matrix.of_apply]
  have h_ij_lt : i * (k params : ℕ) + j < matrixLen params := by
    unfold matrixLen
    have h1 : (i + 1) * (k params : ℕ) ≤ (k params : ℕ) * (k params : ℕ) :=
      Nat.mul_le_mul_right _ hi
    have h2 : i * (k params : ℕ) + (k params : ℕ) = (i + 1) * (k params : ℕ) := by ring
    omega
  have h_in_a1 : i * (k params : ℕ) + j < a1.val.length := by
    rw [h_a1_len_val]; exact h_ij_lt
  have h_in_data : i * (k params : ℕ) + j < (s_mut_back1 s18).data.val.length := by
    rw [h_b1_dlen]; unfold matrixLen at h_ij_lt
    have := k_sq_plus_2k_le_24 params; omega
  have h_a1_to_data :
      a1.val[i * (k params : ℕ) + j]'h_in_a1 =
      (s_mut_back1 s18).data.val[i * (k params : ℕ) + j]'h_in_data := by
    have h_eq_? : a1.val[i * (k params : ℕ) + j]? =
        (s_mut_back1 s18).data.val[i * (k params : ℕ) + j]? := by
      rw [a1_post7]
      rw [List.getElem?_take]
      simp [h_ij_lt]
    rw [List.getElem?_eq_getElem h_in_a1,
        List.getElem?_eq_getElem h_in_data] at h_eq_?
    exact Option.some.inj h_eq_?
  rw [h_a1_to_data]
  rw [h_b1_mat_conj i j hi hj]
  unfold expandAEntrySeed
  rw [h_Â_spec i j hi hj]

/-- **Residual D helper for `mlkem.key_expand_from_private_seed.spec`.**

Hoisted from the inline body of `h_D` in the main theorem to give the
D2 algebraic alignment (`toPolyVecOfLen t3 = Â * NTT s + NTT e`) its own
elaboration unit.  The inline form (~190 LoC of `Vector.ext` + entry-wise
`getElem?` chases + `apply keygen_t_hat_chain` unification) blew past the
parent's wall-clock budget (>25 min vs ~3 min baseline); separating the
work here is mechanical.

The D1 piece — `keyEncodedTPrefix pk_mlkem_key9 = (ByteEncode 12 t3).cast`
— remains an open sub-residual taken as the hypothesis `h_t_hat_impl`.

Args mirror the local-context names of the parent theorem; `d_bytes`
abstracts `arrayToSpecBytes pk_mlkem_key.private_seed`. -/
private theorem mlkem.key_expand_residual_D_helper
    (params : ParameterSet)
    (d_bytes : 𝔹 32)
    (pk_mlkem_key9 : mlkem.key.Key)
    {a1 a3 _s t1 t2 t3 s18 s19 pv_tmp1 : Aeneas.Std.Slice PolyElement}
    {i9 : Aeneas.Std.Usize}
    {_index_mut_back1 : Aeneas.Std.Slice PolyElement →
      Aeneas.Std.Array PolyElement 4#usize}
    {s_mut_back1 : Aeneas.Std.Slice PolyElement → mlkem.key.Key}
    (h_b1_dlen : (s_mut_back1 s18).data.val.length = 24)
    (h_a3_len_val : a3.val.length = matrixLen params)
    (h_t2_len_val : t2.val.length = (k params : ℕ))
    (h_t3_len_val : t3.val.length = (k params : ℕ))
    (h_t1_len_val : t1.val.length = (k params : ℕ))
    (_h__s_len_val : _s.val.length = 24 - matrixLen params - (k params : ℕ))
    (a1_post7 : a1.val = (s_mut_back1 s18).data.val.take (matrixLen params))
    (a1_post8 : t1.val =
      ((s_mut_back1 s18).data.val.drop (matrixLen params)).take (k params : ℕ))
    (h_a1_len_val : a1.val.length = matrixLen params)
    (h_pv1_len : pv_tmp1.val.length = (k params : ℕ))
    (h_s18_len : s18.val.length = (k params : ℕ))
    (h_arr_len : (_index_mut_back1 pv_tmp1).to_slice.val.length = 4)
    (h_s19_len_val : s19.length = (k params : ℕ))
    (h_app3_len : (a3.val ++ t2.val ++ _s.val).length = 24)
    (s19_post1 : s19.val = (_index_mut_back1 pv_tmp1).to_slice.val.slice 0 i9.val)
    (h_i9_val : (i9 : ℕ) = (k params : ℕ))
    (h_arr_prefix : ∀ (i : ℕ) (_h_i : i < (k params : ℕ)),
        (_index_mut_back1 pv_tmp1).to_slice.val[i]'(by
          have h_arr_len_val :
              (_index_mut_back1 pv_tmp1).to_slice.val.length = 4 := h_arr_len
          rw [h_arr_len_val]; have := k_le_4 params; omega) =
        pv_tmp1.val[i]'(by rw [h_pv1_len]; exact _h_i))
    (pv_tmp1_post3 : ∀ (i : ℕ) (h_i : i < s18.val.length),
        toPoly (pv_tmp1.val[i]'(by
          have : pv_tmp1.val.length = (k params : ℕ) := h_pv1_len
          have _h_s18 : s18.val.length = (k params : ℕ) := h_s18_len
          omega)) =
        (toPoly (s18.val[i]'h_i)).map (R * ·))
    (h_s18_ntt : ∀ (i : ℕ) (h_i : i < (k params : ℕ)),
        toPoly (s18.val[i]'(by rw [h_s18_len]; exact h_i)) =
        MLKEM.NTT (MLKEM.SamplePolyCBD
          (MLKEM.PRF (η₁ params)
            (MLKEM.G (d_bytes ‖ #v[((k params : ℕ) : Byte)])).2
            ((i : ℕ) : Byte))))
    (h_b1_t_conj : ∀ (i : ℕ) (h_i : i < (k params : ℕ)),
        toPoly ((s_mut_back1 s18).data.val[matrixLen params + i]'(by
          rw [h_b1_dlen]; unfold matrixLen
          have := k_le_4 params; have := k_sq_plus_2k_le_24 params; omega)) =
        MLKEM.NTT (MLKEM.SamplePolyCBD
          (MLKEM.PRF (η₁ params)
            (MLKEM.G (d_bytes ‖ #v[((k params : ℕ) : Byte)])).2
            ((k params + i) : Byte))))
    (h_b1_mat_conj : ∀ (row col : ℕ)
        (h_row : row < (k params : ℕ)) (h_col : col < (k params : ℕ)),
        toPoly ((s_mut_back1 s18).data.val[row * (k params : ℕ) + col]'(by
          rw [h_b1_dlen]
          have h_k4 := k_le_4 params
          have h_sq := k_sq_plus_2k_le_24 params
          have h1 : (row + 1) * (k params : ℕ) ≤ (k params : ℕ) * (k params : ℕ) :=
            Nat.mul_le_mul_right _ h_row
          have h2 : row * (k params : ℕ) + (k params : ℕ) = (row + 1) * (k params : ℕ) := by
            ring
          omega)) =
        MLKEM.SampleNTT (expandAEntrySeed
          (MLKEM.G (d_bytes ‖ #v[((k params : ℕ) : Byte)])).1 row col))
    (t2_post4 : toPolyVecOfLen t2 (k params) h_t2_len_val =
        toPolyVecOfLen t1 (k params) h_t1_len_val +
        ((toPolyMatrixOfLen a1 (k params) (by
              show a1.val.length = _; rw [h_a1_len_val])).MulVectorNTT
          (toPolyVecOfLen s19 (k params) (by
              show s19.val.length = _
              have : s19.val.length = s19.length := rfl
              rw [this, h_s19_len_val]))).map (fun p => p.map (Rinv * ·)))
    (h_t3_eq_data : ∀ (i : ℕ) (h_i : i < (k params : ℕ)),
        t3.val[i]'(by have := h_t3_len_val; omega) =
        (a3.val ++ t2.val ++ _s.val)[matrixLen params + i]'(by
          rw [h_app3_len]; unfold matrixLen
          have := k_le_4 params; have := k_sq_plus_2k_le_24 params; omega))
    (h_t_hat_impl :
        keyEncodedTPrefix pk_mlkem_key9 params =
        ((MLKEM.PolyVector.ByteEncode 12 (toPolyVecOfLen t3 (k params) h_t3_len_val)
            ⟨by omega, by omega⟩).cast (polyVector_byteEncode_size_cast 12))) :
    keyEncodedTPrefix pk_mlkem_key9 params =
      slice (K_PKE.KeyGen params d_bytes).1 0 (384 * (k params : ℕ)) (by simp) := by
  -- Residual D2 helper body.  D2-A/B/C are delegated to sub-helpers
  -- (key_expand_residual_D_helper_{t1_eq,s19_eq,Â_impl}) to keep each
  -- elaboration unit within the per-declaration heartbeat budget.
  obtain ⟨Â_spec, s_spec, e_spec, h_Â_spec, h_s_spec, h_e_spec, h_ek_eq⟩ :=
    KPKE_t_hat_explicit params d_bytes
  -- Cache the matrixLen-shifted index bound used by both D2-A's t1 entry
  -- and h_b1_t_conj's quantifier; passing it as an explicit argument avoids
  -- omega running inside the helper signature's type-checking.
  have h_in_data : ∀ (i : ℕ), i < (k params : ℕ) →
      matrixLen params + i < (s_mut_back1 s18).data.val.length := by
    intro i _
    rw [h_b1_dlen]; unfold matrixLen
    have := k_le_4 params; have := k_sq_plus_2k_le_24 params; omega
  have h_t1_eq :=
    mlkem.key_expand_residual_D_helper_t1_eq params d_bytes
      h_b1_dlen h_t1_len_val a1_post8 h_in_data h_b1_t_conj e_spec h_e_spec
  have h_s19_eq :=
    mlkem.key_expand_residual_D_helper_s19_eq params d_bytes
      h_pv1_len h_s18_len h_arr_len h_s19_len_val s19_post1 h_i9_val
      h_arr_prefix pv_tmp1_post3 h_s18_ntt s_spec h_s_spec
  have h_a1_len_mat : a1.length = (k params : ℕ) * (k params : ℕ) := by
    show a1.val.length = _; rw [h_a1_len_val]
  have h_Â_impl :=
    mlkem.key_expand_residual_D_helper_Â_impl params d_bytes
      h_b1_dlen h_a1_len_val a1_post7 h_b1_mat_conj Â_spec h_Â_spec h_a1_len_mat
  -- D2 assembly: toPolyVecOfLen t2 = Â_spec * NTT s_spec + NTT e_spec.
  have h_t2_chain : toPolyVecOfLen t2 (k params) h_t2_len_val =
      Â_spec * MLKEM.PolyVector.NTT s_spec + MLKEM.PolyVector.NTT e_spec := by
    rw [t2_post4]
    apply keygen_t_hat_chain Â_spec
      (toPolyMatrixOfLen a1 (k params) h_a1_len_mat)
      s_spec e_spec
      (toPolyVecOfLen t1 (k params) h_t1_len_val)
      (toPolyVecOfLen s19 (k params) (by
        show s19.val.length = _
        have : s19.val.length = s19.length := rfl
        rw [this, h_s19_len_val]))
      h_t1_eq h_s19_eq
    intro i j hi hj
    exact h_Â_impl i j hi hj
  -- D-bridge: toPolyVecOfLen t3 = toPolyVecOfLen t2 via h_t3_eq_data.
  have h_t3_eq_t2 : toPolyVecOfLen t3 (k params) h_t3_len_val =
      toPolyVecOfLen t2 (k params) h_t2_len_val := by
    apply Vector.ext
    intro i hi
    simp only [toPolyVecOfLen, Vector.getElem_ofFn]
    fcongr 1
    have h_in_t2 : i < t2.val.length := by rw [h_t2_len_val]; exact hi
    have h_in_data : matrixLen params + i < (a3.val ++ t2.val ++ _s.val).length := by
      rw [h_app3_len]; unfold matrixLen
      have := k_le_4 params; have := k_sq_plus_2k_le_24 params; omega
    have h_ab_len : (a3.val ++ t2.val).length = matrixLen params + (k params : ℕ) := by
      rw [List.length_append, h_a3_len_val, h_t2_len_val]
    have h_in_ab : matrixLen params + i < (a3.val ++ t2.val).length := by
      rw [h_ab_len]; omega
    have h_ge_a3 : a3.val.length ≤ matrixLen params + i := by
      rw [h_a3_len_val]; omega
    have h_data_to_t2 :
        (a3.val ++ t2.val ++ _s.val)[matrixLen params + i]'h_in_data =
          t2.val[i]'h_in_t2 := by
      rw [List.getElem_append_left h_in_ab,
          List.getElem_append_right h_ge_a3]
      fcongr 1
      rw [h_a3_len_val]; omega
    rw [h_t3_eq_data i hi, h_data_to_t2]
  -- D-bridge: toPolyVecOfLen t3 = toPolyVecOfLen t2 via h_t3_eq_data.
  -- Final assembly: chain D1 → D-bridge → D2 → spec append form → prefix slice.
  rw [h_t_hat_impl, h_t3_eq_t2, h_t2_chain]
  rw [show (K_PKE.KeyGen params d_bytes).1 = _ from h_ek_eq]
  -- The remaining goal is a slice-of-cast-of-append equality.  We prove it
  -- directly with `Vector.ext` (rather than `cast_slice_eq_of_append₂_prefix`,
  -- whose `na` would unify with `k * (32*12)` not `384 * k`).
  apply Vector.ext
  intro i hi
  simp only [Spec.slice, Vector.getElem_ofFn, Vector.getElem_cast, Nat.zero_add]
  have h_lt : i < (k params : ℕ) * (32 * 12) := by
    have h_eq : 384 * (k params : ℕ) = (k params : ℕ) * (32 * 12) := by ring
    rw [← h_eq]; exact hi
  exact (Vector.getElem_append_left h_lt).symm

/-- **D1 helper for `mlkem.key_expand_from_private_seed.spec`** — impl encoding chain.

Closes the residual D1 obligation that ties the keyEncodedTPrefix view of
`pk_mlkem_key9` to the polynomial-level `ByteEncode 12` over `t3`.

The per-byte chase: for index `i`,
* LHS [`pk9.encoded_t.val[i].bv`] chains via `pk9.encoded_t = index_mut_back2 s21`
  and `index_mut_back2 s21 = encoded_t.setSlice! 0 s21` to `s21.val[i].bv`.
* RHS unpacks via `polyVector_slice_byteEncode_eq` to
  `(ByteEncode 12 (toPoly t3.val[pi]))[bi]` for `i = pi·(32·12) + bi`.
* Bridge: `s21_post2 pi` plus the `d = 12` collapse of `compressEncodePoly`
  identify LHS[i] with `(ByteEncode 12 (toPoly t3.val[pi]))[bi]`.

Hoisted into its own elaboration unit to keep the parent spec's heartbeat
budget bounded (per the project-wide 8M cap). -/
private theorem mlkem.key_expand_residual_D1_helper
    (params : ParameterSet)
    (pk_mlkem_key9 : mlkem.key.Key)
    {t3 : Aeneas.Std.Slice PolyElement}
    {s21 : Aeneas.Std.Slice Aeneas.Std.U8}
    {encoded_t : Aeneas.Std.Array Aeneas.Std.U8 1536#usize}
    {t_encoded_t_mut_back :
      Aeneas.Std.Slice PolyElement × Aeneas.Std.Array Aeneas.Std.U8 1536#usize →
      mlkem.key.Key}
    {index_mut_back2 : Aeneas.Std.Slice Aeneas.Std.U8 →
      Aeneas.Std.Array Aeneas.Std.U8 1536#usize}
    (h_t3_len_val : (↑t3 : List PolyElement).length = ↑(k params))
    (h_s21_len : s21.length = 384 * ↑(k params))
    (h_pk9_enc :
      pk_mlkem_key9.encoded_t = (t_encoded_t_mut_back (t3, index_mut_back2 s21)).encoded_t)
    (h_temb_enc :
      (t_encoded_t_mut_back (t3, index_mut_back2 s21)).encoded_t = index_mut_back2 s21)
    (h_imb2 :
      ∀ (s' : Aeneas.Std.Slice Aeneas.Std.U8),
        ↑(index_mut_back2 s') = (↑encoded_t : List Aeneas.Std.U8).setSlice! 0 ↑s')
    (s21_post2 :
      ∀ (i : ℕ) (_h_i : i < t3.length),
        ∃ (_h : i * (32 * 12) + 32 * 12 ≤ s21.length),
          sliceWindowToSpecBytes s21 (i * (32 * 12)) (32 * 12) _h =
            MLKEM.ByteEncode 12
              (toPoly ((↑t3 : List PolyElement)[i]'_h_i))
              ⟨by omega, by omega⟩) :
    keyEncodedTPrefix pk_mlkem_key9 params =
    Vector.cast (n := (k params : ℕ) * (32 * 12)) (m := 384 * (k params : ℕ))
      (by have := polyVector_byteEncode_size_cast (n := k params) 12; omega)
      (MLKEM.PolyVector.ByteEncode 12 (toPolyVecOfLen t3 (k params) h_t3_len_val)
        ⟨by omega, by omega⟩) := by
  apply Vector.ext
  intro i hi
  -- Decompose i = pi * (32*12) + bi
  set pi := i / (32 * 12) with hpi_def
  set bi := i % (32 * 12) with hbi_def
  have h_kp_eq : 384 * (k params : ℕ) = (k params : ℕ) * (32 * 12) := by ring
  have h_bi_lt : bi < 32 * 12 := Nat.mod_lt _ (by omega)
  have h_idecomp : pi * (32 * 12) + bi = i := by
    have := Nat.div_add_mod i (32 * 12); omega
  have h_i_lt_kt : i < (k params : ℕ) * (32 * 12) := by rw [← h_kp_eq]; exact hi
  have h_pi_lt_k : pi < (k params : ℕ) :=
    (Nat.div_lt_iff_lt_mul (by omega)).mpr h_i_lt_kt
  have h_pi_lt_t3 : pi < t3.length := by
    show pi < (↑t3 : List PolyElement).length
    rw [h_t3_len_val]; exact h_pi_lt_k
  have h_i_lt_s21 : i < s21.length := by rw [h_s21_len]; omega
  have h_enc_len : (↑encoded_t : List Aeneas.Std.U8).length = 1536 := encoded_t.property
  have hk_le_4 : (k params : ℕ) ≤ 4 := k_le_4 params
  have h_i_lt_1536 : i < 1536 := by
    have : 384 * (k params : ℕ) ≤ 384 * 4 := Nat.mul_le_mul_left _ hk_le_4
    omega
  -- LHS list equality: pk9.encoded_t.val = encoded_t.val.setSlice! 0 s21.val
  have h_encT_eq : pk_mlkem_key9.encoded_t = index_mut_back2 s21 := h_pk9_enc.trans h_temb_enc
  have h_pk9_val : (↑pk_mlkem_key9.encoded_t : List Aeneas.Std.U8) =
                   (↑encoded_t : List Aeneas.Std.U8).setSlice! 0 (↑s21 : List Aeneas.Std.U8) := by
    rw [h_encT_eq]; exact h_imb2 s21
  have h_setSl_len : ((↑encoded_t : List Aeneas.Std.U8).setSlice! 0
                       (↑s21 : List Aeneas.Std.U8)).length = 1536 := by
    rw [List.length_setSlice!]; omega
  have h_pk9_len : (↑pk_mlkem_key9.encoded_t : List Aeneas.Std.U8).length = 1536 := by
    rw [h_pk9_val]; exact h_setSl_len
  have h_setSl_idx :
      ((↑encoded_t : List Aeneas.Std.U8).setSlice! 0 (↑s21 : List Aeneas.Std.U8))[i]'
          (by rw [h_setSl_len]; omega) =
        (↑s21 : List Aeneas.Std.U8)[i]'h_i_lt_s21 := by
    have := List.getElem_setSlice!_middle (↑encoded_t : List Aeneas.Std.U8)
              (↑s21 : List Aeneas.Std.U8) 0 i
              ⟨by omega, by simpa using h_i_lt_s21, by omega⟩
    simpa using this
  -- Unfold LHS and RHS to getElem form
  unfold keyEncodedTPrefix
  simp only [Vector.getElem_ofFn, Vector.getElem_cast]
  -- Now goal: pk_mlkem_key9.encoded_t.val[i].bv = (PolyVector.ByteEncode 12 ... ⟨_,_⟩)[i]
  -- Rewrite LHS via the chain
  rw [show (↑pk_mlkem_key9.encoded_t : List Aeneas.Std.U8)[i]'_ =
        (↑s21 : List Aeneas.Std.U8)[i]'h_i_lt_s21 from
        (List.getElem_of_eq h_pk9_val _).trans h_setSl_idx]
  -- Now goal: ↑↑(↑s21)[i] = (PolyVector.ByteEncode 12 v ⋯)[i]
  obtain ⟨h_bnd_s21, h_eq_s21⟩ := s21_post2 pi h_pi_lt_t3
  set v := toPolyVecOfLen t3 (k params) h_t3_len_val with hv_def
  have h_d12 : (1 : ℕ) ≤ 12 ∧ (12 : ℕ) ≤ 12 := by omega
  have h_bnd_pV : 32 * 12 * pi + 32 * 12 ≤ 32 * 12 * (k params : ℕ) := by
    have h1 := Nat.mul_le_mul_left (32 * 12) (Nat.succ_le_of_lt h_pi_lt_k)
    have h2 : 32 * 12 * (pi + 1) = 32 * 12 * pi + 32 * 12 := by ring
    omega
  -- v[pi] = toPoly t3.val[pi]
  have h_v_pi : v[pi]'h_pi_lt_k = toPoly ((↑t3 : List PolyElement)[pi]'h_pi_lt_t3) := by
    show (toPolyVecOfLen t3 (k params) h_t3_len_val)[pi] = _
    unfold toPolyVecOfLen
    rw [Vector.getElem_ofFn]
  -- RHS bridge: (PolyVector.ByteEncode 12 v _)[i] = (ByteEncode 12 v[pi] _)[bi]
  have h_rhs_bridge :
      (MLKEM.PolyVector.ByteEncode 12 v h_d12)[i]'h_i_lt_kt =
      (MLKEM.ByteEncode 12 (v[pi]'h_pi_lt_k) h_d12)[bi]'h_bi_lt := by
    have h_slice_eq := polyVector_slice_byteEncode_eq (n := k params) 12 h_d12 v pi h_pi_lt_k h_bnd_pV
    have h_at_bi : (slice (Vector.cast (polyVector_byteEncode_size_cast 12)
                            (MLKEM.PolyVector.ByteEncode 12 v h_d12))
                          (32 * 12 * pi) (32 * 12) h_bnd_pV)[bi]'h_bi_lt =
                   (MLKEM.ByteEncode 12 (v[pi]'h_pi_lt_k) h_d12)[bi]'h_bi_lt :=
      congrArg (·[bi]'h_bi_lt) h_slice_eq
    simp only [slice, Vector.getElem_ofFn, Vector.getElem_cast] at h_at_bi
    -- h_at_bi : (PolyVector.ByteEncode 12 v h_d12)[32*12*pi + bi] = (ByteEncode 12 v[pi] h_d12)[bi]
    have hi_eq : 32 * 12 * pi + bi = i := by rw [← h_idecomp]; ring
    -- Use index-substitution via Vector.getElem equality at congruent indices
    have h_idx_congr : ∀ (j : ℕ) (hj : j < (k params : ℕ) * (32 * 12)),
                       j = i →
                       (MLKEM.PolyVector.ByteEncode 12 v h_d12)[j]'hj =
                       (MLKEM.PolyVector.ByteEncode 12 v h_d12)[i]'h_i_lt_kt := by
      intro j hj h_eq; subst h_eq; rfl
    rw [← h_idx_congr (32 * 12 * pi + bi)
          (by rw [hi_eq]; exact h_i_lt_kt) hi_eq]
    exact h_at_bi
  -- LHS bridge: (s21.val[i]).bv = (ByteEncode 12 (toPoly t3.val[pi]) _)[bi]
  have h_lhs_bridge :
      ((↑s21 : List Aeneas.Std.U8)[i]'h_i_lt_s21 : Aeneas.Std.U8).bv =
      (MLKEM.ByteEncode 12 (toPoly ((↑t3 : List PolyElement)[pi]'h_pi_lt_t3)) h_d12)[bi]'h_bi_lt := by
    have h_at_bi := congrArg (·[bi]'h_bi_lt) h_eq_s21
    simp only [sliceWindowToSpecBytes, Vector.getElem_ofFn] at h_at_bi
    -- h_at_bi : ((↑s21)[pi*(32*12) + bi]).bv = (ByteEncode 12 ...)[bi]
    have h_idx_eq : (↑s21 : List Aeneas.Std.U8)[pi * (32 * 12) + bi]'(by
                       have := h_bnd_s21
                       show pi * (32 * 12) + bi < (↑s21 : List Aeneas.Std.U8).length
                       have h_eq_len : (↑s21 : List Aeneas.Std.U8).length = s21.length := rfl
                       rw [h_eq_len]; omega) =
                    (↑s21 : List Aeneas.Std.U8)[i]'h_i_lt_s21 := by
      have h_eq : pi * (32 * 12) + bi = i := h_idecomp
      have h_aux : ∀ (j : ℕ) (hj : j < (↑s21 : List Aeneas.Std.U8).length), j = i →
                   (↑s21 : List Aeneas.Std.U8)[j]'hj =
                   (↑s21 : List Aeneas.Std.U8)[i]'h_i_lt_s21 := by
        intro j hj heq; subst heq; rfl
      exact h_aux _ _ h_eq
    rw [← h_idx_eq]; exact h_at_bi
  -- Final chain (with U8 → Byte coercion handled by simp)
  have h_chain : ((↑s21 : List Aeneas.Std.U8)[i]'h_i_lt_s21 : Aeneas.Std.U8).bv =
                 (MLKEM.PolyVector.ByteEncode 12 v h_d12)[i]'h_i_lt_kt := by
    rw [h_lhs_bridge, ← h_v_pi, ← h_rhs_bridge]
  -- Convert the goal coercion to .bv form and close
  show ((↑((↑s21 : List Aeneas.Std.U8)[i]'h_i_lt_s21) : Byte) : BitVec 8) = _
  rw [show (((↑((↑s21 : List Aeneas.Std.U8)[i]'h_i_lt_s21) : Byte) : BitVec 8)) =
        ((↑s21 : List Aeneas.Std.U8)[i]'h_i_lt_s21 : Aeneas.Std.U8).bv from by simp]
  exact h_chain

/-- **Top spec for `key_expand_from_private_seed`**.

Postcondition: the resulting key holds the spec-level outputs of
`K_PKE.KeyGen params (arrayToSpecBytes pk_mlkem_key.private_seed)`:

* `public_seed = ρ = slice ekPKE (384·k) 32`
* `encoded_t[0..384·k] = ByteEncode 12 t̂ = slice ekPKE 0 (384·k)`
* `keySEncoded = dkPKE = ByteEncode 12 ŝ`
* `encaps_key_hash = SHA3-256(ekPKE)`
* `Â^T` slots match `SampleNTT(ρ ‖ [i, j])` (after transpose).

The `temps` post-state is scratch with no externally observable
invariant.

Informal proof.  After `unfold mlkem.key_expand_from_private_seed`,
the proof proceeds in nine phases (matching Key.lean module header
steps 1–9):

**Phase 1 — G(d ‖ k).**  `step` through `MlKemHashState.set_alg.spec`
(SHA3-512), `MlKemHashState.init.spec`, two `MlKemHashState.append.spec`
calls (append `d = arrayToSpecBytes key.private_seed`, then `k.byte`),
and `MlKemHashState.result.spec`: gives 64-byte output split as
`ρ := out[0..32)` and `σ := out[32..64)`, equal to `(G(d ‖ k)).1`
and `(G(d ‖ k)).2` respectively.  Write `ρ` into `key.public_seed`
via a slice-copy step.

**Phase 2 — PRF base state.**  `step` through
`MlKemHashState.set_alg.spec` (SHAKE-256), `MlKemHashState.init.spec`,
`MlKemHashState.append.spec` (absorb `σ`): establishes ghost state
`g_base` with `g_base.absorbed.map (·.bv) = σ.toList`, ready for
the CBD loop invariant.

**Phase 3 — Sample s (loop 0).**  `step` with
`mlkem.key_expand_from_private_seed_loop0.spec` (iter = `0..k params`,
initial `cbdLoopInv` at `i = 0` from the ghost state from phase 2):
fills s-slots `[sOffset, sOffset + k)` with
`SamplePolyCBD(PRF η₁ σ j.byte)` for `j ∈ [0, k)`.

**Phase 4 — Sample e (loop 1).**  `step` with
`mlkem.key_expand_from_private_seed_loop1.spec` (iter = `0..k params`,
`offset = k params`): fills t-slots `[tOffset, tOffset + k)` with
`SamplePolyCBD(PRF η₁ σ (k + j).byte)` for `j ∈ [0, k)`.

**Phase 5 — NTT s and e in place.**  `step` with `vector_ntt.spec`
twice: s-slots become `ŝ = NTT(s)`, t-slots become `ê = NTT(e)`.

**Phase 6 — Expand matrix and compute t̂.**  `step` with
`expand_matrix.spec` (SampleNTT via XOF(ρ, i, j)): fills matrix
slots `[0, k²)` with `Â[i][j] = SampleNTT(XOF(ρ, i, j))`.  Then
`step` with the matrix-vector multiply spec:
t-slots `← Â · ŝ + ê = t̂`.

**Phase 7 — Transpose Â → Â^T.**  `step` with the in-place transpose
spec: matrix slots `[0, k²)` hold `Â^T[row][col] =
Â[col][row] = SampleNTT(XOF(ρ, col, row)) =
SampleNTT(expandAEntrySeed ρ row col)`.

**Phase 8 — Encode t̂.**  `step` with the 12-bit vector-encode spec:
`key.encoded_t[0..384·k] = ByteEncode 12 t̂`.

**Phase 9 — Compute H(ekPKE).**  `step` through `set_alg.spec`
(SHA3-256), `init.spec`, `append.spec` (encoded_t ‖ ρ), `result.spec`:
gives `key.encaps_key_hash = SHA3-256(encoded_t ‖ ρ) = SHA3-256(ekPKE)`.
Set `has_private_key := true`.

Residual FC: connect each key field to the `K_PKE.KeyGen` output.
`ekPKE = encoded_t ‖ ρ` so `keyEncodedTPrefix = tEncoded` and
`arrayToSpecBytes key.public_seed = ρ` follow from phases 1 and 8.
`keySEncoded = dkPKE` follows from phase 5 (ŝ = NTT(s) in s-slots)
and the definition of `keySEncoded`.  `encaps_key_hash = SHA3-256(ekPKE)`
from phase 9.  `Â^T` entry equality from phase 7.  `wfKey key'` from
the `wfPoly` invariant maintained through all slot writes.  Close by
`agrind`. -/
@[step]
theorem mlkem.key_expand_from_private_seed.spec
    (params : ParameterSet)
    (pk_mlkem_key : mlkem.key.Key)
    (p_comp_temps : mlkem.ntt.InternalComputationTemporaries)
    (h_wf : wfKey pk_mlkem_key params)
    (h_seed : pk_mlkem_key.has_private_seed = true)
    (h_pct_max0 : wfPolyVec p_comp_temps.max_size_vector0.to_slice) :
    mlkem.key_expand_from_private_seed pk_mlkem_key p_comp_temps
      ⦃ key' _temps' => keyExpand.Inv4 pk_mlkem_key key' params ⦄ := by
  -- Replace the body of `mlkem.key_expand_from_private_seed` by its folded
  -- form `do let r ← keyExpand.prelude ...; <Phases 10..23>`.  The prelude
  -- helper packages Phases 1..9 (G(d‖k), CBD loops, NTT, public-matrix
  -- expand, pv_tmp window, s_mut for vector_mul_r) behind a single
  -- `@[step]` spec whose post is the 6-conjunct
  -- `keyExpand.prelude.spec`.  After `step` consumes the prelude (the
  -- precondition discharge is below), `step*` drives Phases 10..23 in a
  -- single fresh-budget block.
  rw [mlkem.key_expand_from_private_seed.fold]
  have h_k_le : (k params : ℕ) ≤ 4 := k_le_4 params
  have h_nrows : pk_mlkem_key.params.n_rows.val = (k params : ℕ) := by
    have h_params := wfKey.params_ok (self := pk_mlkem_key) (p := params) h_wf
    exact wfInternalParams.n_rows_val h_params
  -- Step through prelude.  Its preconditions are exactly
  -- `wfKey pk_mlkem_key params`, `pk_mlkem_key.has_private_seed = true`,
  -- and `wfPolyVec p_comp_temps.max_size_vector0.to_slice`.
  step with keyExpand.prelude.spec params pk_mlkem_key p_comp_temps
    h_wf h_seed h_pct_max0
    as ⟨cb_encoded_vector, private_seed_hash1, _p_comp_temps1, _mkhs2,
        _mkhs4, _cbd_sample_buffer4, pv_tmp, _index_mut_back1, s18,
        s_mut_back1, h_G_eq, h_cbev, h_pv_tmp_len, h_pv_tmp_wf,
        h_s18_len, h_s18_wf, h_s18_ntt, h_idx1_universal, h_back1_universal⟩
  -- Now drive Phases 10..23 inline.  The first iteration of this proof
  -- intentionally lets `step*` discover the residual; once the residual
  -- is identified, the prelude.spec post may need to be widened (or
  -- already-present conjuncts repackaged) to feed Phases 10..23.
  step*
  -- Residual A: `?params : ParameterSet` (ats_mut spec param).
  · exact params
  -- Residual B: Phase 10 vector_mul_r precondition `s18.length > 0 ∧ ≤ 4`.
  · rw [h_s18_len]
    have h_k_ge := k_ge_2 params
    refine ⟨?_, h_k_le⟩
    scalar_tac
  -- Residual C: Phase 12 ats_mut precondition `wfKey (s_mut_back1 s18) params`.
  · obtain ⟨⟨h_b1_wf, _, _, _, _, _⟩, _⟩ :=
      h_back1_universal s18 h_s18_len h_s18_wf
    exact h_b1_wf
  -- Derived lengths/wfness for `_index_mut_back1 pv_tmp1` (Phase 13 prep).
  have h_pv1_len : pv_tmp1.length = (k params : ℕ) := pv_tmp1_post2.trans h_s18_len
  have h_idx1 := h_idx1_universal pv_tmp1 h_pv1_len pv_tmp1_post1
  have h_arr_wf : wfPolyVec (_index_mut_back1 pv_tmp1).to_slice := h_idx1.1
  have h_arr_len : (_index_mut_back1 pv_tmp1).to_slice.length = 4 := h_idx1.2.1
  have h_arr_prefix := h_idx1.2.2
  step*
  -- Residuals from `matrix_vector_mont_mul_and_add` (Phase 13).
  · -- kn : K (the K element matching n_rows)
    exact k params
  · -- h_kn : (kn : ℕ) = n_rows.val
    exact h_nrows.symm
  · -- h_wf_pm : wfPolyVec a1
    exact a1_post4
  · -- h_wf_src2 : wfPolyVec s19 (prefix slice of (_index_mut_back1 pv_tmp1).to_slice).
    have h_i9 : i9.val = pk_mlkem_key.params.n_rows.val := by
      rw [i9_post]; scalar_tac
    have h_le : i9.val ≤ (4#usize : Usize).val := by
      rw [h_i9, h_nrows]; show (k params : ℕ) ≤ 4; exact h_k_le
    exact wfPolyVec_of_prefix_slice (_index_mut_back1 pv_tmp1) s19 i9.val
      (by rw [s19_post1]; simp only [Aeneas.Std.Array.val_to_slice])
      (by rw [s19_post2]; omega) h_le h_arr_wf
  · -- h_wf_dst : wfPolyVec t
    exact a1_post5
  · -- h_nrows : 0 < n_rows ∧ n_rows ≤ 4
    rw [h_nrows]
    have := k_ge_2 params
    refine ⟨?_, h_k_le⟩; scalar_tac
  step*
  -- Phase 14 (matrix_transpose) + Phase 15 (t_encoded_t_mut) residuals.
  · -- Residual: `?params : ParameterSet` (left as metavar by t_encoded_t_mut spec).
    exact params
  · -- h_n : 2 ≤ n_rows ∧ n_rows ≤ 4 (matrix_transpose)
    rw [h_nrows]
    refine ⟨?_, h_k_le⟩
    have := k_ge_2 params; scalar_tac
  · -- h_wf : wfPolyVec a1 (matrix_transpose)
    exact a1_post4
  · -- wfKey (x✝ (a3, t1, _s)) params  via a1_post7 universal.
    -- a3.length = a1.length = matrixLen params; a3 is wfPoly via matrix_transpose post;
    -- t1 via t1_post1; _s via a1_post6.
    have h_a3_wf : ∀ i (_ : i < a3.length), wfPoly (↑a3)[i] := a3_post1
    obtain ⟨⟨h_wf_out, _, _, _, _, _⟩, _⟩ :=
      a1_post10 a3 t1 _s (a3_post2.trans a1_post1) t1_post3 a1_post3
        h_a3_wf t1_post1 a1_post6
    exact h_wf_out
  step*
  -- Phase 17/18 (vector_compress_and_encode + key_compute_encapsulation_key_hash) preconditions.
  · -- ?params : ParameterSet metavar (key_compute_encapsulation_key_hash)
    exact params
  · -- wfPolyVec t2
    exact t2_post2
  · -- 2 ≤ t2.length ∧ t2.length ≤ 4  (n_rows bound on t2)
    rw [t2_post1]
    refine ⟨?_, h_k_le⟩
    exact k_ge_2 params
  · -- wfKey (t_encoded_t_mut_back (t2, index_mut_back2 s21)) params  via t2_post4.
    obtain ⟨⟨h_wf_out, _, _, _, _, _⟩, _⟩ :=
      t2_post5 t2 (index_mut_back2 s21) t2_post1 t2_post2
    exact h_wf_out
  step*
  -- ============================================================
  -- Final FC: build `keyExpand.Inv4 pk_mlkem_key pk_mlkem_key9 params`.
  -- After unfolding the `abbrev` cascade Inv4 → Inv3 → Inv2 → Inv1,
  -- the goal is an 8-conjunct ∧:
  --   1. KeyInv pk_mlkem_key pk_mlkem_key9 params
  --   2. pk_mlkem_key9.has_private_key = pk_mlkem_key.has_private_key
  --   3. pk_mlkem_key9.public_seed.toSpec = slice ekPKE (384·k) 32
  --   4. (↑pk_mlkem_key9.data).length = 24
  --   5. keySEncoded pk_mlkem_key9 params = dkPKE
  --   6. ∀ row col, toPoly pk_mlkem_key9.data[row*k+col] = SampleNTT(expandAEntrySeed ρ col row)
  --   7. keyEncodedTPrefix pk_mlkem_key9 params = slice ekPKE 0 (384·k)
  --   8. pk_mlkem_key9.encaps_key_hash.toSpec = SHA3-256(ekPKE)
  --
  -- where  ekPKE := (K_PKE.KeyGen p d).1,  dkPKE := (K_PKE.KeyGen p d).2,
  --        d   := pk_mlkem_key.private_seed.toSpec,
  --        ρ   := (G (d ‖ ⟨k⟩)).1.
  --
  -- Bind the three back-fn universals plus the framing produced by
  -- `key_compute_encapsulation_key_hash`.
  have hb1 := h_back1_universal s18 h_s18_len h_s18_wf
  have h_a3_wf : ∀ i (_ : i < a3.length), wfPoly (↑a3)[i] := a3_post1
  have ha1 := a1_post10 a3 t1 _s (a3_post2.trans a1_post1) t1_post3 a1_post3
                h_a3_wf t1_post1 a1_post6
  have ht3 := t2_post5 t2 (index_mut_back2 s21) t2_post1 t2_post2
  -- Re-package the per-field equalities from
  -- `key_compute_encapsulation_key_hash` as a single `KeyInv`.
  have h_t_to_9 : KeyInv (t_encoded_t_mut_back (t2, index_mut_back2 s21))
      pk_mlkem_key9 params := by
    refine ⟨pk_mlkem_key9_post1, ?_, ?_, ?_, ?_, ?_⟩
    · exact pk_mlkem_key9_post5
    · exact pk_mlkem_key9_post6
    · exact pk_mlkem_key9_post9
    · exact pk_mlkem_key9_post7
    · exact pk_mlkem_key9_post8
  -- Residual D extracted as a `have` BEFORE refine so that both
  -- `case ektprefix` (which IS Residual D) and `case ekhash`'s sub-need
  -- `h_residD` discharge from a single proof.  Body delegated to the
  -- file-scope helper `mlkem.key_expand_residual_D_helper` to give the
  -- D2 algebraic chain its own elaboration unit (the inline body blew
  -- the heartbeat / wall-time budget on the main theorem).  D1 (the
  -- per-byte impl encoding chain) is discharged via the sister helper
  -- `mlkem.key_expand_residual_D1_helper`, fed as the last argument
  -- below.
  have h_b1_dlen : (s_mut_back1 s18).data.val.length = 24 := hb1.2.2.2.2.2.1
  have h_a3_len_val : a3.val.length = matrixLen params := by
    show a3.length = _; exact a3_post2.trans a1_post1
  have h_a1_len_val : a1.val.length = matrixLen params := by
    rw [a1_post7, List.length_take, h_b1_dlen]; unfold matrixLen
    have := k_le_4 params; have := k_sq_plus_2k_le_24 params; omega
  have h_app3_len : (a3.val ++ t1.val ++ _s.val).length = 24 := by
    simp only [List.length_append, h_a3_len_val, t1_post3, a1_post3]
    unfold matrixLen
    have := k_le_4 params; have := k_sq_plus_2k_le_24 params; omega
  have h_i9_val : (i9 : ℕ) = (k params : ℕ) := by
    rw [i9_post]; simp_scalar
  have h_s19_len_val : s19.length = (k params : ℕ) := by
    rw [s19_post2, h_i9_val]; omega
  have h_t3_len_val : t2.val.length = (k params : ℕ) := t2_post1
  have h_t3_eq_data : ∀ (i : ℕ) (h_i : i < (k params : ℕ)),
      t2.val[i]'(h_t3_len_val ▸ h_i) =
      (a3.val ++ t1.val ++ _s.val)[matrixLen params + i]'(by
        rw [h_app3_len]; unfold matrixLen
        have := k_le_4 params; have := k_sq_plus_2k_le_24 params; omega) := by
    intro i hi
    -- From t2_post4 + ha1.2.2.2.2.2:
    --   t2.val = List.slice (matrixLen) (sOffset) (a3 ++ t1 ++ _s)
    -- For i < k, this gives t2.val[i] = (a3 ++ t1 ++ _s)[matrixLen + i].
    have h_t3_val : t2.val =
        ((a3.val ++ t1.val ++ _s.val).drop (matrixLen params)).take
          (sOffset params - matrixLen params) := by
      have h := t2_post4
      simp only [List.slice] at h
      rw [h, ha1.2.2.2.2.2]
    have h_in_drop : i < ((a3.val ++ t1.val ++ _s.val).drop (matrixLen params)).length := by
      rw [List.length_drop, h_app3_len]
      unfold matrixLen
      have := k_le_4 params; have := k_sq_plus_2k_le_24 params; omega
    have h_lt_diff : i < sOffset params - matrixLen params := by
      unfold sOffset matrixLen
      have := k_le_4 params; have := k_sq_plus_2k_le_24 params; omega
    have h_in_take :
        i < (((a3.val ++ t1.val ++ _s.val).drop (matrixLen params)).take
              (sOffset params - matrixLen params)).length := by
      rw [List.length_take, List.length_drop, h_app3_len]
      unfold sOffset matrixLen
      have := k_le_4 params; have := k_sq_plus_2k_le_24 params; omega
    calc t2.val[i]'_
        = (((a3.val ++ t1.val ++ _s.val).drop (matrixLen params)).take
              (sOffset params - matrixLen params))[i]'h_in_take :=
              List.getElem_of_eq h_t3_val _
      _ = ((a3.val ++ t1.val ++ _s.val).drop (matrixLen params))[i]'h_in_drop := by
              rw [List.getElem_take]
      _ = (a3.val ++ t1.val ++ _s.val)[matrixLen params + i]'_ := by
              rw [List.getElem_drop]
  have h_t_hat_impl :
      keyEncodedTPrefix pk_mlkem_key9 params =
      Vector.cast (n := (k params : ℕ) * (32 * 12)) (m := 384 * (k params : ℕ))
        (by have := polyVector_byteEncode_size_cast (n := k params) 12; omega)
        (MLKEM.PolyVector.ByteEncode 12 (toPolyVecOfLen t2 (k params) h_t3_len_val)
          ⟨by omega, by omega⟩) := by
    -- D1: impl encoding chain — discharged via helper.
    have h_s21_len : s21.length = 384 * (k params : ℕ) := by
      rw [s21_post1, s20_post2, h_cbev]; omega
    have h_s21_post2_h :
        ∀ (i : ℕ) (_h_i : i < t2.length),
          ∃ (_h : i * (32 * 12) + 32 * 12 ≤ s21.length),
            sliceWindowToSpecBytes s21 (i * (32 * 12)) (32 * 12) _h =
              MLKEM.ByteEncode 12 (toPoly ((↑t2 : List PolyElement)[i]'_h_i))
                ⟨by omega, by omega⟩ := by
      intro i h_i
      obtain ⟨h_w, h_eq⟩ := s21_post2 i h_i
      have h_bnd : i * (32 * 12) + 32 * 12 ≤ s21.length := by
        have := h_w; ring_nf at this ⊢; exact this
      refine ⟨h_bnd, ?_⟩
      -- compressEncodePoly 12 = ByteEncode 12 (d = 12 branch collapse).
      have h_collapse :
          compressEncodePoly (↑(12#u32 : Aeneas.Std.U32))
            (toPoly ((↑t2 : List PolyElement)[i]'h_i))
            (by simp) =
          MLKEM.ByteEncode 12
            (toPoly ((↑t2 : List PolyElement)[i]'h_i))
            ⟨by omega, by omega⟩ := by
        unfold compressEncodePoly
        simp
        rfl
      exact h_eq.trans h_collapse
    exact mlkem.key_expand_residual_D1_helper params pk_mlkem_key9
      h_t3_len_val h_s21_len pk_mlkem_key9_post3 ht3.2.1 s20_post3 h_s21_post2_h
  have h_D : keyEncodedTPrefix pk_mlkem_key9 params =
      slice (K_PKE.KeyGen params (arrayToSpecBytes pk_mlkem_key.private_seed)).1
        0 (384 * (k params : ℕ)) (by simp) :=
    mlkem.key_expand_residual_D_helper params
      (arrayToSpecBytes pk_mlkem_key.private_seed) pk_mlkem_key9
      h_b1_dlen h_a3_len_val t1_post3 t2_post1 a1_post2 a1_post3 a1_post7 a1_post8
      h_a1_len_val h_pv1_len h_s18_len h_arr_len h_s19_len_val h_app3_len
      s19_post1 h_i9_val h_arr_prefix pv_tmp1_post3 h_s18_ntt
      hb1.2.2.2.2.2.2.2.1 hb1.2.2.2.2.2.2.2.2 t1_post4 h_t3_eq_data
      h_t_hat_impl
  -- ════════════════════════════════════════════════════════════════════
  -- New conjunct (Inv4's 9th): byte-form witness for keyT, consumed by
  -- `mlkem.encapsulate_internal.spec` to discharge the c-equality residual.
  -- Chain: h_t_hat_impl (LHS = ByteEncode 12 (toPolyVecOfLen t2))
  --      + h_keyT_eq_t3 (toPolyVecOfLen t2 = keyT pk_mlkem_key9 params)
  -- ════════════════════════════════════════════════════════════════════
  have h_keyT_eq_t3 :
      toPolyVecOfLen t2 (k params) h_t3_len_val = keyT pk_mlkem_key9 params := by
    apply Vector.ext
    intro i hi
    simp only [toPolyVecOfLen, keyT, Vector.getElem_ofFn]
    -- Goal: toPoly t2.val[i] = toPoly pk_mlkem_key9.data.val[tOffset + i]
    fcongr 1
    -- pk_mlkem_key9.data.val = (a3 ++ t1 ++ _s).setSlice! matrixLen t2.val
    have hd9 :
        pk_mlkem_key9.data.val =
        (t_encoded_t_mut_back (t2, index_mut_back2 s21)).data.val := by
      rw [pk_mlkem_key9_post2]
    have h_pk9_list :
        pk_mlkem_key9.data.val =
        (a3.val ++ t1.val ++ _s.val).setSlice! (matrixLen params) t2.val := by
      rw [hd9, ht3.2.2.2.2.2, ha1.2.2.2.2.2]
    have h_in_t3 : i < t2.val.length := h_t3_len_val ▸ hi
    have h_pk9_dlen : pk_mlkem_key9.data.val.length = 24 := pk_mlkem_key9.data.property
    have h_kbnd := k_le_4 params
    have h_ksqbnd := k_sq_plus_2k_le_24 params
    have h_in_pk9 :
        tOffset params + i < pk_mlkem_key9.data.val.length := by
      rw [h_pk9_dlen]; unfold tOffset matrixLen; omega
    -- Bridge via `?`-form (avoids motive issues with dependent bounds).
    have h_eq_? :
        pk_mlkem_key9.data.val[tOffset params + i]? =
        t2.val[i]? := by
      rw [h_pk9_list]
      have h_mid := List.setSlice!_getElem?_middle
        (a3.val ++ t1.val ++ _s.val) t2.val (matrixLen params) (tOffset params + i)
        ⟨by unfold tOffset; omega,
         by unfold tOffset; rw [Nat.add_sub_cancel_left]; exact h_in_t3,
         by rw [h_app3_len]; unfold tOffset matrixLen; omega⟩
      rw [h_mid]
      unfold tOffset; rw [Nat.add_sub_cancel_left]
    rw [List.getElem?_eq_getElem h_in_pk9, List.getElem?_eq_getElem h_in_t3] at h_eq_?
    exact (Option.some.inj h_eq_?).symm
  have h_D1_keyT :
      keyEncodedTPrefix pk_mlkem_key9 params =
      Vector.cast (n := (k params : ℕ) * (32 * 12)) (m := 384 * (k params : ℕ))
        (by have := polyVector_byteEncode_size_cast (n := k params) 12; omega)
        (MLKEM.PolyVector.ByteEncode 12 (keyT pk_mlkem_key9 params)
          ⟨by omega, by omega⟩) := by
    -- After rewriting via `h_t_hat_impl`, the LHS becomes the same
    -- `Vector.cast` shape but with `toPolyVecOfLen t2 ...`; then
    -- `← h_keyT_eq_t3` rewrites the RHS's `keyT pk9 params` back to
    -- `toPolyVecOfLen t2 ...`, closing the goal by reflexivity.
    rw [h_t_hat_impl, ← h_keyT_eq_t3]
  refine ⟨?kinv, ?hpk, ?pseed, ?dlen, ?ksenc, ?mat, ?ektprefix, ?ekhash, ?ektprefix_keyT⟩
  case kinv =>
    -- Compose KeyInv through all four phases via transitivity.
    exact KeyInv.trans (KeyInv.trans (KeyInv.trans hb1.1 ha1.1) ht3.1) h_t_to_9
  case hpk =>
    -- Chain has_private_key equalities back to pk_mlkem_key.
    rw [pk_mlkem_key9_post10, ht3.2.2.2.2.1, ha1.2.1, hb1.2.1]
  case dlen =>
    -- `pk_mlkem_key9.data : Std.Array PolyElement 24#usize` ⇒ length = 24.
    exact pk_mlkem_key9.data.property
  case pseed =>
    -- ────────────────────────────────────────────────────────────────────
    -- Residual A: bridge `pk_mlkem_key9.public_seed.toSpec = ρ`
    -- where ρ = slice (K_PKE.KeyGen p d).1 (384·k) 32, closed via
    -- `KPKEStructure.KPKE_fst_suffix_eq_rho`.
    --
    -- LHS chain (each step is an equality between concrete keys/fields):
    --   pk_mlkem_key9.public_seed = (t_encoded_t_mut_back …).public_seed   (pk_mlkem_key9_post4)
    --   = (x✝⁴ (a3,t1,_s)).public_seed                                     (ht3.2.2.1)
    --   = (s_mut_back1 s18).public_seed                                    (ha1.2.2.2.1)
    --   ⇒ arrayToSpecBytes _ = (G (private_seed ‖ ⟨k⟩)).1                  (hb1.2.2.2.2.1)
    -- RHS: KPKE_fst_suffix_eq_rho gives slice ekPKE (384·k) 32 = (G …).1.
    rw [show pk_mlkem_key9.public_seed.toSpec
          = arrayToSpecBytes (s_mut_back1 s18).public_seed from by
        show arrayToSpecBytes _ = _
        rw [pk_mlkem_key9_post4, ht3.2.2.1, ha1.2.2.2.1]]
    rw [hb1.2.2.2.2.1]
    exact (KPKE_fst_suffix_eq_rho params pk_mlkem_key.private_seed.toSpec).symm
  case ksenc =>
    -- ────────────────────────────────────────────────────────────────────
    -- Residual B: keySEncoded pk_mlkem_key9 params = (K_PKE.KeyGen p d).2.
    --
    -- Spec-side bridge: `KPKE_snd_eq_byteEncode_NTT_CBD` in
    -- `Helpers/KPKEStructure.lean` rewrites the RHS as
    --   (PolyVector.ByteEncode 12 (Vector.ofFn fun i =>
    --      NTT(SamplePolyCBD(PRF η₁ σ i)))).cast _
    -- where σ = (G (private_seed.toSpec ‖ ⟨k⟩)).2.
    --
    -- Impl-side chain (each step is an equality between concrete fields):
    --   pk_mlkem_key9.data.val[sOffset + i]
    --   = (t_encoded_t_mut_back ...).data.val[sOffset + i]      (pk_mlkem_key9_post2)
    --   = (back_fn-of-ats_mut (a3,t1,_s)).data.val[sOffset + i] (ht3.2.2.2.2.2 + setSlice!_suffix)
    --   = _s.val[i]                                             (ha1.2.2.2.2.2 + append index)
    --   = (s_mut_back1 s18).data.val[sOffset + i]               (a1_post9 + drop_getElem)
    --   = s18.val[i]                                            (hb1.2.2.2.2.2.2.1)
    --   ⇒ toPoly = NTT(SamplePolyCBD(PRF η₁ σ i))               (h_s18_ntt)
    have h_pk9_dlen : pk_mlkem_key9.data.val.length = 24 := pk_mlkem_key9.data.property
    have h_b1_dlen : (s_mut_back1 s18).data.val.length = 24 := hb1.2.2.2.2.2.1
    have h_a3_len_val : a3.val.length = matrixLen params := by
      show a3.length = _; exact a3_post2.trans a1_post1
    have h_t2_len_val : t1.val.length = (k params : ℕ) := t1_post3
    have h__s_len_val : _s.val.length = 24 - matrixLen params - (k params : ℕ) :=
      a1_post3
    have h_t3_len_val : t2.val.length = (k params : ℕ) := t2_post1
    have hk_le : (k params : ℕ) ≤ 4 := k_le_4 params
    have hk2 : (k params : ℕ) * (k params : ℕ) + 2 * (k params : ℕ) ≤ 24 :=
      k_sq_plus_2k_le_24 params
    have h_app3_len : (a3.val ++ t1.val ++ _s.val).length = 24 := by
      simp only [List.length_append, h_a3_len_val, h_t2_len_val, h__s_len_val]
      unfold matrixLen; omega
    -- Per-index data-slot equality.
    have h_pk9_to_b1 : ∀ (i : ℕ) (_ : i < (k params : ℕ)),
        pk_mlkem_key9.data.val[sOffset params + i]'(by
          have := hk2; rw [h_pk9_dlen]; unfold sOffset matrixLen; omega) =
        (s_mut_back1 s18).data.val[sOffset params + i]'(by
          have := hk2; rw [h_b1_dlen]; unfold sOffset matrixLen; omega) := by
      intro i hi
      -- Bounds for sOffset + i.
      have h_si_lt_24 : sOffset params + i < 24 := by
        have := hk2; unfold sOffset matrixLen; omega
      have h_si_ge_mat_plus_t3 : matrixLen params + t2.val.length ≤ sOffset params + i := by
        rw [h_t3_len_val]; unfold sOffset; omega
      have h_si_in_pk9 : sOffset params + i < pk_mlkem_key9.data.val.length := by
        rw [h_pk9_dlen]; exact h_si_lt_24
      have h_si_in_b1 : sOffset params + i < (s_mut_back1 s18).data.val.length := by
        rw [h_b1_dlen]; exact h_si_lt_24
      -- Compute the LHS via setSlice! suffix → append-index in `_s` → drop view.
      have h_eq_? : pk_mlkem_key9.data.val[sOffset params + i]? =
                    (s_mut_back1 s18).data.val[sOffset params + i]? := by
        -- Rewrite pk_mlkem_key9.data.val.
        rw [show pk_mlkem_key9.data.val =
              ((a3.val ++ t1.val ++ _s.val).setSlice! (matrixLen params) t2.val) from by
          rw [pk_mlkem_key9_post2, ht3.2.2.2.2.2, ha1.2.2.2.2.2]]
        -- setSlice! suffix: index ≥ matrixLen + t2.length.
        rw [List.setSlice!_getElem?_suffix _ _ _ _ h_si_ge_mat_plus_t3]
        -- Append index in `_s` part: matrixLen + k ≤ sOffset + i < matrixLen + k + |_s|.
        have h_ab_len : (a3.val ++ t1.val).length = matrixLen params + (k params : ℕ) := by
          rw [List.length_append, h_a3_len_val, h_t2_len_val]
        have h_si_ge_ab : (a3.val ++ t1.val).length ≤ sOffset params + i := by
          rw [h_ab_len]; unfold sOffset; omega
        rw [List.getElem?_append_right h_si_ge_ab]
        rw [h_ab_len]
        -- _s.val = (s_mut_back1 s18).data.val.drop (matrixLen + k).
        rw [a1_post9]
        rw [List.getElem?_drop]
        fcongr 1
        unfold sOffset; omega
      rw [List.getElem?_eq_getElem h_si_in_pk9,
          List.getElem?_eq_getElem h_si_in_b1] at h_eq_?
      exact Option.some.inj h_eq_?
    -- Bridge keySEncoded pk_mlkem_key9 = (K_PKE.KeyGen ..).2 via the spec bridge.
    -- First establish entry-wise equality on the s-slot view.
    have h_keys :
        keyS_std pk_mlkem_key9 params =
        (Vector.ofFn fun (i : Fin (k params : ℕ)) =>
          MLKEM.NTT (MLKEM.SamplePolyCBD
            (MLKEM.PRF (η₁ params)
              (MLKEM.G (arrayToSpecBytes pk_mlkem_key.private_seed ‖
                #v[((k params : ℕ) : Byte)])).2
              ((i : ℕ) : Byte)))) := by
      apply Vector.ext
      intro i hi
      simp only [keyS_std, Vector.getElem_ofFn]
      rw [h_pk9_to_b1 i hi]
      rw [hb1.2.2.2.2.2.2.1 i hi]
      exact h_s18_ntt i hi
    show keySEncoded pk_mlkem_key9 params = _
    unfold keySEncoded
    rw [h_keys, KPKE_snd_eq_byteEncode_NTT_CBD params pk_mlkem_key.private_seed.toSpec]
    rfl
  case mat =>
    -- ────────────────────────────────────────────────────────────────────
    -- Residual C: matrix slot fact after transpose.
    -- Chain via the widened ats_mut / t_encoded_t_mut data frames:
    --   pk_mlkem_key9.data  ←post2←  (t_encoded_t_mut_back …).data
    --   .val =  setSlice! (matrixLen p) ↑t2 ((ats_mut_back).data.val)
    --       (ht3.2.2.2.2.2)
    --   .val =  setSlice! (matrixLen p) ↑t2 (↑a3 ++ ↑t1 ++ ↑_s)
    --       (ha1.2.2.2.2.2)
    --   For i < matrixLen, setSlice! preserves; for i < a3.length = matrixLen,
    --   List.getElem_append_left gives a3[i].
    --   a3_post3 (transpose) bridges a3[row*nr+col] ↔ a1[col*nr+row].
    --   a1_post7 (slot frame) bridges a1[i] ↔ (s_mut_back1 s18).data[i] for i < matrixLen.
    --   hb1's matrix conjunct closes (s_mut_back1 s18).data[col*k+row] = SampleNTT(...).
    intro row col ⟨h_row, h_col⟩
    have hk_le' : (k params : ℕ) ≤ 4 := k_le_4 params
    have hk2 := k_sq_plus_2k_le_24 params
    have hmlen_24 : matrixLen params ≤ 24 := by unfold matrixLen; omega
    have h_rc : row * (k params : ℕ) + col < matrixLen params := by
      unfold matrixLen
      have h1 : (row + 1) * (k params : ℕ) ≤ (k params : ℕ) * (k params : ℕ) :=
        Nat.mul_le_mul_right _ h_row
      have h2 : row * (k params : ℕ) + (k params : ℕ) = (row + 1) * (k params : ℕ) := by ring
      omega
    have h_cr : col * (k params : ℕ) + row < matrixLen params := by
      unfold matrixLen
      have h1 : (col + 1) * (k params : ℕ) ≤ (k params : ℕ) * (k params : ℕ) :=
        Nat.mul_le_mul_right _ h_col
      have h2 : col * (k params : ℕ) + (k params : ℕ) = (col + 1) * (k params : ℕ) := by ring
      omega
    have h_rc_24 : row * (k params : ℕ) + col < 24 := by omega
    have h_cr_24 : col * (k params : ℕ) + row < 24 := by omega
    have h_pk9_dlen : pk_mlkem_key9.data.val.length = 24 := pk_mlkem_key9.data.property
    have h_rc_d9 : row * (k params : ℕ) + col < pk_mlkem_key9.data.val.length := by
      rw [h_pk9_dlen]; exact h_rc_24
    -- Length facts
    have h_a3_len_val : a3.val.length = matrixLen params := by
      show a3.length = _; exact a3_post2.trans a1_post1
    have h_t2_len_val : t1.val.length = (k params : ℕ) := t1_post3
    have h__s_len_val : _s.val.length = 24 - matrixLen params - (k params : ℕ) :=
      a1_post3
    have h_app3_len : (a3.val ++ t1.val ++ _s.val).length = 24 := by
      simp only [List.length_append, h_a3_len_val, h_t2_len_val, h__s_len_val]
      unfold matrixLen; omega
    have h_b1_dlen : (s_mut_back1 s18).data.val.length = 24 :=
      hb1.2.2.2.2.2.1
    have h_a1_len_val : a1.val.length = matrixLen params := by
      rw [a1_post7, List.length_take, h_b1_dlen]; omega
    have h_nrows_val : (pk_mlkem_key.params.n_rows : ℕ) = (k params : ℕ) := h_nrows
    -- Step 1: pk_mlkem_key9.data[row*k+col] = a3.val[row*k+col]
    have h_pk9_to_a3 :
        pk_mlkem_key9.data[row * (k params : ℕ) + col]'h_rc_d9 =
        a3.val[row * (k params : ℕ) + col]'(h_a3_len_val.symm ▸ h_rc) := by
      show pk_mlkem_key9.data.val[row * (k params : ℕ) + col]'h_rc_d9 = _
      -- Use ?-form to avoid motive issues with dependent bounds.
      have hd9 : pk_mlkem_key9.data.val = (t_encoded_t_mut_back (t2, index_mut_back2 s21)).data.val := by
        rw [pk_mlkem_key9_post2]
      have h_pk9_list :
          pk_mlkem_key9.data.val =
          (a3.val ++ t1.val ++ _s.val).setSlice! (matrixLen params) t2.val := by
        rw [hd9, ht3.2.2.2.2.2, ha1.2.2.2.2.2]
      have h_in_pk9 : row * (k params : ℕ) + col < pk_mlkem_key9.data.val.length := h_rc_d9
      have h_in_a3 : row * (k params : ℕ) + col < a3.val.length := h_a3_len_val.symm ▸ h_rc
      have h_app_in : row * (k params : ℕ) + col < (a3.val ++ t1.val ++ _s.val).length := by
        rw [h_app3_len]; exact h_rc_24
      have h_ab_in : row * (k params : ℕ) + col < (a3.val ++ t1.val).length := by
        rw [List.length_append, h_a3_len_val, h_t2_len_val]; omega
      have h_eq_? : pk_mlkem_key9.data.val[row * (k params : ℕ) + col]? =
                    a3.val[row * (k params : ℕ) + col]? := by
        rw [h_pk9_list]
        rw [List.setSlice!_getElem?_prefix _ _ _ _ h_rc]
        rw [List.getElem?_append_left h_ab_in]
        rw [List.getElem?_append_left (by rw [h_a3_len_val]; exact h_rc)]
      rw [List.getElem?_eq_getElem h_in_pk9, List.getElem?_eq_getElem h_in_a3] at h_eq_?
      exact Option.some.inj h_eq_?
    -- Step 2: a3.val[row*k+col] = a1.val[col*k+row] via transpose (a3_post3)
    have h_row_nr : row < (pk_mlkem_key.params.n_rows : ℕ) := by rw [h_nrows_val]; exact h_row
    have h_col_nr : col < (pk_mlkem_key.params.n_rows : ℕ) := by rw [h_nrows_val]; exact h_col
    have h_tr := a3_post3 row col h_row_nr h_col_nr
    have h_tr' :
        toPoly (a3.val[row * (k params : ℕ) + col]'(h_a3_len_val.symm ▸ h_rc)) =
        toPoly (a1.val[col * (k params : ℕ) + row]'(h_a1_len_val.symm ▸ h_cr)) := by
      have := h_tr; simp only [h_nrows_val] at this; exact this
    -- Step 3: a1.val[col*k+row] = (s_mut_back1 s18).data.val[col*k+row]
    have h_a1_to_b1 :
        a1.val[col * (k params : ℕ) + row]'(h_a1_len_val.symm ▸ h_cr) =
        (s_mut_back1 s18).data.val[col * (k params : ℕ) + row]'(h_b1_dlen.symm ▸ h_cr_24) := by
      have h_in_a1 : col * (k params : ℕ) + row < a1.val.length := h_a1_len_val.symm ▸ h_cr
      have h_in_b1 : col * (k params : ℕ) + row < (s_mut_back1 s18).data.val.length :=
        h_b1_dlen.symm ▸ h_cr_24
      have h_eq_? : a1.val[col * (k params : ℕ) + row]? =
                    (s_mut_back1 s18).data.val[col * (k params : ℕ) + row]? := by
        rw [a1_post7]; simp_lists
      rw [List.getElem?_eq_getElem h_in_a1, List.getElem?_eq_getElem h_in_b1] at h_eq_?
      exact Option.some.inj h_eq_?
    -- Step 4: apply hb1's matrix conjunct (swap row/col)
    have h_mat := hb1.2.2.2.2.2.2.2.2 col row h_col h_row
    -- Final chain.
    show toPoly pk_mlkem_key9.data[row * (k params : ℕ) + col] = _
    rw [show pk_mlkem_key9.data[row * (k params : ℕ) + col]'h_rc_d9 =
            a3.val[row * (k params : ℕ) + col]'(h_a3_len_val.symm ▸ h_rc) from h_pk9_to_a3]
    rw [h_tr', h_a1_to_b1]
    -- After this we have:
    --   toPoly (s_mut_back1 s18).data.val[col*k+row] = SampleNTT(expandAEntrySeed (G (pk_mlkem_key.private_seed.toSpec ‖ ...)).1 col row)
    -- h_mat gives the same thing with arrayToSpecBytes; they agree by rfl.
    exact h_mat
  -- ════════════════════════════════════════════════════════════════════
  -- Residuals D + E (CASES ektprefix + ekhash).
  -- Both cases discharge from the shared `h_D` above:
  --   * D (impl encoding) via `mlkem.key_expand_residual_D_helper`
  --     (D2 algebraic chain) + `mlkem.key_expand_residual_D1_helper`
  --     (D1 per-byte impl encoding chain).
  --   * E (ekhash) closes by composing pk_mlkem_key9_post11 with the
  --     encoded_t/public_seed/SHA3 chain (a..e below) and `h_D`.
  -- ════════════════════════════════════════════════════════════════════
  case ektprefix =>
    -- ────────────────────────────────────────────────────────────────────
    -- Residual D: keyEncodedTPrefix pk_mlkem_key9 params =
    --   slice (K_PKE.KeyGen params pk_mlkem_key.private_seed.toSpec).1
    --     0 (384 * (k params : ℕ)) _
    --
    -- SPEC SIDE (CLOSED — three lemmas in `Helpers/KPKEStructure.lean`,
    -- one in `Bridges/MatrixVectorMul.lean`):
    --   • `KPKE_t_hat_explicit params d` yields explicit Â, s, e with
    --     entry characterisations and
    --     (K_PKE.KeyGen p d).1 = (ByteEncode 12 (Â * NTT s + NTT e) ‖ ρ).cast _.
    --   • `cast_slice_eq_of_append₂_prefix` peels off the (384·k)-byte
    --     prefix as `(ByteEncode 12 (Â * NTT s + NTT e)).cast _`.
    --   • `keygen_t_hat_chain` (Bridges/MatrixVectorMul.lean, G2.3)
    --     reduces the impl-side `t1_post4` shape
    --       NTT e + (Â_impl · (NTT s).map R).map Rinv
    --     into the spec's `Â * NTT s + NTT e` form, given an entry-wise
    --     Â_impl = Â proof.
    --
    -- IMPL→SPEC ALGEBRA (DRAFTED + COMPILES IN ISOLATION):
    --   t[i] poly = NTT e_spec[i]   (via hb1.2.2.2.2.2.2.2.1 + h_e_spec)
    --   s19 poly   = (NTT s_spec).map R   (via s19_post1 + h_arr_prefix +
    --                                          pv_tmp1_post3 + h_s18_ntt + h_s_spec)
    --   a1 poly    = Â_spec           (via a1_post7 + hb1.2.2.2.2.2.2.2.2 +
    --                                          expandAEntrySeed + h_Â_spec)
    --   t2 poly    = t1 poly          (via t2_post4 + ha1.2.2.2.2.2 + slice/append index)
    --   `apply keygen_t_hat_chain` then closes Â_spec * NTT s + NTT e.
    --
    -- D1 IMPL ENCODING CHAIN.
    --   Discharged via `mlkem.key_expand_residual_D1_helper` (file-scope
    --   private theorem, ~150 LoC).  The helper takes the raw `s21_post2`
    --   (`compressEncodePoly`-form, bound `(i+1)*(32·12) ≤ s21.length`)
    --   plus the encoded_t chain (`pk_mlkem_key9_post3`, `ht3.2.1`,
    --   `s20_post3`) and performs the per-byte chase via
    --   `polyVector_slice_byteEncode_eq` and the d=12 collapse of
    --   `compressEncodePoly` (`unfold compressEncodePoly; simp; rfl`).
    --   See the helper's docstring and the call site under case D.
    --
    -- Residual D — discharged via the `h_D` extracted before the refine.
    -- See the helper invocation above for the actual proof obligation;
    -- both cases share it.
    exact h_D
  case ekhash =>
    -- ────────────────────────────────────────────────────────────────────
    -- Residual E: pk_mlkem_key9.encaps_key_hash.toSpec = SHA3-256(ekPKE)
    -- where ekPKE := (K_PKE.KeyGen params pk_mlkem_key.private_seed.toSpec).1.
    --
    -- Structure: (a), (b), (d), (e) are closed; (c)
    -- h_residD = h_D (the shared Residual D `have`).
    -- ────────────────────────────────────────────────────────────────────
    -- (a) keyEncodedTPrefix depends only on encoded_t; pk_mlkem_key9_post3
    --     gives encoded_t-equality between pk_mlkem_key9 and the
    --     t_encoded_t_mut_back image.
    have h_kept_eq :
        keyEncodedTPrefix (t_encoded_t_mut_back (t2, index_mut_back2 s21)) params =
        keyEncodedTPrefix pk_mlkem_key9 params := by
      have h_enc_eq :
          (t_encoded_t_mut_back (t2, index_mut_back2 s21)).encoded_t =
          pk_mlkem_key9.encoded_t :=
        pk_mlkem_key9_post3.symm
      unfold keyEncodedTPrefix
      apply Vector.ext
      intro i hi
      simp only [Vector.getElem_ofFn]
      simp only [h_enc_eq]
    -- (b) public_seed chain through ht3 → ha1 → hb1.  `hb1.2.2.2.2.1`
    --     uses `arrayToSpecBytes` (not the `.toSpec` abbrev) so we state
    --     the hypothesis in the underlying form to match the rewrite.
    have h_pubseed_chain :
        arrayToSpecBytes (t_encoded_t_mut_back (t2, index_mut_back2 s21)).public_seed =
        (G (arrayToSpecBytes pk_mlkem_key.private_seed ‖
            #v[((k params : ℕ) : Byte)])).1 := by
      rw [ht3.2.2.1, ha1.2.2.2.1, hb1.2.2.2.2.1]
      rfl
    -- (c) Residual D — shared with case ektprefix via `h_D`.
    have h_residD :
        keyEncodedTPrefix pk_mlkem_key9 params =
        Spec.slice (K_PKE.KeyGen params (arrayToSpecBytes pk_mlkem_key.private_seed)).1
          0 (384 * (k params : ℕ)) (by simp) :=
      h_D
    -- (d) (G ..).1 = ρ = slice ekPKE (384·k) 32  (KPKE_fst_suffix_eq_rho).
    have h_pubseed_to_ekPKE :
        (G (arrayToSpecBytes pk_mlkem_key.private_seed ‖
            #v[((k params : ℕ) : Byte)])).1 =
        Spec.slice (K_PKE.KeyGen params (arrayToSpecBytes pk_mlkem_key.private_seed)).1
          (384 * (k params : ℕ)) 32 (by simp) :=
      (KPKE_fst_suffix_eq_rho params (arrayToSpecBytes pk_mlkem_key.private_seed)).symm
    -- (e) `slice ekPKE 0 (384·k) ‖ slice ekPKE (384·k) 32 = ekPKE` (cast-aware)
    --     closed via the `slice_append_slice_self` helper landed
    --     in `Helpers/VectorSliceCastAppend.lean`.  Stated with `‖`
    --     to match the goal's notation (the helper proves the same
    --     statement with `++`; the two are defeq).
    have h_concat_ekPKE :
        (Spec.slice (K_PKE.KeyGen params (arrayToSpecBytes pk_mlkem_key.private_seed)).1
          0 (384 * (k params : ℕ)) (by simp) ‖
         Spec.slice (K_PKE.KeyGen params (arrayToSpecBytes pk_mlkem_key.private_seed)).1
          (384 * (k params : ℕ)) 32 (by simp))
        = (K_PKE.KeyGen params (arrayToSpecBytes pk_mlkem_key.private_seed)).1 :=
      Helpers.slice_append_slice_self
        (K_PKE.KeyGen params (arrayToSpecBytes pk_mlkem_key.private_seed)).1
        (384 * (k params : ℕ)) 32 rfl
    -- Final assembly: post11 gives the SHA3 LHS shape; rewrite both
    -- arguments of sha3_256 down to ekPKE, then the two sides match.
    -- We normalise the goal's `.toSpec` abbrev to `arrayToSpecBytes` first
    -- so the rewrites match the bridge lemmas verbatim.
    show arrayToSpecBytes pk_mlkem_key9.encaps_key_hash =
      SHA3.sha3_256 (K_PKE.KeyGen params (arrayToSpecBytes pk_mlkem_key.private_seed)).1
    rw [pk_mlkem_key9_post11, h_kept_eq, h_pubseed_chain, h_residD,
        h_pubseed_to_ekPKE]
    exact congrArg SHA3.sha3_256 h_concat_ekPKE
  case ektprefix_keyT =>
    -- ────────────────────────────────────────────────────────────────────
    -- New 9th conjunct: keyEncodedTPrefix pk9 params
    --   = (ByteEncode 12 (keyT pk9 params)).cast _
    -- Discharged from the shared `h_D1_keyT` above (computed from
    -- `h_t_hat_impl` + `h_keyT_eq_t3`).
    -- ────────────────────────────────────────────────────────────────────
    exact h_D1_keyT
  -- ============================================================

end Symcrust.Properties.MLKEM
