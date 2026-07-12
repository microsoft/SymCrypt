/-
  # Encoding/KeySetValue/Decap.lean — DecapsulationKey arm specs.

  Contains `ksv_decap_after_prep`, `ksv_decap_branch_b`, and `ksv_decap`
  (the DecapsulationKey format-arm dispatcher).  Independent of
  `KeySetValue/Encap.lean` — the two files build in parallel.
-/
import Symcrust.Properties.MLKEM.Encoding.KeySetValue.Prelude

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust

open scoped Spec.Notations
open symcrust.common
namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

/-! ### `ksv_decap_after_prep` — terminal Decap arm content

Opaque ~25-bind tail starting from `(p, t_encoded_t_mut_back)`:
decode `t` from `encoded_t[0..cb]`, branch on decode error, copy
`public_seed` from `pb_src[2·cb..2·cb+32]`, re-expand A and recompute
H(ek), compare `H(ek)` against `pb_src[2·cb+32..2·cb+64]` via
`const_time_slices_equal`, copy `private_random` from
`pb_src[2·cb+64..2·cb+96]`, run final length massert.

Reachable error variants: `NoError`, `InvalidBlob` (either from t
decode at d=12, or from H(ek) mismatch).  Other variants ruled out
by the input format and the per-call specs. -/
@[step]
theorem ksv_decap_after_prep.spec
    {params : ParameterSet}
    (pb_src : Slice U8) (pk_mlkem_key : mlkem.key.Key)
    (cb_encoded_vector : Usize)
    (p_comp_temps : mlkem.ntt.InternalComputationTemporaries)
    (i9 : Usize)
    (t : Slice PolyElement)
    (encoded_t : Array U8 1536#usize)
    (t_encoded_t_mut_back :
      Slice PolyElement × Array U8 1536#usize → mlkem.key.Key)
    (h_wf : wfKey pk_mlkem_key params)
    (h_cb : cb_encoded_vector.val = 384 * (k params : ℕ))
    (h_i9 : i9.val = 2 * cb_encoded_vector.val)
    (h_pas_len : pb_src.length = 768 * (k params : ℕ) + 96)
    (h_p1_len : t.length = (k params : ℕ))
    (h_p1_wf : ∀ i (_ : i < t.length), wfPoly t.val[i])
    (h_p2_len : encoded_t.val.length = 1536)
    /- Encoded_t window mirrors `pb_src[cb..2cb]` — established by
       the preceding `ksv_decap_decode_t_prep` step. -/
    (h_p2_enc : ∀ (j : Nat) (h_j : j < cb_encoded_vector.val),
                  encoded_t.val[j]'(by simp only [h_p2_len]; have := h_cb; have := k_le_4 params; scalar_tac) =
                  pb_src.val[cb_encoded_vector.val + j]'(by
                    have := h_pas_len; have := h_cb; have := k_le_4 params;
                    scalar_tac))
    /- Decoded `ŝ` vector written into the s-slot by the preceding
       `s_mut_back` (before this leaf runs).  Threaded so `after_prep`
       can expose `key'`'s s-slot content as `s2` (used for the
       `keySEncoded` FC equality at the toplevel). -/
    (s2 : Slice PolyElement)
    (h_s2_len : s2.length = (k params : ℕ))
    /- Back-closure semantics — assumes the chain
       `s_mut_back ∘ index_mut_back` has been applied. -/
    (h_back_wf : ∀ (t' : Slice PolyElement) (enc' : Array U8 1536#usize)
                   (h_t'_len : t'.length = (k params : ℕ))
                   (_h_t'_wf : ∀ i (_ : i < t'.length), wfPoly t'.val[i]),
                   wfKey (t_encoded_t_mut_back (t', enc')) params ∧
                   (t_encoded_t_mut_back (t', enc')).params = pk_mlkem_key.params ∧
                   (t_encoded_t_mut_back (t', enc')).n_rows = pk_mlkem_key.n_rows ∧
                   (t_encoded_t_mut_back (t', enc')).encoded_t = enc' ∧
                   /- Elementwise data fact: the back-closure overwrites the
                      matrix-T slots with `t'.val`.  Stated elementwise rather
                      than `setSlice!` so the caller can supply a different
                      `pre_data` (Decap has an extra s-prefix write before
                      this back-closure runs).  Needed to close
                      `wfDecapKey.toWfEncapKey.byte_form_t`. -/
                   (∀ (j : ℕ) (h_j : j < (k params : ℕ)),
                     (t_encoded_t_mut_back (t', enc')).data.val[matrixLen params + j]'(by
                       have hl : (t_encoded_t_mut_back (t', enc')).data.val.length = 24 :=
                         (t_encoded_t_mut_back (t', enc')).data.property
                       have := k_sq_plus_2k_le_24 params
                       unfold matrixLen; grind) =
                     t'.val[j]'(by
                       rw [show t'.val.length = t'.length from rfl, h_t'_len]
                       exact h_j)) ∧
                   /- S-slot content: the back-closure leaves the `ŝ` window
                     `[sOffset, sOffset + k)` equal to the decoded `s2` written
                     by the preceding `s_mut_back`.  Threaded so `after_prep`
                     can expose the s-slot content of `key'` (used for the
                     `keySEncoded` FC equality). -/
                   (∀ (j : ℕ) (h_j : j < (k params : ℕ)),
                    (t_encoded_t_mut_back (t', enc')).data.val[sOffset params + j]'(by
                      have hl : (t_encoded_t_mut_back (t', enc')).data.val.length = 24 :=
                        (t_encoded_t_mut_back (t', enc')).data.property
                      have := k_sq_plus_2k_le_24 params
                      unfold sOffset matrixLen; grind) =
                    s2.val[j]'(by
                      rw [show s2.val.length = s2.length from rfl, h_s2_len];
                      exact h_j))) :
    ksv_decap_after_prep pb_src pk_mlkem_key cb_encoded_vector
        p_comp_temps i9 t encoded_t t_encoded_t_mut_back
      ⦃ err key' =>
          /- Universal conjuncts. -/
          wfKey key' params ∧
          key'.params = pk_mlkem_key.params ∧
          key'.n_rows = pk_mlkem_key.n_rows ∧
          match err with
          | Error.NoError =>
              /- S-slot content: the a_transpose regeneration and the
                 t-slot copy leave the `ŝ` data window untouched, so `key'`'s
                 s-slot equals the decoded `s2`.  Combined with the decode
                 fidelity + canonicity this yields `keySEncoded key' = window`
                 for the s-prefix FC equality (Phase 5). -/
              (∀ (j : ℕ) (h_j : j < (k params : ℕ)),
                key'.data.val[sOffset params + j]'(by
                  have hl : key'.data.val.length = 24 := key'.data.property
                  have := k_sq_plus_2k_le_24 params
                  unfold sOffset matrixLen; grind) =
                s2.val[j]'(by
                  rw [show s2.val.length = s2.length from rfl, h_s2_len]; exact h_j)) ∧
              /- DecapsulationKey-arm FC: encoded_t prefix matches
                 `pb_src[cb..2cb]`; ρ matches `pb_src[2cb..2cb+32]`;
                 H(ek) verified via const-time-eq; private_random
                 matches `pb_src[2cb+64..2cb+96]`; flags reflect
                 a full decapsulation key. -/
              keyEncodedTPrefix key' params = pb_src.toSpecWindow (384 * (k params : ℕ)) (384 * (k params : ℕ)) (by have := k_le_4 params; simp [h_pas_len]; grind) ∧
              key'.public_seed.toSpec = pb_src.toSpecWindow (768 * (k params : ℕ)) 32 (by simp [h_pas_len]) ∧
              key'.encaps_key_hash.toSpec = pb_src.toSpecWindow (768 * (k params : ℕ) + 32) 32 (by simp [h_pas_len]) ∧
              key'.encaps_key_hash.toSpec = Spec.SHA3.sha3_256 (encapsulationKey key' params) ∧
              key'.private_random.toSpec = pb_src.toSpecWindow (768 * (k params : ℕ) + 64) 32 (by simp [h_pas_len]) ∧
              key'.has_private_seed = false ∧ key'.has_private_key = true ∧
              /- Bundled crypto-level commitments for the decapsulation key —
                 consumed by `mlkem.decapsulate.spec` (which preconditions
                 `wfDecapKey`).  `wfDecapKey = wfEncapKey + has_private_key`. -/
              wfDecapKey key' params
          /- `InvalidBlob` is reachable from two sources:
             (i) `vector_decode_and_decompress` at d=12 (>= q coefficient),
             (ii) `const_time_slices_equal` mismatch on H(ek). -/
          | Error.InvalidBlob => True
          | _ => False ⦄ := by
  unfold ksv_decap_after_prep
  have hk_ge2 := k_ge_2 params
  have hk_le4 := k_le_4 params
  step    -- s6 := encoded_t[0..cb]
  -- Capture the slice's val/length posts before they're shadowed by step*.
  set err_slice := s6 with h_err_slice
  have err_slice_val_eq : err_slice.val =
      List.slice 0 cb_encoded_vector.val encoded_t.to_slice.val := s6_post1
  have err_slice_len : err_slice.length = cb_encoded_vector.val - 0 := s6_post2
  step    -- (sc_error1, t1) := vector_decode_and_decompress s6 12 t
  case h_wf_in => exact h_p1_wf
  step    -- b1 := sc_error1.ne NoError
  split
  · -- b1 = true → error path
    rename_i hb_true
    have h_sc_ne : sc_error1 ≠ Error.NoError := by
      have := b1_post.symm.trans hb_true
      exact of_decide_eq_true this
    have h_sc_eq : sc_error1 = Error.InvalidBlob := by
      cases hsc : sc_error1
      all_goals first
        | rfl
        | (rw [hsc] at h_sc_ne; exact (h_sc_ne rfl).elim)
        | (rw [hsc] at sc_error1_post3; exact sc_error1_post3.elim)
    subst h_sc_eq
    have h_t1_wf := sc_error1_post2
    have h_t1_len : t1.length = (k params : ℕ) := by
      rw [sc_error1_post1]; exact h_p1_len
    have hb := h_back_wf t1 encoded_t h_t1_len h_t1_wf
    simp only [WP.spec_ok]
    refine ⟨hb.1, hb.2.1, hb.2.2.1, ?_⟩
    simp
  · -- b1 = false → NoError path
    rename_i hb_false
    have h_sc_eq : sc_error1 = Error.NoError := by
      by_contra hne
      apply hb_false
      rw [b1_post]; exact decide_eq_true hne
    subst h_sc_eq
    simp only at sc_error1_post3
    have h_t1_wf := sc_error1_post2
    have h_t1_len : t1.length = (k params : ℕ) := by
      rw [sc_error1_post1]; exact h_p1_len
    have hb := h_back_wf t1 encoded_t h_t1_len h_t1_wf
    set pk1 := t_encoded_t_mut_back (t1, encoded_t) with h_pk1_def
    have h_pk1_wf : wfKey pk1 params := hb.1
    have h_pk1_params : pk1.params = pk_mlkem_key.params := hb.2.1
    have h_pk1_n_rows : pk1.n_rows = pk_mlkem_key.n_rows := hb.2.2.1
    have h_pk1_enc : pk1.encoded_t = encoded_t := hb.2.2.2.1
    have h_pk1_data_elt : ∀ (j : ℕ) (h_j : j < (k params : ℕ)),
        pk1.data.val[matrixLen params + j]'(by
          have hl : pk1.data.val.length = 24 := pk1.data.property
          have := k_sq_plus_2k_le_24 params
          unfold matrixLen; grind) =
        t1.val[j]'(by
          rw [show t1.val.length = t1.length from rfl, h_t1_len]; exact h_j) :=
      hb.2.2.2.2.1
    have h_pk1_n_rows_val : pk1.n_rows.val = (k params : ℕ) :=
      h_pk1_n_rows ▸ wfKey.n_rows_ok h_wf
    have h_pubseed_len : pk1.public_seed.val.length = 32 := pk1.public_seed.property
    step    -- s7 := pk1.public_seed.to_slice
    step    -- (s8, to_slice_mut_back) := pk1.public_seed.to_slice_mut
    step    -- i10 := i9 + s7.len
    step    -- s9 := pb_src[i9..i10]
    step    -- s10 := copy_from_slice s8 s9
    case hlen =>
      have h_s7_len : s7.length = 32 := by rw [s7_post]; exact h_pubseed_len
      simp [s8_post1, s9_post2, i10_post, h_s7_len]
    step    -- s11 := (to_slice_mut_back s10).to_slice
    step    -- pb_curr := i9 + s11.len
    -- Construct the post-public_seed key explicitly.
    set pk1' : mlkem.key.Key :=
      { algorithm_info := pk1.algorithm_info, has_private_seed := pk1.has_private_seed,
        has_private_key := pk1.has_private_key, private_seed := pk1.private_seed,
        private_random := pk1.private_random, public_seed := to_slice_mut_back s10,
        encoded_t := pk1.encoded_t, encaps_key_hash := pk1.encaps_key_hash,
        params := pk1.params, n_rows := pk1.n_rows, data := pk1.data } with h_pk1'_def
    have h_pk1'_wf : wfKey pk1' params := by
      refine ⟨?_, ?_, ?_⟩
      · exact wfKey.params_ok (self := pk1) h_pk1_wf
      · exact wfKey.n_rows_ok (self := pk1) h_pk1_wf
      · exact wfKey.data_wf (self := pk1) h_pk1_wf
    -- Step the matrix expansion with explicit params instantiation.
    step with mlkem.key_expand_public_matrix_from_public_seed.spec params pk1' p_comp_temps h_pk1'_wf
    have h_pk3_params_eq : pk_mlkem_key3.params = pk_mlkem_key.params := by
      have h2 : pk_mlkem_key3.params = _ :=
        wfKey.params_ok (self := pk_mlkem_key3) pk_mlkem_key3_post1
      have h1 : pk_mlkem_key.params = _ :=
        wfKey.params_ok (self := pk_mlkem_key) h_wf
      rw [h2, h1]
    have h_pk3_nrows_val : pk_mlkem_key.params.n_rows.val = (k params : ℕ) :=
      wfInternalParams.n_rows_val (wfKey.params_ok (self := pk_mlkem_key) h_wf)
    step with Bridges.mlkem.key.Key.a_transpose_mut.spec pk_mlkem_key3 params pk_mlkem_key3_post1
    step
    case h_wf => exact s12_post2
    -- Build pk4 = a_transpose_mut_back s13 and discharge its key invariants.
    have h_s13_len : s13.length = matrixLen params := by grind
    have h_pk4_all := s12_post4 s13 h_s13_len s13_post1
    set pk4 := a_transpose_mut_back s13 with h_pk4_def
    have h_pk4_wf : wfKey pk4 params := h_pk4_all.1
    have h_pk4_params : pk4.params = pk_mlkem_key3.params := h_pk4_all.2.1
    have h_pk4_n_rows : pk4.n_rows = pk_mlkem_key3.n_rows := h_pk4_all.2.2.1
    have h_pk4_pubseed : pk4.public_seed = pk_mlkem_key3.public_seed := h_pk4_all.2.2.2.1
    have h_pk4_enc : pk4.encoded_t = pk_mlkem_key3.encoded_t := h_pk4_all.2.2.2.2.1
    have h_pk4_n_rows_val : pk4.n_rows.val = (k params : ℕ) :=
      wfKey.n_rows_ok h_pk4_wf
    step with mlkem.key_compute_encapsulation_key_hash.spec params pk4 p_comp_temps1 h_pk4_wf
    -- After H(ek): pk_mlkem_key5 is the post-H key.
    have h_s11_len : s11.length = 32 := by
      have h1 : (to_slice_mut_back s10).val.length = 32 :=
        (to_slice_mut_back s10).property
      simp [s11_post, Std.Array.to_slice, h1]
    have h_i9_val : i9.val = 768 * (k params : ℕ) := by
      rw [h_i9, h_cb]; ring
    have h_s7_len : s7.len.val = 32 := by
      rw [s7_post]; exact pk1.public_seed.property
    have h_i10_val : i10.val = 768 * (k params : ℕ) + 32 := by
      rw [i10_post, h_i9_val, h_s7_len]
    have h_pb_curr_val : pb_curr.val = 768 * (k params : ℕ) + 32 := by
      have h1 : s11.len.val = s11.length := rfl
      rw [pb_curr_post, h_i9_val, h1, h_s11_len]
    -- Step through s14, s15 (both = pk_mlkem_key5.encaps_key_hash.to_slice).
    step    -- s14
    step    -- s15
    have h_s14_len : s14.length = 32 := by
      rw [s14_post]; exact pk_mlkem_key5.encaps_key_hash.property
    have h_s15_len : s15.length = 32 := by
      rw [s15_post]; exact pk_mlkem_key5.encaps_key_hash.property
    step    -- i12 := pb_curr + s14.len
    step    -- s16 := pb_src[pb_curr..i12]
    step with common.const_time_slices_equal_local.spec s15 s16    -- b2 := const_time_slices_equal s15 s16
    case h_len =>
      have h_s14_len_eq : s14.len.val = 32 := by
        show s14.length = 32; exact h_s14_len
      have h_i12_val : i12.val = 768 * (k params : ℕ) + 64 := by
        rw [i12_post, h_pb_curr_val, h_s14_len_eq]
      simp [s16_post2, h_i12_val, h_pb_curr_val, h_s15_len]
    split
    · -- b2 = true → continue to private_random copy
      rename_i hb2_true
      have h_b2_iff := b2_post.mp hb2_true
      -- s15.val = s16.val: encaps_key_hash bytes match pb_src window.
      step    -- s17 := pk_mlkem_key5.encaps_key_hash.to_slice
      step    -- pb_curr1 := pb_curr + s17.len
      step    -- s18 := pk_mlkem_key5.private_random.to_slice
      step    -- (s19, to_slice_mut_back1) := pk_mlkem_key5.private_random.to_slice_mut
      step    -- i14 := pb_curr1 + s18.len
      step    -- s20 := pb_src[pb_curr1..i14]
      step    -- s21 := copy_from_slice s19 s20
      case hlen =>
        have h_s18_len : s18.len.val = 32 := by
          rw [s18_post]; exact pk_mlkem_key5.private_random.property
        have h_s19_len : s19.length = 32 := by
          have h1 : s19.val.length = pk_mlkem_key5.private_random.val.length := by
            rw [← Slice.length, ← s19_post1]
          rw [show s19.length = s19.val.length from rfl, h1]
          exact pk_mlkem_key5.private_random.property
        simp [s20_post2, i14_post, h_s18_len, h_s19_len]
      step    -- s22 := (to_slice_mut_back1 s21).to_slice
      step as ⟨pb_curr2, pb_curr2_post⟩    -- pb_curr2 := pb_curr1 + s22.len
      case hmax =>
        have h_s17_len : s17.len.val = 32 := by
          rw [s17_post]; exact pk_mlkem_key5.encaps_key_hash.property
        have h_pb_curr1_val : pb_curr1.val = 768 * (k params : ℕ) + 64 := by
          rw [pb_curr1_post, h_pb_curr_val, h_s17_len]
        have h_s22_len : s22.length = 32 := by
          have h1 : (to_slice_mut_back1 s21).val.length = 32 :=
            (to_slice_mut_back1 s21).property
          simp [s22_post, Std.Array.to_slice, h1]
        have h1 : s22.len.val = s22.length := rfl
        rw [h_pb_curr1_val, h1, h_s22_len]
        have := k_le_4 params
        scalar_tac
      have h_s17_len : s17.len.val = 32 := by
        rw [s17_post]; exact pk_mlkem_key5.encaps_key_hash.property
      have h_pb_curr1_val : pb_curr1.val = 768 * (k params : ℕ) + 64 := by
        rw [pb_curr1_post, h_pb_curr_val, h_s17_len]
      have h_s22_len : s22.length = 32 := by
        have h1 : (to_slice_mut_back1 s21).val.length = 32 :=
          (to_slice_mut_back1 s21).property
        simp [s22_post, Std.Array.to_slice, h1]
      have h_pb_curr2_val : pb_curr2.val = pb_src.length := by
        have h1 : s22.len.val = s22.length := rfl
        rw [pb_curr2_post, h_pb_curr1_val, h1, h_s22_len, h_pas_len]
      step    -- final massert
      -- Final FC conjunction (7 conjuncts + universal triple).
      have h_pk3_params : pk_mlkem_key3.params = pk_mlkem_key.params := h_pk3_params_eq
      have h_pk3_n_rows : pk_mlkem_key3.n_rows = pk_mlkem_key.n_rows :=
        pk_mlkem_key3_post6.trans h_pk1_n_rows
      have h_pk3_enc : pk_mlkem_key3.encoded_t = encoded_t :=
        pk_mlkem_key3_post7.trans h_pk1_enc
      have h_pk4_n_rows' : pk4.n_rows = pk_mlkem_key.n_rows := h_pk4_n_rows.trans h_pk3_n_rows
      have h_pk4_params' : pk4.params = pk_mlkem_key.params := h_pk4_params.trans h_pk3_params
      have h_pk4_enc' : pk4.encoded_t = encoded_t := h_pk4_enc.trans h_pk3_enc
      have h_pk4_pubseed' : pk4.public_seed = to_slice_mut_back s10 :=
        h_pk4_pubseed.trans pk_mlkem_key3_post2
      -- pk_mlkem_key5 has all of pk4's field-preservation properties chained.
      have h_pk5_params : pk_mlkem_key5.params = pk_mlkem_key.params :=
        pk_mlkem_key5_post5.trans h_pk4_params'
      have h_pk5_n_rows : pk_mlkem_key5.n_rows = pk_mlkem_key.n_rows :=
        pk_mlkem_key5_post6.trans h_pk4_n_rows'
      have h_pk5_enc : pk_mlkem_key5.encoded_t = encoded_t :=
        pk_mlkem_key5_post3.trans h_pk4_enc'
      have h_pk5_pubseed : pk_mlkem_key5.public_seed = to_slice_mut_back s10 :=
        pk_mlkem_key5_post4.trans h_pk4_pubseed'
      refine ⟨?_, h_pk5_params, h_pk5_n_rows, ?_, ?_, ?_, ?_, ?_, ?_⟩
      · -- wfKey of final record (override has_private_seed/has_private_key + private_random)
        refine ⟨?_, ?_, ?_⟩
        · show wfInternalParams pk_mlkem_key5.params params
          exact wfKey.params_ok pk_mlkem_key5_post1
        · show pk_mlkem_key5.n_rows.val = (k params : ℕ)
          exact wfKey.n_rows_ok pk_mlkem_key5_post1
        · intro i h_end
          exact wfKey.data_wf pk_mlkem_key5_post1 i h_end
      · -- s-slot content: key'.data[sOffset+j] = s2.val[j].
        -- The a_transpose regen + t-write leave the ŝ window untouched; chain the
        -- frames pk5 ← pk4 ← pk3 ← pk1' ← pk1, ending at s2 (mirror h_data_t).
        intro j hj
        have hkk := k_sq_plus_2k_le_24 params
        have h_pk5_data_len : pk_mlkem_key5.data.val.length = 24 := pk_mlkem_key5.data.property
        have h_pk4_data_len : pk4.data.val.length = 24 := pk4.data.property
        have h_pk3_data_len : pk_mlkem_key3.data.val.length = 24 := pk_mlkem_key3.data.property
        have h_pk1_data_len : pk1.data.val.length = 24 := pk1.data.property
        have h_soj_lt_24 : sOffset params + j < 24 := by unfold sOffset matrixLen; grind
        have h_soj_ge : matrixLen params ≤ sOffset params + j := by unfold sOffset matrixLen; omega
        have h_soj_lt_dataEnd : sOffset params + j < Bridges.dataEnd params := by
          unfold sOffset matrixLen Bridges.dataEnd; grind
        have h_soj_lt_pk5 : sOffset params + j < pk_mlkem_key5.data.val.length := by
          rw [h_pk5_data_len]; exact h_soj_lt_24
        have h_soj_lt_pk4 : sOffset params + j < pk4.data.val.length := by
          rw [h_pk4_data_len]; exact h_soj_lt_24
        have h_soj_lt_pk3 : sOffset params + j < pk_mlkem_key3.data.val.length := by
          rw [h_pk3_data_len]; exact h_soj_lt_24
        have h_soj_lt_pk1' : sOffset params + j < pk1'.data.val.length := by
          show sOffset params + j < pk1.data.val.length
          rw [h_pk1_data_len]; exact h_soj_lt_24
        have h_soj_lt_pk1 : sOffset params + j < pk1.data.val.length := by
          rw [h_pk1_data_len]; exact h_soj_lt_24
        have h_s2_lt : j < s2.val.length := by
          rw [show s2.val.length = s2.length from rfl, h_s2_len]; exact hj
        show pk_mlkem_key5.data.val[sOffset params + j]'h_soj_lt_pk5
            = s2.val[j]'h_s2_lt
        have h_eq54 : pk_mlkem_key5.data.val[sOffset params + j]'h_soj_lt_pk5 =
            pk4.data.val[sOffset params + j]'h_soj_lt_pk4 :=
          List.getElem_of_eq (congrArg (·.val) pk_mlkem_key5_post2) _
        have h_eq43 : pk4.data.val[sOffset params + j]'h_soj_lt_pk4 =
            pk_mlkem_key3.data.val[sOffset params + j]'h_soj_lt_pk3 :=
          h_pk4_all.2.2.2.2.2.2.2.2.2.2.2 (sOffset params + j) h_soj_ge h_soj_lt_24
        have h_eq31 : pk_mlkem_key3.data.val[sOffset params + j]'h_soj_lt_pk3 =
            pk1'.data.val[sOffset params + j]'h_soj_lt_pk1' :=
          pk_mlkem_key3_post4 (sOffset params + j) ⟨h_soj_ge, h_soj_lt_dataEnd⟩
        have h_eq1'_1 : pk1'.data.val[sOffset params + j]'h_soj_lt_pk1' =
            pk1.data.val[sOffset params + j]'h_soj_lt_pk1 := rfl
        have h_pk1_eq : pk1.data.val[sOffset params + j]'h_soj_lt_pk1 =
            s2.val[j]'h_s2_lt :=
          hb.2.2.2.2.2 j hj
        exact h_eq54.trans (h_eq43.trans (h_eq31.trans (h_eq1'_1.trans h_pk1_eq)))
      · -- keyEncodedTPrefix bridge
        unfold keyEncodedTPrefix Slice.toSpecWindow sliceWindowToSpecBytes
        apply Vector.ext
        intro i hi
        simp only [Vector.getElem_ofFn]
        have h_pb := h_p2_enc i (by rw [h_cb]; exact hi)
        rw [show pk_mlkem_key5.encoded_t = encoded_t from h_pk5_enc, h_pb]
        simp [h_cb]
      · -- public_seed bridge: pk_mlkem_key5.public_seed = pb_src[768k..768k+32]
        have h_s8_len : s8.length = 32 := by
          have h_eq : s8.val.length = pk1.public_seed.val.length := by
            rw [← Slice.length, ← s8_post1]
          rw [show s8.length = s8.val.length from rfl, h_eq]
          exact pk1.public_seed.property
        have h_s10_len : s10.length = 32 := s10_post1.trans h_s8_len
        have h_pas_len' : (↑pb_src : List U8).length = 768 * (k params : ℕ) + 96 := h_pas_len
        have h_pubseed_eq : pk_mlkem_key5.public_seed = pk1.public_seed.from_slice s10 := by
          rw [h_pk5_pubseed, s8_post2]
        have h_s10_len_list : (↑s10 : List U8).length = 32 := h_s10_len
        have h_arr_val : (pk1.public_seed.from_slice s10).val = s10.val :=
          Aeneas.Std.Array.from_slice_val _ _ (by rw [h_s10_len_list]; rfl)
        have h_s9_len_list : (↑s9 : List U8).length = 32 := by
          have h1 : s9.length = i10.val - i9.val := s9_post2
          have h2 : i10.val - i9.val = 32 := by
            rw [h_i10_val, h_i9_val]; exact Nat.add_sub_cancel_left _ _
          show s9.val.length = 32
          rw [← Slice.length]; rw [h1, h2]
        unfold Slice.toSpecWindow sliceWindowToSpecBytes
        rw [show pk_mlkem_key5.public_seed.toSpec
              = arrayToSpecBytes pk_mlkem_key5.public_seed from rfl,
            h_pubseed_eq]
        apply Vector.ext
        intro i hi
        simp only [arrayToSpecBytes, Vector.getElem_ofFn]
        have h_i_arr : i < (pk1.public_seed.from_slice s10).val.length := by
          rw [h_arr_val, h_s10_len_list]; exact hi
        have h_i_s10 : i < (↑s10 : List U8).length := by rw [h_s10_len_list]; exact hi
        have h_i_s9 : i < (↑s9 : List U8).length := by rw [h_s9_len_list]; exact hi
        have h_i_pb : i9.val + i < (↑pb_src : List U8).length := by
          rw [h_pas_len', h_i9_val]
          exact Nat.add_lt_add_left (Nat.lt_of_lt_of_le hi (by decide)) _
        have h_arr_idx : (pk1.public_seed.from_slice s10).val[i]'h_i_arr =
            s10.val[i]'h_i_s10 :=
          List.getElem_of_eq h_arr_val h_i_arr
        rw [h_arr_idx]
        have h_s10_idx : s10.val[i]'h_i_s10 = s9.val[i]'h_i_s9 :=
          List.getElem_of_eq s10_post2 h_i_s10
        rw [h_s10_idx]
        have h_s9_idx : s9.val[i]'h_i_s9 = pb_src.val[i9.val + i]'h_i_pb := by
          rw [List.getElem_of_eq s9_post1]
          have hbound : i10.val ≤ pb_src.val.length ∧ i9.val + i < i10.val := by
            refine ⟨?_, ?_⟩
            · show i10.val ≤ (↑pb_src : List U8).length
              rw [h_pas_len', h_i10_val]
              exact Nat.add_le_add_left (by decide : (32 : ℕ) ≤ 96) _
            · rw [h_i10_val, h_i9_val]
              exact Nat.add_lt_add_left hi _
          exact List.getElem_slice i9.val i10.val i pb_src.val hbound
        rw [h_s9_idx]
        show (↑pb_src : List U8)[↑i9 + i].bv =
          (Vector.ofFn fun (j : Fin 32) => (↑pb_src : List U8)[768 * (k params : ℕ) + j.val].bv)[i]'(by simpa using hi)
        rw [Vector.getElem_ofFn]
        simp [← h_i9_val]
      · -- encaps_key_hash bridge via const-time-eq: pk_mlkem_key5.encaps_key_hash = pb_src[768k+32..768k+64]
        unfold Slice.toSpecWindow sliceWindowToSpecBytes
        apply Vector.ext
        intro i hi
        show (arrayToSpecBytes pk_mlkem_key5.encaps_key_hash)[i] = _
        simp only [arrayToSpecBytes, Vector.getElem_ofFn]
        have h32 : (↑(32#usize : Usize) : ℕ) = 32 := by decide
        have hi32 : i < 32 := h32 ▸ hi
        have h_s15_len_list : (↑s15 : List U8).length = 32 := h_s15_len
        have h_s16_len_list : (↑s16 : List U8).length = 32 := by
          rw [← h_b2_iff]; exact h_s15_len_list
        have h_i_s15 : i < (↑s15 : List U8).length := by rw [h_s15_len_list]; exact hi32
        have h_i_s16 : i < (↑s16 : List U8).length := by rw [h_s16_len_list]; exact hi32
        have h_i12_val : i12.val = 768 * (k params : ℕ) + 64 := by
          have h_s14_len_eq : s14.len.val = 32 := by show s14.length = 32; exact h_s14_len
          rw [i12_post, h_pb_curr_val, h_s14_len_eq]
        have h_pas_len_list : (↑pb_src : List U8).length = 768 * (k params : ℕ) + 96 := h_pas_len
        have h_i_pb : pb_curr.val + i < (↑pb_src : List U8).length := by
          rw [h_pas_len_list, h_pb_curr_val, Nat.add_assoc]
          refine Nat.add_lt_add_left ?_ (768 * (k params : ℕ))
          -- goal: 32 + i < 96
          calc 32 + i < 32 + 32 := Nat.add_lt_add_left hi32 32
            _ ≤ 96 := by decide
        have h_eq1 : pk_mlkem_key5.encaps_key_hash.val[i]'(by
            rw [show pk_mlkem_key5.encaps_key_hash.val.length
                  = (↑(32#usize : Usize) : ℕ) from pk_mlkem_key5.encaps_key_hash.property]
            exact hi) = s15.val[i]'h_i_s15 := by
          have h_s15_val : (↑s15 : List U8) = (↑pk_mlkem_key5.encaps_key_hash.to_slice : List U8) := by
            rw [s15_post]
          exact (List.getElem_of_eq h_s15_val h_i_s15).symm
        rw [h_eq1]
        have h_eq2 : s15.val[i]'h_i_s15 = s16.val[i]'h_i_s16 :=
          List.getElem_of_eq h_b2_iff h_i_s15
        rw [h_eq2]
        have h_s16_idx : s16.val[i]'h_i_s16 = pb_src.val[pb_curr.val + i]'h_i_pb := by
          rw [List.getElem_of_eq s16_post1]
          have h_pas_len_list' : pb_src.val.length = 768 * (k params : ℕ) + 96 := h_pas_len
          have hbound : i12.val ≤ pb_src.val.length ∧ pb_curr.val + i < i12.val := by
            refine ⟨?_, ?_⟩
            · rw [h_pas_len_list', h_i12_val]
              exact Nat.add_le_add_left (by decide : (64 : ℕ) ≤ 96) _
            · rw [h_i12_val, h_pb_curr_val]
              exact Nat.add_lt_add_left hi32 _
          exact List.getElem_slice pb_curr.val i12.val i pb_src.val hbound
        rw [h_s16_idx]
        show (↑pb_src : List U8)[↑pb_curr + i].bv =
          (Vector.ofFn fun (j : Fin 32) => (↑pb_src : List U8)[768 * (k params : ℕ) + 32 + j.val].bv)[i]'(by simpa using hi)
        rw [Vector.getElem_ofFn]
        simp [← h_pb_curr_val]
      · -- SHA3 conjunct
        rw [encapsulationKey_struct_upd_full]
        show arrayToSpecBytes pk_mlkem_key5.encaps_key_hash = _
        rw [pk_mlkem_key5_post11]
        apply congrArg SHA3.sha3_256
        have h_enc : keyEncodedTPrefix (a_transpose_mut_back s13) params
            = keyEncodedTPrefix pk_mlkem_key5 params := by
          unfold keyEncodedTPrefix
          apply Vector.ext
          intro i hi
          simp only [Vector.getElem_ofFn]
          have h : (↑pk_mlkem_key5.encoded_t : List U8) = (↑(a_transpose_mut_back s13).encoded_t : List U8) :=
            congrArg (·.val) pk_mlkem_key5_post3
          have hi' : i < (↑pk_mlkem_key5.encoded_t : List U8).length := by
            have hp : (↑pk_mlkem_key5.encoded_t : List U8).length = 1536 :=
              pk_mlkem_key5.encoded_t.property
            rw [hp]
            calc i < 384 * (k params : ℕ) := hi
              _ ≤ 384 * 4 := Nat.mul_le_mul_left 384 hk_le4
              _ = 1536 := by decide
          fcongr 1
          apply congrArg
          exact (List.getElem_of_eq h hi').symm
        have h_pub : arrayToSpecBytes (a_transpose_mut_back s13).public_seed
            = arrayToSpecBytes pk_mlkem_key5.public_seed := by
          rw [pk_mlkem_key5_post4]
        show keyEncodedTPrefix (a_transpose_mut_back s13) params
            ‖ arrayToSpecBytes (a_transpose_mut_back s13).public_seed
          = encapsulationKey pk_mlkem_key5 params
        unfold encapsulationKey
        rw [h_enc, h_pub]
        rfl
      · -- private_random bridge ∧ flags ∧ wfDecapKey: split into
        -- private_random+flags (existing proof) and wfDecapKey (new bundle).
        refine ⟨?_, ?_⟩
        · -- private_random bridge: pb_src[768k+64..768k+96] copied into private_random
          have h_s19_len : s19.length = 32 := by
            have h_eq : s19.val.length = pk_mlkem_key5.private_random.val.length := by
              rw [← Slice.length, ← s19_post1]
            rw [show s19.length = s19.val.length from rfl, h_eq]
            exact pk_mlkem_key5.private_random.property
          have h_s21_len : s21.length = 32 := s21_post1.trans h_s19_len
          have h_pas_len' : (↑pb_src : List U8).length = 768 * (k params : ℕ) + 96 := h_pas_len
          have h_s18_len : s18.len.val = 32 := by
            rw [s18_post]; exact pk_mlkem_key5.private_random.property
          have h_i14_val : i14.val = 768 * (k params : ℕ) + 96 := by
            rw [i14_post, h_pb_curr1_val, h_s18_len]
          have h_priv_eq : (to_slice_mut_back1 s21) = pk_mlkem_key5.private_random.from_slice s21 := by
            rw [s19_post2]
          have h_s21_len_list : (↑s21 : List U8).length = 32 := h_s21_len
          have h_arr_val : (pk_mlkem_key5.private_random.from_slice s21).val = s21.val :=
            Aeneas.Std.Array.from_slice_val _ _ (by rw [h_s21_len_list]; rfl)
          have h_s20_len_list : (↑s20 : List U8).length = 32 := by
            have h1 : s20.length = i14.val - pb_curr1.val := s20_post2
            have h2 : i14.val - pb_curr1.val = 32 := by
              rw [h_i14_val, h_pb_curr1_val, Nat.add_sub_add_left]
            show s20.val.length = 32
            rw [← Slice.length]; rw [h1, h2]
          show arrayToSpecBytes (to_slice_mut_back1 s21) = _
          rw [h_priv_eq]
          unfold Slice.toSpecWindow sliceWindowToSpecBytes
          apply Vector.ext
          intro i hi
          simp only [arrayToSpecBytes, Vector.getElem_ofFn]
          have h_i_arr : i < (pk_mlkem_key5.private_random.from_slice s21).val.length := by
            rw [h_arr_val, h_s21_len_list]; exact hi
          have h_i_s21 : i < (↑s21 : List U8).length := by rw [h_s21_len_list]; exact hi
          have h_i_s20 : i < (↑s20 : List U8).length := by rw [h_s20_len_list]; exact hi
          have h32 : (↑(32#usize : Usize) : ℕ) = 32 := by decide
          have hi32 : i < 32 := h32 ▸ hi
          have h_i_pb : pb_curr1.val + i < (↑pb_src : List U8).length := by
            rw [h_pas_len', h_pb_curr1_val, Nat.add_assoc]
            exact Nat.add_lt_add_left
              (Nat.add_lt_add_left (k := 64) hi32) (768 * (k params : ℕ))
          have h_arr_idx : (pk_mlkem_key5.private_random.from_slice s21).val[i]'h_i_arr =
              s21.val[i]'h_i_s21 :=
            List.getElem_of_eq h_arr_val h_i_arr
          rw [h_arr_idx]
          have h_s21_idx : s21.val[i]'h_i_s21 = s20.val[i]'h_i_s20 :=
            List.getElem_of_eq s21_post2 h_i_s21
          rw [h_s21_idx]
          have h_s20_idx : s20.val[i]'h_i_s20 = pb_src.val[pb_curr1.val + i]'h_i_pb := by
            rw [List.getElem_of_eq s20_post1]
            have hbound : i14.val ≤ pb_src.val.length ∧ pb_curr1.val + i < i14.val := by
              refine ⟨?_, ?_⟩
              · show i14.val ≤ (↑pb_src : List U8).length
                rw [h_pas_len', h_i14_val]
              · rw [h_i14_val, h_pb_curr1_val]
                exact Nat.add_lt_add_left hi _
            exact List.getElem_slice pb_curr1.val i14.val i pb_src.val hbound
          rw [h_s20_idx]
          show (↑pb_src : List U8)[↑pb_curr1 + i].bv =
            (Vector.ofFn fun (j : Fin 32) => (↑pb_src : List U8)[768 * (k params : ℕ) + 64 + j.val].bv)[i]'(by simpa using hi)
          rw [Vector.getElem_ofFn]
          simp [← h_pb_curr1_val]
        · -- wfDecapKey key' params.
          --
          -- The final returned key' = { pk_mlkem_key5 with
          --   has_private_seed := false, has_private_key := true,
          --   private_random := to_slice_mut_back1 s21 }.  Every wfEncapKey
          --   field reads only data / encoded_t / public_seed / encaps_key_hash,
          --   all preserved by the trailing struct update — so we prove each
          --   field about pk_mlkem_key5 and ride the projection through
          --   (iota-reduces).  has_private_key := true is rfl from the override.
          refine ⟨⟨?_, ?_, ?_, ?_⟩, ?_⟩
          · -- towfKey: wfKey { pk_mlkem_key5 with flags + private_random } params.
            refine ⟨?_, ?_, ?_⟩
            · show wfInternalParams pk_mlkem_key5.params params
              exact wfKey.params_ok pk_mlkem_key5_post1
            · show pk_mlkem_key5.n_rows.val = (k params : ℕ)
              exact wfKey.n_rows_ok pk_mlkem_key5_post1
            · intro i h_end
              exact wfKey.data_wf pk_mlkem_key5_post1 i h_end
          · -- hash_pinned: identical to the SHA3 conjunct above (L405-436), but
            -- packaged as `keyHashPinned` (= `encaps_key_hash.toSpec = SHA3 (...)`).
            -- Uses encapsulationKey_struct_upd_full to discharge the
            -- private_random override.
            show arrayToSpecBytes pk_mlkem_key5.encaps_key_hash =
              Spec.SHA3.sha3_256
                (keyEncodedTPrefix pk_mlkem_key5 params
                  ‖ arrayToSpecBytes pk_mlkem_key5.public_seed)
            rw [pk_mlkem_key5_post11]
            apply congrArg Spec.SHA3.sha3_256
            have h_enc : keyEncodedTPrefix (a_transpose_mut_back s13) params
                = keyEncodedTPrefix pk_mlkem_key5 params := by
              unfold keyEncodedTPrefix
              apply Vector.ext
              intro i hi
              simp only [Vector.getElem_ofFn]
              have h : (↑pk_mlkem_key5.encoded_t : List U8) =
                  (↑(a_transpose_mut_back s13).encoded_t : List U8) :=
                congrArg (·.val) pk_mlkem_key5_post3
              have hi' : i < (↑pk_mlkem_key5.encoded_t : List U8).length := by
                have hp : (↑pk_mlkem_key5.encoded_t : List U8).length = 1536 :=
                  pk_mlkem_key5.encoded_t.property
                rw [hp]
                calc i < 384 * (k params : ℕ) := hi
                  _ ≤ 384 * 4 := Nat.mul_le_mul_left 384 hk_le4
                  _ = 1536 := by decide
              fcongr 1
              apply congrArg
              exact (List.getElem_of_eq h hi').symm
            have h_pub : arrayToSpecBytes (a_transpose_mut_back s13).public_seed
                = arrayToSpecBytes pk_mlkem_key5.public_seed := by
              rw [pk_mlkem_key5_post4]
            rw [h_enc, h_pub]
          · -- byte_form_t — close via byte_form_t_bridge (mirrors Encap closure
            -- at Encap.lean L381-538).  The chain has one extra hop
            -- (pk_mlkem_key5 → pk4 = a_transpose_mut_back s13 → pk_mlkem_key3
            --   → pk1' → pk1) compared with Encap because Decap recomputes H(ek).
            --
            -- WHY-VALID: the runtime's d=12 InvalidBlob check ensures every
            -- raw 12-bit segment of `err_slice` (= pb_src[cb..2cb], = encoded_t
            -- after the inline-window copy) is < q.  The bridge
            -- `polyVector_byteEncode_byteDecode_canonical_eq 12` then gives
            -- `keyEncodedTPrefix pk_mlkem_key5 params =
            --    (ByteEncode 12 (keyT pk_mlkem_key5 params)).cast _`.
            refine ⟨keyT _ params, ?_, rfl⟩
            have hkk := k_sq_plus_2k_le_24 params
            have h_pk5_data_len : pk_mlkem_key5.data.val.length = 24 :=
              pk_mlkem_key5.data.property
            have h_pk4_data_len : pk4.data.val.length = 24 := pk4.data.property
            have h_pk3_data_len : pk_mlkem_key3.data.val.length = 24 :=
              pk_mlkem_key3.data.property
            have h_pk_data_len : pk_mlkem_key.data.val.length = 24 :=
              pk_mlkem_key.data.property
            have h_pk1_data_len : pk1.data.val.length = 24 := pk1.data.property
            have h_t1_val_len : t1.val.length = (k params : ℕ) := h_t1_len
            -- Data-bridge: pk_mlkem_key5.data[matrixLen + j] = t1.val[j].
            -- pk_mlkem_key5 = { pk4 with flags + private_random }; data preserved.
            have h_data_t :
                ∀ (j : ℕ) (h_j : j < (k params : ℕ)),
                  pk_mlkem_key5.data.val[matrixLen params + j]'(by
                    rw [h_pk5_data_len]; unfold matrixLen; grind) =
                  t1.val[j]'(by rw [h_t1_val_len]; exact h_j) := by
              intro j hj
              have h_mlj_lt_24 : matrixLen params + j < 24 := by
                unfold matrixLen; grind
              have h_mlj_ge : matrixLen params ≤ matrixLen params + j := by omega
              have h_mlj_lt_dataEnd :
                  matrixLen params + j < Bridges.dataEnd params := by
                unfold matrixLen Bridges.dataEnd; grind
              have h_mlj_lt_pk5 :
                  matrixLen params + j < pk_mlkem_key5.data.val.length := by
                rw [h_pk5_data_len]; exact h_mlj_lt_24
              have h_mlj_lt_pk4 :
                  matrixLen params + j < pk4.data.val.length := by
                rw [h_pk4_data_len]; exact h_mlj_lt_24
              have h_mlj_lt_pk3 :
                  matrixLen params + j < pk_mlkem_key3.data.val.length := by
                rw [h_pk3_data_len]; exact h_mlj_lt_24
              have h_mlj_lt_pk1' : matrixLen params + j < pk1'.data.val.length := by
                show matrixLen params + j < pk1.data.val.length
                rw [h_pk1_data_len]; exact h_mlj_lt_24
              have h_mlj_lt_pk1 : matrixLen params + j < pk1.data.val.length := by
                rw [h_pk1_data_len]; exact h_mlj_lt_24
              -- pk_mlkem_key5.data = pk4.data (struct update only flips
              -- flags + private_random — data preserved).
              have h_eq54 : pk_mlkem_key5.data.val[matrixLen params + j]'h_mlj_lt_pk5 =
                  pk4.data.val[matrixLen params + j]'h_mlj_lt_pk4 :=
                List.getElem_of_eq (congrArg (·.val) pk_mlkem_key5_post2) _
              -- pk4.data[mlj] = pk_mlkem_key3.data[mlj] via slot frame on
              -- a_transpose (12th conjunct of h_pk4_all).
              have h_eq43 :
                  pk4.data.val[matrixLen params + j]'h_mlj_lt_pk4 =
                  pk_mlkem_key3.data.val[matrixLen params + j]'h_mlj_lt_pk3 :=
                h_pk4_all.2.2.2.2.2.2.2.2.2.2.2
                  (matrixLen params + j) h_mlj_ge h_mlj_lt_24
              -- pk_mlkem_key3.data[mlj] = pk1'.data[mlj] via key_expand's
              -- slot frame (pk_mlkem_key3_post4 takes ⟨ml ≤ slot, slot < dataEnd⟩).
              have h_eq31 :
                  pk_mlkem_key3.data.val[matrixLen params + j]'h_mlj_lt_pk3 =
                  pk1'.data.val[matrixLen params + j]'h_mlj_lt_pk1' :=
                pk_mlkem_key3_post4 (matrixLen params + j) ⟨h_mlj_ge, h_mlj_lt_dataEnd⟩
              -- pk1'.data = pk1.data (struct update preserves data field).
              have h_eq1'_1 :
                  pk1'.data.val[matrixLen params + j]'h_mlj_lt_pk1' =
                  pk1.data.val[matrixLen params + j]'h_mlj_lt_pk1 := rfl
              -- pk1.data[mlj] = t1.val[j] via the elementwise conjunct.
              have h_pk1_eq :
                  pk1.data.val[matrixLen params + j]'h_mlj_lt_pk1 =
                  t1.val[j]'(by rw [h_t1_val_len]; exact hj) :=
                h_pk1_data_elt j hj
              exact h_eq54.trans (h_eq43.trans
                (h_eq31.trans (h_eq1'_1.trans h_pk1_eq)))
            -- Encoded_t bridge: pk_mlkem_key5.encoded_t.val[i] = err_slice.val[i].
            have h_enc_t_len : encoded_t.val.length = 1536 := encoded_t.property
            have h_pk5_enc_len : pk_mlkem_key5.encoded_t.val.length = 1536 :=
              pk_mlkem_key5.encoded_t.property
            have h_err_len_val : err_slice.val.length = 384 * (k params : ℕ) := by
              rw [show err_slice.val.length = err_slice.length from rfl,
                  err_slice_len, h_cb]; omega
            -- pk_mlkem_key5.encoded_t = pk4.encoded_t (struct update preserves)
            -- pk4.encoded_t = pk_mlkem_key3.encoded_t (a_transpose_mut frame)
            -- pk_mlkem_key3.encoded_t = pk1.encoded_t (key_expand frame:
            --   pk_mlkem_key3_post7 returns to pk1' = pk1)
            -- pk1.encoded_t = encoded_t (h_pk1_enc)
            have h_pk5_enc_eq_encT : pk_mlkem_key5.encoded_t = encoded_t := by
              have h54 : pk_mlkem_key5.encoded_t = pk4.encoded_t :=
                pk_mlkem_key5_post3
              have h43 : pk4.encoded_t = pk_mlkem_key3.encoded_t := h_pk4_enc
              have h31 : pk_mlkem_key3.encoded_t = pk1.encoded_t :=
                pk_mlkem_key3_post7
              exact h54.trans (h43.trans (h31.trans h_pk1_enc))
            have h_enc_err :
                ∀ (i : ℕ) (h_i : i < 384 * (k params : ℕ)),
                  pk_mlkem_key5.encoded_t.val[i]'(by
                    rw [h_pk5_enc_len]; have := k_le_4 params; grind) =
                  err_slice.val[i]'(by rw [h_err_len_val]; exact h_i) := by
              intro i hi
              have h_i_lt_enc : i < encoded_t.val.length := by
                rw [h_enc_t_len]; have := k_le_4 params; grind
              have h_cb_le_enc :
                  cb_encoded_vector.val ≤ encoded_t.val.length := by
                rw [h_enc_t_len, h_cb]; have := k_le_4 params; grind
              have h_i_lt_cb : i < cb_encoded_vector.val := by
                rw [h_cb]; exact hi
              have h_eq_enc : pk_mlkem_key5.encoded_t.val[i]'(by
                  rw [h_pk5_enc_len]; have := k_le_4 params; grind) =
                  encoded_t.val[i]'h_i_lt_enc :=
                List.getElem_of_eq (congrArg (·.val) h_pk5_enc_eq_encT) _
              have h_to_slice : encoded_t.to_slice.val = encoded_t.val := by
                simp [Aeneas.Std.Array.to_slice]
              have h_err_eq_slice : err_slice.val =
                  encoded_t.val.slice 0 cb_encoded_vector.val := by
                rw [err_slice_val_eq, h_to_slice]
              have h_err_eq : err_slice.val[i]'(by
                  rw [h_err_len_val]; exact hi) =
                  (encoded_t.val.slice 0 cb_encoded_vector.val)[i]'(by
                    rw [← h_err_eq_slice]
                    show i < err_slice.val.length
                    rw [h_err_len_val]; exact hi) :=
                List.getElem_of_eq h_err_eq_slice _
              have h_slice_eq :=
                List.getElem_slice 0 cb_encoded_vector.val i encoded_t.val
                  ⟨h_cb_le_enc, by omega⟩
              rw [h_eq_enc, h_err_eq, h_slice_eq]
              fcongr 1; omega
            -- Row-by-row decode+canonicity (directly from vector_decode post).
            have h_row :
                ∀ (j : ℕ) (h_j : j < (k params : ℕ)),
                  ∃ (h_window : (j + 1) * (32 * 12) ≤ err_slice.length),
                    toPoly (t1.val[j]'(by rw [h_t1_val_len]; exact h_j)) =
                      decodeDecompressPoly 12
                        (sliceWindowToSpecBytes err_slice (j * (32 * 12)) (32 * 12)
                          (Nat.add_one_mul _ _ ▸ h_window))
                        ⟨by decide, by decide⟩ ∧
                    (∀ (i : ℕ) (_h_i : i < 256),
                      Bridges.dBitSegment 12
                          (sliceWindowToSpecBytes err_slice (j * (32 * 12)) (32 * 12)
                            (Nat.add_one_mul _ _ ▸ h_window))
                          i < MLKEM.m 12) := by
              intro j hj
              have hj' : j < t1.length := by rw [h_t1_len]; exact hj
              show ∃ (h_window : (j + 1) * (32 * 12) ≤ err_slice.length),
                toPoly (t1.val[j]'(by rw [h_t1_val_len]; exact hj)) =
                  decodeDecompressPoly 12
                    (sliceWindowToSpecBytes err_slice (j * (32 * 12)) (32 * 12)
                      (Nat.add_one_mul _ _ ▸ h_window))
                    ⟨by decide, by decide⟩ ∧
                (∀ (i : ℕ) (_h_i : i < 256),
                  Bridges.dBitSegment 12
                      (sliceWindowToSpecBytes err_slice (j * (32 * 12)) (32 * 12)
                        (Nat.add_one_mul _ _ ▸ h_window))
                      i < MLKEM.m 12)
              rw [h_err_slice]
              exact sc_error1_post3 j hj'
            -- pk_mlkem_key5 reads the same keyT / keyEncodedTPrefix as pk4 /
            -- pk_mlkem_key3 / pk1 (matrix/T/S slots all preserved by trailing
            -- struct update).  Use byte_form_t_bridge on pk_mlkem_key5 directly.
            show keyEncodedTPrefix pk_mlkem_key5 params =
              (MLKEM.PolyVector.ByteEncode 12 (keyT pk_mlkem_key5 params)).cast
                (Bridges.polyVector_byteEncode_size_cast 12)
            exact byte_form_t_bridge pk_mlkem_key5 t1 err_slice
                    h_t1_len h_err_len_val h_data_t h_enc_err h_row
          · -- matrix_form_a: chain
            --   key'.data[i*k+j]  = pk_mlkem_key5.data[i*k+j] (iota: struct update)
            --                     = pk4.data[i*k+j]            (pk_mlkem_key5_post2)
            --                     = s13[i*k+j]                  (back-col-clause of h_pk4_all)
            --   toPoly s13[i*k+j] = toPoly s12[j*k+i]           (s13_post3, nrows=k)
            --                     = toPoly pk_mlkem_key3.data[j*k+i] (s12_post3)
            --                     = SampleNTT (expandAEntrySeed ρ j i)
            --                                                     (pk_mlkem_key3_post3 j i)
            --                     = SampleNTT (ρ ‖ #v[i] ‖ #v[j]) (def of expandAEntrySeed,
            --                                                       ρ = to_slice_mut_back s10 = pk5.public_seed)
            intro i j hi hj
            have hkk := k_sq_plus_2k_le_24 params
            have h_mul_i : (i + 1) * (k params : ℕ) ≤ (k params : ℕ) * (k params : ℕ) :=
              Nat.mul_le_mul_right _ hi
            have h_mul_j : (j + 1) * (k params : ℕ) ≤ (k params : ℕ) * (k params : ℕ) :=
              Nat.mul_le_mul_right _ hj
            have h_idx_lt : i * (k params : ℕ) + j < matrixLen params := by
              unfold matrixLen; grind
            have h_swap_lt : j * (k params : ℕ) + i < matrixLen params := by
              unfold matrixLen; grind
            have h_pk5_data_len : pk_mlkem_key5.data.val.length = 24 :=
              pk_mlkem_key5.data.property
            have h_pk4_data_len : pk4.data.val.length = 24 := pk4.data.property
            have h_pk3_data_len : pk_mlkem_key3.data.val.length = 24 :=
              pk_mlkem_key3.data.property
            have h_s13_val_len : s13.val.length = matrixLen params := h_s13_len
            have h_s12_val_len : s12.val.length = matrixLen params := s12_post1
            have h_ij_lt_pk5 : i * (k params : ℕ) + j < pk_mlkem_key5.data.val.length := by
              rw [h_pk5_data_len]; unfold matrixLen at h_idx_lt; grind
            have h_ij_lt_pk4 : i * (k params : ℕ) + j < pk4.data.val.length := by
              rw [h_pk4_data_len]; unfold matrixLen at h_idx_lt; grind
            have h_ij_lt_s13 : i * (k params : ℕ) + j < s13.val.length := by
              rw [h_s13_val_len]; exact h_idx_lt
            have h_ji_lt_s12 : j * (k params : ℕ) + i < s12.val.length := by
              rw [h_s12_val_len]; exact h_swap_lt
            have h_ji_lt_pk3 : j * (k params : ℕ) + i < pk_mlkem_key3.data.val.length := by
              rw [h_pk3_data_len]; unfold matrixLen at h_swap_lt; grind
            -- Element equation: pk_mlkem_key5.data[ij] = pk4.data[ij] = s13[ij]
            have h_data5_eq_4 : pk_mlkem_key5.data.val[i * (k params : ℕ) + j]'h_ij_lt_pk5 =
                pk4.data.val[i * (k params : ℕ) + j]'h_ij_lt_pk4 := by
              have h_eq : pk_mlkem_key5.data.val = pk4.data.val :=
                congrArg (·.val) pk_mlkem_key5_post2
              exact List.getElem_of_eq h_eq _
            have h_data4_eq_s13 : pk4.data.val[i * (k params : ℕ) + j]'h_ij_lt_pk4 =
                s13.val[i * (k params : ℕ) + j]'h_ij_lt_s13 :=
              h_pk4_all.2.2.2.2.2.2.2.2.2.2.1 (i * (k params : ℕ) + j) h_idx_lt
            -- Element equation: s12[ji] = pk_mlkem_key3.data[ji]
            have h_s12_eq_pk3 : s12.val[j * (k params : ℕ) + i]'h_ji_lt_s12 =
                pk_mlkem_key3.data.val[j * (k params : ℕ) + i]'h_ji_lt_pk3 :=
              s12_post3 (j * (k params : ℕ) + i) s12_post1 h_swap_lt
            -- toPoly equation for the matrix transpose, with bound proofs aligned to
            -- the n_rows = k convention via h_pk3_nrows_val.
            have h_i_nr : i < pk_mlkem_key.params.n_rows.val := by rw [h_pk3_nrows_val]; exact hi
            have h_j_nr : j < pk_mlkem_key.params.n_rows.val := by rw [h_pk3_nrows_val]; exact hj
            have h_trans_raw := s13_post3 i j h_i_nr h_j_nr
            -- Lift the Nat index inside the getElems via getElem_congr_idx
            -- (h_pk3_nrows_val : pk_mlkem_key.params.n_rows.val = k params).
            have h_idx_ij : i * pk_mlkem_key.params.n_rows.val + j = i * (k params : ℕ) + j := by
              rw [h_pk3_nrows_val]
            have h_idx_ji : j * pk_mlkem_key.params.n_rows.val + i = j * (k params : ℕ) + i := by
              rw [h_pk3_nrows_val]
            rw [getElem_congr_idx (c := s13.val) h_idx_ij,
                getElem_congr_idx (c := s12.val) h_idx_ji] at h_trans_raw
            have h_trans : toPoly (s13.val[i * (k params : ℕ) + j]'h_ij_lt_s13) =
                toPoly (s12.val[j * (k params : ℕ) + i]'h_ji_lt_s12) := h_trans_raw
            -- pk_mlkem_key3_post3 at row=j col=i.
            have h_pk3_sample := pk_mlkem_key3_post3 j i hj hi
            -- Assemble the chain.
            show toPoly (pk_mlkem_key5.data.val[i * (k params : ℕ) + j]'h_ij_lt_pk5) =
              MLKEM.SampleNTT
                (arrayToSpecBytes pk_mlkem_key5.public_seed
                  ‖ #v[(i : Byte)] ‖ #v[(j : Byte)])
            rw [h_data5_eq_4, h_data4_eq_s13, h_trans, congrArg toPoly h_s12_eq_pk3,
                h_pk3_sample]
            -- Reduce expandAEntrySeed and rewrite ρ.
            unfold expandAEntrySeed
            rw [show arrayToSpecBytes pk_mlkem_key5.public_seed
                  = arrayToSpecBytes (to_slice_mut_back s10) from by rw [h_pk5_pubseed]]
            rfl
          · -- has_private_key = true: rfl from the trailing struct update.
            rfl
    · -- b2 = false → InvalidBlob path (returns pk_mlkem_key5)
      have h_pk5_params : pk_mlkem_key5.params = pk_mlkem_key.params := by
        have h_pk3_params : pk_mlkem_key3.params = pk_mlkem_key.params := h_pk3_params_eq
        exact pk_mlkem_key5_post5.trans (h_pk4_params.trans h_pk3_params)
      have h_pk5_n_rows : pk_mlkem_key5.n_rows = pk_mlkem_key.n_rows := by
        have h_pk3_n_rows : pk_mlkem_key3.n_rows = pk_mlkem_key.n_rows :=
          pk_mlkem_key3_post6.trans h_pk1_n_rows
        exact pk_mlkem_key5_post6.trans (h_pk4_n_rows.trans h_pk3_n_rows)
      simp only [WP.spec_ok]
      refine ⟨pk_mlkem_key5_post1, h_pk5_params, h_pk5_n_rows, ?_⟩
      simp

/-! ### `ksv_decap_branch_b` — post-decode_s composer

After `ksv_decap_decode_s` returns `(i8, s_mut_back, sc_error, s2, b)`,
`ksv_decap_branch_b` dispatches on `b`:
  • `b = true` (i.e. `sc_error ≠ NoError`, reachable only as
    `InvalidBlob` at `d = 12`): return `(s_mut_back s2, sc_error)`.
  • `b = false`: chain `ksv_decap_decode_t_prep` →
    `ksv_decap_after_prep` to finish the DecapsulationKey blob.

All preconditions mirror the universal conjuncts of
`ksv_decap_decode_s.spec` (back-closure, `s2.length`, `i8.val`, `b`
relation to `sc_error`) plus the per-`sc_error` match (which carries
the success-path `wfPoly s2` + decode-fidelity facts). -/
@[step]
theorem ksv_decap_branch_b.spec
    {params : ParameterSet}
    (pb_src : Slice U8)
    (pk_mlkem_key : mlkem.key.Key)
    (cb_encoded_vector : Usize)
    (p_comp_temps : mlkem.ntt.InternalComputationTemporaries)
    (i8 : Usize)
    (s_mut_back : Slice PolyElement → mlkem.key.Key)
    (sc_error : common.Error)
    (s2 : Slice PolyElement)
    (b : Bool)
    (h_wf : wfKey pk_mlkem_key params)
    (h_cb : cb_encoded_vector.val = 384 * (k params : ℕ))
    (h_pas_len : pb_src.length = 768 * (k params : ℕ) + 96)
    (h_i8 : i8.val = cb_encoded_vector.val)
    (h_b : b = (sc_error ≠ Error.NoError))
    (h_s2_len : s2.length = (k params : ℕ))
    /- Back-closure semantics of `s_mut_back` (full 10-conjunct, as
       returned by `ksv_decap_decode_s.spec`). -/
    (h_s_back : ∀ (s' : Slice PolyElement)
                  (_h_s'_len : s'.length = (k params : ℕ))
                  (_h_s'_wf : ∀ i (_ : i < s'.length), wfPoly s'.val[i]),
                  wfKey (s_mut_back s') params ∧
                  (s_mut_back s').params = pk_mlkem_key.params ∧
                  (s_mut_back s').n_rows = pk_mlkem_key.n_rows ∧
                  (s_mut_back s').has_private_seed = pk_mlkem_key.has_private_seed ∧
                  (s_mut_back s').has_private_key = pk_mlkem_key.has_private_key ∧
                  (s_mut_back s').private_seed = pk_mlkem_key.private_seed ∧
                  (s_mut_back s').private_random = pk_mlkem_key.private_random ∧
                  (s_mut_back s').public_seed = pk_mlkem_key.public_seed ∧
                  (s_mut_back s').encoded_t = pk_mlkem_key.encoded_t ∧
                  (s_mut_back s').encaps_key_hash = pk_mlkem_key.encaps_key_hash ∧
                  /- S-slot read-back: `s_mut_back` writes `s'` into the `ŝ`
                     window.  Threaded so the b=false path can bridge the
                     decoded `s2` to `keySEncoded key'`. -/
                  (∀ (i : ℕ) (_h_i : i < (k params : ℕ)),
                    (s_mut_back s').data.val[sOffset params + i]'(by
                      have hl : (s_mut_back s').data.val.length = 24 :=
                        (s_mut_back s').data.property
                      have := k_sq_plus_2k_le_24 params
                      unfold sOffset matrixLen; grind) =
                    s'.val[i]'(by
                      rw [show s'.val.length = s'.length from rfl, _h_s'_len];
                      exact _h_i)))
    (h_s2_wf_all : ∀ i (_ : i < s2.length), wfPoly s2.val[i])
    /- Per-`sc_error` match from `ksv_decap_decode_s.spec`. -/
    (h_dec : match sc_error with
             | Error.NoError =>
                 (∀ i (_ : i < s2.length), wfPoly s2.val[i]) ∧
                 (∀ (j : Nat) (h_j : j < s2.length),
                    ∃ (h_w : (j + 1) * (32 * 12) ≤ cb_encoded_vector.val),
                      toPoly (s2.val[j]'h_j) =
                        decodeDecompressPoly 12
                          (sliceWindowToSpecBytes pb_src
                            (j * (32 * 12)) (32 * 12)
                            (by have := h_w; have := h_pas_len; have := k_le_4 params;
                                scalar_tac))
                          ⟨by decide, by decide⟩ ∧
                      (∀ (i : ℕ) (_h_i : i < 256),
                        dBitSegment 12
                          (sliceWindowToSpecBytes pb_src
                            (j * (32 * 12)) (32 * 12)
                            (by have := h_w; have := h_pas_len; have := k_le_4 params;
                                scalar_tac))
                          i < MLKEM.m 12))
             | Error.InvalidBlob => True
             | _ => False) :
    ksv_decap_branch_b pb_src pk_mlkem_key cb_encoded_vector
        p_comp_temps i8 s_mut_back sc_error s2 b
      ⦃ err key' =>
          wfKey key' params ∧
          key'.params = pk_mlkem_key.params ∧
          key'.n_rows = pk_mlkem_key.n_rows ∧
          match err with
          | Error.NoError =>
              keySEncoded key' params = pb_src.toSpecWindow 0 (384 * (k params : ℕ)) (by simp only [h_pas_len]; scalar_tac) ∧
              keyEncodedTPrefix key' params = pb_src.toSpecWindow (384 * (k params : ℕ)) (384 * (k params : ℕ)) (by have := k_le_4 params; simp [h_pas_len]; grind) ∧
              key'.public_seed.toSpec = pb_src.toSpecWindow (768 * (k params : ℕ)) 32 (by simp [h_pas_len]) ∧
              key'.encaps_key_hash.toSpec = pb_src.toSpecWindow (768 * (k params : ℕ) + 32) 32 (by simp [h_pas_len]) ∧
              key'.encaps_key_hash.toSpec = Spec.SHA3.sha3_256 (encapsulationKey key' params) ∧
              key'.private_random.toSpec = pb_src.toSpecWindow (768 * (k params : ℕ) + 64) 32 (by simp [h_pas_len]) ∧
              key'.has_private_seed = false ∧ key'.has_private_key = true ∧
              wfDecapKey key' params
          | Error.InvalidBlob => True
          | _ => False ⦄ := by
  rw [ksv_decap_branch_b.fold]
  split
  · -- b = true → error path: return (s_mut_back s2, sc_error)
    rename_i hb_true
    have h_sc_ne : sc_error ≠ Error.NoError := by
      rw [← h_b]; exact hb_true
    -- From `h_dec`, the only reachable case under `sc_error ≠ NoError` is `InvalidBlob`.
    have h_sc_eq : sc_error = Error.InvalidBlob := by grind
    subst h_sc_eq
    -- `wfPolyVec s2` is now available unconditionally from the
    -- strengthened `ksv_decap_decode_s.spec` (which surfaces it from
    -- `vector_decode_and_decompress.spec` — the impl preserves
    -- `wfPolyVec` regardless of failure since the offending
    -- coefficient is rejected BEFORE the store; see Rust
    -- `mlkem/ntt.rs:798-806`).
    have h_s2_wf : ∀ i (_ : i < s2.length), wfPoly s2.val[i] := h_s2_wf_all
    have hb := h_s_back s2 h_s2_len h_s2_wf
    simp only [WP.spec_ok]
    refine ⟨hb.1, hb.2.1, hb.2.2.1, ?_⟩
    -- match on err = sc_error = InvalidBlob: the post arm is `True`.
    simp
  · -- b = false → success path: decode_t_prep then after_prep
    rename_i hb_false
    have h_sc_eq : sc_error = Error.NoError := by
      by_contra hne
      apply hb_false
      rw [h_b]; exact hne
    subst h_sc_eq
    -- Specialize h_dec at NoError.
    simp only at h_dec
    obtain ⟨h_s2_wf, _h_decode_fid⟩ := h_dec
    -- Compose s_mut_back@s2 preservations (10 conjuncts).
    have hb := h_s_back s2 h_s2_len h_s2_wf
    have h_back_wfKey : wfKey (s_mut_back s2) params := hb.1
    -- Step decode_t_prep (precondition h_back_wf : wfKey (s_mut_back s2) params).
    step    -- ksv_decap_decode_t_prep
    -- Step after_prep (precondition h_back_wf : 10-conjunct on t_encoded_t_mut_back).
    -- decode_t_prep's i9_post5 carries the back-closure post wrt `(s_mut_back s2)`;
    -- compose with hb to lift to pk_mlkem_key.
    step with ksv_decap_after_prep.spec (s2 := s2)   -- ksv_decap_after_prep
    case h_back_wf =>
      intro t' enc' h_t'_len h_t'_wf
      have hcomp := i9_post6 t' enc' h_t'_len h_t'_wf
      refine ⟨hcomp.1, ?_, ?_, ?_, ?_, ?_⟩
      · rw [hcomp.2.1]; exact hb.2.1
      · rw [hcomp.2.2.1]; exact hb.2.2.1
      · exact hcomp.2.2.2.1
      · -- Convert the underlying `setSlice!` form (`hcomp.2.2.2.2.2.2.2.2.2.2`)
        -- to the elementwise form expected by after_prep's contract.
        intro j h_j
        have h_setSlice := hcomp.2.2.2.2.2.2.2.2.2.2
        have h_ml_lt_24 : matrixLen params + j < 24 := by
          have := k_sq_plus_2k_le_24 params
          unfold matrixLen; grind
        have h_smb_data_len : (s_mut_back s2).data.val.length = 24 :=
          (s_mut_back s2).data.property
        have h_t'_val_len : t'.val.length = (k params : ℕ) := h_t'_len
        -- Rewrite the LHS via the setSlice! equation, then use
        -- List.getElem_setSlice!_middle to extract `t'.val[j]`.
        rw [List.getElem_of_eq h_setSlice]
        rw [List.getElem_setSlice!_middle (s_mut_back s2).data.val t'.val
              (matrixLen params) (matrixLen params + j)
              ⟨by omega, by rw [h_t'_val_len]; omega,
               by rw [h_smb_data_len]; exact h_ml_lt_24⟩]
        fcongr 1; omega
      · -- S-slot content: (t_encoded_t_mut_back (t', enc')).data[sOffset+j] = s2.val[j].
        -- The t-write leaves the ŝ window (in the suffix of the setSlice!)
        -- equal to what `s_mut_back` wrote, i.e. the decoded `s2`.
        intro j h_j
        have h_setSlice := hcomp.2.2.2.2.2.2.2.2.2.2
        have hkk := k_sq_plus_2k_le_24 params
        have h_soj_lt_24 : sOffset params + j < 24 := by unfold sOffset matrixLen; grind
        have h_smb_data_len : (s_mut_back s2).data.val.length = 24 :=
          (s_mut_back s2).data.property
        have h_t'_val_len : t'.val.length = (k params : ℕ) := h_t'_len
        rw [List.getElem_of_eq h_setSlice]
        rw [List.getElem_setSlice!_suffix (s_mut_back s2).data.val t'.val
              (matrixLen params) (sOffset params + j)
              ⟨by rw [h_t'_val_len]; unfold sOffset matrixLen; omega,
               by rw [h_smb_data_len]; exact h_soj_lt_24⟩]
        exact hb.2.2.2.2.2.2.2.2.2.2 j h_j
    refine ⟨err_post1, err_post2, err_post3, ?_⟩
    match err, err_post4 with
    | .NoError, h =>
        -- after_prep's NoError arm = ⟨s-slot content, rest⟩; convert the
        -- s-slot content to `keySEncoded key' = window` via the canonical
        -- round-trip bridge, then thread the rest unchanged.
        obtain ⟨h_s_content, h_rest⟩ := h
        refine ⟨?_, h_rest⟩
        apply keySEncoded_window_bridge key' s2 pb_src h_s2_len (by simp only [h_pas_len]; scalar_tac) h_s_content
        intro j hj
        obtain ⟨h_w, h_fid, h_can⟩ := _h_decode_fid j (by rw [h_s2_len]; exact hj)
        refine ⟨by have := k_le_4 params; scalar_tac, h_fid, h_can⟩
    | .InvalidBlob, h => exact h
    | .Unused, h | .WrongKeySize, h | .WrongBlockSize, h
    | .WrongDataSize, h | .WrongNonceSize, h | .WrongTagSize, h
    | .WrongIterationCount, h | .AuthenticationFailure, h
    | .ExternalFailure, h | .FipsFailure, h | .HardwareFailure, h
    | .NotImplemented, h => exact h.elim

/-- **Spec for `ksv_decap`** — DecapsulationKey format arm dispatcher
(lencheck + lendispatch → `ksv_decap_decode_s` + `ksv_decap_branch_b`). -/
@[step]
theorem ksv_decap.spec
    {params : ParameterSet}
    (pb_src : Slice U8)
    (pk_mlkem_key : mlkem.key.Key)
    (cb_encoded_vector : Usize)
    (p_comp_temps : mlkem.ntt.InternalComputationTemporaries)
    (h_wf : wfKey pk_mlkem_key params)
    (h_cb : cb_encoded_vector.val = 384 * (k params : ℕ)) :
    ksv_decap pb_src pk_mlkem_key cb_encoded_vector p_comp_temps
      ⦃ err key' =>
          wfKey key' params ∧
          key'.params = pk_mlkem_key.params ∧
          key'.n_rows = pk_mlkem_key.n_rows ∧
          match err with
          | Error.NoError =>
              ∃ (h_len : pb_src.length = 768 * (k params : ℕ) + 96),
                keySEncoded key' params = pb_src.toSpecWindow 0 (384 * (k params : ℕ)) (by simp only [h_len]; scalar_tac) ∧
                keyEncodedTPrefix key' params = pb_src.toSpecWindow (384 * (k params : ℕ)) (384 * (k params : ℕ)) (by have := k_le_4 params; simp [h_len]; grind) ∧
                key'.public_seed.toSpec = pb_src.toSpecWindow (768 * (k params : ℕ)) 32 (by simp [h_len]) ∧
                key'.encaps_key_hash.toSpec = pb_src.toSpecWindow (768 * (k params : ℕ) + 32) 32 (by simp [h_len]) ∧
                key'.encaps_key_hash.toSpec = Spec.SHA3.sha3_256 (encapsulationKey key' params) ∧
                key'.private_random.toSpec = pb_src.toSpecWindow (768 * (k params : ℕ) + 64) 32 (by simp [h_len]) ∧
                key'.has_private_seed = false ∧ key'.has_private_key = true ∧
                wfDecapKey key' params
          | Error.WrongKeySize => pb_src.length ≠ 768 * (k params : ℕ) + 96
          | Error.InvalidBlob => True
          | _ => False ⦄ := by
  rw [ksv_decap.fold]
  step
  rw [ksv_decap_lendispatch.fold]
  split
  · rename_i h_ne
    simp only [WP.spec_ok]
    refine ⟨h_wf, rfl, rfl, ?_⟩
    simp only [bne_iff_ne, ne_eq] at h_ne
    intro hcontra
    apply h_ne
    apply UScalar.eq_of_val_eq
    rw [i5_post1, i5_post2]; exact hcontra
  · -- i5 = i6 → decode s, then dispatch on decode error
    rename_i h_eq
    simp only [bne_iff_ne, ne_eq, not_not] at h_eq
    have h_pas_len : pb_src.length = 768 * (k params : ℕ) + 96 := by
      rw [← i5_post1, ← i5_post2]; exact congrArg UScalar.val h_eq
    step    -- ksv_decap_decode_s
    step    -- ksv_decap_branch_b
    · exact i8_post6
    refine ⟨err_post1, err_post2, err_post3, ?_⟩
    match err, err_post4 with
    | .NoError, h => exact ⟨h_pas_len, h⟩
    | .InvalidBlob, h => exact h
    | .Unused, h | .WrongKeySize, h | .WrongBlockSize, h
    | .WrongDataSize, h | .WrongNonceSize, h | .WrongTagSize, h
    | .WrongIterationCount, h | .AuthenticationFailure, h
    | .ExternalFailure, h | .FipsFailure, h | .HardwareFailure, h
    | .NotImplemented, h => exact h.elim


end Symcrust.Properties.MLKEM
