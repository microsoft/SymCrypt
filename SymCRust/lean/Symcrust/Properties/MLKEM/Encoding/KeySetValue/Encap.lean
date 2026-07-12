/-
  # Encoding/KeySetValue/Encap.lean — EncapsulationKey arm specs.

  Contains `ksv_encap_after_prep` and `ksv_encap`
  (the EncapsulationKey format-arm dispatcher).  Independent of
  `KeySetValue/Decap.lean` — the two files build in parallel.
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

/-! ### `ksv_encap_after_prep` — terminal Encap arm content

Opaque ~25-bind tail starting from `(p, t_encoded_t_mut_back)`:
decode `t` from `encoded_t[0..cb]`, branch on decode error, copy
`public_seed` from `pb_src[cb..cb+32]`, re-expand A and recompute
H(ek), run final length massert.

Reachable error variants: `NoError`, `InvalidBlob` (only from t decode
at d=12). -/
@[step]
theorem ksv_encap_after_prep.spec
    {params : ParameterSet}
    (pb_src : Slice U8) (pk_mlkem_key : mlkem.key.Key)
    (cb_encoded_vector : Usize)
    (p_comp_temps : mlkem.ntt.InternalComputationTemporaries)
    (i8 : Usize)
    (t : Slice PolyElement)
    (encoded_t : Array U8 1536#usize)
    (t_encoded_t_mut_back :
      Slice PolyElement × Array U8 1536#usize → mlkem.key.Key)
    (h_wf : wfKey pk_mlkem_key params)
    (h_cb : cb_encoded_vector.val = 384 * (k params : ℕ))
    (h_i8 : i8.val = cb_encoded_vector.val)
    (h_pas_len : pb_src.length = 384 * (k params : ℕ) + 32)
    (h_p1_len : t.length = (k params : ℕ))
    (h_p1_wf : ∀ i (_ : i < t.length), wfPoly t.val[i])
    (h_p2_len : encoded_t.val.length = 1536)
    /- Encoded_t window mirrors `pb_src[0..cb]` — established by
       the preceding `ksv_encap_decode_t_prep` step. -/
    (h_p2_enc : ∀ (j : Nat) (h_j : j < cb_encoded_vector.val),
                  encoded_t.val[j]'(by simp only [h_p2_len]; have := h_cb; have := k_le_4 params; scalar_tac) =
                  pb_src.val[j]'(by have := h_pas_len; have := h_cb;
                                     have := k_le_4 params; scalar_tac))
    /- Back-closure semantics — fields preserved from `pk_mlkem_key`
       except encoded_t (replaced by the argument pair). -/
    (h_back_wf : ∀ (t' : Slice PolyElement) (enc' : Array U8 1536#usize),
                   t'.length = (k params : ℕ) →
                   (∀ i (_ : i < t'.length), wfPoly t'.val[i]) →
                   wfKey (t_encoded_t_mut_back (t', enc')) params ∧
                   (t_encoded_t_mut_back (t', enc')).params = pk_mlkem_key.params ∧
                   (t_encoded_t_mut_back (t', enc')).n_rows = pk_mlkem_key.n_rows ∧
                   (t_encoded_t_mut_back (t', enc')).encoded_t = enc' ∧
                   (t_encoded_t_mut_back (t', enc')).data.val =
                     pk_mlkem_key.data.val.setSlice! (matrixLen params) t'.val) :
    ksv_encap_after_prep pb_src pk_mlkem_key cb_encoded_vector
        p_comp_temps i8 t encoded_t t_encoded_t_mut_back
      ⦃ err key' =>
          wfKey key' params ∧
          key'.params = pk_mlkem_key.params ∧
          key'.n_rows = pk_mlkem_key.n_rows ∧
          match err with
          | Error.NoError =>
              /- EncapsulationKey-arm FC: encoded_t prefix matches
                 `pb_src[0..cb]`; ρ matches `pb_src[cb..cb+32]`;
                 H(ek) recomputed by `key_compute_encapsulation_key_hash`;
                 flags reflect a public-only key. -/
              keyEncodedTPrefix key' params = pb_src.toSpecWindow 0 (384 * (k params : ℕ)) (by simp [h_pas_len]) ∧
              key'.public_seed.toSpec = pb_src.toSpecWindow (384 * (k params : ℕ)) 32 (by simp [h_pas_len]) ∧
              key'.encaps_key_hash.toSpec = Spec.SHA3.sha3_256 (encapsulationKey key' params) ∧
              key'.has_private_seed = false ∧ key'.has_private_key = false ∧
              /- Bundled crypto-level commitments for the encapsulation key —
                 consumed by `mlkem.encapsulate.spec` (which precondition's
                 `wfEncapKey`).  See `wfEncapKey` structure in
                 `Sampling/ExpandMatrix.lean` for the three component fields. -/
              wfEncapKey key' params
          | Error.InvalidBlob => True
          | _ => False ⦄ := by
  unfold ksv_encap_after_prep
  have hk_ge2 := k_ge_2 params
  have hk_le4 := k_le_4 params
  step    -- s3 := encoded_t[0..cb]
  -- Capture the slice + its posts in non-shadowed bindings.
  set err_slice := s3 with h_err_slice
  have err_slice_val_eq : err_slice.val = (encoded_t.to_slice.val).slice 0 cb_encoded_vector.val :=
    s3_post1
  have err_slice_len : err_slice.length = cb_encoded_vector.val - 0 := s3_post2
  step    -- (sc_error, t1) := vector_decode_and_decompress s3 12 t
  case h_wf_in => exact h_p1_wf
  step    -- b := sc_error.ne NoError
  split
  · -- b = true → error path
    rename_i hb_true
    have h_sc_ne : sc_error ≠ Error.NoError := by
      have := b_post.symm.trans hb_true
      exact of_decide_eq_true this
    have h_sc_eq : sc_error = Error.InvalidBlob := by
      cases hsc : sc_error
      all_goals first
        | rfl
        | (rw [hsc] at h_sc_ne; exact (h_sc_ne rfl).elim)
        | (rw [hsc] at sc_error_post3; exact sc_error_post3.elim)
    subst h_sc_eq
    have h_t1_wf := sc_error_post2
    have h_t1_len : t1.length = (k params : ℕ) := by
      rw [sc_error_post1]; exact h_p1_len
    have hb := h_back_wf t1 encoded_t h_t1_len h_t1_wf
    simp only [WP.spec_ok]
    refine ⟨hb.1, hb.2.1, hb.2.2.1, ?_⟩
    simp
  · -- b = false → NoError path
    rename_i hb_false
    have h_sc_eq : sc_error = Error.NoError := by
      by_contra hne
      apply hb_false
      rw [b_post]; exact decide_eq_true hne
    subst h_sc_eq
    simp only at sc_error_post3
    have h_t1_wf := sc_error_post2
    have h_t1_len : t1.length = (k params : ℕ) := by
      rw [sc_error_post1]; exact h_p1_len
    have hb := h_back_wf t1 encoded_t h_t1_len h_t1_wf
    set pk1 := t_encoded_t_mut_back (t1, encoded_t) with h_pk1_def
    have h_pk1_wf : wfKey pk1 params := hb.1
    have h_pk1_params : pk1.params = pk_mlkem_key.params := hb.2.1
    have h_pk1_n_rows : pk1.n_rows = pk_mlkem_key.n_rows := hb.2.2.1
    have h_pk1_enc : pk1.encoded_t = encoded_t := hb.2.2.2.1
    have h_pk1_data : pk1.data.val =
        pk_mlkem_key.data.val.setSlice! (matrixLen params) t1.val :=
      hb.2.2.2.2
    have h_pk1_n_rows_val : pk1.n_rows.val = (k params : ℕ) :=
      h_pk1_n_rows ▸ wfKey.n_rows_ok h_wf
    have h_pubseed_len : pk1.public_seed.val.length = 32 := pk1.public_seed.property
    step    -- s4 := pk1.public_seed.to_slice
    step    -- (s5, to_slice_mut_back) := pk1.public_seed.to_slice_mut
    step    -- i9 := i8 + s4.len
    step    -- s6 := pb_src[i8..i9]
    step    -- s7 := copy_from_slice s5 s6
    case hlen =>
      have h_s4_len : s4.length = 32 := by rw [s4_post]; exact h_pubseed_len
      simp [s5_post1, s6_post2, i9_post, h_s4_len]
    step    -- s8 := (to_slice_mut_back s7).to_slice
    step    -- pb_curr := i8 + s8.len
    -- Construct the post-public_seed key explicitly.
    set pk1' : mlkem.key.Key :=
      { algorithm_info := pk1.algorithm_info, has_private_seed := pk1.has_private_seed,
        has_private_key := pk1.has_private_key, private_seed := pk1.private_seed,
        private_random := pk1.private_random, public_seed := to_slice_mut_back s7,
        encoded_t := pk1.encoded_t, encaps_key_hash := pk1.encaps_key_hash,
        params := pk1.params, n_rows := pk1.n_rows, data := pk1.data } with h_pk1'_def
    have h_pk1'_wf : wfKey pk1' params := by
      refine ⟨?_, ?_, ?_⟩
      · exact wfKey.params_ok (self := pk1) h_pk1_wf
      · exact wfKey.n_rows_ok (self := pk1) h_pk1_wf
      · exact wfKey.data_wf (self := pk1) h_pk1_wf
    -- Step the matrix expansion with explicit params instantiation.
    step with mlkem.key_expand_public_matrix_from_public_seed.spec params pk1' p_comp_temps h_pk1'_wf
    have h_pk2_params_eq : pk_mlkem_key2.params = pk_mlkem_key.params := by
      have h2 : pk_mlkem_key2.params = _ :=
        wfKey.params_ok (self := pk_mlkem_key2) pk_mlkem_key2_post1
      have h1 : pk_mlkem_key.params = _ :=
        wfKey.params_ok (self := pk_mlkem_key) h_wf
      rw [h2, h1]
    have h_pk2_nrows_val : pk_mlkem_key.params.n_rows.val = (k params : ℕ) :=
      wfInternalParams.n_rows_val (wfKey.params_ok (self := pk_mlkem_key) h_wf)
    step with Bridges.mlkem.key.Key.a_transpose_mut.spec pk_mlkem_key2 params pk_mlkem_key2_post1
    step
    case h_wf => exact s9_post2
    -- Build pk3 = a_transpose_mut_back s10 and discharge its key invariants.
    have h_s10_len : s10.length = matrixLen params := by grind
    have h_pk3_all := s9_post4 s10 h_s10_len s10_post1
    -- nudge LSP to re-elaborate
    set pk3 := a_transpose_mut_back s10 with h_pk3_def
    have h_pk3_wf : wfKey pk3 params := h_pk3_all.1
    have h_pk3_params : pk3.params = pk_mlkem_key2.params := h_pk3_all.2.1
    have h_pk3_n_rows : pk3.n_rows = pk_mlkem_key2.n_rows := h_pk3_all.2.2.1
    have h_pk3_pubseed : pk3.public_seed = pk_mlkem_key2.public_seed := h_pk3_all.2.2.2.1
    have h_pk3_enc : pk3.encoded_t = pk_mlkem_key2.encoded_t := h_pk3_all.2.2.2.2.1
    have h_pk3_n_rows_val : pk3.n_rows.val = (k params : ℕ) :=
      wfKey.n_rows_ok h_pk3_wf
    step with mlkem.key_compute_encapsulation_key_hash.spec params pk3 p_comp_temps1 h_pk3_wf
    have h_s8_len : s8.length = 32 := by
      have h1 : (to_slice_mut_back s7).val.length = 32 :=
        (to_slice_mut_back s7).property
      simp [s8_post, Std.Array.to_slice, h1]
    have h_pb_curr_val : pb_curr.val = pb_src.length := by
      have h1 : s8.len.val = s8.length := rfl
      rw [pb_curr_post, h_i8, h_cb, h1, h_s8_len, h_pas_len]
    step
    -- Final FC conjunction.  Build the field-preservation chain:
    -- pk_mlkem_key4 → pk3 (a_transpose_mut_back s10) → pk_mlkem_key2 → pk1' → pk1 → pk_mlkem_key.
    -- params:    pk4 = pk3 = pk_mlkem_key2 = pk_mlkem_key.params  (a_transpose_mut + key_expand + struct)
    -- n_rows:    similar chain
    -- encoded_t: pk4 = pk3 = pk_mlkem_key2 = pk1.encoded_t = encoded_t (the input array)
    -- public_seed: pk4 = pk3 = pk_mlkem_key2 = to_slice_mut_back s7
    have h_pk2_params : pk_mlkem_key2.params = pk_mlkem_key.params := h_pk2_params_eq
    have h_pk2_n_rows : pk_mlkem_key2.n_rows = pk_mlkem_key.n_rows :=
      pk_mlkem_key2_post6.trans h_pk1_n_rows
    have h_pk2_enc : pk_mlkem_key2.encoded_t = encoded_t :=
      pk_mlkem_key2_post7.trans h_pk1_enc
    have h_pk3_n_rows' : pk3.n_rows = pk_mlkem_key.n_rows := h_pk3_n_rows.trans h_pk2_n_rows
    have h_pk3_params' : pk3.params = pk_mlkem_key.params := h_pk3_params.trans h_pk2_params
    have h_pk3_enc' : pk3.encoded_t = encoded_t := h_pk3_enc.trans h_pk2_enc
    have h_pk3_pubseed' : pk3.public_seed = to_slice_mut_back s7 :=
      h_pk3_pubseed.trans pk_mlkem_key2_post2
    -- The final returned record overrides has_private_seed/has_private_key to false.
    -- pk_mlkem_key4 has all of pk3's field-preservation properties chained.
    have h_pk4_params : pk_mlkem_key4.params = pk_mlkem_key.params :=
      pk_mlkem_key4_post5.trans h_pk3_params'
    have h_pk4_n_rows : pk_mlkem_key4.n_rows = pk_mlkem_key.n_rows :=
      pk_mlkem_key4_post6.trans h_pk3_n_rows'
    have h_pk4_enc : pk_mlkem_key4.encoded_t = encoded_t :=
      pk_mlkem_key4_post3.trans h_pk3_enc'
    have h_pk4_pubseed : pk_mlkem_key4.public_seed = to_slice_mut_back s7 :=
      pk_mlkem_key4_post4.trans h_pk3_pubseed'
    refine ⟨?_, h_pk4_params, h_pk4_n_rows, ?_, ?_, ?_⟩
    · refine ⟨?_, ?_, ?_⟩
      · show wfInternalParams pk_mlkem_key4.params params
        exact wfKey.params_ok pk_mlkem_key4_post1
      · show pk_mlkem_key4.n_rows.val = (k params : ℕ)
        exact wfKey.n_rows_ok pk_mlkem_key4_post1
      · intro i h_end
        exact wfKey.data_wf pk_mlkem_key4_post1 i h_end
    · -- keyEncodedTPrefix bridge
      unfold keyEncodedTPrefix Slice.toSpecWindow sliceWindowToSpecBytes
      apply Vector.ext
      intro i hi
      simp only [Vector.getElem_ofFn, Nat.zero_add]
      have h_pb := h_p2_enc i (by rw [h_cb]; exact hi)
      rw [h_pk4_enc, h_pb]
      simp
    · -- public_seed bridge
      have h_s5_len : s5.length = 32 := by
        have h_eq : s5.val.length = pk1.public_seed.val.length := by
          rw [← Slice.length, ← s5_post1]
        rw [show s5.length = s5.val.length from rfl, h_eq]
        exact pk1.public_seed.property
      have h_s7_len : s7.length = 32 := s7_post1.trans h_s5_len
      have h_s4_len : s4.len.val = 32 := by
        rw [s4_post]; exact pk1.public_seed.property
      have h_i9_val : i9.val = i8.val + 32 := i9_post.trans (by rw [h_s4_len])
      have h_i8_val : i8.val = 384 * (k params : ℕ) := h_i8.trans h_cb
      have h_pas_len' : (↑pb_src : List U8).length = 384 * (k params : ℕ) + 32 := h_pas_len
      have h_pubseed_eq : pk_mlkem_key4.public_seed = pk1.public_seed.from_slice s7 := by
        rw [h_pk4_pubseed, s5_post2]
      have h_s7_len_list : (↑s7 : List U8).length = 32 := h_s7_len
      have h_arr_val : (pk1.public_seed.from_slice s7).val = s7.val :=
        Aeneas.Std.Array.from_slice_val _ _ (by rw [h_s7_len_list]; rfl)
      have h_s6_len_list : (↑s6 : List U8).length = 32 := by
        have h1 : s6.length = i9.val - i8.val := s6_post2
        have h2 : i9.val - i8.val = 32 := by rw [h_i9_val]; scalar_tac
        show s6.val.length = 32
        rw [← Slice.length]; rw [h1, h2]
      unfold Slice.toSpecWindow sliceWindowToSpecBytes
      rw [show pk_mlkem_key4.public_seed.toSpec
            = arrayToSpecBytes pk_mlkem_key4.public_seed from rfl,
          h_pubseed_eq]
      apply Vector.ext
      intro i hi
      simp only [arrayToSpecBytes, Vector.getElem_ofFn]
      have h_i_arr : i < (pk1.public_seed.from_slice s7).val.length := by
        rw [h_arr_val, h_s7_len_list]; exact hi
      have h_i_s7 : i < (↑s7 : List U8).length := by rw [h_s7_len_list]; exact hi
      have h_i_s6 : i < (↑s6 : List U8).length := by rw [h_s6_len_list]; exact hi
      have h_i_pb : i8.val + i < (↑pb_src : List U8).length := by
        rw [h_pas_len', h_i8_val]; exact Nat.add_lt_add_left hi _
      have h_arr_idx : (pk1.public_seed.from_slice s7).val[i]'h_i_arr =
          s7.val[i]'h_i_s7 :=
        List.getElem_of_eq h_arr_val h_i_arr
      rw [h_arr_idx]
      have h_s7_idx : s7.val[i]'h_i_s7 = s6.val[i]'h_i_s6 :=
        List.getElem_of_eq s7_post2 h_i_s7
      rw [h_s7_idx]
      have h_s6_idx : s6.val[i]'h_i_s6 = pb_src.val[i8.val + i]'h_i_pb := by
        rw [List.getElem_of_eq s6_post1]
        have hbound : i9.val ≤ pb_src.val.length ∧ i8.val + i < i9.val := by
          refine ⟨?_, ?_⟩
          · show i9.val ≤ (↑pb_src : List U8).length
            rw [h_pas_len', h_i9_val, h_i8_val]
          · rw [h_i9_val]; exact Nat.add_lt_add_left hi _
        exact List.getElem_slice i8.val i9.val i pb_src.val hbound
      rw [h_s6_idx]
      show (↑pb_src : List U8)[↑i8 + i].bv =
        (Vector.ofFn fun (j : Fin 32) => (↑pb_src : List U8)[384 * (k params : ℕ) + j.val].bv)[i]'(by simpa using hi)
      rw [Vector.getElem_ofFn]
      simp [← h_i8_val]
    · -- SHA3 conjunct ∧ flags ∧ wfEncapKey: split into SHA3+flags (existing
      -- proof) and wfEncapKey (new bundle).
      refine ⟨?_, ?_⟩
      · -- SHA3 conjunct (existing proof, also discharges trailing flag rfls
        -- via has_private_seed/key projection on struct-update).
        rw [encapsulationKey_struct_upd_flags]
        show arrayToSpecBytes pk_mlkem_key4.encaps_key_hash = _
        rw [pk_mlkem_key4_post11]
        apply congrArg SHA3.sha3_256
        have h_enc : keyEncodedTPrefix (a_transpose_mut_back s10) params
            = keyEncodedTPrefix pk_mlkem_key4 params := by
          unfold keyEncodedTPrefix
          apply Vector.ext
          intro i hi
          simp only [Vector.getElem_ofFn]
          have h : (↑pk_mlkem_key4.encoded_t : List U8) = (↑(a_transpose_mut_back s10).encoded_t : List U8) :=
            congrArg (·.val) pk_mlkem_key4_post3
          have hi' : i < (↑pk_mlkem_key4.encoded_t : List U8).length := by
            have hp : (↑pk_mlkem_key4.encoded_t : List U8).length = 1536 :=
              pk_mlkem_key4.encoded_t.property
            rw [hp]; scalar_tac
          fcongr 1
          apply congrArg
          exact (List.getElem_of_eq h hi').symm
        have h_pub : arrayToSpecBytes (a_transpose_mut_back s10).public_seed
            = arrayToSpecBytes pk_mlkem_key4.public_seed := by
          rw [pk_mlkem_key4_post4]
        show keyEncodedTPrefix (a_transpose_mut_back s10) params
            ‖ arrayToSpecBytes (a_transpose_mut_back s10).public_seed
          = encapsulationKey pk_mlkem_key4 params
        unfold encapsulationKey
        rw [h_enc, h_pub]
        rfl
      · -- wfEncapKey key' params.
        --
        -- The final returned key' = { pk_mlkem_key4 with has_private_seed := false,
        -- has_private_key := false }.  Every wfEncapKey field reads only
        -- data / encoded_t / public_seed / encaps_key_hash, all preserved by the
        -- flag-only struct update — so we prove each field about pk_mlkem_key4
        -- and ride the projection through (iota-reduces).
        refine ⟨?_, ?_, ?_, ?_⟩
        · -- towfKey: wfKey { pk_mlkem_key4 with flags } params.
          refine ⟨?_, ?_, ?_⟩
          · show wfInternalParams pk_mlkem_key4.params params
            exact wfKey.params_ok pk_mlkem_key4_post1
          · show pk_mlkem_key4.n_rows.val = (k params : ℕ)
            exact wfKey.n_rows_ok pk_mlkem_key4_post1
          · intro i h_end
            exact wfKey.data_wf pk_mlkem_key4_post1 i h_end
        · -- hash_pinned: identical to the SHA3 conjunct above (L294-323), but
          -- packaged as `keyHashPinned` (= `encaps_key_hash.toSpec = SHA3 (...)`).
          show arrayToSpecBytes pk_mlkem_key4.encaps_key_hash =
            Spec.SHA3.sha3_256
              (keyEncodedTPrefix pk_mlkem_key4 params
                ‖ arrayToSpecBytes pk_mlkem_key4.public_seed)
          rw [pk_mlkem_key4_post11]
          apply congrArg Spec.SHA3.sha3_256
          have h_enc : keyEncodedTPrefix (a_transpose_mut_back s10) params
              = keyEncodedTPrefix pk_mlkem_key4 params := by
            unfold keyEncodedTPrefix
            apply Vector.ext
            intro i hi
            simp only [Vector.getElem_ofFn]
            have h : (↑pk_mlkem_key4.encoded_t : List U8) =
                (↑(a_transpose_mut_back s10).encoded_t : List U8) :=
              congrArg (·.val) pk_mlkem_key4_post3
            have hi' : i < (↑pk_mlkem_key4.encoded_t : List U8).length := by
              have hp : (↑pk_mlkem_key4.encoded_t : List U8).length = 1536 :=
                pk_mlkem_key4.encoded_t.property
              rw [hp]; scalar_tac
            fcongr 1
            apply congrArg
            exact (List.getElem_of_eq h hi').symm
          have h_pub : arrayToSpecBytes (a_transpose_mut_back s10).public_seed
              = arrayToSpecBytes pk_mlkem_key4.public_seed := by
            rw [pk_mlkem_key4_post4]
          rw [h_enc, h_pub]
        · -- byte_form_t — close via byte_form_t_bridge.
          --
          -- WHY-VALID: the runtime's d=12 InvalidBlob check ensures every
          -- raw 12-bit segment of `pb_src[0..384k]` (= encoded_t after copy)
          -- is < q.  The bridge wraps this canonicity (exposed by
          -- `vector_decode_and_decompress.spec`'s NoError post) into the
          -- FIPS-203 byte-form commitment
          -- `keyEncodedTPrefix self p = (ByteEncode 12 (keyT self p)).cast _`.
          refine ⟨keyT _ params, ?_, rfl⟩
          have hkk := k_sq_plus_2k_le_24 params
          have h_pk4_data_len : pk_mlkem_key4.data.val.length = 24 :=
            pk_mlkem_key4.data.property
          have h_pk3_data_len : pk3.data.val.length = 24 := pk3.data.property
          have h_pk2_data_len : pk_mlkem_key2.data.val.length = 24 :=
            pk_mlkem_key2.data.property
          have h_pk_data_len : pk_mlkem_key.data.val.length = 24 :=
            pk_mlkem_key.data.property
          have h_pk1_data_len : pk1.data.val.length = 24 := pk1.data.property
          have h_t1_val_len : t1.val.length = (k params : ℕ) := h_t1_len
          -- Data-bridge: pk_mlkem_key4.data[matrixLen + j] = t1.val[j].
          have h_data_t :
              ∀ (j : ℕ) (h_j : j < (k params : ℕ)),
                pk_mlkem_key4.data.val[matrixLen params + j]'(by
                  rw [h_pk4_data_len]; unfold matrixLen; grind) =
                t1.val[j]'(by rw [h_t1_val_len]; exact h_j) := by
            intro j hj
            have h_mlj_lt_24 : matrixLen params + j < 24 := by
              unfold matrixLen; grind
            have h_mlj_ge : matrixLen params ≤ matrixLen params + j := by omega
            have h_mlj_lt_dataEnd : matrixLen params + j < Bridges.dataEnd params := by
              unfold matrixLen Bridges.dataEnd; grind
            have h_mlj_lt_pk4 : matrixLen params + j < pk_mlkem_key4.data.val.length := by
              rw [h_pk4_data_len]; exact h_mlj_lt_24
            have h_mlj_lt_pk3 : matrixLen params + j < pk3.data.val.length := by
              rw [h_pk3_data_len]; exact h_mlj_lt_24
            have h_mlj_lt_pk2 : matrixLen params + j < pk_mlkem_key2.data.val.length := by
              rw [h_pk2_data_len]; exact h_mlj_lt_24
            have h_mlj_lt_pk1' : matrixLen params + j < pk1'.data.val.length := by
              show matrixLen params + j < pk1.data.val.length
              rw [h_pk1_data_len]; exact h_mlj_lt_24
            have h_mlj_lt_pk1 : matrixLen params + j < pk1.data.val.length := by
              rw [h_pk1_data_len]; exact h_mlj_lt_24
            have h_mlj_lt_pk : matrixLen params + j < pk_mlkem_key.data.val.length := by
              rw [h_pk_data_len]; exact h_mlj_lt_24
            -- pk_mlkem_key4.data = pk3.data
            have h_eq43 : pk_mlkem_key4.data.val[matrixLen params + j]'h_mlj_lt_pk4 =
                pk3.data.val[matrixLen params + j]'h_mlj_lt_pk3 :=
              List.getElem_of_eq (congrArg (·.val) pk_mlkem_key4_post2) _
            -- pk3.data[mlj] = pk_mlkem_key2.data[mlj] via slot frame (col-clause is .1,
            -- slot-frame is .2; h_pk3_all.2.2.2.2.2.2.2.2.2.2.2)
            have h_eq32 : pk3.data.val[matrixLen params + j]'h_mlj_lt_pk3 =
                pk_mlkem_key2.data.val[matrixLen params + j]'(by
                  rw [h_pk2_data_len]; exact h_mlj_lt_24) := by
              -- s9_post4 instantiated as h_pk3_all gives the back-closure post;
              -- but a_transpose_mut's frame is wrt `self = pk_mlkem_key2`.
              have := h_pk3_all.2.2.2.2.2.2.2.2.2.2.2
                        (matrixLen params + j) h_mlj_ge h_mlj_lt_24
              exact this
            -- pk_mlkem_key2.data[mlj] = pk1'.data[mlj] via key_expand's slot frame
            -- (pk_mlkem_key2_post4 takes ⟨matrixLen ≤ slot, slot < dataEnd⟩)
            have h_eq21 : pk_mlkem_key2.data.val[matrixLen params + j]'h_mlj_lt_pk2 =
                pk1'.data.val[matrixLen params + j]'h_mlj_lt_pk1' :=
              pk_mlkem_key2_post4 (matrixLen params + j) ⟨h_mlj_ge, h_mlj_lt_dataEnd⟩
            -- pk1'.data = pk1.data (struct update preserves data field)
            have h_eq1'_1 : pk1'.data.val[matrixLen params + j]'h_mlj_lt_pk1' =
                pk1.data.val[matrixLen params + j]'h_mlj_lt_pk1 := rfl
            -- pk1.data[mlj] = t1.val[j] via setSlice!_middle
            have h_t1_len_nat : t1.val.length = (k params : ℕ) := h_t1_val_len
            have h_setSlice :
                (pk_mlkem_key.data.val.setSlice! (matrixLen params) t1.val)[matrixLen params + j]'(by
                    rw [List.length_setSlice!, h_pk_data_len]; exact h_mlj_lt_24) =
                t1.val[(matrixLen params + j) - matrixLen params]'(by
                    rw [h_t1_len_nat]; omega) := by
              apply List.getElem_setSlice!_middle pk_mlkem_key.data.val t1.val
                (matrixLen params) (matrixLen params + j)
                ⟨h_mlj_ge,
                 by rw [h_t1_len_nat]; omega,
                 by rw [h_pk_data_len]; exact h_mlj_lt_24⟩
            have h_pk1_eq : pk1.data.val[matrixLen params + j]'h_mlj_lt_pk1 =
                t1.val[j]'(by rw [h_t1_val_len]; exact hj) := by
              have h_pk1_at : pk1.data.val[matrixLen params + j]'h_mlj_lt_pk1 =
                  (pk_mlkem_key.data.val.setSlice! (matrixLen params) t1.val)[matrixLen params + j]'(by
                    rw [List.length_setSlice!, h_pk_data_len]; exact h_mlj_lt_24) :=
                List.getElem_of_eq h_pk1_data _
              rw [h_pk1_at, h_setSlice]
              fcongr 1; omega
            -- Chain the equations.
            exact h_eq43.trans (h_eq32.trans (h_eq21.trans (h_eq1'_1.trans h_pk1_eq)))
          -- Encoded_t bridge: pk_mlkem_key4.encoded_t.val[i] = err.val[i].
          have h_enc_t_len : encoded_t.val.length = 1536 := encoded_t.property
          have h_pk4_enc_len : pk_mlkem_key4.encoded_t.val.length = 1536 :=
            pk_mlkem_key4.encoded_t.property
          have h_err_len_val : err_slice.val.length = 384 * (k params : ℕ) := by
            rw [show err_slice.val.length = err_slice.length from rfl,
                err_slice_len, h_cb]; omega
          have h_enc_err :
              ∀ (i : ℕ) (h_i : i < 384 * (k params : ℕ)),
                pk_mlkem_key4.encoded_t.val[i]'(by
                  rw [h_pk4_enc_len]; have := k_le_4 params; grind) =
                err_slice.val[i]'(by rw [h_err_len_val]; exact h_i) := by
            intro i hi
            have h_i_lt_enc : i < encoded_t.val.length := by
              rw [h_enc_t_len]; have := k_le_4 params; grind
            have h_cb_le_enc : cb_encoded_vector.val ≤ encoded_t.val.length := by
              rw [h_enc_t_len, h_cb]; have := k_le_4 params; grind
            have h_i_lt_cb : i < cb_encoded_vector.val := by rw [h_cb]; exact hi
            have h_eq_enc : pk_mlkem_key4.encoded_t.val[i]'(by
                rw [h_pk4_enc_len]; have := k_le_4 params; grind) =
                encoded_t.val[i]'h_i_lt_enc :=
              List.getElem_of_eq (congrArg (·.val) h_pk4_enc) _
            have h_to_slice : encoded_t.to_slice.val = encoded_t.val := by
              simp [Aeneas.Std.Array.to_slice]
            have h_err_eq_slice : err_slice.val = encoded_t.val.slice 0 cb_encoded_vector.val := by
              rw [err_slice_val_eq, h_to_slice]
            have h_err_eq : err_slice.val[i]'(by rw [h_err_len_val]; exact hi) =
                (encoded_t.val.slice 0 cb_encoded_vector.val)[i]'(by
                  rw [← h_err_eq_slice]; show i < err_slice.val.length
                  rw [h_err_len_val]; exact hi) :=
              List.getElem_of_eq h_err_eq_slice _
            have h_slice_eq := List.getElem_slice 0 cb_encoded_vector.val i encoded_t.val
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
            exact sc_error_post3 j hj'
          -- Discharge `key' = { pk_mlkem_key4 with flags := false }` ⇒ same
          -- `keyEncodedTPrefix`/`keyT` (struct update is flag-only).
          show keyEncodedTPrefix pk_mlkem_key4 params =
                 (MLKEM.PolyVector.ByteEncode 12 (keyT pk_mlkem_key4 params)).cast
                   (Bridges.polyVector_byteEncode_size_cast 12)
          exact byte_form_t_bridge pk_mlkem_key4 t1 err_slice
                  h_t1_len h_err_len_val h_data_t h_enc_err h_row
        · -- matrix_form_a: chain
          --   key'.data[i*k+j]  = pk_mlkem_key4.data[i*k+j]  (iota: flag-only update)
          --                     = pk3.data[i*k+j]            (pk_mlkem_key4_post2)
          --                     = s10[i*k+j]                  (back-col-clause of s9_post4 via h_pk3_all)
          --   toPoly s10[i*k+j] = toPoly s9[j*k+i]            (s10_post3, transpose swap; nrows=k)
          --                     = toPoly pk_mlkem_key2.data[j*k+i] (s9_post3)
          --                     = SampleNTT (expandAEntrySeed ρ j i)  (pk_mlkem_key2_post3 j i)
          --                     = SampleNTT (ρ ‖ #v[i] ‖ #v[j])  (def of expandAEntrySeed,
          --                                                       ρ = to_slice_mut_back s7 = pk4.public_seed)
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
          have h_pk4_data_len : pk_mlkem_key4.data.val.length = 24 :=
            pk_mlkem_key4.data.property
          have h_pk3_data_len : pk3.data.val.length = 24 := pk3.data.property
          have h_pk2_data_len : pk_mlkem_key2.data.val.length = 24 :=
            pk_mlkem_key2.data.property
          have h_s10_val_len : s10.val.length = matrixLen params := h_s10_len
          have h_s9_val_len : s9.val.length = matrixLen params := s9_post1
          have h_ij_lt_pk4 : i * (k params : ℕ) + j < pk_mlkem_key4.data.val.length := by
            rw [h_pk4_data_len]; unfold matrixLen at h_idx_lt; grind
          have h_ij_lt_pk3 : i * (k params : ℕ) + j < pk3.data.val.length := by
            rw [h_pk3_data_len]; unfold matrixLen at h_idx_lt; grind
          have h_ij_lt_s10 : i * (k params : ℕ) + j < s10.val.length := by
            rw [h_s10_val_len]; exact h_idx_lt
          have h_ji_lt_s9 : j * (k params : ℕ) + i < s9.val.length := by
            rw [h_s9_val_len]; exact h_swap_lt
          have h_ji_lt_pk2 : j * (k params : ℕ) + i < pk_mlkem_key2.data.val.length := by
            rw [h_pk2_data_len]; unfold matrixLen at h_swap_lt; grind
          -- Element equation: pk_mlkem_key4.data[ij] = pk3.data[ij] = s10[ij]
          have h_data4_eq_3 : pk_mlkem_key4.data.val[i * (k params : ℕ) + j]'h_ij_lt_pk4 =
              pk3.data.val[i * (k params : ℕ) + j]'h_ij_lt_pk3 := by
            have h_eq : pk_mlkem_key4.data.val = pk3.data.val :=
              congrArg (·.val) pk_mlkem_key4_post2
            exact List.getElem_of_eq h_eq _
          have h_data3_eq_s10 : pk3.data.val[i * (k params : ℕ) + j]'h_ij_lt_pk3 =
              s10.val[i * (k params : ℕ) + j]'h_ij_lt_s10 :=
            h_pk3_all.2.2.2.2.2.2.2.2.2.2.1 (i * (k params : ℕ) + j) h_idx_lt
          -- Element equation: s9[ji] = pk_mlkem_key2.data[ji]
          have h_s9_eq_pk2 : s9.val[j * (k params : ℕ) + i]'h_ji_lt_s9 =
              pk_mlkem_key2.data.val[j * (k params : ℕ) + i]'h_ji_lt_pk2 :=
            s9_post3 (j * (k params : ℕ) + i) s9_post1 h_swap_lt
          -- toPoly equation for the matrix transpose, with bound proofs aligned to
          -- the n_rows = k convention via h_pk2_nrows_val.
          have h_i_nr : i < pk_mlkem_key.params.n_rows.val := by rw [h_pk2_nrows_val]; exact hi
          have h_j_nr : j < pk_mlkem_key.params.n_rows.val := by rw [h_pk2_nrows_val]; exact hj
          have h_trans_raw := s10_post3 i j h_i_nr h_j_nr
          -- Lift the Nat index inside the getElems via getElem_congr_idx
          -- (h_pk2_nrows_val : pk_mlkem_key.params.n_rows.val = k params).
          have h_idx_ij : i * pk_mlkem_key.params.n_rows.val + j = i * (k params : ℕ) + j := by
            rw [h_pk2_nrows_val]
          have h_idx_ji : j * pk_mlkem_key.params.n_rows.val + i = j * (k params : ℕ) + i := by
            rw [h_pk2_nrows_val]
          rw [getElem_congr_idx (c := s10.val) h_idx_ij,
              getElem_congr_idx (c := s9.val) h_idx_ji] at h_trans_raw
          have h_trans : toPoly (s10.val[i * (k params : ℕ) + j]'h_ij_lt_s10) =
              toPoly (s9.val[j * (k params : ℕ) + i]'h_ji_lt_s9) := h_trans_raw
          -- pk_mlkem_key2_post3 at row=j col=i.
          have h_pk2_sample := pk_mlkem_key2_post3 j i hj hi
          -- Assemble the chain.
          show toPoly (pk_mlkem_key4.data.val[i * (k params : ℕ) + j]'h_ij_lt_pk4) =
            MLKEM.SampleNTT
              (arrayToSpecBytes pk_mlkem_key4.public_seed
                ‖ #v[(i : Byte)] ‖ #v[(j : Byte)])
          rw [h_data4_eq_3, h_data3_eq_s10, h_trans, congrArg toPoly h_s9_eq_pk2,
              h_pk2_sample]
          -- Reduce expandAEntrySeed and rewrite ρ.
          unfold expandAEntrySeed
          rw [show arrayToSpecBytes pk_mlkem_key4.public_seed
                = arrayToSpecBytes (to_slice_mut_back s7) from by rw [h_pk4_pubseed]]
          rfl

/-- **Spec for `ksv_encap`** — EncapsulationKey format arm dispatcher
(lencheck + lendispatch → `ksv_encap_body`). -/
@[step]
theorem ksv_encap.spec
    {params : ParameterSet}
    (pb_src : Slice U8)
    (pk_mlkem_key : mlkem.key.Key)
    (cb_encoded_vector : Usize)
    (p_comp_temps : mlkem.ntt.InternalComputationTemporaries)
    (h_wf : wfKey pk_mlkem_key params)
    (h_cb : cb_encoded_vector.val = 384 * (k params : ℕ)) :
    ksv_encap pb_src pk_mlkem_key cb_encoded_vector p_comp_temps
      ⦃ err key' =>
          wfKey key' params ∧
          key'.params = pk_mlkem_key.params ∧
          key'.n_rows = pk_mlkem_key.n_rows ∧
          match err with
          | Error.NoError =>
              ∃ (h_len : pb_src.length = 384 * (k params : ℕ) + 32),
                keyEncodedTPrefix key' params = pb_src.toSpecWindow 0 (384 * (k params : ℕ)) (by simp [h_len]) ∧
                key'.public_seed.toSpec = pb_src.toSpecWindow (384 * (k params : ℕ)) 32 (by simp [h_len]) ∧
                key'.encaps_key_hash.toSpec = Spec.SHA3.sha3_256 (encapsulationKey key' params) ∧
                key'.has_private_seed = false ∧ key'.has_private_key = false ∧
                wfEncapKey key' params ∧
                encapsulationKey key' params = pb_src.toSpec (384 * (k params : ℕ) + 32) h_len
          | Error.WrongKeySize => pb_src.length ≠ 384 * (k params : ℕ) + 32
          | Error.InvalidBlob => True
          | _ => False ⦄ := by
  rw [ksv_encap.fold]
  step
  rw [ksv_encap_lendispatch.fold]
  split
  · rename_i h_ne
    simp only [WP.spec_ok]
    refine ⟨h_wf, rfl, rfl, ?_⟩
    simp only [bne_iff_ne, ne_eq] at h_ne
    intro hcontra
    apply h_ne
    apply UScalar.eq_of_val_eq
    rw [i5_post1, i5_post2]; exact hcontra
  · -- i5 = i6 → decode t_prep then after_prep
    rename_i h_eq
    simp only [bne_iff_ne, ne_eq, not_not] at h_eq
    have h_pas_len : pb_src.length = 384 * (k params : ℕ) + 32 := by
      rw [← i5_post1, ← i5_post2]; exact congrArg UScalar.val h_eq
    step    -- ksv_encap_decode_t_prep
    step    -- ksv_encap_after_prep
    case h_back_wf =>
      intro t' enc' h_t'_len h_t'_wf
      have hb := i8_post6 t' enc' h_t'_len h_t'_wf
      exact ⟨hb.1, hb.2.1, hb.2.2.1, hb.2.2.2.1, hb.2.2.2.2.2.2.2.2.2.2⟩
    refine ⟨err_post1, err_post2, err_post3, ?_⟩
    match err, err_post4 with
    | .NoError, h =>
        refine ⟨h_pas_len, h.1, h.2.1, h.2.2.1, h.2.2.2.1, h.2.2.2.2.1, h.2.2.2.2.2, ?_⟩
        -- Build encapsulationKey = pb_src.toSpec from the two window equalities.
        unfold encapsulationKey
        rw [h.1, h.2.1]
        exact (slice_toSpec_eq_concat2 pb_src h_pas_len
                  (by simp [h_pas_len]) (by simp [h_pas_len])).symm
    | .InvalidBlob, h => exact h
    | .Unused, h | .WrongKeySize, h | .WrongBlockSize, h
    | .WrongDataSize, h | .WrongNonceSize, h | .WrongTagSize, h
    | .WrongIterationCount, h | .AuthenticationFailure, h
    | .ExternalFailure, h | .FipsFailure, h | .HardwareFailure, h
    | .NotImplemented, h => exact h.elim

end Symcrust.Properties.MLKEM
