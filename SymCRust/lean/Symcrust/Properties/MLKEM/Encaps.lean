/-
  # Encaps.lean — Top-level specs for `encapsulate_internal`, `encapsulate_ex`,
  `encapsulate`.

  The loops and phases are in `Encaps/Loops.lean` and `Encaps/Phases.lean`.
-/
import Symcrust.Properties.MLKEM.Encaps.Phases
import Symcrust.Properties.MLKEM.Bridges.KPKE_Encrypt
import Symcrust.Properties.MLKEM.Axioms.BoxDefault
import Symcrust.Properties.MLKEM.Helpers.SliceWindowsAssembly

open Aeneas Aeneas.Std Result
open scoped Spec.Notations
open Spec
open Spec.MLKEM
open symcrust

open symcrust.common
open sha3.sha3_impl
namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 8000000

@[step]
theorem mlkem.encapsulate_internal.spec
    (params : ParameterSet)
    (pk_mlkem_key : mlkem.key.Key)
    (pb_agreed_secret : Slice U8)
    (pb_ciphertext : Slice U8)
    (pb_random : Array U8 32#usize)
    (p_comp_temps : mlkem.ntt.InternalComputationTemporaries)
    (h_key : wfEncapKey pk_mlkem_key params)
    (_h_wfpe1 : wfPoly p_comp_temps.poly_element1) :
    mlkem.encapsulate_internal
      pk_mlkem_key pb_agreed_secret pb_ciphertext pb_random p_comp_temps
      ⦃ error pb_agreed_secret' pb_ciphertext' _temps' =>
          match error with
          | .NoError =>
            ∃ (h_a : pb_agreed_secret'.length = 32)
              (h_c : pb_ciphertext'.length = cipherlength params),
              let ek := pk_mlkem_key.toPubKey params
              let r := pb_random.toSpec
              let K := pb_agreed_secret'.toSpec 32 h_a
              let c := pb_ciphertext'.toSpec (cipherlength params) h_c
              MLKEM.Encaps_internal params ek r = (K, c)
          | .InvalidArgument =>
              pb_agreed_secret.length ≠ 32 ∨
              pb_ciphertext.length ≠ cipherlength params
          | _ => False
        ⦄
  := by
  -- Unbundle `wfEncapKey` into the named key-load facts the proof body
  -- consumes (`h_wf`, `h_t_form`, `h_a_form`).  `h_hash` is re-stated
  -- against `encapsulationKey` (defeq to `keyHashPinned`'s
  -- `keyEncodedTPrefix ‖ public_seed`), the form the body consumes.
  obtain ⟨h_wf, h_hash_pinned, h_t_form, h_a_form⟩ := h_key
  have h_hash : pk_mlkem_key.encaps_key_hash.toSpec =
      Spec.SHA3.sha3_256 (encapsulationKey pk_mlkem_key params) := h_hash_pinned
  simp only [mlkem.encapsulate_internal.fold,
             encapsInt.dispatchAgreedLen.fold,
             encapsInt.dispatchCtLen.fold,
             encapsInt.body.fold]
  have h_k_le : (k params : ℕ) ≤ 4 := k_le_4 params
  have h_params_ok := wfKey.params_ok (self := pk_mlkem_key) (p := params) h_wf
  have h_nrows : pk_mlkem_key.params.n_rows.val = (k params : ℕ) :=
    wfInternalParams.n_rows_val h_params_ok
  have h_n_bits_of_u : pk_mlkem_key.params.n_bits_of_u.val = dᵤ params :=
    wfInternalParams.n_bits_of_u_val h_params_ok
  have h_n_bits_of_v : pk_mlkem_key.params.n_bits_of_v.val = dᵥ params :=
    wfInternalParams.n_bits_of_v_val h_params_ok
  have h_n_eta1 : pk_mlkem_key.params.n_eta1.val = (η₁ params : ℕ) :=
    wfInternalParams.n_eta1_val h_params_ok
  have h_n_eta2 : pk_mlkem_key.params.n_eta2.val = (η₂ : ℕ) :=
    wfInternalParams.n_eta2_val h_params_ok
  step*
  case h_pas_len =>
    show pb_agreed_secret.val.length = 32
    have h_guard : ¬(pb_agreed_secret.len != mlkem.SIZEOF_AGREED_SECRET) = true := by assumption
    simp only [bne_iff_ne, ne_eq, not_not] at h_guard
    simp only [mlkem.SIZEOF_AGREED_SECRET] at *
    have := congrArg (·.val) h_guard
    simp at this
    omega
  case h_cb_as =>
    have h_guard : ¬(pb_agreed_secret.len != mlkem.SIZEOF_AGREED_SECRET) = true := by assumption
    simp only [bne_iff_ne, ne_eq, not_not] at h_guard
    show pb_agreed_secret.len.val = 32
    have := congrArg (·.val) h_guard
    simp [mlkem.SIZEOF_AGREED_SECRET] at this
    exact this
  case rOuter =>
    -- Instantiate σ := (G (m ‖ H(ek))).2 — the second 32 bytes of the
    -- output of G, used as the PRF key for sampling r̂ and e₂ (FIPS 203
    -- line 1).
    exact (G (pb_random.toSpec ‖ pk_mlkem_key.encaps_key_hash.toSpec)).2
  case g_base =>
    -- The ghost state for the inner SHAKE absorb chain: init Shake256
    -- (rate=136 bytes, pad=31#u8) then append the second 32 bytes of
    -- the G output (slice [32..64) of cbd_sample_buffer1).
    refine (GhostState.init 136 31#u8 (by decide)).append
            (List.slice 32 64 cbd_sample_buffer1.val) false
  case h_inv =>
    -- Entry invariant at i = 0: vacuous quantifiers, ghost-state plumbing
    -- comes from prelude's post3-5.
    refine ⟨?_, ?_, Nat.zero_le _, ?_, ?_, ?_, ?_, ?_⟩
    · exact pvr_inner_post1
    · exact pvr_inner_post1
    · -- mkhs7.absorbing g_base, where g_base = (init).append (slice ...) false
      exact pvr_inner_post3
    · -- g_base.absorbed.map (·.bv) = rOuter.toList
      simp only [GhostState.append, GhostState.init, List.nil_append]
      exact pvr_inner_post5
    · exact pvr_inner_post4
    · -- ∀ j < 0, vacuous
      intros _ _ _ h; omega
    · -- pvr.val[j] = orig_pvr.val[j], same slice
      intros _ _ _ _ _; rfl
  -- InvalidArgument residual from the `dispatchAgreedLen` agreed-secret-length cascade
  case h1 =>
    rename_i h_g
    simp only [bne_iff_ne, ne_eq, mlkem.SIZEOF_AGREED_SECRET] at h_g
    left
    simp only [Slice.length, ne_eq]
    intro h_len_eq
    apply h_g
    apply UScalar.eq_of_val_eq
    simp [h_len_eq]
  -- After prelude+sampleR (closed above), the second step* drives
  -- through `mulMatR` and `sampleE1Add` (the wfPolyVec strengthening
  -- on sampleR.spec lets step* discharge mulMatR's h_wf_pvr_inner
  -- automatically), and stalls on the four named witnesses for
  -- sampleE1Add (phase 4): rOuter, g_base, h_inv, h_orig_wf_all.
  -- Phase 4 reuses the same σ and prelude-ghost-state as phase 2.
  step*
  case rOuter =>
    exact (G (pb_random.toSpec ‖ pk_mlkem_key.encaps_key_hash.toSpec)).2
  case g_base =>
    refine (GhostState.init 136 31#u8 (by decide)).append
            (List.slice 32 64 cbd_sample_buffer1.val) false
  case h_inv =>
    -- Entry invariant for sampleE1Add at i = 0: ghost-state plumbing
    -- identical to phase 2 (sampleR shares mkhs7, g_base).  The
    -- `pv_tmp3.length = k params` witness comes from mulMatR's post.
    replace h_x_len := pvr_inner2_post2
    refine ⟨h_x_len, h_x_len, Nat.zero_le _, ?_, ?_, ?_, ?_, ?_⟩
    · exact pvr_inner_post3
    · simp only [GhostState.append, GhostState.init, List.nil_append]
      exact pvr_inner_post5
    · exact pvr_inner_post4
    · intros _ _ _ _ h; omega
    · intros _ _ _ _ _; rfl
  case h_orig_wf_all =>
    intros j h_j _h_olen
    replace h_wf_x := pvr_inner2_post4
    exact h_wf_x j (by simp_all [Slice.length])
  -- The third step* drives through buildU_dotE2, shakeE2 — the
  -- wfPolyVec strengthening on sampleE1Add.spec lets step* discharge
  -- buildU_dotE2's h_wf_pv_tmp4 automatically.  Two named witnesses
  -- remain for shakeE2 (phase 5): σ and h_g_absorbed.
  step*
  case σ =>
    exact (G (pb_random.toSpec ‖ pk_mlkem_key.encaps_key_hash.toSpec)).2
  case h_g_absorbed =>
    simp only [GhostState.append, GhostState.init, List.nil_append]
    exact pvr_inner_post5
  -- The fourth step* fully drove through buildV and wipeRepack.
  -- We have error_post1 : error = NoError, error_post2 : agreed'.val =
  -- pb_agreed_secret1.val, error_post3 : ct'.val = (index_mut_back6 s18).val.
  step*
  case h_back4_len =>
    show (index_mut_back4 s10).val.length = cb_u.val + 32 * dᵥ params
    rw [index_mut_back4_post5, List.length_setSlice!]
    have h_guard : pb_ciphertext.len = i5 := by
      have h0 : ¬(pb_ciphertext.len != i5) = true := by assumption
      simp only [bne_iff_ne, ne_eq, not_not] at h0
      exact h0
    have h_pb : pb_ciphertext.val.length = i5.val :=
      congrArg Aeneas.Std.UScalar.val h_guard
    rw [h_pb, i5_post, cb_v_post]
    have hi4 : i4.val = dᵥ params := by
      rw [i4_post, U8.cast_Usize_val_eq]; exact h_n_bits_of_v
    have hi3 : i3.val = 32 := by
      rw [i3_post, MLWE_POLYNOMIAL_COEFFICIENTS_val]
    rw [hi4, hi3]
    ring
  rw [error_post1]
  have h_pas1_len := pvr_inner_post6
  have h_pas1_K := pvr_inner_post7
  have h_agreed_len : pb_agreed_secret'.length = 32 := by
    rw [show pb_agreed_secret'.length = pb_agreed_secret1.length from
        congrArg List.length error_post2]
    exact h_pas1_len
  have h_K_eq : pb_agreed_secret'.toSpec 32 h_agreed_len
              = (G (pb_random.toSpec ‖ H (encapsulationKey pk_mlkem_key params))).1 := by
    -- Bridge `H ek = encaps_key_hash.toSpec` via `h_hash` so the resulting
    -- form is definitionally equal to `(MLKEM.Encaps_internal ...).1` and
    -- the kernel's `refine` unification is a single rfl-unfold rather than
    -- an open-ended whnf search.
    rw [show H (encapsulationKey pk_mlkem_key params)
          = pk_mlkem_key.encaps_key_hash.toSpec from h_hash.symm]
    rw [show pb_agreed_secret'.toSpec 32 h_agreed_len
        = pb_agreed_secret1.toSpec 32 h_pas1_len from ?_]
    · exact h_pas1_K
    · show sliceToSpecBytes _ _ _ = sliceToSpecBytes _ _ _
      simp only [sliceToSpecBytes]
      ext i hi
      simp [error_post2]
  -- Length of the ciphertext slice: `cipherlength params = 32 * (dᵤ k + dᵥ)`.
  -- Follows from the second falsified length guard (ct'.val = (index_mut_back6 s18).val
  -- = (pb_ciphertext.val.setSlice! 0 s10.val).setSlice! cb_u.val s18.val), since
  -- setSlice! preserves the underlying length, and pb_ciphertext.len = i5 = cb_u + cb_v
  -- by the guard.  The heavy `scalar_tac +nonLin` chain is extracted as
  -- `encapsInt.ct_length_from_guard` to keep this theorem's heartbeat budget manageable.
  have h_ct_len : pb_ciphertext'.length = cipherlength params := by
    have h_guard : ¬(pb_ciphertext.len != i5) = true := by assumption
    simp only [bne_iff_ne, ne_eq, not_not] at h_guard
    have h_pb := congrArg (·.val) h_guard
    simp at h_pb
    have hi : i.val = pk_mlkem_key.params.n_rows.val := by simp [i_post]
    have hi1 : i1.val = pk_mlkem_key.params.n_bits_of_u.val := by simp [i1_post]
    have hi4 : i4.val = pk_mlkem_key.params.n_bits_of_v.val := by simp [i4_post]
    show pb_ciphertext'.val.length = cipherlength params
    rw [error_post3, pe_tmp11_post7, index_mut_back4_post5]
    simp only [List.length_setSlice!]
    exact encapsInt.ct_length_from_guard h_params_ok
      h_pb hi hi1 hi4 i2_post i3_post cb_u_post cb_v_post i5_post
  refine ⟨h_agreed_len, h_ct_len, ?_⟩
  show MLKEM.Encaps_internal params (pk_mlkem_key.toPubKey params) pb_random.toSpec
      = (pb_agreed_secret'.toSpec 32 h_agreed_len,
         pb_ciphertext'.toSpec (cipherlength params) h_ct_len)
  rw [Prod.ext_iff]
  refine ⟨h_K_eq.symm, ?_⟩
  symm
  have h_ct_val : pb_ciphertext'.val =
      ((↑pb_ciphertext : List U8).setSlice! 0 s10.val).setSlice! cb_u.val s18.val := by
    rw [error_post3, pe_tmp11_post7, index_mut_back4_post5]
  have h_guard : ¬(pb_ciphertext.len != i5) = true := by assumption
  simp only [bne_iff_ne, ne_eq, not_not] at h_guard
  have h_pb := congrArg (·.val) h_guard
  simp at h_pb
  have hi : i.val = pk_mlkem_key.params.n_rows.val := by simp [i_post]
  have hi1 : i1.val = pk_mlkem_key.params.n_bits_of_u.val := by simp [i1_post]
  have hi4 : i4.val = pk_mlkem_key.params.n_bits_of_v.val := by simp [i4_post]
  have h_pb_len := encapsInt.ct_length_from_guard h_params_ok
    h_pb hi hi1 hi4 i2_post i3_post cb_u_post cb_v_post i5_post
  have h_i3_eq : i3.val = 32 := by
    rw [i3_post]; unfold mlkem.key.MLWE_POLYNOMIAL_COEFFICIENTS; rfl
  have h_cb_v_eq : cb_v.val = 32 * dᵥ params := by
    rw [cb_v_post, h_i3_eq, hi4, h_n_bits_of_v]; ring
  have h_cipher_split : cipherlength params = cb_u.val + 32 * dᵥ params := by
    rw [← h_pb_len, h_pb, i5_post, h_cb_v_eq]
  have h_b_len : cb_u.val + 32 * dᵥ params ≤ pb_ciphertext.length := by
    show cb_u.val + 32 * dᵥ params ≤ pb_ciphertext.val.length
    rw [← h_cipher_split, ← h_pb_len]
  have h_b1 :
      pb_ciphertext'.toSpec (cipherlength params) h_ct_len =
        ((sliceToSpecBytes s10 cb_u.val index_mut_back4_post1) ++
          (sliceToSpecBytes s18 (32 * dᵥ params) pe_tmp11_post5)).cast
            h_cipher_split.symm := by
    apply sliceToSpecBytes_setSlice₂_eq_append index_mut_back4_post1 pe_tmp11_post5
      h_b_len h_cipher_split h_ct_val
  -- Destructure B3's witness; `v_t` is the poly-vector view of the encoded
  -- t̂ prefix, and `h_t` ties it to the byte-form prefix used by the spec.
  -- Combined with `polyVector_byteDecode_byteEncode`, this lets us collapse
  -- `PolyVector.ByteDecode 12 (slice ekPKE 0 (384·k)) = v_t = keyT pk_mlkem_key params`
  -- under the Inv4 9th-conjunct identification (Key/Prelude.lean L435-443).
  obtain ⟨v_t, h_t, h_keyT⟩ := h_t_form
  -- ## Reduce LHS to the bytes-side append form.
  -- After this rewrite, the LHS exposes the two written halves
  -- (`s10` carrying compress-encoded u, `s18` carrying compress-encoded v)
  -- as `sliceToSpecBytes` views, modulo a `Vector.cast`.
  rw [h_b1]
  -- B3/encoded-key prefix: expose the spec-side decoded `t̂` witness.
  -- The remaining B3 obligation is to connect this witness to the
  -- runtime `keyT` view consumed by `vector_mont_dot_product`.
  have h_t_hat_spec :
      MLKEM.PolyVector.ByteDecode 12
        (slice (encapsulationKey pk_mlkem_key params) 0 (384 * (k params : ℕ))
          (by grind)) = v_t :=
    encapsulationKey_prefix_byteDecode_eq_of_encodedT v_t h_t
  -- B2/u-side: assemble the per-row windows written by
  -- `vector_compress_and_encode` into the spec `PolyVector.ByteEncode`
  -- form.  The remaining gap below is to rewrite `toPolyVecOfLen pv_tmp4`
  -- through the sample/matrix invariants to the `u` used by
  -- `K_PKE.Encrypt`.
  have h_cb_u_eq : cb_u.val = (k params : ℕ) * (32 * dᵤ params) := by
    rw [cb_u_post, i2_post, i3_post, hi, hi1,
        h_nrows, h_n_bits_of_u, MLWE_POLYNOMIAL_COEFFICIENTS_val]
    ring_nf
  have h_pv_tmp4_len : pv_tmp4.length = (k params : ℕ) :=
    cbd_sample_buffer3_post1.1
  have h_s10_len_polyvec : s10.length = (k params : ℕ) * (32 * dᵤ params) := by
    rw [index_mut_back4_post1, h_cb_u_eq]
  have h_c1_impl :
      sliceToSpecBytes s10 ((k params : ℕ) * (32 * dᵤ params)) h_s10_len_polyvec =
        MLKEM.PolyVector.ByteEncode (dᵤ params)
          (MLKEM.PolyVector.Compress (dᵤ params)
            (toPolyVecOfLen pv_tmp4 (k params) h_pv_tmp4_len)
            (by rcases params <;> decide))
          (by rcases params <;> decide) := by
    apply Helpers.polyVector_byteEncode_compress_of_per_window
      (dᵤ params) (by rcases params <;> decide) s10 h_s10_len_polyvec
    intro i h_i
    obtain ⟨h_window, h_row⟩ := index_mut_back4_post3 i h_i
    refine ⟨h_window, ?_⟩
    rw [h_row]
    unfold toPolyVecOfLen
    simp only [Vector.getElem_ofFn]
  -- B2/v-side: the scalar encode helper for the second ciphertext half is
  -- already available directly from `buildV.spec`; unfold the `dᵥ < 12`
  -- branch to expose the spec's `ByteEncode (Compress v)` shape.
  have h_c2_impl :
      sliceToSpecBytes s18 (32 * dᵥ params) pe_tmp11_post5 =
        MLKEM.ByteEncode (dᵥ params)
          (MLKEM.Polynomial.Compress (dᵥ params) (toPoly pe_tmp04)
            (by rcases params <;> decide))
          (by rcases params <;> decide) := by
    rw [pe_tmp11_post6]
    unfold compressEncodePoly
    have h_dv_lt : dᵥ params < 12 := by rcases params <;> decide
    simp only [h_dv_lt, _root_.dite_true]
  let r_spec : 𝔹 32 :=
    (G (pb_random.toSpec ‖ H (encapsulationKey pk_mlkem_key params))).2
  let Â_spec : MLKEM.PolyMatrix q (k params) :=
    Matrix.of fun i j =>
      MLKEM.SampleNTT
        (pk_mlkem_key.public_seed.toSpec ‖
          #v[((j : ℕ) : Byte)] ‖ #v[((i : ℕ) : Byte)])
  let y_spec : MLKEM.PolyVector q (k params) :=
    Vector.ofFn fun i =>
      MLKEM.SamplePolyCBD
        (MLKEM.PRF (η₁ params) r_spec (((i : ℕ) : Byte)))
  let e₁_spec : MLKEM.PolyVector q (k params) :=
    Vector.ofFn fun i =>
      MLKEM.SamplePolyCBD
        (MLKEM.PRF η₂ r_spec ((((k params : ℕ) + (i : ℕ) : ℕ) : Byte)))
  have h_A_matrix :
      Matrix.of (keyAHat pk_mlkem_key params) = Matrix.transpose Â_spec := by
    funext i j
    obtain ⟨i, hi⟩ := i
    obtain ⟨j, hj⟩ := j
    simp only [Matrix.of_apply, Matrix.transpose, Â_spec]
    exact h_a_form i j hi hj
  have h_u_value :
      toPolyVecOfLen pv_tmp4 (k params) h_pv_tmp4_len =
        MLKEM.PolyVector.NTTInv
          (MLKEM.PolyMatrix.MulVectorNTT
            (Matrix.transpose Â_spec) (MLKEM.PolyVector.NTT y_spec)) + e₁_spec := by
    -- Identify the outer hash with `r_spec` via `h_hash`.
    have h_r :
        (G (pb_random.toSpec ‖ pk_mlkem_key.encaps_key_hash.toSpec)).2 = r_spec := by
      simp only [r_spec, h_hash, H]
      rfl
    -- Unbundle the loop-1 (sampleE1Add) and loop-0 (sampleR) invariants.
    obtain ⟨h_len4, h_olen4, _, _, _, _, h_done4, _⟩ := cbd_sample_buffer3_post1
    obtain ⟨h_len_pvr1, _, _, _, _, _, h_done_r, _⟩ := mkhs8_post1
    -- Identify `Vector.ofFn (NTT ∘ toPoly pvr_inner1)` with `y_spec.NTT`.
    have h_ŷ :
        (Vector.ofFn fun (j : Fin (k params : ℕ)) =>
            MLKEM.NTT (toPoly ((↑pvr_inner1 : List _)[(j : ℕ)]'(by
              show pvr_inner1.val.length > (j : ℕ)
              rw [show pvr_inner1.val.length = pvr_inner1.length from rfl,
                  h_len_pvr1]; exact j.is_lt))))
          = MLKEM.PolyVector.NTT y_spec := by
      unfold MLKEM.PolyVector.NTT
      apply Vector.ext; intro j hj
      simp only [Vector.getElem_ofFn, Vector.getElem_map, y_spec]
      rw [h_r] at h_done_r
      exact congrArg MLKEM.NTT (h_done_r j hj h_len_pvr1 hj).2
    -- Pull `encaps_u_chain` backwards on the RHS so we can compare per-row
    -- against the `pv_tmp3 = R · NTTInv (Rinv · MulVec)` form from
    -- `pvr_inner2_post6` directly.
    rw [← encaps_u_chain (Matrix.transpose Â_spec)
          (MLKEM.PolyVector.NTT y_spec) e₁_spec]
    -- Per-index equality.
    apply Vector.ext; intro i hi
    -- LHS: `toPolyVecOfLen pv_tmp4 (k params) _`[i] = `toPoly pv_tmp4[i]`.
    -- Then apply the loop-1 invariant to get the `pv_tmp3[i] + cbd` form.
    simp only [toPolyVecOfLen, Vector.getElem_ofFn]
    rw [(h_done4 i hi h_len4 h_olen4 hi).2.2]
    -- RHS: `(PolyVector.NTTInv ... + e₁_spec)[i]` — unfold `+` and pick coords.
    show _ = (Vector.ofFn (fun (j : Fin (k params : ℕ)) =>
      (MLKEM.PolyVector.NTTInv
        (((MLKEM.PolyMatrix.MulVectorNTT (Matrix.transpose Â_spec)
            (MLKEM.PolyVector.NTT y_spec)).map (fun p => p.map (fun x => Rinv * x))).map
          (fun p => p.map (fun x => R * x))))[(j : ℕ)] + e₁_spec[(j : ℕ)]))[i]
    rw [Vector.getElem_ofFn]
    -- Identify `e₁_spec[i]` with the `cbd` summand on the LHS.
    have h_e1_get : e₁_spec[i] =
        MLKEM.SamplePolyCBD
          (MLKEM.PRF η₂ r_spec ((((k params : ℕ) + i : ℕ) : Byte))) := by
      simp only [e₁_spec, Vector.getElem_ofFn]
    rw [h_e1_get, h_r]
    -- Rewrite the matrix-vector summand on the LHS via `pvr_inner2_post6`,
    -- `h_A_matrix`, and `h_ŷ`; then reduce the per-row RHS form.
    rw [pvr_inner2_post6 i hi, h_A_matrix, h_ŷ]
    simp only [MLKEM.PolyVector.NTTInv, Vector.getElem_map]
    -- Last step: move outer `.map (R·)` past `NTTInv` via `NTTInv_scalarMul`.
    rw [← NTTInv_scalarMul R]; rfl
  /- ## V-side scaffolding (mirrors the u-side above). -/
  let e₂_spec : MLKEM.Polynomial q :=
    MLKEM.SamplePolyCBD
      (MLKEM.PRF η₂ r_spec (((2 * (k params : ℕ) : ℕ) : Byte)))
  let μ_spec : MLKEM.Polynomial q :=
    MLKEM.Polynomial.Decompress 1
      (MLKEM.ByteDecode (d := 1) (pb_random.toSpec.cast (by simp)) ⟨by decide, by decide⟩)
      ⟨by decide, by decide⟩
  have h_v_value :
      toPoly pe_tmp04 =
        MLKEM.NTTInv (MLKEM.PolyVector.innerProductNTT
          v_t (MLKEM.PolyVector.NTT y_spec)) + e₂_spec + μ_spec := by
    have h_r : (G (pb_random.toSpec ‖ pk_mlkem_key.encaps_key_hash.toSpec)).2 = r_spec := by
      simp only [r_spec, h_hash, H]; rfl
    obtain ⟨h_len_pvr1, _, _, _, _, _, h_done_r, _⟩ := mkhs8_post1
    have h_ŷ_vec :
        toPolyVecOfLen pvr_inner2 (k params) pvr_inner2_post1 = y_spec.NTT := by
      unfold MLKEM.PolyVector.NTT
      apply Vector.ext; intro j hj
      simp only [toPolyVecOfLen, Vector.getElem_ofFn, Vector.getElem_map, y_spec]
      rw [pvr_inner2_post5 j hj]
      rw [h_r] at h_done_r
      exact congrArg MLKEM.NTT (h_done_r j hj h_len_pvr1 hj).2
    rw [pe_tmp11_post4]
    apply Vector.ext; intro i hi
    simp only [Vector.getElem_ofFn]
    show (toPoly pe_tmp03)[i] + (toPoly pe_tmp11)[i] = _
    rw [mkhs11_post4]
    simp only [Vector.getElem_ofFn]
    rw [show Vector.get (toPoly _) ⟨i, hi⟩ = (toPoly _)[i] from rfl]
    rw [show Vector.get (toPoly pe_tmp1) ⟨i, hi⟩ = (toPoly pe_tmp1)[i] from rfl]
    rw [index_mut_back4_post4, h_keyT, h_ŷ_vec]
    rw [mkhs11_post3, pe_tmp11_post3, h_r]
    rw [NTTInv_scalarMul Rinv]
    simp only [Vector.getElem_map]
    rw [show R * (Rinv * (MLKEM.NTTInv (v_t.innerProductNTT y_spec.NTT))[i])
            = R * Rinv * (MLKEM.NTTInv (v_t.innerProductNTT y_spec.NTT))[i] from by ring,
        R_mul_Rinv, one_mul]
    show _ = ((MLKEM.NTTInv (v_t.innerProductNTT y_spec.NTT) + e₂_spec).zipWith
                 (· + ·) μ_spec)[i]
    rw [Vector.getElem_zipWith]
    show _ = ((MLKEM.NTTInv (v_t.innerProductNTT y_spec.NTT)).zipWith
                 (· + ·) e₂_spec)[i] + _
    rw [Vector.getElem_zipWith]
    have h_e2 :
        MLKEM.SamplePolyCBD (MLKEM.PRF η₂ r_spec (2 * ↑↑(k params))) = e₂_spec := by
      show _ = MLKEM.SamplePolyCBD (MLKEM.PRF η₂ r_spec ((2 * (k params : ℕ) : ℕ) : Byte))
      have h_byte : ((2 : Byte) * ↑↑(k params)) = ((2 * (k params : ℕ) : ℕ) : Byte) := by
        push_cast; ring
      rw [h_byte]
    have h_mu : decodeDecompressPoly 1 pb_random.toSpec ⟨by decide, by decide⟩ = μ_spec := by
      show MLKEM.Polynomial.Decompress 1 (MLKEM.ByteDecode pb_random.toSpec ⟨by decide, by decide⟩) ⟨by decide, by decide⟩ = _
      rfl
    rw [h_e2, h_mu]
  -- Step 1: align the LHS length on the u-side via h_cb_u_eq so that
  -- the byte-side append matches h_c1_impl's domain.
  have h_align : sliceToSpecBytes s10 (↑cb_u) index_mut_back4_post1
      = (sliceToSpecBytes s10 ((k params : ℕ) * (32 * dᵤ params))
          h_s10_len_polyvec).cast h_cb_u_eq.symm := by
    apply Vector.ext; intro i hi
    simp only [sliceToSpecBytes, Vector.getElem_ofFn, Vector.getElem_cast]
  rw [h_align]
  rw [h_c1_impl]
  rw [h_c2_impl]
  rw [h_u_value]
  -- v-side bridge via congrArg (avoids `rw [h_v_value]` heartbeat).
  have h_dv_bounds : 1 ≤ dᵥ params ∧ dᵥ params < 12 := by rcases params <;> decide
  have h_dv_bounds' : 1 ≤ dᵥ params ∧ dᵥ params ≤ 12 := by rcases params <;> decide
  have h_B :
      ByteEncode (dᵥ params)
        (Polynomial.Compress (dᵥ params) (toPoly pe_tmp04) h_dv_bounds) h_dv_bounds'
      = ByteEncode (dᵥ params)
        (Polynomial.Compress (dᵥ params)
          (MLKEM.NTTInv (MLKEM.PolyVector.innerProductNTT v_t (MLKEM.PolyVector.NTT y_spec))
            + e₂_spec + μ_spec) h_dv_bounds) h_dv_bounds' :=
    congrArg
      (fun p => ByteEncode (dᵥ params)
        (Polynomial.Compress (dᵥ params) p h_dv_bounds) h_dv_bounds')
      h_v_value
  rw [h_B]
  -- Helper: pull a `Vector.cast` past an append.
  have h_cast_append :
      ∀ {α} {n m k : ℕ} (h : n = k) (xs : Vector α n) (ys : Vector α m),
        (xs.cast h) ++ ys = (xs ++ ys).cast (by omega) := by
    intros _ _ _ _ h xs ys; subst h; rfl
  rw [h_cast_append]
  -- Now both sides are `Vector.cast _ (encode_u ++ encode_v)` — close via the
  -- spec-side helper `K_PKE.Encrypt_eq_ciphers`.  The Encaps_internal
  -- projection unfolds to `K_PKE.Encrypt` with `r := (G ...).2 = r_spec`.
  show _ =
      Spec.MLKEM.K_PKE.Encrypt params
        (encapsulationKey pk_mlkem_key params) pb_random.toSpec
        (G (pb_random.toSpec ‖ H (encapsulationKey pk_mlkem_key params))).2
  have h_r : (G (pb_random.toSpec ‖ H (encapsulationKey pk_mlkem_key params))).2 = r_spec := rfl
  rw [h_r,
      Bridges.K_PKE.Encrypt_eq_ciphers params
        (encapsulationKey pk_mlkem_key params) pb_random.toSpec r_spec
        v_t Â_spec y_spec e₁_spec e₂_spec μ_spec
        (by rw [encapsulationKey_suffix_eq]; rfl)
        (by rw [encapsulationKey_prefix_byteDecode_eq_of_encodedT _ h_t])
        rfl rfl rfl rfl]
  -- After the rewrite, both sides have the same `Vector.cast h (c₁ ‖ c₂)` shape.
  rfl

/-! ## `encapsulate_ex` — Box allocation + dispatch to `_internal` -/

/-- **Spec for `encapsulate_ex`**.

Allocates `InternalComputationTemporaries`, then dispatches to
`encapsulate_internal`.  Returns `MemoryAllocationFailure` if
allocation fails.  Length validation happens inside `_internal`, so the
length witnesses live in the `NoError` arm existentially.

Informal proof. Unfold `encapsulate_ex`; the body is a
`Box::<InternalComputationTemporaries>::default()` call followed by a
delegate to `encapsulate_internal`. Two arms:
- Allocation success: `step` produces a fresh `temps` with
  `Box::default` semantics (axiomatized in `Axioms/BoxDefault.lean`),
  then apply `encapsulate_internal.spec`. The `NoError`/`InvalidArgument`
  arms propagate; the existential length witnesses are forwarded.
- Allocation failure: post is `True` — trivial. The `Result.bind`
  short-circuit lets `Error.MemoryAllocationFailure` propagate without
  reaching the inner call. -/
@[step]
theorem mlkem.encapsulate_ex.spec
    (params : ParameterSet)
    (pk_mlkem_key : mlkem.key.Key) (pb_random : Array U8 32#usize)
    (pb_agreed_secret pb_ciphertext : Slice U8)
    (h_key : wfEncapKey pk_mlkem_key params) :
    mlkem.encapsulate_ex pk_mlkem_key pb_random pb_agreed_secret
        pb_ciphertext
      ⦃ error pb_agreed_secret' pb_ciphertext' =>
          match error with
          | .NoError =>
              ∃ (h_a : pb_agreed_secret'.length = 32)
                (h_c : pb_ciphertext'.length = cipherlength params),
                let ek := pk_mlkem_key.toPubKey params
                let r := pb_random.toSpec
                let (K, c) := MLKEM.Encaps_internal params ek r
                K = pb_agreed_secret'.toSpec 32 h_a ∧
                c = pb_ciphertext'.toSpec (cipherlength params) h_c
          | .InvalidArgument =>
              pb_agreed_secret.length ≠ 32 ∨
              pb_ciphertext.length ≠ cipherlength params
          | .MemoryAllocationFailure => out_of_memory
          | _ => False
          ⦄ := by
  unfold mlkem.encapsulate_ex
  step*
  all_goals first
    | (cases e <;> simp_all)
    | (assumption)
    | simp_all
  grind

/-! ## `encapsulate` — top-level public entry with randomness

The FC postcondition existentially quantifies the random draw `m : 𝔹 32`:
for *some* `m` consistent with the visible outputs, the outputs match
`MLKEM.Encaps_internal params ek m`. (`encapsulate_internal`'s FC is
deterministic; the existential covers the opaque randomness source.) -/

/-- **Bridge** — given a witness `v_t : PolyVector q k` and the byte-form
equation `keyEncodedTPrefix self params = ByteEncode 12 v_t` (modulo cast),
`Encaps.KeyCheck` accepts the assembled `encapsulationKey`.

The proof reduces the ekPKE slice to `keyEncodedTPrefix`, rewrites via
`h_t_form` to `ByteEncode 12 v_t`, then applies the PolyVector-level
round-trip `polyVector_byteDecode_byteEncode` (`Bridges/Encoding.lean`).

**Why the precondition is shaped this way.** `wfKey` is layout-only
(see its docstring in `Bridges/KeyView.lean`) and does NOT carry the
byte-form connection between `self.encoded_t` and a `PolyVector`.
The byte-form witness must come from the caller, which obtains it from
`mlkem.key_expand_from_private_seed.spec`'s postcondition (`Key.lean`). -/
private theorem encaps_keycheck_holds
    {self : mlkem.key.Key} {params : ParameterSet}
    (v_t : MLKEM.PolyVector q (k params))
    (h_t_form : keyEncodedTPrefix self params =
                (MLKEM.PolyVector.ByteEncode 12 v_t).cast
                  (polyVector_byteEncode_size_cast 12)) :
    Encaps.KeyCheck params (encapsulationKey self params) = true := by
  have h_slice : slice (encapsulationKey self params) 0 (384 * (k params : ℕ))
      (by grind) = keyEncodedTPrefix self params := by
    unfold encapsulationKey
    apply Vector.ext
    intro i hi
    unfold slice
    simp only [Vector.getElem_ofFn]
    change (Vector.append (keyEncodedTPrefix self params) self.public_seed.toSpec)[0 + i] = _
    rw [show Vector.append (keyEncodedTPrefix self params) self.public_seed.toSpec
            = keyEncodedTPrefix self params ++ self.public_seed.toSpec from rfl]
    rw [Vector.getElem_append (i := 0 + i)]
    simp [hi]
  unfold Encaps.KeyCheck
  show (decide _) = true
  rw [h_slice, h_t_form,
      polyVector_byteDecode_byteEncode 12 ⟨by decide, by decide⟩ v_t]
  apply decide_eq_true
  apply Vector.ext; intro i hi
  simp

/-- **Spec for `encapsulate`** (top-level public entry).

Informal proof. Unfold `encapsulate`; the body samples 32 random
bytes via the system randomness primitive (`Properties/Axioms/
System.lean :: rand_bytes`) into a fresh array `pb_random : Array U8
32`, then delegates to `encapsulate_ex`. The proof:
1. `step` through the randomness draw; the resulting `pb_random.val`
   is an opaque `𝔹 32` value — bind it as `m` via the FC's
   existential `∃ m : 𝔹 32, ...`.
2. Apply `encapsulate_ex.spec` with this `m` — its NoError arm
   delivers `Encaps_internal params ek m`-equality for both
   outputs, threading through the same length witnesses.
3. Re-package as `∃ m, ∃ h_a, ∃ h_c, ...` — `m` is the just-bound
   random draw; `h_a`/`h_c` come from the inner existential.
The `MemoryAllocationFailure` arm yields `out_of_memory` (propagated
from `encapsulate_ex`); other arms likewise. The existential over `m`
covers the opaque randomness source.

**Preconditions `h_hash` and `h_t_form`.** Both are key-load
invariants, not function-local checks. Verified against the
Rust source (`SymCRust/src/mlkem/mlkem.rs`):

* `encapsulate_internal` (mlkem.rs:587-722) does NOT re-validate
  `encoded_t` — it consumes the pre-decoded `pk_mlkem_key.t()`
  (mlkem.rs:689 `vector_mont_dot_product`) and uses
  `pk_mlkem_key.encaps_key_hash` directly (L622) as the
  precomputed `H(ek)` for `G(m ‖ H(ek))`. No re-hash, no
  re-decode.
* The byte-form `keyEncodedTPrefix = ByteEncode 12 v_t` is
  enforced at **key-load time**:
  - `key_set_value(EncapsulationKey)` mlkem.rs:397: calls
    `vector_decode_and_decompress(&encoded_t, 12, t)` — returns
    `Error::InvalidBlob` if any decoded coefficient is ≥ q.
  - `key_set_value(DecapsulationKey)` mlkem.rs:346: same check.
  - `key_expand_from_private_seed` mlkem.rs:232: builds
    `encoded_t` via `vector_compress_and_encode(t, 12, ...)` from
    a freshly-sampled valid PolyVector `t`.
* Similarly `encaps_key_hash` is computed at key-load time
  (mlkem.rs:139 for KeyGen; mlkem.rs:362-372 for
  `key_set_value(DecapsulationKey)`, where it is also re-checked
  against the blob's hash slot before accepting the load) and
  copied into the encapsulation-key field at mlkem.rs:413.

FIPS 203 §7.3 explicitly leaves dk-validation policy
implementation-defined; SymCrypt's choice is to pay once at key
load and skip on each encapsulate/decapsulate. Both
preconditions are therefore architectural invariants every
valid `Key` carries by construction, exposed by
`key_set_value.spec` (`Encoding/KeySetValue.lean`,
EncapsulationKey/DecapsulationKey arms) and by
`key_expand_from_private_seed.spec` (`Key.lean`). -/
@[step]
theorem mlkem.encapsulate.spec
    (params : ParameterSet)
    (pk_mlkem_key : mlkem.key.Key)
    (pb_agreed_secret pb_ciphertext : Slice U8)
    (h_key : wfEncapKey pk_mlkem_key params) :
    mlkem.encapsulate pk_mlkem_key pb_agreed_secret pb_ciphertext
      ⦃ error pb_agreed_secret' pb_ciphertext' =>
          match error with
          | .NoError =>
              -- Bind FC to the top-level `MLKEM.Encaps` (Alg. 20); the
              -- unobservable random draw is the outermost existential (`tape : RandomTape`).
              -- `MLKEM.Encaps` is `Option`-valued: `none` iff §7.2's
              -- `Encaps.KeyCheck` (ByteEncode∘ByteDecode round-trip on
              -- ekPKE) fails.  Under `wfEncapKey`, every encoded coefficient
              -- is < q (wfPolyVec), so the round-trip is identity and
              -- `MLKEM.Encaps` is necessarily `some _`.  Length witnesses
              -- live here because the function validates lengths internally.
              ∃ (tape : MLKEM.RandomTape)
                (h_a : pb_agreed_secret'.length = 32)
                (h_c : pb_ciphertext'.length = cipherlength params),
                match MLKEM.Encaps params
                        (pk_mlkem_key.toPubKey params) tape with
                | some (K, c, _) =>
                    K = pb_agreed_secret'.toSpec 32 h_a ∧
                    c = pb_ciphertext'.toSpec (cipherlength params) h_c
                | none => False
          | .InvalidArgument =>
              pb_agreed_secret.length ≠ 32 ∨
              pb_ciphertext.length ≠ cipherlength params
          | .MemoryAllocationFailure =>
              -- Propagated through `encapsulate_ex` from its
              -- `try_new_box_default.ICT.spec` allocation gate, which
              -- yields `out_of_memory` on failure.
              out_of_memory
          | _ => False ⦄ := by
  unfold mlkem.encapsulate
  have h_t_form := wfEncapKey.byte_form_t (self := pk_mlkem_key) (p := params) h_key
  step*
  cases sc_error1 <;> try agrind
  case NoError =>
    -- Existential witness: the random tape returned by `common.random`
    -- (currently anonymous in context as `x✝²`).  By `sc_error_post3`,
    -- `s1`'s bytes equal the tape's first `s1.length = 32` bytes.
    rename MLKEM.RandomTape => tape
    -- `sc_error1_post` matches on `Error.NoError` (literal); reduce it.
    simp only [] at sc_error1_post
    obtain ⟨h_a, h_c, h_eq⟩ := sc_error1_post
    refine ⟨tape, h_a, h_c, ?_⟩
    -- Goal: match Encaps params ek tape with | some (K, c, _) => ... | none => False
    -- where ek = encapsulationKey pk_mlkem_key params.
    --
    -- Encaps = if Encaps.KeyCheck p ek then some (Encaps_internal p ek m, tape')
    --          else none
    -- where m = (tape.readBytes 32).1.
    --
    -- We need:
    --   (a) Encaps.KeyCheck params ek = true        ← BRIDGE (wfKey ⇒ KeyCheck)
    --   (b) (tape.readBytes 32).1 = (to_slice_mut_back s1).toSpec
    -- Then the match reduces to `Encaps_internal …` and the conjuncts come
    -- from h_K, h_C.
    have h_s1_len : s1.length = 32 := by
      simp [Slice.length, sc_error_post2, s_post1]
    have h_tape : (tape.readBytes 32).1 = (to_slice_mut_back s1).toSpec := by
      apply Vector.ext
      intro i hi
      have hi_s1 : i < s1.length := by rw [h_s1_len]; exact hi
      have h_bi : (↑s1 : List U8)[i].bv = tape i := by
        have h_post := sc_error_post3 i hi_s1
        -- new shape: (s1.val[i] : Byte) = tape i, i.e., BitVec.ofNat 8 s1.val[i].val = tape i
        have h_cast : BitVec.ofNat 8 ((↑s1 : List U8)[i]).val = ((↑s1 : List U8)[i]).bv := by
          bv_tac 8
        rw [← h_cast]; exact h_post
      show (Vector.ofFn (fun i : Fin 32 => tape i))[i] = _
      rw [Vector.getElem_ofFn]
      show tape i = (Vector.ofFn (fun j : Fin 32 =>
        ((to_slice_mut_back s1).val[j.val]'(by
          have := (to_slice_mut_back s1).property; grind)).bv))[i]
      rw [Vector.getElem_ofFn]
      show tape i = ((to_slice_mut_back s1).val[i]).bv
      rw [s_post2]
      have h_from : ((Array.repeat 32#usize 0#u8).from_slice s1).val = s1.val :=
        Array.from_slice_val _ s1 (by
          rw [show s1.val.length = s1.length from rfl]; exact h_s1_len)
      rw [show ((Array.repeat 32#usize 0#u8).from_slice s1).val[i] = (↑s1 : List U8)[i]
              from by fcongr 1]
      exact h_bi.symm
    have h_kc : Encaps.KeyCheck params (encapsulationKey pk_mlkem_key params) = true := by
      obtain ⟨v_t, h_t, _h_keyT⟩ := h_t_form
      exact encaps_keycheck_holds v_t h_t
    -- Unfold `Encaps`; the `let (m, _) := tape.readBytes 32`
    -- discriminant simplifies via h_tape; the `if KeyCheck` collapses
    -- to `some _` via h_kc; the resulting tuple matches via h_eq.
    show match Encaps params (encapsulationKey pk_mlkem_key params) tape with
         | some (K, c, _) =>
             K = pb_agreed_secret1.toSpec 32 h_a ∧
             c = pb_ciphertext1.toSpec (cipherlength params) h_c
         | none => False
    unfold Encaps
    simp only [h_kc, ↓reduceIte, h_tape, h_eq]
    trivial

end Symcrust.Properties.MLKEM
