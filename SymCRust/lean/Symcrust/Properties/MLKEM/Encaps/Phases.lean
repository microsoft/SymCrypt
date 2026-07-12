/-
  # Encaps/Phases.lean — 8-phase decomposition of `encapsulate_internal`.

  Split from `Encaps.lean` for parallel elaboration.  The loops (Loop 0 and
  Loop 1) are in `Encaps/Loops.lean`; the top-level specs (`encapsulate_internal`,
  `encapsulate_ex`, `encapsulate`) are in `Encaps.lean`.
-/
import Symcrust.Properties.MLKEM.Encaps.Loops
import Symcrust.Properties.MLKEM.Bridges.KPKE_Encrypt
import Symcrust.Properties.MLKEM.Ntt.Ntt
import Symcrust.Properties.MLKEM.Ntt.Intt
import Symcrust.Properties.MLKEM.Ntt.MatVec
import Symcrust.Properties.MLKEM.Ntt.MulAccumWrapper
import Symcrust.Properties.MLKEM.Encoding.Compress
import Symcrust.Properties.MLKEM.Encoding.Decompress
import Symcrust.Properties.MLKEM.Encoding.VectorSetZero
import Symcrust.Properties.MLKEM.Axioms.BoxDefault

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

/-! ### `#decompose` cascade for `mlkem.encapsulate_internal`

Three-step gate-peeling cascade that strips off the two length-guard
`if`s (matching the gold-standard pattern in `KeyGen.lean` and
`Decaps.lean`), leaving `encapsInt.body` = the 70-binding straight-line
crypto body. -/

set_option maxHeartbeats 1000000 in
set_option maxRecDepth 1024 in
#decompose mlkem.encapsulate_internal mlkem.encapsulate_internal.fold
  letRange 10 1 => encapsInt.dispatchAgreedLen

set_option maxHeartbeats 1000000 in
set_option maxRecDepth 1024 in
#decompose encapsInt.dispatchAgreedLen encapsInt.dispatchAgreedLen.fold
  branch 1 (letRange 1 1) => encapsInt.dispatchCtLen

set_option maxHeartbeats 1000000 in
set_option maxRecDepth 1024 in
#decompose encapsInt.dispatchCtLen encapsInt.dispatchCtLen.fold
  branch 1 full => encapsInt.body

/-! ### 8-phase decomposition of `encapsInt.body`

70-binding crypto body split into 8 phases per Algorithm 17. Three of
them (`mulMatR`, `buildU_dotE2`, `buildV`) group the adjacent bindings
that drive the NTT / Encode / Decode primitives; the other five
(`prelude`, `sampleR`, `sampleE1Add`, `shakeE2`, `wipeRepack`) carry the
hashing, CBD-sampling and wipe steps. All eight phases are proved
against full-FC postconditions.

The grouping consolidates three adjacent ranges of the natural
Funs.lean binding boundaries:
* `prelude` = K-derivation (Sha3_512(m‖H(ek))) + K copy + Shake init
  with σ.
* `buildU_dotE2` = encode u + dot e2.
* `buildV` = decode m + add + encode v.

Loops `_loop0` (CBD η₁) and `_loop1` (CBD η₂) stay as their own
phases (`sampleR`, `sampleE1Add`) so the proof can step through their
existing `_loop0.spec` / `_loop1.spec` directly.  `shakeE2` is kept
distinct because it owns the second Bridge-5 invocation.
`wipeRepack` is the terminal `ok` arm.

Relative indices: each clause N+1's `letRange` start is `N`, because
the prior clause replaced its phase with a single helper call. -/

set_option maxHeartbeats 1000000 in
set_option maxRecDepth 1024 in
#decompose encapsInt.body encapsInt.body.fold
  letRange 0 26 => encapsInt.prelude        -- p1+p2+p3: hash seed, K copy, shake init
  letRange 1 1  => encapsInt.sampleR        -- loop0 wrapper
  letRange 2 5  => encapsInt.mulMatR        -- NTT (a_transpose · r̂, INTT)
  letRange 3 1  => encapsInt.sampleE1Add    -- loop1 wrapper
  letRange 4 6  => encapsInt.buildU_dotE2   -- Encode+NTT (encode u, dot e2)
  letRange 5 17 => encapsInt.shakeE2        -- Shake counter, sample e2, add
  letRange 6 7  => encapsInt.buildV         -- Decode+Encode (decode m+add, encode v)
  letRange 7 6  => encapsInt.wipeRepack     -- terminal: wipe + repack + ok

/-! ### Phase specs for `encapsInt.body` (8 phases)

Each phase carries a full-FC postcondition expressing what that phase
computes in spec-level terms (per Scaffold-3 S16 and `aeneas-postconditions`
"no True-post stubs").  Three phases (`mulMatR`, `buildU_dotE2`, `buildV`)
have FC equations that rest on the NTT / Encode / Decode bridge lemmas;
their proofs and statements compose, via the parent's `step*`, into the
top-level FIPS 203 Algorithm 17 equality. -/

/-! ### Phase 1: `encapsInt.prelude` — derive `(K, σ) ← G(m ‖ H(ek))`

Computes `G(m ‖ H(ek)) = sha3_512(m ‖ H(ek))`, splits it into the
shared-secret half `K` (copied into `pb_agreed_secret[0..32]`) and the
PRF seed half `σ` (absorbed into a fresh Shake256 state `mkhs7`).  Also
opens slice views `pvr_inner`, `pv_tmp` (of length `k params`) into the
two scratch vectors carried by `p_comp_temps.max_size_vector{0,1}`.

Informal proof.  Unfold `encapsInt.prelude`; the body is 27 straight-line
monadic bindings:

1. **Open slices** (positions 1-4): `step Array.index_mut_SliceIndexRangeUsizeSlice`
   twice on `p_comp_temps.max_size_vector{0,1}` at range `[0, n_rows)`,
   producing `pvr_inner`, `pv_tmp` of length `n_rows.val = k params`
   (via `h_wf.params_ok.n_rows = k params`) plus the two back-closures
   `ibm_pvr`, `ibm_pvtmp` whose framings `(ibm s').val =
   max_size_vector_i.val.setSlice! 0 s'.val` come from the stdlib
   `index_mut` spec.

2. **G-hash** (positions 5-13): `step MlKemHashState.set_alg.spec` to
   `Sha3_512`; `step .init.spec` (ghost `g0 = init 72 6#u8 _`);
   `step Array.to_slice.spec` + `step .append.spec` absorbs `pb_random`
   (ghost grows to `g0.append m.toList false`); a second `to_slice` +
   `append` absorbs `H(ek)` (ghost becomes `g1 := (g0.append m.toList
   false).append (H(ek)).toList false`); `step Array.index_mut.spec`
   opens `cbd_sample_buffer[0..64]`; `step .result.spec` writes
   `sha3_512(m ‖ H(ek))` into that slice.  Combined with the standing
   `h_hash` precondition (`encaps_key_hash.toSpec = sha3_256
   (encapsulationKey ...)` = `H(ek)`), the 64-byte result equals
   `MLKEM.G(m ‖ H(ek)).fst ‖ MLKEM.G(m ‖ H(ek)).snd` as a `𝔹 64`.

3. **K-copy** (positions 14-17): `step Slice.index_mut.spec` opens
   `pb_agreed_secret[0..32]`; the pure let `cbd_sample_buffer1 :=
   index_mut_back2 s3` writes the G-result back into `cbd_sample_buffer`;
   `step Array.index.spec` re-slices `[0..32]` (= `K`); `step
   Slice.copy_from_slice.spec` copies `K` into `pb_agreed_secret[0..32]`,
   producing `s6`.

4. **Shake256 init absorbing σ** (positions 18-22): `step
   MlKemHashState.set_alg.spec` to `Shake256`; `step .init.spec` (ghost
   `g2 = init 136 31#u8 _`); `step UScalar.add.spec` computes
   `cb_agreed_secret + 32 = 64`; `step Array.index.spec` slices
   `cbd_sample_buffer1[32..64]` (= `σ`); `step .append.spec` absorbs
   `σ` (ghost becomes `g_σ := g2.append σ.toList false`).  The post's
   `absorbing mkhs7 g_σ` clause holds by `append.spec`.

5. **`n_rows ∈ [2, 4]` asserts** (positions 23-26): `step UScalar.cast.spec`
   for `MATRIX_MIN_NROWS` and `MATRIX_MAX_NROWS`; both `massert`s
   discharge from `h_wf.params_ok.n_rows_in_range`.

6. **Pb_agreed_secret writeback** (position 27): the pure let
   `pb_agreed_secret1 := index_mut_back3 s6` re-injects the K-prefixed
   slice into `pb_agreed_secret`.  Since `pb_agreed_secret.length = 32`
   (precondition `h_pas_len`), the entire slice IS `K`, so
   `pb_as1.toSpec 32 _ = K` discharges from the `copy_from_slice` post.

**Discharge** the 7-conjunction post with `split_conjs` + `agrind` /
`grind` per clause.  The ghost equality
`(g2.append σ.toList false) = (init 136 31#u8 _).append σ.toList false`
is `rfl` by `GhostState.init` body; `setSlice!` framing for ibm closures
is direct from `Array.index_mut_SliceIndexRangeUsizeSlice.spec`.

The output `_cbd1` (final cbd_sample_buffer state) is **deliberately
unconstrained** in the post: it is fully overwritten by `shakeE2` later
in the chain (counter byte + PRF squeeze), so its prelude-exit content
is dead data.  Quantifying it would only inflate the post without
contributing to the parent's FC. -/

/-! The G-decomposition bridges `MLKEM_G_snd_toList`,
`MLKEM_G_fst_toList`, `MLKEM_G_fst_eq_slice` (used twice in
`encapsInt.prelude.spec` below to discharge the runtime ↔ spec halves
of `MLKEM.G(m ‖ H(ek))`) live in `HashCalls.lean` alongside the
matching SHA3-256/512 array bridges; same statements, dropped
`private` qualifier, generic in the input bit-vector width. -/

@[step]
theorem encapsInt.prelude.spec
    (params : ParameterSet)
    (pk_mlkem_key : mlkem.key.Key)
    (pb_agreed_secret : Slice U8)
    (pb_random : Array U8 32#usize)
    (p_comp_temps : mlkem.ntt.InternalComputationTemporaries)
    (cb_agreed_secret : Usize)
    (cbd_sample_buffer : Array U8 193#usize)
    (h_wf : wfKey pk_mlkem_key params)
    (_h_hash : pk_mlkem_key.encaps_key_hash.toSpec =
              Spec.SHA3.sha3_256 (encapsulationKey pk_mlkem_key params))
    (h_pas_len : pb_agreed_secret.length = 32)
    (h_cb_as : cb_agreed_secret.val = 32) :
    encapsInt.prelude pk_mlkem_key pb_agreed_secret pb_random
        p_comp_temps cb_agreed_secret cbd_sample_buffer
    ⦃ pvr_inner ibm_pvr pv_tmp ibm_pvtmp cbd1 mkhs7 pb_as1 =>
        let m := pb_random.toSpec
        let h_ek := pk_mlkem_key.encaps_key_hash.toSpec
        let G_out := MLKEM.G (m ‖ h_ek)
        let K := G_out.1
        let σ := G_out.2
        pvr_inner.length = (k params : ℕ) ∧
        pv_tmp.length = (k params : ℕ) ∧
        mlkem.hash.MlKemHashState.absorbing mkhs7
          ((GhostState.init 136 31#u8 (by decide)).append
             (cbd1.val.slice 32 64) false) ∧
        mkhs7.alg = mlkem.hash.MlKemHashAlg.Shake256 ∧
        (cbd1.val.slice 32 64).map (·.bv) = σ.toList ∧
        (∃ (h : pb_as1.length = 32), pb_as1.toSpec 32 h = K) ∧
        (∀ s', (ibm_pvr s').val =
            p_comp_temps.max_size_vector0.val.setSlice! 0 s'.val) ∧
        (∀ s', (ibm_pvtmp s').val =
            p_comp_temps.max_size_vector1.val.setSlice! 0 s'.val) ⦄ := by
  unfold encapsInt.prelude
  have h_params_ok := wfKey.params_ok h_wf
  have h_nrows : pk_mlkem_key.params.n_rows.val = (k params : ℕ) :=
    wfInternalParams.n_rows_val h_params_ok
  have h_k_le_4 : (k params : ℕ) ≤ 4 := k_le_4 params
  have h_nrows_le_4 : pk_mlkem_key.params.n_rows.val ≤ 4 := by omega
  -- Phase 1 setup: open the two scratch slice views.
  step  -- i6 = cast n_rows
  have h_i6_le4 : i6.val ≤ 4 := by rw [i6_post]; scalar_tac
  step  -- pvr_inner index_mut p_comp_temps.max_size_vector0 [0..i6]
  step  -- i7 = cast n_rows
  have h_i7_le4 : i7.val ≤ 4 := by rw [i7_post]; scalar_tac
  step  -- pv_tmp index_mut p_comp_temps.max_size_vector1 [0..i7]
  -- Phase 2 setup: Sha3_512 hash session.
  step  -- mkhs = hash_state0.set_alg Sha3_512
  step with mlkem.hash.MlKemHashState.init.spec _ 72 6#u8
    (by rw [mkhs_post2]; rfl)
    (by refine ⟨by decide, ?_, by decide⟩; show 8 * 72 < Spec.SHA3.b; decide)
  step  -- s = pb_random.to_slice
  step with mlkem.hash.MlKemHashState.append.spec _ _ _ (Or.inl mkhs1_post2)
  step  -- s1 = pk_mlkem_key.encaps_key_hash.to_slice
  step with mlkem.hash.MlKemHashState.append.spec _ _ _ (Or.inl mkhs2_post2)
  step  -- s2, index_mut_back2 = cbd_sample_buffer index_mut [0..64]
  case h1 => native_decide
  -- result needs h_len : s2.length = 64 (resultSize Sha3_512)
  step with mlkem.hash.MlKemHashState.result.spec _ s2 _ (Or.inl mkhs3_post2)
    (by
      have halg : mkhs3.alg = mlkem.hash.MlKemHashAlg.Sha3_512 := by
        rw [mkhs3_post1, mkhs2_post1, mkhs1_post1, mkhs_post2]
      simp [Slice.length, s2_post2, halg, mlkem.hash.MlKemHashState.resultSize]
      native_decide)
  step  -- s4 = index_mut pb_agreed_secret [0..SIZEOF_AGREED_SECRET]
  case h1 => simp [mlkem.SIZEOF_AGREED_SECRET, h_pas_len]
  step  -- s5 = index (index_mut_back2 s3).to_slice [0..SIZEOF_AGREED_SECRET]
  case h1 => simp [mlkem.SIZEOF_AGREED_SECRET, Std.Array.to_slice]
  step  -- s6 = copy_from_slice s4 s5
  step  -- mkhs5 = mkhs4.set_alg Shake256
  step with mlkem.hash.MlKemHashState.init.spec _ 136 31#u8
    (by rw [mkhs5_post2]; rfl)
    (by refine ⟨by decide, ?_, by decide⟩; show 8 * 136 < Spec.SHA3.b; decide)
  step  -- i8 = cb_agreed_secret + 32 = 64
  step  -- s7 = index (index_mut_back2 s3).to_slice [cb_agreed_secret..i8]
  case h1 => simp [Std.Array.to_slice, h_cb_as, i8_post]
  step with mlkem.hash.MlKemHashState.append.spec _ _ _ (Or.inl mkhs6_post2)
  step  -- i9 = cast MATRIX_MIN_NROWS
  step  -- massert n_rows ≥ i9
  case h =>
    have hi9 : i9.val = 2 := by simp [i9_post, mlkem.ntt.MATRIX_MIN_NROWS]
    have := k_ge_2 params
    scalar_tac
  step  -- i10 = cast MATRIX_MAX_NROWS
  step  -- massert n_rows ≤ i10
  case h =>
    have hi10 : i10.val = 4 := by simp [i10_post, mlkem.ntt.MATRIX_MAX_NROWS]
    scalar_tac
  -- Discharge 8-conjunct postcondition.
  -- First derive the helpers we need for conjuncts (3), (5), (6).
  have h_mkhs1_no_sq : mkhs1.state.squeeze_mode = false := by
    have hab := mkhs1_post2
    simp only [mlkem.hash.MlKemHashState.absorbing] at hab
    have h := hab.1.1.2.1
    cases hsq : mkhs1.state.squeeze_mode
    · rfl
    · rw [hsq] at h; exact absurd rfl h
  have h_mkhs2_no_sq : mkhs2.state.squeeze_mode = false := by
    have hab := mkhs2_post2
    simp only [mlkem.hash.MlKemHashState.absorbing] at hab
    have h := hab.1.1.2.1
    cases hsq : mkhs2.state.squeeze_mode
    · rfl
    · rw [hsq] at h; exact absurd rfl h
  have h_mkhs6_no_sq : mkhs6.state.squeeze_mode = false := by
    have hab := mkhs6_post2
    simp only [mlkem.hash.MlKemHashState.absorbing] at hab
    have h := hab.1.1.2.1
    cases hsq : mkhs6.state.squeeze_mode
    · rfl
    · rw [hsq] at h; exact absurd rfl h
  -- s and s1 byte lengths
  have h_s_len : s.length = 32 := by
    rw [s_post]; simp [Aeneas.Std.Array.to_slice]
  have h_s1_len : s1.length = 32 := by
    rw [s1_post]; simp [Aeneas.Std.Array.to_slice]
  have h_s_val_len : (↑s : List U8).length = 32 := h_s_len
  have h_s1_val_len : (↑s1 : List U8).length = 32 := h_s1_len
  -- Build the ghost SHA3-512 state G with squeeze_mode pinned to false.
  set G_init : sha3.sha3_impl.GhostState :=
    sha3.sha3_impl.GhostState.init 72 6#u8
      (by refine ⟨by decide, ?_, by decide⟩; show 8 * 72 < Spec.SHA3.b; decide)
    with hG_init_def
  set G : sha3.sha3_impl.GhostState :=
    (G_init.append (↑s) mkhs1.state.squeeze_mode).append (↑s1)
        mkhs2.state.squeeze_mode with hG_def
  -- s3.val = (extractOutput G s2.length).toList   (from mkhs4_post3)
  have h_s3_val : (↑s3 : List U8) =
      (sha3.sha3_impl.extractOutput G s2.length).toList := mkhs4_post3
  have h_s2_len_64 : s2.length = 64 := by
    simp [Slice.length, s2_post2]
    native_decide
  have h_s3_len : s3.length = 64 := mkhs4_post2.trans h_s2_len_64
  have h_s3_val64 : (↑s3 : List U8) =
      (sha3.sha3_impl.extractOutput G 64).toList := by
    have := h_s3_val
    rw [h_s2_len_64] at this
    exact this
  -- Properties of G under squeeze_mode pinning.
  have h_G_absorbed : G.absorbed = (↑s : List U8) ++ (↑s1 : List U8) := by
    simp [hG_def, hG_init_def, sha3.sha3_impl.GhostState.append,
          sha3.sha3_impl.GhostState.init, h_mkhs1_no_sq, h_mkhs2_no_sq]
  have h_G_abs_len : G.absorbed.length = 64 := by
    rw [h_G_absorbed, List.length_append, h_s_val_len, h_s1_val_len]
  have h_G_rate : G.rate = 72 := by
    simp only [hG_def, hG_init_def, h_mkhs1_no_sq, h_mkhs2_no_sq,
               sha3.sha3_impl.GhostState.append, sha3.sha3_impl.GhostState.init,
               Bool.false_eq_true, ite_false]
  have h_G_padVal : G.padVal = 6#u8 := by
    simp only [hG_def, hG_init_def, h_mkhs1_no_sq, h_mkhs2_no_sq,
               sha3.sha3_impl.GhostState.append, sha3.sha3_impl.GhostState.init,
               Bool.false_eq_true, ite_false]
  have h_G_squeezed : G.squeezed = [] := by
    simp [hG_def, hG_init_def, sha3.sha3_impl.GhostState.append,
          sha3.sha3_impl.GhostState.init, h_mkhs1_no_sq, h_mkhs2_no_sq]
  -- B = m ‖ H(ek) = pb_random.toSpec ‖ pk_mlkem_key.encaps_key_hash.toSpec
  set B : 𝔹 64 :=
    pb_random.toSpec ++ pk_mlkem_key.encaps_key_hash.toSpec with hB_def
  -- Per-byte equality: B[i] = G.absorbed[i].bv
  have h_per_byte : ∀ (i : Fin 64),
      B.get i = (G.absorbed[i.val]'(by rw [h_G_abs_len]; exact i.isLt)).bv := by
    intro i
    have hi_G : i.val < G.absorbed.length := by rw [h_G_abs_len]; exact i.isLt
    have hi_abs : i.val < ((↑s : List U8) ++ (↑s1 : List U8)).length := by
      rw [List.length_append, h_s_val_len, h_s1_val_len]; exact i.isLt
    have h_abs_idx :
        ((↑s : List U8) ++ (↑s1 : List U8))[i.val]'hi_abs =
          G.absorbed[i.val]'hi_G := List.getElem_of_eq h_G_absorbed.symm hi_abs
    have h_s_val_pb : (↑s : List U8) = pb_random.val := by
      rw [s_post]; rfl
    have h_s1_val_ek : (↑s1 : List U8) = pk_mlkem_key.encaps_key_hash.val := by
      rw [s1_post]; rfl
    -- Unfold B = pb_random.toSpec ++ encaps_key_hash.toSpec.
    show (pb_random.toSpec ++ pk_mlkem_key.encaps_key_hash.toSpec)[i.val]'i.isLt = _
    rw [Vector.getElem_append]
    have hi32 : ((32#usize : Usize).val : ℕ) = 32 := by decide
    by_cases hii : i.val < 32
    · simp only [hi32, hii, ↓reduceDIte]
      have hi_s : i.val < (↑s : List U8).length := by rw [h_s_val_len]; exact hii
      have h_left : (((↑s : List U8) ++ (↑s1 : List U8))[i.val]'hi_abs) =
          (↑s : List U8)[i.val]'hi_s := List.getElem_append_left hi_s
      have hi_pb : i.val < pb_random.val.length := by
        rw [← h_s_val_pb]; exact hi_s
      have h_s_pb_idx : (↑s : List U8)[i.val]'hi_s =
          pb_random.val[i.val]'hi_pb :=
        List.getElem_of_eq h_s_val_pb hi_s
      show (pb_random.toSpec : 𝔹 32)[i.val]'hii = _
      simp only [Aeneas.Std.Array.toSpec, arrayToSpecBytes, Vector.getElem_ofFn]
      rw [← h_abs_idx, h_left, h_s_pb_idx]
    · push Not at hii
      simp only [hi32, show ¬ (i.val < 32) from Nat.not_lt.mpr hii, ↓reduceDIte]
      have h_ge : (↑s : List U8).length ≤ i.val := by rw [h_s_val_len]; exact hii
      have hi_s1 : i.val - (↑s : List U8).length < (↑s1 : List U8).length := by
        rw [h_s_val_len, h_s1_val_len]
        have := i.isLt; omega
      have h_right : (((↑s : List U8) ++ (↑s1 : List U8))[i.val]'hi_abs) =
          (↑s1 : List U8)[i.val - (↑s : List U8).length]'hi_s1 :=
        List.getElem_append_right h_ge
      have hi_ek_via_s1 : i.val - (↑s : List U8).length <
          pk_mlkem_key.encaps_key_hash.val.length := by
        rw [← h_s1_val_ek]; exact hi_s1
      have h_s1_ek_idx_pre : (↑s1 : List U8)[i.val - (↑s : List U8).length]'hi_s1 =
          pk_mlkem_key.encaps_key_hash.val[i.val - (↑s : List U8).length]'hi_ek_via_s1 :=
        List.getElem_of_eq h_s1_val_ek hi_s1
      have hi_ek : i.val - 32 < pk_mlkem_key.encaps_key_hash.val.length := by
        rw [h_s_val_len] at hi_ek_via_s1; exact hi_ek_via_s1
      have h_idx_swap : pk_mlkem_key.encaps_key_hash.val[i.val -
          (↑s : List U8).length]'hi_ek_via_s1 =
          pk_mlkem_key.encaps_key_hash.val[i.val - 32]'hi_ek := by
        fcongr 1; rw [h_s_val_len]
      show (pk_mlkem_key.encaps_key_hash.toSpec : 𝔹 32)[i.val - 32]'(by
            have := i.isLt; omega) = _
      simp only [Aeneas.Std.Array.toSpec, arrayToSpecBytes, Vector.getElem_ofFn]
      rw [← h_abs_idx, h_right, h_s1_ek_idx_pre, h_idx_swap]
  -- Apply the SHA3-512 bridge.
  have h_sha3 : (sha3.sha3_impl.extractOutput G 64).map (·.bv) =
      Spec.SHA3.sha3_512 B :=
    symcrust.mlkem.hash.sha3_512_extractOutput G B h_G_abs_len h_per_byte
      h_G_rate h_G_padVal h_G_squeezed
  -- Discharge the 8-conjunct postcondition.
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · -- pvr_inner.length = ↑(k params)
    rw [pvr_inner_post2, i6_post]; simp; omega
  · -- pv_tmp.length = ↑(k params)
    rw [pv_tmp_post2, i7_post]; simp; omega
  · -- mkhs7.absorbing ((init 136 31 _).append (slice 32 64 (index_mut_back2 s3)) false)
    have h_s7_eq : (↑s7 : List U8) = List.slice 32 64 ↑(index_mut_back2 s3) := by
      rw [s7_post1, h_cb_as]
      have hi8 : i8.val = 64 := by rw [i8_post, h_cb_as]
      rw [hi8]
      rfl
    have := mkhs7_post2
    rw [h_s7_eq, h_mkhs6_no_sq] at this
    exact this
  · -- mkhs7.alg = Shake256
    rw [mkhs7_post1, mkhs6_post1, mkhs5_post2]
  · -- (slice 32 64 (index_mut_back2 s3)).map (·.bv) = G(B).2.toList
    have h_imb2_eq : (↑(index_mut_back2 s3) : List U8) =
        (↑cbd_sample_buffer : List U8).setSlice! 0 ↑s3 := s2_post3 s3
    have h_slice_eq : List.slice 32 64 ↑(index_mut_back2 s3) =
        (↑s3 : List U8).drop 32 := by
      rw [h_imb2_eq]
      have h_cb_len : (↑cbd_sample_buffer : List U8).length = 193 := by simp
      -- inline List.take_setSlice!_zero: take 64 of (cbd.setSlice! 0 s3) = s3
      have h_take64 : ((↑cbd_sample_buffer : List U8).setSlice! 0 ↑s3).take 64 = ↑s3 := by
        unfold _root_.List.setSlice!
        simp [_root_.List.take_zero, h_s3_len, h_cb_len]
      unfold _root_.List.slice
      rw [show (64 - 32 : ℕ) = 32 from rfl]
      have : (((↑cbd_sample_buffer : List U8).setSlice! 0 ↑s3).drop 32).take 32 =
          (((↑cbd_sample_buffer : List U8).setSlice! 0 ↑s3).take 64).drop 32 := by
        rw [List.take_drop]
      rw [this, h_take64]
    -- Substitute slice-eq, then use h_sha3 to swap to sha3_512 B.
    rw [h_slice_eq, h_s3_val64]
    -- Goal: ((extractOutput G 64).toList.drop 32).map (·.bv) = (MLKEM.G B).2.toList
    rw [List.map_drop]
    rw [show (extractOutput G 64).toList.map (·.bv) = (Vector.map (·.bv) (extractOutput G 64)).toList from
      by rw [Vector.toList_map]]
    rw [h_sha3]
    -- Goal: (sha3_512 B).toList.drop 32 = (MLKEM.G (m ‖ ek)).2.toList
    rw [MLKEM_G_snd_toList, hB_def]
    rfl
  · -- ∃ h : (index_mut_back3 s6).length = 32, (index_mut_back3 s6).toSpec 32 h = (MLKEM.G B).1
    -- Step 1: derive (index_mut_back3 s6).val = pb_agreed_secret.val.setSlice! 0 s6.val.
    have h_imb3_eq : index_mut_back3 s6 = pb_agreed_secret.setSlice! 0 ↑s6 := s4_post3 s6
    have h_imb3_val : (index_mut_back3 s6).val =
        pb_agreed_secret.val.setSlice! 0 (↑s6 : List U8) := by
      rw [h_imb3_eq]; rfl
    -- Step 2: length facts on s4, s6, s5 (all equal to SIZEOF_AGREED_SECRET = 32).
    have h_s4_len : s4.length = 32 := by
      simp [s4_post2, mlkem.SIZEOF_AGREED_SECRET]
    have h_s6_len : s6.length = 32 := by rw [s6_post1, h_s4_len]
    have h_s6_val_len : (↑s6 : List U8).length = 32 := h_s6_len
    have h_pas_val_len : pb_agreed_secret.val.length = 32 := h_pas_len
    -- Step 3: setSlice! at offset 0 over a length-32 target with a length-32 source
    -- returns the source verbatim.
    have h_setSlice_eq :
        pb_agreed_secret.val.setSlice! 0 (↑s6 : List U8) = (↑s6 : List U8) := by
      unfold _root_.List.setSlice!
      simp [h_s6_val_len, h_pas_val_len]
    have h_imb3_val_eq_s6 : (index_mut_back3 s6).val = (↑s6 : List U8) := by
      rw [h_imb3_val, h_setSlice_eq]
    have h_imb3_len : (index_mut_back3 s6).length = 32 := by
      show (index_mut_back3 s6).val.length = 32
      rw [h_imb3_val_eq_s6, h_s6_val_len]
    refine ⟨h_imb3_len, ?_⟩
    -- Step 4: derive s6.val = s3.val.take 32 via setSlice!_0 + slice 0 32 reasoning.
    have h_imb2_eq : (↑(index_mut_back2 s3) : List U8) =
        (↑cbd_sample_buffer : List U8).setSlice! 0 ↑s3 := s2_post3 s3
    have h_cb_len : (↑cbd_sample_buffer : List U8).length = 193 := by simp
    have h_slice_take : List.slice 0 32 (↑(index_mut_back2 s3) : List U8) =
        (↑s3 : List U8).take 32 := by
      rw [h_imb2_eq]
      unfold _root_.List.slice
      simp only [Nat.sub_zero, _root_.List.drop_zero]
      unfold _root_.List.setSlice!
      simp only
      rw [show min (↑s3 : List U8).length ((↑cbd_sample_buffer : List U8).length - 0) =
            (↑s3 : List U8).length from by simp [h_s3_len, h_cb_len]]
      rw [_root_.List.take_zero]
      simp only [_root_.List.nil_append]
      rw [_root_.List.take_of_length_le (le_refl _)]
      rw [_root_.List.take_append_of_le_length (by simp [h_s3_len])]
    have h_s5_eq : (↑s5 : List U8) = (↑s3 : List U8).take 32 := by
      have := s5_post1
      rw [this, show ((↑mlkem.SIZEOF_AGREED_SECRET : Nat)) = 32 from by
        simp [mlkem.SIZEOF_AGREED_SECRET]]
      show List.slice 0 32 (↑(index_mut_back2 s3) : List U8) = _
      exact h_slice_take
    have h_s6_eq_take : (↑s6 : List U8) = (↑s3 : List U8).take 32 := by
      rw [s6_post2]; exact h_s5_eq
    -- Step 5: chain (index_mut_back3 s6).val to (extractOutput G 64).toList.take 32.
    have h_imb3_val_eq_take : (index_mut_back3 s6).val =
        ((sha3.sha3_impl.extractOutput G 64).toList).take 32 := by
      rw [h_imb3_val_eq_s6, h_s6_eq_take, h_s3_val64]
    -- Step 6: reduce Vector equality to .toList equality (escapes per-element `(MLKEM.G B).1[i]`
    -- exposure that caused the kernel whnf timeout in the previous attempt).
    apply Vector.toList_inj.mp
    -- Goal: ((imb3).toSpec 32 h_imb3_len).toList = (MLKEM.G (m ‖ h_ek)).1.toList
    -- LHS: simplify (sliceToSpecBytes ..).toList to imb3.val.map (·.bv).
    have h_lhs : ((index_mut_back3 s6).toSpec 32 h_imb3_len).toList =
        (index_mut_back3 s6).val.map (·.bv) := by
      apply List.ext_getElem
      · simp [Vector.length_toList, List.length_map, h_imb3_len]
      · intro i h1 h2
        rw [Vector.getElem_toList]
        unfold Aeneas.Std.Slice.toSpec sliceToSpecBytes
        rw [Vector.getElem_ofFn, List.getElem_map]
    rw [h_lhs, MLKEM_G_fst_toList]
    -- Goal: imb3.val.map (·.bv) = (sha3_512 (m ‖ h_ek)).toList.take 32
    rw [h_imb3_val_eq_take, List.map_take, ← Vector.toList_map, h_sha3]
    -- Goal: (sha3_512 B).toList.take 32 = (sha3_512 (m ‖ h_ek)).toList.take 32
    -- B = pb_random.toSpec ++ ek.toSpec, m ‖ h_ek = pb_random.toSpec ‖ ek.toSpec; ++ ≡ ‖.
    rfl
  · -- ibm_pvr frame
    exact pvr_inner_post3
  · -- ibm_pvtmp frame
    exact pv_tmp_post3

/-! ### Phase 2: `encapsInt.sampleR` — invoke `_loop0` to sample r̂

Thin wrapper: `sampleR` is exactly one monadic call to
`mlkem.encapsulate_internal_loop0` with `iter.start = 0`, `iter.end =
n_rows`.  The body delivers the full streaming invariant
`encInvSampleR ... (k params)` at exit — i.e., `pvr_inner` holds the
sampled CBD-η₁ polys for every row `j ∈ [0, k)`.

Informal proof.  Unfold `encapsInt.sampleR`; the body is the single
`step mlkem.encapsulate_internal_loop0.spec` with `rOuter := σ`,
`pk_mlkem_key`, the iterator `{ start := 0#u8, end := n_rows }`, the
input `mkhs7`, `p_comp_temps.hash_state1` (used internally), the
incoming `cbd_sample_buffer1`, the input `pvr_inner` (used as both
`orig_pvr` and `pvr_inner` at i=0), `g_base`, and the chain of side
conditions:

- `h_wf` from the precondition.
- `h_inv` (entry at i=0): comes verbatim from the caller.
- `h_iter_end : iter.end.val = k params` — `pk_mlkem_key.params.n_rows`
  case-converted via `h_wf.params_ok.n_rows = k params`.
- `h_iter_start : 0 ≤ k params` — `Nat.zero_le _`.
- `h_eta1` from the precondition.

`loop0.spec`'s post is `encInvSampleR ... (k params) mkhs g_base`,
from which `wfPolyVec pvr_inner1` follows by
`wfPolyVec_of_encInvSampleR_full` (per-slot `wfPoly` clause at
`i = k params` covers every position). -/
@[step]
theorem encapsInt.sampleR.spec
    (params : ParameterSet)
    (rOuter : 𝔹 32)
    (pk_mlkem_key : mlkem.key.Key)
    (p_comp_temps : mlkem.ntt.InternalComputationTemporaries)
    (pvr_inner : Slice (PolyElement))
    (cbd_sample_buffer1 : Array U8 193#usize)
    (mkhs7 : mlkem.hash.MlKemHashState)
    (g_base : GhostState)
    (h_wf : wfKey pk_mlkem_key params)
    (h_inv : encInvSampleR params rOuter pvr_inner pvr_inner 0 mkhs7 g_base)
    (h_eta1 : pk_mlkem_key.params.n_eta1.val = (η₁ params : ℕ)) :
    encapsInt.sampleR pk_mlkem_key p_comp_temps pvr_inner
        cbd_sample_buffer1 mkhs7
    ⦃ _mkhs8 _cbd2 pvr_inner1 =>
        encInvSampleR params rOuter pvr_inner pvr_inner1
          (k params : ℕ) mkhs7 g_base ∧
        wfPolyVec pvr_inner1 ⦄ := by
  unfold encapsInt.sampleR
  step
  case h_inv => simpa using h_inv
  case h_iter_end =>
    exact wfInternalParams.n_rows_val (wfKey.params_ok (self := pk_mlkem_key) h_wf)
  case a =>
    exact And.intro mkhs8_post (wfPolyVec_of_encInvSampleR_full mkhs8_post)

/-! ### Phase 3: `encapsInt.mulMatR` — compute `INTT(Â^T · r̂)` with Mont. mul

This phase performs the matrix-vector product portion of the K-PKE
encrypt's step 2g (`u = INTT(Â^T · r̂) + e₁`).  After phases 1–2 we
have `pvr_inner1` holding the CBD-η₁ samples `r` (in standard form).
`mulMatR` produces:

* `pvr_inner2 = NTT_Vec(pvr_inner1) = r̂` — kept around because it is
  reused in phase 5 (`buildU_dotE2`) to compute `t̂·r̂`.
* `pv_tmp3 = INTT(Â^T · r̂)` — fed to phase 4 (`sampleE1Add`) which
  adds `e₁` in standard form.
* `pa_tmp` — leftover scratch (cleared by MMM, dead afterwards).

Internally: `vector_ntt(pvr_inner1) ; vector_set_zero(pv_tmp) ;
a_transpose self → s8 ; MMM(s8, pvr_inner2, 0-vector, …) → (pv_tmp2,
pa_tmp) ; vector_intt_and_mul_r(pv_tmp2) → pv_tmp3`.

Note on Montgomery factors.  `matrix_vector_mont_mul_and_add`'s post
applies a `(Rinv * ·)` factor to the result; `vector_intt_and_mul_r`'s
post applies a `(R * ·)` factor.  Composition collapses to identity
mod q, so the slot-level equality below is `toPoly pv_tmp3[i] =
NTTInv(MulVectorNTT(Â^T, NTT_Vec r)).map (R * ·)` with the inner
`(Rinv * ·)` map already absorbed in `MulVectorNTT` — leaving a
single residual `(R * ·)` factor on the outside that is the standard
NTT-domain convention used throughout the codebase.

The full FC postcondition is stated and proved; downstream consumers
(`sampleE1Add`, `buildU_dotE2`) use it via `step`.

Informal proof.  Unfold `encapsInt.mulMatR`; sequence:
1. `step vector_ntt.spec` consumes `pvr_inner1` (needs `wfPolyVec`
   from `h_wf_pvr_inner`).
2. `step vector_set_zero.spec` zeros `pv_tmp` (length precondition
   `1 ≤ pv_tmp.length ≤ 4` from `h_pv_tmp_len + k_le_4`).  The output
   has all-zero coefficients, hence `wfPolyVec` follows trivially
   (`0 < q`); used as `h_wf_dst` precondition of MMM below.
3. `step a_transpose.spec` exposes `Â^T` view of length `(k p)²`.
4. `step matrix_vector_mont_mul_and_add.spec` produces `pv_tmp2`
   accumulating `Â^T · r̂` (with `Rinv` factor) into the zero
   destination.
5. `step vector_intt_and_mul_r.spec` produces `pv_tmp3 = INTT(...) ·
   R`.
Compose the per-slot equalities. -/
@[step]
theorem encapsInt.mulMatR.spec
    (params : ParameterSet)
    (pk_mlkem_key : mlkem.key.Key)
    (p_comp_temps : mlkem.ntt.InternalComputationTemporaries)
    (pv_tmp : Slice (PolyElement))
    (pvr_inner1 : Slice (PolyElement))
    (h_wf : wfKey pk_mlkem_key params)
    (h_wf_pvr_inner : wfPolyVec pvr_inner1)
    (h_pvr_inner_len : pvr_inner1.length = (k params : ℕ))
    (h_pv_tmp_len : pv_tmp.length = (k params : ℕ)) :
    encapsInt.mulMatR pk_mlkem_key p_comp_temps pv_tmp pvr_inner1
    ⦃ pvr_inner2 _pa_tmp pv_tmp3 =>
        ∃ (h_pvr_len : pvr_inner2.length = (k params : ℕ))
          (h_pv3_len : pv_tmp3.length = (k params : ℕ)),
        wfPolyVec pvr_inner2 ∧
        wfPolyVec pv_tmp3 ∧
        (∀ (i : ℕ) (h_i : i < (k params : ℕ)),
          toPoly (pvr_inner2.val[i]'(by simp [Slice.length] at h_pvr_len; omega))
            = MLKEM.NTT (toPoly (pvr_inner1.val[i]'(by
              simp [Slice.length] at h_pvr_inner_len; omega)))) ∧
        (∀ (i : ℕ) (h_i : i < (k params : ℕ)),
          toPoly (pv_tmp3.val[i]'(by simp [Slice.length] at h_pv3_len; omega))
            = (MLKEM.NTTInv
                (((MLKEM.PolyMatrix.MulVectorNTT
                    (Matrix.of (keyAHat pk_mlkem_key params))
                    (Vector.ofFn fun j =>
                      MLKEM.NTT (toPoly (pvr_inner1.val[(j : ℕ)]'(by
                        simp [Slice.length] at h_pvr_inner_len
                        have := j.isLt; omega))))).get
                  ⟨i, h_i⟩).map (Rinv * ·))).map (R * ·)) ⦄ := by
  unfold encapsInt.mulMatR
  -- Step 1: vector_ntt on pvr_inner1
  have h_pvr_n : pvr_inner1.length > 0 ∧ pvr_inner1.length ≤ 4 := by
    rw [h_pvr_inner_len]; have := k_le_4 params; have := k_ge_2 params
    constructor <;> scalar_tac
  let* ⟨ pvr_inner2, hwf_pvr2, hlen_pvr2, h_pvr2_eq ⟩ ←
    mlkem.ntt.vector_ntt.spec
  -- Step 2: vector_set_zero on pv_tmp
  have h_pv_tmp_n : 1 ≤ pv_tmp.length ∧ pv_tmp.length ≤ 4 := by
    rw [h_pv_tmp_len]; have := k_le_4 params; have := k_ge_2 params
    constructor <;> scalar_tac
  let* ⟨ pv_tmp1, hlen_pv1, h_pv1_zero ⟩ ←
    mlkem.ntt.vector_set_zero.spec
  -- pv_tmp1 has wfPolyVec since all coefficients are 0 < q.
  have hwf_pv1 : wfPolyVec pv_tmp1 := by
    intro i h_i k h_k
    have h := h_pv1_zero i h_i k h_k
    show (pv_tmp1.val[i].val[k]).val < q
    rw [h]; unfold MLKEM.q; decide
  -- Step 3: a_transpose exposes Â^T view.
  step with mlkem.key.Key.a_transpose.spec as ⟨ s8, h_s8_len, h_s8_wf, h_s8_eq ⟩
  -- Step 4: matrix-vector mont mul-and-add.
  have h_nrows_eq : pk_mlkem_key.params.n_rows.val = (k params : ℕ) := by
    obtain ⟨hp, _, _⟩ := h_wf
    exact wfInternalParams.n_rows_val hp
  have h_s8_pm_len : s8.length = pk_mlkem_key.params.n_rows.val *
                                  pk_mlkem_key.params.n_rows.val := by
    rw [h_s8_len]; show matrixLen params = _; unfold matrixLen; rw [h_nrows_eq]
  have h_pvr2_n_rows : pvr_inner2.length = pk_mlkem_key.params.n_rows.val := by
    rw [hlen_pvr2, h_pvr_inner_len, h_nrows_eq]
  have h_pv1_n_rows : pv_tmp1.length = pk_mlkem_key.params.n_rows.val := by
    rw [hlen_pv1, h_pv_tmp_len, h_nrows_eq]
  have h_n_rows_bounds : 0 < pk_mlkem_key.params.n_rows.val ∧
                          pk_mlkem_key.params.n_rows.val ≤ 4 := by
    rw [h_nrows_eq]; have := k_le_4 params; have := k_ge_2 params
    constructor <;> scalar_tac
  have h_s8_wfvec : wfPolyVec s8 := by
    intro i h_i kk h_k
    have := h_s8_wf i h_i; exact this kk h_k
  step with mlkem.ntt.matrix_vector_mont_mul_and_add.spec s8 pvr_inner2 pv_tmp1
    p_comp_temps.poly_element_accumulator pk_mlkem_key.params.n_rows (k params)
    h_nrows_eq.symm h_s8_wfvec hwf_pvr2 hwf_pv1 h_n_rows_bounds
    h_s8_pm_len h_pvr2_n_rows h_pv1_n_rows
    as ⟨ pv_tmp2, pa_tmp, pv_tmp2_post1, pv_tmp2_post2, h_pv2_len, h_pv2_eq ⟩
  -- Step 5: vector_intt_and_mul_r.
  have h_pv2_n : pv_tmp2.length > 0 ∧ pv_tmp2.length ≤ 4 := by
    rw [h_pv2_len]; have := k_le_4 params; have := k_ge_2 params
    constructor <;> scalar_tac
  let* ⟨ pv_tmp3, hwf_pv3, h_pv3_len, h_pv3_eq ⟩ ←
    mlkem.ntt.vector_intt_and_mul_r.spec
  -- Final composition.
  have h_pvr2_kparams : pvr_inner2.length = (k params : ℕ) := by
    rw [hlen_pvr2, h_pvr_inner_len]
  have h_pv3_kparams : pv_tmp3.length = (k params : ℕ) := by
    rw [h_pv3_len, h_pv2_len]
  refine ⟨h_pvr2_kparams, h_pv3_kparams, hwf_pvr2, hwf_pv3, ?_, ?_⟩
  · -- pvr_inner2 = NTT pvr_inner1 (pointwise)
    intro i h_i
    have h_i_inner : i < pvr_inner1.length := by rw [h_pvr_inner_len]; exact h_i
    exact h_pvr2_eq i h_i_inner
  · -- pv_tmp3[i] = R · NTTInv ( Rinv · ((Â · NTT(pvr_inner1))[i]) )
    --
    -- Proof outline: extract index i from `h_pv2_eq`; the `pv_tmp1` summand
    -- is zero (by `h_pv1_zero`), and the matrix/vector bridges from
    -- `h_s8_eq` and `h_pvr2_eq` collapse `toPolyMatrixOfLen s8 …` to
    -- `Matrix.of (keyAHat …)` and `toPolyVecOfLen pvr_inner2 …` to
    -- `Vector.ofFn (NTT ∘ toPoly ∘ pvr_inner1)`.
    intro i h_i
    have h_i_pv3 : i < pv_tmp3.length := by rw [h_pv3_kparams]; exact h_i
    rw [h_pv3_eq i h_i_pv3]
    -- Peel `Vector.map (R * ·) ∘ NTTInv` on both sides.
    apply congrArg (Vector.map (fun x => R * x))
    apply congrArg MLKEM.NTTInv
    -- Take h_pv2_eq at slot i and rewrite LHS.
    have h_get : (toPolyVecOfLen pv_tmp2 (k params) h_pv2_len).get ⟨i, h_i⟩ =
        (toPolyVecOfLen pv_tmp1 (k params) (by rw [hlen_pv1, h_pv_tmp_len]) +
          Vector.map (fun p => Vector.map (fun x => Rinv * x) p)
            ((toPolyMatrixOfLen s8 (k params)
                (by rw [h_s8_pm_len, h_nrows_eq])).MulVectorNTT
              (toPolyVecOfLen pvr_inner2 (k params) h_pvr2_kparams))).get ⟨i, h_i⟩ := by
      rw [h_pv2_eq]
    have h_lhs_get : (toPolyVecOfLen pv_tmp2 (k params) h_pv2_len).get ⟨i, h_i⟩ =
                     toPoly (↑pv_tmp2 : List _)[i] := by
      simp only [toPolyVecOfLen, Vector_get_ofFn]
    rw [h_lhs_get] at h_get
    rw [h_get]
    -- Unfold the `Add (PolyVector …)` instance.
    show (Vector.ofFn _).get ⟨i, h_i⟩ = _
    rw [Vector_get_ofFn]
    -- Bridge Fin-getElem to Nat-getElem.
    simp only [Fin.getElem_fin]
    -- Show first summand = Polynomial.zero q.
    have h_pv1_get : (toPolyVecOfLen pv_tmp1 (k params)
                       (by rw [hlen_pv1, h_pv_tmp_len]))[i]'h_i = Polynomial.zero q := by
      simp only [toPolyVecOfLen, Vector.getElem_ofFn]
      apply Vector.ext; intro k' hk'
      simp only [toPoly, MLKEM.Polynomial.zero, Vector.getElem_ofFn, Vector.getElem_replicate]
      have h_zero := h_pv1_zero i (by rw [hlen_pv1, h_pv_tmp_len]; exact h_i) k' hk'
      simp only [u16ToZq]; rw [h_zero]; rfl
    rw [h_pv1_get]
    -- Polynomial.zero + p = p (Polynomial uses Vector.zipWith via Vector's Add instance).
    have h_zero_add (p : MLKEM.Polynomial q) : MLKEM.Polynomial.zero q + p = p := by
      apply Vector.ext; intro k' hk'
      show (Vector.zipWith _ _ _)[k']'hk' = _
      simp only [MLKEM.Polynomial.zero, Vector.getElem_zipWith, Vector.getElem_replicate, zero_add]
    rw [h_zero_add]
    -- Peel the outer Vector.map.
    rw [Vector.getElem_map]
    apply congrArg
    -- Bridge the matrix: toPolyMatrixOfLen s8 _ _ = Matrix.of (keyAHat …)
    have h_mat : (toPolyMatrixOfLen s8 (k params)
                   (by rw [h_s8_pm_len, h_nrows_eq]) : MLKEM.PolyMatrix q (k params)) =
                 Matrix.of (keyAHat pk_mlkem_key params) := by
      funext a b; simp only [toPolyMatrixOfLen, Matrix.of_apply]; exact h_s8_eq a b
    -- Bridge the vector.
    have h_vec : toPolyVecOfLen pvr_inner2 (k params) h_pvr2_kparams =
        Vector.ofFn (fun j : Fin (k params) =>
          MLKEM.NTT (toPoly ((↑pvr_inner1 : List _)[j.val]'(by
            have hj := j.isLt
            show pvr_inner1.val.length > j.val
            rw [show pvr_inner1.val.length = pvr_inner1.length from rfl, h_pvr_inner_len]
            exact hj)))) := by
      apply Vector.ext; intro j hj
      simp only [toPolyVecOfLen, Vector.getElem_ofFn]
      exact h_pvr2_eq j (by rw [h_pvr_inner_len]; exact hj)
    rw [h_mat, h_vec]
    -- Now both sides are `(M.MulVectorNTT V).get/getElem ⟨i, h_i⟩` — bridge .get/getElem.
    show (MLKEM.PolyMatrix.MulVectorNTT _ _)[i]'h_i = _
    rfl

/-! ### Phase 4: `encapsInt.sampleE1Add` — invoke `_loop1` to sample e₁

Thin wrapper: `sampleE1Add` is exactly one monadic call to
`mlkem.encapsulate_internal_loop1` with `iter.start = 0`, `iter.end =
n_rows`, and exit value `pe_tmp0`.  The body delivers the streaming
invariant `encInvSampleE1Add ... (k params)` at exit — i.e., `pv_tmp4`
holds `orig_pv_tmp[j] + SamplePolyCBD η₂(PRF η₂(σ, (k + j) : Byte))`
for every row `j ∈ [0, k)`.

Informal proof.  Unfold `encapsInt.sampleE1Add`; the body is the single
`step mlkem.encapsulate_internal_loop1.spec` with the iterator
`{ start := 0#u8, end := n_rows }`, the input `(mkhs7, mkhs8)`, the
incoming `cbd_sample_buffer2`, the input `pv_tmp3` (used as both
`orig_pv_tmp` and `pv_tmp` at i=0), `p_comp_temps.poly_element0`, and
the chain of side conditions: `h_wf`, `h_inv` (entry at i=0), the
forall over `orig_pv_tmp` well-formedness `h_orig_wf_all`,
`h_iter_end : n_rows.val = k params`, `h_iter_start : 0 ≤ k params`,
`h_eta2`, `h_n_rows`.

`loop1.spec`'s post is `encInvSampleE1Add ... (k params) mkhs g_base`,
matching this wrapper's post directly. -/
@[step]
theorem encapsInt.sampleE1Add.spec
    (params : ParameterSet)
    (rOuter : 𝔹 32)
    (pk_mlkem_key : mlkem.key.Key)
    (p_comp_temps : mlkem.ntt.InternalComputationTemporaries)
    (pv_tmp3 : Slice (PolyElement))
    (cbd_sample_buffer2 : Array U8 193#usize)
    (mkhs7 mkhs8 : mlkem.hash.MlKemHashState)
    (g_base : GhostState)
    (h_wf : wfKey pk_mlkem_key params)
    (h_inv : encInvSampleE1Add params rOuter pv_tmp3 pv_tmp3 0 mkhs7 g_base)
    (h_orig_wf_all : ∀ (j : ℕ) (h_j : j < (k params : ℕ))
                      (_h_olen : pv_tmp3.length = (k params : ℕ)),
                      wfPoly (pv_tmp3.val[j]'(by
                        have := pv_tmp3.property; grind)))
    (h_eta2 : pk_mlkem_key.params.n_eta2.val = (η₂ : ℕ))
    (h_n_rows : pk_mlkem_key.params.n_rows.val = (k params : ℕ)) :
    encapsInt.sampleE1Add pk_mlkem_key p_comp_temps mkhs7 mkhs8
        cbd_sample_buffer2 pv_tmp3
    ⦃ _cbd3 pv_tmp4 _pe_tmp0 =>
        encInvSampleE1Add params rOuter pv_tmp3 pv_tmp4
          (k params : ℕ) mkhs7 g_base ∧
        wfPolyVec pv_tmp4 ⦄ := by
  unfold encapsInt.sampleE1Add
  step
  case rOuter => exact rOuter
  case g_base => exact g_base
  case h_inv => simpa using h_inv
  exact And.intro cbd_sample_buffer3_post
    (wfPolyVec_of_encInvSampleE1Add_full cbd_sample_buffer3_post)

/-! ### Phase 5: `encapsInt.shakeE2` — sample e₂ via Shake-PRF(σ, 2k)

Realizes FIPS 203 Algorithm 17 line 2e (`e₂ ← SamplePolyCBD η₂
PRF η₂ σ N`, with `N = 2k`) and the leading partial of line 2h (the
addition of `e₂` to the running `v` accumulator that already holds
`INTT(t̂·r̂)` from `buildU_dotE2`).

Body (from `Funs.lean`).  Writes counter byte `2k` to
`cbd_sample_buffer[0]`; clones the original `mkhs7` (still
absorbing σ from prelude); appends the counter byte (length 1) →
`mkhs10`; extracts `64·η₂` bytes from `mkhs10` into
`cbd_sample_buffer[0..64η₂]` → `mkhs11` (now squeezing); calls
`poly_element_sample_cbd_from_bytes` with `η₂` → `pe_tmp1`; adds
`pe_tmp1` to `pe_tmp02` → `pe_tmp03`.

Bridge 5 (`prf_shake_samplePolyCBD_bridge_of_absorbing`, in
`Bridges/PrfShake.lean`) packages the clone/append/extract/SampleCBD
chain into:

```
toPoly pe_tmp1 = MLKEM.SamplePolyCBD η₂ (MLKEM.PRF η₂ σ (2k : Byte))
```

given that `mkhs7` is `absorbing g_base` with
`g_base.absorbed.map (·.bv) = σ.toList` and counter byte `2k`.

Informal proof.  Unfold `encapsInt.shakeE2`; sequence:
1. `step Array.update.spec` writes the counter byte at index 0.
2. `step MlKemHashState.clone.spec` clones `mkhs7` → `mkhs9`.
3. `step MlKemHashState.get_alg.spec`; `step PartialEq.eq.spec`;
   `step massert` — all discharge given `h_alg`.
4. `step Array.index.spec` for the 1-byte slice; `step .append.spec`
   for the counter byte → `mkhs10` absorbing `g_base.append [2k]
   false`.
5. `step Array.index_mut.spec` for the `64·η₂`-byte destination
   slice.
6. `step MlKemHashState.extract.spec` with `wipe = false` →
   `mkhs11` squeezing.
7. `step Array.to_slice.spec`; `step
   poly_element_sample_cbd_from_bytes.spec` with `η = η₂`; apply
   Bridge 5 to close the per-coefficient equality.
8. `step poly_element_add_in_place.spec` for the sum.

Composability.  Phase 6 (`buildV`) consumes `pe_tmp03` to add μ; the
top-spec proof rewrites `pe_tmp03` via this post's equation. -/
@[step]
theorem encapsInt.shakeE2.spec
    (params : ParameterSet)
    (σ : 𝔹 32)
    (pk_mlkem_key : mlkem.key.Key)
    (p_comp_temps : mlkem.ntt.InternalComputationTemporaries)
    (mkhs7 : mlkem.hash.MlKemHashState)
    (cbd_sample_buffer3 : Array U8 193#usize)
    (pe_tmp02 : PolyElement)
    (g_base : GhostState)
    (_h_wf : wfKey pk_mlkem_key params)
    (h_eta2 : pk_mlkem_key.params.n_eta2.val = (η₂ : ℕ))
    (h_n_rows : pk_mlkem_key.params.n_rows.val = (k params : ℕ))
    (h_abs : mlkem.hash.MlKemHashState.absorbing mkhs7 g_base)
    (h_alg : mkhs7.alg = mlkem.hash.MlKemHashAlg.Shake256)
    (h_g_absorbed : g_base.absorbed.map (·.bv) = σ.toList)
    (h_wf_pe : wfPoly pe_tmp02) :
    encapsInt.shakeE2 pk_mlkem_key p_comp_temps mkhs7
        cbd_sample_buffer3 pe_tmp02
    ⦃ _mkhs11 _cbd5 pe_tmp1 pe_tmp03 =>
        wfPoly pe_tmp1 ∧
        wfPoly pe_tmp03 ∧
        toPoly pe_tmp1 =
          MLKEM.SamplePolyCBD (η := η₂)
            (MLKEM.PRF (η := η₂) σ (2 * (k params : ℕ) : Byte)) ∧
        toPoly pe_tmp03 = Vector.ofFn fun (j : Fin 256) =>
          (toPoly pe_tmp02).get j + (toPoly pe_tmp1).get j ⦄ := by
  unfold encapsInt.shakeE2
  have h_k_le : (k params : ℕ) ≤ 4 := k_le_4 params
  have h_n_rows_le : pk_mlkem_key.params.n_rows.val ≤ 4 := by rw [h_n_rows]; exact h_k_le
  -- Phase A: counter byte 2k, clone+assert+append.
  step  -- i12 := 2 * n_rows
  step  -- cbd_sample_buffer4 := update
  step as ⟨mkhs9, h_mkhs9⟩; subst h_mkhs9  -- clone
  step  -- mkha
  step  -- b
  step  -- massert
  step  -- s12 := index [0..1]
  step with mlkem.hash.MlKemHashState.append.spec _ _ g_base (Or.inl h_abs)
    as ⟨mkhs10, h_alg10, h_abs10⟩
  -- Phase B: extract 64 * η₂ PRF bytes.
  have h_n_eta2_le : pk_mlkem_key.params.n_eta2.val ≤ 3 := by rw [h_eta2]; decide
  step  -- i13
  step  -- i14
  step  -- index_mut [0..i14]
  step with mlkem.hash.MlKemHashState.extract.spec _ _ _ _
    (Or.inl h_abs10) (Or.inr (h_alg10.trans h_alg))
    as ⟨_mkhs11, s14, _h_alg11, h_s14_len, h_s14_val, _h_mkhs11_post⟩
  -- Phase C: sample CBD into pe_tmp1.
  step  -- s15 := to_slice
  step  -- i15 := cast n_eta2 U32
  have h_cb4_len : (↑cbd_sample_buffer4 : List U8).length = 193 := by
    have := cbd_sample_buffer4.property; simp
  have h_imb_len : (↑(index_mut_back5 s14) : List U8).length = 193 := by
    rw [s13_post3, List.length_setSlice!]; exact h_cb4_len
  have h_s15_len : s15.length = 64 * 3 + 1 := by
    simp [s15_post, Aeneas.Std.Slice.length, Aeneas.Std.Array.to_slice, h_imb_len]
  have h_i16_eta : i15.val = 2 ∨ i15.val = 3 := by
    rw [i15_post]; simp; exact Or.inl h_eta2
  step with mlkem.ntt.poly_element_sample_cbd_from_bytes.spec _ _ _ h_i16_eta h_s15_len
    as ⟨pe_tmp1, h_pe1_wf, h_pe1_eq⟩
  -- Phase D: add_in_place
  step with mlkem.ntt.poly_element_add_in_place.spec pe_tmp1 pe_tmp02 h_pe1_wf h_wf_pe
    as ⟨pe_tmp03, h_pe03_wf, h_pe03_eq⟩
  refine ⟨h_pe1_wf, h_pe03_wf, ?_, h_pe03_eq⟩
  rw [h_pe1_eq]
  -- Bridge: SamplePolyCBD over extracted bytes = SamplePolyCBD over PRF.
  have h_sm : mkhs9.state.squeeze_mode = false := by
    unfold mlkem.hash.MlKemHashState.absorbing at h_abs
    have h_weak : sha3.sha3_impl.absorbingWeak mkhs9.state g_base := h_abs.1.1
    simpa using h_weak.2.1
  have h_counter_bv : i12.bv = ((2 * (k params : ℕ) : ℕ) : BitVec 8) := by
    apply BitVec.eq_of_toNat_eq
    rw [UScalar.bv_toNat, i12_post, h_n_rows]
    simp [BitVec.toNat_ofNat]
    omega
  have h_s12_val : (↑s12 : List U8) = [i12] := by
    rw [s12_post1, cbd_sample_buffer4_post]
    have h_cb3_len : (↑cbd_sample_buffer3 : List U8).length = 193 := by
      have := cbd_sample_buffer3.property; simp
    simp [Aeneas.Std.Array.to_slice]
    rcases hcb : (↑cbd_sample_buffer3 : List U8) with _ | ⟨x, xs⟩
    · rw [hcb] at h_cb3_len; simp at h_cb3_len
    · simp [List.set, List.take]
  have h_i16_val : (i15.val : ℕ) = pk_mlkem_key.params.n_eta2.val := by
    rw [i15_post]; simp
  have h_eta_cbd_val : (cbdEta i15 h_i16_eta).val = η₂ := by
    show i15.val = η₂; rw [h_i16_val]; exact h_eta2
  have h_s15_bound : 0 + 64 * ((cbdEta i15 h_i16_eta).val : ℕ) ≤ s15.length := by
    show 0 + 64 * (i15.val : ℕ) ≤ s15.length
    rw [h_s15_len, h_i16_val, h_eta2]; simp; decide
  have h_bridge :
      @MLKEM.SamplePolyCBD
          (cbdEta i15 h_i16_eta)
          (sliceWindowToSpecBytes s15 0 (64 * ((cbdEta i15 h_i16_eta).val : ℕ))
            (by linarith [h_s15_bound]))
        = @MLKEM.SamplePolyCBD η₂ (MLKEM.PRF η₂ σ i12.bv) := by
    apply prf_shake_samplePolyCBD_bridge_of_absorbing
      (cbdEta i15 h_i16_eta) η₂ h_eta_cbd_val
      σ i12 mkhs9 g_base h_abs h_alg h_g_absorbed
      mkhs9.state.squeeze_mode h_sm s15 h_s15_bound
    intro kk hkk
    -- Chain at the list level:
    --   s15.val = (cbd_sample_buffer4.val).setSlice! 0 s14.val
    --   s14.val = (extractOutput (g_base.append s12.val sm) s13.length).toList
    --   s12.val = [i12]
    --   s13.length = i14.val = 64 * i13.val = 64 * n_eta2.val = 64*(cbdEta i15 _).val
    have h_i14_val : i13.val = pk_mlkem_key.params.n_eta2.val := by
      rw [i13_post]; simp
    have h_i15_val : i14.val = 64 * pk_mlkem_key.params.n_eta2.val := by
      rw [i14_post, h_i14_val]
    have h_s13_len : s13.length = 64 * pk_mlkem_key.params.n_eta2.val := by
      rw [s13_post2, h_i15_val]; simp
    have h_cbdEta_val : (cbdEta i15 h_i16_eta).val = pk_mlkem_key.params.n_eta2.val := by
      show i15.val = _; exact h_i16_val
    have h_kk_n : kk < 64 * pk_mlkem_key.params.n_eta2.val := by
      rw [← h_cbdEta_val]; exact hkk
    have h_kk_s13 : kk < s13.length := by rw [h_s13_len]; exact h_kk_n
    have h_kk_extract :
        kk < (extractOutput (g_base.append [i12] mkhs9.state.squeeze_mode) s13.length).toList.length := by
      rw [Vector.toList_length]; exact h_kk_s13
    -- s14.val[kk] equality from h_s14_val (with s12 := [i12]).
    have h_s14_kk : s14.val[kk]'(by
        rw [show s14.val.length = s14.length from rfl, h_s14_len]; exact h_kk_s13) =
        (extractOutput (g_base.append [i12] mkhs9.state.squeeze_mode) s13.length).toList[kk]'h_kk_extract := by
      have h_lists_eq : s14.val =
          (extractOutput (g_base.append [i12] mkhs9.state.squeeze_mode) s13.length).toList := by
        rw [h_s14_val, h_s12_val]
      exact List.getElem_of_eq h_lists_eq _
    -- s15.val[kk] = s14.val[kk] via setSlice!_middle (kk in [0, s14.val.length)).
    have h_s15_val_eq : s15.val = cbd_sample_buffer4.val.setSlice! 0 s14.val := by
      rw [s15_post]
      show (index_mut_back5 s14).to_slice.val = _
      simp [Aeneas.Std.Array.to_slice]
      exact s13_post3 s14
    have h_s14_len_eq : s14.val.length = s13.length := by
      show s14.length = _; exact h_s14_len
    have h_kk_s14 : kk < s14.val.length := by rw [h_s14_len_eq]; exact h_kk_s13
    have h_kk_cb4 : kk < cbd_sample_buffer4.val.length := by
      rw [h_cb4_len]; have := h_n_eta2_le; rw [h_s13_len] at h_kk_s13; omega
    have h_s15_kk : s15.val[kk]'(by
        rw [show s15.val.length = s15.length from rfl, h_s15_len]
        rw [h_s13_len] at h_kk_s13; omega) = s14.val[kk] := by
      -- Convert s15.val to its set-slice form, then use getElem_setSlice!_middle.
      have heq : (cbd_sample_buffer4.val.setSlice! 0 s14.val)[kk]'(by
          rw [List.length_setSlice!]; exact h_kk_cb4) = s14.val[kk - 0] :=
        List.getElem_setSlice!_middle cbd_sample_buffer4.val s14.val 0 kk
          ⟨Nat.zero_le _, by simpa using h_kk_s14, h_kk_cb4⟩
      simp at heq
      calc s15.val[kk] = (cbd_sample_buffer4.val.setSlice! 0 s14.val)[kk]'(by
              rw [List.length_setSlice!]; exact h_kk_cb4) :=
            List.getElem_of_eq h_s15_val_eq _
        _ = s14.val[kk] := heq
    -- Combine.
    rw [h_s15_kk, h_s14_kk]
    -- Both sides extract at index kk; close by congr on the length argument.
    -- s13.length = 64 * (cbdEta i15 _).val (both reduce to 64 * n_eta2.val).
    have h_len_eq : s13.length = 64 * (cbdEta i15 h_i16_eta).val := by
      rw [h_s13_len, h_cbdEta_val]
    -- Cast the index witness via the length equality.
    exact List.getElem_of_eq (congrArg (fun n =>
        (extractOutput (g_base.append [i12] mkhs9.state.squeeze_mode) n).toList) h_len_eq) _
  show @MLKEM.SamplePolyCBD (cbdEta i15 h_i16_eta)
        (sliceWindowToSpecBytes s15 0 (64 * ((cbdEta i15 h_i16_eta).val : ℕ)) _)
      = @MLKEM.SamplePolyCBD η₂ (MLKEM.PRF η₂ σ (2 * (↑(k params) : Byte)))
  rw [h_bridge]
  have h_byte_eq : i12.bv = 2 * ((k params : ℕ) : Byte) := by
    rw [h_counter_bv]
    apply BitVec.eq_of_toNat_eq
    simp [BitVec.toNat_mul, BitVec.toNat_ofNat]
  rw [h_byte_eq]

/-! ### Phase 6: `encapsInt.buildU_dotE2` — encode u and start v computation

Realizes FIPS 203 Algorithm 17 line 2i (`c₁ ← ByteEncode_dᵤ(Compress_dᵤ(u))`)
and the leading partial of line 2h (`v_acc = INTT(t̂·r̂)`) — i.e., the
dot-product of the public NTT vector `t̂` with the NTT-form `r̂`, with
Montgomery factors arranged so the final result is a standard-form
polynomial `INTT(t̂·r̂)` (up to the `R·R⁻¹ ≡ 1 mod q` collapse).

Body (from `Funs.lean`).
1. Cast `n_bits_of_u` to `U32` → `i11 = dᵤ`.
2. `index_mut pb_ciphertext[0..cb_u]` → slice `s9`, back-closure
   `index_mut_back4` for the [0..cb_u] portion.
3. `vector_compress_and_encode pv_tmp4 i11 s9` → `s10` holds
   per-row `compressEncodePoly dᵤ (toPoly pv_tmp4[i])` at each
   `32·dᵤ`-byte window `[i·(32·dᵤ) ..]`.
4. `pk_mlkem_key.t` → slice `s11` of length `k` = `keyT _ params`
   in standard NTT form.
5. `vector_mont_dot_product s11 pvr_inner2 pe_tmp0 pa_tmp` →
   `pe_tmp01 = innerProductNTT(t̂, r̂) · R⁻¹` (R⁻¹ from Montgomery
   accumulator), `pa_tmp1 = 0`.
6. `poly_element_intt_and_mul_r pe_tmp01` → `pe_tmp02 =
   INTT(innerProductNTT(t̂, r̂) · R⁻¹) · R` = `INTT(t̂·r̂)` modulo the
   R·R⁻¹ collapse (handled at the top-spec).

Composability.  Phase 7 (`buildV`) consumes `pe_tmp02` (adds decoded μ
and re-encodes); phase 8 (`wipeRepack`) consumes the back-closure
`index_mut_back4` together with `s10`'s extended form (after `buildV`
writes the v-portion into the [cb_u..] tail) to reach
`pb_ciphertext = c₁ ‖ c₂` at the top-spec. -/
@[step]
theorem encapsInt.buildU_dotE2.spec
    (params : ParameterSet)
    (pk_mlkem_key : mlkem.key.Key)
    (pb_ciphertext : Slice U8)
    (cb_u : Usize)
    (pvr_inner2 : Slice (PolyElement))
    (pa_tmp : PolyAccumulator)
    (pv_tmp4 : Slice (PolyElement))
    (pe_tmp0 : PolyElement)
    (h_wf : wfKey pk_mlkem_key params)
    (h_wf_pvr_inner2 : wfPolyVec pvr_inner2)
    (h_wf_pv_tmp4 : wfPolyVec pv_tmp4)
    (h_pvr_inner_len : pvr_inner2.length = (k params : ℕ))
    (h_pv_tmp4_len : pv_tmp4.length = (k params : ℕ))
    (h_pb_ct_len : pb_ciphertext.length = cipherlength params)
    (h_cb_u : cb_u.val = 32 * dᵤ params * (k params : ℕ)) :
    encapsInt.buildU_dotE2 pk_mlkem_key pb_ciphertext cb_u
        pvr_inner2 pa_tmp pv_tmp4 pe_tmp0
    ⦃ index_mut_back4 s10 _pa_tmp1 pe_tmp02 =>
        ∃ (_h_s10_len : s10.length = cb_u.val),
        wfPoly pe_tmp02 ∧
        /- (a) u-bytes: each row i's `32·dᵤ`-byte window of `s10`
              is the compress-encode of row i of `pv_tmp4`. -/
        (∀ (i : ℕ) (h_i : i < (k params : ℕ)),
          ∃ (h_window : (i + 1) * (32 * dᵤ params) ≤ s10.length),
            sliceWindowToSpecBytes s10
                (i * (32 * dᵤ params))
                (32 * dᵤ params)
                (Nat.add_one_mul _ _ ▸ h_window)
              = compressEncodePoly (dᵤ params)
                  (toPoly (pv_tmp4.val[i]'(by
                    simp [Slice.length] at h_pv_tmp4_len; omega)))
                  (by rcases params <;> decide)) ∧
        /- (b) v-accumulator: `pe_tmp02 = INTT(t̂·r̂) · (R⁻¹·R)`,
              with Mont factors composed left-to-right per the body. -/
        toPoly pe_tmp02 =
          ((MLKEM.NTTInv
              ((PolyVector.innerProductNTT
                  (keyT pk_mlkem_key params)
                  (toPolyVecOfLen pvr_inner2 (k params) h_pvr_inner_len)).map
                  (Rinv * ·))).map (R * ·)) ∧
        /- (c) Back-closure framing: applying `index_mut_back4` to
              any slice `s'` produces `pb_ciphertext` with `[0..cb_u]`
              overwritten by `s'`. -/
        (∀ s', (index_mut_back4 s').val =
            pb_ciphertext.val.setSlice! 0 s'.val) ⦄ := by
  -- Extract parameter projections from wfKey
  have h_params_ok := wfKey.params_ok h_wf
  have h_n_bits_of_u : pk_mlkem_key.params.n_bits_of_u.val = dᵤ params :=
    wfInternalParams.n_bits_of_u_val h_params_ok
  have h_k_ge_2 : 2 ≤ (k params : ℕ) := k_ge_2 params
  have h_k_le_4 : (k params : ℕ) ≤ 4 := k_le_4 params
  have h_dᵤ_bounds : 1 ≤ dᵤ params ∧ dᵤ params ≤ 12 := by
    rcases params <;> decide
  unfold encapsInt.buildU_dotE2
  step*
  case kn => exact k params
  case h_kn => exact s11_post1.symm
  case h_wf1 => exact s11_post2
  -- After cases close, the continuation is the do-block ending with poly_element_intt_and_mul_r.
  step*
  -- After both step*, the goal is the existential conjunction.
  -- s11 ↔ keyT bridge: toPolyVecOfLen s11 (k params) _ = keyT pk_mlkem_key params
  have h_s11_eq_keyT :
      toPolyVecOfLen s11 (k params) s11_post1 = keyT pk_mlkem_key params := by
    apply Vector.ext
    intro i hi
    unfold toPolyVecOfLen
    simp only [Vector.getElem_ofFn]
    exact s11_post3 ⟨i, hi⟩
  -- Discharge the 5-part existential + conjunction.
  have h_s10_len : s10.length = cb_u.val := by
    rw [s10_post1, s9_post2]; agrind
  refine ⟨h_s10_len, ?_, ?_, ?_, ?_⟩
  · -- wfPoly pe_tmp02 from intt_and_mul_r post (first conjunct)
    rename_i pe_tmp02_post1 _
    exact pe_tmp02_post1
  · -- (a) Per-row u-bytes from s10_post2 (window indexed by dᵤ via h_n_bits_of_u)
    intro i h_i
    have h_i' : i < pv_tmp4.length := by rw [h_pv_tmp4_len]; exact h_i
    have h_i12_val : i11.val = dᵤ params := by
      subst i11_post; simp [h_n_bits_of_u]
    have key := s10_post2 i h_i'
    simp only [h_i12_val] at key
    convert key using 6
    · exact h_i12_val.symm
    · exact h_i12_val.symm
    · exact h_i12_val.symm
  · -- (b) toPoly pe_tmp02 = ... (intt_and_mul_r ∘ vector_mont_dot_product, then s11 ↔ keyT)
    rename_i _ pe_tmp02_post2
    rename_i pe_tmp01_post3 _ _
    rw [pe_tmp02_post2, pe_tmp01_post3, h_s11_eq_keyT]
  · -- (c) Back-closure framing
    intro s'
    simp [s9_post3]

/-! ### Phase 7: `encapsInt.buildV` — decode μ from m, build v, encode v

Realizes FIPS 203 Algorithm 17 line 2f (`μ ← Decompress_1(ByteDecode_1
(m))`), the tail of line 2h (`v = INTT(t̂·r̂) + e₂ + μ`), and line 2j
(`c₂ ← ByteEncode_dᵥ(Compress_dᵥ(v))`).

Body (from `Funs.lean`).
1. `pb_random.to_slice` → `s16` (32 bytes = the 32-byte message m).
2. `poly_element_decode_and_decompress s16 1 pe_tmp1` → `pe_tmp11 =
   decodeDecompressPoly 1 m` = `μ` (the second output overwrites
   `pe_tmp1`).  Note: `d = 1`, `32·1 = 32` bytes match `s16.length`.
3. `poly_element_add_in_place pe_tmp11 pe_tmp03` → `pe_tmp04 =
   pe_tmp03 + μ` per-coefficient.  By phase 5's post,
   `pe_tmp03 = INTT(t̂·r̂) + e₂` (modulo Mont collapse), so
   `pe_tmp04 = INTT(t̂·r̂) + e₂ + μ` = `v`.
4. Cast `n_bits_of_v` to `U32` → `i16 = dᵥ`.
5. `index_mut pb_ciphertext[cb_u..]` → slice `s17` of length
   `pb_ciphertext.length - cb_u.val = 32·dᵥ`, back-closure
   `index_mut_back6`.
6. `poly_element_compress_and_encode pe_tmp04 i16 s17` → `s18 =
   compressEncodePoly dᵥ (toPoly pe_tmp04)`.

Composability.  Phase 8 (`wipeRepack`) consumes `s18` together with
`index_mut_back6` (and the prior `index_mut_back4` from phase 6) to
assemble `pb_ciphertext = c₁ ‖ c₂` at the top-spec. -/

/-- Bridge between `sliceToSpecBytes pb_random.to_slice (32 * (1#u32).val) _` and
    `pb_random.toSpec`.  Extracted to a standalone lemma so the minimal context
    keeps elaboration fast.  The two `Vector` types have different sizes
    syntactically (`32 * (1#u32).val` vs `32`); `congr!` resolves both the
    size and the element function. -/
private theorem encapsInt.buildV.sliceToSpec_bridge
    (pb_random : Array U8 32#usize)
    (h : pb_random.to_slice.length = 32 * (1#u32).val) :
    HEq (sliceToSpecBytes pb_random.to_slice (32 * (1#u32).val) h)
        pb_random.toSpec := by
  unfold sliceToSpecBytes Aeneas.Std.Array.toSpec arrayToSpecBytes
  congr! 1

private theorem encapsInt.buildV.sliceWindowToSpec_bridge
    (pb_random : Array U8 32#usize)
    (h : 0 + 32 * (1#u32).val ≤ pb_random.to_slice.length) :
    HEq (sliceWindowToSpecBytes pb_random.to_slice 0 (32 * (1#u32).val) h)
        pb_random.toSpec := by
  have h_len : (32 * (1#u32).val : ℕ) = (32#usize).val := by decide
  unfold sliceWindowToSpecBytes Aeneas.Std.Array.toSpec arrayToSpecBytes
  congr! 1
  funext i
  simp

@[step]
theorem encapsInt.buildV.spec
    (params : ParameterSet)
    (pk_mlkem_key : mlkem.key.Key)
    (pb_random : Array U8 32#usize)
    (cb_u : Usize)
    (index_mut_back4 : Slice U8 → Slice U8)
    (s10 : Slice U8)
    (pe_tmp1 : PolyElement)
    (pe_tmp03 : PolyElement)
    (h_wf : wfKey pk_mlkem_key params)
    (h_wf_pe_tmp1 : wfPoly pe_tmp1)
    (h_wf_pe_tmp03 : wfPoly pe_tmp03)
    (_h_s10_len : s10.length = cb_u.val)
    (h_cb_u : cb_u.val = 32 * dᵤ params * (k params : ℕ))
    (h_n_bits_of_v : pk_mlkem_key.params.n_bits_of_v.val = dᵥ params)
    (h_back4_len : (index_mut_back4 s10).length = cb_u.val + 32 * dᵥ params) :
    encapsInt.buildV pk_mlkem_key pb_random cb_u index_mut_back4 s10
        pe_tmp1 pe_tmp03
    ⦃ pe_tmp11 pe_tmp04 index_mut_back6 s18 =>
        wfPoly pe_tmp11 ∧
        wfPoly pe_tmp04 ∧
        /- (a) μ: `pe_tmp11 = Decompress_1 ∘ ByteDecode_1` of `m`. -/
        toPoly pe_tmp11 =
          decodeDecompressPoly 1 (pb_random.toSpec)
            (by decide) ∧
        /- (b) v: pe_tmp04 = pe_tmp03 + μ point-wise. -/
        toPoly pe_tmp04 = (Vector.ofFn fun (j : Fin 256) =>
          (toPoly pe_tmp03).get j + (toPoly pe_tmp11).get j) ∧
        /- (c) c₂ bytes: `s18 = compressEncodePoly dᵥ v`. -/
        (∃ (h_s18_len : s18.length = 32 * dᵥ params),
            sliceToSpecBytes s18 (32 * dᵥ params) h_s18_len
              = compressEncodePoly (dᵥ params)
                  (toPoly pe_tmp04)
                  (by rcases params <;> decide)) ∧
        /- (d) Back-closure framing: applying `index_mut_back6` to
              any slice `s'` produces a slice with `[cb_u..]`
              overwritten by `s'`. -/
        (∀ s', (index_mut_back6 s').val =
            (index_mut_back4 s10).val.setSlice! cb_u.val s'.val) ⦄ := by
  unfold encapsInt.buildV
  step  -- s16 ← pb_random.to_slice
  step as ⟨err_decode, pe_tmp11, h_wf_pe_tmp11, h_decode⟩  -- decode_and_decompress
  -- `err_decode` is the discarded error; per
  -- `poly_element_decode_and_decompress.spec` with `d = 1`,
  -- only `NoError` is reachable (`InvalidBlob` requires `d = 12`).
  -- Variant order in `common.Error`: NoError (0), Unused, WrongKeySize,
  -- WrongBlockSize, WrongDataSize, WrongNonceSize, WrongTagSize,
  -- WrongIterationCount, AuthenticationFailure, ExternalFailure,
  -- FipsFailure, HardwareFailure, NotImplemented, InvalidBlob (13),
  -- BufferTooSmall, InvalidArgument, MemoryAllocationFailure,
  -- SignatureVerificationFailure, IncompatibleFormat, ValueTooLarge,
  -- SessionReplayFailure, HbsNoOtsKeysLeft, HbsPublicRootMismatch.
  rcases err_decode with _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _
    | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _
  · -- NoError (variant 0): main proof.
    obtain ⟨h_s16_len, h_toPoly_pe_tmp11, _h_canon_pe_tmp11⟩ := h_decode
    step*
    · -- (h_d): 1 ≤ i16 ∧ i16 ≤ 12
      have h_i17_val : i16.val = dᵥ params := by simp [i16_post, h_n_bits_of_v]
      rw [h_i17_val]; refine ⟨?_, ?_⟩ <;> rcases params <;> decide
    · -- (h_len): s17.length = i16 * 32
      have h_i17_val : i16.val = dᵥ params := by simp [i16_post, h_n_bits_of_v]
      rw [s17_post2, h_back4_len, h_i17_val]; agrind
    · -- Final 6-conjunct.
      have h_i17_val : i16.val = dᵥ params := by simp [i16_post, h_n_bits_of_v]
      have h_s18_len_dv : s18.length = 32 * dᵥ params := by
        rw [s18_post1, h_i17_val]
      refine ⟨h_wf_pe_tmp11, pe_tmp04_post1, ?_, pe_tmp04_post2,
              ⟨h_s18_len_dv, ?_⟩, s17_post3⟩
      · -- (μ): toPoly pe_tmp11 = decodeDecompressPoly 1 pb_random.toSpec _
        rw [h_toPoly_pe_tmp11]
        fcongr 1
        · rfl
        · subst s16_post
          exact encapsInt.buildV.sliceWindowToSpec_bridge pb_random _
        · rfl
      · -- (c₂): sliceToSpecBytes s18 (32 * dᵥ) _ = compressEncodePoly dᵥ pe_tmp04 _
        grind
  -- Variants 1–22 (all absurd): either `h_decode : False` (most) or
  -- `h_decode : 1 = 12` (InvalidBlob, variant 13). Normalize the match
  -- first since rcases does not reduce it under the binder.
  all_goals first
    | exact h_decode.elim
    | (simp only at h_decode; exact absurd h_decode (by decide))

/-! ### Phase 8: `encapsInt.wipeRepack` — terminal: wipe scratch, pack outputs

The terminal "thin re-pack" phase: wipes the secret material in
`cbd_sample_buffer5` (no spec-observable effect), applies the four
back-closures (`index_mut_back` for `pvr_inner`, `index_mut_back1` for
`pv_tmp`, `index_mut_back6` for the [cb_u..] tail of `pb_ciphertext`),
and returns `(NoError, pb_agreed_secret1, pb_ciphertext_final,
temps_final)`.

Body (from `Funs.lean`).
1. `cbd_sample_buffer5.to_slice_mut` → mutable view `s19`.
2. `common.wipe_slice s19` — overwrites with zeros (secret hygiene).
3. `pb_ciphertext2 := index_mut_back6 s18` — installs the c₂ tail.
4. `a := index_mut_back pvr_inner2`,
   `a1 := index_mut_back1 pv_tmp4` — re-pack `max_size_vector{0,1}`.
5. `Result.ok (NoError, pb_agreed_secret1, pb_ciphertext2,
   { max_size_vector0 := a, max_size_vector1 := a1, … })`.

This phase produces no FC data on its own — it is a structural
re-assembly.  The post records the byte-level shape of the outputs
(`pb_agreed_secret1` passes through unchanged, `pb_ciphertext2`
applies the c₂ back-closure to s18) and the `NoError` arm.  The
top-spec proof composes this with the prior phases' posts to obtain
the final FC equalities (`pb_agreed_secret = K`, `pb_ciphertext =
c₁ ‖ c₂`).

Informal proof.  Unfold `encapsInt.wipeRepack`; sequence:
1. `step Array.to_slice_mut.spec` exposes `s19`.
2. `step common.wipe_slice.spec` zeros it (post irrelevant here).
3. The remaining steps are pure (`let`s + `Result.ok`); `agrind`
   closes after `split_conjs`. -/
@[step]
theorem encapsInt.wipeRepack.spec
    (index_mut_back : Slice (PolyElement) →
                      Array (Array U16 256#usize) 4#usize)
    (index_mut_back1 : Slice (PolyElement) →
                       Array (Array U16 256#usize) 4#usize)
    (mkhs7 : mlkem.hash.MlKemHashState)
    (pb_agreed_secret1 : Slice U8)
    (pvr_inner2 pv_tmp4 : Slice (PolyElement))
    (pa_tmp1 : PolyAccumulator)
    (mkhs11 : mlkem.hash.MlKemHashState)
    (cbd_sample_buffer5 : Array U8 193#usize)
    (pe_tmp11 pe_tmp04 : PolyElement)
    (index_mut_back6 : Slice U8 → Slice U8)
    (s18 : Slice U8) :
    encapsInt.wipeRepack index_mut_back index_mut_back1 mkhs7
        pb_agreed_secret1 pvr_inner2 pv_tmp4 pa_tmp1 mkhs11
        cbd_sample_buffer5 pe_tmp11 pe_tmp04 index_mut_back6 s18
    ⦃ err agreed' ct' _temps' =>
        err = common.Error.NoError ∧
        agreed'.val = pb_agreed_secret1.val ∧
        ct'.val = (index_mut_back6 s18).val ⦄ := by
  unfold encapsInt.wipeRepack
  step*

/-! ## `encapsulate_internal` — FC against `MLKEM.Encaps_internal`

The Rust function takes its randomness `m` as an explicit input
parameter (`pb_random`), so the FC is deterministic.

Preconditions:
* `wfKey pk_mlkem_key params` — the key is well-formed.
* The key's encapsulation-key view is consistent with the spec's `ek`
  (we use `encapsulationKey pk_mlkem_key params` directly).
* `pb_agreed_secret.length = 32`.
* `pb_ciphertext.length = cipherlength params` (see `Properties/MLKEM/Basic.lean`).

On `NoError`, the visible outputs `(agreed', ct')` match
`MLKEM.Encaps_internal params ek m` where `ek = encapsulationKey
pk_mlkem_key params` and `m = arrayToSpecBytes pb_random`.

Note: the runtime requires `pk_mlkem_key.encaps_key_hash` to already
equal `H(ek)`; this is enforced by `wfKey` (the hash is precomputed
at key-load time).  Without this, `G(m ‖ H(ek))` would not match. -/

/-- Helper: from the falsified second length guard plus the chain of
`Usize.cast` / `Usize.mul` posts, conclude `pb_ciphertext.val.length =
cipherlength params`. Extracted out of `encapsulate_internal.spec` to
keep its heartbeat budget manageable. -/
theorem encapsInt.ct_length_from_guard
    {params : ParameterSet} {pk_mlkem_key : mlkem.key.Key}
    {pb_ciphertext : Slice U8}
    (h_params_ok : wfInternalParams pk_mlkem_key.params params)
    {i i1 i2 i3 cb_u i4 cb_v i5 : Usize}
    (h_pb : pb_ciphertext.val.length = i5.val)
    (hi : i.val = pk_mlkem_key.params.n_rows.val)
    (hi1 : i1.val = pk_mlkem_key.params.n_bits_of_u.val)
    (hi4 : i4.val = pk_mlkem_key.params.n_bits_of_v.val)
    (h_i2 : i2.val = i.val * i1.val)
    (h_i3 : i3.val = mlkem.key.MLWE_POLYNOMIAL_COEFFICIENTS.val / 8)
    (h_cb_u : cb_u.val = i2.val * i3.val)
    (h_cb_v : cb_v.val = i4.val * i3.val)
    (h_i5 : i5.val = cb_u.val + cb_v.val) :
    pb_ciphertext.val.length = cipherlength params := by
  have h_nrows := wfInternalParams.n_rows_val h_params_ok
  have h_n_bits_of_u := wfInternalParams.n_bits_of_u_val h_params_ok
  have h_n_bits_of_v := wfInternalParams.n_bits_of_v_val h_params_ok
  have h_i3_eq_32 : i3.val = 32 := by
    rw [h_i3]; unfold mlkem.key.MLWE_POLYNOMIAL_COEFFICIENTS; rfl
  simp only [cipherlength]
  rw [h_pb, h_i5, h_cb_u, h_cb_v, h_i2, h_i3_eq_32, hi, hi1, hi4,
      h_nrows, h_n_bits_of_u, h_n_bits_of_v]
  ring

/-- **B1 helper for the c-equality** — when two `setSlice!` writes at
offsets `0` (of length `m`) and `m` (of length `n`) populate a buffer
of length `nout = m + n`, the `sliceToSpecBytes` of the resulting
length-`nout` view equals the concatenation of the two writes' own
`sliceToSpecBytes`, modulo a `Vector.cast` that aligns the dependent
length. Pure structural lemma — no encoding content. -/
theorem sliceToSpecBytes_setSlice₂_eq_append
    {pb_ciphertext s10 s18 ct' : Slice U8}
    {m n nout : ℕ}
    (h_s10_len : s10.length = m)
    (h_s18_len : s18.length = n)
    (h_b_len : m + n ≤ pb_ciphertext.length)
    (h_nout : nout = m + n)
    (h_ct'_val : ct'.val =
        ((pb_ciphertext.val).setSlice! 0 s10.val).setSlice! m s18.val)
    (h_ct'_len : ct'.length = nout) :
    sliceToSpecBytes ct' nout h_ct'_len =
      ((sliceToSpecBytes s10 m h_s10_len) ++
        (sliceToSpecBytes s18 n h_s18_len)).cast h_nout.symm := by
  subst h_nout
  apply Vector.ext
  intro i hi
  simp only [sliceToSpecBytes, Vector.getElem_ofFn, Vector.getElem_cast]
  rw [Vector.getElem_append]
  split <;> rename_i hcase
  · simp only [Vector.getElem_ofFn]
    fcongr 1
    rw [List.Inhabited_getElem_eq_getElem! ct'.val i
          (by simp only [Slice.length] at h_ct'_len; omega),
        h_ct'_val]
    simp_lists [hcase]
  · simp only [Vector.getElem_ofFn]
    fcongr 1
    rw [List.Inhabited_getElem_eq_getElem! ct'.val i
          (by simp only [Slice.length] at h_ct'_len; omega),
        h_ct'_val]
    simp_lists [hcase]


end Symcrust.Properties.MLKEM
