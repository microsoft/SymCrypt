/-
  # Encoding/KeyGetValue.lean — `key_get_value`.

  `mlkem.key.key_get_value` is the public *encode* entry point for ML-KEM
  keys: it serialises `pk_mlkem_key` into a blob in the requested format
  (PrivateSeed / DecapsulationKey / EncapsulationKey).  This file collects
  the `#decompose` cascade, `@[step]` specs for every helper, and the
  top-level `mlkem.key_get_value.spec`.

  See `KeySetValue.lean` for the symmetric decode path. -/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.Encoding
import Symcrust.Properties.MLKEM.Bridges.KeyView
import Symcrust.Properties.MLKEM.Encoding.Compress
import Symcrust.Properties.MLKEM.Encoding.Decompress
import Symcrust.Properties.MLKEM.Encoding.KeySetValue.Prelude
import Symcrust.Properties.MLKEM.Sampling.ExpandMatrix
import Symcrust.Properties.MLKEM.Key

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust

open symcrust.common
namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

/-! ## `#decompose` cascade for `key_get_value`

`mlkem.key_get_value` is a 91-bind dispatcher with no FIPS distinction:
2 prefix binds + `match format` (3 arms).  Each arm has a length-check
guard and (for `PrivateSeed`/`DecapsulationKey`) a `has_private_*` flag
guard; the body is a linear write-to-`pb_dst` pipeline.

After Stage 2 (format-match merger) and Stage 3 (`full`-subpattern
refinement), the cascade is 5 invocations: each leaf body is split
directly into named phase helpers (no intermediate `kgv_*_body` defs).

* `kgv_priv` (23 binds): write `private_seed ‖ private_random`.
* `kgv_decap` (43 binds): write `ByteEncode₁₂(s) ‖ encoded_t ‖ ρ ‖ H(ek) ‖ private_random`.
* `kgv_encap` (18 binds): write `encoded_t[0..cb] ‖ public_seed`. -/

#decompose mlkem.key_get_value mlkem.key_get_value.fold
  letRange 0 2 => kgv_prefix
  letRange 1 1 => kgv_match_format

#decompose kgv_match_format kgv_match_format.fold
  branch 0 (letRange 0 2) => kgv_priv_lencheck
  branch 0 (letRange 1 1) => kgv_priv_lendispatch
  branch 1 (letRange 0 3) => kgv_decap_lencheck
  branch 1 (letRange 1 1) => kgv_decap_lendispatch
  branch 2 (letRange 0 3) => kgv_encap_lencheck
  branch 2 (letRange 1 1) => kgv_encap_lendispatch

-- PRIV body (23 binds): split into 2 write phases (no intermediate `kgv_priv_body`).
#decompose kgv_priv_lendispatch kgv_priv_lendispatch.fold
  branch 1 (branch 0 (letRange 0 10)) => kgv_priv_write_seed    -- private_seed into [0..32]
  branch 1 (branch 0 (letRange 1 13)) => kgv_priv_write_random  -- private_random into [32..64] + massert + terminate

-- DECAP body (43 binds): 4 write phases + 1 body fold (so the composer
-- only deals with the small body-spec, not the 4 phases + frame chain).
#decompose kgv_decap_lendispatch kgv_decap_lendispatch.fold
  branch 1 (branch 0 (letRange 0 10)) => kgv_decap_write_s_t      -- ByteEncode₁₂(s) into [0..cb] + encoded_t into [cb..2cb]
  branch 1 (branch 0 (letRange 1 10)) => kgv_decap_write_rho      -- public_seed into [2cb..2cb+32]
  branch 1 (branch 0 (letRange 2 10)) => kgv_decap_write_hash     -- encaps_key_hash into [2cb+32..2cb+64]
  branch 1 (branch 0 (letRange 3 13)) => kgv_decap_write_random   -- private_random into [2cb+64..2cb+96] + massert + terminate
  branch 1 (branch 0 (letRange 0 4)) => kgv_decap_lendispatch_body  -- whole body branch (4 calls)

-- ENCAP body (18 binds): split into 2 write phases (no intermediate `kgv_encap_body`).
#decompose kgv_encap_lendispatch kgv_encap_lendispatch.fold
  branch 1 (letRange 0 7) => kgv_encap_write_encoded_t          -- encoded_t[0..cb] into [0..cb]
  branch 1 (letRange 1 11) => kgv_encap_write_public_seed       -- public_seed into [cb..cb+32] + massert + terminate

/-- **Spec for `kgv_prefix`** — first 2 binds of `key_get_value`.

Result = `cb_encoded_vector` with `.val = 384·(k params)`.  No flags
in `key_get_value`, so just the size computation.

**Proof outline.**
Symmetric to `ksv_prefix.spec` for the first two binds: cast + sizeof. -/
@[step]
theorem kgv_prefix.spec
    {params : ParameterSet} (pk_mlkem_key : mlkem.key.Key)
    (h_wf : wfKey pk_mlkem_key params) :
    kgv_prefix pk_mlkem_key
      ⦃ (r : Usize) => r.val = 384 * (k params : ℕ) ⦄ := by
  unfold kgv_prefix
  have h_nrows : pk_mlkem_key.params.n_rows.val = (k params : ℕ) :=
    wfInternalParams.n_rows_val (wfKey.params_ok (self := pk_mlkem_key) h_wf)
  have h_nle4 : pk_mlkem_key.params.n_rows.val ≤ 4 := by
    rw [h_nrows]; exact k_le_4 params
  step
  have h_i_le4 : i.val ≤ 4 := by rw [i_post]; scalar_tac
  step
  rw [r_post, i_post]; scalar_tac

/-! ## Length-check helper specs

The three `kgv_*_lencheck` helpers each compute a `(observed, expected)`
length pair for one format arm.  No errors reachable. -/

/-- **`kgv_priv_lencheck`** — `(pb_dst.len, 64)`. -/
@[step]
theorem kgv_priv_lencheck.spec (pb_dst : Slice U8) :
    kgv_priv_lencheck pb_dst
      ⦃ r => r.1.val = pb_dst.length ∧ r.2.val = 64 ⦄ := by
  unfold kgv_priv_lencheck mlkem.SIZEOF_FORMAT_PRIVATE_SEED
  step
  refine ⟨by simp [Slice.length], ?_⟩
  scalar_tac

/-- **`kgv_decap_lencheck`** — `(pb_dst.len, 768·k + 96)`. -/
@[step]
theorem kgv_decap_lencheck.spec
    {params : ParameterSet} (pk_mlkem_key : mlkem.key.Key) (pb_dst : Slice U8)
    (h_wf : wfKey pk_mlkem_key params) :
    kgv_decap_lencheck pk_mlkem_key pb_dst
      ⦃ (r : Usize × Usize) =>
          r.1.val = pb_dst.length ∧ r.2.val = 768 * (k params : ℕ) + 96 ⦄ := by
  unfold kgv_decap_lencheck
  have h_nrows : pk_mlkem_key.params.n_rows.val = (k params : ℕ) :=
    wfInternalParams.n_rows_val (wfKey.params_ok (self := pk_mlkem_key) h_wf)
  have h_nle4 : pk_mlkem_key.params.n_rows.val ≤ 4 := by
    rw [h_nrows]; exact k_le_4 params
  step
  have h_cast_le4 : r.val ≤ 4 := by rw [r_post]; scalar_tac
  step
  refine ⟨by simp [Slice.length], ?_⟩
  rw [i3_post, r_post]; scalar_tac

/-- **`kgv_encap_lencheck`** — `(pb_dst.len, 384·k + 32)`. -/
@[step]
theorem kgv_encap_lencheck.spec
    {params : ParameterSet} (pk_mlkem_key : mlkem.key.Key) (pb_dst : Slice U8)
    (h_wf : wfKey pk_mlkem_key params) :
    kgv_encap_lencheck pk_mlkem_key pb_dst
      ⦃ (r : Usize × Usize) =>
          r.1.val = pb_dst.length ∧ r.2.val = 384 * (k params : ℕ) + 32 ⦄ := by
  unfold kgv_encap_lencheck
  have h_nrows : pk_mlkem_key.params.n_rows.val = (k params : ℕ) :=
    wfInternalParams.n_rows_val (wfKey.params_ok (self := pk_mlkem_key) h_wf)
  have h_nle4 : pk_mlkem_key.params.n_rows.val ≤ 4 := by
    rw [h_nrows]; exact k_le_4 params
  step
  have h_cast_le4 : r.val ≤ 4 := by rw [r_post]; scalar_tac
  step
  refine ⟨by simp [Slice.length], ?_⟩
  rw [i3_post, r_post]; scalar_tac

/-! ## Leaf-helper `@[step]` specs

Each helper from the cascade above gets a `@[step]` spec carrying its
full FC content (per `aeneas-postconditions`: no `True`-post stubs,
strong byte-level equalities tying the helper's output to spec-level
quantities derived from the Key fields).

These specs are placed BEFORE the two top specs they feed into, so the
top-spec `step*` (after `rw [.fold]` chaining) can dispatch to them. -/

/-- Window-propagation helper.

Two slices that agree pointwise on a window `[off, off+n)` have equal
`toSpecWindow`s on that window.  Used in the lendispatch composer proofs
to propagate per-byte frame equalities through `toSpecWindow`. -/
private theorem toSpecWindow_eq_of_pointwise
    {s_dst s_src : Slice U8} {off n : ℕ}
    (h_dst : off + n ≤ s_dst.length) (h_src : off + n ≤ s_src.length)
    (h_pw : ∀ (i : ℕ) (h_i : i < n),
      s_dst.val[off + i]'(by grind) =
      s_src.val[off + i]'(by grind)) :
    s_dst.toSpecWindow off n h_dst = s_src.toSpecWindow off n h_src := by
  unfold Slice.toSpecWindow sliceWindowToSpecBytes
  apply Vector.ext
  intro i hi
  simp only [Vector.getElem_ofFn]
  rw [h_pw i hi]

private theorem mlkem.key.Key.s_std.spec
    (self : mlkem.key.Key) (p : ParameterSet) (h_wf : wfKey self p) :
    mlkem.key.Key.s self
      ⦃ (s : Slice (PolyElement)) =>
        ∃ (h_len : s.length = (k p : ℕ)),
        (∀ i (_ : i < s.length), wfPoly s.val[i]) ∧
        (∀ (i : Fin (k p)),
          toPoly (s.val[(i : ℕ)]'(by
            have hi := i.isLt
            grind)) = (keyS_std self p)[i]) ⦄ := by
  unfold mlkem.key.Key.s
  have hwf := h_wf
  obtain ⟨params_ok, hn_rows, data_wf⟩ := h_wf
  have hk := k_le_4 p
  have hk2 := k_sq_plus_2k_le_24 p
  have hdlen : self.data.val.length = 24 := self.data.property
  step with mlkem.key.Key.matrix_len.spec self p hwf
  step
  step
  step
  step
  · show (i2 : ℕ) ≤ self.data.to_slice.length
    have hl : self.data.to_slice.length = 24 := by simp [Std.Array.to_slice, Slice.length]
    rw [hl, i2_post, i1_post, m_len_post]; unfold matrixLen; scalar_tac
  · refine ⟨?_, ?_, ?_⟩
    · show _ = (k p : ℕ); scalar_tac
    · intro j hj
      have hsval : s.val = self.data.val.slice (Bridges.sOffset p) (Bridges.dataEnd p) := by
        simp_all [Bridges.matrixLen, Bridges.sOffset, Bridges.dataEnd]
      have hslen : s.length = (k p : ℕ) := by show _ = (k p : ℕ); scalar_tac
      have hbound : Bridges.sOffset p + j < Bridges.dataEnd p := by
        rw [hslen] at hj
        unfold Bridges.sOffset Bridges.matrixLen Bridges.dataEnd
        grind
      have hbound2 : Bridges.sOffset p + j < self.data.val.length := by
        rw [hdlen]
        grind
      have hidx : s.val[j]'hj = self.data.val[Bridges.sOffset p + j]'hbound2 := by
        have e := List.getElem_slice (Bridges.sOffset p) (Bridges.dataEnd p) j self.data.val
                    ⟨by rw [hdlen]; unfold Bridges.dataEnd Bridges.matrixLen; grind, hbound⟩
        have hj' : j < (self.data.val.slice (Bridges.sOffset p) (Bridges.dataEnd p)).length := by
          rw [← hsval]; exact hj
        have : s.val[j]'hj = (self.data.val.slice (Bridges.sOffset p) (Bridges.dataEnd p))[j]'hj' := by
          simp [hsval]
        rw [this]; exact e
      rw [hidx]
      apply data_wf
      exact hbound
    · intro i
      have hi := i.isLt
      unfold keyS_std
      have hsval : s.val = self.data.val.slice (Bridges.sOffset p) (Bridges.dataEnd p) := by
        simp_all [Bridges.matrixLen, Bridges.sOffset, Bridges.dataEnd]
      have hslen : s.length = (k p : ℕ) := by show _ = (k p : ℕ); scalar_tac
      have hbound : Bridges.sOffset p + (i : ℕ) < Bridges.dataEnd p := by
        unfold Bridges.sOffset Bridges.matrixLen Bridges.dataEnd
        grind
      have hbound2 : Bridges.sOffset p + (i : ℕ) < self.data.val.length := by
        rw [hdlen]
        grind
      have hjs : (i : ℕ) < s.val.length := by
        show (i : ℕ) < s.length
        rw [hslen]
        exact hi
      have hidx : s.val[(i : ℕ)]'hjs =
          self.data.val[Bridges.sOffset p + (i : ℕ)]'hbound2 := by
        have e := List.getElem_slice (Bridges.sOffset p) (Bridges.dataEnd p) (i : ℕ) self.data.val
                    ⟨by rw [hdlen]; unfold Bridges.dataEnd Bridges.matrixLen; grind, hbound⟩
        have hj' : (i : ℕ) < (self.data.val.slice (Bridges.sOffset p) (Bridges.dataEnd p)).length := by
          rw [← hsval]; exact hjs
        have : s.val[(i : ℕ)]'hjs =
            (self.data.val.slice (Bridges.sOffset p) (Bridges.dataEnd p))[(i : ℕ)]'hj' := by
          simp [hsval]
        rw [this]; exact e
      rw [hidx]
      simp

private theorem keySEncoded_eq_vector_compress_output
    (params : ParameterSet) (pk_mlkem_key : mlkem.key.Key)
    {s : Slice PolyElement} {s2 : Slice U8}
    (h_s_len : s.length = (k params : ℕ))
    (h_s_std : ∀ (i : Fin (k params)),
      toPoly (s.val[(i : ℕ)]'(by
        have hi := i.isLt
        grind)) = (keyS_std pk_mlkem_key params)[i])
    (h_s2_len : s2.length = 384 * (k params : ℕ))
    (s2_post :
      ∀ (i : ℕ) (h_i : i < s.length),
        ∃ (h : (i + 1) * (32 * 12) ≤ s2.length),
          sliceWindowToSpecBytes s2 (i * (32 * ↑(12#u32 : U32)))
              (32 * ↑(12#u32 : U32)) (Nat.add_one_mul _ _ ▸ h) =
            compressEncodePoly (↑(12#u32 : U32)) (toPoly (↑s)[i])
              ⟨by decide, by decide⟩) :
    keySEncoded pk_mlkem_key params =
      s2.toSpecWindow 0 (384 * (k params : ℕ))
        (by rw [h_s2_len]; grind) := by
  apply Vector.ext
  intro i hi
  set pi := i / (32 * 12) with hpi_def
  set bi := i % (32 * 12) with hbi_def
  have h_kp_eq : 384 * (k params : ℕ) = (k params : ℕ) * (32 * 12) := by ring
  have h_bi_lt : bi < 32 * 12 := by
    rw [hbi_def]
    exact Nat.mod_lt _ (by decide)
  have h_idecomp : pi * (32 * 12) + bi = i := by
    rw [hpi_def, hbi_def]
    have h := Nat.div_add_mod i (32 * 12)
    rw [Nat.mul_comm] at h
    exact h
  have h_i_lt_kt : i < (k params : ℕ) * (32 * 12) := by
    rw [← h_kp_eq]
    exact hi
  have h_pi_lt_k : pi < (k params : ℕ) :=
    (Nat.div_lt_iff_lt_mul (by decide)).mpr (by simpa [hpi_def] using h_i_lt_kt)
  have h_pi_lt_s : pi < s.length := by
    rw [h_s_len]
    exact h_pi_lt_k
  have h_i_lt_s2 : i < s2.length := by
    rw [h_s2_len]
    exact hi
  have h_d12 : (1 : ℕ) ≤ 12 ∧ (12 : ℕ) ≤ 12 := by decide
  obtain ⟨h_bnd_s2, h_eq_s2⟩ := s2_post pi h_pi_lt_s
  set v := keyS_std pk_mlkem_key params with hv_def
  have h_bnd_pV : 32 * 12 * pi + 32 * 12 ≤ 32 * 12 * (k params : ℕ) := by
    have h1 := Nat.mul_le_mul_left (32 * 12) (Nat.succ_le_of_lt h_pi_lt_k)
    have h2 : 32 * 12 * (pi + 1) = 32 * 12 * pi + 32 * 12 := by ring
    grind
  have h_v_pi :
      v[pi]'h_pi_lt_k = toPoly ((↑s : List PolyElement)[pi]'h_pi_lt_s) := by
    simpa [hv_def] using (h_s_std ⟨pi, h_pi_lt_k⟩).symm
  have h_rhs_bridge :
      (MLKEM.PolyVector.ByteEncode 12 v h_d12)[i]'h_i_lt_kt =
      (MLKEM.ByteEncode 12 (v[pi]'h_pi_lt_k) h_d12)[bi]'h_bi_lt := by
    have h_slice_eq :=
      polyVector_slice_byteEncode_eq (n := k params) 12 h_d12 v pi h_pi_lt_k h_bnd_pV
    have h_at_bi :
        (slice (Vector.cast (polyVector_byteEncode_size_cast 12)
                (MLKEM.PolyVector.ByteEncode 12 v h_d12))
              (32 * 12 * pi) (32 * 12) h_bnd_pV)[bi]'h_bi_lt =
        (MLKEM.ByteEncode 12 (v[pi]'h_pi_lt_k) h_d12)[bi]'h_bi_lt :=
      congrArg (·[bi]'h_bi_lt) h_slice_eq
    simp only [slice, Vector.getElem_ofFn, Vector.getElem_cast] at h_at_bi
    have hi_eq : 32 * 12 * pi + bi = i := by
      rw [← h_idecomp]
      ring
    have h_idx_congr : ∀ (j : ℕ) (hj : j < (k params : ℕ) * (32 * 12)), j = i →
        (MLKEM.PolyVector.ByteEncode 12 v h_d12)[j]'hj =
        (MLKEM.PolyVector.ByteEncode 12 v h_d12)[i]'h_i_lt_kt := by
      intro j hj h_eq
      subst h_eq
      rfl
    rw [← h_idx_congr (32 * 12 * pi + bi) (by rw [hi_eq]; exact h_i_lt_kt) hi_eq]
    exact h_at_bi
  have h_lhs_bridge :
      ((↑s2 : List U8)[i]'h_i_lt_s2 : U8).bv =
      (MLKEM.ByteEncode 12 (toPoly ((↑s : List PolyElement)[pi]'h_pi_lt_s)) h_d12)[bi]'h_bi_lt := by
    have h_collapse :
        compressEncodePoly (↑(12#u32 : U32))
          (toPoly ((↑s : List PolyElement)[pi]'h_pi_lt_s)) (by simp) =
        MLKEM.ByteEncode 12
          (toPoly ((↑s : List PolyElement)[pi]'h_pi_lt_s)) h_d12 := by
      unfold compressEncodePoly
      simp
      rfl
    have h_eq_s2' := h_eq_s2.trans h_collapse
    have h_at_bi := congrArg (·[bi]'h_bi_lt) h_eq_s2'
    simp only [sliceWindowToSpecBytes, Vector.getElem_ofFn] at h_at_bi
    have h_idx_eq : (↑s2 : List U8)[pi * (32 * 12) + bi]'(by
          show pi * (32 * 12) + bi < (↑s2 : List U8).length
          rw [show (↑s2 : List U8).length = s2.length from rfl]
          rw [h_s2_len]
          rw [h_idecomp]
          exact hi) =
        (↑s2 : List U8)[i]'h_i_lt_s2 := by
      have h_eq : pi * (32 * 12) + bi = i := h_idecomp
      have h_aux : ∀ (j : ℕ) (hj : j < (↑s2 : List U8).length), j = i →
          (↑s2 : List U8)[j]'hj = (↑s2 : List U8)[i]'h_i_lt_s2 := by
        intro j hj heq
        subst heq
        rfl
      exact h_aux _ _ h_eq
    rw [← h_idx_eq]
    exact h_at_bi
  unfold keySEncoded Slice.toSpecWindow sliceWindowToSpecBytes
  simp only [Vector.getElem_cast, Vector.getElem_ofFn]
  rw [show (MLKEM.PolyVector.ByteEncode 12 (keyS_std pk_mlkem_key params)
          (by decide))[i] =
        (MLKEM.PolyVector.ByteEncode 12 v h_d12)[i]'h_i_lt_kt by
      simp [hv_def]]
  rw [h_rhs_bridge, h_v_pi]
  symm
  simpa using h_lhs_bridge


/-! ### `kgv_priv_write_seed` — write `private_seed` to `pb_dst[0..32]`

10-bind first phase of the `PrivateSeed` arm body (inside the
`has_private_seed = true` branch). Opens `pb_dst[0..32]` mutable view,
copies the 32-byte `private_seed` array into it, returns `pb_curr = 32`
together with the patched `pb_dst1`. No errors reachable. -/
@[step]
theorem kgv_priv_write_seed.spec
    (pk_mlkem_key : mlkem.key.Key)
    (pb_dst : Slice U8)
    (h_pas_len : pb_dst.length = 64) :
    kgv_priv_write_seed pk_mlkem_key pb_dst
      ⦃ (r : Usize × Slice U8) =>
          r.1.val = 32 ∧
          ∃ (h_len : r.2.length = pb_dst.length),
            pk_mlkem_key.private_seed.toSpec = r.2.toSpecWindow 0 32 (by simp [h_len, h_pas_len]) ⦄ := by
  unfold kgv_priv_write_seed
  step*
  refine ⟨?_, ?_, ?_⟩ <;>
    simp_all [arrayToSpecBytes, sliceWindowToSpecBytes];
    try scalar_tac
  apply Vector.ext; intro i hi; simp_lists; symm; exact Vector.getElem_ofFn hi

/-! ### `kgv_priv_write_random` — write `private_random` to `pb_dst1[32..64]`

13-bind tail phase: takes the offset `pb_curr = 32` and patched buffer
from `kgv_priv_write_seed`; copies `private_random` to
`pb_dst1[pb_curr..pb_curr+32]`; the trailing `massert` requires
`pb_dst1.length = 64`. Preserves `pb_dst1[0..pb_curr]`. -/
@[step]
theorem kgv_priv_write_random.spec
    (pk_mlkem_key : mlkem.key.Key)
    (pb_curr : Usize)
    (pb_dst1 : Slice U8)
    (h_pb_curr : pb_curr.val = 32)
    (h_pas_len : pb_dst1.length = 64)
    (h_seed : pk_mlkem_key.private_seed.toSpec = pb_dst1.toSpecWindow 0 32 (by simp [h_pas_len])) :
    kgv_priv_write_random pk_mlkem_key pb_curr pb_dst1
      ⦃ err pb_dst' =>
          pb_dst'.length = pb_dst1.length ∧
          match err with
          | Error.NoError =>
              ∃ (h_len : pb_dst'.length = 64),
                pk_mlkem_key.private_seed.toSpec = pb_dst'.toSpecWindow 0 32 (by simp [h_len]) ∧
                pk_mlkem_key.private_random.toSpec = pb_dst'.toSpecWindow 32 32 (by simp [h_len])
          | _ => False ⦄ := by
  unfold kgv_priv_write_random
  step*
  case hlen => scalar_tac
  refine ⟨?_, ?_, ?_, ?_⟩ <;>
    simp_all [arrayToSpecBytes, sliceWindowToSpecBytes] <;>
    try scalar_tac
  · apply Vector.ext; intro i hi; simp_lists
  · apply Vector.ext; intro i hi; simp_lists; symm; exact Vector.getElem_ofFn hi

/-! ### `kgv_decap_write_s_t` — write `ByteEncode₁₂(s) ‖ encoded_t[0..cb]`

10-bind first phase of `kgv_decap_body`.  Writes (i) `compressEncodePoly 12`
of each row of `pk.s` into `pb_dst[i*384..(i+1)*384]` for i < k (via
`vector_compress_and_encode`), then (ii) `encoded_t[0..cb]` into
`pb_dst[cb..2cb]`.  Returns updated offset `i4 = 2cb`.

Only the `encoded_t` window appears in the top-spec FC (the ByteEncode(s)
prefix is the residual round-trip captured indirectly via the
`encaps_key_hash` SHA3-256 conjunct). -/
@[step]
theorem kgv_decap_write_s_t.spec
    {params : ParameterSet}
    (pk_mlkem_key : mlkem.key.Key)
    (pb_dst : Slice U8)
    (cb_encoded_vector : Usize)
    (h_wf : wfKey pk_mlkem_key params)
    (h_cb : cb_encoded_vector.val = 384 * (k params : ℕ))
    (h_pas_len : pb_dst.length = 768 * (k params : ℕ) + 96) :
    kgv_decap_write_s_t pk_mlkem_key pb_dst cb_encoded_vector
      ⦃ result =>
          let i4 := result.1
          let pb_dst2 := result.2
          i4.val = 768 * (k params : ℕ) ∧
          (∃ (h_len : pb_dst2.length = 768 * (k params : ℕ) + 96),
            keySEncoded pk_mlkem_key params =
              pb_dst2.toSpecWindow 0 (384 * (k params : ℕ))
                (by have := k_le_4 params; simp [h_len]; grind) ∧
            keyEncodedTPrefix pk_mlkem_key params =
              pb_dst2.toSpecWindow (384 * (k params : ℕ)) (384 * (k params : ℕ))
                (by have := k_le_4 params; simp [h_len]; grind)) ⦄ := by
  unfold kgv_decap_write_s_t
  step with mlkem.key.Key.s_std.spec pk_mlkem_key params h_wf
  step*
  case h_wf => exact s_post2
  case h_nrows => grind
  case h1 => grind
  case hlen => grind
  refine ⟨?_, ?_, ?_, ?_⟩
  · grind
  · grind
  · have h_s2_len : s2.length = 384 * (k params : ℕ) := by
      rw [s2_post1, s1_post2, h_cb]
      grind
    have h_key_s :=
      keySEncoded_eq_vector_compress_output params pk_mlkem_key
        s_post1 s_post3 h_s2_len s2_post2
    rw [h_key_s]
    clear h_key_s
    refine (toSpecWindow_eq_of_pointwise (by have := k_le_4 params; grind)
      (by rw [h_s2_len]; grind) ?_).symm
    intro i hi
    simp [s3_post3, s1_post3]
    have h_pref := List.getElem_setSlice!_prefix
        ((↑pb_dst : List U8).setSlice! 0 (↑s2 : List U8)) (↑s5 : List U8) (↑pb_curr) i
        ⟨by rw [pb_curr_post, h_cb]; grind,
         by rw [List.length_setSlice!]; show i < pb_dst.length; rw [h_pas_len]; grind⟩
    have h_mid := List.getElem_setSlice!_middle (↑pb_dst : List U8) (↑s2 : List U8) 0 i
        ⟨by grind,
         by rw [show (↑s2 : List U8).length = s2.length from rfl, h_s2_len]; grind,
         by show i < pb_dst.length; rw [h_pas_len]; grind⟩
    rw [h_pref, h_mid]
    simp
  · unfold keyEncodedTPrefix Slice.toSpecWindow sliceWindowToSpecBytes
    apply Vector.ext; intro i hi
    simp [s3_post3, s1_post3]
    simp_lists
    simp only [s5_post2, s4_post1]
    simp_lists
    agrind

/-! ### `kgv_decap_write_rho` — write `public_seed` (ρ) at offset `i4 = 2cb`

10-bind second phase.  Opens `pb_dst2[i4..i4+32]` and copies `public_seed`.
Returns updated offset `pb_curr1 = i4 + 32 = 2cb + 32`.

Frame: bytes `[0..i4)` of `pb_dst3` equal bytes `[0..i4)` of `pb_dst2` —
carries phase 1's `encoded_t` FC forward through composition. -/
@[step]
theorem kgv_decap_write_rho.spec
    {params : ParameterSet}
    (pk_mlkem_key : mlkem.key.Key)
    (i4 : Usize) (pb_dst2 : Slice U8)
    (h_wf : wfKey pk_mlkem_key params)
    (h_i4 : i4.val = 768 * (k params : ℕ))
    (h_pas_len : pb_dst2.length = 768 * (k params : ℕ) + 96) :
    kgv_decap_write_rho pk_mlkem_key i4 pb_dst2
      ⦃ result =>
          let pb_curr1 := result.1
          let pb_dst3 := result.2
          pb_curr1.val = 768 * (k params : ℕ) + 32 ∧
          (∃ (h_len : pb_dst3.length = 768 * (k params : ℕ) + 96),
            pk_mlkem_key.public_seed.toSpec = pb_dst3.toSpecWindow (768 * (k params : ℕ)) 32 (by simp [h_len]) ∧
            (∀ (i : Nat) (h_i : i < 768 * (k params : ℕ)),
              (pb_dst3.val[i]'(by
                  have := k_le_4 params; simp [h_len]; grind)) =
              (pb_dst2.val[i]'(by
                  have := k_le_4 params; simp [h_pas_len]; grind)))) ⦄ := by
  unfold kgv_decap_write_rho
  step*
  case hlen => scalar_tac
  refine ⟨?_, ?_, ?_, ?_⟩ <;>
    simp_all [arrayToSpecBytes, sliceWindowToSpecBytes] <;>
    try scalar_tac
  · apply Vector.ext; intro i hi; simp_lists; symm; exact Vector.getElem_ofFn hi
  · intro i hi; simp_lists

/-! ### `kgv_decap_write_hash` — write `encaps_key_hash` at offset `pb_curr1 = 2cb + 32`

10-bind third phase.  Opens `pb_dst3[pb_curr1..pb_curr1+32]` and copies
`encaps_key_hash`.  Returns updated offset `pb_curr2 = pb_curr1 + 32 = 2cb + 64`.

Frame: bytes `[0..pb_curr1)` preserved (carries phases 1 & 2 forward). -/
@[step]
theorem kgv_decap_write_hash.spec
    {params : ParameterSet}
    (pk_mlkem_key : mlkem.key.Key)
    (pb_curr1 : Usize) (pb_dst3 : Slice U8)
    (h_wf : wfKey pk_mlkem_key params)
    (h_pb_curr1 : pb_curr1.val = 768 * (k params : ℕ) + 32)
    (h_pas_len : pb_dst3.length = 768 * (k params : ℕ) + 96) :
    kgv_decap_write_hash pk_mlkem_key pb_curr1 pb_dst3
      ⦃ result =>
          let pb_curr2 := result.1
          let pb_dst4 := result.2
          pb_curr2.val = 768 * (k params : ℕ) + 64 ∧
          (∃ (h_len : pb_dst4.length = 768 * (k params : ℕ) + 96),
            pk_mlkem_key.encaps_key_hash.toSpec = pb_dst4.toSpecWindow (768 * (k params : ℕ) + 32) 32 (by simp [h_len]) ∧
            (∀ (i : Nat) (h_i : i < 768 * (k params : ℕ) + 32),
              (pb_dst4.val[i]'(by
                  have := k_le_4 params; simp [h_len]; grind)) =
              (pb_dst3.val[i]'(by
                  have := k_le_4 params; simp [h_pas_len]; grind)))) ⦄ := by
  unfold kgv_decap_write_hash
  step*
  case hlen => scalar_tac
  refine ⟨?_, ?_, ?_, ?_⟩ <;>
    simp_all [arrayToSpecBytes, sliceWindowToSpecBytes] <;>
    try scalar_tac
  · apply Vector.ext; intro i hi; simp_lists; symm; exact Vector.getElem_ofFn hi
  · intro i hi; simp_lists

/-! ### `kgv_decap_write_random` — write `private_random` at offset `pb_curr2 = 2cb + 64`

13-bind terminal phase.  Opens `pb_dst4[pb_curr2..pb_curr2+32]`, copies
`private_random`, runs the trailing `massert(pb_curr3 = len pb_dst5)`
(true since `pb_curr2 + 32 = 2cb + 96 = pb_dst.length`), returns
`(NoError, pb_dst5)`. -/
@[step]
theorem kgv_decap_write_random.spec
    {params : ParameterSet}
    (pk_mlkem_key : mlkem.key.Key)
    (pb_curr2 : Usize) (pb_dst4 : Slice U8)
    (h_wf : wfKey pk_mlkem_key params)
    (h_pb_curr2 : pb_curr2.val = 768 * (k params : ℕ) + 64)
    (h_pas_len : pb_dst4.length = 768 * (k params : ℕ) + 96) :
    kgv_decap_write_random pk_mlkem_key pb_curr2 pb_dst4
      ⦃ err pb_dst5 =>
          /- Length preservation holds across every reachable arm. -/
          pb_dst5.length = pb_dst4.length ∧
          match err with
          | Error.NoError =>
              ∃ (h_len : pb_dst5.length = 768 * (k params : ℕ) + 96),
                pk_mlkem_key.private_random.toSpec = pb_dst5.toSpecWindow (768 * (k params : ℕ) + 64) 32 (by simp [h_len]) ∧
                (∀ (i : Nat) (h_i : i < 768 * (k params : ℕ) + 64),
                  (pb_dst5.val[i]'(by
                      have := k_le_4 params; simp [h_len]; grind)) =
                  (pb_dst4.val[i]'(by
                      have := k_le_4 params; simp [h_pas_len]; grind)))
          /- Terminal phase succeeds whenever the length precondition holds. -/
          | _ => False ⦄ := by
  unfold kgv_decap_write_random
  step*
  case hlen => scalar_tac
  refine ⟨?_, ?_, ?_, ?_⟩ <;>
    simp_all [arrayToSpecBytes, sliceWindowToSpecBytes] <;>
    try scalar_tac
  · apply Vector.ext; intro i hi; simp_lists; symm; exact Vector.getElem_ofFn hi
  · intro i hi; simp_lists

/-! ### `kgv_encap_write_encoded_t` — write `encoded_t[0..cb]` to `pb_dst[0..cb]`

7-bind first phase of the `EncapsulationKey` arm body.  Opens
`pb_dst[0..cb_encoded_vector]` mutable view, copies the
`encoded_t[0..cb_encoded_vector]` prefix into it; returns the offset
`i4 = cb_encoded_vector` together with the patched buffer `pb_dst1`
and the length `i5 = pb_dst1.length` (passed unchanged to the next
phase). -/
@[step]
theorem kgv_encap_write_encoded_t.spec
    {params : ParameterSet}
    (pk_mlkem_key : mlkem.key.Key)
    (pb_dst : Slice U8)
    (cb_encoded_vector : Usize)
    (h_wf : wfKey pk_mlkem_key params)
    (h_cb : cb_encoded_vector.val = 384 * (k params : ℕ))
    (h_pas_len : pb_dst.length = 384 * (k params : ℕ) + 32) :
    kgv_encap_write_encoded_t pk_mlkem_key pb_dst cb_encoded_vector
      ⦃ (r : Usize × Slice U8 × Usize) =>
          r.1.val = 384 * (k params : ℕ) ∧
          r.2.2.val = 32 ∧
          ∃ (h_len : r.2.1.length = pb_dst.length),
            keyEncodedTPrefix pk_mlkem_key params = r.2.1.toSpecWindow 0 (384 * (k params : ℕ))
              (by simp [h_len, h_pas_len]) ⦄ := by
  unfold kgv_encap_write_encoded_t
  step*
  case h1 => have := k_le_4 params; scalar_tac
  refine ⟨?_, ?_, ?_, ?_⟩
  · scalar_tac
  · simp [s3_post]
  · simp [s_post3]
  · unfold keyEncodedTPrefix Slice.toSpecWindow sliceWindowToSpecBytes
    apply Vector.ext; intro i hi
    simp [s_post3, s2_post2, s1_post1]
    simp_lists

/-! ### `kgv_encap_write_public_seed` — write `public_seed` to `pb_dst1[cb..cb+32]`

11-bind tail phase: takes the offset `i4 = cb_encoded_vector` and the
patched buffer `pb_dst1` from `kgv_encap_write_encoded_t`; copies the
32-byte `public_seed` into `pb_dst1[i4..i4+32]`. Trailing `massert`
requires `pb_dst1.length = i4 + 32 = cb_encoded_vector + 32`.
Preserves `pb_dst1[0..i4]`. -/
@[step]
theorem kgv_encap_write_public_seed.spec
    {params : ParameterSet}
    (pk_mlkem_key : mlkem.key.Key)
    (i4 : Usize)
    (pb_dst1 : Slice U8)
    (i5 : Usize)
    (h_wf : wfKey pk_mlkem_key params)
    (h_i4 : i4.val = 384 * (k params : ℕ))
    (h_i5 : i5.val = 32)
    (h_pas_len : pb_dst1.length = 384 * (k params : ℕ) + 32)
    (h_encoded_t : keyEncodedTPrefix pk_mlkem_key params =
      pb_dst1.toSpecWindow 0 (384 * (k params : ℕ)) (by have := k_le_4 params; simp [h_pas_len])) :
    kgv_encap_write_public_seed pk_mlkem_key i4 pb_dst1 i5
      ⦃ err pb_dst' =>
          pb_dst'.length = pb_dst1.length ∧
          match err with
          | Error.NoError =>
              ∃ (h_len : pb_dst'.length = 384 * (k params : ℕ) + 32),
                keyEncodedTPrefix pk_mlkem_key params = pb_dst'.toSpecWindow 0 (384 * (k params : ℕ))
                  (by have := k_le_4 params; simp [h_len]) ∧
                pk_mlkem_key.public_seed.toSpec = pb_dst'.toSpecWindow (384 * (k params : ℕ)) 32 (by simp [h_len])
          | _ => False ⦄ := by
  unfold kgv_encap_write_public_seed
  step*
  case hlen => scalar_tac
  refine ⟨?_, ?_, ?_, ?_⟩ <;>
    simp_all [arrayToSpecBytes, sliceWindowToSpecBytes] <;>
    try scalar_tac
  · -- encoded_t window preserved via frame
    apply Vector.ext; intro i hi; simp_lists
  · -- public_seed window
    apply Vector.ext; intro i hi; simp_lists; symm; exact Vector.getElem_ofFn hi

/-! ## Lendispatch composer specs

The three `kgv_*_lendispatch` helpers chain the per-arm length check
(via `bne` on the two `lencheck` outputs) with the body work.  They
absorb the role formerly played by the obsolete `kgv_priv`, `kgv_decap`,
`kgv_encap` intermediates: the format-match merger turned each format
arm into `lencheck >>= lendispatch`, so the lendispatch *is* the composer.

Postconditions enumerate reachable errors per arm and pull length
preservation outside the `match`. -/

/-- **Spec for `kgv_priv_lendispatch`** — PrivateSeed length check +
`has_private_seed` dispatch + write-seed/write-random body. -/
@[step]
theorem kgv_priv_lendispatch.spec
    (pk_mlkem_key : mlkem.key.Key)
    (pb_dst : Slice U8)
    (i1 i2 : Usize)
    (h_i1 : i1.val = pb_dst.length)
    (h_i2 : i2.val = 64) :
    kgv_priv_lendispatch pk_mlkem_key pb_dst i1 i2
      ⦃ err pb_dst' =>
          pb_dst'.length = pb_dst.length ∧
          match err with
          | Error.NoError =>
              ∃ (h_len : pb_dst'.length = 64),
                pk_mlkem_key.has_private_seed = true ∧
                pk_mlkem_key.private_seed.toSpec = pb_dst'.toSpecWindow 0 32 (by simp [h_len]) ∧
                pk_mlkem_key.private_random.toSpec = pb_dst'.toSpecWindow 32 32 (by simp [h_len])
          | Error.WrongKeySize => pb_dst.length ≠ 64
          | Error.IncompatibleFormat =>
              pk_mlkem_key.has_private_seed = false
          | _ => False ⦄ := by
  rw [kgv_priv_lendispatch.fold]
  split
  · rename_i h_ne
    simp only [WP.spec_ok]
    refine ⟨rfl, ?_⟩
    simp only [bne_iff_ne, ne_eq] at h_ne
    intro hcontra
    apply h_ne
    apply UScalar.eq_of_val_eq
    rw [h_i1, h_i2]; exact hcontra
  · rename_i h_eq
    simp only [bne_iff_ne, ne_eq, not_not] at h_eq
    have h_pas_len : pb_dst.length = 64 := by
      rw [← h_i1, ← h_i2]; exact congrArg UScalar.val h_eq
    split
    · rename_i h_seed
      step
      step
      refine ⟨err_post1.trans pb_curr_post2, ?_⟩
      match err, err_post2 with
      | .NoError, ⟨h_len, h1, h2⟩ => exact ⟨h_len, h_seed, h1, h2⟩
      | .Unused, h | .WrongKeySize, h | .WrongBlockSize, h | .WrongDataSize, h
      | .WrongNonceSize, h | .WrongTagSize, h | .WrongIterationCount, h
      | .AuthenticationFailure, h | .ExternalFailure, h | .FipsFailure, h
      | .HardwareFailure, h | .NotImplemented, h | .InvalidBlob, h
      | .BufferTooSmall, h | .MemoryAllocationFailure, h
      | .SignatureVerificationFailure, h | .IncompatibleFormat, h
      | .ValueTooLarge, h | .SessionReplayFailure, h | .InvalidArgument, h
      | .HbsNoOtsKeysLeft, h | .HbsPublicRootMismatch, h => exact h.elim
    · rename_i h_no_seed
      simp only [WP.spec_ok]
      refine ⟨rfl, ?_⟩
      simp only [Bool.not_eq_true] at h_no_seed
      exact h_no_seed

/-- **Spec for `kgv_decap_lendispatch_body`** — the 4-phase write body
of the DecapsulationKey arm, extracted by `#decompose` from
`kgv_decap_lendispatch`. Carries the heavy 4-step / 3-frame proof so
the outer composer remains short. -/
@[step]
theorem kgv_decap_lendispatch_body.spec
    {params : ParameterSet}
    (pk_mlkem_key : mlkem.key.Key)
    (pb_dst : Slice U8)
    (cb_encoded_vector : Usize)
    (h_wf : wfKey pk_mlkem_key params)
    (h_cb : cb_encoded_vector.val = 384 * (k params : ℕ))
    (h_pas_len : pb_dst.length = 768 * (k params : ℕ) + 96) :
    kgv_decap_lendispatch_body pk_mlkem_key pb_dst cb_encoded_vector
      ⦃ err pb_dst' =>
          pb_dst'.length = pb_dst.length ∧
          match err with
          | Error.NoError =>
              ∃ (h_len : pb_dst'.length = 768 * (k params : ℕ) + 96),
                keySEncoded pk_mlkem_key params = pb_dst'.toSpecWindow 0 (384 * (k params : ℕ))
                  (by have := k_le_4 params; simp [h_len]; grind) ∧
                keyEncodedTPrefix pk_mlkem_key params = pb_dst'.toSpecWindow (384 * (k params : ℕ)) (384 * (k params : ℕ))
                  (by have := k_le_4 params; simp [h_len]; grind) ∧
                pk_mlkem_key.public_seed.toSpec = pb_dst'.toSpecWindow (768 * (k params : ℕ)) 32 (by simp [h_len]) ∧
                pk_mlkem_key.encaps_key_hash.toSpec = pb_dst'.toSpecWindow (768 * (k params : ℕ) + 32) 32 (by simp [h_len]) ∧
                pk_mlkem_key.private_random.toSpec = pb_dst'.toSpecWindow (768 * (k params : ℕ) + 64) 32 (by simp [h_len])
          | _ => False ⦄ := by
  unfold kgv_decap_lendispatch_body
  step  -- write_s_t
  step  -- write_rho
  step  -- write_hash
  step  -- write_random
  replace h_encoded_s_2 := i4_post3
  replace h_encoded_t_2 := i4_post4
  replace h_pub3 := pb_curr1_post3
  replace h_hash4 := pb_curr2_post3
  have h_k := k_le_4 params
  refine ⟨?_, ?_⟩
  · rw [err_post1]; grind
  · match err, err_post2 with
    | .NoError, ⟨h_len', h_rand', h_frame'⟩ =>
      refine ⟨h_len', ?_, ?_, ?_, ?_, h_rand'⟩
      · rw [h_encoded_s_2]
        refine (toSpecWindow_eq_of_pointwise (by grind) (by grind) ?_).symm
        grind
      · rw [h_encoded_t_2]
        refine (toSpecWindow_eq_of_pointwise (by grind) (by grind) ?_).symm
        grind
      · rw [h_pub3]
        refine (toSpecWindow_eq_of_pointwise (by grind) (by grind) ?_).symm
        grind
      · rw [h_hash4]
        refine (toSpecWindow_eq_of_pointwise (by grind) (by grind) ?_).symm
        grind
    | .Unused, h | .WrongKeySize, h | .WrongBlockSize, h | .WrongDataSize, h
    | .WrongNonceSize, h | .WrongTagSize, h | .WrongIterationCount, h
    | .AuthenticationFailure, h | .ExternalFailure, h | .FipsFailure, h
    | .HardwareFailure, h | .NotImplemented, h | .InvalidBlob, h
    | .BufferTooSmall, h | .MemoryAllocationFailure, h
    | .SignatureVerificationFailure, h | .IncompatibleFormat, h
    | .ValueTooLarge, h | .SessionReplayFailure, h | .InvalidArgument, h
    | .HbsNoOtsKeysLeft, h | .HbsPublicRootMismatch, h => exact h.elim

/-- **Spec for `kgv_decap_lendispatch`** — DecapsulationKey length check
+ `has_private_key` dispatch + 4-phase write body
(`ByteEncode₁₂(s) ‖ encoded_t ‖ ρ ‖ H(ek) ‖ private_random`). -/
@[step]
theorem kgv_decap_lendispatch.spec
    {params : ParameterSet}
    (pk_mlkem_key : mlkem.key.Key)
    (pb_dst : Slice U8)
    (cb_encoded_vector i1 i3 : Usize)
    (h_wf : wfKey pk_mlkem_key params)
    (h_cb : cb_encoded_vector.val = 384 * (k params : ℕ))
    (h_i1 : i1.val = pb_dst.length)
    (h_i3 : i3.val = 768 * (k params : ℕ) + 96) :
    kgv_decap_lendispatch pk_mlkem_key pb_dst cb_encoded_vector i1 i3
      ⦃ err pb_dst' =>
          pb_dst'.length = pb_dst.length ∧
          match err with
          | Error.NoError =>
              ∃ (h_len : pb_dst'.length = 768 * (k params : ℕ) + 96),
                pk_mlkem_key.has_private_key = true ∧
                keySEncoded pk_mlkem_key params = pb_dst'.toSpecWindow 0 (384 * (k params : ℕ))
                  (by have := k_le_4 params; simp [h_len]; grind) ∧
                keyEncodedTPrefix pk_mlkem_key params = pb_dst'.toSpecWindow (384 * (k params : ℕ)) (384 * (k params : ℕ))
                  (by have := k_le_4 params; simp [h_len]; grind) ∧
                pk_mlkem_key.public_seed.toSpec = pb_dst'.toSpecWindow (768 * (k params : ℕ)) 32 (by simp [h_len]) ∧
                pk_mlkem_key.encaps_key_hash.toSpec = pb_dst'.toSpecWindow (768 * (k params : ℕ) + 32) 32 (by simp [h_len]) ∧
                pk_mlkem_key.private_random.toSpec = pb_dst'.toSpecWindow (768 * (k params : ℕ) + 64) 32 (by simp [h_len])
          | Error.InvalidArgument =>
              /- Reachable two ways: (a) length mismatch (`i1 != i3`), or
                 (b) past length check but `has_private_key = false`. -/
              pb_dst.length ≠ 768 * (k params : ℕ) + 96 ∨
                pk_mlkem_key.has_private_key = false
          | _ => False ⦄ := by
  rw [kgv_decap_lendispatch.fold]
  split
  · rename_i h_ne
    simp only [WP.spec_ok]
    refine ⟨rfl, ?_⟩
    left
    simp only [bne_iff_ne, ne_eq] at h_ne
    intro hcontra
    apply h_ne
    apply UScalar.eq_of_val_eq
    rw [h_i1, h_i3]; exact hcontra
  · rename_i h_eq
    simp only [bne_iff_ne, ne_eq, not_not] at h_eq
    have h_pas_len : pb_dst.length = 768 * (k params : ℕ) + 96 := by
      rw [← h_i1, ← h_i3]; exact congrArg UScalar.val h_eq
    split
    · rename_i h_key
      step  -- body.spec: one call absorbs the 4 phases
      refine ⟨err_post1, ?_⟩
      agrind
    · rename_i h_no_key
      simp only [WP.spec_ok]
      refine ⟨rfl, ?_⟩
      right
      simp only [Bool.not_eq_true] at h_no_key
      exact h_no_key

/-- **Spec for `kgv_encap_lendispatch`** — EncapsulationKey length check
+ 2-phase write body (`encoded_t[0..cb] ‖ public_seed`). No
`has_private_*` guard. -/
@[step]
theorem kgv_encap_lendispatch.spec
    {params : ParameterSet}
    (pk_mlkem_key : mlkem.key.Key)
    (pb_dst : Slice U8)
    (cb_encoded_vector i1 i3 : Usize)
    (h_wf : wfKey pk_mlkem_key params)
    (h_cb : cb_encoded_vector.val = 384 * (k params : ℕ))
    (h_i1 : i1.val = pb_dst.length)
    (h_i3 : i3.val = 384 * (k params : ℕ) + 32) :
    kgv_encap_lendispatch pk_mlkem_key pb_dst cb_encoded_vector i1 i3
      ⦃ err pb_dst' =>
          pb_dst'.length = pb_dst.length ∧
          match err with
          | Error.NoError =>
              ∃ (h_len : pb_dst'.length = 384 * (k params : ℕ) + 32),
                keyEncodedTPrefix pk_mlkem_key params = pb_dst'.toSpecWindow 0 (384 * (k params : ℕ))
                  (by have := k_le_4 params; simp [h_len]) ∧
                pk_mlkem_key.public_seed.toSpec = pb_dst'.toSpecWindow (384 * (k params : ℕ)) 32 (by simp [h_len])
          | Error.InvalidArgument => pb_dst.length ≠ 384 * (k params : ℕ) + 32
          | _ => False ⦄ := by
  rw [kgv_encap_lendispatch.fold]
  split
  · rename_i h_ne
    simp only [WP.spec_ok]
    refine ⟨rfl, ?_⟩
    simp only [bne_iff_ne, ne_eq] at h_ne
    intro hcontra
    apply h_ne
    apply UScalar.eq_of_val_eq
    rw [h_i1, h_i3]; exact hcontra
  · rename_i h_eq
    simp only [bne_iff_ne, ne_eq, not_not] at h_eq
    have h_pas_len : pb_dst.length = 384 * (k params : ℕ) + 32 := by
      rw [← h_i1, ← h_i3]; exact congrArg UScalar.val h_eq
    step
    step
    grind

/-! ## `key_get_value`

Serialises `pk_mlkem_key` into `pb_dst` according to `format`. -/

/-- **Top spec for `key_get_value`**.

Postcondition: serializes `pk_mlkem_key` to a byte view determined by
`format`. On success, `pb_dst'.toSpec _ = pk_mlkem_key.toSpec format params`.

- `PrivateSeed`     → `private_seed ‖ private_random`              (64 bytes)
- `EncapsulationKey`→ `encapsulationKey = encoded_t ‖ ρ`           (384k+32)
- `DecapsulationKey`→ `decapsulationKey = ByteEncode₁₂(s) ‖ encapsulationKey ‖ H(ek) ‖ private_random` (768k+96)

**Error arms** (verified against `mlkem.rs:426-504`):
- `WrongKeySize`     — `PrivateSeed` only, length ≠ 64 (mlkem.rs:439).
- `InvalidArgument`  — `EncapsulationKey` or `DecapsulationKey`, length mismatch
  (mlkem.rs:457, 488). The `has_private_key = false` disjunct on
  `DecapsulationKey` (mlkem.rs:461) is vacuous under `wfKeyFormat`.
- `IncompatibleFormat` (mlkem.rs:443) is vacuous: `wfKeyFormat .PrivateSeed`
  implies `has_private_seed = true`.
- All other errors are unreachable. -/
@[step]
theorem mlkem.key_get_value.spec
    {params : ParameterSet}
    (pk_mlkem_key : mlkem.key.Key)
    (pb_dst : Slice U8)
    (format : mlkem.key.Format)
    (flags : U32)
    (h_wf : wfKeyFormat pk_mlkem_key format params) :
    mlkem.key_get_value pk_mlkem_key pb_dst format flags
      ⦃ err pb_dst' =>
          pb_dst'.length = pb_dst.length ∧
          match err with
          | Error.NoError =>
              ∃ (h_len : pb_dst'.length = format.length params),
                pk_mlkem_key.toSpec format params = pb_dst'.toSpec _ h_len
          | Error.WrongKeySize =>
              format = mlkem.key.Format.PrivateSeed ∧ pb_dst.length ≠ 64
          | Error.InvalidArgument =>
              (format = mlkem.key.Format.EncapsulationKey ∧
                 pb_dst.length ≠ 384 * (k params : ℕ) + 32) ∨
              (format = mlkem.key.Format.DecapsulationKey ∧
                 pb_dst.length ≠ 768 * (k params : ℕ) + 96)
          | _ => False ⦄ := by
  have h_wf_key : wfKey pk_mlkem_key params := by
    rcases format with _ | _ | _
    · exact wfEncapKey.towfKey (wfEncapKey_of_wfPrivateSeed h_wf)
    · exact wfEncapKey.towfKey (wfEncapKey_of_wfDecapKey h_wf)
    · exact wfEncapKey.towfKey h_wf
  rw [mlkem.key_get_value.fold]
  step with kgv_prefix.spec pk_mlkem_key h_wf_key
  rw [kgv_match_format.fold]
  match format with
  | mlkem.key.Format.PrivateSeed =>
      simp [wfKeyFormat] at h_wf
      step*
      · refine ⟨err_post1, ?_⟩
        match err, err_post2 with
        | .NoError, ⟨h_len64, _h_seed_flag, h_seed, h_rand⟩ =>
          refine ⟨by simpa [mlkem.key.Format.length] using h_len64, ?_⟩
          unfold mlkem.key.Key.toSpec
          rw [h_seed, h_rand]
          have hcat := slice_toSpec_eq_concat2 (m := 32) (n := 32) pb_dst'
            (by simpa using h_len64) (by simp [h_len64]) (by simp [h_len64])
          show (pb_dst'.toSpecWindow 0 32 (by simp [h_len64]) ++
                pb_dst'.toSpecWindow 32 32 (by simp [h_len64])) =
            pb_dst'.toSpec (mlkem.key.Format.PrivateSeed.length params)
              (by simpa [mlkem.key.Format.length] using h_len64)
          simpa [mlkem.key.Format.length] using hcat.symm
        | .WrongKeySize, h => exact h
        | .IncompatibleFormat, h =>
          have hfalse : pk_mlkem_key.has_private_seed = false := by
            change pk_mlkem_key.has_private_seed = false at h
            exact h
          rw [wfPrivateSeed.has_private_seed h_wf] at hfalse
          contradiction
        | .Unused, h | .WrongBlockSize, h | .WrongDataSize, h
        | .WrongNonceSize, h | .WrongTagSize, h | .WrongIterationCount, h
        | .AuthenticationFailure, h | .ExternalFailure, h | .FipsFailure, h
        | .HardwareFailure, h | .NotImplemented, h | .InvalidBlob, h
        | .BufferTooSmall, h | .MemoryAllocationFailure, h
        | .SignatureVerificationFailure, h
        | .ValueTooLarge, h | .SessionReplayFailure, h | .InvalidArgument, h
        | .HbsNoOtsKeysLeft, h | .HbsPublicRootMismatch, h => exact h.elim
  | mlkem.key.Format.DecapsulationKey =>
      simp [wfKeyFormat] at h_wf
      step*
      · refine ⟨err_post1, ?_⟩
        match err, err_post2 with
        | .NoError, ⟨h_len, _h_key_flag, h_s, h_t, h_pub, h_hash, h_rand⟩ =>
          refine ⟨by simpa [mlkem.key.Format.length] using h_len, ?_⟩
          unfold mlkem.key.Key.toSpec decapsulationKey encapsulationKey
          rw [h_s, h_t, h_pub, h_hash, h_rand]
          simp only [mlkem.key.Format.length]
          apply Vector.ext; intro i hi
          simp only [Vector.getElem_cast]
          show ((((_ : 𝔹 (384 * (k params : ℕ))) ++
              ((_ : 𝔹 (384 * (k params : ℕ))) ++ (_ : 𝔹 32))) ++
              (_ : 𝔹 32)) ++ (_ : 𝔹 32))[i]'(by grind) =
            (sliceToSpecBytes pb_dst' (768 * (k params : ℕ) + 96) h_len)[i]
          rw [Vector.getElem_append (by grind)]
          split_ifs with h4
          · rw [Vector.getElem_append (by grind)]
            split_ifs with h3
            · rw [Vector.getElem_append (by grind)]
              split_ifs with h0
              · unfold sliceToSpecBytes
                simp only [Slice.toSpecWindow, sliceWindowToSpecBytes, Vector.getElem_ofFn]
                simp
              · rw [Vector.getElem_append (by grind)]
                split_ifs with h1
                · unfold sliceToSpecBytes
                  simp only [Slice.toSpecWindow, sliceWindowToSpecBytes, Vector.getElem_ofFn]
                  have hidx : 384 * (k params : ℕ) + (i - 384 * (k params : ℕ)) = i := by grind
                  simp [hidx]
                · unfold sliceToSpecBytes
                  simp only [Slice.toSpecWindow, sliceWindowToSpecBytes, Vector.getElem_ofFn]
                  have hidx : 768 * (k params : ℕ) + (i - 384 * (k params : ℕ) - 384 * (k params : ℕ)) = i := by grind
                  simp [hidx]
            · unfold sliceToSpecBytes
              simp only [Slice.toSpecWindow, sliceWindowToSpecBytes, Vector.getElem_ofFn]
              have hidx :
                  768 * (k params : ℕ) + 32 + (i - (384 * (k params : ℕ) + (384 * (k params : ℕ) + 32))) = i := by
                grind
              simp [hidx]
          · unfold sliceToSpecBytes
            simp only [Slice.toSpecWindow, sliceWindowToSpecBytes, Vector.getElem_ofFn]
            have hidx :
                768 * (k params : ℕ) + 64 + (i - (384 * (k params : ℕ) + (384 * (k params : ℕ) + 32) + 32)) = i := by
              grind
            simp [hidx]
        | .InvalidArgument, h =>
          rcases h with h_len_bad | h_key_bad
          · exact Or.inr h_len_bad
          · rw [wfDecapKey.has_private_key h_wf] at h_key_bad
            contradiction
        | .Unused, h | .WrongKeySize, h | .WrongBlockSize, h | .WrongDataSize, h
        | .WrongNonceSize, h | .WrongTagSize, h | .WrongIterationCount, h
        | .AuthenticationFailure, h | .ExternalFailure, h | .FipsFailure, h
        | .HardwareFailure, h | .NotImplemented, h | .InvalidBlob, h
        | .BufferTooSmall, h | .MemoryAllocationFailure, h
        | .SignatureVerificationFailure, h | .IncompatibleFormat, h
        | .ValueTooLarge, h | .SessionReplayFailure, h
        | .HbsNoOtsKeysLeft, h | .HbsPublicRootMismatch, h => exact h.elim
  | mlkem.key.Format.EncapsulationKey =>
      simp [wfKeyFormat] at h_wf
      step*
      · refine ⟨err_post1, ?_⟩
        match err, err_post2 with
        | .NoError, ⟨h_len, h_t, h_pub⟩ =>
          refine ⟨by simpa [mlkem.key.Format.length] using h_len, ?_⟩
          unfold mlkem.key.Key.toSpec encapsulationKey
          rw [h_t, h_pub]
          have hcat := slice_toSpec_eq_concat2 (m := 384 * (k params : ℕ)) (n := 32) pb_dst'
            (by simpa [mlkem.key.Format.length] using h_len)
            (by simp [h_len]) (by rw [h_len])
          show (pb_dst'.toSpecWindow 0 (384 * (k params : ℕ)) (by simp [h_len]) ++
                pb_dst'.toSpecWindow (384 * (k params : ℕ)) 32 (by rw [h_len])) =
            pb_dst'.toSpec (mlkem.key.Format.EncapsulationKey.length params)
              (by simpa [mlkem.key.Format.length] using h_len)
          simpa [mlkem.key.Format.length] using hcat.symm
        | .InvalidArgument, h =>
          have hbad : pb_dst.length ≠ 384 * ↑(k params) + 32 := by
            change pb_dst.length ≠ 384 * ↑(k params) + 32 at h
            exact h
          exact Or.inl hbad
        | .Unused, h | .WrongKeySize, h | .WrongBlockSize, h | .WrongDataSize, h
        | .WrongNonceSize, h | .WrongTagSize, h | .WrongIterationCount, h
        | .AuthenticationFailure, h | .ExternalFailure, h | .FipsFailure, h
        | .HardwareFailure, h | .NotImplemented, h | .InvalidBlob, h
        | .BufferTooSmall, h | .MemoryAllocationFailure, h
        | .SignatureVerificationFailure, h | .IncompatibleFormat, h
        | .ValueTooLarge, h | .SessionReplayFailure, h
        | .HbsNoOtsKeysLeft, h | .HbsPublicRootMismatch, h => exact h.elim

end Symcrust.Properties.MLKEM
