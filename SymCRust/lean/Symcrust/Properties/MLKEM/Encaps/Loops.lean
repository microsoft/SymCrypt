/-
  # Encaps.lean — `encapsulate_internal`, `encapsulate_ex`,
  `encapsulate` and the two CBD loops they share.

  Maps to FIPS 203 Alg. 17 (`ML-KEM.Encaps_internal`) and the public
  randomness-wrapping entry points in Alg. 20 (`ML-KEM.Encaps`).

  ## Spec correspondence (Alg. 14 = `K_PKE.Encrypt`)

  `encapsulate_internal(key, secret, ct, m, temps)`:
  1. `(K, rOuter) := G(m ‖ H(ek))`; `secret := K`.
  2. Shake256 init absorbing `rOuter`.
  3. **Loop 0**: sample `y_i := SamplePolyCBD η₁(PRF η₁(rOuter, i))`
     into `pvr_inner[i]` for `i ∈ [0, k)`.
  4. `NTT` on `pvr_inner`; `vector_set_zero(pv_tmp)`.
  5. `pv_tmp := Â^T · ŷ / R` (Mont form, in NTT domain).
  6. `pv_tmp := INTT(Â^T · ŷ)` (after `vector_intt_and_mul_r`).
  7. **Loop 1**: sample `e1_i := SamplePolyCBD η₂(PRF η₂(rOuter, k+i))`
     and add into `pv_tmp[i]`.  After the loop:
     `pv_tmp = INTT(Â^T · ŷ) + e1 = u`.
  8. `vector_compress_and_encode(pv_tmp, du, ct[0..cb_u])` —
     `ct[0..cb_u] = ByteEncode_du(Compress_du(u)) = c₁`.
  9. `pe_tmp0 := t̂ · ŷ / R` (Mont form, in NTT domain).
  10. `pe_tmp0 := INTT(t̂ · ŷ)`.
  11. Sample `e2 := SamplePolyCBD η₂(PRF η₂(rOuter, 2k))`.
  12. `pe_tmp0 += e2`.
  13. `μ := Decompress_1(ByteDecode_1(m))` into `pe_tmp1`.
  14. `pe_tmp0 += μ` → `v = INTT(t̂ · ŷ) + e2 + μ`.
  15. `poly_element_compress_and_encode(pe_tmp0, dv, ct[cb_u..])` —
      `ct[cb_u..] = ByteEncode_dv(Compress_dv(v)) = c₂`.

  ## Top-level

  `encapsulate(key, secret, ct)`: calls `random` to draw a
  fresh 32-byte `m`, then `encapsulate_ex(key, m, secret, ct)` which
  Box-allocates `InternalComputationTemporaries` and dispatches to
  `encapsulate_internal`.

  The randomness draw is captured at the top level via an
  *existential* over `m : 𝔹 32`.
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.KeyView
import Symcrust.Properties.MLKEM.Bridges.PrfShake
import Symcrust.Properties.MLKEM.Ntt.PolyArith
import Symcrust.Properties.MLKEM.Sampling.SampleCBD
import Symcrust.Properties.MLKEM.Sampling.ExpandMatrix
import Symcrust.Properties.Axioms.System

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

/-! ## Spec-side view of the encapsulation key

The `encapsulationKey` definition and its two byte-side projection
helpers (`encapsulationKey_prefix_eq`,
`encapsulationKey_prefix_byteDecode_eq_of_encodedT`) live in
`Sampling/ExpandMatrix.lean` alongside `keyEncodedTPrefix`, their
only structural dependency.  Same names, dropped `private`
qualifier, so callers in this file resolve them via the shared
`Symcrust.Properties.MLKEM` namespace. -/


/-! ## Loop 0 streaming invariant (sampling `y` into `pvr_inner`) -/

/-- **Loop 0 invariant**: after `i` iterations, `pvr_inner[j]` for
`j < i` holds `SamplePolyCBD η₁(PRF η₁(rOuter, j.byte))`; the
remaining slots are unchanged from `orig_pvr`. -/
def encInvSampleR
    (params : ParameterSet) (rOuter : 𝔹 32)
    (orig_pvr pvr : Slice (PolyElement))
    (i : ℕ)
    (mkhs_base : mlkem.hash.MlKemHashState)
    (g_base : sha3.sha3_impl.GhostState) : Prop :=
  pvr.length = (k params : ℕ) ∧
  orig_pvr.length = (k params : ℕ) ∧
  i ≤ (k params : ℕ) ∧
  mlkem.hash.MlKemHashState.absorbing mkhs_base g_base ∧
  g_base.absorbed.map (·.bv) = rOuter.toList ∧
  mkhs_base.alg = mlkem.hash.MlKemHashAlg.Shake256 ∧
  (∀ (j : ℕ) (h_j : j < (k params : ℕ)) (_h_len : pvr.length = (k params : ℕ)),
      j < i →
      wfPoly (pvr.val[j]'(by have := pvr.property; grind)) ∧
      toPoly (pvr.val[j]'(by have := pvr.property; grind)) =
        MLKEM.SamplePolyCBD
          (MLKEM.PRF (η₁ params) rOuter ((j : ℕ) : Byte))) ∧
  (∀ (j : ℕ) (h_j : j < (k params : ℕ))
      (_h_len : pvr.length = (k params : ℕ))
      (_h_olen : orig_pvr.length = (k params : ℕ)),
      i ≤ j →
      pvr.val[j]'(by have := pvr.property; grind) =
      orig_pvr.val[j]'(by have := orig_pvr.property; grind))

/-- The full `encInvSampleR` at `i = k params` implies `wfPolyVec` on
the sampled vector. Used to propagate well-formedness from `sampleR`
to consumers like `mulMatR`. -/
theorem wfPolyVec_of_encInvSampleR_full
    {params : ParameterSet} {rOuter : 𝔹 32}
    {orig_pvr pvr : Slice (PolyElement)}
    {mkhs : mlkem.hash.MlKemHashState}
    {g : sha3.sha3_impl.GhostState}
    (h : encInvSampleR params rOuter orig_pvr pvr (k params : ℕ) mkhs g) :
    wfPolyVec pvr := by
  intro i hi
  obtain ⟨h_len, _, _, _, _, _, h_done, _⟩ := h
  have h_i_lt : i < (k params : ℕ) := by rw [h_len] at hi; exact hi
  exact (h_done i h_i_lt h_len h_i_lt).1

/-! ## Loop 1 streaming invariant (sampling `e₁` and adding into `pv_tmp`) -/

/-- **Loop 1 invariant**: after `i` iterations, `pv_tmp[j]` for `j < i`
holds `orig_pv_tmp[j] + SamplePolyCBD η₂(PRF η₂(rOuter, k+j.byte))`
(coefficient-wise mod q); the remaining slots are unchanged.  After
the full loop `pv_tmp = INTT(Â^T·ŷ) + e₁ = u`. -/
def encInvSampleE1Add
    (params : ParameterSet) (rOuter : 𝔹 32)
    (orig_pv_tmp pv_tmp : Slice (PolyElement))
    (i : ℕ)
    (mkhs_base : mlkem.hash.MlKemHashState)
    (g_base : sha3.sha3_impl.GhostState) : Prop :=
  pv_tmp.length = (k params : ℕ) ∧
  orig_pv_tmp.length = (k params : ℕ) ∧
  i ≤ (k params : ℕ) ∧
  mlkem.hash.MlKemHashState.absorbing mkhs_base g_base ∧
  g_base.absorbed.map (·.bv) = rOuter.toList ∧
  mkhs_base.alg = mlkem.hash.MlKemHashAlg.Shake256 ∧
  (∀ (j : ℕ) (h_j : j < (k params : ℕ))
      (_h_len : pv_tmp.length = (k params : ℕ))
      (_h_olen : orig_pv_tmp.length = (k params : ℕ)),
      j < i →
      wfPoly (pv_tmp.val[j]'(by have := pv_tmp.property; grind)) ∧
      wfPoly (orig_pv_tmp.val[j]'(by have := orig_pv_tmp.property; grind)) ∧
      toPoly (pv_tmp.val[j]'(by have := pv_tmp.property; grind)) =
        toPoly (orig_pv_tmp.val[j]'(by have := orig_pv_tmp.property; grind))
        + MLKEM.SamplePolyCBD
            (MLKEM.PRF (η₂)
              rOuter (((k params : ℕ) + j : ℕ) : Byte))) ∧
  (∀ (j : ℕ) (h_j : j < (k params : ℕ))
      (_h_len : pv_tmp.length = (k params : ℕ))
      (_h_olen : orig_pv_tmp.length = (k params : ℕ)),
      i ≤ j →
      pv_tmp.val[j]'(by have := pv_tmp.property; grind) =
      orig_pv_tmp.val[j]'(by have := orig_pv_tmp.property; grind))

/-- The full `encInvSampleE1Add` at `i = k params` implies `wfPolyVec`
on the sampled+accumulated vector.  Used to propagate well-formedness
from `sampleE1Add` to consumers like `buildU_dotE2`. -/
theorem wfPolyVec_of_encInvSampleE1Add_full
    {params : ParameterSet} {rOuter : 𝔹 32}
    {orig_pv_tmp pv_tmp : Slice (PolyElement)}
    {mkhs : mlkem.hash.MlKemHashState}
    {g : sha3.sha3_impl.GhostState}
    (h : encInvSampleE1Add params rOuter orig_pv_tmp pv_tmp
          (k params : ℕ) mkhs g) :
    wfPolyVec pv_tmp := by
  intro i hi
  obtain ⟨h_len, h_olen, _, _, _, _, h_done, _⟩ := h
  have h_i_lt : i < (k params : ℕ) := by rw [h_len] at hi; exact hi
  exact (h_done i h_i_lt h_len h_olen h_i_lt).1

/-! ## Loop 0 (`y` sampling) -/

#decompose mlkem.encapsulate_internal_loop0
    encapsulate_internal_loop0.fold
  letRange 1 1 => encapsulate_internal_loop0_match

#decompose encapsulate_internal_loop0_match
    encapsulate_internal_loop0_match.fold
  branch 1 (letRange 0 18) => encapsulate_internal_loop0_body

/-! ### Sub-phase decomposition of `encapsulate_internal_loop0_body`

The 19-op monadic body splits into three logically independent phases.
Each gets its own `@[step]` spec; the parent body proof composes them
in three `step` lines plus an `encInvSampleR` rebuild.

- **phaseA** — clone the base SHAKE state, assert Shake256, write byte
  `i` at buffer position 0, read it back, and `append` it.  Output:
  `(cbd_sample_buffer1, mkhs3)` with
  `mkhs3.absorbing (g_base.append [i] mkhs.state.squeeze_mode)`.
- **phaseB** — `extract` `64 * η₁` PRF bytes into the buffer prefix.
  Output: `(mkhs4, cbd_sample_buffer2)` where the first `64*η₁` bytes
  of `cbd_sample_buffer2` carry `(extractOutput G (64*η₁)).toList`.
- **phaseC** — slice the buffer, sample one CBD polynomial, write it
  back at `pvr_inner[i]`.  Output: `s4 = pvr_inner.set i a1` with `a1`
  satisfying the CBD spec on `sliceWindowToSpecBytes ...`. -/
#decompose encapsulate_internal_loop0_body
    encaps_loop0_body.fold
  letRange 0 7 => encaps_loop0_phaseA
  letRange 1 5 => encaps_loop0_phaseB
  letRange 2 6 => encaps_loop0_phaseC

/-! ### Phase A — clone, assert Shake256, append counter byte `i`. -/
@[local step]
theorem encaps_loop0_phaseA.spec
    (mkhs : mlkem.hash.MlKemHashState)
    (cbd_sample_buffer : Array U8 193#usize) (i : U8)
    (g_base : sha3.sha3_impl.GhostState)
    (h_abs : mlkem.hash.MlKemHashState.absorbing mkhs g_base)
    (h_alg : mkhs.alg = mlkem.hash.MlKemHashAlg.Shake256) :
    encaps_loop0_phaseA mkhs cbd_sample_buffer i
      ⦃ _buf1 mkhs3 =>
          mkhs3.alg = mlkem.hash.MlKemHashAlg.Shake256 ∧
          mlkem.hash.MlKemHashState.absorbing mkhs3
            (g_base.append [i] mkhs.state.squeeze_mode) ⦄ := by
  unfold encaps_loop0_phaseA
  step
  step as ⟨mkhs2, h_mkhs2⟩
  subst h_mkhs2
  step
  step
  step
  step
  step with mlkem.hash.MlKemHashState.append.spec _ _ g_base (Or.inl h_abs)
    as ⟨mkhs3, h_alg3, h_abs3⟩
  refine ⟨h_alg3.trans h_alg, ?_⟩
  have hs_eq : (↑s : List U8) = [i] := by
    have h_len : (↑cbd_sample_buffer : List U8).length = 193 := by
      have := cbd_sample_buffer.property; simp
    simp [s_post1, cbd_sample_buffer1_post]
    -- goal: List.take 1 ((↑cbd_sample_buffer).set 0 i) = [i]
    rcases hcb : (↑cbd_sample_buffer : List U8) with _ | ⟨x, xs⟩
    · rw [hcb] at h_len; simp at h_len
    · simp [List.set, List.take]
  rw [hs_eq] at h_abs3
  exact h_abs3

/-! ### Phase B — extract `64 * η₁` PRF bytes. -/
@[local step]
theorem encaps_loop0_phaseB.spec
    (pk_mlkem_key : mlkem.key.Key)
    (cbd_sample_buffer1 : Array U8 193#usize)
    (mkhs3 : mlkem.hash.MlKemHashState)
    (G : sha3.sha3_impl.GhostState)
    (h_abs3 : mlkem.hash.MlKemHashState.absorbing mkhs3 G)
    (h_alg3 : mkhs3.alg = mlkem.hash.MlKemHashAlg.Shake256)
    (h_n_eta1_le : pk_mlkem_key.params.n_eta1.val ≤ 3) :
    encaps_loop0_phaseB pk_mlkem_key cbd_sample_buffer1 mkhs3
      ⦃ _mkhs4 cbd_sample_buffer2 =>
          ∀ (j : ℕ) (hj : j < 64 * pk_mlkem_key.params.n_eta1.val),
            cbd_sample_buffer2.val[j]'(by
              have hlen : cbd_sample_buffer2.val.length = 193 := by
                have := cbd_sample_buffer2.property; simp
              omega) =
            ((extractOutput G (64 * pk_mlkem_key.params.n_eta1.val)).toList)[j]'(by
              simp; omega) ⦄ := by
  unfold encaps_loop0_phaseB
  step  -- i1 ← cast n_eta1 Usize
  step  -- i2 ← 64 * i1
  step  -- index_mut [0..i2)
  step with mlkem.hash.MlKemHashState.extract.spec _ _ _ _
    (Or.inl h_abs3) (Or.inr h_alg3)
    as ⟨mkhs4, s2, h_mkhs4_alg, h_s2_len, h_s2_val, _h_mkhs4_post⟩
  intro j hj
  have h_i1_val : i1.val = pk_mlkem_key.params.n_eta1.val := by
    rw [i1_post]; simp
  have h_i2_val : i2.val = 64 * pk_mlkem_key.params.n_eta1.val := by
    rw [i2_post, h_i1_val]
  have h_s1_len : s1.length = 64 * pk_mlkem_key.params.n_eta1.val := by
    rw [s1_post2]; omega
  have h_s2_val' : (↑s2 : List U8) =
      (extractOutput G (64 * pk_mlkem_key.params.n_eta1.val)).toList := by
    rw [h_s2_val, h_s1_len]
  have h_imb : (↑(index_mut_back s2) : List U8) =
      (↑cbd_sample_buffer1 : List U8).setSlice! 0 (↑s2) := s1_post3 s2
  have h_s2_len' : (↑s2 : List U8).length = 64 * pk_mlkem_key.params.n_eta1.val := by
    have := h_s2_len; rw [h_s1_len] at this
    simpa [Aeneas.Std.Slice.length] using this
  -- Chain through index_mut_back → setSlice! → s2 → extractOutput via list equalities.
  have h_cb_len : (↑cbd_sample_buffer1 : List U8).length = 193 := by
    have := cbd_sample_buffer1.property; simp
  have h_imb_len : (↑(index_mut_back s2) : List U8).length = 193 := by
    have := (index_mut_back s2).property; simp
  have h_lhs : (↑(index_mut_back s2) : List U8)[j]'(by omega) =
      ((↑cbd_sample_buffer1 : List U8).setSlice! 0 ↑s2)[j]'(by
        rw [List.length_setSlice!]; omega) :=
    List.getElem_of_eq h_imb _
  rw [h_lhs]
  rw [List.getElem_setSlice!_middle (h := by omega)]
  exact List.getElem_of_eq h_s2_val' _

/-! ### Phase C — sample one CBD polynomial; write it back at `pvr_inner[i]`.

Post: `s4` equals `pvr_inner.set (cast i) a1` where `a1` is well-formed and
`toPoly a1 = MLKEM.SamplePolyCBD` of the first `64 * η₁` bytes of
`cbd_sample_buffer2`. -/
@[local step]
theorem encaps_loop0_phaseC.spec
    (pk_mlkem_key : mlkem.key.Key)
    (pvr_inner : Slice (PolyElement)) (i : U8)
    (cbd_sample_buffer2 : Array U8 193#usize)
    (h_eta1_eq : pk_mlkem_key.params.n_eta1.val = 2 ∨
                 pk_mlkem_key.params.n_eta1.val = 3)
    (h_i_lt : i.val < pvr_inner.length) :
    encaps_loop0_phaseC pk_mlkem_key pvr_inner i cbd_sample_buffer2
      ⦃ s4 =>
          ∃ a1 : PolyElement,
            s4 = pvr_inner.set (UScalar.cast UScalarTy.Usize i) a1 ∧
            wfPoly a1 ∧
            toPoly a1 = MLKEM.SamplePolyCBD
              (η := cbdEta
                (UScalar.cast UScalarTy.U32 pk_mlkem_key.params.n_eta1)
                (by simp; exact h_eta1_eq))
              (sliceWindowToSpecBytes cbd_sample_buffer2.to_slice 0
                (64 * pk_mlkem_key.params.n_eta1.val)
                (by
                  have h_to_slice_len : cbd_sample_buffer2.to_slice.length = 193 := by
                    simp [Aeneas.Std.Slice.length, Aeneas.Std.Array.to_slice]
                  have : pk_mlkem_key.params.n_eta1.val ≤ 3 := by
                    rcases h_eta1_eq with h | h <;> omega
                  omega)) ⦄ := by
  unfold encaps_loop0_phaseC
  step  -- s3 ← Array.to_slice cbd_sample_buffer2
  step  -- i3 ← UScalar.cast .U32 n_eta1
  step  -- i4 ← UScalar.cast .Usize i
  step as ⟨a, index_mut_back2, h_a_post⟩
  have h_s3_len : s3.length = 64 * 3 + 1 := by
    simp [s3_post, Aeneas.Std.Slice.length, Aeneas.Std.Array.to_slice]
  have h_i3_eta : i3.val = 2 ∨ i3.val = 3 := by
    rw [i3_post]; simp; exact h_eta1_eq
  step with mlkem.ntt.poly_element_sample_cbd_from_bytes.spec _ _ _ h_i3_eta h_s3_len
    as ⟨a1, h_a1_wf, h_a1_eq⟩
  refine ⟨a1, ?_, h_a1_wf, ?_⟩
  · -- s4 = pvr_inner.set (cast i) a1
    have h_imb2 : index_mut_back2 = pvr_inner.set i4 := by grind
    rw [h_imb2, i4_post]
  · -- toPoly a1 = SamplePolyCBD ...
    rw [h_a1_eq]
    have h_s3_eq : s3 = cbd_sample_buffer2.to_slice := s3_post
    have h_i3_cast : i3 = UScalar.cast UScalarTy.U32 pk_mlkem_key.params.n_eta1 := i3_post
    subst h_i3_cast
    subst h_s3_eq
    rfl

/-- **Body spec** for loop 0: sample one `y_i ← SamplePolyCBD η₁(PRF η₁ rOuter i)`
and write it to `pvr_inner[i]`.  Advances `encInvSampleR` by one slot.

Informal proof. Template: leaf monadic step-spec for the `#decompose`-extracted
`_loop0._body`. Unfold `encapsulate_internal_loop0_body`.

The invariant `encInvSampleR` says, in plain English: `pvr_inner` and the
original vector both have length `k params`; the base SHAKE256 state `mkhs`
is still the PRF seed state absorbing exactly `rOuter`; slots `j < i` already
contain well-formed polynomials equal to
`SamplePolyCBD (PRF (η₁ params) rOuter (j : Byte))`; and slots `j ≥ i` are
unchanged from `orig_pvr`.  The loop preamble initializes it at `i = 0` after
setting SHAKE256, initializing it, and appending `rOuter`: the processed
prefix is empty and the frame clause is reflexive.

Step through the decomposed body:
1. `step Array.index_mut_usize.spec` on `cbd_sample_buffer[0]`, obtaining
   the back function that writes the PRF counter byte.
2. `step MlKemHashState.clone.spec`, `step MlKemHashState.get_alg.spec`,
   `step MlKemHashAlg.eq`, and `step massert.spec` to clone the base
   SHAKE256 PRF state and check it is SHAKE256.
3. Apply the buffer back function to write `i` at byte 0, then
   `step Array.index_SliceIndexRangeUsizeSlice.step_spec` to expose the
   one-byte counter slice.
4. `step MlKemHashState.append.spec` — the PRF-state-threading step: the
   worker ghost state becomes `g_base.append [i]`, while the invariant's
   base `mkhs` / `g_base` remains unchanged for subsequent iterations.
5. `step UScalar.cast.spec` and `step Usize.mul.spec` to compute `64 * η₁`.
6. `step Array.index_mut_SliceIndexRangeUsizeSlice` to borrow the output
   byte slice and `step MlKemHashState.extract.spec` with `wipe = false` to
   squeeze exactly `64 * η₁` bytes.  Combined with the SHAKE256/PRF bridge,
   this byte slice is `MLKEM.PRF (η₁ params) rOuter (i : Byte)`.
7. `step Array.to_slice.spec`, `step UScalar.cast.spec` for `η₁`,
   `step UScalar.cast.spec` for `i`, and `step Slice.index_mut_usize.spec`
   for `pvr_inner[i]`.
8. `step mlkem.ntt.poly_element_sample_cbd_from_bytes.spec` to obtain a
   well-formed polynomial with
   `toPoly = MLKEM.SamplePolyCBD (MLKEM.PRF (η₁ params) rOuter (i : Byte))`.
9. Apply the slice back function to store the sampled polynomial in slot `i`.

Propagation: rebuild `encInvSampleR` at `i.val + 1`.  The new-slot case
`j = i.val` uses the CBD postcondition and the PRF bridge; old processed
slots `j < i.val` come from `h_inv` plus the slice-frame theorem; untouched
slots `i.val + 1 ≤ j` come from the back-function frame and the old rest
clause.

Loop exit: when the parent `*_loop0.spec` reaches `i = k params`, the
invariant says every slot of `pvr_inner` is the corresponding sampled `y_j`;
the parent then uses `mlkem.ntt.vector_ntt.spec` to obtain
`ŷ = PolyVector.NTT y`.

Close with `split_conjs`, one focused `· agrind` per structural conjunct.
The SHAKE / PRF monotonicity sub-goal is closed by
`MlKemHashState.append.spec` + `MlKemHashState.extract.spec` and the PRF
bridge — there is no separate `PRNG.update.spec` in this file. -/
@[step]
theorem encapsulate_internal_loop0_body.spec
    (params : ParameterSet) (rOuter : 𝔹 32)
    (i : U8)
    (pk_mlkem_key : mlkem.key.Key)
    (mkhs : mlkem.hash.MlKemHashState)
    (cbd_sample_buffer : Array U8 193#usize)
    (orig_pvr pvr_inner : Slice (PolyElement))
    (g_base : sha3.sha3_impl.GhostState)
    (h_wf : wfKey pk_mlkem_key params)
    (h_inv : encInvSampleR params rOuter orig_pvr pvr_inner i.val
              mkhs g_base)
    (h_i : i.val < (k params : ℕ))
    (h_eta1 : pk_mlkem_key.params.n_eta1.val = (η₁ params : ℕ)) :
    encapsulate_internal_loop0_body pk_mlkem_key mkhs
        cbd_sample_buffer pvr_inner i
      ⦃ _mkhs' _buf' pvr_inner' =>
          encInvSampleR params rOuter orig_pvr pvr_inner'
            (i.val + 1) mkhs g_base ⦄ := by
  obtain ⟨h_pvr_len, h_orig_len, h_i_le, h_abs, h_g_abs, h_alg, h_cbd, h_frame⟩ := h_inv
  rw [encaps_loop0_body.fold]
  -- Phase A: clone + assert + append byte i.
  step with encaps_loop0_phaseA.spec _ _ _ g_base h_abs h_alg
    as ⟨cbd_sample_buffer1, mkhs3, h_alg3, h_abs3⟩
  -- Phase B: extract 64*η₁ bytes into prefix.
  have h_n_eta1_le : pk_mlkem_key.params.n_eta1.val ≤ 3 := by
    rw [h_eta1]; rcases params <;> decide
  step with encaps_loop0_phaseB.spec _ _ _ _ h_abs3 h_alg3 h_n_eta1_le
    as ⟨_mkhs4, cbd_sample_buffer2, h_bytes⟩
  -- Phase C: sample one CBD polynomial; write at slot i.
  have h_eta1_eq : pk_mlkem_key.params.n_eta1.val = 2 ∨
                   pk_mlkem_key.params.n_eta1.val = 3 := by
    rw [h_eta1]; rcases params <;> decide
  have h_i_lt_pvr : i.val < pvr_inner.length := by
    rw [h_pvr_len]; exact h_i
  step with encaps_loop0_phaseC.spec _ _ _ _ h_eta1_eq h_i_lt_pvr
    as ⟨a1, pvr_inner', h_s4_eq, h_a1_wf, h_a1_cbd⟩
  -- Substitute pvr_inner' = pvr_inner.set (cast i) a1 globally.
  subst h_s4_eq
  -- Rebuild encInvSampleR at i.val + 1.
  unfold encInvSampleR
  have h_set_len' : (pvr_inner.set (UScalar.cast UScalarTy.Usize i) a1).val.length =
      pvr_inner.val.length := by
    simp [Aeneas.Std.Slice.set, Aeneas.Std.Slice.setAtNat]
  have h_set_slice_len : (pvr_inner.set (UScalar.cast UScalarTy.Usize i) a1).length =
      pvr_inner.length := by
    simp [Aeneas.Std.Slice.length, Aeneas.Std.Slice.set, Aeneas.Std.Slice.setAtNat]
  have h_cast_i_val : (UScalar.cast UScalarTy.Usize i).val = i.val := by simp
  refine ⟨?_, h_orig_len, by omega, h_abs, h_g_abs, h_alg, ?_, ?_⟩
  · -- length preserved
    rw [h_set_slice_len]; exact h_pvr_len
  · -- cbd_new
    intro j h_j _h_len' h_j_lt
    by_cases h_j_lt_i : j < i.val
    · -- Old slot — use h_cbd plus frame.
      have h_j_ne : (UScalar.cast UScalarTy.Usize i).val ≠ j := by
        rw [h_cast_i_val]; omega
      have h_j_ne' : (i.val : ℕ) ≠ j := by omega
      have h_old := h_cbd j h_j h_pvr_len h_j_lt_i
      have h_get_eq :
          (pvr_inner.set (UScalar.cast UScalarTy.Usize i) a1).val[j]'(by
            rw [h_set_len']; have := pvr_inner.property; grind) =
          pvr_inner.val[j]'(by have := pvr_inner.property; grind) := by
        simp [Aeneas.Std.Slice.set, Aeneas.Std.Slice.setAtNat]
        rw [List.getElem_set_ne h_j_ne']
      refine ⟨?_, ?_⟩
      · rw [h_get_eq]; exact h_old.1
      · rw [h_get_eq]; exact h_old.2
    · -- New slot j = i.val.
      have h_j_eq : j = i.val := by omega
      have h_eq_idx : (UScalar.cast UScalarTy.Usize i).val = j := by
        rw [h_cast_i_val]; omega
      have h_get_new :
          (pvr_inner.set (UScalar.cast UScalarTy.Usize i) a1).val[j]'(by
            rw [h_set_len']; have := pvr_inner.property; grind) = a1 := by
        simp [Aeneas.Std.Slice.set, Aeneas.Std.Slice.setAtNat, h_eq_idx]
      refine ⟨?_, ?_⟩
      · rw [h_get_new]; exact h_a1_wf
      · rw [h_get_new, h_a1_cbd]
        -- Bridge: @SamplePolyCBD η_cbd (sliceWindowToSpecBytes ...)
        --       = @SamplePolyCBD (η₁ params) (MLKEM.PRF (η₁ params) rOuter ((j : ℕ) : Byte))
        -- where η_cbd = cbdEta (UScalar.cast .U32 n_eta1) _ has the same `.val`
        -- as `η₁ params`. Use Bridge 5 (`prf_shake_samplePolyCBD_bridge_of_absorbing`)
        -- to absorb the `Subtype.ext` + bridge invocation + cast-rfl in one shot,
        -- avoiding the slow `congr 1` on `SamplePolyCBD` with mismatched implicit η.
        have h_sm : mkhs.state.squeeze_mode = false := by
          unfold mlkem.hash.MlKemHashState.absorbing at h_abs
          have h_weak : sha3.sha3_impl.absorbingWeak mkhs.state g_base := h_abs.1.1
          simpa using h_weak.2.1
        have h_j_byte : (i.bv : BitVec 8) = ((j : ℕ) : BitVec 8) := by
          rw [h_j_eq]; simp
        rw [← h_j_byte]
        apply prf_shake_samplePolyCBD_bridge_of_absorbing
          (cbdEta (UScalar.cast UScalarTy.U32 pk_mlkem_key.params.n_eta1)
            (by simp; exact h_eta1_eq))
          (η₁ params) (by simp [cbdEta]; exact h_eta1)
          rOuter i mkhs g_base h_abs h_alg h_g_abs
          mkhs.state.squeeze_mode h_sm cbd_sample_buffer2.to_slice
        intro k hk
        have h_kk : k < 64 * pk_mlkem_key.params.n_eta1.val := by
          simpa [cbdEta] using hk
        have := h_bytes k h_kk
        change (↑cbd_sample_buffer2)[k] =
          (extractOutput (g_base.append [i] mkhs.state.squeeze_mode)
            (64 * pk_mlkem_key.params.n_eta1.val)).toList[k]
        exact this
  · -- frame
    intro j h_j _h_len' _h_olen' h_j_ge
    have h_j_ne : (UScalar.cast UScalarTy.Usize i).val ≠ j := by
      rw [h_cast_i_val]; omega
    have h_j_ne' : (i.val : ℕ) ≠ j := by omega
    have h_get_eq :
        (pvr_inner.set (UScalar.cast UScalarTy.Usize i) a1).val[j]'(by
          rw [h_set_len']; have := pvr_inner.property; grind) =
        pvr_inner.val[j]'(by have := pvr_inner.property; grind) := by
      simp [Aeneas.Std.Slice.set, Aeneas.Std.Slice.setAtNat]
      rw [List.getElem_set_ne h_j_ne']
    rw [h_get_eq]
    exact h_frame j h_j h_pvr_len h_orig_len (by omega)

/-! The `#decompose` declarations and `_loop0_match.fold` equation above
are consumed inside `mlkem.encapsulate_internal_loop0.spec`'s proof via
the canonical Variant B pattern (see `proof-patterns` skill): the loop
dispatch and per-slot body step are inlined there, so no standalone
`@[step]` spec is needed for `_match`. -/

/-- **Loop spec** for loop 0: run the `y`-sampling loop from `iter.start`
to `k params`.

The invariant `encInvSampleR` carries both ghost state and vector state.
It records that the base SHAKE256 PRF state `mkhs` is an absorbing state
for exactly `rOuter`, that all slots before `iter.start` already contain
`SamplePolyCBD (PRF (η₁ params) rOuter j)`, and that all remaining slots
are still equal to `orig_pvr`.  The encapsulation preamble initializes it
at `iter.start = 0` after `MlKemHashState.set_alg Shake256`, `init`, and
`append rOuter`; the prefix clauses are vacuous and the rest clause holds
by reflexivity.

Informal proof. Canonical recursive Range-U8 loop (`proof-patterns`
"Loop — Canonical Template", Variant B). No separate
`_loop0_match.spec` is needed: the match dispatch is inlined.

- **Mandatory first step**: `rw [encapsulate_internal_loop0.fold]`. Do
  NOT use `unfold mlkem.encapsulate_internal_loop0`. After the `(next iter)` step is
  consumed, `rw [encapsulate_internal_loop0_match.fold]` to expose the
  `_body` Kind A helper call inside the some-arm.
- `step` to consume `next iter` (Range-U8 → `o, iter1`).
- `cases o`:
  - **`none` arm** (`iter.start = k params`): `_match`'s `none` body
    returns the current tuple unchanged; the post `encInvSampleR …
    (k params) …` is just `h_inv` rewritten at `iter.start.val = k
    params`; close with `agrind`.
  - **`some i` arm**: from the Range-U8 iterator equation,
    `i.val = iter.start.val` and `iter1.start.val = i.val + 1`;
    `step with encapsulate_internal_loop0_body.spec` (discharging
    `h_wf`, `h_i`, `h_eta1`, `h_inv`); body post extends
    `encInvSampleR` by one slot; `step*` closes the recursive
    `_loop0` call via the IH at `iter1`.
- `termination_by iter.«end».val - iter.start.val`; `decreasing_by agrind`.

The post at loop exit gives the spec-level conclusion used by the parent:
all `pvr_inner[j]` are the sampled `y_j`; applying `vector_ntt.spec`
afterwards turns this into the NTT-domain noise vector `ŷ`, matching
K-PKE.Encrypt Algorithm 14 steps 9–12 and 18.

Close with `split_conjs`; use one focused `· agrind` per invariant
conjunct and for the termination / decreasing side conditions. -/
@[step]
theorem mlkem.encapsulate_internal_loop0.spec
    (params : ParameterSet) (rOuter : 𝔹 32)
    (pk_mlkem_key : mlkem.key.Key)
    (iter : core.ops.range.Range U8)
    (mkhs mkhs1 : mlkem.hash.MlKemHashState)
    (cbd_sample_buffer : Array U8 193#usize)
    (orig_pvr pvr_inner : Slice (PolyElement))
    (g_base : sha3.sha3_impl.GhostState)
    (h_wf : wfKey pk_mlkem_key params)
    (h_inv : encInvSampleR params rOuter orig_pvr pvr_inner
              iter.start.val mkhs g_base)
    (h_iter_end : iter.«end».val = (k params : ℕ))
    (h_iter_start : iter.start.val ≤ (k params : ℕ))
    (h_eta1 : pk_mlkem_key.params.n_eta1.val = (η₁ params : ℕ)) :
    mlkem.encapsulate_internal_loop0 pk_mlkem_key iter mkhs mkhs1
        cbd_sample_buffer pvr_inner
      ⦃ _mkhs' _buf' pvr_inner' =>
          encInvSampleR params rOuter orig_pvr pvr_inner'
            (k params : ℕ) mkhs g_base ⦄ := by
  rw [encapsulate_internal_loop0.fold]
  by_cases hlt : iter.start.val < iter.«end».val
  · step with core.iter.range.IteratorRange.next_U8_some_spec iter hlt
      as ⟨o, iter1, ho, hstart1, hend1⟩
    simp only [ho]
    rw [encapsulate_internal_loop0_match.fold]
    have h_i_lt : iter.start.val < (k params : ℕ) := by rw [← h_iter_end]; exact hlt
    step with encapsulate_internal_loop0_body.spec params rOuter iter.start
      pk_mlkem_key mkhs cbd_sample_buffer orig_pvr pvr_inner g_base
      h_wf h_inv h_i_lt h_eta1
      as ⟨mkhs4, cbd_buf2, new_pvr, h_body_post⟩
    have hx_le : iter1.start.val ≤ (k params : ℕ) := by rw [hstart1, ← h_iter_end]; omega
    have h_inv' : encInvSampleR params rOuter orig_pvr new_pvr iter1.start.val mkhs g_base := by
      rw [hstart1]; exact h_body_post
    apply mlkem.encapsulate_internal_loop0.spec
      params rOuter pk_mlkem_key iter1 mkhs mkhs4 cbd_buf2 orig_pvr new_pvr g_base
      h_wf h_inv' (by rw [hend1]; exact h_iter_end) hx_le h_eta1
  · step with core.iter.range.IteratorRange.next_U8_none_spec iter (by agrind)
      as ⟨o, iter1, ho, hiter1⟩
    simp only [ho]
    have h_eq : iter.start.val = (k params : ℕ) := by
      rw [h_iter_end] at hlt; omega
    rw [encapsulate_internal_loop0_match.fold]
    simp only [WP.spec_ok]
    rw [h_eq] at h_inv; exact h_inv
termination_by iter.«end».val - iter.start.val
decreasing_by
  rw [hstart1]
  scalar_tac

/-! ## Loop 1 (`e₁` sampling and accumulate) -/

#decompose mlkem.encapsulate_internal_loop1
    encapsulate_internal_loop1.fold
  letRange 1 1 => encapsulate_internal_loop1_match

#decompose encapsulate_internal_loop1_match
    encapsulate_internal_loop1_match.fold
  branch 1 (letRange 0 20) => encapsulate_internal_loop1_body

/-! ### `#decompose` of `encapsulate_internal_loop1_body`

The body has 21 monadic ops vs loop0's 19 (extra leading `i1 ← n_rows
+ i` for the PRF counter byte = `k + i`). Split into 4 phases:

- **phaseA** — counter byte (`n_rows + i`), clone+validate Shake256,
  write counter byte into `cbd_sample_buffer[0]`, and append it to the
  hash state.  Output: the updated buffer (`cbd_sample_buffer1`) and
  new hash state (`mkhs3`).
- **phaseB** — cast η₂ to `Usize`, multiply by 64, borrow the buffer's
  `[0..64*η₂)` window, extract that many PRF bytes, write back.
  Output: `mkhs4`, `cbd_sample_buffer2`.
- **phaseC** — slice the buffer, cast η₂ to `U32`, sample one CBD
  polynomial into the scratch `pe_tmp0`.  Output: `pe_tmp01`.
- **phaseD** — cast `i` to `Usize`, borrow `pv_tmp[i]`,
  `poly_element_add_in_place pe_tmp01 a`, write back to slot `i`. -/
#decompose encapsulate_internal_loop1_body
    encaps_loop1_body.fold
  letRange 0 8 => encaps_loop1_phaseA
  letRange 1 5 => encaps_loop1_phaseB
  letRange 2 3 => encaps_loop1_phaseC
  letRange 3 4 => encaps_loop1_phaseD

/-! ### Phase A (loop 1) — counter byte `n_rows + i`, clone, assert Shake256, append. -/
@[local step]
theorem encaps_loop1_phaseA.spec
    (pk_mlkem_key : mlkem.key.Key)
    (mkhs : mlkem.hash.MlKemHashState)
    (cbd_sample_buffer : Array U8 193#usize) (i : U8)
    (g_base : sha3.sha3_impl.GhostState)
    (h_abs : mlkem.hash.MlKemHashState.absorbing mkhs g_base)
    (h_alg : mkhs.alg = mlkem.hash.MlKemHashAlg.Shake256)
    (h_no_overflow : pk_mlkem_key.params.n_rows.val + i.val < 256) :
    encaps_loop1_phaseA pk_mlkem_key mkhs cbd_sample_buffer i
      ⦃ _buf1 mkhs3 =>
          mkhs3.alg = mlkem.hash.MlKemHashAlg.Shake256 ∧
          ∃ counter : U8,
            counter.val = (pk_mlkem_key.params.n_rows.val + i.val) % 256 ∧
            mlkem.hash.MlKemHashState.absorbing mkhs3
              (g_base.append [counter] mkhs.state.squeeze_mode) ⦄ := by
  unfold encaps_loop1_phaseA
  step as ⟨i1, h_i1⟩
  step
  step as ⟨mkhs2, h_mkhs2⟩
  subst h_mkhs2
  step
  step
  step
  step
  step with mlkem.hash.MlKemHashState.append.spec _ _ g_base (Or.inl h_abs)
    as ⟨mkhs3, h_alg3, h_abs3⟩
  refine ⟨h_alg3.trans h_alg, i1, ?_, ?_⟩
  · rw [h_i1]; omega
  · have hs_eq : (↑s : List U8) = [i1] := by
      have h_len : (↑cbd_sample_buffer : List U8).length = 193 := by
        have := cbd_sample_buffer.property; simp
      simp [s_post1, cbd_sample_buffer1_post]
      rcases hcb : (↑cbd_sample_buffer : List U8) with _ | ⟨x, xs⟩
      · rw [hcb] at h_len; simp at h_len
      · simp [List.set, List.take]
    rw [hs_eq] at h_abs3
    exact h_abs3

/-! ### Phase B (loop 1) — extract `64 * η₂` PRF bytes. -/
@[local step]
theorem encaps_loop1_phaseB.spec
    (pk_mlkem_key : mlkem.key.Key)
    (cbd_sample_buffer1 : Array U8 193#usize)
    (mkhs3 : mlkem.hash.MlKemHashState)
    (G : sha3.sha3_impl.GhostState)
    (h_abs3 : mlkem.hash.MlKemHashState.absorbing mkhs3 G)
    (h_alg3 : mkhs3.alg = mlkem.hash.MlKemHashAlg.Shake256)
    (h_n_eta2_le : pk_mlkem_key.params.n_eta2.val ≤ 3) :
    encaps_loop1_phaseB pk_mlkem_key cbd_sample_buffer1 mkhs3
      ⦃ _mkhs4 cbd_sample_buffer2 =>
          ∀ (j : ℕ) (hj : j < 64 * pk_mlkem_key.params.n_eta2.val),
            cbd_sample_buffer2.val[j]'(by
              have hlen : cbd_sample_buffer2.val.length = 193 := by
                have := cbd_sample_buffer2.property; simp
              omega) =
            ((extractOutput G (64 * pk_mlkem_key.params.n_eta2.val)).toList)[j]'(by
              simp; omega) ⦄ := by
  unfold encaps_loop1_phaseB
  step  -- i1 ← cast n_eta2 Usize
  step  -- i2 ← 64 * i1
  step  -- index_mut [0..i2)
  step with mlkem.hash.MlKemHashState.extract.spec _ _ _ _
    (Or.inl h_abs3) (Or.inr h_alg3)
    as ⟨mkhs4, s2, h_mkhs4_alg, h_s2_len, h_s2_val, _h_mkhs4_post⟩
  intro j hj
  have h_i2_val : i2.val = pk_mlkem_key.params.n_eta2.val := by
    rw [i2_post]; simp
  have h_i3_val : i3.val = 64 * pk_mlkem_key.params.n_eta2.val := by
    rw [i3_post, h_i2_val]
  have h_s1_len : s1.length = 64 * pk_mlkem_key.params.n_eta2.val := by
    rw [s1_post2]; omega
  have h_s2_val' : (↑s2 : List U8) =
      (extractOutput G (64 * pk_mlkem_key.params.n_eta2.val)).toList := by
    rw [h_s2_val, h_s1_len]
  have h_imb : (↑(index_mut_back s2) : List U8) =
      (↑cbd_sample_buffer1 : List U8).setSlice! 0 (↑s2) := s1_post3 s2
  have h_s2_len' : (↑s2 : List U8).length = 64 * pk_mlkem_key.params.n_eta2.val := by
    have := h_s2_len; rw [h_s1_len] at this
    simpa [Aeneas.Std.Slice.length] using this
  have h_cb_len : (↑cbd_sample_buffer1 : List U8).length = 193 := by
    have := cbd_sample_buffer1.property; simp
  have h_imb_len : (↑(index_mut_back s2) : List U8).length = 193 := by
    have := (index_mut_back s2).property; simp
  have h_lhs : (↑(index_mut_back s2) : List U8)[j]'(by omega) =
      ((↑cbd_sample_buffer1 : List U8).setSlice! 0 ↑s2)[j]'(by
        rw [List.length_setSlice!]; omega) :=
    List.getElem_of_eq h_imb _
  rw [h_lhs]
  rw [List.getElem_setSlice!_middle (h := by omega)]
  exact List.getElem_of_eq h_s2_val' _

/-! ### Phase C (loop 1) — sample one CBD polynomial into the scratch `pe_tmp0`.

Post: `pe_tmp01` is well-formed and `toPoly pe_tmp01 = SamplePolyCBD_η₂` of
the first `64 * η₂` bytes of `cbd_sample_buffer2`. -/
@[local step]
theorem encaps_loop1_phaseC.spec
    (pk_mlkem_key : mlkem.key.Key)
    (pe_tmp0 : PolyElement)
    (cbd_sample_buffer2 : Array U8 193#usize)
    (h_eta2_eq : pk_mlkem_key.params.n_eta2.val = (η₂ : ℕ)) :
    encaps_loop1_phaseC pk_mlkem_key pe_tmp0 cbd_sample_buffer2
      ⦃ pe_tmp01 =>
          wfPoly pe_tmp01 ∧
          toPoly pe_tmp01 = MLKEM.SamplePolyCBD
            (η := cbdEta
              (UScalar.cast UScalarTy.U32 pk_mlkem_key.params.n_eta2)
              (by simp; exact Or.inl h_eta2_eq))
            (sliceWindowToSpecBytes cbd_sample_buffer2.to_slice 0
              (64 * pk_mlkem_key.params.n_eta2.val)
              (by
                have h_to_slice_len : cbd_sample_buffer2.to_slice.length = 193 := by
                  simp [Aeneas.Std.Slice.length, Aeneas.Std.Array.to_slice]
                have : pk_mlkem_key.params.n_eta2.val ≤ 3 := by
                  rw [h_eta2_eq]; decide
                omega)) ⦄ := by
  unfold encaps_loop1_phaseC
  step  -- s3 ← Array.to_slice cbd_sample_buffer2
  step  -- i4 ← cast n_eta2 to U32
  have h_s3_len : s3.length = 64 * 3 + 1 := by
    simp [s3_post, Aeneas.Std.Slice.length, Aeneas.Std.Array.to_slice]
  have h_i4_eta : i4.val = 2 ∨ i4.val = 3 := by
    rw [i4_post]; simp; exact Or.inl h_eta2_eq
  step with mlkem.ntt.poly_element_sample_cbd_from_bytes.spec _ _ _ h_i4_eta h_s3_len
    as ⟨a1, h_a1_wf, h_a1_eq⟩
  refine ⟨h_a1_wf, ?_⟩
  rw [h_a1_eq]
  have h_s3_eq : s3 = cbd_sample_buffer2.to_slice := s3_post
  have h_i4_cast : i4 = UScalar.cast UScalarTy.U32 pk_mlkem_key.params.n_eta2 := i4_post
  subst h_i4_cast
  subst h_s3_eq
  rfl

/-! ### Phase D (loop 1) — borrow `pv_tmp[i]`, add-in-place, write back.

Post: `s4` equals `pv_tmp.set (cast i) (orig + pe_tmp01)` (in `toPoly` sense)
where `orig = pv_tmp[i]`.  The returned slot is well-formed if both inputs
are. -/
@[local step]
theorem encaps_loop1_phaseD.spec
    (pv_tmp : Slice (PolyElement)) (i : U8) (pe_tmp01 : PolyElement)
    (h_i_lt : i.val < pv_tmp.length)
    (h_orig_wf : wfPoly (pv_tmp.val[i.val]'(by
      rw [show pv_tmp.val.length = pv_tmp.length from rfl]; exact h_i_lt)))
    (h_pe_wf : wfPoly pe_tmp01) :
    encaps_loop1_phaseD pv_tmp i pe_tmp01
      ⦃ s4 =>
          ∃ a1 : PolyElement,
            s4 = pv_tmp.set (UScalar.cast UScalarTy.Usize i) a1 ∧
            wfPoly a1 ∧
            toPoly a1 = Vector.ofFn fun (j : Fin 256) =>
              (toPoly (pv_tmp.val[i.val]'(by
                rw [show pv_tmp.val.length = pv_tmp.length from rfl]; exact h_i_lt))).get j
              + (toPoly pe_tmp01).get j ⦄ := by
  unfold encaps_loop1_phaseD
  step  -- i5 ← cast i to Usize
  step as ⟨a, index_mut_back2, h_a_post⟩
  have h_i_lt_val : i.val < pv_tmp.val.length := by
    rw [show pv_tmp.val.length = pv_tmp.length from rfl]; exact h_i_lt
  have h_i5_val : i5.val = i.val := by rw [i5_post]; simp
  have h_a_eq : a = pv_tmp.val[i.val]'h_i_lt_val := by
    grind
  step with mlkem.ntt.poly_element_add_in_place.spec pe_tmp01 a
    h_pe_wf (h_a_eq ▸ h_orig_wf)
    as ⟨a1, h_a1_wf, h_a1_eq⟩
  refine ⟨a1, ?_, h_a1_wf, ?_⟩
  · have h_imb2 : index_mut_back2 = pv_tmp.set i5 := by grind
    rw [h_imb2, i5_post]
  · rw [h_a1_eq, h_a_eq]
/-- **Body spec** for loop 1: sample one `e₁_i ← SamplePolyCBD η₂(PRF η₂ rOuter (k+i))`
and add it into `pv_tmp[i]`.  Advances `encInvSampleE1Add` by one slot.

Informal proof. Template: leaf monadic step-spec for the `#decompose`-extracted
`_loop1._body`. Unfold `encapsulate_internal_loop1_body`.

The invariant `encInvSampleE1Add` says, in plain English: `pv_tmp` and
`orig_pv_tmp` both have length `k params`; the base SHAKE256 PRF state
`mkhs` still absorbs exactly `rOuter`; slots `j < i` are well-formed and
equal to `orig_pv_tmp[j] + SamplePolyCBD (PRF η₂ rOuter (k+j))`; and slots
`j ≥ i` are unchanged from `orig_pv_tmp`.  The loop preamble initializes it
at `i = 0` just after `pv_tmp` has become `INTT(Âᵀ · ŷ)`: the processed
prefix is empty and every slot is framed by reflexivity.

Step through the decomposed body:
1. `step U8.add.spec` computes the PRF counter byte
   `pk_mlkem_key.params.n_rows + i`; using `h_n_rows`, this is
   `(k params + i.val : Byte)`.
2. `step Array.index_mut_usize.spec` on `cbd_sample_buffer[0]`.
3. `step MlKemHashState.clone.spec`, `step MlKemHashState.get_alg.spec`,
   `step MlKemHashAlg.eq`, and `step massert.spec` to clone and validate
   the SHAKE256 base state.
4. Write the counter byte into the buffer, then
   `step Array.index_SliceIndexRangeUsizeSlice.step_spec` to expose the
   one-byte slice.
5. `step MlKemHashState.append.spec` — the PRF-state-threading step: the
   worker ghost becomes `g_base.append [(k+i : Byte)]`, while the
   invariant base `mkhs` / `g_base` remains the same for subsequent
   iterations.
6. `step UScalar.cast.spec` and `step Usize.mul.spec` to compute
   `64 * η₂`; then `step Array.index_mut_SliceIndexRangeUsizeSlice` and
   `step MlKemHashState.extract.spec` to squeeze those bytes.  With the
   SHAKE256 / PRF bridge, this is
   `MLKEM.PRF η₂ rOuter ((k params + i.val : ℕ) : Byte)`.
7. `step Array.to_slice.spec` and `step UScalar.cast.spec` for `η₂`.
8. `step mlkem.ntt.poly_element_sample_cbd_from_bytes.spec` into scratch
   `pe_tmp0`, yielding a well-formed polynomial with
   `toPoly = MLKEM.SamplePolyCBD (MLKEM.PRF η₂ rOuter (k+i))`.
9. `step UScalar.cast.spec` for `i`, `step Slice.index_mut_usize.spec` to
   borrow `pv_tmp[i]`, and `step mlkem.ntt.poly_element_add_in_place.spec`
   to compute `orig_slot + e₁_i`.
10. Apply the slice back function to store the sum at slot `i`.

Propagation: rebuild `encInvSampleE1Add` at `i.val + 1`.  The new-slot case
uses the CBD postcondition plus `poly_element_add_in_place.spec`; old
processed slots come from `h_inv` and the slice frame; untouched suffix
slots come from the back-function frame and the old rest clause.

At loop exit the invariant gives the spec-level e1-add conclusion: for
every slot, `pv_tmp[j] = orig_pv_tmp[j] + e₁[j]`, so the parent has
`u = INTT(Âᵀ · ŷ) + e₁` before `vector_compress_and_encode`.

Close with `split_conjs`, one focused `· agrind` per conjunct.  The PRF
monotonicity subgoal is closed by `MlKemHashState.append.spec` +
`MlKemHashState.extract.spec` and the PRF bridge; there is no separate
`PRNG.update.spec` in this file. -/
@[step]
theorem encapsulate_internal_loop1_body.spec
    (params : ParameterSet) (rOuter : 𝔹 32)
    (i : U8)
    (pk_mlkem_key : mlkem.key.Key)
    (mkhs : mlkem.hash.MlKemHashState)
    (cbd_sample_buffer : Array U8 193#usize)
    (orig_pv_tmp pv_tmp : Slice (PolyElement))
    (pe_tmp0 : PolyElement)
    (g_base : sha3.sha3_impl.GhostState)
    (h_wf : wfKey pk_mlkem_key params)
    (h_inv : encInvSampleE1Add params rOuter orig_pv_tmp pv_tmp i.val
              mkhs g_base)
    (h_orig_wf_all : ∀ (j : ℕ) (h_j : j < (k params : ℕ))
                      (_h_olen : orig_pv_tmp.length = (k params : ℕ)),
                      wfPoly (orig_pv_tmp.val[j]'(by
                        have := orig_pv_tmp.property; grind)))
    (h_i : i.val < (k params : ℕ))
    (h_eta2 : pk_mlkem_key.params.n_eta2.val = (η₂ : ℕ))
    (h_n_rows : pk_mlkem_key.params.n_rows.val = (k params : ℕ)) :
    encapsulate_internal_loop1_body pk_mlkem_key mkhs
        cbd_sample_buffer pv_tmp pe_tmp0 i
      ⦃ _mkhs' _buf' _pe' pv_tmp' =>
          encInvSampleE1Add params rOuter orig_pv_tmp pv_tmp'
            (i.val + 1) mkhs g_base ⦄ := by
  obtain ⟨h_pv_len, h_orig_len, h_i_le, h_abs, h_g_abs, h_alg, h_cbd, h_frame⟩ := h_inv
  rw [encaps_loop1_body.fold]
  -- Phase A: counter byte n_rows+i, clone+assert+append.
  have h_no_overflow : pk_mlkem_key.params.n_rows.val + i.val < 256 := by
    have h_k_le : (k params : ℕ) ≤ 4 := by rcases params <;> decide
    rw [h_n_rows]; omega
  step with encaps_loop1_phaseA.spec _ _ _ _ g_base h_abs h_alg h_no_overflow
    as ⟨cbd_sample_buffer1, mkhs3, h_alg3, counter, h_counter_val, h_abs3⟩
  -- Phase B: extract 64*η₂ bytes.
  have h_n_eta2_le : pk_mlkem_key.params.n_eta2.val ≤ 3 := by
    rw [h_eta2]; decide
  step with encaps_loop1_phaseB.spec _ _ _ _ h_abs3 h_alg3 h_n_eta2_le
    as ⟨_mkhs4, cbd_sample_buffer2, h_bytes⟩
  -- Phase C: sample one CBD polynomial into pe_tmp0.
  step with encaps_loop1_phaseC.spec _ _ _ h_eta2
    as ⟨pe_tmp01, h_pe_wf, h_pe_eq⟩
  -- Phase D: borrow pv_tmp[i], add_in_place, writeback.
  have h_i_lt_pv : i.val < pv_tmp.length := by
    rw [h_pv_len]; exact h_i
  have h_i_lt_val : i.val < pv_tmp.val.length := by
    rw [show pv_tmp.val.length = pv_tmp.length from rfl]; exact h_i_lt_pv
  have h_i_lt_orig_val : i.val < orig_pv_tmp.val.length := by
    rw [show orig_pv_tmp.val.length = orig_pv_tmp.length from rfl, h_orig_len]; exact h_i
  -- The frame says pv_tmp[i.val] = orig_pv_tmp[i.val], and orig is wfPoly.
  have h_pv_at_i_eq :
      pv_tmp.val[i.val]'h_i_lt_val =
      orig_pv_tmp.val[i.val]'h_i_lt_orig_val :=
    h_frame i.val h_i h_pv_len h_orig_len (Nat.le_refl _)
  have h_orig_wf_i : wfPoly (orig_pv_tmp.val[i.val]'h_i_lt_orig_val) :=
    h_orig_wf_all i.val h_i h_orig_len
  have h_pv_at_i_wf : wfPoly (pv_tmp.val[i.val]'h_i_lt_val) := by
    rw [h_pv_at_i_eq]; exact h_orig_wf_i
  step with encaps_loop1_phaseD.spec _ _ _ h_i_lt_pv h_pv_at_i_wf h_pe_wf
    as ⟨a1, new_pv_tmp, h_s4_eq, h_a1_wf, h_a1_eq⟩
  subst h_s4_eq
  -- Rebuild encInvSampleE1Add at i.val + 1.
  unfold encInvSampleE1Add
  have h_set_len' : (pv_tmp.set (UScalar.cast UScalarTy.Usize i) a1).val.length =
      pv_tmp.val.length := by
    simp [Aeneas.Std.Slice.set, Aeneas.Std.Slice.setAtNat]
  have h_set_slice_len : (pv_tmp.set (UScalar.cast UScalarTy.Usize i) a1).length =
      pv_tmp.length := by
    simp [Aeneas.Std.Slice.length, Aeneas.Std.Slice.set, Aeneas.Std.Slice.setAtNat]
  have h_cast_i_val : (UScalar.cast UScalarTy.Usize i).val = i.val := by simp
  refine ⟨?_, h_orig_len, by omega, h_abs, h_g_abs, h_alg, ?_, ?_⟩
  · -- length preserved
    rw [h_set_slice_len]; exact h_pv_len
  · -- cbd_new conjunct
    intro j h_j _h_len' _h_olen' h_j_lt
    by_cases h_j_lt_i : j < i.val
    · -- Old slot — use h_cbd plus frame.
      have h_j_ne : (UScalar.cast UScalarTy.Usize i).val ≠ j := by
        rw [h_cast_i_val]; omega
      have h_j_ne' : (i.val : ℕ) ≠ j := by omega
      have h_old := h_cbd j h_j h_pv_len h_orig_len h_j_lt_i
      have h_get_eq :
          (pv_tmp.set (UScalar.cast UScalarTy.Usize i) a1).val[j]'(by
            rw [h_set_len']; have := pv_tmp.property; grind) =
          pv_tmp.val[j]'(by have := pv_tmp.property; grind) := by
        simp [Aeneas.Std.Slice.set, Aeneas.Std.Slice.setAtNat]
        rw [List.getElem_set_ne h_j_ne']
      refine ⟨?_, h_old.2.1, ?_⟩
      · rw [h_get_eq]; exact h_old.1
      · rw [h_get_eq]; exact h_old.2.2
    · -- New slot j = i.val.
      have h_j_eq : j = i.val := by omega
      have h_eq_idx : (UScalar.cast UScalarTy.Usize i).val = j := by
        rw [h_cast_i_val]; omega
      have h_get_new :
          (pv_tmp.set (UScalar.cast UScalarTy.Usize i) a1).val[j]'(by
            rw [h_set_len']; have := pv_tmp.property; grind) = a1 := by
        simp [Aeneas.Std.Slice.set, Aeneas.Std.Slice.setAtNat,
              h_eq_idx]
      refine ⟨?_, ?_, ?_⟩
      · rw [h_get_new]; exact h_a1_wf
      · exact h_j_eq ▸ h_orig_wf_i
      · rw [h_get_new, h_a1_eq]
        -- Bridge: Vector.ofFn pointwise add → Polynomial.add (Vector.zipWith) +
        -- PRF↔SHAKE bridge for the η₂ sampling at counter byte (n_rows+i).
        -- We substitute j := ↑i first to eliminate motive-not-type-correct issues.
        subst h_j_eq
        rw [show (Vector.ofFn fun j => Vector.get (toPoly (pv_tmp.val[i.val]'h_i_lt_val)) j + Vector.get (toPoly pe_tmp01) j)
             = toPoly (pv_tmp.val[i.val]'h_i_lt_val) + toPoly pe_tmp01 from by
             apply Vector.ext
             intro k hk
             rw [Vector.getElem_ofFn]
             change _ = (toPoly (pv_tmp.val[i.val]'h_i_lt_val) + toPoly pe_tmp01)[k]
             show _ = (Polynomial.add _ _)[k]
             unfold Polynomial.add
             rw [Vector.getElem_zipWith]
             rfl,
            h_pv_at_i_eq, h_pe_eq]
        -- Goal now: toPoly orig_pv_tmp[↑i] + SamplePolyCBD(sliceWindowToSpecBytes ...)
        --        = toPoly orig_pv_tmp[↑i] + SamplePolyCBD(PRF η₂ rOuter ↑(↑(k params) + ↑i))
        -- Avoid `congr 1` (which triggers maxRecDepth on Polynomial.add); use congrArg.
        have h_sm : mkhs.state.squeeze_mode = false := by
          unfold mlkem.hash.MlKemHashState.absorbing at h_abs
          have h_weak : sha3.sha3_impl.absorbingWeak mkhs.state g_base := h_abs.1.1
          simpa using h_weak.2.1
        have h_eta2_disj : pk_mlkem_key.params.n_eta2.val = 2 ∨
                           pk_mlkem_key.params.n_eta2.val = 3 := by
          left; rw [h_eta2]; decide
        have h_counter_bv :
            counter.bv = (((k params : ℕ) + i.val : ℕ) : BitVec 8) := by
          apply BitVec.eq_of_toNat_eq
          rw [UScalar.bv_toNat, h_counter_val, h_n_rows]
          simp [BitVec.toNat_ofNat]
        have h_bridge :
            @MLKEM.SamplePolyCBD
                (cbdEta (UScalar.cast UScalarTy.U32 pk_mlkem_key.params.n_eta2)
                  (by simp; exact h_eta2_disj))
                (sliceWindowToSpecBytes cbd_sample_buffer2.to_slice 0
                  (64 * (pk_mlkem_key.params.n_eta2.val : ℕ)) (by grind))
              = @MLKEM.SamplePolyCBD η₂ (MLKEM.PRF η₂ rOuter counter.bv) := by
          apply prf_shake_samplePolyCBD_bridge_of_absorbing
            (cbdEta (UScalar.cast UScalarTy.U32 pk_mlkem_key.params.n_eta2)
              (by simp; exact h_eta2_disj))
            η₂ (by simp [cbdEta]; exact h_eta2)
            rOuter counter mkhs g_base h_abs h_alg h_g_abs
            mkhs.state.squeeze_mode h_sm cbd_sample_buffer2.to_slice
          intro k hk
          have h_kk : k < 64 * pk_mlkem_key.params.n_eta2.val := by
            simpa [cbdEta] using hk
          have := h_bytes k h_kk
          change (↑cbd_sample_buffer2)[k] =
            (extractOutput (g_base.append [counter] mkhs.state.squeeze_mode)
              (64 * pk_mlkem_key.params.n_eta2.val)).toList[k]
          exact this
        exact congrArg (toPoly ((↑orig_pv_tmp : List PolyElement)[i.val]'h_i_lt_orig_val) + ·)
          (by rw [h_bridge, h_counter_bv])
  · -- frame conjunct
    intro j h_j _h_len' _h_olen' h_j_ge
    have h_j_ne : (UScalar.cast UScalarTy.Usize i).val ≠ j := by
      rw [h_cast_i_val]; omega
    have h_j_ne' : (i.val : ℕ) ≠ j := by omega
    have h_get_eq :
        (pv_tmp.set (UScalar.cast UScalarTy.Usize i) a1).val[j]'(by
          rw [h_set_len']; have := pv_tmp.property; grind) =
        pv_tmp.val[j]'(by have := pv_tmp.property; grind) := by
      simp [Aeneas.Std.Slice.set, Aeneas.Std.Slice.setAtNat]
      rw [List.getElem_set_ne h_j_ne']
    rw [h_get_eq]
    exact h_frame j h_j h_pv_len h_orig_len (by omega)


/-! The `#decompose` declarations and `_loop1_match.fold` equation above
are consumed inside `mlkem.encapsulate_internal_loop1.spec`'s proof via
the canonical Variant B pattern (see `proof-patterns` skill): the loop
dispatch and per-slot body step are inlined there, so no standalone
`@[step]` spec is needed for `_match`. -/

/-- **Loop spec** for loop 1: run the `e₁` sampling-and-addition loop from
`iter.start` to `k params`.

The invariant `encInvSampleE1Add` carries both the ghost PRF state and the
partial result vector.  It records that the base SHAKE256 state `mkhs`
absorbs exactly `rOuter`, that every processed slot before `iter.start` is
`orig_pv_tmp[j] + SamplePolyCBD (PRF η₂ rOuter (k+j))`, and that every
unprocessed slot is unchanged from `orig_pv_tmp`.  The encapsulation
preamble initializes it at `iter.start = 0` immediately after
`vector_intt_and_mul_r`: the prefix is empty and the rest clause identifies
`pv_tmp` with `orig_pv_tmp`.

Informal proof. Canonical recursive Range-U8 loop (`proof-patterns`
"Loop — Canonical Template", Variant B). No separate
`_loop1_match.spec` is needed: the match dispatch is inlined.

- **Mandatory first step**: `rw [encapsulate_internal_loop1.fold]`. (Do
  NOT use `unfold`.) After the `(next iter)`
  step is consumed, `rw [encapsulate_internal_loop1_match.fold]` to
  expose the `_body` call.
- `step` to consume `next iter` (Range-U8 → `o, iter1`).
- `cases o`:
  - **`none` arm** (`iter.start = k params`): `_match`'s `none` body
    returns the current tuple; the post is `h_inv` at `iter.start.val =
    k params`; `agrind`.
  - **`some i` arm**: `i.val = iter.start.val`, `iter1.start.val =
    i.val + 1`; `step with encapsulate_internal_loop1_body.spec`
    (discharging `h_wf`, `h_i`, `h_eta2`, `h_n_rows`, `h_inv`); body
    post advances `encInvSampleE1Add` by one slot (`orig_pv_tmp[i] +
    SamplePolyCBD (PRF η₂ rOuter (k+i))`); `step*` closes the recursive
    `_loop1` call via the IH at `iter1`.
- `termination_by iter.«end».val - iter.start.val`; `decreasing_by agrind`.

At loop exit, `encInvSampleE1Add ... (k params)` gives
`pv_tmp = INTT(Âᵀ · ŷ) + e₁`, the `u` vector used by the subsequent
`vector_compress_and_encode` step and matching K-PKE.Encrypt Algorithm 14
steps 13–16 and 19.

Close with `split_conjs`; use focused `· agrind` blocks for structural
conjuncts, recursive-call preconditions, and termination / decreasing
obligations. -/
@[step]
theorem mlkem.encapsulate_internal_loop1.spec
    (params : ParameterSet) (rOuter : 𝔹 32)
    (pk_mlkem_key : mlkem.key.Key)
    (iter : core.ops.range.Range U8)
    (mkhs mkhs1 : mlkem.hash.MlKemHashState)
    (cbd_sample_buffer : Array U8 193#usize)
    (orig_pv_tmp pv_tmp : Slice (PolyElement))
    (pe_tmp0 : PolyElement)
    (g_base : sha3.sha3_impl.GhostState)
    (h_wf : wfKey pk_mlkem_key params)
    (h_inv : encInvSampleE1Add params rOuter orig_pv_tmp pv_tmp
              iter.start.val mkhs g_base)
    (h_orig_wf_all : ∀ (j : ℕ) (h_j : j < (k params : ℕ))
                      (_h_olen : orig_pv_tmp.length = (k params : ℕ)),
                      wfPoly (orig_pv_tmp.val[j]'(by
                        have := orig_pv_tmp.property; grind)))
    (h_iter_end : iter.«end».val = (k params : ℕ))
    (h_iter_start : iter.start.val ≤ (k params : ℕ))
    (h_eta2 : pk_mlkem_key.params.n_eta2.val = (η₂ : ℕ))
    (h_n_rows : pk_mlkem_key.params.n_rows.val = (k params : ℕ)) :
    mlkem.encapsulate_internal_loop1 pk_mlkem_key iter mkhs mkhs1
        cbd_sample_buffer pv_tmp pe_tmp0
      ⦃ _buf' pv_tmp' _pe' =>
          encInvSampleE1Add params rOuter orig_pv_tmp pv_tmp'
            (k params : ℕ) mkhs g_base ⦄ := by
  rw [encapsulate_internal_loop1.fold]
  by_cases hlt : iter.start.val < iter.«end».val
  · step with core.iter.range.IteratorRange.next_U8_some_spec iter hlt
      as ⟨o, iter1, ho, hstart1, hend1⟩
    simp only [ho]
    rw [encapsulate_internal_loop1_match.fold]
    have h_i_lt : iter.start.val < (k params : ℕ) := by rw [← h_iter_end]; exact hlt
    step with encapsulate_internal_loop1_body.spec params rOuter iter.start
      pk_mlkem_key mkhs cbd_sample_buffer orig_pv_tmp pv_tmp pe_tmp0 g_base
      h_wf h_inv h_orig_wf_all h_i_lt h_eta2 h_n_rows
      as ⟨mkhs4, cbd_buf2, pe_tmp01, new_pv_tmp, h_body_post⟩
    have hx_le : iter1.start.val ≤ (k params : ℕ) := by rw [hstart1, ← h_iter_end]; omega
    have h_inv' : encInvSampleE1Add params rOuter orig_pv_tmp new_pv_tmp iter1.start.val mkhs g_base := by
      rw [hstart1]; exact h_body_post
    apply mlkem.encapsulate_internal_loop1.spec
      params rOuter pk_mlkem_key iter1 mkhs mkhs4 cbd_buf2 orig_pv_tmp new_pv_tmp
      pe_tmp01 g_base h_wf h_inv' h_orig_wf_all (by rw [hend1]; exact h_iter_end) hx_le h_eta2 h_n_rows
  · step with core.iter.range.IteratorRange.next_U8_none_spec iter (by agrind)
      as ⟨o, iter1, ho, hiter1⟩
    simp only [ho]
    have h_eq : iter.start.val = (k params : ℕ) := by
      rw [h_iter_end] at hlt; omega
    rw [encapsulate_internal_loop1_match.fold]
    simp only [WP.spec_ok]
    rw [h_eq] at h_inv; exact h_inv
termination_by iter.«end».val - iter.start.val
decreasing_by
  rw [hstart1]
  scalar_tac


end Symcrust.Properties.MLKEM
