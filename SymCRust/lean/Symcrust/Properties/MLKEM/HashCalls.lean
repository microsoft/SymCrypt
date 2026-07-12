/-
  # HashCalls.lean — Layer-3 SHA3 hash composites for MLKEM.

  **Layer 2 (one theorem per `MlKemHashState` method) lives in
  `Hash.lean` — fully proved with ghost-state predicates
  `MlKemHashState.absorbing` / `squeezing` / `absorbingFor` /
  `freshFor`.**  This file holds **Layer 3** — MLKEM call-pattern
  composites that fuse Layer-2 method calls into a single FC
  equality against a FIPS 203 §3.4 hash flavour built on SHA3:

  * `H(x) = SHA3-256(x)` — `H(ek)`, public-key hash
  * `G(x) = SHA3-512(x)` — `(K̄, r) ← G(m ‖ H(ek))`

  SHAKE-based composites (`J`, `PRF_η`, `XOF`) live in
  `Bridges/PrfShake.lean`.

  Each composite assembles `init → append* → result/extract` via the
  proven Layer-2 specs in `Hash.lean` and discharges the chain to a
  direct equation `arrayToSpecBytes out = MLKEM.<flavour> input`,
  plus byte-wise/halve-wise projection helpers for the `G`
  decomposition `ρ ‖ σ`.
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Hash

namespace Symcrust.Properties.MLKEM

open Aeneas Aeneas.Std
open Spec
open scoped Spec.Notations
open symcrust

/-! ## SHA3-512 → `MLKEM.G` composites

`MLKEM.G(x) := (slice (SHA3-512 x) 0 32, slice (SHA3-512 x) 32 32)`.
These bridges connect the runtime SHA3-512 streaming chain
(a `Std.Array U8 64` produced by `init → append* → extract`) to the
spec-side `MLKEM.G` decomposition `(K̄ ‖ r) = ρ ‖ σ`.  Used identically
by `keyExpand.prelude.spec` (Key/Prelude.lean) and
`encapsInt.prelude.spec` (Encaps.lean). -/

/-- Bridge: `arrayToSpecBytes result = sha3_512 B` when `result.val` is
the `toList` of an `extractOutput` of a SHA3-512-shaped ghost state
whose absorbed bytes correspond byte-by-byte to the bit-vector `B`.

The proof works at the `.toList` level (rather than indexing into
the vector) to avoid the proof-irrelevance mismatch between
`i < ↑64#usize` and `i < 64`. -/
theorem arrayToSpecBytes_eq_sha3_512
    {n : ℕ} (result : Std.Array Std.U8 64#usize)
    (G : sha3.sha3_impl.GhostState)
    (h_result_val : (↑result : List Std.U8) =
      (sha3.sha3_impl.extractOutput G 64).toList)
    (B : 𝔹 n)
    (h_G_abs_len : G.absorbed.length = n)
    (h_per_byte : ∀ (i : Fin n),
      B.get i = (G.absorbed[i.val]'(h_G_abs_len ▸ i.isLt)).bv)
    (h_G_rate : G.rate = 72)
    (h_G_padVal : G.padVal = 6#u8)
    (h_G_squeezed : G.squeezed = []) :
    arrayToSpecBytes result = Spec.SHA3.sha3_512 B := by
  have h_sha3 := symcrust.mlkem.hash.sha3_512_extractOutput G B
    h_G_abs_len h_per_byte h_G_rate h_G_padVal h_G_squeezed
  rw [← Vector.toList_inj]
  have h_lhs : (arrayToSpecBytes result).toList =
      List.map (·.bv) (↑result : List Std.U8) := by
    unfold arrayToSpecBytes
    rw [Vector.toList_ofFn]
    have h_res_len : (↑result : List Std.U8).length = 64 := by
      have := result.property; simp_all
    apply List.ext_get
    · simp [h_res_len]
    · intro i _ _
      simp only [List.get_eq_getElem, List.getElem_ofFn, List.getElem_map]
  rw [h_lhs, h_result_val, ← Vector.toList_map, h_sha3]
  rfl

/-- Vector-level: `(MLKEM.G B).1 ‖ (MLKEM.G B).2 = sha3_512 B`.

`MLKEM.G B = (slice (sha3_512 B) 0 32, slice (sha3_512 B) 32 32)`.
Splicing the two halves back together recovers the original vector. -/
theorem MLKEM_G_append_eq_sha3_512 {n : ℕ} (B : 𝔹 n) :
    ((Spec.MLKEM.G B).1 ‖ (Spec.MLKEM.G B).2 :
        𝔹 64) =
      Spec.SHA3.sha3_512 B := by
  show ((slice (Spec.SHA3.sha3_512 B) 0 32) ‖
       (slice (Spec.SHA3.sha3_512 B) 32 32) : 𝔹 64) = _
  apply Vector.ext
  intro i hi
  show ((slice (Spec.SHA3.sha3_512 B) 0 32) ++
       (slice (Spec.SHA3.sha3_512 B) 32 32) : 𝔹 64)[i]'hi = _
  rw [Vector.getElem_append hi]
  by_cases h32 : i < 32
  · simp only [h32, ↓reduceDIte]
    unfold slice
    rw [Vector.getElem_ofFn]
    fcongr 1; simp
  · simp only [show ¬ i < 32 from h32, ↓reduceDIte]
    unfold slice
    rw [Vector.getElem_ofFn]
    fcongr 1; simp; omega

/-- toList-level: `(MLKEM.G x).2.toList = (sha3_512 x).toList.drop 32`.

Proved generic in the input bit-vector to avoid kernel whnf timeouts
when the input is a deep `++` of runtime conversions. -/
theorem MLKEM_G_snd_toList {n : ℕ} (x : 𝔹 n) :
    (Spec.MLKEM.G x).2.toList = (Spec.SHA3.sha3_512 x).toList.drop 32 := by
  apply List.ext_getElem
  · rw [List.length_drop, Vector.length_toList, Vector.length_toList]
  · intro i h1 h2
    rw [List.getElem_drop, Vector.getElem_toList, Vector.getElem_toList]
    show (Spec.slice _ 32 32)[i] = _
    unfold Spec.slice
    rw [Vector.getElem_ofFn]

/-- toList-level: `(MLKEM.G x).1.toList = (sha3_512 x).toList.take 32`.

Proved generic in the input bit-vector to avoid kernel whnf timeouts
when the input is a deep `++` of runtime conversions. -/
theorem MLKEM_G_fst_toList {n : ℕ} (x : 𝔹 n) :
    (Spec.MLKEM.G x).1.toList = (Spec.SHA3.sha3_512 x).toList.take 32 := by
  apply List.ext_getElem
  · simp [List.length_take, Vector.length_toList]
  · intro i h1 h2
    rw [List.getElem_take, Vector.getElem_toList, Vector.getElem_toList]
    show (Spec.slice _ 0 32)[i] = _
    unfold Spec.slice
    rw [Vector.getElem_ofFn]
    simp

/-- Vector-level: `(MLKEM.G x).1 = slice (sha3_512 x) 0 32`.
Definitional projection; useful to rewrite away `(MLKEM.G ·).1` before
elements are accessed via `[i]` (each such access would otherwise
re-trigger `MLKEM.G` whnf on the runtime argument). -/
theorem MLKEM_G_fst_eq_slice {n : ℕ} (x : 𝔹 n) :
    (Spec.MLKEM.G x).1 =
      Spec.slice (Spec.SHA3.sha3_512 x) 0 32 := rfl

/-- Vector-level: `(MLKEM.G x).2 = slice (sha3_512 x) 32 32`.
Symmetric companion to `MLKEM_G_fst_eq_slice`. -/
theorem MLKEM_G_snd_eq_slice {n : ℕ} (x : 𝔹 n) :
    (Spec.MLKEM.G x).2 =
      Spec.slice (Spec.SHA3.sha3_512 x) 32 32 := rfl

/-- σ-bridge: when a runtime slice `s13` is exactly the second half
(offset 32..64) of the SHA3-512 output `private_seed_hash1`, and
`arrayToSpecBytes private_seed_hash1` decomposes as `(G B).1 ‖ (G B).2`,
the value `σ = sliceToSpecBytes s13 32` matches the second half `(G B).2`.

Extracted as a top-level lemma so its proof has its own heartbeat
budget — the cumulative cost of `Vector.ext` + `Vector.getElem_append_right`
inside the giant `prelude.spec` elaboration unit hits the timeout. -/
theorem sigma_eq_G_snd
    {n : ℕ}
    (s13 : Slice U8)
    (private_seed_hash1 : Std.Array U8 64#usize)
    (B : 𝔹 n)
    (hs13_len : s13.length = 32)
    (h_s13_eq_drop_take : (↑s13 : List U8) =
        ((↑private_seed_hash1 : List U8).drop 32).take 32)
    (h_arr_decomp : arrayToSpecBytes private_seed_hash1 =
        (Spec.MLKEM.G B).1 ‖ (Spec.MLKEM.G B).2) :
    sliceToSpecBytes s13 32 hs13_len = (Spec.MLKEM.G B).2 := by
  have h_phs_len : (↑private_seed_hash1 : List U8).length = 64 := by grind
  -- Bridge to sha3_512 via MLKEM_G_append_eq_sha3_512.
  have h_arr_sha :
      arrayToSpecBytes private_seed_hash1 = Spec.SHA3.sha3_512 B := by
    rw [h_arr_decomp]; exact MLKEM_G_append_eq_sha3_512 B
  -- (G B).2 = slice (sha3_512 B) 32 32 (definitional).
  show sliceToSpecBytes s13 32 hs13_len =
       Spec.slice (Spec.SHA3.sha3_512 B) 32 32
  apply Vector.ext
  intro j hj
  -- Both sides unfold via Vector.getElem_ofFn.
  have h_lhs : (sliceToSpecBytes s13 32 hs13_len)[j] =
      ((↑s13 : List U8)[j]'(by show j < s13.length; omega)).bv := by
    simp [sliceToSpecBytes, Vector.getElem_ofFn]
  have h_s13_idx : (↑s13 : List U8)[j]'(by show j < s13.length; omega) =
      (↑private_seed_hash1 : List U8)[32 + j]'(by rw [h_phs_len]; omega) := by
    conv_lhs => rw [List.getElem_of_eq h_s13_eq_drop_take]
    rw [List.getElem_take, List.getElem_drop]
  have h_psh_bv : ((↑private_seed_hash1 : List U8)[32 + j]'(by rw [h_phs_len]; omega)).bv =
      (arrayToSpecBytes private_seed_hash1)[32 + j]'(by
        show 32 + j < (64#usize : Usize).val; simp; omega) := by
    simp [arrayToSpecBytes, Vector.getElem_ofFn]
  have h_rhs :
      (Spec.slice (Spec.SHA3.sha3_512 B) 32 32)[j] =
      (Spec.SHA3.sha3_512 B)[32 + j]'(by
        show 32 + j < 64; omega) := by
    unfold Spec.slice
    rw [Vector.getElem_ofFn]
  rw [h_lhs, h_s13_idx, h_psh_bv, h_arr_sha, h_rhs]
  rfl

set_option maxHeartbeats 1600000 in
/-- ρ-bridge: when `s10` is the first 32 bytes of the SHA3-512 output
`private_seed_hash1`, and `arrayToSpecBytes private_seed_hash1`
decomposes as `(G B).1 ‖ (G B).2`, then the array reconstructed by
`from_slice s10` encodes to `ρ = (G B).1`.

Extracted as a top-level lemma to keep its proof's heartbeat budget
isolated from the giant `prelude.spec` elaboration unit. -/
theorem rho_eq_G_fst
    {n : ℕ}
    (s10 : Slice U8)
    (private_seed_hash1 : Std.Array U8 64#usize)
    (pub : Std.Array U8 32#usize)
    (B : 𝔹 n)
    (hs10_len : s10.length = 32)
    (h_s10_eq_take : (↑s10 : List U8) =
        (↑private_seed_hash1 : List U8).take 32)
    (h_arr_decomp : arrayToSpecBytes private_seed_hash1 =
        (Spec.MLKEM.G B).1 ‖ (Spec.MLKEM.G B).2) :
    arrayToSpecBytes (pub.from_slice s10) = (Spec.MLKEM.G B).1 := by
  have h_phs_len : (↑private_seed_hash1 : List U8).length = 64 := by
    have := private_seed_hash1.property; grind
  have h_arr_sha :
      arrayToSpecBytes private_seed_hash1 = Spec.SHA3.sha3_512 B := by
    rw [h_arr_decomp]; exact MLKEM_G_append_eq_sha3_512 B
  have h_s10_val_len : (↑s10 : List U8).length = (32#usize : Usize).val := by
    have : (↑s10 : List U8).length = s10.length := rfl
    rw [this, hs10_len]; decide
  have h_from_val : (pub.from_slice s10).val = (↑s10 : List U8) := by
    exact Aeneas.Std.Array.from_slice_val pub s10 h_s10_val_len
  -- Reduce target to a Vector equality on slice of sha3_512.
  show arrayToSpecBytes (pub.from_slice s10) =
       Spec.slice (Spec.SHA3.sha3_512 B) 0 32
  apply Vector.ext
  intro j hj
  have hj' : j < 32 := by simpa using hj
  -- LHS: arrayToSpecBytes (from_slice pub s10) [j]
  have h_lhs : (arrayToSpecBytes (pub.from_slice s10))[j] =
      ((↑s10 : List U8)[j]'(by show j < s10.length; rw [hs10_len]; exact hj')).bv := by
    simp [arrayToSpecBytes, Vector.getElem_ofFn]
    rw [List.getElem_of_eq h_from_val.symm]
  have h_s10_idx : (↑s10 : List U8)[j]'(by show j < s10.length; rw [hs10_len]; exact hj') =
      (↑private_seed_hash1 : List U8)[j]'(by rw [h_phs_len]; omega) := by
    conv_lhs => rw [List.getElem_of_eq h_s10_eq_take]
    rw [List.getElem_take]
  have h_psh_bv : ((↑private_seed_hash1 : List U8)[j]'(by rw [h_phs_len]; omega)).bv =
      (arrayToSpecBytes private_seed_hash1)[j]'(by
        show j < (64#usize : Usize).val; simp; omega) := by
    simp [arrayToSpecBytes, Vector.getElem_ofFn]
  have h_rhs :
      (Spec.slice (Spec.SHA3.sha3_512 B) 0 32)[j] =
      (Spec.SHA3.sha3_512 B)[j]'(by omega) := by
    simp [Spec.slice]
  rw [h_lhs, h_s10_idx, h_psh_bv, h_arr_sha]
  exact h_rhs.symm

/-! ## SHA3-256 → `MLKEM.H` composite

`MLKEM.H(x) := SHA3-256(x)`.  This is the SHA3-256 sibling of
`arrayToSpecBytes_eq_sha3_512`: it discharges the FC equality
`arrayToSpecBytes result = sha3_256 B` for a runtime `Std.Array U8 32`
extracted from a SHA3-256-shaped ghost state.  Reused by
`key_compute_encap_hash` in `Sampling/ExpandMatrix.lean` to close
the `encaps_key_hash.toSpec = SHA3-256(encapsulationKey ...)`
postcondition. -/

/-- Bridge: `arrayToSpecBytes result = sha3_256 B` when `result.val` is
the `toList` of an `extractOutput` of a SHA3-256-shaped ghost state
whose absorbed bytes correspond byte-by-byte to the bit-vector `B`.

Direct analogue of `arrayToSpecBytes_eq_sha3_512`; only the output
length (32 vs 64), rate (136 vs 72), and the underlying
`sha3_256_extractOutput` bridge differ. -/
theorem arrayToSpecBytes_eq_sha3_256
    {n : ℕ} (result : Std.Array Std.U8 32#usize)
    (G : sha3.sha3_impl.GhostState)
    (h_result_val : (↑result : List Std.U8) =
      (sha3.sha3_impl.extractOutput G 32).toList)
    (B : 𝔹 n)
    (h_G_abs_len : G.absorbed.length = n)
    (h_per_byte : ∀ (i : Fin n),
      B.get i = (G.absorbed[i.val]'(h_G_abs_len ▸ i.isLt)).bv)
    (h_G_rate : G.rate = 136)
    (h_G_padVal : G.padVal = 6#u8)
    (h_G_squeezed : G.squeezed = []) :
    arrayToSpecBytes result = Spec.SHA3.sha3_256 B := by
  have h_sha3 := symcrust.mlkem.hash.sha3_256_extractOutput G B
    h_G_abs_len h_per_byte h_G_rate h_G_padVal h_G_squeezed
  rw [← Vector.toList_inj]
  have h_lhs : (arrayToSpecBytes result).toList =
      List.map (·.bv) (↑result : List Std.U8) := by
    unfold arrayToSpecBytes
    rw [Vector.toList_ofFn]
    have h_res_len : (↑result : List Std.U8).length = 32 := by
      have := result.property; simp_all
    apply List.ext_get
    · simp [h_res_len]
    · intro i _ _
      simp only [List.get_eq_getElem, List.getElem_ofFn, List.getElem_map]
  rw [h_lhs, h_result_val, ← Vector.toList_map, h_sha3]
  rfl

/-- Composite bridge: `arrayToSpecBytes (a.from_slice s3) = sha3_256 B`
when `s3` carries the SHA3-256 output and the absorbed ghost state
matches `B`.  Packages `arrayToSpecBytes_eq_sha3_256` with the
`from_slice` view: the caller passes the underlying `a : Std.Array U8 32`
(the receiving buffer, e.g., `pk.encaps_key_hash`) and the slice `s3`
that carries the extracted bytes; the helper discharges the
`(↑(a.from_slice s3) : List U8) = (extractOutput G 32).toList` chain
internally.

This is the entry point used by `key_compute_encap_hash` in
`Sampling/ExpandMatrix.lean` to close the
`encaps_key_hash.toSpec = SHA3-256 (encapsulationKey ...)` post. -/
theorem arrayToSpecBytes_from_slice_eq_sha3_256
    {n : ℕ}
    (a : Std.Array U8 32#usize) (s3 : Slice U8)
    (h_s3_len : s3.length = 32)
    (G : sha3.sha3_impl.GhostState)
    (h_s3_val : (↑s3 : List U8) = (sha3.sha3_impl.extractOutput G 32).toList)
    (B : 𝔹 n)
    (h_G_abs_len : G.absorbed.length = n)
    (h_per_byte : ∀ (i : Fin n),
      B.get i = (G.absorbed[i.val]'(h_G_abs_len ▸ i.isLt)).bv)
    (h_G_rate : G.rate = 136)
    (h_G_padVal : G.padVal = 6#u8)
    (h_G_squeezed : G.squeezed = []) :
    arrayToSpecBytes (a.from_slice s3) = Spec.SHA3.sha3_256 B := by
  have h_arr_val : (a.from_slice s3).val = (↑s3 : List U8) :=
    Std.Array.from_slice_val a s3 (by simp [h_s3_len])
  refine arrayToSpecBytes_eq_sha3_256 (a.from_slice s3) G ?_
    B h_G_abs_len h_per_byte h_G_rate h_G_padVal h_G_squeezed
  show (a.from_slice s3).val = _
  rw [h_arr_val]; exact h_s3_val

end Symcrust.Properties.MLKEM
