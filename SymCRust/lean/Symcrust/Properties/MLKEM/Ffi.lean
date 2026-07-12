/-
  # Ffi.lean — FFI surface and size-query helpers.

  These functions are the lightweight "shape" of the public ML-KEM
  API: size queries, key allocation, and parameter dispatchers.  No
  loops; specs are anchored on
  `MLKEM.{Param.k, sizeof_*, ParameterSet}` from
  `lean/Symcrust/Spec/MLKEM/Spec.lean`.

  ## Functions covered

  * `mlkem.sizeof_encoded_uncompressed_vector`
  * `mlkem.sizeof_format_decapsulation_key`
  * `mlkem.sizeof_format_encapsulation_key`
  * `mlkem.sizeof_key_format_from_params`
  * `mlkem.sizeof_ciphertext_from_params`
  * `mlkem.key.get_internal_params_from_params`
  * `mlkem.key.key_allocate`
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.KeyView
import Symcrust.Properties.MLKEM.Axioms.BoxDefault

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust

open symcrust.common
namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 4000000
set_option maxRecDepth 2048

/-! ## Sizeof helpers -/

/-- **`sizeof_encoded_uncompressed_vector n = 384 * n`**.  This is
the bit-packing for an unsigned 12-bit vector of `n` polynomials.

Informal proof.  After `unfold mlkem.sizeof_encoded_uncompressed_vector`,
the goal is a single monadic step `384#usize * n`.  Apply `step` with
`Usize.mul_spec`; the no-overflow side condition `384 * n.val ≤
Usize.max` follows from `h_bound : n.val ≤ 4` by `agrind`.  The
postcondition `r.val = 384 * n.val` holds directly from the
multiplication spec. -/
@[step]
theorem mlkem.sizeof_encoded_uncompressed_vector.spec (n : Usize)
    (h_bound : n.val ≤ 4) :
    mlkem.sizeof_encoded_uncompressed_vector n
      ⦃ (r : Usize) => r.val = 384 * n.val ⦄ := by
  unfold mlkem.sizeof_encoded_uncompressed_vector
  step
  scalar_tac

/-- **Encoded decapsulation key size**: `2 * 384 * n + 3 * 32`.

Informal proof.  After `unfold mlkem.sizeof_format_decapsulation_key`:
(1) `step` with `sizeof_encoded_uncompressed_vector.spec` (precondition
`h_bound`): gives `i.val = 384 * n.val`.
(2) `step` with `Usize.mul_spec` for `2#usize * i`: gives
`i1.val = 768 * n.val`; overflow from `h_bound` and `agrind`.
(3) `step` on `3#usize * 32#usize`: literal multiplication, no overflow.
(4) `step` with `Usize.add_spec` for `i1 + i2`: result
`r.val = 768 * n.val + 96 = 2 * 384 * n.val + 3 * 32`; overflow
from `h_bound` and `agrind`. -/
@[step]
theorem mlkem.sizeof_format_decapsulation_key.spec (n : Usize)
    (h_bound : n.val ≤ 4) :
    mlkem.sizeof_format_decapsulation_key n
      ⦃ (r : Usize) => r.val = 2 * 384 * n.val + 3 * 32 ⦄ := by
  unfold mlkem.sizeof_format_decapsulation_key
  step
  step
  step
  step
  scalar_tac

/-- **Encoded encapsulation key size**: `384 * n + 32`.

Informal proof.  After `unfold mlkem.sizeof_format_encapsulation_key`:
(1) `step` with `sizeof_encoded_uncompressed_vector.spec` (precondition
`h_bound`): gives `i.val = 384 * n.val`.
(2) `step` with `Usize.add_spec` for `i + 32#usize`: gives
`r.val = 384 * n.val + 32`; overflow from `h_bound`
(`384 * 4 + 32 = 1568 ≤ Usize.max`) by `agrind`. -/
@[step]
theorem mlkem.sizeof_format_encapsulation_key.spec (n : Usize)
    (h_bound : n.val ≤ 4) :
    mlkem.sizeof_format_encapsulation_key n
      ⦃ (r : Usize) => r.val = 384 * n.val + 32 ⦄ := by
  unfold mlkem.sizeof_format_encapsulation_key
  step
  step
  scalar_tac

/-! ## Parameter dispatch -/

/-- **Spec for `get_internal_params_from_params`**.

Maps each `Params` variant to the canonical `INTERNAL_PARAMS_*`
record.  The resulting `InternalParams` satisfies
`wfInternalParams r (paramsToSpec params)`.

Informal proof.  After `unfold mlkem.key.get_internal_params_from_params`,
the goal is a three-way match; each branch is `ok INTERNAL_PARAMS_MLKEM*`.
`step*` (or a single `step` per branch) closes the WP sub-goal with
`WP.spec_ok`.  The residual goal is `wfInternalParams INTERNAL_PARAMS_*
(paramsToSpec params) ∧ r.params = params`; both conjuncts hold for
each concrete constant by `native_decide` (all three records are
fully-reduced ground terms). -/
@[step]
theorem mlkem.key.get_internal_params_from_params.spec
    (params : mlkem.key.Params) :
    mlkem.key.get_internal_params_from_params params
      ⦃ (r : mlkem.key.InternalParams) =>
          wfInternalParams r (paramsToSpec params) ∧
          r.params = params ⦄ := by
  unfold mlkem.key.get_internal_params_from_params
  match params with
  | mlkem.key.Params.MlKem512 =>
    refine ⟨?_, ?_⟩
    · simp [wfInternalParams]
    · simp [mlkem.key.INTERNAL_PARAMS_MLKEM512]
  | mlkem.key.Params.MlKem768 =>
    refine ⟨?_, ?_⟩
    · simp [wfInternalParams]
    · simp [mlkem.key.INTERNAL_PARAMS_MLKEM768]
  | mlkem.key.Params.MlKem1024 =>
    refine ⟨?_, ?_⟩
    · simp [wfInternalParams]
    · simp [mlkem.key.INTERNAL_PARAMS_MLKEM1024]

/-- **Top spec for `sizeof_key_format_from_params`**.

Returns the encoded byte size for the given `(params, format)`
pair, per FIPS 203 Table 2 with `k := k (paramsToSpec params)`.

Informal proof.  After `unfold mlkem.sizeof_key_format_from_params`:
(1) `step` with `get_internal_params_from_params.spec`: gives
`wfInternalParams ip p` and `ip.params = params`; from
`wfInternalParams` extract `ip.n_rows.val = k p`.
(2) Case-split on `format`:
  * `PrivateSeed`: evaluate `SIZEOF_FORMAT_PRIVATE_SEED = 64` by
    unfolding the irreducible constant; `agrind`.
  * `DecapsulationKey`: `lift (UScalar.cast .Usize ip.n_rows)`
    (no overflow: `ip.n_rows.val ≤ 4` from `wfInternalParams`),
    then `step` with `sizeof_format_decapsulation_key.spec`
    (precondition `i.val ≤ 4`); `agrind`.
  * `EncapsulationKey`: same cast, then `step` with
    `sizeof_format_encapsulation_key.spec`; `agrind`. -/
@[step]
theorem mlkem.sizeof_key_format_from_params.spec
    (params : mlkem.key.Params) (format : mlkem.key.Format) :
    mlkem.sizeof_key_format_from_params params format
      ⦃ (r : Usize) =>
          let kn := (k (paramsToSpec params) : ℕ)
          match format with
          | mlkem.key.Format.PrivateSeed     => r.val = 64
          | mlkem.key.Format.DecapsulationKey => r.val = 2 * 384 * kn + 3 * 32
          | mlkem.key.Format.EncapsulationKey => r.val = 384 * kn + 32 ⦄ := by
  unfold mlkem.sizeof_key_format_from_params
  step
  have hk := k_le_4 (paramsToSpec params)
  have hn := internal_params_post1.n_rows_val
  match format with
  | mlkem.key.Format.PrivateSeed =>
    unfold mlkem.SIZEOF_FORMAT_PRIVATE_SEED
    step
    scalar_tac
  | mlkem.key.Format.DecapsulationKey =>
    step
    have hr : r.val = internal_params.n_rows.val := by simp [r_post]
    step
    scalar_tac
  | mlkem.key.Format.EncapsulationKey =>
    step
    have hr : r.val = internal_params.n_rows.val := by simp [r_post]
    step
    scalar_tac

/-- **Top spec for `sizeof_ciphertext_from_params`**.

Returns `32 * (dᵤ p * k p + dᵥ p)` (FIPS 203 §4.2.2 ciphertext size):
- MLKEM-512:  32 * (10*2 + 4)  = 768
- MLKEM-768:  32 * (10*3 + 4)  = 1088
- MLKEM-1024: 32 * (11*4 + 5)  = 1568

Informal proof.  After `unfold mlkem.sizeof_ciphertext_from_params`:
(1) `step` with `get_internal_params_from_params.spec`: gives
`wfInternalParams ip p`; note `ip.n_rows.val = k p`,
`ip.n_bits_of_u.val = dᵤ p`, `ip.n_bits_of_v.val = dᵥ p`.
(2–4) `step` through three `lift (UScalar.cast .Usize ...)` calls for
`n_rows`, `n_bits_of_u`, `n_bits_of_v`; each fits in `Usize` since
the values are ≤ 11 per `wfInternalParams`.
(5–8) Arithmetic steps for `n_rows * n_bits_of_u`, the constant
`MLWE_POLYNOMIAL_COEFFICIENTS / 8 = 32` (unfold the `@[irreducible]`
constant or use `native_decide`), `cb_u = k * dᵤ * 32`, and
`cb_v = dᵥ * 32`.
(9) Three `massert` checks: case-split on `params`; each asserts
`cb_u_concrete + cb_v_concrete = CIPHERTEXT_SIZE_*_concrete`;
discharge each branch by `native_decide` after unfolding the
relevant `@[irreducible]` `CIPHERTEXT_SIZE_*` constant.
(10) Final `Usize.add_spec` step: `r.val = k * dᵤ * 32 + dᵥ * 32 =
32 * (dᵤ * k + dᵥ)`; `agrind`. -/
@[step]
theorem mlkem.sizeof_ciphertext_from_params.spec
    (params : mlkem.key.Params) :
    mlkem.sizeof_ciphertext_from_params params
      ⦃ (r : Usize) =>
          let p := paramsToSpec params
          r.val = 32 * (dᵤ p * (k p : ℕ) + dᵥ p) ⦄ := by
  unfold mlkem.sizeof_ciphertext_from_params
  step
  step; step; step; step; step; step; step
  have hpe := internal_params_post1.params_eq
  have hk := internal_params_post1.n_rows_val
  have hdu := internal_params_post1.n_bits_of_u_val
  have hdv := internal_params_post1.n_bits_of_v_val
  -- Each Params.ne step yields `b_post : b = decide (paramsX ≠ Y)` which
  -- simp can reduce to `true` or `false`; the if-then-else then opens up
  -- and the inner massert (when needed) is discharged via the cb_u/cb_v
  -- values + scalar_tac.
  match params with
  | mlkem.key.Params.MlKem512 =>
    simp only [hpe, specToRustParams] at *
    step; simp [b_post]
    step
    step by (simp [mlkem.CIPHERTEXT_SIZE_MLKEM512,
      mlkem.key.MLWE_POLYNOMIAL_COEFFICIENTS] at *; scalar_tac)
    step; simp [b1_post]
    step; simp [b2_post]
    step
    simp only [paramsToSpec, dᵤ, dᵥ,
      mlkem.key.MLWE_POLYNOMIAL_COEFFICIENTS] at *
    scalar_tac
  | mlkem.key.Params.MlKem768 =>
    simp only [hpe, specToRustParams] at *
    step; simp [b_post]
    step; simp [b1_post]
    step
    step by (simp [mlkem.CIPHERTEXT_SIZE_MLKEM768,
      mlkem.key.MLWE_POLYNOMIAL_COEFFICIENTS] at *; scalar_tac)
    step; simp [b2_post]
    step
    simp only [paramsToSpec, dᵤ, dᵥ,
      mlkem.key.MLWE_POLYNOMIAL_COEFFICIENTS] at *
    scalar_tac
  | mlkem.key.Params.MlKem1024 =>
    simp only [hpe, specToRustParams] at *
    step; simp [b_post]
    step; simp [b1_post]
    step; simp [b2_post]
    step
    step by (simp [mlkem.CIPHERTEXT_SIZE_MLKEM1024,
      mlkem.key.MLWE_POLYNOMIAL_COEFFICIENTS] at *; scalar_tac)
    step
    simp only [paramsToSpec, dᵤ, dᵥ,
      mlkem.key.MLWE_POLYNOMIAL_COEFFICIENTS] at *
    scalar_tac

/-! ## Key allocation -/

/-- **Spec for `key_allocate`**.

Boxes a fresh `mlkem.key.Key` initialised via
`Key.Insts.SymcrustCommonBoxDefault.box_default` (zero-filled
buffers + algorithm-stamped `params` / `n_rows` fields).
May fail with `MemoryAllocationFailure`.

Informal proof.  After `unfold mlkem.key.key_allocate`:
(1) `step` with `try_new_box_default.Key.spec`: gives either
`Ok key` (with `key.data = ZeroPolyVec 24`) or
`Err MemoryAllocationFailure`.
(2) Case on `r`:
  * `Err` branch: postcondition `e = MemoryAllocationFailure ∧
    out_of_memory` is immediate from the step postcondition; `agrind`.
  * `Ok key` branch: every `data` slot is `ZeroPoly`, hence `wfPoly`
    by `wfPoly_zeroPoly`.  Case-split on `params`; each variant
    performs `lift (UScalar.cast .Usize INTERNAL_PARAMS_*.n_rows)`
    (no overflow: `n_rows.val ≤ 4`) then returns
    `Ok { key with params := INTERNAL_PARAMS_*, n_rows := i }`.
    `wfKey key' p` follows from: `wfInternalParams INTERNAL_PARAMS_*
    p` (by `native_decide`), `wfPoly` on all data slots, and
    `n_rows.val = k p` from `wfInternalParams`; close by `agrind`. -/
@[step]
theorem mlkem.key.key_allocate.spec (params : mlkem.key.Params) :
    mlkem.key.key_allocate params
      ⦃ (r : core.result.Result mlkem.key.Key common.Error) =>
          match r with
          | core.result.Result.Ok key =>
              wfKey key (paramsToSpec params) ∧
              key.params.params = params
          | core.result.Result.Err e =>
              e = Error.MemoryAllocationFailure ∧ out_of_memory ⦄ := by
  unfold mlkem.key.key_allocate
  step
  cases r with
  | Err e =>
    exact r_post
  | Ok key =>
    simp only at r_post
    have hlen : key.data.val.length = 24 := key.data.property
    have hdata : ∀ (i : ℕ) (h : i < key.data.val.length),
        wfPoly (key.data.val[i]'h) := by
      intro i h
      have hz : key.data.val[i]'h = ZeroPoly := by
        simp only [r_post, ZeroPolyVec, Array.repeat_val, List.getElem_replicate]
      rw [hz]; exact wfPoly_zeroPoly
    match params with
    | mlkem.key.Params.MlKem512 =>
      step
      have hwf : wfInternalParams mlkem.key.INTERNAL_PARAMS_MLKEM512
                   (paramsToSpec mlkem.key.Params.MlKem512) := by
        unfold wfInternalParams paramsToSpec; rfl
      have hk2 := k_sq_plus_2k_le_24 (paramsToSpec mlkem.key.Params.MlKem512)
      refine ⟨⟨hwf, ?_, ?_⟩, ?_⟩
      · have hnr := hwf.n_rows_val
        simp only [r_post]; scalar_tac
      · intro j hj
        exact hdata j (by unfold dataEnd matrixLen at hj; rw [hlen]; grind)
      · exact hwf.params_eq
    | mlkem.key.Params.MlKem768 =>
      step
      have hwf : wfInternalParams mlkem.key.INTERNAL_PARAMS_MLKEM768
                   (paramsToSpec mlkem.key.Params.MlKem768) := by
        unfold wfInternalParams paramsToSpec; rfl
      have hk2 := k_sq_plus_2k_le_24 (paramsToSpec mlkem.key.Params.MlKem768)
      refine ⟨⟨hwf, ?_, ?_⟩, ?_⟩
      · have hnr := hwf.n_rows_val
        simp only [r_post]; scalar_tac
      · intro j hj
        exact hdata j (by unfold dataEnd matrixLen at hj; rw [hlen]; grind)
      · exact hwf.params_eq
    | mlkem.key.Params.MlKem1024 =>
      step
      have hwf : wfInternalParams mlkem.key.INTERNAL_PARAMS_MLKEM1024
                   (paramsToSpec mlkem.key.Params.MlKem1024) := by
        unfold wfInternalParams paramsToSpec; rfl
      have hk2 := k_sq_plus_2k_le_24 (paramsToSpec mlkem.key.Params.MlKem1024)
      refine ⟨⟨hwf, ?_, ?_⟩, ?_⟩
      · have hnr := hwf.n_rows_val
        simp only [r_post]; scalar_tac
      · intro j hj
        exact hdata j (by unfold dataEnd matrixLen at hj; rw [hlen]; grind)
      · exact hwf.params_eq

end Symcrust.Properties.MLKEM
