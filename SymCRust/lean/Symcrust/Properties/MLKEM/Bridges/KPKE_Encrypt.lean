/-
  # Bridges/KPKE_Encrypt.lean — pure-form rewrite of `K_PKE.Encrypt`.

  Provides `K_PKE.Encrypt_pure` (a pure version of `Spec.MLKEM.K_PKE.Encrypt`
  using `Matrix.of` / `Vector.ofFn` directly in place of the three nested
  `Id.run do` for-loops that construct `Â`, `y`, and `e₁`) and the equivalence
  theorem `K_PKE.Encrypt_eq_pure`.

  Consumers (notably the outer-chain residual at `Encaps.lean:3271`) can rewrite
  `K_PKE.Encrypt` → `K_PKE.Encrypt_pure` exposing the `(c₁ ‖ c₂).cast _` shape
  needed to match impl-side equalities `h_c1_impl`, `h_c2_impl`, plus the
  semantic equalities `h_u_value`, `h_v_value`.

  The proof reduces to three per-k unroll lemmas (k ∈ {2,3,4}), mirroring the
  `MulVectorNTT_get_eq_<k>` template in `Bridges/NttLinearity.lean`.
-/
import Symcrust.Properties.MLKEM.Basic.Params

open Aeneas Aeneas.Std Result
open scoped Spec.Notations
open Spec
open Spec.MLKEM
open Symcrust

namespace Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 1000000
set_option maxRecDepth 2048

/-! ## Pure-form `K_PKE.Encrypt`

Hand-rewrites the three `Id.run do` for-loops in `Spec.MLKEM.K_PKE.Encrypt`
(Spec.lean L528-L552, FIPS 203 Algorithm 14) to `Matrix.of` / `Vector.ofFn`
shape.  All other steps (`ByteDecode`, `slice`, `SamplePolyCBD` for `e₂`,
`NTT`, arithmetic, `ByteEncode`, `Compress`, final cast) are textually the
same. -/
def K_PKE.Encrypt_pure (p : ParameterSet)
    (ekPKE : 𝔹 (384 * k p + 32)) (m : 𝔹 32) (r : 𝔹 32) :
    𝔹 (32 * (dᵤ p * k p + dᵥ p)) :=
  let «t̂» := PolyVector.ByteDecode 12 (slice ekPKE 0 (384 * k p))
  let ρ := slice ekPKE (384 * k p) 32
  let «Â» : PolyMatrix q (k p) :=
    Matrix.of fun (i : Fin (k p)) (j : Fin (k p)) =>
      SampleNTT (ρ ‖ #v[((j : ℕ) : Byte)] ‖ #v[((i : ℕ) : Byte)])
  let y : PolyVector q (k p) :=
    Vector.ofFn fun (i : Fin (k p)) =>
      SamplePolyCBD (PRF (η₁ p) r ((i.val : ℕ) : Byte))
  let e₁ : PolyVector q (k p) :=
    Vector.ofFn fun (i : Fin (k p)) =>
      SamplePolyCBD (PRF η₂ r ((((k p : ℕ) + i.val : ℕ) : Byte)))
  let e₂ := SamplePolyCBD (PRF η₂ r (((2 * (k p : ℕ) : ℕ) : Byte)))
  let «ŷ» := PolyVector.NTT y
  let u := PolyVector.NTTInv (Matrix.transpose «Â» * «ŷ») + e₁
  let μ := Polynomial.Decompress 1 (ByteDecode (m.cast (by grind)))
  let v := NTTInv (PolyVector.innerProductNTT «t̂» «ŷ») + e₂ + μ
  let c₁ := PolyVector.ByteEncode (dᵤ p) (PolyVector.Compress (dᵤ p) u)
  let c₂ := ByteEncode (dᵥ p) (Polynomial.Compress (dᵥ p) v)
  (c₁ ‖ c₂).cast (by cases p <;> simp [dᵤ, dᵥ])

/-! ## Bridge theorem: `K_PKE.Encrypt` equals `K_PKE.Encrypt_pure`

Reduces the three nested `Id.run do` for-loops in
`Spec.MLKEM.K_PKE.Encrypt` to the `Matrix.of` / `Vector.ofFn` shapes used
by `Encrypt_pure`.  Mechanisation strategy mirrors
`MulVectorNTT_get_eq_<k>` (`Bridges/NttLinearity.lean:473-553`):

Per `p : ParameterSet` (k ∈ {2,3,4}), unroll
`Aeneas.SRRange.forIn'_eq_forIn'_range'` and `List.forIn'_cons/nil` to
expose the concrete update chain, then reduce `PolyMatrix.update` /
`PolyVector.set` and project rows via `Matrix.ext` / `Vector.ext`.
-/

/- k=2 case of `K_PKE.Encrypt_eq_pure`. -/
set_option maxHeartbeats 4000000 in
private theorem Encrypt_eq_pure_512
    (ekPKE : 𝔹 (384 * k .ML_KEM_512 + 32)) (m : 𝔹 32) (r : 𝔹 32) :
    Spec.MLKEM.K_PKE.Encrypt .ML_KEM_512 ekPKE m r =
      K_PKE.Encrypt_pure .ML_KEM_512 ekPKE m r := by
  unfold Spec.MLKEM.K_PKE.Encrypt K_PKE.Encrypt_pure
  simp only [Id.run, Aeneas.SRRange.forIn'_eq_forIn'_range', Aeneas.SRRange.size,
             show ∀ (n : Nat), (n - 0 + 1 - 1) / 1 = n from fun _ => by omega,
             List.range', List.forIn'_cons, List.forIn'_nil, pure_bind]
  -- Three sub-equalities: Â-matrix, y-vector, e₁-vector. Both halves of
  -- the final `(c₁ ‖ c₂).cast` share `y` (via `ŷ` in c₂) so we handle it once.
  have h_A : ((((PolyMatrix.zero q (k ParameterSet.ML_KEM_512)).update 0 0
                    (SampleNTT (slice ekPKE (384 * 2) 32 (by simp) ‖
                      #v[((0 : Nat) : Byte)] ‖ #v[((0 : Nat) : Byte)]))).update
                  0 (0 + 1) (SampleNTT (slice ekPKE (384 * 2) 32 (by simp) ‖
                    #v[(((0 + 1 : Nat) : Byte))] ‖ #v[((0 : Nat) : Byte)]))).update
                (0 + 1) 0 (SampleNTT (slice ekPKE (384 * 2) 32 (by simp) ‖
                  #v[((0 : Nat) : Byte)] ‖ #v[(((0 + 1 : Nat) : Byte))]))).update
            (0 + 1) (0 + 1) (SampleNTT (slice ekPKE (384 * 2) 32 (by simp) ‖
              #v[(((0 + 1 : Nat) : Byte))] ‖ #v[(((0 + 1 : Nat) : Byte))]))
        = (Matrix.of fun (i : Fin (k ParameterSet.ML_KEM_512))
                       (j : Fin (k ParameterSet.ML_KEM_512)) =>
            SampleNTT (slice ekPKE (384 * 2) 32 (by simp) ‖
              #v[((j : Nat) : Byte)] ‖ #v[((i : Nat) : Byte)])) := by
    apply Matrix.ext; intro i j
    fin_cases i <;> fin_cases j <;>
      simp [PolyMatrix.update, PolyMatrix.zero, Matrix.updateRow,
            Matrix.of_apply, Function.update]
  have h_y : ((PolyVector.zero q (k ParameterSet.ML_KEM_512)).set 0
                  (SamplePolyCBD (PRF (η₁ ParameterSet.ML_KEM_512) r 0))).set
              (0 + 1) (SamplePolyCBD (PRF (η₁ ParameterSet.ML_KEM_512) r (0 + 1)))
        = Vector.ofFn (fun (i : Fin (k ParameterSet.ML_KEM_512)) =>
            SamplePolyCBD (PRF (η₁ ParameterSet.ML_KEM_512) r ((i : Nat) : Byte))) := by
    apply Vector.ext; intro i hi
    unfold PolyVector.set PolyVector.zero
    interval_cases i <;> rfl
  have h_e1 : ((PolyVector.zero q (k ParameterSet.ML_KEM_512)).set 0
                  (SamplePolyCBD (PRF η₂ r (0 + 1 + 1)))).set
              (0 + 1) (SamplePolyCBD (PRF η₂ r (0 + 1 + 1 + 1)))
        = Vector.ofFn (fun (i : Fin (k ParameterSet.ML_KEM_512)) =>
            SamplePolyCBD (PRF η₂ r ((((2 : Nat) + (i : Nat) : Nat) : Byte)))) := by
    apply Vector.ext; intro i hi
    unfold PolyVector.set PolyVector.zero
    interval_cases i <;> rfl
  -- e₂ N-counter: `0+1+1+1+1 = 2*2 = 4`. Both sides need to equal `PRF η₂ r 4`.
  have h_e2 : SamplePolyCBD (PRF η₂ r (0 + 1 + 1 + 1 + 1)) =
              SamplePolyCBD (PRF η₂ r ((((2 * 2 : Nat) : Nat) : Byte))) := by rfl
  rw [h_A, h_y, h_e1, h_e2]

/- k=3 case of `K_PKE.Encrypt_eq_pure`. -/
set_option maxHeartbeats 8000000 in
private theorem Encrypt_eq_pure_768
    (ekPKE : 𝔹 (384 * k .ML_KEM_768 + 32)) (m : 𝔹 32) (r : 𝔹 32) :
    Spec.MLKEM.K_PKE.Encrypt .ML_KEM_768 ekPKE m r =
      K_PKE.Encrypt_pure .ML_KEM_768 ekPKE m r := by
  unfold Spec.MLKEM.K_PKE.Encrypt K_PKE.Encrypt_pure
  simp only [Id.run, Aeneas.SRRange.forIn'_eq_forIn'_range', Aeneas.SRRange.size,
             show ∀ (n : Nat), (n - 0 + 1 - 1) / 1 = n from fun _ => by omega,
             List.range', List.forIn'_cons, List.forIn'_nil, pure_bind]
  have h_A : (((((((((PolyMatrix.zero q (k ParameterSet.ML_KEM_768)).update 0 0
                    (SampleNTT (slice ekPKE (384 * 3) 32 (by simp) ‖
                      #v[((0 : Nat) : Byte)] ‖ #v[((0 : Nat) : Byte)]))).update
                  0 (0 + 1) (SampleNTT (slice ekPKE (384 * 3) 32 (by simp) ‖
                    #v[(((0 + 1 : Nat) : Byte))] ‖ #v[((0 : Nat) : Byte)]))).update
                0 (0 + 1 + 1) (SampleNTT (slice ekPKE (384 * 3) 32 (by simp) ‖
                  #v[(((0 + 1 + 1 : Nat) : Byte))] ‖ #v[((0 : Nat) : Byte)]))).update
              (0 + 1) 0 (SampleNTT (slice ekPKE (384 * 3) 32 (by simp) ‖
                #v[((0 : Nat) : Byte)] ‖ #v[(((0 + 1 : Nat) : Byte))]))).update
            (0 + 1) (0 + 1) (SampleNTT (slice ekPKE (384 * 3) 32 (by simp) ‖
              #v[(((0 + 1 : Nat) : Byte))] ‖ #v[(((0 + 1 : Nat) : Byte))]))).update
          (0 + 1) (0 + 1 + 1) (SampleNTT (slice ekPKE (384 * 3) 32 (by simp) ‖
            #v[(((0 + 1 + 1 : Nat) : Byte))] ‖ #v[(((0 + 1 : Nat) : Byte))]))).update
        (0 + 1 + 1) 0 (SampleNTT (slice ekPKE (384 * 3) 32 (by simp) ‖
          #v[((0 : Nat) : Byte)] ‖ #v[(((0 + 1 + 1 : Nat) : Byte))]))).update
      (0 + 1 + 1) (0 + 1) (SampleNTT (slice ekPKE (384 * 3) 32 (by simp) ‖
        #v[(((0 + 1 : Nat) : Byte))] ‖ #v[(((0 + 1 + 1 : Nat) : Byte))]))).update
    (0 + 1 + 1) (0 + 1 + 1) (SampleNTT (slice ekPKE (384 * 3) 32 (by simp) ‖
      #v[(((0 + 1 + 1 : Nat) : Byte))] ‖ #v[(((0 + 1 + 1 : Nat) : Byte))]))
        = (Matrix.of fun (i : Fin (k ParameterSet.ML_KEM_768))
                       (j : Fin (k ParameterSet.ML_KEM_768)) =>
            SampleNTT (slice ekPKE (384 * 3) 32 (by simp) ‖
              #v[((j : Nat) : Byte)] ‖ #v[((i : Nat) : Byte)])) := by
    apply Matrix.ext; intro i j
    fin_cases i <;> fin_cases j <;>
      simp [PolyMatrix.update, PolyMatrix.zero, Matrix.updateRow,
            Matrix.of_apply, Function.update]
  have h_y : (((PolyVector.zero q (k ParameterSet.ML_KEM_768)).set 0
                  (SamplePolyCBD (PRF (η₁ ParameterSet.ML_KEM_768) r 0))).set
              (0 + 1) (SamplePolyCBD (PRF (η₁ ParameterSet.ML_KEM_768) r (0 + 1)))).set
              (0 + 1 + 1) (SamplePolyCBD (PRF (η₁ ParameterSet.ML_KEM_768) r (0 + 1 + 1)))
        = Vector.ofFn (fun (i : Fin (k ParameterSet.ML_KEM_768)) =>
            SamplePolyCBD (PRF (η₁ ParameterSet.ML_KEM_768) r ((i : Nat) : Byte))) := by
    apply Vector.ext; intro i hi
    unfold PolyVector.set PolyVector.zero
    interval_cases i <;> rfl
  have h_e1 : (((PolyVector.zero q (k ParameterSet.ML_KEM_768)).set 0
                  (SamplePolyCBD (PRF η₂ r (0 + 1 + 1 + 1)))).set
              (0 + 1) (SamplePolyCBD (PRF η₂ r (0 + 1 + 1 + 1 + 1)))).set
              (0 + 1 + 1) (SamplePolyCBD (PRF η₂ r (0 + 1 + 1 + 1 + 1 + 1)))
        = Vector.ofFn (fun (i : Fin (k ParameterSet.ML_KEM_768)) =>
            SamplePolyCBD (PRF η₂ r ((((3 : Nat) + (i : Nat) : Nat) : Byte)))) := by
    apply Vector.ext; intro i hi
    unfold PolyVector.set PolyVector.zero
    interval_cases i <;> rfl
  have h_e2 : SamplePolyCBD (PRF η₂ r (0 + 1 + 1 + 1 + 1 + 1 + 1)) =
              SamplePolyCBD (PRF η₂ r ((((2 * 3 : Nat) : Nat) : Byte))) := by rfl
  rw [h_A, h_y, h_e1, h_e2]

/- k=4 case of `K_PKE.Encrypt_eq_pure`. -/
set_option maxHeartbeats 16000000 in
private theorem Encrypt_eq_pure_1024
    (ekPKE : 𝔹 (384 * k .ML_KEM_1024 + 32)) (m : 𝔹 32) (r : 𝔹 32) :
    Spec.MLKEM.K_PKE.Encrypt .ML_KEM_1024 ekPKE m r =
      K_PKE.Encrypt_pure .ML_KEM_1024 ekPKE m r := by
  unfold Spec.MLKEM.K_PKE.Encrypt K_PKE.Encrypt_pure
  simp only [Id.run, Aeneas.SRRange.forIn'_eq_forIn'_range', Aeneas.SRRange.size,
             show ∀ (n : Nat), (n - 0 + 1 - 1) / 1 = n from fun _ => by omega,
             List.range', List.forIn'_cons, List.forIn'_nil, pure_bind]
  have h_A : ((((((((((((((((PolyMatrix.zero q (k ParameterSet.ML_KEM_1024)).update 0 0
        (SampleNTT (slice ekPKE (384 * 4) 32 (by simp) ‖ #v[((0:Nat):Byte)] ‖ #v[((0:Nat):Byte)]))).update
        0 (0+1) (SampleNTT (slice ekPKE (384 * 4) 32 (by simp) ‖ #v[(((0+1:Nat):Byte))] ‖ #v[((0:Nat):Byte)]))).update
        0 (0+1+1) (SampleNTT (slice ekPKE (384 * 4) 32 (by simp) ‖ #v[(((0+1+1:Nat):Byte))] ‖ #v[((0:Nat):Byte)]))).update
        0 (0+1+1+1) (SampleNTT (slice ekPKE (384 * 4) 32 (by simp) ‖ #v[(((0+1+1+1:Nat):Byte))] ‖ #v[((0:Nat):Byte)]))).update
        (0+1) 0 (SampleNTT (slice ekPKE (384 * 4) 32 (by simp) ‖ #v[((0:Nat):Byte)] ‖ #v[(((0+1:Nat):Byte))]))).update
        (0+1) (0+1) (SampleNTT (slice ekPKE (384 * 4) 32 (by simp) ‖ #v[(((0+1:Nat):Byte))] ‖ #v[(((0+1:Nat):Byte))]))).update
        (0+1) (0+1+1) (SampleNTT (slice ekPKE (384 * 4) 32 (by simp) ‖ #v[(((0+1+1:Nat):Byte))] ‖ #v[(((0+1:Nat):Byte))]))).update
        (0+1) (0+1+1+1) (SampleNTT (slice ekPKE (384 * 4) 32 (by simp) ‖ #v[(((0+1+1+1:Nat):Byte))] ‖ #v[(((0+1:Nat):Byte))]))).update
        (0+1+1) 0 (SampleNTT (slice ekPKE (384 * 4) 32 (by simp) ‖ #v[((0:Nat):Byte)] ‖ #v[(((0+1+1:Nat):Byte))]))).update
        (0+1+1) (0+1) (SampleNTT (slice ekPKE (384 * 4) 32 (by simp) ‖ #v[(((0+1:Nat):Byte))] ‖ #v[(((0+1+1:Nat):Byte))]))).update
        (0+1+1) (0+1+1) (SampleNTT (slice ekPKE (384 * 4) 32 (by simp) ‖ #v[(((0+1+1:Nat):Byte))] ‖ #v[(((0+1+1:Nat):Byte))]))).update
        (0+1+1) (0+1+1+1) (SampleNTT (slice ekPKE (384 * 4) 32 (by simp) ‖ #v[(((0+1+1+1:Nat):Byte))] ‖ #v[(((0+1+1:Nat):Byte))]))).update
        (0+1+1+1) 0 (SampleNTT (slice ekPKE (384 * 4) 32 (by simp) ‖ #v[((0:Nat):Byte)] ‖ #v[(((0+1+1+1:Nat):Byte))]))).update
        (0+1+1+1) (0+1) (SampleNTT (slice ekPKE (384 * 4) 32 (by simp) ‖ #v[(((0+1:Nat):Byte))] ‖ #v[(((0+1+1+1:Nat):Byte))]))).update
        (0+1+1+1) (0+1+1) (SampleNTT (slice ekPKE (384 * 4) 32 (by simp) ‖ #v[(((0+1+1:Nat):Byte))] ‖ #v[(((0+1+1+1:Nat):Byte))]))).update
        (0+1+1+1) (0+1+1+1) (SampleNTT (slice ekPKE (384 * 4) 32 (by simp) ‖ #v[(((0+1+1+1:Nat):Byte))] ‖ #v[(((0+1+1+1:Nat):Byte))]))
        = (Matrix.of fun (i : Fin (k ParameterSet.ML_KEM_1024))
                       (j : Fin (k ParameterSet.ML_KEM_1024)) =>
            SampleNTT (slice ekPKE (384 * 4) 32 (by simp) ‖
              #v[((j : Nat) : Byte)] ‖ #v[((i : Nat) : Byte)])) := by
    apply Matrix.ext; intro i j
    fin_cases i <;> fin_cases j <;>
      simp [PolyMatrix.update, PolyMatrix.zero, Matrix.updateRow,
            Matrix.of_apply, Function.update]
  have h_y : ((((PolyVector.zero q (k ParameterSet.ML_KEM_1024)).set 0
                  (SamplePolyCBD (PRF (η₁ ParameterSet.ML_KEM_1024) r 0))).set
              (0 + 1) (SamplePolyCBD (PRF (η₁ ParameterSet.ML_KEM_1024) r (0 + 1)))).set
              (0 + 1 + 1) (SamplePolyCBD (PRF (η₁ ParameterSet.ML_KEM_1024) r (0 + 1 + 1)))).set
              (0 + 1 + 1 + 1) (SamplePolyCBD (PRF (η₁ ParameterSet.ML_KEM_1024) r (0 + 1 + 1 + 1)))
        = Vector.ofFn (fun (i : Fin (k ParameterSet.ML_KEM_1024)) =>
            SamplePolyCBD (PRF (η₁ ParameterSet.ML_KEM_1024) r ((i : Nat) : Byte))) := by
    apply Vector.ext; intro i hi
    unfold PolyVector.set PolyVector.zero
    interval_cases i <;> rfl
  have h_e1 : ((((PolyVector.zero q (k ParameterSet.ML_KEM_1024)).set 0
                  (SamplePolyCBD (PRF η₂ r (0 + 1 + 1 + 1 + 1)))).set
              (0 + 1) (SamplePolyCBD (PRF η₂ r (0 + 1 + 1 + 1 + 1 + 1)))).set
              (0 + 1 + 1) (SamplePolyCBD (PRF η₂ r (0 + 1 + 1 + 1 + 1 + 1 + 1)))).set
              (0 + 1 + 1 + 1) (SamplePolyCBD (PRF η₂ r (0 + 1 + 1 + 1 + 1 + 1 + 1 + 1)))
        = Vector.ofFn (fun (i : Fin (k ParameterSet.ML_KEM_1024)) =>
            SamplePolyCBD (PRF η₂ r ((((4 : Nat) + (i : Nat) : Nat) : Byte)))) := by
    apply Vector.ext; intro i hi
    unfold PolyVector.set PolyVector.zero
    interval_cases i <;> rfl
  have h_e2 : SamplePolyCBD (PRF η₂ r (0 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1)) =
              SamplePolyCBD (PRF η₂ r ((((2 * 4 : Nat) : Nat) : Byte))) := by rfl
  rw [h_A, h_y, h_e1, h_e2]

theorem K_PKE.Encrypt_eq_pure (p : ParameterSet)
    (ekPKE : 𝔹 (384 * k p + 32)) (m : 𝔹 32) (r : 𝔹 32) :
    Spec.MLKEM.K_PKE.Encrypt p ekPKE m r =
      K_PKE.Encrypt_pure p ekPKE m r := by
  cases p
  · exact Encrypt_eq_pure_512 ekPKE m r
  · exact Encrypt_eq_pure_768 ekPKE m r
  · exact Encrypt_eq_pure_1024 ekPKE m r

/-! ## `K_PKE.Encrypt_eq_ciphers` — outer-chain helper for `encapsulate_internal`.

Spec-side bridge that consumes user-supplied identifications for the pure-form
`Â`, `y`, `e₁`, `e₂`, `μ`, `t̂` and reduces `K_PKE.Encrypt p ekPKE m r` to the
explicit `(c₁ ‖ c₂).cast _` shape over those user-named quantities.

This lemma elaborates in a tiny context (no Aeneas state, no `pe_tmp*`),
making the per-half `rfl`/`subst` chain cheap.  The `encapsulate_internal`
spec body then closes its outer chain by `exact` to this helper after a few
local rewrites — avoiding the heartbeat-fatal `rw [h_v_value]` against the
full spec-body context. -/
theorem K_PKE.Encrypt_eq_ciphers (p : ParameterSet)
    (ekPKE : 𝔹 (384 * k p + 32)) (m : 𝔹 32) (r : 𝔹 32)
    (v_t : PolyVector q (k p))
    («Â» : PolyMatrix q (k p))
    (y e₁ : PolyVector q (k p))
    (e₂ μ : Polynomial q)
    (hÂ : «Â» = Matrix.of fun (i j : Fin (k p)) =>
            SampleNTT (slice ekPKE (384 * (k p : ℕ)) 32 (by simp) ‖
              #v[((j : ℕ) : Byte)] ‖ #v[((i : ℕ) : Byte)]))
    (h_t : PolyVector.ByteDecode 12 (slice ekPKE 0 (384 * (k p : ℕ)) (by simp)) = v_t)
    (h_y : y = Vector.ofFn fun (i : Fin (k p)) =>
             SamplePolyCBD (PRF (η₁ p) r ((i.val : ℕ) : Byte)))
    (h_e₁ : e₁ = Vector.ofFn fun (i : Fin (k p)) =>
              SamplePolyCBD (PRF η₂ r ((((k p : ℕ) + i.val : ℕ) : Byte))))
    (h_e₂ : e₂ = SamplePolyCBD (PRF η₂ r (((2 * (k p : ℕ) : ℕ) : Byte))))
    (h_μ : μ = Polynomial.Decompress 1 (ByteDecode (m.cast (by grind)))) :
    Spec.MLKEM.K_PKE.Encrypt p ekPKE m r =
      (PolyVector.ByteEncode (dᵤ p)
         (PolyVector.Compress (dᵤ p)
           ((PolyMatrix.MulVectorNTT (Matrix.transpose «Â») (PolyVector.NTT y)).NTTInv + e₁)) ‖
       ByteEncode (dᵥ p)
         (Polynomial.Compress (dᵥ p)
           (NTTInv (PolyVector.innerProductNTT v_t (PolyVector.NTT y)) + e₂ + μ))).cast
        (by cases p <;> simp [dᵤ, dᵥ]) := by
  rw [Encrypt_eq_pure]
  unfold K_PKE.Encrypt_pure
  subst hÂ h_y h_e₁ h_e₂ h_μ
  rw [h_t]
  rfl

/-! ## `K_PKE.Decrypt_eq` — outer-chain helper for `decaps_reencaps`.

Spec-side bridge that consumes user-supplied identifications for `ŝ`, `u'`,
and `v'` (the three named intermediates in `K_PKE.Decrypt`) and reduces
`K_PKE.Decrypt p dkPKE c` to the explicit `(ByteEncode 1 (Compress 1 w)).cast _`
shape over those user-named quantities, where `w = v' - NTTInv(innerProductNTT ŝ (NTT u'))`.

Unlike `Encrypt`, `Decrypt` has no `Id.run do` loops — the entire body is a
straight-line `let`-binding chain, so this lemma reduces to
`unfold + simp only [← h_s, ← h_u, ← h_v]`. -/
theorem K_PKE.Decrypt_eq (p : ParameterSet)
    (dkPKE : 𝔹 (384 * k p)) (c : 𝔹 (32 * (dᵤ p * k p + dᵥ p)))
    («ŝ» : PolyVector q (k p))
    (u' : PolyVector q (k p))
    (v' : Polynomial)
    (h_s : «ŝ» = PolyVector.ByteDecode 12 (dkPKE.cast (by grind)))
    (h_u : u' = PolyVector.Decompress (dᵤ p)
              (PolyVector.ByteDecode (dᵤ p)
                (slice c 0 (32 * dᵤ p * k p) (by cases p <;> simp [dᵤ, dᵥ])))
              (by cases p <;> simp [dᵤ]))
    (h_v : v' = Polynomial.Decompress (dᵥ p)
              (ByteDecode
                (slice c (32 * dᵤ p * k p) (32 * dᵥ p)
                  (by cases p <;> simp [dᵤ, dᵥ])))
              (by cases p <;> simp [dᵥ])) :
    Spec.MLKEM.K_PKE.Decrypt p dkPKE c =
      (ByteEncode 1 (Polynomial.Compress 1
         (v' - NTTInv (PolyVector.innerProductNTT «ŝ» (PolyVector.NTT u'))))).cast (by grind) := by
  unfold Spec.MLKEM.K_PKE.Decrypt
  show _ = _
  simp only [← h_s, ← h_u, ← h_v]

end Symcrust.Properties.MLKEM.Bridges
