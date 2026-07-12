import Spec.MLKEM.Spec
import Spec.Defs
import Symcrust.Properties.MLKEM.Helpers.VectorSliceCastAppend

/-!
# K_PKE.KeyGen structural bridges

Spec-level lemmas exposing the structural shape of `K_PKE.KeyGen p d`.
Used by `MLKEM/Key.lean` to discharge final-FC residuals that bridge
impl-key fields to ekPKE / dkPKE.

The K_PKE.KeyGen body contains heavy for-loops (matrix sampling, s/e
sampling) that whnf-reduction cannot penetrate. The pattern here is to
expose the OUTER `pure (a, b)` structure via `unfold; simp; split; split;
rfl`-on-existential, then chain through `Helpers.cast_slice_eq_of_append₂*`
to read off the named pieces.
-/

open Spec Spec.Notations MLKEM Symcrust.Properties.MLKEM.Helpers

/-- `K_PKE.KeyGen p d`'s first component has the append-cast shape `(... ‖ ρ).cast _`.
Used to close Residual A (public_seed bridge). -/
theorem KPKE_fst_eq_append (p : ParameterSet) (d : 𝔹 32) :
    ∃ (t_hat : PolyVector q (k p)),
      (K_PKE.KeyGen p d).1 =
        (PolyVector.ByteEncode 12 t_hat (by decide) ‖
          (G (d ‖ #v[(k p : Byte)])).1).cast (by ring) := by
  unfold K_PKE.KeyGen
  simp only [Id.run, bind]
  split; split
  exact ⟨_, rfl⟩

/-- The trailing 32-byte slice of `ekPKE = (K_PKE.KeyGen p d).1` equals ρ. -/
theorem KPKE_fst_suffix_eq_rho (p : ParameterSet) (d : 𝔹 32) :
    slice (K_PKE.KeyGen p d).1 (384 * (k p : ℕ)) 32 (by simp) =
      (G (d ‖ #v[(k p : Byte)])).1 := by
  obtain ⟨t_hat, h_ek⟩ := KPKE_fst_eq_append p d
  rw [show (K_PKE.KeyGen p d).1 = _ from h_ek]
  exact cast_slice_eq_of_append₂_suffix
    (PolyVector.ByteEncode 12 t_hat (by decide))
    (G (d ‖ #v[(k p : Byte)])).1
    (by ring) (384 * (k p : ℕ)) (by ring) _

/-- The leading `384·k`-byte slice of `ekPKE = (K_PKE.KeyGen p d).1` equals
`ByteEncode 12` of the `t̂` polyvector witnessed by `KPKE_fst_eq_append`.
Used to close Residual D (`keyEncodedTPrefix` bridge). -/
theorem KPKE_fst_prefix_eq_byteEncode_t_hat (p : ParameterSet) (d : 𝔹 32) :
    ∃ (t_hat : PolyVector q (k p)),
      slice (K_PKE.KeyGen p d).1 0 (384 * (k p : ℕ)) (by simp) =
        (PolyVector.ByteEncode 12 t_hat (by decide)).cast (by ring) := by
  obtain ⟨t_hat, h_ek⟩ := KPKE_fst_eq_append p d
  refine ⟨t_hat, ?_⟩
  rw [show (K_PKE.KeyGen p d).1 = _ from h_ek]
  apply Vector.ext
  intro i hi
  simp only [slice, Vector.getElem_ofFn, Vector.getElem_cast, Nat.zero_add]
  exact Vector.getElem_append_left (hi := by simp; grind)

set_option maxHeartbeats 800000 in
set_option maxRecDepth 2048 in
/-- Strong spec-side bridge: expose `K_PKE.KeyGen p d`'s `t̂` in explicit
`Â * NTT s + NTT e` form, with each of `Â`, `s`, `e` characterised by
the standard FIPS-203 §5.1 sampling formulas.

This is the **right-hand side** of the Phase-13 NTT-mat-vec correctness
bridge (BRIDGE II in `Key.lean`): given the impl's
`toPolyVecOfLen t3 = ê_impl + (Â_impl · ŝ_impl_R).map (Rinv·)`
post-`matrix_vector_mont_mul_and_add`, this lemma names the spec t̂ and
its components so the impl→spec algebra can chain row-by-row. -/
theorem KPKE_t_hat_explicit (p : ParameterSet) (d : 𝔹 32) :
    ∃ (Â : PolyMatrix q (k p)) (s e : PolyVector q (k p)),
      (∀ (i j : ℕ) (hi : i < k p) (hj : j < k p),
        Â ⟨i, hi⟩ ⟨j, hj⟩ = SampleNTT
          ((G (d ‖ #v[(k p : Byte)])).1 ‖ #v[(j : Byte)] ‖ #v[(i : Byte)])) ∧
      (∀ (i : ℕ) (_ : i < k p),
        s[i] = SamplePolyCBD
          (PRF (η₁ p) (G (d ‖ #v[(k p : Byte)])).2 ((i : ℕ) : Byte))) ∧
      (∀ (i : ℕ) (_ : i < k p),
        e[i] = SamplePolyCBD
          (PRF (η₁ p) (G (d ‖ #v[(k p : Byte)])).2 ((((k p : ℕ) + i) : ℕ) : Byte))) ∧
      (K_PKE.KeyGen p d).1 =
        (PolyVector.ByteEncode 12 (Â * PolyVector.NTT s + PolyVector.NTT e)
          (by decide) ‖
          (G (d ‖ #v[(k p : Byte)])).1).cast (by ring) := by
  cases p
  all_goals {
    unfold K_PKE.KeyGen
    simp only [Id.run, bind]
    split
    rename_i N1 s_val hS
    split
    rename_i N2 e_val hE
    refine ⟨_, s_val, e_val, ?_, ?_, ?_, rfl⟩
    · -- matrix entries
      intro i j hi hj
      simp only [Aeneas.SRRange.forIn'_eq_forIn'_range', Aeneas.SRRange.size,
                 List.range', List.forIn'_cons, List.forIn'_nil, bind, pure]
      interval_cases i <;> interval_cases j <;> rfl
    · -- s entries
      intro i hi
      rw [Aeneas.SRRange.forIn'_eq_forIn'_range'] at hS
      simp only [Aeneas.SRRange.size, k, List.range', List.forIn'_cons, List.forIn'_nil,
                 bind, pure, PolyVector.set] at hS
      injection hS with _ hs2
      simp only [Nat.zero_add] at hs2
      rw [← hs2]
      interval_cases i <;> rfl
    · -- e entries (depends on N1 from s-loop, so re-derive)
      intro i hi
      rw [Aeneas.SRRange.forIn'_eq_forIn'_range'] at hS
      simp only [Aeneas.SRRange.size, k, List.range', List.forIn'_cons, List.forIn'_nil,
                 bind, pure, PolyVector.set] at hS
      injection hS with hN1 _
      rw [Aeneas.SRRange.forIn'_eq_forIn'_range'] at hE
      simp only [Aeneas.SRRange.size, k, List.range', List.forIn'_cons, List.forIn'_nil,
                 bind, pure, PolyVector.set] at hE
      injection hE with _ he2
      subst hN1
      rw [← he2]
      interval_cases i <;> rfl
  }


set_option maxRecDepth 2048 in
/--
`dkPKE = (K_PKE.KeyGen p d).2` is the 12-bit packed encoding of `ŝ`,
the NTT of the CBD-sampled secret-vector `s`.  Closes Residual B of
`mlkem.key_expand_from_private_seed.spec`.

See the proof body for the two-stage suffices+cases structure.
-/
theorem KPKE_snd_eq_byteEncode_NTT_CBD (p : ParameterSet) (d : 𝔹 32) :
    (K_PKE.KeyGen p d).2 =
      (PolyVector.ByteEncode 12
        (Vector.ofFn fun (i : Fin (k p : ℕ)) =>
          MLKEM.NTT (MLKEM.SamplePolyCBD
            (MLKEM.PRF (η₁ p) (G (d ‖ #v[((k p : ℕ) : Byte)])).2
              ((i : ℕ) : Byte))))
        (by grind)).cast (by cases p <;> simp) := by
  suffices h : ∃ (s_final : PolyVector q (k p)),
      (K_PKE.KeyGen p d).2 =
        (PolyVector.ByteEncode 12 (PolyVector.NTT s_final) (by grind)).cast
          (by cases p <;> simp)
      ∧ s_final = Vector.ofFn fun (i : Fin (k p : ℕ)) =>
          MLKEM.SamplePolyCBD
            (MLKEM.PRF (η₁ p) (G (d ‖ #v[((k p : ℕ) : Byte)])).2
              ((i : ℕ) : Byte)) by
    obtain ⟨s_final, h_eq, h_shape⟩ := h
    rw [h_eq, h_shape]
    simp only [PolyVector.NTT, Vector.map_ofFn]
    rfl
  cases p
  all_goals {
    unfold K_PKE.KeyGen
    simp only [Id.run, bind]
    split
    rename_i N₁ s₁ heq₁
    split
    refine ⟨s₁, rfl, ?_⟩
    rw [Aeneas.SRRange.forIn'_eq_forIn'_range'] at heq₁
    simp only [Aeneas.SRRange.size, k, List.range', List.forIn'_cons, List.forIn'_nil,
               bind, pure, PolyVector.set] at heq₁
    injection heq₁ with _ hs
    simp only [Nat.zero_add] at hs
    rw [← hs]
    apply Vector.ext
    intro i hi
    interval_cases i <;> rfl
  }
