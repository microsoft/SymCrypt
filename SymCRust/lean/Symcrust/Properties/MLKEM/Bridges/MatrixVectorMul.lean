/-
  # Bridges/MatrixVectorMul.lean — Mont-aware matrix-vector chain bridge (ML-KEM).

  Tracks divergence categories **E3** (matrix-vector loop iso), **G2**
  (keygen `t := A·s + e` chain), **G3** (encaps `u := A^T·r + e₁` chain),
  **G4** (decaps `m := v - s·u` chain).

  ## Why this file exists

  The impl's `matrix_vector_mont_mul_and_add a v k ℓ result` (or the
  ML-KEM-specific `vector_mont_dot_product`) introduces an extra `Rinv`
  factor per inner-product coefficient (one Mont cancellation per
  `mont_mul` call, accumulated by `mod_add`). Spec's
  `MLKEM.PolyMatrix.MulVectorNTT Ah sh` does pure pointwise
  multiplication (no Mont factors).

  Three main chains need bridging:

  ### G2 — keygen chain

  Impl in `keygen_finish`:
    matrix_vector_mont_mul_and_add Ah sh eh → t      -- result has /R per coeff
    vector_mul_r t                                   -- multiplies each coeff by R, cancels

  Spec equivalent (FIPS 203 Algorithm 13, line 9):
    t̂ := Ah · sh + eh

  When `sh` is stored in Montgomery NTT form (`sh[i] = (NTT s_i).map (R *
  ·)`), the impl's `mont_mul`-accumulator computes
  `R · sh_std[i][j] · v[j] · Rinv = sh_std[i][j] · v[j]`, matching the
  spec's pure pointwise product. The `+ eh` step is direct.

  ### G3 — encaps chain

  Impl in `encaps_finish`:
    matrix_vector_mont_mul_and_add Ah^T rh → u₀     -- Mont cancel as above
    vector_intt u₀                                  -- back to standard form
    vector_add u₀ eh1 → u                            -- + error

  Spec equivalent (FIPS 203 Algorithm 14, line 19):
    u := NTTInv(Ah^T · NTT r) + e₁

  ### G4 — decaps chain (inner-product)

  Impl in `decaps_finish`:
    poly_element_mul_and_accumulate sh wh → m₀      -- inner product /R per coeff
    poly_intt_and_mul_r m₀                          -- back to standard form, scale R
    poly_sub_from_in_place v m → m'                 -- decoded msg

  Spec (FIPS 203 Algorithm 15):
    w := NTTInv(sh ◦ NTT(u))         -- where ◦ is `innerProductNTT`
    m := v - w                       -- in standard form

  ### E3 — matrix-vector loop iso

  Outer rows × middle columns × inner (`poly_element_mul_and_accumulate`).
  Bridge to `MLKEM.PolyMatrix.MulVectorNTT`:

      Vector.ofFn (fun i => Id.run do
        for hj: j in [0:k] do
          whi := AddNTT whi (MultiplyNTTs Ah[i][j] v̂[j])
        pure whi)

  (FIPS 203 §2.4.7, definition `MulVectorNTT`.)
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.MontArith
import Symcrust.Properties.MLKEM.Bridges.NttLinearity

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open Symcrust

namespace Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 1000000
set_option maxRecDepth 2048

/-! ## E3 — matrix-vector loop iso

The impl's `matrix_vector_mont_mul_and_add A v k_ℓ result` (a triple-nested
loop) implements the pure-spec form

    result[i] := ∑ⱼ MultiplyNTTs A[i][j] v[j] · Rinv

i.e. it differs from `MLKEM.PolyMatrix.MulVectorNTT` by one Mont
factor per output coefficient.

We *do not* state E3 as a top-level Bridge theorem: the corresponding
impl-side step-spec (in `Ntt/MatVec.lean`, to be written) will carry
this `Rinv` factor in its postcondition directly; downstream consumers
compose it with `vector_mul_r` (G2.1 below) or `vector_intt_and_mul_r`
(G3.1 below) to cancel the `Rinv` at the call site. Keeping the Bridge
file free of E3 placeholders keeps the trust footprint minimal.
-/

/-! ## G2 — keygen chain `Ah · sh_mont + eh` -/

/-- **G2.1** — Mont-form scaling under matrix-vector multiplication.

If every coefficient of `sh` carries an extra `R` factor (i.e.
`sh = sh₀.map (R * ·)` componentwise, where `sh₀` is the standard-form
NTT of `s`), then the impl-side product `Ah · sh` (with one `Rinv` per
inner coefficient) equals the spec product `Ah · sh₀`:

    (Ah · sh).map (Rinv * ·) = Ah · sh₀

Informal proof: pointwise — each coefficient of the result is
`(∑ⱼ MultiplyNTTs Ah[i][j] (sh₀[j].map (R * ·))) · Rinv`.
By `MultiplyNTTs_scalarMul_right` (D2.4.b), this equals
`(∑ⱼ MultiplyNTTs Ah[i][j] sh₀[j]).map (R * ·).map (Rinv * ·)`. The
double `.map` collapses by `R_mul_Rinv` (`R * Rinv = 1`). -/
theorem matrix_vector_mont_cancel {k_ : MLKEM.K}
    (Ah : MLKEM.PolyMatrix q k_)
    (sh_std : MLKEM.PolyVector q k_) :
    let sh_mont : MLKEM.PolyVector q k_ :=
      sh_std.map (fun p => p.map (R * ·))
    (MLKEM.PolyMatrix.MulVectorNTT Ah sh_mont).map (fun p => p.map (Rinv * ·))
      = MLKEM.PolyMatrix.MulVectorNTT Ah sh_std := by
  intro sh_mont
  show Vector.map _ (MLKEM.PolyMatrix.MulVectorNTT Ah sh_mont) = _
  rw [show sh_mont = sh_std.map (fun p => p.map (R * ·)) from rfl,
      MulVectorNTT_scalarMul_right R Ah sh_std]
  apply Vector.ext; intro i hi
  simp only [Vector.getElem_map]
  apply Vector.ext; intro l hl
  simp only [Vector.getElem_map]
  rw [show Rinv * (R * (MLKEM.PolyMatrix.MulVectorNTT Ah sh_std)[i][l])
          = Rinv * R * (MLKEM.PolyMatrix.MulVectorNTT Ah sh_std)[i][l] from by ring,
      Rinv_mul_R, one_mul]

/-- **G2.2** — Full keygen chain identity.

    NTTInv (Ah · sh_mont · Rinv + eh) = NTTInv (Ah · sh₀ + eh)

where `sh_mont = sh₀.map (R * ·)`. Note: the impl stores `sh` in
Montgomery NTT form, so this identity is *exactly* the bridge needed
to show that `t = NTTInv(Ah · NTT(s)) + e` (FIPS 203 Algorithm 13
line 9) equals what the impl computes.

Informal proof: by G2.1 applied inside `NTTInv`. -/
theorem keygen_t_chain {k_ : MLKEM.K}
    (Ah : MLKEM.PolyMatrix q k_)
    (sh_std : MLKEM.PolyVector q k_) (eh : MLKEM.PolyVector q k_) :
    let sh_mont : MLKEM.PolyVector q k_ :=
      sh_std.map (fun p => p.map (R * ·))
    MLKEM.PolyVector.NTTInv
        ((MLKEM.PolyMatrix.MulVectorNTT Ah sh_mont).map
          (fun p => p.map (Rinv * ·))
         + eh)
      = MLKEM.PolyVector.NTTInv
          (MLKEM.PolyMatrix.MulVectorNTT Ah sh_std + eh) := by
  simp only
  rw [matrix_vector_mont_cancel Ah sh_std]

/-- Pointwise commutativity of `PolyVector` addition.  Manual proof
because the `Add (PolyVector m k)` instance (Spec.lean:276) is
`Vector.ofFn fun i => v[i] + w[i]` over a `Vector.zipWith`-based
`Polynomial.add` — no `AddCommMagma` instance is available, so
`add_comm` does not typeclass-resolve. -/
private theorem PolyVector_add_comm {k_ : MLKEM.K}
    (v w : MLKEM.PolyVector q k_) : v + w = w + v := by
  show (Vector.ofFn fun j => v[j] + w[j]) = (Vector.ofFn fun j => w[j] + v[j])
  apply Vector.ext
  intro i hi
  rw [Vector.getElem_ofFn, Vector.getElem_ofFn]
  show Polynomial.add v[i] w[i] = Polynomial.add w[i] v[i]
  unfold Polynomial.add
  apply Vector.ext
  intro j hj
  rw [Vector.getElem_zipWith, Vector.getElem_zipWith]
  ring

/-- **G2.3 — Key-gen `t̂` chain identity (post-NTT form).**

Closes Residual D2 of `mlkem.key_expand_from_private_seed.spec`
(`Key.lean:2775` case `ektprefix`).  Given the impl-side post-conditions
that:

  * `t1_impl = NTT e`              (entry-wise, from the prelude e-loop +
    `KPKE_t_hat_explicit`'s e characterisation);
  * `s_R_impl = (NTT s).map (R·)`  (s19 carries the Mont factor R after
    `vector_mul_r` on the NTT(s) buffer);
  * `Â_impl ⟨i,_⟩ ⟨j,_⟩ = Â ⟨i,_⟩ ⟨j,_⟩`   (entry-wise — the impl matrix
    in `a1` equals the spec `Â` modulo orientation, discharged at
    `case mat`),

this lemma rewrites the impl-side post of `matrix_vector_mont_mul_and_add`
(the `t2_post4` shape) directly into spec's `Â * NTT s + NTT e` form.

Mechanisation: `matrix_vector_mont_cancel` (G2.1) does the R/Rinv
collapse; `Matrix.ext` lifts the entry-wise `h_Â` to matrix equality;
`PolyVector_add_comm` (above) commutes the `+ NTT e` summand to match
the spec order. -/
theorem keygen_t_hat_chain {k_ : MLKEM.K}
    (Â Â_impl : MLKEM.PolyMatrix q k_)
    (s e t1_impl s_R_impl : MLKEM.PolyVector q k_)
    (h_t1 : t1_impl = MLKEM.PolyVector.NTT e)
    (h_s_R : s_R_impl = (MLKEM.PolyVector.NTT s).map (fun p => p.map (R * ·)))
    (h_Â : ∀ (i j : ℕ) (hi : i < k_) (hj : j < k_),
       Â_impl ⟨i, hi⟩ ⟨j, hj⟩ = Â ⟨i, hi⟩ ⟨j, hj⟩) :
    t1_impl + (Â_impl.MulVectorNTT s_R_impl).map (fun p => p.map (Rinv * ·))
      = Â * MLKEM.PolyVector.NTT s + MLKEM.PolyVector.NTT e := by
  rw [h_t1, h_s_R, matrix_vector_mont_cancel]
  have h_Âeq : Â_impl = Â := by
    funext i j
    obtain ⟨i, hi⟩ := i
    obtain ⟨j, hj⟩ := j
    exact h_Â i j hi hj
  rw [h_Âeq]
  show e.NTT + Â.MulVectorNTT s.NTT = Â.MulVectorNTT s.NTT + e.NTT
  exact PolyVector_add_comm _ _

/-! ## G3 — encaps chain `Ah^T · rh + eh1` -/

/-- **G3.1** — Encaps matrix-vector chain. Symmetric to G2.2 but for
the `Ah^T · NTT(r)` step in `K_PKE.Encrypt` (FIPS 203 Algorithm 14
line 19).

When `rh` is in *standard* NTT form (not Mont), the impl's
`matrix_vector_mont_mul_and_add` still introduces a `Rinv` factor; it
is cancelled at the call site by a follow-up `vector_mul_r`. Reading
the impl, the actual chain is

    u_ntt := matrix_vector_mont_mul_and_add Ah^T (NTT r) → +Rinv
    u_ntt := vector_mul_r u_ntt                         → +R, cancels
    u := NTTInv u_ntt + e₁

Result: `u = NTTInv (Ah^T · NTT r) + e₁` matching spec.

Informal proof: same as G2.1, applied with `c = R` instead of `c =
Rinv` (since `vector_mul_r` scales by `R`, leaving the result clean).
-/
theorem encaps_u_chain {k_ : MLKEM.K}
    (AhT : MLKEM.PolyMatrix q k_)
    (rh : MLKEM.PolyVector q k_) (eh1 : MLKEM.PolyVector q k_) :
    MLKEM.PolyVector.NTTInv
        (((MLKEM.PolyMatrix.MulVectorNTT AhT rh).map
          (fun p => p.map (Rinv * ·))).map (fun p => p.map (R * ·)))
         + eh1
      = MLKEM.PolyVector.NTTInv
          (MLKEM.PolyMatrix.MulVectorNTT AhT rh) + eh1 := by
  fcongr 1
  fcongr 1
  apply Vector.ext; intro i hi
  simp only [Vector.getElem_map]
  apply Vector.ext; intro j hj
  simp only [Vector.getElem_map]
  rw [show R * (Rinv * (MLKEM.PolyMatrix.MulVectorNTT AhT rh)[i][j])
          = R * Rinv * (MLKEM.PolyMatrix.MulVectorNTT AhT rh)[i][j] from by ring,
      R_mul_Rinv, one_mul]

/-! ## G4 — decaps inner-product chain `v - sh ◦ NTT(u)` -/

/-- **G4.1** — Mont-form inner-product cancellation.

For `wh : PolyVector q k`, `sh_std : PolyVector q k`,

    (innerProductNTT (sh_std.map (R * ·)) wh).map (Rinv * ·)
      = innerProductNTT sh_std wh

Informal proof: by `innerProductNTT_scalarMul_left` (D2.6) applied
inside the sum, then `R · Rinv = 1` collapses the double `.map`. -/
theorem inner_product_mont_cancel {k_ : MLKEM.K}
    (sh_std wh : MLKEM.PolyVector q k_) :
    let sh_mont : MLKEM.PolyVector q k_ :=
      sh_std.map (fun p => p.map (R * ·))
    (MLKEM.PolyVector.innerProductNTT sh_mont wh).map (Rinv * ·)
      = MLKEM.PolyVector.innerProductNTT sh_std wh := by
  intro sh_mont
  show Vector.map _ (MLKEM.PolyVector.innerProductNTT sh_mont wh) = _
  rw [show sh_mont = sh_std.map (fun p => p.map (R * ·)) from rfl,
      innerProductNTT_scalarMul_left R sh_std wh]
  apply Vector.ext; intro l hl
  simp only [Vector.getElem_map]
  rw [show Rinv * (R * (MLKEM.PolyVector.innerProductNTT sh_std wh)[l])
          = Rinv * R * (MLKEM.PolyVector.innerProductNTT sh_std wh)[l] from by ring,
      Rinv_mul_R, one_mul]

/-- **G4.2** — Decaps decryption chain identity.

The impl's `decaps_finish` computes `m := v - NTTInv(⟨sh_mont, wh⟩) · Rinv`,
which by G4.1 equals `v - NTTInv(⟨sh_std, wh⟩) = v - NTTInv(sh ◦ NTT u)`,
matching spec line 4 of FIPS 203 Algorithm 15. -/
theorem decaps_m_chain {k_ : MLKEM.K}
    (sh_std wh : MLKEM.PolyVector q k_)
    (v : MLKEM.Polynomial) :
    let sh_mont : MLKEM.PolyVector q k_ :=
      sh_std.map (fun p => p.map (R * ·))
    v - MLKEM.NTTInv
          ((MLKEM.PolyVector.innerProductNTT sh_mont wh).map (Rinv * ·))
      = v - MLKEM.NTTInv
              (MLKEM.PolyVector.innerProductNTT sh_std wh) := by
  simp only
  rw [inner_product_mont_cancel sh_std wh]

/-- **G4.3** — Decaps decryption identity for *standard-form* `sh`.

Symcrust's `decapsulate` calls `vector_mont_dot_product s pvu2` with
`s := Key.s`, whose slot holds `ŝ` in *standard* NTT form
(per `key_expand_from_private_seed`, the only writer to the slot: it
runs `vector_ntt(s_mut)` and stops there; the subsequent
`vector_mul_r(s_mut, pv_tmp)` writes into a scratch vector, leaving
`Key.s` itself in standard form).

The Rinv factor introduced by `vector_mont_dot_product` is then
cancelled by the R factor from `poly_element_intt_and_mul_r` via
`NTTInv_scalarMul` (D2.6: NTTInv distributes over per-coeff scalar
mult) plus `R · Rinv = 1`:

    (NTTInv((⟨ŝ, ŵ⟩).map(Rinv·))).map(R·)
      = (NTTInv(⟨ŝ, ŵ⟩)).map(Rinv·).map(R·)        -- NTTInv linearity
      = NTTInv(⟨ŝ, ŵ⟩).map(c ↦ R · Rinv · c)
      = NTTInv(⟨ŝ, ŵ⟩)                              -- R · Rinv = 1

The composite chain `v - NTTInv(⟨ŝ, ŵ⟩)` matches `K_PKE.Decrypt`'s
`w := v' - NTTInv(ŝ ◦ NTT u')` (FIPS 203 Algorithm 15, step 6).

Distinct from `decaps_m_chain` (G4.2), which absorbs `R` *into* `sh`
to match a hypothetical Mont-form `s` slot.  G4.2 is unused for the
current code path; G4.3 is the bridge that actually fires in
`decapsulateBody.spec`. -/
theorem decaps_m_chain_std {k_ : MLKEM.K}
    (sh wh : MLKEM.PolyVector q k_) :
    (MLKEM.NTTInv
        ((MLKEM.PolyVector.innerProductNTT sh wh).map (Rinv * ·))).map (R * ·)
      = MLKEM.NTTInv (MLKEM.PolyVector.innerProductNTT sh wh) := by
  rw [NTTInv_scalarMul]
  apply Vector.ext; intro i hi
  simp only [Vector.getElem_map]
  linear_combination ((MLKEM.NTTInv (MLKEM.PolyVector.innerProductNTT sh wh))[i])
                       * R_mul_Rinv

end Symcrust.Properties.MLKEM.Bridges
