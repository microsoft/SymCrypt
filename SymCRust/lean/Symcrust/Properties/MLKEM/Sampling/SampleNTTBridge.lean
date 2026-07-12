/-
  # Sampling/SampleNTT.lean — `poly_element_sample_ntt_from_shake128`.

  Implements FIPS 203 Algorithm 7 (SampleNTT): rejection-sample 256
  coefficients in `[0, q)` from a SHAKE128 XOF, producing a polynomial
  in NTT domain.  Each 24-bit chunk of XOF output yields two 12-bit
  candidates; each candidate is accepted iff `< q`.

  ## Structure-vs-body decomposition

  This loop has a non-standard shape: top is `if i < MLWE then …
  recursive body … else ok` (no `next + match`).  We use a single
  `branch 0 (letRange 0 16) => body_prefix` extraction:

  * `_body_prefix` — pure per-iteration prep work:
    refill the 24-byte buffer if exhausted, load two 12-bit samples,
    advance the buffer cursor by 3, return the new buffer state and
    the two candidate samples plus the closure that writes
    `pe_dst[i]`.
  * `_loop.fold` — top-level equation; the remaining body is the
    terminal `if i8 < MLWE then recurse else recurse` (two
    `if-then-else` branches both doing one recursive call with
    different counter increments).

  The terminal inner-if cannot be further decomposed by the current
  `#decompose` primitives without introducing a fold over both
  recursive branches.

  ## Postcondition shape (wrapper)

  `toPoly result.2 = MLKEM.SampleNTT (xofExtract p_state)`

  where `xofExtract : MlKemHashState → ByteStream` is the abstract
  XOF byte-stream model (to be defined in `HashCalls.lean`).
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Hash
import Symcrust.Properties.MLKEM.Bridges.MontArith
import Symcrust.Properties.MLKEM.Ntt.Bytes
import Symcrust.Properties.MLKEM.Helpers.SampleNttBytes
import Symcrust.Properties.MLKEM.Helpers.Shake128ByteBridge
import Symcrust.Properties.MLKEM.Helpers.SampleNttTermination
import Symcrust.Properties.Iterators

open Aeneas Aeneas.Std Result
open scoped Spec.Notations
open Spec
open Spec.MLKEM
open symcrust

namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges
open Symcrust.Properties.MLKEM.Helpers

set_option maxHeartbeats 4000000
set_option maxRecDepth 2048

/-- The two 12-bit candidates derived from one 3-byte XOF chunk
(`d₁, d₂` per FIPS 203 Algorithm 7 / matching `sampleNttPartial`'s
per-round step). -/
def nttCandidatesOfBytes (c0 c1 c2 : U8) : Nat × Nat :=
  (c0.val + 256 * (c1.val % 16), c1.val / 16 + 16 * c2.val)

/-! ### Parameterised, recursive form of the SampleNTT rejection loop.

The actual `def` lives in `Helpers/Shake128ByteBridge.lean` (so that the
byte-bridge contract's signature and the consumer here refer to the **same**
declaration; separate `private` definitions would cause a
unification mismatch when applying the bridge).  See that file for the
docstring. -/

/- `sampleNttPartialAux_succ`, `_filled_le`, `_stable_at_256`, `_add`
   are defined in `Helpers/Shake128ByteBridge.lean`. -/

/-- Partial run of `MLKEM.SampleNTT`: runs the rejection-sampling
loop for `n_rounds` rounds (each round consumes 3 XOF bytes, proposes
up to 2 candidates) and returns the partial polynomial together with
the number of accepted coefficients.

This is a Nat-fueled total version of the spec's `while` loop — it
runs at most `n_rounds` rounds regardless of how many coefficients
have been accepted. The full spec is recovered when `n_rounds` is
large enough to fill `j = 256`.

Defined as a projection of the recursive helper `sampleNttPartialAux`
(declared just above) so that all subsequent monotonicity / stability
lemmas can reason directly about the recursive form.  Bridge to the
spec's `Id.run do … for … in List.range n_rounds do …` shape is
straightforward: the per-round body in `sampleNttPartialAux` matches
the spec body modulo `Vector.set!` ↔ `Vector.set` (equal under the
guard `j < 256`). -/
noncomputable def sampleNttPartial (B : 𝔹 34) (n_rounds : Nat) :
    MLKEM.Polynomial × Nat :=
  let s := sampleNttPartialAux (MLKEM.XOF.Absorb MLKEM.XOF.Init B) MLKEM.Polynomial.zero 0 n_rounds
  (s.2.1, s.2.2)


/-- **SampleNTT termination** — the rejection-sampling loop accepts 256
coefficients after finitely many rounds.

ML-KEM samples polynomial coefficients by rejection sampling from a stream of
12-bit values derived from SHAKE, which raises the question of whether the loop
terminates. It does: this theorem is discharged by
`Helpers.sampleNttPartialAux_terminates`, a formalization of the
Barbosa–Schwabe termination argument (Manuel Barbosa and Peter Schwabe,
"Kyber Terminates", ePrint 2023/708) via the eventual periodicity of the
SHAKE128 squeeze stream (`Spec/SHA3/Termination.lean`). It is therefore fully
proved — not assumed. -/

theorem kyber_terminates (B : 𝔹 34) :
    ∃ (n : Nat), (sampleNttPartial B n).2 = 256 := by
  obtain ⟨n, hn⟩ := Helpers.sampleNttPartialAux_terminates B
  exact ⟨n, hn⟩

-- `sampleNttPartial_full_eq_SampleNTT` and the derived
-- `sampleNttPartial_eq.spec` are defined below, after the helper
-- lemmas (`sampleNttPartialAux_stable_at_256` etc.) they depend on.

/-! ### Elementary monotonicity / stability lemmas for `sampleNttPartial`

These are pure Nat-fueled facts about the deterministic recursive
helper `sampleNttPartialAux` (above): each round adds 0, 1, or 2
accepted coefficients, and once `j = 256` the round body is the
inner-`if`'s false branch — the state stops changing.  Both lemmas
are required by the termination argument of the runtime loop
(lexicographic measure on `(256 - i.val, nCap - n_rounds)`). -/

/-- Bridge from `sampleNttPartial` to the recursive helper
`sampleNttPartialAux`.  Holds by definition because
`sampleNttPartial` is defined as a projection of
`sampleNttPartialAux`. -/
theorem sampleNttPartial_eq_aux (B : 𝔹 34) (n : Nat) :
    sampleNttPartial B n =
      ((sampleNttPartialAux (MLKEM.XOF.Absorb MLKEM.XOF.Init B) MLKEM.Polynomial.zero 0 n).2.1,
       (sampleNttPartialAux (MLKEM.XOF.Absorb MLKEM.XOF.Init B) MLKEM.Polynomial.zero 0 n).2.2) := by
  rfl

/-- The number of accepted coefficients never exceeds 256. -/
theorem sampleNttPartial_filled_count_le (B : 𝔹 34) (n : Nat) :
    (sampleNttPartial B n).2 ≤ 256 := by
  rw [sampleNttPartial_eq_aux]
  exact sampleNttPartialAux_filled_le _ _ _ _ (by simp)


/-! ### Bridge from `sampleNttPartial` to `MLKEM.SampleNTT` (spec)

The spec `MLKEM.SampleNTT` is defined as a `letRange 0 (256 ⊔ N) ⋯`
loop over an opaque `Lean.Loop.forIn` body that mutates a triple
`(ctx, j, â)` (note: spec orders the inner pair `(j, â)`, whereas
`sampleNttPartialAux` uses `(â, j)`).  The mechanical proof
`sampleNttPartial_full_eq_SampleNTT` proceeds in three steps:

1. **`specBody`**: pull the spec's inline body out as a named def
   (modulo the j/â reordering, this is `MLKEM.SampleNTT`'s body
   verbatim).  Use `Loop_forIn_Id_unfold` to peel one iteration at a
   time and match against `sampleNttPartialAux_succ`.

2. **`forIn_spec_eq_aux`**: generalised induction on `n`, with `j`
   generalised too.  Base case (`n = 0`) forces `j = 256` and the
   body's outer-`if` falls through to `.done`.  Inductive case splits
   on `j < 256`; the `j < 256` branch peels one body iteration and
   appeals to `ih`; the `j = 256` branch uses `stable_at_256`.

3. Specialise to the initial state `(XOF.Absorb XOF.Init B, 0, zero)`.
-/

/-- `Vector.set!` agrees with `Vector.set` whenever the index is in
range.  Used to bridge the spec's `set` (proof-carrying) with the
recursive helper's `set!` (panic-on-OOB). -/
private theorem Vector.set!_eq_set_of_lt {α : Type*} {n : Nat}
    (v : Vector α n) (i : Nat) (h : i < n) (a : α) :
    v.set! i a = v.set i a h := by
  simp [_root_.Vector.set!, _root_.Vector.set, Array.setIfInBounds, h]

/-- The body of the spec's `Lean.Loop.forIn`, named.  This is `rfl`-
equal to the inline lambda that elaborates inside `MLKEM.SampleNTT`. -/
private noncomputable def specBody :
    Unit → MProd (SHA3.Incremental.sponge.state (SHA3.b - 256))
              (MProd Nat MLKEM.Polynomial) →
        ForInStep (MProd (SHA3.Incremental.sponge.state (SHA3.b - 256))
                    (MProd Nat MLKEM.Polynomial)) :=
  fun _ r =>
    let ctx := r.fst
    let j := r.snd.fst
    let â := r.snd.snd
    if hj : j < 256 then
      let (ctx', C) := MLKEM.XOF.Squeeze ctx 3
      let d₁ := C[0].val + 256 * (C[1].val % 16)
      let d₂ := C[1].val / 16 + 16 * C[2].val
      if d₁ < MLKEM.q then
        let â' := â.set j (↑d₁) hj
        let j' := j + 1
        if h : d₂ < MLKEM.q ∧ j' < 256 then
          ForInStep.yield ⟨ctx', j' + 1, â'.set j' (↑d₂) h.2⟩
        else
          ForInStep.yield ⟨ctx', j', â'⟩
      else
        if h : d₂ < MLKEM.q ∧ j < 256 then
          ForInStep.yield ⟨ctx', j + 1, â.set j (↑d₂) h.2⟩
        else
          ForInStep.yield ⟨ctx', j, â⟩
    else
      ForInStep.done r

/-- The spec `MLKEM.SampleNTT B` unfolds (definitionally) to the
`Lean.Loop.forIn` driven by `specBody` starting from the initial
state `⟨XOF.Absorb XOF.Init B, 0, Polynomial.zero⟩`. -/
private theorem sample_eq_loop (B : 𝔹 34) :
    MLKEM.SampleNTT B = (@Lean.Loop.forIn _ Id _ Lean.Loop.mk
      (⟨MLKEM.XOF.Absorb MLKEM.XOF.Init B, 0, MLKEM.Polynomial.zero⟩ :
        MProd _ (MProd Nat MLKEM.Polynomial)) specBody).snd.snd := rfl

/-- Generalised induction lemma: if the recursive helper saturates
`j = 256` at some round count `n`, then the spec's `Lean.Loop.forIn`
from the same intermediate state agrees on the polynomial output. -/
private theorem forIn_spec_eq_aux
    (n : Nat) (ctx : SHA3.Incremental.sponge.state (SHA3.b - 256))
    (â : MLKEM.Polynomial) (j : Nat) (hj : j ≤ 256)
    (h_full : (sampleNttPartialAux ctx â j n).2.2 = 256) :
    (@Lean.Loop.forIn _ Id _ Lean.Loop.mk
      (⟨ctx, j, â⟩ : MProd _ (MProd Nat MLKEM.Polynomial))
      specBody).snd.snd = (sampleNttPartialAux ctx â j n).2.1 := by
  induction n generalizing ctx â j with
  | zero =>
    have h_jeq : j = 256 := by
      have : (sampleNttPartialAux ctx â j 0).2.2 = j := rfl
      grind
    subst h_jeq
    rw [symcrust.Loop_forIn_Id_unfold]
    have hstep_done : specBody () ⟨ctx, 256, â⟩ = ForInStep.done ⟨ctx, 256, â⟩ := by
      unfold specBody
      simp
    rw [hstep_done]
    rfl
  | succ k ih =>
    rw [symcrust.Loop_forIn_Id_unfold]
    rw [sampleNttPartialAux_succ] at h_full ⊢
    by_cases h_j_lt : j < 256
    · generalize hsqu : MLKEM.XOF.Squeeze ctx 3 = sq
      obtain ⟨ctx', C⟩ := sq
      simp only [h_j_lt, if_true, hsqu] at h_full ⊢
      by_cases h1 : C[0].val + 256 * (C[1].val % 16) < MLKEM.q
      · by_cases h2 : C[1].val / 16 + 16 * C[2].val < MLKEM.q ∧ j + 1 < 256
        · have h_step :
              specBody () ⟨ctx, j, â⟩ =
                ForInStep.yield ⟨ctx', j + 1 + 1,
                  (â.set! j (↑(C[0].val + 256 * (C[1].val % 16) : Nat) : ZMod MLKEM.q)).set!
                    (j + 1) (↑(C[1].val / 16 + 16 * C[2].val : Nat) : ZMod MLKEM.q)⟩ := by
            unfold specBody; dsimp only; rw [hsqu]
            rw [dif_pos h_j_lt, if_pos h1, dif_pos h2]
            simp only [Vector.set!_eq_set_of_lt _ _ h_j_lt,
                       Vector.set!_eq_set_of_lt _ _ h2.2]
          rw [h_step]
          show (@Lean.Loop.forIn _ Id _ Lean.Loop.mk _ specBody).snd.snd = _
          simp only [h1, if_true, h2] at h_full ⊢
          apply ih _ _ _ (by scalar_tac) h_full
        · have h_step :
              specBody () ⟨ctx, j, â⟩ =
                ForInStep.yield ⟨ctx', j + 1,
                  â.set! j (↑(C[0].val + 256 * (C[1].val % 16) : Nat) : ZMod MLKEM.q)⟩ := by
            unfold specBody; dsimp only; rw [hsqu]
            rw [dif_pos h_j_lt, if_pos h1, dif_neg h2]
            simp only [Vector.set!_eq_set_of_lt _ _ h_j_lt]
          rw [h_step]
          show (@Lean.Loop.forIn _ Id _ Lean.Loop.mk _ specBody).snd.snd = _
          simp only [h1, if_true, h2, if_false] at h_full ⊢
          apply ih _ _ _ (by scalar_tac) h_full
      · by_cases h2 : C[1].val / 16 + 16 * C[2].val < MLKEM.q ∧ j < 256
        · have h_step :
              specBody () ⟨ctx, j, â⟩ =
                ForInStep.yield ⟨ctx', j + 1,
                  â.set! j (↑(C[1].val / 16 + 16 * C[2].val : Nat) : ZMod MLKEM.q)⟩ := by
            unfold specBody; dsimp only; rw [hsqu]
            rw [dif_pos h_j_lt, if_neg h1, dif_pos h2]
            simp only [Vector.set!_eq_set_of_lt _ _ h2.2]
          rw [h_step]
          show (@Lean.Loop.forIn _ Id _ Lean.Loop.mk _ specBody).snd.snd = _
          simp only [h1, if_false, h2] at h_full ⊢
          apply ih _ _ _ (by scalar_tac) h_full
        · have h_step :
              specBody () ⟨ctx, j, â⟩ = ForInStep.yield ⟨ctx', j, â⟩ := by
            unfold specBody; dsimp only; rw [hsqu]
            rw [dif_pos h_j_lt, if_neg h1, dif_neg h2]
          rw [h_step]
          show (@Lean.Loop.forIn _ Id _ Lean.Loop.mk _ specBody).snd.snd = _
          simp only [h1, if_false, h2] at h_full ⊢
          apply ih _ _ _ (by scalar_tac) h_full
    · have h_jeq : j = 256 := Nat.le_antisymm hj (Nat.le_of_not_lt h_j_lt)
      subst h_jeq
      simp only [show ¬ (256 : Nat) < 256 from by decide, if_false] at h_full ⊢
      have hstep_done : specBody () ⟨ctx, 256, â⟩ = ForInStep.done ⟨ctx, 256, â⟩ := by
        unfold specBody
        simp
      rw [hstep_done]
      show â = (sampleNttPartialAux ctx â 256 k).2.1
      rw [sampleNttPartialAux_stable_at_256]

/-- **Mechanical bridge** — when the recursive helper terminates
(reaches `j = 256` at some `n`), its accumulated polynomial agrees
with the spec `MLKEM.SampleNTT`.

This is the spec↔recursion half of the trust-base split.  Combined
with the (out-of-scope, axiomatic) `kyber_terminates`, it gives
`sampleNttPartial_eq.spec`. -/
theorem sampleNttPartial_full_eq_SampleNTT (B : 𝔹 34) (n : Nat)
    (h_full : (sampleNttPartial B n).2 = 256) :
    (sampleNttPartial B n).1 = MLKEM.SampleNTT B := by
  rw [sample_eq_loop]
  unfold sampleNttPartial
  unfold sampleNttPartial at h_full
  simp at h_full ⊢
  exact (forIn_spec_eq_aux n _ _ 0 (Nat.zero_le _) h_full).symm

/-- The spec↔recursion existential.  Combines the external
`kyber_terminates` (Barbosa–Schwabe 2023) with the mechanical
`sampleNttPartial_full_eq_SampleNTT`. -/
theorem sampleNttPartial_eq.spec (B : 𝔹 34) :
    ∃ (n : Nat), (sampleNttPartial B n).2 = 256 ∧
                 (sampleNttPartial B n).1 = MLKEM.SampleNTT B := by
  obtain ⟨n, h_full⟩ := kyber_terminates B
  exact ⟨n, h_full, sampleNttPartial_full_eq_SampleNTT B n h_full⟩

/-- The accepted-count function is monotone in `n_rounds`. -/
theorem sampleNttPartial_filled_count_mono (B : 𝔹 34) {m n : Nat} (h : m ≤ n) :
    (sampleNttPartial B m).2 ≤ (sampleNttPartial B n).2 := by
  rw [sampleNttPartial_eq_aux, sampleNttPartial_eq_aux]
  -- Generalise: prove `j₀ ≤ (sampleNttPartialAux ctx â j₀ k).2.2`.
  suffices h_aux :
      ∀ (k : Nat) (ctx : SHA3.Incremental.sponge.state (SHA3.b - 256))
        (â : MLKEM.Polynomial) (j : Nat),
        j ≤ (sampleNttPartialAux ctx â j k).2.2 by
    have h_nm : n = m + (n - m) := by agrind
    rw [h_nm, sampleNttPartialAux_add]
    exact h_aux _ _ _ _
  intro k ctx â j
  induction k generalizing ctx â j with
  | zero => unfold sampleNttPartialAux; simp
  | succ k ih =>
    rw [sampleNttPartialAux_succ]
    by_cases hj : j < 256
    · simp only [hj, if_true]
      split <;> split <;> · refine le_trans ?_ (ih _ _ _); agrind
    · simp only [hj, if_false]
      exact ih _ _ _

/-- Once 256 coefficients are accepted, additional rounds are no-ops:
`sampleNttPartial` is stable for `n ≥ n₀`. -/
theorem sampleNttPartial_stable_at_256 (B : 𝔹 34) {m n : Nat}
    (h_full : (sampleNttPartial B m).2 = 256) (h_le : m ≤ n) :
    sampleNttPartial B n = sampleNttPartial B m := by
  rw [sampleNttPartial_eq_aux, sampleNttPartial_eq_aux]
  have h_nm : n = m + (n - m) := by agrind
  have h_j_eq :
      (sampleNttPartialAux (MLKEM.XOF.Absorb MLKEM.XOF.Init B) MLKEM.Polynomial.zero 0 m).2.2 = 256 := by
    have := h_full
    rw [sampleNttPartial_eq_aux] at this
    exact this
  rw [h_nm, sampleNttPartialAux_add]
  simp only
  rw [h_j_eq, sampleNttPartialAux_stable_at_256]

/-- Contrapositive of stability, the form used in the termination
argument: if the partial run has not yet filled 256 slots at round
`n_rounds`, then `n_rounds` is strictly below any `nCap` that does. -/
theorem sampleNttPartial_not_full_lt (B : 𝔹 34) {n_rounds nCap : Nat}
    (h_cap : (sampleNttPartial B nCap).2 = 256)
    (h_not_full : (sampleNttPartial B n_rounds).2 < 256) :
    n_rounds < nCap := by
  by_contra h
  push Not at h
  -- From `h : nCap ≤ n_rounds` and `h_cap`, stability yields
  -- `(sampleNttPartial B n_rounds).2 = 256`, contradicting `h_not_full`.
  have := sampleNttPartial_stable_at_256 B h_cap h
  rw [this] at h_not_full
  omega


end Symcrust.Properties.MLKEM
