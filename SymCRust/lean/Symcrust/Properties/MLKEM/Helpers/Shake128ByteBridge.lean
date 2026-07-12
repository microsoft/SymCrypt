/-
  # Helpers/Shake128ByteBridge.lean — XOF chained-squeeze ↔ extractOutput bridge.

  ## Purpose

  This file provides the **byte-stream bridge** that connects the MLKEM spec's
  chained `MLKEM.XOF.Squeeze · 3` calls (inside `sampleNttPartialAux`) to the
  impl-side ghost-tracked `extractOutput`-derived bytes (witnessed by
  `MlKemHashState.extract.spec`).

  This file provides the **byte-stream bridge** that connects the MLKEM spec's
  chained `MLKEM.XOF.Squeeze · 3` calls (inside `sampleNttPartialAux`) to the
  impl-side ghost-tracked `extractOutput`-derived bytes (witnessed by
  `MlKemHashState.extract.spec`).

  It exposes a single bridge theorem,
  `sampleNttPartialAux_squeeze_eq_extractOutput`, **discharged** against the
  SHA3 XOF properties landed in `Spec/SHA3/XOFProperties.lean`
  (`sponge.squeeze1_concat_bits`, `SHAKE128.squeeze_chain_eq_batch`,
  `bitsToBytes_squeeze1_init_eq_shake128`) plus the SHAKE128 incremental
  `shake128_extractOutput` from `Bridges/PrfShake.lean`.  No axioms.

  ## Why this lives in MLKEM/Helpers/ rather than SHA3/

  The contract is stated in MLKEM-specific terms (`sampleNttPartialAux`,
  `MLKEM.XOF.Squeeze`, `MLKEM.Polynomial.zero`).  It is discharged
  by combining three SHA3-internal lemmas (see
  `Properties/SHA3/XOF.md` §2.1–2.4):

  1. `sponge.squeeze1_concat_bits`  — bit-level composition (new, Spec/SHA3).
  2. `shake128_extractOutput`      — SHAKE128 analog of `shake256_extractOutput`
                                     (new, mirror of existing SHAKE256 work).
  3. A small ctx-equivalence step bridging `sampleNttPartialAux`'s chained
     ctx to a state-only chained accumulator.

  ## Downstream consumers

  - `Sampling/SampleNTT.lean` :: `poly_element_sample_ntt_from_shake128_spec_gen`
    accept arm (L811, L814) and reject arm (L909, L912).

  - No other consumer.  Encaps / Decaps / KeyGen use SHA3 only through
    `MlKemHashState.extract.spec` directly (no chained-squeeze pattern).
-/
import Symcrust.Properties.MLKEM.Basic.Params
import Symcrust.Properties.MLKEM.Hash
import Symcrust.Properties.MLKEM.Bridges.PrfShake
import Symcrust.Properties.SHA3.Basic
import Spec.MLKEM.Spec
import Spec.SHA3.XOFProperties

open Aeneas Aeneas.Std Result
open Spec
open Spec.SHA3
open Spec.SHA3.Incremental
open Spec.MLKEM
open scoped Spec.Notations
open symcrust
open sha3.sha3_impl

namespace Symcrust.Properties.MLKEM.Helpers

/-! ### Spec-side recursive XOF-sampling function.

This is the canonical (public) definition.  `Sampling/SampleNTT.lean` re-opens
this namespace and uses this very definition (avoiding a duplicate name and
the resulting unification mismatch when applying the bridge contract).
-/

noncomputable def sampleNttPartialAux
    (ctx : SHA3.Incremental.sponge.state (SHA3.b - 256))
    (â : MLKEM.Polynomial) (j : Nat) : Nat →
    SHA3.Incremental.sponge.state (SHA3.b - 256) × MLKEM.Polynomial × Nat
  | 0 => (ctx, â, j)
  | n + 1 =>
    if j < 256 then
      let (ctx', C) := MLKEM.XOF.Squeeze ctx 3
      let d₁ := C[0].val + 256 * (C[1].val % 16)
      let d₂ := C[1].val / 16 + 16 * C[2].val
      let (â₁, j₁) := if d₁ < MLKEM.q then (â.set! j d₁, j + 1) else (â, j)
      let (â₂, j₂) := if d₂ < MLKEM.q ∧ j₁ < 256 then (â₁.set! j₁ d₂, j₁ + 1) else (â₁, j₁)
      sampleNttPartialAux ctx' â₂ j₂ n
    else sampleNttPartialAux ctx â j n

/-! ### The bridge — single focused interface.

Reads: "for any seed and any round count `n`, IF the spec's `j`-counter has
not yet hit `256` after `n` rounds (i.e. the loop is still consuming bytes),
THEN the 3 bytes the spec would squeeze in round `n+1` equal the bytes at
positions `[3·n, 3·n+3)` of the canonical `extractOutput` from a fresh
SHAKE128 ghost state that absorbed the same seed."

This is the **sole** byte-bridge consumed by MLKEM SampleNTT.  All four byte-
bridge sorrys in `Sampling/SampleNTT.lean` close mechanically against this
single fact + the strengthened `sampleNttInv` clauses.

**Discharge plan**: see `Properties/SHA3/XOF.md` §2.4.  Three-piece composition:

1. Show that under `h_j_final`, the spec ctx after `n` rounds matches the ctx
   of a purely-state-threaded chained-squeeze accumulator (Nat induction; no
   byte reasoning).
2. Apply `sponge.squeeze1_concat_bits` (new — see XOF.md §2.1) to identify
   the concatenated chained bytes with one batched `(8·3·n)`-bit squeeze.
3. Apply `shake128_extractOutput` (new — see XOF.md §2.3) to identify the
   batched spec output with `extractOutput init_g (3·n)` byte-wise.

Once SHA3 lands those three pieces, the body of this theorem becomes the
composition; no further MLKEM-side coordination needed.
-/

/-! ### Helper lemmas for the bridge body. -/

lemma sampleNttPartialAux_j_le
    (ctx : SHA3.Incremental.sponge.state (SHA3.b - 256))
    (â : MLKEM.Polynomial) (j : Nat) (n : Nat) :
    j ≤ (sampleNttPartialAux ctx â j n).2.2 := by
  induction n generalizing ctx â j with
  | zero => simp [sampleNttPartialAux]
  | succ k ih =>
    unfold sampleNttPartialAux
    split
    · next h_j_lt =>
      split
      next ctx' C heq =>
      simp only
      split <;> split <;> (apply le_trans _ (ih _ _ _); omega)
    · exact ih ctx â j

lemma sampleNttPartialAux_fst_eq_squeeze
    (ctx : SHA3.Incremental.sponge.state (SHA3.b - 256))
    (â : MLKEM.Polynomial) (j : Nat) (n : Nat)
    (h_j : (sampleNttPartialAux ctx â j n).2.2 < 256) :
    (sampleNttPartialAux ctx â j n).1 =
      (sponge.squeeze1 SHA3.KECCAK_f (SHA3.b - 256) (by decide) ctx (24 * n)).1 := by
  induction n generalizing ctx â j with
  | zero =>
    simp [sampleNttPartialAux]
    conv_rhs => unfold sponge.squeeze1
    rw [dif_neg (by have := ctx.hx; simp; omega)]
    simp only [Nat.add_zero]
  | succ k ih =>
    have h_j_lt : j < 256 := by
      by_contra h
      simp only [not_lt] at h
      have hle := sampleNttPartialAux_j_le ctx â j (k+1)
      omega
    have h_xof_eq : MLKEM.XOF.Squeeze ctx 3 =
        ((sponge.squeeze1 KECCAK_f (b - 256) (by decide) ctx (8 * 3)).1,
         bitsToBytes (sponge.squeeze1 KECCAK_f (b - 256) (by decide) ctx (8 * 3)).2) := by
      show SHAKE128.squeeze ctx 3 = _; unfold SHAKE128.squeeze; rfl
    conv_lhs => unfold sampleNttPartialAux; rw [if_pos h_j_lt]
    have h_j' : (sampleNttPartialAux ctx â j (k+1)).2.2 < 256 := h_j
    conv at h_j' => unfold sampleNttPartialAux; rw [if_pos h_j_lt]
    rw [h_xof_eq] at h_j' ⊢
    simp only [] at h_j' ⊢
    generalize hp₁ : (if (bitsToBytes (sponge.squeeze1 KECCAK_f (b - 256) (by decide) ctx (8 * 3)).2)[0].val + 256 *
                          ((bitsToBytes (sponge.squeeze1 KECCAK_f (b - 256) (by decide) ctx (8 * 3)).2)[1].val % 16) <
                        MLKEM.q then
                      (Vector.set! â j (↑((bitsToBytes (sponge.squeeze1 KECCAK_f (b - 256) (by decide) ctx (8 * 3)).2)[0].val + 256 *
                          ((bitsToBytes (sponge.squeeze1 KECCAK_f (b - 256) (by decide) ctx (8 * 3)).2)[1].val % 16))), j + 1)
                    else (â, j)) = p₁ at h_j' ⊢
    obtain ⟨â₁, j₁⟩ := p₁
    simp only at h_j' ⊢
    generalize hp₂ : (if (bitsToBytes (sponge.squeeze1 KECCAK_f (b - 256) (by decide) ctx (8 * 3)).2)[1].val / 16 + 16 *
                          (bitsToBytes (sponge.squeeze1 KECCAK_f (b - 256) (by decide) ctx (8 * 3)).2)[2].val <
                        MLKEM.q ∧ j₁ < 256 then
                      (â₁.set! j₁ (↑((bitsToBytes (sponge.squeeze1 KECCAK_f (b - 256) (by decide) ctx (8 * 3)).2)[1].val / 16 + 16 *
                          (bitsToBytes (sponge.squeeze1 KECCAK_f (b - 256) (by decide) ctx (8 * 3)).2)[2].val)), j₁ + 1)
                    else (â₁, j₁)) = p₂ at h_j' ⊢
    obtain ⟨â₂, j₂⟩ := p₂
    simp only at h_j' ⊢
    rw [ih _ _ _ h_j']
    have hconcat_fst : (sponge.squeeze1 KECCAK_f (b - 256) (by decide)
            (sponge.squeeze1 KECCAK_f (b - 256) (by decide) ctx (8 * 3)).1 (24 * k)).1 =
          (sponge.squeeze1 KECCAK_f (b - 256) (by decide) ctx (8 * 3 + 24 * k)).1 :=
      congrArg Prod.fst (SHA3.sponge.squeeze1_concat_bits KECCAK_f (b - 256) (by decide) ctx (8*3) (24 * k))
    rw [show 8 * 3 + 24 * k = 24 * (k + 1) by ring] at hconcat_fst
    exact hconcat_fst

/--
**Bridge: spec-side chained `XOF.Squeeze · 3` equals impl-side `extractOutput`.**

For a seed `seed : 𝔹 n_seed`, a SHAKE128 ghost state `init_g` with absorbed
bytes equal to `seed.toList`, and any round count `n` for which the spec
has not yet stopped advancing the ctx (`j < 256` after `n` rounds), the 3
bytes the spec emits in round `n+1` of `sampleNttPartialAux` equal the
bytes `[3·n, 3·n+3)` of `extractOutput init_g (3·n+3)`.
-/
theorem sampleNttPartialAux_squeeze_eq_extractOutput
    {n_seed : Nat} (seed : 𝔹 n_seed) (init_g : GhostState)
    (h_absorbed : init_g.absorbed.map (·.bv) = seed.toList)
    (h_rate     : init_g.rate = 168)
    (h_pad      : init_g.padVal = 31#u8)
    (h_sq       : init_g.squeezed = [])
    (n : Nat)
    (h_j        : (sampleNttPartialAux (MLKEM.XOF.Absorb MLKEM.XOF.Init seed)
                     MLKEM.Polynomial.zero 0 n).2.2 < 256)
    (k : Fin 3) :
    (MLKEM.XOF.Squeeze
        (sampleNttPartialAux (MLKEM.XOF.Absorb MLKEM.XOF.Init seed)
          MLKEM.Polynomial.zero 0 n).1 3).2.get k =
      ((extractOutput init_g (3 * n + 3)).get
        ⟨3 * n + k.val, by have := k.isLt; omega⟩).bv := by
  set init_s := MLKEM.XOF.Absorb MLKEM.XOF.Init seed with h_init_s
  -- ctx_n = (sponge.squeeze1 ... init_s (24*n)).1
  have h_ctx : (sampleNttPartialAux init_s MLKEM.Polynomial.zero 0 n).1 =
      (sponge.squeeze1 KECCAK_f (b - 256) (by decide) init_s (24 * n)).1 :=
    sampleNttPartialAux_fst_eq_squeeze init_s _ _ _ h_j
  rw [h_ctx]
  show (SHAKE128.squeeze _ 3).2.get k = _
  unfold SHAKE128.squeeze
  simp only []
  -- Step 1: hctx_chain — (chainedSqueeze 3 init_s n).1 = ctx_n.
  have hctx_chain : (chainedSqueeze 3 init_s n).1 =
      (sponge.squeeze1 KECCAK_f (b - 256) (by decide) init_s (24 * n)).1 := by
    have := SHAKE128.squeeze_chain_eq_batch 3 init_s n
    have h : (chainedSqueeze 3 init_s n).1 = ((sponge.squeeze1 KECCAK_f (b - 256) (by decide) init_s (8 * (3 * n))).map id bitsToBytes).1 :=
      congrArg Prod.fst this
    rw [h]
    show (sponge.squeeze1 KECCAK_f (b - 256) (by decide) init_s (8 * (3 * n))).1 = _
    rw [show 8 * (3 * n) = 24 * n by ring]
  -- Step 2: (chainedSqueeze 3 init_s (n+1)).2 = ((chainedSqueeze 3 init_s n).2 ‖ ...).cast _
  have h_succ : (chainedSqueeze 3 init_s (n + 1)).2 =
      ((chainedSqueeze 3 init_s n).2 ‖
       (SHAKE128.squeeze (chainedSqueeze 3 init_s n).1 3).2).cast (by ring) := by
    show (let (s', acc) := chainedSqueeze 3 init_s n
          let (s'', bs) := SHAKE128.squeeze s' 3
          (s'', Vector.cast _ (acc ++ bs))).2 = _
    rfl
  -- Step 3: position 3*n + k.val of (acc ‖ bs).cast = bs.get k
  have h_pos : ∀ (acc : 𝔹 (3 * n)) (bs : 𝔹 3),
      ((acc ‖ bs).cast (by ring : 3 * n + 3 = 3 * (n + 1))).get ⟨3 * n + k.val, by have := k.isLt; omega⟩
      = bs.get k := by
    intros acc bs
    show ((acc ‖ bs).cast _)[3 * n + k.val] = _
    rw [Vector.getElem_cast]
    rw [show (acc ‖ bs) = (acc ++ bs) from rfl]
    rw [Vector.getElem_append]
    rw [dif_neg (by omega : ¬ 3 * n + k.val < 3 * n)]
    show bs[(3 * n + k.val) - 3 * n]'(by have := k.isLt; omega) = bs[k.val]'k.isLt
    fcongr 1
    omega
  -- Step 4: rewrite LHS = (chainedSqueeze 3 init_s (n+1)).2 .get ⟨3*n+k.val, _⟩
  rw [← hctx_chain]
  show ((SHAKE128.squeeze (chainedSqueeze 3 init_s n).1 3).2).get k = _
  rw [← h_pos (chainedSqueeze 3 init_s n).2
        (SHAKE128.squeeze (chainedSqueeze 3 init_s n).1 3).2]
  rw [← h_succ]
  -- Step 5: expand via squeeze_chain_eq_batch
  rw [SHAKE128.squeeze_chain_eq_batch]
  show (bitsToBytes (sponge.squeeze1 KECCAK_f (b - 256) (by decide) init_s (8 * (3 * (n + 1)))).2).get
        ⟨3 * n + k.val, _⟩ = _
  -- Step 6: bridge to shake128 via bitsToBytes_squeeze1_init_eq_shake128
  have h_init_eq : init_s = SHAKE128.absorb SHAKE128.init seed := by
    show MLKEM.XOF.Absorb MLKEM.XOF.Init seed = _; rfl
  rw [h_init_eq, SHAKE128.bitsToBytes_squeeze1_init_eq_shake128 seed (3 * (n + 1))]
  -- Step 7: bridge RHS via shake128_extractOutput
  have h_n_seed : init_g.absorbed.length = n_seed := by
    have h := congrArg List.length h_absorbed
    simp only [List.length_map, Vector.length_toList] at h
    exact h
  have h_bytes : ∀ (i : Fin n_seed),
      seed.get i = (init_g.absorbed[i.val]'(h_n_seed ▸ i.isLt)).bv := by
    intro i
    show seed[i.val]'i.isLt = _
    have hi_lt : i.val < seed.toList.length := by have := i.isLt; simp [Vector.length_toList]
    have h1 : seed.toList[i.val] = seed[i.val]'i.isLt := Vector.getElem_toList hi_lt
    have h2 : (List.map (·.bv) init_g.absorbed)[i.val]'(by have := i.isLt; simp [List.length_map, h_n_seed])
            = (init_g.absorbed[i.val]'(h_n_seed ▸ i.isLt)).bv :=
      List.getElem_map _
    rw [← h1, ← h2]
    fcongr 1
    exact h_absorbed.symm
  have hRHS : ((extractOutput init_g (3 * n + 3)).get
        ⟨3 * n + k.val, by have := k.isLt; omega⟩).bv
      = ((extractOutput init_g (3 * n + 3)).map (·.bv)).get
        ⟨3 * n + k.val, by have := k.isLt; omega⟩ := by
    show _ = ((extractOutput init_g (3 * n + 3)).map (·.bv))[3 * n + k.val]
    rw [Vector.getElem_map]
    rfl
  rw [hRHS, shake128_extractOutput init_g seed (3 * n + 3) h_n_seed h_bytes h_rate h_pad h_sq]
  -- Step 8: 3*(n+1) = 3*n+3 (definitional: Nat.mul recurses on the successor)
  rfl

/-! ### Elementary helper lemmas for `sampleNttPartialAux`.

These were originally `private` in `Sampling/SampleNTT.lean`; they are
moved here so that the new `Helpers/SampleNttTermination.lean` (which
proves the Barbosa–Schwabe termination argument) can use them without
introducing a cycle. -/

/-- Cons step for `sampleNttPartialAux`: direct unfolding. -/
theorem sampleNttPartialAux_succ
    (ctx : SHA3.Incremental.sponge.state (SHA3.b - 256))
    (â : MLKEM.Polynomial) (j : Nat) (n : Nat) :
    sampleNttPartialAux ctx â j (n + 1) =
      if j < 256 then
        let (ctx', C) := MLKEM.XOF.Squeeze ctx 3
        let d₁ := C[0].val + 256 * (C[1].val % 16)
        let d₂ := C[1].val / 16 + 16 * C[2].val
        let (â₁, j₁) := if d₁ < MLKEM.q then (â.set! j d₁, j + 1) else (â, j)
        let (â₂, j₂) := if d₂ < MLKEM.q ∧ j₁ < 256 then (â₁.set! j₁ d₂, j₁ + 1) else (â₁, j₁)
        sampleNttPartialAux ctx' â₂ j₂ n
      else sampleNttPartialAux ctx â j n := rfl

/-- Invariant: `j ≤ 256` is preserved by the helper. -/
theorem sampleNttPartialAux_filled_le
    (ctx : SHA3.Incremental.sponge.state (SHA3.b - 256))
    (â : MLKEM.Polynomial) (j : Nat) (n : Nat) (h_j : j ≤ 256) :
    (sampleNttPartialAux ctx â j n).2.2 ≤ 256 := by
  induction n generalizing ctx â j with
  | zero => unfold sampleNttPartialAux; simpa
  | succ k ih =>
    rw [sampleNttPartialAux_succ]
    by_cases hj : j < 256
    · simp only [hj, if_true]
      split <;> split <;> apply ih <;> agrind
    · simp only [hj, if_false]
      exact ih ctx â j h_j

/-- Once `j` reaches 256 the helper is stable. -/
theorem sampleNttPartialAux_stable_at_256
    (ctx : SHA3.Incremental.sponge.state (SHA3.b - 256))
    (â : MLKEM.Polynomial) (n : Nat) :
    sampleNttPartialAux ctx â 256 n = (ctx, â, 256) := by
  induction n generalizing ctx â with
  | zero => rfl
  | succ k ih => rw [sampleNttPartialAux_succ]; simp [ih]

/-- Splitting lemma: a sum of round counts equals nested calls. -/
theorem sampleNttPartialAux_add
    (ctx : SHA3.Incremental.sponge.state (SHA3.b - 256))
    (â : MLKEM.Polynomial) (j : Nat) (m n : Nat) :
    sampleNttPartialAux ctx â j (m + n) =
      let s := sampleNttPartialAux ctx â j m
      sampleNttPartialAux s.1 s.2.1 s.2.2 n := by
  induction m generalizing ctx â j with
  | zero => simp [sampleNttPartialAux]
  | succ k ih =>
    rw [Nat.add_right_comm]
    rw [sampleNttPartialAux_succ, sampleNttPartialAux_succ]
    split <;> simp_all

end Symcrust.Properties.MLKEM.Helpers
