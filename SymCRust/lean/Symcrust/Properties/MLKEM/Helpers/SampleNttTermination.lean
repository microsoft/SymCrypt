import Spec.SHA3.Termination
import Symcrust.Properties.MLKEM.Helpers.Shake128ByteBridge
import Mathlib.Algebra.BigOperators.Group.Finset.Basic

/-!
# MLKEM SampleNTT — unconditional termination

This module discharges the termination axiom for ML-KEM's
rejection-sampling helper `sampleNttPartialAux`.  We prove

```
theorem sampleNttPartialAux_terminates (B : 𝔹 34) :
    ∃ n, (sampleNttPartialAux (MLKEM.XOF.Absorb MLKEM.XOF.Init B)
            MLKEM.Polynomial.zero 0 n).2.2 = 256
```

The proof formalises the Barbosa–Schwabe (2024, ePrint 2023/708)
argument:

* Since `KECCAK_f` is a permutation on `Vector Bool 1600`, the
  SHAKE128 squeeze stream from any seed is eventually periodic
  with some period `m ≤ 2^1600` (`Spec/SHA3/Termination.lean`).
* The pre-Absorb state `S₋₁` has at least 43 fully-aligned zero
  3-byte triples (out of 56) in its rate part.  At each period the
  rate part of `S₋₁` reappears in the squeeze, contributing 43
  zero rounds (`zero_bytes_per_cycle`).
* Each zero round contributes 2 accepted coefficients (since the
  candidates `d₁ = 0` and `d₂ = 0` are both `< q = 3329`).
* After 3 cycles we have at least 129 zero rounds → 258 ≥ 256
  acceptances.

The SHA3-side facts live in `Spec/SHA3/Termination.lean`.  This
file does the MLKEM-side counting.
-/

open Aeneas Aeneas.Std Result
open scoped Spec.Notations
open scoped Classical
open Spec
open Spec.SHA3
open Spec.SHA3.Incremental
open Spec.MLKEM
open Symcrust.Properties.MLKEM.Helpers

namespace Symcrust.Properties.MLKEM.Helpers

/-! ## §1. Round-byte ↔ shake128 bridge. -/

/-- **Strong round-byte bridge.**  For any seed `B`, any round index `n`,
and any byte length `M` covering at least `3·(n+1)` bytes, the 3 bytes
emitted by round `n+1` of `sampleNttPartialAux` (i.e. the bytes the spec
would squeeze when reading round `n`'s `XOF.Squeeze` call) coincide with
bytes `[3·n, 3·n+3)` of `shake128 B M`.

The hypothesis `h_j` records that the loop has not yet hit its `j = 256`
ceiling after `n` rounds — only in that case do we still squeeze fresh
bytes. -/
theorem sampleNttPartialAux_round_bytes_eq_shake128
    (B : 𝔹 34) (n : Nat) (M : Nat) (hM : 3 * (n + 1) ≤ M) (k : Fin 3)
    (h_j : (sampleNttPartialAux (MLKEM.XOF.Absorb MLKEM.XOF.Init B)
              MLKEM.Polynomial.zero 0 n).2.2 < 256) :
    (MLKEM.XOF.Squeeze
        (sampleNttPartialAux (MLKEM.XOF.Absorb MLKEM.XOF.Init B)
          MLKEM.Polynomial.zero 0 n).1 3).2.get k =
      (shake128 B M)[3 * n + k.val]'(by have := k.isLt; omega) := by
  set init_s := MLKEM.XOF.Absorb MLKEM.XOF.Init B with h_init_s
  /- Step 1: bridge ctx after n rounds to (chainedSqueeze 3 init_s n).1. -/
  have h_ctx_sq : (sampleNttPartialAux init_s MLKEM.Polynomial.zero 0 n).1 =
      (sponge.squeeze1 KECCAK_f (b - 256) (by decide) init_s (24 * n)).1 :=
    sampleNttPartialAux_fst_eq_squeeze init_s _ _ _ h_j
  have h_24n : (24 : Nat) * n = 8 * (3 * n) := by ring
  have h_ctx_chain : (sampleNttPartialAux init_s MLKEM.Polynomial.zero 0 n).1 =
      (chainedSqueeze 3 init_s n).1 := by
    rw [h_ctx_sq, SHAKE128.squeeze_chain_eq_batch]
    show (sponge.squeeze1 KECCAK_f (b - 256) (by decide) init_s (24 * n)).1 =
         (sponge.squeeze1 KECCAK_f (b - 256) (by decide) init_s (8 * (3 * n))).1
    rw [h_24n]
  rw [h_ctx_chain]
  /- Step 2: turn the goal LHS into a byte-index of (chainedSqueeze 3 init_s (n+1)).2. -/
  show ((SHAKE128.squeeze (chainedSqueeze 3 init_s n).1 3).2).get k = _
  /- Unfold the (n+1)-st step of chainedSqueeze:
       (chainedSqueeze 3 init_s (n+1)).2
       = ((chainedSqueeze 3 init_s n).2 ‖ (SHAKE128.squeeze _ 3).2).cast _    -/
  /- Read off the right segment of the appended Vector. -/
  have h_idx_eq :
      ((SHAKE128.squeeze (chainedSqueeze 3 init_s n).1 3).2).get k
      = (chainedSqueeze 3 init_s (n + 1)).2.get
          ⟨3 * n + k.val, by have := k.isLt; omega⟩ := by
    /- chainedSqueeze (n+1) = let (s', acc) := chainedSqueeze n; let (s'', bs) := SHAKE128.squeeze s' 3;
       (s'', (acc ++ bs).cast _).  Take .2 and reduce. -/
    conv_rhs =>
      rw [show (chainedSqueeze 3 init_s (n + 1)).2 =
        ((chainedSqueeze 3 init_s n).2 ++
         (SHAKE128.squeeze (chainedSqueeze 3 init_s n).1 3).2).cast
            (by ring : 3 * n + 3 = 3 * (n + 1)) from rfl]
    show _ = (((chainedSqueeze 3 init_s n).2 ++
               (SHAKE128.squeeze (chainedSqueeze 3 init_s n).1 3).2).cast _)[3 * n + k.val]
    rw [Vector.getElem_cast]
    rw [Vector.getElem_append]
    rw [dif_neg (by omega : ¬ 3 * n + k.val < 3 * n)]
    have h_simp : (3 * n + k.val) - 3 * n = k.val := by omega
    show (SHAKE128.squeeze (chainedSqueeze 3 init_s n).1 3).2[k.val]'k.isLt
        = (SHAKE128.squeeze (chainedSqueeze 3 init_s n).1 3).2[(3 * n + k.val) - 3 * n]'
              (by have := k.isLt; omega)
    fcongr 1
    omega
  rw [h_idx_eq]
  /- Step 3: convert chainedSqueeze (n+1) bytes to shake128 B (3*(n+1)). -/
  have h_init_eq : init_s = SHAKE128.absorb SHAKE128.init B := by
    show MLKEM.XOF.Absorb MLKEM.XOF.Init B = _; rfl
  have h_batch :
      (chainedSqueeze 3 init_s (n + 1)).2
      = bitsToBytes (sponge.squeeze1 KECCAK_f (b - 256) (by decide) init_s
                       (8 * (3 * (n + 1)))).2 := by
    have := SHAKE128.squeeze_chain_eq_batch 3 init_s (n + 1)
    have hb := congrArg Prod.snd this
    simpa using hb
  rw [h_batch]
  rw [h_init_eq, SHAKE128.bitsToBytes_squeeze1_init_eq_shake128 B (3 * (n + 1))]
  /- Step 4: prefix-stability: shake128 B (3*(n+1)) and shake128 B M agree
     at byte index 3*n + k.val (since 3*n + k.val < 3*(n+1) ≤ M). -/
  show (shake128 B (3 * (n + 1)))[3 * n + k.val]'(by have := k.isLt; omega) = _
  exact SHAKE128.shake128_prefix_byte B (3 * (n + 1)) M hM (3 * n + k.val)
          (by have := k.isLt; omega)

/-! ## §2. Zero-round predicate and counting. -/

/-- A round `r` of `sampleNttPartialAux` is a **zero round** w.r.t. the
SHAKE128 byte stream of length `M` iff the 3 bytes it would consume
(`shake128 B M` at indices `[3·r, 3·r+3)`) are all zero. -/
private def isZeroRound (B : 𝔹 34) (M : Nat) (r : Nat) : Prop :=
  3 * r + 3 ≤ M ∧
    ∀ (h : 3 * r + 3 ≤ M),
      (shake128 B M)[3 * r]'(by omega) = (0 : Byte) ∧
      (shake128 B M)[3 * r + 1]'(by omega) = (0 : Byte) ∧
      (shake128 B M)[3 * r + 2]'(by omega) = (0 : Byte)

open scoped Classical in
/-- Number of zero rounds in `[0, n)`. -/
private noncomputable def countZeroRounds (B : 𝔹 34) (M : Nat) : Nat → Nat
  | 0 => 0
  | n + 1 =>
    countZeroRounds B M n + (if isZeroRound B M n then 1 else 0)

private theorem countZeroRounds_le (B : 𝔹 34) (M n : Nat) :
    countZeroRounds B M n ≤ n := by
  induction n with
  | zero => simp [countZeroRounds]
  | succ k ih =>
    simp only [countZeroRounds]
    split <;> omega

/-! ## §3. One-step zero-round lemma. -/

/-- If a one-round invocation of `sampleNttPartialAux` consumes three
zero bytes and we have not yet hit `j = 256`, the new accepted count
is at least `j + 1`. -/
private lemma sampleNttPartialAux_zero_one_step
    (ctx : SHA3.Incremental.sponge.state (SHA3.b - 256))
    (â : MLKEM.Polynomial) (j : Nat) (hj : j < 256)
    (hC0 : (MLKEM.XOF.Squeeze ctx 3).2[0]'(by simp) = (0 : Byte))
    (hC1 : (MLKEM.XOF.Squeeze ctx 3).2[1]'(by simp) = (0 : Byte))
    (hC2 : (MLKEM.XOF.Squeeze ctx 3).2[2]'(by simp) = (0 : Byte)) :
    j + 1 ≤ (sampleNttPartialAux ctx â j 1).2.2 := by
  show j + 1 ≤
    (sampleNttPartialAux ctx â j (0 + 1)).2.2
  rw [sampleNttPartialAux_succ]
  rw [if_pos hj]
  /- Reduce the cleartext: with C[0]=C[1]=C[2]=0, d₁=d₂=0<q, both
     get accepted (up to the `j₁ < 256` guard on d₂). -/
  have hq : (0 : Nat) < MLKEM.q := by decide
  /- The two `let` bindings reduce; the final tail call returns its
     middle argument j₂ as the .2.2 component. -/
  have h_d1 : (MLKEM.XOF.Squeeze ctx 3).2[0].val +
              256 * ((MLKEM.XOF.Squeeze ctx 3).2[1].val % 16) = 0 := by
    rw [show (MLKEM.XOF.Squeeze ctx 3).2[0].val =
            (0 : Byte).val from by rw [hC0]]
    rw [show (MLKEM.XOF.Squeeze ctx 3).2[1].val =
            (0 : Byte).val from by rw [hC1]]
    decide
  have h_d2 : (MLKEM.XOF.Squeeze ctx 3).2[1].val / 16 +
              16 * (MLKEM.XOF.Squeeze ctx 3).2[2].val = 0 := by
    rw [show (MLKEM.XOF.Squeeze ctx 3).2[1].val =
            (0 : Byte).val from by rw [hC1]]
    rw [show (MLKEM.XOF.Squeeze ctx 3).2[2].val =
            (0 : Byte).val from by rw [hC2]]
    decide
  /- Unfold the let-bindings using h_d1, h_d2. -/
  simp only [h_d1, h_d2, hq, if_true, sampleNttPartialAux]
  /- After unfolding, .2.2 is `if (0 < q ∧ j + 1 < 256) then j + 2 else j + 1`. -/
  split <;> omega

/-! ## §4. Counting invariant: zero rounds force `j` to grow. -/

/-- **Counting invariant.** After `n` rounds of `sampleNttPartialAux`
starting from a fresh state, the number of accepted coefficients `j`
is at least `min 256 (countZeroRounds B M n)`, provided `M` covers
the bytes consumed (`3·n ≤ M`). -/
private theorem sampleNttPartialAux_count_lb (B : 𝔹 34) (M : Nat) (n : Nat)
    (hM : 3 * n ≤ M) :
    min 256 (countZeroRounds B M n) ≤
      (sampleNttPartialAux (MLKEM.XOF.Absorb MLKEM.XOF.Init B)
          MLKEM.Polynomial.zero 0 n).2.2 := by
  set init_s := MLKEM.XOF.Absorb MLKEM.XOF.Init B with h_init_s
  induction n with
  | zero =>
    simp [countZeroRounds, sampleNttPartialAux]
  | succ k ih =>
    have hM_k  : 3 * k ≤ M := by omega
    have hM_kk : 3 * (k + 1) ≤ M := by omega
    have ih'   := ih hM_k
    set s := sampleNttPartialAux init_s MLKEM.Polynomial.zero 0 k with hs
    have h_split :
        sampleNttPartialAux init_s MLKEM.Polynomial.zero 0 (k + 1) =
          sampleNttPartialAux s.1 s.2.1 s.2.2 1 := by
      have := sampleNttPartialAux_add init_s MLKEM.Polynomial.zero 0 k 1
      exact this
    have h_s_le : s.2.2 ≤ 256 :=
      sampleNttPartialAux_filled_le _ _ _ _ (by simp)
    by_cases hz : isZeroRound B M k
    · /- Zero round: count goes up by 1. -/
      have h_count_succ :
          countZeroRounds B M (k + 1) = countZeroRounds B M k + 1 := by
        simp [countZeroRounds, hz]
      rw [h_count_succ]
      by_cases h_full : s.2.2 = 256
      · /- Already full: stable. -/
        rw [h_split, h_full, sampleNttPartialAux_stable_at_256]
        exact Nat.min_le_left 256 _
      · have h_lt : s.2.2 < 256 := lt_of_le_of_ne h_s_le h_full
        /- Translate `isZeroRound` to byte equalities on `XOF.Squeeze s.1 3`. -/
        obtain ⟨hM_zr, h_eq⟩ := hz
        obtain ⟨h0, h1, h2⟩ := h_eq hM_zr
        have h_brg_get : ∀ (idx : Fin 3),
            (MLKEM.XOF.Squeeze s.1 3).2.get idx = (0 : Byte) := by
          intro idx
          have h_round := sampleNttPartialAux_round_bytes_eq_shake128 B k M hM_kk idx
                          (by simpa [hs] using h_lt)
          have h_s1 : s.1 = (sampleNttPartialAux init_s MLKEM.Polynomial.zero 0 k).1 := rfl
          rw [h_s1, h_round]
          fin_cases idx
          · exact h0
          · exact h1
          · exact h2
        have hC0 : (MLKEM.XOF.Squeeze s.1 3).2[0]'(by simp) = (0 : Byte) := by
          have := h_brg_get ⟨0, by decide⟩
          show (MLKEM.XOF.Squeeze s.1 3).2.get ⟨0, _⟩ = _
          exact this
        have hC1 : (MLKEM.XOF.Squeeze s.1 3).2[1]'(by simp) = (0 : Byte) := by
          have := h_brg_get ⟨1, by decide⟩
          show (MLKEM.XOF.Squeeze s.1 3).2.get ⟨1, _⟩ = _
          exact this
        have hC2 : (MLKEM.XOF.Squeeze s.1 3).2[2]'(by simp) = (0 : Byte) := by
          have := h_brg_get ⟨2, by decide⟩
          show (MLKEM.XOF.Squeeze s.1 3).2.get ⟨2, _⟩ = _
          exact this
        have h_step :=
          sampleNttPartialAux_zero_one_step s.1 s.2.1 s.2.2 h_lt hC0 hC1 hC2
        rw [h_split]
        omega
    · /- Non-zero round: count unchanged; j is monotone. -/
      have h_count_eq :
          countZeroRounds B M (k + 1) = countZeroRounds B M k := by
        simp [countZeroRounds, hz]
      rw [h_count_eq]
      have h_mono : s.2.2 ≤
          (sampleNttPartialAux init_s MLKEM.Polynomial.zero 0 (k + 1)).2.2 := by
        rw [h_split]
        exact sampleNttPartialAux_j_le _ _ _ _
      omega

/-! ## §5. Lower bound on `countZeroRounds` from `zero_bytes_per_cycle`. -/

/-- `countZeroRounds B M N` equals the sum over `[0, N)` of the
0/1 indicator of `isZeroRound B M ·`. -/
private lemma countZeroRounds_eq_sum (B : 𝔹 34) (M N : Nat) :
    countZeroRounds B M N =
      ∑ r ∈ Finset.range N, (if isZeroRound B M r then 1 else 0) := by
  induction N with
  | zero => simp [countZeroRounds]
  | succ k ih =>
    simp only [countZeroRounds, Finset.sum_range_succ, ih]

/-- A set of zero-round indices in `[0, N)` lower-bounds the count. -/
private lemma countZeroRounds_ge_card (B : 𝔹 34) (M N : Nat) (S : Finset Nat)
    (hS : ∀ r ∈ S, r < N ∧ isZeroRound B M r) :
    S.card ≤ countZeroRounds B M N := by
  rw [countZeroRounds_eq_sum]
  have hS_sub : S ⊆ (Finset.range N).filter (isZeroRound B M) := by
    intro r hr
    rcases hS r hr with ⟨hN, hz⟩
    simp [hN, hz]
  calc S.card
      = ∑ _r ∈ S, (1 : Nat) := by simp
    _ ≤ ∑ _r ∈ (Finset.range N).filter (isZeroRound B M), (1 : Nat) :=
        Finset.sum_le_sum_of_subset hS_sub
    _ = ∑ r ∈ Finset.range N, (if isZeroRound B M r then 1 else 0) := by
        rw [Finset.sum_filter]

/-- For an `m`-period, the i-th zero-round-index across cycles `c ∈ {1,…}`
of width 43 zero rounds each, is `56·(c·m − 1) + 12 + t`, where
`i = 43·(c−1) + t` (`0 ≤ t < 43`). -/
private def cycleZeroIdx (m i : Nat) : Nat :=
  56 * ((i / 43 + 1) * m - 1) + 12 + (i % 43)

private lemma cycleZeroIdx_strict_mono (m : Nat) (hm : 1 ≤ m) :
    StrictMono (cycleZeroIdx m) := by
  intro i j hij
  unfold cycleZeroIdx
  set A := (i / 43 + 1) * m with hA_def
  set B := (j / 43 + 1) * m with hB_def
  have hci_le_cj : i / 43 ≤ j / 43 := Nat.div_le_div_right (by omega : i ≤ j)
  have hA_pos : 1 ≤ A := Nat.one_le_iff_ne_zero.mpr
    (Nat.mul_ne_zero (by omega) (by omega))
  have hB_pos : 1 ≤ B := Nat.one_le_iff_ne_zero.mpr
    (Nat.mul_ne_zero (by omega) (by omega))
  have hi_mod : i % 43 < 43 := Nat.mod_lt _ (by decide)
  have hj_mod : j % 43 < 43 := Nat.mod_lt _ (by decide)
  by_cases hc_eq : i / 43 = j / 43
  · /- Same cycle: A = B and ti < tj. -/
    have hAB : A = B := by simp [hA_def, hB_def, hc_eq]
    have : i % 43 < j % 43 := by omega
    omega
  · /- Different cycle: j/43 ≥ i/43 + 1, so B ≥ A + m. -/
    have hlt : i / 43 + 1 ≤ j / 43 := by omega
    have hmul : A + m ≤ B := by
      simp only [hA_def, hB_def]
      have h1 := Nat.mul_le_mul_right m hlt
      have h2 : (i / 43 + 1) * m + m = (i / 43 + 1 + 1) * m := by ring
      have h3 : (i / 43 + 1 + 1) * m ≤ (j / 43 + 1) * m := by
        apply Nat.mul_le_mul_right; omega
      omega
    /- Now omega should close: A ≥ 1, B ≥ 1, A + m ≤ B, m ≥ 1 ⇒
       56*(B-1) ≥ 56*(A + m - 1) = 56*(A-1) + 56*m ≥ 56*(A-1) + 56,
       so 56*(B-1) + 12 + j%43 > 56*(A-1) + 12 + i%43. -/
    omega

private lemma cycleZeroIdx_inj_on_range (m : Nat) (hm : 1 ≤ m) (K : Nat) :
    Set.InjOn (cycleZeroIdx m) (Finset.range K : Set Nat) := by
  intro i _ j _ hij
  exact (cycleZeroIdx_strict_mono m hm).injective hij

private lemma cycleZeroIdx_bound (m : Nat) (hm : 1 ≤ m) (C : Nat) (i : Nat)
    (hi : i < 43 * C) :
    cycleZeroIdx m i < 56 * (C * m) := by
  unfold cycleZeroIdx
  have hi_div_lt : i / 43 < C := Nat.div_lt_of_lt_mul hi
  have hc_le : i / 43 + 1 ≤ C := by omega
  have hi_mod_lt : i % 43 < 43 := Nat.mod_lt _ (by decide)
  have hcm_le : (i / 43 + 1) * m ≤ C * m := Nat.mul_le_mul_right m hc_le
  have hcm_pos : 1 ≤ (i / 43 + 1) * m := Nat.one_le_iff_ne_zero.mpr
    (Nat.mul_ne_zero (by omega) (by omega))
  have hCm_pos : 1 ≤ C * m := le_trans hcm_pos hcm_le
  /- Now: 56*((i/43+1)*m - 1) + 12 + (i%43) ≤ 56*((i/43+1)*m) - 56 + 12 + 42
                                            < 56*C*m. -/
  set A := (i / 43 + 1) * m with hA_def
  set Cm := C * m with hCm_def
  /- A ≤ Cm and A ≥ 1 and Cm ≥ 1 (so 56*Cm ≥ 56). -/
  have h56_le : 56 ≤ 56 * Cm := by
    have : 56 * 1 ≤ 56 * Cm := Nat.mul_le_mul_left 56 hCm_pos
    linarith
  have hA_le : 56 * A ≤ 56 * Cm := Nat.mul_le_mul_left 56 hcm_le
  omega

private lemma cycleZeroIdx_isZero (B : 𝔹 34) (m : Nat) (hm : 1 ≤ m)
    (hcycle : ∀ c ≥ 1, ∀ outBytes : Nat,
                168 * (c * m) ≤ outBytes →
                ∀ k, 168 * (c * m - 1) + 36 ≤ k → k < 168 * (c * m - 1) + 165 →
                  ∀ (h : k < outBytes), (shake128 B outBytes)[k]'h = 0)
    (C : Nat) (i : Nat) (hi : i < 43 * C) :
    isZeroRound B (168 * (C * m)) (cycleZeroIdx m i) := by
  unfold isZeroRound
  unfold cycleZeroIdx
  set c := i / 43 + 1
  set t := i % 43
  have hi_div_lt : i / 43 < C := Nat.div_lt_of_lt_mul hi
  have hc_pos  : 1 ≤ c := by simp [c]
  have hc_le_C : c ≤ C := by simp [c]; omega
  have ht_lt   : t < 43 := Nat.mod_lt _ (by decide)
  have hcm_le  : c * m ≤ C * m := Nat.mul_le_mul_right m hc_le_C
  have hcm_pos : 1 ≤ c * m := Nat.one_le_iff_ne_zero.mpr
    (Nat.mul_ne_zero (by omega) (by omega))
  /- Compute the byte indices we need to be zero: 3r, 3r+1, 3r+2
     for r := 56*(c*m - 1) + 12 + t.  Then 3r = 168*(c*m-1) + 36 + 3t,
     so they lie in [168*(c*m - 1) + 36, 168*(c*m - 1) + 36 + 3*43). -/
  have hb_pos : 3 * (56 * (c * m - 1) + 12 + t) + 3 ≤ 168 * (C * m) := by
    have h_expand : 3 * (56 * (c * m - 1) + 12 + t) + 3
                  = 168 * (c * m - 1) + 36 + 3 * t + 3 := by ring
    have h_cm_step : 168 * (c * m - 1) + 168 = 168 * (c * m) := by
      rw [Nat.mul_sub_one]; omega
    have h_cm_bnd : 168 * (c * m) ≤ 168 * (C * m) :=
      Nat.mul_le_mul_left 168 hcm_le
    rw [h_expand]
    omega
  refine ⟨hb_pos, ?_⟩
  intro _
  /- Three byte equalities. -/
  refine ⟨?_, ?_, ?_⟩ <;>
    (apply hcycle c hc_pos (168 * (C * m)) (Nat.mul_le_mul_left 168 hcm_le)
     <;> (try omega))

/-- Picking `C = 6` (so 43·6 = 258 ≥ 256) gives a count of at least
`256` zero rounds within the first `56·6·m` rounds (`168·6·m` bytes). -/
private theorem countZeroRounds_ge_256 (B : 𝔹 34) :
    ∃ m N M, 1 ≤ m ∧ 3 * N ≤ M ∧ 256 ≤ countZeroRounds B M N := by
  obtain ⟨m, hm, hcycle⟩ := SHAKE128.zero_bytes_per_cycle B
  let C : Nat := 6
  let N : Nat := 56 * (C * m)
  let M : Nat := 168 * (C * m)
  refine ⟨m, N, M, hm, ?_, ?_⟩
  · simp only [N, M]; ring_nf; linarith
  /- Build the Finset of 258 = 43·6 zero-round indices. -/
  classical
  set S : Finset Nat := (Finset.range (43 * C)).image (cycleZeroIdx m) with hS_def
  have hinj : Set.InjOn (cycleZeroIdx m) ↑(Finset.range (43 * C)) :=
    cycleZeroIdx_inj_on_range m hm (43 * C)
  have hcard_S : S.card = 43 * C := by
    rw [hS_def, Finset.card_image_of_injOn hinj, Finset.card_range]
  have hS_props : ∀ r ∈ S, r < N ∧ isZeroRound B M r := by
    intro r hr
    rcases Finset.mem_image.mp hr with ⟨i, hi_mem, rfl⟩
    have hi : i < 43 * C := Finset.mem_range.mp hi_mem
    refine ⟨cycleZeroIdx_bound m hm C i hi,
            cycleZeroIdx_isZero B m hm hcycle C i hi⟩
  have h_ge := countZeroRounds_ge_card B M N S hS_props
  have h_card_val : S.card = 258 := by rw [hcard_S]; simp [C]
  omega

/-! ## §6. Final theorem: `sampleNttPartialAux` terminates. -/

/-- **Termination of MLKEM's rejection-sampling helper.**

For any 34-byte seed `B`, there exists a round count `n` such that
`sampleNttPartialAux` reaches the saturated state `j = 256`. -/
theorem sampleNttPartialAux_terminates (B : 𝔹 34) :
    ∃ n, (sampleNttPartialAux (MLKEM.XOF.Absorb MLKEM.XOF.Init B)
            MLKEM.Polynomial.zero 0 n).2.2 = 256 := by
  obtain ⟨_m, N, M, _, hM, h_count⟩ := countZeroRounds_ge_256 B
  refine ⟨N, ?_⟩
  /- Lower bound on j via `_count_lb`: j ≥ min 256 (count) = 256. -/
  have h_lb := sampleNttPartialAux_count_lb B M N hM
  have h_le := sampleNttPartialAux_filled_le
    (MLKEM.XOF.Absorb MLKEM.XOF.Init B) MLKEM.Polynomial.zero 0 N (by simp)
  have h_min : min 256 (countZeroRounds B M N) = 256 :=
    Nat.min_eq_left h_count
  rw [h_min] at h_lb
  omega

end Symcrust.Properties.MLKEM.Helpers
