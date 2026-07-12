/-
  # Bridges/NttLoops.lean — Cooley–Tukey / Gentleman–Sande loop helpers for ML-KEM NTT.

  Tracks divergence categories **E1** (forward NTT, Algorithm 9) and
  **E2** (inverse NTT, Algorithm 10) for ML-KEM (FIPS 203).

  ## Why this file exists

  The Aeneas-extracted `mlkem.ntt.poly_element_ntt` is implemented as
  seven sequential calls to `poly_element_ntt_layer` with `(k, len)` =
  `(1, 128), (2, 64), …, (64, 2)`. Each layer is itself a
  doubly-nested `IteratorStepBy` + range loop nest with monad-threaded
  twiddle-counter state `k`.

  The spec `MLKEM.NTT` (Algorithm 9, lines 405–416 of `Spec.lean`)
  is a triple-nested for-loop

      for h0: len in [128 : >1 : /= 2] do
        for h1: start in [0 : 256 : 2*len] do
          let zeta := ζ ^ bitRev 7 i
          i := i + 1
          for h: j in [start : start+len] do
            let t := zeta * f̂[j + len]
            f̂ := f̂.set (j + len) (f̂[j] - t)
            f̂ := f̂.set j         (f̂[j] + t)

  with twiddle counter `i ∈ [1, 128)`. The two loops compute the same
  butterfly, but Lean cannot see the equivalence directly (different
  syntactic forms, different state-threading idioms).

  ## Helper API design (mirrors MLDSA, scaled to ML-KEM)

  ML-KEM-specific differences from MLDSA:
  * 7 NTT layers (not 8), corresponding to `len ∈ {128, 64, 32, 16, 8, 4, 2}`.
  * Twiddle table size 128 (not 256).
  * Post-INTT fixup factor `f := 3303 ≡ 128⁻¹` (not `256⁻¹`).
  * Domain: `Polynomial = Vector Zq 256` (same coefficient count, but
    the NTT acts on 128 *pairs* via the base-case multiply).

  Per the design critique applied to MLDSA's version, the helpers below
  carry **explicit index preconditions** (not no-op fallbacks) and use
  **direct recursion** (not `for h: j in [..]`) so peel-one unfolds via
  `.eq_def`.

  ## Structure

      `nttButterflyAt z p j len <bounds>`        — single CT butterfly at (j, j+len)
      `nttButterflies z p len j_lo j_hi <bound>` — inner loop over j ∈ [j_lo, j_hi)
      `nttMidStep len start m p`                  — one mid-iter: pick twiddle, run inner
      `nttMidLayer len <h_len> start m p`         — middle loop over start
      `nttOuter len m p`                          — outer loop over len

  Inverse-NTT counterparts (Gentleman–Sande):
      `inttButterflyAt`, `inttButterflies`, `inttMidStep`,
      `inttMidLayer`, `inttOuter`, `inttFixup`.

  Note: `tbd_toPoly_intt_butterfly_step` retains its `tbd_` prefix
  for backward name-compatibility; its proof is closed.
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.MontArith
import Symcrust.Properties.MLKEM.Ntt.NttSpecAux

open Aeneas Aeneas.Std
open Spec
open Spec.MLKEM
open Symcrust
open Symcrust.Properties.MLKEM.Ntt (ntt nttLayer nttLayerInner invNtt invNttLayer invNttLayerInner
  nttBangButterfly invNttBangButterfly nttLayerInner_unfold nttLayer_unfold
  invNttLayerInner_unfold invNttLayer_unfold)

namespace Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 1000000

/-! ## E1 — Forward NTT (Cooley–Tukey) helpers -/

/-- One Cooley–Tukey butterfly at indices `(j, j+len)` with twiddle `z`.

  `p[j]      ← p[j] + z · p[j+len]`
  `p[j+len]  ← p[j] - z · p[j+len]`

The two updates must be sequenced: capture the old `p[j]` and
`z · p[j+len]` in `let`-bindings before mutating, otherwise the second
update reads the already-mutated `p[j+len]`.

Explicit preconditions (no no-op fallback) — if `len = 0` the spec/impl
do not execute this code path. -/
def nttButterflyAt (z : Zq) (p : MLKEM.Polynomial) (j len : Nat)
    (hj : j < 256) (h_jlen : j + len < 256) : MLKEM.Polynomial :=
  let t : Zq := z * p[j + len]
  let p' := p.set (j + len) (p[j] - t)
  p'.set j (p[j] + t) (by simpa using hj)

/-- Inner butterfly loop: applies `nttButterflyAt z _ j len` for
`j ∈ [j_lo, j_hi)`. Mirrors `mlkem.ntt.poly_element_ntt_layer_generic_loop0_loop0`.

Precondition `h_hi : j_hi + len ≤ 256` ensures every `j + len < 256`
inside the loop.

Defined as direct recursion (not `for h: j in [..]`) so that peel-one
unfolds via `.eq_def`. Termination: `j_hi - j_lo` decreasing. -/
def nttButterflies (z : Zq) (p : MLKEM.Polynomial)
    (len j_lo j_hi : Nat) (h_hi : j_hi + len ≤ 256) : MLKEM.Polynomial :=
  if h : j_lo < j_hi then
    let p' := nttButterflyAt z p j_lo len (by scalar_tac) (by scalar_tac)
    nttButterflies z p' len (j_lo + 1) j_hi h_hi
  else p
termination_by j_hi - j_lo
decreasing_by scalar_tac

/-- Middle layer step: use twiddle `ζ ^ bitRev_7 m`, run the inner
butterfly loop on `[start, start+len)`. Returns the updated `(p, m+1)`.

Precondition `h : start + 2·len ≤ 256` is what the inner butterflies
need: each butterfly accesses `j + len` for `j < start + len`, so the
maximal access index is `start + 2·len - 1 < 256`.

Note: `m` is bounded by `< 128` in the actual NTT (only 127 mid-steps
across all 7 layers); we do not encode that bound here, letting `ζ^0 = 1`
provide a harmless fallback.

The `m → m + 1` post-increment is symmetric with `inttMidStep`'s
`m → m - 1` decrement: both step the counter after the butterfly so
the wrapper postconditions can use the impl's `k` directly. -/
def nttMidStep (len start m : Nat) (h : start + 2 * len ≤ 256)
    (p : MLKEM.Polynomial) : MLKEM.Polynomial × Nat :=
  let z : Zq := MLKEM.ζ ^ _root_.bitRev 7 m
  let p' := nttButterflies z p len start (start + len) (by scalar_tac)
  (p', m + 1)

/-- Middle loop: iterate `start` over `{start_init, start_init + 2·len,
…}` while `start + 2·len ≤ 256`. Threads `m` through every step.

The `h_len : 0 < len` precondition ensures recursion terminates by
`256 - start` (each iteration adds `2·len ≥ 2`).

Mirrors `mlkem.ntt.poly_element_ntt_layer_generic_loop0`. -/
def nttMidLayer (len : Nat) (h_len : 0 < len) (start m : Nat)
    (p : MLKEM.Polynomial) : MLKEM.Polynomial × Nat :=
  if h : start + 2 * len ≤ 256 then
    let (p', m') := nttMidStep len start m h p
    nttMidLayer len h_len (start + 2 * len) m' p'
  else (p, m)
termination_by 256 - start
decreasing_by scalar_tac

/-- Outer loop: iterate `len ∈ {128, 64, 32, 16, 8, 4, 2}` (halving) while
`len > 1`. Threads `m` through every middle-layer call.

Initial call: `nttOuter 128 1 p`. After 7 iterations, `m = 128` and
`len = 1`, terminating. -/
def nttOuter (len : Nat) (m : Nat) (p : MLKEM.Polynomial) :
    MLKEM.Polynomial × Nat :=
  if h : 1 < len then
    let (p', m') := nttMidLayer len (by scalar_tac) 0 m p
    nttOuter (len / 2) m' p'
  else (p, m)
termination_by len
decreasing_by scalar_tac

/-! ## E1 — Bridge to spec via NttSpecAux

The pure-spec layer in `Ntt/NttSpecAux.lean` provides:
* `ntt p = MLKEM.NTT p`   (closed; `ntt_eq`)
* `invNtt p = MLKEM.NTTInv p`   (closed; `invNtt_eq_ntt_inv`)

`ntt` / `nttLayer` / `nttLayerInner` form a recursive presentation of
the NTT closely matching the spec's `for`-loop unfolding. Our
`nttOuter` / `nttMidLayer` / `nttButterflies` / `nttButterflyAt` form a
parallel impl-aligned presentation. The bridge below proves the two
presentations equal, then composes with `ntt_eq` to discharge
`nttOuter_eq_NTT` and `NTT_unfold_layers`.
-/

/-- Per-butterfly bridge: our impl-form butterfly = older bang form. -/
private theorem nttButterflyAt_eq_nttBangButterfly
    (z : Zq) (p : MLKEM.Polynomial) (j len : Nat)
    (hj : j < 256) (h_jlen : j + len < 256) (h_len_pos : 0 < len) :
    nttButterflyAt z p j len hj h_jlen
      = Symcrust.Properties.MLKEM.Ntt.nttBangButterfly z p j len := by
  unfold nttButterflyAt Symcrust.Properties.MLKEM.Ntt.nttBangButterfly
  have hne : j + len ≠ j := by omega
  simp only [Vector.set_eq_set!, Vector.Inhabited_getElem_eq_getElem!]
  rw [Symcrust.Properties.MLKEM.Ntt.Vector.set!_comm _ j (j+len) _ _ (fun h => hne h.symm)]
  ring_nf

/-- Inner-loop bridge: our impl-form butterfly loop equals the spec's
recursive `nttLayerInner`. The two recurse in lock-step over `j ∈ [k, len)`
applying the same butterfly to `(start+j, start+j+len)`. -/
private theorem nttButterflies_eq_nttLayerInner
    (i : Nat) (p : MLKEM.Polynomial) (len start k : Nat)
    (h_k : k ≤ len) (h_bound : start + 2 * len ≤ 256) (h_len : 0 < len) :
    nttButterflies (MLKEM.ζ ^ _root_.bitRev 7 i) p len
        (start + k) (start + len) (by scalar_tac)
      = nttLayerInner p i len start k := by
  induction hn : len - k generalizing k p with
  | zero =>
    have hkl : k = len := by omega
    subst hkl
    rw [nttButterflies, nttLayerInner_unfold]
    simp
  | succ n ih =>
    have hlt : k < len := by omega
    rw [nttButterflies, nttLayerInner_unfold]
    have h_jlt : start + k < start + len := by scalar_tac
    simp only [h_jlt, hlt, ↓reduceDIte, ↓reduceIte]
    have h_jb : start + k < 256 := by scalar_tac
    have h_jlenb : start + k + len < 256 := by scalar_tac
    rw [nttButterflyAt_eq_nttBangButterfly _ _ _ _ h_jb h_jlenb h_len]
    rw [show start + k + 1 = start + (k + 1) from by ring]
    have hn' : len - (k + 1) = n := by omega
    have := ih (nttBangButterfly (MLKEM.ζ ^ _root_.bitRev 7 i) p (start + k) len)
        (k + 1) (by omega) hn'
    rw [this]
    unfold nttBangButterfly
    rfl

/-- Middle-layer bridge (auxiliary): induct directly on the number of
remaining iterations, given as the integer factor `k` such that
`k * (2*len) = 256 - start`. Produces both `.1` (polynomial = `nttLayer`)
and `.2` (m-counter increment by `k`). -/
private theorem nttMidLayer_eq_nttLayer_aux
    (len : Nat) (h_len : 0 < len) (k : Nat)
    (start m : Nat) (h_eq : k * (2 * len) = 256 - start) (h_start : start ≤ 256)
    (p : MLKEM.Polynomial) :
    nttMidLayer len h_len start m p = (nttLayer p m len start h_len, m + k) := by
  induction k generalizing start m p with
  | zero =>
    have h_diff_zero : start = 256 := by omega
    subst h_diff_zero
    rw [nttMidLayer, nttLayer_unfold]
    have h1 : ¬ ((256 : Nat) + 2 * len ≤ 256) := by omega
    have h2 : ¬ ((256 : Nat) < 256) := by omega
    simp_all
  | succ k ih =>
    have h_start_plus : start + 2 * len ≤ 256 := by
      have h1 : 2 * len ≤ (k + 1) * (2 * len) := by
        have : 1 * (2 * len) ≤ (k + 1) * (2 * len) :=
          Nat.mul_le_mul_right _ (by omega)
        omega
      omega
    have h_lt : start < 256 := by omega
    rw [nttMidLayer]
    simp only [h_start_plus, ↓reduceDIte]
    unfold nttMidStep
    rw [nttLayer_unfold]
    simp only [h_lt, ↓reduceIte]
    have h_eq_next : k * (2 * len) = 256 - (start + 2 * len) := by
      have hexp : (k + 1) * (2 * len) = k * (2 * len) + 2 * len := by ring
      omega
    have h_bridge := nttButterflies_eq_nttLayerInner m p len start 0
        (by omega) h_start_plus h_len
    simp only [Nat.add_zero] at h_bridge
    rw [h_bridge]
    have h_ih := ih (start + 2 * len) (m + 1) h_eq_next h_start_plus
        (nttLayerInner p m len start 0)
    show nttMidLayer len h_len (start + 2 * len) (m + 1) _ =
        (nttLayer _ (m + 1) len (start + 2 * len) _, m + (k + 1))
    rw [h_ih]
    fcongr 1
    omega

/-- Middle-layer bridge: our impl-form middle loop equals the spec's
recursive `nttLayer`. Both use `m` directly as the twiddle index (with
`nttMidStep` post-incrementing). -/
private theorem nttMidLayer_eq_nttLayer
    (len : Nat) (h_len : 0 < len) (m start : Nat) (p : MLKEM.Polynomial)
    (h_div_start : 2 * len ∣ start) (h_div_256 : 2 * len ∣ 256)
    (h_start : start ≤ 256) :
    nttMidLayer len h_len start m p =
      (nttLayer p m len start h_len, m + (256 - start) / (2 * len)) := by
  have h_div_diff : 2 * len ∣ (256 - start) := by
    obtain ⟨a, ha⟩ := h_div_256
    obtain ⟨b, hb⟩ := h_div_start
    have hba : b ≤ a := by
      rcases Nat.lt_or_ge a b with h | h
      · exfalso
        have hab : a + 1 ≤ b := h
        have hmul : 2 * len * (a + 1) ≤ 2 * len * b := Nat.mul_le_mul_left _ hab
        have : 2 * len * (a + 1) = 2 * len * a + 2 * len := by ring
        omega
      · exact h
    refine ⟨a - b, ?_⟩
    rw [Nat.mul_sub]; omega
  obtain ⟨k, hk⟩ := h_div_diff
  have h_k_eq : k * (2 * len) = 256 - start := by rw [Nat.mul_comm]; exact hk.symm
  have h_k_val : k = (256 - start) / (2 * len) := by
    have h_2len_pos : 0 < 2 * len := by omega
    have := Nat.mul_div_cancel k h_2len_pos
    rw [← h_k_eq] at *; omega
  rw [h_k_val.symm]
  exact nttMidLayer_eq_nttLayer_aux len h_len k start m h_k_eq h_start p

/-- **E1.peel** — peel-one for the outer loop.

Convenience lemma extracted because every induction over the outer
layer uses it: split `nttOuter 128 m p` into one layer (`len = 128`)
followed by the remaining six (`len ∈ {64, 32, …, 2}`). -/
theorem nttOuter_peel (m : Nat) (p : MLKEM.Polynomial) :
    nttOuter 128 m p =
      let (p', m') := nttMidLayer 128 (by decide) 0 m p
      nttOuter 64 m' p' := by
  rw [nttOuter]
  simp

/-- **E1.unfold-spec** — spec NTT as a sequence of 7 `nttMidLayer` calls.

This is the converse direction of `nttOuter_eq_NTT`'s induction
hypothesis, useful for the impl-side proof where each layer is a
separate `poly_element_ntt_layer` call (constants `(1,128), (2,64), …`).

Informal proof: unfold `MLKEM.NTT`'s outer `for h0: len in [...]`
seven times. -/
theorem NTT_unfold_layers (p : MLKEM.Polynomial) :
    MLKEM.NTT p =
      let p1 := (nttMidLayer 128 (by decide) 0 1  p).1
      let p2 := (nttMidLayer 64  (by decide) 0 2  p1).1
      let p3 := (nttMidLayer 32  (by decide) 0 4  p2).1
      let p4 := (nttMidLayer 16  (by decide) 0 8  p3).1
      let p5 := (nttMidLayer 8   (by decide) 0 16 p4).1
      let p6 := (nttMidLayer 4   (by decide) 0 32 p5).1
      let p7 := (nttMidLayer 2   (by decide) 0 64 p6).1
      p7 := by
  rw [show MLKEM.NTT p = Symcrust.Properties.MLKEM.Ntt.ntt p from
        (Symcrust.Properties.MLKEM.Ntt.ntt_eq p).symm]
  unfold Symcrust.Properties.MLKEM.Ntt.ntt
  simp only
    [nttMidLayer_eq_nttLayer 128 (by decide) 1 0 _ (by decide) (by decide) (by decide),
     nttMidLayer_eq_nttLayer 64 (by decide) 2 0 _ (by decide) (by decide) (by decide),
     nttMidLayer_eq_nttLayer 32 (by decide) 4 0 _ (by decide) (by decide) (by decide),
     nttMidLayer_eq_nttLayer 16 (by decide) 8 0 _ (by decide) (by decide) (by decide),
     nttMidLayer_eq_nttLayer 8 (by decide) 16 0 _ (by decide) (by decide) (by decide),
     nttMidLayer_eq_nttLayer 4 (by decide) 32 0 _ (by decide) (by decide) (by decide),
     nttMidLayer_eq_nttLayer 2 (by decide) 64 0 _ (by decide) (by decide) (by decide)]

/-! ## E2 — Inverse NTT (Gentleman–Sande) helpers -/

/-- One Gentleman–Sande butterfly at indices `(j, j+len)` with twiddle `z`.

  `t := p[j]`
  `p[j]     ← t + p[j+len]`
  `p[j+len] ← z · (p[j+len] - t)`

The ordering matters: the new `p[j]` is the *sum* (no twiddle), and the
new `p[j+len]` uses the *old* `p[j]` (captured in `t`). -/
def inttButterflyAt (z : Zq) (p : MLKEM.Polynomial) (j len : Nat)
    (hj : j < 256) (h_jlen : j + len < 256) : MLKEM.Polynomial :=
  let t : Zq := p[j]
  let p' := p.set j (t + p[j + len])
  p'.set (j + len) (z * (p[j + len] - t))

/-- INTT inner butterfly loop, mirroring `nttButterflies` but with
Gentleman–Sande. -/
def inttButterflies (z : Zq) (p : MLKEM.Polynomial)
    (len j_lo j_hi : Nat) (h_hi : j_hi + len ≤ 256) : MLKEM.Polynomial :=
  if h : j_lo < j_hi then
    let p' := inttButterflyAt z p j_lo len (by scalar_tac) (by scalar_tac)
    inttButterflies z p' len (j_lo + 1) j_hi h_hi
  else p
termination_by j_hi - j_lo
decreasing_by scalar_tac

/-- INTT mid-step: decrement twiddle counter `m`, fetch `ζ ^ bitRev_7 m`,
run inner butterflies. -/
def inttMidStep (len start m : Nat) (h : start + 2 * len ≤ 256)
    (p : MLKEM.Polynomial) : MLKEM.Polynomial × Nat :=
  let z : Zq := MLKEM.ζ ^ _root_.bitRev 7 m
  let p' := inttButterflies z p len start (start + len) (by scalar_tac)
  let m' := m - 1
  (p', m')

/-- INTT middle loop. -/
def inttMidLayer (len : Nat) (h_len : 0 < len) (start m : Nat)
    (p : MLKEM.Polynomial) : MLKEM.Polynomial × Nat :=
  if h : start + 2 * len ≤ 256 then
    let (p', m') := inttMidStep len start m h p
    inttMidLayer len h_len (start + 2 * len) m' p'
  else (p, m)
termination_by 256 - start
decreasing_by scalar_tac

/-- INTT outer loop: iterate `len ∈ {2, 4, 8, 16, 32, 64, 128}` (doubling).

Termination is by `128 - len`; precondition `h_pos : 0 < len` keeps the
doubling step monotone. The recursion stops when `len ≥ 128`. -/
def inttOuter (len : Nat) (h_pos : 0 < len) (m : Nat) (p : MLKEM.Polynomial) :
    MLKEM.Polynomial × Nat :=
  if h : len ≤ 128 then
    let h_2len : 0 < 2 * len := by scalar_tac
    let (p', m') := inttMidLayer len h_pos 0 m p
    if h2 : len < 128 then
      inttOuter (2 * len) h_2len m' p'
    else
      (p', m')
  else (p, m)
termination_by 128 - len
decreasing_by scalar_tac

/-- Post-INTT fixup: multiply every coefficient by `f := 3303 ≡ 128⁻¹ (mod q)`.

Spec `MLKEM.NTTInv` line 433 of `Spec.lean`:
    `f := f * (3303 : Zq)`. -/
def inttFixup (p : MLKEM.Polynomial) : MLKEM.Polynomial :=
  p.map ((3303 : Zq) * ·)

/-! ## E2.iso — Inverse NTT iso theorem -/

/-- Per-butterfly bridge (INTT side): our impl-form GS butterfly = older bang form. -/
private theorem inttButterflyAt_eq_invNttBangButterfly
    (z : Zq) (p : MLKEM.Polynomial) (j len : Nat)
    (hj : j < 256) (h_jlen : j + len < 256) (_h_len_pos : 0 < len) :
    inttButterflyAt z p j len hj h_jlen
      = invNttBangButterfly z p j len := by
  unfold inttButterflyAt invNttBangButterfly
  simp only [Vector.set_eq_set!, Vector.Inhabited_getElem_eq_getElem!]

/-- Inner-loop bridge (INTT): our impl-form GS butterfly loop equals the spec's
recursive `invNttLayerInner`. The two recurse in lock-step over `j ∈ [k, len)`
applying the same butterfly to `(start+j, start+j+len)`. -/
private theorem inttButterflies_eq_invNttLayerInner
    (i : Nat) (p : MLKEM.Polynomial) (len start k : Nat)
    (h_k : k ≤ len) (h_bound : start + 2 * len ≤ 256) (h_len : 0 < len) :
    inttButterflies (MLKEM.ζ ^ _root_.bitRev 7 i) p len
        (start + k) (start + len) (by scalar_tac)
      = invNttLayerInner p i len start k := by
  induction hn : len - k generalizing k p with
  | zero =>
    have hkl : k = len := by omega
    subst hkl
    rw [inttButterflies, invNttLayerInner_unfold]
    simp
  | succ n ih =>
    have hlt : k < len := by omega
    rw [inttButterflies, invNttLayerInner_unfold]
    have h_jlt : start + k < start + len := by scalar_tac
    simp only [h_jlt, hlt, ↓reduceDIte, ↓reduceIte]
    have h_jb : start + k < 256 := by scalar_tac
    have h_jlenb : start + k + len < 256 := by scalar_tac
    rw [inttButterflyAt_eq_invNttBangButterfly _ _ _ _ h_jb h_jlenb h_len]
    rw [show start + k + 1 = start + (k + 1) from by ring]
    have hn' : len - (k + 1) = n := by omega
    have := ih (invNttBangButterfly (MLKEM.ζ ^ _root_.bitRev 7 i) p (start + k) len)
        (k + 1) (by omega) hn'
    rw [this]
    unfold invNttBangButterfly
    rfl

/-- Middle-layer bridge (auxiliary, INTT): induct on the number of remaining
iterations `k` such that `k * (2*len) = 256 - start`. Produces both
`.1` (polynomial = `invNttLayer`) and `.2` (m counter decreased by `k`).

Twiddle counter: `inttMidStep` uses `m` directly (no `+1` shift, unlike the
forward direction), then decrements to `m - 1`. So the matching `invNttLayer`
call uses `i := m`. -/
private theorem inttMidLayer_eq_invNttLayer_aux
    (len : Nat) (h_len : 0 < len) (k : Nat)
    (start m : Nat) (h_eq : k * (2 * len) = 256 - start) (h_start : start ≤ 256)
    (h_m : k ≤ m)
    (p : MLKEM.Polynomial) :
    inttMidLayer len h_len start m p = (invNttLayer p m len start h_len, m - k) := by
  induction k generalizing start m p with
  | zero =>
    have h_diff_zero : start = 256 := by omega
    subst h_diff_zero
    rw [inttMidLayer, invNttLayer_unfold]
    have h1 : ¬ ((256 : Nat) + 2 * len ≤ 256) := by omega
    have h2 : ¬ ((256 : Nat) < 256) := by omega
    simp_all
  | succ k ih =>
    have h_start_plus : start + 2 * len ≤ 256 := by
      have h1 : 2 * len ≤ (k + 1) * (2 * len) := by
        have : 1 * (2 * len) ≤ (k + 1) * (2 * len) :=
          Nat.mul_le_mul_right _ (by omega)
        omega
      omega
    have h_lt : start < 256 := by omega
    rw [inttMidLayer]
    simp only [h_start_plus, ↓reduceDIte]
    unfold inttMidStep
    rw [invNttLayer_unfold]
    simp only [h_lt, ↓reduceIte]
    have h_eq_next : k * (2 * len) = 256 - (start + 2 * len) := by
      have hexp : (k + 1) * (2 * len) = k * (2 * len) + 2 * len := by ring
      omega
    have h_bridge := inttButterflies_eq_invNttLayerInner m p len start 0
        (by omega) h_start_plus h_len
    simp only [Nat.add_zero] at h_bridge
    rw [h_bridge]
    have h_m_pred : k ≤ m - 1 := by omega
    have h_ih := ih (start + 2 * len) (m - 1) h_eq_next h_start_plus h_m_pred
        (invNttLayerInner p m len start 0)
    show inttMidLayer len h_len (start + 2 * len) (m - 1) _ =
        (invNttLayer _ (m - 1) len (start + 2 * len) _, m - (k + 1))
    rw [h_ih]
    fcongr 1
    omega

/-- Middle-layer bridge (INTT, public form): our impl-form middle loop equals
the spec's recursive `invNttLayer`. -/
private theorem inttMidLayer_eq_invNttLayer
    (len : Nat) (h_len : 0 < len) (m start : Nat) (p : MLKEM.Polynomial)
    (h_div_start : 2 * len ∣ start) (h_div_256 : 2 * len ∣ 256)
    (h_start : start ≤ 256) (h_m : (256 - start) / (2 * len) ≤ m) :
    inttMidLayer len h_len start m p =
      (invNttLayer p m len start h_len, m - (256 - start) / (2 * len)) := by
  have h_div_diff : 2 * len ∣ (256 - start) := by
    obtain ⟨a, ha⟩ := h_div_256
    obtain ⟨b, hb⟩ := h_div_start
    have hba : b ≤ a := by
      rcases Nat.lt_or_ge a b with h | h
      · exfalso
        have hab : a + 1 ≤ b := h
        have hmul : 2 * len * (a + 1) ≤ 2 * len * b := Nat.mul_le_mul_left _ hab
        have : 2 * len * (a + 1) = 2 * len * a + 2 * len := by ring
        omega
      · exact h
    refine ⟨a - b, ?_⟩
    rw [Nat.mul_sub]; omega
  obtain ⟨k, hk⟩ := h_div_diff
  have h_k_eq : k * (2 * len) = 256 - start := by rw [Nat.mul_comm]; exact hk.symm
  have h_k_val : k = (256 - start) / (2 * len) := by
    have h_2len_pos : 0 < 2 * len := by omega
    have := Nat.mul_div_cancel k h_2len_pos
    rw [← h_k_eq] at *; omega
  rw [h_k_val.symm]
  have h_m' : k ≤ m := by rw [h_k_val]; exact h_m
  exact inttMidLayer_eq_invNttLayer_aux len h_len k start m h_k_eq h_start h_m' p

/-- Auxiliary: `inttFixup p = p * (3303 : Zq)` (Polynomial scalar mul). -/
private theorem inttFixup_eq_scalarMul (p : MLKEM.Polynomial) :
    inttFixup p = p * (3303 : Zq) := by
  unfold inttFixup
  show p.map _ = MLKEM.Polynomial.scalarMul p _
  unfold MLKEM.Polynomial.scalarMul
  fcongr 1
  funext v
  ring

/-- **E2.unfold-spec (let-pair form)** — spec NTTInv as seven `inttMidLayer`
calls + fixup, threading the `.2` counter explicitly.  This is the right
shape for proving `inttFixup_inttOuter_eq_NTTInv` via the
`inttOuter_peel` chain.  See `NTTInv_unfold_layers` for the linear form
(useful in wrapper proofs). -/
theorem NTTInv_unfold_layers_letpair (p : MLKEM.Polynomial) :
    MLKEM.NTTInv p =
      let (p1, m1) := inttMidLayer 2   (by decide) 0 127 p
      let (p2, m2) := inttMidLayer 4   (by decide) 0 m1  p1
      let (p3, m3) := inttMidLayer 8   (by decide) 0 m2  p2
      let (p4, m4) := inttMidLayer 16  (by decide) 0 m3  p3
      let (p5, m5) := inttMidLayer 32  (by decide) 0 m4  p4
      let (p6, m6) := inttMidLayer 64  (by decide) 0 m5  p5
      let (p7, _)  := inttMidLayer 128 (by decide) 0 m6  p6
      inttFixup p7 := by
  rw [Symcrust.Properties.MLKEM.Ntt.invNtt_eq_ntt_inv]
  unfold Symcrust.Properties.MLKEM.Ntt.invNtt
  simp only
    [inttMidLayer_eq_invNttLayer 2 (by decide) 127 0 _
        (by decide) (by decide) (by decide) (by decide),
     inttMidLayer_eq_invNttLayer 4 (by decide) 63 0 _
        (by decide) (by decide) (by decide) (by decide),
     inttMidLayer_eq_invNttLayer 8 (by decide) 31 0 _
        (by decide) (by decide) (by decide) (by decide),
     inttMidLayer_eq_invNttLayer 16 (by decide) 15 0 _
        (by decide) (by decide) (by decide) (by decide),
     inttMidLayer_eq_invNttLayer 32 (by decide) 7 0 _
        (by decide) (by decide) (by decide) (by decide),
     inttMidLayer_eq_invNttLayer 64 (by decide) 3 0 _
        (by decide) (by decide) (by decide) (by decide),
     inttMidLayer_eq_invNttLayer 128 (by decide) 1 0 _
        (by decide) (by decide) (by decide) (by decide)]
  rw [inttFixup_eq_scalarMul]

/-- **E2.unfold-spec** — spec NTTInv as seven `.1`-projected `inttMidLayer`
calls + fixup, with explicit pre-computed twiddle indices.  This is the
shape the wrapper `poly_element_intt.spec` needs because each impl-side
layer call lands on `(inttMidLayer len _ 0 k _).1` with `k` a literal
(127, 63, 31, …, 1). -/
theorem NTTInv_unfold_layers (p : MLKEM.Polynomial) :
    MLKEM.NTTInv p =
      let p1 := (inttMidLayer 2   (by decide) 0 127 p).1
      let p2 := (inttMidLayer 4   (by decide) 0 63  p1).1
      let p3 := (inttMidLayer 8   (by decide) 0 31  p2).1
      let p4 := (inttMidLayer 16  (by decide) 0 15  p3).1
      let p5 := (inttMidLayer 32  (by decide) 0 7   p4).1
      let p6 := (inttMidLayer 64  (by decide) 0 3   p5).1
      let p7 := (inttMidLayer 128 (by decide) 0 1   p6).1
      inttFixup p7 := by
  rw [NTTInv_unfold_layers_letpair]
  simp only [inttMidLayer_eq_invNttLayer 2 (by decide) 127 0 _
        (by decide) (by decide) (by decide) (by decide),
     inttMidLayer_eq_invNttLayer 4 (by decide) 63 0 _
        (by decide) (by decide) (by decide) (by decide),
     inttMidLayer_eq_invNttLayer 8 (by decide) 31 0 _
        (by decide) (by decide) (by decide) (by decide),
     inttMidLayer_eq_invNttLayer 16 (by decide) 15 0 _
        (by decide) (by decide) (by decide) (by decide),
     inttMidLayer_eq_invNttLayer 32 (by decide) 7 0 _
        (by decide) (by decide) (by decide) (by decide),
     inttMidLayer_eq_invNttLayer 64 (by decide) 3 0 _
        (by decide) (by decide) (by decide) (by decide),
     inttMidLayer_eq_invNttLayer 128 (by decide) 1 0 _
        (by decide) (by decide) (by decide) (by decide)]

/-- Peel one iteration of `inttOuter` when `len < 128`. -/
private theorem inttOuter_peel
    (len : Nat) (h_pos : 0 < len) (m : Nat) (p : MLKEM.Polynomial)
    (h_lt : len < 128) :
    inttOuter len h_pos m p =
      inttOuter (2 * len) (by scalar_tac)
        (inttMidLayer len h_pos 0 m p).2
        (inttMidLayer len h_pos 0 m p).1 := by
  rw [inttOuter]
  simp only [h_lt.le, h_lt, ↓reduceDIte]

/-- Final iteration of `inttOuter` at `len = 128` returns the midLayer result. -/
private theorem inttOuter_128 (m : Nat) (p : MLKEM.Polynomial) :
    inttOuter 128 (by decide) m p = inttMidLayer 128 (by decide) 0 m p := by
  rw [inttOuter]
  simp only [show (128 : Nat) ≤ 128 from by decide,
             show ¬ ((128 : Nat) < 128) from by decide, ↓reduceDIte]

/-- **E2** — outer-loop helper composed with `inttFixup` equals spec `NTTInv`.

Informal proof: analogous to E1, with Gentleman–Sande butterflies. The
spec's `NTTInv` (Algorithm 10):

  * `for h0: len in [2 : <256 : *= 2]` runs 7 iterations
    (len = 2, 4, …, 128),
  * twiddle counter `i` starts at `127` and is decremented after each
    mid-step,
  * post-loop, every coefficient is scaled by `3303 ≡ 128⁻¹ (mod q)`.

Our `inttOuter` starts at `len = 2`, threads `m = 127` downward, and
returns the pre-fixup result; `inttFixup` applies the `* 3303` scaling.

Proof strategy: rewrite the spec side via `NTTInv_unfold_layers`, then
peel `inttOuter` seven times (lens 2, 4, 8, 16, 32, 64) and close the
final `len = 128` iteration via `inttOuter_128`. -/
theorem inttFixup_inttOuter_eq_NTTInv (p : MLKEM.Polynomial) :
    inttFixup (inttOuter 2 (by decide) 127 p).1 = MLKEM.NTTInv p := by
  rw [NTTInv_unfold_layers_letpair]
  rw [inttOuter_peel 2 (by decide) 127 p (by decide)]
  rw [inttOuter_peel 4 (by decide) _ _ (by decide)]
  rw [inttOuter_peel 8 (by decide) _ _ (by decide)]
  rw [inttOuter_peel 16 (by decide) _ _ (by decide)]
  rw [inttOuter_peel 32 (by decide) _ _ (by decide)]
  rw [inttOuter_peel 64 (by decide) _ _ (by decide)]
  rw [inttOuter_128]

/-! ## E3 — Impl-side toPoly bridge for butterflies

The impl works with `Array U16 256` (under-`q` values); the helpers
above work on `Polynomial = Vector Zq 256`. Bridge: applying one impl
butterfly (`mont_mul` + `mod_sub` + `mod_add`) on the impl array
mirrors applying `nttButterflyAt` on the corresponding `Polynomial`.
-/

/-- **E3** — One impl butterfly step corresponds to one spec butterfly.

Given an impl array `a : PolyElement` and a logical twiddle `z : Zq`,
suppose two new U16 coefficients `c0_new`, `c1_new` satisfy the
butterfly equations modulo `q`:

* `u16ToZq c0_new = u16ToZq a[j] + z * u16ToZq a[j+len]`         (sum)
* `u16ToZq c1_new = u16ToZq a[j] - z * u16ToZq a[j+len]`         (diff)

(In the impl, `z` corresponds to `u32ToZq twiddle_factor * R⁻¹` after
Montgomery cancellation; `c0_new`, `c1_new` are the `cast U16` of the
`mod_add` / `mod_sub` results — see `Bridges/MontArith.lean` for the
Mont-form cancellation lemmas that discharge the equations above.
For the typical layer impl, `twiddle_factor` carries a `R` factor:
`mont_mul x ζ_mont = x · ζ_mont · R⁻¹ = x · ζ` when `ζ_mont = ζ · R`.)

Then the impl array obtained by writing `c0_new` at index `j` and
`c1_new` at index `j+len` is `toPoly`-equivalent to applying the spec's
single Cooley–Tukey butterfly `nttButterflyAt z (toPoly a) j len`.

Informal proof: pointwise on the underlying vector.
- At index `j`: spec writes `p[j] + z·p[j+len]`; impl writes `c0_new`
  whose `u16ToZq` is by `h_sum` the same value.
- At index `j+len`: spec writes `p[j] - z·p[j+len]`; impl writes
  `c1_new` whose `u16ToZq` is by `h_diff` the same value.  (Note the
  spec uses the *old* `p[j]` when computing the second write, because
  `let t := z * p[j+len]` is computed once before either `set`.  The
  impl computes `c0` and `c1` from `a` in the same way — both `c0_new`
  and `c1_new` are defined in terms of the original `a[j]` and
  `a[j+len]`.)
- At every other index `i ∉ {j, j+len}`: both sides leave the value
  unchanged.  `Vector.getElem_ofFn` + `Array.set_set_ne` close it.

The two `Array.set` calls in the impl write distinct positions
(`j ≠ j+len` since `len > 0` in every NTT layer), so the write order
is irrelevant. -/
theorem toPoly_ntt_butterfly_step
    (a : PolyElement) (z : Zq)
    (j len : Nat) (hj : j < 256) (h_jlen : j + len < 256) (h_len_pos : 0 < len)
    (c0_new c1_new : U16)
    (h_sum :
      u16ToZq c0_new =
        u16ToZq (a.val[j]'(by have := a.property; grind))
          + z * u16ToZq (a.val[j + len]'(by have := a.property; grind)))
    (h_diff :
      u16ToZq c1_new =
        u16ToZq (a.val[j]'(by have := a.property; grind))
          - z * u16ToZq (a.val[j + len]'(by have := a.property; grind)))
    (a' : PolyElement)
    (h_a' : a'.val = (a.val.set j c0_new).set (j + len) c1_new) :
    toPoly a' = nttButterflyAt z (toPoly a) j len hj h_jlen := by
  unfold nttButterflyAt
  have hne : j ≠ j + len := by omega
  have h_a_len : a.val.length = 256 := by have := a.property; grind
  have h_a'_len : a'.val.length = 256 := by have := a'.property; grind
  -- toPoly read at j / j+len reduces to u16ToZq of the array entry
  have h_toPoly_j : (toPoly a)[j] = u16ToZq (a.val[j]'(by omega)) := by
    unfold toPoly; simp [Vector.getElem_ofFn]
  have h_toPoly_jlen : (toPoly a)[j + len] = u16ToZq (a.val[j + len]'(by omega)) := by
    unfold toPoly; simp [Vector.getElem_ofFn]
  apply Vector.ext
  intro i hi
  -- Compute toPoly a' at index i
  have h_lhs : (toPoly a')[i] = u16ToZq (a'.val[i]'(by omega)) := by
    unfold toPoly; simp [Vector.getElem_ofFn]
  rw [h_lhs]
  -- Compute the RHS (double set!) at index i
  by_cases h_ij : i = j
  · -- index j (and j ≠ j+len since len > 0)
    simp only [h_ij] at *
    rw [Vector.getElem_set_self]
    have h_a'_at_j : a'.val[j]'(by omega) = c0_new := by
      rw [List.getElem_of_eq h_a']
      rw [List.getElem_set]
      split_ifs with h1
      · omega
      · rw [List.getElem_set]
        split_ifs with h2
        · rfl
        · exact (h2 rfl).elim
    rw [h_a'_at_j, h_sum, h_toPoly_j, h_toPoly_jlen]
  · by_cases h_ijl : i = j + len
    · -- index j+len
      simp only [h_ijl] at *
      rw [Vector.getElem_set_ne (h := by omega)]
      rw [Vector.getElem_set_self]
      have h_a'_at_jl : a'.val[j + len]'(by omega) = c1_new := by
        rw [List.getElem_of_eq h_a']
        rw [List.getElem_set]
        split_ifs with h1
        · rfl
        · exact (h1 rfl).elim
      rw [h_a'_at_jl, h_diff, h_toPoly_j, h_toPoly_jlen]
    · -- other index: unchanged
      rw [Vector.getElem_set_ne (h := by omega)]
      rw [Vector.getElem_set_ne (h := by omega)]
      have h_a'_at_i : a'.val[i]'(by omega) = a.val[i]'(by omega) := by
        rw [List.getElem_of_eq h_a']
        rw [List.getElem_set]
        split_ifs with h1
        · omega
        · rw [List.getElem_set]
          split_ifs with h2
          · omega
          · rfl
      rw [h_a'_at_i]
      unfold toPoly
      simp [Vector.getElem_ofFn]

/-- **E3 (INTT)** — One impl GS butterfly step corresponds to one spec
inverse butterfly.

Given an impl array `a : PolyElement` and a logical twiddle `z : Zq`,
suppose two new U16 coefficients `c0_new`, `c1_new` satisfy the
Gentleman–Sande butterfly equations modulo `q`:

* `u16ToZq c0_new = u16ToZq a[j] + u16ToZq a[j+len]`              (sum, no twiddle)
* `u16ToZq c1_new = z * (u16ToZq a[j+len] - u16ToZq a[j])`        (twiddle · diff)

Then the impl array obtained by writing `c0_new` at index `j` and
`c1_new` at index `j+len` is `toPoly`-equivalent to applying the spec's
single inverse butterfly `inttButterflyAt z (toPoly a) j len`. -/
theorem tbd_toPoly_intt_butterfly_step
    (a : PolyElement) (z : Zq)
    (j len : Nat) (hj : j < 256) (h_jlen : j + len < 256) (h_len_pos : 0 < len)
    (c0_new c1_new : U16)
    (h_sum :
      u16ToZq c0_new =
        u16ToZq (a.val[j]'(by have := a.property; grind))
          + u16ToZq (a.val[j + len]'(by have := a.property; grind)))
    (h_diff :
      u16ToZq c1_new =
        z * (u16ToZq (a.val[j + len]'(by have := a.property; grind))
              - u16ToZq (a.val[j]'(by have := a.property; grind))))
    (a' : PolyElement)
    (h_a' : a'.val = (a.val.set j c0_new).set (j + len) c1_new) :
    toPoly a' = inttButterflyAt z (toPoly a) j len hj h_jlen := by
  unfold inttButterflyAt
  have hne : j ≠ j + len := by omega
  have h_a_len : a.val.length = 256 := by have := a.property; grind
  have h_a'_len : a'.val.length = 256 := by have := a'.property; grind
  have h_toPoly_j : (toPoly a)[j] = u16ToZq (a.val[j]'(by omega)) := by
    unfold toPoly; simp [Vector.getElem_ofFn]
  have h_toPoly_jlen : (toPoly a)[j + len] = u16ToZq (a.val[j + len]'(by omega)) := by
    unfold toPoly; simp [Vector.getElem_ofFn]
  apply Vector.ext
  intro i hi
  have h_lhs : (toPoly a')[i] = u16ToZq (a'.val[i]'(by omega)) := by
    unfold toPoly; simp [Vector.getElem_ofFn]
  rw [h_lhs]
  by_cases h_ij : i = j
  · -- index j (sum branch)
    simp only [h_ij] at *
    rw [Vector.getElem_set_ne (h := by omega)]
    rw [Vector.getElem_set_self]
    have h_a'_at_j : a'.val[j]'(by omega) = c0_new := by
      rw [List.getElem_of_eq h_a']
      rw [List.getElem_set]
      split_ifs with h1
      · omega
      · rw [List.getElem_set]
        split_ifs with h2
        · rfl
        · exact (h2 rfl).elim
    rw [h_a'_at_j, h_sum, h_toPoly_j, h_toPoly_jlen]
  · by_cases h_ijl : i = j + len
    · -- index j+len (twiddle * diff branch)
      simp only [h_ijl] at *
      rw [Vector.getElem_set_self]
      have h_a'_at_jl : a'.val[j + len]'(by omega) = c1_new := by
        rw [List.getElem_of_eq h_a']
        rw [List.getElem_set]
        split_ifs with h1
        · rfl
        · exact (h1 rfl).elim
      rw [h_a'_at_jl, h_diff, h_toPoly_j, h_toPoly_jlen]
    · -- other index: unchanged
      rw [Vector.getElem_set_ne (h := by omega)]
      rw [Vector.getElem_set_ne (h := by omega)]
      have h_a'_at_i : a'.val[i]'(by omega) = a.val[i]'(by omega) := by
        rw [List.getElem_of_eq h_a']
        rw [List.getElem_set]
        split_ifs with h1
        · omega
        · rw [List.getElem_set]
          split_ifs with h2
          · omega
          · rfl
      rw [h_a'_at_i]
      unfold toPoly
      simp [Vector.getElem_ofFn]

/-! ## E4 — Parallel-equals-sequential bridge

For SIMD layers (`Vec128Layer`, `Avx2LayerNtt`), the implementation does
8/16 butterflies in parallel via vector load → arith → store. The two
output windows `[j_lo, j_lo+W)` and `[j_lo+len, j_lo+W+len)` are
disjoint as long as `W ≤ len`, so the parallel update is equivalent to
folding `W` independent `nttButterflyAt` steps via `nttButterflies`. -/

/-- Pointwise read of `nttButterflyAt`. Useful for reasoning about
`nttButterflyAt` indices when the parallel update writes them. -/
private theorem nttButterflyAt_getElem
    (z : Zq) (p : MLKEM.Polynomial) (j len : Nat)
    (hj : j < 256) (h_jlen : j + len < 256) (h_len_pos : 0 < len)
    (i : Nat) (hi : i < 256) :
    (nttButterflyAt z p j len hj h_jlen)[i] =
      if i = j then p[j] + z * p[j + len]
      else if i = j + len then p[j] - z * p[j + len]
      else p[i] := by
  unfold nttButterflyAt
  have hne_sym : j + len ≠ j := by omega
  by_cases h1 : i = j
  · subst h1
    rw [Vector.getElem_set_self, if_pos rfl]
  · rw [Vector.getElem_set_ne (h := by omega)]
    by_cases h2 : i = j + len
    · subst h2
      rw [Vector.getElem_set_self, if_neg hne_sym, if_pos rfl]
    · rw [Vector.getElem_set_ne (h := by omega), if_neg h1, if_neg h2]

/-- **Parallel-equals-sequential bridge** for `nttButterflies`.

If a SIMD step produces a polynomial `q` such that, for every
`j ∈ [j_lo, j_hi)`, the pair `(q[j], q[j+len])` satisfies the butterfly
equations against `(p[j], p[j+len])` with twiddle `z`, and `q` agrees
with `p` outside the two windows `[j_lo, j_hi)` and `[j_lo+len, j_hi+len)`,
then `q = nttButterflies z p len j_lo j_hi _` — i.e. `q` is exactly the
sequential fold of `j_hi - j_lo` butterflies.

The precondition `j_hi - j_lo ≤ len` ensures the two windows are
disjoint, so the order of the parallel writes does not matter. -/
theorem nttButterflies_eq_parallel
    (z : Zq) (len : Nat) (h_len_pos : 0 < len)
    (p q : MLKEM.Polynomial) (j_lo j_hi : Nat) (h_hi : j_hi + len ≤ 256)
    (h_le : j_lo ≤ j_hi) (h_W : j_hi - j_lo ≤ len)
    (h_pair_lo : ∀ (j : Nat) (_hjlt : j_lo ≤ j) (_hjub : j < j_hi),
      q[j]'(by omega) =
        p[j]'(by omega) + z * p[j + len]'(by omega))
    (h_pair_hi : ∀ (j : Nat) (_hjlt : j_lo ≤ j) (_hjub : j < j_hi),
      q[j + len]'(by omega) =
        p[j]'(by omega) - z * p[j + len]'(by omega))
    (h_frame : ∀ (i : Nat) (hi : i < 256),
      ¬(j_lo ≤ i ∧ i < j_hi) →
      ¬(j_lo + len ≤ i ∧ i < j_hi + len) →
      q[i]'hi = p[i]'hi) :
    q = nttButterflies z p len j_lo j_hi h_hi := by
  induction hn : j_hi - j_lo generalizing j_lo p with
  | zero =>
    have h_eq : j_lo = j_hi := by omega
    subst h_eq
    unfold nttButterflies
    simp only [lt_irrefl, ↓reduceDIte]
    apply Vector.ext
    intro i hi
    exact h_frame i hi (by omega) (by omega)
  | succ n ih =>
    have hlt : j_lo < j_hi := by omega
    have h_jb : j_lo < 256 := by omega
    have h_jlenb : j_lo + len < 256 := by omega
    unfold nttButterflies
    simp only [hlt, ↓reduceDIte]
    set p' := nttButterflyAt z p j_lo len h_jb h_jlenb with hp'
    refine ih p' (j_lo + 1) (by omega) (by omega) ?_ ?_ ?_ (by omega)
    · intro j hjlt hjub
      have h_p'_at_j : p'[j]'(by omega) = p[j]'(by omega) := by
        rw [hp', nttButterflyAt_getElem z p j_lo len h_jb h_jlenb h_len_pos _ (by omega)]
        rw [if_neg (by omega), if_neg (by omega)]
      have h_p'_at_jlen : p'[j + len]'(by omega) = p[j + len]'(by omega) := by
        rw [hp', nttButterflyAt_getElem z p j_lo len h_jb h_jlenb h_len_pos _ (by omega)]
        rw [if_neg (by omega), if_neg (by omega)]
      rw [h_p'_at_j, h_p'_at_jlen]
      exact h_pair_lo j (by omega) hjub
    · intro j hjlt hjub
      have h_p'_at_j : p'[j]'(by omega) = p[j]'(by omega) := by
        rw [hp', nttButterflyAt_getElem z p j_lo len h_jb h_jlenb h_len_pos _ (by omega)]
        rw [if_neg (by omega), if_neg (by omega)]
      have h_p'_at_jlen : p'[j + len]'(by omega) = p[j + len]'(by omega) := by
        rw [hp', nttButterflyAt_getElem z p j_lo len h_jb h_jlenb h_len_pos _ (by omega)]
        rw [if_neg (by omega), if_neg (by omega)]
      rw [h_p'_at_j, h_p'_at_jlen]
      exact h_pair_hi j (by omega) hjub
    · intro i hi h_not_lo h_not_hi
      rw [hp', nttButterflyAt_getElem z p j_lo len h_jb h_jlenb h_len_pos _ hi]
      by_cases hi_j : i = j_lo
      · subst hi_j
        rw [if_pos rfl]
        exact h_pair_lo i (le_refl _) hlt
      · by_cases hi_jl : i = j_lo + len
        · subst hi_jl
          rw [if_neg (by omega), if_pos rfl]
          exact h_pair_hi j_lo (le_refl _) hlt
        · rw [if_neg hi_j, if_neg hi_jl]
          exact h_frame i hi
            (fun ⟨_, _⟩ => h_not_lo ⟨by omega, by omega⟩)
            (fun ⟨_, _⟩ => h_not_hi ⟨by omega, by omega⟩)

/-! ### Pointwise / parallel bridges for `inttButterflies` (Gentleman-Sande)

Symmetric mirror of `nttButterflyAt_getElem` / `nttButterflies_eq_parallel`.
The bodies differ only in the local equations:

- new `p[j]     = p[j] + p[j+len]`       (no twiddle on the *sum*)
- new `p[j+len] = z · (p[j+len] - p[j])` (twiddle on the *diff*)

vs. the forward NTT (Cooley-Tukey):

- new `p[j]     = p[j] + z · p[j+len]`
- new `p[j+len] = p[j] - z · p[j+len]`

The disjointness / commutation argument is identical, because the two
windows are independent regardless of the per-pair formula. -/

/-- Pointwise read of `inttButterflyAt`. Useful for reasoning about
`inttButterflyAt` indices when a SIMD parallel update writes them. -/
private theorem inttButterflyAt_getElem
    (z : Zq) (p : MLKEM.Polynomial) (j len : Nat)
    (hj : j < 256) (h_jlen : j + len < 256) (h_len_pos : 0 < len)
    (i : Nat) (hi : i < 256) :
    (inttButterflyAt z p j len hj h_jlen)[i] =
      if i = j then p[j] + p[j + len]
      else if i = j + len then z * (p[j + len] - p[j])
      else p[i] := by
  unfold inttButterflyAt
  have hne_sym : j + len ≠ j := by omega
  by_cases h1 : i = j
  · subst h1
    rw [Vector.getElem_set_ne (h := by omega), Vector.getElem_set_self, if_pos rfl]
  · by_cases h2 : i = j + len
    · subst h2
      rw [Vector.getElem_set_self, if_neg h1, if_pos rfl]
    · rw [Vector.getElem_set_ne (h := by omega),
          Vector.getElem_set_ne (h := by omega), if_neg h1, if_neg h2]

/-- **Parallel-equals-sequential bridge** for `inttButterflies` (Gentleman-Sande).

Symmetric counterpart of `nttButterflies_eq_parallel`. If a SIMD step produces
a polynomial `q` such that, for every `j ∈ [j_lo, j_hi)`, the pair
`(q[j], q[j+len])` satisfies the **Gentleman-Sande** butterfly equations
against `(p[j], p[j+len])` with twiddle `z`, and `q` agrees with `p` outside
the two windows, then `q = inttButterflies z p len j_lo j_hi _` — i.e. `q`
is exactly the sequential fold of `j_hi - j_lo` butterflies.

The precondition `j_hi - j_lo ≤ len` ensures the two windows are
disjoint, so the order of the parallel writes does not matter. -/
theorem inttButterflies_eq_parallel
    (z : Zq) (len : Nat) (h_len_pos : 0 < len)
    (p q : MLKEM.Polynomial) (j_lo j_hi : Nat) (h_hi : j_hi + len ≤ 256)
    (h_le : j_lo ≤ j_hi) (h_W : j_hi - j_lo ≤ len)
    (h_pair_lo : ∀ (j : Nat) (_hjlt : j_lo ≤ j) (_hjub : j < j_hi),
      q[j]'(by omega) =
        p[j]'(by omega) + p[j + len]'(by omega))
    (h_pair_hi : ∀ (j : Nat) (_hjlt : j_lo ≤ j) (_hjub : j < j_hi),
      q[j + len]'(by omega) =
        z * (p[j + len]'(by omega) - p[j]'(by omega)))
    (h_frame : ∀ (i : Nat) (hi : i < 256),
      ¬(j_lo ≤ i ∧ i < j_hi) →
      ¬(j_lo + len ≤ i ∧ i < j_hi + len) →
      q[i]'hi = p[i]'hi) :
    q = inttButterflies z p len j_lo j_hi h_hi := by
  induction hn : j_hi - j_lo generalizing j_lo p with
  | zero =>
    have h_eq : j_lo = j_hi := by omega
    subst h_eq
    unfold inttButterflies
    simp only [lt_irrefl, ↓reduceDIte]
    apply Vector.ext
    intro i hi
    exact h_frame i hi (by omega) (by omega)
  | succ n ih =>
    have hlt : j_lo < j_hi := by omega
    have h_jb : j_lo < 256 := by omega
    have h_jlenb : j_lo + len < 256 := by omega
    unfold inttButterflies
    simp only [hlt, ↓reduceDIte]
    set p' := inttButterflyAt z p j_lo len h_jb h_jlenb with hp'
    refine ih p' (j_lo + 1) (by omega) (by omega) ?_ ?_ ?_ (by omega)
    · intro j hjlt hjub
      have h_p'_at_j : p'[j]'(by omega) = p[j]'(by omega) := by
        rw [hp', inttButterflyAt_getElem z p j_lo len h_jb h_jlenb h_len_pos _ (by omega)]
        rw [if_neg (by omega), if_neg (by omega)]
      have h_p'_at_jlen : p'[j + len]'(by omega) = p[j + len]'(by omega) := by
        rw [hp', inttButterflyAt_getElem z p j_lo len h_jb h_jlenb h_len_pos _ (by omega)]
        rw [if_neg (by omega), if_neg (by omega)]
      rw [h_p'_at_j, h_p'_at_jlen]
      exact h_pair_lo j (by omega) hjub
    · intro j hjlt hjub
      have h_p'_at_j : p'[j]'(by omega) = p[j]'(by omega) := by
        rw [hp', inttButterflyAt_getElem z p j_lo len h_jb h_jlenb h_len_pos _ (by omega)]
        rw [if_neg (by omega), if_neg (by omega)]
      have h_p'_at_jlen : p'[j + len]'(by omega) = p[j + len]'(by omega) := by
        rw [hp', inttButterflyAt_getElem z p j_lo len h_jb h_jlenb h_len_pos _ (by omega)]
        rw [if_neg (by omega), if_neg (by omega)]
      rw [h_p'_at_j, h_p'_at_jlen]
      exact h_pair_hi j (by omega) hjub
    · intro i hi h_not_lo h_not_hi
      rw [hp', inttButterflyAt_getElem z p j_lo len h_jb h_jlenb h_len_pos _ hi]
      by_cases hi_j : i = j_lo
      · subst hi_j
        rw [if_pos rfl]
        exact h_pair_lo i (le_refl _) hlt
      · by_cases hi_jl : i = j_lo + len
        · subst hi_jl
          rw [if_neg (by omega), if_pos rfl]
          exact h_pair_hi j_lo (le_refl _) hlt
        · rw [if_neg hi_j, if_neg hi_jl]
          exact h_frame i hi
            (fun ⟨_, _⟩ => h_not_lo ⟨by omega, by omega⟩)
            (fun ⟨_, _⟩ => h_not_hi ⟨by omega, by omega⟩)

/-! ### Range-composition lemmas for `nttButterflies` / `inttButterflies`

`_nil` (empty range collapses to identity) and `_split` (split the range
at any interior point) — used by the SIMD inner-loop proofs to compose a
per-step `nttButterflies … (start+j) (start+j+W)` chunk with the
recursive `nttButterflies … (start+j+W) (start+len)` IH. -/

theorem nttButterflies_nil
    (z : Zq) (p : MLKEM.Polynomial) (len j_lo j_hi : Nat) (h_hi : j_hi + len ≤ 256)
    (h_empty : ¬ j_lo < j_hi) :
    nttButterflies z p len j_lo j_hi h_hi = p := by
  unfold nttButterflies; simp [h_empty]

theorem nttButterflies_split
    (z : Zq) (p : MLKEM.Polynomial) (len j_lo j_mid j_hi : Nat)
    (h_lo : j_lo ≤ j_mid) (h_mid : j_mid ≤ j_hi)
    (h_hi : j_hi + len ≤ 256) :
    nttButterflies z p len j_lo j_hi h_hi
      = nttButterflies z
          (nttButterflies z p len j_lo j_mid (by omega))
          len j_mid j_hi h_hi := by
  -- Induct on the size of [j_lo, j_mid) using strong induction on `j_mid - j_lo`.
  induction h_diff : j_mid - j_lo generalizing p j_lo with
  | zero =>
    have h_eq : j_lo = j_mid := by omega
    subst h_eq
    rw [nttButterflies_nil z p len j_lo j_lo (by omega) (by omega)]
  | succ n ih =>
    have h_lt : j_lo < j_mid := by omega
    -- Unfold the LHS once: pull off the j_lo butterfly, then it's _split on j_lo+1..j_hi.
    conv_lhs => rw [nttButterflies]; simp [show j_lo < j_hi by omega]
    -- Unfold the inner butterflies on the RHS the same way.
    conv_rhs =>
      rw [show nttButterflies z p len j_lo j_mid (by omega : j_mid + len ≤ 256)
            = nttButterflies z
                (nttButterflyAt z p j_lo len (by scalar_tac) (by scalar_tac))
                len (j_lo + 1) j_mid (by omega) from by
        conv_lhs => rw [nttButterflies]; simp [h_lt]]
    -- Apply IH with the shifted lower bound.
    exact ih _ (j_lo + 1) (by omega) (by omega)

theorem inttButterflies_nil
    (z : Zq) (p : MLKEM.Polynomial) (len j_lo j_hi : Nat) (h_hi : j_hi + len ≤ 256)
    (h_empty : ¬ j_lo < j_hi) :
    inttButterflies z p len j_lo j_hi h_hi = p := by
  unfold inttButterflies; simp [h_empty]

theorem inttButterflies_split
    (z : Zq) (p : MLKEM.Polynomial) (len j_lo j_mid j_hi : Nat)
    (h_lo : j_lo ≤ j_mid) (h_mid : j_mid ≤ j_hi)
    (h_hi : j_hi + len ≤ 256) :
    inttButterflies z p len j_lo j_hi h_hi
      = inttButterflies z
          (inttButterflies z p len j_lo j_mid (by omega))
          len j_mid j_hi h_hi := by
  induction h_diff : j_mid - j_lo generalizing p j_lo with
  | zero =>
    have h_eq : j_lo = j_mid := by omega
    subst h_eq
    rw [inttButterflies_nil z p len j_lo j_lo (by omega) (by omega)]
  | succ n ih =>
    have h_lt : j_lo < j_mid := by omega
    conv_lhs => rw [inttButterflies]; simp [show j_lo < j_hi by omega]
    conv_rhs =>
      rw [show inttButterflies z p len j_lo j_mid (by omega : j_mid + len ≤ 256)
            = inttButterflies z
                (inttButterflyAt z p j_lo len (by scalar_tac) (by scalar_tac))
                len (j_lo + 1) j_mid (by omega) from by
        conv_lhs => rw [inttButterflies]; simp [h_lt]]
    exact ih _ (j_lo + 1) (by omega) (by omega)

end Symcrust.Properties.MLKEM.Bridges
