/-
# `NttSpecAux.lean` — pure-spec NTT / INTT decomposition

A stratified pure-spec layer between the Aeneas-extracted NTT/INTT code and
the FIPS 203 specs (`Spec.NTT` / `NTTInv`). The Aeneas-side
proofs (in `Ntt.lean` / `Intt.lean`) target these auxiliary functions, and a
single equation per direction (`ntt_eq` / `invNtt_eq`) closes the loop back
to the FIPS spec.
-/
import Spec.MLKEM.Polynomials
import Spec.NatBit
import Symcrust.Properties.MLKEM.AeneasExtras

namespace Symcrust.Properties.MLKEM.Ntt

open Spec
open Spec.MLKEM
open Aeneas

set_option maxHeartbeats 1000000
set_option maxRecDepth 65536

/-- Vector.set! coincides with Vector.setIfInBounds. Used as a simp bridge so
that the kernel rewrites between `set!` (used in `nttLayerInner` /
`invNttLayerInner`) and the typed `set` from `Spec.MLKEM.NTT` / `NTTInv`. -/
theorem Vector.set!_eq_setIfInBounds {α : Type*} {n : Nat}
    (v : _root_.Vector α n) (i : Nat) (a : α) :
    v.set! i a = v.setIfInBounds i a := by
  unfold _root_.Vector.set!; rfl

/-- Commute two `set!` writes at distinct indices. -/
theorem Vector.set!_comm {α : Type*} {n : Nat} (v : _root_.Vector α n)
    (i j : Nat) (a b : α) (h : i ≠ j) :
    (v.set! i a).set! j b = (v.set! j b).set! i a := by
  simp only [Vector.set!_eq_setIfInBounds]
  exact _root_.Vector.setIfInBound_comm a b h

/-! ## Forward NTT (Cooley–Tukey) -/

/-- One layer of the NTT forward butterfly across positions
`[start, start + len) × [start + len, start + 2*len)`, parameterised by the
twiddle index `i`. Recurses on `j` from 0 to `len`. -/
def nttLayerInner (f : Polynomial) (i len start j : Nat) : Polynomial :=
  if j < len then
    let c0   := f[start + j]!
    let c1   := f[start + j + len]!
    let zeta := ζ ^ bitRev 7 i
    let f    := f.set! (start + j)       (c0 + c1 * zeta)
    let f    := f.set! (start + j + len) (c0 - c1 * zeta)
    nttLayerInner f i len start (j + 1)
  else f
termination_by len - j

/-- The NTT layer: walks `start` over multiples of `2*len` from 0 to 256,
incrementing the twiddle index `i` at each step. -/
def nttLayer (f : Polynomial) (i len start : Nat) (hLen : 0 < len := by simp) :
    Polynomial :=
  if start < 256 then
    let f := nttLayerInner f i len start 0
    nttLayer f (i + 1) len (start + 2 * len) hLen
  else f
termination_by 256 - start
decreasing_by omega

/-- The whole forward NTT: 7 layers, halving `len` and doubling the twiddle base. -/
def ntt (f : Polynomial) : Polynomial :=
  let f := nttLayer f  1 128 0
  let f := nttLayer f  2  64 0
  let f := nttLayer f  4  32 0
  let f := nttLayer f  8  16 0
  let f := nttLayer f 16   8 0
  let f := nttLayer f 32   4 0
  let f := nttLayer f 64   2 0
  f

/-! ### Forward NTT layer-equivalence helpers

`nttBangButterfly zeta f j len` is the bang-form butterfly used in
`nttLayerInner`. We prove three layer-equivalence lemmas:

* `nttLayerInner_eq_forIn` — inner-loop iso (recursion → `forIn'`).
* `nttLayer_eq_specForIn` — `nttLayer` matches the spec's middle `for`
  with mutable `(i, f)` state.
* The spec's typed-`set` butterfly equals `nttBangButterfly`
  (`specForm_eq_nttBangButterfly`).
-/

def nttBangButterfly (zeta : Zq) (f : Polynomial) (j len : Nat) : Polynomial :=
  let c0 := f[j]!
  let c1 := f[j + len]!
  (f.set! j (c0 + c1 * zeta)).set! (j + len) (c0 - c1 * zeta)

/-- The spec body of `NTT`'s innermost loop (typed `set`, j+len-then-j order)
equals `nttBangButterfly` (bang form, j-then-j+len order). The two-set
sequence commutes because `j ≠ j + len` (which holds since `len > 0`). -/
private theorem specForm_eq_nttBangButterfly
    (zeta : Zq) (f : Polynomial) (j len : Nat) (h_len : 0 < len)
    (hj : j < 256) (hjlen : j + len < 256) :
    (f.set (j + len) (f[j] - zeta * f[j + len]) (by simpa using hjlen)).set j
        ((f.set (j + len) (f[j] - zeta * f[j + len]) (by simpa using hjlen))[j]
          + zeta * f[j + len]) (by simpa using hj)
      = nttBangButterfly zeta f j len := by
  show _ = (f.set! j (f[j]! + f[j+len]! * zeta)).set! (j+len) (f[j]! - f[j+len]! * zeta)
  have hne : j + len ≠ j := by omega
  -- Convert RHS `set!` and `[..]!` to typed `set` and `[..]`.
  rw [show f[j]! = f[j] from (Vector.Inhabited_getElem_eq_getElem! f j (by simpa using hj)).symm]
  rw [show f[j + len]! = f[j + len] from
        (Vector.Inhabited_getElem_eq_getElem! f (j + len) (by simpa using hjlen)).symm]
  rw [← Vector.set_eq_set! f j _ (by simpa using hj)]
  rw [← Vector.set_eq_set! _ (j + len) _ (by simpa using hjlen)]
  -- LHS inner getElem at j after set at j+len: just f[j].
  rw [Vector.getElem_set_ne (h := hne)]
  -- Now both sides have form `(f.set a va).set b vb` (different indices).
  -- Extensionality reduces to per-coord equality.
  apply Vector.ext
  intro k hk
  rw [Vector.getElem_set (hi := by simpa using hj) (hj := hk)]
  rw [Vector.getElem_set (hi := by simpa using hjlen) (hj := hk)]
  rw [Vector.getElem_set (hi := by simpa using hjlen) (hj := hk)]
  rw [Vector.getElem_set (hi := by simpa using hj) (hj := hk)]
  -- 4 sub-cases from split_ifs: (k=j or not) × (k=j+len or not). The (yes,yes) case is contradictory.
  by_cases hkj : j = k
  · subst hkj
    by_cases hkjl : j + len = j
    · omega
    · rw [if_neg hkjl, if_pos rfl, if_neg hkjl, if_pos rfl]
      ring
  · by_cases hkjl : j + len = k
    · subst hkjl
      have hjne : ¬ j = j + len := fun h => hkj (by omega)
      rw [if_pos rfl, if_neg hkj, if_pos rfl]
      ring
    · rw [if_neg hkjl, if_neg hkj, if_neg hkjl, if_neg hkj]

/-- Bang-form butterfly bridge: the spec body in bang form (sets at `j+len` then
`j`) equals `nttBangButterfly` (sets at `j` then `j+len`). The two-set sequence
commutes because `j ≠ j + len` (which holds since `len > 0`). -/
theorem specForm_bang_eq_nttBangButterfly
    (zeta : Zq) (f : Polynomial) (j len : Nat) (h_len : 0 < len) :
    (f.set! (j + len) (f[j]! - zeta * f[j + len]!)).set! j
        ((f.set! (j + len) (f[j]! - zeta * f[j + len]!))[j]! + zeta * f[j + len]!)
      = nttBangButterfly zeta f j len := by
  have hne : j + len ≠ j := by omega
  rw [Vector.getElem!_set!_ne hne]
  unfold nttBangButterfly
  rw [Vector.set!_comm _ (j + len) j _ _ hne]
  ring_nf

/-- Unfold `nttLayerInner` one step. -/
theorem nttLayerInner_unfold (f : Polynomial) (i len start j : Nat) :
    nttLayerInner f i len start j =
      if j < len then
        let c0 := f[start + j]!
        let c1 := f[start + j + len]!
        let zeta := ζ ^ bitRev 7 i
        let f := f.set! (start + j) (c0 + c1 * zeta)
        let f := f.set! (start + j + len) (c0 - c1 * zeta)
        nttLayerInner f i len start (j + 1)
      else f := by
  conv_lhs => rw [nttLayerInner]

/-- Inner-loop equivalence: `nttLayerInner f i len start j` equals a `forIn'`
over `List.range' (start + j) (len - j)` whose body applies the bang
butterfly at position `(k, k + len)`. -/
private theorem nttLayerInner_eq_forIn (i len start j : Nat) (h_j : j ≤ len)
    (f : Polynomial) :
    nttLayerInner f i len start j =
    Id.run (forIn' (List.range' (start + j) (len - j)) f (fun k _ p =>
      pure (ForInStep.yield (nttBangButterfly (ζ ^ bitRev 7 i) p k len)))) := by
  rw [nttLayerInner_unfold]
  by_cases hlt : j < len
  · simp only [hlt, ite_true]
    have hlen_succ : len - j = (len - (j + 1)) + 1 := by omega
    have h_j' : j + 1 ≤ len := by omega
    rw [hlen_succ, List.range'_succ]
    simp only [List.forIn'_cons, Id.run, pure_bind]
    have ih := nttLayerInner_eq_forIn i len start (j + 1) h_j'
                  ((f.set! (start + j) (f[start + j]! + f[start + j + len]! * (ζ ^ bitRev 7 i))).set!
                     (start + j + len)
                     (f[start + j]! - f[start + j + len]! * (ζ ^ bitRev 7 i)))
    show nttLayerInner _ i len start (j + 1) =
         (forIn' (List.range' (start + (j + 1)) (len - (j + 1)))
             (nttBangButterfly (ζ ^ bitRev 7 i) f (start + j) len) _ : Id _)
    exact ih
  · simp only [hlt, ite_false]
    have : len - j = 0 := by omega
    rw [this]
    rfl
termination_by len - j

/-- Specialised inner-loop fold-back at j = 0 (used in `nttLayer_eq_specForIn`). -/
private theorem nttLayerInner_eq_forIn_zero (i len start : Nat) (f : Polynomial) :
    nttLayerInner f i len start 0 =
    Id.run (forIn' (List.range' start len) f (fun k _ p =>
      pure (ForInStep.yield (nttBangButterfly (ζ ^ bitRev 7 i) p k len)))) := by
  have := nttLayerInner_eq_forIn i len start 0 (Nat.zero_le _) f
  simpa using this

/-- Unfold `nttLayer` one step. -/
theorem nttLayer_unfold (f : Polynomial) (i len start : Nat) (hLen : 0 < len) :
    nttLayer f i len start hLen =
      if start < 256 then
        let f := nttLayerInner f i len start 0
        nttLayer f (i + 1) len (start + 2 * len) hLen
      else f := by
  conv_lhs => rw [nttLayer]

/-- Middle-layer equivalence: `nttLayer f i_init len start` equals the first
component of a `forIn'` over `List.range' start K (2*len)` threading
`MProd Polynomial Nat` state and running the inner loop in bang form.
This state ordering matches `Spec.NTT`'s desugared `mut «f̂» := f; mut i := 1`.
The second component (counter) is `i_init + (number of iterations completed)`.

Using `MProd` (not `Prod`) is essential — the `do { let mut ...; ... }` macro
elaborates mutable bindings to `MProd`, so the goal in `ntt_eq` will have
`MProd Polynomial Nat`, and a lemma stated with `Prod` will not unify. -/
private theorem nttLayer_eq_specForIn (len : Nat) (h_len : 0 < len)
    (K start i_init : Nat) (h_K : K * (2 * len) = 256 - start) (h_start : start ≤ 256)
    (f : Polynomial) :
    Id.run (forIn' (List.range' start K (2 * len))
        (⟨f, i_init⟩ : MProd Polynomial Nat)
        (fun s _ st => do
          let r ← forIn' (List.range' s len) st.fst (fun k _ p =>
            pure (ForInStep.yield
              (nttBangButterfly (ζ ^ bitRev 7 st.snd) p k len)))
          pure (ForInStep.yield (⟨r, st.snd + 1⟩ : MProd Polynomial Nat)))) =
      (⟨nttLayer f i_init len start h_len, i_init + K⟩ : MProd Polynomial Nat) := by
  induction K generalizing start i_init f with
  | zero =>
    have h_start_eq : start = 256 := by simp at h_K; omega
    rw [nttLayer_unfold]
    have hns : ¬ start < 256 := by omega
    simp [hns, List.range'_zero, Id.run]
    rfl
  | succ K' ih =>
    have h_expand : (K' + 1) * (2 * len) = K' * (2 * len) + 2 * len := by ring
    have h_yes : start < 256 := by omega
    have h_start_next : start + 2 * len ≤ 256 := by omega
    have h_next : K' * (2 * len) = 256 - (start + 2 * len) := by omega
    rw [nttLayer_unfold]
    simp only [h_yes, ite_true]
    rw [List.range'_succ]
    simp only [List.forIn'_cons, Id.run, bind_pure_comp]
    have ih' := ih (start + 2 * len) (i_init + 1) h_next h_start_next
                  (nttLayerInner f i_init len start 0)
    rw [nttLayerInner_eq_forIn_zero] at ih'
    simp only [Id.run, bind_pure_comp] at ih'
    have hcount : i_init + (K' + 1) = i_init + 1 + K' := by ring
    rw [hcount]
    -- Rewrite the inner `nttLayerInner` to its forIn' form so both sides match.
    have hbridge := nttLayerInner_eq_forIn_zero i_init len start f
    simp only [Id.run] at hbridge
    rw [hbridge]
    exact ih'

/-- Variant of `nttLayer_eq_specForIn` without explicit `Id.run` wrapping, for
direct rewriting in `ntt_eq`. Threads `MProd` state (matching do-block elaboration). -/
private theorem nttLayer_eq_forIn (len : Nat) (h_len : 0 < len)
    (K start i_init : Nat) (h_K : K * (2 * len) = 256 - start) (h_start : start ≤ 256)
    (f : Polynomial) :
    forIn' (m := Id) (List.range' start K (2 * len))
      (⟨f, i_init⟩ : MProd Polynomial Nat)
      (fun s _ st => do
        let r ← forIn' (List.range' s len) st.fst
                  (fun k _ p =>
                    pure (ForInStep.yield
                      (nttBangButterfly (ζ ^ bitRev 7 st.snd) p k len)))
        pure (ForInStep.yield ((⟨r, st.snd + 1⟩ : MProd Polynomial Nat)))) =
    pure (⟨nttLayer f i_init len start h_len, i_init + K⟩ : MProd Polynomial Nat) := by
  have := nttLayer_eq_specForIn len h_len K start i_init h_K h_start f
  exact this

/-- The aux-spec `ntt` matches `NTT` on every input.

Informal proof: by induction on the seven layers, each `nttLayer ... 0` walks
a fixed sequence of `(i, len, start)` triples that exactly mirrors the
`for h0: len in [128 : >1 : /= 2]` × `for h1: start in [0 : 256 : 2*len]`
nested loops in `NTT`, with the inner butterfly identical between
the two presentations. -/
theorem ntt_eq (f : Polynomial) : ntt f = NTT f := by
  unfold ntt NTT
  -- Step 1: convert outer DivRange to explicit list, then to seven nested forIn'.
  simp only [Id.run, Aeneas.DivRange.forIn'_eq_forIn_divRange,
             show (Aeneas.divRange 128 1 2) = [128, 64, 32, 16, 8, 4, 2] from by decide,
             List.forIn'_cons, List.forIn'_nil]
  -- Step 2: convert each typed `set` / `[·]` in the spec body to bang form.
  simp only [Vector.set_eq_set!, Vector.Inhabited_getElem_eq_getElem!]
  -- Step 3: convert middle SRRange forIn' to List.range' forIn'.
  simp only [Aeneas.SRRange.forIn'_eq_forIn'_range', Aeneas.SRRange.size]
  -- Step 4: simplify the inner SRRange size to `len`.
  -- `size_step_one_const_len` from `AeneasExtras` replaces seven hand-rolled
  -- `show ∀ a, (a + N - a + 1 - 1) / 1 = N` lines.
  simp only [Symcrust.Properties.MLKEM.AeneasExtras.size_step_one_const_len]
  -- Step 5: simplify the middle (outer) SRRange size to `K` per layer.
  simp only [show (256 - 0 + 2 * 128 - 1) / (2 * 128) = 1 from by decide,
             show (256 - 0 + 2 * 64 - 1) / (2 * 64) = 2 from by decide,
             show (256 - 0 + 2 * 32 - 1) / (2 * 32) = 4 from by decide,
             show (256 - 0 + 2 * 16 - 1) / (2 * 16) = 8 from by decide,
             show (256 - 0 + 2 * 8 - 1) / (2 * 8) = 16 from by decide,
             show (256 - 0 + 2 * 4 - 1) / (2 * 4) = 32 from by decide,
             show (256 - 0 + 2 * 2 - 1) / (2 * 2) = 64 from by decide]
  -- Step 6: replace bang spec-body with `nttBangButterfly`.
  simp only [specForm_bang_eq_nttBangButterfly _ _ _ _ (by decide : 0 < 128),
             specForm_bang_eq_nttBangButterfly _ _ _ _ (by decide : 0 < 64),
             specForm_bang_eq_nttBangButterfly _ _ _ _ (by decide : 0 < 32),
             specForm_bang_eq_nttBangButterfly _ _ _ _ (by decide : 0 < 16),
             specForm_bang_eq_nttBangButterfly _ _ _ _ (by decide : 0 < 8),
             specForm_bang_eq_nttBangButterfly _ _ _ _ (by decide : 0 < 4),
             specForm_bang_eq_nttBangButterfly _ _ _ _ (by decide : 0 < 2)]
  -- Step 6b: eliminate `pure PUnit.unit` residue from the bang-butterfly fold.
  simp only [pure_bind]
  -- Step 7: fold each layer back via `nttLayer_eq_forIn`. After each rewrite,
  -- collapse the `pure x >>= ...` / `match yield x with | yield b => ...` chain
  -- so the next layer sees a concrete state.
  rw [nttLayer_eq_forIn 128 (by decide) 1 0 1 (by decide) (by decide) f]
  simp only [pure_bind]
  rw [nttLayer_eq_forIn 64 (by decide) 2 0 2 (by decide) (by decide)]
  simp only [pure_bind]
  rw [nttLayer_eq_forIn 32 (by decide) 4 0 4 (by decide) (by decide)]
  simp only [pure_bind]
  rw [nttLayer_eq_forIn 16 (by decide) 8 0 8 (by decide) (by decide)]
  simp only [pure_bind]
  rw [nttLayer_eq_forIn 8 (by decide) 16 0 16 (by decide) (by decide)]
  simp only [pure_bind]
  rw [nttLayer_eq_forIn 4 (by decide) 32 0 32 (by decide) (by decide)]
  simp only [pure_bind]
  rw [nttLayer_eq_forIn 2 (by decide) 64 0 64 (by decide) (by decide)]
  rfl

/-! ## Inverse NTT (Gentleman–Sande) -/

/-- One layer of the INTT inverse butterfly across positions
`[start, start + len) × [start + len, start + 2*len)`. The lower index
receives `c0 + c1`; the upper receives `zeta * (c1 - c0)` (note the sign
inversion vs the forward butterfly — this is a Gentleman–Sande pattern,
which the Rust code reproduces — see
`Funs.lean::poly_element_intt_layer_generic_loop0_loop0`). -/
def invNttLayerInner (f : Polynomial) (i len start j : Nat) : Polynomial :=
  if j < len then
    let c0   := f[start + j]!
    let c1   := f[start + j + len]!
    let zeta := ζ ^ bitRev 7 i
    let f    := f.set! (start + j)       (c0 + c1)
    let f    := f.set! (start + j + len) (zeta * (c1 - c0))
    invNttLayerInner f i len start (j + 1)
  else f
termination_by len - j

/-- The INTT layer: walks `start` over multiples of `2*len` from 0 to 256,
**decrementing** the twiddle index `i` at each step (the inverse winds the
twiddle indices down from 127 to 1). -/
def invNttLayer (f : Polynomial) (i len start : Nat) (hLen : 0 < len := by simp) :
    Polynomial :=
  if start < 256 then
    let f := invNttLayerInner f i len start 0
    invNttLayer f (i - 1) len (start + 2 * len) hLen
  else f
termination_by 256 - start
decreasing_by omega

/-- The whole inverse NTT (7 layers), **without** the trailing `* 3303`
multiplication that `NTTInv` applies. The Aeneas-extracted
`poly_element_intt` decomposes into these seven layers; the `* 3303` factor
is folded into `poly_element_intt_and_mul_r` via
`INTT_FIXUP_TIMES_RSQR`. -/
def invNtt (f : Polynomial) : Polynomial :=
  let f := invNttLayer f 127   2 0
  let f := invNttLayer f  63   4 0
  let f := invNttLayer f  31   8 0
  let f := invNttLayer f  15  16 0
  let f := invNttLayer f   7  32 0
  let f := invNttLayer f   3  64 0
  let f := invNttLayer f   1 128 0
  f

/-- INTT inverse-butterfly in bang form: at positions `j, j+len`,
upper gets `c0 + c1`, lower gets `zeta * (c1 - c0)` (Gentleman–Sande,
sign-flipped vs the forward butterfly `nttBangButterfly`). -/
def invNttBangButterfly (zeta : Zq) (f : Polynomial) (j len : Nat) : Polynomial :=
  let c0 := f[j]!
  let c1 := f[j + len]!
  (f.set! j (c0 + c1)).set! (j + len) (zeta * (c1 - c0))

/-- Bang-form butterfly bridge: the INTT spec body in bang form (with the
intermediate `t := f[j]!` and sequential sets) equals `invNttBangButterfly`.
The key observation: `(f.set! j x)[j+len]! = f[j+len]!` since `j ≠ j+len`. -/
theorem specForm_bang_eq_invNttBangButterfly
    (zeta : Zq) (f : Polynomial) (j len : Nat) (h_len : 0 < len) :
    (f.set! j (f[j]! + f[j + len]!)).set! (j + len)
        (zeta * ((f.set! j (f[j]! + f[j + len]!))[j + len]! - f[j]!))
      = invNttBangButterfly zeta f j len := by
  have hne : j ≠ j + len := by omega
  rw [Vector.getElem!_set!_ne hne]
  unfold invNttBangButterfly
  rfl

/-- Unfold `invNttLayerInner` one step. -/
theorem invNttLayerInner_unfold (f : Polynomial) (i len start j : Nat) :
    invNttLayerInner f i len start j =
      if j < len then
        let c0   := f[start + j]!
        let c1   := f[start + j + len]!
        let zeta := ζ ^ bitRev 7 i
        let f    := f.set! (start + j)       (c0 + c1)
        let f    := f.set! (start + j + len) (zeta * (c1 - c0))
        invNttLayerInner f i len start (j + 1)
      else f := by
  conv_lhs => rw [invNttLayerInner]

/-- Inner-loop equivalence for INTT: `invNttLayerInner f i len start j` equals
a `forIn'` over `List.range' (start + j) (len - j)` whose body applies the
bang inverse butterfly at position `(k, k + len)`. -/
private theorem invNttLayerInner_eq_forIn (i len start j : Nat) (h_j : j ≤ len)
    (f : Polynomial) :
    invNttLayerInner f i len start j =
    Id.run (forIn' (List.range' (start + j) (len - j)) f (fun k _ p =>
      pure (ForInStep.yield (invNttBangButterfly (ζ ^ bitRev 7 i) p k len)))) := by
  rw [invNttLayerInner_unfold]
  by_cases hlt : j < len
  · simp only [hlt, ite_true]
    have hlen_succ : len - j = (len - (j + 1)) + 1 := by omega
    have h_j' : j + 1 ≤ len := by omega
    rw [hlen_succ, List.range'_succ]
    simp only [List.forIn'_cons, Id.run, pure_bind]
    have ih := invNttLayerInner_eq_forIn i len start (j + 1) h_j'
                  ((f.set! (start + j) (f[start + j]! + f[start + j + len]!)).set!
                     (start + j + len)
                     ((ζ ^ bitRev 7 i) * (f[start + j + len]! - f[start + j]!)))
    show invNttLayerInner _ i len start (j + 1) =
         (forIn' (List.range' (start + (j + 1)) (len - (j + 1)))
             (invNttBangButterfly (ζ ^ bitRev 7 i) f (start + j) len) _ : Id _)
    exact ih
  · simp only [hlt, ite_false]
    have : len - j = 0 := by omega
    rw [this]
    rfl
termination_by len - j

private theorem invNttLayerInner_eq_forIn_zero (i len start : Nat) (f : Polynomial) :
    invNttLayerInner f i len start 0 =
    Id.run (forIn' (List.range' start len) f (fun k _ p =>
      pure (ForInStep.yield (invNttBangButterfly (ζ ^ bitRev 7 i) p k len)))) := by
  have := invNttLayerInner_eq_forIn i len start 0 (Nat.zero_le _) f
  simpa using this

/-- Unfold `invNttLayer` one step. -/
theorem invNttLayer_unfold (f : Polynomial) (i len start : Nat) (hLen : 0 < len) :
    invNttLayer f i len start hLen =
      if start < 256 then
        let f := invNttLayerInner f i len start 0
        invNttLayer f (i - 1) len (start + 2 * len) hLen
      else f := by
  conv_lhs => rw [invNttLayer]

/-- Middle-layer equivalence for INTT: index `i` decrements at each step. -/
private theorem invNttLayer_eq_specForIn (len : Nat) (h_len : 0 < len)
    (K start i_init : Nat) (h_K : K * (2 * len) = 256 - start) (h_start : start ≤ 256)
    (f : Polynomial) :
    Id.run (forIn' (List.range' start K (2 * len))
        (⟨f, i_init⟩ : MProd Polynomial Nat)
        (fun s _ st => do
          let r ← forIn' (List.range' s len) st.fst (fun k _ p =>
            pure (ForInStep.yield
              (invNttBangButterfly (ζ ^ bitRev 7 st.snd) p k len)))
          pure (ForInStep.yield (⟨r, st.snd - 1⟩ : MProd Polynomial Nat)))) =
      (⟨invNttLayer f i_init len start h_len, i_init - K⟩ : MProd Polynomial Nat) := by
  induction K generalizing start i_init f with
  | zero =>
    have h_start_eq : start = 256 := by simp at h_K; omega
    rw [invNttLayer_unfold]
    have hns : ¬ start < 256 := by omega
    simp [hns, List.range'_zero, Id.run]
    rfl
  | succ K' ih =>
    have h_expand : (K' + 1) * (2 * len) = K' * (2 * len) + 2 * len := by ring
    have h_yes : start < 256 := by omega
    have h_start_next : start + 2 * len ≤ 256 := by omega
    have h_next : K' * (2 * len) = 256 - (start + 2 * len) := by omega
    rw [invNttLayer_unfold]
    simp only [h_yes, ite_true]
    rw [List.range'_succ]
    simp only [List.forIn'_cons, Id.run]
    have ih' := ih (start + 2 * len) (i_init - 1) h_next h_start_next
                  (invNttLayerInner f i_init len start 0)
    rw [invNttLayerInner_eq_forIn_zero] at ih'
    simp only [Id.run, bind_pure_comp] at ih'
    have hcount : i_init - (K' + 1) = i_init - 1 - K' := by omega
    rw [hcount]
    have hbridge := invNttLayerInner_eq_forIn_zero i_init len start f
    simp only [Id.run] at hbridge
    rw [hbridge]
    exact ih'

private theorem invNttLayer_eq_forIn (len : Nat) (h_len : 0 < len)
    (K start i_init : Nat) (h_K : K * (2 * len) = 256 - start) (h_start : start ≤ 256)
    (f : Polynomial) :
    forIn' (m := Id) (List.range' start K (2 * len))
      (⟨f, i_init⟩ : MProd Polynomial Nat)
      (fun s _ st => do
        let r ← forIn' (List.range' s len) st.fst
                  (fun k _ p =>
                    pure (ForInStep.yield
                      (invNttBangButterfly (ζ ^ bitRev 7 st.snd) p k len)))
        pure (ForInStep.yield ((⟨r, st.snd - 1⟩ : MProd Polynomial Nat)))) =
    pure (⟨invNttLayer f i_init len start h_len, i_init - K⟩ : MProd Polynomial Nat) := by
  have := invNttLayer_eq_specForIn len h_len K start i_init h_K h_start f
  exact this

/-- The aux-spec `invNtt` matches `NTTInv` *up to the trailing
`* 3303` multiplication* — which is why the Rust function is named
`poly_element_intt_and_mul_r` (it folds the missing factor into the
Montgomery `mul_r` post-processing).

Informal proof: same shape as `ntt_eq`, with the index recursion running
**downward**. The `* 3303` factor in `NTTInv` is the inverse of the
**number of base polynomials** in ML-KEM's *partial* NTT, not the
polynomial degree: `n_base = 128` (since the NTT maps a degree-256
polynomial to 128 length-2 base polynomials over `Z_q[X]/(X² − ζ^{2i+1})`,
i.e., 7 layers of butterflies). Numerically:
`128 · 3303 = 422784 = 127 · 3329 + 1`, so `3303 = 128⁻¹ mod q`.
The 7 layers of `invNttLayer` together produce
`128 · NTTInv(f)` per element, which the `* 3303 = · 128⁻¹` fixup
divides back down to `NTTInv(f)`. -/
theorem invNtt_eq_ntt_inv (f : Polynomial) :
    NTTInv f = (invNtt f) * (3303 : Zq) := by
  unfold NTTInv invNtt
  -- Step 1: convert outer MulRange to explicit list, then to seven nested forIn'.
  simp only [Id.run, Aeneas.MulRange.forIn'_eq_forIn_MulRange,
             show Aeneas.mulRange 256 2 (by decide) 2 (by decide) =
                  [2, 4, 8, 16, 32, 64, 128] from by
               rw [Aeneas.MulRange.mulRange_step _ _ _ _ _ (by decide)]
               rw [Aeneas.MulRange.mulRange_step _ _ _ _ _ (by decide)]
               rw [Aeneas.MulRange.mulRange_step _ _ _ _ _ (by decide)]
               rw [Aeneas.MulRange.mulRange_step _ _ _ _ _ (by decide)]
               rw [Aeneas.MulRange.mulRange_step _ _ _ _ _ (by decide)]
               rw [Aeneas.MulRange.mulRange_step _ _ _ _ _ (by decide)]
               rw [Aeneas.MulRange.mulRange_step _ _ _ _ _ (by decide)]
               rw [Aeneas.MulRange.mulRange_nil _ _ _ _ _ (by decide)],
             List.forIn'_cons, List.forIn'_nil]
  -- Step 2: convert each typed `set` / `[·]` in the spec body to bang form.
  simp only [Vector.set_eq_set!, Vector.Inhabited_getElem_eq_getElem!]
  -- Step 3: convert middle SRRange forIn' to List.range' forIn'.
  simp only [Aeneas.SRRange.forIn'_eq_forIn'_range', Aeneas.SRRange.size]
  -- Step 4: simplify the inner SRRange size to `len`.
  -- See `AeneasExtras.size_step_one_const_len`; replaces seven `show` lines.
  simp only [Symcrust.Properties.MLKEM.AeneasExtras.size_step_one_const_len]
  -- Step 5: simplify the middle SRRange size to `K` per layer.
  simp only [show (256 - 0 + 2 * 2 - 1) / (2 * 2) = 64 from by decide,
             show (256 - 0 + 2 * 4 - 1) / (2 * 4) = 32 from by decide,
             show (256 - 0 + 2 * 8 - 1) / (2 * 8) = 16 from by decide,
             show (256 - 0 + 2 * 16 - 1) / (2 * 16) = 8 from by decide,
             show (256 - 0 + 2 * 32 - 1) / (2 * 32) = 4 from by decide,
             show (256 - 0 + 2 * 64 - 1) / (2 * 64) = 2 from by decide,
             show (256 - 0 + 2 * 128 - 1) / (2 * 128) = 1 from by decide]
  -- Step 6: replace bang spec-body with `invNttBangButterfly`.
  simp only [specForm_bang_eq_invNttBangButterfly _ _ _ _ (by decide : 0 < 2),
             specForm_bang_eq_invNttBangButterfly _ _ _ _ (by decide : 0 < 4),
             specForm_bang_eq_invNttBangButterfly _ _ _ _ (by decide : 0 < 8),
             specForm_bang_eq_invNttBangButterfly _ _ _ _ (by decide : 0 < 16),
             specForm_bang_eq_invNttBangButterfly _ _ _ _ (by decide : 0 < 32),
             specForm_bang_eq_invNttBangButterfly _ _ _ _ (by decide : 0 < 64),
             specForm_bang_eq_invNttBangButterfly _ _ _ _ (by decide : 0 < 128)]
  simp only [pure_bind]
  -- Step 7: fold each layer back via `invNttLayer_eq_forIn` (i_init descends).
  rw [invNttLayer_eq_forIn 2 (by decide) 64 0 127 (by decide) (by decide) f]
  simp only [pure_bind]
  rw [invNttLayer_eq_forIn 4 (by decide) 32 0 63 (by decide) (by decide)]
  simp only [pure_bind]
  rw [invNttLayer_eq_forIn 8 (by decide) 16 0 31 (by decide) (by decide)]
  simp only [pure_bind]
  rw [invNttLayer_eq_forIn 16 (by decide) 8 0 15 (by decide) (by decide)]
  simp only [pure_bind]
  rw [invNttLayer_eq_forIn 32 (by decide) 4 0 7 (by decide) (by decide)]
  simp only [pure_bind]
  rw [invNttLayer_eq_forIn 64 (by decide) 2 0 3 (by decide) (by decide)]
  simp only [pure_bind]
  rw [invNttLayer_eq_forIn 128 (by decide) 1 0 1 (by decide) (by decide)]
  rfl

/-! ## Pointwise NTT-domain multiplication (`MLKEM.MultiplyNTTs`)

Decomposed into per-pair scalar functions for use in
`poly_element_mul_and_accumulate`. -/

def baseCaseMultiply0 (f g : Polynomial) (i : Nat) : Zq :=
  f[2*i]! * g[2*i]! + f[2*i+1]! * g[2*i+1]! * (ζ ^ (2 * bitRev 7 i + 1))

def baseCaseMultiply1 (f g : Polynomial) (i : Nat) : Zq :=
  f[2*i]! * g[2*i+1]! + f[2*i+1]! * g[2*i]!

theorem baseCaseMultiply_eq (f g : Polynomial) (i : Nat) :
    MLKEM.BaseCaseMultiply f[2*i]! f[2*i+1]! g[2*i]! g[2*i+1]!
        (ζ ^ (2 * bitRev 7 i + 1)) =
      (baseCaseMultiply0 f g i, baseCaseMultiply1 f g i) := by
  unfold MLKEM.BaseCaseMultiply baseCaseMultiply0 baseCaseMultiply1
  rfl

/-! Bridge: `MLKEM.MultiplyNTTs` (defined as a 128-step imperative for-loop in
`Spec.MLKEM`) equals a `Vector.ofFn` whose `2i`-th coefficient is
`baseCaseMultiply0 f g i` and whose `2i+1`-th is `baseCaseMultiply1 f g i`.

This is the composition keystone for callers of
`montgomery_reduce_and_add_..._spec`: the latter's post is per-coefficient
in `Vector.ofFn` form; `MultiplyNTTs_eq_ofFn` rewrites the spec-side
`MultiplyNTTs` (used by `PolyMatrix.MulVectorNTT` and friends) into the
same shape so the two compose by `Vector.ofFn`-extensionality. -/

/-- One step of the imperative loop, as a pure function: writes the two
new coefficients at positions `2*i` and `2*i+1`. -/
private def multiplyNTTsBody (f g h : Polynomial) (i : Nat) : Polynomial :=
  (h.set! (2*i) (baseCaseMultiply0 f g i)).set! (2*i+1) (baseCaseMultiply1 f g i)

/-- Recursive form of the loop body running from index `i` up to `128`. -/
private def multiplyNTTsPure (f g h : Polynomial) (i : Nat) : Polynomial :=
  if i < 128 then multiplyNTTsPure f g (multiplyNTTsBody f g h i) (i + 1) else h
termination_by 128 - i

private theorem multiplyNTTsPure_unfold (f g : Polynomial) :
    ∀ x i, multiplyNTTsPure f g x i =
      if i < 128 then multiplyNTTsPure f g (multiplyNTTsBody f g x i) (i + 1) else x := by
  intro x i; conv_lhs => unfold multiplyNTTsPure

/-- Coord-by-coord characterization of `multiplyNTTsPure`. -/
private theorem multiplyNTTsPure_getElem! (f g h : Polynomial) (i j : Nat) (hj : j < 128) :
    (multiplyNTTsPure f g h i)[2 * j]! =
      (if j < i then h[2 * j]! else baseCaseMultiply0 f g j) ∧
    (multiplyNTTsPure f g h i)[2 * j + 1]! =
      (if j < i then h[2 * j + 1]! else baseCaseMultiply1 f g j) := by
  unfold multiplyNTTsPure
  split <;> rename_i hi
  · have hind := multiplyNTTsPure_getElem! f g (multiplyNTTsBody f g h i) (i + 1) j hj
    by_cases hij : j < i
    · simp only [hij, ↓reduceIte]
      have h1 : j < i + 1 := by agrind
      simp only [h1, ↓reduceIte] at hind
      unfold multiplyNTTsBody at hind
      simp_lists at hind ⊢
      exact hind
    · by_cases hij' : j = i
      · subst hij'
        have hlt : ¬ j < j := by agrind
        have hlt' : j < j + 1 := by agrind
        simp only [hlt, ↓reduceIte]
        simp only [hlt', ↓reduceIte] at hind
        unfold multiplyNTTsBody at hind
        simp_lists at hind ⊢
        exact hind
      · have h1 : ¬ j < i := hij
        have h2 : ¬ j < i + 1 := by agrind
        simp only [h1, h2, ↓reduceIte] at hind ⊢
        exact hind
  · have : j < i := by agrind
    simp only [this, ↓reduceIte, and_self]
termination_by 128 - i
decreasing_by agrind

/-- Imperative loop = recursive form. The body unfolding uses the
`Aeneas.SRRange.eq_foldWhile` induction principle. -/
private theorem MultiplyNTTs_eq_multiplyNTTsPure (f g : Polynomial) :
    MLKEM.MultiplyNTTs f g = multiplyNTTsPure f g Polynomial.zero 0 := by
  unfold MLKEM.MultiplyNTTs
  simp only [Vector.set_eq_set!, Vector.Inhabited_getElem_eq_getElem!,
             pure_bind, bind_pure, Id.run,
             forIn'_eq_forIn, Aeneas.SRRange.forIn_eq_forIn_range',
             SRRange.size, Nat.add_one_sub_one, Nat.div_one, Nat.sub_zero,
             List.forIn_pure_yield_eq_foldl]
  rw [show (fun (b : Polynomial) (a : Nat) =>
        (Vector.set! b (2 * a)
          (BaseCaseMultiply f[2 * a]! f[2 * a + 1]! g[2 * a]! g[2 * a + 1]!
            (ζ ^ (2 * bitRev 7 a + 1))).1).set!
          (2 * a + 1)
          (BaseCaseMultiply f[2 * a]! f[2 * a + 1]! g[2 * a]! g[2 * a + 1]!
            (ζ ^ (2 * bitRev 7 a + 1))).2) =
        (fun b a => multiplyNTTsBody f g b a) from rfl]
  simp only [Nat.one_pos, SRRange.foldl_range'_eq_foldWhile, mul_one, Nat.zero_add]
  rw [← SRRange.eq_foldWhile 128 1 Nat.one_pos
        (multiplyNTTsPure f g) (multiplyNTTsBody f g) _ _ (multiplyNTTsPure_unfold f g)]
  rfl

theorem MultiplyNTTs_eq_ofFn (f g : Polynomial) :
    MLKEM.MultiplyNTTs f g =
      Vector.ofFn (fun i : Fin 256 =>
        if i.val % 2 = 0 then baseCaseMultiply0 f g (i.val / 2)
        else baseCaseMultiply1 f g (i.val / 2)) := by
  rw [MultiplyNTTs_eq_multiplyNTTsPure, Polynomial.eq_iff']
  intro i hi
  have hcoord := multiplyNTTsPure_getElem! f g Polynomial.zero 0 i hi
  simp only [not_lt_zero, ↓reduceIte] at hcoord
  rw [hcoord.1, hcoord.2]
  refine ⟨?_, ?_⟩
  · rw [Vector.getElem!_ofFn _ _ (by agrind)]
    simp [Nat.mul_mod_right]
  · rw [Vector.getElem!_ofFn _ _ (by agrind)]
    have h1 : (2 * i + 1) % 2 = 1 := by agrind
    have h2 : (2 * i + 1) / 2 = i := by agrind
    simp [h1, h2]

end Symcrust.Properties.MLKEM.Ntt
