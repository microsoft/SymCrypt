/-
  ML-KEM byte bridges and small loop helpers — sub-file of
  `Properties/MLKEM/Basic`.

  Carries `arrayToSpecBytes` / `sliceToSpecBytes` / `listToSpecBytes` /
  `sliceWindowToSpecBytes` and the dot-notation aliases, plus the
  generic `Vector_get_ofFn` and `List.forIn'_id_invariant{,_indexed}` /
  `forIn'_getElem_indexed` / `forIn'_mprod_snd_indexed` helpers.

  Imports no Mathlib — keep it that way so consumers that only need byte
  bridges (e.g. `Encoding/*`) don't pay the ZMod load cost.
-/
import Symcrust.Code
import Spec.MLKEM.Spec
import Symcrust.Properties.MLKEM.AeneasExtras
import Symcrust.Properties.Axioms.Stdlib
import Symcrust.Properties.SliceToSpec

open Aeneas Aeneas.Std Result
open scoped Spec.Notations

namespace Symcrust.Properties.MLKEM

open Spec
open Spec.MLKEM
open Spec.MLKEM.Bounds
open symcrust

/-! ## Small Vector helpers (public — shared across files)

A few one-line helpers about Lean 4's native `Vector` type that recur in
bridge proofs.  Mathlib's `Vector.get_ofFn` is on `List.Vector` (not the
new `Vector`), so we provide our own. -/

/-- `(Vector.ofFn f).get i = f i`. Sibling to `Vector.getElem_ofFn`
phrased in `Vector.get` form (which is the form `congrArg` produces
after `.get ⟨i, h⟩`). -/
@[grind =]
theorem Vector_get_ofFn {n : Nat} {α : Type*} (f : Fin n → α) (i : Fin n) :
    (Vector.ofFn f).get i = f i := by
  obtain ⟨i, hi⟩ := i; show (Vector.ofFn f)[i] = _; rw [Vector.getElem_ofFn]

/-! ## `forIn'` invariant helpers (public — shared across files)

Public versions of the `forIn'_id_invariant` and `forIn'_getElem_indexed`
helpers from `Spec/AES/Properties.lean`.  These let us reason about
imperative loops in `Id.run do …` form by induction on the iteration
count, without unfolding the full loop. -/

/-- `forIn'` with pure yield in the `Id` monad preserves any invariant `P`. -/
theorem List.forIn'_id_invariant {α β : Type} (xs : List α) (init : β)
    (body : (a : α) → a ∈ xs → β → Id (ForInStep β))
    (P : β → Prop) (hInit : P init)
    (hStep : ∀ a (h : a ∈ xs) b, P b →
      ∃ b', body a h b = pure (ForInStep.yield b') ∧ P b') :
    P (Id.run (forIn' xs init body)) := by
  induction xs generalizing init with
  | nil => exact hInit
  | cons x xs ih =>
    simp only [List.forIn'_cons, Id.run, Bind.bind]
    obtain ⟨b', hb'_eq, hb'_P⟩ := hStep x (.head _) init hInit
    change P (Id.run (body x _ init >>= fun x => match x with
      | .done b => pure b | .yield b => forIn' xs b _))
    rw [hb'_eq]; simp only [Bind.bind, Id.run]
    exact ih b' (fun a' m b => body a' (.tail _ m) b) hb'_P
      (fun a ha b hb => hStep a (.tail _ ha) b hb)

set_option linter.unusedVariables false in -- Lean unused-variable linter false positive
/-- Indexed-invariant variant of `List.forIn'_id_invariant`. The
state can be any type, and the invariant is parameterized by the
loop iteration count. -/
theorem List.forIn'_id_invariant_indexed {α β : Type} :
    ∀ (xs : List α) (init : β)
    (body : (a : α) → a ∈ xs → β → Id (ForInStep β))
    (P : Nat → β → Prop)
    (hInit : P 0 init)
    (hStep : ∀ (k : Nat) (hk : k < xs.length) b, P k b →
      ∀ a (ha : a ∈ xs), a = xs[k]'hk →
      ∃ b', body a ha b = pure (ForInStep.yield b') ∧ P (k + 1) b'),
    P xs.length (Id.run (forIn' xs init body)) := by
  intro xs; induction xs with
  | nil => intro init body P hInit _hStep; exact hInit
  | cons x xs ih =>
    intro init body P hInit hStep
    simp only [List.forIn'_cons, Id.run]
    obtain ⟨b', hb'_eq, hb'_P⟩ := hStep 0 (Nat.zero_lt_succ _) init hInit x (.head _) rfl
    rw [hb'_eq]
    have ih' := ih b' (fun a' m b => body a' (.tail _ m) b) (fun k => P (k + 1)) hb'_P
      (fun k hk b hPk a ha heq => by
        have hk' : k + 1 < (x :: xs).length := by simp; omega
        exact hStep (k + 1) hk' b hPk a (.tail _ ha) (by simp [heq]))
    simpa [List.length_cons, Id.run] using ih'

set_option linter.unusedVariables false in -- Lean unused-variable linter false positive
/-- Indexed-invariant `forIn'_getElem` lemma for vector-state loops. -/
theorem forIn'_getElem_indexed {α : Type} {β : Type} {n : Nat} :
    ∀ (xs : List α) (init : Vector β n)
    (body : (a : α) → a ∈ xs → Vector β n → Id (ForInStep (Vector β n)))
    (i : Nat) (hi : i < n) (val : β)
    (P : Nat → Vector β n → Prop)
    (hInit : P 0 init)
    (hFinal : ∀ dw, P xs.length dw → dw[i] = val)
    (hStep : ∀ (k : Nat) (hk : k < xs.length) b, P k b →
      ∀ a (ha : a ∈ xs), a = xs[k]'hk →
      ∃ b', body a ha b = pure (ForInStep.yield b') ∧ P (k + 1) b'),
    (Id.run (forIn' xs init body))[i] = val := by
  intro xs; induction xs with
  | nil => intro init body i hi val P hInit hFinal _hStep; exact hFinal init hInit
  | cons x xs ih =>
    intro init body i hi val P hInit hFinal hStep
    simp only [List.forIn'_cons, Id.run, Bind.bind]
    obtain ⟨b', hb'_eq, hb'_P⟩ := hStep 0 (Nat.zero_lt_succ _) init hInit x (.head _) rfl
    conv_lhs => arg 1; rw [hb'_eq]
    exact ih b' (fun a' m b => body a' (.tail _ m) b) i hi val (fun k => P (k + 1))
      hb'_P
      (fun dw hP => hFinal dw (by rwa [List.length_cons]))
      (fun k hk b hPk a ha heq => by
        have hk' : k + 1 < (x :: xs).length := by simp; omega
        exact hStep (k + 1) hk' b hPk a (.tail _ ha) (by simp [heq]))

/-- Indexed-invariant `forIn'_getElem` lemma for `MProd Nat (Vector β n)`-state
loops, projecting the value at position `k` from the vector component.

Lean's `do`-notation desugars `let mut a := ...; let mut b := ...; for ... do …`
to `forIn'` on an `MProd Nat (Vector β n)` state — NOT `Prod`.  Use this
lemma when the loop accumulates a scalar shift register and a bit/byte
vector simultaneously (e.g. `ByteEncode`'s inner loop). -/
theorem forIn'_mprod_snd_indexed {α : Type} {β : Type} {n : Nat} :
    ∀ (xs : List α) (init : MProd Nat (Vector β n))
    (body : (a : α) → a ∈ xs → MProd Nat (Vector β n) →
            Id (ForInStep (MProd Nat (Vector β n))))
    (k : Nat) (hk : k < n) (val : β)
    (P : Nat → MProd Nat (Vector β n) → Prop)
    (_hInit : P 0 init)
    (_hFinal : ∀ b, P xs.length b → b.snd[k]'hk = val)
    (_hStep : ∀ (j : Nat) (hj : j < xs.length) (b : MProd Nat (Vector β n)), P j b →
      ∀ a (ha : a ∈ xs), a = xs[j]'hj →
      ∃ b', body a ha b = pure (ForInStep.yield b') ∧ P (j + 1) b'),
    (forIn' xs init body).snd[k]'hk = val := by
  intro xs init body k hk val P hInit hFinal hStep
  exact hFinal _ (List.forIn'_id_invariant_indexed xs init body P hInit hStep)

/-! ## Byte bridges (`Array U8 n` / `Slice U8` → `𝔹 n`)

`𝔹 n = Vector Byte n` (`Byte = UInt8`). We convert via `U8.bv.toUInt8`,
the natural truncation. -/

-- Byte bridges are now in `Symcrust.Properties.SliceToSpec` (imported above).
open Symcrust.Properties

end Symcrust.Properties.MLKEM
