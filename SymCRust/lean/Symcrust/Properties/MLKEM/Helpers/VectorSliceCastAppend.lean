/-
  # Helpers/VectorSliceCastAppend.lean

  Small isolated helper for the `slice 0 N (cast h (a ++ b ++ c ++ d))`
  collapse that appears in `KeyGen.lean`'s Conjunct-4 obligation
  (`keySEncoded = dkPKE prefix`).

  ## Why isolated?

  Inlining the obvious closing chain
  ```
  rw [show ((K_PKE.KeyGen …).2 ‖ … ‖ … ‖ …) = (K_PKE.KeyGen …).2 ++ (… ++ … ++ …) from rfl]
  simp only [Spec.slice, Vector.getElem_ofFn, Vector.getElem_cast, Nat.zero_add]
  exact Vector.getElem_append_left hdk
  ```
  inside `KeyGen.lean` times out at 4M heartbeats because the `‖`-chain
  repeats the large `K_PKE.KeyGen params (tape_random.readBytes 32).1`
  term four times and the kernel descends into it during the
  `‖ ↔ ++` head reduction.

  The fix is mechanical: prove the slice/cast/append identity
  **once**, in a small file where every relevant term is a free
  variable, then `apply` it at the call site.  The kernel does not
  have to whnf the large terms — it only needs to unify with the
  helper's universally-quantified `a b c d` parameters.

  ## Naming

  `cast_slice_eq_cast_of_append₄`: from a cast of a 4-way `Vector.append`,
  taking a prefix slice of length matching the first component collapses
  to a cast of that first component.  The "₄" suffix is for the 4
  components (`dkPKE ‖ ek ‖ Hek ‖ z` in the call site).
-/

import Spec.Defs

namespace Symcrust.Properties.MLKEM.Helpers

open Spec

/-- Slice of a cast of an append of 4 vectors: the length-`a.size`
prefix collapses to `a`. -/
theorem cast_slice_eq_of_append₄
    {α : Type*}
    {na nb nc nd m : ℕ}
    (a : Vector α na) (b : Vector α nb) (c : Vector α nc) (d : Vector α nd)
    (h_total : na + nb + nc + nd = m)
    (h_pref : 0 + na ≤ m)
    :
    Spec.slice (Vector.cast h_total (((a ++ b) ++ c) ++ d)) 0 na h_pref = a := by
  apply Vector.ext
  intro i hi
  simp only [Spec.slice, Vector.getElem_ofFn, Vector.getElem_cast, Nat.zero_add]
  have hi_ab : i < na + nb := by omega
  have hi_abc : i < na + nb + nc := by omega
  rw [Vector.getElem_append_left (hi := hi_abc)]
  rw [Vector.getElem_append_left (hi := hi_ab)]
  rw [Vector.getElem_append_left (hi := hi)]

/-- Slice of a cast of a 4-way append: the second component `b` at
offset `na`, length `nb`. -/
theorem cast_slice_eq_of_append₄_mid
    {α : Type*}
    {na nb nc nd m : ℕ}
    (a : Vector α na) (b : Vector α nb) (c : Vector α nc) (d : Vector α nd)
    (h_total : na + nb + nc + nd = m)
    (h_bound : na + nb ≤ m)
    :
    Spec.slice (Vector.cast h_total (((a ++ b) ++ c) ++ d)) na nb h_bound = b := by
  apply Vector.ext
  intro i hi
  simp only [Spec.slice, Vector.getElem_ofFn, Vector.getElem_cast]
  have hi_ab : na + i < na + nb := by omega
  have hi_abc : na + i < na + nb + nc := by omega
  rw [Vector.getElem_append_left (hi := hi_abc)]
  rw [Vector.getElem_append_left (hi := hi_ab)]
  rw [Vector.getElem_append_right (hi := by omega)]
  fcongr 1; omega

/-- Slice of a cast of a 4-way append: the third component `c` at
offset `off = na + nb`, length `nc`. The explicit `off` argument
makes the call site usable when the offset is presented in a
non-`na + nb` arithmetic form (e.g., `768·k + 32` for the
ML-KEM decapsulation key's hash-slot offset). -/
theorem cast_slice_eq_of_append₄_third
    {α : Type*}
    {na nb nc nd m : ℕ}
    (a : Vector α na) (b : Vector α nb) (c : Vector α nc) (d : Vector α nd)
    (h_total : na + nb + nc + nd = m)
    (off : ℕ) (h_off : off = na + nb)
    (h_bound : off + nc ≤ m)
    :
    Spec.slice (Vector.cast h_total (((a ++ b) ++ c) ++ d)) off nc h_bound = c := by
  subst h_off
  apply Vector.ext
  intro i hi
  simp only [Spec.slice, Vector.getElem_ofFn, Vector.getElem_cast]
  have hi_abc : (na + nb) + i < na + nb + nc := by omega
  rw [Vector.getElem_append_left (hi := hi_abc)]
  rw [Vector.getElem_append_right (hi := by omega)]
  fcongr 1; omega

/-- Slice of a cast of a 4-way append: the fourth component `d` at
offset `off = na + nb + nc`, length `nd`. The explicit `off` argument
makes the call site usable when the offset is presented in a
non-`na + nb + nc` arithmetic form (e.g., `768·k + 64` for the
ML-KEM decapsulation key's private-random slot offset). -/
theorem cast_slice_eq_of_append₄_fourth
    {α : Type*}
    {na nb nc nd m : ℕ}
    (a : Vector α na) (b : Vector α nb) (c : Vector α nc) (d : Vector α nd)
    (h_total : na + nb + nc + nd = m)
    (off : ℕ) (h_off : off = na + nb + nc)
    (h_bound : off + nd ≤ m)
    :
    Spec.slice (Vector.cast h_total (((a ++ b) ++ c) ++ d)) off nd h_bound = d := by
  subst h_off
  apply Vector.ext
  intro i hi
  simp only [Spec.slice, Vector.getElem_ofFn, Vector.getElem_cast]
  rw [Vector.getElem_append_right (hi := by omega)]
  fcongr 1; omega

end Symcrust.Properties.MLKEM.Helpers

namespace Symcrust.Properties.MLKEM.Helpers

/-- Slice of a cast of a 2-way append: the length-`na` prefix collapses to `a`.
Used for `keyEncodedTPrefix` ↔ `ByteEncode 12 t̂` bridge in `K_PKE.KeyGen`'s
`ekPKE = (ByteEncode 12 t̂ ‖ ρ).cast _`. -/
theorem cast_slice_eq_of_append₂_prefix
    {α : Type*}
    {na nb m : ℕ}
    (a : Vector α na) (b : Vector α nb)
    (h_total : na + nb = m)
    (h_bound : 0 + na ≤ m)
    :
    Spec.slice (Vector.cast h_total (a ++ b)) 0 na h_bound = a := by
  apply Vector.ext
  intro i hi
  simp only [Spec.slice, Vector.getElem_ofFn, Vector.getElem_cast, Nat.zero_add]
  rw [Vector.getElem_append_left (hi := hi)]

/-- Slice of a cast of a 2-way append: the length-`nb` suffix at offset `na`
collapses to `b`.  Used for `public_seed.toSpec` ↔ `ρ` bridge. -/
theorem cast_slice_eq_of_append₂_suffix
    {α : Type*}
    {na nb m : ℕ}
    (a : Vector α na) (b : Vector α nb)
    (h_total : na + nb = m)
    (off : ℕ) (h_off : off = na)
    (h_bound : off + nb ≤ m)
    :
    Spec.slice (Vector.cast h_total (a ++ b)) off nb h_bound = b := by
  subst h_off
  apply Vector.ext
  intro i hi
  simp only [Spec.slice, Vector.getElem_ofFn, Vector.getElem_cast]
  rw [Vector.getElem_append_right (hi := by omega)]
  fcongr 1; omega

/-- Concatenation of a vector's `[0, a)` and `[a, a+b)` slices recovers the
original vector (up to a `Vector.cast` over `a + b = n`).  Used for Key
Residual E in `case ekhash`: collapses `slice ekPKE 0 (384·k) ‖ slice
ekPKE (384·k) 32` back to `ekPKE` after both halves have been
characterised. -/
theorem slice_append_slice_self
    {α : Type*} {n : ℕ} (v : Vector α n) (a b : ℕ) (h_ab : a + b = n)
    (h_a : 0 + a ≤ n := by omega) (h_b : a + b ≤ n := by omega) :
    Spec.slice v 0 a h_a ++ Spec.slice v a b h_b = v.cast h_ab.symm := by
  apply Vector.ext
  intro i hi
  simp only [Spec.slice, Vector.getElem_cast, Nat.zero_add]
  by_cases h : i < a
  · rw [Vector.getElem_append_left (hi := h)]
    simp
  · rw [Vector.getElem_append_right hi (by omega)]
    simp; fcongr 1; omega

end Symcrust.Properties.MLKEM.Helpers
