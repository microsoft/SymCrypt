import Spec.MLKEM.Spec

/-!
Properties about the polynomials
-/

open Aeneas

/-!
# Polynomials
-/

namespace Spec.MLKEM

theorem Polynomial.eq_iff {n} (f g : Polynomial n) :
  f = g ↔ ∀ i < 256, f[i]! = g[i]! := by
  simp only [Vector.eq_iff_forall_eq_getElem!]

theorem Polynomial.eq_iff' (f g : Polynomial n) :
  f = g ↔ ∀ i < 128, (f[2 * i]! = g[2 * i]! ∧ f[2 * i + 1]! = g[2 * i + 1]!) := by
  rw [Polynomial.eq_iff]
  constructor <;> intros heq i hi
  . have h0 := heq (2 * i) (by agrind)
    have h1 := heq (2 * i + 1) (by agrind)
    simp only [h0, h1, and_self]
  . have h0 := heq (i / 2) (by agrind)
    have h1 : 2 * (i / 2) = i ∨ 2 * (i / 2) + 1 = i := by agrind
    cases h1 <;> simp_all only

@[simp, simp_lists]
theorem Polynomial.getElem!_add (f g : Polynomial n) (i : Nat) :
  (f + g)[i]! = f[i]! + g[i]! := by
  dcases hi : i < 256
  · show (Vector.zipWith (· + ·) f g)[i]! = f[i]! + g[i]!
    rw [getElem!_pos (Vector.zipWith _ f g) i hi, Vector.getElem_zipWith hi,
        getElem!_pos f i hi, getElem!_pos g i hi]
  · have hge : 256 ≤ i := by agrind
    rw [Vector.getElem!_default (f + g) i hge,
        Vector.getElem!_default f i hge,
        Vector.getElem!_default g i hge]
    unfold default ZMod.inhabited
    simp only [add_zero]

@[simp, simp_lists]
theorem Polynomial.getElem!_sub (f g : Polynomial n) (i : Nat) :
  (f - g)[i]! = f[i]! - g[i]! := by
  dcases hi : i < 256
  · show (Vector.zipWith (· - ·) f g)[i]! = f[i]! - g[i]!
    rw [getElem!_pos (Vector.zipWith _ f g) i hi, Vector.getElem_zipWith hi,
        getElem!_pos f i hi, getElem!_pos g i hi]
  · have hge : 256 ≤ i := by agrind
    rw [Vector.getElem!_default (f - g) i hge,
        Vector.getElem!_default f i hge,
        Vector.getElem!_default g i hge]
    unfold default ZMod.inhabited
    simp only [sub_zero]

@[simp, simp_lists]
theorem Polynomial.getElem!_mul (f : Polynomial n) (x : ZMod n) (i : Nat) :
  (f * x)[i]! = f[i]! * x := by
  obtain ⟨f, hf⟩ := f
  simp only [show ((Vector.mk f hf) * x : Polynomial n)
                  = Polynomial.scalarMul (Vector.mk f hf) x from rfl,
             Polynomial.scalarMul]
  dcases hi : i < 256 <;> simp_lists
  simp only [default, zero_mul]

theorem Polynomial.add_assoc (f g h : Polynomial n) : f + g + h = f + (g + h) := by
  simp only [eq_iff, getElem!_add]; intro i hi; ring

theorem Polynomial.add_comm (f g : Polynomial n) : f + g = g + f := by
  simp only [eq_iff, getElem!_add]; intro i hi; ring

@[simp]
theorem Polynomial.zero_add (f : Polynomial n) : Polynomial.zero n + f = f := by
  rw [eq_iff]
  simp +contextual only [zero, getElem!_add, Vector.getElem!_replicate, _root_.zero_add,
    implies_true]

@[simp]
theorem Polynomial.add_zero (f : Polynomial n) : f + Polynomial.zero n = f := by
  rw [eq_iff]
  simp +contextual only [zero, getElem!_add, Vector.getElem!_replicate, _root_.add_zero,
    implies_true]

@[simp, simp_lists]
theorem Polynomial.zero_getElem! (i : Nat) :
  (Polynomial.zero n)[i]! = 0 := by
  simp [Polynomial.zero]
  by_cases hi: i < 256 <;>
  simp_all only [not_lt, Vector.getElem!_default, Vector.getElem!_replicate, default]

end Spec.MLKEM
