/-
  Shared byte-bridge definitions and dot-notation aliases.
  The verified primitives import this file
  instead of defining their own copies.
-/
import Symcrust.Code
import Spec.Defs

open Aeneas Aeneas.Std
open Spec

namespace Symcrust.Properties

/-- Convert a Rust `Array U8 n` to a spec `𝔹 n` byte vector. -/
def arrayToSpecBytes {n : Usize} (a : Array U8 n) : 𝔹 (n : ℕ) :=
  Vector.ofFn fun (i : Fin (n : ℕ)) =>
    (a.val[i.val]'(by have := a.property; grind)).bv

/-- Convert a Rust `Slice U8` of length `n` to a spec `𝔹 n` byte vector. -/
def sliceToSpecBytes (s : Slice U8) (n : ℕ) (h : s.length = n := by agrind) : 𝔹 n :=
  Vector.ofFn fun (i : Fin n) =>
    (s.val[i.val]'(by simp [h])).bv

/-- `sliceToSpecBytes` does not depend on the length proof (proof irrelevance). -/
theorem sliceToSpecBytes_proof_irrel {s : Slice U8} {n : ℕ} (h1 h2 : s.length = n) :
    sliceToSpecBytes s n h1 = sliceToSpecBytes s n h2 := rfl

/-- Convert a window `[offset, offset + n)` of a Rust `Slice U8` to `𝔹 n`. -/
def sliceWindowToSpecBytes (s : Slice U8) (offset n : ℕ)
    (h : offset + n ≤ s.length) : 𝔹 n :=
  Vector.ofFn fun (i : Fin n) =>
    (s.val[offset + i.val]'(by have := i.isLt; grind)).bv

/-- Convert a `List Byte` of length `n` to a spec `𝔹 n` byte vector. -/
def listToSpecBytes (src : List Byte) (n : ℕ) (h : src.length = n := by agrind) : 𝔹 n :=
  Vector.ofFn fun (i : Fin n) =>
    src[i.val]'(by simp [h])

/-- Two slices with the same `.val` produce the same `sliceToSpecBytes`. -/
theorem sliceToSpecBytes_val_eq {s₁ s₂ : Slice U8} {n : ℕ}
    {h₁ : s₁.length = n} {h₂ : s₂.length = n}
    (heq : s₁.val = s₂.val) :
    sliceToSpecBytes s₁ n h₁ = sliceToSpecBytes s₂ n h₂ := by
  unfold sliceToSpecBytes
  congr 1; funext i; simp [heq]

end Symcrust.Properties

/-! ### Utility lemmas -/

open Symcrust.Properties

/-- `Vector.cast` of `sliceToSpecBytes s s.length` equals `sliceToSpecBytes s n`
when `s.length = n`. Both are `Vector.ofFn` with the same body. -/
@[simp]
theorem sliceToSpecBytes_cast_eq {s : Slice U8} {n : ℕ}
    (h_eq : s.length = n) (h_self : s.length = s.length := rfl) :
    Vector.cast h_eq (sliceToSpecBytes s s.length h_self) =
      sliceToSpecBytes s n h_eq := by
  ext i hi
  simp [sliceToSpecBytes, Vector.getElem_cast, Vector.getElem_ofFn]

/-- `sliceToSpecBytes s m` cast to `𝔹 n` equals `sliceToSpecBytes s n`. -/
@[simp]
theorem sliceToSpecBytes_cast_eq' {s : Slice U8} {m n : ℕ}
    (h_m : s.length = m) (h_n : s.length = n) (h_eq : m = n) :
    Vector.cast h_eq (sliceToSpecBytes s m h_m) =
      sliceToSpecBytes s n h_n := by
  subst h_eq; rfl

/-- `(sliceToSpecBytes s s.length).toArray.toList = s.val.map (·.bv)`. -/
theorem sliceToSpecBytes_toArray_toList_eq (s : Slice U8) :
    (sliceToSpecBytes s s.length).toArray.toList = s.val.map (·.bv) := by
  simp only [sliceToSpecBytes]; simp

/-- `(sliceToSpecBytes s s.length).toList = s.val.map (·.bv)`. -/
theorem sliceToSpecBytes_toList_eq (s : Slice U8) :
    (sliceToSpecBytes s s.length).toList = s.val.map (·.bv) := by
  simp only [sliceToSpecBytes]; simp [Vector.toList_ofFn]

/-- `sliceToSpecBytes` of `Array.to_slice` equals `arrayToSpecBytes`
(when given the matching size). -/
theorem sliceToSpecBytes_to_slice_eq {n : Usize} (a : Array U8 n)
    (h : (a.to_slice).length = n.val) :
    sliceToSpecBytes a.to_slice n.val h = arrayToSpecBytes a := by
  simp [sliceToSpecBytes, arrayToSpecBytes, Array.to_slice]

/-- `(sliceToSpecBytes s s.length).toList` simplified via `@[simp]`. -/
@[simp] theorem sliceToSpecBytes_toList (s : Slice U8) :
    (sliceToSpecBytes s s.length).toList = s.val.map (·.bv) := by
  unfold sliceToSpecBytes; simp [Vector.toList_ofFn]

/-- Two `sliceToSpecBytes` at the same `n` are equal iff the underlying
`.val` lists are equal. -/
theorem sliceToSpecBytes_eq_iff_val_eq {n : Nat} (s1 s2 : Slice U8)
    (h1 : s1.length = n) (h2 : s2.length = n) :
    sliceToSpecBytes s1 n h1 = sliceToSpecBytes s2 n h2 ↔ s1.val = s2.val := by
  subst h1
  constructor
  · intro h
    have h_len : s1.val.length = s2.val.length := by
      have := h2; simp [Slice.length] at this; omega
    apply List.ext_getElem h_len
    intro i hi1 hi2
    have h_eq : (sliceToSpecBytes s1 s1.length)[i]'hi1 =
        (sliceToSpecBytes s2 s1.length h2)[i]'hi1 := by rw [h]
    simp [sliceToSpecBytes, Vector.getElem_ofFn] at h_eq
    grind
  · intro h; ext i hi; simp [sliceToSpecBytes, Vector.getElem_ofFn, h]

/-- `sliceToSpecBytes` of a `List.drop` sub-slice equals `sliceWindowToSpecBytes`
on the parent. -/
theorem sliceToSpecBytes_drop_eq_sliceWindow
    (parent s : Slice U8) (off n : ℕ)
    (h_val : s.val = List.drop off parent.val)
    (h_s_len : s.length = n)
    (h_window : off + n ≤ parent.length) :
    sliceToSpecBytes s n h_s_len
      = sliceWindowToSpecBytes parent off n h_window := by
  unfold sliceToSpecBytes sliceWindowToSpecBytes
  apply Vector.ext
  intro i hi
  simp only [Vector.getElem_ofFn]
  congr 1
  have hi_s : i < s.val.length := by simp [Slice.length] at h_s_len; omega
  have h_drop_idx : i < (List.drop off parent.val).length := by
    rw [List.length_drop]
    have : parent.val.length = parent.length := rfl
    omega
  have h1 : s.val[i]'hi_s = (List.drop off parent.val)[i]'h_drop_idx :=
    getElem_congr_coll h_val
  rw [h1, List.getElem_drop]

/-! ### Dot-notation aliases -/

abbrev _root_.Aeneas.Std.Array.toSpec {n : Usize} (a : Array U8 n) : 𝔹 (n : ℕ) :=
  Symcrust.Properties.arrayToSpecBytes a

abbrev _root_.Aeneas.Std.Slice.toSpec (s : Slice U8) (n : ℕ := s.length)
    (h : s.length = n := by agrind) : 𝔹 n :=
  Symcrust.Properties.sliceToSpecBytes s n h

abbrev _root_.Aeneas.Std.Slice.toSpecWindow (s : Slice U8) (offset n : ℕ)
    (h : offset + n ≤ s.length) : 𝔹 n :=
  Symcrust.Properties.sliceWindowToSpecBytes s offset n h

/- Auxiliary lemmas for lifting `setSlice!` through `sliceToSpecBytes` / `sliceWindowToSpecBytes`. -/

/-- `sliceWindowToSpecBytes` is unchanged by a non-overlapping `setSlice!` that starts
    strictly after the window's end. -/
theorem sliceWindowToSpecBytes_setSlice!_prefix
    (s : Slice U8) (new : List U8) (pos offset n : ℕ)
    (h_end_le_pos : offset + n ≤ pos)
    (h_window_old : offset + n ≤ s.length)
    (h_window_new : offset + n ≤ (s.setSlice! pos new).length) :
    sliceWindowToSpecBytes (s.setSlice! pos new) offset n h_window_new
    = sliceWindowToSpecBytes s offset n h_window_old := by
  apply Vector.ext; intro r h_r
  simp only [sliceWindowToSpecBytes, Vector.getElem_ofFn]
  congr 1
  simp only [Slice.setSlice!]
  have h_lt_pos : offset + r < pos := by omega
  have := List.getElem!_setSlice!_prefix s.val new pos (offset + r) h_lt_pos
  simp_lists at this ⊢

/-- Bytes in the `setSlice!` region `[pos, pos + n)` come from `new`.
    Stated in terms of `sliceWindowToSpecBytes` and `sliceToSpecBytes`. -/
theorem sliceWindowToSpecBytes_setSlice!_middle
    (s : Slice U8) (s3 : Slice U8) (pos n : ℕ)
    (h_s3_len : s3.length = n)
    (h_pos_fit : pos + n ≤ s.length)
    (h_window : pos + n ≤ (s.setSlice! pos s3.val).length) :
    sliceWindowToSpecBytes (s.setSlice! pos s3.val) pos n h_window
    = sliceToSpecBytes s3 n h_s3_len := by
  apply Vector.ext; intro r h_r
  simp only [sliceWindowToSpecBytes, sliceToSpecBytes, Vector.getElem_ofFn]
  congr 1
  simp only [Slice.setSlice!]
  have := List.getElem!_setSlice!_middle s.val s3.val pos (pos + r)
    ⟨by omega, by simp [Slice.length] at h_s3_len; omega,
     by simp [Slice.length, List.length_setSlice!] at *; omega⟩
  simp only [Nat.add_sub_cancel_left] at this
  simp_lists at this ⊢

/-- Chain two getElem! equalities: if `output2.val[idx]! = imb.val[idx]!`
    and `imb.val[idx]! = c_tilde.val[idx]!`, then `output2.val[idx]! = c_tilde.val[idx]!`. -/
theorem getElem!_chain {α : Type} [Inhabited α] (l1 l2 l3 : List α) (idx : ℕ)
    (h1 : l1[idx]! = l2[idx]!) (h2 : l2[idx]! = l3[idx]!) :
    l1[idx]! = l3[idx]! := h1.trans h2
