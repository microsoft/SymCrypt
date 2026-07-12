/-
  ArrayBridge.lean — Bridge between `Aeneas.Std.Array U8 16` and `AES.Block`.

  Pure spec-layer glue: converts a concrete byte array into the FIPS 197 `AES.Block`
  type (`Vector Byte 16`) and back, with round-trip lemmas.
-/
import Aeneas
import Spec.AES.Spec

namespace symcrust.aesgcm

open Aeneas Aeneas.Std Result Spec

/-- Convert an `Array U8 16` to a spec `AES.Block` (= `𝔹 16 = Vector Byte 16`). -/
def arrayToAesBlock (a : Array Std.U8 16#usize) : AES.Block :=
  Vector.ofFn fun (i : Fin 16) => (a.val[i.val]).bv

/- Indexing `arrayToAesBlock` equals the underlying bounded byte access. -/
theorem arrayToAesBlock_index (tag : Array Std.U8 16#usize) (i : Nat) (hi : i < 16) :
    (arrayToAesBlock tag)[(⟨i, hi⟩ : Fin 16)] =
      (tag.val[i]'(by simp [tag.property]; exact hi)).bv := by
  simp [arrayToAesBlock]

/-- Convert a spec `AES.Block` back to an `Array U8 16`. Inverse of `arrayToAesBlock`. -/
def aesBlockToArray (b : AES.Block) : Array Std.U8 16#usize :=
  ⟨(_root_.Array.ofFn fun (i : Fin 16) => (⟨b[i.val]⟩ : Std.U8)).toList, by simp⟩

-- UScalar eta: reconstructing from .bv gives back the original
@[simp] private theorem UScalar.eta {ty : UScalarTy} (x : UScalar ty) :
    (⟨x.bv⟩ : UScalar ty) = x := by cases x; rfl

/-- Round-trip: converting to AES block and back gives the original array. -/
@[simp]
theorem aesBlockToArray_arrayToAesBlock (a : Std.Array U8 16#usize) :
    aesBlockToArray (arrayToAesBlock a) = a := by
  simp only [aesBlockToArray, arrayToAesBlock]
  apply Subtype.ext
  simp only [Vector.getElem_ofFn, _root_.Array.toList_ofFn, UScalar.eta]
  apply List.ext_getElem
  · simp [a.property]
  · intro i h1 h2
    rw [List.getElem_ofFn]

/- Round-trip: converting from AES block and back gives the original block. -/
@[simp]
theorem arrayToAesBlock_aesBlockToArray (b : AES.Block) :
    arrayToAesBlock (aesBlockToArray b) = b := by
  simp only [arrayToAesBlock, aesBlockToArray]
  apply Vector.ext
  intro i hi
  simp only [Vector.getElem_ofFn, _root_.Array.toList_ofFn, List.getElem_ofFn]

/-- Byte-wise XOR of two AES blocks (FIPS-197 §5.1.4 `AddRoundKey`). -/
def blockXor (a b : AES.Block) : AES.Block :=
  Vector.ofFn fun (i : Fin 16) => a[i] ^^^ b[i]

local macro_rules | `(tactic| get_elem_tactic) => `(tactic| first | assumption | grind)

/-- `arrayToAesBlock` of a lane-wise byte XOR is the `blockXor` of the parts. -/
theorem arrayToAesBlock_lanexor {a b r : Array Std.U8 16#usize}
    (h : ∀ k, (hk : k < 16) → r[k] = a[k] ^^^ b[k]) :
    arrayToAesBlock r = blockXor (arrayToAesBlock a) (arrayToAesBlock b) := by
  ext i hi
  have key : r.val[i] = a.val[i] ^^^ b.val[i] := h i hi
  simp only [arrayToAesBlock, blockXor, Vector.getElem_ofFn, Fin.getElem_fin]
  bv_tac 8

end symcrust.aesgcm
