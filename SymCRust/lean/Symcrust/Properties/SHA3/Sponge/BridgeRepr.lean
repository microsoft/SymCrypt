import Symcrust.Properties.SHA3.Basic
import Symcrust.Properties.SHA3.Keccak.Core

/-!
# SHA-3 Sponge Bridge — Representation lemmas

Lightweight bridge between the implementation's lane/array representation
and the spec's bit-vector view. These lemmas are dependencies of the
heavier bit-FC proofs (`absorbByte_bridge`, `squeezeByte_toBits`)
and the math FC `code_toSpec`.

Split out of `Bridge.lean` to lower the per-file elaborator state for
the heavy proofs that live in `Sponge/BridgeBitFC.lean` and
`Sponge/Bridge.lean` (`code_toSpec`).
-/

namespace symcrust.sha3.sha3_impl

open Aeneas Aeneas.Std Spec
open Spec (𝔹 bytesToBits bitsToBytes Bits.toNatLE)
open Spec.SHA3 (b w KECCAK_f SPONGE)
open scoped Spec.Notations

/-! ## Representation bridge lemmas -/

/-- Casting a `U32` to `Usize` preserves the value (since `U32.numBits = 32 ≤
    System.Platform.numBits = Usize.numBits`). Used to extract `lane_idx.val =
    state_index.val / 8` from `step*` outputs in absorb/extract specs. -/
theorem UScalar.cast_u32_to_usize_val (x : U32) :
    (UScalar.cast UScalarTy.Usize x).val = x.val := by
  unfold UScalar.cast
  show (BitVec.setWidth _ x.bv).toNat = x.bv.toNat
  rw [BitVec.toNat_setWidth]
  have h1 : x.bv.toNat < 2 ^ 32 := x.bv.isLt
  have h2 : (2 : Nat) ^ 32 ≤ 2 ^ UScalarTy.Usize.numBits := by
    apply Nat.pow_le_pow_right (by decide)
    show 32 ≤ System.Platform.numBits
    rcases System.Platform.numBits_eq with h | h <;> rw [h]; decide
  have h3 : x.bv.toNat < 2 ^ UScalarTy.Usize.numBits := by omega
  rw [Nat.mod_eq_of_lt h3]

/-- `toLane` distributes over XOR. -/
theorem toLane_xor (a b : U64) :
    toLane (a ^^^ b) = Vector.ofFn fun z => (toLane a)[z] ^^ (toLane b)[z] := by
  apply Vector.ext; intro i hi
  simp only [toLane, Vector.getElem_ofFn]
  change (a.bv ^^^ b.bv).getLsbD i = _
  rw [BitVec.getLsbD_xor]
  simp [Vector.getElem_ofFn, Fin.getElem_fin, BitVec.getLsbD]

/-- `Lanes25.get x y` reads flat index `5*y+x` from the array. -/
private theorem Lanes25.ofArray_get (a : Keccak1600) (x : Fin 5) (y : Fin 5) :
    (Lanes25.ofArray a).get x y = a.val[5 * y.val + x.val]! := by
  fin_cases x <;> fin_cases y <;> simp [Lanes25.ofArray, Lanes25.get]

private theorem Vector.getElem_ofFn_fin {n : Nat} (f : Fin n → α) (i : Fin n) :
    (Vector.ofFn f)[i] = f i := by
  simp [Vector.getElem_ofFn]

theorem toBits_getElem (a : Keccak1600) (i : Fin SHA3.b) :
    (toBits a)[i] = a.val[i.val / SHA3.w]!.bv.getLsbD (i.val % SHA3.w) := by
  simp only [toBits, toState, SHA3.stateToString, Lanes25.toState, toLane,
    Vector.getElem_ofFn, Lanes25.ofArray_get]
  rw [Vector.getElem_ofFn_fin]
  fcongr 2
  have hd : 5 * (i.val / w / 5) + i.val / w % 5 = i.val / w :=
    Nat.div_add_mod (i.val / w) 5
  rw [hd]

/-- Nat-indexed variant of `toBits_getElem`. -/
theorem toBits_getElem' (a : Keccak1600) (i : Nat) (hi : i < SHA3.b) :
    (toBits a)[i] = a.val[i / SHA3.w]!.bv.getLsbD (i % SHA3.w) :=
  toBits_getElem a ⟨i, hi⟩

/-- A Keccak1600 with all lanes zero maps to the all-false bit vector. -/
theorem toBits_allZero (a : Keccak1600) (h : ∀ i : Fin 25, a[i] = 0#u64) :
    toBits a = Vector.replicate b false := by
  ext i hi
  show (toBits a)[(⟨i, hi⟩ : Fin b)] = _
  rw [toBits_getElem]
  simp only [Vector.getElem_replicate]
  have hlt : i / w < 25 := by
    have : i < 1600 := hi
    have hw : (w : Nat) = 64 := rfl
    rw [hw]; scalar_tac
  have hzero : a[(⟨i / w, hlt⟩ : Fin 25)] = 0#u64 := h _
  have ha : a.val[i / w]! = 0#u64 := by
    have hlen : a.val.length = 25 := a.property
    have hlt' : i / w < a.val.length := by rw [hlen]; exact hlt
    have hbridge : a.val[i / w]! = a[(⟨i / w, hlt⟩ : Fin 25)] := by
      rw [getElem!_pos a.val (i / w) hlt']
      rfl
    rw [hbridge]; exact hzero
  simp [ha, BitVec.getLsbD]

/-! ## Byte/bit indexing helpers -/

/-- Helper: `(8*idx + i) / 64 = idx / 8` when `i < 8`. -/
theorem div_step (idx i : Nat) (hi : i < 8) : (8 * idx + i) / 64 = idx / 8 := by
  have hmod : idx % 8 < 8 := Nat.mod_lt _ (by decide)
  have hsmall : 8 * (idx % 8) + i < 64 := by
    have h1 : 8 * (idx % 8) ≤ 8 * 7 := Nat.mul_le_mul_left 8 (Nat.le_of_lt_succ hmod)
    have h2 : 8 * (idx % 8) + i ≤ 8 * 7 + 7 := Nat.add_le_add h1 (Nat.le_of_lt_succ hi)
    exact Nat.lt_of_le_of_lt h2 (by decide)
  have heq : 8 * idx + i = 64 * (idx / 8) + (8 * (idx % 8) + i) := by
    have h := Nat.div_add_mod idx 8
    conv_lhs => rw [show idx = 8 * (idx / 8) + idx % 8 from h.symm]
    ring
  rw [heq, Nat.mul_add_div (by decide : 0 < 64), Nat.div_eq_of_lt hsmall, Nat.add_zero]

/-- Helper: `(8*idx + i) % 64 = 8 * (idx % 8) + i` when `i < 8`. -/
theorem mod_step (idx i : Nat) (hi : i < 8) :
    (8 * idx + i) % 64 = 8 * (idx % 8) + i := by
  have hmod : idx % 8 < 8 := Nat.mod_lt _ (by decide)
  have hsmall : 8 * (idx % 8) + i < 64 := by
    have h1 : 8 * (idx % 8) ≤ 8 * 7 := Nat.mul_le_mul_left 8 (Nat.le_of_lt_succ hmod)
    have h2 : 8 * (idx % 8) + i ≤ 8 * 7 + 7 := Nat.add_le_add h1 (Nat.le_of_lt_succ hi)
    exact Nat.lt_of_le_of_lt h2 (by decide)
  have heq : 8 * idx + i = 64 * (idx / 8) + (8 * (idx % 8) + i) := by
    have h := Nat.div_add_mod idx 8
    conv_lhs => rw [show idx = 8 * (idx / 8) + idx % 8 from h.symm]
    ring
  rw [heq, Nat.mul_add_mod, Nat.mod_eq_of_lt hsmall]

/-- Bit at byte position `8*idx + i` of `toBits a` reads from
    `a.val[idx/8]` at bit `8*(idx%8) + i`. -/
theorem toBits_byte_bit (a : Keccak1600) (idx i : Nat)
    (hi : i < 8) (hb : 8 * idx + i < SHA3.b) :
    (toBits a)[8 * idx + i] = a.val[idx / 8]!.bv.getLsbD (8 * (idx % 8) + i) := by
  rw [toBits_getElem' a (8 * idx + i) hb]
  rw [show SHA3.w = 64 from rfl, div_step idx i hi, mod_step idx i hi]

/-- Pure BV: extracting a byte from a U64 lane via shift+mask+truncate equals
    reading 8 bits at the corresponding offset. -/
private theorem byte_extract_bv (lane : BitVec 64) (k : Nat) :
    ((lane >>> (8 * k)) &&& 255#64).setWidth 8 =
      BitVec.ofFn fun (i : Fin 8) => lane.getLsbD (8 * k + i.val) := by
  apply BitVec.eq_of_getElem_eq
  intro i hi
  simp only [BitVec.getElem_ofFn]
  rw [← BitVec.getLsbD_eq_getElem hi (x := _)]
  rw [BitVec.getLsbD_setWidth, BitVec.getLsbD_and, BitVec.getLsbD_ushiftRight]
  have h255 : (255#64).getLsbD i = decide (i < 8) := by decide +revert
  rw [h255]
  simp [hi]

/-! ## bv_tac helpers (centralized to avoid cross-file `enumToBitVec` clash) -/

/-- `si &&& 7` extracts the low 3 bits, equivalent to `si.val % 8`. -/
theorem and7_val (si : U32) : (si &&& 7#u32).val = si.val % 8 := by bv_tac 32

/-- When `x.val % 8 = 0`, the low-3-bit mask `x &&& 7` is zero.
    Centralised here to avoid cross-file `bv_tac` helper clashes. -/
theorem and7_eq_zero_of_mod8 (x i : U32)
    (h_eq : i.bv = x.bv &&& (7 : BitVec 32)) (hmod : x.val % 8 = 0) :
    i = 0#u32 := by bv_tac 32

/-- state_index &&& 7 ≠ 0, combined with input_block_size % 8 = 0 and ≤, gives strict <. -/
theorem and7_ne_zero_imp_lt (si ibs : U32)
    (h_le : si.val ≤ ibs.val) (h_mod : ibs.val % 8 = 0)
    (h_ne : (si &&& 7#u32) ≠ 0#u32) : si.val < ibs.val := by
  have h1 := and7_val si
  have h2 : si.val % 8 ≠ 0 := by
    intro heq; apply h_ne; exact UScalar.eq_of_val_eq (by simp_scalar)
  scalar_tac

end symcrust.sha3.sha3_impl
