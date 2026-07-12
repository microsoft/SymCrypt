import Mathlib.Data.Nat.Bits
import Mathlib.Data.Nat.Bitwise
import Init.Data.Int.Bitwise.Lemmas
import Mathlib.Data.Int.Bitwise
import Aeneas

/-!
# Bit-reversal for NTT (FIPS 203 §4.3, FIPS 204)

`bitRev n i` reverses the `n` least-significant bits of `i`.
Used by ML-KEM (NTT/NTT⁻¹/MultiplyNTTs) and ML-DSA.
-/

def Nat.bitsn (x n : ℕ) : Vector Bool n := Vector.ofFn fun i => x.testBit i

def Nat.ofBitsList (bits : List Bool) : Nat := @Nat.ofBits bits.length (fun f => bits[f])

/-- Reverse the `n` least-significant bits of `i` (FIPS 203 BitRev₇). -/
def bitRev (n : Nat) (i : Nat) : Nat :=
  let bits := i.bitsn n
  let bits := List.reverse bits.toList
  Nat.ofBitsList bits

#guard List.map (bitRev 2) [0, 1, 2, 3] = [0, 2, 1, 3]
#guard List.map (bitRev 3) [0, 1, 2, 3, 4, 5, 6, 7] = [0, 4, 2, 6, 1, 5, 3, 7]

@[simp]
theorem Nat.ofBitsList_bitsn (x n : ℕ) : Nat.ofBitsList (x.bitsn n).toList  = x % 2^n := by
  apply Nat.eq_of_testBit_eq
  intros j
  simp [ofBitsList, bitsn, Nat.testBit_ofBits]

theorem Nat.bits_append_bit_bodd_div2 (n : Nat) (h : n ≠ 0) :
  (bit n.bodd n.div2).bits = n.bodd :: n.div2.bits := by
  cases h: n.bodd <;> try simp_all only [ne_eq, implies_true, bits_append_bit]
  unfold bit
  simp only [cond_false]

  have := Nat.mod_two_of_bodd n

  have := Nat.bit0_bits (n / 2) (by simp_all only [Bool.toNat_false, ne_eq, Nat.div_eq_zero_iff,
    OfNat.ofNat_ne_zero, not_false_eq_true, Aeneas.Simp.neq_imp, false_or, not_lt]; omega)

  have hDiv : n.div2 = n / 2 := Nat.div2_val n
  rw [hDiv]

  simp_all only [Bool.toNat_false]

-- This belongs upstream in Mathlib.
/-- This is the important reasoning theorem about `bits`, together with `Nat.zero_bits` -/
theorem Nat.bits_bit_decomp {n : Nat} (h : n ≠ 0) :
  n.bits = n.bodd :: n.div2.bits := by
  have hBit := Nat.bit_bodd_div2 n
  conv => lhs; rw [← hBit]
  simp only [Nat.bits_append_bit_bodd_div2 n h]

attribute [-simp] List.getElem!_eq_getElem?_getD

@[simp]
theorem Nat.getElem!_bits (n i : ℕ) : n.bits[i]! = n.testBit i := by
  simp [Nat.testBit_eq_inth]
  by_cases h: i < n.bits.length <;>
  simp_all only [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem, List.getI_eq_default,
    List.getI_eq_getElem, Bool.default_bool, Option.getD_some, not_lt, Option.getD_none,
    List.getElem?_length_le]

@[simp]
theorem Nat.getElem_bits (n i : ℕ) (hi: i < n.bits.length) : n.bits[i] = n.testBit i := by
  have := Nat.getElem!_bits n i
  rw [← this]
  unfold List.instGetElem?NatLtLength
  simp_all only [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem, Bool.default_bool,
    Option.getD_some, List.get!Internal_eq_getElem!]

-- This belongs upstream in Mathlib.
theorem Nat.lt_two_pow_length_bits (n : ℕ) :
  n < 2^n.bits.length := by
  if hn: n = 0 then
    simp only [hn, zero_bits, List.length_nil, pow_zero, lt_one_iff, pos_of_gt]
  else
    have h := Nat.bits_bit_decomp hn
    simp only [h, List.length_cons, gt_iff_lt]
    have := Nat.lt_two_pow_length_bits (n/2)
    have : n < 2 * (2 ^ (n / 2).bits.length) := by omega
    simp only [Nat.div2_val, Nat.pow_add_one']
    omega

@[simp]
theorem Nat.ofBitsList_bits (n : Nat) :
  Nat.ofBitsList n.bits = n := by
  apply Nat.eq_of_testBit_eq
  intros j
  simp [ofBitsList, Nat.testBit_ofBits]
  intro h
  have := Nat.ge_two_pow_of_testBit h
  have := Nat.lt_two_pow_length_bits n
  have hj : 2^j < 2^n.bits.length := by omega
  have := @Nat.pow_lt_pow_iff_right 2 j n.bits.length (by simp)
  rw [this] at hj; clear this
  omega

/-
@[simp]
theorem Nat.ofBitsList_bits (n : Nat) :
  Nat.ofBitsList n.bits = n := by
  if h: n = 0 then
    simp only [ofBitsList, h, zero_bits, List.foldr_nil]
  else
    have hBit := Nat.bit_decomp n
    conv => lhs; rw [← hBit]

    simp only [ofBitsList, Nat.bits_append_bit_bodd_div2 n h, List.foldr_cons]

    have hDiv : n.div2 = n / 2 := Nat.div2_val n
    rw [hDiv]

    have hMod : n.bodd.toNat = n % 2 := by
      rw [← Nat.mod_two_of_bodd]

    have hInd := ofBitsList_bits (n / 2)
    simp only [ofBitsList] at hInd

    cases h:n.bodd <;> simp_all only [Bool.toNat_true, Bool.toNat_false]

@[simp]
theorem Nat.bits_div_two (n : Nat) :
  (n / 2).bits = n.bits.drop 1 := by
  dcases h: n = 0 <;> simp_all only [Nat.zero_div, zero_bits, List.drop_nil, List.drop_one]
  have := Nat.bits_bit_decomp n h
  rw [this]
  simp only [List.tail_cons]
  have hDiv : n.div2 = n / 2 := Nat.div2_val n
  rw [hDiv]

@[simp]
theorem Nat.bits_div_pow (n i : Nat) :
  (n / 2^i).bits = n.bits.drop i := by
  revert n
  induction i <;> intro n
  . simp_all only [pow_zero, Nat.div_one, List.drop_zero]
  . rename_i i hInd
    rw [Nat.pow_add_one]
    rw [← Nat.div_div_eq_div_mul]
    simp only [bits_div_two, List.drop_one]
    rw [hInd]
    simp only [List.tail_drop]-/

/-@[simp]
theorem Nat.bits_shiftRight (n i : Nat) :
  (n >>> i).bits = n.bits.drop i := by
  simp only [shiftRight_eq_div_pow, bits_div_pow]-/

--def toBitsn
