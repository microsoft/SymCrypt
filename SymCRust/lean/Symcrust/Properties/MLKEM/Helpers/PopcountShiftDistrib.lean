/-
  # Helpers/PopcountShiftDistrib.lean — popcount-mask distributivity helpers.

  The CBD bridges in `Bridges/Cbd.lean` (`popcountPackBridge3`, `popcountPackBridge2`)
  reduce the impl-side popcount-packed sample bits to the spec's per-coefficient
  `samplePolyCbdCoeff`.  The hard kernel is a 32-bit BitVec identity: the
  `r`-bit field of `(raw & M) + ((raw >>> 1) & M) + ...` at position `s` is the
  popcount of `raw`'s bits at the corresponding window.

  We prove the η=3 / η=2 variants of this kernel here, lifted to Nat (the form
  the bridges receive after popcount-folding in `u32` arithmetic).  Each is a
  per-`j` `bv_decide` on `BitVec 32` wrapped with the standard Nat ↔ BV bridge
  (with `raw < 2^32` as the hypothesis the bridges actually have from the
  4-byte LE decomposition of a `Slice U8` window).

  Used only by `Bridges/Cbd.lean`.
-/
import Symcrust.Properties.MLKEM.Basic.Params

open Aeneas Aeneas.Std

-- File-level: default (200K) heartbeats is sufficient since each per-j bv_decide
-- branch is small (4 branches for η=3, 8 for η=2 each on BitVec 32).

namespace Symcrust.Properties.MLKEM.Helpers

/-! ## Lift helper: `b.toNat` ≤ 1 (one-line wrapper for `omega`). -/

private theorem Bool.toNat_le_one (b : Bool) : b.toNat ≤ 1 := by
  rcases b with _ | _ <;> decide

private theorem setWidth_ofBool_toNat (b : Bool) :
    ((BitVec.ofBool b).setWidth 32).toNat = b.toNat := by
  rcases b with _ | _ <;> decide

/-! ## η=3: mask `0x249249`, 3-bit fields, `j ∈ {0,1,2,3}`. -/

/-- For `raw < 2^32` and `j < 4`, the `6j`-th 3-bit field of the η=3
popcount-folded value equals the popcount of the 3-bit window
`[6j, 6j+3)` of `raw`. -/
theorem popcount_eta3_low_nat (raw : Nat) (h_raw : raw < 2^32) (j : Nat) (h_j : j < 4) :
    ((((raw &&& 2396745) + ((raw >>> 1) &&& 2396745) + ((raw >>> 2) &&& 2396745)) >>> (6 * j)) &&& 7 : Nat) =
      (raw.testBit (6*j)).toNat + (raw.testBit (6*j+1)).toNat + (raw.testBit (6*j+2)).toNat := by
  set rawBV : BitVec 32 := BitVec.ofNat 32 raw with hraw
  have h_toNat : rawBV.toNat = raw := by
    show raw % 2^32 = raw; exact Nat.mod_eq_of_lt h_raw
  have h_packed_bv : (raw &&& 2396745) + ((raw >>> 1) &&& 2396745) + ((raw >>> 2) &&& 2396745) =
      ((rawBV &&& 0x249249#32) + ((rawBV >>> 1) &&& 0x249249#32) + ((rawBV >>> 2) &&& 0x249249#32)).toNat := by
    rw [BitVec.toNat_add, BitVec.toNat_add, BitVec.toNat_and, BitVec.toNat_and, BitVec.toNat_and,
        BitVec.toNat_ushiftRight, BitVec.toNat_ushiftRight, h_toNat]
    have h1 : (raw &&& 2396745) ≤ 2396745 := Nat.and_le_right
    have h2 : ((raw >>> 1) &&& 2396745) ≤ 2396745 := Nat.and_le_right
    have h3 : ((raw >>> 2) &&& 2396745) ≤ 2396745 := Nat.and_le_right
    have hm : (0x249249#32).toNat = 2396745 := by decide
    rw [hm, Nat.mod_eq_of_lt (by omega), Nat.mod_eq_of_lt (by omega)]
  rw [h_packed_bv]
  set packed_bv : BitVec 32 :=
    (rawBV &&& 0x249249#32) + ((rawBV >>> 1) &&& 0x249249#32) + ((rawBV >>> 2) &&& 0x249249#32)
  have h_shift : (packed_bv.toNat >>> (6 * j)) &&& 7 = (packed_bv >>> (6 * j) &&& 7#32).toNat := by
    rw [BitVec.toNat_and, BitVec.toNat_ushiftRight]
    have : (7#32).toNat = 7 := by decide
    rw [this]
  rw [h_shift]
  have h_bv : (packed_bv >>> (6 * j) &&& 7#32) =
      (BitVec.ofBool (rawBV.getLsbD (6 * j))).setWidth 32
      + (BitVec.ofBool (rawBV.getLsbD (6 * j + 1))).setWidth 32
      + (BitVec.ofBool (rawBV.getLsbD (6 * j + 2))).setWidth 32 := by
    simp only [packed_bv]
    interval_cases j <;> bv_decide
  rw [h_bv, BitVec.toNat_add, BitVec.toNat_add,
      setWidth_ofBool_toNat, setWidth_ofBool_toNat, setWidth_ofBool_toNat]
  have ha := Bool.toNat_le_one (rawBV.getLsbD (6 * j))
  have hb := Bool.toNat_le_one (rawBV.getLsbD (6 * j + 1))
  have hc := Bool.toNat_le_one (rawBV.getLsbD (6 * j + 2))
  rw [Nat.mod_eq_of_lt (by omega), Nat.mod_eq_of_lt (by omega)]
  rw [show raw.testBit (6 * j) = rawBV.getLsbD (6 * j) by rw [← h_toNat]; exact BitVec.testBit_toNat _,
      show raw.testBit (6 * j + 1) = rawBV.getLsbD (6 * j + 1) by rw [← h_toNat]; exact BitVec.testBit_toNat _,
      show raw.testBit (6 * j + 2) = rawBV.getLsbD (6 * j + 2) by rw [← h_toNat]; exact BitVec.testBit_toNat _]

/-- For `raw < 2^32` and `j < 4`, the `(6j+3)`-th 3-bit field equals the
popcount of the high 3-bit window `[6j+3, 6j+6)` of `raw`. -/
theorem popcount_eta3_high_nat (raw : Nat) (h_raw : raw < 2^32) (j : Nat) (h_j : j < 4) :
    ((((raw &&& 2396745) + ((raw >>> 1) &&& 2396745) + ((raw >>> 2) &&& 2396745)) >>> (6 * j + 3)) &&& 7 : Nat) =
      (raw.testBit (6*j+3)).toNat + (raw.testBit (6*j+4)).toNat + (raw.testBit (6*j+5)).toNat := by
  set rawBV : BitVec 32 := BitVec.ofNat 32 raw with hraw
  have h_toNat : rawBV.toNat = raw := by
    show raw % 2^32 = raw; exact Nat.mod_eq_of_lt h_raw
  have h_packed_bv : (raw &&& 2396745) + ((raw >>> 1) &&& 2396745) + ((raw >>> 2) &&& 2396745) =
      ((rawBV &&& 0x249249#32) + ((rawBV >>> 1) &&& 0x249249#32) + ((rawBV >>> 2) &&& 0x249249#32)).toNat := by
    rw [BitVec.toNat_add, BitVec.toNat_add, BitVec.toNat_and, BitVec.toNat_and, BitVec.toNat_and,
        BitVec.toNat_ushiftRight, BitVec.toNat_ushiftRight, h_toNat]
    have h1 : (raw &&& 2396745) ≤ 2396745 := Nat.and_le_right
    have h2 : ((raw >>> 1) &&& 2396745) ≤ 2396745 := Nat.and_le_right
    have h3 : ((raw >>> 2) &&& 2396745) ≤ 2396745 := Nat.and_le_right
    have hm : (0x249249#32).toNat = 2396745 := by decide
    rw [hm, Nat.mod_eq_of_lt (by omega), Nat.mod_eq_of_lt (by omega)]
  rw [h_packed_bv]
  set packed_bv : BitVec 32 :=
    (rawBV &&& 0x249249#32) + ((rawBV >>> 1) &&& 0x249249#32) + ((rawBV >>> 2) &&& 0x249249#32)
  have h_shift : (packed_bv.toNat >>> (6 * j + 3)) &&& 7 = (packed_bv >>> (6 * j + 3) &&& 7#32).toNat := by
    rw [BitVec.toNat_and, BitVec.toNat_ushiftRight]
    have : (7#32).toNat = 7 := by decide
    rw [this]
  rw [h_shift]
  have h_bv : (packed_bv >>> (6 * j + 3) &&& 7#32) =
      (BitVec.ofBool (rawBV.getLsbD (6 * j + 3))).setWidth 32
      + (BitVec.ofBool (rawBV.getLsbD (6 * j + 4))).setWidth 32
      + (BitVec.ofBool (rawBV.getLsbD (6 * j + 5))).setWidth 32 := by
    simp only [packed_bv]
    interval_cases j <;> bv_decide
  rw [h_bv, BitVec.toNat_add, BitVec.toNat_add,
      setWidth_ofBool_toNat, setWidth_ofBool_toNat, setWidth_ofBool_toNat]
  have ha := Bool.toNat_le_one (rawBV.getLsbD (6 * j + 3))
  have hb := Bool.toNat_le_one (rawBV.getLsbD (6 * j + 4))
  have hc := Bool.toNat_le_one (rawBV.getLsbD (6 * j + 5))
  rw [Nat.mod_eq_of_lt (by omega), Nat.mod_eq_of_lt (by omega)]
  rw [show raw.testBit (6 * j + 3) = rawBV.getLsbD (6 * j + 3) by rw [← h_toNat]; exact BitVec.testBit_toNat _,
      show raw.testBit (6 * j + 4) = rawBV.getLsbD (6 * j + 4) by rw [← h_toNat]; exact BitVec.testBit_toNat _,
      show raw.testBit (6 * j + 5) = rawBV.getLsbD (6 * j + 5) by rw [← h_toNat]; exact BitVec.testBit_toNat _]

/-! ## η=2: mask `0x55555555`, 2-bit fields, `j ∈ {0,…,7}`. -/

/-- For `raw < 2^32` and `j < 8`, the `4j`-th 2-bit field of the η=2
popcount-folded value equals the popcount of the 2-bit window
`[4j, 4j+2)` of `raw`. -/
theorem popcount_eta2_low_nat (raw : Nat) (h_raw : raw < 2^32) (j : Nat) (h_j : j < 8) :
    ((((raw &&& 1431655765) + ((raw >>> 1) &&& 1431655765)) >>> (4 * j)) &&& 3 : Nat) =
      (raw.testBit (4*j)).toNat + (raw.testBit (4*j+1)).toNat := by
  set rawBV : BitVec 32 := BitVec.ofNat 32 raw with hraw
  have h_toNat : rawBV.toNat = raw := by
    show raw % 2^32 = raw; exact Nat.mod_eq_of_lt h_raw
  have h_packed_bv : (raw &&& 1431655765) + ((raw >>> 1) &&& 1431655765) =
      ((rawBV &&& 0x55555555#32) + ((rawBV >>> 1) &&& 0x55555555#32)).toNat := by
    rw [BitVec.toNat_add, BitVec.toNat_and, BitVec.toNat_and, BitVec.toNat_ushiftRight, h_toNat]
    have h1 : (raw &&& 1431655765) ≤ 1431655765 := Nat.and_le_right
    have h2 : ((raw >>> 1) &&& 1431655765) ≤ 1431655765 := Nat.and_le_right
    have hm : (0x55555555#32).toNat = 1431655765 := by decide
    rw [hm, Nat.mod_eq_of_lt (by omega)]
  rw [h_packed_bv]
  set packed_bv : BitVec 32 := (rawBV &&& 0x55555555#32) + ((rawBV >>> 1) &&& 0x55555555#32)
  have h_shift : (packed_bv.toNat >>> (4 * j)) &&& 3 = (packed_bv >>> (4 * j) &&& 3#32).toNat := by
    rw [BitVec.toNat_and, BitVec.toNat_ushiftRight]
    have : (3#32).toNat = 3 := by decide
    rw [this]
  rw [h_shift]
  have h_bv : (packed_bv >>> (4 * j) &&& 3#32) =
      (BitVec.ofBool (rawBV.getLsbD (4 * j))).setWidth 32
      + (BitVec.ofBool (rawBV.getLsbD (4 * j + 1))).setWidth 32 := by
    simp only [packed_bv]
    interval_cases j <;> bv_decide
  rw [h_bv, BitVec.toNat_add, setWidth_ofBool_toNat, setWidth_ofBool_toNat]
  have ha := Bool.toNat_le_one (rawBV.getLsbD (4 * j))
  have hb := Bool.toNat_le_one (rawBV.getLsbD (4 * j + 1))
  rw [Nat.mod_eq_of_lt (by omega)]
  rw [show raw.testBit (4 * j) = rawBV.getLsbD (4 * j) by rw [← h_toNat]; exact BitVec.testBit_toNat _,
      show raw.testBit (4 * j + 1) = rawBV.getLsbD (4 * j + 1) by rw [← h_toNat]; exact BitVec.testBit_toNat _]

/-- For `raw < 2^32` and `j < 8`, the `(4j+2)`-th 2-bit field equals the
popcount of the high 2-bit window `[4j+2, 4j+4)` of `raw`. -/
theorem popcount_eta2_high_nat (raw : Nat) (h_raw : raw < 2^32) (j : Nat) (h_j : j < 8) :
    ((((raw &&& 1431655765) + ((raw >>> 1) &&& 1431655765)) >>> (4 * j + 2)) &&& 3 : Nat) =
      (raw.testBit (4*j+2)).toNat + (raw.testBit (4*j+3)).toNat := by
  set rawBV : BitVec 32 := BitVec.ofNat 32 raw with hraw
  have h_toNat : rawBV.toNat = raw := by
    show raw % 2^32 = raw; exact Nat.mod_eq_of_lt h_raw
  have h_packed_bv : (raw &&& 1431655765) + ((raw >>> 1) &&& 1431655765) =
      ((rawBV &&& 0x55555555#32) + ((rawBV >>> 1) &&& 0x55555555#32)).toNat := by
    rw [BitVec.toNat_add, BitVec.toNat_and, BitVec.toNat_and, BitVec.toNat_ushiftRight, h_toNat]
    have h1 : (raw &&& 1431655765) ≤ 1431655765 := Nat.and_le_right
    have h2 : ((raw >>> 1) &&& 1431655765) ≤ 1431655765 := Nat.and_le_right
    have hm : (0x55555555#32).toNat = 1431655765 := by decide
    rw [hm, Nat.mod_eq_of_lt (by omega)]
  rw [h_packed_bv]
  set packed_bv : BitVec 32 := (rawBV &&& 0x55555555#32) + ((rawBV >>> 1) &&& 0x55555555#32)
  have h_shift : (packed_bv.toNat >>> (4 * j + 2)) &&& 3 = (packed_bv >>> (4 * j + 2) &&& 3#32).toNat := by
    rw [BitVec.toNat_and, BitVec.toNat_ushiftRight]
    have : (3#32).toNat = 3 := by decide
    rw [this]
  rw [h_shift]
  have h_bv : (packed_bv >>> (4 * j + 2) &&& 3#32) =
      (BitVec.ofBool (rawBV.getLsbD (4 * j + 2))).setWidth 32
      + (BitVec.ofBool (rawBV.getLsbD (4 * j + 3))).setWidth 32 := by
    simp only [packed_bv]
    interval_cases j <;> bv_decide
  rw [h_bv, BitVec.toNat_add, setWidth_ofBool_toNat, setWidth_ofBool_toNat]
  have ha := Bool.toNat_le_one (rawBV.getLsbD (4 * j + 2))
  have hb := Bool.toNat_le_one (rawBV.getLsbD (4 * j + 3))
  rw [Nat.mod_eq_of_lt (by omega)]
  rw [show raw.testBit (4 * j + 2) = rawBV.getLsbD (4 * j + 2) by rw [← h_toNat]; exact BitVec.testBit_toNat _,
      show raw.testBit (4 * j + 3) = rawBV.getLsbD (4 * j + 3) by rw [← h_toNat]; exact BitVec.testBit_toNat _]

/-! ## 4-byte little-endian decomposition: `raw.testBit r` for `r < 32`.

`raw = b0 + 256*b1 + 65536*b2 + 16777216*b3` (where each `bi < 256`) is the
standard 4-byte LE word.  Its `r`-th bit is the `(r%8)`-th bit of the
`(r/8)`-th byte. -/

/-- The `r`-th bit of a 4-byte LE-composed word: equals the `(r%8)`-th bit
of byte `r/8`.  Stated for `r < 32` as 4 explicit `if`-branches matching the
LE byte index. -/
theorem testBit_le_word_branches (b0 b1 b2 b3 : Nat)
    (h0 : b0 < 256) (h1 : b1 < 256) (h2 : b2 < 256)
    (r : Nat) (_hr : r < 32) :
    (b0 + 256 * b1 + 65536 * b2 + 16777216 * b3).testBit r =
      (if r < 8 then b0.testBit r
       else if r < 16 then b1.testBit (r - 8)
       else if r < 24 then b2.testBit (r - 16)
       else b3.testBit (r - 24)) := by
  -- Peel off b0: raw = 2^8 * (b1 + 256*b2 + 65536*b3) + b0.
  have h_eq1 : b0 + 256 * b1 + 65536 * b2 + 16777216 * b3 =
      2^8 * (b1 + 256 * b2 + 65536 * b3) + b0 := by ring
  rw [h_eq1, Nat.testBit_two_pow_mul_add _ (by simpa using h0)]
  -- Now check r < 8 branch is closed; recurse on the else.
  by_cases hr0 : r < 8
  · simp only [hr0, if_true]
  · simp only [hr0, if_false]
    -- Now: (b1 + 256*b2 + 65536*b3).testBit (r - 8) = ... else-branch
    have h_eq2 : b1 + 256 * b2 + 65536 * b3 = 2^8 * (b2 + 256 * b3) + b1 := by ring
    rw [h_eq2, Nat.testBit_two_pow_mul_add _ (by simpa using h1)]
    by_cases hr1 : r - 8 < 8
    · have hrlt16 : r < 16 := by omega
      simp only [hr1, if_true, hrlt16, if_true]
    · simp only [hr1, if_false]
      have hrge16 : ¬ r < 16 := by omega
      simp only [hrge16, if_false]
      -- Now: (b2 + 256*b3).testBit (r - 8 - 8)
      have h_eq3 : b2 + 256 * b3 = 2^8 * b3 + b2 := by ring
      rw [h_eq3, Nat.testBit_two_pow_mul_add _ (by simpa using h2)]
      by_cases hr2 : r - 8 - 8 < 8
      · have hrlt24 : r < 24 := by omega
        have heq : r - 8 - 8 = r - 16 := by omega
        simp only [hr2, if_true, hrlt24, if_true]
        rw [heq]
      · simp only [hr2, if_false]
        have hrge24 : ¬ r < 24 := by omega
        simp only [hrge24, if_false]
        have heq : r - 8 - 8 - 8 = r - 24 := by omega
        rw [heq]

end Symcrust.Properties.MLKEM.Helpers
