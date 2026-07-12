/-
  # Helpers/SampleNttBytes.lean — byte-extract identity for SampleNTT.

  The impl `mlkem.ntt.poly_element_sample_ntt_from_shake128_loop_body_prefix`
  loads two `U16`s from a 3-byte chunk `(c0, c1, c2)` using

      i3 := c0 + 256 * c1        -- low 16 bits, U16 from c0,c1
      i5 := c1 + 256 * c2        -- high 16 bits, U16 from c1,c2
      sample0 := i3 &&& 0x0FFF   -- low 12 bits
      sample1 := i5 >>> 4        -- high 12 bits

  The pure spec (`nttCandidatesOfBytes`) is:

      (sample0, sample1) = (c0 + 256 * (c1 % 16), c1 / 16 + 16 * c2)

  This file proves the pure-Nat / BitVec bridge.

  Used by `Sampling/SampleNTT.lean :: body_prefix.spec`.
-/
import Symcrust.Properties.MLKEM.Basic.Params

open Aeneas Aeneas.Std

namespace Symcrust.Properties.MLKEM.Helpers

/-- `(U16 &&& 0x0FFF).val = U16.val % 4096` — masking with `2^12 - 1`. -/
theorem U16_and_4095_val (i3 : U16) : (i3 &&& 4095#u16).val = i3.val % 4096 := by
  show (i3.bv &&& 4095#u16.bv).toNat = i3.bv.toNat % 4096
  rw [show (4095#u16).bv = 4095#16 from rfl, BitVec.toNat_and]
  show i3.bv.toNat &&& 4095 = i3.bv.toNat % 4096
  rw [show (4095 : Nat) = 2^12 - 1 from rfl, Nat.and_two_pow_sub_one_eq_mod]

/-- Low 12 bits of `c0 + 256 * c1` (with `c0, c1` U8-sized) equal
`c0 + 256 * (c1 % 16)`. -/
theorem mod_4096_concat (b0 b1 : Nat) (hb0 : b0 < 256) (_hb1 : b1 < 256) :
    (b0 + 256 * b1) % 4096 = b0 + 256 * (b1 % 16) := by
  grind

/-- Right-shift by 4 of `c1 + 256 * c2` (with `c1, c2` U8-sized) equals
`c1 / 16 + 16 * c2`. -/
theorem div_16_concat (b1 b2 : Nat) (_hb1 : b1 < 256) (_hb2 : b2 < 256) :
    (b1 + 256 * b2) / 16 = b1 / 16 + 16 * b2 := by
  grind

/-- **Byte-extract identity** for `SampleNTT`: the two candidates derived
from a 3-byte chunk by the impl match `nttCandidatesOfBytes`. -/
theorem sampleNtt_byte_extract
    (c0 c1 c2 : U8) (i3 i5 sample0 sample1 : U16)
    (h_i3 : i3.val = c0.val + 256 * c1.val)
    (h_i5 : i5.val = c1.val + 256 * c2.val)
    (h_s0 : sample0.val = (i3 &&& 4095#u16).val)
    (h_s1 : sample1.val = i5.val >>> 4) :
    sample0.val = c0.val + 256 * (c1.val % 16) ∧
    sample1.val = c1.val / 16 + 16 * c2.val := by
  refine ⟨?_, ?_⟩
  · -- sample0 = c0 + 256 * (c1 % 16)
    rw [h_s0, U16_and_4095_val, h_i3]
    exact mod_4096_concat c0.val c1.val (by scalar_tac) (by scalar_tac)
  · -- sample1 = c1 / 16 + 16 * c2
    rw [h_s1, h_i5, Nat.shiftRight_eq_div_pow]
    show (c1.val + 256 * c2.val) / 16 = c1.val / 16 + 16 * c2.val
    exact div_16_concat c1.val c2.val (by scalar_tac) (by scalar_tac)

end Symcrust.Properties.MLKEM.Helpers
