/-
  # Helpers/FastCompressBarrett.lean — Barrett-shift ≡ fastCompress identity.

  The impl `mlkem.ntt.poly_element_compress_and_encode_loop_body_prefix`
  computes, for `1 ≤ d < 12` and `x = src_coeff.val < q`:

      coefficient2 := (x * 2580335) >>> (32 - d)            -- U32
      coefficient3 := coefficient2 + 1
      coefficient4 := coefficient3 >>> 1
      coefficient5 := coefficient4 &&& (2^d - 1)

  The post of `body_prefix.spec` asserts `coefficient5 = fastCompress d x`
  where (Bridges/Encoding.lean):

      fastCompress d x = ((x * 2^d * 2580335 + 2^32) / 2^33) % 2^d

  This file proves the pure-Nat bridge equating the two forms, modulo
  the BitVec / `>>>` ↔ `/` translation that body_prefix's `step*?` provides.

  Used by `Encoding/Compress.lean :: body_prefix.spec`.
-/
import Symcrust.Properties.MLKEM.Basic.Params
import Symcrust.Properties.MLKEM.Bridges.Encoding

open Aeneas Aeneas.Std

namespace Symcrust.Properties.MLKEM.Helpers

/-! ## A — generic `(a/b + 1)/2` identity. -/

/-- `(a / b + 1) / 2 = (a + b) / (2 * b)` for `0 < b`. -/
theorem nat_div_add_one_div_two (a b : Nat) (hb : 0 < b) :
    (a / b + 1) / 2 = (a + b) / (2 * b) := by
  have h1 : (a + b) / b = a / b + 1 := Nat.add_div_right a hb
  have h2 : (a + b) / b / 2 = (a + b) / (b * 2) := Nat.div_div_eq_div_mul (a + b) b 2
  rw [← h1, h2, Nat.mul_comm b 2]

/-! ## B — Barrett-shift identity for `fastCompress`. -/

/-- **Barrett ≡ fastCompress (numerator form).** For `d ≤ 32`,

    (x * 2580335 / 2^(32-d) + 1) / 2 = (x * 2^d * 2580335 + 2^32) / 2^33.

The proof rewrites LHS via `(a/b + 1)/2 = (a+b)/(2b)`, then scales numerator
and denominator by `2^d` via `Nat.mul_div_mul_left`, using `2^d * 2^(32-d) = 2^32`
and `2^d * (2 * 2^(32-d)) = 2^33`. -/
theorem barrett_shift_eq_fastCompress_num (d x : Nat) (hd : d ≤ 32) :
    (x * 2580335 / 2 ^ (32 - d) + 1) / 2 =
      (x * 2 ^ d * 2580335 + 2 ^ 32) / 2 ^ 33 := by
  have hB_pos : 0 < 2 ^ (32 - d) := Nat.two_pow_pos _
  have hPd_pos : 0 < 2 ^ d := Nat.two_pow_pos _
  -- Step 1: rewrite LHS as a single division.
  rw [nat_div_add_one_div_two (x * 2580335) (2 ^ (32 - d)) hB_pos]
  -- Goal: (x*2580335 + 2^(32-d)) / (2 * 2^(32-d)) = (x*2^d*2580335 + 2^32) / 2^33.
  -- Step 2: scale numerator & denominator on LHS by 2^d.
  have h_scale := Nat.mul_div_mul_left
                    (x * 2580335 + 2 ^ (32 - d))
                    (2 * 2 ^ (32 - d))
                    hPd_pos
  rw [← h_scale]
  -- Goal: (2^d * (x*2580335 + 2^(32-d))) / (2^d * (2 * 2^(32-d))) =
  --       (x*2^d*2580335 + 2^32) / 2^33.
  -- Reduce both numerator and denominator algebraically.
  have hpow32 : 2 ^ d * 2 ^ (32 - d) = 2 ^ 32 := by
    rw [← Nat.pow_add]; fcongr 1; omega
  have h_num_eq : 2 ^ d * (x * 2580335 + 2 ^ (32 - d)) = x * 2 ^ d * 2580335 + 2 ^ 32 := by
    rw [Nat.mul_add, hpow32]; ring
  have h_den_eq : 2 ^ d * (2 * 2 ^ (32 - d)) = 2 ^ 33 := by
    have : 2 ^ d * (2 * 2 ^ (32 - d)) = 2 * (2 ^ d * 2 ^ (32 - d)) := by ring
    rw [this, hpow32, show (33 : Nat) = 32 + 1 from rfl, Nat.pow_add, Nat.pow_one]
    ring
  rw [h_num_eq, h_den_eq]

/-- **Barrett ≡ fastCompress (mod form, the body_prefix shape).** For `1 ≤ d < 12`,

    ((x * 2580335 / 2^(32-d) + 1) / 2) % 2^d = fastCompress d x.

This is the form `body_prefix.spec`'s `step*?` leaves (after lowering
the U32 `>>>` to `/` via `UScalar.ushr_val` and the `&&& (2^d - 1)` mask
to `% 2^d` via `Nat.and_two_pow_sub_one_eq_mod`). -/
theorem barrett_shift_eq_fastCompress (d x : Nat) (hd : 1 ≤ d ∧ d < 12) :
    ((x * 2580335 / 2 ^ (32 - d) + 1) / 2) % 2 ^ d
      = Symcrust.Properties.MLKEM.Bridges.fastCompress d x := by
  unfold Symcrust.Properties.MLKEM.Bridges.fastCompress
  rw [barrett_shift_eq_fastCompress_num d x (by omega)]

/-! ## C — bitwise mask ≡ mod-power-of-two. -/

/-- `n &&& (2^d - 1) = n % 2^d`. The body_prefix uses this to bridge the
final `coefficient4 &&& (i5 - 1)` (where `i5 = 1 <<< d = 2^d`) to a
modular reduction. -/
theorem nat_and_two_pow_sub_one (n d : Nat) :
    n &&& (2 ^ d - 1) = n % 2 ^ d := by
  refine Nat.eq_of_testBit_eq (fun i => ?_)
  rw [Nat.testBit_and, Nat.testBit_mod_two_pow, Nat.testBit_two_pow_sub_one]
  by_cases hi : i < d
  · simp [hi]
  · simp [hi]

end Symcrust.Properties.MLKEM.Helpers
