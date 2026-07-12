/-
  Symcrust/Properties/MLKEM/Bridges/ModArithLanes.lean — generic per-lane
  modular-arithmetic cores shared by the SSE2 / AVX2 / NEON ML-KEM gadget
  proofs (`vec128_mod_*`, `mod_*_avx2`, …).

  Every lemma here is **lane-count independent**: it is stated over `BitVec 16`
  or `Nat` for a SINGLE lane, given the `< q` lane bounds. The carrier-specific
  gadget proofs (8-lane `m128`, 16-lane `m256`, NEON) instantiate these cores
  per lane after projecting through `m128.u16x8` / `m256.u16x16` / the NEON
  lane view.

  These lane lemmas are shared here so the SSE2, AVX2, and NEON consumers
  can reuse them without duplication.
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.MontArith

open Aeneas Aeneas.Std Result
open Symcrust Spec.MLKEM
open symcrust

namespace Symcrust.Properties.MLKEM.Bridges.ModArithLanes

theorem mod_add_lane (A B R : _root_.BitVec 16)
    (hA : A.toNat < 3329) (hB : B.toNat < 3329)
    (hR : R = (A + B) -
      (~~~(if (3329#16).toInt > (A + B).toInt then 65535#16 else 0#16) &&& 3329#16)) :
    R.toNat < 3329 ∧
    ((R.toNat : ZMod 3329) = (A.toNat : ZMod 3329) + (B.toNat : ZMod 3329)) := by
  have h3329 : (3329#16 : _root_.BitVec 16).toNat = 3329 := by decide
  have hA' : A < 3329#16 := by rw [_root_.BitVec.lt_def, h3329]; exact hA
  have hB' : B < 3329#16 := by rw [_root_.BitVec.lt_def, h3329]; exact hB
  simp only [gt_iff_lt, ← _root_.BitVec.slt_iff_toInt_lt] at hR
  have hboundbv : R < 3329#16 := by rw [hR]; bv_decide
  have hbound : R.toNat < 3329 := by
    have := _root_.BitVec.lt_def.mp hboundbv; rw [h3329] at this; exact this
  have hbv : R = A + B ∨ R + 3329#16 = A + B := by rw [hR]; bv_decide
  have hABnat : A.toNat + B.toNat < 65536 := by scalar_tac
  refine ⟨hbound, ?_⟩
  rcases hbv with h | h
  · have hRnat : R.toNat = A.toNat + B.toNat := by
      rw [h, _root_.BitVec.toNat_add, Nat.mod_eq_of_lt hABnat]
    rw [hRnat]; push_cast; ring
  · have hRnat : R.toNat + 3329 = A.toNat + B.toNat := by
      have hc := congrArg _root_.BitVec.toNat h
      rw [_root_.BitVec.toNat_add, _root_.BitVec.toNat_add, h3329,
        Nat.mod_eq_of_lt (by scalar_tac), Nat.mod_eq_of_lt hABnat] at hc
      exact hc
    have hcast : (R.toNat : ZMod 3329) = ((A.toNat + B.toNat : ℕ) : ZMod 3329) := by
      have h0 : ((3329 : ℕ) : ZMod 3329) = 0 := by decide
      calc (R.toNat : ZMod 3329)
            = ((R.toNat + 3329 : ℕ) : ZMod 3329) := by push_cast [h0]; ring
        _ = ((A.toNat + B.toNat : ℕ) : ZMod 3329) := by rw [hRnat]
    rw [hcast]; push_cast; ring
theorem mod_sub_lane (A B R : _root_.BitVec 16)
    (hA : A.toNat < 3329) (hB : B.toNat < 3329)
    (hR : R = (A - B) +
      ((if (0#16).toInt > (A - B).toInt then 65535#16 else 0#16) &&& 3329#16)) :
    R.toNat < 3329 ∧
    ((R.toNat : ZMod 3329) = (A.toNat : ZMod 3329) - (B.toNat : ZMod 3329)) := by
  have h3329 : (3329#16 : _root_.BitVec 16).toNat = 3329 := by decide
  have hA' : A < 3329#16 := by rw [_root_.BitVec.lt_def, h3329]; exact hA
  have hB' : B < 3329#16 := by rw [_root_.BitVec.lt_def, h3329]; exact hB
  simp only [gt_iff_lt, ← _root_.BitVec.slt_iff_toInt_lt] at hR
  have hboundbv : R < 3329#16 := by rw [hR]; bv_decide
  have hbound : R.toNat < 3329 := by
    have := _root_.BitVec.lt_def.mp hboundbv; rw [h3329] at this; exact this
  have hbv : R + B = A ∨ R + B = A + 3329#16 := by rw [hR]; bv_decide
  have hRBnat : R.toNat + B.toNat < 65536 := by scalar_tac
  refine ⟨hbound, ?_⟩
  have hkey : (R.toNat : ZMod 3329) + (B.toNat : ZMod 3329) = (A.toNat : ZMod 3329) := by
    rcases hbv with h | h
    · have hn : R.toNat + B.toNat = A.toNat := by
        have hc := congrArg _root_.BitVec.toNat h
        rw [_root_.BitVec.toNat_add, Nat.mod_eq_of_lt hRBnat] at hc; exact hc
      rw [← Nat.cast_add, hn]
    · have hn : R.toNat + B.toNat = A.toNat + 3329 := by
        have hc := congrArg _root_.BitVec.toNat h
        rw [_root_.BitVec.toNat_add, _root_.BitVec.toNat_add, h3329,
          Nat.mod_eq_of_lt hRBnat, Nat.mod_eq_of_lt (by scalar_tac)] at hc
        exact hc
      have h0 : ((3329 : ℕ) : ZMod 3329) = 0 := by decide
      rw [← Nat.cast_add, hn]; push_cast [h0]; ring
  rw [eq_sub_iff_add_eq]; exact hkey

/-- Montgomery divisibility at the Nat level: `A·B + m·q ≡ 0 (mod 2^16)` where
    `m = (A·B·3327) mod 2^16` (companion `1 + 3327·3329 = 169·2^16`). -/
theorem mont_div_nat (A B : Nat) :
    (A * B + (A * B * 3327 % 65536) * 3329) % 65536 = 0 := by
  conv_lhs => rw [Nat.add_mod]
  have hinner : (A * B * 3327 % 65536 * 3329) % 65536 = (A * B * 3327 * 3329) % 65536 := by
    conv_lhs => rw [Nat.mul_mod, Nat.mod_mod_of_dvd _ (dvd_refl 65536), ← Nat.mul_mod]
  rw [hinner, ← Nat.add_mod]
  have h : A * B + A * B * 3327 * 3329 = A * B * 169 * 65536 := by ring
  rw [h]; simp [Nat.mul_mod_left]

/-- The SIMD high/low-split result equals the Montgomery reduction value:
    `mulhi(A·B) + mulhi(m·q) + [m ≠ 0] = (A·B + m·q) / 2^16` (`m` as above). -/
theorem mont_carry_nat (A B : Nat) :
    A * B / 65536 + (A * B * 3327 % 65536) * 3329 / 65536
      + (if A * B * 3327 % 65536 = 0 then 0 else 1)
      = (A * B + (A * B * 3327 % 65536) * 3329) / 65536 := by
  set m := A * B * 3327 % 65536 with hm
  have hdiv : (A * B + m * 3329) % 65536 = 0 := mont_div_nat A B
  have hsum : (A * B % 65536 + m * 3329 % 65536) % 65536 = 0 := by
    rw [← Nat.add_mod]; exact hdiv
  have hrab : A * B % 65536 < 65536 := Nat.mod_lt _ (by decide)
  have hrmq : m * 3329 % 65536 < 65536 := Nat.mod_lt _ (by decide)
  have hAB := Nat.div_add_mod (A * B) 65536
  have hmq := Nat.div_add_mod (m * 3329) 65536
  by_cases hm0 : m = 0
  · simp only [hm0]; grind
  · simp only [hm0, if_neg, not_false_iff]
    have hmlt : m < 65536 := by rw [hm]; exact Nat.mod_lt _ (by decide)
    have hrmq_ne : m * 3329 % 65536 ≠ 0 := by
      intro hz
      have hdvd : (65536 : Nat) ∣ m * 3329 := Nat.dvd_of_mod_eq_zero hz
      have hcop : Nat.Coprime 65536 3329 := by decide
      have hmd : (65536 : Nat) ∣ m := Nat.Coprime.dvd_of_dvd_mul_right hcop hdvd
      have := Nat.le_of_dvd (by grind) hmd
      grind
    -- residue sum is divisible by 65536, positive, and < 2·65536 ⟹ equals 65536
    have hrsum : A * B % 65536 + m * 3329 % 65536 = 65536 := by grind
    grind

/-- Per-lane Montgomery correctness: the reduction value `t = (A·B + m·q)/2^16`
    (`m = A·B·3327 mod 2^16`) is `< 2q` and equals `A·B·R⁻¹` in `Z_q`. -/
theorem mont_mul_lane (A B : Nat) (hA : A < 3329) (hB : B < 3329) :
    (A * B + (A * B * 3327 % 65536) * 3329) / 65536 < 6658 ∧
    (((A * B + (A * B * 3327 % 65536) * 3329) / 65536 : ℕ) : ZMod 3329)
      = (A : ZMod 3329) * (B : ZMod 3329) * Rinv := by
  set m := A * B * 3327 % 65536 with hm_def
  set N := A * B + m * 3329 with hN_def
  have hdvd : (65536 : ℕ) ∣ N := Nat.dvd_of_mod_eq_zero (by rw [hN_def, hm_def]; exact mont_div_nat A B)
  obtain ⟨t, hNt⟩ := hdvd
  have ht : N / 65536 = t := by rw [hNt]; exact Nat.mul_div_cancel_left t (by decide)
  rw [ht]
  have hmle : m ≤ 65535 := by rw [hm_def]; exact Nat.le_of_lt_succ (Nat.mod_lt _ (by decide))
  have hABle : A * B ≤ 3328 * 3328 := Nat.mul_le_mul (by grind) (by grind)
  refine ⟨?_, ?_⟩
  · have hNlt : 65536 * t < 65536 * 6658 := by
      rw [← hNt, hN_def]
      calc A * B + m * 3329 ≤ 3328 * 3328 + 65535 * 3329 :=
              Nat.add_le_add hABle (Nat.mul_le_mul_right _ hmle)
        _ < 65536 * 6658 := by decide
    exact Nat.lt_of_mul_lt_mul_left hNlt
  · have hNcast_q : ((N : ℕ) : ZMod 3329) = (A : ZMod 3329) * (B : ZMod 3329) := by
      rw [hN_def]; push_cast; ring
    have hNcast_R : ((N : ℕ) : ZMod 3329) = (65536 : ZMod 3329) * (t : ZMod 3329) := by
      rw [hNt]; push_cast; ring
    have hR1 : (65536 : ZMod 3329) * Rinv = 1 := by unfold Rinv; decide
    rw [hNcast_R] at hNcast_q
    calc (t : ZMod 3329)
        = (65536 * Rinv) * t := by rw [hR1]; ring
      _ = Rinv * (65536 * t) := by ring
      _ = Rinv * ((A : ZMod 3329) * (B : ZMod 3329)) := by rw [hNcast_q]
      _ = (A : ZMod 3329) * (B : ZMod 3329) * Rinv := by ring

/-- Final canonical reduction lane: for `X ∈ [0, 2q)`, the `mod_sub`-by-`q`
    gadget yields `X mod q` (in `[0, q)`, congruent to `X`). -/
theorem mont_final_lane (X R : _root_.BitVec 16) (hX : X.toNat < 6658)
    (hR : R = (X - 3329#16) +
      ((if (0#16).toInt > (X - 3329#16).toInt then 65535#16 else 0#16) &&& 3329#16)) :
    R.toNat < 3329 ∧ ((R.toNat : ZMod 3329) = (X.toNat : ZMod 3329)) := by
  have h6658 : (6658#16 : _root_.BitVec 16).toNat = 6658 := by decide
  have hX' : X < 6658#16 := by rw [_root_.BitVec.lt_def, h6658]; exact hX
  simp only [gt_iff_lt, ← _root_.BitVec.slt_iff_toInt_lt] at hR
  have h3329 : (3329#16 : _root_.BitVec 16).toNat = 3329 := by decide
  have hbound : R < 3329#16 := by rw [hR]; bv_decide
  have hRlt : R.toNat < 3329 := by
    have := _root_.BitVec.lt_def.mp hbound; rw [h3329] at this; exact this
  refine ⟨hRlt, ?_⟩
  have hcase : R = X ∨ R + 3329#16 = X := by rw [hR]; bv_decide
  rcases hcase with h | h
  · rw [h]
  · have hn : R.toNat + 3329 = X.toNat := by
      have hc := congrArg _root_.BitVec.toNat h
      rw [_root_.BitVec.toNat_add, h3329, Nat.mod_eq_of_lt (by scalar_tac)] at hc
      exact hc
    have h0 : ((3329 : ℕ) : ZMod 3329) = 0 := ZMod.natCast_self 3329
    calc ((R.toNat : ℕ) : ZMod 3329)
        = ((R.toNat + 3329 : ℕ) : ZMod 3329) := by push_cast [h0]; ring
      _ = ((X.toNat : ℕ) : ZMod 3329) := by rw [hn]

/-- No-wrap collapse of the three `add_epi16` lanes in `vec128_mont_mul`:
    `hab ≤ 169`, `hmq ≤ 3328`, mask `tmp2 ∈ {0, 65535}`. -/
theorem mont_res3_collapse (hab hmq tmp2 : Nat)
    (hhab : hab ≤ 169) (hhmq : hmq ≤ 3328) (htmp2 : tmp2 = 65535 ∨ tmp2 = 0) :
    (((hab + 1) % 65536 + tmp2) % 65536 + hmq) % 65536
      = hab + hmq + (if tmp2 = 0 then 1 else 0) := by
  rcases htmp2 with h | h <;> subst h <;> grind

theorem u16_wadd_val (x y : Std.U16) :
    (core.num.U16.wrapping_add x y).val = (x.val + y.val) % 65536 := by
  show (core.num.U16.wrapping_add x y).bv.toNat = _
  rw [core.num.U16.wrapping_add_bv_eq, _root_.BitVec.toNat_add]; rfl

theorem u16_wmul_val (x y : Std.U16) :
    (core.num.U16.wrapping_mul x y).val = (x.val * y.val) % 65536 := by
  show (core.num.U16.wrapping_mul x y).bv.toNat = _
  rw [core.num.U16.wrapping_mul_bv_eq, _root_.BitVec.toNat_mul]; rfl

/-- NEON `mod_add` lane core: the NEON gadget uses the **unsigned** compare
    `vcgeq_u16` (`a+b ≥ q`) + `and`, where the x86 gadget used the signed
    `cmpgt` + `andnot`.  The two are equal on `< q` lanes; this is the NEON form. -/
theorem mod_add_lane_neon (A B R : _root_.BitVec 16)
    (hA : A.toNat < 3329) (hB : B.toNat < 3329)
    (hR : R = (A + B) -
      ((if 3329 ≤ (A + B).toNat then 65535#16 else 0#16) &&& 3329#16)) :
    R.toNat < 3329 ∧
    ((R.toNat : ZMod 3329) = (A.toNat : ZMod 3329) + (B.toNat : ZMod 3329)) := by
  have hcond : (3329 ≤ (A + B).toNat) = (3329#16 ≤ A + B) := by
    rw [_root_.BitVec.le_def]; apply propext; constructor <;> intro h <;> simpa using h
  simp only [hcond] at hR
  have h3329 : (3329#16 : _root_.BitVec 16).toNat = 3329 := by decide
  have hA' : A < 3329#16 := by rw [_root_.BitVec.lt_def, h3329]; exact hA
  have hB' : B < 3329#16 := by rw [_root_.BitVec.lt_def, h3329]; exact hB
  have hboundbv : R < 3329#16 := by rw [hR]; bv_decide
  have hbound : R.toNat < 3329 := by
    have := _root_.BitVec.lt_def.mp hboundbv; rw [h3329] at this; exact this
  have hbv : R = A + B ∨ R + 3329#16 = A + B := by rw [hR]; bv_decide
  have hABnat : A.toNat + B.toNat < 65536 := by scalar_tac
  refine ⟨hbound, ?_⟩
  rcases hbv with h | h
  · have hRnat : R.toNat = A.toNat + B.toNat := by
      rw [h, _root_.BitVec.toNat_add, Nat.mod_eq_of_lt hABnat]
    rw [hRnat]; push_cast; ring
  · have hRnat : R.toNat + 3329 = A.toNat + B.toNat := by
      have hc := congrArg _root_.BitVec.toNat h
      rw [_root_.BitVec.toNat_add, _root_.BitVec.toNat_add, h3329,
        Nat.mod_eq_of_lt (by scalar_tac), Nat.mod_eq_of_lt hABnat] at hc
      exact hc
    have hcast : (R.toNat : ZMod 3329) = ((A.toNat + B.toNat : ℕ) : ZMod 3329) := by
      have h0 : ((3329 : ℕ) : ZMod 3329) = 0 := by decide
      calc (R.toNat : ZMod 3329)
            = ((R.toNat + 3329 : ℕ) : ZMod 3329) := by push_cast [h0]; ring
        _ = ((A.toNat + B.toNat : ℕ) : ZMod 3329) := by rw [hRnat]
    rw [hcast]; push_cast; ring

end Symcrust.Properties.MLKEM.Bridges.ModArithLanes
