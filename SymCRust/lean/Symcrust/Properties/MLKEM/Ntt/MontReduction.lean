/-
  # Ntt/MontReduction.lean — pure-math Montgomery reduction theory.

  Defines `mont_reduce q R minus_q_minus_1 a` (the abstract Montgomery
  reduction) and proves the three core theorems used by the NTT
  primitives in `Ntt/ModArith.lean`:

  * `mont_reduce.spec` — correctness modulo `q` and bound `< 2 * q`.
  * `mont_reduce_add` — additivity over `+ k * R` shifts (used by the
    enumeration bound).
  * `mont_reduce_bounds` — enumeration-based tighter bound.

  This file is pure math (no Aeneas `Result` monad, no extracted code
  references).

  Namespace: `Symcrust.mont_reduce` (case-sensitive) does not collide
  with the extracted `symcrust.mlkem.ntt.mont_reduce`.
-/
import Aeneas

namespace Symcrust

open Aeneas.Arith

set_option maxHeartbeats 1000000

/-- Montgomery reduction -/
def mont_reduce (q R : Nat) (minus_q_minus_1 : Int) (a : Nat) : Int :=
  let f := (a * minus_q_minus_1) % R
  let t := (a + f * q) / R
  t

theorem mont_reduce.spec
  (q: Nat)
  (R: Nat)
  (minus_q_minus_1: Int)
  (a: Nat)
  (h_R: R > q ∧ exists n, R = 2 ^ n)
  (h_q_minus_1: (minus_q_minus_1 * q) % R = (-1) % R)
  (h_q: 0 < q)
  (h_a: a < q * R)
  (h_q_R: Nat.Coprime R q) :
  let t := mont_reduce q R minus_q_minus_1 a
  t % (q : Int) = (a * (R: ZMod q)⁻¹.val) % q ∧
  0 ≤ t ∧ t < 2 * q
  := by
  let f := (a * minus_q_minus_1) % R
  let t := (a + f * q) / R

  -- Having this is in the context is useful as it triggers simplifications
  have : NeZero q := by constructor; agrind

  -- Main goal
  have h_t: t % (q : Int) = (a * ((R : ZMod q)⁻¹.val : Int)) % q := by
    zmodify at h_q_minus_1
    zmodify [t, f]
    rw [div_to_ZMod]
    . simp only [Int.cast_add, Int.cast_natCast, Int.cast_mul, CharP.cast_eq_zero, mul_zero,
      add_zero, f]
    . simp only [Int.cast_add, Int.cast_natCast, Int.cast_mul, ZMod.intCast_mod, mul_assoc,
      h_q_minus_1, mul_neg, mul_one, add_neg_cancel, f]
    . simp only [Int.gcd_natCast_natCast, h_q_R]

  -- Secondary goals
  have h_t1 : 0 ≤ t := by scalar_tac +nonLin

  have h_t2 : t < 2 * q := by
    simp +zetaDelta only [gt_iff_lt, Int.reduceNeg, ZMod.natCast_val] at *; clear t f
    have h': (↑a + ↑a * minus_q_minus_1 % ↑R * ↑q) < R * q + R * q := by
      apply Int.add_lt_add
      have := @Int.ofNat_lt a (q * R)
      . simp_all only [Nat.cast_mul, iff_true, gt_iff_lt]
        rw [Int.mul_comm]
        simp [*]
      . apply mul_lt_mul_of_pos_right
        . scalar_tac +nonLin
        . simp [*]
    apply Int.ediv_lt_of_lt_mul
    . scalar_tac
    . conv => rhs; rw [Int.mul_assoc]; rhs; rw [Int.mul_comm]
      scalar_tac

  simp +zetaDelta [mont_reduce, *]


/-!
Below, we provide facilities to compute an exact bound for the Montgomery reduction.
We do it by enumerating all possibilities: this requires only |q| operations (and not |q.R|),
as is thus feasible even when |q| is quite large.
-/

theorem mont_reduce_add (q R : Nat) (minus_q_minus_1 : Int) (a : Nat) (hR : R ≠ 0) (k : Nat):
  mont_reduce q R minus_q_minus_1 (a + k * R) = (mont_reduce q R minus_q_minus_1 a) + k
  := by
  simp only [mont_reduce, Nat.cast_add, Nat.cast_mul]
  rw [Int.add_mul]

  rw [← Int.add_emod_emod]
  have h1 :=
    calc
    (k * R * minus_q_minus_1) % ↑R
      = R * (k * minus_q_minus_1) % R := by ring_nf
    _ = 0 := by apply Int.mul_emod_right
  simp only [h1, add_zero]

  have h2 :=
    calc
    (a + k * R + a * minus_q_minus_1 % R * q) / R
      = (R * k + (a + a * minus_q_minus_1 % R * q)) / R := by ring_nf
    _ = (R * k) / R + (a + a * minus_q_minus_1 % R * q) / R := by
        apply Int.add_ediv_of_dvd_left
        simp
    _ = k + (a + a * minus_q_minus_1 % R * q) / R := by
      simp
      rw [mul_comm]
      apply Int.mul_ediv_cancel
      agrind

  rw [h2]
  ring_nf

theorem mont_reduce_bounds (q R : Nat) (minus_q_minus_1 : Int) (B m : Nat)
  (hR : R ≠ 0)
  (hMax : List.maximum (List.map (mont_reduce q R minus_q_minus_1) (List.range' 0 R)) = .some m := by reduce) :
  ∀ x, x ≤ B → mont_reduce q R minus_q_minus_1 x ≤ m + B / R := by
  rw [List.maximum_eq_coe_iff] at hMax
  intro x hIneq
  have h0 : x % R + x / R * R = x := by
    have := Nat.div_add_mod x R
    ring_nf at *
    assumption
  have h1 := mont_reduce_add q R minus_q_minus_1 (x % R) hR (x / R)
  rw [h0] at h1
  have h2 := hMax.right (mont_reduce q R minus_q_minus_1 (x % R))
  simp at h2
  replace h2 := h2 (x % R)
  simp at h2
  replace h2 := h2 (by apply Nat.mod_lt; agrind)

  have : x / R ≤ B / R := by
    apply Nat.div_le_div_right
    agrind

  agrind

end Symcrust
