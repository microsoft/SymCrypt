/-
  # `Ntt/Twiddles.lean` — `step_array_spec` lemmas for NTT twiddle tables

  `step_array_spec` lemmas for the precomputed twiddle-factor tables
  `mlkem.ntt.ZETA_BIT_REV_TIMES_R` and
  `mlkem.ntt.ZETA_BIT_REV_TIMES_R_TIMES_NEG_Q_INV_MOD_R`.
  Both forward (`Ntt/Ntt.lean`) and inverse (`Ntt/Intt.lean`) butterfly
  loops index into these tables, so the lemmas are declared once here
  and imported from both files.

  Also provides the higher-level
  `mlkem.ntt.mont_mul_twiddle.spec`: invoking `mont_mul c twiddle
  twiddle_mont` with `twiddle = ζ^(bitRev 7 k) · R` and the
  corresponding Montgomery hint yields the Zq-product
  `c · ζ^(bitRev 7 k)` — the twiddle's `· R` factor cancels against
  `mont_mul`'s `· R⁻¹`.

  `mont_mul.spec` takes val-form preconditions
  (`b_mont.val ≤ 65535` and `b_mont.val = (b.val * 3327) % 65536`)
  rather than the bv-form `bMont.bv = (b.bv * NEG_Q_INV_MOD_R.bv) &&& RMASK.bv`;
  we re-derive the val form below.
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.MontArith
import Symcrust.Properties.MLKEM.Ntt.ModArith

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust

namespace Symcrust.Properties.MLKEM

set_option maxHeartbeats 4000000
set_option maxRecDepth 2048

/-! ## Step-array specs for the precomputed twiddle tables

These are pure decidable lookups: at compile time we know each table
entry. `native_decide` evaluates the assertion as a single boolean
predicate.  The specs are universally applicable for every valid `k`
because the assertion uses `bitRev 7 k` to index the spec side. -/

step_array_spec (name := mlkem.ntt.ZETA_BIT_REV_TIMES_R_spec)
  mlkem.ntt.ZETA_BIT_REV_TIMES_R[k]!
  { v =>
    (v.val : Zq) = ζ ^ (bitRev 7 k) * 65536 ∧
    v.bv.zeroExtend 32 = BitVec.ofNat 32 (17 ^ bitRev 7 k * 65536 % 3329) ∧
    v.val < 3329 }
  by
    native_decide

step_array_spec (name := mlkem.ntt.ZETA_BIT_REV_TIMES_R_TIMES_NEG_Q_INV_MOD_R_spec)
  mlkem.ntt.ZETA_BIT_REV_TIMES_R_TIMES_NEG_Q_INV_MOD_R[k]!
  { v =>
    BitVec.ofNat 32 v.val =
      (BitVec.ofNat 32 ((17 ^ bitRev 7 k.val * 65536) % 3329) * 3327#32)
        &&& 65535#32 ∧
    v.val ≤ 65535 ∧
    v.val = ((17 ^ bitRev 7 k.val * 65536) % 3329 * 3327) % 65536 }
  by
    native_decide

/-! ## Twiddle-aware `mont_mul` spec

`mont_mul c twiddle twiddle_mont` with `twiddle = ζ^(bitRev 7 k) · R`
and the corresponding Montgomery hint yields the Zq-product
`c · ζ^(bitRev 7 k)`: the twiddle's `· R` factor cancels against
`mont_mul`'s `· R⁻¹`.

Used by **both** forward `Ntt/Ntt.lean` and inverse `Ntt/Intt.lean`
butterfly chains (the operation is the same; only the
twiddle-index `k` direction differs). -/

@[step]
theorem mlkem.ntt.mont_mul_twiddle.spec
    (k : Usize) (c twiddle twiddle_mont : U32)
    (hc : c.val < q) (hTwiddle : twiddle.val < q)
    (hTwiddleNat : twiddle.val = (17 ^ bitRev 7 k.val * 65536) % 3329)
    (hTwiddleMontNat : twiddle_mont.val ≤ 65535)
    (hTwiddleMontEq : twiddle_mont.val = (twiddle.val * 3327) % 65536) :
    mlkem.ntt.mont_mul c twiddle twiddle_mont ⦃ (d : U32) =>
      d.val < q ∧
      u32ToZq d = u32ToZq c * (ζ ^ bitRev 7 k.val) ⦄ := by
  apply WP.spec_mono
    (mlkem.ntt.mont_mul.spec c twiddle twiddle_mont hc hTwiddle
      hTwiddleMontNat hTwiddleMontEq)
  rintro d ⟨hd_lt, hd_eq⟩
  refine ⟨hd_lt, ?_⟩
  -- hd_eq : u32ToZq d = u32ToZq c * u32ToZq twiddle * Rinv
  rw [hd_eq]
  unfold u32ToZq
  rw [hTwiddleNat]
  -- Goal: (c.val : Zq) * ((17^k * 65536) % 3329 : Zq) * Rinv = (c.val : Zq) * ζ^k
  rw [show ((((17 ^ bitRev 7 k.val * 65536) % 3329 : Nat) : Zq))
        = ζ ^ bitRev 7 k.val * 65536 from by
        rw [ZMod.natCast_mod]
        push_cast
        show ((17 : Zq) ^ bitRev 7 k.val) * 65536 = ζ ^ bitRev 7 k.val * 65536
        rfl]
  -- Goal: c * (ζ^k * 65536) * Rinv = c * ζ^k.
  -- 65536 = 2^16 = R in Zq, and R * Rinv = 1.
  have hR : ((65536 : Zq) : Zq) = R := by unfold R; decide
  rw [show (65536 : Zq) = R from by unfold R; decide]
  ring_nf
  rw [mul_assoc, R_mul_Rinv, mul_one]

end Symcrust.Properties.MLKEM
