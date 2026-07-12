/-
  # Bridges/MontArith.lean — Montgomery cancellation arithmetic for ML-KEM.

  ## Why this file exists

  Every NTT primitive in ML-KEM that uses `mont_mul` ends up invoking the
  same algebraic identity:

      (u32ToZq (mont_mul a b)) = (u32ToZq a) · (u32ToZq b) · Rinv

  This is the postcondition shape of `mont_mul.spec`.  Callers always need
  a *specialization* — e.g. "result equals `(spec value)`" because one
  operand is in Montgomery form (carries an extra `R` factor) and the
  `· Rinv` cancels it.

  This file collects those specializations as named `simp` / `agrind`
  lemmas so every downstream proof can rewrite without re-doing the
  cancellation algebra.  It also gives concrete `Zq` values to the
  precomputed Montgomery constants `RSQR`, `INTT_FIXUP_TIMES_RSQR`, etc.,
  defined as `irreducible` U32 literals in `Code/Funs.lean`.

  Constants (all defined in `mlkem.ntt`):

  * `Q = 3329` — prime modulus.
  * `RMASK = 65535 = 2^16 - 1` — low-16-bit mask.
  * `RLOG2 = 16` — `log₂ R`.
  * `RSQR = 1353 = R² mod q` — used to lift to Montgomery form via `mont_mul`.
  * `NEG_Q_INV_MOD_R = 3327 = (-q⁻¹) mod 2^16` — Montgomery reduction factor.
  * `RSQR_TIMES_NEG_Q_INV_MOD_R = 44983 = RSQR · NEG_Q_INV_MOD_R mod 2^16` — precomputed.
  * `INTT_FIXUP_TIMES_RSQR = 1441 = 256⁻¹ · R² mod q` — INTT post-fixup, lifts and
    rescales by 256⁻¹.
-/
import Symcrust.Properties.MLKEM.Basic
import Mathlib.Tactic.LinearCombination
import Intrinsics.BVRealize

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust

/-! ## Pre-realised `enumToBitVec` aux defs — olean-clash mitigation.

`bv_decide` / `bv_tac` lazily realise a per-file public aux def named
`<Enum>.enumToBitVec` whenever its goal mentions a value of an enum
type.  Two oleans on the same import chain that each realise the
same imported enum (e.g. `PUnit` from core Lean) clash at link time:

    environment already contains 'PUnit.enumToBitVec'
    from Symcrust.Properties.MLKEM.Ntt.ModArith

The realisation lives in `Intrinsics/BVRealize.lean` (imported
above) so it dominates both this file's import closure AND the
`Intrinsics/Properties/X86_64/Sse2Specs.lean` closure — necessary
once `Symcrust/Properties/MLKEM/Intrinsics/X86_64/Sse2.lean` imports
both transitively. -/

namespace Symcrust.Properties.MLKEM.Bridges

open Symcrust.Properties.MLKEM

set_option maxHeartbeats 400000

/-! ## Numeric constants — `_val` lemmas

Each precomputed constant in `mlkem.ntt` is marked `irreducible`, so the
solvers cannot see its numeric value directly.  These `_val` lemmas
register the value with every solver (`simp`, `scalar_tac`, `agrind`,
`grind`, `bvify`). -/

@[simp, scalar_tac_simps, agrind =, grind =, bvify]
theorem ntt_Q_val : mlkem.ntt.Q.val = 3329 := by
  unfold mlkem.ntt.Q; decide

@[simp, scalar_tac_simps, agrind =, grind =, bvify]
theorem ntt_RMASK_val : mlkem.ntt.RMASK.val = 65535 := by
  unfold mlkem.ntt.RMASK; decide

@[simp, scalar_tac_simps, agrind =, grind =, bvify]
theorem ntt_RLOG2_val : mlkem.ntt.RLOG2.val = 16 := by
  unfold mlkem.ntt.RLOG2; decide

@[simp, scalar_tac_simps, agrind =, grind =, bvify]
theorem ntt_NEG_Q_INV_MOD_R_val : mlkem.ntt.NEG_Q_INV_MOD_R.val = 3327 := by
  unfold mlkem.ntt.NEG_Q_INV_MOD_R; decide

@[simp, scalar_tac_simps, agrind =, grind =, bvify]
theorem ntt_RSQR_val : mlkem.ntt.RSQR.val = 1353 := by
  unfold mlkem.ntt.RSQR; decide

@[simp, scalar_tac_simps, agrind =, grind =, bvify]
theorem ntt_RSQR_TIMES_NEG_Q_INV_MOD_R_val :
    mlkem.ntt.RSQR_TIMES_NEG_Q_INV_MOD_R.val = 44983 := by
  unfold mlkem.ntt.RSQR_TIMES_NEG_Q_INV_MOD_R; decide

@[simp, scalar_tac_simps, agrind =, grind =, bvify]
theorem ntt_INTT_FIXUP_TIMES_RSQR_val :
    mlkem.ntt.INTT_FIXUP_TIMES_RSQR.val = 1441 := by
  unfold mlkem.ntt.INTT_FIXUP_TIMES_RSQR; decide

@[simp, scalar_tac_simps, agrind =, grind =, bvify]
theorem ntt_INTT_FIXUP_TIMES_RSQR_TIMES_NEQ_Q_INV_MOD_R_val :
    mlkem.ntt.INTT_FIXUP_TIMES_RSQR_TIMES_NEQ_Q_INV_MOD_R.val = 10079 := by
  unfold mlkem.ntt.INTT_FIXUP_TIMES_RSQR_TIMES_NEQ_Q_INV_MOD_R; decide

/-! ## `Zq` value bridges

Each precomputed Montgomery constant has a closed-form `Zq` value.  These
are the rewrites callers use to bring `u32ToZq const` into a useful
algebraic shape. -/

/-- `RSQR : Zq = R · R`.  Used by `poly_mul_r` (each coefficient times
`R`), and by `vector_scalar_mont_mul` style call sequences. -/
theorem ntt_RSQR_zq : u32ToZq mlkem.ntt.RSQR = R * R := by
  unfold u32ToZq R; rw [ntt_RSQR_val]; decide

/-- `INTT_FIXUP_TIMES_RSQR : Zq = 128⁻¹ · R · R`.  Used as the post-INTT
multiplier: combined with one Montgomery cancellation, scales each
coefficient by `128⁻¹ · R` (Mont form), matching FIPS 203 Algorithm 10
line 19's `f := 3303` (= `128⁻¹ mod q`).  Note `n = 128` for ML-KEM,
not 256: the NTT acts on 128 *pairs* of base polynomials. -/
theorem ntt_INTT_FIXUP_TIMES_RSQR_zq :
    u32ToZq mlkem.ntt.INTT_FIXUP_TIMES_RSQR = (128 : Zq)⁻¹ * R * R := by
  unfold u32ToZq R
  rw [ntt_INTT_FIXUP_TIMES_RSQR_val, ZMod.inv_eq_of_mul_eq_one q 128 3303 (by decide)]
  decide

/-! ## Core `mont_mul` cancellation identities

Direct algebraic consequences of `R · R⁻¹ = 1` in `Zq`.  These are the
basic rewrites that fire after every `step` over a `mont_mul` call. -/

/-- **M1** — Montgomery-form left operand cancels.

If `a` is stored in Montgomery form (representative `a · R`), then
`(a · R) · b · Rinv = a · b`.  This is the bread-and-butter rewrite for
every NTT inner loop that does `mont_mul cMont twiddle twiddleMont`. -/
@[simp, agrind =]
theorem mont_mul_R_left (a b : Zq) :
    R * a * b * Rinv = a * b := by
  linear_combination a * b * R_mul_Rinv

/-- **M2** — Montgomery-form right operand cancels (symmetric to M1). -/
@[simp, agrind =]
theorem mont_mul_R_right (a b : Zq) :
    a * (R * b) * Rinv = a * b := by
  linear_combination a * b * R_mul_Rinv

/-- **M3** — `RSQR` lifts standard form to Montgomery form via `mont_mul`.

`mont_mul (R²) a = R² · a · Rinv = R · a · (R · Rinv) = R · a`, matching
`poly_mul_r`'s effect of scaling each coefficient by `R`. -/
theorem mont_mul_RSQR (a : Zq) :
    u32ToZq mlkem.ntt.RSQR * a * Rinv = R * a := by
  rw [ntt_RSQR_zq]
  linear_combination R * a * R_mul_Rinv

/-- **M4** — Generic Mont-mul postcondition shape.

The raw post of `mont_mul.spec`; given a name so callers can refer to it
when composing with M1 / M2 / M3 to recover the spec value. -/
@[simp]
theorem mont_mul_zq (a b : Zq) :
    a * b * Rinv = a * b * Rinv := rfl

/-! ## INTT post-fixup cancellation -/

/-- **M5** — The `INTT_FIXUP_TIMES_RSQR` constant gives `128⁻¹ · R` after
one Mont cancellation.

`mont_mul fixup x = (128⁻¹ · R · R) · x · Rinv = 128⁻¹ · R · x`.  When
`x` is already in Montgomery form (stored value `xSpec · R`), the
result of `mont_mul fixup (xSpec · R) = 128⁻¹ · R · (xSpec · R)`; a
second cancellation when read back as spec gives `128⁻¹ · xSpec` — i.e.
the `f := 3303 ≡ 128⁻¹ (mod q)` fixup from FIPS 203 Algorithm 10. -/
theorem mont_mul_intt_fixup (x : Zq) :
    u32ToZq mlkem.ntt.INTT_FIXUP_TIMES_RSQR * x * Rinv = (128 : Zq)⁻¹ * R * x := by
  rw [ntt_INTT_FIXUP_TIMES_RSQR_zq]
  linear_combination ((128 : Zq)⁻¹ * R * x) * R_mul_Rinv

/-! ## Composite cancellations

These appear when an NTT step chains `mont_mul`s (e.g. butterfly inside a
loop).  Pre-proven so step-spec proofs can rewrite once instead of
working through the algebra. -/

/-- **M6** — Both operands in Montgomery form: `(R·a) · (R·b) · Rinv = R · a · b`.

Used in inner butterfly loops where two Mont-form coefficients are
multiplied and the result must remain in Mont form. -/
@[simp, agrind =]
theorem mont_mul_R_both (a b : Zq) :
    (R * a) * (R * b) * Rinv = R * (a * b) := by
  linear_combination (R * a * b) * R_mul_Rinv

/-- **M7** — `Rinv · R · x = x`.  Useful when reading a Mont-form buffer
back as spec value. -/
@[simp, agrind =]
theorem Rinv_R (x : Zq) : Rinv * (R * x) = x := by
  linear_combination x * R_mul_Rinv

end Symcrust.Properties.MLKEM.Bridges

/-! ## BV-level value lemmas for NTT constants

These mirror the `_val` lemmas but project to `.bv` (BitVec 32).
`bv_tac` invokes `bvify` under the hood; constants such as
`mlkem.ntt.Q` are `@[irreducible]`, so without these lemmas the BV
solver sees `mlkem.ntt.Q.bv` as opaque — even in hypotheses produced
by `step*`.

We register on `bvify` (the goal-side simp set) only.

Note: any `bv_decide` or `bv_tac` over a goal mentioning a
`UScalarTy`-typed value emits an `Aeneas.Std.UScalarTy.enumToBitVec`
aux def per olean, and two oleans on the same import chain clash at
link time.  The central realiser above mitigates this. -/

namespace symcrust.mlkem.ntt

@[simp, bvify, grind =, agrind =]
theorem Q.bv_eq : Q.bv = 3329#32 := by
  unfold Q; rfl

@[simp, bvify, grind =, agrind =]
theorem RMASK.bv_eq : RMASK.bv = 65535#32 := by
  unfold RMASK; rfl

@[simp, bvify, grind =, agrind =]
theorem NEG_Q_INV_MOD_R.bv_eq : NEG_Q_INV_MOD_R.bv = 3327#32 := by
  unfold NEG_Q_INV_MOD_R; rfl

@[simp, bvify, grind =, agrind =]
theorem RLOG2.bv_eq : RLOG2.bv = 16#32 := by
  unfold RLOG2; rfl

end symcrust.mlkem.ntt
