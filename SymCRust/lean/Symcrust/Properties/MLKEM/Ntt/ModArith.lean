/-
  # Ntt/ModArith.lean — modular arithmetic primitives.

  Step specs for `mod_reduce`, `mod_add`, `mod_sub`, and `mont_mul`.
  All four operate on `U32` values constrained to `< q = 3329` (or
  `< 2q` for `mod_reduce`) and produce results in `[0, q)`.

  ## FC strategy

  Each spec states both a **numeric bound** (`r.val < q`) and a **`Zq`
  equation** (`u32ToZq r = …`).  The numeric bound is the precondition
  fuel for downstream `mod_*` / `mont_mul` calls; the `Zq` equation
  carries the FC.

  The Montgomery primitive `mont_mul` differs: its postcondition is
  `u32ToZq result = u32ToZq a · u32ToZq b · Rinv` (the raw `R`-scaled
  product).  Callers cancel the `Rinv` factor by composing with
  `Bridges.mont_mul_R_left` / `_R_right` / `_R_SQR` etc. from
  `Bridges/MontArith.lean`.

  ## Proof strategy

  * `mod_reduce` and `mod_sub` contain an Aeneas-translated
    `if i = 0 then ok () else massert (i = 65535)` whose two-branch
    structure interferes with `step*`.  We introduce internal primed
    variants `mod_reduce'` and `mod_sub'` with a single
    `massert (i = 0 ∨ i = 65535)` and prove equality
    (`mod_reduce_eq`, `mod_sub_eq`) for use inside the proofs.
  * Each spec proof unfolds the (primed) body, runs `step*` after
    switching to BV-level `U32.add_bv_spec`/`U32.mul_bv_spec`, and
    discharges remaining BV obligations with `bv_tac 32`.
  * The Zq equality uses `show (… : ZMod 3329) = …` to force the
    opaque `Zq = ZMod q` into a numeric form `bv_tac` can solve.
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.MontArith
import Symcrust.Properties.MLKEM.Ntt.MontReduction

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust

namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

/-! ## Bit-vector / nat / int identities -/

private theorem bv_and_65535_eq_mod (x : BitVec 32) : x &&& 65535#32 = x % 65536#32 := by bv_decide
private theorem bv_shift_16_eq_div (x : BitVec 32) : x >>> 16 = x / 65536#32 := by bv_decide
private theorem nat_and_65535_eq_mod (x : Nat) : x &&& 65535 = x % 65536 := by
  apply Nat.and_two_pow_sub_one_eq_mod x 16

private theorem mod_4294967296_65536_eq (x : Nat) : ((x % 4294967296) % 65536) = x % 65536 := by
  rw [Nat.mod_mod_of_dvd]; agrind

private theorem mod_65536_4294967296_eq (x : Nat) : ((x % 65536) % 4294967296) = x % 65536 := by
  apply Nat.mod_eq_of_lt; agrind

private theorem mod_int_4294967296_65536_eq (x : Int) : ((x % 4294967296) % 65536) = x % 65536 := by
  rw [Int.emod_emod_of_dvd]; agrind

private theorem mod_int_65536_4294967296_eq (x : Int) : ((x % 65536) % 4294967296) = x % 65536 := by
  apply Int.emod_eq_of_lt <;> agrind

private theorem Nat_mod_3329_mod_4294967296_eq (x : Nat) :
    x % 3329 % 4294967296 = x % 3329 := by
  apply Nat.mod_eq_of_lt; agrind

private theorem Int_mod_3329_mod_4294967296_eq (x : Int) :
    x % 3329 % 4294967296 = x % 3329 := by
  apply Int.emod_eq_of_lt <;> agrind

/-! ## Switch to bv-level step lemmas for U32 arithmetic. -/

attribute [-step] U32.add_spec U32.mul_spec
attribute [local step] U32.add_bv_spec U32.mul_bv_spec
attribute [local step] UScalar.cast_inBounds_spec

attribute [local simp, local grind =, agrind =]
  bv_and_65535_eq_mod bv_shift_16_eq_div nat_and_65535_eq_mod

attribute [local simp]
  mod_4294967296_65536_eq mod_65536_4294967296_eq
  mod_int_4294967296_65536_eq mod_int_65536_4294967296_eq
  Nat_mod_3329_mod_4294967296_eq Int_mod_3329_mod_4294967296_eq

/-! ## `mod_reduce`: conditional subtraction `(a mod q)` when `a < 2q` -/

/-- Refactored variant of `mlkem.ntt.mod_reduce` that collapses the
two-branch `if i = 0 then ok () else massert (i = 65535)` into a
single `massert (i = 0 ∨ i = 65535)`.  Used internally to drive
`step*` without branching.
-/
private def mod_reduce' (a : U32) : Result U32 := do
  let i ← 2#u32 * mlkem.ntt.Q
  massert (a < i)
  let res ← lift (core.num.U32.wrapping_sub a mlkem.ntt.Q)
  let i1 ← res >>> 16#i32
  massert (i1 = 0#u32 || i1 = 65535#u32)
  let i2 ← lift (mlkem.ntt.Q &&& i1)
  let res1 ← lift (core.num.U32.wrapping_add res i2)
  massert (res1 < mlkem.ntt.Q)
  ok res1

private theorem mod_reduce_eq (a : U32) :
    mlkem.ntt.mod_reduce a = mod_reduce' a := by
  unfold mlkem.ntt.mod_reduce mod_reduce'
  simp
  intros
  split <;> simp [*]

private theorem mod_reduce'_spec (a : U32) (ha : a.val < 2 * q) :
    mod_reduce' a ⦃ (r : U32) =>
      r.val < q ∧
      u32ToZq r = u32ToZq a ⦄ := by
  unfold mod_reduce'
  have hq : (q : Nat) = 3329 := rfl
  simp only [hq] at *
  step*
  · bv_tac 32
  · bv_tac 32
  · refine ⟨?_, ?_⟩
    · bv_tac 32
    · unfold u32ToZq
      show (res1.val : ZMod 3329) = (a.val : ZMod 3329)
      bv_tac 32

/-- **Spec for `symcrust::mlkem::ntt::mod_reduce`**

Constant-time conditional subtraction: given `a < 2q`, returns `a` if
`a < q` else `a - q`.  Result is always `< q` and equal to `a mod q` in
`Zq`. -/
@[step]
theorem mlkem.ntt.mod_reduce.spec (a : U32) (ha : a.val < 2 * q) :
    mlkem.ntt.mod_reduce a ⦃ (r : U32) =>
      r.val < q ∧
      u32ToZq r = u32ToZq a ⦄ := by
  rw [mod_reduce_eq]; exact mod_reduce'_spec a ha

/-! ## `mod_add` -/

/-- **Spec for `symcrust::mlkem::ntt::mod_add`**

Constant-time modular addition: `(a + b) mod q` as a `U32 < q`. -/
@[step]
theorem mlkem.ntt.mod_add.spec (a b : U32)
    (ha : a.val < q) (hb : b.val < q) :
    mlkem.ntt.mod_add a b ⦃ (r : U32) =>
      r.val < q ∧
      u32ToZq r = u32ToZq a + u32ToZq b ⦄ := by
  unfold mlkem.ntt.mod_add
  step
  step
  step as ⟨i, i_post, i_bv⟩
  -- `step` produced two hypotheses: `i_post : ↑i = ↑a + ↑b` (Nat) and
  -- `i_bv : i.bv = a.bv + b.bv` (BV).  In newer Aeneas these are separate
  -- (not conjoined) so we name both.
  have hi_val : i.val = a.val + b.val := i_post
  have : i.val < 2 * q := by agrind
  step as ⟨r, hr1, hr2⟩
  refine ⟨hr1, ?_⟩
  -- hr2 : u32ToZq r = u32ToZq i; FC by hi_val.
  simp only [u32ToZq] at hr2 ⊢
  rw [hr2, hi_val]
  push_cast
  ring

/-! ## `mod_sub` -/

private def mod_sub' (a b : U32) : Result U32 := do
  massert (a < mlkem.ntt.Q)
  massert (b < mlkem.ntt.Q)
  let res ← lift (core.num.U32.wrapping_sub a b)
  let i ← res >>> 16#i32
  massert (i = 0#u32 || i = 65535#u32)
  let i1 ← lift (mlkem.ntt.Q &&& i)
  let res1 ← lift (core.num.U32.wrapping_add res i1)
  massert (res1 < mlkem.ntt.Q)
  ok res1

private theorem mod_sub_eq (a b : U32) :
    mlkem.ntt.mod_sub a b = mod_sub' a b := by
  unfold mlkem.ntt.mod_sub mod_sub'
  simp
  intros
  split <;> simp [*]

private theorem mod_sub'_spec (a b : U32)
    (_ : a.val < q) (_ : b.val < q) :
    mod_sub' a b ⦃ (r : U32) =>
      r.val < q ∧
      u32ToZq r = u32ToZq a - u32ToZq b ⦄ := by
  unfold mod_sub'
  have hq : (q : Nat) = 3329 := rfl
  simp only [hq] at *
  step*
  · bv_tac 32
  · bv_tac 32
  · refine ⟨?_, ?_⟩
    · bv_tac 32
    · unfold u32ToZq
      show (res1.val : ZMod 3329) = (a.val : ZMod 3329) - (b.val : ZMod 3329)
      bv_tac 32

/-- **Spec for `symcrust::mlkem::ntt::mod_sub`**

Constant-time modular subtraction: `(a - b) mod q` as a `U32 < q`. -/
@[step]
theorem mlkem.ntt.mod_sub.spec (a b : U32)
    (ha : a.val < q) (hb : b.val < q) :
    mlkem.ntt.mod_sub a b ⦃ (r : U32) =>
      r.val < q ∧
      u32ToZq r = u32ToZq a - u32ToZq b ⦄ := by
  rw [mod_sub_eq]; exact mod_sub'_spec a b ha hb

/-! ## `mont_mul`: Montgomery multiplication

The proof reuses the abstract `Symcrust.mont_reduce.spec` (in
`Ntt/MontReduction.lean`) at the leaf, bridged through bit-vector
identities.  The Montgomery divisibility identity
`(a · b + (a · b_mont mod R) · q) mod R = 0`
follows from `1 + 3327 · 3329 = 169 · R`. -/

private theorem mont_reduce_bv.spec (a b bMont tR t : U32)
    (haBound : a.val < q)
    (hbBound : b.val < q)
    (hbMont : bMont.bv = (b.bv * mlkem.ntt.NEG_Q_INV_MOD_R.bv) &&& mlkem.ntt.RMASK.bv)
    (htR : tR.bv = a.bv * b.bv + ((a.bv * bMont.bv) &&& mlkem.ntt.RMASK.bv) * mlkem.ntt.Q.bv)
    (ht : t.bv = tR.bv >>> 16) :
    u32ToZq t = u32ToZq a * u32ToZq b * Rinv ∧
    t.val < 2 * q := by
  refine ⟨?_, ?_⟩
  · -- Int → ZMod q bridge.  The chain is:
    --   1. Apply `Symcrust.mont_reduce.spec` at `(a.val * b.val)` to obtain the
    --      Int-mod-q identity `t % q ≡ a.val * b.val * (U16.size : ZMod q)⁻¹`.
    --   2. Compute `t.val` in Nat form from the BV definition via `congrArg
    --      BitVec.toNat ht`.
    --   3. Convert the goal from `Rinv` form to `(U16.size : Zq)⁻¹` form using
    --      `decide` (both equal `169 : Zq`).
    --   4. `natify; rw [htNat]; zify; simp` closes via `hMont_eq`.
    have hq : (q : Nat) = 3329 := rfl
    simp only [hq] at haBound hbBound
    have habLt : a.val * b.val < 3329 * U16.size := by
      simp only [show U16.size = 65536 from by simp [U16.size, U16.numBits]]
      scalar_tac +nonLin
    have hMont := mont_reduce.spec 3329 U16.size 3327 (a.val * b.val)
        (by simp [U16.size, U16.numBits]; exists 16)
        (by simp [U16.size, U16.numBits]) (by simp)
        habLt (by simp [U16.size, U16.numBits]; constructor)
    simp [mont_reduce] at hMont
    obtain ⟨hMont_eq, _hBounds⟩ := hMont
    rw [htR, hbMont] at ht
    simp at ht
    have htNat := congrArg BitVec.toNat ht
    simp [BitVec.toNat_udiv, BitVec.toNat_add, BitVec.toNat_mul, BitVec.toNat_umod] at htNat
    have hRinv : Rinv = ((U16.size : ZMod q) : Zq)⁻¹ := by
      simp [U16.size, U16.numBits]; decide
    show (t.val : Zq) = (a.val : Zq) * (b.val : Zq) * Rinv
    rw [hRinv]
    natify; simp
    rw [htNat]
    have heq_mod : (a.val * b.val + a.val * (b.val * 3327) % 65536 * 3329) % 4294967296 =
           a.val * b.val + a.val * (b.val * 3327) % 65536 * 3329 := by
      apply Nat.mod_eq_of_lt
      scalar_tac
    rw [heq_mod]; clear heq_mod
    simp [U16.size, U16.numBits] at *
    zify
    simp [← mul_assoc, hMont_eq]
  · -- Bound `t.val < 2 * q`: a pure bit-vector consequence given
    -- `a, b < q = 3329`.  Established at the BV level via `bv_tac 32`.
    have ha_bv : a.bv < 3329#32 := by
      have : a.bv.toNat < 3329 := haBound
      bv_omega
    have hb_bv : b.bv < 3329#32 := by
      have : b.bv.toNat < 3329 := hbBound
      bv_omega
    have ht_bv : t.bv < 6658#32 := by bv_tac 32
    show t.val < 2 * q
    have ht_nat : t.bv.toNat < 6658 := ht_bv
    have heq : t.val = t.bv.toNat := rfl
    rw [heq]
    have : (2 * q : Nat) = 6658 := by decide
    scalar_tac

/-! ### `mont_reduce_single_u32.spec` — inline Montgomery reduction (no inner multiply)

A separate-variable form of Montgomery reduction over a single `u32`
input `a` (not the product of two `< q` inputs as in `mont_mul`).
Used by `poly_element_mul_and_accumulate_loop` which inlines the
reduction on the product `a1 * b1` (already bounded by the
accumulator-MAX rather than by `q²`).

Input bound: `a.val ≤ 4 * (MAX_COEFF² + MAX_FIRST · ZETA_MAX) =
4 * (3328² + 3494 · 3254)`, which is the (loose) bound carried by the
`pa_dst` accumulator slot in the mul-and-accumulate body.

Output `t = (a + ((a*NEG_Q_INV_MOD_R) &&& RMASK) * Q) >>> 16`
satisfies `(t.val : Zq) = (a.val : Zq) * Rinv` and `t.val ≤ 4698`. -/
theorem mont_reduce_single_u32.spec (a i6 inv i7 i8 t : U32)
    (haBound : a.val ≤ 4 * (3328 * 3328 + 3494 * 3254))
    (hi6 : i6.bv = (core.num.U32.wrapping_mul a mlkem.ntt.NEG_Q_INV_MOD_R).bv)
    (hinv : inv.bv = i6.bv &&& mlkem.ntt.RMASK.bv)
    (hi7 : i7.bv = inv.bv * mlkem.ntt.Q.bv)
    (hi8 : i8.bv = a.bv + i7.bv)
    (ht : t.bv = i8.bv >>> 16) :
    (t.val : Zq) = (a.val : Zq) * (U16.size : Zq)⁻¹ ∧
    t.val ≤ 4698 := by
  have hN : mlkem.ntt.NEG_Q_INV_MOD_R.bv = 3327#32 := by
    unfold mlkem.ntt.NEG_Q_INV_MOD_R; rfl
  have hR : mlkem.ntt.RMASK.bv = 65535#32 := by
    unfold mlkem.ntt.RMASK; rfl
  have hQ : mlkem.ntt.Q.bv = 3329#32 := by
    unfold mlkem.ntt.Q; rfl
  refine ⟨?_, ?_⟩
  · -- Modular equality via mont_reduce.spec (Nat-level), bridged through BV.
    have hMont := mont_reduce.spec 3329 U16.size 3327 a.val
      (by simp [U16.size, U16.numBits]; exists 16)
      (by simp [U16.size, U16.numBits])
      (by simp)
      (by show a.val < 3329 * U16.size; simp [U16.size, U16.numBits]; scalar_tac)
      (by simp [U16.size, U16.numBits]; constructor)
    simp [mont_reduce] at hMont
    obtain ⟨hMontEq, _hLB, _hUB⟩ := hMont
    -- Compute t.val in Nat form: (a + ((a*3327) mod 65536) * 3329) / 65536.
    have htNat' : t.val = (a.val + a.val * 3327 % 65536 * 3329) / 65536 := by
      rw [hi6, hN, hR, hQ] at *
      bv_tac (config := { timeout := 60, acNf := true }) 32
    natify; simp
    rw [htNat']
    simp [U16.size, U16.numBits] at *
    zify
    simp [hMontEq]
  · -- Tight bound `t.val ≤ 4698` from input bound + BV computation.
    rw [hi6, hN, hR, hQ] at *
    bv_tac 32

private theorem mont_mod_mul_mod_eq (x y m : Nat) :
    (x % m * y) % m = (x * y) % m := by
  conv_lhs => rw [Nat.mul_mod, Nat.mod_mod_of_dvd x (dvd_refl m), ← Nat.mul_mod]

private theorem mont_mul_mod_right_eq (x y m : Nat) :
    (x * (y % m)) % m = (x * y) % m := by
  conv_lhs => rw [Nat.mul_mod, Nat.mod_mod_of_dvd y (dvd_refl m), ← Nat.mul_mod]

private theorem mont_bv_div (x y : BitVec 32) :
    (x * y + (x * (y * 3327#32 % 65536#32) % 65536#32) * 3329#32) % 65536#32 = 0#32 := by
  natify; simp
  rw [Nat.add_mod, mont_mod_mul_mod_eq (x.toNat * (y.toNat * 3327)) 3329 65536, ← Nat.add_mod]
  have h : x.toNat * y.toNat + x.toNat * (y.toNat * 3327) * 3329 =
           x.toNat * y.toNat * (1 + 3327 * 3329) := by ring
  rw [h, show 1 + 3327 * 3329 = 169 * 65536 from by agrind,
      show x.toNat * y.toNat * (169 * 65536) = x.toNat * y.toNat * 169 * 65536 from by ring]
  agrind

private theorem mont_bv_div_andForm (x y : BitVec 32) :
    (x * y + (x * (y * 3327#32 &&& 65535#32) &&& 65535#32) * 3329#32) &&& 65535#32 = 0#32 := by
  simp only [bv_and_65535_eq_mod]
  exact mont_bv_div x y

private theorem mont_mul_div_by_R (a b bMont : U32)
    (hbMont : bMont.bv = (b.bv * mlkem.ntt.NEG_Q_INV_MOD_R.bv) &&& mlkem.ntt.RMASK.bv)
    (res : U32) (hRes : res.bv = a.bv * b.bv)
    (inv : U32) (hInv_eq : inv.bv = (a.bv * bMont.bv) &&& mlkem.ntt.RMASK.bv)
    (i3 : U32) (hi3 : i3.bv = inv.bv * mlkem.ntt.Q.bv)
    (res1 : U32) (hRes1 : res1.bv = res.bv + i3.bv) :
    (res1.bv &&& mlkem.ntt.RMASK.bv) = 0#32 := by
  rw [hRes1, hRes, hi3, hInv_eq, hbMont]
  have hN : mlkem.ntt.NEG_Q_INV_MOD_R.bv = 3327#32 := by
    unfold mlkem.ntt.NEG_Q_INV_MOD_R; rfl
  have hR : mlkem.ntt.RMASK.bv = 65535#32 := by
    unfold mlkem.ntt.RMASK; rfl
  have hQ : mlkem.ntt.Q.bv = 3329#32 := by
    unfold mlkem.ntt.Q; rfl
  rw [hN, hR, hQ]
  exact mont_bv_div_andForm a.bv b.bv

/-- **Spec for `symcrust::mlkem::ntt::mont_mul`**

Computes `a · b · R⁻¹ mod q`, where `b_mont = b · (-q⁻¹) mod 2^16` is
the precomputed Montgomery factor for `b`.  The caller is responsible
for supplying a correct `b_mont`; the runtime `massert` (line 2473)
enforces consistency.

The FC postcondition is the **raw** Montgomery product
`u32ToZq r = u32ToZq a · u32ToZq b · R⁻¹`.  Callers absorb the `R⁻¹`
factor via the bridge lemmas `mont_mul_R_left` / `_R_right` /
`_R_SQR` / etc. in `Bridges/MontArith.lean`. -/
@[step]
theorem mlkem.ntt.mont_mul.spec (a b b_mont : U32)
    (ha : a.val < q) (hb : b.val < q)
    (hbm : b_mont.val ≤ 65535)
    (hbm_eq : b_mont.val = (b.val * 3327) % 65536) :
    mlkem.ntt.mont_mul a b b_mont ⦃ (r : U32) =>
      r.val < q ∧
      u32ToZq r = u32ToZq a * u32ToZq b * Rinv ⦄ := by
  unfold mlkem.ntt.mont_mul
  have hq : (q : Nat) = 3329 := rfl
  simp only [hq] at hbm_eq ⊢
  -- Convert the val-form precondition `hbm_eq` to a BV-form precondition
  -- (the shape expected by `mont_mul_div_by_R` and `mont_reduce_bv.spec`).
  have hbMont : b_mont.bv = (b.bv * mlkem.ntt.NEG_Q_INV_MOD_R.bv) &&& mlkem.ntt.RMASK.bv := by
    have hN : mlkem.ntt.NEG_Q_INV_MOD_R.bv = 3327#32 := by
      unfold mlkem.ntt.NEG_Q_INV_MOD_R; rfl
    have hR : mlkem.ntt.RMASK.bv = 65535#32 := by
      unfold mlkem.ntt.RMASK; rfl
    rw [hN, hR]
    bv_tac 32
  step*
  · -- i4 = 0, Montgomery divisibility
    have hinv : inv.bv = a.bv * b_mont.bv &&& mlkem.ntt.RMASK.bv := by
      simp only [inv_post2, i2_post2]
    have hdiv := mont_mul_div_by_R a b b_mont hbMont
      res res_post2 inv hinv i3 i3_post2 res1 res1_post2
    bv_tac 32
  · -- res2.val < 2 * q (Montgomery bound)
    have htR : res1.bv = a.bv * b.bv + ((a.bv * b_mont.bv) &&& mlkem.ntt.RMASK.bv) * mlkem.ntt.Q.bv := by
      simp only [res1_post2, res_post2, i3_post2, inv_post2, i2_post2]
    have ht : res2.bv = res1.bv >>> 16 := by
      simp only [res2_post2, ntt_RLOG2_val]
    exact (mont_reduce_bv.spec a b b_mont res1 res2 (by simp_all) (by simp_all) hbMont htR ht).2
  · -- Final FC postcondition
    refine ⟨r_post1, ?_⟩
    rw [r_post2]
    have htR : res1.bv = a.bv * b.bv + ((a.bv * b_mont.bv) &&& mlkem.ntt.RMASK.bv) * mlkem.ntt.Q.bv := by
      simp only [res1_post2, res_post2, i3_post2, inv_post2, i2_post2]
    have ht : res2.bv = res1.bv >>> 16 := by
      simp only [res2_post2, ntt_RLOG2_val]
    exact (mont_reduce_bv.spec a b b_mont res1 res2 (by simp_all) (by simp_all) hbMont htR ht).1

end Symcrust.Properties.MLKEM
