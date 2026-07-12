/-
  # Ntt/MulAccum.lean — Step-specs for the BaseCaseMultiply accumulator.

  The ML-KEM pointwise NTT multiply is more subtle than a simple
  coefficient-wise product because the NTT pairs consecutive
  coefficients via `BaseCaseMultiply` (FIPS 203, §4.3.2):

      (c₀, c₁) := BaseCaseMultiply((a₀, a₁), (b₀, b₁), ζ)
                = (a₀·b₀ + a₁·b₁·ζ, a₀·b₁ + a₁·b₀)

  where ζ = ζ^{2·bitRev(i) + 1}.

  Covered functions (base file — shared defs + accumulate specs):

      mlkem.ntt.poly_element_mul_and_accumulate_loop
      mlkem.ntt.poly_element_mul_and_accumulate
      mlkem.ntt.poly_element_mul_and_accumulate_aux

  The remaining specs are split for parallel elaboration:
  - `MulAccumMontReduce.lean`: montgomery_reduce_and_add_*
  - `MulAccumDotProduct.lean`: vector_mont_dot_product_loop
  - `MulAccumWrapper.lean`: vector_mont_dot_product (top wrapper)

  ## Storage shape

  * Inputs `pe_src1`, `pe_src2 : Array U16 256` hold NTT-domain
    coefficients (`< q` each).
  * Output accumulator `pa_dst : Array U32 256` holds **un-reduced**
    32-bit accumulations across multiple row contributions.
  * After accumulating all `n_rows` rows, the final reduction step
    `montgomery_reduce_and_add_poly_element_accumulator_to_poly_element`
    applies a Montgomery reduction (one `R⁻¹` factor) and writes the
    result into the destination `pe_dst : Array U16 256`.

  ## Postcondition shape

  For `poly_element_mul_and_accumulate.spec`, the accumulator `pa_dst'`
  satisfies:
      `(toPoly_via_acc pa_dst') = (toPoly_via_acc pa_dst)
                                + R · MultiplyNTTs(toPoly pe_src1, toPoly pe_src2)`
  where `toPoly_via_acc` interprets the U32 array as a `Polynomial`
  with an extra `R` factor baked in (one Mont reduction pending).
  The exact statement is parametrised by a helper `accToPoly` that
  treats `pa_dst[i].val mod q · Rinv` as the `Zq` interpretation.

  For the final reduction step, the postcondition is
      `toPoly result = toPoly pe_dst + (Rinv · accToPoly pa_src) mod q`
  i.e., one Montgomery reduction applied on the accumulator.
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.MontArith
import Symcrust.Properties.MLKEM.Bridges.NttLinearity
import Symcrust.Properties.MLKEM.Bridges.Iterators
import Symcrust.Properties.MLKEM.Ntt.ModArith
import Symcrust.Properties.Axioms.System

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust
open Symcrust.Properties.MLKEM.Ntt (baseCaseMultiply0 baseCaseMultiply1)

namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 1000000

local macro_rules
| `(tactic| get_elem_tactic) => `(tactic| grind)

/-! ## Helper: interpret a U32 accumulator as a polynomial

The accumulator holds `R · MultiplyNTTs(a, b)` plus contributions from
prior rows, all mod 2³². Since each contribution is bounded by
`4·(MAX_COEFF_PRODUCT + MAX_A1_B1_ZETA_POW)` and `n_rows ≤ 4`, the
total fits in U32 without overflow (verified by `massert` checks in
the impl). -/

/-- View an accumulator coefficient as `Zq` (mod q). -/
noncomputable def accToZq (x : U32) : Zq := (x.val : Zq)

/-- View an accumulator array as a `Polynomial`. -/
noncomputable def accToPoly (a : PolyAccumulator) : MLKEM.Polynomial :=
  Vector.ofFn fun (i : Fin 256) => accToZq (a.val[i.val]'(by have := a.property; grind))

/-- A "bounded" accumulator: every coefficient ≤ `4·(MAX_COEFF² + MAX_FIRST·ZETA_MAX)`
where `ZETA_MAX = 3254` is the maximum value in the
`ZETA_TWO_TIMES_BIT_REV_PLUS_1_TIMES_R` table. Tight bound used as
both the post of `poly_element_mul_and_accumulate.spec` and the pre
of `montgomery_reduce_and_add_*.spec`. -/
def wfAcc (a : PolyAccumulator) : Prop :=
  ∀ (i : Nat) (h_i : i < 256),
    (a.val[i]'(by have := a.property; grind)).val ≤ 4 * (3328 * 3328 + 3494 * 3254)

/-! ## `MAX_*` constant `.eq` lemmas

The Aeneas extraction emits `MAX_*` constants as `@[irreducible]` opaque
defs.  These local `.eq` lemmas unfold them to concrete numerals so the
body proof can do bit-vector / scalar arithmetic on them. -/

@[local simp, local scalar_tac_simps, local grind =, local agrind =]
private theorem ntt_MAX_FIRST_STEP_REDUCTION_eq :
    mlkem.ntt.MAX_FIRST_STEP_REDUCTION = 3494#u32 := by
  unfold mlkem.ntt.MAX_FIRST_STEP_REDUCTION; rfl

@[local simp, local scalar_tac_simps, local grind =, local agrind =]
private theorem ntt_MAX_COEFF_PRODUCT_eq :
    mlkem.ntt.MAX_COEFF_PRODUCT = ok 11075584#u32 := by
  unfold mlkem.ntt.MAX_COEFF_PRODUCT
  simp [global_simps]; rfl

@[local simp, local scalar_tac_simps, local grind =, local agrind =]
private theorem ntt_MAX_A1_B1_ZETA_POW_eq :
    mlkem.ntt.MAX_A1_B1_ZETA_POW = ok 11369476#u32 := by
  unfold mlkem.ntt.MAX_A1_B1_ZETA_POW
  simp [global_simps]; rfl

/-- Total-form bridge from `toPoly` to the underlying `U16` array: for any
in-bounds index `i < 256`, `(toPoly a)[i] = u16ToZq (a.val[i]'h)`. This is
the canonical form; `getElem!_toPoly` below is a partial-access corollary
kept only for legacy call sites that operate in `!` form. -/
theorem getElem_toPoly (a : PolyElement) (i : Nat) (hi : i < 256) :
    (toPoly a)[i] = (u16ToZq (a.val[i]'(by have := a.property; grind))) := by
  unfold toPoly
  rw [Vector.getElem_ofFn]

/-- `getElem!`-bridge from `toPoly` to the underlying `U16` array: for any
in-bounds index `i < 256`, `(toPoly a)[i]! = u16ToZq (a.val[i]!)`. Derived
from the total form `getElem_toPoly` by two `getElem!_pos` conversions. -/
theorem getElem!_toPoly (a : PolyElement) (i : Nat) (hi : i < 256) :
    (toPoly a)[i]! = (u16ToZq (a.val[i]!)) := by
  rw [getElem!_pos _ i (by show i < (toPoly a).size; exact hi),
      getElem_toPoly a i hi,
      getElem!_pos a.val i (by have := a.property; grind)]

/-! ## Twiddle table for base-case multiplication

`ZETA_TWO_TIMES_BIT_REV_PLUS_1_TIMES_R[i]` stores `ζ^(2*bitRev 7 i + 1) * R mod q`
in u16 form. Used by `BaseCaseMultiply` at `i = 0..127`. -/

local step_array_spec (name := ntt_ZETA_TWO_TIMES_BIT_REV_PLUS_1_TIMES_R_spec)
  mlkem.ntt.ZETA_TWO_TIMES_BIT_REV_PLUS_1_TIMES_R[i]!
  { v =>
    BitVec.ofNat 32 v.val = BitVec.ofNat 32 ((17 ^ (2 * bitRev 7 i + 1) * 2^16) % 3329) ∧
    v.val = (17 ^ (2 * bitRev 7 i + 1) * 2^16) % 3329 ∧
    v.val ≤ 3254 }
  by
    native_decide


/-! ## `#decompose` cascade for `poly_element_mul_and_accumulate_loop`

The body has ~36 monadic ops (4 `FromU32U16` casts, 4 multiplies,
Montgomery-reduce step, ZETA lookup, 2 accumulator writes) + recursive
call.  Two-level decompose: first peel the `match` on the iterator's
`Option<Usize>` result; then within the `some` branch, peel the 59
`let`-bindings that form one iteration's work, leaving the trailing
recursive call as the continuation. -/

set_option maxRecDepth 4096 in
set_option maxHeartbeats 1000000 in
#decompose mlkem.ntt.poly_element_mul_and_accumulate_loop
    mlkem.ntt.poly_element_mul_and_accumulate_loop.match_eq
  letRange 1 1 => mlkem.ntt.poly_element_mul_and_accumulate_loop.match_helper

set_option maxRecDepth 4096 in
set_option maxHeartbeats 1000000 in
#decompose mlkem.ntt.poly_element_mul_and_accumulate_loop.match_helper
    mlkem.ntt.poly_element_mul_and_accumulate_loop.match_branch_eq
  branch 1 (letRange 0 59) => mlkem.ntt.poly_element_mul_and_accumulate_loop.body

/-! ## `poly_element_mul_and_accumulate_loop`

Inner loop iterating `i ∈ [iter.start.val, 128)`.  Each iteration
processes the coefficient pair `(2i, 2i+1)`: it computes the BaseCaseMultiply
of `(pe_src1[2i], pe_src1[2i+1])` against `(pe_src2[2i], pe_src2[2i+1])`
and adds the result into `pa_dst[2i], pa_dst[2i+1]`.

The body inlines a Montgomery reduction of the inner `a₁·b₁` product
(via the Montgomery factor `R⁻¹`), then *multiplies* the result by
`ZETA_BIT_REV_TIMES_R[i] = ζ^(2·bitRev 7 i + 1) · R`. The two `R`
factors cancel: `(a₁·b₁ · R⁻¹) · (ζ^k · R) = a₁·b₁ · ζ^k`. Hence the
post matches `baseCaseMultiply0/1` **without** any extra `R` factor.
The `R⁻¹` factor in `vector_mont_dot_product` comes from the final
Mont reduction in `montgomery_reduce_and_add_*`, NOT from the body. -/

/-! ## Body spec for `poly_element_mul_and_accumulate_loop.body`

Captures one iteration's effect on `pa_dst` at indices `2*i.val` and
`2*i.val+1`. The result equals `pa_dst` with two updates, where the
new values are bounded by `4 * (3328² + 3494·3254)` and the Zq value
matches `baseCaseMultiply0` / `baseCaseMultiply1`. -/

set_option maxHeartbeats 2000000 in
@[local step]
theorem mlkem.ntt.poly_element_mul_and_accumulate_loop.body.spec
    (pe_src1 pe_src2 : PolyElement)
    (pa_dst : PolyAccumulator)
    (i : Usize)
    (hi : i.val < 128)
    (h_wf1 : wfPoly pe_src1) (h_wf2 : wfPoly pe_src2)
    -- Asymmetric c0/c1 invariant (strict-c1 refactor):
    -- the c0 (even-slot) precondition is LOOSE because the Rust c0 assert is
    -- `c01 <= i24`; the c1 (odd-slot) precondition
    -- stays STRICT because the Rust c1 assert is `c11 < i27` = `5*M + 3*A`.
    (hAccBound2i : (pa_dst.val[2*i.val]'(by grind)).val
        ≤ 3 * (3328 * 3328 + 3494 * 3254))
    (hAccBound2i1 : (pa_dst.val[2*i.val+1]'(by grind)).val
        < 3 * (3328 * 3328 + 3494 * 3254)) :
    mlkem.ntt.poly_element_mul_and_accumulate_loop.body pe_src1 pe_src2 pa_dst i
      ⦃ a =>
        ∃ (j0 j1 : Usize) (v0 v1 : U32),
          j0.val = 2 * i.val ∧ j1.val = 2 * i.val + 1 ∧
          a = (pa_dst.set j0 v0).set j1 v1 ∧
          -- Even-slot uniform LOOSE bound `≤ 4*(M+A)` matches the patched
          -- c0 assert.  Odd-slot uniform STRICT bound `< 4*(M+A)` matches
          -- the unchanged c1 assert.
          v0.val ≤ 4 * (3328 * 3328 + 3494 * 3254) ∧
          v1.val < 4 * (3328 * 3328 + 3494 * 3254) ∧
          -- Additive LOOSE bound: one body call adds at most (M+A) per slot.
          -- Used by callers that maintain a uniform `pa_tmp[k] ≤ K*(M+A)`
          -- invariant.
          v0.val ≤ (pa_dst.val[2*i.val]'(by grind)).val
                    + (3328 * 3328 + 3494 * 3254) ∧
          v1.val ≤ (pa_dst.val[2*i.val+1]'(by grind)).val
                    + (3328 * 3328 + 3494 * 3254) ∧
          -- Additive TIGHT odd bound: `a0b11 ≤ 2*M`, so
          -- `c11 ≤ pa_dst[2i+1] + 2*M`.  Combined with a parallel odd
          -- invariant `pa_tmp[2j+1] ≤ K*2*M`, this gives the strict bound
          -- `pa_tmp[2j+1] < 3*(M+A)` needed to feed back into the strict
          -- c1 precondition `hAccBound2i1` at the next iteration.
          v1.val ≤ (pa_dst.val[2*i.val+1]'(by grind)).val
                    + 2 * (3328 * 3328) ∧
          ((v0.val : Zq) =
            ((pa_dst.val[2*i.val]'(by grind)).val : Zq) +
            baseCaseMultiply0 (toPoly pe_src1) (toPoly pe_src2) i.val) ∧
          ((v1.val : Zq) =
            ((pa_dst.val[2*i.val+1]'(by grind)).val : Zq) +
            baseCaseMultiply1 (toPoly pe_src1) (toPoly pe_src2) i.val) ⦄ := by
  unfold mlkem.ntt.poly_element_mul_and_accumulate_loop.body
  simp only [ntt_MAX_FIRST_STEP_REDUCTION_eq, ntt_MAX_COEFF_PRODUCT_eq,
             ntt_MAX_A1_B1_ZETA_POW_eq]
  -- Bridge total-form preconditions to `!` form so step*/bv_tac see uniform form
  -- (the postcondition stays in total form; we bridge it back at the 4 affected
  -- conjuncts via `rw [← getElem!_pos ...]`).
  replace hAccBound2i : (pa_dst.val[2*i.val]'(by grind)).val ≤ 3 * (3328 * 3328 + 3494 * 3254) := by
    grind
  replace hAccBound2i1 : (pa_dst.val[2*i.val+1]'(by grind)).val < 3 * (3328 * 3328 + 3494 * 3254) := by
    grind
  step*
  · -- 1. FromU32U16.from i2 < Q
    have hlen : pe_src1.val.length = 256 := by have := pe_src1.property; grind
    have h : ((↑pe_src1)[i1.val]'(by omega)).val < q :=
      h_wf1 i1.val (by grind)
    grind
  · -- 2. FromU32U16.from i4 < Q
    have hlen : pe_src1.val.length = 256 := by have := pe_src1.property; grind
    have h : ((↑pe_src1)[i3.val]'(by omega)).val < q :=
      h_wf1 i3.val (by grind)
    grind
  · -- 3. FromU32U16.from i5 < Q
    have hlen : pe_src2.val.length = 256 := by have := pe_src2.property; grind
    have h : ((↑pe_src2)[i1.val]'(by omega)).val < q :=
      h_wf2 i1.val (by grind)
    grind
  · -- 4. FromU32U16.from i7 < Q
    have hlen : pe_src2.val.length = 256 := by have := pe_src2.property; grind
    have h : ((↑pe_src2)[i6.val]'(by omega)).val < q :=
      h_wf2 i6.val (by grind)
    grind
  · -- 5. a1b11 ≤ 3494
    have hlen1 : pe_src1.val.length = 256 := by have := pe_src1.property; grind
    have hlen2 : pe_src2.val.length = 256 := by have := pe_src2.property; grind
    have ha1 : (core.convert.num.FromU32U16.from i4).val < 3329 := by
      have h : ((↑pe_src1)[i3.val]'(by omega)).val < q :=
        h_wf1 i3.val (by grind)
      grind
    have hb1 : (core.convert.num.FromU32U16.from i7).val < 3329 := by
      have h : ((↑pe_src2)[i6.val]'(by omega)).val < q :=
        h_wf2 i6.val (by grind)
      grind
    bv_tac 32
  · -- 9. ∃ j0 j1 v0 v1, ...
    refine ⟨i1, i28, c01, c11, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · -- j0.val = 2 * i.val
      exact i1_post
    · -- j1.val = 2 * i.val + 1
      rw [i28_post, i1_post]
    · -- a = (set pa_dst i1 c01).set i28 c11
      rw [a_post, pa_dst1_post]
    · -- c01.val ≤ 4 * (3328*3328 + 3494*3254) — LOOSE c0
      grind
    · -- c11.val < 4 * (3328*3328 + 3494*3254) — STRICT c1 (unchanged Rust assert)
      grind
    · -- additive LOOSE bound for v0: c01.val ≤ pa_dst[2i].val + (M+A)
      -- c01 = c0 + a0b01, c0 = pa_dst[i1]! = pa_dst[2*i]!, a0b01 ≤ i20 = M+A
      rw [← getElem!_pos pa_dst.val (2 * i.val) (by grind)]
      have hc0_eq : c0.val = pa_dst.val[2 * i.val]!.val := by grind
      grind
    · -- additive LOOSE bound for v1: c11.val ≤ pa_dst[2i+1].val + (M+A)
      -- c11 = c1 + a0b11, c1 = pa_dst[i12]! = pa_dst[2*i + 1]!, a0b11 ≤ i21 = 2*M
      -- Note: a0b11 ≤ 2*M ≤ M+A (since A > M), so the LOOSE bound holds.
      rw [← getElem!_pos pa_dst.val (2 * i.val + 1) (by grind)]
      have hc1_eq : c1.val = pa_dst.val[2 * i.val + 1]!.val := by grind
      grind
    · -- additive TIGHT-ODD bound for v1: c11.val ≤ pa_dst[2i+1].val + 2*M
      -- c11 = c1 + a0b11, c1 = pa_dst[2i+1], a0b11 ≤ i21 = 2*M.  Strictly tighter
      -- than the loose additive bound (since M < A); used by outer-loop callers to
      -- maintain the parallel odd invariant `pa_tmp[2j+1] ≤ K·2·M` and thereby
      -- derive the strict c1 precondition at the next iteration.
      rw [← getElem!_pos pa_dst.val (2 * i.val + 1) (by grind)]
      have hc1_eq : c1.val = pa_dst.val[2 * i.val + 1]!.val := by grind
      grind
    · -- (c01.val : Zq) = (pa_dst[2i].val : Zq) + baseCaseMultiply0 ...
      rw [← getElem!_pos pa_dst.val (2 * i.val) (by grind)]
      have hlen1 : pe_src1.val.length = 256 := by have := pe_src1.property; grind
      have hlen2 : pe_src2.val.length = 256 := by have := pe_src2.property; grind
      have hi4_lt : i4.val < 3329 := by
        have h : ((↑pe_src1)[i3.val]'(by omega)).val < q :=
          h_wf1 i3.val (by grind)
        grind
      have hi7_lt : i7.val < 3329 := by
        have h : ((↑pe_src2)[i6.val]'(by omega)).val < q :=
          h_wf2 i6.val (by grind)
        grind
      have hi2_lt : i2.val < 3329 := by
        have h : ((↑pe_src1)[i1.val]'(by omega)).val < q :=
          h_wf1 i1.val (by grind)
        grind
      have hi5_lt : i5.val < 3329 := by
        have h : ((↑pe_src2)[i1.val]'(by omega)).val < q :=
          h_wf2 i1.val (by grind)
        grind
      have ha1b1_bound : a1b1.val ≤ 4 * (3328 * 3328 + 3494 * 3254) := by
        rw [a1b1_post, core.convert.num.FromU32U16.from_val_eq,
            core.convert.num.FromU32U16.from_val_eq]
        scalar_tac +nonLin
      have hi15_bv : i15.bv = (core.num.U32.wrapping_mul a1b1 mlkem.ntt.NEG_Q_INV_MOD_R).bv := by
        rw [i15_post]
      have hi16_bv : i16.bv = inv.bv * mlkem.ntt.Q.bv := by natify; grind
      have hi17_bv : i17.bv = a1b1.bv + i16.bv := by natify; grind
      have ha1b11_bv : a1b11.bv = i17.bv >>> 16 := by natify; grind
      have hMR := mont_reduce_single_u32.spec a1b1 i15 inv i16 i17 a1b11
        ha1b1_bound hi15_bv inv_post2 hi16_bv hi17_bv ha1b11_bv
      have ha1b11_zq : (a1b11.val : Zq) = (a1b1.val : Zq) * (U16.size : Zq)⁻¹ := hMR.1
      have hi19_val : i19.val = i18.val := by
        rw [i19_post]; simp [UScalar.cast]
        show (BitVec.setWidth 32 i18.bv).toNat = i18.val
        rw [BitVec.toNat_setWidth]
        apply Nat.mod_eq_of_lt
        have : i18.val < 2^16 := i18.hBounds
        omega
      have hi18_zq : ((i18.val : ℕ) : Zq) =
          (17 : Zq) ^ (2 * bitRev 7 i.val + 1) * (65536 : Zq) := by
        rw [i18_post2, ZMod.natCast_mod]
        push_cast
        rfl
      rw [c01_post]; push_cast
      rw [c0_post, a0b01_post]; push_cast
      rw [a0b0_post, a1b1zetapow_post]; push_cast
      rw [ha1b11_zq, hi19_val, hi18_zq, a1b1_post]
      push_cast
      rw [core.convert.num.FromU32U16.from_val_eq, core.convert.num.FromU32U16.from_val_eq,
          core.convert.num.FromU32U16.from_val_eq, core.convert.num.FromU32U16.from_val_eq]
      rw [i2_post, i5_post, i4_post, i7_post]
      --rw [i3_post, i6_post, i1_post]
      unfold baseCaseMultiply0
      simp only [getElem!_toPoly _ _ (by grind : 2 * i.val < 256),
                 getElem!_toPoly _ _ (by grind : 2 * i.val + 1 < 256)]
      show _ = _
      have hU16 : ((U16.size : Nat) : Zq) = 65536 := by
        simp [U16.size, U16.numBits]
      have hζ : (ζ : Zq) = 17 := rfl
      rw [hU16, hζ]
      have hkey : (65536 : Zq)⁻¹ * 38845 = 17 := by
        rw [ZMod.inv_eq_of_mul_eq_one q 65536 169 (by decide)]; decide
      ring_nf
      rw [show ∀ (B : Zq) (k : ℕ),
            B * 65536⁻¹ * (17 : Zq)^k * 38845 = B * (17 : Zq)^k * 17 by
          intros B k; rw [show B * 65536⁻¹ * (17 : Zq)^k * 38845
                              = B * (17 : Zq)^k * (65536⁻¹ * 38845) by ring,
                          hkey]]
      grind
    · -- (c11.val : Zq) = (pa_dst[2i+1].val : Zq) + baseCaseMultiply1 ...
      rw [← getElem!_pos pa_dst.val (2 * i.val + 1) (by grind)]
      rw [c11_post]; push_cast
      rw [c1_post, a0b11_post]; push_cast
      rw [a0b1_post, a1b0_post]; push_cast
      rw [core.convert.num.FromU32U16.from_val_eq,
          core.convert.num.FromU32U16.from_val_eq,
          core.convert.num.FromU32U16.from_val_eq,
          core.convert.num.FromU32U16.from_val_eq]
      rw [i2_post, i5_post, i4_post, i7_post]

      --rw [i3_post, i6_post, i12_post, i1_post]
      unfold baseCaseMultiply1
      simp only [getElem!_toPoly _ _ (by grind : 2 * i.val < 256),
                 getElem!_toPoly _ _ (by grind : 2 * i.val + 1 < 256)]
      grind

set_option maxHeartbeats 4000000 in
/-- **Loop spec** for the inner mul-and-accumulate body.

Per-index half-open form: at the cursor `iter.start.val`, slots
`[0, 2·iter.start.val)` have been touched (bounded `≤ 4·MAX`), slots
`[2·iter.start.val, 256)` are untouched-this-pass (bounded `≤ 3·MAX`).
The post says: below-cursor slots are unchanged; at-and-above slots
get the per-pair `baseCaseMultiply0/1` contribution.

Informal proof. Canonical Range-loop induction on the cursor,
decreasing `128 - iter.start.val`. Body call delivers `body.spec`
which witnesses one `BaseCaseMultiply` step. IH closes the tail. -/
@[local step]
theorem mlkem.ntt.poly_element_mul_and_accumulate_loop.spec
    (iter : core.ops.range.Range Usize)
    (pe_src1 pe_src2 : PolyElement)
    (pa_dst : PolyAccumulator)
    (h_wf1 : wfPoly pe_src1) (h_wf2 : wfPoly pe_src2)
    (h_end : iter.«end».val = 128)
    (h_start : iter.start.val ≤ 128)
    (hAccBoundBelow : ∀ k (hk : k < 2 * iter.start.val),
      pa_dst.val[k].val
        ≤ 4 * (3328 * 3328 + 3494 * 3254))
    -- Asymmetric c0/c1 invariant.  Even (c0) slots have the LOOSE
    -- precondition `≤ 3*(M+A)` (matches the patched Rust `<=` assert); odd (c1)
    -- slots keep the STRICT `<` precondition (matches the unpatched Rust `<` assert).
    (hAccBoundAboveEven : ∀ j (_hj_ge : iter.start.val ≤ j) (hj_lt : j < 128),
      (pa_dst.val[2*j]).val ≤ 3 * (3328 * 3328 + 3494 * 3254))
    (hAccBoundAboveOdd : ∀ j (_hj_ge : iter.start.val ≤ j) (hj_lt : j < 128),
      pa_dst.val[2*j+1].val < 3 * (3328 * 3328 + 3494 * 3254)) :
    mlkem.ntt.poly_element_mul_and_accumulate_loop iter pe_src1 pe_src2 pa_dst
      ⦃ (pa_dst' : PolyAccumulator) =>
        (∀ k (hk : k < 2 * iter.start.val),
          pa_dst'.val[k].val
            = pa_dst.val[k].val) ∧
        (∀ i (_hi_ge : iter.start.val ≤ i) (hi_lt : i < 128),
          (pa_dst'.val[2*i].val : Zq)
            = (pa_dst.val[2*i].val : Zq)
              + baseCaseMultiply0 (toPoly pe_src1) (toPoly pe_src2) i ∧
          (pa_dst'.val[2*i+1].val : Zq)
            = (pa_dst.val[2*i+1].val : Zq)
              + baseCaseMultiply1 (toPoly pe_src1) (toPoly pe_src2) i) ∧
        (∀ k (hk : k < 256),
          pa_dst'.val[k].val ≤ 4 * (3328 * 3328 + 3494 * 3254)) ∧
        -- Additive LOOSE bound for slots processed by this call (above-cursor):
        -- one body call adds at most (M+A) per slot. Carried forward to outer
        -- loops via `vector_mont_dot_product_loop.spec`.
        (∀ k (_hk_ge : 2 * iter.start.val ≤ k) (hk_lt : k < 256),
          pa_dst'.val[k].val
            ≤ pa_dst.val[k].val
              + (3328 * 3328 + 3494 * 3254)) ∧
        -- Additive TIGHT-ODD bound: each odd slot 2j+1 that this
        -- call touches grows by at most 2*M (vs the loose (M+A) above).  Each
        -- j ∈ [iter.start, 128) is touched exactly once by the loop body.
        -- This is what enables the outer dot-product loop to maintain the
        -- parallel invariant `pa_tmp[2j+1] ≤ K · 2M` and thereby derive the
        -- strict c1 precondition for the next row.
        (∀ j (_hj_ge : iter.start.val ≤ j) (hj_lt : j < 128),
          pa_dst'.val[2*j+1].val
            ≤ pa_dst.val[2*j+1].val
              + 2 * (3328 * 3328)) ⦄ := by
  rw [mlkem.ntt.poly_element_mul_and_accumulate_loop.match_eq]
  -- Bridge total-form preconditions to `!`-form so the existing `simp_lists`-
  -- based proof body (which traffics in `!`) continues to work. We re-bridge
  -- back to total at the final `refine`.
  replace hAccBoundBelow : ∀ k, k < 2 * iter.start.val →
      pa_dst.val[k]!.val ≤ 4 * (3328 * 3328 + 3494 * 3254) := by
    intro k hk
    rw [getElem!_pos pa_dst.val k (by grind)]
    exact hAccBoundBelow k hk
  replace hAccBoundAboveEven : ∀ j, iter.start.val ≤ j → j < 128 →
      pa_dst.val[2*j]!.val ≤ 3 * (3328 * 3328 + 3494 * 3254) := by
    intro j hj_ge hj_lt
    rw [getElem!_pos pa_dst.val (2*j) (by grind)]
    exact hAccBoundAboveEven j hj_ge hj_lt
  replace hAccBoundAboveOdd : ∀ j, iter.start.val ≤ j → j < 128 →
      pa_dst.val[2*j+1]!.val < 3 * (3328 * 3328 + 3494 * 3254) := by
    intro j hj_ge hj_lt
    rw [getElem!_pos pa_dst.val (2*j+1) (by grind)]
    exact hAccBoundAboveOdd j hj_ge hj_lt
  by_cases hlt : iter.start.val < iter.end.val
  · -- some branch: iterator yields i = iter.start
    let* ⟨ o, iter1, ho_some, hiter1_start, hiter1_end ⟩ ←
      IteratorRange_next_Usize_some
    rw [ho_some, mlkem.ntt.poly_element_mul_and_accumulate_loop.match_branch_eq]
    have hi_lt : iter.start.val < 128 := by grind
    have hi_lt2 : 2 * iter.start.val < 256 := by grind
    have hi_lt2' : 2 * iter.start.val + 1 < 256 := by grind
    have hAccBound2i : pa_dst.val[2*iter.start.val].val
        ≤ 3 * (3328 * 3328 + 3494 * 3254) := by grind
    have hAccBound2i1 : pa_dst.val[2*iter.start.val+1].val
        < 3 * (3328 * 3328 + 3494 * 3254) := by grind
    let* ⟨ j0, j1, v0, v1, a, hj0, hj1, ha_eq, hv0_lt, hv1_lt,
           hv0_add_tot, hv1_add_tot, hv1_tight_tot, hv0_zq_tot, hv1_zq_tot ⟩ ←
      mlkem.ntt.poly_element_mul_and_accumulate_loop.body.spec
        pe_src1 pe_src2 pa_dst iter.start hi_lt h_wf1 h_wf2
        hAccBound2i hAccBound2i1
    -- Bridge total-form post-conditions back to `!`-form so the existing
    -- proof body (written against the `!` outer signature) goes through.
    have hv0_add : v0.val ≤ pa_dst.val[2*iter.start.val]!.val
                              + (3328 * 3328 + 3494 * 3254) := by
      rw [getElem!_pos pa_dst.val _ (by grind)]; exact hv0_add_tot
    have hv1_add : v1.val ≤ pa_dst.val[2*iter.start.val+1]!.val
                              + (3328 * 3328 + 3494 * 3254) := by
      rw [getElem!_pos pa_dst.val _ (by grind)]; exact hv1_add_tot
    have hv1_tight : v1.val ≤ pa_dst.val[2*iter.start.val+1]!.val
                              + 2 * (3328 * 3328) := by
      rw [getElem!_pos pa_dst.val _ (by grind)]; exact hv1_tight_tot
    have hv0_zq : (v0.val : Zq) = (pa_dst.val[2*iter.start.val]!.val : Zq)
        + baseCaseMultiply0 (toPoly pe_src1) (toPoly pe_src2) iter.start.val := by
      rw [getElem!_pos pa_dst.val _ (by grind)]; exact hv0_zq_tot
    have hv1_zq : (v1.val : Zq) = (pa_dst.val[2*iter.start.val+1]!.val : Zq)
        + baseCaseMultiply1 (toPoly pe_src1) (toPoly pe_src2) iter.start.val := by
      rw [getElem!_pos pa_dst.val _ (by grind)]; exact hv1_zq_tot
    have hiter1_end_val : iter1.end.val = 128 := by rw [hiter1_end]; exact h_end
    have hiter1_start_le : iter1.start.val ≤ 128 := by rw [hiter1_start]; grind
    have ha_val_eq : a.val = ((pa_dst.val.set j0.val v0).set j1.val v1) := by
      rw [ha_eq, Std.Array.set_val_eq, Std.Array.set_val_eq]
    have hAccBoundBelow' : ∀ k, (_ : k < 2 * iter1.start.val) →
        a.val[k].val ≤ 4 * (3328 * 3328 + 3494 * 3254) := by
      intro k hk
      have hkB : k < 2 * iter.start.val + 2 := by rw [hiter1_start] at hk; grind
      by_cases hk1 : k = j1.val
      · simp_lists
        grind
      · simp_lists [hk1]
        by_cases hk0 : k = j0.val
        · simp_lists
          grind
        · simp_lists [hk0]
          by_cases hkBl : k < 2 * iter.start.val
          · grind
          · exfalso; rw [hj0] at hk0; rw [hj1] at hk1; grind
    -- Build the asymmetric above-bounds for the recursive call
    have hAccBoundAboveEven' : ∀ jj, iter1.start.val ≤ jj → jj < 128 →
        a.val[2*jj]!.val ≤ 3 * (3328 * 3328 + 3494 * 3254) := by
      intro jj hjj_ge hjj_lt
      have hjj_gt : iter.start.val < jj := by rw [hiter1_start] at hjj_ge; grind
      rw [ha_val_eq]
      have hne1 : j1.val ≠ 2 * jj := by rw [hj1]; grind
      have hne0 : j0.val ≠ 2 * jj := by rw [hj0]; grind
      simp_lists [hne1, hne0]
      grind
    have hAccBoundAboveOdd' : ∀ jj, iter1.start.val ≤ jj → jj < 128 →
        a.val[2*jj+1]!.val < 3 * (3328 * 3328 + 3494 * 3254) := by
      intro jj hjj_ge hjj_lt
      have hjj_gt : iter.start.val < jj := by rw [hiter1_start] at hjj_ge; grind
      rw [ha_val_eq]
      have hne1 : j1.val ≠ 2 * jj + 1 := by rw [hj1]; grind
      have hne0 : j0.val ≠ 2 * jj + 1 := by rw [hj0]; grind
      simp_lists [hne1, hne0]
      grind
    apply WP.spec_mono
      (mlkem.ntt.poly_element_mul_and_accumulate_loop.spec iter1 pe_src1 pe_src2 a
        h_wf1 h_wf2 hiter1_end_val hiter1_start_le
        (by grind)
        (by grind)
        (by grind))
    rintro pa_dst' ⟨ hbelow_tot, habove_tot, hboundAll_tot, hadd_tot, hadd_tight_tot ⟩
    -- Bridge IH's total-form outputs to `!` form for the existing internal
    -- proof body. Each conjunct is bridged at the final `refine` back to total.
    have hbelow : ∀ k, k < 2 * iter1.start.val →
        pa_dst'.val[k]!.val = a.val[k]!.val := by
      intro k hk
      rw [getElem!_pos pa_dst'.val k (by have := hiter1_start_le; grind),
          getElem!_pos a.val k (by have := hiter1_start_le; grind)]
      exact hbelow_tot k hk
    have habove : ∀ ii, iter1.start.val ≤ ii → ii < 128 →
        (pa_dst'.val[2*ii]!.val : Zq)
          = (a.val[2*ii]!.val : Zq)
            + baseCaseMultiply0 (toPoly pe_src1) (toPoly pe_src2) ii ∧
        (pa_dst'.val[2*ii+1]!.val : Zq)
          = (a.val[2*ii+1]!.val : Zq)
            + baseCaseMultiply1 (toPoly pe_src1) (toPoly pe_src2) ii := by
      intro ii hii_ge hii_lt
      have ⟨h0, h1⟩ := habove_tot ii hii_ge hii_lt
      refine ⟨?_, ?_⟩
      · rw [getElem!_pos pa_dst'.val (2*ii) (by grind),
            getElem!_pos a.val (2*ii) (by grind)]
        exact h0
      · rw [getElem!_pos pa_dst'.val (2*ii+1) (by grind),
            getElem!_pos a.val (2*ii+1) (by grind)]
        exact h1
    have hboundAll : ∀ k, k < 256 →
        pa_dst'.val[k]!.val ≤ 4 * (3328 * 3328 + 3494 * 3254) := by
      intro k hk
      rw [getElem!_pos pa_dst'.val k (by grind)]
      exact hboundAll_tot k hk
    have hadd : ∀ k, 2 * iter1.start.val ≤ k → k < 256 →
        pa_dst'.val[k]!.val ≤ a.val[k]!.val + (3328 * 3328 + 3494 * 3254) := by
      intro k hk_ge hk_lt
      rw [getElem!_pos pa_dst'.val k (by grind),
          getElem!_pos a.val k (by grind)]
      exact hadd_tot k hk_ge hk_lt
    have hadd_tight : ∀ jj, iter1.start.val ≤ jj → jj < 128 →
        pa_dst'.val[2*jj+1]!.val ≤ a.val[2*jj+1]!.val + 2 * (3328 * 3328) := by
      intro jj hjj_ge hjj_lt
      rw [getElem!_pos pa_dst'.val (2*jj+1) (by grind),
          getElem!_pos a.val (2*jj+1) (by grind)]
      exact hadd_tight_tot jj hjj_ge hjj_lt
    refine ⟨ ?_, ?_, ?_, ?_, ?_ ⟩
    · -- below: ∀ k < 2*iter.start.val, pa_dst'[k] = pa_dst[k] (total form)
      intro k hk
      rw [show pa_dst'.val[k] = pa_dst'.val[k]! from
           (getElem!_pos pa_dst'.val k (by grind)).symm,
          show pa_dst.val[k] = pa_dst.val[k]! from
           (getElem!_pos pa_dst.val k (by grind)).symm]
      have hk_lt_iter1 : k < 2 * iter1.start.val := by rw [hiter1_start]; grind
      rw [hbelow k hk_lt_iter1, ha_val_eq]
      have hne1 : j1.val ≠ k := by rw [hj1]; grind
      have hne0 : j0.val ≠ k := by rw [hj0]; grind
      simp_lists [hne1, hne0]
    · -- above: ∀ ii, iter.start.val ≤ ii < 128 (total form)
      intro ii hii_ge hii_lt
      rw [show pa_dst'.val[2*ii] = pa_dst'.val[2*ii]! from
           (getElem!_pos pa_dst'.val (2*ii) (by grind)).symm,
          show pa_dst.val[2*ii] = pa_dst.val[2*ii]! from
           (getElem!_pos pa_dst.val (2*ii) (by grind)).symm,
          show pa_dst'.val[2*ii+1] = pa_dst'.val[2*ii+1]! from
           (getElem!_pos pa_dst'.val (2*ii+1) (by grind)).symm,
          show pa_dst.val[2*ii+1] = pa_dst.val[2*ii+1]! from
           (getElem!_pos pa_dst.val (2*ii+1) (by grind)).symm]
      by_cases hii_eq : ii = iter.start.val
      · -- ii = iter.start: just-written slots
        have h2ii_lt_iter1 : 2 * ii < 2 * iter1.start.val := by
          rw [hiter1_start, hii_eq]; grind
        have h2ii1_lt_iter1 : 2 * ii + 1 < 2 * iter1.start.val := by
          rw [hiter1_start, hii_eq]; grind
        have heq0 := hbelow (2 * ii) h2ii_lt_iter1
        have heq1 := hbelow (2 * ii + 1) h2ii1_lt_iter1
        grind
      · -- ii > iter.start: use IH
        have hii_gt : iter.start.val < ii := by grind
        have hii_ge_iter1 : iter1.start.val ≤ ii := by rw [hiter1_start]; grind
        have ⟨ hpa0, hpa1 ⟩ := habove ii hii_ge_iter1 hii_lt
        have ha_eq_2ii : a.val[2*ii]!.val = pa_dst.val[2*ii]!.val := by
          rw [ha_val_eq]
          have hne1 : j1.val ≠ 2 * ii := by rw [hj1]; grind
          have hne0 : j0.val ≠ 2 * ii := by rw [hj0]; grind
          simp_lists [hne1, hne0]
        have ha_eq_2ii1 : a.val[2*ii + 1]!.val = pa_dst.val[2*ii + 1]!.val := by
          rw [ha_val_eq]
          have hne1 : j1.val ≠ 2 * ii + 1 := by rw [hj1]; grind
          have hne0 : j0.val ≠ 2 * ii + 1 := by rw [hj0]; grind
          simp_lists [hne1, hne0]
        rw [ha_eq_2ii] at hpa0
        rw [ha_eq_2ii1] at hpa1
        exact ⟨ hpa0, hpa1 ⟩
    · -- hboundAll bridge: IH gave it; conclude in total form
      intro k hk
      rw [show pa_dst'.val[k] = pa_dst'.val[k]! from
           (getElem!_pos pa_dst'.val k (by grind)).symm]
      exact hboundAll k hk
    · -- additive: ∀ k, 2*iter.start.val ≤ k < 256 (total form)
      intro k hk_ge hk_lt
      rw [show pa_dst'.val[k] = pa_dst'.val[k]! from
           (getElem!_pos pa_dst'.val k (by grind)).symm,
          show pa_dst.val[k] = pa_dst.val[k]! from
           (getElem!_pos pa_dst.val k (by grind)).symm]
      by_cases hk_eq0 : k = 2 * iter.start.val
      · -- k = 2*iter.start.val (= j0): pa_dst'[k] = a[k] (IH below) = v0
        grind
      · by_cases hk_eq1 : k = 2 * iter.start.val + 1
        · -- k = 2*iter.start.val + 1 (= j1): pa_dst'[k] = a[k] = v1
          have hk_lt_iter1 : k < 2 * iter1.start.val := by
            rw [hiter1_start, hk_eq1]; grind
          rw [hbelow k hk_lt_iter1, ha_val_eq]
          have heq1' : j1.val = k := by rw [hj1, hk_eq1]
          simp_lists [heq1']
          grind
        · -- k ≥ 2*iter.start.val + 2 = 2*iter1.start.val: use IH additive
          have hk_ge_iter1 : 2 * iter1.start.val ≤ k := by
            rw [hiter1_start]; grind
          have hia := hadd k hk_ge_iter1 hk_lt
          have ha_eq_k : a.val[k]!.val = pa_dst.val[k]!.val := by
            rw [ha_val_eq]
            have hne1 : j1.val ≠ k := by rw [hj1]; grind
            have hne0 : j0.val ≠ k := by rw [hj0]; grind
            simp_lists [hne1, hne0]
          rw [ha_eq_k] at hia
          exact hia
    · -- additive TIGHT-ODD: ∀ j ∈ [iter.start, 128), pa_dst'[2j+1] ≤ pa_dst[2j+1] + 2M
      intro jj hjj_ge hjj_lt
      rw [show pa_dst'.val[2*jj+1] = pa_dst'.val[2*jj+1]! from
           (getElem!_pos pa_dst'.val (2*jj+1) (by grind)).symm,
          show pa_dst.val[2*jj+1] = pa_dst.val[2*jj+1]! from
           (getElem!_pos pa_dst.val (2*jj+1) (by grind)).symm]
      by_cases hjj_eq : jj = iter.start.val
      · -- jj = iter.start: just-written odd slot 2*jj+1 = j1; use hv1_tight
        grind
      · -- jj > iter.start: use IH tight-odd
        grind
  · -- none branch
    have hge : iter.start.val ≥ iter.end.val := by grind
    let* ⟨ o, iter1, ho_none, hiter1_eq ⟩ ←
      IteratorRange_next_Usize_none
    rw [ho_none, mlkem.ntt.poly_element_mul_and_accumulate_loop.match_branch_eq]
    simp only [WP.spec_ok]
    refine ⟨ ?_, ?_, ?_, ?_, ?_ ⟩
    · intro k hk; trivial
    · intro ii hii_ge hii_lt
      have hi128 : iter.start.val = 128 := by grind
      rw [hi128] at hii_ge; grind
    · intro k hk
      rw [show pa_dst.val[k] = pa_dst.val[k]! from
           (getElem!_pos pa_dst.val k (by grind)).symm]
      by_cases hkb : k < 2 * iter.start.val
      · exact hAccBoundBelow k hkb
      · -- k ≥ 2*iter.start.val.  But iter.start = 128 so k ≥ 256, contradiction.
        have hi128 : iter.start.val = 128 := by grind
        rw [hi128] at hkb; grind
    · -- additive: vacuous since no k ≥ 2*iter.start.val = 256
      intro k hk_ge hk_lt
      have hi128 : iter.start.val = 128 := by grind
      rw [hi128] at hk_ge; grind
    · -- tight-odd: vacuous since jj ≥ iter.start.val = 128 ≥ 128 (no jj)
      intro jj hjj_ge hjj_lt
      have hi128 : iter.start.val = 128 := by grind
      rw [hi128] at hjj_ge; grind
  termination_by iter.end.val - iter.start.val
  decreasing_by scalar_decr_tac

/-- **Wrapper spec** for `poly_element_mul_and_accumulate` — full FC.

Informal proof. Leaf wrapper: `unfold` the function body — the
impl constructs `iter = Range 0 128` and calls
`poly_element_mul_and_accumulate_loop`. Apply
`poly_element_mul_and_accumulate_loop.spec` (with `iter.start.val = 0`,
`iter.«end».val = 128`); the "below" clause is vacuous
(`k < 0` impossible), and the "above" clause gives
`pa_dst'[2i] = pa_dst[2i] + baseCaseMultiply0 ...` for all `i < 128`. -/
@[step]
theorem mlkem.ntt.poly_element_mul_and_accumulate.spec
    (pe_src1 pe_src2 : PolyElement)
    (pa_dst : PolyAccumulator)
    (h_wf1 : wfPoly pe_src1) (h_wf2 : wfPoly pe_src2)
    -- Asymmetric c0/c1 invariant.
    (hAccBoundEven : ∀ j (hj : j < 128),
      pa_dst.val[2*j].val ≤ 3 * (3328 * 3328 + 3494 * 3254))
    (hAccBoundOdd : ∀ j (hj : j < 128),
      pa_dst.val[2*j+1].val < 3 * (3328 * 3328 + 3494 * 3254)) :
    mlkem.ntt.poly_element_mul_and_accumulate pe_src1 pe_src2 pa_dst
      ⦃ (pa_dst' : PolyAccumulator) =>
        (∀ i (hi : i < 128),
          (pa_dst'.val[2*i].val : Zq)
            = (pa_dst.val[2*i].val : Zq)
              + baseCaseMultiply0 (toPoly pe_src1) (toPoly pe_src2) i ∧
          (pa_dst'.val[2*i+1].val : Zq)
            = (pa_dst.val[2*i+1].val : Zq)
              + baseCaseMultiply1 (toPoly pe_src1) (toPoly pe_src2) i) ∧
        (∀ k (hk : k < 256),
          pa_dst'.val[k].val ≤ 4 * (3328 * 3328 + 3494 * 3254)) ∧
        -- Additive LOOSE bound: one call to `poly_element_mul_and_accumulate`
        -- adds at most (M+A) per slot. Used to maintain the LOOSE inductive
        -- invariant in `vector_mont_dot_product_loop.spec`.
        (∀ k (hk : k < 256),
          pa_dst'.val[k].val
            ≤ pa_dst.val[k].val
              + (3328 * 3328 + 3494 * 3254)) ∧
        -- Additive TIGHT-ODD bound: each odd slot 2j+1 grows by at
        -- most 2*M.  Strictly tighter than the LOOSE bound (since A > M).  Used
        -- by `vector_mont_dot_product_loop.spec` to maintain the parallel odd
        -- invariant `pa_tmp[2j+1] ≤ K · 2M` and derive the strict c1 precondition.
        (∀ j (hj : j < 128),
          pa_dst'.val[2*j+1].val
            ≤ pa_dst.val[2*j+1].val
              + 2 * (3328 * 3328)) ⦄ := by
  unfold mlkem.ntt.poly_element_mul_and_accumulate
  step as ⟨n2, hn2⟩
  apply WP.spec_mono <| mlkem.ntt.poly_element_mul_and_accumulate_loop.spec
    { start := 0#usize, «end» := n2 }
    pe_src1 pe_src2 pa_dst h_wf1 h_wf2
    (by simp [hn2]) (by simp)
    (by intros _ hk; simp at hk)
    (by intro j _ hj; exact hAccBoundEven j hj)
    (by intro j _ hj; exact hAccBoundOdd j hj)
  rintro pa_dst' ⟨_hUnchanged, hZq, hBound, hAdd, hAddTight⟩
  refine ⟨fun i hi => hZq i (Nat.zero_le _) hi, hBound, ?_, ?_⟩
  · intro k hk; exact hAdd k (by simp) hk
  · intro j hj; exact hAddTight j (by simp) hj

/-! ## `poly_element_mul_and_accumulate_aux`

Thin wrapper indexing into `pm_src1[i*n_rows + j]` and delegating. -/

/-- **Spec for `poly_element_mul_and_accumulate_aux`** — thin wrapper.

Informal proof. The impl body is a single `Slice.index` (via
`U.checked_mul`/`U.checked_add` to compute `i*n_rows + j`), then a
delegate call to `poly_element_mul_and_accumulate`. Discharge:
`step` through the index arithmetic (`U.checked_mul.spec`,
`U.checked_add.spec`, `Slice.index.spec` — bounds from `h_idx`),
then apply `poly_element_mul_and_accumulate.spec`. The post is
identical mod the index substitution. `agrind` closes residual
side conditions. -/
@[step]
theorem mlkem.ntt.poly_element_mul_and_accumulate_aux.spec
    (pm_src1 : Slice PolyElement) (n_rows i j : Usize)
    (pe_src2 : PolyElement)
    (pa_tmp : PolyAccumulator)
    (h_wf_pm : wfPolyVec pm_src1)
    (h_wf2 : wfPoly pe_src2)
    -- Asymmetric c0/c1 invariant.
    (hAccBoundEven : ∀ jj (hjj : jj < 128),
      pa_tmp.val[2*jj].val ≤ 3 * (3328 * 3328 + 3494 * 3254))
    (hAccBoundOdd : ∀ jj (hjj : jj < 128),
      pa_tmp.val[2*jj+1].val < 3 * (3328 * 3328 + 3494 * 3254))
    (h_idx : (i.val * n_rows.val + j.val) < pm_src1.length) :
    mlkem.ntt.poly_element_mul_and_accumulate_aux pm_src1 n_rows i j pe_src2 pa_tmp
      ⦃ (pa_tmp' : PolyAccumulator) =>
        (∀ ii (hii : ii < 128),
          (pa_tmp'.val[2*ii].val : Zq)
            = (pa_tmp.val[2*ii].val : Zq)
              + baseCaseMultiply0
                  (toPoly (pm_src1.val[i.val * n_rows.val + j.val]'h_idx))
                  (toPoly pe_src2) ii ∧
          (pa_tmp'.val[2*ii+1].val : Zq)
            = (pa_tmp.val[2*ii+1].val : Zq)
              + baseCaseMultiply1
                  (toPoly (pm_src1.val[i.val * n_rows.val + j.val]'h_idx))
                  (toPoly pe_src2) ii) ∧
        (∀ k (hk : k < 256),
          pa_tmp'.val[k].val ≤ 4 * (3328 * 3328 + 3494 * 3254)) ∧
        -- Additive LOOSE bound propagated from `_accumulate.spec`.
        (∀ k (hk : k < 256),
          pa_tmp'.val[k].val
            ≤ pa_tmp.val[k].val
              + (3328 * 3328 + 3494 * 3254)) ∧
        -- Additive TIGHT-ODD bound propagated from `_accumulate.spec`.
        (∀ jj (hjj : jj < 128),
          pa_tmp'.val[2*jj+1].val
            ≤ pa_tmp.val[2*jj+1].val
              + 2 * (3328 * 3328)) ⦄ := by
  unfold mlkem.ntt.poly_element_mul_and_accumulate_aux
  step*
  · grind
  · grind
  · grind [wfPolyVec]
  · grind

/-! ## Final Montgomery reduction + add

`montgomery_reduce_and_add_poly_element_accumulator_to_poly_element`
walks the accumulator and the destination in parallel, applying one
Montgomery reduction (`x ↦ x · R⁻¹ mod q`) to each accumulator entry,
adding it to the destination, and zeroing the accumulator slot. -/

end Symcrust.Properties.MLKEM
