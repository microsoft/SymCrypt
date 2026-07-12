/-
  # Sampling/SampleCBD.lean — `poly_element_sample_cbd_from_bytes`.

  Implements FIPS 203 Algorithm 8 (SamplePolyCBD_η): centered binomial
  distribution sampler.  Given `64·η` bytes, produces 256 coefficients
  in `{-η, …, η} ⊂ Zq`.

  Two specialized paths:
  * `eta = 3`: 6 bits per coefficient, 4 coefficients per 24-bit chunk
    (3 source bytes), via popcount-then-subtract.
  * `eta = 2`: 4 bits per coefficient, 8 coefficients per 32-bit chunk
    (4 source bytes), same popcount technique.

  ## Structure-vs-body decomposition

  Each of the 4 loops in this file follows the standard Aeneas
  `let (o, iter1) ← next iter; match o with | none => …  | some j =>
  …body…; recurse` shape.  We apply the two-clause `#decompose`
  recipe to peel off the per-iteration body so that:

  * `<loop>_body` — non-recursive helper that performs one iteration
    of work (one coefficient for `_loop0` inner loops, one 4- or
    8-coefficient chunk for the outer loops).  Has its own `@[step]`
    spec that any proof of the loop can consume via `step*`.
  * `<loop>_match.fold` — per-iteration dispatch (`match o with …`)
    expressed in terms of the body helper and the recursive call.
  * `<loop>.fold` — top-level equation `loop iter = do let (o, iter1)
    ← next; <match-helper> o iter1`.

  The loop spec itself is then proved by induction on the iterator's
  remaining-length measure, rewriting with the two `.fold` lemmas to
  expose the body call so `step*` discharges it.

  ## Covered functions

      mlkem.ntt.poly_element_sample_cbd_from_bytes_loop0_loop0  -- inner η=3 (4 coeffs)
      mlkem.ntt.poly_element_sample_cbd_from_bytes_loop0        -- outer η=3 (over chunks)
      mlkem.ntt.poly_element_sample_cbd_from_bytes_loop1_loop0  -- inner η=2 (8 coeffs)
      mlkem.ntt.poly_element_sample_cbd_from_bytes_loop1        -- outer η=2 (over chunks)
      mlkem.ntt.poly_element_sample_cbd_from_bytes              -- wrapper
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.MontArith
import Symcrust.Properties.MLKEM.Bridges.Encoding
import Symcrust.Properties.MLKEM.Bridges.Cbd
import Symcrust.Properties.MLKEM.Ntt.ModArith
import Symcrust.Properties.MLKEM.Ntt.Bytes
import Symcrust.Properties.Iterators

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust

namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 4000000
set_option maxRecDepth 32768

/-! ## η=3 inner loop

`poly_element_sample_cbd_from_bytes_loop0_loop0`:
walks `j ∈ [0, 4)`, each iteration extracts the low 6 bits of
`sample_bits`, maps them to `{-3, …, 3} ⊂ Zq` via popcount trick,
writes to `pe_dst[i + j]`, and shifts `sample_bits >>>= 6`. -/

#decompose mlkem.ntt.poly_element_sample_cbd_from_bytes_loop0_loop0
  poly_element_sample_cbd_from_bytes_loop0_loop0.fold
  letRange 1 1 => poly_element_sample_cbd_from_bytes_loop0_loop0_match

#decompose poly_element_sample_cbd_from_bytes_loop0_loop0_match
  poly_element_sample_cbd_from_bytes_loop0_loop0_match.fold
  branch 1 (letRange 0 14) => poly_element_sample_cbd_from_bytes_loop0_loop0_body

/-- BV-level popcount-mask field bound (η=3): every 3-bit field of the
parallel-popcount packing with mask `0x249249` is ≤ 3. Proved by `bv_decide`
per `k < 4`. Used to discharge the popcount-structure conjunct of
`cbdInnerEta3Inv` at consumed=0. -/
private theorem popcount3_field_le (sb : BitVec 32) (k : Nat) (hk : k < 4) :
    (((sb &&& 2396745#32) + ((sb >>> 1) &&& 2396745#32) + ((sb >>> 2) &&& 2396745#32)) >>> (6 * k) &&& 7#32).toNat ≤ 3
  ∧ (((sb &&& 2396745#32) + ((sb >>> 1) &&& 2396745#32) + ((sb >>> 2) &&& 2396745#32)) >>> (6 * k + 3) &&& 7#32).toNat ≤ 3 := by
  have h_aux : ∀ k < 4,
      (((sb &&& 2396745#32) + ((sb >>> 1) &&& 2396745#32) + ((sb >>> 2) &&& 2396745#32)) >>> (6 * k) &&& 7#32) ≤ 3#32
    ∧ (((sb &&& 2396745#32) + ((sb >>> 1) &&& 2396745#32) + ((sb >>> 2) &&& 2396745#32)) >>> (6 * k + 3) &&& 7#32) ≤ 3#32 := by
    intro k hk; interval_cases k <;> refine ⟨?_, ?_⟩ <;> bv_decide
  obtain ⟨h1, h2⟩ := h_aux k hk
  have h3 : (3#32 : BitVec 32).toNat = 3 := by decide
  rw [BitVec.le_def] at h1 h2
  rw [h3] at h1 h2
  exact ⟨h1, h2⟩

/-- BV-level popcount-mask field bound (η=2): every 2-bit field of the
parallel-popcount packing with mask `0x55555555` is ≤ 2. Proved by
`bv_decide` per `k < 8`. Used to discharge the popcount-structure conjunct of
`cbdInnerEta2Inv` at consumed=0. -/
private theorem popcount2_field_le (sb : BitVec 32) (k : Nat) (hk : k < 8) :
    (((sb &&& 1431655765#32) + ((sb >>> 1) &&& 1431655765#32)) >>> (4 * k) &&& 3#32).toNat ≤ 2
  ∧ (((sb &&& 1431655765#32) + ((sb >>> 1) &&& 1431655765#32)) >>> (4 * k + 2) &&& 3#32).toNat ≤ 2 := by
  have h_aux : ∀ k < 8,
      (((sb &&& 1431655765#32) + ((sb >>> 1) &&& 1431655765#32)) >>> (4 * k) &&& 3#32) ≤ 2#32
    ∧ (((sb &&& 1431655765#32) + ((sb >>> 1) &&& 1431655765#32)) >>> (4 * k + 2) &&& 3#32) ≤ 2#32 := by
    intro k hk; interval_cases k <;> refine ⟨?_, ?_⟩ <;> bv_decide
  obtain ⟨h1, h2⟩ := h_aux k hk
  have h3 : (2#32 : BitVec 32).toNat = 2 := by decide
  rw [BitVec.le_def] at h1 h2
  rw [h3] at h1 h2
  exact ⟨h1, h2⟩

/-- Impl-side coefficient formula for the popcount-packed sample_bits.

When `init` is the popcount-packed value (each 3-bit group holds the
popcount of 3 raw bits), the j-th coefficient extracted by the inner body
is `(low_pop j) - (high_pop j)` taken mod Q, where each pop value is in {0,1,2,3}.

The outer body bridges this to `samplePolyCbdCoeff bytes (4*chunks + j)` via
the popcount-mask identity. -/
def cbdPopCoeff3 (initial_sample_bits : Nat) (j : Nat) : MLKEM.Zq :=
  ((((initial_sample_bits >>> (6 * j)) &&& 7 : Nat) : Int)
    - (((initial_sample_bits >>> (6 * j + 3)) &&& 7 : Nat) : Int) : MLKEM.Zq)

/-- **Streaming invariant for the η=3 inner loop**.

After processing `consumed` coefficients of the current 4-coeff chunk,
`pe_dst[i, i + consumed)` holds the CBD-decoded coefficients of the
low `6·consumed` bits of `initial_sample_bits`, and `sample_bits` has
been shifted right by `6·consumed`.

The final conjunct ("popcount structure") records the bit-shape of
`initial_sample_bits`: it was produced by the outer body's
parallel-popcount packing with mask `0x249249`, so every 6-bit field
splits into two 3-bit subfields each holding a popcount value (≤ 3 since
3 input bits contribute). This precondition is what makes the per-iter
body's `wrapping_sub` massert
`(coefficient1 ≥ Q-3) || (coefficient1 ≤ 3)` provable from `h_inv`. -/
def cbdInnerEta3Inv
    (initial_sample_bits : U32) (sample_bits : U32)
    (pe_dst_orig pe_dst : PolyElement)
    (i : Usize) (consumed : Nat)
    (h_ic : i.val + consumed ≤ 256) : Prop :=
  consumed ≤ 4 ∧
  sample_bits.val = initial_sample_bits.val >>> (6 * consumed) ∧
  (∀ (j : Nat) (_ : j < consumed),
      ((pe_dst.val[i.val + j]'(by grind)) : U16).val =
        ((cbdPopCoeff3 initial_sample_bits.val j).val : Nat)) ∧
  (∀ (k : Nat) (_ : k < 256),
      k < i.val ∨ i.val + consumed ≤ k →
      (pe_dst.val[k]'(by grind)) = (pe_dst_orig.val[k]'(by grind))) ∧
  (∀ (k : Nat), k < 4 →
      ((initial_sample_bits.val >>> (6 * k)) &&& 7) ≤ 3 ∧
      ((initial_sample_bits.val >>> (6 * k + 3)) &&& 7) ≤ 3)

/-! The `#decompose` declarations and `_loop0_loop0_match.fold` equation
above are consumed inside
`mlkem.ntt.poly_element_sample_cbd_from_bytes_loop0_loop0.spec`'s proof
via the canonical Variant B pattern (see `proof-patterns` skill): the
loop dispatch and per-coefficient body step are inlined there, so no
standalone `@[step]` spec is needed for `_match`. -/

/-- **Body spec** for the η=3 inner loop's per-coefficient work.

Extracts one coefficient from the low 6 bits of `sample_bits`, maps to
a Zq value via the popcount trick `low_count - high_count mod q`,
writes to `pe_dst[i + j]`. Returns `(sample_bits >>> 6, iter1, updated
pe_dst)`.

Informal proof. Template: leaf step-spec (no recursion). `unfold
poly_element_sample_cbd_from_bytes_loop0_loop0_body`; `step*` through:
1. `U32.band.spec` for `sample_bits &&& 63#u32` — yields `coefficient =
   sample_bits.val % 64`; `bv_tac 32` for the mask identity.
2. `U32.shr.spec` for `sample_bits >>> 6#i32` — yields the shifted residue.
3. `U32.band.spec` for `coefficient &&& 3#u32` — yields `low_count` =
   bits 0,1 of `coefficient` (= popcount of the first 3 raw bits, value ≤ 3).
4. `U32.shr.spec` for `coefficient >>> 3#i32` — yields `high_count` =
   bits 3,4 of `coefficient` shifted to 0,1 (= popcount of next 3 raw bits,
   value ≤ 3; no extra mask needed since `coefficient ≤ 63`).
5. `U32.wrapping_sub.spec` for `low_count - high_count`; the massert
   `(coefficient1 >= (Q-3)) || (coefficient1 <= 3#u32)` is discharged by
   `agrind` from the popcount bounds (both ≤ 3).
6. Conditional add-`Q`: `step*` through `U32.shr.spec` (`>>> 16`) and
   `U32.band.spec` (`&&& Q`) + `U32.wrapping_add.spec`; this reduces the
   value to `[0, Q)`. Show `coefficient2 = cbdDecodeBits 3 (sample_bits.val % 64)`
   by `cbdDecodeBits_eq_specCoeff` from `Bridges/Encoding.lean`.
7. `UScalar.cast.spec` (U32 → U16, in-range since result < Q < 2^16).
8. `Array.update.spec` for write at `i + j` (bound `h_ic'`); the back result
   `pe_dst'` differs from `pe_dst` only at slot `i.val + j.val`.
Establish `cbdInnerEta3Inv initial_sample_bits (sample_bits >>> 6)
pe_dst_orig pe_dst' i (consumed+1) h_ic'` by splitting conjuncts:
the new `k = i.val + consumed` case uses the `cbdDecodeBits_eq_specCoeff`
result; the frame clause (`k < i.val` or `k ≥ i.val + consumed+1`) follows
from `h_inv`'s frame + `Array.update.spec`'s frame; `agrind` for all bounds. -/
@[step]
theorem poly_element_sample_cbd_from_bytes_loop0_loop0_body.spec
    (initial_sample_bits : U32)
    (pe_dst_orig pe_dst : PolyElement)
    (i : Usize) (sample_bits : U32)
    (iter1 : core.ops.range.Range Usize) (j : Usize)
    (consumed : Nat)
    (h_ic : i.val + consumed ≤ 256)
    (h_jc : j.val = consumed)
    (h_consumed_lt : consumed < 4)
    (h_ic' : i.val + (consumed + 1) ≤ 256)
    (h_inv : cbdInnerEta3Inv initial_sample_bits sample_bits
               pe_dst_orig pe_dst i consumed h_ic) :
    poly_element_sample_cbd_from_bytes_loop0_loop0_body
        pe_dst i sample_bits iter1 j
      ⦃ next_sample_bits next_iter1 pe_dst' =>
          next_sample_bits.val = sample_bits.val >>> 6 ∧
          next_iter1 = iter1 ∧
          cbdInnerEta3Inv initial_sample_bits next_sample_bits
            pe_dst_orig pe_dst' i (consumed + 1) h_ic' ⦄ := by
  unfold poly_element_sample_cbd_from_bytes_loop0_loop0_body
  obtain ⟨h_cons_le, h_sb_eq, h_done, h_frame, h_popc⟩ := h_inv
  have h_popc_cur := h_popc consumed h_consumed_lt
  obtain ⟨h_low_bd, h_high_bd⟩ := h_popc_cur
  step*
  case _ =>
    interval_cases consumed <;> bv_tac 32
  case _ =>
    interval_cases consumed <;> bv_tac 32
  refine ⟨by simp [sample_bits1_post1, h_sb_eq], by omega, ?_, ?_, ?_, h_popc⟩
  · rw [sample_bits1_post1, h_sb_eq]; rw [show 6 * (consumed + 1) = 6 * consumed + 6 from by ring, Nat.shiftRight_add]
  · -- per-coefficient: j < consumed via h_done, j = consumed via bv_tac
    intro j hj
    by_cases hjc : j < consumed
    · have h_prev := h_done j hjc
      simp only [a_post, Std.Array.set_val_eq, List.getElem_set]
      have h_i6_val : i6.val = i.val + consumed := by rw [i6_post]; omega
      have h_neq : i6.val ≠ i.val + j := by omega
      rw [if_neg h_neq]; exact h_prev
    · -- new slot j = consumed: bridge ZMod over Int to impl coefficient2.val.
      have hj_eq : j = consumed := by omega
      subst hj_eq
      simp only [a_post, Std.Array.set_val_eq, List.getElem_set]
      have h_i6_val : i6.val = i.val + j := by rw [i6_post]; omega
      rw [if_pos h_i6_val]
      -- Reduce LHS to coefficient2.val (Q < 2^16 so cast preserves value)
      have h_Q_val : mlkem.ntt.Q.val = 3329 := by
        unfold mlkem.ntt.Q; decide
      have h_coeff2_lt_Q : coefficient2.val < 3329 := by
        have := show coefficient2 < mlkem.ntt.Q from by assumption
        bv_tac 32
      have h_i7_val : i7.val = coefficient2.val := by
        rw [i7_post]; bv_tac 32
      rw [h_i7_val]
      -- Bridge sample_bits.bv to initial_sample_bits.bv >>> 6j (preserved across all)
      have h_sb_bv : sample_bits.bv = (initial_sample_bits.bv >>> (6 * j) : BitVec 32) := by
        apply BitVec.eq_of_toNat_eq
        rw [BitVec.toNat_ushiftRight]; exact h_sb_eq
      -- Compute i1.val and i2.val in terms of init.val (using popcount bounds)
      have h_i1_val : i1.val = (initial_sample_bits.val >>> (6 * j)) &&& 7 := by bv_tac 32
      have h_i2_val : i2.val = (initial_sample_bits.val >>> (6 * j + 3)) &&& 7 := by bv_tac 32
      have h_i1_bd : i1.val ≤ 3 := h_i1_val ▸ h_low_bd
      have h_i2_bd : i2.val ≤ 3 := h_i2_val ▸ h_high_bd
      -- Bridge coefficient2.val to (i1.val + Q - i2.val) % Q
      have h_coeff2_eq : coefficient2.val = (i1.val + 3329 - i2.val) % 3329 := by
        have h_i1_lt : i1.val < 4 := by omega
        have h_i2_lt : i2.val < 4 := by omega
        -- wrapping_sub.val = (x + size - y) % size where size = 2^32
        have h_wsub : ∀ (x y : U32), (core.num.U32.wrapping_sub x y).val =
                      (x.val + (Std.UScalar.size UScalarTy.U32 - y.val)) %
                      Std.UScalar.size UScalarTy.U32 := by
          intros; simp [core.num.U32.wrapping_sub, Std.UScalar.wrapping_sub_val_eq]
        have h_wadd : ∀ (x y : U32), (core.num.U32.wrapping_add x y).val =
                      (x.val + y.val) % Std.UScalar.size UScalarTy.U32 := by
          intros; simp [core.num.U32.wrapping_add, Std.UScalar.wrapping_add_val_eq]
        have h_size : Std.UScalar.size UScalarTy.U32 = 2^32 := by
          show Std.UScalar.size UScalarTy.U32 = 4294967296
          simp [Std.UScalar.size_UScalarTyU32, Std.U32.size_eq]
        by_cases hle : i2.val ≤ i1.val
        · -- No underflow
          have h_c1_val : coefficient1.val = i1.val - i2.val := by
            rw [coefficient1_post, h_wsub, h_size]
            have : (i1.val + (2^32 - i2.val)) = (i1.val - i2.val) + 2^32 := by omega
            rw [this, Nat.add_mod_right, Nat.mod_eq_of_lt]; omega
          have h_i4_val : i4.val = 0 := by
            rw [i4_post1, h_c1_val]
            have h_lt65k : i1.val - i2.val < 65536 := by omega
            have : (i1.val - i2.val) >>> 16 = 0 := by
              rw [Nat.shiftRight_eq_div_pow]
              exact Nat.div_eq_zero_iff.mpr (Or.inr (by norm_num; omega))
            omega
          have h_i5_val : i5.val = 0 := by
            rw [i5_post1]
            have : (mlkem.ntt.Q &&& i4).val = (mlkem.ntt.Q.val) &&& i4.val := by
              simp [Std.UScalar.val_and]
            rw [this, h_i4_val]; simp
          have h_c2_val : coefficient2.val = i1.val - i2.val := by
            rw [coefficient2_post, h_wadd, h_c1_val, h_i5_val, h_size]
            rw [Nat.add_zero, Nat.mod_eq_of_lt]; omega
          omega
        · push Not at hle
          have h_c1_val : coefficient1.val = 2^32 + i1.val - i2.val := by
            rw [coefficient1_post, h_wsub, h_size]
            have h_lt : i1.val + (2^32 - i2.val) < 2^32 := by omega
            rw [Nat.mod_eq_of_lt h_lt]; omega
          have h_i4_val : i4.val = 0xFFFF := by
            rw [i4_post1, h_c1_val]
            have h_range : 2^32 - 3 ≤ 2^32 + i1.val - i2.val ∧ 2^32 + i1.val - i2.val < 2^32 := by
              omega
            have : (2^32 + i1.val - i2.val) >>> 16 = 0xFFFF := by
              have := h_range.2; have := h_range.1
              -- shift right by 16: top 16 bits
              omega
            omega
          have h_i5_val : i5.val = 3329 := by
            rw [i5_post1]
            have h_and_val : (mlkem.ntt.Q &&& i4).val = (mlkem.ntt.Q.val) &&& i4.val := by
              simp [Std.UScalar.val_and]
            rw [h_and_val, h_i4_val, h_Q_val]; decide
          have h_c2_val : coefficient2.val = i1.val + 3329 - i2.val := by
            rw [coefficient2_post, h_wadd, h_c1_val, h_i5_val, h_size]
            rw [show 2^32 + i1.val - i2.val + 3329 = (i1.val + 3329 - i2.val) + 2^32 from by omega,
                Nat.add_mod_right, Nat.mod_eq_of_lt]; omega
          omega
      rw [h_coeff2_eq]
      -- Reduce RHS via ZMod.val
      have h_q_eq : MLKEM.q = 3329 := rfl
      unfold cbdPopCoeff3
      rw [← h_i1_val, ← h_i2_val]
      -- Goal: (i1.val + 3329 - i2.val) % 3329 = ZMod.val (((i1.val:Int) - (i2.val:Int)) : Zq)
      by_cases hle : i2.val ≤ i1.val
      · -- i1 ≥ i2: no underflow. Cast (i1-i2 : Int) Zq = (i1-i2 : Nat) Zq.
        have h_eq : ((((i1.val : Int) : MLKEM.Zq) - ((i2.val : Int) : MLKEM.Zq))) =
                    ((i1.val - i2.val : Nat) : MLKEM.Zq) := by
          have h_sub_nat : ((i1.val - i2.val : Nat) : Int) =
                          (i1.val : Int) - (i2.val : Int) := by omega
          have h_to_int : ((i1.val - i2.val : Nat) : MLKEM.Zq) =
                ((((i1.val - i2.val : Nat) : Int)) : MLKEM.Zq) := by push_cast; rfl
          rw [h_to_int, h_sub_nat]; push_cast; ring
        rw [h_eq, ZMod.val_natCast, h_q_eq]
        -- Goal: (i1 + 3329 - i2) % 3329 = (i1 - i2) % 3329
        have h_rewrite : i1.val + 3329 - i2.val = (i1.val - i2.val) + 3329 := by omega
        rw [h_rewrite, Nat.add_mod_right]
      · -- i1 < i2: underflow → wraps to q + i1 - i2
        push Not at hle
        have hQ_zero : ((MLKEM.q : Nat) : MLKEM.Zq) = 0 := ZMod.natCast_self _
        have h_eq : ((((i1.val : Int) : MLKEM.Zq) - ((i2.val : Int) : MLKEM.Zq))) =
                    ((MLKEM.q + i1.val - i2.val : Nat) : MLKEM.Zq) := by
          have h_sub_int : ((MLKEM.q + i1.val - i2.val : Nat) : Int) =
                          (MLKEM.q : Int) + (i1.val : Int) - (i2.val : Int) := by
            push_cast; omega
          have h_to_int : ((MLKEM.q + i1.val - i2.val : Nat) : MLKEM.Zq) =
                ((((MLKEM.q + i1.val - i2.val : Nat) : Int)) : MLKEM.Zq) := by push_cast; rfl
          rw [h_to_int, h_sub_int]
          push_cast
          ring
        rw [h_eq, ZMod.val_natCast, h_q_eq]
        -- Goal: (i1 + 3329 - i2) % 3329 = (3329 + i1 - i2) % 3329
        fcongr 1; omega
  · intro k hk hor
    have h_i6_val : i6.val = i.val + consumed := by rw [i6_post]; omega
    simp only [a_post, Std.Array.set_val_eq]
    rw [List.getElem_set]
    split
    · omega
    · exact h_frame k hk (by omega)

/-- **Inner loop spec** for η=3.

After the loop, `pe_dst[i, i+4)` holds the 4 CBD-decoded coefficients
of `initial_sample_bits`, and other cells are unchanged. The remaining
work in the iter is exposed through the streaming invariant: the loop
runs from `iter.start` (current `consumed`) to `iter.end = 4`.

Informal proof. Canonical recursive Range-Usize loop (`proof-patterns`
"Loop — Canonical Template", Variant B). No separate
`_loop0_loop0_match.spec` is needed: the match dispatch is inlined.

- **Mandatory first step**: `rw [poly_element_sample_cbd_from_bytes_loop0_loop0.fold]`
  to expose `<loop>_match` under the let-binder. Do NOT use `unfold
  mlkem.ntt.poly_element_sample_cbd_from_bytes_loop0_loop0`. After the `(next iter)` step is consumed, `rw
  [poly_element_sample_cbd_from_bytes_loop0_loop0_match.fold]` to
  expose the `_body` call.
- `step` to consume `next iter` (Range-Usize → `o, iter1`).
- `cases o`:
  - **`none` arm** (`iter.start = 4`, `consumed = 4`): `_match`'s `none`
    body is `ok pe_dst`; close from `h_inv` directly — the post is just
    `cbdInnerEta3Inv … (initial_sample_bits >>> 24) pe_dst i 4 _`,
    which follows from `h_inv` at `consumed = iter.start.val = 4` (the
    shifted residue at `consumed = 4` is `>>> 24`, ≤ 24-bit input).
    `agrind`.
  - **`some j` arm**: extract `j.val = iter.start.val` and `j.val < 4`
    from the Range iterator semantics and `h_start`/`h_end`; `step with
    poly_element_sample_cbd_from_bytes_loop0_loop0_body.spec` (discharging
    `h_jc`, `h_ic'`, and the strengthened `h_inv`'s popcount-structure
    conjunct, which gives the massert bound); the body post yields
    `cbdInnerEta3Inv … next_sample_bits pe_dst' i (consumed+1)`; `step*`
    then closes the recursive `loop0_loop0` call via the IH (this very
    theorem) at the updated iterator.
- `termination_by iter.«end».val - iter.start.val`; `decreasing_by agrind`. -/
@[step]
theorem mlkem.ntt.poly_element_sample_cbd_from_bytes_loop0_loop0.spec
    (initial_sample_bits : U32)
    (iter : core.ops.range.Range Usize)
    (pe_dst_orig pe_dst : PolyElement)
    (i : Usize) (sample_bits : U32)
    (h_i : i.val + 4 ≤ 256)
    (h_start : iter.start.val ≤ 4) (h_end : iter.«end».val = 4)
    (h_inv : cbdInnerEta3Inv initial_sample_bits sample_bits
               pe_dst_orig pe_dst i iter.start.val (by grind)) :
    mlkem.ntt.poly_element_sample_cbd_from_bytes_loop0_loop0
        iter pe_dst i sample_bits
      ⦃ (r : PolyElement) =>
          cbdInnerEta3Inv initial_sample_bits
            (({ bv := initial_sample_bits.bv >>> (6 * 4) } : U32))
            pe_dst_orig r i 4 (by grind) ⦄ := by
  rw [poly_element_sample_cbd_from_bytes_loop0_loop0.fold]
  by_cases hlt : iter.start.val < iter.end.val
  · -- some branch
    let* ⟨o, iter1, ho, hstart1, hend1⟩ ← IteratorRange_next_some
    rw [ho]
    rw [poly_element_sample_cbd_from_bytes_loop0_loop0_match.fold]
    simp only
    have h_consumed_lt : iter.start.val < 4 := by rw [← h_end]; exact hlt
    have h_ic_cur : i.val + iter.start.val ≤ 256 := by omega
    have h_ic' : i.val + (iter.start.val + 1) ≤ 256 := by omega
    step with poly_element_sample_cbd_from_bytes_loop0_loop0_body.spec initial_sample_bits
      pe_dst_orig pe_dst i sample_bits iter1 iter.start iter.start.val h_ic_cur rfl
      h_consumed_lt h_ic' h_inv
      as ⟨nsb, niter, pe_dst1, h_nsb, h_niter, h_inv'⟩
    have h_iter1_start : iter1.start.val ≤ 4 := by rw [hstart1]; omega
    have h_iter1_end : iter1.end.val = 4 := by rw [hend1]; exact h_end
    have h_iter1_start_eq : iter1.start.val = iter.start.val + 1 := hstart1
    -- Build h_inv'' at iter1.start.val from h_inv' at iter.start.val + 1
    have h_inv'' : cbdInnerEta3Inv initial_sample_bits nsb pe_dst_orig pe_dst1 i
                     iter1.start.val (by omega) := by
      convert h_inv' using 2
    -- niter = iter1 from body post; rewrite goal to use iter1
    cases h_niter
    apply WP.spec_mono
      (mlkem.ntt.poly_element_sample_cbd_from_bytes_loop0_loop0.spec initial_sample_bits
        iter1 pe_dst_orig pe_dst1 i nsb (by omega) h_iter1_start h_iter1_end h_inv'')
    rintro r hinv_f
    exact hinv_f
  · -- none branch
    have hge : iter.start.val ≥ iter.end.val := by omega
    let* ⟨o, iter1, ho, _⟩ ← IteratorRange_next_none
    rw [ho]
    rw [poly_element_sample_cbd_from_bytes_loop0_loop0_match.fold]
    simp only [WP.spec_ok]
    have h_start_eq : iter.start.val = 4 := by omega
    -- Build h_inv2 at consumed=4
    have h_inv2 : cbdInnerEta3Inv initial_sample_bits sample_bits pe_dst_orig pe_dst i 4
                    (by omega) := by
      convert h_inv using 2
      omega
    -- Goal: cbdInnerEta3Inv initial_sample_bits (init.bv >>> (6 * 4)) pe_dst_orig pe_dst i 4 _
    -- h_inv2 has sample_bits; the spec's invariant says sample_bits.val = init.val >>> (6 * 4)
    -- We need to convert sample_bits to init.bv >>> (6 * 4) (a U32 with this bv)
    obtain ⟨h_le4, h_sb, h_done, h_undone, h_pop⟩ := h_inv2
    refine ⟨h_le4, ?_, ?_, h_undone, h_pop⟩
    · bv_tac 32
    · exact h_done
termination_by 4 - iter.start.val
decreasing_by
  rw [hstart1]
  omega

/-! ## η=3 outer loop

`poly_element_sample_cbd_from_bytes_loop0`:
each iteration consumes 3 source bytes from `pb_src[src_i .. src_i+3)`,
loads as little-endian `u32`, applies popcount partitioning
(constant `2396745 = 0o11111111`), then dispatches to the inner loop
to write 4 coefficients to `pe_dst[i .. i+4)`. -/

#decompose mlkem.ntt.poly_element_sample_cbd_from_bytes_loop0
  poly_element_sample_cbd_from_bytes_loop0.fold
  letRange 1 1 => poly_element_sample_cbd_from_bytes_loop0_match

#decompose poly_element_sample_cbd_from_bytes_loop0_match
  poly_element_sample_cbd_from_bytes_loop0_match.fold
  branch 1 (letRange 0 10) => poly_element_sample_cbd_from_bytes_loop0_body

/-- **Streaming invariant for the η=3 outer loop**.

After the outer loop has processed `chunks` chunks (each 3 input bytes
producing 4 output coefficients):
* `src_i = chunks * 3` (each chunk advances the source cursor by 3);
* the first `4 · chunks` cells of `pe_dst` hold the spec coefficients
  `samplePolyCbdCoeff bytes k` for `k ∈ [0, 4·chunks)`;
* the remaining cells are unchanged from `pe_dst_orig`. -/
def cbdOuterEta3Inv
    (bytes : 𝔹 (64 * (cbdEta 3#u32 (Or.inr rfl)).val))
    (pe_dst_orig pe_dst : PolyElement)
    (src_i : Usize) (chunks : Nat) : Prop :=
  src_i.val = 3 * chunks ∧
  4 * chunks ≤ 256 ∧
  (∀ (k : Nat) (h_k : k < 256),
      k < 4 * chunks →
      ((pe_dst.val[k]'(by have := pe_dst.property; grind)) : U16).val =
        (samplePolyCbdCoeff bytes k h_k).val) ∧
  (∀ (k : Nat) (_ : k < 256),
      4 * chunks ≤ k →
      (pe_dst.val[k]'(by have := pe_dst.property; grind)) =
        (pe_dst_orig.val[k]'(by have := pe_dst_orig.property; grind)))

/-! The `#decompose` declarations and `_loop0_match.fold` equation above
are consumed inside `mlkem.ntt.poly_element_sample_cbd_from_bytes_loop0.spec`'s
proof via the canonical Variant B pattern (see `proof-patterns` skill):
the loop dispatch and per-chunk body step are inlined there, so no
standalone `@[step]` spec is needed for `_match`. -/

/-- **Body spec** for the η=3 outer loop's per-chunk work.

Loads 3 bytes from `pb_src[src_i..src_i+3)`, applies popcount
partitioning, dispatches inner loop to write 4 coefficients, advances
`src_i` by 3. Each of the 4 new coefficients equals the corresponding
`samplePolyCbdCoeff` value.

Informal proof. Template: leaf step-spec. `unfold
poly_element_sample_cbd_from_bytes_loop0_body`; `step*` through:
1. `mlkem.ntt.load_u32_le.spec` at `offset = src_i` — yields
   `raw.val = b0.val + 256*b1.val + 65536*b2.val + (b3.val * 16777216)`
   where `b0..b3 = pb_src[src_i..src_i+4)`; bound `src_i.val + 4
   ≤ pb_src.length` follows from `h_pb_len = 64*3 + 1` and the
   invariant's `src_i.val = 3 * chunks ∧ 4 * chunks + 4 ≤ 256`
   (final chunk `src_i = 189`, `src_i + 4 = 193 = 64*3 + 1` ✓).
   The +1 padding byte is read but never contributes to a sampled
   coefficient (`b3` is only used at non-final chunks, where it is
   re-read as `b0` of the next chunk).
2. Three `U32.band.spec` + `U32.shr.spec` calls for the parallel-popcount
   computation with mask `2396745 = 0x249249` (selects bits 0,3,6,…,21):
   `sample_bits1 = (raw &&& M) + ((raw >>> 1) &&& M) + ((raw >>> 2) &&& M)`
   where each summand adds the bit at positions 0,3,6,…,21 of successive
   shifts; the result packs the popcount of each 3-bit group at bit
   positions `3k` and `3k+1`; `bv_tac 32` or `agrind` for bitwise goals.
3. **Popcount-structure conjunct** (precondition for the inner loop's
   strengthened `cbdInnerEta3Inv`): for every `k < 4`, the 3-bit fields
   `(sample_bits1 >>> (6*k)) &&& 7` and `(sample_bits1 >>> (6*k+3)) &&& 7`
   are both ≤ 3. This follows from the mask+shift+add identity above —
   each 3-bit field is the popcount of 3 input bits, hence in {0,1,2,3};
   establish via `bv_decide` (the whole identity is a pure 32-bit goal).
4. `mlkem.ntt.poly_element_sample_cbd_from_bytes_loop0_loop0.spec` with
   `initial_sample_bits = sample_bits1`, `iter = {start:=0, end:=4}`,
   `i = 4*chunks`, and initial `cbdInnerEta3Inv` vacuously at `consumed=0`
   (both per-coefficient and frame ∀-clauses empty; the popcount-structure
   conjunct from step 3 fills the new fifth clause; `h_ic : 4*chunks + 0 ≤
   256` from `h_chunks`).
5. `Usize.add.spec` for `src_i + 3`.
Reconstruct `cbdOuterEta3Inv bytes pe_dst_orig pe_dst' next_src_i
(chunks+1)` from the inner-loop postcondition: each new coefficient
`pe_dst'[4*chunks + j]` equals `samplePolyCbdCoeff bytes (4*chunks+j)` by
`cbdDecodeBits_eq_specCoeff` (η=3) applied to the inner-loop's per-entry
claim; framing (slots outside `[4*chunks, 4*(chunks+1))`) from the inner
invariant's frame clause; `agrind` for source-index arithmetic. -/
@[step]
theorem poly_element_sample_cbd_from_bytes_loop0_body.spec
    (pb_src : Slice U8) (pe_dst_orig pe_dst : PolyElement)
    (src_i : Usize) (i : Usize)
    (chunks : Nat)
    (h_pb_len : pb_src.length = 64 * 3 + 1)
    (h_i : i.val = 4 * chunks)
    (h_chunks : 4 * chunks + 4 ≤ 256)
    (h_inv : cbdOuterEta3Inv
               (sliceWindowToSpecBytes pb_src 0 (64 * 3) (by grind))
               pe_dst_orig pe_dst src_i chunks) :
    poly_element_sample_cbd_from_bytes_loop0_body pb_src pe_dst src_i i
      ⦃ next_src_i pe_dst' =>
          next_src_i.val = src_i.val + 3 ∧
          cbdOuterEta3Inv (sliceWindowToSpecBytes pb_src 0 (64 * 3) (by grind))
            pe_dst_orig pe_dst' next_src_i (chunks + 1) ⦄ := by
  unfold poly_element_sample_cbd_from_bytes_loop0_body
  obtain ⟨h_src_i_val, h_4ch_le, h_done, h_undone⟩ := h_inv
  have h_pb_lt : src_i.val + 4 ≤ pb_src.length := by
    rw [h_src_i_val]; omega
  -- Step through: load_u32_le, src_i + 3, masked popcount partition.
  step*
  case hmax =>
    have h_i1_bd : i1.val ≤ 2396745 := by
      have := Std.UScalar.val_and sample_bits 2396745#u32
      rw [i1_post1, this]
      have : (2396745#u32).val = 2396745 := by decide
      rw [this]; exact Nat.and_le_right
    have h_i3_bd : i3.val ≤ 2396745 := by
      have := Std.UScalar.val_and i2 2396745#u32
      rw [i3_post1, this]
      have : (2396745#u32).val = 2396745 := by decide
      rw [this]; exact Nat.and_le_right
    have : (Std.U32.max : Nat) = 4294967295 := Std.U32.max_eq
    rw [this]; omega
  case hmax =>
    have h_i1_bd : i1.val ≤ 2396745 := by
      have := Std.UScalar.val_and sample_bits 2396745#u32
      rw [i1_post1, this]
      have : (2396745#u32).val = 2396745 := by decide
      rw [this]; exact Nat.and_le_right
    have h_i3_bd : i3.val ≤ 2396745 := by
      have := Std.UScalar.val_and i2 2396745#u32
      rw [i3_post1, this]
      have : (2396745#u32).val = 2396745 := by decide
      rw [this]; exact Nat.and_le_right
    have h_i6_bd : i6.val ≤ 2396745 := by
      have := Std.UScalar.val_and i5 2396745#u32
      rw [i6_post1, this]
      have : (2396745#u32).val = 2396745 := by decide
      rw [this]; exact Nat.and_le_right
    have h_i4_bd : i4.val ≤ 4793490 := by rw [i4_post]; omega
    have : (Std.U32.max : Nat) = 4294967295 := Std.U32.max_eq
    rw [this]; omega
  case pe_dst_orig => exact pe_dst
  case h_inv =>
    show cbdInnerEta3Inv sample_bits1 sample_bits1 pe_dst pe_dst i 0 _
    refine ⟨by omega, by simp, ?_, ?_, ?_⟩
    · intro j hj; omega
    · intro k _ _; rfl
    · intro k hk
      have h_2396 : ((2396745#u32) : U32).val = 2396745 := by decide
      have h_i1_v : i1.val = sample_bits.val &&& 2396745 := by
        rw [i1_post1, Std.UScalar.val_and, h_2396]
      have h_i3_v : i3.val = sample_bits.val >>> 1 &&& 2396745 := by
        rw [i3_post1, Std.UScalar.val_and, h_2396, i2_post1]
      have h_i6_v : i6.val = sample_bits.val >>> 2 &&& 2396745 := by
        rw [i6_post1, Std.UScalar.val_and, h_2396, i5_post1]
      have h_i1_bd : i1.val ≤ 2396745 := by rw [h_i1_v]; exact Nat.and_le_right
      have h_i3_bd : i3.val ≤ 2396745 := by rw [h_i3_v]; exact Nat.and_le_right
      have h_i6_bd : i6.val ≤ 2396745 := by rw [h_i6_v]; exact Nat.and_le_right
      have h_sb1_bv : sample_bits1.bv =
          (sample_bits.bv &&& 2396745#32) + (sample_bits.bv >>> 1 &&& 2396745#32) +
            (sample_bits.bv >>> 2 &&& 2396745#32) := by
        apply BitVec.eq_of_toNat_eq
        rw [BitVec.toNat_add, BitVec.toNat_add]
        simp only [BitVec.toNat_and, BitVec.toNat_ushiftRight]
        have h_2396_bv : (2396745#32 : BitVec 32).toNat = 2396745 := by decide
        rw [h_2396_bv]
        simp only [Std.UScalar.bv_toNat]
        rw [sample_bits1_post, i4_post, h_i1_v, h_i3_v, h_i6_v]
        omega
      have h_helper := popcount3_field_le sample_bits.bv k hk
      have h_eq : sample_bits1.val = ((sample_bits.bv &&& 2396745#32) +
          (sample_bits.bv >>> 1 &&& 2396745#32) + (sample_bits.bv >>> 2 &&& 2396745#32)).toNat := by
        rw [← h_sb1_bv, Std.UScalar.bv_toNat]
      rw [h_eq]
      simp only [BitVec.toNat_ushiftRight, BitVec.toNat_and] at h_helper
      have h7 : (7#32 : BitVec 32).toNat = 7 := by decide
      rw [h7] at h_helper
      exact h_helper
  -- After inner loop, rebuild cbdOuterEta3Inv at chunks+1.
  obtain ⟨_, _, h_inner_done, h_inner_frame, _⟩ := pe_dst1_post
  refine ⟨src_i1_post, by rw [src_i1_post, h_src_i_val]; ring, by omega, ?_, ?_⟩
  · -- per-coefficient: split on k < 4*chunks vs k ∈ [4*chunks, 4*chunks+4)
    intro k h_k h_k_lt
    by_cases h_k_low : k < 4 * chunks
    · -- k < 4*chunks: frame from inner inv + h_done
      have h_frame_k : (pe_dst1.val[k]'(by have := pe_dst1.property; grind)) =
                       (pe_dst.val[k]'(by have := pe_dst.property; grind)) := by
        apply h_inner_frame k h_k; left; rw [h_i]; exact h_k_low
      rw [h_frame_k]; exact h_done k h_k h_k_low
    · -- k ∈ [4*chunks, 4*chunks+4): use inner inv per-coeff + popcount→specCoeff bridge
      push Not at h_k_low
      set j := k - 4 * chunks with h_j_def
      have h_j_lt : j < 4 := by omega
      have h_k_eq : k = i.val + j := by rw [h_i]; omega
      have h_inner_k := h_inner_done j h_j_lt
      -- Reframe the inner-loop result to use index k directly (avoids motive
      -- issues from rewriting under `[↑i + j]'_`).
      have h_pe_eq : (pe_dst1.val[i.val + j]'(by have := pe_dst1.property; grind)) =
                     (pe_dst1.val[k]'(by have := pe_dst1.property; grind)) := by
        fcongr 1; exact h_k_eq.symm
      rw [h_pe_eq] at h_inner_k
      rw [h_inner_k]
      -- Deep bridge: cbdPopCoeff3 sample_bits1.val j = samplePolyCbdCoeff bytes (4*chunks+j).
      -- Closed against the axiomatised popcount-mask identity
      -- `popcountPackBridge3` (see `Bridges/Cbd.lean`).  Bridges the impl-side
      -- popcount-packed `sample_bits1` to the spec-side `samplePolyCbdCoeff`;
      -- the axiom encodes the 24-bit popcount→signed-coeff identity that the
      -- prior dev proved as `shiftDistribMask2396745`.
      have h_k_4cj : k = 4 * chunks + j := by rw [h_k_eq, h_i]
      have h_2396 : ((2396745#u32) : U32).val = 2396745 := by decide
      have h_packed : sample_bits1.val =
          (sample_bits.val &&& 2396745) +
          ((sample_bits.val >>> 1) &&& 2396745) +
          ((sample_bits.val >>> 2) &&& 2396745) := by
        rw [sample_bits1_post, i4_post, i1_post1, i3_post1, i6_post1,
            Std.UScalar.val_and, Std.UScalar.val_and, Std.UScalar.val_and, h_2396,
            i2_post1, i5_post1]
      have h_sb_eq : sample_bits.val =
          (pb_src.val[3 * chunks]'(by grind)).val +
          256 * (pb_src.val[3 * chunks + 1]'(by grind)).val +
          65536 * (pb_src.val[3 * chunks + 2]'(by grind)).val +
          16777216 * (pb_src.val[3 * chunks + 3]'(by grind)).val := by
        rw [sample_bits_post]; simp only [h_src_i_val]
      have ax := popcountPackBridge3 pb_src h_pb_len chunks h_chunks j h_j_lt
      unfold cbdPopCoeff3
      rw [h_packed, h_sb_eq]
      exact congrArg ZMod.val (ax.trans (samplePolyCbdCoeff_idx_eq h_k_4cj.symm _ h_k))
  · -- frame: ∀ k ≥ 4*(chunks+1), pe_dst1[k] = pe_dst_orig[k]
    intro k h_k h_k_ge
    have h_frame_k : (pe_dst1.val[k]'(by have := pe_dst1.property; grind)) =
                     (pe_dst.val[k]'(by have := pe_dst.property; grind)) := by
      apply h_inner_frame k h_k; right; rw [h_i]; omega
    rw [h_frame_k]; exact h_undone k h_k (by omega)

/-- **Outer loop spec** for η=3.

After the loop the polynomial is fully written: every coefficient of
`r` equals the corresponding `samplePolyCbdCoeff` value, i.e.,
`toPoly r = MLKEM.SamplePolyCBD bytes`. The iterator is opaque,
so the spec is parameterised by a chunk witness via the streaming
invariant.

Informal proof. Canonical recursive opaque-`StepBy`-iterator loop
(`proof-patterns` "Loop — Canonical Template", Variant B applied to the
opaque-iterator variant). No separate `_loop0_match.spec` is needed:
the match dispatch is inlined.

- **Mandatory first step**: `rw [poly_element_sample_cbd_from_bytes_loop0.fold]`
  to expose `<loop>_match` under the let-binder. Do NOT use `unfold
  mlkem.ntt.poly_element_sample_cbd_from_bytes_loop0`. After the `(next iter)` step is consumed, `rw
  [poly_element_sample_cbd_from_bytes_loop0_match.fold]` to expose the
  `_body` call.
- `step` to consume `iter.next` — produces `o, iter1`.
- `cases o`:
  - **`none` arm**: from `h_iter` with `remaining = 0`, `chunks = 64`;
    `cbdOuterEta3Inv` at `chunks = 64` gives `∀ k < 256, pe_dst[k] =
    samplePolyCbdCoeff bytes k`; close with `final_chunks = 64`,
    `4 * 64 = 256` (`agrind`).
  - **`some _` arm**: `step with
    poly_element_sample_cbd_from_bytes_loop0_body.spec` (discharging
    `h_chunks : 4 * chunks + 4 ≤ 256` and the source-length bound from
    `h_inv` + `h_pb_len`); body post yields `next_src_i.val = src_i.val
    + 3` and `cbdOuterEta3Inv … (chunks+1)`; `step*` closes the
    recursive outer-loop call via the IH with `remaining' = remaining
    - 1` (the `some` arm proves `remaining > 0` from the iterator
    witness).
- Decreasing measure: `remaining` from `h_iter`; `decreasing_by agrind`.
`wfPoly r` follows because each `samplePolyCbdCoeff` value is `< q`
(definitionally, from the CBD spec). Derive `toPoly r = MLKEM.SamplePolyCBD
bytes` from the per-coefficient equality via a bridge lemma
`samplePolyCbdCoeff_eq_SamplePolyCBD` (declared in `Bridges/Encoding.lean`,
imported here). -/
@[step]
theorem mlkem.ntt.poly_element_sample_cbd_from_bytes_loop0.spec
    (iter : core.iter.adapters.step_by.StepBy (core.ops.range.Range Usize))
    (pb_src : Slice U8) (pe_dst_orig pe_dst : PolyElement)
    (src_i : Usize)
    (chunks : Nat)
    (h_pb_len : pb_src.length = 64 * 3 + 1)
    (h_inv : cbdOuterEta3Inv
               (sliceWindowToSpecBytes pb_src 0 (64 * 3) (by grind))
               pe_dst_orig pe_dst src_i chunks)
    (h_iter_start : iter.iter.start.val = 4 * chunks)
    (h_iter_end : iter.iter.«end».val = 256)
    (h_iter_step : iter.step_by.val = 4) :
    mlkem.ntt.poly_element_sample_cbd_from_bytes_loop0 iter pb_src pe_dst src_i
      ⦃ (r : PolyElement) =>
          ∃ (final_chunks : Nat) (final_src_i : Usize),
            cbdOuterEta3Inv (sliceWindowToSpecBytes pb_src 0 (64 * 3) (by grind))
              pe_dst_orig r final_src_i final_chunks ∧
            4 * final_chunks = 256 ⦄ := by
  rw [poly_element_sample_cbd_from_bytes_loop0.fold]
  obtain ⟨h_src_i, h_4ch_le, h_done, h_undone⟩ := h_inv
  by_cases hlt : iter.iter.start.val < iter.iter.«end».val
  · -- some branch: more chunks to process
    have h_step_pos : iter.step_by.val > 0 := by rw [h_iter_step]; decide
    have h_no_overflow : iter.iter.start.val + iter.step_by.val ≤ Usize.max := by
      rw [h_iter_start, h_iter_step]; scalar_tac
    let* ⟨o, iter1, ho, hstart1, hend1, hstep1⟩ ← core.iter.adapters.step_by.IteratorStepBy.next_Range_Usize_some_spec
    rw [ho]
    -- Now: do let pe_dst1 ← _body pb_src pe_dst src_i iter.iter.start; _loop0 iter1 ...
    rw [poly_element_sample_cbd_from_bytes_loop0_match.fold]
    simp only
    -- Apply body spec
    have h_i_eq : iter.iter.start.val = 4 * chunks := h_iter_start
    have h_chunks_lt : 4 * chunks < 256 := by
      have := hlt; rw [h_iter_start, h_iter_end] at this; exact this
    have h_chunks_bd : 4 * chunks + 4 ≤ 256 := by omega
    step with poly_element_sample_cbd_from_bytes_loop0_body.spec pb_src pe_dst_orig pe_dst src_i iter.iter.start chunks h_pb_len h_iter_start h_chunks_bd ⟨h_src_i, h_4ch_le, h_done, h_undone⟩
      as ⟨next_src_i, pe_dst1, h_next_src_i, h_inv'⟩
    -- recurse
    have h_iter1_start : iter1.iter.start.val = 4 * (chunks + 1) := by
      rw [hstart1, h_iter_start, h_iter_step]; ring
    have h_iter1_end : iter1.iter.«end».val = 256 := by rw [hend1]; exact h_iter_end
    have h_iter1_step : iter1.step_by.val = 4 := by rw [hstep1]; exact h_iter_step
    apply WP.spec_mono
      (mlkem.ntt.poly_element_sample_cbd_from_bytes_loop0.spec iter1 pb_src pe_dst_orig
        pe_dst1 next_src_i (chunks + 1) h_pb_len h_inv' h_iter1_start h_iter1_end h_iter1_step)
    rintro r ⟨fc, fsi, hinv_f, hfc⟩
    exact ⟨fc, fsi, hinv_f, hfc⟩
  · -- none branch: iter exhausted
    have hge : iter.iter.start.val ≥ iter.iter.«end».val := by omega
    let* ⟨o, iter1, ho, _⟩ ← core.iter.adapters.step_by.IteratorStepBy.next_Range_Usize_none_spec
    rw [ho]
    rw [poly_element_sample_cbd_from_bytes_loop0_match.fold]
    simp only [WP.spec_ok]
    -- chunks = 64
    have h_chunks_eq : 4 * chunks = 256 := by
      rw [h_iter_start, h_iter_end] at hge
      omega
    exact ⟨chunks, src_i, ⟨h_src_i, h_4ch_le, h_done, h_undone⟩, h_chunks_eq⟩
termination_by 256 - iter.iter.start.val
decreasing_by
  rw [hstart1, h_iter_start, h_iter_step]
  rw [h_iter_start] at hlt; rw [h_iter_end] at hlt
  omega

/-! ## η=2 inner loop

Same shape as η=3 inner, with 4-bit coefficients (8 per chunk),
mask `15 = 0xF`, shift `>>> 4`. Range `{-2, …, 2}`. -/

#decompose mlkem.ntt.poly_element_sample_cbd_from_bytes_loop1_loop0
  poly_element_sample_cbd_from_bytes_loop1_loop0.fold
  letRange 1 1 => poly_element_sample_cbd_from_bytes_loop1_loop0_match

#decompose poly_element_sample_cbd_from_bytes_loop1_loop0_match
  poly_element_sample_cbd_from_bytes_loop1_loop0_match.fold
  branch 1 (letRange 0 14) => poly_element_sample_cbd_from_bytes_loop1_loop0_body

/-- Impl-side coefficient formula for η=2 (popcount-packed sample_bits).

When `init` is the popcount-packed value (each 2-bit group holds the
popcount of 2 raw bits, value 0..2), the j-th coefficient extracted by
the inner body is `(low_pop j) - (high_pop j)` taken mod Q. -/
def cbdPopCoeff2 (initial_sample_bits : Nat) (j : Nat) : MLKEM.Zq :=
  ((((initial_sample_bits >>> (4 * j)) &&& 3 : Nat) : Int)
    - (((initial_sample_bits >>> (4 * j + 2)) &&& 3 : Nat) : Int) : MLKEM.Zq)

/-- **Streaming invariant for the η=2 inner loop**.

Same shape as `cbdInnerEta3Inv` but with 4-bit chunks (η=2), 8
coefficients per outer chunk, shift `>>> 4`. The final conjunct
("popcount structure") records that `initial_sample_bits` was produced
by the outer body's `(sb & 0x55555555) + ((sb >>> 1) & 0x55555555)`
packing, so every 4-bit field splits into two 2-bit subfields each
holding a popcount of 2 input bits (∈ {0,1,2}, ≤ 2). This precondition
makes the per-iter body's `wrapping_sub` massert provable. -/
def cbdInnerEta2Inv
    (initial_sample_bits : U32) (sample_bits : U32)
    (pe_dst_orig pe_dst : PolyElement)
    (i : Usize) (consumed : Nat)
    (h_ic : i.val + consumed ≤ 256) : Prop :=
  consumed ≤ 8 ∧
  sample_bits.val = initial_sample_bits.val >>> (4 * consumed) ∧
  (∀ (j : Nat) (_ : j < consumed),
      ((pe_dst.val[i.val + j]'(by grind)) : U16).val =
        ((cbdPopCoeff2 initial_sample_bits.val j).val : Nat)) ∧
  (∀ (k : Nat) (_ : k < 256),
      k < i.val ∨ i.val + consumed ≤ k →
      (pe_dst.val[k]'(by grind)) = (pe_dst_orig.val[k]'(by grind))) ∧
  (∀ (k : Nat), k < 8 →
      ((initial_sample_bits.val >>> (4 * k)) &&& 3) ≤ 2 ∧
      ((initial_sample_bits.val >>> (4 * k + 2)) &&& 3) ≤ 2)

/-! The `#decompose` declarations and `_loop1_loop0_match.fold` equation
above are consumed inside
`mlkem.ntt.poly_element_sample_cbd_from_bytes_loop1_loop0.spec`'s proof
via the canonical Variant B pattern (see `proof-patterns` skill): the
loop dispatch and per-coefficient body step are inlined there, so no
standalone `@[step]` spec is needed for `_match`. -/

/-- **Body spec** for the η=2 inner loop's per-coefficient work.

Extracts one coefficient from the low 4 bits of `sample_bits` via
the CBD(η=2) popcount trick `low2_count - high2_count mod q`, writes to
`pe_dst[i + j]`, returns `(sample_bits >>> 4, iter1, updated pe_dst)`.

Informal proof. Template: leaf step-spec; mirror of the η=3 body spec
with 4-bit mask and 2-bit subgroups. `unfold
poly_element_sample_cbd_from_bytes_loop1_loop0_body`; `step*` through:
1. `U32.band.spec` for `sample_bits &&& 15#u32` — yields `coefficient =
   sample_bits.val % 16`; `bv_tac 32`.
2. `U32.shr.spec` for `sample_bits >>> 4#i32` — yields next residue.
3. `U32.band.spec` for `coefficient &&& 3#u32` — yields `low_count`
   (= bits 0,1 of coefficient = popcount of the first 2 raw bits, ≤ 2).
4. `U32.shr.spec` for `coefficient >>> 2#i32` — yields `high_count`
   (= bits 2,3 of coefficient shifted to 0,1 = popcount of next 2 raw
   bits, ≤ 2; in range since `coefficient ≤ 15`).
5. `U32.wrapping_sub.spec` for `low_count - high_count`; massert
   `(coefficient1 ≥ Q-2) || (coefficient1 ≤ 2#u32)`. **This is the
   massert that requires the popcount-structure conjunct from
   `cbdInnerEta2Inv`** (final clause): from `h_inv.5 consumed (by agrind)`
   at `k = consumed` we get `(initial_sample_bits >>> (4*consumed)) &&& 3
   ≤ 2` (low pair) and `(initial_sample_bits >>> (4*consumed+2)) &&& 3 ≤ 2`
   (high pair); since `sample_bits = initial_sample_bits >>> (4*consumed)`
   (by `h_inv.2`), this says `low_count ≤ 2` and `high_count ≤ 2`, hence
   the unsigned wrapping result is in `[Q-2, Q) ∪ [0, 2]`. `bv_decide`
   closes after substituting these bounds.
6. Conditional add-`Q` via `U32.shr.spec` + `U32.band.spec` +
   `U32.wrapping_add.spec`; result in `[0, Q)`. Show `coefficient2 =
   cbdDecodeBits 2 (sample_bits.val % 16)` by `cbdDecodeBits_eq_specCoeff`
   (η=2).
7. `UScalar.cast.spec` (U32 → U16).
8. `Array.update.spec` for write at `i + j` (bound `h_ic'`).
Establish `cbdInnerEta2Inv initial_sample_bits (sample_bits >>> 4)
pe_dst_orig pe_dst' i (consumed+1) h_ic'` by `split_conjs` + `agrind`
per conjunct; framing by `by_cases` on `k = i.val + consumed` + `agrind`.
The popcount-structure conjunct on `initial_sample_bits` is preserved
verbatim from `h_inv` (it does not depend on `consumed`). -/
@[step]
theorem poly_element_sample_cbd_from_bytes_loop1_loop0_body.spec
    (initial_sample_bits : U32)
    (pe_dst_orig pe_dst : PolyElement)
    (i : Usize) (sample_bits : U32)
    (iter1 : core.ops.range.Range Usize) (j : Usize)
    (consumed : Nat)
    (h_ic : i.val + consumed ≤ 256)
    (h_jc : j.val = consumed)
    (h_consumed_lt : consumed < 8)
    (h_ic' : i.val + (consumed + 1) ≤ 256)
    (h_inv : cbdInnerEta2Inv initial_sample_bits sample_bits
               pe_dst_orig pe_dst i consumed h_ic) :
    poly_element_sample_cbd_from_bytes_loop1_loop0_body
        pe_dst i sample_bits iter1 j
      ⦃ next_sample_bits next_iter1 pe_dst' =>
          next_sample_bits.val = sample_bits.val >>> 4 ∧
          next_iter1 = iter1 ∧
          cbdInnerEta2Inv initial_sample_bits next_sample_bits
            pe_dst_orig pe_dst' i (consumed + 1) h_ic' ⦄ := by
  unfold poly_element_sample_cbd_from_bytes_loop1_loop0_body
  obtain ⟨h_cons_le, h_sb_eq, h_done, h_frame, h_popc⟩ := h_inv
  have h_popc_cur := h_popc consumed h_consumed_lt
  obtain ⟨h_low_bd, h_high_bd⟩ := h_popc_cur
  step*
  case _ =>
    interval_cases consumed <;> bv_tac 32
  case _ =>
    interval_cases consumed <;> bv_tac 32
  refine ⟨by simp [sample_bits1_post1, h_sb_eq], by omega, ?_, ?_, ?_, h_popc⟩
  · rw [sample_bits1_post1, h_sb_eq]; rw [show 4 * (consumed + 1) = 4 * consumed + 4 from by ring, Nat.shiftRight_add]
  · intro j hj
    by_cases hjc : j < consumed
    · have h_prev := h_done j hjc
      simp only [a_post, Std.Array.set_val_eq, List.getElem_set]
      have h_i6_val : i6.val = i.val + consumed := by rw [i6_post]; omega
      have h_neq : i6.val ≠ i.val + j := by omega
      rw [if_neg h_neq]; exact h_prev
    · have hj_eq : j = consumed := by omega
      subst hj_eq
      simp only [a_post, Std.Array.set_val_eq, List.getElem_set]
      have h_i6_val : i6.val = i.val + j := by rw [i6_post]; omega
      rw [if_pos h_i6_val]
      have h_Q_val : mlkem.ntt.Q.val = 3329 := by
        unfold mlkem.ntt.Q; decide
      have h_coeff2_lt_Q : coefficient2.val < 3329 := by
        have := show coefficient2 < mlkem.ntt.Q from by assumption
        bv_tac 32
      have h_i7_val : i7.val = coefficient2.val := by
        rw [i7_post]; bv_tac 32
      rw [h_i7_val]
      have h_sb_bv : sample_bits.bv = (initial_sample_bits.bv >>> (4 * j) : BitVec 32) := by
        apply BitVec.eq_of_toNat_eq
        rw [BitVec.toNat_ushiftRight]; exact h_sb_eq
      have h_i1_val : i1.val = (initial_sample_bits.val >>> (4 * j)) &&& 3 := by bv_tac 32
      have h_i2_val : i2.val = (initial_sample_bits.val >>> (4 * j + 2)) &&& 3 := by bv_tac 32
      have h_i1_bd : i1.val ≤ 2 := h_i1_val ▸ h_low_bd
      have h_i2_bd : i2.val ≤ 2 := h_i2_val ▸ h_high_bd
      have h_coeff2_eq : coefficient2.val = (i1.val + 3329 - i2.val) % 3329 := by
        have h_i1_lt : i1.val < 3 := by omega
        have h_i2_lt : i2.val < 3 := by omega
        have h_wsub : ∀ (x y : U32), (core.num.U32.wrapping_sub x y).val =
                      (x.val + (Std.UScalar.size UScalarTy.U32 - y.val)) %
                      Std.UScalar.size UScalarTy.U32 := by
          intros; simp [core.num.U32.wrapping_sub, Std.UScalar.wrapping_sub_val_eq]
        have h_wadd : ∀ (x y : U32), (core.num.U32.wrapping_add x y).val =
                      (x.val + y.val) % Std.UScalar.size UScalarTy.U32 := by
          intros; simp [core.num.U32.wrapping_add, Std.UScalar.wrapping_add_val_eq]
        have h_size : Std.UScalar.size UScalarTy.U32 = 2^32 := by
          show Std.UScalar.size UScalarTy.U32 = 4294967296
          simp [Std.UScalar.size_UScalarTyU32, Std.U32.size_eq]
        by_cases hle : i2.val ≤ i1.val
        · have h_c1_val : coefficient1.val = i1.val - i2.val := by
            rw [coefficient1_post, h_wsub, h_size]
            have : (i1.val + (2^32 - i2.val)) = (i1.val - i2.val) + 2^32 := by omega
            rw [this, Nat.add_mod_right, Nat.mod_eq_of_lt]; omega
          have h_i4_val : i4.val = 0 := by
            rw [i4_post1, h_c1_val]
            have h_lt65k : i1.val - i2.val < 65536 := by omega
            have : (i1.val - i2.val) >>> 16 = 0 := by
              rw [Nat.shiftRight_eq_div_pow]
              exact Nat.div_eq_zero_iff.mpr (Or.inr (by norm_num; omega))
            omega
          have h_i5_val : i5.val = 0 := by
            rw [i5_post1]
            have : (mlkem.ntt.Q &&& i4).val = (mlkem.ntt.Q.val) &&& i4.val := by
              simp [Std.UScalar.val_and]
            rw [this, h_i4_val]; simp
          have h_c2_val : coefficient2.val = i1.val - i2.val := by
            rw [coefficient2_post, h_wadd, h_c1_val, h_i5_val, h_size]
            rw [Nat.add_zero, Nat.mod_eq_of_lt]; omega
          omega
        · push Not at hle
          have h_c1_val : coefficient1.val = 2^32 + i1.val - i2.val := by
            rw [coefficient1_post, h_wsub, h_size]
            have h_lt : i1.val + (2^32 - i2.val) < 2^32 := by omega
            rw [Nat.mod_eq_of_lt h_lt]; omega
          have h_i4_val : i4.val = 0xFFFF := by
            rw [i4_post1, h_c1_val]
            have : (2^32 + i1.val - i2.val) >>> 16 = 0xFFFF := by omega
            omega
          have h_i5_val : i5.val = 3329 := by
            rw [i5_post1]
            have h_and_val : (mlkem.ntt.Q &&& i4).val = (mlkem.ntt.Q.val) &&& i4.val := by
              simp [Std.UScalar.val_and]
            rw [h_and_val, h_i4_val, h_Q_val]; decide
          have h_c2_val : coefficient2.val = i1.val + 3329 - i2.val := by
            rw [coefficient2_post, h_wadd, h_c1_val, h_i5_val, h_size]
            rw [show 2^32 + i1.val - i2.val + 3329 = (i1.val + 3329 - i2.val) + 2^32 from by omega,
                Nat.add_mod_right, Nat.mod_eq_of_lt]; omega
          omega
      rw [h_coeff2_eq]
      have h_q_eq : MLKEM.q = 3329 := rfl
      unfold cbdPopCoeff2
      rw [← h_i1_val, ← h_i2_val]
      by_cases hle : i2.val ≤ i1.val
      · have h_eq : ((((i1.val : Int) : MLKEM.Zq) - ((i2.val : Int) : MLKEM.Zq))) =
                    ((i1.val - i2.val : Nat) : MLKEM.Zq) := by
          have h_sub_nat : ((i1.val - i2.val : Nat) : Int) =
                          (i1.val : Int) - (i2.val : Int) := by omega
          have h_to_int : ((i1.val - i2.val : Nat) : MLKEM.Zq) =
                ((((i1.val - i2.val : Nat) : Int)) : MLKEM.Zq) := by push_cast; rfl
          rw [h_to_int, h_sub_nat]; push_cast; ring
        rw [h_eq, ZMod.val_natCast, h_q_eq]
        have h_rewrite : i1.val + 3329 - i2.val = (i1.val - i2.val) + 3329 := by omega
        rw [h_rewrite, Nat.add_mod_right]
      · push Not at hle
        have h_eq : ((((i1.val : Int) : MLKEM.Zq) - ((i2.val : Int) : MLKEM.Zq))) =
                    ((MLKEM.q + i1.val - i2.val : Nat) : MLKEM.Zq) := by
          have h_sub_int : ((MLKEM.q + i1.val - i2.val : Nat) : Int) =
                          (MLKEM.q : Int) + (i1.val : Int) - (i2.val : Int) := by
            push_cast; omega
          have h_to_int : ((MLKEM.q + i1.val - i2.val : Nat) : MLKEM.Zq) =
                ((((MLKEM.q + i1.val - i2.val : Nat) : Int)) : MLKEM.Zq) := by push_cast; rfl
          rw [h_to_int, h_sub_int]
          push_cast
          ring
        rw [h_eq, ZMod.val_natCast, h_q_eq]
        fcongr 1; omega
  · intro k hk hor
    have h_i6_val : i6.val = i.val + consumed := by rw [i6_post]; omega
    simp only [a_post, Std.Array.set_val_eq]
    rw [List.getElem_set]
    split
    · omega
    · exact h_frame k hk (by omega)

/-- **Inner loop spec** for η=2: walk `j ∈ [iter.start, 8)` advancing
`cbdInnerEta2Inv` from `consumed = iter.start.val` to `consumed = 8`.

Postcondition: `pe_dst[i, i+8)` holds the 8 CBD(η=2)-decoded coefficients
packed in `initial_sample_bits`; all other cells unchanged.

Informal proof. Canonical recursive Range-Usize loop (`proof-patterns`
"Loop — Canonical Template", Variant B); mirror of η=3 inner. No
separate `_loop1_loop0_match.spec`: the dispatch is inlined.

- **Mandatory first step**: `rw [poly_element_sample_cbd_from_bytes_loop1_loop0.fold]`.
  (Do NOT use `unfold`.) After the `(next
  iter)` step is consumed, `rw
  [poly_element_sample_cbd_from_bytes_loop1_loop0_match.fold]` to
  expose the `_body` call.
- `step` to consume `next iter`; `cases o`:
  - **`none` arm** (`iter.start = 8`, `consumed = 8`): `_match`'s `none`
    body is `ok pe_dst`; close from `h_inv` directly — at `consumed = 8`,
    `(initial_sample_bits.bv >>> 32) = 0`, so `sample_bits.val = 0`
    matches the post's claimed shift. `agrind`.
  - **`some j` arm**: `j.val = iter.start.val < 8`; `step with
    poly_element_sample_cbd_from_bytes_loop1_loop0_body.spec`
    (discharging `h_ic'` and `h_inv`; the popcount-structure conjunct in
    `h_inv` lets the body's massert succeed); body post yields
    `cbdInnerEta2Inv … (consumed+1)`; `step*` closes the recursive call
    via the IH at `iter' = {iter with start := iter.start + 1}`.
- `termination_by iter.«end».val - iter.start.val`; `decreasing_by agrind`. -/
@[step]
theorem mlkem.ntt.poly_element_sample_cbd_from_bytes_loop1_loop0.spec
    (initial_sample_bits : U32)
    (iter : core.ops.range.Range Usize)
    (pe_dst_orig pe_dst : PolyElement)
    (i : Usize) (sample_bits : U32)
    (h_i : i.val + 8 ≤ 256)
    (h_start : iter.start.val ≤ 8) (h_end : iter.«end».val = 8)
    (h_inv : cbdInnerEta2Inv initial_sample_bits sample_bits
               pe_dst_orig pe_dst i iter.start.val (by grind)) :
    mlkem.ntt.poly_element_sample_cbd_from_bytes_loop1_loop0
        iter pe_dst i sample_bits
      ⦃ (r : PolyElement) =>
          cbdInnerEta2Inv initial_sample_bits
            (({ bv := initial_sample_bits.bv >>> (4 * 8) } : U32))
            pe_dst_orig r i 8 (by grind) ⦄ := by
  rw [poly_element_sample_cbd_from_bytes_loop1_loop0.fold]
  by_cases hlt : iter.start.val < iter.end.val
  · -- some branch
    let* ⟨o, iter1, ho, hstart1, hend1⟩ ← IteratorRange_next_some
    rw [ho]
    rw [poly_element_sample_cbd_from_bytes_loop1_loop0_match.fold]
    simp only
    have h_consumed_lt : iter.start.val < 8 := by rw [← h_end]; exact hlt
    have h_ic_cur : i.val + iter.start.val ≤ 256 := by omega
    have h_ic' : i.val + (iter.start.val + 1) ≤ 256 := by omega
    step with poly_element_sample_cbd_from_bytes_loop1_loop0_body.spec initial_sample_bits
      pe_dst_orig pe_dst i sample_bits iter1 iter.start iter.start.val h_ic_cur rfl
      h_consumed_lt h_ic' h_inv
      as ⟨nsb, niter, pe_dst1, h_nsb, h_niter, h_inv'⟩
    have h_iter1_start : iter1.start.val ≤ 8 := by rw [hstart1]; omega
    have h_iter1_end : iter1.end.val = 8 := by rw [hend1]; exact h_end
    have h_iter1_start_eq : iter1.start.val = iter.start.val + 1 := hstart1
    have h_inv'' : cbdInnerEta2Inv initial_sample_bits nsb pe_dst_orig pe_dst1 i
                     iter1.start.val (by omega) := by
      convert h_inv' using 2
    cases h_niter
    apply WP.spec_mono
      (mlkem.ntt.poly_element_sample_cbd_from_bytes_loop1_loop0.spec initial_sample_bits
        iter1 pe_dst_orig pe_dst1 i nsb (by omega) h_iter1_start h_iter1_end h_inv'')
    rintro r hinv_f
    exact hinv_f
  · -- none branch
    have hge : iter.start.val ≥ iter.end.val := by omega
    let* ⟨o, iter1, ho, _⟩ ← IteratorRange_next_none
    rw [ho]
    rw [poly_element_sample_cbd_from_bytes_loop1_loop0_match.fold]
    simp only [WP.spec_ok]
    have h_start_eq : iter.start.val = 8 := by omega
    have h_inv2 : cbdInnerEta2Inv initial_sample_bits sample_bits pe_dst_orig pe_dst i 8
                    (by omega) := by
      convert h_inv using 2
      omega
    obtain ⟨h_le8, h_sb, h_done, h_undone, h_pop⟩ := h_inv2
    refine ⟨h_le8, ?_, ?_, h_undone, h_pop⟩
    · bv_tac 32
    · exact h_done
termination_by 8 - iter.start.val
decreasing_by
  rw [hstart1]
  omega

/-! ## η=2 outer loop

Each iteration consumes 4 source bytes, applies popcount partitioning
(constant `1431655765 = 0x55555555`), dispatches to inner loop. -/

#decompose mlkem.ntt.poly_element_sample_cbd_from_bytes_loop1
  poly_element_sample_cbd_from_bytes_loop1.fold
  letRange 1 1 => poly_element_sample_cbd_from_bytes_loop1_match

#decompose poly_element_sample_cbd_from_bytes_loop1_match
  poly_element_sample_cbd_from_bytes_loop1_match.fold
  branch 1 (letRange 0 7) => poly_element_sample_cbd_from_bytes_loop1_body

/-- **Streaming invariant for the η=2 outer loop**. -/
def cbdOuterEta2Inv
    (bytes : 𝔹 (64 * (cbdEta 2#u32 (Or.inl rfl)).val))
    (pe_dst_orig pe_dst : PolyElement)
    (src_i : Usize) (chunks : Nat) : Prop :=
  src_i.val = 4 * chunks ∧
  8 * chunks ≤ 256 ∧
  (∀ (k : Nat) (h_k : k < 256),
      k < 8 * chunks →
      ((pe_dst.val[k]'(by have := pe_dst.property; grind)) : U16).val =
        (samplePolyCbdCoeff bytes k h_k).val) ∧
  (∀ (k : Nat) (_ : k < 256),
      8 * chunks ≤ k →
      (pe_dst.val[k]'(by have := pe_dst.property; grind)) =
        (pe_dst_orig.val[k]'(by have := pe_dst_orig.property; grind)))

/-! The `#decompose` declarations and `_loop1_match.fold` equation above
are consumed inside `mlkem.ntt.poly_element_sample_cbd_from_bytes_loop1.spec`'s
proof via the canonical Variant B pattern (see `proof-patterns` skill):
the loop dispatch and per-chunk body step are inlined there, so no
standalone `@[step]` spec is needed for `_match`. -/

/-- **Body spec** for the η=2 outer loop's per-chunk work.

Loads 4 bytes from `pb_src[src_i..src_i+4)`, applies popcount
partitioning with mask `1431655765 = 0x55555555` (selects every other
bit), dispatches inner loop to write 8 CBD(η=2) coefficients, advances
`src_i` by 4.

Informal proof. Template: leaf step-spec; mirror of the η=3 body with
4-byte load and 8-coefficient output. `unfold
poly_element_sample_cbd_from_bytes_loop1_body`; `step*` through:
1. `mlkem.ntt.load_u32_le.spec` at `offset = src_i` — bound
   `src_i.val + 4 ≤ pb_src.length` from `h_inv` and `h_pb_len = 64*2`
   (4-byte read is always in bounds since `src_i = 4*chunks` and
   `4*(chunks+1) ≤ 4*32 = 128 = 64*2`). ✓
2. `U32.band.spec` for `raw &&& 1431655765#u32` (`= 0x55555555` — selects
   bits 0,2,4,…,30: the "low-bit" operands); `bv_tac 32` for the identity.
3. `U32.shr.spec` (`>>> 1`) + `U32.band.spec` (`&&& 0x55555555`) for the
   "high-bit" operands.
4. `U32.add.spec` for `low_bits + high_bits`; the result `sample_bits1`
   packs the 2-bit popcount of each bit-pair at positions 0,2,4,…,30.
5. **Establish the popcount-structure conjunct** required by the
   strengthened `cbdInnerEta2Inv`: for every `k < 8`, the 2-bit fields
   `(sample_bits1 >>> (4*k)) &&& 3` and `(sample_bits1 >>> (4*k+2)) &&& 3`
   are both ≤ 2. This follows from the `0x55555555` mask+shift+add
   identity above — each 2-bit field is the popcount of 2 input bits,
   hence in {0,1,2}; establish via `bv_decide` (a pure 32-bit goal once
   `sample_bits1` is expanded in terms of `raw`).
6. `mlkem.ntt.poly_element_sample_cbd_from_bytes_loop1_loop0.spec` with
   `initial_sample_bits = sample_bits1`, `iter = {start:=0, end:=8}`,
   `i = 8*chunks`; initial `cbdInnerEta2Inv` vacuously at `consumed = 0`
   (the popcount-structure clause comes from step 5).
7. `Usize.add.spec` for `src_i + 4`.
Reconstruct `cbdOuterEta2Inv bytes pe_dst_orig pe_dst' next_src_i
(chunks+1)` from the inner-loop post via `cbdDecodeBits_eq_specCoeff`
(η=2); framing from inner invariant's frame clause; `agrind`. -/
@[step]
theorem poly_element_sample_cbd_from_bytes_loop1_body.spec
    (pb_src : Slice U8) (pe_dst_orig pe_dst : PolyElement)
    (src_i : Usize) (i : Usize)
    (chunks : Nat)
    (h_pb_len : pb_src.length = 64 * 3 + 1)
    (h_i : i.val = 8 * chunks)
    (h_chunks : 8 * chunks + 8 ≤ 256)
    (h_inv : cbdOuterEta2Inv
               (sliceWindowToSpecBytes pb_src 0 (64 * 2) (by grind))
               pe_dst_orig pe_dst src_i chunks) :
    poly_element_sample_cbd_from_bytes_loop1_body pb_src pe_dst src_i i
      ⦃ next_src_i pe_dst' =>
          next_src_i.val = src_i.val + 4 ∧
          cbdOuterEta2Inv (sliceWindowToSpecBytes pb_src 0 (64 * 2) (by grind))
            pe_dst_orig pe_dst' next_src_i (chunks + 1) ⦄ := by
  unfold poly_element_sample_cbd_from_bytes_loop1_body
  obtain ⟨h_src_i_val, h_8ch_le, h_done, h_undone⟩ := h_inv
  have h_pb_lt : src_i.val + 4 ≤ pb_src.length := by
    rw [h_src_i_val, h_pb_len]; omega
  step*
  case hmax =>
    have h_i1_bd : i1.val ≤ 1431655765 := by
      have := Std.UScalar.val_and sample_bits 1431655765#u32
      rw [i1_post1, this]
      have : (1431655765#u32).val = 1431655765 := by decide
      rw [this]; exact Nat.and_le_right
    have h_i3_bd : i3.val ≤ 1431655765 := by
      have := Std.UScalar.val_and i2 1431655765#u32
      rw [i3_post1, this]
      have : (1431655765#u32).val = 1431655765 := by decide
      rw [this]; exact Nat.and_le_right
    have : (Std.U32.max : Nat) = 4294967295 := Std.U32.max_eq
    rw [this]; omega
  case pe_dst_orig => exact pe_dst
  case h_inv =>
    show cbdInnerEta2Inv sample_bits1 sample_bits1 pe_dst pe_dst i 0 _
    refine ⟨by omega, by simp, ?_, ?_, ?_⟩
    · intro j hj; omega
    · intro k _ _; rfl
    · intro k hk
      have h_1431 : ((1431655765#u32) : U32).val = 1431655765 := by decide
      have h_i1_v : i1.val = sample_bits.val &&& 1431655765 := by
        rw [i1_post1, Std.UScalar.val_and, h_1431]
      have h_i3_v : i3.val = sample_bits.val >>> 1 &&& 1431655765 := by
        rw [i3_post1, Std.UScalar.val_and, h_1431, i2_post1]
      have h_i1_bd : i1.val ≤ 1431655765 := by rw [h_i1_v]; exact Nat.and_le_right
      have h_i3_bd : i3.val ≤ 1431655765 := by rw [h_i3_v]; exact Nat.and_le_right
      have h_sb1_bv : sample_bits1.bv =
          (sample_bits.bv &&& 1431655765#32) + (sample_bits.bv >>> 1 &&& 1431655765#32) := by
        apply BitVec.eq_of_toNat_eq
        rw [BitVec.toNat_add]
        simp only [BitVec.toNat_and, BitVec.toNat_ushiftRight]
        have h_1431_bv : (1431655765#32 : BitVec 32).toNat = 1431655765 := by decide
        rw [h_1431_bv]
        simp only [Std.UScalar.bv_toNat]
        rw [sample_bits1_post, h_i1_v, h_i3_v]
        omega
      have h_helper := popcount2_field_le sample_bits.bv k hk
      have h_eq : sample_bits1.val = ((sample_bits.bv &&& 1431655765#32) +
          (sample_bits.bv >>> 1 &&& 1431655765#32)).toNat := by
        rw [← h_sb1_bv, Std.UScalar.bv_toNat]
      rw [h_eq]
      simp only [BitVec.toNat_ushiftRight, BitVec.toNat_and] at h_helper
      have h3 : (3#32 : BitVec 32).toNat = 3 := by decide
      rw [h3] at h_helper
      exact h_helper
  -- After inner loop, rebuild cbdOuterEta2Inv at chunks+1.
  obtain ⟨_, _, h_inner_done, h_inner_frame, _⟩ := pe_dst1_post
  refine ⟨src_i1_post, by rw [src_i1_post, h_src_i_val]; ring, by omega, ?_, ?_⟩
  · -- per-coefficient: split on k < 8*chunks vs k ∈ [8*chunks, 8*chunks+8)
    intro k h_k h_k_lt
    by_cases h_k_low : k < 8 * chunks
    · have h_frame_k : (pe_dst1.val[k]'(by have := pe_dst1.property; grind)) =
                       (pe_dst.val[k]'(by have := pe_dst.property; grind)) := by
        apply h_inner_frame k h_k; left; rw [h_i]; exact h_k_low
      rw [h_frame_k]; exact h_done k h_k h_k_low
    · push Not at h_k_low
      set j := k - 8 * chunks with h_j_def
      have h_j_lt : j < 8 := by omega
      have h_k_eq : k = i.val + j := by rw [h_i]; omega
      have h_inner_k := h_inner_done j h_j_lt
      have h_pe_eq : (pe_dst1.val[i.val + j]'(by have := pe_dst1.property; grind)) =
                     (pe_dst1.val[k]'(by have := pe_dst1.property; grind)) := by
        fcongr 1; exact h_k_eq.symm
      rw [h_pe_eq] at h_inner_k
      rw [h_inner_k]
      -- Deep bridge: cbdPopCoeff2 sample_bits1.val j = samplePolyCbdCoeff bytes (8*chunks+j).
      -- Closed against the axiomatised popcount-mask identity
      -- `popcountPackBridge2` (see `Bridges/Cbd.lean`). Mirror of the η=3
      -- closure at L702-720.
      have h_k_4cj : k = 8 * chunks + j := by rw [h_k_eq, h_i]
      have h_1431 : ((1431655765#u32) : U32).val = 1431655765 := by decide
      have h_packed : sample_bits1.val =
          (sample_bits.val &&& 1431655765) +
          ((sample_bits.val >>> 1) &&& 1431655765) := by
        rw [sample_bits1_post, i1_post1, i3_post1,
            Std.UScalar.val_and, Std.UScalar.val_and, h_1431,
            i2_post1]
      have h_sb_eq : sample_bits.val =
          (pb_src.val[4 * chunks]'(by grind)).val +
          256 * (pb_src.val[4 * chunks + 1]'(by grind)).val +
          65536 * (pb_src.val[4 * chunks + 2]'(by grind)).val +
          16777216 * (pb_src.val[4 * chunks + 3]'(by grind)).val := by
        rw [sample_bits_post]; simp only [h_src_i_val]
      have ax := popcountPackBridge2 pb_src h_pb_len chunks h_chunks j h_j_lt
      unfold cbdPopCoeff2
      rw [h_packed, h_sb_eq]
      exact congrArg ZMod.val (ax.trans (samplePolyCbdCoeff_idx_eq h_k_4cj.symm _ h_k))
  · intro k h_k h_k_ge
    have h_frame_k : (pe_dst1.val[k]'(by have := pe_dst1.property; grind)) =
                     (pe_dst.val[k]'(by have := pe_dst.property; grind)) := by
      apply h_inner_frame k h_k; right; rw [h_i]; omega
    rw [h_frame_k]; exact h_undone k h_k (by omega)

/-- **Outer loop spec** for η=2: walk all 32 4-byte chunks, writing 8
CBD(η=2) coefficients per chunk, until `256 = 8 * 32` coefficients are
filled.

Informal proof. Canonical recursive opaque-`StepBy`-iterator loop
(`proof-patterns` "Loop — Canonical Template", Variant B applied to the
opaque-iterator variant); mirror of η=3 outer. No separate
`_loop1_match.spec` needed.

- **Mandatory first step**: `rw [poly_element_sample_cbd_from_bytes_loop1.fold]`.
  (Do NOT use `unfold`.) After the `(next
  iter)` step is consumed, `rw
  [poly_element_sample_cbd_from_bytes_loop1_match.fold]` to expose the
  `_body` call.
- `step` to consume `iter.next`; `cases o`:
  - **`none` arm**: from `h_iter` with `remaining = 0`, `chunks = 32`;
    `cbdOuterEta2Inv` at `chunks = 32` gives `∀ k < 256, pe_dst[k] =
    samplePolyCbdCoeff bytes k`; close with `final_chunks = 32`, `8 * 32
    = 256`.
  - **`some _` arm**: `step with
    poly_element_sample_cbd_from_bytes_loop1_body.spec`; body post
    yields `cbdOuterEta2Inv … (chunks+1)` and `next_src_i.val = src_i.val
    + 4`; `step*` closes the recursive call via the IH at `remaining' =
    remaining - 1`.
- Decreasing measure: `remaining`; `decreasing_by agrind`.
`wfPoly r` from coefficient bounds; `toPoly r = MLKEM.SamplePolyCBD bytes`
via `samplePolyCbdCoeff_eq_SamplePolyCBD` (bridge in `Bridges/Encoding.lean`). -/
@[step]
theorem mlkem.ntt.poly_element_sample_cbd_from_bytes_loop1.spec
    (iter : core.iter.adapters.step_by.StepBy (core.ops.range.Range Usize))
    (pb_src : Slice U8) (pe_dst_orig pe_dst : PolyElement)
    (src_i : Usize)
    (chunks : Nat)
    (h_pb_len : pb_src.length = 64 * 3 + 1)
    (h_inv : cbdOuterEta2Inv
               (sliceWindowToSpecBytes pb_src 0 (64 * 2) (by grind))
               pe_dst_orig pe_dst src_i chunks)
    (h_iter_start : iter.iter.start.val = 8 * chunks)
    (h_iter_end : iter.iter.«end».val = 256)
    (h_iter_step : iter.step_by.val = 8) :
    mlkem.ntt.poly_element_sample_cbd_from_bytes_loop1 iter pb_src pe_dst src_i
      ⦃ (r : PolyElement) =>
          ∃ (final_chunks : Nat) (final_src_i : Usize),
            cbdOuterEta2Inv (sliceWindowToSpecBytes pb_src 0 (64 * 2) (by grind))
              pe_dst_orig r final_src_i final_chunks ∧
            8 * final_chunks = 256 ⦄ := by
  rw [poly_element_sample_cbd_from_bytes_loop1.fold]
  obtain ⟨h_src_i, h_8ch_le, h_done, h_undone⟩ := h_inv
  by_cases hlt : iter.iter.start.val < iter.iter.«end».val
  · -- some branch: more chunks to process
    have h_step_pos : iter.step_by.val > 0 := by rw [h_iter_step]; decide
    have h_no_overflow : iter.iter.start.val + iter.step_by.val ≤ Usize.max := by
      rw [h_iter_start, h_iter_step]; scalar_tac
    let* ⟨o, iter1, ho, hstart1, hend1, hstep1⟩ ← core.iter.adapters.step_by.IteratorStepBy.next_Range_Usize_some_spec
    rw [ho]
    rw [poly_element_sample_cbd_from_bytes_loop1_match.fold]
    simp only
    have h_chunks_lt : 8 * chunks < 256 := by
      have := hlt; rw [h_iter_start, h_iter_end] at this; exact this
    have h_chunks_bd : 8 * chunks + 8 ≤ 256 := by omega
    step with poly_element_sample_cbd_from_bytes_loop1_body.spec pb_src pe_dst_orig pe_dst src_i iter.iter.start chunks h_pb_len h_iter_start h_chunks_bd ⟨h_src_i, h_8ch_le, h_done, h_undone⟩
      as ⟨next_src_i, pe_dst1, h_next_src_i, h_inv'⟩
    have h_iter1_start : iter1.iter.start.val = 8 * (chunks + 1) := by
      rw [hstart1, h_iter_start, h_iter_step]; ring
    have h_iter1_end : iter1.iter.«end».val = 256 := by rw [hend1]; exact h_iter_end
    have h_iter1_step : iter1.step_by.val = 8 := by rw [hstep1]; exact h_iter_step
    apply WP.spec_mono
      (mlkem.ntt.poly_element_sample_cbd_from_bytes_loop1.spec iter1 pb_src pe_dst_orig
        pe_dst1 next_src_i (chunks + 1) h_pb_len h_inv' h_iter1_start h_iter1_end h_iter1_step)
    rintro r ⟨fc, fsi, hinv_f, hfc⟩
    exact ⟨fc, fsi, hinv_f, hfc⟩
  · -- none branch: iter exhausted
    have hge : iter.iter.start.val ≥ iter.iter.«end».val := by omega
    let* ⟨o, iter1, ho, _⟩ ← core.iter.adapters.step_by.IteratorStepBy.next_Range_Usize_none_spec
    rw [ho]
    rw [poly_element_sample_cbd_from_bytes_loop1_match.fold]
    simp only [WP.spec_ok]
    have h_chunks_eq : 8 * chunks = 256 := by
      rw [h_iter_start, h_iter_end] at hge; omega
    exact ⟨chunks, src_i, ⟨h_src_i, h_8ch_le, h_done, h_undone⟩, h_chunks_eq⟩
termination_by 256 - iter.iter.start.val
decreasing_by
  rw [hstart1, h_iter_start, h_iter_step]
  rw [h_iter_start] at hlt; rw [h_iter_end] at hlt
  omega

/-! ## Bridge: terminal-state outer invariant ⟹ wrapper postcondition

The η=3 and η=2 outer loops both finish with their respective
`cbdOuterEta{3,2}Inv` invariant at a terminal `chunks` value (such that
`4*chunks = 256` resp. `8*chunks = 256`).  From this, every coefficient
of `r` equals `samplePolyCbdCoeff bytes k`, which gives `wfPoly r`
(coefficients are `ZMod`-valued, hence `.val < q`) and `toPoly r =
MLKEM.SamplePolyCBD bytes` via `samplePolyCbdCoeff_eq_SamplePolyCBD`.

Used by both `_loop0.spec` (terminal `none` arm) and the wrapper's two
branches. -/

private theorem cbdOuterEta3Inv_to_post (bytes : 𝔹 (64 * 3))
    (pe_orig r : PolyElement) (src_i : Usize) (chunks : Nat)
    (h_chunks : 4 * chunks = 256)
    (h_inv : cbdOuterEta3Inv bytes pe_orig r src_i chunks) :
    wfPoly r ∧ toPoly r = MLKEM.SamplePolyCBD (η := cbdEta 3#u32 (Or.inr rfl)) bytes := by
  obtain ⟨_, _, h_eq, _⟩ := h_inv
  refine ⟨?_, ?_⟩
  · intro k hk
    have hkc : k < 4 * chunks := by grind
    rw [h_eq k hk hkc]
    exact ZMod.val_lt _
  · apply samplePolyCbdCoeff_eq_SamplePolyCBD
    intro i hi
    have hic : i < 4 * chunks := by grind
    have hval := h_eq i hi hic
    unfold toPoly
    show (Vector.ofFn fun (i : Fin 256) =>
        u16ToZq (r.val[i.val]'(by have := r.property; grind)))[i] = _
    rw [Vector.getElem_ofFn]
    unfold u16ToZq
    rw [hval]
    exact ZMod.natCast_zmod_val _

private theorem cbdOuterEta2Inv_to_post (bytes : 𝔹 (64 * 2))
    (pe_orig r : PolyElement) (src_i : Usize) (chunks : Nat)
    (h_chunks : 8 * chunks = 256)
    (h_inv : cbdOuterEta2Inv bytes pe_orig r src_i chunks) :
    wfPoly r ∧ toPoly r = MLKEM.SamplePolyCBD (η := cbdEta 2#u32 (Or.inl rfl)) bytes := by
  obtain ⟨_, _, h_eq, _⟩ := h_inv
  refine ⟨?_, ?_⟩
  · intro k hk
    have hkc : k < 8 * chunks := by grind
    rw [h_eq k hk hkc]
    exact ZMod.val_lt _
  · apply samplePolyCbdCoeff_eq_SamplePolyCBD
    intro i hi
    have hic : i < 8 * chunks := by grind
    have hval := h_eq i hi hic
    unfold toPoly
    show (Vector.ofFn fun (i : Fin 256) =>
        u16ToZq (r.val[i.val]'(by have := r.property; grind)))[i] = _
    rw [Vector.getElem_ofFn]
    unfold u16ToZq
    rw [hval]
    exact ZMod.natCast_zmod_val _

/-! ## Top wrapper -/

/-- **Top spec for `poly_element_sample_cbd_from_bytes`**.

Branches on `eta`: dispatches to `loop0` (η=3) or `loop1` (η=2). The
result polynomial equals the spec's `SamplePolyCBD` applied to the
input bytes, lifted to the runtime type.

Informal proof. Template: two-way case-dispatch wrapper.
`unfold mlkem.ntt.poly_element_sample_cbd_from_bytes`; step through the
`massert` (`eta = 2 || eta = 3`, discharged by `rcases h_eta`); then split
on `h_eta : eta.val = 2 ∨ eta.val = 3`:
- **`eta = 3` branch**: `step*` resolves the `if eta = 3` branch; establish
  initial `cbdOuterEta3Inv bytes pe_dst pe_dst 0#usize 0` (vacuous: `src_i
  = 0`, `chunks = 0`, both ∀-clauses have empty range); apply
  `mlkem.ntt.poly_element_sample_cbd_from_bytes_loop0.spec` with `h_iter :
  ∃ remaining, 0 + remaining = 64 ∧ 4 * 64 ≤ 256` (take `remaining = 64`);
  extract `toPoly r = MLKEM.SamplePolyCBD bytes` and `wfPoly r` from the
  loop postcondition.
- **`eta = 2` branch**: same using
  `mlkem.ntt.poly_element_sample_cbd_from_bytes_loop1.spec` with `h_iter :
  ∃ remaining, 0 + remaining = 32 ∧ 8 * 32 ≤ 256` (take `remaining = 32`).
In both branches `cbdEta eta h_eta` reduces to the concrete `Η` value by
`cbdEta_val` (Encoding.lean line 340); `h_pb_len` gives the byte-length
as `64 * eta.val = 64 * 3` or `64 * 2` respectively; `agrind` closes all
arithmetic side-goals. -/
@[step]
theorem mlkem.ntt.poly_element_sample_cbd_from_bytes.spec
    (pb_src : Slice U8) (eta : U32)
    (pe_dst : PolyElement)
    (h_eta : eta.val = 2 ∨ eta.val = 3)
    -- R5-F2: the η=3 path requires 1 padding byte at the tail (193 vs
    -- 192) because the body issues 4-byte `load_u32_le`s while advancing
    -- by 3 per chunk; the η=2 path needs only `64 * 2 = 128`.  SymCrust
    -- allocates a uniform `Array U8 193` (= `[u8; 3 * 64 + 1]`,
    -- `mlkem.rs` line 147) and passes the full slice in both cases, so
    -- the spec records the actual call-site length.  The meaningful
    -- spec data is the first `64 * η` bytes; the remaining bytes are
    -- read (only at the final η=3 chunk) but never contribute to a
    -- sampled coefficient.
    (h_pb_len : pb_src.length = 64 * 3 + 1) :
    mlkem.ntt.poly_element_sample_cbd_from_bytes pb_src eta pe_dst
      ⦃ (r : PolyElement) =>
          wfPoly r ∧
          toPoly r = MLKEM.SamplePolyCBD (η := cbdEta eta h_eta)
                       (sliceWindowToSpecBytes pb_src 0 (64 * eta.val)
                         (by grind)) ⦄ := by
  unfold mlkem.ntt.poly_element_sample_cbd_from_bytes
  rcases h_eta with heq2 | heq3
  · -- η = 2 branch
    have h_eta_2 : eta = 2#u32 := by scalar_tac
    subst h_eta_2
    simp only [↓reduceIte, show ((2#u32 : U32) ≠ 3#u32) from by decide]
    step*
    case pe_dst_orig => exact pe_dst
    case chunks => exact 0
    case h_inv =>
      refine ⟨by simp, by decide, ?_, ?_⟩
      · intro k _ hh; exact absurd hh (by scalar_tac)
      · intro k _ _; rfl
    case h_iter_start => simp [iter_post1]
    rename_i final_src_i r_arr
    -- r : ℕ (final_chunks), final_src_i : Usize, r_arr : PolyElement (result poly)
    have := cbdOuterEta2Inv_to_post _ pe_dst r_arr final_src_i r r_post2 r_post1
    convert this using 2
    norm_cast
  · -- η = 3 branch
    have h_eta_3 : eta = 3#u32 := by scalar_tac
    subst h_eta_3
    simp only [↓reduceIte, show ((3#u32 : U32) ≠ 2#u32) from by decide]
    step*
    case pe_dst_orig => exact pe_dst
    case chunks => exact 0
    case h_inv =>
      refine ⟨by simp, by decide, ?_, ?_⟩
      · intro k _ h; exact absurd h (by scalar_tac)
      · intro k _ _; rfl
    case h_iter_start => simp [iter_post1]
    rename_i final_src_i r_arr
    have := cbdOuterEta3Inv_to_post _ pe_dst r_arr final_src_i r r_post2 r_post1
    convert this using 2
    norm_cast

end Symcrust.Properties.MLKEM
