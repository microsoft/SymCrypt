/-
  # Encoding/Compress.lean — `poly_element_compress_and_encode` and
  `vector_compress_and_encode`.

  FIPS 203 §4.2.1: pack a polynomial of `d`-bit compressed coefficients
  into a tight byte stream.  Two layers:

  * `poly_element_compress_and_encode` — per-polynomial: maintain a
    32-bit `accumulator` of pending bits; on every coefficient, push
    `d` bits LSB-first; flush a 4-byte little-endian word whenever
    the accumulator is full.
  * `vector_compress_and_encode` — iterate over the `k` polynomials
    of an MLWE vector, writing each one into a slice of `pb_dst`
    of length `d · 32`.

  Bridge target: `Bridges/Encoding.lean`'s `fastCompress_eq_spec_compress`
  (A1.1) — the "multiply-by-magic-constant + shift" optimisation
  computes the same value as `MLKEM.Compress d` for d ∈ {1,4,5,10,11}.

  ## Decompose pattern

  * `poly_element_compress_and_encode_loop`: outer match + inner
    `if-32-then-flush-else-buffer` terminal. Two-clause cascade:
    `letRange 1 1 => match`, `branch 1 (letRange 0 12) => body_prefix`.
    `body_prefix` computes the compressed coefficient and packs into
    the accumulator (12 monadic binds); the terminal `if
    accumulator_full then recurse-with-flush else recurse-without`
    cannot be further decomposed.
  * `vector_compress_and_encode_loop`: body uses
    `Enumerate.Insts.next` which is an `axiom` in `FunsExternal.lean`,
    so Lean's code generator refuses, and `#decompose` reports
    `Failed to find LCNF signature for ...vector_compress_and_encode_loop`.
    Spec given without body extraction.
-/
import Symcrust.Properties.Iterators
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.Encoding
import Symcrust.Properties.MLKEM.Bridges.EncodingStreamCompress
import Symcrust.Properties.MLKEM.Bridges.MontArith
import Symcrust.Properties.MLKEM.Helpers.FastCompressBarrett

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust

namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

/-! ## Per-coefficient body of the compress loop -/

#decompose mlkem.ntt.poly_element_compress_and_encode_loop
    poly_element_compress_and_encode_loop.fold
  letRange 1 1 => poly_element_compress_and_encode_loop_match

#decompose poly_element_compress_and_encode_loop_match
    poly_element_compress_and_encode_loop_match.fold
  branch 1 (letRange 0 12) => poly_element_compress_and_encode_loop_body_prefix

/-! Isolate the Barrett `if d<12 then fast_compress else id` block at position 2
of `_body_prefix` into its own helper.  This shrinks the body_prefix proof from
14+ goals (the inner if-branch's 12 Barrett binds were each side-conditioned by
`step*`) down to a flat 11-bind tail + one helper-spec call.  The helper's
spec is the natural place to invoke `barrett_shift_eq_fastCompress`. -/
#decompose poly_element_compress_and_encode_loop_body_prefix
    poly_element_compress_and_encode_loop_body_prefix.fold
  letRange 2 1 => compress_barrett_step

/-- **Helper spec for `compress_barrett_step`**.

This is the `if n_bits_per_coefficient < 12 then Barrett(d, coeff) else coeff`
block at position 2 of `_body_prefix`, extracted by `#decompose`.

The post follows `coeffToEncode d c = if d<12 then fastCompress d c else c.val`
(see `Bridges/EncodingStream.lean`).  At `d = 12`, the Rust loop is invoked
for the raw 12-bit encoding of the public key (no compression); at `d < 12`,
compression via the Barrett shift is performed and `fastCompress` captures the
mathematical effect (see `Helpers/FastCompressBarrett.lean`).

The numeric bound `r.val < 2 ^ n_bits_per_coefficient.val` is needed downstream
to discharge the AND-mask side-condition in body_prefix. -/
@[step]
theorem compress_barrett_step.spec
    (n_bits_per_coefficient coefficient : U32)
    (h_d : 1 ≤ n_bits_per_coefficient.val ∧ n_bits_per_coefficient.val ≤ 12)
    (h_coeff : coefficient.val < q) :
    compress_barrett_step n_bits_per_coefficient coefficient
      ⦃ (r : U32) =>
          r.val = (if n_bits_per_coefficient.val < 12 then
                    fastCompress n_bits_per_coefficient.val coefficient.val
                  else coefficient.val) ∧
          r.val < 2 ^ n_bits_per_coefficient.val ⦄ := by
  unfold compress_barrett_step
  by_cases hd12 : n_bits_per_coefficient < 12#u32
  · -- if branch: d < 12, run the Barrett pipeline.
    --
    -- Strategy:
    --   The chain (coefficient.val * 2580335 / 2^(32-d) + 1) / 2 % 2^d
    --   = fastCompress d coefficient.val by `barrett_shift_eq_fastCompress`.
    --   Key non-overflow witnesses:
    --     (a) coefficient.val * 2580335 < 2^33 (Barrett bound for c < q).
    --     (b) coefficient2 = multiplication / 2^(32-d) < 2^(d+1) ≤ 2^12.
    --     (c) coefficient4 = (coefficient2 + 1) / 2 ≤ 2^d.
    have hd12' : n_bits_per_coefficient.val < 12 := by scalar_tac
    simp only [hd12, ite_true, if_pos hd12']
    have hSHIFT : mlkem.ntt.COMPRESS_SHIFTCONSTANT.val = 33 := by
      unfold mlkem.ntt.COMPRESS_SHIFTCONSTANT; rfl
    have hMUL : mlkem.ntt.COMPRESS_MULCONSTANT.val = 2580335 := by
      unfold mlkem.ntt.COMPRESS_MULCONSTANT; rfl
    -- The central Barrett bound: c * 2580335 < 2^33 for c < q.
    have hq : (q : Nat) = 3329 := by decide
    have h_barrett_bound : coefficient.val * 2580335 < 2^33 := by
      have hcq : coefficient.val ≤ 3328 := by rw [hq] at h_coeff; scalar_tac
      calc coefficient.val * 2580335
          ≤ 3328 * 2580335 := Nat.mul_le_mul_right _ hcq
        _ < 2^33 := by decide
    /- Five side-goals after step*:
       (0) coefficient2 + 1 ≤ U32.max — coefficient2.val < 2^12 ≤ 4096
       (1) coefficient4 ≤ i5  (= 2^d)  — coefficient4.val ≤ 2^d
       (2) 1 ≤ i5 — i5.val = 2^d ≥ 2 for d ≥ 1
       (3) coefficient5 < i5 — coefficient5 = coefficient4 &&& (2^d-1) < 2^d
       (4) Final: coefficient5.val = fastCompress d coeff ∧ coefficient5.val < 2^d
    -/
    step*
    · -- Goal 0: coefficient2.val + 1 ≤ U32.max
      -- Use the bounds chain: coefficient2.val = i4.val < 2^12 < 2^32
      have h_i_val : i.val = coefficient.val := by
        rw [i_post]; exact U32.cast_U64_val_eq coefficient
      have h_i1_val : i1.val = 2580335 := by
        rw [i1_post, U32.cast_U64_val_eq]; exact hMUL
      have h_mul_val : multiplication.val = coefficient.val * 2580335 := by
        rw [multiplication_post, h_i_val, h_i1_val]
      have h_i3_val : i3.val = 32 - n_bits_per_coefficient.val := by
        rw [i3_post1, hSHIFT, i2_post]; scalar_tac
      have h_pow_pos : 2 ^ (32 - n_bits_per_coefficient.val) > 0 := by positivity
      have h_i4_val : i4.val = multiplication.val / 2 ^ (32 - n_bits_per_coefficient.val) := by
        rw [i4_post1, h_i3_val]; simp [Nat.shiftRight_eq_div_pow]
      have h_i4_bound : i4.val < 2 ^ (n_bits_per_coefficient.val + 1) := by
        rw [h_i4_val, h_mul_val]
        have h_div : coefficient.val * 2580335 / 2 ^ (32 - n_bits_per_coefficient.val)
                     < 2 ^ 33 / 2 ^ (32 - n_bits_per_coefficient.val) := by
          apply Nat.div_lt_div_of_lt_of_dvd
          · exact Nat.pow_dvd_pow 2 (by scalar_tac)
          · exact h_barrett_bound
        have h_calc : (2 : Nat) ^ 33 / 2 ^ (32 - n_bits_per_coefficient.val)
                      = 2 ^ (n_bits_per_coefficient.val + 1) := by
          rw [Nat.pow_div (by scalar_tac) (by decide)]
          fcongr 1; scalar_tac
        rw [h_calc] at h_div; exact h_div
      have h_c2_val : coefficient2.val = i4.val := by
        rw [coefficient2_post, UScalar.cast_val_eq]
        apply Nat.mod_eq_of_lt
        calc i4.val < 2 ^ (n_bits_per_coefficient.val + 1) := h_i4_bound
          _ ≤ 2 ^ 13 := Nat.pow_le_pow_right (by decide) (by scalar_tac)
          _ < 2 ^ 32 := by decide
      have h_c2_bd : coefficient2.val < 4096 := by
        rw [h_c2_val]
        calc i4.val
            < 2 ^ (n_bits_per_coefficient.val + 1) := h_i4_bound
          _ ≤ 2 ^ 12 := Nat.pow_le_pow_right (by decide) (by scalar_tac)
      scalar_tac
    · -- Goal 1: coefficient4 ≤ i5
      -- coefficient4.val = (coefficient2.val + 1) / 2 ≤ (4095 + 1) / 2 = 2048 ≤ 2^d
      -- Actually: coefficient3.val = coefficient2.val + 1 ≤ 2^(d+1)
      -- coefficient4.val = coefficient3.val / 2 ≤ 2^d
      -- i5.val = 1 <<< d = 2^d.
      have h_i_val : i.val = coefficient.val := by
        rw [i_post]; exact U32.cast_U64_val_eq coefficient
      have h_i1_val : i1.val = 2580335 := by
        rw [i1_post, U32.cast_U64_val_eq]; exact hMUL
      have h_mul_val : multiplication.val = coefficient.val * 2580335 := by
        rw [multiplication_post, h_i_val, h_i1_val]
      have h_i3_val : i3.val = 32 - n_bits_per_coefficient.val := by
        rw [i3_post1, hSHIFT, i2_post]; scalar_tac
      have h_i4_val : i4.val = multiplication.val / 2 ^ (32 - n_bits_per_coefficient.val) := by
        rw [i4_post1, h_i3_val]; simp [Nat.shiftRight_eq_div_pow]
      have h_i4_bound : i4.val < 2 ^ (n_bits_per_coefficient.val + 1) := by
        rw [h_i4_val, h_mul_val]
        have h_div : coefficient.val * 2580335 / 2 ^ (32 - n_bits_per_coefficient.val)
                     < 2 ^ 33 / 2 ^ (32 - n_bits_per_coefficient.val) := by
          apply Nat.div_lt_div_of_lt_of_dvd
          · exact Nat.pow_dvd_pow 2 (by scalar_tac)
          · exact h_barrett_bound
        have h_calc : (2 : Nat) ^ 33 / 2 ^ (32 - n_bits_per_coefficient.val)
                      = 2 ^ (n_bits_per_coefficient.val + 1) := by
          rw [Nat.pow_div (by scalar_tac) (by decide)]
          fcongr 1; scalar_tac
        rw [h_calc] at h_div; exact h_div
      have h_c2_val : coefficient2.val = i4.val := by
        rw [coefficient2_post, UScalar.cast_val_eq]
        apply Nat.mod_eq_of_lt
        calc i4.val < 2 ^ (n_bits_per_coefficient.val + 1) := h_i4_bound
          _ ≤ 2 ^ 13 := Nat.pow_le_pow_right (by decide) (by scalar_tac)
          _ < 2 ^ 32 := by decide
      have h_c2_bound : coefficient2.val < 2 ^ (n_bits_per_coefficient.val + 1) := h_c2_val ▸ h_i4_bound
      have h_c3_bound : coefficient3.val ≤ 2 ^ (n_bits_per_coefficient.val + 1) := by
        rw [coefficient3_post]; scalar_tac
      have h_c4_val : coefficient4.val = coefficient3.val / 2 := by
        rw [coefficient4_post1]
        simp [Nat.shiftRight_eq_div_pow]
      have h_c4_bound : coefficient4.val ≤ 2 ^ n_bits_per_coefficient.val := by
        rw [h_c4_val]
        have : coefficient3.val / 2 ≤ 2 ^ (n_bits_per_coefficient.val + 1) / 2 := by
          exact Nat.div_le_div_right h_c3_bound
        have h_pow_div : (2 : Nat) ^ (n_bits_per_coefficient.val + 1) / 2 = 2 ^ n_bits_per_coefficient.val := by
          rw [Nat.pow_succ, Nat.mul_div_cancel _ (by decide : (0:Nat) < 2)]
        rw [h_pow_div] at this; exact this
      have h_i5_val : i5.val = 2 ^ n_bits_per_coefficient.val := by
        rw [i5_post1]
        rw [Nat.shiftLeft_eq, Nat.one_mul]
        apply Nat.mod_eq_of_lt
        calc 2 ^ n_bits_per_coefficient.val
            ≤ 2 ^ 12 := Nat.pow_le_pow_right (by decide) (by scalar_tac)
          _ < U32.size := by scalar_tac
      -- Goal: coefficient4 ≤ i5 (UScalar comparison) → .val ≤ .val
      show coefficient4.val ≤ i5.val
      rw [h_i5_val]; exact h_c4_bound
    · -- Goal 2: 1 ≤ i5 (i5.val = 2^d ≥ 2 for d ≥ 1)
      have h_i5_val : i5.val = 2 ^ n_bits_per_coefficient.val := by
        rw [i5_post1]
        rw [Nat.shiftLeft_eq, Nat.one_mul]
        apply Nat.mod_eq_of_lt
        calc 2 ^ n_bits_per_coefficient.val
            ≤ 2 ^ 12 := Nat.pow_le_pow_right (by decide) (by scalar_tac)
          _ < U32.size := by scalar_tac
      show (1 : Nat) ≤ i5.val
      rw [h_i5_val]
      calc 1 ≤ 2 ^ 1 := by decide
        _ ≤ 2 ^ n_bits_per_coefficient.val := Nat.pow_le_pow_right (by decide) (by scalar_tac)
    · -- Goal 3: coefficient5 < i5
      -- coefficient5 = coefficient4 &&& (i5 - 1) = coefficient4 &&& (2^d - 1) = coefficient4 % 2^d < 2^d
      have h_i5_val : i5.val = 2 ^ n_bits_per_coefficient.val := by
        rw [i5_post1]
        rw [Nat.shiftLeft_eq, Nat.one_mul]
        apply Nat.mod_eq_of_lt
        calc 2 ^ n_bits_per_coefficient.val
            ≤ 2 ^ 12 := Nat.pow_le_pow_right (by decide) (by scalar_tac)
          _ < U32.size := by scalar_tac
      have h_i6_val : i6.val = 2 ^ n_bits_per_coefficient.val - 1 := by
        rw [i6_post1, h_i5_val]
      have h_c5_val : coefficient5.val = coefficient4.val % 2 ^ n_bits_per_coefficient.val := by
        rw [coefficient5_post1]
        have h_and : (coefficient4 &&& i6).val = coefficient4.val &&& i6.val :=
          UScalar.val_and coefficient4 i6
        rw [h_and, h_i6_val]
        exact Symcrust.Properties.MLKEM.Helpers.nat_and_two_pow_sub_one
                coefficient4.val n_bits_per_coefficient.val
      show coefficient5.val < i5.val
      rw [h_c5_val, h_i5_val]
      exact Nat.mod_lt _ (Nat.pos_of_ne_zero (by
        have : (2 : Nat) ^ n_bits_per_coefficient.val ≥ 2 ^ 1 :=
          Nat.pow_le_pow_right (by decide) (by scalar_tac)
        scalar_tac))
    · -- Goal 4: coefficient5 = fastCompress d c ∧ coefficient5 < 2^d
      -- Full chain: coefficient5.val = ((coefficient.val * 2580335 / 2^(32-d) + 1) / 2) % 2^d
      --           = fastCompress d coefficient.val (via barrett_shift_eq_fastCompress)
      have h_i_val : i.val = coefficient.val := by
        rw [i_post]; exact U32.cast_U64_val_eq coefficient
      have h_i1_val : i1.val = 2580335 := by
        rw [i1_post, U32.cast_U64_val_eq]; exact hMUL
      have h_mul_val : multiplication.val = coefficient.val * 2580335 := by
        rw [multiplication_post, h_i_val, h_i1_val]
      have h_i3_val : i3.val = 32 - n_bits_per_coefficient.val := by
        rw [i3_post1, hSHIFT, i2_post]; scalar_tac
      have h_i4_val : i4.val = multiplication.val / 2 ^ (32 - n_bits_per_coefficient.val) := by
        rw [i4_post1, h_i3_val]; simp [Nat.shiftRight_eq_div_pow]
      have h_i4_bound : i4.val < 2 ^ (n_bits_per_coefficient.val + 1) := by
        rw [h_i4_val, h_mul_val]
        have h_div : coefficient.val * 2580335 / 2 ^ (32 - n_bits_per_coefficient.val)
                     < 2 ^ 33 / 2 ^ (32 - n_bits_per_coefficient.val) := by
          apply Nat.div_lt_div_of_lt_of_dvd
          · exact Nat.pow_dvd_pow 2 (by scalar_tac)
          · exact h_barrett_bound
        have h_calc : (2 : Nat) ^ 33 / 2 ^ (32 - n_bits_per_coefficient.val)
                      = 2 ^ (n_bits_per_coefficient.val + 1) := by
          rw [Nat.pow_div (by scalar_tac) (by decide)]
          fcongr 1; scalar_tac
        rw [h_calc] at h_div; exact h_div
      have h_c2_val : coefficient2.val = i4.val := by
        rw [coefficient2_post, UScalar.cast_val_eq]
        apply Nat.mod_eq_of_lt
        calc i4.val < 2 ^ (n_bits_per_coefficient.val + 1) := h_i4_bound
          _ ≤ 2 ^ 13 := Nat.pow_le_pow_right (by decide) (by scalar_tac)
          _ < 2 ^ 32 := by decide
      have h_c3_val : coefficient3.val = coefficient2.val + 1 := coefficient3_post
      have h_c4_val : coefficient4.val = coefficient3.val / 2 := by
        rw [coefficient4_post1]
        simp [Nat.shiftRight_eq_div_pow]
      have h_i5_val : i5.val = 2 ^ n_bits_per_coefficient.val := by
        rw [i5_post1]
        rw [Nat.shiftLeft_eq, Nat.one_mul]
        apply Nat.mod_eq_of_lt
        calc 2 ^ n_bits_per_coefficient.val
            ≤ 2 ^ 12 := Nat.pow_le_pow_right (by decide) (by scalar_tac)
          _ < U32.size := by scalar_tac
      have h_i6_val : i6.val = 2 ^ n_bits_per_coefficient.val - 1 := by
        rw [i6_post1, h_i5_val]
      have h_c5_val : coefficient5.val = coefficient4.val % 2 ^ n_bits_per_coefficient.val := by
        rw [coefficient5_post1]
        have h_and : (coefficient4 &&& i6).val = coefficient4.val &&& i6.val :=
          UScalar.val_and coefficient4 i6
        rw [h_and, h_i6_val]
        exact Symcrust.Properties.MLKEM.Helpers.nat_and_two_pow_sub_one
                coefficient4.val n_bits_per_coefficient.val
      -- Now assemble: coefficient5.val
      --   = coefficient4.val % 2^d
      --   = (coefficient3.val / 2) % 2^d
      --   = ((coefficient2.val + 1) / 2) % 2^d
      --   = ((i4.val + 1) / 2) % 2^d
      --   = ((multiplication.val / 2^(32-d) + 1) / 2) % 2^d
      --   = ((coefficient.val * 2580335 / 2^(32-d) + 1) / 2) % 2^d
      --   = fastCompress d coefficient.val   (by barrett_shift_eq_fastCompress)
      have h_eq_chain : coefficient5.val
          = ((coefficient.val * 2580335 / 2 ^ (32 - n_bits_per_coefficient.val) + 1) / 2)
              % 2 ^ n_bits_per_coefficient.val := by
        rw [h_c5_val, h_c4_val, h_c3_val, h_c2_val, h_i4_val, h_mul_val]
      have h_fc : ((coefficient.val * 2580335 / 2 ^ (32 - n_bits_per_coefficient.val) + 1) / 2)
                  % 2 ^ n_bits_per_coefficient.val
                  = Symcrust.Properties.MLKEM.Bridges.fastCompress
                      n_bits_per_coefficient.val coefficient.val :=
        Symcrust.Properties.MLKEM.Helpers.barrett_shift_eq_fastCompress
          n_bits_per_coefficient.val coefficient.val (And.intro h_d.1 hd12')
      refine ⟨?_, ?_⟩
      · rw [h_eq_chain, h_fc]
      · -- coefficient5.val < 2^d
        rw [h_c5_val]
        exact Nat.mod_lt _ (Nat.pos_of_ne_zero (by
          have : (2 : Nat) ^ n_bits_per_coefficient.val ≥ 2 ^ 1 :=
            Nat.pow_le_pow_right (by decide) (by scalar_tac)
          scalar_tac))
  · -- else branch: d = 12, passthrough
    have hd12' : ¬ n_bits_per_coefficient.val < 12 := by scalar_tac
    have hd_eq : n_bits_per_coefficient.val = 12 := by scalar_tac
    simp only [hd12, ite_false, if_neg hd12']
    refine ⟨rfl, ?_⟩
    rw [hd_eq]
    have hq_val : (q : Nat) = 3329 := by decide
    have : coefficient.val < 3329 := by rw [← hq_val]; exact h_coeff
    have : coefficient.val < 4096 := by scalar_tac
    show coefficient.val < 2 ^ 12
    have h2 : (2 : Nat) ^ 12 = 4096 := by decide
    rw [h2]; assumption




/-! The `#decompose` declarations and `_loop_match.fold` equation above
are consumed inside `poly_element_compress_and_encode_loop.spec`'s proof
via the canonical Variant B pattern (see `proof-patterns` skill): the
loop dispatch and per-iteration `_loop_body_prefix` step are inlined
there, so no standalone `@[step]` spec is needed for `_loop_match`. -/

/-- **Body-prefix spec** for the compress loop — per-iteration bit-level FC.

Effect of one body iteration on the bit-pump state:
* `c := fastCompress d src_coeff.val` is the compressed value to inject.
* `n_bits_to_encode := min d (32 - n_bits_in_accumulator)` bits of `c`
  go into the accumulator at position `n_bits_in_accumulator`.
* `n_bits_in_coefficient := d - n_bits_to_encode` is the leftover that
  remains in `coefficient1`.

The `accumulator1` / `coefficient1` bit-equations specify exactly which
bits move where; this is what the leaf wrapper composes with the
streaming invariant.

  **Informal proof.**
  `rw [poly_element_compress_and_encode_loop_body_prefix.fold]; step*;
   simp only [core.cmp.min]; step*` through the ~10 monadic binds.
  After the leaf `compress_barrett_step.spec` consumes the Barrett block,
  the remaining sub-goals fall into:
  * **Numeric**: bit-counter equalities (`n_bits_to_encode = min …`,
    `n_bits_in_coefficient = …`, `n_bits_in_accumulator1 = …`) and the
    overflow side-goal `1 ≤ i1` (where `i1 = 1 <<< min`).  Discharge
    with `scalar_tac`/`agrind` after `core.cmp.impls.OrdU32.min_val`.
  * **Bit equations**: two `∀ j < ·, testBit …` conjuncts — the
    OR-into-accumulator (uses `h_acc_zero` to kill the high-acc bits)
    and the accumulator low-prefix unchanged.  Each is a chain of
    `Nat.testBit_or/and/shiftLeft/two_pow_sub_one/mod_two_pow` lemmas.
  * **Coefficient equality**: `coefficient1.val = compressed` is the
    helper's own post; `coefficient1.val < 2^d` likewise. -/
@[step]
theorem poly_element_compress_and_encode_loop_body_prefix.spec
    (n_bits_per_coefficient accumulator n_bits_in_accumulator : U32)
    (src_coeff : U16)
    (h_d : 1 ≤ n_bits_per_coefficient.val ∧ n_bits_per_coefficient.val ≤ 12)
    (h_coeff : src_coeff.val < q)
    (h_acc : n_bits_in_accumulator.val < 32)
    (h_acc_zero : ∀ k, n_bits_in_accumulator.val ≤ k →
        ¬ accumulator.val.testBit k) :
    poly_element_compress_and_encode_loop_body_prefix
        n_bits_per_coefficient accumulator n_bits_in_accumulator src_coeff
      ⦃ coefficient1 n_bits_to_encode n_bits_in_coefficient
        accumulator1 n_bits_in_accumulator1 =>
          /- Bit-accounting: split `d` into encoded + leftover. -/
          n_bits_to_encode.val =
            min n_bits_per_coefficient.val (32 - n_bits_in_accumulator.val) ∧
          n_bits_in_coefficient.val =
            n_bits_per_coefficient.val - n_bits_to_encode.val ∧
          n_bits_in_accumulator1.val =
            n_bits_in_accumulator.val + n_bits_to_encode.val ∧
          /- `coefficient1` is the (possibly compressed) coefficient,
             un-shifted.  Downstream loop consumer right-shifts by
             `n_bits_to_encode` to obtain the leftover for the next
             iteration's accumulator.  Guarded by `if d<12` because at
             `d=12` the Rust impl skips Barrett compression. -/
          coefficient1.val =
            (if n_bits_per_coefficient.val < 12 then
                fastCompress n_bits_per_coefficient.val src_coeff.val
              else src_coeff.val) ∧
          coefficient1.val < 2 ^ n_bits_per_coefficient.val ∧
          /- OR-into-accumulator: the low `n_bits_to_encode` bits of
             `coefficient1` (= compressed) are written to accumulator
             positions `[n_bits_in_accumulator, n_bits_in_accumulator1)`. -/
          (∀ (j : Nat) (_ : j < n_bits_to_encode.val),
              accumulator1.val.testBit (n_bits_in_accumulator.val + j)
                = (if n_bits_per_coefficient.val < 12 then
                    fastCompress n_bits_per_coefficient.val src_coeff.val
                  else src_coeff.val).testBit j) ∧
          /- Accumulator low prefix unchanged. -/
          (∀ (j : Nat) (_ : j < n_bits_in_accumulator.val),
              accumulator1.val.testBit j = accumulator.val.testBit j) ∧
          /- High accumulator bits above `n_bits_in_accumulator1` are 0.
             Needed by the loop spec to derive the BitVec equation
             expected by `matchesRuntime_step_compress`. -/
          (∀ (j : Nat),
              n_bits_in_accumulator1.val ≤ j →
              ¬ accumulator1.val.testBit j) ⦄ := by
  rw [poly_element_compress_and_encode_loop_body_prefix.fold]
  step*
  simp only [core.cmp.min]
  step*
  · -- 1 ≤ i1 overflow side-goal:  i1 = 1 <<< min, min ≤ 12 < 32.
    have hmin : (core.cmp.impls.OrdU32.min n_bits_per_coefficient i).val ≤ 12 := by
      rw [core.cmp.impls.OrdU32.min_val]; scalar_tac
    have hpow : (1 <<< (core.cmp.impls.OrdU32.min n_bits_per_coefficient i).val
                  : Nat) < U32.size := by
      rw [Nat.shiftLeft_eq, Nat.one_mul]
      calc (2 : Nat) ^ _ ≤ 2 ^ 12 := Nat.pow_le_pow_right (by decide) hmin
        _ < U32.size := by scalar_tac
    rw [i1_post1, Nat.mod_eq_of_lt hpow, Nat.shiftLeft_eq, Nat.one_mul]
    show 1 ≤ 2 ^ _
    exact Nat.one_le_two_pow
  -- Main 8-conjunct post.
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · -- n_bits_to_encode = min n_bits_per_coefficient (32 - n_bits_in_accumulator)
    rw [core.cmp.impls.OrdU32.min_val, i_post1]
  · -- n_bits_in_coefficient = n_bits_per_coefficient - n_bits_to_encode
    exact n_bits_in_coefficient_post1
  · -- n_bits_in_accumulator1 = n_bits_in_accumulator + n_bits_to_encode
    exact n_bits_in_accumulator1_post
  · -- coefficient1 = compressed
    convert coefficient1_post1 using 2 <;> try rfl
  · -- coefficient1 < 2^d
    exact coefficient1_post2
  · -- bit equation: OR-into-acc.
    intros j hj
    have hmin12 : (core.cmp.impls.OrdU32.min n_bits_per_coefficient i).val ≤ 12 := by
      rw [core.cmp.impls.OrdU32.min_val]; scalar_tac
    have hmin_le : (core.cmp.impls.OrdU32.min n_bits_per_coefficient i).val ≤ i.val := by
      rw [core.cmp.impls.OrdU32.min_val]; exact Nat.min_le_right _ _
    have hp_lt : (n_bits_in_accumulator.val + j) < 32 := by
      have hi_val : i.val = 32 - n_bits_in_accumulator.val := i_post1
      omega
    have hp_ge : n_bits_in_accumulator.val + j ≥ n_bits_in_accumulator.val := by omega
    have hpow_lt : (1 <<< (core.cmp.impls.OrdU32.min n_bits_per_coefficient i).val
                    : Nat) < U32.size := by
      rw [Nat.shiftLeft_eq, Nat.one_mul]
      calc (2 : Nat) ^ _ ≤ 2 ^ 12 := Nat.pow_le_pow_right (by decide) hmin12
        _ < U32.size := by scalar_tac
    have hi1 : i1.val =
        2 ^ (core.cmp.impls.OrdU32.min n_bits_per_coefficient i).val := by
      rw [i1_post1, Nat.mod_eq_of_lt hpow_lt, Nat.shiftLeft_eq, Nat.one_mul]
    have hi2 : i2.val =
        2 ^ (core.cmp.impls.OrdU32.min n_bits_per_coefficient i).val - 1 := by
      rw [i2_post1, hi1]
    have hbe : bits_to_encode.val =
        coefficient1.val &&& (2 ^ (core.cmp.impls.OrdU32.min n_bits_per_coefficient i).val - 1) := by
      rw [bits_to_encode_post1, UScalar.val_and, hi2]
    have hacc1 : accumulator1.val = accumulator.val ||| i3.val := by
      rw [accumulator1_post1, UScalar.val_or]
    have hacc_p : accumulator.val.testBit (n_bits_in_accumulator.val + j) = false := by
      simpa using h_acc_zero _ hp_ge
    have hsize : U32.size = 2^32 := by simp [U32.size, U32.numBits]
    have hjdiff : n_bits_in_accumulator.val + j - n_bits_in_accumulator.val = j := by omega
    rw [hacc1, Nat.testBit_or, hacc_p, Bool.false_or,
        i3_post1, hsize, Nat.testBit_mod_two_pow, Nat.testBit_shiftLeft,
        hbe, Nat.testBit_and, Nat.testBit_two_pow_sub_one, coefficient1_post1,
        core.convert.num.FromU32U16.from_val_eq, hjdiff]
    simp only [decide_eq_true hp_lt, decide_eq_true hp_ge,
      decide_eq_true hj, Bool.true_and, Bool.and_true]
  · -- bit equation: low prefix unchanged.
    intros j hj
    have hacc1 : accumulator1.val = accumulator.val ||| i3.val := by
      rw [accumulator1_post1, UScalar.val_or]
    have hsize : U32.size = 2^32 := by simp [U32.size, U32.numBits]
    have hj32 : j < 32 := by scalar_tac
    have hjnot_ge : ¬ j ≥ n_bits_in_accumulator.val := by omega
    rw [hacc1, Nat.testBit_or, i3_post1, hsize, Nat.testBit_mod_two_pow,
        Nat.testBit_shiftLeft]
    simp only [decide_eq_true hj32, decide_eq_false hjnot_ge,
      Bool.true_and, Bool.false_and, Bool.or_false]
  · -- High bits zero: ∀ j ≥ n_bits_in_accumulator1, ¬ accumulator1.testBit j.
    intros j hj
    have hmin12 : (core.cmp.impls.OrdU32.min n_bits_per_coefficient i).val ≤ 12 := by
      rw [core.cmp.impls.OrdU32.min_val]; scalar_tac
    have hmin_le_i : (core.cmp.impls.OrdU32.min n_bits_per_coefficient i).val ≤ i.val := by
      rw [core.cmp.impls.OrdU32.min_val]; exact Nat.min_le_right _ _
    have hpow_lt : (1 <<< (core.cmp.impls.OrdU32.min n_bits_per_coefficient i).val
                    : Nat) < U32.size := by
      rw [Nat.shiftLeft_eq, Nat.one_mul]
      calc (2 : Nat) ^ _ ≤ 2 ^ 12 := Nat.pow_le_pow_right (by decide) hmin12
        _ < U32.size := by scalar_tac
    have hi1 : i1.val =
        2 ^ (core.cmp.impls.OrdU32.min n_bits_per_coefficient i).val := by
      rw [i1_post1, Nat.mod_eq_of_lt hpow_lt, Nat.shiftLeft_eq, Nat.one_mul]
    have hi2 : i2.val =
        2 ^ (core.cmp.impls.OrdU32.min n_bits_per_coefficient i).val - 1 := by
      rw [i2_post1, hi1]
    have hbe : bits_to_encode.val =
        coefficient1.val &&& (2 ^ (core.cmp.impls.OrdU32.min n_bits_per_coefficient i).val - 1) := by
      rw [bits_to_encode_post1, UScalar.val_and, hi2]
    have hacc1 : accumulator1.val = accumulator.val ||| i3.val := by
      rw [accumulator1_post1, UScalar.val_or]
    have hsize : U32.size = 2^32 := by simp [U32.size, U32.numBits]
    -- accumulator.testBit j = false (j ≥ n_bia1 ≥ n_bia, by h_acc_zero).
    have hj_ge_nbia : n_bits_in_accumulator.val ≤ j := by
      rw [n_bits_in_accumulator1_post] at hj; omega
    have hacc_p : accumulator.val.testBit j = false := by
      simpa using h_acc_zero j hj_ge_nbia
    rw [hacc1, Nat.testBit_or, hacc_p, Bool.false_or,
        i3_post1, hsize, Nat.testBit_mod_two_pow, Nat.testBit_shiftLeft, hbe,
        Nat.testBit_and, Nat.testBit_two_pow_sub_one]
    -- After splitting on j < 32 and j ≥ n_bia, we need coeff.testBit (j-n_bia) AND
    -- (decide (j-n_bia < min)) = false because j-n_bia ≥ min (since j ≥ n_bia1).
    rcases Nat.lt_or_ge j 32 with hj32 | hj32
    · simp only [decide_eq_true hj32, Bool.true_and]
      rcases Nat.lt_or_ge j n_bits_in_accumulator.val with hjlt | hjge
      · simp only [decide_eq_false (Nat.not_le_of_lt hjlt), Bool.false_and,
          ]
        decide
      · simp only [decide_eq_true hjge, Bool.true_and]
        have hjsub : (core.cmp.impls.OrdU32.min n_bits_per_coefficient i).val
                       ≤ j - n_bits_in_accumulator.val := by
          rw [n_bits_in_accumulator1_post] at hj; omega
        have hnotlt : ¬ j - n_bits_in_accumulator.val
                        < (core.cmp.impls.OrdU32.min n_bits_per_coefficient i).val := by
          omega
        simp only [decide_eq_false hnotlt, Bool.and_false]
        decide
    · simp only [decide_eq_false (Nat.not_lt_of_ge hj32), Bool.false_and,
        ]
      decide

/-- **Loop spec** for `poly_element_compress_and_encode_loop` — streaming FC
in Stream form.

The runtime quadruple `(pb_dst, cb_dst_written, accumulator,
n_bits_in_accumulator)` enters the loop matching an abstract Stream
state `s_in : CompressEncodeState` (via `matchesRuntime`). The loop
processes each remaining coefficient of `iter` by applying
`CompressEncodeState.body d (coeffToEncode d ⟨coeff, _⟩)` once
per iteration. On exit, the runtime matches `recBody d coeffs_compressed
s_in`, where `coeffs_compressed` is the list of compressed-coefficient
values for the iter coeffs processed.

This spec describes the **post-loop, pre-flush** state: the loop itself
does NOT perform the final `massert (n_bits_in_accumulator = 0)`; that
check (and the resulting `n_bits_left.val = 0` consequence) belongs to
`poly_element_compress_and_encode.spec`.

  **Informal proof.** Canonical recursive loop (`proof-patterns`
  "Loop — Canonical Template", Variant B). No separate `_match.spec`
  is used: the match dispatch is inlined into this proof.

  - **Mandatory first step**: `rw [poly_element_compress_and_encode_loop.fold]`
    to expose `<loop>_match` under the let-binder (do NOT `unfold` —
    that inlines the body and prevents the body-prefix `step` from
    firing). After the `(next iter)` step is consumed, `rw
    [poly_element_compress_and_encode_loop_match.fold]` to expose
    the `_body_prefix` call.
  - `step` to consume `next iter` (yields `o` and `iter1`).
  - `cases o`:
    - **`none` arm** (iterator exhausted): the body is
      `ok (pb_dst, cb_dst_written, n_bits_in_accumulator)`; close
      the existential by witnessing `coeffs_remaining := []`, hence
      `recBody d [] s_in = s_in`, hence the post `matchesRuntime`
      is exactly the entering `h_match`; `agrind`.
    - **`some src_coeff` arm**: `step with
      poly_element_compress_and_encode_loop_body_prefix.spec`
      (per-iteration bit-pump leaf); the body-prefix post delivers
      the accumulator-update bit-equations.  The terminal flush-or-
      buffer step fires via a further `step` (in-line); we then have
      the runtime state `(pb_dst1, cb_dst_written1, acc1, acci1)`
      matching `body d (coeffToEncode d ⟨src_coeff.val, _⟩) s_in`
      via a bridge lemma `step_matches_body` (see below).  Recurse
      via the IH with `s_in' := body d ... s_in` and prepend
      `src_coeff.val` to the output coefficient list; `recBody`
      composes via `recBody_cons`.
  - `termination_by iter.slice.length - iter.i`;
    `decreasing_by scalar_decr_tac`.

  **Bridge lemma**: `step_matches_body_compress`
  (`Bridges/EncodingStream.lean`) — relates the post of `_body_prefix.spec` + the terminal
  `if-32` to one `CompressEncodeState.body d x s_in` step.  It takes
  the bit-equations from the body-prefix post combined with the
  flush-arm conditional and produces the four fields of
  `body d (coeffToEncode d ⟨src_coeff.val, h⟩) s_in`.  This is the
  central piece of Bridge 2 (Aeneas → Stream). -/
@[step]
theorem mlkem.ntt.poly_element_compress_and_encode_loop.spec
    (iter : core.slice.iter.Iter U16)
    (n_bits_per_coefficient : U32) (pb_dst : Slice U8)
    (cb_dst_written : Usize) (accumulator n_bits_in_accumulator : U32)
    (s_in : Bridges.CompressEncodeState)
    (h_d : 1 ≤ n_bits_per_coefficient.val ∧ n_bits_per_coefficient.val ≤ 12)
    (h_match : Bridges.CompressEncodeState.matchesRuntime s_in pb_dst
                cb_dst_written accumulator n_bits_in_accumulator)
    (h_len_inv : Bridges.CompressEncodeState.length_inv
                  n_bits_per_coefficient.val s_in iter.i)
    (h_iter_bound : iter.slice.length ≤ 256)
    (h_wf_iter : ∀ k : ℕ, ∀ (h_k : iter.i + k < iter.slice.length),
                    (iter.slice.val[iter.i + k]'h_k).val < q) :
    mlkem.ntt.poly_element_compress_and_encode_loop
        iter n_bits_per_coefficient pb_dst cb_dst_written accumulator
        n_bits_in_accumulator
      ⦃ pb_dst' cb_dst_written' n_bits_left =>
          pb_dst'.length = pb_dst.length ∧
          ∃ (coeffs_remaining : List Nat) (s_out : Bridges.CompressEncodeState)
            (acc_final : U32),
              coeffs_remaining.length = iter.slice.length - iter.i ∧
              (∀ (k : Nat) (h_k : k < coeffs_remaining.length),
                  coeffs_remaining[k]'h_k < q ∧
                  ∃ (h_k' : iter.i + k < iter.slice.length),
                    (coeffs_remaining[k]'h_k : Nat)
                      = (iter.slice.val[iter.i + k]'h_k').val) ∧
              /- Stream invariant: `s_out` results from folding
                 `coeffToEncode d ⟨c, _⟩` over the remaining
                 coefficient values starting at `s_in`. -/
              s_out = Bridges.CompressEncodeState.recBody
                        n_bits_per_coefficient.val
                        (coeffs_remaining.map (fun (c : Nat) =>
                          /- Each coefficient is bounded by `q`; the
                             ZMod coercion ⟨c, _⟩ is safe.  We use
                             `coeffToEncode` so the d=12 case stays
                             uniform. -/
                          Bridges.coeffToEncode n_bits_per_coefficient.val
                            (ZMod.cast (c : ZMod q) : Zq)))
                        s_in ∧
              Bridges.CompressEncodeState.matchesRuntime s_out pb_dst'
                cb_dst_written' acc_final n_bits_left ⦄ := by
  /- Phase 5b — Wiring via `matchesRuntime_step_compress` umbrella.

     Induct on `iter.slice.length - iter.i` generalizing the loop
     state.  Zero arm: iter exhausted → witness `coeffs_remaining := []`.
     Succ arm: step `next` (some), step `body_prefix.spec`, then split
     on the terminal `if n_bits_in_accumulator1 = 32` (FLUSH vs CARRY).
     Each branch invokes the umbrella + recurses via IH.
  -/
  induction hn : iter.slice.length - iter.i
    generalizing iter pb_dst cb_dst_written accumulator n_bits_in_accumulator s_in with
  | zero =>
    -- iter exhausted
    have h_done : iter.i ≥ iter.slice.length := by omega
    have h_done' : iter.i ≥ iter.slice.len := h_done
    rw [poly_element_compress_and_encode_loop.fold]
    step with core.slice.iter.IteratorSliceIter.next_spec_none iter h_done'
    rw [o_post1, o_post2, poly_element_compress_and_encode_loop_match]
    refine ⟨rfl, [], s_in, accumulator, ?_, ?_, ?_, h_match⟩
    · simp
    · intro k h_k; simp at h_k
    · simp [Bridges.CompressEncodeState.recBody]
  | succ n ih =>
    have h_lt : iter.i < iter.slice.length := by scalar_tac
    have h_lt' : iter.i < iter.slice.len := h_lt
    have h_coeff_lt_q : (iter.slice.val[iter.i]'h_lt).val < q := by
      have := h_wf_iter 0 (by simpa using h_lt); simpa using this
    -- Extract precondition witnesses for body_prefix.spec from h_match+h_len_inv.
    have h_d_ge1 : 1 ≤ n_bits_per_coefficient.val := h_d.1
    have h_d_le12 : n_bits_per_coefficient.val ≤ 12 := h_d.2
    have h_acc_strict : n_bits_in_accumulator.val < 32 := by
      have h_acci : s_in.acci = n_bits_in_accumulator.val := h_match.2.2.2.2.1
      have h_acci_mod : s_in.acci = (n_bits_per_coefficient.val * iter.i) % 32 :=
        h_len_inv.2.2.2
      have h_lt_32 : (n_bits_per_coefficient.val * iter.i) % 32 < 32 :=
        Nat.mod_lt _ (by decide)
      omega
    have h_acc_zero : ∀ k, n_bits_in_accumulator.val ≤ k →
        ¬ accumulator.val.testBit k := by
      intro k hk
      have h_acc_eq : s_in.acc = BitVec.ofNat 32 accumulator.val := h_match.2.2.2.2.2.2.1
      have h_acci : s_in.acci = n_bits_in_accumulator.val := h_match.2.2.2.2.1
      have h_hi : ∀ j, s_in.acci ≤ j → ¬ s_in.acc.getLsbD j := h_match.2.2.2.2.2.2.2
      rcases Nat.lt_or_ge k 32 with hk32 | hk32
      · have hge : s_in.acci ≤ k := by omega
        have h1 : ¬ s_in.acc.getLsbD k := h_hi k hge
        rw [h_acc_eq, BitVec.getLsbD_ofNat] at h1
        simp [hk32] at h1
        intro h_tb
        exact absurd h_tb (by simp [h1])
      · have h_lt32 : accumulator.val < 2 ^ 32 := by
          have h_sz : accumulator.val < U32.size := by scalar_tac
          simpa [U32.size, U32.numBits] using h_sz
        have h_pow_le : (2 : Nat) ^ 32 ≤ 2 ^ k :=
          Nat.pow_le_pow_right (by decide) hk32
        have h_acc_lt : accumulator.val < 2 ^ k := lt_of_lt_of_le h_lt32 h_pow_le
        intro h_tb
        exact absurd h_tb (by simp [Nat.testBit_lt_two_pow h_acc_lt])
    -- Begin loop unfolding.
    rw [poly_element_compress_and_encode_loop.fold]
    step with core.slice.iter.IteratorSliceIter.next.spec iter h_lt'
    rw [poly_element_compress_and_encode_loop_match.fold]
    rw [o_post1]
    step with poly_element_compress_and_encode_loop_body_prefix.spec
    rename_i acc1 nbia1
    -- pb_dst' = coefficient1; cb_dst_written' = n_bits_to_encode;
    -- n_bits_left = n_bits_in_coefficient; acc1 = accumulator1; nbia1 = n_bits_in_accumulator1
    -- Set up convenient names for the body_prefix posts.
    have h_nbe : cb_dst_written'.val = min n_bits_per_coefficient.val (32 - n_bits_in_accumulator.val) :=
      pb_dst'_post1
    have h_nleft : n_bits_left.val = n_bits_per_coefficient.val - cb_dst_written'.val := pb_dst'_post2
    have h_nbia1 : nbia1.val = n_bits_in_accumulator.val + cb_dst_written'.val := pb_dst'_post3
    have h_coeff_eq : pb_dst'.val =
        (if n_bits_per_coefficient.val < 12 then
            fastCompress n_bits_per_coefficient.val (iter.slice.val[iter.i]'h_lt).val
          else (iter.slice.val[iter.i]'h_lt).val) := pb_dst'_post4
    have h_coeff_lt : pb_dst'.val < 2 ^ n_bits_per_coefficient.val := pb_dst'_post5
    have h_acc1_bits : ∀ j < cb_dst_written'.val,
        acc1.val.testBit (n_bits_in_accumulator.val + j) =
          (if n_bits_per_coefficient.val < 12 then
              fastCompress n_bits_per_coefficient.val (iter.slice.val[iter.i]'h_lt).val
            else (iter.slice.val[iter.i]'h_lt).val).testBit j := pb_dst'_post6
    have h_acc1_low : ∀ j < n_bits_in_accumulator.val,
        acc1.val.testBit j = accumulator.val.testBit j := pb_dst'_post7
    have h_acc1_hi_zero : ∀ j, nbia1.val ≤ j → ¬ acc1.val.testBit j := pb_dst'_post8
    -- Split on FLUSH vs CARRY.
    split
    · -- FLUSH branch (isTrue): nbia1 = 32#u32
      rename_i h_flush
      have h_nbia_eq_32 : nbia1.val = 32 := by simp [h_flush]
      -- Bridge: pb_dst'.val = coeffToEncode d (ZMod.cast ((iter.slice[iter.i].val : ZMod q)) : Zq)
      have h_cast_val :
          (ZMod.cast ((((iter.slice.val[iter.i]'h_lt).val : ℕ) : ZMod q)) : Zq).val =
            (iter.slice.val[iter.i]'h_lt).val := by
        rw [ZMod.cast_natCast' (n := q)]
        exact ZMod.val_cast_of_lt h_coeff_lt_q
      have h_x_eq : pb_dst'.val =
          Bridges.coeffToEncode n_bits_per_coefficient.val
            ((((iter.slice.val[iter.i]'h_lt).val : ℕ) : ZMod q).cast : Zq) := by
        rw [h_coeff_eq]
        unfold Bridges.coeffToEncode
        split
        · rw [h_cast_val]
        · rw [h_cast_val]
      have h_x_lt : pb_dst'.val < 2 ^ n_bits_per_coefficient.val := h_coeff_lt
      -- cb_dst_written' = 32 - n_bia (since nbia1 = 32 and nbia1 = n_bia + cb_dst_written').
      have h_cb_eq_room : cb_dst_written'.val = 32 - n_bits_in_accumulator.val := by
        rw [h_nbia1] at h_nbia_eq_32; omega
      have h_d_ge_room : n_bits_per_coefficient.val ≥ 32 - n_bits_in_accumulator.val := by
        rw [h_nbe] at h_cb_eq_room
        by_cases hle : n_bits_per_coefficient.val ≤ 32 - n_bits_in_accumulator.val
        · rw [Nat.min_eq_left hle] at h_cb_eq_room; omega
        · push Not at hle; exact Nat.le_of_lt hle
      have h_n_bits_left_val : n_bits_left.val =
          n_bits_per_coefficient.val - (32 - n_bits_in_accumulator.val) := by
        rw [h_nleft, h_cb_eq_room]
      have h_flush_ge : n_bits_in_accumulator.val + n_bits_per_coefficient.val ≥ 32 := by
        omega
      -- Room from h_len_inv: cb + 4 ≤ pb_dst.length.
      have h_room : cb_dst_written.val + 4 ≤ pb_dst.length := by
        have h_bi : s_in.bi = cb_dst_written.val := h_match.2.2.1
        have h_blen : s_in.b.length = pb_dst.length := h_match.1
        have h_blen_d : 32 * n_bits_per_coefficient.val ≤ s_in.b.length := h_len_inv.1
        have h_bi_eq : s_in.bi = 4 * (n_bits_per_coefficient.val * iter.i / 32) :=
          h_len_inv.2.2.1
        have h_iter_lt_256 : iter.i < 256 := by
          have : iter.slice.length ≤ 256 := h_iter_bound
          omega
        have h_div_lt :
            n_bits_per_coefficient.val * iter.i / 32 < 8 * n_bits_per_coefficient.val := by
          apply (Nat.div_lt_iff_lt_mul (by decide)).mpr
          calc n_bits_per_coefficient.val * iter.i
              < n_bits_per_coefficient.val * 256 := by
                apply Nat.mul_lt_mul_of_pos_left h_iter_lt_256 h_d.1
            _ = 8 * n_bits_per_coefficient.val * 32 := by ring
        have h_cb_le : cb_dst_written.val + 4 ≤ 32 * n_bits_per_coefficient.val := by
          rw [← h_bi, h_bi_eq]; omega
        have h_len_le : 32 * n_bits_per_coefficient.val ≤ pb_dst.length := by
          rw [← h_blen]; exact h_blen_d
        omega
      step*
      · -- s_in: pick the new stream state
        exact Bridges.CompressEncodeState.body n_bits_per_coefficient.val pb_dst'.val s_in
      · -- h_match: matchesRuntime via umbrella + FLUSH dispatch
        -- Bridge: acc1.bv = BitVec.ofNat 32 acc1.val (used in toLEBytes equality)
        have h_acc1_bv : acc1.bv = BitVec.ofNat 32 acc1.val := by
          apply BitVec.eq_of_toNat_eq; simp
        -- s2.val = a.val (Slice/Array)
        have h_s2_eq_a : s2.val = a.val := by rw [s2_post, s1_post]; rfl
        have h_a_len : a.val.length = 4 := by simp
        have h_s2_len : s2.val.length = 4 := by
          rw [h_s2_eq_a]; exact h_a_len
        -- a.val[i].bv equals acc1.bv.toLEBytes[i]
        have h_a_bv : ∀ (i : ℕ) (hi : i < 4), (a.val[i]'(by rw [h_a_len]; exact hi)).bv
                                              = acc1.bv.toLEBytes[i]! := by
          intro i hi
          have h_len_bv : acc1.bv.toLEBytes.length = 4 := BitVec.toLEBytes_length _
          have h_i_lt_a : i < a.val.length := by rw [h_a_len]; exact hi
          have h_i_lt_bv : i < acc1.bv.toLEBytes.length := by rw [h_len_bv]; exact hi
          have h_eq_idx : a.val[i]'h_i_lt_a =
              (List.map (UScalar.mk (ty := .U8)) acc1.bv.toLEBytes)[i]'
                (by rw [List.length_map, h_len_bv]; exact hi) :=
            List.getElem_of_eq a_post h_i_lt_a
          rw [h_eq_idx, List.getElem_map]
          rw [getElem!_pos acc1.bv.toLEBytes i h_i_lt_bv]
        -- FLUSH dispatch witness
        exact Bridges.matchesRuntime_step_compress
          n_bits_per_coefficient.val s_in pb_dst'.val
          pb_dst (index_mut_back s2) cb_dst_written i4
          accumulator n_bits_in_accumulator accumulator2 n_bits_left
          h_d h_x_lt h_match h_room
          (Or.inr ⟨acc1, h_flush_ge,
            (fun j hj => by
              have h := h_acc1_bits j (by rw [h_cb_eq_room]; exact hj)
              rw [← h_coeff_eq] at h
              exact h),
            h_acc1_low,
            -- length preserved by setSlice!
            (by rw [s_post3]; scalar_tac),
            -- prefix: k < cb
            (fun k hk => by
              rw [s_post3]
              show ((pb_dst.setSlice! cb_dst_written.val s2.val).val[k]?.getD 0#u8) = _
              rw [show (pb_dst.setSlice! cb_dst_written.val s2.val).val =
                    pb_dst.val.setSlice! cb_dst_written.val s2.val from rfl]
              rw [List.setSlice!_getElem?_prefix _ _ _ _ hk]),
            -- suffix: cb + 4 ≤ k, k < length
            (fun k hk_ge hk_lt => by
              rw [s_post3]
              show ((pb_dst.setSlice! cb_dst_written.val s2.val).val[k]?.getD 0#u8) = _
              rw [show (pb_dst.setSlice! cb_dst_written.val s2.val).val =
                    pb_dst.val.setSlice! cb_dst_written.val s2.val from rfl]
              rw [List.setSlice!_getElem?_suffix _ _ _ _ (by rw [h_s2_len]; omega)]),
            -- middle: pb_dst1[cb+i].bv = (BitVec.ofNat 32 acc1.val).toLEBytes[i]!
            (fun i hi => by
              rw [s_post3]
              show ((pb_dst.setSlice! cb_dst_written.val s2.val).val[cb_dst_written.val + i]?.getD 0#u8).bv = _
              rw [show (pb_dst.setSlice! cb_dst_written.val s2.val).val =
                    pb_dst.val.setSlice! cb_dst_written.val s2.val from rfl]
              have h_mid :
                  cb_dst_written.val ≤ cb_dst_written.val + i ∧
                    cb_dst_written.val + i - cb_dst_written.val < s2.val.length ∧
                      cb_dst_written.val + i < pb_dst.val.length := by
                have h_len_eq : pb_dst.val.length = pb_dst.length := rfl
                refine ⟨by omega, ?_, ?_⟩
                · rw [h_s2_len]; omega
                · rw [h_len_eq]; omega
              rw [List.setSlice!_getElem?_middle _ _ _ _ h_mid]
              have h_ilt : i < s2.val.length := by rw [h_s2_len]; exact hi
              rw [show cb_dst_written.val + i - cb_dst_written.val = i from by omega,
                  List.getElem?_eq_getElem h_ilt]
              simp only [Option.getD_some]
              rw [List.getElem_of_eq h_s2_eq_a h_ilt]
              rw [h_a_bv i hi, ← h_acc1_bv]),
            -- cb1.val = cb.val + 4
            i4_post,
            -- acc1.val = x >>> (32 - n_bia)
            (by rw [accumulator2_post1, h_cb_eq_room]),
            -- n_bia1.val = d - (32 - n_bia)
            h_n_bits_left_val⟩)
      · -- h_len_inv: body preserves length_inv (iter.i → iter.i + 1 = iter1.i)
        rw [o_post3]
        exact Bridges.CompressEncodeState.body_length_inv n_bits_per_coefficient.val
          pb_dst'.val s_in iter.i h_d (by omega) h_len_inv
      · -- h_wf_iter: same as CARRY arm
        intro k h_k
        have h_k' : iter.i + (k + 1) < iter.slice.length := by
          simp only [o_post2, o_post3] at h_k; omega
        have h_get : (iter1.slice.val[iter1.i + k]'h_k) =
            (iter.slice.val[iter.i + (k+1)]'h_k') := by
          simp only [o_post2, o_post3]; fcongr 1; omega
        rw [h_get]; exact h_wf_iter (k + 1) h_k'
      -- Final post: assemble cons list and equalities.
      rename_i coeffs_rest s_out_inner acc_final_inner
      refine ⟨?_, (iter.slice.val[iter.i]'h_lt).val :: coeffs_rest,
              s_out_inner, acc_final_inner, ?_, ?_, ?_, pb_dst'_post5⟩
      · -- length: index_mut_back s2 preserves pb_dst.length
        rw [pb_dst'_post1, s_post3]; scalar_tac
      · -- length of cons list
        simp [pb_dst'_post2]
      · -- coeffs[k] < q and equality (same as CARRY)
        intro k h_k
        match k, h_k with
        | 0, _ =>
          refine ⟨h_coeff_lt_q, h_lt, ?_⟩
          rfl
        | k+1, h_k =>
          have h_k' : k < coeffs_rest.length := by simpa using h_k
          obtain ⟨h_q, h_k'', h_eq⟩ := pb_dst'_post3 k h_k'
          refine ⟨h_q, ?_, ?_⟩
          · have hkeq : iter.i + (k + 1) = iter1.i + k := by rw [o_post3]; omega
            rw [hkeq, ← o_post2]; exact h_k''
          · show (_ :: coeffs_rest)[k+1] = _
            rw [List.getElem_cons_succ, h_eq]
            simp only [o_post2, o_post3]
            fcongr 1
            simp [Nat.add_assoc, Nat.add_comm 1]
      · -- recBody cons step
        rw [pb_dst'_post4]
        simp only [List.map_cons, Bridges.CompressEncodeState.recBody, List.foldl_cons,
          ← h_x_eq]
    · -- CARRY branch (isFalse): nbia1 ≠ 32#u32
      rename_i h_no_flush
      -- Bridge: pb_dst'.val = coeffToEncode d (ZMod.cast ((iter.slice[iter.i].val : ZMod q)) : Zq)
      have h_cast_val :
          (ZMod.cast ((((iter.slice.val[iter.i]'h_lt).val : ℕ) : ZMod q)) : Zq).val =
            (iter.slice.val[iter.i]'h_lt).val := by
        rw [ZMod.cast_natCast' (n := q)]
        exact ZMod.val_cast_of_lt h_coeff_lt_q
      have h_x_eq : pb_dst'.val =
          Bridges.coeffToEncode n_bits_per_coefficient.val
            ((((iter.slice.val[iter.i]'h_lt).val : ℕ) : ZMod q).cast : Zq) := by
        rw [h_coeff_eq]
        unfold Bridges.coeffToEncode
        split
        · rw [h_cast_val]
        · rw [h_cast_val]
      -- In CARRY: cb_dst_written'.val = d (n_bits_to_encode = d).
      have h_nbia_ne_32 : nbia1.val ≠ 32 := by scalar_tac
      have h_d_le_room : n_bits_per_coefficient.val ≤ 32 - n_bits_in_accumulator.val := by
        rw [h_nbia1, h_nbe] at h_nbia_ne_32
        rcases Nat.lt_or_ge n_bits_per_coefficient.val (32 - n_bits_in_accumulator.val + 1)
          with h | h
        · omega
        · -- min = 32 - n_bia, then nbia1 = 32, contradicts h_nbia_ne_32.
          have : min n_bits_per_coefficient.val (32 - n_bits_in_accumulator.val)
                  = 32 - n_bits_in_accumulator.val := by
            rw [Nat.min_eq_right (by omega : 32 - n_bits_in_accumulator.val ≤ _)]
          rw [this] at h_nbia_ne_32
          exfalso; apply h_nbia_ne_32; omega
      have h_cb_eq_d : cb_dst_written'.val = n_bits_per_coefficient.val := by
        rw [h_nbe, Nat.min_eq_left h_d_le_room]
      have h_carry_bound : n_bits_in_accumulator.val + n_bits_per_coefficient.val ≤ 31 := by
        have h_neq : nbia1.val ≠ 32 := h_nbia_ne_32
        rw [h_nbia1, h_cb_eq_d] at h_neq
        omega
      -- Bit-level equation for matchesRuntime_step_compress (CARRY).
      have h_bv : BitVec.ofNat 32 acc1.val =
          BitVec.ofNat 32 accumulator.val |||
            ((BitVec.ofNat 32 pb_dst'.val) <<< n_bits_in_accumulator.val) := by
        apply BitVec.eq_of_getLsbD_eq
        intro j hj32
        simp only [BitVec.getLsbD_or, BitVec.getLsbD_shiftLeft,
          BitVec.getLsbD_ofNat]
        by_cases h_jn : j < n_bits_in_accumulator.val
        · -- low bits
          have h1 : acc1.val.testBit j = accumulator.val.testBit j :=
            h_acc1_low j h_jn
          have h2 : ¬ n_bits_in_accumulator.val ≤ j := Nat.not_le_of_lt h_jn
          simp [hj32, h1, h2]
        · -- j ≥ n_bia
          push Not at h_jn
          by_cases h_jn1 : j < nbia1.val
          · -- mid bits: in [n_bia, nbia1) = [n_bia, n_bia + d)
            have h_jsub_lt : j - n_bits_in_accumulator.val < cb_dst_written'.val := by
              rw [h_nbia1] at h_jn1; omega
            have h1 : acc1.val.testBit j =
                pb_dst'.val.testBit (j - n_bits_in_accumulator.val) := by
              have := h_acc1_bits (j - n_bits_in_accumulator.val) h_jsub_lt
              rw [show n_bits_in_accumulator.val + (j - n_bits_in_accumulator.val) = j
                  from by omega] at this
              rw [this, ← h_coeff_eq]
            have h_acc_zero_j : accumulator.val.testBit j = false := by
              simpa using h_acc_zero j h_jn
            have h_jsub_lt_32 : j - n_bits_in_accumulator.val < 32 := by omega
            simp [hj32, h1, h_jn, h_acc_zero_j, h_jsub_lt_32]
          · -- high bits: j ≥ nbia1
            push Not at h_jn1
            have h1 : acc1.val.testBit j = false := by
              simpa using h_acc1_hi_zero j h_jn1
            have h_acc_zero_j : accumulator.val.testBit j = false := by
              simpa using h_acc_zero j h_jn
            -- For pb_dst'.val.testBit (j-n_bia): need j-n_bia ≥ d.
            have h_jsub_ge_d : j - n_bits_in_accumulator.val ≥ n_bits_per_coefficient.val := by
              rw [h_nbia1, h_cb_eq_d] at h_jn1; omega
            have h_pbd_lt : pb_dst'.val < 2 ^ (j - n_bits_in_accumulator.val) :=
              lt_of_lt_of_le h_coeff_lt (Nat.pow_le_pow_right (by decide) h_jsub_ge_d)
            have h_pbd_tb : pb_dst'.val.testBit (j - n_bits_in_accumulator.val) = false :=
              Nat.testBit_lt_two_pow h_pbd_lt
            simp [hj32, h1, h_acc_zero_j, h_pbd_tb]
      have h_x_lt : pb_dst'.val < 2 ^ n_bits_per_coefficient.val := h_coeff_lt
      -- Room hypothesis (umbrella signature requires it even though CARRY doesn't consume it).
      have h_room : cb_dst_written.val + 4 ≤ pb_dst.length := by
        have h_bi : s_in.bi = cb_dst_written.val := h_match.2.2.1
        have h_blen : s_in.b.length = pb_dst.length := h_match.1
        have h_blen_d : 32 * n_bits_per_coefficient.val ≤ s_in.b.length := h_len_inv.1
        have h_bi_eq : s_in.bi = 4 * (n_bits_per_coefficient.val * iter.i / 32) :=
          h_len_inv.2.2.1
        have h_iter_lt_256 : iter.i < 256 := by
          have : iter.slice.length ≤ 256 := h_iter_bound
          omega
        have h_div_lt :
            n_bits_per_coefficient.val * iter.i / 32 < 8 * n_bits_per_coefficient.val := by
          apply (Nat.div_lt_iff_lt_mul (by decide)).mpr
          calc n_bits_per_coefficient.val * iter.i
              < n_bits_per_coefficient.val * 256 := by
                apply Nat.mul_lt_mul_of_pos_left h_iter_lt_256 h_d.1
            _ = 8 * n_bits_per_coefficient.val * 32 := by ring
        have h_cb_le : cb_dst_written.val + 4 ≤ 32 * n_bits_per_coefficient.val := by
          rw [← h_bi, h_bi_eq]; omega
        have h_len_le : 32 * n_bits_per_coefficient.val ≤ pb_dst.length := by
          rw [← h_blen]; exact h_blen_d
        omega
      -- Apply matchesRuntime_step_compress umbrella with inline CARRY dispatch.
      have h_match' : Bridges.CompressEncodeState.matchesRuntime
          (Bridges.CompressEncodeState.body n_bits_per_coefficient.val pb_dst'.val s_in)
          pb_dst cb_dst_written acc1 nbia1 :=
        Bridges.matchesRuntime_step_compress n_bits_per_coefficient.val s_in pb_dst'.val
          pb_dst pb_dst cb_dst_written cb_dst_written accumulator n_bits_in_accumulator
          acc1 nbia1 h_d h_x_lt h_match h_room
          (Or.inl ⟨h_carry_bound, rfl, rfl, h_bv, by rw [h_nbia1, h_cb_eq_d]⟩)
      -- length_inv preservation.
      have h_len_inv' : Bridges.CompressEncodeState.length_inv n_bits_per_coefficient.val
          (Bridges.CompressEncodeState.body n_bits_per_coefficient.val pb_dst'.val s_in)
          iter1.i := by
        rw [o_post3]
        exact Bridges.CompressEncodeState.body_length_inv n_bits_per_coefficient.val
          pb_dst'.val s_in iter.i h_d (by omega) h_len_inv
      -- iter1 bounds.
      have h_iter1_bound : iter1.slice.length ≤ 256 := by rw [o_post2]; exact h_iter_bound
      have h_wf_iter1 : ∀ k : ℕ, ∀ (h_k : iter1.i + k < iter1.slice.length),
                          (iter1.slice.val[iter1.i + k]'h_k).val < q := by
        intro k h_k
        have h_k' : iter.i + (k + 1) < iter.slice.length := by
          have := h_k
          rw [o_post2, o_post3] at this; omega
        have h_get : (iter1.slice.val[iter1.i + k]'h_k) =
            (iter.slice.val[iter.i + (k+1)]'h_k') := by
          simp only [o_post2, o_post3]; fcongr 1; omega
        rw [h_get]; exact h_wf_iter (k + 1) h_k'
      have h_meas : iter1.slice.length - iter1.i = n := by
        rw [o_post2, o_post3]; omega
      -- Apply IH.
      apply Aeneas.Std.WP.spec_mono
        (ih iter1 pb_dst cb_dst_written acc1 nbia1
          (Bridges.CompressEncodeState.body n_bits_per_coefficient.val pb_dst'.val s_in)
          h_match' h_len_inv' h_iter1_bound h_wf_iter1 h_meas)
      rintro ⟨pb_dst'', cb_dst_written'', n_bits_left''⟩
      simp only [Aeneas.Std.WP.uncurry']
      rintro ⟨h_len_pres, coeffs_rest, s_out, acc_final, h_len_rest,
              h_coeffs_eq, h_s_out, h_match''⟩
      refine ⟨h_len_pres,
              (iter.slice.val[iter.i]'h_lt).val :: coeffs_rest,
              s_out, acc_final, ?_, ?_, ?_, h_match''⟩
      · -- length
        simp [h_len_rest]
      · -- coeffs[k] < q and equality with iter.slice
        intro k h_k
        match k, h_k with
        | 0, _ =>
          refine ⟨h_coeff_lt_q, h_lt, ?_⟩
          rfl
        | k+1, h_k =>
          have h_k' : k < coeffs_rest.length := by simpa using h_k
          obtain ⟨h_q, h_k'', h_eq⟩ := h_coeffs_eq k h_k'
          refine ⟨h_q, ?_, ?_⟩
          · have hkeq : iter.i + (k + 1) = iter1.i + k := by rw [o_post3]; omega
            rw [hkeq, ← o_post2]; exact h_k''
          · show (_ :: coeffs_rest)[k+1] = _
            rw [List.getElem_cons_succ, h_eq]
            simp only [o_post2, o_post3]
            fcongr 1
            simp [Nat.add_assoc, Nat.add_comm 1]
      · -- s_out = recBody d (compressed_list) s_in
        rw [h_s_out]
        simp only [List.map_cons, Bridges.CompressEncodeState.recBody, List.foldl_cons,
          ← h_x_eq]

end Symcrust.Properties.MLKEM
