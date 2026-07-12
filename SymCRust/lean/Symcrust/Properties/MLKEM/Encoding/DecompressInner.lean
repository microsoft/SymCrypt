/-
  # Encoding/Decompress.lean — `poly_element_decode_and_decompress`
  and `vector_decode_and_decompress`.

  FIPS 203 §4.2.1 inverse: parse a tight byte stream of `d`-bit
  compressed coefficients into a polynomial of `Zq` values.  Three
  layers:

  * `poly_element_decode_and_decompress_loop0_loop0` — per-coefficient
    bit-pump: drain `d` bits from a 32-bit accumulator, refilling
    from `pb_src` whenever exhausted.
  * `poly_element_decode_and_decompress_loop0` — per-coefficient
    wrapper: decompresses the assembled `d`-bit value via the
    fast-decompress trick (mul-by-Q, shift-and-round) and writes
    into the destination polynomial via the IterMut.
  * `poly_element_decode_and_decompress` — wrapper that sets up the
    IterMut over the dst array.
  * `vector_decode_and_decompress_loop` / `_vector_decode_and_decompress`
    — vector-level: iterate over `k` polynomial slots.

  Bridge target: `Bridges/Encoding.lean`'s `fastDecompress_eq_spec_decompress`
  (A1.2) — the "multiply-by-Q + shift-and-round" trick computes the
  same value as `MLKEM.Decompress d` for d ∈ {1,4,5,10,11}.

  ## Decompose patterns

  * `_loop0_loop0`: if-then-recurse top — `branch 0 (letRange 0 12) => body`.
  * `_loop0`: standard match shape with non-trivial NONE arm
    (validation) AND non-trivial SOME arm. Two-clause cascade extracts
    only the SOME-arm prefix (`branch 1 (letRange 0 2) => some_body`).
  * `vector_decode_and_decompress_loop`: standard shape with terminal
    error-propagation `match sc_error` (25+ arms). Two-clause cascade
    `letRange 1 1 => match`, `branch 1 (letRange 0 6) => body`. -/
import Symcrust.Properties.Iterators
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.Encoding
import Symcrust.Properties.MLKEM.Bridges.EncodingStreamDecompress
import Symcrust.Properties.MLKEM.Bridges.MontArith
import Symcrust.Properties.MLKEM.Ntt.Bytes
import Symcrust.Properties.MLKEM.Ntt.ModArith

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust

open symcrust.common
namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

/-! ## Bit-pump inner loop -/

#decompose mlkem.ntt.poly_element_decode_and_decompress_loop0_loop0
    poly_element_decode_and_decompress_loop0_loop0.fold
  branch 0 (letRange 0 12) => poly_element_decode_and_decompress_loop0_loop0_body

/-! Isolate the 4-byte refill prologue at position 0 of `_loop0_loop0_body`
into its own helper.  This shrinks the inner-body proof from 14+ goals
(the refill `if n_acc=0` cascade had ~10 inner binds, each side-conditioned
by `step*`) down to a flat 11-bind tail + one helper-spec call.  The
helper's spec is the natural place to invoke the 4-byte LE load lemma. -/
#decompose poly_element_decode_and_decompress_loop0_loop0_body
    poly_element_decode_and_decompress_loop0_loop0_body.fold
  letRange 0 1 => decompress_refill_step

/-- **Helper spec for `decompress_refill_step`**.

This is the `if n_bits_in_accumulator = 0 then refill_4_LE else id` block
at position 0 of `_loop0_loop0_body`, extracted by `#decompose`.

When the bit-pump accumulator is empty (i.e. all previously loaded bits have
been consumed), this helper reads the next 4 little-endian bytes from
`pb_src[cb_src_read .. cb_src_read + 4]`, ORs them into the accumulator,
advances `cb_src_read` by 4, and sets `n_bits_in_accumulator` to 32.

When the accumulator still has bits, the helper is the identity.

This factors out the byte-load cascade from `_loop0_loop0_body.spec`, so the
inner body proof only sees the linear bit-shift tail. -/
@[step]
theorem decompress_refill_step.spec
    (pb_src : Slice U8)
    (cb_src_read : Usize)
    (accumulator n_bits_in_accumulator : U32)
    (h_src : n_bits_in_accumulator.val = 0 →
              cb_src_read.val + 4 ≤ pb_src.length) :
    decompress_refill_step pb_src cb_src_read accumulator n_bits_in_accumulator
      ⦃ cb_src_read1 accumulator1 n_bits_in_accumulator1 =>
          /- The effective post-refill accumulator. -/
          n_bits_in_accumulator1.val =
            (if n_bits_in_accumulator.val = 0 then 32
             else n_bits_in_accumulator.val) ∧
          cb_src_read1.val =
            (if n_bits_in_accumulator.val = 0 then cb_src_read.val + 4
             else cb_src_read.val) ∧
          accumulator1.val =
            (if h_refill : n_bits_in_accumulator.val = 0 then
               (pb_src.val[cb_src_read.val]'(by grind)).val
               + 2^8 * (pb_src.val[cb_src_read.val + 1]'(by grind)).val
               + 2^16 * (pb_src.val[cb_src_read.val + 2]'(by grind)).val
               + 2^24 * (pb_src.val[cb_src_read.val + 3]'(by grind)).val
             else accumulator.val) ⦄ := by
  unfold decompress_refill_step
  by_cases h_refill : n_bits_in_accumulator = 0#u32
  · -- Refill arm
    simp only [h_refill, ↓reduceIte]
    have h_bounds : cb_src_read.val + 4 ≤ pb_src.length := h_src (by scalar_tac)
    step as ⟨a, ha⟩
    step as ⟨c, hc⟩
    simp only [show ((0#u32).val : Nat) = 0 from rfl, ↓reduceIte, ↓reduceDIte]
    refine ⟨by scalar_tac, by scalar_tac, ?_⟩
    have hp1 : (2^8 : Nat) = 256 := by decide
    have hp2 : (2^16 : Nat) = 65536 := by decide
    have hp3 : (2^24 : Nat) = 16777216 := by decide
    rw [hp1, hp2, hp3]
    exact ha
  · -- No-refill arm
    simp only [h_refill, ↓reduceIte]
    have h_ne : n_bits_in_accumulator.val ≠ 0 := by
      intro hzero
      apply h_refill
      scalar_tac
    simp only [show ¬ n_bits_in_accumulator.val = 0 from h_ne,
               ↓reduceIte, ↓reduceDIte]
    exact ⟨rfl, rfl, rfl⟩



/-- **Body spec** for the bit-pump inner loop's per-iteration work.

Per iteration: optionally refill `accumulator` with 4 fresh bytes
from `pb_src` (when `n_bits_in_accumulator = 0`), then peel off
`n_bits_to_decode := min (d - n_bits_in_coefficient) n_bits_in_accumulator`
bits and OR them into `coefficient` at position `n_bits_in_coefficient`.

The post specifies the bit-level effect on the registers — this is
what the leaf wrapper composes with `decodeDecompressBitsInv` to
derive coefficient-level FC.

  **Informal proof.**
  `unfold poly_element_decode_and_decompress_loop0_loop0_body; step*`
  through ~12 binds (refill branch + OR-into-coefficient + shift
  accumulator).  Split on the refill condition:
  `by_cases h_refill : n_bits_in_accumulator.val = 0`.
  - **Refill branch** (`h_refill`): `step*` processes the 4-byte LE
    load; `h_src h_refill` provides the 4-byte read bounds;
    `acc_eff` is defined by the 4 load expressions; `cb_src_read1 =
    cb_src_read + 4`, `n_bits_in_accumulator_eff = 32`; `agrind`.
  - **No-refill branch** (`¬ h_refill`): accumulator used directly;
    `acc_eff = accumulator.val`; `agrind`.
  - In both branches: count goals (`n_bits_to_decode`,
    `n_bits_in_coefficient1 ≤ d`, `n_bits_in_accumulator1 ≤ 32`,
    `cb_src_read1 ≤ pb_src.length`) close with `agrind` /
    `scalar_tac`.
  - Three bit-register conjuncts (coefficient prefix unchanged, new
    bits = low bits of `acc_eff`, accumulator shifted right by
    `n_bits_to_decode`): `bvify 32` normalises ORs and shifts;
    `bv_tac 32` closes each. -/
@[step]
theorem poly_element_decode_and_decompress_loop0_loop0_body.spec
    (pb_src : Slice U8) (n_bits_per_coefficient : U32)
    (cb_src_read : Usize) (accumulator n_bits_in_accumulator : U32)
    (coefficient n_bits_in_coefficient : U32)
    (h_d : 1 ≤ n_bits_per_coefficient.val ∧ n_bits_per_coefficient.val ≤ 12)
    (h_remaining : n_bits_in_coefficient.val < n_bits_per_coefficient.val)
    (h_acc : n_bits_in_accumulator.val ≤ 32)
    (h_src : n_bits_in_accumulator.val = 0 → cb_src_read.val + 4 ≤ pb_src.length)
    (h_cb : cb_src_read.val ≤ pb_src.length)
    (h_coeff_zero : ∀ k, n_bits_in_coefficient.val ≤ k →
        ¬ coefficient.val.testBit k) :
    poly_element_decode_and_decompress_loop0_loop0_body
        pb_src n_bits_per_coefficient cb_src_read accumulator
        n_bits_in_accumulator coefficient n_bits_in_coefficient
      ⦃ cb_src_read1 accumulator1 n_bits_in_accumulator1
        coefficient1 n_bits_in_coefficient1 =>
          /- Bit-accounting. -/
          let n_bits_to_decode := min
            (n_bits_per_coefficient.val - n_bits_in_coefficient.val)
            (if n_bits_in_accumulator.val = 0 then 32 else n_bits_in_accumulator.val)
          /- The effective (post-refill) accumulator: when the input
             accumulator was empty, we read 4 little-endian bytes from
             `pb_src[cb_src_read..cb_src_read+4]`; otherwise the
             accumulator is untouched. -/
          let acc_eff : Nat :=
            if h_refill : n_bits_in_accumulator.val = 0 then
              (pb_src.val[cb_src_read.val]'(by grind)).val
              + 2^8 * (pb_src.val[cb_src_read.val + 1]'(by grind)).val
              + 2^16 * (pb_src.val[cb_src_read.val + 2]'(by grind)).val
              + 2^24 * (pb_src.val[cb_src_read.val + 3]'(by grind)).val
            else accumulator.val
          n_bits_in_coefficient1.val
            = n_bits_in_coefficient.val + n_bits_to_decode ∧
          n_bits_in_coefficient1.val ≤ n_bits_per_coefficient.val ∧
          n_bits_in_accumulator1.val ≤ 32 ∧
          cb_src_read1.val ≤ pb_src.length ∧
          /- Coefficient prefix unchanged. -/
          (∀ (j : Nat) (_ : j < n_bits_in_coefficient.val),
              coefficient1.val.testBit j = coefficient.val.testBit j) ∧
          /- New coefficient bits = low bits of the effective accumulator. -/
          (∀ (j : Nat) (_ : n_bits_in_coefficient.val ≤ j)
             (_ : j < n_bits_in_coefficient1.val),
              coefficient1.val.testBit j
                = acc_eff.testBit (j - n_bits_in_coefficient.val)) ∧
          /- High bits of coefficient1 are zero. -/
          (∀ k, n_bits_in_coefficient1.val ≤ k →
              ¬ coefficient1.val.testBit k) ∧
          /- Accumulator was shifted right by `n_bits_to_decode`. -/
          accumulator1.val = acc_eff >>> n_bits_to_decode ∧
          /- Source pointer update: advances by 4 iff we refilled. -/
          cb_src_read1.val = cb_src_read.val
              + (if n_bits_in_accumulator.val = 0 then 4 else 0) ∧
          /- Additive bit-pump conservation.  This is the key fact
             needed by the inner loop's bit-pump invariant. -/
          8 * cb_src_read1.val + n_bits_in_accumulator.val
                + n_bits_in_coefficient.val =
            8 * cb_src_read.val + n_bits_in_accumulator1.val
                + n_bits_in_coefficient1.val ⦄ := by
  rw [poly_element_decode_and_decompress_loop0_loop0_body.fold]
  have hsize : U32.size = 2^32 := by simp [U32.size, U32.numBits]
  have h_n_pc_lt : n_bits_per_coefficient.val < 32 := by scalar_tac
  step*
  simp only [core.cmp.min]
  step*
  · -- 1 ≤ i1 overflow side-goal.
    have hmin : (core.cmp.impls.OrdU32.min i n_bits_in_accumulator1).val ≤ 12 := by
      rw [core.cmp.impls.OrdU32.min_val]
      have hi_le : i.val ≤ 12 := by rw [i_post1]; scalar_tac
      exact le_trans (Nat.min_le_left _ _) hi_le
    have hpow : (1 <<< (core.cmp.impls.OrdU32.min i n_bits_in_accumulator1).val
                  : Nat) < U32.size := by
      rw [Nat.shiftLeft_eq, Nat.one_mul]
      calc (2 : Nat) ^ _ ≤ 2 ^ 12 := Nat.pow_le_pow_right (by decide) hmin
        _ < U32.size := by scalar_tac
    rw [i1_post1, Nat.mod_eq_of_lt hpow, Nat.shiftLeft_eq, Nat.one_mul]
    show 1 ≤ 2 ^ _
    exact Nat.one_le_two_pow
  -- Main 8-conjunct post.
  -- Common facts.
  have hmin : (core.cmp.impls.OrdU32.min i n_bits_in_accumulator1).val ≤ 12 := by
    rw [core.cmp.impls.OrdU32.min_val]
    have hi_le : i.val ≤ 12 := by rw [i_post1]; scalar_tac
    exact le_trans (Nat.min_le_left _ _) hi_le
  have hmin_lt32 : (core.cmp.impls.OrdU32.min i n_bits_in_accumulator1).val < 32 := by
    omega
  have hpow_lt : (1 <<< (core.cmp.impls.OrdU32.min i n_bits_in_accumulator1).val
                  : Nat) < U32.size := by
    rw [Nat.shiftLeft_eq, Nat.one_mul]
    calc (2 : Nat) ^ _ ≤ 2 ^ 12 := Nat.pow_le_pow_right (by decide) hmin
      _ < U32.size := by scalar_tac
  have hi1 : i1.val =
      2 ^ (core.cmp.impls.OrdU32.min i n_bits_in_accumulator1).val := by
    rw [i1_post1, Nat.mod_eq_of_lt hpow_lt, Nat.shiftLeft_eq, Nat.one_mul]
  have hi2 : i2.val =
      2 ^ (core.cmp.impls.OrdU32.min i n_bits_in_accumulator1).val - 1 := by
    rw [i2_post1, hi1]
  have hbd : bits_to_decode.val =
      accumulator1.val &&& (2 ^ (core.cmp.impls.OrdU32.min i n_bits_in_accumulator1).val - 1) := by
    rw [bits_to_decode_post1, UScalar.val_and, hi2]
  have hcoeff1 : coefficient1.val = coefficient.val ||| i3.val := by
    rw [coefficient1_post1, UScalar.val_or]
  have hmin_eq :
      (core.cmp.impls.OrdU32.min i n_bits_in_accumulator1).val =
        min (n_bits_per_coefficient.val - n_bits_in_coefficient.val)
          (if n_bits_in_accumulator.val = 0 then 32 else n_bits_in_accumulator.val) := by
    rw [core.cmp.impls.OrdU32.min_val, i_post1, cb_src_read1_post1]
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · -- conjunct 1: n_bic1 = n_bic + n_bits_to_decode
    rw [n_bits_in_coefficient1_post, hmin_eq]
  · -- conjunct 2: n_bic1 ≤ n_pc
    rw [n_bits_in_coefficient1_post, hmin_eq]
    have hmin_le : min (n_bits_per_coefficient.val - n_bits_in_coefficient.val)
        (if n_bits_in_accumulator.val = 0 then 32 else n_bits_in_accumulator.val)
        ≤ n_bits_per_coefficient.val - n_bits_in_coefficient.val := Nat.min_le_left _ _
    have hle : n_bits_in_coefficient.val ≤ n_bits_per_coefficient.val :=
      le_of_lt h_remaining
    omega
  · -- conjunct 3: n_bia1 ≤ 32  (output binder, our n_bits_in_accumulator2)
    rw [n_bits_in_accumulator2_post1, cb_src_read1_post1]
    split_ifs with h
    all_goals omega
  · -- conjunct 4: cb_src_read1 ≤ pb_src.length
    rw [cb_src_read1_post2]
    split_ifs with h
    · have := h_src h; omega
    · exact h_cb
  · -- conjunct 5: coefficient prefix unchanged
    intros j hj
    have hj32 : j < 32 := by
      have : n_bits_in_coefficient.val < n_bits_per_coefficient.val := h_remaining
      have : n_bits_per_coefficient.val ≤ 12 := h_d.2
      omega
    have hjlt : ¬ j ≥ n_bits_in_coefficient.val := by omega
    have hi3_low : i3.val.testBit j = false := by
      rw [i3_post1, hsize, Nat.testBit_mod_two_pow, Nat.testBit_shiftLeft]
      simp only [decide_eq_true hj32, decide_eq_false hjlt,
        Bool.true_and, Bool.false_and]
    rw [hcoeff1, Nat.testBit_or, hi3_low, Bool.or_false]
  · -- conjunct 6: new bits = acc_eff bits.
    intros j hj_lo hj_hi
    have hcoeff_j : coefficient.val.testBit j = false := by
      simpa using h_coeff_zero _ hj_lo
    have hmin_val_eq : n_bits_in_coefficient1.val =
        n_bits_in_coefficient.val
          + (core.cmp.impls.OrdU32.min i n_bits_in_accumulator1).val :=
      n_bits_in_coefficient1_post
    have hj_diff : j - n_bits_in_coefficient.val
        < (core.cmp.impls.OrdU32.min i n_bits_in_accumulator1).val := by
      omega
    have hj_ge : j ≥ n_bits_in_coefficient.val := hj_lo
    have hj32 : j < 32 := by omega
    rw [hcoeff1, Nat.testBit_or, hcoeff_j, Bool.false_or,
        i3_post1, hsize, Nat.testBit_mod_two_pow, Nat.testBit_shiftLeft,
        hbd, Nat.testBit_and, Nat.testBit_two_pow_sub_one]
    simp only [decide_eq_true hj32, decide_eq_true hj_ge,
      decide_eq_true hj_diff, Bool.true_and, Bool.and_true]
    rw [cb_src_read1_post3]
  · -- conjunct 7: high bits of coefficient1 are zero.
    intros k hk
    have hmin_val_eq : n_bits_in_coefficient1.val =
        n_bits_in_coefficient.val
          + (core.cmp.impls.OrdU32.min i n_bits_in_accumulator1).val :=
      n_bits_in_coefficient1_post
    have hk_ge_bic : n_bits_in_coefficient.val ≤ k := by omega
    have hk_diff_ge : k - n_bits_in_coefficient.val
        ≥ (core.cmp.impls.OrdU32.min i n_bits_in_accumulator1).val := by omega
    have hcoeff_k : coefficient.val.testBit k = false := by
      simpa using h_coeff_zero _ hk_ge_bic
    have hi3_k : i3.val.testBit k = false := by
      rw [i3_post1, hsize, Nat.testBit_mod_two_pow, Nat.testBit_shiftLeft,
          hbd, Nat.testBit_and, Nat.testBit_two_pow_sub_one]
      have hkd_ge : ¬ (k - n_bits_in_coefficient.val <
                       (core.cmp.impls.OrdU32.min i n_bits_in_accumulator1).val) := by
        omega
      simp only [decide_eq_false hkd_ge, Bool.and_false]
    simp only [hcoeff1, Nat.testBit_or, hcoeff_k, hi3_k, Bool.or_self]
    decide
  · -- conjunct 8: accumulator1 (output binder = accumulator2) = acc_eff >>> n_bits_to_decode.
    rw [accumulator2_post1, cb_src_read1_post3, hmin_eq]
  · -- conjunct 9: cb_src_read1 = cb_src_read + (if n_bia = 0 then 4 else 0)
    rw [cb_src_read1_post2]
    split_ifs with h0
    · -- refill
      simp []
    · -- no refill
      simp []
  · -- conjunct 10: additive bit-pump conservation.
    -- cb_src_read1 = if n_bia = 0 then cb_src + 4 else cb_src
    -- n_bits_in_accumulator2 = n_bia1 - n_bits_to_decode where
    -- n_bia1 = if n_bia = 0 then 32 else n_bia
    -- n_bic1 = n_bic + n_bits_to_decode (which = (core.cmp...).val)
    rw [n_bits_in_accumulator2_post1, n_bits_in_coefficient1_post,
        cb_src_read1_post1, cb_src_read1_post2]
    split_ifs with h0
    · -- input n_bia = 0 (refill).
      rw [h0]
      have : (core.cmp.impls.OrdU32.min i n_bits_in_accumulator1).val ≤ 32 := by omega
      omega
    · -- input n_bia > 0 (no refill).
      have : (core.cmp.impls.OrdU32.min i n_bits_in_accumulator1).val ≤
              n_bits_in_accumulator1.val :=
        n_bits_in_accumulator2_post2
      have hbia1 : n_bits_in_accumulator1.val = n_bits_in_accumulator.val := by
        rw [cb_src_read1_post1]; simp [h0]
      omega

/-- **Inner loop spec**: drain bits from the source bit-stream
through the accumulator until `n_bits_in_coefficient = d`.

On exit, `coefficient`'s low `d` bits encode the next `d`-bit chunk
of the source bit-stream.

  **Informal proof.** Canonical recursive loop (`proof-patterns`
  Variant A).  **Mandatory first step**: `rw
  [poly_element_decode_and_decompress_loop0_loop0.fold]` to expose the
  `_body` call inside the outer `if`. Do NOT use `unfold
  mlkem.ntt.poly_element_decode_and_decompress_loop0_loop0` — `unfold`
  inlines the 12 bindings and prevents `step
  poly_element_decode_and_decompress_loop0_loop0_body.spec` from firing
  (single-level `branch 0 (letRange 0 12)` decomposition, no `_match`).
  Loop condition: `n_bits_in_coefficient < d`.
  - **SOME (loop continues)**: `step with
    poly_element_decode_and_decompress_loop0_loop0_body.spec` supplying
    `h_d`, `h_remaining : n_bits_in_coefficient.val < d`, `h_acc`,
    `h_src`.  From body post: `n_bits_in_coefficient1 >
    n_bits_in_coefficient`; recursive call with `h_init :
    n_bits_in_coefficient1 ≤ d` (from body post + `agrind`).
    Coefficient prefix unchanged: inductive via the body's `∀ j <`
    clause; `agrind`.  Bit-pump conservation accumulates across
    iterations; `agrind`.
  - **NONE (done, `n_bits_in_coefficient = d`)**: `n_bits_in_coefficient1
    = d` by assumption; bit-pump conservation trivially holds
    (`n_bits_in_coefficient.val - n_bits_in_coefficient.val = 0`);
    `agrind`.
  - `termination_by n_bits_per_coefficient.val - n_bits_in_coefficient.val`;
    `decreasing_by scalar_tac`. -/
@[step]
theorem mlkem.ntt.poly_element_decode_and_decompress_loop0_loop0.spec
    (pb_src : Slice U8) (n_bits_per_coefficient : U32)
    (cb_src_read : Usize) (accumulator n_bits_in_accumulator : U32)
    (coefficient n_bits_in_coefficient : U32)
    (h_d : 1 ≤ n_bits_per_coefficient.val ∧ n_bits_per_coefficient.val ≤ 12)
    (h_init : n_bits_in_coefficient.val ≤ n_bits_per_coefficient.val)
    (h_acc : n_bits_in_accumulator.val ≤ 32)
    (h_src : n_bits_in_accumulator.val ≥
              n_bits_per_coefficient.val - n_bits_in_coefficient.val ∨
             cb_src_read.val + 4 ≤ pb_src.length)
    (h_cb : cb_src_read.val ≤ pb_src.length)
    (h_coeff_zero : ∀ k, n_bits_in_coefficient.val ≤ k →
        ¬ coefficient.val.testBit k) :
    mlkem.ntt.poly_element_decode_and_decompress_loop0_loop0
        pb_src n_bits_per_coefficient cb_src_read accumulator
        n_bits_in_accumulator coefficient n_bits_in_coefficient
      ⦃ cb_src_read1 _accumulator1 n_bits_in_accumulator1
        _coefficient1 n_bits_in_coefficient1 =>
          /- Loop exits with the requested coefficient fully assembled
             and the bit-pump state advanced. -/
          n_bits_in_coefficient1.val = n_bits_per_coefficient.val ∧
          cb_src_read1.val ≤ pb_src.length ∧
          n_bits_in_accumulator1.val ≤ 32 ∧
          /- Coefficient prefix unchanged. -/
          (∀ (j : Nat) (_ : j < n_bits_in_coefficient.val),
              _coefficient1.val.testBit j = coefficient.val.testBit j) ∧
          /- High bits of the fully-assembled coefficient are zero. -/
          (∀ k, n_bits_per_coefficient.val ≤ k →
              ¬ _coefficient1.val.testBit k) ∧
          /- Bit-pump conservation (additive Nat-safe form): bits read
             from source = net bits added to accumulator and coefficient. -/
          cb_src_read1.val * 8 + n_bits_in_accumulator.val + n_bits_in_coefficient.val =
            cb_src_read.val * 8 + n_bits_in_accumulator1.val + n_bits_in_coefficient1.val ⦄ := by
  rw [poly_element_decode_and_decompress_loop0_loop0.fold]
  by_cases h_more : n_bits_in_coefficient.val < n_bits_per_coefficient.val
  · -- Recursive case.
    have h_more_bv : n_bits_per_coefficient > n_bits_in_coefficient := by scalar_tac
    rw [if_pos h_more_bv]
    -- Discharge body's h_src precondition.
    have h_body_src : n_bits_in_accumulator.val = 0 →
                      cb_src_read.val + 4 ≤ pb_src.length := by
      intro h0
      rcases h_src with h_eno | h_ref
      · rw [h0] at h_eno
        omega
      · exact h_ref
    step with poly_element_decode_and_decompress_loop0_loop0_body.spec
      pb_src n_bits_per_coefficient cb_src_read accumulator n_bits_in_accumulator
      coefficient n_bits_in_coefficient h_d h_more h_acc h_body_src h_cb
      h_coeff_zero
    -- Body's posts are now in scope under names cb_src_read1_post1..post9.
    -- Unpack what we need.
    have h_bic1_eq : n_bits_in_coefficient1.val =
        n_bits_in_coefficient.val
          + min (n_bits_per_coefficient.val - n_bits_in_coefficient.val)
              (if n_bits_in_accumulator.val = 0 then 32
               else n_bits_in_accumulator.val) := cb_src_read1_post1
    have h_bic1_le : n_bits_in_coefficient1.val ≤ n_bits_per_coefficient.val :=
      cb_src_read1_post2
    have h_acc1 : n_bits_in_accumulator2.val ≤ 32 := cb_src_read1_post3
    have h_cb1 : cb_src_read1.val ≤ pb_src.length := cb_src_read1_post4
    have h_coeff_zero1 : ∀ k, n_bits_in_coefficient1.val ≤ k →
                          ¬ coefficient1.val.testBit k := cb_src_read1_post7
    have h_body_pump :
        8 * cb_src_read1.val + n_bits_in_accumulator.val + n_bits_in_coefficient.val =
        8 * cb_src_read.val + n_bits_in_accumulator2.val + n_bits_in_coefficient1.val :=
      cb_src_read1_post10
    have h_cb_eq : cb_src_read1.val = cb_src_read.val +
        (if n_bits_in_accumulator.val = 0 then 4 else 0) := cb_src_read1_post9
    -- Body's bits decoded δ > 0 (used for termination and h_src1).
    have h_delta_pos :
        min (n_bits_per_coefficient.val - n_bits_in_coefficient.val)
            (if n_bits_in_accumulator.val = 0 then 32
             else n_bits_in_accumulator.val) > 0 := by
      by_cases h0 : n_bits_in_accumulator.val = 0
      · have h1 : (if n_bits_in_accumulator.val = 0 then (32:Nat)
                   else n_bits_in_accumulator.val) = 32 := by simp [h0]
        rw [h1]; omega
      · have h1 : (if n_bits_in_accumulator.val = 0 then (32:Nat)
                   else n_bits_in_accumulator.val) = n_bits_in_accumulator.val := by simp [h0]
        rw [h1]; omega
    have h_bic_strict : n_bits_in_coefficient.val < n_bits_in_coefficient1.val := by
      rw [h_bic1_eq]; omega
    -- New h_src for recursion.
    have h_src1 :
        n_bits_in_accumulator2.val ≥
          n_bits_per_coefficient.val - n_bits_in_coefficient1.val ∨
        cb_src_read1.val + 4 ≤ pb_src.length := by
      by_cases h0 : n_bits_in_accumulator.val = 0
      · -- Refill case: δ = n_pc - n_bic, n_bic1 = n_pc, so n_pc - n_bic1 = 0.
        left
        have h12 : n_bits_per_coefficient.val ≤ 12 := h_d.2
        have hif1 : (if n_bits_in_accumulator.val = 0 then (32 : Nat)
                     else n_bits_in_accumulator.val) = 32 := by simp [h0]
        have hmin : min (n_bits_per_coefficient.val - n_bits_in_coefficient.val) 32
                    = n_bits_per_coefficient.val - n_bits_in_coefficient.val := by
          apply min_eq_left; omega
        have hbic1' : n_bits_in_coefficient1.val = n_bits_per_coefficient.val := by
          rw [h_bic1_eq, hif1, hmin]; omega
        rw [hbic1']
        simp
      · -- No refill: cb_src_read1 = cb_src_read, original h_src right disjunct preserved.
        rcases h_src with h_eno | h_ref
        · -- n_bia ≥ n_pc - n_bic: δ = n_pc - n_bic, n_bic1 = n_pc, so n_pc - n_bic1 = 0.
          left
          have hbic1' : n_bits_in_coefficient1.val = n_bits_per_coefficient.val := by
            rw [h_bic1_eq]
            have hif : (if n_bits_in_accumulator.val = 0 then (32 : Nat)
                       else n_bits_in_accumulator.val) = n_bits_in_accumulator.val := by
              simp [h0]
            rw [hif]
            have : min (n_bits_per_coefficient.val - n_bits_in_coefficient.val)
                       n_bits_in_accumulator.val =
                    n_bits_per_coefficient.val - n_bits_in_coefficient.val := by
              apply min_eq_left; exact h_eno
            omega
          omega
        · -- cb_src + 4 ≤ length; cb_src_read1 = cb_src_read.
          right
          have hcb_eq' : cb_src_read1.val = cb_src_read.val := by
            rw [h_cb_eq]; simp [h0]
          omega
    -- Recursive call.
    have h_rec := mlkem.ntt.poly_element_decode_and_decompress_loop0_loop0.spec
      pb_src n_bits_per_coefficient cb_src_read1 accumulator2 n_bits_in_accumulator2
      coefficient1 n_bits_in_coefficient1 h_d h_bic1_le h_acc1 h_src1 h_cb1
      h_coeff_zero1
    -- Discharge the goal using the IH via spec_mono.
    apply Aeneas.Std.WP.spec_mono h_rec
    rintro ⟨cb_src_final, acc_final, n_bia_final, coeff_final, n_bic_final⟩
      ⟨h1, h2, h3, h4, h5, h6⟩
    refine ⟨h1, h2, h3, ?_, h5, ?_⟩
    · -- Prefix unchanged: combine body's prefix (j < n_bic) with IH's (j < n_bic1).
      intros j hj
      have hj1 : j < n_bits_in_coefficient1.val := by omega
      have hbody : coefficient1.val.testBit j = coefficient.val.testBit j :=
        cb_src_read1_post5 j hj
      rw [h4 j hj1, hbody]
    · -- Bit-pump composition: body + IH ⇒ loop.
      omega
  · -- Loop terminates.
    have h_eq : n_bits_in_coefficient.val = n_bits_per_coefficient.val := by omega
    have h_nbv : ¬ n_bits_per_coefficient > n_bits_in_coefficient := by scalar_tac
    rw [if_neg h_nbv]
    simp only [Aeneas.Std.WP.spec_ok]
    refine ⟨h_eq, h_cb, h_acc, ?_, ?_, ?_⟩
    · intros j _; trivial
    · intros k hk
      have : n_bits_in_coefficient.val ≤ k := by omega
      exact h_coeff_zero k this
    · omega
termination_by n_bits_per_coefficient.val - n_bits_in_coefficient.val
decreasing_by
  -- Use h_bic_strict from the recursive branch.
  scalar_tac

/-! ### Strengthened inner-loop specs for n_bic_in = 0

The aggregate `_loop0_loop0.spec` above hides the bit-level structure of
the assembled coefficient (it only exposes the high-bits-zero invariant
and bit-pump conservation).  The outer loop wiring needs more: it must
build a `matchesRuntime_step_decode` dispatch witness which depends on
whether the body refilled (`n_bia < d`) or not (`n_bia ≥ d`).

We provide two strengthened specs for the entry point `n_bic_in = 0`,
`coefficient_in = 0`, parametrised by which branch the body takes.  Each
exposes the dispatch-witness-relevant equalities:
* `_loop0_loop0.spec_at_zero_no_refill` — when `n_bia ≥ d`.
  The loop runs exactly one body iteration with `δ = d`.
* `_loop0_loop0.spec_at_zero_refill` — when `n_bia < d` (covers both
  `n_bia = 0` fresh-refill and `0 < n_bia < d` cross-word).  Both cases
  load `loadLEWord pb_src cb_src_read` and produce the bit pattern
  `coefficient = (acc | (loadLEWord <<< n_bia)) & ((1 <<< d) - 1)`.
-/

set_option maxRecDepth 1024 in
/-- **Strengthened inner-loop spec — NO-REFILL case** (`n_bia ≥ d`).

Loop body runs once with `δ = d`, no refill.  Exposes the exact final
accumulator and coefficient bit pattern. -/
theorem mlkem.ntt.poly_element_decode_and_decompress_loop0_loop0.spec_at_zero_no_refill
    (pb_src : Slice U8) (n_bits_per_coefficient : U32)
    (cb_src_read : Usize) (accumulator n_bits_in_accumulator : U32)
    (h_d : 1 ≤ n_bits_per_coefficient.val ∧ n_bits_per_coefficient.val ≤ 12)
    (h_acc : n_bits_in_accumulator.val ≤ 32)
    (h_cb : cb_src_read.val ≤ pb_src.length)
    (h_no_refill : n_bits_per_coefficient.val ≤ n_bits_in_accumulator.val) :
    mlkem.ntt.poly_element_decode_and_decompress_loop0_loop0
        pb_src n_bits_per_coefficient cb_src_read accumulator
        n_bits_in_accumulator 0#u32 0#u32
      ⦃ cb_src_read1 accumulator1 n_bits_in_accumulator1
        coefficient n_bits_in_coefficient1 =>
          n_bits_in_coefficient1.val = n_bits_per_coefficient.val ∧
          cb_src_read1 = cb_src_read ∧
          accumulator1.val = accumulator.val >>> n_bits_per_coefficient.val ∧
          n_bits_in_accumulator1.val =
              n_bits_in_accumulator.val - n_bits_per_coefficient.val ∧
          coefficient.val =
              accumulator.val &&& ((1 <<< n_bits_per_coefficient.val) - 1) ⦄ := by
  rw [poly_element_decode_and_decompress_loop0_loop0.fold]
  have h_pos : n_bits_per_coefficient > 0#u32 := by scalar_tac
  rw [if_pos h_pos]
  have h_nbia_ne_zero : n_bits_in_accumulator.val ≠ 0 := by omega
  have h_body_src : n_bits_in_accumulator.val = 0 →
                    cb_src_read.val + 4 ≤ pb_src.length := fun h0 =>
    absurd h0 h_nbia_ne_zero
  have h_remaining_0 : (0 : Nat) < n_bits_per_coefficient.val := by omega
  have h_coeff_zero_init : ∀ k, (0 : Nat) ≤ k → ¬ (0 : Nat).testBit k := by
    intros k _; simp
  step with poly_element_decode_and_decompress_loop0_loop0_body.spec
    pb_src n_bits_per_coefficient cb_src_read accumulator
    n_bits_in_accumulator 0#u32 0#u32 h_d h_remaining_0 h_acc h_body_src h_cb
    h_coeff_zero_init
  -- δ value at entry n_bic_in = 0.
  have h_delta : min (n_bits_per_coefficient.val - 0)
                  (if n_bits_in_accumulator.val = 0 then 32
                   else n_bits_in_accumulator.val)
              = n_bits_per_coefficient.val := by
    rw [if_neg h_nbia_ne_zero]; omega
  -- Now n_bic_1 = d, so the loop terminates.
  rw [poly_element_decode_and_decompress_loop0_loop0.fold]
  have h_nbic1_eq : n_bits_in_coefficient1.val = n_bits_per_coefficient.val := by
    rw [show n_bits_in_coefficient1.val =
            0 + min (n_bits_per_coefficient.val - 0)
                  (if n_bits_in_accumulator.val = 0 then 32
                   else n_bits_in_accumulator.val) from cb_src_read1_post1, h_delta]
    omega
  have h_term : ¬ (n_bits_per_coefficient > n_bits_in_coefficient1) := by
    scalar_tac
  rw [if_neg h_term]
  simp only [Aeneas.Std.WP.spec_ok]
  have h_cb_eq : cb_src_read1 = cb_src_read := by
    have h_cb_val : cb_src_read1.val = cb_src_read.val := by
      have := cb_src_read1_post9
      rw [if_neg h_nbia_ne_zero] at this; omega
    cases cb_src_read1; cases cb_src_read
    fcongr 1
    apply BitVec.eq_of_toNat_eq
    exact h_cb_val
  refine ⟨h_nbic1_eq, h_cb_eq, ?_, ?_, ?_⟩
  · -- accumulator1.val = accumulator.val >>> d
    have h_acc2 := cb_src_read1_post8
    rw [dif_neg h_nbia_ne_zero, h_delta] at h_acc2
    exact h_acc2
  · -- n_bia1.val = n_bia.val - d
    have h_pump := cb_src_read1_post10
    have h_cb_val : cb_src_read1.val = cb_src_read.val := by
      have := cb_src_read1_post9
      rw [if_neg h_nbia_ne_zero] at this; omega
    omega
  · -- coefficient.val = accumulator.val &&& ((1<<<d) - 1)
    apply Nat.eq_of_testBit_eq
    intro j
    rw [Nat.testBit_and,
        show (1 <<< n_bits_per_coefficient.val - 1) =
              (2 ^ n_bits_per_coefficient.val - 1) from by
              rw [Nat.shiftLeft_eq, Nat.one_mul],
        Nat.testBit_two_pow_sub_one]
    by_cases h_j : j < n_bits_per_coefficient.val
    · simp [h_j]
      have h_lo : (0 : Nat) ≤ j := Nat.zero_le _
      have h_hi : j < n_bits_in_coefficient1.val := by rw [h_nbic1_eq]; exact h_j
      have h_new := cb_src_read1_post6 j h_lo h_hi
      rw [dif_neg h_nbia_ne_zero] at h_new
      simp only [Nat.sub_zero] at h_new
      exact h_new
    · simp [h_j]
      have h_j' : n_bits_per_coefficient.val ≤ j := Nat.le_of_not_lt h_j
      have h_zero := cb_src_read1_post7 j (by rw [h_nbic1_eq]; exact h_j')
      exact Bool.eq_false_iff.mpr h_zero

/- `loadLEWordBytes` and `loadLEWordBytes_eq_proofForm` are now defined
in `Bridges/Encoding.lean` and inherited via the import chain. -/

/-- Pointwise relate the mapped byte-list (used by `loadLEWord` on
`List Byte`) and the U8-keyed `getD` form (used by `loadLEWordBytes`). -/
private theorem map_bv_getD_eq (pb_src : Slice U8) (k : ℕ) :
    (pb_src.val.map (·.bv)).getD k 0#8 = (pb_src.val.getD k 0#u8).bv := by
  by_cases h : k < pb_src.val.length
  · have h' : k < (pb_src.val.map (·.bv)).length := by simp; exact h
    rw [List.getD_eq_getElem _ _ h, List.getD_eq_getElem _ _ h',
        List.getElem_map]
  · push Not at h
    have h' : (pb_src.val.map (·.bv)).length ≤ k := by simp; exact h
    rw [List.getD_eq_default _ _ h', List.getD_eq_default _ _ h]
    rfl

/-- Bridge: a full-window view (`offset = 0`, length `n`) of `s` matches the
list-form `listToSpecBytes` applied to `s.val.take n` (as bytes, then mapped
back to U8 — but `listToSpecBytes` takes `List Byte` so we map via `.bv`).

Used by the per-poly spec body to relate its `streamDecodeDecompressPoly`-style
state (built from the take-truncated source list) to the
`sliceWindowToSpecBytes`-style post (parameterized by `pb_src` plus the
window).  Symmetric to the `Compress`-side slice-window bridge. -/
theorem sliceWindowToSpecBytes_full_eq_listToSpecBytes_take_map
    (s : Slice U8) (n : ℕ) (h_le : n ≤ s.length) :
    sliceWindowToSpecBytes s 0 n (by omega) =
    listToSpecBytes ((s.val.take n).map (·.bv)) n
      (by simp [List.length_take]; omega) := by
  unfold sliceWindowToSpecBytes listToSpecBytes
  apply Vector.ext
  intro k hk
  have h_s : k < s.val.length := by
    have h_eq : s.length = s.val.length := rfl
    have : k < s.length := lt_of_lt_of_le hk h_le
    rw [h_eq] at this; exact this
  have h_take : k < n ∧ k < s.val.length := ⟨hk, h_s⟩
  simp only [Vector.getElem_ofFn, Nat.zero_add, List.getElem_map,
             List.getElem_take]

/-! ### Phase B helper — `loadLEWord ↔ loadLEWordBytes` bridge -/

/-- Bridge between `(loadLEWord (pb_src.val.map (·.bv)) cb).toNat` (the form
used in `matchesRuntime_step_decode`'s REFILL witness) and `loadLEWordBytes
pb_src cb` (the Nat sum form produced by `_some_body.spec_bits`).

Proven via `Nat.eq_of_testBit_eq` + `loadLEWord_getLsbD` + recursive
`Nat.testBit_two_pow_mul_add` decomposition of the little-endian Nat sum. -/
theorem loadLEWord_toNat_eq_loadLEWordBytes
    (pb_src : Slice U8) (cb : ℕ) (h : cb + 4 ≤ pb_src.length) :
    (Bridges.DecodeDecompressState.loadLEWord
        (pb_src.val.map (·.bv)) cb).toNat
      = loadLEWordBytes pb_src cb := by
  have h0 : cb < pb_src.val.length := by simp [Slice.length] at h; omega
  have h1 : cb + 1 < pb_src.val.length := by simp [Slice.length] at h; omega
  have h2 : cb + 2 < pb_src.val.length := by simp [Slice.length] at h; omega
  have h3 : cb + 3 < pb_src.val.length := by simp [Slice.length] at h; omega
  -- Byte values (Nat) and their bounds
  set v0 := (pb_src.val.getD cb 0#u8).val with hv0_def
  set v1 := (pb_src.val.getD (cb + 1) 0#u8).val with hv1_def
  set v2 := (pb_src.val.getD (cb + 2) 0#u8).val with hv2_def
  set v3 := (pb_src.val.getD (cb + 3) 0#u8).val with hv3_def
  have hv0_lt : v0 < 256 := by
    simp only [hv0_def, List.getD_eq_getElem _ _ h0]
    exact (by scalar_tac : (pb_src.val[cb]'h0).val < 256)
  have hv1_lt : v1 < 256 := by
    simp only [hv1_def, List.getD_eq_getElem _ _ h1]
    exact (by scalar_tac : (pb_src.val[cb+1]'h1).val < 256)
  have hv2_lt : v2 < 256 := by
    simp only [hv2_def, List.getD_eq_getElem _ _ h2]
    exact (by scalar_tac : (pb_src.val[cb+2]'h2).val < 256)
  have hv3_lt : v3 < 256 := by
    simp only [hv3_def, List.getD_eq_getElem _ _ h3]
    exact (by scalar_tac : (pb_src.val[cb+3]'h3).val < 256)
  -- Bound the LHS (BitVec 32 toNat)
  have h_LHS_lt : (Bridges.DecodeDecompressState.loadLEWord
      (pb_src.val.map (·.bv)) cb).toNat < 2 ^ 32 :=
    (Bridges.DecodeDecompressState.loadLEWord _ _).isLt
  -- Bound the RHS (sum of 4 bytes)
  have h_RHS_lt : loadLEWordBytes pb_src cb < 2 ^ 32 := by
    show v0 + 2^8 * v1 + 2^16 * v2 + 2^24 * v3 < 2 ^ 32
    have : (2:Nat)^32 = 2^24 * 256 := by norm_num
    omega
  -- Mapped byte list lookup
  have h_map_get : ∀ (i : Nat) (hi : i < pb_src.val.length),
      (pb_src.val.map (·.bv)).getD i 0#8 = (pb_src.val[i]'hi).bv := by
    intro i hi
    have hi' : i < (pb_src.val.map (·.bv)).length := by simp; exact hi
    rw [List.getD_eq_getElem _ _ hi', List.getElem_map]
  -- Each map-getD-bv-toNat equals the byte val
  have hmap0 : ((pb_src.val.map (·.bv)).getD cb 0#8).toNat = v0 := by
    rw [h_map_get _ h0, hv0_def, List.getD_eq_getElem _ _ h0]; rfl
  have hmap1 : ((pb_src.val.map (·.bv)).getD (cb+1) 0#8).toNat = v1 := by
    rw [h_map_get _ h1, hv1_def, List.getD_eq_getElem _ _ h1]; rfl
  have hmap2 : ((pb_src.val.map (·.bv)).getD (cb+2) 0#8).toNat = v2 := by
    rw [h_map_get _ h2, hv2_def, List.getD_eq_getElem _ _ h2]; rfl
  have hmap3 : ((pb_src.val.map (·.bv)).getD (cb+3) 0#8).toNat = v3 := by
    rw [h_map_get _ h3, hv3_def, List.getD_eq_getElem _ _ h3]; rfl
  -- Prove via testBit equality
  apply Nat.eq_of_testBit_eq
  intro k
  by_cases hk : k < 32
  · -- For k < 32: decompose RHS into bytes via testBit_two_pow_mul_add
    have h_RHS_eq : loadLEWordBytes pb_src cb
        = 2^8 * (v1 + 2^8 * (v2 + 2^8 * v3)) + v0 := by
      show v0 + 2^8 * v1 + 2^16 * v2 + 2^24 * v3 = _
      have h16 : (2:Nat)^16 = 2^8 * 2^8 := by norm_num
      have h24 : (2:Nat)^24 = 2^8 * (2^8 * 2^8) := by norm_num
      ring
    rw [h_RHS_eq]
    rw [Nat.testBit_two_pow_mul_add _ (by simpa using hv0_lt : v0 < 2^8)]
    -- LHS: use loadLEWord_getLsbD
    rw [BitVec.testBit_toNat]
    rw [Symcrust.Properties.MLKEM.Bridges.loadLEWord_getLsbD _ _ _ hk]
    unfold Bridges.srcBit
    have h_div : (8 * cb + k) / 8 = cb + k / 8 := by
      rw [show 8 * cb + k = k + cb * 8 by ring,
          Nat.add_mul_div_right _ _ (by decide : (0:ℕ) < 8)]; omega
    have h_mod : (8 * cb + k) % 8 = k % 8 := by
      rw [show 8 * cb + k = k + cb * 8 by ring, Nat.add_mul_mod_self_right]
    rw [h_div, h_mod]
    rcases Nat.lt_or_ge k 8 with hk8 | hk8
    · -- k < 8: byte 0
      simp only [if_pos hk8]
      have h_div_k : k / 8 = 0 := Nat.div_eq_of_lt hk8
      have h_mod_k : k % 8 = k := Nat.mod_eq_of_lt hk8
      rw [h_div_k, h_mod_k, Nat.add_zero, h_map_get _ h0]
      rw [← BitVec.testBit_toNat]
      simp only [hv0_def, List.getD_eq_getElem _ _ h0]
      rfl
    · -- k ≥ 8
      simp only [if_neg (by omega : ¬ k < 8)]
      rw [show v1 + 2^8 * (v2 + 2^8 * v3) = 2^8 * (v2 + 2^8 * v3) + v1 from
            Nat.add_comm _ _]
      rw [Nat.testBit_two_pow_mul_add _ (by simpa using hv1_lt : v1 < 2^8)]
      rcases Nat.lt_or_ge k 16 with hk16 | hk16
      · -- 8 ≤ k < 16: byte 1
        simp only [if_pos (by omega : k - 8 < 8)]
        have h_div_k : k / 8 = 1 := by omega
        have h_mod_k : k % 8 = k - 8 := by omega
        rw [h_div_k, h_mod_k, h_map_get _ h1]
        rw [← BitVec.testBit_toNat]
        simp only [hv1_def, List.getD_eq_getElem _ _ h1]
        rfl
      · simp only [if_neg (by omega : ¬ k - 8 < 8)]
        rw [show v2 + 2^8 * v3 = 2^8 * v3 + v2 from Nat.add_comm _ _]
        rw [Nat.testBit_two_pow_mul_add _ (by simpa using hv2_lt : v2 < 2^8)]
        rcases Nat.lt_or_ge k 24 with hk24 | hk24
        · -- 16 ≤ k < 24: byte 2
          simp only [if_pos (by omega : k - 8 - 8 < 8)]
          have h_div_k : k / 8 = 2 := by omega
          have h_mod_k : k % 8 = k - 16 := by omega
          rw [h_div_k, h_mod_k, h_map_get _ h2]
          rw [← BitVec.testBit_toNat]
          simp only [hv2_def, List.getD_eq_getElem _ _ h2]
          rw [show k - 8 - 8 = k - 16 by omega]
          rfl
        · -- 24 ≤ k < 32: byte 3
          simp only [if_neg (by omega : ¬ k - 8 - 8 < 8)]
          have h_div_k : k / 8 = 3 := by omega
          have h_mod_k : k % 8 = k - 24 := by omega
          rw [h_div_k, h_mod_k, h_map_get _ h3]
          rw [← BitVec.testBit_toNat]
          simp only [hv3_def, List.getD_eq_getElem _ _ h3]
          rw [show k - 8 - 8 - 8 = k - 24 by omega]
          rfl
  · -- k ≥ 32: both LHS and RHS testBit are false
    push Not at hk
    have hk_pow : (2:Nat)^32 ≤ 2^k := Nat.pow_le_pow_right (by decide) hk
    rw [Nat.testBit_lt_two_pow (lt_of_lt_of_le h_LHS_lt hk_pow)]
    rw [Nat.testBit_lt_two_pow (lt_of_lt_of_le h_RHS_lt hk_pow)]

/-- `loadLEWord` depends only on the source bytes at positions `[si, si+4)`;
two `src` lists agreeing on this range produce the same word.

Useful for bridging `loadLEWord s_in.src` (in matchesRuntime) to
`loadLEWord (pb_src.val.map (·.bv))` (in the loadLEWordBytes bridge). -/
theorem loadLEWord_src_eq
    (src1 src2 : List Byte) (si : ℕ)
    (h : ∀ k, si ≤ k → k < si + 4 → src1.getD k 0#8 = src2.getD k 0#8) :
    Bridges.DecodeDecompressState.loadLEWord src1 si
      = Bridges.DecodeDecompressState.loadLEWord src2 si := by
  simp only [Bridges.DecodeDecompressState.loadLEWord]
  rw [h si (le_refl _) (by omega)]
  rw [h (si+1) (by omega) (by omega)]
  rw [h (si+2) (by omega) (by omega)]
  rw [h (si+3) (by omega) (by omega)]

/-- Combined bridge: `loadLEWordBytes pb_src cb = (loadLEWord src cb).toNat`
given the per-position byte-equality conjunct from `matchesRuntime`
(quantified up to some bound `n`) and a 4-byte window guarantee.

The bound `n` is implicit and unified from the type of `h_byteq`.
`matchesRuntime`'s byteq is quantified up to `32 * d` (rather than
`pb_src.length`), so call sites supply `h_room_n : cb + 4 ≤ 32 * d`
in addition to `h_room : cb + 4 ≤ pb_src.length`.  Both bounds coincide
when `pb_src.length = 32 * d` (the per-poly fast path).

Used at all 3 REFILL sites (d<12 OK arm h_match', d=12 OK arm h_match',
d=12 OK arm h_wf k=s_in.pi). -/
theorem loadLEWordBytes_eq_loadLEWord_toNat_of_byteEq
    (pb_src : Slice U8) (src : List Byte) (cb : ℕ) {n : ℕ}
    (h_byteq : ∀ k : ℕ, k < n →
        src.getD k 0#8 = (pb_src.val.getD k 0#u8).bv)
    (h_room_n : cb + 4 ≤ n)
    (h_room : cb + 4 ≤ pb_src.length) :
    loadLEWordBytes pb_src cb
      = (Bridges.DecodeDecompressState.loadLEWord src cb).toNat := by
  rw [← loadLEWord_toNat_eq_loadLEWordBytes pb_src cb h_room]
  fcongr 1
  apply loadLEWord_src_eq
  intro k _ hk_hi
  have hk_lt_n : k < n := by omega
  have hk_lt : k < pb_src.length := by omega
  rw [h_byteq k hk_lt_n]
  rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD]
  simp only [List.getElem?_map]
  rcases hk_some : pb_src.val[k]? with _ | x
  · simp [] at hk_some
    simp [Slice.length] at hk_lt
    omega
  · simp

set_option maxRecDepth 4096 in
set_option maxHeartbeats 800000 in
/-- **Strengthened inner-loop spec — REFILL case** (`n_bia < d`).

Covers both `n_bia = 0` (1 body iteration) and `0 < n_bia < d`
(2 body iterations).  Exposes the final accumulator and coefficient
bit pattern as functions of the 4-byte LE word loaded from
`pb_src[cb_src_read..cb_src_read+4]`. -/
theorem mlkem.ntt.poly_element_decode_and_decompress_loop0_loop0.spec_at_zero_refill
    (pb_src : Slice U8) (n_bits_per_coefficient : U32)
    (cb_src_read : Usize) (accumulator n_bits_in_accumulator : U32)
    (h_d : 1 ≤ n_bits_per_coefficient.val ∧ n_bits_per_coefficient.val ≤ 12)
    (h_acc : n_bits_in_accumulator.val ≤ 32)
    (h_room : cb_src_read.val + 4 ≤ pb_src.length)
    (h_cb : cb_src_read.val ≤ pb_src.length)
    (h_refill : n_bits_in_accumulator.val < n_bits_per_coefficient.val) :
    mlkem.ntt.poly_element_decode_and_decompress_loop0_loop0
        pb_src n_bits_per_coefficient cb_src_read accumulator
        n_bits_in_accumulator 0#u32 0#u32
      ⦃ cb_src_read1 accumulator1 n_bits_in_accumulator1
        coefficient n_bits_in_coefficient1 =>
          let bytes := loadLEWordBytes pb_src cb_src_read.val
          n_bits_in_coefficient1.val = n_bits_per_coefficient.val ∧
          cb_src_read1.val = cb_src_read.val + 4 ∧
          accumulator1.val =
              bytes >>> (n_bits_per_coefficient.val - n_bits_in_accumulator.val) ∧
          n_bits_in_accumulator1.val =
              n_bits_in_accumulator.val + 32 - n_bits_per_coefficient.val ∧
          coefficient.val =
              (accumulator.val &&& ((1 <<< n_bits_in_accumulator.val) - 1))
            ||| ((bytes &&&
                    ((1 <<< (n_bits_per_coefficient.val
                              - n_bits_in_accumulator.val)) - 1))
                  <<< n_bits_in_accumulator.val) ⦄ := by
  rw [poly_element_decode_and_decompress_loop0_loop0.fold]
  have h_pos : n_bits_per_coefficient > 0#u32 := by scalar_tac
  rw [if_pos h_pos]
  have h_body_src : n_bits_in_accumulator.val = 0 →
                    cb_src_read.val + 4 ≤ pb_src.length := fun _ => h_room
  have h_remaining_0 : (0 : Nat) < n_bits_per_coefficient.val := by omega
  have h_coeff_zero_init : ∀ k, (0 : Nat) ≤ k → ¬ (0 : Nat).testBit k := by
    intros k _; simp
  step with poly_element_decode_and_decompress_loop0_loop0_body.spec
    pb_src n_bits_per_coefficient cb_src_read accumulator
    n_bits_in_accumulator 0#u32 0#u32 h_d h_remaining_0 h_acc h_body_src h_cb
    h_coeff_zero_init
  -- Case split: n_bia = 0 (one body call) vs 0 < n_bia < d (two body calls).
  by_cases h_nbia_zero : n_bits_in_accumulator.val = 0
  · -- Case B: n_bia = 0.  δ = d, refill in iter 1, loop terminates.
    -- δ_value
    have h_delta : min (n_bits_per_coefficient.val - 0)
                    (if n_bits_in_accumulator.val = 0 then 32
                     else n_bits_in_accumulator.val)
                = n_bits_per_coefficient.val := by
      rw [if_pos h_nbia_zero]; omega
    rw [poly_element_decode_and_decompress_loop0_loop0.fold]
    have h_nbic1_eq : n_bits_in_coefficient1.val = n_bits_per_coefficient.val := by
      rw [show n_bits_in_coefficient1.val =
              0 + min (n_bits_per_coefficient.val - 0)
                    (if n_bits_in_accumulator.val = 0 then 32
                     else n_bits_in_accumulator.val) from cb_src_read1_post1, h_delta]
      omega
    have h_term : ¬ (n_bits_per_coefficient > n_bits_in_coefficient1) := by scalar_tac
    rw [if_neg h_term]
    simp only [Aeneas.Std.WP.spec_ok]
    -- All bounds equalities at byte form.
    have h_cb1_val : cb_src_read1.val = cb_src_read.val + 4 := by
      have := cb_src_read1_post9; rw [if_pos h_nbia_zero] at this; omega
    have h_load_eq := loadLEWordBytes_eq_proofForm pb_src cb_src_read.val h_room
    refine ⟨h_nbic1_eq, ?_, ?_, ?_, ?_⟩
    · -- cb1.val = cb.val + 4
      exact h_cb1_val
    · -- acc1.val = bytes >>> (d - n_bia)
      have h_acc2 := cb_src_read1_post8
      rw [dif_pos h_nbia_zero, h_delta] at h_acc2
      rw [← h_load_eq] at h_acc2
      have h_dsub : n_bits_per_coefficient.val - n_bits_in_accumulator.val
                  = n_bits_per_coefficient.val := by omega
      rw [h_dsub]
      exact h_acc2
    · -- n_bia1.val = n_bia.val + 32 - d
      have h_pump := cb_src_read1_post10
      omega
    · -- coefficient.val = (acc & ((1<<<n_bia)-1)) | ((bytes & ((1<<<(d-n_bia))-1)) <<< n_bia)
      rw [h_nbia_zero, Nat.sub_zero]
      show coefficient1.val = (accumulator.val &&& ((1 <<< 0) - 1))
        ||| ((loadLEWordBytes pb_src cb_src_read.val
                  &&& ((1 <<< n_bits_per_coefficient.val) - 1)) <<< 0)
      rw [h_load_eq]
      apply Nat.eq_of_testBit_eq
      intro j
      rw [show (1 <<< 0 : ℕ) - 1 = 0 by norm_num, Nat.and_zero, Nat.zero_or,
          Nat.shiftLeft_zero, Nat.testBit_and,
          show (1 <<< n_bits_per_coefficient.val - 1 : ℕ) =
                (2 ^ n_bits_per_coefficient.val - 1) from by
                rw [Nat.shiftLeft_eq, Nat.one_mul],
          Nat.testBit_two_pow_sub_one]
      by_cases h_j : j < n_bits_per_coefficient.val
      · simp [h_j]
        have h_hi : j < n_bits_in_coefficient1.val := by rw [h_nbic1_eq]; exact h_j
        have h_new := cb_src_read1_post6 j (Nat.zero_le _) h_hi
        rw [dif_pos h_nbia_zero] at h_new
        simp only [Nat.sub_zero] at h_new
        exact h_new
      · simp [h_j]
        have h_j' : n_bits_per_coefficient.val ≤ j := Nat.le_of_not_lt h_j
        have h_zero := cb_src_read1_post7 j (by rw [h_nbic1_eq]; exact h_j')
        exact Bool.eq_false_iff.mpr h_zero
  · -- Case C: 0 < n_bia < d.  δ_iter1 = n_bia (no refill), loop continues; iter 2 refills.
    have h_nbia_pos : 0 < n_bits_in_accumulator.val := Nat.pos_of_ne_zero h_nbia_zero
    -- δ_iter1 = n_bia.
    have h_delta1 : min (n_bits_per_coefficient.val - 0)
                    (if n_bits_in_accumulator.val = 0 then 32
                     else n_bits_in_accumulator.val)
                 = n_bits_in_accumulator.val := by
      rw [if_neg h_nbia_zero]; omega
    -- Capture iter-1 facts as Prop hypotheses with fresh names that survive
    -- the shadowing by iter 2's step.
    have h_iter1_p1 := cb_src_read1_post1
    have h_iter1_p2 := cb_src_read1_post2
    have h_iter1_p3 := cb_src_read1_post3
    have h_iter1_p4 := cb_src_read1_post4
    have h_iter1_p5 := cb_src_read1_post5
    have h_iter1_p6 := cb_src_read1_post6
    have h_iter1_p7 := cb_src_read1_post7
    have h_iter1_p8 := cb_src_read1_post8
    have h_iter1_p9 := cb_src_read1_post9
    have h_iter1_p10 := cb_src_read1_post10
    have h_nbic1_eq : n_bits_in_coefficient1.val = n_bits_in_accumulator.val := by
      rw [show n_bits_in_coefficient1.val =
              0 + min (n_bits_per_coefficient.val - 0)
                    (if n_bits_in_accumulator.val = 0 then 32
                     else n_bits_in_accumulator.val) from h_iter1_p1, h_delta1]
      omega
    have h_cb1_val : cb_src_read1.val = cb_src_read.val := by
      have := h_iter1_p9; rw [if_neg h_nbia_zero] at this; omega
    have h_acc2_val : accumulator2.val = accumulator.val >>> n_bits_in_accumulator.val := by
      have h_acc2 := h_iter1_p8
      rw [dif_neg h_nbia_zero, h_delta1] at h_acc2
      exact h_acc2
    have h_nbia2_val : n_bits_in_accumulator2.val = 0 := by
      have h_pump := h_iter1_p10
      omega
    have h_coeff_i1_low : ∀ j, j < n_bits_in_accumulator.val →
        coefficient1.val.testBit j = accumulator.val.testBit j := by
      intro j hj
      have h_hi : j < n_bits_in_coefficient1.val := by rw [h_nbic1_eq]; exact hj
      have h_new := h_iter1_p6 j (Nat.zero_le _) h_hi
      rw [dif_neg h_nbia_zero] at h_new
      simpa using h_new
    -- Continue loop: iter 2.
    rw [poly_element_decode_and_decompress_loop0_loop0.fold]
    have h_more2_val : n_bits_in_coefficient1.val < n_bits_per_coefficient.val := by
      rw [h_nbic1_eq]; exact h_refill
    have h_more2 : n_bits_per_coefficient > n_bits_in_coefficient1 := by
      cases n_bits_per_coefficient; cases n_bits_in_coefficient1
      exact h_more2_val
    rw [if_pos h_more2]
    have h_remaining_2 : n_bits_in_coefficient1.val < n_bits_per_coefficient.val := by
      rw [h_nbic1_eq]; exact h_refill
    have h_acc_2 : n_bits_in_accumulator2.val ≤ 32 := by rw [h_nbia2_val]; omega
    have h_body_src_2 : n_bits_in_accumulator2.val = 0 →
                        cb_src_read1.val + 4 ≤ pb_src.length := by
      intro _; rw [h_cb1_val]; exact h_room
    -- For the bit-equality goal after iter 2, capture iter-1 var values via h_*.
    -- These survive iter 2's shadowing because they reference the iter-1 fvars
    -- which become inaccessible-but-still-bound after the shadow.
    -- Also stash a loadLEWordBytes equation for iter 1's cb (which becomes
    -- daggered after iter 2's step).
    have h_load_eq_i1 := loadLEWordBytes_eq_proofForm pb_src cb_src_read1.val
      (by rw [h_cb1_val]; exact h_room)
    step with poly_element_decode_and_decompress_loop0_loop0_body.spec
      pb_src n_bits_per_coefficient cb_src_read1 accumulator2
      n_bits_in_accumulator2 coefficient1 n_bits_in_coefficient1
      h_d h_remaining_2 h_acc_2 h_body_src_2 h_iter1_p4 h_iter1_p7
    -- Use iter 2's posts directly with iter-1 facts captured above.
    -- Compute n_bic_final = d via post1 + h_nbic1_eq + h_nbia2_val.
    have h_nbic2_eq : n_bits_in_coefficient1.val = n_bits_per_coefficient.val := by
      have h := cb_src_read1_post1
      rw [if_pos h_nbia2_val] at h
      -- h : n_bits_in_coefficient1.val = nbic_iter1.val + min(d - nbic_iter1.val) 32
      -- nbic_iter1.val = n_bia (h_nbic1_eq), and d - n_bia ≤ 32 since d ≤ 12.
      have hd1 := h_d.1; have hd2 := h_d.2
      omega
    -- Terminate loop after iter 2.
    rw [poly_element_decode_and_decompress_loop0_loop0.fold]
    have h_term : ¬ (n_bits_per_coefficient > n_bits_in_coefficient1) := by
      cases n_bits_per_coefficient; cases n_bits_in_coefficient1
      intro hh; exact absurd hh (by simp [h_nbic2_eq])
    rw [if_neg h_term]
    simp only [Aeneas.Std.WP.spec_ok]
    have h_load_eq := loadLEWordBytes_eq_proofForm pb_src cb_src_read.val h_room
    have h_cb2_val : cb_src_read1.val = cb_src_read.val + 4 := by
      have := cb_src_read1_post9
      rw [if_pos h_nbia2_val, h_cb1_val] at this
      exact this
    refine ⟨h_nbic2_eq, h_cb2_val, ?_, ?_, ?_⟩
    · -- accumulator_final.val = bytes >>> (d - n_bia)
      have h_acc2 := cb_src_read1_post8
      rw [dif_pos h_nbia2_val] at h_acc2
      -- h_acc2 : acc_final = (pb_src.val[cb_iter1✝] + ...) >>> min(d - nbic_iter1✝) (...)
      rw [h_acc2, ← h_load_eq_i1, h_cb1_val]
      fcongr 1
      -- min(d - n_bia_iter1✝) ... = d - n_bia
      rw [if_pos h_nbia2_val]
      have hd1 := h_d.1; have hd2 := h_d.2
      -- nbic_iter1✝ = n_bia via h_nbic1_eq
      omega
    · -- n_bits_in_accumulator_final.val = n_bia + 32 - d
      have h_pump := cb_src_read1_post10
      omega
    · -- coefficient_final = (acc & ((1<<<n_bia)-1)) | ((bytes & ((1<<<(d-n_bia))-1)) <<< n_bia)
      rw [h_load_eq]
      apply Nat.eq_of_testBit_eq
      intro j
      rw [Nat.testBit_or, Nat.testBit_and,
          Nat.testBit_shiftLeft, Nat.testBit_and,
          show (1 <<< n_bits_in_accumulator.val - 1 : ℕ) =
                (2 ^ n_bits_in_accumulator.val - 1) from by
                rw [Nat.shiftLeft_eq, Nat.one_mul],
          show (1 <<< (n_bits_per_coefficient.val - n_bits_in_accumulator.val) - 1 : ℕ) =
                (2 ^ (n_bits_per_coefficient.val - n_bits_in_accumulator.val) - 1) from by
                rw [Nat.shiftLeft_eq, Nat.one_mul],
          Nat.testBit_two_pow_sub_one,
          Nat.testBit_two_pow_sub_one]
      by_cases h_j1 : j < n_bits_in_accumulator.val
      · -- j < n_bia: LHS via iter-2 prefix-unchanged + h_coeff_i1_low.
        have h_hi_i1 : j < n_bits_in_accumulator.val := h_j1
        have h_pref := cb_src_read1_post5 j (by rw [h_nbic1_eq]; exact h_hi_i1)
        rw [h_pref, h_coeff_i1_low j h_j1]
        have h_ge : ¬ n_bits_in_accumulator.val ≤ j := by omega
        rw [show decide (j < n_bits_in_accumulator.val) = true from by
              rw [decide_eq_true_eq]; exact h_j1,
            show decide (n_bits_in_accumulator.val ≤ j) = false from by
              rw [decide_eq_false_iff_not]; exact h_ge]
        simp
      · by_cases h_j2 : j < n_bits_per_coefficient.val
        · -- n_bia ≤ j < d: LHS via iter-2 post6.
          push Not at h_j1
          have h_lo2 : n_bits_in_accumulator.val ≤ j := h_j1
          have h_hi2 : j < n_bits_in_coefficient1.val := by
            have : n_bits_in_coefficient1.val = n_bits_per_coefficient.val := h_nbic2_eq
            omega
          have h_new := cb_src_read1_post6 j (by rw [h_nbic1_eq]; exact h_lo2) h_hi2
          rw [dif_pos h_nbia2_val] at h_new
          -- Fold byte-sum to loadLEWordBytes, swap cb_src_read1✝ → cb_src_read, re-expand.
          rw [← h_load_eq_i1, h_cb1_val, h_load_eq, h_nbic1_eq] at h_new
          rw [h_new]
          have h_jnb_lt : j - n_bits_in_accumulator.val
                         < n_bits_per_coefficient.val - n_bits_in_accumulator.val := by omega
          rw [show decide (j < n_bits_in_accumulator.val) = false from by
                rw [decide_eq_false_iff_not]; omega,
              show decide (n_bits_in_accumulator.val ≤ j) = true from by
                rw [decide_eq_true_eq]; exact h_j1,
              show decide (j - n_bits_in_accumulator.val <
                            n_bits_per_coefficient.val - n_bits_in_accumulator.val) = true from by
                rw [decide_eq_true_eq]; exact h_jnb_lt]
          simp
        · -- j ≥ d: LHS = 0 (high bits).
          push Not at h_j1 h_j2
          have h_zero := cb_src_read1_post7 j (by
            have : n_bits_in_coefficient1.val = n_bits_per_coefficient.val := h_nbic2_eq
            omega)
          rw [Bool.eq_false_iff.mpr h_zero]
          have h_jnb_ge_dn : ¬ (j - n_bits_in_accumulator.val
                              < n_bits_per_coefficient.val - n_bits_in_accumulator.val) := by omega
          have h_j1' : ¬ j < n_bits_in_accumulator.val := by omega
          rw [show decide (j < n_bits_in_accumulator.val) = false from by
                rw [decide_eq_false_iff_not]; exact h_j1',
              show decide (j - n_bits_in_accumulator.val <
                            n_bits_per_coefficient.val - n_bits_in_accumulator.val) = false from by
                rw [decide_eq_false_iff_not]; exact h_jnb_ge_dn]
          simp


end Symcrust.Properties.MLKEM
