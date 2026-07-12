/-
  # Encoding/DecompressOuter.lean — Outer loop + top spec for decode-and-decompress.

  Split from `Decompress.lean`.  Inner loop specs are in `DecompressInner.lean`;
  vector decompress is in `Decompress.lean`.
-/
import Symcrust.Properties.MLKEM.Encoding.DecompressInner

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust

open symcrust.common
namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

/-! ## Per-coefficient outer loop

`poly_element_decode_and_decompress_loop0` iterates over the
destination IterMut. NONE arm: drain massert (cb_src_read at end of
buffer); SOME arm: assemble bits via `_loop0`, decompress, write. -/

#decompose mlkem.ntt.poly_element_decode_and_decompress_loop0
    poly_element_decode_and_decompress_loop0.fold
  letRange 1 1 => poly_element_decode_and_decompress_loop0_match

#decompose poly_element_decode_and_decompress_loop0_match
    poly_element_decode_and_decompress_loop0_match.fold
  branch 1 (letRange 0 2) => poly_element_decode_and_decompress_loop0_some_body

/-! The `#decompose` declarations and `_loop0_match.fold` equation above
are consumed inside `poly_element_decode_and_decompress_loop0.spec`'s proof
via the canonical Variant B pattern (see `proof-patterns` skill): the
loop dispatch and per-iteration `_some_body` step are inlined there, so
no standalone `@[step]` spec is needed for `_loop0_match`. -/

/-- **Some-body spec** for the outer loop's `some` arm.

Effect of one body iteration after the option scrutinee fires:
* call `_loop0_loop0` to assemble `d` bits into `coefficient`;
* `n_bits_in_coefficient1 = n_bits_per_coefficient` (full coefficient);
* `cb_src_read1.val ≤ pb_src.length`.

The result is then `fastDecompress d coefficient` (at d<12) or
`coefficient` itself (at d=12, with a range check).

  **Informal proof.**
  `unfold poly_element_decode_and_decompress_loop0_some_body; step*`
  (2 binds before the inner-loop call).  Then `step with
  mlkem.ntt.poly_element_decode_and_decompress_loop0_loop0.spec`
  with `n_bits_in_coefficient := 0`, `h_init : 0 ≤ d`, `h_d`, `h_acc`.

  From the inner-loop post:
  - `n_bits_in_coefficient1 = d`; `cb_src_read1 ≤ pb_src.length`;
    `n_bits_in_accumulator1 ≤ 32`.
  - `_coefficient.val < 2^d`: exactly `d` bits were assembled into
    bits `[0, d)` of `_coefficient`; bits above `d` were never
    written; `bv_tac 32` or `scalar_tac` using the coefficient-prefix
    invariant.
  - Bit-pump conservation:
    `cb_src_read1 * 8 - n_bits_in_accumulator1 =
     cb_src_read * 8 - n_bits_in_accumulator + d`; directly from
    the inner-loop's conservation property with
    `n_bits_in_coefficient_initial = 0`; `scalar_tac`. -/
@[step]
theorem poly_element_decode_and_decompress_loop0_some_body.spec
    (pb_src : Slice U8) (n_bits_per_coefficient : U32)
    (cb_src_read : Usize) (accumulator n_bits_in_accumulator : U32)
    (h_d : 1 ≤ n_bits_per_coefficient.val ∧ n_bits_per_coefficient.val ≤ 12)
    (h_acc : n_bits_in_accumulator.val ≤ 32)
    (h_src : n_bits_in_accumulator.val ≥ n_bits_per_coefficient.val ∨
             cb_src_read.val + 4 ≤ pb_src.length)
    (h_cb : cb_src_read.val ≤ pb_src.length) :
    poly_element_decode_and_decompress_loop0_some_body
        pb_src n_bits_per_coefficient cb_src_read accumulator n_bits_in_accumulator
      ⦃ cb_src_read1 _accumulator1 n_bits_in_accumulator1 _coefficient =>
          cb_src_read1.val ≤ pb_src.length ∧
          n_bits_in_accumulator1.val ≤ 32 ∧
          /- Assembled coefficient fits in `d` bits. -/
          _coefficient.val < 2^n_bits_per_coefficient.val ∧
          /- Bit-pump (additive Nat-safe form): one full coefficient consumed. -/
          cb_src_read1.val * 8 + n_bits_in_accumulator.val =
            cb_src_read.val * 8 + n_bits_in_accumulator1.val + n_bits_per_coefficient.val ⦄ := by
  unfold poly_element_decode_and_decompress_loop0_some_body
  have h_init : (0 : Nat) ≤ n_bits_per_coefficient.val := by omega
  have h_src_loop : n_bits_in_accumulator.val ≥
                     n_bits_per_coefficient.val - 0 ∨
                    cb_src_read.val + 4 ≤ pb_src.length := by
    rcases h_src with h | h
    · left; simpa using h
    · right; exact h
  have h_coeff_zero : ∀ k, (0 : Nat) ≤ k → ¬ (0 : Nat).testBit k := by
    intros k _; simp
  step with mlkem.ntt.poly_element_decode_and_decompress_loop0_loop0.spec
    pb_src n_bits_per_coefficient cb_src_read accumulator n_bits_in_accumulator
    0#u32 0#u32 h_d h_init h_acc h_src_loop h_cb h_coeff_zero
  -- After inner loop, posts: cb_src_read1_post1..post6
  step*
  refine ⟨cb_src_read1_post2, cb_src_read1_post3, ?_, ?_⟩
  · -- coefficient.val < 2^n_pc from high-bits-zero
    apply Nat.lt_pow_two_of_testBit
    intros k hk
    have h_zero : ¬ coefficient.val.testBit k := cb_src_read1_post5 k hk
    exact Bool.eq_false_iff.mpr h_zero
  · -- bit-pump: from cb_src_read1_post6 + post1 (n_bic = n_pc)
    have := cb_src_read1_post6
    have h_bic_eq : n_bits_in_coefficient.val = n_bits_per_coefficient.val :=
      cb_src_read1_post1
    omega

set_option maxRecDepth 4096 in
set_option maxHeartbeats 800000 in
/-- **Some-body strengthened spec — bit-level dispatch**.

Companion to `_some_body.spec` exposing the dispatch witness expected
by `matchesRuntime_step_decode` (Bridges/EncodingStream.lean L2599).
The post is a disjunction over NO-REFILL (`d ≤ n_bia`) and REFILL
(`n_bia < d`) arms, mirroring the umbrella signature verbatim.

The source-room hypothesis is **disjunctive**: either NO-REFILL applies
(`d ≤ n_bia.val`, so no load needed and `h_room` is irrelevant) or
strict `cb_src_read.val + 4 ≤ pb_src.length` holds (needed for the
REFILL load).  This shape is essential because in the d=12 last
iteration of the outer loop, NO-REFILL fires with
`cb_src_read = pb_src.length` (algebra: `pi=255`, `acci=12 ≥ d=12`,
`si = 384 = pb_src.length`), so strict `h_room` cannot hold. -/
theorem poly_element_decode_and_decompress_loop0_some_body.spec_bits
    (pb_src : Slice U8) (n_bits_per_coefficient : U32)
    (cb_src_read : Usize) (accumulator n_bits_in_accumulator : U32)
    (h_d : 1 ≤ n_bits_per_coefficient.val ∧ n_bits_per_coefficient.val ≤ 12)
    (h_acc : n_bits_in_accumulator.val ≤ 32)
    (h_src : n_bits_per_coefficient.val ≤ n_bits_in_accumulator.val ∨
             cb_src_read.val + 4 ≤ pb_src.length)
    (h_cb : cb_src_read.val ≤ pb_src.length) :
    poly_element_decode_and_decompress_loop0_some_body
        pb_src n_bits_per_coefficient cb_src_read accumulator n_bits_in_accumulator
      ⦃ cb_src_read1 _accumulator1 n_bits_in_accumulator1 _coefficient =>
          cb_src_read1.val ≤ pb_src.length ∧
          n_bits_in_accumulator1.val ≤ 32 ∧
          _coefficient.val < 2 ^ n_bits_per_coefficient.val ∧
          cb_src_read1.val * 8 + n_bits_in_accumulator.val =
            cb_src_read.val * 8 + n_bits_in_accumulator1.val
              + n_bits_per_coefficient.val ∧
          (/- NO-REFILL: d ≤ n_bia. -/
           (n_bits_per_coefficient.val ≤ n_bits_in_accumulator.val ∧
            cb_src_read1 = cb_src_read ∧
            _accumulator1.val = accumulator.val >>> n_bits_per_coefficient.val ∧
            n_bits_in_accumulator1.val =
                n_bits_in_accumulator.val - n_bits_per_coefficient.val ∧
            _coefficient.val =
                accumulator.val &&& ((1 <<< n_bits_per_coefficient.val) - 1))
         ∨ (/- REFILL: n_bia < d. -/
            n_bits_in_accumulator.val < n_bits_per_coefficient.val ∧
            cb_src_read1.val = cb_src_read.val + 4 ∧
            _accumulator1.val =
                loadLEWordBytes pb_src cb_src_read.val
                  >>> (n_bits_per_coefficient.val - n_bits_in_accumulator.val) ∧
            n_bits_in_accumulator1.val =
                n_bits_in_accumulator.val + 32 - n_bits_per_coefficient.val ∧
            _coefficient.val =
                (accumulator.val
                    &&& ((1 <<< n_bits_in_accumulator.val) - 1))
                  ||| ((loadLEWordBytes pb_src cb_src_read.val
                          &&& ((1 <<< (n_bits_per_coefficient.val
                                        - n_bits_in_accumulator.val)) - 1))
                       <<< n_bits_in_accumulator.val))) ⦄ := by
  unfold poly_element_decode_and_decompress_loop0_some_body
  by_cases h_no_refill : n_bits_per_coefficient.val ≤ n_bits_in_accumulator.val
  · -- NO-REFILL arm: h_room not needed.
    step with
      mlkem.ntt.poly_element_decode_and_decompress_loop0_loop0.spec_at_zero_no_refill
      pb_src n_bits_per_coefficient cb_src_read accumulator n_bits_in_accumulator
      h_d h_acc h_cb h_no_refill
    -- Posts: cb_src_read1_post1..post5.
    step*
    have h_cb1 : cb_src_read1.val ≤ pb_src.length := by
      rw [cb_src_read1_post2]; exact h_cb
    have h_nbia1_le : n_bits_in_accumulator1.val ≤ 32 := by
      rw [cb_src_read1_post4]; omega
    have h_coeff_lt : coefficient.val < 2 ^ n_bits_per_coefficient.val := by
      apply Nat.lt_pow_two_of_testBit
      intro k hk
      rw [cb_src_read1_post5, Nat.testBit_and,
          show (1 <<< n_bits_per_coefficient.val - 1 : Nat)
            = 2 ^ n_bits_per_coefficient.val - 1 from by
              rw [Nat.shiftLeft_eq, Nat.one_mul],
          Nat.testBit_two_pow_sub_one,
          show decide (k < n_bits_per_coefficient.val) = false from by
            rw [decide_eq_false_iff_not]; omega]
      simp
    have h_pump : cb_src_read1.val * 8 + n_bits_in_accumulator.val =
        cb_src_read.val * 8 + n_bits_in_accumulator1.val + n_bits_per_coefficient.val := by
      rw [cb_src_read1_post2, cb_src_read1_post4]; omega
    exact ⟨h_cb1, h_nbia1_le, h_coeff_lt, h_pump,
           Or.inl ⟨h_no_refill, cb_src_read1_post2, cb_src_read1_post3,
                   cb_src_read1_post4, cb_src_read1_post5⟩⟩
  · -- REFILL arm: derive h_room from disjunctive h_src.
    push Not at h_no_refill
    have h_room : cb_src_read.val + 4 ≤ pb_src.length := by
      rcases h_src with h_disj | h_room
      · exact absurd h_disj (by omega)
      · exact h_room
    step with
      mlkem.ntt.poly_element_decode_and_decompress_loop0_loop0.spec_at_zero_refill
      pb_src n_bits_per_coefficient cb_src_read accumulator n_bits_in_accumulator
      h_d h_acc h_room h_cb h_no_refill
    -- Posts: cb_src_read1_post1..post5 (from spec_at_zero_refill).
    step*
    have h_cb1 : cb_src_read1.val ≤ pb_src.length := by
      rw [cb_src_read1_post2]; simp [Slice.length] at h_room ⊢; omega
    have h_nbia1_le : n_bits_in_accumulator1.val ≤ 32 := by
      rw [cb_src_read1_post4]; omega
    have h_coeff_lt : coefficient.val < 2 ^ n_bits_per_coefficient.val := by
      apply Nat.lt_pow_two_of_testBit
      intro k hk
      rw [cb_src_read1_post5, Nat.testBit_or, Nat.testBit_and,
          show (1 <<< n_bits_in_accumulator.val - 1 : Nat)
            = 2 ^ n_bits_in_accumulator.val - 1 from by
              rw [Nat.shiftLeft_eq, Nat.one_mul],
          Nat.testBit_two_pow_sub_one,
          Nat.testBit_shiftLeft, Nat.testBit_and,
          show (1 <<<
                  (n_bits_per_coefficient.val - n_bits_in_accumulator.val) - 1 : Nat)
            = 2 ^ (n_bits_per_coefficient.val - n_bits_in_accumulator.val) - 1 from by
              rw [Nat.shiftLeft_eq, Nat.one_mul],
          Nat.testBit_two_pow_sub_one]
      by_cases h_lo : k < n_bits_in_accumulator.val
      · rw [show decide (k < n_bits_in_accumulator.val) = true from by
              rw [decide_eq_true_eq]; exact h_lo,
            show decide (n_bits_in_accumulator.val ≤ k) = false from by
              rw [decide_eq_false_iff_not]; omega]
        simp
        exfalso; omega
      · rw [show decide (k < n_bits_in_accumulator.val) = false from by
              rw [decide_eq_false_iff_not]; exact h_lo,
            show decide (n_bits_in_accumulator.val ≤ k) = true from by
              rw [decide_eq_true_eq]; omega]
        simp
        rintro _
        omega
    have h_pump : cb_src_read1.val * 8 + n_bits_in_accumulator.val =
        cb_src_read.val * 8 + n_bits_in_accumulator1.val + n_bits_per_coefficient.val := by
      rw [cb_src_read1_post2, cb_src_read1_post4]
      simp [Slice.length] at h_room
      omega
    exact ⟨h_cb1, h_nbia1_le, h_coeff_lt, h_pump,
           Or.inr ⟨h_no_refill, cb_src_read1_post2, cb_src_read1_post3,
                   cb_src_read1_post4, cb_src_read1_post5⟩⟩

/-- **Loop spec** for `poly_element_decode_and_decompress_loop0` — streaming FC
in Stream form.

The runtime quintuple `(pb_src, cb_src_read, accumulator,
n_bits_in_accumulator, IterMut over pe_dst)` enters the loop matching
an abstract Stream state `s_in : DecodeDecompressState` (via
`matchesRuntime`).  The loop processes each remaining slot by applying
`DecodeDecompressState.body d` once per iteration: refill if needed,
extract `d` LSBs of `acc`, write `coeffFromDecode d v` to `dst[pi]`,
advance the read cursor.

On exit, `s_out = recBody d s_in (iter.slice.length - iter.i)`, and
the runtime matches `s_out` (via the IterMut's `back` closure for
the polynomial slots).

  **Informal proof.** Canonical recursive loop (`proof-patterns`
  Variant B with IterMut).  No separate `_loop0_match.spec`.

  - **Mandatory first step**: `rw
    [poly_element_decode_and_decompress_loop0.fold]`; do NOT `unfold`.
  - `step` to consume `next iter` (yields `o`, `iter1`, `back1`).
  - `cases o`:
    - **`none` arm** (iter exhausted): inline the `massert
      (cb_src_read = pb_src.length)`; from `h_match` we have
      `s_in.si = cb_src_read.val` and the loop has already drained
      `iter.i` coefficients (`iter.i = s_in.pi`), so the residual
      `n_bits_in_accumulator = 0`.  Witness `coeffs_remaining := []`,
      `s_out := s_in`, `recBody d s_in 0 = s_in`; the IterMut `back1`
      is identity; `agrind`.
    - **`some _` arm**: `step with
      poly_element_decode_and_decompress_loop0_some_body.spec`
      (per-coefficient bit-pump leaf; supplies `h_d`, `h_acc`).
      The leaf post gives the assembled coefficient
      `_coefficient.val < 2^d` and bit-pump conservation.  Combine
      with a bridge lemma `step_matches_body_decode`
      (`Bridges/EncodingStream.lean:2292`) to lift the register-level
      effect to one `DecodeDecompressState.body d s_in` step.  `step*` then drives
      the IterMut writeback (which corresponds to setting
      `s_in.dst[s_in.pi]` to `coeffFromDecode d v`) and the recursive
      call, which closes via the IH at the body-bridged Stream state.
  - `InvalidBlob`: propagated from `_some_body.spec`; `agrind`.
  - `termination_by iter.slice.length - iter.i`;
    `decreasing_by scalar_decr_tac`.

  **Bridge lemma**: `step_matches_body_decode`
  (`Bridges/EncodingStream.lean`) — relates the register-level
  post of `_some_body.spec` + the IterMut writeback to one
  `DecodeDecompressState.body d s` step.

  **IterMut witness convention**: the
  `pe_dst_ghost : PolyElement` argument is a **caller-supplied
  parameter**, not closed existentially in the post.  This is the
  canonical IterMut function-trace pattern: the caller (here, the
  outer wrapper `poly_element_decode_and_decompress.spec`) holds the
  original `pe_dst` and threads it as the witness across the
  `_loop0` call.  Do not "pull the witness into the postcondition"
  via `∃ pe_dst_ghost, ...` — that would break the chain because the
  post quantifies over the back-fn output, not over the input view. -/
@[step]
theorem mlkem.ntt.poly_element_decode_and_decompress_loop0.spec
    (iter : core.slice.iter.IterMut U16)
    (back : core.slice.iter.IterMut U16 → core.slice.iter.IterMut U16)
    (pb_src : Slice U8) (n_bits_per_coefficient : U32)
    (cb_src_read : Usize) (accumulator n_bits_in_accumulator : U32)
    (s_in : Bridges.DecodeDecompressState)
    (pe_dst_ghost : PolyElement)
    (h_d : 1 ≤ n_bits_per_coefficient.val ∧ n_bits_per_coefficient.val ≤ 12)
    (h_match :
      Bridges.DecodeDecompressState.matchesRuntime n_bits_per_coefficient.val s_in pe_dst_ghost
        accumulator n_bits_in_accumulator pb_src cb_src_read)
    (h_iter_i : iter.i = s_in.pi)
    /- Canonical IterMut framing predicates (mirror VectorSetZero.lean
       L75-107 and Ntt.lean L734-870).  `orig_slice` is the slice
       BEFORE the back-write chain; the loop preserves
       `length = orig_slice.length` and the back-fn only writes at
       positions `[0, iter.i)` (already processed) while passing
       `[iter.i, orig_slice.length)` through unchanged. -/
    (orig_slice : Slice U16)
    (h_slice : iter.slice = orig_slice)
    (h_orig_len : orig_slice.length = 256)
    /- Loop invariant: source-byte cursor and 4-alignment.  These
       jointly enable `h_room` derivation at REFILL time (algebra:
       `8*si = pi*d + acci`, `4 ∣ si`, `acci < d`, `pi < 256`,
       `32*d ≤ pb_src.length` ⟹ `si + 4 ≤ pb_src.length`).
       Listed early so `hback_writes`'s `[j]` index obligation
       can derive `iter.i ≤ 256` from `length_inv`. -/
    (h_len_inv : Bridges.DecodeDecompressState.length_inv
                    n_bits_per_coefficient.val s_in iter.i)
    (h_si_aligned : 4 ∣ cb_src_read.val)
    (h_src_len : 32 * n_bits_per_coefficient.val ≤ pb_src.length)
    (hback_len : ∀ (im : core.slice.iter.IterMut U16),
        im.slice.length = orig_slice.length →
        (back im).slice.length = orig_slice.length)
    (hback_writes : ∀ (im : core.slice.iter.IterMut U16)
        (him : im.slice.length = orig_slice.length)
        (j : ℕ) (_hj : j < iter.i),
          ((back im).slice.val[j]'(by
              have := hback_len im him
              have := h_len_inv.2.2.1
              scalar_tac)).val
            = s_in.dst.getD j 0)
    (hback_rest : ∀ (im : core.slice.iter.IterMut U16)
        (him : im.slice.length = orig_slice.length)
        (j : ℕ) (_hj_ge : iter.i ≤ j) (_hj_lt : j < orig_slice.length),
          (back im).slice.val[j]'(by
              have := hback_len im him; scalar_tac)
            = im.slice.val[j]'(by scalar_tac))
    /- `wfPoly`-preservation preconditions: the original (input) slice
       has all coefficients `< q`, and every slot already-written by the
       back-chain (positions `< s_in.pi`) is also `< q`.  These thread
       through to the new universal `wfPoly` post conjunct below, which
       holds on **both** `NoError` and `InvalidBlob` arms.  Required by
       the vector loop spec at `Decompress.lean:3155` to recover
       `wfPolyVec pv_dst'` regardless of failure. -/
    (h_orig_wf : ∀ (j : ℕ) (h_j : j < orig_slice.length),
                   (orig_slice.val[j]'h_j).val < q)
    (h_s_in_dst_wf : ∀ k, k < s_in.pi → s_in.dst.getD k 0 < q) :
    mlkem.ntt.poly_element_decode_and_decompress_loop0
        iter back pb_src n_bits_per_coefficient cb_src_read
        accumulator n_bits_in_accumulator
      ⦃ err iter' =>
          iter'.slice.length = orig_slice.length ∧
          (match err with
           | Error.NoError =>
               /- All remaining slots processed.  `s_out` results from
                  folding `body d` over the remaining iterations,
                  starting at `s_in`. -/
               ∃ (s_out : Bridges.DecodeDecompressState),
                 s_out = Bridges.DecodeDecompressState.recBody
                          n_bits_per_coefficient.val s_in
                          (orig_slice.length - iter.i) ∧
                 s_out.pi = 256 ∧
                 /- The IterMut's reattached slice carries `s_out.dst`. -/
                 (∀ (j : ℕ) (h_j : j < iter'.slice.length),
                     (iter'.slice.val[j]'h_j).val
                       = s_out.dst.getD j 0) ∧
                 /- Well-formedness on positions written by THIS call.
                    For `d<12` this is the trivial `2^d`-bit bound; for
                    `d=12` it encodes the Rust loop's InvalidBlob check.
                    Used by Bridge 1 to convert `streamDecodeDecompressPoly`
                    into the FIPS `decodeDecompressPoly` form. -/
                 (∀ (k : ℕ), s_in.pi ≤ k → k < 256 →
                     Bridges.fipsBitSum n_bits_per_coefficient.val s_in.src k
                       < MLKEM.m n_bits_per_coefficient.val)
           | Error.InvalidBlob => n_bits_per_coefficient.val = 12
           | _ => False) ∧
          /- Universal `wfPoly` preservation — holds on both `NoError`
             and `InvalidBlob` arms.  Derived from `h_orig_wf` +
             `h_s_in_dst_wf` plus `hback_writes`/`hback_rest`.  Used by
             `poly_element_decode_and_decompress.spec` to forward
             `wfPoly pe_dst'` on InvalidBlob to the vector loop. -/
          (∀ (j : ℕ) (h_j : j < iter'.slice.length),
              (iter'.slice.val[j]'h_j).val < q) ⦄ := by
  -- Outer IterMut loop over the 256 coefficients: each iteration decodes one
  -- coefficient (`_some_body.spec_bits`) and writes it back through the `back`
  -- closure, bridging Code state to `DecodeDecompressState.body` via
  -- `matchesRuntime_step_decode`.  Framing uses the canonical IterMut pattern
  -- (`orig_slice` / `hback_len` / `hback_writes` / `hback_rest`), as in
  -- `VectorSetZero.lean` and `Ntt.lean :: vector_ntt_loop.spec`.
  rw [poly_element_decode_and_decompress_loop0.fold]
  -- Substitute iter.i for s_in.pi everywhere via h_iter_i.symm.
  have hi_pe : iter.slice.length = orig_slice.length := by rw [h_slice]
  have h_pi_eq : s_in.pi = iter.i := h_iter_i.symm
  -- Algebra: length_inv gives `8*si = iter.i*d + acci`; matchesRuntime gives
  -- `si = cb_src_read.val` and `acci = n_bia.val`.
  have h_si_eq : s_in.si = cb_src_read.val := h_match.2.2.1
  have h_acci_eq : s_in.acci = n_bits_in_accumulator.val := h_match.2.2.2.2.1
  have h_acci_le31 : s_in.acci ≤ 31 := h_len_inv.2.2.2.2.2
  have h_8si_eq : 8 * s_in.si = iter.i * n_bits_per_coefficient.val + s_in.acci :=
    h_len_inv.2.2.2.2.1
  have h_iter_i_le256 : iter.i ≤ 256 := h_len_inv.2.2.1
  have h_iter_i_le : iter.i ≤ orig_slice.length := by rw [h_orig_len]; exact h_iter_i_le256
  by_cases hlt : iter.i < iter.slice.len
  · -- SOME branch — body iteration.
    have hLen_eq : (↑iter.slice.len : ℕ) = iter.slice.length := by
      simp [Slice.len, Slice.length]
    have hi_lt : iter.i < orig_slice.length := by rw [← hi_pe]; scalar_tac
    have h_pi_lt_256 : s_in.pi < 256 := by
      rw [h_pi_eq]; rw [← h_orig_len]; exact hi_lt
    -- Derive h_room for REFILL: cb_src_read.val + 4 ≤ pb_src.length.
    -- Algebra: 8*si = pi*d + acci; 4|si ⇒ 32|8*si; pi < 256, acci ≤ 31 ⇒
    -- 8*si < 256*d + 32 ≤ 32*d_max + ... actually we need disjunctive form:
    -- if acci ≥ d, NO-REFILL fires, no h_room needed. If acci < d,
    -- pi*d + acci < (pi+1)*d ≤ 256*d, so 8*si < 256*d = 8*pb_src.length, so si < pb_src.length.
    -- With 4|si: si ≤ pb_src.length - 4, i.e. si + 4 ≤ pb_src.length.
    have h_src_disj_32d :
        n_bits_per_coefficient.val ≤ n_bits_in_accumulator.val ∨
        cb_src_read.val + 4 ≤ 32 * n_bits_per_coefficient.val := by
      by_cases h_acci_ge_d : n_bits_per_coefficient.val ≤ n_bits_in_accumulator.val
      · exact Or.inl h_acci_ge_d
      · right
        push Not at h_acci_ge_d
        have h_acci_lt_d : s_in.acci < n_bits_per_coefficient.val := by
          rw [h_acci_eq]; exact h_acci_ge_d
        -- 8*si = pi*d + acci < (pi+1)*d ≤ 256*d
        have h_8si_lt : 8 * s_in.si < 256 * n_bits_per_coefficient.val := by
          have h1 : iter.i * n_bits_per_coefficient.val + s_in.acci <
                    (iter.i + 1) * n_bits_per_coefficient.val := by
            rw [Nat.add_mul, Nat.one_mul]; omega
          have h2 : (iter.i + 1) * n_bits_per_coefficient.val ≤
                    256 * n_bits_per_coefficient.val := by
            apply Nat.mul_le_mul_right
            have : iter.i < 256 := by rw [← h_orig_len]; exact hi_lt
            omega
          omega
        -- 4 ∣ si ⇒ si + 4 ≤ 32 * d (32*d is a multiple of 4).
        rcases h_si_aligned with ⟨q, hq⟩
        have h_si_q : s_in.si = 4 * q := by rw [h_si_eq]; exact hq
        have h_si_lt_32d : s_in.si < 32 * n_bits_per_coefficient.val := by omega
        rw [← h_si_eq, h_si_q]
        rw [h_si_q] at h_si_lt_32d
        have h_q_lt : q < 8 * n_bits_per_coefficient.val := by omega
        rw [show (32 : ℕ) * n_bits_per_coefficient.val = 4 * (8 * n_bits_per_coefficient.val)
            from by ring]
        omega
    -- Weaker `pb_src.length` form, derived from the `32*d` form via h_src_len.
    have h_src_disj :
        n_bits_per_coefficient.val ≤ n_bits_in_accumulator.val ∨
        cb_src_read.val + 4 ≤ pb_src.length := by
      rcases h_src_disj_32d with h | h
      · exact Or.inl h
      · right; omega
    have h_cb_le : cb_src_read.val ≤ pb_src.length := h_match.2.2.2.1
    have h_acc_le : n_bits_in_accumulator.val ≤ 32 := h_match.2.2.2.2.2.1
    -- Pull next_spec to expose (o, iter1, next_back) with iter1 = iter at index iter.i+1.
    let* ⟨ o, iter1, next_back, h_all ⟩ ←
      core.slice.iter.IteratorIterMut.next.spec
    obtain ⟨ho, hit2_slice, hit2_i, _, hsome_set⟩ := h_all
    rw [ho, poly_element_decode_and_decompress_loop0_match.fold]
    simp only []
    -- Now goal has `_some_body pb_src d cb_src_read acc nbia` as the next bind.
    step with poly_element_decode_and_decompress_loop0_some_body.spec_bits
              pb_src n_bits_per_coefficient cb_src_read accumulator n_bits_in_accumulator
              h_d h_acc_le h_src_disj h_cb_le
    -- Split on (d < 12) and (coefficient ≥ Q).
    split_ifs with h_dlt12 h_coeff_ge_q
    · -- BODY_DLT12: d < 12 path — fastDecompress.
      -- Extract d < 12 in Nat form.
      have h_dlt12_nat : n_bits_per_coefficient.val < 12 := by
        have h := h_dlt12; scalar_tac
      have h_d_pos : 1 ≤ n_bits_per_coefficient.val := h_d.1
      -- Bound coefficient: coefficient.val < 2^d ≤ 2^11 = 2048.
      have h_c_lt_2d : coefficient.val < 2 ^ n_bits_per_coefficient.val :=
        cb_src_read1_post3
      have h_c_lt_2048 : coefficient.val < 2048 := by
        have h_pow : (2 : ℕ) ^ n_bits_per_coefficient.val ≤ 2 ^ 11 :=
          Nat.pow_le_pow_right (by norm_num) (by omega)
        have h_eq : (2 : ℕ) ^ 11 = 2048 := by decide
        omega
      -- ntt.Q.val = 3329.
      have h_Q_val : mlkem.ntt.Q.val = 3329 := ntt_Q_val
      -- Step 1: coefficient1 ← coefficient * Q.  Bound: c * Q < 2^32.
      have h_mul_bound : coefficient.val * 3329 ≤ UScalar.max UScalarTy.U32 := by
        have hmax : UScalar.max UScalarTy.U32 = 4294967295 := by scalar_tac
        rw [hmax]; nlinarith
      step
      step
      step  -- coefficient2 = coefficient1 >>> i
      -- Bound coefficient2: coefficient2.val ≤ coefficient1.val < 2^d * Q ≤ 2048*3329.
      have h_c2_bound : coefficient2.val < UScalar.max UScalarTy.U32 := by
        have h := coefficient2_post1
        have h1 := coefficient1_post
        have hmax : UScalar.max UScalarTy.U32 = 4294967295 := by scalar_tac
        rw [hmax, h, h1]
        have : coefficient.val * mlkem.ntt.Q.val ≤ 2047 * 3329 := by
          rw [h_Q_val]; nlinarith
        have h_shr_le : (coefficient.val * mlkem.ntt.Q.val) >>> i.val
                          ≤ coefficient.val * mlkem.ntt.Q.val :=
          Nat.shiftRight_le _ _
        omega
      step  -- coefficient3 = coefficient2 + 1
      step  -- coefficient4 = coefficient3 >>> 1
      -- Bound coefficient4.val < 2*q for mod_reduce.
      have h_c4_lt_2q : coefficient4.val < 2 * 3329 := by
        have hp : (2 : ℕ) ^ n_bits_per_coefficient.val =
                    2 * 2 ^ (n_bits_per_coefficient.val - 1) := by
          have hh := Nat.sub_add_cancel h_d_pos
          conv_lhs => rw [← hh, pow_succ, mul_comm]
        have hpow_pos : 0 < 2 ^ (n_bits_per_coefficient.val - 1) := Nat.two_pow_pos _
        -- coefficient2.val < 2 * 3329
        have h_c2_bd : coefficient2.val < 2 * 3329 := by
          rw [coefficient2_post1, coefficient1_post, h_Q_val, i_post1,
              Nat.shiftRight_eq_div_pow, Nat.div_lt_iff_lt_mul hpow_pos]
          have h1 : coefficient.val * 3329 < 2 ^ n_bits_per_coefficient.val * 3329 :=
            (Nat.mul_lt_mul_right (by norm_num : 0 < 3329)).mpr h_c_lt_2d
          have h2 : 2 ^ n_bits_per_coefficient.val * 3329 =
                      2 * 3329 * 2 ^ (n_bits_per_coefficient.val - 1) := by
            rw [hp]; ring
          omega
        rw [coefficient4_post1, coefficient3_post, Nat.shiftRight_eq_div_pow]
        omega
      step with Symcrust.Properties.MLKEM.mlkem.ntt.mod_reduce.spec coefficient4 h_c4_lt_2q
        as ⟨ coefficient5, hc5_lt, hc5_zq ⟩
      -- massert (c5 < Q): from hc5_lt: c5.val < q = 3329 = Q.val.
      have hc5_lt_Q : coefficient5 < mlkem.ntt.Q := by
        have h_q3329 : (q : Nat) = 3329 := rfl
        have h_c5_val : coefficient5.val < 3329 := by rw [← h_q3329]; exact hc5_lt
        -- mlkem.ntt.Q is a U32 with .val = 3329.
        show coefficient5.bv < mlkem.ntt.Q.bv
        rw [BitVec.lt_def]
        rw [show coefficient5.bv.toNat = coefficient5.val from rfl]
        rw [show mlkem.ntt.Q.bv.toNat = mlkem.ntt.Q.val from rfl]
        rw [h_Q_val]; exact h_c5_val
      step  -- discharges massert
      -- cast U16: c5.val < 3329 ≤ 65535
      have h_c5_lt_u16 : coefficient5.val ≤ UScalar.max UScalarTy.U16 := by
        have h_q3329 : (q : Nat) = 3329 := rfl
        have h_c5_val : coefficient5.val < 3329 := by rw [← h_q3329]; exact hc5_lt
        have hmax : UScalar.max UScalarTy.U16 = 65535 := by scalar_tac
        omega
      let* ⟨ dst_coeff, dst_coeff_post ⟩ ←
        UScalar.cast_inBounds_spec UScalarTy.U16 coefficient5 h_c5_lt_u16
      -- The dst_coeff value equals fastDecompress d coefficient.val.
      -- Step A: coefficient4.val = fastDecompress d coefficient.val.
      have h_fast_id : ∀ (a k : Nat),
          ((a / 2 ^ k) + 1) / 2 = (a + 2 ^ k) / 2 ^ (k + 1) := by
        intro a k
        have hpos : (0 : Nat) < 2 ^ k := Nat.two_pow_pos _
        rw [pow_succ, ← Nat.div_div_eq_div_mul, Nat.add_div_right _ hpos]
      have h_c4_fast : coefficient4.val
                        = fastDecompress n_bits_per_coefficient.val coefficient.val := by
        rw [coefficient4_post1, coefficient3_post, coefficient2_post1,
            coefficient1_post, i_post1, h_Q_val]
        rw [Nat.shiftRight_eq_div_pow, Nat.shiftRight_eq_div_pow]
        unfold fastDecompress
        rw [show (q : Nat) = 3329 from rfl]
        have h_d_succ : n_bits_per_coefficient.val
                          = (n_bits_per_coefficient.val - 1) + 1 := by omega
        conv_rhs => rw [h_d_succ]
        exact h_fast_id _ _
      -- Step B: fastDecompress d c.val < q = 3329.
      have h_fast_lt_Q : fastDecompress n_bits_per_coefficient.val coefficient.val < q := by
        unfold fastDecompress
        apply Nat.div_lt_of_lt_mul
        have hy' : coefficient.val + 1 ≤ 2 ^ n_bits_per_coefficient.val := h_c_lt_2d
        have h2d1_lt : 2 ^ (n_bits_per_coefficient.val - 1) ≤ 2 ^ 10 :=
          Nat.pow_le_pow_right (by norm_num) (by omega)
        have h2d1_lt_q : 2 ^ (n_bits_per_coefficient.val - 1) < q := by
          show _ < 3329; omega
        calc coefficient.val * q + 2 ^ (n_bits_per_coefficient.val - 1)
            < coefficient.val * q + q := by omega
          _ = (coefficient.val + 1) * q := by ring
          _ ≤ 2 ^ n_bits_per_coefficient.val * q := Nat.mul_le_mul_right q hy'
      -- Step C: coefficient5.val = coefficient4.val (both < q + ZMod eq).
      have h_c5_eq_c4 : coefficient5.val = coefficient4.val := by
        have h_c4_lt_q : coefficient4.val < q := h_c4_fast ▸ h_fast_lt_Q
        have h_zq : ((coefficient5.val : ZMod q)) = ((coefficient4.val : ZMod q)) := hc5_zq
        have h1 : (coefficient5.val : ZMod q).val = coefficient5.val :=
          ZMod.val_natCast_of_lt hc5_lt
        have h2 : (coefficient4.val : ZMod q).val = coefficient4.val :=
          ZMod.val_natCast_of_lt h_c4_lt_q
        rw [← h1, ← h2, h_zq]
      have h_dst_coeff_fast : dst_coeff.val
                                = fastDecompress n_bits_per_coefficient.val coefficient.val := by
        rw [dst_coeff_post, h_c5_eq_c4, h_c4_fast]
      -- Conditional h_room: only needed when REFILL fires (n_bia < d).
      have h_room : n_bits_in_accumulator.val < n_bits_per_coefficient.val →
                    cb_src_read.val + 4 ≤ pb_src.length := by
        intro h_refill
        rcases h_src_disj with h_no_refill | h_refill_room
        · exact absurd h_no_refill (by omega)
        · exact h_refill_room
      have h_room_32d : n_bits_in_accumulator.val < n_bits_per_coefficient.val →
                    cb_src_read.val + 4 ≤ 32 * n_bits_per_coefficient.val := by
        intro h_refill
        rcases h_src_disj_32d with h_no_refill | h_refill_room
        · exact absurd h_no_refill (by omega)
        · exact h_refill_room
      -- Build pe_dst_ghost' = pe_dst_ghost with slot s_in.pi := dst_coeff.
      have h_pi_lt_dst : s_in.pi < pe_dst_ghost.val.length := by
        have := pe_dst_ghost.property; rw [this]; exact h_pi_lt_256
      let pe_dst_ghost' : PolyElement :=
        ⟨pe_dst_ghost.val.set s_in.pi dst_coeff, by
          have hp := pe_dst_ghost.property
          rw [List.length_set, hp]⟩
      -- Apply matchesRuntime_step_decode to build h_match' for body d s_in.
      have h_match' : Bridges.DecodeDecompressState.matchesRuntime
                        n_bits_per_coefficient.val
                        (Bridges.DecodeDecompressState.body
                          n_bits_per_coefficient.val s_in)
                        pe_dst_ghost' accumulator1 n_bits_in_accumulator1
                        pb_src cb_src_read1 := by
        apply Bridges.matchesRuntime_step_decode
                n_bits_per_coefficient.val s_in pe_dst_ghost pe_dst_ghost'
                accumulator n_bits_in_accumulator accumulator1 n_bits_in_accumulator1
                pb_src cb_src_read cb_src_read1 h_d h_match h_room h_pi_lt_256
        rcases cb_src_read1_post5 with
          ⟨h_d_le_nbia, h_cb_eq, h_acc1_eq, h_nbia1_eq, h_coeff_eq⟩
        | ⟨h_nbia_lt_d, h_cb1_eq, h_acc1_eq, h_nbia1_eq, h_coeff_eq⟩
        · -- NO-REFILL dispatch (d ≤ n_bia).
          left
          refine ⟨h_d_le_nbia, h_cb_eq, h_acc1_eq, h_nbia1_eq, ?_, ?_⟩
          · intro k hk
            simp only [pe_dst_ghost']
            rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD]
            fcongr 1
            rw [List.getElem?_set_ne (by omega)]
          · simp only [pe_dst_ghost']
            rw [List.getD_eq_getElem?_getD]
            rw [List.getElem?_set_self h_pi_lt_dst]
            simp only [Option.getD_some]
            rw [h_dst_coeff_fast]
            rw [if_pos h_dlt12_nat]
            fcongr 1
        · -- REFILL dispatch (n_bia < d).
          right
          have h_room_eval : cb_src_read.val + 4 ≤ pb_src.length := h_room h_nbia_lt_d
          have h_room_eval_32d : cb_src_read.val + 4 ≤ 32 * n_bits_per_coefficient.val :=
            h_room_32d h_nbia_lt_d
          have h_load_eq : loadLEWordBytes pb_src cb_src_read.val
                          = (Bridges.DecodeDecompressState.loadLEWord s_in.src
                              cb_src_read.val).toNat :=
            loadLEWordBytes_eq_loadLEWord_toNat_of_byteEq
              pb_src s_in.src cb_src_read.val h_match.2.1 h_room_eval_32d h_room_eval
          refine ⟨h_nbia_lt_d, h_cb1_eq, ?_, h_nbia1_eq, ?_, ?_⟩
          · rw [h_acc1_eq, h_load_eq]
          · intro k hk
            simp only [pe_dst_ghost']
            rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD]
            fcongr 1
            rw [List.getElem?_set_ne (by omega)]
          · simp only [pe_dst_ghost']
            rw [List.getD_eq_getElem?_getD]
            rw [List.getElem?_set_self h_pi_lt_dst]
            simp only [Option.getD_some]
            rw [h_dst_coeff_fast]
            rw [if_pos h_dlt12_nat]
            fcongr 1
            rw [h_coeff_eq, h_load_eq]
      have h_pi_body : (Bridges.DecodeDecompressState.body
                          n_bits_per_coefficient.val s_in).pi = s_in.pi + 1 := by
        unfold Bridges.DecodeDecompressState.body
        split_ifs <;> rfl
      have h_iter_i_new : iter1.i =
            (Bridges.DecodeDecompressState.body
              n_bits_per_coefficient.val s_in).pi := by
        rw [hit2_i, h_iter_i, h_pi_body]
      have h_slice_new : iter1.slice = orig_slice := by
        rw [hit2_slice, h_slice]
      have h_len_inv_new : Bridges.DecodeDecompressState.length_inv
            n_bits_per_coefficient.val
            (Bridges.DecodeDecompressState.body
              n_bits_per_coefficient.val s_in) iter1.i := by
        rw [hit2_i, h_iter_i]
        exact Bridges.DecodeDecompressState.body_length_inv
                n_bits_per_coefficient.val s_in s_in.pi
                h_d (by omega) (by rw [← h_pi_eq] at h_len_inv; exact h_len_inv)
      have h_si_aligned_new : 4 ∣ cb_src_read1.val := by
        rcases cb_src_read1_post5 with
          ⟨_, h_cb_eq, _, _, _⟩ | ⟨_, h_cb1_eq, _, _, _⟩
        · rw [h_cb_eq]; exact h_si_aligned
        · rw [h_cb1_eq]; exact Nat.dvd_add h_si_aligned ⟨1, rfl⟩
      have hback_len_new : ∀ (im : core.slice.iter.IterMut U16),
          im.slice.length = orig_slice.length →
          (back (next_back im (some dst_coeff))).slice.length
            = orig_slice.length := by
        intro im him
        rw [hsome_set]
        apply hback_len
        simp [Slice.setAtNat_length, him]
      have h_iter1_le : iter1.i ≤ orig_slice.length := by
        rw [hit2_i]; rw [h_iter_i]; omega
      have hback_writes_new : ∀ (im : core.slice.iter.IterMut U16)
          (him : im.slice.length = orig_slice.length)
          (j : ℕ) (hj : j < iter1.i),
            ((back (next_back im (some dst_coeff))).slice.val[j]'(by
                have := hback_len_new im him
                scalar_tac)).val
              = (Bridges.DecodeDecompressState.body
                  n_bits_per_coefficient.val s_in).dst.getD j 0 := by
        intro im him j hj
        rw [hit2_i] at hj
        have him_set : (next_back im (some dst_coeff)).slice.length
                          = orig_slice.length := by
          rw [hsome_set]; simp [Slice.setAtNat_length, him]
        have h_j_lt_body_pi : j < (Bridges.DecodeDecompressState.body
                                    n_bits_per_coefficient.val s_in).pi := by
          rw [h_pi_body]; omega
        have h_dst_eq := h_match'.2.2.2.2.2.2.2.2.2.2.2 j h_j_lt_body_pi
        rw [h_dst_eq]
        by_cases hji : j = iter.i
        · subst hji
          have hi_lt' : iter.i < orig_slice.length := hi_lt
          have hrest := hback_rest (next_back im (some dst_coeff)) him_set iter.i
                        (le_refl _) hi_lt'
          have hi_lt_im : iter.i < im.slice.length := by rw [him]; exact hi_lt'
          have h_pi_lt_dst' : iter.i < pe_dst_ghost.val.length := by
            rw [← h_pi_eq]; exact h_pi_lt_dst
          calc ((back (next_back im (some dst_coeff))).slice.val[iter.i]'_).val
              = ((next_back im (some dst_coeff)).slice.val[iter.i]'(by
                  have := him_set; have := hi_lt'; scalar_tac)).val := by
                  fcongr 1
            _ = dst_coeff.val := by
                simp [hsome_set, Slice.setAtNat, Slice.length] at *
            _ = (pe_dst_ghost'.val.getD iter.i 0#u16).val := by
                simp only [pe_dst_ghost']
                have : iter.i = s_in.pi := h_pi_eq.symm
                rw [this, List.getD_eq_getElem?_getD,
                    List.getElem?_set_self h_pi_lt_dst]
                simp
        · have hj_lt : j < iter.i := by omega
          have hwrites := hback_writes (next_back im (some dst_coeff)) him_set j hj_lt
          calc ((back (next_back im (some dst_coeff))).slice.val[j]'_).val
              = s_in.dst.getD j 0 := hwrites
            _ = (pe_dst_ghost.val.getD j 0#u16).val :=
                h_match.2.2.2.2.2.2.2.2.2.2.2 j (by rw [h_pi_eq]; omega)
            _ = (pe_dst_ghost'.val.getD j 0#u16).val := by
                simp only [pe_dst_ghost']
                have hpi_ne_j : s_in.pi ≠ j := by rw [h_pi_eq]; omega
                rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD,
                    List.getElem?_set_ne hpi_ne_j]
      have hback_rest_new : ∀ (im : core.slice.iter.IterMut U16)
          (him : im.slice.length = orig_slice.length)
          (j : ℕ) (_hj_ge : iter1.i ≤ j) (_hj_lt : j < orig_slice.length),
            (back (next_back im (some dst_coeff))).slice.val[j]'(by
                have := hback_len_new im him; scalar_tac)
              = im.slice.val[j]'(by scalar_tac) := by
        intro im him j hj_ge hj_lt
        rw [hit2_i] at hj_ge
        have him_set : (next_back im (some dst_coeff)).slice.length
                          = orig_slice.length := by
          rw [hsome_set]; simp [Slice.setAtNat_length, him]
        have hrest := hback_rest (next_back im (some dst_coeff)) him_set j
                      (by omega) hj_lt
        have hj_ne : iter.i ≠ j := by omega
        calc (back (next_back im (some dst_coeff))).slice.val[j]'_
            = (next_back im (some dst_coeff)).slice.val[j]'(by
                have := him_set; have := hj_lt; scalar_tac) := hrest
          _ = im.slice.val[j]'(by
                have := him; have := hj_lt; scalar_tac) := by
                simp [hsome_set, Slice.setAtNat, Slice.length] at *
                rw [List.getElem_set_ne hj_ne]
      -- New wfPoly-preservation preconditions for the IH.
      have h_s_in_dst_wf_new : ∀ k, k < (Bridges.DecodeDecompressState.body
                                    n_bits_per_coefficient.val s_in).pi →
                                  (Bridges.DecodeDecompressState.body
                                    n_bits_per_coefficient.val s_in).dst.getD k 0 < q := by
        intro k hk
        have hk_lt_body : k < (Bridges.DecodeDecompressState.body
                                n_bits_per_coefficient.val s_in).pi := hk
        have h_dst_match := h_match'.2.2.2.2.2.2.2.2.2.2.2 k hk_lt_body
        rw [h_dst_match]
        rw [h_pi_body] at hk
        by_cases hk_eq : k = s_in.pi
        · subst hk_eq
          have h_set_get : pe_dst_ghost'.val.getD s_in.pi 0#u16 = dst_coeff := by
            simp only [pe_dst_ghost']
            rw [List.getD_eq_getElem?_getD]
            rw [List.getElem?_set_self h_pi_lt_dst]
            simp
          rw [h_set_get, h_dst_coeff_fast]
          exact h_fast_lt_Q
        · have hk_lt_pi : k < s_in.pi := by omega
          have h_set_get : pe_dst_ghost'.val.getD k 0#u16 = pe_dst_ghost.val.getD k 0#u16 := by
            simp only [pe_dst_ghost']
            rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD]
            fcongr 1
            rw [List.getElem?_set_ne (by omega : s_in.pi ≠ k)]
          rw [h_set_get]
          have h_orig_dst := h_match.2.2.2.2.2.2.2.2.2.2.2 k hk_lt_pi
          rw [← h_orig_dst]
          exact h_s_in_dst_wf k hk_lt_pi
      -- Apply WP.spec_mono with the recursive _loop0.spec call on (body d s_in).
      apply WP.spec_mono
        (mlkem.ntt.poly_element_decode_and_decompress_loop0.spec iter1
          (fun im => back (next_back im (some dst_coeff)))
          pb_src n_bits_per_coefficient cb_src_read1
          accumulator1 n_bits_in_accumulator1
          (Bridges.DecodeDecompressState.body
            n_bits_per_coefficient.val s_in)
          pe_dst_ghost' h_d h_match' h_iter_i_new orig_slice h_slice_new
          h_orig_len h_len_inv_new h_si_aligned_new h_src_len
          hback_len_new hback_writes_new hback_rest_new
          h_orig_wf h_s_in_dst_wf_new)
      -- Post conversion via recBody step identity.
      have h_rec_step :
          Bridges.DecodeDecompressState.recBody
            n_bits_per_coefficient.val s_in (orig_slice.length - iter.i)
            = Bridges.DecodeDecompressState.recBody
                n_bits_per_coefficient.val
                (Bridges.DecodeDecompressState.body
                  n_bits_per_coefficient.val s_in)
                (orig_slice.length - iter1.i) := by
        have h_sub : orig_slice.length - iter.i
                       = (orig_slice.length - iter1.i) + 1 := by
          rw [hit2_i]; omega
        rw [h_sub]
        unfold Bridges.DecodeDecompressState.recBody
        rw [List.range_succ_eq_map, List.foldl_cons]
        simp [List.foldl_map]
      intro err hpost
      cases err with
      | mk e it =>
        obtain ⟨h_slen, h_err, h_wfpoly⟩ := hpost
        refine ⟨h_slen, ?_, h_wfpoly⟩
        cases e with
        | NoError =>
          obtain ⟨s_out, h_sout_eq, h_pi256, h_dst_eq, h_wf⟩ := h_err
          subst h_sout_eq
          rw [← h_rec_step] at h_pi256 h_dst_eq
          refine ⟨h_pi256, h_dst_eq, ?_⟩
          intro k hk_ge hk_lt
          by_cases hk_eq : k = s_in.pi
          · subst hk_eq
            -- d<12 case: MLKEM.m d = 2^d, use Bridges.fipsBitSum_lt_two_pow.
            have h_src_body : (Bridges.DecodeDecompressState.body
                                n_bits_per_coefficient.val s_in).src = s_in.src := by
              unfold Bridges.DecodeDecompressState.body
              split_ifs <;> rfl
            have h_m_eq : MLKEM.m n_bits_per_coefficient.val
                          = 2 ^ n_bits_per_coefficient.val := by
              simp [MLKEM.m, h_dlt12_nat]
            rw [h_m_eq]
            exact Bridges.fipsBitSum_lt_two_pow _ _ _
          · have hk_ge' : (Bridges.DecodeDecompressState.body
                            n_bits_per_coefficient.val s_in).pi ≤ k := by
              rw [h_pi_body]; omega
            have h_src_eq : (Bridges.DecodeDecompressState.body
                              n_bits_per_coefficient.val s_in).src
                                = s_in.src := by
              unfold Bridges.DecodeDecompressState.body
              split_ifs <;> rfl
            rw [← h_src_eq]
            exact h_wf k hk_ge' hk_lt
        | InvalidBlob => exact h_err
        | _ => exact h_err
    · -- d = 12, coefficient ≥ Q ⇒ InvalidBlob (immediate ok).
      simp only [WP.spec_ok]
      have h_im_len : (next_back iter1 (some iter.slice[iter.i])).slice.length
                        = orig_slice.length := by
        rw [hsome_set]; simp only
        rw [Slice.setAtNat_length]; rw [hit2_slice]; exact hi_pe
      refine ⟨?_, ?_, ?_⟩
      · -- iter'.slice.length = orig_slice.length
        exact hback_len _ h_im_len
      · -- InvalidBlob ⇒ d = 12
        have h_d_ge_12 : ¬ (n_bits_per_coefficient.val < 12) := by
          intro h; apply h_dlt12
          show n_bits_per_coefficient < 12#u32
          scalar_tac
        have h_d_eq_12 : n_bits_per_coefficient.val = 12 := by
          have := h_d.2; omega
        exact h_d_eq_12
      · -- Universal wfPoly: derive from hback_writes + h_s_in_dst_wf (for j < iter.i)
        --                   and hback_rest + h_orig_wf (for j ≥ iter.i; at j = iter.i,
        --                   the slot stores `iter.slice[iter.i] = orig_slice[iter.i]`).
        intro j h_j
        have h_back_len_eq : (back (next_back iter1 (some iter.slice[iter.i]))).slice.length
                                = orig_slice.length := hback_len _ h_im_len
        have h_j_orig : j < orig_slice.length := by
          rw [← h_back_len_eq]; exact h_j
        by_cases hj_lt : j < iter.i
        · -- j < iter.i: back-write
          have hw := hback_writes (next_back iter1 (some iter.slice[iter.i]))
                                    h_im_len j hj_lt
          rw [hw]
          exact h_s_in_dst_wf j (by rw [← h_iter_i]; exact hj_lt)
        · -- j ≥ iter.i: back-pass-through, then set at iter.i
          push Not at hj_lt
          have hr := hback_rest (next_back iter1 (some iter.slice[iter.i]))
                                  h_im_len j hj_lt h_j_orig
          rw [hr]
          -- Goal: (next_back iter1 (some iter.slice[iter.i])).slice.val[j] < q
          -- iter.slice = orig_slice (function level); h_slice gives the bridge.
          have h_j_iter : j < iter.slice.length := h_slice ▸ h_j_orig
          have h_iter_i_lt : iter.i < iter.slice.length := h_slice ▸ hi_lt
          have h_j_iter1 : j < iter1.slice.length := hit2_slice ▸ h_j_iter
          have h_iter_i_iter1 : iter.i < iter1.slice.length := hit2_slice ▸ h_iter_i_lt
          by_cases hj_eq : j = iter.i
          · -- j = iter.i: slot stores iter.slice[iter.i], same as orig_slice[iter.i] via h_slice
            have h_eq : (iter.slice.val[iter.i]'h_iter_i_lt).val
                          = (orig_slice.val[iter.i]'hi_lt).val := by
              subst h_slice; rfl
            calc ((next_back iter1 (some iter.slice[iter.i])).slice.val[j]'(by
                    have := h_im_len; scalar_tac)).val
                = (iter.slice.val[iter.i]'h_iter_i_lt).val := by
                    simp [hsome_set, Slice.setAtNat, hj_eq, hit2_slice]
                    rfl
              _ = (orig_slice.val[iter.i]'hi_lt).val := h_eq
              _ < q := h_orig_wf iter.i hi_lt
          · -- j > iter.i: unchanged
            have h_eq : (iter.slice.val[j]'h_j_iter).val
                          = (orig_slice.val[j]'h_j_orig).val := by
              subst h_slice; rfl
            calc ((next_back iter1 (some iter.slice[iter.i])).slice.val[j]'(by
                    have := h_im_len; scalar_tac)).val
                = (iter.slice.val[j]'h_j_iter).val := by
                    simp [hsome_set, Slice.setAtNat, hit2_slice]
                    rw [List.getElem_set_ne (Ne.symm hj_eq)]
              _ = (orig_slice.val[j]'h_j_orig).val := h_eq
              _ < q := h_orig_wf j h_j_orig
    · -- d = 12, coefficient < Q: body without fastDecompress.
      -- Step the U16 cast.
      have h_d12_eq : n_bits_per_coefficient.val = 12 := by
        have h12 : ¬ n_bits_per_coefficient.val < 12 := by
          intro h; apply h_dlt12
          show n_bits_per_coefficient < 12#u32
          scalar_tac
        have := h_d.2; omega
      have h_coeff_lt_16 : coefficient.val ≤ UScalar.max UScalarTy.U16 := by
        have h_c := cb_src_read1_post3
        rw [h_d12_eq] at h_c
        have : (2 : ℕ) ^ 12 = 4096 := by decide
        rw [this] at h_c
        have h_max : UScalar.max UScalarTy.U16 = 65535 := by scalar_tac
        rw [h_max]; omega
      let* ⟨ dst_coeff, dst_coeff_post ⟩ ←
        UScalar.cast_inBounds_spec UScalarTy.U16 coefficient h_coeff_lt_16
      -- Conditional h_room: only needed when REFILL fires (n_bia < d).
      have h_room : n_bits_in_accumulator.val < n_bits_per_coefficient.val →
                    cb_src_read.val + 4 ≤ pb_src.length := by
        intro h_refill
        rcases h_src_disj with h_no_refill | h_refill_room
        · exact absurd h_no_refill (by omega)
        · exact h_refill_room
      have h_room_32d : n_bits_in_accumulator.val < n_bits_per_coefficient.val →
                    cb_src_read.val + 4 ≤ 32 * n_bits_per_coefficient.val := by
        intro h_refill
        rcases h_src_disj_32d with h_no_refill | h_refill_room
        · exact absurd h_no_refill (by omega)
        · exact h_refill_room
      -- Build pe_dst_ghost' = pe_dst_ghost with slot s_in.pi := dst_coeff.
      have h_pi_lt_dst : s_in.pi < pe_dst_ghost.val.length := by
        have := pe_dst_ghost.property; rw [this]; exact h_pi_lt_256
      let pe_dst_ghost' : PolyElement :=
        ⟨pe_dst_ghost.val.set s_in.pi dst_coeff, by
          have hp := pe_dst_ghost.property
          rw [List.length_set, hp]⟩
      -- Apply matchesRuntime_step_decode to build h_match' for body d s_in.
      have h_match' : Bridges.DecodeDecompressState.matchesRuntime
                        n_bits_per_coefficient.val
                        (Bridges.DecodeDecompressState.body
                          n_bits_per_coefficient.val s_in)
                        pe_dst_ghost' accumulator1 n_bits_in_accumulator1
                        pb_src cb_src_read1 := by
        apply Bridges.matchesRuntime_step_decode
                n_bits_per_coefficient.val s_in pe_dst_ghost pe_dst_ghost'
                accumulator n_bits_in_accumulator accumulator1 n_bits_in_accumulator1
                pb_src cb_src_read cb_src_read1 h_d h_match h_room h_pi_lt_256
        -- Provide dispatch witness from cb_src_read1_post5.
        rcases cb_src_read1_post5 with
          ⟨h_d_le_nbia, h_cb_eq, h_acc1_eq, h_nbia1_eq, h_coeff_eq⟩
        | ⟨h_nbia_lt_d, h_cb1_eq, h_acc1_eq, h_nbia1_eq, h_coeff_eq⟩
        · -- NO-REFILL dispatch (d ≤ n_bia).
          left
          refine ⟨h_d_le_nbia, h_cb_eq, h_acc1_eq, h_nbia1_eq, ?_, ?_⟩
          · -- pe_dst_ghost'.val.getD k = pe_dst_ghost.val.getD k for k < s_in.pi
            intro k hk
            simp only [pe_dst_ghost']
            rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD]
            fcongr 1
            rw [List.getElem?_set_ne (by omega)]
          · -- pe_dst_ghost'.val.getD s_in.pi 0#u16 . val = (d=12 RHS)
            simp only [pe_dst_ghost']
            rw [List.getD_eq_getElem?_getD]
            rw [List.getElem?_set_self h_pi_lt_dst]
            simp only [Option.getD_some]
            rw [dst_coeff_post]
            -- coefficient.val = accumulator &&& ((1<<<d) - 1) (from h_coeff_eq).
            -- d = 12, so if-branch is `else`.
            rw [if_neg (by omega : ¬ n_bits_per_coefficient.val < 12)]
            convert h_coeff_eq using 2
        · -- REFILL dispatch (n_bia < d).  Need to convert
          --   loadLEWordBytes pb_src cb to (loadLEWord s_in.src cb).toNat.
          right
          have h_room_eval : cb_src_read.val + 4 ≤ pb_src.length := h_room h_nbia_lt_d
          have h_room_eval_32d : cb_src_read.val + 4 ≤ 32 * n_bits_per_coefficient.val :=
            h_room_32d h_nbia_lt_d
          have h_load_eq : loadLEWordBytes pb_src cb_src_read.val
                          = (Bridges.DecodeDecompressState.loadLEWord s_in.src
                              cb_src_read.val).toNat :=
            loadLEWordBytes_eq_loadLEWord_toNat_of_byteEq
              pb_src s_in.src cb_src_read.val h_match.2.1 h_room_eval_32d h_room_eval
          refine ⟨h_nbia_lt_d, h_cb1_eq, ?_, h_nbia1_eq, ?_, ?_⟩
          · -- acc1 = (loadLEWord s.src cb).toNat >>> (d - n_bia)
            rw [h_acc1_eq, h_load_eq]
          · -- pe_dst_ghost'.val.getD k = pe_dst_ghost.val.getD k for k < s_in.pi
            intro k hk
            simp only [pe_dst_ghost']
            rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD]
            fcongr 1
            rw [List.getElem?_set_ne (by omega)]
          · -- pe_dst_ghost'.val.getD s_in.pi 0#u16 . val = (REFILL d=12 RHS)
            simp only [pe_dst_ghost']
            rw [List.getD_eq_getElem?_getD]
            rw [List.getElem?_set_self h_pi_lt_dst]
            simp only [Option.getD_some]
            rw [dst_coeff_post]
            rw [if_neg (by omega : ¬ n_bits_per_coefficient.val < 12)]
            -- h_coeff_eq has loadLEWordBytes; convert to loadLEWord.toNat.
            rw [h_coeff_eq, h_load_eq]
      -- Recursive call setup: build the 6 IterMut framing predicates for the
      -- inner _loop0.spec on (body d s_in), then apply WP.spec_mono.  See
      -- handoff comment above for the full per-precondition recipe.
      have h_pi_body : (Bridges.DecodeDecompressState.body
                          n_bits_per_coefficient.val s_in).pi = s_in.pi + 1 := by
        unfold Bridges.DecodeDecompressState.body
        split_ifs <;> rfl
      have h_iter_i_new : iter1.i =
            (Bridges.DecodeDecompressState.body
              n_bits_per_coefficient.val s_in).pi := by
        rw [hit2_i, h_iter_i, h_pi_body]
      have h_slice_new : iter1.slice = orig_slice := by
        rw [hit2_slice, h_slice]
      have h_len_inv_new : Bridges.DecodeDecompressState.length_inv
            n_bits_per_coefficient.val
            (Bridges.DecodeDecompressState.body
              n_bits_per_coefficient.val s_in) iter1.i := by
        rw [hit2_i, h_iter_i]
        exact Bridges.DecodeDecompressState.body_length_inv
                n_bits_per_coefficient.val s_in s_in.pi
                h_d (by omega) (by rw [← h_pi_eq] at h_len_inv; exact h_len_inv)
      have h_si_aligned_new : 4 ∣ cb_src_read1.val := by
        rcases cb_src_read1_post5 with
          ⟨_, h_cb_eq, _, _, _⟩ | ⟨_, h_cb1_eq, _, _, _⟩
        · rw [h_cb_eq]; exact h_si_aligned
        · rw [h_cb1_eq]; exact Nat.dvd_add h_si_aligned ⟨1, rfl⟩
      have hback_len_new : ∀ (im : core.slice.iter.IterMut U16),
          im.slice.length = orig_slice.length →
          (back (next_back im (some dst_coeff))).slice.length
            = orig_slice.length := by
        intro im him
        rw [hsome_set]
        apply hback_len
        simp [Slice.setAtNat_length, him]
      -- Helper: precondition for accessing (back ...).slice[j].
      have h_iter1_le : iter1.i ≤ orig_slice.length := by
        rw [hit2_i]
        rw [h_iter_i]; omega
      have hback_writes_new : ∀ (im : core.slice.iter.IterMut U16)
          (him : im.slice.length = orig_slice.length)
          (j : ℕ) (hj : j < iter1.i),
            ((back (next_back im (some dst_coeff))).slice.val[j]'(by
                have := hback_len_new im him
                scalar_tac)).val
              = (Bridges.DecodeDecompressState.body
                  n_bits_per_coefficient.val s_in).dst.getD j 0 := by
        intro im him j hj
        rw [hit2_i] at hj
        have him_set : (next_back im (some dst_coeff)).slice.length
                          = orig_slice.length := by
          rw [hsome_set]; simp [Slice.setAtNat_length, him]
        have h_j_lt_body_pi : j < (Bridges.DecodeDecompressState.body
                                    n_bits_per_coefficient.val s_in).pi := by
          rw [h_pi_body]; omega
        have h_dst_eq := h_match'.2.2.2.2.2.2.2.2.2.2.2 j h_j_lt_body_pi
        rw [h_dst_eq]
        by_cases hji : j = iter.i
        · subst hji
          have hi_lt' : iter.i < orig_slice.length := hi_lt
          have hrest := hback_rest (next_back im (some dst_coeff)) him_set iter.i
                        (le_refl _) hi_lt'
          have hi_lt_im : iter.i < im.slice.length := by rw [him]; exact hi_lt'
          have h_pi_lt_dst' : iter.i < pe_dst_ghost.val.length := by
            rw [← h_pi_eq]; exact h_pi_lt_dst
          calc ((back (next_back im (some dst_coeff))).slice.val[iter.i]'_).val
              = ((next_back im (some dst_coeff)).slice.val[iter.i]'(by
                  have := him_set; have := hi_lt'; scalar_tac)).val := by
                  fcongr 1
            _ = dst_coeff.val := by
                simp [hsome_set, Slice.setAtNat, Slice.length] at *
            _ = (pe_dst_ghost'.val.getD iter.i 0#u16).val := by
                simp only [pe_dst_ghost']
                have : iter.i = s_in.pi := h_pi_eq.symm
                rw [this, List.getD_eq_getElem?_getD,
                    List.getElem?_set_self h_pi_lt_dst]
                simp
        · have hj_lt : j < iter.i := by omega
          have hwrites := hback_writes (next_back im (some dst_coeff)) him_set j hj_lt
          calc ((back (next_back im (some dst_coeff))).slice.val[j]'_).val
              = s_in.dst.getD j 0 := hwrites
            _ = (pe_dst_ghost.val.getD j 0#u16).val :=
                h_match.2.2.2.2.2.2.2.2.2.2.2 j (by rw [h_pi_eq]; omega)
            _ = (pe_dst_ghost'.val.getD j 0#u16).val := by
                simp only [pe_dst_ghost']
                have hpi_ne_j : s_in.pi ≠ j := by rw [h_pi_eq]; omega
                rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD,
                    List.getElem?_set_ne hpi_ne_j]
      have hback_rest_new : ∀ (im : core.slice.iter.IterMut U16)
          (him : im.slice.length = orig_slice.length)
          (j : ℕ) (_hj_ge : iter1.i ≤ j) (_hj_lt : j < orig_slice.length),
            (back (next_back im (some dst_coeff))).slice.val[j]'(by
                have := hback_len_new im him; scalar_tac)
              = im.slice.val[j]'(by scalar_tac) := by
        intro im him j hj_ge hj_lt
        rw [hit2_i] at hj_ge
        have him_set : (next_back im (some dst_coeff)).slice.length
                          = orig_slice.length := by
          rw [hsome_set]; simp [Slice.setAtNat_length, him]
        have hrest := hback_rest (next_back im (some dst_coeff)) him_set j
                      (by omega) hj_lt
        have hj_ne : iter.i ≠ j := by omega
        calc (back (next_back im (some dst_coeff))).slice.val[j]'_
            = (next_back im (some dst_coeff)).slice.val[j]'(by
                have := him_set; have := hj_lt; scalar_tac) := hrest
          _ = im.slice.val[j]'(by
                have := him; have := hj_lt; scalar_tac) := by
                simp [hsome_set, Slice.setAtNat, Slice.length] at *
                rw [List.getElem_set_ne hj_ne]
      -- New wfPoly-preservation preconditions for the IH (d=12 NoError).
      have h_coeff_lt_q_d12 : coefficient.val < q := by
        have h_lt_Q : coefficient.val < mlkem.ntt.Q.val := by
          by_contra h
          push Not at h
          exact h_coeff_ge_q h
        have h_Q_val : mlkem.ntt.Q.val = 3329 := ntt_Q_val
        show _ < (3329 : ℕ); rw [← h_Q_val]; exact h_lt_Q
      have h_s_in_dst_wf_new : ∀ k, k < (Bridges.DecodeDecompressState.body
                                    n_bits_per_coefficient.val s_in).pi →
                                  (Bridges.DecodeDecompressState.body
                                    n_bits_per_coefficient.val s_in).dst.getD k 0 < q := by
        intro k hk
        have hk_lt_body : k < (Bridges.DecodeDecompressState.body
                                n_bits_per_coefficient.val s_in).pi := hk
        have h_dst_match := h_match'.2.2.2.2.2.2.2.2.2.2.2 k hk_lt_body
        rw [h_dst_match]
        rw [h_pi_body] at hk
        by_cases hk_eq : k = s_in.pi
        · subst hk_eq
          have h_set_get : pe_dst_ghost'.val.getD s_in.pi 0#u16 = dst_coeff := by
            simp only [pe_dst_ghost']
            rw [List.getD_eq_getElem?_getD]
            rw [List.getElem?_set_self h_pi_lt_dst]
            simp
          rw [h_set_get, dst_coeff_post]
          exact h_coeff_lt_q_d12
        · have hk_lt_pi : k < s_in.pi := by omega
          have h_set_get : pe_dst_ghost'.val.getD k 0#u16 = pe_dst_ghost.val.getD k 0#u16 := by
            simp only [pe_dst_ghost']
            rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD]
            fcongr 1
            rw [List.getElem?_set_ne (by omega : s_in.pi ≠ k)]
          rw [h_set_get]
          have h_orig_dst := h_match.2.2.2.2.2.2.2.2.2.2.2 k hk_lt_pi
          rw [← h_orig_dst]
          exact h_s_in_dst_wf k hk_lt_pi
      -- Apply WP.spec_mono with the recursive _loop0.spec call on (body d s_in).
      apply WP.spec_mono
        (mlkem.ntt.poly_element_decode_and_decompress_loop0.spec iter1
          (fun im => back (next_back im (some dst_coeff)))
          pb_src n_bits_per_coefficient cb_src_read1
          accumulator1 n_bits_in_accumulator1
          (Bridges.DecodeDecompressState.body
            n_bits_per_coefficient.val s_in)
          pe_dst_ghost' h_d h_match' h_iter_i_new orig_slice h_slice_new
          h_orig_len h_len_inv_new h_si_aligned_new h_src_len
          hback_len_new hback_writes_new hback_rest_new
          h_orig_wf h_s_in_dst_wf_new)
      -- Post conversion: IH talks about (body d s_in) and iter1.i;
      -- goal is for s_in and iter.i.  Bridge via recBody step identity.
      have h_rec_step :
          Bridges.DecodeDecompressState.recBody
            n_bits_per_coefficient.val s_in (orig_slice.length - iter.i)
            = Bridges.DecodeDecompressState.recBody
                n_bits_per_coefficient.val
                (Bridges.DecodeDecompressState.body
                  n_bits_per_coefficient.val s_in)
                (orig_slice.length - iter1.i) := by
        have h_sub : orig_slice.length - iter.i
                       = (orig_slice.length - iter1.i) + 1 := by
          rw [hit2_i]; omega
        rw [h_sub]
        unfold Bridges.DecodeDecompressState.recBody
        rw [List.range_succ_eq_map, List.foldl_cons]
        simp [List.foldl_map]
      intro err hpost
      cases err with
      | mk e it =>
        obtain ⟨h_slen, h_err, h_wfpoly⟩ := hpost
        refine ⟨h_slen, ?_, h_wfpoly⟩
        cases e with
        | NoError =>
          obtain ⟨s_out, h_sout_eq, h_pi256, h_dst_eq, h_wf⟩ := h_err
          subst h_sout_eq
          rw [← h_rec_step] at h_pi256 h_dst_eq
          refine ⟨h_pi256, h_dst_eq, ?_⟩
          intro k hk_ge hk_lt
          by_cases hk_eq : k = s_in.pi
          · subst hk_eq
            -- d=12 case: MLKEM.m d = q = 3329.  Bridge fipsBitSum to the
            -- runtime `coefficient.val` via matchesRuntime's `acc_match`
            -- conjunct (path (i) — h_match strengthened with acc_match +
            -- bit-conservation), then use the runtime check
            -- `¬ Q ≤ coefficient.val` to bound the result.
            have h_m_eq : MLKEM.m n_bits_per_coefficient.val = MLKEM.q := by
              simp [MLKEM.m, h_d12_eq]
            rw [h_m_eq]
            -- Extract relevant conjuncts from h_match.
            obtain ⟨h_src_len_eq, h_src_byteq, h_si_eqv, h_cb_lev, h_acci_eqv,
                    h_nbia_le_32, h_acc_bv, h_8si_eqv, h_acc_zero, h_acc_match,
                    h_dst_len, _h_dst_match⟩ := h_match
            -- s_in.acc.toNat = accumulator.val (since accumulator < 2^32).
            have h_acc_to_nat : s_in.acc.toNat = accumulator.val := by
              rw [h_acc_bv]
              have h_lt : accumulator.val < 2 ^ 32 := by scalar_tac
              simp []
            have h_d_le_12 : n_bits_per_coefficient.val ≤ 12 := h_d.2
            -- Q.val = 3329.
            have h_Q_val : mlkem.ntt.Q.val = 3329 := ntt_Q_val
            -- coefficient.val < 3329 from the runtime ¬ Q ≤ coefficient.val.
            have h_coeff_lt_q : coefficient.val < mlkem.ntt.Q.val := by
              by_contra h
              push Not at h
              exact h_coeff_ge_q h
            have h_coeff_lt : coefficient.val < MLKEM.q := by
              rw [show (MLKEM.q : ℕ) = 3329 from rfl, ← h_Q_val]; exact h_coeff_lt_q
            -- Dispatch on NO-REFILL vs REFILL formula for coefficient.val.
            rcases cb_src_read1_post5 with
              ⟨h_d_le_nbia, _h_cb_eq, _h_acc1_eq, _h_nbia1_eq, h_coeff_eq⟩
              | ⟨h_nbia_lt_d, _h_cb1_eq, _h_acc1_eq, _h_nbia1_eq, h_coeff_eq⟩
            · -- NO-REFILL: coefficient.val = acc.val &&& ((1<<<d) - 1).
              have h_d_le_acci : n_bits_per_coefficient.val ≤ s_in.acci := by
                rw [h_acci_eqv]; exact h_d_le_nbia
              have h_eq := Bridges.v_lhs_no_refill_eq_fipsBitSum
                            n_bits_per_coefficient.val s_in.src s_in.pi
                            s_in.acc s_in.acci h_acc_match h_d_le_acci
              rw [← h_eq, h_acc_to_nat, ← h_coeff_eq]
              exact h_coeff_lt
            · -- REFILL: coefficient.val = (acc &&& ((1<<<nbia)-1)) |||
              --   ((loadLEWordBytes &&& ((1<<<(d-nbia))-1)) <<< nbia).
              have h_d_gt_acci : s_in.acci < n_bits_per_coefficient.val := by
                rw [h_acci_eqv]; exact h_nbia_lt_d
              have h_room_eval : cb_src_read.val + 4 ≤ pb_src.length := by
                apply h_room; exact h_nbia_lt_d
              have h_room_eval_32d : cb_src_read.val + 4 ≤ 32 * n_bits_per_coefficient.val := by
                apply h_room_32d; exact h_nbia_lt_d
              have h_load_eq : loadLEWordBytes pb_src cb_src_read.val
                              = (Bridges.DecodeDecompressState.loadLEWord
                                  s_in.src cb_src_read.val).toNat :=
                loadLEWordBytes_eq_loadLEWord_toNat_of_byteEq
                  pb_src s_in.src cb_src_read.val h_src_byteq h_room_eval_32d h_room_eval
              -- Bit-conservation: 8 * s_in.si = s_in.pi * d + s_in.acci.
              have h_8si : 8 * s_in.si
                            = s_in.pi * n_bits_per_coefficient.val + s_in.acci :=
                h_8si_eqv
              have h_eq := Bridges.v_lhs_refill_eq_fipsBitSum
                            n_bits_per_coefficient.val h_d_le_12
                            s_in.src s_in.pi s_in.si
                            s_in.acc s_in.acci h_8si h_acc_match h_d_gt_acci
              rw [← h_eq, h_acc_to_nat, h_acci_eqv, h_si_eqv,
                  ← h_load_eq, ← h_coeff_eq]
              exact h_coeff_lt
          · have hk_ge' : (Bridges.DecodeDecompressState.body
                            n_bits_per_coefficient.val s_in).pi ≤ k := by
              rw [h_pi_body]; omega
            have h_src_eq : (Bridges.DecodeDecompressState.body
                              n_bits_per_coefficient.val s_in).src
                                = s_in.src := by
              unfold Bridges.DecodeDecompressState.body
              split_ifs <;> rfl
            rw [← h_src_eq]
            exact h_wf k hk_ge' hk_lt
        | InvalidBlob => exact h_err
        | _ => exact h_err
  · -- NONE branch — loop done.
    have hge : iter.i ≥ iter.slice.len := by scalar_tac
    have hLen_eq : (↑iter.slice.len : ℕ) = iter.slice.length := by
      simp [Slice.len, Slice.length]
    have hi_eq : iter.i = orig_slice.length := by
      have : iter.slice.len.val = orig_slice.length := by
        rw [← hi_pe]; simp [Slice.len, Slice.length]
      scalar_tac
    have h_iter_i_256 : iter.i = 256 := by rw [hi_eq, h_orig_len]
    -- nbia = 0 (from length_inv + alignment + iter.i = 256).
    have h_acci_zero : s_in.acci = 0 := by
      -- 8*si = 256*d + acci; 4|si ⇒ 32|8*si; 256*d = 32*(8*d) ⇒ 32|acci; acci ≤ 31.
      have h_eq2 : 8 * s_in.si = 256 * n_bits_per_coefficient.val + s_in.acci := by
        rw [← h_iter_i_256]; exact h_8si_eq
      have h_si_dvd : 8 * s_in.si % 32 = 0 := by
        rw [h_si_eq]
        rcases h_si_aligned with ⟨q, hq⟩
        rw [hq]; ring_nf; simp [Nat.mul_mod_left]
      have h_pi_d_mod : 256 * n_bits_per_coefficient.val % 32 = 0 := by
        rw [show (256 : ℕ) = 32 * 8 by rfl, Nat.mul_assoc]; simp []
      have h_acci_mod : s_in.acci % 32 = 0 := by omega
      omega
    have h_nbia_zero : n_bits_in_accumulator.val = 0 := by
      rw [← h_acci_eq]; exact h_acci_zero
    -- cb_src_read = 32 * d (from length_inv at iter.i = 256 with acci = 0).
    have h_cb_eq_32d : cb_src_read.val = 32 * n_bits_per_coefficient.val := by
      have h_eq2 : 8 * cb_src_read.val = 256 * n_bits_per_coefficient.val + 0 := by
        rw [← h_si_eq, ← h_acci_zero, ← h_iter_i_256]; exact h_8si_eq
      omega
    let* ⟨ o, iter1, next_back, h_all ⟩ ←
      core.slice.iter.IteratorIterMut.next_spec_none
    obtain ⟨ho, hit2_eq, hsome_back⟩ := h_all
    rw [ho, poly_element_decode_and_decompress_loop0_match.fold]
    simp only []
    -- NONE arm body:
    --   massert (nbia = 0); compute i3 = d * 32; massert (cb_src_read = i3); return.
    step*
    -- Final: build the post.  The outer refine destructures via the existential's
    -- s_out := recBody ... witness, giving 3 bullets:
    --   (1) length, (2) s_out.pi = 256, (3) the rest (dst-eq ∧ h_wf ∧ wfpoly).
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · -- length
      rw [hsome_back, hit2_eq]
      exact hback_len iter hi_pe
    · -- s_out.pi = 256 (after rewriting orig_slice.length - iter.i = 0)
      rw [hi_eq, Nat.sub_self]
      simp only [Bridges.DecodeDecompressState.recBody, List.range_zero, List.foldl_nil]
      rw [h_pi_eq]; exact h_iter_i_256
    · -- iter'.slice.val[j].val = (recBody ...).dst.getD j 0
      rw [hi_eq, Nat.sub_self]
      simp only [Bridges.DecodeDecompressState.recBody, List.range_zero, List.foldl_nil]
      intro j h_j
      simp only [hsome_back, hit2_eq] at h_j ⊢
      have h_j_lt_iter : j < iter.i := by
        have h_len := hback_len iter hi_pe
        rw [hi_eq]
        have : (back iter).slice.length = orig_slice.length := h_len
        omega
      exact hback_writes iter hi_pe j h_j_lt_iter
    · -- h_wf: vacuous since s_in.pi = 256
      intro k h_k h_k2; rw [h_pi_eq, h_iter_i_256] at h_k; omega
    · -- Universal wfPoly: derive via hback_writes + h_s_in_dst_wf (at NONE
      --   branch, iter.i = orig_slice.length, so all positions are < iter.i
      --   and hback_writes applies for the entire range).
      intro j h_j
      simp only [hsome_back, hit2_eq] at h_j ⊢
      have h_back_len_eq : (back iter).slice.length = orig_slice.length :=
        hback_len iter hi_pe
      have h_j_lt_iter : j < iter.i := by
        rw [hi_eq]; rw [h_back_len_eq] at h_j; exact h_j
      have hw := hback_writes iter hi_pe j h_j_lt_iter
      rw [hw]
      exact h_s_in_dst_wf j (by rw [← h_iter_i]; exact h_j_lt_iter)
  termination_by iter.slice.len.val - iter.i
  decreasing_by all_goals decreasing_by_preprocess; agrind

/-- **Top spec for `poly_element_decode_and_decompress`** — full FC.

On `NoError`, the result polynomial equals
`decodeDecompressPoly d (sliceToSpecBytes pb_src)`.
On `InvalidBlob` (only possible at `d = 12`): the input had a
coefficient ≥ `q`.

  **Informal proof.**
  `unfold mlkem.ntt.poly_element_decode_and_decompress; step*` through
  the IterMut setup over `pe_dst.val`.  Then `step with
  mlkem.ntt.poly_element_decode_and_decompress_loop0.spec` instantiating
  `s_in := DecodeDecompressState.init d (pb_src.val.map (·.bv))`
  (the source-aware initial state — `pb_src` content is read at
  `body`-time via `loadLEWord`, so `init`'s `src` must hold the actual
  source bytes; `dst` starts at all-zeros).

  The `matchesRuntime` precondition holds reflexively at entry:
  `s_in.src = pb_src.val.map (·.bv)` ⇒ `src[k] = pb_src[k].bv`,
  `si = 0 = cb_src_read.val`, `acci = 0`, `acc = 0`, `dst.length = 256`,
  `pi = 0` (no slots written yet, so the `∀ k < 0` is vacuous).

  The loop post then gives `s_out = recBody d s_in 256` and
  `s_out.pi = 256` and `(iter'.slice.val[j]).val = s_out.dst.getD j 0`.

  **Bridge 1 application**: by
  `streamDecodeDecompressPoly_eq.spec d (pb_src.val.map (·.bv)) h_d
    h_src_len`,
  `streamDecodeDecompressPoly d (pb_src.val.map (·.bv))
     = (decodeDecompressPoly d B h_d).toList.map ZMod.val`
  where `B = Vector.ofFn (...)`.  By construction
  `s_out.dst = streamDecodeDecompressPoly d (pb_src.val.map (·.bv))`,
  so each `(iter'.slice.val[j]).val = (decodeDecompressPoly d B h_d).get j |>.val`.
  Converting `iter'.slice` to `toPoly pe_dst'` (the polynomial after
  IterMut's writebacks) — at each j, `pe_dst'.val[j].val` equals
  `(iter'.slice.val[j]).val` by IterMut framing — yields exactly the
  FIPS output.

  - `wfPoly pe_dst'`: each written coefficient `y = coeffFromDecode d v`
    satisfies `y < q` (because `coeffFromDecode d v = if d < 12 then
    fastDecompress d v else v`, and for `d = 12` the validation
    `_some_body.spec` returns `InvalidBlob` if `v ≥ q`).
  - `InvalidBlob`: `d = 12` from loop post; `agrind`.
  - `h_src_len`: `pb_src.length = 32 * d` from `h_len` + `agrind`. -/
@[step]
theorem mlkem.ntt.poly_element_decode_and_decompress.spec
    (pb_src : Slice U8) (n_bits_per_coefficient : U32)
    (pe_dst : PolyElement)
    (h_d : 1 ≤ n_bits_per_coefficient.val ∧ n_bits_per_coefficient.val ≤ 12)
    (h_len : 32 * n_bits_per_coefficient.val ≤ pb_src.length)
    (h_wf_pe : wfPoly pe_dst) :
    mlkem.ntt.poly_element_decode_and_decompress pb_src n_bits_per_coefficient pe_dst
      ⦃ err pe_dst' =>
          wfPoly pe_dst' ∧
          (match err with
          | Error.NoError =>
              ∃ (_h_window : 32 * n_bits_per_coefficient.val ≤ pb_src.length),
                toPoly pe_dst' =
                  decodeDecompressPoly n_bits_per_coefficient.val
                    (sliceWindowToSpecBytes pb_src 0
                        (32 * n_bits_per_coefficient.val) (by omega))
                    ⟨h_d.1, h_d.2⟩ ∧
                (∀ (i : ℕ) (_h_i : i < 256),
                  Bridges.dBitSegment n_bits_per_coefficient.val
                      (sliceWindowToSpecBytes pb_src 0
                          (32 * n_bits_per_coefficient.val) (by omega))
                      i < MLKEM.m n_bits_per_coefficient.val)
          | Error.InvalidBlob => n_bits_per_coefficient.val = 12
          | _ => False) ⦄ := by
  unfold mlkem.ntt.poly_element_decode_and_decompress
  step*
  case s_in =>
    exact Bridges.DecodeDecompressState.init n_bits_per_coefficient.val
            ((pb_src.val.take (32 * n_bits_per_coefficient.val)).map (·.bv))
  case pe_dst_ghost => exact pe_dst
  case h_match =>
    -- All 12 conjuncts of matchesRuntime at the init state:
    --   src = (pb_src.val.take (32*d)).map (·.bv), si = 0, acci = 0, acc = 0,
    --   pi = 0, dst.length = 256, vacuous tails.  `matchesRuntime`
    --   requires `s.src.length = 32 * d` and per-position byte equality
    --   up to `32 * d` — exactly what the `take`-truncated init list
    --   provides.
    have h_len' : 32 * n_bits_per_coefficient.val ≤ pb_src.val.length := by
      simpa [Slice.length] using h_len
    unfold Bridges.DecodeDecompressState.matchesRuntime Bridges.DecodeDecompressState.init
    refine ⟨?_, ?_, rfl, ?_, rfl, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · -- (take (32*d) map).length = 32*d
      simp only [List.length_map, List.length_take]
      exact Nat.min_eq_left h_len'
    · -- pointwise byte equality for k < 32*d (and hence < pb_src.val.length)
      intro k h_k
      have h_k_pb : k < pb_src.val.length := lt_of_lt_of_le h_k h_len'
      have h_k_take : k < (pb_src.val.take (32 * n_bits_per_coefficient.val)).length := by
        rw [List.length_take]; exact lt_min h_k h_k_pb
      have h_k_map :
          k < ((pb_src.val.take (32 * n_bits_per_coefficient.val)).map (·.bv)).length := by
        rw [List.length_map]; exact h_k_take
      rw [List.getD_eq_getElem _ _ h_k_map, List.getD_eq_getElem _ _ h_k_pb,
          List.getElem_map, List.getElem_take]
    · scalar_tac
    · scalar_tac
    · rfl
    · -- bit-conservation at init: 8 * 0 = 0 * d + 0.
      simp
    · intro j _; simp [BitVec.getLsbD]
    · -- acc_match at init: vacuous since acci = 0.
      intro j h_j; exact (Nat.not_lt_zero _ h_j).elim
    · simp
    · intros k h_k; exact (Nat.not_lt_zero _ h_k).elim
  case h_iter_i =>
    -- iter.i = 0 = pi(init) = 0
    simp only [iter_post2, Bridges.DecodeDecompressState.init]
  case h_len_inv =>
    -- length_inv d (init d src) 0 : 32*d ≤ src.length ∧ dst.length=256 ∧ 0≤256 ∧ pi=0 ∧ 8*si=0 ∧ acci≤31
    have h_len' : 32 * n_bits_per_coefficient.val ≤ pb_src.val.length := by
      simpa [Slice.length] using h_len
    unfold Bridges.DecodeDecompressState.length_inv Bridges.DecodeDecompressState.init
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
    · -- 32 * d ≤ ((take (32*d) ⊕ map)).length — exact equality by min_eq_left.
      simp only [List.length_map, List.length_take]
      rw [Nat.min_eq_left h_len']
    · simp []
    · simp [iter_post2]
    · simp [iter_post2]
    · simp [iter_post2]
    · simp
  case hback_writes =>
    intro im him j hj
    simp [iter_post2] at hj
  case h_orig_wf =>
    -- orig_slice = iter.slice = s = pe_dst (as lists); wfPoly pe_dst gives the bound.
    intro j h_j
    have h_s_pe : s.val = pe_dst.val := s_post1
    have h_s_len_eq : s.length = pe_dst.val.length := by
      show s.val.length = pe_dst.val.length; rw [h_s_pe]
    have h_j_pe : j < pe_dst.val.length := by rw [← h_s_len_eq]; exact h_j
    have h_idx : (s.val[j]'(by rw [show s.val.length = s.length from rfl, h_s_len_eq]; exact h_j_pe))
                  = pe_dst.val[j]'h_j_pe := by
      have : s.val[j]? = pe_dst.val[j]? := by rw [h_s_pe]
      have h1 := List.getElem?_eq_getElem (l := s.val) (i := j)
                  (by rw [show s.val.length = s.length from rfl]; exact h_j)
      have h2 := List.getElem?_eq_getElem (l := pe_dst.val) (i := j) h_j_pe
      have := h1.symm.trans this
      rw [h2] at this; exact Option.some.inj this
    have h_pe_dst_len' : pe_dst.val.length = 256 := by
      have := pe_dst.property; scalar_tac
    have h_j_lt_256 : j < 256 := h_pe_dst_len' ▸ h_j_pe
    have h_q := h_wf_pe j h_j_lt_256
    have : (s.val[j]'(by rw [show s.val.length = s.length from rfl, h_s_len_eq]; exact h_j_pe)).val
              = (pe_dst.val[j]'h_j_pe).val := by rw [h_idx]
    -- The goal references orig_slice (= s); rewrite via this.
    show _ < q
    rw [this]; exact h_q
  case h_s_in_dst_wf =>
    -- s_in = init d src_bits has pi = 0, so the precondition is vacuous.
    intro k h_k
    simp [Bridges.DecodeDecompressState.init] at h_k
  -- Discharge final FC equality.
  -- After step*, three goals: (a) overflow `d * 32 ≤ U32.max`, (b) post-loop
  -- massert `cb_dst_written = ?`, (c) FC.  But here the loop returns
  -- (e, back) so the chain is simpler than Compress.  The _loop0.spec post
  -- has 3 outer conjuncts (length ∧ match ∧ wfpoly), so step* exposes
  -- e_post1/e_post2/e_post3.
  rename_i e back e_post1 e_post2 e_post3
  -- Bridge lengths.  After the new spec sig, `orig_slice` was discharged
  -- to `iter.slice` which was unified with `s` via `iter_post1`, so the
  -- post mentions `s.length`, not `iter.slice.length`.
  have h_pe_dst_len : pe_dst.val.length = 256 := by
    have := pe_dst.property; scalar_tac
  have h_s_len : s.length = 256 := by
    show s.val.length = 256
    rw [s_post1]; exact h_pe_dst_len
  have h_iter_len : iter.slice.length = 256 := by
    rw [iter_post1]; exact h_s_len
  have h_back_len : back.slice.length = 256 := by rw [e_post1]; exact h_s_len
  have h_back_val_len : back.slice.val.length = 256 := h_back_len
  have h_s_diff : s.length - iter.i = 256 := by
    rw [h_s_len, iter_post2, Nat.sub_zero]
  have h_from_val : (Aeneas.Std.Array.from_slice pe_dst back.slice).val = back.slice.val :=
    Aeneas.Std.Array.from_slice_val pe_dst back.slice h_back_val_len
  -- Source list (Bridge 1 form).  Take-truncated to length 32*d, since the
  -- relaxed per-poly spec admits `pb_src.length ≥ 32*d` (with equality
  -- being the common-case fast path).  matchesRuntime's init used the
  -- same take-truncated list (see `case s_in` above).
  have h_len' : 32 * n_bits_per_coefficient.val ≤ pb_src.val.length := by
    simpa [Slice.length] using h_len
  set src_bits := (pb_src.val.take (32 * n_bits_per_coefficient.val)).map (·.bv)
    with src_bits_def
  have h_src_bits_len : src_bits.length = 32 * n_bits_per_coefficient.val := by
    simp only [src_bits, List.length_map, List.length_take]
    exact Nat.min_eq_left h_len'
  -- s_out via recBody at i=256.
  set s_out := Bridges.DecodeDecompressState.recBody n_bits_per_coefficient.val
                (Bridges.DecodeDecompressState.init n_bits_per_coefficient.val src_bits) 256
    with s_out_def
  rw [h_s_diff] at e_post2
  -- Rewrite the goal's `to_slice_mut_back (iter_mut_back back)` to the canonical form.
  simp only [iter_post3, s_post2]
  -- Universal wfPoly derivation — from e_post3 (∀ j, back.slice.val[j] < q), bridge
  -- to wfPoly (from_slice pe_dst back.slice).
  have h_wfpoly_dst : wfPoly (Aeneas.Std.Array.from_slice pe_dst back.slice) := by
    intro i hi
    have hi_back : i < back.slice.val.length := by rw [h_back_val_len]; exact hi
    have h_idx : (Aeneas.Std.Array.from_slice pe_dst back.slice).val[i]'
          (by rw [h_from_val]; exact hi_back) = back.slice.val[i]'hi_back := by
      fcongr 1
    rw [h_idx]
    exact e_post3 i hi_back
  refine ⟨h_wfpoly_dst, ?_⟩
  -- Cases on the loop error.
  cases e with
  | InvalidBlob => simp at e_post2 ⊢; exact e_post2
  | NoError =>
    simp only at e_post2
    obtain ⟨h_pi_eq, h_back_dst, h_wf_post⟩ := e_post2
    -- Bridge 1 well-formedness premise: s_in = init has pi = 0, so the post's
    -- bound `s_in.pi ≤ k` is trivial; pass through with `Nat.zero_le _`.
    have h_wf : ∀ k, k < 256 →
        Bridges.fipsBitSum n_bits_per_coefficient.val src_bits k
          < MLKEM.m n_bits_per_coefficient.val := by
      intro k h_k
      exact h_wf_post k (Nat.zero_le _) h_k
    simp only
    -- toPoly equality, sliceWindowToSpecBytes form.
    -- The existential witness is h_len itself.
    refine ⟨h_len, ?_, ?_⟩
    · apply Vector.ext
      intro i hi
      unfold toPoly
      rw [Vector.getElem_ofFn]
      have hi_back : i < back.slice.val.length := by rw [h_back_val_len]; exact hi
      have hi_fs : i < (Aeneas.Std.Array.from_slice pe_dst back.slice).val.length := by
        rw [h_from_val]; exact hi_back
      have h_idx : (Aeneas.Std.Array.from_slice pe_dst back.slice).val[i]'hi_fs
            = back.slice.val[i]'hi_back := by
        fcongr 1
      rw [h_idx]
      have h_bd := h_back_dst i hi_back
      have h_stream : s_out.dst = streamDecodeDecompressPoly n_bits_per_coefficient.val src_bits := rfl
      have h_bridge :
          streamDecodeDecompressPoly n_bits_per_coefficient.val src_bits =
          (decodeDecompressPoly n_bits_per_coefficient.val
            (listToSpecBytes src_bits (32 * n_bits_per_coefficient.val) h_src_bits_len) h_d).toList.map
              ZMod.val :=
        streamDecodeDecompressPoly_eq.spec _ _ h_d h_src_bits_len h_wf
      -- Bridge listToSpecBytes (take.map ·.bv) = sliceWindowToSpecBytes pb_src 0 (32*d).
      have h_specbytes_eq :
          listToSpecBytes src_bits (32 * n_bits_per_coefficient.val) h_src_bits_len =
          sliceWindowToSpecBytes pb_src 0 (32 * n_bits_per_coefficient.val) (by omega) := by
        rw [sliceWindowToSpecBytes_full_eq_listToSpecBytes_take_map pb_src
              (32 * n_bits_per_coefficient.val) h_len]
      have h_dd_poly :
          decodeDecompressPoly n_bits_per_coefficient.val
              (listToSpecBytes src_bits (32 * n_bits_per_coefficient.val) h_src_bits_len) h_d =
          decodeDecompressPoly n_bits_per_coefficient.val
              (sliceWindowToSpecBytes pb_src 0 (32 * n_bits_per_coefficient.val) (by omega)) h_d := by
        rw [h_specbytes_eq]
      have h_dd_eq :
          (decodeDecompressPoly n_bits_per_coefficient.val
              (listToSpecBytes src_bits (32 * n_bits_per_coefficient.val) h_src_bits_len) h_d).toList =
          (decodeDecompressPoly n_bits_per_coefficient.val
              (sliceWindowToSpecBytes pb_src 0 (32 * n_bits_per_coefficient.val) (by omega)) h_d).toList :=
        congrArg Vector.toList h_dd_poly
      unfold u16ToZq
      have h_back_val : back.slice.val[i]'hi_back ∈ (Set.univ : Set U16) := Set.mem_univ _
      have h_val_eq : (back.slice.val[i]'hi_back).val =
          (((decodeDecompressPoly n_bits_per_coefficient.val
              (sliceWindowToSpecBytes pb_src 0 (32 * n_bits_per_coefficient.val) (by omega)) h_d).toList.map
              ZMod.val).getD i 0) := by
        rw [← h_dd_eq, ← h_bridge, ← h_stream]
        exact h_bd
      have h_len_map : ((decodeDecompressPoly n_bits_per_coefficient.val
            (sliceWindowToSpecBytes pb_src 0 (32 * n_bits_per_coefficient.val) (by omega)) h_d).toList.map
              ZMod.val).length = 256 := by simp [List.length_map]
      have h_i_lt_map : i < ((decodeDecompressPoly n_bits_per_coefficient.val
            (sliceWindowToSpecBytes pb_src 0 (32 * n_bits_per_coefficient.val) (by omega)) h_d).toList.map
              ZMod.val).length := by rw [h_len_map]; exact hi
      have h_i_lt_dd : i < (decodeDecompressPoly n_bits_per_coefficient.val
            (sliceWindowToSpecBytes pb_src 0 (32 * n_bits_per_coefficient.val) (by omega)) h_d).toList.length := by
        simp; exact hi
      rw [List.getD_eq_getElem _ _ h_i_lt_map] at h_val_eq
      rw [List.getElem_map] at h_val_eq
      rw [show ((decodeDecompressPoly n_bits_per_coefficient.val
            (sliceWindowToSpecBytes pb_src 0 (32 * n_bits_per_coefficient.val) (by omega)) h_d)[i]'hi) =
              (decodeDecompressPoly n_bits_per_coefficient.val
              (sliceWindowToSpecBytes pb_src 0 (32 * n_bits_per_coefficient.val) (by omega)) h_d).toList[i]'h_i_lt_dd
            from (Vector.getElem_toList _).symm]
      rw [h_val_eq]
      exact ZMod.natCast_zmod_val _
    · -- Canonicity conjunct: dBitSegment ... < MLKEM.m d, transferred from h_wf.
      intro i h_i
      have h_specbytes_eq :
          listToSpecBytes src_bits (32 * n_bits_per_coefficient.val) h_src_bits_len =
          sliceWindowToSpecBytes pb_src 0 (32 * n_bits_per_coefficient.val) (by omega) := by
        rw [sliceWindowToSpecBytes_full_eq_listToSpecBytes_take_map pb_src
              (32 * n_bits_per_coefficient.val) h_len]
      have h_bound : (i + 1) * n_bits_per_coefficient.val ≤ 8 * (32 * n_bits_per_coefficient.val) := by
        have h_d_le : n_bits_per_coefficient.val ≤ 12 := h_d.2
        have : (i + 1) * n_bits_per_coefficient.val ≤ 256 * n_bits_per_coefficient.val := by
          apply Nat.mul_le_mul_right; omega
        have h_8_32 : 8 * (32 * n_bits_per_coefficient.val) = 256 * n_bits_per_coefficient.val := by ring
        omega
      have h_bridge_eq :
          Bridges.fipsBitSum n_bits_per_coefficient.val src_bits i =
          Bridges.dBitSegment n_bits_per_coefficient.val
            (listToSpecBytes src_bits (32 * n_bits_per_coefficient.val) h_src_bits_len) i :=
        Bridges.fipsBitSum_eq_dBitSegment n_bits_per_coefficient.val
          src_bits h_src_bits_len i h_bound
      have h_wf_i := h_wf i h_i
      rw [h_bridge_eq] at h_wf_i
      rw [← h_specbytes_eq]
      exact h_wf_i
  | _ => exact e_post2.elim


end Symcrust.Properties.MLKEM
