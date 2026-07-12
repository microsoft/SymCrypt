/-
  # Encoding/Decompress.lean — Vector decode-and-decompress spec.

  The inner loop and outer loop + top specs are in `DecompressInner.lean`
  and `DecompressOuter.lean`.
-/
import Symcrust.Properties.MLKEM.Encoding.DecompressOuter

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust

open symcrust.common
namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

/-! ## Vector decompress

`vector_decode_and_decompress_loop` iterates over the `k`
polynomials, calling `poly_element_decode_and_decompress` on each
input slice; propagates first `Error.InvalidBlob` if encountered. -/

#decompose mlkem.ntt.vector_decode_and_decompress_loop
    vector_decode_and_decompress_loop.fold
  letRange 1 1 => vector_decode_and_decompress_loop_match

#decompose vector_decode_and_decompress_loop_match
    vector_decode_and_decompress_loop_match.fold
  branch 1 (letRange 0 6) => vector_decode_and_decompress_loop_some_body

/-! ## Note on body decomposition

The `some _` arm of `vector_decode_and_decompress_loop_match` has 6
monadic binds followed by an inner `match sc_error` whose `NoError`
arm carries the recursive call (and every other error arm wraps the
back-fn + error result).  The second `#decompose` above carves out
those 6 binds — `index_mut` + cast + arithmetic + slice index + the
per-poly `poly_element_decode_and_decompress` call — into
`vector_decode_and_decompress_loop_some_body`, which returns
`(index_mut_back, sc_error, pe_dst1)` for the parent's inner match.
The inner `match sc_error` and its trailing pure back-fn applications
(repeated across all error arms) intentionally stay in `_loop_match`:
the recursive call sits in the `NoError` arm of that match, so per the
`decompose-command` skill (Example 3 — "do NOT include the recursive
call in the extracted sub-expression") `letRange 0 7` (which would
absorb the whole some-arm including the inner match and the recursive
call) is structurally available but intentionally avoided.  An earlier
note here claimed `letRange 0 7` reports `out of range`; the actual
behaviour is that it is accepted but captures the recursion. -/

/-! The `#decompose` declaration and `_loop_match.fold` equation above
are consumed inside `vector_decode_and_decompress_loop.spec`'s proof
via the canonical Variant B pattern (see `proof-patterns` skill): the
loop dispatch and per-row `poly_element_decode_and_decompress` step are
inlined there, so no standalone `@[step]` spec is needed for `_loop_match`. -/

/-- **Per-row body spec** for `vector_decode_and_decompress_loop_some_body`.

This carves out the 6 monadic binds that the parent loop runs at every
iteration: `index_mut_usize`, cast, two multiplications, slice index
(producing the suffix `pb_src[i1*32*d ..]`), and the per-poly call.
The post packages everything the parent's `cases sc_error` dispatch
needs.

  **Informal proof.** `step` through `index_mut_back` (gives
  `back = pv_dst.set i1`); through the three arithmetic binds; through
  the slice-index step (gives `s.val = pb_src.val.drop pb_src_index.val`
  and `s.length = pb_src.length - pb_src_index.val`); through the
  per-poly call (gives the FC equation on `s`, which we bridge to the
  parent `pb_src` view via a local `Vector.ext` argument).  -/
@[step]
theorem mlkem.ntt.vector_decode_and_decompress_loop_some_body.spec
    (i : Usize) (pb_src : Slice U8) (n_bits_per_coefficient : U32)
    (pv_dst : Slice (PolyElement)) (i1 : Usize)
    (h_d : 1 ≤ n_bits_per_coefficient.val ∧ n_bits_per_coefficient.val ≤ 12)
    (h_i : i.val = (mlkem.key.MLWE_POLYNOMIAL_COEFFICIENTS.val) / 8)
    (h_i1_lt : i1.val < pv_dst.length)
    (h_win : (i1.val + 1) * (32 * n_bits_per_coefficient.val) ≤ pb_src.length)
    (h_wf_in : wfPolyVec pv_dst) :
    vector_decode_and_decompress_loop_some_body
        i pb_src n_bits_per_coefficient pv_dst i1
      ⦃ back err pe_dst1 =>
          back = pv_dst.set i1 ∧
          wfPoly pe_dst1 ∧
          (match err with
           | Error.NoError =>
               toPoly pe_dst1 =
                 decodeDecompressPoly n_bits_per_coefficient.val
                   (sliceWindowToSpecBytes pb_src
                     (i1.val * (32 * n_bits_per_coefficient.val))
                     (32 * n_bits_per_coefficient.val)
                     (Nat.add_one_mul _ _ ▸ h_win))
                   ⟨h_d.1, h_d.2⟩ ∧
               (∀ (i : ℕ) (_h_i : i < 256),
                 Bridges.dBitSegment n_bits_per_coefficient.val
                     (sliceWindowToSpecBytes pb_src
                       (i1.val * (32 * n_bits_per_coefficient.val))
                       (32 * n_bits_per_coefficient.val)
                       (Nat.add_one_mul _ _ ▸ h_win))
                     i < MLKEM.m n_bits_per_coefficient.val)
           | Error.InvalidBlob => n_bits_per_coefficient.val = 12
           | _ => False) ⦄ := by
  unfold vector_decode_and_decompress_loop_some_body
  -- index_mut_usize: extracts pv_dst[i1] and back-fn pv_dst.set i1.
  let* ⟨ pe_dst_in, back_in, h_pe_dst_in, h_back_in ⟩ ←
    _root_.Aeneas.Std.Slice.index_mut_usize_spec
  step  -- i2 := cast n_bits_per_coefficient
  step  -- i3 := i1 * i2
  step  -- pb_src_index := i3 * i
  -- Compute pb_src_index.val arithmetically; `step` left hypotheses
  -- `i2`, `i2_post`, `i3`, `i3_post`, `pb_src_index`, `pb_src_index_post`.
  have h_i2_val : i2.val = n_bits_per_coefficient.val := by
    rw [i2_post]; simp
  have h_i3_val : i3.val = i1.val * n_bits_per_coefficient.val := by
    rw [i3_post, h_i2_val]
  have h_i_val : i.val = 32 := by
    rw [h_i, show (mlkem.key.MLWE_POLYNOMIAL_COEFFICIENTS.val) / 8 = 32 from by
      simp [mlkem.key.MLWE_POLYNOMIAL_COEFFICIENTS]]
  have h_pbi_val : pb_src_index.val
      = i1.val * (32 * n_bits_per_coefficient.val) := by
    rw [pb_src_index_post, h_i3_val, h_i_val]; ring
  -- Slice index (RangeFrom): produces a suffix `s` of `pb_src`.
  have h_pbi_le : pb_src_index.val ≤ pb_src.length := by
    have h_step : (i1.val + 1) * (32 * n_bits_per_coefficient.val)
                = i1.val * (32 * n_bits_per_coefficient.val)
                  + 32 * n_bits_per_coefficient.val := by ring
    have h_d_pos : 1 ≤ 32 * n_bits_per_coefficient.val := by
      have := h_d.1; omega
    omega
  let* ⟨ s, h_s_val, h_s_len ⟩ ←
    _root_.Aeneas.Std.core.slice.index.SliceIndexRangeFromUsizeSlice.index.step_spec
  -- s.length ≥ 32 * d, suitable for the per-poly spec.
  have h_s_len_ge : 32 * n_bits_per_coefficient.val ≤ s.length := by
    rw [h_s_len, h_pbi_val]
    have h_step : (i1.val + 1) * (32 * n_bits_per_coefficient.val)
                = i1.val * (32 * n_bits_per_coefficient.val)
                  + 32 * n_bits_per_coefficient.val := by ring
    omega
  -- Per-poly call.  Discharge new h_wf_pe from h_wf_in.
  have h_wf_row : wfPoly (pe_dst_in) := by
    rw [h_pe_dst_in]
    exact h_wf_in i1.val h_i1_lt
  step with mlkem.ntt.poly_element_decode_and_decompress.spec
  -- Final `pure`: rebuilds the (back, err, pe_dst1) tuple.
  refine ⟨h_back_in, ?_⟩
  -- Bridge per-poly's window-on-s to window-on-pb_src.
  have h_arith : i1.val * (32 * n_bits_per_coefficient.val)
                 + 32 * n_bits_per_coefficient.val ≤ pb_src.length := by
    have h_step : (i1.val + 1) * (32 * n_bits_per_coefficient.val)
                = i1.val * (32 * n_bits_per_coefficient.val)
                  + 32 * n_bits_per_coefficient.val := by ring
    omega
  have h_bridge :
      sliceWindowToSpecBytes s 0 (32 * n_bits_per_coefficient.val) (by omega)
        = sliceWindowToSpecBytes pb_src
            (i1.val * (32 * n_bits_per_coefficient.val))
            (32 * n_bits_per_coefficient.val) h_arith := by
    unfold sliceWindowToSpecBytes
    apply Vector.ext
    intro k h_k
    simp only [Vector.getElem_ofFn]
    have h_k_lt : k < 32 * n_bits_per_coefficient.val := h_k
    have h_pb_len : pb_src.val.length = pb_src.length := rfl
    have h_drop_len : k < (pb_src.val.drop pb_src_index.val).length := by
      rw [List.length_drop, h_pb_len]; omega
    have h_pb_idx_in : i1.val * (32 * n_bits_per_coefficient.val) + k
                     < pb_src.val.length := by
      rw [h_pb_len]; omega
    have h_s_val_len : s.val.length = pb_src.length - pb_src_index.val :=
      h_s_len
    have h_k_in_s : 0 + k < s.val.length := by
      rw [h_s_val_len, h_pbi_val]; omega
    -- s.val[k] = (pb_src.val.drop pb_src_index.val)[k] = pb_src.val[pb_src_index.val + k]
    have h1 : s.val[0 + k]'h_k_in_s
            = (pb_src.val.drop pb_src_index.val)[k]'h_drop_len := by
      simp [getElem_congr_coll h_s_val]
    have h2 :
        s.val[0 + k]'h_k_in_s
        = pb_src.val[i1.val * (32 * n_bits_per_coefficient.val) + k]'h_pb_idx_in := by
      rw [h1, List.getElem_drop]
      apply getElem_congr_idx
      omega
    rw [h2]
  -- The per-poly post is now `wfPoly pe_dst1 ∧ match err with ...`.
  -- Extract wfPoly universally, then case-split on sc_error.
  refine ⟨sc_error_post1, ?_⟩
  cases sc_error with
  | NoError =>
    obtain ⟨h_window_pre, h_eq, h_canon⟩ := sc_error_post2
    refine ⟨?_, ?_⟩
    · rw [h_eq, h_bridge]
    · intro i h_i
      rw [← h_bridge]
      exact h_canon i h_i
  | InvalidBlob => exact sc_error_post2
  | _ => exact sc_error_post2.elim

/-- **Loop spec** for `vector_decode_and_decompress_loop` — streaming FC.

After processing slots `[i_done, k)`, every row of `pv_dst'` in that
range matches `decodeDecompressPoly d` of its `32·d`-byte source
window; earlier rows are unchanged.

**Reshape (2026 Track 2 / Tier 1, Decompress side)**: `wfPolyVec pv_dst'`
is now claimed **universally** (out of the `match err`), so the KSV
caller (`KeySetValue.lean`) can recover `wfPolyVec` regardless of the
result tag.  The implementation rejects the offending coefficient
BEFORE the store (`mlkem/ntt.rs:798-806`), so on InvalidBlob the
already-overwritten slots are wfPoly-valid and trailing slots retain
the input's `wfPoly`.  At the wrapper call site `iter.start = 0`, the
frame on [0, iter.start) is vacuous, so the input `wfPolyVec pv_dst`
threads directly to the output.

  **Informal proof.** Canonical recursive loop (`proof-patterns`
  "Loop — Canonical Template", Variant B). No separate
  `_loop_match.spec` is needed: the match dispatch is inlined.

  - **Mandatory first step**: `rw [vector_decode_and_decompress_loop.fold]`
    to expose `<loop>_match` under the let-binder. Do NOT use `unfold
    mlkem.ntt.vector_decode_and_decompress_loop`. After the `(next iter)` step is consumed, `rw
    [vector_decode_and_decompress_loop_match.fold]` to expose the
    per-row helper call.
  - `step` to consume `next iter` (Range iterator → `o, iter1`).
  - `cases o`:
    - **`none` arm** (Range exhausted): `pv_dst' = pv_dst`; frame
      clauses vacuously hold; the per-row FC `∀ j, iter.start.val ≤ j
      < iter.end.val → …` is vacuous because the range is empty;
      `wfPolyVec pv_dst'` ⇐ `h_wf_in`; `agrind`.
    - **`some i_val` arm**: `rw
      [vector_decode_and_decompress_loop_match.fold]` exposes the
      per-row helper.  `step` consumes
      `vector_decode_and_decompress_loop_some_body.spec` (a separate
      `@[step]` theorem to be written; its post calls
      `mlkem.ntt.poly_element_decode_and_decompress.spec`
      internally) for row `i_val.val` over source window
      `[i_val.val * 32 * d, (i_val.val + 1) * 32 * d)` of `pb_src`,
      yielding `(index_mut_back, sc_error, pe_dst1)`.  The per-poly
      spec (also reshaped — see L416 below) yields `wfPoly pe_dst'`
      on BOTH NoError and InvalidBlob arms.  `cases sc_error`
      dispatches the 24 error arms (each is a `let s1 :=
      index_mut_back pe_dst1; ok (…, s1)` except `NoError` which
      recurses via the IH at `iter.start' = iter.start + 1`).
      `wfPolyVec` is preserved because (a) entries before
      `iter.start` are unchanged (frame), (b) entries in
      `[iter.start, iter.start')` are valid from the body, (c)
      entries beyond are unchanged.
  - `termination_by iter.end.val - iter.start.val`;
    `decreasing_by scalar_decr_tac`. -/
@[step]
theorem mlkem.ntt.vector_decode_and_decompress_loop.spec
    (i : Usize) (iter : core.ops.range.Range Usize)
    (pb_src : Slice U8) (n_bits_per_coefficient : U32)
    (pv_dst : Slice (PolyElement))
    (h_d : 1 ≤ n_bits_per_coefficient.val ∧ n_bits_per_coefficient.val ≤ 12)
    (h_i : i.val = (mlkem.key.MLWE_POLYNOMIAL_COEFFICIENTS.val) / 8)
    (h_len : pb_src.length =
             pv_dst.length * (n_bits_per_coefficient.val * 32))
    /- Iterator end bounded by `pv_dst.length`.  Threaded so the
       SOME-branch can derive `iter.start.val < pv_dst.length` from
       `hlt : iter.start.val < iter.end.val`.  At the wrapper call
       site, `iter.end = pv_dst.len`, so this holds with equality. -/
    (h_iter_end : iter.«end».val ≤ pv_dst.length)
    /- Input vector well-formedness — threaded through both result arms
       so downstream KSV callers can recover `wfPolyVec pv_dst'`
       universally.  See reshape rationale in the docstring above. -/
    (h_wf_in : wfPolyVec pv_dst) :
    mlkem.ntt.vector_decode_and_decompress_loop
        i iter pb_src n_bits_per_coefficient pv_dst
      ⦃ err pv_dst' =>
          pv_dst'.length = pv_dst.length ∧
          (∀ (j : Nat) (h_j : j < pv_dst'.length) (h_j' : j < pv_dst.length),
              j < iter.start.val → (pv_dst'.val[j]'h_j) = (pv_dst.val[j]'h_j')) ∧
          /- Universal `wfPolyVec` — lifted out of the match (Tier 1
             reshape).  Holds on both NoError and InvalidBlob arms. -/
          wfPolyVec pv_dst' ∧
          (match err with
           | Error.NoError =>
               (∀ (j : Nat) (_h_j : iter.start.val ≤ j ∧ j < iter.«end».val)
                 (h_j' : j < pv_dst'.length),
                  ∃ (h_src_window :
                      (j + 1) * (32 * n_bits_per_coefficient.val) ≤ pb_src.length),
                  toPoly (pv_dst'.val[j]'h_j')
                    = decodeDecompressPoly n_bits_per_coefficient.val
                        (sliceWindowToSpecBytes pb_src
                          (j * (32 * n_bits_per_coefficient.val))
                          (32 * n_bits_per_coefficient.val)
                          (Nat.add_one_mul _ _ ▸ h_src_window))
                        ⟨h_d.1, h_d.2⟩ ∧
                  (∀ (i : ℕ) (_h_i : i < 256),
                    Bridges.dBitSegment n_bits_per_coefficient.val
                        (sliceWindowToSpecBytes pb_src
                          (j * (32 * n_bits_per_coefficient.val))
                          (32 * n_bits_per_coefficient.val)
                          (Nat.add_one_mul _ _ ▸ h_src_window))
                        i < MLKEM.m n_bits_per_coefficient.val))
           | Error.InvalidBlob => n_bits_per_coefficient.val = 12
           | _ => False) ⦄ := by
  -- Range loop over the polynomial-vector rows: each iteration decodes and
  -- decompresses one polynomial from its `32*d`-byte window of `pb_src` via
  -- `poly_element_decode_and_decompress.spec`, accumulating into `pv_dst`
  -- and preserving `wfPolyVec`.  Error arms short-circuit; the NoError arm
  -- recurses on the next row.
  rw [vector_decode_and_decompress_loop.fold]
  by_cases hlt : iter.start.val < iter.«end».val
  · -- SOME branch: process one row, then recurse.
    let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← IteratorRange_next_some
    rw [hsome]
    rw [vector_decode_and_decompress_loop_match.fold]
    simp only
    -- Derive preconditions for `_some_body.spec`.
    have h_i1_lt : iter.start.val < pv_dst.length := by
      have := hlt; omega
    have h_win : (iter.start.val + 1) * (32 * n_bits_per_coefficient.val)
                 ≤ pb_src.length := by
      rw [h_len]
      have h_le : iter.start.val + 1 ≤ pv_dst.length := by omega
      calc (iter.start.val + 1) * (32 * n_bits_per_coefficient.val)
          = (iter.start.val + 1) * (n_bits_per_coefficient.val * 32) := by ring
        _ ≤ pv_dst.length * (n_bits_per_coefficient.val * 32) :=
            Nat.mul_le_mul_right _ h_le
    step with mlkem.ntt.vector_decode_and_decompress_loop_some_body.spec
      i pb_src n_bits_per_coefficient pv_dst iter.start
      h_d h_i h_i1_lt h_win h_wf_in
    -- After step, the names exposed are:
    --   index_mut_back, sc_error, pe_dst1 (the binders)
    --   index_mut_back_post1 : index_mut_back = pv_dst.set iter.start
    --   index_mut_back_post2 : wfPoly pe_dst1
    --   index_mut_back_post3 : match sc_error with NoError => FC | InvalidBlob => d=12 | _ => False
    -- Rewrite `index_mut_back` to `pv_dst.set iter.start` everywhere in the goal,
    -- so every `index_mut_back pe_dst1` becomes `pv_dst.set iter.start pe_dst1`.
    rw [index_mut_back_post1]
    -- key length fact for `pv_dst.set iter.start pe_dst1`
    have h_set_len : (pv_dst.set iter.start pe_dst1).val.length = pv_dst.val.length := by
      simp [Slice.set_val_eq, List.length_set]
    have h_set_get_at :
        (pv_dst.set iter.start pe_dst1).val[iter.start.val]'(h_set_len ▸ h_i1_lt)
          = pe_dst1 := by
      simp [Slice.set_val_eq, List.getElem_set_self]
    have h_set_get_other :
        ∀ j (h_j : j < (pv_dst.set iter.start pe_dst1).val.length), j ≠ iter.start.val →
          (pv_dst.set iter.start pe_dst1).val[j]'h_j
            = pv_dst.val[j]'(h_set_len ▸ h_j) := by
      intros j h_j hne
      simp [Slice.set_val_eq, List.getElem_set_ne (Ne.symm hne)]
    have h_wf_s1 : wfPolyVec (pv_dst.set iter.start pe_dst1) := by
      intros k h_k
      by_cases hk_eq : k = iter.start.val
      · subst hk_eq
        rw [h_set_get_at]
        exact index_mut_back_post2
      · rw [h_set_get_other k h_k hk_eq]
        have h_k' : k < pv_dst.length := by
          show k < pv_dst.val.length
          rw [← h_set_len]; exact h_k
        exact h_wf_in k h_k'
    cases sc_error with
    | NoError =>
      -- Recurse via IH at iter1.start = iter.start + 1.
      have h_iter1_end : iter1.«end».val ≤ (pv_dst.set iter.start pe_dst1).length := by
        show iter1.«end».val ≤ (pv_dst.set iter.start pe_dst1).val.length
        rw [h_set_len, hend']; exact h_iter_end
      have h_len1 : pb_src.length
                    = (pv_dst.set iter.start pe_dst1).length
                      * (n_bits_per_coefficient.val * 32) := by
        show pb_src.length = (pv_dst.set iter.start pe_dst1).val.length * _
        rw [h_set_len]; exact h_len
      apply WP.spec_mono
        (mlkem.ntt.vector_decode_and_decompress_loop.spec i iter1 pb_src
          n_bits_per_coefficient (pv_dst.set iter.start pe_dst1)
          h_d h_i h_len1 h_iter1_end h_wf_s1)
      rintro res ⟨h_res_len, h_res_frame, h_res_wf, h_res_match⟩
      refine ⟨?_, ?_, h_res_wf, ?_⟩
      · -- length: res.length = pv_dst.length
        show res.2.val.length = pv_dst.val.length
        rw [← h_set_len]; exact h_res_len
      · -- frame on j < iter.start.val: chain through res = set
        intro j h_j h_j' h_j_lt
        have h_j_s1 : j < (pv_dst.set iter.start pe_dst1).val.length := by
          rw [h_set_len]; exact h_j'
        have h_j_lt_iter1 : j < iter1.start.val := by rw [hstart']; omega
        have h_pv_eq_s1 := h_res_frame j h_j h_j_s1 h_j_lt_iter1
        have hne : j ≠ iter.start.val := by omega
        rw [h_pv_eq_s1]; exact h_set_get_other j h_j_s1 hne
      · -- third bullet: match res.1 with ... — dispatch by res.1 explicitly
        cases hres : res.1 with
        | NoError =>
          rw [hres] at h_res_match
          -- h_res_match now : ∀ j ∈ [iter1.start, iter1.end), FC
          rintro j hj_lo hj_hi h_j_dst'
          have hj_lt_pv : j < pv_dst.length := by
            have : j < iter.«end».val := hj_hi
            omega
          have h_j_s1 : j < (pv_dst.set iter.start pe_dst1).val.length := by
            show j < (pv_dst.set iter.start pe_dst1).val.length
            rw [h_set_len]; exact hj_lt_pv
          by_cases hj_eq : j = iter.start.val
          · -- j = iter.start.val: pe_dst1's FC, transported through frame.
            subst hj_eq
            have h_lt_iter1 : iter.start.val < iter1.start.val := by rw [hstart']; omega
            have h_pv_eq_s1 := h_res_frame iter.start.val h_j_dst' h_j_s1 h_lt_iter1
            -- index_mut_back_post3 now bundles toPoly equality + canonicity
            obtain ⟨h_toPoly_eq, h_canon⟩ := index_mut_back_post3
            refine ⟨h_win, ?_, ?_⟩
            · rw [h_pv_eq_s1, h_set_get_at]
              exact h_toPoly_eq
            · intro i h_i
              exact h_canon i h_i
          · -- j ≠ iter.start.val: use IH's NoError match.
            have hj_lo' : iter1.start.val ≤ j := by rw [hstart']; omega
            have hj_hi' : j < iter1.«end».val := by rw [hend']; exact hj_hi
            exact h_res_match j ⟨hj_lo', hj_hi'⟩ h_j_dst'
        | InvalidBlob =>
          rw [hres] at h_res_match; exact h_res_match
        | Unused => rw [hres] at h_res_match; exact h_res_match.elim
        | WrongKeySize => rw [hres] at h_res_match; exact h_res_match.elim
        | WrongBlockSize => rw [hres] at h_res_match; exact h_res_match.elim
        | WrongDataSize => rw [hres] at h_res_match; exact h_res_match.elim
        | WrongNonceSize => rw [hres] at h_res_match; exact h_res_match.elim
        | WrongTagSize => rw [hres] at h_res_match; exact h_res_match.elim
        | WrongIterationCount => rw [hres] at h_res_match; exact h_res_match.elim
        | AuthenticationFailure => rw [hres] at h_res_match; exact h_res_match.elim
        | ExternalFailure => rw [hres] at h_res_match; exact h_res_match.elim
        | FipsFailure => rw [hres] at h_res_match; exact h_res_match.elim
        | HardwareFailure => rw [hres] at h_res_match; exact h_res_match.elim
        | NotImplemented => rw [hres] at h_res_match; exact h_res_match.elim
        | BufferTooSmall => rw [hres] at h_res_match; exact h_res_match.elim
        | InvalidArgument => rw [hres] at h_res_match; exact h_res_match.elim
        | MemoryAllocationFailure => rw [hres] at h_res_match; exact h_res_match.elim
        | SignatureVerificationFailure => rw [hres] at h_res_match; exact h_res_match.elim
        | IncompatibleFormat => rw [hres] at h_res_match; exact h_res_match.elim
        | ValueTooLarge => rw [hres] at h_res_match; exact h_res_match.elim
        | SessionReplayFailure => rw [hres] at h_res_match; exact h_res_match.elim
        | HbsNoOtsKeysLeft => rw [hres] at h_res_match; exact h_res_match.elim
        | HbsPublicRootMismatch => rw [hres] at h_res_match; exact h_res_match.elim
    | InvalidBlob =>
      simp only [WP.spec_ok]
      refine ⟨?_, ?_, h_wf_s1, index_mut_back_post3⟩
      · -- length
        show (pv_dst.set iter.start pe_dst1).val.length = pv_dst.val.length
        exact h_set_len
      · -- frame: set only changes iter.start, leaves j < iter.start untouched
        intro j h_j h_j' h_j_lt
        have hne : j ≠ iter.start.val := by omega
        exact h_set_get_other j h_j hne
    | Unused => exact index_mut_back_post3.elim
    | WrongKeySize => exact index_mut_back_post3.elim
    | WrongBlockSize => exact index_mut_back_post3.elim
    | WrongDataSize => exact index_mut_back_post3.elim
    | WrongNonceSize => exact index_mut_back_post3.elim
    | WrongTagSize => exact index_mut_back_post3.elim
    | WrongIterationCount => exact index_mut_back_post3.elim
    | AuthenticationFailure => exact index_mut_back_post3.elim
    | ExternalFailure => exact index_mut_back_post3.elim
    | FipsFailure => exact index_mut_back_post3.elim
    | HardwareFailure => exact index_mut_back_post3.elim
    | NotImplemented => exact index_mut_back_post3.elim
    | BufferTooSmall => exact index_mut_back_post3.elim
    | InvalidArgument => exact index_mut_back_post3.elim
    | MemoryAllocationFailure => exact index_mut_back_post3.elim
    | SignatureVerificationFailure => exact index_mut_back_post3.elim
    | IncompatibleFormat => exact index_mut_back_post3.elim
    | ValueTooLarge => exact index_mut_back_post3.elim
    | SessionReplayFailure => exact index_mut_back_post3.elim
    | HbsNoOtsKeysLeft => exact index_mut_back_post3.elim
    | HbsPublicRootMismatch => exact index_mut_back_post3.elim
  · -- NONE branch: iterator exhausted.
    let* ⟨ o, iter1, hnone, _hiter_eq ⟩ ← IteratorRange_next_none (by omega)
    rw [hnone]
    rw [vector_decode_and_decompress_loop_match.fold]
    simp only [WP.spec_ok]
    refine ⟨rfl, ?_, h_wf_in, ?_⟩
    · -- frame: trivial when LHS = RHS
      intro j h_j h_j' _; rfl
    · -- per-row FC vacuous: range empty
      intro j hj_lo hj_hi h_j'
      omega
termination_by iter.«end».val - iter.start.val
decreasing_by scalar_decr_tac

/-- **Top spec for `vector_decode_and_decompress`** — full FC.

On `NoError`, every row of `pv_dst'` equals
`decodeDecompressPoly d` applied to its `32·d`-byte window of `pb_src`.

  **Informal proof.**
  `unfold mlkem.ntt.vector_decode_and_decompress; step*` through
  Range setup.  Then `step with
  mlkem.ntt.vector_decode_and_decompress_loop.spec` with
  `iter = { start := 0, end := pv_dst.length }` and
  `h_i : i.val = MLWE_POLYNOMIAL_COEFFICIENTS.val / 8` (the IterMut
  initial cursor from the extracted code); preconditions from `h_d`,
  `h_nrows`, `h_len`.

  From the loop post (`NoError` branch):
  - `wfPolyVec pv_dst'`: directly from the loop post; `agrind`.
  - `∀ j < pv_dst'.length, toPoly pv_dst'[j] =
    decodeDecompressPoly d (sliceWindowToSpecBytes pb_src ...)`:
    from loop post's `∀ j, 0 ≤ j < pv_dst.length → ...` (since
    `iter.start = 0`); window bounds from `h_len` + `h_nrows` +
    `agrind`.
  - `pv_dst'.length = pv_dst.length`: from loop post; `agrind`.
  - `InvalidBlob`: `d = 12` from loop post; `agrind`. -/
@[step]
theorem mlkem.ntt.vector_decode_and_decompress.spec
    (pb_src : Slice U8) (n_bits_per_coefficient : U32)
    (pv_dst : Slice (PolyElement))
    (h_d : 1 ≤ n_bits_per_coefficient.val ∧ n_bits_per_coefficient.val ≤ 12)
    (h_nrows : 2 ≤ pv_dst.length ∧ pv_dst.length ≤ 4)
    (h_len : pb_src.length =
             pv_dst.length * (n_bits_per_coefficient.val * 32))
    /- Input vector well-formedness: callers always pass a slice whose
       coefficients already satisfy `wfPoly` (e.g. drawn from a `wfKey`
       state via `s_mut` / `t_mut`).  Required to expose `wfPolyVec`
       on the `InvalidBlob` arm — the impl rejects the offending
       coefficient BEFORE the store, so previously-overwritten slots
       are validated and trailing slots retain the input's `wfPoly`. -/
    (h_wf_in : wfPolyVec pv_dst) :
    mlkem.ntt.vector_decode_and_decompress pb_src n_bits_per_coefficient pv_dst
      ⦃ err pv_dst' =>
          pv_dst'.length = pv_dst.length ∧
          /- Universal: `wfPolyVec` is preserved regardless of failure.
             The Rust impl rejects the offending coefficient BEFORE the
             store, so overwritten slots are validated and trailing
             slots retain the input's `wfPoly` (`mlkem/ntt.rs:798-806`).
             Required by downstream key-state reconstruction
             (`KSV::*_after_prep`, `KSV::*_branch_b`). -/
          wfPolyVec pv_dst' ∧
          (match err with
           | Error.NoError =>
               (∀ (j : Nat) (h_j : j < pv_dst'.length),
                  ∃ (h_src_window :
                      (j + 1) * (32 * n_bits_per_coefficient.val) ≤ pb_src.length),
                  toPoly (pv_dst'.val[j]'h_j)
                    = decodeDecompressPoly n_bits_per_coefficient.val
                        (sliceWindowToSpecBytes pb_src
                          (j * (32 * n_bits_per_coefficient.val))
                          (32 * n_bits_per_coefficient.val)
                          (Nat.add_one_mul _ _ ▸ h_src_window))
                        ⟨h_d.1, h_d.2⟩ ∧
                  (∀ (i : ℕ) (_h_i : i < 256),
                    Bridges.dBitSegment n_bits_per_coefficient.val
                        (sliceWindowToSpecBytes pb_src
                          (j * (32 * n_bits_per_coefficient.val))
                          (32 * n_bits_per_coefficient.val)
                          (Nat.add_one_mul _ _ ▸ h_src_window))
                        i < MLKEM.m n_bits_per_coefficient.val))
           | Error.InvalidBlob =>
               n_bits_per_coefficient.val = 12
           | _ => False) ⦄ := by
  unfold mlkem.ntt.vector_decode_and_decompress
  step*
  · -- Precondition: pv_dst.len ≤ MATRIX_MAX_NROWS (= 4)
    simp [mlkem.ntt.MATRIX_MAX_NROWS]
    scalar_tac
  · -- Final post-loop goal.
    refine ⟨err_post1, err_post3, ?_⟩
    match err, err_post4 with
    | .NoError, h_match =>
      intro j h_j
      have h_j_pv_dst : j < pv_dst.len.val := by rw [err_post1] at h_j; exact h_j
      obtain ⟨h_src_window, h_eq, h_canon⟩ := h_match j (Nat.zero_le _) h_j_pv_dst h_j
      exact ⟨by scalar_tac, h_eq, h_canon⟩
    | .InvalidBlob, h_match => exact h_match
    | .Unused, h_match => exact h_match.elim
    | .WrongKeySize, h_match => exact h_match.elim
    | .WrongBlockSize, h_match => exact h_match.elim
    | .WrongDataSize, h_match => exact h_match.elim
    | .WrongNonceSize, h_match => exact h_match.elim
    | .WrongTagSize, h_match => exact h_match.elim
    | .WrongIterationCount, h_match => exact h_match.elim
    | .AuthenticationFailure, h_match => exact h_match.elim
    | .ExternalFailure, h_match => exact h_match.elim
    | .FipsFailure, h_match => exact h_match.elim
    | .HardwareFailure, h_match => exact h_match.elim
    | .NotImplemented, h_match => exact h_match.elim
    | .BufferTooSmall, h_match => exact h_match.elim
    | .InvalidArgument, h_match => exact h_match.elim
    | .MemoryAllocationFailure, h_match => exact h_match.elim
    | .SignatureVerificationFailure, h_match => exact h_match.elim
    | .IncompatibleFormat, h_match => exact h_match.elim
    | .ValueTooLarge, h_match => exact h_match.elim
    | .SessionReplayFailure, h_match => exact h_match.elim
    | .HbsNoOtsKeysLeft, h_match => exact h_match.elim
    | .HbsPublicRootMismatch, h_match => exact h_match.elim

end Symcrust.Properties.MLKEM
