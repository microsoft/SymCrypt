/-
  # Sampling/SampleNTT.lean — Runtime loop + wrapper specs for SampleNTT.

  Split from the original `SampleNTT.lean`.  The spec-side bridge lemmas are
  in `SampleNTTBridge.lean`.
-/
import Symcrust.Properties.MLKEM.Sampling.SampleNTTBridge

open Aeneas Aeneas.Std Result
open scoped Spec.Notations
open Spec
open Spec.MLKEM
open symcrust

namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges
open Symcrust.Properties.MLKEM.Helpers

set_option maxHeartbeats 4000000
set_option maxRecDepth 2048

/-! ## Per-iteration body prefix

Extracts the "do work + return new buffer state + two candidate
samples" portion of one loop iteration, *before* the terminal inner
`if i8 < MLWE then recurse else recurse` dispatch. -/

#decompose mlkem.ntt.poly_element_sample_ntt_from_shake128_loop
  poly_element_sample_ntt_from_shake128_loop.fold
  branch 0 (letRange 0 16) => poly_element_sample_ntt_from_shake128_loop_body_prefix

/-- "Fresh-absorb" ghost state: same `absorbed/rate/padVal` as `g`, but with
    `squeezed := []`.  Because `extractOutput` depends only on
    `absorbed/rate/padVal/squeezed.length`, the byte stream
    `(extractOutput (freshAbsorbGhost g) n).toList` is the *canonical*
    SHAKE128 squeeze stream for the absorbed prefix.  This canonicality
    is what lets us state `g.squeezed = (extractOutput (freshAbsorbGhost g)
    g.squeezed.length).toList` as an invariant. -/
private def freshAbsorbGhost (g : sha3.sha3_impl.GhostState) :
    sha3.sha3_impl.GhostState :=
  ⟨g.rate, g.padVal, g.absorbed, [], g.h_rate⟩

@[simp] private theorem freshAbsorbGhost_rate (g : sha3.sha3_impl.GhostState) :
    (freshAbsorbGhost g).rate = g.rate := rfl
@[simp] private theorem freshAbsorbGhost_padVal (g : sha3.sha3_impl.GhostState) :
    (freshAbsorbGhost g).padVal = g.padVal := rfl
@[simp] private theorem freshAbsorbGhost_absorbed (g : sha3.sha3_impl.GhostState) :
    (freshAbsorbGhost g).absorbed = g.absorbed := rfl
@[simp] private theorem freshAbsorbGhost_squeezed (g : sha3.sha3_impl.GhostState) :
    (freshAbsorbGhost g).squeezed = [] := rfl

/-- `freshAbsorbGhost` ignores any `squeeze` applied to its argument: only
    rate/padVal/absorbed flow through. -/
@[simp] private theorem freshAbsorbGhost_squeeze (g : sha3.sha3_impl.GhostState)
    (data : List U8) :
    freshAbsorbGhost (g.squeeze data) = freshAbsorbGhost g := rfl

/-- Key cancellation: `extractOutput` is determined by
    `(rate, padVal, absorbed, squeezed.length)`.  Advancing the fresh-absorb
    sibling by `g.squeezed.length` yields a state whose `extractOutput`
    matches `g`'s.  This is the bridge that lets the (β) invariant clause
    re-establish itself after `MlKemHashState.extract` extends the ghost. -/
private theorem extractOutput_freshAbsorbGhost_squeezeAdvance
    (g : sha3.sha3_impl.GhostState) (m : Nat) :
    sha3.sha3_impl.extractOutput
        ((freshAbsorbGhost g).squeezeAdvance g.squeezed.length) m =
      sha3.sha3_impl.extractOutput g m := by
  have h_rate :
      ((freshAbsorbGhost g).squeezeAdvance g.squeezed.length).rate = g.rate := rfl
  have h_padVal :
      ((freshAbsorbGhost g).squeezeAdvance g.squeezed.length).padVal = g.padVal := rfl
  have h_absorbed :
      ((freshAbsorbGhost g).squeezeAdvance g.squeezed.length).absorbed = g.absorbed := rfl
  have h_len :
      ((freshAbsorbGhost g).squeezeAdvance g.squeezed.length).squeezed.length
        = g.squeezed.length := by
    simp [sha3.sha3_impl.GhostState.squeezeAdvance, sha3.sha3_impl.GhostState.squeeze]
  unfold sha3.sha3_impl.extractOutput
  rw [h_rate, h_padVal, h_absorbed, h_len]

/-- **Streaming invariant for SampleNTT**.

After processing `n_rounds` XOF rounds (3 bytes each) and accepting `j`
coefficients (`j = (sampleNttPartial seed n_rounds).2`):

* `pe_dst[0, j)` matches `sampleNttPartial seed n_rounds` ((.1).get k);
* `pe_dst[j, 256)` is unconstrained (zero or junk — will be overwritten);
* the hash state `p_state` is in absorbing/squeezing mode for the ghost
  `g` whose `absorbed = seed` and `squeezed` contains `n_rounds * 3`
  bytes (consumed for the XOF rounds; possibly buffered in
  `shake_output_buf`).

`shake_output_buf` and `curr_buf_index` encode the suffix of the
already-squeezed bytes still to be processed: when `curr_buf_index = 24`
the next iteration triggers a fresh `extract` of 24 bytes; when
`curr_buf_index < 24`, the bytes at `shake_output_buf[curr_buf_index ..
curr_buf_index + 3)` are the next round's input. -/
def sampleNttInv
    (seed : 𝔹 34)
    (p_state : mlkem.hash.MlKemHashState)
    (pe_dst : PolyElement)
    (i : Usize)
    (shake_output_buf : Array U8 24#usize)
    (curr_buf_index : Usize)
    (n_rounds : Nat) (g : sha3.sha3_impl.GhostState) : Prop :=
  i.val ≤ 256 ∧
  curr_buf_index.val ≤ 24 ∧
  -- Buffer cursor lies on a 3-byte boundary: ∈ {0, 3, 6, ..., 21, 24}.
  -- This is what licenses reading three bytes at offsets [ci, ci+1, ci+2]
  -- in the cached arm (where ci ≠ 24 ⇒ ci ≤ 21).
  curr_buf_index.val % 3 = 0 ∧
  -- ghost state: absorbing or squeezing for seed
  (mlkem.hash.MlKemHashState.absorbing p_state g ∨
   mlkem.hash.MlKemHashState.squeezing p_state g) ∧
  g.absorbed.map (·.bv) = seed.toList ∧
  p_state.alg = mlkem.hash.MlKemHashAlg.Shake128 ∧
  -- (α) **Byte accounting**: the total bytes squeezed from the XOF so far
  -- equal 3·n_rounds (consumed by prior rounds) + (24 − ci) (remaining in
  -- the buffer, indices [ci, 24)).
  g.squeezed.length = 3 * n_rounds + (24 - curr_buf_index.val) ∧
  -- (β) **Canonical sponge output**: `g.squeezed` is determined by the
  -- absorbed bytes alone — every state reached during sampling agrees
  -- with the fresh-absorb canonical squeeze.  Bridges spec ↔ impl.
  g.squeezed = (sha3.sha3_impl.extractOutput
                  (freshAbsorbGhost g)
                  g.squeezed.length).toList ∧
  -- (γ) **Buffer-suffix coverage**: the bytes still in the buffer
  -- (indices [ci, 24)) equal the corresponding tail of `g.squeezed`
  -- (positions [3·n_rounds, g.squeezed.length)).
  (∀ (k : Nat), k < 24 - curr_buf_index.val →
      shake_output_buf.val[curr_buf_index.val + k]? =
      g.squeezed[3 * n_rounds + k]?) ∧
  -- `n_rounds` rounds of the spec have been processed; the partial run
  -- yields `i` accepted coefficients.
  (sampleNttPartial seed n_rounds).2 = i.val ∧
  -- pe_dst[0..i) matches the partial output
  (∀ (k : Nat) (h_k : k < 256), k < i.val →
      (pe_dst.val[k]).val =
        ((sampleNttPartial seed n_rounds).1.get ⟨k, h_k⟩).val) ∧
  -- pe_dst[0..i) is well-formed (< q)
  (∀ (k : Nat) (_h_k : k < 256), k < i.val →
      (pe_dst.val[k]).val < q)

/-- **Body-prefix spec**.

Refills the buffer if `curr_buf_index = 24` (by squeezing 24 more bytes
from the XOF); loads two 12-bit candidates `sample0` and `sample1`
from `shake_output_buf[curr_buf_index .. curr_buf_index + 3)` (one
3-byte chunk = one XOF round), masks the first to 12 bits, right-shifts
the second by 4; advances `curr_buf_index` by 3.

The returned `(p_state', buf', sample0, sample1, curr_buf_index',
index_mut_back, i6)` satisfies:
* `p_state'` is in squeezing mode for the ghost extended by the
  consumed XOF bytes;
* `sample0.val = (sampleNttPartial seed (n_rounds + 1)).bytes-derived
  candidate d₁` and similarly for `sample1`;
* `i6.val = sample0.val` (used as the accept check `i6 < q`);
* `index_mut_back` is the closure storing back into `pe_dst[i]`.

Informal proof. Template: leaf fold-helper (body-prefix, no recursion).
`unfold poly_element_sample_ntt_from_shake128_loop_body_prefix`; case-split
on `curr_buf_index.val = 24` (buffer exhausted vs. cached):
- **Refill branch** (`= 24`): `step*` through `MlKemHashState.extract.spec`
  (squeezes 24 bytes into `shake_output_buf`; postcondition gives squeezing
  ghost `g'` with `g'.squeezed = g.squeezed ++ (extracted 24 bytes)`,
  `g'.absorbed = g.absorbed`, and `p_state'` in squeezing mode); cursor
  resets to `3` after the three-byte read.
- **Cached branch** (`< 24`): no `extract` call; `g' = g`; ghost stays squeezing.
In both branches, `step*` through `Array.index_spec` three times to read bytes
`c0, c1, c2` at positions `buf'[b], buf'[b+1], buf'[b+2]` (where `b =
curr_buf_index'`). Candidates `sample0 = c0 + 256*(c1 % 16)` and
`sample1 = c1/16 + 16*c2` match `nttCandidatesOfBytes c0 c1 c2` by definition;
12-bit bound goals `sample0 < 4096` and `sample1 < 4096` close with
`bv_tac 32`. The `i6.val = sample0.val` goal closes with `agrind` (U32→U32
cast). `index_mut_back` framing from `Array.index_usize_mut.spec`: writes `v`
at slot `i.val` and is identity elsewhere; `agrind` for slice length. -/
@[step]
theorem poly_element_sample_ntt_from_shake128_loop_body_prefix.spec
    (seed : 𝔹 34)
    (p_state : mlkem.hash.MlKemHashState)
    (pe_dst : PolyElement)
    (i : Usize)
    (shake_output_buf : Array U8 24#usize)
    (curr_buf_index : Usize)
    (n_rounds : Nat) (g : sha3.sha3_impl.GhostState)
    (h_i : i.val < 256)
    (h_inv : sampleNttInv seed p_state pe_dst i shake_output_buf
              curr_buf_index n_rounds g) :
    poly_element_sample_ntt_from_shake128_loop_body_prefix
        p_state pe_dst i shake_output_buf curr_buf_index
      ⦃ p_state' buf' sample0 sample1 curr_buf_index'
        index_mut_back i6 =>
          ∃ (g' : sha3.sha3_impl.GhostState) (n_squeeze_bytes : Nat),
            -- The new ghost extends the old by the bytes consumed.
            g'.absorbed = g.absorbed ∧
            g'.squeezed.length = g.squeezed.length + n_squeeze_bytes ∧
            -- New ghost state is either absorbing (no refill: cached arm,
            -- ghost is unchanged) or squeezing (refill arm OR previously
            -- already squeezing).  Matches `sampleNttInv`'s
            -- `absorbing ∨ squeezing` disjunction.
            (mlkem.hash.MlKemHashState.absorbing p_state' g' ∨
             mlkem.hash.MlKemHashState.squeezing p_state' g') ∧
            p_state'.alg = p_state.alg ∧
            -- The two candidates are in 12-bit range.
            sample0.val < 2 ^ 12 ∧ sample1.val < 2 ^ 12 ∧
            -- Cursor advance.
            curr_buf_index'.val = (if curr_buf_index.val = 24 then 0 else curr_buf_index.val) + 3 ∧
            -- Candidate values match `sampleNttPartial`'s per-round step:
            -- the 3 bytes at `buf'[curr_buf_index'.val - 3 .. curr_buf_index'.val)`
            -- yield (sample0.val, sample1.val) via `nttCandidatesOfBytes`.
            (∃ (h0 : curr_buf_index'.val - 3 < buf'.val.length)
               (h1 : curr_buf_index'.val - 2 < buf'.val.length)
               (h2 : curr_buf_index'.val - 1 < buf'.val.length),
                (sample0.val, sample1.val) =
                  nttCandidatesOfBytes
                    (buf'.val[curr_buf_index'.val - 3]'h0)
                    (buf'.val[curr_buf_index'.val - 2]'h1)
                    (buf'.val[curr_buf_index'.val - 1]'h2)) ∧
            -- i6 carries sample0 in u32 form (used for the < q accept check).
            i6.val = sample0.val ∧
            -- index_mut_back, when applied to a u16 value v, writes v at
            -- pe_dst[i].
            (∀ (v : U16),
                (index_mut_back v).val.length = pe_dst.val.length ∧
                ∀ (k : Nat) (_ : k < (index_mut_back v).val.length),
                  (index_mut_back v).val[k] =
                    if k = i.val then v
                    else pe_dst.val[k]) ∧
            -- (NEW-1) **Arm classification**: either a refill happened
            -- (consumed 24 bytes; previous buffer was exhausted), or no
            -- refill (consumed 0 bytes; previous buffer was partial).
            ((n_squeeze_bytes = 24 ∧ curr_buf_index.val = 24) ∨
             (n_squeeze_bytes = 0 ∧ curr_buf_index.val < 24)) ∧
            -- (NEW-2) **Canonical sponge output**: `g'.squeezed` is the
            -- canonical SHAKE128 squeeze stream from the fresh-absorb
            -- state.  Preserves (β) for the next loop iteration.
            -- (Note: `freshAbsorbGhost g' = freshAbsorbGhost g` since
            -- `g'.absorbed = g.absorbed` and squeezing doesn't change
            -- rate/padVal.)
            g'.squeezed = (sha3.sha3_impl.extractOutput (freshAbsorbGhost g')
                            g'.squeezed.length).toList ∧
            -- (NEW-3) **Unified byte equation**: bytes at buffer positions
            -- `[curr_buf_index'.val − 3 .. 24)` (the 3 just-consumed plus
            -- the still-pending suffix) match `g'.squeezed` at positions
            -- `[3·n_rounds .. 3·n_rounds + 24)`.  Specialised at `k < 3`
            -- gives the 3-byte equation for the bridge; at `k ∈ [3, 24−ci'+3)`
            -- preserves (γ) for the next loop iteration.
            (∀ (k : Nat), k < 24 - curr_buf_index'.val + 3 →
                buf'.val[curr_buf_index'.val - 3 + k]? =
                g'.squeezed[3 * n_rounds + k]?) ⦄ := by
  unfold poly_element_sample_ntt_from_shake128_loop_body_prefix
  obtain ⟨h_i_le, h_ci_le, h_ci_mod, h_state, h_absorbed, h_alg, h_sq_len,
          h_canonical, h_buf_match, h_n_rounds_eq, h_done, h_wf⟩ := h_inv
  step*
  -- Now we have `if curr_buf_index = s1.len` (with s1 = shake_output_buf.to_slice).
  have h_s1_len : (s1.len : Nat) = 24 := by
    simp [s1_post, Array.to_slice, Slice.len]
  -- Case split on the refill condition.
  by_cases h_refill : (curr_buf_index = s1.len)
  · -- Refill arm: invoke `MlKemHashState.extract` to fill 24 fresh bytes.
    -- Then step through loads, masks, shifts.  The new ghost g' extends g
    -- by the 24 extracted bytes; the resulting state is squeezing.
    simp only [if_pos h_refill]
    let* ⟨ x_slice_pair, x_slice_post1, x_slice_post2 ⟩ ← Array.to_slice_mut_spec
    obtain ⟨x_slice, x_slice_back⟩ := x_slice_pair
    dsimp only at x_slice_post1 x_slice_post2 ⊢
    let* ⟨ ext_pair, x_post1, x_post2, x_post3, x_post4 ⟩
        ← mlkem.hash.MlKemHashState.extract.spec
    obtain ⟨p_state2, extracted⟩ := ext_pair
    dsimp only at x_post1 x_post2 x_post3 x_post4 ⊢
    let* ⟨ buf2, buf2_post ⟩ ← Array.to_slice.step_spec
    let* ⟨ i3, i3_post ⟩ ← mlkem.ntt.load_u16_le.spec
    let* ⟨ sample0, sample0_post1, sample0_post2 ⟩ ← UScalar.and_spec
    let* ⟨ buf3, buf3_post ⟩ ← Array.to_slice.step_spec
    let* ⟨ i4, i4_post ⟩ ← Usize.add_spec
    let* ⟨ i5, i5_post ⟩ ← mlkem.ntt.load_u16_le.spec
    let* ⟨ sample1, sample1_post1, sample1_post2 ⟩ ← U16.ShiftRight_IScalar_spec
    let* ⟨ curr_buf_index2, curr_buf_index2_post ⟩ ← Usize.add_spec
    let* ⟨ _, index_mut_back, _, __post2 ⟩ ← Array.index_mut_usize_spec
    let* ⟨ i6, i6_post ⟩ ← UScalar.cast.step_spec
    -- Existentials: new ghost extends g by 24 squeezed bytes.
    refine ⟨g.squeeze extracted.val, 24, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · -- absorbed unchanged
      simp [sha3.sha3_impl.GhostState.squeeze]
    · -- squeezed extended by 24
      have h_ext_len : extracted.length = 24 := by scalar_tac
      simp [sha3.sha3_impl.GhostState.squeeze, h_ext_len]
    · -- p_state2.absorbing ∨ squeezing — from x_post4 (wipe = false)
      right
      simpa using x_post4
    · -- p_state2.alg = p_state.alg
      exact x_post1
    · -- sample0 < 2^12 — 12-bit mask
      have h := sample0_post2
      bv_tac 16
    · -- sample1 < 2^12 — 16-bit shifted right by 4
      have h := sample1_post2
      bv_tac 16
    · -- curr_buf_index2 = (if curr_buf_index = 24 then 0 else curr_buf_index) + 3
      -- Refill case: curr_buf_index = s1.len, s1.len = 24, so the if takes the 0 branch.
      have h_ci : curr_buf_index.val = 24 := by
        have := h_refill; scalar_tac
      rw [curr_buf_index2_post]
      simp [h_ci]
    · -- candidate bytes equation via nttCandidatesOfBytes (refill arm)
      -- Normalize the anonymous from_slice closure away.
      simp only [x_slice_post2] at buf2_post buf3_post ⊢
      set buf' : Std.Array U8 24#usize := shake_output_buf.from_slice extracted with hbuf'
      have h_ci2 : curr_buf_index2.val = 3 := by rw [curr_buf_index2_post]
      have h_eq1 : curr_buf_index2.val - 3 = 0 := by scalar_tac
      have h_eq2 : curr_buf_index2.val - 2 = 1 := by scalar_tac
      have h_eq3 : curr_buf_index2.val - 1 = 2 := by scalar_tac
      have h_buf2 : buf2.val = buf'.val := by
        rw [buf2_post]; simp [Std.Array.to_slice]
      have h_buf3 : buf3.val = buf'.val := by
        rw [buf3_post]; simp [Std.Array.to_slice]
      have h_i4_eq : i4.val = 1 := by rw [i4_post]
      have h_len : buf'.val.length = 24 := by
        have := buf'.property; scalar_tac
      have h_b0 : (0 : Nat) < buf'.val.length := by scalar_tac
      have h_b1 : (1 : Nat) < buf'.val.length := by scalar_tac
      have h_b2 : (2 : Nat) < buf'.val.length := by scalar_tac
      refine ⟨by scalar_tac, by scalar_tac, by scalar_tac, ?_⟩
      simp only [h_eq1, h_eq2, h_eq3]
      set c0 := buf'.val[0]'h_b0 with hc0
      set c1 := buf'.val[1]'h_b1 with hc1
      set c2 := buf'.val[2]'h_b2 with hc2
      have h_i3' : i3.val = c0.val + 256 * c1.val := by
        rw [i3_post]
        fcongr 1 <;> simp [h_buf2, hc0, hc1]
      have hl1 : (buf3.val)[i4.val]'(by simp [h_buf3]; scalar_tac) =
                 buf'.val[1]'h_b1 := by
        simp only [h_buf3, h_i4_eq]
      have hl2 : (buf3.val)[i4.val + 1]'(by simp [h_buf3]; scalar_tac) =
                 buf'.val[2]'h_b2 := by
        simp only [h_buf3, h_i4_eq]
      have h_i5' : i5.val = c1.val + 256 * c2.val := by
        rw [i5_post, hl1, hl2]
      obtain ⟨e0, e1⟩ := Helpers.sampleNtt_byte_extract c0 c1 c2 i3 i5 sample0 sample1
        h_i3' h_i5' sample0_post1 sample1_post1
      unfold nttCandidatesOfBytes
      exact Prod.mk.injEq .. |>.mpr ⟨e0, e1⟩
    · -- i6.val = sample0.val (cast preserves value)
      scalar_tac
    · -- index_mut_back closure equations (length + getElem)
      intro v
      refine ⟨?_, ?_⟩
      · subst __post2; simp [Std.Array.set]
      · intro k hk
        subst __post2
        simp only [Std.Array.set_val_eq, List.getElem_set]
        split <;> rename_i h <;>
          (first | rw [if_pos h.symm] | rw [if_neg (fun heq => h heq.symm)])
    · -- (NEW-1) Arm classification: refill arm has n_squeeze_bytes = 24 and ci = 24.
      left
      refine ⟨rfl, ?_⟩
      have := h_refill; scalar_tac
    · -- (NEW-2) g'.squeezed canonical.
      -- LHS: (g.squeeze extracted.val).squeezed = g.squeezed ++ extracted.val.
      -- RHS via extractOutput_append + h_canonical + extractOutput_freshAbsorbGhost_squeezeAdvance:
      --     (extractOutput (freshAbsorbGhost g) (g.sq.length + 24)).toList
      --   = g.squeezed ++ (extractOutput g 24).toList = g.squeezed ++ extracted.val.
      have h_ext_len : extracted.length = 24 := by scalar_tac
      have h_ext_val_len : extracted.val.length = 24 := h_ext_len
      have h_xs_len : x_slice.length = 24 := by
        rw [Aeneas.Std.Slice.length, x_slice_post1]; scalar_tac
      have h_xpost3' : extracted.val = (sha3.sha3_impl.extractOutput g 24).toList := by
        rw [x_post3, h_xs_len]
      show (g.squeeze extracted.val).squeezed =
           (sha3.sha3_impl.extractOutput
              (freshAbsorbGhost (g.squeeze extracted.val))
              (g.squeeze extracted.val).squeezed.length).toList
      rw [freshAbsorbGhost_squeeze]
      show g.squeezed ++ extracted.val =
           (sha3.sha3_impl.extractOutput (freshAbsorbGhost g)
              (g.squeezed ++ extracted.val).length).toList
      rw [List.length_append, h_ext_val_len,
          sha3.sha3_impl.extractOutput_append (freshAbsorbGhost g)
            g.squeezed.length 24,
          extractOutput_freshAbsorbGhost_squeezeAdvance,
          ← h_canonical, ← h_xpost3']
    · -- (NEW-3) Refill arm: curr_buf_index' = 3, so ci' - 3 + k = k.  buf' is
      -- `shake_output_buf.from_slice extracted` (from `index_mut_back` mechanics),
      -- with `extracted.val.length = 24`, so `buf'.val = extracted.val`.
      -- RHS: `g'.squeezed = g.squeezed ++ extracted.val`; using (α) `g.squeezed.length
      -- = 3·n_rounds + (24 - 24) = 3·n_rounds`, the index `3·n_rounds + k` falls
      -- in the `extracted` tail at position `k`.  Both sides reduce to
      -- `extracted.val[k]?`.
      intro k hk
      have h_ci : curr_buf_index.val = 24 := by have := h_refill; scalar_tac
      have h_ci2 : curr_buf_index2.val = 3 := by rw [curr_buf_index2_post]
      have h_ext_val_len : extracted.val.length = 24 := by scalar_tac
      have h_k_lt : k < 24 := by scalar_tac
      have h_buf'_val :
          (shake_output_buf.from_slice extracted).val = extracted.val :=
        Aeneas.Std.Array.from_slice_val shake_output_buf extracted h_ext_val_len
      have h_g'_sq : (g.squeeze extracted.val).squeezed
                       = g.squeezed ++ extracted.val := by
        simp [sha3.sha3_impl.GhostState.squeeze]
      have h_g_sq_len : g.squeezed.length = 3 * n_rounds := by
        rw [h_sq_len, h_ci]; scalar_tac
      have h_lhs_idx : curr_buf_index2.val - 3 + k = k := by scalar_tac
      have h_rhs_idx : 3 * n_rounds + k = g.squeezed.length + k := by
        rw [h_g_sq_len]
      rw [x_slice_post2, h_buf'_val, h_lhs_idx, h_g'_sq, h_rhs_idx,
          List.getElem?_append_right (Nat.le_add_right _ _),
          Nat.add_sub_cancel_left]
  · -- Cached arm: no refill, ghost & buffer unchanged.
    simp only [if_neg h_refill]
    have h_ci_lt : curr_buf_index.val < 24 := by
      have h_ne : curr_buf_index.val ≠ s1.len.val := by
        intro heq; apply h_refill
        have : (curr_buf_index : Usize).val = (s1.len : Usize).val := heq
        scalar_tac
      scalar_tac
    have h_ci_le_21 : curr_buf_index.val ≤ 21 := by
      have ⟨q, hq⟩ := Nat.dvd_of_mod_eq_zero h_ci_mod
      have hq_lt : q < 8 := by scalar_tac
      scalar_tac
    let* ⟨ s2, s2_post ⟩ ← Array.to_slice.step_spec
    let* ⟨ i3, i3_post ⟩ ← mlkem.ntt.load_u16_le.spec
    let* ⟨ sample0, sample0_post1, sample0_post2 ⟩ ← UScalar.and_spec
    let* ⟨ s3, s3_post ⟩ ← Array.to_slice.step_spec
    let* ⟨ i4, i4_post ⟩ ← Usize.add_spec
    let* ⟨ i5, i5_post ⟩ ← mlkem.ntt.load_u16_le.spec
    let* ⟨ sample1, sample1_post1, sample1_post2 ⟩ ← U16.ShiftRight_IScalar_spec
    let* ⟨ curr_buf_index2, curr_buf_index2_post ⟩ ← Usize.add_spec
    let* ⟨ _, index_mut_back, _, __post2 ⟩ ← Array.index_mut_usize_spec
    let* ⟨ i6, i6_post ⟩ ← UScalar.cast.step_spec
    refine ⟨g, 0, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · -- g'.absorbed = g.absorbed
      rfl
    · -- g'.squeezed.length = g.squeezed.length + 0
      simp
    · -- absorbing ∨ squeezing: unchanged from input
      exact h_state
    · -- sample0 < 2^12
      have h := sample0_post2; bv_tac 16
    · -- sample1 < 2^12
      have h := sample1_post2; bv_tac 16
    · -- curr_buf_index2 = (if ci = 24 then 0 else ci) + 3
      have h_ci_ne : curr_buf_index.val ≠ 24 := by scalar_tac
      rw [curr_buf_index2_post]
      simp [h_ci_ne]
    · -- candidate bytes equation via nttCandidatesOfBytes (cached arm)
      have h_ci2 : curr_buf_index2.val = curr_buf_index.val + 3 := curr_buf_index2_post
      have h_s2 : s2.val = shake_output_buf.val := by
        simp [s2_post, Std.Array.to_slice]
      have h_s3 : s3.val = shake_output_buf.val := by
        simp [s3_post, Std.Array.to_slice]
      have h_i4_eq : i4.val = curr_buf_index.val + 1 := i4_post
      have h_eq1 : curr_buf_index2.val - 3 = curr_buf_index.val := by scalar_tac
      have h_eq2 : curr_buf_index2.val - 2 = curr_buf_index.val + 1 := by scalar_tac
      have h_eq3 : curr_buf_index2.val - 1 = curr_buf_index.val + 2 := by scalar_tac
      have h_b0 : curr_buf_index.val < shake_output_buf.val.length := by scalar_tac
      have h_b1 : curr_buf_index.val + 1 < shake_output_buf.val.length := by scalar_tac
      have h_b2 : curr_buf_index.val + 2 < shake_output_buf.val.length := by scalar_tac
      refine ⟨by scalar_tac, by scalar_tac, by scalar_tac, ?_⟩
      simp only [h_eq1, h_eq2, h_eq3]
      set c0 := shake_output_buf.val[curr_buf_index.val]'h_b0 with hc0
      set c1 := shake_output_buf.val[curr_buf_index.val + 1]'h_b1 with hc1
      set c2 := shake_output_buf.val[curr_buf_index.val + 2]'h_b2 with hc2
      have h_i3' : i3.val = c0.val + 256 * c1.val := by
        rw [i3_post]
        fcongr 1 <;> simp [h_s2, hc0, hc1]
      have h_i5' : i5.val = c1.val + 256 * c2.val := by
        rw [i5_post]
        have hci4 : i4.val + 1 = curr_buf_index.val + 2 := by scalar_tac
        have hl1 : (s3.val)[i4.val]'(by simp [h_s3]; scalar_tac) =
                   (shake_output_buf.val)[curr_buf_index.val + 1]'h_b1 := by
          simp only [h_s3, h_i4_eq]
        have hl2 : (s3.val)[i4.val + 1]'(by simp [h_s3]; scalar_tac) =
                   (shake_output_buf.val)[curr_buf_index.val + 2]'h_b2 := by
          simp only [h_s3, h_i4_eq, Nat.add_assoc]
        rw [hl1, hl2]
      obtain ⟨e0, e1⟩ := Helpers.sampleNtt_byte_extract c0 c1 c2 i3 i5 sample0 sample1
        h_i3' h_i5' sample0_post1 sample1_post1
      unfold nttCandidatesOfBytes
      exact Prod.mk.injEq .. |>.mpr ⟨e0, e1⟩
    · -- i6.val = sample0.val (cast preserves value)
      scalar_tac
    · -- index_mut_back closure equations
      intro v
      refine ⟨?_, ?_⟩
      · subst __post2; simp [Std.Array.set]
      · intro k hk
        subst __post2
        simp only [Std.Array.set_val_eq, List.getElem_set]
        split <;> rename_i h <;>
          (first | rw [if_pos h.symm] | rw [if_neg (fun heq => h heq.symm)])
    · -- (NEW-1) Arm classification: cached arm has n_squeeze_bytes = 0 and ci < 24.
      right
      exact ⟨rfl, h_ci_lt⟩
    · -- (NEW-2) g'.squeezed canonical: g' = g, so directly from (β-pre) = h_canonical.
      exact h_canonical
    · -- (NEW-3) Unified byte equation: cached arm has g' = g and buf' = shake_output_buf;
      -- curr_buf_index2 = curr_buf_index + 3 shifts the index by 3 from h_buf_match.
      intro k hk
      have h_ci2 : curr_buf_index2.val = curr_buf_index.val + 3 := curr_buf_index2_post
      have h_k_orig : k < 24 - curr_buf_index.val := by scalar_tac
      have h_eq : curr_buf_index2.val - 3 + k = curr_buf_index.val + k := by scalar_tac
      rw [h_eq]
      exact h_buf_match k h_k_orig

/-! ## Per-round step of `sampleNttPartial` — byte-bridge consumer.

Given the strengthened streaming invariant data at round `n` (canonical
squeezed bytes, sufficient byte coverage) and the three impl-side bytes
`(c0, c1, c2)` that match `g.squeezed[3n..3n+3)`, the next round of
`sampleNttPartial` is described in closed form by `nttCandidatesOfBytes`
applied to those bytes.  The four byte-bridge steps in `spec_gen` consume
this single lemma.

The body composes the SHA3-side byte-bridge contract
(`Helpers.sampleNttPartialAux_squeeze_eq_extractOutput`) with the
strengthened (α)(β)(γ) invariant. -/

private theorem sampleNttPartial_succ_eq_of_bytes
    (seed : 𝔹 34) (n : Nat)
    (g : sha3.sha3_impl.GhostState)
    (h_abs   : g.absorbed.map (·.bv) = seed.toList)
    (h_rate  : g.rate = 168) (h_pad : g.padVal = 31#u8)
    (h_canon : g.squeezed = (sha3.sha3_impl.extractOutput
                              (freshAbsorbGhost g) g.squeezed.length).toList)
    (h_sq_lb : 3 * n + 3 ≤ g.squeezed.length)
    (h_pn    : (sampleNttPartial seed n).2 < 256)
    (c0 c1 c2 : U8)
    (h_c0 : g.squeezed[3 * n]?     = some c0)
    (h_c1 : g.squeezed[3 * n + 1]? = some c1)
    (h_c2 : g.squeezed[3 * n + 2]? = some c2) :
    let s := sampleNttPartial seed n
    let d := nttCandidatesOfBytes c0 c1 c2
    let â₁ := if d.1 < MLKEM.q then s.1.set! s.2 d.1 else s.1
    let j₁ := if d.1 < MLKEM.q then s.2 + 1 else s.2
    let â₂ := if d.2 < MLKEM.q ∧ j₁ < 256 then â₁.set! j₁ d.2 else â₁
    let j₂ := if d.2 < MLKEM.q ∧ j₁ < 256 then j₁ + 1 else j₁
    sampleNttPartial seed (n + 1) = (â₂, j₂) := by
  intro s d â₁ j₁ â₂ j₂
  set init_s := MLKEM.XOF.Absorb MLKEM.XOF.Init seed with h_init_s
  set s_n := sampleNttPartialAux init_s MLKEM.Polynomial.zero 0 n with h_sn_def
  have h_s_eq_s_n : s = (s_n.2.1, s_n.2.2) := by
    show sampleNttPartial seed n = _
    rw [sampleNttPartial_eq_aux]
  have h_jn : s_n.2.2 < 256 := by
    have : (sampleNttPartial seed n).2 = s_n.2.2 := by rw [sampleNttPartial_eq_aux]
    omega
  -- Apply the bridge to relate XOF bytes to extractOutput.
  set init_g := freshAbsorbGhost g with h_ig_def
  have h_ig_sq : init_g.squeezed = [] := rfl
  have h_bridge : ∀ (k : Fin 3),
      (MLKEM.XOF.Squeeze s_n.1 3).2.get k =
        ((sha3.sha3_impl.extractOutput init_g (3 * n + 3)).get
          ⟨3 * n + k.val, by have := k.isLt; omega⟩).bv :=
    fun k => Helpers.sampleNttPartialAux_squeeze_eq_extractOutput seed init_g
              h_abs h_rate h_pad h_ig_sq n h_jn k
  -- Identify extractOutput bytes with c0, c1, c2 via the canonical invariant.
  set extra := g.squeezed.length - (3 * n + 3) with h_extra
  have h_canon_split :
      g.squeezed =
        (sha3.sha3_impl.extractOutput init_g (3 * n + 3)).toList ++
        (sha3.sha3_impl.extractOutput
            (init_g.squeezeAdvance (3 * n + 3)) extra).toList := by
    have hL : g.squeezed.length = (3 * n + 3) + extra := by simp [h_extra]; omega
    conv_lhs => rw [h_canon, hL]
    rw [sha3.sha3_impl.extractOutput_append init_g (3 * n + 3) extra]
  -- Option-level equation avoids motive-failure when index bounds change.
  have h_c_eq : ∀ (i : Nat), i < 3 * n + 3 →
      (sha3.sha3_impl.extractOutput init_g (3 * n + 3)).toList[i]? = g.squeezed[i]? := by
    intro i hi
    have hg_split :
        g.squeezed[i]? =
          ((sha3.sha3_impl.extractOutput init_g (3 * n + 3)).toList ++
           (sha3.sha3_impl.extractOutput (init_g.squeezeAdvance (3 * n + 3)) extra).toList)[i]? := by
      rw [← h_canon_split]
    rw [hg_split]
    rw [List.getElem?_append_left (by rw [Vector.length_toList]; exact hi)]
  have h_c0_eq :
      (sha3.sha3_impl.extractOutput init_g (3 * n + 3))[3 * n]'(by omega) = c0 := by
    have h := h_c_eq (3 * n) (by omega)
    rw [h_c0] at h
    have hi : 3 * n < (sha3.sha3_impl.extractOutput init_g (3 * n + 3)).toList.length := by
      rw [Vector.length_toList]; omega
    rw [List.getElem?_eq_getElem hi] at h
    have h2 : (sha3.sha3_impl.extractOutput init_g (3 * n + 3)).toList[3 * n]'hi = c0 :=
      Option.some.inj h
    rw [Vector.getElem_toList] at h2
    exact h2
  have h_c1_eq :
      (sha3.sha3_impl.extractOutput init_g (3 * n + 3))[3 * n + 1]'(by omega) = c1 := by
    have h := h_c_eq (3 * n + 1) (by omega)
    rw [h_c1] at h
    have hi : 3 * n + 1 < (sha3.sha3_impl.extractOutput init_g (3 * n + 3)).toList.length := by
      rw [Vector.length_toList]; omega
    rw [List.getElem?_eq_getElem hi] at h
    have h2 : (sha3.sha3_impl.extractOutput init_g (3 * n + 3)).toList[3 * n + 1]'hi = c1 :=
      Option.some.inj h
    rw [Vector.getElem_toList] at h2
    exact h2
  have h_c2_eq :
      (sha3.sha3_impl.extractOutput init_g (3 * n + 3))[3 * n + 2]'(by omega) = c2 := by
    have h := h_c_eq (3 * n + 2) (by omega)
    rw [h_c2] at h
    have hi : 3 * n + 2 < (sha3.sha3_impl.extractOutput init_g (3 * n + 3)).toList.length := by
      rw [Vector.length_toList]; omega
    rw [List.getElem?_eq_getElem hi] at h
    have h2 : (sha3.sha3_impl.extractOutput init_g (3 * n + 3)).toList[3 * n + 2]'hi = c2 :=
      Option.some.inj h
    rw [Vector.getElem_toList] at h2
    exact h2
  -- Combine: (XOF.Squeeze s_n.1 3).2 .get k = c_k.bv for k=0,1,2
  have h_C0 : (MLKEM.XOF.Squeeze s_n.1 3).2.get ⟨0, by decide⟩ = c0.bv := by
    rw [h_bridge ⟨0, by decide⟩]
    show ((sha3.sha3_impl.extractOutput init_g (3 * n + 3))[3 * n]'_).bv = _
    rw [h_c0_eq]
  have h_C1 : (MLKEM.XOF.Squeeze s_n.1 3).2.get ⟨1, by decide⟩ = c1.bv := by
    rw [h_bridge ⟨1, by decide⟩]
    show ((sha3.sha3_impl.extractOutput init_g (3 * n + 3))[3 * n + 1]'_).bv = _
    rw [h_c1_eq]
  have h_C2 : (MLKEM.XOF.Squeeze s_n.1 3).2.get ⟨2, by decide⟩ = c2.bv := by
    rw [h_bridge ⟨2, by decide⟩]
    show ((sha3.sha3_impl.extractOutput init_g (3 * n + 3))[3 * n + 2]'_).bv = _
    rw [h_c2_eq]
  have h_C0_val : (MLKEM.XOF.Squeeze s_n.1 3).2[0].val = c0.val := by
    show ((MLKEM.XOF.Squeeze s_n.1 3).2.get ⟨0, by decide⟩).val = _
    rw [h_C0]; rfl
  have h_C1_val : (MLKEM.XOF.Squeeze s_n.1 3).2[1].val = c1.val := by
    show ((MLKEM.XOF.Squeeze s_n.1 3).2.get ⟨1, by decide⟩).val = _
    rw [h_C1]; rfl
  have h_C2_val : (MLKEM.XOF.Squeeze s_n.1 3).2[2].val = c2.val := by
    show ((MLKEM.XOF.Squeeze s_n.1 3).2.get ⟨2, by decide⟩).val = _
    rw [h_C2]; rfl
  -- Unfold goal: sampleNttPartial seed (n+1) via aux_add n 1 + aux_succ.
  show sampleNttPartial seed (n + 1) = _
  rw [sampleNttPartial_eq_aux, sampleNttPartialAux_add init_s _ 0 n 1]
  rw [show (1 : Nat) = 0 + 1 from rfl, sampleNttPartialAux_succ]
  rw [if_pos h_jn]
  -- Destructure XOF.Squeeze so we can rewrite C[i].val with h_C{i}_val.
  generalize h_sq : MLKEM.XOF.Squeeze (sampleNttPartialAux init_s MLKEM.Polynomial.zero 0 n).1 3 = sq
  obtain ⟨ctx', C⟩ := sq
  dsimp only
  have h_C0' : C[0].val = c0.val := by
    have : C = (MLKEM.XOF.Squeeze (sampleNttPartialAux init_s MLKEM.Polynomial.zero 0 n).1 3).2 :=
      (congrArg Prod.snd h_sq).symm
    rw [this]; exact h_C0_val
  have h_C1' : C[1].val = c1.val := by
    have : C = (MLKEM.XOF.Squeeze (sampleNttPartialAux init_s MLKEM.Polynomial.zero 0 n).1 3).2 :=
      (congrArg Prod.snd h_sq).symm
    rw [this]; exact h_C1_val
  have h_C2' : C[2].val = c2.val := by
    have : C = (MLKEM.XOF.Squeeze (sampleNttPartialAux init_s MLKEM.Polynomial.zero 0 n).1 3).2 :=
      (congrArg Prod.snd h_sq).symm
    rw [this]; exact h_C2_val
  rw [h_C0', h_C1', h_C2']
  unfold sampleNttPartialAux
  simp only [Prod.mk.eta]
  -- Materialize â₂/j₂/â₁/j₁/s.1/s.2/d.1/d.2 in the goal via a `show` chain
  -- (each step is defeq through let-iota), then bridge `s` via h_s_eq_s_n,
  -- bridge `d.1`/`d.2` via the defining equation, push `.1`/`.2` through
  -- the inner ifs (apply_ite), so LHS and RHS share syntactically identical
  -- if-conditions.  `split_ifs <;> rfl` closes all four branches.
  show _ = (â₂, j₂)
  show _ = ((if d.2 < MLKEM.q ∧ j₁ < 256 then â₁.set! j₁ ↑d.2 else â₁),
            (if d.2 < MLKEM.q ∧ j₁ < 256 then j₁ + 1 else j₁))
  show _ = ((if d.2 < MLKEM.q ∧ (if d.1 < MLKEM.q then s.2 + 1 else s.2) < 256
              then (if d.1 < MLKEM.q then Vector.set! s.1 s.2 ↑d.1 else s.1).set!
                    (if d.1 < MLKEM.q then s.2 + 1 else s.2) ↑d.2
              else if d.1 < MLKEM.q then Vector.set! s.1 s.2 ↑d.1 else s.1),
            (if d.2 < MLKEM.q ∧ (if d.1 < MLKEM.q then s.2 + 1 else s.2) < 256
              then (if d.1 < MLKEM.q then s.2 + 1 else s.2) + 1
              else if d.1 < MLKEM.q then s.2 + 1 else s.2))
  simp only [apply_ite Prod.snd, apply_ite Prod.fst, h_s_eq_s_n,
             show d.1 = ↑c0 + 256 * (↑c1 % 16) from rfl,
             show d.2 = ↑c1 / 16 + 16 * ↑c2 from rfl]
  split_ifs <;> rfl

/-! ## `poly_element_sample_ntt_from_shake128_loop`

Recursive sampler with the streaming invariant: after the loop,
`pe_dst` is the fully-sampled polynomial. -/
/-- **Spec for `mlkem.ntt.poly_element_sample_ntt_from_shake128_loop`** —
rejection-sampling loop (FIPS 203 Algorithm 7). Postcondition:
`wfPoly pe_dst'` and `toPoly pe_dst' = MLKEM.SampleNTT seed`.

The loop is non-standard (reject-and-retry, not a Range iterator): `i`
advances only on acceptance; the loop may spin arbitrarily many times before
`i = 256`. Termination is argued via `sampleNttPartial` which guarantees
enough rounds always eventually fill all 256 coefficients.

Informal proof. Template: non-standard recursive loop; well-founded induction
on `256 - i.val` (the `termination_by`).
- **Mandatory first step**: `rw [poly_element_sample_ntt_from_shake128_loop.fold]`
  to expose the `_body_prefix` call inside the outer `if i.val < 256`.
  Do NOT use `unfold mlkem.ntt.poly_element_sample_ntt_from_shake128_loop`
  — `unfold` inlines the 16 bindings and prevents `step
  poly_element_sample_ntt_from_shake128_loop_body_prefix.spec` from
  firing.  SampleNTT
  uses a single-level `branch 0 (letRange 0 16)` decomposition, so
  only one `.fold` rewrite is needed — there is no `_match`).
- **`i = 256` base case**: by `sampleNttPartial_eq.spec` there exists `n_rounds`
  such that `(sampleNttPartial seed n_rounds).filledCount = 256` and the filled
  prefix equals `MLKEM.SampleNTT seed`; combine with `h_inv` (which equates
  `pe_dst[0..256)` to the partial output at round `n_rounds`) to discharge
  `toPoly pe_dst = MLKEM.SampleNTT seed`; close `wfPoly` from the coefficient
  bounds stored in `sampleNttInv`.
- **`i < 256` recursive case**: `step*` consuming
  `poly_element_sample_ntt_from_shake128_loop_body_prefix.spec` gives the
  candidate tuple `(p_state', buf', sample0, sample1, curr_buf_index',
  index_mut_back, i6)`; split on `sample0 < q` and `sample1 < q` (two
  inner-`if` branches, each possibly accepting one candidate):
  - On **accept**: call `index_mut_back` to write the candidate into
    `pe_dst'[i]` (or `pe_dst'[i+1]` for `sample1`); apply the loop IH with
    `i' = i+1` (or `i+2`), updating `sampleNttInv` by one accepted entry.
  - On **reject**: apply the loop IH with `i' = i` and the same `pe_dst`; the
    recursion terminates because `sampleNttPartial_eq_spec` bounds the total
    number of rounds.
  In all branches `sampleNttInv` is maintained by `agrind` + the body-prefix
  postcondition. Residual `wfPoly` bounds (`sample < q`) from the `if` guard.
- `termination_by (256 - i.val, nCap - n_rounds)` — lexicographic
  measure with `nCap` carried as a regular hypothesis of the
  parametric `_gen` spec (see below for the architectural split).
  * Accept arm: `i.val` strictly increases, so `256 - i.val` strictly
    drops — `Prod.Lex.left`.
  * Reject arm: `i.val` unchanged, but `n_rounds` advances by 1; we
    pay for this with `sampleNttPartial_not_full_lt`, which uses the
    invariant's `(sampleNttPartial seed n_rounds).2 = i.val < 256`
    against `hCap_full` to conclude `n_rounds < nCap` — `Prod.Lex.right`.

**Architectural note — termination factored outside the loop.**
The existential from `sampleNttPartial_eq_spec` is opened *outside*
the loop proof, in the public `@[step]` wrapper below.  The loop
itself is proved by a private `_gen` spec parametrised over an
arbitrary `nCap` and the hypotheses `hCap_full : (sampleNttPartial
seed nCap).2 = 256` / `hCap_eq : (sampleNttPartial seed nCap).1 =
SampleNTT seed`.  This keeps `termination_by` clean — it can refer
to `nCap` as a regular term — and avoids the `Classical.choose`
escape hatch that would otherwise be required to thread an
existential witness through a `partial_fixpoint`'s structural
termination spec. -/
private theorem mlkem.ntt.poly_element_sample_ntt_from_shake128_loop.spec_gen
    (seed : 𝔹 34)
    (nCap : Nat)
    (hCap_full : (sampleNttPartial seed nCap).2 = 256)
    (hCap_eq : (sampleNttPartial seed nCap).1 = MLKEM.SampleNTT seed)
    (p_state : mlkem.hash.MlKemHashState)
    (pe_dst : PolyElement)
    (i : Usize)
    (shake_output_buf : Array U8 24#usize)
    (curr_buf_index : Usize)
    (n_rounds : Nat) (g : sha3.sha3_impl.GhostState)
    (h_inv : sampleNttInv seed p_state pe_dst i shake_output_buf
              curr_buf_index n_rounds g) :
    mlkem.ntt.poly_element_sample_ntt_from_shake128_loop
        p_state pe_dst i shake_output_buf curr_buf_index
      ⦃ p_state' pe_dst' =>
          wfPoly pe_dst' ∧
          toPoly pe_dst' = MLKEM.SampleNTT seed ∧
          p_state'.alg = p_state.alg ⦄ := by
  -- Open the recursion via the `.fold` rewrite (do NOT `unfold`).
  rw [poly_element_sample_ntt_from_shake128_loop.fold]
  -- Case-split the outer `if i.val < 256`.
  split
  case isTrue h_i =>
    -- Recursive case.
    -- `step*` consumes `body_prefix.spec` (handing back the candidate
    -- tuple `(p_state1, buf', sample0, sample1, curr_buf_index2,
    -- index_mut_back, i6, _, _)`), the inline casts `i7, i8`, the outer
    -- `if i8 < MLWE` split, and on both arms it also fires the IH
    -- (this very theorem, with `nCap`/`hCap_full`/`hCap_eq` carried
    -- through unchanged), producing two recursive call sites:
    --   * accept arm  (`i8 < MLWE`):   loop p_state1 a i11 buf' ci2
    --     where `a = (index_mut_back sample0).set i8 sample1`,
    --     `i11 = i + i7 + i10 ∈ {i, i+1, i+2}`;
    --   * reject arm  (`¬ i8 < MLWE`): loop p_state1 (index_mut_back sample0) i8 buf' ci2
    --     where the boundary `i+1 = MLWE` forces `i7 = 1`.
    --
    -- After `step*`, six residual goals (in this order):
    --   1. accept: `n_rounds` metavar
    --   2. accept: `g` metavar
    --   3. reject: `n_rounds` metavar
    --   4. reject: `g` metavar
    --   5. accept: `sampleNttInv seed p_state1 a i11 buf' ci2 ?n_rounds ?g`
    --   6. reject: `sampleNttInv seed p_state1 (index_mut_back sample0) i8 buf' ci2 ?n_rounds ?g`
    --
    -- (`seed` is not a metavar — `_gen` carries it as an
    -- explicit parameter, so `step*` unifies it directly.  The fall-through
    -- `wfPoly ∧ toPoly = SampleNTT seed ∧ alg = …` conjunctions are
    -- closed automatically by `step*` from the IH's postcondition + the
    -- transitivity of `alg = …` through `p_state1.alg = p_state.alg`.)
    --
    -- Metavars get `n_rounds + 1` (one XOF chunk consumed) and `i6`
    -- (the ghost extended by `n_sq` squeezed bytes).
    step with poly_element_sample_ntt_from_shake128_loop_body_prefix.spec as
      ⟨p_state1, shake_output_buf1, sample0, sample1, curr_buf_index2, index_mut_back, i6,
       g', n_sq, p_state1_post1, p_state1_post2, p_state1_post3, p_state1_post4,
       p_state1_post5, p_state1_post6, p_state1_post7, h0, h1, h2, h_cands,
       p_state1_post9, p_state1_post10, p_state1_post11, p_state1_post12, p_state1_post13⟩
    step*
    · exact n_rounds + 1          -- 1. accept: n_rounds
    · exact g'                    -- 2. accept: g
    · exact n_rounds + 1          -- 3. reject: n_rounds
    · exact g'                    -- 4. reject: g
    · scalar_tac                  -- 5. accept: i8 = i + i7 overflow (v4.31 step* no longer auto-discharges)
    · scalar_tac                  -- 6. accept: i11 = i8 + i10 overflow
    · -- 5. accept: rebuild `sampleNttInv` at `i11`, `n_rounds + 1`.
      -- Per-sample case analysis on `i7 ∈ {0,1}` and `i10 ∈ {0,1}`
      -- (whether each candidate landed in `[0, q)`).  For each of the
      -- four leaves, use `sampleNttPartial`'s definitional unfolding
      -- at `n_rounds + 1` together with `body_prefix.spec`'s candidate
      -- equation (`p_state1_post8`) to match the spec's per-round
      -- update; the closure equations (`p_state1_post10`) lift the
      -- per-coefficient invariant from `pe_dst` to `a`.
      obtain ⟨h_i_le, h_ci_le, h_ci_mod, _h_state_old, h_absorbed, h_alg,
              h_sq_len, h_canonical, h_buf_match, h_pn,
              h_match_old, h_wf_old⟩ := h_inv
      have h_i_lt : i.val < 256 := by scalar_tac
      have h_i7_le : i7.val ≤ 1 := i7_post ▸ Bool.toNat_le _
      have h_i10_le : i10.val ≤ 1 := i10_post ▸ Bool.toNat_le _
      have h_i8_lt : i8.val < 256 := by scalar_tac
      have h_i11_le : i11.val ≤ 256 := by scalar_tac
      -- Per-sample acceptance bounds.
      -- Helper for sample0 < q when i7 = 1 (mirror of reject-arm h_aux).
      have h_aux_s0 : ∀ {z : U32}, i7.val = (decide (z < mlkem.ntt.Q)).toNat →
                                  z.val = sample0.val → i7.val = 1 →
                                  sample0.val < q := by
        intro z hz heq hi7
        rw [hi7] at hz
        have hd_true : decide (z < mlkem.ntt.Q) = true := by
          rcases hd : decide (z < mlkem.ntt.Q) with _ | _
          · rw [hd] at hz; exact absurd hz (by decide)
          · rfl
        have h_z_lt : z.val < mlkem.ntt.Q.val := of_decide_eq_true hd_true
        have h_qeq : (q : Nat) = mlkem.ntt.Q.val := by simp
        rw [h_qeq, ← heq]; exact h_z_lt
      have h_s0_when_i7 : i7.val = 1 → sample0.val < q :=
        fun h => h_aux_s0 i7_post p_state1_post9 h
      -- Helper for sample1 < q when i10 = 1.
      -- i9 = UScalar.cast U32 sample1 ⇒ i9.val = sample1.val.
      have h_i9_val : i9.val = sample1.val := by
        scalar_tac
      have h_s1_when_i10 : i10.val = 1 → sample1.val < q := by
        intro hi10
        rw [hi10] at i10_post
        have hd_true : decide (i9 < mlkem.ntt.Q) = true := by
          rcases hd : decide (i9 < mlkem.ntt.Q) with _ | _
          · rw [hd] at i10_post; exact absurd i10_post (by decide)
          · rfl
        have h_i9_lt : i9.val < mlkem.ntt.Q.val := of_decide_eq_true hd_true
        have h_qeq : (q : Nat) = mlkem.ntt.Q.val := by simp
        rw [h_qeq, ← h_i9_val]; exact h_i9_lt
      -- index_mut_back closure equations.
      obtain ⟨h_imb_len, h_imb_get⟩ := p_state1_post10 sample0
      -- Byte-bridge setup: h0/h1/h2/h_cands are named by the `step ... as` pattern.
      have h_ci2_ge_3 : curr_buf_index2.val ≥ 3 := by
        rw [p_state1_post7]; split <;> scalar_tac
      have h_idx1 : curr_buf_index2.val - 3 + 1 = curr_buf_index2.val - 2 := by omega
      have h_idx2 : curr_buf_index2.val - 3 + 2 = curr_buf_index2.val - 1 := by omega
      set c0 := (↑shake_output_buf1 : List U8)[curr_buf_index2.val - 3]'h0
      set c1 := (↑shake_output_buf1 : List U8)[curr_buf_index2.val - 2]'h1
      set c2 := (↑shake_output_buf1 : List U8)[curr_buf_index2.val - 1]'h2
      have h_alg' : p_state1.alg = mlkem.hash.MlKemHashAlg.Shake128 := by
        rw [p_state1_post4]; exact h_alg
      have h_params : mlkem.hash.MlKemHashState.algParams p_state1.alg =
                        some (g'.rate, g'.padVal) := by
        rcases p_state1_post3 with h | h
        · unfold mlkem.hash.MlKemHashState.absorbing at h; exact h.2
        · unfold mlkem.hash.MlKemHashState.squeezing at h; exact h.2
      rw [h_alg'] at h_params
      simp only [mlkem.hash.MlKemHashState.algParams, Option.some.injEq,
                  Prod.mk.injEq] at h_params
      have h_i6_rate : g'.rate = 168 := h_params.1.symm
      have h_i6_pad  : g'.padVal = 31#u8 := h_params.2.symm
      have h_i6_abs : g'.absorbed.map (·.bv) = seed.toList := by
        rw [p_state1_post1]; exact h_absorbed
      have h_sq_lb : 3 * n_rounds + 3 ≤ g'.squeezed.length := by
        rw [p_state1_post2, h_sq_len]
        rcases p_state1_post11 with ⟨hnsb, hci⟩ | ⟨hnsb, hci⟩
        · rw [hci, hnsb]; scalar_tac
        · rw [hnsb]
          have h_div : 3 ∣ curr_buf_index.val := Nat.dvd_of_mod_eq_zero h_ci_mod
          obtain ⟨q', hq'⟩ := h_div
          scalar_tac
      have h_pn_lt : (sampleNttPartial seed n_rounds).2 < 256 := by
        rw [h_pn]; exact h_i_lt
      have h_bound_k : ∀ k, k < 3 → k < 24 - curr_buf_index2.val + 3 := by
        intro k hk; scalar_tac
      have h_buf_get : ∀ k (hk : k < 3),
          g'.squeezed[3 * n_rounds + k]? =
            (↑shake_output_buf1 : List U8)[curr_buf_index2.val - 3 + k]? :=
        fun k hk => (p_state1_post13 k (h_bound_k k hk)).symm
      have h_c0_some : g'.squeezed[3 * n_rounds + 0]? = some c0 := by
        rw [h_buf_get 0 (by decide)]; exact List.getElem?_eq_getElem h0
      have h_c1_some : g'.squeezed[3 * n_rounds + 1]? = some c1 := by
        rw [h_buf_get 1 (by decide), h_idx1]; exact List.getElem?_eq_getElem h1
      have h_c2_some : g'.squeezed[3 * n_rounds + 2]? = some c2 := by
        rw [h_buf_get 2 (by decide), h_idx2]; exact List.getElem?_eq_getElem h2
      have h_round := sampleNttPartial_succ_eq_of_bytes
        seed n_rounds g' h_i6_abs h_i6_rate h_i6_pad
        p_state1_post12 h_sq_lb h_pn_lt c0 c1 c2 h_c0_some h_c1_some h_c2_some
      have h_dcands : nttCandidatesOfBytes c0 c1 c2 = (sample0.val, sample1.val) :=
        h_cands.symm
      have h_s2 : (sampleNttPartial seed n_rounds).2 = i.val := h_pn
      -- Bridges between i7/i10 and sample0/sample1 < q.
      have h_q_eq : (q : Nat) = mlkem.ntt.Q.val := by simp
      have h_mq_eq : (MLKEM.q : Nat) = q := by simp [MLKEM.q]
      have h_i7_iff_of : ∀ {z : U32},
          z.val = sample0.val →
          i7.val = (decide (z < mlkem.ntt.Q)).toNat →
          (sample0.val < MLKEM.q ↔ i7.val = 1) := by
        intro z hz hi7p
        constructor
        · intro hs0
          have h_z_lt : z.val < mlkem.ntt.Q.val := by
            rw [hz, ← h_q_eq, ← h_mq_eq]; exact hs0
          have hd : decide (z < mlkem.ntt.Q) = true := decide_eq_true h_z_lt
          rw [hi7p, hd]; rfl
        · intro hi7
          rw [hi7] at hi7p
          have hd : decide (z < mlkem.ntt.Q) = true := by
            rcases hd : decide (z < mlkem.ntt.Q) with _ | _
            · rw [hd] at hi7p; exact absurd hi7p (by decide)
            · rfl
          have h_z_lt : z.val < mlkem.ntt.Q.val := of_decide_eq_true hd
          rw [show (MLKEM.q : Nat) = q from h_mq_eq, ← hz, h_q_eq]
          exact h_z_lt
      have h_i7_iff : sample0.val < MLKEM.q ↔ i7.val = 1 :=
        h_i7_iff_of p_state1_post9 i7_post
      have h_i10_iff : sample1.val < MLKEM.q ↔ i10.val = 1 := by
        constructor
        · intro hs1
          have h_i9_lt : i9.val < mlkem.ntt.Q.val := by
            rw [h_i9_val, ← h_q_eq, ← h_mq_eq]; exact hs1
          have hd : decide (i9 < mlkem.ntt.Q) = true := decide_eq_true h_i9_lt
          rw [i10_post, hd]; rfl
        · intro hi10
          exact h_mq_eq ▸ h_s1_when_i10 hi10
      -- Build sampleNttInv.
      refine ⟨h_i11_le, ?_, ?_, p_state1_post3, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
      · -- 2: curr_buf_index2.val ≤ 24 (uses h_ci_mod to rule out 22, 23).
        rw [p_state1_post7]
        split
        · agrind
        · rename_i h_ci_ne
          have h_ci_lt : curr_buf_index.val < 24 := by agrind
          have h_div : 3 ∣ curr_buf_index.val := Nat.dvd_of_mod_eq_zero h_ci_mod
          obtain ⟨q', hq'⟩ := h_div
          have h1 : q' * 3 < 24 := by rw [Nat.mul_comm] at hq'; rw [← hq']; exact h_ci_lt
          have h2 : q' < 8 := by agrind
          rw [Nat.mul_comm] at hq'
          agrind
      · -- 3: curr_buf_index2.val % 3 = 0
        rw [p_state1_post7]
        split
        · decide
        · rw [Nat.add_mod, h_ci_mod]
      · -- 5: g'.absorbed.map (·.bv) = seed.toList
        rw [p_state1_post1]; exact h_absorbed
      · -- 6: p_state1.alg = Shake128
        rw [p_state1_post4]; exact h_alg
      · -- 7: (α) g'.squeezed.length = 3·(n_rounds+1) + (24 − ci')
        -- Combine body_prefix's NEW-1 (arm classification), post2 (length),
        -- post7 (cursor advance), and input invariant α (h_sq_len).
        rcases p_state1_post11 with ⟨h_nsb, h_ci_old⟩ | ⟨h_nsb, h_ci_old⟩
        · -- Refill arm: ci_old = 24, n_squeeze_bytes = 24, ci_new = 3.
          rw [p_state1_post2, p_state1_post7]
          simp [h_ci_old, h_nsb]
          have := h_sq_len
          agrind
        · -- Cached arm: ci_old < 24, n_squeeze_bytes = 0, ci_new = ci_old + 3.
          rw [p_state1_post2, p_state1_post7]
          have h_ci_ne : curr_buf_index.val ≠ 24 := by agrind
          simp [h_ci_ne, h_nsb]
          have := h_sq_len
          agrind
      · -- 8: (β) g'.squeezed canonical (= body_prefix's NEW-2 directly).
        exact p_state1_post12
      · -- 9: (γ) buffer-suffix coverage for next round (3·(n_rounds+1) onwards).
        -- Use body_prefix's NEW-3 unified equation specialized at k+3
        -- (skipping the 3 just-consumed bytes).
        intro k h_k
        have h_k_lt : k + 3 < 24 - curr_buf_index2.val + 3 := by agrind
        have := p_state1_post13 (k + 3) h_k_lt
        -- Rewrite indices: ci'-3+(k+3) = ci'+k; 3*n_rounds+(k+3) = 3*(n+1)+k.
        have h_lhs : curr_buf_index2.val - 3 + (k + 3) = curr_buf_index2.val + k := by
          agrind
        have h_rhs : 3 * n_rounds + (k + 3) = 3 * (n_rounds + 1) + k := by ring
        rw [h_lhs, h_rhs] at this
        exact this
      · -- 10: (sampleNttPartial seed (n_rounds + 1)).2 = i11.val
        -- Now show the .2 component matches i11.val.
        rw [h_round]
        simp only [h_dcands]
        -- Case split on sample0.val < q.
        by_cases hs0 : sample0.val < q
        · have hi7 : i7.val = 1 := h_i7_iff.mp hs0
          have h_i8_eq : i8.val = i.val + 1 := by rw [i8_post, hi7]
          have h_j1_lt_i : i.val + 1 < 256 := by rw [← h_i8_eq]; exact h_i8_lt
          by_cases hs1 : sample1.val < q
          · have hi10 : i10.val = 1 := h_i10_iff.mp hs1
            have h_i11_eq : i11.val = i.val + 2 := by
              rw [i11_post, i8_post, hi7, hi10]
            have hCond_i : sample1.val < q ∧ i.val + 1 < 256 := ⟨hs1, h_j1_lt_i⟩
            rw [if_pos hs0]
            rw [show (((sampleNttPartial seed n_rounds).2 + 1 : Nat)) = i.val + 1 by
                  rw [h_s2]]
            rw [if_pos hCond_i, h_i11_eq]
          · have hi10 : i10.val = 0 := by
              have h_not : ¬ (i10.val = 1) := fun h => hs1 (h_i10_iff.mpr h)
              agrind
            have h_i11_eq : i11.val = i.val + 1 := by
              rw [i11_post, i8_post, hi7, hi10]
            have hCond_i : ¬ (sample1.val < q ∧ i.val + 1 < 256) :=
              fun ⟨h, _⟩ => hs1 h
            rw [if_pos hs0]
            rw [show (((sampleNttPartial seed n_rounds).2 + 1 : Nat)) = i.val + 1 by
                  rw [h_s2]]
            rw [if_neg hCond_i, h_i11_eq]
        · have hi7 : i7.val = 0 := by
            have h_not : ¬ (i7.val = 1) := fun h => hs0 (h_i7_iff.mpr h)
            agrind
          have h_i8_eq : i8.val = i.val := by rw [i8_post, hi7]; ring
          by_cases hs1 : sample1.val < q
          · have hi10 : i10.val = 1 := h_i10_iff.mp hs1
            have h_i11_eq : i11.val = i.val + 1 := by
              rw [i11_post, i8_post, hi7, hi10]
            have hCond_i : sample1.val < q ∧ i.val < 256 := ⟨hs1, h_i_lt⟩
            rw [if_neg hs0]
            rw [show ((sampleNttPartial seed n_rounds).2 : Nat) = i.val from h_s2]
            rw [if_pos hCond_i, h_i11_eq]
          · have hi10 : i10.val = 0 := by
              have h_not : ¬ (i10.val = 1) := fun h => hs1 (h_i10_iff.mpr h)
              agrind
            have h_i11_eq : i11.val = i.val := by
              rw [i11_post, i8_post, hi7, hi10]; ring
            have hCond_i : ¬ (sample1.val < q ∧ i.val < 256) :=
              fun ⟨h, _⟩ => hs1 h
            rw [if_neg hs0]
            rw [show ((sampleNttPartial seed n_rounds).2 : Nat) = i.val from h_s2]
            rw [if_neg hCond_i, h_i11_eq]
      · -- 11: per-coefficient match.  4-leaf case analysis on
        -- (sample0.val < q, sample1.val < q).
        intros k h_k h_k_lt
        have h_imb_k_bound : k < (index_mut_back sample0).val.length := by
          rw [h_imb_len]; have := pe_dst.property; agrind
        -- Impl side: a[k] = if i8.val = k then sample1 else (index_mut_back sample0)[k]
        --                = if i8.val = k then sample1 else if k = i.val then sample0 else pe_dst[k].
        simp only [a_post, Std.Array.set_val_eq, List.getElem_set]
        rw [h_imb_get k h_imb_k_bound]
        -- A reusable get-of-set! decomposition.
        have h_gs : ∀ (v : MLKEM.Polynomial) (j : ℕ) (x : ZMod q) (h_j : j < 256),
            (v.set! j x).get ⟨k, h_k⟩ =
              if k = j then x else v.get ⟨k, h_k⟩ := by
          intro v j x h_j
          show (v.set! j x)[k] = _
          by_cases hk : k = j
          · rw [Vector.getElem_set! (hi := ⟨h_j, hk⟩), if_pos hk]
          · rw [Vector.getElem_set!_ne (h := ⟨Ne.symm hk, h_k⟩), if_neg hk]
            rfl
        -- Coercion helper: (n : ZMod q).val = n  when n < q.
        have h_cast : ∀ (n : ℕ) (_h : n < q), ((n : ZMod q).val : ℕ) = n := by
          intro n hn; rw [ZMod.val_natCast]; exact Nat.mod_eq_of_lt hn
        -- Spec side: compute (sampleNttPartial seed (n_rounds + 1)).1.get ⟨k, h_k⟩
        -- by case analysis on (hs0, hs1), reducing h_round in each leaf.
        by_cases hs0 : sample0.val < q
        · have hi7 : i7.val = 1 := h_i7_iff.mp hs0
          have h_i8_eq : i8.val = i.val + 1 := by rw [i8_post, hi7]
          have h_j1_lt_i : i.val + 1 < 256 := by rw [← h_i8_eq]; exact h_i8_lt
          by_cases hs1 : sample1.val < q
          · -- (i7=1, i10=1).
            have hi10 : i10.val = 1 := h_i10_iff.mp hs1
            have h_i11_eq : i11.val = i.val + 2 := by
              rw [i11_post, i8_post, hi7, hi10]
            have h_spec_eq : (sampleNttPartial seed (n_rounds + 1)).1 =
                ((sampleNttPartial seed n_rounds).1.set! i.val sample0.val).set!
                  (i.val + 1) sample1.val := by
              have hr := h_round
              simp only [h_dcands, h_s2, if_pos hs0,
                         if_pos (⟨hs1, h_j1_lt_i⟩ : sample1.val < q ∧ i.val + 1 < 256)] at hr
              rw [hr]
            rw [show ((sampleNttPartial seed (n_rounds + 1)).1.get ⟨k, h_k⟩ : ZMod q)
                  = _ from congrArg (fun v => v.get ⟨k, h_k⟩) h_spec_eq,
                h_gs _ (i.val + 1) _ h_j1_lt_i, h_gs _ i.val _ h_i_lt, h_i8_eq]
            -- Goal: ↑(if ↑i+1 = k then sample1 else if k = ↑i then sample0 else pe_dst[k])
            --     = if k = ↑i+1 then sample1.val else if k = ↑i then sample0.val else s.1[k]
            by_cases hk1 : k = i.val + 1
            · simp only [if_pos hk1, if_pos hk1.symm]
              exact (h_cast _ hs1).symm
            · have hk1' : i.val + 1 ≠ k := fun h => hk1 h.symm
              simp only [if_neg hk1, if_neg hk1']
              by_cases hk0 : k = i.val
              · simp only [if_pos hk0]
                exact (h_cast _ hs0).symm
              · simp only [if_neg hk0]
                have h_k_lt_i : k < i.val := by agrind
                exact h_match_old k h_k h_k_lt_i
          · -- (i7=1, i10=0).
            have hi10 : i10.val = 0 := by
              have h_not : ¬ (i10.val = 1) := fun h => hs1 (h_i10_iff.mpr h)
              agrind
            have h_i11_eq : i11.val = i.val + 1 := by
              rw [i11_post, i8_post, hi7, hi10]
            have hCond_neg : ¬ (sample1.val < q ∧ i.val + 1 < 256) :=
              fun ⟨h, _⟩ => hs1 h
            have h_spec_eq : (sampleNttPartial seed (n_rounds + 1)).1 =
                (sampleNttPartial seed n_rounds).1.set! i.val sample0.val := by
              have hr := h_round
              simp only [h_dcands, h_s2, if_pos hs0, if_neg hCond_neg] at hr
              rw [hr]
            rw [show ((sampleNttPartial seed (n_rounds + 1)).1.get ⟨k, h_k⟩ : ZMod q)
                  = _ from congrArg (fun v => v.get ⟨k, h_k⟩) h_spec_eq,
                h_gs _ i.val _ h_i_lt]
            -- k < i11.val = i.val + 1 = i8.val, so i8.val ≠ k.
            have h_i8_ne_k : i8.val ≠ k := by
              rw [h_i8_eq]; have := h_i11_eq; have := h_k_lt; agrind
            simp only [if_neg h_i8_ne_k]
            by_cases hk0 : k = i.val
            · simp only [if_pos hk0]
              exact (h_cast _ hs0).symm
            · simp only [if_neg hk0]
              have h_k_lt_i : k < i.val := by agrind
              exact h_match_old k h_k h_k_lt_i
        · -- sample0 rejected.
          have hi7 : i7.val = 0 := by
            have h_not : ¬ (i7.val = 1) := fun h => hs0 (h_i7_iff.mpr h)
            agrind
          have h_i8_eq : i8.val = i.val := by rw [i8_post, hi7]; ring
          by_cases hs1 : sample1.val < q
          · -- (i7=0, i10=1).
            have hi10 : i10.val = 1 := h_i10_iff.mp hs1
            have h_i11_eq : i11.val = i.val + 1 := by
              rw [i11_post, i8_post, hi7, hi10]
            have hCond_pos : sample1.val < q ∧ i.val < 256 := ⟨hs1, h_i_lt⟩
            have h_spec_eq : (sampleNttPartial seed (n_rounds + 1)).1 =
                (sampleNttPartial seed n_rounds).1.set! i.val sample1.val := by
              have hr := h_round
              simp only [h_dcands, h_s2, if_neg hs0, if_pos hCond_pos] at hr
              rw [hr]
            rw [show ((sampleNttPartial seed (n_rounds + 1)).1.get ⟨k, h_k⟩ : ZMod q)
                  = _ from congrArg (fun v => v.get ⟨k, h_k⟩) h_spec_eq,
                h_gs _ i.val _ h_i_lt, h_i8_eq]
            -- Both ifs now key on k = i.val.
            by_cases hk0 : k = i.val
            · simp only [if_pos hk0, if_pos hk0.symm]
              exact (h_cast _ hs1).symm
            · have hk0' : i.val ≠ k := fun h => hk0 h.symm
              simp only [if_neg hk0, if_neg hk0']
              have h_k_lt_i : k < i.val := by agrind
              exact h_match_old k h_k h_k_lt_i
          · -- (i7=0, i10=0): both rejected.
            have hi10 : i10.val = 0 := by
              have h_not : ¬ (i10.val = 1) := fun h => hs1 (h_i10_iff.mpr h)
              agrind
            have h_i11_eq : i11.val = i.val := by
              rw [i11_post, i8_post, hi7, hi10]; ring
            have hCond_neg : ¬ (sample1.val < q ∧ i.val < 256) :=
              fun ⟨h, _⟩ => hs1 h
            have h_spec_eq : (sampleNttPartial seed (n_rounds + 1)).1 =
                (sampleNttPartial seed n_rounds).1 := by
              have hr := h_round
              simp only [h_dcands, h_s2, if_neg hs0, if_neg hCond_neg] at hr
              rw [hr]
            rw [show ((sampleNttPartial seed (n_rounds + 1)).1.get ⟨k, h_k⟩ : ZMod q)
                  = _ from congrArg (fun v => v.get ⟨k, h_k⟩) h_spec_eq]
            have h_i8_ne_k : i8.val ≠ k := by rw [h_i8_eq]; agrind
            have h_k_ne_i : k ≠ i.val := by agrind
            simp only [if_neg h_i8_ne_k, if_neg h_k_ne_i]
            have h_k_lt_i : k < i.val := by agrind
            exact h_match_old k h_k h_k_lt_i
      · -- 12: wfPoly — four-leaf case analysis.
        intros k h_k h_k_lt
        have h_imb_k_bound : k < (index_mut_back sample0).val.length := by
          rw [h_imb_len]; have := pe_dst.property; agrind
        -- Unfold a and reduce the set/get pair.
        simp only [a_post, Std.Array.set_val_eq, List.getElem_set]
        rw [h_imb_get k h_imb_k_bound]
        -- Goal is now nested if-then-else on (k = i8) and (k = i).
        split
        · -- k = i8.val.  Then a[k] = sample1.  Need i10 = 1.
          rename_i hk_eq_i8
          have h_i10_one : i10.val = 1 := by agrind
          exact h_s1_when_i10 h_i10_one
        · -- k ≠ i8.val.  Look at the index_mut_back equation.
          rename_i hk_ne_i8
          split
          · -- k = i.val.  a[k] = sample0.  Need i7 = 1.
            have h_i7_one : i7.val = 1 := by agrind
            exact h_s0_when_i7 h_i7_one
          · -- k ≠ i.val: k < i.val.  Use old wfPoly.
            rename_i hk_ne_i
            have h_k_lt_i : k < i.val := by agrind
            exact h_wf_old k h_k h_k_lt_i
    · -- 6. reject: rebuild `sampleNttInv` at `i8 = i + 1`, `n_rounds + 1`.
      -- Here `i7 = 1` (forced by `¬ i8 < MLWE` ∧ `i.val < MLWE`); only
      -- sample0 may have been stored, so the invariant rebuild is
      -- one-step (cf. the accept arm's two-step variant).
      obtain ⟨h_i_le, h_ci_le, h_ci_mod, _h_state_old, h_absorbed, h_alg,
              h_sq_len, h_canonical, h_buf_match, h_pn,
              h_match_old, h_wf_old⟩ := h_inv
      -- Forced equalities.
      have h_i_lt : i.val < 256 := by scalar_tac
      have h_i7_le : i7.val ≤ 1 := i7_post ▸ Bool.toNat_le _
      have h_i8_ge : 256 ≤ i8.val := by scalar_tac
      have h_i7_one : i7.val = 1 := by scalar_tac
      have h_i_val : i.val = 255 := by scalar_tac
      have h_i8_val : i8.val = 256 := by scalar_tac
      -- Helper: extract sample0.val < q from i7_post + h_i7_one + p_state1_post9
      -- without naming the anonymous U32.
      have h_aux : ∀ {z : U32}, i7.val = (decide (z < mlkem.ntt.Q)).toNat →
                                z.val = sample0.val → sample0.val < q := by
        intro z hz heq
        rw [h_i7_one] at hz
        have hd_true : decide (z < mlkem.ntt.Q) = true := by
          rcases hd : decide (z < mlkem.ntt.Q) with _ | _
          · rw [hd] at hz; exact absurd hz (by decide)
          · rfl
        have h_z_lt : z.val < mlkem.ntt.Q.val := of_decide_eq_true hd_true
        have h_qeq : (q : Nat) = mlkem.ntt.Q.val := by simp
        rw [h_qeq, ← heq]; exact h_z_lt
      have h_sample0_lt_q : sample0.val < q := h_aux i7_post p_state1_post9
      -- index_mut_back closure equations.
      obtain ⟨h_imb_len, h_imb_get⟩ := p_state1_post10 sample0
      -- Byte-bridge setup: h0/h1/h2/h_cands are named by the `step ... as` pattern.
      have h_ci2_ge_3 : curr_buf_index2.val ≥ 3 := by
        rw [p_state1_post7]; split <;> scalar_tac
      have h_idx1 : curr_buf_index2.val - 3 + 1 = curr_buf_index2.val - 2 := by omega
      have h_idx2 : curr_buf_index2.val - 3 + 2 = curr_buf_index2.val - 1 := by omega
      set c0 := (↑shake_output_buf1 : List U8)[curr_buf_index2.val - 3]'h0
      set c1 := (↑shake_output_buf1 : List U8)[curr_buf_index2.val - 2]'h1
      set c2 := (↑shake_output_buf1 : List U8)[curr_buf_index2.val - 1]'h2
      have h_alg' : p_state1.alg = mlkem.hash.MlKemHashAlg.Shake128 := by
        rw [p_state1_post4]; exact h_alg
      have h_params : mlkem.hash.MlKemHashState.algParams p_state1.alg =
                        some (g'.rate, g'.padVal) := by
        rcases p_state1_post3 with h | h
        · unfold mlkem.hash.MlKemHashState.absorbing at h; exact h.2
        · unfold mlkem.hash.MlKemHashState.squeezing at h; exact h.2
      rw [h_alg'] at h_params
      simp only [mlkem.hash.MlKemHashState.algParams, Option.some.injEq,
                  Prod.mk.injEq] at h_params
      have h_i6_rate : g'.rate = 168 := h_params.1.symm
      have h_i6_pad  : g'.padVal = 31#u8 := h_params.2.symm
      have h_i6_abs : g'.absorbed.map (·.bv) = seed.toList := by
        rw [p_state1_post1]; exact h_absorbed
      have h_sq_lb : 3 * n_rounds + 3 ≤ g'.squeezed.length := by
        rw [p_state1_post2, h_sq_len]
        rcases p_state1_post11 with ⟨hnsb, hci⟩ | ⟨hnsb, hci⟩
        · rw [hci, hnsb]; scalar_tac
        · rw [hnsb]
          have h_div : 3 ∣ curr_buf_index.val :=
            Nat.dvd_of_mod_eq_zero h_ci_mod
          obtain ⟨q', hq'⟩ := h_div
          scalar_tac
      have h_pn_lt : (sampleNttPartial seed n_rounds).2 < 256 := by
        rw [h_pn]; exact h_i_lt
      have h_bound_k : ∀ k, k < 3 → k < 24 - curr_buf_index2.val + 3 := by
        intro k hk; scalar_tac
      have h_buf_get : ∀ k (hk : k < 3),
          g'.squeezed[3 * n_rounds + k]? =
            (↑shake_output_buf1 : List U8)[curr_buf_index2.val - 3 + k]? :=
        fun k hk => (p_state1_post13 k (h_bound_k k hk)).symm
      have h_c0_some : g'.squeezed[3 * n_rounds + 0]? = some c0 := by
        rw [h_buf_get 0 (by decide)]; exact List.getElem?_eq_getElem h0
      have h_c1_some : g'.squeezed[3 * n_rounds + 1]? = some c1 := by
        rw [h_buf_get 1 (by decide), h_idx1]; exact List.getElem?_eq_getElem h1
      have h_c2_some : g'.squeezed[3 * n_rounds + 2]? = some c2 := by
        rw [h_buf_get 2 (by decide), h_idx2]; exact List.getElem?_eq_getElem h2
      have h_round := sampleNttPartial_succ_eq_of_bytes
        seed n_rounds g' h_i6_abs h_i6_rate h_i6_pad
        p_state1_post12 h_sq_lb h_pn_lt c0 c1 c2 h_c0_some h_c1_some h_c2_some
      have h_dcands :
          nttCandidatesOfBytes c0 c1 c2 = (sample0.val, sample1.val) := h_cands.symm
      have h_s2 : (sampleNttPartial seed n_rounds).2 = i.val := h_pn
      -- Closed-form one-round update.  Reject arm: sample0 accepted at j=255;
      -- second write skipped because j₁=256 fails j₁<256.
      have h_round_eq :
          sampleNttPartial seed (n_rounds + 1) =
            ((sampleNttPartial seed n_rounds).1.set! i.val sample0.val, 256) := by
        rw [h_round]
        simp only [h_dcands]
        rw [h_s2]
        simp only [if_pos h_sample0_lt_q]
        have h_outer_neg : ¬ (sample1.val < q ∧ (i.val + 1) < 256) := by
          intro ⟨_, h⟩; rw [h_i_val] at h; exact absurd h (by decide)
        simp only [if_neg h_outer_neg]
        rw [h_i_val]
      -- Build sampleNttInv.
      refine ⟨?_, ?_, ?_, p_state1_post3, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
      · -- 1: i8.val ≤ 256
        scalar_tac
      · -- 2: curr_buf_index2.val ≤ 24 (uses h_ci_mod to rule out 22, 23).
        rw [p_state1_post7]
        split
        · scalar_tac  -- = 24 case: 0 + 3 = 3 ≤ 24
        · -- ≠ 24 case: curr_buf_index ≤ 21 (from ≤ 24, ≠ 24, % 3 = 0).
          rename_i h_ci_ne
          have h_ci_lt : curr_buf_index.val < 24 := by scalar_tac
          have h_div : 3 ∣ curr_buf_index.val := Nat.dvd_of_mod_eq_zero h_ci_mod
          obtain ⟨q', hq'⟩ := h_div
          have : q' * 3 < 24 := by rw [Nat.mul_comm] at hq'; rw [← hq']; exact h_ci_lt
          have : q' < 8 := by scalar_tac
          rw [Nat.mul_comm] at hq'
          scalar_tac
      · -- 3: curr_buf_index2.val % 3 = 0
        rw [p_state1_post7]
        split
        · -- = 24 case: (0 + 3) % 3 = 0
          decide
        · -- ≠ 24 case: (curr_buf_index + 3) % 3 = curr_buf_index % 3 = 0
          rw [Nat.add_mod, h_ci_mod]
      · -- 5: g'.absorbed.map (·.bv) = seed.toList
        rw [p_state1_post1]; exact h_absorbed
      · -- 6: p_state1.alg = Shake128
        rw [p_state1_post4]; exact h_alg
      · -- 7: (α) g'.squeezed.length = 3·(n_rounds+1) + (24 − ci')
        rcases p_state1_post11 with ⟨h_nsb, h_ci_old⟩ | ⟨h_nsb, h_ci_old⟩
        · rw [p_state1_post2, p_state1_post7]
          simp [h_ci_old, h_nsb]
          have := h_sq_len
          scalar_tac
        · rw [p_state1_post2, p_state1_post7]
          have h_ci_ne : curr_buf_index.val ≠ 24 := by scalar_tac
          simp [h_ci_ne, h_nsb]
          have := h_sq_len
          scalar_tac
      · -- 8: (β) g'.squeezed canonical
        exact p_state1_post12
      · -- 9: (γ) buffer-suffix coverage for next round
        intro k h_k
        have h_k_lt : k + 3 < 24 - curr_buf_index2.val + 3 := by scalar_tac
        have := p_state1_post13 (k + 3) h_k_lt
        have h_lhs : curr_buf_index2.val - 3 + (k + 3) = curr_buf_index2.val + k := by
          have h_ci2_ge_3 : curr_buf_index2.val ≥ 3 := by
            rw [p_state1_post7]; split <;> scalar_tac
          scalar_tac
        have h_rhs : 3 * n_rounds + (k + 3) = 3 * (n_rounds + 1) + k := by ring
        rw [h_lhs, h_rhs] at this
        exact this
      · -- 10: (sampleNttPartial seed (n_rounds + 1)).2 = i8.val
        rw [h_round_eq]; exact h_i8_val.symm
      · -- 11: pe_dst[0..i8) coefficient match.  k < i8.val = 256 splits into
        -- k = i.val = 255 (sample0 written, both sides agree) and k < 255
        -- (preserved on both sides via index_mut_back framing + set! at 255).
        intros k h_k h_k_lt
        have h_imb_bound : k < (index_mut_back sample0).val.length := by
          rw [h_imb_len]; have := pe_dst.property; agrind
        rw [h_imb_get k h_imb_bound]
        -- Reduce the spec side using the closed one-round update.
        rw [show (sampleNttPartial seed (n_rounds + 1)).1 =
              (sampleNttPartial seed n_rounds).1.set! i.val sample0.val from
            congrArg Prod.fst h_round_eq]
        -- `(set! i.val sample0.val).get ⟨k, _⟩` decomposes into an if on k = i.val.
        have h_get_split :
            ((sampleNttPartial seed n_rounds).1.set! i.val sample0.val).get ⟨k, h_k⟩ =
              if k = i.val then (sample0.val : ZMod q)
                           else (sampleNttPartial seed n_rounds).1.get ⟨k, h_k⟩ := by
          show ((sampleNttPartial seed n_rounds).1.set! i.val sample0.val)[k] = _
          by_cases hk : k = i.val
          · rw [Vector.getElem_set! (hi := ⟨h_i_lt, hk⟩), if_pos hk]
          · rw [Vector.getElem_set!_ne (h := ⟨Ne.symm hk, h_k⟩), if_neg hk]
            rfl
        rw [h_get_split]
        by_cases hk : k = i.val
        · -- Both sides reduce to the "k = i.val" branch.
          simp only [if_pos hk]
          rw [ZMod.val_natCast, Nat.mod_eq_of_lt h_sample0_lt_q]
        · simp only [if_neg hk]
          have h_k_lt_i : k < i.val := by scalar_tac
          exact h_match_old k h_k h_k_lt_i
      · -- 12: pe_dst[0..i8) wfPoly — closed by case-splitting on `k = i.val`.
        intros k h_k h_k_lt
        have h_imb_bound : k < ((index_mut_back sample0) : Std.Array U16 256#usize).val.length := by
          rw [h_imb_len]
          have := pe_dst.property
          agrind
        rw [h_imb_get k h_imb_bound]
        split
        · -- k = i.val: (index_mut_back sample0).val[i.val] = sample0
          exact h_sample0_lt_q
        · -- k ≠ i.val ∧ k < i8.val = 256, so k < i.val = 255
          rename_i h_ne
          apply h_wf_old k h_k
          scalar_tac
  case isFalse h_i =>
    -- Base case: `i.val ≥ 256`, but the invariant pins `i.val ≤ 256`,
    -- so `i.val = 256`.  The loop returns `ok (p_state, pe_dst)`
    -- immediately.  `step*` discharges the `p_state'.alg = p_state.alg`
    -- conjunct (trivially `rfl`); we are left with
    -- `wfPoly pe_dst ∧ toPoly pe_dst = SampleNTT seed`.
    --
    -- * `wfPoly pe_dst`: every coefficient is bounded by `q`, directly
    --   from `h_inv`'s conjunct 8 at `k < 256 = i.val`.
    -- * `toPoly pe_dst = SampleNTT seed`: chain
    --     `toPoly pe_dst = (sampleNttPartial seed n_rounds).1`  (h_match)
    --     `... = (sampleNttPartial seed nCap).1`                (stable_at_256)
    --     `... = SampleNTT seed`                                (hCap_eq)
    --   We split on `n_rounds ≤ nCap` vs `nCap ≤ n_rounds` to apply
    --   stability in the appropriate direction.
    step*
    obtain ⟨_h_i_le, _, _, _, _, _, _, _, _, h_pn, h_match, h_wf⟩ := h_inv
    have h_i_eq : i.val = 256 := by scalar_tac
    refine ⟨fun k h_k => h_wf k h_k (by omega), ?_⟩
    have h_full : (sampleNttPartial seed n_rounds).2 = 256 := by omega
    have h_eq_partial :
        (sampleNttPartial seed n_rounds).1 = MLKEM.SampleNTT seed := by
      rcases Nat.le_total n_rounds nCap with h | h
      · have h_stab := sampleNttPartial_stable_at_256 seed h_full h
        rw [← h_stab]; exact hCap_eq
      · have h_stab := sampleNttPartial_stable_at_256 seed hCap_full h
        rw [h_stab]; exact hCap_eq
    rw [← h_eq_partial]
    unfold toPoly
    apply Vector.ext
    intro k h_k
    simp only [Vector.getElem_ofFn]
    unfold u16ToZq
    rw [h_match k h_k (by omega)]
    simp [Vector.get]
termination_by (256 - i.val, nCap - n_rounds)
decreasing_by
  -- Two goals: accept arm (with `i11 = i + i7 + i10`) and reject arm
  -- (with `i8 = i + i7`).
  -- Accept arm: `i11 ∈ {i, i+1, i+2}`.  If `i11 > i` (i7 + i10 ≥ 1),
  --   close with `Prod.Lex.left`; else `i11 = i` (both candidates
  --   rejected), close with `Prod.Lex.right`, using
  --   `sampleNttPartial_not_full_lt` to pay for the second-component
  --   drop with `n_rounds < nCap`.
  -- Reject arm: `i < MLWE` and `¬ i8 < MLWE` force `i7.val = 1`,
  --   so `i8 = i + 1`; uniform `Prod.Lex.left`.
  --
  -- Both arms need the Bool.toNat bounds on `i7` (and `i10`, accept
  -- only).  Both are derived up front via `Bool.toNat_le`.
  -- Goal 1 (accept): case-split on whether `i11 > i`.
  · -- The new `step` leaves the loop-body bindings inaccessible (`_x✝…`);
    -- name them (i7, i8, the `i8 < MLWE` hyp, a, i9, i10, i11).
    rename_i i7 i8 _hi8 a i9 i10 i11
    have h_i7 : i7.val ≤ 1 := i7_post ▸ Bool.toNat_le _
    have h_i10 : i10.val ≤ 1 := i10_post ▸ Bool.toNat_le _
    by_cases h_progress : i.val < i11.val
    · -- Progress: at least one candidate accepted, `Prod.Lex.left` wins.
      exact Prod.Lex.left _ _ (by scalar_tac)
    · -- No progress: both candidates rejected, so `i11 = i`.  Pay for
      -- the round with `Prod.Lex.right` using `n_rounds < nCap`.
      have h_i_lt_256 : i.val < 256 := by scalar_tac
      have h_part : (sampleNttPartial seed n_rounds).2 < 256 := by
        have := h_inv.2.2.2.2.2.2.2.2.2.1; omega
      have h_lt := sampleNttPartial_not_full_lt seed hCap_full h_part
      have h_eq : (256 : Nat) - i11.val = 256 - i.val := by scalar_tac
      rw [h_eq]
      exact Prod.Lex.right _ (by omega)
  -- Goal 2 (reject): `i.val < MLWE` and `¬ i8 < MLWE` force `i7 = 1`,
  -- so `i8 = i + 1` and `Prod.Lex.left` closes.
  · rename_i i7 i8 _hi8
    have h_i7 : i7.val ≤ 1 := i7_post ▸ Bool.toNat_le _
    exact Prod.Lex.left _ _ (by scalar_tac)

/-- **Public spec for `mlkem.ntt.poly_element_sample_ntt_from_shake128_loop`** —
opens the `sampleNttPartial_eq_spec` existential and delegates to
`spec_gen`.  Registered `@[step]` so callers' `step*` invokes it
automatically. -/
@[step]
theorem mlkem.ntt.poly_element_sample_ntt_from_shake128_loop.spec
    (seed : 𝔹 34)
    (p_state : mlkem.hash.MlKemHashState)
    (pe_dst : PolyElement)
    (i : Usize)
    (shake_output_buf : Array U8 24#usize)
    (curr_buf_index : Usize)
    (n_rounds : Nat) (g : sha3.sha3_impl.GhostState)
    (h_inv : sampleNttInv seed p_state pe_dst i shake_output_buf
              curr_buf_index n_rounds g) :
    mlkem.ntt.poly_element_sample_ntt_from_shake128_loop
        p_state pe_dst i shake_output_buf curr_buf_index
      ⦃ p_state' pe_dst' =>
          wfPoly pe_dst' ∧
          toPoly pe_dst' = MLKEM.SampleNTT seed ∧
          p_state'.alg = p_state.alg ⦄ := by
  -- The *only* place `sampleNttPartial_eq_spec` is consumed: open it
  -- once, then delegate to the parametric `_gen` proof.
  obtain ⟨nCap, hCap_full, hCap_eq⟩ := sampleNttPartial_eq.spec seed
  exact mlkem.ntt.poly_element_sample_ntt_from_shake128_loop.spec_gen
          seed nCap hCap_full hCap_eq
          p_state pe_dst i shake_output_buf curr_buf_index
          n_rounds g h_inv

/-! ## Wrapper -/

/-- **Wrapper spec**.

Initialises an empty buffer, asserts the XOF is in SHAKE128 mode, then
runs the sampler loop. Postcondition: `toPoly pe_dst' = MLKEM.SampleNTT
seed`, where `seed` is the absorbed input from the hash ghost.

Informal proof. Template: leaf wrapper delegating entirely to the loop spec.
`unfold mlkem.ntt.poly_element_sample_ntt_from_shake128`; `step*` through:
1. `Array.repeat.spec` — creates a zeroed 24-element `shake_output_buf`.
2. `lift Array.to_slice.spec` — converts to slice; `curr_buf_index = 24`
   (= `Slice.len shake_output_buf`) so the first body-prefix call will
   immediately trigger a buffer refill.
3. `MlKemHashState.get_alg.spec` + `MlKemHashAlg.eq.spec` + `massert.spec` —
   discharge the `Shake128` alg check via `h_alg : p_state.alg = Shake128`.
4. Apply `mlkem.ntt.poly_element_sample_ntt_from_shake128_loop.spec` by
   discharging `h_inv : sampleNttInv seed p_state pe_dst 0 buf0 24 0 g`:
   - `i.val = 0 ≤ 256` by construction;
   - `curr_buf_index.val = 24 ≤ 24` by construction;
   - `absorbing ∨ squeezing` from `h_state`;
   - `g.absorbed.map (·.bv) = seed.toList` from `h_absorbed`;
   - `sampleNttPartial seed 0` vacuously agrees with `pe_dst` on zero entries.
The loop postcondition directly yields `wfPoly pe_dst'` and
`toPoly pe_dst' = MLKEM.SampleNTT seed`; close remaining goals with `agrind`. -/
@[step]
theorem mlkem.ntt.poly_element_sample_ntt_from_shake128.spec
    (seed : 𝔹 34)
    (p_state : mlkem.hash.MlKemHashState)
    (pe_dst : PolyElement)
    (g : sha3.sha3_impl.GhostState)
    (h_alg : p_state.alg = mlkem.hash.MlKemHashAlg.Shake128)
    (h_state : mlkem.hash.MlKemHashState.absorbing p_state g ∨
               mlkem.hash.MlKemHashState.squeezing p_state g)
    (h_absorbed : g.absorbed.map (·.bv) = seed.toList)
    (h_squeezed : g.squeezed = []) :
    mlkem.ntt.poly_element_sample_ntt_from_shake128 p_state pe_dst
      ⦃ p_state' pe_dst' =>
          wfPoly pe_dst' ∧
          toPoly pe_dst' = MLKEM.SampleNTT seed ∧
          p_state'.alg = p_state.alg ⦄ := by
  unfold mlkem.ntt.poly_element_sample_ntt_from_shake128
  step*
  case seed => exact seed
  case n_rounds => exact 0
  case g => exact g
  case h_inv =>
    unfold sampleNttInv
    refine ⟨by scalar_tac, ?_, ?_, h_state, h_absorbed, h_alg, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · simp [s_post]
    · -- 24 % 3 = 0
      simp [s_post]
    · -- (α) g.squeezed.length = 3·0 + (24 − 24) = 0
      simp [s_post, h_squeezed]
    · -- (β) g.squeezed canonical: [] = (extractOutput _ 0).toList = []
      simp [h_squeezed]
    · -- (γ) buffer-suffix coverage: ∀ k < 24 − 24 = 0, vacuous.
      intros k h_k
      simp [s_post] at h_k
    · simp [sampleNttPartial, sampleNttPartialAux]
    · intros k _ h; exact absurd h (by scalar_tac)
    · intros k _ h; exact absurd h (by scalar_tac)
  exact ⟨p_state'_post1, p_state'_post2, p_state'_post3⟩

end Symcrust.Properties.MLKEM
