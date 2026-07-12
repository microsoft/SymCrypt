/-
  # Encoding/Compress.lean — Top + vector compress-and-encode specs.

  The per-coefficient body and loop specs are in `CompressLoop.lean`.
-/
import Symcrust.Properties.MLKEM.Encoding.CompressLoop

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust

namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

private theorem compress_top_coeff_list_eq
    (d : ℕ) (pe_src : PolyElement)
    (coeffs_remaining : List ℕ)
    (h_coeffs_len : coeffs_remaining.length = 256)
    (h_pe_len : pe_src.val.length = 256)
    (h_pe_cr : ∀ (k : ℕ) (h_k : k < coeffs_remaining.length),
        coeffs_remaining[k] = (pe_src.val[k]'(by
          rw [h_pe_len, ← h_coeffs_len]; exact h_k)).val) :
    (List.map (fun c : ℕ => coeffToEncode d (((c : ZMod q) : Zq).cast)) coeffs_remaining)
      = (Vector.ofFn (fun i : Fin 256 =>
          coeffToEncode d ((toPoly pe_src).get i))).toList := by
  apply List.ext_getElem
  · simp [h_coeffs_len]
  · intro k hk1 _hk2
    have h_k_lt : k < coeffs_remaining.length := by
      simp only [List.length_map] at hk1; exact hk1
    have h_k_lt256 : k < 256 := by
      rw [h_coeffs_len] at h_k_lt; exact h_k_lt
    simp only [List.getElem_map]
    rw [Vector.getElem_toList, Vector.getElem_ofFn]
    fcongr 1
    rw [h_pe_cr k h_k_lt]
    unfold toPoly u16ToZq
    rw [Vector_get_ofFn]
    simp

/-- **Top spec for `poly_element_compress_and_encode`** — full FC.

The output `r` is exactly `compressEncodePoly d (toPoly pe_src)`
as a `𝔹 (32 * d)` byte buffer.

  **Informal proof.**
  `unfold mlkem.ntt.poly_element_compress_and_encode; step*` through
  the iterator setup (cast `pe_src.val` to a `Slice U16`, build `Iter`).
  Then `step with mlkem.ntt.poly_element_compress_and_encode_loop.spec`
  instantiating `s_in := CompressEncodeState.init d` (the empty stream
  state) and `accumulator := 0#u32`, `n_bits_in_accumulator := 0#u32`,
  which satisfy `matchesRuntime` by `simp [matchesRuntime, init]`
  (the initial `b` is `List.replicate (32*d) 0`, agreeing with the
  caller-supplied `pb_dst` of any byte content — wait, this requires
  that the runtime `pb_dst` and the stream `s_in.b` both start as
  "all-zero buffer of the right length").

  **Caveat on initial buffer content**: the Rust implementation
  *overwrites* `pb_dst` rather than reading it (all output bytes
  come from `copy_from_slice(...acc1.to_le_bytes())`).  So the
  initial `s_in.b` can be ANY buffer of length `32 * d` and the
  Stream evolution will agree as long as we restate `matchesRuntime`
  in terms of `pb_dst.val`'s ACTUAL content (not a fixed zero buffer).
  Concretely: at the top spec entry, choose
  `s_in := { b := pb_dst.val.map (·.bv), bi := 0, acc := 0#32, acci := 0 }`
  so `matchesRuntime` holds reflexively.

  The loop post then gives `s_out = recBody d coeffs s_in` and
  `matchesRuntime s_out pb_dst' cb_dst_written' acc_final n_bits_left`.

  Post-loop, `massert (n_bits_in_accumulator = 0)` forces
  `n_bits_left.val = 0`, hence `cb_dst_written'.val = 32 * d`
  (by `length_inv` at the end of the fold: at `i = 256` we have
  `s_out.bi = 4 * (d * 256 / 32) = 32 * d`).

  **Bridge 1 application**: by
  `streamCompressEncodePoly_eq.spec d (toPoly pe_src)`,
  `streamCompressEncodePoly d F = (compressEncodePoly d F h_d).toList`.
  By construction `s_out.b = streamCompressEncodePoly d (toPoly pe_src)`
  (since `s_in` started as the all-overwritten initial state and
  `recBody` produces exactly the encoded output).  By `matchesRuntime`,
  the first `32 * d` bytes of `pb_dst'` agree (`.bv`-wise) with
  `s_out.b`.  Converting to `sliceToSpecBytes r` (which is
  `Vector.ofFn (fun i => (r.val[i.val]).bv)`) yields exactly the
  FIPS output.

  The `toPoly pe_src` argument is well-formed: `h_wf : wfPoly pe_src`
  gives `(pe_src.val[i]).val < q` for every `i`, so the ZMod cast in
  `coeffToEncode d (toPoly pe_src).get i` is the canonical
  representative. -/
@[step]
theorem mlkem.ntt.poly_element_compress_and_encode.spec
    (pe_src : PolyElement) (n_bits_per_coefficient : U32)
    (pb_dst : Slice U8)
    (h_d : 1 ≤ n_bits_per_coefficient.val ∧ n_bits_per_coefficient.val ≤ 12)
    (h_wf : wfPoly pe_src)
    (h_len : pb_dst.length = n_bits_per_coefficient.val * 32) :
    mlkem.ntt.poly_element_compress_and_encode pe_src n_bits_per_coefficient pb_dst
      ⦃ (r : Slice U8) =>
          ∃ (h_r_len : r.length = 32 * n_bits_per_coefficient.val),
            sliceToSpecBytes r (32 * n_bits_per_coefficient.val) h_r_len
              = compressEncodePoly n_bits_per_coefficient.val
                  (toPoly pe_src) ⟨h_d.1, h_d.2⟩ ⦄ := by
  unfold mlkem.ntt.poly_element_compress_and_encode
  step*
  · -- s_in: pick the initial CompressEncodeState
    exact Bridges.CompressEncodeState.init n_bits_per_coefficient.val
  · -- h_match: matchesRuntime at the initial state
    unfold Bridges.CompressEncodeState.matchesRuntime
    refine ⟨?_, ?_, ?_, ?_, ?_, by simp, ?_, ?_⟩
    · simp [Bridges.CompressEncodeState.init, h_len, Nat.mul_comm]
    · simp
    · simp [Bridges.CompressEncodeState.init]
    · intro k hk; simp at hk
    · simp [Bridges.CompressEncodeState.init]
    · simp [Bridges.CompressEncodeState.init]
    · intro j _; simp [Bridges.CompressEncodeState.init]
  · -- h_len_inv at i=0
    unfold Bridges.CompressEncodeState.length_inv
    refine ⟨?_, ?_, ?_, ?_⟩
    · simp [Bridges.CompressEncodeState.init]
    · rw [iter_post2]; omega
    · simp [Bridges.CompressEncodeState.init, iter_post2]
    · simp [Bridges.CompressEncodeState.init, iter_post2]
  · -- h_wf_iter: well-formedness of input polynomial coefficients
    intro k h_k
    have h_iter_eq : iter.slice.val = pe_src.val := by
      rw [iter_post1, s_post]; rfl
    have h_iter_len : iter.slice.length = 256 := by
      rw [iter_post1, s_post]; simp [Aeneas.Std.Array.to_slice]
    have h_ik_eq : iter.i + k = k := by rw [iter_post2]; ring
    have h_k' : k < 256 := h_iter_len ▸ h_ik_eq ▸ h_k
    have h_pek_lt : k < pe_src.val.length := by
      have : pe_src.val.length = 256 := pe_src.property
      omega
    have h_idx : iter.slice.val[iter.i+k]'h_k = pe_src.val[k]'h_pek_lt := by
      have h_step : iter.slice.val[iter.i+k]'h_k = iter.slice.val[k]'(h_ik_eq ▸ h_k) := by
        fcongr 1
      rw [h_step]
      exact List.getElem_of_eq h_iter_eq (h_ik_eq ▸ h_k)
    rw [h_idx]
    exact h_wf k h_k'
  -- Post-loop arm: unfold matchesRuntime + length_inv to pin
  -- n_bits_in_accumulator = 0 and cb_dst_written = 32*d.
  rename_i coeffs_remaining s_out acc_final
  -- Extract length_inv preservation from the loop spec post via recBody.
  have h_iter_len256 : iter.slice.length = 256 := by
    rw [iter_post1, s_post]; simp [Aeneas.Std.Array.to_slice]
  have h_coeffs_len : coeffs_remaining.length = 256 := by
    rw [pb_dst1_post2, h_iter_len256, iter_post2]
  -- s_out came from recBody d (mapped coeffs of length 256) (init d).
  -- By recBody_length_inv (foundation lemma), length_inv holds at i=256.
  -- Then matchesRuntime gives us acci=n_bia.val, bi=cb.val.
  have h_d_pos : 1 ≤ n_bits_per_coefficient.val := h_d.1
  have h_d_le : n_bits_per_coefficient.val ≤ 12 := h_d.2
  have h_len_inv_init :
      Bridges.CompressEncodeState.length_inv n_bits_per_coefficient.val
        (Bridges.CompressEncodeState.init n_bits_per_coefficient.val) 0 := by
    refine ⟨?_, ?_, ?_, ?_⟩
    · simp [Bridges.CompressEncodeState.init]
    · omega
    · simp [Bridges.CompressEncodeState.init]
    · simp [Bridges.CompressEncodeState.init]
  -- The mapped-coeffs list has length 256.
  have h_mapped_len :
      (coeffs_remaining.map (fun (c : Nat) =>
        Bridges.coeffToEncode n_bits_per_coefficient.val
          (ZMod.cast (c : ZMod q) : Zq))).length = 256 := by
    rw [List.length_map, h_coeffs_len]
  -- Apply recBody_length_inv: length_inv at i = 0 + 256 = 256.
  have h_len_inv_out :
      Bridges.CompressEncodeState.length_inv n_bits_per_coefficient.val s_out 256 := by
    rw [pb_dst1_post4]
    have h_bound : 0 + (coeffs_remaining.map (fun (c : Nat) =>
        Bridges.coeffToEncode n_bits_per_coefficient.val
          (ZMod.cast (c : ZMod q) : Zq))).length ≤ 256 := by
      rw [h_mapped_len]
    have := Bridges.CompressEncodeState.recBody_length_inv
              n_bits_per_coefficient.val
              (coeffs_remaining.map (fun (c : Nat) =>
                Bridges.coeffToEncode n_bits_per_coefficient.val
                  (ZMod.cast (c : ZMod q) : Zq)))
              (Bridges.CompressEncodeState.init n_bits_per_coefficient.val)
              0 h_d h_bound h_len_inv_init
    rw [h_mapped_len] at this
    simpa using this
  -- Extract s_out.bi and s_out.acci values.
  have h_bi : s_out.bi = 32 * n_bits_per_coefficient.val := by
    have ⟨_, _, h_bi_eq, _⟩ := h_len_inv_out
    have h_div : (n_bits_per_coefficient.val * 256) / 32 = 8 * n_bits_per_coefficient.val := by
      have h_eq : n_bits_per_coefficient.val * 256 = 32 * (8 * n_bits_per_coefficient.val) := by ring
      rw [h_eq]
      exact Nat.mul_div_cancel_left (8 * n_bits_per_coefficient.val) (by omega : (32:ℕ) > 0)
    rw [h_bi_eq, h_div]; ring
  have h_acci : s_out.acci = 0 := by
    have ⟨_, _, _, h_acci_eq⟩ := h_len_inv_out
    have h_eq : n_bits_per_coefficient.val * 256 = 32 * (8 * n_bits_per_coefficient.val) := by ring
    rw [h_acci_eq, h_eq, Nat.mul_mod_right]
  -- Pin n_bits_in_accumulator and cb_dst_written via matchesRuntime.
  have ⟨h_blen, h_cb_le, h_bi_eq_cb, h_byteeq, h_acci_eq_nbia, h_nbia_le32,
        h_acc_eq, h_acc_zero⟩ := pb_dst1_post5
  have h_nbia_zero : n_bits_in_accumulator.val = 0 := by
    rw [← h_acci_eq_nbia, h_acci]
  have h_cb_val : cb_dst_written.val = 32 * n_bits_per_coefficient.val := by
    rw [← h_bi_eq_cb, h_bi]
  have h_pb1_len : pb_dst1.length = 32 * n_bits_per_coefficient.val := by
    rw [pb_dst1_post1, h_len]; ring
  -- After step*, three residual goals remain:
  --   (a) n_bits_per_coefficient.val * i1.val ≤ U32.max (overflow for `*`)
  --   (b) cb_dst_written = i3 (the post-loop massert)
  --   (c) the existential FC
  have h_nbia_eq_lit : n_bits_in_accumulator = (0#u32 : U32) := by
    apply Aeneas.Std.UScalar.eq_of_val_eq
    simp [h_nbia_zero]
  step*
  /- Residual condition-B — top spec final FC equality.

     Both post-loop masserts + intermediate overflow checks discharged.
     Only the final byte-vector equality remains:

        sliceToSpecBytes pb_dst1 (32*d) h_r_len = compressEncodePoly d (toPoly pe_src) h_d

     **Strategy.**
       1. `unfold sliceToSpecBytes; apply Vector.ext`. Goal becomes
          `(pb_dst1.val[i]'_).bv = (compressEncodePoly d ...).get i`.
       2. Bridge via s_out.b:
          - pb_dst1[i].bv = s_out.b[i] (from h_byteeq at i < cb=32d).
          - s_out.b = (recBody d (List.map ...) (init d)).b
                  = streamCompressEncodePoly d (toPoly pe_src) modulo
                    showing coeffs_remaining = (Vector.ofFn pe_src.val).toList
                    (per pb_dst1_post3).
       3. Apply Bridge 1 `streamCompressEncodePoly_eq.spec` to bridge to
          (compressEncodePoly _ _ _).toList.
       4. Index-wise equality.

     **Dependencies.** ONLY `streamCompressEncodePoly_eq.spec` (Bridge 1).
  -/
  refine ⟨h_pb1_len, ?_⟩
  -- Identify the per-coefficient lists (hoisted to a private helper
  -- to keep elaboration in a small context — see comment above).
  have h_pe_len : pe_src.val.length = 256 := by
    have := pe_src.property; scalar_tac
  have h_pe_cr : ∀ (k : ℕ) (h_k : k < coeffs_remaining.length),
      coeffs_remaining[k] = (pe_src.val[k]'(by
        rw [h_pe_len, ← h_coeffs_len]; exact h_k)).val := by
    intro k h_k
    obtain ⟨_, _, h_cr_k⟩ := pb_dst1_post3 k h_k
    rw [h_cr_k]
    simp only [iter_post1, s_post, iter_post2, Nat.zero_add,
               Aeneas.Std.Array.val_to_slice]
  have h_coeff_list_eq :=
    compress_top_coeff_list_eq n_bits_per_coefficient.val pe_src
      coeffs_remaining h_coeffs_len h_pe_len h_pe_cr
  -- Bridge s_out.b to streamCompressEncodePoly d (toPoly pe_src).
  have h_sout_b : s_out.b =
      streamCompressEncodePoly n_bits_per_coefficient.val (toPoly pe_src) := by
    unfold streamCompressEncodePoly
    rw [pb_dst1_post4, h_coeff_list_eq]
  -- Bridge to (compressEncodePoly _ _ _).toList via Bridge 1.
  have h_sout_toList : s_out.b =
      (compressEncodePoly n_bits_per_coefficient.val (toPoly pe_src) h_d).toList := by
    rw [h_sout_b, streamCompressEncodePoly_eq.spec _ _ h_d]
  -- Now finish Vector ext.
  apply Vector.ext
  intro i hi
  unfold sliceToSpecBytes
  rw [Vector.getElem_ofFn]
  -- RHS: bridge to s_out.b via toList.
  have h_i_lt_toList :
      i < (compressEncodePoly n_bits_per_coefficient.val (toPoly pe_src) h_d).toList.length := by
    simp; exact hi
  have h_i_lt_cb : i < cb_dst_written.val := by rw [h_cb_val]; exact hi
  have h_be := h_byteeq i h_i_lt_cb
  have h_i_lt_b : i < s_out.b.length := by
    rw [h_blen, h_pb1_len]; exact hi
  have h_i_lt_pb : i < pb_dst1.val.length := by
    rw [show pb_dst1.val.length = pb_dst1.length from rfl, h_pb1_len]; exact hi
  rw [List.getD_eq_getElem _ _ h_i_lt_b] at h_be
  rw [List.getD_eq_getElem _ _ h_i_lt_pb] at h_be
  -- Now h_be : s_out.b[i] = pb_dst1.val[i].bv.
  -- Goal: pb_dst1.val[i].bv = (compressEncodePoly _ _ _)[i]
  rw [← h_be]
  -- Bridge through a typed equality to dodge the motive issue.
  rw [show s_out.b[i]'h_i_lt_b
        = (compressEncodePoly n_bits_per_coefficient.val (toPoly pe_src) h_d).toList[i]'h_i_lt_toList
      from by simp_rw [h_sout_toList]]
  exact Vector.getElem_toList _

/-! ## Vector compress

`vector_compress_and_encode_loop` enumerates `(i, pe_src)` pairs;
each iteration writes one compressed polynomial into the slice
`pb_dst[i·d·32 .. (i+1)·d·32)` via `poly_element_compress_and_encode`.

NOTE: `#decompose` cannot extract the body of this loop because the
`Enumerate` iterator adapter's `partial_fixpoint` has an LCNF
compilation issue. Spec is given monolithically. -/

/-- **Padded per-poly spec** (vector-loop variant).

Same function call as `poly_element_compress_and_encode.spec` (L1181) but
with the precondition `pb_dst.length = 32*d` *relaxed* to `32*d ≤
pb_dst.length`.  The post is correspondingly weaker: instead of equating
the whole result `r` to `compressEncodePoly`, it equates the *window*
`r[0, 32*d)`.

This unblocks the vector loop, where each iteration calls the per-poly
function on `pb_dst[i*32*d ..]` (a `RangeFrom` slice of length
`pb_dst.length - i*32*d > 32*d` until the last iteration).

NOT `@[step]` — the original rigid `.spec` is the dispatch target;
this variant is invoked manually via `step with` at the vector-loop
call site.  Proof structure mirrors the rigid spec but threads
`init_padded d pb_dst.length` instead of `init d`. -/
theorem mlkem.ntt.poly_element_compress_and_encode.spec_padded
    (pe_src : PolyElement) (n_bits_per_coefficient : U32)
    (pb_dst : Slice U8)
    (h_d : 1 ≤ n_bits_per_coefficient.val ∧ n_bits_per_coefficient.val ≤ 12)
    (h_wf : wfPoly pe_src)
    (h_len : 32 * n_bits_per_coefficient.val ≤ pb_dst.length) :
    mlkem.ntt.poly_element_compress_and_encode pe_src n_bits_per_coefficient pb_dst
      ⦃ (r : Slice U8) =>
          r.length = pb_dst.length ∧
          ∃ (h_window : 0 + 32 * n_bits_per_coefficient.val ≤ r.length),
            sliceWindowToSpecBytes r 0 (32 * n_bits_per_coefficient.val) h_window
              = compressEncodePoly n_bits_per_coefficient.val
                  (toPoly pe_src) ⟨h_d.1, h_d.2⟩ ⦄ := by
  unfold mlkem.ntt.poly_element_compress_and_encode
  step*
  · -- s_in: pick the initial CompressEncodeState (padded variant)
    exact Bridges.CompressEncodeState.init_padded n_bits_per_coefficient.val pb_dst.length
  · -- h_match: matchesRuntime at the initial state
    unfold Bridges.CompressEncodeState.matchesRuntime
    refine ⟨?_, ?_, ?_, ?_, ?_, by simp, ?_, ?_⟩
    · simp [Bridges.CompressEncodeState.init_padded]
    · simp
    · simp [Bridges.CompressEncodeState.init_padded]
    · intro k hk; simp at hk
    · simp [Bridges.CompressEncodeState.init_padded]
    · simp [Bridges.CompressEncodeState.init_padded]
    · intro j _; simp [Bridges.CompressEncodeState.init_padded]
  · -- h_len_inv at i=0
    unfold Bridges.CompressEncodeState.length_inv
    refine ⟨?_, ?_, ?_, ?_⟩
    · simp [Bridges.CompressEncodeState.init_padded]; exact h_len
    · rw [iter_post2]; omega
    · simp [Bridges.CompressEncodeState.init_padded, iter_post2]
    · simp [Bridges.CompressEncodeState.init_padded, iter_post2]
  · -- h_wf_iter: well-formedness of input polynomial coefficients
    intro k h_k
    have h_iter_eq : iter.slice.val = pe_src.val := by
      rw [iter_post1, s_post]; rfl
    have h_iter_len : iter.slice.length = 256 := by
      rw [iter_post1, s_post]; simp [Aeneas.Std.Array.to_slice]
    have h_ik_eq : iter.i + k = k := by rw [iter_post2]; ring
    have h_k' : k < 256 := h_iter_len ▸ h_ik_eq ▸ h_k
    have h_pek_lt : k < pe_src.val.length := by
      have : pe_src.val.length = 256 := pe_src.property
      omega
    have h_idx : iter.slice.val[iter.i+k]'h_k = pe_src.val[k]'h_pek_lt := by
      have h_step : iter.slice.val[iter.i+k]'h_k = iter.slice.val[k]'(h_ik_eq ▸ h_k) := by
        fcongr 1
      rw [h_step]
      exact List.getElem_of_eq h_iter_eq (h_ik_eq ▸ h_k)
    rw [h_idx]
    exact h_wf k h_k'
  -- Post-loop arm: unfold matchesRuntime + length_inv to pin
  -- n_bits_in_accumulator = 0 and cb_dst_written = 32*d.
  rename_i coeffs_remaining s_out acc_final
  have h_iter_len256 : iter.slice.length = 256 := by
    rw [iter_post1, s_post]; simp [Aeneas.Std.Array.to_slice]
  have h_coeffs_len : coeffs_remaining.length = 256 := by
    rw [pb_dst1_post2, h_iter_len256, iter_post2]
  have h_d_pos : 1 ≤ n_bits_per_coefficient.val := h_d.1
  have h_d_le : n_bits_per_coefficient.val ≤ 12 := h_d.2
  have h_len_inv_init :
      Bridges.CompressEncodeState.length_inv n_bits_per_coefficient.val
        (Bridges.CompressEncodeState.init_padded n_bits_per_coefficient.val pb_dst.length) 0 := by
    refine ⟨?_, ?_, ?_, ?_⟩
    · simp [Bridges.CompressEncodeState.init_padded]; exact h_len
    · omega
    · simp [Bridges.CompressEncodeState.init_padded]
    · simp [Bridges.CompressEncodeState.init_padded]
  have h_mapped_len :
      (coeffs_remaining.map (fun (c : Nat) =>
        Bridges.coeffToEncode n_bits_per_coefficient.val
          (ZMod.cast (c : ZMod q) : Zq))).length = 256 := by
    rw [List.length_map, h_coeffs_len]
  have h_len_inv_out :
      Bridges.CompressEncodeState.length_inv n_bits_per_coefficient.val s_out 256 := by
    rw [pb_dst1_post4]
    have h_bound : 0 + (coeffs_remaining.map (fun (c : Nat) =>
        Bridges.coeffToEncode n_bits_per_coefficient.val
          (ZMod.cast (c : ZMod q) : Zq))).length ≤ 256 := by
      rw [h_mapped_len]
    have := Bridges.CompressEncodeState.recBody_length_inv
              n_bits_per_coefficient.val
              (coeffs_remaining.map (fun (c : Nat) =>
                Bridges.coeffToEncode n_bits_per_coefficient.val
                  (ZMod.cast (c : ZMod q) : Zq)))
              (Bridges.CompressEncodeState.init_padded n_bits_per_coefficient.val pb_dst.length)
              0 h_d h_bound h_len_inv_init
    rw [h_mapped_len] at this
    simpa using this
  have h_bi : s_out.bi = 32 * n_bits_per_coefficient.val := by
    have ⟨_, _, h_bi_eq, _⟩ := h_len_inv_out
    have h_div : (n_bits_per_coefficient.val * 256) / 32 = 8 * n_bits_per_coefficient.val := by
      have h_eq : n_bits_per_coefficient.val * 256 = 32 * (8 * n_bits_per_coefficient.val) := by ring
      rw [h_eq]
      exact Nat.mul_div_cancel_left (8 * n_bits_per_coefficient.val) (by omega : (32:ℕ) > 0)
    rw [h_bi_eq, h_div]; ring
  have h_acci : s_out.acci = 0 := by
    have ⟨_, _, _, h_acci_eq⟩ := h_len_inv_out
    have h_eq : n_bits_per_coefficient.val * 256 = 32 * (8 * n_bits_per_coefficient.val) := by ring
    rw [h_acci_eq, h_eq, Nat.mul_mod_right]
  have ⟨h_blen, h_cb_le, h_bi_eq_cb, h_byteeq, h_acci_eq_nbia, h_nbia_le32,
        h_acc_eq, h_acc_zero⟩ := pb_dst1_post5
  have h_nbia_zero : n_bits_in_accumulator.val = 0 := by
    rw [← h_acci_eq_nbia, h_acci]
  have h_cb_val : cb_dst_written.val = 32 * n_bits_per_coefficient.val := by
    rw [← h_bi_eq_cb, h_bi]
  have h_pb1_len : pb_dst1.length = pb_dst.length := pb_dst1_post1
  have h_nbia_eq_lit : n_bits_in_accumulator = (0#u32 : U32) := by
    apply Aeneas.Std.UScalar.eq_of_val_eq
    simp [h_nbia_zero]
  step*
  -- Final goal: r.length + window equality
  refine ⟨h_pb1_len, ?_, ?_⟩
  · -- window bound: 32*d ≤ pb_dst1.length = pb_dst.length
    rw [Nat.zero_add, h_pb1_len]; exact h_len
  -- Window equality via padding-irrelevance lemma
  have h_pe_len : pe_src.val.length = 256 := by
    have := pe_src.property; scalar_tac
  have h_pe_cr : ∀ (k : ℕ) (h_k : k < coeffs_remaining.length),
      coeffs_remaining[k] = (pe_src.val[k]'(by
        rw [h_pe_len, ← h_coeffs_len]; exact h_k)).val := by
    intro k h_k
    obtain ⟨_, _, h_cr_k⟩ := pb_dst1_post3 k h_k
    rw [h_cr_k]
    simp only [iter_post1, s_post, iter_post2, Nat.zero_add,
               Aeneas.Std.Array.val_to_slice]
  have h_coeff_list_eq :=
    compress_top_coeff_list_eq n_bits_per_coefficient.val pe_src
      coeffs_remaining h_coeffs_len h_pe_len h_pe_cr
  have h_sout_b_take : s_out.b.take (32 * n_bits_per_coefficient.val) =
      (compressEncodePoly n_bits_per_coefficient.val (toPoly pe_src) h_d).toList := by
    rw [pb_dst1_post4]
    rw [Bridges.CompressEncodeState.recBody_init_padded_take _ _ _ h_len]
    rw [h_coeff_list_eq]
    -- LHS now equals streamCompressEncodePoly definitionally; close via Bridge 1.
    exact streamCompressEncodePoly_eq.spec _ _ h_d
  apply Vector.ext
  intro i hi
  unfold sliceWindowToSpecBytes
  rw [Vector.getElem_ofFn]
  have h_i_lt_toList :
      i < (compressEncodePoly n_bits_per_coefficient.val (toPoly pe_src) h_d).toList.length := by
    simp; exact hi
  have h_i_lt_cb : i < cb_dst_written.val := by rw [h_cb_val]; exact hi
  have h_be := h_byteeq i h_i_lt_cb
  have h_i_lt_b : i < s_out.b.length := by
    rw [h_blen, h_pb1_len]
    have : 32 * n_bits_per_coefficient.val ≤ pb_dst.length := h_len
    omega
  have h_i_lt_pb : i < pb_dst1.val.length := by
    rw [show pb_dst1.val.length = pb_dst1.length from rfl, h_pb1_len]
    have : 32 * n_bits_per_coefficient.val ≤ pb_dst.length := h_len
    omega
  rw [List.getD_eq_getElem _ _ h_i_lt_b] at h_be
  rw [List.getD_eq_getElem _ _ h_i_lt_pb] at h_be
  -- Goal: (pb_dst1.val[0 + ↑⟨i, hi⟩]'_).bv = (compressEncodePoly _ _ _)[i]
  -- Rewrite the index `0 + i` to `i` via `getElem_congr_idx`.
  rw [getElem_congr_idx (show 0 + (⟨i, hi⟩ : Fin _).val = i from Nat.zero_add i)]
  -- Now goal: (pb_dst1.val[i]'_).bv = (compressEncodePoly _ _ _)[i]
  have h_i_lt_take : i < (s_out.b.take (32 * n_bits_per_coefficient.val)).length := by
    rw [List.length_take]
    have : 32 * n_bits_per_coefficient.val ≤ s_out.b.length := by
      rw [h_blen, h_pb1_len]; exact h_len
    omega
  -- Chain via calc to dodge motive issues from dependent proof terms.
  calc (pb_dst1.val[i]'h_i_lt_pb).bv
      = s_out.b[i]'h_i_lt_b := h_be.symm
    _ = (s_out.b.take (32 * n_bits_per_coefficient.val))[i]'h_i_lt_take := by
          rw [List.getElem_take]
    _ = (compressEncodePoly n_bits_per_coefficient.val (toPoly pe_src) h_d).toList[i]'h_i_lt_toList := by
          exact getElem_congr_coll h_sout_b_take
    _ = (compressEncodePoly n_bits_per_coefficient.val (toPoly pe_src) h_d)[i]'hi :=
          Vector.getElem_toList _

/-! ## Vector compress (loop spec)

`vector_compress_and_encode_loop` enumerates `(i, pe_src)` pairs;
each iteration writes one compressed polynomial into the slice
`pb_dst[i·d·32 .. (i+1)·d·32)` via `poly_element_compress_and_encode`.

NOTE: `#decompose` cannot extract the body of this loop because the
`Enumerate` iterator adapter's `partial_fixpoint` has an LCNF
compilation issue. Spec is given monolithically. -/

/- **Loop spec** for `vector_compress_and_encode_loop` — concrete iterator.

Iterator pattern: `iter.iter.slice = pv_src.val`, `iter.iter.i.val ≤
pv_src.length`, with a "rows already done" invariant `h_done` covering
indices `< iter.iter.i.val`.  At wrapper call site `iter.iter.i = 0`,
the invariant is vacuous, and the post directly yields the wrapper's
universal FC.

Pattern invariant (`iter.count.val = iter.iter.i.val`) is maintained by the
underlying `Enumerate (Iter T)` iterator (see
`Properties/Iterators.lean:160-163`).

  **Informal proof.** `#decompose` is unavailable for this loop (LCNF
  issue, see file header).  Canonical recursive loop pattern (Variant C):
  by_cases on `iter.iter.i < iter.iter.slice.len`:
  - **`some` arm**: `let* ... ← Enumerate_SliceIter_next_some`; the
    yielded pair is `(iter.count, iter.iter.slice[iter.iter.i])`; under
    `h_iter_invar` this is `(iter.iter.i, pv_src[iter.iter.i])`; `step*`
    through index_mut + `poly_element_compress_and_encode.spec`; new
    `iter1` has `iter1.iter.i = iter.iter.i + 1`; rebuild invariants
    (`h_done` extends to include row `iter.iter.i`); recursive call by IH.
  - **`none` arm**: `let* ... ← Enumerate_SliceIter_next_none`; the
    iterator is exhausted so `iter.iter.i = iter.iter.slice.len =
    pv_src.length`; `h_done` covers all rows; post follows.
  - `termination_by pv_src.length - iter.iter.i.val`; `decreasing_by`
    `scalar_decr_tac`. -/
@[step]
theorem mlkem.ntt.vector_compress_and_encode_loop.spec
    (iter : core.iter.adapters.enumerate.Enumerate
              (core.slice.iter.Iter (PolyElement)))
    (pv_src : Slice (PolyElement))
    (n_bits_per_coefficient : U32) (pb_dst : Slice U8)
    (h_d : 1 ≤ n_bits_per_coefficient.val ∧ n_bits_per_coefficient.val ≤ 12)
    (h_wf_src : wfPolyVec pv_src)
    /- The iterator wraps `pv_src.val`. -/
    (h_iter_slice : iter.iter.slice = pv_src)
    /- Enumerate's `count` field tracks the underlying iter's cursor 1:1
       (Iterators.lean L160-163). -/
    (h_iter_invar : iter.count.val = iter.iter.i)
    /- Cursor is in bounds. -/
    (h_iter_le : iter.iter.i ≤ pv_src.length)
    /- Output buffer is long enough. -/
    (h_len : pv_src.length * (32 * n_bits_per_coefficient.val) ≤ pb_dst.length)
    /- INVARIANT: rows already processed (`i < iter.iter.i`) have been
       correctly encoded into `pb_dst`. -/
    (h_done : ∀ (i : Nat) (h_i : i < iter.iter.i),
        ∃ (h_window :
            (i + 1) * (32 * n_bits_per_coefficient.val) ≤ pb_dst.length),
          sliceWindowToSpecBytes pb_dst
              (i * (32 * n_bits_per_coefficient.val))
              (32 * n_bits_per_coefficient.val)
              (Nat.add_one_mul _ _ ▸ h_window)
            = compressEncodePoly n_bits_per_coefficient.val
                (toPoly (pv_src.val[i]'(by have := h_iter_le; scalar_tac)))
                ⟨h_d.1, h_d.2⟩) :
    mlkem.ntt.vector_compress_and_encode_loop iter n_bits_per_coefficient pb_dst
      ⦃ (r : Slice U8) =>
          r.length = pb_dst.length ∧
          /- All rows of `pv_src` are correctly encoded into `r`. -/
          ∀ (i : Nat) (h_i : i < pv_src.length),
            ∃ (h_window :
                (i + 1) * (32 * n_bits_per_coefficient.val) ≤ r.length),
              sliceWindowToSpecBytes r
                  (i * (32 * n_bits_per_coefficient.val))
                  (32 * n_bits_per_coefficient.val)
                  (Nat.add_one_mul _ _ ▸ h_window)
                = compressEncodePoly n_bits_per_coefficient.val
                    (toPoly (pv_src.val[i]'h_i)) ⟨h_d.1, h_d.2⟩ ⦄ := by
  unfold mlkem.ntt.vector_compress_and_encode_loop
  by_cases hlt : iter.iter.i < iter.iter.slice.len
  · -- SOME branch: iterator yields one more row.
    have hsl_len : iter.iter.slice.len.val = pv_src.length := by
      rw [h_iter_slice]; rfl
    have h_count_lt : iter.count.val < pv_src.length := by
      rw [h_iter_invar]; rw [hsl_len] at hlt; exact hlt
    have h_count_lt_i : iter.iter.i < pv_src.length := by
      rw [← h_iter_invar]; exact h_count_lt
    -- Bound: pv_src.length ≤ Usize.max / (32*d) — derive iter.count + 1 ≤ Usize.max
    have h_no_overflow : iter.count.val + 1 ≤ Usize.max := by
      have h_bound : pv_src.length ≤ pb_dst.length := by
        have h_d_pos : 32 * n_bits_per_coefficient.val ≥ 1 := by
          have := h_d.1; omega
        calc pv_src.length
            = pv_src.length * 1 := by ring
          _ ≤ pv_src.length * (32 * n_bits_per_coefficient.val) :=
              Nat.mul_le_mul_left _ h_d_pos
          _ ≤ pb_dst.length := h_len
      have := pb_dst.property
      scalar_tac
    -- Bound used by arithmetic side-conditions
    have h_idx_bound : iter.count.val * n_bits_per_coefficient.val * 32 ≤ pb_dst.length := by
      have h_rewrite : iter.count.val * n_bits_per_coefficient.val * 32
          = iter.count.val * (32 * n_bits_per_coefficient.val) := by ring
      rw [h_rewrite]
      calc iter.count.val * (32 * n_bits_per_coefficient.val)
          ≤ pv_src.length * (32 * n_bits_per_coefficient.val) :=
            Nat.mul_le_mul_right _ (Nat.le_of_lt h_count_lt)
        _ ≤ pb_dst.length := h_len
    have h_pb_len_ub : pb_dst.length ≤ Usize.max := pb_dst.property
    let* ⟨ o, iter1, ho, hslice', hi', hcount' ⟩ ← Enumerate_SliceIter_next_some
    rw [ho]
    simp only
    -- Drive arithmetic steps individually, stopping before poly_element_compress_and_encode
    -- so we can apply spec_padded instead of the rigid .spec.
    step  -- i1 := cast
    step  -- i2 := iter.count * i1
    step  -- i3 := MLWE_POLYNOMIAL_COEFFICIENTS / 8
    step  -- pb_dst_index := i2 * i3
    -- index_mut
    let* ⟨ s, index_mut_back, s_post1, s_post2, s_post3 ⟩ ←
      core.slice.index.SliceIndexRangeFromUsizeSlice.index_mut.step_spec
    -- Now identify pb_dst_index.val arithmetically. step has already named hypotheses
    -- as r, r_post (for cast i1), i2, i2_post, i3, i3_post, pb_dst_index, pb_dst_index_post.
    have h_pb_dst_index : pb_dst_index.val
        = iter.iter.i * (32 * n_bits_per_coefficient.val) := by
      have h_r_val : r.val = n_bits_per_coefficient.val := by
        rw [r_post]; simp
      rw [pb_dst_index_post, i2_post, i3_post, h_r_val]
      simp only [mlkem.key.MLWE_POLYNOMIAL_COEFFICIENTS]
      rw [show (256#usize).val / 8 = 32 from by decide, h_iter_invar]
      ring
    -- s.length ≥ 32*d
    have hs_len_ge : 32 * n_bits_per_coefficient.val ≤ s.length := by
      rw [s_post2, h_pb_dst_index]
      have h_one_row :
          (iter.iter.i + 1) * (32 * n_bits_per_coefficient.val) ≤ pb_dst.length := by
        calc (iter.iter.i + 1) * (32 * n_bits_per_coefficient.val)
            ≤ pv_src.length * (32 * n_bits_per_coefficient.val) :=
              Nat.mul_le_mul_right _ h_count_lt_i
          _ ≤ pb_dst.length := h_len
      have : (iter.iter.i + 1) * (32 * n_bits_per_coefficient.val)
           = iter.iter.i * (32 * n_bits_per_coefficient.val)
             + 32 * n_bits_per_coefficient.val := by ring
      omega
    -- pe_src well-formedness
    have h_pe_src_eq : iter.iter.slice[iter.iter.i] = pv_src.val[iter.count.val]'h_count_lt := by
      simp only [h_iter_slice, h_iter_invar]; rfl
    have h_pe_wf : wfPoly (iter.iter.slice[iter.iter.i]) := by
      rw [h_pe_src_eq]
      exact h_wf_src iter.count.val h_count_lt
    -- Manual application of spec_padded (NOT @[step]).
    let* ⟨ s1, hs1_len, h_window_pre, h_window_eq ⟩ ←
      mlkem.ntt.poly_element_compress_and_encode.spec_padded
        (iter.iter.slice[iter.iter.i]) n_bits_per_coefficient s h_d h_pe_wf hs_len_ge
    -- pb_dst1 := index_mut_back s1
    have h_pb_dst1_val : (index_mut_back s1).val
        = pb_dst.val.setSlice! pb_dst_index.val s1.val := s_post3 s1
    have h_pb_dst1_len : (index_mut_back s1).length = pb_dst.length := by
      show (index_mut_back s1).val.length = pb_dst.val.length
      rw [h_pb_dst1_val, List.length_setSlice!]
    -- IH preconditions for iter1
    have h_iter_slice1 : iter1.iter.slice = pv_src := by rw [hslice', h_iter_slice]
    have h_iter_invar1 : iter1.count.val = iter1.iter.i := by
      rw [hi', hcount', h_iter_invar]
    have h_iter_le1 : iter1.iter.i ≤ pv_src.length := by
      rw [hi']; have := h_count_lt_i; scalar_tac
    have h_len1 : pv_src.length * (32 * n_bits_per_coefficient.val) ≤ (index_mut_back s1).length := by
      rw [h_pb_dst1_len]; exact h_len
    -- Rebuild h_done for iter1.iter.i = iter.iter.i + 1
    have h_done1 : ∀ (j : Nat) (h_j : j < iter1.iter.i),
        ∃ (h_window :
            (j + 1) * (32 * n_bits_per_coefficient.val) ≤ (index_mut_back s1).length),
          sliceWindowToSpecBytes (index_mut_back s1)
              (j * (32 * n_bits_per_coefficient.val))
              (32 * n_bits_per_coefficient.val)
              (Nat.add_one_mul _ _ ▸ h_window)
            = compressEncodePoly n_bits_per_coefficient.val
                (toPoly (pv_src.val[j]'(by have := h_iter_le1; scalar_tac)))
                ⟨h_d.1, h_d.2⟩ := by
      intro j h_j
      rw [hi'] at h_j
      have h_window_bound :
          (j + 1) * (32 * n_bits_per_coefficient.val) ≤ (index_mut_back s1).length := by
        rw [h_pb_dst1_len]
        calc (j + 1) * (32 * n_bits_per_coefficient.val)
            ≤ pv_src.length * (32 * n_bits_per_coefficient.val) :=
              Nat.mul_le_mul_right _ (by omega)
          _ ≤ pb_dst.length := h_len
      refine ⟨h_window_bound, ?_⟩
      by_cases h_j_old : j < iter.iter.i
      · -- Old row: window preserved.
        obtain ⟨h_win_old, h_eq_old⟩ := h_done j h_j_old
        rw [← h_eq_old]
        apply Vector.ext
        intro k h_k
        unfold sliceWindowToSpecBytes
        simp only [Vector.getElem_ofFn]
        have h_k_lt : k < 32 * n_bits_per_coefficient.val := h_k
        have h_m_lt : j * (32 * n_bits_per_coefficient.val) + k < pb_dst_index.val := by
          rw [h_pb_dst_index]
          have h1 : (j + 1) * (32 * n_bits_per_coefficient.val)
                  ≤ iter.iter.i * (32 * n_bits_per_coefficient.val) :=
            Nat.mul_le_mul_right _ (by omega)
          have h_step : (j + 1) * (32 * n_bits_per_coefficient.val)
                      = j * (32 * n_bits_per_coefficient.val)
                        + 32 * n_bits_per_coefficient.val := by ring
          omega
        have h_m_lt_pb : j * (32 * n_bits_per_coefficient.val) + k < pb_dst.val.length := by
          have h_step : (j + 1) * (32 * n_bits_per_coefficient.val)
                      = j * (32 * n_bits_per_coefficient.val)
                        + 32 * n_bits_per_coefficient.val := by ring
          have h2 : (j + 1) * (32 * n_bits_per_coefficient.val) ≤ pb_dst.length :=
            h_win_old
          show j * (32 * n_bits_per_coefficient.val) + k < pb_dst.length
          omega
        have h_pb1_len_eq : (pb_dst.val.setSlice! pb_dst_index.val s1.val).length
                          = pb_dst.val.length := List.length_setSlice! _ _ _
        have h_m_lt_pb1 : j * (32 * n_bits_per_coefficient.val) + k
                        < (index_mut_back s1).val.length := by
          show _ < (index_mut_back s1).val.length
          rw [h_pb_dst1_val, h_pb1_len_eq]; exact h_m_lt_pb
        fcongr 1
        rw [List.Inhabited_getElem_eq_getElem! _ _ h_m_lt_pb1,
            List.Inhabited_getElem_eq_getElem! _ _ h_m_lt_pb,
            h_pb_dst1_val]
        exact List.getElem!_setSlice!_same _ _ _ _ (Or.inl h_m_lt)
      · -- New row j = iter.iter.i: window from h_window_eq.
        push Not at h_j_old
        have h_j_eq : j = iter.iter.i := by omega
        subst h_j_eq
        subst h_iter_slice
        -- Prove the window equality explicitly with a fully-ascribed type to
        -- avoid Lean's unification blowing up on implicit proof arguments.
        have h_inter :
            sliceWindowToSpecBytes (index_mut_back s1)
                (iter.iter.i * (32 * n_bits_per_coefficient.val))
                (32 * n_bits_per_coefficient.val)
                (by have := h_window_bound
                    have h_eq : (iter.iter.i + 1) * (32 * n_bits_per_coefficient.val)
                              = iter.iter.i * (32 * n_bits_per_coefficient.val)
                                + 32 * n_bits_per_coefficient.val := by ring
                    omega) =
            sliceWindowToSpecBytes s1 0 (32 * n_bits_per_coefficient.val) h_window_pre := by
          apply Vector.ext
          intro k h_k
          unfold sliceWindowToSpecBytes
          simp only [Vector.getElem_ofFn]
          have h_k_lt : k < 32 * n_bits_per_coefficient.val := h_k
          have h_lo : pb_dst_index.val ≤ iter.iter.i * (32 * n_bits_per_coefficient.val) + k := by
            rw [h_pb_dst_index]; omega
          have hs1_len_val : s1.val.length = s1.length := rfl
          have h_sub_lt : iter.iter.i * (32 * n_bits_per_coefficient.val) + k - pb_dst_index.val
                       < s1.val.length := by
            rw [hs1_len_val, hs1_len, h_pb_dst_index]
            have h_diff : iter.iter.i * (32 * n_bits_per_coefficient.val) + k
                        - iter.iter.i * (32 * n_bits_per_coefficient.val) = k := by omega
            rw [h_diff]; omega
          have h_pb_lt : iter.iter.i * (32 * n_bits_per_coefficient.val) + k < pb_dst.val.length := by
            have h_step : (iter.iter.i + 1) * (32 * n_bits_per_coefficient.val)
                        = iter.iter.i * (32 * n_bits_per_coefficient.val)
                          + 32 * n_bits_per_coefficient.val := by ring
            have h_one_row :
                (iter.iter.i + 1) * (32 * n_bits_per_coefficient.val) ≤ pb_dst.length := by
              calc (iter.iter.i + 1) * (32 * n_bits_per_coefficient.val)
                  ≤ iter.iter.slice.length * (32 * n_bits_per_coefficient.val) :=
                    Nat.mul_le_mul_right _ h_count_lt_i
                _ ≤ pb_dst.length := h_len
            show iter.iter.i * (32 * n_bits_per_coefficient.val) + k < pb_dst.length
            omega
          have h_pb1_len_eq : (pb_dst.val.setSlice! pb_dst_index.val s1.val).length
                            = pb_dst.val.length := List.length_setSlice! _ _ _
          have h_m_lt_pb1 : iter.iter.i * (32 * n_bits_per_coefficient.val) + k
                          < (index_mut_back s1).val.length := by
            show _ < (index_mut_back s1).val.length
            rw [h_pb_dst1_val, h_pb1_len_eq]; exact h_pb_lt
          have h_k_lt_s1' : 0 + k < s1.val.length := by
            rw [hs1_len_val, hs1_len]; omega
          fcongr 1
          rw [List.Inhabited_getElem_eq_getElem! _ _ h_m_lt_pb1,
              List.Inhabited_getElem_eq_getElem! _ _ h_k_lt_s1',
              h_pb_dst1_val]
          rw [List.getElem!_setSlice!_middle _ _ _ _ ⟨h_lo, h_sub_lt, h_pb_lt⟩]
          fcongr 1
          rw [h_pb_dst_index]; omega
        exact h_inter.trans h_window_eq
    -- Recursive call
    apply WP.spec_mono
      (mlkem.ntt.vector_compress_and_encode_loop.spec iter1 pv_src
        n_bits_per_coefficient (index_mut_back s1) h_d h_wf_src h_iter_slice1
        h_iter_invar1 h_iter_le1 h_len1 h_done1)
    intro r ⟨hr_len, hr_done⟩
    refine ⟨?_, hr_done⟩
    rw [hr_len, h_pb_dst1_len]
  · -- NONE branch: iterator exhausted.
    push Not at hlt
    let* ⟨ o, iter1, hnone, _ ⟩ ← Enumerate_SliceIter_next_none
    rw [hnone]
    simp only [WP.spec_ok]
    -- iter.iter.i ≥ iter.iter.slice.len = pv_src.length, with h_iter_le: ≤, so equal.
    have hsl_len : iter.iter.slice.len.val = pv_src.length := by
      rw [h_iter_slice]; rfl
    have h_full : iter.iter.i = pv_src.length := by
      rw [hsl_len] at hlt; omega
    refine ⟨?_, fun j h_j => ?_⟩
    · trivial
    rw [← h_full] at h_j
    exact h_done j h_j
termination_by pv_src.length - iter.iter.i
decreasing_by
  rw [hi']
  omega

/-- **Top spec for `vector_compress_and_encode`** — full FC.

Each `32·d`-byte window of the output equals
`compressEncodePoly d (toPoly pv_src[i])`. Statement shape mirrors
`vector_decode_and_decompress.spec`.

  **Informal proof.**
  `unfold mlkem.ntt.vector_compress_and_encode; step*` through
  the `Enumerate` iterator setup.  Then `step with
  mlkem.ntt.vector_compress_and_encode_loop.spec` instantiating
  `start_idx := 0`, `remaining := pv_src.val`; the length precondition
  `(0 + pv_src.length) * (32 * d) ≤ pb_dst.length` is exactly `h_len`;
  `agrind`.

  From the loop post: the universal over
  `i < pv_src.length` with `start_idx = 0` collapses the window
  offset to `i * 32 * d`; each window equality is
  `compressEncodePoly d (toPoly pv_src[i])` directly from the loop
  post's per-row clause.
  - `r.length = pb_dst.length`: from loop post + `agrind`.
  - Window bounds `(i + 1) * 32 * d ≤ pb_dst.length`: from `h_len` +
    `h_nrows` + `agrind`. -/
@[step]
theorem mlkem.ntt.vector_compress_and_encode.spec
    (pv_src : Slice (PolyElement)) (n_bits_per_coefficient : U32)
    (pb_dst : Slice U8)
    (h_d : 1 ≤ n_bits_per_coefficient.val ∧ n_bits_per_coefficient.val ≤ 12)
    (h_wf : wfPolyVec pv_src)
    (h_len : pb_dst.length =
             pv_src.length * (n_bits_per_coefficient.val * 32))
    (h_nrows : 2 ≤ pv_src.length ∧ pv_src.length ≤ 4) :
    mlkem.ntt.vector_compress_and_encode pv_src n_bits_per_coefficient pb_dst
      ⦃ (r : Slice U8) =>
          r.length = pb_dst.length ∧
          /- Per-row FC: row `i`'s `32·d`-byte window of `r` equals
             `compressEncodePoly d (toPoly pv_src[i])`. -/
          ∀ (i : Nat) (h_i : i < pv_src.length),
            ∃ (h_window :
                (i + 1) * (32 * n_bits_per_coefficient.val) ≤ r.length),
              sliceWindowToSpecBytes r
                  (i * (32 * n_bits_per_coefficient.val))
                  (32 * n_bits_per_coefficient.val)
                  (Nat.add_one_mul _ _ ▸ h_window)
                = compressEncodePoly n_bits_per_coefficient.val
                    (toPoly (pv_src.val[i]'(by have := pv_src.property; grind)))
                    ⟨h_d.1, h_d.2⟩ ⦄ := by
  unfold mlkem.ntt.vector_compress_and_encode
  step*
  · -- pv_src.len ≤ MATRIX_MAX_NROWS (= 4)
    simp [mlkem.ntt.MATRIX_MAX_NROWS]; scalar_tac
  · -- pv_src.len * i4 ≤ Usize.max
    subst i1_post
    simp [mlkem.key.MLWE_POLYNOMIAL_COEFFICIENTS] at i2_post
    scalar_tac

end Symcrust.Properties.MLKEM
