/-
  # Encoding/VectorSetZero.lean — `vector_set_zero` and
  `Key.wipe_private_state`.

  Both are `noncomputable`: the underlying `wipe_slice` is a
  side-effectful zeroization primitive that the Aeneas extraction
  marks as `noncomputable`. We mirror that with
  `noncomputable section` for the whole file.

  ## Functions

  * `mlkem.ntt.vector_set_zero_loop` — iterate via IterMut over a
    polyvec, calling `wipe_slice` on each polynomial's
    underlying `[U16; 256]` slice.
  * `mlkem.ntt.vector_set_zero` — wrapper.
  * `mlkem.key.Key.wipe_private_state` — zeroizes `s`,
    `private_seed`, and `private_random`; clears
    `has_private_seed` and `has_private_key` flags.

  ## Decompose status

  The loop body is tiny (3 monadic binds: extract slice + wipe + write
  back) and the generated helper would itself need to be
  `noncomputable`; rather than work around that, we leave the loop
  spec monolithic.
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.KeyView
import Symcrust.Properties.MLKEM.Bridges.Iterators
import Symcrust.Properties.Iterators
import Symcrust.Properties.Axioms.Wipe
import Symcrust.Properties.Axioms.System

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust

open symcrust.common
namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 4000000
set_option maxRecDepth 2048

noncomputable section

/-- **Loop spec** for `vector_set_zero_loop`.

Canonical IterMut framing pattern (analogue:
`Ntt.lean :: vector_ntt_loop.spec`): the loop is universally
quantified over an outer write-back continuation `back`, so the
spec carries three framing predicates on `back`:
* `hback_len`: length is preserved;
* `hback_writes`: positions `[0, iter.i)` already hold zero coefficients;
* `hback_rest`: positions `[iter.i, orig_slice.length)` pass through.

The exit invariant is just the conjunction "all positions hold zero
coefficients" — which combines the original `writes` for old
positions with the newly-zeroed current position.

  **Informal proof.** Inline induction over the IterMut cursor.
  - **NONE (exhausted)**: `r = back iter`; the `writes` clause for
    `j < iter.i` propagates `hback_writes`; for `j ≥ iter.i` we use
    `hback_rest` and the NONE-condition `iter.i = orig_slice.length`,
    making `j ≥ iter.i` impossible inside `[0, orig_slice.length)`.
  - **SOME (element at iter.i)**: step `IteratorIterMut.next_spec`;
    step `Array.to_slice_mut_spec` + `wipe_slice_u16_spec` to zero
    the 256 U16 coefficients of the current polynomial; recurse with
    `back' im := back (next_back im (some pe_src1))`.  The `set` at
    `iter.i` writes the wiped array; the inductive hypothesis carries
    everything home. -/
@[step]
theorem mlkem.ntt.vector_set_zero_loop.spec
    (iter : core.slice.iter.IterMut (PolyElement))
    (back : core.slice.iter.IterMut (PolyElement) →
            core.slice.iter.IterMut (PolyElement))
    (orig_slice : Slice PolyElement)
    (h_slice : iter.slice = orig_slice)
    (h_iter_i : iter.i ≤ orig_slice.length)
    (hback_len : ∀ (im : core.slice.iter.IterMut (PolyElement)),
      im.slice.length = orig_slice.length →
      (back im).slice.length = orig_slice.length)
    (hback_writes : ∀ (im : core.slice.iter.IterMut (PolyElement))
      (him : im.slice.length = orig_slice.length)
      (j : Nat) (_hj : j < iter.i)
      (k : Nat) (_hk : k < 256),
        (((back im).slice.val[j]'(by
            have := hback_len im him; have := h_iter_i; scalar_tac)).val[k]'(by
            have := ((back im).slice.val[j]'(by
              have := hback_len im him; have := h_iter_i; scalar_tac)).property
            grind)).val = 0)
    (hback_rest : ∀ (im : core.slice.iter.IterMut (PolyElement))
      (him : im.slice.length = orig_slice.length)
      (j : Nat) (_hj_ge : iter.i ≤ j) (_hj_lt : j < orig_slice.length),
        (back im).slice.val[j]'(by
          have := hback_len im him; scalar_tac)
          = im.slice.val[j]'(by scalar_tac)) :
    mlkem.ntt.vector_set_zero_loop iter back
      ⦃ (r : core.slice.iter.IterMut (PolyElement)) =>
          ∃ (h_len : r.slice.length = orig_slice.length),
            ∀ (j : Nat) (_hj : j < orig_slice.length)
              (k : Nat) (_hk : k < 256),
              ((r.slice.val[j]'(by have := h_len; scalar_tac)).val[k]'(by
                have := (r.slice.val[j]'(by have := h_len; scalar_tac)).property
                grind)).val = 0 ⦄ := by
  unfold mlkem.ntt.vector_set_zero_loop
  by_cases hlt : iter.i < iter.slice.len
  · -- SOME branch
    let* ⟨ o, iter1, next_back, h_all ⟩ ←
      core.slice.iter.IteratorIterMut.next.spec
    obtain ⟨ho, hit2_slice, hit2_i, _, hsome_set⟩ := h_all
    rw [ho]
    have hLen_eq : (↑iter.slice.len : ℕ) = iter.slice.length := by
      simp [Slice.len, Slice.length]
    have hi_pe : iter.slice.length = orig_slice.length := by rw [h_slice]
    have hi_lt : iter.i < orig_slice.length := by rw [← hi_pe]; scalar_tac
    -- pe_src := iter.slice[iter.i] : PolyElement (= Array U16 256)
    simp only []
    -- step Array.to_slice_mut yields (s, to_back) where s = pe_src.val
    let* ⟨ s_slice, to_back, hs_val, hto_back ⟩ ← Array.to_slice_mut_spec
    -- step wipe_slice_u16 yields s1 with s1.length = s_slice.length, all zeros
    let* ⟨ s1, hs1_len, hs1_zero ⟩ ← symcrust.common.wipe_slice.spec
    -- pe_src1 := to_back s1 = Array.from_slice pe_src s1 (all zeros)
    -- Recursive call setup:
    --   new back := fun im => back (next_back im (some pe_src1))
    have hs1_len_256 : s1.length = 256 := by
      rw [hs1_len]
      show s_slice.val.length = 256
      rw [hs_val]
      exact (iter.slice[iter.i]).property
    apply WP.spec_mono
      (mlkem.ntt.vector_set_zero_loop.spec iter1
        (fun im => back (next_back im (some (to_back s1))))
        orig_slice (by rw [hit2_slice, h_slice])
        (by rw [hit2_i]; scalar_tac) ?len ?writes ?rest)
    case len =>
      intro im him
      have him_set : (next_back im (some (to_back s1))).slice.length = orig_slice.length := by
        rw [hsome_set]; simp only; rw [setAtNat_length]; exact him
      exact hback_len _ him_set
    case writes =>
      intro im him j hj k hk
      rw [hit2_i] at hj
      have him_set : (next_back im (some (to_back s1))).slice.length = orig_slice.length := by
        rw [hsome_set]; simp only; rw [setAtNat_length]; exact him
      by_cases hji : j = iter.i
      · subst hji
        have hbound : iter.i < im.slice.length := by rw [him]; exact hi_lt
        have hrest := hback_rest (next_back im (some (to_back s1))) him_set iter.i
          (le_refl _) hi_lt
        have hbk_len := hback_len _ him_set
        have hkey : (back (next_back im (some (to_back s1)))).slice.val[iter.i]'(by
            have := hbk_len; scalar_tac) = to_back s1 := by
          apply hrest.trans
          simp only [hsome_set]
          simp_lists [Slice.getElem_Nat_setAtNat_eq]
        -- Lift the polynomial equality to a coefficient list equality.
        have hkey_val :
            ((back (next_back im (some (to_back s1)))).slice.val[iter.i]'(by
                have := hbk_len; scalar_tac)).val = s1.val := by
          rw [hkey, hto_back]
          exact Std.Array.from_slice_val _ _ hs1_len_256
        have hk_s1 : k < s1.val.length := by scalar_tac
        have h_zero : s1.val[k]'hk_s1 = (default : U16) := hs1_zero k (by scalar_tac)
        have h_elem_eq :
            ((back (next_back im (some (to_back s1)))).slice.val[iter.i]'(by
                have := hbk_len; scalar_tac)).val[k]'(by
                have := ((back (next_back im (some (to_back s1)))).slice.val[iter.i]'(by
                  have := hbk_len; scalar_tac)).property
                grind)
              = s1.val[k]'hk_s1 := List.getElem_of_eq hkey_val _
        rw [h_elem_eq, h_zero]; rfl
      · have hjlt : j < iter.i := by scalar_tac
        exact hback_writes (next_back im (some (to_back s1))) him_set j hjlt k hk
    case rest =>
      intro im him j hj_ge hj_lt
      rw [hit2_i] at hj_ge
      have him_set : (next_back im (some (to_back s1))).slice.length = orig_slice.length := by
        rw [hsome_set]; simp only; rw [setAtNat_length]; exact him
      have hrest := hback_rest (next_back im (some (to_back s1))) him_set j
        (by scalar_tac) hj_lt
      have hkey : (next_back im (some (to_back s1))).slice.val[j]'(by
          have := him_set; scalar_tac) = im.slice.val[j]'(by scalar_tac) := by
        simp only [hsome_set]
        simp_lists [Slice.getElem_Nat_setAtNat_ne]
      exact hrest.trans hkey
    intro r hpost; exact hpost
  · -- NONE branch
    have hge : iter.i ≥ iter.slice.len := by scalar_tac
    have hLen_eq : (↑iter.slice.len : ℕ) = iter.slice.length := by
      simp [Slice.len, Slice.length]
    have hi_eq : iter.i = orig_slice.length := by
      have hpe : iter.slice.length = orig_slice.length := by rw [h_slice]
      have : iter.slice.len.val = orig_slice.length := by
        rw [← hpe]; simp [Slice.len, Slice.length]
      scalar_tac
    let* ⟨ o, iter1, next_back, h_all ⟩ ←
      core.slice.iter.IteratorIterMut.next_spec_none
    obtain ⟨ho, hit2_eq, hsome_back⟩ := h_all
    rw [ho]
    show (Result.ok (back (next_back iter1 none))) ⦃ _ ⦄
    rw [hsome_back, hit2_eq]
    have hit_pe : iter.slice.length = orig_slice.length := by rw [h_slice]
    refine ⟨hback_len iter hit_pe, ?_⟩
    intro j hj k hk
    exact hback_writes iter hit_pe j (hi_eq ▸ hj) k hk
  termination_by iter.slice.len.val - iter.i
  decreasing_by scalar_decr_tac

/-- **Top spec for `vector_set_zero`**.

Postcondition: every coefficient of every polynomial in the result
is 0.

  **Informal proof.**
  `unfold mlkem.ntt.vector_set_zero; step*` through IterMut setup
  over `pv_src`.  `step with mlkem.ntt.vector_set_zero_loop.spec`
  instantiating:
  - `back := id` (identity continuation — no outer IterMut stack);
    `h_back_len`: `id` preserves length; `simp`.
  - `iter.i = 0` (cursor starts at beginning of slice);
    `h_i : 0 ≤ pv_src.length` from `h_n`.

  From the loop post:
  - `r.length = pv_src.length`: from `r.slice.length =
    iter.slice.length` + IterMut setup length equality; `agrind`.
  - `∀ i < r.length, ∀ k < 256, coefficient = 0`: from loop's
    `writes` clause with `iter.i = 0` (all positions ≥ 0 are in
    scope); `agrind`.
  - `h_n` discharges the IterMut `length ≤ Usize.max` bound;
    `scalar_tac`. -/
@[step]
theorem mlkem.ntt.vector_set_zero.spec
    (pv_src : Slice (PolyElement))
    (h_n : 1 ≤ pv_src.length ∧ pv_src.length ≤ 4) :
    mlkem.ntt.vector_set_zero pv_src
      ⦃ (r : Slice (PolyElement)) =>
          r.length = pv_src.length ∧
          ∀ (i : Nat) (h_i : i < r.length),
            ∀ (k : Nat) (h_k : k < 256),
              ((r.val[i]'h_i).val[k]'(by grind)).val = 0 ⦄ := by
  unfold mlkem.ntt.vector_set_zero
  simp only [step_simps]
  let* ⟨ _ ⟩ ← massert_spec
  let* ⟨ _ ⟩ ← massert_spec
  case h => simp [mlkem.ntt.MATRIX_MAX_NROWS]; scalar_tac
  step as ⟨iter, back, hslice, hi, hback⟩
  -- Apply the loop spec with `back := id`, `orig_slice := iter.slice`.
  let* ⟨ r_iter, hr_len, hr_writes ⟩ ←
    mlkem.ntt.vector_set_zero_loop.spec iter (fun im => im) iter.slice rfl
      (by rw [hi]; exact Nat.zero_le _)
      (fun _ him => him)
      (fun _ _ j hj _ _ => by rw [hi] at hj; omega)
      (fun _ _ _ _ _ => rfl)
  -- The wrapper applies the outer back closure (which writes the IterMut
  -- back into a Slice via `back` from Slice.iter_mut_spec).
  simp only [hback]
  refine ⟨by rw [hr_len, hslice], ?_⟩
  intro i h_i k h_k
  have h_i' : i < iter.slice.length := by rw [← hr_len]; exact h_i
  exact hr_writes i h_i' k h_k

/-- **Spec for `Key.wipe_private_state`**.

Postcondition: `has_private_seed = false`, `has_private_key = false`,
`s`, `private_seed`, `private_random` all zeroized; public fields
unchanged.

  **Informal proof.**
  `unfold mlkem.key.Key.wipe_private_state; step*`.  Three main
  sub-calls:
  1. `step with mlkem.ntt.vector_set_zero.spec` for `s`; requires
     `h_n : 1 ≤ s.length ∧ s.length ≤ 4` from
     `h_wf : wfKey self params`; post gives all coefficients of all
     polynomials in `s'` equal 0.
  2. `step with wipe_slice.spec` for `private_seed`; post: every byte
     of the 32-element `U8` array is 0; `h_i : i < 32` from the
     field's type property; `agrind`.
  3. `step with wipe_slice.spec` for `private_random`; post: every
     byte 0; symmetric.
  4. `step*` through the two record-update assignments
     `has_private_seed := false` and `has_private_key := false`.
  - `wfKey r params`: preserved since public fields are untouched by
    record update semantics and the key structure is compatible;
    `simp [wfKey]; agrind`.
  - Public fields (`algorithm_info`, `public_seed`, `encoded_t`,
    `encaps_key_hash`, `params`, `n_rows`) unchanged: from record
    update semantics; `rfl` or `agrind`.
  - `has_private_seed = false`, `has_private_key = false`: directly
    from the field assignments; `rfl`.
  - Private field zeros: from `wipe_slice.spec`'s per-element
    postcondition; `simp [wipe_slice_post]; agrind`. -/
@[step]
theorem mlkem.key.Key.wipe_private_state.spec
    {params : ParameterSet}
    (self : mlkem.key.Key) (h_wf : wfKey self params) :
    self.wipe_private_state
      ⦃ (r : mlkem.key.Key) =>
          wfKey r params ∧
          r.has_private_seed = false ∧
          r.has_private_key = false ∧
          /- Public fields are preserved. -/
          r.algorithm_info = self.algorithm_info ∧
          r.public_seed = self.public_seed ∧
          r.encoded_t = self.encoded_t ∧
          r.encaps_key_hash = self.encaps_key_hash ∧
          r.params = self.params ∧
          r.n_rows = self.n_rows ∧
          /- Private fields are zeroized. -/
          (∀ (i : Nat) (h_i : i < 32),
              (r.private_seed.val[i]'(by
                have := r.private_seed.property; grind)).val = 0) ∧
          (∀ (i : Nat) (h_i : i < 32),
              (r.private_random.val[i]'(by
                have := r.private_random.property; grind)).val = 0) ⦄ := by
  unfold mlkem.key.Key.wipe_private_state
  have hk_lo : 2 ≤ (k params : ℕ) := k_ge_2 params
  have hk_hi : (k params : ℕ) ≤ 4 := k_le_4 params
  simp only [step_simps]
  let* ⟨ s, h_s_len, back_s, s_wfpoly, _, s_post4 ⟩ ← mlkem.key.Key.s_mut.spec
  let* ⟨ s1, s1_len_eq, s1_zero ⟩ ← mlkem.ntt.vector_set_zero.spec
  let* ⟨ s2, to_slice_back_pr, s2_val_eq, s2_back_eq ⟩ ← Array.to_slice_mut_spec
  let* ⟨ s3, s3_len_eq, s3_zero ⟩ ← symcrust.common.wipe_slice.spec
  let* ⟨ s4, to_slice_back_ps, s4_val_eq, s4_back_eq ⟩ ← Array.to_slice_mut_spec
  let* ⟨ s5, s5_len_eq, s5_zero ⟩ ← symcrust.common.wipe_slice.spec
  have h_s1_len : s1.length = (k params : ℕ) := s1_len_eq.trans back_s
  have h_s1_wfpoly : ∀ i (_ : i < s1.length), wfPoly s1.val[i] := by
    intro i hi j hj
    have h0 := s1_zero i hi j hj
    unfold q; grind
  obtain ⟨⟨wf, hparams, hnrows, _, _, _⟩, halginfo, _, hpubseed, hencodedt, hekh, _⟩ :=
    s_post4 s1 h_s1_len h_s1_wfpoly
  have h_s4_len : s4.length = 32 := by
    show (↑s4 : List U8).length = 32
    rw [s4_val_eq]; exact (h_s_len s1).private_seed.property
  have h_s5_len : s5.length = 32 := s5_len_eq.trans h_s4_len
  have h_s2_len : s2.length = 32 := by
    show (↑s2 : List U8).length = 32
    rw [s2_val_eq]; exact (h_s_len s1).private_random.property
  have h_s3_len : s3.length = 32 := s3_len_eq.trans h_s2_len
  have h_val_ps : ((h_s_len s1).private_seed.from_slice s5).val = s5.val :=
    Std.Array.from_slice_val _ _ h_s5_len
  have h_val_pr : ((h_s_len s1).private_random.from_slice s3).val = s3.val :=
    Std.Array.from_slice_val _ _ h_s3_len
  refine ⟨⟨wfKey.params_ok (self := h_s_len s1) wf,
          wfKey.n_rows_ok (self := h_s_len s1) wf,
          wfKey.data_wf (self := h_s_len s1) wf⟩,
          halginfo, hpubseed, hencodedt, hekh, hparams, hnrows, ?_, ?_⟩
  · intro i hi
    simp only [s4_back_eq]
    have hi5 : i < s5.length := h_s5_len ▸ hi
    have hz : s5.val[i]'hi5 = (default : U8) := s5_zero i hi5
    have h_eq : ((h_s_len s1).private_seed.from_slice s5).val[i]'(h_val_ps ▸ hi5) =
                s5.val[i]'hi5 := List.getElem_of_eq h_val_ps _
    rw [h_eq, hz]; rfl
  · intro i hi
    simp only [s2_back_eq]
    have hi3 : i < s3.length := h_s3_len ▸ hi
    have hz : s3.val[i]'hi3 = (default : U8) := s3_zero i hi3
    have h_eq : ((h_s_len s1).private_random.from_slice s3).val[i]'(h_val_pr ▸ hi3) =
                s3.val[i]'hi3 := List.getElem_of_eq h_val_pr _
    rw [h_eq, hz]; rfl

end

end Symcrust.Properties.MLKEM
