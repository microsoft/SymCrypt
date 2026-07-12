/-
  # Encoding/KeySetValue.lean — `key_set_value` top-level spec.

  Assembles the per-format arm specs (`ksv_priv`, `ksv_decap`, `ksv_encap`)
  into the top-level `mlkem.key_set_value.spec`.

  The heavy lifting lives in:
  - `KeySetValue/Prelude.lean` (helpers, #decompose, shared specs)
  - `KeySetValue/Decap.lean`   (DecapsulationKey arm)
  - `KeySetValue/Encap.lean`   (EncapsulationKey arm)
-/
import Symcrust.Properties.MLKEM.Encoding.KeySetValue.Decap
import Symcrust.Properties.MLKEM.Encoding.KeySetValue.Encap

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust

open scoped Spec.Notations
open symcrust.common
namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

/-! ## Mid-level `ksv_*` composer specs

Aggregate the leaf specs above into per-arm dispatchers consumed by
`mlkem.key_set_value.spec`.  Each composer's post mirrors the
corresponding top-spec arm.  Universal `wfKey ∧ params ∧ n_rows` is
pulled outside the match; reachable errors enumerated, all other
variants `False`. -/

/-- **Spec for `ksv_priv`** — PrivateSeed format arm dispatcher
(lencheck + lendispatch → `ksv_priv_body`). -/
@[step]
theorem ksv_priv.spec
    {params : ParameterSet}
    (pb_src : Slice U8)
    (pk_mlkem_key : mlkem.key.Key)
    (p_comp_temps : mlkem.ntt.InternalComputationTemporaries)
    (h_wf : wfKey pk_mlkem_key params)
    (h_pct_max0 : wfPolyVec p_comp_temps.max_size_vector0.to_slice) :
    ksv_priv pb_src pk_mlkem_key p_comp_temps
      ⦃ err key' =>
          wfKey key' params ∧
          key'.params = pk_mlkem_key.params ∧
          key'.n_rows = pk_mlkem_key.n_rows ∧
          match err with
          | Error.NoError =>
              ∃ (h_len : pb_src.length = 64),
                key'.private_seed.toSpec = pb_src.toSpecWindow 0 32 (by simp [h_len]) ∧
                key'.private_random.toSpec = pb_src.toSpecWindow 32 32 (by simp [h_len]) ∧
                key'.has_private_seed = true ∧ key'.has_private_key = true ∧
                wfPrivateSeed key' params
          | Error.WrongKeySize => pb_src.length ≠ 64
          | _ => False ⦄ := by
  rw [ksv_priv.fold]
  step
  rw [ksv_priv_lendispatch.fold]
  split
  · -- i5 != i6 = true → WrongKeySize
    rename_i h_ne
    simp only [WP.spec_ok]
    refine ⟨h_wf, rfl, rfl, ?_⟩
    simp only [bne_iff_ne, ne_eq] at h_ne
    intro hcontra
    apply h_ne
    apply UScalar.eq_of_val_eq
    rw [i5_post1, i5_post2]; exact hcontra
  · -- i5 = i6 → call body
    rename_i h_eq
    simp only [bne_iff_ne, ne_eq, not_not] at h_eq
    have h_pas_len : pb_src.length = 64 := by
      rw [← i5_post1, ← i5_post2]; exact congrArg UScalar.val h_eq
    step
    refine ⟨err_post1, err_post2, err_post3, ?_⟩
    match err, err_post4 with
    | .NoError, h => exact ⟨h_pas_len, h⟩
    | .Unused, h | .WrongKeySize, h | .WrongBlockSize, h
    | .WrongDataSize, h | .WrongNonceSize, h | .WrongTagSize, h
    | .WrongIterationCount, h | .AuthenticationFailure, h
    | .ExternalFailure, h | .FipsFailure, h | .HardwareFailure, h
    | .NotImplemented, h | .InvalidBlob, h => exact h.elim

/-! ## `key_set_value`

Parses `pb_src` according to `blob_type ∈ {PrivateSeed,
DecapsulationKey, EncapsulationKey}` and populates the key. -/

/-- **Top spec for `key_set_value`**.

Postcondition (by blob_type):

* `EncapsulationKey`: decode encoded_t and ρ from `pb_src[0..|ek|)`;
  expand A from ρ; compute encaps_key_hash = H(ek); `has_private_*
  = false`.
* `DecapsulationKey`: parse the 32-byte private_seed +
  32-byte private_random preamble, then run
  `key_expand_from_private_seed` to populate s, t, A, etc.;
  verify recomputed `encoded_t` matches the parsed blob.
* `PrivateSeed`: parse the 32-byte private_seed +
  32-byte private_random and run `key_expand_from_private_seed`.

Returns `(Error, key)`.  Error enumeration is *tight* and *format-aware*
(no caller-correctness assumption — each variant is a defined response
to bad input):

* All formats: `NoError`, `InvalidArgument` (bad flag bits or
  `MINIMAL_VALIDATION` in FIPS path), `WrongKeySize` (length mismatch),
  `MemoryAllocationFailure` (`try_new_box_default` of
  `InternalComputationTemporaries` fails).
* `EncapsulationKey` / `DecapsulationKey` also: `InvalidBlob` (out-of-
  range 12-bit coefficient in `vector_decode_and_decompress`, or, for
  `DecapsulationKey`, recomputed `encaps_key_hash` mismatch).
* `PrivateSeed` cannot return `InvalidBlob` (no content checks on this
  branch).
* `FipsFailure` is never returned here (the PCT is run by the caller
  `key_generate`).

  **Informal proof.**
  `unfold mlkem.key_set_value`. The ~150-bind body is split into
  ~20-bind fold helpers via `#decompose letRange 0 N` (7–8 chunks).
  Top-level proof: `simp only [fold_chunk₁,
  fold_chunk₂, ...]` collapses the chunks; then `step*` runs through
  the remaining binds using the following sub-specs:
  - Length massert: `NoError`/`InvalidBlob` dispatch by
    `cases sc_error` then `agrind` per branch (`NoError`,
    `InvalidBlob`); `agrind` for length arithmetic.
  - **`PrivateSeed` branch**: `step with` slice-copy spec twice
    (private_seed ← pb_src[0..32], private_random ← pb_src[32..64]);
    byte-level equalities `arrayToSpecBytes key'.private_seed =
    sliceWindowToSpecBytes pb_src 0 32 h` from the copy post; `agrind`.
    `step with key_expand_from_private_seed.spec`; propagate the key
    expansion postcondition.
  - **`EncapsulationKey` branch**: `step with` copy spec for
    `encoded_t` bytes (384k bytes) and `public_seed` (32 bytes);
    `step with key_expand_A_from_rho.spec`;
    `step with key_compute_encapsulation_key_hash.spec`; FC equalities
    from copy posts; `agrind` for `384k + 32` arithmetic.
  - **`DecapsulationKey` branch**: length precondition
    `pb_src.length = 768k + 96`; the blob layout is
    `s ‖ encoded_t ‖ public_seed ‖ encaps_key_hash ‖ private_random`
    (lengths `384k + 384k + 32 + 32 + 32`).  The Rust impl
    (`mlkem.rs:325-385`):
    (a) `vector_decode_and_decompress(pb_src[0..384k], 12, s)` —
        decodes `s` (12-bit packed) into the runtime field;
    (b) `encoded_t[0..384k] := pb_src[384k..768k]` (direct copy)
        then `vector_decode_and_decompress(encoded_t, 12, t)`;
    (c) `public_seed := pb_src[768k..768k+32]` (direct copy) and
        re-expand A from ρ;
    (d) recompute `encaps_key_hash := SHA3-256(encoded_t ‖ public_seed)`
        and verify it equals `pb_src[768k+32..768k+64]`; on mismatch
        return `InvalidBlob`;
    (e) `private_random := pb_src[768k+64..768k+96]`;
    (f) set `has_private_seed = false`, `has_private_key = true`.
    The post commits to the directly-observable equalities (public_seed,
    encaps_key_hash, private_random, encoded_t prefix) plus the
    re-derived hash check (`SHA3-256(ek) = encaps_key_hash`).  The full
    `decapsulationKey key' params = sliceToSpecBytes pb_src …`
    equality additionally needs the round-trip
    `ByteEncode₁₂(ByteDecode₁₂(pb_src[0..384k])) = pb_src[0..384k]`,
    which holds iff every encoded 12-bit coefficient is `< q` — the
    same well-formedness condition as `Encaps.KeyCheck`.  We capture
    this via the optional `Encaps.KeyCheck` clause on the inner ek slice
    in the FC postcondition; under `FLAG_KEY_MINIMAL_VALIDATION` the
    impl trusts the input, so the equality is conditional on that
    well-formedness.  `step with key_expand_public_matrix_from_public_seed.spec`,
    `step with key_compute_encapsulation_key_hash.spec`,
    `step with const_time_slices_equal.spec`, `step with` slice-copy
    spec for `private_random`; `agrind` for offset arithmetic.
  - `wfKey key' params`: each field assignment preserves `wfKey` since
    only allowed fields are written; `simp [wfKey]; agrind`.
  - `InvalidArgument` arm: `True` (defined behaviour on bad flag bits).
  - `WrongKeySize` arm: `True` (defined behaviour on length mismatch).
  - `InvalidBlob` arm: `format ≠ PrivateSeed`.  The `PrivateSeed` branch
    has no content validation, so this is discharged by case-analysis
    on `format`; on `Encap`/`Decap` the witness comes from
    `vector_decode_and_decompress.spec` (`d = 12` precondition) or the
    `const_time_slices_equal` mismatch branch.
  - `MemoryAllocationFailure` arm: `out_of_memory` (allocator failure
    on `try_new_box_default`, whose `Err` post supplies the witness). -/
@[step]
theorem mlkem.key_set_value.spec
    {params : ParameterSet}
    (pb_src : Slice U8)
    (format : mlkem.key.Format)
    (flags : U32)
    (pk_mlkem_key : mlkem.key.Key)
    (h_wf : wfKey pk_mlkem_key params) :
    mlkem.key_set_value pb_src format flags pk_mlkem_key
      ⦃ err key' =>
          -- Universal conjuncts (preserved across every return arm — error
          -- branches return the input key literally, the success branch
          -- preserves `params`/`n_rows` and re-establishes `wfKey` via
          -- `key_expand_from_private_seed`).  Pulled out of the `match`
          -- so callers don't have to case-split to obtain them.
          wfKey key' params ∧
          key'.params = pk_mlkem_key.params ∧
          key'.n_rows = pk_mlkem_key.n_rows ∧
          match err with
          | Error.NoError =>
              (match format with
               | mlkem.key.Format.PrivateSeed =>
                   ∃ (h_len : pb_src.length = 64),
                     /- Raw seed bytes copied from the input blob. -/
                     key'.private_seed.toSpec = pb_src.toSpecWindow 0 32 (by simp [h_len]) ∧
                     key'.private_random.toSpec = pb_src.toSpecWindow 32 32 (by simp [h_len]) ∧
                     /- Flags reflect a fully-populated private key. -/
                     key'.has_private_seed = true ∧ key'.has_private_key = true ∧
                     /- FC content from `key_expand_from_private_seed`:
                        the key state is the spec-level output of
                        `K_PKE.KeyGen params d`, where `d` is the seed
                        bytes from the input blob.  Consumed by
                        `mlkem.key_generate.spec` to produce the
                        `RandomTape` witness. -/
                     wfPrivateSeed key' params
               | mlkem.key.Format.EncapsulationKey =>
                   ∃ (h_len : pb_src.length = 384 * (k params : ℕ) + 32),
                     /- The encoded-t prefix matches the leading 384·k
                        bytes; ρ matches the trailing 32 bytes. -/
                     keyEncodedTPrefix key' params = pb_src.toSpecWindow 0 (384 * (k params : ℕ)) (by simp [h_len]) ∧
                     key'.public_seed.toSpec = pb_src.toSpecWindow (384 * (k params : ℕ)) 32 (by simp [h_len]) ∧
                     /- The impl runs `key_compute_encapsulation_key_hash`
                        (`mlkem.rs:413`) before returning, so the hash
                        field commits to `SHA3-256(ek)`.  Required by
                        `mlkem.encapsulate.spec`'s `h_hash` hypothesis;
                        without this, the chain
                        `key_set_value(Encap) ⟶ encapsulate` cannot
                        discharge.  (REVIEWING R6-F1.) -/
                     key'.encaps_key_hash.toSpec = Spec.SHA3.sha3_256 (encapsulationKey key' params) ∧
                     /- Flags reflect a public-only key. -/
                     key'.has_private_seed = false ∧ key'.has_private_key = false ∧
                    /- Bundled wf-witness, needed by callers that chain
                       `key_set_value(Encap) ⟶ key_get_value(Encap)`
                       (round-trip) or `⟶ encapsulate`.  Produced by
                       `ksv_encap.spec`; threaded here. -/
                    wfEncapKey key' params ∧
                    /- Full FC: the assembled encapsulation key view
                       equals the input blob.  Locked-API conjunct;
                       derived from the prefix + ρ window equalities
                       via `slice_toSpec_eq_concat2`. -/
                    encapsulationKey key' params = pb_src.toSpec (384 * (k params : ℕ) + 32) h_len
               | mlkem.key.Format.DecapsulationKey =>
                   /- Decapsulation-key blob layout:
                      `s ‖ encoded_t ‖ ρ ‖ H(ek) ‖ private_random`
                      (lengths `384k + 384k + 32 + 32 + 32 = 768k + 96`).

                      Full FC: every byte-window of the input blob is
                      pinned, including the `dkPKE`/s-prefix
                      (`keySEncoded key' params = pb_src[0..384·k]`), which
                      is the canonical 12-bit `ByteEncode∘ByteDecode`
                      round-trip established via `ksv_decap.spec` and
                      `keySEncoded_window_bridge`.  Assembling the five
                      windows yields `decapsulationKey key' params = pb_src`
                      (see `RoundTrip.lean`). -/
                   ∃ (h_len : pb_src.length = 768 * (k params : ℕ) + 96),
                     keySEncoded key' params = pb_src.toSpecWindow 0 (384 * (k params : ℕ)) (by simp only [h_len]; scalar_tac) ∧
                     keyEncodedTPrefix key' params = pb_src.toSpecWindow (384 * (k params : ℕ)) (384 * (k params : ℕ)) (by have := k_le_4 params; simp [h_len]; grind) ∧
                     key'.public_seed.toSpec = pb_src.toSpecWindow (768 * (k params : ℕ)) 32 (by simp [h_len]) ∧
                     key'.encaps_key_hash.toSpec = pb_src.toSpecWindow (768 * (k params : ℕ) + 32) 32 (by simp [h_len]) ∧
                     key'.encaps_key_hash.toSpec = Spec.SHA3.sha3_256 (encapsulationKey key' params) ∧
                     key'.private_random.toSpec = pb_src.toSpecWindow (768 * (k params : ℕ) + 64) 32 (by simp [h_len]) ∧
                    key'.has_private_seed = false ∧ key'.has_private_key = true ∧
                    /- Bundled wf-witness, needed by callers that chain
                       `key_set_value(Decap) ⟶ key_get_value(Decap)`
                       (round-trip).  Produced by `ksv_decap.spec`. -/
                    wfDecapKey key' params)
          | Error.InvalidArgument =>
              -- Two flag-screening sites in `mlkem.key_set_value`
              -- (`mlkem.rs:282-288`): (1) any non-`allowed_flags` bit
              -- set, or (2) `FLAG_KEY_MINIMAL_VALIDATION` set when
              -- `FLAG_KEY_NO_FIPS` is unset (FIPS path forbids skipping
              -- validation).  Allowed flags are `FLAG_KEY_NO_FIPS |
              -- FLAG_KEY_MINIMAL_VALIDATION`.
              flags &&& ~~~(mlkem.FLAG_KEY_NO_FIPS ||| mlkem.FLAG_KEY_MINIMAL_VALIDATION) ≠ 0#u32 ∨
              (flags &&& mlkem.FLAG_KEY_NO_FIPS = 0#u32 ∧
               flags &&& mlkem.FLAG_KEY_MINIMAL_VALIDATION ≠ 0#u32)
          | Error.WrongKeySize =>
              -- `WrongKeySize` fires iff the input length doesn't match
              -- the format's expected size.  Format-aware so callers that
              -- pass a correctly-sized buffer can statically rule out
              -- this arm.
              match format with
              | mlkem.key.Format.PrivateSeed => pb_src.length ≠ 64
              | mlkem.key.Format.EncapsulationKey =>
                  pb_src.length ≠ 384 * (k params : ℕ) + 32
              | mlkem.key.Format.DecapsulationKey =>
                  pb_src.length ≠ 768 * (k params : ℕ) + 96
          | Error.InvalidBlob =>
              -- Only the `Encap`/`Decap` branches do content validation
              -- (12-bit coefficient range and, for `Decap`, the
              -- `encaps_key_hash` recomputation); the `PrivateSeed`
              -- branch contains no such checks.
              format ≠ mlkem.key.Format.PrivateSeed
          | Error.MemoryAllocationFailure => out_of_memory
          -- Tight enumeration of reachable errors (no caller-correctness
          -- assumptions; every variant is a defined response to bad input):
          --
          -- * `InvalidArgument`: unknown flag bit set
          --   (`flags & ~(FLAG_KEY_NO_FIPS | FLAG_KEY_MINIMAL_VALIDATION)
          --   ≠ 0`), or `FLAG_KEY_MINIMAL_VALIDATION` set when
          --   `FLAG_KEY_NO_FIPS` is unset (FIPS path forbids skipping
          --   validation).
          -- * `WrongKeySize`: length mismatch for the requested format
          --   (64 for `PrivateSeed`, `384·k + 32` for
          --   `EncapsulationKey`, `768·k + 96` for `DecapsulationKey`).
          -- * `InvalidBlob`: (a) `vector_decode_and_decompress` rejects
          --   an out-of-range 12-bit coefficient (`Encap`/`Decap` key
          --   formats); (b) on `DecapsulationKey`, the constant-time
          --   `encaps_key_hash` comparison fails.  Not reachable for
          --   `PrivateSeed` (no content checks).
          -- * `MemoryAllocationFailure`: `try_new_box_default` on
          --   `InternalComputationTemporaries` fails (yielding
          --   `out_of_memory`).
          --
          -- `FipsFailure` is *not* reachable here: there is no PCT in
          -- `key_set_value`; the PCT (when applicable) is run by the
          -- caller `key_generate`.
          | _ => False ⦄ := by
  rw [mlkem.key_set_value.fold]
  step
  rw [ksv_guard_i2.fold]
  split
  · -- i2 != 0 → InvalidArgument (case 1 of the disjunction)
    rename _ => h_i2_ne
    simp only [bne_iff_ne, ne_eq] at h_i2_ne
    simp only [WP.spec_ok]
    refine ⟨h_wf, rfl, rfl, ?_⟩
    left
    -- i2 = flags &&& ~~~(FLAG_KEY_NO_FIPS ||| FLAG_KEY_MINIMAL_VALIDATION)
    simp_all
  · rw [ksv_modes_outer.fold]
    step
    rw [ksv_dispatch_i3.fold]
    split
    · -- i3 = 0 → FIPS path
      rw [ksv_fips_path.fold]
      step
      rw [ksv_fips_guard_i4.fold]
      split
      · -- i4 != 0 → InvalidArgument (case 2 of the disjunction)
        rename _ => h_i4_ne
        simp only [bne_iff_ne, ne_eq] at h_i4_ne
        simp only [WP.spec_ok]
        refine ⟨h_wf, rfl, rfl, ?_⟩
        right
        refine ⟨?_, ?_⟩
        · -- flags &&& FLAG_KEY_NO_FIPS = 0#u32
          apply U32.bv_eq_imp_eq
          simp_all [UScalar.bv_and]
        · -- flags &&& FLAG_KEY_MINIMAL_VALIDATION ≠ 0#u32
          intro h
          apply h_i4_ne
          have := congrArg UScalar.val h
          simp_all
      · rw [ksv_fips_validated.fold]
        step
        rw [ksv_fips_match_r.fold]
        split
        · -- try_new_box returned Ok p_comp_temps
          rw [ksv_fips_match_format.fold]
          match format with
          | mlkem.key.Format.PrivateSeed =>
            step
            -- `try_new_box_default.ICT.spec` now yields a value equality
            -- (`max_size_vector0 = ZeroPolyVec 4`); `step` raises
            -- `ksv_priv`'s `wfPolyVec` destination precondition, closed
            -- via the `@[simp]` `wfPolyVec_zeroPolyVec` lemma.
            case h_pct_max0 => simp_all
            refine ⟨err_post1, err_post2, err_post3, ?_⟩
            match err, err_post4 with
            | .NoError, h => exact h
            | .WrongKeySize, h => exact h
            | .Unused, h | .WrongBlockSize, h
            | .WrongDataSize, h | .WrongNonceSize, h | .WrongTagSize, h
            | .WrongIterationCount, h | .AuthenticationFailure, h
            | .ExternalFailure, h | .FipsFailure, h | .HardwareFailure, h
            | .NotImplemented, h | .InvalidBlob, h => exact h.elim
          | mlkem.key.Format.EncapsulationKey =>
            step
            refine ⟨err_post1, err_post2, err_post3, ?_⟩
            match err, err_post4 with
            | .NoError, h =>
              -- ksv_encap.spec yields wfEncapKey + encapsulationKey FC; both
              -- are threaded into the toplevel post (round-trip needs both).
              obtain ⟨h_len, hp⟩ := h
              exact ⟨h_len, hp.1, hp.2.1, hp.2.2.1, hp.2.2.2.1, hp.2.2.2.2.1,
                            hp.2.2.2.2.2.1, hp.2.2.2.2.2.2⟩
            | .WrongKeySize, h => exact h
            | .InvalidBlob, _ => intro h; cases h
            | .Unused, h | .WrongBlockSize, h
            | .WrongDataSize, h | .WrongNonceSize, h | .WrongTagSize, h
            | .WrongIterationCount, h | .AuthenticationFailure, h
            | .ExternalFailure, h | .FipsFailure, h | .HardwareFailure, h
            | .NotImplemented, h => exact h.elim
          | mlkem.key.Format.DecapsulationKey =>
            step
            refine ⟨err_post1, err_post2, err_post3, ?_⟩
            match err, err_post4 with
            | .NoError, h =>
              -- ksv_decap.spec yields wfDecapKey + segment FC; both threaded.
              obtain ⟨h_len, hp⟩ := h
              exact ⟨h_len, hp⟩
            | .WrongKeySize, h => exact h
            | .InvalidBlob, _ => intro h; cases h
            | .Unused, h | .WrongBlockSize, h
            | .WrongDataSize, h | .WrongNonceSize, h | .WrongTagSize, h
            | .WrongIterationCount, h | .AuthenticationFailure, h
            | .ExternalFailure, h | .FipsFailure, h | .HardwareFailure, h
            | .NotImplemented, h => exact h.elim
        · -- try_new_box returned Err → MemoryAllocationFailure
          -- The box-default `Err` post supplies the `out_of_memory` witness.
          simp only [WP.spec_ok]
          refine ⟨h_wf, rfl, rfl, ?_⟩
          simp_all
    · -- i3 != 0 → noFIPS path
      rw [ksv_nofips_path.fold]
      step
      rw [ksv_nofips_match_r.fold]
      split
      · -- Ok p_comp_temps
        rw [ksv_nofips_match_format.fold]
        match format with
        | mlkem.key.Format.PrivateSeed =>
          step
          -- See the FIPS-path note: `step` raises `ksv_priv`'s
          -- `wfPolyVec` precondition; close it from the box_default
          -- value equality via `wfPolyVec_zeroPolyVec`.
          case h_pct_max0 => simp_all
          refine ⟨err_post1, err_post2, err_post3, ?_⟩
          match err, err_post4 with
          | .NoError, h => exact h
          | .WrongKeySize, h => exact h
          | .Unused, h | .WrongBlockSize, h
          | .WrongDataSize, h | .WrongNonceSize, h | .WrongTagSize, h
          | .WrongIterationCount, h | .AuthenticationFailure, h
          | .ExternalFailure, h | .FipsFailure, h | .HardwareFailure, h
          | .NotImplemented, h | .InvalidBlob, h => exact h.elim
        | mlkem.key.Format.EncapsulationKey =>
          step
          refine ⟨err_post1, err_post2, err_post3, ?_⟩
          match err, err_post4 with
          | .NoError, h =>
            -- ksv_encap.spec yields wfEncapKey + encapsulationKey FC; both
            -- are threaded into the toplevel post.
            obtain ⟨h_len, hp⟩ := h
            exact ⟨h_len, hp.1, hp.2.1, hp.2.2.1, hp.2.2.2.1, hp.2.2.2.2.1,
                          hp.2.2.2.2.2.1, hp.2.2.2.2.2.2⟩
          | .WrongKeySize, h => exact h
          | .InvalidBlob, _ => intro h; cases h
          | .Unused, h | .WrongBlockSize, h
          | .WrongDataSize, h | .WrongNonceSize, h | .WrongTagSize, h
          | .WrongIterationCount, h | .AuthenticationFailure, h
          | .ExternalFailure, h | .FipsFailure, h | .HardwareFailure, h
          | .NotImplemented, h => exact h.elim
        | mlkem.key.Format.DecapsulationKey =>
          step
          refine ⟨err_post1, err_post2, err_post3, ?_⟩
          match err, err_post4 with
          | .NoError, h =>
            -- ksv_decap.spec yields wfDecapKey + segment FC; both threaded.
            obtain ⟨h_len, hp⟩ := h
            exact ⟨h_len, hp⟩
          | .WrongKeySize, h => exact h
          | .InvalidBlob, _ => intro h; cases h
          | .Unused, h | .WrongBlockSize, h
          | .WrongDataSize, h | .WrongNonceSize, h | .WrongTagSize, h
          | .WrongIterationCount, h | .AuthenticationFailure, h
          | .ExternalFailure, h | .FipsFailure, h | .HardwareFailure, h
          | .NotImplemented, h => exact h.elim
      · -- Err → MAF
        -- The box-default `Err` post supplies the `out_of_memory` witness.
        simp only [WP.spec_ok]
        refine ⟨h_wf, rfl, rfl, ?_⟩
        simp_all

/-- **Assembly helper**: from the five byte-window equalities exposed by
`mlkem.key_set_value.spec`'s `DecapsulationKey` `NoError` arm, glue the
decapsulation-key view back to the input blob:
`decapsulationKey key' params = pb_src.toSpec (768·k + 96)`.

`decapsulationKey = keySEncoded ‖ (keyEncodedTPrefix ‖ ρ) ‖ H(ek) ‖ z`; each
component is a consecutive window of `pb_src`, so the concatenation is the
whole blob (proof mirrors the writer-side assembly in
`KeyGetValue.lean`). -/
theorem mlkem.ksv_decapsulationKey_toSpec_eq
    {params : ParameterSet} (key' : mlkem.key.Key) (pb_src : Slice U8)
    (h_len : pb_src.length = 768 * (k params : ℕ) + 96)
    (h_s : keySEncoded key' params =
             pb_src.toSpecWindow 0 (384 * (k params : ℕ)) (by simp only [h_len]; scalar_tac))
    (h_t : keyEncodedTPrefix key' params =
             pb_src.toSpecWindow (384 * (k params : ℕ)) (384 * (k params : ℕ))
               (by have := k_le_4 params; simp [h_len]; grind))
    (h_pub : key'.public_seed.toSpec =
               pb_src.toSpecWindow (768 * (k params : ℕ)) 32 (by simp [h_len]))
    (h_hash : key'.encaps_key_hash.toSpec =
                pb_src.toSpecWindow (768 * (k params : ℕ) + 32) 32 (by simp [h_len]))
    (h_rand : key'.private_random.toSpec =
                pb_src.toSpecWindow (768 * (k params : ℕ) + 64) 32 (by simp [h_len])) :
    decapsulationKey key' params = pb_src.toSpec (768 * (k params : ℕ) + 96) h_len := by
  unfold decapsulationKey encapsulationKey
  rw [h_s, h_t, h_pub, h_hash, h_rand]
  apply Vector.ext; intro i hi
  simp only [Vector.getElem_cast]
  show ((((_ : 𝔹 (384 * (k params : ℕ))) ++
      ((_ : 𝔹 (384 * (k params : ℕ))) ++ (_ : 𝔹 32))) ++
      (_ : 𝔹 32)) ++ (_ : 𝔹 32))[i]'(by grind) =
    (sliceToSpecBytes pb_src (768 * (k params : ℕ) + 96) h_len)[i]
  rw [Vector.getElem_append (by grind)]
  split_ifs with h4
  · rw [Vector.getElem_append (by grind)]
    split_ifs with h3
    · rw [Vector.getElem_append (by grind)]
      split_ifs with h0
      · unfold sliceToSpecBytes
        simp only [Slice.toSpecWindow, sliceWindowToSpecBytes, Vector.getElem_ofFn]
        simp
      · rw [Vector.getElem_append (by grind)]
        split_ifs with h1
        · unfold sliceToSpecBytes
          simp only [Slice.toSpecWindow, sliceWindowToSpecBytes, Vector.getElem_ofFn]
          have hidx : 384 * (k params : ℕ) + (i - 384 * (k params : ℕ)) = i := by grind
          simp [hidx]
        · unfold sliceToSpecBytes
          simp only [Slice.toSpecWindow, sliceWindowToSpecBytes, Vector.getElem_ofFn]
          have hidx : 768 * (k params : ℕ) + (i - 384 * (k params : ℕ) - 384 * (k params : ℕ)) = i := by grind
          simp [hidx]
    · unfold sliceToSpecBytes
      simp only [Slice.toSpecWindow, sliceWindowToSpecBytes, Vector.getElem_ofFn]
      have hidx :
          768 * (k params : ℕ) + 32 + (i - (384 * (k params : ℕ) + (384 * (k params : ℕ) + 32))) = i := by
        grind
      simp [hidx]
  · unfold sliceToSpecBytes
    simp only [Slice.toSpecWindow, sliceWindowToSpecBytes, Vector.getElem_ofFn]
    have hidx :
        768 * (k params : ℕ) + 64 + (i - (384 * (k params : ℕ) + (384 * (k params : ℕ) + 32) + 32)) = i := by
      grind
    simp [hidx]

end Symcrust.Properties.MLKEM
