/-
  # KeyGen.lean — `mlkem.key_generate` top spec.

  Maps to FIPS 203 Alg. 19 (`ML-KEM.KeyGen`).  Workflow:

  1. Sanity-check flag bits (only `FLAG_KEY_NO_FIPS` allowed).
  2. Sample 64 random bytes `d ‖ z` via `random`.
  3. `key_set_value(s, Format.PrivateSeed, …)` — internally runs
     `key_expand_from_private_seed` then computes
     `key_compute_encapsulation_key_hash` etc.
  4. Optional self-test (if `FLAG_KEY_NO_FIPS` is unset).
  5. Wipe the seed buffer.

  After step 3, the key state matches `MLKEM.KeyGen_internal p d z`
  (which is `K_PKE.KeyGen p d` + the dk wrapping `dkPKE ‖ ek ‖ H(ek) ‖ z`).

  The FC postcondition existentially quantifies the random draws `d`
  and `z`: for *some* `(d, z)` consistent with the key state, the
  result matches `MLKEM.KeyGen_internal params d z`.
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.KeyView
import Symcrust.Properties.MLKEM.Encoding.KeySetValue
import Symcrust.Properties.MLKEM.Encaps
import Symcrust.Properties.MLKEM.Decaps
import Symcrust.Properties.MLKEM.Key
import Symcrust.Properties.MLKEM.Helpers.VectorSliceCastAppend

open Aeneas Aeneas.Std Result
open scoped Spec.Notations
open Spec
open Spec.MLKEM
open symcrust

open symcrust.common
namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 4000000
set_option maxRecDepth 2048

/-! ## `#decompose` for `mlkem.key_generate`

The body of `mlkem.key_generate` is a 4-deep nest of error-handling
dispatchers wrapped around the only FC-bearing call, `mlkem.key_set_value`
(format `PrivateSeed`):

1.  **Flags gate**: `if flags & ~FLAG_KEY_NO_FIPS ≠ 0 then InvalidArgument
    else …`.
2.  **Random gate**: draw 64 random bytes via `common.random`; on error
    return the propagated `sc_error`.
3.  **KeySetValue gate**: call `mlkem.key_set_value` (PrivateSeed); on
    error return the propagated `sc_error1`.
4.  **FIPS body**: read `FLAG_KEY_NO_FIPS`; if set, just wipe the seed
    buffer and return `NoError`; if unset, run the PCT (encapsulate →
    decapsulate → constant-time-compare → wipe) and return either
    `NoError`, `FipsFailure`, or `MemoryAllocationFailure`.

The leaf `keyGenerate.body` carries the only `@[step]`-tagged spec.
The three intermediate dispatchers each peels exactly one error gate and
forwards the rest; rather than giving them separate specs, the top
proof walks through the three gates inline using
`unfold; rw [key_generate.fold]; step + by_cases` and finishes with one
`step keyGenerate.body.spec` at the leaf. -/

#decompose symcrust.mlkem.key_generate key_generate.fold
  letRange 3 1 => keyGenerate.dispatchFlags

#decompose keyGenerate.dispatchFlags keyGenerate.dispatchFlags.fold
  branch 1 (letRange 3 1) => keyGenerate.dispatchRandom

#decompose keyGenerate.dispatchRandom keyGenerate.dispatchRandom.fold
  branch 1 (letRange 4 1) => keyGenerate.dispatchKeySet

#decompose keyGenerate.dispatchKeySet keyGenerate.dispatchKeySet.fold
  branch 1 full => keyGenerate.body

/-- **Error-free / FC-trivial leaf of `mlkem.key_generate`** —
extracted by the `#decompose` cascade above.

`keyGenerate.body` is invoked once `mlkem.key_set_value` has succeeded
and produced `pk_mlkem_key1` with `has_private_seed = has_private_key
= true`. It runs the FIPS check:

* If `FLAG_KEY_NO_FIPS` is set: wipe the seed buffer, return
  `(NoError, pk_mlkem_key1)`.
* Otherwise, run the PCT (allocate ciphertext, `encapsulate`,
  `decapsulate`, `const_time_arrays_equal`, wipe). On allocation
  failure return `MemoryAllocationFailure`; on encap/decap error or
  cipher-text mismatch return `FipsFailure`; on success return
  `NoError`. The key is never mutated.

The spec therefore certifies two facts:
* **Key preservation**: `key' = pk_mlkem_key1` (every return arm
  yields the input key literally — the parent transports any
  property of `pk_mlkem_key1` to `key'` through this equality).
* **Flag-conditioned error enumeration**: `err ∈ {NoError,
  FipsFailure, MemoryAllocationFailure}`.  When
  `FLAG_KEY_NO_FIPS` is set, the body skips the PCT entirely
  (no allocator call, no encap/decap) and returns only
  `NoError`; conversely, `FipsFailure` and
  `MemoryAllocationFailure` can only fire when
  `FLAG_KEY_NO_FIPS` is unset.

The parent `mlkem.key_generate.spec` composes this with
`mlkem.key_set_value.spec` (PrivateSeed) to lift the FC equalities
(ek, dk, seed, hash) through the `keyGenerate.body` call.

Informal proof.  `unfold keyGenerate.body`; `step` consumes the
`flags &&& FLAG_KEY_NO_FIPS` bind; case-split on `i2 = 0`.

* `i2 ≠ 0` arm (wipe-only): `step` with `Array.to_slice_mut.spec`
  and `common.wipe_slice.spec`; close with `agrind` (key' =
  pk_mlkem_key1; err = NoError).
* `i2 = 0` arm (PCT): `step*` through the arithmetic prefix
  computing `cb_ciphertext`; case-split on the `try_new_box_zeroed`
  result:
  - `Err _`: return `(MemoryAllocationFailure, pk_mlkem_key1)`;
    the `try_new_box_zeroed` `Err` arm supplies `out_of_memory`.
  - `Ok t`: `step` with `core.array.Array.index_mut.spec` (twice),
    `mlkem.encapsulate.spec`, `Error.ne.spec`; case-split on the
    encap-error boolean; the `true` branch returns
    `(FipsFailure, pk_mlkem_key1)`; the `false` branch continues
    with `step` through `mlkem.decapsulate.spec`, another
    `Error.ne.spec`, a second `(FipsFailure, ...)` arm, then
    `core.array.Array.index.spec` twice, `try_from.spec` twice,
    `unwrap.spec` twice, `common.const_time_arrays_equal.spec`,
    and finally branch on its boolean. The `true` arm wipes via
    `common.wipe_slice.spec` and returns `(NoError, pk_mlkem_key1)`;
    the `false` arm returns `(FipsFailure, pk_mlkem_key1)`.

Each arm preserves the key literally (no field updates), so
`key' = pk_mlkem_key1` is discharged by `rfl` in each leaf.
The error enumeration matches the body's four `ok (Error.X, …)`
sites: `NoError` (wipe-only + PCT success), `FipsFailure`
(encap/decap error + CT mismatch), `MemoryAllocationFailure`
(ciphertext-buffer alloc); nothing else. -/
@[step]
theorem keyGenerate.body.spec
    {params : ParameterSet}
    (flags : U32)
    (private_seed1 : Array U8 64#usize)
    (pk_mlkem_key1 : mlkem.key.Key)
    (h_key : wfDecapKey pk_mlkem_key1 params) :
    keyGenerate.body flags private_seed1 pk_mlkem_key1
      ⦃ err key' =>
          key' = pk_mlkem_key1 ∧
          match err with
          | Error.NoError => True
          | Error.FipsFailure => flags &&& mlkem.FLAG_KEY_NO_FIPS = 0#u32
          | Error.MemoryAllocationFailure =>
              flags &&& mlkem.FLAG_KEY_NO_FIPS = 0#u32 ∧ out_of_memory
          | _ => False ⦄ := by
  obtain ⟨⟨h_wf, h_hash, h_t_form, h_a_form⟩, h_priv⟩ := h_key
  unfold keyGenerate.body
  step*
  case h1 =>
    obtain ⟨hp, _, _⟩ := h_wf
    cases params <;>
      (unfold wfInternalParams at hp
       simp [hp, mlkem.key.INTERNAL_PARAMS_MLKEM512,
             mlkem.key.INTERNAL_PARAMS_MLKEM768,
             mlkem.key.INTERNAL_PARAMS_MLKEM1024] at *
       scalar_tac)
  case h1 => unfold mlkem.SIZEOF_AGREED_SECRET; scalar_tac
  case params => exact params
  case h_key =>
    exact { towfKey := h_wf, hash_pinned := h_hash,
            byte_form_t := h_t_form, matrix_form_a := h_a_form }
  -- Residual: drive the PCT continuation manually.  The `match` post on
  -- `sc_error2` blocks step* from case-splitting on `b2 ← .ne sc_error2 NoError`,
  -- so we open the case explicitly.
  have h_flag : flags &&& mlkem.FLAG_KEY_NO_FIPS = 0#u32 := by scalar_tac
  step
  split
  · exact ⟨rfl, h_flag⟩
  -- b2 = false; sc_error2 = NoError; continue PCT
  step*
  case params => exact params
  case h_key =>
    exact { towfEncapKey := { towfKey := h_wf, hash_pinned := h_hash,
                               byte_form_t := h_t_form, matrix_form_a := h_a_form },
            has_private_key := h_priv }
  case hmax => unfold mlkem.SIZEOF_AGREED_SECRET; scalar_tac
  case h1 => have h := i8_post; unfold mlkem.SIZEOF_AGREED_SECRET at h; scalar_tac
  -- Inner: decapsulate's .ne sc_error3
  step
  split
  · exact ⟨rfl, h_flag⟩
  -- sc_error3 = NoError; CT-equality branch
  step*
  case h1 => simp; unfold mlkem.SIZEOF_AGREED_SECRET; scalar_tac
  case h => unfold mlkem.SIZEOF_AGREED_SECRET at s7_post2; scalar_tac
  case h =>
    unfold mlkem.SIZEOF_AGREED_SECRET at s8_post2
    have hi8 := i8_post; unfold mlkem.SIZEOF_AGREED_SECRET at hi8
    scalar_tac

/-- **Top spec for `mlkem.key_generate`** — FC against
`MLKEM.KeyGen_internal` modulo the randomness exception.

On `NoError`, the resulting key holds a freshly generated
`(ek, dk) := KeyGen_internal params d z` for *some* `d, z : 𝔹 32`
(the random draws are opaque, surfaced as existentials).  Error
cases: `InvalidArgument` (bad flags),
`MemoryAllocationFailure`, `FipsFailure` (self-test mismatch).

Informal proof.  After `unfold mlkem.key_generate`:

**Step 1 — Flags check.**  `step` on `flags &&& ~~~FLAG_KEY_NO_FIPS`.
If non-zero: return `(InvalidArgument, pk_mlkem_key)`; postcondition
`True`; `wfKey` from `h_wf`; `agrind`.

**Step 2 — Random sample (existential witnesses).**  `step` with
`random.spec` (`Properties/Axioms/System.lean`): introduces the
existential witnesses `d z : 𝔹 32` from the 64-byte draw
(first 32 = `d`, second 32 = `z`).  Case on error:
* Error: return `(sc_error, pk_mlkem_key)`; postcondition `True`;
  `wfKey` from `h_wf`; `agrind`.

**Step 3 — Key expansion (FC weight-bearing step).**  `step` with
`mlkem.key_set_value.spec` (KeySetValue.lean, `Format.PrivateSeed`):
internally calls `key_expand_from_private_seed`; gives
`wfKey key'1 params`, `key'1.has_private_seed = true`,
`key'1.has_private_key = true`, and all FC conjuncts
(`encapsulationKey key'1 params = ek`, `keySEncoded key'1 params =
dkSlice`, `encaps_key_hash = H(ek)`) with witnesses `d` and `z`
fixed by step 2.  Case on error:
* Error: return `(sc_error1, key'1)`; postcondition `True`; `wfKey`
  from `key_set_value.spec`; `agrind`.

**Step 4a — FLAG_KEY_NO_FIPS set (skip PCT).**  `step` with
`common.wipe_slice.spec` (wipes the seed buffer); return
`(NoError, key'1)`.  Provide existentials `⟨d, z, ...⟩` from
step 2; all FC conjuncts from step 3; `agrind`.

**Step 4b — PCT (FLAG_KEY_NO_FIPS unset).**  `step` through
`try_new_box_zeroed` to allocate the ciphertext buffer; case on result:
* `Err`: return `(MemoryAllocationFailure, key'1)`; postcondition
  `out_of_memory` (from `try_new_box_zeroed`'s `Err` arm).
* `Ok t`:
  (a) Slice `pb_ciphertext = t[0..cb_ciphertext]` and
  `s3 = private_seed[0..32]`; `step` with `mlkem.encapsulate.spec`
  using `d` (first 32 seed bytes) as the Encaps randomness: gives
  ciphertext `c` and agreed secret `K_enc`.
  * Error: return `(FipsFailure, key'1)`; postcondition `True`.
  (b) Slice `s5 = private_seed[32..64]`; `step` with
  `mlkem.decapsulate.spec` on `(key'1, c)`: gives agreed secret
  `K_dec`.
  * Error: return `(FipsFailure, key'1)`; postcondition `True`.
  (c) `step` with `const_time_arrays_equal.spec` comparing `K_enc`
  and `K_dec`: they are equal by the MLKEM correctness theorem
  (`MLKEM.Correctness` in Spec.lean: `Decaps(dk, Encaps(ek, r)) =
  K_enc` for any valid `(ek, dk)` generated from the same seed);
  returns `true`.
  * Mismatch (false): return `(FipsFailure, key'1)`; postcondition `True`.
  (d) `step` with `common.wipe_slice.spec`; return `(NoError, key'1)`.
  Witnesses and FC conjuncts from step 3; `agrind`. -/
@[step]
theorem mlkem.key_generate.spec
    (params : ParameterSet)
    (pk_mlkem_key : mlkem.key.Key) (flags : U32)
    (h_wf : wfKey pk_mlkem_key params) :
    mlkem.key_generate pk_mlkem_key flags
      ⦃ err key' =>
          wfKey key' params ∧
          match err with
          | Error.NoError =>
              -- wfPrivateSeed establishes our strongest key invariant,
              -- and the existential proposition ensures the in-memory
              -- key holds the public/private key pair computed by
              -- the Spec algorithm from an underspecified random tape.
              wfPrivateSeed key' params ∧
              ∃ (tape : MLKEM.RandomTape),
                let (ek, dk, _) := MLKEM.KeyGen params tape
                ek = key'.toEncapKey params ∧
                dk = key'.toDecapKey params
          | Error.InvalidArgument =>
              -- flags screen (`flags & ~FLAG_KEY_NO_FIPS ≠ 0`) raised
              -- directly by `key_generate` (`mlkem.rs:516`).
              -- (`key_set_value(PrivateSeed, flags)` accepts
              -- `flags ∈ {0, FLAG_KEY_NO_FIPS}` after this screen
              -- and therefore cannot independently raise InvalidArgument.)
              flags &&& ~~~mlkem.FLAG_KEY_NO_FIPS ≠ 0#u32
          | Error.MemoryAllocationFailure =>
              -- Triggered by `try_new_box_default` inside `key_set_value`
              -- (allocates `InternalComputationTemporaries`) and
              -- `try_new_box_zeroed` in the PCT branch (allocates the
              -- ciphertext scratch buffer); both allocation gates yield
              -- `out_of_memory` on failure.
              out_of_memory
          | Error.FipsFailure => flags &&& mlkem.FLAG_KEY_NO_FIPS = 0#u32
              -- PCT mismatch (encap/decap error or ciphertext comparison
              -- fail) when `FLAG_KEY_NO_FIPS` is unset.  Note that a
              -- transient `MemoryAllocationFailure` raised inside the
              -- nested `encapsulate`/`decapsulate` calls during the PCT
              -- is also re-labelled `FipsFailure` here (`mlkem.rs:562,
              -- 568`: any non-NoError from the inner call → FipsFailure).

          -- The error enumeration above is tight.
          -- Unreachable here (statically excluded, no caller assumption):
          -- * `WrongKeySize`: the seed slice is a local 64-byte buffer
          --   (`Array.repeat 64#usize 0#u8 |> .to_slice`), so the
          --   `PrivateSeed` length check at the start of `key_set_value`
          --   never fires.
          -- * `InvalidBlob`: `key_set_value.spec` rules this out on
          --   `format = PrivateSeed` (format-aware error arm).
          -- * `sc_error` propagated from `common.random`: axiomatised to
          --   return `NoError` only (see `Properties/Axioms/System.lean`).
          | _ => False ⦄ := by
  -- Enter the cascade.  Each `.fold` rewrite peels one dispatcher
  -- *as a call* (no inlining), so `step*` can pick up the leaf's
  -- `@[step]` spec.  Per `decompose-command` skill: "Apply the
  -- equation with `rw [eq]` as the first step ... do NOT `unfold`
  -- the decomposed function."  We use `simp only` rather than
  -- `rw` because the `private_seed` pure `let` blocks `rw` from
  -- instantiating the metavariable of the inner fold lemmas.
  simp only [key_generate.fold, keyGenerate.dispatchFlags.fold,
             keyGenerate.dispatchRandom.fold, keyGenerate.dispatchKeySet.fold]
  step*
  -- Discharge `params` and `wfDecapKey` preconditions of body.spec.
  case params => exact params
  case h_key =>
    -- key_set_value.spec on `PrivateSeed` produces `wfPrivateSeed`, which
    -- extends `wfDecapKey`.  Project via `cases sc_error1` rather than
    -- `simp_all`-derived `sc_error1 = NoError`: post-Phase-5 the NoError
    -- arm of `sc_error1_post4` will be a nested `wfKeyFormat ∧ ∃ ...`
    -- bundle whose whnf is expensive; per-branch handling avoids that
    -- path and is also robust to the planned Phase-5 KSV rewrite (with
    -- only a 1-line obtain-pattern adjustment).
    cases sc_error1 <;>
      first | (obtain ⟨_, _, _, _, _, h_wfps⟩ := sc_error1_post4
               exact wfDecapKey_of_wfPrivateSeed h_wfps)
            | (exfalso; simp_all)
  -- Discharge error arms uniformly: `wfKey key' params` always comes
  -- from `sc_error1_post1` (key_set_value.spec's bundled post on the
  -- `PrivateSeed` arm) or from `h_wf` directly (when key_set_value
  -- errors out before setting the key), and the error body returns
  -- `key' = pk_mlkem_key` so `simp_all` collapses the match.
  all_goals first
    | (refine ⟨sc_error1_post1, ?_⟩; cases sc_error1 <;> simp_all)
    | (subst err_post1
       refine ⟨sc_error1_post1, ?_⟩
       cases sc_error1 <;> simp_all)
  -- Residual: build the `tape : RandomTape` witness.  `random.spec`
  -- gives `tape_random` with bytewise equality on `s1` (the buffer
  -- returned by `common.random`).  The remaining work is the bridge
  -- from `s1 ↔ tape_random` (random.spec) through `s2 = to_slice_mut_back
  -- s1 |> to_slice` (slice-array round-trip) and into the FC content
  -- equalities exposed by `key_set_value.spec` (`encapsulationKey
  -- key' params = (K_PKE.KeyGen params d).1` etc., where
  -- `d = arrayToSpecBytes key'.private_seed`).  Sketch:
  --   1. extract `tape_random` from `sc_error_post3`;
  --   2. show `sliceWindowToSpecBytes s2 0 32 ⋯ = (tape_random.readBytes 32).1`
  --      (bytewise from `h_tape`, using `s2.val = s1.val` from the
  --      `to_slice_mut_back`/`to_slice` round-trip);
  --   3. similarly for the trailing 32 bytes;
  --   4. lift `K_PKE.KeyGen` ↔ `MLKEM.KeyGen` per `Spec.MLKEM.Spec`
  --      `KeyGen_internal` defn (`ekPKE → ek`, `dkPKE ‖ ek ‖ H ek ‖ z`
  --      → `dk`); `keySEncoded = dkPKE` already given, the prefix
  --      slice equals `dkPKE` by the dk-blob layout.
  case h1.InvalidArgument =>
    have h_no_fips : mlkem.FLAG_KEY_NO_FIPS.bv = 256#32 := by
      unfold mlkem.FLAG_KEY_NO_FIPS; rfl
    have h_min_val : mlkem.FLAG_KEY_MINIMAL_VALIDATION.bv = 512#32 := by
      unfold mlkem.FLAG_KEY_MINIMAL_VALIDATION; rfl
    -- Lift the flag-screen hypothesis to U32 then bv form.
    have h_screen_u32 : flags &&& ~~~mlkem.FLAG_KEY_NO_FIPS = 0#u32 := by
      apply UScalar.eq_of_val_eq
      have h := (by assumption : ↑flags &&& ↑(~~~mlkem.FLAG_KEY_NO_FIPS) = 0)
      simpa [UScalar.val_and] using h
    have h_screen : flags.bv &&& ~~~(256#32) = 0#32 := by
      have h := congrArg UScalar.bv h_screen_u32
      simpa [UScalar.bv_and, UScalar.bv_not, h_no_fips] using h
    rcases sc_error1_post4 with h_l | ⟨h_no_fips_eq, h_r⟩
    · apply h_l
      have h_bv : flags.bv &&& ~~~(256#32 ||| 512#32) = 0#32 := by bv_decide
      have h_u32 : flags &&& ~~~(mlkem.FLAG_KEY_NO_FIPS ||| mlkem.FLAG_KEY_MINIMAL_VALIDATION) = 0#u32 := by
        apply U32.bv_eq_imp_eq
        simp [UScalar.bv_and, UScalar.bv_or, UScalar.bv_not, h_no_fips, h_min_val]
        exact h_bv
      exact congrArg UScalar.val h_u32
    · apply h_r
      have h_nof_bv : flags.bv &&& 256#32 = 0#32 := by
        have h := congrArg UScalar.bv h_no_fips_eq
        simpa [UScalar.bv_and, h_no_fips] using h
      have h_bv : flags.bv &&& 512#32 = 0#32 := by bv_decide
      have h_u32 : flags &&& mlkem.FLAG_KEY_MINIMAL_VALIDATION = 0#u32 := by
        apply U32.bv_eq_imp_eq
        simp [UScalar.bv_and, h_min_val]
        exact h_bv
      exact congrArg UScalar.val h_u32
  rename RandomTape => tape_random
  replace h_tape := sc_error_post3
  cases err <;> simp_all
  -- NoError arm: witness the existential with `tape_random` from `random.spec`.
  -- Two byte-equalities used by Conjuncts 3, 4, 5 below:
  have h64 : s1.val.length = 64 := by simp_all
  have hC1 : sliceWindowToSpecBytes ((Array.repeat 64#usize 0#u8).from_slice s1).to_slice
              0 32 (by simp [h64]) = (tape_random.readBytes 32).1 := by
    apply Vector.ext
    intro i hi
    simp only [sliceWindowToSpecBytes, RandomTape.readBytes,
               Vector.getElem_ofFn, Array.to_slice, Nat.zero_add]
    have hb := h_tape i (by omega)
    grind [Array.from_slice_val]
  have hC2 : sliceWindowToSpecBytes ((Array.repeat 64#usize 0#u8).from_slice s1).to_slice
              32 32 (by simp [h64]) = ((tape_random.readBytes 32).2.readBytes 32).1 := by
    apply Vector.ext
    intro i hi
    simp only [sliceWindowToSpecBytes, RandomTape.readBytes,
               Vector.getElem_ofFn, Array.to_slice]
    have hb := h_tape (32 + i) (by omega)
    grind [Array.from_slice_val]
  obtain ⟨hps, hpr, _, _, h_wfps⟩ := sc_error1_post4
  refine ⟨tape_random, ?_, ?_⟩
  · -- ek = key'.toEncapKey params.
    --   LHS after KeyGen unfold: (K_PKE.KeyGen params (tape_random.readBytes 32).1).1
    --   RHS: key'.toEncapKey params = encapsulationKey key' params
    --   By wfPrivateSeed.fc_encaps, encapsulationKey key' = (K_PKE.KeyGen
    --   params key'.private_seed.toSpec).1.  Bridge tape ↔ private_seed via
    --   hC1 + hps.
    have hek := wfPrivateSeed.fc_encaps h_wfps
    show (MLKEM.KeyGen params tape_random).1 = encapsulationKey key' params
    simp only [KeyGen, KeyGen_internal, ← hC1, ← hps]
    exact hek.symm
  · -- dk = key'.toDecapKey params.
    --   LHS after KeyGen unfold: (dkPKE ‖ ek ‖ H ek ‖ z).cast _
    --       where dkPKE = (K_PKE.KeyGen params d).2,
    --             ek    = (K_PKE.KeyGen params d).1,
    --             d, z  = readBytes off tape_random.
    --   RHS: decapsulationKey key' params =
    --        (keySEncoded ‖ encapsulationKey ‖ encaps_key_hash ‖ private_random).cast _
    --   Match each of the four append components:
    --     dkPKE  ↔ keySEncoded     by wfPrivateSeed.fc_keys
    --     ek     ↔ encapsulationKey by wfPrivateSeed.fc_encaps
    --     H ek   ↔ encaps_key_hash  by wfEncapKey.hash_pinned (via fc_encaps)
    --     z      ↔ private_random   by hpr (+ hC2)
    have hek := wfPrivateSeed.fc_encaps h_wfps
    have hks := wfPrivateSeed.fc_keys h_wfps
    have hhh := wfEncapKey.hash_pinned (wfEncapKey_of_wfPrivateSeed h_wfps)
    show (MLKEM.KeyGen params tape_random).2.1 = decapsulationKey key' params
    unfold encapsulationKey at hek
    unfold keyHashPinned at hhh
    unfold decapsulationKey encapsulationKey
    simp only [KeyGen, KeyGen_internal, H, ← hC1, ← hC2, ← hps, ← hpr, ← hek, ← hks, hhh]
    rfl
end Symcrust.Properties.MLKEM
