/-
  # Workflow.lean — `@[step]` specs for the ML-KEM usability workflow.

  Specs for the extractable end-to-end workflow (`src/mlkem/workflow.rs`):
  `ok_or`, `alice_setup`, `bob_encapsulate`, `alice_decapsulate`, and the
  composed `alice_bob_roundtrip`. Each is monomorphic at ML-KEM-768 and built
  only from the verified public API, so its spec composes the already-proved
  callee specs (`key_allocate`, `key_set_value`, `key_get_value`,
  `encapsulate_ex`, `decapsulate`).

  The functions return the Rust `Result<T, Error>` (`core.result.Result T
  common.Error`); the `?` operator desugars to `Try.branch` / `from_residual`,
  whose `@[step]` specs live in the Aeneas stdlib. Success (`.Ok`) arms carry
  the functional-correctness postcondition; error (`.Err`) arms carry the
  precise set of reachable errors — `out_of_memory` (allocation failures) and,
  where the format allows it, `InvalidBlob`. The fixed monomorphic buffer sizes
  statically rule out every size/flag error of the callees.
-/
import Symcrust.Properties.MLKEM.Encaps
import Symcrust.Properties.MLKEM.Decaps
import Symcrust.Properties.MLKEM.KeyGen
import Symcrust.Properties.MLKEM.Encoding.KeySetValue
import Symcrust.Properties.MLKEM.Encoding.KeyGetValue
import Symcrust.Properties.MLKEM.Ffi

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust
open symcrust.common

namespace Symcrust.Properties.MLKEM

/-- **Spec for `mlkem::workflow::ok_or`.** Converts a SymCrypt `Error` into a
Rust `Result`: `Ok ()` iff the error is `NoError`, else `Err e`. -/
@[step]
theorem mlkem.workflow.ok_or.spec (e : common.Error) :
    mlkem.workflow.ok_or e ⦃ (r : core.result.Result Unit common.Error) =>
      (e = common.Error.NoError → r = .Ok ()) ∧
      (e ≠ common.Error.NoError → r = .Err e) ⦄ := by
  unfold mlkem.workflow.ok_or
  step as ⟨ b, hb ⟩
  split
  · rename_i hbt
    have : e = common.Error.NoError := hb.mp hbt
    simp_all
  · rename_i hbf
    simp only [Bool.not_eq_true] at hbf
    have : e ≠ common.Error.NoError := fun h => by simp [hb.mpr h] at hbf
    simp_all

/-- ML-KEM-768 spec parameter set. -/
private abbrev p768 : ParameterSet := paramsToSpec mlkem.key.Params.MlKem768

/-- `arrayToSpecBytes A` equals `sliceToSpecBytes s` when they share the same
underlying bytes. Stated with the uniform length `m.val` so `Vector.getElem_ofFn`
fires on both sides. -/
private theorem arrayToSpecBytes_eq_sliceToSpecBytes {m : Usize} (A : Array U8 m)
    (s : Slice U8) (h : s.length = m.val) (hval : A.val = s.val) :
    arrayToSpecBytes A = sliceToSpecBytes s m.val h := by
  unfold arrayToSpecBytes sliceToSpecBytes
  apply Vector.ext; intro i hi
  simp only [Vector.getElem_ofFn, hval]

/-- The `toSpecWindow` of a slice that shares an array's bytes is exactly the
corresponding `Spec.slice` of the array's `toSpec`. Taking the slice + a
`val`-equality (rather than `a.to_slice` directly) avoids rewriting the slice
under `toSpecWindow`'s dependent length proof. -/
private theorem sliceWindow_eq_slice_of_array {N : Usize} (a : Array U8 N)
    (s : Slice U8) (hs : s.val = a.val) (off m : ℕ) (hwin : off + m ≤ (N : ℕ))
    (h : off + m ≤ s.length) :
    s.toSpecWindow off m h = Spec.slice a.toSpec off m hwin := by
  apply Vector.ext; intro i hi
  simp only [Aeneas.Std.Slice.toSpecWindow, sliceWindowToSpecBytes,
    Aeneas.Std.Array.toSpec, arrayToSpecBytes, Spec.slice, Vector.getElem_ofFn, hs]

set_option maxHeartbeats 1000000 in
/-- **Spec for `mlkem::workflow::bob_encapsulate`.** On success, the returned
`(secret, ciphertext)` are exactly the FIPS-203 `Encaps_internal` output for the
imported public key and the supplied randomness. -/
theorem mlkem.workflow.bob_encapsulate.spec
    (ek : Array U8 1184#usize) (r : Array U8 32#usize) :
    mlkem.workflow.bob_encapsulate ek r
      ⦃ (res : core.result.Result _ _) =>
          match res with
          | .Ok (secret, ct) =>
              let (K, c) := MLKEM.Encaps_internal p768 ek.toSpec r.toSpec
              K = secret.toSpec /\ c = ct.toSpec
          | .Err e => out_of_memory ∨ e = common.Error.InvalidBlob ⦄ := by
  unfold mlkem.workflow.bob_encapsulate
  step as ⟨r1, r1_post⟩
  match hr1 : r1 with
  | .Err e =>
    step*
  | .Ok val =>
    obtain ⟨h_wfval, _⟩ := r1_post
    step*
    case params => exact p768
    case h_wf => grind
    -- Encapsulate continuation. `ok_or e` gates on whether key_set_value succeeded.
    step as ⟨r2, hr2a, hr2b⟩
    by_cases he : e = common.Error.NoError
    · -- key_set_value succeeded: extract wfEncapKey + encapsulationKey = ek blob.
      rw [hr2a he]
      subst he
      simp only [] at e_post4
      obtain ⟨_, _, _, _, _, _, h_wfek, h_enckey⟩ := e_post4
      step*
      have he1 : e1 = common.Error.NoError := by grind
      simp only [he1] at e1_post
      obtain ⟨h3len, h4len, hK, hC⟩ := e1_post
      have hcl : cipherlength p768 = 1088 := by decide
      -- The imported public key's spec view is exactly the input blob (full-FC import).
      have hkey : val1.toPubKey p768 = ek.toSpec := by
        subst s_post
        show encapsulationKey val1 p768 = ek.toSpec
        rw [h_enckey]
        exact sliceToSpecBytes_to_slice_eq ek _
      rw [hkey] at hK hC
      have hv3 : (to_slice_mut_back s3).val = s3.val := by
        rw [congrFun s1_post2 s3]
        exact Array.from_slice_val _ s3 (by simpa [Slice.length] using h3len)
      have hv4 : (to_slice_mut_back1 s4).val = s4.val := by
        rw [congrFun s2_post2 s4]
        exact Array.from_slice_val _ s4 (by rw [hcl] at h4len; simpa [Slice.length] using h4len)
      refine ⟨?_, ?_⟩
      · rw [hK]
        exact (arrayToSpecBytes_eq_sliceToSpecBytes (to_slice_mut_back s3) s3 (by grind) hv3).symm
      · rw [hC]
        exact (arrayToSpecBytes_eq_sliceToSpecBytes (to_slice_mut_back1 s4) s4
          (by rw [hcl] at h4len; simpa [Slice.length] using h4len) hv4).symm
      -- encapsulate_ex error path: only MemoryAllocationFailure is reachable
      -- (InvalidArgument ruled out by the fixed 32/1088-byte buffers), giving out_of_memory.
      · grind [Aeneas.Std.Array.length_eq]
    · -- key_set_value failed: ok_or e = Err e, propagates, result is Err e.
      -- The only reachable errors are MemoryAllocationFailure (⇒ out_of_memory) and
      -- InvalidBlob; the flag/size errors are impossible with flags = 0 and the fixed
      -- 1184-byte encapsulation-key blob.
      rw [hr2b he]
      step*
      grind [Aeneas.Std.Array.length_eq]


set_option maxHeartbeats 1000000 in
/-- **Spec for `mlkem::workflow::alice_decapsulate`.** On success, the returned
secret is the FIPS-203 `Decaps` of the *input* decapsulation-key blob `dk` on the
ciphertext — the shared secret is a deterministic function of `dk` and `ct`, with
no reference to the internal key object.

One parked bridge: relating the loaded key's `decapsulationKey` view back to the
raw input blob (`decapsulationKey val1 = dk.toSpec`) needs the deferred
`DecapsulationKey` s-prefix `ByteEncode∘ByteDecode` round-trip
(`Encoding/RoundTrip.lean`, Phase 5b) — `key_set_value(Decap)` currently binds the
`ek`/hash/`z` windows of `dk` but not the `dkPKE` prefix. -/
theorem mlkem.workflow.alice_decapsulate.spec
    (dk : Array U8 2400#usize) (ct : Array U8 1088#usize) :
    mlkem.workflow.alice_decapsulate dk ct
      ⦃ (res : core.result.Result _ _ ) =>
          match res with
          | .Ok secret =>
            MLKEM.Decaps p768 dk.toSpec ct.toSpec = some secret.toSpec
          | .Err e => out_of_memory ∨ e = common.Error.InvalidBlob ⦄ := by
  unfold mlkem.workflow.alice_decapsulate
  step as ⟨r1, r1_post⟩
  match hr1 : r1 with
  | .Err e => step*
  | .Ok val =>
    obtain ⟨h_wfval, _⟩ := r1_post
    step*
    case params => exact p768
    case h_wf => grind
    have hcl : cipherlength p768 = 1088 := by decide
    step as ⟨r2, hr2a, hr2b⟩
    by_cases he : e = common.Error.NoError
    · rw [hr2a he]
      subst he
      simp only [] at e_post4
      obtain ⟨h_len, h_keyS, h_t, h_pub, h_hash, _h_sha, h_rand, _hps, _hpk, h_wfdk⟩ := e_post4
      step*
      have he1 : e1 = common.Error.NoError := by grind
      rw [he1] at e1_post
      simp only [] at e1_post
      obtain ⟨h_s, h_c, hdec⟩ := e1_post
      subst s1_post
      -- Relate the input blob `dk` to the loaded key's decap view.  The s-prefix
      -- (`dkPKE`) round-trip is now closed: `key_set_value(Decap)` exposes the
      -- five byte-windows of `dk` (including `keySEncoded val1 = dk[0..384·k]`),
      -- and `mlkem.ksv_decapsulationKey_toSpec_eq` assembles them into the full
      -- `decapsulationKey val1 = dk.toSpec`.
      have h_dk : decapsulationKey val1 p768 = dk.toSpec := by
        subst s_post
        rw [mlkem.ksv_decapsulationKey_toSpec_eq val1 _ h_len h_keyS h_t h_pub h_hash h_rand]
        exact sliceToSpecBytes_to_slice_eq dk _
      have hbridge_ct : (Array.to_slice ct).toSpec (cipherlength p768) h_c = ct.toSpec := by
        simp only [hcl] at h_c ⊢
        exact sliceToSpecBytes_to_slice_eq ct h_c
      have hs : to_slice_mut_back s3 = (Array.repeat 32#usize 0#u8).from_slice s3 :=
        congrFun s2_post2 s3
      have hv : (to_slice_mut_back s3).val = s3.val := by
        rw [hs]; exact Array.from_slice_val _ s3 (by simpa [Slice.length] using h_s)
      have hbridge_out : (to_slice_mut_back s3).toSpec = sliceToSpecBytes s3 32 h_s :=
        arrayToSpecBytes_eq_sliceToSpecBytes (to_slice_mut_back s3) s3
          (by simpa [Slice.length] using h_s) hv
      show MLKEM.Decaps p768 dk.toSpec ct.toSpec = some (to_slice_mut_back s3).toSpec
      rw [← h_dk, hbridge_out, ← hbridge_ct]
      exact hdec
      -- decapsulate error path: only MemoryAllocationFailure is reachable (⇒ out_of_memory);
      -- the 32-byte secret buffer and 1088-byte ciphertext rule out InvalidArgument.
      · have hs2 : s2.length = 32 := by
          simp only [Slice.length, s2_post1, Aeneas.Std.Array.length_eq]; decide
        have hs1len : s1.length = cipherlength p768 := by
          rw [hcl, s1_post]
          simp only [Slice.length, Array.to_slice, Aeneas.Std.Array.length_eq]; decide
        grind
    · -- key_set_value (DecapsulationKey load) fails only with MemoryAllocationFailure
      -- (⇒ out_of_memory) or InvalidBlob; the fixed 2400-byte blob and flags = 0 rule
      -- out the size/flag errors.
      rw [hr2b he]
      step*
      have hslen : s.length = 768 * (k p768) + 96 := by
        rw [s_post]
        simp only [Slice.length, Array.to_slice, Aeneas.Std.Array.length_eq]
        decide
      grind

set_option maxHeartbeats 1000000 in
/-- **Spec for `mlkem::workflow::alice_setup`.** On success, the exported
`(encaps, decaps)` blobs are exactly the FIPS-203 `KeyGen_internal(d, z)`
outputs for the two 32-byte halves of the seed (`d = seed[0:32]`,
`z = seed[32:64]`) — i.e. the keys are a deterministic function of the seed,
not merely of *some* well-formed key. The only reachable error is an allocation
failure: the fixed 64-byte seed and the fixed 1184/2400-byte export buffers rule
out every size/flag/blob error of `key_set_value`/`key_get_value`. -/
theorem mlkem.workflow.alice_setup.spec (seed : Array U8 64#usize) :
    mlkem.workflow.alice_setup seed
      ⦃ (res : core.result.Result _ _) =>
          match res with
          | .Ok (dk, ek) =>
            (dk.toSpec, ek.toSpec) =
              let d := Spec.slice seed.toSpec 0 32
              let z := Spec.slice seed.toSpec 32 32
              MLKEM.KeyGen_internal p768 d z
          | .Err _ => out_of_memory ⦄ := by
  unfold mlkem.workflow.alice_setup
  step as ⟨r1, r1_post⟩
  match hr1 : r1 with
  | .Err e => step*
  | .Ok val =>
    obtain ⟨h_wfval, _⟩ := r1_post
    step*
    case params => exact p768
    case h_wf => grind
    step as ⟨r2, hr2a, hr2b⟩
    by_cases he : e = common.Error.NoError
    · rw [hr2a he]
      subst he
      simp only [] at e_post4
      obtain ⟨_, h_pseed, h_prand, _, _, h_wfps⟩ := e_post4
      step*
      case params => exact p768
      case h_wf => exact wfEncapKey_of_wfPrivateSeed h_wfps
      step as ⟨r3, hr3a, hr3b⟩
      by_cases he1 : e1 = common.Error.NoError
      · rw [hr3a he1]
        subst he1
        simp only [] at e1_post2
        obtain ⟨h_len_e, henc⟩ := e1_post2
        rw [Key.toSpec_EncapsulationKey] at henc
        step*
        case params => exact p768
        case h_wf => exact wfDecapKey_of_wfPrivateSeed h_wfps
        step as ⟨r4, hr4a, hr4b⟩
        by_cases he2 : e2 = common.Error.NoError
        · rw [hr4a he2]
          subst he2
          simp only [] at e2_post2
          obtain ⟨h_len_d, hdec⟩ := e2_post2
          rw [Key.toSpec_DecapsulationKey] at hdec
          -- Bind the two seed halves to the loaded key's private material.
          have hsval : s.val = seed.val := by rw [s_post]; exact Array.val_to_slice seed
          have hd : val1.private_seed.toSpec = Spec.slice seed.toSpec 0 32 := by
            grind [sliceWindow_eq_slice_of_array]
          have hz : val1.private_random.toSpec = Spec.slice seed.toSpec 32 32 := by
            grind [sliceWindow_eq_slice_of_array]
          -- The exported blobs equal the loaded key's spec views (byte bridges).
          have h_enc : (to_slice_mut_back s2).toSpec = encapsulationKey val1 p768 := by
            have hv : (to_slice_mut_back s2).val = s2.val := by
              rw [congrFun s1_post2 s2]
              exact Array.from_slice_val _ s2 (by simpa [Slice.length, mlkem.key.Format.length] using h_len_e)
            rw [henc]
            exact arrayToSpecBytes_eq_sliceToSpecBytes (to_slice_mut_back s2) s2
              (by simpa [Slice.length, mlkem.key.Format.length] using h_len_e) hv
          have h_dec : (to_slice_mut_back1 s4).toSpec = decapsulationKey val1 p768 := by
            have hv : (to_slice_mut_back1 s4).val = s4.val := by
              rw [congrFun s3_post2 s4]
              exact Array.from_slice_val _ s4 (by simpa [Slice.length, mlkem.key.Format.length] using h_len_d)
            rw [hdec]
            exact arrayToSpecBytes_eq_sliceToSpecBytes (to_slice_mut_back1 s4) s4
              (by simpa [Slice.length, mlkem.key.Format.length] using h_len_d) hv
          -- Both blobs are the `KeyGen_internal(d, z)` outputs (mirrors `key_generate.spec`).
          have hek := wfPrivateSeed.fc_encaps h_wfps
          have hks := wfPrivateSeed.fc_keys h_wfps
          have hhh := wfEncapKey.hash_pinned (wfEncapKey_of_wfPrivateSeed h_wfps)
          refine Prod.ext ?_ ?_
          · show (to_slice_mut_back s2).toSpec = _
            rw [h_enc]
            grind [KeyGen_internal]
          · show (to_slice_mut_back1 s4).toSpec = _
            rw [h_dec]
            unfold encapsulationKey at hek
            unfold decapsulationKey encapsulationKey
            grind [KeyGen_internal, H]
        · -- key_get_value (DecapsulationKey) cannot fail: the 2400-byte buffer rules
          -- out every size error, so this branch is unreachable.
          rw [hr4b he2]
          step*
          grind
      · -- key_get_value (EncapsulationKey) cannot fail: the 1184-byte buffer rules
        -- out every size error, so this branch is unreachable.
        rw [hr3b he1]
        step*
        grind
    · -- key_set_value (PrivateSeed load) can only fail with MemoryAllocationFailure
      -- (⇒ out_of_memory): the fixed 64-byte seed, flags = 0, and matching format
      -- rule out the size/flag/blob errors.
      rw [hr2b he]
      step*
      grind

end Symcrust.Properties.MLKEM
