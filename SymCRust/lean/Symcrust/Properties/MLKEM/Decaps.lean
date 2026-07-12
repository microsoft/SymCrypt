/-
  # Decaps.lean — `mlkem.decapsulate` top spec.

  Maps to FIPS 203 Alg. 18 (`ML-KEM.Decaps_internal`).  The Rust
  function is deterministic in its inputs (no randomness draws).

  1. Validate ciphertext length against `(n_bits_of_u, n_bits_of_v)`
     and `has_private_key = true`.
  2. Decompress `c → (u, v)`.
  3. Compute `w := v - INTT(ŝ · NTT(u))` (using the cached `s` in
     standard NTT form).
  4. Recover `m' := ByteEncode_1(Compress_1(w))`.
  5. Re-encapsulate with `m'` to get `(K', c')`.
  6. `K̄ := SHAKE-256(z ‖ c)`; output `K := if c == c' then K' else K̄`
     (constant-time selection).
  7. Wipe ephemeral state.

  No `#decompose` loops at this level; the per-coefficient work lives
  in `vector_decode_and_decompress` / `vector_compress_and_encode` /
  `encapsulate_internal` etc., already scaffolded.

  ## Decapsulation key view

  `dk := dkPKE ‖ ek ‖ H(ek) ‖ z` with lengths summing to
  `384k + (384k + 32) + 32 + 32 = 768k + 96`.  The runtime key holds
  these components in separate slots:
  * `keySEncoded` ↔ `dkPKE` (the 12-bit encoding of `ŝ`).
  * `encapsulationKey` ↔ `ek`.
  * `encaps_key_hash` ↔ `H(ek)`.
  * `private_random` ↔ `z`.
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.KeyView
import Symcrust.Properties.MLKEM.Encoding.Compress
import Symcrust.Properties.MLKEM.Encoding.Decompress
import Symcrust.Properties.MLKEM.Axioms.BoxDefault
import Symcrust.Properties.MLKEM.Key
import Symcrust.Properties.MLKEM.Encaps
import Symcrust.Properties.Stdlib

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

/-! ## `#decompose` cascade for `mlkem.decapsulate`

The body of `mlkem.decapsulate` is a deeply-nested error-handling
dispatch: three input-validation gates (`cb_agreed_secret` length,
`cb_ciphertext = cb_u + cb_v`, `has_private_key`) followed by a
heap allocation gate (`try_new_box_default`); the cryptographic body
is the success arm of the innermost `match`.

We use a 4-level `#decompose` cascade to expose, at the leaf, the
*error-free* cryptographic body `decapsulateBody` — the only function
in this chain that carries a substantive `@[step]` spec.

**The three intermediate dispatchers are plumbing, not proof targets.**
They exist only because `#decompose`'s current grammar cannot extract
the trailing expression of a do-block in a single clause.  Concretely:

* `decapsulateDispatchAgreedLen` is the terminal `if cb_as ≠ 32` …
  isolated as a 1-binding helper so that `branch` is legal on it.
* `decapsulateDispatchCtLen` peels the next `if cb_ct ≠ cb_u + cb_v`.
* `decapsulateDispatchAlloc` peels the `has_private_key` and
  `try_new_box_default` gates.
* `decapsulateBody` is the leaf — the success body, taking the
  validated `local_temps_box : DecapsulateTemps`.

The four `*.fold` equations compose: in the proof of
`mlkem.decapsulate.spec` we chain them via a single
`simp only [decapsulate.fold, decapsulateDispatchAgreedLen.fold,
decapsulateDispatchCtLen.fold, decapsulateDispatchAlloc.fold]`, after
which the dispatchers disappear from goal state and only
`decapsulateBody` remains as a step-eligible call inside the four
nested `if`/`match` layers.  Reviewers: do NOT write `@[step]` specs
for the three dispatchers; they are not on the proof surface.

This cascade is in-scope of Scaffold-3: it cleanly separates the spec
of the cryptographic body (`decapsulateBody.spec`) from the dispatch
plumbing handled inside `mlkem.decapsulate.spec`. -/

#decompose symcrust.mlkem.decapsulate decapsulate.fold
  letRange 9 1 => decapsulateDispatchAgreedLen

#decompose decapsulateDispatchAgreedLen decapsulateDispatchAgreedLen.fold
  branch 1 (letRange 1 1) => decapsulateDispatchCtLen

#decompose decapsulateDispatchCtLen decapsulateDispatchCtLen.fold
  branch 1 (branch 0 (letRange 1 1)) => decapsulateDispatchAlloc

#decompose decapsulateDispatchAlloc decapsulateDispatchAlloc.fold
  branch 0 full => decapsulateBody

/-! ### Sub-decomposition of `decapsulateBody`

The post-prologue body (positions 13–56) is ~44 monadic ops and blows
the parent's heartbeat budget when proven inline.  We split it into
three phase helpers, each with its own `@[local step]` spec.

- **decaps_decrypt** (positions 13–21):
  `vector_ntt → Key.s → vector_mont_dot_product → poly_element_intt_and_mul_r
   → slice (v-half of ct) → cast n_bits_of_v → poly_element_decode_and_decompress
   → Error.eq sc_error1 NoError → massert`.
  Output `(pvu2, pe_tmp01, pa_tmp, pe_tmp1)`: NTT(u'), `NTTInv(⟨ŝ, NTT u'⟩)`
  carried by `pe_tmp01`, the dot-product accumulator scratch, and the
  decompressed v'.

- **decaps_reencaps** (positions 22–30):
  `poly_element_sub_from_in_place (v' − pe_tmp01) → to_slice_mut →
   poly_element_compress_and_encode (m' bytes) → to_slice_mut → projections →
   encapsulate_internal → Error.eq sc_error2 NoError → massert`.
  Output: `(pe_tmp02, s4, s5, pb_decrypted_random1, a, sc_error2,
   s6, pb_reencapsulated_ciphertext1, p_comp_temps, b2)` — actually the
   exposed downstream uses are `pe_tmp02, s6, pb_reencapsulated_ciphertext1,
   p_comp_temps` (the K' bytes, the c' bytes, the hash-state container).

- **decaps_finalize** (positions 31–56):
  4-state SHAKE-256 chain → `const_time_slices_equal` →
  arithmetic (cast/wrapping_sub/AND) for `cb_copy` → `const_time_array_copy`
  for the final cmov → `copy_from_slice pb_agreed_secret` → 4× `wipe_slice`.
  Output: final `pb_agreed_secret1` slice.

Each helper's FC postcondition is stated in spec-side terms (Decrypt /
Encrypt / J(z‖c) / cmov) so the parent's FC composes via three `step`s
of these helpers' specs. -/
#decompose decapsulateBody decapsulateBody.fold
  letRange 13 9 => decaps_decrypt
  letRange 14 23 => decaps_reencaps
  letRange 15 12 => decaps_finalize

/-! ## Decapsulation key view

`decapsulationKey` and `Key.toDecapKey` now live in
`Key/Prelude.lean` (alongside `keySEncoded`) so the format-parametric
helpers in `Encoding/KeySetValue/Prelude.lean` can reference them. -/

/-- Slice identity: the `[0, 384·k)`-prefix of `decapsulationKey` is
`keySEncoded` (the `ŝ`-encoding slot, FIPS 203 Alg. 18 step 1 `dkPKE`). -/
private theorem decapsulationKey_dkPKE_slice
    (self : mlkem.key.Key) (params : ParameterSet) :
    Spec.slice (decapsulationKey self params) 0 (384 * (k params : ℕ))
        (by grind)
      = keySEncoded self params :=
  Helpers.cast_slice_eq_of_append₄ _ _ _ _ _ (by grind)

/-- Slice identity: the `[384·k, 768·k+32)`-window of `decapsulationKey`
is `encapsulationKey` (FIPS 203 Alg. 18 step 2 `ekPKE`). -/
private theorem decapsulationKey_ekPKE_slice
    (self : mlkem.key.Key) (params : ParameterSet) :
    Spec.slice (decapsulationKey self params) (384 * (k params : ℕ))
        (384 * (k params : ℕ) + 32) (by grind)
      = encapsulationKey self params :=
  Helpers.cast_slice_eq_of_append₄_mid _ _ _ _ (by grind) (by grind)

/-- Slice identity: the `[768·k+32, 768·k+64)`-window of `decapsulationKey`
is `Array.toSpec encaps_key_hash` (FIPS 203 Alg. 18 step 3 `H(ekPKE)`). -/
private theorem decapsulationKey_hek_slice
    (self : mlkem.key.Key) (params : ParameterSet) :
    Spec.slice (decapsulationKey self params) (768 * (k params : ℕ) + 32)
        32 (by grind)
      = Array.toSpec self.encaps_key_hash :=
  Helpers.cast_slice_eq_of_append₄_third _ _ _ _ (by grind) _ (by ring) (by grind)

/-- Slice identity: the `[768·k+64, 768·k+96)`-window of `decapsulationKey`
is `Array.toSpec private_random` (FIPS 203 Alg. 18 step 4 `z`).  Used by
the K̄ branch of `decaps_reencaps.spec` to identify the `z ‖ c` absorb
chain that feeds `kbar_from_shake_bridge`. -/
private theorem decapsulationKey_z_slice
    (self : mlkem.key.Key) (params : ParameterSet) :
    Spec.slice (decapsulationKey self params) (768 * (k params : ℕ) + 64)
        32 (by grind)
      = Array.toSpec self.private_random :=
  Helpers.cast_slice_eq_of_append₄_fourth _ _ _ _ (by grind) _ (by scalar_tac) (by grind)

/-! ### Mont/Std bridge for the `s` slot

`Key.s.spec` exposes its post in Montgomery form
(`toMontPoly s.val[i] = (keyS self p)[i]`).  To identify
`toPolyVecOfLen s = keyS_std` (the standard-form view that feeds
`K_PKE.Decrypt`'s `innerProductNTT ŝ (NTT u')`), we need to drop the
`Rinv` map and recover the underlying `toPoly` equality. -/

/-- Bridge: `toMontPoly` is injective on `toPoly`-equalities.

Since `toMontPoly a = (toPoly a).map (· * Rinv)` (definitionally,
`toMontPoly_eq_toPoly_scalarMul`) and `R * Rinv = 1`
(`R_mul_Rinv`), multiplying coefficient-wise by `R` cancels the
`Rinv`.  Used inside the `s` ↔ `keyS_std` derivation needed for
`K_PKE.Decrypt` identification in the `decaps_reencaps` K̄/K' closure
work. -/
private theorem toPoly_eq_of_toMontPoly_eq (a b : PolyElement)
    (h : toMontPoly a = toMontPoly b) : toPoly a = toPoly b := by
  rw [toMontPoly_eq_toPoly_scalarMul, toMontPoly_eq_toPoly_scalarMul] at h
  apply Vector.ext
  intro i hi
  have hi' : (toPoly a)[i] * Rinv = (toPoly b)[i] * Rinv := by
    have h1 : ((toPoly a).map (· * Rinv))[i] = ((toPoly b).map (· * Rinv))[i] :=
      congrArg (fun (v : Vector _ 256) => v[i]) h
    simpa using h1
  have h_RRinv : Rinv * R = 1 := by rw [mul_comm]; exact R_mul_Rinv
  calc (toPoly a)[i]
      = (toPoly a)[i] * 1            := by ring
    _ = (toPoly a)[i] * (Rinv * R)   := by rw [h_RRinv]
    _ = ((toPoly a)[i] * Rinv) * R   := by ring
    _ = ((toPoly b)[i] * Rinv) * R   := by rw [hi']
    _ = (toPoly b)[i] * (Rinv * R)   := by ring
    _ = (toPoly b)[i] * 1            := by rw [h_RRinv]
    _ = (toPoly b)[i]                := by ring

/-- Bridge: the standard-form `PolyVector` view of the `s` slice equals
`keyS_std`, given `Key.s.spec`'s Montgomery-form post.

Composed from `toPoly_eq_of_toMontPoly_eq` (drop `Rinv`) and the
definitional unfolding of `keyS = keyS_std.map (· * Rinv)`. -/
private theorem toPolyVecOfLen_eq_keyS_std
    (self : mlkem.key.Key) (params : ParameterSet)
    (s : Slice (PolyElement))
    (h_len : s.length = (k params : ℕ))
    (h_s3 : ∀ (i : Fin (k params : ℕ)),
      toMontPoly (s.val[(i : ℕ)]'(by have := i.isLt; grind))
        = (keyS self params)[i]) :
    toPolyVecOfLen s (k params) h_len = keyS_std self params := by
  unfold toPolyVecOfLen keyS_std
  apply Vector.ext; intro i hi
  simp only [Vector.getElem_ofFn]
  apply toPoly_eq_of_toMontPoly_eq
  have := h_s3 ⟨i, hi⟩
  rw [this]
  show (keyS self params)[i] = toMontPoly _
  unfold keyS
  rw [Vector.getElem_ofFn]

/-! ### Slice-window bridge

`poly_element_decode_and_decompress.spec` exposes its post in terms of
`sliceToSpecBytes s2 (32 * d) _`, where `s2` is a `List.drop`-suffix
of the parent ciphertext `pb_read_ciphertext1`.  The parent's
`K_PKE.Decrypt` spec uses `sliceWindowToSpecBytes pb_read_ciphertext1
offset len _`.  This lemma bridges the two views, so the spec tie
`toPoly pe_tmp1 = decodeDecompressPoly _ (sliceWindowToSpecBytes _
cb_u (32·dᵥ) _) _` can be derived from the impl-side post. -/

/-- Window-form counterpart to `sliceToSpecBytes_drop_eq_sliceWindow`: when
the windowed per-poly spec returns `sliceWindowToSpecBytes s 0 n h`,
bridge it to the parent ciphertext's window via
`s.val = parent.val.drop off`. -/
private theorem sliceWindowToSpecBytes_drop_eq_sliceWindow
    (parent s : Slice U8) (off n : ℕ)
    (h_val : s.val = List.drop off parent.val)
    (h_s_window : n ≤ s.length)
    (h_window : off + n ≤ parent.length) :
    sliceWindowToSpecBytes s 0 n (by omega)
      = sliceWindowToSpecBytes parent off n h_window := by
  unfold sliceWindowToSpecBytes
  apply Vector.ext
  intro i hi
  simp only [Vector.getElem_ofFn, Nat.zero_add]
  have h_s_len_v : s.val.length = s.length := rfl
  have hi_s : i < s.val.length := by rw [h_s_len_v]; omega
  have h_parent_ge : parent.val.length ≥ off + n := h_window
  have h_drop_idx : i < (List.drop off parent.val).length := by
    rw [List.length_drop]; omega
  have h_eq : s.val[i]'hi_s = parent.val[off + i]'(by omega) := by
    have h1 : s.val[i]'hi_s = (List.drop off parent.val)[i]'h_drop_idx := by
      simp [getElem_congr_coll h_val]
    rw [h1, List.getElem_drop]
  fcongr 1

/-! ### Bridge: `from_slice` of an array yields a slice-equivalent view.

`pb.from_slice s` rebuilds the parent `Array U8 32` by overwriting its
content with the supplied slice `s` (length 32 = array size).  Both the
`.toSpec` of the new array and the `.toSpec 32 _` of the source slice
amount to the same `Vector.ofFn fun i => s.val[i].bv`.

Used three times by `decaps_reencaps.spec`'s K̄/K' branches to bridge
`(to_slice_mut_back* s).toSpec` (the result-buffer view used by
`Decaps_internal`) back to `s.toSpec 32 _` (the form in which
`encapsulate_internal.spec` and the SHAKE chain expose their outputs). -/
private theorem from_slice_toSpec_eq
    (a : Array U8 32#usize) (s : Slice U8) (h : s.length = 32) :
    (a.from_slice s).toSpec = s.toSpec 32 h := by
  have h_val : (a.from_slice s).val = s.val :=
    Aeneas.Std.Array.from_slice_val _ _
      (by rw [show s.val.length = s.length from rfl, h]; rfl)
  apply Vector.ext
  intro i hi
  show (arrayToSpecBytes (a.from_slice s))[i] = (sliceToSpecBytes s 32 h)[i]
  unfold arrayToSpecBytes sliceToSpecBytes
  simp only [Vector.getElem_ofFn]
  have hi' : i < (a.from_slice s).val.length := by
    rw [h_val]; show i < s.length; rw [h]; exact hi
  have heq : (a.from_slice s).val[i]'hi' =
      s.val[i]'(by rw [show s.val.length = s.length from rfl, h]; exact hi) :=
    List.getElem_of_eq h_val hi'
  rw [heq]

/-! ### Bridge: `sliceWindowToSpecBytes` of a `List.slice 0 cb` prefix.

When `s.val = List.slice 0 cb parent.val` and the requested window
`[off, off+n)` fits inside the truncated `[0, cb)` region, the window's
bytes coincide with the corresponding window of the parent.  Used in
the per-row identification of `pvu1[j]` in `decapsulateBody.spec`'s
`h_decrypt_eq_spec` discharge, where the loop's source slice is the
`[0, cb_u)`-prefix of `pb_read_ciphertext1`. -/
private theorem sliceWindow_of_prefix_slice
    (s parent : Slice U8) (off n cb : ℕ)
    (h_val : s.val = List.slice 0 cb parent.val)
    (h_s_len : off + n ≤ s.length)
    (h_p_len : off + n ≤ parent.length) :
    sliceWindowToSpecBytes s off n h_s_len
      = sliceWindowToSpecBytes parent off n h_p_len := by
  unfold sliceWindowToSpecBytes
  apply Vector.ext
  intro i hi
  simp only [Vector.getElem_ofFn]
  fcongr 1
  have h_s_len' : s.val.length = s.length := rfl
  have h_idx_s : off + i < s.val.length := by
    rw [h_s_len']; exact Nat.lt_of_lt_of_le (Nat.add_lt_add_left hi off) h_s_len
  have h1 : s.val[off + i]'h_idx_s =
      (List.slice 0 cb parent.val)[off + i]'(by rw [← h_val]; exact h_idx_s) :=
    List.getElem_of_eq h_val h_idx_s
  rw [h1]
  unfold List.slice
  simp

/-! ### Bridge: spec-side `slice ∘ toSpec = sliceWindowToSpec`.

By definition, both sides build a `Vector.ofFn fun i => s.val[off+i].bv`.
Used in `h_decrypt_eq_spec`'s discharge to bridge the spec-side
`slice (pb_read_ciphertext1.toSpec _) off n _` (as used by
`K_PKE.Decrypt`) to the impl-side `sliceWindowToSpecBytes` form
(as exposed by `pvu2_post7` and `sc_error_post3`). -/
private theorem slice_toSpec_eq_sliceWindow
    (s : Slice U8) (N : ℕ) (h_s_len : s.length = N)
    (off n : ℕ) (h_w : off + n ≤ N) :
    Spec.slice (s.toSpec N h_s_len) off n h_w
      = sliceWindowToSpecBytes s off n (by rw [h_s_len]; exact h_w) := by
  unfold Spec.slice
  show Vector.ofFn (fun i => (sliceToSpecBytes s N h_s_len)[off + i]) = _
  unfold sliceToSpecBytes sliceWindowToSpecBytes
  apply Vector.ext
  intro i hi
  simp only [Vector.getElem_ofFn]

/-! ### Bridge: `keyS_std` is the 12-bit ByteDecode of `keySEncoded`.

By `keySEncoded` definition (Prelude.lean L79) and the PolyVector-level
round-trip `polyVector_byteDecode_byteEncode`, decoding the 12-bit
encoding of `keyS_std` recovers `keyS_std`.  Provides the `h_s`
witness for `K_PKE.Decrypt_eq` in `h_decrypt_eq_spec`'s discharge. -/
private theorem keyS_std_eq_byteDecode_keySEncoded
    (self : mlkem.key.Key) (params : ParameterSet) :
    keyS_std self params =
      MLKEM.PolyVector.ByteDecode 12
        ((keySEncoded self params).cast (by grind))
        (by decide) := by
  unfold keySEncoded
  rw [Vector.cast_cast]
  exact (polyVector_byteDecode_byteEncode 12 (by decide) (keyS_std self params)).symm

/-! ### Bridge: `Slice.toSpec` is injective on `.val` (length-preserving).

Two slices of the same length with equal underlying byte lists have
equal `toSpec`s.  Both reduce to `Vector.ofFn fun i => s.val[i].bv`.
Used in `decaps_reencaps.spec`'s K̄/K' branches to lift
`successful_reencrypt_post`'s `.val =`/`.val ≠` to the spec-side
ciphertext (in)equality consumed by `Decaps_internal`'s `if c ≠ c'`. -/
private theorem Slice.toSpec_congr_val
    (s1 s2 : Slice U8) (n : ℕ) (h1 : s1.length = n) (h2 : s2.length = n)
    (h_val : s1.val = s2.val) :
    s1.toSpec n h1 = s2.toSpec n h2 := by
  unfold Aeneas.Std.Slice.toSpec
  apply Vector.ext
  intro i hi
  grind [sliceToSpecBytes]

/-! ### Bridge: `Slice.toSpec` injection on `.val` (the converse direction).

The contrapositive form is what `decaps_reencaps.spec`'s K̄ branch
consumes: `successful_reencrypt = false` gives `.val ≠ .val`, which
must be lifted to `.toSpec ≠ .toSpec` to feed into `Decaps_internal`'s
`if c ≠ c'`. -/
private theorem Slice.toSpec_inj_val
    (s1 s2 : Slice U8) (n : ℕ) (h1 : s1.length = n) (h2 : s2.length = n)
    (heq : s1.toSpec n h1 = s2.toSpec n h2) : s1.val = s2.val := by
  apply List.ext_getElem
  · rw [show s1.val.length = s1.length from rfl,
        show s2.val.length = s2.length from rfl, h1, h2]
  · intro i h_i1 _
    have hi : i < n := by
      rw [show s1.val.length = s1.length from rfl, h1] at h_i1; exact h_i1
    have hg := congrArg (·[i]'(by simp [hi])) heq
    grind [sliceToSpecBytes]

/-! ### Bridge: `sliceToSpecBytes` to `List.map (·.bv)` at arbitrary length.

Same pattern as `Key/Prelude.lean:sliceToSpecBytes_toList_bv_32` but for
arbitrary length `n`.  Used by the K̄ branch of `decaps_reencaps.spec`
to bridge `pb_read_ciphertext1.toSpec.toList` ↔
`pb_read_ciphertext1.val.map (·.bv)` inside the `h_absorbed`
hypothesis for `kbar_from_shake_bridge`. -/
private theorem sliceToSpecBytes_toList_bv
    (s : Slice U8) (n : ℕ) (h : s.length = n) :
    (sliceToSpecBytes s n h).toList = (↑s : List U8).map (·.bv) := by
  unfold sliceToSpecBytes
  rw [Vector.toList_ofFn]
  apply List.ext_getElem
  · simp [h]
  · intro k _ _; rw [List.getElem_ofFn, List.getElem_map]

/-- The K̄-branch bridge: the spec-side concatenation `arr.toSpec ‖
slc.toSpec` has list form equal to the per-byte `(·.bv)`-mapped
underlying bytes.  Hoisted to a top-level helper so that the rfl-style
elaboration runs in a small context and never triggers a heartbeat
timeout inside the heavy `decaps_reencaps.spec` body. -/
private theorem arrayToSpecBytes_sliceToSpecBytes_append_toList
    (a : Std.Array U8 32#usize) (s : Slice U8) (n : ℕ) (h : s.length = n) :
    a.val.map (·.bv) ++ (↑s : List U8).map (·.bv)
      = (arrayToSpecBytes a ‖ sliceToSpecBytes s n h).toList := by
  rw [← arrayToSpecBytes_toList_bv, ← sliceToSpecBytes_toList_bv]
  exact (Vector.toList_append).symm

/-! ### Bridge: slice-of-prefix-slice collapses.

`slice (slice v 0 a) o len = slice v o len`.  Both unfold to
`Vector.ofFn fun i => v[o + i]`.  Used by `h_decrypt_eq_spec`'s
discharge to bridge `K_PKE.Decrypt_eq`'s `h_u` witness, where the
prefix slice models the u-portion of the ciphertext. -/
private theorem slice_of_slice_zero
    {α : Type*} {n : ℕ} (v : Vector α n) (a o len : ℕ)
    (h2 : o + len ≤ a) (h3 : a ≤ n) :
    Spec.slice (Spec.slice v 0 a (by agrind)) o len h2 =
    Spec.slice v o len (by agrind) := by
  unfold Spec.slice
  apply Vector.ext
  intro i hi
  simp [Vector.getElem_ofFn]

/-! ### Bridge: per-row u' equality for `h_decrypt_eq_spec`'s `h_u` witness.

Hoisted to a top-level helper to avoid heartbeat exhaustion in the
heavy `decapsulateBody.spec` body.  Combines:
- `sc_error_post3.NoError` (per-row `toPoly pvu1[j]` = decode-decompress
  of the impl-side window into `s`);
- `sliceWindow_of_prefix_slice` (lifting the window from `s` to the
  parent ciphertext slice);
- `slice_toSpec_eq_sliceWindow` (bridging impl-side `sliceWindow` to
  spec-side `slice ∘ toSpec`);
- `slice_of_slice_zero` (collapsing the spec-side
  `slice (slice c 0 (32·dᵤ·k)) (32·dᵤ·j) (32·dᵤ)` to
  `slice c (32·dᵤ·j) (32·dᵤ)`).

This is the `h_u` argument for `K_PKE.Decrypt_eq` in the discharge of
`decaps_reencaps.spec`'s `h_decrypt_eq_spec` precondition. -/
set_option maxHeartbeats 8000000 in
private theorem toPolyVecOfLen_pvu1_eq
    (p : ParameterSet)
    (pb_read_ciphertext1 s_slice : Slice U8)
    (pvu1 : Slice PolyElement)
    (cb_u_val : ℕ) (i7_val : ℕ)
    (h_rc_len : pb_read_ciphertext1.length = cipherlength p)
    (h_pvu1_len : pvu1.length = (k p : ℕ))
    (h_s_val : s_slice.val = List.slice 0 cb_u_val pb_read_ciphertext1.val)
    (h_s_len : s_slice.length = cb_u_val)
    (h_cb_u : cb_u_val = 32 * dᵤ p * ↑(k p))
    (h_i7 : i7_val = dᵤ p)
    (h_perRow : ∀ (j : ℕ) (h_j : j < pvu1.length)
        (h_src_window : j * (32 * i7_val) + 32 * i7_val ≤ s_slice.length),
        toPoly pvu1.val[j] =
          decodeDecompressPoly i7_val
            (sliceWindowToSpecBytes s_slice (j * (32 * i7_val)) (32 * i7_val) h_src_window)
            (by subst h_i7; rcases p <;> decide)) :
    toPolyVecOfLen pvu1 (k p) h_pvu1_len =
      MLKEM.PolyVector.Decompress (dᵤ p)
        (MLKEM.PolyVector.ByteDecode (dᵤ p)
          (Spec.slice (pb_read_ciphertext1.toSpec (cipherlength p) h_rc_len) 0
            (32 * dᵤ p * ↑(k p)) (by rcases p <;> simp [cipherlength, dᵤ, dᵥ]))
          (by rcases p <;> simp [dᵤ]))
        (by rcases p <;> simp [dᵤ]) := by
  subst h_i7
  have h_du_lt : dᵤ p < 12 := by rcases p <;> decide
  have h_du_pos : 1 ≤ dᵤ p := by rcases p <;> decide
  have h_kp_pos : 1 ≤ (k p : ℕ) := by rcases p <;> decide
  have h_clen : cipherlength p = 32 * dᵤ p * (k p : ℕ) + 32 * dᵥ p := by
    rcases p <;> rfl
  have h_dvpos : 1 ≤ dᵥ p := by rcases p <;> decide
  have h_kdu_le_cl : 32 * dᵤ p * ↑(k p) ≤ cipherlength p := by
    rw [h_clen]; exact Nat.le_add_right _ _
  apply Vector.ext
  intro j hj
  have hj_pvu : j < pvu1.length := by rw [h_pvu1_len]; exact hj
  have h_jk : j + 1 ≤ ↑(k p) := by rw [← h_pvu1_len]; exact hj_pvu
  have h_jk_mul : (j + 1) * (32 * dᵤ p) ≤ ↑(k p) * (32 * dᵤ p) :=
    Nat.mul_le_mul_right _ h_jk
  have h_src_window : j * (32 * dᵤ p) + 32 * dᵤ p ≤ s_slice.length := by
    rw [h_s_len, h_cb_u]
    calc j * (32 * dᵤ p) + 32 * dᵤ p
        = (j + 1) * (32 * dᵤ p) := by ring
      _ ≤ ↑(k p) * (32 * dᵤ p) := h_jk_mul
      _ = 32 * dᵤ p * ↑(k p) := by ring
  have h_window_p : j * (32 * dᵤ p) + 32 * dᵤ p ≤ pb_read_ciphertext1.length := by
    rw [h_rc_len]
    apply Nat.le_trans _ h_kdu_le_cl
    calc j * (32 * dᵤ p) + 32 * dᵤ p
        = (j + 1) * (32 * dᵤ p) := by ring
      _ ≤ ↑(k p) * (32 * dᵤ p) := h_jk_mul
      _ = 32 * dᵤ p * ↑(k p) := by ring
  have h_jdu_le : 32 * dᵤ p * j + 32 * dᵤ p ≤ 32 * dᵤ p * ↑(k p) := by
    calc 32 * dᵤ p * j + 32 * dᵤ p
        = (j + 1) * (32 * dᵤ p) := by ring
      _ ≤ ↑(k p) * (32 * dᵤ p) := h_jk_mul
      _ = 32 * dᵤ p * ↑(k p) := by ring
  -- Expose LHS element via toPolyVecOfLen unfold + Vector.getElem_ofFn
  unfold toPolyVecOfLen
  rw [Vector.getElem_ofFn]
  rw [h_perRow j hj_pvu h_src_window]
  -- Unfold RHS layer by layer to expose its element form
  unfold MLKEM.PolyVector.Decompress
  rw [Vector.getElem_map]
  unfold MLKEM.PolyVector.ByteDecode
  rw [Vector.getElem_ofFn]
  simp only []
  unfold decodeDecompressPoly
  rw [dif_pos h_du_lt]
  rw [sliceWindow_of_prefix_slice s_slice pb_read_ciphertext1 (j * (32 * dᵤ p)) (32 * dᵤ p)
        cb_u_val h_s_val h_src_window h_window_p]
  rw [slice_of_slice_zero (pb_read_ciphertext1.toSpec (cipherlength p) h_rc_len)
        (32 * dᵤ p * ↑(k p)) (32 * dᵤ p * j) (32 * dᵤ p) h_jdu_le h_kdu_le_cl]
  rw [← slice_toSpec_eq_sliceWindow pb_read_ciphertext1 (cipherlength p) h_rc_len
        (j * (32 * dᵤ p)) (32 * dᵤ p) (by rw [show j * (32 * dᵤ p) = 32 * dᵤ p * j from by ring]; exact Nat.le_trans h_jdu_le h_kdu_le_cl)]
  fcongr 2
  ring_nf

/-! ### Phase-helper step specs

Each fold helper gets a full functional-correctness `@[local step]` spec
so the parent `decapsulateBody.spec` proof composes via `rw
[decapsulateBody.fold] ; step ; step ; step` rather than re-elaborating
the ~44-step inlined tail.  All three bodies are proved; the
**statements** carry the FC contracts required by the parent.

The postconditions are written in spec-side terms so that composing
them yields `Slice.toSpec agreed' 32 _ = MLKEM.Decaps_internal params
dk c` in the parent.  See the docstring above the parent for the FIPS
203 algorithm correspondence. -/

/-- **Phase 1 — decryption (positions 13–21).**

Computes the K-PKE.Decrypt internals.  Given the already-decoded
`pvu1 = u'` (PolyVector in standard form), produces:
- `pvu2 = NTT(u')`;
- `pe_tmp01` carrying `NTTInv(innerProductNTT ŝ (NTT u'))`
  (via R-cancellation through `decaps_m_chain_std`,
   `Bridges/MatrixVectorMul.lean`);
- `pe_tmp1` carrying `v' = Polynomial.Decompress dᵥ (ByteDecode c₂)`
  for `c₂ = slice c (32·dᵤ·k) (32·dᵥ)`.

The dot-product accumulator `pa_tmp` is internal scratch; no FC. -/
@[local step]
private theorem decaps_decrypt.spec
    (params : ParameterSet)
    (pk_mlkem_key : mlkem.key.Key)
    (cb_u : UScalar UScalarTy.Usize)
    (local_temps_box : mlkem.DecapsulateTemps)
    (pb_read_ciphertext1 : Slice U8)
    (pvu1 : Slice (Array U16 256#usize))
    (h_wf : wfKey pk_mlkem_key params)
    (h_cb_u : cb_u.val = 32 * (dᵤ params : ℕ) * (k params : ℕ))
    (h_pvu1_len : pvu1.length = (k params : ℕ))
    (h_wf_pvu1 : wfPolyVec pvu1)
    (h_wfpe1 : wfPoly local_temps_box.comp_temps.poly_element1)
    (h_ct_len : pb_read_ciphertext1.length = cipherlength params) :
    decaps_decrypt pk_mlkem_key cb_u local_temps_box pb_read_ciphertext1 pvu1
      ⦃ pvu2 _pa_tmp pe_tmp01 pe_tmp1 =>
          pvu2.length = (k params : ℕ) ∧
          wfPolyVec pvu2 ∧
          wfPoly pe_tmp01 ∧
          wfPoly pe_tmp1 ∧
          -- Spec tie for `pe_tmp01`: matches `K_PKE.Decrypt`'s
          -- `NTTInv(innerProductNTT ŝ (NTT u'))` factor, with
          -- `ŝ = keyS_std` and `u'` exposed via `toPolyVecOfLen pvu1`.
          toPoly pe_tmp01 = NTTInv
            (PolyVector.innerProductNTT
              (keyS_std pk_mlkem_key params)
              ((toPolyVecOfLen pvu1 (k params) h_pvu1_len).map NTT)) ∧
          -- Spec tie for `pe_tmp1`: matches `K_PKE.Decrypt`'s
          -- `Polynomial.Decompress dᵥ (ByteDecode c₂)` factor, with
          -- `c₂` the `[cb_u, cb_u + 32·dᵥ)` window of the parent ciphertext.
          ∃ (h_window : cb_u.val + 32 * dᵥ params ≤ pb_read_ciphertext1.length),
            toPoly pe_tmp1 = decodeDecompressPoly (dᵥ params)
              (sliceWindowToSpecBytes pb_read_ciphertext1 cb_u.val
                (32 * dᵥ params) h_window)
              (by rcases params <;> decide) ⦄ := by
  have h_params_ok := wfKey.params_ok h_wf
  have h_n_rows : pk_mlkem_key.params.n_rows.val = (k params : ℕ) :=
    wfInternalParams.n_rows_val h_params_ok
  have h_n_bits_of_v : pk_mlkem_key.params.n_bits_of_v.val = dᵥ params :=
    wfInternalParams.n_bits_of_v_val h_params_ok
  have h_k_ge_2 : 2 ≤ (k params : ℕ) := k_ge_2 params
  have h_k_le_4 : (k params : ℕ) ≤ 4 := k_le_4 params
  have h_dᵥ_bounds : 1 ≤ dᵥ params ∧ dᵥ params ≤ 12 := by
    rcases params <;> decide
  unfold decaps_decrypt
  step*
  · -- case kn ⊢ K — supply the dot-product's vector-length witness
    exact k params
  · -- case h_kn ⊢ ↑(k params) = s1.length — from Key.s spec
    exact s1_post1.symm
  · -- case h_wf1 ⊢ wfPolyVec s1
    intro i hi; exact s1_post2 i hi
  -- Continue: pull in `poly_element_intt_and_mul_r`, slice index,
  -- n_bits_of_v lift, decode_and_decompress, Error.eq, massert.
  step*
  case h_len =>
    -- s2.length = ↑i8 * 32 (sliced suffix length)
    have hi8 : i8.val = dᵥ params := by
      rw [i8_post]; simp; exact h_n_bits_of_v
    have h_s2 : s2.length = pb_read_ciphertext1.length - cb_u.val := s2_post2
    rw [h_s2, h_ct_len, h_cb_u, hi8]; unfold cipherlength
    agrind
  case _ =>
    -- b1 = true (massert sc_error1 = NoError)
    simp only [b1_post]
    rcases sc_error1 with _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _
      | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _
    case NoError => rfl
    case InvalidBlob =>
      exfalso
      simp only at sc_error1_post2
      have hi8 : i8.val = dᵥ params := by
        rw [i8_post]; simp; exact h_n_bits_of_v
      rw [hi8] at sc_error1_post2
      rcases params <;> simp [dᵥ] at sc_error1_post2
    all_goals exact sc_error1_post2.elim
  -- *** Discharge the strengthened 6-conjunct post explicitly. ***
  -- After the massert, `sc_error1 = NoError` is extractable from `b1_post`;
  -- specialise `sc_error1_post2` and combine with the dot-product spec ties.
  have h_no : sc_error1 = Error.NoError := b1_post.mp (by assumption)
  rw [h_no] at sc_error1_post2
  obtain ⟨h_window_s2, h_pe_tmp1_eq, _h_canon_pe_tmp1⟩ := sc_error1_post2
  have hi8 : i8.val = dᵥ params := by
    rw [i8_post]; simp; exact h_n_bits_of_v
  -- Conjunct A: pe_tmp01 ≈ NTTInv(innerProductNTT keyS_std (NTT u'))
  --   pe_tmp01 = (NTTInv (toPoly pe_tmp0)).map (R*·)        -- pe_tmp01_post2
  --   toPoly pe_tmp0 = (innerProductNTT ...).map (Rinv*·)   -- pe_tmp0_post3
  --   ⇒ (NTTInv ((⋯).map (Rinv*·))).map (R*·) = NTTInv (⋯)  -- decaps_m_chain_std
  --   then identify toPolyVecOfLen s1 = keyS_std, and
  --   toPolyVecOfLen pvu2 = (toPolyVecOfLen pvu1).map NTT via pvu2_post3.
  have h_pe_tmp01_eq : toPoly pe_tmp01 = NTTInv
      (PolyVector.innerProductNTT
        (keyS_std pk_mlkem_key params)
        ((toPolyVecOfLen pvu1 (k params) h_pvu1_len).map NTT)) := by
    rw [pe_tmp01_post2, pe_tmp0_post3, decaps_m_chain_std]
    -- Goal: NTTInv (innerProductNTT (toPolyVecOfLen s1 ⋯) (toPolyVecOfLen pvu2 ⋯))
    --     = NTTInv (innerProductNTT keyS_std ((toPolyVecOfLen pvu1).map NTT))
    -- Rewrite s1- and pvu2-side factors individually, then close by rfl.
    have h_s_eq : toPolyVecOfLen s1 (k params) s1_post1 = keyS_std pk_mlkem_key params :=
      toPolyVecOfLen_eq_keyS_std pk_mlkem_key params s1 s1_post1 s1_post3
    have h_u_eq : toPolyVecOfLen pvu2 (k params) (pvu2_post2.trans h_pvu1_len)
                = (toPolyVecOfLen pvu1 (k params) h_pvu1_len).map NTT := by
      unfold toPolyVecOfLen
      apply Vector.ext; intro i hi
      simp only [Vector.getElem_ofFn, Vector.getElem_map]
      apply pvu2_post3
    rw [h_s_eq, h_u_eq]
  -- Conjunct B: ∃ h_window, pe_tmp1 ≈ decodeDecompressPoly dᵥ (sliceWindow c cb_u 32·dᵥ)
  have h_window : cb_u.val + 32 * dᵥ params ≤ pb_read_ciphertext1.length := by
    rw [h_ct_len, h_cb_u]; unfold cipherlength
    have h : 32 * dᵤ params * (k params : ℕ) + 32 * dᵥ params
          = 32 * (dᵤ params * (k params : ℕ) + dᵥ params) := by ring
    rw [h]
  -- Bridge i8.val ↔ dᵥ params through a generalised statement; this
  -- avoids `rw` on dependent occurrences inside `decodeDecompressPoly`.
  have h_pe_tmp1_eq' : toPoly pe_tmp1 = decodeDecompressPoly (dᵥ params)
      (sliceWindowToSpecBytes pb_read_ciphertext1 cb_u.val (32 * dᵥ params) h_window)
      (by rcases params <;> decide) := by
    suffices h : ∀ (d : ℕ) (_hd : i8.val = d)
        (h_window' : cb_u.val + 32 * d ≤ pb_read_ciphertext1.length)
        (h_d_bds : 1 ≤ d ∧ d ≤ 12),
        toPoly pe_tmp1 = decodeDecompressPoly d
          (sliceWindowToSpecBytes pb_read_ciphertext1 cb_u.val (32 * d) h_window') h_d_bds by
      exact h (dᵥ params) hi8 h_window (by rcases params <;> decide)
    intro d hd h_window' h_d_bds
    subst hd
    rw [h_pe_tmp1_eq]
    fcongr 1
    exact sliceWindowToSpecBytes_drop_eq_sliceWindow pb_read_ciphertext1 s2 cb_u.val
      (32 * i8.val) s2_post1 h_window_s2 h_window'
  refine ⟨?_, pvu2_post1, pe_tmp01_post1, sc_error1_post1, h_pe_tmp01_eq,
          h_window, h_pe_tmp1_eq'⟩
  rw [pvu2_post2]; exact h_pvu1_len

/-- The cmov mask `cb_copy = i10 &&& i11` evaluates to 0 or 32. -/
private theorem cb_copy_in_set
    (successful_reencrypt : Bool) (i9 i10 i11 cb_copy : U32)
    (i9_post : i9.val = successful_reencrypt.toNat)
    (i10_post : i10 = core.num.U32.wrapping_sub i9 1#u32)
    (i11_post : i11 = UScalar.cast UScalarTy.U32 mlkem.SIZEOF_AGREED_SECRET)
    (cb_copy_post1 : (↑cb_copy : ℕ) = ↑(i10 &&& i11)) :
    (↑cb_copy : ℕ) = 0 ∨ (↑cb_copy : ℕ) = 32 := by
  rcases h_sr : successful_reencrypt with _ | _ <;> simp_all <;> [right; left] <;> native_decide

/-- K̄ branch of `decaps_reencaps`: when `successful_reencrypt = false`,
`cb_copy = 32` and the agreed secret comes from
`Spec.MLKEM.J (z ‖ c)`. -/
private theorem decaps_kbar_branch
    (params : ParameterSet)
    (pk_mlkem_key : mlkem.key.Key)
    (h_hash : pk_mlkem_key.encaps_key_hash.toSpec =
              Spec.SHA3.sha3_256 (encapsulationKey pk_mlkem_key params))
    (pb_read_ciphertext1 pb_reencapsulated_ciphertext1 : Slice U8)
    (h_read_ct_len : pb_read_ciphertext1.length = cipherlength params)
    (h_c_len : pb_reencapsulated_ciphertext1.length = cipherlength params)
    (pb_decrypted_random pb_implicit_rejection_secret : Array U8 32#usize)
    (pe_tmp01 pe_tmp1 pe_tmp02 : Array U16 256#usize)
    (pe_tmp02_post2 :
      toPoly pe_tmp02 =
        Vector.ofFn fun j : Fin 256 =>
          (toPoly pe_tmp1).get j - (toPoly pe_tmp01).get j)
    (h_decrypt_eq_spec :
      ∀ (P : MLKEM.Polynomial),
        P = Vector.ofFn (fun j : Fin 256 =>
          (toPoly pe_tmp1).get j - (toPoly pe_tmp01).get j) →
        Vector.cast (Nat.mul_one 32)
          (compressEncodePoly 1 P (by decide)) =
        Spec.MLKEM.K_PKE.Decrypt params
          (keySEncoded pk_mlkem_key params)
          (pb_read_ciphertext1.toSpec (cipherlength params) h_read_ct_len))
    (s4 s7 s8 s9 : Slice U8)
    (to_slice_mut_back to_slice_mut_back2 : Slice U8 → Array U8 32#usize)
    (s3_post2 : to_slice_mut_back = pb_decrypted_random.from_slice)
    (s4_post1 : s4.length = 32 * ↑(1#u32 : U32))
    (s4_post2 :
      sliceToSpecBytes s4 (32 * ↑(1#u32 : U32)) s4_post1 =
        compressEncodePoly (↑(1#u32 : U32)) (toPoly pe_tmp02) (by decide))
    (h_c_eq :
      pb_reencapsulated_ciphertext1.toSpec (cipherlength params) h_c_len =
        (Spec.MLKEM.Encaps_internal params (pk_mlkem_key.toEncapKey params)
          (to_slice_mut_back s4).toSpec).2)
    (s7_post : s7 = pk_mlkem_key.private_random.to_slice)
    (p_shake_state p_shake_state1 p_shake_state2 p_shake_state3
      : mlkem.hash.MlKemHashState)
    (p_shake_state_post2 : p_shake_state.alg = mlkem.hash.MlKemHashAlg.Shake256)
    (p_shake_state1_post1 : p_shake_state1.alg = p_shake_state.alg)
    (p_shake_state1_post2 :
      p_shake_state1.absorbing (sha3.sha3_impl.GhostState.init 136 31#u8 (by decide)))
    (p_shake_state2_post1 : p_shake_state2.alg = p_shake_state1.alg)
    (p_shake_state2_post2 :
      p_shake_state2.absorbing
        ((sha3.sha3_impl.GhostState.init 136 31#u8 (by decide)).append
          (↑s7) p_shake_state1.state.squeeze_mode))
    (p_shake_state3_post1 : p_shake_state3.alg = p_shake_state2.alg)
    (p_shake_state3_post2 :
      p_shake_state3.absorbing
        (((sha3.sha3_impl.GhostState.init 136 31#u8 (by decide)).append
          (↑s7) p_shake_state1.state.squeeze_mode).append
            (↑pb_read_ciphertext1) p_shake_state2.state.squeeze_mode))
    (s8_post1 : (↑s8 : List U8) = ↑pb_implicit_rejection_secret)
    (s8_post2 : to_slice_mut_back2 = pb_implicit_rejection_secret.from_slice)
    (__post2 : s9.length = s8.length)
    (__post3 :
      ↑s9 =
        (sha3.sha3_impl.extractOutput
          (((sha3.sha3_impl.GhostState.init 136 31#u8 (by decide)).append
            (↑s7) p_shake_state1.state.squeeze_mode).append
              (↑pb_read_ciphertext1) p_shake_state2.state.squeeze_mode)
          s8.length).toList)
    (successful_reencrypt : Bool)
    (successful_reencrypt_post :
      successful_reencrypt = true ↔
        (↑pb_reencapsulated_ciphertext1 : List U8) = ↑pb_read_ciphertext1)
    (h_sr : successful_reencrypt = false) :
    (to_slice_mut_back2 s9).toSpec =
      Spec.MLKEM.Decaps_internal params (decapsulationKey pk_mlkem_key params)
        (pb_read_ciphertext1.toSpec (cipherlength params) h_read_ct_len) := by
  have h_m_impl_eq : (to_slice_mut_back s4).toSpec =
      Spec.MLKEM.K_PKE.Decrypt params (keySEncoded pk_mlkem_key params)
        (pb_read_ciphertext1.toSpec (cipherlength params) h_read_ct_len) := by
    rw [s3_post2, from_slice_toSpec_eq pb_decrypted_random s4 s4_post1]
    rw [← h_decrypt_eq_spec (toPoly pe_tmp02) pe_tmp02_post2]
    have heq : s4.toSpec 32 s4_post1
        = sliceToSpecBytes s4 (32 * ↑(1#u32 : U32)) s4_post1 := rfl
    rw [heq, s4_post2]
    rfl
  have h_c_val_neq : pb_reencapsulated_ciphertext1.val ≠ pb_read_ciphertext1.val := by
    intro heq
    have h_t : successful_reencrypt = true := successful_reencrypt_post.mpr heq
    rw [h_t] at h_sr; cases h_sr
  have h_c_spec_neq :
      pb_reencapsulated_ciphertext1.toSpec (cipherlength params) h_c_len ≠
      pb_read_ciphertext1.toSpec (cipherlength params) h_read_ct_len := by
    intro hspec
    exact h_c_val_neq (Slice.toSpec_inj_val _ _ _ _ _ hspec)
  have h_alg : p_shake_state3.alg = mlkem.hash.MlKemHashAlg.Shake256 := by
    rw [p_shake_state3_post1, p_shake_state2_post1, p_shake_state1_post1,
        p_shake_state_post2]
  have h_sm1 : p_shake_state1.state.squeeze_mode = false :=
    squeeze_mode_eq_false_of_absorbing p_shake_state1_post2
  have h_sm2 : p_shake_state2.state.squeeze_mode = false :=
    squeeze_mode_eq_false_of_absorbing p_shake_state2_post2
  set zc : 𝔹 (32 + cipherlength params) :=
    pk_mlkem_key.private_random.toSpec ‖
      pb_read_ciphertext1.toSpec (cipherlength params) h_read_ct_len with hzc
  have h_s7_val : (↑s7 : List U8) = pk_mlkem_key.private_random.val := by
    rw [s7_post]; rfl
  have h_s8_len : s8.length = 32 := by
    rw [show s8.length = s8.val.length from rfl, s8_post1]
    exact pb_implicit_rejection_secret.property
  have h_s9_len : s9.length = 32 := by rw [__post2]; exact h_s8_len
  have h_absorbed :
      ((((sha3.sha3_impl.GhostState.init 136 31#u8 (by decide)).append
          (↑s7) p_shake_state1.state.squeeze_mode).append
          (↑pb_read_ciphertext1) p_shake_state2.state.squeeze_mode).absorbed.map (·.bv))
        = zc.toList := by
    rw [h_sm1, h_sm2]
    simp [sha3.sha3_impl.GhostState.append, sha3.sha3_impl.GhostState.init,
          List.map_append]
    rw [hzc, h_s7_val]
    exact arrayToSpecBytes_sliceToSpecBytes_append_toList
      pk_mlkem_key.private_random pb_read_ciphertext1 (cipherlength params) h_read_ct_len
  have h_kbar :
      sliceToSpecBytes s9 32 h_s9_len = Spec.MLKEM.J zc :=
    kbar_from_shake_bridge p_shake_state3 _ p_shake_state3_post2 h_alg
      zc h_absorbed s9 h_s9_len (by rw [__post3, h_s8_len])
  rw [s8_post2, from_slice_toSpec_eq pb_implicit_rejection_secret s9 h_s9_len]
  show s9.toSpec 32 h_s9_len = _
  rw [show s9.toSpec 32 h_s9_len = sliceToSpecBytes s9 32 h_s9_len from rfl, h_kbar]
  unfold Spec.MLKEM.Decaps_internal
  simp only
  rw [decapsulationKey_dkPKE_slice, decapsulationKey_ekPKE_slice,
      decapsulationKey_hek_slice, decapsulationKey_z_slice]
  rw [if_pos (by
    intro heq_c
    apply h_c_spec_neq
    have h_c_eq' := h_c_eq
    unfold Spec.MLKEM.Encaps_internal at h_c_eq'
    simp only at h_c_eq'
    rw [h_m_impl_eq] at h_c_eq'
    rw [show Spec.MLKEM.H (encapsulationKey pk_mlkem_key params) =
            pk_mlkem_key.encaps_key_hash.toSpec from h_hash.symm] at h_c_eq'
    rw [h_c_eq', ← heq_c])]

/-- K' branch of `decaps_reencaps`: when `successful_reencrypt = true`,
`cb_copy = 0` and the agreed secret comes from the K-PKE decryption. -/
private theorem decaps_kprime_branch
    (params : ParameterSet)
    (pk_mlkem_key : mlkem.key.Key)
    (h_hash : pk_mlkem_key.encaps_key_hash.toSpec =
              Spec.SHA3.sha3_256 (encapsulationKey pk_mlkem_key params))
    (pb_read_ciphertext1 pb_reencapsulated_ciphertext1 : Slice U8)
    (h_read_ct_len : pb_read_ciphertext1.length = cipherlength params)
    (h_c_len : pb_reencapsulated_ciphertext1.length = cipherlength params)
    (pb_decrypted_random pb_decapsulated_secret : Array U8 32#usize)
    (pe_tmp01 pe_tmp1 pe_tmp02 : Array U16 256#usize)
    (pe_tmp02_post2 :
      toPoly pe_tmp02 =
        Vector.ofFn fun j : Fin 256 =>
          (toPoly pe_tmp1).get j - (toPoly pe_tmp01).get j)
    (h_decrypt_eq_spec :
      ∀ (P : MLKEM.Polynomial),
        P = Vector.ofFn (fun j : Fin 256 =>
          (toPoly pe_tmp1).get j - (toPoly pe_tmp01).get j) →
        Vector.cast (Nat.mul_one 32)
          (compressEncodePoly 1 P (by decide)) =
        Spec.MLKEM.K_PKE.Decrypt params
          (keySEncoded pk_mlkem_key params)
          (pb_read_ciphertext1.toSpec (cipherlength params) h_read_ct_len))
    (s4 s6 : Slice U8)
    (to_slice_mut_back to_slice_mut_back1 : Slice U8 → Array U8 32#usize)
    (s3_post2 : to_slice_mut_back = pb_decrypted_random.from_slice)
    (s4_post1 : s4.length = 32 * ↑(1#u32 : U32))
    (s4_post2 :
      sliceToSpecBytes s4 (32 * ↑(1#u32 : U32)) s4_post1 =
        compressEncodePoly (↑(1#u32 : U32)) (toPoly pe_tmp02) (by decide))
    (s5_post2 : to_slice_mut_back1 = pb_decapsulated_secret.from_slice)
    (h_s6_len : s6.length = 32)
    (h_s6_eq :
      s6.toSpec 32 h_s6_len =
        (Spec.MLKEM.Encaps_internal params (pk_mlkem_key.toEncapKey params)
          (to_slice_mut_back s4).toSpec).1)
    (h_c_eq :
      pb_reencapsulated_ciphertext1.toSpec (cipherlength params) h_c_len =
        (Spec.MLKEM.Encaps_internal params (pk_mlkem_key.toEncapKey params)
          (to_slice_mut_back s4).toSpec).2)
    (successful_reencrypt : Bool)
    (successful_reencrypt_post :
      successful_reencrypt = true ↔
        (↑pb_reencapsulated_ciphertext1 : List U8) = ↑pb_read_ciphertext1)
    (h_sr : successful_reencrypt = true) :
    (to_slice_mut_back1 s6).toSpec =
      Spec.MLKEM.Decaps_internal params (decapsulationKey pk_mlkem_key params)
        (pb_read_ciphertext1.toSpec (cipherlength params) h_read_ct_len) := by
  have h_m_impl_eq : (to_slice_mut_back s4).toSpec =
      Spec.MLKEM.K_PKE.Decrypt params (keySEncoded pk_mlkem_key params)
        (pb_read_ciphertext1.toSpec (cipherlength params) h_read_ct_len) := by
    rw [s3_post2, from_slice_toSpec_eq pb_decrypted_random s4 s4_post1]
    rw [← h_decrypt_eq_spec (toPoly pe_tmp02) pe_tmp02_post2]
    have heq : s4.toSpec 32 s4_post1
        = sliceToSpecBytes s4 (32 * ↑(1#u32 : U32)) s4_post1 := rfl
    rw [heq, s4_post2]
    rfl
  rw [s5_post2, from_slice_toSpec_eq pb_decapsulated_secret s6 h_s6_len, h_s6_eq]
  have h_c_val : pb_reencapsulated_ciphertext1.val = pb_read_ciphertext1.val :=
    successful_reencrypt_post.mp h_sr
  have h_c_spec :
      pb_reencapsulated_ciphertext1.toSpec (cipherlength params) h_c_len =
      pb_read_ciphertext1.toSpec (cipherlength params) h_read_ct_len :=
    Slice.toSpec_congr_val _ _ _ _ _ h_c_val
  unfold Spec.MLKEM.Decaps_internal Spec.MLKEM.Encaps_internal
  simp only
  rw [decapsulationKey_dkPKE_slice, decapsulationKey_ekPKE_slice,
      decapsulationKey_hek_slice]
  rw [show Spec.MLKEM.H (encapsulationKey pk_mlkem_key params) =
          pk_mlkem_key.encaps_key_hash.toSpec from h_hash.symm]
  rw [h_m_impl_eq]
  rw [if_neg (by
    rw [ne_eq, not_not]
    have h_c_eq' := h_c_eq
    unfold Spec.MLKEM.Encaps_internal at h_c_eq'
    simp only at h_c_eq'
    rw [h_m_impl_eq] at h_c_eq'
    rw [show Spec.MLKEM.H (encapsulationKey pk_mlkem_key params) =
            pk_mlkem_key.encaps_key_hash.toSpec from h_hash.symm] at h_c_eq'
    conv_lhs => rw [← h_c_spec, h_c_eq'])]

set_option maxHeartbeats 4000000 in
/-- **Phase 2 — re-encapsulation + SHAKE-256 K̄ (positions 22–44).**

Encodes m' bytes, calls `encapsulate_internal` to compute the candidate
`(K', c')`, then runs the 4-state SHAKE-256 chain over `z ‖ pb_read_ciphertext1`
to derive K̄, and arithmetic-encodes the constant-time selector
`cb_copy ∈ {0, 32}`.

Outputs (in tuple order, matching the function's `Result` payload):
1. `pb_decrypted_random1 : Array U8 32` — holds the m' bytes.
2. `pb_reencapsulated_ciphertext1 : Slice U8` — holds `c'`.
3. `cb_copy : U32` — `0` if `c' = c`, `32` if `c' ≠ c`.
4. `pb_implicit_rejection_secret1 : Array U8 32` — holds `K̄ = J(z ‖ c)`.
5. `pb_decapsulated_secret1 : Array U8 32` — holds `K'`.

The strengthened FC post packages the cmov branch directly as a
`MLKEM.Decaps_internal` equation, factoring all
`K_PKE.Decrypt` / `G` / `K_PKE.Encrypt` / `J` reasoning inside the
helper.  Combined with `decaps_finalize.spec`'s cmov bridge, this
suffices for `decapsulateBody.spec` to close in 2 rewrites.

Closure (now complete) uses:
* threading `decaps_decrypt.spec`'s pe_tmp01/pe_tmp1 spec ties as
  preconditions (the strengthened `decaps_decrypt.spec` post
  provides the spec-side `h_m_impl_eq` identity);
* applying `mlkem.encapsulate_internal.spec` (`Encaps.lean:2719`) for
  the `(K', c')` pair, then `K_PKE.Encrypt_eq_ciphers` for the
  c-equality cb_copy disjunct;
* applying `kbar_from_shake_bridge` (`Bridges/PrfShake.lean`) for the
  `J(z ‖ c)` byte-form of `K̄`. -/
@[local step]
private theorem decaps_reencaps.spec
    (params : ParameterSet)
    (pk_mlkem_key : mlkem.key.Key)
    (local_temps_box : mlkem.DecapsulateTemps)
    (pb_reencapsulated_ciphertext : Slice U8)
    (pb_decrypted_random pb_decapsulated_secret pb_implicit_rejection_secret
      : Array U8 32#usize)
    (pb_read_ciphertext1 : Slice U8)
    (index_mut_back : Slice (Array U16 256#usize) → Array (Array U16 256#usize) 4#usize)
    (pvu2 : Slice (Array U16 256#usize))
    (pa_tmp : Array U32 256#usize)
    (pe_tmp01 pe_tmp1 : Array U16 256#usize)
    (h_wf : wfKey pk_mlkem_key params)
    (_h_priv : pk_mlkem_key.has_private_key = true)
    (h_hash : pk_mlkem_key.encaps_key_hash.toSpec =
              Spec.SHA3.sha3_256 (encapsulationKey pk_mlkem_key params))
    (h_t_form : ∃ (v_t : MLKEM.PolyVector q (k params)),
                  keyEncodedTPrefix pk_mlkem_key params =
                    (MLKEM.PolyVector.ByteEncode 12 v_t).cast
                      (polyVector_byteEncode_size_cast 12)
                  ∧ keyT pk_mlkem_key params = v_t)
    (h_a_form : ∀ (i j : ℕ) (hi : i < (k params : ℕ)) (hj : j < (k params : ℕ)),
                  keyAHat pk_mlkem_key params ⟨i, hi⟩ ⟨j, hj⟩ =
                    MLKEM.SampleNTT
                      (pk_mlkem_key.public_seed.toSpec ‖
                         #v[(i : Byte)] ‖ #v[(j : Byte)]))
    (h_reencap_len : pb_reencapsulated_ciphertext.length = cipherlength params)
    (h_read_ct_len : pb_read_ciphertext1.length = cipherlength params)
    (_h_pvu2_len : pvu2.length = (k params : ℕ))
    (h_wf_pe_tmp01 : wfPoly pe_tmp01)
    (h_wf_pe_tmp1 : wfPoly pe_tmp1)
    /- Spec-side identity: the impl m-bytes (encoded `pe_tmp1 - pe_tmp01`) equal
       `K_PKE.Decrypt` applied to the ciphertext.  This packages the chain
       `compressEncodePoly_eq_byteEncode_compressedF + K_PKE.Decrypt_eq +
       polyVector_byteDecode_byteEncode` so that the K̄/K' closure here can
       proceed without re-deriving it.  Discharged by `decapsulateBody.spec`
       from the strengthened `decaps_decrypt.spec` post + the bridges in
       `Bridges/KPKE_Encrypt.lean`. -/
    (h_decrypt_eq_spec :
       ∀ (P : MLKEM.Polynomial),
         P = Vector.ofFn (fun j : Fin 256 =>
           (toPoly pe_tmp1).get j - (toPoly pe_tmp01).get j) →
         Vector.cast (Nat.mul_one 32)
           (compressEncodePoly 1 P (by decide)) =
         Spec.MLKEM.K_PKE.Decrypt params
           (keySEncoded pk_mlkem_key params)
           (pb_read_ciphertext1.toSpec (cipherlength params) h_read_ct_len)) :
    decaps_reencaps pk_mlkem_key local_temps_box pb_reencapsulated_ciphertext
        pb_decrypted_random pb_decapsulated_secret pb_implicit_rejection_secret
        pb_read_ciphertext1 index_mut_back pvu2 pa_tmp pe_tmp01 pe_tmp1
      ⦃ _pb_decrypted_random1 pb_reencap_ct1 cb_copy
          pb_implicit_rejection_secret1 pb_decapsulated_secret1 =>
          pb_reencap_ct1.length = cipherlength params ∧
          (cb_copy.val = 0 ∨ cb_copy.val = 32) ∧
          (if cb_copy.val = 32 then pb_implicit_rejection_secret1.toSpec
           else pb_decapsulated_secret1.toSpec) =
            MLKEM.Decaps_internal params (decapsulationKey pk_mlkem_key params)
              (pb_read_ciphertext1.toSpec (cipherlength params) h_read_ct_len) ⦄ := by
  unfold decaps_reencaps
  have h_key : wfEncapKey pk_mlkem_key params :=
    { towfKey := h_wf, hash_pinned := h_hash, byte_form_t := h_t_form, matrix_form_a := h_a_form }
  step*
  case rate => exact 136
  case padVal => exact 31#u8
  case h_alg => exact p_shake_state_post2 ▸ rfl
  case h_rate => decide
  step*
  case g => exact (sha3.sha3_impl.GhostState.init 136 31#u8 (by decide))
  case h => exact Or.inl p_shake_state1_post2
  step*
  case g => exact ((sha3.sha3_impl.GhostState.init 136 31#u8 (by decide)).append s7.val p_shake_state1.state.squeeze_mode)
  case h => exact Or.inl p_shake_state2_post2
  step*
  case g => exact (((sha3.sha3_impl.GhostState.init 136 31#u8 (by decide)).append s7.val p_shake_state1.state.squeeze_mode).append pb_read_ciphertext1.val p_shake_state2.state.squeeze_mode)
  case h => exact Or.inl p_shake_state3_post2
  step*
  have h_no : sc_error2 = common.Error.NoError := b2_post.mp (by assumption)
  rw [h_no] at sc_error2_post
  obtain ⟨h_s6_len, h_c_len, h_enc_eq⟩ := sc_error2_post
  have h_ss := congrArg Prod.fst h_enc_eq
  have h_ct := congrArg Prod.snd h_enc_eq
  have h_s6_eq := h_ss.symm
  have h_c_eq := h_ct.symm
  refine ⟨h_c_len, ?_, ?_⟩
  · exact cb_copy_in_set successful_reencrypt i9 i10 i11 cb_copy
      i9_post i10_post i11_post cb_copy_post1
  · rcases h_sr : successful_reencrypt with _ | _
    · -- false ⟹ cb_copy = 32 ⟹ K̄ branch
      have h_cb : cb_copy.val = 32 := by
        simp [h_sr] at i9_post; simp_all; native_decide
      simp [h_cb]
      exact decaps_kbar_branch params pk_mlkem_key h_hash
        pb_read_ciphertext1 pb_reencapsulated_ciphertext1 h_read_ct_len h_c_len
        pb_decrypted_random pb_implicit_rejection_secret
        pe_tmp01 pe_tmp1 pe_tmp02 pe_tmp02_post2 h_decrypt_eq_spec
        s4 s7 s8 s9 to_slice_mut_back to_slice_mut_back2
        s3_post2 s4_post1 s4_post2 h_c_eq s7_post
        p_shake_state p_shake_state1 p_shake_state2 p_shake_state3
        p_shake_state_post2 p_shake_state1_post1 p_shake_state1_post2
        p_shake_state2_post1 p_shake_state2_post2
        p_shake_state3_post1 p_shake_state3_post2
        s8_post1 s8_post2 __post2 __post3
        successful_reencrypt successful_reencrypt_post h_sr
    · -- true ⟹ cb_copy = 0 ⟹ K' branch
      have h_cb : cb_copy.val = 0 := by
        simp [h_sr] at i9_post; simp_all; native_decide
      simp [h_cb]
      exact decaps_kprime_branch params pk_mlkem_key h_hash
        pb_read_ciphertext1 pb_reencapsulated_ciphertext1 h_read_ct_len h_c_len
        pb_decrypted_random pb_decapsulated_secret
        pe_tmp01 pe_tmp1 pe_tmp02 pe_tmp02_post2 h_decrypt_eq_spec
        s4 s6 to_slice_mut_back to_slice_mut_back1
        s3_post2 s4_post1 s4_post2 s5_post2 h_s6_len h_s6_eq h_c_eq
        successful_reencrypt successful_reencrypt_post h_sr

/-- **Phase 3 — finalize (positions 45–56).**

`const_time_array_copy` cmov writes `K̄` or `K'` into the agreed-secret
buffer per `cb_copy`; copies into `pb_agreed_secret`; then 4× wipe.

The post fixes `err = NoError`, the 32-byte length witness, and ties
`agreed'.toSpec` to the cmov:
`agreed'.toSpec = if cb_copy.val = 32 then pb_implicit_rejection_secret1.toSpec
                  else pb_decapsulated_secret1.toSpec`. -/
@[local step]
private theorem decaps_finalize.spec
    (pb_agreed_secret pb_read_ciphertext1 : Slice U8)
    (pb_decrypted_random1 : Array U8 32#usize)
    (pb_reencapsulated_ciphertext1 : Slice U8)
    (cb_copy : U32)
    (pb_implicit_rejection_secret1 pb_decapsulated_secret1 : Array U8 32#usize)
    (h_agreed_len : pb_agreed_secret.length = 32)
    (h_cb_copy : cb_copy.val = 0 ∨ cb_copy.val = 32) :
    decaps_finalize pb_agreed_secret pb_read_ciphertext1
        pb_decrypted_random1 pb_reencapsulated_ciphertext1
        cb_copy pb_implicit_rejection_secret1 pb_decapsulated_secret1
      ⦃ err agreed' =>
          err = Error.NoError ∧
          ∃ (h_a : agreed'.length = 32),
            agreed'.toSpec 32 h_a =
              (if cb_copy.val = 32 then pb_implicit_rejection_secret1.toSpec
               else pb_decapsulated_secret1.toSpec) ⦄ := by
  unfold decaps_finalize
  step*
  refine ⟨?_, ?_⟩
  · rw [pb_agreed_secret1_post1, h_agreed_len]
  · have h_val : (↑pb_agreed_secret1 : List U8) = (↑pb_decapsulated_secret2 : List U8) := by
      rw [pb_agreed_secret1_post2, s10_post]; rfl
    rcases h_cb_copy with h0 | h32
    · have h_eq := pb_decapsulated_secret2_post2 h0
      have : ¬ (cb_copy.val = 32) := by rw [h0]; decide
      simp only [this, if_false]
      unfold Aeneas.Std.Slice.toSpec
        Aeneas.Std.Array.toSpec arrayToSpecBytes
      rw [h_eq] at h_val
      grind [sliceToSpecBytes]
    · have h_eq := pb_decapsulated_secret2_post1 h32
      simp only [h32, if_true]
      unfold Aeneas.Std.Slice.toSpec
        Aeneas.Std.Array.toSpec arrayToSpecBytes
      grind [sliceToSpecBytes]

/-! ### Helper: `h_decrypt_eq_spec` discharge.

Hoisted out of `decapsulateBody.spec` (which already runs near the heartbeat
ceiling).  Consumes the per-row pvu1 witness (`h_perRow` — derived from the
`Error.NoError` branch of `vector_decode_and_decompress.spec`'s
`sc_error_post3`) together with `pvu2_post5` / `pvu2_post7` (from
`decaps_decrypt.spec`), threads them through `K_PKE.Decrypt_eq`
(`Bridges/KPKE_Encrypt.lean:301`), and matches the resulting expression to
the `Vector.cast _ (compressEncodePoly 1 P _)` LHS.

The three `K_PKE.Decrypt_eq` witnesses are:
- `ŝ := keyS_std pk_mlkem_key params`, supplied by
  `keyS_std_eq_byteDecode_keySEncoded` (Decaps.lean L370);
- `u' := toPolyVecOfLen pvu1 (k params) _`, supplied by
  `toPolyVecOfLen_pvu1_eq` (Decaps.lean L484);
- `v' := toPoly pe_tmp1`, derived inline from `pvu2_post7` via
  `slice_toSpec_eq_sliceWindow` (Decaps.lean L352) and `h_cb_u`.

After the `K_PKE.Decrypt_eq` rewrite, the LHS is folded via `pvu2_post5`
(rewriting `NTTInv(innerProductNTT keyS_std (NTT u'))` to `toPoly pe_tmp01`),
`h_P` (substituting `P`), pointwise `Vector.ofFn` ↔ `Polynomial.sub`, and the
`d = 1 < 12` branch of `compressEncodePoly`. -/

/-- Bridge: `decodeDecompressPoly d` for `d < 12` reduces to the explicit
`Polynomial.Decompress ∘ ByteDecode` form. Hoisted so the main helper does
not pay for the `unfold + dif_pos` rewrite each time. -/
private theorem decodeDecompressPoly_of_lt_12
    (d : ℕ) (h_d : 1 ≤ d ∧ d ≤ 12) (h_lt : d < 12) (B : 𝔹 (32 * d)) :
    decodeDecompressPoly d B h_d =
      MLKEM.Polynomial.Decompress d (MLKEM.ByteDecode B ⟨h_d.1, h_d.2⟩) ⟨h_d.1, h_lt⟩ := by
  unfold decodeDecompressPoly
  rw [dif_pos h_lt]

/-- Bridge: `compressEncodePoly d` for `d < 12` reduces to the explicit
`ByteEncode ∘ Polynomial.Compress` form. -/
private theorem compressEncodePoly_of_lt_12
    (d : ℕ) (h_d : 1 ≤ d ∧ d ≤ 12) (h_lt : d < 12) (p : MLKEM.Polynomial) :
    compressEncodePoly d p h_d =
      MLKEM.ByteEncode d (MLKEM.Polynomial.Compress d p ⟨h_d.1, h_lt⟩) ⟨h_d.1, h_d.2⟩ := by
  unfold compressEncodePoly
  rw [dif_pos h_lt]

set_option maxHeartbeats 8000000 in
/-- Generic bridge: combining `decodeDecompressPoly_of_lt_12` and
`slice_toSpec_eq_sliceWindow` for any `d < 12`. Generic over `N`, `d`,
`off` — keeps the kernel proof term small by avoiding params-dependent
embedded proofs. -/
private theorem decodeDecompressPoly_to_slice_eq
    {N : ℕ} (s : Slice U8) (h_s_len : s.length = N) (off d : ℕ)
    (h_d_ge_1 : 1 ≤ d) (h_d_le_12 : d ≤ 12) (h_d_lt : d < 12)
    (h_w : off + 32 * d ≤ s.length)
    (p : Std.Array U16 256#usize)
    (h_eq : toPoly p = decodeDecompressPoly d
              (sliceWindowToSpecBytes s off (32 * d) h_w)
              ⟨h_d_ge_1, h_d_le_12⟩)
    (h_w_spec : off + 32 * d ≤ N) :
    toPoly p =
      MLKEM.Polynomial.Decompress d
        (MLKEM.ByteDecode (Spec.slice (s.toSpec N h_s_len) off (32 * d) h_w_spec)
          ⟨h_d_ge_1, h_d_le_12⟩)
        ⟨h_d_ge_1, h_d_lt⟩ := by
  rw [h_eq, decodeDecompressPoly_of_lt_12 d _ h_d_lt]
  rw [← slice_toSpec_eq_sliceWindow s N h_s_len off (32 * d) h_w_spec]

set_option maxHeartbeats 8000000 in
/-- Helper: rephrase the impl-side `pvu2_post7` as the spec-side
`Polynomial.Decompress ∘ ByteDecode ∘ Spec.slice` form. -/
private theorem decoded_v_eq
    (params : ParameterSet) (cb_u : UScalar UScalarTy.Usize)
    (pb_read_ciphertext1 : Slice U8) (pe_tmp1 : Std.Array U16 256#usize)
    (h_dv_ge_1 : 1 ≤ dᵥ params) (h_dv_le_12 : dᵥ params ≤ 12)
    (h_dv_lt : dᵥ params < 12)
    (h_rc_len : pb_read_ciphertext1.length = cipherlength params)
    (h_cb_u : (↑cb_u : ℕ) = 32 * dᵤ params * ↑(k params))
    (h_v_bnd : (↑cb_u : ℕ) + 32 * dᵥ params ≤ pb_read_ciphertext1.length)
    (h_slice_bnd : 32 * dᵤ params * ↑(k params) + 32 * dᵥ params ≤ cipherlength params)
    (h_pvu2_post7 : toPoly pe_tmp1 = decodeDecompressPoly (dᵥ params)
                    (sliceWindowToSpecBytes pb_read_ciphertext1 (↑cb_u) (32 * dᵥ params) h_v_bnd)
                    ⟨h_dv_ge_1, h_dv_le_12⟩) :
    toPoly pe_tmp1 =
      MLKEM.Polynomial.Decompress (dᵥ params)
        (MLKEM.ByteDecode
          (Spec.slice
            (pb_read_ciphertext1.toSpec (cipherlength params) h_rc_len)
            (32 * dᵤ params * ↑(k params)) (32 * dᵥ params) h_slice_bnd)
          ⟨h_dv_ge_1, h_dv_le_12⟩)
        ⟨h_dv_ge_1, h_dv_lt⟩ := by
  have h_w_new : 32 * dᵤ params * ↑(k params) + 32 * dᵥ params ≤ pb_read_ciphertext1.length :=
    h_cb_u ▸ h_v_bnd
  have h_pvu2_post7' : toPoly pe_tmp1 = decodeDecompressPoly (dᵥ params)
                        (sliceWindowToSpecBytes pb_read_ciphertext1
                          (32 * dᵤ params * ↑(k params)) (32 * dᵥ params) h_w_new)
                        ⟨h_dv_ge_1, h_dv_le_12⟩ := by
    convert h_pvu2_post7 using 4
    exact h_cb_u.symm
  rw [h_pvu2_post7']
  unfold decodeDecompressPoly
  rw [dif_pos h_dv_lt]
  rw [← slice_toSpec_eq_sliceWindow pb_read_ciphertext1 (cipherlength params) h_rc_len
        (32 * dᵤ params * ↑(k params)) (32 * dᵥ params) h_slice_bnd]

/-- Generic: pointwise `Vector.ofFn` of differences equals vector subtraction
on `MLKEM.Polynomial`. Hoisted out of `h_decrypt_eq_spec_helper` so the
`Polynomial.sub` unfolding happens in a minimal context. -/
private theorem polynomial_sub_ofFn (a b : MLKEM.Polynomial) :
    (Vector.ofFn fun j => a.get j - b.get j) = a - b := by
  apply Vector.ext
  intro i hi
  simp only [Vector.getElem_ofFn]
  show a.get ⟨i, hi⟩ - b.get ⟨i, hi⟩ = (a - b).get ⟨i, hi⟩
  simp [HSub.hSub, Sub.sub, Polynomial.sub, Vector.get]

set_option maxHeartbeats 8000000 in
private theorem h_decrypt_eq_spec_helper
    (params : ParameterSet)
    (pk_mlkem_key : mlkem.key.Key)
    (cb_u : UScalar UScalarTy.Usize)
    (i7 : U32)
    (s pb_read_ciphertext1 : Slice U8)
    (pvu1 : Slice (Std.Array U16 256#usize))
    (pe_tmp01 pe_tmp1 : Std.Array U16 256#usize)
    (P : MLKEM.Polynomial)
    (h_dv_ge_1 : 1 ≤ dᵥ params) (h_dv_le_12 : dᵥ params ≤ 12)
    (h_dv_lt : dᵥ params < 12)
    (h_du_bd : 1 ≤ i7.val ∧ i7.val ≤ 12)
    (h_slice_bnd : 32 * dᵤ params * ↑(k params) + 32 * dᵥ params ≤ cipherlength params)
    (h_rc_len : pb_read_ciphertext1.length = cipherlength params)
    (h_pvu1_len : pvu1.length = ((k params) : ℕ))
    (h_i7_val : (i7.val : ℕ) = dᵤ params)
    (h_s_val : s.val = List.slice 0 cb_u.val pb_read_ciphertext1.val)
    (h_s_len : s.length = (cb_u.val : ℕ))
    (h_cb_u : (cb_u.val : ℕ) = 32 * dᵤ params * ↑(k params))
    (h_perRow : ∀ (j : ℕ) (h_j : j < pvu1.length)
        (h_src_window : j * (32 * i7.val) + 32 * i7.val ≤ s.length),
        toPoly pvu1.val[j] = decodeDecompressPoly i7.val
          (sliceWindowToSpecBytes s (j * (32 * i7.val)) (32 * i7.val) h_src_window)
          h_du_bd)
    (h_pvu2_post5 : toPoly pe_tmp01 = NTTInv ((keyS_std pk_mlkem_key params).innerProductNTT
                      (Vector.map NTT (toPolyVecOfLen pvu1 (k params) h_pvu1_len))))
    (h_v_bnd : ↑cb_u + 32 * dᵥ params ≤ pb_read_ciphertext1.length)
    (h_pvu2_post7 : toPoly pe_tmp1 = decodeDecompressPoly (dᵥ params)
                    (sliceWindowToSpecBytes pb_read_ciphertext1 (↑cb_u) (32 * dᵥ params) h_v_bnd)
                    ⟨h_dv_ge_1, h_dv_le_12⟩)
    (h_P : P = Vector.ofFn fun j => Vector.get (toPoly pe_tmp1) j - Vector.get (toPoly pe_tmp01) j) :
    Vector.cast (Nat.mul_one 32) (compressEncodePoly 1 P (by decide)) =
      K_PKE.Decrypt params (keySEncoded pk_mlkem_key params)
        (pb_read_ciphertext1.toSpec (cipherlength params) h_rc_len) := by
  have h_u :=
    toPolyVecOfLen_pvu1_eq params pb_read_ciphertext1 s pvu1
      cb_u.val i7.val h_rc_len h_pvu1_len h_s_val h_s_len h_cb_u h_i7_val h_perRow
  have h_v := decoded_v_eq params cb_u pb_read_ciphertext1 pe_tmp1
                h_dv_ge_1 h_dv_le_12 h_dv_lt h_rc_len h_cb_u h_v_bnd h_slice_bnd h_pvu2_post7
  have h_dec := Bridges.K_PKE.Decrypt_eq params (keySEncoded pk_mlkem_key params)
        (pb_read_ciphertext1.toSpec (cipherlength params) h_rc_len)
        (keyS_std pk_mlkem_key params)
        (toPolyVecOfLen pvu1 (k params) h_pvu1_len)
        (toPoly pe_tmp1)
        (keyS_std_eq_byteDecode_keySEncoded pk_mlkem_key params)
        h_u h_v
  rw [h_dec]
  have h_innerEq : (toPoly pe_tmp1 -
            NTTInv (PolyVector.innerProductNTT (keyS_std pk_mlkem_key params)
                      (PolyVector.NTT (toPolyVecOfLen pvu1 (k params) h_pvu1_len))))
          = toPoly pe_tmp1 - toPoly pe_tmp01 := by
    rw [h_pvu2_post5]; rfl
  rw [h_innerEq, h_P, polynomial_sub_ofFn, compressEncodePoly_of_lt_12 1 _ (by decide)]

/-- **Error-free cryptographic body of `mlkem.decapsulate`** — extracted
by the `#decompose` cascade above.  This `@[step]` carries the
substantive FC content; the surrounding dispatch layers are mechanical
case-splits proved in `mlkem.decapsulate.spec` via the four `*.fold`
equations.

`local_temps_box` is the freshly-allocated `DecapsulateTemps`
workspace; by the `try_new_box_default.DecapsulateTemps.spec` axiom
(`Axioms/BoxDefault.lean`) it carries no observable invariant — every
field is overwritten before any read.

`cb_ciphertext` and `cb_u` are the size scalars computed by the
arithmetic prefix of `mlkem.decapsulate` and threaded through the
dispatch chain; on the success path `cb_ciphertext = pb_ciphertext.length`
(= `cipherlength params`) and `cb_u.val = 32 * dᵤ params * k params`.

The body has no `Error` outcomes on `Result.ok`: the only explicit
return is `ok (NoError, _)` (Funs.lean:5196); the three intermediate
`sc_error`s from `vector_decode_and_decompress`,
`poly_element_decode_and_decompress`, and `encapsulate_internal` are
each followed by a `massert sc_error == NoError`, which promotes a
non-`NoError` sub-error to `Result.err` (i.e., the Hoare triple's
`Result.err` arm).  So the postcondition fixes `err = NoError`.

Informal proof. Sequence of `step` applications mirroring K-PKE
Decrypt (FIPS 203 Algorithm 14) plus the implicit-rejection check
(Algorithm 18 step 5–9):
1. `vector_decode_and_decompress.spec` on the first `k · 32 · dᵤ`
   ciphertext bytes → vector `u' : Vector Polynomial k`.
2. `poly_element_decode_and_decompress.spec` on the last `32 · dᵥ`
   bytes → polynomial `v' : Polynomial`.
3. `vector_ntt.spec` to compute `NTT(u')`, then
   `vector_mont_dot_product.spec` against `s := dk.s` (from `wfKey`
   we know `s.length = k`) → inner product `s ∘ NTT(u')` in
   NTT-domain.
4. `vector_intt_and_mul_r.spec` (or composition of `inv_ntt.spec` +
   `R`-multiply) to bring back to time-domain `s · u'`.
5. `poly_element_sub.spec` to compute `w := v' - s · u'`.
6. `poly_element_compress_and_encode.spec` (with `d = 1`) on `w` to
   reconstruct `m'`.
7. `encapsulate_internal.spec` (recursive call) on `(ek, m')` to
   produce a candidate ciphertext `c'`.
8. Constant-time compare of `c` vs `c'`; on match, output `K'`; on
   mismatch, output the implicit-rejection `K_bar = J(z ‖ c)` via
   `sha3_256.spec`. Both branches write 32 bytes into
   `pb_agreed_secret`; the existential `h_a` is established.
The spec-side `MLKEM.Decaps_internal` (Spec/MLKEM/Spec.lean) executes
the identical chain; the bridges connecting impl operations to spec
operations (e.g., `vector_ntt.spec`'s FC to `MLKEM.NTT_Vec`) compose
straight through. `agrind` discharges the residual bookkeeping. -/

@[step]
theorem decapsulateBody.spec
    (params : ParameterSet)
    (pk_mlkem_key : mlkem.key.Key)
    (pb_ciphertext pb_agreed_secret : Slice U8)
    (cb_ciphertext : Usize)
    (cb_u : UScalar UScalarTy.Usize)
    (local_temps_box : mlkem.DecapsulateTemps)
    (h_wf : wfKey pk_mlkem_key params)
    (h_priv : pk_mlkem_key.has_private_key = true)
    (h_secret_len : pb_agreed_secret.length = 32)
    (h_ct_len : pb_ciphertext.length = cipherlength params)
    (h_cb_ct : cb_ciphertext.val = pb_ciphertext.length)
    (h_cb_u : cb_u.val = 32 * (dᵤ params : ℕ) * (k params : ℕ))
    /- `wfPolyVec` on the polynomial work-buffer (consumed by
       `vector_decode_and_decompress` as `pvu`'s `h_wf_in`).  Discharged
       at the caller from the strengthened
       `try_new_box_default.DecapsulateTemps.spec` Ok-branch invariant
       (`Axioms/BoxDefault.lean:152`). -/
    (h_wfpv0 : wfPolyVec local_temps_box.comp_temps.max_size_vector0.to_slice)
    /- `wfPoly` on the `poly_element1` workspace (consumed by
       `poly_element_decode_and_decompress` as its destination buffer
       precondition).  Discharged at the caller from the strengthened
       `try_new_box_default.DecapsulateTemps.spec` Ok-branch invariant
       (`Axioms/BoxDefault.lean:152`). -/
    (h_wfpe1 : wfPoly local_temps_box.comp_temps.poly_element1)
    /- Hash witness: `encaps_key_hash` slot stores `SHA3-256 ek` (= `H(ek)`).
       Carried by every valid `Key` by construction (set by
       `key_set_value`/`key_expand_from_private_seed`); plumbed here so
       `MLKEM.Decaps_internal`'s `H(ek)` byte-form aligns with the impl's
       slot read.  Mirrors `mlkem.encapsulate_internal.spec`. -/
    (h_hash : pk_mlkem_key.encaps_key_hash.toSpec =
              Spec.SHA3.sha3_256 (encapsulationKey pk_mlkem_key params))
    /- Byte-form witness for the encoded-`t` prefix (consumed inside
       `decaps_reencaps` by the recursive `encapsulate_internal.spec`
       for the `c'`-equality bridge B3, Encaps.lean L3079). -/
    (h_t_form : ∃ (v_t : MLKEM.PolyVector q (k params)),
                  keyEncodedTPrefix pk_mlkem_key params =
                    (MLKEM.PolyVector.ByteEncode 12 v_t).cast
                      (polyVector_byteEncode_size_cast 12)
                  ∧ keyT pk_mlkem_key params = v_t)
    /- Matrix-form witness for `keyAHat` (consumed inside `decaps_reencaps`
       by the recursive `encapsulate_internal.spec` for B4). -/
    (h_a_form : ∀ (i j : ℕ) (hi : i < (k params : ℕ)) (hj : j < (k params : ℕ)),
                  keyAHat pk_mlkem_key params ⟨i, hi⟩ ⟨j, hj⟩ =
                    MLKEM.SampleNTT
                      (pk_mlkem_key.public_seed.toSpec ‖
                         #v[(i : Byte)] ‖ #v[(j : Byte)])) :
    decapsulateBody pk_mlkem_key pb_ciphertext pb_agreed_secret
        cb_ciphertext cb_u local_temps_box
      ⦃ err agreed' =>
          err = Error.NoError ∧
          let dk := decapsulationKey pk_mlkem_key params
          let c := Slice.toSpec pb_ciphertext (cipherlength params) h_ct_len
          ∃ (h_a : agreed'.length = 32),
            Slice.toSpec agreed' 32 h_a =
              MLKEM.Decaps_internal params dk c ⦄ := by
  rw [decapsulateBody.fold]
  -- Pre-derive useful projections from `wfKey`. The 5 numeric side-goals
  -- raised by `step*` are discharged by feeding these hypotheses into context.
  have h_params_ok := wfKey.params_ok h_wf
  have h_n_rows : pk_mlkem_key.params.n_rows.val = (k params : ℕ) :=
    wfInternalParams.n_rows_val h_params_ok
  have h_n_bits_of_u : pk_mlkem_key.params.n_bits_of_u.val = dᵤ params :=
    wfInternalParams.n_bits_of_u_val h_params_ok
  have h_n_bits_of_v : pk_mlkem_key.params.n_bits_of_v.val = dᵥ params :=
    wfInternalParams.n_bits_of_v_val h_params_ok
  have h_k_ge_2 : 2 ≤ (k params : ℕ) := k_ge_2 params
  have h_k_le_4 : (k params : ℕ) ≤ 4 := k_le_4 params
  have h_dᵤ_bounds : 1 ≤ dᵤ params ∧ dᵤ params ≤ 12 := by
    rcases params <;> decide
  have h_dᵥ_bounds : 1 ≤ dᵥ params ∧ dᵥ params ≤ 12 := by
    rcases params <;> decide
  step*
  /- The new step* (after importing Stdlib.lean which makes
     `Error.eq.spec` fire) now consumes Error.eq AND advances past the
     first `massert (sc_error == NoError)` into the standard-form-side
     chain (`vector_ntt`, `Key.s`, the head of `vector_mont_dot_product`).
     Remaining side-goals (in case-label order):
       • `case kn` and `case h_kn`  ← `vector_mont_dot_product`'s `kn : K` arg
       • `case h1` (×2)             ← two `index_mut` numeric bounds (≤ 1568)
       • `case h_wf_in`             ← `wfPolyVec pvu` for `vector_decode_and_decompress`
       • `case h` : b = true        ← the massert; reduces to `sc_error = NoError`
                                       (true on `NoError`; `InvalidBlob` and the
                                       other 21 enum tags absurd by `sc_error_post3`)
       • `case h_wf_in`             ← `wfPolyVec pvu` for `vector_decode_and_decompress`
       • `case h` : b = true        ← the massert; reduces to `sc_error = NoError`
                                        (true on `NoError`; `InvalidBlob` and the
                                        other 21 enum tags absurd by `sc_error_post3`)
       • main FC                    ← the residual standard-form decapsulation body. -/
  · -- case h1 — first `index_mut` (read_ciphertext)
    have h_ct_bound : cipherlength params ≤ 1568 := by rcases params <;> decide
    agrind
  · -- case h1 — second `index_mut` (reencapsulated_ciphertext)
    have h_ct_bound : cipherlength params ≤ 1568 := by rcases params <;> decide
    agrind
  · -- case h_wf_in ⊢ wfPolyVec pvu — for vector_decode_and_decompress.
    -- pvu is the length-k prefix-slice of max_size_vector0; transfer
    -- wfPolyVec via wfPolyVec_of_prefix_slice.
    have hi6 : (UScalar.cast UScalarTy.Usize pk_mlkem_key.params.n_rows).val =
               pk_mlkem_key.params.n_rows.val := by simp
    have h_m_le : (UScalar.cast UScalarTy.Usize pk_mlkem_key.params.n_rows).val ≤ 4 := by
      rw [hi6, h_n_rows]; exact h_k_le_4
    refine wfPolyVec_of_prefix_slice
      local_temps_box.comp_temps.max_size_vector0 pvu
      (UScalar.cast UScalarTy.Usize pk_mlkem_key.params.n_rows).val
      ?_ ?_ h_m_le h_wfpv0
    · rw [pvu_post1, i6_post]
    · rw [pvu_post2]; agrind
  · -- case h : b = true — the massert after `Error.eq sc_error NoError`.
    -- Reduce via `b_post : b = true ↔ sc_error = NoError`, then case-split.
    rw [b_post]
    rcases sc_error with _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _
      | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _
    case NoError => rfl
    case InvalidBlob =>
      exfalso
      simp only at sc_error_post3
      have hi : i7.val = pk_mlkem_key.params.n_bits_of_u.val := by simp [i7_post]
      rw [hi, h_n_bits_of_u] at sc_error_post3
      rcases params <;> simp [dᵤ] at sc_error_post3
    all_goals exact sc_error_post3.elim
  -- Main FC residual.  The rest of the body (after passing the first
  -- massert) goes through vector_ntt, Key.s, vector_mont_dot_product,
  -- poly_element_intt_and_mul_r, poly_element_decode_and_decompress (v'),
  -- poly_element_sub_from_in_place, poly_element_compress_and_encode (m'),
  -- recursive mlkem.encapsulate_internal, 4-state SHAKE-256 (K̄),
  -- const_time_slices_equal + const_time_array_copy (constant-time select),
  -- copy_from_slice into pb_agreed_secret, then 4× wipe_slice.
  --
  -- Bridges used: decaps_m_chain_std (MatrixVectorMul.lean:295,
  -- R-cancellation), K_PKE.Encrypt_eq_ciphers (KPKE_Encrypt.lean),
  -- kbar_from_shake_bridge (PrfShake.lean), encapsulate_internal.spec
  -- (Encaps.lean L3070-3273, c-equality residual under scaffold).
  --
  -- Bridge: rewrite the helper's `pb_read_ciphertext1.toSpec` to
  -- `pb_ciphertext.toSpec` using the byte-list equality from
  -- `copy_from_slice`.  Done as a stand-alone `have` so the expensive
  -- `Vector.ext` work runs in a small context.
  --
  -- Closure outline (now executed below): apply `K_PKE.Decrypt_eq`
  -- (Bridges/KPKE_Encrypt.lean:301) with witnesses
  --   ŝ  := keyS_std pk_mlkem_key params
  --   u' := toPolyVecOfLen pvu1 (k params) _
  --   v' := decodeDecompressPoly (dᵥ params)
  --           (sliceWindowToSpecBytes pb_read_ciphertext1 cb_u (32 * dᵥ params) _) _
  -- then rewrite the LHS via
  --   * `compressEncodePoly_eq_byteEncode_compressedF` (EncodingStream.lean:1258)
  --   * `h_P`, `pvu2_post5`, `pvu2_post7` to align with `K_PKE.Decrypt`'s
  --     `w := v' - NTTInv(innerProductNTT ŝ (NTT u'))` shape.
  --
  -- The three pre-conditions of `K_PKE.Decrypt_eq` need:
  --
  --  (h_s) `keyS_std = PolyVector.ByteDecode 12 ((keySEncoded pk).cast _)`
  --     — already proven as `keyS_std_eq_byteDecode_keySEncoded`
  --       (Decaps.lean L286+, uses `polyVector_byteDecode_byteEncode` round-trip).
  --
  --  (h_v) `decodeDecompressPoly dᵥ (sliceWindowToSpecBytes pb_read_ciphertext1 cb_u (32*dᵥ) _) _`
  --        = `Polynomial.Decompress dᵥ (MLKEM.ByteDecode (slice c (32*dᵤ*k) (32*dᵥ) _)) _`
  --     — unfold `decodeDecompressPoly` in the d<12 branch (always true for
  --       MLKEM dᵥ ∈ {4,5}); then bridge via `slice_toSpec_eq_sliceWindow`
  --       (Decaps.lean L?) since `cb_u = 32*dᵤ*k` (`h_cb_u`).
  --
  --  (h_u) `toPolyVecOfLen pvu1 (k params) _`
  --        = `PolyVector.Decompress dᵤ (PolyVector.ByteDecode dᵤ (slice c 0 (32*dᵤ*k) _)) _`
  --     — Vector.ext over the k rows; per j∈[0,k):
  --         · LHS[j] = toPoly pvu1[j], by def of `toPolyVecOfLen`.
  --         · By `sc_error_post3` (`NoError` branch + `b_post` from massert):
  --             toPoly pvu1[j]
  --               = decodeDecompressPoly dᵤ
  --                   (sliceWindowToSpecBytes s (j*32*dᵤ) (32*dᵤ) _) _
  --           where `s.val = List.slice 0 cb_u pb_read_ciphertext1.val`.
  --         · By def of `PolyVector.Decompress` and `PolyVector.ByteDecode`:
  --             RHS[j] = Polynomial.Decompress dᵤ
  --                       (MLKEM.ByteDecode (slice c' (32*dᵤ*j) (32*dᵤ) _)) _
  --           where c' = slice c 0 (32*dᵤ*k) (note PolyVector.ByteDecode's
  --           internal slice uses `32*d*i` indexing).
  --         · Bridge needed: `sliceWindowToSpecBytes s (j*32*dᵤ) (32*dᵤ) _`
  --                       = `slice c' (32*dᵤ*j) (32*dᵤ) _`
  --           — combines `sliceWindow_of_prefix_slice` (s is prefix-slice of
  --             pb_read_ciphertext1) with `slice_toSpec_eq_sliceWindow` and
  --             a `slice (slice x 0 a) j n = slice x j n` (j+n ≤ a) identity.
  --
  -- The `Vector.ext` argument for h_u is heavyweight, so this
  -- work was hoisted to a top-level lemma `toPolyVecOfLen_pvu1_eq` to avoid
  -- 4M-heartbeat timeouts inside the giant `decapsulateBody.spec` body.
  -- The slice-of-slice arithmetic in h_u's per-row bridge similarly lives
  -- in a standalone helper, with a signature roughly:
  --   `slice_of_prefix_slice (c : 𝔹 N) (a o n : ℕ) (h : o + n ≤ a) ... :
  --     slice (slice c 0 a _) o n _ = slice c o n _`
  --
  -- After applying K_PKE.Decrypt_eq with those three witnesses, the residual
  -- goal reduces to `Vector.cast _ (compressEncodePoly 1 P _) = (ByteEncode 1 (Compress 1 w)).cast _`
  -- where w = (Decompress dᵥ ...) - NTTInv(innerProductNTT keyS_std (NTT (toPolyVecOfLen pvu1 _ _)))).
  -- This should collapse via:
  --   `compressEncodePoly_eq_byteEncode_compressedF`, then `h_P`, then
  --   `pvu2_post5` and `pvu2_post7` (rewriting `toPoly pe_tmp01` and
  --   `toPoly pe_tmp1` via the strengthened `decaps_decrypt.spec` post),
  --   plus `compressedF 1 P _ = Polynomial.Compress 1 P _` (likely defeq in
  --   the d<12 branch; if not, a one-line `unfold compressedF` + `simp only`).
  -- Final cast bookkeeping should be `Vector.cast_cast` or proof-irrelevance.
  · intro P h_P
    have h_rc_len : pb_read_ciphertext1.length = cipherlength params := by
      rw [pb_read_ciphertext1_post1, pb_read_ciphertext_post2]; agrind
    have h_pvu1_len : pvu1.length = ((k params) : ℕ) := by
      rw [sc_error_post1, pvu_post2, i6_post]
      simp only [Nat.sub_zero]
      have h_cast : (UScalar.cast UScalarTy.Usize pk_mlkem_key.params.n_rows).val
              = pk_mlkem_key.params.n_rows.val := by scalar_tac
      rw [h_cast, h_n_rows]
    have h_i7_val : (i7.val : ℕ) = dᵤ params := by
      rw [i7_post]
      have h_cast : (UScalar.cast UScalarTy.U32 pk_mlkem_key.params.n_bits_of_u).val
              = pk_mlkem_key.params.n_bits_of_u.val := by scalar_tac
      rw [h_cast]; exact h_n_bits_of_u
    have h_s_len : s.length = (cb_u.val : ℕ) := by rw [s_post2]; agrind
    have h_no_error : sc_error = Error.NoError := b_post.mp ‹b = true›
    rw [h_no_error] at sc_error_post3
    simp only at sc_error_post3
    have h_dv_ge_1 : 1 ≤ dᵥ params := by rcases params <;> decide
    have h_dv_le_12 : dᵥ params ≤ 12 := by rcases params <;> decide
    have h_dv_lt : dᵥ params < 12 := by rcases params <;> decide
    have h_du_bd : 1 ≤ i7.val ∧ i7.val ≤ 12 := by
      rw [h_i7_val]; rcases params <;> decide
    have h_slice_bnd : 32 * dᵤ params * ↑(k params) + 32 * dᵥ params ≤ cipherlength params := by
      rcases params <;> simp [cipherlength, dᵤ, dᵥ]
    have h_perRow : ∀ (j : ℕ) (h_j : j < pvu1.length)
        (h_src_window : j * (32 * i7.val) + 32 * i7.val ≤ s.length),
        toPoly pvu1.val[j] = decodeDecompressPoly i7.val
          (sliceWindowToSpecBytes s (j * (32 * i7.val)) (32 * i7.val) h_src_window)
          h_du_bd := by
      intro j h_j h_src_window
      obtain ⟨_, h_eq, _⟩ := sc_error_post3 j h_j
      convert h_eq using 2
    have h_pvu2_post7' : toPoly pe_tmp1 = decodeDecompressPoly (dᵥ params)
                          (sliceWindowToSpecBytes pb_read_ciphertext1 (↑cb_u) (32 * dᵥ params) pvu2_post6)
                          ⟨h_dv_ge_1, h_dv_le_12⟩ := pvu2_post7
    exact h_decrypt_eq_spec_helper params pk_mlkem_key cb_u i7 s pb_read_ciphertext1
      pvu1 pe_tmp01 pe_tmp1 P h_dv_ge_1 h_dv_le_12 h_dv_lt h_du_bd
      h_slice_bnd h_rc_len h_pvu1_len h_i7_val s_post1 h_s_len h_cb_u
      h_perRow pvu2_post5 pvu2_post6 h_pvu2_post7' h_P
  have h_rc1_len : pb_read_ciphertext1.length = cipherlength params := by
    rw [pb_read_ciphertext1_post1, pb_read_ciphertext_post2]; agrind
  have h_ct_eq :
      pb_read_ciphertext1.toSpec (cipherlength params) h_rc1_len =
        pb_ciphertext.toSpec (cipherlength params) h_ct_len := by
    unfold Aeneas.Std.Slice.toSpec
    apply Vector.ext; intro i hi
    grind [sliceToSpecBytes]
  refine ⟨err_post1, err_post2, ?_⟩
  rw [err_post3, pb_decrypted_random1_post3, h_ct_eq]

/-- **Bridge** — given the byte-form hash witness
`h_hash : self.encaps_key_hash.toSpec = SHA3-256 (encapsulationKey self params)`,
the FIPS-spec `Decaps.KeyCheck` (§7.3 Eq. 7.2) accepts the assembled
`decapsulationKey`.

The proof reduces the two `slice` projections of `decapsulationKey` to
`encapsulationKey self params` and `self.encaps_key_hash.toSpec` via the
slice/cast/append helpers (`cast_slice_eq_of_append₄_mid` and
`cast_slice_eq_of_append₄_third`), then applies `h_hash` to close
`H(ek) = stored_hash`.

**Why the precondition is shaped this way.** `wfKey` is layout-only
(see `Bridges/KeyView.lean`) and does NOT carry the byte-form
connection between `self.encaps_key_hash` and `H(ek)`. The hash
witness must come from the caller, which obtains it from
`mlkem.key_expand_from_private_seed.spec`'s postcondition (`Key.lean`).
This mirrors `encaps_keycheck_holds` (`Encaps.lean`). -/
private theorem decaps_keycheck_holds
    {self : mlkem.key.Key} {params : ParameterSet}
    (h_hash : self.encaps_key_hash.toSpec =
              MLKEM.H (encapsulationKey self params)) :
    MLKEM.Decaps.KeyCheck params (decapsulationKey self params) = true := by
  set kPKE := keySEncoded self params
  set ek := encapsulationKey self params
  set hek := Array.toSpec self.encaps_key_hash
  set z := Array.toSpec self.private_random
  have h_ek :
      slice (decapsulationKey self params) (384 * (k params : ℕ))
          (384 * (k params : ℕ) + 32) (by grind)
      = ek := by
    show slice ((kPKE ‖ ek ‖ hek ‖ z).cast _) _ _ _ = _
    exact Symcrust.Properties.MLKEM.Helpers.cast_slice_eq_of_append₄_mid
      kPKE ek hek z (by grind) (by grind)
  have h_h :
      slice (decapsulationKey self params) (768 * (k params : ℕ) + 32) 32
          (by grind)
      = hek := by
    show slice ((kPKE ‖ ek ‖ hek ‖ z).cast _) (768 * (k params : ℕ) + 32) 32 _ = _
    exact Symcrust.Properties.MLKEM.Helpers.cast_slice_eq_of_append₄_third
      kPKE ek hek z (by grind) _ (by ring) (by grind)
  unfold MLKEM.Decaps.KeyCheck
  show (decide _) = true
  rw [h_ek, h_h, h_hash]
  apply decide_eq_true
  rfl

/-- **Top spec for `mlkem.decapsulate`** — FC against
`MLKEM.Decaps_internal`.

## Precondition justifications

The two non-trivial preconditions on the cached key are **both
genuinely required** by the function body (cf. `Code/Funs.lean`
lines 5053–5199):

* `h_wf : wfKey pk_mlkem_key params` — used at line 5097 (reading
  `params.n_rows` to cast for the index-mut window), line 5115
  (`Key.s` accessor; the post needs `length = n_rows = k params` and
  every poly satisfies `wfPoly`, both clauses of `wfKey`), line 5117
  (`vector_mont_dot_product` precondition on the `s` argument), and
  line 5144 (recursive call to `encapsulate_internal` which itself
  requires `wfKey`).
* `h_priv : pk_mlkem_key.has_private_key = true` — gates the entire
  cryptographic body (line 5074): when `has_private_key = false` the
  function short-circuits with `Error.InvalidArgument`.  This matches
  the Rust API contract that `decapsulate` is only callable on a key
  that has been populated with private material via the corresponding
  `key_set_value`/`SetKeyValue` call.

`h_ct_len` is the canonical ciphertext-length contract from FIPS 203
§6.3; we use the `cipherlength params` abbreviation defined in
`Properties/MLKEM/Basic.lean`.

## Proof strategy / Informal proof

This top spec is a thin dispatch wrapper around `decapsulateBody.spec`:
the `#decompose` cascade above factors the body into four `fold`
equations.  The proof rewrites via
`decapsulate.fold` (exposes prefix + first dispatcher), steps through
the seven arithmetic binds, then case-splits via
`decapsulateDispatchAgreedLen.fold`, `decapsulateDispatchCtLen.fold`,
and `decapsulateDispatchAlloc.fold` to dispatch the three validation
gates plus the allocation; the success arm of the inner `match` is
closed by `decapsulateBody.spec`.  All three validation-failure arms
and the allocation-failure arm trivially satisfy the `_ => True`
post clauses.

The `NoError` arm's existentials `(h_a, h_c)` are introduced after
the success branch of the validation case-split: `h_a` comes from
the `agreed_secret_length != 32` dispatcher's success branch (which
yields `agreed_secret.length = 32`), `h_c` analogously from the
ciphertext-length dispatcher. Both are passed through to
`decapsulateBody.spec` as `h_secret_len` and `h_ct_len`.

The final FC obligation `Decaps params dk c = some _` decomposes to
`if Decaps.KeyCheck params dk then some _ else none = some _` after
unfolding `Decaps`. We discharge `Decaps.KeyCheck params dk = true`
via `decaps_keycheck_holds`, whose `h_hash` precondition is supplied
by the `wfDecapKey` precondition (`h_hash_pinned`). -/
@[step]
theorem mlkem.decapsulate.spec
    (params : ParameterSet)        -- Spec-level parameter set
    (pk_mlkem_key : mlkem.key.Key) -- Input: private key container
    (pb_ciphertext : Slice U8)     -- Input: encapsulated key
    (pb_agreed_secret : Slice U8)  -- Output: shared secret
    (h_key : wfDecapKey pk_mlkem_key params) :
    -- FIPS 203 §7.3 "Decapsulation Input Check" explicitly
    -- leaves the dk validation policy to the implementer;
    -- the standard only requires that the check happen
    -- *somewhere* before dk is used.
    -- SymCrypt enforces it at key-creation- or key-load-time,
    -- which both establish the wfDecapKey condition above.
    mlkem.decapsulate pk_mlkem_key pb_ciphertext pb_agreed_secret
      ⦃ error pb_agreed_secret' =>
          match error with
          | .NoError =>
              ∃ h_s h_c,
                MLKEM.Decaps params (pk_mlkem_key.toDecapKey params)
                    (pb_ciphertext.toSpec _ h_c)
                  = some (pb_agreed_secret'.toSpec _ h_s)
          | .InvalidArgument =>
              -- The Rust code also checks `!has_private_key`, but
              -- `wfDecapKey` statically excludes that arm.
              pb_agreed_secret.length ≠ 32 ∨
              pb_ciphertext.length ≠ cipherlength params
          | .MemoryAllocationFailure =>
              -- The only allocation in `decapsulate` is the
              -- `try_new_box_default.DecapsulateTemps.spec` gate, which
              -- yields `out_of_memory` on failure.
              out_of_memory
          | _ => False
            -- The 21 other error cases are statically excluded.
          ⦄
  := by
  -- Unbundle `wfDecapKey` into the named facts the proof and
  -- `decapsulateBody.spec` (via `step*`) consume.  The destructure
  -- threads the parent `wfEncapKey`/`wfKey` fields directly.  `h_hash` is
  -- re-stated against `encapsulationKey` (defeq to `keyHashPinned`'s
  -- `keyEncodedTPrefix ‖ public_seed`), the form the body and
  -- `decaps_keycheck_holds` consume.
  obtain ⟨⟨h_wf, h_hash_pinned, h_t_form, h_a_form⟩, h_priv⟩ := h_key
  have h_hash : pk_mlkem_key.encaps_key_hash.toSpec =
      Spec.SHA3.sha3_256 (encapsulationKey pk_mlkem_key params) := h_hash_pinned
  obtain ⟨hp, hnr, hdw⟩ := h_wf
  have hpr := wfInternalParams.n_rows_val hp
  have hpu := wfInternalParams.n_bits_of_u_val hp
  have hpv := wfInternalParams.n_bits_of_v_val hp
  rw [decapsulate.fold]
  simp only [decapsulateDispatchAgreedLen.fold, decapsulateDispatchCtLen.fold,
             decapsulateDispatchAlloc.fold]
  step*
  case h_wf => exact ⟨hp, hnr, hdw⟩
  case h_secret_len => simp only [mlkem.SIZEOF_AGREED_SECRET] at *; agrind
  case h_wfpv0 => simp_all
  case h_wfpe1 => simp_all
  case h1 =>
    rename_i h_g
    simp only [bne_iff_ne, ne_eq, mlkem.SIZEOF_AGREED_SECRET] at h_g
    left
    simp only [Slice.length, ne_eq]
    intro h_len_eq
    apply h_g
    apply UScalar.eq_of_val_eq
    simp [h_len_eq]
  simp only [error_post1]
  have h_c : pb_ciphertext.length = cipherlength params := by
    have hi_cast : (UScalar.cast UScalarTy.Usize pk_mlkem_key.params.n_rows).val =
                   pk_mlkem_key.params.n_rows.val := by simp
    have hi1_cast : (UScalar.cast UScalarTy.Usize pk_mlkem_key.params.n_bits_of_u).val =
                    pk_mlkem_key.params.n_bits_of_u.val := by simp
    have hi4_cast : (UScalar.cast UScalarTy.Usize pk_mlkem_key.params.n_bits_of_v).val =
                    pk_mlkem_key.params.n_bits_of_v.val := by simp
    have hi_val : i.val = (k params : ℕ) := by rw [i_post, hi_cast]; exact hpr
    have hi1_val : i1.val = dᵤ params := by rw [i1_post, hi1_cast]; exact hpu
    have hi4_val : i4.val = dᵥ params := by rw [i4_post, hi4_cast]; exact hpv
    simp only [cipherlength]
    agrind
  refine ⟨error_post2, h_c, ?_⟩
  have h_kc : MLKEM.Decaps.KeyCheck params (decapsulationKey pk_mlkem_key params) = true :=
    decaps_keycheck_holds h_hash
  show MLKEM.Decaps params (decapsulationKey pk_mlkem_key params)
        (pb_ciphertext.toSpec (cipherlength params) h_c)
      = some (pb_agreed_secret'.toSpec 32 error_post2)
  unfold MLKEM.Decaps
  simp only [h_kc, ↓reduceIte]
  exact congrArg some error_post3.symm

end Symcrust.Properties.MLKEM
