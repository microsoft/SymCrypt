/-
  # Bridges/PrfShake.lean — SHAKE256 ↔ FIPS-203 `PRF` bridge.

  ## What this provides

  Four layered bridge lemmas between the SHAKE256 incremental ghost-state
  (`extractOutput`) and the MLKEM spec-level `PRF` (Eq. (4.3)), plus a
  thin `SamplePolyCBD`-shaped wrapper used directly at the CBD loop-body
  call-sites. All five are fully proved (no sorry).

  1. **`shake256_extractOutput`** — Vector-level bridge.  When `g.absorbed`
     is the byte vector `B`, `(extractOutput g outLen).map (·.bv) =
     shake256 B outLen`.  Direct analogue of `sha3_256_extractOutput` in
     `Hash.lean`, specialized to SHAKE256 (`rate = 136`, `padVal = 31#u8 =
     SHAKE_PADDING`, suffix = `SHA3.xofSuffix`).

  2. **`extractOutput_append_PRF`** — Specialisation to the PRF-relevant
     ghost-state pattern `g_base.append [i_byte] sm` (with `sm = false`
     hardcoded internally): `(extractOutput (g_base.append [i_byte] sm)
     (64 * η)).map (·.bv) = PRF η σ i_byte.bv`, given `g_base` carries `σ`.

  3. **`prf_shake_bridge`** — Raw-parameters loop-body wrapper. Takes the
     SHAKE state as separate `rate / padVal / squeezed / absorbed` facts
     (suitable when the caller has these directly, e.g. on a synthetic
     `GhostState`) and closes

     ```
     sliceWindowToSpecBytes s3 0 (64 * (η : ℕ)) h =
       (MLKEM.PRF η σ i_byte.bv).cast _
     ```

     via a per-byte index hypothesis `h_s3_extract`.

  4. **`prf_shake_bridge_of_absorbing`** — Consumer-facing wrapper. Same
     conclusion as Bridge 3 but takes `MlKemHashState.absorbing mkhs g_base`
     and `mkhs.alg = Shake256`, extracting `rate / padVal / squeezed` from
     the invariant.

  5. **`prf_shake_samplePolyCBD_bridge_of_absorbing`** — Loop-body wrapper.
     Closes the residual `@SamplePolyCBD η_cbd (sliceWindow ...) =
     @SamplePolyCBD η_spec (MLKEM.PRF η_spec σ i_byte.bv)` arising at the
     four CBD loop-body sorry sites, where `η_cbd` is built via `cbdEta`
     from a `UScalar` bound and `η_spec` is the spec-level `η₁ / η₂`.
     This is the form callers in `Encaps.lean` / `Key.lean` should apply
     directly.
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Hash

namespace Symcrust.Properties.MLKEM

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open scoped Spec.Notations
open symcrust
open sha3.sha3_impl

/-! ## GhostState/array list-level helpers

Small bridging lemmas used by absorb-pattern sorry sites that need to
reason about `g.absorbed.map (·.bv)` after one or more `GhostState.append`
operations.  Factored here because `Sampling/ExpandMatrix` and other
absorb-pattern callers want them and `PrfShake.lean` already imports
`Basic` and opens `sha3.sha3_impl` so `GhostState` resolves directly.
-/

/-- `arrayToSpecBytes` unfolded to a `List.map (·.bv)` of the underlying
`val` list.  Useful when the spec-side seed is `arrayToSpecBytes seed` and
the impl side has `seed.val.map (·.bv)` after one `Array.val_to_slice`. -/
theorem arrayToSpecBytes_toList_bv {n : Usize} (a : Array U8 n) :
    (arrayToSpecBytes a).toList = a.val.map (·.bv) := by
  unfold arrayToSpecBytes
  rw [Vector.toList_ofFn]
  apply List.ext_getElem
  · simp [a.property]
  · intro k h1 h2; rw [List.getElem_ofFn, List.getElem_map]

/-- `GhostState.append` distributes over `List.map (·.bv)` in absorb mode
(`wasSqueeze = false`): the new absorbed list is the old one ++ data. -/
theorem absorbed_bv_append (g : GhostState) (data : List U8) :
    (g.append data false).absorbed.map (·.bv) =
      g.absorbed.map (·.bv) ++ data.map (·.bv) := by
  simp [GhostState.append, List.map_append]

/-- An absorbing `MlKemHashState` has `squeeze_mode = false` at the
KeccakState level.  Used to specialize `absorbed_bv_append` from the
generic `wasSqueeze` parameter to the concrete `false` value when the
caller only knows `mkhs.absorbing g`. -/
theorem squeeze_mode_eq_false_of_absorbing
    {s : mlkem.hash.MlKemHashState} {g : GhostState}
    (h : mlkem.hash.MlKemHashState.absorbing s g) :
    s.state.squeeze_mode = false := by
  unfold mlkem.hash.MlKemHashState.absorbing at h
  exact Bool.eq_false_iff.mpr h.1.1.2.1

/-! ## Bridge 1 — generic SHAKE256 ↔ extractOutput

Mirror of `sha3_256_extractOutput` (see `Hash.lean:411`) adapted for
the SHAKE256 variant: rate = 136, padValue = `SHAKE_PADDING = 31#u8`,
trail suffix = `Spec.SHA3.xofSuffix`, and a variable squeeze length
`outLen` (not fixed at 32 as for SHA3-256).

**Informal proof.**

1. Build `msg : Vector U8 n := ⟨g.absorbed.toArray, _⟩` so that
   `msg.toList = g.absorbed`.
2. Witness `msg.map (·.bv) = B` from `h_bytes`.
3. Apply `code_toSpec msg SHA3.xofSuffix 136 outLen hs hsmall hr` (after
   rewriting `h_rate`, `h_pad`, `h_squeezed`).
4. Bridge `encodePadVal SHA3.xofSuffix _ = 31#u8` via `native_decide`
   (same pattern as `shake256.spec`).
5. Unfold `Spec.SHA3.shake256` to `bitsToBytes (SHAKE256 (...) (8 * outLen))`
   and conclude by `rfl` on the rate/capacity decomposition
   (`1600 - 512 = 8 * 136`). -/
theorem shake256_extractOutput
    {n : Nat} (g : GhostState) (B : 𝔹 n) (outLen : Nat)
    (h_n : g.absorbed.length = n)
    (h_bytes : ∀ (i : Fin n),
        B.get i = (g.absorbed[i.val]'(h_n ▸ i.isLt)).bv)
    (h_rate : g.rate = 136)
    (h_pad : g.padVal = 31#u8)
    (h_squeezed : g.squeezed = []) :
    (extractOutput g outLen).map (·.bv) =
      Spec.SHA3.shake256 B outLen := by
  let msg : Vector U8 n := ⟨g.absorbed.toArray, by simp [h_n]⟩
  have hmsg_toList : msg.toList = g.absorbed := by
    simp [msg, Vector.toList]
  have hmsg_eq_B : msg.map (·.bv) = B := by
    apply Vector.ext
    intro i hi
    simp only [Vector.getElem_map, msg, Vector.getElem_mk, List.getElem_toArray]
    have hb := h_bytes ⟨i, hi⟩
    simp [Vector.get] at hb
    exact hb.symm
  have hbits : bytesU8ToBits msg = Spec.bytesToBits B := by
    unfold bytesU8ToBits
    rw [hmsg_eq_B]
  unfold extractOutput
  rw [h_rate, h_pad, h_squeezed]
  simp only [List.length_nil]
  unfold squeezeAfter
  have hs : (4 : Nat) + 1 ≤ 8 := by decide
  have hsmall : (4 : Nat) + 1 < 8 := by decide
  have hr : (0 : Nat) < 136 ∧ 8 * 136 < Spec.SHA3.b := by decide
  have hpad : (31#u8 : U8) = encodePadVal Spec.SHA3.xofSuffix hs := by
    unfold encodePadVal Spec.SHA3.xofSuffix; native_decide
  rw [hpad]
  rw [show g.absorbed = msg.toList from hmsg_toList.symm]
  have hcode := code_toSpec msg Spec.SHA3.xofSuffix 136 outLen hs hsmall hr
  rw [hbits] at hcode
  have h := congrArg Spec.bitsToBytes hcode
  unfold bytesU8ToBits at h
  rw [Spec.bitsToBytes_bytesToBits] at h
  unfold Spec.SHA3.shake256 Spec.SHA3.SHAKE256 Spec.SHA3.KECCAK
  simp only [show (1600 - 512 : Nat) = 8 * 136 from rfl]
  exact h

/-! ## Bridge 1' — generic SHAKE128 ↔ extractOutput

Mirror of `shake256_extractOutput` for the SHAKE128 variant: rate = 168,
padValue unchanged (`SHAKE_PADDING = 31#u8`), trail suffix unchanged
(`xofSuffix`).  Rate decomposition: `1600 - 256 = 8 * 168 = 1344`.

Used by `Properties/MLKEM/Helpers/Shake128ByteBridge.lean` (the
SampleNTT byte-bridge); not consumed elsewhere because Encaps/Decaps/
KeyGen use SHA3 only through `MlKemHashState.extract.spec` directly. -/
theorem shake128_extractOutput
    {n : Nat} (g : GhostState) (B : 𝔹 n) (outLen : Nat)
    (h_n : g.absorbed.length = n)
    (h_bytes : ∀ (i : Fin n),
        B.get i = (g.absorbed[i.val]'(h_n ▸ i.isLt)).bv)
    (h_rate : g.rate = 168)
    (h_pad : g.padVal = 31#u8)
    (h_squeezed : g.squeezed = []) :
    (extractOutput g outLen).map (·.bv) =
      Spec.SHA3.shake128 B outLen := by
  let msg : Vector U8 n := ⟨g.absorbed.toArray, by simp [h_n]⟩
  have hmsg_toList : msg.toList = g.absorbed := by
    simp [msg, Vector.toList]
  have hmsg_eq_B : msg.map (·.bv) = B := by
    apply Vector.ext
    intro i hi
    simp only [Vector.getElem_map, msg, Vector.getElem_mk, List.getElem_toArray]
    have hb := h_bytes ⟨i, hi⟩
    simp [Vector.get] at hb
    exact hb.symm
  have hbits : bytesU8ToBits msg = Spec.bytesToBits B := by
    unfold bytesU8ToBits
    rw [hmsg_eq_B]
  unfold extractOutput
  rw [h_rate, h_pad, h_squeezed]
  simp only [List.length_nil]
  unfold squeezeAfter
  have hs : (4 : Nat) + 1 ≤ 8 := by decide
  have hsmall : (4 : Nat) + 1 < 8 := by decide
  have hr : (0 : Nat) < 168 ∧ 8 * 168 < Spec.SHA3.b := by decide
  have hpad : (31#u8 : U8) = encodePadVal Spec.SHA3.xofSuffix hs := by
    unfold encodePadVal Spec.SHA3.xofSuffix; native_decide
  rw [hpad]
  rw [show g.absorbed = msg.toList from hmsg_toList.symm]
  have hcode := code_toSpec msg Spec.SHA3.xofSuffix 168 outLen hs hsmall hr
  rw [hbits] at hcode
  have h := congrArg Spec.bitsToBytes hcode
  unfold bytesU8ToBits at h
  rw [Spec.bitsToBytes_bytesToBits] at h
  unfold Spec.SHA3.shake128 Spec.SHA3.SHAKE128 Spec.SHA3.KECCAK
  simp only [show (1600 - 256 : Nat) = 8 * 168 from rfl]
  exact h

/-! ## Bridge 2 — extractOutput of σ‖[b] yields PRF η σ b

Specialisation to the PRF pattern: `g_base.absorbed` corresponds to σ,
the next byte appended is `i_byte`, and the squeeze length is `64 * η`.

**Informal proof.**

1. Compute the absorbed bytes of `g_base.append [i_byte] sm`:
   `(g_base.append [i_byte] sm).absorbed = g_base.absorbed ++ [i_byte]`
   from `GhostState.append`.
2. Build the spec-side `B := σ ‖ #v[i_byte.bv] : 𝔹 33` so that
   `B.toList = σ.toList ++ [i_byte.bv]`.
3. Per-byte equality: combine `h_g_absorbed : g_base.absorbed.map (·.bv) = σ.toList`
   with the singleton tail.
4. Invoke `shake256_extractOutput` with `n := 33`, `outLen := 64 * (η : ℕ)`.
5. Unfold `MLKEM.PRF` (= `SHA3.shake256 (σ ‖ #v[i_byte.bv]) (64 * η)`).
   Conclude by `rfl`. -/
theorem extractOutput_append_PRF
    (η : Η) (σ : 𝔹 32) (i_byte : U8)
    (g_base : GhostState)
    (h_g_rate : g_base.rate = 136)
    (h_g_pad : g_base.padVal = 31#u8)
    (h_g_squeezed : g_base.squeezed = [])
    (h_g_absorbed : g_base.absorbed.map (·.bv) = σ.toList) :
    (extractOutput (g_base.append [i_byte] false) (64 * (η : ℕ))).map (·.bv) =
      MLKEM.PRF η σ i_byte.bv := by
  let B : 𝔹 33 := σ ‖ #v[i_byte.bv]
  have h_g_len : g_base.absorbed.length = 32 := by
    have := congrArg List.length h_g_absorbed
    simpa using this
  set g' : GhostState := g_base.append [i_byte] false with hg'_def
  have h_g'_absorbed : g'.absorbed = g_base.absorbed ++ [i_byte] := by
    simp [hg'_def, GhostState.append]
  have h_g'_rate : g'.rate = 136 := by simp [hg'_def, GhostState.append, h_g_rate]
  have h_g'_pad : g'.padVal = 31#u8 := by simp [hg'_def, GhostState.append, h_g_pad]
  have h_g'_squeezed : g'.squeezed = [] := by
    simp [hg'_def, GhostState.append, h_g_squeezed]
  have h_n : g'.absorbed.length = 33 := by
    rw [h_g'_absorbed]; simp [h_g_len]
  have h_B_toList : B.toList = σ.toList ++ [i_byte.bv] := by
    show (σ ++ #v[i_byte.bv]).toList = σ.toList ++ [i_byte.bv]
    rw [Vector.toList_append]; rfl
  have h_bytes : ∀ (i : Fin 33),
      B.get i = (g'.absorbed[i.val]'(by rw [h_n]; exact i.isLt)).bv := by
    intro i
    have h_σ_len : σ.toList.length = 32 := σ.toList_length
    -- Master equation: B.toList = (g'.absorbed).map (·.bv).
    have h_master : B.toList = g'.absorbed.map (·.bv) := by
      rw [h_B_toList, h_g'_absorbed, List.map_append, List.map_cons, List.map_nil,
        h_g_absorbed]
    have hBget : B.get i = B.toList[i.val]'(by
        rw [Vector.toList_length]; exact i.isLt) := by
      simp [Vector.get, ← Vector.getElem_toList]
    rw [hBget]
    -- B.toList[i.val] = (g'.absorbed[i.val]).bv via h_master + List.getElem_map
    have hi_g'  : i.val < g'.absorbed.length := by rw [h_n]; exact i.isLt
    have hi_map : i.val < (g'.absorbed.map (·.bv)).length := by
      rw [List.length_map]; exact hi_g'
    have h_step : B.toList[i.val]'(by rw [Vector.toList_length]; exact i.isLt) =
        (g'.absorbed.map (·.bv))[i.val]'hi_map := by
      simp [h_master]
    rw [h_step]
    exact List.getElem_map _
  have hbridge := shake256_extractOutput g' B (64 * (η : ℕ))
    h_n h_bytes h_g'_rate h_g'_pad h_g'_squeezed
  rw [hbridge]
  rfl

/-! ## Bridge 3 — `sliceWindowToSpecBytes` of an extractOutput slice = PRF

The form needed at `Key.lean:182` (`loop0_body.spec` cbd_new) and `:520`
(`loop1_body.spec` cbd_new) — and identically at the matching sites in
`Encaps.lean`.

The use-site hypothesis carries `h_s2_val : s2.val = (extractOutput G n_eta).toList`
where `G := g_base.append [i_byte] sm` (post of `MlKemHashState.extract.spec`).
The slice `s3` is then `(index_mut_back ... s2).to_slice` — same bytes,
possibly embedded in a longer buffer.  The bridge requires the user to
supply `h_s3_val : s3.val[k] = s2.val[k]` (per-byte) for `k ∈ [0, n_eta)`,
which is trivial when `s3.val = s2.val` and otherwise follows from the
specific `index_mut_back` chain.

**Informal proof.**

1. Unfold `sliceWindowToSpecBytes` → `Vector.ofFn fun i => (s3.val[0 + i.val]).bv`.
2. Apply `Vector.ext`: for each `i : Fin n_eta`, show
   `(s3.val[i.val]).bv = (MLKEM.PRF η σ i_byte.bv).get i`.
3. Bridge `s3.val[i.val] = s2.val[i.val]` via `h_s3_val`.
4. Bridge `s2.val[i.val] = (extractOutput G n_eta).toList[i.val]` via `h_s2_val`.
5. Bridge `(extractOutput G n_eta).toList[i.val] = (extractOutput G n_eta).get ⟨i.val, _⟩`
   (definitional).
6. Apply `extractOutput_append_PRF` (mapped per-byte) to conclude. -/
theorem prf_shake_bridge
    (η : Η) (σ : 𝔹 32) (i_byte : U8)
    (g_base : GhostState) (sm : Bool) (h_sm : sm = false)
    (h_g_rate : g_base.rate = 136)
    (h_g_pad : g_base.padVal = 31#u8)
    (h_g_squeezed : g_base.squeezed = [])
    (h_g_absorbed : g_base.absorbed.map (·.bv) = σ.toList)
    (n_eta : Nat) (h_n_eta : n_eta = 64 * (η : ℕ))
    (s3 : Slice U8) (h_s3_bound : 0 + n_eta ≤ s3.length)
    (h_s3_extract : ∀ (k : ℕ) (hk : k < n_eta),
      s3.val[k]'(by
        have : k < s3.length := by omega
        simpa [Aeneas.Std.Slice.length] using this) =
        (extractOutput (g_base.append [i_byte] sm) n_eta).toList[k]'(by
          rw [Vector.toList_length]; exact hk)) :
    sliceWindowToSpecBytes s3 0 n_eta h_s3_bound =
      (MLKEM.PRF η σ i_byte.bv).cast h_n_eta.symm := by
  subst h_sm
  subst h_n_eta
  apply Vector.ext
  intro k hk
  -- LHS: sliceWindowToSpecBytes s3 0 _ _)[k] = (s3.val[k]).bv
  have h_lhs : (sliceWindowToSpecBytes s3 0 (64 * (η : ℕ)) h_s3_bound)[k] =
      (s3.val[k]'(by
        have : k < s3.length := by omega
        simpa [Aeneas.Std.Slice.length] using this)).bv := by
    simp [sliceWindowToSpecBytes, Vector.getElem_ofFn]
  rw [h_lhs, h_s3_extract k hk]
  -- Convert toList[k] to vector .get
  rw [Vector.getElem_toList]
  -- Goal: ((extractOutput G).get ⟨k, hk⟩).bv = ((PRF...).cast _)[k]
  -- Apply Bridge 2 (mapped per-byte)
  have hbridge := extractOutput_append_PRF η σ i_byte g_base h_g_rate h_g_pad
    h_g_squeezed h_g_absorbed
  have h_get :=
    congrArg (fun v : 𝔹 (64 * (η : ℕ)) => v[k]'hk) hbridge
  simp [Vector.getElem_map] at h_get
  rw [h_get]
  simp [Vector.cast]

/-! ## Bridge 4 — wrapper consuming `MlKemHashState.absorbing` directly

The `cbdLoopInv` carries the SHAKE state as
`mlkem.hash.MlKemHashState.absorbing mkhs_base g_base` together with
`mkhs_base.alg = MlKemHashAlg.Shake256`.  From these we derive
`g_base.rate = 136`, `g_base.padVal = 31#u8`, `g_base.squeezed = []` and
pass them to `prf_shake_bridge`.

This is the form consumers should apply at the sorry site.

**Informal proof.**

1. Unfold `MlKemHashState.absorbing` → `absorbing self.state g ∧
   algParams self.alg = some (g.rate, g.padVal)`.
2. Unfold `absorbing` → `absorbingWeak ks g ∧ ...` and extract
   `g.squeezed = []`.
3. From `algParams Shake256 = some (136, 31#u8)` (by `rfl`/`native_decide`)
   and `algParams self.alg = some (g.rate, g.padVal)`, conclude
   `g.rate = 136 ∧ g.padVal = 31#u8` via `Prod.mk.inj`.
4. Apply `prf_shake_bridge`. -/
theorem prf_shake_bridge_of_absorbing
    (η : Η) (σ : 𝔹 32) (i_byte : U8)
    (mkhs : mlkem.hash.MlKemHashState) (g_base : GhostState)
    (h_abs : mlkem.hash.MlKemHashState.absorbing mkhs g_base)
    (h_alg : mkhs.alg = mlkem.hash.MlKemHashAlg.Shake256)
    (h_g_absorbed : g_base.absorbed.map (·.bv) = σ.toList)
    (sm : Bool) (h_sm : sm = false)
    (n_eta : Nat) (h_n_eta : n_eta = 64 * (η : ℕ))
    (s3 : Slice U8) (h_s3_bound : 0 + n_eta ≤ s3.length)
    (h_s3_extract : ∀ (k : ℕ) (hk : k < n_eta),
      s3.val[k]'(by
        have : k < s3.length := by omega
        simpa [Aeneas.Std.Slice.length] using this) =
        (extractOutput (g_base.append [i_byte] sm) n_eta).toList[k]'(by
          rw [Vector.toList_length]; exact hk)) :
    sliceWindowToSpecBytes s3 0 n_eta h_s3_bound =
      (MLKEM.PRF η σ i_byte.bv).cast h_n_eta.symm := by
  -- Unfold absorbing to extract rate / padVal / squeezed.
  unfold mlkem.hash.MlKemHashState.absorbing at h_abs
  obtain ⟨h_abs_state, h_algParams⟩ := h_abs
  have h_abs_state_weak : sha3.sha3_impl.absorbingWeak mkhs.state g_base :=
    h_abs_state.1
  have h_g_squeezed : g_base.squeezed = [] := h_abs_state_weak.2.2.2.2
  -- algParams Shake256 = some (136, 31#u8) ⇒ g.rate = 136, g.padVal = 31#u8.
  rw [h_alg] at h_algParams
  have h_params_eq : (136, (31#u8 : U8)) = (g_base.rate, g_base.padVal) := by
    have : mlkem.hash.MlKemHashState.algParams mlkem.hash.MlKemHashAlg.Shake256 =
        some (136, 31#u8) := by
      unfold mlkem.hash.MlKemHashState.algParams; rfl
    rw [this] at h_algParams
    exact Option.some_inj.mp h_algParams
  have h_g_rate : g_base.rate = 136 := (Prod.mk.inj h_params_eq).1.symm
  have h_g_pad : g_base.padVal = 31#u8 := (Prod.mk.inj h_params_eq).2.symm
  exact prf_shake_bridge η σ i_byte g_base sm h_sm h_g_rate h_g_pad
    h_g_squeezed h_g_absorbed n_eta h_n_eta s3 h_s3_bound h_s3_extract

/-! ## Bridge 4b — `J(zc)` from a 2-append/32-byte-extract SHAKE256 chain

Used at the Decaps implicit-rejection chain (`Code/Funs.lean:5176-5188`):
after `set_alg Shake256 → init → append(z) → append(c) → extract(out, false)`
the runtime byte buffer `out` (length 32) carries
`(extractOutput g 32).toList`, where `g` is the final ghost state whose
`g.absorbed` (in spec form) equals `z ‖ c : 𝔹 (32 + cipherlength params)`.
This bridge packages those facts into the FIPS 203 conclusion
`out.toSpec 32 _ = MLKEM.J (z ‖ c)`.

**Informal proof.**

1. Unfold `mlkem.hash.MlKemHashState.absorbing` to derive `g.rate = 136`,
   `g.padVal = 31#u8`, `g.squeezed = []` (mirrors `prf_shake_bridge_of_absorbing`).
2. From `g.absorbed.map (·.bv) = zc.toList`, derive `g.absorbed.length = n`
   and the per-byte hypothesis required by `shake256_extractOutput`.
3. Apply `shake256_extractOutput` to obtain
   `(extractOutput g 32).map (·.bv) = SHA3.shake256 zc 32`. Since
   `MLKEM.J zc := SHA3.shake256 zc 32` definitionally, this is the RHS.
4. `generalize` `extractOutput g 32` to defeat whnf storms, then bridge
   `sliceToSpecBytes s 32 _ = (extractOutput g 32).map (·.bv)` via
   `Vector.toList_inj` + `List.ext_getElem` + `h_s_val`. -/
theorem kbar_from_shake_bridge
    {n : ℕ}
    (mkhs : mlkem.hash.MlKemHashState) (g : GhostState)
    (h_abs : mlkem.hash.MlKemHashState.absorbing mkhs g)
    (h_alg : mkhs.alg = mlkem.hash.MlKemHashAlg.Shake256)
    (zc : 𝔹 n)
    (h_absorbed : g.absorbed.map (·.bv) = zc.toList)
    (s : Slice U8) (h_s_len : s.length = 32)
    (h_s_val : s.val = (extractOutput g 32).toList) :
    sliceToSpecBytes s 32 h_s_len = MLKEM.J zc := by
  unfold mlkem.hash.MlKemHashState.absorbing at h_abs
  obtain ⟨h_abs_state, h_algParams⟩ := h_abs
  have h_abs_weak : absorbingWeak mkhs.state g := h_abs_state.1
  have h_g_squeezed : g.squeezed = [] := h_abs_weak.2.2.2.2
  rw [h_alg] at h_algParams
  have h_params : (136, (31#u8 : U8)) = (g.rate, g.padVal) := by
    have h_ap : mlkem.hash.MlKemHashState.algParams mlkem.hash.MlKemHashAlg.Shake256 =
        some (136, 31#u8) := by
      unfold mlkem.hash.MlKemHashState.algParams; rfl
    rw [h_ap] at h_algParams
    exact Option.some_inj.mp h_algParams
  have h_g_rate : g.rate = 136 := (Prod.mk.inj h_params).1.symm
  have h_g_pad  : g.padVal = 31#u8 := (Prod.mk.inj h_params).2.symm
  have h_g_len : g.absorbed.length = n := by
    have hL := congrArg List.length h_absorbed
    rw [List.length_map, Vector.length_toList] at hL
    exact hL
  have h_bytes : ∀ (i : Fin n),
      zc.get i = (g.absorbed[i.val]'(h_g_len ▸ i.isLt)).bv := by
    intro i
    have hi_g  : i.val < g.absorbed.length := h_g_len ▸ i.isLt
    have hi_zc : i.val < zc.toList.length := by
      rw [Vector.length_toList]; exact i.isLt
    have hi_map : i.val < (g.absorbed.map (·.bv)).length := by
      rw [List.length_map]; exact hi_g
    have hZget : zc.get i = zc.toList[i.val]'hi_zc := by
      simp [Vector.get, ← Vector.getElem_toList]
    rw [hZget]
    have h_step : zc.toList[i.val]'hi_zc =
        (g.absorbed.map (·.bv))[i.val]'hi_map := by
      simp [← h_absorbed]
    rw [h_step]
    exact List.getElem_map _
  have h_extract : (extractOutput g 32).map (·.bv) =
      Spec.SHA3.shake256 zc 32 :=
    shake256_extractOutput g zc 32 h_g_len h_bytes h_g_rate h_g_pad h_g_squeezed
  -- `MLKEM.J zc = SHA3.shake256 zc 32` is definitional; bridge slice ↔ extractOutput.
  change sliceToSpecBytes s 32 h_s_len = Spec.SHA3.shake256 zc 32
  rw [← h_extract]
  generalize extractOutput g 32 = V at h_s_val
  apply Vector.toList_inj.mp
  unfold sliceToSpecBytes
  rw [Vector.toList_ofFn, Vector.toList_map]
  apply List.ext_getElem
  · simp [Vector.length_toList, h_s_val]
  · intro i h1 h2
    simp only [List.getElem_ofFn, List.getElem_map]
    fcongr 1
    exact List.getElem_of_eq h_s_val _

/-! ## Bridge 5 — `SamplePolyCBD` wrapper closing the loop-body residual

The loop-body proofs reach a residual goal of shape

```
@MLKEM.SamplePolyCBD η_cbd (sliceWindowToSpecBytes s3 0 (64 * (η_cbd : ℕ)) _)
  = @MLKEM.SamplePolyCBD η_spec (MLKEM.PRF η_spec σ i_byte.bv)
```

where the implementation-side `η_cbd : Η` is built via `cbdEta` from a
`UScalar` field of the wfKey-checked parameter set, while `η_spec : Η` is
the spec-level value `η₁ params` / `η₂ params`. They have the same `.val`
but are syntactically distinct, so `fcongr 1` would have to discover the
`Subtype.ext` step by deep unification — an 8M-heartbeat trap, as seen
when this site was first wired (Encaps loop0_body, commit `2f149af0`).

This bridge absorbs that step into a single explicit `Subtype.ext`,
folds in Bridge 4, and closes the goal via `Vector.cast rfl = id`.

**Informal proof.**

1. From `h_η : (η_cbd : ℕ) = (η_spec : ℕ)`, derive `η_cbd = η_spec` via
   `Subtype.ext` (`Η` is a `Subtype`).
2. Apply `prf_shake_bridge_of_absorbing` with `n_eta := 64 * (η_cbd : ℕ)`
   and `h_n_eta := rfl`, obtaining
   `sliceWindowToSpecBytes ... = (MLKEM.PRF η_cbd σ i_byte.bv).cast rfl`.
3. Rewrite the LHS by that equation; `subst` the `η`-equality to align
   both sides at `η_spec`; close by `rfl` (the residual `Vector.cast rfl`
   is definitionally `id`). -/
theorem prf_shake_samplePolyCBD_bridge_of_absorbing
    (η_cbd η_spec : Η) (h_η : (η_cbd : ℕ) = (η_spec : ℕ))
    (σ : 𝔹 32) (i_byte : U8)
    (mkhs : mlkem.hash.MlKemHashState) (g_base : GhostState)
    (h_abs : mlkem.hash.MlKemHashState.absorbing mkhs g_base)
    (h_alg : mkhs.alg = mlkem.hash.MlKemHashAlg.Shake256)
    (h_g_absorbed : g_base.absorbed.map (·.bv) = σ.toList)
    (sm : Bool) (h_sm : sm = false)
    (s3 : Slice U8) (h_s3_bound : 0 + 64 * (η_cbd : ℕ) ≤ s3.length)
    (h_s3_extract : ∀ (k : ℕ) (hk : k < 64 * (η_cbd : ℕ)),
      s3.val[k]'(by
        have : k < s3.length := by omega
        simpa [Aeneas.Std.Slice.length] using this) =
        (extractOutput (g_base.append [i_byte] sm) (64 * (η_cbd : ℕ))).toList[k]'(by
          rw [Vector.toList_length]; exact hk)) :
    @MLKEM.SamplePolyCBD η_cbd
      (sliceWindowToSpecBytes s3 0 (64 * (η_cbd : ℕ)) h_s3_bound) =
    @MLKEM.SamplePolyCBD η_spec (MLKEM.PRF η_spec σ i_byte.bv) := by
  have h_η_eq : η_cbd = η_spec := Subtype.ext h_η
  have h_bridge := prf_shake_bridge_of_absorbing η_cbd σ i_byte mkhs g_base
    h_abs h_alg h_g_absorbed sm h_sm (64 * (η_cbd : ℕ)) rfl s3 h_s3_bound h_s3_extract
  rw [h_bridge]
  subst h_η_eq
  rfl

end Symcrust.Properties.MLKEM
