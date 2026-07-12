/-
  # Key/Prelude.lean — `keyExpand.prelude.spec` and post-state invariants.

  Phases 1..9 of `mlkem.key_expand_from_private_seed` are factored into
  `keyExpand.prelude` and proven here.  Also defines the layered
  post-state invariants `keyExpand.Inv1..Inv4` consumed by the main
  spec in `Symcrust/Properties/MLKEM/Key.lean`.
-/
import Symcrust.Properties.MLKEM.Key.Loops
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.KeyView
import Symcrust.Properties.MLKEM.Bridges.PrfShake
import Symcrust.Properties.MLKEM.Ffi
import Symcrust.Properties.MLKEM.HashCalls
import Symcrust.Properties.MLKEM.Sampling.SampleCBD
import Symcrust.Properties.MLKEM.Sampling.ExpandMatrix
import Symcrust.Properties.MLKEM.Ntt.Ntt
import Symcrust.Properties.MLKEM.Ntt.PolyArith
import Symcrust.Properties.MLKEM.Ntt.MatVec
import Symcrust.Properties.MLKEM.Ntt.Transpose
import Symcrust.Properties.MLKEM.Encoding.Compress
import Symcrust.Properties.MLKEM.Helpers.KPKEStructure
import Symcrust.Properties.MLKEM.Bridges.MatrixVectorMul
import Symcrust.Properties.SHA3.StatefulHash

open Aeneas Aeneas.Std Result
open scoped Spec.Notations
open Spec
open Spec.MLKEM
open symcrust

namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

/-! ## Top spec

The Rust function `key_expand_from_private_seed` implements the
deterministic part of `K-PKE.KeyGen` (FIPS 203 Alg. 13).  Its
postcondition ties the resulting key state directly to the outputs
`(ekPKE, dkPKE) := K_PKE.KeyGen params d`.

The key fields are decomposed (not a single equality) because the
key struct holds the spec-level outputs across several physical
slots — matrix, vectors, encoded byte buffer, hash digest.  Each
conjunct is a direct equation with a spec-side artifact. -/

/-- View of the s-vector as a `PolyVector` in **standard** NTT form.

The `s` slot's content depends on the code path that last wrote it.
`key_expand_from_private_seed` leaves it in standard NTT form (= `ŝ`,
the output of `vector_ntt`; the subsequent `pv_tmp := ŝ ⊙ R` Mont
conversion writes into a scratch vector, not back into the `s` slot).
Other code paths (`decapsulate`) expect the slot in Montgomery form
(`ŝ ⊙ R`), as captured by `keyS` in `Bridges/KeyView.lean`.

This view exposes the raw poly without any Mont conversion; it equals
`ŝ` after `key_expand_from_private_seed`. -/
noncomputable def keyS_std (self : mlkem.key.Key) (params : ParameterSet) :
    MLKEM.PolyVector q (k params) :=
  Vector.ofFn fun (i : Fin (k params : ℕ)) =>
    toPoly (self.data.val[sOffset params + (i : ℕ)]'(by
      have h1 : self.data.val.length = 24 := self.data.property
      have hi := i.isLt
      unfold sOffset matrixLen; grind))

/-- Encoded `s` in 12-bit packed form: `ByteEncode 12 (keyS_std self)`.

Equals `dkPKE = ByteEncode 12 ŝ` (FIPS 203 §4.2.2) **when the `s` slot
holds `ŝ` in standard NTT form** — i.e. after
`key_expand_from_private_seed` and before any Mont conversion writes
back into the slot.  If a code path leaves the slot in Montgomery form
(`ŝ ⊙ R`), this definition encodes `ŝ ⊙ R` instead, which is **not**
`dkPKE`. -/
noncomputable def keySEncoded
    (self : mlkem.key.Key) (params : ParameterSet) :
    𝔹 (384 * (k params : ℕ)) :=
  (MLKEM.PolyVector.ByteEncode 12 (keyS_std self params)).cast (by grind)

/-! ## Decapsulation key view

Moved here from `Decaps.lean` so that the format-parametric helpers
`Key.toSpec` and `wfKeyFormat` (defined in
`Encoding/KeySetValue/Prelude.lean`) can refer to it without dragging
in the full `decapsulate.spec` cascade. -/

/-- Decapsulation key view: `dk = dkPKE ‖ ek ‖ H(ek) ‖ z`, length
`768·k + 96 = (384·k) + (384·k + 32) + 32 + 32`. -/
noncomputable def decapsulationKey
    (self : mlkem.key.Key) (params : ParameterSet) :
    𝔹 (768 * (k params : ℕ) + 96) :=
  (keySEncoded self params ‖ encapsulationKey self params ‖
    Aeneas.Std.Array.toSpec self.encaps_key_hash ‖
    Aeneas.Std.Array.toSpec self.private_random).cast (by grind)

/-- Dot-notation view of a runtime `Key` as its spec-level decapsulation
key: `key.toDecapKey params = decapsulationKey key params`.  Reducible, so
it is interchangeable with `decapsulationKey` in all proofs; we use the
dotted form in spec statements for readability. -/
noncomputable abbrev _root_.symcrust.mlkem.key.Key.toDecapKey
    (self : mlkem.key.Key) (params : ParameterSet) :
    𝔹 (768 * (k params : ℕ) + 96) :=
  decapsulationKey self params

/-- Helper: the spec-byte conversion of a slice of length 32 is the
byte-mapped slice list. Same shape as MLDSA's `sliceToSpecBytes_toList`,
adapted to MLKEM's `(s, n, h)` ternary signature. -/
private theorem sliceToSpecBytes_toList_bv_32
    (s : Slice U8) (h : s.length = 32) :
    (sliceToSpecBytes s 32 h).toList = (↑s : List U8).map (·.bv) := by
  unfold sliceToSpecBytes
  rw [Vector.toList_ofFn]
  apply List.ext_getElem
  · simp [h]
  · intro n h1 h2
    rw [List.getElem_ofFn, List.getElem_map]

/-- Helper: if a slice of `PolyElement` equals `List.slice 0 m (↑a)` for
some `Array PolyElement n`, and `wfPolyVec a.to_slice`, then the slice
also satisfies `wfPolyVec`.  Extracted to its own lemma so the witness
derivation runs in a small context (the call site has 100+ local
hypotheses and otherwise triggers `whnf` heartbeat timeouts — see
`aeneas-fold-decomposition` "Context size affects simp_lists/rw").

(Visibility: public — also consumed by `Decaps.lean` for the wfPolyVec
precondition derivation in `decapsulateBody.spec`.) -/
theorem wfPolyVec_of_prefix_slice
    {n : Usize} (a : Array PolyElement n)
    (pv : Slice PolyElement) (m : Nat)
    (h_pv_val : (↑pv : List PolyElement) = List.slice 0 m (↑a : List PolyElement))
    (h_pv_len : pv.length = m)
    (h_m_le : m ≤ n.val)
    (h_wf : wfPolyVec a.to_slice) :
    wfPolyVec pv := by
  intro i hi
  have h_a_len : (↑a : List PolyElement).length = n.val := a.property
  have hi_m : i < m := h_pv_len ▸ hi
  have hi_n : i < n.val := lt_of_lt_of_le hi_m h_m_le
  have hi_arr : i < (↑a : List PolyElement).length := by rw [h_a_len]; exact hi_n
  have hi_ts : i < a.to_slice.length := by rw [Array.length_to_slice]; exact hi_n
  have h_wf_i := h_wf i hi_ts
  simp only [Array.val_to_slice] at h_wf_i
  have h_at : (↑pv : List PolyElement)[i]'hi =
      (↑a : List PolyElement)[i]'hi_arr := by
    rw [List.getElem_of_eq h_pv_val hi]
    rw [List.getElem_slice 0 m i _ ⟨by rw [h_a_len]; omega, by omega⟩]
    fcongr 1; omega
  rw [h_at]; exact h_wf_i

/-! ### Two-phase decomposition of `mlkem.key_expand_from_private_seed`

The Aeneas-extracted body is ~50 monadic positions and elaborates to ~100
local hypotheses by the end of Phase 9 (post-Phase-9 = "after the second
`s_mut` / `t_mut` round-trip and the `vector_mul_r` setup").  Inlining
all phases into a single `step*` then exhausts the 8M-heartbeat budget
(Landmine #4, refreshed Tier 7.C comment below).  We split the body via
`#decompose`:

* `keyExpand.prelude` captures positions 0..46 (Phases 1-9: seed
  expansion, public-matrix expand, Shake init, CBD loops, NTT(s),
  NTT(t), `pv_tmp` window, `s_mut` for `vector_mul_r`).  Its
  `@[step]` spec exposes a 6-conjunct post (see
  `keyExpand.prelude.spec` below) that the top theorem relies on.
* Phases 10-23 (`vector_mul_r`, `ats_mut`, matrix·vector mont
  mul-and-add, transpose, `t_encoded_t_mut`, vector compress-and-encode,
  encapsulation-key hash, two wipes, terminal `ok`) stay inline in the
  top theorem.  Their cumulative `step*` cost is manageable once the
  prelude has been collapsed into a single `step` against its spec.

The fold theorem `mlkem.key_expand_from_private_seed.fold` rewrites the
function call as `do let r ← keyExpand.prelude …; <phases 10-23>`.
The parent proof becomes `rw [fold]; step* ...; agrind`. -/

set_option maxHeartbeats 4000000 in
set_option maxRecDepth 1024 in
#decompose mlkem.key_expand_from_private_seed mlkem.key_expand_from_private_seed.fold
  letRange 0 47 => keyExpand.prelude

/-! ### Layered post-state invariants for `key_expand_from_private_seed`

The main proof threads four cumulative invariants `Inv1 ⊂ Inv2 ⊂ Inv3 ⊂ Inv4`,
one for each "owner" of the mutable key:

```
pk_mlkem_key                  -- input (precondition: wfKey + has_private_seed = true)
   ↓ prelude (phases 1-9 inline + s_mut_back1)
s_mut_back1 s18               -- ⊢ Inv1
   ↓ phase 13 (mat-vec mul: t-slot ← t̂) + phase 14 (transpose: matrix ← Â^T)
     + ats_mut_back closure
x✝⁴ (a3, t2, _s)              -- ⊢ Inv2
   ↓ phase 15 (compress+encode t̂ into encoded_t) + t_encoded_t_mut_back closure
t_encoded_t_mut_back (t3, _)  -- ⊢ Inv3
   ↓ phases 17-22 (SHA3-256 over encoded_t ‖ public_seed)
pk_mlkem_key9                 -- ⊢ Inv4 = main spec post
```

The `Inv_i` are `abbrev`s — definitionally equal to their conjunction
expansion — so projections (`.1`, `.2.1`, …) are `rfl`-trivial and `simp [Inv1]`
unfolds the bundle.  Each layer **only** captures facts monotone forward
(true at state `i` and forever after); intermediate facts that get
overwritten (e.g. matrix = Â before transpose, t-slot = ê before mat-vec)
remain as auxiliary outputs of the underlying primitives and are not
threaded through the `Inv` chain. -/

/-- Post-state after the prelude (phases 1-9 + `s_mut_back1` re-injection),
re-used as a building block for `Inv2`/`Inv3`/`Inv4`.

Only the facts that remain true at the *final* state are listed (the
`Inv_i` cascade composes by `post := pk_mlkem_key_final`, so any
"preserved-from-input" claim made here must survive every subsequent
phase).  Facts about fields that LATER phases overwrite — `encoded_t`
(Phase 15) and `encaps_key_hash` (Phases 17–22) — are NOT here; they
are asserted by `Inv3` / `Inv4` in their post-Phase-X form:

* base `Inv` (wfKey + 5 immutable-identity fields: params, n_rows,
  has_private_seed, private_seed, private_random),
* `has_private_key` preserved from input (no phase modifies this field;
  callers ensure `input.has_private_key = true` before calling, but the
  spec does not require it — it just carries the value through),
* `public_seed` already in its K_PKE-byte form `slice ekPKE (384·k) 32`
  (set by Phase 1, not overwritten),
* `data.val.length = 24` (the array invariant exposed for slot indexing),
* `keySEncoded post = dkPKE` (s-slot encodes to `dkPKE`; established
  by the s-slot = ŝ fact from the prelude's `s_mut_back1` universal;
  the s-slot is not touched by phases 10–23). -/
abbrev keyExpand.Inv1 (input post : mlkem.key.Key) (params : ParameterSet) : Prop :=
  KeyInv input post params ∧
  post.has_private_key = input.has_private_key ∧
  post.public_seed.toSpec =
    slice (K_PKE.KeyGen params input.private_seed.toSpec).1
          (384 * (k params : ℕ)) 32 ∧
  post.data.val.length = 24 ∧
  keySEncoded post params = (K_PKE.KeyGen params input.private_seed.toSpec).2

/-- Post-state after phase 13 (mat-vec mul producing t̂) and phase 14
(matrix transpose producing Â^T), via the `ats_mut_back` closure.
Extends `Inv1` with the transposed-matrix fact, which is monotone forward
(no later phase writes the matrix slot). -/
abbrev keyExpand.Inv2 (input post : mlkem.key.Key) (params : ParameterSet) : Prop :=
  keyExpand.Inv1 input post params ∧
  (∀ (row col : ℕ) (_ : row < (k params : ℕ) ∧ col < (k params : ℕ)),
    toPoly (post.data[row * (k params : ℕ) + col]'(by
      have h1 : post.data.val.length = 24 := post.data.property
      have h_kpos := k_le_4 params
      have h_ksq := k_sq_plus_2k_le_24 params
      scalar_tac)) =
    MLKEM.SampleNTT
      (expandAEntrySeed
        (MLKEM.G (input.private_seed.toSpec ‖ #v[((k params : ℕ) : Byte)])).1
        col row))

/-- Post-state after phase 15 (compress+encode of t̂ into `encoded_t`), via
the `t_encoded_t_mut_back` closure.  Adds the K_PKE-byte-form encoded_t
prefix.  Phase 16 swaps `encoded_t` back via index_mut_back2 but leaves
the value unchanged. -/
abbrev keyExpand.Inv3 (input post : mlkem.key.Key) (params : ParameterSet) : Prop :=
  keyExpand.Inv2 input post params ∧
  keyEncodedTPrefix post params =
    slice (K_PKE.KeyGen params input.private_seed.toSpec).1 0
          (384 * (k params : ℕ))

/-- Post-state at the end (phases 17-22: SHA3-256 over ekPKE =
encoded_t ‖ public_seed).  Equals the main spec post.  Note:
`has_private_key` and `has_private_seed` are NOT asserted here in
`= true` form — the function never mutates `has_private_key`, and
`has_private_seed` is preserved via `KeyInv`; both flow through `Inv1`
from input.  Downstream consumers that need `= true` recover it from
the caller-side precondition `input.has_private_key = true` (callers
in `key_set_value` set this fixup at `Funs.lean:3873,4126`).

The 9th conjunct (`keyEncodedTPrefix_eq_byteEncode_keyT`) is the
**byte-form witness** consumed by `mlkem.encapsulate_internal.spec` to
discharge the c-equality residual: it pairs the runtime view `keyT
post params` (poly-vector form, read from `data[tOffset..]`) with the
runtime view `keyEncodedTPrefix post params` (byte form, read from
`encoded_t[0..384·k]`).  Combined with the
`polyVector_byteDecode_byteEncode` round-trip lemma
(`Bridges/Encoding.lean`), it lets the encaps spec's
`PolyVector.ByteDecode 12 (slice ekPKE 0 (384·k))` collapse to `keyT
post params`.  `wfKey` alone does NOT carry this — see the
`wfKey` docstring in `Bridges/KeyView.lean`. -/
abbrev keyExpand.Inv4 (input post : mlkem.key.Key) (params : ParameterSet) : Prop :=
  keyExpand.Inv3 input post params ∧
  post.encaps_key_hash.toSpec =
    Spec.SHA3.sha3_256 (K_PKE.KeyGen params input.private_seed.toSpec).1 ∧
  keyEncodedTPrefix post params =
    Vector.cast (n := (k params : ℕ) * (32 * 12)) (m := 384 * (k params : ℕ))
      (by have := polyVector_byteEncode_size_cast (n := k params) 12; omega)
      (MLKEM.PolyVector.ByteEncode 12 (keyT post params)
        ⟨by omega, by omega⟩)

/-- `keyExpand.prelude` spec — full FC postcondition covering Phases 1-9
of the key-expansion prelude.

The body witnesses the Phase 1 hash split `(ρ, σ)`, the sized
`cb_encoded_vector`, the `pv_tmp` length-k prefix view, and the
`s18` view of the post-Phase-9 s-slot in NTT form, together with the
framing equalities (`params`, `n_rows`, `private_seed`,
`private_random`, `has_private_seed`) that downstream phases rely on.

Phase reminder (the postcondition asserts the visible consequences of
these phases; intermediate state is existentially summarised):

* Phase 1 — `G(d ‖ k)`: the 64-byte hash output produced by
  SHA3-512(d ‖ #v[k.byte]) is split as `ρ = out[0..32]` and
  `σ = out[32..64]`; `ρ` is copied into `key.public_seed`.
* Phase 2 — PRF base state: ghost state `g_base` is established with
  `g_base.absorbed.map (·.bv) = σ.toList`.
* Phase 3 — `loop0` over `[0, k)`: s-slots `[sOffset, sOffset + k)` hold
  `SamplePolyCBD η₁ (PRF η₁ σ j.byte)` for `j ∈ [0, k)`.
* Phase 4 — `loop1` over `[0, k)` with `offset = k`: t-slots
  `[tOffset, tOffset + k)` hold `SamplePolyCBD η₁ (PRF η₁ σ (k + j).byte)`.
* Phase 5 — `vector_ntt` twice: s-slots become `ŝ = NTT(s)`, t-slots
  become `ê = NTT(e)`.  (These two `vector_ntt` calls are positions 39
  and 42 in the prelude.)
* Phase 6-9 (in this prelude): index_mut on `max_size_vector0` yielding
  `pv_tmp` (a `k`-prefix slice satisfying `wfPolyVec`); `s_mut` again on
  the post-`vector_ntt` key, yielding `s18` and the `s_mut_back1` closure
  for the `vector_mul_r` setup.

The prelude's output tuple — in order — is:
  `(cb_encoded_vector, private_seed_hash1, p_comp_temps1, mkhs2, mkhs4,
    cbd_sample_buffer4, pv_tmp, index_mut_back1, s18, s_mut_back1)`.

Full FC must constrain at least:
* `wfKey` (via the post of `key_expand_public_matrix_from_public_seed.spec`)
  for the key after Phase 6, and the framing equalities preserving
  `params`, `n_rows`, `private_seed`, `private_random`, `has_private_seed`.
* `public_seed = ρ` (Phase 1).
* The s/t-slot contents in `NTT` form (Phase 5).
* `wfPolyVec pv_tmp` and the slice-prefix equality
  `pv_tmp.val = List.slice 0 (k.val) p_comp_temps1.max_size_vector0` so
  that `key.s_mut` after `vector_mul_r` re-injects correctly. -/
@[step]
theorem keyExpand.prelude.spec
    (params : ParameterSet)
    (pk_mlkem_key : mlkem.key.Key)
    (p_comp_temps : mlkem.ntt.InternalComputationTemporaries)
    (h_wf : wfKey pk_mlkem_key params)
    (h_seed : pk_mlkem_key.has_private_seed = true)
    (h_pct_max0 : wfPolyVec p_comp_temps.max_size_vector0.to_slice) :
    keyExpand.prelude pk_mlkem_key p_comp_temps
      ⦃ cb_encoded_vector private_seed_hash1 _p_comp_temps1 _mkhs2 _mkhs4
        _cbd_sample_buffer4 pv_tmp _index_mut_back1 s18 s_mut_back1 =>
          /- Spec-level intermediates derived from the input key. -/
          let d : 𝔹 32 := arrayToSpecBytes pk_mlkem_key.private_seed
          let G_input : 𝔹 33 := d ‖ #v[((k params : ℕ) : Byte)]
          let ρ : 𝔹 32 := (MLKEM.G G_input).1
          let σ : 𝔹 32 := (MLKEM.G G_input).2
          /- (1) Phase 1 — `G(d ‖ k)`: the 64-byte hash output equals
             `ρ ‖ σ` (the spec-level definition of `G`). -/
          arrayToSpecBytes private_seed_hash1 = ρ ‖ σ ∧
          /- (2) cb_encoded_vector encodes the t-prefix / ek-PKE size
             `32 · 12 · k` (it is set in Phase 2 from
             `sizeof_encoded_uncompressed_vector`). -/
          cb_encoded_vector.val = 32 * 12 * (k params : ℕ) ∧
          /- (3) `pv_tmp` is the length-k prefix view of
             `max_size_vector0`, well-formed under `wfPolyVec`.
             Used by the postlude's `vector_mul_r` (Phase 10). -/
          pv_tmp.length = (k params : ℕ) ∧
          wfPolyVec pv_tmp ∧
          /- (4) `s18` is the length-k view of the post-Phase-9 key's
             s-slot, holding `ŝ = NTT(s)`.  Well-formed under
             `wfPolyVec`.  Each entry equals
             `NTT(SamplePolyCBD η₁ (PRF η₁ σ i.byte))`. -/
          (∃ (h_s18_len : s18.length = (k params : ℕ)),
            wfPolyVec s18 ∧
            (∀ (i : ℕ) (h_i : i < (k params : ℕ)),
              toPoly (s18.val[i]'(by
                have h : s18.val.length = (k params : ℕ) := h_s18_len
                omega)) =
              MLKEM.NTT (MLKEM.SamplePolyCBD
                (MLKEM.PRF (η₁ params) σ ((i : ℕ) : Byte))))) ∧
          /- (5) `_index_mut_back1` universal — re-injecting any length-k
             `wfPolyVec` slice into the borrowed prefix of
             `p_comp_temps.max_size_vector0` yields the underlying
             length-4 array whose `to_slice` is still `wfPolyVec` (the
             prefix matches the supplied `s'`, the tail is the unchanged
             tail of `max_size_vector0`).  Used by Phase 13
             (`matrix_vector_mont_mul_and_add`), which reads the
             length-`n_rows` prefix of `(_index_mut_back1 pv_tmp1).to_slice`. -/
          (∀ (s' : Slice PolyElement)
             (_h_s'_len : s'.length = (k params : ℕ))
             (_h_s'_wf : wfPolyVec s'),
            wfPolyVec (_index_mut_back1 s').to_slice ∧
            (_index_mut_back1 s').to_slice.length = 4 ∧
            (∀ (i : ℕ) (h_i : i < (k params : ℕ)),
              (_index_mut_back1 s').to_slice.val[i]'(by
                have h_eq := Aeneas.Std.Array.val_to_slice (_index_mut_back1 s')
                have h_arr_len : (_index_mut_back1 s').val.length = 4 :=
                  (_index_mut_back1 s').property
                have := k_le_4 params
                rw [h_eq, h_arr_len]; omega) =
              s'.val[i]'(by
                have h : s'.val.length = (k params : ℕ) := _h_s'_len
                omega))) ∧
          /- (6) `s_mut_back1` back-fn universal — the workhorse of the
             prelude post.  Re-injecting any length-k, polynomial-bounded
             slice `s'` into the key gives a `wfKey` whose:
              * structural / framing fields match `pk_mlkem_key` (modulo
                `public_seed` and `has_private_seed = true`);
              * `public_seed` encodes to `ρ` (Phase 1 result);
              * s-slot equals `s'`;
              * t-slot stores `ê = NTT(SamplePolyCBD η₁ (PRF η₁ σ
                (k+i).byte))` (Phase 5);
              * matrix-slot stores `Â` (untransposed — the transpose
                happens in the postlude at Phase 16). -/
          (∀ (s' : Slice PolyElement)
             (h_s'_len : s'.length = (k params : ℕ))
             (_h_s'_wf : ∀ i (_ : i < s'.length), wfPoly s'.val[i]),
            let k' := s_mut_back1 s'
            KeyInv pk_mlkem_key k' params ∧
            k'.has_private_key = pk_mlkem_key.has_private_key ∧
            k'.encoded_t = pk_mlkem_key.encoded_t ∧
            k'.encaps_key_hash = pk_mlkem_key.encaps_key_hash ∧
            arrayToSpecBytes k'.public_seed = ρ ∧
            k'.data.val.length = 24 ∧
            /- s-slot ≡ s' (the injected slice). -/
            (∀ (i : ℕ) (h_i : i < (k params : ℕ)),
              k'.data.val[sOffset params + i]'(by
                have hlen : k'.data.val.length = 24 := k'.data.property
                have := k_sq_plus_2k_le_24 params
                unfold sOffset matrixLen; grind) =
              s'.val[i]'(by
                have h : s'.val.length = (k params : ℕ) := h_s'_len
                omega)) ∧
            /- t-slot ≡ ê = NTT(SamplePolyCBD η₁ (PRF η₁ σ (k+i).byte)). -/
            (∀ (i : ℕ) (h_i : i < (k params : ℕ)),
              toPoly (k'.data.val[tOffset params + i]'(by
                have hlen : k'.data.val.length = 24 := k'.data.property
                have := k_sq_plus_2k_le_24 params
                unfold tOffset matrixLen; grind)) =
              MLKEM.NTT (MLKEM.SamplePolyCBD
                (MLKEM.PRF (η₁ params) σ
                  ((k params + i) : Byte)))) ∧
            /- matrix-slot ≡ Â (untransposed):
                 `data[row · k + col] = SampleNTT(expandAEntrySeed ρ row col)`.
               Same convention as `key_expand_public_matrix_from_public_seed.spec`. -/
            (∀ (row col : ℕ)
               (_h_row : row < (k params : ℕ))
               (_h_col : col < (k params : ℕ)),
              toPoly (k'.data.val[row * (k params : ℕ) + col]'(by
                have hlen : k'.data.val.length = 24 := k'.data.property
                have := k_sq_plus_2k_le_24 params
                have := k_le_4 params
                scalar_tac)) =
              MLKEM.SampleNTT (expandAEntrySeed ρ row col))) ⦄ := by
  --set_option maxHeartbeats 16000000 in
  --set_option maxRecDepth 2048 in
  unfold keyExpand.prelude
  have h_k_le : (k params : ℕ) ≤ 4 := k_le_4 params
  have h_nrows : pk_mlkem_key.params.n_rows.val = (k params : ℕ) := by
    have h_params := wfKey.params_ok (self := pk_mlkem_key) (p := params) h_wf
    exact wfInternalParams.n_rows_val h_params
  have h_n_eta1 : pk_mlkem_key.params.n_eta1.val = (η₁ params : ℕ) := by
    have h_params := wfKey.params_ok (self := pk_mlkem_key) (p := params) h_wf
    exact wfInternalParams.n_eta1_val h_params
  step
  step with mlkem.sizeof_encoded_uncompressed_vector.spec
    as ⟨_cb_v, h_cb_enc⟩
  step*
  have h_eta1_bv : pk_mlkem_key.params.n_eta1 = 2#u8 ∨ pk_mlkem_key.params.n_eta1 = 3#u8 := by
    have h_val : pk_mlkem_key.params.n_eta1.val = 2 ∨ pk_mlkem_key.params.n_eta1.val = 3 := by
      rw [h_n_eta1]; rcases params <;> decide
    rcases h_val with hv | hv
    · left;  apply UScalar.eq_of_val_eq; rw [hv]; decide
    · right; apply UScalar.eq_of_val_eq; rw [hv]; decide
  rcases h_eta1_bv with h_eta_eq | h_eta_eq <;> rw [h_eta_eq]
  · -- η₁ = 2 branch: massert collapses to ok ().
    simp only [↓reduceIte]
    step*
    · exact params
    · refine ⟨?_, ?_, ?_⟩
      · exact wfKey.params_ok (self := pk_mlkem_key) h_wf
      · exact wfKey.n_rows_ok (self := pk_mlkem_key) h_wf
      · exact wfKey.data_wf (self := pk_mlkem_key) h_wf
    step*
    · exact 136
    · exact 31#u8
    · rw [mkhs_post2]; decide
    · refine ⟨by decide, ?_, by decide⟩; show 8 * 136 < 1600; decide
    step*
    · exact sha3.sha3_impl.GhostState.init 136 31#u8
    · exact Or.inl mkhs1_post2
    -- Phase 3 setup.
    have hs11_eq : s11 = s12 := by rw [s11_post, s12_post]
    have hs13_len : s13.length = 32 := by
      rw [s13_post2, i7_post, hs11_eq]; scalar_tac
    have hmkhs1_no_sq : mkhs1.state.squeeze_mode = false := by
      have hab : sha3.sha3_impl.absorbing mkhs1.state
          (sha3.sha3_impl.GhostState.init 136 31#u8
            (by refine ⟨by decide, ?_, by decide⟩; show 8 * 136 < 1600; decide)) := by
        have := mkhs1_post2
        simp only [mlkem.hash.MlKemHashState.absorbing] at this
        exact this.1
      have h := hab.1.2.1
      cases hsq : mkhs1.state.squeeze_mode
      · rfl
      · rw [hsq] at h; exact absurd rfl h
    set σ : 𝔹 32 := sliceToSpecBytes s13 32 hs13_len with hσ_def
    set g_base : sha3.sha3_impl.GhostState :=
      (sha3.sha3_impl.GhostState.init 136 31#u8
        (by refine ⟨by decide, ?_, by decide⟩; show 8 * 136 < 1600; decide)).append (↑s13) false
      with hg_base_def
    have hmkhs2_abs : mkhs2.absorbing g_base := by
      have := mkhs2_post2
      rw [hmkhs1_no_sq] at this
      exact this
    have hg_base_absorbed : g_base.absorbed = ↑s13 := by
      simp [hg_base_def, sha3.sha3_impl.GhostState.append, sha3.sha3_impl.GhostState.init]
    have hσ_toList : σ.toList = (↑s13 : List U8).map (·.bv) :=
      sliceToSpecBytes_toList_bv_32 s13 hs13_len
    -- Loop entry invariant for loop0.
    have h_inv0 : cbdLoopInv params σ pk_mlkem_key1 pk_mlkem_key1 0 (sOffset params)
        (by unfold sOffset dataEnd matrixLen; grind) 0 mkhs2 g_base := by
      refine ⟨pk_mlkem_key1_post1, by omega, hmkhs2_abs, ?_, ?_, ?_, ?_,
              rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩
      · rw [hg_base_absorbed]; exact hσ_toList.symm
      · rw [mkhs2_post1, mkhs1_post1, mkhs_post2]
      · intros _ _ hj0; omega
      · intros _ _ _; rfl
    -- Phase 3: drive loop0.
    step with mlkem.key_expand_from_private_seed_loop0.spec params σ
      ⟨0#u8, pk_mlkem_key.params.n_rows⟩ pk_mlkem_key1 pk_mlkem_key1 mkhs2
      p_comp_temps1.hash_state1 cbd_sample_buffer2 2#u8 g_base h_inv0
      (by show pk_mlkem_key.params.n_rows.val = (k params : ℕ); exact h_nrows)
      (by show (0 : Nat) ≤ (k params : ℕ); omega)
      (by show (2 : Nat) = (η₁ params : ℕ); rw [← h_n_eta1, h_eta_eq]; decide)
      as ⟨pk_mlkem_key2, mkhs3, cbd_sample_buffer3, h_loop0_post⟩
    -- Loop entry invariant for loop1.
    have h_inv1 : cbdLoopInv params σ pk_mlkem_key2 pk_mlkem_key2 (k params : ℕ) (tOffset params)
        (by unfold tOffset dataEnd matrixLen; grind) 0 mkhs2 g_base := by
      refine ⟨h_loop0_post.1, by omega, h_loop0_post.2.2.1,
              h_loop0_post.2.2.2.1, h_loop0_post.2.2.2.2.1, ?_, ?_,
              rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩
      · intros _ _ hj0; omega
      · intros _ _ _; rfl
    -- Phase 4: drive loop1.
    step with mlkem.key_expand_from_private_seed_loop1.spec params σ
      ⟨0#u8, pk_mlkem_key.params.n_rows⟩ pk_mlkem_key2 pk_mlkem_key2 mkhs2 mkhs3
      cbd_sample_buffer3 pk_mlkem_key.params.n_rows 2#u8 g_base h_inv1
      (by show pk_mlkem_key.params.n_rows.val = (k params : ℕ); exact h_nrows)
      (by show (0 : Nat) ≤ (k params : ℕ); omega)
      (by show pk_mlkem_key.params.n_rows.val = (k params : ℕ); exact h_nrows)
      (by show (2 : Nat) = (η₁ params : ℕ); rw [← h_n_eta1, h_eta_eq]; decide)
      as ⟨pk_mlkem_key3, mkhs4, cbd_sample_buffer4, h_loop1_post⟩
    step with mlkem.key.Key.s_mut.spec _ params h_loop1_post.1
      as ⟨s14, s_mut_back, h_s14_len, h_s14_wf, _h_s14_eq, h_s_mut_back⟩
    step with mlkem.ntt.vector_ntt.spec s14 h_s14_wf (by
      rw [h_s14_len]; have := k_le_4 params; have := k_ge_2 params; omega)
      as ⟨s15, s15_wfvec, s15_len_eq, s15_ntt⟩
    have h_s15_len : s15.length = ↑(k params) := s15_len_eq.trans h_s14_len
    have h_s15_wf : ∀ i (_ : i < s15.length), wfPoly s15.val[i] := s15_wfvec
    have h_pk4_wf : wfKey (s_mut_back s15) params := by
      obtain ⟨⟨hwf, _, _, _, _, _⟩, _⟩ := h_s_mut_back s15 h_s15_len h_s15_wf
      exact hwf
    step with mlkem.key.Key.t_mut.spec (s_mut_back s15) params h_pk4_wf
      as ⟨t16, t_mut_back, h_t16_len, h_t16_wf, _h_t16_eq, h_t_mut_back⟩
    step with mlkem.ntt.vector_ntt.spec t16 h_t16_wf (by
      rw [h_t16_len]; have := k_le_4 params; have := k_ge_2 params; omega)
      as ⟨t17, t17_wfvec, t17_len_eq, t17_ntt⟩
    have h_t17_len : t17.length = ↑(k params) := t17_len_eq.trans h_t16_len
    have h_t17_wf : ∀ i (_ : i < t17.length), wfPoly t17.val[i] := t17_wfvec
    have h_pk5_wf : wfKey (t_mut_back t17) params := by
      obtain ⟨⟨hwf, _, _, _, _, _⟩, _⟩ := h_t_mut_back t17 h_t17_len h_t17_wf
      exact hwf
    step
    step
    step with mlkem.key.Key.s_mut.spec (t_mut_back t17) params h_pk5_wf
      as ⟨s18, s_mut_back1, h_s18_len, h_s18_wf, _h_s18_eq, h_s_mut_back1⟩
    -- Phases 1–9 done; the goal should now be the postcondition.
    -- Discharge the 5-conjunct postcondition.
    -- (2) cb_encoded_vector length is from sizeof_encoded_uncompressed_vector.spec.
    -- (3-4) pv_tmp length and wfPolyVec from index_mut + wfPolyVec_of_prefix_slice.
    have h_i8_v : (i8 : Usize).val = pk_mlkem_key.params.n_rows.val := by
      rw [i8_post]; simp
    have h_i8_le_nrows : (i8 : Usize).val ≤ pk_mlkem_key.params.n_rows.val :=
      le_of_eq h_i8_v
    have h_pvlen' : pv_tmp.length = (i8 : Usize).val := by
      rw [pv_tmp_post2]; omega
    have h_pvlen : pv_tmp.length = (k params : ℕ) := by
      rw [h_pvlen', h_i8_v, h_nrows]
    have h_pv_val : (↑pv_tmp : List PolyElement) =
        List.slice 0 (i8 : Usize).val (↑p_comp_temps.max_size_vector0 : List PolyElement) := by
      rw [pv_tmp_post1, pk_mlkem_key1_post13]
    have h_nrows_le : pk_mlkem_key.params.n_rows.val ≤ (4#usize : Usize).val := by
      show pk_mlkem_key.params.n_rows.val ≤ 4
      rw [h_nrows]; exact h_k_le
    have h_pv_tmp_wf : wfPolyVec pv_tmp :=
      wfPolyVec_of_prefix_slice p_comp_temps.max_size_vector0 pv_tmp
        (i8 : Usize).val h_pv_val h_pvlen' (le_trans h_i8_le_nrows h_nrows_le) h_pct_max0
    -- ────────────────────────────────────────────────────────────────────
    -- HOIST: build h_arr_decomp (and σ bridge) BEFORE refine so that
    -- conjunct (1) and conjunct (5) can both consume it.
    -- ────────────────────────────────────────────────────────────────────
    set B : 𝔹 33 :=
      arrayToSpecBytes pk_mlkem_key.private_seed ‖ #v[((k params : ℕ) : Byte)]
      with hB_def
    have h_arr_decomp :
        arrayToSpecBytes private_seed_hash1 = (MLKEM.G B).1 ‖ (MLKEM.G B).2 := by
      have h_priv_len : (↑pk_mlkem_key.private_seed : List U8).length = 32 := by simp
      have h_s5_len : s5.length = 32 := by
        rw [s5_post]; simp [Aeneas.Std.Slice.length, Aeneas.Std.Array.to_slice, h_priv_len]
      have h_s4_len : s4.length = 32 := by
        rw [s4_post]; simp [Aeneas.Std.Slice.length, Aeneas.Std.Array.to_slice, h_priv_len]
      have h_i4_val : (i4 : Usize).val = 33 := by
        rw [i4_post, Aeneas.Std.Slice.len_val, h_s5_len]
      have h_s4_len_val : (s4.len : Usize).val = 32 := by
        rw [Aeneas.Std.Slice.len_val, h_s4_len]
      have h_s3_val : (↑s3 : List U8) = (↑pk_mlkem_key.private_seed : List U8) := by
        rw [s3_post2, s2_post]; rfl
      have h_imb_val : (↑(index_mut_back s3) : List U8) =
          (List.replicate 193 (0#u8 : U8)).setSlice! 0 (↑pk_mlkem_key.private_seed : List U8) := by
        rw [s1_post3 s3, h_s3_val, Aeneas.Std.Array.repeat_val]
        rfl
      have h_cb2_val : (cbd_sample_buffer2 : Std.Array U8 193#usize).val =
          ((List.replicate 193 (0#u8 : U8)).setSlice! 0
            (↑pk_mlkem_key.private_seed : List U8)).set 32 pk_mlkem_key.params.n_rows := by
        rw [cbd_sample_buffer2_post, Aeneas.Std.Array.set_val_eq, h_imb_val, h_s4_len_val]
      have h_s6_val : (↑s6 : List U8) =
          (↑pk_mlkem_key.private_seed : List U8) ++ [pk_mlkem_key.params.n_rows] := by
        rw [s6_post1, h_i4_val]
        simp only [Aeneas.Std.Array.val_to_slice]
        rw [h_cb2_val]
        unfold List.slice
        rw [List.drop_zero, show (33 - 0 : ℕ) = 33 from rfl]
        apply List.ext_getElem?
        intro i
        by_cases hi33 : i < 33
        · rw [List.getElem?_take_of_lt (by omega)]
          by_cases h32 : i < 32
          · rw [List.getElem?_set_ne (by omega)]
            rw [List.getElem?_append_left (by rw [h_priv_len]; exact h32)]
            rw [List.setSlice!_getElem?_middle
              (h := by refine ⟨Nat.zero_le _, ?_, ?_⟩
                       · rw [h_priv_len]; exact h32
                       · simp; omega)]
            simp
          · push Not at h32
            have hi_eq : i = 32 := by omega
            subst hi_eq
            rw [List.getElem?_set_self]
            · rw [List.getElem?_append_right (by rw [h_priv_len])]
              simp [h_priv_len]
            · simp [List.length_setSlice!]
        · rw [List.getElem?_eq_none, List.getElem?_eq_none]
          · simp; omega
          · simp [List.length_take, List.length_set, List.length_setSlice!]
            omega
      have h_s6_len : s6.length = 33 := by
        rw [Aeneas.Std.Slice.length, h_s6_val, List.length_append, List.length_singleton]
        rw [h_priv_len]
      have h_rate_ok : 0 < 72 ∧ 8 * 72 < Spec.SHA3.b ∧ 72 % 8 = 0 := by
        refine ⟨by decide, ?_, by decide⟩
        show 8 * 72 < Spec.SHA3.b; decide
      set G : sha3.sha3_impl.GhostState :=
        (sha3.sha3_impl.GhostState.init 72 6#u8 h_rate_ok).append (↑s6) false
        with hG_def
      have h_G_absorbed : G.absorbed = (↑s6 : List U8) := by
        simp [hG_def, sha3.sha3_impl.GhostState.append, sha3.sha3_impl.GhostState.init]
      have h_G_abs_len : G.absorbed.length = 33 := by
        rw [h_G_absorbed]; exact h_s6_len
      have h_G_rate : G.rate = 72 := by
        simp [hG_def, sha3.sha3_impl.GhostState.append, sha3.sha3_impl.GhostState.init]
      have h_G_padVal : G.padVal = 6#u8 := by
        simp [hG_def, sha3.sha3_impl.GhostState.append, sha3.sha3_impl.GhostState.init]
      have h_G_squeezed : G.squeezed = [] := by
        simp [hG_def, sha3.sha3_impl.GhostState.append, sha3.sha3_impl.GhostState.init]
      have h_psh_val : (↑private_seed_hash1 : List U8) =
          (sha3.sha3_impl.extractOutput G 64).toList := by
        rw [hG_def]
        have h := private_seed_hash1_post
        unfold sha3.sha3_variants.SHA3_PADDING_VALUE at h
        exact h
      have h_per_byte : ∀ (i : Fin 33),
          B.get i = (G.absorbed[i.val]'(by rw [h_G_abs_len]; exact i.isLt)).bv := by
        intro i
        have hi_s6 : i.val < (↑s6 : List U8).length := by
          show i.val < s6.length; rw [h_s6_len]; exact i.isLt
        have h_G_eq : (G.absorbed[i.val]'(by rw [h_G_abs_len]; exact i.isLt)) =
            (↑s6 : List U8)[i.val]'hi_s6 :=
          List.getElem_of_eq h_G_absorbed _
        rw [h_G_eq]
        have h_s6_idx : (↑s6 : List U8)[i.val]'hi_s6 =
            ((↑pk_mlkem_key.private_seed : List U8) ++
              [pk_mlkem_key.params.n_rows])[i.val]'(by
                rw [List.length_append, List.length_singleton, h_priv_len]; exact i.isLt) :=
          List.getElem_of_eq h_s6_val hi_s6
        rw [h_s6_idx]
        show (arrayToSpecBytes pk_mlkem_key.private_seed ‖ #v[((k params : ℕ) : Byte)] :
              𝔹 33)[i.val]'i.isLt = _
        rw [show (arrayToSpecBytes pk_mlkem_key.private_seed ‖
              (#v[((k params : ℕ) : Byte)] : 𝔹 1) : 𝔹 33) =
              (arrayToSpecBytes pk_mlkem_key.private_seed ++
                (#v[((k params : ℕ) : Byte)] : 𝔹 1) : 𝔹 33) from rfl]
        rw [Vector.getElem_append]
        have hi32 : ((32#usize : Usize).val : ℕ) = 32 := by decide
        split_ifs with h32
        · have h32' : i.val < 32 := by rw [hi32] at h32; exact h32
          have h_idx_seed : i.val < (↑pk_mlkem_key.private_seed : List U8).length := by
            rw [h_priv_len]; exact h32'
          rw [List.getElem_append_left h_idx_seed]
          show (arrayToSpecBytes pk_mlkem_key.private_seed : 𝔹 32)[i.val]'h32' = _
          simp only [arrayToSpecBytes, Vector.getElem_ofFn]
        · have hi33 : i.val < 33 := i.isLt
          have h32' : ¬ i.val < 32 := by rw [hi32] at h32; exact h32
          have h32_ge : 32 ≤ i.val := Nat.not_lt.mp h32'
          have h_idx_eq : i.val = 32 := by omega
          have h_idx_ge : (↑pk_mlkem_key.private_seed : List U8).length ≤ i.val := by
            rw [h_priv_len]; exact h32_ge
          have h_app_idx :
              ((↑pk_mlkem_key.private_seed : List U8) ++ [pk_mlkem_key.params.n_rows])[i.val] =
                pk_mlkem_key.params.n_rows := by
            rw [List.getElem_append_right h_idx_ge]
            simp [h_priv_len, h_idx_eq]
          rw [h_app_idx]
          have h_sub : i.val - (32#usize : Usize).val = 0 := by rw [hi32, h_idx_eq]
          simp only [h_sub]
          show ((k params : ℕ) : Byte) = pk_mlkem_key.params.n_rows.bv
          apply BitVec.eq_of_toNat_eq
          simp [BitVec.toNat_ofNat]
          rw [← h_nrows]
          omega
      have h_bridge :
          arrayToSpecBytes private_seed_hash1 = Spec.SHA3.sha3_512 B :=
        arrayToSpecBytes_eq_sha3_512 private_seed_hash1 G h_psh_val B
          h_G_abs_len h_per_byte h_G_rate h_G_padVal h_G_squeezed
      rw [h_bridge]
      exact (MLKEM_G_append_eq_sha3_512 B).symm
    -- ────────────────────────────────────────────────────────────────────
    -- HOIST σ-bridge ABOVE refine so conjunct (5) can reuse it.
    -- σ = sliceToSpecBytes s13 32 ; we need σ = (G B).2 (the second half).
    -- s13 is private_seed_hash1[32..64], i.e. exactly the second half.
    -- ────────────────────────────────────────────────────────────────────
    have h_pubseed_len : (↑pk_mlkem_key1.public_seed : List U8).length = 32 := by
      have := pk_mlkem_key1.public_seed.property; simp
    have h_s11_len_lemma : s11.length = 32 := by
      rw [s11_post]; simp [Aeneas.Std.Slice.length, Aeneas.Std.Array.to_slice, h_pubseed_len]
    have h_s11_len_val : (s11.len : Usize).val = 32 := by
      rw [Aeneas.Std.Slice.len_val, h_s11_len_lemma]
    have h_i7_val_lemma : (i7 : Usize).val = 64 := by
      have hi := i7_post
      rw [hi, hs11_eq.symm, h_s11_len_val]
    have h_phs_len : (↑private_seed_hash1 : List U8).length = 64 := by
      have := private_seed_hash1.property; simp
    have h_s13_eq_drop_take : (↑s13 : List U8) =
        ((↑private_seed_hash1 : List U8).drop 32).take 32 := by
      rw [s13_post1, h_s11_len_val, h_i7_val_lemma]
      simp [List.slice, Aeneas.Std.Array.val_to_slice]
    have h_σ_eq : σ = (Spec.MLKEM.G B).2 :=
      sigma_eq_G_snd s13 private_seed_hash1 B hs13_len h_s13_eq_drop_take h_arr_decomp
    refine ⟨?_, ?_, h_pvlen, h_pv_tmp_wf, ?_, ?_, ?_⟩
    -- ────────────────────────────────────────────────────────────────────
    -- η₁ = 2 branch — refine residual map:
    --   (1) G output equality                : CLOSED via h_arr_decomp
    --   (2) cb_encoded_vector size            : CLOSED via scalar_tac
    --   (3) pv_tmp length                     : CLOSED via h_pvlen
    --   (4) wfPolyVec pv_tmp                  : CLOSED via h_pv_tmp_wf
    --   (5) s18 ∃-witness + wfPolyVec + NTT   : length & wfPolyVec CLOSED;
    --       NTT-eq forall                     : CLOSED
    --   (5') _index_mut_back1 universal       : CLOSED
    --   (6) s_mut_back1 back-fn universal     : CLOSED
    -- ────────────────────────────────────────────────────────────────────
    · -- (1) G(d ‖ k): arrayToSpecBytes private_seed_hash1 = ρ ‖ σ.
      exact h_arr_decomp
    · -- (2) cb_encoded_vector.val = 32 * 12 * (k params : ℕ).
      -- h_cb_enc : cb_encoded_vector.val = 384 * pk_mlkem_key.params.n_rows.val
      -- h_nrows  : pk_mlkem_key.params.n_rows.val = (k params : ℕ)
      have hk := h_nrows; have hc := h_cb_enc; scalar_tac
    · -- (5) s18 ∃ length witness, wfPolyVec, NTT-eq.
      refine ⟨h_s18_len, h_s18_wf, ?_⟩
      intro i h_i
      have h_t_post := h_t_mut_back t17 h_t17_len h_t17_wf
      have h_t_ex := h_t_post.2.2.2.2.2.2
      have h_t_frame := h_t_ex.choose_spec.2
      have h_s_post := h_s_mut_back s15 h_s15_len h_s15_wf
      have h_s_ex := h_s_post.2.2.2.2.2.2
      have h_s_posEq := h_s_ex.choose_spec.1
      have h_i_s14 : i < s14.length := by rw [h_s14_len]; exact h_i
      have h_kk_2k := k_sq_plus_2k_le_24 params
      have h_24 : sOffset params + i < 24 := by
        unfold sOffset matrixLen; omega
      have h_sOffset_i_lt : sOffset params + i < dataEnd params := by
        unfold sOffset dataEnd matrixLen; omega
      have h_not_tslot : ¬ (tOffset params ≤ sOffset params + i ∧
          sOffset params + i < tOffset params + (k params : ℕ)) := by
        unfold sOffset tOffset matrixLen; omega
      have h1 := _h_s18_eq i h_i
      have h2 := h_t_frame (sOffset params + i) h_24 h_not_tslot
      have h3 := h_s_posEq i h_i
      have h4 := s15_ntt i h_i_s14
      have h5 := _h_s14_eq i h_i
      have h6 := h_loop1_post.2.2.2.2.2.2.1 (sOffset params + i)
                  h_sOffset_i_lt h_not_tslot
      have h7 := (h_loop0_post.2.2.2.2.2.1 i h_i h_i).2
      -- Cast σ-eq to the unfolded form (σ := sliceToSpecBytes ... is let-bound,
      -- and cbdLoopInv was instantiated with the unfolded form in h_loop0_post).
      have h_σ_eq' : sliceToSpecBytes s13 32 hs13_len = (Spec.MLKEM.G B).2 :=
        h_σ_eq
      rw [h_σ_eq'] at h7
      simp only [Nat.zero_add] at h7
      set_option maxHeartbeats 400000 in
      rw [h1, h2, h3, h4, h5, h6, h7, hB_def]
      rfl
    · -- (5') `_index_mut_back1` universal — the array (length 4) we get by
      -- writing s' back into the borrowed prefix of `max_size_vector0` is
      -- still wfPolyVec (prefix from s', suffix from the unchanged tail),
      -- its to_slice has length 4, and the prefix indices match s'.
      intro s' h_s'_len h_s'_wf
      have h_max_eq : p_comp_temps1.max_size_vector0 = p_comp_temps.max_size_vector0 :=
        pk_mlkem_key1_post13
      have h_arr_len : (↑(index_mut_back1 s') : List PolyElement).length = 4 :=
        (index_mut_back1 s').property
      have h_orig_arr_len : (↑p_comp_temps.max_size_vector0 : List PolyElement).length = 4 :=
        p_comp_temps.max_size_vector0.property
      have h_to_slice_len : (index_mut_back1 s').to_slice.length = 4 := by
        simp only [Aeneas.Std.Array.length_to_slice]; decide
      have h_orig_ts_len : p_comp_temps.max_size_vector0.to_slice.length = 4 := by
        simp only [Aeneas.Std.Array.length_to_slice]; decide
      have h_s'_arr_len : (↑s' : List PolyElement).length = ↑(k params) := h_s'_len
      have h_imb_val : (↑(index_mut_back1 s') : List PolyElement) =
          (↑p_comp_temps.max_size_vector0 : List PolyElement).setSlice! 0 (↑s' : List PolyElement) := by
        rw [pv_tmp_post3 s', h_max_eq]
      refine ⟨?_, h_to_slice_len, ?_⟩
      · -- wfPolyVec (index_mut_back1 s').to_slice
        intro i hi
        have hi4 : i < 4 := by
          rw [Aeneas.Std.Array.length_to_slice] at hi; exact hi
        have h_orig_idx : i < (↑p_comp_temps.max_size_vector0 : List PolyElement).length :=
          h_orig_arr_len.symm ▸ hi4
        simp only [Aeneas.Std.Array.val_to_slice]
        rw [List.getElem_of_eq h_imb_val]
        by_cases h_pref : i < (↑s' : List PolyElement).length
        · -- prefix: setSlice!_middle gives s'[i - 0] = s'[i]; use h_s'_wf.
          have heq := List.getElem_setSlice!_middle
                        (↑p_comp_temps.max_size_vector0) (↑s') 0 i
                        ⟨by omega, by omega, h_orig_idx⟩
          rw [heq]
          have hi_s' : i < s'.length := h_pref
          have := h_s'_wf i hi_s'
          show wfPoly (↑s')[i - 0]
          simp only [Nat.sub_zero]; exact this
        · -- suffix: setSlice!_suffix gives max_size_vector0[i]; use h_pct_max0.
          push Not at h_pref
          have h_suf : 0 + (↑s' : List PolyElement).length ≤ i ∧
                       i < (↑p_comp_temps.max_size_vector0 : List PolyElement).length :=
            ⟨by omega, h_orig_idx⟩
          have heq : ((↑p_comp_temps.max_size_vector0 : List PolyElement).setSlice! 0
                       (↑s' : List PolyElement))[i] =
                     (↑p_comp_temps.max_size_vector0 : List PolyElement)[i] :=
            List.getElem_setSlice!_suffix _ _ 0 i h_suf
          rw [heq]
          have h_ts := h_pct_max0 i (by rw [h_orig_ts_len]; exact hi4)
          simp only [Aeneas.Std.Array.val_to_slice] at h_ts
          exact h_ts
      · -- prefix equality: (index_mut_back1 s').to_slice.val[i] = s'.val[i] for i < k params.
        intro i h_i
        have hi4 : i < 4 := lt_of_lt_of_le h_i h_k_le
        have h_pref : i < (↑s' : List PolyElement).length := by rw [h_s'_arr_len]; exact h_i
        have h_orig_idx : i < (↑p_comp_temps.max_size_vector0 : List PolyElement).length :=
          h_orig_arr_len.symm ▸ hi4
        have h_mid : 0 ≤ i ∧ i - 0 < (↑s' : List PolyElement).length ∧
                     i < (↑p_comp_temps.max_size_vector0 : List PolyElement).length :=
          ⟨by omega, by omega, h_orig_idx⟩
        simp only [Aeneas.Std.Array.val_to_slice]
        rw [List.getElem_of_eq h_imb_val]
        have heq : ((↑p_comp_temps.max_size_vector0 : List PolyElement).setSlice! 0
                     (↑s' : List PolyElement))[i] =
                   (↑s' : List PolyElement)[i - 0] :=
          List.getElem_setSlice!_middle _ _ 0 i h_mid
        rw [heq]
        simp only [Nat.sub_zero]
    · -- (6) s_mut_back1 back-fn universal — 14-conjunct ∀ over s'.
      intro s' h_s'_len h_s'_wf
      have h_back1 := h_s_mut_back1 s' h_s'_len h_s'_wf
      have h_t_post := h_t_mut_back t17 h_t17_len h_t17_wf
      have h_s_post := h_s_mut_back s15 h_s15_len h_s15_wf
      obtain ⟨⟨h_b1_wf, h_b1_params, h_b1_nrows, h_b1_hpsd, h_b1_psd, h_b1_prnd⟩,
              h_b1_ai, h_b1_hpkey, h_b1_pseed, h_b1_enct, h_b1_kh,
              h_b1_data⟩ := h_back1
      obtain ⟨⟨_h_t_wf, h_t_params, h_t_nrows, h_t_hpsd, h_t_psd, h_t_prnd⟩,
              _h_t_ai, h_t_hpkey, h_t_pseed, h_t_enct, h_t_kh,
              h_t_data⟩ := h_t_post
      obtain ⟨⟨_h_s_wf, h_s_params, h_s_nrows, h_s_hpsd, h_s_psd, h_s_prnd⟩,
              _h_s_ai, h_s_hpkey, h_s_pseed, h_s_enct, h_s_kh,
              h_s_data⟩ := h_s_post
      obtain ⟨_l1_wf, _l1_ile, _l1_abs, _l1_gabs, _l1_alg, _l1_cbd, h_l1_frame,
              h_l1_params, h_l1_nrows, h_l1_pseed, h_l1_enct, h_l1_kh,
              h_l1_hpsd, h_l1_hpkey, h_l1_psd, h_l1_prnd⟩ := h_loop1_post
      obtain ⟨_l0_wf, _l0_ile, _l0_abs, _l0_gabs, _l0_alg, _l0_cbd, h_l0_frame,
              h_l0_params, h_l0_nrows, h_l0_pseed, h_l0_enct, h_l0_kh,
              h_l0_hpsd, h_l0_hpkey, h_l0_psd, h_l0_prnd⟩ := h_loop0_post
      refine ⟨⟨h_b1_wf, ?c_params, ?c_nrows, ?c_hpsd, ?c_psd, ?c_prnd⟩,
              ?c_hpkey, ?c_enct, ?c_kh, ?c_pseed, ?c_dlen, ?c_sslot, ?c_tslot, ?c_mat⟩
      case c_params =>
        show (s_mut_back1 s').params = pk_mlkem_key.params
        rw [h_b1_params, h_t_params, h_s_params, h_l1_params, h_l0_params,
            pk_mlkem_key1_post5]
      case c_nrows =>
        rw [h_b1_nrows, h_t_nrows, h_s_nrows, h_l1_nrows, h_l0_nrows,
            pk_mlkem_key1_post6]
      case c_hpsd =>
        rw [h_b1_hpsd, h_t_hpsd, h_s_hpsd, h_l1_hpsd, h_l0_hpsd,
            pk_mlkem_key1_post11]
        exact h_seed.symm
      case c_hpkey =>
        rw [h_b1_hpkey, h_t_hpkey, h_s_hpkey, h_l1_hpkey, h_l0_hpkey,
            pk_mlkem_key1_post12]
      case c_psd =>
        rw [h_b1_psd, h_t_psd, h_s_psd, h_l1_psd, h_l0_psd,
            pk_mlkem_key1_post9]
      case c_prnd =>
        rw [h_b1_prnd, h_t_prnd, h_s_prnd, h_l1_prnd, h_l0_prnd,
            pk_mlkem_key1_post10]
      case c_enct =>
        rw [h_b1_enct, h_t_enct, h_s_enct, h_l1_enct, h_l0_enct,
            pk_mlkem_key1_post7]
      case c_kh =>
        rw [h_b1_kh, h_t_kh, h_s_kh, h_l1_kh, h_l0_kh,
            pk_mlkem_key1_post8]
      case c_pseed =>
        -- Chain back-fn pseed equalities to to_slice_mut_back s10, then apply ρ-bridge.
        rw [h_b1_pseed, h_t_pseed, h_s_pseed, h_l1_pseed, h_l0_pseed,
            pk_mlkem_key1_post2, s8_post2]
        -- Goal: arrayToSpecBytes (pk_mlkem_key.public_seed.from_slice s10) = (G B).1
        have hs10_len : s10.length = 32 := by
          have h1 : s10.length = s8.length := s10_post1
          have h2 : s8.length = (↑s8 : List U8).length := rfl
          have h3 : (↑s8 : List U8).length = (↑pk_mlkem_key.public_seed : List U8).length := by
            rw [s8_post1]
          have h4 : (↑pk_mlkem_key.public_seed : List U8).length = 32 :=
            pk_mlkem_key.public_seed.property
          omega
        have h_s10_eq_take : (↑s10 : List U8) =
            ((↑private_seed_hash1 : List U8)).take 32 := by
          rw [s10_post2, s9_post1, Aeneas.Std.Array.val_to_slice]
          have h_s7_len : (↑s7.len : ℕ) = 32 := by
            rw [s7_post]; simp
          rw [show (↑s7.len : ℕ) = 32 from h_s7_len]
          unfold List.slice
          simp [List.drop_zero]
        exact rho_eq_G_fst s10 private_seed_hash1 pk_mlkem_key.public_seed B
          hs10_len h_s10_eq_take h_arr_decomp
      case c_dlen =>
        exact h_b1_data.choose
      case c_sslot =>
        exact h_b1_data.choose_spec.1
      case c_tslot =>
        intro i h_i
        have h_i_t16 : i < t16.length := by rw [h_t16_len]; exact h_i
        have h_kk_2k := k_sq_plus_2k_le_24 params
        have h_24 : tOffset params + i < 24 := by
          unfold tOffset matrixLen; omega
        have h_tOffset_i_lt : tOffset params + i < dataEnd params := by
          unfold tOffset dataEnd matrixLen; omega
        have h_not_sslot : ¬ (sOffset params ≤ tOffset params + i ∧
            tOffset params + i < sOffset params + (k params : ℕ)) := by
          unfold sOffset tOffset matrixLen; omega
        have h1 := h_b1_data.choose_spec.2 (tOffset params + i) h_24 h_not_sslot
        have h2 := h_t_data.choose_spec.1 i h_i
        have h3 := t17_ntt i h_i_t16
        have h4 := _h_t16_eq i h_i
        have h5 := h_s_data.choose_spec.2 (tOffset params + i) h_24 h_not_sslot
        have h6 := (_l1_cbd i h_i h_i).2
        have h_σ_eq' : sliceToSpecBytes s13 32 hs13_len = (Spec.MLKEM.G B).2 :=
          h_σ_eq
        rw [h_σ_eq'] at h6
        -- Single-step rewrites combined with a final `rfl` are much
        -- cheaper than a chained `rw [h1,…,h6,hB_def]`: each step's
        -- LHS is a literal subterm of the running goal, so `rw` does
        -- one cheap match instead of re-elaborating the back-fn closure
        -- `(s_mut_back1 s').data` between every step.
        rw [h1]
        rw [h2]
        rw [h3]
        rw [h4]
        rw [h5]
        rw [h6]
        rw [hB_def]
        -- Goal: PRF byte mismatch  ↑(↑(k params) + i)  vs  ↑↑(k params) + ↑i
        push_cast
        rfl
      case c_mat =>
        intro row col h_row h_col
        have h_kk_2k := k_sq_plus_2k_le_24 params
        have h_rk_lt : row * (k params : ℕ) + col < (k params : ℕ) * (k params : ℕ) := by
          calc row * (k params : ℕ) + col
              < row * (k params : ℕ) + (k params : ℕ) := by omega
            _ = (row + 1) * (k params : ℕ) := by ring
            _ ≤ (k params : ℕ) * (k params : ℕ) := by
                apply Nat.mul_le_mul_right; omega
        have h_idx_24 : row * (k params : ℕ) + col < 24 := by omega
        have h_idx_dataEnd : row * (k params : ℕ) + col < dataEnd params := by
          unfold dataEnd matrixLen; omega
        have h_not_sslot : ¬ (sOffset params ≤ row * (k params : ℕ) + col ∧
            row * (k params : ℕ) + col < sOffset params + (k params : ℕ)) := by
          unfold sOffset matrixLen; omega
        have h_not_tslot : ¬ (tOffset params ≤ row * (k params : ℕ) + col ∧
            row * (k params : ℕ) + col < tOffset params + (k params : ℕ)) := by
          unfold tOffset matrixLen; omega
        have h1 := h_b1_data.choose_spec.2 (row * (k params : ℕ) + col) h_idx_24 h_not_sslot
        have h2 := h_t_data.choose_spec.2 (row * (k params : ℕ) + col) h_idx_24 h_not_tslot
        have h3 := h_s_data.choose_spec.2 (row * (k params : ℕ) + col) h_idx_24 h_not_sslot
        have h4 := h_l1_frame (row * (k params : ℕ) + col) h_idx_dataEnd h_not_tslot
        have h5 := h_l0_frame (row * (k params : ℕ) + col) h_idx_dataEnd h_not_sslot
        have h6 := pk_mlkem_key1_post3 row col h_row h_col
        -- ρ witness chain (mirrors c_pseed).
        have hs10_len : s10.length = 32 := by
          have h1 : s10.length = s8.length := s10_post1
          have h2 : s8.length = (↑s8 : List U8).length := rfl
          have h3 : (↑s8 : List U8).length = (↑pk_mlkem_key.public_seed : List U8).length := by
            rw [s8_post1]
          have h4 : (↑pk_mlkem_key.public_seed : List U8).length = 32 :=
            pk_mlkem_key.public_seed.property
          omega
        have h_s10_eq_take : (↑s10 : List U8) =
            ((↑private_seed_hash1 : List U8)).take 32 := by
          rw [s10_post2, s9_post1, Aeneas.Std.Array.val_to_slice]
          have h_s7_len : (↑s7.len : ℕ) = 32 := by
            rw [s7_post]; simp
          rw [show (↑s7.len : ℕ) = 32 from h_s7_len]
          unfold List.slice
          simp [List.drop_zero]
        have h_ρ : arrayToSpecBytes (pk_mlkem_key.public_seed.from_slice s10)
            = (Spec.MLKEM.G B).1 :=
          rho_eq_G_fst s10 private_seed_hash1 pk_mlkem_key.public_seed B
            hs10_len h_s10_eq_take h_arr_decomp
        -- Pre-unfold B in h_ρ so the closing rewrite matches the goal RHS verbatim.
        rw [hB_def] at h_ρ
        -- Same trick as c_tslot: one rewrite at a time keeps each step cheap.
        rw [h1]
        rw [h2]
        rw [h3]
        rw [h4]
        rw [h5]
        rw [h6]
        rw [s8_post2]
        rw [h_ρ]
        rfl
  · -- ════════════════════════════════════════════════════════════════════
    -- η₁ = 3 branch — mirror of η₁=2 (mechanical duplication, 2#u8↔3#u8).
    -- ════════════════════════════════════════════════════════════════════
    rw [if_neg (by decide)]
    step*
    · exact params
    · refine ⟨?_, ?_, ?_⟩
      · exact wfKey.params_ok (self := pk_mlkem_key) h_wf
      · exact wfKey.n_rows_ok (self := pk_mlkem_key) h_wf
      · exact wfKey.data_wf (self := pk_mlkem_key) h_wf
    step*
    · exact 136
    · exact 31#u8
    · rw [mkhs_post2]; decide
    · refine ⟨by decide, ?_, by decide⟩; show 8 * 136 < 1600; decide
    step*
    · exact sha3.sha3_impl.GhostState.init 136 31#u8
    · exact Or.inl mkhs1_post2
    have hs11_eq : s11 = s12 := by rw [s11_post, s12_post]
    have hs13_len : s13.length = 32 := by
      rw [s13_post2, i7_post, hs11_eq]; scalar_tac
    have hmkhs1_no_sq : mkhs1.state.squeeze_mode = false := by
      have hab : sha3.sha3_impl.absorbing mkhs1.state
          (sha3.sha3_impl.GhostState.init 136 31#u8
            (by refine ⟨by decide, ?_, by decide⟩; show 8 * 136 < 1600; decide)) := by
        have := mkhs1_post2
        simp only [mlkem.hash.MlKemHashState.absorbing] at this
        exact this.1
      have h := hab.1.2.1
      cases hsq : mkhs1.state.squeeze_mode
      · rfl
      · rw [hsq] at h; exact absurd rfl h
    set σ : 𝔹 32 := sliceToSpecBytes s13 32 hs13_len with hσ_def
    set g_base : sha3.sha3_impl.GhostState :=
      (sha3.sha3_impl.GhostState.init 136 31#u8
        (by refine ⟨by decide, ?_, by decide⟩; show 8 * 136 < 1600; decide)).append (↑s13) false
      with hg_base_def
    have hmkhs2_abs : mkhs2.absorbing g_base := by
      have := mkhs2_post2
      rw [hmkhs1_no_sq] at this
      exact this
    have hg_base_absorbed : g_base.absorbed = ↑s13 := by
      simp [hg_base_def, sha3.sha3_impl.GhostState.append, sha3.sha3_impl.GhostState.init]
    have hσ_toList : σ.toList = (↑s13 : List U8).map (·.bv) :=
      sliceToSpecBytes_toList_bv_32 s13 hs13_len
    have h_inv0 : cbdLoopInv params σ pk_mlkem_key1 pk_mlkem_key1 0 (sOffset params)
        (by unfold sOffset dataEnd matrixLen; grind) 0 mkhs2 g_base := by
      refine ⟨pk_mlkem_key1_post1, by omega, hmkhs2_abs, ?_, ?_, ?_, ?_,
              rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩
      · rw [hg_base_absorbed]; exact hσ_toList.symm
      · rw [mkhs2_post1, mkhs1_post1, mkhs_post2]
      · intros _ _ hj0; omega
      · intros _ _ _; rfl
    step with mlkem.key_expand_from_private_seed_loop0.spec params σ
      ⟨0#u8, pk_mlkem_key.params.n_rows⟩ pk_mlkem_key1 pk_mlkem_key1 mkhs2
      p_comp_temps1.hash_state1 cbd_sample_buffer2 3#u8 g_base h_inv0
      (by show pk_mlkem_key.params.n_rows.val = (k params : ℕ); exact h_nrows)
      (by show (0 : Nat) ≤ (k params : ℕ); omega)
      (by show (3 : Nat) = (η₁ params : ℕ); rw [← h_n_eta1, h_eta_eq]; decide)
      as ⟨pk_mlkem_key2, mkhs3, cbd_sample_buffer3, h_loop0_post⟩
    have h_inv1 : cbdLoopInv params σ pk_mlkem_key2 pk_mlkem_key2 (k params : ℕ) (tOffset params)
        (by unfold tOffset dataEnd matrixLen; grind) 0 mkhs2 g_base := by
      refine ⟨h_loop0_post.1, by omega, h_loop0_post.2.2.1,
              h_loop0_post.2.2.2.1, h_loop0_post.2.2.2.2.1, ?_, ?_,
              rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩
      · intros _ _ hj0; omega
      · intros _ _ _; rfl
    step with mlkem.key_expand_from_private_seed_loop1.spec params σ
      ⟨0#u8, pk_mlkem_key.params.n_rows⟩ pk_mlkem_key2 pk_mlkem_key2 mkhs2 mkhs3
      cbd_sample_buffer3 pk_mlkem_key.params.n_rows 3#u8 g_base h_inv1
      (by show pk_mlkem_key.params.n_rows.val = (k params : ℕ); exact h_nrows)
      (by show (0 : Nat) ≤ (k params : ℕ); omega)
      (by show pk_mlkem_key.params.n_rows.val = (k params : ℕ); exact h_nrows)
      (by show (3 : Nat) = (η₁ params : ℕ); rw [← h_n_eta1, h_eta_eq]; decide)
      as ⟨pk_mlkem_key3, mkhs4, cbd_sample_buffer4, h_loop1_post⟩
    step with mlkem.key.Key.s_mut.spec _ params h_loop1_post.1
      as ⟨s14, s_mut_back, h_s14_len, h_s14_wf, _h_s14_eq, h_s_mut_back⟩
    step with mlkem.ntt.vector_ntt.spec s14 h_s14_wf (by
      rw [h_s14_len]; have := k_le_4 params; have := k_ge_2 params; omega)
      as ⟨s15, s15_wfvec, s15_len_eq, s15_ntt⟩
    have h_s15_len : s15.length = ↑(k params) := s15_len_eq.trans h_s14_len
    have h_s15_wf : ∀ i (_ : i < s15.length), wfPoly s15.val[i] := s15_wfvec
    have h_pk4_wf : wfKey (s_mut_back s15) params := by
      obtain ⟨⟨hwf, _, _, _, _, _⟩, _⟩ := h_s_mut_back s15 h_s15_len h_s15_wf
      exact hwf
    step with mlkem.key.Key.t_mut.spec (s_mut_back s15) params h_pk4_wf
      as ⟨t16, t_mut_back, h_t16_len, h_t16_wf, _h_t16_eq, h_t_mut_back⟩
    step with mlkem.ntt.vector_ntt.spec t16 h_t16_wf (by
      rw [h_t16_len]; have := k_le_4 params; have := k_ge_2 params; omega)
      as ⟨t17, t17_wfvec, t17_len_eq, t17_ntt⟩
    have h_t17_len : t17.length = ↑(k params) := t17_len_eq.trans h_t16_len
    have h_t17_wf : ∀ i (_ : i < t17.length), wfPoly t17.val[i] := t17_wfvec
    have h_pk5_wf : wfKey (t_mut_back t17) params := by
      obtain ⟨⟨hwf, _, _, _, _, _⟩, _⟩ := h_t_mut_back t17 h_t17_len h_t17_wf
      exact hwf
    step
    step
    step with mlkem.key.Key.s_mut.spec (t_mut_back t17) params h_pk5_wf
      as ⟨s18, s_mut_back1, h_s18_len, h_s18_wf, _h_s18_eq, h_s_mut_back1⟩
    -- Post-chain bookkeeping (mirror of η₁=2 branch L1410-1426).
    have h_i8_v : (i8 : Usize).val = pk_mlkem_key.params.n_rows.val := by
      rw [i8_post]; simp
    have h_i8_le_nrows : (i8 : Usize).val ≤ pk_mlkem_key.params.n_rows.val :=
      le_of_eq h_i8_v
    have h_pvlen' : pv_tmp.length = (i8 : Usize).val := by
      rw [pv_tmp_post2]; omega
    have h_pvlen : pv_tmp.length = (k params : ℕ) := by
      rw [h_pvlen', h_i8_v, h_nrows]
    have h_pv_val : (↑pv_tmp : List PolyElement) =
        List.slice 0 (i8 : Usize).val (↑p_comp_temps.max_size_vector0 : List PolyElement) := by
      rw [pv_tmp_post1, pk_mlkem_key1_post13]
    have h_nrows_le : pk_mlkem_key.params.n_rows.val ≤ (4#usize : Usize).val := by
      show pk_mlkem_key.params.n_rows.val ≤ 4
      rw [h_nrows]; exact h_k_le
    have h_pv_tmp_wf : wfPolyVec pv_tmp :=
      wfPolyVec_of_prefix_slice p_comp_temps.max_size_vector0 pv_tmp
        (i8 : Usize).val h_pv_val h_pvlen' (le_trans h_i8_le_nrows h_nrows_le) h_pct_max0
    -- ────────────────────────────────────────────────────────────────────
    -- HOIST (mirror of η₁=2 L1547-1707): build B, h_arr_decomp, h_σ_eq
    -- BEFORE refine so that conjuncts (1) and (5) can both consume them.
    -- ────────────────────────────────────────────────────────────────────
    set B : 𝔹 33 :=
      arrayToSpecBytes pk_mlkem_key.private_seed ‖ #v[((k params : ℕ) : Byte)]
      with hB_def
    have h_arr_decomp :
        arrayToSpecBytes private_seed_hash1 = (MLKEM.G B).1 ‖ (MLKEM.G B).2 := by
      have h_priv_len : (↑pk_mlkem_key.private_seed : List U8).length = 32 := by
        simp [pk_mlkem_key.private_seed.property]
      have h_s5_len : s5.length = 32 := by
        rw [s5_post]; simp [Aeneas.Std.Slice.length, Aeneas.Std.Array.to_slice, h_priv_len]
      have h_s4_len : s4.length = 32 := by
        rw [s4_post]; simp [Aeneas.Std.Slice.length, Aeneas.Std.Array.to_slice, h_priv_len]
      have h_i4_val : (i4 : Usize).val = 33 := by
        rw [i4_post, Aeneas.Std.Slice.len_val, h_s5_len]
      have h_s4_len_val : (s4.len : Usize).val = 32 := by
        rw [Aeneas.Std.Slice.len_val, h_s4_len]
      have h_s3_val : (↑s3 : List U8) = (↑pk_mlkem_key.private_seed : List U8) := by
        rw [s3_post2, s2_post]; rfl
      have h_imb_val : (↑(index_mut_back s3) : List U8) =
          (List.replicate 193 (0#u8 : U8)).setSlice! 0 (↑pk_mlkem_key.private_seed : List U8) := by
        rw [s1_post3 s3, h_s3_val, Aeneas.Std.Array.repeat_val]
        rfl
      have h_cb2_val : (cbd_sample_buffer2 : Std.Array U8 193#usize).val =
          ((List.replicate 193 (0#u8 : U8)).setSlice! 0
            (↑pk_mlkem_key.private_seed : List U8)).set 32 pk_mlkem_key.params.n_rows := by
        rw [cbd_sample_buffer2_post, Aeneas.Std.Array.set_val_eq, h_imb_val, h_s4_len_val]
      have h_s6_val : (↑s6 : List U8) =
          (↑pk_mlkem_key.private_seed : List U8) ++ [pk_mlkem_key.params.n_rows] := by
        rw [s6_post1, h_i4_val]
        simp only [Aeneas.Std.Array.val_to_slice]
        rw [h_cb2_val]
        unfold List.slice
        rw [List.drop_zero, show (33 - 0 : ℕ) = 33 from rfl]
        apply List.ext_getElem?
        intro i
        by_cases hi33 : i < 33
        · rw [List.getElem?_take_of_lt (by omega)]
          by_cases h32 : i < 32
          · rw [List.getElem?_set_ne (by omega)]
            rw [List.getElem?_append_left (by rw [h_priv_len]; exact h32)]
            rw [List.setSlice!_getElem?_middle
              (h := by refine ⟨Nat.zero_le _, ?_, ?_⟩
                       · rw [h_priv_len]; exact h32
                       · simp; omega)]
            simp
          · push Not at h32
            have hi_eq : i = 32 := by omega
            subst hi_eq
            rw [List.getElem?_set_self]
            · rw [List.getElem?_append_right (by rw [h_priv_len])]
              simp [h_priv_len]
            · simp [List.length_setSlice!]
        · rw [List.getElem?_eq_none, List.getElem?_eq_none]
          · simp; omega
          · simp [List.length_take, List.length_set, List.length_setSlice!]
            omega
      have h_s6_len : s6.length = 33 := by
        rw [Aeneas.Std.Slice.length, h_s6_val, List.length_append, List.length_singleton]
        rw [h_priv_len]
      have h_rate_ok : 0 < 72 ∧ 8 * 72 < Spec.SHA3.b ∧ 72 % 8 = 0 := by
        refine ⟨by decide, ?_, by decide⟩
        show 8 * 72 < Spec.SHA3.b; decide
      set G : sha3.sha3_impl.GhostState :=
        (sha3.sha3_impl.GhostState.init 72 6#u8 h_rate_ok).append (↑s6) false
        with hG_def
      have h_G_absorbed : G.absorbed = (↑s6 : List U8) := by
        simp [hG_def, sha3.sha3_impl.GhostState.append, sha3.sha3_impl.GhostState.init]
      have h_G_abs_len : G.absorbed.length = 33 := by
        rw [h_G_absorbed]; exact h_s6_len
      have h_G_rate : G.rate = 72 := by
        simp [hG_def, sha3.sha3_impl.GhostState.append, sha3.sha3_impl.GhostState.init]
      have h_G_padVal : G.padVal = 6#u8 := by
        simp [hG_def, sha3.sha3_impl.GhostState.append, sha3.sha3_impl.GhostState.init]
      have h_G_squeezed : G.squeezed = [] := by
        simp [hG_def, sha3.sha3_impl.GhostState.append, sha3.sha3_impl.GhostState.init]
      have h_psh_val : (↑private_seed_hash1 : List U8) =
          (sha3.sha3_impl.extractOutput G 64).toList := by
        rw [hG_def]
        have h := private_seed_hash1_post
        unfold sha3.sha3_variants.SHA3_PADDING_VALUE at h
        exact h
      have h_per_byte : ∀ (i : Fin 33),
          B.get i = (G.absorbed[i.val]'(by rw [h_G_abs_len]; exact i.isLt)).bv := by
        intro i
        have hi_s6 : i.val < (↑s6 : List U8).length := by
          show i.val < s6.length; rw [h_s6_len]; exact i.isLt
        have h_G_eq : (G.absorbed[i.val]'(by rw [h_G_abs_len]; exact i.isLt)) =
            (↑s6 : List U8)[i.val]'hi_s6 :=
          List.getElem_of_eq h_G_absorbed _
        rw [h_G_eq]
        have h_s6_idx : (↑s6 : List U8)[i.val]'hi_s6 =
            ((↑pk_mlkem_key.private_seed : List U8) ++
              [pk_mlkem_key.params.n_rows])[i.val]'(by
                rw [List.length_append, List.length_singleton, h_priv_len]; exact i.isLt) :=
          List.getElem_of_eq h_s6_val hi_s6
        rw [h_s6_idx]
        show (arrayToSpecBytes pk_mlkem_key.private_seed ‖ #v[((k params : ℕ) : Byte)] :
              𝔹 33)[i.val]'i.isLt = _
        rw [show (arrayToSpecBytes pk_mlkem_key.private_seed ‖
              (#v[((k params : ℕ) : Byte)] : 𝔹 1) : 𝔹 33) =
              (arrayToSpecBytes pk_mlkem_key.private_seed ++
                (#v[((k params : ℕ) : Byte)] : 𝔹 1) : 𝔹 33) from rfl]
        rw [Vector.getElem_append]
        have hi32 : ((32#usize : Usize).val : ℕ) = 32 := by decide
        split_ifs with h32
        · have h32' : i.val < 32 := by rw [hi32] at h32; exact h32
          have h_idx_seed : i.val < (↑pk_mlkem_key.private_seed : List U8).length := by
            rw [h_priv_len]; exact h32'
          rw [List.getElem_append_left h_idx_seed]
          show (arrayToSpecBytes pk_mlkem_key.private_seed : 𝔹 32)[i.val]'h32' = _
          simp only [arrayToSpecBytes, Vector.getElem_ofFn]
        · have hi33 : i.val < 33 := i.isLt
          have h32' : ¬ i.val < 32 := by rw [hi32] at h32; exact h32
          have h32_ge : 32 ≤ i.val := Nat.not_lt.mp h32'
          have h_idx_eq : i.val = 32 := by omega
          have h_idx_ge : (↑pk_mlkem_key.private_seed : List U8).length ≤ i.val := by
            rw [h_priv_len]; exact h32_ge
          have h_app_idx :
              ((↑pk_mlkem_key.private_seed : List U8) ++ [pk_mlkem_key.params.n_rows])[i.val] =
                pk_mlkem_key.params.n_rows := by
            rw [List.getElem_append_right h_idx_ge]
            simp [h_priv_len, h_idx_eq]
          rw [h_app_idx]
          have h_sub : i.val - (32#usize : Usize).val = 0 := by rw [hi32, h_idx_eq]
          simp only [h_sub]
          show ((k params : ℕ) : Byte) = pk_mlkem_key.params.n_rows.bv
          apply BitVec.eq_of_toNat_eq
          simp [BitVec.toNat_ofNat]
          rw [← h_nrows]
          omega
      have h_bridge :
          arrayToSpecBytes private_seed_hash1 = Spec.SHA3.sha3_512 B :=
        arrayToSpecBytes_eq_sha3_512 private_seed_hash1 G h_psh_val B
          h_G_abs_len h_per_byte h_G_rate h_G_padVal h_G_squeezed
      rw [h_bridge]
      exact (MLKEM_G_append_eq_sha3_512 B).symm
    -- HOIST σ-bridge (mirror of η₁=2 L1687-1707).
    have h_pubseed_len : (↑pk_mlkem_key1.public_seed : List U8).length = 32 := by
      simp [pk_mlkem_key1.public_seed.property]
    have h_s11_len_lemma : s11.length = 32 := by
      rw [s11_post]; simp [Aeneas.Std.Slice.length, Aeneas.Std.Array.to_slice, h_pubseed_len]
    have h_s11_len_val : (s11.len : Usize).val = 32 := by
      rw [Aeneas.Std.Slice.len_val, h_s11_len_lemma]
    have h_i7_val_lemma : (i7 : Usize).val = 64 := by
      have hi := i7_post
      rw [hi, hs11_eq.symm, h_s11_len_val]
    have h_phs_len : (↑private_seed_hash1 : List U8).length = 64 := by
      simp [private_seed_hash1.property]
    have h_s13_eq_drop_take : (↑s13 : List U8) =
        ((↑private_seed_hash1 : List U8).drop 32).take 32 := by
      rw [s13_post1, h_s11_len_val, h_i7_val_lemma]
      simp [List.slice, Aeneas.Std.Array.val_to_slice]
    have h_σ_eq : σ = (Spec.MLKEM.G B).2 :=
      sigma_eq_G_snd s13 private_seed_hash1 B hs13_len h_s13_eq_drop_take h_arr_decomp
    refine ⟨?_, ?_, h_pvlen, h_pv_tmp_wf, ?_, ?_, ?_⟩
    · -- (1) G(d ‖ k) — CLOSED via h_arr_decomp.
      exact h_arr_decomp
    · -- (2) cb_encoded_vector size — CLOSED via scalar_tac.
      have hk := h_nrows; have hc := h_cb_enc; scalar_tac
    · -- (5) s18 ∃-witness — length & wfPolyVec CLOSED; NTT-eq CLOSED.
      refine ⟨h_s18_len, h_s18_wf, ?_⟩
      intro i h_i
      have h_t_post := h_t_mut_back t17 h_t17_len h_t17_wf
      have h_t_ex := h_t_post.2.2.2.2.2.2
      have h_t_frame := h_t_ex.choose_spec.2
      have h_s_post := h_s_mut_back s15 h_s15_len h_s15_wf
      have h_s_ex := h_s_post.2.2.2.2.2.2
      have h_s_posEq := h_s_ex.choose_spec.1
      have h_i_s14 : i < s14.length := by rw [h_s14_len]; exact h_i
      have h_kk_2k := k_sq_plus_2k_le_24 params
      have h_24 : sOffset params + i < 24 := by
        unfold sOffset matrixLen; omega
      have h_sOffset_i_lt : sOffset params + i < dataEnd params := by
        unfold sOffset dataEnd matrixLen; omega
      have h_not_tslot : ¬ (tOffset params ≤ sOffset params + i ∧
          sOffset params + i < tOffset params + (k params : ℕ)) := by
        unfold sOffset tOffset matrixLen; omega
      have h1 := _h_s18_eq i h_i
      have h2 := h_t_frame (sOffset params + i) h_24 h_not_tslot
      have h3 := h_s_posEq i h_i
      have h4 := s15_ntt i h_i_s14
      have h5 := _h_s14_eq i h_i
      have h6 := h_loop1_post.2.2.2.2.2.2.1 (sOffset params + i)
                  h_sOffset_i_lt h_not_tslot
      have h7 := (h_loop0_post.2.2.2.2.2.1 i h_i h_i).2
      have h_σ_eq' : sliceToSpecBytes s13 32 hs13_len = (Spec.MLKEM.G B).2 :=
        h_σ_eq
      rw [h_σ_eq'] at h7
      simp only [Nat.zero_add] at h7
      set_option maxHeartbeats 400000 in
      rw [h1, h2, h3, h4, h5, h6, h7, hB_def]
      rfl
    · -- (5') `_index_mut_back1` universal (η₁=3 mirror of η₁=2 L1934-2001).
      intro s' h_s'_len h_s'_wf
      have h_max_eq : p_comp_temps1.max_size_vector0 = p_comp_temps.max_size_vector0 :=
        pk_mlkem_key1_post13
      have h_arr_len : (↑(index_mut_back1 s') : List PolyElement).length = 4 :=
        (index_mut_back1 s').property
      have h_orig_arr_len : (↑p_comp_temps.max_size_vector0 : List PolyElement).length = 4 :=
        p_comp_temps.max_size_vector0.property
      have h_to_slice_len : (index_mut_back1 s').to_slice.length = 4 := by
        simp only [Aeneas.Std.Array.length_to_slice]; decide
      have h_orig_ts_len : p_comp_temps.max_size_vector0.to_slice.length = 4 := by
        simp only [Aeneas.Std.Array.length_to_slice]; decide
      have h_s'_arr_len : (↑s' : List PolyElement).length = ↑(k params) := h_s'_len
      have h_imb_val : (↑(index_mut_back1 s') : List PolyElement) =
          (↑p_comp_temps.max_size_vector0 : List PolyElement).setSlice! 0 (↑s' : List PolyElement) := by
        rw [pv_tmp_post3 s', h_max_eq]
      refine ⟨?_, h_to_slice_len, ?_⟩
      · -- wfPolyVec (index_mut_back1 s').to_slice
        intro i hi
        have hi4 : i < 4 := by
          rw [Aeneas.Std.Array.length_to_slice] at hi; exact hi
        have h_orig_idx : i < (↑p_comp_temps.max_size_vector0 : List PolyElement).length :=
          h_orig_arr_len.symm ▸ hi4
        simp only [Aeneas.Std.Array.val_to_slice]
        rw [List.getElem_of_eq h_imb_val]
        by_cases h_pref : i < (↑s' : List PolyElement).length
        · have heq := List.getElem_setSlice!_middle
                        (↑p_comp_temps.max_size_vector0) (↑s') 0 i
                        ⟨by omega, by omega, h_orig_idx⟩
          rw [heq]
          have hi_s' : i < s'.length := h_pref
          have := h_s'_wf i hi_s'
          show wfPoly (↑s')[i - 0]
          simp only [Nat.sub_zero]; exact this
        · push Not at h_pref
          have h_suf : 0 + (↑s' : List PolyElement).length ≤ i ∧
                       i < (↑p_comp_temps.max_size_vector0 : List PolyElement).length :=
            ⟨by omega, h_orig_idx⟩
          have heq : ((↑p_comp_temps.max_size_vector0 : List PolyElement).setSlice! 0
                       (↑s' : List PolyElement))[i] =
                     (↑p_comp_temps.max_size_vector0 : List PolyElement)[i] :=
            List.getElem_setSlice!_suffix _ _ 0 i h_suf
          rw [heq]
          have h_ts := h_pct_max0 i (by rw [h_orig_ts_len]; exact hi4)
          simp only [Aeneas.Std.Array.val_to_slice] at h_ts
          exact h_ts
      · intro i h_i
        have hi4 : i < 4 := lt_of_lt_of_le h_i h_k_le
        have h_pref : i < (↑s' : List PolyElement).length := by rw [h_s'_arr_len]; exact h_i
        have h_orig_idx : i < (↑p_comp_temps.max_size_vector0 : List PolyElement).length :=
          h_orig_arr_len.symm ▸ hi4
        have h_mid : 0 ≤ i ∧ i - 0 < (↑s' : List PolyElement).length ∧
                     i < (↑p_comp_temps.max_size_vector0 : List PolyElement).length :=
          ⟨by omega, by omega, h_orig_idx⟩
        simp only [Aeneas.Std.Array.val_to_slice]
        rw [List.getElem_of_eq h_imb_val]
        have heq : ((↑p_comp_temps.max_size_vector0 : List PolyElement).setSlice! 0
                     (↑s' : List PolyElement))[i] =
                   (↑s' : List PolyElement)[i - 0] :=
          List.getElem_setSlice!_middle _ _ 0 i h_mid
        rw [heq]
        simp only [Nat.sub_zero]
    · -- (6) s_mut_back1 back-fn universal (η₁=3 mirror of η₁=2).
      intro s' h_s'_len h_s'_wf
      have h_back1 := h_s_mut_back1 s' h_s'_len h_s'_wf
      have h_t_post := h_t_mut_back t17 h_t17_len h_t17_wf
      have h_s_post := h_s_mut_back s15 h_s15_len h_s15_wf
      obtain ⟨⟨h_b1_wf, h_b1_params, h_b1_nrows, h_b1_hpsd, h_b1_psd, h_b1_prnd⟩,
              h_b1_ai, h_b1_hpkey, h_b1_pseed, h_b1_enct, h_b1_kh,
              h_b1_data⟩ := h_back1
      obtain ⟨⟨_h_t_wf, h_t_params, h_t_nrows, h_t_hpsd, h_t_psd, h_t_prnd⟩,
              _h_t_ai, h_t_hpkey, h_t_pseed, h_t_enct, h_t_kh,
              h_t_data⟩ := h_t_post
      obtain ⟨⟨_h_s_wf, h_s_params, h_s_nrows, h_s_hpsd, h_s_psd, h_s_prnd⟩,
              _h_s_ai, h_s_hpkey, h_s_pseed, h_s_enct, h_s_kh,
              h_s_data⟩ := h_s_post
      obtain ⟨_l1_wf, _l1_ile, _l1_abs, _l1_gabs, _l1_alg, _l1_cbd, h_l1_frame,
              h_l1_params, h_l1_nrows, h_l1_pseed, h_l1_enct, h_l1_kh,
              h_l1_hpsd, h_l1_hpkey, h_l1_psd, h_l1_prnd⟩ := h_loop1_post
      obtain ⟨_l0_wf, _l0_ile, _l0_abs, _l0_gabs, _l0_alg, _l0_cbd, h_l0_frame,
              h_l0_params, h_l0_nrows, h_l0_pseed, h_l0_enct, h_l0_kh,
              h_l0_hpsd, h_l0_hpkey, h_l0_psd, h_l0_prnd⟩ := h_loop0_post
      refine ⟨⟨h_b1_wf, ?c_params, ?c_nrows, ?c_hpsd, ?c_psd, ?c_prnd⟩,
              ?c_hpkey, ?c_enct, ?c_kh, ?c_pseed, ?c_dlen, ?c_sslot, ?c_tslot, ?c_mat⟩
      case c_params =>
        show (s_mut_back1 s').params = pk_mlkem_key.params
        rw [h_b1_params, h_t_params, h_s_params, h_l1_params, h_l0_params,
            pk_mlkem_key1_post5]
      case c_nrows =>
        rw [h_b1_nrows, h_t_nrows, h_s_nrows, h_l1_nrows, h_l0_nrows,
            pk_mlkem_key1_post6]
      case c_hpsd =>
        rw [h_b1_hpsd, h_t_hpsd, h_s_hpsd, h_l1_hpsd, h_l0_hpsd,
            pk_mlkem_key1_post11]
        exact h_seed.symm
      case c_hpkey =>
        rw [h_b1_hpkey, h_t_hpkey, h_s_hpkey, h_l1_hpkey, h_l0_hpkey,
            pk_mlkem_key1_post12]
      case c_psd =>
        rw [h_b1_psd, h_t_psd, h_s_psd, h_l1_psd, h_l0_psd,
            pk_mlkem_key1_post9]
      case c_prnd =>
        rw [h_b1_prnd, h_t_prnd, h_s_prnd, h_l1_prnd, h_l0_prnd,
            pk_mlkem_key1_post10]
      case c_enct =>
        rw [h_b1_enct, h_t_enct, h_s_enct, h_l1_enct, h_l0_enct,
            pk_mlkem_key1_post7]
      case c_kh =>
        rw [h_b1_kh, h_t_kh, h_s_kh, h_l1_kh, h_l0_kh,
            pk_mlkem_key1_post8]
      case c_pseed =>
        rw [h_b1_pseed, h_t_pseed, h_s_pseed, h_l1_pseed, h_l0_pseed,
            pk_mlkem_key1_post2, s8_post2]
        have hs10_len : s10.length = 32 := by
          have h1 : s10.length = s8.length := s10_post1
          have h2 : s8.length = (↑s8 : List U8).length := rfl
          have h3 : (↑s8 : List U8).length = (↑pk_mlkem_key.public_seed : List U8).length := by
            rw [s8_post1]
          have h4 : (↑pk_mlkem_key.public_seed : List U8).length = 32 :=
            pk_mlkem_key.public_seed.property
          omega
        have h_s10_eq_take : (↑s10 : List U8) =
            ((↑private_seed_hash1 : List U8)).take 32 := by
          rw [s10_post2, s9_post1, Aeneas.Std.Array.val_to_slice]
          have h_s7_len : (↑s7.len : ℕ) = 32 := by
            rw [s7_post]; simp
          rw [show (↑s7.len : ℕ) = 32 from h_s7_len]
          unfold List.slice
          simp [List.drop_zero]
        exact rho_eq_G_fst s10 private_seed_hash1 pk_mlkem_key.public_seed B
          hs10_len h_s10_eq_take h_arr_decomp
      case c_dlen =>
        exact h_b1_data.choose
      case c_sslot =>
        exact h_b1_data.choose_spec.1
      case c_tslot =>
        intro i h_i
        have h_i_t16 : i < t16.length := by rw [h_t16_len]; exact h_i
        have h_kk_2k := k_sq_plus_2k_le_24 params
        have h_24 : tOffset params + i < 24 := by
          unfold tOffset matrixLen; omega
        have h_tOffset_i_lt : tOffset params + i < dataEnd params := by
          unfold tOffset dataEnd matrixLen; omega
        have h_not_sslot : ¬ (sOffset params ≤ tOffset params + i ∧
            tOffset params + i < sOffset params + (k params : ℕ)) := by
          unfold sOffset tOffset matrixLen; omega
        have h1 := h_b1_data.choose_spec.2 (tOffset params + i) h_24 h_not_sslot
        have h2 := h_t_data.choose_spec.1 i h_i
        have h3 := t17_ntt i h_i_t16
        have h4 := _h_t16_eq i h_i
        have h5 := h_s_data.choose_spec.2 (tOffset params + i) h_24 h_not_sslot
        have h6 := (_l1_cbd i h_i h_i).2
        have h_σ_eq' : sliceToSpecBytes s13 32 hs13_len = (Spec.MLKEM.G B).2 :=
          h_σ_eq
        rw [h_σ_eq'] at h6
        rw [h1]
        rw [h2]
        rw [h3]
        rw [h4]
        rw [h5]
        rw [h6]
        rw [hB_def]
        push_cast
        rfl
      case c_mat =>
        intro row col h_row h_col
        have h_kk_2k := k_sq_plus_2k_le_24 params
        have h_rk_lt : row * (k params : ℕ) + col < (k params : ℕ) * (k params : ℕ) := by
          calc row * (k params : ℕ) + col
              < row * (k params : ℕ) + (k params : ℕ) := by omega
            _ = (row + 1) * (k params : ℕ) := by ring
            _ ≤ (k params : ℕ) * (k params : ℕ) := by
                apply Nat.mul_le_mul_right; omega
        have h_idx_24 : row * (k params : ℕ) + col < 24 := by omega
        have h_idx_dataEnd : row * (k params : ℕ) + col < dataEnd params := by
          unfold dataEnd matrixLen; omega
        have h_not_sslot : ¬ (sOffset params ≤ row * (k params : ℕ) + col ∧
            row * (k params : ℕ) + col < sOffset params + (k params : ℕ)) := by
          unfold sOffset matrixLen; omega
        have h_not_tslot : ¬ (tOffset params ≤ row * (k params : ℕ) + col ∧
            row * (k params : ℕ) + col < tOffset params + (k params : ℕ)) := by
          unfold tOffset matrixLen; omega
        have h1 := h_b1_data.choose_spec.2 (row * (k params : ℕ) + col) h_idx_24 h_not_sslot
        have h2 := h_t_data.choose_spec.2 (row * (k params : ℕ) + col) h_idx_24 h_not_tslot
        have h3 := h_s_data.choose_spec.2 (row * (k params : ℕ) + col) h_idx_24 h_not_sslot
        have h4 := h_l1_frame (row * (k params : ℕ) + col) h_idx_dataEnd h_not_tslot
        have h5 := h_l0_frame (row * (k params : ℕ) + col) h_idx_dataEnd h_not_sslot
        have h6 := pk_mlkem_key1_post3 row col h_row h_col
        have hs10_len : s10.length = 32 := by
          have h1 : s10.length = s8.length := s10_post1
          have h2 : s8.length = (↑s8 : List U8).length := rfl
          have h3 : (↑s8 : List U8).length = (↑pk_mlkem_key.public_seed : List U8).length := by
            rw [s8_post1]
          have h4 : (↑pk_mlkem_key.public_seed : List U8).length = 32 :=
            pk_mlkem_key.public_seed.property
          omega
        have h_s10_eq_take : (↑s10 : List U8) =
            ((↑private_seed_hash1 : List U8)).take 32 := by
          rw [s10_post2, s9_post1, Aeneas.Std.Array.val_to_slice]
          have h_s7_len : (↑s7.len : ℕ) = 32 := by
            rw [s7_post]; simp
          rw [show (↑s7.len : ℕ) = 32 from h_s7_len]
          unfold List.slice
          simp [List.drop_zero]
        have h_ρ : arrayToSpecBytes (pk_mlkem_key.public_seed.from_slice s10)
            = (Spec.MLKEM.G B).1 :=
          rho_eq_G_fst s10 private_seed_hash1 pk_mlkem_key.public_seed B
            hs10_len h_s10_eq_take h_arr_decomp
        rw [hB_def] at h_ρ
        rw [h1]
        rw [h2]
        rw [h3]
        rw [h4]
        rw [h5]
        rw [h6]
        rw [s8_post2]
        rw [h_ρ]
        rfl


end Symcrust.Properties.MLKEM
