/-
  # Bridges/KeyView.lean — `Key`-record well-formedness + spec views.

  ## Data layout

  The Rust `Key` stores everything in one fixed-size record.  The
  polynomial data lives in a flat buffer `data : Array (Array U16 256)
  24` with logical slots (where `k = n_rows = 2|3|4`):

      data[0 .. k²)           ← A^T (matrix, k × k polynomials)
      data[k² .. k² + k)      ← t   (encapsulation vector, k polynomials)
      data[k² + k .. k² + 2k) ← s   (decapsulation vector, k polynomials)

  Unused trailing slots up to index 24 are scratch (not part of the
  invariant).  All polynomial slots store their coefficients in `U16`
  with values `< q = 3329`.

  ## Form conventions

  * `Â^T` is in **standard** NTT form (`expand_matrix` samples uniformly
    in `Zq` already in NTT domain).
  * `t̂` is in **standard** NTT form (computed in NTT domain and never
    converted back).
  * `ŝ` is in **Montgomery** NTT form (`key_compute_key_from_decoded`
    applies `poly_mul_r` after the NTT so subsequent `mont_mul`s
    cancel).

  These are the conventions used by all `@[step]` postconditions in
  this file and by every downstream caller.  If `key_compute_*` proofs
  reveal a different convention for a particular slot, the bridge
  `keyAHat` / `keyT` / `keyS` can be flipped between `toPoly` and
  `toMontPoly` without changing the `@[step]` interface — only the
  affected `key_compute_*` postcondition needs to follow.

  ## API

  * **`wfKey self p`** (structure) — runtime well-formedness predicate.
  * **`keyAHat self p`**, **`keyT self p`**, **`keyS self p`** — spec views
    (out-of-range indices fall back to the zero polynomial; `wfKey`
    rules this out at every real use site).
  * **`@[step]` specs** for `Key.matrix_len`, `Key.a_transpose`,
    `Key.t`, `Key.s`, and their `_mut` variants.  The `_mut` variants
    are framing-only step specs (they do not connect outputs to views).
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.MontArith

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust

namespace Symcrust.Properties.MLKEM.Bridges

open Symcrust.Properties.MLKEM

set_option maxHeartbeats 400000

/-! ## Offsets into `key.data`

These reduce to closed-form numbers when `p` is concrete; declaring
them `@[reducible]` lets `simp`/`scalar_tac` peek through. -/

@[reducible] def matrixLen (p : ParameterSet) : ℕ := (k p : ℕ) * (k p : ℕ)
@[reducible] def tOffset    (p : ParameterSet) : ℕ := matrixLen p
@[reducible] def sOffset    (p : ParameterSet) : ℕ := matrixLen p + (k p : ℕ)
@[reducible] def dataEnd    (p : ParameterSet) : ℕ := matrixLen p + 2 * (k p : ℕ)

/-! ## `wfKey`: runtime invariants of `mlkem.key.Key`

Layout-only invariant; spec-level correspondence (e.g. `keyT = NTT t̂`)
is established by the `@[step]` specs of `key_compute_*` functions,
not by `wfKey` itself. -/

structure wfKey (self : mlkem.key.Key) (p : ParameterSet) : Prop where
  /-- The cached params struct is the canonical entry for `p`. -/
  params_ok : wfInternalParams self.params p
  /-- `n_rows.val = k p`, redundant with `params_ok` but useful as a
  direct hypothesis at indexing sites. -/
  n_rows_ok : self.n_rows.val = (k p : ℕ)
  /-- Every used `data` slot stores a coefficient-bounded polynomial. -/
  data_wf  : ∀ i (h_end : i < dataEnd p),
             wfPoly (self.data.val[i]'(by
               have h1 : self.data.val.length = 24 := self.data.property
               have := k_sq_plus_2k_le_24 p
               unfold dataEnd matrixLen at h_end
               grind))

/-! ## `Key.Inv`: "valid evolution" of a key

`Inv self other p` packages the invariants every keygen back-fn promises
about its returned key relative to its input — `wfKey` on the result,
and the equalities on the five **immutable-identity** fields that no
keygen step ever touches (`params`, `n_rows`, `has_private_seed`,
`private_seed`, `private_random`).

Use it in back-fn postconditions in place of the six-conjunct litany.
`Inv.trans` composes framing chains in one step; `.params` / `.n_rows`
etc. project out individual equalities.

Note that `has_private_key` is intentionally **NOT** included — keygen
*sets* it to `true` at the end of the flow, so it is not preserved
across the whole pipeline.  Specs for back-fns that genuinely preserve
it (every back-fn except the final write) should add it as an extra
conjunct. -/

structure KeyInv
    (self other : mlkem.key.Key) (p : ParameterSet) : Prop where
  wf               : wfKey other p
  params           : other.params           = self.params
  n_rows           : other.n_rows           = self.n_rows
  has_private_seed : other.has_private_seed = self.has_private_seed
  private_seed     : other.private_seed     = self.private_seed
  private_random   : other.private_random   = self.private_random

namespace KeyInv

/-- Reflexivity (given the key is well-formed). -/
theorem refl {self : mlkem.key.Key} {p : ParameterSet} (h : wfKey self p) :
    KeyInv self self p :=
  ⟨h, rfl, rfl, rfl, rfl, rfl⟩

/-- Transitivity — composes framing chains in a single step. -/
theorem trans {a b c : mlkem.key.Key} {p : ParameterSet}
    (h₁ : KeyInv a b p) (h₂ : KeyInv b c p) : KeyInv a c p := by
  obtain ⟨wf₂, hp₂, hn₂, hpsd₂, hps₂, hpr₂⟩ := h₂
  obtain ⟨_, hp₁, hn₁, hpsd₁, hps₁, hpr₁⟩ := h₁
  exact ⟨wf₂, hp₂.trans hp₁, hn₂.trans hn₁,
         hpsd₂.trans hpsd₁, hps₂.trans hps₁, hpr₂.trans hpr₁⟩

end KeyInv

/-! ## Spec views

Each view derives the index-bound proof from `self.data : Array _ 24#usize`
(so `data.val.length = 24`) together with `k_sq_plus_2k_le_24 p`. -/

variable {self : mlkem.key.Key} {p : ParameterSet}

/-- Spec view of the `Â^T` matrix slot.  Each entry is in standard NTT
form. -/
def keyAHat (self : mlkem.key.Key) (p : ParameterSet) :
    Fin (k p) → Fin (k p) → Polynomial q :=
  fun i j =>
    toPoly (self.data.val[(i : ℕ) * (k p : ℕ) + (j : ℕ)]'(by
      have h1 : self.data.val.length = 24 := self.data.property
      have hi := i.isLt; have hj := j.isLt
      have h_le := k_le_4 p
      have : ((i : ℕ) + 1) * (k p : ℕ) ≤ (k p : ℕ) * (k p : ℕ) :=
        Nat.mul_le_mul_right _ hi
      have := k_sq_plus_2k_le_24 p
      grind))

/-- Spec view of the `t` encapsulation vector slot.  Standard NTT form. -/
def keyT (self : mlkem.key.Key) (p : ParameterSet) : PolyVector q (k p) :=
  Vector.ofFn fun (i : Fin (k p)) =>
    toPoly (self.data.val[tOffset p + (i : ℕ)]'(by
      have h1 : self.data.val.length = 24 := self.data.property
      have hi := i.isLt
      have := k_sq_plus_2k_le_24 p
      unfold tOffset matrixLen
      grind))

/-- Spec view of the `s` decapsulation vector slot.  Montgomery NTT form. -/
def keyS (self : mlkem.key.Key) (p : ParameterSet) : PolyVector q (k p) :=
  Vector.ofFn fun (i : Fin (k p)) =>
    toMontPoly (self.data.val[sOffset p + (i : ℕ)]'(by
      have h1 : self.data.val.length = 24 := self.data.property
      have hi := i.isLt
      have := k_sq_plus_2k_le_24 p
      unfold sOffset matrixLen
      grind))

/-! ## `@[step]` specs for the read-only accessors -/

/-- `Key.matrix_len` returns `n_rows²`, which under `wfKey` is `(k p)²`. -/
@[step]
theorem mlkem.key.Key.matrix_len.spec
    (self : mlkem.key.Key) (p : ParameterSet) (_h : wfKey self p) :
    mlkem.key.Key.matrix_len self
      ⦃ (res : Usize) => res.val = matrixLen p ⦄ := by
  /- Informal proof.
     `matrix_len self = self.n_rows * self.n_rows`.  From
     `_h.n_rows_ok : self.n_rows.val = k p`, the product is `(k p)²`.
     No overflow because `k p ≤ 4`, so `(k p)² ≤ 16 ≤ Usize.max`.
     Close with `unfold; step; scalar_tac` (using `k_le_4 p` and
     `_h.n_rows_ok` in scope). -/
  unfold mlkem.key.Key.matrix_len
  obtain ⟨_, hn, _⟩ := _h
  have hk := k_le_4 p
  step
  simp only [matrixLen, res_post, hn]

/-- `Key.a_transpose` returns a slice of length `(k p)²` whose polys
correspond to `Â^T` in standard NTT form. -/
@[step]
theorem mlkem.key.Key.a_transpose.spec
    (self : mlkem.key.Key) (p : ParameterSet) (_h : wfKey self p) :
    mlkem.key.Key.a_transpose self
      ⦃ (s : Slice (PolyElement)) =>
        ∃ (h_len : s.length = matrixLen p),
        (∀ i (_ : i < s.length), wfPoly s.val[i]) ∧
        (∀ (i j : Fin (k p)),
          toPoly (s.val[(i : ℕ) * (k p : ℕ) + (j : ℕ)]'(by
            have hi := i.isLt; have hj := j.isLt
            have : ((i : ℕ) + 1) * (k p : ℕ) ≤ (k p : ℕ) * (k p : ℕ) :=
              Nat.mul_le_mul_right _ hi
            have h_s : s.val.length = matrixLen p := h_len
            unfold matrixLen at h_s
            grind))
            = keyAHat self p i j) ⦄ := by
  /- Informal proof.
     1. `matrix_len self = ok ((k p)²)` by `matrix_len.spec`.
     2. `core.array.Array.index` with `{start := 0, end := (k p)²}`
        returns `self.data.val[0 .. (k p)²]`.  Length: `(k p)²`.
     3. Each element of the slice is `self.data.val[i]` for `i < (k p)²`,
        all `< dataEnd p`, hence `wfPoly` by `_h.data_wf`.
     4. The conversion equation follows from unfolding `keyAHat` and
        `getElem?_getD` (the slice view of `data` agrees pointwise).
     Close with `step*?` then `agrind`. -/
  unfold mlkem.key.Key.a_transpose
  have hwf := _h
  obtain ⟨params_ok, hn_rows, data_wf⟩ := _h
  have hk := k_le_4 p
  have hk2 := k_sq_plus_2k_le_24 p
  have hdlen : self.data.val.length = 24 := self.data.property
  step with mlkem.key.Key.matrix_len.spec self p hwf
  step
  · show (m_len : ℕ) ≤ self.data.to_slice.length
    have hl : self.data.to_slice.length = 24 := by simp [Std.Array.to_slice, Slice.length]
    rw [hl, m_len_post]; unfold matrixLen; scalar_tac
  refine ⟨?_, ?_, ?_⟩
  · show _ = matrixLen p; scalar_tac
  · intro j hj
    have hsval : s.val = self.data.val.slice 0 (matrixLen p) := by
      simp_all [matrixLen]
    have hslen : s.length = matrixLen p := by show _ = matrixLen p; scalar_tac
    have hjlen : j < matrixLen p := by rw [hslen] at hj; exact hj
    have hbound2 : j < self.data.val.length := by
      rw [hdlen]; have : matrixLen p ≤ 24 := by unfold matrixLen; grind
      omega
    have hidx : s.val[j]'hj = self.data.val[j]'hbound2 := by
      have e := List.getElem_slice 0 (matrixLen p) j self.data.val
                  ⟨by rw [hdlen]; unfold matrixLen; grind, by omega⟩
      have hj' : j < (self.data.val.slice 0 (matrixLen p)).length := by
        rw [← hsval]; exact hj
      have heq1 : s.val[j]'hj = (self.data.val.slice 0 (matrixLen p))[j]'hj' := by
        simp [hsval]
      rw [heq1]
      have : self.data.val[0 + j]'(by omega) = self.data.val[j]'hbound2 := by
        fcongr 1; omega
      rw [← this]; exact e
    rw [hidx]
    apply data_wf
    unfold dataEnd matrixLen; grind
  · intro i j
    have hi := i.isLt
    have hj := j.isLt
    have hsval : s.val = self.data.val.slice 0 (matrixLen p) := by
      simp_all [matrixLen]
    have hslen : s.length = matrixLen p := by show _ = matrixLen p; scalar_tac
    have hibound : (i : ℕ) * (k p : ℕ) + (j : ℕ) < matrixLen p := by
      unfold matrixLen
      have : ((i : ℕ) + 1) * (k p : ℕ) ≤ (k p : ℕ) * (k p : ℕ) :=
        Nat.mul_le_mul_right _ hi
      grind
    have hbound2 : (i : ℕ) * (k p : ℕ) + (j : ℕ) < self.data.val.length := by
      rw [hdlen]; have : matrixLen p ≤ 24 := by unfold matrixLen; grind
      omega
    have hjs : (i : ℕ) * (k p : ℕ) + (j : ℕ) < s.val.length := by
      show _ < s.length; rw [hslen]; exact hibound
    have hidx : s.val[(i : ℕ) * (k p : ℕ) + (j : ℕ)]'hjs =
        self.data.val[(i : ℕ) * (k p : ℕ) + (j : ℕ)]'hbound2 := by
      have e := List.getElem_slice 0 (matrixLen p) ((i : ℕ) * (k p : ℕ) + (j : ℕ)) self.data.val
                  ⟨by rw [hdlen]; unfold matrixLen; grind, by omega⟩
      have hj' : (i : ℕ) * (k p : ℕ) + (j : ℕ) <
          (self.data.val.slice 0 (matrixLen p)).length := by
        rw [← hsval]; exact hjs
      have heq1 : s.val[(i : ℕ) * (k p : ℕ) + (j : ℕ)]'hjs =
          (self.data.val.slice 0 (matrixLen p))[(i : ℕ) * (k p : ℕ) + (j : ℕ)]'hj' := by
        simp [hsval]
      rw [heq1]
      have : self.data.val[0 + ((i : ℕ) * (k p : ℕ) + (j : ℕ))]'(by omega) =
             self.data.val[(i : ℕ) * (k p : ℕ) + (j : ℕ)]'hbound2 := by
        fcongr 1; omega
      rw [← this]; exact e
    rw [hidx]
    unfold keyAHat
    rfl

/-- `Key.t` returns a slice of length `k p` whose polys are `t̂` in
standard NTT form. -/
@[step]
theorem mlkem.key.Key.t.spec
    (self : mlkem.key.Key) (p : ParameterSet) (_h : wfKey self p) :
    mlkem.key.Key.t self
      ⦃ (s : Slice (PolyElement)) =>
        ∃ (h_len : s.length = (k p : ℕ)),
        (∀ i (_ : i < s.length), wfPoly s.val[i]) ∧
        (∀ (i : Fin (k p)),
          toPoly (s.val[(i : ℕ)]'(by
            have hi := i.isLt
            grind)) = (keyT self p)[i]) ⦄ := by
  /- Informal proof.
     1. `matrix_len self = ok ((k p)²)`.
     2. `m_len + self.n_rows = (k p)² + k p` (no overflow, ≤ 20).
     3. Slice `data[(k p)² .. (k p)² + k p]` has length `k p`.
     4. `wfPoly` on each element from `_h.data_wf` with indices in
        `[matrixLen p, sOffset p)`, all `< dataEnd p`.
     5. Pointwise equation: unfold `keyT` and `getElem?_getD`.
     Close with `step*?; agrind`. -/
  unfold mlkem.key.Key.t
  have hwf := _h
  obtain ⟨params_ok, hn_rows, data_wf⟩ := _h
  have hk := k_le_4 p
  have hk2 := k_sq_plus_2k_le_24 p
  have hdlen : self.data.val.length = 24 := self.data.property
  step with mlkem.key.Key.matrix_len.spec self p hwf
  step
  step
  · show (i : ℕ) ≤ self.data.to_slice.length
    have hl : self.data.to_slice.length = 24 := by simp [Std.Array.to_slice, Slice.length]
    rw [hl, i_post, m_len_post]; unfold matrixLen; scalar_tac
  refine ⟨?_, ?_, ?_⟩
  · show _ = (k p : ℕ); scalar_tac
  · intro j hj
    have hsval : s.val = self.data.val.slice (matrixLen p) (sOffset p) := by
      simp_all [matrixLen, sOffset]
    have hslen : s.length = (k p : ℕ) := by show _ = (k p : ℕ); scalar_tac
    have hjlen : j < (k p : ℕ) := by rw [hslen] at hj; exact hj
    have hbound : matrixLen p + j < sOffset p := by
      unfold sOffset matrixLen; grind
    have hbound2 : matrixLen p + j < self.data.val.length := by
      rw [hdlen]; have : sOffset p ≤ 24 := by unfold sOffset matrixLen; grind
      omega
    have hidx : s.val[j]'hj = self.data.val[matrixLen p + j]'hbound2 := by
      have e := List.getElem_slice (matrixLen p) (sOffset p) j self.data.val
                  ⟨by rw [hdlen]; unfold sOffset matrixLen; grind, hbound⟩
      have hj' : j < (self.data.val.slice (matrixLen p) (sOffset p)).length := by
        rw [← hsval]; exact hj
      have : s.val[j]'hj = (self.data.val.slice (matrixLen p) (sOffset p))[j]'hj' := by
        simp [hsval]
      rw [this]; exact e
    rw [hidx]
    apply data_wf
    unfold dataEnd matrixLen; grind
  · intro i
    have hi := i.isLt
    have hsval : s.val = self.data.val.slice (matrixLen p) (sOffset p) := by
      simp_all [matrixLen, sOffset]
    have hslen : s.length = (k p : ℕ) := by show _ = (k p : ℕ); scalar_tac
    have hibound : (i : ℕ) < (k p : ℕ) := hi
    have hbound : matrixLen p + (i : ℕ) < sOffset p := by
      unfold sOffset matrixLen; grind
    have hbound2 : matrixLen p + (i : ℕ) < self.data.val.length := by
      rw [hdlen]; have : sOffset p ≤ 24 := by unfold sOffset matrixLen; grind
      omega
    have hjs : (i : ℕ) < s.val.length := by
      show (i : ℕ) < s.length; rw [hslen]; exact hibound
    have hidx : s.val[(i : ℕ)]'hjs =
        self.data.val[matrixLen p + (i : ℕ)]'hbound2 := by
      have e := List.getElem_slice (matrixLen p) (sOffset p) (i : ℕ) self.data.val
                  ⟨by rw [hdlen]; unfold sOffset matrixLen; grind, hbound⟩
      have hj' : (i : ℕ) < (self.data.val.slice (matrixLen p) (sOffset p)).length := by
        rw [← hsval]; exact hjs
      have : s.val[(i : ℕ)]'hjs = (self.data.val.slice (matrixLen p) (sOffset p))[(i : ℕ)]'hj' := by
        simp [hsval]
      rw [this]; exact e
    have htOffset : tOffset p = matrixLen p := rfl
    have hkeyT : (keyT self p)[i] = toPoly ((↑self.data : List _)[matrixLen p + (i : ℕ)]'hbound2) := by
      unfold keyT
      simp only [htOffset]
      simp
    rw [hkeyT, hidx]

/-- `Key.s` returns a slice of length `k p` whose polys are `ŝ` in
Montgomery NTT form. -/
@[step]
theorem mlkem.key.Key.s.spec
    (self : mlkem.key.Key) (p : ParameterSet) (_h : wfKey self p) :
    mlkem.key.Key.s self
      ⦃ (s : Slice (PolyElement)) =>
        ∃ (h_len : s.length = (k p : ℕ)),
        (∀ i (_ : i < s.length), wfPoly s.val[i]) ∧
        (∀ (i : Fin (k p)),
          toMontPoly (s.val[(i : ℕ)]'(by
            have hi := i.isLt
            grind)) = (keyS self p)[i]) ⦄ := by
  /- Informal proof.
     Template: leaf step-spec with sequential array-index lookups.
     Structurally identical to `t.spec`, but ranging over slots
     `[sOffset p, dataEnd p)` and exporting `toMontPoly` (because the
     `s` portion of `key.data` is stored in Montgomery NTT form per
     `wfKey`'s data layout).
     1. `step with mlkem.key.Key.matrix_len.spec`: `matrix_len self = ok ((k p)²)`.
     2. `step with Usize.add.spec` to form `m_len + self.n_rows = (k p)² + k p
        = sOffset p` (no overflow, ≤ 20 by `k_sq_plus_2k_le_24`).
     3. `step with Usize.add.spec` again for the right endpoint
        `sOffset p + (k p) = dataEnd p`.
     4. `step with core.array.Array.index` over
        `{start := sOffset p, end := dataEnd p}` of length 24:
        returns the slice `data[sOffset p .. dataEnd p]` of length `k p`.
     5. Pointwise: each element of this slice is
        `self.data.val[sOffset p + i]` for `i < k p`.  All indices are
        `< dataEnd p`, hence `wfPoly` by `_h.data_wf`.
     6. The `toMontPoly` equation follows by unfolding `keyS` and
        `getElem?_getD`: the slice view of `data` at offset
        `sOffset p + i` is exactly the `keyS` definition.

     Case analysis: none — straight-line wrapper.

     Close with `step*?` and `agrind`; the arithmetic side conditions
     on offsets reduce via `unfold sOffset matrixLen dataEnd` plus
     `k_sq_plus_2k_le_24 p` and `k_le_4 p`. -/
  unfold mlkem.key.Key.s
  have hwf := _h
  obtain ⟨params_ok, hn_rows, data_wf⟩ := _h
  have hk := k_le_4 p
  have hk2 := k_sq_plus_2k_le_24 p
  have hdlen : self.data.val.length = 24 := self.data.property
  step with mlkem.key.Key.matrix_len.spec self p hwf
  step
  step
  step
  step
  · show (i2 : ℕ) ≤ self.data.to_slice.length
    have hl : self.data.to_slice.length = 24 := by simp [Std.Array.to_slice, Slice.length]
    rw [hl, i2_post, i1_post, m_len_post]; unfold matrixLen; scalar_tac
  refine ⟨?_, ?_, ?_⟩
  · show _ = (k p : ℕ); scalar_tac
  · intro j hj
    have hsval : s.val = self.data.val.slice (sOffset p) (dataEnd p) := by
      simp_all [matrixLen, sOffset, dataEnd]
    have hslen : s.length = (k p : ℕ) := by show _ = (k p : ℕ); scalar_tac
    have hjlen : j < (k p : ℕ) := by rw [hslen] at hj; exact hj
    have hbound : sOffset p + j < dataEnd p := by
      unfold sOffset matrixLen dataEnd; grind
    have hbound2 : sOffset p + j < self.data.val.length := by
      rw [hdlen]; have : dataEnd p ≤ 24 := by unfold dataEnd matrixLen; grind
      omega
    have hidx : s.val[j]'hj = self.data.val[sOffset p + j]'hbound2 := by
      have e := List.getElem_slice (sOffset p) (dataEnd p) j self.data.val
                  ⟨by rw [hdlen]; unfold dataEnd matrixLen; grind, hbound⟩
      have hj' : j < (self.data.val.slice (sOffset p) (dataEnd p)).length := by
        rw [← hsval]; exact hj
      have : s.val[j]'hj = (self.data.val.slice (sOffset p) (dataEnd p))[j]'hj' := by
        simp [hsval]
      rw [this]; exact e
    rw [hidx]
    apply data_wf
    unfold dataEnd matrixLen; grind
  · intro i
    have hi := i.isLt
    have hsval : s.val = self.data.val.slice (sOffset p) (dataEnd p) := by
      simp_all [matrixLen, sOffset, dataEnd]
    have hslen : s.length = (k p : ℕ) := by show _ = (k p : ℕ); scalar_tac
    have hibound : (i : ℕ) < (k p : ℕ) := hi
    have hbound : sOffset p + (i : ℕ) < dataEnd p := by
      unfold sOffset matrixLen dataEnd; grind
    have hbound2 : sOffset p + (i : ℕ) < self.data.val.length := by
      rw [hdlen]; have : dataEnd p ≤ 24 := by unfold dataEnd matrixLen; grind
      omega
    have hjs : (i : ℕ) < s.val.length := by
      show (i : ℕ) < s.length; rw [hslen]; exact hibound
    have hidx : s.val[(i : ℕ)]'hjs =
        self.data.val[sOffset p + (i : ℕ)]'hbound2 := by
      have e := List.getElem_slice (sOffset p) (dataEnd p) (i : ℕ) self.data.val
                  ⟨by rw [hdlen]; unfold dataEnd matrixLen; grind, hbound⟩
      have hj' : (i : ℕ) < (self.data.val.slice (sOffset p) (dataEnd p)).length := by
        rw [← hsval]; exact hjs
      have : s.val[(i : ℕ)]'hjs = (self.data.val.slice (sOffset p) (dataEnd p))[(i : ℕ)]'hj' := by
        simp [hsval]
      rw [this]; exact e
    have hkeyS : (keyS self p)[i] = toMontPoly ((↑self.data : List _)[sOffset p + (i : ℕ)]'hbound2) := by
      unfold keyS
      simp
    rw [hkeyS, hidx]

/-! ## `@[step]` specs for the `_mut` accessors

Framing-only: the slice content and `back`-function preservation
conditions.  Pointwise content of the slice (its `toPoly` view) is the
same as the read-only variant; we don't restate it here because the
typical consumer pattern is "read via `_mut`, mutate, write back" and
the spec of the mutator (e.g. `vector_ntt.spec`) carries the
intermediate content equation.

Not axioms: every step-spec for a known function gets a proof. -/

@[step]
theorem mlkem.key.Key.a_transpose_mut.spec
    (self : mlkem.key.Key) (p : ParameterSet) (_h : wfKey self p) :
    mlkem.key.Key.a_transpose_mut self
      ⦃ s back =>
        s.length = matrixLen p ∧
        (∀ i (_ : i < s.length), wfPoly s.val[i]) ∧
        (∀ (i : ℕ) (h_len : s.length = matrixLen p) (h_i : i < matrixLen p),
          s.val[i]'(by
            have : s.val.length = s.length := rfl
            rw [this, h_len]; exact h_i) =
          self.data.val[i]'(by
            have h1 : self.data.val.length = 24 := self.data.property
            have := k_sq_plus_2k_le_24 p
            unfold matrixLen at h_i; grind)) ∧
        (∀ (s' : Slice (PolyElement))
           (_ : s'.length = matrixLen p)
           (_ : ∀ i (_ : i < s'.length), wfPoly s'.val[i]),
            wfKey (back s') p ∧
            (back s').params = self.params ∧
            (back s').n_rows = self.n_rows ∧
            (back s').public_seed = self.public_seed ∧
            (back s').encoded_t = self.encoded_t ∧
            (back s').encaps_key_hash = self.encaps_key_hash ∧
            (back s').private_seed = self.private_seed ∧
            (back s').private_random = self.private_random ∧
            (back s').has_private_seed = self.has_private_seed ∧
            (back s').has_private_key = self.has_private_key ∧
            (∀ (col : ℕ) (h_col : col < matrixLen p),
              (back s').data.val[col]'(by
                have h1 : (back s').data.val.length = 24 := (back s').data.property
                unfold matrixLen at h_col
                have := k_sq_plus_2k_le_24 p
                grind) =
              s'.val[col]'(by grind)) ∧
            (∀ (slot : ℕ) (_h_lo : matrixLen p ≤ slot) (h_hi : slot < (24 : ℕ)),
              (back s').data.val[slot]'(by
                have h1 : (back s').data.val.length = 24 := (back s').data.property
                grind) =
              self.data.val[slot]'(by
                have h1 : self.data.val.length = 24 := self.data.property
                grind))) ⦄ := by
  /- Informal proof.
     The body calls `Array.index_mut` over `data[0 .. (k p)²]`.  This
     returns `(s, idx_back)` with `s = data[0 .. (k p)²]` and
     `idx_back s' = Array(data with [0 .. (k p)²] := s')`.  Then `back`
     wraps `idx_back` into `Key`-update form: `back s' = { self with
     data := idx_back s' }`.

     For the framing: replacing the matrix slot leaves `t` (slots
     `[matrixLen p, sOffset p)`) and `s` (slots `[sOffset p, dataEnd p)`)
     unchanged.  Hence `wfKey (back s') p` holds — `params_ok` and
     `n_rows_ok` are immediate since `back` only changes `data`;
     `data_wf` follows because the t/s slots are unchanged and the
     a_transpose slots now satisfy `wfPoly` by hypothesis on `s'`. -/
  unfold mlkem.key.Key.a_transpose_mut
  have hwf := _h
  obtain ⟨params_ok, hn_rows, data_wf⟩ := _h
  have hk := k_le_4 p
  have hk2 := k_sq_plus_2k_le_24 p
  have hdlen : self.data.val.length = 24 := self.data.property
  step with mlkem.key.Key.matrix_len.spec self p hwf
  step
  refine ⟨?_, ?_, ?_, ?_⟩
  · show s.length = matrixLen p; show _ = matrixLen p; scalar_tac
  · intro j hj
    have hsval : s.val = self.data.val.slice 0 (matrixLen p) := by
      simp_all [matrixLen]
    have hslen : s.length = matrixLen p := by show _ = matrixLen p; scalar_tac
    have hjlen : j < matrixLen p := by rw [hslen] at hj; exact hj
    have hbound : 0 + j < matrixLen p := by omega
    have hbound2 : j < self.data.val.length := by
      rw [hdlen]; unfold matrixLen at hjlen; omega
    have hidx : s.val[j]'hj = self.data.val[j]'hbound2 := by
      have hj' : j < (self.data.val.slice 0 (matrixLen p)).length := by
        rw [← hsval]; exact hj
      have h1 : s.val[j]'hj = (self.data.val.slice 0 (matrixLen p))[j]'hj' := by
        simp [hsval]
      have h2 := List.getElem_slice 0 (matrixLen p) j self.data.val
                  ⟨by rw [hdlen]; unfold matrixLen; omega, hbound⟩
      rw [h1, h2]; fcongr 1; omega
    rw [hidx]
    apply data_wf
    unfold dataEnd matrixLen; grind
  · -- NEW: pointwise read s.val[i] = self.data.val[i] for i < matrixLen p
    intro i _h_len h_i
    have hsval : s.val = self.data.val.slice 0 (matrixLen p) := by
      simp_all [matrixLen]
    have hbound : 0 + i < matrixLen p := by omega
    have h2 := List.getElem_slice 0 (matrixLen p) i self.data.val
                ⟨by rw [hdlen]; unfold matrixLen; omega, hbound⟩
    have hi' : i < (self.data.val.slice 0 (matrixLen p)).length := by
      rw [← hsval]
      have hslen : s.length = matrixLen p := by show _ = matrixLen p; scalar_tac
      rw [show s.val.length = s.length from rfl, hslen]
      exact h_i
    have hi_s : i < s.val.length := by
      have hslen : s.length = matrixLen p := by show _ = matrixLen p; scalar_tac
      rw [show s.val.length = s.length from rfl, hslen]
      exact h_i
    have heq1 : s.val[i]'hi_s = (self.data.val.slice 0 (matrixLen p))[i]'hi' := by
      simp [hsval]
    rw [heq1, h2]
    fcongr 1; omega
  · intro s' hslen wfs'
    have hbacks' : (index_mut_back s').val = self.data.val.setSlice! 0 s'.val := by
      have := s_post3 s'
      simp_all [matrixLen]
    have hbacklen' : (self.data.val.setSlice! 0 s'.val).length = 24 := by
      rw [List.length_setSlice!]; exact hdlen
    have hbacklen : (index_mut_back s').val.length = 24 := by rw [hbacks']; exact hbacklen'
    have hslen' : s'.val.length = matrixLen p := hslen
    refine ⟨⟨params_ok, hn_rows, ?_⟩, ?_, ?_⟩
    · intro i hi
      have hidatlen : i < self.data.val.length := by
        rw [hdlen]; unfold dataEnd matrixLen at hi
        have := k_sq_plus_2k_le_24 p; omega
      simp only [hbacks']
      by_cases h1 : i < matrixLen p
      · have hi' : i - 0 < s'.val.length := by rw [hslen']; omega
        have heq := List.getElem_setSlice!_middle self.data.val s'.val 0 i
                    ⟨by omega, hi', hidatlen⟩
        rw [heq]
        have hi'' : i - 0 < s'.length := hi'
        exact wfs' (i - 0) hi''
      · push Not at h1
        have heq := List.getElem_setSlice!_suffix self.data.val s'.val 0 i
                    ⟨by rw [hslen']; omega, hidatlen⟩
        rw [heq]; exact data_wf i hi
    · -- NEW: pointwise data update for col < matrixLen p
      intro col h_col
      show (index_mut_back s').val[col]'_ = s'.val[col]'_
      simp only [hbacks']
      have hidatlen : col < self.data.val.length := by
        rw [hdlen]; unfold matrixLen at h_col
        have := k_sq_plus_2k_le_24 p; omega
      have hcol' : col - 0 < s'.val.length := by rw [hslen']; omega
      have heq := List.getElem_setSlice!_middle self.data.val s'.val 0 col
                  ⟨by omega, hcol', hidatlen⟩
      rw [heq]
      show s'.val[col - 0]'hcol' = s'.val[col]'_
      rfl
    · -- NEW: frame for slots outside [0, matrixLen p)
      intro slot h_lo h_hi
      show (index_mut_back s').val[slot]'_ = self.data.val[slot]'_
      simp only [hbacks']
      have hidatlen : slot < self.data.val.length := by rw [hdlen]; exact h_hi
      have heq := List.getElem_setSlice!_suffix self.data.val s'.val 0 slot
                  ⟨by rw [hslen']; omega, hidatlen⟩
      exact heq

@[step]
theorem mlkem.key.Key.t_mut.spec
    (self : mlkem.key.Key) (p : ParameterSet) (_h : wfKey self p) :
    mlkem.key.Key.t_mut self
      ⦃ s back =>
        ∃ (h_s_len : s.length = (k p : ℕ)),
        (∀ i (_ : i < s.length), wfPoly s.val[i]) ∧
        (∀ (i : ℕ) (h_i : i < (k p : ℕ)),
          s.val[i]'(by grind) =
          self.data.val[tOffset p + i]'(by
            have h1 : self.data.val.length = 24 := self.data.property
            have := k_sq_plus_2k_le_24 p
            unfold tOffset matrixLen at *; grind)) ∧
        (∀ (s' : Slice (PolyElement))
           (_ : s'.length = (k p : ℕ))
           (_ : ∀ i (_ : i < s'.length), wfPoly s'.val[i]),
            KeyInv self (back s') p ∧
            (back s').algorithm_info = self.algorithm_info ∧
            (back s').has_private_key = self.has_private_key ∧
            (back s').public_seed = self.public_seed ∧
            (back s').encoded_t = self.encoded_t ∧
            (back s').encaps_key_hash = self.encaps_key_hash ∧
            (∃ (_h_dlen : (back s').data.val.length = 24),
              (∀ (i : ℕ) (h_i : i < (k p : ℕ)),
                (back s').data.val[tOffset p + i]'(by
                  have := k_sq_plus_2k_le_24 p
                  unfold tOffset matrixLen at *; grind) =
                s'.val[i]'(by grind)) ∧
              (∀ (slot : ℕ) (h_slot : slot < (24 : ℕ)),
                ¬ (tOffset p ≤ slot ∧ slot < tOffset p + (k p : ℕ)) →
                (back s').data.val[slot]'(by grind) =
                self.data.val[slot]'(by
                  have h1 : self.data.val.length = 24 := self.data.property
                  grind)))) ⦄ := by
  /- Informal proof.
     Template: leaf step-spec with `Array.index_mut`-style closure
     return.  Structurally identical to `a_transpose_mut.spec` above,
     but ranging over slots `[matrixLen p, sOffset p) = [matrixLen p,
     matrixLen p + k p)`, i.e., the `t` portion of `key.data`.

     1. `step with mlkem.key.Key.matrix_len.spec`: gives
        `matrix_len self = ok ((k p)²)`.
     2. `step with Usize.add.spec` for the right endpoint
        `matrixLen p + (k p) = sOffset p` (no overflow, `≤ 20`).
     3. `step with core.array.Array.index_mut` over
        `{start := matrixLen p, end := sOffset p}`.  This returns
        `(s, idx_back)` with:
        - `s.length = (k p : ℕ)`,
        - `s.val[i] = self.data.val[matrixLen p + i]` for `i < k p`,
        - `idx_back s' = Array(self.data with [matrixLen p .. sOffset p] := s')`.
     4. `back` wraps `idx_back` into the `Key`-update form:
        `back s' = { self with data := idx_back s' }`.

     The strengthened postcondition exposes (a) the forward
     positional equation linking `s.val[i]` to `self.data.val[tOffset
     p + i]` (needed by callers that want to reuse the original
     slot's polynomial); (b) the back's positional effect at
     `[tOffset p, tOffset p + k p)`; (c) the back's framing on all
     other slots `[0, 24)`; and (d) preservation of every non-`data`
     field — all directly readable from the `index_mut` step's
     postcondition combined with the struct-update form of `back`.

     For the framing: replacing the `t` slot leaves the A^T slot
     (`[0, matrixLen p)`) and the `s` slot (`[sOffset p, dataEnd p)`)
     unchanged, so:
     - `params_ok` and `n_rows_ok` are immediate (`back` only changes
       `data`).
     - `data_wf` follows: A^T slots and `s` slots are unchanged, and
       the new `t` slots satisfy `wfPoly` by the hypothesis on `s'`.

     Case analysis: none — straight-line wrapper. `wfPoly` on the
     pre-mutation slice follows from `_h.data_wf` for each slot in
     `[matrixLen p, sOffset p)`.

     Close with `step*?` and `agrind`. -/
  unfold mlkem.key.Key.t_mut
  have hwf := _h
  obtain ⟨params_ok, hn_rows, data_wf⟩ := _h
  have hk := k_le_4 p
  have hk2 := k_sq_plus_2k_le_24 p
  have hdlen : self.data.val.length = 24 := self.data.property
  step with mlkem.key.Key.matrix_len.spec self p hwf
  step
  step
  refine ⟨?_, ?_, ?_, ?_⟩
  · show _ = (k p : ℕ); scalar_tac
  · intro j hj
    have hsval : s.val = self.data.val.slice (matrixLen p) (sOffset p) := by
      simp_all [matrixLen, sOffset]
    have hslen : s.length = (k p : ℕ) := by show _ = (k p : ℕ); scalar_tac
    have hjlen : j < (k p : ℕ) := by rw [hslen] at hj; exact hj
    have hbound : matrixLen p + j < sOffset p := by
      unfold sOffset matrixLen; grind
    have hbound2 : matrixLen p + j < self.data.val.length := by
      rw [hdlen]; have : sOffset p ≤ 24 := by unfold sOffset matrixLen; grind
      omega
    have hidx : s.val[j]'hj = self.data.val[matrixLen p + j]'hbound2 := by
      have e := List.getElem_slice (matrixLen p) (sOffset p) j self.data.val
                  ⟨by rw [hdlen]; unfold sOffset matrixLen; grind, hbound⟩
      have hj' : j < (self.data.val.slice (matrixLen p) (sOffset p)).length := by
        rw [← hsval]; exact hj
      have : s.val[j]'hj = (self.data.val.slice (matrixLen p) (sOffset p))[j]'hj' := by
        simp [hsval]
      rw [this]; exact e
    rw [hidx]
    apply data_wf
    unfold dataEnd matrixLen; grind
  · intro j hj
    have hsval : s.val = self.data.val.slice (matrixLen p) (sOffset p) := by
      simp_all [matrixLen, sOffset]
    have hbound : matrixLen p + j < sOffset p := by
      unfold sOffset matrixLen; grind
    have hbound2 : matrixLen p + j < self.data.val.length := by
      rw [hdlen]; have : sOffset p ≤ 24 := by unfold sOffset matrixLen; grind
      omega
    have hslen : s.length = (k p : ℕ) := by show _ = (k p : ℕ); scalar_tac
    have hjs : j < s.length := by rw [hslen]; exact hj
    show s.val[j]'hjs = _
    have e := List.getElem_slice (matrixLen p) (sOffset p) j self.data.val
                ⟨by rw [hdlen]; unfold sOffset matrixLen; grind, hbound⟩
    have hj' : j < (self.data.val.slice (matrixLen p) (sOffset p)).length := by
      rw [← hsval]; exact hjs
    have heq : s.val[j]'hjs = (self.data.val.slice (matrixLen p) (sOffset p))[j]'hj' := by
      simp [hsval]
    rw [heq, e]
  · intro s' hslen wfs'
    have hbacks' : (index_mut_back s').val = self.data.val.setSlice! (matrixLen p) s'.val := by
      have := s_post3 s'
      simp_all [matrixLen]
    have hbacklen' : (self.data.val.setSlice! (matrixLen p) s'.val).length = 24 := by
      rw [List.length_setSlice!]; exact hdlen
    have hbacklen : (index_mut_back s').val.length = 24 := by rw [hbacks']; exact hbacklen'
    have hslen' : s'.val.length = (k p : ℕ) := hslen
    refine ⟨?_, ?_⟩
    · refine KeyInv.mk (wfKey.mk params_ok hn_rows ?_) rfl rfl rfl rfl rfl
      intro i hi
      have hidatlen : i < self.data.val.length := by
        rw [hdlen]; unfold dataEnd matrixLen at hi
        have := k_sq_plus_2k_le_24 p; omega
      simp only [hbacks']
      by_cases h1 : i < matrixLen p
      · have heq := List.getElem_setSlice!_prefix self.data.val s'.val (matrixLen p) i
                    ⟨h1, hidatlen⟩
        rw [heq]; exact data_wf i hi
      · push Not at h1
        by_cases h2 : i < sOffset p
        · have hi' : i - matrixLen p < s'.val.length := by
            rw [hslen']; unfold sOffset at h2; omega
          have heq := List.getElem_setSlice!_middle self.data.val s'.val (matrixLen p) i
                      ⟨h1, hi', hidatlen⟩
          rw [heq]; exact wfs' _ hi'
        · push Not at h2
          have heq := List.getElem_setSlice!_suffix self.data.val s'.val (matrixLen p) i
                      ⟨by rw [hslen']; unfold sOffset at h2; omega, hidatlen⟩
          rw [heq]; exact data_wf i hi
    · refine ⟨hbacklen, ?_, ?_⟩
      · intro i hi
        simp only [hbacks']
        have hib : matrixLen p + i < self.data.val.length := by
          rw [hdlen]; unfold matrixLen
          have := k_sq_plus_2k_le_24 p; omega
        have hi'_sub : (matrixLen p + i) - matrixLen p < s'.val.length := by
          rw [hslen']; omega
        show (self.data.val.setSlice! (matrixLen p) s'.val)[matrixLen p + i] = s'.val[i]
        have heq := List.getElem_setSlice!_middle self.data.val s'.val (matrixLen p)
                  (matrixLen p + i) ⟨by omega, hi'_sub, hib⟩
        rw [heq]
        fcongr 1; omega
      · intro slot hslot hne
        simp only [hbacks']
        have hsbound : slot < self.data.val.length := by rw [hdlen]; exact hslot
        by_cases h1 : slot < matrixLen p
        · exact List.getElem_setSlice!_prefix self.data.val s'.val (matrixLen p) slot
                  ⟨h1, hsbound⟩
        · push Not at h1
          have h2 : matrixLen p + s'.val.length ≤ slot := by
            rw [hslen']
            unfold tOffset at hne
            push Not at hne
            exact hne h1
          exact List.getElem_setSlice!_suffix self.data.val s'.val (matrixLen p) slot
                  ⟨h2, hsbound⟩

@[step]
theorem mlkem.key.Key.s_mut.spec
    (self : mlkem.key.Key) (p : ParameterSet) (_h : wfKey self p) :
    mlkem.key.Key.s_mut self
      ⦃ s back =>
        ∃ (h_s_len : s.length = (k p : ℕ)),
        (∀ i (_ : i < s.length), wfPoly s.val[i]) ∧
        (∀ (i : ℕ) (h_i : i < (k p : ℕ)),
          s.val[i]'(by grind) =
          self.data.val[sOffset p + i]'(by
            have h1 : self.data.val.length = 24 := self.data.property
            have := k_sq_plus_2k_le_24 p
            unfold sOffset matrixLen at *; grind)) ∧
        (∀ (s' : Slice (PolyElement))
           (_ : s'.length = (k p : ℕ))
           (_ : ∀ i (_ : i < s'.length), wfPoly s'.val[i]),
            KeyInv self (back s') p ∧
            (back s').algorithm_info = self.algorithm_info ∧
            (back s').has_private_key = self.has_private_key ∧
            (back s').public_seed = self.public_seed ∧
            (back s').encoded_t = self.encoded_t ∧
            (back s').encaps_key_hash = self.encaps_key_hash ∧
            (∃ (_h_dlen : (back s').data.val.length = 24),
              (∀ (i : ℕ) (h_i : i < (k p : ℕ)),
                (back s').data.val[sOffset p + i]'(by
                  have := k_sq_plus_2k_le_24 p
                  unfold sOffset matrixLen at *; grind) =
                s'.val[i]'(by grind)) ∧
              (∀ (slot : ℕ) (h_slot : slot < (24 : ℕ)),
                ¬ (sOffset p ≤ slot ∧ slot < sOffset p + (k p : ℕ)) →
                (back s').data.val[slot]'(by grind) =
                self.data.val[slot]'(by
                  have h1 : self.data.val.length = 24 := self.data.property
                  grind)))) ⦄ := by
  /- Informal proof.
     Template: leaf step-spec with `Array.index_mut`-style closure
     return.  Structurally identical to `t_mut.spec` above, but
     ranging over slots `[sOffset p, dataEnd p) = [sOffset p,
     sOffset p + k p)`, i.e., the `s` portion of `key.data`.

     1. `step with mlkem.key.Key.matrix_len.spec`: gives
        `matrix_len self = ok ((k p)²)`.
     2. `step with Usize.add.spec` for the left endpoint
        `matrixLen p + (k p) = sOffset p`.
     3. `step with Usize.add.spec` for the right endpoint
        `sOffset p + (k p) = dataEnd p` (no overflow, ≤ 24 by
        `k_sq_plus_2k_le_24 p`).
     4. `step with core.array.Array.index_mut` over
        `{start := sOffset p, end := dataEnd p}`.  Returns
        `(s, idx_back)` with `s.val[i] = self.data.val[sOffset p + i]`
        for `i < k p` and `idx_back s' = Array(self.data with
        [sOffset p .. dataEnd p] := s')`.
     5. `back s' = { self with data := idx_back s' }`.

     The strengthened postcondition exposes (a) the forward
     positional equation, (b) the back's positional effect at
     `[sOffset p, sOffset p + k p)`, (c) the back's framing on all
     other slots `[0, 24)`, and (d) preservation of every non-`data`
     field.

     For the framing: replacing the `s` slot leaves the A^T slot and
     the `t` slot unchanged, so `params_ok`/`n_rows_ok` are immediate
     and `data_wf` follows: unchanged slots are still `wfPoly` by
     `_h.data_wf`; the new `s` slots are `wfPoly` by hypothesis on
     `s'`.

     Case analysis: none — straight-line wrapper. Pre-mutation
     `wfPoly` of each slot is from `_h.data_wf` over indices in
     `[sOffset p, dataEnd p)`.

     Close with `step*?` and `agrind`. -/
  unfold mlkem.key.Key.s_mut
  have hwf := _h
  obtain ⟨params_ok, hn_rows, data_wf⟩ := _h
  have hk := k_le_4 p
  have hk2 := k_sq_plus_2k_le_24 p
  have hdlen : self.data.val.length = 24 := self.data.property
  step with mlkem.key.Key.matrix_len.spec self p hwf
  step
  step
  step
  step
  refine ⟨?_, ?_, ?_, ?_⟩
  · show _ = (k p : ℕ); scalar_tac
  · intro j hj
    have hsval : s.val = self.data.val.slice (sOffset p) (dataEnd p) := by
      simp_all [matrixLen, sOffset, dataEnd]
    have hslen : s.length = (k p : ℕ) := by show _ = (k p : ℕ); scalar_tac
    have hjlen : j < (k p : ℕ) := by rw [hslen] at hj; exact hj
    have hbound : sOffset p + j < dataEnd p := by
      unfold dataEnd sOffset matrixLen; grind
    have hbound2 : sOffset p + j < self.data.val.length := by
      rw [hdlen]; have : dataEnd p ≤ 24 := by unfold dataEnd matrixLen; grind
      omega
    have hidx : s.val[j]'hj = self.data.val[sOffset p + j]'hbound2 := by
      have e := List.getElem_slice (sOffset p) (dataEnd p) j self.data.val
                  ⟨by rw [hdlen]; unfold dataEnd matrixLen; grind, hbound⟩
      have hj' : j < (self.data.val.slice (sOffset p) (dataEnd p)).length := by
        rw [← hsval]; exact hj
      have heq : s.val[j]'hj = (self.data.val.slice (sOffset p) (dataEnd p))[j]'hj' := by
        simp [hsval]
      rw [heq]; exact e
    rw [hidx]
    apply data_wf
    unfold dataEnd; grind
  · intro j hj
    have hsval : s.val = self.data.val.slice (sOffset p) (dataEnd p) := by
      simp_all [matrixLen, sOffset, dataEnd]
    have hbound : sOffset p + j < dataEnd p := by
      unfold dataEnd sOffset matrixLen; grind
    have hbound2 : sOffset p + j < self.data.val.length := by
      rw [hdlen]; have : dataEnd p ≤ 24 := by unfold dataEnd matrixLen; grind
      omega
    have hslen : s.length = (k p : ℕ) := by show _ = (k p : ℕ); scalar_tac
    have hjs : j < s.length := by rw [hslen]; exact hj
    show s.val[j]'hjs = _
    have e := List.getElem_slice (sOffset p) (dataEnd p) j self.data.val
                ⟨by rw [hdlen]; unfold dataEnd matrixLen; grind, hbound⟩
    have hj' : j < (self.data.val.slice (sOffset p) (dataEnd p)).length := by
      rw [← hsval]; exact hjs
    have heq : s.val[j]'hjs = (self.data.val.slice (sOffset p) (dataEnd p))[j]'hj' := by
      simp [hsval]
    rw [heq, e]
  · intro s' hslen wfs'
    have hbacks' : (index_mut_back s').val = self.data.val.setSlice! (sOffset p) s'.val := by
      have := s_post3 s'
      simp_all [matrixLen, sOffset]
    have hbacklen' : (self.data.val.setSlice! (sOffset p) s'.val).length = 24 := by
      rw [List.length_setSlice!]; exact hdlen
    have hbacklen : (index_mut_back s').val.length = 24 := by rw [hbacks']; exact hbacklen'
    have hslen' : s'.val.length = (k p : ℕ) := hslen
    refine ⟨?_, ?_⟩
    · refine KeyInv.mk (wfKey.mk params_ok hn_rows ?_) rfl rfl rfl rfl rfl
      intro i hi
      have hidatlen : i < self.data.val.length := by
        rw [hdlen]; unfold dataEnd matrixLen at hi
        have := k_sq_plus_2k_le_24 p; omega
      simp only [hbacks']
      by_cases h1 : i < sOffset p
      · have heq := List.getElem_setSlice!_prefix self.data.val s'.val (sOffset p) i
                    ⟨h1, hidatlen⟩
        rw [heq]; exact data_wf i hi
      · push Not at h1
        by_cases h2 : i < dataEnd p
        · have hi' : i - sOffset p < s'.val.length := by
            have h_data : dataEnd p = matrixLen p + 2 * (k p : ℕ) := rfl
            have h_sof : sOffset p = matrixLen p + (k p : ℕ) := rfl
            rw [hslen']
            simp only [h_data, h_sof] at h1 h2 ⊢
            omega
          have heq := List.getElem_setSlice!_middle self.data.val s'.val (sOffset p) i
                      ⟨h1, hi', hidatlen⟩
          rw [heq]; exact wfs' _ hi'
        · push Not at h2
          -- i ≥ dataEnd p but hi : i < dataEnd p contradicts
          omega
    · refine ⟨hbacklen, ?_, ?_⟩
      · intro i hi
        simp only [hbacks']
        have hib : sOffset p + i < self.data.val.length := by
          rw [hdlen]; unfold sOffset matrixLen
          have := k_sq_plus_2k_le_24 p; omega
        have hi'_sub : (sOffset p + i) - sOffset p < s'.val.length := by
          rw [hslen']; omega
        show (self.data.val.setSlice! (sOffset p) s'.val)[sOffset p + i] = s'.val[i]
        have heq := List.getElem_setSlice!_middle self.data.val s'.val (sOffset p)
                  (sOffset p + i) ⟨by omega, hi'_sub, hib⟩
        rw [heq]
        fcongr 1; omega
      · intro slot hslot hne
        simp only [hbacks']
        have hsbound : slot < self.data.val.length := by rw [hdlen]; exact hslot
        by_cases h1 : slot < sOffset p
        · exact List.getElem_setSlice!_prefix self.data.val s'.val (sOffset p) slot
                  ⟨h1, hsbound⟩
        · push Not at h1
          have h2 : sOffset p + s'.val.length ≤ slot := by
            rw [hslen']
            push Not at hne
            exact hne h1
          exact List.getElem_setSlice!_suffix self.data.val s'.val (sOffset p) slot
                  ⟨h2, hsbound⟩

@[step]
theorem mlkem.key.Key.ats_mut.spec
    (self : mlkem.key.Key) (p : ParameterSet) (_h : wfKey self p) :
    mlkem.key.Key.ats_mut self
      ⦃ (a, t, s) back =>
        /- The body uses `split_at_mut data m_len` then `split_at_mut ts n_rows`.
           Since `data` has length 24 (the maximum across parameter sets),
           the trailing `s` slice has length `24 - matrixLen p - k p`, which
           equals `k p` only when `k p = 4` (ML-KEM-1024).  For k=2,3 the
           tail contains unused scratch entries.  We only constrain the
           first `k p` entries (the genuine `s` slot) to be `wfPoly`. -/
        ∃ (_ : a.length = matrixLen p) (_ : t.length = (k p : ℕ))
          (_ : s.length = 24 - matrixLen p - (k p : ℕ)),
        (∀ i (_ : i < a.length), wfPoly a.val[i]) ∧
        (∀ i (_ : i < t.length), wfPoly t.val[i]) ∧
        (∀ i (_ : i < (k p : ℕ)), wfPoly (s.val[i]'(by
          have hk2 := k_sq_plus_2k_le_24 p
          have _hk := k_le_4 p
          have hlen : s.val.length = 24 - matrixLen p - (k p : ℕ) := ‹_›
          unfold matrixLen at hlen
          grind))) ∧
        /- Slot-content frames: the three slices are the matrix/t/s slots
           of `self.data`.  These let callers project slot entries
           (e.g. matrix row `a[row*k+col]`) directly. -/
        a.val = self.data.val.take (matrixLen p) ∧
        t.val = (self.data.val.drop (matrixLen p)).take (k p : ℕ) ∧
        s.val = self.data.val.drop (matrixLen p + (k p : ℕ)) ∧
        (∀ (a' : Slice PolyElement) (t' : Slice PolyElement)
           (s' : Slice PolyElement)
           (_ : a'.length = matrixLen p)
           (_ : t'.length = (k p : ℕ))
           (h_s' : s'.length = 24 - matrixLen p - (k p : ℕ))
           (_ : ∀ i (_ : i < a'.length), wfPoly a'.val[i])
           (_ : ∀ i (_ : i < t'.length), wfPoly t'.val[i])
           (_ : ∀ i (_ : i < (k p : ℕ)), wfPoly (s'.val[i]'(by
              have hk2 := k_sq_plus_2k_le_24 p
              have _hk := k_le_4 p
              have hlen : s'.val.length = 24 - matrixLen p - (k p : ℕ) := h_s'
              unfold matrixLen at hlen
              grind))),
            KeyInv self (back (a', t', s')) p ∧
            (back (a', t', s')).has_private_key  = self.has_private_key  ∧
            (back (a', t', s')).encoded_t        = self.encoded_t        ∧
            (back (a', t', s')).public_seed      = self.public_seed      ∧
            (back (a', t', s')).encaps_key_hash  = self.encaps_key_hash  ∧
            /- Data-frame: the reassembled key's data is the concatenation
               of the three slot slices.  Combined with the slot-content
               frames above this lets callers reason about each slot of
               the input through the back-fn. -/
            (back (a', t', s')).data.val =
              a'.val ++ t'.val ++ s'.val) ⦄ := by
  unfold mlkem.key.Key.ats_mut
  have hwf := _h
  obtain ⟨params_ok, hn_rows, data_wf⟩ := _h
  have hk := k_le_4 p
  have hk2 := k_sq_plus_2k_le_24 p
  have hdlen : self.data.val.length = 24 := self.data.property
  step with mlkem.key.Key.matrix_len.spec self p hwf
  step
  -- After `lift (Array.to_slice_mut self.data)`: s.val = self.data.val,
  -- to_slice_mut_back = Array.from_slice self.data.
  -- First split: split_at_mut s m_len → a (length matrixLen) + ts (length 24 - matrixLen).
  have hm_post : m_len.val = matrixLen p := m_len_post
  have h_m_le : m_len.val ≤ s.length := by
    show _ ≤ s.length
    have : s.length = 24 := by
      have : (s.val : List _).length = self.data.val.length := by rw [‹s.val = _›]
      have : s.length = self.data.val.length := this
      rw [this, hdlen]
    rw [this, hm_post]; unfold matrixLen; grind
  step with core.slice.Slice.split_at_mut.spec s m_len h_m_le
  -- p = (a, ts). split_at_mut_back assembles (a', ts') ↦ (a' ++ ts').
  -- Second split: split_at_mut ts self.n_rows → t (length n_rows = k) + s1.
  have h_n_le : (self.n_rows.val : ℕ) ≤ ts.length := by
    have h_ts_len : ts.length = s.length - m_len.val := by
      simp_all
    rw [h_ts_len, hm_post]
    have hsl : s.length = 24 := by
      have : (s.val : List _).length = self.data.val.length := by rw [‹s.val = _›]
      have : s.length = self.data.val.length := this
      rw [this, hdlen]
    rw [hsl, hn_rows]; unfold matrixLen; grind
  step with core.slice.Slice.split_at_mut.spec ts self.n_rows h_n_le
  -- Helper facts about lengths.
  have h_s_len_val : s.val.length = 24 := by rw [s_post1, hdlen]
  have h_s_len : s.length = 24 := h_s_len_val
  have h_ts_len_val : ts.val.length = 24 - matrixLen p := by
    rw [a_post4, List.length_drop, s_post1, hdlen, hm_post]
  have h_ts_len : ts.length = 24 - matrixLen p := h_ts_len_val
  have h_a_val : a.val = self.data.val.take (matrixLen p) := by
    rw [a_post3, s_post1, hm_post]
  have h_t_val : t.val = (self.data.val.drop (matrixLen p)).take (k p : ℕ) := by
    rw [t_post3, a_post4, s_post1, hm_post, hn_rows]
  have h_s1_val : s1.val = self.data.val.drop (matrixLen p + (k p : ℕ)) := by
    rw [t_post4, a_post4, s_post1, hm_post, hn_rows, List.drop_drop, Nat.add_comm]
  have h_a_len : a.length = matrixLen p := by rw [a_post1, hm_post]
  have h_t_len : t.length = (k p : ℕ) := by rw [t_post1, hn_rows]
  have h_s1_len : s1.length = 24 - matrixLen p - (k p : ℕ) := by
    rw [t_post2, h_ts_len, hn_rows]
  refine ⟨h_a_len, h_t_len, h_s1_len, ?wa, ?wt, ?ws,
          h_a_val, h_t_val, h_s1_val, ?back⟩
  · -- a is wfPoly on [0, matrixLen)
    intro i hi
    have hi' : i < matrixLen p := h_a_len ▸ hi
    have hibd : i < self.data.val.length := by rw [hdlen]; unfold matrixLen at hi'; grind
    have hai : a.val[i] = self.data.val[i]'hibd := by
      have := h_a_val
      simp [this, List.getElem_take]
    rw [hai]
    exact data_wf i (by unfold dataEnd; unfold matrixLen at hi'; grind)
  · -- t is wfPoly on [0, k)
    intro i hi
    have hi' : i < (k p : ℕ) := h_t_len ▸ hi
    have hibd : matrixLen p + i < self.data.val.length := by
      rw [hdlen]; have := k_sq_plus_2k_le_24 p; unfold matrixLen; omega
    have hti : t.val[i] = self.data.val[matrixLen p + i]'hibd := by
      have := h_t_val
      simp [this, List.getElem_take, List.getElem_drop]
    rw [hti]
    exact data_wf _ (by unfold dataEnd; omega)
  · -- s1 first k entries are wfPoly
    intro i hi
    have hs1_val_len : i < s1.val.length := by
      have : s1.val.length = 24 - matrixLen p - (k p : ℕ) := h_s1_len
      rw [this]; unfold matrixLen; have := k_sq_plus_2k_le_24 p; omega
    have hibd : matrixLen p + (k p : ℕ) + i < self.data.val.length := by
      rw [hdlen]; unfold matrixLen; have := k_sq_plus_2k_le_24 p; omega
    have hs1i : s1.val[i]'hs1_val_len = self.data.val[matrixLen p + (k p : ℕ) + i]'hibd := by
      simp [h_s1_val, List.getElem_drop]
    rw [hs1i]
    exact data_wf _ (by unfold dataEnd; omega)
  · -- The back-fn properties.
    intro a' t' s' ha'_len ht'_len hs'_len wfa' wft' wfs'
    have ⟨h_ts1_val, h_ts1_len⟩ :=
      t_post5 t' s'
        (by rw [ht'_len, hn_rows])
        (by rw [hs'_len, h_ts_len, hn_rows])
    set ts1 := split_at_mut_back1 (t', s') with hts1_def
    have ⟨h_s5_val, h_s5_len⟩ :=
      a_post5 a' ts1
        (by rw [ha'_len, hm_post])
        (by simp [h_ts1_len, a_post2])
    set s5 := split_at_mut_back (a', ts1) with hs5_def
    have h_s5_len_val : s5.val.length = 24 := by
      have : s5.length = 24 := h_s5_len.trans h_s_len
      exact this
    have h_back_val : (to_slice_mut_back s5).val = a'.val ++ t'.val ++ s'.val := by
      rw [s_post2]
      rw [Std.Array.from_slice_val _ _ h_s5_len_val]
      rw [h_s5_val, h_ts1_val, List.append_assoc]
    have h_al : a'.val.length = matrixLen p := ha'_len
    have h_tl : t'.val.length = (k p : ℕ) := ht'_len
    have h_sl : s'.val.length = 24 - matrixLen p - (k p : ℕ) := hs'_len
    refine ⟨⟨wfKey.mk params_ok hn_rows ?_, rfl, rfl, rfl, rfl, rfl⟩,
            h_back_val⟩
    intro i hi
    have h_total_24 : (a'.val ++ t'.val ++ s'.val).length = 24 := by
      have h1 : a'.val.length = matrixLen p := h_al
      have h2 : t'.val.length = (k p : ℕ) := h_tl
      have h3 : s'.val.length = 24 - matrixLen p - (k p : ℕ) := h_sl
      have hk := k_le_4 p
      have hk2 := k_sq_plus_2k_le_24 p
      rw [List.length_append, List.length_append, h1, h2, h3]
      unfold matrixLen; omega
    have hilen : i < (to_slice_mut_back s5).val.length := by
      rw [h_back_val, h_total_24]
      unfold dataEnd matrixLen at hi
      have := k_le_4 p; have := k_sq_plus_2k_le_24 p; omega
    have heq : (to_slice_mut_back s5).val[i]'hilen =
               (a'.val ++ t'.val ++ s'.val)[i]'(h_back_val ▸ hilen) := by
      simp [h_back_val]
    rw [heq]
    have h_aplus_t_len : (a'.val ++ t'.val).length = matrixLen p + (k p : ℕ) := by
      rw [List.length_append, h_al, h_tl]
    by_cases h1 : i < matrixLen p
    · have hila : i < (a'.val ++ t'.val).length := by rw [h_aplus_t_len]; omega
      have h_in_a' : i < a'.val.length := by rw [h_al]; exact h1
      rw [List.getElem_append_left hila,
          List.getElem_append_left h_in_a']
      exact wfa' i (by show i < a'.length; rw [ha'_len]; exact h1)
    · push Not at h1
      by_cases h2 : i < matrixLen p + (k p : ℕ)
      · have hila : i < (a'.val ++ t'.val).length := by rw [h_aplus_t_len]; omega
        have h_not_a' : a'.val.length ≤ i := by rw [h_al]; exact h1
        rw [List.getElem_append_left hila,
            List.getElem_append_right h_not_a']
        have hbnd : i - a'.val.length < t'.val.length := by rw [h_al, h_tl]; omega
        exact wft' (i - a'.val.length) (by show _ < t'.length; rw [ht'_len, ← h_tl]; exact hbnd)
      · push Not at h2
        have h_not_ab : (a'.val ++ t'.val).length ≤ i := by rw [h_aplus_t_len]; omega
        rw [List.getElem_append_right h_not_ab]
        have : i - (a'.val ++ t'.val).length < (k p : ℕ) := by
          rw [h_aplus_t_len]; unfold dataEnd at hi; omega
        exact wfs' _ this

@[step]
theorem mlkem.key.Key.t_encoded_t_mut.spec
    (self : mlkem.key.Key) (p : ParameterSet) (_h : wfKey self p) :
    mlkem.key.Key.t_encoded_t_mut self
      ⦃ (t, enc) back =>
        t.length = (k p : ℕ) ∧
        (∀ i (_ : i < t.length), wfPoly t.val[i]) ∧
        enc = self.encoded_t ∧
        /- The mutable view `t` is exactly the encapsulation-key slot
           `self.data[matrixLen .. sOffset]`.  Surfaced so callers can
           reason about matrix-slot entries (which lie before
           `matrixLen`) and t-slot entries through the back-fn frame. -/
        t.val = self.data.val.slice (matrixLen p) (sOffset p) ∧
        (∀ (t' : Slice PolyElement) (enc' : Array U8 _)
           (_ : t'.length = (k p : ℕ))
           (_ : ∀ i (_ : i < t'.length), wfPoly t'.val[i]),
            KeyInv self (back (t', enc')) p ∧
            (back (t', enc')).encoded_t       = enc' ∧
            (back (t', enc')).public_seed     = self.public_seed ∧
            (back (t', enc')).encaps_key_hash = self.encaps_key_hash ∧
            (back (t', enc')).has_private_key = self.has_private_key ∧
            /- Data-frame: back-fn writes ONLY indices
               `[matrixLen, matrixLen + k)` (the t-slot).  Matrix slot
               `[0, matrixLen)` and s-slot `[sOffset, 24)` survive. -/
            (back (t', enc')).data.val =
              self.data.val.setSlice! (matrixLen p) t'.val) ⦄ := by
  /- The body indexes `data[matrixLen p .. sOffset p)` and pairs it
     with `self.encoded_t`.  Polys are `wfPoly` by `_h.data_wf`.
     Back-framing reassembles the mutated t slot and `encoded_t`
     into a fresh `Key`; `wfKey` survives because the t slot
     preserves `wfPoly` and the other slots are unchanged. -/
  unfold mlkem.key.Key.t_encoded_t_mut
  have hwf := _h
  obtain ⟨params_ok, hn_rows, data_wf⟩ := _h
  have hk := k_le_4 p
  have hk2 := k_sq_plus_2k_le_24 p
  have hdlen : self.data.val.length = 24 := self.data.property
  step with mlkem.key.Key.matrix_len.spec self p hwf
  step
  step
  have hsval : s.val = self.data.val.slice (matrixLen p) (sOffset p) := by
    simp_all [matrixLen, sOffset]
  refine ⟨?_, ?_, ?_, ?_⟩
  · show _ = (k p : ℕ); scalar_tac
  · intro j hj
    have hslen : s.length = (k p : ℕ) := by show _ = (k p : ℕ); scalar_tac
    have hjlen : j < (k p : ℕ) := by rw [hslen] at hj; exact hj
    have hbound : matrixLen p + j < sOffset p := by
      unfold sOffset matrixLen; grind
    have hbound2 : matrixLen p + j < self.data.val.length := by
      rw [hdlen]; have : sOffset p ≤ 24 := by unfold sOffset matrixLen; grind
      omega
    have hidx : s.val[j]'hj = self.data.val[matrixLen p + j]'hbound2 := by
      have e := List.getElem_slice (matrixLen p) (sOffset p) j self.data.val
                  ⟨by rw [hdlen]; unfold sOffset matrixLen; grind, hbound⟩
      have hj' : j < (self.data.val.slice (matrixLen p) (sOffset p)).length := by
        rw [← hsval]; exact hj
      have : s.val[j]'hj = (self.data.val.slice (matrixLen p) (sOffset p))[j]'hj' := by
        simp [hsval]
      rw [this]; exact e
    rw [hidx]
    apply data_wf
    unfold dataEnd matrixLen; grind
  · exact hsval
  · intro t' enc' hslen wfs'
    have hbacks' : (index_mut_back t').val = self.data.val.setSlice! (matrixLen p) t'.val := by
      have := s_post3 t'
      simp_all [matrixLen]
    have hbacklen' : (self.data.val.setSlice! (matrixLen p) t'.val).length = 24 := by
      rw [List.length_setSlice!]; exact hdlen
    have hbacklen : (index_mut_back t').val.length = 24 := by rw [hbacks']; exact hbacklen'
    have hslen' : t'.val.length = (k p : ℕ) := hslen
    refine ⟨KeyInv.mk (wfKey.mk params_ok hn_rows ?_) rfl rfl rfl rfl rfl, ?_⟩
    · intro i hi
      have hidatlen : i < self.data.val.length := by
        rw [hdlen]; unfold dataEnd matrixLen at hi
        have := k_sq_plus_2k_le_24 p; omega
      simp only [hbacks']
      by_cases h1 : i < matrixLen p
      · have heq := List.getElem_setSlice!_prefix self.data.val t'.val (matrixLen p) i
                    ⟨h1, hidatlen⟩
        rw [heq]; exact data_wf i hi
      · push Not at h1
        by_cases h2 : i < sOffset p
        · have hi' : i - matrixLen p < t'.val.length := by
            rw [hslen']; unfold sOffset at h2; omega
          have heq := List.getElem_setSlice!_middle self.data.val t'.val (matrixLen p) i
                      ⟨h1, hi', hidatlen⟩
          rw [heq]; exact wfs' _ hi'
        · push Not at h2
          have heq := List.getElem_setSlice!_suffix self.data.val t'.val (matrixLen p) i
                      ⟨by rw [hslen']; unfold sOffset at h2; omega, hidatlen⟩
          rw [heq]; exact data_wf i hi
    · exact hbacks'

end Symcrust.Properties.MLKEM.Bridges
