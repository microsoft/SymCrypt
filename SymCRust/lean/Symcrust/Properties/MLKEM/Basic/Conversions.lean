/-
  ML-KEM polynomial / vector bridges — sub-file of `Properties/MLKEM/Basic`.

  Carries `u16ToZq` / `u32ToZq`, the Montgomery factor `R` and its inverse
  `Rinv`, the `PolyElement` / `PolyAccumulator` type abbreviations, the
  `toPoly` / `toMontPoly` / `wfPoly` bridges, and the vector/matrix
  bridges (`toPolyVecOfLen`, `toMontPolyVecOfLen`, `wfPolyVec`,
  `toPolyMatrixOfLen`, `toMontPolyMatrixOfLen`, `mulVecNTTRow`,
  `mulVecNTTRowRinv`).

  This is the only sub-file of `Basic` that imports Mathlib.
-/
import Mathlib.Data.ZMod.Basic
import Symcrust.Code
import Spec.MLKEM.Spec
import Symcrust.Properties.MLKEM.AeneasExtras
import Symcrust.Properties.Axioms.Stdlib
import Symcrust.Properties.MLKEM.Basic.Params

open Aeneas Aeneas.Std Result
open scoped Spec.Notations

namespace Symcrust.Properties.MLKEM

open Spec
open Spec.MLKEM
open Spec.MLKEM.Bounds
open symcrust

/-! ## Coefficient bridges: `U16` / `U32` ↔ `Zq`

ML-KEM stores polynomial coefficients in `U16` (since `q < 2^16 = 65536`) but
does Montgomery arithmetic in `U32` (since intermediate products fit in 32
bits, not 16). Both `u16ToZq` and `u32ToZq` send the underlying nat to its
residue class mod `q`. -/

/-- Coefficient interpretation: the residue class of `u : U16` modulo `q`. -/
@[reducible]
def u16ToZq (u : U16) : Zq := (u.val : Zq)

/-- Coefficient interpretation: the residue class of `u : U32` modulo `q`.
Used by every Montgomery primitive (`mont_mul`, `mod_add`, `mod_sub`) because
SymCrypt widens to 32-bit for the operation. -/
@[reducible]
def u32ToZq (u : U32) : Zq := (u.val : Zq)

/-- The Montgomery factor `R := 2^16 mod q`. Numerically `2285`. -/
def R : Zq := (2 ^ 16 : Zq)

/-- The numeric inverse of `R` in `Zq`. Given as a literal so it is
computable; `R_mul_Rinv` confirms it is the multiplicative inverse. -/
def Rinv : Zq := (169 : Zq)

@[simp] theorem R_eq_2285 : R = (2285 : Zq) := by
  unfold R; decide

@[simp] theorem R_mul_Rinv : R * Rinv = 1 := by
  unfold R Rinv; decide

@[simp] theorem Rinv_mul_R : Rinv * R = 1 := by
  rw [mul_comm]; exact R_mul_Rinv

/-! ## Polynomial-element / accumulator type abbreviations

The Rust code exposes two type aliases for fixed-size arrays of 256
coefficients:

  ```rust
  pub(super) type PolyElement = [u16; MLWE_POLYNOMIAL_COEFFICIENTS];
  pub(super) type PolyElementAccumulator = [u32; MLWE_POLYNOMIAL_COEFFICIENTS];
  ```

Aeneas inlines the aliases during extraction, so callers see
`Array U16 256#usize` / `Array U32 256#usize` directly.  We re-introduce
the aliases at the proof level to make spec statements read like the
Rust headers. -/

/-- A polynomial element: 256 u16 coefficients, matching the Rust type
alias `mlkem::key::PolyElement`. -/
abbrev PolyElement := Array U16 256#usize

/-- A polynomial-element accumulator: 256 u32 slots, matching the Rust
type alias `mlkem::ntt::PolyElementAccumulator`. Each slot carries the
unreduced sum of up to four `MultiplyNTTs`-style products (so a single
Montgomery reduction is pending). -/
abbrev PolyAccumulator := Array U32 256#usize

/-- An accumulator is **zero** when every U32 slot has zero value.  Used
both as a precondition (clean buffer) and as a post-condition (the loop
re-zeros every slot it processed) of the Mont-reduce-and-add loop. -/
def accZero (pa : PolyAccumulator) : Prop :=
  ∀ (k : Fin 256), (pa.val[k.val]'(by have := pa.property; grind)).val = 0

/-! ## Polynomial bridges (`Array U16 256` ↔ `Polynomial q`)

`toPoly` and `toMontPoly` interpret the same buffer two different ways.
The form a buffer is in is *not* runtime data — it is recovered from each
step-spec's postcondition (e.g. "the output of `ntt` is in NTT-standard
form, so `toPoly` is the relevant bridge"). -/

/-- Standard-form interpretation: each coefficient is its u16
representative modulo `q`. -/
def toPoly (a : PolyElement) : Polynomial q :=
  Vector.ofFn fun (i : Fin 256) => u16ToZq (a.val[i.val]'(by have := a.property; grind))

/-- Montgomery-form interpretation: each stored coefficient `c` denotes
the spec value `c · R⁻¹ mod q`. -/
def toMontPoly (a : PolyElement) : Polynomial q :=
  (toPoly a).map (· * Rinv)

/-- Coefficient-bound well-formedness. Required as a precondition by
every modular primitive that takes a `PolyElement`. -/
def wfPoly (a : PolyElement) : Prop :=
  ∀ i (_ : i < 256), a.val[i].val < q

/-- Bridge identity: a Montgomery-form interpretation is the standard-form
interpretation scaled by `R⁻¹`. -/
theorem toMontPoly_eq_toPoly_scalarMul (a : PolyElement) :
    toMontPoly a = (toPoly a).map (· * Rinv) := rfl

/-! ## Vector bridges (`Slice (Array U16 256)` ↔ `PolyVector q k`)

The Rust `Vector` type is the DST `Slice (Array U16 256)` with dynamic
length `k p` (2, 3, or 4). We bridge to `PolyVector q (k p)` whose
underlying `Vector` length is `(k p).val`. -/

/-- Standard-form bridge for a `Slice` of poly elements, parametric in
the destination length `kn`. The precondition `s.length = kn` matches
the wfKey invariant. -/
def toPolyVecOfLen (s : Slice (PolyElement)) (kn : K)
    (h : s.length = (kn : ℕ)) : PolyVector q kn :=
  Vector.ofFn fun (i : Fin kn) => toPoly (s.val[i.val]'(by simp [h]))

/-- Montgomery-form bridge for a `Slice` of poly elements. -/
def toMontPolyVecOfLen (s : Slice (PolyElement)) (kn : K)
    (h : s.length = (kn : ℕ)) : PolyVector q kn :=
  Vector.ofFn fun (i : Fin kn) => toMontPoly (s.val[i.val]'(by simp [h]))

/-- Coefficient-bound well-formedness for a `Slice` of poly elements. -/
def wfPolyVec (s : Slice (PolyElement)) : Prop :=
  ∀ i (_ : i < s.length), wfPoly (s.val[i])

/-! ## Zero buffers (`alloc_zeroed` model)

`try_new_box_default` zero-fills its backing store via
`alloc::alloc::alloc_zeroed` (every byte `0`).  We name the resulting
buffers at the word level — an all-zero `Array U16` — independent of any
`Polynomial q` interpretation, and derive `wf` from them.  These are the
only facts the `BoxDefault` axioms (`Axioms/BoxDefault.lean`) assert. -/

/-- The all-zero polynomial buffer: 256 zero `U16` words. -/
def ZeroPoly : PolyElement := Array.repeat 256#usize 0#u16

/-- An all-zero vector buffer: `n` copies of `ZeroPoly`. -/
def ZeroPolyVec (n : Usize) : Array PolyElement n := Array.repeat n ZeroPoly

/-- `wfPoly` holds of the all-zero buffer (`0 < q`). -/
@[simp] theorem wfPoly_zeroPoly : wfPoly ZeroPoly := by
  intro i hi
  simp only [ZeroPoly, Array.repeat_val, List.getElem_replicate]
  decide

/-- `wfPolyVec` holds of the all-zero vector buffer. -/
@[simp] theorem wfPolyVec_zeroPolyVec (n : Usize) :
    wfPolyVec (ZeroPolyVec n).to_slice := by
  intro i hi
  have hz : (ZeroPolyVec n).to_slice.val[i] = ZeroPoly := by
    simp only [Array.val_to_slice, ZeroPolyVec, Array.repeat_val, List.getElem_replicate]
  rw [hz]; exact wfPoly_zeroPoly

/-- Standard-form bridge from a row-major flat `Slice` of `k²` poly
elements to a `PolyMatrix q k`.  `M[i, j] = toPoly s[i * k + j]`. -/
def toPolyMatrixOfLen (s : Slice (PolyElement)) (kn : K)
    (h : s.length = (kn : ℕ) * (kn : ℕ)) : PolyMatrix q kn :=
  Matrix.of fun (i j : Fin kn) =>
    toPoly (s.val[i.val * (kn : ℕ) + j.val]'(by grind))

/-- Montgomery-form bridge from a row-major flat `Slice` to a `PolyMatrix`. -/
def toMontPolyMatrixOfLen (s : Slice (PolyElement)) (kn : K)
    (h : s.length = (kn : ℕ) * (kn : ℕ)) : PolyMatrix q kn :=
  Matrix.of fun (i j : Fin kn) =>
    toMontPoly (s.val[i.val * (kn : ℕ) + j.val]'(by grind))

/-! ## MulVectorNTT row helpers

These package the common matrix-vector-product row component used in
`matrix_vector_mont_mul_and_add` postconditions.  They hide the
`toPolyMatrixOfLen` / `toPolyVecOfLen` bridges and the `Fin kn` index
behind a single named term. -/

/-- Row `i` of `A · s` in NTT domain (no Mont scaling). -/
noncomputable def mulVecNTTRow
    (pm pv : Slice (PolyElement)) (kn : K)
    (h_pm : pm.length = (kn : ℕ) * (kn : ℕ))
    (h_pv : pv.length = (kn : ℕ))
    (i : Fin kn) : Polynomial q :=
  (MLKEM.PolyMatrix.MulVectorNTT
    (toPolyMatrixOfLen pm kn h_pm)
    (toPolyVecOfLen pv kn h_pv)).get i

/-- Row `i` of `Rinv · A · s` in NTT domain — the standalone form of the
Mont-mat-vec-mul-and-add accumulator absorbed into a single row. -/
noncomputable def mulVecNTTRowRinv
    (pm pv : Slice (PolyElement)) (kn : K)
    (h_pm : pm.length = (kn : ℕ) * (kn : ℕ))
    (h_pv : pv.length = (kn : ℕ))
    (i : Fin kn) : Polynomial q :=
  (mulVecNTTRow pm pv kn h_pm h_pv i).map (Rinv * ·)

end Symcrust.Properties.MLKEM
