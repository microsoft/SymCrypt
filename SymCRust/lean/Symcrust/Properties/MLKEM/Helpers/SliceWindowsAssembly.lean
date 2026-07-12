/-
  # Helpers/SliceWindowsAssembly.lean

  Per-row → full-slice assembly bridge for `sliceToSpecBytes`.

  ## Use case

  The Encaps ciphertext u-side is produced row-by-row in a `for` loop
  that writes each `Wd = 32 * dᵤ` byte window of a length-`k * Wd`
  output slice.  The accumulated postcondition is per-row:
  ```
  ∀ i < k, sliceWindowToSpecBytes s (i * Wd) Wd _
           = ByteEncode dᵤ (Compress dᵤ (toPoly pv[i]))
  ```
  but the goal at the call site asks for the full slice:
  ```
  sliceToSpecBytes s (k * Wd) _ = compressEncodePolyVector dᵤ (toPoly_vec pv)
  ```
  The bridge `sliceToSpecBytes_eq_of_windows` converts the per-row facts
  into the full-slice equality, by pointwise comparison via
  `Vector.ext` and `k = (k / Wd) * Wd + k % Wd`.
-/

import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.Encoding

namespace Symcrust.Properties.MLKEM.Helpers

open Symcrust
open Symcrust.Properties.MLKEM
open Symcrust.Properties.MLKEM.Bridges
open Spec
open Aeneas.Std

/-- If every `Wd`-wide window of a slice `s` of length `n * Wd` agrees
with the corresponding window of `target`, then `s` as a whole encodes
`target`.

This is the per-row → full assembly lemma used to discharge the u-side
of the Encaps ciphertext: per-row `ByteEncode(Compress dᵤ ·)` window
equalities assemble into the full slice's `sliceToSpecBytes` value. -/
theorem sliceToSpecBytes_eq_of_windows
    (s : Slice U8) (n Wd : ℕ) (hpos : 0 < Wd)
    (h_s_len : s.length = n * Wd)
    (target : Spec.𝔹 (n * Wd))
    (h_rows : ∀ (i : ℕ) (h_i : i < n),
        ∃ (h_window : (i + 1) * Wd ≤ s.length),
          sliceWindowToSpecBytes s (i * Wd) Wd
              (Nat.add_one_mul _ _ ▸ h_window)
            = Vector.ofFn fun (j : Fin Wd) =>
                target[i * Wd + j.val]'(by
                  have hj := j.isLt
                  calc i * Wd + j.val < i * Wd + Wd := by omega
                    _ = (i + 1) * Wd := by ring
                    _ ≤ n * Wd := Nat.mul_le_mul_right _ h_i)) :
    sliceToSpecBytes s (n * Wd) h_s_len = target := by
  apply Vector.ext
  intro k hk
  have hi_lt : k / Wd < n := Nat.div_lt_of_lt_mul (by rw [Nat.mul_comm]; exact hk)
  have hr_lt : k % Wd < Wd := Nat.mod_lt _ hpos
  have hk_eq : k / Wd * Wd + k % Wd = k := Nat.div_add_mod' k Wd
  obtain ⟨h_window, h_row⟩ := h_rows (k / Wd) hi_lt
  have h_row_r := congrArg (·[k % Wd]'hr_lt) h_row
  simp [sliceWindowToSpecBytes, Vector.getElem_ofFn] at h_row_r
  show (sliceToSpecBytes s (n * Wd) h_s_len)[k]'hk = target[k]'hk
  simp only [sliceToSpecBytes, Vector.getElem_ofFn]
  have h_lhs : (s.val)[k]'(by simp only [Slice.length] at h_s_len; rw [h_s_len]; exact hk)
             = (s.val)[k / Wd * Wd + k % Wd]'(by
                  simp only [Slice.length] at h_s_len; rw [h_s_len, hk_eq]; exact hk) :=
    getElem_congr rfl hk_eq.symm _
  have h_rhs : target[k]'hk = target[k / Wd * Wd + k % Wd]'(by rw [hk_eq]; exact hk) :=
    getElem_congr rfl hk_eq.symm _
  rw [h_lhs, h_rhs]
  exact h_row_r

/-- Specialised form of `sliceToSpecBytes_eq_of_windows` for the
`PolyVector.ByteEncode` case: per-row `ByteEncode d pv[i]` window
equalities assemble into the full `PolyVector.ByteEncode d pv`. -/
theorem polyVector_byteEncode_eq_of_per_window
    {kk : MLKEM.K} (d : ℕ) (h_d : 1 ≤ d ∧ d ≤ 12)
    (s : Slice U8)
    (h_s_len : s.length = (kk : ℕ) * (32 * d))
    (pv : MLKEM.PolyVector (MLKEM.m d) kk)
    (h_rows : ∀ (i : ℕ) (h_i : i < (kk : ℕ)),
        ∃ (h_window : (i + 1) * (32 * d) ≤ s.length),
          sliceWindowToSpecBytes s (i * (32 * d)) (32 * d)
              (Nat.add_one_mul _ _ ▸ h_window)
            = MLKEM.ByteEncode d (pv[i]'h_i) h_d) :
    sliceToSpecBytes s ((kk : ℕ) * (32 * d)) h_s_len =
        MLKEM.PolyVector.ByteEncode d pv h_d := by
  apply sliceToSpecBytes_eq_of_windows s (kk : ℕ) (32 * d)
    (by have := h_d.1; omega) h_s_len
  intro i h_i
  obtain ⟨h_window, h_row⟩ := h_rows i h_i
  refine ⟨h_window, ?_⟩
  rw [h_row]
  apply Vector.ext
  intro j hj
  rw [Vector.getElem_ofFn]
  have hbnd : 32 * d * i + 32 * d ≤ 32 * d * (kk : ℕ) :=
    MLKEM.Bounds.poly_vec_decode_idx_le d i h_i
  have h_slice := polyVector_slice_byteEncode_eq d h_d pv i h_i hbnd
  have h_get := congrArg (·[j]'hj) h_slice
  simp only [Spec.slice, Vector.getElem_ofFn, Vector.getElem_cast] at h_get
  rw [← h_get]
  fcongr 1
  ring

/-- Combined window-assembly + `compressEncodePoly` collapse: given
per-row `compressEncodePoly` window equalities for an implementation
poly vector, produce the full-slice `PolyVector.ByteEncode (Compress)`
spec form.

Restricted to `d < 12` because `MLKEM.Polynomial.Compress` is only
defined there (the `compressEncodePoly` `d = 12` branch is handled in
the `t̂`-key residual D1 path — see `key_expand_residual_D1_helper`). -/
theorem polyVector_byteEncode_compress_of_per_window
    {kk : MLKEM.K} (d : ℕ) (h_d : 1 ≤ d ∧ d < 12)
    (s : Slice U8)
    (h_s_len : s.length = (kk : ℕ) * (32 * d))
    (pv : MLKEM.PolyVector MLKEM.q kk)
    (h_rows : ∀ (i : ℕ) (h_i : i < (kk : ℕ)),
        ∃ (h_window : (i + 1) * (32 * d) ≤ s.length),
          sliceWindowToSpecBytes s (i * (32 * d)) (32 * d)
              (Nat.add_one_mul _ _ ▸ h_window)
            = compressEncodePoly d (pv[i]'h_i) (by omega)) :
    sliceToSpecBytes s ((kk : ℕ) * (32 * d)) h_s_len =
        MLKEM.PolyVector.ByteEncode d (MLKEM.PolyVector.Compress d pv h_d)
          (by omega) := by
  apply polyVector_byteEncode_eq_of_per_window d (by omega) s h_s_len
    (MLKEM.PolyVector.Compress d pv h_d)
  intro i h_i
  obtain ⟨h_window, h_row⟩ := h_rows i h_i
  refine ⟨h_window, ?_⟩
  rw [h_row]
  unfold compressEncodePoly
  have hlt : d < 12 := h_d.2
  simp only [hlt, dite_true]
  show MLKEM.ByteEncode d (MLKEM.Polynomial.Compress d (pv[i]'h_i) ⟨h_d.1, hlt⟩) _ =
       MLKEM.ByteEncode d ((MLKEM.PolyVector.Compress d pv h_d)[i]'h_i) _
  unfold MLKEM.PolyVector.Compress
  rw [Vector.getElem_map]

end Symcrust.Properties.MLKEM.Helpers
