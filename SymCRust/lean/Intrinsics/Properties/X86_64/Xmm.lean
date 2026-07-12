/-
  `@[step]` theorems for the Rust SSE2 models of intrinsics
  `verify.intrinsics.x86_64.xmm.*` extracted to `Symcrust/Code/*`.

  See `INTRINSICS.md` for the layered architecture.
-/
import Symcrust.Code.Funs
import Intrinsics.Properties.X86_64.Sse2
import Intrinsics.Properties.Lanes
import Intrinsics.Simd

open Aeneas Aeneas.Std Intrinsics.X86_64 Intrinsics

local macro_rules
| `(tactic| get_elem_tactic) => `(tactic| first | (simp only [Aeneas.Std.Array.length_eq]; first | assumption | scalar_tac) | assumption | scalar_tac | grind)

namespace symcrust

/-! ## Lane-view ↔ per-byte bridge lemmas (16 bytes ↔ 8 × U16, little-endian) -/

open Intrinsics.X86_64 in
/-- `.bv` form: lane `k` of `M128.u16x8 b` decomposes into its two LE bytes. -/
theorem M128.u16x8_bv_getElem (b : M128) (k : ℕ) (hk : k < 8) :
    ((M128.u16x8 b)[k]).bv = b[2*k + 1].bv ++ b[2*k].bv := by
  rw [M128.u16x8_getElem b k hk]

/-! ## Reusable composition bridges -/

open Intrinsics.X86_64 in
/-- **(b) byte→u16 bitwise AND bridge.** -/
theorem M128.u16x8_and_lane (a b r : M128)
    (hr : ∀ k, (hk : k < 16) → r[k] = a[k] &&& b[k])
    (k : ℕ) (hk : k < 8) :
    (M128.u16x8 r)[k] =
      (M128.u16x8 a)[k] &&& (M128.u16x8 b)[k] := by
  apply U16.bv_eq_imp_eq
  simp only [UScalar.bv_and, M128.u16x8_bv_getElem _ k hk]
  have hr0 : r[2*k] = a[2*k] &&& b[2*k] := hr (2*k) (by scalar_tac)
  have hr1 : r[2*k + 1] = a[2*k + 1] &&& b[2*k + 1] := hr (2*k + 1) (by scalar_tac)
  rw [hr0, hr1]
  simp only [UScalar.bv_and]
  rw [_root_.BitVec.and_append]

open Intrinsics.X86_64 in
/-- **(b') byte→u16 bitwise AND-NOT bridge.** -/
theorem M128.u16x8_andnot_lane (a b r : M128)
    (hr : ∀ k, (hk : k < 16) →
      r[k] = (~~~ a[k]) &&& b[k])
    (k : ℕ) (hk : k < 8) :
    (M128.u16x8 r)[k] =
      (~~~ (M128.u16x8 a)[k]) &&& (M128.u16x8 b)[k] := by
  apply U16.bv_eq_imp_eq
  simp only [UScalar.bv_and, UScalar.bv_not, M128.u16x8_bv_getElem _ k hk]
  have hr0 : r[2*k] = (~~~ a[2*k]) &&& b[2*k] := hr (2*k) (by scalar_tac)
  have hr1 : r[2*k + 1] = (~~~ a[2*k + 1]) &&& b[2*k + 1] := hr (2*k + 1) (by scalar_tac)
  rw [hr0, hr1]
  simp only [UScalar.bv_and, UScalar.bv_not]
  rw [_root_.BitVec.not_append, _root_.BitVec.and_append]

/-! ## `@[step]` theorems for the 9 modelled `xmm` lane ops -/

/-- 16-bit lane wrapping add (byte-carrier view). -/
@[step] theorem verify.intrinsics.x86_64.xmm.add_epi16.spec (a b : M128) :
  verify.intrinsics.x86_64.xmm.add_epi16 a b
  ⦃ (r : M128) => ∀ k, (hk : k < 8) →
      (M128.u16x8 r)[k] =
        core.num.U16.wrapping_add (M128.u16x8 a)[k] (M128.u16x8 b)[k] ⦄ := by
  unfold verify.intrinsics.x86_64.xmm.add_epi16
  step*
  rename_i k
  rw [M128.u16x8_of_bv r_post1, M128.u16x8_of_bv a1_post.symm, M128.u16x8_of_bv a2_post.symm]
  exact a3_post k r_post2

/-- 16-bit lane wrapping sub (byte-carrier view). -/
@[step] theorem verify.intrinsics.x86_64.xmm.sub_epi16.spec (a b : M128) :
  verify.intrinsics.x86_64.xmm.sub_epi16 a b
  ⦃ (r : M128) => ∀ k, (hk : k < 8) →
      (M128.u16x8 r)[k] =
        core.num.U16.wrapping_sub (M128.u16x8 a)[k] (M128.u16x8 b)[k] ⦄ := by
  unfold verify.intrinsics.x86_64.xmm.sub_epi16
  step*
  rename_i k
  rw [M128.u16x8_of_bv r_post1, M128.u16x8_of_bv a1_post.symm, M128.u16x8_of_bv a2_post.symm]
  exact a3_post k r_post2

/-- 16-bit lane wrapping mul (low half, byte-carrier view). -/
@[step] theorem verify.intrinsics.x86_64.xmm.mullo_epi16.spec (a b : M128) :
  verify.intrinsics.x86_64.xmm.mullo_epi16 a b
  ⦃ (r : M128) => ∀ k, (hk : k < 8) →
      (M128.u16x8 r)[k] =
        core.num.U16.wrapping_mul (M128.u16x8 a)[k] (M128.u16x8 b)[k] ⦄ := by
  unfold verify.intrinsics.x86_64.xmm.mullo_epi16
  step*
  rename_i k
  rw [M128.u16x8_of_bv r_post1, M128.u16x8_of_bv a1_post.symm, M128.u16x8_of_bv a2_post.symm]
  exact a3_post k r_post2

/-- 16-bit lane high-half multiply (unsigned, byte-carrier view). -/
@[step] theorem verify.intrinsics.x86_64.xmm.mulhi_epu16.spec (a b : M128) :
  verify.intrinsics.x86_64.xmm.mulhi_epu16 a b
  ⦃ (r : M128) => ∀ k, (hk : k < 8) →
      (M128.u16x8 r)[k].val =
        ((M128.u16x8 a)[k].val * (M128.u16x8 b)[k].val) / 65536 ⦄ := by
  unfold verify.intrinsics.x86_64.xmm.mulhi_epu16
  step*
  rename_i k
  rw [M128.u16x8_of_bv r_post1, M128.u16x8_of_bv a1_post.symm, M128.u16x8_of_bv a2_post.symm]
  exact a3_post k r_post2

/-- 16-bit lane equality mask (byte-carrier view). -/
@[step] theorem verify.intrinsics.x86_64.xmm.cmpeq_epi16.spec (a b : M128) :
  verify.intrinsics.x86_64.xmm.cmpeq_epi16 a b
  ⦃ (r : M128) => ∀ k, (hk : k < 8) →
      (M128.u16x8 r)[k] =
        if (M128.u16x8 a)[k] = (M128.u16x8 b)[k] then 65535#u16 else 0#u16 ⦄ := by
  unfold verify.intrinsics.x86_64.xmm.cmpeq_epi16
  step*
  rename_i k
  rw [M128.u16x8_of_bv r_post1, M128.u16x8_of_bv a1_post.symm, M128.u16x8_of_bv a2_post.symm]
  exact a3_post k r_post2

/-- 16-bit lane signed greater-than mask (byte-carrier view). -/
@[step] theorem verify.intrinsics.x86_64.xmm.cmpgt_epi16.spec (a b : M128) :
  verify.intrinsics.x86_64.xmm.cmpgt_epi16 a b
  ⦃ (r : M128) => ∀ k, (hk : k < 8) →
      (M128.u16x8 r)[k] =
        if (M128.u16x8 a)[k].bv.toInt > (M128.u16x8 b)[k].bv.toInt
        then 65535#u16 else 0#u16 ⦄ := by
  unfold verify.intrinsics.x86_64.xmm.cmpgt_epi16
  step*
  rename_i k
  rw [M128.u16x8_of_bv r_post1, M128.u16x8_of_bv a1_post.symm, M128.u16x8_of_bv a2_post.symm]
  exact a3_post k r_post2

/-- Broadcast a 16-bit value across 8 lanes (byte-carrier view). -/
@[step] theorem verify.intrinsics.x86_64.xmm.set1_epi16.spec (v : Std.I16) :
  verify.intrinsics.x86_64.xmm.set1_epi16 v
  ⦃ (r : M128) => ∀ k, (hk : k < 8) → (M128.u16x8 r)[k].bv = v.bv ⦄ := by
  unfold verify.intrinsics.x86_64.xmm.set1_epi16
  step*
  rename_i k
  rw [M128.u16x8_of_bv r_post1, a_post, Std.Array.getElem_repeat _ _ k (by scalar_tac)]

/-- Byte-wise AND, lifted to the u16 lane view. -/
@[step] theorem verify.intrinsics.x86_64.xmm.and_si128.spec (a b : M128) :
  verify.intrinsics.x86_64.xmm.and_si128 a b
  ⦃ (r : M128) => ∀ k, (hk : k < 8) →
      (M128.u16x8 r)[k] = (M128.u16x8 a)[k] &&& (M128.u16x8 b)[k] ⦄ := by
  unfold verify.intrinsics.x86_64.xmm.and_si128
  step*
  rename_i k
  exact M128.u16x8_and_lane a b r (fun j hj => r_post1 j hj) k r_post2

/-- Byte-wise AND-NOT, lifted to the u16 lane view. -/
@[step] theorem verify.intrinsics.x86_64.xmm.andnot_si128.spec (a b : M128) :
  verify.intrinsics.x86_64.xmm.andnot_si128 a b
  ⦃ (r : M128) => ∀ k, (hk : k < 8) →
      (M128.u16x8 r)[k] = (~~~ (M128.u16x8 a)[k]) &&& (M128.u16x8 b)[k] ⦄ := by
  unfold verify.intrinsics.x86_64.xmm.andnot_si128
  step*
  rename_i k
  exact M128.u16x8_andnot_lane a b r (fun j hj => r_post1 j hj) k r_post2
