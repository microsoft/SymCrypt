/-
  Public NEON Layer-1 surface.

  `@[step]` theorems for the Rust models of intrinsics
  `verify.intrinsics.aarch64.neon.*` extracted to `Symcrust/Code/*`.

  See `INTRINSICS.md` for the layered architecture.
-/
import Symcrust.Code.Funs
import Intrinsics.Properties.Lanewise
import Intrinsics.Properties.Lanes
import Intrinsics.Properties.IterRange
import Intrinsics.Simd

open Aeneas Aeneas.Std Intrinsics

/- Override get_elem_tactic so that `a[k]` with hypothesis `k < N.val`
   (and similarly `k < a.length`) auto-discharges through `agrind`.
   Same convention as `X86_64/Sse2.lean`. -/
local macro_rules
| `(tactic| get_elem_tactic) => `(tactic| first | assumption | grind)

/- Widening `UScalar.cast` is value-preserving (no overflow): register the
   Aeneas spec as a local `step` rule so `step*` extracts `y.val = x.val`
   posts for the `lift (UScalar.cast .U32 _)` binds in the `vmull*`/`vmlal*`
   loop bodies (instead of leaving the cast definitional). -/
attribute [local step] Std.UScalar.cast_inBounds_spec

namespace symcrust

/-! ## §1. Lanewise-delegated wrappers

These wrappers are 1-line shims; the post mirrors the corresponding
layer-2 spec in `Intrinsics/Properties/Lanewise.lean`. -/

/-- 16-bit lane wrapping add (8 lanes). -/
@[step] theorem verify.intrinsics.aarch64.neon.vaddq_u16.spec
    (a b : U16x8) :
  verify.intrinsics.aarch64.neon.vaddq_u16 a b
  ⦃ (r : U16x8) =>
    ∀ k, (hk : k < 8) →
      r[k] = core.num.U16.wrapping_add a[k] b[k] ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vaddq_u16
  step*

/-- 16-bit lane wrapping sub (8 lanes). -/
@[step] theorem verify.intrinsics.aarch64.neon.vsubq_u16.spec
    (a b : U16x8) :
  verify.intrinsics.aarch64.neon.vsubq_u16 a b
  ⦃ (r : U16x8) =>
    ∀ k, (hk : k < 8) →
      r[k] = core.num.U16.wrapping_sub a[k] b[k] ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vsubq_u16
  step*

/-- 16-bit lane wrapping mul (low half, 8 lanes). -/
@[step] theorem verify.intrinsics.aarch64.neon.vmulq_u16.spec
    (a b : U16x8) :
  verify.intrinsics.aarch64.neon.vmulq_u16 a b
  ⦃ (r : U16x8) =>
    ∀ k, (hk : k < 8) →
      r[k] = core.num.U16.wrapping_mul a[k] b[k] ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vmulq_u16
  step*

/-- 16-bit lanewise AND (8 lanes). -/
@[step] theorem verify.intrinsics.aarch64.neon.vandq_u16.spec
    (a b : U16x8) :
  verify.intrinsics.aarch64.neon.vandq_u16 a b
  ⦃ (r : U16x8) =>
    ∀ k, (hk : k < 8) →
      r[k] = a[k] &&& b[k] ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vandq_u16
  step*

/-- 8-bit lanewise XOR (16 lanes). -/
@[step] theorem verify.intrinsics.aarch64.neon.veorq_u8.spec
    (a b : U8x16) :
  verify.intrinsics.aarch64.neon.veorq_u8 a b
  ⦃ (r : U8x16) =>
    ∀ k, (hk : k < 16) →
      r[k] = a[k] ^^^ b[k] ⦄ := by
  unfold verify.intrinsics.aarch64.neon.veorq_u8
  step*

/-! ## §2. Broadcast / duplicate (`vdupq_n_*`)

`vdupq_n_T(a)` returns `[a; N]` where `N = 128 / sizeof(T)`. -/

/-- Broadcast a u16 to 8 lanes. -/
@[step] theorem verify.intrinsics.aarch64.neon.vdupq_n_u16.spec
    (a : Std.U16) :
  verify.intrinsics.aarch64.neon.vdupq_n_u16 a
  ⦃ (r : U16x8) =>
    ∀ k, (hk : k < 8) → r[k] = a ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vdupq_n_u16
  intro k hk
  simp_lists [Std.Array.repeat_val]

/-- Broadcast a u32 to 4 lanes. -/
@[step] theorem verify.intrinsics.aarch64.neon.vdupq_n_u32.spec
    (a : Std.U32) :
  verify.intrinsics.aarch64.neon.vdupq_n_u32 a
  ⦃ (r : U32x4) =>
    ∀ k, (hk : k < 4) → r[k] = a ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vdupq_n_u32
  intro k hk
  simp_lists [Std.Array.repeat_val]

/-- Broadcast a u64 to 2 lanes. -/
@[step] theorem verify.intrinsics.aarch64.neon.vdupq_n_u64.spec
    (a : Std.U64) :
  verify.intrinsics.aarch64.neon.vdupq_n_u64 a
  ⦃ (r : U64x2) =>
    ∀ k, (hk : k < 2) → r[k] = a ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vdupq_n_u64
  intro k hk
  simp_lists [Std.Array.repeat_val]

/-! ## §3. Lane extraction (`vget_low_*`, `vgetq_lane_*`)

`vget_low_T(v)` returns the low half of `v` (lanes 0..N/2-1).
`vgetq_lane_T(v, LANE)` extracts a single lane at a const-generic index. -/

/-- Extract the low 4 u16 lanes of a 8-lane u16 vector. -/
@[step] theorem verify.intrinsics.aarch64.neon.vget_low_u16.spec
    (v : U16x8) :
  verify.intrinsics.aarch64.neon.vget_low_u16 v
  ⦃ (r : U16x4) =>
    ∀ k, (hk : k < 4) → r[k] = v[k] ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vget_low_u16
  step*
  intro k hk
  subst_vars
  rcases (show k = 0 ∨ k = 1 ∨ k = 2 ∨ k = 3 from by agrind)
    with rfl | rfl | rfl | rfl <;> rfl

/-- Extract the low 2 u32 lanes of a 4-lane u32 vector. -/
@[step] theorem verify.intrinsics.aarch64.neon.vget_low_u32.spec
    (v : U32x4) :
  verify.intrinsics.aarch64.neon.vget_low_u32 v
  ⦃ (r : U32x2) =>
    ∀ k, (hk : k < 2) → r[k] = v[k] ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vget_low_u32
  step*
  intro k hk
  subst_vars
  rcases (show k = 0 ∨ k = 1 from by scalar_tac)
    with rfl | rfl <;> rfl

/-! ## §4. Slice → register broadcast loads (`vld1q_dup_*`)

`vld1q_dup_T(arr, at1)` reads one element from `arr[at1]` and broadcasts
it to all N lanes. -/

/-- Load one u32 from `arr[at1]` and broadcast to 4 lanes. -/
@[step] theorem verify.intrinsics.aarch64.neon.vld1q_dup_u32.spec
    (arr : Slice Std.U32) (at1 : Std.Usize)
    (h_at : at1.val < arr.length) :
  verify.intrinsics.aarch64.neon.vld1q_dup_u32 arr at1
  ⦃ (r : U32x4) =>
    ∀ k, (hk : k < 4) → r[k] = arr[at1.val]'(h_at) ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vld1q_dup_u32
  step*
  intro k hk
  exact Std.Array.getElem_repeat_eq i_post

/-- Load one u64 from `arr[at1]` and broadcast to 2 lanes. -/
@[step] theorem verify.intrinsics.aarch64.neon.vld1q_dup_u64.spec
    (arr : Slice Std.U64) (at1 : Std.Usize)
    (h_at : at1.val < arr.length) :
  verify.intrinsics.aarch64.neon.vld1q_dup_u64 arr at1
  ⦃ (r : U64x2) =>
    ∀ k, (hk : k < 2) → r[k] = arr[at1.val]'(h_at) ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vld1q_dup_u64
  step*
  intro k hk
  exact Std.Array.getElem_repeat_eq i_post

/-! ## §5. Cross-lane reinterprets (delegate to `lanes.*`) -/

/-- Reinterpret 16 u8 lanes as 8 u16 lanes (little-endian).  Inherits the
    post from `lanes.bytes_to_words.spec`. -/
@[step] theorem verify.intrinsics.aarch64.neon.vreinterpretq_u16_u8.spec
    (v : U8x16) :
  verify.intrinsics.aarch64.neon.vreinterpretq_u16_u8 v
  ⦃ (r : U16x8) =>
    r = M128.u16x8 v ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vreinterpretq_u16_u8
  step*
  exact (M128.u16x8_of_bv r_post.symm).symm

/-- Reinterpret 8 u16 lanes as 16 u8 lanes (little-endian).  Round-trip form:
    the `u16x8` byte-view of the result recovers the input. -/
@[step] theorem verify.intrinsics.aarch64.neon.vreinterpretq_u8_u16.spec
    (v : U16x8) :
  verify.intrinsics.aarch64.neon.vreinterpretq_u8_u16 v
  ⦃ (r : U8x16) =>
    M128.u16x8 r = v ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vreinterpretq_u8_u16
  step*
  exact M128.u16x8_of_bv r_post

/-- Reinterpret 4 u32 lanes as 16 u8 lanes (little-endian).  Round-trip form:
    the `u32x4` byte-view of the result recovers the input. -/
@[step] theorem verify.intrinsics.aarch64.neon.vreinterpretq_u8_u32.spec
    (v : U32x4) :
  verify.intrinsics.aarch64.neon.vreinterpretq_u8_u32 v
  ⦃ (r : U8x16) =>
    M128.u32x4 r = v ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vreinterpretq_u8_u32
  step*
  exact M128.u32x4_of_bv r_post

/-- Reinterpret 2 u64 lanes as 16 u8 lanes (little-endian).  Round-trip form:
    the `u64x2` byte-view of the result recovers the input. -/
@[step] theorem verify.intrinsics.aarch64.neon.vreinterpretq_u8_u64.spec
    (v : U64x2) :
  verify.intrinsics.aarch64.neon.vreinterpretq_u8_u64 v
  ⦃ (r : U8x16) =>
    M128.u64x2 r = v ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vreinterpretq_u8_u64
  step*
  exact M128.u64x2_of_bv r_post

/-- Reinterpret 16 u8 lanes as 4 u32 lanes (little-endian).  Inherits the
    `u32x4` post from `lanes.bytes_to_dwords.spec`. -/
@[step] theorem verify.intrinsics.aarch64.neon.vreinterpretq_u32_u8.spec
    (v : U8x16) :
  verify.intrinsics.aarch64.neon.vreinterpretq_u32_u8 v
  ⦃ (r : U32x4) =>
    r = M128.u32x4 v ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vreinterpretq_u32_u8
  step*
  exact (M128.u32x4_of_bv r_post.symm).symm

/-- Extract the u32 lane at compile-time index `LANE` (must be in `0..4`). -/
@[step] theorem verify.intrinsics.aarch64.neon.vgetq_lane_u32.spec
    (LANE : Std.I32) (v : U32x4) (h : 0 ≤ LANE.val ∧ LANE.val < 4) :
  verify.intrinsics.aarch64.neon.vgetq_lane_u32 LANE v
  ⦃ (r : Std.U32) =>
    r = v[LANE.val.toNat]'(by
      obtain ⟨h0, h1⟩ := h
      have h2 : LANE.val.toNat < 4 := by rw [Int.toNat_lt h0]; exact_mod_cast h1
      have := v.property
      scalar_tac) ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vgetq_lane_u32
  have hc_bnd : 0 ≤ LANE.val ∧ LANE.val ≤ Std.UScalar.max .Usize := ⟨h.1, by scalar_tac⟩
  step with IScalar.hcast_inBounds_spec as ⟨i, hi⟩
  have hidx : i.val = LANE.val.toNat := by scalar_tac
  step*

/-! ## §6. Per-shim `@[step]` specs -/

/-- Loop companion for `vcgeq_u16`: below the cursor the accumulator `out`
    is framed; at and above the cursor each lane carries the ≥-mask. -/
@[step] theorem verify.intrinsics.aarch64.neon.vcgeq_u16_loop.spec
    (iter : core.ops.range.Range Std.Usize) (a b out : U16x8)
    (hStart : iter.start.val ≤ 8) (hEnd : iter.«end».val = 8) :
  verify.intrinsics.aarch64.neon.vcgeq_u16_loop iter a b out
  ⦃ (r : U16x8) =>
    (∀ k, (hk : k < iter.start.val) → r[k] = out[k]) ∧
    (∀ k, iter.start.val ≤ k → (hk : k < 8) →
      r[k] = if a[k].val ≥ b[k].val then 65535#u16 else 0#u16) ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vcgeq_u16_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← iter_next_some
    rw [hsome]
    dsimp only
    simp only [← apply_ite Result.ok]
    step*
    have ha1_at : a1[iter.start.val] = (if i1 ≥ i2 then 65535#u16 else 0#u16) := by
      grind
    have ha1_other : ∀ k, k ≠ iter.start.val → (hk : k < 8) → a1[k] = out[k] := by
      grind
    refine ⟨?_, ?_⟩
    · intro k hk
      have hk1 : k < iter1.start.val := by rw [hstart']; scalar_tac
      have e1 : r[k] = a1[k] := r_post1 k hk1
      rw [e1, ha1_other k (by scalar_tac) (by scalar_tac)]
    · intro k hk_lo hk_hi
      by_cases heq : k = iter.start.val
      · subst heq
        have hk1 : iter.start.val < iter1.start.val := by rw [hstart']; scalar_tac
        have e1 : r[iter.start.val] = a1[iter.start.val] := r_post1 iter.start.val hk1
        rw [e1, ha1_at, i1_post, i2_post]
        agrind
      · have hk1 : iter1.start.val ≤ k := by rw [hstart']; scalar_tac
        exact r_post2 k hk1 hk_hi
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← iter_next_none
    rw [hnone]
    dsimp only
    simp only [WP.spec_ok]
    refine ⟨?_, ?_⟩
    · intro k hk; trivial
    · intro k hk_lo hk_hi; scalar_tac
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- 16-bit lane unsigned ≥ mask (per-lane 0xFFFF if a≥b else 0). -/
@[step] theorem verify.intrinsics.aarch64.neon.vcgeq_u16.spec
    (a b : U16x8) :
  verify.intrinsics.aarch64.neon.vcgeq_u16 a b
  ⦃ (r : U16x8) =>
    ∀ k, (hk : k < 8) →
      r[k] = if a[k].val ≥ b[k].val then 65535#u16 else 0#u16 ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vcgeq_u16
  step with verify.intrinsics.aarch64.neon.vcgeq_u16_loop.spec
  exact r_post2 _ (by scalar_tac) (by assumption)

/-- Loop companion for `vcltzq_s16`. -/
@[step] theorem verify.intrinsics.aarch64.neon.vcltzq_s16_loop.spec
    (iter : core.ops.range.Range Std.Usize) (a : Array Std.I16 8#usize)
    (out : U16x8)
    (hStart : iter.start.val ≤ 8) (hEnd : iter.«end».val = 8) :
  verify.intrinsics.aarch64.neon.vcltzq_s16_loop iter a out
  ⦃ (r : U16x8) =>
    (∀ k, (hk : k < iter.start.val) → r[k] = out[k]) ∧
    (∀ k, iter.start.val ≤ k → (hk : k < 8) →
      r[k] = if a[k].val < 0 then 65535#u16 else 0#u16) ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vcltzq_s16_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← iter_next_some
    rw [hsome]
    dsimp only
    simp only [← apply_ite Result.ok]
    step*
    have ha1_other : ∀ k, k ≠ iter.start.val → (hk : k < 8) → a1[k] = out[k] := by
      intro k hne hk
      rw [a1_post]; simp_lists
    refine ⟨?_, ?_⟩
    · intro k hk
      have hk1 : k < iter1.start.val := by rw [hstart']; scalar_tac
      rw [r_post1 k hk1, ha1_other k (by scalar_tac) (by scalar_tac)]
    · intro k hk_lo hk_hi
      by_cases heq : k = iter.start.val
      · subst heq
        have hk1 : iter.start.val < iter1.start.val := by rw [hstart']; scalar_tac
        rw [r_post1 iter.start.val hk1, a1_post]
        simp_lists
        rw [i1_post]
        agrind
      · have hk1 : iter1.start.val ≤ k := by rw [hstart']; scalar_tac
        exact r_post2 k hk1 hk_hi
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← iter_next_none
    rw [hnone]
    dsimp only
    simp only [WP.spec_ok]
    refine ⟨?_, ?_⟩
    · intro k hk; trivial
    · intro k hk_lo hk_hi; scalar_tac
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- 16-bit lane signed less-than-zero mask. -/
@[step] theorem verify.intrinsics.aarch64.neon.vcltzq_s16.spec
    (a : Array Std.I16 8#usize) :
  verify.intrinsics.aarch64.neon.vcltzq_s16 a
  ⦃ (r : U16x8) =>
    ∀ k, (hk : k < 8) →
      r[k] = if a[k].val < 0 then 65535#u16 else 0#u16 ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vcltzq_s16
  step with verify.intrinsics.aarch64.neon.vcltzq_s16_loop.spec
  exact r_post2 _ (by scalar_tac) (by assumption)

/-- Loop companion for `vmull_u16`. -/
@[step] theorem verify.intrinsics.aarch64.neon.vmull_u16_loop.spec
    (iter : core.ops.range.Range Std.Usize) (a b : U16x4) (out : U32x4)
    (hStart : iter.start.val ≤ 4) (hEnd : iter.«end».val = 4) :
  verify.intrinsics.aarch64.neon.vmull_u16_loop iter a b out
  ⦃ (r : U32x4) =>
    (∀ k, (hk : k < iter.start.val) → r[k] = out[k]) ∧
    (∀ k, iter.start.val ≤ k → (hk : k < 4) →
      r[k].val = a[k].val * b[k].val) ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vmull_u16_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← iter_next_some
    rw [hsome]
    dsimp only
    step*
    have ha1_other : ∀ k, k ≠ iter.start.val → (hk : k < 4) → a1[k] = out[k] := by
      intro k hne hk
      rw [a1_post]; simp_lists
    refine ⟨?_, ?_⟩
    · intro k hk
      have hk1 : k < iter1.start.val := by rw [hstart']; scalar_tac
      rw [r_post1 k hk1, ha1_other k (by scalar_tac) (by scalar_tac)]
    · intro k hk_lo hk_hi
      by_cases heq : k = iter.start.val
      · subst heq
        have hk1 : iter.start.val < iter1.start.val := by rw [hstart']; scalar_tac
        rw [r_post1 iter.start.val hk1, a1_post]
        simp_lists
        agrind
      · have hk1 : iter1.start.val ≤ k := by rw [hstart']; scalar_tac
        exact r_post2 k hk1 hk_hi
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← iter_next_none
    rw [hnone]
    dsimp only
    simp only [WP.spec_ok]
    refine ⟨?_, ?_⟩
    · intro k hk; trivial
    · intro k hk_lo hk_hi; scalar_tac
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- 16×16 → 32-bit widening multiply, low half (4 lanes of `a`/`b`). -/
@[step] theorem verify.intrinsics.aarch64.neon.vmull_u16.spec
    (a b : U16x4) :
  verify.intrinsics.aarch64.neon.vmull_u16 a b
  ⦃ (r : U32x4) =>
    ∀ k, (hk : k < 4) →
      r[k].val = a[k].val * b[k].val ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vmull_u16
  step with verify.intrinsics.aarch64.neon.vmull_u16_loop.spec
  exact r_post2 _ (by scalar_tac) (by assumption)

/-- Loop companion for `vmull_high_u16`. -/
@[step] theorem verify.intrinsics.aarch64.neon.vmull_high_u16_loop.spec
    (iter : core.ops.range.Range Std.Usize) (a b : U16x8) (out : U32x4)
    (hStart : iter.start.val ≤ 4) (hEnd : iter.«end».val = 4) :
  verify.intrinsics.aarch64.neon.vmull_high_u16_loop iter a b out
  ⦃ (r : U32x4) =>
    (∀ k, (hk : k < iter.start.val) → r[k] = out[k]) ∧
    (∀ k, iter.start.val ≤ k → (hk : k < 4) →
      r[k].val = a[k+4].val * b[k+4].val) ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vmull_high_u16_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← iter_next_some
    rw [hsome]
    dsimp only
    step*
    have ha1_other : ∀ k, k ≠ iter.start.val → (hk : k < 4) → a1[k] = out[k] := by
      intro k hne hk
      rw [a1_post]; simp_lists
    refine ⟨?_, ?_⟩
    · intro k hk
      have hk1 : k < iter1.start.val := by rw [hstart']; scalar_tac
      rw [r_post1 k hk1, ha1_other k (by scalar_tac) (by scalar_tac)]
    · intro k hk_lo hk_hi
      by_cases heq : k = iter.start.val
      · subst heq
        have hk1 : iter.start.val < iter1.start.val := by rw [hstart']; scalar_tac
        rw [r_post1 iter.start.val hk1, a1_post]
        simp_lists
        agrind
      · have hk1 : iter1.start.val ≤ k := by rw [hstart']; scalar_tac
        exact r_post2 k hk1 hk_hi
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← iter_next_none
    rw [hnone]
    dsimp only
    simp only [WP.spec_ok]
    refine ⟨?_, ?_⟩
    · intro k hk; trivial
    · intro k hk_lo hk_hi; scalar_tac
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- 16×16 → 32-bit widening multiply, high half (4 lanes of `a[4..]`/`b[4..]`). -/
@[step] theorem verify.intrinsics.aarch64.neon.vmull_high_u16.spec
    (a b : U16x8) :
  verify.intrinsics.aarch64.neon.vmull_high_u16 a b
  ⦃ (r : U32x4) =>
    ∀ k, (hk : k < 4) →
      r[k].val = a[k+4].val * b[k+4].val ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vmull_high_u16
  step with verify.intrinsics.aarch64.neon.vmull_high_u16_loop.spec
  exact r_post2 _ (by scalar_tac) (by assumption)

/-- Loop companion for `vmlal_u16`. -/
@[step] theorem verify.intrinsics.aarch64.neon.vmlal_u16_loop.spec
    (iter : core.ops.range.Range Std.Usize) (acc : U32x4) (a b : U16x4)
    (out : U32x4)
    (hStart : iter.start.val ≤ 4) (hEnd : iter.«end».val = 4) :
  verify.intrinsics.aarch64.neon.vmlal_u16_loop iter acc a b out
  ⦃ (r : U32x4) =>
    (∀ k, (hk : k < iter.start.val) → r[k] = out[k]) ∧
    (∀ k, iter.start.val ≤ k → (hk : k < 4) →
      r[k].val = (acc[k].val + a[k].val * b[k].val) % 2^32) ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vmlal_u16_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← iter_next_some
    rw [hsome]
    dsimp only
    step*
    have ha1_other : ∀ k, k ≠ iter.start.val → (hk : k < 4) → a1[k] = out[k] := by
      intro k hne hk
      rw [a1_post]; simp_lists
    refine ⟨?_, ?_⟩
    · intro k hk
      have hk1 : k < iter1.start.val := by rw [hstart']; scalar_tac
      rw [r_post1 k hk1, ha1_other k (by scalar_tac) (by scalar_tac)]
    · intro k hk_lo hk_hi
      by_cases heq : k = iter.start.val
      · subst heq
        have hk1 : iter.start.val < iter1.start.val := by rw [hstart']; scalar_tac
        rw [r_post1 iter.start.val hk1, a1_post]
        simp_lists
        have hi6 : i6.val = a[iter.start.val].val * b[iter.start.val].val := by
          rw [i6_post, i3_post, i5_post, i2_post, i4_post]; rfl
        rw [i7_post, core.num.U32.wrapping_add_val_eq, i1_post, hi6,
            show Std.UScalar.size Std.UScalarTy.U32 = 2^32 from by scalar_tac]
        rfl
      · have hk1 : iter1.start.val ≤ k := by rw [hstart']; scalar_tac
        exact r_post2 k hk1 hk_hi
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← iter_next_none
    rw [hnone]
    dsimp only
    simp only [WP.spec_ok]
    refine ⟨?_, ?_⟩
    · intro k hk; trivial
    · intro k hk_lo hk_hi; scalar_tac
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- 16×16 → 32-bit widening multiply-accumulate, low half.  Post is the
    BitVec lane-bridge form; closing it requires the corresponding
    `vmlal_u16_loop.spec`. -/
@[step] theorem verify.intrinsics.aarch64.neon.vmlal_u16.spec
    (acc : U32x4) (a b : U16x4) :
  verify.intrinsics.aarch64.neon.vmlal_u16 acc a b
  ⦃ (r : U32x4) =>
    ∀ k, (hk : k < 4) →
      r[k].val = (acc[k].val + a[k].val * b[k].val) % 2^32 ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vmlal_u16
  step with verify.intrinsics.aarch64.neon.vmlal_u16_loop.spec
  exact r_post2 _ (by scalar_tac) (by assumption)

/-- Loop companion for `vmlal_high_u16`. -/
@[step] theorem verify.intrinsics.aarch64.neon.vmlal_high_u16_loop.spec
    (iter : core.ops.range.Range Std.Usize) (acc : U32x4) (a b : U16x8)
    (out : U32x4)
    (hStart : iter.start.val ≤ 4) (hEnd : iter.«end».val = 4) :
  verify.intrinsics.aarch64.neon.vmlal_high_u16_loop iter acc a b out
  ⦃ (r : U32x4) =>
    (∀ k, (hk : k < iter.start.val) → r[k] = out[k]) ∧
    (∀ k, iter.start.val ≤ k → (hk : k < 4) →
      r[k].val = (acc[k].val + a[k+4].val * b[k+4].val) % 2^32) ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vmlal_high_u16_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← iter_next_some
    rw [hsome]
    dsimp only
    step*
    have ha1_other : ∀ k, k ≠ iter.start.val → (hk : k < 4) → a1[k] = out[k] := by
      intro k hne hk
      rw [a1_post]; simp_lists
    refine ⟨?_, ?_⟩
    · intro k hk
      have hk1 : k < iter1.start.val := by rw [hstart']; scalar_tac
      rw [r_post1 k hk1, ha1_other k (by scalar_tac) (by scalar_tac)]
    · intro k hk_lo hk_hi
      by_cases heq : k = iter.start.val
      · subst heq
        have hk1 : iter.start.val < iter1.start.val := by rw [hstart']; scalar_tac
        have hprod : i7.val = a[i2.val].val * b[i2.val].val := by
          rw [i7_post, i4_post, i6_post, i3_post, i5_post]; rfl
        have hi2 : i2.val = iter.start.val + 4 := by rw [i2_post]
        rw [r_post1 iter.start.val hk1, a1_post]
        simp_lists
        rw [i8_post, core.num.U32.wrapping_add_val_eq, i1_post, hprod,
            show Std.UScalar.size Std.UScalarTy.U32 = 2^32 from by scalar_tac]
        agrind
      · have hk1 : iter1.start.val ≤ k := by rw [hstart']; scalar_tac
        exact r_post2 k hk1 hk_hi
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← iter_next_none
    rw [hnone]
    dsimp only
    simp only [WP.spec_ok]
    refine ⟨?_, ?_⟩
    · intro k hk; trivial
    · intro k hk_lo hk_hi; scalar_tac
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- 16×16 → 32-bit widening multiply-accumulate, high half. -/
@[step] theorem verify.intrinsics.aarch64.neon.vmlal_high_u16.spec
    (acc : U32x4) (a b : U16x8) :
  verify.intrinsics.aarch64.neon.vmlal_high_u16 acc a b
  ⦃ (r : U32x4) =>
    ∀ k, (hk : k < 4) →
      r[k].val = (acc[k].val + a[k+4].val * b[k+4].val) % 2^32 ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vmlal_high_u16
  step with verify.intrinsics.aarch64.neon.vmlal_high_u16_loop.spec
  exact r_post2 _ (by scalar_tac) (by assumption)

/-- Loop companion for `vld1q_u16`. -/
@[step] theorem verify.intrinsics.aarch64.neon.vld1q_u16_loop.spec
    (iter : core.ops.range.Range Std.Usize) (arr : Slice Std.U16)
    (at1 : Std.Usize) (out : U16x8)
    (hStart : iter.start.val ≤ 8) (hEnd : iter.«end».val = 8)
    (h_bounds : at1.val + 8 ≤ arr.length) :
  verify.intrinsics.aarch64.neon.vld1q_u16_loop iter arr at1 out
  ⦃ (r : U16x8) =>
    (∀ k, (hk : k < iter.start.val) → r[k] = out[k]) ∧
    (∀ k, iter.start.val ≤ k → (hk : k < 8) →
      r[k] = arr[at1.val + k]'(by scalar_tac)) ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vld1q_u16_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← iter_next_some
    rw [hsome]
    dsimp only
    step*
    have ha1_other : ∀ k, k ≠ iter.start.val → (hk : k < 8) → a[k] = out[k] := by
      intro k hne hk
      rw [a_post]; simp_lists
    refine ⟨?_, ?_⟩
    · intro k hk
      have hk1 : k < iter1.start.val := by rw [hstart']; scalar_tac
      rw [r_post1 k hk1, ha1_other k (by scalar_tac) (by scalar_tac)]
    · intro k hk_lo hk_hi
      by_cases heq : k = iter.start.val
      · subst heq
        have hk1 : iter.start.val < iter1.start.val := by rw [hstart']; scalar_tac
        rw [r_post1 iter.start.val hk1, a_post]
        simp_lists
        agrind
      · have hk1 : iter1.start.val ≤ k := by rw [hstart']; scalar_tac
        exact r_post2 k hk1 hk_hi
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← iter_next_none
    rw [hnone]
    dsimp only
    simp only [WP.spec_ok]
    refine ⟨?_, ?_⟩
    · intro k hk; trivial
    · intro k hk_lo hk_hi; scalar_tac
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- Slice → register load (8 u16 lanes starting at `at1`). -/
@[step] theorem verify.intrinsics.aarch64.neon.vld1q_u16.spec
    (arr : Slice Std.U16) (at1 : Std.Usize)
    (h_bounds : at1.val + 8 ≤ arr.length) :
  verify.intrinsics.aarch64.neon.vld1q_u16 arr at1
  ⦃ (r : U16x8) =>
    ∀ k, (hk : k < 8) → r[k] = arr[at1.val + k]'(by scalar_tac) ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vld1q_u16
  step with verify.intrinsics.aarch64.neon.vld1q_u16_loop.spec
  exact r_post2 _ (by scalar_tac) (by assumption)

/-- Loop companion for `vst1_u16`. -/
@[step] theorem verify.intrinsics.aarch64.neon.vst1_u16_loop.spec
    (iter : core.ops.range.Range Std.Usize) (arr : Slice Std.U16)
    (at1 : Std.Usize) (v : U16x4)
    (hStart : iter.start.val ≤ iter.«end».val) (hEnd : iter.«end».val ≤ 4)
    (hbnd : at1.val + iter.«end».val ≤ arr.length) :
  verify.intrinsics.aarch64.neon.vst1_u16_loop iter arr at1 v
  ⦃ (r : Slice Std.U16) =>
    ∃ (h_len : r.length = arr.length),
      (∀ k, (hk : k < arr.length) →
         k < at1.val + iter.start.val ∨ at1.val + iter.«end».val ≤ k →
         r[k] = arr[k]) ∧
      (∀ k, iter.start.val ≤ k → (hk : k < iter.«end».val) →
         r[at1.val + k] = v[k]) ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vst1_u16_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← iter_next_some
    rw [hsome]
    dsimp only
    step*
    have h_lenr := r_post1
    have hout := r_post2
    have hin := r_post3
    have hsval : s.val = arr.val.set i2.val i1 := by rw [s_post]; simp [Slice.set, Slice.setAtNat]
    have h_lens : s.length = arr.length := by
      simp [s_post]
    have h_lenra : r.length = arr.length := h_lenr.trans h_lens
    have hi2 : i2.val = at1.val + iter.start.val := by rw [i2_post]
    refine ⟨h_lenra, ?_, ?_⟩
    · intro k hk hcase
      have hcase1 : k < at1.val + iter1.start.val ∨ at1.val + iter1.«end».val ≤ k := by
        rw [hstart', hend']; rcases hcase with h | h
        · left; scalar_tac
        · right; exact h
      have hk_s : k < s.length := by rw [h_lens]; exact hk
      have hne : k ≠ i2.val := by
        rw [hi2]; rcases hcase with h | h <;> scalar_tac
      rw [hout k hk_s hcase1]
      simp_lists [s_post]
    · intro k hk_lo hk_hi
      by_cases heq : k = iter.start.val
      · subst heq
        have hk_s : at1.val + iter.start.val < s.length := by rw [h_lens]; scalar_tac
        have hcond : at1.val + iter.start.val < at1.val + iter1.start.val ∨
                     at1.val + iter1.«end».val ≤ at1.val + iter.start.val := by
          left; rw [hstart']; scalar_tac
        rw [hout (at1.val + iter.start.val) hk_s hcond]
        simp only [← hi2]; simp_lists [s_post]; exact i1_post
      · exact hin k (by rw [hstart']; scalar_tac) (by rw [hend']; exact hk_hi)
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← iter_next_none
    rw [hnone]
    dsimp only
    simp only [WP.spec_ok]
    refine ⟨trivial, ?_, ?_⟩
    · intro k hk hcase; trivial
    · intro k hk_lo hk_hi; scalar_tac
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- Register → slice store (4 u16 lanes starting at `at1`). -/
@[step] theorem verify.intrinsics.aarch64.neon.vst1_u16.spec
    (arr : Slice Std.U16) (at1 : Std.Usize) (v : U16x4)
    (h_bounds : at1.val + 4 ≤ arr.length) :
  verify.intrinsics.aarch64.neon.vst1_u16 arr at1 v
  ⦃ (r : Slice Std.U16) =>
    ∃ (h_len : r.length = arr.length),
      ∀ k (hk : k < arr.length),
        r[k] = if h : at1.val ≤ k ∧ k < at1.val + 4
               then v[k - at1.val]
               else arr[k] ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vst1_u16
  step*
  refine ⟨r_post1, fun k hk => ?_⟩
  split
  · rename_i h
    have hk' : k - at1.val < 4 := by scalar_tac
    have heq : at1.val + (k - at1.val) = k := by scalar_tac
    have h3 := r_post3 (k - at1.val) (Nat.zero_le _) hk'; simp only [heq] at h3; exact h3
  · rename_i h
    exact r_post2 k hk (by push Not at h; scalar_tac)

/-- Loop companion for `vst1q_u16`. -/
@[step] theorem verify.intrinsics.aarch64.neon.vst1q_u16_loop.spec
    (iter : core.ops.range.Range Std.Usize) (arr : Slice Std.U16)
    (at1 : Std.Usize) (v : U16x8)
    (hStart : iter.start.val ≤ iter.«end».val) (hEnd : iter.«end».val ≤ 8)
    (hbnd : at1.val + iter.«end».val ≤ arr.length) :
  verify.intrinsics.aarch64.neon.vst1q_u16_loop iter arr at1 v
  ⦃ (r : Slice Std.U16) =>
    ∃ (h_len : r.length = arr.length),
      (∀ k, (hk : k < arr.length) →
         k < at1.val + iter.start.val ∨ at1.val + iter.«end».val ≤ k →
         r[k] = arr[k]) ∧
      (∀ k, iter.start.val ≤ k → (hk : k < iter.«end».val) →
         r[at1.val + k] = v[k]) ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vst1q_u16_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← iter_next_some
    rw [hsome]
    dsimp only
    step*
    have h_lenr := r_post1
    have hout := r_post2
    have hin := r_post3
    have hsval : s.val = arr.val.set i2.val i1 := by rw [s_post]; simp [Slice.set, Slice.setAtNat]
    have h_lens : s.length = arr.length := by
      simp [s_post]
    have h_lenra : r.length = arr.length := h_lenr.trans h_lens
    have hi2 : i2.val = at1.val + iter.start.val := by rw [i2_post]
    refine ⟨h_lenra, ?_, ?_⟩
    · intro k hk hcase
      have hcase1 : k < at1.val + iter1.start.val ∨ at1.val + iter1.«end».val ≤ k := by
        rw [hstart', hend']; rcases hcase with h | h
        · left; scalar_tac
        · right; exact h
      have hk_s : k < s.length := by rw [h_lens]; exact hk
      have hne : k ≠ i2.val := by
        rw [hi2]; rcases hcase with h | h <;> scalar_tac
      rw [hout k hk_s hcase1]
      simp_lists [s_post]
    · intro k hk_lo hk_hi
      by_cases heq : k = iter.start.val
      · subst heq
        have hk_s : at1.val + iter.start.val < s.length := by rw [h_lens]; scalar_tac
        have hcond : at1.val + iter.start.val < at1.val + iter1.start.val ∨
                     at1.val + iter1.«end».val ≤ at1.val + iter.start.val := by
          left; rw [hstart']; scalar_tac
        rw [hout (at1.val + iter.start.val) hk_s hcond]
        simp only [← hi2]; simp_lists [s_post]; exact i1_post
      · exact hin k (by rw [hstart']; scalar_tac) (by rw [hend']; exact hk_hi)
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← iter_next_none
    rw [hnone]
    dsimp only
    simp only [WP.spec_ok]
    refine ⟨trivial, ?_, ?_⟩
    · intro k hk hcase; trivial
    · intro k hk_lo hk_hi; scalar_tac
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- Register → slice store (8 u16 lanes starting at `at1`).
    Same `∃ h_len` shape as `vst1_u16.spec`. -/
@[step] theorem verify.intrinsics.aarch64.neon.vst1q_u16.spec
    (arr : Slice Std.U16) (at1 : Std.Usize) (v : U16x8)
    (h_bounds : at1.val + 8 ≤ arr.length) :
  verify.intrinsics.aarch64.neon.vst1q_u16 arr at1 v
  ⦃ (r : Slice Std.U16) =>
    ∃ (h_len : r.length = arr.length),
      ∀ k (hk : k < arr.length),
        r[k] = if h : at1.val ≤ k ∧ k < at1.val + 8
               then v[k - at1.val]
               else arr[k] ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vst1q_u16
  step*
  refine ⟨r_post1, fun k hk => ?_⟩
  split
  · rename_i h
    have hk' : k - at1.val < 8 := by scalar_tac
    have heq : at1.val + (k - at1.val) = k := by scalar_tac
    have h3 := r_post3 (k - at1.val) (Nat.zero_le _) hk'; simp only [heq] at h3; exact h3
  · rename_i h
    exact r_post2 k hk (by push Not at h; scalar_tac)

/-- Loop companion for `vreinterpretq_s16_u16`. -/
@[step] theorem verify.intrinsics.aarch64.neon.vreinterpretq_s16_u16_loop.spec
    (iter : core.ops.range.Range Std.Usize) (v : U16x8)
    (out : Array Std.I16 8#usize)
    (hStart : iter.start.val ≤ 8) (hEnd : iter.«end».val = 8) :
  verify.intrinsics.aarch64.neon.vreinterpretq_s16_u16_loop iter v out
  ⦃ (r : Array Std.I16 8#usize) =>
    (∀ k, (hk : k < iter.start.val) → r[k] = out[k]) ∧
    (∀ k, iter.start.val ≤ k → (hk : k < 8) → r[k].bv = v[k].bv) ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vreinterpretq_s16_u16_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← iter_next_some
    rw [hsome]
    dsimp only
    step*
    have ha1_other : ∀ k, k ≠ iter.start.val → (hk : k < 8) → a[k] = out[k] := by
      intro k hne hk
      rw [a_post]; simp_lists
    refine ⟨?_, ?_⟩
    · intro k hk
      have hk1 : k < iter1.start.val := by rw [hstart']; scalar_tac
      rw [r_post1 k hk1, ha1_other k (by scalar_tac) (by scalar_tac)]
    · intro k hk_lo hk_hi
      by_cases heq : k = iter.start.val
      · subst heq
        have hk1 : iter.start.val < iter1.start.val := by rw [hstart']; scalar_tac
        rw [r_post1 iter.start.val hk1, a_post]
        simp_lists
        rw [i2_post, i1_post]
        simp only [Std.UScalar.hcast, Std.IScalar.bv_mk_apply]
        bv_tac 16
      · have hk1 : iter1.start.val ≤ k := by rw [hstart']; scalar_tac
        exact r_post2 k hk1 hk_hi
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← iter_next_none
    rw [hnone]
    dsimp only
    simp only [WP.spec_ok]
    refine ⟨?_, ?_⟩
    · intro k hk; trivial
    · intro k hk_lo hk_hi; scalar_tac
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- Same-lane-width signed/unsigned reinterpret (8 lanes). -/
@[step] theorem verify.intrinsics.aarch64.neon.vreinterpretq_s16_u16.spec
    (v : U16x8) :
  verify.intrinsics.aarch64.neon.vreinterpretq_s16_u16 v
  ⦃ (r : Array Std.I16 8#usize) =>
    ∀ k, (hk : k < 8) → r[k].bv = v[k].bv ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vreinterpretq_s16_u16
  step with verify.intrinsics.aarch64.neon.vreinterpretq_s16_u16_loop.spec
  exact r_post2 _ (by scalar_tac) (by assumption)

/-- Loop companion for `vreinterpretq_u16_s16`. -/
@[step] theorem verify.intrinsics.aarch64.neon.vreinterpretq_u16_s16_loop.spec
    (iter : core.ops.range.Range Std.Usize) (v : Array Std.I16 8#usize)
    (out : U16x8)
    (hStart : iter.start.val ≤ 8) (hEnd : iter.«end».val = 8) :
  verify.intrinsics.aarch64.neon.vreinterpretq_u16_s16_loop iter v out
  ⦃ (r : U16x8) =>
    (∀ k, (hk : k < iter.start.val) → r[k] = out[k]) ∧
    (∀ k, iter.start.val ≤ k → (hk : k < 8) → r[k].bv = v[k].bv) ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vreinterpretq_u16_s16_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← iter_next_some
    rw [hsome]
    dsimp only
    step*
    have ha1_other : ∀ k, k ≠ iter.start.val → (hk : k < 8) → a[k] = out[k] := by
      intro k hne hk
      rw [a_post]; simp_lists
    refine ⟨?_, ?_⟩
    · intro k hk
      have hk1 : k < iter1.start.val := by rw [hstart']; scalar_tac
      rw [r_post1 k hk1, ha1_other k (by scalar_tac) (by scalar_tac)]
    · intro k hk_lo hk_hi
      by_cases heq : k = iter.start.val
      · subst heq
        have hk1 : iter.start.val < iter1.start.val := by rw [hstart']; scalar_tac
        rw [r_post1 iter.start.val hk1, a_post]
        simp_lists
        rw [i2_post, i1_post]
        simp only [Std.IScalar.hcast, Std.UScalar.bv_mk_apply]
        bv_tac 16
      · have hk1 : iter1.start.val ≤ k := by rw [hstart']; scalar_tac
        exact r_post2 k hk1 hk_hi
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← iter_next_none
    rw [hnone]
    dsimp only
    simp only [WP.spec_ok]
    refine ⟨?_, ?_⟩
    · intro k hk; trivial
    · intro k hk_lo hk_hi; scalar_tac
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

@[step] theorem verify.intrinsics.aarch64.neon.vreinterpretq_u16_s16.spec
    (v : Array Std.I16 8#usize) :
  verify.intrinsics.aarch64.neon.vreinterpretq_u16_s16 v
  ⦃ (r : U16x8) =>
    ∀ k, (hk : k < 8) → r[k].bv = v[k].bv ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vreinterpretq_u16_s16
  step with verify.intrinsics.aarch64.neon.vreinterpretq_u16_s16_loop.spec
  exact r_post2 _ (by scalar_tac) (by assumption)

/-- Lane bridge for the `u32x4 → u16x8` reinterpret: from the 128-bit byte-view
    equality `r.bv = v.bv`, lane `2k` of the `u16` view is the low half of `u32`
    lane `k`, and lane `2k+1` is the high half. -/
theorem reinterpret_u32x4_lane (v : U16x8) (w : U32x4)
    (hbv : v.bv (·.bv) = w.bv (·.bv)) (k : Nat) (hk : k < 4) :
    (v[2*k]).val = w[k].val % 65536 ∧ (v[2*k+1]).val = w[k].val / 65536 := by
  have hb2k : 2*k < (8#usize).val := by scalar_tac
  have hb2k1 : 2*k+1 < (8#usize).val := by scalar_tac
  have hbk : k < (4#usize).val := by scalar_tac
  have e_lo : v[2*k].bv = (w[k].bv).extractLsb' 0 16 := by
    rw [← Aeneas.Std.Array.bv_slice v (·.bv) (2*k) hb2k,
        ← Aeneas.Std.Array.bv_slice w (·.bv) k hbk, hbv,
        _root_.BitVec.extractLsb'_extractLsb' _ _ _ _ _ (by omega)]
    congr 1; omega
  have e_hi : v[2*k+1].bv = (w[k].bv).extractLsb' 16 16 := by
    rw [← Aeneas.Std.Array.bv_slice v (·.bv) (2*k+1) hb2k1,
        ← Aeneas.Std.Array.bv_slice w (·.bv) k hbk, hbv,
        _root_.BitVec.extractLsb'_extractLsb' _ _ _ _ _ (by omega)]
    congr 1; omega
  have hvf : w[k].val = w[k].bv.toNat := rfl
  have hlt : w[k].bv.toNat < 2^32 := w[k].bv.isLt
  refine ⟨?_, ?_⟩
  · show v[2*k].bv.toNat = w[k].val % 65536
    rw [e_lo]; simp [_root_.BitVec.extractLsb', Nat.shiftRight_eq_div_pow]
  · show v[2*k+1].bv.toNat = w[k].val / 65536
    rw [e_hi]; simp [_root_.BitVec.extractLsb', Nat.shiftRight_eq_div_pow]; rw [hvf]; omega

/-- Reinterpret a `u32x4` as a `u16x8` (byte-identity reinterpret via
    `dwords_to_bytes ∘ bytes_to_words`): lane `2k` is the low 16 bits of `u32`
    lane `k`, lane `2k+1` is the high 16 bits. -/
@[step] theorem verify.intrinsics.aarch64.neon.vreinterpretq_u16_u32.spec
    (v : U32x4) :
  verify.intrinsics.aarch64.neon.vreinterpretq_u16_u32 v
  ⦃ (r : U16x8) =>
    ∀ k, (hk : k < 4) →
      (r[2*k]).val = v[k].val % 65536 ∧
      (r[2*k+1]).val = v[k].val / 65536 ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vreinterpretq_u16_u32
  step as ⟨b, hb⟩
  step as ⟨r, hr⟩
  rename_i k hk
  exact reinterpret_u32x4_lane r v (hr.trans hb) k hk

/-- Unzip-odd of two u16 vectors: take odd-indexed lanes from `a` then `b`. -/
@[step] theorem verify.intrinsics.aarch64.neon.vuzp2q_u16.spec
    (a b : U16x8) :
  verify.intrinsics.aarch64.neon.vuzp2q_u16 a b
  ⦃ (r : U16x8) =>
    (∀ k, (hk : k < 4) → r[k] = a[2*k+1]) ∧
    (∀ k, (hk : k < 4) → r[k+4] = b[2*k+1]) ⦄ := by
  unfold verify.intrinsics.aarch64.neon.vuzp2q_u16
  step*
  refine ⟨?_, ?_⟩
  · intro k hk
    match k, hk with
    | 0, _ => simp_all [Std.Array.make]
    | 1, _ => simp_all [Std.Array.make]
    | 2, _ => simp_all [Std.Array.make]
    | 3, _ => simp_all [Std.Array.make]
  · intro k hk
    match k, hk with
    | 0, _ => simp_all [Std.Array.make]
    | 1, _ => simp_all [Std.Array.make]
    | 2, _ => simp_all [Std.Array.make]
    | 3, _ => simp_all [Std.Array.make]

end symcrust
