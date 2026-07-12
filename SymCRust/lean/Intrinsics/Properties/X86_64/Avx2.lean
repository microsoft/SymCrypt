/-
  Public AVX2 Layer-1 surface.

  `@[step]` theorems for the Rust models of intrinsics `verify.intrinsics.x86_64.avx2.*`
  extracted to `Symcrust/Code/*`.

  See `INTRINSICS.md` for the layered architecture.
-/
import Symcrust.Code.Funs
import Intrinsics.Properties.Lanewise
import Intrinsics.Properties.Lanes
import Intrinsics.Properties.IterRange
import Intrinsics.Simd
import Intrinsics.Properties.X86_64.Register
open Aeneas Aeneas.Std Intrinsics

local macro_rules
| `(tactic| get_elem_tactic) => `(tactic| first | assumption | grind)

private theorem i32_hcast_u32_val (count : I32) (h1 : (0#i32) ≤ count) (h2 : count < (64#i32))
    (c : U32) (c_post : c = IScalar.hcast .U32 count) : c.val < 64 := by
  subst c_post
  simp only [UScalar.val, IScalar.hcast, UScalarTy.numBits]
  have hse : BitVec.signExtend 32 count.bv = count.bv := by simp [BitVec.signExtend_eq]
  rw [hse]
  have hlt : count.val < 64 := by scalar_tac
  have hge : (0 : Int) ≤ count.val := by scalar_tac
  have hbv : count.bv.toInt = count.val := IScalar.bv_toInt_eq count
  have hnn : 0 ≤ count.bv.toInt := by linarith
  have := @BitVec.toInt_eq_msb_cond 32 count.bv
  simp at this
  split at this <;> linarith [count.bv.isLt]

private theorem i32_hcast_u32_toNat (count : I32) (h1 : (0#i32) ≤ count) (_h2 : count < (64#i32))
    (c : U32) (c_post : c = IScalar.hcast .U32 count) : (c.val : ℕ) = count.toNat := by
  subst c_post
  simp only [UScalar.val, IScalar.hcast, UScalarTy.numBits]
  have hse : BitVec.signExtend 32 count.bv = count.bv := by simp [BitVec.signExtend_eq]
  rw [hse]
  show count.bv.toNat = (count.val).toNat
  have hge : (0 : Int) ≤ count.val := by scalar_tac
  have hbv : count.bv.toInt = count.val := IScalar.bv_toInt_eq count
  have hnn : 0 ≤ count.bv.toInt := by linarith
  have := @BitVec.toInt_eq_msb_cond 32 count.bv
  simp at this
  split at this
  · linarith [count.bv.isLt]
  · rw [this, Int.toNat_natCast]

private theorem repeat_u64_zero_bv (k : Nat) (hk : k < 4) :
    (Array.repeat 4#usize 0#u64)[k].bv = (0 : BitVec 64) := by
  show ((Array.repeat 4#usize (0#u64)).val[k]'(by simp [Array.repeat_val]; exact hk)).bv = 0
  simp only [Array.repeat_val, List.getElem_replicate]; rfl

namespace symcrust

attribute [local step] iter_next_some iter_next_none

/-! ## Cross-arch type conversions (256-bit) -/

/-- `_loop` partner of `bytes256_to_words16x16`: at index `i` writes
    `out[i] := u16-from-LE-bytes b[2i .. 2i+1]`. -/
@[step] theorem verify.intrinsics.x86_64.avx2.bytes256_to_words16x16_loop.spec
    (iter : core.ops.range.Range Std.Usize)
    (b : U8x32) (out : U16x16)
    (hStart : iter.start.val ≤ iter.end.val) (hEnd : iter.end.val ≤ 16) :
  verify.intrinsics.x86_64.avx2.bytes256_to_words16x16_loop iter b out
  ⦃ (r : U16x16) =>
    (∀ k, (hk : k < iter.start.val) → r[k] = out[k]) ∧
    (∀ k, iter.start.val ≤ k → (hk : k < iter.end.val) →
        r[k].val =
          b[2*k].val + 256 * b[2*k + 1].val) ∧
    (∀ k, iter.end.val ≤ k → (hk : k < 16) → r[k] = out[k]) ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.bytes256_to_words16x16_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← iter_next_some
    rw [hsome]
    dsimp only
    step*
    refine ⟨?_, ?_, ?_⟩
    · intro k hk
      have h1 : k < iter1.start.val := by scalar_tac
      rw [r_post1 k h1, a_post]
      simp_lists
    · intro k hk_lo hk_hi
      by_cases heq : k = iter.start.val
      · subst heq
        have h1 : iter.start.val < iter1.start.val := by scalar_tac
        rw [r_post1 iter.start.val h1, a_post]
        simp_lists
        -- Goal: i5.val = b[2*iter.start.val].val + 256 * b[2*iter.start.val + 1].val
        show i5.bv.toNat = _
        rw [i5_post, _root_.BitVec.toNat_cast]
        change (_root_.BitVec.fromLEBytes [i2.bv, i4.bv]).toNat = _
        rw [_root_.BitVec.fromLEBytes_cons_toNat, _root_.BitVec.fromLEBytes_cons_toNat]
        simp only [_root_.BitVec.fromLEBytes, List.length_nil, _root_.BitVec.toNat_ofNat,
                   Nat.zero_mod, mul_zero, add_zero]
        have hi2v : i2.bv.toNat = i2.val := rfl
        have hi4v : i4.bv.toNat = i4.val := rfl
        rw [hi2v, hi4v, i2_post, i4_post]
        have hi1eq : i1.val = 2 * iter.start.val := by rw [i1_post]
        have hi3eq : i3.val = 2 * iter.start.val + 1 := by rw [i3_post, i1_post]
        simp_rw [hi1eq, hi3eq]
      · have h1 : iter1.start.val ≤ k := by scalar_tac
        have h2 : k < iter1.end.val := by scalar_tac
        exact r_post2 k h1 h2
    · intro k hk_lo hk_hi
      have h1 : iter1.end.val ≤ k := by scalar_tac
      rw [r_post3 k h1 hk_hi, a_post]
      simp_lists
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← iter_next_none
    rw [hnone]
    dsimp only
    simp only [WP.spec_ok]
    refine ⟨?_, ?_, ?_⟩
    · intro k hk; trivial
    · intro k hk_lo hk_hi; scalar_tac
    · intro k hk_lo hk_hi; trivial
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- 256-bit byte view → 16-lane u16 view. -/
@[step] theorem verify.intrinsics.x86_64.avx2.bytes256_to_words16x16.spec
    (b : U8x32) :
  verify.intrinsics.x86_64.avx2.bytes256_to_words16x16 b
  ⦃ (r : U16x16) =>
    ∀ k, (hk : k < 16) →
      r[k].val = b[2*k].val + 256 * b[2*k + 1].val ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.bytes256_to_words16x16
  step*
  -- `step*` calls `bytes256_to_words16x16_loop.spec` whose middle conjunct
  -- (with iter.start=0, iter.end=16) is exactly this post. Closes via step*.

set_option maxHeartbeats 1000000 in
/-- `_loop` partner of `words16x16_to_bytes256`. -/
@[step] theorem verify.intrinsics.x86_64.avx2.words16x16_to_bytes256_loop.spec
    (iter : core.ops.range.Range Std.Usize)
    (w : U16x16) (out : U8x32)
    (hStart : iter.start.val ≤ iter.end.val) (hEnd : iter.end.val ≤ 16) :
  verify.intrinsics.x86_64.avx2.words16x16_to_bytes256_loop iter w out
  ⦃ (r : U8x32) =>
    (∀ k, (hk : k < 2*iter.start.val) → r[k] = out[k]) ∧
    (∀ k, iter.start.val ≤ k → (hk : k < iter.end.val) →
        r[2*k].val = w[k].val % 256 ∧
        r[2*k + 1].val = (w[k].val >>> 8) % 256) ∧
    (∀ k, 2*iter.end.val ≤ k → (hk : k < 32) → r[k] = out[k]) ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.words16x16_to_bytes256_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← iter_next_some
    rw [hsome]
    dsimp only
    step*
    refine ⟨?_, ?_, ?_⟩
    · intro k hk
      have h1 : k < 2 * iter1.start.val := by scalar_tac
      rw [r_post1 k h1, a_post]
      have hne1 : k ≠ i5.val := by rw [i5_post, i3_post]; scalar_tac
      have hne2 : k ≠ i3.val := by rw [i3_post]; scalar_tac
      simp_lists
      rw [out1_post]
      simp_lists
    · intro k hk_lo hk_hi
      by_cases heq : k = iter.start.val
      · subst heq
        have h1 : iter.start.val < iter1.start.val := by scalar_tac
        have h2 : 2 * iter.start.val < 2 * iter1.start.val := by scalar_tac
        have h3 : 2 * iter.start.val + 1 < 2 * iter1.start.val := by scalar_tac
        refine ⟨?_, ?_⟩
        · -- r[2*iter.start.val] = p[0].val = w[iter.start].val % 256
          rw [r_post1 (2 * iter.start.val) h2, a_post]
          have hne : 2 * iter.start.val ≠ i5.val := by rw [i5_post, i3_post]; scalar_tac
          have heqv : 2 * iter.start.val = i3.val := by scalar_tac
          simp_lists
          simp_rw [out1_post]
          simp_lists [heqv]
          simp_rw [i2_post, p_post]
          rw [List.getElem_map]
          show i1.bv.toLEBytes[0].toNat = _
          rw [_root_.BitVec.toLEBytes_getElem_toNat (by decide) i1.bv 0
                (by simp [_root_.BitVec.toLEBytes_length])]
          simp only [i1_post]
          grind
        · -- r[2*iter.start.val + 1] = p[1].val = (w[iter.start].val >>> 8) % 256
          rw [r_post1 (2 * iter.start.val + 1) h3, a_post]
          have heqv : 2 * iter.start.val + 1 = i5.val := by scalar_tac
          simp_lists [heqv]
          simp_rw [i4_post, p_post]
          rw [List.getElem_map]
          show i1.bv.toLEBytes[1].toNat = _
          rw [_root_.BitVec.toLEBytes_getElem_toNat (by decide) i1.bv 1
                (by simp [_root_.BitVec.toLEBytes_length])]
          simp only [i1_post]
          grind
      · have h1 : iter1.start.val ≤ k := by scalar_tac
        have h2 : k < iter1.end.val := by scalar_tac
        exact r_post2 k h1 h2
    · intro k hk_lo hk_hi
      have h1 : 2 * iter1.end.val ≤ k := by scalar_tac
      rw [r_post3 k h1 hk_hi, a_post]
      have hne1 : k ≠ i5.val := by rw [i5_post, i3_post]; scalar_tac
      have hne2 : k ≠ i3.val := by rw [i3_post]; scalar_tac
      simp_lists
      rw [out1_post]
      simp_lists
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← iter_next_none
    rw [hnone]
    dsimp only
    simp only [WP.spec_ok]
    refine ⟨?_, ?_, ?_⟩
    · intro k hk; trivial
    · intro k hk_lo hk_hi; scalar_tac
    · intro k hk_lo hk_hi; trivial
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- 16-lane u16 view → 256-bit byte view. -/
@[step] theorem verify.intrinsics.x86_64.avx2.words16x16_to_bytes256.spec
    (w : U16x16) :
  verify.intrinsics.x86_64.avx2.words16x16_to_bytes256 w
  ⦃ (r : U8x32) =>
    ∀ k, (hk : k < 16) →
      r[2*k].val = w[k].val % 256 ∧
      r[2*k + 1].val = (w[k].val >>> 8) % 256 ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.words16x16_to_bytes256
  step*
  -- Closes via `step*` consuming `words16x16_to_bytes256_loop.spec` (middle conjunct).

/-- Load a little-endian u64 from 8 consecutive bytes at offset `8 * k`
    of `b`. -/
def bytes256_to_qwords256_lane
    (b : U8x32) (k : Nat) (hk : 8 * k + 7 < 32) : _root_.BitVec 64 :=
  ((_root_.BitVec.fromLEBytes
    [b[8*k].bv, b[8*k + 1].bv,
     b[8*k + 2].bv, b[8*k + 3].bv,
     b[8*k + 4].bv, b[8*k + 5].bv,
     b[8*k + 6].bv, b[8*k + 7].bv]).cast (by simp))

set_option maxHeartbeats 1000000 in
set_option maxRecDepth 1000 in
/-- Loop of `bytes256_to_qwords256`. -/
@[step]
theorem verify.intrinsics.x86_64.avx2.bytes256_to_qwords256_loop.spec
    (iter : core.ops.range.Range Std.Usize)
    (b : U8x32) (out : U64x4)
    (hStart : iter.start.val ≤ iter.end.val) (hEnd : iter.end.val ≤ 4) :
  verify.intrinsics.x86_64.avx2.bytes256_to_qwords256_loop iter b out
  ⦃ (r : U64x4) =>
    (∀ k, (hk : k < iter.start.val) → r[k] = out[k]) ∧
    (∀ k, iter.start.val ≤ k → (hk : k < iter.end.val) →
        r[k].val =
          (bytes256_to_qwords256_lane b k (by scalar_tac)).toNat) ∧
    (∀ k, iter.end.val ≤ k → (hk : k < 4) → r[k] = out[k]) ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.bytes256_to_qwords256_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← iter_next_some
    rw [hsome]
    dsimp only
    step*
    refine ⟨?_, ?_, ?_⟩
    · intro k hk
      have h1 : k < iter1.start.val := by scalar_tac
      rw [r_post1 k h1, a_post]
      simp_lists
    · intro k hk_lo hk_hi
      by_cases heq : k = iter.start.val
      · subst heq
        have h1 : iter.start.val < iter1.start.val := by scalar_tac
        rw [r_post1 iter.start.val h1, a_post]
        simp_lists
        show i17.bv.toNat = _
        rw [i17_post, _root_.BitVec.toNat_cast]
        change (_root_.BitVec.fromLEBytes [i2.bv, i4.bv, i6.bv, i8.bv,
                                           i10.bv, i12.bv, i14.bv, i16.bv]).toNat = _
        unfold bytes256_to_qwords256_lane
        rw [_root_.BitVec.toNat_cast]
        congr 2
        rw [i2_post, i4_post, i6_post, i8_post, i10_post, i12_post, i14_post, i16_post]
        have hi1eq  : i1.val  = 8 * iter.start.val      := by scalar_tac
        have hi3eq  : i3.val  = 8 * iter.start.val + 1  := by scalar_tac
        have hi5eq  : i5.val  = 8 * iter.start.val + 2  := by scalar_tac
        have hi7eq  : i7.val  = 8 * iter.start.val + 3  := by scalar_tac
        have hi9eq  : i9.val  = 8 * iter.start.val + 4  := by scalar_tac
        have hi11eq : i11.val = 8 * iter.start.val + 5  := by scalar_tac
        have hi13eq : i13.val = 8 * iter.start.val + 6  := by scalar_tac
        have hi15eq : i15.val = 8 * iter.start.val + 7  := by scalar_tac
        simp_lists [hi1eq, hi3eq, hi5eq, hi7eq, hi9eq, hi11eq, hi13eq, hi15eq]
      · have h1 : iter1.start.val ≤ k := by scalar_tac
        have h2 : k < iter1.end.val := by scalar_tac
        exact r_post2 k h1 h2
    · intro k hk_lo hk_hi
      have h1 : iter1.end.val ≤ k := by scalar_tac
      rw [r_post3 k h1 hk_hi, a_post]
      simp_lists
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← iter_next_none
    rw [hnone]
    dsimp only
    simp only [WP.spec_ok]
    refine ⟨?_, ?_, ?_⟩
    · intro k hk; trivial
    · intro k hk_lo hk_hi; scalar_tac
    · intro k hk_lo hk_hi; trivial
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- 256-bit byte view → 4-lane u64 view. -/
@[step] theorem verify.intrinsics.x86_64.avx2.bytes256_to_qwords256.spec
    (b : U8x32) :
  verify.intrinsics.x86_64.avx2.bytes256_to_qwords256 b
  ⦃ (r : U64x4) =>
    ∀ k, (hk : k < 4) →
      r[k].val = (bytes256_to_qwords256_lane b k (by scalar_tac)).toNat ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.bytes256_to_qwords256
  step*

/-- Loop of `qwords256_to_bytes256`.  -/
@[step] theorem verify.intrinsics.x86_64.avx2.qwords256_to_bytes256_loop.spec
    (iter : core.ops.range.Range Std.Usize)
    (q : U64x4) (out : U8x32)
    (hStart : iter.start.val ≤ iter.end.val) (hEnd : iter.end.val ≤ 4) :
  verify.intrinsics.x86_64.avx2.qwords256_to_bytes256_loop iter q out
  ⦃ (r : U8x32) =>
    (∀ k, (hk : k < 8*iter.start.val) → r[k] = out[k]) ∧
    (∀ i, iter.start.val ≤ i → (hi : i < iter.end.val) →
        ∀ j, (hj : j < 8) →
          r[8*i + j].val = (q[i].val >>> (8 * j)) % 256) ∧
    (∀ k, 8*iter.end.val ≤ k → (hk : k < 32) → r[k] = out[k]) ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.qwords256_to_bytes256_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← iter_next_some
    rw [hsome]
    dsimp only
    step*
    have hi2eq : i2.val = 8 * iter.start.val := by scalar_tac
    have hi3eq : i3.val = 8 * iter.start.val + 8 := by scalar_tac
    have hs2v : s2.val = p.val := by rw [s2_post, s1_post]; simp [Std.Array.to_slice]
    have hs2len : s2.length = 8 := by simp [Slice.length, hs2v]
    have hbacks2 : (index_mut_back s2).val = out.val.setSlice! i2.val s2.val := s_post3 s2
    refine ⟨?_, ?_, ?_⟩
    · intro k hk
      have h1 : k < 8 * iter1.start.val := by scalar_tac
      have hk_lt : k < i2.val := by scalar_tac
      rw [r_post1 k h1]
      grind
    · intro i hi_lo hi_hi j hj
      by_cases heq_i : i = iter.start.val
      · subst heq_i
        have h1 : 8 * iter.start.val + j < 8 * iter1.start.val := by scalar_tac
        rw [r_post1 (8 * iter.start.val + j) h1]
        have hkb : 8 * iter.start.val + j < (index_mut_back s2).val.length := by
          rw [Array.length_eq]; scalar_tac
        change ((index_mut_back s2).val[8 * iter.start.val + j]'hkb).val = _
        simp only [hbacks2]
        have hmid : i2.val ≤ 8 * iter.start.val + j ∧
                    8 * iter.start.val + j - i2.val < s2.val.length ∧
                    8 * iter.start.val + j < out.val.length := by
          constructor
          · scalar_tac
          constructor
          · simp [Slice.length] at hs2len; scalar_tac
          · simp []; scalar_tac
        rw [List.getElem_setSlice!_middle _ _ _ _ hmid]
        simp only [hi2eq, hs2v, p_post, List.getElem_map, Nat.add_sub_cancel_left]
        show (i1.bv.toLEBytes[j]).toNat = _
        rw [_root_.BitVec.toLEBytes_getElem_toNat (by decide) i1.bv j (by simp [_root_.BitVec.toLEBytes_length]; scalar_tac)]
        rw [i1_post]; rfl
      · have h1 : iter1.start.val ≤ i := by scalar_tac
        have h2 : i < iter1.end.val := by scalar_tac
        exact r_post2 i h1 h2 j hj
    · intro k hk_lo hk_hi
      have h1 : 8 * iter1.end.val ≤ k := by scalar_tac
      have hk_ge : i2.val + s2.length ≤ k := by scalar_tac
      rw [r_post3 k h1 hk_hi]
      grind
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← iter_next_none
    rw [hnone]
    dsimp only
    simp only [WP.spec_ok]
    grind
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- 4-lane u64 view → 256-bit byte view. -/
@[step] theorem verify.intrinsics.x86_64.avx2.qwords256_to_bytes256.spec
    (q : U64x4) :
  verify.intrinsics.x86_64.avx2.qwords256_to_bytes256 q
  ⦃ (r : U8x32) =>
    ∀ i, (hi : i < 4) → ∀ j, (hj : j < 8) →
      r[8*i + j].val = (q[i].val >>> (8 * j)) % 256 ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.qwords256_to_bytes256
  step*
  try agrind

/-! ## Load / store fixed-size U64 (no `_loop` — 4 unrolled indices) -/

/-- Load 4 u64s starting at `arr[at1]`. -/
@[step] theorem verify.intrinsics.x86_64.avx2.loadu_si256_u64.spec
    (arr : Slice Std.U64) (at1 : Std.Usize)
    (hbnd : at1.val + 4 ≤ arr.length) :
  verify.intrinsics.x86_64.avx2.loadu_si256_u64 arr at1
  ⦃ (r : U64x4) =>
    ∀ k, (hk : k < 4) → r[k] = arr[at1.val + k] ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.loadu_si256_u64
  step*
  intro k hk
  rcases k with _ | _ | _ | _ | k
  · show i = _
    rw [i_post]
    exact getElem_congr_idx (Nat.add_zero _).symm
  · show i2 = _
    rw [i2_post]
    exact getElem_congr_idx i1_post
  · show i4 = _
    rw [i4_post]
    exact getElem_congr_idx i3_post
  · show i6 = _
    rw [i6_post]
    exact getElem_congr_idx i5_post
  · exact absurd hk (by scalar_tac)

/-- Aligned variant of `loadu_si256_u64`. -/
@[step] theorem verify.intrinsics.x86_64.avx2.load_si256_u64.spec
    (arr : Slice Std.U64) (at1 : Std.Usize)
    (hbnd : at1.val + 4 ≤ arr.length) :
  verify.intrinsics.x86_64.avx2.load_si256_u64 arr at1
  ⦃ (r : U64x4) =>
    ∀ k, (hk : k < 4) → r[k] = arr[at1.val + k] ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.load_si256_u64
  step*
  try agrind

/-- Store 4 u64s into `arr[at1..at1+4]`. -/
@[step] theorem verify.intrinsics.x86_64.avx2.storeu_si256_u64.spec
    (arr : Slice Std.U64) (at1 : Std.Usize) (v : U64x4)
    (hbnd : at1.val + 4 ≤ arr.length) :
  verify.intrinsics.x86_64.avx2.storeu_si256_u64 arr at1 v
  ⦃ (r : Slice Std.U64) =>
    ∃ (h_len : r.length = arr.length),
      ∀ k (hk : k < arr.length),
        r[k] = if h : at1.val ≤ k ∧ k < at1.val + 4
               then v[k - at1.val]
               else arr[k] ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.storeu_si256_u64
  step*
  · agrind
  · grind

/-- Aligned variant of `storeu_si256_u64`. -/
@[step] theorem verify.intrinsics.x86_64.avx2.store_si256_u64.spec
    (arr : Slice Std.U64) (at1 : Std.Usize) (v : U64x4)
    (hbnd : at1.val + 4 ≤ arr.length) :
  verify.intrinsics.x86_64.avx2.store_si256_u64 arr at1 v
  ⦃ (r : Slice Std.U64) =>
    ∃ (h_len : r.length = arr.length),
      ∀ k (hk : k < arr.length),
        r[k] = if h : at1.val ≤ k ∧ k < at1.val + 4
               then v[k - at1.val]
               else arr[k] ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.store_si256_u64
  step*

/-! ## Load / store U16 (loop-based, 16 entries) -/

/-- Loop of `loadu_si256_u16`. -/
@[step] theorem verify.intrinsics.x86_64.avx2.loadu_si256_u16_loop.spec
    (iter : core.ops.range.Range Std.Usize) (arr : Slice Std.U16)
    (at1 : Std.Usize) (out : U16x16)
    (hStart : iter.start.val ≤ iter.end.val) (hEnd : iter.end.val ≤ 16)
    (hbnd : at1.val + iter.end.val ≤ arr.length) :
  verify.intrinsics.x86_64.avx2.loadu_si256_u16_loop iter arr at1 out
  ⦃ (r : U16x16) =>
    (∀ k, (hk : k < iter.start.val) → r[k] = out[k]) ∧
    (∀ k, iter.start.val ≤ k → (hk : k < iter.end.val) →
        r[k] = arr[at1.val + k]) ∧
    (∀ k, iter.end.val ≤ k → (hk : k < 16) → r[k] = out[k]) ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.loadu_si256_u16_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← iter_next_some
    rw [hsome]
    dsimp only
    step*
    have ha1_at : a[iter.start.val] = i2 := by grind
    have ha1_other : ∀ k, k ≠ iter.start.val → (hk : k < 16) → a[k] = out[k] := by
      intro k hne hk
      rw [a_post]; simp_lists
    refine ⟨?_, ?_, ?_⟩
    · grind
    · intro k hk_lo hk_hi
      by_cases heq : k = iter.start.val
      · subst heq
        have hk1 : iter.start.val < iter1.start.val := by rw [hstart']; scalar_tac
        have e1 : r[iter.start.val] = a[iter.start.val] := r_post1 iter.start.val hk1
        rw [e1, ha1_at, i2_post]
        exact getElem_congr_idx i1_post
      · have hk1 : iter1.start.val ≤ k := by rw [hstart']; scalar_tac
        have hk1' : k < iter1.«end».val := by rw [hend']; exact hk_hi
        exact r_post2 k hk1 hk1'
    · grind
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← iter_next_none
    rw [hnone]
    dsimp only
    simp only [WP.spec_ok]
    refine ⟨?_, ?_, ?_⟩
    · intro k hk; trivial
    · intro k hk_lo hk_hi; scalar_tac
    · intro k hk_lo hk_hi; trivial
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- Load 16 u16s starting at `arr[at1]`. -/
@[step] theorem verify.intrinsics.x86_64.avx2.loadu_si256_u16.spec
    (arr : Slice Std.U16) (at1 : Std.Usize)
    (hbnd : at1.val + 16 ≤ arr.length) :
  verify.intrinsics.x86_64.avx2.loadu_si256_u16 arr at1
  ⦃ (r : U16x16) =>
    ∀ k, (hk : k < 16) → r[k] = arr[at1.val + k] ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.loadu_si256_u16
  step*
  try agrind

/-- Loop of `storeu_si256_u16`. -/
@[step] theorem verify.intrinsics.x86_64.avx2.storeu_si256_u16_loop.spec
    (iter : core.ops.range.Range Std.Usize) (arr : Slice Std.U16)
    (at1 : Std.Usize) (v : U16x16)
    (hStart : iter.start.val ≤ iter.end.val) (hEnd : iter.end.val ≤ 16)
    (hbnd : at1.val + iter.end.val ≤ arr.length) :
  verify.intrinsics.x86_64.avx2.storeu_si256_u16_loop iter arr at1 v
  ⦃ (r : Slice Std.U16) =>
    ∃ (h_len : r.length = arr.length),
      (∀ k, (hk : k < arr.length) →
         k < at1.val + iter.start.val ∨ at1.val + iter.end.val ≤ k →
         r[k] = arr[k]) ∧
      (∀ k, iter.start.val ≤ k → (hk : k < iter.end.val) →
         r[at1.val + k] = v[k]) ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.storeu_si256_u16_loop
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
      simp [Slice.length, hsval, List.length_set]
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
      simp only [s_post]; exact Slice.getElem_Nat_set_ne arr i2 k i1 _ (Ne.symm hne)
    · intro k hk_lo hk_hi
      by_cases heq : k = iter.start.val
      · subst heq
        have hk_s : at1.val + iter.start.val < s.length := by rw [h_lens]; scalar_tac
        have hcond : at1.val + iter.start.val < at1.val + iter1.start.val ∨
                     at1.val + iter1.«end».val ≤ at1.val + iter.start.val := by
          left; rw [hstart']; scalar_tac
        rw [hout (at1.val + iter.start.val) hk_s hcond]
        simp only [s_post, Slice.getElem_Nat_set_eq, hi2]
        exact i1_post
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

/-- Store 16 u16s into `arr[at1..at1+16]`. -/
@[step] theorem verify.intrinsics.x86_64.avx2.storeu_si256_u16.spec
    (arr : Slice Std.U16) (at1 : Std.Usize) (v : U16x16)
    (hbnd : at1.val + 16 ≤ arr.length) :
  verify.intrinsics.x86_64.avx2.storeu_si256_u16 arr at1 v
  ⦃ (r : Slice Std.U16) =>
    ∃ (h_len : r.length = arr.length),
      ∀ k (hk : k < arr.length),
        r[k] = if h : at1.val ≤ k ∧ k < at1.val + 16
               then v[k - at1.val]
               else arr[k] ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.storeu_si256_u16
  step*
  refine ⟨r_post1, fun k hk => ?_⟩
  split
  · grind
  · grind

/-! ## Constants & broadcasts -/

/-- Zeroed 256-bit register. -/
@[step] theorem verify.intrinsics.x86_64.avx2.setzero_si256.spec :
  verify.intrinsics.x86_64.avx2.setzero_si256
  ⦃ (r : U8x32) =>
    ∀ k, (hk : k < 32) → r[k] = 0#u8 ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.setzero_si256
  step*
  grind [Array.repeat_val]

/-- Broadcast a signed i16 to all 16 lanes (interpreted as u16). -/
@[step] theorem verify.intrinsics.x86_64.avx2.set1_epi16.spec (a : Std.I16) :
  verify.intrinsics.x86_64.avx2.set1_epi16 a
  ⦃ (r : U16x16) =>
    ∀ k, (hk : k < 16) → r[k].bv = a.bv ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.set1_epi16
  step*
  intro k hk
  have hrep : (Array.repeat 16#usize v)[k] = v :=
    Std.Array.getElem_repeat _ _ _ (by scalar_tac)
  have hbv : v.bv = a.bv := by
    subst v_post
    show (IScalar.hcast .U16 a).bv = a.bv
    unfold IScalar.hcast; simp [BitVec.signExtend_eq]
  grind

/-! ## Lanewise-delegated wrappers

These are 1-line shims; the post mirrors the corresponding layer-2 spec in
`Intrinsics/Properties/Lanewise.lean`.

Each op's post was validated against the Intel® 64/IA-32 SDM "Operation"
pseudocode (vol. 2, via the felixcloutier.com mirror) for the VEX.256
encoding, and is exercised by the differential HW tests in
`SymCRust/src/verify/tests/`. Per-op mnemonic tagged on each docstring. -/

/-- 16-bit lane wrapping add.  Intel SDM `VPADDW` — packed 16-bit add,
    overflow wraps (low 16 bits kept). -/
@[step] theorem verify.intrinsics.x86_64.avx2.add_epi16.spec
    (a b : U16x16) :
  verify.intrinsics.x86_64.avx2.add_epi16 a b
  ⦃ (r : U16x16) =>
    ∀ k, (hk : k < 16) →
      r[k] = core.num.U16.wrapping_add a[k] b[k] ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.add_epi16
  step*


/-- 16-bit lane wrapping sub.  Intel SDM `VPSUBW` — packed 16-bit subtract,
    overflow wraps (low 16 bits kept). -/
@[step] theorem verify.intrinsics.x86_64.avx2.sub_epi16.spec
    (a b : U16x16) :
  verify.intrinsics.x86_64.avx2.sub_epi16 a b
  ⦃ (r : U16x16) =>
    ∀ k, (hk : k < 16) →
      r[k] = core.num.U16.wrapping_sub a[k] b[k] ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.sub_epi16
  step*


/-- 16-bit lane wrapping mul (low half).  Intel SDM `VPMULLW` — packed 16-bit
    multiply, stores the low 16 bits of each 32-bit product. -/
@[step] theorem verify.intrinsics.x86_64.avx2.mullo_epi16.spec
    (a b : U16x16) :
  verify.intrinsics.x86_64.avx2.mullo_epi16 a b
  ⦃ (r : U16x16) =>
    ∀ k, (hk : k < 16) →
      r[k] = core.num.U16.wrapping_mul a[k] b[k] ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.mullo_epi16
  step*


/-- 16-bit lane unsigned multiply, high half.  Intel SDM `VPMULHUW` — packed
    unsigned 16-bit multiply, stores the high 16 bits of each 32-bit product. -/
@[step] theorem verify.intrinsics.x86_64.avx2.mulhi_epu16.spec
    (a b : U16x16) :
  verify.intrinsics.x86_64.avx2.mulhi_epu16 a b
  ⦃ (r : U16x16) =>
    ∀ k, (hk : k < 16) →
      r[k].val = (a[k].val * b[k].val) / 65536 ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.mulhi_epu16
  step*


/-- 16-bit lane equality mask.  Intel SDM `VPCMPEQW` — per-word compare-equal,
    result lane all-ones (0xFFFF) if equal else all-zeros. -/
@[step] theorem verify.intrinsics.x86_64.avx2.cmpeq_epi16.spec
    (a b : U16x16) :
  verify.intrinsics.x86_64.avx2.cmpeq_epi16 a b
  ⦃ (r : U16x16) =>
    ∀ k, (hk : k < 16) →
      r[k] = if a[k] = b[k] then 65535#u16 else 0#u16 ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.cmpeq_epi16
  step*
  exact r_post1 _ r_post2


/-- 16-bit lane signed greater-than mask.  Intel SDM `VPCMPGTW` — per-word
    *signed* compare-greater, result lane all-ones (0xFFFF) if greater else
    all-zeros. -/
@[step] theorem verify.intrinsics.x86_64.avx2.cmpgt_epi16.spec
    (a b : U16x16) :
  verify.intrinsics.x86_64.avx2.cmpgt_epi16 a b
  ⦃ (r : U16x16) =>
    ∀ k, (hk : k < 16) →
      r[k] = if a[k].bv.toInt > b[k].bv.toInt then 65535#u16
                 else 0#u16 ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.cmpgt_epi16
  step*
  exact r_post1 _ r_post2


/-- Bytewise AND on 256-bit register.  Intel SDM `VPAND` — bitwise `a & b`. -/
@[step] theorem verify.intrinsics.x86_64.avx2.and_si256.spec
    (a b : U8x32) :
  verify.intrinsics.x86_64.avx2.and_si256 a b
  ⦃ (r : U8x32) =>
    ∀ k, (hk : k < 32) → r[k] = a[k] &&& b[k] ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.and_si256
  step*


/-- Bytewise ANDNOT on 256-bit register (`~a & b`).  Intel SDM `VPANDN` —
    bitwise `(NOT a) & b` (first operand negated). -/
@[step] theorem verify.intrinsics.x86_64.avx2.andnot_si256.spec
    (a b : U8x32) :
  verify.intrinsics.x86_64.avx2.andnot_si256 a b
  ⦃ (r : U8x32) =>
    ∀ k, (hk : k < 32) → r[k] = (~~~ a[k]) &&& b[k] ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.andnot_si256
  step*


/-- Bytewise OR on 256-bit register.  Intel SDM `VPOR` — bitwise `a | b`. -/
@[step] theorem verify.intrinsics.x86_64.avx2.or_si256.spec
    (a b : U8x32) :
  verify.intrinsics.x86_64.avx2.or_si256 a b
  ⦃ (r : U8x32) =>
    ∀ k, (hk : k < 32) → r[k] = a[k] ||| b[k] ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.or_si256
  step*


/-! ## Shifts (each entry-point drives an AVX2-local `_loop`)

Validated against Intel SDM: `VPSLLQ` / `VPSRLQ` shift each 64-bit lane left /
right logically by the count; when the count exceeds 63 the lane is zeroed
(the model computes `c.val < 64` and yields `0` otherwise). -/

/-- Loop of `slli_epi64`: shift each u64 lane left by `c.val`. -/
@[step] theorem verify.intrinsics.x86_64.avx2.slli_epi64_loop.spec
    (iter : core.ops.range.Range Std.Usize) (a out : U64x4)
    (c : Std.U32)
    (hStart : iter.start.val ≤ iter.end.val) (hEnd : iter.end.val ≤ 4)
    (hc : c.val < 64) :
  verify.intrinsics.x86_64.avx2.slli_epi64_loop iter a out c
  ⦃ (r : U64x4) =>
    (∀ k, (hk : k < iter.start.val) → r[k] = out[k]) ∧
    (∀ k, iter.start.val ≤ k → (hk : k < iter.end.val) →
        r[k].bv = a[k].bv.shiftLeft c.val) ∧
    (∀ k, iter.end.val ≤ k → (hk : k < 4) → r[k] = out[k]) ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.slli_epi64_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← iter_next_some
    rw [hsome]
    dsimp only
    step*
    have ha1_at : a1[iter.start.val] = i2 := by
      rw [a1_post]; simp
    have ha1_other : ∀ k, k ≠ iter.start.val → (hk : k < 4) → a1[k] = out[k] := by
      intro k hne hk
      rw [a1_post]; simp_lists
    refine ⟨?_, ?_, ?_⟩
    · intro k hk
      have hk1 : k < iter1.start.val := by rw [hstart']; scalar_tac
      have e1 : r[k] = a1[k] := r_post1 k hk1
      rw [e1, ha1_other k (by scalar_tac) (by scalar_tac)]
    · intro k hk_lo hk_hi
      by_cases heq : k = iter.start.val
      · subst heq
        have hk1 : iter.start.val < iter1.start.val := by rw [hstart']; scalar_tac
        have e1 : r[iter.start.val] = a1[iter.start.val] := r_post1 iter.start.val hk1
        rw [e1, ha1_at]
        refine i2_post2.trans ?_
        rw [i1_post]
        rfl
      · have hk1 : iter1.start.val ≤ k := by rw [hstart']; scalar_tac
        have hk1' : k < iter1.«end».val := by rw [hend']; exact hk_hi
        exact r_post2 k hk1 hk1'
    · intro k hk_lo hk_hi
      have hk1 : iter1.«end».val ≤ k := by rw [hend']; exact hk_lo
      have e3 : r[k] = a1[k] := r_post3 k hk1 hk_hi
      rw [e3, ha1_other k (by scalar_tac) hk_hi]
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← iter_next_none
    rw [hnone]
    dsimp only
    simp only [WP.spec_ok]
    refine ⟨?_, ?_, ?_⟩
    · intro k hk; trivial
    · intro k hk_lo hk_hi; scalar_tac
    · intro k hk_lo hk_hi; trivial
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- 64-bit lane shift-left by `count` (signed; out-of-range → all zeros).
    Intel SDM `VPSLLQ` — per-qword logical left shift; count > 63 zeros the lane. -/
@[step] theorem verify.intrinsics.x86_64.avx2.slli_epi64.spec
    (a : U64x4) (count : Std.I32) :
  verify.intrinsics.x86_64.avx2.slli_epi64 a count
  ⦃ (r : U64x4) =>
    ∀ k (hk : k < 4), r[k].bv =
      if 0 ≤ count.val ∧ count.val < 64 then a[k].bv.shiftLeft count.toNat
      else 0 ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.slli_epi64
  step*
  · -- hc: side condition ↑c < 64
    exact i32_hcast_u32_val count ‹_› ‹_› c c_post
  · -- out-of-range (¬ count < 64)
    simp only [if_neg (show ¬ (0 ≤ count.val ∧ count.val < 64) from by
      intro ⟨_, h2⟩; scalar_tac)]
    intro k hk; exact repeat_u64_zero_bv k hk
  · -- out-of-range (¬ 0 ≤ count)
    simp only [if_neg (show ¬ (0 ≤ count.val ∧ count.val < 64) from by
      intro ⟨h1, _⟩; scalar_tac)]
    intro k hk; exact repeat_u64_zero_bv k hk

/-- Loop of `srli_epi64`: shift each u64 lane right (logical) by `c.val`. -/
@[step] theorem verify.intrinsics.x86_64.avx2.srli_epi64_loop.spec
    (iter : core.ops.range.Range Std.Usize) (a out : U64x4)
    (c : Std.U32)
    (hStart : iter.start.val ≤ iter.end.val) (hEnd : iter.end.val ≤ 4)
    (hc : c.val < 64) :
  verify.intrinsics.x86_64.avx2.srli_epi64_loop iter a out c
  ⦃ (r : U64x4) =>
    (∀ k, (hk : k < iter.start.val) → r[k] = out[k]) ∧
    (∀ k, iter.start.val ≤ k → (hk : k < iter.end.val) →
        r[k].bv = a[k].bv.ushiftRight c.val) ∧
    (∀ k, iter.end.val ≤ k → (hk : k < 4) → r[k] = out[k]) ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.srli_epi64_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← iter_next_some
    rw [hsome]
    dsimp only
    step*
    have ha1_at : a1[iter.start.val] = i2 := by
      rw [a1_post]; simp
    have ha1_other : ∀ k, k ≠ iter.start.val → (hk : k < 4) → a1[k] = out[k] := by
      intro k hne hk
      rw [a1_post]; simp_lists
    refine ⟨?_, ?_, ?_⟩
    · intro k hk
      have hk1 : k < iter1.start.val := by rw [hstart']; scalar_tac
      have e1 : r[k] = a1[k] := r_post1 k hk1
      rw [e1, ha1_other k (by scalar_tac) (by scalar_tac)]
    · intro k hk_lo hk_hi
      by_cases heq : k = iter.start.val
      · subst heq
        have hk1 : iter.start.val < iter1.start.val := by rw [hstart']; scalar_tac
        have e1 : r[iter.start.val] = a1[iter.start.val] := r_post1 iter.start.val hk1
        rw [e1, ha1_at]
        refine i2_post2.trans ?_
        rw [i1_post]
        rfl
      · have hk1 : iter1.start.val ≤ k := by rw [hstart']; scalar_tac
        have hk1' : k < iter1.«end».val := by rw [hend']; exact hk_hi
        exact r_post2 k hk1 hk1'
    · intro k hk_lo hk_hi
      have hk1 : iter1.«end».val ≤ k := by rw [hend']; exact hk_lo
      have e3 : r[k] = a1[k] := r_post3 k hk1 hk_hi
      rw [e3, ha1_other k (by scalar_tac) hk_hi]
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← iter_next_none
    rw [hnone]
    dsimp only
    simp only [WP.spec_ok]
    refine ⟨?_, ?_, ?_⟩
    · intro k hk; trivial
    · intro k hk_lo hk_hi; scalar_tac
    · intro k hk_lo hk_hi; trivial
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- 64-bit lane shift-right logical by `count` (signed; out-of-range → all zeros).
    Intel SDM `VPSRLQ` — per-qword logical right shift; count > 63 zeros the lane. -/
@[step] theorem verify.intrinsics.x86_64.avx2.srli_epi64.spec
    (a : U64x4) (count : Std.I32) :
  verify.intrinsics.x86_64.avx2.srli_epi64 a count
  ⦃ (r : U64x4) =>
    ∀ k (hk : k < 4), r[k].bv =
      if 0 ≤ count.val ∧ count.val < 64 then a[k].bv.ushiftRight count.toNat
      else 0 ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.srli_epi64
  step*
  · -- hc: side condition ↑c < 64
    exact i32_hcast_u32_val count ‹_› ‹_› c c_post
  · -- out-of-range (¬ count < 64)
    simp only [if_neg (show ¬ (0 ≤ count.val ∧ count.val < 64) from by
      intro ⟨_, h2⟩; scalar_tac)]
    intro k hk; exact repeat_u64_zero_bv k hk
  · -- out-of-range (¬ 0 ≤ count)
    simp only [if_neg (show ¬ (0 ≤ count.val ∧ count.val < 64) from by
      intro ⟨h1, _⟩; scalar_tac)]
    intro k hk; exact repeat_u64_zero_bv k hk

/-! ## `M256` byte-carrier YMM wrappers (`verify.intrinsics.x86_64.ymm.*`)

The SHA-3 4-way Keccak `rol4!` macro is redirected through the
byte-carrier backend `crate::verify::intrinsics::x86_64::ymm` (`M256 =
[u8;32]`). The `u64×4` op specs (`or`/`slli`/`srli`) present the `u64×4` lane
semantics on the `M256.u64x4` projection; the ML-KEM `u16×16` op specs
(`set1`/`setzero`/`add`/`sub`/`mullo`/`mulhi`/`cmpeq`/`cmpgt`/`and`/`andnot`)
present the `u16×16` lane semantics on the `M256.u16x16` projection. Both
mirror the silicon `_mm256_*` operations as **theorems** composing the
`avx2.*` shims above.

Vendor-doc validation: these wrappers carry no independent silicon semantics —
each composes exactly one `avx2.*` shim, whose post was validated against the
Intel SDM "Operation" pseudocode (see the per-op `VP*` mnemonics tagged on the
`## Lanewise-delegated wrappers` and `## Shifts` sections above). No separate
citation is duplicated here. -/

section YmmBackend

open Intrinsics.X86_64

/-- File-scoped: discharge `M256.u16x16`/`M256.u64x4` getElem bounds via
    `Array.length_eq` *before* `assumption`/`scalar_tac`, so the index proof
    never whnf-reduces the lane-view definition (which would blow up). -/
local macro_rules | `(tactic| get_elem_tactic) => `(tactic| first | (simp only [Aeneas.Std.Array.length_eq]; first | assumption | scalar_tac) | assumption | scalar_tac | grind)

/-- The loop's `fromLEBytes`-concatenation lane form *is* Simd's `M256.u64x4`
    lane (both are the little-endian octet of the same 8 source bytes). -/
private theorem bytes256_to_qwords256_lane_eq (b : M256) (k : Nat) (hk : k < 4) :
    bytes256_to_qwords256_lane b k (by scalar_tac) = (M256.u64x4 b)[k].bv := by
  rw [M256.u64x4_bv_getElem b k hk]
  unfold bytes256_to_qwords256_lane
  apply BitVec.eq_of_getLsbD_eq; intro j
  simp only [_root_.BitVec.fromLEBytes, BitVec.getLsbD_cast, BitVec.getLsbD_append,
    BitVec.getLsbD_or, BitVec.getLsbD_setWidth, BitVec.getLsbD_shiftLeft, List.length_cons,
    List.length_nil]
  by_cases h0 : (j:Nat) < 8 <;> by_cases h1 : (j:Nat) < 16 <;> by_cases h2 : (j:Nat) < 24
    <;> by_cases h3 : (j:Nat) < 32 <;> by_cases h4 : (j:Nat) < 40
    <;> by_cases h5 : (j:Nat) < 48 <;> by_cases h6 : (j:Nat) < 56 <;> grind

/-- The extracted `bytes256_to_qwords256` is the `M256.u64x4` projection. -/
private theorem bytes256_to_qwords256_eq (b : M256) :
    verify.intrinsics.x86_64.avx2.bytes256_to_qwords256 b
    ⦃ (r : U64x4) => r = M256.u64x4 b ⦄ := by
  have hspec := verify.intrinsics.x86_64.avx2.bytes256_to_qwords256.spec b
  apply WP.exists_imp_spec
  obtain ⟨r, hr_eq, hr_post⟩ := WP.spec_imp_exists hspec
  refine ⟨r, hr_eq, ?_⟩
  apply Subtype.ext
  apply List.ext_getElem (by simp)
  intro k h1 h2
  have hk : k < 4 := by simpa [Std.Array.length_eq] using h1
  apply UScalar.eq_of_val_eq
  change r[k].val = (M256.u64x4 b)[k].val
  rw [hr_post k hk]
  exact congrArg BitVec.toNat (bytes256_to_qwords256_lane_eq b k hk)

/-- **byte→u64 bitwise OR bridge** (u64×4 analogue of `M256.u16x16_and_lane`). -/
theorem M256.u64x4_or_lane (a b r : M256)
    (hr : ∀ k, (hk : k < 32) → r[k] = a[k] ||| b[k])
    (k : ℕ) (hk : k < 4) :
    (M256.u64x4 r)[k].bv = (M256.u64x4 a)[k].bv ||| (M256.u64x4 b)[k].bv := by
  rw [M256.u64x4_bv_getElem r k hk, M256.u64x4_bv_getElem a k hk, M256.u64x4_bv_getElem b k hk]
  have e : ∀ j, (hj : j < 8) → r[8*k+j].bv = a[8*k+j].bv ||| b[8*k+j].bv := by
    intro j hj
    rw [hr (8*k+j) (by omega)]; simp [UScalar.bv_or]
  simp only [e 1 (by omega), e 2 (by omega), e 3 (by omega),
             e 4 (by omega), e 5 (by omega), e 6 (by omega), e 7 (by omega)]
  apply BitVec.eq_of_getLsbD_eq
  intro j
  simp only [BitVec.getLsbD_append, BitVec.getLsbD_or]
  grind

open Intrinsics.X86_64 in
set_option maxHeartbeats 2000000 in
/-- The extracted `qwords256_to_bytes256` round-trips through `M256.u64x4`. -/
private theorem qwords256_to_bytes256_u64x4 (q : U64x4) :
    verify.intrinsics.x86_64.avx2.qwords256_to_bytes256 q
    ⦃ (r : M256) => M256.u64x4 r = q ⦄ := by
  unfold verify.intrinsics.x86_64.avx2.qwords256_to_bytes256
  step*
  · apply Subtype.ext
    apply List.ext_getElem (by simp)
    intro k h1 h2
    have hk : k < 4 := by simpa [Std.Array.length_eq] using h1
    apply UScalar.eq_of_val_eq
    change (M256.u64x4 r)[k].val = q[k].val
    rw [M256.u64x4_val_getElem r k hk]
    have p0 : r[8*k].val = q[k].val >>> (8*0) % 256 := r_post2 k (by omega) hk 0 (by omega)
    have p1 : r[8*k+1].val = q[k].val >>> (8*1) % 256 := r_post2 k (by omega) hk 1 (by omega)
    have p2 : r[8*k+2].val = q[k].val >>> (8*2) % 256 := r_post2 k (by omega) hk 2 (by omega)
    have p3 : r[8*k+3].val = q[k].val >>> (8*3) % 256 := r_post2 k (by omega) hk 3 (by omega)
    have p4 : r[8*k+4].val = q[k].val >>> (8*4) % 256 := r_post2 k (by omega) hk 4 (by omega)
    have p5 : r[8*k+5].val = q[k].val >>> (8*5) % 256 := r_post2 k (by omega) hk 5 (by omega)
    have p6 : r[8*k+6].val = q[k].val >>> (8*6) % 256 := r_post2 k (by omega) hk 6 (by omega)
    have p7 : r[8*k+7].val = q[k].val >>> (8*7) % 256 := r_post2 k (by omega) hk 7 (by omega)
    rw [p0, p1, p2, p3, p4, p5, p6, p7]
    have hq : q[k].val < 2^64 := by have := (q[k]'h2).hBounds; scalar_tac
    simp only [Nat.shiftRight_eq_div_pow]
    omega

open Intrinsics.X86_64 in
set_option maxHeartbeats 4000000 in
/-- `_mm256_or_si256` (byte-carrier) — per-`u64`-lane bitwise OR. -/
@[step] theorem verify.intrinsics.x86_64.ymm.or_si256.spec (a b : M256) :
  verify.intrinsics.x86_64.ymm.or_si256 a b
  ⦃ (r : M256) => ∀ k, (hk : k < 4) →
      (M256.u64x4 r)[k].bv = (M256.u64x4 a)[k].bv ||| (M256.u64x4 b)[k].bv ⦄ := by
  unfold verify.intrinsics.x86_64.ymm.or_si256
  step with verify.intrinsics.x86_64.avx2.or_si256.spec as ⟨r, hr⟩
  rename_i k hk
  exact M256.u64x4_or_lane a b r hr k hk

open Intrinsics.X86_64 in
/-- `_mm256_slli_epi64::<N>` (byte-carrier) — per-`u64`-lane logical shift left. -/
@[step] theorem verify.intrinsics.x86_64.ymm.slli_epi64.spec (N : Std.I32) (a : M256) :
  verify.intrinsics.x86_64.ymm.slli_epi64 N a
  ⦃ (r : M256) => ∀ k, (hk : k < 4) →
      (M256.u64x4 r)[k].bv =
        if 0 ≤ N.val ∧ N.val < 64
        then (M256.u64x4 a)[k].bv.shiftLeft N.toNat else 0#64 ⦄ := by
  unfold verify.intrinsics.x86_64.ymm.slli_epi64
  step with bytes256_to_qwords256_eq as ⟨a1, ha1⟩
  step with verify.intrinsics.x86_64.avx2.slli_epi64.spec as ⟨a2, ha2⟩
  step with qwords256_to_bytes256_u64x4 as ⟨r, hr⟩
  rename_i k hk
  have hrk : (M256.u64x4 r)[k] = a2[k] := by simp [hr]
  rw [hrk, ha2 k hk, ha1]
  split <;> rfl

open Intrinsics.X86_64 in
/-- `_mm256_srli_epi64::<N>` (byte-carrier) — per-`u64`-lane logical shift right. -/
@[step] theorem verify.intrinsics.x86_64.ymm.srli_epi64.spec (N : Std.I32) (a : M256) :
  verify.intrinsics.x86_64.ymm.srli_epi64 N a
  ⦃ (r : M256) => ∀ k, (hk : k < 4) →
      (M256.u64x4 r)[k].bv =
        if 0 ≤ N.val ∧ N.val < 64
        then (M256.u64x4 a)[k].bv.ushiftRight N.toNat else 0#64 ⦄ := by
  unfold verify.intrinsics.x86_64.ymm.srli_epi64
  step with bytes256_to_qwords256_eq as ⟨a1, ha1⟩
  step with verify.intrinsics.x86_64.avx2.srli_epi64.spec as ⟨a2, ha2⟩
  step with qwords256_to_bytes256_u64x4 as ⟨r, hr⟩
  rename_i k hk
  have hrk : (M256.u64x4 r)[k] = a2[k] := by simp [hr]
  rw [hrk, ha2 k hk, ha1]
  split <;> rfl

open Intrinsics.X86_64 in
/-- The extracted `bytes256_to_words16x16` is the `M256.u16x16` projection.
    Public Layer-1 bridge: used by the ML-KEM `mm256_store` consumer spec
    (`Symcrust/Properties/MLKEM/Intrinsics/X86_64/Avx2LayerNtt.lean`) to re-view the
    stored byte register as its `u16×16` lanes. -/
theorem bytes256_to_words16x16_eq (b : M256) :
    verify.intrinsics.x86_64.avx2.bytes256_to_words16x16 b
    ⦃ (r : U16x16) => r = M256.u16x16 b ⦄ := by
  have hspec := verify.intrinsics.x86_64.avx2.bytes256_to_words16x16.spec b
  apply WP.exists_imp_spec
  obtain ⟨r, hr_eq, hr_post⟩ := WP.spec_imp_exists hspec
  refine ⟨r, hr_eq, ?_⟩
  apply Subtype.ext
  apply List.ext_getElem
  · simp []
  · intro k h1 h2
    have hk : k < 16 := by simpa [Std.Array.length_eq] using h1
    apply UScalar.eq_of_val_eq
    change r[k].val = (M256.u16x16 b)[k].val
    rw [hr_post k hk, M256.u16x16_val_getElem b k hk]

open Intrinsics.X86_64 in
/-- The extracted `words16x16_to_bytes256` round-trips through `M256.u16x16`.
    Public Layer-1 bridge: used by the ML-KEM `mm256_load` consumer spec
    (`Symcrust/Properties/MLKEM/Intrinsics/X86_64/Avx2LayerNtt.lean`) to read the
    loaded byte register as its `u16×16` lanes. -/
theorem words16x16_to_bytes256_u16x16 (w : U16x16) :
    verify.intrinsics.x86_64.avx2.words16x16_to_bytes256 w
    ⦃ (r : M256) => M256.u16x16 r = w ⦄ := by
  have hspec := verify.intrinsics.x86_64.avx2.words16x16_to_bytes256.spec w
  apply WP.exists_imp_spec
  obtain ⟨r, hr_eq, hr_post⟩ := WP.spec_imp_exists hspec
  refine ⟨r, hr_eq, ?_⟩
  apply Subtype.ext
  apply List.ext_getElem
  · simp []
  · intro k h1 h2
    have hk : k < 16 := by simpa [Std.Array.length_eq] using h2
    apply UScalar.eq_of_val_eq
    change (M256.u16x16 r)[k].val = w[k].val
    rw [M256.u16x16_val_getElem r k hk]
    obtain ⟨e0, e1⟩ := hr_post k hk
    have hub : (w[k]'h2).val < 65536 := by have := (w[k]'h2).hBounds; scalar_tac
    rw [e0, e1]
    simp only [Nat.shiftRight_eq_div_pow]
    agrind

open Intrinsics.X86_64 in
/-- **byte→u16 bitwise AND bridge** (u16×16 analogue of `m128.u16x8_and_lane`). -/
theorem M256.u16x16_and_lane (a b r : M256)
    (hr : ∀ k, (hk : k < 32) → r[k] = a[k] &&& b[k])
    (k : ℕ) (hk : k < 16) :
    (M256.u16x16 r)[k] =
      (M256.u16x16 a)[k] &&& (M256.u16x16 b)[k] := by
  apply U16.bv_eq_imp_eq
  rw [UScalar.bv_and]
  rw [M256.u16x16_getElem r k hk, M256.u16x16_getElem a k hk, M256.u16x16_getElem b k hk]
  have hr0 : r[2*k] = a[2*k] &&& b[2*k] := hr (2*k) (by scalar_tac)
  have hr1 : r[2*k + 1] = a[2*k + 1] &&& b[2*k + 1] :=
    hr (2*k + 1) (by scalar_tac)
  rw [hr0, hr1]
  simp only [UScalar.bv_and]
  rw [_root_.BitVec.and_append]

open Intrinsics.X86_64 in
/-- **byte→u16 bitwise AND-NOT bridge** (u16×16 analogue of `m128.u16x8_andnot_lane`). -/
theorem M256.u16x16_andnot_lane (a b r : M256)
    (hr : ∀ k, (hk : k < 32) →
      r[k] = (~~~ a[k]) &&& b[k])
    (k : ℕ) (hk : k < 16) :
    (M256.u16x16 r)[k] =
      (~~~ (M256.u16x16 a)[k]) &&& (M256.u16x16 b)[k] := by
  apply U16.bv_eq_imp_eq
  rw [UScalar.bv_and, UScalar.bv_not]
  rw [M256.u16x16_getElem r k hk, M256.u16x16_getElem a k hk, M256.u16x16_getElem b k hk]
  have hr0 : r[2*k] = (~~~ a[2*k]) &&& b[2*k] := hr (2*k) (by scalar_tac)
  have hr1 : r[2*k + 1] = (~~~ a[2*k + 1]) &&& b[2*k + 1] :=
    hr (2*k + 1) (by scalar_tac)
  rw [hr0, hr1]
  simp only [UScalar.bv_and, UScalar.bv_not]
  rw [_root_.BitVec.not_append, _root_.BitVec.and_append]

/-! ### `u16×16` ML-KEM lane-op `@[step]` specs (byte-carrier `M256`) -/

open Intrinsics.X86_64 in
/-- `_mm256_setzero_si256` (byte-carrier) — all 16 u16 lanes zero. -/
@[step] theorem verify.intrinsics.x86_64.ymm.setzero_si256.spec :
  verify.intrinsics.x86_64.ymm.setzero_si256
  ⦃ (r : M256) => ∀ k, (hk : k < 16) → (M256.u16x16 r)[k] = 0#u16 ⦄ := by
  unfold verify.intrinsics.x86_64.ymm.setzero_si256
  step with verify.intrinsics.x86_64.avx2.setzero_si256.spec as ⟨r, hr⟩
  rename_i k hk
  apply UScalar.eq_of_val_eq
  rw [M256.u16x16_val_getElem r k hk]
  rw [hr (2*k) (by scalar_tac), hr (2*k+1) (by scalar_tac)]
  rfl

open Intrinsics.X86_64 in
/-- `_mm256_set1_epi16` (byte-carrier) — broadcast `v` to all 16 u16 lanes. -/
@[step] theorem verify.intrinsics.x86_64.ymm.set1_epi16.spec (v : Std.I16) :
  verify.intrinsics.x86_64.ymm.set1_epi16 v
  ⦃ (r : M256) => ∀ k, (hk : k < 16) → (M256.u16x16 r)[k].bv = v.bv ⦄ := by
  unfold verify.intrinsics.x86_64.ymm.set1_epi16
  step with verify.intrinsics.x86_64.avx2.set1_epi16.spec as ⟨a1, ha1⟩
  step with words16x16_to_bytes256_u16x16 as ⟨r, hr⟩
  rename_i k hk
  subst hr
  exact ha1 k hk

open Intrinsics.X86_64 in
/-- `_mm256_add_epi16` (byte-carrier) — lane-wise wrapping u16 add. -/
@[step] theorem verify.intrinsics.x86_64.ymm.add_epi16.spec (a b : M256) :
  verify.intrinsics.x86_64.ymm.add_epi16 a b
  ⦃ (r : M256) => ∀ k, (hk : k < 16) →
      (M256.u16x16 r)[k] =
        core.num.U16.wrapping_add (M256.u16x16 a)[k] (M256.u16x16 b)[k] ⦄ := by
  unfold verify.intrinsics.x86_64.ymm.add_epi16
  step with bytes256_to_words16x16_eq as ⟨a1, ha1⟩
  step with bytes256_to_words16x16_eq as ⟨a2, ha2⟩
  step with verify.intrinsics.x86_64.avx2.add_epi16.spec as ⟨a3, ha3⟩
  step with words16x16_to_bytes256_u16x16 as ⟨r, hr⟩
  rename_i k hk
  subst ha1 ha2 hr
  exact ha3 k hk

open Intrinsics.X86_64 in
/-- `_mm256_sub_epi16` (byte-carrier) — lane-wise wrapping u16 sub. -/
@[step] theorem verify.intrinsics.x86_64.ymm.sub_epi16.spec (a b : M256) :
  verify.intrinsics.x86_64.ymm.sub_epi16 a b
  ⦃ (r : M256) => ∀ k, (hk : k < 16) →
      (M256.u16x16 r)[k] =
        core.num.U16.wrapping_sub (M256.u16x16 a)[k] (M256.u16x16 b)[k] ⦄ := by
  unfold verify.intrinsics.x86_64.ymm.sub_epi16
  step with bytes256_to_words16x16_eq as ⟨a1, ha1⟩
  step with bytes256_to_words16x16_eq as ⟨a2, ha2⟩
  step with verify.intrinsics.x86_64.avx2.sub_epi16.spec as ⟨a3, ha3⟩
  step with words16x16_to_bytes256_u16x16 as ⟨r, hr⟩
  rename_i k hk
  subst ha1 ha2 hr
  exact ha3 k hk

open Intrinsics.X86_64 in
/-- `_mm256_mullo_epi16` (byte-carrier) — lane-wise low 16 bits of the u16 product. -/
@[step] theorem verify.intrinsics.x86_64.ymm.mullo_epi16.spec (a b : M256) :
  verify.intrinsics.x86_64.ymm.mullo_epi16 a b
  ⦃ (r : M256) => ∀ k, (hk : k < 16) →
      (M256.u16x16 r)[k] =
        core.num.U16.wrapping_mul (M256.u16x16 a)[k] (M256.u16x16 b)[k] ⦄ := by
  unfold verify.intrinsics.x86_64.ymm.mullo_epi16
  step with bytes256_to_words16x16_eq as ⟨a1, ha1⟩
  step with bytes256_to_words16x16_eq as ⟨a2, ha2⟩
  step with verify.intrinsics.x86_64.avx2.mullo_epi16.spec as ⟨a3, ha3⟩
  step with words16x16_to_bytes256_u16x16 as ⟨r, hr⟩
  rename_i k hk
  subst ha1 ha2 hr
  exact ha3 k hk

open Intrinsics.X86_64 in
/-- `_mm256_mulhi_epu16` (byte-carrier) — lane-wise high 16 bits of the unsigned u16 product. -/
@[step] theorem verify.intrinsics.x86_64.ymm.mulhi_epu16.spec (a b : M256) :
  verify.intrinsics.x86_64.ymm.mulhi_epu16 a b
  ⦃ (r : M256) => ∀ k, (hk : k < 16) →
      (M256.u16x16 r)[k].val =
        ((M256.u16x16 a)[k].val * (M256.u16x16 b)[k].val) / 65536 ⦄ := by
  unfold verify.intrinsics.x86_64.ymm.mulhi_epu16
  step with bytes256_to_words16x16_eq as ⟨a1, ha1⟩
  step with bytes256_to_words16x16_eq as ⟨a2, ha2⟩
  step with verify.intrinsics.x86_64.avx2.mulhi_epu16.spec as ⟨a3, ha3⟩
  step with words16x16_to_bytes256_u16x16 as ⟨r, hr⟩
  rename_i k hk
  subst ha1 ha2 hr
  exact ha3 k hk

/-- Pure lane-wise equality mask: lane `i` is all-ones iff `a[i] = b[i]`.
    The spec function for `cmpeq_epi16`, so its postcondition is a plain array
    equality (no inline `ite` over carrier lanes — see `cmpgt_epi16.pure`). -/
def cmpeq_epi16.pure (a b : U16x16) : U16x16 :=
  Std.Array.ofFn fun i : Fin 16 => if a[i] = b[i] then 65535#u16 else 0#u16

@[simp] theorem cmpeq_epi16.pure_getElem (a b : U16x16) (k : ℕ) (hk : k < 16) :
    (cmpeq_epi16.pure a b)[k] = if a[k] = b[k] then 65535#u16 else 0#u16 := by
  unfold cmpeq_epi16.pure; exact Std.Array.getElem_ofFn _ k (by scalar_tac)

/-- Pure lane-wise signed greater-than mask: lane `i` is all-ones iff
    `a[i] >ₛ b[i]`.

    **Why a named pure function, not an inline `ite` in the post.**  An inline
    `if (M256.u16x16 a)[k]… then …` puts a `Decidable` comparison over *carrier
    lane accesses* in the goal; discharging it forces the goal's and the
    hypothesis' `Decidable` instances to be proven defeq, which whnf-evaluates
    `(M256.u16x16 a)[k]` — the `Std.Array.bv`/`listToBV` fold over 32 bytes. -/
def cmpgt_epi16.pure (a b : U16x16) : U16x16 :=
  Std.Array.ofFn fun i : Fin 16 =>
    if a[i].bv.toInt > b[i].bv.toInt then 65535#u16 else 0#u16

@[simp] theorem cmpgt_epi16.pure_getElem (a b : U16x16) (k : ℕ) (hk : k < 16) :
    (cmpgt_epi16.pure a b)[k] = if a[k].bv.toInt > b[k].bv.toInt then 65535#u16 else 0#u16 := by
  unfold cmpgt_epi16.pure; exact Std.Array.getElem_ofFn _ k (by scalar_tac)

open Intrinsics.X86_64 in
/-- `_mm256_cmpeq_epi16` (byte-carrier) — lane-wise equality mask. -/
@[step] theorem verify.intrinsics.x86_64.ymm.cmpeq_epi16.spec (a b : M256) :
  verify.intrinsics.x86_64.ymm.cmpeq_epi16 a b
  ⦃ (r : M256) => M256.u16x16 r = cmpeq_epi16.pure (M256.u16x16 a) (M256.u16x16 b) ⦄ := by
  unfold verify.intrinsics.x86_64.ymm.cmpeq_epi16
  step with bytes256_to_words16x16_eq as ⟨a1, ha1⟩
  step with bytes256_to_words16x16_eq as ⟨a2, ha2⟩
  step with verify.intrinsics.x86_64.avx2.cmpeq_epi16.spec as ⟨a3, ha3⟩
  step with words16x16_to_bytes256_u16x16 as ⟨r, hr⟩
  subst ha1 ha2
  rw [hr]
  apply Subtype.ext
  apply List.ext_getElem (by simp [cmpeq_epi16.pure])
  intro k h1 h2
  have hk : k < 16 := by simpa [Std.Array.length_eq] using h1
  show a3[k] = (cmpeq_epi16.pure (M256.u16x16 a) (M256.u16x16 b))[k]
  rw [ha3 k hk]
  exact (cmpeq_epi16.pure_getElem (M256.u16x16 a) (M256.u16x16 b) k hk).symm

open Intrinsics.X86_64 in
/-- `_mm256_cmpgt_epi16` (byte-carrier) — lane-wise signed greater-than mask. -/
@[step] theorem verify.intrinsics.x86_64.ymm.cmpgt_epi16.spec (a b : M256) :
  verify.intrinsics.x86_64.ymm.cmpgt_epi16 a b
  ⦃ (r : M256) => M256.u16x16 r = cmpgt_epi16.pure (M256.u16x16 a) (M256.u16x16 b) ⦄ := by
  unfold verify.intrinsics.x86_64.ymm.cmpgt_epi16
  step with bytes256_to_words16x16_eq as ⟨a1, ha1⟩
  step with bytes256_to_words16x16_eq as ⟨a2, ha2⟩
  step with verify.intrinsics.x86_64.avx2.cmpgt_epi16.spec as ⟨a3, ha3⟩
  step with words16x16_to_bytes256_u16x16 as ⟨r, hr⟩
  subst ha1 ha2
  rw [hr]
  apply Subtype.ext
  apply List.ext_getElem (by simp [cmpgt_epi16.pure])
  intro k h1 h2
  have hk : k < 16 := by simpa [Std.Array.length_eq] using h1
  show a3[k] = (cmpgt_epi16.pure (M256.u16x16 a) (M256.u16x16 b))[k]
  rw [ha3 k hk]
  exact (cmpgt_epi16.pure_getElem (M256.u16x16 a) (M256.u16x16 b) k hk).symm

open Intrinsics.X86_64 in
/-- `_mm256_and_si256` (byte-carrier) — lifted to the u16 lane view. -/
@[step] theorem verify.intrinsics.x86_64.ymm.and_si256.spec (a b : M256) :
  verify.intrinsics.x86_64.ymm.and_si256 a b
  ⦃ (r : M256) => ∀ k, (hk : k < 16) →
      (M256.u16x16 r)[k] = (M256.u16x16 a)[k] &&& (M256.u16x16 b)[k] ⦄ := by
  unfold verify.intrinsics.x86_64.ymm.and_si256
  step with verify.intrinsics.x86_64.avx2.and_si256.spec as ⟨r, hr⟩
  rename_i k hk
  exact M256.u16x16_and_lane a b r (fun j hj => hr j hj) k hk

open Intrinsics.X86_64 in
/-- `_mm256_andnot_si256` (byte-carrier) — lifted to the u16 lane view (`~a & b`). -/
@[step] theorem verify.intrinsics.x86_64.ymm.andnot_si256.spec (a b : M256) :
  verify.intrinsics.x86_64.ymm.andnot_si256 a b
  ⦃ (r : M256) => ∀ k, (hk : k < 16) →
      (M256.u16x16 r)[k] = (~~~ (M256.u16x16 a)[k]) &&& (M256.u16x16 b)[k] ⦄ := by
  unfold verify.intrinsics.x86_64.ymm.andnot_si256
  step with verify.intrinsics.x86_64.avx2.andnot_si256.spec as ⟨r, hr⟩
  rename_i k hk
  exact M256.u16x16_andnot_lane a b r (fun j hj => hr j hj) k hk

end YmmBackend

end symcrust
