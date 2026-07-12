/-
  Public SSSE3 Layer-1 surface.

  `@[step]` theorems for the Rust models of intrinsics `verify.intrinsics.x86_64.ssse3.*`
  extracted to `Symcrust/Code/*`.

  See `INTRINSICS.md` for the layered architecture.
-/
import Symcrust.Code.Funs
import Intrinsics.Properties.Lanewise
import Intrinsics.Properties.Lanes
import Intrinsics.Properties.IterRange
import Intrinsics.Simd
open Aeneas Aeneas.Std Intrinsics

local macro_rules
| `(tactic| get_elem_tactic) => `(tactic| first | assumption | grind)

namespace symcrust

attribute [local step] iter_next_some iter_next_none

/-! ## `shuffle_epi8`

Validated against Intel SDM `PSHUFB` "Operation": for each result byte `i`, if
the control byte's high bit (`mask[i] & 0x80`) is set the result byte is `0`,
otherwise the result byte is `a[mask[i] & 0x0F]` (in-lane 16-byte lookup).
Exercised by the differential HW tests in `SymCRust/src/verify/tests/`. -/

/-- SSSE3 byte shuffle, per-iteration loop body.  At index `i ∈ [iter.start,
    iter.end)` the loop writes `out[i] := 0` if the mask high bit is set, else
    `out[i] := a[mask[i] & 0x0f]`.  Entries outside the iteration range remain
    untouched. -/
@[step] theorem verify.intrinsics.x86_64.ssse3.shuffle_epi8_loop.spec
    (iter : core.ops.range.Range Std.Usize)
    (a mask out : U8x16)
    (hStart : iter.start.val ≤ iter.end.val) (hEnd : iter.end.val ≤ 16) :
  verify.intrinsics.x86_64.ssse3.shuffle_epi8_loop iter a mask out
  ⦃ (r : U8x16) =>
    (∀ k, (hk : k < iter.start.val) → r[k] = out[k]) ∧
    (∀ k, iter.start.val ≤ k → (hk : k < iter.end.val) →
        r[k] =
          if (mask[k].bv &&& 128#8) ≠ 0#8 then 0#u8
          else a[(mask[k].bv &&& 15#8).toNat]'(by
            rw [Std.Array.length_eq, BitVec.toNat_and]
            exact Nat.lt_of_le_of_lt Nat.and_le_right (by decide))) ∧
    (∀ k, iter.end.val ≤ k → (hk : k < 16) → r[k] = out[k]) ⦄ := by
  unfold verify.intrinsics.x86_64.ssse3.shuffle_epi8_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← iter_next_some
    rw [hsome]
    dsimp only
    step*
    case _ => -- TRUE branch: mask hi-bit set, write 0
      refine ⟨?_, ?_, ?_⟩
      · intro k hk
        have h1 : k < iter1.start.val := by scalar_tac
        rw [r_post1 k h1, a1_post]
        simp_lists
      · intro k hk_lo hk_hi
        by_cases heq : k = iter.start.val
        · subst heq
          have h1 : iter.start.val < iter1.start.val := by scalar_tac
          rw [r_post1 iter.start.val h1, a1_post]
          have hcond : (mask[iter.start.val].bv &&& 128#8) ≠ 0#8 := by
            have hne : (i1 != 0#u8) = true := by assumption
            simp only [bne_iff_ne, ne_eq] at hne
            have hmm : mask[iter.start.val] = m := by
              rw [m_post]; rfl
            rw [hmm]
            have hi1 : i1.bv = m.bv &&& 128#8 := by
              have := i1_post2
              simpa using this
            intro h
            apply hne
            have hbv : i1.bv = 0#8 := by rw [hi1]; exact h
            have : i1.val = 0 := by
              show i1.bv.toNat = 0
              rw [hbv]; decide
            apply UScalar.eq_of_val_eq; exact this
          rw [if_pos hcond]
          simp_lists
        · have h1 : iter1.start.val ≤ k := by scalar_tac
          have h2 : k < iter1.end.val := by scalar_tac
          exact r_post2 k h1 h2
      · intro k hk_lo hk_hi
        have h1 : iter1.end.val ≤ k := by scalar_tac
        rw [r_post3 k h1 hk_hi, a1_post]
        simp_lists
    case hbound =>
      have : i3.val = (m.bv &&& 15#8).toNat := by
        have heq : i2.bv = m.bv &&& 15#8 := by have := i2_post2; simpa using this
        have h_eq : i3.val = i2.val := by simp [i3_post]
        rw [h_eq]
        show i2.bv.toNat = _
        rw [heq]
      simp only [Std.Array.length_eq]
      rw [this]
      exact Nat.lt_of_le_of_lt Nat.and_le_right (by decide)
    case _ => -- FALSE branch: mask hi-bit clear, write a[i3]
      refine ⟨?_, ?_, ?_⟩
      · intro k hk
        have h1 : k < iter1.start.val := by scalar_tac
        rw [r_post1 k h1, a1_post]
        simp_lists
      · intro k hk_lo hk_hi
        by_cases heq : k = iter.start.val
        · subst heq
          have h1 : iter.start.val < iter1.start.val := by scalar_tac
          rw [r_post1 iter.start.val h1, a1_post]
          have hcond : ¬ ((mask[iter.start.val].bv &&& 128#8) ≠ 0#8) := by
            have hne : ¬ (i1 != 0#u8) = true := by assumption
            simp only [bne_iff_ne, ne_eq, not_not] at hne
            have hmm : mask[iter.start.val] = m := by
              rw [m_post]; rfl
            rw [hmm]
            simp only [not_not]
            have hi1 : i1.bv = m.bv &&& 128#8 := by have := i1_post2; simpa using this
            rw [← hi1]
            have : i1.val = 0 := by rw [hne]; decide
            apply BitVec.eq_of_toNat_eq
            exact this
          rw [if_neg hcond]
          have hi3 : i3.val = (mask[iter.start.val].bv &&& 15#8).toNat := by
            have hmm : mask[iter.start.val] = m := by
              rw [m_post]; rfl
            rw [hmm]
            have hi2bv : i2.bv = m.bv &&& 15#8 := by have := i2_post2; simpa using this
            have h_eq : i3.val = i2.val := by simp [i3_post]
            rw [h_eq]
            show i2.bv.toNat = _
            rw [hi2bv]
          simp_lists
          rw [i4_post]
          exact getElem_congr_idx hi3
        · have h1 : iter1.start.val ≤ k := by scalar_tac
          have h2 : k < iter1.end.val := by scalar_tac
          exact r_post2 k h1 h2
      · intro k hk_lo hk_hi
        have h1 : iter1.end.val ≤ k := by scalar_tac
        rw [r_post3 k h1 hk_hi, a1_post]
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
  decreasing_by all_goals (simp only [hstart', hend']; scalar_tac)

/-- SSSE3 byte shuffle: each output lane is either zero (mask high bit set)
    or the source byte at the index encoded in the low 4 bits of the mask. -/
@[step] theorem verify.intrinsics.x86_64.ssse3.shuffle_epi8.spec
    (a mask : U8x16) :
  verify.intrinsics.x86_64.ssse3.shuffle_epi8 a mask
  ⦃ (r : U8x16) =>
    ∀ k, (hk : k < 16) →
      r[k] =
        if (mask[k].bv &&& 128#8) ≠ 0#8 then 0#u8
        else a[(mask[k].bv &&& 15#8).toNat]'(by
          rw [Std.Array.length_eq, BitVec.toNat_and]
          exact Nat.lt_of_le_of_lt Nat.and_le_right (by decide)) ⦄ := by
  unfold verify.intrinsics.x86_64.ssse3.shuffle_epi8
  step*
  exact r_post2 _ (Nat.zero_le _) r_post4

/-! ## `alignr_epi8`

Validated against Intel SDM `PALIGNR` "Operation": the destination and source
are concatenated (`a` high, `b` low) and the 256-bit composite is shifted right
by `count` bytes, keeping the low 16 bytes; offsets `≥ 32` read as `0`. -/

/-- SSSE3 byte-aligned right shift, per-iteration loop body.  Conceptually
    aligns the 256-bit concatenation `a || b` (lower 16 bytes = `b`, upper
    16 bytes = `a`) and reads the byte at offset `i + count`; if
    `i + count ≥ 32`, the byte is zero. -/
@[step] theorem verify.intrinsics.x86_64.ssse3.alignr_epi8_loop.spec
    (iter : core.ops.range.Range Std.Usize)
    (a b : U8x16) (count : Std.Usize)
    (out : U8x16)
    (hStart : iter.start.val ≤ iter.end.val) (hEnd : iter.end.val ≤ 16)
    (hCount : count.val + iter.end.val ≤ Std.Usize.max) :
  verify.intrinsics.x86_64.ssse3.alignr_epi8_loop iter a b count out
  ⦃ (r : U8x16) =>
    (∀ k, (hk : k < iter.start.val) → r[k] = out[k]) ∧
    (∀ k, iter.start.val ≤ k → (hk : k < iter.end.val) →
        r[k] =
          if h1 : k + count.val < 16 then b[k + count.val]
          else if h2 : k + count.val < 32 then a[k + count.val - 16]
          else 0#u8) ∧
    (∀ k, iter.end.val ≤ k → (hk : k < 16) → r[k] = out[k]) ⦄ := by
  unfold verify.intrinsics.x86_64.ssse3.alignr_epi8_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← iter_next_some
    rw [hsome]
    dsimp only
    step*
    -- Now we case-split on `src < 16` and `src < 32`
    by_cases hsrc16 : src < 16#usize
    · simp only [hsrc16, if_true]
      step*
      have hsrc_val : src.val < 16 := by
        have := hsrc16
        scalar_tac
      refine ⟨?_, ?_, ?_⟩
      · intro k hk
        have h1 : k < iter1.start.val := by scalar_tac
        rw [r_post1 k h1, a1_post]
        simp_lists
      · intro k hk_lo hk_hi
        by_cases heq : k = iter.start.val
        · subst heq
          have h1 : iter.start.val < iter1.start.val := by scalar_tac
          rw [r_post1 iter.start.val h1, a1_post]
          simp_lists
          have hpos : iter.start.val + count.val < 16 := by
            rw [← src_post]; exact hsrc_val
          rw [x_post]
          rw [dif_pos hpos]
          exact getElem_congr_idx src_post
        · have h1 : iter1.start.val ≤ k := by scalar_tac
          have h2 : k < iter1.end.val := by scalar_tac
          exact r_post2 k h1 h2
      · intro k hk_lo hk_hi
        have h1 : iter1.end.val ≤ k := by scalar_tac
        rw [r_post3 k h1 hk_hi, a1_post]
        simp_lists
    · simp only [hsrc16, if_false]
      by_cases hsrc32 : src < 32#usize
      · simp only [hsrc32, if_true]
        step*
        have hsrc16_val : ¬ (src.val < 16) := by
          intro h; apply hsrc16; scalar_tac
        have hsrc32_val : src.val < 32 := by
          have := hsrc32; scalar_tac
        refine ⟨?_, ?_, ?_⟩
        · intro k hk
          have h1 : k < iter1.start.val := by scalar_tac
          rw [r_post1 k h1, a1_post]
          simp_lists
        · intro k hk_lo hk_hi
          by_cases heq : k = iter.start.val
          · subst heq
            have h1 : iter.start.val < iter1.start.val := by scalar_tac
            rw [r_post1 iter.start.val h1, a1_post]
            simp_lists
            have hneg : ¬ (iter.start.val + count.val < 16) := by
              rw [← src_post]; exact hsrc16_val
            have hpos : iter.start.val + count.val < 32 := by
              rw [← src_post]; exact hsrc32_val
            rw [dif_neg hneg, dif_pos hpos]
            rw [x_post]
            exact getElem_congr_idx (by rw [x_post1, src_post])
          · have h1 : iter1.start.val ≤ k := by scalar_tac
            have h2 : k < iter1.end.val := by scalar_tac
            exact r_post2 k h1 h2
        · intro k hk_lo hk_hi
          have h1 : iter1.end.val ≤ k := by scalar_tac
          rw [r_post3 k h1 hk_hi, a1_post]
          simp_lists
      · simp only [hsrc32, if_false]
        step*
        have hsrc16_val : ¬ (src.val < 16) := by
          intro h; apply hsrc16; scalar_tac
        have hsrc32_val : ¬ (src.val < 32) := by
          intro h; apply hsrc32; scalar_tac
        refine ⟨?_, ?_, ?_⟩
        · intro k hk
          have h1 : k < iter1.start.val := by scalar_tac
          rw [r_post1 k h1, a1_post]
          simp_lists
        · intro k hk_lo hk_hi
          by_cases heq : k = iter.start.val
          · subst heq
            have h1 : iter.start.val < iter1.start.val := by scalar_tac
            rw [r_post1 iter.start.val h1, a1_post]
            simp_lists
            have hneg1 : ¬ (iter.start.val + count.val < 16) := by
              rw [← src_post]; exact hsrc16_val
            have hneg2 : ¬ (iter.start.val + count.val < 32) := by
              rw [← src_post]; exact hsrc32_val
            rw [dif_neg hneg1, dif_neg hneg2]
          · have h1 : iter1.start.val ≤ k := by scalar_tac
            have h2 : k < iter1.end.val := by scalar_tac
            exact r_post2 k h1 h2
        · intro k hk_lo hk_hi
          have h1 : iter1.end.val ≤ k := by scalar_tac
          rw [r_post3 k h1 hk_hi, a1_post]
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
  decreasing_by all_goals (simp only [hstart', hend']; scalar_tac)

/-- SSSE3 byte-aligned right shift: result is `(a || b) >> (count * 8)`
    (byte-wise), where `(a || b)[k] = b[k]` for `k < 16`, `a[k-16]` for
    `16 ≤ k < 32`, and `0` for `k ≥ 32`. -/
@[step] theorem verify.intrinsics.x86_64.ssse3.alignr_epi8.spec
    (a b : U8x16) (count : Std.Usize)
    (hCount : count.val + 16 ≤ Std.Usize.max) :
  verify.intrinsics.x86_64.ssse3.alignr_epi8 a b count
  ⦃ (r : U8x16) =>
    ∀ k, (hk : k < 16) →
      r[k] =
        if h1 : k + count.val < 16 then b[k + count.val]
        else if h2 : k + count.val < 32 then a[k + count.val - 16]
        else 0#u8 ⦄ := by
  unfold verify.intrinsics.x86_64.ssse3.alignr_epi8
  step*

end symcrust
