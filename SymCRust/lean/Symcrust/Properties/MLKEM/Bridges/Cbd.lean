/-
  # Bridges/Cbd.lean — Popcount-mask CBD bridges.

  Provides the bridge theorems that the η=3 and η=2 outer body proofs
  of `Sampling/SampleCBD.lean` use to convert the impl-side
  popcount-packed sample bits into the spec-side `samplePolyCbdCoeff`.

  The "shiftDistribMask2396745" identity family: given 24 raw bits at
  byte offset `3*chunks` of `pb_src`, the popcount-folding
  `(raw & 0x249249) + ((raw>>>1) & 0x249249) + ((raw>>>2) & 0x249249)`
  produces a value whose `j`-th 6-bit field `[6j, 6j+6)` carries the
  popcount of two disjoint 3-bit windows of the raw bits.  Each
  window's popcount matches the `low_pop / high_pop` of
  `samplePolyCbdCoeff` at index `4*chunks + j`.  An analogous identity
  holds for η=2 with mask `0x55555555` and 4-bit fields.

  Closure recipe (see `Helpers/PopcountShiftDistrib.lean` for the
  per-`j` bit-shift identities):

  1. Reduce `raw` to a `BitVec 32` via the 4-byte LE decomposition.
  2. Prove the shift/mask popcount identity by `bv_decide` on the
     32-bit BV (the j-th 6-bit field of `packed` is the popcount of
     the j-th two disjoint 3-bit windows of `raw`).
  3. Bridge `packed`'s 6-bit field to `low_pop − high_pop` and equate
     with `samplePolyCbdCoeff`'s definition via
     `BytesToBits ∘ sliceWindowToSpecBytes`.
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.Encoding
import Symcrust.Properties.MLKEM.Helpers.PopcountShiftDistrib

open Aeneas Aeneas.Std
open Spec
open Spec.MLKEM
open Symcrust

namespace Symcrust.Properties.MLKEM.Bridges

/-- Proof-irrelevance helper: `samplePolyCbdCoeff` does not depend on its
    bound proof, so a same-index pair of calls is `rfl`, and `subst` lifts
    that to an index-equality bridge.  Used by callers of
    `popcountPackBridge3`/`popcountPackBridge2` to swap a loop-local index
    (`4*chunks+j`) for the surrounding `k`-variable when `subst` of the
    natural equation is blocked by a let-cycle. -/
theorem samplePolyCbdCoeff_idx_eq {η : MLKEM.Η}
    {bytes : 𝔹 (64 * η.val)} {a b : Nat} (hab : a = b)
    (ha : a < 256) (hb : b < 256) :
    @samplePolyCbdCoeff η bytes a ha = @samplePolyCbdCoeff η bytes b hb := by
  subst hab; rfl

/-! ## η=3 popcount-mask bridge

The η=3 outer body loads a 32-bit little-endian word `raw` from
`pb_src[3*chunks .. 3*chunks+4)` (the +1 padding byte exists in `pb_src`
but is never consumed: only the low 24 bits of `raw` survive the
popcount-folding because the mask `0x249249` is zero in bits 24+).
After packing it produces `sample_bits1.val = (raw &&& 0x249249) +
((raw >>> 1) &&& 0x249249) + ((raw >>> 2) &&& 0x249249)`.

For every `j < 4`, the impl-side coefficient
`(((sample_bits1.val >>> (6j)) &&& 7 : Int) - ((sample_bits1.val >>> (6j+3)) &&& 7 : Int) : Zq`
equals `samplePolyCbdCoeff bytes (4*chunks + j) _` where `bytes` is the
spec view of `pb_src[0, 64*3)`.
-/

/-- **η=3 popcount→specCoeff bridge.** Decomposes the impl-side popcount-packed
sample bits into the spec-side `samplePolyCbdCoeff` via the existing
`cbdDecodeBits_eq_specCoeff` bridge and the popcount-mask BV identity
`popcount_eta3_{low,high}_nat`. -/
theorem popcountPackBridge3
    (pb_src : Slice U8) (h_pb_len : pb_src.length = 64 * 3 + 1)
    (chunks : Nat) (h_chunks : 4 * chunks + 4 ≤ 256)
    (j : Nat) (h_j : j < 4) :
    let raw : Nat :=
      (pb_src.val[3 * chunks]'(by grind)).val +
      256 * (pb_src.val[3 * chunks + 1]'(by grind)).val +
      65536 * (pb_src.val[3 * chunks + 2]'(by grind)).val +
      16777216 * (pb_src.val[3 * chunks + 3]'(by grind)).val
    let packed : Nat :=
      (raw &&& 2396745) + ((raw >>> 1) &&& 2396745) + ((raw >>> 2) &&& 2396745)
    ((((packed >>> (6 * j)) &&& 7 : Nat) : Int)
        - (((packed >>> (6 * j + 3)) &&& 7 : Nat) : Int) : Zq) =
      @samplePolyCbdCoeff ⟨3, by grind⟩
        (sliceWindowToSpecBytes pb_src 0 (64 * 3) (by grind))
        (4 * chunks + j) (by omega) := by
  -- Abbreviations.
  set b0 : Nat := (pb_src.val[3 * chunks]'(by grind)).val with hb0e
  set b1 : Nat := (pb_src.val[3 * chunks + 1]'(by grind)).val with hb1e
  set b2 : Nat := (pb_src.val[3 * chunks + 2]'(by grind)).val with hb2e
  set b3 : Nat := (pb_src.val[3 * chunks + 3]'(by grind)).val with hb3e
  have hb0_lt : b0 < 256 := (pb_src.val[3 * chunks]'(by grind)).hBounds
  have hb1_lt : b1 < 256 := (pb_src.val[3 * chunks + 1]'(by grind)).hBounds
  have hb2_lt : b2 < 256 := (pb_src.val[3 * chunks + 2]'(by grind)).hBounds
  have hb3_lt : b3 < 256 := (pb_src.val[3 * chunks + 3]'(by grind)).hBounds
  set raw : Nat := b0 + 256 * b1 + 65536 * b2 + 16777216 * b3 with hrawe
  have hraw_lt : raw < 2^32 := by simp only [raw]; omega
  set bytes : 𝔹 (64 * (⟨3, by grind⟩ : MLKEM.Η).val) :=
    sliceWindowToSpecBytes pb_src 0 (64 * 3) (by grind)
  set bits : Nat := raw >>> (6 * j) with hbitse
  -- Bridge: bits.testBit k = BytesToBits bytes [2*(4*chunks+j)*3 + k] for k < 6.
  have h_bits_testBit :
      ∀ (k : Nat) (_ : k < 2 * (⟨3, by grind⟩ : MLKEM.Η).val),
        bits.testBit k = (MLKEM.BytesToBits bytes).get
          ⟨2 * (4 * chunks + j) * (⟨3, by grind⟩ : MLKEM.Η).val + k, by
            have : (⟨3, by grind⟩ : MLKEM.Η).val = 3 := rfl
            rw [this]; omega⟩ := by
    intro k h_k
    have h_eta_val : (⟨3, by grind⟩ : MLKEM.Η).val = 3 := rfl
    simp only at h_k
    -- bits.testBit k = (raw >>> 6j).testBit k = raw.testBit (6j+k)
    simp only [bits, Nat.testBit_shiftRight]
    have h_raw_idx : 6 * j + k < 32 := by omega
    -- Apply 4-byte LE decomposition.
    rw [show raw = b0 + 256 * b1 + 65536 * b2 + 16777216 * b3 from rfl]
    rw [Helpers.testBit_le_word_branches b0 b1 b2 b3 hb0_lt hb1_lt hb2_lt
        (6 * j + k) h_raw_idx]
    -- First normalize eta.val to 3 in the goal.
    have h_eta_val : (⟨3, by grind⟩ : MLKEM.Η).val = 3 := rfl
    -- Unfold MLKEM.BytesToBits to a Vector.ofFn projection.
    unfold MLKEM.BytesToBits Spec.bytesToBits
    show _ = (Vector.ofFn _)[2 * (4 * chunks + j) * (⟨3, by grind⟩ : MLKEM.Η).val + k]
    simp only [Vector.getElem_ofFn]
    -- The goal is now: <branch> = (BitVec.toNat bytes[idx / 8]).testBit (idx % 8)
    -- where idx = 2*(4*chunks+j)*eta.val + k.
    -- Step 1: rewrite idx via congruence using a Nat.testBit-of-BitVec.toNat congruence.
    have hidx_eq : 2 * (4 * chunks + j) * (⟨3, by grind⟩ : MLKEM.Η).val + k = 24 * chunks + 6 * j + k := by
      rw [h_eta_val]; ring
    have h_div_eq : (24 * chunks + 6 * j + k) / 8 = 3 * chunks + (6 * j + k) / 8 := by
      have h24 : 24 * chunks = 8 * (3 * chunks) := by ring
      rw [h24, Nat.add_assoc, Nat.mul_add_div (by norm_num)]
    have h_mod_eq : (24 * chunks + 6 * j + k) % 8 = (6 * j + k) % 8 := by
      have h24 : 24 * chunks = 8 * (3 * chunks) := by ring
      rw [h24, Nat.add_assoc, Nat.mul_add_mod_self_left]
    -- Use generalize to abstract idx_div and idx_mod so the dependent proof is no longer entangled.
    -- Compute the target value of bytes[idx/8] first using a helper.
    have h_byte_eq :
        bytes[(2 * (4 * chunks + j) * (⟨3, by grind⟩ : MLKEM.Η).val + k) / 8]'(by
            show _ < 64 * (⟨3, by grind⟩ : MLKEM.Η).val
            rw [h_eta_val, hidx_eq, h_div_eq]; omega) =
          (pb_src.val[3 * chunks + (6 * j + k) / 8]'(by grind)).bv := by
      have h1 : (2 * (4 * chunks + j) * (⟨3, by grind⟩ : MLKEM.Η).val + k) / 8 =
                3 * chunks + (6 * j + k) / 8 := by
        rw [hidx_eq, h_div_eq]
      rw [show bytes[(2 * (4 * chunks + j) * (⟨3, by grind⟩ : MLKEM.Η).val + k) / 8]'_ =
              bytes[3 * chunks + (6 * j + k) / 8]'(by
                show _ < 64 * (⟨3, by grind⟩ : MLKEM.Η).val
                rw [h_eta_val]; omega) from by
        fcongr 1]
      simp only [bytes, sliceWindowToSpecBytes, Vector.getElem_ofFn, Nat.zero_add]
    have h_mod_eq2 : (2 * (4 * chunks + j) * (⟨3, by grind⟩ : MLKEM.Η).val + k) % 8 = (6 * j + k) % 8 := by
      rw [hidx_eq, h_mod_eq]
    rw [h_byte_eq, h_mod_eq2]
    -- Now relate the LE-decomposed bytes to pb_src.val[3*chunks + (6j+k)/8].
    have h_bv_toNat : ∀ (u : U8), u.bv.toNat = u.val := fun u => rfl
    rcases (show (6 * j + k) / 8 = 0 ∨ (6 * j + k) / 8 = 1 ∨
                 (6 * j + k) / 8 = 2 ∨ (6 * j + k) / 8 = 3 by omega) with hd | hd | hd | hd
    · simp only [hd, Nat.add_zero]
      have h_lt8 : 6 * j + k < 8 := by omega
      have h_mod : (6 * j + k) % 8 = 6 * j + k := Nat.mod_eq_of_lt h_lt8
      simp only [if_pos h_lt8, h_mod, h_bv_toNat]
      rfl
    · simp only [hd]
      have h_ge8 : ¬ 6 * j + k < 8 := by omega
      have h_lt16 : 6 * j + k < 16 := by omega
      have h_mod : (6 * j + k) % 8 = 6 * j + k - 8 := by omega
      simp only [if_neg h_ge8, if_pos h_lt16, h_mod, h_bv_toNat]
      rfl
    · simp only [hd]
      have h_ge8 : ¬ 6 * j + k < 8 := by omega
      have h_ge16 : ¬ 6 * j + k < 16 := by omega
      have h_lt24 : 6 * j + k < 24 := by omega
      have h_mod : (6 * j + k) % 8 = 6 * j + k - 16 := by omega
      simp only [if_neg h_ge8, if_neg h_ge16, if_pos h_lt24, h_mod, h_bv_toNat]
      rfl
    · simp only [hd]
      have h_ge8 : ¬ 6 * j + k < 8 := by omega
      have h_ge16 : ¬ 6 * j + k < 16 := by omega
      have h_ge24 : ¬ 6 * j + k < 24 := by omega
      have h_mod : (6 * j + k) % 8 = 6 * j + k - 24 := by omega
      simp only [if_neg h_ge8, if_neg h_ge16, if_neg h_ge24, h_mod, h_bv_toNat]
      rfl
  -- Apply the existing bridge.
  rw [← cbdDecodeBits_eq_specCoeff ⟨3, by grind⟩ bytes (4 * chunks + j) (by omega)
        bits h_bits_testBit]
  -- Goal: ((LHS_lo : Int) - (LHS_hi : Int) : Zq) = cbdDecodeBits 3 bits
  unfold cbdDecodeBits
  -- low_pop = sum_{k<3} (bits.testBit k).toNat = sum_{k<3} (raw.testBit (6j+k)).toNat
  --        = (packed >>> 6j) &&& 7   by popcount_eta3_low_nat
  have h_low_pop :
      ((List.range 3).map (fun k => (bits.testBit k).toNat)).sum =
        ((((raw &&& 2396745) + ((raw >>> 1) &&& 2396745) + ((raw >>> 2) &&& 2396745))
            >>> (6 * j)) &&& 7 : Nat) := by
    rw [Helpers.popcount_eta3_low_nat raw hraw_lt j h_j]
    show ((List.range 3).map (fun k => (bits.testBit k).toNat)).sum = _
    have : (List.range 3) = [0, 1, 2] := by decide
    rw [this]
    simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, Nat.add_zero, bits,
               Nat.testBit_shiftRight]
    ring
  have h_high_pop :
      ((List.range 3).map (fun k => (bits.testBit (3 + k)).toNat)).sum =
        ((((raw &&& 2396745) + ((raw >>> 1) &&& 2396745) + ((raw >>> 2) &&& 2396745))
            >>> (6 * j + 3)) &&& 7 : Nat) := by
    rw [Helpers.popcount_eta3_high_nat raw hraw_lt j h_j]
    show ((List.range 3).map (fun k => (bits.testBit (3 + k)).toNat)).sum = _
    have : (List.range 3) = [0, 1, 2] := by decide
    rw [this]
    simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, Nat.add_zero, bits,
               Nat.testBit_shiftRight]
    have e0 : 6 * j + (3 + 0) = 6 * j + 3 := by ring
    have e1 : 6 * j + (3 + 1) = 6 * j + 4 := by ring
    have e2 : 6 * j + (3 + 2) = 6 * j + 5 := by ring
    rw [e0, e1, e2]
    ring
  show _ = (((((List.range 3).map (fun k => (bits.testBit k).toNat)).sum : Int) -
            (((List.range 3).map (fun k => (bits.testBit (3 + k)).toNat)).sum : Int) : Int) :
            MLKEM.Zq)
  rw [h_low_pop, h_high_pop]
  push_cast
  ring

/-! ## η=2 popcount-mask bridge

Mirror of η=3 with mask `0x55555555`, 4-bit fields, 8 coefficients per
chunk.  Same shape: only the low 32 bits of `raw` matter (and only the
2-bit popcounts of disjoint 2-bit windows survive).
-/

/-- **η=2 popcount→specCoeff bridge.** Mirror of `popcountPackBridge3` with
mask `0x55555555` (4-bit fields, 8 coefficients per chunk). -/
theorem popcountPackBridge2
    (pb_src : Slice U8) (h_pb_len : pb_src.length = 64 * 3 + 1)
    (chunks : Nat) (h_chunks : 8 * chunks + 8 ≤ 256)
    (j : Nat) (h_j : j < 8) :
    let raw : Nat :=
      (pb_src.val[4 * chunks]'(by grind)).val +
      256 * (pb_src.val[4 * chunks + 1]'(by grind)).val +
      65536 * (pb_src.val[4 * chunks + 2]'(by grind)).val +
      16777216 * (pb_src.val[4 * chunks + 3]'(by grind)).val
    let packed : Nat :=
      (raw &&& 1431655765) + ((raw >>> 1) &&& 1431655765)
    ((((packed >>> (4 * j)) &&& 3 : Nat) : Int)
        - (((packed >>> (4 * j + 2)) &&& 3 : Nat) : Int) : Zq) =
      @samplePolyCbdCoeff ⟨2, by grind⟩
        (sliceWindowToSpecBytes pb_src 0 (64 * 2) (by grind))
        (8 * chunks + j) (by omega) := by
  -- Abbreviations (4 bytes starting at 4*chunks).
  set b0 : Nat := (pb_src.val[4 * chunks]'(by grind)).val with hb0e
  set b1 : Nat := (pb_src.val[4 * chunks + 1]'(by grind)).val with hb1e
  set b2 : Nat := (pb_src.val[4 * chunks + 2]'(by grind)).val with hb2e
  set b3 : Nat := (pb_src.val[4 * chunks + 3]'(by grind)).val with hb3e
  have hb0_lt : b0 < 256 := (pb_src.val[4 * chunks]'(by grind)).hBounds
  have hb1_lt : b1 < 256 := (pb_src.val[4 * chunks + 1]'(by grind)).hBounds
  have hb2_lt : b2 < 256 := (pb_src.val[4 * chunks + 2]'(by grind)).hBounds
  have hb3_lt : b3 < 256 := (pb_src.val[4 * chunks + 3]'(by grind)).hBounds
  set raw : Nat := b0 + 256 * b1 + 65536 * b2 + 16777216 * b3 with hrawe
  have hraw_lt : raw < 2^32 := by simp only [raw]; omega
  set bytes : 𝔹 (64 * (⟨2, by grind⟩ : MLKEM.Η).val) :=
    sliceWindowToSpecBytes pb_src 0 (64 * 2) (by grind)
  set bits : Nat := raw >>> (4 * j) with hbitse
  -- Bridge: bits.testBit k = BytesToBits bytes [2*(8*chunks+j)*2 + k] for k < 4.
  have h_bits_testBit :
      ∀ (k : Nat) (_ : k < 2 * (⟨2, by grind⟩ : MLKEM.Η).val),
        bits.testBit k = (MLKEM.BytesToBits bytes).get
          ⟨2 * (8 * chunks + j) * (⟨2, by grind⟩ : MLKEM.Η).val + k, by
            have : (⟨2, by grind⟩ : MLKEM.Η).val = 2 := rfl
            rw [this]; omega⟩ := by
    intro k h_k
    have h_eta_val : (⟨2, by grind⟩ : MLKEM.Η).val = 2 := rfl
    simp only at h_k
    -- bits.testBit k = (raw >>> 4j).testBit k = raw.testBit (4j+k)
    simp only [bits, Nat.testBit_shiftRight]
    have h_raw_idx : 4 * j + k < 32 := by omega
    -- Apply 4-byte LE decomposition.
    rw [show raw = b0 + 256 * b1 + 65536 * b2 + 16777216 * b3 from rfl]
    rw [Helpers.testBit_le_word_branches b0 b1 b2 b3 hb0_lt hb1_lt hb2_lt
        (4 * j + k) h_raw_idx]
    -- Unfold MLKEM.BytesToBits.
    unfold MLKEM.BytesToBits Spec.bytesToBits
    show _ = (Vector.ofFn _)[2 * (8 * chunks + j) * (⟨2, by grind⟩ : MLKEM.Η).val + k]
    simp only [Vector.getElem_ofFn]
    -- Index arithmetic helpers.
    have hidx_eq : 2 * (8 * chunks + j) * (⟨2, by grind⟩ : MLKEM.Η).val + k = 32 * chunks + 4 * j + k := by
      rw [h_eta_val]; ring
    have h_div_eq : (32 * chunks + 4 * j + k) / 8 = 4 * chunks + (4 * j + k) / 8 := by
      have h32 : 32 * chunks = 8 * (4 * chunks) := by ring
      rw [h32, Nat.add_assoc, Nat.mul_add_div (by norm_num)]
    have h_mod_eq : (32 * chunks + 4 * j + k) % 8 = (4 * j + k) % 8 := by
      have h32 : 32 * chunks = 8 * (4 * chunks) := by ring
      rw [h32, Nat.add_assoc, Nat.mul_add_mod_self_left]
    have h_byte_eq :
        bytes[(2 * (8 * chunks + j) * (⟨2, by grind⟩ : MLKEM.Η).val + k) / 8]'(by
            show _ < 64 * (⟨2, by grind⟩ : MLKEM.Η).val
            rw [h_eta_val, hidx_eq, h_div_eq]; omega) =
          (pb_src.val[4 * chunks + (4 * j + k) / 8]'(by grind)).bv := by
      have h1 : (2 * (8 * chunks + j) * (⟨2, by grind⟩ : MLKEM.Η).val + k) / 8 =
                4 * chunks + (4 * j + k) / 8 := by
        rw [hidx_eq, h_div_eq]
      rw [show bytes[(2 * (8 * chunks + j) * (⟨2, by grind⟩ : MLKEM.Η).val + k) / 8]'_ =
              bytes[4 * chunks + (4 * j + k) / 8]'(by
                show _ < 64 * (⟨2, by grind⟩ : MLKEM.Η).val
                rw [h_eta_val]; omega) from by
        fcongr 1]
      simp only [bytes, sliceWindowToSpecBytes, Vector.getElem_ofFn, Nat.zero_add]
    have h_mod_eq2 : (2 * (8 * chunks + j) * (⟨2, by grind⟩ : MLKEM.Η).val + k) % 8 = (4 * j + k) % 8 := by
      rw [hidx_eq, h_mod_eq]
    rw [h_byte_eq, h_mod_eq2]
    -- Now case split on (4j+k)/8 ∈ {0,1,2,3}.
    have h_bv_toNat : ∀ (u : U8), u.bv.toNat = u.val := fun u => rfl
    rcases (show (4 * j + k) / 8 = 0 ∨ (4 * j + k) / 8 = 1 ∨
                 (4 * j + k) / 8 = 2 ∨ (4 * j + k) / 8 = 3 by omega) with hd | hd | hd | hd
    · simp only [hd, Nat.add_zero]
      have h_lt8 : 4 * j + k < 8 := by omega
      have h_mod : (4 * j + k) % 8 = 4 * j + k := Nat.mod_eq_of_lt h_lt8
      simp only [if_pos h_lt8, h_mod, h_bv_toNat]
      rfl
    · simp only [hd]
      have h_ge8 : ¬ 4 * j + k < 8 := by omega
      have h_lt16 : 4 * j + k < 16 := by omega
      have h_mod : (4 * j + k) % 8 = 4 * j + k - 8 := by omega
      simp only [if_neg h_ge8, if_pos h_lt16, h_mod, h_bv_toNat]
      rfl
    · simp only [hd]
      have h_ge8 : ¬ 4 * j + k < 8 := by omega
      have h_ge16 : ¬ 4 * j + k < 16 := by omega
      have h_lt24 : 4 * j + k < 24 := by omega
      have h_mod : (4 * j + k) % 8 = 4 * j + k - 16 := by omega
      simp only [if_neg h_ge8, if_neg h_ge16, if_pos h_lt24, h_mod, h_bv_toNat]
      rfl
    · simp only [hd]
      have h_ge8 : ¬ 4 * j + k < 8 := by omega
      have h_ge16 : ¬ 4 * j + k < 16 := by omega
      have h_ge24 : ¬ 4 * j + k < 24 := by omega
      have h_mod : (4 * j + k) % 8 = 4 * j + k - 24 := by omega
      simp only [if_neg h_ge8, if_neg h_ge16, if_neg h_ge24, h_mod, h_bv_toNat]
      rfl
  -- Apply the existing bridge.
  rw [← cbdDecodeBits_eq_specCoeff ⟨2, by grind⟩ bytes (8 * chunks + j) (by omega)
        bits h_bits_testBit]
  unfold cbdDecodeBits
  -- low popcount: sum_{k<2} (bits.testBit k).toNat
  have h_low_pop :
      ((List.range 2).map (fun k => (bits.testBit k).toNat)).sum =
        ((((raw &&& 1431655765) + ((raw >>> 1) &&& 1431655765))
            >>> (4 * j)) &&& 3 : Nat) := by
    rw [Helpers.popcount_eta2_low_nat raw hraw_lt j h_j]
    show ((List.range 2).map (fun k => (bits.testBit k).toNat)).sum = _
    have : (List.range 2) = [0, 1] := by decide
    rw [this]
    simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, Nat.add_zero, bits,
               Nat.testBit_shiftRight]
  have h_high_pop :
      ((List.range 2).map (fun k => (bits.testBit (2 + k)).toNat)).sum =
        ((((raw &&& 1431655765) + ((raw >>> 1) &&& 1431655765))
            >>> (4 * j + 2)) &&& 3 : Nat) := by
    rw [Helpers.popcount_eta2_high_nat raw hraw_lt j h_j]
    show ((List.range 2).map (fun k => (bits.testBit (2 + k)).toNat)).sum = _
    have : (List.range 2) = [0, 1] := by decide
    rw [this]
    simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, Nat.add_zero, bits,
               Nat.testBit_shiftRight]
  show _ = (((((List.range 2).map (fun k => (bits.testBit k).toNat)).sum : Int) -
            (((List.range 2).map (fun k => (bits.testBit (2 + k)).toNat)).sum : Int) : Int) :
            MLKEM.Zq)
  rw [h_low_pop, h_high_pop]
  push_cast
  ring

end Symcrust.Properties.MLKEM.Bridges
