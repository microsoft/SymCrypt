/-
  Layer-2 specs for the cross-arch byte ↔ wider-lane reinterpretation
  primitives defined in `Symcrust/Code/Funs.lean` under
  `verify.intrinsics.lanes.*`.

  ## Purpose

  `bytes_to_{words,dwords,qwords}` and their inverses repack a flat byte
  array into / from wider-lane arrays using little-endian byte order.
  They are the portable model of a SIMD *reinterpret cast* (same bits,
  different lane view): shared by the per-arch NEON `vreinterpretq_*`
  family and by the x86_64 memory-op composites.

  Vendor-doc validation: these are *not* silicon arithmetic instructions —
  a reinterpret cast has no Intel SDM / Arm "Operation" pseudocode to cite.
  Their correctness is the bit-preservation property proved below (input and
  output denote the same register), so no vendor mnemonic is attached.

  ## Spec shape (no carrier sugar)

  Every spec says exactly "input and output denote the same register":
  the two arrays, packed into the `Intrinsics.Simd` `Register` hub, have
  equal bit-vectors — `r.bv (·.bv) = b.bv (·.bv)`.  There is no `m128` /
  `M128` carrier and no `core.core_arch.x86.*`; this file is arch-neutral.

  ## API-level bridges

  The proofs go through reusable bridges from `Intrinsics.Simd`, all stated at
  the `Array` / `Register` / `from_le_bytes` boundary (no bits exposed):

  * `Array_bv_eq_fromLEBytes` — Simd's register-packing of a byte array
    *is* `BitVec.fromLEBytes` of those bytes (reconciles the two ways of
    turning `[u8; n]` into one wide bit-vector).
  * `Array.bv_congr` — lane-wise congruence of the register packing.
  * `Array.bv_nest` — the nesting law: packing a nested array-of-arrays
    equals packing its flattening (regrouping doesn't change the bits).
  * `U{16,32,64}_{from,to}_le_bytes_bv` — `uN::{from,to}_le_bytes` and the
    Simd register-packing of the bytes carry the same bit-vector.

  All of these live in `Simd.lean`; this file imports them and stays at the
  byte / `.bv` API level.
-/
import Symcrust.Code.Funs
import Intrinsics.Simd

open Aeneas Aeneas.Std Intrinsics

namespace symcrust

/-! ## Iterator step lemmas (range `0..n`) -/

private theorem iter_some (range : core.ops.range.Range Std.Usize)
    (h : range.start.val < range.«end».val) :
    core.iter.range.IteratorRange.next core.iter.range.StepUsize range
    ⦃ (o : Option Std.Usize) (iter1 : core.ops.range.Range Std.Usize) =>
      o = some range.start ∧
      iter1.start.val = range.start.val + 1 ∧
      iter1.«end» = range.«end» ⦄ := by
  exact core.iter.range.IteratorRange.next_Usize_some_spec range h

private theorem iter_none (range : core.ops.range.Range Std.Usize)
    (h : range.start.val ≥ range.«end».val) :
    core.iter.range.IteratorRange.next core.iter.range.StepUsize range
    ⦃ (o : Option Std.Usize) (iter1 : core.ops.range.Range Std.Usize) =>
      o = none ∧ iter1 = range ⦄ := by
  simp only [core.iter.range.IteratorRange.next,
    core.iter.range.UScalarStep, core.iter.range.UScalarStep.forward_checked,
    core.cmp.impls.PartialOrdUsize.lt, liftFun2,
    show ¬ (range.start.val < range.«end».val) from by omega]
  simp [WP.spec_ok]

attribute [local step] iter_some iter_none

/-! ## Pack: bytes → wider lanes (little-endian)

  Each `bytes_to_*` reinterprets the same 128-bit register; the post is the
  packed-bit-vector equality `r.bv (·.bv) = b.bv (·.bv)`.

  Proof recipe (no bit reasoning at the spec level): `step*` exposes each
  output lane as `from_le_bytes` of its byte group; `Array.bv_congr` rewrites
  each lane to that group's `Array.bv` (via `Array_bv_eq_fromLEBytes`); then
  `Array.bv_nest` flattens the nested byte grouping back to the whole input
  register. -/

set_option maxHeartbeats 1000000 in
/-- `bytes_to_words` reinterprets 16 bytes as 8 little-endian u16s. -/
@[step] theorem verify.intrinsics.lanes.bytes_to_words.spec (b : M128) :
  verify.intrinsics.lanes.bytes_to_words b
  ⦃ (r : U16x8) => r.bv (·.bv) = b.bv (·.bv) ⦄ := by
  unfold verify.intrinsics.lanes.bytes_to_words
  step*
  subst_vars
  -- Group the 16 bytes into eight 2-byte chunks (the nested view of `b`).
  set bb : Std.Array (Std.Array Std.U8 2#usize) 8#usize :=
    Std.Array.make 8#usize
      [Std.Array.make 2#usize [b[0],b[1]] (by simp),
       Std.Array.make 2#usize [b[2],b[3]] (by simp),
       Std.Array.make 2#usize [b[4],b[5]] (by simp),
       Std.Array.make 2#usize [b[6],b[7]] (by simp),
       Std.Array.make 2#usize [b[8],b[9]] (by simp),
       Std.Array.make 2#usize [b[10],b[11]] (by simp),
       Std.Array.make 2#usize [b[12],b[13]] (by simp),
       Std.Array.make 2#usize [b[14],b[15]] (by simp)] (by simp) with hbb
  -- Each output u16 lane = its byte group's packing (`from_le_bytes` bridge).
  rw [Aeneas.Std.Array.bv_congr (Std.Array.make 8#usize [i2,i5,i8,i11,i14,i17,i20,i23] (by simp))
        bb (·.bv) (fun g => g.bv (·.bv))
        (by intro i; fin_cases i
            · show i2.bv = bb[0].bv (·.bv);  rw [i2_post,  Array_bv_eq_fromLEBytes]; rfl
            · show i5.bv = bb[1].bv (·.bv);  rw [i5_post,  Array_bv_eq_fromLEBytes]; rfl
            · show i8.bv = bb[2].bv (·.bv);  rw [i8_post,  Array_bv_eq_fromLEBytes]; rfl
            · show i11.bv = bb[3].bv (·.bv); rw [i11_post, Array_bv_eq_fromLEBytes]; rfl
            · show i14.bv = bb[4].bv (·.bv); rw [i14_post, Array_bv_eq_fromLEBytes]; rfl
            · show i17.bv = bb[5].bv (·.bv); rw [i17_post, Array_bv_eq_fromLEBytes]; rfl
            · show i20.bv = bb[6].bv (·.bv); rw [i20_post, Array_bv_eq_fromLEBytes]; rfl
            · show i23.bv = bb[7].bv (·.bv); rw [i23_post, Array_bv_eq_fromLEBytes]; rfl)]
  -- Flatten the nested grouping back to `b` (nesting law).  Use `exact ∘ trans`
  -- (defeq) rather than `rw`: after `fin_cases` the packing lambda is an
  -- un-beta-reduced redex that `rw`'s syntactic matcher cannot see through.
  have hnest := Aeneas.Std.Array.bv_nest bb b (·.bv) (by decide) (by decide) (by decide)
        (by intro K r hK hr
            have e8 : (8#usize).val = 8 := rfl
            have e2 : (2#usize).val = 2 := rfl
            rcases (by omega : K=0∨K=1∨K=2∨K=3∨K=4∨K=5∨K=6∨K=7) with h|h|h|h|h|h|h|h <;> subst h <;>
              rcases (by omega : r=0∨r=1) with h|h <;> subst h <;> rfl)
  exact hnest.trans (BitVec.cast_eq _ _)

set_option maxHeartbeats 1000000 in
/-- `bytes_to_dwords` reinterprets 16 bytes as 4 little-endian u32s. -/
@[step] theorem verify.intrinsics.lanes.bytes_to_dwords.spec (b : M128) :
  verify.intrinsics.lanes.bytes_to_dwords b
  ⦃ (r : U32x4) => r.bv (·.bv) = b.bv (·.bv) ⦄ := by
  unfold verify.intrinsics.lanes.bytes_to_dwords
  step*
  subst_vars
  -- Group the 16 bytes into four 4-byte chunks (the nested view of `b`).
  set bb : Std.Array (Std.Array Std.U8 4#usize) 4#usize :=
    Std.Array.make 4#usize
      [Std.Array.make 4#usize [b[0], b[1], b[2], b[3]] (by simp),
       Std.Array.make 4#usize [b[4], b[5], b[6], b[7]] (by simp),
       Std.Array.make 4#usize [b[8], b[9], b[10], b[11]] (by simp),
       Std.Array.make 4#usize [b[12], b[13], b[14], b[15]] (by simp)] (by simp) with hbb
  -- Each output u32 lane = its byte group's packing (`from_le_bytes` bridge).
  rw [Aeneas.Std.Array.bv_congr (Std.Array.make 4#usize [i4, i9, i14, i19] (by simp)) bb (·.bv)
        (fun g => g.bv (·.bv))
        (by intro i; fin_cases i
            · show i4.bv = bb[0].bv (·.bv);  rw [i4_post,  Array_bv_eq_fromLEBytes]; rfl
            · show i9.bv = bb[1].bv (·.bv);  rw [i9_post,  Array_bv_eq_fromLEBytes]; rfl
            · show i14.bv = bb[2].bv (·.bv); rw [i14_post, Array_bv_eq_fromLEBytes]; rfl
            · show i19.bv = bb[3].bv (·.bv); rw [i19_post, Array_bv_eq_fromLEBytes]; rfl)]
  -- Flatten the nested grouping back to `b` (nesting law); `exact ∘ trans` (defeq).
  have hnest := Aeneas.Std.Array.bv_nest bb b (·.bv) (by decide) (by decide) (by decide)
        (by intro K r hK hr
            have e4 : (4#usize).val = 4 := rfl
            rcases (by omega : K=0∨K=1∨K=2∨K=3) with h|h|h|h <;> subst h <;>
              rcases (by omega : r=0∨r=1∨r=2∨r=3) with h|h|h|h <;> subst h <;> rfl)
  exact hnest.trans (BitVec.cast_eq _ _)

set_option maxHeartbeats 1000000 in
/-- `bytes_to_qwords` reinterprets 16 bytes as 2 little-endian u64s. -/
@[step] theorem verify.intrinsics.lanes.bytes_to_qwords.spec (b : M128) :
  verify.intrinsics.lanes.bytes_to_qwords b
  ⦃ (r : U64x2) => r.bv (·.bv) = b.bv (·.bv) ⦄ := by
  unfold verify.intrinsics.lanes.bytes_to_qwords
  step*
  subst_vars
  set bb : Std.Array (Std.Array Std.U8 8#usize) 2#usize :=
    Std.Array.make 2#usize
      [Std.Array.make 8#usize [b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7]] (by simp),
       Std.Array.make 8#usize [b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]] (by simp)] (by simp)
    with hbb
  rw [Aeneas.Std.Array.bv_congr (Std.Array.make 2#usize [i8, i17] (by simp)) bb (·.bv)
        (fun g => g.bv (·.bv))
        (by intro i; fin_cases i
            · show i8.bv = bb[0].bv (·.bv);  rw [i8_post,  Array_bv_eq_fromLEBytes]; rfl
            · show i17.bv = bb[1].bv (·.bv); rw [i17_post, Array_bv_eq_fromLEBytes]; rfl)]
  -- Flatten the nested grouping back to `b` (nesting law); `exact ∘ trans` (defeq).
  have hnest := Aeneas.Std.Array.bv_nest bb b (·.bv) (by decide) (by decide) (by decide)
        (by intro K r hK hr
            have e2 : (2#usize).val = 2 := rfl
            have e8 : (8#usize).val = 8 := rfl
            rcases (by omega : K=0∨K=1) with h|h <;> subst h <;>
              rcases (by omega : r=0∨r=1∨r=2∨r=3∨r=4∨r=5∨r=6∨r=7) with h|h|h|h|h|h|h|h <;>
                subst h <;> rfl)
  exact hnest.trans (BitVec.cast_eq _ _)

/-! ## Unpack: wider lanes → bytes (little-endian) -/

private theorem lane_to_le (dk : Std.U32) (bk : Std.Array Std.U8 4#usize)
    (h : bk.val = List.map (@Std.UScalar.mk .U8) dk.bv.toLEBytes) :
    bk.bv (·.bv) = dk.bv := by
  have hb : bk = core.num.U32.to_le_bytes dk := by apply Subtype.ext; rw [h]; rfl
  rw [hb, U32_to_le_bytes_bv]

set_option maxHeartbeats 2000000 in
/-- `dwords_to_bytes` reinterprets 4 little-endian u32s as 16 bytes. -/
@[step] theorem verify.intrinsics.lanes.dwords_to_bytes.spec (d : U32x4) :
  verify.intrinsics.lanes.dwords_to_bytes d
  ⦃ (r : M128) => r.bv (·.bv) = d.bv (·.bv) ⦄ := by
  unfold verify.intrinsics.lanes.dwords_to_bytes
  step*
  subst_vars
  -- The four byte groups `b0..b3` (each `to_le_bytes dₖ`) as a nested view.
  set bb : Std.Array (Std.Array Std.U8 4#usize) 4#usize :=
    Std.Array.make 4#usize [b0, b1, b2, b3] (by simp) with hbb
  -- The flat 16-byte output is the flattening of `bb`.
  have hnest := Aeneas.Std.Array.bv_nest bb
    (Std.Array.make 16#usize [b0[0],b0[1],b0[2],b0[3], b1[0],b1[1],b1[2],b1[3],
      b2[0],b2[1],b2[2],b2[3], b3[0],b3[1],b3[2],b3[3]] (by simp)) (·.bv)
    (by decide) (by decide) (by decide)
    (by intro K r hK hr
        have e4 : (4#usize).val = 4 := rfl
        rcases (by omega : K=0∨K=1∨K=2∨K=3) with h|h|h|h <;> subst h <;>
          rcases (by omega : r=0∨r=1∨r=2∨r=3) with h|h|h|h <;> subst h <;> rfl)
  -- Each byte group repacks to its source dword (`to_le_bytes` round-trip).
  have hbbd : bb.bv (fun g => g.bv (·.bv)) = d.bv (·.bv) :=
    Aeneas.Std.Array.bv_congr bb d (fun g => g.bv (·.bv)) (·.bv)
      (by intro i; fin_cases i
          · exact lane_to_le _ b0 b0_post
          · exact lane_to_le _ b1 b1_post
          · exact lane_to_le _ b2 b2_post
          · exact lane_to_le _ b3 b3_post)
  exact hnest.symm.trans hbbd

private theorem lane_to_le_u64 (dk : Std.U64) (bk : Std.Array Std.U8 8#usize)
    (h : bk.val = List.map (@Std.UScalar.mk .U8) dk.bv.toLEBytes) :
    bk.bv (·.bv) = dk.bv := by
  have hb : bk = core.num.U64.to_le_bytes dk := by apply Subtype.ext; rw [h]; rfl
  rw [hb, U64_to_le_bytes_bv]

set_option maxHeartbeats 2000000 in
/-- `qwords_to_bytes` reinterprets 2 little-endian u64s as 16 bytes. -/
@[step] theorem verify.intrinsics.lanes.qwords_to_bytes.spec (q : U64x2) :
  verify.intrinsics.lanes.qwords_to_bytes q
  ⦃ (r : M128) => r.bv (·.bv) = q.bv (·.bv) ⦄ := by
  unfold verify.intrinsics.lanes.qwords_to_bytes
  step*
  subst_vars
  -- The two byte groups `lo`, `hi` (each `to_le_bytes qₖ`) as a nested view.
  set bb : Std.Array (Std.Array Std.U8 8#usize) 2#usize :=
    Std.Array.make 2#usize [lo, hi] (by simp) with hbb
  -- The flat 16-byte output is the flattening of `bb`.
  have hnest := Aeneas.Std.Array.bv_nest bb
    (Std.Array.make 16#usize [lo[0],lo[1],lo[2],lo[3],lo[4],lo[5],lo[6],lo[7],
      hi[0],hi[1],hi[2],hi[3],hi[4],hi[5],hi[6],hi[7]] (by simp)) (·.bv)
    (by decide) (by decide) (by decide)
    (by intro K r hK hr
        have e2 : (2#usize).val = 2 := rfl
        have e8 : (8#usize).val = 8 := rfl
        rcases (by omega : K=0∨K=1) with h|h <;> subst h <;>
          rcases (by omega : r=0∨r=1∨r=2∨r=3∨r=4∨r=5∨r=6∨r=7) with h|h|h|h|h|h|h|h <;>
            subst h <;> rfl)
  -- Each byte group repacks to its source qword (`to_le_bytes` round-trip).
  have hbbd : bb.bv (fun g => g.bv (·.bv)) = q.bv (·.bv) :=
    Aeneas.Std.Array.bv_congr bb q (fun g => g.bv (·.bv)) (·.bv)
      (by intro i; fin_cases i
          · exact lane_to_le_u64 _ lo lo_post
          · exact lane_to_le_u64 _ hi hi_post)
  exact hnest.symm.trans hbbd

/-! ### `words_to_bytes` (loop) -/

-- The loop spec's per-lane postconditions index output arrays (`r[k]`, `out[k]`,
-- `r[2*i]`); enable the cheap-first `get_elem_tactic` override here.  (The pack /
-- unpack specs above deliberately avoid it: it would stamp `grind`-generated
-- bound proofs into hand-written `b[k]` literals that then fail to match the
-- extracted code's default-tactic proofs under `rfl`.)
local macro_rules
  | `(tactic| get_elem_tactic) => `(tactic| first | assumption | grind)

set_option maxHeartbeats 2000000 in
/-- Generalized loop spec: lanes before `iter.start` keep their `out` value;
    lanes from `iter.start` on hold the two little-endian bytes of `w[i]`. -/
@[step] theorem words_to_bytes_loop.spec_gen
    (iter : core.ops.range.Range Std.Usize) (w : U16x8) (out : U8x16)
    (hStart : iter.start.val ≤ 8) (hEnd : iter.«end».val = 8) :
  verify.intrinsics.lanes.words_to_bytes_loop iter w out
  ⦃ (r : U8x16) =>
    (∀ k, (hk : k < 2*iter.start.val) → r[k] = out[k]) ∧
    (∀ i, (hi : i < 8) → iter.start.val ≤ i →
        r[2*i] = (core.num.U16.to_le_bytes w[i])[0] ∧
        r[2*i+1] = (core.num.U16.to_le_bytes w[i])[1]) ⦄ := by
  unfold verify.intrinsics.lanes.words_to_bytes_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨o, iter1, hsome, hstart', hend'⟩ ← iter_some
    rw [hsome]
    step*
    -- `p` is exactly `to_le_bytes (w[start])` (mirrors the unpack `lane_to_le`).
    have hp : p = core.num.U16.to_le_bytes w[iter.start.val] := by
      apply Subtype.ext; rw [p_post, i1_post]; rfl
    refine ⟨fun k hk => ?_, fun i hi hsi => ?_⟩
    · -- prefix unchanged: k < 2*start hits neither freshly-written index
      rw [r_post1 k (by omega), a_post, out1_post,
          Array.getElem_Nat_set_ne (h1 := by omega), Array.getElem_Nat_set_ne (h1 := by omega)]
    · -- lanes ≥ start: the fresh lane `start`, else delegate to the IH
      by_cases hi_eq : i = iter.start.val
      · subst hi_eq
        refine ⟨?_, ?_⟩
        · rw [r_post1 _ (by omega), a_post, out1_post,
              Array.getElem_Nat_set_ne (h1 := by omega), Array.getElem_Nat_set_eq (h1 := by omega),
              i2_post, hp]; rfl
        · rw [r_post1 _ (by omega), a_post, Array.getElem_Nat_set_eq (h1 := by omega),
              i4_post, hp]; rfl
      · exact r_post2 i hi (by omega)
  · let* ⟨o, iter1, hnone, _⟩ ← iter_none (by omega)
    rw [hnone]
    refine ⟨fun k _ => rfl, fun i hi hsi => ?_⟩
    -- `start = 8` here, so `start ≤ i < 8` is contradictory: no lanes remain
    omega
termination_by iter.«end».val - iter.start.val
decreasing_by scalar_decr_tac

/-- A 2-byte array holding the little-endian bytes of `dk` packs to `dk.bv`
    (the U16 analogue of `lane_to_le`). -/
private theorem lane_bytes_u16 (dk : Std.U16) (b0 b1 : Std.U8)
    (h0 : b0 = (core.num.U16.to_le_bytes dk)[0])
    (h1 : b1 = (core.num.U16.to_le_bytes dk)[1]) :
    (Std.Array.make 2#usize [b0, b1] (by simp)).bv (·.bv) = dk.bv := by
  have hb : Std.Array.make 2#usize [b0, b1] (by simp) = core.num.U16.to_le_bytes dk := by
    apply Subtype.ext
    subst h0 h1
    have hl : (core.num.U16.to_le_bytes dk).val.length = 2 := by
      simp [core.num.U16.to_le_bytes, BitVec.toLEBytes_length]
    apply List.ext_getElem (by simp [hl]) ?_
    intro n h1 h2
    rw [hl] at h2
    rcases (by omega : n = 0 ∨ n = 1) with h | h <;> subst h <;> rfl
  rw [hb, U16_to_le_bytes_bv]

set_option maxHeartbeats 2000000 in
/-- `words_to_bytes` reinterprets 8 little-endian u16s as 16 bytes. -/
@[step] theorem verify.intrinsics.lanes.words_to_bytes.spec (w : U16x8) :
  verify.intrinsics.lanes.words_to_bytes w
  ⦃ (r : M128) => r.bv (·.bv) = w.bv (·.bv) ⦄ := by
  unfold verify.intrinsics.lanes.words_to_bytes
  step*
  -- nested 2-byte view of the result `r`; `bb[i] = [r[2i], r[2i+1]]`.
  set bb : Std.Array (Std.Array Std.U8 2#usize) 8#usize :=
    Std.Array.make 8#usize
      [Std.Array.make 2#usize [r[0], r[1]] (by simp),
       Std.Array.make 2#usize [r[2], r[3]] (by simp),
       Std.Array.make 2#usize [r[4], r[5]] (by simp),
       Std.Array.make 2#usize [r[6], r[7]] (by simp),
       Std.Array.make 2#usize [r[8], r[9]] (by simp),
       Std.Array.make 2#usize [r[10], r[11]] (by simp),
       Std.Array.make 2#usize [r[12], r[13]] (by simp),
       Std.Array.make 2#usize [r[14], r[15]] (by simp)] (by simp) with hbb
  -- Flatten the nested view back to `r` (nesting law).
  have hnest := Aeneas.Std.Array.bv_nest bb r (·.bv) (by decide) (by decide) (by decide)
    (by intro K s hK hs
        have e8 : (8#usize).val = 8 := rfl
        have e2 : (2#usize).val = 2 := rfl
        rcases (by omega : K=0∨K=1∨K=2∨K=3∨K=4∨K=5∨K=6∨K=7) with h|h|h|h|h|h|h|h <;> subst h <;>
          rcases (by omega : s = 0 ∨ s = 1) with h | h <;> subst h <;> rfl)
  -- Each 2-byte group repacks to its source u16 (`to_le_bytes` round-trip).
  have hbbd : bb.bv (fun g => g.bv (·.bv)) = w.bv (·.bv) :=
    Aeneas.Std.Array.bv_congr bb w (fun g => g.bv (·.bv)) (·.bv)
      (by intro i; fin_cases i
          · exact lane_bytes_u16 _ _ _ (r_post2 0 (by omega) (by omega)).1 (r_post2 0 (by omega) (by omega)).2
          · exact lane_bytes_u16 _ _ _ (r_post2 1 (by omega) (by omega)).1 (r_post2 1 (by omega) (by omega)).2
          · exact lane_bytes_u16 _ _ _ (r_post2 2 (by omega) (by omega)).1 (r_post2 2 (by omega) (by omega)).2
          · exact lane_bytes_u16 _ _ _ (r_post2 3 (by omega) (by omega)).1 (r_post2 3 (by omega) (by omega)).2
          · exact lane_bytes_u16 _ _ _ (r_post2 4 (by omega) (by omega)).1 (r_post2 4 (by omega) (by omega)).2
          · exact lane_bytes_u16 _ _ _ (r_post2 5 (by omega) (by omega)).1 (r_post2 5 (by omega) (by omega)).2
          · exact lane_bytes_u16 _ _ _ (r_post2 6 (by omega) (by omega)).1 (r_post2 6 (by omega) (by omega)).2
          · exact lane_bytes_u16 _ _ _ (r_post2 7 (by omega) (by omega)).1 (r_post2 7 (by omega) (by omega)).2)
  exact hnest.symm.trans hbbd

end symcrust
