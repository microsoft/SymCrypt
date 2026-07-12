/-
  Public SSE2 Layer-1 surface.

  `@[step]` theorems for the Rust models of intrinsics `verify.intrinsics.x86_64.sse2.*`
  extracted to `Symcrust/Code/*`.

  See `INTRINSICS.md` for the layered architecture.
-/
import Symcrust.Code.Funs
import Intrinsics.Properties.Lanewise
import Intrinsics.Properties.Lanes
import Intrinsics.BVRealize
import Intrinsics.Simd
open Aeneas Aeneas.Std Intrinsics.X86_64 Intrinsics

local macro_rules
| `(tactic| get_elem_tactic) => `(tactic| first | assumption | grind)

namespace symcrust

/-! ## Range-iterator step specs (private, scoped to this file)

These mirror `Symcrust/Properties/SHA3/Keccak/Loop.lean:28-61`. We
duplicate them here because the SSE2 layer must not depend on the
Symcrust SHA3 layer. The `private` modifier makes the declarations
file-local, avoiding any name clash with the Keccak copy at link time. -/

private theorem sse2_iter_next_some
    (range : core.ops.range.Range Std.Usize)
    (h : range.start.val < range.«end».val) :
    core.iter.range.IteratorRange.next core.iter.range.StepUsize range
    ⦃ (o : Option Std.Usize) (iter1 : core.ops.range.Range Std.Usize) =>
      o = some range.start ∧
      iter1.start.val = range.start.val + 1 ∧
      iter1.«end» = range.«end» ⦄ := by
  exact core.iter.range.IteratorRange.next_Usize_some_spec range h

private theorem sse2_iter_next_none
    (range : core.ops.range.Range Std.Usize)
    (h : range.start.val ≥ range.«end».val) :
    core.iter.range.IteratorRange.next core.iter.range.StepUsize range
    ⦃ (o : Option Std.Usize) (iter1 : core.ops.range.Range Std.Usize) =>
      o = none ∧ iter1 = range ⦄ := by
  simp only [core.iter.range.IteratorRange.next,
    core.iter.range.UScalarStep, core.iter.range.UScalarStep.forward_checked,
    core.cmp.impls.PartialOrdUsize.lt, liftFun2,
    show ¬ (range.start.val < range.«end».val) from by omega]
  simp [WP.spec_ok]

attribute [local step] sse2_iter_next_some sse2_iter_next_none

/-! ## Lanewise-delegated wrappers

These wrappers are 1-line shims; the post mirrors the corresponding layer-2
spec in `Intrinsics/Properties/Lanewise.lean`.

Each op's post was validated against the Intel® 64/IA-32 SDM "Operation"
pseudocode (vol. 2, via the felixcloutier.com mirror) and is exercised by the
differential HW tests in `SymCRust/src/verify/tests/`. Per-op mnemonic tagged
on each docstring. -/

/-- 16-bit lane wrapping add.  Intel SDM `PADDW` — packed 16-bit add, overflow
    wraps (low 16 bits kept). -/
@[step] theorem verify.intrinsics.x86_64.sse2.add_epi16.spec
    (a b : U16x8) :
  verify.intrinsics.x86_64.sse2.add_epi16 a b
  ⦃ (r : U16x8) =>
    ∀ k, (hk : k < 8) →
      r[k] = core.num.U16.wrapping_add a[k] b[k] ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.add_epi16
  step*
  try agrind

/-- 16-bit lane wrapping sub.  Intel SDM `PSUBW` — packed 16-bit subtract,
    overflow wraps (low 16 bits kept). -/
@[step] theorem verify.intrinsics.x86_64.sse2.sub_epi16.spec
    (a b : U16x8) :
  verify.intrinsics.x86_64.sse2.sub_epi16 a b
  ⦃ (r : U16x8) =>
    ∀ k, (hk : k < 8) →
      r[k] = core.num.U16.wrapping_sub a[k] b[k] ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.sub_epi16
  step*
  try agrind

/-- 16-bit lane wrapping mul (low half).  Intel SDM `PMULLW` — packed 16-bit
    multiply, stores the low 16 bits of each 32-bit product. -/
@[step] theorem verify.intrinsics.x86_64.sse2.mullo_epi16.spec
    (a b : U16x8) :
  verify.intrinsics.x86_64.sse2.mullo_epi16 a b
  ⦃ (r : U16x8) =>
    ∀ k, (hk : k < 8) →
      r[k] = core.num.U16.wrapping_mul a[k] b[k] ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.mullo_epi16
  step*
  try agrind

/-- 16-bit lane high-half multiply (unsigned).  Intel SDM `PMULHUW` — packed
    unsigned 16-bit multiply, stores the high 16 bits of each 32-bit product. -/
@[step] theorem verify.intrinsics.x86_64.sse2.mulhi_epu16.spec
    (a b : U16x8) :
  verify.intrinsics.x86_64.sse2.mulhi_epu16 a b
  ⦃ (r : U16x8) =>
    ∀ k, (hk : k < 8) →
      r[k].val = (a[k].val * b[k].val) / 65536 ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.mulhi_epu16
  step*
  try agrind

/-- 16-bit lane equality mask.  Intel SDM `PCMPEQW` — per-word compare-equal,
    result lane all-ones (0xFFFF) if equal else all-zeros. -/
@[step] theorem verify.intrinsics.x86_64.sse2.cmpeq_epi16.spec
    (a b : U16x8) :
  verify.intrinsics.x86_64.sse2.cmpeq_epi16 a b
  ⦃ (r : U16x8) =>
    ∀ k, (hk : k < 8) →
      r[k] = if a[k] = b[k] then 65535#u16 else 0#u16 ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.cmpeq_epi16
  step*
  try agrind

/-- 16-bit lane signed greater-than mask.  Intel SDM `PCMPGTW` — per-word
    *signed* compare-greater, result lane all-ones (0xFFFF) if greater else
    all-zeros. -/
@[step] theorem verify.intrinsics.x86_64.sse2.cmpgt_epi16.spec
    (a b : U16x8) :
  verify.intrinsics.x86_64.sse2.cmpgt_epi16 a b
  ⦃ (r : U16x8) =>
    ∀ k, (hk : k < 8) →
      r[k] =
        if a[k].bv.toInt > b[k].bv.toInt then 65535#u16 else 0#u16 ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.cmpgt_epi16
  step*
  try agrind

/-- 32-bit lane wrapping add.  Intel SDM `PADDD` — packed 32-bit add, overflow
    wraps (low 32 bits kept). -/
@[step] theorem verify.intrinsics.x86_64.sse2.add_epi32.spec
    (a b : U32x4) :
  verify.intrinsics.x86_64.sse2.add_epi32 a b
  ⦃ (r : U32x4) =>
    ∀ k, (hk : k < 4) →
      r[k] = core.num.U32.wrapping_add a[k] b[k] ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.add_epi32
  step*
  try agrind

/-- Byte-wise AND of 128-bit values.  Intel SDM `PAND` — bitwise `a & b`. -/
@[step] theorem verify.intrinsics.x86_64.sse2.and_si128.spec
    (a b : M128) :
  verify.intrinsics.x86_64.sse2.and_si128 a b
  ⦃ (r : M128) =>
    ∀ k, (hk : k < 16) → r[k] = a[k] &&& b[k] ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.and_si128
  step*
  try agrind

/-- Byte-wise AND-NOT of 128-bit values: `(¬a) ∧ b`.  Intel SDM `PANDN` —
    bitwise `(NOT a) & b` (first operand negated). -/
@[step] theorem verify.intrinsics.x86_64.sse2.andnot_si128.spec
    (a b : M128) :
  verify.intrinsics.x86_64.sse2.andnot_si128 a b
  ⦃ (r : M128) =>
    ∀ k, (hk : k < 16) → r[k] = (~~~ a[k]) &&& b[k] ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.andnot_si128
  step*
  try agrind

/-- Byte-wise OR of 128-bit values.  Intel SDM `POR` — bitwise `a | b`. -/
@[step] theorem verify.intrinsics.x86_64.sse2.or_si128.spec
    (a b : M128) :
  verify.intrinsics.x86_64.sse2.or_si128 a b
  ⦃ (r : M128) =>
    ∀ k, (hk : k < 16) → r[k] = a[k] ||| b[k] ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.or_si128
  step*
  try agrind

/-- Byte-wise XOR of 128-bit values.  Intel SDM `PXOR` — bitwise `a ^ b`. -/
@[step] theorem verify.intrinsics.x86_64.sse2.xor_si128.spec
    (a b : M128) :
  verify.intrinsics.x86_64.sse2.xor_si128 a b
  ⦃ (r : M128) =>
    ∀ k, (hk : k < 16) → r[k] = a[k] ^^^ b[k] ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.xor_si128
  step*
  try agrind

/-- Silicon `_mm_xor_si128` redirects to the byte model; `__m128i = Array U8 16`,
    so it is defined as the model (P7 diff-test bridge). -/
@[rust_fun "core::core_arch::x86::sse2::_mm_xor_si128"]
noncomputable def core.core_arch.x86.sse2._mm_xor_si128 (a b : M128) : Result M128 :=
  verify.intrinsics.x86_64.sse2.xor_si128 a b

/-- **Intel SDM Vol.2B `PXOR` — `u64x2` view.**  Bitwise XOR of two 128-bit
    registers, stated on the two 64-bit lanes for GHASH.

    Trust basis: the byte-wise model spec `verify.…sse2.xor_si128.spec` via
    `M128.u64x2_bv_getElem` (differential test
    `tests/x86_64_sse2_hw_extras.rs::bitwise_si128_matches`). -/
@[step]
theorem core.core_arch.x86.sse2._mm_xor_si128.spec_u64x2 (a b : M128) :
    core.core_arch.x86.sse2._mm_xor_si128 a b
    ⦃ (r : M128) =>
      r.u64x2[0].bv = a.u64x2[0].bv ^^^ b.u64x2[0].bv ∧
      r.u64x2[1].bv = a.u64x2[1].bv ^^^ b.u64x2[1].bv ⦄ := by
  unfold core.core_arch.x86.sse2._mm_xor_si128
  apply WP.spec_mono (verify.intrinsics.x86_64.sse2.xor_si128.spec a b)
  intro r hr
  refine ⟨?_, ?_⟩
  · apply BitVec.eq_of_getLsbD_eq; intro k hk
    simp only [BitVec.getLsbD_xor, M128.u64x2_lane0_getLsbD r k hk,
               M128.u64x2_lane0_getLsbD a k hk, M128.u64x2_lane0_getLsbD b k hk,
               hr (k / 8) (by omega), Std.UScalar.bv_xor]
  · apply BitVec.eq_of_getLsbD_eq; intro k hk
    simp only [BitVec.getLsbD_xor, M128.u64x2_lane1_getLsbD r k hk,
               M128.u64x2_lane1_getLsbD a k hk, M128.u64x2_lane1_getLsbD b k hk,
               hr (8 + k / 8) (by omega), Std.UScalar.bv_xor]

/-! ## Array constructors (broadcast / explicit set) -/

/-- Zero 128-bit register. -/
@[step] theorem verify.intrinsics.x86_64.sse2.setzero_si128.spec :
  verify.intrinsics.x86_64.sse2.setzero_si128
  ⦃ (r : M128) => r = Array.repeat 16#usize 0#u8 ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.setzero_si128
  step*

/-- Broadcast a 16-bit value across 8 lanes. -/
@[step] theorem verify.intrinsics.x86_64.sse2.set1_epi16.spec
    (a : Std.I16) :
  verify.intrinsics.x86_64.sse2.set1_epi16 a
  ⦃ (r : U16x8) => r = Array.repeat 8#usize (⟨a.bv⟩ : U16) ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.set1_epi16
  step*
  rw [v_post]; simp [IScalar.hcast]

/-- Broadcast a 32-bit value across 4 lanes. -/
@[step] theorem verify.intrinsics.x86_64.sse2.set1_epi32.spec
    (a : Std.I32) :
  verify.intrinsics.x86_64.sse2.set1_epi32 a
  ⦃ (r : U32x4) => r = Array.repeat 4#usize (⟨a.bv⟩ : U32) ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.set1_epi32
  step*
  rw [v_post]; simp [IScalar.hcast]

/-- Pack 16 signed bytes into an SSE register (lane 0 = `b0`, lane 15 = `b15`). -/
@[step] theorem verify.intrinsics.x86_64.sse2.set_epi8.spec
    (b15 b14 b13 b12 b11 b10 b9 b8 b7 b6 b5 b4 b3 b2 b1 b0 : Std.I8) :
  verify.intrinsics.x86_64.sse2.set_epi8 b15 b14 b13 b12 b11 b10 b9 b8
                                          b7  b6  b5  b4  b3  b2  b1 b0
  ⦃ (r : M128) =>
    r = Std.Array.make 16#usize
      [(⟨b0.bv⟩ : U8),  (⟨b1.bv⟩ : U8),  (⟨b2.bv⟩ : U8),  (⟨b3.bv⟩ : U8),
       (⟨b4.bv⟩ : U8),  (⟨b5.bv⟩ : U8),  (⟨b6.bv⟩ : U8),  (⟨b7.bv⟩ : U8),
       (⟨b8.bv⟩ : U8),  (⟨b9.bv⟩ : U8),  (⟨b10.bv⟩ : U8), (⟨b11.bv⟩ : U8),
       (⟨b12.bv⟩ : U8), (⟨b13.bv⟩ : U8), (⟨b14.bv⟩ : U8), (⟨b15.bv⟩ : U8)] ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.set_epi8
  step*
  subst i_post i1_post i2_post i3_post i4_post i5_post i6_post i7_post
  subst i8_post i9_post i10_post i11_post i12_post i13_post i14_post i15_post
  simp [IScalar.hcast]

/-- Pack 4 signed dwords into an SSE register (lane 0 = `e0`, lane 3 = `e3`). -/
@[step] theorem verify.intrinsics.x86_64.sse2.set_epi32.spec
    (e3 e2 e1 e0 : Std.I32) :
  verify.intrinsics.x86_64.sse2.set_epi32 e3 e2 e1 e0
  ⦃ (r : U32x4) =>
    r = Std.Array.make 4#usize
      [(⟨e0.bv⟩ : U32), (⟨e1.bv⟩ : U32), (⟨e2.bv⟩ : U32), (⟨e3.bv⟩ : U32)] ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.set_epi32
  step*
  subst i_post i1_post i2_post i3_post
  simp [IScalar.hcast]

/-- Pack 2 signed qwords into an SSE register (lane 0 = `e0`, lane 1 = `e1`). -/
@[step] theorem verify.intrinsics.x86_64.sse2.set_epi64x.spec
    (e1 e0 : Std.I64) :
  verify.intrinsics.x86_64.sse2.set_epi64x e1 e0
  ⦃ (r : U64x2) =>
    r = Std.Array.make 2#usize [(⟨e0.bv⟩ : U64), (⟨e1.bv⟩ : U64)] ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.set_epi64x
  step*
  subst i_post i1_post
  simp [IScalar.hcast]

/-! ## Unpack (64-bit lane interleave) -/

/-- Interleave the low 64-bit half of `a` and `b`: result lanes
    `[a[0], a[1], b[0], b[1]]`.  Intel SDM `PUNPCKLQDQ` — interleave the low
    quadwords (dst low = SRC1 low qword, dst high = SRC2 low qword). -/
@[step] theorem verify.intrinsics.x86_64.sse2.unpacklo_epi64.spec
    (a b : U32x4) :
  verify.intrinsics.x86_64.sse2.unpacklo_epi64 a b
  ⦃ (r : U32x4) =>
    r[0] = a[0] ∧ r[1] = a[1] ∧
    r[2] = b[0] ∧ r[3] = b[1] ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.unpacklo_epi64
  step*
  subst i_post i1_post i2_post i3_post
  exact ⟨rfl, rfl, rfl, rfl⟩

/-- Interleave the high 64-bit half of `a` and `b`: result lanes
    `[a[2], a[3], b[2], b[3]]`.  Intel SDM `PUNPCKHQDQ` — interleave the high
    quadwords (dst low = SRC1 high qword, dst high = SRC2 high qword). -/
@[step] theorem verify.intrinsics.x86_64.sse2.unpackhi_epi64.spec
    (a b : U32x4) :
  verify.intrinsics.x86_64.sse2.unpackhi_epi64 a b
  ⦃ (r : U32x4) =>
    r[0] = a[2] ∧ r[1] = a[3] ∧
    r[2] = b[2] ∧ r[3] = b[3] ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.unpackhi_epi64
  step*
  subst i_post i1_post i2_post i3_post
  exact ⟨rfl, rfl, rfl, rfl⟩

/-! ## Converts (single-lane I/O) -/

/-- Extract lane 0 as a signed dword.  Intel SDM `MOVD` — move the low 32-bit
    doubleword of the register to a general register. -/
@[step] theorem verify.intrinsics.x86_64.sse2.cvtsi128_si32.spec
    (a : U32x4) :
  verify.intrinsics.x86_64.sse2.cvtsi128_si32 a
  ⦃ (r : Std.I32) => r.bv = a[0].bv ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.cvtsi128_si32
  step*
  subst i_post
  show I32.bv (UScalar.hcast _ _) = _
  unfold UScalar.hcast
  simp only [I32.bv, IScalarTy.I32_numBits_eq, BitVec.zeroExtend]
  refine (BitVec.setWidth_eq _).trans ?_
  exact congrArg U32.bv rfl

/-- Place a signed dword in lane 0, zeroing lanes 1..3.  Intel SDM `MOVD` —
    move a doubleword into the low 32 bits and zero-extend to 128 bits. -/
@[step] theorem verify.intrinsics.x86_64.sse2.cvtsi32_si128.spec
    (a : Std.I32) :
  verify.intrinsics.x86_64.sse2.cvtsi32_si128 a
  ⦃ (r : U32x4) =>
    r[0].bv = a.bv ∧ r[1] = 0#u32 ∧
    r[2] = 0#u32 ∧ r[3] = 0#u32 ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.cvtsi32_si128
  step*
  subst i_post
  refine ⟨?_, ?_, ?_, ?_⟩
  · exact BitVec.signExtend_eq _
  · rfl
  · rfl
  · rfl

/-! ## Shuffle (dword permutation by const-generic immediate)

`shuffle_epi32` now takes the control byte as a `#[rustc_legacy_const_generics]`
const parameter `IMM8 : I32` (mirroring silicon `PSHUFD`), so Aeneas threads it
as a Lean value parameter rather than a runtime argument.  Lane `k` reads
`a[(IMM8 >> (2*k)) & 3]`.  The SHA-NI driver bakes in the two concrete control
bytes `0x1B = 27` (lane reverse) and `0x0E = 14`; we give their step specs
directly so callers obtain the four lane equalities without unfolding the
modular index arithmetic. -/

/-- `n &&& 3 = n % 4` at the `Nat` level (low 2 bits = remainder mod 4). -/
private theorem nat_and3 (n : Nat) : n &&& 3 = n % 4 := by
  have h := Nat.and_two_pow_sub_one_eq_mod n 2
  simpa using h

/-- `(x &&& 3).val = x.val % 4` for a u32 (masking to the low 2 bits). -/
private theorem and3_val (x : Std.U32) : (x &&& 3#u32).val = x.val % 4 := by
  rw [Std.UScalar.val_and]
  exact nat_and3 x.val

/-- Lane-permutation post for `sse2.shuffle_epi32` at a concrete non-negative
immediate.  Lane `k` reads `a[(IMM8 >> (2*k)) & 3]`.  Helper for the two
concrete SHA-NI specialisations below; not `@[step]` (the specialisations are). -/
private theorem shuffle_epi32_perm
    (IMM8 : Std.I32) (a : U32x4)
    (hlo : 0 ≤ IMM8.val) (hhi : IMM8.val ≤ Std.UScalar.max .U32) :
  verify.intrinsics.x86_64.sse2.shuffle_epi32 IMM8 a
  ⦃ (r : U32x4) =>
    ∀ k, (hk : k < 4) →
      r[k] = a[(IMM8.val.toNat >>> (2 * k)) % 4] ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.shuffle_epi32
  -- `imm = IMM8 as u32`, value-preserving since `0 ≤ IMM8 ≤ u32::MAX`.
  have hc_bnd : 0 ≤ IMM8.val ∧ IMM8.val ≤ Std.UScalar.max .U32 := ⟨hlo, hhi⟩
  step with IScalar.hcast_inBounds_spec
  step*
  all_goals first
    | -- array-index bound side-goals: `(cast .Usize (_ &&& 3)).val < 4`
      (simp only [*, and3_val, Std.U32.cast_Usize_val_eq]; agrind)
    | -- the four lane equalities
      (intro k hk
       have himm : imm.val = IMM8.val.toNat := by scalar_tac
       rcases k with _ | _ | _ | _ | k
       · -- k = 0: index (IMM8 >>> 0) & 3
         show i3 = _
         rw [i3_post]
         apply getElem_congr_idx
         simp only [i2_post, Std.U32.cast_Usize_val_eq, i1_post1, i_post1, himm,
                    Std.UScalar.val_and, Nat.shiftRight_zero, Nat.mul_zero]
         exact nat_and3 _
       · -- k = 1: index (IMM8 >>> 2) & 3
         show i7 = _
         rw [i7_post]
         apply getElem_congr_idx
         simp only [i6_post, Std.U32.cast_Usize_val_eq, i5_post1, i4_post1, himm,
                    Std.UScalar.val_and]
         exact nat_and3 _
       · -- k = 2: index (IMM8 >>> 4) & 3
         show i11 = _
         rw [i11_post]
         apply getElem_congr_idx
         simp only [i10_post, Std.U32.cast_Usize_val_eq, i9_post1, i8_post1, himm,
                    Std.UScalar.val_and, show 2 * 2 = 4 from rfl]
         exact nat_and3 _
       · -- k = 3: index (IMM8 >>> 6) & 3
         show i15 = _
         rw [i15_post]
         apply getElem_congr_idx
         simp only [i14_post, Std.U32.cast_Usize_val_eq, i13_post1, i12_post1, himm,
                    Std.UScalar.val_and, show 2 * 3 = 6 from rfl]
         exact nat_and3 _
       · -- k ≥ 4: impossible
         exact absurd hk (by scalar_tac))

/-- SHA-NI `_mm_shuffle_epi32::<0x1B>` reverses the 4 u32 lanes. -/
@[step] theorem verify.intrinsics.x86_64.sse2.shuffle_epi32.spec_0x1b (a : U32x4) :
  verify.intrinsics.x86_64.sse2.shuffle_epi32 27#i32 a
  ⦃ (r : U32x4) =>
    r[0] = a[3] ∧ r[1] = a[2] ∧
    r[2] = a[1] ∧ r[3] = a[0] ⦄ := by
  have h := shuffle_epi32_perm 27#i32 a (by native_decide) (by native_decide)
  apply WP.spec_mono h
  intro r hr
  exact ⟨hr 0 (by decide), hr 1 (by decide), hr 2 (by decide), hr 3 (by decide)⟩

/-- SHA-NI `_mm_shuffle_epi32::<0x0E>` brings the upper two u32 lanes down and
    broadcasts the original `a[0]` into the upper half: `[a[2], a[3], a[0], a[0]]`. -/
@[step] theorem verify.intrinsics.x86_64.sse2.shuffle_epi32.spec_0x0e (a : U32x4) :
  verify.intrinsics.x86_64.sse2.shuffle_epi32 14#i32 a
  ⦃ (r : U32x4) =>
    r[0] = a[2] ∧ r[1] = a[3] ∧
    r[2] = a[0] ∧ r[3] = a[0] ⦄ := by
  have h := shuffle_epi32_perm 14#i32 a (by native_decide) (by native_decide)
  apply WP.spec_mono h
  intro r hr
  exact ⟨hr 0 (by decide), hr 1 (by decide), hr 2 (by decide), hr 3 (by decide)⟩

/-- GHASH `_mm_shuffle_epi32::<0x4E>` swaps the two 64-bit halves:
    `[a[2], a[3], a[0], a[1]]`. -/
@[step] theorem verify.intrinsics.x86_64.sse2.shuffle_epi32.spec_0x4e (a : U32x4) :
  verify.intrinsics.x86_64.sse2.shuffle_epi32 78#i32 a
  ⦃ (r : U32x4) =>
    r[0] = a[2] ∧ r[1] = a[3] ∧
    r[2] = a[0] ∧ r[3] = a[1] ⦄ := by
  have h := shuffle_epi32_perm 78#i32 a (by native_decide) (by native_decide)
  apply WP.spec_mono h
  intro r hr
  exact ⟨hr 0 (by decide), hr 1 (by decide), hr 2 (by decide), hr 3 (by decide)⟩

/-- GHASH `_mm_shuffle_epi32::<0x93>` rotates the lanes by one toward the
    high end: `[a[3], a[0], a[1], a[2]]`. -/
@[step] theorem verify.intrinsics.x86_64.sse2.shuffle_epi32.spec_0x93 (a : U32x4) :
  verify.intrinsics.x86_64.sse2.shuffle_epi32 147#i32 a
  ⦃ (r : U32x4) =>
    r[0] = a[3] ∧ r[1] = a[0] ∧
    r[2] = a[1] ∧ r[3] = a[2] ⦄ := by
  have h := shuffle_epi32_perm 147#i32 a (by native_decide) (by native_decide)
  apply WP.spec_mono h
  intro r hr
  exact ⟨hr 0 (by decide), hr 1 (by decide), hr 2 (by decide), hr 3 (by decide)⟩

/-- Silicon `_mm_shuffle_epi32` redirects to the model; `__m128i`'s `u32x4` view
    is the `Array U32 4` carrier, so it is defined as the model (P7 diff-test
    bridge). -/
@[rust_fun "core::core_arch::x86::sse2::_mm_shuffle_epi32"]
noncomputable def core.core_arch.x86.sse2._mm_shuffle_epi32
    (IMM8 : Std.I32) (a : U32x4) : Result U32x4 :=
  verify.intrinsics.x86_64.sse2.shuffle_epi32 IMM8 a

/-- **Intel SDM Vol.2B `PSHUFD`** — shuffle four 32-bit lanes per `IMM8`:
    `dst[k] = src[(IMM8 >> (2·k)) & 3]`, for a non-negative immediate (always
    the case for the compile-time u8-range shuffle constant).

    Trust basis: discharged by `shuffle_epi32_perm` over the byte/lane
    model. -/
@[step]
theorem core.core_arch.x86.sse2._mm_shuffle_epi32.spec
    (IMM8 : Std.I32) (a : U32x4)
    (hlo : 0 ≤ IMM8.val) (hhi : IMM8.val ≤ Std.UScalar.max .U32) :
    core.core_arch.x86.sse2._mm_shuffle_epi32 IMM8 a
    ⦃ (r : U32x4) =>
      ∀ k, (hk : k < 4) → r[k] = a[(IMM8.val.toNat >>> (2 * k)) % 4] ⦄ := by
  unfold core.core_arch.x86.sse2._mm_shuffle_epi32
  exact shuffle_epi32_perm IMM8 a hlo hhi

/-! ## Shifts (each entry-point drives an SSE2-local `_loop`)

Validated against Intel SDM: `PSLLD`/`PSLLQ` (per-dword/qword logical left) and
`PSRLD` (per-dword logical right) zero the lane when the count exceeds the lane
width; `PSRLDQ` shifts the whole 128-bit register right by whole bytes,
saturating the count at 16 (→ all zeros). -/

/-- Shift each 32-bit lane left by `c.val` (with `c.val < 32`). Lanes are
    written entry by entry; entries outside `[iter.start, iter.end)` are
    untouched. -/
@[step] theorem verify.intrinsics.x86_64.sse2.slli_epi32_loop.spec
    (iter : core.ops.range.Range Std.Usize) (a out : U32x4)
    (c : Std.U32)
    (hStart : iter.start.val ≤ iter.«end».val) (hEnd : iter.«end».val ≤ 4)
    (hc : c.val < 32) :
  verify.intrinsics.x86_64.sse2.slli_epi32_loop iter a out c
  ⦃ (r : U32x4) =>
    (∀ k, (hk : k < iter.start.val) → r[k] = out[k]) ∧
    (∀ k, iter.start.val ≤ k → (hk : k < iter.«end».val) →
        r[k].bv = a[k].bv.shiftLeft c.val) ∧
    (∀ k, iter.«end».val ≤ k → (hk : k < 4) → r[k] = out[k]) ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.slli_epi32_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← sse2_iter_next_some
    rw [hsome]
    dsimp only
    step*
    have ha1_at : a1[iter.start.val] = i2 := by
      rw [a1_post]; simp_lists
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
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← sse2_iter_next_none
    rw [hnone]
    dsimp only
    simp only [WP.spec_ok]
    refine ⟨?_, ?_, ?_⟩
    · intro k hk; trivial
    · intro k hk_lo hk_hi; scalar_tac
    · intro k hk_lo hk_hi; trivial
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- 32-bit lane shift-left by `count` (signed; out-of-range → all zeros).
    Intel SDM `PSLLD` — per-dword logical left shift; count > 31 zeros the lane. -/
@[step] theorem verify.intrinsics.x86_64.sse2.slli_epi32.spec
    (a : U32x4) (count : Std.I32) :
  verify.intrinsics.x86_64.sse2.slli_epi32 a count
  ⦃ (r : U32x4) =>
    if 0 ≤ count.val ∧ count.val < 32 then
      ∀ k, (hk : k < 4) → r[k].bv = a[k].bv.shiftLeft count.toNat
    else
      ∀ k, (hk : k < 4) → r[k] = 0#u32 ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.slli_epi32
  dsimp only
  by_cases h1 : 0 ≤ count.val
  · by_cases h2 : count.val < 32
    · have hcond : (0#i32 : Std.I32) ≤ count := by scalar_tac
      have hcond2 : count < (32#i32 : Std.I32) := by scalar_tac
      rw [if_pos hcond, if_pos hcond2]
      have hc_bnd : 0 ≤ count.val ∧ count.val ≤ Std.UScalar.max .U32 := by
        refine ⟨h1, ?_⟩
        have : (Std.UScalar.max .U32 : Int) = 2^32 - 1 := by native_decide
        scalar_tac
      step with Std.IScalar.hcast_inBounds_spec
      have hcv : (c.val : Int) = count.val := c_post
      step with verify.intrinsics.x86_64.sse2.slli_epi32_loop.spec
      rw [if_pos (And.intro h1 h2)]
      intro k hk
      have e := r_post2 k (by scalar_tac) hk
      rw [e]
      congr 1
      have : count.toNat = c.val := by scalar_tac
      rw [this]
    · have hcond : (0#i32 : Std.I32) ≤ count := by scalar_tac
      have hcond2 : ¬ count < (32#i32 : Std.I32) := by scalar_tac
      rw [if_pos hcond, if_neg hcond2]
      simp only [WP.spec_ok]
      have hne : ¬ (0 ≤ count.val ∧ count.val < 32) := by scalar_tac
      rw [if_neg hne]
      intro k hk
      exact Std.Array.getElem_repeat _ _ _ (by scalar_tac)
  · have hcond : ¬ (0#i32 : Std.I32) ≤ count := by scalar_tac
    rw [if_neg hcond]
    simp only [WP.spec_ok]
    have hne : ¬ (0 ≤ count.val ∧ count.val < 32) := by scalar_tac
    rw [if_neg hne]
    intro k hk
    exact Std.Array.getElem_repeat _ _ _ (by scalar_tac)

/-- Shift each 64-bit lane left by `c.val`. -/
@[step] theorem verify.intrinsics.x86_64.sse2.slli_epi64_loop.spec
    (iter : core.ops.range.Range Std.Usize) (a out : U64x2)
    (c : Std.U32)
    (hStart : iter.start.val ≤ iter.«end».val) (hEnd : iter.«end».val ≤ 2)
    (hc : c.val < 64) :
  verify.intrinsics.x86_64.sse2.slli_epi64_loop iter a out c
  ⦃ (r : U64x2) =>
    (∀ k, (hk : k < iter.start.val) → r[k] = out[k]) ∧
    (∀ k, iter.start.val ≤ k → (hk : k < iter.«end».val) →
        r[k].bv = a[k].bv.shiftLeft c.val) ∧
    (∀ k, iter.«end».val ≤ k → (hk : k < 2) → r[k] = out[k]) ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.slli_epi64_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← sse2_iter_next_some
    rw [hsome]
    dsimp only
    step*
    have ha1_at : a1[iter.start.val] = i2 := by
      rw [a1_post]; simp_lists
    have ha1_other : ∀ k, k ≠ iter.start.val → (hk : k < 2) → a1[k] = out[k] := by
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
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← sse2_iter_next_none
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
    Intel SDM `PSLLQ` — per-qword logical left shift; count > 63 zeros the lane. -/
@[step] theorem verify.intrinsics.x86_64.sse2.slli_epi64.spec
    (a : U64x2) (count : Std.I32) :
  verify.intrinsics.x86_64.sse2.slli_epi64 a count
  ⦃ (r : U64x2) =>
    if 0 ≤ count.val ∧ count.val < 64 then
      ∀ k, (hk : k < 2) → r[k].bv = a[k].bv.shiftLeft count.toNat
    else
      ∀ k, (hk : k < 2) → r[k] = 0#u64 ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.slli_epi64
  dsimp only
  by_cases h1 : 0 ≤ count.val
  · by_cases h2 : count.val < 64
    · have hcond : (0#i32 : Std.I32) ≤ count := by scalar_tac
      have hcond2 : count < (64#i32 : Std.I32) := by scalar_tac
      rw [if_pos hcond, if_pos hcond2]
      have hc_bnd : 0 ≤ count.val ∧ count.val ≤ Std.UScalar.max .U32 := by
        refine ⟨h1, ?_⟩
        have : (Std.UScalar.max .U32 : Int) = 2^32 - 1 := by native_decide
        scalar_tac
      step with Std.IScalar.hcast_inBounds_spec
      have hcv : (c.val : Int) = count.val := c_post
      step with verify.intrinsics.x86_64.sse2.slli_epi64_loop.spec
      rw [if_pos (And.intro h1 h2)]
      intro k hk
      have e := r_post2 k (by scalar_tac) hk
      rw [e]
      congr 1
      have : count.toNat = c.val := by scalar_tac
      rw [this]
    · have hcond : (0#i32 : Std.I32) ≤ count := by scalar_tac
      have hcond2 : ¬ count < (64#i32 : Std.I32) := by scalar_tac
      rw [if_pos hcond, if_neg hcond2]
      simp only [WP.spec_ok]
      have hne : ¬ (0 ≤ count.val ∧ count.val < 64) := by scalar_tac
      rw [if_neg hne]
      intro k hk
      exact Std.Array.getElem_repeat _ _ _ (by scalar_tac)
  · have hcond : ¬ (0#i32 : Std.I32) ≤ count := by scalar_tac
    rw [if_neg hcond]
    simp only [WP.spec_ok]
    have hne : ¬ (0 ≤ count.val ∧ count.val < 64) := by scalar_tac
    rw [if_neg hne]
    intro k hk
    exact Std.Array.getElem_repeat _ _ _ (by scalar_tac)

/-- Shift each 32-bit lane right (logical) by `c.val`. -/
@[step] theorem verify.intrinsics.x86_64.sse2.srli_epi32_loop.spec
    (iter : core.ops.range.Range Std.Usize) (a out : U32x4)
    (c : Std.U32)
    (hStart : iter.start.val ≤ iter.«end».val) (hEnd : iter.«end».val ≤ 4)
    (hc : c.val < 32) :
  verify.intrinsics.x86_64.sse2.srli_epi32_loop iter a out c
  ⦃ (r : U32x4) =>
    (∀ k, (hk : k < iter.start.val) → r[k] = out[k]) ∧
    (∀ k, iter.start.val ≤ k → (hk : k < iter.«end».val) →
        r[k].bv = a[k].bv.ushiftRight c.val) ∧
    (∀ k, iter.«end».val ≤ k → (hk : k < 4) → r[k] = out[k]) ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.srli_epi32_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← sse2_iter_next_some
    rw [hsome]
    dsimp only
    step*
    have ha1_at : a1[iter.start.val] = i2 := by
      rw [a1_post]; simp_lists
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
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← sse2_iter_next_none
    rw [hnone]
    dsimp only
    simp only [WP.spec_ok]
    refine ⟨?_, ?_, ?_⟩
    · intro k hk; trivial
    · intro k hk_lo hk_hi; scalar_tac
    · intro k hk_lo hk_hi; trivial
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- 32-bit lane shift-right logical by `count` (signed; out-of-range → all zeros).
    Intel SDM `PSRLD` — per-dword logical right shift; count > 31 zeros the lane. -/
@[step] theorem verify.intrinsics.x86_64.sse2.srli_epi32.spec
    (a : U32x4) (count : Std.I32) :
  verify.intrinsics.x86_64.sse2.srli_epi32 a count
  ⦃ (r : U32x4) =>
    if 0 ≤ count.val ∧ count.val < 32 then
      ∀ k, (hk : k < 4) → r[k].bv = a[k].bv.ushiftRight count.toNat
    else
      ∀ k, (hk : k < 4) → r[k] = 0#u32 ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.srli_epi32
  dsimp only
  by_cases h1 : 0 ≤ count.val
  · by_cases h2 : count.val < 32
    · have hcond : (0#i32 : Std.I32) ≤ count := by scalar_tac
      have hcond2 : count < (32#i32 : Std.I32) := by scalar_tac
      rw [if_pos hcond, if_pos hcond2]
      have hc_bnd : 0 ≤ count.val ∧ count.val ≤ Std.UScalar.max .U32 := by
        refine ⟨h1, ?_⟩
        have : (Std.UScalar.max .U32 : Int) = 2^32 - 1 := by native_decide
        scalar_tac
      step with Std.IScalar.hcast_inBounds_spec
      have hcv : (c.val : Int) = count.val := c_post
      step with verify.intrinsics.x86_64.sse2.srli_epi32_loop.spec
      rw [if_pos (And.intro h1 h2)]
      intro k hk
      have e := r_post2 k (by scalar_tac) hk
      rw [e]
      congr 1
      have : count.toNat = c.val := by scalar_tac
      rw [this]
    · have hcond : (0#i32 : Std.I32) ≤ count := by scalar_tac
      have hcond2 : ¬ count < (32#i32 : Std.I32) := by scalar_tac
      rw [if_pos hcond, if_neg hcond2]
      simp only [WP.spec_ok]
      have hne : ¬ (0 ≤ count.val ∧ count.val < 32) := by scalar_tac
      rw [if_neg hne]
      intro k hk
      exact Std.Array.getElem_repeat _ _ _ (by scalar_tac)
  · have hcond : ¬ (0#i32 : Std.I32) ≤ count := by scalar_tac
    rw [if_neg hcond]
    simp only [WP.spec_ok]
    have hne : ¬ (0 ≤ count.val ∧ count.val < 32) := by scalar_tac
    rw [if_neg hne]
    intro k hk
    exact Std.Array.getElem_repeat _ _ _ (by scalar_tac)

/-- Byte-granular shift loop: for `i ∈ [iter.start, iter.end)`, writes
    `out[i] := a[i + c]`. Used by `srli_si128` after preprocessing
    `iter.end := 16 - c`. -/
@[step] theorem verify.intrinsics.x86_64.sse2.srli_si128_loop.spec
    (iter : core.ops.range.Range Std.Usize) (a out : M128)
    (c : Std.Usize)
    (hStart : iter.start.val ≤ iter.«end».val) (hEnd : iter.«end».val ≤ 16)
    (hc : c.val ≤ 16) (hPair : iter.«end».val + c.val ≤ 16) :
  verify.intrinsics.x86_64.sse2.srli_si128_loop iter a out c
  ⦃ (r : M128) =>
    (∀ k, (hk : k < iter.start.val) → r[k] = out[k]) ∧
    (∀ k, iter.start.val ≤ k → (hk : k < iter.«end».val) →
        r[k] = a[k + c.val]) ∧
    (∀ k, iter.«end».val ≤ k → (hk : k < 16) → r[k] = out[k]) ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.srli_si128_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← sse2_iter_next_some
    rw [hsome]
    dsimp only
    step*
    have ha1_at : a1[iter.start.val] = i2 := by
      rw [a1_post]; simp_lists
    have ha1_other : ∀ k, k ≠ iter.start.val → (hk : k < 16) → a1[k] = out[k] := by
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
        rw [e1, ha1_at, i2_post]
        exact getElem_congr_idx i1_post
      · have hk1 : iter1.start.val ≤ k := by rw [hstart']; scalar_tac
        have hk1' : k < iter1.«end».val := by rw [hend']; exact hk_hi
        exact r_post2 k hk1 hk1'
    · intro k hk_lo hk_hi
      have hk1 : iter1.«end».val ≤ k := by rw [hend']; exact hk_lo
      have e3 : r[k] = a1[k] := r_post3 k hk1 hk_hi
      rw [e3, ha1_other k (by scalar_tac) hk_hi]
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← sse2_iter_next_none
    rw [hnone]
    dsimp only
    simp only [WP.spec_ok]
    refine ⟨?_, ?_, ?_⟩
    · intro k hk; trivial
    · intro k hk_lo hk_hi; scalar_tac
    · intro k hk_lo hk_hi; trivial
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- Byte-granular right shift of a 128-bit value by `count` bytes
    (signed; out-of-range → all zeros).  Intel SDM `PSRLDQ` — shift the whole
    double-quadword right by whole bytes; count > 15 saturates to 16 (all zeros). -/
@[step] theorem verify.intrinsics.x86_64.sse2.srli_si128.spec
    (a : M128) (count : Std.I32) :
  verify.intrinsics.x86_64.sse2.srli_si128 a count
  ⦃ (r : M128) =>
    if 0 ≤ count.val ∧ count.val < 16 then
      (∀ k, (hk : k + count.toNat < 16) → r[k] = a[k + count.toNat]) ∧
      (∀ k, 16 - count.toNat ≤ k → (hk : k < 16) → r[k] = 0#u8)
    else
      ∀ k, (hk : k < 16) → r[k] = 0#u8 ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.srli_si128
  dsimp only
  by_cases h1 : 0 ≤ count.val
  · by_cases h2 : count.val < 16
    · have hcond : (0#i32 : Std.I32) ≤ count := by scalar_tac
      have hcond2 : count < (16#i32 : Std.I32) := by scalar_tac
      rw [if_pos hcond, if_pos hcond2]
      have hc_bnd : 0 ≤ count.val ∧ count.val ≤ Std.UScalar.max .Usize := by
        refine ⟨h1, ?_⟩
        scalar_tac
      step with Std.IScalar.hcast_inBounds_spec
      have hcv : (c.val : Int) = count.val := c_post
      step  -- Usize.sub_spec for `16#usize - c`
      step with verify.intrinsics.x86_64.sse2.srli_si128_loop.spec
      rw [if_pos (And.intro h1 h2)]
      refine ⟨?_, ?_⟩
      · intro k hk
        have hk_lt_i : k < i.val := by scalar_tac
        have e := r_post2 k (by scalar_tac) hk_lt_i
        rw [e]
        congr 1
        scalar_tac
      · intro k hlo hhi
        have hk_ge_i : i.val ≤ k := by scalar_tac
        have e := r_post3 k hk_ge_i hhi
        rw [e]
        exact Std.Array.getElem_repeat _ _ _ (by scalar_tac)
    · have hcond : (0#i32 : Std.I32) ≤ count := by scalar_tac
      have hcond2 : ¬ count < (16#i32 : Std.I32) := by scalar_tac
      rw [if_pos hcond, if_neg hcond2]
      simp only [WP.spec_ok]
      have hne : ¬ (0 ≤ count.val ∧ count.val < 16) := by scalar_tac
      rw [if_neg hne]
      intro k hk
      exact Std.Array.getElem_repeat _ _ _ (by scalar_tac)
  · have hcond : ¬ (0#i32 : Std.I32) ≤ count := by scalar_tac
    rw [if_neg hcond]
    simp only [WP.spec_ok]
    have hne : ¬ (0 ≤ count.val ∧ count.val < 16) := by scalar_tac
    rw [if_neg hne]
    intro k hk
    exact Std.Array.getElem_repeat _ _ _ (by scalar_tac)

/-! ## Memory operations on `Slice U8` / `Slice U32`

These talk about the underlying byte/dword layout of the slice; bit
patterns are expressed via `BitVec.{from,to}LEBytes`. -/

/-- Load 16 bytes from `bytes[at1..at1+16]`, packed as 4 little-endian u32s:
    the loaded register equals the bit-packing of that 16-byte window. -/
@[step] theorem verify.intrinsics.x86_64.sse2.loadu_si128_u8.spec
    (bytes : Slice Std.U8) (at1 : Std.Usize)
    (hbnd : at1.val + 16 ≤ bytes.length) :
  verify.intrinsics.x86_64.sse2.loadu_si128_u8 bytes at1
  ⦃ (r : U32x4) =>
    r.bv (·.bv) = (bytes.subArray at1 16#usize hbnd).bv (·.bv) ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.loadu_si128_u8
  step*
  case h =>
    -- copy_from_slice length side-condition
    rw [show s.length = s.val.length from rfl, s_post1, s1_post2, i_post]; simp
  -- `bytes_to_dwords` made `r` the dword-packing of the destination window
  -- `to_slice_mut_back s2`, which is exactly the byte sub-array `bytes[at1..at1+16]`.
  have hs1len : s1.val.length = 16 := by
    have h := s1_post2
    rw [show s1.length = s1.val.length from rfl, i_post] at h; scalar_tac
  have hb1 : (to_slice_mut_back s2).val = s1.val := by rw [s_post2, s2_post]; simp [hs1len]
  have heq : to_slice_mut_back s2 = bytes.subArray at1 16#usize hbnd := by
    apply Subtype.ext
    rw [Aeneas.Std.Slice.subArray_val, hb1, s1_post1, i_post]; rfl
  rw [r_post, heq]

/-- Load 4 u32s directly from `bytes[at1..at1+4]` (element-wise, not byte-wise). -/
@[step] theorem verify.intrinsics.x86_64.sse2.loadu_si128_u32.spec
    (arr : Slice Std.U32) (at1 : Std.Usize)
    (hbnd : at1.val + 4 ≤ arr.length) :
  verify.intrinsics.x86_64.sse2.loadu_si128_u32 arr at1
  ⦃ (r : U32x4) =>
    ∀ k, (hk : k < 4) → r[k] = arr[at1.val + k] ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.loadu_si128_u32
  step*
  intro k hk
  rcases k with _|_|_|_|k
  · -- k = 0
    show i = arr[at1.val + 0]
    rw [i_post]
    exact getElem_congr_idx (Nat.add_zero _).symm
  · -- k = 1
    show i2 = arr[at1.val + 1]
    rw [i2_post]
    exact getElem_congr_idx i1_post
  · -- k = 2
    show i4 = arr[at1.val + 2]
    rw [i4_post]
    exact getElem_congr_idx i3_post
  · -- k = 3
    show i6 = arr[at1.val + 3]
    rw [i6_post]
    exact getElem_congr_idx i5_post
  · scalar_tac

/-- Store 4 u32s into `arr[at1..at1+4]`, leaving other entries untouched. -/
@[step] theorem verify.intrinsics.x86_64.sse2.storeu_si128_u32.spec
    (arr : Slice Std.U32) (at1 : Std.Usize) (v : U32x4)
    (hbnd : at1.val + 4 ≤ arr.length) :
  verify.intrinsics.x86_64.sse2.storeu_si128_u32 arr at1 v
  ⦃ (r : Slice Std.U32) =>
    ∃ (h_len : r.length = arr.length),
      ∀ k (hk : k < arr.length),
        r[k] = if h : at1.val ≤ k ∧ k < at1.val + 4
                   then v[k - at1.val]
                   else arr[k] ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.storeu_si128_u32
  step*
  · agrind
  · grind

/-- Store 16 bytes (`v.val`) into `bytes[at1..at1+16]`. -/
@[step] theorem verify.intrinsics.x86_64.sse2.store_si128.spec
    (bytes : Slice Std.U8) (at1 : Std.Usize) (v : M128)
    (hbnd : at1.val + 16 ≤ bytes.length) :
  verify.intrinsics.x86_64.sse2.store_si128 bytes at1 v
  ⦃ (r : Slice Std.U8) =>
    ∃ (h_len : r.length = bytes.length),
      ∀ k (hk : k < bytes.length),
        r[k] = if h : at1.val ≤ k ∧ k < at1.val + 16
                   then v[k - at1.val]
                   else bytes[k] ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.store_si128
  step as ⟨ i, hi ⟩
  step as ⟨ s, back, hsval, hslen, hback ⟩
  step as ⟨ s1, hs1 ⟩
  step as ⟨ s2, hs2 ⟩
  subst hs2; subst hs1; rw [hback]
  have hvts : v.to_slice.val = v.val := by simp [Array.to_slice]
  have hvlen : v.length = 16 := by simp
  refine ⟨by simp, fun k hk => ?_⟩
  simp only [hvts]
  split
  · rename_i h; obtain ⟨hle, hlt⟩ := h
    exact Slice.setSlice!_getElem_middle bytes v.val at1.val k
      ⟨hle, by scalar_tac, hk⟩
  · rename_i h; push Not at h
    by_cases hle : at1.val ≤ k
    · exact Slice.setSlice!_getElem_suffix bytes v.val at1.val k
        ⟨by scalar_tac, hk⟩
    · exact Slice.setSlice!_getElem_prefix bytes v.val at1.val k
        ⟨by scalar_tac, hk⟩

/-- Helper: For a `BitVec 64`, the k-th little-endian byte's `.toNat` equals
    `(b.toNat >>> (8 * k)) % 256`. -/
private theorem BitVec.toLEBytes_getElem_toNat_u64
    (b : _root_.BitVec 64) (k : Nat) (hk : k < 8) :
    b.toLEBytes[k].toNat = (b.toNat >>> (8 * k)) % 256 := by
  have hlen : b.toLEBytes.length = 8 := by simp [_root_.BitVec.toLEBytes_length]
  have hk_lt : k < b.toLEBytes.length := by rw [hlen]; exact hk
  -- Prove both Nats equal by `Nat.eq_of_testBit_eq`
  apply Nat.eq_of_testBit_eq
  intro j
  by_cases hj : j < 8
  · have hL : (b.toLEBytes[k]).toNat.testBit j = b.toNat.testBit (8 * k + j) := by
      change Byte.testBit (b.toLEBytes[k]) j = _
      rw [_root_.BitVec.toLEBytes_getElem_testBit _ _ _ (by grind)]
      rw [_root_.BitVec.getElem_eq_testBit_toNat]
      grind
    rw [hL]
    -- RHS
    rw [show (256 : Nat) = 2^8 from rfl, Nat.testBit_mod_two_pow,
        Nat.testBit_shiftRight]
    simp [hj, Nat.add_comm]
  · -- j ≥ 8: both sides are 0 because both numbers are < 2^8 ≤ 2^j
    have hj' : 8 ≤ j := by scalar_tac
    have hpow : (2:Nat)^8 ≤ 2^j := Nat.pow_le_pow_right (by decide) hj'
    have h1 : b.toLEBytes[k].toNat < 2^j := by
      have := b.toLEBytes[k].isLt
      scalar_tac
    have h2 : (b.toNat >>> (8 * k)) % 256 < 2^j := by
      have : (b.toNat >>> (8 * k)) % 256 < 256 := Nat.mod_lt _ (by decide)
      have h256 : (256 : Nat) = 2^8 := by decide
      scalar_tac
    rw [Nat.testBit_lt_two_pow h1, Nat.testBit_lt_two_pow h2]

@[step] theorem verify.intrinsics.x86_64.sse2.loadu_si64.spec
    (bytes : Slice Std.U8) (at1 : Std.Usize)
    (hbnd : at1.val + 8 ≤ bytes.length) :
  verify.intrinsics.x86_64.sse2.loadu_si64 bytes at1
  ⦃ (r : U64x2) =>
    r[1] = 0#u64 ∧
    r[0].bv = BitVec.fromLEBytes
      [bytes[at1.val].bv, bytes[at1.val + 1].bv,
       bytes[at1.val + 2].bv, bytes[at1.val + 3].bv,
       bytes[at1.val + 4].bv, bytes[at1.val + 5].bv,
       bytes[at1.val + 6].bv, bytes[at1.val + 7].bv] ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.loadu_si64
  step*
  refine ⟨rfl, ?_⟩
  show i15.bv = _
  rw [i15_post]
  rw [i_post, i2_post, i4_post, i6_post, i8_post, i10_post, i12_post, i14_post]
  simp only [Std.Array.make, List.map]
  rw [getElem_congr_idx i1_post, getElem_congr_idx i3_post,
      getElem_congr_idx i5_post, getElem_congr_idx i7_post,
      getElem_congr_idx i9_post, getElem_congr_idx i11_post,
      getElem_congr_idx i13_post]
  norm_cast

/-- Store 8 bytes (the little-endian encoding of `v[0]`) into
    `bytes[at1..at1+8]`; lane 1 of `v` is ignored. -/
@[step] theorem verify.intrinsics.x86_64.sse2.storeu_si64.spec
    (bytes : Slice Std.U8) (at1 : Std.Usize) (v : U64x2)
    (hbnd : at1.val + 8 ≤ bytes.length) :
  verify.intrinsics.x86_64.sse2.storeu_si64 bytes at1 v
  ⦃ (r : Slice Std.U8) =>
    ∃ (h_len : r.length = bytes.length),
      ∀ k (hk : k < bytes.length),
        r[k].val = if at1.val ≤ k ∧ k < at1.val + 8
                       then (v[0].val >>> (8 * (k - at1.val))) % 256
                       else bytes[k].val ⦄ := by
  unfold verify.intrinsics.x86_64.sse2.storeu_si64
  step as ⟨ i, hi ⟩
  step as ⟨ s, back, hsval, hslen, hback ⟩
  step as ⟨ i1, hi1 ⟩
  step as ⟨ a, ha ⟩
  step as ⟨ s1, hs1 ⟩
  step as ⟨ s2, hs2 ⟩
  subst hs2; subst hs1; rw [hback]
  have hats : a.to_slice.val = a.val := by simp [Array.to_slice]
  have halen : a.val.length = 8 := by rw [ha]; simp [_root_.BitVec.toLEBytes_length]
  refine ⟨by simp, fun k hk => ?_⟩
  simp only [hats]
  split
  · rename_i h; obtain ⟨hle, hlt⟩ := h
    have hkn : k - at1.val < a.val.length := by rw [halen]; scalar_tac
    rw [Slice.setSlice!_getElem_middle bytes a.val at1.val k ⟨hle, hkn, hk⟩]
    -- the stored byte is the `(k-at1)`-th little-endian byte of `v[0]`
    simp only [ha, List.getElem_map]
    show (i1.bv.toLEBytes[k - at1.val]'_).toNat = _
    rw [BitVec.toLEBytes_getElem_toNat_u64 _ _ (by scalar_tac)]
    simp [hi1]
  · rename_i h; push Not at h
    by_cases hle : at1.val ≤ k
    · rw [Slice.setSlice!_getElem_suffix bytes a.val at1.val k ⟨by rw [halen]; scalar_tac, hk⟩]
    · rw [Slice.setSlice!_getElem_prefix bytes a.val at1.val k ⟨by scalar_tac, hk⟩]

end symcrust
