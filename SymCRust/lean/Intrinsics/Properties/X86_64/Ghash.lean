/-
  Public GHASH Layer-1 surface.

  `@[step]` theorems for the Rust GHASH models of intrinsics
  `verify.intrinsics.x86_64.ghash.*` extracted to in `Symcrust/Code/*`.

  See `INTRINSICS.md` for the layered architecture.
-/
import Intrinsics.Simd
import Intrinsics.Properties.X86_64.Sse2
import Intrinsics.Properties.X86_64.Ssse3
import Symcrust.Code.Funs
import Intrinsics.Properties.Lanewise
import Intrinsics.Properties.Lanes
import Intrinsics.BVRealize
import Intrinsics.Properties.X86_64.Register
open Aeneas Aeneas.Std Intrinsics

local macro_rules
| `(tactic| get_elem_tactic) => `(tactic| first | assumption | agrind)

namespace symcrust

/-! ## `xor` — bytewise XOR of two registers -/

@[step] theorem verify.intrinsics.x86_64.ghash.xor.spec (a b : M128) :
  verify.intrinsics.x86_64.ghash.xor a b
  ⦃ (r : M128) =>
    ∀ k, (hk : k < 16) → r[k] = a[k] ^^^ b[k] ⦄ := by
  unfold verify.intrinsics.x86_64.ghash.xor
  step*

/-! ## `srli_si128_8` — byte-shift the register right by 8 bytes -/

@[step] theorem verify.intrinsics.x86_64.ghash.srli_si128_8.spec (a : M128) :
  verify.intrinsics.x86_64.ghash.srli_si128_8 a
  ⦃ (r : M128) =>
    (∀ k, (hk : k + 8 < 16) → r[k] = a[k + 8]) ∧
    (∀ k, 8 ≤ k → (hk : k < 16) → r[k] = 0#u8) ⦄ := by
  unfold verify.intrinsics.x86_64.ghash.srli_si128_8
  step*

/-! ## `set_epi32` — assemble a register from four i32 lanes -/

@[step] theorem verify.intrinsics.x86_64.ghash.set_epi32.spec
    (e3 e2 e1 e0 : Std.I32) :
  verify.intrinsics.x86_64.ghash.set_epi32 e3 e2 e1 e0
  ⦃ (r : M128) =>
    r.bv (·.bv) = (Std.Array.make 4#usize [e0, e1, e2, e3]).bv (·.bv) ⦄ := by
  unfold verify.intrinsics.x86_64.ghash.set_epi32
  step*
  rw [r_post, a_post]
  apply Aeneas.Std.Array.bv_congr
  intro i; fin_cases i <;> rfl

/-! ## `slli_epi32_1` — shift each 32-bit lane left by 1 -/

@[step] theorem verify.intrinsics.x86_64.ghash.slli_epi32_1.spec (a : M128) :
  verify.intrinsics.x86_64.ghash.slli_epi32_1 a
  ⦃ (r : M128) =>
    ∀ k, (hk : k < 4) →
      (M128.u32x4 r)[k].bv = (M128.u32x4 a)[k].bv.shiftLeft 1 ⦄ := by
  unfold verify.intrinsics.x86_64.ghash.slli_epi32_1
  step*
  simp only [M128.u32x4_of_bv r_post1, M128.u32x4_of_bv a1_post.symm]
  exact a2_post _ r_post2

/-! ## `srli_epi32_31` — shift each 32-bit lane right by 31 -/

@[step] theorem verify.intrinsics.x86_64.ghash.srli_epi32_31.spec (a : M128) :
  verify.intrinsics.x86_64.ghash.srli_epi32_31 a
  ⦃ (r : M128) =>
    ∀ k, (hk : k < 4) →
      (M128.u32x4 r)[k].bv = (M128.u32x4 a)[k].bv.ushiftRight 31 ⦄ := by
  unfold verify.intrinsics.x86_64.ghash.srli_epi32_31
  step*
  simp only [M128.u32x4_of_bv r_post1, M128.u32x4_of_bv a1_post.symm]
  exact a2_post _ r_post2

/-! ## `slli_epi64_1` — shift each 64-bit lane left by 1 -/

@[step] theorem verify.intrinsics.x86_64.ghash.slli_epi64_1.spec (a : M128) :
  verify.intrinsics.x86_64.ghash.slli_epi64_1 a
  ⦃ (r : M128) =>
    ∀ k, (hk : k < 2) →
      (M128.u64x2 r)[k].bv = (M128.u64x2 a)[k].bv.shiftLeft 1 ⦄ := by
  unfold verify.intrinsics.x86_64.ghash.slli_epi64_1
  step*
  simp only [M128.u64x2_of_bv r_post1, M128.u64x2_of_bv a1_post.symm]
  exact a2_post _ (by scalar_tac)

/-! ## `shuffle_epi32_0x4e` — swap the two 64-bit halves (dword view) -/

@[step] theorem verify.intrinsics.x86_64.ghash.shuffle_epi32_0x4e.spec (a : M128) :
  verify.intrinsics.x86_64.ghash.shuffle_epi32_0x4e a
  ⦃ (r : M128) =>
    (M128.u32x4 r)[0] = (M128.u32x4 a)[2] ∧
    (M128.u32x4 r)[1] = (M128.u32x4 a)[3] ∧
    (M128.u32x4 r)[2] = (M128.u32x4 a)[0] ∧
    (M128.u32x4 r)[3] = (M128.u32x4 a)[1] ⦄ := by
  unfold verify.intrinsics.x86_64.ghash.shuffle_epi32_0x4e
  step*
  refine ⟨?_, ?_, ?_, ?_⟩ <;>
    simp only [M128.u32x4_of_bv r_post, M128.u32x4_of_bv a1_post.symm,
               a2_post1, a2_post2, a2_post3, a2_post4]

/-! ## `shuffle_epi32_0x93` — rotate lanes toward the high end (dword view) -/

@[step] theorem verify.intrinsics.x86_64.ghash.shuffle_epi32_0x93.spec (a : M128) :
  verify.intrinsics.x86_64.ghash.shuffle_epi32_0x93 a
  ⦃ (r : M128) =>
    (M128.u32x4 r)[0] = (M128.u32x4 a)[3] ∧
    (M128.u32x4 r)[1] = (M128.u32x4 a)[0] ∧
    (M128.u32x4 r)[2] = (M128.u32x4 a)[1] ∧
    (M128.u32x4 r)[3] = (M128.u32x4 a)[2] ⦄ := by
  unfold verify.intrinsics.x86_64.ghash.shuffle_epi32_0x93
  step*
  refine ⟨?_, ?_, ?_, ?_⟩ <;>
    simp only [M128.u32x4_of_bv r_post, M128.u32x4_of_bv a1_post.symm,
               a2_post1, a2_post2, a2_post3, a2_post4]

/-! ## `byte_reverse` — reverse the 16 bytes of the register -/

@[step] theorem verify.intrinsics.x86_64.ghash.byte_reverse.spec (a : M128) :
  verify.intrinsics.x86_64.ghash.byte_reverse a
  ⦃ (r : M128) =>
    ∀ k, (hk : k < 16) → r[k] = a[15 - k] ⦄ := by
  unfold verify.intrinsics.x86_64.ghash.byte_reverse
  apply WP.spec_mono (verify.intrinsics.x86_64.ssse3.shuffle_epi8.spec a
    verify.intrinsics.x86_64.ghash.BYTE_REVERSE_ORDER)
  intro r hr k hk
  match k, hk with
  | 0, _ => simp_all [Std.Array.make, verify.intrinsics.x86_64.ghash.BYTE_REVERSE_ORDER]
  | 1, _ => simp_all [Std.Array.make, verify.intrinsics.x86_64.ghash.BYTE_REVERSE_ORDER]
  | 2, _ => simp_all [Std.Array.make, verify.intrinsics.x86_64.ghash.BYTE_REVERSE_ORDER]
  | 3, _ => simp_all [Std.Array.make, verify.intrinsics.x86_64.ghash.BYTE_REVERSE_ORDER]
  | 4, _ => simp_all [Std.Array.make, verify.intrinsics.x86_64.ghash.BYTE_REVERSE_ORDER]
  | 5, _ => simp_all [Std.Array.make, verify.intrinsics.x86_64.ghash.BYTE_REVERSE_ORDER]
  | 6, _ => simp_all [Std.Array.make, verify.intrinsics.x86_64.ghash.BYTE_REVERSE_ORDER]
  | 7, _ => simp_all [Std.Array.make, verify.intrinsics.x86_64.ghash.BYTE_REVERSE_ORDER]
  | 8, _ => simp_all [Std.Array.make, verify.intrinsics.x86_64.ghash.BYTE_REVERSE_ORDER]
  | 9, _ => simp_all [Std.Array.make, verify.intrinsics.x86_64.ghash.BYTE_REVERSE_ORDER]
  | 10, _ => simp_all [Std.Array.make, verify.intrinsics.x86_64.ghash.BYTE_REVERSE_ORDER]
  | 11, _ => simp_all [Std.Array.make, verify.intrinsics.x86_64.ghash.BYTE_REVERSE_ORDER]
  | 12, _ => simp_all [Std.Array.make, verify.intrinsics.x86_64.ghash.BYTE_REVERSE_ORDER]
  | 13, _ => simp_all [Std.Array.make, verify.intrinsics.x86_64.ghash.BYTE_REVERSE_ORDER]
  | 14, _ => simp_all [Std.Array.make, verify.intrinsics.x86_64.ghash.BYTE_REVERSE_ORDER]
  | 15, _ => simp_all [Std.Array.make, verify.intrinsics.x86_64.ghash.BYTE_REVERSE_ORDER]
  | n + 16, hk => exact absurd hk (by scalar_tac)

/-! ## `clmul_00/01/10/11` — carry-less multiply of selected 64-bit halves

Each wraps the opaque `pclmulqdq.clmulepi64_si128` over the qword carrier;
the spec exposes the two output qwords as the low/high halves of the
`Spec.AESGCM.clmul64` product of the selected input lanes (`_NM`: lane `N`
of `a`, lane `M` of `b`). -/

@[step] theorem verify.intrinsics.x86_64.ghash.clmul_00.spec (a b : M128) :
  verify.intrinsics.x86_64.ghash.clmul_00 a b
  ⦃ (r : M128) =>
    let p := Spec.AESGCM.clmul64 a.u64x2[0].bv b.u64x2[0].bv
    r.u64x2[0].bv = p.extractLsb' 0 64 ∧
    r.u64x2[1].bv = p.extractLsb' 64 64 ⦄ := by
  unfold verify.intrinsics.x86_64.ghash.clmul_00
  step*
  simp only [M128.u64x2_of_bv r_post, M128.u64x2_of_bv a1_post.symm,
             M128.u64x2_of_bv a2_post.symm]
  exact ⟨a3_post1, a3_post2⟩

@[step] theorem verify.intrinsics.x86_64.ghash.clmul_01.spec (a b : M128) :
  verify.intrinsics.x86_64.ghash.clmul_01 a b
  ⦃ (r : M128) =>
    let p := Spec.AESGCM.clmul64 a.u64x2[1].bv b.u64x2[0].bv
    r.u64x2[0].bv = p.extractLsb' 0 64 ∧
    r.u64x2[1].bv = p.extractLsb' 64 64 ⦄ := by
  unfold verify.intrinsics.x86_64.ghash.clmul_01
  step*
  simp only [M128.u64x2_of_bv r_post, M128.u64x2_of_bv a1_post.symm,
             M128.u64x2_of_bv a2_post.symm]
  exact ⟨a3_post1, a3_post2⟩

@[step] theorem verify.intrinsics.x86_64.ghash.clmul_10.spec (a b : M128) :
  verify.intrinsics.x86_64.ghash.clmul_10 a b
  ⦃ (r : M128) =>
    let p := Spec.AESGCM.clmul64 a.u64x2[0].bv b.u64x2[1].bv
    r.u64x2[0].bv = p.extractLsb' 0 64 ∧
    r.u64x2[1].bv = p.extractLsb' 64 64 ⦄ := by
  unfold verify.intrinsics.x86_64.ghash.clmul_10
  step*
  simp only [M128.u64x2_of_bv r_post, M128.u64x2_of_bv a1_post.symm,
             M128.u64x2_of_bv a2_post.symm]
  exact ⟨a3_post1, a3_post2⟩

@[step] theorem verify.intrinsics.x86_64.ghash.clmul_11.spec (a b : M128) :
  verify.intrinsics.x86_64.ghash.clmul_11 a b
  ⦃ (r : M128) =>
    let p := Spec.AESGCM.clmul64 a.u64x2[1].bv b.u64x2[1].bv
    r.u64x2[0].bv = p.extractLsb' 0 64 ∧
    r.u64x2[1].bv = p.extractLsb' 64 64 ⦄ := by
  unfold verify.intrinsics.x86_64.ghash.clmul_11
  step*
  simp only [M128.u64x2_of_bv r_post, M128.u64x2_of_bv a1_post.symm,
             M128.u64x2_of_bv a2_post.symm]
  exact ⟨a3_post1, a3_post2⟩

end symcrust
