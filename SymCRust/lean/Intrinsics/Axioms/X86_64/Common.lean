/-
  Silicon register types for SSE2/SSSE3/AVX/AVX2.

  ## Sources of truth
  Intel SDM: `__m128i` / `__m256i` register layout, little-endian byte
  addressing.

  ## Trust ledger
  Trusted model: `__m256i` for the opaque 256-bit register type. The byte views
  and derived wider lane views are plain helper defs.
-/
import Aeneas
import Symcrust.Code.Types
import Intrinsics.Simd
import Intrinsics.Properties.X86_64.Register

open Aeneas Aeneas.Std Result Intrinsics

set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false

local macro_rules | `(tactic| get_elem_tactic) => `(tactic| first | assumption | grind)

/-! ## Type abbreviations -/

/-- [core::core_arch::x86::__m256i] — 256-bit AVX register type. -/
@[rust_type "core::core_arch::x86::__m256i"]
def core.core_arch.x86.__m256i : Type := Intrinsics.M256

namespace Intrinsics.X86_64

/-- 128-bit XMM register (`core.core_arch.x86.__m128i`). -/
abbrev Xmm := core.core_arch.x86.__m128i

/-- 256-bit YMM register (`core.core_arch.x86.__m256i`). -/
abbrev Ymm := core.core_arch.x86.__m256i

end Intrinsics.X86_64

/-! ## XMM (`__m128i`) — byte view + derived lane views -/

namespace core.core_arch.x86.__m128i

/-- Reinterpret a `__m128i` as sixteen bytes, lane 0 = low byte. -/
def u8x16 (x : __m128i) : U8x16 := x

/-- Reinterpret sixteen bytes as a `__m128i`, lane 0 = low byte. -/
def ofU8x16 (b : U8x16) : __m128i := b

/-- Round-trip: bytes → xmm → bytes. -/
@[simp] theorem u8x16_ofU8x16 (b : U8x16) : (__m128i.ofU8x16 b).u8x16 = b := rfl

/-- Round-trip: xmm → bytes → xmm. -/
@[simp] theorem ofU8x16_u8x16 (x : __m128i) : __m128i.ofU8x16 x.u8x16 = x := rfl

/-! ### Derived lane views -/

noncomputable section

/-- Reinterpret a `__m128i` as eight `U16` lanes (LE). -/
def u16x8 (x : __m128i) : U16x8 := Register.u16x8 (x.u8x16.bv (·.bv))
/-- Pack eight `U16` lanes (LE) into a `__m128i`. -/
def ofU16x8 (w : U16x8) : __m128i := __m128i.ofU8x16 (Register.u8x16 (w.bv (·.bv)))

/-- Reinterpret a `__m128i` as four `U32` lanes (LE). -/
def u32x4 (x : __m128i) : U32x4 := Register.u32x4 (x.u8x16.bv (·.bv))
/-- Pack four `U32` lanes (LE) into a `__m128i`. -/
def ofU32x4 (w : U32x4) : __m128i := __m128i.ofU8x16 (Register.u8x16 (w.bv (·.bv)))

/-- Reinterpret a `__m128i` as two `U64` lanes (LE). -/
def u64x2 (x : __m128i) : U64x2 := Register.u64x2 (x.u8x16.bv (·.bv))
/-- Pack two `U64` lanes (LE) into a `__m128i`. -/
def ofU64x2 (w : U64x2) : __m128i := __m128i.ofU8x16 (Register.u8x16 (w.bv (·.bv)))

@[simp] theorem u16x8_ofU16x8 (w : U16x8) : (__m128i.ofU16x8 w).u16x8 = w := by
  simp [u16x8, ofU16x8, Register.u16x8, Register.u8x16]
@[simp] theorem ofU16x8_u16x8 (x : __m128i) : __m128i.ofU16x8 x.u16x8 = x := by
  simp [u16x8, ofU16x8, Register.u16x8, Register.u8x16]
@[simp] theorem u32x4_ofU32x4 (w : U32x4) : (__m128i.ofU32x4 w).u32x4 = w := by
  simp [u32x4, ofU32x4, Register.u32x4, Register.u8x16]
@[simp] theorem ofU32x4_u32x4 (x : __m128i) : __m128i.ofU32x4 x.u32x4 = x := by
  simp [u32x4, ofU32x4, Register.u32x4, Register.u8x16]
@[simp] theorem u64x2_ofU64x2 (w : U64x2) : (__m128i.ofU64x2 w).u64x2 = w := by
  simp [u64x2, ofU64x2, Register.u64x2, Register.u8x16]
@[simp] theorem ofU64x2_u64x2 (x : __m128i) : __m128i.ofU64x2 x.u64x2 = x := by
  simp [u64x2, ofU64x2, Register.u64x2, Register.u8x16]

end

end core.core_arch.x86.__m128i

/-! ## YMM (`__m256i`) — byte view + derived lane views -/

namespace core.core_arch.x86.__m256i

/-- Reinterpret a `__m256i` as thirty-two bytes, lane 0 = low byte. -/
def u8x32 (y : __m256i) : U8x32 := y

/-- Reinterpret thirty-two bytes as a `__m256i`, lane 0 = low byte. -/
def ofU8x32 (b : U8x32) : __m256i := b

/-- Round-trip: bytes → ymm → bytes. -/
@[simp] theorem u8x32_ofU8x32 (b : U8x32) : (__m256i.ofU8x32 b).u8x32 = b := rfl

/-- Round-trip: ymm → bytes → ymm. -/
@[simp] theorem ofU8x32_u8x32 (y : __m256i) : __m256i.ofU8x32 y.u8x32 = y := rfl

/-! ### Derived lane views -/

noncomputable section

/-- Reinterpret a `__m256i` as sixteen `U16` lanes (LE). -/
def u16x16 (y : __m256i) : U16x16 := Register.u16x16 (y.u8x32.bv (·.bv))
/-- Pack sixteen `U16` lanes (LE) into a `__m256i`. -/
def ofU16x16 (w : U16x16) : __m256i := __m256i.ofU8x32 (Register.u8x32 (w.bv (·.bv)))

/-- Reinterpret a `__m256i` as four `U64` lanes (LE). -/
def u64x4 (y : __m256i) : U64x4 := Register.u64x4 (y.u8x32.bv (·.bv))
/-- Pack four `U64` lanes (LE) into a `__m256i`. -/
def ofU64x4 (w : U64x4) : __m256i := __m256i.ofU8x32 (Register.u8x32 (w.bv (·.bv)))

@[simp] theorem u16x16_ofU16x16 (w : U16x16) : (__m256i.ofU16x16 w).u16x16 = w := by
  simp [u16x16, ofU16x16, Register.u16x16, Register.u8x32]
@[simp] theorem ofU16x16_u16x16 (y : __m256i) : __m256i.ofU16x16 y.u16x16 = y := by
  simp [u16x16, ofU16x16, Register.u16x16, Register.u8x32]
@[simp] theorem u64x4_ofU64x4 (w : U64x4) : (__m256i.ofU64x4 w).u64x4 = w := by
  simp [u64x4, ofU64x4, Register.u64x4, Register.u8x32]
@[simp] theorem ofU64x4_u64x4 (y : __m256i) : __m256i.ofU64x4 y.u64x4 = y := by
  simp [u64x4, ofU64x4, Register.u64x4, Register.u8x32]

end

end core.core_arch.x86.__m256i
