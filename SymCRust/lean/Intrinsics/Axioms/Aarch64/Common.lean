/-
  Concrete lane views for the opaque NEON register types.

  ## Sources of truth
  Arm ARM (DDI 0487 K.a, March 2024) §C2.3 (Advanced SIMD vector types),
  ACLE `vld1q_*` / `vst1q_*`. Little-endian aarch64 only.

  ## Trust ledger
  Trusted models for the opaque NEON register types: `uint16x8_t`, `uint8x16_t`,
  `uint32x4_t`, `uint64x2_t`.
-/
import Aeneas
import Symcrust.Code.Types

open Aeneas Aeneas.Std

/-! ## NEON register types

Concrete lane-`Vector` models of the opaque NEON register types; the
`@[rust_type]` tags bind them to the extracted Aeneas names. -/

/-- `uint16x8_t` as eight `u16` lanes. -/
@[rust_type "core::core_arch::arm_shared::neon::uint16x8_t"]
def core.core_arch.arm_shared.neon.uint16x8_t : Type := Vector Std.U16 8

/-- `uint8x16_t` as sixteen `u8` lanes. -/
@[rust_type "core::core_arch::arm_shared::neon::uint8x16_t"]
def core.core_arch.arm_shared.neon.uint8x16_t : Type := Vector Std.U8 16

/-- `uint32x4_t` as four `u32` lanes. -/
@[rust_type "core::core_arch::arm_shared::neon::uint32x4_t"]
def core.core_arch.arm_shared.neon.uint32x4_t : Type := Vector Std.U32 4

/-- `uint64x2_t` as two `u64` lanes. -/
@[rust_type "core::core_arch::arm_shared::neon::uint64x2_t"]
def core.core_arch.arm_shared.neon.uint64x2_t : Type := Vector Std.U64 2

/-! ## `uint16x8_t` lane view -/

namespace core.core_arch.arm_shared.neon.uint16x8_t

/-- Reinterpret a `uint16x8_t` as eight `u16` lanes, lane 0 = low. -/
def u16x8 (v : core.core_arch.arm_shared.neon.uint16x8_t) : Vector Std.U16 8 := v

/-- Build a `uint16x8_t` from eight `u16` lanes, lane 0 = low. -/
def ofU16x8 (w : Vector Std.U16 8) : core.core_arch.arm_shared.neon.uint16x8_t := w

/-- Round-trip: lanes → vec → lanes. -/
@[simp]
theorem u16x8_ofU16x8 (w : Vector Std.U16 8) :
    (core.core_arch.arm_shared.neon.uint16x8_t.ofU16x8 w).u16x8 = w := rfl

/-- Round-trip: vec → lanes → vec. -/
@[simp]
theorem ofU16x8_u16x8 (v : core.core_arch.arm_shared.neon.uint16x8_t) :
    core.core_arch.arm_shared.neon.uint16x8_t.ofU16x8 v.u16x8 = v := rfl

end core.core_arch.arm_shared.neon.uint16x8_t

/-! ## `uint8x16_t` lane view -/

namespace core.core_arch.arm_shared.neon.uint8x16_t

/-- Reinterpret a `uint8x16_t` as sixteen `u8` lanes, lane 0 = low. -/
def u8x16 (v : core.core_arch.arm_shared.neon.uint8x16_t) : Vector Std.U8 16 := v

/-- Build a `uint8x16_t` from sixteen `u8` lanes, lane 0 = low. -/
def ofU8x16 (w : Vector Std.U8 16) : core.core_arch.arm_shared.neon.uint8x16_t := w

/-- Round-trip: lanes → vec → lanes. -/
@[simp]
theorem u8x16_ofU8x16 (w : Vector Std.U8 16) :
    (core.core_arch.arm_shared.neon.uint8x16_t.ofU8x16 w).u8x16 = w := rfl

/-- Round-trip: vec → lanes → vec. -/
@[simp]
theorem ofU8x16_u8x16 (v : core.core_arch.arm_shared.neon.uint8x16_t) :
    core.core_arch.arm_shared.neon.uint8x16_t.ofU8x16 v.u8x16 = v := rfl

end core.core_arch.arm_shared.neon.uint8x16_t

/-! ## `uint32x4_t` lane view -/

namespace core.core_arch.arm_shared.neon.uint32x4_t

/-- Reinterpret a `uint32x4_t` as four `u32` lanes, lane 0 = low. -/
def u32x4 (v : core.core_arch.arm_shared.neon.uint32x4_t) : Vector Std.U32 4 := v

/-- Build a `uint32x4_t` from four `u32` lanes, lane 0 = low. -/
def ofU32x4 (w : Vector Std.U32 4) : core.core_arch.arm_shared.neon.uint32x4_t := w

/-- Round-trip: lanes → vec → lanes. -/
@[simp]
theorem u32x4_ofU32x4 (w : Vector Std.U32 4) :
    (core.core_arch.arm_shared.neon.uint32x4_t.ofU32x4 w).u32x4 = w := rfl

/-- Round-trip: vec → lanes → vec. -/
@[simp]
theorem ofU32x4_u32x4 (v : core.core_arch.arm_shared.neon.uint32x4_t) :
    core.core_arch.arm_shared.neon.uint32x4_t.ofU32x4 v.u32x4 = v := rfl

end core.core_arch.arm_shared.neon.uint32x4_t

/-! ## `uint64x2_t` lane view -/

namespace core.core_arch.arm_shared.neon.uint64x2_t

/-- Reinterpret a `uint64x2_t` as two `u64` lanes, lane 0 = low. -/
def u64x2 (v : core.core_arch.arm_shared.neon.uint64x2_t) : Vector Std.U64 2 := v

/-- Build a `uint64x2_t` from two `u64` lanes, lane 0 = low. -/
def ofU64x2 (w : Vector Std.U64 2) : core.core_arch.arm_shared.neon.uint64x2_t := w

/-- Round-trip: lanes → vec → lanes. -/
@[simp]
theorem u64x2_ofU64x2 (w : Vector Std.U64 2) :
    (core.core_arch.arm_shared.neon.uint64x2_t.ofU64x2 w).u64x2 = w := rfl

/-- Round-trip: vec → lanes → vec. -/
@[simp]
theorem ofU64x2_u64x2 (v : core.core_arch.arm_shared.neon.uint64x2_t) :
    core.core_arch.arm_shared.neon.uint64x2_t.ofU64x2 v.u64x2 = v := rfl

end core.core_arch.arm_shared.neon.uint64x2_t

/-! ## Cross-width little-endian byte serialization helpers

Pure functions modelling the `vreinterpretq_*` family (a no-op reinterpret at
the register file) as little-endian byte (de)serialisation, mirroring the shim
defs in `src/verify/intrinsics/aarch64/neon.rs`. -/

/-- Little-endian serialization of a `Vector U32 4` to a `Vector U8 16`:
    lane `k` of the input occupies bytes `[4*k .. 4*k+4)` of the output,
    LSB first. -/
def u32x4ToU8x16 (v : Vector Std.U32 4) : Vector Std.U8 16 :=
  Vector.ofFn fun (i : Fin 16) =>
    let lane := v[i.val / 4]
    ⟨(lane.bv >>> ((i.val % 4) * 8)).truncate 8⟩

/-- Inverse of `u32x4ToU8x16`: read 4 little-endian bytes per output lane. -/
def u8x16ToU32x4 (b : Vector Std.U8 16) : Vector Std.U32 4 :=
  Vector.ofFn fun (k : Fin 4) =>
    let b0 := b[4 * k.val + 0].bv
    let b1 := b[4 * k.val + 1].bv
    let b2 := b[4 * k.val + 2].bv
    let b3 := b[4 * k.val + 3].bv
    ⟨b3 ++ b2 ++ b1 ++ b0⟩

/-- Little-endian serialization of a `Vector U64 2` to a `Vector U8 16`:
    lane `k` of the input occupies bytes `[8*k .. 8*k+8)` of the output. -/
def u64x2ToU8x16 (v : Vector Std.U64 2) : Vector Std.U8 16 :=
  Vector.ofFn fun (i : Fin 16) =>
    let lane := v[i.val / 8]
    ⟨(lane.bv >>> ((i.val % 8) * 8)).truncate 8⟩
