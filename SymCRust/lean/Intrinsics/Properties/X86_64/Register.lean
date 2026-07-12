/-
  X86 register carrier types.
-/
import Intrinsics.Simd

open Aeneas Aeneas.Std Intrinsics

namespace Intrinsics.X86_64

/-- 256-bit register carrier modelled as thirty-two bytes (Rust `[u8; 32]`). -/
abbrev m256 : Type := M256

namespace m256

/-- Sixteen little-endian `U16` lanes (matches `M256.u16x16`). -/
abbrev u16x16 (b : m256) : U16x16 := M256.u16x16 b

/-- Four little-endian `U64` lanes (Rust-model sync: `store_lane`). -/
abbrev u64x4 (b : m256) : U64x4 := M256.u64x4 b

/-- Pack four little-endian `U64` lanes (Rust-model sync: `load_lane`). -/
def ofU64x4 (w : U64x4) : m256 := Register.u8x32 (w.bv (·.bv))

@[simp] theorem u64x4_ofU64x4 (w : U64x4) : (ofU64x4 w).u64x4 = w := by
  simp [u64x4, ofU64x4, M256.u64x4, Register.u64x4, Register.u8x32]

@[simp] theorem ofU64x4_u64x4 (b : m256) : ofU64x4 b.u64x4 = b := by
  simp [u64x4, ofU64x4, M256.u64x4, Register.u64x4, Register.u8x32]

end m256

end Intrinsics.X86_64
