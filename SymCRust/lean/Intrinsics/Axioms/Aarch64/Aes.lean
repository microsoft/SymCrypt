/-
  Silicon axioms for the Armv8-A AES round intrinsics used by
  `src/aes/aes_neon.rs`.

  ## Sources of truth
  Arm ARM (DDI 0487 K.a, March 2024) §C7.2 (`AESE`, `AESD`, `AESMC`, `AESIMC`);
  FIPS-197 §5. Shims: `src/verify/intrinsics/aarch64/{aes,neon}.rs`. Differential
  test: `tests/aarch64_aes_hw.rs`.

  ## Trust ledger
  Axioms for the silicon AES round instructions:
  - `vaeseq_u8`, `vaesdq_u8`, `vaesmcq_u8`, `vaesimcq_u8`.

  Their `.spec` siblings and the generic NEON specs are in
  `Intrinsics/Properties/Aarch64/Aes.lean`.
-/
import Aeneas
import Intrinsics.Axioms.Aarch64.Common
import Intrinsics.Axioms.Aarch64.Neon
import Spec.AES.Spec
import Spec.AES.ArrayBridge

open Aeneas Aeneas.Std Result Spec
open core.core_arch.arm_shared.neon
open core.core_arch.arm_shared.neon.uint8x16_t

/-! ## Silicon AES round instructions

The axiom + `.spec` sibling for each AES round intrinsic are co-located here (the
specs are FIPS-197-shaped). Generic NEON intrinsics keep their axioms in
`Intrinsics/Axioms/Aarch64/Neon.lean`. -/

/-- `vaesdq_u8`: one Armv8 AES decryption round — `XOR(state,key)` THEN
    `InvShiftRows ∘ InvSubBytes` (XOR first, opposite of Intel AES-NI).
    Arm ARM §C7.2 `AESD`, FIPS-197 §5.3. -/
@[rust_fun "core::core_arch::arm_shared::neon::generated::vaesdq_u8"]
axiom core.core_arch.arm_shared.neon.generated.vaesdq_u8
  :
  uint8x16_t →
    uint8x16_t → Result
    uint8x16_t

/-- `vaeseq_u8`: one Armv8 AES encryption round — `XOR(state,key)` THEN
    `ShiftRows ∘ SubBytes` (XOR first; the `aes_neon.rs` driver treats
    `round_keys[0]` as initial whitening). Arm ARM §C7.2 `AESE`, FIPS-197 §5.1. -/
@[rust_fun "core::core_arch::arm_shared::neon::generated::vaeseq_u8"]
axiom core.core_arch.arm_shared.neon.generated.vaeseq_u8
  :
  uint8x16_t →
    uint8x16_t → Result
    uint8x16_t

/-- `vaesimcq_u8`: AES InvMixColumns of a `uint8x16_t` state.
    Arm ARM §C7.2 `AESIMC`, FIPS-197 §5.3. -/
@[rust_fun "core::core_arch::arm_shared::neon::generated::vaesimcq_u8"]
axiom core.core_arch.arm_shared.neon.generated.vaesimcq_u8
  :
  uint8x16_t → Result
    uint8x16_t

/-- `vaesmcq_u8`: AES MixColumns of a `uint8x16_t` state.
    Arm ARM §C7.2 `AESMC`, FIPS-197 §5.1. -/
@[rust_fun "core::core_arch::arm_shared::neon::generated::vaesmcq_u8"]
axiom core.core_arch.arm_shared.neon.generated.vaesmcq_u8
  :
  uint8x16_t → Result
    uint8x16_t

namespace symcrust.aesgcm

/-! ## Bridge: NEON register ↔ AES block

`neonToAesBlock` interprets a `uint8x16_t` as a spec `AES.Block` (per-byte
`Std.U8 → Byte`), with bijective inverse `aesBlockToNeon` and round-trip
`@[simp]` lemmas. -/

/-- Interpret a NEON `uint8x16_t` as a spec `AES.Block` (per-byte `(·.bv)`).
    Lane `i` = byte `i` of the little-endian representation (Arm ARM §B2.2). -/
def neonToAesBlock (a : uint8x16_t) : AES.Block := a.map (·.bv)

/-- Construct a NEON `uint8x16_t` from a spec `AES.Block` (per-byte inverse). -/
def aesBlockToNeon (b : AES.Block) : uint8x16_t := b.map (Std.UScalar.mk (ty := .U8))

/-- Round-trip: `neonToAesBlock ∘ aesBlockToNeon = id`. -/
@[simp]
theorem neonToAesBlock_aesBlockToNeon (b : AES.Block) :
  neonToAesBlock (aesBlockToNeon b) = b := by
  apply Vector.ext; intro i hi
  simp only [neonToAesBlock, aesBlockToNeon, Vector.getElem_map]

/-- Round-trip: `aesBlockToNeon ∘ neonToAesBlock = id`. -/
@[simp]
theorem aesBlockToNeon_neonToAesBlock (a : uint8x16_t) :
  aesBlockToNeon (neonToAesBlock a) = a := by
  apply Vector.ext; intro i hi
  simp only [neonToAesBlock, aesBlockToNeon, Vector.getElem_map]

/-! ### Phase-B bridge: `neonToAesBlock` factored through the `u8x16` lane view

Both `AES.Block` and the NEON `u8x16` view are byte-indexed in the same
little-endian order, so `neonToAesBlock` factors through `u8x16` via
`Std.U8 → Byte = (·.bv)`. -/

/-- Reinterpret a `Vector Std.U8 16` (NEON lane view) as a spec `AES.Block`. -/
def u8x16ToAesBlock (v : Vector Std.U8 16) : AES.Block :=
  v.map (·.bv)

/-- Reinterpret a spec `AES.Block` as a `Vector Std.U8 16`. -/
def aesBlockToU8x16 (b : AES.Block) : Vector Std.U8 16 :=
  b.map (Std.UScalar.mk (ty := .U8))

@[simp]
theorem u8x16ToAesBlock_aesBlockToU8x16 (b : AES.Block) :
    u8x16ToAesBlock (aesBlockToU8x16 b) = b := by
  apply Vector.ext; intro i hi
  simp only [u8x16ToAesBlock, aesBlockToU8x16, Vector.getElem_map]

@[simp]
theorem aesBlockToU8x16_u8x16ToAesBlock (v : Vector Std.U8 16) :
    aesBlockToU8x16 (u8x16ToAesBlock v) = v := by
  apply Vector.ext; intro i hi
  simp only [u8x16ToAesBlock, aesBlockToU8x16, Vector.getElem_map]

/-- `neonToAesBlock` factors through the `u8x16` lane view.  Now a theorem
    (`u8x16` is the identity on the concrete `uint8x16_t`). -/
@[simp]
theorem neonToAesBlock_via_u8x16 (a : uint8x16_t) :
  neonToAesBlock a = u8x16ToAesBlock a.u8x16 := by
  simp only [neonToAesBlock, u8x16ToAesBlock,
    core.core_arch.arm_shared.neon.uint8x16_t.u8x16]

/-- Derived: the `u8x16` view of a register equals `aesBlockToU8x16` of its
    `AES.Block` view. -/
theorem u8x16_eq_aesBlockToU8x16_neonToAesBlock (a : uint8x16_t) :
    a.u8x16 = aesBlockToU8x16 (neonToAesBlock a) := by
  rw [neonToAesBlock_via_u8x16, aesBlockToU8x16_u8x16ToAesBlock]

end symcrust.aesgcm
