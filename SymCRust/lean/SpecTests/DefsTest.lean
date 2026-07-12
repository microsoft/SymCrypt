import Spec.Defs

/-!
# Tests for Defs.lean — byte ↔ bit conversions

- `#guard` for fast unit tests.
- `#eval! show IO Unit from do` for speed benchmarks and larger round-trips.
-/

namespace Spec.DefsTest

open Spec
open Spec.Notations

/-! ## Unit tests (`#guard`) -/

-- Zero bytes → zero bits → zero bytes
#guard bytesToBits (Vector.replicate 0 (0 : Byte)) = Vector.replicate 0 false
#guard bitsToBytes (Vector.replicate 0 false) = Vector.replicate 0 (0 : Byte)

-- Single byte: 0x00
#guard bytesToBits (⟨⟨[0]⟩, rfl⟩ : 𝔹 1) = Vector.replicate 8 false

-- Single byte: 0x01 = bit 0 set (LSB first)
#guard (bytesToBits (⟨⟨[1]⟩, rfl⟩ : 𝔹 1))[0] = true
#guard (bytesToBits (⟨⟨[1]⟩, rfl⟩ : 𝔹 1))[1] = false

-- Single byte: 0x80 = bit 7 set
#guard (bytesToBits (⟨⟨[0x80]⟩, rfl⟩ : 𝔹 1))[7] = true
#guard (bytesToBits (⟨⟨[0x80]⟩, rfl⟩ : 𝔹 1))[0] = false

-- Single byte: 0xFF = all bits set
#guard bytesToBits (⟨⟨[0xFF]⟩, rfl⟩ : 𝔹 1) = Vector.replicate 8 true

-- Round-trip: bytesToBits ∘ bitsToBytes = id (small)
#guard
  let b : Vector Bool (8 * 2) :=
    ⟨⟨[false, true, false, true, false, false, false, false,
      true, false, false, false, false, false, false, false]⟩, by simp⟩
  bytesToBits (bitsToBytes b) = b

-- Round-trip: bitsToBytes ∘ bytesToBits = id (small)
#guard
  let B : 𝔹 2 := ⟨⟨[0x0A, 0x01]⟩, rfl⟩
  bitsToBytes (bytesToBits B) = B

-- Round-trip on all-zeros (4 bytes)
#guard bitsToBytes (bytesToBits (Vector.replicate 4 (0 : Byte))) = Vector.replicate 4 (0 : Byte)

-- Round-trip on all-0xFF (4 bytes)
#guard bitsToBytes (bytesToBits (Vector.replicate 4 (0xFF : Byte))) = Vector.replicate 4 (0xFF : Byte)

-- bytesToBits agrees with bytesToBits_alg4 (small)
#guard
  let B : 𝔹 3 := ⟨⟨[0xAB, 0xCD, 0xEF]⟩, rfl⟩
  bytesToBits B = bytesToBits_alg4 B

/-! ## Speed benchmarks (`#eval!`) -/

#eval! show IO Unit from do
  IO.println "=== Defs.lean byte↔bit conversion tests ==="

  -- Round-trip: bytesToBits (bitsToBytes b) = b for a pattern vector
  let t0 ← IO.monoMsNow
  let n := 1024
  let b : Vector Bool (8 * n) := Vector.ofFn fun ⟨i, _⟩ => i % 3 == 0
  let rt := bytesToBits (bitsToBytes b)
  assert! rt == b
  let t1 ← IO.monoMsNow
  IO.println s!"  bitsToBytes→bytesToBits round-trip ({n} bytes): {t1 - t0} ms"

  -- Round-trip: bitsToBytes (bytesToBits B) = B for sequential bytes
  let t0 ← IO.monoMsNow
  let B : 𝔹 1024 := Vector.ofFn fun ⟨i, _⟩ => (i : Byte)
  let rt := bitsToBytes (bytesToBits B)
  assert! rt == B
  let t1 ← IO.monoMsNow
  IO.println s!"  bytesToBits→bitsToBytes round-trip ({n} bytes): {t1 - t0} ms"

  -- bytesToBits vs bytesToBits_alg4 agreement on larger input
  let t0 ← IO.monoMsNow
  let B : 𝔹 256 := Vector.ofFn fun ⟨i, _⟩ => (i : Byte)
  assert! bytesToBits B == bytesToBits_alg4 B
  let t1 ← IO.monoMsNow
  IO.println s!"  bytesToBits vs bytesToBits_alg4 agreement (256 bytes): {t1 - t0} ms"

  -- Speed: bitsToBytes on large input
  let t0 ← IO.monoMsNow
  let bits : Vector Bool (8 * 4096) := Vector.ofFn fun ⟨i, _⟩ => i % 2 == 0
  let _bytes := bitsToBytes bits
  let t1 ← IO.monoMsNow
  IO.println s!"  bitsToBytes (4096 bytes): {t1 - t0} ms"

  -- Speed: bytesToBits on large input
  let t0 ← IO.monoMsNow
  let bytes : 𝔹 4096 := Vector.ofFn fun ⟨i, _⟩ => (i : Byte)
  let _bits := bytesToBits bytes
  let t1 ← IO.monoMsNow
  IO.println s!"  bytesToBits (4096 bytes): {t1 - t0} ms"

end Spec.DefsTest
