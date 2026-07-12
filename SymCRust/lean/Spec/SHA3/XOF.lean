import Spec.SHA3.Spec

set_option grind.warning false

namespace Spec.SHA3

open Spec (𝔹 slice Bits.zeroExtend bytesToBits bitsToBytes)
open scoped Spec.Notations

/-!
# Incremental Sponge API

This file defines an incremental (streaming) sponge API: `init → absorb → squeeze*`.
This is **not** a formalization of any NIST standard — FIPS 202 only defines the
functional sponge (Algorithm 8). The incremental API models the software implementation
pattern used by the Rust `KeccakState` (with `state_index` and `squeeze_mode`), and
serves as a bridge specification for proving that the streaming implementation matches
the functional `SPONGE` from `SHA3New.lean`.

The top-level SHAKE functions operate on `𝔹 n` (byte vectors), converting to/from
bit vectors internally via `bytesToBits`/`bitsToBytes`. The generic incremental
primitives operate on bits.
-/

section Sponge -- generic sponge construction

namespace Incremental

variable
  -- algorithm
  (f   : Vector Bool b → Vector Bool b)
  (r   : Nat)  -- rate: number of bits added/squeezed at a time
  (hr  : 0 < r ∧ r < b := by decide)

structure sponge.state where
  S   : Vector Bool b        -- permutation internal state
  Z   : Array Bool           -- bits already squeezed, excluding Trunc r S
  x   : Nat                  -- number of bits already returned
  hx  : x ≤ Z.size + r

def sponge.init : sponge.state r := {
  S := .replicate b false,
  Z := #[],
  x := 0,
  hx := by omega }

/-- Pad and absorb a bit vector. Reuses `SPONGE.absorb` from SHA3New. -/
def sponge.absorb1 {n} (s : state r) (N : Vector Bool n) : state r :=
  let P := N ‖ «pad10*1» r n
  let S := SPONGE.absorb f r P (padLen_dvd r n)
  { s with S }

/-- Squeeze r extra bits using `SPONGE.squeeze_step` from SHA3New. -/
def sponge.squeeze_r (s : state r) :=
  let (block, S) := SPONGE.squeeze_step f r s.S
  let Z := s.Z ++ block.toArray
  have hx : s.x ≤ Z.size + r := le_trans s.hx (by grind)
  { s with Z, S, hx }

/-- Squeeze d bits on demand, permuting only when the buffer is exhausted. -/
def sponge.squeeze1 (s : state r) d : state r × Vector Bool d :=
  if hd : s.Z.size + r < s.x + d then
    squeeze1 (squeeze_r f r hr s) d
  else
    let A := s.Z ++ (Trunc r s.S).toArray
    let D : Vector Bool d := (A.extract s.x (s.x + d)).toVector.cast (by grind)
    have hx : s.x + d ≤ s.Z.size + r := by grind
    ({ s with x := s.x + d, hx}, D)
  termination_by s.x + d - (s.Z.size + r)
  decreasing_by
    unfold squeeze_r
    simp [SPONGE.squeeze_step]
    grind

private lemma size_extract (A : Array α) {i size} (hsize : i + size ≤ A.size) :
  (A.extract i (i+size)).size = size := by
  let B := A.extract i (i+size)
  have hB: B.size = min (i + size) A.size - min i A.size := by
    grind [Array.extract]
  grind

/-- Simplified squeeze when enough bits are buffered (no permutation needed). -/
def sponge.lookup (s : state r) m (hm : s.x + m ≤ s.Z.size := by grind) : state r × Vector Bool m :=
  let s' := { s with x := s.x + m, hx := by grind }
  let B := s.Z.extract s.x (s.x + m)
  (s', B.toVector.cast (size_extract s.Z hm))

end Incremental

end Sponge

/-! ## Incremental API for SHAKE128 and SHAKE256

Top-level functions operate on `𝔹 n` (byte vectors). Internal state uses bits. -/

def SHAKE128.init := Incremental.sponge.init (r := b - 256)
def SHAKE256.init := Incremental.sponge.init (r := b - 512)

def SHAKE128.absorb {n} (s : Incremental.sponge.state (b - 256)) (msg : 𝔹 n) :=
  Incremental.sponge.absorb1 KECCAK_f (r := b - 256) (hr := by decide) s (bytesToBits msg ‖ xofSuffix)

def SHAKE256.absorb {n} (s : Incremental.sponge.state (b - 512)) (msg : 𝔹 n) :=
  Incremental.sponge.absorb1 KECCAK_f (r := b - 512) (hr := by decide) s (bytesToBits msg ‖ xofSuffix)

def SHAKE128.squeeze (s : Incremental.sponge.state (b - 256)) (outBytes : Nat) :=
  let (s, bits) := Incremental.sponge.squeeze1 KECCAK_f (r := b - 256) (hr := by decide) s (8 * outBytes)
  (s, bitsToBytes bits)

def SHAKE256.squeeze (s : Incremental.sponge.state (b - 512)) (outBytes : Nat) :=
  let (s, bits) := Incremental.sponge.squeeze1 KECCAK_f (r := b - 512) (hr := by decide) s (8 * outBytes)
  (s, bitsToBytes bits)

end Spec.SHA3
