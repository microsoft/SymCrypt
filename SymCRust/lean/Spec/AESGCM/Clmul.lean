/-
  Spec/AESGCM/Clmul.lean — Carry-less 64×64 → 128-bit multiplication over GF(2)[X].

  The silicon primitive underlying every GHASH leaf: Intel SDM Vol.2B
  `PCLMULQDQ`, Arm ARM `PMULL`.  This file defines `clmul64` as a pure
  Lean function and the trivial helper to split a 128-bit product into
  two 64-bit lanes.

  ## Bit ordering

  We use LSB-first BitVec semantics for the multiplier: bit `i` of `b`
  multiplies `a` shifted left by `i` (carry-less, i.e. XOR-accumulated
  rather than addition-with-carry).  This matches Intel SDM "Operation:"
  pseudocode and Arm ARM PMULL pseudocode under the standard LSB-first
  interpretation of register contents.

  The top bit of the result is always 0 (since the maximum degree of
  the product of two degree-63 polynomials is `63 + 63 = 126 < 127`),
  so the spec is stated as `BitVec 128` for convenience of downstream
  XOR aggregation but the high bit (bit 127) is identically zero.

  Trust basis is the differential test
  `tests/x86_64_pclmulqdq_hw.rs::clmulepi64_silicon_matches_transcription_all_imm`.
-/
import Spec.Defs

namespace Spec.AESGCM

/-- Carry-less 64×64 → 128-bit multiplication over GF(2)[X].

    `clmul64 a b = XOR_{i ∈ [0..64), b.getLsbD i} (a.zeroExtend 128 <<< i)`.

    Equivalent to the polynomial product `a(x) · b(x)` over GF(2),
    where the coefficients of `a` and `b` are read LSB-first (bit 0 ↦
    coefficient of `x^0`).

    Note: the top bit of `clmul64 a b` is always zero, since the maximum
    degree of the product of two degree-63 polynomials is `63 + 63 =
    126 < 127`.  A proof of `(clmul64 a b).getLsbD 127 = false` would
    induct on the `Fin.foldl`; it is not needed by GCM at this stage. -/
def clmul64 (a b : BitVec 64) : BitVec 128 :=
  Fin.foldl 64 (fun acc i =>
    if b.getLsbD i.val then
      acc ^^^ ((a.zeroExtend 128) <<< i.val)
    else acc) 0#128

end Spec.AESGCM
