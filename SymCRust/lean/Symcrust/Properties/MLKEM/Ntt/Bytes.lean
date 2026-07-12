/-
  # Ntt/Bytes.lean — Step-specs for the byte-load helpers.

  `mlkem.ntt.load_u16_le` / `mlkem.ntt.load_u32_le` are pure little-endian
  byte-pump utilities used by the SampleNTT (Alg. 7) and SamplePolyCBD
  (Alg. 8) inner loops to read 2/4-byte chunks out of a SHAKE128/PRF
  byte stream.

  Each function chains `Slice.index { start := offset, end := offset + N }`
  → `TryFromArrayCopySlice.try_from` → `Result.unwrap` →
  `core.num.U{16,32}.from_le_bytes`.  The Aeneas core library already
  proves `from_le_bytes.step_spec` for both widths; we lift that into the
  little-endian *byte equation* form

      r.val = byte₀ + 256·byte₁                       (U16)
      r.val = byte₀ + 256·byte₁ + 65536·byte₂ + 2²⁴·byte₃   (U32)

  because every downstream caller pipes the result into `&&&` /
  `>>>` extractions where the byte equation is what `agrind` /
  `bv_decide` need.

  The specs discharge by `progress`-style stepping
  through `Slice.index_spec`, `try_from.step_spec`, `unwrap.step_spec`,
  and `from_le_bytes.step_spec`, then `simp`/`bv_decide` to extract
  byte arithmetic.
-/
import Symcrust.Properties.MLKEM.Basic.Params

open Aeneas Aeneas.Std Result
open symcrust

namespace Symcrust.Properties.MLKEM

/-- Helper for the `try_from` proof: cloning a list of `U8`s is identity. -/
private theorem List.mapM_clone_u8_ok' (l : List Std.U8) :
    List.mapM (liftFun1 core.clone.impls.CloneU8.clone) l = ok l := by
  have heq : (liftFun1 core.clone.impls.CloneU8.clone : Std.U8 → Result Std.U8)
           = fun x => ok x := by ext; rfl
  rw [heq]
  induction l with
  | nil => rfl
  | cons h t ih => simp only [List.mapM_cons, ih]; rfl

/-- Two-byte LE composition at the `BitVec` level. -/
private theorem fromLEBytes_two_toNat (b0 b1 : BitVec 8) :
    (BitVec.fromLEBytes [b0, b1]).toNat = b0.toNat + 256 * b1.toNat := by
  have h1 : (BitVec.fromLEBytes [b1] : BitVec (8 * 1)) = b1.setWidth 8 := by
    show (b1.setWidth (8 * [b1].length)
           ||| (BitVec.fromLEBytes []).setWidth (8 * [b1].length) <<< 8) = _
    simp [BitVec.fromLEBytes]
  have h2 : (BitVec.fromLEBytes [b0, b1] : BitVec (8 * 2))
          = b0.setWidth 16 ||| (b1.setWidth 16) <<< 8 := by
    show (b0.setWidth (8 * [b0, b1].length)
           ||| (BitVec.fromLEBytes [b1]).setWidth (8 * [b0, b1].length) <<< 8) = _
    rw [h1]; simp
  rw [h2]
  clear h1 h2
  have e0 : (BitVec.setWidth 16 b0).toNat = b0.toNat := by
    rw [BitVec.toNat_setWidth]; have := b0.isLt; scalar_tac
  have e1 : (BitVec.setWidth 16 b1 <<< 8).toNat = b1.toNat * 256 := by
    rw [BitVec.toNat_shiftLeft, BitVec.toNat_setWidth, Nat.shiftLeft_eq]
    have := b1.isLt
    rw [show (2 : Nat)^8 = 256 from rfl]
    rw [Nat.mod_eq_of_lt (by scalar_tac : b1.toNat < 2^16)]
    rw [Nat.mod_eq_of_lt (by scalar_tac : b1.toNat * 256 < 2^16)]
  rw [BitVec.toNat_or, e0, e1]
  have hb0 : b0.toNat < 2^8 := b0.isLt
  rw [show b1.toNat * 256 = b1.toNat <<< 8 by rw [Nat.shiftLeft_eq]]
  rw [Nat.lor_comm]
  rw [← Nat.shiftLeft_add_eq_or_of_lt hb0]
  rw [Nat.shiftLeft_eq, show (2 : Nat)^8 = 256 from rfl]
  ring

/-- Four-byte LE composition. -/
private theorem fromLEBytes_four_toNat (b0 b1 b2 b3 : BitVec 8) :
    (BitVec.fromLEBytes [b0, b1, b2, b3]).toNat
      = b0.toNat + 256 * b1.toNat + 65536 * b2.toNat + 16777216 * b3.toNat := by
  have h1 : (BitVec.fromLEBytes [b3] : BitVec (8 * 1)) = b3.setWidth 8 := by
    show (b3.setWidth (8 * [b3].length)
           ||| (BitVec.fromLEBytes []).setWidth (8 * [b3].length) <<< 8) = _
    simp [BitVec.fromLEBytes]
  have h2 : (BitVec.fromLEBytes [b2, b3] : BitVec (8 * 2))
          = b2.setWidth 16 ||| (b3.setWidth 16) <<< 8 := by
    show (b2.setWidth (8 * [b2, b3].length)
           ||| (BitVec.fromLEBytes [b3]).setWidth (8 * [b2, b3].length) <<< 8) = _
    rw [h1]; simp
  have h3 : (BitVec.fromLEBytes [b1, b2, b3] : BitVec (8 * 3))
          = b1.setWidth 24 ||| (b2.setWidth 24) <<< 8 ||| (b3.setWidth 24) <<< 16 := by
    show (b1.setWidth (8 * [b1, b2, b3].length)
           ||| (BitVec.fromLEBytes [b2, b3]).setWidth (8 * [b1, b2, b3].length) <<< 8) = _
    rw [h2]; simp; bv_decide
  have h4 : (BitVec.fromLEBytes [b0, b1, b2, b3] : BitVec (8 * 4))
          = b0.setWidth 32 ||| (b1.setWidth 32) <<< 8
            ||| (b2.setWidth 32) <<< 16 ||| (b3.setWidth 32) <<< 24 := by
    show (b0.setWidth (8 * [b0, b1, b2, b3].length)
           ||| (BitVec.fromLEBytes [b1, b2, b3]).setWidth (8 * [b0, b1, b2, b3].length) <<< 8) = _
    rw [h3]; simp; bv_decide
  rw [h4]
  clear h4 h3 h2 h1
  have e0 : (BitVec.setWidth 32 b0).toNat = b0.toNat := by
    rw [BitVec.toNat_setWidth]; have := b0.isLt; scalar_tac
  have e1 : (BitVec.setWidth 32 b1 <<< 8).toNat = b1.toNat * 256 := by
    rw [BitVec.toNat_shiftLeft, BitVec.toNat_setWidth, Nat.shiftLeft_eq]
    have := b1.isLt
    rw [show (2 : Nat)^8 = 256 from rfl]
    rw [Nat.mod_eq_of_lt (by scalar_tac : b1.toNat < 2^32)]
    rw [Nat.mod_eq_of_lt (by scalar_tac : b1.toNat * 256 < 2^32)]
  have e2 : (BitVec.setWidth 32 b2 <<< 16).toNat = b2.toNat * 65536 := by
    rw [BitVec.toNat_shiftLeft, BitVec.toNat_setWidth, Nat.shiftLeft_eq]
    have := b2.isLt
    rw [show (2 : Nat)^16 = 65536 from rfl]
    rw [Nat.mod_eq_of_lt (by scalar_tac : b2.toNat < 2^32)]
    rw [Nat.mod_eq_of_lt (by scalar_tac : b2.toNat * 65536 < 2^32)]
  have e3 : (BitVec.setWidth 32 b3 <<< 24).toNat = b3.toNat * 16777216 := by
    rw [BitVec.toNat_shiftLeft, BitVec.toNat_setWidth, Nat.shiftLeft_eq]
    have := b3.isLt
    rw [show (2 : Nat)^24 = 16777216 from rfl]
    rw [Nat.mod_eq_of_lt (by scalar_tac : b3.toNat < 2^32)]
    rw [Nat.mod_eq_of_lt (by scalar_tac : b3.toNat * 16777216 < 2^32)]
  rw [BitVec.toNat_or, BitVec.toNat_or, BitVec.toNat_or, e0, e1, e2, e3]
  have hb0 : b0.toNat < 2^8 := b0.isLt
  have hb1 : b1.toNat < 2^8 := b1.isLt
  have hb2 : b2.toNat < 2^8 := b2.isLt
  rw [show b1.toNat * 256 = b1.toNat <<< 8 by rw [Nat.shiftLeft_eq]]
  rw [show b2.toNat * 65536 = b2.toNat <<< 16 by rw [Nat.shiftLeft_eq]]
  rw [show b3.toNat * 16777216 = b3.toNat <<< 24 by rw [Nat.shiftLeft_eq]]
  rw [show b0.toNat = b0.toNat <<< 0 by rw [Nat.shiftLeft_zero]]
  rw [Nat.shiftLeft_zero]
  rw [Nat.lor_comm b0.toNat]
  rw [← Nat.shiftLeft_add_eq_or_of_lt hb0]
  rw [Nat.shiftLeft_eq, show (2 : Nat)^8 = 256 from rfl]
  rw [Nat.lor_comm _ (b2.toNat <<< 16)]
  rw [← Nat.shiftLeft_add_eq_or_of_lt (by
    have : b1.toNat * 256 + b0.toNat < 2^16 := by scalar_tac
    exact this)]
  rw [Nat.shiftLeft_eq, show (2 : Nat)^16 = 65536 from rfl]
  rw [Nat.lor_comm _ (b3.toNat <<< 24)]
  rw [← Nat.shiftLeft_add_eq_or_of_lt (by
    have : b2.toNat * 65536 + (b1.toNat * 256 + b0.toNat) < 2^24 := by scalar_tac
    exact this)]
  rw [Nat.shiftLeft_eq, show (2 : Nat)^24 = 16777216 from rfl]
  ring

/-! ## `load_u16_le` — read 2 little-endian bytes -/

/-- **Spec for `mlkem.ntt.load_u16_le`** — pure byte read; result is
the unsigned little-endian decoding of `pb_src[offset..offset+2]`.

Informal proof. The function body is
`Slice.index { start := offset, end := offset + 2 }` then
`<[U8;2]>::try_from(slice).unwrap()` then `U16::from_le_bytes`. Step
through with:
- `Slice.index_spec` (bounds `h_offset`) yields a sub-slice of length 2;
- `TryFromArrayCopySlice.try_from.step_spec` with length-2 witness
  produces `Ok(arr)` with `arr.val[i]! = pb_src.val[offset.val+i]!`;
- `Result.unwrap.step_spec` strips the `Ok`;
- `core.num.U16.from_le_bytes.step_spec` (in
  `Aeneas/Std/Scalar/CoreConvertNum.lean`) gives
  `r.bv = BitVec.fromLEBytes arr`. Unfolding `BitVec.fromLEBytes` for a
  length-2 array and converting `.bv` → `.val` produces the byte
  equation by `bv_decide` (or expanding `BitVec.toNat` of an explicit
  2-byte concatenation). -/
@[step]
theorem mlkem.ntt.load_u16_le.spec
    (pb_src : Slice U8) (offset : Usize)
    (h_offset : offset.val + 2 ≤ pb_src.length) :
    mlkem.ntt.load_u16_le pb_src offset
      ⦃ (r : U16) =>
          r.val = (pb_src.val[offset.val]'(by grind)).val +
                  256 * (pb_src.val[offset.val + 1]'(by grind)).val ⦄ := by
  unfold mlkem.ntt.load_u16_le
  step as ⟨i, hi⟩
  step as ⟨s, hs1, hs2⟩
  have hs_len : s.length = 2 := by scalar_tac
  have hmapM := List.mapM_clone_u8_ok' s.val
  simp only [core.array.TryFromArrayCopySlice.try_from,
    show s.length = (2#usize).val from by simp [hs_len],
    core.result.Result.unwrap, core.num.U16.from_le_bytes]
  simp only [↓reduceDIte]
  simp
  have hsv : s.val = [s.val[0]!, s.val[1]!] := by
    have h2 : s.val.length = 2 := hs_len
    match hs_decomp : s.val, h2 with
    | [_, _], _ => simp
  have h0 : s.val[0]! = pb_src.val[offset.val]! := by
    rw [hs1, hi]; simp [List.slice]
  have h1 : s.val[1]! = pb_src.val[offset.val + 1]! := by
    rw [hs1, hi]; simp [List.slice]
  show (BitVec.fromLEBytes (List.map U8.bv ↑s)).toNat = _
  rw [hsv]
  simp only [List.map_cons, List.map_nil]
  rw [fromLEBytes_two_toNat]
  rw [show (s.val[0]!).bv.toNat = s.val[0]!.val from rfl,
      show (s.val[1]!).bv.toNat = s.val[1]!.val from rfl, h0, h1]
  grind

/-! ## `load_u32_le` — read 4 little-endian bytes -/

/-- **Spec for `mlkem.ntt.load_u32_le`** — pure byte read; result is
the unsigned little-endian decoding of `pb_src[offset..offset+4]`.

Informal proof. Identical chain to `load_u16_le.spec` but with the
4-byte width: `Slice.index_spec` (bounds `h_offset`) →
`TryFromArrayCopySlice.try_from.step_spec` (length-4 array witness) →
`Result.unwrap.step_spec` → `core.num.U32.from_le_bytes.step_spec`,
yielding `r.bv = BitVec.fromLEBytes arr`. Expanding `BitVec.fromLEBytes`
for a 4-byte array and converting `.bv` → `.val` gives the byte
equation; `bv_decide` (or explicit `BitVec.toNat` over a 4-byte
concatenation) discharges the arithmetic. -/
@[step]
theorem mlkem.ntt.load_u32_le.spec
    (pb_src : Slice U8) (offset : Usize)
    (h_offset : offset.val + 4 ≤ pb_src.length) :
    mlkem.ntt.load_u32_le pb_src offset
      ⦃ (r : U32) =>
          r.val = (pb_src.val[offset.val]'(by grind)).val +
                  256 * (pb_src.val[offset.val + 1]'(by grind)).val +
                  65536 * (pb_src.val[offset.val + 2]'(by grind)).val +
                  16777216 * (pb_src.val[offset.val + 3]'(by grind)).val ⦄ := by
  unfold mlkem.ntt.load_u32_le
  step as ⟨i, hi⟩
  step as ⟨s, hs1, hs2⟩
  have hs_len : s.length = 4 := by scalar_tac
  have hmapM := List.mapM_clone_u8_ok' s.val
  simp only [core.array.TryFromArrayCopySlice.try_from,
    show s.length = (4#usize).val from by simp [hs_len],
    core.result.Result.unwrap, core.num.U32.from_le_bytes]
  simp only [↓reduceDIte]
  simp
  have hsv : s.val = [s.val[0]!, s.val[1]!, s.val[2]!, s.val[3]!] := by
    have h2 : s.val.length = 4 := hs_len
    match hs_decomp : s.val, h2 with
    | [_, _, _, _], _ => simp
  have h0 : s.val[0]! = pb_src.val[offset.val]! := by
    rw [hs1, hi]; simp [List.slice]
  have h1 : s.val[1]! = pb_src.val[offset.val + 1]! := by
    rw [hs1, hi]; simp [List.slice]
  have h2 : s.val[2]! = pb_src.val[offset.val + 2]! := by
    rw [hs1, hi]; simp [List.slice]
  have h3 : s.val[3]! = pb_src.val[offset.val + 3]! := by
    rw [hs1, hi]; simp [List.slice]
  show (BitVec.fromLEBytes (List.map U8.bv ↑s)).toNat = _
  rw [hsv]
  simp only [List.map_cons, List.map_nil]
  rw [fromLEBytes_four_toNat]
  rw [show (s.val[0]!).bv.toNat = s.val[0]!.val from rfl,
      show (s.val[1]!).bv.toNat = s.val[1]!.val from rfl,
      show (s.val[2]!).bv.toNat = s.val[2]!.val from rfl,
      show (s.val[3]!).bv.toNat = s.val[3]!.val from rfl,
      h0, h1, h2, h3]
  grind

end Symcrust.Properties.MLKEM
