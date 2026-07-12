/-
  # Bridges/EncodingStreamDecompress.lean — Stream intermediate for
  decode+decompress.

  Split from `EncodingStream.lean` so that the compress and decompress
  halves elaborate in parallel.  See `EncodingStreamCompress.lean` for
  the compress+encode side.
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.Encoding

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open Symcrust

namespace Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 1000000

/-! ## Decompress-side stream state and step function -/

/-- Streaming state of `poly_element_decode_and_decompress`.

The decode direction is the inverse of compress-encode: instead of
ingesting coefficients and flushing bytes, the stream ingests `4`-byte
words from `src`, refills the 32-bit accumulator, and emits one
`d`-bit chunk per coefficient (whose `Decompress_d` then writes one
polynomial coefficient).

Fields:
* `dst` — output polynomial; growing partial vector of `Nat` values
  (each `< m d`).  Modelled as `List ℕ` so that prefix updates are
  free.
* `pi` — next coefficient index to write (`0 ≤ pi ≤ 256`).
* `acc` — 32-bit shift register holding `acci` LSB-justified bits
  read from `src` but not yet consumed.
* `acci` — bit count in `acc`, in `[0, 32]`.
* `src` — full source byte list (NOT consumed mutably; the read
  cursor is `si`).
* `si` — next read index into `src` (always a multiple of 4 between
  refills). -/
structure DecodeDecompressState where
  dst : List ℕ
  pi : ℕ
  acc : BitVec 32
  acci : ℕ
  src : List Byte
  si : ℕ
  deriving Repr

/-! ### Bit-extraction helper (used by `DecodeDecompressState.matchesRuntime`
and decode-side FIPS bridges) -/

/-- Bit `n` of the source byte stream: byte `n / 8`, bit `n % 8`.
Uses `getD` to keep the definition free of bound proofs. -/
def srcBit (src : List Byte) (n : ℕ) : Bool :=
  (src.getD (n / 8) 0#8).getLsbD (n % 8)

namespace DecodeDecompressState

/-- Initial decoder state for source buffer `src` (length `32 * d`):
empty output, zero accumulator, read cursor at zero.  The `d`
parameter is kept for API symmetry with `CompressEncodeState.init`
even though `src` already determines the buffer length. -/
def init (_d : ℕ) (src : List Byte) : DecodeDecompressState :=
  { dst := List.replicate 256 (0 : ℕ),
    pi := 0,
    acc := 0#32,
    acci := 0,
    src := src,
    si := 0 }

/-- Read 4 little-endian bytes from `s.src[s.si..s.si+4]` as a
`BitVec 32`.  Used by `refill`. -/
def loadLEWord (src : List Byte) (si : ℕ) : BitVec 32 :=
  let b0 : BitVec 32 := BitVec.setWidth 32 (src.getD si       0#8)
  let b1 : BitVec 32 := BitVec.setWidth 32 (src.getD (si + 1) 0#8)
  let b2 : BitVec 32 := BitVec.setWidth 32 (src.getD (si + 2) 0#8)
  let b3 : BitVec 32 := BitVec.setWidth 32 (src.getD (si + 3) 0#8)
  b0 ||| (b1 <<< (8 : ℕ)) ||| (b2 <<< (16 : ℕ)) ||| (b3 <<< (24 : ℕ))

/-- One-coefficient emit step.

Effect (mirrors the inner-loop body `poly_element_decode_and_decompress_loop0`
followed by the `fastDecompress` wrapper):

1. While `s.acci < d`: refill — read 4 LE bytes from
   `s.src[s.si..s.si+4]` into the high `32 - s.acci` bits of `s.acc`;
   advance `si` by 4; advance `acci` by 32 (capped at 32).
   In practice the Rust code refills *at most once* per call because
   `d ≤ 12 < 32`, so an `acci < d` accumulator is at most `d - 1 <
   32` bits short; one 32-bit refill is enough.
2. Extract `d` LSBs from `s.acc`: `v := s.acc.toNat &&& ((1 <<< d) - 1)`.
3. Write `fastDecompress d v` (which equals `(MLKEM.Decompress d v).val`
   via `fastDecompress_eq_spec_decompress`) to `s.dst[s.pi]`.
4. Drain: `s.acc' := s.acc >>> d`, `s.acci' := s.acci - d`,
   `s.pi' := s.pi + 1`. -/
def body (d : ℕ) (s : DecodeDecompressState) : DecodeDecompressState :=
  if s.acci < d then
    -- Refill arm: drain `s.acci` old low bits, refill with a fresh 4-byte
    -- load, then drain `d - s.acci` more bits from the load.  This
    -- faithfully mirrors the Rust inner loop (`Funs.lean:3555–3593`),
    -- which drains acc to 0 *before* the refill so the new accumulator
    -- equals the load itself — preserving all 32 fresh bits.  The
    -- previous shape `s.acc ||| (load <<< s.acci)` silently lost the
    -- top `s.acci` bits of `load` through BitVec-32 truncation; this
    -- shape avoids that bug by computing the post-drain accumulator
    -- directly as `load >>> (d - s.acci)`.
    let load := DecodeDecompressState.loadLEWord s.src s.si
    let v_low  : ℕ := s.acc.toNat &&& ((1 <<< s.acci) - 1)
    let v_high : ℕ := load.toNat  &&& ((1 <<< (d - s.acci)) - 1)
    let v : ℕ := v_low ||| (v_high <<< s.acci)
    -- For d < 12 we decompress via the fast formula; at d = 12 the
    -- decompression is the identity (m 12 = q) and `v` itself is the
    -- canonical representative.
    let y : ℕ := if d < 12 then fastDecompress d v else v
    { dst := s.dst.set s.pi y,
      pi := s.pi + 1,
      acc := load >>> (d - s.acci),
      acci := s.acci + 32 - d,
      src := s.src,
      si := s.si + 4 }
  else
    -- No-refill arm: drain `d` bits directly from `s.acc`.
    let v : ℕ := s.acc.toNat &&& ((1 <<< d) - 1)
    let y : ℕ := if d < 12 then fastDecompress d v else v
    { dst := s.dst.set s.pi y,
      pi := s.pi + 1,
      acc := s.acc >>> d,
      acci := s.acci - d,
      src := s.src,
      si := s.si }

/-- Fold `body` `n` times. -/
def recBody (d : ℕ) (s : DecodeDecompressState) (n : ℕ) :
    DecodeDecompressState :=
  (List.range n).foldl (fun s' _ => body d s') s

/-- Structural length invariant on the decoder state.  After emitting
`i` coefficients: read cursor and accumulator bit-count satisfy
`8 * si = i * d + acci`, the source length is at least `32 * d`
(so the per-poly function can be called on a longer `pb_src` slice in
the vector loop; `init`/`init_padded` constructors both satisfy `≥` and
`body` never changes `s.src.length`), the partial output has length 256
with the first `i` coefficients written. -/
def length_inv (d : ℕ) (s : DecodeDecompressState) (i : ℕ) : Prop :=
  32 * d ≤ s.src.length ∧ s.dst.length = 256 ∧ i ≤ 256 ∧
  s.pi = i ∧
  8 * s.si = i * d + s.acci ∧
  s.acci ≤ 31

/-- Runtime ↔ Stream correspondence for the decode loop.

Says: the abstract decoder state `s` faithfully captures the runtime
`(pe_dst, accumulator, n_bits_in_accumulator, pb_src, cb_src_consumed)` —
that is, the partially-written output array, the bit-pump accumulator
state, and the source-read cursor.

* `s.src` equals the bytewise `.bv` view of `pb_src`;
* `s.si = cb_src_consumed.val`;
* `s.acc` equals the runtime accumulator (`acc` U32) as a `BitVec 32`;
  the high `32 - s.acci` bits of `s.acc` are zero (loop invariant —
  drains by `>>> d` keep this);
* `s.acci = n_bits_in_accumulator.val`;
* `s.pi` coefficient slots of `pe_dst` have been written; their
  `Nat` values match `s.dst[0..s.pi]`. -/
def matchesRuntime (d : ℕ)
    (s : DecodeDecompressState) (pe_dst : PolyElement)
    (acc n_bits_in_accumulator : U32)
    (pb_src : Slice U8) (cb_src_consumed : Usize) : Prop :=
  /- Source-length conjunct: `s.src.length = 32 * d` so the per-poly
     spec can be invoked on a longer remainder of `pb_src` in the
     vector loop.  The runtime only reads bytes from `pb_src[0 .. 32*d)`
     (loop terminates at `s.pi = 256`, having consumed exactly `32 * d`
     bytes); the byte-equality conjunct below covers exactly that
     window. -/
  s.src.length = 32 * d ∧
  (∀ k : ℕ, k < 32 * d →
      s.src.getD k 0#8 = (pb_src.val.getD k 0#u8).bv) ∧
  s.si = cb_src_consumed.val ∧
  cb_src_consumed.val ≤ pb_src.length ∧
  s.acci = n_bits_in_accumulator.val ∧
  n_bits_in_accumulator.val ≤ 32 ∧
  s.acc = BitVec.ofNat 32 acc.val ∧
  /- Bit-conservation: `8 * s.si` bits have been read from `src`; of
     these, `s.acci` are still in `s.acc`, and `s.pi * d` have been
     consumed into emitted coefficients.  Required to derive `acc_match`
     downstream from `loadLEWord_getLsbD`. -/
  8 * s.si = s.pi * d + s.acci ∧
  /- High bits of the accumulator above `s.acci` are 0 (loop invariant
     — drains by `>>> d` preserve this). -/
  (∀ (j : ℕ), s.acci ≤ j → ¬ s.acc.getLsbD j) ∧
  /- Acc low bits match the next FIPS source bits.  Pinned via
     bit-conservation: `8 * s.si - s.acci = d * s.pi`, so bits
     `[d * s.pi, d * s.pi + s.acci)` of `src` live at positions
     `[0, s.acci)` of `s.acc`.  Mirrors `streamDecodeDecompressPartial`'s
     `acc_match` conjunct.  Needed by the d=12 OK arm to derive
     `fipsBitSum d s.src s.pi = coefficient.val` from the runtime
     `coefficient < Q` check. -/
  (∀ (j : ℕ), j < s.acci → s.acc.getLsbD j = srcBit s.src (d * s.pi + j)) ∧
  s.dst.length = 256 ∧
  (∀ k : ℕ, k < s.pi →
      s.dst.getD k 0 = (pe_dst.val.getD k 0#u16).val)

/-! ### Structural preservation lemmas for `body` / `recBody` (decode side)

Symmetric to the compress-side helpers above; expert-mandated
"body preserves invariant" decomposition for the decode pipeline. -/

/-- `body` preserves `length_inv` (decode side). -/
theorem body_length_inv (d : ℕ) (s : DecodeDecompressState) (i : ℕ)
    (h_d : 1 ≤ d ∧ d ≤ 12) (h_i : i < 256)
    (h_inv : length_inv d s i) :
    length_inv d (body d s) (i + 1) := by
  unfold body length_inv
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := h_inv
  by_cases h_refill : s.acci < d
  · rw [if_pos h_refill]
    dsimp only
    have h_sub : s.acci + 32 - d + d = s.acci + 32 := by omega
    refine ⟨h1, ?_, by omega, by omega, ?_, by omega⟩
    · rw [List.length_set]; exact h2
    · -- 8 * (s.si + 4) = (i + 1) * d + (s.acci + 32 - d)
      have : (i + 1) * d + (s.acci + 32 - d) = i * d + (s.acci + 32 - d + d) := by ring
      rw [this, h_sub]; omega
  · rw [if_neg h_refill]
    dsimp only
    have h_sub : s.acci - d + d = s.acci := by omega
    refine ⟨h1, ?_, by omega, by omega, ?_, by omega⟩
    · rw [List.length_set]; exact h2
    · -- 8 * s.si = (i + 1) * d + (s.acci - d)
      have : (i + 1) * d + (s.acci - d) = i * d + (s.acci - d + d) := by ring
      rw [this, h_sub]; exact h5

/-- `body` preserves the high-bits-zero invariant on the decoder's `acc`. -/
theorem body_high_bits_zero (d : ℕ) (s : DecodeDecompressState)
    (_h_d : 1 ≤ d ∧ d ≤ 12)
    (_h_acci : s.acci ≤ 32)
    (h_zero : ∀ j, s.acci ≤ j → ¬ s.acc.getLsbD j) :
    ∀ j, (body d s).acci ≤ j → ¬ (body d s).acc.getLsbD j := by
  intros j hj
  unfold body at hj ⊢
  by_cases h_refill : s.acci < d
  · -- Refill arm: new acc = load >>> (d - s.acci), new acci = s.acci + 32 - d.
    rw [if_pos h_refill] at hj ⊢
    dsimp only at hj ⊢
    -- hj : s.acci + 32 - d ≤ j; goal: ¬ (load >>> (d - s.acci)).getLsbD j.
    rw [BitVec.getLsbD_ushiftRight]
    -- Bit at position (d - s.acci + j) of load (BitVec 32): is ≥ 32 since
    -- d - s.acci + j ≥ d - s.acci + (s.acci + 32 - d) = 32.
    rw [BitVec.getLsbD_of_ge _ _ (by omega : 32 ≤ d - s.acci + j)]
    decide
  · -- No-refill arm: new acc = s.acc >>> d, new acci = s.acci - d.
    rw [if_neg h_refill] at hj ⊢
    dsimp only at hj ⊢
    -- hj : s.acci - d ≤ j; goal: ¬ (s.acc >>> d).getLsbD j.
    rw [BitVec.getLsbD_ushiftRight]
    -- Need: ¬ s.acc.getLsbD (d + j).  Since s.acci ≤ d + j (from h_acci, h_refill, hj).
    simpa using h_zero (d + j) (by omega)

/-- `recBody` preserves both invariants over `n` decoder steps. -/
theorem recBody_length_inv (d : ℕ) (s : DecodeDecompressState) (n i : ℕ)
    (h_d : 1 ≤ d ∧ d ≤ 12) (h_bound : i + n ≤ 256)
    (h_inv : length_inv d s i) :
    length_inv d (recBody d s n) (i + n) := by
  induction n generalizing s i with
  | zero => simpa [recBody] using h_inv
  | succ n ih =>
    have h_step_n : length_inv d (recBody d s n) (i + n) := by
      have h_bound' : i + n ≤ 256 := by grind
      exact ih (s := s) (i := i) h_bound' h_inv
    have h_i_n : i + n < 256 := by grind
    have h_body :
        length_inv d (body d (recBody d s n)) ((i + n) + 1) :=
      body_length_inv d (recBody d s n) (i + n) h_d h_i_n h_step_n
    have h_unfold : recBody d s (n + 1) = body d (recBody d s n) := by
      simp [recBody, List.range_succ, List.foldl_append]
    have h_idx : i + (n + 1) = (i + n) + 1 := by grind
    rw [h_unfold, h_idx]
    exact h_body

end DecodeDecompressState

/-! ### Cross-bridge: Rust `decodeDecompressBitsInv` ↔ Stream invariants (decode side)

Symmetric to the compress-side cross-bridge.  `decodeDecompressBitsInv`
(defined in `Bridges/Encoding.lean`, parameterized by the list of
emitted coefficients `coeffs_emitted`) is the loop invariant the outer
decode loop uses.  These bridges let Stream's body preservation
(`body_length_inv`, `body_high_bits_zero`, `recBody_*`) feed back into
a Rust BitsInv at the next iteration. -/


/-- **Reverse bridge (decode side, per-step).**  Given Stream invariants
at the new state `body d s_in` and the Rust body's outputs (refill +
drain + write), conclude `decodeDecompressBitsInv` at the next
coefficient. -/
theorem decodeDecompressBitsInv_of_stream_step
    (d : ℕ) (coeffs_emitted : List ℕ) (pb_src : Slice U8)
    (cb_src_read cb_src_read' : Usize)
    (accumulator accumulator' n_bia n_bia' : U32)
    (v : ℕ)
    (_h_d : 1 ≤ d ∧ d ≤ 12)
    (_h_count : coeffs_emitted.length + 1 ≤ 256)
    /- Old BitsInv (threads the per-coefficient content tie). -/
    (h_inv_old : decodeDecompressBitsInv d pb_src coeffs_emitted
                   cb_src_read.val accumulator.val n_bia.val)
    /- Bit-conservation at new state: -/
    (h_cons : (coeffs_emitted.length + 1) * d + n_bia'.val = 8 * cb_src_read'.val)
    (h_cb_le : cb_src_read'.val ≤ pb_src.length)
    (h_nbia : n_bia'.val ≤ 31)
    (h_cb_mod : cb_src_read'.val % 4 = 0)
    /- Per-acc-bit content tie: -/
    (h_acc_bits : ∀ (j : Nat) (_ : j < n_bia'.val),
        accumulator'.val.testBit j
          = (srcBits pb_src).getD
              ((coeffs_emitted.length + 1) * d + j) false)
    /- Acc high-bits-zero: -/
    (h_acc_zero : ∀ (j : Nat), n_bia'.val ≤ j → ¬ accumulator'.val.testBit j)
    /- New coefficient v equals the d-bit chunk decoded via Nat.ofBitsList: -/
    (h_v : v = fastDecompress d
              (Nat.ofBitsList ((List.range d).map
                (fun j => (srcBits pb_src).getD (coeffs_emitted.length * d + j) false)))) :
    decodeDecompressBitsInv d pb_src (coeffs_emitted ++ [v])
      cb_src_read'.val accumulator'.val n_bia'.val := by
  refine ⟨?_, h_cb_le, h_nbia, h_cb_mod, ?_, h_acc_zero, ?_⟩
  · rw [List.length_append, List.length_singleton]; exact h_cons
  · intros j hj
    rw [List.length_append, List.length_singleton]
    exact h_acc_bits j hj
  · intros k hk
    rw [List.length_append, List.length_singleton] at hk
    by_cases hk_old : k < coeffs_emitted.length
    · -- old entries: getD picks from the prefix; reuse h_inv_old's content tie.
      rw [List.getD_eq_getElem?_getD, List.getElem?_append_left hk_old,
          ← List.getD_eq_getElem?_getD]
      obtain ⟨_, _, _, _, _, _, h_pc_old⟩ := h_inv_old
      exact h_pc_old k hk_old
    · -- new entry: k = coeffs_emitted.length.
      have hk_eq : k = coeffs_emitted.length := by omega
      rw [hk_eq, List.getD_eq_getElem?_getD,
          List.getElem?_append_right (by simp)]
      simp
      exact h_v

/-! ### `step_matches_body` — per-iteration Rust ↔ Stream bridge (decode side)

Decomposed by Stream `body`'s structural case-split on `s.acci < d`. -/

/-- Low-d-bits AND equals the `Nat.ofBitsList` of the testBits. -/
theorem and_mask_eq_ofBitsList (d : ℕ) (acc : ℕ) (f : ℕ → Bool)
    (h_bits : ∀ j (_ : j < d), acc.testBit j = f j) :
    acc &&& ((1 <<< d) - 1) =
      Nat.ofBitsList ((List.range d).map f) := by
  apply Nat.eq_of_testBit_eq
  intro j
  rw [Nat.testBit_and]
  unfold Nat.ofBitsList
  rw [Nat.testBit_ofBits]
  simp only [List.length_map, List.length_range, Nat.one_shiftLeft]
  by_cases hj : j < d
  · have h_mask : (2 ^ d - 1).testBit j = true := by
      rw [Nat.testBit_two_pow_sub_one]; exact decide_eq_true_iff.mpr hj
    rw [h_mask, Bool.and_true, h_bits j hj]
    rw [dif_pos hj]
    simp [List.getElem_map, List.getElem_range]
  · push Not at hj
    have h_mask : (2 ^ d - 1).testBit j = false := by
      rw [Nat.testBit_two_pow_sub_one]; exact decide_eq_false (by omega)
    rw [h_mask, Bool.and_false, dif_neg (by omega)]

/-- **Decode-side `step_matches_body` (NO-REFILL branch).**

When `n_bia ≥ d`, no source bytes are loaded: only `accumulator` shifts
right by `d`, `n_bia` decrements by `d`, `cb_src_read` is unchanged.
Mirrors Stream's `body` else-branch. -/
theorem step_matches_body_no_refill
    (d : ℕ) (coeffs_emitted : List ℕ) (pb_src : Slice U8)
    (cb_src_read : Usize) (acc n_bia : U32) (acc1 n_bia1 : U32)
    (h_d : 1 ≤ d ∧ d ≤ 12)
    (_h_count : coeffs_emitted.length + 1 ≤ 256)
    (h_inv : decodeDecompressBitsInv d pb_src coeffs_emitted
              cb_src_read.val acc.val n_bia.val)
    (h_no_refill : d ≤ n_bia.val)
    (h_acc1 : acc1.val = acc.val >>> d)
    (h_nbia1 : n_bia1.val = n_bia.val - d) :
    decodeDecompressBitsInv d pb_src
      (coeffs_emitted ++ [fastDecompress d (acc.val &&& ((1 <<< d) - 1))])
      cb_src_read.val acc1.val n_bia1.val := by
  obtain ⟨h_cons, h_cb_le, h_nbia, h_cb_mod, h_acc, h_acc_zero, h_pc⟩ := h_inv
  refine ⟨?_, h_cb_le, ?_, h_cb_mod, ?_, ?_, ?_⟩
  · -- bit-conservation
    rw [List.length_append, List.length_singleton, h_nbia1]
    rw [Nat.add_mul, Nat.one_mul]
    omega
  · -- n_bia1 ≤ 32
    omega
  · -- per-acc-bit content tie
    intros j hj
    rw [h_acc1, Nat.testBit_shiftRight]
    rw [List.length_append, List.length_singleton, Nat.add_mul, Nat.one_mul]
    have h_lt : d + j < n_bia.val := by omega
    have := h_acc (d + j) h_lt
    rw [this]
    fcongr 1; omega
  · -- acc high-bits-zero
    intros j hj
    rw [h_acc1, Nat.testBit_shiftRight]
    apply h_acc_zero; omega
  · -- per-coefficient content tie
    intros k hk
    rw [List.length_append, List.length_singleton] at hk
    by_cases hk_old : k < coeffs_emitted.length
    · -- old entries: getD picks from the prefix; reuse h_pc.
      rw [List.getD_eq_getElem?_getD, List.getElem?_append_left hk_old,
          ← List.getD_eq_getElem?_getD]
      exact h_pc k hk_old
    · -- new entry
      have hk_eq : k = coeffs_emitted.length := by omega
      rw [hk_eq, List.getD_eq_getElem?_getD,
          List.getElem?_append_right (by simp)]
      simp only [Nat.sub_self, List.getElem?_cons_zero, Option.getD_some]
      -- Goal: fastDecompress d (acc &&& mask) = fastDecompress d (Nat.ofBitsList ...)
      fcongr 1
      apply and_mask_eq_ofBitsList
      intros j hj
      -- acc.testBit j = (srcBits pb_src).getD (length*d + j) false
      exact h_acc j (by omega)

/- Bitwise helpers for the REFILL proof. -/

private theorem testBit_add_pow_mul_low (a b n k : Nat)
    (ha : a < 2 ^ n) (hk : k < n) :
    (a + 2 ^ n * b).testBit k = a.testBit k := by
  have lhs : (a + 2 ^ n * b).testBit k
      = ((a + 2 ^ n * b) % 2 ^ n).testBit k := by
    rw [Nat.testBit_mod_two_pow]; simp [hk]
  have rhs : a.testBit k = (a % 2 ^ n).testBit k := by
    rw [Nat.testBit_mod_two_pow]; simp [hk]
  rw [lhs, rhs, Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt ha]

private theorem testBit_add_pow_mul_high (a b n k : Nat)
    (ha : a < 2 ^ n) (hk : n ≤ k) :
    (a + 2 ^ n * b).testBit k = b.testBit (k - n) := by
  rw [show k = (k - n) + n from by omega, Nat.testBit_add]
  simp [Nat.add_mul_div_left _ _ (Nat.two_pow_pos n), Nat.div_eq_of_lt ha]

private theorem U8_val_lt' (b : U8) : b.val < 2 ^ 8 := by
  have := b.hmax; simp at this; exact this

theorem srcBits_getD_eq (pb_src : Slice U8) (i j : ℕ) (hj : j < 8) :
    (srcBits pb_src).getD (8 * i + j) false
      = (pb_src.val.getD i 0#u8).val.testBit j := by
  unfold srcBits
  induction pb_src.val generalizing i with
  | nil => simp [List.flatMap]
  | cons hd tl ih =>
    simp only [List.flatMap_cons]
    by_cases hi : i = 0
    · subst hi; simp only [Nat.mul_zero, Nat.zero_add, List.getD_cons_zero]
      rw [List.getD_eq_getElem?_getD,
          List.getElem?_append_left (by simp [List.length_map, List.length_range]; exact hj)]
      simp [List.getElem?_map, List.getElem?_range hj]
    · rw [List.getD_eq_getElem?_getD,
          List.getElem?_append_right (by simp [List.length_map, List.length_range]; omega)]
      simp only [List.length_map, List.length_range]
      have : 8 * i + j - 8 = 8 * (i - 1) + j := by omega
      rw [this, ← List.getD_eq_getElem?_getD]
      rw [ih (i - 1)]
      fcongr 1; fcongr 1
      rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD]
      fcongr 1
      have hi' : i = (i - 1) + 1 := by omega
      rw [hi', List.getElem?_cons_succ]; simp

set_option maxHeartbeats 8000000 in
theorem loadLEWordBytes_testBit (pb_src : Slice U8) (cb k : ℕ) (hk : k < 32) :
    (Bridges.loadLEWordBytes pb_src cb).testBit k
      = (pb_src.val.getD (cb + k / 8) 0#u8).val.testBit (k % 8) := by
  unfold Bridges.loadLEWordBytes
  let b0 := (pb_src.val.getD cb 0#u8).val
  let b1 := (pb_src.val.getD (cb + 1) 0#u8).val
  let b2 := (pb_src.val.getD (cb + 2) 0#u8).val
  let b3 := (pb_src.val.getD (cb + 3) 0#u8).val
  have h_rewrite : b0 + 2 ^ 8 * b1 + 2 ^ 16 * b2 + 2 ^ 24 * b3
      = b0 + 2 ^ 8 * (b1 + 2 ^ 8 * (b2 + 2 ^ 8 * b3)) := by ring
  rw [h_rewrite]
  have hb0 : b0 < 2 ^ 8 := U8_val_lt' _
  have hb1 : b1 < 2 ^ 8 := U8_val_lt' _
  have hb2 : b2 < 2 ^ 8 := U8_val_lt' _
  by_cases h8 : k < 8
  · rw [testBit_add_pow_mul_low b0 _ 8 k hb0 h8,
        show k % 8 = k from Nat.mod_eq_of_lt h8,
        show k / 8 = 0 from Nat.div_eq_of_lt h8, Nat.add_zero]
  · rw [testBit_add_pow_mul_high b0 _ 8 k hb0 (by omega)]
    by_cases h16 : k < 16
    · have hk8 : k - 8 < 8 := by omega
      rw [testBit_add_pow_mul_low b1 _ 8 (k - 8) hb1 hk8,
          show k % 8 = k - 8 from by omega,
          show k / 8 = 1 from by omega]
    · rw [testBit_add_pow_mul_high b1 _ 8 (k - 8) hb1 (by omega),
          show k - 8 - 8 = k - 16 from by omega]
      by_cases h24 : k < 24
      · have hk16 : k - 16 < 8 := by omega
        rw [testBit_add_pow_mul_low b2 _ 8 (k - 16) hb2 hk16,
            show k % 8 = k - 16 from by omega,
            show k / 8 = 2 from by omega]
      · rw [testBit_add_pow_mul_high b2 _ 8 (k - 16) hb2 (by omega),
            show k - 16 - 8 = k - 24 from by omega,
            show k % 8 = k - 24 from by omega,
            show k / 8 = 3 from by omega]

/- Combined bridge: loadLEWordBytes testBit connects to srcBits. -/
theorem loadLEWordBytes_testBit_eq_srcBits (pb_src : Slice U8) (cb k : ℕ)
    (hk : k < 32) :
    (loadLEWordBytes pb_src cb).testBit k
      = (srcBits pb_src).getD (8 * cb + k) false := by
  rw [loadLEWordBytes_testBit pb_src cb k hk]
  have hk8 : k % 8 < 8 := Nat.mod_lt k (by norm_num)
  rw [show 8 * cb + k = 8 * (cb + k / 8) + k % 8 from by omega]
  exact (srcBits_getD_eq pb_src (cb + k / 8) (k % 8) hk8).symm

private theorem loadLEWordBytes_lt_2_32 (pb_src : Slice U8) (cb : ℕ) :
    loadLEWordBytes pb_src cb < 2 ^ 32 := by
  unfold loadLEWordBytes
  have h0 := U8_val_lt' (pb_src.val.getD cb 0#u8)
  have h1 := U8_val_lt' (pb_src.val.getD (cb + 1) 0#u8)
  have h2 := U8_val_lt' (pb_src.val.getD (cb + 2) 0#u8)
  have h3 := U8_val_lt' (pb_src.val.getD (cb + 3) 0#u8)
  show _ < 4294967296; nlinarith

/-- **Decode-side `step_matches_body` (REFILL branch).**

When `n_bia < d`, four LE bytes are loaded from
`pb_src[cb_src_read..cb_src_read + 4]` into the high `32 - n_bia` bits
of the accumulator; `n_bia` advances by 32, then the drain extracts `d`
LSBs as usual.  Mirrors Stream's `body` if-branch
(`acc := s.acc ||| (loadLEWord <<< s.acci); si += 4; acci += 32`). -/
theorem step_matches_body_refill
    (d : ℕ) (coeffs_emitted : List ℕ) (pb_src : Slice U8)
    (cb_src_read cb_src_read1 : Usize) (acc n_bia : U32)
    (acc_loaded acc1 n_bia1 : U32)
    (h_d : 1 ≤ d ∧ d ≤ 12)
    (h_inv : decodeDecompressBitsInv d pb_src coeffs_emitted
              cb_src_read.val acc.val n_bia.val)
    (h_refill : n_bia.val < d)
    (h_room : cb_src_read.val + 4 ≤ pb_src.length)
    (h_cb1 : cb_src_read1.val = cb_src_read.val + 4)
    (h_load : acc_loaded.val = acc.val ||| (loadLEWordBytes pb_src cb_src_read.val <<< n_bia.val))
    (h_acc1_val : acc1.val = acc_loaded.val >>> d)
    (h_nbia1 : n_bia1.val = n_bia.val + 32 - d) :
    decodeDecompressBitsInv d pb_src
      (coeffs_emitted ++ [fastDecompress d (acc_loaded.val &&& ((1 <<< d) - 1))])
      cb_src_read1.val acc1.val n_bia1.val := by
  obtain ⟨h_cons, h_cb_le, h_nbia, h_cb_mod, h_acc, h_acc_zero, h_pc⟩ := h_inv
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · /- 1. Bit-conservation -/
    rw [List.length_append, List.length_singleton, h_nbia1, h_cb1,
        Nat.add_mul, Nat.one_mul]; omega
  · /- 2. cb_src_read1 ≤ pb_src.length -/
    rw [h_cb1]; exact h_room
  · /- 3. n_bia1 ≤ 31 -/
    rw [h_nbia1]; omega
  · /- 4. cb_src_read1 % 4 = 0 -/
    rw [h_cb1]; omega
  · /- 5. Per-acc-bit content tie at acc1 -/
    intros j hj
    rw [h_acc1_val, Nat.testBit_shiftRight]
    rw [List.length_append, List.length_singleton, Nat.add_mul, Nat.one_mul]
    /- acc_loaded.testBit (d + j) = srcBits at (len*d + d + j) -/
    rw [h_load, Nat.testBit_or, Nat.testBit_shiftLeft]
    /- Split: acc's bit at d+j vs loaded word's bit at d+j-n_bia. -/
    have h_dj_ge_nbia : n_bia.val ≤ d + j := by omega
    simp [h_dj_ge_nbia]
    /- acc's high bits are 0: d + j ≥ d > n_bia, so acc.testBit (d+j) = false -/
    have h_acc_hi : acc.val.testBit (d + j) = false := by
      apply Bool.eq_false_iff.mpr; exact h_acc_zero (d + j) (by omega)
    rw [h_acc_hi, Bool.false_or]
    /- Loaded word testBit: d + j - n_bia < 32 -/
    have h_idx_lt : d + j - n_bia.val < 32 := by rw [h_nbia1] at hj; omega
    rw [loadLEWordBytes_testBit_eq_srcBits pb_src cb_src_read.val (d + j - n_bia.val)
          h_idx_lt]
    rw [List.getD_eq_getElem?_getD,
      show 8 * cb_src_read.val + (d + j - n_bia.val)
        = coeffs_emitted.length * d + d + j from by omega]
  · /- 6. Acc1 high-bits-zero -/
    intros j hj
    rw [h_acc1_val, Nat.testBit_shiftRight]
    rw [h_load, Nat.testBit_or, Nat.testBit_shiftLeft]
    /- d + j ≥ n_bia + 32, so loaded word bit is false (loadLEWordBytes < 2^32). -/
    have h_dj_ge : n_bia.val ≤ d + j := by omega
    simp [h_dj_ge]
    refine ⟨?_, ?_⟩
    · apply Bool.eq_false_iff.mpr; exact h_acc_zero (d + j) (by omega)
    · have h_idx_ge : 32 ≤ d + j - n_bia.val := by rw [h_nbia1] at hj; omega
      exact Nat.testBit_eq_false_of_lt (Nat.lt_of_lt_of_le
        (loadLEWordBytes_lt_2_32 pb_src cb_src_read.val)
        (Nat.pow_le_pow_right (by norm_num) h_idx_ge))
  · /- 7. Per-coefficient content tie -/
    intros k hk
    rw [List.length_append, List.length_singleton] at hk
    by_cases hk_old : k < coeffs_emitted.length
    · rw [List.getD_eq_getElem?_getD, List.getElem?_append_left hk_old,
          ← List.getD_eq_getElem?_getD]
      exact h_pc k hk_old
    · have hk_eq : k = coeffs_emitted.length := by omega
      rw [hk_eq, List.getD_eq_getElem?_getD,
          List.getElem?_append_right (by simp)]
      simp only [Nat.sub_self, List.getElem?_cons_zero, Option.getD_some]
      fcongr 1
      apply and_mask_eq_ofBitsList
      intros j hj
      /- acc_loaded.testBit j connects to srcBits at (len*d + j). -/
      rw [h_load, Nat.testBit_or, Nat.testBit_shiftLeft]
      by_cases h_j_low : j < n_bia.val
      · /- j < n_bia: loaded word contributes 0, acc contributes the right bit. -/
        simp [show ¬(n_bia.val ≤ j) from by omega]
        exact h_acc j h_j_low
      · /- j ≥ n_bia: acc contributes 0 (high bits), loaded word contributes. -/
        push Not at h_j_low
        simp [h_j_low]
        have h_acc_hi : acc.val.testBit j = false := by
          apply Bool.eq_false_iff.mpr; exact h_acc_zero j h_j_low
        rw [h_acc_hi, Bool.false_or]
        have h_idx_lt : j - n_bia.val < 32 := by omega
        rw [loadLEWordBytes_testBit_eq_srcBits pb_src cb_src_read.val
              (j - n_bia.val) h_idx_lt]
        rw [List.getD_eq_getElem?_getD,
          show 8 * cb_src_read.val + (j - n_bia.val)
            = coeffs_emitted.length * d + j from by omega]

/-- **Umbrella `step_matches_body` for the decode side.**  Dispatches
on `n_bia < d` (REFILL vs NO-REFILL) to one of
`step_matches_body_refill` / `step_matches_body_no_refill`. -/
theorem step_matches_body_decode
    (d : ℕ) (coeffs_emitted : List ℕ) (pb_src : Slice U8)
    (cb_src_read cb_src_read1 : Usize) (acc n_bia : U32)
    (acc1 n_bia1 : U32) (v : ℕ)
    (h_d : 1 ≤ d ∧ d ≤ 12)
    (h_count : coeffs_emitted.length + 1 ≤ 256)
    (h_inv : decodeDecompressBitsInv d pb_src coeffs_emitted
              cb_src_read.val acc.val n_bia.val)
    /- Discriminated dispatch over Rust's two output shapes. -/
    (h_dispatch :
        (/- NO-REFILL: cb1 = cb; acc1 = acc >>> d; n_bia1 = n_bia - d;
              v decoded directly from the low d bits of acc. -/
         d ≤ n_bia.val ∧
         cb_src_read1 = cb_src_read ∧
         acc1.val = acc.val >>> d ∧
         n_bia1.val = n_bia.val - d ∧
         v = fastDecompress d (acc.val &&& ((1 <<< d) - 1)))
      ∨ (/- REFILL: load 4 bytes, shift, drain. -/
         n_bia.val < d ∧
         cb_src_read.val + 4 ≤ pb_src.length ∧
         cb_src_read1.val = cb_src_read.val + 4 ∧
         n_bia1.val = n_bia.val + 32 - d ∧
         ∃ acc_loaded : U32,
           acc_loaded.val = acc.val ||| (loadLEWordBytes pb_src cb_src_read.val <<< n_bia.val) ∧
           acc1.val = acc_loaded.val >>> d ∧
           v = fastDecompress d (acc_loaded.val &&& ((1 <<< d) - 1)))) :
    decodeDecompressBitsInv d pb_src (coeffs_emitted ++ [v])
      cb_src_read1.val acc1.val n_bia1.val := by
  rcases h_dispatch with ⟨h_no_refill, h_cb_eq, h_acc1_eq, h_nbia1_eq, h_v_eq⟩
                       | ⟨h_refill, h_room, h_cb1, h_nbia1_eq, acc_loaded, h_load, h_acc1_eq, h_v_eq⟩
  · -- NO-REFILL branch
    have h_cb : cb_src_read1 = cb_src_read := h_cb_eq
    rw [h_cb, h_v_eq]
    exact step_matches_body_no_refill d coeffs_emitted pb_src cb_src_read
            acc n_bia acc1 n_bia1 h_d h_count h_inv h_no_refill
            h_acc1_eq h_nbia1_eq
  · /- REFILL branch: dispatch to step_matches_body_refill. -/
    rw [h_v_eq]
    exact step_matches_body_refill d coeffs_emitted pb_src cb_src_read cb_src_read1
            acc n_bia acc_loaded acc1 n_bia1 h_d h_inv h_refill h_room h_cb1
            h_load h_acc1_eq h_nbia1_eq

/-! ### `matchesRuntime_step_decode` — direct per-iteration bridge (decode)

Symmetric to `matchesRuntime_step_compress`: provides the outer-loop
consumer for `_loop0.spec` which carries `matchesRuntime` (Stream↔Rust)
as its loop invariant.  The `step_matches_body_*` decode bridges work
in `decodeDecompressBitsInv` and don't directly compose; these bridges
do. -/

/-- Auxiliary lemma: for any four 8-bit bytes assembled in little-endian
order into a `BitVec 32`, the bit at position `k < 32` comes from the
byte indexed by `k / 8`. -/
private theorem loadLEWord_aux (b0 b1 b2 b3 : BitVec 8) (k : ℕ) (h_k : k < 32) :
    ((BitVec.setWidth 32 b0 ||| BitVec.setWidth 32 b1 <<< (8 : ℕ) |||
        BitVec.setWidth 32 b2 <<< (16 : ℕ) ||| BitVec.setWidth 32 b3 <<< (24 : ℕ))).getLsbD k =
      if k < 8 then b0.getLsbD k
      else if k < 16 then b1.getLsbD (k - 8)
      else if k < 24 then b2.getLsbD (k - 16)
      else b3.getLsbD (k - 24) := by
  interval_cases k <;> simp

/-- The bit at position `k < 32` of `loadLEWord src si` is the source
bit at position `8 * si + k`. -/
theorem loadLEWord_getLsbD (src : List Byte) (si k : ℕ) (h_k : k < 32) :
    (DecodeDecompressState.loadLEWord src si).getLsbD k = srcBit src (8 * si + k) := by
  unfold DecodeDecompressState.loadLEWord srcBit
  have h_di : (8 * si + k) / 8 = si + k / 8 := by
    rw [show 8 * si + k = k + si * 8 by ring,
        Nat.add_mul_div_right _ _ (by decide : (0:ℕ) < 8)]
    omega
  have h_mod : (8 * si + k) % 8 = k % 8 := by
    rw [show 8 * si + k = k + si * 8 by ring, Nat.add_mul_mod_self_right]
  rw [h_di, h_mod]
  set b0 := src.getD si 0#8
  set b1 := src.getD (si + 1) 0#8
  set b2 := src.getD (si + 2) 0#8
  set b3 := src.getD (si + 3) 0#8
  rw [loadLEWord_aux b0 b1 b2 b3 k h_k]
  rcases Nat.lt_or_ge k 8 with h | h
  · rw [if_pos h, Nat.div_eq_of_lt h, Nat.mod_eq_of_lt h, Nat.add_zero]
  · rcases Nat.lt_or_ge k 16 with h2 | h2
    · rw [if_neg (by omega), if_pos h2]
      have h_div : k / 8 = 1 := by omega
      have h_mod_eq : k % 8 = k - 8 := by omega
      rw [h_div, h_mod_eq]
    · rcases Nat.lt_or_ge k 24 with h3 | h3
      · rw [if_neg (by omega), if_neg (by omega), if_pos h3]
        have h_div : k / 8 = 2 := by omega
        have h_mod_eq : k % 8 = k - 16 := by omega
        rw [h_div, h_mod_eq]
      · rw [if_neg (by omega), if_neg (by omega), if_neg (by omega)]
        have h_div : k / 8 = 3 := by omega
        have h_mod_eq : k % 8 = k - 24 := by omega
        rw [h_div, h_mod_eq]

/-- Decode-side NO-REFILL-arm bridge in `matchesRuntime`. -/
theorem matchesRuntime_step_decode_no_refill
    (d : ℕ) (s : DecodeDecompressState) (pe_dst pe_dst1 : PolyElement)
    (acc n_bia acc1 n_bia1 : U32)
    (pb_src : Slice U8) (cb_src_read : Usize)
    (h_d : 1 ≤ d ∧ d ≤ 12)
    (h_match : DecodeDecompressState.matchesRuntime d s pe_dst acc n_bia
                pb_src cb_src_read)
    /- NO-REFILL hypothesis. -/
    (h_no_refill : d ≤ n_bia.val)
    /- Post-iteration register state. -/
    (h_acc1 : acc1.val = acc.val >>> d)
    (h_nbia1 : n_bia1.val = n_bia.val - d)
    /- The output coefficient: extracted from low d bits of acc, then
       fastDecompress'd, written to pe_dst1[s.pi]. -/
    (h_pe_dst1_old : ∀ (k : ℕ), k < s.pi →
        pe_dst1.val.getD k 0#u16 = pe_dst.val.getD k 0#u16)
    (h_pe_dst1_new :
        (pe_dst1.val.getD s.pi 0#u16).val
          = (if d < 12 then fastDecompress d (acc.val &&& ((1 <<< d) - 1))
             else acc.val &&& ((1 <<< d) - 1)))
    /- Length invariant on `s.pi` (needed for `List.set` reasoning). -/
    (h_pi : s.pi < 256) :
    DecodeDecompressState.matchesRuntime d
      (DecodeDecompressState.body d s) pe_dst1 acc1 n_bia1 pb_src cb_src_read := by
  /- Decode NO-REFILL: s.acci ≥ d, so body's if-branch is false (s' = s).
     Body emits one coefficient and drains the accumulator by d. -/
  obtain ⟨h_slen, h_stie, h_si, h_cb_le, h_acci, _h_nb_le, h_s_acc, h_cons, h_zero,
          h_acc_match, h_dlen, h_dtie⟩ := h_match
  -- Step 1: reduce body's if (s.acci < d is FALSE since s.acci = n_bia ≥ d).
  have h_acci_ge : ¬ s.acci < d := by rw [h_acci]; omega
  unfold DecodeDecompressState.body DecodeDecompressState.matchesRuntime
  simp only [h_acci_ge, if_false]
  -- Step 2: identify s' = s.
  -- Step 3: prepare BitVec equations.
  have h_acc1_bv : (s.acc >>> d) = BitVec.ofNat 32 acc1.val := by
    apply BitVec.eq_of_toNat_eq
    rw [BitVec.toNat_ushiftRight, h_s_acc, BitVec.toNat_ofNat, BitVec.toNat_ofNat]
    have h_lt : acc.val < 2 ^ 32 := by
      have := acc.hBounds; simpa [U32.size, U32.numBits] using this
    have h_lt' : acc1.val < 2 ^ 32 := by
      have := acc1.hBounds; simpa [U32.size, U32.numBits] using this
    rw [Nat.mod_eq_of_lt h_lt, Nat.mod_eq_of_lt h_lt', h_acc1]
  -- Step 4: acci alignment and bounds.
  have h_acci_new : s.acci - d = n_bia1.val := by rw [h_nbia1, h_acci]
  have h_nbia1_le : n_bia1.val ≤ 32 := by rw [h_nbia1]; omega
  -- Step 5: discharge all matchesRuntime conjuncts.
  refine ⟨h_slen, h_stie, h_si, h_cb_le, h_acci_new, h_nbia1_le, h_acc1_bv, ?_, ?_, ?_, ?_, ?_⟩
  · -- bit-conservation: 8 * s.si = (s.pi + 1) * d + (s.acci - d)
    have h_dle : d ≤ s.acci := by omega
    rw [Nat.add_mul, Nat.one_mul]; omega
  · -- high-bits-zero on (s.acc >>> d).
    intro j hj
    rw [BitVec.getLsbD_ushiftRight]
    exact h_zero (d + j) (by omega)
  · -- acc_match on (s.acc >>> d) at (body d s).pi = s.pi + 1.
    intro j hj
    rw [BitVec.getLsbD_ushiftRight]
    -- Goal: s.acc.getLsbD (d + j) = srcBit s.src (d * (s.pi + 1) + j)
    -- From h_acc_match (d + j) : s.acc.getLsbD (d + j) = srcBit s.src (d * s.pi + (d + j))
    have h_dj_lt : d + j < s.acci := by
      rw [h_acci]; omega
    have h_eq := h_acc_match (d + j) h_dj_lt
    rw [h_eq]
    fcongr 1
    ring
  · -- (s.dst.set s.pi y).length = 256
    rw [List.length_set]; exact h_dlen
  · -- coefficient tie at indices 0..(s.pi + 1)
    intro k hk
    by_cases h_kpi : k < s.pi
    · -- index < s.pi: untouched by set
      have h_ne : s.pi ≠ k := by omega
      simp only [List.getD, List.getElem?_set_ne h_ne]
      show s.dst.getD k 0 = (pe_dst1.val.getD k 0#u16).val
      rw [h_dtie k h_kpi, h_pe_dst1_old k h_kpi]
    · -- k = s.pi: matches h_pe_dst1_new
      have h_keq : k = s.pi := by omega
      subst h_keq
      have h_pi_lt : s.pi < s.dst.length := by rw [h_dlen]; exact h_pi
      have h_set_self :
        (s.dst.set s.pi
           (if d < 12 then fastDecompress d (s.acc.toNat &&& ((1 : ℕ) <<< d - 1))
            else s.acc.toNat &&& ((1 : ℕ) <<< d - 1))).getD s.pi 0
        = (if d < 12 then fastDecompress d (s.acc.toNat &&& ((1 : ℕ) <<< d - 1))
           else s.acc.toNat &&& ((1 : ℕ) <<< d - 1)) := by
        show ((s.dst.set s.pi _)[s.pi]?).getD 0 = _
        rw [List.getElem?_set_self h_pi_lt]
        rfl
      rw [h_set_self]
      -- Equate s.acc.toNat with acc.val to match h_pe_dst1_new.
      have h_eq : s.acc.toNat = acc.val := by
        rw [h_s_acc, BitVec.toNat_ofNat]
        have h_lt : acc.val < 2 ^ 32 := by
          have := acc.hBounds; simpa [U32.size, U32.numBits] using this
        exact Nat.mod_eq_of_lt h_lt
      rw [h_eq, ← h_pe_dst1_new]

/-- Decode-side REFILL-arm bridge in `matchesRuntime`.

The Rust inner loop drains `n_bia` old bits, refills with a fresh
4-byte word, and drains `d - n_bia` more bits in one shot.  The
final accumulator equals `load >>> (d - n_bia)`; the coefficient is
the concatenation `acc[0..n_bia) ++ load[0..d-n_bia)` (using the
high-bits-zero loop invariant on `acc`). -/
theorem matchesRuntime_step_decode_refill
    (d : ℕ) (s : DecodeDecompressState) (pe_dst pe_dst1 : PolyElement)
    (acc n_bia acc1 n_bia1 : U32)
    (pb_src : Slice U8) (cb_src_read cb_src_read1 : Usize)
    (h_d : 1 ≤ d ∧ d ≤ 12)
    (h_match : DecodeDecompressState.matchesRuntime d s pe_dst acc n_bia
                pb_src cb_src_read)
    /- REFILL hypothesis. -/
    (h_refill : n_bia.val < d)
    /- Refill operation: read 4 LE bytes from pb_src[cb..cb+4]; advance
       cb_src_read by 4. -/
    (h_room : cb_src_read.val + 4 ≤ pb_src.length)
    (h_cb1 : cb_src_read1.val = cb_src_read.val + 4)
    /- Post-iteration register state.  `acc1` is the freshly-loaded word
       drained by `d - n_bia` (the bits not absorbed into the current
       coefficient); `n_bia1 = 32 - (d - n_bia) = n_bia + 32 - d`. -/
    (h_acc1 : acc1.val =
        (DecodeDecompressState.loadLEWord s.src cb_src_read.val).toNat
          >>> (d - n_bia.val))
    (h_nbia1 : n_bia1.val = n_bia.val + 32 - d)
    /- Output coefficient: low `n_bia` bits from the old accumulator,
       high `d - n_bia` bits from the fresh load. -/
    (h_pe_dst1_old : ∀ (k : ℕ), k < s.pi →
        pe_dst1.val.getD k 0#u16 = pe_dst.val.getD k 0#u16)
    (h_pe_dst1_new :
        (pe_dst1.val.getD s.pi 0#u16).val
          = (let v_low  : ℕ := acc.val &&& ((1 <<< n_bia.val) - 1)
             let v_high : ℕ := (DecodeDecompressState.loadLEWord s.src cb_src_read.val).toNat
                                &&& ((1 <<< (d - n_bia.val)) - 1)
             let v : ℕ := v_low ||| (v_high <<< n_bia.val)
             if d < 12 then fastDecompress d v else v))
    /- Length invariant on `s.pi` (needed for `List.set` reasoning). -/
    (h_pi : s.pi < 256) :
    DecodeDecompressState.matchesRuntime d
      (DecodeDecompressState.body d s) pe_dst1 acc1 n_bia1 pb_src cb_src_read1 := by
  obtain ⟨h_slen, h_stie, h_si, h_cb_le, h_acci, _h_nb_le, h_s_acc, h_cons, _h_zero,
          h_acc_match, h_dlen, h_dtie⟩ := h_match
  have h_acci_lt : s.acci < d := by rw [h_acci]; exact h_refill
  -- Numeric bound: acc.val < 2^32 (needed several times).
  have h_acc_lt : acc.val < 2 ^ 32 := by
    have := acc.hBounds; simpa [U32.size, U32.numBits] using this
  -- Numeric bound: acc1.val < 2^32.
  have h_acc1_lt : acc1.val < 2 ^ 32 := by
    have := acc1.hBounds; simpa [U32.size, U32.numBits] using this
  -- s.acc.toNat = acc.val.
  have h_s_acc_nat : s.acc.toNat = acc.val := by
    rw [h_s_acc, BitVec.toNat_ofNat, Nat.mod_eq_of_lt h_acc_lt]
  -- s.si = cb_src_read.val (already h_si).
  -- Unfold body and matchesRuntime, pick refill arm.
  unfold DecodeDecompressState.body DecodeDecompressState.matchesRuntime
  simp only [h_acci_lt, if_true]
  -- Now discharge each conjunct.
  refine ⟨h_slen, h_stie, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · -- (body).si = cb_src_read1.val: s.si + 4 = cb_src_read.val + 4 = cb_src_read1.val.
    rw [h_si, ← h_cb1]
  · -- cb_src_read1.val ≤ pb_src.length.
    rw [h_cb1]; exact h_room
  · -- (body).acci = n_bia1.val: s.acci + 32 - d = n_bia.val + 32 - d.
    rw [h_acci, ← h_nbia1]
  · -- n_bia1.val ≤ 32.
    rw [h_nbia1]; have := h_d.2; omega
  · -- (body).acc = BitVec.ofNat 32 acc1.val.
    -- body.acc = load >>> (d - s.acci).  After h_acci, h_si this matches
    -- h_acc1's RHS modulo BitVec.ofNat round-trip.
    rw [h_acci, h_si]
    apply BitVec.eq_of_toNat_eq
    rw [BitVec.toNat_ushiftRight, BitVec.toNat_ofNat]
    rw [Nat.mod_eq_of_lt h_acc1_lt, h_acc1]
  · -- bit-conservation: 8 * (s.si + 4) = (s.pi + 1) * d + (s.acci + 32 - d).
    have h_dle : s.acci ≤ d := by omega
    have : (s.pi + 1) * d + (s.acci + 32 - d) = s.pi * d + s.acci + 32 := by
      rw [Nat.add_mul, Nat.one_mul]; omega
    rw [this]; omega
  · -- High-bits-zero on (body).acc = load >>> (d - s.acci).
    intro j hj
    rw [BitVec.getLsbD_ushiftRight]
    rw [BitVec.getLsbD_of_ge _ _ (by rw [h_acci] at hj; omega : 32 ≤ d - s.acci + j)]
    decide
  · -- acc_match on (load >>> (d - s.acci)) at (body).pi = s.pi + 1.
    intro j hj
    rw [BitVec.getLsbD_ushiftRight]
    -- LHS = load.getLsbD (d - s.acci + j); by loadLEWord_getLsbD this
    -- equals srcBit s.src (8 * s.si + (d - s.acci) + j), provided
    -- d - s.acci + j < 32.  hj : j < s.acci + 32 - d gives that.
    have h_kbnd : d - s.acci + j < 32 := by
      have : s.acci ≤ d := by omega
      omega
    rw [loadLEWord_getLsbD s.src s.si (d - s.acci + j) h_kbnd]
    -- Goal: srcBit s.src (8 * s.si + (d - s.acci + j))
    --     = srcBit s.src (d * (s.pi + 1) + j)
    fcongr 1
    -- 8 * s.si + (d - s.acci + j) = d * (s.pi + 1) + j  via h_cons.
    have h_acci_le_d : s.acci ≤ d := by omega
    have h_cons' : 8 * s.si = s.pi * d + s.acci := h_cons
    have hgoal : 8 * s.si + (d - s.acci + j) = (s.pi + 1) * d + j := by
      have : 8 * s.si + (d - s.acci + j) = (s.pi * d + s.acci) + (d - s.acci + j) := by
        rw [h_cons']
      rw [this]; rw [Nat.add_mul, Nat.one_mul]; omega
    rw [hgoal, Nat.mul_comm d (s.pi + 1)]
  · -- (body).dst.length = 256.
    rw [List.length_set]; exact h_dlen
  · -- Coefficient tie at indices 0..(s.pi + 1).
    intro k hk
    by_cases h_kpi : k < s.pi
    · -- index < s.pi: untouched by set.
      have h_ne : s.pi ≠ k := by omega
      simp only [List.getD, List.getElem?_set_ne h_ne]
      show s.dst.getD k 0 = (pe_dst1.val.getD k 0#u16).val
      rw [h_dtie k h_kpi, h_pe_dst1_old k h_kpi]
    · -- k = s.pi: matches h_pe_dst1_new after substituting h_acci, h_si,
      -- and h_s_acc_nat.
      have h_keq : k = s.pi := by omega
      subst h_keq
      have h_pi_lt : s.pi < s.dst.length := by rw [h_dlen]; exact h_pi
      have h_set_self :
        ∀ (y : ℕ),
          (s.dst.set s.pi y).getD s.pi 0 = y := by
        intro y
        show ((s.dst.set s.pi y)[s.pi]?).getD 0 = _
        rw [List.getElem?_set_self h_pi_lt]; rfl
      rw [h_set_self]
      -- Now rewrite using h_acci (s.acci = n_bia.val), h_si (s.si = cb_src_read.val),
      -- and h_s_acc_nat (s.acc.toNat = acc.val).
      rw [h_acci, h_si, h_s_acc_nat, ← h_pe_dst1_new]

/-- Decode-side `matchesRuntime` umbrella step.  Direct outer-loop
consumer.  Dispatches REFILL vs NO-REFILL on `Or` hypothesis. -/
theorem matchesRuntime_step_decode
    (d : ℕ) (s : DecodeDecompressState) (pe_dst pe_dst1 : PolyElement)
    (acc n_bia acc1 n_bia1 : U32)
    (pb_src : Slice U8) (cb_src_read cb_src_read1 : Usize)
    (h_d : 1 ≤ d ∧ d ≤ 12)
    (h_match : DecodeDecompressState.matchesRuntime d s pe_dst acc n_bia
                pb_src cb_src_read)
    (h_room : n_bia.val < d → cb_src_read.val + 4 ≤ pb_src.length)
    (h_pi : s.pi < 256)
    (h_dispatch :
       (/- NO-REFILL -/
        d ≤ n_bia.val ∧
        cb_src_read1 = cb_src_read ∧
        acc1.val = acc.val >>> d ∧
        n_bia1.val = n_bia.val - d ∧
        (∀ (k : ℕ), k < s.pi →
            pe_dst1.val.getD k 0#u16 = pe_dst.val.getD k 0#u16) ∧
        (pe_dst1.val.getD s.pi 0#u16).val
          = (if d < 12 then fastDecompress d (acc.val &&& ((1 <<< d) - 1))
             else acc.val &&& ((1 <<< d) - 1)))
     ∨ (/- REFILL: the Rust inner loop drains old `n_bia` bits then
          refills with a fresh load, so the post-refill `acc1` is just
          the load drained by `d - n_bia`. -/
        n_bia.val < d ∧
        cb_src_read1.val = cb_src_read.val + 4 ∧
        acc1.val = (DecodeDecompressState.loadLEWord s.src cb_src_read.val).toNat
                    >>> (d - n_bia.val) ∧
        n_bia1.val = n_bia.val + 32 - d ∧
        (∀ (k : ℕ), k < s.pi →
            pe_dst1.val.getD k 0#u16 = pe_dst.val.getD k 0#u16) ∧
        (pe_dst1.val.getD s.pi 0#u16).val
          = (let v_low  : ℕ := acc.val &&& ((1 <<< n_bia.val) - 1)
             let v_high : ℕ := (DecodeDecompressState.loadLEWord s.src cb_src_read.val).toNat
                                &&& ((1 <<< (d - n_bia.val)) - 1)
             let v : ℕ := v_low ||| (v_high <<< n_bia.val)
             if d < 12 then fastDecompress d v else v))) :
    DecodeDecompressState.matchesRuntime d
      (DecodeDecompressState.body d s) pe_dst1 acc1 n_bia1 pb_src cb_src_read1 := by
  rcases h_dispatch with
    ⟨h_no_refill, h_cb_eq, h_acc1, h_nbia1, h_pe_old, h_pe_new⟩
  | ⟨h_refill, h_cb1, h_acc1, h_nbia1, h_pe_old, h_pe_new⟩
  · -- NO-REFILL
    rw [h_cb_eq]
    exact matchesRuntime_step_decode_no_refill d s pe_dst pe_dst1 acc n_bia
            acc1 n_bia1 pb_src cb_src_read h_d h_match h_no_refill h_acc1
            h_nbia1 h_pe_old h_pe_new h_pi
  · -- REFILL
    exact matchesRuntime_step_decode_refill d s pe_dst pe_dst1 acc n_bia
            acc1 n_bia1 pb_src cb_src_read cb_src_read1 h_d h_match
            h_refill (h_room h_refill) h_cb1 h_acc1 h_nbia1 h_pe_old h_pe_new h_pi

end Symcrust.Properties.MLKEM.Bridges

/-! ## Decompress wrapper at the polynomial level -/

namespace Symcrust.Properties.MLKEM.Bridges

/-- Convert a decoded `Nat` value back to its decompressed `Zq` form.

For `d < 12`, this is `fastDecompress d v` (equal to
`(MLKEM.Decompress d v).val` via `fastDecompress_eq_spec_decompress`).
For `d = 12`, no decompression occurs (`m 12 = q`), so we return `v`
directly. -/
def coeffFromDecode (d : ℕ) (v : ℕ) : ℕ :=
  if d < 12 then fastDecompress d v else v

/-- Stream form of `poly_element_decode_and_decompress`.

Run `recBody` 256 times starting from the initial decoder state.
Returns the produced polynomial as a `Vector ℕ 256`.

Domain restriction: this is well-defined only when `src.length =
32 * d` (refills don't run off the end).  The `@[step]` post enforces
this precondition. -/
def streamDecodeDecompressPoly (d : ℕ) (src : List Byte) : List ℕ :=
  (DecodeDecompressState.recBody d (DecodeDecompressState.init d src) 256).dst

/-! ## Bridge 1 (decompress side): Stream ↔ FIPS -/

/-! ### Bit-extraction helpers for the decode side -/

/-- FIPS-style bit sum: the `d`-bit value encoded by source bits
`[d * i, d * (i + 1))`. -/
def fipsBitSum (d : ℕ) (src : List Byte) (i : ℕ) : ℕ :=
  ∑ j : Fin d, (srcBit src (d * i + j.val)).toNat * 2 ^ j.val

/-- FIPS-style decoded coefficient at index `i`. -/
def fipsCoeff (d : ℕ) (src : List Byte) (i : ℕ) : ℕ :=
  coeffFromDecode d (fipsBitSum d src i)

/-- Bit-extraction identity: `acc.toNat &&& ((1 <<< d) - 1)` equals the
sum of low `d` bits of `acc`, expressed as `∑ j : Fin d, getLsbD j · 2^j`. -/
private theorem bitvec_and_mask_eq_lsbSum (acc : BitVec 32) (d : ℕ) :
    acc.toNat &&& ((1 <<< d) - 1)
      = ∑ j : Fin d, (acc.getLsbD j.val).toNat * 2 ^ j.val := by
  rw [Nat.shiftLeft_eq, one_mul, Nat.and_two_pow_sub_one_eq_mod]
  have h : ∀ (v d : ℕ),
      v % 2^d = ∑ j : Fin d, (v.testBit j.val).toNat * 2 ^ j.val := by
    intro v d
    induction d with
    | zero => simp [Nat.mod_one]
    | succ d ih =>
      rw [Fin.sum_univ_castSucc]
      simp only [Fin.val_last, Fin.val_castSucc]
      rw [show 2^(d+1) = 2^d * 2 by ring, Nat.mod_mul, ih]
      fcongr 1; rw [Nat.toNat_testBit]; ring
  rw [h]
  apply Finset.sum_congr rfl
  intro j _
  rw [BitVec.testBit_toNat]

/-- Same identity but for an arbitrary `Nat` value:
`v &&& ((1 <<< d) - 1) = ∑ j : Fin d, (v.testBit j).toNat * 2^j`. -/
private theorem nat_and_mask_eq_testBitSum (v d : ℕ) :
    v &&& ((1 <<< d) - 1)
      = ∑ j : Fin d, (v.testBit j.val).toNat * 2 ^ j.val := by
  rw [Nat.shiftLeft_eq, one_mul, Nat.and_two_pow_sub_one_eq_mod]
  induction d with
  | zero => simp [Nat.mod_one]
  | succ d ih =>
    rw [Fin.sum_univ_castSucc]
    simp only [Fin.val_last, Fin.val_castSucc]
    rw [show 2^(d+1) = 2^d * 2 by ring, Nat.mod_mul, ih]
    fcongr 1; rw [Nat.toNat_testBit]; ring

/-- Range-based bit sum (using `Finset.range` for easier reasoning). -/
private def bitSumRange (b : ℕ → Bool) (n : ℕ) : ℕ :=
  ∑ k ∈ Finset.range n, (b k).toNat * 2 ^ k

private theorem bitSumRange_lt (b : ℕ → Bool) (n : ℕ) :
    bitSumRange b n < 2 ^ n := by
  unfold bitSumRange
  induction n with
  | zero => simp
  | succ n ih =>
    rw [Finset.sum_range_succ]
    have h_bk : (b n).toNat ≤ 1 := by cases b n <;> decide
    have hpow : 0 < 2 ^ n := Nat.two_pow_pos _
    have h_term : (b n).toNat * 2 ^ n ≤ 2 ^ n := by nlinarith
    have h_sum : 2 ^ (n + 1) = 2 ^ n + 2 ^ n := by ring
    omega

private theorem bitSumRange_testBit_low (b : ℕ → Bool) (n j : ℕ) (h : j < n) :
    (bitSumRange b n).testBit j = b j := by
  unfold bitSumRange
  induction n with
  | zero => omega
  | succ n ih =>
    rw [Finset.sum_range_succ]
    have h_S_lt : (∑ k ∈ Finset.range n, (b k).toNat * 2 ^ k) < 2 ^ n :=
      bitSumRange_lt b n
    rcases Nat.lt_or_ge j n with hj | hj
    · -- j < n: bit j unaffected.
      have h_comm :
          (∑ k ∈ Finset.range n, (b k).toNat * 2 ^ k) + (b n).toNat * 2 ^ n
            = 2 ^ n * (b n).toNat + (∑ k ∈ Finset.range n, (b k).toNat * 2 ^ k) := by ring
      rw [h_comm, Nat.testBit_two_pow_mul_add (b n).toNat h_S_lt]
      rw [if_pos hj]; exact ih hj
    · -- j = n.
      have h_jn : j = n := by omega
      have h_comm :
          (∑ k ∈ Finset.range n, (b k).toNat * 2 ^ k) + (b n).toNat * 2 ^ n
            = 2 ^ n * (b n).toNat + (∑ k ∈ Finset.range n, (b k).toNat * 2 ^ k) := by ring
      rw [h_comm, Nat.testBit_two_pow_mul_add (b n).toNat h_S_lt]
      rw [if_neg (by omega), h_jn, Nat.sub_self]
      cases b n <;> decide

private theorem bitSumRange_testBit_high (b : ℕ → Bool) (n j : ℕ) (h : n ≤ j) :
    (bitSumRange b n).testBit j = false :=
  Nat.testBit_lt_two_pow (lt_of_lt_of_le (bitSumRange_lt b n)
    (Nat.pow_le_pow_right (by decide) h))

/-- `fipsBitSum` as a range-based sum. -/
private theorem fipsBitSum_eq_range (d : ℕ) (src : List Byte) (i : ℕ) :
    fipsBitSum d src i = bitSumRange (fun k => srcBit src (d * i + k)) d := by
  unfold fipsBitSum bitSumRange
  exact (Fin.sum_univ_eq_sum_range (fun k => (srcBit src (d * i + k)).toNat * 2 ^ k) d)

/-- Public bound: `fipsBitSum d src i` extracts d bits, so the value is `< 2^d`.

Used by the decode-side outer-loop spec for d < 12, where `MLKEM.m d = 2^d`. -/
theorem fipsBitSum_lt_two_pow (d : ℕ) (src : List Byte) (i : ℕ) :
    fipsBitSum d src i < 2 ^ d := by
  rw [fipsBitSum_eq_range]
  exact bitSumRange_lt _ _

/-- Bridge: `srcBit src k` matches `(Spec.bytesToBits B)[k]` when `B`
is the `listToSpecBytes` view of `src`. -/
theorem srcBit_eq_bytesToBits_listToSpecBytes
    {N : ℕ} (src : List Byte) (h_src : src.length = N)
    (k : ℕ) (h_k : k < 8 * N) :
    srcBit src k =
      (Spec.bytesToBits (Symcrust.Properties.listToSpecBytes src N h_src))[k]'h_k := by
  unfold srcBit Symcrust.Properties.listToSpecBytes
  show (src.getD (k / 8) 0#8).getLsbD (k % 8) = _
  have hkmod : k % 8 < 8 := Nat.mod_lt _ (by decide)
  have hkdiv : k / 8 < N := Nat.div_lt_of_lt_mul h_k
  have hkdiv_src : k / 8 < src.length := by rw [h_src]; exact hkdiv
  simp only [Spec.bytesToBits, Vector.getElem_ofFn]
  rw [List.getD_eq_getElem _ _ hkdiv_src]
  rw [BitVec.getLsbD_eq_getElem hkmod]
  rfl

/-- Bridge: `fipsBitSum` over a list matches `dBitSegment` over the
`listToSpecBytes` view, term-by-term. -/
theorem fipsBitSum_eq_dBitSegment
    (d : ℕ) {N : ℕ} (src : List Byte) (h_src : src.length = N)
    (i : ℕ) (h_i : (i + 1) * d ≤ 8 * N) :
    fipsBitSum d src i = dBitSegment d (Symcrust.Properties.listToSpecBytes src N h_src) i := by
  unfold fipsBitSum dBitSegment
  rw [show (∑ j : Fin d, (srcBit src (d * i + ↑j)).toNat * 2 ^ (↑j : ℕ))
        = ∑ j ∈ Finset.range d, (srcBit src (d * i + j)).toNat * 2 ^ j
      from Fin.sum_univ_eq_sum_range
        (fun n => (srcBit src (d * i + n)).toNat * 2 ^ n) d]
  apply Finset.sum_congr rfl
  intro j hj_mem
  rw [Finset.mem_range] at hj_mem
  have hk : i * d + j < 8 * N := by
    have hstep : (i + 1) * d = i * d + d := by ring
    omega
  have hk' : d * i + j = i * d + j := by ring
  rw [hk']
  rw [dif_pos hk]
  fcongr 1
  exact congrArg (fun b : Bool => b.toNat)
    (srcBit_eq_bytesToBits_listToSpecBytes src h_src (i * d + j) hk)

/-- NO-REFILL bit-extraction: when `d ≤ acci`, the low `d` bits of `acc`
sum (LE) to `fipsBitSum d src i`. -/
theorem v_lhs_no_refill_eq_fipsBitSum
    (d : ℕ) (src : List Byte) (i : ℕ)
    (acc : BitVec 32) (acci : ℕ)
    (h_acc_match : ∀ j, j < acci → acc.getLsbD j = srcBit src (d * i + j))
    (h_d_le_acci : d ≤ acci) :
    acc.toNat &&& ((1 <<< d) - 1) = fipsBitSum d src i := by
  rw [fipsBitSum_eq_range]
  apply Nat.eq_of_testBit_eq
  intro j
  rcases Nat.lt_or_ge j d with hj_d | hj_d
  · rw [bitSumRange_testBit_low _ _ _ hj_d]
    rw [Nat.testBit_and, Nat.shiftLeft_eq, one_mul, Nat.testBit_two_pow_sub_one]
    have h_j_acci : j < acci := by omega
    simp only [hj_d, decide_true, Bool.and_true]
    rw [BitVec.testBit_toNat, h_acc_match j h_j_acci]
  · rw [bitSumRange_testBit_high _ _ _ hj_d]
    rw [Nat.testBit_and, Nat.shiftLeft_eq, one_mul, Nat.testBit_two_pow_sub_one]
    have h_not_d : ¬ j < d := by omega
    simp only [h_not_d, decide_false, Bool.and_false]

/-- REFILL bit-extraction: when `acci < d` and `8 * si = i * d + acci`,
the OR of the low `acci` bits of `acc` and the low `d - acci` bits of
`loadLEWord src si` (shifted up by `acci`) sums to `fipsBitSum d src i`. -/
theorem v_lhs_refill_eq_fipsBitSum
    (d : ℕ) (h_d_le_12 : d ≤ 12)
    (src : List Byte) (i : ℕ) (si : ℕ)
    (acc : BitVec 32) (acci : ℕ)
    (h_si_acci : 8 * si = i * d + acci)
    (h_acc_match : ∀ j, j < acci → acc.getLsbD j = srcBit src (d * i + j))
    (h_acci_lt_d : acci < d) :
    (acc.toNat &&& ((1 <<< acci) - 1)) |||
      ((DecodeDecompressState.loadLEWord src si).toNat &&&
        ((1 <<< (d - acci)) - 1)) <<< acci
    = fipsBitSum d src i := by
  rw [fipsBitSum_eq_range]
  apply Nat.eq_of_testBit_eq
  intro j
  rcases Nat.lt_or_ge j d with hj_d | hj_d
  · rw [bitSumRange_testBit_low _ _ _ hj_d]
    simp only [Nat.testBit_or, Nat.testBit_and,
               Nat.shiftLeft_eq, one_mul, Nat.testBit_two_pow_sub_one,
               Nat.testBit_mul_two_pow]
    rcases Nat.lt_or_ge j acci with hj_acci | hj_acci
    · have hne : ¬ acci ≤ j := by omega
      simp only [hj_acci, decide_true,
                 Bool.and_true, hne, decide_false, Bool.false_and,
                 Bool.or_false]
      rw [BitVec.testBit_toNat, h_acc_match j hj_acci]
    · have h_not_lt : ¬ j < acci := by omega
      have h_diff_lt : j - acci < d - acci := by omega
      have h_acci_le : acci ≤ j := hj_acci
      simp only [h_not_lt, decide_false, Bool.and_false,
                 Bool.false_or, h_acci_le, decide_true, Bool.true_and,
                 h_diff_lt]
      have h_j_minus_lt_32 : j - acci < 32 := by omega
      rw [BitVec.testBit_toNat,
          loadLEWord_getLsbD src si (j - acci) h_j_minus_lt_32]
      simp only [Bool.and_true]
      fcongr 1
      calc 8 * si + (j - acci)
          = (i * d + acci) + (j - acci) := by rw [h_si_acci]
        _ = i * d + (acci + (j - acci)) := by ring
        _ = i * d + j := by rw [Nat.add_sub_cancel' h_acci_le]
        _ = d * i + j := by ring
  · rw [bitSumRange_testBit_high _ _ _ hj_d]
    simp only [Nat.testBit_or, Nat.testBit_and,
               Nat.shiftLeft_eq, one_mul, Nat.testBit_two_pow_sub_one,
               Nat.testBit_mul_two_pow]
    have h_not_acci : ¬ j < acci := by omega
    have h_not_diff : ¬ j - acci < d - acci := by omega
    simp only [h_not_acci, decide_false, Bool.and_false,
               Bool.false_or, h_not_diff, Bool.and_false]

/-- The partial invariant carried by induction on the decode side.
Mirrors `streamCompressEncodePartial`. -/
def streamDecodeDecompressPartial
    (d : ℕ) (src : List Byte) (_h_d : 1 ≤ d ∧ d ≤ 12)
    (i : ℕ) (s : DecodeDecompressState) : Prop :=
  DecodeDecompressState.length_inv d s i ∧
  s.src = src ∧
  /- Already-written coefficients match the FIPS-decoded values. -/
  (∀ (k : ℕ), k < i → s.dst.getD k 0 = fipsCoeff d src k) ∧
  /- Acc low bits match the next FIPS source bits.
     `length_inv` pins `8 * s.si - s.acci = d * i`, so bits at positions
     `[d * i, d * i + s.acci)` of `src` live at positions `[0, s.acci)`
     of `s.acc`. -/
  (∀ (j : ℕ), j < s.acci → s.acc.getLsbD j = srcBit src (d * i + j)) ∧
  /- Acc high bits zero (mirrors `body_high_bits_zero`). -/
  (∀ (j : ℕ), s.acci ≤ j → ¬ s.acc.getLsbD j)

/-- Base case: `init d src` satisfies the partial invariant at `i = 0`. -/
private theorem init_streamDecodeDecompressPartial
    (d : ℕ) (src : List Byte) (h_d : 1 ≤ d ∧ d ≤ 12)
    (h_src_len : 32 * d ≤ src.length) :
    streamDecodeDecompressPartial d src h_d 0
        (DecodeDecompressState.init d src) := by
  unfold streamDecodeDecompressPartial DecodeDecompressState.length_inv
  refine ⟨⟨?_, ?_, ?_, ?_, ?_, ?_⟩, ?_, ?_, ?_, ?_⟩
  · show 32 * d ≤ src.length; exact h_src_len
  · show (List.replicate 256 (0 : ℕ)).length = 256
    rw [List.length_replicate]
  · omega
  · rfl
  · show (0 : ℕ) = 0 * d + 0; omega
  · show (0 : ℕ) ≤ 31; omega
  · rfl
  · intro k hk; omega
  · intro j hj
    change j < 0 at hj
    omega
  · intro j _
    change ¬ (0#32).getLsbD j = true
    simp

set_option maxRecDepth 1024 in
/-- Inductive step: `body d` preserves the partial invariant.

The bit accounting:
- NO-REFILL arm (`s.acci ≥ d`): bits `[0, d)` of `s.acc` (which match
  `src` bits `[d * i, d * i + d)` by IH) become the new coefficient.
- REFILL arm (`s.acci < d`): bits `[0, s.acci)` of `s.acc` together with
  bits `[0, d - s.acci)` of the fresh load become the new coefficient.
  The load bits match `src` bits `[8 * s.si, 8 * s.si + 32) =
  [d * i + s.acci, ...)` (by `length_inv` and `loadLEWord_getLsbD`),
  which is exactly the continuation of the coefficient. -/
private theorem body_streamDecodeDecompressPartial
    (d : ℕ) (src : List Byte) (h_d : 1 ≤ d ∧ d ≤ 12)
    (i : ℕ) (h_i : i < 256) (s : DecodeDecompressState)
    (h_inv : streamDecodeDecompressPartial d src h_d i s) :
    streamDecodeDecompressPartial d src h_d (i + 1)
        (DecodeDecompressState.body d s) := by
  obtain ⟨h_len, h_src_eq, h_dst_match, h_acc_match, h_acc_zero⟩ := h_inv
  have ⟨h_slen, h_dlen, h_iL, h_pi, h_si_acci, h_acci_le⟩ := h_len
  have h_d_pos : 0 < d := h_d.1
  have h_d_le_12 : d ≤ 12 := h_d.2
  -- Length invariant on the post-body state.
  have h_body_len :
      DecodeDecompressState.length_inv d (DecodeDecompressState.body d s) (i + 1) :=
    DecodeDecompressState.body_length_inv d s i h_d h_i h_len
  -- High-bits-zero on the post-body acc.
  have h_body_zero :
      ∀ (j : ℕ), (DecodeDecompressState.body d s).acci ≤ j →
        ¬ (DecodeDecompressState.body d s).acc.getLsbD j :=
    DecodeDecompressState.body_high_bits_zero d s h_d (by omega) h_acc_zero
  -- Source preservation (body never touches s.src).
  have h_body_src : (DecodeDecompressState.body d s).src = src := by
    unfold DecodeDecompressState.body
    by_cases h_refill : s.acci < d
    · rw [if_pos h_refill]; dsimp only; exact h_src_eq
    · rw [if_neg h_refill]; dsimp only; exact h_src_eq
  -- Length facts.
  have h_dst_len_eq : (DecodeDecompressState.body d s).dst.length = 256 :=
    h_body_len.2.1
  -- The new coefficient written equals `fipsCoeff d src i`.
  have h_coeff :
      (DecodeDecompressState.body d s).dst.getD i 0 = fipsCoeff d src i := by
    have h_pi_lt : i < s.dst.length := by rw [h_dlen]; exact h_i
    have h_set_at_i : ∀ (y : ℕ), (s.dst.set s.pi y).getD i 0 = y := by
      intro y
      have h_pi_lt' : s.pi < s.dst.length := by rw [h_pi]; exact h_pi_lt
      have h_to_set : (s.dst.set s.pi y).getD i 0 = (s.dst.set s.pi y).getD s.pi 0 := by
        rw [h_pi]
      rw [h_to_set]
      show ((s.dst.set s.pi y)[s.pi]?).getD 0 = y
      rw [List.getElem?_set_self h_pi_lt']; rfl
    unfold DecodeDecompressState.body
    by_cases h_refill : s.acci < d
    · -- REFILL arm
      rw [if_pos h_refill]
      dsimp only
      rw [h_set_at_i]
      -- Show: extracted v equals fipsBitSum d src i; then both arms of `if d < 12` match.
      set load := DecodeDecompressState.loadLEWord s.src s.si with h_load_def
      set v_lhs : ℕ :=
        s.acc.toNat &&& ((1 <<< s.acci) - 1) |||
          ((load.toNat &&& ((1 <<< (d - s.acci)) - 1)) <<< s.acci) with h_v_lhs_def
      have h_v_eq : v_lhs = fipsBitSum d src i := by
        rw [h_v_lhs_def, fipsBitSum_eq_range]
        apply Nat.eq_of_testBit_eq
        intro j
        rcases Nat.lt_or_ge j d with hj_d | hj_d
        · rw [bitSumRange_testBit_low _ _ _ hj_d]
          simp only [Nat.testBit_or, Nat.testBit_and,
                     Nat.shiftLeft_eq, one_mul, Nat.testBit_two_pow_sub_one,
                     Nat.testBit_mul_two_pow]
          rcases Nat.lt_or_ge j s.acci with hj_acci | hj_acci
          · have hne : ¬ s.acci ≤ j := by omega
            simp only [hj_acci, decide_true,
                       Bool.and_true, hne, decide_false, Bool.false_and,
                       Bool.or_false]
            rw [BitVec.testBit_toNat, h_acc_match j hj_acci]
          · have h_not_lt : ¬ j < s.acci := by omega
            have h_diff_lt : j - s.acci < d - s.acci := by omega
            have h_acci_le : s.acci ≤ j := hj_acci
            simp only [h_not_lt, decide_false, Bool.and_false,
                       Bool.false_or, h_acci_le, decide_true, Bool.true_and,
                       h_diff_lt]
            have h_j_minus_lt_32 : j - s.acci < 32 := by omega
            rw [BitVec.testBit_toNat, h_load_def,
                loadLEWord_getLsbD s.src s.si (j - s.acci) h_j_minus_lt_32]
            simp only [Bool.and_true]
            rw [h_src_eq]
            fcongr 1
            calc 8 * s.si + (j - s.acci)
                = (i * d + s.acci) + (j - s.acci) := by rw [h_si_acci]
              _ = i * d + (s.acci + (j - s.acci)) := by ring
              _ = i * d + j := by rw [Nat.add_sub_cancel' h_acci_le]
              _ = d * i + j := by ring
        · rw [bitSumRange_testBit_high _ _ _ hj_d]
          simp only [Nat.testBit_or, Nat.testBit_and,
                     Nat.shiftLeft_eq, one_mul, Nat.testBit_two_pow_sub_one,
                     Nat.testBit_mul_two_pow]
          have h_not_acci : ¬ j < s.acci := by omega
          have h_not_diff : ¬ j - s.acci < d - s.acci := by omega
          simp only [h_not_acci, decide_false, Bool.and_false,
                     Bool.false_or, h_not_diff, Bool.and_false]
      rw [h_v_eq]
      rfl
    · -- NO-REFILL arm
      rw [if_neg h_refill]
      dsimp only
      rw [h_set_at_i]
      set v_lhs : ℕ := s.acc.toNat &&& ((1 <<< d) - 1) with h_v_lhs_def
      have h_v_eq : v_lhs = fipsBitSum d src i := by
        rw [h_v_lhs_def, fipsBitSum_eq_range]
        apply Nat.eq_of_testBit_eq
        intro j
        rcases Nat.lt_or_ge j d with hj_d | hj_d
        · rw [bitSumRange_testBit_low _ _ _ hj_d]
          rw [Nat.testBit_and, Nat.shiftLeft_eq, one_mul, Nat.testBit_two_pow_sub_one]
          have h_j_acci : j < s.acci := by
            have : d ≤ s.acci := Nat.not_lt.mp h_refill
            omega
          simp only [hj_d, decide_true, Bool.and_true]
          rw [BitVec.testBit_toNat, h_acc_match j h_j_acci]
        · rw [bitSumRange_testBit_high _ _ _ hj_d]
          rw [Nat.testBit_and, Nat.shiftLeft_eq, one_mul, Nat.testBit_two_pow_sub_one]
          have h_not_d : ¬ j < d := by omega
          simp only [h_not_d, decide_false, Bool.and_false]
      rw [h_v_eq]
      rfl
  refine ⟨h_body_len, h_body_src, ?_, ?_, h_body_zero⟩
  · -- Existing coefficients (k < i + 1).
    intro k hk
    rcases Nat.lt_or_ge k i with h_lt | h_ge
    · -- k < i: untouched by set.
      have h_ne : s.pi ≠ k := by rw [h_pi]; omega
      unfold DecodeDecompressState.body
      by_cases h_refill : s.acci < d
      · rw [if_pos h_refill]; dsimp only
        show ((s.dst.set s.pi _)[k]?).getD 0 = _
        rw [List.getElem?_set_ne h_ne]
        exact h_dst_match k h_lt
      · rw [if_neg h_refill]; dsimp only
        show ((s.dst.set s.pi _)[k]?).getD 0 = _
        rw [List.getElem?_set_ne h_ne]
        exact h_dst_match k h_lt
    · -- k = i: the freshly-written coefficient.
      have h_keq : k = i := by omega
      rw [h_keq]
      exact h_coeff
  · -- New acc low bits match.
    intro j hj
    unfold DecodeDecompressState.body at hj ⊢
    by_cases h_refill : s.acci < d
    · -- REFILL: new acc = load >>> (d - s.acci), new acci = s.acci + 32 - d.
      rw [if_pos h_refill] at hj ⊢
      dsimp only at hj ⊢
      rw [BitVec.getLsbD_ushiftRight]
      have h_j_lt_32 : (d - s.acci) + j < 32 := by omega
      rw [← h_src_eq, loadLEWord_getLsbD s.src s.si _ h_j_lt_32]
      rw [h_src_eq]
      fcongr 1
      -- Combine `8*s.si = i*d + s.acci` and `d - s.acci ≥ 0` (since s.acci < d).
      have h_si_ge : s.acci ≤ 8 * s.si := by omega
      have h_sub_acci : 8 * s.si - s.acci = i * d := by omega
      have h_d_sub : (d - s.acci) + s.acci = d := by omega
      have : 8 * s.si + (d - s.acci + j) = i * d + d + j := by
        have := h_d_sub
        omega
      linarith [show d * (i + 1) = d * i + d from by ring,
                show d * i = i * d from by ring]
    · -- NO-REFILL: new acc = s.acc >>> d, new acci = s.acci - d.
      rw [if_neg h_refill] at hj ⊢
      dsimp only at hj ⊢
      rw [BitVec.getLsbD_ushiftRight]
      have h_dj_lt : d + j < s.acci := by omega
      rw [h_acc_match (d + j) h_dj_lt]
      fcongr 1
      rw [show d * (i + 1) = d * i + d by ring]
      ring

/-- Inductive step over a count `n`: applying `body` `n` times
preserves the partial invariant, advancing the index from `i` to `i + n`. -/
private theorem recBody_streamDecodeDecompressPartial
    (d : ℕ) (src : List Byte) (h_d : 1 ≤ d ∧ d ≤ 12)
    (n i : ℕ) (h_bnd : i + n ≤ 256) (s : DecodeDecompressState)
    (h_inv : streamDecodeDecompressPartial d src h_d i s) :
    streamDecodeDecompressPartial d src h_d (i + n)
        (DecodeDecompressState.recBody d s n) := by
  induction n generalizing i s with
  | zero =>
    simp only [Nat.add_zero, DecodeDecompressState.recBody,
               List.range_zero, List.foldl_nil]
    exact h_inv
  | succ n ih =>
    have h_i_lt : i < 256 := by omega
    have h_step : streamDecodeDecompressPartial d src h_d (i + 1)
        (DecodeDecompressState.body d s) :=
      body_streamDecodeDecompressPartial d src h_d i h_i_lt s h_inv
    have h_bnd' : (i + 1) + n ≤ 256 := by omega
    have h_ih := ih (i + 1) h_bnd' (DecodeDecompressState.body d s) h_step
    have h_eq : (i + 1) + n = i + (n + 1) := by omega
    rw [h_eq] at h_ih
    -- recBody d s (n+1) = recBody d (body d s) n
    have h_rec_step :
        DecodeDecompressState.recBody d s (n + 1)
          = DecodeDecompressState.recBody d (DecodeDecompressState.body d s) n := by
      unfold DecodeDecompressState.recBody
      rw [List.range_succ_eq_map, List.foldl_cons]
      simp [List.foldl_map]
    rw [h_rec_step]
    exact h_ih

/-- Specialised wrapper at `i := 0, n := 256`. -/
private theorem recBody_streamDecodeDecompressPartial_full
    (d : ℕ) (src : List Byte) (h_d : 1 ≤ d ∧ d ≤ 12)
    (s : DecodeDecompressState)
    (h_inv : streamDecodeDecompressPartial d src h_d 0 s) :
    streamDecodeDecompressPartial d src h_d 256
        (DecodeDecompressState.recBody d s 256) := by
  have h := recBody_streamDecodeDecompressPartial d src h_d 256 0
    (by omega) s h_inv
  simpa using h

/-- Pure consequence of the partial invariant at `i = 256`: the
output list equals the FIPS-decoded coefficients. -/
private theorem streamDecodeDecompressPartial_buffer_eq
    (d : ℕ) (src : List Byte) (h_d : 1 ≤ d ∧ d ≤ 12)
    (s : DecodeDecompressState)
    (h_partial : streamDecodeDecompressPartial d src h_d 256 s) :
    s.dst = (List.range 256).map (fun k => fipsCoeff d src k) := by
  obtain ⟨h_len, _h_src, h_dst_match, _h_acc, _h_zero⟩ := h_partial
  have h_dlen : s.dst.length = 256 := h_len.2.1
  apply List.ext_getElem
  · rw [h_dlen, List.length_map, List.length_range]
  · intro k h_k_lhs _h_k_rhs
    have h_k_lt : k < 256 := h_dlen ▸ h_k_lhs
    have h_get_d : s.dst.getD k 0 = s.dst[k]'h_k_lhs := by
      simp [List.getD, List.getElem?_eq_getElem h_k_lhs]
    have h_match := h_dst_match k h_k_lt
    rw [h_get_d] at h_match
    rw [h_match]
    simp [List.getElem_map, List.getElem_range]

set_option maxRecDepth 2048 in
/-- Per-coefficient bit-level identity for `MLKEM.ByteDecode`.

`ByteDecode B` at index `k` equals (mod `m d`) the FIPS bit-sum
`fipsBitSum d src k`, where `B = listToSpecBytes src (32*d) h`. -/
private theorem byteDecode_getElem
    (d : ℕ) (h_d : 1 ≤ d ∧ d ≤ 12) (src : List Byte)
    (h_src_len : src.length = 32 * d) (k : ℕ) (h_k : k < 256) :
    (MLKEM.ByteDecode (listToSpecBytes src (32 * d) h_src_len) h_d)[k]'h_k
      = ((fipsBitSum d src k : ℕ) : ZMod (MLKEM.m d)) := by
  have h_d_pos : 0 < d := h_d.1
  have h_d_le : d ≤ 12 := h_d.2
  set B := listToSpecBytes src (32 * d) h_src_len with hB_def
  -- Bit-extraction: for any n with n/8 < src.length, bytesToBits B at n
  -- equals srcBit src n.
  have h_src_eq : ∀ (n : ℕ) (h_n : n < 8 * (32 * d)),
      (Spec.bytesToBits B)[n]'h_n = srcBit src n := by
    intro n h_n
    have h_div : n / 8 < 32 * d := by omega
    have h_div_src : n / 8 < src.length := by rw [h_src_len]; exact h_div
    unfold Spec.bytesToBits srcBit
    rw [Vector.getElem_ofFn]
    show (B[n / 8]'h_div).toNat.testBit (n % 8) =
         (src.getD (n / 8) 0#8).getLsbD (n % 8)
    rw [BitVec.testBit_toNat]
    rw [hB_def]
    unfold listToSpecBytes
    rw [Vector.getElem_ofFn]
    rw [List.getD_eq_getElem _ _ h_div_src]
  unfold MLKEM.ByteDecode
  simp only [Aeneas.SRRange.forIn'_eq_forIn'_range', SRRange.size,
             Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one]
  refine forIn'_getElem_indexed (List.range' 0 256) _ _ k h_k _
    (P := fun s (F' : MLKEM.Polynomial (MLKEM.m d)) =>
      F'[k]'h_k = if s ≤ k then (0 : ZMod (MLKEM.m d))
                  else ((fipsBitSum d src k : ℕ) : ZMod (MLKEM.m d)))
    ?hInit ?hFinal ?hStep
  case hInit =>
    show (MLKEM.Polynomial.zero (MLKEM.m d))[k]'h_k = _
    simp [MLKEM.Polynomial.zero, Vector.getElem_replicate]
  case hFinal =>
    intro F' hP
    rw [List.length_range'] at hP
    rwa [if_neg (by omega : ¬ 256 ≤ k)] at hP
  case hStep =>
    intro s hs F' hPF' a' ha' ha'_eq
    have h_len : (List.range' 0 256).length = 256 := by simp
    have hs_lt : s < 256 := h_len ▸ hs
    have ha'_val : a' = s := by rw [ha'_eq]; simp [List.getElem_range']
    have ha'_lt : a' < 256 := ha'_val ▸ hs_lt
    refine ⟨_, rfl, ?_⟩
    try simp only []
    rw [Vector.getElem_set ha'_lt h_k]
    by_cases h_eq : a' = k
    · rw [if_pos h_eq, if_neg (by omega : ¬ s + 1 ≤ k)]
      simp only [h_eq]
      unfold fipsBitSum
      have h_sum_pointwise : ∀ (j : Fin d),
          ((Spec.bytesToBits B)[k * d + j.val]'(by
            have h_jd : j.val < d := j.isLt
            have h_upper : (k + 1) * d ≤ 256 * d := Nat.mul_le_mul_right d (by omega)
            calc k * d + j.val < (k + 1) * d := by nlinarith
              _ ≤ 256 * d := h_upper
              _ = 8 * (32 * d) := by ring)).toNat
          = (srcBit src (d * k + j.val)).toNat := by
        intro j
        have h_jd : j.val < d := j.isLt
        have h_idx_lt : k * d + j.val < 8 * (32 * d) := by
          have h_upper : (k + 1) * d ≤ 256 * d := Nat.mul_le_mul_right d (by omega)
          calc k * d + j.val < (k + 1) * d := by nlinarith
            _ ≤ 256 * d := h_upper
            _ = 8 * (32 * d) := by ring
        rw [h_src_eq (k * d + j.val) h_idx_lt]
        fcongr 2
        ring
      -- Sum elementwise via the cast.
      push_cast
      apply Finset.sum_congr rfl
      intro j _
      rw [h_sum_pointwise j]
    · rw [if_neg h_eq, hPF']
      have h_eq' : s ≠ k := by rw [← ha'_val]; exact fun h => h_eq h
      by_cases h_si : s ≤ k
      · rw [if_pos h_si, if_pos (by omega : s + 1 ≤ k)]
      · rw [if_neg h_si, if_neg (by omega : ¬ s + 1 ≤ k)]

set_option maxRecDepth 2048 in
/-- **Bridge 1 — decompress side.**

The stream-decoded polynomial equals the FIPS-decoded polynomial,
coefficient-list form.

For `d = 12`, raw 12-bit reads from `src` may exceed `q = 3329`; the
Rust impl rejects those with `Error.InvalidBlob`, so the equality only
holds when every decoded coefficient is `< m d`.  We expose that as
`h_wf`: callers at `d < 12` discharge it automatically (the bound is
`2^d`), callers at `d = 12` get the precondition from their own
no-invalid-blob hypothesis. -/
theorem streamDecodeDecompressPoly_eq.spec (d : ℕ) (src : List Byte)
    (h_d : 1 ≤ d ∧ d ≤ 12)
    (h_src_len : src.length = 32 * d)
    (h_wf : ∀ k, k < 256 → fipsBitSum d src k < MLKEM.m d) :
    streamDecodeDecompressPoly d src =
      (decodeDecompressPoly d (listToSpecBytes src (32 * d) h_src_len) h_d).toList.map ZMod.val := by
  have h_d_pos : 0 < d := h_d.1
  have h_d_le : d ≤ 12 := h_d.2
  have h_src_le : 32 * d ≤ src.length := by rw [h_src_len]
  set B := listToSpecBytes src (32 * d) h_src_len with hB_def
  unfold streamDecodeDecompressPoly
  set s := DecodeDecompressState.recBody d (DecodeDecompressState.init d src) 256 with h_s
  have h_partial : streamDecodeDecompressPartial d src h_d 256 s :=
    recBody_streamDecodeDecompressPartial_full d src h_d _
      (init_streamDecodeDecompressPartial d src h_d h_src_le)
  rw [streamDecodeDecompressPartial_buffer_eq d src h_d s h_partial]
  -- Goal: (range 256).map (fipsCoeff d src) = (decodeDecompressPoly d B h_d).toList.map ZMod.val
  apply List.ext_getElem
  · simp [Vector.length_toList]
  · intro k h_k_lhs h_k_rhs
    have h_k_lt : k < 256 := by
      have := h_k_lhs
      simp at this
      exact this
    simp only [List.getElem_map, List.getElem_range, Vector.getElem_toList]
    -- Show: fipsCoeff d src k = (decodeDecompressPoly d B h_d)[k]'_ .val
    have h_byteDecode := byteDecode_getElem d h_d src h_src_len k h_k_lt
    -- fipsBitSum bound for `ZMod.val_cast_of_lt`.
    have h_wf_k : fipsBitSum d src k < MLKEM.m d := h_wf k h_k_lt
    have h_m_pos : 0 < MLKEM.m d := by
      simp only [MLKEM.m]
      split <;> [positivity; decide]
    haveI : NeZero (MLKEM.m d) := ⟨Nat.pos_iff_ne_zero.mp h_m_pos⟩
    unfold fipsCoeff coeffFromDecode decodeDecompressPoly
    split_ifs with h_d12
    · -- d < 12: Polynomial.Decompress is applied.
      show fastDecompress d (fipsBitSum d src k) =
          ((MLKEM.Polynomial.Decompress d (MLKEM.ByteDecode B h_d) ⟨h_d.1, h_d12⟩)[k]'h_k_lt).val
      unfold MLKEM.Polynomial.Decompress
      rw [Vector.getElem_map]
      rw [h_byteDecode]
      rw [fastDecompress_eq_spec_decompress d (fipsBitSum d src k) ⟨h_d.1, h_d12⟩
            (by
              have : MLKEM.m d = 2^d := by simp [MLKEM.m, h_d12]
              rw [← this]; exact h_wf_k)]
    · -- d = 12: no decompress; the heq cast is between defeq types.
      have h12 : d = 12 := by omega
      subst h12
      have h_m12 : MLKEM.m 12 = Spec.MLKEM.q := by simp [MLKEM.m]
      simp only []
      -- Goal: fipsBitSum 12 src k = (ByteDecode B ⋯)[k].val (at ZMod q)
      have h_bd : ((MLKEM.ByteDecode B h_d)[k]'h_k_lt).val
          = ((fipsBitSum 12 src k : ℕ) : ZMod (MLKEM.m 12)).val := by
        rw [byteDecode_getElem 12 h_d src h_src_len k h_k_lt]
      rw [ZMod.val_cast_of_lt h_wf_k] at h_bd
      exact h_bd.symm

end Symcrust.Properties.MLKEM.Bridges
