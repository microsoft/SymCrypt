/-
  # Bridges/EncodingStreamCompress.lean — Stream intermediate for compress+encode.

  Split from `EncodingStream.lean` so that the compress and decompress
  halves elaborate in parallel.  See `EncodingStreamDecompress.lean` for
  the decode+decompress side.

  ## Architecture (3-step pipeline, derived from prior `sp` branch)

  ```
  FIPS spec (compressEncodePoly d F)
    ⟷₁ Stream (streamCompressEncodePoly d F)    [Bridge 1, math identity]
    ⟷₂ Aeneas (mlkem.ntt.poly_element_compress_and_encode)  [FC via step*]
  ```

  The prior `sp` development (blobs `f4666a3a`, `5dd2d694`, `11c79a61`,
  `4bf39419` on origin/sp) used a 4-step pipeline with an extra
  `Target` layer (functional accumulator over `Vector Bool (256·d)`).
  We drop `Target` because the current `Spec.MLKEM.ByteEncode`
  is already functional (uses `Id.run do ... for hi : i in [0:256] ...`).

  The Stream layer hardcodes `n = 4` (Rust `u32` accumulator word) and
  uses `List Byte` for the output buffer (one-to-one with the
  `Slice U8` carried by Aeneas).

  ## Why a stream intermediate

  The Aeneas-extracted body operates on a runtime accumulator state
  `(pb_dst : Slice U8, cb_dst_written : Usize, accumulator : U32,
  n_bits_in_accumulator : U32)`.  Connecting this directly to FIPS
  `ByteEncode` requires reasoning about partial bit-level rewrites of
  the output buffer mid-loop (the prior `compressEncodeBitsInv`
  testBit-based invariant tried this and ran into 80+ line ad-hoc
  chain proofs).

  The Stream layer factors the proof into two independent halves:

  * **Bridge 2 (Aeneas ↔ Stream)** is *purely structural*: the body /
    loop / wrapper `@[step]` posts say "the state advances by exactly
    one `CompressEncodeState.body d x s_in` step" (resp. `recBody`).
    No bit-level reasoning; just unfold + `step*` + record-equality
    `simp`.
  * **Bridge 1 (Stream ↔ FIPS)** is *purely mathematical*: prove
    `streamCompressEncodePoly d F = (compressEncodePoly d F).toList`
    by induction on coefficients.  No reference to runtime types.

  Composition: every top-level `@[step]` post on a poly-element /
  vector function still states FIPS-form FC
  (`= compressEncodePoly d ...` / `= decodeDecompressPoly d ...`);
  internally the proof chains Bridge 2 then Bridge 1.
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.Encoding

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open Symcrust

namespace Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 1000000

/-! ## Compress-side stream state and step function -/

/-- Streaming state of `poly_element_compress_and_encode`.

Mirrors `Symcrust.SpecAux.Stream.EncodeState 4` from the prior `sp`
branch (`prior/StreamEncode.lean` lines 62-65, blob `11c79a61`), with
`n` fixed at 4 (the Rust `u32` accumulator word).

Fields:
* `b` — output byte buffer; growing list of `Byte = BitVec 8`.  At
  every full-accumulator flush, 4 LE bytes are written to
  `b[bi..bi+4]`.
* `bi` — next write index into `b` (always a multiple of 4 between
  flushes).
* `acc` — 32-bit shift register holding `acci` LSB-justified pending
  bits.
* `acci` — bit count in `acc`, in `[0, 32]`. -/
structure CompressEncodeState where
  b : List Byte
  bi : ℕ
  acc : BitVec 32
  acci : ℕ
  deriving Repr

namespace CompressEncodeState

/-- Initial stream state for a polynomial whose encoded output is
`32 * d` bytes: empty buffer (pre-filled with zero bytes), zero
accumulator. -/
def init (d : ℕ) : CompressEncodeState :=
  { b := List.replicate (32 * d) (0#8 : Byte),
    bi := 0,
    acc := 0#32,
    acci := 0 }

/-- Initial stream state for the *padded* per-poly call: the runtime
slice `pb_dst` may be longer than the encoded-poly footprint `32*d`
(e.g., when the vector loop passes `pb_dst[i*32*d ..]`).  The buffer
length matches `n` (the runtime `pb_dst.length`); the relaxed
`length_inv` only requires `32*d ≤ n`.

`init_padded d (32*d) = init d` definitionally; this constructor
exists so the relaxed per-poly spec can witness `matchesRuntime`'s
`s.b.length = pb_dst.length` conjunct at any compatible length. -/
def init_padded (_d : ℕ) (n : ℕ) : CompressEncodeState :=
  { b := List.replicate n (0#8 : Byte),
    bi := 0,
    acc := 0#32,
    acci := 0 }

/-- One-coefficient ingest step.  `x` is the (already-compressed)
value to encode, with `x < 2^d` as a caller-side invariant.

Effect (mirrors the Rust body `poly_element_compress_and_encode_loop_body_prefix`
+ the terminal `if n_bits_in_accumulator1 = 32` arm):

1. `nBits := min d (32 - s.acci)`         -- # bits of `x` to push *now*
2. `bitsToEncode := x &&& ((1 <<< nBits) - 1)`
3. `acc1 := s.acc ||| (bitsToEncode << s.acci)`
4. `acci1 := s.acci + nBits`
5. If `acci1 = 32`:
     - Flush `acc1` to `b[bi..bi+4]` in little-endian byte order.
     - The remaining `d - nBits` high bits of `x` become the new
       accumulator's low bits.
   Else:
     - Carry `acc1`, `acci1` forward; `bi` and `b` unchanged.

This is `Stream.encode.body` from the prior development
(`prior/StreamEncode.lean` lines 67-95) specialised to `n = 4`. -/
def body (d : ℕ) (x : ℕ) (s : CompressEncodeState) : CompressEncodeState :=
  let nBits := min d (32 - s.acci)
  let bitsToEncode : ℕ := x &&& ((1 <<< nBits) - 1)
  let acc1 : BitVec 32 := s.acc ||| ((BitVec.ofNat 32 bitsToEncode) <<< s.acci)
  let acci1 := s.acci + nBits
  if acci1 = 32 then
    let b1 := s.b.set s.bi       (BitVec.setWidth 8 acc1)
    let b2 := b1.set (s.bi + 1)  (BitVec.setWidth 8 (acc1 >>> 8))
    let b3 := b2.set (s.bi + 2)  (BitVec.setWidth 8 (acc1 >>> 16))
    let b4 := b3.set (s.bi + 3)  (BitVec.setWidth 8 (acc1 >>> 24))
    { b := b4,
      bi := s.bi + 4,
      acc := BitVec.ofNat 32 (x >>> nBits),
      acci := d - nBits }
  else
    { s with acc := acc1, acci := acci1 }

/-- Fold `body` over a list of already-compressed coefficient values. -/
def recBody (d : ℕ) (xs : List ℕ) (s : CompressEncodeState) :
    CompressEncodeState :=
  xs.foldl (fun s' x => body d x s') s

/-- Structural length invariant on the stream state.  Stays true on
every step; needed for the body-spec ↔ flush-arm dispatch.

`length_inv` says: after processing `i` coefficients, the buffer
length is at least `32 * d` (the encoded-poly footprint), the write
cursor `bi` and the bit count `acci` are pinned by
`bi = 4 * ((d * i) / 32)`, `acci = (d * i) % 32`.

The buffer-length conjunct uses `32 * d ≤ s.b.length` so that the
runtime per-poly function can be called on a longer `pb_dst` slice
(e.g., `pb_dst[i*32*d ..]` in the vector loop) without losing the
length-pinning information.  The `init`/`init_padded` constructors
both satisfy this; `body` never changes `s.b.length`. -/
def length_inv (d : ℕ) (s : CompressEncodeState) (i : ℕ) : Prop :=
  32 * d ≤ s.b.length ∧ i ≤ 256 ∧
  s.bi = 4 * ((d * i) / 32) ∧
  s.acci = (d * i) % 32

/-- Runtime ↔ Stream correspondence for the encode loop.

Says: the abstract stream state `s` faithfully captures the runtime
`(pb_dst, cb_dst_written, accumulator, n_bits_in_accumulator)` quadruple:

* the first `bi` bytes of `pb_dst` agree with `s.b` (bytewise via
  `.bv`);
* `s.bi = cb_dst_written.val`, `s.acci = n_bits_in_accumulator.val`;
* `s.acc` equals the runtime `accumulator` as a 32-bit value;
* the high `32 - acci` bits of `s.acc` are zero (loop invariant of
  the bit-pump — every flush at exactly 32 bits resets to a leftover
  in `[0, 2^(d - nBits))` whose width is `d - nBits ≤ 11`).

The acc-clearing-high-bits clause is what lets the flush-arm `flush`
output `s.acc` in full without garbage. -/
def matchesRuntime
    (s : CompressEncodeState) (pb_dst : Slice U8) (cb_dst_written : Usize)
    (acc n_bits_in_accumulator : U32) : Prop :=
  -- Length equality FIRST so subsequent `agrind`/`omega` can use it
  -- without an extra `have` step after `unfold matchesRuntime`.
  s.b.length = pb_dst.length ∧
  cb_dst_written.val ≤ pb_dst.length ∧
  s.bi = cb_dst_written.val ∧
  (∀ k : ℕ, k < cb_dst_written.val →
      s.b.getD k 0#8 = (pb_dst.val.getD k 0#u8).bv) ∧
  s.acci = n_bits_in_accumulator.val ∧
  n_bits_in_accumulator.val ≤ 32 ∧
  s.acc = BitVec.ofNat 32 acc.val ∧
  /- High bits of the accumulator above `s.acci` are 0
     (loop invariant of the bit-pump — every flush at exactly 32 bits
     resets to a leftover whose width is `d - nBits ≤ 11`).  This is
     what lets the flush arm output the full accumulator without
     garbage. -/
  (∀ (j : ℕ), s.acci ≤ j → ¬ s.acc.getLsbD j)

/-! ### Structural preservation lemmas for `body` / `recBody` (compress side)

These foundation lemmas decouple the per-step state book-keeping
(`length_inv`, high-bits-zero) from the bit-level FC content
(captured by `bitsMatch` below).  They are the structural half of
the expert-mandated "body preserves invariant" decomposition. -/

/-- `body` preserves `length_inv` (compress side). -/
theorem body_length_inv (d : ℕ) (x : ℕ) (s : CompressEncodeState) (i : ℕ)
    (h_d : 1 ≤ d ∧ d ≤ 12) (h_i : i < 256)
    (h_inv : length_inv d s i) :
    length_inv d (body d x s) (i + 1) := by
  unfold body length_inv
  obtain ⟨hlen, hi_le, hbi, hacci⟩ := h_inv
  dsimp only
  split_ifs <;> (refine ⟨?_, ?_, ?_, ?_⟩ <;> agrind)

/-- `body` preserves the high-bits-zero invariant on `acc`. -/
theorem body_high_bits_zero (d : ℕ) (x : ℕ) (s : CompressEncodeState)
    (h_d : 1 ≤ d ∧ d ≤ 12)
    (h_x : x < 2 ^ d)
    (_h_acci : s.acci ≤ 32)
    (h_zero : ∀ j, s.acci ≤ j → ¬ s.acc.getLsbD j) :
    ∀ j, (body d x s).acci ≤ j → ¬ (body d x s).acc.getLsbD j := by
  intros j hj
  unfold body at hj ⊢
  dsimp only at hj ⊢
  split_ifs at hj ⊢ with h
  · -- pos arm: flush; new acc = BitVec.ofNat 32 (x >>> nBits), acci' = d - nBits.
    -- Need: ¬(x >>> nBits).testBit j when j ≥ d - nBits, using x < 2^d.
    have hj' : d - min d (32 - s.acci) ≤ j := hj
    simp only [BitVec.getLsbD_ofNat, Nat.testBit_shiftRight, Bool.and_eq_true,
      decide_eq_true_eq, not_and]
    intro _
    have hbound : x < 2 ^ (min d (32 - s.acci) + j) :=
      lt_of_lt_of_le h_x (Nat.pow_le_pow_right (by norm_num) (by omega))
    exact (Bool.not_eq_true _).mpr (Nat.testBit_eq_false_of_lt hbound)
  · -- neg arm: carry; new acc = s.acc ||| (bits-to-encode << s.acci),
    -- acci' = s.acci + nBits.  Both s.acc.getLsbD j and the shifted-load bit are 0
    -- whenever j ≥ s.acci + nBits.
    have hj' : s.acci + min d (32 - s.acci) ≤ j := hj
    simp only [BitVec.getLsbD_or, BitVec.getLsbD_shiftLeft, BitVec.getLsbD_ofNat,
      Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq, not_or, Nat.testBit_and,
      Bool.not_eq_true]
    refine ⟨?_, ?_⟩
    · -- s.acc.getLsbD j = false from h_zero (j ≥ s.acci).
      simpa using h_zero j (by omega)
    · -- shifted-load bit = false: (1 <<< nBits - 1).testBit (j - s.acci) = false
      -- because j - s.acci ≥ nBits.
      rintro ⟨_, _, _, h_bit⟩
      have h1 : (1 : ℕ) <<< min d (32 - s.acci) = 2 ^ min d (32 - s.acci) := by
        simp [Nat.shiftLeft_eq, one_mul]
      rw [h1, Nat.testBit_two_pow_sub_one] at h_bit
      exact absurd (of_decide_eq_true h_bit) (by omega)

/-- `recBody` preserves `length_inv` over a list of `n` ingests.
The list length advances the iteration index `i` by exactly `xs.length`. -/
theorem recBody_length_inv (d : ℕ) (xs : List ℕ) (s : CompressEncodeState) (i : ℕ)
    (h_d : 1 ≤ d ∧ d ≤ 12) (h_bound : i + xs.length ≤ 256)
    (h_inv : length_inv d s i) :
    length_inv d (recBody d xs s) (i + xs.length) := by
  induction xs generalizing s i with
  | nil => simpa [recBody] using h_inv
  | cons x xs ih =>
    have h_i_lt : i < 256 := by
      have : i + (xs.length + 1) ≤ 256 := by simpa using h_bound
      grind
    have h_step : length_inv d (body d x s) (i + 1) :=
      body_length_inv d x s i h_d h_i_lt h_inv
    have h_bound' : (i + 1) + xs.length ≤ 256 := by
      have : i + (xs.length + 1) ≤ 256 := by simpa using h_bound
      grind
    have := ih (s := body d x s) (i := i + 1) h_bound' h_step
    simpa [recBody, List.foldl_cons, Nat.add_assoc, Nat.add_comm 1 xs.length]
      using this

/-- `recBody` preserves the high-bits-zero invariant. -/
theorem recBody_high_bits_zero (d : ℕ) (xs : List ℕ) (s : CompressEncodeState)
    (h_d : 1 ≤ d ∧ d ≤ 12)
    (h_xs : ∀ x ∈ xs, x < 2 ^ d)
    (h_acci : s.acci ≤ 32)
    (h_zero : ∀ j, s.acci ≤ j → ¬ s.acc.getLsbD j) :
    (∀ j, (recBody d xs s).acci ≤ j → ¬ (recBody d xs s).acc.getLsbD j) ∧
    (recBody d xs s).acci ≤ 32 := by
  induction xs generalizing s with
  | nil => exact ⟨by simpa [recBody] using h_zero, by simpa [recBody] using h_acci⟩
  | cons x xs ih =>
    have h_x : x < 2 ^ d := h_xs x (List.mem_cons_self)
    have h_zero' :
        ∀ j, (body d x s).acci ≤ j → ¬ (body d x s).acc.getLsbD j :=
      body_high_bits_zero d x s h_d h_x h_acci h_zero
    /- `body`'s new acci is either `s.acci + nBits ≤ 32` (no-flush, with
       flush triggered exactly at 32) or `d - nBits ≤ d ≤ 12`. -/
    have h_acci' : (body d x s).acci ≤ 32 := by
      unfold body; dsimp only; split_ifs <;> agrind
    have h_xs' : ∀ y ∈ xs, y < 2 ^ d := fun y hy => h_xs y (List.mem_cons_of_mem _ hy)
    obtain ⟨h_zero'', h_acci''⟩ := ih (s := body d x s) h_xs' h_acci' h_zero'
    refine ⟨?_, ?_⟩
    · simpa [recBody, List.foldl_cons] using h_zero''
    · simpa [recBody, List.foldl_cons] using h_acci''

/-! ### Padding-irrelevance for `init_padded`

The relaxed per-poly spec witnesses `matchesRuntime` with
`init_padded d n` (buffer length `n ≥ 32*d`) rather than the rigid
`init d` (buffer length exactly `32*d`).  Since `body`'s writes only
touch indices in `[bi, bi+4)` and the loop invariant pins
`bi + 4 ≤ 32*d` for `i < 256`, the trailing zero bytes of
`init_padded` are preserved through every iteration.

Concretely: `(recBody d xs (init_padded d n)).b.take (32*d) =
(recBody d xs (init d)).b`. -/

/-- `bi` only depends on previous `bi`, `acci`, `d`, `x` — not on `s.b`. -/
private theorem body_bi (d x : ℕ) (s : CompressEncodeState) :
    (body d x s).bi = if s.acci + min d (32 - s.acci) = 32 then s.bi + 4 else s.bi := by
  unfold body; dsimp only; split_ifs <;> rfl

/-- `acc` only depends on previous `acc`, `acci`, `d`, `x`. -/
private theorem body_acc (d x : ℕ) (s : CompressEncodeState) :
    (body d x s).acc =
      if s.acci + min d (32 - s.acci) = 32 then BitVec.ofNat 32 (x >>> min d (32 - s.acci))
      else s.acc ||| (BitVec.ofNat 32 (x &&& ((1 <<< min d (32 - s.acci)) - 1)) <<< s.acci) := by
  unfold body; dsimp only; split_ifs <;> rfl

/-- `acci` only depends on previous `acci`, `d`. -/
private theorem body_acci (d x : ℕ) (s : CompressEncodeState) :
    (body d x s).acci =
      if s.acci + min d (32 - s.acci) = 32 then d - min d (32 - s.acci)
      else s.acci + min d (32 - s.acci) := by
  unfold body; dsimp only; split_ifs <;> rfl

/-- `body` preserves buffer length. -/
private theorem body_b_length (d x : ℕ) (s : CompressEncodeState) :
    (body d x s).b.length = s.b.length := by
  unfold body; dsimp only; split_ifs <;> simp [List.length_set]

/-- Key lemma: if two states agree on `bi`, `acc`, `acci`, and the prefix
`b.take m` for any `m`, then after `body` they still agree on all four. -/
private theorem body_prefix_eq (d x : ℕ) (s s' : CompressEncodeState) (m : ℕ)
    (h_bi : s.bi = s'.bi) (h_acc : s.acc = s'.acc) (h_acci : s.acci = s'.acci)
    (h_take : s.b.take m = s'.b.take m) :
    (body d x s).bi = (body d x s').bi ∧
    (body d x s).acc = (body d x s').acc ∧
    (body d x s).acci = (body d x s').acci ∧
    (body d x s).b.take m = (body d x s').b.take m := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · rw [body_bi, body_bi, h_acci, h_bi]
  · rw [body_acc, body_acc, h_acci, h_acc]
  · rw [body_acci, body_acci, h_acci]
  · unfold body
    -- Case-split on the flush condition first; the `if` lives under `let`s and a
    -- `.b` projection, so `split_ifs` can't reach it through both states uniformly.
    by_cases h_flush : (s.acci + min d (32 - s.acci) = 32)
    · have h_flush' : s'.acci + min d (32 - s'.acci) = 32 := by rw [← h_acci]; exact h_flush
      dsimp only
      rw [if_pos h_flush, if_pos h_flush']
      dsimp only
      rw [h_bi, h_acc, h_acci]
      simp only [List.take_set, h_take]
    · have h_flush' : ¬ s'.acci + min d (32 - s'.acci) = 32 := by rw [← h_acci]; exact h_flush
      dsimp only
      rw [if_neg h_flush, if_neg h_flush']
      dsimp only
      exact h_take

/-- Iterated padding-irrelevance: if two states agree on `bi`, `acc`,
`acci`, and `b.take m`, then `recBody` preserves this agreement. -/
theorem recBody_prefix_eq (d : ℕ) (xs : List ℕ)
    (s s' : CompressEncodeState) (m : ℕ)
    (h_bi : s.bi = s'.bi) (h_acc : s.acc = s'.acc) (h_acci : s.acci = s'.acci)
    (h_take : s.b.take m = s'.b.take m) :
    (recBody d xs s).b.take m = (recBody d xs s').b.take m := by
  induction xs generalizing s s' with
  | nil => simpa [recBody] using h_take
  | cons x xs ih =>
    obtain ⟨hbi', hacc', hacci', htake'⟩ :=
      body_prefix_eq d x s s' m h_bi h_acc h_acci h_take
    have h_unfold : ∀ (t : CompressEncodeState),
        (recBody d (x :: xs) t).b = (recBody d xs (body d x t)).b := by
      intro t; simp [recBody, List.foldl_cons]
    rw [h_unfold, h_unfold]
    exact ih (body d x s) (body d x s') hbi' hacc' hacci' htake'

/-- `recBody` preserves buffer length. -/
private theorem recBody_b_length (d : ℕ) (xs : List ℕ) (t : CompressEncodeState) :
    (recBody d xs t).b.length = t.b.length := by
  induction xs generalizing t with
  | nil => rfl
  | cons y ys ih =>
    have h : recBody d (y :: ys) t = recBody d ys (body d y t) := by simp [recBody]
    rw [h, ih, body_b_length]

/-- Specialization: `init_padded d n` and `init d` agree on prefix
`b.take (32*d)` (both are `replicate (32*d) 0`), so `recBody` results
agree there. -/
theorem recBody_init_padded_take (d : ℕ) (xs : List ℕ) (n : ℕ)
    (h_n : 32 * d ≤ n) :
    (recBody d xs (init_padded d n)).b.take (32 * d) = (recBody d xs (init d)).b := by
  have h_init_take : (init_padded d n).b.take (32 * d) = (init d).b.take (32 * d) := by
    simp [init_padded, init, List.take_replicate, Nat.min_eq_left h_n]
  have h_bi : (init_padded d n).bi = (init d).bi := by simp [init_padded, init]
  have h_acc : (init_padded d n).acc = (init d).acc := by simp [init_padded, init]
  have h_acci : (init_padded d n).acci = (init d).acci := by simp [init_padded, init]
  have h_eq := recBody_prefix_eq d xs (init_padded d n) (init d) (32 * d)
                 h_bi h_acc h_acci h_init_take
  have h_final_len : (recBody d xs (init d)).b.length = 32 * d := by
    rw [recBody_b_length]; simp [init]
  have h_id : (recBody d xs (init d)).b.take (32 * d) = (recBody d xs (init d)).b :=
    List.take_of_length_le (Nat.le_of_eq h_final_len)
  rw [h_eq, h_id]

end CompressEncodeState

/-! ### Cross-bridge: Rust `compressEncodeBitsInv` ↔ Stream invariants (compress side)

These bridges relate the Rust-only bit invariant `compressEncodeBitsInv`
(defined in `Bridges/Encoding.lean`, parameterized by the list of
processed coefficients `coeffs_done`) to the Stream-side invariants
`matchesRuntime`, `length_inv`, and the high-acc-bits-zero property.

The expert-mandated design is:

* `compressEncodeBitsInv` is what the OUTER LOOP and TOP SPEC use as
  their loop invariant.  It carries everything Rust-only that the
  proof needs: bit-conservation, FIPS bit-content tie, high-zero.
* Stream's `matchesRuntime + length_inv + acc-high-zero` is what the
  Stream body-preservation theorems (`body_length_inv`,
  `body_high_bits_zero`, `recBody_*`) talk about.
* The cross-bridges let us LIFT a per-iteration Rust step into a
  per-iteration Stream `body` step, apply Stream's preservation, and
  PUSH the result back to a Rust BitsInv at the next iteration.

The forward bridge `compressEncodeBitsInv_to_stream` is fully
constructive: it builds a Stream witness `s` whose `b` mirrors
`pb_dst` on the written prefix and zero-fills the rest, whose `bi`
and `acci` track Rust's cursor / bit-count exactly, and whose `acc`
is `BitVec.ofNat 32 accumulator.val`.

The reverse bridge `bitsInv_of_stream_step` is used after Stream's
body advances `s ⟶ body d x s`: given Stream invariants at the new
state plus the body's bit-level outputs (from the Rust body spec),
reconstruct `compressEncodeBitsInv` at `coeffs_done ++ [x]`. -/

/-- **Forward bridge (cmp side).**  Given `compressEncodeBitsInv` on
the Rust state, build a Stream witness satisfying `matchesRuntime`,
`length_inv`, and `acc-high-bits-zero`. -/
theorem compressEncodeBitsInv_to_stream
    (d : ℕ) (coeffs_done : List ℕ) (pb_dst : Slice U8)
    (cb_dst_written : Usize) (accumulator n_bia : U32)
    (_h_d : 1 ≤ d ∧ d ≤ 12) (h_len : pb_dst.length = 32 * d)
    (h_count : coeffs_done.length ≤ 256)
    (h_inv : compressEncodeBitsInv d coeffs_done pb_dst
              cb_dst_written.val accumulator.val n_bia.val) :
    ∃ s : CompressEncodeState,
      CompressEncodeState.matchesRuntime s pb_dst cb_dst_written
        accumulator n_bia ∧
      CompressEncodeState.length_inv d s coeffs_done.length ∧
      (∀ j : ℕ, s.acci ≤ j → ¬ s.acc.getLsbD j) := by
  obtain ⟨h_cons, h_cb_le, h_nbia, h_cb_mod, h_bytes, h_acc, h_acc_zero⟩ := h_inv
  -- Witness: zero-padded image of pb_dst's prefix.
  refine ⟨{ b := (pb_dst.val.take cb_dst_written.val).map (·.bv)
              ++ List.replicate (32 * d - cb_dst_written.val) (0#8 : Byte),
            bi := cb_dst_written.val,
            acc := BitVec.ofNat 32 accumulator.val,
            acci := n_bia.val }, ?_, ?_, ?_⟩
  · -- matchesRuntime: 8 conjuncts
    refine ⟨?_, h_cb_le, rfl, ?_, rfl, by omega, rfl, ?_⟩
    · -- s.b.length = pb_dst.length
      simp only [List.length_append, List.length_map, List.length_take,
                 List.length_replicate, h_len]
      omega
    · -- bytewise agreement on prefix
      intros k hk
      have hk' : k < (pb_dst.val.take cb_dst_written.val).length := by
        simp [List.length_take, h_cb_le]; omega
      rw [List.getD_eq_getElem?_getD,
          List.getElem?_append_left (by simpa using hk')]
      have : ((pb_dst.val.take cb_dst_written.val).map (·.bv))[k]?
              = some ((pb_dst.val[k]?.getD 0#u8).bv) := by
        rw [List.getElem?_map]
        rw [List.getElem?_take_of_lt hk]
        rcases hpv : pb_dst.val[k]? with _ | v
        · -- impossible: k < cb_dst_written ≤ pb_dst.val.length
          exfalso
          have := List.getElem?_eq_none_iff.mp hpv
          have hlen : k < pb_dst.val.length := by
            have : pb_dst.length = pb_dst.val.length := rfl
            omega
          omega
        · simp
      rw [this]
      simp
    · -- acc-high-bits-zero (inside matchesRuntime)
      intros j hj
      simp only [BitVec.getLsbD_ofNat, Bool.and_eq_true, decide_eq_true_eq,
                 Bool.not_eq_true, not_and]
      intro _hj32
      have := h_acc_zero j hj
      rcases h : accumulator.val.testBit j with _ | _
      · rfl
      · exact absurd h this
  · -- length_inv: 4 conjuncts
    refine ⟨?_, h_count, ?_, ?_⟩
    · -- s.b.length = 32 * d
      simp only [List.length_append, List.length_map, List.length_take,
                 List.length_replicate, h_len]
      omega
    · -- bi = 4 * ((d * length) / 32)
      have h_mul : d * coeffs_done.length = 8 * cb_dst_written.val + n_bia.val := by
        rw [Nat.mul_comm]; exact h_cons
      obtain ⟨k, hk⟩ : ∃ k, cb_dst_written.val = 4 * k :=
        ⟨cb_dst_written.val / 4, by omega⟩
      show cb_dst_written.val = 4 * ((d * coeffs_done.length) / 32)
      rw [h_mul, hk]
      have h_eq : (8 * (4 * k) + n_bia.val) / 32 = k := by omega
      rw [h_eq]
    · -- acci = (d * length) % 32
      have h_mul : d * coeffs_done.length = 8 * cb_dst_written.val + n_bia.val := by
        rw [Nat.mul_comm]; exact h_cons
      obtain ⟨k, hk⟩ : ∃ k, cb_dst_written.val = 4 * k :=
        ⟨cb_dst_written.val / 4, by omega⟩
      show n_bia.val = (d * coeffs_done.length) % 32
      rw [h_mul, hk]
      have h_eq : (8 * (4 * k) + n_bia.val) % 32 = n_bia.val := by omega
      rw [h_eq]
  · -- top-level acc-high-bits-zero
    intros j hj
    simp only [BitVec.getLsbD_ofNat, Bool.and_eq_true, decide_eq_true_eq,
               Bool.not_eq_true, not_and]
    intro _hj32
    have := h_acc_zero j hj
    rcases h : accumulator.val.testBit j with _ | _
    · rfl
    · exact absurd h this

/-- **Reverse bridge (cmp side, per-step).**  Given that Stream's body
step `body d x s_in` advanced from `s_in` (with old BitsInv at
`coeffs_done`) to `s_out` (Stream invariants verified by
`body_length_inv` + `body_high_bits_zero`), and given the Rust body's
bit-level outputs justify the FIPS bit-content tie at
`coeffs_done ++ [x]`, conclude `compressEncodeBitsInv` at the new
Rust state. -/
theorem compressEncodeBitsInv_of_stream_step
    (d : ℕ) (coeffs_done : List ℕ) (x : ℕ) (pb_dst' : Slice U8)
    (cb_dst_written' : Usize) (accumulator' n_bia' : U32)
    (_h_d : 1 ≤ d ∧ d ≤ 12)
    (_h_x : x < 2 ^ d) (_h_count : coeffs_done.length + 1 ≤ 256)
    /- Bit-conservation at the next iteration: -/
    (h_cons : (coeffs_done.length + 1) * d
              = 8 * cb_dst_written'.val + n_bia'.val)
    (h_cb_le : cb_dst_written'.val ≤ pb_dst'.length)
    (h_nbia : n_bia'.val ≤ 31)
    (h_cb_mod : cb_dst_written'.val % 4 = 0)
    /- Per-byte FIPS content tie: -/
    (h_bytes : ∀ (i : Nat) (_ : i < cb_dst_written'.val) (j : Nat) (_ : j < 8),
        ((pb_dst'.val[i]?.getD 0#u8).val).testBit j
          = (compressBits d (coeffs_done ++ [x])).getD (8 * i + j) false)
    /- Per-acc-bit FIPS content tie: -/
    (h_acc_bits : ∀ (j : Nat) (_ : j < n_bia'.val),
        accumulator'.val.testBit j
          = (compressBits d (coeffs_done ++ [x])).getD
              (8 * cb_dst_written'.val + j) false)
    /- Acc high-bits-zero (carried by stream body_high_bits_zero): -/
    (h_acc_zero : ∀ (j : Nat), n_bia'.val ≤ j → ¬ accumulator'.val.testBit j) :
    compressEncodeBitsInv d (coeffs_done ++ [x]) pb_dst'
      cb_dst_written'.val accumulator'.val n_bia'.val := by
  -- All seven conjuncts are direct repackaging of the hypotheses.
  refine ⟨?_, h_cb_le, h_nbia, h_cb_mod, ?_, ?_, h_acc_zero⟩
  · -- length * d = 8 * cb + n_bia
    rw [List.length_append, List.length_singleton]; exact h_cons
  · -- per-byte content tie
    intros i hi j hj
    exact h_bytes i hi j hj
  · -- per-acc-bit content tie
    intros j hj
    exact h_acc_bits j hj

/-! ### `step_matches_body` — per-iteration Rust ↔ Stream bridge (compress side)

This is the CENTRAL lemma the outer loop consumes.  Given that the Rust
body has been executed (specs in `Encoding/Compress.lean` —
`poly_element_compress_and_encode_loop_body_prefix.spec` plus the flush
arm), and given `compressEncodeBitsInv` held BEFORE, conclude that
`compressEncodeBitsInv` holds AFTER, with `coeffs_done` extended by
one new coefficient `x = coeffToEncode d c`.

We decompose the proof by the **Stream body's structural case-split**:
* `step_matches_body_carry` handles `n_bia + nBits < 32` (no flush; Stream
  takes the else-branch of `body`).
* `step_matches_body_flush` handles `n_bia + nBits = 32` (flush; Stream
  writes 4 LE bytes via `s.b.set` four times, then carries the leftover
  into a fresh accumulator).

Each chunk is provable from the body-prefix spec's bit-level outputs
without re-deriving from raw `step*`.  The umbrella `step_matches_body`
case-splits and dispatches. -/

/-! Helper lemmas about `compressBits` (definitional flatMap identities). -/

theorem compressBits_length (d : ℕ) (coeffs : List ℕ) :
    (compressBits d coeffs).length = coeffs.length * d := by
  unfold compressBits
  induction coeffs with
  | nil => simp
  | cons hd tl ih =>
    simp [List.flatMap_cons, List.length_append, List.length_map,
          List.length_range, Nat.add_mul, Nat.add_comm]

theorem compressBits_append (d : ℕ) (coeffs : List ℕ) (c : ℕ) :
    compressBits d (coeffs ++ [c]) =
      compressBits d coeffs ++ (List.range d).map (fun i => (fastCompress d c).testBit i) := by
  unfold compressBits
  rw [List.flatMap_append]
  simp [List.flatMap_cons, List.flatMap_nil]

theorem compressBits_append_prefix (d : ℕ) (coeffs : List ℕ) (c : ℕ) (k : ℕ)
    (hk : k < coeffs.length * d) :
    (compressBits d (coeffs ++ [c])).getD k false
      = (compressBits d coeffs).getD k false := by
  rw [compressBits_append]
  rw [List.getD_eq_getElem?_getD, List.getElem?_append_left, ← List.getD_eq_getElem?_getD]
  rw [compressBits_length]; exact hk

theorem compressBits_append_suffix (d : ℕ) (coeffs : List ℕ) (c : ℕ) (k : ℕ)
    (h_lo : coeffs.length * d ≤ k) (h_hi : k < (coeffs.length + 1) * d) :
    (compressBits d (coeffs ++ [c])).getD k false
      = (fastCompress d c).testBit (k - coeffs.length * d) := by
  rw [compressBits_append]
  rw [List.getD_eq_getElem?_getD, List.getElem?_append_right]
  · rw [compressBits_length]
    have h_idx : k - coeffs.length * d < d := by
      rw [Nat.add_mul, Nat.one_mul] at h_hi; omega
    rw [List.getElem?_map, List.getElem?_range h_idx]
    simp
  · rw [compressBits_length]; exact h_lo

/-- **Compress-side `step_matches_body` (CARRY branch).**

When the Rust body's accumulator update keeps `n_bia + n_bits_to_encode
< 32`, no flush occurs: only `accumulator` and `n_bits_in_accumulator`
advance; `cb_dst_written` and the buffer bytes are unchanged.  This
mirrors Stream's `body` else-branch (`{ s with acc := acc1, acci := acci1 }`). -/
theorem step_matches_body_carry
    (d : ℕ) (coeffs_done : List ℕ) (c : ℕ) (pb_dst : Slice U8)
    (cb_dst_written : Usize) (acc n_bia : U32) (acc1 n_bia1 : U32)
    (h_d : 1 ≤ d ∧ d ≤ 12)
    (_h_count : coeffs_done.length + 1 ≤ 256)
    (h_inv : compressEncodeBitsInv d coeffs_done pb_dst cb_dst_written.val
              acc.val n_bia.val)
    /- Rust body output: no flush.  `nBits := min d (32 - n_bia)`. -/
    (h_no_flush : n_bia.val + d ≤ 31)
    /- The value OR'd is the d-bit compressed form of c. -/
    (h_acc1 : acc1.val = acc.val ||| ((fastCompress d c) <<< n_bia.val))
    (h_nbia1 : n_bia1.val = n_bia.val + d)
    (_h_c : c < q)
    /- Width bound on fastCompress: -/
    (h_fc_lt : fastCompress d c < 2 ^ d) :
    compressEncodeBitsInv d (coeffs_done ++ [c]) pb_dst
      cb_dst_written.val acc1.val n_bia1.val := by
  obtain ⟨h_cons, h_cb_le, h_nbia, h_cb_mod, h_bytes, h_acc, h_acc_zero⟩ := h_inv
  refine ⟨?_, h_cb_le, ?_, h_cb_mod, ?_, ?_, ?_⟩
  · -- Bit-conservation
    rw [List.length_append, List.length_singleton, Nat.add_mul, Nat.one_mul,
        h_cons, h_nbia1]
    ring
  · -- n_bia1 ≤ 31
    omega
  · -- Per-byte content unchanged on existing prefix.
    intros i hi j hj
    rw [compressBits_append_prefix _ _ _ _ (by
      have : 8 * i + j < 8 * cb_dst_written.val := by omega
      omega)]
    exact h_bytes i hi j hj
  · -- Per-acc-bit content tie at new n_bia1.
    intros j hj
    rw [h_acc1, Nat.testBit_or]
    by_cases h_low : j < n_bia.val
    · -- carried bits: same as old.
      have h_shift_zero : ((fastCompress d c) <<< n_bia.val).testBit j = false := by
        rw [Nat.testBit_shiftLeft]; simp; intro; omega
      rw [h_shift_zero, Bool.or_false, h_acc j h_low]
      rw [compressBits_append_prefix _ _ _ _ (by omega)]
    · -- new bits: from fastCompress
      push Not at h_low
      have h_old_zero : acc.val.testBit j = false := by
        rw [Bool.eq_false_iff]; exact h_acc_zero j h_low
      rw [h_old_zero, Bool.false_or, Nat.testBit_shiftLeft]
      rw [decide_eq_true_iff.mpr h_low]
      simp only [Bool.true_and]
      rw [compressBits_append_suffix _ _ _ _ (by omega)
                (by rw [Nat.add_mul, Nat.one_mul]; omega)]
      fcongr 1; omega
  · -- Acc high-bits-zero
    intros j hj
    rw [h_acc1, Nat.testBit_or]
    simp only [Bool.or_eq_true, not_or]
    refine ⟨?_, ?_⟩
    · exact h_acc_zero j (by omega)
    · -- ¬(fastCompress d c <<< n_bia).testBit j: j ≥ n_bia + d, fastCompress < 2^d.
      rw [Nat.testBit_shiftLeft]
      simp only [Bool.and_eq_true, decide_eq_true_eq]
      rintro ⟨_, h_tb⟩
      have h_ge : d ≤ j - n_bia.val := by omega
      have : (fastCompress d c).testBit (j - n_bia.val) = false :=
        Nat.testBit_eq_false_of_lt
          (Nat.lt_of_lt_of_le h_fc_lt (Nat.pow_le_pow_right (by omega) h_ge))
      exact absurd h_tb (by rw [this]; exact Bool.false_ne_true)

/-- **Compress-side `step_matches_body` (FLUSH branch).**

When `n_bia + n_bits_to_encode = 32`, the Rust body writes 4 LE bytes
of `acc1` to `pb_dst[cb_dst_written..cb_dst_written + 4]`, advances
`cb_dst_written` by 4, and (if `d > n_bits_to_encode`) loads the
remaining `d - n_bits_to_encode` high bits of the coefficient into a
fresh accumulator.  Mirrors Stream's `body` then-branch. -/
theorem step_matches_body_flush
    (d : ℕ) (coeffs_done : List ℕ) (c : ℕ) (pb_dst : Slice U8)
    (cb_dst_written cb_dst_written1 : Usize) (acc n_bia : U32)
    (acc1 n_bia1 : U32)
    (h_d : 1 ≤ d ∧ d ≤ 12)
    (h_inv : compressEncodeBitsInv d coeffs_done pb_dst cb_dst_written.val
              acc.val n_bia.val)
    (h_flush : n_bia.val + min d (32 - n_bia.val) = 32)
    (h_cb1 : cb_dst_written1.val = cb_dst_written.val + 4)
    (h_nbia1 : n_bia1.val = d - min d (32 - n_bia.val))
    (h_room : cb_dst_written.val + 4 ≤ pb_dst.length)
    (h_acc_full : ∀ j (_ : j < 32),
        (acc.val ||| ((fastCompress d c) <<< n_bia.val)).testBit j
          = (compressBits d (coeffs_done ++ [c])).getD
              (8 * cb_dst_written.val + j) false)
    (h_writes : ∀ i (_ : cb_dst_written.val ≤ i)
                  (_ : i < cb_dst_written.val + 4) j (_ : j < 8),
        ((pb_dst.val[i]?.getD 0#u8).val).testBit j
          = (acc.val ||| ((fastCompress d c) <<< n_bia.val)).testBit (8 * (i - cb_dst_written.val) + j))
    (h_old_bytes : ∀ i (_ : i < cb_dst_written.val) j (_ : j < 8),
        ((pb_dst.val[i]?.getD 0#u8).val).testBit j
          = (compressBits d coeffs_done).getD (8 * i + j) false)
    (h_acc1_eq : acc1.val = (fastCompress d c) >>> min d (32 - n_bia.val))
    (h_acc1_zero : ∀ j, n_bia1.val ≤ j → ¬ acc1.val.testBit j) :
    compressEncodeBitsInv d (coeffs_done ++ [c]) pb_dst
      cb_dst_written1.val acc1.val n_bia1.val := by
  obtain ⟨h_cons, h_cb_le, h_nbia_le, h_cb_mod, h_bytes, h_acc, h_acc_zero⟩ := h_inv
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, h_acc1_zero⟩
  · /- 1. Bit-conservation -/
    rw [List.length_append, List.length_singleton, h_nbia1, h_cb1,
        Nat.add_mul, Nat.one_mul]; omega
  · /- 2. cb_dst_written1 ≤ pb_dst.length -/
    rw [h_cb1]; exact h_room
  · /- 3. n_bia1 ≤ 31 -/
    rw [h_nbia1]; omega
  · /- 4. cb_dst_written1 % 4 = 0 -/
    rw [h_cb1]; omega
  · /- 5. Per-byte content -/
    intros i hi j hj
    rw [h_cb1] at hi
    by_cases h_old : i < cb_dst_written.val
    · rw [h_old_bytes i h_old j hj, compressBits_append_prefix]
      have : 8 * i + j < 8 * cb_dst_written.val := by omega
      omega
    · push Not at h_old
      rw [h_writes i h_old (by omega) j hj,
          h_acc_full (8 * (i - cb_dst_written.val) + j) (by omega)]
      fcongr 1; omega
  · /- 6. Per-acc-bit content tie -/
    intros j hj
    rw [h_acc1_eq, h_cb1, Nat.testBit_shiftRight]
    have h_idx : 8 * (cb_dst_written.val + 4) + j
        = coeffs_done.length * d + (min d (32 - n_bia.val) + j) := by omega
    have h_nBits_val : min d (32 - n_bia.val) = 32 - n_bia.val := by omega
    have h_hi_bound : 8 * (cb_dst_written.val + 4) + j
        < (coeffs_done.length + 1) * d := by
      rw [Nat.add_mul, Nat.one_mul]; rw [h_nBits_val] at h_nbia1; omega
    rw [compressBits_append_suffix d coeffs_done c
          (8 * (cb_dst_written.val + 4) + j)
          (by omega) h_hi_bound]
    fcongr 1; omega

/-- **Compress-side `step_matches_body` (umbrella).**

Top-level bridge: dispatches CARRY vs FLUSH on `n_bia + d ≤ 31`.

The Rust body of `poly_element_compress_and_encode_loop_body_prefix.spec`
emits **one** of the two output shapes depending on whether the
post-acc-OR `n_bia + nBits` reaches 32; the caller in
`Encoding/Compress.lean` materialises this disjunction and feeds it to
this lemma which then routes to the appropriate semantics chunk. -/
theorem step_matches_body_compress
    (d : ℕ) (coeffs_done : List ℕ) (c : ℕ) (pb_dst pb_dst1 : Slice U8)
    (cb_dst_written cb_dst_written1 : Usize) (acc n_bia acc1 n_bia1 : U32)
    (h_d : 1 ≤ d ∧ d ≤ 12)
    (h_count : coeffs_done.length + 1 ≤ 256)
    (h_inv : compressEncodeBitsInv d coeffs_done pb_dst cb_dst_written.val
              acc.val n_bia.val)
    (h_c : c < q)
    (h_fc_lt : fastCompress d c < 2 ^ d)
    /- Disjunction over Rust's two output shapes (one always holds). -/
    (h_dispatch :
        (/- CARRY: no flush; pb_dst unchanged, only acc/n_bia advance. -/
         n_bia.val + d ≤ 31 ∧
         pb_dst1 = pb_dst ∧
         cb_dst_written1 = cb_dst_written ∧
         acc1.val = acc.val ||| ((fastCompress d c) <<< n_bia.val) ∧
         n_bia1.val = n_bia.val + d)
      ∨ (/- FLUSH: 4 bytes written; cb advances by 4; leftover bits in acc. -/
         32 ≤ n_bia.val + d ∧
         pb_dst1 = pb_dst ∧
         cb_dst_written1.val = cb_dst_written.val + 4 ∧
         n_bia1.val = d - min d (32 - n_bia.val) ∧
         cb_dst_written.val + 4 ≤ pb_dst.length ∧
         (∀ j (_ : j < 32),
            (acc.val ||| ((fastCompress d c) <<< n_bia.val)).testBit j
              = (compressBits d (coeffs_done ++ [c])).getD
                  (8 * cb_dst_written.val + j) false) ∧
         (∀ i (_ : cb_dst_written.val ≤ i)
                (_ : i < cb_dst_written.val + 4) j (_ : j < 8),
            ((pb_dst1.val[i]?.getD 0#u8).val).testBit j
              = (acc.val ||| ((fastCompress d c) <<< n_bia.val)).testBit
                  (8 * (i - cb_dst_written.val) + j)) ∧
         (∀ i (_ : i < cb_dst_written.val) j (_ : j < 8),
            ((pb_dst1.val[i]?.getD 0#u8).val).testBit j
              = (compressBits d coeffs_done).getD (8 * i + j) false) ∧
         acc1.val = (fastCompress d c) >>> min d (32 - n_bia.val) ∧
         (∀ j, n_bia1.val ≤ j → ¬ acc1.val.testBit j))) :
    compressEncodeBitsInv d (coeffs_done ++ [c]) pb_dst1
      cb_dst_written1.val acc1.val n_bia1.val := by
  rcases h_dispatch with ⟨h_no_flush, h_pb_eq, h_cb_eq, h_acc1_eq, h_nbia1_eq⟩
                       | ⟨h_flush_ge, h_pb_eq, h_cb1, h_nbia1, h_room, h_acc_full,
                          h_writes, h_old_bytes, h_acc1_eq, h_acc1_zero⟩
  · -- CARRY branch
    have h_pb : pb_dst1 = pb_dst := h_pb_eq
    have h_cb : cb_dst_written1 = cb_dst_written := h_cb_eq
    rw [h_pb, h_cb]
    exact step_matches_body_carry d coeffs_done c pb_dst cb_dst_written
            acc n_bia acc1 n_bia1 h_d h_count h_inv h_no_flush
            h_acc1_eq h_nbia1_eq h_c h_fc_lt
  · /- FLUSH branch -/
    rw [h_pb_eq]
    have h_nbia_le : n_bia.val ≤ 31 := h_inv.2.2.1
    exact step_matches_body_flush d coeffs_done c pb_dst cb_dst_written
            cb_dst_written1 acc n_bia acc1 n_bia1
            h_d h_inv
            (by omega) h_cb1 h_nbia1 h_room
            h_acc_full (by rw [← h_pb_eq]; exact h_writes)
            (by rw [← h_pb_eq]; exact h_old_bytes)
            h_acc1_eq h_acc1_zero

/-! ### `matchesRuntime_step_compress` — direct per-iteration bridge

The outer-loop `_loop.spec` carries `matchesRuntime` (Stream↔Rust
correspondence) as its loop invariant.  The `step_matches_body_*`
bridges above work in `compressEncodeBitsInv` (testBit equations on
the Rust state alone, no Stream witness): they DON'T directly
compose with `matchesRuntime` because the Stream state they would
materialise is some witness `∃ s', matchesRuntime s' ...`, not the
specific `body d x s_in` step the outer loop needs.

This section provides the bridge that the outer loop ACTUALLY consumes:

```
matchesRuntime s_in (pb, cb, acc, n_bia) →
body_prefix output (per-bit equations on acc1) →
(CARRY xor FLUSH dispatch on n_bia + d = 32) →
matchesRuntime (body d x s_in) (pb', cb', acc', n_bia')
```

Decomposed by case (parallel to BitsInv versions):
* `matchesRuntime_step_compress_carry`  — no flush; pb unchanged.
* `matchesRuntime_step_compress_flush`  — 4 LE bytes written from acc1.
* `matchesRuntime_step_compress` (umbrella) — dispatches on `Or`.

These supersede the BitsInv-based `step_matches_body_*` lemmas for
outer-loop consumption.  The BitsInv lemmas remain valid and may be
used by future work that needs a Rust-only bit-content witness.

## Architectural note
The BitsInv layer carries Rust-side bit equations directly.  The
outer-loop spec, however, carries `matchesRuntime` (a Stream witness);
the `matchesRuntime_step_*` bridges below are the shape that loop
invariant consumes. -/

/-- Compress-side CARRY-arm bridge in `matchesRuntime`.

Takes the OR-form witness for `acc1` (rather than per-bit equations).
This shape is the right consumer of body_prefix.spec because the
underlying Rust code computes `accumulator1 := accumulator ||| (i3)`
directly (see L488 of body_prefix.spec's proof, which derives
`accumulator1.val = accumulator.val ||| i3.val`). -/
theorem matchesRuntime_step_compress_carry
    (d : ℕ) (s : CompressEncodeState) (x : ℕ)
    (pb_dst : Slice U8) (cb : Usize) (acc n_bia acc1 n_bia1 : U32)
    (h_d : 1 ≤ d ∧ d ≤ 12)
    (h_x : x < 2 ^ d)
    (h_match : CompressEncodeState.matchesRuntime s pb_dst cb acc n_bia)
    /- CARRY hypothesis: -/
    (h_no_flush : n_bia.val + d ≤ 31)
    /- OR-form witness: acc1 (as BitVec) equals acc ||| (x << n_bia).
       Caller derives this from `body_prefix.spec`'s per-bit posts +
       the OR-formula `accumulator1.val = accumulator.val ||| i3.val`
       (see L488 of body_prefix.spec's proof). -/
    (h_acc1_or :
        BitVec.ofNat 32 acc1.val
          = BitVec.ofNat 32 acc.val ||| ((BitVec.ofNat 32 x) <<< n_bia.val))
    (h_nbia1 : n_bia1.val = n_bia.val + d) :
    CompressEncodeState.matchesRuntime (CompressEncodeState.body d x s)
        pb_dst cb acc1 n_bia1 := by
  /- Condition-B residual.
     SHAPE OF PROOF:
       1. Unfold `body` and verify the if-branch (n_bia + d ≠ 32).
       2. matchesRuntime conjuncts at new state — most are unchanged
          from h_match; the key ones are #7 (acc equality) using
          h_acc1_or directly, and #8 (high-bits-zero) which follows
          from h_acc1_or + h_zero (on old acc) + h_x (high bits of x).
     STATUS: proof attempted; redesign passed the bridge signature
     test (OR-form is the right shape), but the BitVec/Nat bit
     manipulation for the high-bits-zero clause is fiddly.  The
     remaining work is ~40 LoC of careful bit chasing using
     `BitVec.getLsbD_or`, `BitVec.getLsbD_shiftLeft`,
     `BitVec.getLsbD_ofNat`, and the lemma
     `Nat.lt_of_testBit_eq_true_of_lt : x.testBit k = true → x < 2^k+1`. -/
  obtain ⟨h_blen, h_cb_le, h_bi, h_b_tie, h_acci, _h_nb_le, h_s_acc, h_zero⟩ := h_match
  -- Step 1: reduce `nBits = d` and clear the AND mask on `x`.
  have h_nb_eq : min d (32 - s.acci) = d := by rw [h_acci]; omega
  have h_pow_eq : (1 : ℕ) <<< d = 2 ^ d := by rw [Nat.shiftLeft_eq, Nat.one_mul]
  have h_mask : x &&& ((1 : ℕ) <<< d - 1) = x := by
    rw [h_pow_eq]; exact Nat.and_two_pow_sub_one_of_lt_two_pow h_x
  have h_acci_ne : s.acci + d ≠ 32 := by rw [h_acci]; omega
  -- Step 2: unfold `body`, expose the let chain, take the else branch.
  unfold CompressEncodeState.body CompressEncodeState.matchesRuntime
  simp only [h_nb_eq, h_mask, h_acci_ne, if_false]
  -- Step 3: prepare the BitVec equation we need for conjunct #7.
  have h_acc_or_eq :
      s.acc ||| ((BitVec.ofNat 32 x) <<< s.acci) = BitVec.ofNat 32 acc1.val := by
    rw [h_s_acc, h_acci, ← h_acc1_or]
  -- Step 4: bounds and acci alignment.
  have h_nbia1_le : n_bia1.val ≤ 32 := by rw [h_nbia1]; omega
  have h_acci_new : s.acci + d = n_bia1.val := by rw [h_nbia1, h_acci]
  -- Step 5: discharge each `matchesRuntime` conjunct.
  refine ⟨h_blen, h_cb_le, h_bi, h_b_tie, h_acci_new, h_nbia1_le, h_acc_or_eq, ?_⟩
  -- high-bits-zero on the new acc = s.acc ||| (BitVec.ofNat 32 x) <<< s.acci.
  intro j hj
  rw [BitVec.getLsbD_or, BitVec.getLsbD_shiftLeft, BitVec.getLsbD_ofNat]
  have h_acc_bit : ¬ s.acc.getLsbD j := h_zero j (by omega)
  have h_x_bit : ¬ x.testBit (j - s.acci) := by
    have hge : d ≤ j - s.acci := by omega
    have hxlt : x < 2 ^ (j - s.acci) :=
      lt_of_lt_of_le h_x (Nat.pow_le_pow_right (by decide) hge)
    rw [Nat.testBit_lt_two_pow hxlt]; decide
  simp only [h_acc_bit, h_x_bit, Bool.and_false, Bool.or_false,
    ]
  decide

/-- Compress-side FLUSH-arm bridge in `matchesRuntime`. -/
theorem matchesRuntime_step_compress_flush
    (d : ℕ) (s : CompressEncodeState) (x : ℕ)
    (pb_dst pb_dst1 : Slice U8) (cb cb1 : Usize)
    (acc n_bia acc_or acc1 n_bia1 : U32)
    (h_d : 1 ≤ d ∧ d ≤ 12)
    (h_x : x < 2 ^ d)
    (h_match : CompressEncodeState.matchesRuntime s pb_dst cb acc n_bia)
    /- FLUSH hypothesis. -/
    (h_flush : n_bia.val + d ≥ 32)
    /- body_prefix output: the OR'd register `acc_or` before flush. -/
    (h_acc_or_new : ∀ (j : ℕ), j < (32 - n_bia.val) →
        acc_or.val.testBit (n_bia.val + j) = x.testBit j)
    (h_acc_or_old : ∀ (j : ℕ), j < n_bia.val →
        acc_or.val.testBit j = acc.val.testBit j)
    /- The 4 byte writes to pb_dst[cb..cb+4]. -/
    (h_pb_dst1_len : pb_dst1.length = pb_dst.length)
    (h_pb_dst1_old : ∀ (k : ℕ), k < cb.val →
        pb_dst1.val[k]?.getD 0#u8 = pb_dst.val[k]?.getD 0#u8)
    (_h_pb_dst1_old_hi : ∀ (k : ℕ), cb.val + 4 ≤ k → k < pb_dst1.val.length →
        pb_dst1.val[k]?.getD 0#u8 = pb_dst.val[k]?.getD 0#u8)
    (h_pb_dst1_new : ∀ (i : ℕ), i < 4 →
        (pb_dst1.val[cb.val + i]?.getD 0#u8).bv
          = (BitVec.ofNat 32 acc_or.val).toLEBytes[i]!)
    /- Post-flush state. -/
    (h_cb1 : cb1.val = cb.val + 4)
    (h_acc1 : acc1.val = x >>> (32 - n_bia.val))
    (h_nbia1 : n_bia1.val = d - (32 - n_bia.val))
    (h_room : cb.val + 4 ≤ pb_dst.length) :
    CompressEncodeState.matchesRuntime (CompressEncodeState.body d x s)
        pb_dst1 cb1 acc1 n_bia1 := by
  -- Step 1: extract matchesRuntime conjuncts.
  obtain ⟨h_blen, h_cb_le, h_bi, h_b_tie, h_acci, _h_nb_le, h_s_acc, h_zero⟩ := h_match
  -- Step 2: identify `nBits = 32 - s.acci` and the if-condition fires.
  have h_nb_eq : min d (32 - s.acci) = 32 - s.acci := by rw [h_acci]; omega
  have h_acci1_eq : s.acci + (32 - s.acci) = 32 := by rw [h_acci]; omega
  have h_acci_le : s.acci ≤ 32 := by rw [h_acci]; omega
  -- The body's masked x term simplifies because we keep only the low (32 - s.acci) bits.
  set bits_kept : ℕ := x &&& ((1 : ℕ) <<< (32 - s.acci) - 1) with h_bits_kept_def
  set acc1' : BitVec 32 := s.acc ||| ((BitVec.ofNat 32 bits_kept) <<< s.acci)
    with h_acc1'_def
  -- Step 3: prove acc1' = BitVec.ofNat 32 acc_or.val via bit-by-bit equality.
  have h_acc1_or_bv : acc1' = BitVec.ofNat 32 acc_or.val := by
    apply BitVec.eq_of_getLsbD_eq
    intro k hk32
    rw [h_acc1'_def, BitVec.getLsbD_or, BitVec.getLsbD_shiftLeft]
    -- Reduce the RHS via getLsbD_ofNat.
    have h_rhs : (BitVec.ofNat 32 acc_or.val).getLsbD k = acc_or.val.testBit k := by
      rw [BitVec.getLsbD_ofNat]; simp [hk32]
    rw [h_rhs]
    by_cases hks : k < s.acci
    · -- low half: bit comes from old acc; use h_acc_or_old.
      have hks' : ¬ s.acci ≤ k := Nat.not_le.mpr hks
      have h_s_bit : s.acc.getLsbD k = acc.val.testBit k := by
        rw [h_s_acc, BitVec.getLsbD_ofNat]; simp [hk32]
      have h_old_bit : acc.val.testBit k = acc_or.val.testBit k :=
        (h_acc_or_old k (h_acci ▸ hks)).symm
      rw [h_s_bit, h_old_bit]
      -- The shifted disjunct: !decide (k < s.acci) is false.
      simp [hks]
    · -- high half: bit comes from x; use h_acc_or_new.
      push Not at hks
      have h_zero_k : s.acc.getLsbD k = false := by
        rw [Bool.eq_false_iff]; exact h_zero k hks
      rw [h_zero_k, Bool.false_or]
      have hk_minus : k - s.acci < 32 - s.acci := by omega
      have h_kept_bit : (BitVec.ofNat 32 bits_kept).getLsbD (k - s.acci)
          = x.testBit (k - s.acci) := by
        rw [BitVec.getLsbD_ofNat, h_bits_kept_def, Nat.testBit_and]
        have h_mask_bit : ((1 : ℕ) <<< (32 - s.acci) - 1).testBit (k - s.acci) = true := by
          rw [show ((1 : ℕ) <<< (32 - s.acci) - 1) = 2 ^ (32 - s.acci) - 1 by
                rw [Nat.shiftLeft_eq, Nat.one_mul]]
          rw [Nat.testBit_two_pow_sub_one]
          simp [hk_minus]
        rw [h_mask_bit, Bool.and_true]
        have : k - s.acci < 32 := by omega
        simp [this]
      have h_acc_or_bit : acc_or.val.testBit k = x.testBit (k - s.acci) := by
        have hk_minus' : k - n_bia.val < 32 - n_bia.val := by rw [← h_acci]; exact hk_minus
        have h_new := h_acc_or_new (k - n_bia.val) hk_minus'
        have h_idx : n_bia.val + (k - n_bia.val) = k := by rw [← h_acci]; omega
        rw [h_idx] at h_new
        rw [h_new, h_acci]
      rw [h_kept_bit, h_acc_or_bit]
      have hks' : ¬ k < s.acci := Nat.not_lt.mpr hks
      simp [hks', hk32]
  -- Step 4: unfold body, take the if-branch.
  unfold CompressEncodeState.body CompressEncodeState.matchesRuntime
  simp only [h_nb_eq, h_acci1_eq, ↓reduceIte]
  refine ⟨?b_len, ?cb_le, ?bi_eq, ?b_tie, ?acci_eq, ?nbia_le, ?acc_eq, ?zero⟩
  case b_len =>
    simp only [List.length_set]
    rw [h_blen, h_pb_dst1_len]
  case cb_le =>
    rw [h_cb1, h_pb_dst1_len]; exact h_room
  case bi_eq =>
    rw [h_bi, h_cb1]
  case b_tie =>
    intro k hk
    by_cases h_klo : k < s.bi
    · -- prefix: untouched by all 4 sets.
      have h_ne0 : s.bi ≠ k := by omega
      have h_ne1 : s.bi + 1 ≠ k := by omega
      have h_ne2 : s.bi + 2 ≠ k := by omega
      have h_ne3 : s.bi + 3 ≠ k := by omega
      simp only [List.getD, List.getElem?_set_ne h_ne3, List.getElem?_set_ne h_ne2,
        List.getElem?_set_ne h_ne1, List.getElem?_set_ne h_ne0]
      have h_kcb : k < cb.val := h_bi ▸ h_klo
      show s.b[k]?.getD 0#8 = (pb_dst1.val.getD k 0#u8).bv
      have h_b_tie_k := h_b_tie k h_kcb
      simp only [List.getD] at h_b_tie_k
      rw [h_b_tie_k]
      show ((pb_dst.val)[k]?.getD 0#u8).bv = (pb_dst1.val.getD k 0#u8).bv
      have h_old := h_pb_dst1_old k h_kcb
      simp only [List.getD]
      rw [h_old]
    · -- k ∈ [s.bi, cb1.val) = [s.bi, s.bi + 4): one of the 4 writes.
      push Not at h_klo
      have h_khi : k < s.bi + 4 := by rw [h_bi, ← h_cb1]; exact hk
      have h_pi_lt : k < s.b.length := by rw [h_blen]; rw [h_bi] at h_klo h_khi; omega
      -- Local helper: BitVec.setWidth 8 (v >>> (8*i)) = v.toLEBytes[i]! for i < 4.
      have h_byte_eq : ∀ (v : BitVec 32) (i : ℕ), i < 4 →
          BitVec.setWidth 8 (v >>> (8 * i)) = v.toLEBytes[i]! := by
        intro v i hi
        apply BitVec.eq_of_getLsbD_eq
        intro j hj
        rw [BitVec.getLsbD_setWidth, BitVec.getLsbD_ushiftRight]
        show (decide (j < 8) && v.getLsbD (8 * i + j)) = v.toLEBytes[i]!.testBit j
        rw [BitVec.toLEBytes_getElem!_testBit _ _ _ hj]
        have h_bnd : 8 * i + j < 32 := by omega
        rw [BitVec.getElem!_eq_getElem (hi := h_bnd)]
        show (decide (j < 8) && v.getLsbD (8 * i + j)) = v[8 * i + j]
        rw [BitVec.getElem_eq_testBit_toNat, BitVec.testBit_toNat]
        simp [hj]
      obtain h_keq | h_keq | h_keq | h_keq :
          k = s.bi ∨ k = s.bi + 1 ∨ k = s.bi + 2 ∨ k = s.bi + 3 := by omega
      · -- k = s.bi: written by FIRST .set; outer sets at +3, +2, +1 don't touch.
        subst h_keq
        simp only [List.getD]
        rw [List.getElem?_set_ne (by omega), List.getElem?_set_ne (by omega),
            List.getElem?_set_ne (by omega), List.getElem?_set_self (by omega)]
        have h_new := h_pb_dst1_new 0 (by decide)
        simp only [Nat.add_zero] at h_new
        show BitVec.setWidth 8 acc1' = (pb_dst1.val.getD s.bi 0#u8).bv
        rw [h_bi]
        simp only [List.getD]
        rw [h_new, h_acc1_or_bv]
        have := h_byte_eq (BitVec.ofNat 32 acc_or.val) 0 (by decide)
        simpa using this
      · -- k = s.bi + 1
        subst h_keq
        simp only [List.getD]
        rw [List.getElem?_set_ne (by omega), List.getElem?_set_ne (by omega),
            List.getElem?_set_self (by simp only [List.length_set]; omega)]
        have h_new := h_pb_dst1_new 1 (by decide)
        show BitVec.setWidth 8 (acc1' >>> 8) = (pb_dst1.val.getD (s.bi + 1) 0#u8).bv
        rw [h_bi]
        simp only [List.getD]
        rw [h_new, h_acc1_or_bv]
        exact h_byte_eq (BitVec.ofNat 32 acc_or.val) 1 (by decide)
      · -- k = s.bi + 2
        subst h_keq
        simp only [List.getD]
        rw [List.getElem?_set_ne (by omega),
            List.getElem?_set_self (by simp only [List.length_set]; omega)]
        have h_new := h_pb_dst1_new 2 (by decide)
        show BitVec.setWidth 8 (acc1' >>> 16) = (pb_dst1.val.getD (s.bi + 2) 0#u8).bv
        rw [h_bi]
        simp only [List.getD]
        rw [h_new, h_acc1_or_bv]
        exact h_byte_eq (BitVec.ofNat 32 acc_or.val) 2 (by decide)
      · -- k = s.bi + 3
        subst h_keq
        simp only [List.getD]
        rw [List.getElem?_set_self (by simp only [List.length_set]; omega)]
        have h_new := h_pb_dst1_new 3 (by decide)
        show BitVec.setWidth 8 (acc1' >>> 24) = (pb_dst1.val.getD (s.bi + 3) 0#u8).bv
        rw [h_bi]
        simp only [List.getD]
        rw [h_new, h_acc1_or_bv]
        exact h_byte_eq (BitVec.ofNat 32 acc_or.val) 3 (by decide)
  case acci_eq =>
    rw [h_nbia1, h_acci]
  case nbia_le =>
    rw [h_nbia1]; omega
  case acc_eq =>
    rw [h_acci, h_acc1]
  case zero =>
    intro j hj
    rw [BitVec.getLsbD_ofNat]
    have h_xtest : (x >>> (32 - s.acci)).testBit j = false := by
      rw [Nat.testBit_shiftRight]
      have h_ge : d ≤ 32 - s.acci + j := by omega
      have hxlt : x < 2 ^ (32 - s.acci + j) :=
        lt_of_lt_of_le h_x (Nat.pow_le_pow_right (by decide) h_ge)
      exact Nat.testBit_lt_two_pow hxlt
    rw [h_xtest, Bool.and_false]
    decide

/-- Compress-side `matchesRuntime` umbrella step.  Direct outer-loop
consumer.  Dispatches CARRY vs FLUSH on `Or` hypothesis. -/
theorem matchesRuntime_step_compress
    (d : ℕ) (s : CompressEncodeState) (x : ℕ)
    (pb_dst pb_dst1 : Slice U8) (cb cb1 : Usize)
    (acc n_bia acc1 n_bia1 : U32)
    (h_d : 1 ≤ d ∧ d ≤ 12)
    (h_x : x < 2 ^ d)
    (h_match : CompressEncodeState.matchesRuntime s pb_dst cb acc n_bia)
    (h_room : cb.val + 4 ≤ pb_dst.length)
    (h_dispatch :
       (/- CARRY -/
        n_bia.val + d ≤ 31 ∧ pb_dst1 = pb_dst ∧ cb1 = cb ∧
        BitVec.ofNat 32 acc1.val
          = BitVec.ofNat 32 acc.val ||| ((BitVec.ofNat 32 x) <<< n_bia.val) ∧
        n_bia1.val = n_bia.val + d)
     ∨ (/- FLUSH -/
        ∃ (acc_or : U32),
          n_bia.val + d ≥ 32 ∧
          (∀ (j : ℕ), j < (32 - n_bia.val) →
              acc_or.val.testBit (n_bia.val + j) = x.testBit j) ∧
          (∀ (j : ℕ), j < n_bia.val →
              acc_or.val.testBit j = acc.val.testBit j) ∧
          pb_dst1.length = pb_dst.length ∧
          (∀ (k : ℕ), k < cb.val →
              pb_dst1.val[k]?.getD 0#u8 = pb_dst.val[k]?.getD 0#u8) ∧
          (∀ (k : ℕ), cb.val + 4 ≤ k → k < pb_dst1.val.length →
              pb_dst1.val[k]?.getD 0#u8 = pb_dst.val[k]?.getD 0#u8) ∧
          (∀ (i : ℕ), i < 4 →
              (pb_dst1.val[cb.val + i]?.getD 0#u8).bv
                = (BitVec.ofNat 32 acc_or.val).toLEBytes[i]!) ∧
          cb1.val = cb.val + 4 ∧
          acc1.val = x >>> (32 - n_bia.val) ∧
          n_bia1.val = d - (32 - n_bia.val))) :
    CompressEncodeState.matchesRuntime (CompressEncodeState.body d x s)
        pb_dst1 cb1 acc1 n_bia1 := by
  rcases h_dispatch with
    ⟨h_no_flush, h_pb_eq, h_cb_eq, h_acc1_or, h_nbia1⟩
  | ⟨acc_or, h_flush, h_new, h_old, h_pb_len, h_pb_old, h_pb_old_hi, h_pb_new,
     h_cb1, h_acc1, h_nbia1⟩
  · -- CARRY: pb_dst1 = pb_dst, cb1 = cb
    rw [h_pb_eq, h_cb_eq]
    exact matchesRuntime_step_compress_carry d s x pb_dst cb acc n_bia acc1
            n_bia1 h_d h_x h_match h_no_flush h_acc1_or h_nbia1
  · -- FLUSH
    exact matchesRuntime_step_compress_flush d s x pb_dst pb_dst1 cb cb1
            acc n_bia acc_or acc1 n_bia1 h_d h_x h_match h_flush h_new
            h_old h_pb_len h_pb_old h_pb_old_hi h_pb_new h_cb1 h_acc1
            h_nbia1 h_room

/-! ## Compress-encode wrapper at the polynomial level -/

/-- Convert a `Zq` coefficient to its already-compressed `Nat` form.

For `d < 12`, this is the `fastCompress` bit-shift formula (equal to
`(MLKEM.Compress d c).val` via `fastCompress_eq_spec_compress`).
For `d = 12`, no compression occurs (`m 12 = q`), so we return the
canonical representative.

In both cases the result is in `[0, 2^d)`. -/
def coeffToEncode (d : ℕ) (c : Zq) : ℕ :=
  if d < 12 then fastCompress d c.val else c.val

/-- Stream form of `poly_element_compress_and_encode`.

Run `recBody` over the 256 already-compressed coefficient values of
`F`, starting from an empty stream state.  The output buffer is
exactly `32 * d` bytes.

This definition matches `Stream.compressOpt_encode d 4` from the
prior development (`prior/StreamEncode.lean` end of file). -/
def streamCompressEncodePoly (d : ℕ) (F : MLKEM.Polynomial) : List Byte :=
  let xs : List ℕ :=
    (Vector.ofFn (fun i : Fin 256 => coeffToEncode d (F.get i))).toList
  (CompressEncodeState.recBody d xs (CompressEncodeState.init d)).b

/-! ## Bridge 1 (compress side): Stream ↔ FIPS -/

/-! ### Per-bit characterization of `compressEncodePoly`

This lifts `byteEncode_byte_invariant` through the `Polynomial.Compress`
prefix (resp. `d=12` identity cast) to give a uniform per-bit
characterization expressed in terms of `coeffToEncode`. -/

private theorem coeffToEncode_eq_compress_val_d_lt_12
    (d : ℕ) (h_d : 1 ≤ d ∧ d < 12) (c : MLKEM.Zq) :
    coeffToEncode d c = (MLKEM.Compress d c).val := by
  unfold coeffToEncode
  simp only [h_d.2, if_true]
  have h_c : c.val < MLKEM.q := ZMod.val_lt _
  have := fastCompress_eq_spec_compress d c.val ⟨h_d.1, h_d.2⟩ h_c
  have h_cast : ((c.val : ℕ) : MLKEM.Zq) = c := by
    exact ZMod.natCast_zmod_val c
  rw [this, h_cast]

private theorem coeffToEncode_lt_two_pow (d : ℕ) (h_d : 1 ≤ d ∧ d ≤ 12)
    (c : MLKEM.Zq) :
    coeffToEncode d c < 2 ^ d := by
  unfold coeffToEncode
  split_ifs with h
  · unfold fastCompress
    exact Nat.mod_lt _ (Nat.two_pow_pos d)
  · have h12 : d = 12 := by omega
    subst h12
    have h_c : c.val < MLKEM.q := ZMod.val_lt _
    have : MLKEM.q < 2 ^ 12 := by decide
    exact lt_of_lt_of_le h_c (le_of_lt this)

/-- The "compressed polynomial" fed into `ByteEncode` by
`compressEncodePoly`: for `d < 12` it is `Polynomial.Compress d F`; at
`d = 12` it is `F` cast through `MLKEM.q = MLKEM.m 12`.  In both cases
each coefficient's `val` equals `coeffToEncode d (F.get i)`. -/
private def compressedF (d : ℕ) (F : MLKEM.Polynomial) (h_d : 1 ≤ d ∧ d ≤ 12) :
    MLKEM.Polynomial (MLKEM.m d) :=
  if h : d < 12 then MLKEM.Polynomial.Compress d F ⟨h_d.1, h⟩
  else
    have heq : MLKEM.q = MLKEM.m d := by
      have h12 : d = 12 := by omega
      subst h12; simp [MLKEM.m]
    heq ▸ F

private theorem compressEncodePoly_eq_byteEncode_compressedF
    (d : ℕ) (F : MLKEM.Polynomial) (h_d : 1 ≤ d ∧ d ≤ 12) :
    compressEncodePoly d F h_d = MLKEM.ByteEncode d (compressedF d F h_d) h_d := by
  unfold compressEncodePoly compressedF
  by_cases h12 : d < 12
  · simp only [h12, dif_pos]
  · simp only [h12, dif_neg, not_false_eq_true]

private theorem compressedF_val
    (d : ℕ) (F : MLKEM.Polynomial) (h_d : 1 ≤ d ∧ d ≤ 12)
    (i : ℕ) (h_i : i < 256) :
    ((compressedF d F h_d).get ⟨i, h_i⟩).val = coeffToEncode d (F.get ⟨i, h_i⟩) := by
  unfold compressedF
  by_cases h12 : d < 12
  · simp only [h12, dif_pos]
    show ((F.map (fun x => MLKEM.Compress d x ⟨h_d.1, h12⟩)).get ⟨i, h_i⟩).val
        = coeffToEncode d (F.get ⟨i, h_i⟩)
    show ((F.map (fun x => MLKEM.Compress d x ⟨h_d.1, h12⟩))[i]'h_i).val
        = coeffToEncode d (F[i]'h_i)
    rw [Vector.getElem_map]
    rw [coeffToEncode_eq_compress_val_d_lt_12 d ⟨h_d.1, h12⟩]
  · simp only [h12, dif_neg, not_false_eq_true]
    have hd12 : d = 12 := by omega
    have h_cte : coeffToEncode d (F.get ⟨i, h_i⟩) = (F.get ⟨i, h_i⟩).val := by
      unfold coeffToEncode
      simp only [h12, if_false]
    rw [h_cte]
    subst hd12
    rfl

/-- Per-bit characterization of `compressEncodePoly`. -/
theorem compressEncodePoly_testBit (d : ℕ) (F : MLKEM.Polynomial)
    (h_d : 1 ≤ d ∧ d ≤ 12)
    (k : ℕ) (h_k : k < 32 * d) (j : ℕ) (h_j : j < 8) :
    haveI h_idx : (8 * k + j) / d < 256 := byteEncode_idx_bound h_d.1 h_d.2 h_k h_j
    ((compressEncodePoly d F h_d)[k]'h_k).toNat.testBit j
      = (coeffToEncode d (F[(8 * k + j) / d]'h_idx)).testBit ((8 * k + j) % d) := by
  have h_idx : (8 * k + j) / d < 256 := byteEncode_idx_bound h_d.1 h_d.2 h_k h_j
  rw [compressEncodePoly_eq_byteEncode_compressedF]
  rw [show ((MLKEM.ByteEncode d (compressedF d F h_d) h_d)[k]'h_k)
          = (MLKEM.ByteEncode d (compressedF d F h_d) h_d).get ⟨k, h_k⟩
        from rfl,
     byteEncode_byte_invariant d h_d (compressedF d F h_d) k h_k j h_j,
     compressedF_val d F h_d _ h_idx]
  rfl

/-! ### Partial stream / FIPS-bit invariant (compress side)

After processing `i` coefficients with `recBody`, the stream state's
byte buffer `s.b[0..s.bi)` agrees byte-for-byte with the FIPS output
on the same prefix, and the low `s.acci` bits of `s.acc` carry the
next FIPS bits `[8*s.bi, 8*s.bi + s.acci) = [d*i − acci, d*i)`. -/

/-- The FIPS bit at position `n` of the encoded buffer (as a bit-array
of length `256 * d`).  Returns `false` outside the valid range. -/
def fipsBit (d : ℕ) (F : MLKEM.Polynomial) (n : ℕ) : Bool :=
  if h : n / d < 256 then
    Nat.testBit (coeffToEncode d (F.get ⟨n / d, h⟩)) (n % d)
  else
    false

/-- The partial invariant carried by induction.  Uses `.getD` to avoid
threading bound proofs into the predicate body. -/
def streamCompressEncodePartial
    (d : ℕ) (F : MLKEM.Polynomial) (_h_d : 1 ≤ d ∧ d ≤ 12)
    (i : ℕ) (s : CompressEncodeState) : Prop :=
  CompressEncodeState.length_inv d s i ∧
  /- Bytes already flushed match the FIPS bits. -/
  (∀ (k : ℕ), k < s.bi → ∀ (j : ℕ), j < 8 →
      (s.b.getD k 0#8).toNat.testBit j = fipsBit d F (8 * k + j)) ∧
  /- Acc low bits match the next FIPS bits. -/
  (∀ (j : ℕ), j < s.acci → s.acc.getLsbD j = fipsBit d F (8 * s.bi + j)) ∧
  /- Acc high bits zero (mirrors body_high_bits_zero). -/
  (∀ (j : ℕ), s.acci ≤ j → ¬ s.acc.getLsbD j)
/-! ### Bridge 1 (compress) — supporting lemmas -/

/-- Bit `j` of the LE byte `m` of a 32-bit register `v` (`m < 4`,
`j < 8`) equals bit `8*m + j` of `v`.  Used in the FLUSH arm of
`body_streamCompressEncodePartial`. -/
private theorem flush_byte_setWidth_bit (v : BitVec 32) (m : ℕ) (_h_m : m < 4)
    (j : ℕ) (h_j : j < 8) :
    (BitVec.setWidth 8 (v >>> (8 * m))).toNat.testBit j = v.getLsbD (8 * m + j) := by
  rw [BitVec.testBit_toNat]
  rw [BitVec.getLsbD_setWidth, BitVec.getLsbD_ushiftRight]
  simp [h_j]

/-- Base case: `init d` satisfies the partial invariant at `i = 0`.
All quantifiers are vacuous over the empty bit range. -/
private theorem init_streamCompressEncodePartial
    (d : ℕ) (F : MLKEM.Polynomial) (h_d : 1 ≤ d ∧ d ≤ 12) :
    streamCompressEncodePartial d F h_d 0
        (CompressEncodeState.init d) := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · -- length_inv at i=0
    refine ⟨?_, ?_, ?_, ?_⟩
    · simp [CompressEncodeState.init]
    · omega
    · simp [CompressEncodeState.init]
    · simp [CompressEncodeState.init]
  · -- bytes match: vacuous (k < 0)
    intros k hk; simp [CompressEncodeState.init] at hk
  · -- acc low bits match: vacuous (j < 0)
    intros j hj; simp [CompressEncodeState.init] at hj
  · -- acc high bits zero: all bits of 0#32 are false
    intros j _; simp [CompressEncodeState.init]

/-- Arithmetic consequence of `length_inv`: `8*bi + acci = d*i`. -/
private theorem length_inv_bi_acci_sum (d : ℕ) (s : CompressEncodeState) (i : ℕ)
    (h_inv : CompressEncodeState.length_inv d s i) :
    8 * s.bi + s.acci = d * i := by
  obtain ⟨_, _, h_bi, h_acci⟩ := h_inv
  rw [h_bi, h_acci]
  have h := Nat.div_add_mod (d * i) 32
  omega

/-- `fipsBit` at a position inside coefficient `i`: bit `p < d` of
the encoded value at index `d*i + p` equals `(coeffToEncode d F[i]).testBit p`. -/
private theorem fipsBit_within_coeff
    (d : ℕ) (F : MLKEM.Polynomial) (h_d : 1 ≤ d ∧ d ≤ 12)
    (i : ℕ) (h_i : i < 256) (p : ℕ) (h_p : p < d) :
    fipsBit d F (d * i + p) = (coeffToEncode d (F.get ⟨i, h_i⟩)).testBit p := by
  unfold fipsBit
  have h_dpos : 0 < d := h_d.1
  have h_div : (d * i + p) / d = i := by
    rw [Nat.mul_add_div h_dpos]
    simp [Nat.div_eq_of_lt h_p]
  have h_mod : (d * i + p) % d = p := by
    rw [Nat.mul_add_mod, Nat.mod_eq_of_lt h_p]
  have h_idx : (d * i + p) / d < 256 := by rw [h_div]; exact h_i
  rw [dif_pos h_idx, h_mod]
  have h_fin : (⟨(d * i + p) / d, h_idx⟩ : Fin 256) = ⟨i, h_i⟩ := Fin.ext h_div
  rw [h_fin]

/-- Inductive step: `body d (coeffToEncode d F[i]) s` preserves the
partial invariant. -/
private theorem body_streamCompressEncodePartial
    (d : ℕ) (F : MLKEM.Polynomial) (h_d : 1 ≤ d ∧ d ≤ 12)
    (i : ℕ) (h_i : i < 256) (s : CompressEncodeState)
    (h_inv : streamCompressEncodePartial d F h_d i s) :
    streamCompressEncodePartial d F h_d (i + 1)
        (CompressEncodeState.body d (coeffToEncode d (F.get ⟨i, h_i⟩)) s) := by
  set x := coeffToEncode d (F.get ⟨i, h_i⟩) with hx_def
  have h_x : x < 2 ^ d := coeffToEncode_lt_two_pow d h_d _
  obtain ⟨h_len, h_bytes, h_acc, h_zero⟩ := h_inv
  have h_acci_le : s.acci ≤ 32 := by
    have h := h_len.2.2.2; rw [h]
    have : (d * i) % 32 < 32 := Nat.mod_lt _ (by decide)
    omega
  have h_arith : 8 * s.bi + s.acci = d * i := length_inv_bi_acci_sum d s i h_len
  have h_len' : CompressEncodeState.length_inv d (CompressEncodeState.body d x s) (i + 1) :=
    CompressEncodeState.body_length_inv d x s i h_d h_i h_len
  have h_zero' : ∀ j, (CompressEncodeState.body d x s).acci ≤ j →
      ¬ (CompressEncodeState.body d x s).acc.getLsbD j :=
    CompressEncodeState.body_high_bits_zero d x s h_d h_x h_acci_le h_zero
  set nBits := min d (32 - s.acci) with hnBits
  have h_nBits_le_d : nBits ≤ d := Nat.min_le_left _ _
  have h_nBits_le_rem : nBits ≤ 32 - s.acci := Nat.min_le_right _ _
  -- Helper: extracted body fields
  have h_body_bi := CompressEncodeState.body_bi d x s
  have h_body_acc := CompressEncodeState.body_acc d x s
  have h_body_acci := CompressEncodeState.body_acci d x s
  by_cases h_flush : s.acci + nBits = 32
  · -- FLUSH arm
    have h_nBits_eq : nBits = 32 - s.acci := by
      have h1 := h_nBits_le_rem
      have h2 : 32 - s.acci ≤ nBits := by omega
      omega
    rw [if_pos h_flush] at h_body_bi h_body_acc h_body_acci
    refine ⟨h_len', ?_, ?_, h_zero'⟩
    · -- Bytes match: ∀ k < bi+4, ∀ j < 8, …
      intro k h_k j h_j
      rw [h_body_bi] at h_k
      -- Abbreviate the flushed accumulator
      set acc1 : BitVec 32 :=
        s.acc ||| (BitVec.ofNat 32 (x &&& ((1 <<< nBits) - 1))) <<< s.acci with h_acc1_def
      have h_b_eq : (CompressEncodeState.body d x s).b =
          (((s.b.set s.bi (BitVec.setWidth 8 acc1)).set
              (s.bi + 1) (BitVec.setWidth 8 (acc1 >>> 8))).set
              (s.bi + 2) (BitVec.setWidth 8 (acc1 >>> 16))).set
              (s.bi + 3) (BitVec.setWidth 8 (acc1 >>> 24)) := by
        unfold CompressEncodeState.body
        dsimp only
        rw [if_pos h_flush]
      -- We need s.bi + 4 ≤ s.b.length so each .set is in-range
      have h_bi_lt : s.bi + 4 ≤ s.b.length := by
        have h_bi_eq : s.bi = 4 * ((d * i) / 32) := h_len.2.2.1
        have h_acci_eq : s.acci = (d * i) % 32 := h_len.2.2.2
        have h_32_sub_acci_le : 32 - s.acci ≤ d := by rw [← h_nBits_eq]; exact h_nBits_le_d
        have h_di_d_le : d * i + d ≤ d * 256 := by nlinarith [h_i]
        have h_arith2 : 8 * (s.bi + 4) ≤ d * i + d := by omega
        have h_blen_ge : 32 * d ≤ s.b.length := h_len.1
        omega
      -- Helper: bits of acc1 match fipsBit at the proper offset, for p < 32
      have h_acc1_bit : ∀ (p : ℕ), p < 32 →
          acc1.getLsbD p = fipsBit d F (8 * s.bi + p) := by
        intro p h_p
        rw [h_acc1_def, BitVec.getLsbD_or]
        by_cases h_p_lt_acci : p < s.acci
        · have h_shift_zero :
              ((BitVec.ofNat 32 (x &&& ((1 <<< nBits) - 1))) <<< s.acci).getLsbD p = false := by
            rw [BitVec.getLsbD_shiftLeft]
            have h_not : (!decide (p < s.acci)) = false := by simp [h_p_lt_acci]
            rw [h_not, Bool.and_false, Bool.false_and]
          rw [h_shift_zero, Bool.or_false]
          exact h_acc p h_p_lt_acci
        · have h_p_ge : s.acci ≤ p := Nat.le_of_not_lt h_p_lt_acci
          have h_acc_zero : s.acc.getLsbD p = false := by
            have := h_zero p h_p_ge
            simpa using this
          rw [h_acc_zero, Bool.false_or]
          rw [BitVec.getLsbD_shiftLeft, BitVec.getLsbD_ofNat]
          have h_p_sub_lt_32 : p - s.acci < 32 := by omega
          have h_notdec : (!decide (p < s.acci)) = true := by simp [h_p_lt_acci]
          have h_dec32 : decide (p < 32) = true := decide_eq_true h_p
          have h_decsub32 : decide (p - s.acci < 32) = true := decide_eq_true h_p_sub_lt_32
          rw [h_notdec, h_dec32, h_decsub32]
          simp only [Bool.true_and]
          rw [Nat.testBit_and]
          have h_psub_lt_nBits : p - s.acci < nBits := by rw [h_nBits_eq]; omega
          have h_mask_bit : ((1 <<< nBits) - 1).testBit (p - s.acci) = true := by
            have h1 : (1 : ℕ) <<< nBits = 2 ^ nBits := by simp [Nat.shiftLeft_eq, one_mul]
            rw [h1, Nat.testBit_two_pow_sub_one]
            exact decide_eq_true h_psub_lt_nBits
          rw [h_mask_bit, Bool.and_true]
          have h_pos_eq : 8 * s.bi + p = d * i + (p - s.acci) := by omega
          have h_psub_lt_d : p - s.acci < d := by omega
          rw [h_pos_eq, hx_def]
          rw [fipsBit_within_coeff d F h_d i h_i (p - s.acci) h_psub_lt_d]
      -- Case-split on k: old (k < s.bi) vs new (k ∈ {bi, bi+1, bi+2, bi+3})
      by_cases h_k_old : k < s.bi
      · rw [h_b_eq]
        simp only [List.getD]
        rw [List.getElem?_set_ne (by omega)]
        rw [List.getElem?_set_ne (by omega)]
        rw [List.getElem?_set_ne (by omega)]
        rw [List.getElem?_set_ne (by omega)]
        exact h_bytes k h_k_old j h_j
      · push Not at h_k_old
        obtain h_keq | h_keq | h_keq | h_keq :
            k = s.bi ∨ k = s.bi + 1 ∨ k = s.bi + 2 ∨ k = s.bi + 3 := by omega
        · -- k = s.bi: m = 0
          subst h_keq
          rw [h_b_eq]
          simp only [List.getD]
          rw [List.getElem?_set_ne (by omega)]
          rw [List.getElem?_set_ne (by omega)]
          rw [List.getElem?_set_ne (by omega)]
          rw [List.getElem?_set_self (by omega)]
          show (BitVec.setWidth 8 acc1).toNat.testBit j = _
          rw [show (BitVec.setWidth 8 acc1 : BitVec 8) = BitVec.setWidth 8 (acc1 >>> (8 * 0)) by simp]
          rw [flush_byte_setWidth_bit acc1 0 (by decide) j h_j]
          have h_bnd : 0 * 8 + j < 32 := by omega
          have h_p_lt : 8 * 0 + j < 32 := by omega
          rw [show 8 * s.bi + j = 8 * s.bi + (8 * 0 + j) by ring]
          exact h_acc1_bit (8 * 0 + j) h_p_lt
        · -- k = s.bi + 1: m = 1
          subst h_keq
          rw [h_b_eq]
          simp only [List.getD]
          rw [List.getElem?_set_ne (by omega)]
          rw [List.getElem?_set_ne (by omega)]
          rw [List.getElem?_set_self (by simp only [List.length_set]; omega)]
          show (BitVec.setWidth 8 (acc1 >>> 8)).toNat.testBit j = _
          rw [show ((acc1 >>> 8 : BitVec 32)) = acc1 >>> (8 * 1) by norm_num]
          rw [flush_byte_setWidth_bit acc1 1 (by decide) j h_j]
          have h_p_lt : 8 * 1 + j < 32 := by omega
          rw [show 8 * (s.bi + 1) + j = 8 * s.bi + (8 * 1 + j) by ring]
          exact h_acc1_bit (8 * 1 + j) h_p_lt
        · -- k = s.bi + 2: m = 2
          subst h_keq
          rw [h_b_eq]
          simp only [List.getD]
          rw [List.getElem?_set_ne (by omega)]
          rw [List.getElem?_set_self (by simp only [List.length_set]; omega)]
          show (BitVec.setWidth 8 (acc1 >>> 16)).toNat.testBit j = _
          rw [show ((acc1 >>> 16 : BitVec 32)) = acc1 >>> (8 * 2) by norm_num]
          rw [flush_byte_setWidth_bit acc1 2 (by decide) j h_j]
          have h_p_lt : 8 * 2 + j < 32 := by omega
          rw [show 8 * (s.bi + 2) + j = 8 * s.bi + (8 * 2 + j) by ring]
          exact h_acc1_bit (8 * 2 + j) h_p_lt
        · -- k = s.bi + 3: m = 3
          subst h_keq
          rw [h_b_eq]
          simp only [List.getD]
          rw [List.getElem?_set_self (by simp only [List.length_set]; omega)]
          show (BitVec.setWidth 8 (acc1 >>> 24)).toNat.testBit j = _
          rw [show ((acc1 >>> 24 : BitVec 32)) = acc1 >>> (8 * 3) by norm_num]
          rw [flush_byte_setWidth_bit acc1 3 (by decide) j h_j]
          have h_p_lt : 8 * 3 + j < 32 := by omega
          rw [show 8 * (s.bi + 3) + j = 8 * s.bi + (8 * 3 + j) by ring]
          exact h_acc1_bit (8 * 3 + j) h_p_lt
    · -- Acc low bits match at new state
      intro j h_j
      rw [h_body_acci] at h_j
      rw [h_body_acc, h_body_bi]
      have h_test : (BitVec.ofNat 32 (x >>> nBits)).getLsbD j = x.testBit (j + nBits) := by
        rw [BitVec.getLsbD_ofNat]
        have h_jlt32 : j < 32 := by
          have : d - nBits ≤ d := Nat.sub_le _ _
          omega
        simp only [h_jlt32, decide_true, Bool.true_and]
        rw [Nat.testBit_shiftRight, Nat.add_comm]
      rw [h_test]
      have h_pos_eq : 8 * (s.bi + 4) + j = d * i + (nBits + j) := by
        rw [h_nBits_eq]; omega
      have h_bnd : nBits + j < d := by omega
      rw [h_pos_eq, hx_def]
      rw [fipsBit_within_coeff d F h_d i h_i (nBits + j) h_bnd]
      rw [Nat.add_comm]
  · -- CARRY arm
    have h_acci_d : s.acci + d < 32 := by
      by_contra h_contra
      push Not at h_contra
      -- If s.acci + d ≥ 32, then 32 - s.acci ≤ d, so min d (32 - s.acci) = 32 - s.acci.
      have h_min : min d (32 - s.acci) = 32 - s.acci := Nat.min_eq_right (by omega)
      have h_eq : s.acci + nBits = 32 := by
        rw [hnBits, h_min]; omega
      exact h_flush h_eq
    have h_nBits_eq : nBits = d := by
      have h_min : min d (32 - s.acci) = d := Nat.min_eq_left (by omega)
      rw [hnBits, h_min]
    rw [if_neg h_flush] at h_body_bi h_body_acc h_body_acci
    refine ⟨h_len', ?_, ?_, h_zero'⟩
    · -- Bytes unchanged
      intro k h_k j h_j
      rw [h_body_bi] at h_k
      have h_b_eq : (CompressEncodeState.body d x s).b = s.b := by
        unfold CompressEncodeState.body
        dsimp only
        rw [if_neg h_flush]
      rw [h_b_eq]
      exact h_bytes k h_k j h_j
    · -- Acc low bits at new acci' = s.acci + d
      intro j h_j
      rw [h_body_acci] at h_j
      rw [h_body_acc, h_body_bi]
      have h_shifted_load :
          (s.acc ||| (BitVec.ofNat 32 (x &&& ((1 <<< nBits) - 1))) <<< s.acci).getLsbD j
            = if j < s.acci then s.acc.getLsbD j else x.testBit (j - s.acci) := by
        rw [BitVec.getLsbD_or]
        by_cases h_lt : j < s.acci
        · rw [if_pos h_lt]
          have h_zero_shift :
              ((BitVec.ofNat 32 (x &&& ((1 <<< nBits) - 1))) <<< s.acci).getLsbD j = false := by
            rw [BitVec.getLsbD_shiftLeft]
            have h_not : (!decide (j < s.acci)) = false := by simp [h_lt]
            rw [h_not, Bool.and_false, Bool.false_and]
          rw [h_zero_shift, Bool.or_false]
        · rw [if_neg h_lt]
          have h_jge : s.acci ≤ j := Nat.le_of_not_lt h_lt
          have h_jbnd : j < s.acci + nBits := h_j
          have h_jlt32 : j < 32 := by rw [h_nBits_eq] at h_jbnd; omega
          have h_acc_zero : s.acc.getLsbD j = false := by
            have := h_zero j h_jge
            simpa using this
          rw [h_acc_zero, Bool.false_or]
          rw [BitVec.getLsbD_shiftLeft, BitVec.getLsbD_ofNat]
          have h_jsub_lt32 : j - s.acci < 32 := by omega
          have h_notdec : (!decide (j < s.acci)) = true := by simp [h_lt]
          have h_dec32 : decide (j < 32) = true := decide_eq_true h_jlt32
          have h_decsub32 : decide (j - s.acci < 32) = true := decide_eq_true h_jsub_lt32
          rw [h_notdec, h_dec32, h_decsub32]
          simp only [Bool.true_and]
          rw [Nat.testBit_and]
          have h_jsub_lt_nBits : j - s.acci < nBits := by rw [h_nBits_eq]; omega
          have h_mask_bit : ((1 <<< nBits) - 1).testBit (j - s.acci) = true := by
            have h1 : (1 : ℕ) <<< nBits = 2 ^ nBits := by simp [Nat.shiftLeft_eq, one_mul]
            rw [h1, Nat.testBit_two_pow_sub_one]
            exact decide_eq_true h_jsub_lt_nBits
          rw [h_mask_bit, Bool.and_true]
      rw [h_shifted_load]
      by_cases h_lt : j < s.acci
      · rw [if_pos h_lt]
        exact h_acc j h_lt
      · rw [if_neg h_lt]
        have h_jge : s.acci ≤ j := Nat.le_of_not_lt h_lt
        have h_pos_eq : 8 * s.bi + j = d * i + (j - s.acci) := by omega
        have h_jsub_lt : j - s.acci < d := by
          have h_jbnd : j < s.acci + nBits := h_j
          rw [h_nBits_eq] at h_jbnd
          omega
        rw [h_pos_eq, hx_def]
        rw [fipsBit_within_coeff d F h_d i h_i (j - s.acci) h_jsub_lt]

/-- Inductive lift of `body_streamCompressEncodePartial` over a list `xs`
of already-compressed coefficient values aligned with `F[i..i+xs.length]`. -/
private theorem recBody_streamCompressEncodePartial
    (d : ℕ) (F : MLKEM.Polynomial) (h_d : 1 ≤ d ∧ d ≤ 12)
    (xs : List ℕ) (i n : ℕ) (h_n : i + xs.length = n) (h_bnd : n ≤ 256)
    (h_xs : ∀ (k : ℕ) (h_k : k < xs.length) (h_ik : i + k < 256),
        xs[k]'h_k = coeffToEncode d (F.get ⟨i + k, h_ik⟩))
    (s : CompressEncodeState)
    (h_inv : streamCompressEncodePartial d F h_d i s) :
    streamCompressEncodePartial d F h_d n
        (CompressEncodeState.recBody d xs s) := by
  have h_aux : ∀ (xs : List ℕ) (i : ℕ) (h_bnd : i + xs.length ≤ 256)
      (h_xs : ∀ (k : ℕ) (h_k : k < xs.length) (h_ik : i + k < 256),
          xs[k]'h_k = coeffToEncode d (F.get ⟨i + k, h_ik⟩))
      (s : CompressEncodeState)
      (h_inv : streamCompressEncodePartial d F h_d i s),
      streamCompressEncodePartial d F h_d (i + xs.length)
          (CompressEncodeState.recBody d xs s) := by
    intro xs
    induction xs with
    | nil =>
      intro i _ _ s h_inv
      simp only [List.length_nil, Nat.add_zero, CompressEncodeState.recBody,
                 List.foldl_nil]
      exact h_inv
    | cons x xs ih =>
      intro i h_bnd h_xs s h_inv
      have h_xs_len_cons : (x :: xs).length = xs.length + 1 := by simp
      have h_i_lt : i < 256 := by
        have : i + (x :: xs).length ≤ 256 := h_bnd
        rw [h_xs_len_cons] at this; omega
      have h_x : x = coeffToEncode d (F.get ⟨i, h_i_lt⟩) := by
        have h0 := h_xs 0 (by simp) (by omega)
        simpa using h0
      have h_step : streamCompressEncodePartial d F h_d (i + 1)
          (CompressEncodeState.body d x s) := by
        rw [h_x]
        exact body_streamCompressEncodePartial d F h_d i h_i_lt s h_inv
      have h_bnd' : (i + 1) + xs.length ≤ 256 := by
        have : i + (x :: xs).length ≤ 256 := h_bnd
        rw [h_xs_len_cons] at this; omega
      have h_xs' : ∀ (k : ℕ) (h_k : k < xs.length) (h_ik : (i + 1) + k < 256),
          xs[k]'h_k = coeffToEncode d (F.get ⟨(i + 1) + k, h_ik⟩) := by
        intro k h_k h_ik
        have h_ik' : i + (k + 1) < 256 := by omega
        have h := h_xs (k + 1) (by simpa using Nat.succ_lt_succ h_k) h_ik'
        simp only [List.getElem_cons_succ] at h
        have h_fin : (⟨i + (k + 1), h_ik'⟩ : Fin 256) = ⟨(i + 1) + k, h_ik⟩ :=
          Fin.mk_eq_mk.mpr (by omega)
        rw [h_fin] at h
        exact h
      have h_ih := ih (i + 1) h_bnd' h_xs' _ h_step
      have h_eq : (i + 1) + xs.length = i + (xs.length + 1) := by omega
      rw [h_eq] at h_ih
      show streamCompressEncodePartial d F h_d (i + (x :: xs).length)
          (CompressEncodeState.recBody d (x :: xs) s)
      simp only [List.length_cons, CompressEncodeState.recBody, List.foldl_cons]
      exact h_ih
  have h_bnd' : i + xs.length ≤ 256 := by rw [h_n]; exact h_bnd
  have h := h_aux xs i h_bnd' h_xs s h_inv
  rw [h_n] at h
  exact h

/-- The coefficient list passed to `recBody` by
`streamCompressEncodePoly`. Extracted to keep the bridge proof term-size
manageable. Marked `@[irreducible]` so the proof never tries to unfold
the 256-element `Vector.ofFn` body during whnf. -/
@[irreducible]
private def streamCompressCoeffList (d : ℕ) (F : MLKEM.Polynomial) : List ℕ :=
  (Vector.ofFn (fun i : Fin 256 => coeffToEncode d (F.get i))).toList

private theorem streamCompressCoeffList_length (d : ℕ) (F : MLKEM.Polynomial) :
    (streamCompressCoeffList d F).length = 256 := by
  unfold streamCompressCoeffList; rw [Vector.length_toList]

private theorem streamCompressCoeffList_getElem (d : ℕ) (F : MLKEM.Polynomial)
    (k : ℕ) (h : k < 256) :
    (streamCompressCoeffList d F)[k]'(by rw [streamCompressCoeffList_length]; exact h)
      = coeffToEncode d (F.get ⟨k, h⟩) := by
  unfold streamCompressCoeffList
  rw [Vector.getElem_toList, Vector.getElem_ofFn]

private theorem streamCompressEncodePoly_eq_recBody (d : ℕ) (F : MLKEM.Polynomial) :
    streamCompressEncodePoly d F =
      (CompressEncodeState.recBody d (streamCompressCoeffList d F)
        (CompressEncodeState.init d)).b := by
  unfold streamCompressEncodePoly streamCompressCoeffList
  rfl

set_option maxRecDepth 2048 in
/-- Specialised wrapper of `recBody_streamCompressEncodePartial` at `i := 0`,
    using `streamCompressCoeffList` directly to avoid elaboration blowup at the
    closure call site. -/
private theorem recBody_streamCompressEncodePartial_full
    (d : ℕ) (F : MLKEM.Polynomial) (h_d : 1 ≤ d ∧ d ≤ 12)
    (s : CompressEncodeState)
    (h_inv : streamCompressEncodePartial d F h_d 0 s) :
    streamCompressEncodePartial d F h_d 256
        (CompressEncodeState.recBody d (streamCompressCoeffList d F) s) := by
  have h_len := streamCompressCoeffList_length d F
  have h_n : 0 + (streamCompressCoeffList d F).length = 256 := by rw [h_len]
  have h_bnd : (256 : ℕ) ≤ 256 := le_refl _
  have h_xs_get : ∀ (k : ℕ) (h_k : k < (streamCompressCoeffList d F).length)
      (h_ik : 0 + k < 256),
      (streamCompressCoeffList d F)[k]'h_k
        = coeffToEncode d (F.get ⟨0 + k, h_ik⟩) := by
    intro k h_k h_ik
    have h_k' : k < 256 := by rw [h_len] at h_k; exact h_k
    have h_get := streamCompressCoeffList_getElem d F k h_k'
    have h_fin : (⟨k, h_k'⟩ : Fin 256) = ⟨0 + k, h_ik⟩ :=
      Fin.mk_eq_mk.mpr (Nat.zero_add k).symm
    rw [h_fin] at h_get
    exact h_get
  exact recBody_streamCompressEncodePartial d F h_d
      (streamCompressCoeffList d F) 0 256 h_n h_bnd h_xs_get s h_inv

set_option maxRecDepth 2048 in
/-- Pure consequence of the partial invariant at i=256: the buffer matches
the FIPS-encoded list. Abstract over the state to keep the proof term small
and prevent kernel-time blowup when the state involves `streamCompressCoeffList`. -/
private theorem streamCompressEncodePartial_buffer_eq
    (d : ℕ) (F : MLKEM.Polynomial) (h_d : 1 ≤ d ∧ d ≤ 12)
    (s : CompressEncodeState)
    (h_partial : streamCompressEncodePartial d F h_d 256 s)
    (h_blen : s.b.length = 32 * d) :
    s.b = (compressEncodePoly d F h_d).toList := by
  obtain ⟨h_len, h_bytes, _h_acc, _h_zero⟩ := h_partial
  have h_bi_eq : s.bi = 32 * d := by
    have h_b := h_len.2.2.1
    rw [h_b]
    have h256 : (d * 256) / 32 = 8 * d := by
      rw [show d * 256 = 32 * (8 * d) by ring,
        Nat.mul_div_cancel_left _ (by decide : (0:ℕ) < 32)]
    rw [h256]; ring
  have h_rhs_len : (compressEncodePoly d F h_d).toList.length = 32 * d := by
    rw [Vector.length_toList]
  apply List.ext_getElem
  · rw [h_blen, h_rhs_len]
  · intro k h_k_lhs h_k_rhs
    have h_k_lt_32d : k < 32 * d := h_blen ▸ h_k_lhs
    have h_k_lt_bi : k < s.bi := by rw [h_bi_eq]; exact h_k_lt_32d
    apply BitVec.eq_of_getLsbD_eq
    intro j h_j
    have h_lhs_bit := h_bytes k h_k_lt_bi j h_j
    have h_lhs_getD : s.b.getD k 0#8 = s.b[k]'h_k_lhs := by
      simp [List.getD, List.getElem?_eq_getElem h_k_lhs]
    rw [h_lhs_getD] at h_lhs_bit
    have h_rhs_bit := compressEncodePoly_testBit d F h_d k h_k_lt_32d j h_j
    have h_rhs_list_get :
        ((compressEncodePoly d F h_d).toList)[k]'h_k_rhs
          = (compressEncodePoly d F h_d)[k]'h_k_lt_32d := by
      simp [Vector.getElem_toList]
    rw [h_rhs_list_get]
    rw [← BitVec.testBit_toNat, ← BitVec.testBit_toNat]
    rw [h_lhs_bit, h_rhs_bit]
    have h_idx : (8 * k + j) / d < 256 := byteEncode_idx_bound h_d.1 h_d.2 h_k_lt_32d h_j
    have h_dpos : 0 < d := h_d.1
    have h_split : 8 * k + j = d * ((8 * k + j) / d) + ((8 * k + j) % d) :=
      (Nat.div_add_mod (8 * k + j) d).symm
    have h_mod_lt : (8 * k + j) % d < d := Nat.mod_lt _ h_dpos
    conv_lhs => rw [h_split]
    rw [fipsBit_within_coeff d F h_d ((8 * k + j) / d) h_idx _ h_mod_lt]
    rfl

/-- **Bridge 1 — compress side.**

The stream-encoded buffer equals the FIPS-encoded buffer, byte-list
form.
-/
theorem streamCompressEncodePoly_eq.spec (d : ℕ) (F : MLKEM.Polynomial)
    (h_d : 1 ≤ d ∧ d ≤ 12) :
    streamCompressEncodePoly d F = (compressEncodePoly d F h_d).toList := by
  rw [streamCompressEncodePoly_eq_recBody d F]
  set xs := streamCompressCoeffList d F
  set s := CompressEncodeState.recBody d xs (CompressEncodeState.init d) with h_s
  have h_partial : streamCompressEncodePartial d F h_d 256 s :=
    recBody_streamCompressEncodePartial_full d F h_d _
      (init_streamCompressEncodePartial d F h_d)
  have h_blen : s.b.length = 32 * d := by
    rw [h_s, CompressEncodeState.recBody_b_length]
    simp [CompressEncodeState.init]
  exact streamCompressEncodePartial_buffer_eq d F h_d s h_partial h_blen


end Symcrust.Properties.MLKEM.Bridges
