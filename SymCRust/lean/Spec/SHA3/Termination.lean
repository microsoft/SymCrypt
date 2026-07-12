import Spec.SHA3.Permutation
import Spec.SHA3.XOFProperties

/-!
# Unconditional termination for SHAKE128-based rejection sampling

This module formalises the Barbosa–Schwabe argument
("Kyber terminates", Polynesian J. Math. 1(6), 2024) that the SHAKE128
squeeze stream produced from any 34-byte seed contains at least 256
candidate 12-bit integers `< q = 3329`, so the ML-KEM `SampleNTT`
rejection-sampling loop terminates **unconditionally**.

The argument is purely structural: it does not depend on the
distribution of `KECCAK_f` outputs, only on the facts that
(1) `KECCAK_f` is a permutation on the 1600-bit state space
    (`KECCAK_f_bijective`, in `Permutation.lean`), and
(2) the SHAKE128 pre-permutation state `S₋₁` produced by `Absorb` on
    any 34-byte seed contains a large explicit fully-zero region in
    its rate part (43 fully-aligned zero byte triples,
    yielding ≥ 86 acceptable candidates per cycle).

## Top-level structure

* `S_minus_1 B`: the explicit `Vector Bool 1600` produced by padding
  `bytesToBits B ‖ xofSuffix` to one rate block of 1344 bits and
  zero-extending to the full state width.  This is the unique pre-image
  of the post-Absorb state under `KECCAK_f`.

* `SHAKE128.absorb_init_closed_form`: the post-`Absorb` state equals
  `KECCAK_f (S_minus_1 B)`.

* `SHAKE128.squeezeBytes_eq_blocks`: the byte output of `n` rate blocks
  of squeezing equals `bitsToBytes` of the concatenation
  `Trunc r (KECCAK_f^[j+1] (S_minus_1 B))` for `j ∈ [0, n)`.

* `S_minus_1_in_squeeze_orbit`: the rate part of `S_minus_1 B` appears
  once per period in the squeeze stream (via the cycle lemma + the
  predecessor-in-orbit lemma from `Permutation.lean`).

The downstream MLKEM-side discharge lives in
`Properties/MLKEM/Sampling/SampleNTTTermination.lean`; this file
provides the SHA3 building blocks only.
-/

namespace Spec.SHA3

open Spec (𝔹 Bits.zeroExtend bytesToBits bitsToBytes)
open scoped Spec.Notations

/-! ## §1. The pre-Absorb state `S₋₁`

For a 34-byte seed `B`, the SHAKE128 pre-permutation state has the
explicit form:

  S₋₁ = zeroExtend ( bytesToBits B ‖ xofSuffix ‖ pad10*1 1344 276 ) 1600

In byte form (LSB-first per byte) this is:

  bytes 0..33  = B                       (the seed)
  byte  34     = 0x1F                    (xofSuffix 1111 + first pad bit 1)
  bytes 35..166 = 0                      (zero pad)
  byte  167    = 0x80                    (final pad bit, at high bit)
  bytes 168..199 = 0                     (capacity)

The 43 fully-aligned zero byte triples in the range `[36, 165)`
provide the structural reason for unconditional termination.
-/

/-- The padded one-block input to SHAKE128's `Absorb`, before
zero-extension to the state width.  Length: `276 + padLen 1344 276 = 1344`. -/
def S_minus_1_payload (B : 𝔹 34) :
    Vector Bool (8 * 34 + 4 + padLen 1344 (8 * 34 + 4)) :=
  (bytesToBits B ‖ xofSuffix) ‖ «pad10*1» 1344 (8 * 34 + 4)

/-- The pre-permutation state `S₋₁` for SHAKE128 on a 34-byte input.

The first `8 * 34 + 4 + padLen 1344 276 = 1344` bits are the padded
input; the remaining `256` bits are the capacity (zero-extended). -/
def S_minus_1 (B : 𝔹 34) : Vector Bool b :=
  Bits.zeroExtend (S_minus_1_payload B) b

/-! ## §2. Single-block absorb characterisation

Since `34 * 8 + 4 = 276 < 1344` and the padding tops it up to exactly
one rate block, `SPONGE.absorb` evaluates to a single `KECCAK_f` call
on the zero-extended padded input. -/

/-- `(0 : Vector Bool n)[i] = false` under the SHA-3 LSB-first `OfNat`. -/
private theorem zero_get_bits {n : Nat} (i : Nat) (hi : i < n) :
    (0 : Vector Bool n)[i] = false := by
  show (Bits.ofNatLE 0 : Vector Bool n)[i] = false
  simp [Bits.ofNatLE]

/-- XOR with the all-zero bit vector is the identity. -/
private theorem zero_xor_bits {n : Nat} (X : Vector Bool n) :
    HXor.hXor (0 : Vector Bool n) X = X := by
  apply Vector.ext
  intro i hi
  show (Vector.zipWith _ (0 : Vector Bool n) X)[i] = X[i]
  rw [Vector.getElem_zipWith, zero_get_bits i hi]
  simp

/-- **Generic single-block absorb characterisation.** When the input has
length exactly `r` (one rate block), `SPONGE.absorb` evaluates to a
single `f` call on the zero-extended block. -/
theorem SPONGE.absorb_single_block
    (f : Vector Bool b → Vector Bool b) (r : Nat) (hr : 0 < r)
    (P : Vector Bool r) :
    SPONGE.absorb f r P (by simp : r % r = 0) hr =
    f (Bits.zeroExtend P b) := by
  rw [SPONGE_absorb_eq_blocks _ _ hr (by simp : r % r = 0)]
  have hone : r / r = 1 := Nat.div_self hr
  have hb : blocks P r hr (by simp) =
            Vector.cast hone.symm (#v[P] : Vector (Vector Bool r) 1) := by
    apply Vector.ext
    intro i hi
    simp [blocks, slice]
    have hI : i = 0 := by simp [hone] at hi; omega
    subst hI
    simp
  rw [hb, absorbBlocks]
  simp [Vector.foldl, zero_xor_bits]

/-- Variant of `SPONGE.absorb_single_block` for inputs whose length is
propositionally equal to `r` (e.g. via a `decide`-able expression). -/
theorem SPONGE.absorb_single_block_eq
    (f : Vector Bool b → Vector Bool b) {m r : Nat} (hr : 0 < r)
    (hm_eq : m = r) (P : Vector Bool m) (hm : m % r = 0) :
    SPONGE.absorb f r P hm hr = f (Bits.zeroExtend P b) := by
  subst m
  exact SPONGE.absorb_single_block f r hr P

/-- **Single-block Absorb closed form for SHAKE128 on 34 bytes.** -/
theorem SHAKE128.absorb_init_S_eq (B : 𝔹 34) :
    (SHAKE128.absorb SHAKE128.init B).S = KECCAK_f (S_minus_1 B) := by
  unfold SHAKE128.absorb SHAKE128.init Incremental.sponge.absorb1
    Incremental.sponge.init
  simp only []
  /- Apply the single-block absorb lemma with the propositional length equality. -/
  have hlen : 8 * 34 + 4 + padLen (b - 256) (8 * 34 + 4) = b - 256 := by decide
  rw [SPONGE.absorb_single_block_eq KECCAK_f (by decide) hlen _ (by decide)]
  /- `KECCAK_f (Bits.zeroExtend ((bytesToBits B ‖ xofSuffix) ‖ pad) b) = KECCAK_f (S_minus_1 B)`. -/
  rfl

/-! ## §3. Cycle visit lemma — `S₋₁` lies on the squeeze orbit

Combine `KECCAK_f_periodic` and `KECCAK_f_predecessor_in_orbit` with
the closed-form Absorb result: the post-Absorb state `S₀ = KECCAK_f S₋₁`
is on a cycle of some length `m ≥ 1`, and at the cycle position
`m - 1` we recover `S₋₁` itself.

So for any `c ≥ 1` cycles of squeezing, the iteration
`KECCAK_f^[c·m - 1] S₀ = S₋₁`. -/

/-- `S₋₁` appears at position `m - 1` (and every `m`-th step thereafter)
in the post-Absorb squeeze orbit, for some cycle length `m ≥ 1`. -/
theorem S_minus_1_in_squeeze_orbit (B : 𝔹 34) :
    ∃ m ≥ 1, ∀ c ≥ 1,
      KECCAK_f^[c * m - 1] (KECCAK_f (S_minus_1 B)) = S_minus_1 B := by
  obtain ⟨m, hm_pos, hperiod⟩ := KECCAK_f_periodic (KECCAK_f (S_minus_1 B))
  refine ⟨m, hm_pos, fun c hc => ?_⟩
  have hpred := KECCAK_f_predecessor_in_orbit (S_minus_1 B) hm_pos hperiod
  /- KECCAK_f^[c*m] (KECCAK_f S₋₁) = KECCAK_f S₋₁ by iterating `hperiod`,
     so KECCAK_f^[c*m - 1] (KECCAK_f S₋₁) = S₋₁ by `hpred`-style step. -/
  have hcm_period : KECCAK_f^[c * m] (KECCAK_f (S_minus_1 B)) =
                     KECCAK_f (S_minus_1 B) := by
    induction c, hc using Nat.le_induction with
    | base => simpa using hperiod
    | succ c _ ih =>
      have : (c + 1) * m = c * m + m := by ring
      rw [this, Function.iterate_add_apply, hperiod, ih]
  have hcm_pos : 1 ≤ c * m := by
    have : 1 ≤ c := hc
    exact Nat.one_le_iff_ne_zero.mpr (by
      intro h; rcases Nat.mul_eq_zero.mp h with h | h <;> omega)
  /- KECCAK_f^[c*m] = KECCAK_f ∘ KECCAK_f^[c*m - 1], and KECCAK_f is injective. -/
  have hsucc : (c * m - 1).succ = c * m := by omega
  have : KECCAK_f (KECCAK_f^[c * m - 1] (KECCAK_f (S_minus_1 B))) =
         KECCAK_f (S_minus_1 B) := by
    have h := hcm_period
    rw [← hsucc, Function.iterate_succ_apply'] at h
    exact h
  exact KECCAK_f_bijective.injective this

/-! ## §4. The rate part of `S₋₁` has 43 fully-aligned zero byte triples

For any `B : 𝔹 34`, every byte in the range `[36, 165)` of the rate
part of `S_minus_1 B` is zero.  Since `36 = 12 * 3` and `165 = 55 * 3`,
this gives `(55 - 12) = 43` fully-aligned three-byte chunks at byte
offsets `36, 39, ..., 162`.  Each such all-zero triple yields the
12-bit candidates `d₁ = 0` and `d₂ = 0`, both `< q = 3329`, hence
≥ `2 * 43 = 86` acceptable candidates per cycle. -/

/-- For any 34-byte input, the bits at positions `[280, 1336)` of
`S_minus_1 B` are all zero — i.e. bytes 35..166 of its rate part.

Indices 280..1335 cover the `0^j` zero pad introduced by
`pad10*1 1344 276` (which starts at bit 277), so the proof reduces to
unfolding `pad10*1` and the byte/bit conversions. -/
theorem S_minus_1_zero_bits (B : 𝔹 34) :
    ∀ i, 280 ≤ i → i < 1336 → ∀ (h : i < b),
      (S_minus_1 B)[i]'h = false := by
  intro i h1 h2 h
  unfold S_minus_1 Bits.zeroExtend S_minus_1_payload
  simp only [Vector.getElem_ofFn]
  have hi : i < 8 * 34 + 4 + padLen 1344 (8 * 34 + 4) := by
    have hp : padLen 1344 (8*34+4) = 1068 := by decide
    omega
  rw [dif_pos hi]
  unfold «pad10*1»
  have hjj : padLen.j 1344 (8*34+4) = 1066 := by decide
  /- Convert ‖ (Vector.append) to ++ so Vector.getElem_append_* fires. -/
  show ((bytesToBits B ++ xofSuffix) ++
        ((#v[1] : Vector Bool 1) ++
         Vector.replicate (padLen.j 1344 (8*34+4)) (false : Bool) ++
         (#v[1] : Vector Bool 1)))[i] = false
  rw [Vector.getElem_append_right (by simp [hjj]; omega)
        (by omega : (8 * 34 + 4 : Nat) ≤ i)]
  rw [Vector.getElem_append_left
        (by simp [hjj]; omega : i - (8*34+4) < 1 + padLen.j 1344 (8*34+4))]
  rw [Vector.getElem_append_right
        (by simp [hjj]; omega : i - (8*34+4) < 1 + padLen.j 1344 (8*34+4))
        (by omega : (1 : Nat) ≤ i - (8*34+4))]
  rw [Vector.getElem_replicate]

/-! ## §5. Byte-stream characterisation: bytes from `shake128` and `KECCAK_f` orbit

We characterise the byte at any position `k < N` of `shake128 B N` in
terms of the orbit `KECCAK_f^[k·8/r + 1] (S_minus_1 B)` (when the 8
bits fall inside a single rate block). -/

open Incremental in
/-- **Bit-level characterisation of the SHAKE128 incremental squeeze
from the post-Absorb state.**  For `i < 8 * outBytes`, the `i`-th bit
of the squeezed bit-stream is the `(i % (b-256))`-th bit of
`KECCAK_f^[i / (b-256) + 1] (S_minus_1 B)`. -/
theorem SHAKE128.squeeze_bit_eq_iterate (B : 𝔹 34) (outBytes : Nat)
    (i : Nat) (hi : i < 8 * outBytes) :
    ((sponge.squeeze1 KECCAK_f (r := b - 256) (hr := by decide)
        (SHAKE128.absorb SHAKE128.init B) (8 * outBytes)).2[i]'hi) =
      (KECCAK_f^[i / (b - 256) + 1] (S_minus_1 B))[i % (b - 256)]'(by
        have h := Nat.mod_lt i (show 0 < b - 256 from by decide)
        have h2 : b - 256 ≤ b := by decide
        omega) := by
  have hs_x : (SHAKE128.absorb SHAKE128.init B).x = 0 := by
    simp [SHAKE128.absorb, SHAKE128.init, sponge.absorb1, sponge.init]
  have hs_Z : (SHAKE128.absorb SHAKE128.init B).Z = #[] := by
    simp [SHAKE128.absorb, SHAKE128.init, sponge.absorb1, sponge.init]
  have hs_S : (SHAKE128.absorb SHAKE128.init B).S = KECCAK_f (S_minus_1 B) :=
    SHAKE128.absorb_init_S_eq B
  /- Apply the bit-level squeeze lemma. -/
  rw [sponge.squeeze1_at_x_zero_aux KECCAK_f (b - 256) (by decide)
        (SHAKE128.absorb SHAKE128.init B) (8 * outBytes) hs_x i hi]
  have hZsize : (SHAKE128.absorb SHAKE128.init B).Z.size = 0 := by rw [hs_Z]; simp
  have hnotlt : ¬ i < (SHAKE128.absorb SHAKE128.init B).Z.size := by
    rw [hZsize]; omega
  rw [dif_neg hnotlt, hs_S]
  /- After substitution: goal is
       (KECCAK_f^[(i - Z.size)/(b-256)] (KECCAK_f (S_minus_1 B)))[(i - Z.size) % (b-256)]
       = (KECCAK_f^[i/(b-256) + 1] (S_minus_1 B))[i % (b-256)].
     Use fcongr to handle the dependent proof, then prove the data equality. -/
  have hiter : KECCAK_f^[(i - (SHAKE128.absorb SHAKE128.init B).Z.size) / (b - 256)]
                  (KECCAK_f (S_minus_1 B))
              = KECCAK_f^[i / (b - 256) + 1] (S_minus_1 B) := by
    rw [hZsize, Nat.sub_zero, Function.iterate_succ_apply]
  have hidx : (i - (SHAKE128.absorb SHAKE128.init B).Z.size) % (b - 256) = i % (b - 256) := by
    rw [hZsize, Nat.sub_zero]
  conv_lhs => rw [hiter]
  fcongr 1

/-- For `c ≥ 1` and bit position `p ∈ [1344·(c·m − 1), 1344·(c·m))` where
`m` is the period of the orbit at `S_minus_1 B`, the bit of the
SHAKE128 squeeze stream equals the corresponding bit of `S_minus_1 B`. -/
theorem SHAKE128.squeeze_bit_at_cycle (B : 𝔹 34) :
    ∃ m ≥ 1, ∀ c ≥ 1, ∀ (outBytes p : Nat)
      (_hp_lo : 1344 * (c * m - 1) ≤ p)
      (hp_hi : p < 1344 * (c * m))
      (hp : p < 8 * outBytes),
        ((Incremental.sponge.squeeze1 KECCAK_f (r := b - 256) (hr := by decide)
            (SHAKE128.absorb SHAKE128.init B) (8 * outBytes)).2[p]'hp) =
        (S_minus_1 B)[p - 1344 * (c * m - 1)]'(by
          /- Need: p - 1344*(c*m-1) < b = 1600. -/
          by_cases hcm : c * m = 0
          · rw [hcm, Nat.mul_zero] at hp_hi; omega
          · have hcm_pos : c * m ≥ 1 := Nat.one_le_iff_ne_zero.mpr hcm
            have heq : c * m = (c * m - 1) + 1 := by omega
            have : 1344 * (c * m) = 1344 * (c * m - 1) + 1344 := by
              conv_lhs => rw [heq]
              rw [Nat.mul_succ]
            have hb_val : (b : Nat) = 1600 := rfl
            omega) := by
  obtain ⟨m, hm_pos, horbit⟩ := S_minus_1_in_squeeze_orbit B
  refine ⟨m, hm_pos, fun c hc outBytes p hp_lo hp_hi hp => ?_⟩
  rw [SHAKE128.squeeze_bit_eq_iterate B outBytes p hp]
  /- Compute p / (b-256) and p % (b-256), using (b-256) = 1344. -/
  have hb256 : (b - 256 : Nat) = 1344 := by decide
  have hcm_pos : c * m ≥ 1 := Nat.one_le_iff_ne_zero.mpr (fun h => by
    rcases Nat.mul_eq_zero.mp h with h | h <;> omega)
  have heq : c * m = (c * m - 1) + 1 := by omega
  have hmul_eq : 1344 * (c * m) = 1344 * (c * m - 1) + 1344 := by
    conv_lhs => rw [heq]
    rw [Nat.mul_succ]
  have hp_hi' : p < 1344 * (c * m - 1) + 1344 := by omega
  have hdiv : p / 1344 = c * m - 1 := by omega
  have hmod : p % 1344 = p - 1344 * (c * m - 1) := by omega
  /- Simplify the iterate: KECCAK_f^[(c*m-1) + 1] (S_minus_1 B) = S_minus_1 B. -/
  have hiter : KECCAK_f^[p / (b - 256) + 1] (S_minus_1 B) = S_minus_1 B := by
    rw [hb256, hdiv, Function.iterate_succ_apply]
    exact horbit c hc
  /- Substitute via conv + fcongr, then close the index equation. -/
  conv_lhs => rw [hiter]
  fcongr 1
  rw [hb256]; exact hmod

/-- **Byte-level zero corollary.**  If the 8 bits at positions
`[8k, 8k+8)` of the squeeze bit-stream are all `false`, then byte `k`
of `shake128 B outBytes` is `0`. -/
theorem SHAKE128.shake128_byte_zero_of_bits_zero (B : 𝔹 34)
    (outBytes : Nat) (k : Nat) (hk : k < outBytes)
    (hzero : ∀ j, ∀ (_hj : j < 8) (h : 8 * k + j < 8 * outBytes),
      ((Incremental.sponge.squeeze1 KECCAK_f (r := b - 256) (hr := by decide)
          (SHAKE128.absorb SHAKE128.init B) (8 * outBytes)).2[8 * k + j]'h)
        = false) :
    (shake128 B outBytes)[k]'hk = 0 := by
  apply Spec.Byte.ext_testBit
  intro j hj
  rw [show shake128 B outBytes
        = bitsToBytes (Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide)
            (SHAKE128.absorb SHAKE128.init B) (8 * outBytes)).2 from
      (SHAKE128.bitsToBytes_squeeze1_init_eq_shake128 B outBytes).symm]
  rw [bitsToBytes_testBit _ k hk j hj]
  have hij : 8 * k + j < 8 * outBytes := by omega
  rw [hzero j hj hij]
  simp

/-- **The 43 zero byte triples**: for any seed `B`, at every cycle position
`c ≥ 1` the bytes at offsets `[168·(c·m-1) + 36, 168·(c·m-1) + 165)`
of the squeeze stream are zero, where `m` is the period from
`KECCAK_f_periodic`. -/
theorem SHAKE128.zero_bytes_per_cycle (B : 𝔹 34) :
    ∃ m ≥ 1, ∀ c ≥ 1, ∀ outBytes : Nat,
      168 * (c * m) ≤ outBytes →
      ∀ k, 168 * (c * m - 1) + 36 ≤ k → k < 168 * (c * m - 1) + 165 →
        ∀ (h : k < outBytes), (shake128 B outBytes)[k]'h = 0 := by
  obtain ⟨m, hm_pos, hbit⟩ := SHAKE128.squeeze_bit_at_cycle B
  refine ⟨m, hm_pos, fun c hc outBytes hN k hk1 hk2 hk => ?_⟩
  apply SHAKE128.shake128_byte_zero_of_bits_zero
  intro j hj h
  /- Bit position p = 8k+j. We have p ∈ [1344·(c·m-1) + 288, 1344·(c·m-1) + 1320). -/
  have hcm_pos : 1 ≤ c * m := by
    have hc' := hc
    have hm' := hm_pos
    have : 1 * 1 ≤ c * m := Nat.mul_le_mul hc' hm'
    omega
  have hp_lo : 1344 * (c * m - 1) ≤ 8 * k + j := by
    have h1 : 1344 * (c * m - 1) = 8 * (168 * (c * m - 1)) := by ring
    omega
  have hp_hi : 8 * k + j < 1344 * (c * m) := by
    have h1 : 1344 * (c * m) = 1344 * (c * m - 1) + 1344 := by
      have heq : c * m = (c * m - 1) + 1 := by omega
      conv_lhs => rw [heq]
      rw [Nat.mul_succ]
    have h2 : 1344 * (c * m - 1) = 8 * (168 * (c * m - 1)) := by ring
    omega
  rw [hbit c hc outBytes (8 * k + j) hp_lo hp_hi h]
  /- Now we need: (S_minus_1 B)[8*k + j - 1344*(c*m-1)] = false.
     The offset = 8*(k - 168*(c*m-1)) + j ∈ [8*36, 8*165) + [0,8) = [288, 1320). -/
  have hoffset : 8 * k + j - 1344 * (c * m - 1) = 8 * (k - 168 * (c * m - 1)) + j := by
    have h1 : 1344 * (c * m - 1) = 8 * (168 * (c * m - 1)) := by ring
    omega
  apply S_minus_1_zero_bits B
  · rw [hoffset]
    have h_off : 36 ≤ k - 168 * (c * m - 1) := by omega
    omega
  · rw [hoffset]
    have h_off : k - 168 * (c * m - 1) < 165 := by omega
    omega

/-! ## §6. Prefix stability of `shake128`

For any seed `B`, the byte stream `shake128 B M` is a prefix of
`shake128 B N` whenever `M ≤ N`.  This follows from
`sponge.squeeze1_concat_bits`: the bits of one `(8·N)`-bit squeeze are
the concatenation of the bits of an `(8·M)`-bit squeeze and the bits of
an `(8·(N - M))`-bit continuation squeeze.
-/

/-- **Bit-level prefix stability for the SHAKE128 squeeze stream.**
For any seed and any extra count `m`, the first `n` bits of an `(n+m)`-bit
squeeze coincide with the bits of an `n`-bit squeeze (both starting from
the post-Absorb state). -/
private theorem SHAKE128.squeeze1_prefix_bit
    {n_seed : Nat} (seed : 𝔹 n_seed)
    (n m : Nat) (i : Nat) (hi : i < n) :
    (Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide)
       (SHAKE128.absorb SHAKE128.init seed) n).2[i]'hi
    = (Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide)
       (SHAKE128.absorb SHAKE128.init seed) (n + m)).2[i]'(by omega) := by
  set init_s := SHAKE128.absorb SHAKE128.init seed
  have hbits := congrArg Prod.snd
    (sponge.squeeze1_concat_bits KECCAK_f (b - 256) (by decide) init_s n m)
  simp only at hbits
  /- hbits : (sq n).2 ‖ (sq' m).2 = (sq (n+m)).2 -- both Vector Bool (n+m). -/
  have h_idx : i < n + m := by omega
  have heq : ((Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide) init_s n).2 ‖
              (Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide)
                (Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide) init_s n).1 m).2)[i]'h_idx
            = (Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide) init_s (n + m)).2[i]'h_idx := by
    exact congrArg (fun (v : Vector Bool (n + m)) => v[i]'h_idx) hbits
  /- heq says: index i of the appended Vector equals index i of the (n+m) squeeze. -/
  rw [← heq]
  rw [show ((Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide) init_s n).2 ‖
            (Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide)
              (Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide) init_s n).1 m).2)
          = ((Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide) init_s n).2 ++
             (Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide)
               (Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide) init_s n).1 m).2) from rfl]
  rw [Vector.getElem_append, dif_pos hi]

/-- **Byte-level prefix stability for `shake128`.** -/
theorem SHAKE128.shake128_prefix_byte {n_seed : Nat} (seed : 𝔹 n_seed)
    (M N : Nat) (hMN : M ≤ N) (i : Nat) (hi : i < M) :
    (shake128 seed M)[i]'hi = (shake128 seed N)[i]'(by omega) := by
  apply Spec.Byte.ext_testBit
  intro j hj
  set init_s := SHAKE128.absorb SHAKE128.init seed with h_init_s
  /- Rewrite both sides via bitsToBytes form. -/
  rw [show shake128 seed M
        = bitsToBytes (Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide)
            init_s (8 * M)).2 from
      (SHAKE128.bitsToBytes_squeeze1_init_eq_shake128 seed M).symm]
  rw [show shake128 seed N
        = bitsToBytes (Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide)
            init_s (8 * N)).2 from
      (SHAKE128.bitsToBytes_squeeze1_init_eq_shake128 seed N).symm]
  have hi_N : i < N := by omega
  rw [bitsToBytes_testBit _ i hi j hj, bitsToBytes_testBit _ i hi_N j hj]
  /- Goal: (sq 8M).2[8i+j] = (sq 8N).2[8i+j].
     Use the helper to bridge across types: 8N = 8M + 8(N-M). -/
  have h_aux : ∀ (k : Nat) (_hk : k = 8 * N),
      (Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide) init_s k).2[8 * i + j]'(by omega)
      = (Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide) init_s (8 * N)).2[8 * i + j]'(by omega) := by
    intros k hk
    subst hk; rfl
  rw [← h_aux (8 * M + 8 * (N - M)) (by omega)]
  exact SHAKE128.squeeze1_prefix_bit seed (8 * M) (8 * (N - M)) (8 * i + j) (by omega)

end Spec.SHA3
