/-
  # Bridges/Encoding.lean — bit-pack + Compress/Decompress fast-formula bridges.

  Tracks divergence categories **A1** (Compress/Decompress identities),
  **A2** (ByteEncode_d bit-pack), **A3** (ByteDecode_d bit-unpack).

  ## Why this file exists

  ### A1 — `Compress_d` / `Decompress_d` fast formulas

  Spec (FIPS 203 §4.2.1, Eq. (4.7)):

      Compress_d(x) := round(2^d · x / q) mod 2^d

  Impl (`poly_element_compress_and_encode` in `ntt.rs`):

      y := ((x << d) · MULCONSTANT + (1 << (SHIFTCONSTANT - 1))) >> SHIFTCONSTANT

  where for ML-KEM:
      MULCONSTANT     = 2580335           -- ≈ 2^33 / q
      SHIFTCONSTANT   = 33
      q               = 3329

  Equivalence: for `x ∈ [0, q)`, the bit-shift formula equals
  `round((2^d · x) / q) mod 2^d`. This is the standard Barrett-like
  approximation: `2^33 / q = 2580335.18…`, and `(x << d) · 2580335`
  approximates `2^33 · 2^d · x / q` to within rounding error covered by
  the `+ (1 << 32)` half-bit adjustment.

  Verified by exhaustive 11·3329-case `decide` (per `d`, all 3329 inputs);
  or by a Barrett-bound argument over the integers.

  Similarly for Decompress (Eq. (4.8)):

      Decompress_d(y) := round(q · y / 2^d)        -- range [0, q)

  Impl: `(y · q + (1 << (d-1))) >> d`. Direct from definition.

  ### A2 — `ByteEncode_d` bit-pack

  Spec (Algorithm 5): for each `i ∈ [0, 256)`, write the `d`-bit binary
  representation of `F[i].val` into bits `[i·d, (i+1)·d)`, then pack 8
  consecutive bits into a byte.

  Impl: a tight loop accumulating `d`-bit values into a `u64`/`u32`
  shift register, emitting bytes when ≥ 8 bits are buffered.

  Equivalence: standard byte-bit serialization identity. Stated as
  `arrayToSpecBytes (compress_and_encode d F) = ByteEncode d F`.

  ### A3 — `ByteDecode_d` bit-unpack

  Spec (Algorithm 6): unpack a byte array into a sequence of `d`-bit
  integers. Impl: shift-register pattern as above. Inverse of A2.
-/
import Symcrust.Properties.MLKEM.Basic
import Mathlib.Algebra.BigOperators.Fin

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open Symcrust
open scoped Spec.Notations

namespace Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 1000000
set_option maxRecDepth 4000

/-! ## Streaming-state invariant for the bit-pump

The Rust per-polynomial compress-and-encode loop pumps `d` bits per
coefficient through a 32-bit shift register (`accumulator` +
`n_bits_in_accumulator`), flushing 4 bytes at a time to `pb_dst`. The
streaming invariant relates the *partial* state mid-loop to the
bit-prefix of the eventual output. Defined here after `fastCompress`. -/

/-! ## Compress-then-encode wrapper (handling `d = 12`)

The Rust `poly_element_compress_and_encode` is called with `1 ≤ d ≤ 12`.
The spec's `Polynomial.Compress` is only defined for `d < 12` because
at `d = 12` no compression occurs (the input is already in `Zq` and
`m 12 = q`). This helper unifies both cases for use in FC
postconditions. -/

/-- Combined compress-then-encode: applies `Compress_d` then
`ByteEncode_d` when `d < 12`; at `d = 12`, encodes the polynomial
directly (since `m 12 = q`). -/
def compressEncodePoly (d : ℕ) (p : MLKEM.Polynomial)
    (h_d : 1 ≤ d ∧ d ≤ 12) : 𝔹 (32 * d) :=
  if h : d < 12 then
    MLKEM.ByteEncode d
      (MLKEM.Polynomial.Compress d p ⟨h_d.1, h⟩) ⟨h_d.1, h_d.2⟩
  else
    have heq : Spec.MLKEM.q = MLKEM.m d := by
      have h12 : d = 12 := by grind
      simp [MLKEM.m, h12]
    MLKEM.ByteEncode d (heq ▸ p) ⟨h_d.1, h_d.2⟩

/-- Combined decode-then-decompress: inverse of `compressEncodePoly`. -/
def decodeDecompressPoly (d : ℕ) (B : 𝔹 (32 * d))
    (h_d : 1 ≤ d ∧ d ≤ 12) : MLKEM.Polynomial :=
  if h : d < 12 then
    MLKEM.Polynomial.Decompress d
      (MLKEM.ByteDecode B ⟨h_d.1, h_d.2⟩) ⟨h_d.1, h⟩
  else
    have heq : MLKEM.m d = Spec.MLKEM.q := by
      have h12 : d = 12 := by grind
      simp [MLKEM.m, h12]
    heq ▸ MLKEM.ByteDecode B ⟨h_d.1, h_d.2⟩

/-! ## A1 — Compress / Decompress fast formulas

The impl's `COMPRESS_MULCONSTANT = 2580335`, `COMPRESS_SHIFTCONSTANT = 33`. -/

/-- The fast-Compress shift register, modelled at the `Nat` level.

`fast_compress d x = ((x · 2^d) · 2580335 + 2^32) >>> 33 mod 2^d`. -/
@[reducible] def fastCompress (d : Nat) (x : Nat) : Nat :=
  ((x * 2^d * 2580335 + 2^32) / 2^33) % 2^d

/-- **A1.1** — fast-Compress equals spec `Compress_d`.

For `x ∈ [0, q)` and `1 ≤ d < 12`:

    fastCompress d x = (MLKEM.Compress d (x : Zq)).val

Informal proof: by case split on `d ∈ {1, …, 11}` and exhaustive
`x ∈ [0, 3329)`: `native_decide` over the 11 · 3329 ≈ 36 k combinations,
checking that the integer-shifted product matches the rounded rational.

Alternative analytic proof: `(x · 2^d · 2580335 + 2^32) / 2^33`
deviates from `(2^d · x) / q` by at most `1/2`, so the floor equals
`round(2^d · x / q)` (this is the Barrett-reduction soundness
argument). -/
theorem fastCompress_eq_spec_compress (d : Nat) (x : Nat)
    (h_d : 1 ≤ d ∧ d < 12) (h_x : x < q) :
    fastCompress d x = (MLKEM.Compress d (x : Zq)).val := by
  have hall : ∀ d : Fin 12, ∀ h1 : 1 ≤ d.val, ∀ x : Fin 3329,
      fastCompress d.val x.val = (MLKEM.Compress d.val ((x.val : Zq)) ⟨h1, d.isLt⟩).val := by
    native_decide
  exact hall ⟨d, h_d.2⟩ h_d.1 ⟨x, h_x⟩

/-- The fast-Decompress formula.

`fast_decompress d y = (y · q + 2^(d-1)) / 2^d`, range `[0, q)`. -/
@[reducible] def fastDecompress (d : Nat) (y : Nat) : Nat :=
  (y * q + 2^(d - 1)) / 2^d

/-- **A1.2** — fast-Decompress equals spec `Decompress_d`.

Informal proof: direct from the definition.
`round((q · y) / 2^d) = (q · y + 2^(d-1)) / 2^d` for any `y ∈ ℕ`,
since `2^(d-1)` is the half-bit rounding adjustment. -/
theorem fastDecompress_eq_spec_decompress (d : Nat) (y : Nat)
    (h_d : 1 ≤ d ∧ d < 12) (h_y : y < 2^d) :
    fastDecompress d y = (MLKEM.Decompress d (y : ZMod (MLKEM.m d))).val := by
  unfold fastDecompress MLKEM.Decompress
  have hd12 : d < 12 := h_d.2
  have hd1 : 1 ≤ d := h_d.1
  have hm : MLKEM.m d = 2^d := by simp [MLKEM.m, hd12]
  have hyval : ((y : ZMod (MLKEM.m d))).val = y := by
    rw [hm]; exact ZMod.val_cast_of_lt h_y
  rw [hyval]
  have round_div : ⌈ ((q : ℚ) / (2^d : ℚ)) * (y : ℚ) ⌋
                  = ((2 * (q * y) + 2^d : ℕ) : ℤ) / ((2 * 2^d : ℕ) : ℤ) := by
    unfold rat_round
    have heq : (q : ℚ) / (2^d : ℚ) * (y : ℚ) + 1/2
               = (((2*(q*y) + 2^d : ℕ)) : ℚ) / ((2 * 2^d : ℕ) : ℚ) := by
      push_cast; field_simp
    rw [heq, Rat.floor_natCast_div_natCast]
  rw [round_div]
  have h2d_pos : 0 < 2^d := Nat.pos_of_ne_zero (by positivity)
  have hpow : 2 * 2^(d-1) = 2^d := by
    conv_rhs => rw [show d = (d-1)+1 from by omega]
    rw [pow_succ]; ring
  have h_quotient : ((2 * (q * y) + 2^d : ℕ) : ℤ) / ((2 * 2^d : ℕ) : ℤ)
                    = ((y * q + 2^(d-1)) / 2^d : ℕ) := by
    have h1 : (2 * (q * y) + 2^d : ℕ) = 2 * (y * q + 2^(d-1)) := by rw [← hpow]; ring
    rw [h1]; push_cast
    rw [Int.mul_ediv_mul_of_pos _ _ (by norm_num : (0:ℤ) < 2)]
  rw [h_quotient]
  have hq_val : (q : ℕ) = 3329 := rfl
  have h21 : 2^(d-1) ≤ 2^10 := Nat.pow_le_pow_right (by norm_num) (by omega)
  have hbound : (y * q + 2^(d-1)) / 2^d < q := by
    apply Nat.div_lt_of_lt_mul
    set v := 2^d with hv_def
    have hy' : y + 1 ≤ v := h_y
    have hq_big : 2^(d-1) < q := by rw [hq_val]; omega
    calc y * q + 2^(d-1)
        < y * q + q := by omega
      _ = (y + 1) * q := by ring
      _ ≤ v * q := Nat.mul_le_mul_right q hy'
  simp only [Int.cast_natCast]
  exact (ZMod.val_natCast_of_lt hbound).symm

/-! ## A2 — `ByteEncode_d` bit-pack identity

Given a `Polynomial (m d) = Vector (ZMod (m d)) 256` of `d`-bit values,
the spec `ByteEncode d F : 𝔹 (32·d)` concatenates the binary
expansions and packs 8 bits per byte.

The impl's `poly_element_compress_and_encode` writes the same byte
sequence: at each `j ∈ [0, 256)`, it appends `d` bits of
`fastCompress d F[j].val` to a shift register; when the register
holds ≥ 8 bits, the low byte is emitted.

We do **NOT** introduce a generic `bitPackEncode` helper here (would
either require a `sorry`'d def — which we avoid — or a concrete recursive
body we don't need at this
layer). Instead, the FC of `poly_element_compress_and_encode.spec`
cites `MLKEM.ByteEncode` directly, with the bridge below
linking them.
-/

/-- Index bound for `byteEncode_byte_invariant`: `(8·k + j) / d < 256`
under the standard ML-KEM bit-layout constraints. Tagged `@[grind]`
so callers (and the statement of `byteEncode_byte_invariant` itself)
get the bound for free. -/
@[grind .]
theorem byteEncode_idx_bound
    {d : Nat} (h_d_lo : 1 ≤ d) (_h_d_hi : d ≤ 12)
    {k : Nat} (h_k : k < 32 * d) {j : Nat} (h_j : j < 8) :
    (8 * k + j) / d < 256 := by
  have h_d_pos : 0 < d := h_d_lo
  rw [Nat.div_lt_iff_lt_mul h_d_pos]
  grind

/-- Inner arithmetic helper for `byteEncode_byte_invariant`: after the
inner-loop body writes `b[i*d+j] = Bool.ofNat (a%2)`, we have
`b[i*d+j].toNat = a%2`, so `(a - b[i*d+j].toNat) / 2 = a / 2`. -/
private theorem inner_shift_step (a : Nat) :
    (a - (Bool.ofNat (a % 2)).toNat) / 2 = a / 2 := by
  have : (Bool.ofNat (a % 2)).toNat = a % 2 := by
    rcases h : a % 2 with _ | n
    · simp [Bool.ofNat]
    · have hn : n = 0 := by have := Nat.mod_lt a (by norm_num : (0:Nat) < 2); omega
      subst hn; simp [Bool.ofNat]
  rw [this]; omega

/-- After `r` inner-shift steps starting from `a = F[i].val`, the
running value equals `F[i].val >>> r`, and `(a >>> r) % 2` is the
`r`-th bit of `a`. -/
private theorem ofNat_shiftRight_mod_two_eq_testBit (a r : Nat) :
    Bool.ofNat ((a >>> r) % 2) = Nat.testBit a r := by
  rw [Nat.testBit]
  rcases h : (a >>> r) % 2 with _ | n
  · simp [Bool.ofNat, h]
  · have hn : n = 0 := by have := Nat.mod_lt (a >>> r) (by norm_num : (0:Nat) < 2); omega
    subst hn; simp [Bool.ofNat, h]

/-- Sum-of-bits-times-powers-of-2 identity (for `byteDecode_byteEncode`). -/
private theorem sum_testBit_pow_eq (a d : Nat) (h_lt : a < 2 ^ d) :
    ∑ j : Fin d, (Nat.testBit a j.val).toNat * 2 ^ j.val = a := by
  induction d generalizing a with
  | zero => simp at h_lt; subst h_lt; simp
  | succ d ih =>
    have h2pos : (0 : Nat) < 2 := by norm_num
    rw [Fin.sum_univ_succ]
    have h_a2 : a / 2 < 2 ^ d := by
      rw [Nat.div_lt_iff_lt_mul h2pos]
      rw [show 2 ^ d * 2 = 2 ^ (d + 1) from by rw [pow_succ]] -- a < 2^(d+1) = 2^d * 2
      exact h_lt
    have ih' := ih (a / 2) h_a2
    have h_shift : ∀ k, Nat.testBit (a / 2) k = Nat.testBit a (k + 1) := by
      intro k
      have h1 : a / 2 = a >>> 1 := by simp [Nat.shiftRight_eq_div_pow]
      rw [h1, Nat.testBit_shiftRight, Nat.add_comm]
    have h_zero : (Nat.testBit a 0).toNat = a % 2 := by
      rw [Nat.testBit_zero]
      rcases h : a % 2 with _ | n
      · simp
      · have hn : n = 0 := by have := Nat.mod_lt a h2pos; omega
        subst hn; simp
    simp only [Fin.val_zero, pow_zero, mul_one, Fin.val_succ, h_zero]
    have h_inner : ∀ j : Fin d,
        (Nat.testBit a (j.val + 1)).toNat * 2 ^ (j.val + 1) =
        2 * ((Nat.testBit (a / 2) j.val).toNat * 2 ^ j.val) := by
      intro j
      rw [h_shift j.val]; ring
    simp_rw [h_inner]
    rw [← Finset.mul_sum, ih']
    omega

/-- Inner-loop fact for `MLKEM.ByteEncode`: starting from `(F[i].val, b_in)`
and running the `d`-iteration body, the resulting accumulator is
`F[i].val >>> d` and the resulting bit vector matches `b_in` outside
positions `[i*d, i*d + d)` and `Nat.testBit F[i].val (n - i*d)` inside. -/
private theorem byteEncode_inner_aux
    (d : Nat) (h_d_lo : 1 ≤ d) (h_d_hi : d ≤ 12)
    (F : MLKEM.Polynomial (MLKEM.m d)) (i : Nat) (h_i : i < 256)
    (b_in : Vector Bool (256 * d)) :
    let xs : List Nat := List.range' 0 d 1
    let body : (a : Nat) → a ∈ xs → (Nat × Vector Bool (256 * d)) →
        Id (ForInStep (Nat × Vector Bool (256 * d))) :=
      fun a m b =>
        have h_idx : i * d + a < 256 * d := by
          have hj_mem : a ∈ List.range' 0 d 1 := m
          have hj_range := List.mem_range'.mp hj_mem
          have _hj : a < d := by omega
          calc i * d + a < i * d + d := by omega
            _ = (i + 1) * d := by ring
            _ ≤ 256 * d := Nat.mul_le_mul_right d (by omega)
        (do pure PUnit.unit
            pure (ForInStep.yield
              ⟨(b.fst - (b.snd.set (i * d + a) (Bool.ofNat (b.fst % 2)) h_idx)[i * d + a].toNat) / 2,
                b.snd.set (i * d + a) (Bool.ofNat (b.fst % 2)) h_idx⟩) : Id _)
    let result := Id.run (forIn' xs ((F[i].val, b_in) : Nat × Vector Bool (256 * d)) body)
    result.fst = F[i].val >>> d ∧
    ∀ n (hn : n < 256 * d),
      result.snd[n] = if i * d ≤ n ∧ n < i * d + d then
                         Nat.testBit F[i].val (n - i * d)
                       else b_in[n] := by
  intro xs body
  let P : Nat → Nat × Vector Bool (256 * d) → Prop := fun step ab =>
    ab.1 = F[i].val >>> step ∧
    ∀ n (hn : n < 256 * d),
      ab.2[n] = if i * d ≤ n ∧ n < i * d + step then
                  Nat.testBit F[i].val (n - i * d)
                else b_in[n]
  have hInit : P 0 (F[i].val, b_in) := by
    refine ⟨by simp, ?_⟩
    intro n hn
    have h_not : ¬ (i * d ≤ n ∧ n < i * d + 0) := by omega
    simp only [h_not, if_false]
  have hLen : xs.length = d := by simp [xs]
  have hLoop := List.forIn'_id_invariant_indexed xs (F[i].val, b_in) body P hInit ?_
  · rw [hLen] at hLoop; exact hLoop
  · intro step hstep ab hPstep j hj hj_eq
    have hj_val : j = step := by
      rw [hj_eq]; simp [xs, List.getElem_range']
    have hj_val_sym : step = j := hj_val.symm
    subst hj_val_sym
    rw [hLen] at hstep
    obtain ⟨ha_eq, hb_eq⟩ := hPstep
    have h_idx : i * d + step < 256 * d := by
      calc i * d + step < i * d + d := by omega
        _ = (i + 1) * d := by ring
        _ ≤ 256 * d := Nat.mul_le_mul_right d (by omega)
    refine ⟨_, rfl, ?_, ?_⟩
    · show ((ab.1 - (ab.2.set (i * d + step) (Bool.ofNat (ab.1 % 2)) h_idx)[i * d + step].toNat) / 2 :
            Nat) = F[i].val >>> (step + 1)
      rw [Vector.getElem_set_self]
      rw [inner_shift_step, ha_eq]
      rw [show F[i].val >>> step / 2 = F[i].val >>> step >>> 1 from by
            simp [Nat.shiftRight_eq_div_pow]]
      rw [show F[i].val >>> step >>> 1 = F[i].val >>> (step + 1) from by
            rw [← Nat.shiftRight_add]]
    · intro n hn
      by_cases h_eq : n = i * d + step
      · subst h_eq
        rw [Vector.getElem_set_self]
        have h_in : i * d ≤ i * d + step ∧ i * d + step < i * d + (step + 1) := by omega
        have h_sub : i * d + step - i * d = step := by omega
        rw [if_pos h_in, h_sub]
        have h_ofN := ofNat_shiftRight_mod_two_eq_testBit F[i].val step
        rw [← h_ofN, ha_eq]
      · rw [Vector.getElem_set_ne h_idx hn (by omega)]
        have h_old := hb_eq n hn
        rw [h_old]
        by_cases h_in_old : i * d ≤ n ∧ n < i * d + step
        · have h_in_new : i * d ≤ n ∧ n < i * d + (step + 1) := ⟨h_in_old.1, by omega⟩
          rw [if_pos h_in_old, if_pos h_in_new]
        · have h_not_new : ¬ (i * d ≤ n ∧ n < i * d + (step + 1)) := by
            intro ⟨h_le, h_lt⟩
            apply h_in_old
            exact ⟨h_le, by omega⟩
          rw [if_neg h_in_old, if_neg h_not_new]

/-- **A2.1** — per-bit identity for the byte-encode bit pump.

For `k < 32·d` and `j < 8`, bit `j` of byte `k` of `MLKEM.ByteEncode d F`
equals bit `(8·k + j) % d` of `F[(8·k + j) / d].val`.

Informal proof.  Unfolding `MLKEM.ByteEncode` (Algorithm 5):
1. The inner loop establishes `b[i·d + r] = Bool.ofNat ((F[i].val >>> r) % 2)
   = Nat.testBit F[i].val r` for `i < 256, r < d`, by direct induction on
   `r`: the spec computes `b[i·d + r] = (a % 2)` with `a` initially
   `F[i].val` and `a := (a - b[i·d + r].toNat) / 2 = a / 2` after each write,
   so after `r` iterations `a = F[i].val / 2^r` and `b[i·d + r] = a % 2 =
   Nat.testBit F[i].val r`.
2. Substituting `n := 8·k + j` and rewriting `n = (n/d)·d + (n%d)` gives
   `b[n] = Nat.testBit F[n/d].val (n%d)`.
3. The outermost `BitsToBytes` packs 8 bits per byte; by
   `Spec.bitsToBytes_testBit`, bit `j` of byte `k` of
   `BitsToBytes b` equals `b[8·k + j]`.  Combine with step 2.

The per-byte aggregation `byte_k.toNat = Σ m:Fin 8, b_m · 2^m` follows
by `Nat.eq_of_testBit_eq` from the per-bit form; we state the per-bit
form because it composes more directly with the impl's shift-register
invariants. -/
theorem byteEncode_byte_invariant (d : Nat) (h_d : 1 ≤ d ∧ d ≤ 12)
    (F : MLKEM.Polynomial (MLKEM.m d))
    (k : Nat) (h_k : k < 32 * d) (j : Nat) (h_j : j < 8) :
    haveI h_idx : (8 * k + j) / d < 256 :=
      byteEncode_idx_bound h_d.1 h_d.2 h_k h_j
    ((MLKEM.ByteEncode d F h_d).get ⟨k, h_k⟩).toNat.testBit j =
      (F.get ⟨(8 * k + j) / d, h_idx⟩).val.testBit ((8 * k + j) % d) := by
  have h_d_lo : 1 ≤ d := h_d.1
  have h_d_hi : d ≤ 12 := h_d.2
  have h_d_pos : 0 < d := h_d_lo
  have h_idx : (8 * k + j) / d < 256 := byteEncode_idx_bound h_d_lo h_d_hi h_k h_j
  -- Switch to `getElem`.
  show ((MLKEM.ByteEncode d F h_d)[k]).toNat.testBit j =
       Nat.testBit (F[(8 * k + j) / d]).val ((8 * k + j) % d)
  set n := 8 * k + j with hn_def
  have h_n_bound : n < 256 * d := by
    have h_n_lt : n < 32 * d * 8 := by simp [hn_def]; omega
    linarith
  have h_n8 : n < 8 * (32 * d) := by omega
  have h_n_div : n / d < 256 := h_idx
  -- The inner expression of `MLKEM.ByteEncode` (post-`Aeneas.SRRange` reduction).
  unfold MLKEM.ByteEncode
  simp only [Aeneas.SRRange.forIn'_eq_forIn'_range', SRRange.size,
             Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one]
  -- Now goal is `(Id.run (do let r ← outer; pure (BitsToBytes (Vector.cast _ r))))[k].toNat.testBit j = ...`.
  -- In `Id`, `do let r ← x; pure (f r) = f x`, so we can pull `BitsToBytes` out.
  show ((BitsToBytes ((Id.run (forIn' (List.range' 0 256) _ _) :
              Vector Bool (256 * d)).cast (by grind : 256 * d = 8 * (32 * d))))[k]).toNat.testBit j
       = Nat.testBit F[(8 * k + j) / d].val ((8 * k + j) % d)
  rw [bitsToBytes_testBit _ k h_k j h_j]
  show (((Id.run (forIn' (List.range' 0 256) _ _) :
              Vector Bool (256 * d)).cast _) : Vector Bool (8 * (32 * d)))[8 * k + j] =
         Nat.testBit F[(8 * k + j) / d].val ((8 * k + j) % d)
  rw [show ((((Id.run (forIn' (List.range' 0 256) _ _) :
              Vector Bool (256 * d)).cast _) : Vector Bool (8 * (32 * d)))[8 * k + j])
          = (Id.run (forIn' (List.range' 0 256)
              (Vector.replicate (256 * d) (0 : Bool)) _) : Vector Bool (256 * d))[n]'h_n_bound
          from rfl]
  · -- Now goal: (forIn' result)[n] = Nat.testBit F[n/d].val (n%d)
    refine forIn'_getElem_indexed (List.range' 0 256) _ _ n h_n_bound _
      (P := fun s b => b[n]'h_n_bound = if s ≤ n / d then (0 : Bool)
                                          else Nat.testBit F[n / d].val (n % d))
      ?hInit ?hFinal ?hStep
    case hInit =>
      simp [Vector.getElem_replicate]
    case hFinal =>
      intro dw hP
      have h_len : (List.range' 0 256).length = 256 := by simp
      rw [h_len] at hP
      have : ¬ 256 ≤ n / d := by omega
      rw [if_neg this] at hP
      exact hP
    case hStep =>
      intro s hs ab hPs i hi hi_eq
      have h_len : (List.range' 0 256).length = 256 := by simp [List.length_range']
      rw [h_len] at hs
      have hi_val : i = s := by rw [hi_eq]; simp [List.getElem_range']
      have hi_val_sym : s = i := hi_val.symm
      subst hi_val_sym
      -- INLINE invariant route: directly apply `List.forIn'_id_invariant_indexed`
      -- to the goal's inner `forIn'`. The body is captured by unification with
      -- the goal, so there is no body-shape comparison.
      refine ⟨_, rfl, ?_⟩
      simp only [] at *
      -- Bridge the outer-loop RHS via case analysis on (s*d ≤ n ∧ n < s*d+d).
      have hRHS_eq :
          (if s + 1 ≤ n / d then (0 : Bool) else F[n / d].val.testBit (n % d)) =
          (if s * d ≤ n ∧ n < s * d + d then F[s].val.testBit (n - s * d) else ab[n]'h_n_bound) := by
        by_cases hcase : s * d ≤ n ∧ n < s * d + d
        · rw [if_pos hcase]
          obtain ⟨h_le, h_lt⟩ := hcase
          have h_nd : n / d = s := by
            have h_lt' : n < (s + 1) * d := by
              have : (s + 1) * d = s * d + d := by ring
              omega
            have h_ge : s ≤ n / d := by
              have := Nat.div_le_div_right (h := h_le) (c := d)
              rwa [Nat.mul_div_cancel s h_d_pos] at this
            have h_lt'' : n / d < s + 1 :=
              (Nat.div_lt_iff_lt_mul h_d_pos).mpr h_lt'
            omega
          have h_nmod : n % d = n - s * d := by
            have h_dm := Nat.div_add_mod n d
            rw [h_nd] at h_dm
            have h_le' : s * d ≤ n := h_le
            have : s * d = d * s := Nat.mul_comm s d
            omega
          have hne : ¬ s + 1 ≤ n / d := by rw [h_nd]; omega
          rw [if_neg hne]
          have hF : F[n / d]'(by rw [h_nd]; exact hs) = F[s] := by
            simp [h_nd]
          rw [hF, h_nmod]
        · rw [if_neg hcase, hPs]
          push Not at hcase
          by_cases h_le : s * d ≤ n
          · have h_ge : s * d + d ≤ n := hcase h_le
            have h_div_ge : s + 1 ≤ n / d := by
              have h_mul : (s + 1) * d ≤ n := by
                have : (s + 1) * d = s * d + d := by ring
                omega
              exact (Nat.le_div_iff_mul_le h_d_pos).mpr h_mul
            have h_div_ge' : s ≤ n / d := by omega
            rw [if_pos h_div_ge', if_pos h_div_ge]
          · push Not at h_le
            have h_div_lt : n / d < s := by
              apply (Nat.div_lt_iff_lt_mul h_d_pos).mpr
              omega
            have h1 : ¬ s ≤ n / d := by omega
            have h2 : ¬ s + 1 ≤ n / d := by omega
            rw [if_neg h1, if_neg h2]
      rw [hRHS_eq]
      -- INLINE invariant approach: apply `forIn'_pair_snd_indexed` to the
      -- goal's `forIn'` directly. The body is captured via unification with
      -- the goal, sidestepping all body-shape comparison. P tracks BOTH the
      -- shift-register accumulator (.fst) and the bit at position n (.snd[n]).
      refine forIn'_mprod_snd_indexed (List.range' 0 d) ⟨F[s].val, ab⟩ _ n h_n_bound _
        (fun step pair =>
          pair.fst = F[s].val >>> step ∧
          pair.snd[n]'h_n_bound =
            if s * d ≤ n ∧ n < s * d + step then F[s].val.testBit (n - s * d)
            else ab[n]'h_n_bound)
        ?hInit ?hFinal ?hStep
      case hInit =>
        refine ⟨?_, ?_⟩
        · show F[s].val = F[s].val >>> 0
          simp
        · show ab[n]'h_n_bound = if s * d ≤ n ∧ n < s * d + 0 then _ else ab[n]'h_n_bound
          have h_not : ¬ (s * d ≤ n ∧ n < s * d + 0) := by omega
          rw [if_neg h_not]
      case hFinal => -- extract the .snd[n] part at step = d.
        intro pair hP
        have h_len_xs : (List.range' 0 d).length = d := by simp
        rw [h_len_xs] at hP
        exact hP.2
      case hStep => -- step extension for the inner loop body.
        intro step hstep' state hPstate a' ha' ha'_eq
        have h_len_xs : (List.range' 0 d).length = d := by simp
        have hstep_lt_d : step < d := h_len_xs ▸ hstep'
        have ha'_val : a' = step := by
          rw [ha'_eq]; simp [List.getElem_range']
        have h_idx : s * d + a' < 256 * d := by
          calc s * d + a' < s * d + d := by rw [ha'_val]; omega
            _ = (s + 1) * d := by ring
            _ ≤ 256 * d := Nat.mul_le_mul_right d (by omega)
        obtain ⟨h_fst_eq, h_snd_eq⟩ := hPstate
        -- The body of the goal's inner loop. After unification, Lean knows
        -- `body a' ha' state = pure (.yield ⟨new_state⟩)` for the FIPS body.
        refine ⟨_, rfl, ?_, ?_⟩
        · -- New .fst = F[s].val >>> (step + 1).
          simp only [ha'_val]
          show ((state.fst -
                (state.snd.set (s * d + step) (Bool.ofNat (state.fst % 2)) (ha'_val ▸ h_idx))[s * d + step].toNat) / 2 :
                Nat) = F[s].val >>> (step + 1)
          rw [Vector.getElem_set_self]
          rw [inner_shift_step, h_fst_eq]
          rw [show F[s].val >>> step / 2 = F[s].val >>> step >>> 1 from by
                simp [Nat.shiftRight_eq_div_pow]]
          rw [show F[s].val >>> step >>> 1 = F[s].val >>> (step + 1) from by
                rw [← Nat.shiftRight_add]]
        · -- New .snd[n] = if-then-else (s*d+(step+1)).
          simp only [ha'_val]
          show (state.snd.set (s * d + step) (Bool.ofNat (state.fst % 2)) (ha'_val ▸ h_idx))[n]'h_n_bound =
            if s * d ≤ n ∧ n < s * d + (step + 1) then F[s].val.testBit (n - s * d)
            else ab[n]'h_n_bound
          have h_idx_step : s * d + step < 256 * d := ha'_val ▸ h_idx
          rw [Vector.getElem_set h_idx_step h_n_bound]
          by_cases h_eq : s * d + step = n
          · -- We just wrote bit `step` at position `n = s*d + step`.
            rw [if_pos h_eq]
            have h_in : s * d ≤ n ∧ n < s * d + (step + 1) := by omega
            have h_sub : n - s * d = step := by omega
            rw [if_pos h_in, h_sub]
            -- The accumulator at iteration `step` is `F[s].val >>> step`,
            -- so `state.fst % 2 = testBit F[s].val step`.
            have h_ofN := ofNat_shiftRight_mod_two_eq_testBit F[s].val step
            rw [← h_ofN, h_fst_eq]
          · -- Position `n` is not the one just written; the bit is unchanged.
            rw [if_neg h_eq, h_snd_eq]
            by_cases h_in_old : s * d ≤ n ∧ n < s * d + step
            · have h_in_new : s * d ≤ n ∧ n < s * d + (step + 1) := ⟨h_in_old.1, by omega⟩
              rw [if_pos h_in_old, if_pos h_in_new]
            · have h_not_new : ¬ (s * d ≤ n ∧ n < s * d + (step + 1)) := by
                intro ⟨h_le, h_lt⟩
                apply h_in_old
                exact ⟨h_le, by omega⟩
              rw [if_neg h_in_old, if_neg h_not_new]

/-! ## A3 — `ByteDecode_d` bit-unpack identity

Inverse of A2. The impl's `poly_element_decode_and_decompress` reads
the byte stream into a shift register and emits `d`-bit values to fill
`F[j]` for `j ∈ [0, 256)`. -/

/-- **A3.1** — top-level byte-decode round-trip with A2.

For any `F : Polynomial (m d)`,

    MLKEM.ByteDecode (MLKEM.ByteEncode d F) = F

Informal proof: standard composition. By unfolding `ByteEncode` and
`ByteDecode` together, each `d`-bit segment is written and then read
unchanged: the bit `b[i*d+j]` set by `ByteEncode` at iteration `(i, j)`
is exactly the bit recovered by `ByteDecode` at iteration `(i, j)`. -/
theorem byteDecode_byteEncode (d : Nat) (h_d : 1 ≤ d ∧ d ≤ 12)
    (F : MLKEM.Polynomial (MLKEM.m d)) :
    MLKEM.ByteDecode (MLKEM.ByteEncode d F) = F := by
  have h_d_lo : 1 ≤ d := h_d.1
  have h_d_hi : d ≤ 12 := h_d.2
  have h_d_pos : 0 < d := h_d_lo
  -- `m d = 2^d` for `d < 12`, else `q = 3329`; both positive.
  have h_m_pos : 0 < MLKEM.m d := by
    simp only [MLKEM.m]; split <;> [positivity; exact (by decide : 0 < 3329)]
  haveI : NeZero (MLKEM.m d) := ⟨Nat.pos_iff_ne_zero.mp h_m_pos⟩
  -- Coefficient bound: `F[i].val < 2^d` for both `d < 12` and `d = 12`.
  have h_val_bound : ∀ (i : Nat) (h_i : i < 256), F[i].val < 2 ^ d := by
    intro i h_i
    have := (F[i]).val_lt
    simp only [MLKEM.m] at this
    split_ifs at this with h_d12
    · exact this
    · -- d = 12; this : F[i].val < q = 3329 < 4096 = 2^12.
      have : d = 12 := by omega
      subst this
      exact lt_of_lt_of_le ‹F[i].val < 3329› (by decide : 3329 ≤ 2 ^ 12)
  apply Vector.ext
  intro i h_i
  unfold MLKEM.ByteDecode
  simp only [Aeneas.SRRange.forIn'_eq_forIn'_range', SRRange.size,
             Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one]
  -- Goal: (Id.run (do let b := bytesToBits …; let mut F' := zero; for s in 256 do F' := F'.set s …; pure F'))[i] = F[i]
  refine forIn'_getElem_indexed (List.range' 0 256) _ _ i h_i _
    (P := fun s (F' : MLKEM.Polynomial (MLKEM.m d)) =>
      F'[i]'h_i = if s ≤ i then (0 : ZMod (MLKEM.m d)) else F[i])
    ?hInit ?hFinal ?hStep
  case hInit =>
    -- Initial state is `Polynomial.zero (m d)` (= `Vector.replicate 256 0`).
    show (MLKEM.Polynomial.zero (MLKEM.m d))[i]'h_i =
      if 0 ≤ i then (0 : ZMod (MLKEM.m d)) else F[i]
    simp [MLKEM.Polynomial.zero, Vector.getElem_replicate]
  case hFinal =>
    intro F' hP
    have h_len : (List.range' 0 256).length = 256 := by simp
    rw [h_len] at hP
    have h_n_le : ¬ 256 ≤ i := by omega
    rw [if_neg h_n_le] at hP
    exact hP
  case hStep =>
    intro s hs F' hPF' a' ha' ha'_eq
    have h_len : (List.range' 0 256).length = 256 := by simp
    have hs_lt : s < 256 := h_len ▸ hs
    have ha'_val : a' = s := by rw [ha'_eq]; simp [List.getElem_range']
    have ha'_lt : a' < 256 := ha'_val ▸ hs_lt
    refine ⟨_, rfl, ?_⟩
    -- The invariant P is `fun s F' => …`; reduce the beta-redex first.
    try simp only []
    -- Goal: (F'.set a' new_sum ha'_lt)[i] = if s + 1 ≤ i then 0 else F[i]
    rw [Vector.getElem_set ha'_lt h_i]
    by_cases h_eq : a' = i
    · -- We just wrote at position `i = a' = s`; show new sum = F[i].
      rw [if_pos h_eq]
      have hi_eq_s : s = i := by rw [← ha'_val, h_eq]
      rw [if_neg (by omega : ¬ s + 1 ≤ i)]
      -- Replace `a'` by `i` in the sum.
      simp only [h_eq]
      -- Bit-level identity at position `i * d + j` for `j < d`.
      have h_bits_eq : ∀ (j : Fin d),
          ((Spec.bytesToBits (MLKEM.ByteEncode d F h_d))[i * d + j.val]'(by
            have h_jd : j.val < d := j.isLt
            have : (i + 1) * d ≤ 256 * d := Nat.mul_le_mul_right d (by omega)
            have h_idx : i * d + j.val < (i + 1) * d := by nlinarith
            calc i * d + j.val < (i + 1) * d := h_idx
              _ ≤ 256 * d := this
              _ = 8 * (32 * d) := by ring)).toNat =
          (F[i].val.testBit j.val).toNat := by
        intro j
        have h_jd : j.val < d := j.isLt
        have h_m_bound : i * d + j.val < 8 * (32 * d) := by
          have : (i + 1) * d ≤ 256 * d := Nat.mul_le_mul_right d (by omega)
          nlinarith
        set m_pos := i * d + j.val with hm_def
        -- `bytesToBits B m = B[m/8].toNat.testBit (m%8)` (from definition).
        have h_pos : (Spec.bytesToBits (MLKEM.ByteEncode d F h_d))[m_pos]'h_m_bound =
            ((MLKEM.ByteEncode d F h_d)[m_pos / 8]'(by
              have := h_m_bound; omega)).toNat.testBit (m_pos % 8) := by
          unfold Spec.bytesToBits
          simp [Vector.getElem_ofFn]
        rw [h_pos]
        have h_m8_lt : m_pos / 8 < 32 * d := by
          have := h_m_bound; omega
        have h_mod8 : m_pos % 8 < 8 := Nat.mod_lt _ (by decide)
        have h_inv := byteEncode_byte_invariant d h_d F (m_pos / 8) h_m8_lt (m_pos % 8) h_mod8
        fcongr 1
        change ((MLKEM.ByteEncode d F h_d).get ⟨m_pos / 8, h_m8_lt⟩).toNat.testBit (m_pos % 8) = _
        rw [h_inv]
        have h_idx_eq : (8 * (m_pos / 8) + m_pos % 8) / d = i := by
          have h_recover : 8 * (m_pos / 8) + m_pos % 8 = m_pos := Nat.div_add_mod m_pos 8
          rw [h_recover, hm_def, Nat.mul_comm i d, Nat.add_comm,
              Nat.add_mul_div_left _ _ h_d_pos, Nat.div_eq_of_lt h_jd, Nat.zero_add]
        have h_mod_eq : (8 * (m_pos / 8) + m_pos % 8) % d = j.val := by
          have h_recover : 8 * (m_pos / 8) + m_pos % 8 = m_pos := Nat.div_add_mod m_pos 8
          rw [h_recover, hm_def, Nat.mul_comm i d, Nat.add_comm,
              Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt h_jd]
        simp only [h_idx_eq, h_mod_eq]
        rfl
      -- Combine into the ZMod sum.
      have h_sum_nat :
          ∑ j : Fin d, ((Spec.bytesToBits (MLKEM.ByteEncode d F h_d))[i * d + j.val]'(by
            have h_jd : j.val < d := j.isLt
            have : (i + 1) * d ≤ 256 * d := Nat.mul_le_mul_right d (by omega)
            nlinarith)).toNat * 2 ^ j.val = F[i].val := by
        rw [show (∑ j : Fin d, _ * 2 ^ j.val) =
              ∑ j : Fin d, (F[i].val.testBit j.val).toNat * 2 ^ j.val from
              Finset.sum_congr rfl (fun j _ => by rw [h_bits_eq j])]
        exact sum_testBit_pow_eq F[i].val d (h_val_bound i h_i)
      -- Lift sum to ZMod.
      show (∑ j : Fin d, ((Spec.bytesToBits (MLKEM.ByteEncode d F h_d))[i * d + j.val]'_).toNat
            * 2 ^ j.val : ZMod (MLKEM.m d)) = F[i]
      have h_lift : (∑ j : Fin d,
          (((Spec.bytesToBits (MLKEM.ByteEncode d F h_d))[i * d + j.val]'(by
            have h_jd : j.val < d := j.isLt
            have : (i + 1) * d ≤ 256 * d := Nat.mul_le_mul_right d (by omega)
            nlinarith)).toNat * 2 ^ j.val : ZMod (MLKEM.m d))) =
          ((∑ j : Fin d, ((Spec.bytesToBits (MLKEM.ByteEncode d F h_d))[i * d + j.val]'(by
            have h_jd : j.val < d := j.isLt
            have : (i + 1) * d ≤ 256 * d := Nat.mul_le_mul_right d (by omega)
            nlinarith)).toNat * 2 ^ j.val : Nat) : ZMod (MLKEM.m d)) := by
        push_cast; rfl
      rw [h_lift, h_sum_nat]
      exact ZMod.natCast_zmod_val F[i]
    · -- We wrote at position `a' ≠ i`; old invariant carries through.
      rw [if_neg h_eq, hPF']
      have h_eq' : s ≠ i := by rw [← ha'_val]; exact fun h => h_eq h
      by_cases h_si : s ≤ i
      · rw [if_pos h_si]
        rw [if_pos (by omega : s + 1 ≤ i)]
      · rw [if_neg h_si]
        rw [if_neg (by omega : ¬ s + 1 ≤ i)]

/-! ## PolyVector lift of `byteDecode_byteEncode`

Lift the polynomial-level round-trip
`ByteDecode (ByteEncode F) = F` to the `PolyVector` level:
`PolyVector.ByteDecode (PolyVector.ByteEncode v) = v`.

This is needed by callers (e.g. `encaps_keycheck_holds` in
`Encaps.lean`) that must show `Encaps.KeyCheck` accepts a byte-encoded
key.  The `wfKey` invariant in `Bridges/KeyView.lean` is layout-only and
does NOT carry the byte-form information; callers therefore supply the
byte-form witness explicitly via the `keyEncodedTPrefix = ByteEncode v_t`
precondition. -/

/-- Cast equation relating the natural size of `PolyVector.ByteEncode`
(`n * (32·d)`) to the size expected by `PolyVector.ByteDecode`
(`32·d·n`). -/
theorem polyVector_byteEncode_size_cast {n : MLKEM.K} (d : Nat) :
    (n : ℕ) * (32 * d) = 32 * d * (n : ℕ) := by ring

/-- The `i`-th `32·d`-byte slice of `PolyVector.ByteEncode d v` is the
polynomial-level `ByteEncode d (v[i])`. -/
theorem polyVector_slice_byteEncode_eq {n : MLKEM.K} (d : Nat)
    (h_d : 1 ≤ d ∧ d ≤ 12)
    (v : MLKEM.PolyVector (MLKEM.m d) n) (i : Nat) (hi : i < (n : ℕ))
    (hbnd : 32 * d * i + 32 * d ≤ 32 * d * (n : ℕ)) :
    slice ((MLKEM.PolyVector.ByteEncode d v).cast
            (polyVector_byteEncode_size_cast d))
          (32 * d * i) (32 * d) hbnd =
    MLKEM.ByteEncode d (v[i]'hi) := by
  apply Vector.ext
  intro j hj
  have hpos : 0 < 32 * d := by omega
  have hbnd_flat : 32 * d * i + j < (n : ℕ) * (32 * d) := by
    have : (n : ℕ) * (32 * d) = 32 * d * (n : ℕ) := by ring
    omega
  have hdiv : (32 * d * i + j) / (32 * d) = i := by
    have hcomm : 32 * d * i + j = j + 32 * d * i := by ring
    rw [hcomm, Nat.add_mul_div_left _ _ hpos, Nat.div_eq_of_lt hj]; ring
  have hmod : (32 * d * i + j) % (32 * d) = j := by
    have hcomm : 32 * d * i + j = j + 32 * d * i := by ring
    rw [hcomm, Nat.add_mul_mod_self_left]
    exact Nat.mod_eq_of_lt hj
  unfold slice
  unfold MLKEM.PolyVector.ByteEncode
  rw [Vector.getElem_ofFn]
  rw [Vector.getElem_cast]
  rw [Vector.getElem_flatten (m := 32 * d)
        (xss := v.map fun p => MLKEM.ByteEncode d p)
        (i := 32 * d * i + j) (hi := hbnd_flat)]
  simp only [hdiv, hmod, Vector.getElem_map]

/-- PolyVector-level round-trip:
`PolyVector.ByteDecode d (PolyVector.ByteEncode d v) = v`. -/
theorem polyVector_byteDecode_byteEncode {n : MLKEM.K} (d : Nat)
    (h_d : 1 ≤ d ∧ d ≤ 12) (v : MLKEM.PolyVector (MLKEM.m d) n) :
    MLKEM.PolyVector.ByteDecode d
      ((MLKEM.PolyVector.ByteEncode d v).cast
        (polyVector_byteEncode_size_cast d)) = v := by
  apply Vector.ext
  intro i hi
  unfold MLKEM.PolyVector.ByteDecode
  rw [Vector.getElem_ofFn]
  have hbnd : 32 * d * i + 32 * d ≤ 32 * d * (n : ℕ) := by
    have hh := MLKEM.Bounds.poly_vec_decode_idx_le d i hi; omega
  show MLKEM.ByteDecode (slice ((MLKEM.PolyVector.ByteEncode d v).cast _)
                         (32 * d * i) (32 * d) _) _ = v[i]'hi
  rw [polyVector_slice_byteEncode_eq d h_d v i hi hbnd]
  rw [byteDecode_byteEncode d h_d]

/-! ## Forward round-trip (Encode ∘ Decode = id under canonical assumption)

The reverse round-trip `Decode ∘ Encode = id` (above) is unconditional.
The **forward** round-trip `Encode ∘ Decode = id` requires the input
bytes to be "canonical" — each `d`-bit segment encodes a value `< m d`.

For `d < 12`, `m d = 2^d`, so every `d`-bit segment is automatically
canonical and `Encode ∘ Decode = id` is unconditional at those `d`.

For `d = 12`, `m 12 = q = 3329 < 2^12`, so a 12-bit segment can encode
a value in `[q, 2^12)` that gets reduced mod q by `ByteDecode`, losing
information.  The runtime check
`Spec.MLKEM.Encaps.KeyCheck p ek = (ByteEncode (ByteDecode ek) = ek)`
exists precisely to enforce canonicity at d=12 (FIPS 203 §7.2 Eq. 7.1).

We state both forms as **byte-level** equations (the only thing
downstream consumers need), with the canonicity precondition phrased
as "each `d`-bit segment, read as a Nat from the bytes, is `< m d`".
This holds vacuously for `d < 12` and is enforced by the runtime
`vector_decode_and_decompress` InvalidBlob check for `d = 12`. -/

/-- The Nat value of the `i`-th `d`-bit segment of a byte block, read
LSB-first from the bit expansion `Spec.bytesToBits B`. -/
def dBitSegment (d : Nat) {N : Nat} (B : Vector Byte N) (i : Nat) : Nat :=
  ∑ j ∈ Finset.range d,
    (if h : i * d + j < 8 * N then
       ((Spec.bytesToBits B)[i * d + j]'h).toNat
     else 0) * 2 ^ j

/-- The bit-pack sum of `d` Booleans is strictly less than `2^d`. -/
private theorem sum_pow_lt (b : Nat → Bool) (d : Nat) :
    ∑ j ∈ Finset.range d, (b j).toNat * 2 ^ j < 2 ^ d := by
  induction d with
  | zero => simp
  | succ n ih =>
    rw [Finset.sum_range_succ]
    have h_bn : (b n).toNat * 2 ^ n ≤ 2 ^ n := by
      cases b n <;> simp
    have h_pow : 2 ^ (n + 1) = 2 ^ n + 2 ^ n := by rw [pow_succ]; ring
    omega

/-- The `r`-th bit of the bit-pack sum of `d` Booleans is `b r`, for `r < d`.
The inverse of `sum_testBit_pow_eq`. -/
private theorem sum_pow_testBit (b : Nat → Bool) (d r : Nat) (h_r : r < d) :
    (∑ j ∈ Finset.range d, (b j).toNat * 2 ^ j).testBit r = b r := by
  induction d generalizing r with
  | zero => omega
  | succ n ih =>
    rw [Finset.sum_range_succ]
    set S := ∑ j ∈ Finset.range n, (b j).toNat * 2 ^ j with hS_def
    have h_S_lt : S < 2 ^ n := sum_pow_lt b n
    -- Rewrite `S + (b n).toNat * 2^n = 2^n * (b n).toNat + S`, then split via
    -- disjoint-OR (since `S < 2^n` and `(b n).toNat * 2^n` only has bit n).
    rw [show S + (b n).toNat * 2 ^ n = 2 ^ n * (b n).toNat + S from by ring]
    rw [Nat.two_pow_add_eq_or_of_lt h_S_lt]
    rw [Nat.testBit_or, Nat.testBit_two_pow_mul]
    by_cases h_rn : r < n
    · -- r < n: the `2^n * (b n).toNat` factor contributes nothing; recurse on S.
      have h_dec : ¬ r ≥ n := Nat.not_le_of_lt h_rn
      simp [h_dec, ih r h_rn]
    · -- r = n (since r < n + 1).
      have h_rn_eq : r = n := by omega
      rw [h_rn_eq]
      have h_S_bit : S.testBit n = false := Nat.testBit_lt_two_pow h_S_lt
      have h_dec : (n : Nat) ≥ n := Nat.le_refl _
      simp only [h_dec, decide_true, Bool.true_and,
                 h_S_bit, Bool.or_false, Nat.sub_self, Nat.testBit_zero]
      cases b n <;> rfl

/-- The `r`-th bit of `dBitSegment d B i` is the `(i*d + r)`-th bit of
`Spec.bytesToBits B`, for `r < d` and `i*d + r < 8*N`. -/
private theorem dBitSegment_testBit (d : Nat) {N : Nat} (B : 𝔹 N) (i r : Nat)
    (h_r : r < d) (h_bd : i * d + r < 8 * N) :
    (dBitSegment d B i).testBit r = (Spec.bytesToBits B)[i * d + r]'h_bd := by
  unfold dBitSegment
  -- View the dite-sum as ∑ j ∈ range d, (b j).toNat * 2^j with b total.
  set b : Nat → Bool := fun j =>
    if h : i * d + j < 8 * N then (Spec.bytesToBits B)[i * d + j]'h else false
    with hb_def
  have h_eq : ∑ j ∈ Finset.range d,
      (if h : i * d + j < 8 * N then ((Spec.bytesToBits B)[i * d + j]'h).toNat else 0) * 2 ^ j
    = ∑ j ∈ Finset.range d, (b j).toNat * 2 ^ j := by
    apply Finset.sum_congr rfl
    intro j _
    show _ = (b j).toNat * _
    rw [hb_def]
    by_cases h : i * d + j < 8 * N
    · simp [dif_pos h]
    · simp [dif_neg h]
  rw [h_eq, sum_pow_testBit b d r h_r]
  show b r = _
  rw [hb_def]
  exact dif_pos h_bd

/-- Per-coefficient identity for `MLKEM.ByteDecode B` as a ZMod cast.
This is the analogue of `byteDecode_getElem` in `EncodingStreamDecompress.lean`,
expressed in terms of `dBitSegment` (which works on `𝔹 (32*d)` directly,
without a `listToSpecBytes` wrapping). -/
private theorem byteDecode_getElem_eq_cast
    (d : Nat) (h_d : 1 ≤ d ∧ d ≤ 12) (B : 𝔹 (32 * d))
    (i : Nat) (h_i : i < 256) :
    (MLKEM.ByteDecode B h_d)[i]'h_i =
      ((dBitSegment d B i : ℕ) : ZMod (MLKEM.m d)) := by
  have h_d_pos : 0 < d := h_d.1
  have h_d_le : d ≤ 12 := h_d.2
  have h_m_pos : 0 < MLKEM.m d := by
    simp only [MLKEM.m]; split <;> [positivity; decide]
  haveI : NeZero (MLKEM.m d) := ⟨Nat.pos_iff_ne_zero.mp h_m_pos⟩
  unfold MLKEM.ByteDecode
  simp only [Aeneas.SRRange.forIn'_eq_forIn'_range', SRRange.size,
             Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one]
  refine forIn'_getElem_indexed (List.range' 0 256) _ _ i h_i _
    (P := fun s (F' : MLKEM.Polynomial (MLKEM.m d)) =>
      F'[i]'h_i = if s ≤ i then (0 : ZMod (MLKEM.m d))
                  else ((dBitSegment d B i : ℕ) : ZMod (MLKEM.m d)))
    ?hInit ?hFinal ?hStep
  case hInit =>
    show (MLKEM.Polynomial.zero (MLKEM.m d))[i]'h_i = _
    simp [MLKEM.Polynomial.zero, Vector.getElem_replicate]
  case hFinal =>
    intro F' hP
    rw [List.length_range'] at hP
    rwa [if_neg (by omega : ¬ 256 ≤ i)] at hP
  case hStep =>
    intro s hs F' hPF' a' ha' ha'_eq
    have h_len : (List.range' 0 256).length = 256 := by simp
    have hs_lt : s < 256 := h_len ▸ hs
    have ha'_val : a' = s := by rw [ha'_eq]; simp [List.getElem_range']
    have ha'_lt : a' < 256 := ha'_val ▸ hs_lt
    refine ⟨_, rfl, ?_⟩
    try simp only []
    rw [Vector.getElem_set ha'_lt h_i]
    by_cases h_eq : a' = i
    · rw [if_pos h_eq, if_neg (by omega : ¬ s + 1 ≤ i)]
      simp only [h_eq]
      -- The body sets F[i] := (∑ j : Fin d, b[i*d + j.val].toNat * 2^j.val : ZMod (m d)).
      -- We want this to equal ((dBitSegment d B i : ℕ) : ZMod (m d)).
      unfold dBitSegment
      -- Each in-range index satisfies the dite condition; reduce.
      have h_in : ∀ j : Fin d, i * d + j.val < 8 * (32 * d) := by
        intro j
        have h_jd : j.val < d := j.isLt
        have h_upper : (i + 1) * d ≤ 256 * d := Nat.mul_le_mul_right d (by omega)
        calc i * d + j.val < (i + 1) * d := by nlinarith
          _ ≤ 256 * d := h_upper
          _ = 8 * (32 * d) := by ring
      have h_in_range : ∀ j, j ∈ Finset.range d → i * d + j < 8 * (32 * d) := by
        intro j hj
        have h_jd : j < d := Finset.mem_range.mp hj
        exact h_in ⟨j, h_jd⟩
      -- Replace the dite-laden range sum with a clean Fin-sum.
      rw [show (∑ j ∈ Finset.range d,
                  (if h : i * d + j < 8 * (32 * d) then
                     ((Spec.bytesToBits B)[i * d + j]'h).toNat
                   else 0) * 2 ^ j) =
              ∑ j : Fin d, ((Spec.bytesToBits B)[i * d + j.val]'(h_in j)).toNat * 2 ^ j.val
              from ?h_sum_eq]
      case h_sum_eq =>
        rw [← Fin.sum_univ_eq_sum_range
              (fun j => (if h : i * d + j < 8 * (32 * d) then
                           ((Spec.bytesToBits B)[i * d + j]'h).toNat
                         else 0) * 2 ^ j)]
        apply Finset.sum_congr rfl
        intro j _
        rw [dif_pos (h_in j)]
      -- Now cast the Fin-sum into ZMod.
      push_cast
      apply Finset.sum_congr rfl
      intro j _
      rfl
    · rw [if_neg h_eq, hPF']
      have h_eq' : s ≠ i := by rw [← ha'_val]; exact fun h => h_eq h
      by_cases h_si : s ≤ i
      · rw [if_pos h_si, if_pos (by omega : s + 1 ≤ i)]
      · rw [if_neg h_si, if_neg (by omega : ¬ s + 1 ≤ i)]

/-- Under canonicity at index `i`, `(ByteDecode B)[i].val = dBitSegment d B i`.
The mod-`m d` reduction is a no-op because the d-bit segment is already
in range `[0, m d)`. -/
private theorem byteDecode_get_val_eq_dBitSegment
    (d : Nat) (h_d : 1 ≤ d ∧ d ≤ 12) (B : 𝔹 (32 * d))
    (i : Nat) (h_i : i < 256)
    (h_canon_i : dBitSegment d B i < MLKEM.m d) :
    ((MLKEM.ByteDecode B h_d)[i]'h_i).val = dBitSegment d B i := by
  have h_m_pos : 0 < MLKEM.m d := by
    simp only [MLKEM.m]; split <;> [positivity; decide]
  haveI : NeZero (MLKEM.m d) := ⟨Nat.pos_iff_ne_zero.mp h_m_pos⟩
  rw [byteDecode_getElem_eq_cast d h_d B i h_i]
  exact ZMod.val_cast_of_lt h_canon_i

/-- Forward round-trip at the polynomial level, conditional on every
`d`-bit segment of the input bytes encoding a value `< m d`. -/
theorem byteEncode_byteDecode_canonical_eq (d : Nat)
    (h_d : 1 ≤ d ∧ d ≤ 12) (B : 𝔹 (32 * d))
    (h_canon : ∀ (i : Nat) (_ : i < 256), dBitSegment d B i < MLKEM.m d) :
    MLKEM.ByteEncode d (MLKEM.ByteDecode B h_d) h_d = B := by
  have h_d_pos : 0 < d := h_d.1
  have h_d_le : d ≤ 12 := h_d.2
  apply Vector.ext
  intro k h_k
  -- Two bytes are equal iff their low 8 bits agree.
  apply Byte.ext_testBit
  intro j h_j
  -- Set up arithmetic on n := 8*k + j.
  set n := 8 * k + j with hn_def
  have h_div_lt : n / d < 256 := byteEncode_idx_bound h_d.1 h_d.2 h_k h_j
  have h_mod_lt : n % d < d := Nat.mod_lt _ h_d_pos
  have h_div_mod : n / d * d + n % d = n := by
    have h := Nat.div_add_mod n d; rw [Nat.mul_comm d _] at h; omega
  have h_n_lt : n < 8 * (32 * d) := by
    calc n = 8 * k + j := rfl
      _ < 8 * k + 8 := by omega
      _ = 8 * (k + 1) := by ring
      _ ≤ 8 * (32 * d) := Nat.mul_le_mul_left 8 (by omega)
  have h_seg_idx_lt : ∀ r, r < d → n / d * d + r < 8 * (32 * d) := by
    intro r h_r
    calc n / d * d + r < n / d * d + d := by omega
      _ = (n / d + 1) * d := by ring
      _ ≤ 256 * d := Nat.mul_le_mul_right d (by omega)
      _ = 8 * (32 * d) := by ring
  -- Use `byteEncode_byte_invariant` via `change`/`show` to bridge .get / [].
  have h_inv := byteEncode_byte_invariant d h_d (MLKEM.ByteDecode B h_d) k h_k j h_j
  -- h_inv : (ByteEncode … .get ⟨k, h_k⟩).toNat.testBit j =
  --         ((ByteDecode B h_d).get ⟨(8*k+j)/d, _⟩).val.testBit ((8*k+j)%d)
  show ((MLKEM.ByteEncode d (MLKEM.ByteDecode B h_d) h_d)[k]'h_k).toNat.testBit j =
         (B[k]'h_k).toNat.testBit j
  rw [show ((MLKEM.ByteEncode d (MLKEM.ByteDecode B h_d) h_d)[k]'h_k).toNat.testBit j =
         ((MLKEM.ByteDecode B h_d)[(8 * k + j) / d]'(byteEncode_idx_bound h_d.1 h_d.2 h_k h_j)).val.testBit
            ((8 * k + j) % d)
       from h_inv]
  -- ByteDecode B [n/d].val = dBitSegment d B (n/d) (under canonicity).
  rw [byteDecode_get_val_eq_dBitSegment d h_d B (n / d) h_div_lt
        (h_canon (n / d) h_div_lt)]
  -- Apply the dBitSegment_testBit helper to extract bit (n%d).
  have h_pos_mod : n / d * d + n % d < 8 * (32 * d) := h_seg_idx_lt (n % d) h_mod_lt
  rw [dBitSegment_testBit d B (n / d) (n % d) h_mod_lt h_pos_mod]
  -- Now: (bytesToBits B)[n/d * d + n%d] = B[k].toNat.testBit j.
  rw [getElem_congr_idx (c := Spec.bytesToBits B) h_div_mod]
  unfold Spec.bytesToBits
  rw [Vector.getElem_ofFn]
  have h_n8_div : n / 8 = k := by simp only [hn_def]; omega
  have h_n8_mod : n % 8 = j := by simp only [hn_def]; omega
  simp only [h_n8_div, h_n8_mod]

/-- Forward round-trip at the PolyVector level, conditional on each
`32·d`-byte window of the input being canonical at the bit-segment
level.  Derived from `byteEncode_byteDecode_canonical_eq` per row. -/
theorem polyVector_byteEncode_byteDecode_canonical_eq {n : MLKEM.K} (d : Nat)
    (h_d : 1 ≤ d ∧ d ≤ 12) (B : 𝔹 (32 * d * (n : ℕ)))
    (h_canon : ∀ (j : Nat) (_h_j : j < (n : ℕ)) (i : Nat) (_ : i < 256),
                 dBitSegment d (slice B (32 * d * j) (32 * d)
                                  (by have hh := MLKEM.Bounds.poly_vec_decode_idx_le d j _h_j
                                      omega)) i < MLKEM.m d) :
    (MLKEM.PolyVector.ByteEncode d
       (MLKEM.PolyVector.ByteDecode (k := n) d B h_d) h_d).cast
       (polyVector_byteEncode_size_cast d) = B := by
  set v := MLKEM.PolyVector.ByteDecode (k := n) d B h_d with hv_def
  apply Vector.ext
  intro j hj
  have h_d_pos : 0 < d := h_d.1
  have h32d_pos : 0 < 32 * d := by omega
  set q := j / (32 * d) with hq_def
  set r := j % (32 * d) with hr_def
  have hr_lt : r < 32 * d := Nat.mod_lt _ h32d_pos
  have hq_lt : q < (n : ℕ) := by
    rw [hq_def]
    apply Nat.div_lt_of_lt_mul
    rw [Nat.mul_comm]; rwa [show (n : ℕ) * (32 * d) = 32 * d * (n : ℕ) from by ring]
  have hqr_eq : 32 * d * q + r = j := by
    have := Nat.div_add_mod j (32 * d); rw [hq_def, hr_def]; omega
  have hbnd : 32 * d * q + 32 * d ≤ 32 * d * (n : ℕ) := by
    have : (q + 1) * (32 * d) ≤ (n : ℕ) * (32 * d) :=
      Nat.mul_le_mul_right (32 * d) hq_lt
    have h_rw : (n : ℕ) * (32 * d) = 32 * d * (n : ℕ) := by ring
    have h_lhs : (q + 1) * (32 * d) = 32 * d * q + 32 * d := by ring
    omega
  have h_qr_bnd : 32 * d * q + r < 32 * d * (n : ℕ) := by omega
  -- Rewrite index j as 32*d*q + r.
  rw [getElem_congr_idx (c := ((MLKEM.PolyVector.ByteEncode d v h_d).cast _)) hqr_eq.symm]
  rw [getElem_congr_idx (c := B) hqr_eq.symm]
  -- Use the slice characterization of the cast-flatten, already proved.
  have h_slice_eq :
      slice ((MLKEM.PolyVector.ByteEncode d v h_d).cast
              (polyVector_byteEncode_size_cast d)) (32 * d * q) (32 * d) hbnd
      = MLKEM.ByteEncode d (v[q]'hq_lt) h_d :=
    polyVector_slice_byteEncode_eq d h_d v q hq_lt hbnd
  -- LHS = slice [r] = ByteEncode d v[q] [r]
  have h_lhs : ((MLKEM.PolyVector.ByteEncode d v h_d).cast
                  (polyVector_byteEncode_size_cast d))[32 * d * q + r]'h_qr_bnd
             = (MLKEM.ByteEncode d (v[q]'hq_lt) h_d)[r]'hr_lt := by
    rw [← h_slice_eq]
    unfold slice
    rw [Vector.getElem_ofFn]
  rw [h_lhs]
  -- Now: v[q] = ByteDecode d (slice B (32*d*q) (32*d) _) h_d
  have h_v_q : v[q]'hq_lt = MLKEM.ByteDecode (slice B (32 * d * q) (32 * d)
                            (by have hh := MLKEM.Bounds.poly_vec_decode_idx_le d q hq_lt
                                omega)) h_d := by
    rw [hv_def]
    unfold MLKEM.PolyVector.ByteDecode
    rw [Vector.getElem_ofFn]
  rw [h_v_q]
  -- Apply byteEncode_byteDecode_canonical_eq at row q.
  rw [byteEncode_byteDecode_canonical_eq d h_d _
        (fun i h_i => h_canon q hq_lt i h_i)]
  -- Final: (slice B (32*d*q) (32*d) _)[r] = B[32*d*q + r]
  unfold slice
  rw [Vector.getElem_ofFn]

/-! ## Streaming bit-pump invariants

These follow the "ghost predicate over partial state" pattern from
`aeneas-postconditions` (§Streaming and ghost state). They allow the
loop-body and loop-match `@[step]` posts to carry per-iteration FC
that composes upward into the leaf wrapper's full FC.

These four definitions (`compressBits`, `compressEncodeBitsInv`,
`srcBits`, `decodeDecompressBitsInv`) are the **Rust-side** half of
the architecture

```
FIPS spec ⟷₁ Stream ⟷₂ Aeneas
```

implemented in `Bridges/EncodingStream.lean`.  Bridge 2 there
relates them (via `CompressEncodeState.matchesRuntime` + `recBody`)
to the Stream-level invariants used by the `@[step]` posts on the
loop / wrapper functions; Bridge 1 is the pure math identity
`streamCompressEncodePoly d F = (compressEncodePoly d F).toList`
(resp. for decode).

These four definitions are referenced from
`Bridges/EncodingStream.lean` and from the leaf wrappers in
`Encoding/Compress.lean` / `Encoding/Decompress.lean`.  Do not
delete. -/

/-- Concrete bit-stream produced by compress-and-encode applied to
`coeffs` (each `c < q`, LSB-first within each `d`-bit coefficient):
each coefficient emits `d` bits of `fastCompress d c`. The
`fastCompress_eq_spec_compress` bridge lifts this to `Compress`. -/
def compressBits (d : Nat) (coeffs : List Nat) : List Bool :=
  coeffs.flatMap fun c =>
    (List.range d).map fun i => (fastCompress d c).testBit i

/-- Streaming-state invariant of `poly_element_compress_and_encode_loop`.

After processing `coeffs_done` coefficients (`coeffs_done.length ≤ 256`),
the running state holds the bit-prefix of `compressBits d coeffs_done`:

* `pb_dst.val[0..cb_dst_written]` carries the first `8·cb_dst_written`
  bits, low-bit first within each byte;
* `accumulator`'s low `n_bits_in_accumulator` bits carry the remaining
  `coeffs_done.length * d - 8 * cb_dst_written` bits. -/
def compressEncodeBitsInv (d : Nat)
    (coeffs_done : List Nat) (pb_dst : Slice U8)
    (cb_dst_written : Nat) (accumulator : Nat)
    (n_bits_in_accumulator : Nat) : Prop :=
  coeffs_done.length * d = 8 * cb_dst_written + n_bits_in_accumulator ∧
  cb_dst_written ≤ pb_dst.length ∧
  n_bits_in_accumulator ≤ 31 ∧
  /- The bit-pump only ever writes 4 bytes at a time (`store_u32_le`),
     so `cb_dst_written` is always a multiple of 4.  Required by the
     forward bridge to derive Stream's `s.bi = 4 * ((d * length) / 32)`. -/
  cb_dst_written % 4 = 0 ∧
  (∀ (i : Nat) (_ : i < cb_dst_written) (j : Nat) (_ : j < 8),
      ((pb_dst.val[i]?.getD 0#u8).val).testBit j
        = (compressBits d coeffs_done).getD (8 * i + j) false) ∧
  (∀ (j : Nat) (_ : j < n_bits_in_accumulator),
      accumulator.testBit j
        = (compressBits d coeffs_done).getD (8 * cb_dst_written + j) false) ∧
  /- High bits of the accumulator above `n_bits_in_accumulator` are 0.
     Loop invariant of the bit-pump — every flush at exactly 32 bits resets
     to a leftover whose width is `d - nBits ≤ 11`. Without this clause,
     the loop's terminal flush of the partial accumulator carries garbage. -/
  (∀ (j : Nat), n_bits_in_accumulator ≤ j → ¬ accumulator.testBit j)

/-! ## Decode-and-decompress streaming invariant

The inverse direction.  `poly_element_decode_and_decompress_loop0`
sequentially reads `d` bits per coefficient from `pb_src`, applies
`fastDecompress d`, and writes the result through an `IterMut` cursor.

After `i_done` coefficients have been emitted, the runtime state
holds:
* `cb_src_read` bytes of `pb_src` have been read into the bit-pump
  via 4-byte `load_u32_le` refills;
* `accumulator`'s low `n_bits_in_accumulator` bits are the next
  unread bits (LSB-first within each loaded byte word);
* the IterMut writes the first `i_done` destination coefficients,
  each equal to `fastDecompress d (k-th d-bit chunk of pb_src)`.

The exact bit-accounting is identical in shape to
`compressEncodeBitsInv` but the bit-stream direction is reversed:
here `compressBits` is replaced by the literal bit-decomposition of
`pb_src`. -/

/-- Sequence of bits read out of `pb_src`, LSB-first within each byte.
The runtime's bit-pump consumes this list in order. -/
def srcBits (pb_src : Slice U8) : List Bool :=
  pb_src.val.flatMap fun b =>
    (List.range 8).map (fun j => b.val.testBit j)

/-- Streaming-state invariant of `poly_element_decode_and_decompress_loop0`.

After `i_done` coefficients have been written, with `coeffs_emitted`
listing their `Nat` values:
* `i_done = coeffs_emitted.length ≤ 256`;
* `8 * cb_src_read = i_done * d + n_bits_in_accumulator`;
* the next `n_bits_in_accumulator` bits in `accumulator`'s LSBs are
  the source bits at positions `[i_done*d, i_done*d + n_bits_in_accumulator)`;
* high bits of `accumulator` above `n_bits_in_accumulator` are 0
  (loop invariant — every refill resets to a width-bounded leftover);
* each emitted coefficient `coeffs_emitted[k] = fastDecompress d c_k`
  where `c_k` is the LSB-first `Nat` whose bit `j ∈ [0, d)` is
  `srcBits pb_src` at position `k*d + j`. Uses `Nat.ofBitsList`
  rather than a hand-rolled `foldr` for both simplicity and the
  correct LSB-first ordering (matching `MLKEM.ByteDecode`). -/
def decodeDecompressBitsInv (d : Nat)
    (pb_src : Slice U8) (coeffs_emitted : List Nat)
    (cb_src_read : Nat) (accumulator : Nat)
    (n_bits_in_accumulator : Nat) : Prop :=
  coeffs_emitted.length * d + n_bits_in_accumulator = 8 * cb_src_read ∧
  cb_src_read ≤ pb_src.length ∧
  n_bits_in_accumulator ≤ 31 ∧
  /- Refills always read 4 bytes (`load_u32_le`), so `cb_src_read`
     is always a multiple of 4. -/
  cb_src_read % 4 = 0 ∧
  (∀ (j : Nat) (_ : j < n_bits_in_accumulator),
      accumulator.testBit j
        = (srcBits pb_src).getD
            (coeffs_emitted.length * d + j) false) ∧
  /- High bits of the accumulator above `n_bits_in_accumulator` are 0. -/
  (∀ (j : Nat), n_bits_in_accumulator ≤ j → ¬ accumulator.testBit j) ∧
  (∀ (k : Nat) (_ : k < coeffs_emitted.length),
      coeffs_emitted.getD k 0
        = fastDecompress d
            (Nat.ofBitsList
              ((List.range d).map (fun j => (srcBits pb_src).getD (k * d + j) false))))

/-! ## SamplePolyCBD bridge

`MLKEM.SamplePolyCBD η (B : 𝔹 (64·η)) : Polynomial` computes 256
coefficients via the centered-binomial-distribution formula.

The Rust `poly_element_sample_cbd_from_bytes` uses a popcount-based
trick on a packed `u32` whose low `2η` bits encode one coefficient:

    coeff_i = popcount(low η bits) - popcount(high η bits)  (mod q)

These two formulas agree, but the Rust loop processes 4 (η=3) or 8
(η=2) coefficients per outer chunk, walking pb_src in 3- or 4-byte
strides. The helpers below let us state the FC at three levels (body /
loop / wrapper). -/

/-- Coerce a `U32` whose runtime value is in `{2, 3}` to the spec subtype
`MLKEM.Η`. Used at the FC of CBD samplers so that
`MLKEM.SamplePolyCBD (η := …)` typechecks against the runtime
parameter. -/
def cbdEta (eta : U32) (h : eta.val = 2 ∨ eta.val = 3) : MLKEM.Η :=
  ⟨eta.val, by
    rcases h with h | h <;>
    simp [h, Set.mem_insert_iff, Set.mem_singleton_iff]⟩

@[simp]
theorem cbdEta_val (eta : U32) (h : eta.val = 2 ∨ eta.val = 3) :
    (cbdEta eta h).val = eta.val := rfl

/-- The i-th coefficient of `MLKEM.SamplePolyCBD` applied to bytes.

Used in loop / body postconditions to express "coefficient `i` has been
correctly computed" without needing to unfold the spec function. -/
noncomputable def samplePolyCbdCoeff
    {η : MLKEM.Η} (bytes : 𝔹 (64 * η.val)) (i : Nat) (h : i < 256) :
    MLKEM.Zq :=
  (MLKEM.SamplePolyCBD bytes).get ⟨i, h⟩

/-- **Bridge** — a polynomial that agrees with `samplePolyCbdCoeff bytes`
pointwise on every index equals `MLKEM.SamplePolyCBD bytes`.

Used at the exit of the CBD outer loops (`poly_element_sample_cbd_from_bytes_loop{0,1}.spec`)
to discharge `toPoly r = MLKEM.SamplePolyCBD bytes` from the per-coefficient
invariant `cbdOuterEta{2,3}Inv`.

Informal proof: by `Vector.ext` on `MLKEM.Polynomial = Vector Zq 256`;
the per-index hypothesis is precisely the def of `samplePolyCbdCoeff`. -/
theorem samplePolyCbdCoeff_eq_SamplePolyCBD {η : MLKEM.Η}
    (bytes : 𝔹 (64 * η.val)) (f : MLKEM.Polynomial)
    (h : ∀ (i : Nat) (h_i : i < 256),
        f.get ⟨i, h_i⟩ = samplePolyCbdCoeff bytes i h_i) :
    f = MLKEM.SamplePolyCBD bytes := by
  apply Vector.ext
  intro i hi
  have := h i hi
  unfold samplePolyCbdCoeff at this
  exact this

/-- Decode a single CBD coefficient from `2η` bits via the Rust popcount
trick: low `η` bits popcount minus high `η` bits popcount, taken
mod `q`.

`bits` is treated as a `Nat` whose binary expansion encodes the
`2η`-bit chunk (LSB first); only bits `[0, 2η)` are read. -/
noncomputable def cbdDecodeBits (η : Nat) (bits : Nat) : MLKEM.Zq :=
  let low_pop  : Int := (List.range η).map (fun j => (bits.testBit j).toNat) |>.sum
  let high_pop : Int := (List.range η).map (fun j => (bits.testBit (η + j)).toNat) |>.sum
  ((low_pop - high_pop : Int) : MLKEM.Zq)

/-! ### Intermediate spec for SamplePolyCBD

We define `samplePolyCbdRec`, a pure functional `foldl` form of
`MLKEM.SamplePolyCBD`, then prove a per-coefficient lemma
`samplePolyCbdCoeff_eq_sums` that characterises each coefficient as the
explicit signed sum of `BytesToBits` values. This is the workhorse
for `cbdDecodeBits_eq_specCoeff` below. -/

namespace SamplePolyCBD

/-- Pure functional body: write coefficient `i` from the popcount
formula on `BytesToBits B`. Uses `set!` to avoid carrying the
`i < 256` bound proof through the fold. -/
private noncomputable def body {η : MLKEM.Η} (B : 𝔹 (64 * η.val))
    (f : MLKEM.Polynomial) (i : Nat) : MLKEM.Polynomial :=
  let x : MLKEM.Zq :=
    ∑ (j : Fin η.val), ((MLKEM.BytesToBits B)[2 * i * η.val + j]!).toNat
  let y : MLKEM.Zq :=
    ∑ (j : Fin η.val), ((MLKEM.BytesToBits B)[2 * i * η.val + η.val + j]!).toNat
  f.set! i (x - y)

/-- Functional recursion: `samplePolyCbdRec B f s` applies `body B` to
positions `[s, 256)` of `f`. The spec corresponds to `rec B Polynomial.zero 0`. -/
private noncomputable def samplePolyCbdRec {η : MLKEM.Η} (B : 𝔹 (64 * η.val))
    (f : MLKEM.Polynomial) (start : Nat) : MLKEM.Polynomial :=
  List.foldl (fun g x => body B g x.val) f
    (List.range' start (256 - start)).attach

private theorem samplePolyCBD_eq_rec {η : MLKEM.Η} (B : 𝔹 (64 * η.val)) :
    MLKEM.SamplePolyCBD B = samplePolyCbdRec B MLKEM.Polynomial.zero 0 := by
  unfold MLKEM.SamplePolyCBD samplePolyCbdRec body
  simp only [Aeneas.SRRange.forIn'_eq_forIn'_range', Aeneas.SRRange.size,
    Nat.sub_zero, Nat.div_one, Nat.add_sub_cancel,
    pure_bind, List.forIn'_pure_yield_eq_foldl, Id.run_pure,
    Vector.Inhabited_getElem_eq_getElem!, Vector.set_eq_set!, Nat.cast_sum]

/-- For positions `j` strictly less than the recursion start, the
functional fold leaves coefficient `j` untouched. -/
private theorem samplePolyCbdRec_preserves_below {η : MLKEM.Η}
    (B : 𝔹 (64 * η.val)) (f : MLKEM.Polynomial) (start : Nat)
    (h_start : start ≤ 256) :
    ∀ j, j < start → (samplePolyCbdRec B f start)[j]! = f[j]! := by
  intro j hj
  by_cases h_start255 : start = 256
  · -- empty fold
    subst h_start255
    simp [samplePolyCbdRec]
  · -- non-empty: rec.unfold + IH
    have h_lt : start < 256 := lt_of_le_of_ne h_start h_start255
    have h_diff : 256 - start = (256 - (start + 1)) + 1 := by omega
    have h_unfold :
        samplePolyCbdRec B f start =
          samplePolyCbdRec B (body B f start) (start + 1) := by
      unfold samplePolyCbdRec
      conv_lhs => rw [h_diff, List.range'_succ]
      simp only [List.attach_cons, List.foldl_cons, List.foldl_map]
    rw [h_unfold]
    rw [samplePolyCbdRec_preserves_below B (body B f start) (start + 1)
        (by omega) j (by omega)]
    -- body B f start at index j (j < start): unchanged
    simp only [body]
    rw [Vector.getElem!_set!_ne (show start ≠ j by omega)]
termination_by 256 - start

/-- The key per-coefficient lemma. `samplePolyCbdRec B f start` at
index `j ∈ [start, 256)` equals the popcount-difference formula. The
extra hypothesis `hf` carries the formula already-established for
positions `< start`. -/
private theorem samplePolyCbdRec_get {η : MLKEM.Η} (B : 𝔹 (64 * η.val))
    (f : MLKEM.Polynomial) (start : Nat) (h_start : start ≤ 256)
    (hf : ∀ k, k < start →
      f[k]! =
        (∑ (j : Fin η.val),
          (((MLKEM.BytesToBits B)[2 * k * η.val + j]!).toNat : MLKEM.Zq)) -
        (∑ (j : Fin η.val),
          (((MLKEM.BytesToBits B)[2 * k * η.val + η.val + j]!).toNat : MLKEM.Zq))) :
    ∀ i, i < 256 →
      (samplePolyCbdRec B f start)[i]! =
        (∑ (j : Fin η.val),
          (((MLKEM.BytesToBits B)[2 * i * η.val + j]!).toNat : MLKEM.Zq)) -
        (∑ (j : Fin η.val),
          (((MLKEM.BytesToBits B)[2 * i * η.val + η.val + j]!).toNat : MLKEM.Zq)) := by
  intro i hi
  by_cases h_start255 : start = 256
  · -- start = 256: rec is the identity; use hf
    subst h_start255
    have : (samplePolyCbdRec B f 256)[i]! = f[i]! := by simp [samplePolyCbdRec]
    rw [this]; exact hf i hi
  · -- start < 256: unfold one step + case-split on i = start vs i > start
    have h_lt : start < 256 := lt_of_le_of_ne h_start h_start255
    have h_diff : 256 - start = (256 - (start + 1)) + 1 := by omega
    have h_unfold :
        samplePolyCbdRec B f start =
          samplePolyCbdRec B (body B f start) (start + 1) := by
      unfold samplePolyCbdRec
      conv_lhs => rw [h_diff, List.range'_succ]
      simp only [List.attach_cons, List.foldl_cons, List.foldl_map]
    rw [h_unfold]
    -- Apply IH at start+1 with extended invariant
    have hf' : ∀ k, k < start + 1 →
        (body B f start)[k]! =
          (∑ (j : Fin η.val),
            (((MLKEM.BytesToBits B)[2 * k * η.val + j]!).toNat : MLKEM.Zq)) -
          (∑ (j : Fin η.val),
            (((MLKEM.BytesToBits B)[2 * k * η.val + η.val + j]!).toNat : MLKEM.Zq)) := by
      intro k hk
      by_cases h_keq : k = start
      · -- the just-set position: equals the body's value
        subst h_keq
        simp only [body]
        rw [Vector.getElem!_set! (show k < 256 ∧ k = k from ⟨h_lt, rfl⟩)]
      · -- k < start: was preserved
        have hk' : k < start := by omega
        simp only [body]
        rw [Vector.getElem!_set!_ne (show start ≠ k by omega)]
        exact hf k hk'
    exact samplePolyCbdRec_get B (body B f start) (start + 1)
            (by omega) hf' i hi
termination_by 256 - start

/-- Public per-coefficient characterisation of `MLKEM.SamplePolyCBD`. -/
theorem samplePolyCbdCoeff_eq_sums {η : MLKEM.Η}
    (B : 𝔹 (64 * η.val)) (i : Nat) (h_i : i < 256) :
    (MLKEM.SamplePolyCBD B).get ⟨i, h_i⟩ =
      (∑ (j : Fin η.val),
        (((MLKEM.BytesToBits B)[2 * i * η.val + j]!).toNat : MLKEM.Zq)) -
      (∑ (j : Fin η.val),
        (((MLKEM.BytesToBits B)[2 * i * η.val + η.val + j]!).toNat : MLKEM.Zq)) := by
  change (MLKEM.SamplePolyCBD B)[i] = _
  rw [Vector.Inhabited_getElem_eq_getElem!]
  rw [samplePolyCBD_eq_rec]
  exact samplePolyCbdRec_get B MLKEM.Polynomial.zero 0 (by omega) (by intros; omega) i h_i

end SamplePolyCBD

/-- **CBD bridge** — the popcount decode equals the spec's per-coefficient
formula via the byte-to-bit unrolling.

For `η ∈ {2, 3}`, `i < 256`, and bytes of length `64η`, the popcount of
the appropriate `2η`-bit window of `BytesToBits bytes` equals
`samplePolyCbdCoeff bytes i`. The Rust packs those `2η` bits into the
low bits of a `u32` it shifts by `2η` between iterations. -/
theorem cbdDecodeBits_eq_specCoeff (η : MLKEM.Η)
    (bytes : 𝔹 (64 * η.val)) (i : Nat) (h_i : i < 256)
    (bits : Nat)
    (h_bits : ∀ (j : Nat) (_ : j < 2 * η.val),
        bits.testBit j
          = (MLKEM.BytesToBits bytes).get
              ⟨2 * i * η.val + j, by
                have := η.property
                have := Set.mem_insert_iff.mp (by exact_mod_cast this)
                rcases this with h | h <;> simp [*] <;> grind⟩) :
    cbdDecodeBits η.val bits = samplePolyCbdCoeff bytes i h_i := by
  unfold cbdDecodeBits samplePolyCbdCoeff
  rw [SamplePolyCBD.samplePolyCbdCoeff_eq_sums]
  push_cast
  simp only [List.map_map]
  have list_sum_eq_fin_sum : ∀ (f : ℕ → MLKEM.Zq) (n : ℕ),
      (List.map f (List.range n)).sum = ∑ (j : Fin n), f j.val := by
    intros f n
    induction n with
    | zero => simp
    | succ k ih => rw [List.range_succ, List.map_append, List.sum_append, ih,
                       Fin.sum_univ_castSucc]
                   simp
  rw [list_sum_eq_fin_sum, list_sum_eq_fin_sum]
  have hbnd : ∀ j : ℕ, j < 2 * η.val → 2 * i * η.val + j < 8 * (64 * η.val) := by
    intros j hj
    have := η.property
    rcases Set.mem_insert_iff.mp (by exact_mod_cast this) with h | h <;> simp [*] <;> grind
  fcongr 1
  · apply Finset.sum_congr rfl; intro k _
    have hk : k.val < 2 * η.val := by have := k.isLt; omega
    have hk2 := hbnd k.val hk
    have := h_bits k.val hk
    simp only [Function.comp_apply]
    change ((bits.testBit k.val).toNat : MLKEM.Zq) = _
    rw [this, ← Vector.Inhabited_getElem_eq_getElem! _ _ hk2]
    rfl
  · apply Finset.sum_congr rfl; intro k _
    have hk : η.val + k.val < 2 * η.val := by have := k.isLt; omega
    have hk2' : 2 * i * η.val + η.val + k.val < 8 * (64 * η.val) := by
      have := hbnd (η.val + k.val) hk; omega
    have := h_bits (η.val + k.val) hk
    simp only [Function.comp_apply]
    change ((bits.testBit (η.val + k.val)).toNat : MLKEM.Zq) = _
    rw [this]
    have e_idx : 2 * i * η.val + (η.val + k.val) = 2 * i * η.val + η.val + k.val := by ring
    rw [← Vector.Inhabited_getElem_eq_getElem! _ _ hk2']
    simp only [e_idx]
    rfl

/-! ## SampleNTT bridge

`MLKEM.SampleNTT (B : 𝔹 34) : Polynomial` runs rejection sampling
over the XOF byte stream, accepting candidates that are `< q`. Each
"round" consumes 3 XOF bytes and proposes up to 2 candidates.

The Rust `poly_element_sample_ntt_from_shake128_loop` mirrors this round
structure but buffers 24 bytes (= 8 rounds) at a time via
`MlKemHashState.extract`. The streaming-invariant pattern below tracks
the number of accepted coefficients (`j`) and the number of XOF byte
triples consumed (`n_rounds`), so the body/loop `@[step]` specs can
express their per-iteration FC against a partial spec output. -/

/-! ## loadLEWordBytes — little-endian 4-byte assembly

Assembles 4 consecutive bytes from a `Slice U8` into a `Nat` in
little-endian order.  Used by the decode-side REFILL path where the
Rust `load_u32_le` intrinsic reads 4 bytes from the bit-stream source. -/

@[reducible] def loadLEWordBytes (pb_src : Slice U8) (cb : ℕ) : ℕ :=
  (pb_src.val.getD cb 0#u8).val
  + 2^8 * (pb_src.val.getD (cb + 1) 0#u8).val
  + 2^16 * (pb_src.val.getD (cb + 2) 0#u8).val
  + 2^24 * (pb_src.val.getD (cb + 3) 0#u8).val

theorem loadLEWordBytes_eq_proofForm
    (pb_src : Slice U8) (cb : ℕ) (h : cb + 4 ≤ pb_src.length) :
    loadLEWordBytes pb_src cb
    = ((pb_src.val[cb]'(by simp [Slice.length] at h; omega)).val
      + 2^8 * (pb_src.val[cb + 1]'(by simp [Slice.length] at h; omega)).val
      + 2^16 * (pb_src.val[cb + 2]'(by simp [Slice.length] at h; omega)).val
      + 2^24 * (pb_src.val[cb + 3]'(by simp [Slice.length] at h; omega)).val) := by
  unfold loadLEWordBytes
  have h0 : cb < pb_src.val.length := by simp [Slice.length] at h; omega
  have h1 : cb + 1 < pb_src.val.length := by simp [Slice.length] at h; omega
  have h2 : cb + 2 < pb_src.val.length := by simp [Slice.length] at h; omega
  have h3 : cb + 3 < pb_src.val.length := by simp [Slice.length] at h; omega
  rw [List.getD_eq_getElem _ _ h0, List.getD_eq_getElem _ _ h1,
      List.getD_eq_getElem _ _ h2, List.getD_eq_getElem _ _ h3]

end Symcrust.Properties.MLKEM.Bridges
