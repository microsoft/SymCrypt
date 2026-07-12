import Mathlib.Data.ZMod.Defs
import Mathlib.LinearAlgebra.Matrix.Defs
import Mathlib.LinearAlgebra.Matrix.RowCol
import Mathlib.Tactic.IntervalCases
import Aeneas
import Spec.NatBit
import Spec.Round
import Spec.SHA3.XOF
import Spec.Defs

/-!
# ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)

Based on: FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
URL: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf

All algorithm, section, and equation references are to FIPS 203.

## Mechanization notes

- **Byte vectors** use `𝔹 n` (= `Vector Byte n`) at all interfaces, matching FIPS 203.
- **Polynomials** are `Vector (ZMod m) 256`, representing elements of ℤ_m^256.
  The modulus `m` depends on the parameter `d`: `m = 2^d` if `d < 12`, `m = q` if `d = 12`.
- **NTT domain**: the same `Polynomial` type represents both `R_q` and `T_q` elements;
  the distinction is tracked by convention (hat notation in comments), not in types.
- **Hat variables** (`f̂`, `ŝ`, etc.): Lean identifiers use `«f̂»` escaping for
  combining-circumflex characters that lack precomposed forms.
- **Randomness**: `_internal` functions take random bytes as explicit parameters.
  Top-level ML-KEM.KeyGen and ML-KEM.Encaps use a `RandomTape` for completeness.
- **SampleNTT** uses a `while` loop (Lean compiles this via `Lean.Loop`, which is total).
  The FIPS 203 while loop has no a priori bound (Appendix B).
- **SHA3/SHAKE**: wrapper functions (H, J, G, PRF, XOF) are defined here in terms of
  `SHA3New.lean` (byte-level wrappers) and `XOF.lean` (incremental sponge API).
- **Rounding**: `⌈ x ⌋` denotes `⌊x + 1/2⌋` (nearest integer), defined in `Round.lean`.
- **`‖`** (concatenation): FIPS `X ‖ Y` is `X ‖ Y` on `Vector`s (from `Notations`).
- **Transpose**: `Âᵀ` in K-PKE.Encrypt uses `Matrix.transpose`.
- **`.cast`** appears where Lean cannot unify dependent-type arithmetic across
  `ParameterSet` branches (e.g., `384 * k` vs `32 * 12 * k`). This is inherent to
  working with parameter-dependent byte lengths.
- **Input validation**: Type-level enforcement provides all length checks (Algorithms 19–21).
  The encapsulation key modulus check (§7.2, Eq. 7.1) is explicitly implemented in `Encaps`.
  The decapsulation key hash check (§7.3) is explicitly implemented in `Decaps`.
  RBG failure checks are trivially satisfied by the `RandomTape` model.
- **Algorithm ordering**: Algorithm 12 (BaseCaseMultiply) is defined before
  Algorithm 11 (MultiplyNTTs) because the latter calls the former.
-/

namespace Spec.MLKEM

open Aeneas (rat_round)
open Aeneas.Notations.SRRange
open Aeneas.Notations.DivRange
open Aeneas.Notations.MulRange
open scoped Spec.Notations

/-! ## Bounds infrastructure for `get_elem_tactic`

These scoped lemmas let `grind` discharge array-index bounds arising from `for`
loops over `SRRange`, `DivRange`, and `MulRange`. They are activated by
`open Bounds`. The `idx_bound` tactic applies the matching bounds lemma. -/

namespace Bounds

/-! ### SRRange membership lemmas -/

/-- Forward-chaining: extract `i < stop` from `i ∈ [start : stop]`. -/
@[scoped grind →]
theorem srrange_upper {i n0 n1 : Nat}
    (hm : i ∈ [n0:n1]) : i < n1 := by
  rw [Notations.mem_std_range_step_one] at hm; exact hm.2

/-- Forward-chaining: extract `start ≤ i` from `i ∈ [start : stop]`. -/
@[scoped grind →]
theorem srrange_lower {i n0 n1 : Nat}
    (hm : i ∈ [n0:n1]) : n0 ≤ i := by
  rw [Notations.mem_std_range_step_one] at hm; exact hm.1

/-! ### Nonlinear index bounds -/

/-- `i * d + j < n * d` from `i < n, j < d`. -/
@[scoped grind ←]
theorem idx_mul_add_lt (i d j n : Nat) (hi : i < n) (hj : j < d) :
    i * d + j < n * d := by
  calc i * d + j < i * d + d := by agrind
    _ = (i + 1) * d := by ring
    _ ≤ n * d := Nat.mul_le_mul_right d hi

/-! ### NTT DivRange/MulRange butterfly bounds (§4.3) -/

/-- `start + 2 * len ≤ 256` for NTT butterfly loops with halving `len` (Algorithm 9). -/
theorem div_range_in_bounds {len start : ℕ}
    (h0 : 1 < len ∧ len ≤ 128 ∧ ∃ k, len = 128 / 2 ^ k)
    (h1 : start < 256 ∧ start % (2 * len) = 0) : start + 2 * len ≤ 256 := by
  rcases h0 with ⟨hlen_gt, hlen_le, ⟨k, hk⟩⟩
  have : k ≤ 6 := by
    have k_le : 2^k <= 2^6 := by
      rw [hk] at hlen_gt
      have : 0 < 2^k := pow_pos (by decide) _
      have := (Nat.le_div_iff_mul_le this).mp hlen_gt
      have h : 2 * 2^k ≤ 2 * 2^6 := this
      apply Nat.le_of_mul_le_mul_left h; decide
    contrapose! k_le
    apply Nat.pow_lt_pow_right (by decide); exact k_le
  interval_cases k <;> simp_all <;> omega

theorem div_range_in_bounds_mem
    (h0 : len ∈ ({ start := 128, stop := 1, divisor := 2, divisor_pos } : Aeneas.DivRange))
    (h1 : start ∈ ({ stop := 256, step := 2 * len, step_pos } : Aeneas.SRRange)) :
    start + 2 * len ≤ 256 := by
  apply div_range_in_bounds <;> simp [Membership.mem] at * <;> grind

scoped grind_pattern div_range_in_bounds_mem =>
  len ∈ ({ start := 128, stop := 1, divisor := 2, divisor_pos } : Aeneas.DivRange),
  start ∈ ({ stop := 256, step := 2 * len, step_pos } : Aeneas.SRRange)

/-- `start + 2 * len ≤ 256` for NTT⁻¹ butterfly loops with doubling `len` (Algorithm 10). -/
theorem mul_range_add_in_bounds {len start : ℕ}
    (h0 : 2 ≤ len ∧ len < 256 ∧ ∃ k, len = 2 * 2 ^ k)
    (h1 : start < 256 ∧ start % (2 * len) = 0) : start + 2 * len ≤ 256 := by
  rcases h0 with ⟨_, hlen_lt, ⟨k, hk⟩⟩
  have : k <= 6 := by
    contrapose hlen_lt; simp_all
    have : 256 = 2 * 2^7 := by simp
    rw [this]; apply Nat.mul_le_mul_left
    apply Nat.pow_le_pow_right (by decide); exact hlen_lt
  interval_cases k <;> simp_all <;> omega

theorem mul_range_add_in_bounds_mem {start_pos mul_pos}
    (h0 : len ∈ ({ start := 2, stop := 256, mul := 2, start_pos, mul_pos } : Aeneas.MulRange))
    (h1 : start ∈ ({ stop := 256, step := 2 * len, step_pos } : Aeneas.SRRange)) :
    start + 2 * len ≤ 256 := by
  apply mul_range_add_in_bounds <;> simp [Membership.mem] at * <;> grind

scoped grind_pattern mul_range_add_in_bounds_mem =>
  len ∈ ({ start := 2, stop := 256, mul := 2, start_pos, mul_pos } : Aeneas.MulRange),
  start ∈ ({ stop := 256, step := 2 * len, step_pos } : Aeneas.SRRange)

/-! ### Encoding/sampling index bounds (§4.2.1, §4.2.2) -/

/-- `i * d ≤ 255 * d` from `i < 256` (ByteEncode/ByteDecode, Algorithms 5–6). -/
@[scoped grind ←]
theorem byte_encode_idx_le (i d : Nat) (hi : i < 256) : i * d ≤ 255 * d :=
  Nat.mul_le_mul_right d (by omega)

/-- `32 * d * (i + 1) ≤ 32 * d * k` from `i < k` (PolyVector.ByteDecode). -/
@[scoped grind ←]
theorem poly_vec_decode_idx_le (d i : Nat) {k : Nat} (hi : i < k) :
    32 * d * (i + 1) ≤ 32 * d * k :=
  Nat.mul_le_mul_left _ hi

/-- `2 * i * η ≤ 510 * η` from `i < 256` (SamplePolyCBD, Algorithm 8). -/
@[scoped grind ←]
theorem sample_cbd_idx_le (i : Nat) (η : Nat) (hi : i < 256) :
    2 * i * η ≤ 510 * η := by
  have : i ≤ 255 := by omega
  calc 2 * i * η ≤ 2 * 255 * η := Nat.mul_le_mul_right η (Nat.mul_le_mul_left 2 this)
    _ = 510 * η := by ring

end Bounds

open Bounds

/-! ## §2.4 / §8 Constants and Parameters (Table 2) -/

/- `𝔹 n` (from Defs) is the standard interface type in FIPS 203. -/

/-- q = 3329, the modulus for ML-KEM (§2). -/
abbrev q : Nat := 3329

/-- ℤ_q = ℤ/3329ℤ, the coefficient ring. -/
abbrev Zq := ZMod q

/-- Polynomial ring element: `ℤ_m[X] / (X^256 + 1)`, represented as `Vector (ZMod m) 256`.
    When `d = 12`, `m = q`; when `d < 12`, `m = 2^d` (§4.2.1). -/
abbrev Polynomial (m : ℕ := q) := Vector (ZMod m) 256

def Polynomial.zero (m : ℕ := q) : Polynomial m := Vector.replicate 256 0

/-- Pointwise addition.

The body uses `Vector.zipWith` rather than the seemingly-equivalent
`Vector.ofFn (fun i => f[i] + g[i])`.  This is a *grind workaround*: the
latter shape causes `grind`'s `whnf` to descend through `Vector.ofFn`'s
lambda and infinitely unfold `Add` on the element type, blowing
`maxRecDepth` on any goal containing `_ + _ : Polynomial m`.  The bug is
reproducible in plain Lean (no imports beyond `Init`) with element type
`Fin n` (any `n ≥ 2`) or `ZMod n`; `Vector.zipWith` avoids it because its
body is a non-recursive `Array.zipWith` wrapper that `whnf` does not
recurse into.  See `Repro_GrindWhnfTimeout.lean` for the minimal repro. -/
def Polynomial.add (f g : Polynomial m) : Polynomial m :=
  Vector.zipWith (· + ·) f g

/-- Pointwise subtraction.  See `Polynomial.add` for the `zipWith`
rationale. -/
def Polynomial.sub (f g : Polynomial m) : Polynomial m :=
  Vector.zipWith (· - ·) f g

instance {m} : Add (Polynomial m) where add := Polynomial.add

instance {m} : Sub (Polynomial m) where sub := Polynomial.sub

def Polynomial.scalarMul (f : Polynomial m) (c : ZMod m) : Polynomial m :=
  f.map fun v => v * c

instance {m} : HMul (Polynomial m) (ZMod m) (Polynomial m) where
  hMul := Polynomial.scalarMul

/-- ζ = 17 ∈ ℤ_q is a primitive 256-th root of unity modulo q (§4.3). -/
def ζ : Zq := 17

/-- m(d) = 2^d if d < 12, q if d = 12 (§4.2.1). -/
abbrev m (d : ℕ) := if d < 12 then 2^d else q

/-- ML-KEM parameter sets (§8, Table 2).
    ML-KEM-512, ML-KEM-768, and ML-KEM-1024 correspond to
    NIST security categories 1, 3, and 5 respectively. -/
inductive ParameterSet where
  | ML_KEM_512
  | ML_KEM_768
  | ML_KEM_1024

/-- Module rank `k` (Table 2): dimension of the polynomial module lattice. -/
abbrev K := {k : ℕ // k ∈ ({2, 3, 4} : Set ℕ)}
/-- CBD noise parameter type: η ∈ {2, 3} (Table 2). -/
abbrev Η := {η : ℕ // η ∈ ({2, 3} : Set ℕ)}

/-- Module rank k: 2 for ML-KEM-512, 3 for 768, 4 for 1024 (Table 2). -/

@[reducible, scoped grind, scalar_tac_simps] def k (p : ParameterSet) : K :=
  match p with
  | .ML_KEM_512  => ⟨2, by grind⟩
  | .ML_KEM_768  => ⟨3, by grind⟩
  | .ML_KEM_1024 => ⟨4, by grind⟩

/-- CBD noise parameter η₁ (Table 2): 3 for ML-KEM-512, 2 for 768/1024. -/
@[reducible, scalar_tac_simps] def η₁ (p : ParameterSet) : Η :=
  match p with
  | .ML_KEM_512  => ⟨3, by grind⟩
  | .ML_KEM_768  => ⟨2, by grind⟩
  | .ML_KEM_1024 => ⟨2, by grind⟩

/-- CBD noise parameter η₂ = 2 for all parameter sets (Table 2). -/
def η₂ : Η := ⟨2, by grind⟩

/-- Ciphertext compression parameter dᵤ (Table 2): 10 for 512/768, 11 for 1024. -/
@[reducible, scalar_tac_simps] def dᵤ (p : ParameterSet) : ℕ :=
  match p with
  | .ML_KEM_512  => 10
  | .ML_KEM_768  => 10
  | .ML_KEM_1024 => 11

/-- Ciphertext compression parameter dᵥ (Table 2): 4 for 512/768, 5 for 1024. -/
@[reducible, scalar_tac_simps] def dᵥ (p : ParameterSet) : ℕ :=
  match p with
  | .ML_KEM_512  => 4
  | .ML_KEM_768  => 4
  | .ML_KEM_1024 => 5

/-! ## Vectors and Matrices of Polynomials (§2.4.4–§2.4.8) -/

@[reducible] def PolyVector (m : ℕ) (k : K) := Vector (Polynomial m) k
def PolyVector.zero (m : ℕ) (k : K) : PolyVector m k := Vector.replicate k (Polynomial.zero m)

def PolyVector.set {k : K} {m : ℕ} (v : PolyVector m k) (i : ℕ) (f : Polynomial m)
    (_ : i < k := by get_elem_tactic) : PolyVector m k :=
  Vector.set v i f

@[reducible] def PolyMatrix (m : ℕ) (k : K) := Matrix (Fin k) (Fin k) (Polynomial m)
def PolyMatrix.zero (m : ℕ) (k : K) : PolyMatrix m k := Matrix.of (fun _ _ => Polynomial.zero m)

/-- Element-wise matrix update: `M.update i j val` sets entry (i,j) to `val`. -/
def PolyMatrix.update {k : K} {m : ℕ} (M : PolyMatrix m k) (i j : ℕ) (val : Polynomial m)
    (hi : i < k := by get_elem_tactic) (_ : j < k := by get_elem_tactic) : PolyMatrix m k :=
  Matrix.updateRow M ⟨i, hi⟩ (fun col => if col = j then val else M ⟨i, hi⟩ col)

instance {k : K} {m : ℕ} : Add (PolyVector m k) where
  add v w := Vector.ofFn fun i => v[i] + w[i]

/-! ## §4.1 Cryptographic Functions (Eq. 4.1–4.5)

Defined in terms of the SHA-3 specification from `SHA3New.lean` (byte-level wrappers)
and the incremental sponge API from `XOF.lean`. -/

/-- H(s) := SHA3-256(s) — Eq. (4.4). -/
def H {n} (s : 𝔹 n) : 𝔹 32 := SHA3.sha3_256 s

/-- J(s) := SHAKE256(s, 32) — Eq. (4.4). -/
def J {n} (s : 𝔹 n) : 𝔹 32 := SHA3.shake256 s 32

/-- G(c) := SHA3-512(c), split into two 32-byte outputs — Eq. (4.5). -/
def G {n} (s : 𝔹 n) : 𝔹 32 × 𝔹 32 :=
  let hash := SHA3.sha3_512 s
  (slice hash 0 32, slice hash 32 32)

/-- PRF_η(s,b) := SHAKE256(s‖b, 8·64·η) — Eq. (4.3). -/
def PRF (η : Η) (s : 𝔹 32) (b : Byte) : 𝔹 (64 * η) :=
  SHA3.shake256 (s ‖ #v[b]) (64 * η)

/-! ### eXtendable-Output Function (XOF) — §4.1, Eq. (4.1)–(4.2)

XOF is SHAKE128 (§4.1). The state-passing API (Init/Absorb/Squeeze) allows
incremental squeezing as required by SampleNTT (Algorithm 7). -/

def XOF.Init := SHA3.SHAKE128.init

def XOF.Absorb s (B : 𝔹 ℓ) := SHA3.SHAKE128.absorb s B

def XOF.Squeeze s ℓ := SHA3.SHAKE128.squeeze s ℓ

/-! ## §4.2.1 Algorithm 3 — BitsToBytes(b)

Converts a bit array (of a length that is a multiple of eight) into an array of bytes. -/
abbrev BitsToBytes := @Spec.bitsToBytes

/-! ## §4.2.1 Algorithm 4 — BytesToBits(B)

Converts a byte array into a bit array. -/
abbrev BytesToBits := @Spec.bytesToBits

/-! ## §4.2.1 Compress / Decompress — Eq. (4.7), (4.8)

Lossy compression from ℤ_q to ℤ_{2^d} and decompression back. -/

def Compress (d : ℕ) (x : Zq) (_ : 1 ≤ d ∧ d < 12 := by grind) : ZMod (m d) :=
  ⌈ ((2^d : ℚ) / (q : ℚ)) * x.val ⌋

def Decompress (d : ℕ) (y : ZMod (m d)) (_ : 1 ≤ d ∧ d < 12 := by grind) : Zq :=
  ⌈ ((q : ℚ) / (2^d : ℚ)) * y.val ⌋

def Polynomial.Compress (d : ℕ) (f : Polynomial) (_ : 1 ≤ d ∧ d < 12 := by grind) : Polynomial (m d) :=
  f.map (MLKEM.Compress d)

def Polynomial.Decompress (d : ℕ) (f : Polynomial (m d)) (_ : 1 ≤ d ∧ d < 12 := by grind) : Polynomial :=
  f.map (MLKEM.Decompress d)

def PolyVector.Compress {k : K} (d : ℕ) (v : PolyVector q k) (_ : 1 ≤ d ∧ d < 12 := by grind) : PolyVector (m d) k :=
  v.map (Polynomial.Compress d)

def PolyVector.Decompress {k : K} (d : ℕ) (v : PolyVector (m d) k) (_ : 1 ≤ d ∧ d < 12 := by grind) : PolyVector q k :=
  v.map (Polynomial.Decompress d)

/-! ## §4.2.1 Algorithm 5 — ByteEncode_d(F)

Encodes an array of `d`-bit integers into a byte array, for `1 ≤ d ≤ 12`. -/
def ByteEncode (d : ℕ) (F : Polynomial (m d)) (_ : 1 ≤ d ∧ d ≤ 12 := by grind) : 𝔹 (32 * d) := Id.run do
  let mut b := Vector.replicate (256 * d) 0
  for hi: i in [0:256] do
    have := byte_encode_idx_le i d
    let mut a := F[i].val
    for hj: j in [0:d] do
      b := b.set (i * d + j) (Bool.ofNat (a % 2))
      a := (a - b[i * d + j].toNat) / 2
  let B := BitsToBytes (b.cast (by grind))
  pure B

/-! ## §4.2.1 Algorithm 6 — ByteDecode_d(B)

Decodes a byte array into an array of `d`-bit integers, for `1 ≤ d ≤ 12`. -/
def ByteDecode {d : ℕ} (B : 𝔹 (32 * d)) (_ : 1 ≤ d ∧ d ≤ 12 := by grind) : Polynomial (m d) := Id.run do
  let b := BytesToBits B
  let mut F := Polynomial.zero (m d)
  for hi: i in [0:256] do
    have := byte_encode_idx_le i d
    F := F.set i (∑ (j : Fin d), b[i * d + j].toNat * 2^j.val)
  pure F

def PolyVector.ByteEncode {k : K} (d : ℕ) (v : PolyVector (m d) k) (_ : 1 ≤ d ∧ d ≤ 12 := by grind) : 𝔹 (k * (32 * d)) :=
  (v.map (MLKEM.ByteEncode d)).flatten

def PolyVector.ByteDecode {k : K} (d : ℕ) (bytes : 𝔹 (32 * d * k)) (_ : 1 ≤ d ∧ d ≤ 12 := by grind) : PolyVector (m d) k :=
  Vector.ofFn fun i =>
    have := poly_vec_decode_idx_le d i i.isLt
    MLKEM.ByteDecode (slice bytes (32 * d * i) (32 * d) (by simp_scalar; grind))

/-! ## §4.2.2 Algorithm 7 — SampleNTT(B)

Uses rejection sampling to deterministically generate an element of `T_q`
from a byte stream `B ∥ XOF(B)`. -/
def SampleNTT (B : 𝔹 34) : Polynomial := Id.run do
  let mut ctx := XOF.Init
  ctx := XOF.Absorb ctx B
  let mut «â» := Polynomial.zero
  let mut j := 0
  while hj : j < 256 do
    let (ctx', C) := XOF.Squeeze ctx 3
    ctx := ctx'
    let d₁ := C[0].val + 256 * (C[1].val % 16)
    let d₂ := C[1].val / 16 + 16 * C[2].val
    if d₁ < q then
      «â» := «â».set j d₁
      j := j + 1
    if h : d₂ < q ∧ j < 256 then
      «â» := «â».set j d₂
      j := j + 1
  pure «â»

/-! ## §4.2.2 Algorithm 8 — SamplePolyCBD_η(B)

Uses the centered binomial distribution to deterministically generate
a polynomial in `R_q` from a `64·η`-byte array. -/

@[scalar_tac η.val]
theorem Η.val_le (η : Η) : η.val ≤ 3 := by
  have := η.property; scalar_tac

scoped grind_pattern Η.val_le => η.val

def SamplePolyCBD {η : Η} (B : 𝔹 (64 * η)) : Polynomial := Id.run do
  let b := BytesToBits B
  let mut f := Polynomial.zero
  for hi: i in [0:256] do
    have := sample_cbd_idx_le i η (by grind)
    let x := ∑ (j : Fin η), b[2 * i * η + j].toNat
    let y := ∑ (j : Fin η), b[2 * i * η + η + j].toNat
    f := f.set i (x - y)
  pure f

/-! ## §4.3 Algorithm 9 — NTT(f)

Computes the NTT representation `f̂ ∈ T_q` of a polynomial `f ∈ R_q`
using Cooley–Tukey butterflies. -/
def NTT (f : Polynomial) : Polynomial := Id.run do
  let mut «f̂» := f
  let mut i := 1
  for h0: len in [128 : >1 : /= 2] do
    for h1: start in [0 : 256 : 2*len] do
      let zeta := ζ ^ (bitRev 7 i)
      i := i + 1
      for h: j in [start : start+len] do
        let t := zeta * «f̂»[j + len]
        «f̂» := «f̂».set (j + len) («f̂»[j] - t)
        «f̂» := «f̂».set j         («f̂»[j] + t)
  pure «f̂»

/-! ## §4.3 Algorithm 10 — NTT⁻¹(f̂)

Computes the polynomial `f ∈ R_q` corresponding to an NTT representation `f̂ ∈ T_q`
using Gentleman–Sande butterflies. -/
def NTTInv («f̂» : Polynomial) : Polynomial := Id.run do
  let mut f := «f̂»
  let mut i := 127
  for h0: len in [2 : <256 : *= 2] do
    for h1: start in [0:256:2*len] do
      let zeta := ζ ^ bitRev 7 i
      i := i - 1
      for h: j in [start:start+len] do
        let t := f[j]
        f := f.set j (t + f[j + len])
        f := f.set (j + len) (zeta * (f[j + len] - t))
  f := f * (3303 : Zq)
  pure f

/-! ## §4.3.1 Algorithm 12 — BaseCaseMultiply(a₀,a₁,b₀,b₁,γ)

Computes the product of two degree-one polynomials with respect to a
quadratic modulus `X² − γ`. -/
def BaseCaseMultiply (a₀ a₁ b₀ b₁ γ : Zq) : Zq × Zq :=
  let c₀ := a₀ * b₀ + a₁ * b₁ * γ                                              -- Alg. 12, step 1
  let c₁ := a₀ * b₁ + a₁ * b₀                                                  -- Alg. 12, step 2
  (c₀, c₁)                                                                      -- Alg. 12, step 3

/-! ## §4.3.1 Algorithm 11 — MultiplyNTTs(f̂, ĝ)

Computes the product (in the NTT domain) of two NTT representations,
via 128 base-case multiplications in the factor rings of `T_q`. -/
def MultiplyNTTs («f̂» «ĝ» : Polynomial) : Polynomial := Id.run do
  let mut «ĥ» := Polynomial.zero
  for h: i in [0:128] do
    let (c₀, c₁) := BaseCaseMultiply «f̂»[2*i] «f̂»[2*i+1] «ĝ»[2*i] «ĝ»[2*i+1] (ζ^(2 * bitRev 7 i + 1))
    «ĥ» := «ĥ».set (2*i) c₀
    «ĥ» := «ĥ».set (2*i+1) c₁
  pure «ĥ»

/-! ### Linear algebra over T_q (§2.4.7–§2.4.8) -/

def PolyVector.NTT {k : K} (v : PolyVector q k) : PolyVector q k := v.map MLKEM.NTT
def PolyVector.NTTInv {k : K} (v : PolyVector q k) : PolyVector q k := v.map MLKEM.NTTInv

def PolyMatrix.MulVectorNTT {k : K} (A : PolyMatrix q k) (v : PolyVector q k) : PolyVector q k := Id.run do
  let mut w := PolyVector.zero q k
  for hi: i in [0:k] do
    for hj: j in [0:k] do
      w := w.set i (w[i] + MultiplyNTTs (A ⟨i, by scalar_tac⟩ ⟨j, by scalar_tac⟩) v[j])
  pure w

instance {k} : HMul (PolyMatrix q k) (PolyVector q k) (PolyVector q k) where
  hMul := PolyMatrix.MulVectorNTT

def PolyVector.innerProductNTT {k : K} (v w : PolyVector q k) : Polynomial := Id.run do
  let mut a := Polynomial.zero
  for hi: i in [0:k] do
    a := a + MultiplyNTTs v[i] w[i]
  pure a

/-! ## §5.1 Algorithm 13 — K-PKE.KeyGen(d)

Uses a 32-byte seed `d` to deterministically generate an encryption key
and a corresponding decryption key for the K-PKE scheme. -/
def K_PKE.KeyGen (p : ParameterSet) (d : 𝔹 32) : 𝔹 (384 * k p + 32) × 𝔹 (384 * k p) := Id.run do
  let (ρ, σ) := G (d ‖ #v[(k p : Byte)])                                 -- Alg. 13, step 1
  let mut N := 0                                                        -- Alg. 13, step 2
  let mut «Â» := PolyMatrix.zero q (k p)                                       -- Alg. 13, steps 3–7
  for hi: i in [0:k p] do
    for hj: j in [0:k p] do
      «Â» := «Â».update i j (SampleNTT (ρ ‖ #v[(j : Byte)] ‖ #v[(i : Byte)]))
  let mut s := PolyVector.zero q (k p)                                         -- Alg. 13, steps 8–11
  for hi: i in [0:k p] do
    s := s.set i (SamplePolyCBD (PRF (η₁ p) σ N))
    N := N + 1
  let mut e := PolyVector.zero q (k p)                                         -- Alg. 13, steps 12–15
  for hi: i in [0:k p] do
    e := e.set i (SamplePolyCBD (PRF (η₁ p) σ N))
    N := N + 1
  let «ŝ» := PolyVector.NTT s                                                  -- Alg. 13, step 16
  let «ê» := PolyVector.NTT e                                                  -- Alg. 13, step 17
  let «t̂» := «Â» * «ŝ» + «ê»                             -- Alg. 13, step 18
  let ekPKE := (PolyVector.ByteEncode 12 «t̂» ‖ ρ).cast (by cases p <;> simp)  -- Alg. 13, step 19
  let dkPKE := (PolyVector.ByteEncode 12 «ŝ»).cast (by cases p <;> simp)      -- Alg. 13, step 20
  pure (ekPKE, dkPKE)

/-! ## §5.2 Algorithm 14 — K-PKE.Encrypt(ekPKE, m, r)

Uses the encryption key to encrypt a plaintext message using the randomness `r`.

*Mechanization note*: FIPS 203 names the noise vector `r` in Algorithm 14, but
this collides with the randomness parameter `r : 𝔹 32`. We rename the noise
vector to `y` (and its NTT to `ŷ`) to avoid shadowing. -/
def K_PKE.Encrypt (p : ParameterSet) (ekPKE : 𝔹 (384 * k p + 32)) (m : 𝔹 32) (r : 𝔹 32) :
    𝔹 (32 * (dᵤ p * k p + dᵥ p)) := Id.run do
  let mut N := 0                                                               -- Alg. 14, step 1
  let «t̂» := PolyVector.ByteDecode 12 (slice ekPKE 0 (384 * k p))              -- Alg. 14, step 2
  let ρ := slice ekPKE (384 * k p) 32                                          -- Alg. 14, step 3
  let mut «Â» := PolyMatrix.zero q (k p)                                       -- Alg. 14, steps 4–8
  for hi: i in [0:k p] do
    for hj: j in [0:k p] do
      «Â» := «Â».update i j (SampleNTT (ρ ‖ #v[(j : Byte)] ‖ #v[(i : Byte)]))
  let mut y := PolyVector.zero q (k p)                                         -- Alg. 14, steps 9–12
  for hi: i in [0:k p] do
    y := y.set i (SamplePolyCBD (PRF (η₁ p) r N))
    N := N + 1
  let mut e₁ := PolyVector.zero q (k p)                                        -- Alg. 14, steps 13–16
  for hi: i in [0:k p] do
    e₁ := e₁.set i (SamplePolyCBD (PRF η₂ r N))
    N := N + 1
  let e₂ := SamplePolyCBD (PRF η₂ r N)                                         -- Alg. 14, step 17
  let «ŷ» := PolyVector.NTT y                                                  -- Alg. 14, step 18
  let u := PolyVector.NTTInv (Matrix.transpose «Â» * «ŷ») + e₁                 -- Alg. 14, step 19
  let μ := Polynomial.Decompress 1 (ByteDecode (m.cast (by grind)))          -- Alg. 14, step 20
  let v := NTTInv (PolyVector.innerProductNTT «t̂» «ŷ») + e₂ + μ                -- Alg. 14, step 21
  let c₁ := PolyVector.ByteEncode (dᵤ p) (PolyVector.Compress (dᵤ p) u)        -- Alg. 14, step 22
  let c₂ := ByteEncode (dᵥ p) (Polynomial.Compress (dᵥ p) v)                   -- Alg. 14, step 23
  (c₁ ‖ c₂).cast (by cases p <;> simp [dᵤ, dᵥ])                               -- Alg. 14, step 24

/-! ## §5.3 Algorithm 15 — K-PKE.Decrypt(dkPKE, c)

Uses the decryption key to decrypt a ciphertext. -/
def K_PKE.Decrypt (p : ParameterSet) (dkPKE : 𝔹 (384 * k p)) (c : 𝔹 (32 * (dᵤ p * k p + dᵥ p))) :
    𝔹 32 :=
  let c₁ := slice c 0 (32 * dᵤ p * k p)                                       -- Alg. 15, step 1
  let c₂ := slice c (32 * dᵤ p * k p) (32 * dᵥ p)                             -- Alg. 15, step 2
  let u' := PolyVector.Decompress (dᵤ p) (PolyVector.ByteDecode (k := k p) (dᵤ p) c₁) -- Alg. 15, step 3
  let v' := Polynomial.Decompress (dᵥ p) (ByteDecode c₂)                             -- Alg. 15, step 4
  let «ŝ» := PolyVector.ByteDecode (k := k p) 12 (dkPKE.cast (by grind))          -- Alg. 15, step 5
  let w := v' - NTTInv (PolyVector.innerProductNTT «ŝ» (PolyVector.NTT u'))      -- Alg. 15, step 6
  let m := ByteEncode 1 (Polynomial.Compress 1 w)                              -- Alg. 15, step 7
  m.cast (by grind)

/-! ## §6.1 Algorithm 16 — ML-KEM.KeyGen_internal(d,z)

Uses seeds `d` and `z` to deterministically generate an encapsulation key
and a corresponding decapsulation key. -/
def KeyGen_internal (p : ParameterSet) (d z : 𝔹 32) :
    𝔹 (384 * k p + 32) × 𝔹 (768 * k p + 96) :=
  let (ekPKE, dkPKE) := K_PKE.KeyGen p d                                       -- Alg. 16, step 1
  let ek := ekPKE                                                              -- Alg. 16, step 2
  let dk := dkPKE ‖ ek ‖ H ek ‖ z                                              -- Alg. 16, step 3
  (ek, dk.cast (by grind))

/-! ## §6.2 Algorithm 17 — ML-KEM.Encaps_internal(ek, m)

Uses the encapsulation key and a 32-byte message to deterministically
generate a shared key and an associated ciphertext. -/
def Encaps_internal (p : ParameterSet) (ek : 𝔹 (384 * k p + 32)) (m : 𝔹 32) :
    𝔹 32 × 𝔹 (32 * (dᵤ p * k p + dᵥ p)) :=
  let (K, r) := G (m ‖ H ek)                                                -- Alg. 17, step 1
  let c := K_PKE.Encrypt p ek m r                                            -- Alg. 17, step 2
  (K, c)

/-! ## §6.3 Algorithm 18 — ML-KEM.Decaps_internal(dk, c)

Uses the decapsulation key to produce a shared key from a ciphertext.
Uses implicit rejection via the seed `z` embedded in `dk`. -/
def Decaps_internal (p : ParameterSet)
    (dk : 𝔹 (768 * k p + 96))
    (c : 𝔹 (32 * (dᵤ p * k p + dᵥ p))) : 𝔹 32 :=
  let dkPKE := slice dk 0 (384 * k p)                       -- Alg. 18, step 1
  let ekPKE := slice dk (384 * k p) (384 * k p + 32)       -- Alg. 18, step 2
  let h := slice dk (768 * k p + 32) 32                    -- Alg. 18, step 3
  let z := slice dk (768 * k p + 64) 32                   -- Alg. 18, step 4
  let m' := K_PKE.Decrypt p dkPKE c                                           -- Alg. 18, step 5
  let (K', r') := G (m' ‖ h)                                                 -- Alg. 18, step 6
  let «K̄» := J (z ‖ c)                                                       -- Alg. 18, step 7
  let c' := K_PKE.Encrypt p ekPKE m' r'                                       -- Alg. 18, step 8
  if c ≠ c' then «K̄» else K'                                                  -- Alg. 18, steps 9–12

/-! ## §7 The ML-KEM Key-Encapsulation Mechanism

The top-level API wraps the `_internal` functions with a `RandomTape` for randomness. -/

/-- A random tape is an infinite stream of bytes.
    This models the RBG (Random Bit Generator) of §3.3. -/
def RandomTape := ℕ → Byte

def RandomTape.readBytes (tape : RandomTape) (n : ℕ) : 𝔹 n × RandomTape :=
  (Vector.ofFn (fun i => tape i), fun i => tape (n + i))

/-! ### Input validation checks (§7.2–§7.3)

These checks were added late in the FIPS 203 standardization process (they are not
present in the earlier CRYSTALS-Kyber specification). They guard against malformed
keys and corrupted decapsulation key material, and are security-relevant: the modulus
check prevents a class of chosen-ciphertext attacks on malformed encapsulation keys,
and the hash check detects decapsulation key corruption before use. -/

/-! ## §7.1 Algorithm 19 — ML-KEM.KeyGen()

Generates an encapsulation key and a corresponding decapsulation key. -/
def KeyGen (p : ParameterSet) (tape : RandomTape) :
    𝔹 (384 * k p + 32) × 𝔹 (768 * k p + 96) × RandomTape :=
  -- Steps 3–5: RBG failure check.
  -- Trivially succeeds with `RandomTape` (no RBG failure mode).
  let (d, tape) := tape.readBytes 32
  let (z, tape) := tape.readBytes 32
  let (ek, dk) := KeyGen_internal p d z
  (ek, dk, tape)

/-- Encapsulation Key Modulus Check (§7.2, Eq. 7.1).
    Verifies `ByteEncode₁₂(ByteDecode₁₂(ekPKE)) = ekPKE`, i.e., all encoded
    coefficients are reduced modulo q. Returns `true` if valid. -/
def Encaps.KeyCheck (p : ParameterSet) (ek : 𝔹 (384 * k p + 32)) : Bool :=
  let ekPKE := slice ek 0 (384 * k p)
  let decoded := PolyVector.ByteDecode (k := k p) 12 ekPKE
  let recoded := PolyVector.ByteEncode 12 decoded
  recoded = ekPKE.cast (by grind)

/-! ## §7.2 Algorithm 20 — ML-KEM.Encaps(ek)

Uses the encapsulation key to generate a shared key and an associated ciphertext.
Returns `none` if the encapsulation key fails validation. -/
def Encaps (p : ParameterSet) (ek : 𝔹 (384 * k p + 32)) (tape : RandomTape) :
    Option (𝔹 32 × 𝔹 (32 * (dᵤ p * k p + dᵥ p)) × RandomTape) :=
  -- Steps 1–2: Encapsulation Key type check (length).
  -- Trivially enforced by `ek : 𝔹 (384 * k p + 32)`.
  -- Steps 3–4: RBG failure check.
  -- Trivially succeeds with `RandomTape` (no RBG failure mode).
  let (m, tape) := tape.readBytes 32
  if Encaps.KeyCheck p ek then                                                   -- Alg. 20, steps 5–6
    let (K, c) := Encaps_internal p ek m                                       -- Alg. 20, step 7
    some (K, c, tape)
  else none

/-- Decapsulation Key Hash Check (§7.3, Eq. 7.2).
    Computes `H(dk[384k : 768k+32])` and compares to `dk[768k+32 : 768k+64]`.
    Verifies integrity of the embedded ekPKE against the stored hash.
    Returns `true` if valid. -/
def Decaps.KeyCheck (p : ParameterSet) (dk : 𝔹 (768 * k p + 96)) : Bool :=
  let ek := slice dk (384 * k p) (384 * k p + 32)
  let h := slice dk (768 * k p + 32) 32
  H ek = h                                                      -- Eq. (7.2)


/-! ## §7.3 Algorithm 21 — ML-KEM.Decaps(dk, c)

Uses the decapsulation key to produce a shared key from a ciphertext.
Returns `none` if the decapsulation key fails validation. -/
def Decaps (p : ParameterSet) (dk : 𝔹 (768 * k p + 96))
    (c : 𝔹 (32 * (dᵤ p * k p + dᵥ p))) : Option (𝔹 32) :=
  -- Step 1: Decapsulation Key type check (length).
  -- Trivially enforced by `dk : 𝔹 (768 * k p + 96)`.
  -- Step 2: Ciphertext type check (length).
  -- Trivially enforced by `c : 𝔹 (32 * (dᵤ p * k p + dᵥ p))`.
  if Decaps.KeyCheck p dk then some (Decaps_internal p dk c)                      -- Alg. 21, steps 1–2
  else none

end Spec.MLKEM
