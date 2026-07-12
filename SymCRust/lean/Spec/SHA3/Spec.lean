import Spec.Defs

/-!
# SHA-3 (Permutation-Based Hash and Extendable-Output Functions) specification

Based on: FIPS 202: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

All algorithm, section, and equation references are to FIPS 202.

## Scope

KECCAK-p[1600,24] and the six SHA-3 functions (§3–§6), specialized to b = 1600.
Not formalized: other KECCAK-p widths (Table 1), h2b/b2h (§B.1).

## Mechanization notes

- Lanes are `Vector Bool 64` (§3.1.1). The state array A[x][y] is
  `Vector (Vector Lane 5) 5`.
- Bit strings are `Vector Bool n` with dependent lengths, using LSB-first indexing
  (index 0 = least significant bit), matching FIPS 202 lane-bit ordering.
- The sponge (§4) uses `Vector Bool b` for state and `‖` (concatenation)
  for block operations, avoiding per-bit loops in absorb and squeeze.
- FIPS concatenation `X || Y` places X at lower bit indices; `Vector.append`
  (notation `‖`) already places its first argument at lower indices, so
  `Pᵢ ‖ 0^c` reads exactly as in Algorithm 8, Step 6.
- The `·` in χ (§3.2.4) is `&&&`; `⊕ 1` is `~~~` (complement).
- `pad10*1` builds the pad as `#v[1] ‖ 0^j ‖ #v[1]`, directly transcribing
  "1 || 0^j || 1" from FIPS §5.1.
- `Fin` subtraction wraps correctly for modular expressions like `C[x−1]`.
- Indexing with `Fin 5` arithmetic (e.g., `x + 1`, `x - 1`, `2*x + 3*y`)
  implicitly computes modulo 5, matching the standard's `(x+1) mod 5` etc.
- FIPS loop bounds are inclusive ("for t from 0 to 23"); Lean `for t in [0:24]`
  uses exclusive upper bounds, so the range is `[0, 24)` = `{0, 1, ..., 23}`.
- `rc` (Algorithm 5) uses `Vector Bool 8`/`Vector Bool 9` with `‖` for step (a)
  "0 || R" and `slice` for step (f) "Trunc₈(R)".
- `SPONGE` takes pre-padded input `P` rather than `(N, pad)` separately;
  padding is performed by `KECCAK` (§5.2), which appends `N ‖ pad10*1(r, len(N))`
  before calling `SPONGE`. This keeps `SPONGE` generic (faithful to §4).
- Numeric literals use `Bits.ofNatLE` (via a scoped `OfNat` override) so that
  e.g. `(1 : Vector Bool 8)` has bit 0 = true, matching the FIPS LSB-first convention.

Properties, examples, and test vectors are in auxiliary files.
-/

namespace Spec.SHA3

open Spec (𝔹 slice bytesToBits bitsToBytes)
open scoped Spec.Notations

-- Override the default BE OfNat instance: SHA-3 is entirely LSB-first.
scoped instance : OfNat (Vector Bool n) k := ⟨Bits.ofNatLE k⟩

-- FIPS uses ⊕ for XOR (§2.3)
scoped notation:65 a " ⊕ " b => HXor.hXor (α := Vector Bool _) a b


/-! ## Parameters (Table 1), specialized to b = 1600 -/

abbrev b : Nat := 1600
abbrev w : Nat := 64
abbrev ℓ : Nat := 6

/-! ## Basic Operations (§2.3) -/

/-- Trunc_s(X): the string comprised of bits X[0] to X[s-1] (§2.3). -/
def Trunc (s : Nat) (X : Vector Bool n) (h : s ≤ n := by grind) :=
  slice X 0 s

/-! ## State (§3.1) -/

abbrev Lane := Vector Bool w
abbrev State := Vector (Vector Lane 5) 5

/-! ### String ↔ State conversions (§3.1.2–3.1.3)

Lane(x,y) occupies bits [w(5y+x) .. w(5y+x)+w-1] of the b-bit string. -/

def stringToState (S : Vector Bool b) : State :=
  Vector.ofFn fun x => Vector.ofFn fun y => Vector.ofFn fun z =>
    S[w * (5 * y.val + x.val) + z.val]

def stateToString (A : State) : Vector Bool b :=
  Vector.ofFn fun (i : Fin b) =>
    let lane := i.val / w
    let x := lane % 5
    let y := lane / 5
    let z := i.val % w
    A[x][y][z]


/-! ## Step Mappings (§3.2) -/

/-! ### Algorithm 1: θ(A) (§3.2.1) -/

def θ (A : State) :=
  let C := Vector.ofFn fun x => A[x][0] ⊕ A[x][1] ⊕ A[x][2] ⊕ A[x][3] ⊕ A[x][4]
  let D := Vector.ofFn fun x => C[x - 1] ⊕ C[x + 1].rotateLeft 1
  Vector.ofFn fun x => Vector.ofFn fun y => A[x][y] ⊕ D[x]

/-! ### Algorithm 2: ρ(A) (§3.2.2) — rotate each lane by its computed offset

    1. A′[0, 0, z] = A[0, 0, z].       (offset 0 — handled by zero-initialization)
    2. Let (x, y) = (1, 0).
    3. For t from 0 to 23:
       a. A′[x, y, z] = A[x, y, (z − (t+1)(t+2)/2) mod w].
       b. Let (x, y) = (y, (2x + 3y) mod 5). -/

/-- Rotation offsets for ρ, computed from Algorithm 2 (§3.2.2). -/
def ρ.Offsets : Vector (Vector Nat 5) 5 := Id.run do
  let mut offsets := .replicate 5 (.replicate 5 0)
  let mut x : Fin 5 := 1
  let mut y : Fin 5 := 0
  for t in [0 : 24] do
    offsets := offsets.set x (offsets[x].set y ((t + 1) * (t + 2) / 2))
    (x, y) := (y, 2 * x + 3 * y)
  pure offsets

def ρ (A : State) : State :=
  Vector.ofFn fun x => Vector.ofFn fun y =>
    A[x][y].rotateLeft (ρ.Offsets[x][y] % w)

/-! ### Algorithm 3: π(A) (§3.2.3) -/

def π (A : State) : State :=
  Vector.ofFn fun x => Vector.ofFn fun y => A[x + 3 * y][x]

/-! ### Algorithm 4: χ(A) (§3.2.4)

The standard writes `A′[x,y,z] = A[x,y,z] ⊕ ((A[(x+1) mod 5, y, z] ⊕ 1) · A[(x+2) mod 5, y, z])`
where `⊕ 1` is bitwise complement and `·` is AND.
We write `~~~A[x+1][y] &&& A[x+2][y]` (complement + AND). -/

def χ (A : State) : State :=
  Vector.ofFn fun x => Vector.ofFn fun y =>
    A[x][y] ⊕ (~~~A[x + 1][y] &&& A[x + 2][y])

/-! ### Algorithm 5: rc(t) (§3.2.5) -/

def rc (t : Nat) : Bool := Id.run do
  -- 1. If t mod 255 = 0, return 1.
  if t % 255 = 0 then return true
  -- 2. Let R = 10000000.
  let mut R := #v[1, 0, 0, 0, 0, 0, 0, 0]
  -- 3. For i from 1 to t mod 255:
  for _ in [1 : t % 255 + 1] do
    let R' := #v[0] ‖ Trunc 8 R
    let R' := R'.set 0 (R'[0] ^^ R'[8])
    let R' := R'.set 4 (R'[4] ^^ R'[8])
    let R' := R'.set 5 (R'[5] ^^ R'[8])
    let R' := R'.set 6 (R'[6] ^^ R'[8])
    R := Trunc 8 R'
  pure R[0]

/-! ### Algorithm 6: ι(A, iᵣ) (§3.2.5) -/

/-- Round constant RC for round iᵣ (Algorithm 6, Steps 2–3).
    "For j from 0 to ℓ, let RC[2^j − 1] = rc(j + 7iᵣ)." -/
def ι.RC (iᵣ : Nat) : Lane := Id.run do
  let mut RC : Lane := 0
  for hj : j in [0 : ℓ + 1] do
    have : 2 ^ j - 1 < w := by
      have hj_lt := hj.upper
      simp only [ℓ, w] at *
      have : 2 ^ j ≤ 2 ^ 6 := Nat.pow_le_pow_right (by omega) (by omega)
      omega
    RC := RC.set (2 ^ j - 1) (rc (j + 7 * iᵣ))
  pure RC

def ι (A : State) (iᵣ : Nat) : State :=
  let RC := ι.RC iᵣ
  Vector.ofFn fun x => Vector.ofFn fun y =>
    if x = 0 ∧ y = 0
    then A[x][y] ⊕ RC
    else A[x][y]


/-! ## Round Function and KECCAK-p (§3.3) -/

def Rnd (A : State) (iᵣ : Nat) : State := ι (χ (π (ρ (θ A)))) iᵣ

/-! Algorithm 7: KECCAK-p[b, nr](S), specialized to b = 1600.
    Steps 1,3 convert between bit string and state array (§3.1.2–3.1.3). -/

def KECCAK_p (nr : Nat) (S : Vector Bool b) : Vector Bool b := Id.run do
  let mut A := stringToState S
  for _h : iᵣ in [12 + 2 * ℓ - nr : 12 + 2 * ℓ] do
    A := Rnd A iᵣ
  pure (stateToString A)

/-! KECCAK-f[1600] = KECCAK-p[1600, 24] (§3.4) -/

def KECCAK_f (S : Vector Bool b) : Vector Bool b := KECCAK_p 24 S


/-! ## Sponge Construction (§4, Algorithm 8)

SPONGE[f, pad, r](N, d) — generic over f, pad, r.
All bit strings use `Vector Bool` with dependent lengths. -/

/-- Padding length for pad10*1(x, m) (§5.1). -/
abbrev padLen.j (x m : Nat) := ((-(m : Int) - 2) % x).toNat
abbrev padLen x m := 1 + padLen.j x m + 1

/-- Algorithm 9: pad10*1(x, m) (§5.1). Returns `Vector Bool (padLen x m)`.
    1. j = (−m − 2) mod x
    2. Return 1 || 0^j || 1 -/
def «pad10*1» x m : Vector Bool (padLen x m) :=
  #v[1]  ‖ .replicate (padLen.j x m) 0 ‖ #v[1]

/-- Padding always produces a total length divisible by x.
    Used to discharge the `blocks` divisibility precondition.
    Proof: `pad10*1(x, m)` has length `j + 2` where `j = (−m − 2) mod x`,
    so `m + j + 2 ≡ m + (−m − 2) + 2 ≡ 0 (mod x)`. -/
theorem padLen_dvd (r n : Nat) (hr : 0 < r := by grind) : (n + padLen r n) % r = 0 := by
  simp only [padLen, padLen.j]
  have hnn : (-(↑n : Int) - 2) % ↑r ≥ 0 := Int.emod_nonneg _ (by omega)
  have h_eq : (n : Int) + (1 + ((-(↑n : Int) - 2) % ↑r).toNat + 1) =
    ((-(↑n : Int) - 2) % ↑r + ↑n + 2) := by omega
  have h_mod : ((-(↑n : Int) - 2) % ↑r + ↑n + 2) % ↑r = 0 := by
    have := Int.emod_add_mul_ediv (-(n : Int) - 2) r
    rw [show (-(↑n : Int) - 2) % ↑r + ↑n + 2 = -(↑r * ((-(↑n : Int) - 2) / ↑r)) from by omega]
    exact Int.neg_mul_emod_right r _
  grind

private theorem blocks_bound (i : Fin (pLen / r)) (_hr : 0 < r := by grind) :
    i.val * r + r ≤ pLen := by
  have h1 : (↑i + 1) * r ≤ (pLen / r) * r := Nat.mul_le_mul_right r (by omega)
  have h2 := Nat.div_mul_le_self pLen r
  calc ↑i * r + r = (↑i + 1) * r := by rw [Nat.add_mul, Nat.one_mul]
    _ ≤ (pLen / r) * r := h1
    _ ≤ pLen := h2

/-- Partition a bit string into r-bit blocks (§4, Step 4).
    Precondition: `pLen` is a multiple of `r` (guaranteed by padding). -/
def blocks (P : Vector Bool pLen) (r : Nat)
    (_hr : 0 < r := by grind)
    (_hdiv : pLen % r = 0 := by grind) :
    Vector (Vector Bool r) (pLen / r) :=
  Vector.ofFn fun i => slice P (i * r) r (blocks_bound i)

def SPONGE.absorb {m}
    (f : Vector Bool b → Vector Bool b) r
    (P : Vector Bool m)
    (hm : m % r = 0 := by grind)
    (hr : 0 < r := by grind) : Vector Bool b := Id.run do
  let mut S : Vector Bool b := 0
  for Pi in blocks P r do
    S := f (S ⊕ Bits.zeroExtend Pi b)
  pure S

/-- One step of the squeeze phase: extract r bits from the state, then permute.
    Factored out so that both the functional `SPONGE.squeeze` and the incremental
    sponge API (`Sha3XOF.lean`) can share the same primitive. -/
def SPONGE.squeeze_step
    (f : Vector Bool b → Vector Bool b) (r : Nat)
    (S : Vector Bool b) (_hr : r ≤ b := by grind) :
    Vector Bool r × Vector Bool b :=
  (Trunc r S, f S)

def SPONGE.squeeze {m d}
    (f : Vector Bool b → Vector Bool b) r
    (Z : Vector Bool m) (S : Vector Bool b)
    (hr : 0 < r ∧ r < b := by grind) : Vector Bool d :=
  if hd: d <= m then
    Trunc d Z
  else
    let (block, S) := SPONGE.squeeze_step f r S
    SPONGE.squeeze f r (Z ‖ block) S

/-- SPONGE[f, pad, r](N, d) (§4, Algorithm 8). -/
def SPONGE {l : Nat}
    (f : Vector Bool b → Vector Bool b)
    (r : Nat) (N : Vector Bool l) (d : Nat)
    (hr : 0 < r ∧ r < b := by grind) (_hrb : r ≤ b := by grind) :
    Vector Bool d := Id.run do
  let P := N ‖ «pad10*1» r l
  have := padLen_dvd r l
  let S := SPONGE.absorb f r P
  SPONGE.squeeze f r #v[] S

/-! ## KECCAK[c] (§5.2)

KECCAK[c] = SPONGE[KECCAK-p[1600, 24], pad10*1, 1600 − c] -/

def KECCAK {n} c (N : Vector Bool n) d
    (_hc : 0 < c ∧ c < 1536 := by grind) : Vector Bool d :=
  SPONGE KECCAK_f (1600 - c) N d


/-! ## SHA-3 Hash Functions (§6.1)

SHA3-224(M) = KECCAK[448](M || 01, 224), etc.
The two-bit suffix 01 supports domain separation. -/

-- hashSuffix = FIPS "01": bit 0 = 0, bit 1 = 1 (LSB-first)
def hashSuffix : Vector Bool 2 := #v[0, 1]

def SHA3_224 {n} (M : Vector Bool n) := KECCAK  448 (M ‖ hashSuffix) 224
def SHA3_256 {n} (M : Vector Bool n) := KECCAK  512 (M ‖ hashSuffix) 256
def SHA3_384 {n} (M : Vector Bool n) := KECCAK  768 (M ‖ hashSuffix) 384
def SHA3_512 {n} (M : Vector Bool n) := KECCAK 1024 (M ‖ hashSuffix) 512


/-! ## Alternate Definitions (§6.3)

RawSHAKE128(J, d) = KECCAK[256](J || 11, d)
RawSHAKE256(J, d) = KECCAK[512](J || 11, d)
The suffix 11 supports domain separation and Sakura compatibility. -/

-- rawSuffix = FIPS "11": bit 0 = 1, bit 1 = 1 (LSB-first)
def rawSuffix : Vector Bool 2 := #v[1, 1]

def RawSHAKE128 {n} (J : Vector Bool n) (d : Nat) := KECCAK 256 (J ‖ rawSuffix) d
def RawSHAKE256 {n} (J : Vector Bool n) (d : Nat) := KECCAK 512 (J ‖ rawSuffix) d


/-! ## SHA-3 Extendable-Output Functions (§6.2)

SHAKE128(M, d) = KECCAK[256](M || 1111, d)
SHAKE256(M, d) = KECCAK[512](M || 1111, d)
Equivalently (§6.3): SHAKE(M, d) = RawSHAKE(M || 11, d).
The four-bit suffix 1111 = 11 || 11. -/

-- xofSuffix = FIPS "1111": all four bits 1 (LSB-first)
def xofSuffix : Vector Bool 4 := #v[1, 1, 1, 1]

def SHAKE128 {n} (M : Vector Bool n) (d : Nat) : Vector Bool d := KECCAK 256 (M ‖ xofSuffix) d
def SHAKE256 {n} (M : Vector Bool n) (d : Nat) : Vector Bool d := KECCAK 512 (M ‖ xofSuffix) d


/-! ## Byte-Level Interface

Convert between `𝔹 n` (byte vectors) and `Vector Bool (8*n)`.
Uses `bytesToBits`/`bitsToBytes` from `Spec.Defs` — the SHA-3
LSB-first bit ordering within bytes (§B.1) matches FIPS 203 Algorithms 3–4. -/

def sha3_224 {n} (msg : 𝔹 n) : 𝔹 28 := bitsToBytes (SHA3_224 (bytesToBits msg))
def sha3_256 {n} (msg : 𝔹 n) : 𝔹 32 := bitsToBytes (SHA3_256 (bytesToBits msg))
def sha3_384 {n} (msg : 𝔹 n) : 𝔹 48 := bitsToBytes (SHA3_384 (bytesToBits msg))
def sha3_512 {n} (msg : 𝔹 n) : 𝔹 64 := bitsToBytes (SHA3_512 (bytesToBits msg))

def shake128 {n} (msg : 𝔹 n) length : 𝔹 length  :=
  bitsToBytes (SHAKE128 (bytesToBits msg) (8 * length))

def shake256 {n} (msg : 𝔹 n) length : 𝔹 length :=
  bitsToBytes (SHAKE256 (bytesToBits msg) (8 * length))

end Spec.SHA3
