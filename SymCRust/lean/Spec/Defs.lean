import Mathlib.Data.List.Defs
import Mathlib.Data.ZMod.Defs
import Aeneas

/-!
# Shared Infrastructure

Common definitions and notations used across all algorithm specifications.
Algorithm-specific content lives in its own subdirectory.
-/

namespace Spec

/-- Rotate a vector at the index level: output[i] = input[(i + n - k) % n].
    Used by FIPS 202 (SHA-3) where index 0 is the least significant bit.
    For big-endian contexts (index 0 = MSB), use `Bits.rotlBE`. -/
def _root_.Vector.rotateLeft (v : Vector α n) (k : Nat) : Vector α n :=
  if h : n = 0 then v
  else Vector.ofFn fun (i : Fin n) => v[(i.val + n - k % n) % n]'(Nat.mod_lt _ (by omega))

open Aeneas.Notations.SRRange
open Aeneas.Notations.DivRange
open Aeneas.Notations.MulRange

namespace Notations

  -- Crypto standards universally write 0 and 1 for boolean values.
  -- These instances let us match that convention in Lean.
  scoped instance : OfNat Bool 0 := ⟨false⟩
  scoped instance : OfNat Bool 1 := ⟨true⟩

  scoped macro_rules
  | `(tactic| get_elem_tactic) => `(tactic| grind)

  -- Standards write X || Y for concatenation; ‖ is the Unicode equivalent.
  -- Vector.append already places the first argument at lower indices,
  -- matching the standard convention.
  scoped infixl:65 " ‖ " => Vector.append

  @[scoped grind =]
  theorem mem_std_range_step_one (x n0 n1 : Nat) :
    x ∈ [n0:n1] ↔ (n0 ≤ x ∧ x < n1) := by
    simp only [Membership.mem, Nat.mod_one, and_true]

  /-- Extract upper bound from SRRange membership `i ∈ [0 : m]`. -/
  theorem srrange_lt {i m : ℕ} (h : i ∈ [0 : m]) : i < m := by
    simp [Membership.mem] at h; exact h.1

end Notations

open Notations

abbrev 𝔹 := Vector Byte

/-! ## Byte-Vector Arithmetic

Operations on `𝔹 n` (big-endian byte vectors) used as fixed-width words across
multiple algorithms (SHA-2, AES-GCM, etc.). All operations interpret byte 0 as
the most significant byte. -/

/-- Interpret a byte vector as a big-endian natural number. -/
def 𝔹.toNatBE (v : 𝔹 n) : Nat :=
  v.foldl (fun acc b => acc * 256 + b.toNat) 0

/-- Encode a natural number as a big-endian byte vector (truncates mod 2^(8n)). -/
def 𝔹.ofNatBE {n : Nat} (val : Nat) : 𝔹 n :=
  Vector.ofFn fun (i : Fin n) => ((val >>> (8 * (n - 1 - i.val))) : Byte)

namespace Notations

  /-- Interpret a hex/decimal literal as a big-endian byte vector. -/
  scoped instance (priority := low) : OfNat (𝔹 n) k := ⟨𝔹.ofNatBE k⟩

  /-- Big-endian modular addition: (a + b) mod 2^(8n). -/
  scoped instance : HAdd (𝔹 n) (𝔹 n) (𝔹 n) :=
    ⟨fun a b => 𝔹.ofNatBE ((a.toNatBE + b.toNatBE) % 2^(8*n))⟩

  instance : HXor (𝔹 n) (𝔹 n) (𝔹 n) := ⟨Vector.zipWith (· ^^^ ·)⟩
  instance : HAnd (𝔹 n) (𝔹 n) (𝔹 n) := ⟨Vector.zipWith (· &&& ·)⟩
  instance : Complement (𝔹 n) := ⟨Vector.map (~~~ ·)⟩

  /-- Big-endian logical right shift (zero-fill from MSB side). -/
  instance : HShiftRight (𝔹 n) Nat (𝔹 n) :=
    ⟨fun x k => 𝔹.ofNatBE (x.toNatBE >>> k)⟩

end Notations

open Notations

/-- Big-endian right rotation by `k` bits. -/
def 𝔹.rotrBE (x : 𝔹 n) (k : Nat) : 𝔹 n :=
  if n = 0 then x
  else
    let bits := 8 * n
    let k := k % bits
    let v := x.toNatBE
    𝔹.ofNatBE (((v >>> k) ||| (v <<< (bits - k))) % (2 ^ bits))

/-! ## Bit-Vector Arithmetic

Operations on `Vector Bool n` (bit strings, MSB-first: index 0 = most significant bit)
used by algorithms that operate at the bit level (GF(2^128), SHA-2 words, etc.).
All operations interpret bit 0 as the most significant bit, matching the convention
of NIST SP 800-38D and FIPS 180-4. -/

/-- Interpret a bit vector as a big-endian natural number (bit 0 = MSB). -/
def Bits.toNatBE (v : Vector Bool n) : Nat :=
  v.foldl (fun acc b => acc * 2 + b.toNat) 0

/-- Encode a natural number as a big-endian bit vector (truncates mod 2^n). -/
def Bits.ofNatBE {n : Nat} (val : Nat) : Vector Bool n :=
  Vector.ofFn fun (i : Fin n) => (val >>> (n - 1 - i.val)) % 2 != 0

namespace Notations

  /-- Interpret a hex/decimal literal as a big-endian bit vector. -/
  scoped instance (priority := low) : OfNat (Vector Bool n) k := ⟨Bits.ofNatBE k⟩

  /-- Bitwise XOR on bit vectors. -/
  scoped instance : HXor (Vector Bool n) (Vector Bool n) (Vector Bool n) :=
    ⟨Vector.zipWith (· != ·)⟩

  /-- Bitwise AND on bit vectors. -/
  scoped instance : HAnd (Vector Bool n) (Vector Bool n) (Vector Bool n) :=
    ⟨Vector.zipWith (· && ·)⟩

  /-- Bitwise OR on bit vectors. -/
  scoped instance : HOr (Vector Bool n) (Vector Bool n) (Vector Bool n) :=
    ⟨Vector.zipWith (· || ·)⟩

  /-- Bitwise complement on bit vectors. -/
  scoped instance : Complement (Vector Bool n) := ⟨Vector.map (!·)⟩

  /-- Big-endian modular addition on bit vectors: (a + b) mod 2^n. -/
  scoped instance : HAdd (Vector Bool n) (Vector Bool n) (Vector Bool n) :=
    ⟨fun a b => Bits.ofNatBE ((Bits.toNatBE a + Bits.toNatBE b) % 2^n)⟩

  /-- Big-endian logical right shift on bit vectors (zero-fill from MSB side). -/
  scoped instance : HShiftRight (Vector Bool n) Nat (Vector Bool n) :=
    ⟨fun x k => Bits.ofNatBE (Bits.toNatBE x >>> k)⟩

end Notations

open Notations

/-! ## Bit-Vector Arithmetic Properties

Foundational facts about `Bits.toNatBE` / `Bits.ofNatBE` and the resulting
modular `+` on `Vector Bool n`.  Needed wherever spec-level proofs reassociate
the modular addition (e.g. SHA-NI bridge proofs that pre-sum `K + W` before
applying a SHA-256 round). -/

private theorem Bits.foldl_eq_toList_foldl {α n β} (init : β) (B : Vector α n)
    (f : β → α → β) : Vector.foldl f init B = B.toList.foldl f init := by
  rcases B with ⟨⟨L⟩, h⟩
  simp [Vector.foldl, Vector.toList]

/-- `Bits.toNatBE v < 2^n` for any `v : Vector Bool n`. -/
theorem Bits.toNatBE_lt {n} (v : Vector Bool n) : Bits.toNatBE v < 2^n := by
  unfold Bits.toNatBE
  rw [Bits.foldl_eq_toList_foldl]
  generalize hL : v.toList = L
  have hLn : L.length = n := by rw [← hL]; simp
  clear v hL
  subst hLn
  induction L using List.reverseRecOn with
  | nil => simp
  | append_singleton xs x ih =>
      simp only [List.foldl_append, List.length_append, List.length_singleton, List.foldl_cons,
                 List.foldl_nil, pow_succ]
      have hb : x.toNat ≤ 1 := by cases x <;> decide
      have hxs : List.foldl (fun acc b => acc * 2 + b.toNat) 0 xs < 2^xs.length := ih
      have hpow : 2^xs.length ≥ 1 := Nat.one_le_iff_ne_zero.mpr (by positivity)
      omega

private theorem Bits.toNatBE_succ_pop {n : Nat} (v : Vector Bool (n+1)) :
    Bits.toNatBE v
      = Bits.toNatBE ((v.take n).cast (Nat.min_eq_left (Nat.le_succ n))) * 2
        + v[n].toNat := by
  unfold Bits.toNatBE
  conv_lhs => rw [show v
        = ((v.take n).cast (Nat.min_eq_left (Nat.le_succ n))).push v[n] from by
    apply Vector.ext
    intro i hi
    simp [Vector.getElem_push]
    by_cases hin : i < n
    · simp [hin]
    · have : i = n := by omega
      simp [this]]
  rw [Vector.foldl_push]

private theorem Bits.testBit_two_mul_add_bool (x : Nat) (b : Bool) (p : Nat) (hp : p > 0) :
    (2 * x + b.toNat).testBit p = x.testBit (p - 1) := by
  rw [show p = (p - 1) + 1 from by omega]
  rw [Nat.testBit_add_one]
  rw [Nat.add_div_of_dvd_right (Dvd.intro x rfl)]
  rw [Nat.mul_div_cancel_left _ (by decide : (2:Nat) > 0)]
  cases b <;> simp

/-- The `p`-th BE bit of `Bits.toNatBE v` (for `p < n`) is `v[n - 1 - p]`. -/
theorem Bits.testBit_toNatBE_lt {n : Nat} (v : Vector Bool n) (p : Nat) (hp : p < n) :
    (Bits.toNatBE v).testBit p = v[n - 1 - p] := by
  induction n generalizing p with
  | zero => omega
  | succ k ih =>
    rw [Bits.toNatBE_succ_pop]
    rw [show Bits.toNatBE _ * 2 + v[k].toNat = 2 * (Bits.toNatBE _) + v[k].toNat from by ring]
    by_cases hp_zero : p = 0
    · subst hp_zero
      have h_idx : k + 1 - 1 - 0 = k := by omega
      simp only [h_idx, Nat.testBit_zero]
      have h2 : (2 * Bits.toNatBE
            ((v.take k).cast (Nat.min_eq_left (Nat.le_succ k))) + v[k].toNat) % 2
          = v[k].toNat := by
        cases v[k] <;> simp [Bool.toNat]
      rw [h2]
      cases v[k] <;> decide
    · have hp_pos : 0 < p := by omega
      rw [Bits.testBit_two_mul_add_bool _ _ _ hp_pos]
      have ih_app := ih ((v.take k).cast (Nat.min_eq_left (Nat.le_succ k)))
        (p - 1) (by omega)
      rw [ih_app]
      simp only [Vector.getElem_cast, Vector.getElem_take]
      have heq : k - 1 - (p - 1) = k + 1 - 1 - p := by omega
      simp only [heq]

/-- `Bits.toNatBE` is the left-inverse of `Bits.ofNatBE` modulo `2^n`. -/
theorem Bits.toNatBE_ofNatBE_mod {n : Nat} (x : Nat) :
    Bits.toNatBE (Bits.ofNatBE x : Vector Bool n) = x % 2^n := by
  apply Nat.eq_of_testBit_eq
  intro p
  by_cases hp : p < n
  · rw [Bits.testBit_toNatBE_lt _ _ hp]
    unfold Bits.ofNatBE
    have hidx : n - 1 - p < n := by omega
    rw [Vector.getElem_ofFn]
    have h_inner : n - 1 - (⟨n - 1 - p, hidx⟩ : Fin n).val = p := by simp; omega
    rw [h_inner]
    rw [Nat.testBit_mod_two_pow]
    simp [hp, Nat.testBit, Nat.shiftRight_eq_div_pow]
  · push Not at hp
    have hbnd : Bits.toNatBE (Bits.ofNatBE x : Vector Bool n) < 2^n := Bits.toNatBE_lt _
    have hmodbnd : x % 2^n < 2^n := Nat.mod_lt _ (Nat.two_pow_pos n)
    have hpow_le : 2^n ≤ 2^p := Nat.pow_le_pow_right (by decide) hp
    rw [Nat.testBit_eq_false_of_lt
        (by omega : Bits.toNatBE (Bits.ofNatBE x : Vector Bool n) < 2^p)]
    rw [Nat.testBit_eq_false_of_lt (by omega : x % 2^n < 2^p)]

/-- Modular addition on `Vector Bool n` is associative.  This is *not*
    definitional — it routes through `Bits.toNatBE_ofNatBE_mod` and
    `Nat.add_assoc`. -/
theorem Bits.add_assoc {n} (a b c : Vector Bool n) :
    a + b + c = a + (b + c) := by
  show Bits.ofNatBE _ = Bits.ofNatBE _
  congr 1
  show ((Bits.toNatBE (Bits.ofNatBE ((Bits.toNatBE a + Bits.toNatBE b) % 2^n) :
          Vector Bool n)) + Bits.toNatBE c) % 2^n
       = (Bits.toNatBE a +
          (Bits.toNatBE (Bits.ofNatBE ((Bits.toNatBE b + Bits.toNatBE c) % 2^n) :
              Vector Bool n))) % 2^n
  rw [Bits.toNatBE_ofNatBE_mod, Bits.toNatBE_ofNatBE_mod]
  conv_lhs => rw [Nat.add_mod]
  conv_rhs => rw [Nat.add_mod]
  simp [Nat.add_assoc]

/-- Modular addition on `Vector Bool n` is commutative. -/
theorem Bits.add_comm {n} (a b : Vector Bool n) : a + b = b + a := by
  show Bits.ofNatBE _ = Bits.ofNatBE _
  congr 1
  rw [Nat.add_comm]

/-- Bitwise XOR on `Vector Bool n` is associative.  Definitional once both
    sides are pushed through `Vector.getElem_zipWith`. -/
theorem Bits.xor_assoc {n} (a b c : Vector Bool n) :
    a ^^^ b ^^^ c = a ^^^ (b ^^^ c) := by
  apply Vector.ext
  intro i hi
  simp [HXor.hXor, Vector.getElem_zipWith]

/-- Big-endian right rotation by `k` positions on a bit vector. -/
def Bits.rotrBE (x : Vector Bool n) (k : Nat) : Vector Bool n :=
  if n = 0 then x
  else
    let k := k % n
    let v := Bits.toNatBE x
    Bits.ofNatBE (((v >>> k) ||| (v <<< (n - k))) % (2 ^ n))

/-- Big-endian left rotation by `k` positions on a bit vector. -/
def Bits.rotlBE (x : Vector Bool n) (k : Nat) : Vector Bool n :=
  Bits.rotrBE x (n - k % n)

/-- Access bit `i` (MSB-first numbering: bit 0 = most significant).
    Equivalent to `v[i]` but provided for documentation clarity. -/
@[inline] def Bits.bit (v : Vector Bool n) (i : Nat) (h : i < n := by grind) : Bool := v[i]

/-- The least significant bit (rightmost, index n-1). -/
@[inline] def Bits.lsb (v : Vector Bool n) (h : 0 < n := by grind) : Bool := v[n - 1]

/-! ## General Bit-Vector Helpers

Operations on `Vector Bool n` that are independent of endianness (pure index-level). -/

/-- Zero-extend a bit vector to `m` bits (pad with `false` at higher indices). -/
def Bits.zeroExtend (v : Vector Bool n) (m : Nat) : Vector Bool m :=
  Vector.ofFn fun (i : Fin m) => if h : i.val < n then v[i.val] else false

abbrev Bits.rotateLeft := @Vector.rotateLeft Bool

/-! ## LSB-First Bit-Vector Operations

Operations on `Vector Bool n` with LSB-first indexing (index 0 = least significant bit).
Used by FIPS 202 (SHA-3), where lane bit z=0 is the LSB.

Note: The `Vector Bool` type itself is index-agnostic. These functions interpret
index 0 as the LSB; the big-endian functions above interpret index 0 as the MSB.
Algorithms should use one convention consistently; SHA-2 uses big-endian (Bits.ofNatBE),
SHA-3 uses little-endian (Bits.ofNatLE). -/

/-- Interpret a bit vector as a little-endian natural number (bit 0 = LSB). -/
def Bits.toNatLE (v : Vector Bool n) : Nat :=
  Fin.foldl n (fun acc (i : Fin n) => acc + v[i].toNat * 2 ^ i.val) 0

/-- Encode a natural number as a little-endian bit vector (truncates mod 2^n). -/
def Bits.ofNatLE {n : Nat} (val : Nat) : Vector Bool n :=
  Vector.ofFn fun (i : Fin n) => (val >>> i.val) % 2 != 0

/-! ## Byte ↔ Bit Conversions (FIPS 203, Algorithms 3 & 4)

These are defined in the ML-KEM standard but used as shared infrastructure
by multiple algorithms (ML-KEM, FrodoKEM, etc.). -/

/-- Algorithm 3 (FIPS 203): convert a bit vector to a byte vector.
    Pure `Vector.ofFn` version — each byte is accumulated locally. -/
def bitsToBytes {ℓ : Nat} (b : Vector Bool (8 * ℓ)) : 𝔹 ℓ :=
  Vector.ofFn fun ⟨i, _⟩ =>
    Fin.foldl 8 (fun (acc : Byte) (j : Fin 8) =>
      acc + b[8 * i + j.val].toNat * (2 ^ j.val)) 0

/-- Algorithm 3 — original imperative version (FIPS 203, line-by-line). -/
def bitsToBytes_alg3 {ℓ : Nat} (b : Vector Bool (8 * ℓ)) : 𝔹 ℓ := Id.run do
  let mut B := Vector.replicate ℓ 0
  for h: i in [0:8*ℓ] do
    B := B.set (i/8) (B[i/8] + (b[i].toNat * (2 ^(i%8)) : Byte))
  pure B

/-- Algorithm 4 (FIPS 203): convert a byte vector to a bit vector.
    Pure `Vector.ofFn` version — each bit is extracted via `Nat.testBit`. -/
def bytesToBits {ℓ : Nat} (B : 𝔹 ℓ) : Vector Bool (8 * ℓ) :=
  Vector.ofFn fun ⟨i, _⟩ => B[i / 8].toNat.testBit (i % 8)

/-- Algorithm 4 — original imperative version (FIPS 203, line-by-line). -/
def bytesToBits_alg4 {ℓ : Nat} (B : 𝔹 ℓ) : Vector Bool (8 * ℓ) := Id.run do
  let mut C := B
  let mut b := Vector.replicate (8 * ℓ) false
  for hi: i in [0:ℓ] do
    for hj: j in [0:8] do
      b := b.set (8 * i + j) (C[i] % 2 ≠ 0)
      C := C.set i (C[i] / 2)
  pure b

/-! ### Byte ↔ Bit helpers and round-trip theorems -/

/-- Two bytes are equal iff they agree on all 8 test bits. -/
theorem Byte.ext_testBit (a b : Byte)
    (h : ∀ j < 8, a.toNat.testBit j = b.toNat.testBit j) : a = b := by
  apply BitVec.eq_of_toNat_eq
  apply Nat.eq_of_testBit_eq
  intro i
  by_cases hi : i < 8
  · exact h i hi
  · have hi8 : 8 ≤ i := Nat.le_of_not_lt hi
    have ha : a.toNat < 2 ^ i :=
      calc a.toNat < 2 ^ 8 := a.isLt
        _ ≤ 2 ^ i := Nat.pow_le_pow_right (by norm_num) hi8
    have hb : b.toNat < 2 ^ i :=
      calc b.toNat < 2 ^ 8 := b.isLt
        _ ≤ 2 ^ i := Nat.pow_le_pow_right (by norm_num) hi8
    rw [Nat.testBit_eq_false_of_lt ha, Nat.testBit_eq_false_of_lt hb]

private theorem testBit_byte_of_bools (f : Fin 8 → Bool) (k : Fin 8) :
    (Fin.foldl 8 (fun (acc : Byte) (j : Fin 8) =>
      acc + (f j).toNat * (2 ^ j.val)) 0).toNat.testBit k.val = f k := by
  native_decide +revert

private theorem byte_of_testBits (b : Byte) :
    Fin.foldl 8 (fun (acc : Byte) (j : Fin 8) =>
      acc + (b.toNat.testBit j.val).toNat * (2 ^ j.val)) 0 = b := by
  native_decide +revert

/-- Each bit of the pure `bitsToBytes` output matches the input. -/
theorem bitsToBytes_testBit {ℓ : Nat} (b : Vector Bool (8 * ℓ))
    (i : Nat) (hi : i < ℓ) (j : Nat) (hj : j < 8) :
    (bitsToBytes b)[i].toNat.testBit j = b[8 * i + j] := by
  simp only [bitsToBytes, Vector.getElem_ofFn]
  exact testBit_byte_of_bools (fun k => b[8 * i + k.val]) ⟨j, hj⟩

/-- Round-trip: `bytesToBits (bitsToBytes b) = b`. -/
theorem bytesToBits_bitsToBytes {ℓ : Nat} (b : Vector Bool (8 * ℓ)) :
    bytesToBits (bitsToBytes b) = b := by
  apply Vector.ext
  intro i hi
  simp only [bytesToBits, bitsToBytes, Vector.getElem_ofFn]
  have h8 : i % 8 < 8 := Nat.mod_lt i (by decide)
  have hd : i / 8 < ℓ := Nat.div_lt_of_lt_mul (by linarith [Nat.mul_comm 8 ℓ])
  have key := testBit_byte_of_bools (fun j => b[8 * (i / 8) + j.val]) ⟨i % 8, h8⟩
  simp only at key
  have heq : 8 * (i / 8) + i % 8 = i := Nat.div_add_mod i 8
  simp only [heq] at key
  exact key

/-- Round-trip: `bitsToBytes (bytesToBits B) = B`. -/
theorem bitsToBytes_bytesToBits {ℓ : Nat} (B : 𝔹 ℓ) :
    bitsToBytes (bytesToBits B) = B := by
  apply Vector.ext
  intro i hi
  simp only [bitsToBytes, bytesToBits, Vector.getElem_ofFn]
  have key : ∀ (j : Fin 8),
      B[(8 * i + ↑j) / 8].toNat.testBit ((8 * i + ↑j) % 8) =
      B[i].toNat.testBit ↑j := by
    intro ⟨j, hj⟩
    simp only
    have h1 : (8 * i + j) / 8 = i := by omega
    have h2 : (8 * i + j) % 8 = j := by omega
    simp [h1, h2]
  convert byte_of_testBits B[i] using 2
  funext acc j
  simp only [key j]

/-- `bytesToBits` distributes over `Vector.append` (modulo ring-cast on
the length).  Used to bridge byte-level concatenation in the impl with
bit-level concatenation in the spec. -/
theorem bytesToBits_append {m n : Nat} (a : 𝔹 m) (b : 𝔹 n) :
    bytesToBits (a ++ b) = (bytesToBits a ++ bytesToBits b).cast (by ring) := by
  apply Vector.ext
  intro i hi
  simp only [bytesToBits, Vector.getElem_ofFn, Vector.getElem_cast,
    Vector.getElem_append]
  by_cases hilt : i < 8 * m
  · simp only [hilt, ↓reduceDIte]
    have h_div : i / 8 < m := by omega
    simp only [h_div, ↓reduceDIte]
  · simp only [hilt, ↓reduceDIte]
    have h_div : ¬ i / 8 < m := by omega
    simp only [h_div, ↓reduceDIte]
    have h_div2 : i / 8 - m = (i - 8 * m) / 8 := by omega
    have h_mod : i % 8 = (i - 8 * m) % 8 := by omega
    rw [h_mod]
    congr 1
    apply congrArg
    exact getElem_congr rfl h_div2 (by omega)

/-! ### Big-Endian Byte ↔ Bit Conversions (FIPS 180-4 §3.1)

SHA-2 and AES-GCM use MSB-first (big-endian) bit ordering: byte 0's MSB is bit 0.
This is the opposite of the FIPS 203 LSB-first convention used by `bytesToBits`
and `bitsToBytes` above. These conversions compose `𝔹.toNatBE`/`𝔹.ofNatBE` with
`Bits.toNatBE`/`Bits.ofNatBE`. -/

/-- Convert a byte vector to a big-endian bit vector (byte 0 MSB = bit 0). -/
def bytesToBitsBE {n : Nat} (B : 𝔹 n) : Vector Bool (8 * n) :=
  Bits.ofNatBE (𝔹.toNatBE B)

/-- Convert a big-endian bit vector to a byte vector (bit 0 = byte 0 MSB). -/
def bitsToByteBE {n : Nat} (b : Vector Bool (8 * n)) : 𝔹 n :=
  𝔹.ofNatBE (Bits.toNatBE b)

/-- Extract `len` elements from `v` starting at offset `off`.
    Works uniformly for `𝔹 n` (byte vectors) and `Vector Bool n` (bit vectors). -/
def slice {n : ℕ} (v : Vector α n) (off len : ℕ) (h : off + len ≤ n := by grind) : Vector α len :=
  Vector.ofFn fun i => v[off + i]

/-- Split `n` consecutive slices of `s` bytes starting at `off`. -/
def slices {m : ℕ} (v : 𝔹 m) (off s n : ℕ) (h : off + s * n ≤ m := by grind) : Vector (𝔹 s) n :=
  Vector.ofFn fun i => Vector.ofFn fun j =>
    v[off + s * i.val + j.val]'(by
      have h1 : off + s * i.val + j.val < off + (s * i.val + s) := by omega
      have h2 : s * i.val + s ≤ s * n := Nat.mul_le_mul_left s i.isLt
      omega)

end Spec
