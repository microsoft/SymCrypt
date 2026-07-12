import Spec.Defs

/-!
# AES (Advanced Encryption Standard)

Based on: FIPS 197-upd1: Advanced Encryption Standard (AES)
URL: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf

All algorithm, section, and equation references are to FIPS 197-upd1.

## Mechanization notes

- **Naming convention.** FIPS 197 uses ALL CAPS function names (SUBBYTES, CIPHER, etc.).
  Lean convention is camelCase, so we write `subBytes`, `cipher`, etc. throughout.
  Two functions are additionally renamed for clarity at the byte level:
  `SBOX` → `subByte` (byte-level S-box) and `INVSBOX` → `invSubByte`.
- **Parameter order.** `addRoundKey` takes `(w, state, round)` rather than the standard's
  `(state, w[4*round..4*round+3])`, placing the key schedule first as is natural in Lean
  (it is the "environment"; the state is the "input").
- **Nb = 4 always.** FIPS 197 defines Nb (number of state columns) but fixes it to 4 for all
  AES variants. We do not introduce a named constant for Nb; the value 4 appears directly
  in `State := Vector Word 4` and related definitions.
- **Nr implicit.** `cipher`, `invCipher`, and `eqInvCipher` receive Nr implicitly via the
  `Params` type class rather than as an explicit parameter.
- **`keyExpansionEIC` signature.** FIPS 197 Algorithm 5 takes a raw key and internally calls
  KEYEXPANSION. Our `keyExpansionEIC` takes a pre-expanded `KeySchedule` and applies only
  the INVMIXCOLUMNS post-processing (lines 19–21 of Algorithm 5). The composition
  `keyExpansionEIC (keyExpansion key)` recovers the full Algorithm 5 behavior.
- **`invSubByte` formula.** FIPS 197 defines INVSBOX only via Table 6 (the inverse lookup
  table). We define `invSubByte` algebraically using the inverse affine transformation from
  the Rijndael proposal [Daemen & Rijmen, 1999]. The equivalence with Table 6 is verified
  in `Properties.lean` via `INVSBOX_correct`.
- Properties, examples, and test vectors are in auxiliary files under `AES/`.
-/

namespace Spec.AES

open Spec (𝔹)
open Aeneas.Notations.SRRange
open Notations

/-! ## §3 Types and Abbreviations -/

/-- The AES Block: 128-bit (16 bytes). -/
abbrev Block := 𝔹 16

/-- A 4-byte word (§3.3). -/
abbrev Word := 𝔹 4

/-- The AES internal state: 4 columns, each a Word (4×4 byte matrix, column-major).
    `state[c][r]` = byte at row r of column c. (§3.4) -/
abbrev State := Vector Word 4

/-- State ↔ Block conversions (§3.4).
    Input bytes a[0..15] fill the state column-major: `state[c][r] = a[4c+r]`.  -/
def blockToState (a : Block) : State :=
  Vector.ofFn fun c => Vector.ofFn fun r => a[4 * c.val + r.val]

/-- Inverse of `blockToState`: `a[4c+r] = state[c][r]`. (§3.4) -/
def stateToBlock (s : State) : Block :=
  Vector.ofFn fun i => s[i / 4][i % 4]


/-! ## GF(2^8) arithmetic (§4) -/

-- ⊕ denotes XOR in GF(2) and GF(2^8) (§2.3)
scoped notation:65 a " ⊕ " b => a ^^^ b

-- Lift ⊕ to Word and State (element-wise)
instance : HXor Word Word Word := ⟨fun w₁ w₂ => Vector.ofFn fun i => w₁[i] ⊕ w₂[i]⟩
instance : HXor State State State := ⟨fun s₁ s₂ => Vector.ofFn fun c => s₁[c] ⊕ s₂[c]⟩

/-- XTIMES(b): multiply by {02} = x in GF(2^8)/m(x).  (§4.2, Eq. 4.5) -/
def xTimes (b : Byte) : Byte :=
  let shifted := b <<< 1
  if b.getLsbD 7 then shifted ⊕ 0b00011011 else shifted

/-- Multiply a and b in GF(2^8) via repeated doubling.  (§4.2) -/
def mulGF (a b : Byte) : Byte := Id.run do
  let mut r : Byte := 0
  let mut x := a
  for i in [0:8] do
    if b.getLsbD i then r := r ⊕ x
    x := xTimes x
  pure r

-- ∙ denotes GF(2^8) multiplication (§4.2, "•" notation)
scoped infix:70 " ∙ " => mulGF

/-- Multiplicative inverse in GF(2^8): b^{254} (since every nonzero element has order dividing 255).
    Returns 0 for the input 0 (§4.4). -/
def powGF : Byte → ℕ → Byte
  | _, 0     => 1
  | a, n + 1 =>
    let half := powGF a ((n + 1) / 2)
    let sq   := half ∙ half
    if (n + 1) % 2 = 0 then sq else sq ∙ a

private def invGF (a : Byte) : Byte := if a = 0 then 0 else powGF a 254

instance : Inv Byte := ⟨invGF⟩


/-! ## §5 Algorithm Strength (Nk, Nr) -/

/-- AES parameter set: exactly the three strengths from FIPS 197, §5, Table 3. -/
inductive Params where
  | aes128
  | aes192
  | aes256

/-- Key length in 32-bit words. (§5, Table 3) -/
def Params.Nk : Params → ℕ | .aes128 => 4 | .aes192 => 6 | .aes256 => 8

/-- Number of cipher rounds. (§5, Table 3) -/
def Params.Nr : Params → ℕ | .aes128 => 10 | .aes192 => 12 | .aes256 => 14

/-- The AES key: `4*Nk` bytes (16 for AES-128, 24 for AES-192, 32 for AES-256). (§5, Table 3) -/
abbrev Key (p : Params) := 𝔹 (4 * p.Nk)

/-- AES expanded key schedule: `4*(Nr+1)` words, indexed by parameter set. (§5.2) -/
abbrev KeySchedule (p : Params) := Vector Word (4 * (p.Nr + 1))

/- Grind needs to bridge `i < p.Nk` → `i < 4*(p.Nr+1)` and `i < 4*(p.Nr+1)` → `i/p.Nk < 11`
   across the opaque `Params` function calls.  After `cases p` all values are concrete. -/
private theorem Params.lt_schedLen {p : Params} {i : Nat} (h : i < p.Nk) :
    i < 4 * (p.Nr + 1) := by cases p <;> simp_all [Params.Nk, Params.Nr] <;> grind

local grind_pattern Params.lt_schedLen => i < p.Nk

private theorem Params.rconIdx_lt {p : Params} {i : Nat} (h : i < 4 * (p.Nr + 1)) :
    i / p.Nk < 11 := by cases p <;> simp_all [Params.Nk, Params.Nr] <;> grind

local grind_pattern Params.rconIdx_lt => i < 4 * (p.Nr + 1)

private theorem Params.schedIdx_lt {p : Params} {round c : Nat}
    (hr : round < p.Nr) (hc : c < 4) :
    4 * round + c < 4 * (p.Nr + 1) := by cases p <;> simp_all [Params.Nr] <;> omega

local grind_pattern Params.schedIdx_lt => round < p.Nr, c < 4


/-! ## S-box and inverse S-box (§5.1.1, §5.3.2) -/

/-- SUBBYTE(b): apply the AES S-box to a single byte.
    b' = affine(inv(b)) where affine applies Eq. (5.3):
    `b'_i = b~_i ⊕ b~_{(i+4) mod 8} ⊕ b~_{(i+5) mod 8} ⊕ b~_{(i+6) mod 8} ⊕ b~_{(i+7) mod 8} ⊕ c_i`
    with c = {01100011}. (§5.1.1, Eq. 5.3) -/
def subByte (b : Byte) :=
  let i := b⁻¹
  i ⊕ i.rotateRight 4 ⊕ i.rotateRight 5 ⊕ i.rotateRight 6 ⊕ i.rotateRight 7 ⊕ 0b01100011

/-- INVSUBBYTE(b): apply the inverse S-box to a single byte.
    b~ = (invAffine(b))⁻¹ where invAffine is the inverse of the affine transformation
    in Eq. (5.3). (§5.3.2; inverse affine formula from Rijndael proposal §4.2.1) -/
def invSubByte (b : Byte) :=
  (b.rotateRight 2 ⊕ b.rotateRight 5 ⊕ b.rotateRight 7 ⊕ 0b00000101)⁻¹


/-! ## §5.1, §5.3 State transformations -/

/-- SUBBYTES: apply SUBBYTE to every byte in the state. (§5.1.1) -/
def subBytes (s : State) : State := s.map (·.map subByte)

/-- INVSUBBYTES: apply INVSUBBYTE to every byte in the state. (§5.3.2) -/
def invSubBytes (s : State) : State := s.map (·.map invSubByte)

/-- SHIFTROWS: cyclically shift row r by r positions to the left. (§5.1.2)
    `s'[r][c] = s[r][(c+r) mod 4]`, or in column-major: `state'[c][r] = state[(c.val+r.val) mod 4][r]`. -/
def shiftRows (s : State) : State :=
  Vector.ofFn fun c => Vector.ofFn fun r => s[c + r][r]

/-- INVSHIFTROWS: cyclically shift row r by r positions to the right. (§5.3.1)
    `s'[r][c] = s[r][(c-r) mod 4]`, or: `state'[c][r] = state[(c + 4 - r) % 4][r]`. -/
def invShiftRows (s : State) : State :=
  Vector.ofFn fun c => Vector.ofFn fun r => s[c - r][r]

/-- MixColumns matrix (§5.1.3, Eq. 5.7). -/
def mcMatrix : State :=
  #v[ #v[0x02, 0x03, 0x01, 0x01],
      #v[0x01, 0x02, 0x03, 0x01],
      #v[0x01, 0x01, 0x02, 0x03],
      #v[0x03, 0x01, 0x01, 0x02] ]

/-- InvMixColumns matrix (§5.3.3, Eq. 5.14). -/
def imcMatrix : State :=
  #v[ #v[0x0e, 0x0b, 0x0d, 0x09],
      #v[0x09, 0x0e, 0x0b, 0x0d],
      #v[0x0d, 0x09, 0x0e, 0x0b],
      #v[0x0b, 0x0d, 0x09, 0x0e] ]

/-- Multiply a 4×4 GF(2^8) matrix `mat` (row-major) by a state `s` (column-major).
    `(matMulGF mat s)[c][r] = mat[r][0] ∙ s[c][0] ⊕ mat[r][1] ∙ s[c][1] ⊕ mat[r][2] ∙ s[c][2] ⊕ mat[r][3] ∙ s[c][3]`
    (§5.1.3, §5.3.3) -/
def matMulGF (mat : State) (s : State) : State :=
  Vector.ofFn fun c => Vector.ofFn fun r =>
    (Vector.ofFn (fun k => mat[r][k] ∙ s[c][k])).foldl (· ⊕ ·) 0

/-- MIXCOLUMNS: multiply each column of the state by the MixColumns matrix. (§5.1.3) -/
def mixColumns (s : State) : State := matMulGF mcMatrix s

/-- INVMIXCOLUMNS: multiply each column of the state by the InvMixColumns matrix. (§5.3.3) -/
def invMixColumns (s : State) : State := matMulGF imcMatrix s

/-- ADDROUNDKEY: XOR state columns with the corresponding key-schedule words.
    `state[c] = state[c] ⊕ w[4*round + c]` for c = 0..3.
    Precondition: `round ≤ Nr` ensures all key-schedule accesses are in bounds. (§5.1.4) -/
def addRoundKey (w : KeySchedule p) (s : State) round (h : round ≤ p.Nr := by grind) : State :=
  Vector.ofFn fun c => s[c] ⊕ w[4 * round + c]


/-! ## Key Expansion (§5.2) -/

/-- SUBWORD: apply SUBBYTE to each byte of a word. (§5.2) -/
def subWord (w : Word) := w.map subByte

/-- ROTWORD: cyclic byte shift [a₀, a₁, a₂, a₃] → [a₁, a₂, a₃, a₀]. (§5.2) -/
def rotWord (w : Word) := #v[w[1], w[2], w[3], w[0]]

/-- Round constants Rcon[j] = [x^{j-1}, {00}, {00}, {00}] for j = 1..10.
    Index 0 is a padding entry (never accessed). (§5.2) -/
def Rcon : Vector Word 11 :=
  Vector.ofFn fun i => #v[powGF 0x02 (i.val - 1), 0x00, 0x00, 0x00]

/-- KEYEXPANSION: expand a Nk-word key into 4*(Nr+1) words. (§5.2, Algorithm 2)
    ```
    for i = 0..Nk-1:  w[i] = key[4i..4i+3]
    for i = Nk..4(Nr+1)-1:
      temp = w[i-1]
      if i mod Nk = 0: temp = SUBWORD(ROTWORD(temp)) ⊕ Rcon[i/Nk]
      elif Nk > 6 and i mod Nk = 4: temp = SUBWORD(temp)
      w[i] = w[i-Nk] ⊕ temp
    ``` -/
def keyExpansion {p} (key : Key p) : KeySchedule p := Id.run do
  let mut w : KeySchedule p := Vector.replicate _ default
  -- The first Nk words come directly from the key (§5.2, line 1-2)
  for h : i in [0 : p.Nk] do
    w := w.set i (Vector.ofFn fun j => key[4 * i + j.val])
  -- The remaining words are scrambled from them (§5.2, line 3-8)
  for h : i in [p.Nk : 4 * (p.Nr + 1)] do
    let temp := w[i - 1]
    let temp :=
      if i % p.Nk = 0 then
        subWord (rotWord temp) ⊕ Rcon[i / p.Nk]
      else if p.Nk > 6 && i % p.Nk = 4 then
        subWord temp
      else
        temp
    w := w.set i (w[i - p.Nk] ⊕ temp)
  pure w


/-! ## §5.1, §5.3 Cipher and InvCipher -/

/-- CIPHER(in, Nr, w): AES encryption. (§5.1, Algorithm 1) -/
def cipher {p} (input : Block) (w : KeySchedule p) : Block :=
  Id.run do
    let mut state := blockToState input
    state := addRoundKey w state 0
    for h : round in [1 : p.Nr] do
      state := subBytes state
      state := shiftRows state
      state := mixColumns state
      state := addRoundKey w state round
    state := subBytes state
    state := shiftRows state
    state := addRoundKey w state p.Nr
    pure (stateToBlock state)

/-- INVCIPHER(in, Nr, w): AES decryption. (§5.3, Algorithm 3) -/
def invCipher {p} (input : Block) (w : KeySchedule p) : Block :=
  Id.run do
    let mut state := blockToState input
    state := addRoundKey w state p.Nr
    for h : round in [1 : p.Nr] do
      state := invShiftRows state
      state := invSubBytes state
      state := addRoundKey w state (p.Nr - round)
      state := invMixColumns state
    state := invShiftRows state
    state := invSubBytes state
    state := addRoundKey w state 0
    pure (stateToBlock state)


/-! ## §5 Top-level AES encrypt / decrypt -/

/-- AES-encrypt a 16-byte plaintext block under a key of the appropriate length. -/
def encrypt {p} (key : Key p) (plain : Block) : Block :=
  cipher plain (keyExpansion key)

/-- AES-decrypt a 16-byte ciphertext block under a key of the appropriate length. -/
def decrypt {p} (key : Key p) (ct : Block) : Block :=
  invCipher ct (keyExpansion key)


/-! ## §5.4 Equivalent Inverse Cipher -/

/-- KEYEXPANSIONEIC: extend the standard key schedule for the equivalent inverse cipher.
    Rounds 0 and Nr are left unchanged; intermediate round keys (1 through Nr−1) are
    passed through INVMIXCOLUMNS, with the word array interpreted as a state (§5.4, Algorithm 5).
    ```
    dw ← KEYEXPANSION(key)
    for round from 1 to Nr − 1 do
      dw[4*round..4*round+3] ← INVMIXCOLUMNS(dw[4*round..4*round+3])
    end for
    ``` -/
def keyExpansionEIC {p} (w : KeySchedule p) : KeySchedule p := Id.run do
  let mut dw := w
  for h : round in [1 : p.Nr] do
    let rk : State := Vector.ofFn fun c => dw[4 * round + c.val]
    let rk' := invMixColumns rk
    for hc : c in [0:4] do
      dw := dw.set (4 * round + c) rk'[c]
  pure dw

/-- EQINVCIPHER(in, Nr, dw): equivalent inverse cipher. (§5.4, Algorithm 4)
    ```
    state ← ADDROUNDKEY(state, dw[4*Nr..4*Nr+3])
    for round from Nr−1 downto 1 do
      state ← INVSUBBYTES(state)
      state ← INVSHIFTROWS(state)
      state ← INVMIXCOLUMNS(state)
      state ← ADDROUNDKEY(state, dw[4*round..4*round+3])
    end for
    state ← INVSUBBYTES(state)
    state ← INVSHIFTROWS(state)
    state ← ADDROUNDKEY(state, dw[0..3])
    ``` -/
def eqInvCipher {p} (input : Block) (dw : KeySchedule p) : Block :=
  Id.run do
    let mut state := blockToState input
    state := addRoundKey dw state p.Nr
    for h : round in [1 : p.Nr] do
      state := invSubBytes state
      state := invShiftRows state
      state := invMixColumns state
      state := addRoundKey dw state (p.Nr - round)
    state := invSubBytes state
    state := invShiftRows state
    state := addRoundKey dw state 0
    pure (stateToBlock state)


/-! ## §5.4 Top-level AES encrypt / decrypt (equivalent inverse cipher variant) -/

/-- AES-decrypt using the equivalent inverse cipher (§5.4). -/
def eqDecrypt {p} (key : Key p) (ct : Block) : Block :=
  eqInvCipher ct (keyExpansionEIC (keyExpansion key))

end Spec.AES
