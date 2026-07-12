import Spec.SHA3.Spec

/-!
# Properties of the SHA-3 specification (FIPS 202)

## Pure spec-level properties

1. KECCAK-f = KECCAK-p[1600, 24] (§3.4) — by definition.
2. Padding length ≥ 2 (§5.1).
3. Domain separation: hash and RawSHAKE suffixes are distinct (§6.1, §6.3).
4. ρ offsets table matches Algorithm 2 (§3.2.2).

## Spec-side helpers used by the code-verification bridge

This file collects spec-only properties of the FIPS 202 SHA-3 specification
that are reused by the code-verification proofs in `Properties/SHA3/`.

- `stringToState` ↔ `stateToString` round-trips (§3.1.2–3.1.3).
- Byte/bit access bridges for `bitsToBytes` / `bytesToBits` (Algorithms 3 & 4):
  point-wise characterizations that are awkward to derive from the
  `Fin.foldl` / `Nat.testBit` definitions.
- `SPONGE.squeeze` block-level characterization (`squeezeBlocks` +
  `SPONGE_squeeze_blocks` family): expresses the squeeze as a
  concatenation of whole r-bit rate blocks `Trunc r (f^[j] S)`.
-/

namespace Spec.SHA3

open scoped Spec.Notations

scoped macro_rules
| `(tactic| get_elem_tactic) => `(tactic| grind)

/-! ## Layer 0: Pure spec-level properties -/

theorem KECCAK_f_eq : KECCAK_f = KECCAK_p 24 := rfl

theorem padLen_ge_two (x m : Nat) : padLen x m ≥ 2 := by
  simp [padLen]

theorem hash_raw_suffixes_distinct : hashSuffix ≠ rawSuffix := by decide

/-! ## ρ offsets verification (§3.2.2, Table 2)

Table 2 of FIPS 202 lists the rotation offsets. We verify that the
algorithmic definition `ρ.Offsets` (from Algorithm 2) matches. -/

/-- Table 2 (§3.2.2): precomputed ρ rotation offsets. -/
def ρOffsetsTable2 : Vector (Vector Nat 5) 5 := #v[
  #v[  0,  36,   3, 105, 210],
  #v[  1, 300,  10,  45,  66],
  #v[190,   6, 171,  15, 253],
  #v[ 28,  55, 153,  21, 120],
  #v[ 91, 276, 231, 136,  78]]

/-- Algorithm 2 matches Table 2 (§3.2.2). -/
theorem rhoOffsets_eq_table2 : ρ.Offsets = ρOffsetsTable2 := by native_decide


/-! ## stringToState / stateToString round-trips

These are fundamental properties of the spec's state↔string conversions (§3.1.2–3.1.3).
They hold by elementary index arithmetic:
- lane index = i / w, x = lane % 5, y = lane / 5, z = i % w
- 5 * (lane / 5) + (lane % 5) = lane (division algorithm)
- w * (i / w) + (i % w) = i (division algorithm) -/

/-- Round-trip: `stringToState ∘ stateToString = id`. -/
theorem stringToState_stateToString (A : State) :
    stringToState (stateToString A) = A := by
  simp only [stringToState, stateToString]
  ext x hx y hy z hz
  simp only [Vector.getElem_ofFn]
  simp only [show w = 64 from rfl] at hz ⊢
  have h1 : (64 * (5 * y + x) + z) / 64 = 5 * y + x := by omega
  have h2 : (64 * (5 * y + x) + z) % 64 = z := by omega
  have h3 : (5 * y + x) % 5 = x := by omega
  have h4 : (5 * y + x) / 5 = y := by omega
  simp only [h1, h2, h3, h4]

/-- Round-trip: `stateToString ∘ stringToState = id`. -/
theorem stateToString_stringToState (S : Vector Bool b) :
    stateToString (stringToState S) = S := by
  simp only [stateToString, stringToState]
  ext i hi
  simp only [Vector.getElem_ofFn]
  simp only [show w = 64 from rfl, show b = 1600 from rfl] at hi ⊢
  have h1 : 64 * (5 * (i / 64 / 5) + i / 64 % 5) + i % 64 = i := by omega
  simp only [h1]

/-! ## Layer 1.5: Byte/bit access bridges

The spec definitions `bitsToBytes` and `bytesToBits` (`Spec/Defs.lean`,
Algorithms 3 & 4 of FIPS 203) are stated in `Vector.ofFn` form, with each
output element built from a `Fin.foldl` (for `bitsToBytes`) or a
`Nat.testBit` (for `bytesToBits`). Direct case-analysis on those forms is
awkward in downstream proofs because the bit/byte structure is buried
inside the foldl accumulator.

The lemmas below give point-wise characterizations:
- `bitsToBytes_byte_getLsbD`: `(bitsToBytes V)[k]`'s bit `j` is just `V[8k+j]`.
- `bytesToBits_bit_eq`: `(bytesToBits B)`'s bit `8k+j` is `B[k]`'s bit `j`. -/

section ByteBitBridges

/-! ### Auxiliary lemmas about `Fin.foldl` over `Nat` and `BitVec` -/

/-- The byte-builder `Fin.foldl` produces a value bounded by `2^n`. -/
private theorem fin_foldl_nat_lt (n : Nat) (g : Fin n → Bool) :
    Fin.foldl n (fun (acc : Nat) (j : Fin n) => acc + (g j).toNat * 2 ^ j.val) 0 < 2 ^ n := by
  induction n with
  | zero => simp [Fin.foldl_zero]
  | succ k ih =>
    rw [Fin.foldl_succ_last (n := k)]
    have hcs : ∀ (j : Fin k), j.castSucc.val = j.val := fun _ => rfl
    simp only [hcs]
    have h1 := ih (fun j => g j.castSucc)
    have h2 : (g (Fin.last k)).toNat * 2 ^ (Fin.last k).val ≤ 2 ^ k := by
      simp only [Fin.val_last]; cases g (Fin.last k) <;> simp
    have h3 : 2 ^ k + 2 ^ k = 2 ^ (k + 1) := by rw [pow_succ]; ring
    omega

/-- Bit `i` of the byte-builder `Fin.foldl` is the input bit `g i`. -/
private theorem fin_foldl_nat_testBit (n : Nat) (g : Fin n → Bool) (i : Fin n) :
    (Fin.foldl n (fun (acc : Nat) (j : Fin n) => acc + (g j).toNat * 2 ^ j.val) 0).testBit i.val
    = g i := by
  induction n with
  | zero => exact i.elim0
  | succ k ih =>
    rw [Fin.foldl_succ_last (n := k)]
    have hcs : ∀ (j : Fin k), j.castSucc.val = j.val := fun _ => rfl
    simp only [hcs, Fin.val_last]
    have hbnd : Fin.foldl k (fun (acc : Nat) (j : Fin k) =>
        acc + (g j.castSucc).toNat * 2 ^ j.val) 0 < 2 ^ k :=
      fin_foldl_nat_lt k (fun j => g j.castSucc)
    rw [show (g (Fin.last k)).toNat * 2 ^ k = 2 ^ k * (g (Fin.last k)).toNat from by ring,
        Nat.add_comm, Nat.testBit_two_pow_mul_add _ hbnd]
    by_cases hi : i.val < k
    · simp [hi]; exact ih (fun j => g j.castSucc) ⟨i.val, hi⟩
    · have heq : i.val = k := by have := i.isLt; omega
      have hi_eq : i = Fin.last k := Fin.eq_of_val_eq (by simp [Fin.val_last, heq])
      simp [hi_eq]; cases g (Fin.last k) <;> simp

/-- BitVec foldl distributes over `BitVec.ofNat`: building a byte by `BitVec`
addition equals `BitVec.ofNat` of the corresponding `Nat` foldl. -/
private theorem fin_foldl_bv_eq_ofNat (w : Nat) (n : Nat) (g : Fin n → Bool) :
    Fin.foldl n (fun (acc : BitVec w) (j : Fin n) =>
        acc + BitVec.ofNat w ((g j).toNat * 2 ^ j.val)) 0
    = BitVec.ofNat w
        (Fin.foldl n (fun (acc : Nat) (j : Fin n) => acc + (g j).toNat * 2 ^ j.val) 0) := by
  induction n with
  | zero => simp [Fin.foldl_zero]
  | succ k ih =>
    rw [Fin.foldl_succ_last (n := k), Fin.foldl_succ_last (n := k)]
    have hcs : ∀ (j : Fin k), j.castSucc.val = j.val := fun _ => rfl
    simp only [hcs]
    rw [ih (fun j => g j.castSucc), BitVec.add_comm]
    conv_rhs => rw [Nat.add_comm]
    rw [BitVec.ofNat_add]

/-- Bridge between the implicit `Nat`-to-`BitVec 8` coercion of `Bool.toNat` and
the explicit `BitVec.ofNat 8` form used by `fin_foldl_bv_eq_ofNat`. -/
private theorem coerce_bool_mul_eq_ofNat (b : Bool) (j : Nat) :
    (↑(b.toNat) : BitVec 8) * (2 ^ j) = BitVec.ofNat 8 (b.toNat * 2 ^ j) := by
  rcases b with _ | _ <;> simp

/-! ### The two byte/bit access lemmas -/

/-- **Byte-level access for `bitsToBytes`** (FIPS 203 Algorithm 3, point-wise form).

For a bit-vector `V : Vector Bool (8*ℓ)` and a valid byte index `k < ℓ`, the
`j`-th bit (LSB-first) of the `k`-th output byte is exactly the input bit at
position `8*k + j`.

This packages the "byte = bits 8k..8k+7 in LSB order" identity as a one-liner
for downstream FC proofs. Without it, callers must unfold `bitsToBytes` and
manipulate `Fin.foldl` over `BitVec 8` by hand. -/
theorem bitsToBytes_byte_getLsbD {ℓ : Nat} (V : Vector Bool (8 * ℓ)) (k : Nat) (hk : k < ℓ)
    (j : Fin 8) :
    (bitsToBytes V)[k].getLsbD j.val = V[8 * k + j.val] := by
  simp only [bitsToBytes, Vector.getElem_ofFn]
  -- Step 1: rewrite each summand from coercion-form to `BitVec.ofNat` form.
  simp only [coerce_bool_mul_eq_ofNat]
  -- Step 2: pull `BitVec.ofNat` outside the foldl via the bridge.
  rw [fin_foldl_bv_eq_ofNat 8 8 (fun j => V[8 * k + j.val])]
  -- Step 3: `getLsbD` on `BitVec.ofNat` is `Nat.testBit` (since `j.val < 8`).
  rw [BitVec.getLsbD_ofNat]
  simp [j.isLt]
  -- Step 4: `testBit` of the `Nat`-foldl is the input bit.
  exact fin_foldl_nat_testBit 8 (fun j => V[8 * k + j.val]) j

/-- **Bit-level access for `bytesToBits`** (FIPS 203 Algorithm 4, point-wise form).

For a byte-vector `B : 𝔹 ℓ` and indices `k < ℓ`, `j : Fin 8`, the bit at
position `8*k + j` of `bytesToBits B` is the `j`-th LSB of byte `B[k]`.

The `bytesToBits` definition uses `Nat.testBit` directly; this lemma rewrites
it as `BitVec.getLsbD` so callers can chain with `BitVec` lemmas. -/
theorem bytesToBits_bit_eq {ℓ : Nat} (B : 𝔹 ℓ) (k : Nat) (j : Fin 8) (hk : k < ℓ) :
    (bytesToBits B)[8 * k + j.val] = B[k].getLsbD j.val := by
  simp only [bytesToBits, Vector.getElem_ofFn]
  have h1 : (8 * k + j.val) / 8 = k := by have := j.isLt; omega
  have h2 : (8 * k + j.val) % 8 = j.val := by have := j.isLt; omega
  simp only [h1, h2, BitVec.testBit_toNat]

end ByteBitBridges

/-! ### `SPONGE.squeeze` block-level characterization

The `SPONGE.squeeze` definition is structured as a recursive accumulation of
r-bit blocks: each step truncates the current state to `r` bits, appends them
to the output prefix, and applies `f` to advance the state. The natural
algebraic view of the output is a concatenation of whole r-bit "rate blocks",
each of the form `Trunc r (f^[j] S)`. Reasoning about the squeeze at the
level of individual bits or bytes is the wrong granularity — it forces
re-derivation of the block decomposition at every use site.

We therefore introduce `squeezeBlocks f r S k` as the concatenation of the
first `k` r-bit blocks, and characterise `SPONGE.squeeze` as truncation of
this block concatenation. The byte/bit access lemmas above are then applied
*only* at the boundary, when extracting individual bytes from a single
block — never threaded through the recursion.

This block-level abstraction matches the structure of the sponge code: the
absorb/squeeze loops in the implementation also work block-by-block (one
permutation per rate block), so the FC proof composes cleanly. -/

/-- The first `k` r-bit blocks of the squeeze output, concatenated in order:
    `Trunc r S ‖ Trunc r (f S) ‖ … ‖ Trunc r (f^[k-1] S)`.
    Length: `k * r`. -/
def squeezeBlocks (f : Vector Bool b → Vector Bool b) (r : Nat)
    (S : Vector Bool b) (k : Nat) (_hr : r ≤ b := by grind) : Vector Bool (k * r) :=
  Vector.flatten (Vector.ofFn fun (j : Fin k) => Trunc r (f^[j.val] S))

/-- Bit-level access to `Trunc r S` for `j < r`: `(Trunc r S)[j] = S[j]`.
A small helper used in the `squeezeBlocks_succ` proof. -/
private theorem Trunc_getElem (r : Nat) (S : Vector Bool b) (h : r ≤ b)
    (j : Nat) (hj : j < r) :
    (Trunc r S h)[j] = S[j]'(by omega) := by
  unfold Trunc slice
  simp [Vector.getElem_ofFn]

/-- Generalised version of `Trunc_getElem` over any inner Vector length. -/
theorem Trunc_getElem' {n d : Nat} (V : Vector Bool n) (h : d ≤ n)
    (j : Nat) (hj : j < d) :
    (Trunc d V h)[j]'hj = V[j]'(by omega) := by
  unfold Trunc slice
  simp [Vector.getElem_ofFn]

/-- Block-level recurrence: prepending one block uses the original state and
shifts the remaining blocks to start from `f S`. Element-wise proof: at index
`j`, both sides project to `(f^[j/r] S)[j%r]` (using `iterate_succ` to shift
by one block in the recursive case). -/
theorem squeezeBlocks_succ (f : Vector Bool b → Vector Bool b) (r : Nat)
    (S : Vector Bool b) (k : Nat) (hr : r ≤ b) (hr_pos : 0 < r) :
    squeezeBlocks f r S (k + 1) hr
    = Vector.cast (by ring) (Vector.append (Trunc r S) (squeezeBlocks f r (f S) k hr)) := by
  unfold squeezeBlocks
  apply Vector.ext
  intro j hj
  have hjkr : j < (k + 1) * r := hj
  have hjkr' : j < r + k * r := by rw [Nat.succ_mul] at hjkr; omega
  rw [Vector.getElem_cast]
  rw [Vector.getElem_flatten hjkr]
  rw [Vector.getElem_ofFn]
  rw [Trunc_getElem r _ hr (j % r) (Nat.mod_lt _ hr_pos)]
  show (f^[j/r] S)[j%r] = (Trunc r S hr ++
    (Vector.ofFn fun (j' : Fin k) => Trunc r (f^[j'.val] (f S)) hr).flatten)[j]'hjkr'
  rw [Vector.getElem_append hjkr']
  by_cases hjr : j < r
  · have hdiv : j / r = 0 := Nat.div_eq_of_lt hjr
    have hmod : j % r = j := Nat.mod_eq_of_lt hjr
    rw [hdiv, Function.iterate_zero, id, dif_pos hjr]
    rw [Trunc_getElem r _ hr j hjr]
    congr 1
  · push Not at hjr
    rw [dif_neg (by omega : ¬ j < r)]
    rw [Vector.getElem_flatten (by omega : j - r < k * r)]
    rw [Vector.getElem_ofFn]
    rw [Trunc_getElem r _ hr ((j - r) % r) (Nat.mod_lt _ hr_pos)]
    have hdiv : (j - r) / r + 1 = j / r := by
      rw [show j = (j - r) + r from by omega, Nat.add_div_right _ hr_pos,
          Nat.add_sub_cancel]
    have hmod : (j - r) % r = j % r := by
      rw [show j = (j - r) + r from by omega, Nat.add_mod_right, Nat.add_sub_cancel]
    rw [show f^[(j - r) / r] (f S) = f^[(j - r) / r + 1] S from by
      rw [Function.iterate_succ, Function.comp_apply]]
    rw [hdiv]
    congr 1
    exact hmod.symm

/-- **Block-level characterization of `SPONGE.squeeze`** (with arbitrary prefix).

For any prefix `Z` of length `m`, `SPONGE.squeeze` of total length `m + k*r`
returns `Z` followed by the first `k` rate blocks of the squeeze on `S`:

    SPONGE.squeeze f r Z S (m + k*r) = Z ‖ squeezeBlocks f r S k

This is the workhorse. It is stated with a free prefix `Z` so that the
inductive proof goes through (each recursive step grows `Z` by one block);
specialise with `Z = #v[]` for the standalone-squeeze case below.

The proof is by induction on `k`, using
`squeezeBlocks_succ` and the definitional unfolding of `SPONGE.squeeze`
(which itself unfolds to the recursive `if d ≤ m then Trunc d Z else …`). -/
private theorem SPONGE_squeeze_with_prefix_aux {r m d : Nat} (f : Vector Bool b → Vector Bool b)
    (S : Vector Bool b) (hr : 0 < r ∧ r < b) (k : Nat) (Z : Vector Bool m)
    (hd : d = m + k * r) :
    SPONGE.squeeze (d := d) f r Z S hr
    = Vector.cast hd.symm (Vector.append Z (squeezeBlocks f r S k (le_of_lt hr.2))) := by
  induction k generalizing m S Z d with
  | zero =>
    unfold SPONGE.squeeze
    rw [dif_pos (by omega : d ≤ m)]
    apply Vector.ext
    intro j hj
    rw [Vector.getElem_cast]
    have hjm : j < m := by omega
    show (Trunc d Z _)[j] = (Z ++ squeezeBlocks f r S 0 _)[j]'(by simp; omega)
    rw [@Vector.getElem_append _ _ _ _ Z (squeezeBlocks f r S 0 (le_of_lt hr.2))
        (by simp; omega)]
    rw [dif_pos hjm]
    unfold Trunc slice
    simp [Vector.getElem_ofFn]
  | succ k ih =>
    unfold SPONGE.squeeze
    have hnle : ¬ d ≤ m := by
      have := hr.1; rw [hd, Nat.succ_mul]; omega
    rw [dif_neg hnle]
    simp only [SPONGE.squeeze_step]
    have hd' : d = (m + r) + k * r := by rw [hd]; ring
    rw [ih (S := f S) (Z := Z.append (Trunc r S (le_of_lt hr.2))) hd']
    rw [squeezeBlocks_succ f r S k (le_of_lt hr.2) hr.1]
    apply Vector.ext
    intro j hj
    rw [Vector.getElem_cast, Vector.getElem_cast]
    have hjLHS : j < (m + r) + k * r := by omega
    have hjRHS : j < m + (k + 1) * r := by omega
    rw [show ((Z.append (Trunc r S (le_of_lt hr.2))).append
              (squeezeBlocks f r (f S) k (le_of_lt hr.2)))[j]'hjLHS
            = if h : j < m + r then (Z.append (Trunc r S (le_of_lt hr.2)))[j]'h
              else (squeezeBlocks f r (f S) k (le_of_lt hr.2))[j - (m + r)]'(by omega)
            from Vector.getElem_append hjLHS]
    rw [show (Z.append (Vector.cast (by ring : r + k * r = (k + 1) * r)
              ((Trunc r S (le_of_lt hr.2)).append
                (squeezeBlocks f r (f S) k (le_of_lt hr.2)))))[j]'hjRHS
            = if h : j < m then Z[j]'h
              else (Vector.cast (by ring : r + k * r = (k + 1) * r)
                ((Trunc r S (le_of_lt hr.2)).append
                  (squeezeBlocks f r (f S) k (le_of_lt hr.2))))[j - m]'(by omega)
            from Vector.getElem_append hjRHS]
    by_cases h1 : j < m + r
    · rw [dif_pos h1]
      rw [show (Z.append (Trunc r S (le_of_lt hr.2)))[j]'h1
              = if h : j < m then Z[j]'h
                else (Trunc r S (le_of_lt hr.2))[j - m]'(by omega)
              from Vector.getElem_append h1]
      by_cases h2 : j < m
      · rw [dif_pos h2, dif_pos h2]
      · rw [dif_neg h2, dif_neg h2]
        rw [Vector.getElem_cast]
        rw [show ((Trunc r S (le_of_lt hr.2)).append
                  (squeezeBlocks f r (f S) k (le_of_lt hr.2)))[j - m]'(by omega)
                = if h : j - m < r then (Trunc r S (le_of_lt hr.2))[j - m]'h
                  else (squeezeBlocks f r (f S) k (le_of_lt hr.2))[j - m - r]'(by omega)
                from Vector.getElem_append (by omega)]
        rw [dif_pos (by omega : j - m < r)]
    · rw [dif_neg h1]
      have hnm : ¬ j < m := by omega
      rw [dif_neg hnm]
      rw [Vector.getElem_cast]
      rw [show ((Trunc r S (le_of_lt hr.2)).append
                (squeezeBlocks f r (f S) k (le_of_lt hr.2)))[j - m]'(by omega)
              = if h : j - m < r then (Trunc r S (le_of_lt hr.2))[j - m]'h
                else (squeezeBlocks f r (f S) k (le_of_lt hr.2))[j - m - r]'(by omega)
              from Vector.getElem_append (by omega)]
      rw [dif_neg (by omega : ¬ j - m < r)]
      congr 1
      omega

theorem SPONGE_squeeze_with_prefix {r m : Nat} (f : Vector Bool b → Vector Bool b)
    (S : Vector Bool b) (hr : 0 < r ∧ r < b) (k : Nat) (Z : Vector Bool m) :
    SPONGE.squeeze (d := m + k * r) f r Z S hr
    = Vector.append Z (squeezeBlocks f r S k (le_of_lt hr.2)) := by
  rw [SPONGE_squeeze_with_prefix_aux f S hr k Z rfl]
  rfl

/-- Standalone form: `SPONGE.squeeze` from an empty prefix at a multiple-of-r
length is exactly the block concatenation. -/
theorem SPONGE_squeeze_blocks {r : Nat} (f : Vector Bool b → Vector Bool b)
    (S : Vector Bool b) (hr : 0 < r ∧ r < b) (k : Nat) :
    SPONGE.squeeze (d := k * r) f r (#v[] : Vector Bool 0) S hr
    = Vector.cast (by ring) (squeezeBlocks f r S k (le_of_lt hr.2)) := by
  rw [SPONGE_squeeze_with_prefix_aux f S hr k (#v[] : Vector Bool 0) (by simp)]
  apply Vector.ext
  intro j hj
  rw [Vector.getElem_cast, Vector.getElem_cast]
  rw [show ((#v[] : Vector Bool 0).append (squeezeBlocks f r S k (le_of_lt hr.2)))[j]'(by simp; omega)
          = if h : j < 0 then (#v[] : Vector Bool 0)[j]'h
            else (squeezeBlocks f r S k (le_of_lt hr.2))[j - 0]'(by omega)
          from Vector.getElem_append (by simp; omega)]
  rw [dif_neg (by omega : ¬ j < 0)]
  congr 1

/-- Bit-level access to `squeezeBlocks` via `Trunc_getElem'`. -/
theorem squeezeBlocks_getElem
    (f : Vector Bool b → Vector Bool b) (r : Nat) (hr_pos : 0 < r) (hr_b : r ≤ b)
    (S : Vector Bool b) (k : Nat) (j : Nat) (hj : j < k * r) :
    (squeezeBlocks f r S k hr_b)[j]'hj = (f^[j / r] S)[j % r]'(by
      have := Nat.mod_lt j hr_pos
      omega) := by
  unfold squeezeBlocks
  rw [Vector.getElem_flatten hj, Vector.getElem_ofFn]
  have hjmod : j % r < r := Nat.mod_lt _ hr_pos
  show (Trunc r (f^[_] S) hr_b)[j % r]'hjmod = _
  rw [Trunc_getElem' _ _ _ hjmod]

/-- For the general case (d not a multiple of r), the squeeze output is the
prefix of the block concatenation. Take any `k` with `k * r ≥ d`. -/
private theorem SPONGE_squeeze_eq_trunc_aux {r : Nat} (f : Vector Bool b → Vector Bool b)
    (S : Vector Bool b) (hr : 0 < r ∧ r < b) (k : Nat) {m d : Nat} (Z : Vector Bool m)
    (hd : d ≤ m + k * r) :
    SPONGE.squeeze (d := d) f r Z S hr =
    Trunc d (Vector.append Z (squeezeBlocks f r S k (le_of_lt hr.2))) hd := by
  induction k generalizing m d S Z with
  | zero =>
    unfold SPONGE.squeeze
    rw [dif_pos (by omega : d ≤ m)]
    apply Vector.ext
    intro j hj
    have hjm : j < m := by have : j < d := hj; omega
    rw [Trunc_getElem' _ _ j hj, Trunc_getElem' _ _ j hj]
    have hjbound : j < m + 0 * r := by omega
    show Z[j] = (Z ++ squeezeBlocks f r S 0 (le_of_lt hr.2))[j]'hjbound
    rw [show (Z ++ squeezeBlocks f r S 0 (le_of_lt hr.2))[j]'hjbound
            = if h : j < m then Z[j]'h
              else (squeezeBlocks f r S 0 (le_of_lt hr.2))[j - m]'(by omega)
            from Vector.getElem_append hjbound]
    rw [dif_pos hjm]
  | succ k ih =>
    by_cases hdm : d ≤ m
    · unfold SPONGE.squeeze
      rw [dif_pos hdm]
      apply Vector.ext
      intro j hj
      have hjm : j < m := by omega
      rw [Trunc_getElem' _ _ j hj, Trunc_getElem' _ _ j hj]
      have hjbound : j < m + (k + 1) * r := by rw [Nat.succ_mul]; omega
      show Z[j] = (Z ++ squeezeBlocks f r S (k + 1) (le_of_lt hr.2))[j]'hjbound
      rw [show (Z ++ squeezeBlocks f r S (k + 1) (le_of_lt hr.2))[j]'hjbound
              = if h : j < m then Z[j]'h
                else (squeezeBlocks f r S (k + 1) (le_of_lt hr.2))[j - m]'(by omega)
              from Vector.getElem_append hjbound]
      rw [dif_pos hjm]
    · push Not at hdm
      unfold SPONGE.squeeze
      rw [dif_neg (by omega : ¬ d ≤ m)]
      simp only [SPONGE.squeeze_step]
      have hd' : d ≤ (m + r) + k * r := by
        rw [show (m + r) + k * r = m + (k + 1) * r from by rw [Nat.succ_mul]; ring]; exact hd
      rw [ih (f S) (Z.append (Trunc r S (le_of_lt hr.2))) hd']
      rw [squeezeBlocks_succ f r S k (le_of_lt hr.2) hr.1]
      apply Vector.ext
      intro j hj
      rw [Trunc_getElem' _ _ j hj, Trunc_getElem' _ _ j hj]
      have hjL : j < (m + r) + k * r := by omega
      have hjR : j < m + (k + 1) * r := by rw [Nat.succ_mul]; omega
      rw [show ((Z.append (Trunc r S (le_of_lt hr.2))).append
                (squeezeBlocks f r (f S) k (le_of_lt hr.2)))[j]'hjL
              = if h : j < m + r then (Z.append (Trunc r S (le_of_lt hr.2)))[j]'h
                else (squeezeBlocks f r (f S) k (le_of_lt hr.2))[j - (m + r)]'(by omega)
              from Vector.getElem_append hjL]
      rw [show (Z.append (Vector.cast (by ring : r + k * r = (k + 1) * r)
                ((Trunc r S (le_of_lt hr.2)).append
                  (squeezeBlocks f r (f S) k (le_of_lt hr.2)))))[j]'hjR
              = if h : j < m then Z[j]'h
                else (Vector.cast (by ring : r + k * r = (k + 1) * r)
                  ((Trunc r S (le_of_lt hr.2)).append
                    (squeezeBlocks f r (f S) k (le_of_lt hr.2))))[j - m]'(by omega)
              from Vector.getElem_append hjR]
      by_cases h1 : j < m + r
      · rw [dif_pos h1]
        rw [show (Z.append (Trunc r S (le_of_lt hr.2)))[j]'h1
                = if h : j < m then Z[j]'h
                  else (Trunc r S (le_of_lt hr.2))[j - m]'(by omega)
                from Vector.getElem_append h1]
        by_cases h2 : j < m
        · rw [dif_pos h2, dif_pos h2]
        · rw [dif_neg h2, dif_neg h2]
          rw [Vector.getElem_cast]
          rw [show ((Trunc r S (le_of_lt hr.2)).append
                    (squeezeBlocks f r (f S) k (le_of_lt hr.2)))[j - m]'(by omega)
                  = if h : j - m < r then (Trunc r S (le_of_lt hr.2))[j - m]'h
                    else (squeezeBlocks f r (f S) k (le_of_lt hr.2))[j - m - r]'(by omega)
                  from Vector.getElem_append (by omega)]
          rw [dif_pos (by omega : j - m < r)]
      · rw [dif_neg h1]
        have hnm : ¬ j < m := by omega
        rw [dif_neg hnm]
        rw [Vector.getElem_cast]
        rw [show ((Trunc r S (le_of_lt hr.2)).append
                  (squeezeBlocks f r (f S) k (le_of_lt hr.2)))[j - m]'(by omega)
                = if h : j - m < r then (Trunc r S (le_of_lt hr.2))[j - m]'h
                  else (squeezeBlocks f r (f S) k (le_of_lt hr.2))[j - m - r]'(by omega)
                from Vector.getElem_append (by omega)]
        rw [dif_neg (by omega : ¬ j - m < r)]
        congr 1
        omega

theorem SPONGE_squeeze_eq_trunc_blocks {r d : Nat} (f : Vector Bool b → Vector Bool b)
    (S : Vector Bool b) (hr : 0 < r ∧ r < b) (k : Nat) (hk : d ≤ k * r) :
    SPONGE.squeeze (d := d) f r (#v[] : Vector Bool 0) S hr
    = Trunc d (Vector.cast (by ring) (squeezeBlocks f r S k (le_of_lt hr.2))) hk := by
  rw [SPONGE_squeeze_eq_trunc_aux f S hr k (#v[] : Vector Bool 0) (by omega)]
  apply Vector.ext
  intro j hj
  rw [Trunc_getElem' _ _ j hj, Trunc_getElem' _ _ j hj, Vector.getElem_cast]
  show ((#v[] : Vector Bool 0) ++ squeezeBlocks f r S k (le_of_lt hr.2))[j]'(by simp; omega)
     = (squeezeBlocks f r S k (le_of_lt hr.2))[j]'(by omega)
  rw [show ((#v[] : Vector Bool 0) ++ squeezeBlocks f r S k (le_of_lt hr.2))[j]'(by simp; omega)
          = if h : j < 0 then (#v[] : Vector Bool 0)[j]'h
            else (squeezeBlocks f r S k (le_of_lt hr.2))[j - 0]'(by simp; omega)
          from Vector.getElem_append (by simp; omega)]
  rw [dif_neg (by omega : ¬ j < 0)]
  congr 1

/-! ### `SPONGE.absorb` block-level characterization

Mirror of the squeeze block-level API: `SPONGE.absorb` is naturally a fold
over the `r`-bit blocks of its padded input. We expose this as
`absorbBlocks`, with `SPONGE_absorb_eq_blocks` connecting the spec form
(an `Id.run do for`-loop) to the fold form. -/

/-- The state after absorbing `k` r-bit blocks `Bs` into starting state `S`.
    Each step XORs one block into the state and applies `f`. -/
def absorbBlocks {r k : Nat} (f : Vector Bool b → Vector Bool b)
    (S : Vector Bool b) (Bs : Vector (Vector Bool r) k) : Vector Bool b :=
  Bs.foldl (fun S Pi => f (S ⊕ Bits.zeroExtend Pi b)) S

/-- `SPONGE.absorb` is exactly `absorbBlocks` from a zero state, applied to the
r-bit-block decomposition of `P`. The `for`-loop in the definition is
literally `Vector.foldl` once the `Id.run do` is unfolded. -/
theorem SPONGE_absorb_eq_blocks {m r} (f : Vector Bool b → Vector Bool b)
    (P : Vector Bool m) (hr : 0 < r) (hm : m % r = 0) :
    SPONGE.absorb f r P hm hr = absorbBlocks f 0 (blocks P r hr hm) := by
  unfold SPONGE.absorb absorbBlocks
  simp

/-- Block-level recurrence: an empty block list returns the start state. -/
@[simp]
theorem absorbBlocks_empty {r} (f : Vector Bool b → Vector Bool b) (S : Vector Bool b) :
    absorbBlocks f S (k := 0) (#v[] : Vector (Vector Bool r) 0) = S := by
  simp [absorbBlocks]

/-- The state immediately *before* the FINAL `f` permutation in `absorbBlocks`.
    Decomposed as: absorb the first k blocks (k+1 total), then XOR the (k+1)-th
    block in without permuting. The final result of `absorbBlocks` over k+1 blocks
    is therefore `f (preFinalState f init Bs)` (see lemma below). -/
def preFinalState {r k : Nat} (f : Vector Bool b → Vector Bool b)
    (init : Vector Bool b) (Bs : Vector (Vector Bool r) (k + 1)) :
    Vector Bool b :=
  absorbBlocks f init Bs.pop ⊕ Bits.zeroExtend Bs.back b

/-- Recurrence: absorbing k+1 blocks = `f` applied to the pre-final state. -/
theorem absorbBlocks_eq_f_preFinalState {r k} (f : Vector Bool b → Vector Bool b)
    (init : Vector Bool b) (Bs : Vector (Vector Bool r) (k + 1)) :
    absorbBlocks f init Bs = f (preFinalState f init Bs) := by
  unfold preFinalState
  conv_lhs => rw [show Bs = Bs.pop.push Bs.back from (Vector.push_pop_back _).symm]
  unfold absorbBlocks
  simp [Vector.foldl_push]

/-! ## Layer 2: Step-mapping bridge lemmas

Each theorem states that applying the Rust step function on a flat array
(as defined in the Aeneas-generated code) produces the same result as
applying the spec step on the 2D state, modulo the representation bridge.

### Strategy for each step:

- **θ**: The Rust computes `col_sum[x]` as XOR of `state[x+5k]` for k=0..4,
  matching `C[x] = A[x][0] ⊕ … ⊕ A[x][4]` since `state[x + 5k]` = `A[x][k]`.
  Then `D[x] = col_sum[(x-1)%5] ^ col_sum[(x+1)%5].rotate_left(1)`,
  matching `C[x−1] ⊕ rot(C[x+1], 1)`.
  Then each row element is XORed with `D[x]`.

- **ρ**: The Rust applies `state[5y+x].rotate_left(KECCAK_RHO_K[5y+x])` for each lane.
  This requires `KECCAK_RHO_K[5y+x] = ρ.Offsets[x][y] % 64`.
  Proof: `rhoOffsets_flat_eq` below (by `native_decide`).

- **π**: The Rust does an in-place 24-cycle permutation.
  Proof: `pi_cycle_eq` below shows the cycle implements `A'[x][y] = A[(x+3y)%5][x]`.

- **χ**: The Rust computes per-row with two temporaries.
  Proof: algebraic — all 5 outputs use only the original row values.

- **ι**: The Rust XORs `KECCAK_IOTA_K[rnd]` into `state[0]`.
  This requires `KECCAK_IOTA_K[rnd] = ι.RC rnd`.
  Proof: `iota_constants_eq` below (by `native_decide`).
-/

section StepBridge

/-! ### Precomputed-constant verification

These discharge the constant tables used by ρ and ι, avoiding
the need to inline Algorithm 2 or Algorithm 5 proofs. -/

/-- The Rust `KECCAK_RHO_K` constants (flat layout) match `ρ.Offsets` (2D layout) mod 64.
    `KECCAK_RHO_K[5*y + x] = ρ.Offsets[x][y] % 64` for all valid x, y. -/
def rustRhoFlat : Vector Nat 25 :=
  #v[ 0,  1, 62, 28, 27,   -- y=0
     36, 44,  6, 55, 20,   -- y=1
      3, 10, 43, 25, 39,   -- y=2
     41, 45, 15, 21,  8,   -- y=3
     18,  2, 61, 56, 14]   -- y=4

def specRhoFlat : Vector Nat 25 :=
  Vector.ofFn fun i => ρ.Offsets[i % 5][i / 5] % w

theorem rhoOffsets_flat_eq : rustRhoFlat = specRhoFlat := by native_decide

/-- The Rust `KECCAK_IOTA_K` constants match `ι.RC` for all 24 rounds. -/
def rustIotaConstants : Vector (BitVec 64) 24 := #v[
  0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
  0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
  0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
  0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
  0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]

def specIotaConstants : Vector Lane 24 :=
  Vector.ofFn fun i => ι.RC i

theorem iota_constants_eq : ∀ i : Fin 24,
    Bits.toNatLE (specIotaConstants[i]) = (rustIotaConstants[i]).toNat := by native_decide

/-- The π permutation implemented as a 24-cycle matches `π`. Specifically,
    the Rust cycle `[1→6→9→22→14→20→2→12→13→19→23→15→4→24→21→8→16→5→3→18→17→11→7→10→1]`
    produces the same mapping as `A'[x][y] = A[(x+3y)%5][x]`. -/
def piCycle : Vector (Fin 25) 24 :=
  #v[1, 6, 9, 22, 14, 20, 2, 12, 13, 19, 23, 15, 4, 24, 21, 8, 16, 5, 3, 18, 17, 11, 7, 10]

/-- The spec π mapping as a flat permutation: `piSpec[5y+x] = 5*x + (x+3y)%5`. -/
def piSpecFlat : Vector (Fin 25) 25 :=
  Vector.ofFn fun (i : Fin 25) =>
    let x := i.val % 5
    let y := i.val / 5
    ⟨5 * x + (x + 3 * y) % 5, by agrind⟩

end StepBridge


/-! ## Layer 2b: Padding bridge

The Rust `apply_padding` merges the domain suffix and `pad10*1` into a single
operation. We prove this is equivalent to the spec's separate suffix + padding. -/

section PaddingBridge

/-- SHA3 padding value `0x06` encodes `hashSuffix ‖ 1` in LSB-first byte order.
    Bits 0,1 = suffix (0,1 = FIPS "01"), bit 2 = pad10*1 leading 1. -/
theorem sha3_padding_value_bits :
    (0x06 : BitVec 8).getLsbD 0 = false ∧   -- suffix bit 0
    (0x06 : BitVec 8).getLsbD 1 = true  ∧   -- suffix bit 1
    (0x06 : BitVec 8).getLsbD 2 = true  ∧   -- pad10*1 leading 1
    (∀ i, 3 ≤ i → i < 8 → (0x06 : BitVec 8).getLsbD i = false) := by  -- zeros
  decide

/-- SHAKE padding value `0x1F` encodes `xofSuffix ‖ 1` in LSB-first byte order.
    Bits 0..3 = suffix (1,1,1,1 = FIPS "1111"), bit 4 = pad10*1 leading 1. -/
theorem shake_padding_value_bits :
    (0x1F : BitVec 8).getLsbD 0 = true  ∧
    (0x1F : BitVec 8).getLsbD 1 = true  ∧
    (0x1F : BitVec 8).getLsbD 2 = true  ∧
    (0x1F : BitVec 8).getLsbD 3 = true  ∧
    (0x1F : BitVec 8).getLsbD 4 = true  ∧
    (∀ i, 5 ≤ i → i < 8 → (0x1F : BitVec 8).getLsbD i = false) := by
  decide

/-- The final `1` bit of `pad10*1` corresponds to setting bit 63 of the last rate lane.
    For rate `r` bytes (= `8*r` bits), the last bit of the rate portion is at position
    `8*r - 1`, which is bit 63 of lane `r/8 - 1`.  -/
theorem pad_final_bit_position (r : Nat) (hr : 0 < r) (hr8 : r % 8 = 0) :
    8 * r - 1 = 64 * (r / 8 - 1) + 63 := by
  agrind

end PaddingBridge

end Spec.SHA3
