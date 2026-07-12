import Symcrust.Properties.SHA3.Sponge.BridgeRepr
import Symcrust.Properties.SHA3.Sponge.BridgeBitFC
import Symcrust.Properties.SHA3.Sponge.BridgeComp

/-!
# SHA-3 Sponge Bridge — Math FC sublemmas

The 3 sublemmas decomposing `code_toSpec` (Bridge.lean): the equivalence
between code-adjacent byte-level operations and the FIPS 202 bit-level
SPONGE.

  bridge: absorbBytes ; padAndPermute ; squeezeBytes
  spec:   bitsToBytes ∘ SPONGE KECCAK_f (8*rate) ∘ (· ‖ suffix)

Decomposition:

A. `absorbBytes_eq_SPONGE_absorb`:
   the state after byte-level absorb of `msg.toList` (NO padding) plus
   `padAndPermute` with `padVal` (encoding `suffix ‖ leading-1-of-pad10*1`)
   equals `SPONGE.absorb KECCAK_f (8*rate) P` where `P = bytesToBits msg ‖
   suffix ‖ pad10*1 (8*rate) (8*n+s)`.

B. `padAndPermute_eq_final_block`:
   `padAndPermute S idx rate padVal` is exactly the absorb of a final
   block consisting of (the unaligned suffix bits XOR'd in) + the
   trailing `1`-bit at position `8*rate-1` (the last bit of pad10*1).

C. `squeezeBytes_eq_SPONGE_squeeze`:
   for any post-absorb state S, `(squeezeBytes S 0 rate m) =
   bitsToBytes (SPONGE.squeeze KECCAK_f (8*rate) #v[] S (8*m))`.

These three glue together in `code_toSpec` (Bridge.lean).
-/

namespace symcrust.sha3.sha3_impl

open Aeneas Aeneas.Std Spec
open Spec (𝔹 bytesToBits bitsToBytes Bits.toNatLE)
open Spec.SHA3 (b w KECCAK_f SPONGE «pad10*1» padLen padLen_dvd)
open scoped Spec.Notations
open scoped Spec.SHA3

/-! ## A. Byte-level absorb matches block-level SPONGE.absorb

**Proof strategy: induction matching `SPONGE.absorb`'s definition shape.**

`SPONGE.absorb f r P` iterates `for Pi in blocks P r do S := f (S ⊕ Pi)`.
This unfolds to `Vector.foldl (fun S Pi => f (S ⊕ Pi)) 0 (blocks P r)`
(see `SPONGE_absorb_eq_blocks` ✓).

The induction therefore matches: peel off ONE block from `blocks P r` per step,
both sides applying ONE `KECCAK_f`. Alignment:

- **Spec side** (block iteration): one block = 8*rate bits = rate bytes worth.
  After consuming block `Pi`, state becomes `f (init ⊕ Bits.zeroExtend Pi b)`.

- **Code side** (byte iteration): `absorbBytes_append` ✓ splits `msg` =
  `first ++ rest`. When `|first| = rate` and starting `idx = 0`, the
  byte-level loop hits `idx = rate` after the last byte of `first` and
  invokes KECCAK_f, giving state `KECCAK_f (init ⊕ chunkBits 0 first)`.
  Then `absorbBytes` continues from `(KECCAK_f (init ⊕ chunkBits first), 0)`
  on `rest`.

Induction on K = `(blocks P r).length` = Q+1 where Q = `n / rate`.

- **K=1 (base case)**: `msg` has fewer than `rate` bytes. `absorbBytes`
  never permutes; result is `(init ⊕ chunkBits 0 msg.toList, n)`.
  `padAndPermute` applies the only KECCAK_f.
  Spec side: single trailing block = bytes' bits ‖ suffix ‖ pad10*1.
  The base-case identity is purely algebraic on the inner XOR pattern,
  proved via `chunkBits_getElem` ✓ + `shiftedByte_getElem` ✓.

- **K=k+2 (step case)**: `msg` has ≥ `rate` bytes. `msg.toList = first ++ rest`
  with `|first| = rate`, `|rest| = n - rate`. `blocks P r = first_block :: rest_blocks`
  where `first_block = bytesU8ToBits first` (no suffix/pad in first block).
    LHS:
      `absorbBytes_append` gives:
        `(absorbBytes init 0 rate msg.toList).1 =
         (absorbBytes (KECCAK_f (init ⊕ chunkBits 0 first)) 0 rate rest).1`
    RHS:
      `absorbBlocks f init (first_block :: rest_blocks) =
       absorbBlocks f (f (init ⊕ Bits.zeroExtend first_block b)) rest_blocks`
    Reduce both via `f (init ⊕ chunkBits 0 first) = f (init ⊕ Bits.zeroExtend first_block b)`
    (a single block-extension identity, ~10 lines), then apply IH on `rest`.

**Generalization needed**: an auxiliary form parameterized by the starting
state `init` (not just `Vector.replicate b false`) and by the SPECIFIC
block list `Bs` (not derived from msg). This lets the IH apply with
`init := KECCAK_f (S₀ ⊕ first_block_bits)`.

**Estimated breakdown**:
- Aux lemma signature + induction scaffold: ~20 lines
- Step case (block-extension identity + IH apply): ~30 lines
- Base case (algebraic bit-pattern identity for trailing block): ~50 lines
- Top-level `absorbBytes_eq_SPONGE_absorb` from aux: ~10 lines

Status: COMPLETE. The aux lemma is `absorbBytes_eq_SPONGE_absorb_aux`,
the top-level wrapper is `absorbBytes_eq_SPONGE_absorb`. -/

/-- Bridge: byte-level absorbBytesRaw at idx=0 = state XOR'd with the
    zeroExtend of bytesU8ToBits. Used in the step case to match
    init' = KECCAK_f (absorbBytesRaw ...) with f (init ⊕ Bits.zeroExtend B b). -/
private theorem absorbBytesRaw_eq_zeroExtend {n}
    (S : Vector Bool b) (msg : Vector U8 n) (_hsize : 8 * n ≤ b) :
    absorbBytesRaw S 0 msg.toList = S ⊕ Bits.zeroExtend (bytesU8ToBits msg) b := by
  rw [absorbBytesRaw_eq_xor]
  -- Show: S ⊕ chunkBits 0 msg.toList = S ⊕ Bits.zeroExtend (bytesU8ToBits msg) b
  -- Pointwise equivalence of chunkBits and zeroExtend.
  apply Vector.ext
  intro j hj
  show (Vector.zipWith _ S (chunkBits 0 msg.toList))[j] =
       (Vector.zipWith _ S (Bits.zeroExtend (bytesU8ToBits msg) b))[j]
  rw [Vector.getElem_zipWith, Vector.getElem_zipWith]
  rw [chunkBits_getElem 0 j msg.toList hj]
  simp only [Nat.mul_zero, Nat.zero_add, Nat.sub_zero, Nat.zero_le, true_and]
  have hlen : msg.toList.length = n := by simp
  rw [hlen]
  unfold Bits.zeroExtend
  rw [Vector.getElem_ofFn]
  by_cases hj' : j < 8 * n
  · simp only [hj', decide_true, Bool.true_and, ↓reduceDIte]
    have hjdiv : j / 8 < n := by omega
    have hjdiv_l : j / 8 < msg.toList.length := by simp; omega
    have heq : msg.toList[j / 8]! = msg[j / 8] := by
      rw [List.getElem!_eq_getElem?_getD,
          List.getElem?_eq_getElem hjdiv_l, Option.getD_some,
          Vector.getElem_toList]
    rw [heq]
    -- bytesU8ToBits = bytesToBits ∘ Vector.map (·.bv); apply bytesToBits_bit_eq.
    show _ = (S[j] != _)
    have hjdiv8 : j / 8 < n := hjdiv
    have hjmod : j % 8 < 8 := Nat.mod_lt _ (by omega)
    have h_eq : (bytesU8ToBits msg)[j] = msg[j / 8].bv.getLsbD (j % 8) := by
      unfold bytesU8ToBits
      have hbe := Spec.SHA3.bytesToBits_bit_eq (msg.map (·.bv)) (j / 8)
              ⟨j % 8, hjmod⟩ hjdiv8
      simp only [Vector.getElem_map] at hbe
      have hj_decomp : 8 * (j / 8) + j % 8 = j := Nat.div_add_mod j 8
      have hj_lhs : (bytesToBits (Vector.map (fun x : U8 => x.bv) msg))[j]
                  = (bytesToBits (Vector.map (fun x : U8 => x.bv) msg))[8 * (j / 8) + j % 8] := by
        congr 1; exact hj_decomp.symm
      rw [hj_lhs, hbe]
    rw [h_eq]
  · push Not at hj'
    simp only [show ¬ (j < 8 * n) from by omega, decide_false, Bool.false_and, ↓reduceDIte]

/-- Helper: when consuming exactly `rate - idx` bytes (with idx < rate), the
    byte-level `absorbBytes` ends with a `KECCAK_f` permute and resets idx to 0.
    This captures the boundary behaviour: idx hits rate on the LAST byte of data. -/
private theorem absorbBytes_consume_to_boundary
    (S : Vector Bool b) (idx rate : Nat) (data : List U8)
    (hsum : idx + data.length = rate) (hidx : idx < rate) :
    absorbBytes S idx rate data = (KECCAK_f (absorbBytesRaw S idx data), 0) := by
  induction data generalizing S idx with
  | nil =>
    -- |data| = 0 ⇒ idx = rate, contradicting idx < rate.
    simp at hsum; omega
  | cons byte rest ih =>
    show (let S' := absorbByte S idx byte
          let idx' := idx + 1
          if idx' = rate then absorbBytes (KECCAK_f S') 0 rate rest
          else absorbBytes S' idx' rate rest) = _
    by_cases hone : idx + 1 = rate
    · -- LAST BYTE: |rest| = 0, recursive call returns immediately.
      have hrest_len : rest.length = 0 := by simp [List.length_cons] at hsum; omega
      have hrest_nil : rest = [] := List.length_eq_zero_iff.mp hrest_len
      simp only [hone, ↓reduceIte, hrest_nil]
      show absorbBytes (KECCAK_f (absorbByte S idx byte)) 0 rate [] = _
      show (KECCAK_f (absorbByte S idx byte), 0) = _
      rw [show absorbBytesRaw S idx [byte] = absorbByte S idx byte from
            absorbBytesRaw_singleton S idx byte]
    · -- NOT LAST BYTE: recurse on rest with idx+1.
      simp only [hone, ↓reduceIte]
      have hidx' : idx + 1 < rate := by omega
      have hsum' : idx + 1 + rest.length = rate := by simp [List.length_cons] at hsum; omega
      rw [ih (absorbByte S idx byte) (idx + 1) hsum' hidx']
      -- Bridge: absorbBytesRaw (absorbByte S idx byte) (idx+1) rest = absorbBytesRaw S idx (byte :: rest)
      rw [show absorbBytesRaw S idx (byte :: rest) =
            absorbBytesRaw (absorbByte S idx byte) (idx + 1) rest from by
          rw [show (byte :: rest) = [byte] ++ rest from rfl,
              absorbBytesRaw_append, absorbBytesRaw_singleton,
              show idx + [byte].length = idx + 1 from rfl]]

/-- **First-block bridge**: when `rate ≤ n`, byte-absorbing `msg` from a
boundary state (`idx = 0`) is the same as advancing `init` by one `KECCAK_f`
step on the bit-image of the first `rate` bytes, then byte-absorbing the
remaining `n - rate` bytes from the new boundary.

This consolidates `absorbBytes_append` + `absorbBytes_consume_to_boundary`
+ `absorbBytesRaw_eq_zeroExtend` into a single step. -/
private theorem absorbBytes_first_block {n} (msg : Vector U8 n) (rate : Nat)
    (hr : 0 < rate ∧ 8 * rate < b) (hge : rate ≤ n) (init : Vector Bool b) :
    let first : Vector U8 rate     := (msg.extract 0    rate).cast (by omega)
    let rest  : Vector U8 (n-rate) := (msg.extract rate n   ).cast (by omega)
    absorbBytes init 0 rate msg.toList =
    absorbBytes (KECCAK_f (init ⊕ Bits.zeroExtend (bytesU8ToBits first) b))
                0 rate rest.toList := by
  intro first rest
  have hflen : first.toList.length = rate := by
    simp [first, Vector.toList_cast, Vector.toList_extract]; omega
  have hrlen : rest.toList.length = n - rate := by
    simp [rest, Vector.toList_cast, Vector.toList_extract]
  have hsplit : msg.toList = first.toList ++ rest.toList := by
    show msg.toList = ((msg.extract 0 rate).cast _).toList ++ ((msg.extract rate n).cast _).toList
    simp only [Vector.toList_cast, Vector.toList_extract, Nat.sub_zero]
    have h1 : (msg.toList.drop rate).take (n - rate) = msg.toList.drop rate := by
      apply List.take_of_length_le
      rw [List.length_drop, Vector.length_toList]
    rw [h1, show msg.toList.drop 0 = msg.toList from rfl, List.take_append_drop]
  rw [hsplit, absorbBytes_append,
      absorbBytes_consume_to_boundary init 0 rate first.toList (by omega) hr.1,
      absorbBytesRaw_eq_zeroExtend init first (by show 8 * rate ≤ b; omega)]

/-- **`absorbBlocks` cons recurrence**: peeling off the first block.

For a block-vector that's `Vector.cast` of `#v[B] ++ rest_blocks`, folding equals
folding `rest_blocks` from the state advanced by one block on `B`. -/
private theorem absorbBlocks_cons {r k k' : Nat} (f : Vector Bool b → Vector Bool b)
    (init : Vector Bool b) (B : Vector Bool r)
    (rest_blocks : Vector (Vector Bool r) k) (h : 1 + k = k') :
    Spec.SHA3.absorbBlocks f init
      ((#v[B] ++ rest_blocks).cast h)
    = Spec.SHA3.absorbBlocks f
        (f (init ⊕ Bits.zeroExtend B b)) rest_blocks := by
  subst h
  unfold Spec.SHA3.absorbBlocks
  rw [Vector.cast_rfl, Vector.foldl_append]
  rfl

/-- **`padLen` is r-periodic**: `padLen r (m + r) = padLen r m`. -/
private theorem padLen_period (r m : Nat) :
    padLen r (m + r) = padLen r m := by
  show 1 + ((-((m + r : Nat) : Int) - 2) % (r : Nat)).toNat + 1
     = 1 + ((-((m : Nat) : Int) - 2) % (r : Nat)).toNat + 1
  congr 2
  rw [show (-((m + r : Nat) : Int) - 2) = (-((m : Nat) : Int) - 2) + (r : Nat) * (-1)
        from by push_cast; ring,
      Int.add_mul_emod_self_left]

/-- **Closed form for `pad10*1` indexing**: `(pad10*1 r m)[i] = true` iff
`i = 0` or `i = padLen r m - 1` (the two `1`-bits framing the zero block). -/
private theorem pad10star1_getElem (r m i : Nat) (hi : i < padLen r m) :
    («pad10*1» r m)[i]'hi = decide (i = 0 ∨ i = padLen r m - 1) := by
  have hpad : padLen r m = 1 + Spec.SHA3.padLen.j r m + 1 := by unfold padLen; omega
  show ((#v[(1 : Bool)] ‖ Vector.replicate (Spec.SHA3.padLen.j r m) (0 : Bool))
        ‖ #v[(1 : Bool)])[i] = _
  rw [show ((#v[(1 : Bool)] : Vector Bool 1) ‖ Vector.replicate (Spec.SHA3.padLen.j r m) (0 : Bool))
        ‖ ((#v[(1 : Bool)] : Vector Bool 1))
       = ((#v[(1 : Bool)] : Vector Bool 1) ++ Vector.replicate (Spec.SHA3.padLen.j r m) (0 : Bool))
        ++ ((#v[(1 : Bool)] : Vector Bool 1)) from rfl]
  rw [Vector.getElem_append]
  by_cases h1 : i < 1 + Spec.SHA3.padLen.j r m
  · simp only [h1, ↓reduceDIte]
    rw [Vector.getElem_append]
    by_cases h2 : i < 1
    · have heq : i = 0 := by omega
      subst heq
      simp only [show (0 : Nat) < 1 from by decide, ↓reduceDIte]
      have : decide (True ∨ (0 : Nat) = padLen r m - 1) = true := by
        apply decide_eq_true; left; trivial
      rw [this]; rfl
    · simp only [h2, ↓reduceDIte]
      simp only [Vector.getElem_replicate]
      have hi0 : i ≠ 0 := by omega
      have hi_last : i ≠ 1 + Spec.SHA3.padLen.j r m := by omega
      have : decide (i = 0 ∨ i = padLen r m - 1) = false := by
        apply decide_eq_false; intro h
        cases h with
        | inl h => exact hi0 h
        | inr h => exact hi_last (by omega)
      rw [this]; rfl
  · simp only [h1, ↓reduceDIte]
    have hi_last : i = padLen r m - 1 := by omega
    have hi_eq : i - (1 + Spec.SHA3.padLen.j r m) = 0 := by omega
    have hgoal : (#v[(1 : Bool)] : Vector Bool 1)[i - (1 + Spec.SHA3.padLen.j r m)]'(by
        rw [hi_eq]; decide) = (1 : Bool) := by
      rw [show (#v[(1 : Bool)] : Vector Bool 1)[i - (1 + Spec.SHA3.padLen.j r m)]'(by rw [hi_eq]; decide)
          = (#v[(1 : Bool)] : Vector Bool 1)[(0 : Nat)]'(by decide) from by congr 1]
      rfl
    rw [hgoal]
    have : decide (i = 0 ∨ i = padLen r m - 1) = true := by
      apply decide_eq_true; right; exact hi_last
    rw [this]; rfl

/-- **`pad10*1` is `r`-periodic in `m`**: `(pad10*1 r (m+r))[i] = (pad10*1 r m)[i]`,
where the lengths agree by `padLen_period`. -/
private theorem pad10star1_period_getElem (r m i : Nat)
    (hi : i < padLen r (m + r)) :
    («pad10*1» r (m + r))[i]'hi
      = («pad10*1» r m)[i]'(by rw [← padLen_period r m]; exact hi) := by
  rw [pad10star1_getElem, pad10star1_getElem, padLen_period r m]

/-- Block-count step: shifting `m` by `r` changes the block count by 1. -/
private theorem blocks_count_step {r m : Nat} (hr : 0 < r) :
    1 + (m + padLen r m) / r = (m + r + padLen r (m + r)) / r := by
  rw [padLen_period r m]
  have hdvd := padLen_dvd r m hr
  rw [show m + r + padLen r m = (m + padLen r m) + 1 * r from by ring,
      Nat.add_mul_div_right _ _ hr]
  omega

/-- **`blocks` decomposition**: when the bit-string P factors as `B ‖ Q` with
`|B| = r`, the block list of P is the singleton `B` prepended to the block list
of Q. -/
private theorem blocks_split {r kRest : Nat}
    (B : Vector Bool r) (Q : Vector Bool (kRest * r))
    (hr : 0 < r) :
    Spec.SHA3.blocks (B ‖ Q) r hr
      (by simp) =
    ((⟨#[B], rfl⟩ : Vector (Vector Bool r) 1) ++
     Spec.SHA3.blocks Q r hr (by simp)).cast
      (by rw [Nat.add_comm r (kRest * r), Nat.add_div_right _ hr,
              Nat.mul_div_cancel _ hr]; omega) := by
  unfold Spec.SHA3.blocks Spec.slice
  apply Vector.ext; intro i hi
  rw [Vector.getElem_cast, Vector.getElem_append]
  simp only [Vector.getElem_ofFn]
  have hdiv : (r + kRest * r) / r = 1 + kRest := by
    rw [Nat.add_comm r (kRest * r), Nat.add_div_right _ hr, Nat.mul_div_cancel _ hr,
        Nat.add_comm]
  rw [hdiv] at hi
  by_cases h0 : i = 0
  · subst h0
    simp only [show (0 : Nat) < 1 from by omega, ↓reduceDIte]
    apply Vector.ext; intro j hj
    rw [Vector.getElem_ofFn]
    show (B ++ Q)[0 * r + j] = _
    rw [Vector.getElem_append]
    rw [dif_pos (show 0*r + j < r from by omega)]
    show B[0*r+j] = B[j]
    congr 1; omega
  · have hi_pos : 0 < i := Nat.pos_of_ne_zero h0
    simp only [show ¬ i < 1 from by omega, ↓reduceDIte]
    apply Vector.ext; intro j hj
    rw [Vector.getElem_ofFn, Vector.getElem_ofFn]
    show (B ++ Q)[i * r + j]'(by
      have hi_kRest : i ≤ kRest := by omega
      have : i * r ≤ kRest * r := Nat.mul_le_mul_right r hi_kRest
      omega) = _
    rw [Vector.getElem_append]
    rw [dif_neg (show ¬ (i * r + j < r) from by
                   have : i * r ≥ r := Nat.le_mul_of_pos_left r hi_pos
                   omega)]
    -- Goal: Q[i*r+j-r] = Q[(i-1)*r+j]; show indices are equal.
    congr 1
    have hge : r ≤ i * r := Nat.le_mul_of_pos_left r hi_pos
    rw [Nat.sub_mul, Nat.one_mul, show i * r + j - r = i * r - r + j from by omega]

/-- **`bytesU8ToBits` distributes over `‖`** (homomorphism). Proved pointwise.
Used by `blocks_msg_split` (and reusable for future bridge work). -/
private theorem bytesU8ToBits_append {m k : Nat} (X : Vector U8 m) (Y : Vector U8 k) :
    bytesU8ToBits (X ‖ Y) = (bytesU8ToBits X ‖ bytesU8ToBits Y).cast (by ring) := by
  apply Vector.ext; intro i hi
  unfold bytesU8ToBits bytesToBits
  simp only [Vector.getElem_ofFn, Vector.getElem_cast, Vector.getElem_map]
  have hdiv : i / 8 < m + k := by omega
  have hi' : i < 8 * m + 8 * k := by omega
  rw [show (X.append Y)[i/8]'hdiv = (X ++ Y)[i/8]'hdiv from rfl,
      Vector.getElem_append]
  rw [show ((Vector.ofFn fun x : Fin (8*m) => X[↑x / 8].bv.toNat.testBit (↑x % 8)).append
            (Vector.ofFn fun x : Fin (8*k) => Y[↑x / 8].bv.toNat.testBit (↑x % 8)))[i]'hi'
        = ((Vector.ofFn fun x : Fin (8*m) => X[↑x / 8].bv.toNat.testBit (↑x % 8)) ++
            (Vector.ofFn fun x : Fin (8*k) => Y[↑x / 8].bv.toNat.testBit (↑x % 8)))[i]'hi' from rfl,
      Vector.getElem_append]
  by_cases him : i / 8 < m
  · simp only [him, ↓reduceDIte]
    have hi_8m : i < 8 * m := by omega
    simp only [hi_8m, ↓reduceDIte]
    rw [Vector.getElem_ofFn]
  · simp only [him, ↓reduceDIte]
    have hi_8m : ¬ i < 8 * m := by omega
    simp only [hi_8m, ↓reduceDIte, Vector.getElem_ofFn]
    have hd : (i - 8 * m) / 8 = i / 8 - m := by omega
    have hm : (i - 8 * m) % 8 = i % 8 := by omega
    simp only [hd, hm]

/-- `bytesU8ToBits` commutes with `Vector.cast`. -/
private theorem bytesU8ToBits_cast {n m : Nat} (h : n = m) (V : Vector U8 n) :
    bytesU8ToBits (V.cast h) = (bytesU8ToBits V).cast (by rw [h]) := by
  subst h; rfl

/-- **Padded-message blocks decomposition**: when `n ≥ rate`, the blocks of
the padded P decompose as the singleton bit-block `bytesU8ToBits first`
prepended to the blocks of the corresponding padded `rest`. Folds together
the bit-level decomposition + `blocks_split` + cast/length handling. -/
private theorem blocks_msg_split {n s} (msg : Vector U8 n) (suffix : Vector Bool s)
    (rate : Nat) (hr : 0 < rate ∧ 8 * rate < b) (hge : rate ≤ n) :
    let first : Vector U8 rate := (msg.extract 0 rate).cast (by omega)
    let rest : Vector U8 (n - rate) := (msg.extract rate n).cast (by omega)
    Spec.SHA3.blocks
        ((bytesU8ToBits msg ‖ suffix) ‖ «pad10*1» (8 * rate) (8 * n + s))
        (8 * rate) (by grind)
        (padLen_dvd (8 * rate) (8 * n + s) (by grind))
    =
    ((⟨#[bytesU8ToBits first], rfl⟩ : Vector (Vector Bool (8*rate)) 1) ++
     Spec.SHA3.blocks
       ((bytesU8ToBits rest ‖ suffix) ‖ «pad10*1» (8 * rate) (8 * (n - rate) + s))
       (8 * rate) (by grind)
       (padLen_dvd (8 * rate) (8 * (n - rate) + s) (by grind))).cast
        (by have := blocks_count_step (r := 8*rate) (m := 8*(n-rate)+s) (by omega)
            rw [show 8*(n-rate)+s+8*rate = 8*n+s from by omega] at this; exact this) := by
  intro first rest
  have hr0 : 0 < 8 * rate := by omega
  -- `msg = (first ‖ rest).cast`, so `bytesU8ToBits msg` indexed at k splits into
  -- `bytesU8ToBits first[k]` (k < 8*rate) or `bytesU8ToBits rest[k - 8*rate]` (k ≥ 8*rate).
  have hmsg_split : msg = ((first ‖ rest).cast (by omega) : Vector U8 n) := by
    apply Vector.ext; intro i hi
    simp only [Vector.getElem_cast]
    rw [show ((first ‖ rest) : Vector U8 (rate + (n - rate)))[i]'(by omega)
          = ((first ++ rest) : Vector U8 (rate + (n - rate)))[i]'(by omega) from rfl,
        Vector.getElem_append]
    by_cases hi_rate : i < rate
    · simp only [hi_rate, ↓reduceDIte, first, Vector.getElem_cast, Vector.getElem_extract]
      congr 1; omega
    · simp only [hi_rate, ↓reduceDIte, rest, Vector.getElem_cast, Vector.getElem_extract]
      congr 1; omega
  -- Bit-level version: indexing `bytesU8ToBits msg` at k < 8*n splits at 8*rate.
  have hbits_at : ∀ (k : Nat) (hk : k < 8 * n),
      (bytesU8ToBits msg)[k]'hk =
        if hkr : k < 8 * rate then (bytesU8ToBits first)[k]'hkr
        else (bytesU8ToBits rest)[k - 8 * rate]'(by omega) := by
    intro k hk
    conv_lhs => rw [hmsg_split]
    rw [bytesU8ToBits_cast, bytesU8ToBits_append]
    simp only [Vector.getElem_cast]
    rw [show ((bytesU8ToBits first ‖ bytesU8ToBits rest)
              : Vector Bool (8 * rate + 8 * (n - rate)))[k]'(by omega)
          = ((bytesU8ToBits first ++ bytesU8ToBits rest)
              : Vector Bool (8 * rate + 8 * (n - rate)))[k]'(by omega) from rfl,
        Vector.getElem_append]
  -- Now prove the blocks equality pointwise.
  apply Vector.ext; intro i hi
  unfold Spec.SHA3.blocks
  rw [Vector.getElem_cast, Vector.getElem_append]
  simp only [Vector.getElem_ofFn]
  by_cases h0 : i < 1
  · -- Block 0: should equal `bytesU8ToBits first`.
    have heq : i = 0 := by omega
    subst heq
    simp only [show (0 : Nat) < 1 from by decide, ↓reduceDIte]
    show Spec.slice _ _ _ _ = bytesU8ToBits first
    apply Vector.ext; intro j hj
    unfold Spec.slice
    rw [Vector.getElem_ofFn]
    show ((bytesU8ToBits msg ‖ suffix) ‖ «pad10*1» (8 * rate) (8 * n + s))[0 * (8 * rate) + j]'_
       = (bytesU8ToBits first)[j]
    rw [show ((bytesU8ToBits msg ‖ suffix) ‖ «pad10*1» (8 * rate) (8 * n + s))
          = ((bytesU8ToBits msg ‖ suffix) ++ «pad10*1» (8 * rate) (8 * n + s)) from rfl,
        Vector.getElem_append]
    rw [dif_pos (show 0 * (8 * rate) + j < 8 * n + s from by have := hge; omega)]
    rw [show (bytesU8ToBits msg ‖ suffix) = (bytesU8ToBits msg ++ suffix) from rfl,
        Vector.getElem_append]
    rw [dif_pos (show 0 * (8 * rate) + j < 8 * n from by have := hge; omega)]
    -- LHS: bytesU8ToBits msg[0*8*rate + j]. Use hbits_at.
    rw [hbits_at]
    rw [dif_pos (show 0 * (8 * rate) + j < 8 * rate from by omega)]
    congr 1; omega
  · -- Block i ≥ 1: should equal block (i-1) of the rest-padded message.
    simp only [h0, ↓reduceDIte]
    have hi_pos : 0 < i := by omega
    -- Both LHS and RHS are now `slice ...`; ext on j.
    apply Vector.ext; intro j hj
    unfold Spec.slice
    rw [Vector.getElem_ofFn, Vector.getElem_ofFn]
    show ((bytesU8ToBits msg ‖ suffix) ‖ «pad10*1» (8 * rate) (8 * n + s))[i * (8 * rate) + j]'_
       = ((bytesU8ToBits rest ‖ suffix) ‖ «pad10*1» (8 * rate) (8 * (n - rate) + s))[(i - 1) * (8 * rate) + j]'_
    have hk_eq : (i - 1) * (8 * rate) + j = i * (8 * rate) + j - 8 * rate := by
      have : 8 * rate ≤ i * (8 * rate) := Nat.le_mul_of_pos_left _ hi_pos
      rw [Nat.sub_mul, Nat.one_mul]; omega
    rw [show ((bytesU8ToBits msg ‖ suffix) ‖ «pad10*1» (8 * rate) (8 * n + s))
          = ((bytesU8ToBits msg ‖ suffix) ++ «pad10*1» (8 * rate) (8 * n + s)) from rfl,
        Vector.getElem_append]
    rw [show ((bytesU8ToBits rest ‖ suffix) ‖ «pad10*1» (8 * rate) (8 * (n - rate) + s))
          = ((bytesU8ToBits rest ‖ suffix) ++ «pad10*1» (8 * rate) (8 * (n - rate) + s)) from rfl,
        Vector.getElem_append]
    by_cases hpad : i * (8 * rate) + j < 8 * n + s
    · simp only [hpad, ↓reduceDIte]
      have hpad' : (i - 1) * (8 * rate) + j < 8 * (n - rate) + s := by
        rw [hk_eq]; have : 8 * rate ≤ i * (8 * rate) := Nat.le_mul_of_pos_left _ hi_pos
        omega
      simp only [hpad', ↓reduceDIte]
      rw [show (bytesU8ToBits msg ‖ suffix) = (bytesU8ToBits msg ++ suffix) from rfl,
          Vector.getElem_append]
      rw [show (bytesU8ToBits rest ‖ suffix) = (bytesU8ToBits rest ++ suffix) from rfl,
          Vector.getElem_append]
      by_cases hdata : i * (8 * rate) + j < 8 * n
      · simp only [hdata, ↓reduceDIte]
        have hdata' : (i - 1) * (8 * rate) + j < 8 * (n - rate) := by
          rw [hk_eq]; have : 8 * rate ≤ i * (8 * rate) := Nat.le_mul_of_pos_left _ hi_pos
          omega
        simp only [hdata', ↓reduceDIte]
        rw [hbits_at]
        have hk_ge : ¬ i * (8 * rate) + j < 8 * rate := by
          have : 8 * rate ≤ i * (8 * rate) := Nat.le_mul_of_pos_left _ hi_pos
          omega
        rw [dif_neg hk_ge]
        congr 1; rw [hk_eq]
      · -- suffix region
        simp only [hdata, ↓reduceDIte]
        have hdata' : ¬ (i - 1) * (8 * rate) + j < 8 * (n - rate) := by
          rw [hk_eq]; have : 8 * rate ≤ i * (8 * rate) := Nat.le_mul_of_pos_left _ hi_pos
          omega
        simp only [hdata', ↓reduceDIte]
        congr 1; rw [hk_eq]; omega
    · -- pad10*1 region: use closed-form pad10star1_getElem on both sides.
      simp only [hpad, ↓reduceDIte]
      have hpad' : ¬ (i - 1) * (8 * rate) + j < 8 * (n - rate) + s := by
        rw [hk_eq]; have : 8 * rate ≤ i * (8 * rate) := Nat.le_mul_of_pos_left _ hi_pos
        omega
      simp only [hpad', ↓reduceDIte]
      have hidx_eq : i * (8 * rate) + j - (8 * n + s)
                   = (i - 1) * (8 * rate) + j - (8 * (n - rate) + s) := by
        rw [hk_eq]
        have : 8 * rate ≤ i * (8 * rate) := Nat.le_mul_of_pos_left _ hi_pos
        omega
      -- Bound on LHS index for pad10star1_getElem.
      have hbnd_L : i * (8 * rate) + j - (8 * n + s) < padLen (8 * rate) (8 * n + s) := by
        have hi_full : i * (8 * rate) + j < (8 * n + s) + padLen (8 * rate) (8 * n + s) := by
          have hmod := padLen_dvd (8 * rate) (8 * n + s) hr0
          have hdvd : 8 * rate ∣ (8 * n + s) + padLen (8 * rate) (8 * n + s) :=
            Nat.dvd_of_mod_eq_zero hmod
          have hi' : i + 1 ≤ ((8 * n + s) + padLen (8 * rate) (8 * n + s)) / (8 * rate) := hi
          have hmul : (i + 1) * (8 * rate) ≤ ((8 * n + s) + padLen (8 * rate) (8 * n + s)) :=
            calc (i + 1) * (8 * rate)
                ≤ (((8 * n + s) + padLen (8 * rate) (8 * n + s)) / (8 * rate)) * (8 * rate) :=
                    Nat.mul_le_mul_right _ hi'
              _ = (8 * n + s) + padLen (8 * rate) (8 * n + s) := Nat.div_mul_cancel hdvd
          calc i * (8 * rate) + j < i * (8 * rate) + 8 * rate := by omega
            _ = (i + 1) * (8 * rate) := by ring
            _ ≤ (8 * n + s) + padLen (8 * rate) (8 * n + s) := hmul
        omega
      have hbnd_R : (i - 1) * (8 * rate) + j - (8 * (n - rate) + s)
                  < padLen (8 * rate) (8 * (n - rate) + s) := by
        rw [← hidx_eq]
        rw [show padLen (8 * rate) (8 * (n - rate) + s)
              = padLen (8 * rate) (8 * n + s) from by
            have h8n : 8 * n + s = 8 * (n - rate) + s + 8 * rate := by have := hge; omega
            rw [h8n, padLen_period (8*rate) (8*(n-rate)+s)]]
        exact hbnd_L
      rw [pad10star1_getElem _ _ _ hbnd_L, pad10star1_getElem _ _ _ hbnd_R, hidx_eq]
      have hpadLen_eq : padLen (8 * rate) (8 * n + s) = padLen (8 * rate) (8 * (n - rate) + s) := by
        have h8n : 8 * n + s = 8 * (n - rate) + s + 8 * rate := by have := hge; omega
        rw [h8n, padLen_period (8*rate) (8*(n-rate)+s)]
      rw [hpadLen_eq]

/-! ### Sub-lemmas for the BASE case of `absorbBytes_eq_SPONGE_absorb_aux`. -/

/-- **No-permute byte absorb**: when consuming fewer than `rate - idx` bytes,
`absorbBytes` never hits the boundary and reduces to `absorbBytesRaw`. -/
private theorem absorbBytes_no_permute (S : Vector Bool b) (idx rate : Nat)
    (data : List U8) (hbnd : idx + data.length < rate) :
    absorbBytes S idx rate data = (absorbBytesRaw S idx data, idx + data.length) := by
  induction data generalizing S idx with
  | nil =>
    show (S, idx) = (absorbBytesRaw S idx [], idx + 0)
    simp [absorbBytesRaw_nil]
  | cons byte rest ih =>
    show (let S' := absorbByte S idx byte
          let idx' := idx + 1
          if idx' = rate then absorbBytes (KECCAK_f S') 0 rate rest
          else absorbBytes S' idx' rate rest) = _
    have hidx_ne : idx + 1 ≠ rate := by simp [List.length_cons] at hbnd; omega
    simp only [hidx_ne, ↓reduceIte]
    have hbnd' : idx + 1 + rest.length < rate := by simp [List.length_cons] at hbnd; omega
    rw [ih (absorbByte S idx byte) (idx + 1) hbnd']
    -- Bridge: absorbBytesRaw (absorbByte S idx byte) (idx+1) rest = absorbBytesRaw S idx (byte :: rest)
    rw [show absorbBytesRaw S idx (byte :: rest) =
            absorbBytesRaw (absorbByte S idx byte) (idx + 1) rest from by
        rw [show (byte :: rest) = [byte] ++ rest from rfl,
            absorbBytesRaw_append, absorbBytesRaw_singleton,
            show idx + [byte].length = idx + 1 from rfl]]
    simp [List.length_cons]; omega

/-- **`padAndPermute` as XOR**: unfolds the double-`absorbByte` definition
to its algebraic XOR form via `absorbByte_eq_xor`. -/
private theorem padAndPermute_eq_xor (S : Vector Bool b) (idx rate : Nat) (padVal : U8) :
    padAndPermute S idx rate padVal =
    KECCAK_f ((S ⊕ shiftedByte padVal idx) ⊕ shiftedByte 0x80#u8 (rate - 1)) := by
  unfold padAndPermute
  rw [absorbByte_eq_xor, absorbByte_eq_xor]

/-- `absorbBlocks` over a length-1 vector is one `f`-step. -/
private theorem absorbBlocks_one {r : Nat} (f : Vector Bool b → Vector Bool b)
    (init : Vector Bool b) (Bs : Vector (Vector Bool r) 1) :
    Spec.SHA3.absorbBlocks f init Bs = f (init ⊕ Bits.zeroExtend Bs[0] b) := by
  unfold Spec.SHA3.absorbBlocks
  rcases Bs with ⟨arr, harr⟩
  match arr, harr with
  | ⟨[B]⟩, _ => simp [Vector.foldl, Vector.getElem_mk, Array.foldl, Array.foldlM, Array.foldlM.loop]

/-- **Single-block `absorbBlocks`**: when `pLen = r`, the block list is a
singleton and `absorbBlocks f init` applies `f` once on `init ⊕ ext P b`. -/
private theorem absorbBlocks_singleton {pLen r : Nat}
    (P : Vector Bool pLen) (f : Vector Bool b → Vector Bool b)
    (init : Vector Bool b) (hr : 0 < r) (hm : pLen % r = 0)
    (heq : pLen = r) :
    Spec.SHA3.absorbBlocks f init
      (Spec.SHA3.blocks P r hr hm) =
    f (init ⊕ Bits.zeroExtend (P.cast heq) b) := by
  subst heq
  have hlen : pLen / pLen = 1 := Nat.div_self hr
  -- Rewrite the foldl over `Vector _ (pLen/pLen)` to one over `Vector _ 1`.
  have : Spec.SHA3.absorbBlocks f init (Spec.SHA3.blocks P pLen hr hm)
       = Spec.SHA3.absorbBlocks f init
           ((Spec.SHA3.blocks P pLen hr hm).cast hlen) := by
    unfold Spec.SHA3.absorbBlocks
    rfl
  rw [this, absorbBlocks_one]
  -- Goal: f (init ⊕ ext (cast Bs)[0] b) = f (init ⊕ ext (P.cast rfl) b)
  apply congrArg f
  apply congrArg (init ⊕ ·)
  apply congrArg (Bits.zeroExtend · b)
  unfold Spec.SHA3.blocks Spec.slice
  apply Vector.ext; intro i hi
  simp [Vector.getElem_ofFn, Vector.getElem_cast]

/-- When `8*n+s+1 ≤ 8*rate`, the padded length is exactly `8*rate`
(single block). NOTE: this requires `8*n+s+2 ≤ 8*rate` strictly to rule out
the corner `8*n+s = 8*rate-1` where padding spills to a second block. -/
private theorem padded_len_eq_rate {n s rate : Nat} (hr : 0 < rate)
    (hK : 8 * n + s + 2 ≤ 8 * rate) :
    8 * n + s + padLen (8 * rate) (8 * n + s) = 8 * rate := by
  -- padLen.j = ((-(8*n+s)-2) mod (8*rate)).toNat. With 8*n+s+2 ≤ 8*rate,
  -- the integer (-(8*n+s)-2) mod (8*rate) = 8*rate - (8*n+s) - 2.
  show 8 * n + s + (1 + padLen.j (8 * rate) (8 * n + s) + 1) = 8 * rate
  show 8 * n + s + (1 + ((-((8 * n + s : Nat) : Int) - 2) % (8 * rate : Nat)).toNat + 1) = 8 * rate
  have hpos : (0 : Int) < (8 * rate : Nat) := by exact_mod_cast (by omega : 0 < 8 * rate)
  have hmod_eq : (-((8 * n + s : Nat) : Int) - 2) % (8 * rate : Nat)
               = (8 * rate - (8 * n + s) - 2 : Nat) := by
    rw [show (-((8 * n + s : Nat) : Int) - 2)
          = (8 * rate - (8 * n + s) - 2 : Nat) + (8 * rate : Nat) * (-1) from by push_cast; omega,
        Int.add_mul_emod_self_left]
    rw [Int.emod_eq_of_lt (by exact_mod_cast (by omega : 0 ≤ 8 * rate - (8 * n + s) - 2))
                          (by exact_mod_cast (by omega : 8 * rate - (8 * n + s) - 2 < 8 * rate))]
  rw [hmod_eq, Int.toNat_natCast]
  omega

/-! #### Byte-level lifting helpers (reusable across SHA3 verification) -/

/-- Bits of `m` zero bytes are `8*m` zero bits. -/
private theorem bytesU8ToBits_replicate_zero (m : Nat) :
    bytesU8ToBits (Vector.replicate m (0#u8 : U8)) = Vector.replicate (8 * m) false := by
  unfold bytesU8ToBits bytesToBits
  apply Vector.ext; intro i hi
  simp [Vector.getElem_replicate]

/-- The 8 bits of `0x80#u8` are `replicate 7 false ‖ #v[true]`. -/
private theorem bytesU8ToBits_0x80 :
    bytesU8ToBits #v[(0x80#u8 : U8)] =
      (Vector.replicate 7 false ‖ #v[true]).cast (by omega) := by
  unfold bytesU8ToBits bytesToBits
  apply Vector.ext; intro i hi
  simp only [Vector.getElem_ofFn, Vector.getElem_cast]
  have hi8 : i / 8 = 0 := by omega
  have hi8' : i % 8 = i := by omega
  simp only [hi8, hi8', Vector.getElem_map, Vector.getElem_mk, List.getElem_toArray,
             List.getElem_cons_zero]
  rw [show ((Vector.replicate 7 false).append #v[true])[i]'(by omega)
        = ((Vector.replicate 7 false) ++ #v[true])[i]'(by omega) from rfl,
      Vector.getElem_append]
  show (BitVec.ofNat 8 0x80).toNat.testBit i = _
  by_cases h7 : i < 7
  · simp only [h7, ↓reduceDIte, Vector.getElem_replicate]
    rcases i with _|i; · rfl
    rcases i with _|i; · rfl
    rcases i with _|i; · rfl
    rcases i with _|i; · rfl
    rcases i with _|i; · rfl
    rcases i with _|i; · rfl
    rcases i with _|i; · rfl
    omega
  · simp only [h7, ↓reduceDIte]
    have : i = 7 := by omega
    subst this; rfl

/-- **`Bits.toNatLE` recurrence**: peel off the last bit. -/
private theorem toNatLE_succ {n : Nat} (v : Vector Bool (n+1)) :
    Bits.toNatLE v = Bits.toNatLE ((v.take n).cast (Nat.min_eq_left (Nat.le_succ n)))
                   + v[n].toNat * 2^n := by
  show Fin.foldl (n+1) _ 0 = Fin.foldl n _ 0 + _
  rw [Fin.foldl_succ_last]
  congr 1; congr 1; funext acc i; simp

/-- **`Bits.toNatLE` is bounded**: at most `2^n`. -/
private theorem toNatLE_lt_pow {n : Nat} (v : Vector Bool n) : Bits.toNatLE v < 2^n := by
  induction n with
  | zero => show Fin.foldl 0 _ 0 < 1; rw [Fin.foldl_zero]; omega
  | succ k ih =>
    rw [toNatLE_succ]
    have h1 := ih ((v.take k).cast (Nat.min_eq_left (Nat.le_succ k)))
    have h3 : v[k].toNat ≤ 1 := by cases v[k] <;> decide
    have h2 : v[k].toNat * 2^k ≤ 2^k :=
      calc v[k].toNat * 2^k ≤ 1 * 2^k := Nat.mul_le_mul_right _ h3
        _ = 2^k := one_mul _
    rw [pow_succ]; omega

/-- **`testBit` of `Bits.toNatLE`** (in-range): bit `i` is `v[i]`. -/
private theorem testBit_toNatLE_lt {n : Nat} (v : Vector Bool n) (i : Nat) (hi : i < n) :
    (Bits.toNatLE v).testBit i = v[i] := by
  induction n generalizing i with
  | zero => omega
  | succ k ih =>
    rw [toNatLE_succ]
    have hlt := toNatLE_lt_pow ((v.take k).cast (Nat.min_eq_left (Nat.le_succ k)))
    rw [show Bits.toNatLE ((v.take k).cast (Nat.min_eq_left (Nat.le_succ k))) + v[k].toNat * 2^k
          = 2^k * v[k].toNat + Bits.toNatLE ((v.take k).cast (Nat.min_eq_left (Nat.le_succ k)))
          from by ring]
    rw [Nat.testBit_two_pow_mul_add _ hlt]
    by_cases hik : i < k
    · simp only [hik, ↓reduceIte]
      rw [ih _ _ hik]; simp
    · simp only [hik, ↓reduceIte]
      have hi_eq : i = k := by omega
      subst hi_eq
      rw [Nat.sub_self]
      simp [Nat.testBit_zero]
      cases v[i] <;> decide

/-- **`testBit` of `Bits.toNatLE`** (out-of-range): bit `i ≥ n` is `false`. -/
private theorem testBit_toNatLE_ge {n : Nat} (v : Vector Bool n) (i : Nat) (hi : n ≤ i) :
    (Bits.toNatLE v).testBit i = false := by
  exact Nat.testBit_lt_two_pow
    (lt_of_lt_of_le (toNatLE_lt_pow v) (Nat.pow_le_pow_right (by omega) hi))

/-- The 8 bits of `encodePadVal suffix hs` are `(suffix ‖ #v[true]) ‖ replicate (7-s) false`. -/
private theorem bytesU8ToBits_encodePadVal {s} (suffix : Vector Bool s) (hs : s + 1 ≤ 8) :
    bytesU8ToBits #v[encodePadVal suffix hs] =
      ((suffix ‖ #v[true]) ‖ Vector.replicate (7 - s) false).cast (by omega) := by
  apply Vector.ext; intro i hi
  unfold bytesU8ToBits bytesToBits
  simp only [Vector.getElem_ofFn, Vector.getElem_cast]
  have hi8 : i < 8 := by omega
  have hdiv : i / 8 = 0 := Nat.div_eq_of_lt hi8
  have hmod : i % 8 = i := Nat.mod_eq_of_lt hi8
  rw [show ((#v[encodePadVal suffix hs]).map (·.bv))[i / 8].toNat.testBit (i % 8)
        = (encodePadVal suffix hs).bv.toNat.testBit i from by
      simp only [Vector.getElem_map, hmod]
      congr 2
      have : (#v[encodePadVal suffix hs])[i / 8]'(by omega : i / 8 < 1)
           = (#v[encodePadVal suffix hs])[0]'(by decide) := by congr 1
      rw [this]; rfl]
  unfold encodePadVal
  show (BitVec.ofNat 8 (Bits.toNatLE (suffix ‖ #v[true]))).toNat.testBit i = _
  rw [BitVec.toNat_ofNat]
  rw [show 2^8 = 256 from rfl]
  have hbnd : Bits.toNatLE (suffix ‖ #v[true]) < 256 := by
    have := toNatLE_lt_pow (suffix ‖ #v[true])
    have : 2^(s + 1) ≤ 2^8 := Nat.pow_le_pow_right (by decide) hs
    omega
  rw [Nat.mod_eq_of_lt hbnd]
  rw [show ((suffix ‖ #v[true]) ‖ Vector.replicate (7 - s) false)
        = ((suffix ‖ #v[true]) ++ Vector.replicate (7 - s) false) from rfl,
      Vector.getElem_append]
  by_cases hi_le_s : i < s + 1
  · rw [testBit_toNatLE_lt _ _ hi_le_s]
    simp [hi_le_s]
  · rw [testBit_toNatLE_ge _ _ (by omega)]
    simp [hi_le_s]

/-! #### XOR algebra on `Vector Bool n` -/

/-- XOR associativity. -/
private theorem xor_assoc_v {n : Nat} (X Y Z : Vector Bool n) :
    (X ^^^ Y) ^^^ Z = X ^^^ (Y ^^^ Z) := by
  apply Vector.ext; intro i hi
  show (Vector.zipWith (· != ·) (Vector.zipWith (· != ·) X Y) Z)[i]
     = (Vector.zipWith (· != ·) X (Vector.zipWith (· != ·) Y Z))[i]
  repeat rw [Vector.getElem_zipWith]
  cases X[i] <;> cases Y[i] <;> cases Z[i] <;> rfl

/-- XOR commutativity. -/
private theorem xor_comm_v {n : Nat} (X Y : Vector Bool n) : X ^^^ Y = Y ^^^ X := by
  apply Vector.ext; intro i hi
  show (Vector.zipWith (· != ·) X Y)[i] = (Vector.zipWith (· != ·) Y X)[i]
  rw [Vector.getElem_zipWith, Vector.getElem_zipWith]
  cases X[i] <;> cases Y[i] <;> rfl

/-- XOR with the all-`false` vector is identity (right). -/
private theorem xor_replicate_false_right {n : Nat} (X : Vector Bool n) :
    (X ^^^ Vector.replicate n false : Vector Bool n) = X := by
  apply Vector.ext; intro i hi
  show (Vector.zipWith (· != ·) X (Vector.replicate n false))[i] = X[i]
  rw [Vector.getElem_zipWith, Vector.getElem_replicate]
  cases X[i] <;> rfl

/-- XOR with the all-`false` vector is identity (left). -/
private theorem xor_replicate_false_left {n : Nat} (X : Vector Bool n) :
    (Vector.replicate n false ^^^ X : Vector Bool n) = X := by
  apply Vector.ext; intro i hi
  show (Vector.zipWith (· != ·) (Vector.replicate n false) X)[i] = X[i]
  rw [Vector.getElem_zipWith, Vector.getElem_replicate]
  cases X[i] <;> rfl

/-- **Concat-as-XOR (basic algebraic identity)**: a concat is the XOR of two
zero-padded vectors (when extended to a common length). For `X : Vector Bool m`,
`Y : Vector Bool k`:
  `X ‖ Y = (X ‖ replicate k false) ⊕ (replicate m false ‖ Y)`. -/
private theorem concat_eq_xor_zero_padded {m k : Nat} (X : Vector Bool m) (Y : Vector Bool k) :
    X ‖ Y =
    (X ‖ Vector.replicate k false : Vector Bool (m + k))
      ^^^ (Vector.replicate m false ‖ Y : Vector Bool (m + k)) := by
  apply Vector.ext; intro i hi
  show (X.append Y)[i] = (Vector.zipWith (· != ·) (X.append (Vector.replicate k false))
                            (Vector.append (Vector.replicate m false) Y))[i]
  rw [Vector.getElem_zipWith]
  rw [show (X.append Y)[i] = (X ++ Y)[i] from rfl,
      show (X.append (Vector.replicate k false))[i] = (X ++ Vector.replicate k false)[i] from rfl,
      show ((Vector.replicate m false).append Y)[i] = (Vector.replicate m false ++ Y)[i] from rfl]
  rw [Vector.getElem_append, Vector.getElem_append, Vector.getElem_append]
  by_cases hi_m : i < m
  · simp only [hi_m, ↓reduceDIte]
    rw [Vector.getElem_replicate]
    cases X[i] <;> rfl
  · simp only [hi_m, ↓reduceDIte]
    rw [Vector.getElem_replicate]
    cases Y[i - m]'(by omega) <;> rfl

/-- XOR distributes over a common left-prefix (factoring zeros). -/
private theorem xor_factor_left_prefix {m k : Nat}
    (X Y : Vector Bool k) :
    ((Vector.replicate m false ‖ X : Vector Bool (m + k))
      ^^^ (Vector.replicate m false ‖ Y : Vector Bool (m + k)))
    = (Vector.replicate m false ‖ (X ^^^ Y) : Vector Bool (m + k)) := by
  apply Vector.ext; intro i hi
  show (Vector.zipWith (· != ·)
          (Vector.append (Vector.replicate m false) X)
          (Vector.append (Vector.replicate m false) Y))[i]
     = (Vector.append (Vector.replicate m false) (Vector.zipWith (· != ·) X Y))[i]
  rw [Vector.getElem_zipWith]
  rw [show ((Vector.replicate m false).append X)[i] = (Vector.replicate m false ++ X)[i] from rfl,
      show ((Vector.replicate m false).append Y)[i] = (Vector.replicate m false ++ Y)[i] from rfl,
      show ((Vector.replicate m false).append (Vector.zipWith (· != ·) X Y))[i]
            = (Vector.replicate m false ++ Vector.zipWith (· != ·) X Y)[i] from rfl]
  rw [Vector.getElem_append, Vector.getElem_append, Vector.getElem_append]
  by_cases hi_m : i < m
  · simp only [hi_m, ↓reduceDIte]
    rw [Vector.getElem_replicate]; rfl
  · simp only [hi_m, ↓reduceDIte]
    rw [Vector.getElem_zipWith]

/-! #### Bit-level / byte-level placement bridges -/

/-- `Bits.zeroExtend (X ‖ Y) B = ext X B ⊕ ext (replicate |X| false ‖ Y) B`. -/
private theorem zeroExtend_append {m k B : Nat} (X : Vector Bool m) (Y : Vector Bool k) :
    Bits.zeroExtend (X ‖ Y) B
    = (Bits.zeroExtend X B : Vector Bool B)
      ^^^ Bits.zeroExtend (Vector.replicate m false ‖ Y : Vector Bool (m + k)) B := by
  apply Vector.ext; intro i hi
  show (Bits.zeroExtend (X.append Y) B)[i]
     = (Vector.zipWith (· != ·) (Bits.zeroExtend X B) (Bits.zeroExtend (Vector.append _ Y) B))[i]
  rw [Vector.getElem_zipWith]
  unfold Bits.zeroExtend
  rw [Vector.getElem_ofFn, Vector.getElem_ofFn, Vector.getElem_ofFn]
  by_cases hi_m : i < m
  · -- i < m: append-left on both sides
    have hi_mk : i < m + k := by omega
    simp only [hi_m, hi_mk, ↓reduceDIte]
    show ((X.append Y)[i]'(by omega)) = _
    rw [show (X.append Y)[i]'(by omega) = (X ++ Y)[i]'(by omega) from rfl,
        Vector.getElem_append]
    simp only [hi_m, ↓reduceDIte]
    rw [show ((Vector.replicate m false).append Y)[i]'hi_mk
            = (Vector.replicate m false ++ Y)[i]'hi_mk from rfl,
        Vector.getElem_append]
    simp only [hi_m, ↓reduceDIte]
    rw [Vector.getElem_replicate]
    cases X[i] <;> rfl
  · -- i ≥ m
    simp only [hi_m, ↓reduceDIte]
    by_cases hi_mk : i < m + k
    · simp only [hi_mk, ↓reduceDIte]
      show ((X.append Y)[i]'(by omega)) = _
      rw [show (X.append Y)[i]'(by omega) = (X ++ Y)[i]'(by omega) from rfl,
          Vector.getElem_append]
      simp only [hi_m, ↓reduceDIte]
      rw [show ((Vector.replicate m false).append Y)[i]'hi_mk
              = (Vector.replicate m false ++ Y)[i]'hi_mk from rfl,
          Vector.getElem_append]
      simp only [hi_m, ↓reduceDIte]
      cases Y[i - m]'(by omega) <;> rfl
    · simp only [hi_mk, ↓reduceDIte]
      rfl

/-- `(bytesU8ToBits #v[val])[i] = val.bv.getLsbD i` — single-byte indexing. -/
private theorem byte_getLsbD_eq (val : U8) (i : Nat) (hi : i < 8) :
    val.bv.getLsbD i = (bytesU8ToBits #v[val])[i]'(by omega) := by
  unfold bytesU8ToBits bytesToBits
  simp only [Vector.getElem_ofFn, Vector.getElem_map]
  have hmod : i % 8 = i := Nat.mod_eq_of_lt hi
  show val.bv.getLsbD i = (#v[val] : Vector U8 1)[i / 8].bv.toNat.testBit (i % 8)
  rw [hmod, Vector.getElem_singleton, BitVec.testBit_toNat]

/-- `shiftedByte val k` is the bit-extension of a length-`8*rate` vector with
`val`'s bits at byte position `k` and zeros elsewhere. (Specialised to fit
the `base_bit_identity` proof, where `rate` is the natural total length.) -/
private theorem shiftedByte_eq_zeroExtend_aligned (val : U8) (k rate : Nat)
    (hk : k < rate) :
    shiftedByte val k = Bits.zeroExtend
      ((Vector.replicate (8 * k) false ‖ bytesU8ToBits #v[val] ‖
          Vector.replicate (8 * (rate - k - 1)) false).cast (by omega) : Vector Bool (8 * rate)) b := by
  apply Vector.ext; intro j hj
  rw [shiftedByte_getElem _ _ _ hj]
  unfold Bits.zeroExtend
  rw [Vector.getElem_ofFn]
  by_cases hj_8r : j < 8 * rate
  · simp only [hj_8r, ↓reduceDIte, Vector.getElem_cast]
    rw [show ((Vector.replicate (8 * k) false ‖ bytesU8ToBits #v[val]) ‖
              Vector.replicate (8 * (rate - k - 1)) false)
            = ((Vector.replicate (8 * k) false ‖ bytesU8ToBits #v[val]) ++
              Vector.replicate (8 * (rate - k - 1)) false) from rfl,
        Vector.getElem_append]
    by_cases hj_lo : j < 8 * k + 8
    · simp only [hj_lo, ↓reduceDIte]
      rw [show ((Vector.replicate (8 * k) false ‖ bytesU8ToBits #v[val])
                : Vector Bool (8 * k + 8 * 1))
            = ((Vector.replicate (8 * k) false ++ bytesU8ToBits #v[val])
                : Vector Bool (8 * k + 8 * 1)) from rfl,
          Vector.getElem_append]
      by_cases hj_k : j < 8 * k
      · simp only [hj_k, ↓reduceDIte, Vector.getElem_replicate]
        have : ¬ (8 * k ≤ j) := by omega
        simp [this]
      · simp only [hj_k, ↓reduceDIte]
        have hj_mid : 8 * k ≤ j ∧ j < 8 * k + 8 := by omega
        simp only [hj_mid, Bool.decide_true, Bool.true_and, and_self]
        rw [byte_getLsbD_eq val (j - 8 * k) (by omega)]
    · simp only [hj_lo, ↓reduceDIte, Vector.getElem_replicate]
      have : ¬ (8 * k ≤ j ∧ j < 8 * k + 8) := by intro ⟨_, h⟩; omega
      simp
  · simp only [hj_8r, ↓reduceDIte]
    have : ¬ (8 * k ≤ j ∧ j < 8 * k + 8) := by intro ⟨_, h⟩; omega
    simp [this]

/-- `Bits.zeroExtend` distributes over XOR (when both sides have the same length). -/
private theorem zeroExtend_xor_distrib {n B : Nat} (X Y : Vector Bool n) :
    Bits.zeroExtend (X ^^^ Y) B
    = (Bits.zeroExtend X B : Vector Bool B) ^^^ Bits.zeroExtend Y B := by
  apply Vector.ext; intro i hi
  unfold Bits.zeroExtend
  show (Vector.ofFn _)[i] = (Vector.zipWith (· != ·) (Vector.ofFn _) (Vector.ofFn _))[i]
  rw [Vector.getElem_zipWith, Vector.getElem_ofFn, Vector.getElem_ofFn, Vector.getElem_ofFn]
  by_cases hi_n : i < n
  · simp only [hi_n, ↓reduceDIte]
    show (Vector.zipWith (· != ·) X Y)[i] = _
    rw [Vector.getElem_zipWith]
  · simp only [hi_n, ↓reduceDIte]
    rfl

/-! #### `pad10*1` definitional unfolding -/

private theorem pad10star1_def (r m : Nat) :
    «pad10*1» r m = (#v[true] ‖ Vector.replicate (padLen.j r m) false) ‖ #v[true] := rfl

/-! #### Length-aligned helpers (canonical length: `8 * rate` for the active region) -/

/-- `Bits.zeroExtend (bytesU8ToBits msg) b` viewed at the canonical
length-`8*rate` form, with zeros padding the high `8*(rate-n)` bits. -/
private theorem msg_at_8rate {n} (msg : Vector U8 n) (rate : Nat)
    (hge : n ≤ rate) :
    Bits.zeroExtend (bytesU8ToBits msg) b
    = Bits.zeroExtend ((bytesU8ToBits msg ‖ Vector.replicate (8 * (rate - n)) false).cast
        (by show 8 * n + 8 * (rate - n) = 8 * rate; omega) : Vector Bool (8 * rate)) b := by
  apply Vector.ext; intro i hi
  unfold Bits.zeroExtend
  simp only [Vector.getElem_ofFn]
  by_cases hi_8n : i < 8 * n
  · have hi_8r : i < 8 * rate := by omega
    simp only [hi_8n, hi_8r, ↓reduceDIte, Vector.getElem_cast]
    rw [show ((bytesU8ToBits msg ‖ Vector.replicate (8 * (rate - n)) false)
              : Vector Bool (8 * n + 8 * (rate - n)))[i]'(by omega)
          = ((bytesU8ToBits msg ++ Vector.replicate (8 * (rate - n)) false)
              : Vector Bool (8 * n + 8 * (rate - n)))[i]'(by omega) from rfl,
        Vector.getElem_append]
    simp [hi_8n]
  · simp only [hi_8n, ↓reduceDIte]
    by_cases hi_8r : i < 8 * rate
    · simp only [hi_8r, ↓reduceDIte, Vector.getElem_cast]
      rw [show ((bytesU8ToBits msg ‖ Vector.replicate (8 * (rate - n)) false)
                : Vector Bool (8 * n + 8 * (rate - n)))[i]'(by omega)
            = ((bytesU8ToBits msg ++ Vector.replicate (8 * (rate - n)) false)
                : Vector Bool (8 * n + 8 * (rate - n)))[i]'(by omega) from rfl,
          Vector.getElem_append]
      simp [hi_8n]
    · simp only [hi_8r, ↓reduceDIte]

/-- **Aligned-byte index closed form**: a `Vector Bool (8*rate)` formed by
zero-padding a single byte at byte-position `k` returns the byte's bit when
indexed within the byte's range, and `false` elsewhere. -/
private theorem aligned_byte_getElem (val : U8) (k rate : Nat) (hk : k < rate)
    (i : Nat) (hi : i < 8 * rate) :
    ((Vector.replicate (8 * k) false ‖ bytesU8ToBits #v[val] ‖
        Vector.replicate (8 * (rate - k - 1)) false).cast (by omega) : Vector Bool (8 * rate))[i]'hi
    = if 8 * k ≤ i ∧ i < 8 * k + 8 then val.bv.getLsbD (i - 8 * k) else false := by
  rw [Vector.getElem_cast]
  rw [show ((Vector.replicate (8 * k) false ‖ bytesU8ToBits #v[val]) ‖
            Vector.replicate (8 * (rate - k - 1)) false)
          = ((Vector.replicate (8 * k) false ‖ bytesU8ToBits #v[val]) ++
            Vector.replicate (8 * (rate - k - 1)) false) from rfl,
      Vector.getElem_append]
  by_cases hi_lo : i < 8 * k + 8
  · simp only [hi_lo, ↓reduceDIte]
    rw [show ((Vector.replicate (8 * k) false ‖ bytesU8ToBits #v[val])
              : Vector Bool (8 * k + 8 * 1))
            = ((Vector.replicate (8 * k) false ++ bytesU8ToBits #v[val])
              : Vector Bool (8 * k + 8 * 1)) from rfl,
        Vector.getElem_append]
    by_cases hi_k : i < 8 * k
    · simp only [hi_k, ↓reduceDIte, Vector.getElem_replicate]
      have : ¬ (8 * k ≤ i) := by omega
      simp [this]
    · simp only [hi_k, ↓reduceDIte]
      have hi_mid : 8 * k ≤ i ∧ i < 8 * k + 8 := by omega
      simp only [hi_mid, and_self, if_true]
      rw [byte_getLsbD_eq val (i - 8 * k) (by omega)]
  · simp only [hi_lo, ↓reduceDIte, Vector.getElem_replicate]
    have : ¬ (i < 8 * k + 8) := hi_lo
    simp

/-- The byte `0x80` has only its high bit set: bit 7 is `true`, others `false`. -/
private theorem getLsbD_0x80 (j : Nat) (hj : j < 8) :
    (0x80#u8 : U8).bv.getLsbD j = decide (j = 7) := by
  rcases j with _|_|_|_|_|_|_|_|j
  all_goals first | decide | omega

/-- Bit-level decomposition of `encodePadVal suffix hs`: bit `j` is `suffix[j]`
if `j < s`, the trailing `1` if `j = s`, else `false`. -/
private theorem getLsbD_encodePadVal {s} (suffix : Vector Bool s) (hs : s + 1 ≤ 8)
    (j : Nat) (hj : j < 8) :
    (encodePadVal suffix hs).bv.getLsbD j =
      if h : j < s then suffix[j]'h else if j = s then true else false := by
  rw [byte_getLsbD_eq (encodePadVal suffix hs) j hj, bytesU8ToBits_encodePadVal]
  rw [Vector.getElem_cast]
  rw [show ((suffix ‖ #v[true]) ‖ Vector.replicate (7 - s) false)
        = ((suffix ‖ #v[true]) ++ Vector.replicate (7 - s) false) from rfl,
      Vector.getElem_append]
  by_cases hj_le : j < s + 1
  · simp only [hj_le, ↓reduceDIte]
    rw [show ((suffix ‖ #v[true]) : Vector Bool (s + 1))
          = ((suffix ++ #v[true]) : Vector Bool (s + 1)) from rfl,
        Vector.getElem_append]
    by_cases hjs : j < s
    · simp [hjs]
    · simp only [hjs, ↓reduceDIte]
      have hjeq : j = s := by omega
      subst hjeq
      simp
  · simp only [hj_le, ↓reduceDIte, Vector.getElem_replicate]
    have h1 : ¬ (j < s) := by omega
    have h2 : ¬ (j = s) := by omega
    simp [h1, h2]

/-- The RHS pad-bridging lemma: at length `8*rate`, the XOR of the three
length-`8*rate` LHS contributions equals the canonical RHS bit-string. -/
private theorem bit_identity_8rate {n s} (msg : Vector U8 n) (suffix : Vector Bool s)
    (rate : Nat) (hs : s + 1 ≤ 8) (hr : 0 < rate ∧ 8 * rate < b)
    (hK : 8 * n + s + 2 ≤ 8 * rate) :
    ((((bytesU8ToBits msg ‖ Vector.replicate (8 * (rate - n)) false).cast
          (by have := padded_len_eq_rate hr.1 hK; omega) : Vector Bool (8 * rate))
        ^^^ ((Vector.replicate (8 * n) false ‖ bytesU8ToBits #v[encodePadVal suffix hs]
              ‖ Vector.replicate (8 * (rate - n - 1)) false).cast
            (by have := padded_len_eq_rate hr.1 hK; omega) : Vector Bool (8 * rate)))
        ^^^ ((Vector.replicate (8 * (rate - 1)) false ‖ bytesU8ToBits #v[(0x80#u8 : U8)]
              ‖ Vector.replicate (8 * (rate - (rate - 1) - 1)) false).cast
            (by have := padded_len_eq_rate hr.1 hK; omega) : Vector Bool (8 * rate)))
    = ((bytesU8ToBits msg ‖ suffix) ‖ «pad10*1» (8 * rate) (8 * n + s)).cast
        (padded_len_eq_rate hr.1 hK) := by
  have hn_rate : n ≤ rate - 1 := by
    by_contra h; push Not at h; omega
  have hpadLen : padLen (8 * rate) (8 * n + s) = 8 * rate - (8 * n + s) := by
    have := padded_len_eq_rate hr.1 hK; omega
  apply Vector.ext; intro i hi
  show (Vector.zipWith _ (Vector.zipWith _ _ _) _)[i] = _
  rw [Vector.getElem_zipWith, Vector.getElem_zipWith]
  rw [show ((Vector.replicate (8 * (rate - 1)) false ‖ bytesU8ToBits #v[(0x80#u8 : U8)]
            ‖ Vector.replicate (8 * (rate - (rate - 1) - 1)) false).cast _
            : Vector Bool (8 * rate))[i]'hi
        = if 8 * (rate - 1) ≤ i ∧ i < 8 * (rate - 1) + 8 then
            (0x80#u8 : U8).bv.getLsbD (i - 8 * (rate - 1)) else false from
      aligned_byte_getElem (0x80#u8 : U8) (rate - 1) rate (by omega) i hi]
  rw [show ((Vector.replicate (8 * n) false ‖ bytesU8ToBits #v[encodePadVal suffix hs]
            ‖ Vector.replicate (8 * (rate - n - 1)) false).cast _
            : Vector Bool (8 * rate))[i]'hi
        = if 8 * n ≤ i ∧ i < 8 * n + 8 then
            (encodePadVal suffix hs).bv.getLsbD (i - 8 * n) else false from
      aligned_byte_getElem (encodePadVal suffix hs) n rate (by omega) i hi]
  rw [Vector.getElem_cast,
      show ((bytesU8ToBits msg ‖ Vector.replicate (8 * (rate - n)) false)
              : Vector Bool (8 * n + 8 * (rate - n)))[i]'(by omega)
          = ((bytesU8ToBits msg ++ Vector.replicate (8 * (rate - n)) false)
              : Vector Bool (8 * n + 8 * (rate - n)))[i]'(by omega) from rfl,
      Vector.getElem_append]
  rw [Vector.getElem_cast,
      show (((bytesU8ToBits msg ‖ suffix) ‖ «pad10*1» (8 * rate) (8 * n + s))
              : Vector Bool (8 * n + s + padLen (8 * rate) (8 * n + s)))[i]'(by omega)
          = (((bytesU8ToBits msg ‖ suffix) ++ «pad10*1» (8 * rate) (8 * n + s))
              : Vector Bool (8 * n + s + padLen (8 * rate) (8 * n + s)))[i]'(by omega) from rfl,
      Vector.getElem_append]
  by_cases hT1 : i < 8 * n
  · have hT2_off : ¬ (8 * n ≤ i ∧ i < 8 * n + 8) := by intro ⟨h, _⟩; omega
    have hT3_off : ¬ (8 * (rate - 1) ≤ i ∧ i < 8 * (rate - 1) + 8) := by
      intro ⟨h, _⟩; omega
    have hRHS_msg : i < 8 * n + s := by omega
    simp only [hRHS_msg, ↓reduceDIte]
    rw [show (bytesU8ToBits msg ‖ suffix)[i]'hRHS_msg
              = (bytesU8ToBits msg ++ suffix)[i]'hRHS_msg from rfl,
        Vector.getElem_append]
    simp [hT1, hT2_off, hT3_off]
  push Not at hT1
  have hT1_false :
    (if h : i < 8 * n then (bytesU8ToBits msg)[i]'h
      else (Vector.replicate (8 * (rate - n)) false)[i - 8 * n]'(by omega)) = false := by
    have : ¬ i < 8 * n := by omega
    simp [this, Vector.getElem_replicate]
  rw [hT1_false]
  by_cases hT3 : 8 * (rate - 1) ≤ i
  · have hT3_lo : 8 * (rate - 1) ≤ i := hT3
    have hT3_hi : i < 8 * (rate - 1) + 8 := by omega
    rw [if_pos (show 8 * (rate - 1) ≤ i ∧ i < 8 * (rate - 1) + 8 from ⟨hT3_lo, hT3_hi⟩)]
    rw [getLsbD_0x80 (i - 8 * (rate - 1)) (by omega)]
    by_cases hn_eq : n = rate - 1
    · have hn8 : 8 * n = 8 * (rate - 1) := by rw [hn_eq]
      have hT2 : 8 * n ≤ i ∧ i < 8 * n + 8 := by rw [hn8]; exact ⟨hT3_lo, by omega⟩
      rw [if_pos hT2]
      rw [getLsbD_encodePadVal suffix hs (i - 8 * n) (by omega)]
      have hs_le_6 : s ≤ 6 := by
        have : 8 * n + s + 2 ≤ 8 * rate := hK
        rw [hn_eq] at this; omega
      by_cases hi_lo : i < 8 * n + s
      · simp only [hi_lo, ↓reduceDIte]
        rw [show (bytesU8ToBits msg ‖ suffix)[i]'hi_lo
                = (bytesU8ToBits msg ++ suffix)[i]'hi_lo from rfl,
            Vector.getElem_append]
        have : ¬ i < 8 * n := by omega
        simp only [this, ↓reduceDIte]
        have hi_ne : i ≠ 8 * rate - 1 := by omega
        have hT3_calc : ¬ (i - 8 * (rate - 1) = 7) := by omega
        simp [show i - 8 * n < s from by omega, hT3_calc]
      · push Not at hi_lo
        have h_neg : ¬ i < 8 * n + s := by omega
        simp only [h_neg, ↓reduceDIte]
        rw [pad10star1_getElem (8 * rate) (8 * n + s) (i - (8 * n + s)) (by rw [hpadLen]; omega)]
        by_cases hi_eq_s : i = 8 * n + s
        · subst hi_eq_s
          have h_isub : (8 * n + s - 8 * n : Nat) = s := by omega
          rw [h_isub]
          have h_iso : ¬ (s < s) := by omega
          have hT3_calc : ¬ (8 * n + s - 8 * (rate - 1) = 7) := by rw [hn_eq]; omega
          have hpad_calc : (8 * n + s - (8 * n + s) = 0 ∨
                          8 * n + s - (8 * n + s) = padLen (8 * rate) (8 * n + s) - 1) := by
            left; omega
          simp [hT3_calc]
        · have hi_gt : i > 8 * n + s := by omega
          have h_iso : ¬ (i - 8 * n < s) := by omega
          have h_ies : ¬ (i - 8 * n = s) := by omega
          by_cases hi_last : i = 8 * rate - 1
          · subst hi_last
            have hT3_calc : (8 * rate - 1 - 8 * (rate - 1) = 7) := by
              have : rate ≥ 1 := by omega
              omega
            have hpad_calc : (8 * rate - 1 - (8 * n + s) = 0 ∨
                          8 * rate - 1 - (8 * n + s) = 1 + padLen.j (8 * rate) (8 * n + s)) := by
              right
              show 8 * rate - 1 - (8 * n + s) = padLen (8 * rate) (8 * n + s) - 1
              rw [hpadLen]; omega
            simp [h_iso, h_ies, hT3_calc, hpad_calc]
          · have hT3_calc : ¬ (i - 8 * (rate - 1) = 7) := by
              have h1 : 8 * (rate - 1) ≤ i := hT3_lo
              omega
            have hpad_calc : ¬ (i - (8 * n + s) = 0 ∨
                          i - (8 * n + s) = 1 + padLen.j (8 * rate) (8 * n + s)) := by
              show ¬ (i - (8 * n + s) = 0 ∨
                      i - (8 * n + s) = padLen (8 * rate) (8 * n + s) - 1)
              rw [hpadLen]; intro h
              cases h with
              | inl h => omega
              | inr h => omega
            simp [h_iso, h_ies, hT3_calc, hpad_calc]
    · have hn_lt : n ≤ rate - 2 := by omega
      have hT2_off : ¬ (8 * n ≤ i ∧ i < 8 * n + 8) := by
        intro ⟨_, h⟩; omega
      rw [if_neg hT2_off]
      have hi_pad : i ≥ 8 * n + s := by omega
      have h_suf_off : ¬ i < 8 * n + s := by omega
      simp only [h_suf_off, ↓reduceDIte]
      rw [pad10star1_getElem (8 * rate) (8 * n + s) (i - (8 * n + s)) (by rw [hpadLen]; omega)]
      by_cases hi_last : i = 8 * rate - 1
      · subst hi_last
        have hT3_calc : (8 * rate - 1 - 8 * (rate - 1) = 7) := by omega
        have hpad_calc : (8 * rate - 1 - (8 * n + s) = 0 ∨
                      8 * rate - 1 - (8 * n + s) = 1 + padLen.j (8 * rate) (8 * n + s)) := by
          right
          show 8 * rate - 1 - (8 * n + s) = padLen (8 * rate) (8 * n + s) - 1
          rw [hpadLen]; omega
        simp [hT3_calc, hpad_calc]
      · have hT3_calc : ¬ (i - 8 * (rate - 1) = 7) := by omega
        have hpad_calc : ¬ (i - (8 * n + s) = 0 ∨
                      i - (8 * n + s) = 1 + padLen.j (8 * rate) (8 * n + s)) := by
          show ¬ (i - (8 * n + s) = 0 ∨
                  i - (8 * n + s) = padLen (8 * rate) (8 * n + s) - 1)
          rw [hpadLen]; intro h
          cases h with
          | inl h => omega
          | inr h => omega
        simp [hT3_calc, hpad_calc]
  push Not at hT3
  have hT3_off : ¬ (8 * (rate - 1) ≤ i ∧ i < 8 * (rate - 1) + 8) := by
    intro ⟨h, _⟩; omega
  rw [if_neg hT3_off]
  simp only [Bool.bne_false]
  by_cases hT2_in : i < 8 * n + 8
  · have hT2 : 8 * n ≤ i ∧ i < 8 * n + 8 := ⟨hT1, hT2_in⟩
    rw [if_pos hT2]
    rw [getLsbD_encodePadVal suffix hs (i - 8 * n) (by omega)]
    have h_msg_off : ¬ i < 8 * n := by omega
    by_cases hi_lt_s : i - 8 * n < s
    · have h_in_suf : i < 8 * n + s := by omega
      simp only [h_in_suf, ↓reduceDIte]
      rw [show (bytesU8ToBits msg ‖ suffix)[i]'h_in_suf
              = (bytesU8ToBits msg ++ suffix)[i]'h_in_suf from rfl,
          Vector.getElem_append]
      simp only [h_msg_off, ↓reduceDIte]
      simp [hi_lt_s]
    · by_cases hi_eq_s : i - 8 * n = s
      · have hi_eq : i = 8 * n + s := by omega
        subst hi_eq
        have h_in_pad : ¬ (8 * n + s < 8 * n + s) := by omega
        simp only [h_in_pad, ↓reduceDIte]
        rw [pad10star1_getElem (8 * rate) (8 * n + s) (8 * n + s - (8 * n + s))
              (by rw [hpadLen]; omega)]
        have h_iso : ¬ (s < s) := by omega
        have hpad_calc : (8 * n + s - (8 * n + s) = 0 ∨
                      8 * n + s - (8 * n + s) = 1 + padLen.j (8 * rate) (8 * n + s)) := by
          left; omega
        simp
      · have h_gt_s : i > 8 * n + s := by omega
        have h_in_pad : ¬ (i < 8 * n + s) := by omega
        simp only [h_in_pad, ↓reduceDIte]
        rw [pad10star1_getElem (8 * rate) (8 * n + s) (i - (8 * n + s))
              (by rw [hpadLen]; omega)]
        have hpad_calc : ¬ (i - (8 * n + s) = 0 ∨
                      i - (8 * n + s) = 1 + padLen.j (8 * rate) (8 * n + s)) := by
          show ¬ (i - (8 * n + s) = 0 ∨
                  i - (8 * n + s) = padLen (8 * rate) (8 * n + s) - 1)
          rw [hpadLen]; intro h
          cases h with
          | inl h => omega
          | inr h => omega
        simp [hi_lt_s, hi_eq_s, hpad_calc]
  · push Not at hT2_in
    have hT2_off : ¬ (8 * n ≤ i ∧ i < 8 * n + 8) := by intro ⟨_, h⟩; omega
    rw [if_neg hT2_off]
    have h_in_pad : ¬ (i < 8 * n + s) := by omega
    simp only [h_in_pad, ↓reduceDIte]
    rw [pad10star1_getElem (8 * rate) (8 * n + s) (i - (8 * n + s)) (by rw [hpadLen]; omega)]
    have hpad_calc : ¬ (i - (8 * n + s) = 0 ∨
                  i - (8 * n + s) = 1 + padLen.j (8 * rate) (8 * n + s)) := by
      show ¬ (i - (8 * n + s) = 0 ∨
              i - (8 * n + s) = padLen (8 * rate) (8 * n + s) - 1)
      rw [hpadLen]; intro h
      cases h with
      | inl h => omega
      | inr h => omega
    simp [hpad_calc]

/-- **Base-case bit identity**: when `n < rate` and `s+1 ≤ 8`, the XOR of the
message bits, the encoded pad value at position `n`, and the trailing `0x80`
at position `rate-1`, equals the bit-extended single padded block.

Proof structure (4 steps, no case split, all length-`8*rate` work in one
helper `bit_identity_8rate`):
1. Convert LHS msg-portion to canonical length-`8*rate` form via `msg_at_8rate`.
2. Convert each `shiftedByte` to length-`8*rate` form via `shiftedByte_eq_zeroExtend_aligned`.
3. Combine three `Bits.zeroExtend` of length-`8*rate` vectors via `← zeroExtend_xor_distrib`.
4. Apply `bit_identity_8rate` via `congrArg`. -/
private theorem base_bit_identity {n s} (msg : Vector U8 n) (suffix : Vector Bool s)
    (rate : Nat) (hs : s + 1 ≤ 8) (hr : 0 < rate ∧ 8 * rate < b)
    (hK : 8 * n + s + 2 ≤ 8 * rate) :
    ((Bits.zeroExtend (bytesU8ToBits msg) b
      ^^^ shiftedByte (encodePadVal suffix hs) n)
      ^^^ shiftedByte 0x80#u8 (rate - 1) : Vector Bool b) =
    Bits.zeroExtend
      (((bytesU8ToBits msg ‖ suffix) ‖ «pad10*1» (8 * rate) (8 * n + s)).cast
        (padded_len_eq_rate hr.1 hK)) b := by
  have hb_rate : 8 * rate ≤ b := by have := hr.2; omega
  -- Step 1: lift each LHS term to canonical length-8*rate form.
  rw [msg_at_8rate msg rate (by omega)]
  rw [shiftedByte_eq_zeroExtend_aligned (encodePadVal suffix hs) n rate (by omega)]
  rw [shiftedByte_eq_zeroExtend_aligned 0x80#u8 (rate - 1) rate (by omega)]
  -- Step 2: combine three `ext` into one via `← zeroExtend_xor_distrib`.
  rw [← zeroExtend_xor_distrib]
  rw [← zeroExtend_xor_distrib]
  -- Step 3: lift the length-8*rate identity to `Bits.zeroExtend ... b`.
  exact congrArg (Bits.zeroExtend · b) (bit_identity_8rate msg suffix rate hs hr hK)

/-- **Inductive aux** (parameterized by starting state `init`):
absorbBytes byte-iteration + padAndPermute equals absorbBlocks block-iteration.

Inducts on `n` via strong recursion (case split on `n < rate` vs `n ≥ rate`),
peeling off `rate` bytes per step. Each step applies ONE `KECCAK_f` on both
sides, matching `SPONGE.absorb`'s `foldl` over blocks. -/
private theorem absorbBytes_eq_SPONGE_absorb_aux {n s} (msg : Vector U8 n)
    (suffix : Vector Bool s) (rate : Nat) (hs : s + 1 ≤ 8)
    (hr : 0 < rate ∧ 8 * rate < b)
    (hsmall : s + 1 < 8)
    (init : Vector Bool b) :
    let P := (bytesU8ToBits msg ‖ suffix) ‖ «pad10*1» (8 * rate) (8 * n + s)
    let (S, idx) := absorbBytes init 0 rate msg.toList
    padAndPermute S idx rate (encodePadVal suffix hs) =
      Spec.SHA3.absorbBlocks KECCAK_f init
        (Spec.SHA3.blocks P (8 * rate)
          (by grind)
          (padLen_dvd (8 * rate) (8 * n + s) (by grind))) := by
  -- Bind P explicitly and reason about its length pLen.
  -- pLen is determined by n,s,rate; pLen = K * 8 * rate where K ≥ 1.
  -- K = 1 ⟺ pLen = 8*rate ⟺ n < rate (given s+1 ≤ 8).
  -- K ≥ 2 ⟺ pLen > 8*rate ⟺ n ≥ rate.
  intro P
  rcases habs : absorbBytes init 0 rate msg.toList with ⟨S, idx⟩
  dsimp only
  by_cases hge : rate ≤ n
  case neg =>
    -- BASE CASE: n < rate. The byte loop never permutes; padAndPermute does the
    -- one and only KECCAK_f. Sub-case on whether the padding bits fit in one block.
    push Not at hge
    by_cases hK : 8 * n + s + 2 ≤ 8 * rate
    case pos =>
      -- BASE-1: K = 1, padding fits in one block (typical case for SHA3/SHAKE).
      -- (a) Byte-absorb is no-permute: (S, idx) = (init ⊕ ext (bytesU8ToBits msg), n).
      have hno := absorbBytes_no_permute init 0 rate msg.toList
                    (by simp [Vector.length_toList]; omega)
      simp only [Nat.zero_add] at hno
      rw [hno, absorbBytesRaw_eq_zeroExtend init msg (by show 8*n ≤ b; omega)] at habs
      -- (b) `padAndPermute` becomes a triple-XOR via `padAndPermute_eq_xor`.
      cases habs
      rw [padAndPermute_eq_xor]
      -- (c) Single-block `absorbBlocks` becomes `KECCAK_f (init ⊕ ext block b)`.
      rw [absorbBlocks_singleton P KECCAK_f init (by grind)
          (padLen_dvd (8*rate) (8*n+s) (by grind)) (padded_len_eq_rate hr.1 hK)]
      -- (d) Strip outer KECCAK_f and use the bit identity.
      simp only [Vector.length_toList] at *
      apply congrArg KECCAK_f
      rw [xor_assoc_v, xor_assoc_v]
      apply congrArg (init ^^^ ·)
      rw [← xor_assoc_v]
      exact base_bit_identity msg suffix rate hs hr hK
    case neg =>
      -- BASE-2 EDGE CASE: n < rate but 8*n+s+1 = 8*rate ⟹ s = 7 ∧ n = rate-1.
      -- Excluded by `hsmall : s + 1 < 8`. SHA3/SHAKE never trigger this case
      -- (s ∈ {2, 4}); the corresponding code (one absorbByte at idx and one at
      -- rate-1) doesn't perform the second permute that the spec would require.
      exfalso
      have h1 : ¬ (8 * n + s + 2 ≤ 8 * rate) := hK
      have h2 : 8 * n ≤ 8 * (rate - 1) := by
        have : n ≤ rate - 1 := by omega
        omega
      omega
  case pos =>
    -- STEP CASE: rate ≤ n. Peel off first `rate` bytes, recurse on the rest.
    let first : Vector U8 rate     := (msg.extract 0    rate).cast (by omega)
    let rest  : Vector U8 (n-rate) := (msg.extract rate n   ).cast (by omega)
    let init' := KECCAK_f (init ⊕ Bits.zeroExtend (bytesU8ToBits first) b)
    rw [absorbBytes_first_block msg rate hr hge init] at habs
    have ih := absorbBytes_eq_SPONGE_absorb_aux rest suffix rate hs hr hsmall init'
    rw [habs] at ih; dsimp only at ih
    rw [ih]
    have hP := blocks_msg_split msg suffix rate hr hge
    dsimp only at hP
    show SHA3.absorbBlocks KECCAK_f init'
        (SHA3.blocks (bytesU8ToBits rest ‖ suffix ‖ «pad10*1» (8*rate) (8*(n-rate)+s))
          (8*rate) (by grind) (padLen_dvd (8*rate) (8*(n-rate)+s) (by grind))) =
      SHA3.absorbBlocks KECCAK_f init
        (SHA3.blocks (bytesU8ToBits msg ‖ suffix ‖ «pad10*1» (8*rate) (8*n+s))
          (8*rate) (by grind) (padLen_dvd (8*rate) (8*n+s) (by grind)))
    rw [hP, absorbBlocks_cons (k := _)
        (h := by have := blocks_count_step (r := 8*rate) (m := 8*(n-rate)+s) (by omega)
                 rw [show 8*(n-rate)+s+8*rate = 8*n+s from by omega] at this; exact this)]
termination_by n
decreasing_by exact Nat.sub_lt (by omega) hr.1

/-- `0` literal at type `Vector Bool n` equals `Vector.replicate n false`.
    In SHA-3's scope, the OfNat instance is `Bits.ofNatLE` (LSB-first override). -/
private theorem zero_vec_eq_replicate {n : Nat} :
    (0 : Vector Bool n) = Vector.replicate n false := by
  apply Vector.ext; intro i hi
  rw [Vector.getElem_replicate]
  show (Bits.ofNatLE 0 : Vector Bool n)[i] = false
  simp [Bits.ofNatLE]

theorem absorbBytes_eq_SPONGE_absorb {n s} (msg : Vector U8 n) (suffix : Vector Bool s)
    (rate : Nat) (hs : s + 1 ≤ 8) (hsmall : s + 1 < 8)
    (hr : 0 < rate ∧ 8 * rate < b) :
    let (S, idx) := absorbBytes (Vector.replicate b false) 0 rate msg.toList
    padAndPermute S idx rate (encodePadVal suffix hs) =
      SPONGE.absorb KECCAK_f (8 * rate)
        ((bytesU8ToBits msg ‖ suffix) ‖ «pad10*1» (8 * rate) (8 * n + s))
        (hm := padLen_dvd (8 * rate) (8 * n + s) (by grind))
        (hr := by grind) := by
  rw [Spec.SHA3.SPONGE_absorb_eq_blocks, zero_vec_eq_replicate]
  exact absorbBytes_eq_SPONGE_absorb_aux msg suffix rate hs hr hsmall (Vector.replicate b false)

/-! ## B. Padding equivalence — DROPPED

Previously `padAndPermute_eq_final_block` characterised
`padAndPermute S idx rate padVal` as `KECCAK_f (S ⊕ Bits.zeroExtend bit_pattern b)`
where `bit_pattern : Vector Bool (8*rate)` was a `Vector.ofFn fun i => if-cascade`
over the final-block bit positions.

That sublemma is now subsumed by `absorbByte_eq_xor` (BridgeComp.lean): with
`padAndPermute = KECCAK_f ∘ absorbByte ∘ absorbByte`, two applications of
`absorbByte_eq_xor` directly yield
`padAndPermute S idx rate padVal = KECCAK_f (S ⊕ shiftedByte padVal idx ⊕ shiftedByte 0x80 (rate-1))`,
which is the same content but expressed algebraically via the two
`shiftedByte` patterns rather than one big `Vector.ofFn` cascade. -/

/-! ## C. Byte-level squeeze matches SPONGE.squeeze

Once the post-absorb state S is fixed, byte-by-byte squeeze of m bytes
matches the bit-level SPONGE.squeeze of 8*m bits, then bitsToBytes. -/

/-- The k-th byte of `bitsToBytes ∘ SPONGE.squeeze` reads from the
    `(k % rate)`-th byte of the `(k / rate)`-th iterate of KECCAK_f. -/
private theorem SPONGE_squeeze_byte_eq (S : Vector Bool b) (rate m : Nat)
    (hr : 0 < rate ∧ 8 * rate < b) (k : Nat) (hk : k < m) :
    (bitsToBytes (SPONGE.squeeze KECCAK_f (8 * rate) #v[] S
      (m := 0) (d := 8 * m) (hr := by grind)))[k] =
      (squeezeByte (KECCAK_f^[k / rate] S) (k % rate)).bv := by
  apply BitVec.eq_of_getLsbD_eq
  intro j hj8
  -- Step 1: bitsToBytes-byte-bit-access lemma
  rw [show (bitsToBytes (SPONGE.squeeze KECCAK_f (8 * rate) #v[] S
        (m := 0) (d := 8 * m) (hr := by grind)))[k].getLsbD j
        = (SPONGE.squeeze KECCAK_f (8 * rate) #v[] S
            (m := 0) (d := 8 * m) (hr := by grind))[8 * k + j]
        from Spec.SHA3.bitsToBytes_byte_getLsbD _ k hk ⟨j, hj8⟩]
  -- Step 2: SPONGE.squeeze = Trunc (8m) ∘ squeezeBlocks (m+1 blocks suffice)
  have hK : 8 * m ≤ (m + 1) * (8 * rate) := by
    have : 1 ≤ rate := hr.1
    nlinarith
  rw [Spec.SHA3.SPONGE_squeeze_eq_trunc_blocks KECCAK_f S
      ⟨by linarith, hr.2⟩ (m + 1) hK]
  -- Step 3: Strip Trunc and Vector.cast
  have h8kj : 8 * k + j < 8 * m := by omega
  rw [Spec.SHA3.Trunc_getElem' _ _ _ h8kj, Vector.getElem_cast]
  -- Step 4: squeezeBlocks bit-level access
  have hbnd : 8 * k + j < (m + 1) * (8 * rate) := by omega
  rw [Spec.SHA3.squeezeBlocks_getElem KECCAK_f (8*rate) (by linarith) (le_of_lt hr.2) S
      (m+1) (8*k+j) hbnd]
  -- Step 5: Simplify (8k+j)/(8r) = k/r and (8k+j)%(8r) = 8(k%r) + j
  have hkmod : k % rate < rate := Nat.mod_lt _ hr.1
  have hkdivmod : k = rate * (k / rate) + k % rate := (Nat.div_add_mod k rate).symm
  have hdiv : (8 * k + j) / (8 * rate) = k / rate := by
    rw [show 8 * k + j = (8 * (k % rate) + j) + (k / rate) * (8 * rate) from by
      have hk := hkdivmod; nlinarith]
    rw [Nat.add_mul_div_right _ _ (by linarith : 0 < 8 * rate)]
    rw [show (8 * (k % rate) + j) / (8 * rate) = 0 from
      Nat.div_eq_of_lt (by omega)]
    omega
  have hmod : (8 * k + j) % (8 * rate) = 8 * (k % rate) + j := by
    rw [show 8 * k + j = (8 * (k % rate) + j) + (k / rate) * (8 * rate) from by
      have hk := hkdivmod; nlinarith]
    rw [Nat.add_mul_mod_self_right]
    exact Nat.mod_eq_of_lt (by omega)
  simp only [hmod, hdiv]
  -- Step 6: squeezeByte bit-level access
  unfold squeezeByte
  show (KECCAK_f^[k / rate] S)[8 * (k % rate) + j] = (BitVec.ofFn _).getLsbD j
  unfold BitVec.ofFn
  rw [BitVec.getLsbD_cast]
  rw [BitVec.getLsbD_ofBoolListLE]
  -- Need: S[...] = (List.ofFn fun i : Fin 8 => S.getD (8*(k%rate) + i.val) false).getD j false
  -- After cases on j, both reduce to S.getD (8 * (k%rate) + j) false; left side equals via getElem.
  have hkmod : k % rate < rate := Nat.mod_lt _ hr.1
  have hsbnd : 8 * (k % rate) + j < b := by have := hr.2; omega
  rw [show (KECCAK_f^[k / rate] S)[8 * (k % rate) + j]
        = (KECCAK_f^[k / rate] S).getD (8 * (k % rate) + j) false from by
        rw [Vector.getD]; simp [hsbnd]]
  match j, hj8 with
  | 0, _ => rfl
  | 1, _ => rfl
  | 2, _ => rfl
  | 3, _ => rfl
  | 4, _ => rfl
  | 5, _ => rfl
  | 6, _ => rfl
  | 7, _ => rfl

theorem squeezeBytes_eq_SPONGE_squeeze (S : Vector Bool b) (rate m : Nat)
    (hr : 0 < rate ∧ 8 * rate < b) :
    bytesU8ToBits (squeezeBytes S 0 rate m) =
      SPONGE.squeeze KECCAK_f (8 * rate) #v[] S
        (m := 0) (d := 8 * m) (hr := by grind) := by
  -- Byte-level intermediate: element-wise via the two byte characterizations.
  have hbytes : (squeezeBytes S 0 rate m).map (·.bv) =
      bitsToBytes (SPONGE.squeeze KECCAK_f (8 * rate) #v[] S
        (m := 0) (d := 8 * m) (hr := by grind)) := by
    apply Vector.ext
    intro k hk
    simp only [Vector.getElem_map]
    rw [squeezeBytes_byte_eq S rate m hr.1 k hk]
    rw [SPONGE_squeeze_byte_eq S rate m hr k hk]
  -- Lift to bits via `bytesToBits ∘ bitsToBytes = id` round trip.
  unfold bytesU8ToBits
  rw [hbytes, bytesToBits_bitsToBytes]

end symcrust.sha3.sha3_impl
