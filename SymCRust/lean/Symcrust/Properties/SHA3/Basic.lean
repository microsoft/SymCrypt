import Spec.SHA3.Properties
import Symcrust.Code.Funs

/-!
# SHA-3 Verification — Bridge Definitions and Ghost State

## The four state representations and why they coexist

Verifying SHA-3 requires bridging the Rust array representation used by the
implementation to the bit-string representation used by FIPS 202 §4 (the
sponge construction). The four representations split into two **implementation
types** (rooted in the Aeneas-translated Rust code) and two **spec types**
(rooted in FIPS 202). Each carries its own weight; none is redundant.

### Implementation side (Rust / Aeneas)

1. **`Keccak1600 = Array U64 25#usize`** — *the Aeneas-extracted Rust array.*
   This is the physical state in `Code/Funs.lean` and in every per-function
   spec (`KeccakState.append_byte.spec`, etc.). We cannot eliminate it: it is
   the type produced by Aeneas extraction.

2. **`Lanes25`** — *a 25-field flat structure (l0, …, l24).* Used **only** by
   the round-permutation proofs in `Keccak/{Core,Fold,Loop}.lean`. The reason
   it exists: `θ`, `ρ`, `π`, `χ`, `ι` each touch all 25 lanes by index, and
   reasoning about `Array.get!` of 25 distinct indices via Lean's `simp`
   stack is far slower and noisier than reasoning about named fields. The
   round-permutation proof case-splits on all 25 (x, y) pairs; with `Lanes25`
   that is one `cases` away. Once we exit the round permutation, we never
   touch `Lanes25` again.

### Spec side (FIPS 202)

3. **`State = Vector (Vector Lane 5) 5`** (where `Lane = Vector Bool 64`) —
   *the FIPS 202 2-D state array (§3.1.4).* Every spec step function (θ, ρ,
   π, χ, ι, KECCAK-p) is stated on `State`. We cannot reformulate the spec
   without diverging from the standard.

4. **`Vector Bool b`** with `b = 1600` — *the FIPS 202 bit-string (§3.1.2).*
   `SPONGE.absorb` and `SPONGE.squeeze` (§4) operate on bit-strings: absorb
   is `f (S ⊕ Bits.zeroExtend Pi b)`, squeeze concatenates `Trunc r (f^[j] S)`.
   The bridge invariant `toBits ks.state = S` lives here. We cannot
   eliminate it either: a 2-D state cannot be XORed with a 1-D padded
   message block without first being flattened, and FIPS 202 phrases the
   sponge axiomatically on bit-strings.

### How they connect

The conversion between the two spec types (3) ↔ (4) is `stateToString` /
`stringToState`, proved to be mutual inverses in
`Spec/SHA3/Properties.lean`. The full chain implementation → spec is
composed in `toState` (1 → 2 → 3) and `toBits` (1 → 2 → 3 → 4) below.
The first hop crosses the implementation/spec boundary and is where the
Aeneas-level `U64.bv` extraction happens (in `toLane`).

(Earlier drafts also carried a `Vector (BitVec 64) 25` "flat" layer between
(1) and (3); it has been removed as it was only consumed by an orphaned
verification attempt.)
-/

namespace symcrust

open Aeneas Aeneas.Std Result
open Spec (𝔹 bytesToBits bitsToBytes Bits.toNatLE)
open Spec.SHA3 (State Lane w b stateToString KECCAK_f SPONGE SPONGE.squeeze)
open scoped Spec.Notations
open scoped Spec.SHA3

/- Fast default for `a[i]` / `a.val[i]` bound goals in this file: discharge
   with `scalar_tac` (cheaper than the global `agrind` override). This lets us
   write plain `a.val[k]` instead of `a.val[k]'(by scalar_tac)` and avoids the
   deprecated `a.val[k]!`. -/
local macro_rules | `(tactic| get_elem_tactic) => `(tactic| scalar_tac)

namespace sha3.sha3_impl

abbrev Keccak1600 := Array U64 25#usize

/-! ## Representation bridge -/

/-- Convert a single U64 lane to a spec Lane (Vector Bool 64) via getLsbD. -/
def toLane (u : U64) : Lane :=
  Vector.ofFn fun (z : Fin w) => u.bv.getLsbD z

/-- 25 U64 lanes as a flat structure — no vectors, no indexing. -/
structure Lanes25 where
  l0 : U64
  l1 : U64
  l2 : U64
  l3 : U64
  l4 : U64
  l5 : U64
  l6 : U64
  l7 : U64
  l8 : U64
  l9 : U64
  l10 : U64
  l11 : U64
  l12 : U64
  l13 : U64
  l14 : U64
  l15 : U64
  l16 : U64
  l17 : U64
  l18 : U64
  l19 : U64
  l20 : U64
  l21 : U64
  l22 : U64
  l23 : U64
  l24 : U64

@[ext]
theorem Lanes25.ext {a b : Lanes25}
    (h0 : a.l0 = b.l0) (h1 : a.l1 = b.l1) (h2 : a.l2 = b.l2) (h3 : a.l3 = b.l3)
    (h4 : a.l4 = b.l4) (h5 : a.l5 = b.l5) (h6 : a.l6 = b.l6) (h7 : a.l7 = b.l7)
    (h8 : a.l8 = b.l8) (h9 : a.l9 = b.l9) (h10 : a.l10 = b.l10) (h11 : a.l11 = b.l11)
    (h12 : a.l12 = b.l12) (h13 : a.l13 = b.l13) (h14 : a.l14 = b.l14) (h15 : a.l15 = b.l15)
    (h16 : a.l16 = b.l16) (h17 : a.l17 = b.l17) (h18 : a.l18 = b.l18) (h19 : a.l19 = b.l19)
    (h20 : a.l20 = b.l20) (h21 : a.l21 = b.l21) (h22 : a.l22 = b.l22) (h23 : a.l23 = b.l23)
    (h24 : a.l24 = b.l24) : a = b := by
  cases a; cases b; simp_all
def Lanes25.get (s : Lanes25) (x y : Fin 5) : U64 :=
  match x, y with
  | ⟨0,_⟩,⟨0,_⟩ => s.l0  | ⟨1,_⟩,⟨0,_⟩ => s.l1  | ⟨2,_⟩,⟨0,_⟩ => s.l2  | ⟨3,_⟩,⟨0,_⟩ => s.l3  | ⟨4,_⟩,⟨0,_⟩ => s.l4
  | ⟨0,_⟩,⟨1,_⟩ => s.l5  | ⟨1,_⟩,⟨1,_⟩ => s.l6  | ⟨2,_⟩,⟨1,_⟩ => s.l7  | ⟨3,_⟩,⟨1,_⟩ => s.l8  | ⟨4,_⟩,⟨1,_⟩ => s.l9
  | ⟨0,_⟩,⟨2,_⟩ => s.l10 | ⟨1,_⟩,⟨2,_⟩ => s.l11 | ⟨2,_⟩,⟨2,_⟩ => s.l12 | ⟨3,_⟩,⟨2,_⟩ => s.l13 | ⟨4,_⟩,⟨2,_⟩ => s.l14
  | ⟨0,_⟩,⟨3,_⟩ => s.l15 | ⟨1,_⟩,⟨3,_⟩ => s.l16 | ⟨2,_⟩,⟨3,_⟩ => s.l17 | ⟨3,_⟩,⟨3,_⟩ => s.l18 | ⟨4,_⟩,⟨3,_⟩ => s.l19
  | ⟨0,_⟩,⟨4,_⟩ => s.l20 | ⟨1,_⟩,⟨4,_⟩ => s.l21 | ⟨2,_⟩,⟨4,_⟩ => s.l22 | ⟨3,_⟩,⟨4,_⟩ => s.l23 | ⟨4,_⟩,⟨4,_⟩ => s.l24

/-- `Fin 25`-indexed accessor on `Lanes25`.  Enables ONE parametric
    bridge lemma (`Keccak4xHybrid.permute_loop.body_fused_bridge`) instead
    of 25 per-lane copies. -/
def Lanes25.lane25 (s : Lanes25) (n : Fin 25) : U64 :=
  let k := n.val
  if      k = 0  then s.l0  else if k = 1  then s.l1  else if k = 2  then s.l2
  else if k = 3  then s.l3  else if k = 4  then s.l4  else if k = 5  then s.l5
  else if k = 6  then s.l6  else if k = 7  then s.l7  else if k = 8  then s.l8
  else if k = 9  then s.l9  else if k = 10 then s.l10 else if k = 11 then s.l11
  else if k = 12 then s.l12 else if k = 13 then s.l13 else if k = 14 then s.l14
  else if k = 15 then s.l15 else if k = 16 then s.l16 else if k = 17 then s.l17
  else if k = 18 then s.l18 else if k = 19 then s.l19 else if k = 20 then s.l20
  else if k = 21 then s.l21 else if k = 22 then s.l22 else if k = 23 then s.l23
  else s.l24

/-- `Fin 25`-indexed extensionality.  Lets us discharge `a = b` by a
    single `intro n; cases n` instead of 25 separate field equations. -/
theorem Lanes25.ext_lane25 {a b : Lanes25}
    (h : ∀ n : Fin 25, a.lane25 n = b.lane25 n) : a = b := by
  apply Lanes25.ext
  all_goals first
    | exact h ⟨0, by decide⟩  | exact h ⟨1, by decide⟩  | exact h ⟨2, by decide⟩
    | exact h ⟨3, by decide⟩  | exact h ⟨4, by decide⟩  | exact h ⟨5, by decide⟩
    | exact h ⟨6, by decide⟩  | exact h ⟨7, by decide⟩  | exact h ⟨8, by decide⟩
    | exact h ⟨9, by decide⟩  | exact h ⟨10, by decide⟩ | exact h ⟨11, by decide⟩
    | exact h ⟨12, by decide⟩ | exact h ⟨13, by decide⟩ | exact h ⟨14, by decide⟩
    | exact h ⟨15, by decide⟩ | exact h ⟨16, by decide⟩ | exact h ⟨17, by decide⟩
    | exact h ⟨18, by decide⟩ | exact h ⟨19, by decide⟩ | exact h ⟨20, by decide⟩
    | exact h ⟨21, by decide⟩ | exact h ⟨22, by decide⟩ | exact h ⟨23, by decide⟩
    | exact h ⟨24, by decide⟩

/-- `simp`-form reductions for `lane25` at literal indices. -/
@[simp] theorem Lanes25.lane25_0  (s : Lanes25) (h : 0  < 25 := by decide) : s.lane25 ⟨0,  h⟩ = s.l0  := rfl
@[simp] theorem Lanes25.lane25_1  (s : Lanes25) (h : 1  < 25 := by decide) : s.lane25 ⟨1,  h⟩ = s.l1  := rfl
@[simp] theorem Lanes25.lane25_2  (s : Lanes25) (h : 2  < 25 := by decide) : s.lane25 ⟨2,  h⟩ = s.l2  := rfl
@[simp] theorem Lanes25.lane25_3  (s : Lanes25) (h : 3  < 25 := by decide) : s.lane25 ⟨3,  h⟩ = s.l3  := rfl
@[simp] theorem Lanes25.lane25_4  (s : Lanes25) (h : 4  < 25 := by decide) : s.lane25 ⟨4,  h⟩ = s.l4  := rfl
@[simp] theorem Lanes25.lane25_5  (s : Lanes25) (h : 5  < 25 := by decide) : s.lane25 ⟨5,  h⟩ = s.l5  := rfl
@[simp] theorem Lanes25.lane25_6  (s : Lanes25) (h : 6  < 25 := by decide) : s.lane25 ⟨6,  h⟩ = s.l6  := rfl
@[simp] theorem Lanes25.lane25_7  (s : Lanes25) (h : 7  < 25 := by decide) : s.lane25 ⟨7,  h⟩ = s.l7  := rfl
@[simp] theorem Lanes25.lane25_8  (s : Lanes25) (h : 8  < 25 := by decide) : s.lane25 ⟨8,  h⟩ = s.l8  := rfl
@[simp] theorem Lanes25.lane25_9  (s : Lanes25) (h : 9  < 25 := by decide) : s.lane25 ⟨9,  h⟩ = s.l9  := rfl
@[simp] theorem Lanes25.lane25_10 (s : Lanes25) (h : 10 < 25 := by decide) : s.lane25 ⟨10, h⟩ = s.l10 := rfl
@[simp] theorem Lanes25.lane25_11 (s : Lanes25) (h : 11 < 25 := by decide) : s.lane25 ⟨11, h⟩ = s.l11 := rfl
@[simp] theorem Lanes25.lane25_12 (s : Lanes25) (h : 12 < 25 := by decide) : s.lane25 ⟨12, h⟩ = s.l12 := rfl
@[simp] theorem Lanes25.lane25_13 (s : Lanes25) (h : 13 < 25 := by decide) : s.lane25 ⟨13, h⟩ = s.l13 := rfl
@[simp] theorem Lanes25.lane25_14 (s : Lanes25) (h : 14 < 25 := by decide) : s.lane25 ⟨14, h⟩ = s.l14 := rfl
@[simp] theorem Lanes25.lane25_15 (s : Lanes25) (h : 15 < 25 := by decide) : s.lane25 ⟨15, h⟩ = s.l15 := rfl
@[simp] theorem Lanes25.lane25_16 (s : Lanes25) (h : 16 < 25 := by decide) : s.lane25 ⟨16, h⟩ = s.l16 := rfl
@[simp] theorem Lanes25.lane25_17 (s : Lanes25) (h : 17 < 25 := by decide) : s.lane25 ⟨17, h⟩ = s.l17 := rfl
@[simp] theorem Lanes25.lane25_18 (s : Lanes25) (h : 18 < 25 := by decide) : s.lane25 ⟨18, h⟩ = s.l18 := rfl
@[simp] theorem Lanes25.lane25_19 (s : Lanes25) (h : 19 < 25 := by decide) : s.lane25 ⟨19, h⟩ = s.l19 := rfl
@[simp] theorem Lanes25.lane25_20 (s : Lanes25) (h : 20 < 25 := by decide) : s.lane25 ⟨20, h⟩ = s.l20 := rfl
@[simp] theorem Lanes25.lane25_21 (s : Lanes25) (h : 21 < 25 := by decide) : s.lane25 ⟨21, h⟩ = s.l21 := rfl
@[simp] theorem Lanes25.lane25_22 (s : Lanes25) (h : 22 < 25 := by decide) : s.lane25 ⟨22, h⟩ = s.l22 := rfl
@[simp] theorem Lanes25.lane25_23 (s : Lanes25) (h : 23 < 25 := by decide) : s.lane25 ⟨23, h⟩ = s.l23 := rfl
@[simp] theorem Lanes25.lane25_24 (s : Lanes25) (h : 24 < 25 := by decide) : s.lane25 ⟨24, h⟩ = s.l24 := rfl

/-- Bridge from Lanes25 to State via toLane. -/
def Lanes25.toState (s : Lanes25) : State :=
  Vector.ofFn fun x : Fin 5 => Vector.ofFn fun y : Fin 5 =>
    toLane (s.get x y)

/-- Unpack a Keccak1600 (Aeneas Array) directly into Lanes25. -/
def Lanes25.ofArray (a : Keccak1600) : Lanes25 :=
  ⟨a.val[0], a.val[1], a.val[2], a.val[3], a.val[4],
   a.val[5], a.val[6], a.val[7], a.val[8], a.val[9],
   a.val[10], a.val[11], a.val[12], a.val[13], a.val[14],
   a.val[15], a.val[16], a.val[17], a.val[18], a.val[19],
   a.val[20], a.val[21], a.val[22], a.val[23], a.val[24]⟩

/-- Pack a Lanes25 into a Keccak1600 (Aeneas Array). -/
def Lanes25.toArray (s : Lanes25) : Keccak1600 :=
  Array.make 25#usize [s.l0, s.l1, s.l2, s.l3, s.l4,
    s.l5, s.l6, s.l7, s.l8, s.l9, s.l10, s.l11, s.l12, s.l13, s.l14,
    s.l15, s.l16, s.l17, s.l18, s.l19, s.l20, s.l21, s.l22, s.l23, s.l24]

/-- Bridge from Keccak1600 (Array U64 25) to the spec's State type. -/
def toState (s : Keccak1600) : State :=
  (Lanes25.ofArray s).toState

def toBits (s : Keccak1600) : Vector Bool b :=
  stateToString (toState s)

/-- Fold: 25 List-indexed reads from an Array = ofArray. -/
theorem fold_ofArray (a : Keccak1600) :
    (⟨a.val[0], a.val[1], a.val[2], a.val[3], a.val[4],
      a.val[5], a.val[6], a.val[7], a.val[8], a.val[9],
      a.val[10], a.val[11], a.val[12], a.val[13], a.val[14],
      a.val[15], a.val[16], a.val[17], a.val[18], a.val[19],
      a.val[20], a.val[21], a.val[22], a.val[23], a.val[24]⟩ : Lanes25) =
    Lanes25.ofArray a := rfl

/-- Round-trip: ofArray ∘ toArray = identity. -/
@[simp]
theorem Lanes25.ofArray_toArray (s : Lanes25) :
    Lanes25.ofArray s.toArray = s := by
  cases s; simp [Lanes25.ofArray, Lanes25.toArray, Array.make]

/-- toState of a packed Lanes25 = toState. -/
@[simp]
theorem toState_toArray (s : Lanes25) :
    toState s.toArray = s.toState := by
  simp [toState, Lanes25.ofArray_toArray]

/-! ## Byte conversions

Code operates on `U8`; the spec operates on `Byte = BitVec 8`. The single
boundary between the two is `u8ToByte = (·.bv)`, applied at three places:

- `sliceToSpecBytes : Slice U8 → 𝔹 s.len.val` (this file's spec)
- `arrayToSpecBytes : Array U8 n → 𝔹 n.val` (Shake1x.lean)

Both produce a `Vector Byte _` from the underlying `List U8` by mapping
`u8ToByte`. -/

/-- Coerce `Byte = BitVec 8` to `U8` (the wrapper structure). -/
def byteToU8 (b : Byte) : U8 := ⟨b⟩

/-- Convert a `Vector U8 n` directly to its bit-string representation
    `Vector Bool (8 * n)`. Composes `(·.bv)` (U8 → Byte) with `bytesToBits`
    (𝔹 n → Vector Bool (8*n)).

    Used in main FC statements (`code_toSpec` and the variant wrappers) to
    avoid the clunky `bytesToBits (msg.map (·.bv))` double-conversion. -/
def bytesU8ToBits {n : Nat} (msg : Vector U8 n) : Vector Bool (8 * n) :=
  bytesToBits (msg.map (·.bv))

/-! ## Ghost state -/

/-- Ghost state threading through the streaming sponge API.
    Records absorbed/squeezed bytes plus the rate and padding-suffix byte.

    **Why `List U8` rather than `Slice U8`?** Both are pure Lean values, so
    purity is not the discriminator. The decisive constraint is that ghost
    state accumulates across many calls (`append`, `append`, `append`, …),
    and `Slice α` is `{ val : List α // val.length ≤ Usize.size }` — a
    length-capped list. Two slices each below the cap can concatenate to one
    that exceeds it, so `Slice.append` (if it existed) would carry a proof
    obligation per accumulation step. `List` has no such cap, so
    concatenation is unconditional and downstream specs don't have to thread
    a "fits in a Usize" precondition.

    **Why `U8` rather than `Byte`?** The code passes `U8` (Aeneas-extracted
    Rust bytes) at every API boundary, so storing `U8` removes a `.bv`
    conversion at every call site. The bridge functions in this file
    (`absorbByte`, `squeezeByte`, …) still operate on `Byte`; they
    receive `g.absorbed.map (·.bv)` / `g.padVal.bv` at the spec boundary.

    `h_rate` packages the standing constraints on `rate` so downstream
    specs don't need to re-thread them. -/
structure GhostState where
  rate : Nat
  padVal : U8
  absorbed : List U8
  squeezed : List U8
  h_rate : 0 < rate ∧ 8 * rate < b ∧ rate % 8 = 0

def GhostState.init (rate : Nat) (padVal : U8)
    (h_rate : 0 < rate ∧ 8 * rate < b ∧ rate % 8 = 0 := by decide) : GhostState :=
  ⟨rate, padVal, [], [], h_rate⟩

def GhostState.append (g : GhostState) (data : List U8)
    (wasSqueeze : Bool) : GhostState :=
  if wasSqueeze then { g with absorbed := data, squeezed := [] }
  else { g with absorbed := g.absorbed ++ data }

def GhostState.squeeze (g : GhostState) (output : List U8) : GhostState :=
  { g with squeezed := g.squeezed ++ output }

@[simp]
theorem GhostState.squeeze_append (g : GhostState) (a b : List U8) :
    (g.squeeze a).squeeze b = g.squeeze (a ++ b) := by
  simp [GhostState.squeeze, List.append_assoc]

@[simp]
theorem GhostState.squeeze_nil (g : GhostState) :
    g.squeeze [] = g := by
  simp [GhostState.squeeze]

/-! ## Code-adjacent bridge functions

These model the implementation's byte-by-byte sponge operations on `Vector Bool b`.
They are used in the FC invariants (`spongeInvariant`, `squeezingInvariant`) to relate
the concrete Keccak state to these intermediate pure functions.

The FC theorem (`code_toSpec` in Bridge.lean) then proves that these code-adjacent
operations compute the same result as the FIPS 202 Spec functions (`SPONGE`, `sha3_256`,
etc.), which are used directly — no byte-level duplicate definitions needed.

The definitions and predicates below are grouped in the streaming-API processing
order: **absorb → pad → squeeze/extract**. Within each group, the bridge functions
come first, then the FC invariant they support, then the public predicates.

### Architectural note: bit-string vs `Keccak1600` for the bridge layer

These bridge functions all operate on `Vector Bool b` (1600-bit string) rather
than directly on `Keccak1600` (the Aeneas-extracted `Array U64 25`). An
alternative would be to define them on `Keccak1600`, in which case:

* Each bit-FC bridge lemma in `Sponge/BridgeBitFC.lean` (`absorbByte_bridge`,
  `squeezeByte_toBits`, `keccak_permute_toBits`) would collapse to `rfl` or
  near-`rfl`. The 80-line BV proof for `absorbByte_bridge` and the
  cold-build-OOM-prone `squeezeByte_toBits` would simply disappear.
* Per-API postconditions (`append_byte.spec`, `extract_byte.spec`, …) become
  type-clean equalities on `Keccak1600`, with no `toBits` view in sight.
* Conversely, the math sublemmas in `Sponge/BridgeMathFC.lean`
  (`absorbBytes_eq_SPONGE_absorb`, `squeezeBytes_eq_SPONGE_squeeze`) would
  become harder: they currently relate two bit-string functions; under the
  alternative they would have to thread `toBits` through their statements.
* Mixed is worse than either pure choice: any bridge-function
  fragmentation (some on `Keccak1600`, others on `Vector Bool b`) re-introduces
  representation conversions inside their bodies — exactly the `flatToBV` /
  `bvToFlat` round-trip we deleted from `Spec/SHA3/Properties.lean`.

We keep the `Vector Bool b` form for now because `BridgeBitFC.lean` is largely
already proven and the math sublemmas are the bottleneck. The trade-off
should be revisited if/when the Rust source is re-extracted (forcing
`BridgeBitFC.lean` to be redone anyway), or if the per-API specs end up
demanding bit-level reasoning that `step*` cannot auto-discharge. -/

/-! ### Absorb -/

/-- XOR byte `val` into the sponge state `S` at byte position `idx`. -/
def absorbByte (S : Vector Bool b) (idx : Nat) (val : U8) : Vector Bool b :=
  Vector.ofFn fun (i : Fin b) =>
    S[i] ^^ (val.bv.zeroExtend b <<< (8 * idx)).getLsbD i.val

/-- The bit-pattern of the byte `val` placed at byte position `idx` in a fresh
    state — i.e., what `absorbByte` XORs into the state. Algebraic primitive
    for `absorbByte_eq_xor` and `chunkBits`. -/
def shiftedByte (val : U8) (idx : Nat) : Vector Bool b :=
  Vector.ofFn fun (i : Fin b) => (val.bv.zeroExtend b <<< (8 * idx)).getLsbD i.val

/-- Bit-pattern of a chunk of bytes XOR'd at byte positions
    `[idx, idx + chunk.length)`. Algebraic primitive used by
    `absorbBytesRaw_eq_xor`. -/
def chunkBits (idx : Nat) (chunk : List U8) : Vector Bool b :=
  match chunk with
  | [] => Vector.replicate b false
  | byte :: rest => shiftedByte byte idx ⊕ chunkBits (idx + 1) rest

/-- XOR a sequence of bytes into the state without permuting.
    Used by `append_bytes_loop` which stays within a single block.

    Defined via `List.foldl` (rather than direct recursion) so that
    downstream lemmas reduce to `List.foldl` properties — avoiding the
    cold-build `maxRecDepth` that arises when chasing the auto-generated
    equation lemmas of a recursive definition through heavy import contexts. -/
def absorbBytesRaw (S : Vector Bool b) (idx : Nat)
    (data : List U8) : Vector Bool b :=
  (data.foldl (fun (acc : Vector Bool b × Nat) byte =>
    (absorbByte acc.1 acc.2 byte, acc.2 + 1)) (S, idx)).1

/-- Absorb a sequence of bytes, permuting at rate boundaries.
    Mirrors the code exactly: XOR one byte, advance idx, permute when idx = rate.
    Starting from idx < rate, always returns idx < rate. -/
def absorbBytes (S : Vector Bool b) (idx : Nat) (rate : Nat)
    (data : List U8) : Vector Bool b × Nat :=
  match data with
  | [] => (S, idx)
  | byte :: rest =>
    let S' := absorbByte S idx byte
    let idx' := idx + 1
    if idx' = rate then
      absorbBytes (KECCAK_f S') 0 rate rest
    else
      absorbBytes S' idx' rate rest

/-- Relates the code state to `absorbBytes` applied to all absorbed data. -/
def spongeInvariant (ks : KeccakState) (g : GhostState) : Prop :=
  let (S, idx) := absorbBytes (Vector.replicate b false) 0 g.rate g.absorbed
  toBits ks.state = S ∧ ks.state_index.val = idx

/-- Internal absorb-mode invariant. Uses `≤` for state_index because
    `append_byte` can produce `state_index = input_block_size` transiently.
    NO FC content: when state_index = rate, the impl state diverges from
    `absorbBytes` (pre-permute vs post-permute). FC is established at API
    boundaries (`absorbing`) where state_index < rate is guaranteed.

    The rate-shape constraints (`% 8 = 0`, `0 < rate`, `rate < b/8`) are now
    bundled in `g.h_rate` so they don't appear here. -/
def absorbingWeak (ks : KeccakState) (g : GhostState) : Prop :=
  ks.state_index.val ≤ ks.input_block_size.val ∧
  ¬ ks.squeeze_mode ∧
  ks.input_block_size = g.rate ∧
  ks.padding_value = g.padVal ∧
  g.squeezed = []

/-- Public absorb-mode predicate with full FC.
    `absorbBytes` starting from idx=0 always returns idx < rate (when rate > 0),
    so the FC invariant is always consistent with the strict `<` bound. -/
def absorbing (ks : KeccakState) (g : GhostState) : Prop :=
  absorbingWeak ks g ∧
  ks.state_index.val < ks.input_block_size.val ∧
  spongeInvariant ks g

/-! ### Padding -/

/-- Compute the byte that encodes `suffix ‖ leading-1-of-pad10*1`,
    little-endian-packed into a single byte (zero-padded above bit `s`).
    E.g., SHA3: `encodePadVal #v[0, 1] = 0x06`;
          SHAKE: `encodePadVal #v[1, 1, 1, 1] = 0x1F`. -/
@[irreducible] def encodePadVal {s : Nat} (suffix : Vector Bool s) (_hs : s + 1 ≤ 8 := by decide) : U8 :=
  ⟨BitVec.ofNat 8 (Bits.toNatLE (suffix ‖ #v[true]))⟩

/-- Apply domain suffix + pad10*1, then permute.
    `padVal` encodes `suffix ‖ leading-1-of-pad10*1` (e.g., 0x06 for SHA3).
    The final `1` of pad10*1 goes at bit `8*rate - 1`.

    **Structural form, mirroring the Rust `apply_padding`:**
    Two `absorbByte`s (one for `padVal` at position `idx`, one for `0x80` at
    position `rate - 1` to set bit `8*rate - 1`) followed by a permute. The
    bit-pattern characterization is given by `padAndPermute_bitForm`. -/
def padAndPermute (S : Vector Bool b) (idx : Nat) (rate : Nat)
    (padVal : U8) : Vector Bool b :=
  KECCAK_f (absorbByte (absorbByte S idx padVal) (rate - 1) (0x80#u8))

/-! ### Squeeze and extract -/

/-- Read one byte from the sponge state at byte position `idx`. -/
def squeezeByte (S : Vector Bool b) (idx : Nat) : U8 :=
  ⟨BitVec.ofFn fun (i : Fin 8) => S.getD (8 * idx + i.val) false⟩

/-- The sponge state and index after squeezing n bytes from (S, idx).
    Mirrors `extract_loop1`: check boundary → permute if needed → read → advance.
    Can produce idx = rate (after reading byte rate-1), matching `squeezing`'s ≤. -/
def squeezeAfter (S : Vector Bool b) (idx : Nat) (rate : Nat) :
    Nat → Vector Bool b × Nat
  | 0 => (S, idx)
  | n + 1 =>
    let (S', idx') := squeezeAfter S idx rate n
    let (S'', idx'') := if idx' = rate then (KECCAK_f S', 0) else (S', idx')
    (S'', idx'' + 1)

/-- Squeeze `m` output bytes from sponge state. Returns `Vector U8 m`.
    Defined via `squeezeAfter` to track state at each position. -/
def squeezeBytes (S : Vector Bool b) (idx : Nat) (rate : Nat) (m : Nat) : Vector U8 m :=
  Vector.ofFn fun (k : Fin m) =>
    let (S_k, idx_k) := squeezeAfter S idx rate k.val
    let (S_k', idx_k') := if idx_k = rate then (KECCAK_f S_k, 0) else (S_k, idx_k)
    squeezeByte S_k' idx_k'

/-- Relates the code state to `squeezeAfter` applied to the post-padding state. -/
def squeezingInvariant (ks : KeccakState) (g : GhostState) : Prop :=
  let (S_abs, idx_abs) := absorbBytes (Vector.replicate b false) 0 g.rate g.absorbed
  let S_pad := padAndPermute S_abs idx_abs g.rate g.padVal
  let (S_cur, idx_cur) := squeezeAfter S_pad 0 g.rate g.squeezed.length
  toBits ks.state = S_cur ∧ ks.state_index.val = idx_cur ∧
  g.squeezed = (squeezeBytes S_pad 0 g.rate g.squeezed.length).toList

/-- Structural squeeze-mode predicate (no FC). Used by internal Extract proofs.
    The rate-shape constraints (`% 8 = 0`, `0 < rate`, `rate < b/8`) are now
    bundled in `g.h_rate` so they don't appear here. -/
def squeezingStructural (ks : KeccakState) (g : GhostState) : Prop :=
  ks.state_index.val ≤ ks.input_block_size.val ∧
  ks.squeeze_mode ∧
  ks.input_block_size = g.rate ∧
  ks.padding_value = g.padVal

/-- Squeeze-mode predicate with full FC. -/
def squeezing (ks : KeccakState) (g : GhostState) : Prop :=
  squeezingStructural ks g ∧ squeezingInvariant ks g

/-- Structural squeezing is invariant under `squeeze` (only checks rate/padVal). -/
@[simp]
theorem squeezingStructural_squeeze_inv (ks : KeccakState) (g : GhostState) (bytes : List U8) :
    squeezingStructural ks (g.squeeze bytes) ↔ squeezingStructural ks g := by
  simp [squeezingStructural, GhostState.squeeze]

/-- The expected output bytes for an extract call at the current squeeze position.
    Starts from `squeezeAfter(S_pad, 0, rate, |squeezed|)` — the state after
    already-squeezed bytes — and squeezes `outLen` more bytes. -/
def extractOutput (g : GhostState) (outLen : Nat) : Vector U8 outLen :=
  let (S_abs, idx_abs) := absorbBytes (Vector.replicate b false) 0 g.rate g.absorbed
  let S_pad := padAndPermute S_abs idx_abs g.rate g.padVal
  let (S_cur, idx_cur) := squeezeAfter S_pad 0 g.rate g.squeezed.length
  squeezeBytes S_cur idx_cur g.rate outLen

/-- Advance the ghost by `n` more squeezed bytes, computed via the bridge. -/
def GhostState.squeezeAdvance (g : GhostState) (n : Nat) : GhostState :=
  g.squeeze (extractOutput g n).toList

end sha3.sha3_impl

end symcrust
