import Intrinsics.Simd
open Aeneas Std

-- Default tactic for `[]` indexing: assumption, then `length_eq`-normalize, then grind.
local macro_rules
  | `(tactic| get_elem_tactic) =>
    `(tactic| first
      | assumption
      | (simp only [Aeneas.Std.Array.length_eq]; first | assumption | scalar_tac)
      | grind)

/-! # Intrinsics/Bytes.lean — byte-normalization library

A small Aeneas library that normalizes arrays of scalars (and, later, bit lanes)
into / out of flat `Array U8 _` byte arrays.

The central abstraction is `Bytes.Repr T`: a *byte representation* of `T` — its
serialized width plus an `encode`/`decode` pair and their round-trip laws.  A
type has several representations (little- and big-endian), so `Repr` is a plain
**structure** (a first-class value), not a typeclass keyed on `T` (which would be
ambiguous).  The rest of the library is parametric in a `Repr`.

| | `T → Array U8 w` (`encode`) | `Array U8 w → T` (`decode`) |
|---|---|---|
| **LE** | `core.num.U32.to_le_bytes` | `core.num.U32.from_le_bytes` |
| **BE** | `core.num.U32.to_be_bytes` | `core.num.U32.from_be_bytes` |

Builds on `Intrinsics.Simd` (reusing `Std.Array.ofFn`/`getElem_ofFn`,
`Slice.subArray`, `fromLEBytes_congr`, …) so it composes with the rest of the
Intrinsics tree. -/

/-- Extensionality for fixed-size arrays via indexed elements. -/
theorem Std.Array.ext_getElem {α : Type} {n : Usize} {a b : Array α n}
    (h : ∀ k (hk : k < n.val), a[k] = b[k]) : a = b := by
  apply Subtype.ext
  apply List.ext_getElem (by rw [Array.length_eq, Array.length_eq])
  intro k h1 _
  exact h k (by rw [Array.length_eq] at h1; exact h1)

/-! ## Byte round-trip lemmas (companions to Simd's serialization layer) -/

/-- `BitVec.fromBEBytes` congruence under list equality (motive-safe via `subst`). -/
theorem fromBEBytes_congr {l₁ l₂ : List (BitVec 8)} (h : l₁ = l₂) :
    BitVec.fromBEBytes l₁ = (BitVec.fromBEBytes l₂).cast (by rw [h]) := by subst h; simp

/-! ## Missing `BitVec` byte round-trip lemmas

Aeneas ships only `BitVec.fromLEBytes_toLEBytes`.  These three complete the
square (`toLEBytes_fromLEBytes`, `fromBEBytes_toBEBytes`, `toBEBytes_fromBEBytes`)
and belong upstream in `Aeneas.Data.BitVec`; they are proved here for now. -/

/-- `BitVec.cast` commutes with `toLEBytes` (equal widths ⇒ same bytes). -/
theorem toLEBytes_cast {v w : ℕ} (h : v = w) (x : BitVec v) :
    (x.cast h).toLEBytes = x.toLEBytes := by subst h; simp

/-- `BitVec.cast` commutes with `toBEBytes` (equal widths ⇒ same bytes). -/
theorem toBEBytes_cast {v w : ℕ} (h : v = w) (x : BitVec v) :
    (x.cast h).toBEBytes = x.toBEBytes := by subst h; simp

/-- Decoding-then-encoding LE bytes is the identity (the missing converse of
    `BitVec.fromLEBytes_toLEBytes`). -/
theorem toLEBytes_fromLEBytes (L : List Byte) :
    (BitVec.fromLEBytes L).toLEBytes = L := by
  have hlen : (BitVec.fromLEBytes L).toLEBytes.length = L.length := by
    rw [BitVec.toLEBytes_length]; omega
  apply List.ext_getElem hlen
  intro i h1 h2
  rw [Byte.eq_iff]; intro j hj
  have hw : 8 * i + j < 8 * L.length := by
    calc 8 * i + j < 8 * i + 8 := by omega
      _ = 8 * (i + 1) := by ring
      _ ≤ 8 * L.length := Nat.mul_le_mul_left _ h2
  rw [BitVec.toLEBytes_getElem_testBit _ i j h1 ⟨hj, hw⟩, BitVec.fromLEBytes_getElem L (8 * i + j) hw]
  have hdiv : (8 * i + j) / 8 = i := by omega
  have hmod : (8 * i + j) % 8 = j := by omega
  simp only [hdiv, hmod]

/-- BE analog of `BitVec.fromLEBytes_toLEBytes`. -/
theorem fromBEBytes_toBEBytes {w : ℕ} (h : w % 8 = 0) (b : BitVec w) :
    BitVec.fromBEBytes b.toBEBytes = BitVec.cast (by simp only [BitVec.toBEBytes_length]; omega) b := by
  have key : b.toBEBytes.reverse = b.toLEBytes := by simp [BitVec.toBEBytes]
  unfold BitVec.fromBEBytes
  rw [fromLEBytes_congr key, BitVec.fromLEBytes_toLEBytes h]
  simp [BitVec.cast_cast]

/-- Decoding-then-encoding BE bytes is the identity. -/
theorem toBEBytes_fromBEBytes (L : List Byte) :
    (BitVec.fromBEBytes L).toBEBytes = L := by
  unfold BitVec.toBEBytes BitVec.fromBEBytes
  rw [toLEBytes_cast, toLEBytes_fromLEBytes, List.reverse_reverse]

/-! ## Arithmetic helpers for the windowing index map -/

private theorem div_window {i w j : Nat} (hj : j < w) : (i * w + j) / w = i := by
  rw [Nat.mul_comm, Nat.mul_add_div (by omega), Nat.div_eq_of_lt hj, Nat.add_zero]

private theorem mod_window {i w j : Nat} (hj : j < w) : (i * w + j) % w = j := by
  rw [Nat.mul_comm, Nat.mul_add_mod, Nat.mod_eq_of_lt hj]


/-! ## `Repr` — a byte representation of a type -/

/-- A byte representation of `T`: a fixed serialized `width`, an `encode`/`decode`
    pair between values and `width`-byte arrays, and their round-trip laws.  For
    fixed-width integers (LE/BE) `encode`/`decode` are mutually inverse, so both
    laws hold. -/
structure Bytes.Repr (T : Type) where
  width  : Usize
  encode : T → Array U8 width
  decode : Array U8 width → T
  /-- `decode` is a left inverse of `encode`. -/
  decode_encode : ∀ x, decode (encode x) = x
  /-- `encode` is a left inverse of `decode` (every byte block is a valid code). -/
  encode_decode : ∀ a, encode (decode a) = a

/-! ## Design note: should `Repr` carry a bit-vector view?

It is tempting to add a `toBV : T → BitVec (8 * width.val)` field (or a law
relating `encode` to `T`'s native `.bv`), since every Aeneas scalar type has a
`.bv`.  We deliberately do **not** put it in `Repr`, for two reasons:

* **Redundancy.** `toBV` is derivable as `(encode x).bv (·.bv)`, so as a field
  it stores no new information.
* **Over-constraining.** `Repr T` is generic over *any* `T : Type`.  Relating a
  bv view to `T`'s *native* `.bv` requires `T` to be an Aeneas scalar; baking
  that into `Repr` specializes an otherwise general abstraction.

The genuinely useful fact is the *endianness bridge* — `(encode x).bv (·.bv) =
perm (x.bv)` (identity for LE, `byteSwap` for BE) — which is what bv-level
intrinsics proofs consume.  When that is needed, prefer a thin extension over a
core field, e.g.

```
structure ScalarRepr (T) extends Repr T where
  toBV      : T → BitVec (8 * width.val)
  encode_bv : ∀ x, (encode x).bv (·.bv) = toBV x   -- LE: toBV = (·.bv); BE: byteSwap
```

keeping the generic combinators bv-agnostic and confining bv to where it is
meaningful. -/

/-! ## Generic, `Repr`-parametric array (de)serialization

The flat byte size is carried as a single `Usize` `nw` plus a factorization
hypothesis `hnw : nw.val = n.val * r.width.val`.  This is what makes the design
total: Aeneas scalar `*` is monadic (overflow-checked → `Result`), so
`Array U8 (n*w)` is not a well-formed type; threading `nw` + `hnw` instead both
names the size and encodes the no-overflow assumption. -/

/-- Decode `n` consecutive `width`-byte windows of a flat byte array into
    `Array T n`, under representation `r`.  Usable as `a.decode r hnw`. -/
def Aeneas.Std.Array.decode {T : Type} {nw n : Usize}
    (a : Array U8 nw) (r : Bytes.Repr T) (hnw : nw.val = n.val * r.width.val) : Array T n :=
  Std.Array.ofFn fun i : Fin n.val =>
    r.decode (Std.Array.ofFn fun j : Fin r.width.val =>
      have hb : i.val * r.width.val + j.val < a.val.length := by
        rw [Std.Array.length_eq a, hnw]
        calc i.val * r.width.val + j.val
            < i.val * r.width.val + r.width.val := by have := j.isLt; omega
          _ = (i.val + 1) * r.width.val         := by ring
          _ ≤ n.val * r.width.val               := Nat.mul_le_mul_right _ i.isLt
      a[i.val * r.width.val + j.val]'hb)

/-- Encode `Array T n` into `nw = n*width` bytes under representation `r`.  Byte
    `i` is byte `i % width` of the encoding of element `i / width`.  Usable as
    `a.encode r hnw`. -/
def Aeneas.Std.Array.encode {T : Type} {nw n : Usize}
    (a : Array T n) (r : Bytes.Repr T) (hnw : nw.val = n.val * r.width.val) : Array U8 nw :=
  Std.Array.ofFn fun i : Fin nw.val =>
    have hi : i.val < n.val * r.width.val := hnw ▸ i.isLt
    have hw : 0 < r.width.val := by
      rcases Nat.eq_zero_or_pos r.width.val with h | h
      · simp [h] at hi
      · exact h
    have hdiv : i.val / r.width.val < n.val :=
      Nat.div_lt_of_lt_mul (by rw [Nat.mul_comm]; exact hi)
    let row : Array U8 r.width := r.encode (a[i.val / r.width.val]'(by
      rw [Std.Array.length_eq a]; exact hdiv))
    row[i.val % r.width.val]'(by rw [Std.Array.length_eq row]; exact Nat.mod_lt _ hw)

/-! ## Indexing lemmas (the bridge intrinsic proofs reach for) -/

/-- `decode` commutes with indexing: the `i`-th decoded element is `r.decode`
    applied to the `i`-th `width`-byte window of `a`.  This is the entry point
    for reasoning about an individual lane of a decoded array. -/
theorem Aeneas.Std.Array.decode_getElem {T : Type} {nw n : Usize}
    (a : Array U8 nw) (r : Bytes.Repr T) (hnw : nw.val = n.val * r.width.val)
    (i : ℕ) (hi : i < n.val) :
    (a.decode r hnw)[i] = r.decode (Std.Array.ofFn fun j : Fin r.width.val =>
      a[i * r.width.val + j.val]'(by
        rw [Std.Array.length_eq a, hnw]
        calc i * r.width.val + j.val < i * r.width.val + r.width.val := by have := j.isLt; omega
          _ = (i + 1) * r.width.val := by ring
          _ ≤ n.val * r.width.val := Nat.mul_le_mul_right _ hi)) := by
  unfold Aeneas.Std.Array.decode
  rw [Std.Array.getElem_ofFn _ i hi]

/-! ## Generic array round-trip laws (the payoff of bundling the codec laws) -/

/-- Round-trip: encode an `Array T n`, then decode it back.
    mechanical — `ext_getElem`, then per element reduce the rebuilt window to
    `r.encode a[i]` via `getElem_ofFn` + `div_window`/`mod_window`, then
    `r.decode_encode`. -/
theorem Aeneas.Std.Array.decode_encode {T : Type} {nw n : Usize}
    (a : Array T n) (r : Bytes.Repr T) (hnw : nw.val = n.val * r.width.val) :
    (a.encode r hnw).decode r hnw = a := by
  apply Std.Array.ext_getElem; intro i hi
  unfold Aeneas.Std.Array.decode
  rw [Std.Array.getElem_ofFn _ i hi]
  rw [← r.decode_encode (a[i]'(by rw [Std.Array.length_eq]; exact hi))]
  fcongr 1
  apply Std.Array.ext_getElem; intro j hj
  have hb : i * r.width.val + j < nw.val := by
    rw [hnw]
    calc i * r.width.val + j < i * r.width.val + r.width.val := by omega
      _ = (i + 1) * r.width.val := by ring
      _ ≤ n.val * r.width.val := Nat.mul_le_mul_right _ hi
  rw [Std.Array.getElem_ofFn _ j hj]
  unfold Aeneas.Std.Array.encode
  rw [Std.Array.getElem_ofFn _ (i * r.width.val + j) hb]
  simp only [div_window hj, mod_window hj]

/-- Round-trip: decode a flat byte array, then re-encode it.
    Symmetric to `decode_encode`, using `r.encode_decode`. -/
theorem Aeneas.Std.Array.encode_decode {T : Type} {nw n : Usize}
    (a : Array U8 nw) (r : Bytes.Repr T) (hnw : nw.val = n.val * r.width.val) :
    (a.decode r hnw).encode r hnw = a := by
  apply Std.Array.ext_getElem; intro i hi
  have hi' : i < n.val * r.width.val := hnw ▸ hi
  have hw : 0 < r.width.val := by
    rcases Nat.eq_zero_or_pos r.width.val with h | h
    · simp [h] at hi'
    · exact h
  have hdiv : i / r.width.val < n.val := Nat.div_lt_of_lt_mul (by rw [Nat.mul_comm]; exact hi')
  have hmod : i % r.width.val < r.width.val := Nat.mod_lt _ hw
  have hidx : i / r.width.val * r.width.val + i % r.width.val = i := by
    rw [Nat.mul_comm]; exact Nat.div_add_mod i r.width.val
  unfold Aeneas.Std.Array.encode Aeneas.Std.Array.decode
  simp only [Std.Array.getElem_ofFn, r.encode_decode, hidx, hi, hdiv, hmod]

/-! ## Generic `Repr` for every Aeneas unsigned integer

`uscalarLE`/`uscalarBE ty w hw` build the little- and big-endian representation of
`UScalar ty` from `width = w` and the size proof `hw : ty.numBits = 8 * w.val`.
Working directly on `UScalar ty` (rather than the per-type `core.num.«%S».*`
functions) makes a single construction cover U8/U16/U32/U64/U128/Usize; the
concrete instances below are one-liners. -/

/-- `width`-byte little-endian serialization of `UScalar ty`. -/
def Bytes.uscalarToLE {ty : UScalarTy} (w : Usize) (hw : ty.numBits = 8 * w.val)
    (x : UScalar ty) : Array U8 w :=
  ⟨x.bv.toLEBytes.map UScalar.mk, by rw [List.length_map, BitVec.toLEBytes_length, hw]; omega⟩

/-- Little-endian deserialization of `UScalar ty`. -/
def Bytes.uscalarFromLE {ty : UScalarTy} (w : Usize) (hw : ty.numBits = 8 * w.val)
    (a : Array U8 w) : UScalar ty :=
  ⟨(BitVec.fromLEBytes (a.val.map U8.bv)).cast (by rw [List.length_map, Aeneas.Std.Array.length_eq, hw])⟩

/-- `width`-byte big-endian serialization of `UScalar ty`. -/
def Bytes.uscalarToBE {ty : UScalarTy} (w : Usize) (hw : ty.numBits = 8 * w.val)
    (x : UScalar ty) : Array U8 w :=
  ⟨x.bv.toBEBytes.map UScalar.mk, by rw [List.length_map, BitVec.toBEBytes_length, hw]; omega⟩

/-- Big-endian deserialization of `UScalar ty`. -/
def Bytes.uscalarFromBE {ty : UScalarTy} (w : Usize) (hw : ty.numBits = 8 * w.val)
    (a : Array U8 w) : UScalar ty :=
  ⟨(BitVec.fromBEBytes (a.val.map U8.bv)).cast (by rw [List.length_map, Aeneas.Std.Array.length_eq, hw])⟩

/-- The little-endian byte representation of any `UScalar ty`. -/
def Bytes.Repr.uscalarLE {ty : UScalarTy} (w : Usize) (hw : ty.numBits = 8 * w.val) :
    Bytes.Repr (UScalar ty) where
  width  := w
  encode := Bytes.uscalarToLE w hw
  decode := Bytes.uscalarFromLE w hw
  decode_encode := by
    intro x; rw [UScalar.eq_equiv_bv_eq]
    show (Bytes.uscalarFromLE w hw (Bytes.uscalarToLE w hw x)).bv = x.bv
    unfold Bytes.uscalarFromLE Bytes.uscalarToLE
    have key : List.map U8.bv (x.bv.toLEBytes.map (@UScalar.mk UScalarTy.U8)) = x.bv.toLEBytes := by
      rw [List.map_map, show (U8.bv ∘ (@UScalar.mk UScalarTy.U8) : Byte → Byte) = id from by
        funext b; rfl, List.map_id]
    apply BitVec.eq_of_getLsbD_eq; intro j _
    rw [fromLEBytes_congr key, BitVec.fromLEBytes_toLEBytes (by omega)]; simp
  encode_decode := by
    intro a; apply Subtype.ext
    simp only [Bytes.uscalarToLE, Bytes.uscalarFromLE, toLEBytes_cast, toLEBytes_fromLEBytes,
      List.map_map]
    rw [show (UScalar.mk ∘ U8.bv : U8 → U8) = id from by funext b; rfl, List.map_id]

/-- The big-endian byte representation of any `UScalar ty`. -/
def Bytes.Repr.uscalarBE {ty : UScalarTy} (w : Usize) (hw : ty.numBits = 8 * w.val) :
    Bytes.Repr (UScalar ty) where
  width  := w
  encode := Bytes.uscalarToBE w hw
  decode := Bytes.uscalarFromBE w hw
  decode_encode := by
    intro x; rw [UScalar.eq_equiv_bv_eq]
    show (Bytes.uscalarFromBE w hw (Bytes.uscalarToBE w hw x)).bv = x.bv
    unfold Bytes.uscalarFromBE Bytes.uscalarToBE
    have key : List.map U8.bv (x.bv.toBEBytes.map (@UScalar.mk UScalarTy.U8)) = x.bv.toBEBytes := by
      rw [List.map_map, show (U8.bv ∘ (@UScalar.mk UScalarTy.U8) : Byte → Byte) = id from by
        funext b; rfl, List.map_id]
    apply BitVec.eq_of_getLsbD_eq; intro j _
    rw [fromBEBytes_congr key, fromBEBytes_toBEBytes (by omega)]; simp
  encode_decode := by
    intro a; apply Subtype.ext
    simp only [Bytes.uscalarToBE, Bytes.uscalarFromBE, toBEBytes_cast, toBEBytes_fromBEBytes,
      List.map_map]
    rw [show (UScalar.mk ∘ U8.bv : U8 → U8) = id from by funext b; rfl, List.map_id]

/-! ## Concrete instances (one line each, for every width). -/

def Bytes.Repr.u32le : Bytes.Repr U32 := Bytes.Repr.uscalarLE 4#usize (by decide)
def Bytes.Repr.u32be : Bytes.Repr U32 := Bytes.Repr.uscalarBE 4#usize (by decide)
def Bytes.Repr.u16le : Bytes.Repr U16 := Bytes.Repr.uscalarLE 2#usize (by decide)
def Bytes.Repr.u16be : Bytes.Repr U16 := Bytes.Repr.uscalarBE 2#usize (by decide)
def Bytes.Repr.u64le : Bytes.Repr U64 := Bytes.Repr.uscalarLE 8#usize (by decide)
def Bytes.Repr.u64be : Bytes.Repr U64 := Bytes.Repr.uscalarBE 8#usize (by decide)

/-! Width-reduction `@[simp]` lemmas: make `r.width` reduce to its literal so
that `decode`/`encode` factorization side-goals and `getElem_ofFn` bounds
discharge automatically. -/
@[simp] theorem Bytes.Repr.u32le_width : Bytes.Repr.u32le.width = 4#usize := rfl
@[simp] theorem Bytes.Repr.u32be_width : Bytes.Repr.u32be.width = 4#usize := rfl
@[simp] theorem Bytes.Repr.u16le_width : Bytes.Repr.u16le.width = 2#usize := rfl
@[simp] theorem Bytes.Repr.u16be_width : Bytes.Repr.u16be.width = 2#usize := rfl
@[simp] theorem Bytes.Repr.u64le_width : Bytes.Repr.u64le.width = 8#usize := rfl
@[simp] theorem Bytes.Repr.u64be_width : Bytes.Repr.u64be.width = 8#usize := rfl


/-! ## Lane bit-vector bridges (for intrinsics proofs)

Intrinsics proofs reason at the per-byte bit-vector-concat level, so they need
to connect a decoded lane back to the concat of its source bytes.  `u32be` is the
big-endian reading (`byte0` is most significant), so its `.bv` is `b0 ++ b1 ++ b2
++ b3` (most-significant first).  Companion `u32le` lanes are `Simd`'s
`Array.bv`.  (The fully generic per-`Repr` bridge — the `ScalarRepr` extension
noted above — would derive these uniformly; these concrete u32 lemmas are what
the SHA-NI shims need today.) -/

private theorem cast_fromLEBytes_quad (b0 b1 b2 b3 : BitVec 8)
    (h : 8 * [b3, b2, b1, b0].length = 32) :
    BitVec.cast h (BitVec.fromLEBytes [b3, b2, b1, b0]) = b0 ++ b1 ++ b2 ++ b3 := by
  simp only [BitVec.fromLEBytes, List.length_cons, List.length_nil]; bv_decide

/-- **u32be lane = big-endian byte concat.** Decoding 4 bytes big-endian yields
    the `U32` whose bit-vector is `w[0] ++ w[1] ++ w[2] ++ w[3]` (byte 0 = MSB). -/
theorem u32be_decode_bv (w : Array U8 4#usize) :
    (Bytes.Repr.u32be.decode w).bv = w[0].bv ++ w[1].bv ++ w[2].bv ++ w[3].bv := by
  show (Bytes.uscalarFromBE 4#usize (by decide) w).bv = _
  unfold Bytes.uscalarFromBE
  have hm : List.map U8.bv w.val = [w[0].bv, w[1].bv, w[2].bv, w[3].bv] := by
    apply List.ext_getElem (by simp)
    intro k hk _
    have hk4 : k < 4 := by simp only [List.length_map, Aeneas.Std.Array.length_eq] at hk; scalar_tac
    rw [List.getElem_map]
    match k, hk4 with
    | 0, _ => rfl | 1, _ => rfl | 2, _ => rfl | 3, _ => rfl | n+4, h => omega
  rw [fromBEBytes_congr hm, BitVec.fromBEBytes]
  rw [fromLEBytes_congr (show ([w[0].bv, w[1].bv, w[2].bv, w[3].bv]).reverse
        = [w[3].bv, w[2].bv, w[1].bv, w[0].bv] from rfl)]
  simp only [BitVec.cast_cast]
  exact cast_fromLEBytes_quad w[0].bv w[1].bv w[2].bv w[3].bv _

/-- **u32le lane = little-endian byte concat.** Decoding 4 bytes little-endian
    yields the `U32` whose bit-vector is `w[3] ++ w[2] ++ w[1] ++ w[0]` (byte 0 =
    LSB).  Companion to `u32be_decode_bv`. -/
theorem u32le_decode_bv (w : Array U8 4#usize) :
    (Bytes.Repr.u32le.decode w).bv = w[3].bv ++ w[2].bv ++ w[1].bv ++ w[0].bv := by
  show (Bytes.uscalarFromLE 4#usize (by decide) w).bv = _
  unfold Bytes.uscalarFromLE
  have hm : List.map U8.bv w.val = [w[0].bv, w[1].bv, w[2].bv, w[3].bv] := by
    apply List.ext_getElem (by simp)
    intro k hk _
    have hk4 : k < 4 := by simp only [List.length_map, Aeneas.Std.Array.length_eq] at hk; scalar_tac
    rw [List.getElem_map]
    match k, hk4 with
    | 0, _ => rfl | 1, _ => rfl | 2, _ => rfl | 3, _ => rfl | n+4, h => omega
  rw [fromLEBytes_congr hm]; simp only [BitVec.cast_cast]
  exact cast_fromLEBytes_quad w[3].bv w[2].bv w[1].bv w[0].bv _

/-! ### Array-level lane bridges

`u32{be,le}_decode_getElem_bv` lift the single-window `u32{be,le}_decode_bv` to
an *array* of windows: lane `i` of `a.decode u32be` (or `u32le`) is the
big-endian (resp. little-endian) concat of source bytes `a[4i .. 4i+3]`.  These
are what intrinsic load/store proofs reach for after `Std.Array.ext_getElem`.

The proof composes `Array.decode_getElem` (lane → window), the single-window
`u32{be,le}_decode_bv`, and `grind [Std.Array.getElem_ofFn]` to discharge the
window's `ofFn` lane access (whose `k < n.val` bound `rw`/`simp only` cannot
unify, but `grind` can). -/

/-- Lane `i` of a `u32be`-decoded byte array = big-endian concat of `a[4i..4i+3]`. -/
theorem u32be_decode_getElem_bv {nw n : Usize} (a : Array U8 nw)
    (hnw : nw.val = n.val * 4) (i : ℕ) (hi : i < n.val) :
    ((a.decode Bytes.Repr.u32be (by rw [Bytes.Repr.u32be_width]; exact hnw))[i]).bv
      = (a[4*i]'(by rw [Aeneas.Std.Array.length_eq, hnw]; omega)).bv
      ++ (a[4*i+1]'(by rw [Aeneas.Std.Array.length_eq, hnw]; omega)).bv
      ++ (a[4*i+2]'(by rw [Aeneas.Std.Array.length_eq, hnw]; omega)).bv
      ++ (a[4*i+3]'(by rw [Aeneas.Std.Array.length_eq, hnw]; omega)).bv := by
  rw [Aeneas.Std.Array.decode_getElem a Bytes.Repr.u32be _ i hi, u32be_decode_bv]
  simp only [Bytes.Repr.u32be_width]; grind [Std.Array.getElem_ofFn]

/-- `getElem!`-form of `u32be_decode_getElem_bv`: lane `i` as a `getElem!` byte
    concat (no baked-in bound proofs, so it `rw`s cleanly into downstream goals
    that reason with `[·]!`).  This is the form intrinsic load proofs consume. -/
theorem u32be_decode_getElem!_bv {nw n : Usize} (a : Array U8 nw)
    (hnw : nw.val = n.val * 4) (i : ℕ) (hi : i < n.val) :
    ((a.decode Bytes.Repr.u32be (by rw [Bytes.Repr.u32be_width]; exact hnw))[i]).bv
      = a.val[4*i]!.bv ++ a.val[4*i+1]!.bv ++ a.val[4*i+2]!.bv ++ a.val[4*i+3]!.bv := by
  have hb : ∀ c, c < 4 → 4*i+c < a.val.length := by
    intro c hc; rw [Aeneas.Std.Array.length_eq, hnw]; omega
  rw [u32be_decode_getElem_bv a hnw i hi,
      Aeneas.Std.Array.getElem_Nat_eq a (4*i)   (hb 0 (by omega)),
      Aeneas.Std.Array.getElem_Nat_eq a (4*i+1) (hb 1 (by omega)),
      Aeneas.Std.Array.getElem_Nat_eq a (4*i+2) (hb 2 (by omega)),
      Aeneas.Std.Array.getElem_Nat_eq a (4*i+3) (hb 3 (by omega)),
      ← getElem!_pos a.val (4*i)   (hb 0 (by omega)),
      ← getElem!_pos a.val (4*i+1) (hb 1 (by omega)),
      ← getElem!_pos a.val (4*i+2) (hb 2 (by omega)),
      ← getElem!_pos a.val (4*i+3) (hb 3 (by omega))]

/-- Lane `i` of a `u32le`-decoded byte array = little-endian concat of `a[4i..4i+3]`. -/
theorem u32le_decode_getElem_bv {nw n : Usize} (a : Array U8 nw)
    (hnw : nw.val = n.val * 4) (i : ℕ) (hi : i < n.val) :
    ((a.decode Bytes.Repr.u32le (by rw [Bytes.Repr.u32le_width]; exact hnw))[i]).bv
      = (a[4*i+3]'(by rw [Aeneas.Std.Array.length_eq, hnw]; omega)).bv
      ++ (a[4*i+2]'(by rw [Aeneas.Std.Array.length_eq, hnw]; omega)).bv
      ++ (a[4*i+1]'(by rw [Aeneas.Std.Array.length_eq, hnw]; omega)).bv
      ++ (a[4*i]'(by rw [Aeneas.Std.Array.length_eq, hnw]; omega)).bv := by
  rw [Aeneas.Std.Array.decode_getElem a Bytes.Repr.u32le _ i hi, u32le_decode_bv]
  simp only [Bytes.Repr.u32le_width]; grind [Std.Array.getElem_ofFn]
