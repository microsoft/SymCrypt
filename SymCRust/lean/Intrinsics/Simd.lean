/-
  Copyright (c) Microsoft Corporation. All rights reserved.
  Licensed under the MIT license.
-/
import Aeneas
open Aeneas Std

-- Default tactic for `[]` indexing: try assumption first, then Std.Array.length_eq + omega.
local macro_rules
  | `(tactic| get_elem_tactic) =>
    `(tactic| first | assumption | grind)

/-! # Intrinsics/Simd.lean — SIMD register library

Two-layer design:

## Layer 1 — BitVec split / concat (no scalar wrappers)

    Register k n = BitVec (k * n.val)

    Register.ofFn f  : (Fin n.val → BitVec k) → Register   (build from lanes)
    v.slice i        : BitVec k                             (extract lane i)
    a.toBV           : Array (BitVec k) n → Register       (pack array)

Round-trips:
    (Register.ofFn f).slice i = f ⟨i, hi⟩
    Register.ofFn (fun i => v.slice i) = v

Bitwise ops (XOR, AND, OR) distribute over slices for free.

## Layer 2 — Scalar conversions (UScalar / IScalar)

    v.lane scalar    : Register → Array t n            (split + wrap)
    a.bv toBits      : Array t n → Register            (unwrap + pack)

Sugar: `v.u16x8`, `v.i16x8`, etc.
Round-trips hold whenever `scalar ∘ toBits = id` / `bv ∘ scalar = id`.

## Layer 2 (cont.) — Multilane nesting

A multilane value (`U16x16`, `U32x8`, …) is just an `Array` of `Array`s, so the
single-layer brick `Std.Array.bv` applied **twice** packs it. The nesting law

    Std.Array.bv_nest : aa.bv (·.bv) = (flat.bv toBits).cast _

says packing an array-of-arrays equals packing its flattening, and

    Std.Array.bv_transmute : same flat byte list ⟹ same register

is the transmute / injectivity corollary: the register's bits are *determined by
the flat `[U8; N]`*. This is the working contract — see Design decisions.

## Design decisions

* **Flat `[U8; N]` is the normal form.** Following Rust's `src/verify`, proofs
  normalize register values to flat byte arrays and discharge equalities at the
  byte / `List` level. The *bit* level appears only here in the foundation
  (`extractLsb'`, `getLsbD`); downstream lane proofs stay byte-algebraic.
* **`Std.Array.bv` is the only packing primitive; there is no `Array.flatten` def.**
  On Aeneas arrays flattening is *partial*: `Array (Array S m) N` is always
  well-formed, but its flattening has length `m*N`, which can exceed `2^64` —
  no `Usize` may hold it. So nesting is **relational**: the flat array is given
  explicitly, and we **reuse Lean's `List.flatten`** for the hypothesis
  (`b.val = (aa.val.map (·.val)).flatten`).
* **Lane ordering is little-endian and uniform.** Index 0 = least significant;
  lane `i` at bit offset `width·i`. This matches Aeneas `from_le_bytes`/`bv` and
  the x86/NEON intrinsic carriers (they are *defined* on this hub), so lane
  proofs move between `from_le_bytes`, `Std.Array.bv` and `__m128i.u32x4` with no
  byte permutation.

## Provenance (reused vs. new)

* **Reused from Lean core**: `BitVec.extractLsb'` (the slice function),
  `getLsbD_extractLsb'`, `getElem_extractLsb'`, `eq_of_getLsbD_eq`,
  `List.flatten` / `List.length_flatten`. **From Aeneas**: `BitVec.extractLsb'_cast`,
  `BitVec.fromLEBytes`/`toLEBytes`, the scalar `.bv`/`UScalar.mk` bridge.
* **New small derived lemmas**:
  `BitVec.extractLsb'_extractLsb'` (slice-of-slice), `BitVec.ext_chunks`
  (window extensionality), `List.getElem?_flatten_const` (constant-chunk
  flatten indexing), and the `Array.bv_*` nesting/transmute lemmas built on them.

Rust code already operates on arrays, so specs stay in array terms; Register
helps when reasoning across typed views.
-/

-- ============================================================================
-- Core type
-- ============================================================================

/-- SIMD register: `k`-bit lanes × `n` lanes. Transparent `BitVec`. -/
abbrev Register (k : Nat) (n : Usize) := BitVec (k * n.val)

-- ============================================================================
-- Lane-array type abbreviations (mirroring lanes.rs)
-- ============================================================================

namespace Intrinsics

abbrev U8x16  : Type := Array U8  16#usize
abbrev U16x4  : Type := Array U16  4#usize
abbrev U16x8  : Type := Array U16  8#usize
abbrev U32x2  : Type := Array U32  2#usize
abbrev U32x4  : Type := Array U32  4#usize
abbrev U64x2  : Type := Array U64  2#usize

abbrev U8x32  : Type := Array U8  32#usize
abbrev U16x16 : Type := Array U16 16#usize
abbrev U32x8  : Type := Array U32  8#usize
abbrev U64x4  : Type := Array U64  4#usize

-- Arch-neutral byte-carrier register types: a `k`-bit SIMD register modelled as
-- its `k/8` little-endian bytes (the Lean image of Rust's `M128 = Bytes = [u8;16]`
-- thin abbrev). Specs/proofs view their lanes through the `Register` hub directly
-- (`Register.u16x8 (a.bv (·.bv))`, …).
abbrev M128 : Type := U8x16
abbrev M256 : Type := U8x32

end Intrinsics

/-- [core::core_arch::x86::__m128i] — the concrete byte carrier `Intrinsics.M128`
    (`= Array U8 16`).  The `@[rust_type]` binding for the silicon register type
    lives here (in `Intrinsics.Simd`, a leaf importing only `Aeneas`) rather than
    in the generated `Code/TypesExternal.lean`, so that:
      * there is a single source of truth for the carrier concretization, and
      * `scripts/prune-external-template.py` can strip the opaque
        opaque `core.core_arch.x86.__m128i : Type` declaration from
        `TypesExternal_Template` and inject `import Intrinsics.Simd` —
        codifying the concretization the same way `@[rust_fun]` silicon
        bindings are, instead of a hand-edit.
    `Code/TypesExternal.lean` imports this file (no cycle: `Simd` is a leaf). -/
@[rust_type "core::core_arch::x86::__m128i"]
def core.core_arch.x86.__m128i : Type := Intrinsics.M128

-- ============================================================================
-- Std.Array.ofFn (needed for lane and intrinsic defs)
-- ============================================================================

/-- Build `Array α n` from a function. -/
def Std.Array.ofFn {α : Type} {n : Usize}
    (f : Fin n.val → α) : Array α n :=
  Std.Array.make n ((_root_.Array.ofFn f).toList)

@[simp] theorem Std.Array.getElem_ofFn {α : Type} {n : Usize}
    (f : Fin n.val → α) (k : ℕ) (hk : k < n.val) :
    (Std.Array.ofFn f)[k] = f ⟨k, hk⟩ := by
  grind [Std.Array.ofFn, Std.Array.make, _root_.Array.toList_ofFn]

/-- `(Array.repeat n x)[k] = x` -/
@[simp] theorem Std.Array.getElem_repeat {α : Type} (n : Usize) (x : α)
    (k : Nat) (hk : k < n.val) :
    (Array.repeat n x)[k] = x := by
  show (Array.repeat n x).val[k]'(by simp [Array.repeat_val]; exact hk) = x
  simp only [Array.repeat_val]
  exact List.getElem_replicate (by simp [List.length_replicate]; exact hk)

/-- `(Array.repeat n x)[k] = y` when `x = y`: folds the broadcast value through an
    equation so load-and-broadcast (`vld1q_dup`) specs close in one `exact`.  The
    index bound is discharged by `scalar_tac` by default. -/
theorem Std.Array.getElem_repeat_eq {α : Type} {n : Usize} {x y : α} {k : Nat}
    (h : x = y) (hk : k < n.val := by scalar_tac) :
    (Array.repeat n x)[k] = y :=
  (Std.Array.getElem_repeat n x k hk).trans h

/-- The `n`-element window `s[at .. at+n]` of a slice as a genuine fixed-size
    `Array α n`.  The bound `h : at + n ≤ s.length` guarantees the window is
    exactly `n` elements long, so no junk/padding is needed — pairs with
    `Array.bv` to talk about the bit-packing of a loaded window. -/
def Aeneas.Std.Slice.subArray {α : Type} (s : Aeneas.Std.Slice α) (at1 n : Usize)
    (h : at1.val + n.val ≤ s.length) : Aeneas.Std.Array α n :=
  ⟨s.val.slice at1.val (at1.val + n.val), by
    rw [List.slice_length]; have hs : s.length = s.val.length := rfl; omega⟩

@[simp] theorem Aeneas.Std.Slice.subArray_val {α : Type} (s : Aeneas.Std.Slice α)
    (at1 n : Usize) (h : at1.val + n.val ≤ s.length) :
    (s.subArray at1 n h).val = s.val.slice at1.val (at1.val + n.val) := rfl

-- ╔══════════════════════════════════════════════════════════════════════════╗
-- ║  LAYER 1 — BitVec split / concat                                       ║
-- ╚══════════════════════════════════════════════════════════════════════════╝

-- ============================================================================
-- Internal: LE concatenation of k-bit vectors
-- ============================================================================

/-- Concatenate a list of k-bit vectors (LE: head = low bits). -/
def listToBV : (l : List (BitVec k)) → BitVec (k * l.length)
  | [] => .cast (by simp) 0#0
  | b :: bs => .cast (by grind) (listToBV bs ++ b)

theorem listToBV_extractLsb' {k : Nat} (l : List (BitVec k))
    (i : Nat) (hi : i < l.length) :
    (listToBV l).extractLsb' (k * i) k = l[i] := by
  induction l generalizing i with
  | nil => grind
  | cons b bs ih =>
    simp only [listToBV, BitVec.extractLsb'_cast]
    cases i with
    | zero => grind
    | succ i' => grind

theorem listToBV_ofFn_extractLsb' {k n : Nat} (v : BitVec (k * n)) :
    listToBV (List.ofFn (fun (i : Fin n) => v.extractLsb' (k * i.val) k))
      = .cast (by grind) v := by
  apply BitVec.eq_of_getLsbD_eq; intro j hj
  simp only [BitVec.getLsbD_cast]
  by_cases hk : k = 0
  · subst hk; simp at hj
  · have hkp : 0 < k := Nat.pos_of_ne_zero hk
    set L := listToBV (List.ofFn (n := n) (fun i : Fin n => v.extractLsb' (k * ↑i) k))
    have hj_eq : L.getLsbD j = (L.extractLsb' (k * (j / k)) k).getLsbD (j % k) := by
      simp only [BitVec.getLsbD_extractLsb']
      rw [show decide (j % k < k) = true from decide_eq_true (Nat.mod_lt j hkp),
          Bool.true_and, show k * (j / k) + j % k = j from Nat.div_add_mod j k]
    rw [hj_eq, listToBV_extractLsb' _ (j / k) (by
      simp only [List.length_ofFn]; exact Nat.div_lt_of_lt_mul (by
        simp only [List.length_ofFn] at hj; exact hj))]
    simp [List.getElem_ofFn, BitVec.getLsbD_extractLsb']
    rw [show decide (j % k < k) = true from decide_eq_true (Nat.mod_lt j hkp),
        Bool.true_and, show k * (j / k) + j % k = j from Nat.div_add_mod j k]

/-- Nested extraction composes: a `len2`-window of a `len1`-window of `x`
    (offsets `a` then `b`) is the `len2`-window of `x` at offset `a + b`. -/
theorem BitVec.extractLsb'_extractLsb' {w : Nat} (x : BitVec w) (a b len1 len2 : Nat)
    (h : b + len2 ≤ len1) :
    (x.extractLsb' a len1).extractLsb' b len2 = x.extractLsb' (a + b) len2 := by
  ext i hi
  simp only [BitVec.getElem_extractLsb', BitVec.getLsbD_extractLsb']
  have h1 : b + i < len1 := by omega
  rw [show a + (b + i) = a + b + i by ring]; simp [h1]

/-- Chunk extensionality: two `BitVec`s of width `W * Ntot` are equal iff all
    their `Ntot` consecutive `W`-bit windows agree. The total width is supplied
    as an equation so the lemma applies to any width expression (e.g. `(k*m)*N`). -/
theorem BitVec.ext_chunks {tot W Ntot : Nat} (htot : tot = W * Ntot) (hW : 0 < W)
    (u v : BitVec tot)
    (h : ∀ idx, idx < Ntot → u.extractLsb' (W * idx) W = v.extractLsb' (W * idx) W) :
    u = v := by
  subst htot
  apply BitVec.eq_of_getLsbD_eq; intro j hj
  have hkN : j / W < Ntot := Nat.div_lt_of_lt_mul hj
  have hb := congrArg (fun b => BitVec.getLsbD b (j % W)) (h (j / W) hkN)
  simp only [BitVec.getLsbD_extractLsb', Nat.mod_lt _ hW, decide_true, Bool.true_and] at hb
  have he : W * (j / W) + j % W = j := by conv_rhs => rw [← Nat.div_add_mod j W]
  rwa [he] at hb

-- ============================================================================
-- Layer 1 API
-- ============================================================================

/-- Extract lane `i` as raw `BitVec k`. Lane 0 = low bits. -/
abbrev Register.slice {k : Nat} {n : Usize}
    (v : Register k n) (i : Nat) : BitVec k :=
  v.extractLsb' (k * i) k

/-- Build register from a lane function. The Layer 1 primitive. -/
def Register.ofFn {k : Nat} {n : Usize}
    (f : Fin n.val → BitVec k) : Register k n :=
  .cast (by simp [List.length_ofFn]) (listToBV (List.ofFn f))

/-- Pack bitvec array into register. -/
def Aeneas.Std.Array.toBV {k : Nat} {n : Usize}
    (a : Array (BitVec k) n) : Register k n :=
  Register.ofFn (fun i => a[i])

-- ============================================================================
-- Layer 1 round-trips
-- ============================================================================

@[simp] theorem Register.ofFn_slice {k : Nat} {n : Usize}
    (f : Fin n.val → BitVec k) (i : Nat) (hi : i < n) :
    (Register.ofFn f).slice i = f ⟨i, hi⟩ := by
  unfold Register.ofFn Register.slice
  simp only [BitVec.extractLsb'_cast]
  rw [listToBV_extractLsb' _ i (by simp; exact hi)]
  simp [List.getElem_ofFn]

@[simp] theorem Register.slice_ofFn {k : Nat} {n : Usize}
    (v : Register k n) :
    Register.ofFn (fun i => v.slice i) = v := by
  unfold Register.ofFn Register.slice
  have h := listToBV_ofFn_extractLsb' v
  rw [h]; simp [BitVec.cast_cast]

@[simp] theorem Register.toBV_slice {k : Nat} {n : Usize}
    (a : Array (BitVec k) n) (i : Nat) (hi : i < n) :
    (a.toBV).slice i = a[i] := by
  show (Register.ofFn (fun i => a[i])).slice i = a[i]
  rw [Register.ofFn_slice _ i hi]; rfl

-- ============================================================================
-- Layer 1: bitwise distributivity
-- ============================================================================

@[simp] theorem Register.slice_xor {k : Nat} {n : Usize}
    (a b : Register k n) (i : Nat) :
    (a ^^^ b).slice i = a.slice i ^^^ b.slice i :=
  BitVec.extractLsb'_xor ..

@[simp] theorem Register.slice_and {k : Nat} {n : Usize}
    (a b : Register k n) (i : Nat) :
    (a &&& b).slice i = a.slice i &&& b.slice i :=
  BitVec.extractLsb'_and ..

@[simp] theorem Register.slice_or {k : Nat} {n : Usize}
    (a b : Register k n) (i : Nat) :
    (a ||| b).slice i = a.slice i ||| b.slice i :=
  BitVec.extractLsb'_or ..

-- ╔══════════════════════════════════════════════════════════════════════════╗
-- ║  LAYER 2 — Scalar conversions                                          ║
-- ╚══════════════════════════════════════════════════════════════════════════╝

/-- Split register into typed lanes: `v.lane scalar`. Lane 0 = low bits. -/
def Register.lane {t : Type} {k : Nat} {n : Usize}
    (v : Register k n) (scalar : BitVec k → t) : Array t n :=
  Std.Array.ofFn (fun (i : Fin n.val) => scalar (v.extractLsb' (k * i.val) k))

/-- Pack typed array into register: `a.bv toBits`. -/
def Aeneas.Std.Array.bv {t : Type} {k : Nat} {n : Usize}
    (a : Array t n) (toBits : t → BitVec k) : Register k n :=
  Register.ofFn (fun i => toBits a[i])

-- ============================================================================
-- Simp lemmas
-- ============================================================================

@[simp] theorem Register.lane_getElem {t : Type} {k : Nat} {n : Usize}
    (v : Register k n) (scalar : BitVec k → t)
    (i : Nat) (hi : i < n) :
    (v.lane scalar)[i] = scalar (v.extractLsb' (k * i) k) := by
  unfold Register.lane
  grind [Std.Array.getElem_ofFn]

@[simp] theorem UScalar.mk_bv {ty : UScalarTy} (x : UScalar ty) :
    UScalar.mk x.bv = x := by cases x; rfl
@[simp] theorem UScalar.bv_mk {ty : UScalarTy} (v : BitVec ty.numBits) :
    (UScalar.mk v).bv = v := rfl
@[simp] theorem IScalar.mk_bv {ty : IScalarTy} (x : IScalar ty) :
    IScalar.mk x.bv = x := by cases x; rfl
@[simp] theorem IScalar.bv_mk {ty : IScalarTy} (v : BitVec ty.numBits) :
    (IScalar.mk v).bv = v := rfl

-- ============================================================================
-- Layer 2 round-trips
-- ============================================================================

@[simp] theorem Std.Array.ofFn_eta {α : Type} {n : Usize}
    (a : Array α n) : Std.Array.ofFn (fun i => a[i.val]) = a := by
  apply Subtype.ext
  simp only [Std.Array.ofFn, Std.Array.make, _root_.Array.toList_ofFn]
  apply List.ext_getElem (by rw [List.length_ofFn, a.property])
  intro i h1 h2; rw [List.getElem_ofFn]; rfl

/-- Round-trip: pack then split = identity. -/
@[simp] theorem Register.lane_bv {t : Type} {k : Nat} {n : Usize}
    (scalar : BitVec k → t) (toBits : t → BitVec k)
    (hinv : ∀ x, scalar (toBits x) = x) (a : Array t n) :
    (a.bv toBits).lane scalar = a := by
  show Std.Array.ofFn (fun i => scalar ((Register.ofFn
    (fun j => toBits a[j])).slice i.val)) = a
  simp [Register.ofFn_slice, hinv]; exact Std.Array.ofFn_eta a

/-- Round-trip: split then pack = identity. -/
@[simp] theorem Register.bv_lane {t : Type} {k : Nat} {n : Usize}
    (scalar : BitVec k → t) (toBits : t → BitVec k)
    (hinv : ∀ v, toBits (scalar v) = v) (v : Register k n) :
    (v.lane scalar).bv toBits = v := by
  show Register.ofFn (fun i => toBits ((Std.Array.ofFn
    (fun j => scalar (v.slice j)))[i])) = v
  have h : ∀ (i : Fin n.val), (Std.Array.ofFn (fun j => scalar (v.slice j)))[i.val]
      = scalar (v.slice i.val) := fun i => Std.Array.getElem_ofFn _ i.val i.isLt
  simp only [Fin.getElem_fin, h, hinv, Register.slice_ofFn]

-- ============================================================================
-- Lane views (sugar)
-- ============================================================================

-- Unsigned
abbrev Register.u8x16  (v : Register 8  16#usize) := v.lane (UScalar.mk (ty := .U8))
abbrev Register.u16x8  (v : Register 16 8#usize)  := v.lane (UScalar.mk (ty := .U16))
abbrev Register.u32x4  (v : Register 32 4#usize)  := v.lane (UScalar.mk (ty := .U32))
abbrev Register.u64x2  (v : Register 64 2#usize)  := v.lane (UScalar.mk (ty := .U64))
abbrev Register.u8x32  (v : Register 8  32#usize) := v.lane (UScalar.mk (ty := .U8))
abbrev Register.u16x16 (v : Register 16 16#usize) := v.lane (UScalar.mk (ty := .U16))
abbrev Register.u32x8  (v : Register 32 8#usize)  := v.lane (UScalar.mk (ty := .U32))
abbrev Register.u64x4  (v : Register 64 4#usize)  := v.lane (UScalar.mk (ty := .U64))
abbrev Register.u16x32 (v : Register 16 32#usize) := v.lane (UScalar.mk (ty := .U16))
abbrev Register.u32x16 (v : Register 32 16#usize) := v.lane (UScalar.mk (ty := .U32))
abbrev Register.u64x8  (v : Register 64 8#usize)  := v.lane (UScalar.mk (ty := .U64))

-- Signed
abbrev Register.i16x8  (v : Register 16 8#usize)  := v.lane (IScalar.mk (ty := .I16))
abbrev Register.i32x4  (v : Register 32 4#usize)  := v.lane (IScalar.mk (ty := .I32))
abbrev Register.i16x16 (v : Register 16 16#usize) := v.lane (IScalar.mk (ty := .I16))
abbrev Register.i32x8  (v : Register 32 8#usize)  := v.lane (IScalar.mk (ty := .I32))

-- ============================================================================
-- Bitwise distributivity (typed lanes — derived from Layer 1)
-- ============================================================================

theorem Register.lane_xor {k : Nat} {n : Usize} (a b : Register k n) (i : Fin n.val) :
    ((a ^^^ b).lane id)[i] = (a.lane id)[i] ^^^ (b.lane id)[i] := by
  grind [Register.lane_getElem, BitVec.extractLsb'_xor]

theorem Register.lane_and {k : Nat} {n : Usize} (a b : Register k n) (i : Fin n.val) :
    ((a &&& b).lane id)[i] = (a.lane id)[i] &&& (b.lane id)[i] := by
  grind [Register.lane_getElem, BitVec.extractLsb'_and]

theorem Register.lane_or {k : Nat} {n : Usize} (a b : Register k n) (i : Fin n.val) :
    ((a ||| b).lane id)[i] = (a.lane id)[i] ||| (b.lane id)[i] := by
  grind [Register.lane_getElem, BitVec.extractLsb'_and]

-- ╔══════════════════════════════════════════════════════════════════════════╗
-- ║  LAYER 2 — Multilane nesting                                            ║
-- ╚══════════════════════════════════════════════════════════════════════════╝

/-- Slice characterization of the packing brick: lane `i` of `a.bv toBits`
    is `toBits a[i]`. (The `Std.Array.bv` companion to `Register.toBV_slice`.) -/
theorem Aeneas.Std.Array.bv_slice {t : Type} {k : Nat} {n : Usize}
    (a : Array t n) (toBits : t → BitVec k) (i : Nat) (hi : i < n.val) :
    (a.bv toBits).extractLsb' (k * i) k = toBits a[i] := by
  show (Register.ofFn (fun i => toBits a[i])).slice i = toBits a[i]
  rw [Register.ofFn_slice _ i hi]; rfl

/-- **Lane congruence.** Two equal-length arrays pack to the same register when
    their lanes agree pointwise (after the respective `toBits`). The standard
    way to relate a typed-lane array to its byte-group view. -/
theorem Aeneas.Std.Array.bv_congr {t s : Type} {k : Nat} {n : Usize}
    (a : Array t n) (b : Array s n) (f : t → BitVec k) (g : s → BitVec k)
    (h : ∀ i : Fin n.val, f a[i.val] = g b[i.val]) :
    a.bv f = b.bv g := by
  show Register.ofFn (fun i => f a[i.val]) = Register.ofFn (fun i => g b[i.val])
  congr 1; funext i; exact h i

/-- **Nesting law.** Packing an array-of-arrays = packing the flattened array.
    `U16x16` viewed as `Array (Array U8 2) 16` packs to the same register as
    the flat `Array U8 32`; multilane = the single-layer brick applied twice.
    The flat array `b` is supplied explicitly with its length equation `hP`
    and the element correspondence `hflat` (so no overflow side-condition on
    `m * N`). The trailing `.cast` is the associativity regroup
    `(k*m)*N = k*(m*N)`, which reduces away at concrete numerals. -/
theorem Aeneas.Std.Array.bv_nest {S : Type} {k : Nat} {m N P : Usize}
    (aa : Array (Array S m) N) (b : Array S P) (toBits : S → BitVec k)
    (hk : 0 < k) (hm : 0 < m.val) (hP : P.val = m.val * N.val)
    (hflat : ∀ K r (hK : K < N.val) (hr : r < m.val), (aa[K])[r] = b[m.val * K + r]'(by
      have h3 : m.val * K + r < m.val * (K + 1) := by rw [Nat.mul_succ]; omega
      have h2 : m.val * (K + 1) ≤ m.val * N.val := Nat.mul_le_mul_left _ (by omega)
      simp only [Std.Array.length_eq, hP]; omega)) :
    aa.bv (fun g => g.bv toBits) = (b.bv toBits).cast (by rw [hP]; ring) := by
  apply BitVec.ext_chunks (tot := (k * m.val) * N.val) (W := k) (Ntot := m.val * N.val) (by ring) hk
  intro idx hidx
  have hK : idx / m.val < N.val := Nat.div_lt_of_lt_mul hidx
  have hr : idx % m.val < m.val := Nat.mod_lt _ hm
  rw [BitVec.extractLsb'_cast, Std.Array.bv_slice b toBits idx (by simp only [hP]; exact hidx)]
  have e : m.val * (idx / m.val) + idx % m.val = idx := Nat.div_add_mod idx m.val
  have hmul : k * idx = (k * m.val) * (idx / m.val) + k * (idx % m.val) := by
    calc k * idx = k * (m.val * (idx / m.val) + idx % m.val) := by rw [e]
      _ = (k * m.val) * (idx / m.val) + k * (idx % m.val) := by ring
  have hle : k * (idx % m.val) + k ≤ k * m.val := by
    calc k * (idx % m.val) + k = k * (idx % m.val + 1) := by ring
      _ ≤ k * m.val := Nat.mul_le_mul_left _ (by omega)
  rw [hmul, ← BitVec.extractLsb'_extractLsb' _ ((k * m.val) * (idx / m.val)) (k * (idx % m.val))
        (k * m.val) k hle,
      Std.Array.bv_slice aa (fun g => g.bv toBits) (idx / m.val) hK,
      Std.Array.bv_slice (aa[idx / m.val]) toBits (idx % m.val) hr,
      hflat (idx / m.val) (idx % m.val) hK hr]
  exact congrArg toBits (getElem_congr_idx e)

/-- Constant-chunk flatten indexing: if every inner list has length `m`, then
    element `idx` of the flattening is element `idx % m` of chunk `idx / m`.
    The keystone for normalizing nested arrays to a flat `List` (no library
    equivalent; reuses Lean's `List.flatten`). -/
theorem List.getElem?_flatten_const {S : Type} (m : Nat) (hm0 : 0 < m) :
    ∀ (ll : List (List S)), (∀ l ∈ ll, l.length = m) → ∀ idx,
      ll.flatten[idx]? = (ll[idx / m]?).bind (fun l => l[idx % m]?)
  | [], _, idx => by simp
  | l :: ls, hlen, idx => by
    have hl : l.length = m := hlen l (by simp)
    have ih := List.getElem?_flatten_const m hm0 ls (fun l hl => hlen l (by simp [hl])) (idx - m)
    rw [List.flatten_cons, List.getElem?_append, hl]
    by_cases h : idx < m
    · simp [h, Nat.div_eq_of_lt h, Nat.mod_eq_of_lt h]
    · rw [if_neg h, Nat.div_eq_sub_div hm0 (by omega), List.getElem?_cons_succ,
          Nat.mod_eq_sub_mod (by omega), ih]

/-- A `List.flatten` hypothesis fixes the flat length: `P = m * N`. -/
theorem Aeneas.Std.Array.flatten_imp_length {S : Type} {m N P : Usize}
    (aa : Array (Array S m) N) (b : Array S P)
    (hflat : b.val = (aa.val.map (·.val)).flatten) : P.val = m.val * N.val := by
  have h := congrArg List.length hflat
  rw [Std.Array.length_eq, List.length_flatten, List.map_map] at h
  have hconst : aa.val.map (List.length ∘ (·.val)) = List.replicate aa.val.length m.val := by
    apply List.ext_getElem (by simp) ?_
    intro i h1 h2; simp only [List.getElem_map, Function.comp, List.getElem_replicate]
    exact (aa.val[i]).property
  rw [hconst, List.sum_replicate, Std.Array.length_eq, smul_eq_mul] at h
  exact h.trans (Nat.mul_comm N.val m.val)

/-- A `List.flatten` hypothesis gives the per-element correspondence
    `aa[K][r] = b[m*K+r]` (the form `bv_nest` consumes). -/
theorem Aeneas.Std.Array.flatten_imp_elem {S : Type} {m N P : Usize}
    (aa : Array (Array S m) N) (b : Array S P) (hm : 0 < m.val)
    (hflat : b.val = (aa.val.map (·.val)).flatten)
    (K r : Nat) (hK : K < N.val) (hr : r < m.val) (hidx : m.val * K + r < P.val) :
    (aa[K])[r] = b[m.val * K + r] := by
  have hll : ∀ l ∈ aa.val.map (·.val), l.length = m.val := by
    intro l hl; rw [List.mem_map] at hl; obtain ⟨g, _, rfl⟩ := hl; exact g.property
  have hbr := List.getElem?_flatten_const m.val hm (aa.val.map (·.val)) hll (m.val * K + r)
  rw [Nat.mul_add_div hm, Nat.div_eq_of_lt hr, Nat.add_zero, Nat.mul_add_mod, Nat.mod_eq_of_lt hr,
      ← hflat, List.getElem?_map,
      List.getElem?_eq_getElem (show K < aa.val.length by simpa [Std.Array.length_eq] using hK),
      List.getElem?_eq_getElem (show m.val*K+r < b.val.length by simpa [Std.Array.length_eq] using hidx)] at hbr
  simp only [Option.map_some] at hbr
  rw [show ∀ (X : List S), (some X).bind (fun l => l[r]?) = X[r]? from fun _ => rfl,
      List.getElem?_eq_getElem (show r < (aa.val[K]).val.length by simpa [Std.Array.length_eq] using hr)] at hbr
  injection hbr with hbr; exact hbr.symm

/-- **Nesting law (byte-normal-form).** Packing an array-of-arrays equals
    packing its flattening, with the flat array given as a `List.flatten`. -/
theorem Aeneas.Std.Array.bv_nest_flatten {S : Type} {k : Nat} {m N P : Usize}
    (aa : Array (Array S m) N) (b : Array S P) (toBits : S → BitVec k)
    (hk : 0 < k) (hm : 0 < m.val) (hflat : b.val = (aa.val.map (·.val)).flatten) :
    aa.bv (fun g => g.bv toBits)
      = (b.bv toBits).cast (by rw [Std.Array.flatten_imp_length aa b hflat]; ring) := by
  have hP := Std.Array.flatten_imp_length aa b hflat
  exact Std.Array.bv_nest aa b toBits hk hm hP
    (fun K r hK hr => Std.Array.flatten_imp_elem aa b hm hflat K r hK hr (by
      have h3 : m.val * K + r < m.val * (K + 1) := by rw [Nat.mul_succ]; omega
      have h2 : m.val * (K + 1) ≤ m.val * N.val := Nat.mul_le_mul_left _ (by omega)
      rw [hP]; omega))

/-- **Transmute / injectivity.** Two nested arrays with the *same flat byte list*
    pack to the same register — the register's bits are determined by the flat
    `[U8; N]`. This is what licenses reinterpreting between lane views. -/
theorem Aeneas.Std.Array.bv_transmute {S : Type} {k : Nat} {m1 N1 m2 N2 P : Usize}
    (aa1 : Array (Array S m1) N1) (aa2 : Array (Array S m2) N2)
    (b : Array S P) (toBits : S → BitVec k) (hk : 0 < k) (hm1 : 0 < m1.val) (hm2 : 0 < m2.val)
    (h1 : b.val = (aa1.val.map (·.val)).flatten) (h2 : b.val = (aa2.val.map (·.val)).flatten) :
    aa1.bv (fun g => g.bv toBits)
      = (aa2.bv (fun g => g.bv toBits)).cast (by
          have e : m1.val * N1.val = m2.val * N2.val :=
            (Std.Array.flatten_imp_length aa1 b h1).symm.trans
              (Std.Array.flatten_imp_length aa2 b h2)
          rw [Nat.mul_assoc, Nat.mul_assoc, e]) := by
  rw [Std.Array.bv_nest_flatten aa1 b toBits hk hm1 h1,
      Std.Array.bv_nest_flatten aa2 b toBits hk hm2 h2, BitVec.cast_cast]

-- ╔══════════════════════════════════════════════════════════════════════════╗
-- ║  Byte serialization — Simd `.bv` ↔ Aeneas to_le_bytes / from_le_bytes     ║
-- ╚══════════════════════════════════════════════════════════════════════════╝

/-- The one bit-level bridge: Simd's little-endian `listToBV` *is*
    `BitVec.fromLEBytes`. Every byte-serialization fact below is built on it
    abstractly, so downstream proofs stay at the byte / `.bv` API level. -/
theorem listToBV_eq_fromLEBytes (l : List (BitVec 8)) :
    listToBV l = (BitVec.fromLEBytes l).cast (by simp) := by
  induction l with
  | nil => apply BitVec.eq_of_getLsbD_eq; intro i hi; simp at hi
  | cons b bs ih =>
    apply BitVec.eq_of_getLsbD_eq; intro j hj
    simp only [listToBV, BitVec.getLsbD_cast, BitVec.fromLEBytes, BitVec.getLsbD_append,
      BitVec.getLsbD_or, BitVec.getLsbD_setWidth, BitVec.getLsbD_shiftLeft]
    rw [ih]; grind

/-- `BitVec.fromLEBytes` congruence under list equality (motive-safe via `subst`). -/
theorem fromLEBytes_congr {l₁ l₂ : List (BitVec 8)} (h : l₁ = l₂) :
    BitVec.fromLEBytes l₁ = (BitVec.fromLEBytes l₂).cast (by rw [h]) := by subst h; simp

/-- A bit-disjoint `|||` is an `+`: when the low byte `c < 2^8` does not overlap
    the byte-shifted high part `a * 2^8`, the two combine additively. -/
theorem BitVec.disjoint_or_add (a c : Nat) (hc : c < 2 ^ 8) :
    a * 2 ^ 8 ||| c = a * 2 ^ 8 + c := by
  have hsl : a * 2 ^ 8 = a <<< 8 := by rw [Nat.shiftLeft_eq]
  have hmod : (a * 2 ^ 8 ||| c) % 2 ^ 8 = c := by
    apply Nat.eq_of_testBit_eq
    intro i
    rw [Nat.testBit_mod_two_pow]
    by_cases hi : i < 8
    · simp only [hi, decide_true, Bool.true_and, Nat.testBit_or, hsl, Nat.testBit_shiftLeft]
      simp [hi]
    · simp only [hi, decide_false, Bool.false_and]
      symm
      exact Nat.testBit_lt_two_pow
        (Nat.lt_of_lt_of_le hc (Nat.pow_le_pow_right (by norm_num) (by omega)))
  have hdiv : (a * 2 ^ 8 ||| c) / 2 ^ 8 = a := by
    apply Nat.eq_of_testBit_eq
    intro i
    rw [Nat.testBit_div_two_pow, Nat.testBit_or, hsl, Nat.testBit_shiftLeft]
    have : c.testBit (i + 8) = false :=
      Nat.testBit_lt_two_pow
        (Nat.lt_of_lt_of_le hc (Nat.pow_le_pow_right (by norm_num) (by omega)))
    simp [this]
  omega

set_option linter.unusedSimpArgs false in
/-- `BitVec.fromLEBytes (b :: l)` is the high part `fromLEBytes l` concatenated
    above the low byte `b` (up to a width cast). -/
theorem BitVec.fromLEBytes_cons_eq_append (b : BitVec 8) (l : List (BitVec 8)) :
    BitVec.fromLEBytes (b :: l)
      = (BitVec.fromLEBytes l ++ b).cast (by simp [List.length_cons]; ring) := by
  apply BitVec.eq_of_getLsbD_eq
  intro j
  simp only [_root_.BitVec.fromLEBytes, BitVec.getLsbD_cast, BitVec.getLsbD_append,
    BitVec.getLsbD_or, BitVec.getLsbD_setWidth, BitVec.getLsbD_shiftLeft, List.length_cons]
  by_cases hj : (j : Nat) < 8 <;> grind

/-- `.toNat` of `BitVec.fromLEBytes` peels one little-endian byte at a time:
    the head byte contributes its value, the tail is shifted up by 256. -/
theorem BitVec.fromLEBytes_cons_toNat (b : BitVec 8) (l : List (BitVec 8)) :
    (BitVec.fromLEBytes (b :: l)).toNat
      = b.toNat + 256 * (BitVec.fromLEBytes l).toNat := by
  rw [BitVec.fromLEBytes_cons_eq_append, BitVec.toNat_cast, BitVec.toNat_append,
    Nat.shiftLeft_eq]
  rw [BitVec.disjoint_or_add _ _ b.isLt]
  ring

/-- `.toNat` of the `k`-th little-endian byte of a width-multiple-of-8 bit-vector
    is the byte-aligned slice `(b.toNat >>> (8 * k)) % 256`. -/
theorem BitVec.toLEBytes_getElem_toNat {w : Nat} (_hw : w % 8 = 0)
    (b : _root_.BitVec w) (k : Nat) (hk : k < b.toLEBytes.length) :
    b.toLEBytes[k].toNat = (b.toNat >>> (8 * k)) % 256 := by
  apply Nat.eq_of_testBit_eq
  intro j
  by_cases hj : j < 8
  · have hL : (b.toLEBytes[k]).toNat.testBit j = b.toNat.testBit (8 * k + j) := by
      change Byte.testBit (b.toLEBytes[k]) j = _
      rw [_root_.BitVec.toLEBytes_getElem_testBit _ _ _ (by grind)]
      rw [_root_.BitVec.getElem_eq_testBit_toNat]
      grind
    rw [hL]
    rw [show (256 : Nat) = 2 ^ 8 from rfl, Nat.testBit_mod_two_pow, Nat.testBit_shiftRight]
    simp [hj, Nat.add_comm]
  · have hj' : 8 ≤ j := by scalar_tac
    have hpow : (2 : Nat) ^ 8 ≤ 2 ^ j := Nat.pow_le_pow_right (by decide) hj'
    have h1 : b.toLEBytes[k].toNat < 2 ^ j := by
      have := b.toLEBytes[k].isLt
      scalar_tac
    have h2 : (b.toNat >>> (8 * k)) % 256 < 2 ^ j := by
      have : (b.toNat >>> (8 * k)) % 256 < 256 := Nat.mod_lt _ (by decide)
      have h256 : (256 : Nat) = 2 ^ 8 := by decide
      scalar_tac
    rw [Nat.testBit_lt_two_pow h1, Nat.testBit_lt_two_pow h2]

/-- Packing a byte array (`Array.bv`) equals `BitVec.fromLEBytes` of its bytes. -/
theorem Array_bv_eq_fromLEBytes {n : Usize} (b : Array U8 n) :
    b.bv (·.bv) = (BitVec.fromLEBytes (b.val.map U8.bv)).cast (by simp) := by
  have h : (List.ofFn (fun i : Fin n.val => b[i].bv)) = b.val.map U8.bv := by
    apply List.ext_getElem (by simp) ?_; intro i h1 h2; grind
  unfold Std.Array.bv Register.ofFn
  rw [listToBV_eq_fromLEBytes, fromLEBytes_congr h]; simp

/-- **Lane bridge.** `u32::from_le_bytes a` has, as its bit-vector, exactly the
    register-packing of the four input bytes. -/
theorem U32_from_le_bytes_bv (a : Array U8 4#usize) :
    (core.num.U32.from_le_bytes a).bv = (a.bv (·.bv)).cast (by simp) := by
  rw [Array_bv_eq_fromLEBytes a]
  simp only [core.num.U32.from_le_bytes, UScalar.bv_mk, BitVec.cast_cast]

/-- **u32 → [u8; 4] preserves the bits**: packing `to_le_bytes x` recovers `x.bv`.
    (Bits confined to `Array_bv_eq_fromLEBytes` + library `fromLEBytes_toLEBytes`.) -/
theorem U32_to_le_bytes_bv (x : U32) : (core.num.U32.to_le_bytes x).bv (·.bv) = x.bv := by
  have key : List.map U8.bv (List.map UScalar.mk x.bv.toLEBytes) = x.bv.toLEBytes := by
    simp [List.map_map]
  rw [Array_bv_eq_fromLEBytes]
  apply BitVec.eq_of_getLsbD_eq; intro j hj
  simp only [BitVec.getLsbD_cast, core.num.U32.to_le_bytes]
  rw [fromLEBytes_congr key]
  simp only [BitVec.getLsbD_cast]
  rw [BitVec.fromLEBytes_toLEBytes (by decide)]
  exact BitVec.getLsbD_cast ..

/-- **Lane bridge (u16).** `u16::from_le_bytes a` = register-packing of 2 bytes. -/
theorem U16_from_le_bytes_bv (a : Array U8 2#usize) :
    (core.num.U16.from_le_bytes a).bv = (a.bv (·.bv)).cast (by simp) := by
  rw [Array_bv_eq_fromLEBytes a]
  simp only [core.num.U16.from_le_bytes, UScalar.bv_mk, BitVec.cast_cast]

/-- **Lane bridge (u64).** `u64::from_le_bytes a` = register-packing of 8 bytes. -/
theorem U64_from_le_bytes_bv (a : Array U8 8#usize) :
    (core.num.U64.from_le_bytes a).bv = (a.bv (·.bv)).cast (by simp) := by
  rw [Array_bv_eq_fromLEBytes a]
  simp only [core.num.U64.from_le_bytes, UScalar.bv_mk, BitVec.cast_cast]

/-- **u16 → [u8; 2] preserves the bits.** -/
theorem U16_to_le_bytes_bv (x : U16) : (core.num.U16.to_le_bytes x).bv (·.bv) = x.bv := by
  have key : List.map U8.bv (List.map UScalar.mk x.bv.toLEBytes) = x.bv.toLEBytes := by
    simp [List.map_map]
  rw [Array_bv_eq_fromLEBytes]
  apply BitVec.eq_of_getLsbD_eq; intro j hj
  simp only [BitVec.getLsbD_cast, core.num.U16.to_le_bytes]
  rw [fromLEBytes_congr key]
  simp only [BitVec.getLsbD_cast]
  rw [BitVec.fromLEBytes_toLEBytes (by decide)]
  exact BitVec.getLsbD_cast ..

/-- **u64 → [u8; 8] preserves the bits.** -/
theorem U64_to_le_bytes_bv (x : U64) : (core.num.U64.to_le_bytes x).bv (·.bv) = x.bv := by
  have key : List.map U8.bv (List.map UScalar.mk x.bv.toLEBytes) = x.bv.toLEBytes := by
    simp [List.map_map]
  rw [Array_bv_eq_fromLEBytes]
  apply BitVec.eq_of_getLsbD_eq; intro j hj
  simp only [BitVec.getLsbD_cast, core.num.U64.to_le_bytes]
  rw [fromLEBytes_congr key]
  simp only [BitVec.getLsbD_cast]
  rw [BitVec.fromLEBytes_toLEBytes (by decide)]
  exact BitVec.getLsbD_cast ..

/-- **u32 ↔ [u8; 4]** (register form). A 32-bit register, split into four `u8`
    lanes and repacked, is the identity — pure round-trip, no `extractLsb'`/`cast`. -/
example (x : Register 8 4#usize) :
    (x.lane (UScalar.mk (ty := .U8))).bv (·.bv) = x :=
  Register.bv_lane _ _ (fun _ => rfl) x

/-- **u32 → [u8; 4] preserves the bits**: `(to_le_bytes x).bv = x.bv`. -/
example (x : U32) : (core.num.U32.to_le_bytes x).bv (·.bv) = x.bv := U32_to_le_bytes_bv x

-- ╔══════════════════════════════════════════════════════════════════════════╗
-- ║  Wider windows of a packed byte register (16- and 64-bit lanes)            ║
-- ║                                                                            ║
-- ║  `Array.bv_slice` characterises a single 8-bit window of `a.bv (·.bv)`.    ║
-- ║  These two lemmas characterise the 16-bit and 64-bit windows as the        ║
-- ║  little-endian concatenation of the underlying bytes — the building        ║
-- ║  blocks for the wide-lane carriers below (and any arch's `uNxM` views).    ║
-- ╚══════════════════════════════════════════════════════════════════════════╝

local macro_rules | `(tactic| get_elem_tactic) => `(tactic| first | assumption | grind | scalar_tac)

/-- A 16-bit window of a packed byte register is the little-endian pair
    `b[2k+1] ++ b[2k]`. -/
theorem Aeneas.Std.Array.bv_extractLsb'_pair {n : Usize} (b : Array Std.U8 n)
    (k : ℕ) (h2 : 2 * k + 1 < n.val) :
    (b.bv (·.bv)).extractLsb' (16 * k) 16 = b[2*k+1].bv ++ b[2*k].bv := by
  have hsplit : (b.bv (·.bv)).extractLsb' (16 * k) 16
      = ((b.bv (·.bv)).extractLsb' (16*k+8) 8) ++ ((b.bv (·.bv)).extractLsb' (16*k) 8) := by
    apply BitVec.eq_of_getLsbD_eq; intro j
    simp only [BitVec.getLsbD_extractLsb', BitVec.getLsbD_append]
    by_cases hj : (j:Nat) < 8 <;> grind
  have e0 : (b.bv (·.bv)).extractLsb' (16*k) 8 = b[2*k].bv := by
    have := Array.bv_slice b (·.bv) (2*k) (by omega)
    rw [show 8*(2*k) = 16*k by ring] at this; exact this
  have e1 : (b.bv (·.bv)).extractLsb' (16*k+8) 8 = b[2*k+1].bv := by
    have := Array.bv_slice b (·.bv) (2*k+1) (by omega)
    rw [show 8*(2*k+1) = 16*k+8 by ring] at this; exact this
  rw [hsplit, e0, e1]

/-- A 64-bit window of a packed byte register is the little-endian octet
    `b[8k+7] ++ … ++ b[8k]` (byte `8k` lowest). -/
theorem Aeneas.Std.Array.bv_extractLsb'_oct {n : Usize} (b : Array Std.U8 n)
    (k : ℕ) (h8 : 8 * k + 7 < n.val) :
    (b.bv (·.bv)).extractLsb' (64 * k) 64 =
      b[8*k+7].bv ++ b[8*k+6].bv ++ b[8*k+5].bv ++ b[8*k+4].bv ++
      b[8*k+3].bv ++ b[8*k+2].bv ++ b[8*k+1].bv ++ b[8*k].bv := by
  have hsplit : (b.bv (·.bv)).extractLsb' (64 * k) 64 =
      ((b.bv (·.bv)).extractLsb' (64*k+56) 8) ++ ((b.bv (·.bv)).extractLsb' (64*k+48) 8) ++
      ((b.bv (·.bv)).extractLsb' (64*k+40) 8) ++ ((b.bv (·.bv)).extractLsb' (64*k+32) 8) ++
      ((b.bv (·.bv)).extractLsb' (64*k+24) 8) ++ ((b.bv (·.bv)).extractLsb' (64*k+16) 8) ++
      ((b.bv (·.bv)).extractLsb' (64*k+8) 8) ++ ((b.bv (·.bv)).extractLsb' (64*k) 8) := by
    apply BitVec.eq_of_getLsbD_eq; intro j
    simp only [BitVec.getLsbD_extractLsb', BitVec.getLsbD_append]
    by_cases h0 : (j:Nat) < 8 <;> by_cases h1 : (j:Nat) < 16 <;> by_cases h2 : (j:Nat) < 24
      <;> by_cases h3 : (j:Nat) < 32 <;> by_cases h4 : (j:Nat) < 40
      <;> by_cases h5 : (j:Nat) < 48 <;> by_cases h6 : (j:Nat) < 56 <;> grind
  rw [hsplit]
  have e : ∀ j, (hj : j < 8) → (b.bv (·.bv)).extractLsb' (64*k+8*j) 8 = b[8*k+j].bv := by
    intro j hj
    have := Array.bv_slice b (·.bv) (8*k+j) (by omega)
    rw [show 8*(8*k+j) = 64*k+8*j by ring] at this; exact this
  rw [show (64*k+56) = 64*k+8*7 by ring, show (64*k+48) = 64*k+8*6 by ring,
      show (64*k+40) = 64*k+8*5 by ring, show (64*k+32) = 64*k+8*4 by ring,
      show (64*k+24) = 64*k+8*3 by ring, show (64*k+16) = 64*k+8*2 by ring,
      show (64*k+8) = 64*k+8*1 by ring]
  rw [e 7 (by omega), e 6 (by omega), e 5 (by omega), e 4 (by omega),
      e 3 (by omega), e 2 (by omega), e 1 (by omega)]
  rw [show (64*k) = 64*k+8*0 by ring, e 0 (by omega)]
  simp

/-- A 32-bit window of a packed byte register is the little-endian quadruple
    `b[4k+3] ++ b[4k+2] ++ b[4k+1] ++ b[4k]` (byte `4k` lowest). -/
theorem Aeneas.Std.Array.bv_extractLsb'_quad {n : Usize} (b : Array Std.U8 n)
    (k : ℕ) (h4 : 4 * k + 3 < n.val) :
    (b.bv (·.bv)).extractLsb' (32 * k) 32 =
      b[4*k+3].bv ++ b[4*k+2].bv ++ b[4*k+1].bv ++ b[4*k].bv := by
  have hsplit : (b.bv (·.bv)).extractLsb' (32 * k) 32 =
      ((b.bv (·.bv)).extractLsb' (32*k+24) 8) ++ ((b.bv (·.bv)).extractLsb' (32*k+16) 8) ++
      ((b.bv (·.bv)).extractLsb' (32*k+8) 8) ++ ((b.bv (·.bv)).extractLsb' (32*k) 8) := by
    apply BitVec.eq_of_getLsbD_eq; intro j
    simp only [BitVec.getLsbD_extractLsb', BitVec.getLsbD_append]
    by_cases h0 : (j:Nat) < 8 <;> by_cases h1 : (j:Nat) < 16 <;> by_cases h2 : (j:Nat) < 24 <;> grind
  rw [hsplit]
  have e : ∀ j, (hj : j < 4) → (b.bv (·.bv)).extractLsb' (32*k+8*j) 8 = b[4*k+j].bv := by
    intro j hj
    have := Array.bv_slice b (·.bv) (4*k+j) (by omega)
    rw [show 8*(4*k+j) = 32*k+8*j by ring] at this; exact this
  rw [show (32*k+24) = 32*k+8*3 by ring, show (32*k+16) = 32*k+8*2 by ring,
      show (32*k+8) = 32*k+8*1 by ring]
  rw [e 3 (by omega), e 2 (by omega), e 1 (by omega)]
  rw [show (32*k) = 32*k+8*0 by ring, e 0 (by omega)]
  simp

-- ╔══════════════════════════════════════════════════════════════════════════╗
-- ║  128-bit byte-lane carriers (M128)                                        ║
-- ║                                                                            ║
-- ║  Byte ↔ wide-lane reinterpretations of a 128-bit byte register            ║
-- ║  `M128 = [u8; 16]` (XMM / NEON Q-register).  Each carrier is the           ║
-- ║  `Register.uNxM` lane-view of the packed 128-bit `b.bv (·.bv)`, using the   ║
-- ║  defeq `Register 8 16 = Register 16 8 = Register 32 4 = Register 64 2`       ║
-- ║  (all `BitVec 128`).  Structural mirror of the M256 carriers below.         ║
-- ╚══════════════════════════════════════════════════════════════════════════╝

namespace Intrinsics

local macro_rules | `(tactic| get_elem_tactic) => `(tactic| first | (simp only [Aeneas.Std.Array.length_eq]; first | assumption | scalar_tac) | assumption | scalar_tac | grind)

/-- 16 bytes → 8 little-endian `U16` lanes: the `Register.u16x8` lane-view of
    the packed register `b.bv (·.bv)` (reinterpreted from `Register 8 16`). -/
def M128.u16x8 (b : M128) : U16x8 := Register.u16x8 (b.bv (·.bv))

/-- Lane `k` of `M128.u16x8 b` is `b[2k+1] ++ b[2k]` (little-endian). -/
@[simp] theorem M128.u16x8_getElem (b : M128) (k : ℕ) (hk : k < 8) :
    (M128.u16x8 b)[k] = (⟨b[2 * k + 1].bv ++ b[2 * k].bv⟩ : Std.U16) := by
  have h : (M128.u16x8 b)[k].bv = (b.bv (·.bv)).extractLsb' (16 * k) 16 := by
    unfold M128.u16x8 Register.u16x8 Register.lane; grind [Std.Array.getElem_ofFn]
  exact U16.bv_eq_imp_eq _ _ (h.trans (Aeneas.Std.Array.bv_extractLsb'_pair b k (by scalar_tac)))

/-- `.val` of lane `k` of `M128.u16x8 b` is the little-endian byte polynomial
    `b[2k] + 256·b[2k+1]`. -/
@[simp] theorem M128.u16x8_val_getElem (b : M128) (k : ℕ) (hk : k < 8) :
    (M128.u16x8 b)[k].val = b[2*k].val + 256 * b[2*k + 1].val := by
  simp only [M128.u16x8_getElem b k hk, UScalar.val, UScalar.bv_mk_apply,
             BitVec.toNat_append, Nat.shiftLeft_eq]
  rw [BitVec.disjoint_or_add _ _ b[2*k].bv.isLt]
  ring

/-- 16 bytes → 4 little-endian `U32` lanes: the `Register.u32x4` lane-view of
    the packed register `b.bv (·.bv)` (reinterpreted from `Register 8 16`). -/
def M128.u32x4 (b : M128) : U32x4 := Register.u32x4 (b.bv (·.bv))

/-- `.bv` of lane `k` of `M128.u32x4 b` is the little-endian quadruple
    `b[4k+3] ++ b[4k+2] ++ b[4k+1] ++ b[4k]`. -/
@[simp] theorem M128.u32x4_bv_getElem (b : M128) (k : ℕ) (hk : k < 4) :
    (M128.u32x4 b)[k].bv =
      b[4*k+3].bv ++ b[4*k+2].bv ++ b[4*k+1].bv ++ b[4*k].bv := by
  have h : (M128.u32x4 b)[k].bv = (b.bv (·.bv)).extractLsb' (32 * k) 32 := by
    unfold M128.u32x4 Register.u32x4 Register.lane; grind [Std.Array.getElem_ofFn]
  exact h.trans (Aeneas.Std.Array.bv_extractLsb'_quad b k (by scalar_tac))

/-- `.val` of lane `k` of `M128.u32x4 b` is the little-endian byte polynomial
    `b[4k] + 256·(b[4k+1] + 256·(b[4k+2] + 256·b[4k+3]))`. -/
@[simp] theorem M128.u32x4_val_getElem (b : M128) (k : ℕ) (hk : k < 4) :
    (M128.u32x4 b)[k].val =
      b[4*k].val + 256 * (b[4*k+1].val + 256 * (b[4*k+2].val + 256 * b[4*k+3].val)) := by
  have hb : ∀ x : Std.U8, x.bv.toNat = x.val ∧ x.val < 2^8 := by
    intro x; exact ⟨rfl, by have := x.hBounds; scalar_tac⟩
  refine (congrArg BitVec.toNat (M128.u32x4_bv_getElem b k hk)).trans ?_
  simp only [BitVec.toNat_append, Nat.shiftLeft_eq, (hb _).1]
  rw [BitVec.disjoint_or_add _ _ (hb _).2, BitVec.disjoint_or_add _ _ (hb _).2,
      BitVec.disjoint_or_add _ _ (hb _).2]
  ring

/-- 16 bytes → 2 little-endian `U64` lanes: the `Register.u64x2` lane-view of
    the packed register `b.bv (·.bv)` (reinterpreted from `Register 8 16`). -/
def M128.u64x2 (b : M128) : U64x2 := Register.u64x2 (b.bv (·.bv))

/-- `.bv` of lane `k` of `M128.u64x2 b` is the little-endian octet
    `b[8k+7] ++ … ++ b[8k]`. -/
@[simp] theorem M128.u64x2_bv_getElem (b : M128) (k : ℕ) (hk : k < 2) :
    (M128.u64x2 b)[k].bv =
      b[8*k+7].bv ++ b[8*k+6].bv ++ b[8*k+5].bv ++ b[8*k+4].bv ++
      b[8*k+3].bv ++ b[8*k+2].bv ++ b[8*k+1].bv ++ b[8*k].bv := by
  have h : (M128.u64x2 b)[k].bv = (b.bv (·.bv)).extractLsb' (64 * k) 64 := by
    unfold M128.u64x2 Register.u64x2 Register.lane; grind [Std.Array.getElem_ofFn]
  exact h.trans (Aeneas.Std.Array.bv_extractLsb'_oct b k (by scalar_tac))

/-- `.val` of lane `k` of `M128.u64x2 b` is the little-endian byte polynomial
    `b[8k] + 256·(b[8k+1] + 256·(… + 256·b[8k+7]))`. -/
@[simp] theorem M128.u64x2_val_getElem (b : M128) (k : ℕ) (hk : k < 2) :
    (M128.u64x2 b)[k].val =
      b[8*k].val + 256 * (b[8*k+1].val + 256 * (b[8*k+2].val + 256 * (b[8*k+3].val
      + 256 * (b[8*k+4].val + 256 * (b[8*k+5].val + 256 * (b[8*k+6].val
      + 256 * b[8*k+7].val)))))) := by
  have hb : ∀ x : Std.U8, x.bv.toNat = x.val ∧ x.val < 2^8 := by
    intro x; exact ⟨rfl, by have := x.hBounds; scalar_tac⟩
  refine (congrArg BitVec.toNat (M128.u64x2_bv_getElem b k hk)).trans ?_
  simp only [BitVec.toNat_append, Nat.shiftLeft_eq, (hb _).1]
  rw [BitVec.disjoint_or_add _ _ (hb _).2, BitVec.disjoint_or_add _ _ (hb _).2,
      BitVec.disjoint_or_add _ _ (hb _).2, BitVec.disjoint_or_add _ _ (hb _).2,
      BitVec.disjoint_or_add _ _ (hb _).2, BitVec.disjoint_or_add _ _ (hb _).2,
      BitVec.disjoint_or_add _ _ (hb _).2]
  ring

/-- Lane counts (cheap, via the `Std.Array` length invariant — no def unfolding). -/
@[simp] theorem M128.u16x8_length (b : M128) : (M128.u16x8 b).val.length = 8 :=
  (M128.u16x8 b).property
@[simp] theorem M128.u32x4_length (b : M128) : (M128.u32x4 b).val.length = 4 :=
  (M128.u32x4 b).property
@[simp] theorem M128.u64x2_length (b : M128) : (M128.u64x2 b).val.length = 2 :=
  (M128.u64x2 b).property

/-- **Round-trip bridge.** If a byte carrier `r` packs to the same register as a
    `U16x8` lane array `w` (`r.bv (·.bv) = w.bv (·.bv)`), then the `u16x8` lane
    view of `r` *is* `w`.  This is the companion to the lane-view defs that lets
    a `bytes_to_X → op → X_to_bytes` carrier-sandwich proof transport the inner
    lane-op post (stated on `w`) onto `M128.u16x8 r`. -/
theorem M128.u16x8_of_bv {r : M128} {w : U16x8}
    (h : r.bv (·.bv) = w.bv (·.bv)) : M128.u16x8 r = w := by
  unfold M128.u16x8
  rw [show (r.bv (·.bv) : Register 16 8#usize) = w.bv (·.bv) from h]
  exact Register.lane_bv _ _ (fun x => UScalar.mk_bv x) w

/-- Round-trip bridge for the `u32x4` lane view (see `M128.u16x8_of_bv`). -/
theorem M128.u32x4_of_bv {r : M128} {w : U32x4}
    (h : r.bv (·.bv) = w.bv (·.bv)) : M128.u32x4 r = w := by
  unfold M128.u32x4
  rw [show (r.bv (·.bv) : Register 32 4#usize) = w.bv (·.bv) from h]
  exact Register.lane_bv _ _ (fun x => UScalar.mk_bv x) w

/-- Round-trip bridge for the `u64x2` lane view (see `M128.u16x8_of_bv`). -/
theorem M128.u64x2_of_bv {r : M128} {w : U64x2}
    (h : r.bv (·.bv) = w.bv (·.bv)) : M128.u64x2 r = w := by
  unfold M128.u64x2
  rw [show (r.bv (·.bv) : Register 64 2#usize) = w.bv (·.bv) from h]
  exact Register.lane_bv _ _ (fun x => UScalar.mk_bv x) w

/-- Bit `k` of the packed register `b.bv (·.bv)` is bit `k % 8` of byte `k / 8`. -/
theorem reg_bv_getLsbD_byte {n : Std.Usize} (b : Std.Array Std.U8 n) (k : Nat)
    (hk : k / 8 < n.val) :
    (b.bv (·.bv)).getLsbD k
      = (b[k/8]'(by simp only [Aeneas.Std.Array.length_eq]; exact hk)).bv.getLsbD (k % 8) := by
  rw [← Aeneas.Std.Array.bv_slice b (·.bv) (k/8) hk, BitVec.getLsbD_extractLsb']
  simp only [Nat.mod_lt _ (show 0 < 8 by omega), decide_true, Bool.true_and,
             show 8 * (k/8) + k%8 = k from by omega]

/-- Lane `i` of the `u64x2` view is the 64-bit window `extractLsb' (64·i) 64`
    of the packed register. -/
theorem M128.u64x2_bv_extract (r : M128) (i : ℕ) (hi : i < 2) :
    (r.u64x2[i]'(by simp [M128.u64x2]; omega)).bv = (r.bv (·.bv)).extractLsb' (64 * i) 64 := by
  rw [M128.u64x2_bv_getElem r i hi, ← Aeneas.Std.Array.bv_extractLsb'_oct r i (by scalar_tac)]

/-- Bit `k` of `u64x2` lane 0 is bit `k % 8` of byte `k / 8`. -/
theorem M128.u64x2_lane0_getLsbD (b : U8x16) (k : Nat) (hk : k < 64) :
    ((M128.u64x2 b)[0]'(by simp [M128.u64x2])).bv.getLsbD k
      = (b[k / 8]'(by have := b.property; scalar_tac)).bv.getLsbD (k % 8) := by
  rw [M128.u64x2_bv_extract b 0 (by omega), BitVec.getLsbD_extractLsb']
  simp only [hk, decide_true, Bool.true_and, Nat.zero_add, Nat.mul_zero]
  exact reg_bv_getLsbD_byte b k (by have := b.property; scalar_tac)

/-- Bit `k` of `u64x2` lane 1 is bit `k % 8` of byte `8 + k / 8`. -/
theorem M128.u64x2_lane1_getLsbD (b : U8x16) (k : Nat) (hk : k < 64) :
    ((M128.u64x2 b)[1]'(by simp [M128.u64x2])).bv.getLsbD k
      = (b[8 + k / 8]'(by have := b.property; scalar_tac)).bv.getLsbD (k % 8) := by
  rw [M128.u64x2_bv_extract b 1 (by omega), BitVec.getLsbD_extractLsb']
  simp only [hk, decide_true, Bool.true_and]
  rw [reg_bv_getLsbD_byte b (64 + k) (by have := b.property; scalar_tac)]
  simp only [show (64 + k) / 8 = 8 + k / 8 from by omega, show (64 + k) % 8 = k % 8 from by omega]

attribute [irreducible] M128.u16x8 M128.u32x4 M128.u64x2

end Intrinsics

-- ╔══════════════════════════════════════════════════════════════════════════╗
-- ║  256-bit byte-lane carriers (M256)                                        ║
-- ║                                                                            ║
-- ║  Arch-agnostic byte ↔ wide-lane reinterpretations of a 256-bit byte       ║
-- ║  register `M256 = [u8; 32]` (used by AVX2, but nothing here is x86-        ║
-- ║  specific — 256-bit registers also exist on ARM SVE etc.).  Each carrier   ║
-- ║  is the `Register.uNxM` lane-view of the packed 256-bit `b.bv (·.bv)`,      ║
-- ║  using the defeq `Register 8 32 = Register 16 16 = Register 64 4` (all       ║
-- ║  `BitVec 256`) — the same direct idiom the silicon layer uses at            ║
-- ║  128-bit (`Register.u16x8 (x.u8x16.bv (·.bv))`).  ZMM (512-bit) extends      ║
-- ║  this trivially: `M512 := U8x64` with `Register.{u32x16,u64x8}` views.      ║
-- ╚══════════════════════════════════════════════════════════════════════════╝

namespace Intrinsics

local macro_rules | `(tactic| get_elem_tactic) => `(tactic| first | (simp only [Aeneas.Std.Array.length_eq]; first | assumption | scalar_tac) | assumption | scalar_tac | grind)

/-- 32 bytes → 16 little-endian `U16` lanes: the `Register.u16x16` lane-view of
    the packed register `b.bv (·.bv)` (reinterpreted from `Register 8 32`). -/
def M256.u16x16 (b : M256) : U16x16 := Register.u16x16 (b.bv (·.bv))

/-- Lane `k` of `M256.u16x16 b` is `b[2k+1] ++ b[2k]` (little-endian). -/
@[simp] theorem M256.u16x16_getElem (b : M256) (k : ℕ) (hk : k < 16) :
    (M256.u16x16 b)[k] = (⟨b[2 * k + 1].bv ++ b[2 * k].bv⟩ : Std.U16) := by
  have h : (M256.u16x16 b)[k].bv = (b.bv (·.bv)).extractLsb' (16 * k) 16 := by
    unfold M256.u16x16 Register.u16x16 Register.lane; grind [Std.Array.getElem_ofFn]
  exact U16.bv_eq_imp_eq _ _ (h.trans (Aeneas.Std.Array.bv_extractLsb'_pair b k (by scalar_tac)))

/-- `.val` of lane `k` of `M256.u16x16 b` is the little-endian byte polynomial
    `b[2k] + 256·b[2k+1]`. -/
@[simp] theorem M256.u16x16_val_getElem (b : M256) (k : ℕ) (hk : k < 16) :
    (M256.u16x16 b)[k].val = b[2*k].val + 256 * b[2*k + 1].val := by
  simp only [M256.u16x16_getElem b k hk, UScalar.val, UScalar.bv_mk_apply,
             BitVec.toNat_append, Nat.shiftLeft_eq]
  rw [BitVec.disjoint_or_add _ _ b[2*k].bv.isLt]
  ring

/-- 32 bytes → 4 little-endian `U64` lanes: the `Register.u64x4` lane-view of
    the packed register `b.bv (·.bv)` (reinterpreted from `Register 8 32`). -/
def M256.u64x4 (b : M256) : U64x4 := Register.u64x4 (b.bv (·.bv))

/-- `.bv` of lane `k` of `M256.u64x4 b` is the little-endian octet
    `b[8k+7] ++ … ++ b[8k]`. -/
@[simp] theorem M256.u64x4_bv_getElem (b : M256) (k : ℕ) (hk : k < 4) :
    (M256.u64x4 b)[k].bv =
      b[8*k+7].bv ++ b[8*k+6].bv ++ b[8*k+5].bv ++ b[8*k+4].bv ++
      b[8*k+3].bv ++ b[8*k+2].bv ++ b[8*k+1].bv ++ b[8*k].bv := by
  have h : (M256.u64x4 b)[k].bv = (b.bv (·.bv)).extractLsb' (64 * k) 64 := by
    unfold M256.u64x4 Register.u64x4 Register.lane; grind [Std.Array.getElem_ofFn]
  exact h.trans (Aeneas.Std.Array.bv_extractLsb'_oct b k (by scalar_tac))

/-- `.val` of lane `k` of `M256.u64x4 b` is the little-endian byte polynomial
    `b[8k] + 256·(b[8k+1] + 256·(… + 256·b[8k+7]))`. -/
@[simp] theorem M256.u64x4_val_getElem (b : M256) (k : ℕ) (hk : k < 4) :
    (M256.u64x4 b)[k].val =
      b[8*k].val + 256 * (b[8*k+1].val + 256 * (b[8*k+2].val + 256 * (b[8*k+3].val
      + 256 * (b[8*k+4].val + 256 * (b[8*k+5].val + 256 * (b[8*k+6].val
      + 256 * b[8*k+7].val)))))) := by
  have hb : ∀ x : Std.U8, x.bv.toNat = x.val ∧ x.val < 2^8 := by
    intro x; exact ⟨rfl, by have := x.hBounds; scalar_tac⟩
  refine (congrArg BitVec.toNat (M256.u64x4_bv_getElem b k hk)).trans ?_
  simp only [BitVec.toNat_append, Nat.shiftLeft_eq, (hb _).1]
  rw [BitVec.disjoint_or_add _ _ (hb _).2, BitVec.disjoint_or_add _ _ (hb _).2,
      BitVec.disjoint_or_add _ _ (hb _).2, BitVec.disjoint_or_add _ _ (hb _).2,
      BitVec.disjoint_or_add _ _ (hb _).2, BitVec.disjoint_or_add _ _ (hb _).2,
      BitVec.disjoint_or_add _ _ (hb _).2]
  ring

/-- Lane counts (cheap, via the `Std.Array` length invariant — no def unfolding). -/
@[simp] theorem M256.u16x16_length (b : M256) : (M256.u16x16 b).val.length = 16 :=
  (M256.u16x16 b).property
@[simp] theorem M256.u64x4_length (b : M256) : (M256.u64x4 b).val.length = 4 :=
  (M256.u64x4 b).property

/-- **Round-trip bridge** (see `M128.u16x8_of_bv`): if `r`'s bytes pack to the
    same register as the `U16x16` lane array `w`, the `u16x16` lane view of `r`
    *is* `w`.  Transports a `bytes→op→bytes` carrier-sandwich's inner lane-op
    post (stated on `w`) onto `M256.u16x16 r`. -/
theorem M256.u16x16_of_bv {r : M256} {w : U16x16}
    (h : r.bv (·.bv) = w.bv (·.bv)) : M256.u16x16 r = w := by
  unfold M256.u16x16
  rw [show (r.bv (·.bv) : Register 16 16#usize) = w.bv (·.bv) from h]
  exact Register.lane_bv _ _ (fun x => UScalar.mk_bv x) w

/-- Round-trip bridge for the `u64x4` lane view (see `M256.u16x16_of_bv`). -/
theorem M256.u64x4_of_bv {r : M256} {w : U64x4}
    (h : r.bv (·.bv) = w.bv (·.bv)) : M256.u64x4 r = w := by
  unfold M256.u64x4
  rw [show (r.bv (·.bv) : Register 64 4#usize) = w.bv (·.bv) from h]
  exact Register.lane_bv _ _ (fun x => UScalar.mk_bv x) w

-- The lane-views pack `Register.lane` over the expensive `b.bv (·.bv)` fold;
-- make them irreducible so downstream `[k]` access never whnf-unfolds them.
-- All reasoning goes through the `_getElem` / `_length` lemmas above.
attribute [irreducible] M256.u16x16 M256.u64x4

end Intrinsics
