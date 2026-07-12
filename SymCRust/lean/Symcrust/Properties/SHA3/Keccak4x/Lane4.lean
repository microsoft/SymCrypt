/-
# Properties/SHA3/Keccak4x/Lane4 — `@[step]` specs for `sha3.keccak4x.Lane4.*`
                                 and `sha3.keccak4x_hybrid.Lane4.*`.

All `@[step]` theorems below have real, vacuity-checked
postconditions; all proofs are closed.

Conventions and design:

  * `Lane4 := Array U64 4` in both `sha3.keccak4x` and
    `sha3.keccak4x_hybrid` (see `Symcrust/Code/Types.lean:743-757`).  The
    safe and hybrid variants share the same algebraic shape (4 parallel
    u64 lanes); the hybrid variant differs only by open-coding `rol` via
    AVX2 intrinsics (see `Hybrid.lean`).  Lane4-level specs are therefore
    identical between the two variants and we instantiate both here.

  * Postconditions are **per-lane equations** on the underlying `Array
    U64 4`, ruling out the trivial `True` postcondition.  Index access
    uses `arr.val[k]'(by ...)` with `k < 4` preconditions (no `[]!` —
    User preference).

  * `rol` requires `0 < n < 64` (matches the `massert`s in the Rust
    body); the postcondition is the standard u64 left-rotation lane-wise.

  * **Safe vs hybrid extracted shape.** Safe Lane4 ops (`xor`, `andnot`,
    `rol`, `xor_assign`) factor through `xor_loop`/`andnot_loop`/
    `rol_loop`/`xor_assign_loop` helpers (`Code/Funs.lean:22301-22425`).
    Hybrid Lane4 ops are **fully unrolled** in extraction
    (`Code/Funs.lean:23395-23459`) — no loops; `splat` is the only
    extracted definition that already returns the answer directly via
    `Array.repeat`.  Loop specs therefore cover the safe variant only.
-/
import Symcrust.Code
import Symcrust.Properties.SHA3.Basic
import Symcrust.Properties.Iterators

namespace symcrust

open Aeneas Aeneas.Std Result
open scoped Spec.Notations

set_option linter.unusedSectionVars false
set_option linter.unusedVariables false

local macro_rules | `(tactic| get_elem_tactic) => `(tactic| first | assumption | (simp only [Aeneas.Std.Array.length_eq, List.length_set]; first | assumption | decide) | scalar_tac | (simp only [Aeneas.Std.Array.length_eq, List.length_set]; scalar_tac))

/-! ## Pure pointwise algebra on `Lane4`

  A `Lane4` is a 4-lane `U64` vector.  We give it the *same* bitwise
  notations as the scalar `U64` lanes (`^^^`, `&&&`, `~~~`) plus a named
  left-rotation `rotl4`, all acting pointwise.  This lets every phase
  postcondition be stated as a whole-`Lane4` equality
  (`s50[j] = l_a ^^^ ((~~~ l_b) &&& l_c)`) instead of a pointwise
  `∀ k < 4, s50[j][k] = …` clause — ~4× smaller, no quantifier.
  `Keccak4x.projectLane_lane` (Base.lean) is a homomorphism for each, so
  the 4-way round reduces to 4 parallel scalar rounds. -/

namespace Keccak4x

instance : HXor sha3.keccak4x.Lane4 sha3.keccak4x.Lane4 sha3.keccak4x.Lane4 where
  hXor a b := ⟨List.zipWith (· ^^^ ·) a.val b.val, by
    have := a.property; have := b.property
    simp [List.length_zipWith]⟩

instance : HAnd sha3.keccak4x.Lane4 sha3.keccak4x.Lane4 sha3.keccak4x.Lane4 where
  hAnd a b := ⟨List.zipWith (· &&& ·) a.val b.val, by
    have := a.property; have := b.property
    simp [List.length_zipWith]⟩

instance : Complement sha3.keccak4x.Lane4 where
  complement a := ⟨a.val.map (~~~ ·), by have := a.property; simp⟩

/-- Pointwise left-rotation of a `Lane4` by `n` bits (no standard bitwise
    notation exists for rotation, so it is named). -/
def rotl4 (a : sha3.keccak4x.Lane4) (n : U32) : sha3.keccak4x.Lane4 :=
  ⟨a.val.map (fun x => UScalar.rotate_left x n), by have := a.property; simp⟩

@[simp] theorem val_xor (a b : sha3.keccak4x.Lane4) :
    (a ^^^ b).val = List.zipWith (· ^^^ ·) a.val b.val := rfl
@[simp] theorem val_and (a b : sha3.keccak4x.Lane4) :
    (a &&& b).val = List.zipWith (· &&& ·) a.val b.val := rfl
@[simp] theorem val_not (a : sha3.keccak4x.Lane4) :
    (~~~ a).val = a.val.map (~~~ ·) := rfl
@[simp] theorem val_rotl4 (a : sha3.keccak4x.Lane4) (n : U32) :
    (rotl4 a n).val = a.val.map (fun x => UScalar.rotate_left x n) := rfl

@[simp] theorem length_xor (a b : sha3.keccak4x.Lane4) : (a ^^^ b).val.length = 4 := by
  have := a.property; have := b.property; simp [List.length_zipWith]
@[simp] theorem length_and (a b : sha3.keccak4x.Lane4) : (a &&& b).val.length = 4 := by
  have := a.property; have := b.property; simp [List.length_zipWith]
@[simp] theorem length_not (a : sha3.keccak4x.Lane4) : (~~~ a).val.length = 4 := by
  have := a.property; simp
@[simp] theorem length_rotl4 (a : sha3.keccak4x.Lane4) (n : U32) : (rotl4 a n).val.length = 4 := by
  have := a.property; simp

theorem getElem_xor (a b : sha3.keccak4x.Lane4) (k : Nat) (hk : k < 4) :
    (a ^^^ b).val[k] = a.val[k] ^^^ b.val[k] := by
  simp [List.getElem_zipWith]
theorem getElem_and (a b : sha3.keccak4x.Lane4) (k : Nat) (hk : k < 4) :
    (a &&& b).val[k] = a.val[k] &&& b.val[k] := by
  simp [List.getElem_zipWith]
theorem getElem_not (a : sha3.keccak4x.Lane4) (k : Nat) (hk : k < 4) :
    (~~~ a).val[k] = ~~~ a.val[k] := by
  simp
theorem bv_getElem_rotl4 (a : sha3.keccak4x.Lane4) (n : U32) (k : Nat) (hk : k < 4) :
    ((rotl4 a n).val[k]).bv = (a.val[k]).bv.rotateLeft n.val := by
  simp only [val_rotl4, List.getElem_map]
  rfl

/-- Extensionality for `Lane4` by its four lanes. -/
theorem lane4_ext (a b : sha3.keccak4x.Lane4)
    (h : ∀ k, (hk : k < 4) → a.val[k] = b.val[k]) : a = b := by
  apply Subtype.ext
  apply List.ext_getElem
  · rw [a.property, b.property]
  · intro n h1 h2
    have hn : n < 4 := by rw [a.property] at h1; scalar_tac
    exact h n hn

end Keccak4x


/-! ## Pure pointwise algebra on the hybrid `Lane4` (parallel to the safe block) -/

namespace Keccak4xHybrid

instance : HXor sha3.keccak4x_hybrid.Lane4 sha3.keccak4x_hybrid.Lane4 sha3.keccak4x_hybrid.Lane4 where
  hXor a b := ⟨List.zipWith (· ^^^ ·) a.val b.val, by
    have := a.property; have := b.property
    simp [List.length_zipWith]⟩

instance : HAnd sha3.keccak4x_hybrid.Lane4 sha3.keccak4x_hybrid.Lane4 sha3.keccak4x_hybrid.Lane4 where
  hAnd a b := ⟨List.zipWith (· &&& ·) a.val b.val, by
    have := a.property; have := b.property
    simp [List.length_zipWith]⟩

instance : Complement sha3.keccak4x_hybrid.Lane4 where
  complement a := ⟨a.val.map (~~~ ·), by have := a.property; simp⟩

/-- Pointwise left-rotation of a `Lane4` by `n` bits (no standard bitwise
    notation exists for rotation, so it is named). -/
def rotl4 (a : sha3.keccak4x_hybrid.Lane4) (n : U32) : sha3.keccak4x_hybrid.Lane4 :=
  ⟨a.val.map (fun x => UScalar.rotate_left x n), by have := a.property; simp⟩

@[simp] theorem val_xor (a b : sha3.keccak4x_hybrid.Lane4) :
    (a ^^^ b).val = List.zipWith (· ^^^ ·) a.val b.val := rfl
@[simp] theorem val_and (a b : sha3.keccak4x_hybrid.Lane4) :
    (a &&& b).val = List.zipWith (· &&& ·) a.val b.val := rfl
@[simp] theorem val_not (a : sha3.keccak4x_hybrid.Lane4) :
    (~~~ a).val = a.val.map (~~~ ·) := rfl
@[simp] theorem val_rotl4 (a : sha3.keccak4x_hybrid.Lane4) (n : U32) :
    (rotl4 a n).val = a.val.map (fun x => UScalar.rotate_left x n) := rfl

@[simp] theorem length_xor (a b : sha3.keccak4x_hybrid.Lane4) : (a ^^^ b).val.length = 4 := by
  have := a.property; have := b.property; simp [List.length_zipWith]
@[simp] theorem length_and (a b : sha3.keccak4x_hybrid.Lane4) : (a &&& b).val.length = 4 := by
  have := a.property; have := b.property; simp [List.length_zipWith]
@[simp] theorem length_not (a : sha3.keccak4x_hybrid.Lane4) : (~~~ a).val.length = 4 := by
  have := a.property; simp
@[simp] theorem length_rotl4 (a : sha3.keccak4x_hybrid.Lane4) (n : U32) : (rotl4 a n).val.length = 4 := by
  have := a.property; simp

theorem getElem_xor (a b : sha3.keccak4x_hybrid.Lane4) (k : Nat) (hk : k < 4) :
    (a ^^^ b).val[k] = a.val[k] ^^^ b.val[k] := by
  simp [List.getElem_zipWith]
theorem getElem_and (a b : sha3.keccak4x_hybrid.Lane4) (k : Nat) (hk : k < 4) :
    (a &&& b).val[k] = a.val[k] &&& b.val[k] := by
  simp [List.getElem_zipWith]
theorem getElem_not (a : sha3.keccak4x_hybrid.Lane4) (k : Nat) (hk : k < 4) :
    (~~~ a).val[k] = ~~~ a.val[k] := by
  simp
theorem bv_getElem_rotl4 (a : sha3.keccak4x_hybrid.Lane4) (n : U32) (k : Nat) (hk : k < 4) :
    ((rotl4 a n).val[k]).bv = (a.val[k]).bv.rotateLeft n.val := by
  simp only [val_rotl4, List.getElem_map]
  rfl

/-- Extensionality for `Lane4` by its four lanes. -/
theorem lane4_ext (a b : sha3.keccak4x_hybrid.Lane4)
    (h : ∀ k, (hk : k < 4) → a.val[k] = b.val[k]) : a = b := by
  apply Subtype.ext
  apply List.ext_getElem
  · rw [a.property, b.property]
  · intro n h1 h2
    have hn : n < 4 := by rw [a.property] at h1; scalar_tac
    exact h n hn

end Keccak4xHybrid

/-! ## Safe variant — `sha3.keccak4x.Lane4` -/

namespace Keccak4x.Lane4


/-- **Informal proof.**
    Body: `let a := Array.repeat 4#usize v; ok a` (`Funs.lean:22294-22296`).
    No monadic call; the result is definitionally `Array.repeat 4 v`,
    whose `.val` is `List.replicate 4 v`.  Post follows from
    `List.length_replicate` and `List.getElem_replicate`.
    Proof: `unfold splat; simp [Array.repeat, List.replicate]; agrind`. -/
@[step]
theorem splat.spec (v : U64) :
    sha3.keccak4x.Lane4.splat v
    ⦃ (r : sha3.keccak4x.Lane4) =>
        r.val.length = 4 ∧
        ∀ k, (hk : k < 4) → r.val[k]'(by scalar_tac) = v ⦄ := by
  unfold sha3.keccak4x.Lane4.splat
  simp [Array.repeat]
  intro k hk
  match k, hk with
  | 0, _ => rfl
  | 1, _ => rfl
  | 2, _ => rfl
  | 3, _ => rfl

/-- **Informal proof** (loop spec — `Lane4.xor` body).
    Body (`Funs.lean:22301-22316`): tail-recursive Range loop.  Each
    iteration reads `self[i]`, `other[i]`, computes `i1 ^^^ i2`, and
    writes the result into the accumulator `r`.  Loop exits when
    `iter.start = iter.end`.

    **Canonical pattern**: Range loop with array accumulator, monotonically
    increasing cursor.  **Frame/mutation split** (per `aeneas-postconditions`
    §IterMut, S8 convention):

      * **below the cursor** (`k < iter.start.val`): the entry passed in
        as `r` is unchanged (frame).
      * **at and above the cursor** (`k ∈ [iter.start.val, 4)`): r is
        overwritten with `a.val[k] ^^^ b.val[k]` (mutation).

    Lemma chain in call order:
      1. `IteratorRange.next` — Aeneas-stdlib spec for Range iterator
         next; advances `iter.start` by 1, returns `some iter.start` if
         `iter.start < iter.end`, else `none`.
      2. `Array.index_usize.spec` ×2 — per-element reads.
      3. `Array.update.spec` — per-element write.
      4. Recursive IH on `xor_loop iter1 self other a`.

    Discharge tactic for residual arithmetic: `scalar_tac`. -/
@[step]
theorem xor_loop.spec
    (iter : core.ops.range.Range Std.Usize)
    (self other : sha3.keccak4x.Lane4) (r : Array Std.U64 4#usize)
    (hLs : self.val.length = 4) (hLo : other.val.length = 4)
    (hLr : r.val.length = 4)
    (hStart : iter.start.val ≤ iter.«end».val)
    (hEnd : iter.«end».val = 4) :
    sha3.keccak4x.Lane4.xor_loop iter self other r
    ⦃ (r' : Array Std.U64 4#usize) =>
        r'.val.length = 4 ∧
        ∀ k, (hk : k < 4) →
          r'.val[k]'(by scalar_tac)
            = if k < iter.start.val then r.val[k]'(by scalar_tac)
              else self.val[k]'(by scalar_tac) ^^^ other.val[k]'(by scalar_tac) ⦄ := by
  unfold sha3.keccak4x.Lane4.xor_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← IteratorRange_next_some iter hlt
    rw [hsome]
    step*
    refine ⟨r'_post1, fun k hk => ?_⟩
    have hr := r'_post2 k hk
    simp only [hstart', a_post, Std.Array.set] at hr
    by_cases hk_lt : k < iter.start.val
    · have h1 : k < iter.start.val + 1 := by scalar_tac
      rw [if_pos h1] at hr
      simp_lists at hr
      simp [hk_lt, hr]
    · by_cases hk_eq : k = iter.start.val
      · subst hk_eq
        rw [if_pos (by scalar_tac)] at hr
        simp_lists at hr
        simp [hr]; agrind
      · have h1 : ¬ k < iter.start.val + 1 := by scalar_tac
        rw [if_neg h1] at hr
        simp [hk_lt, hr]
  · let* ⟨ o, iter1, hnone, _ ⟩ ← IteratorRange_next_none iter (by scalar_tac)
    rw [hnone]; simp only [WP.spec_ok]
    refine ⟨hLr, fun k hk => ?_⟩
    have : k < iter.start.val := by scalar_tac
    simp [this]
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- **Informal proof** (`Lane4.xor` wrapper).
    Body (`Funs.lean:22320-22328`): allocate `r := Array.repeat 4 0#u64`,
    then call `xor_loop {start := 0, end := 4} self other r`.
    Lemma chain: `xor_loop.spec` with `iter.start = 0`, `iter.end = 4`.
    The `if k < 0` branch is always false (k : Nat), so the post collapses
    to `r'[k] = self[k] ^^^ other[k]`, exactly the wrapper post.
    Proof: `unfold xor; step xor_loop.spec; simp`. -/
@[step]
theorem xor.spec (a b : sha3.keccak4x.Lane4)
    (hLa : a.val.length = 4) (hLb : b.val.length = 4) :
    sha3.keccak4x.Lane4.xor a b
    ⦃ (r : sha3.keccak4x.Lane4) => r = a ^^^ b ⦄ := by
  unfold sha3.keccak4x.Lane4.xor
  step*
  apply lane4_ext; intro k hk
  rw [getElem_xor a b k hk]
  simp_all

/-- **Informal proof** (loop spec — `Lane4.andnot` body).
    Body (`Funs.lean:22333-22349`): same Range-loop shape as `xor_loop`,
    inner op is `(~~~ self[i]) &&& other[i]`.  Frame/mutation split:
    identical to `xor_loop.spec`, with the inner op replaced.
    Lemma chain identical; mechanically: read self[i], `lift (~~~ ·)`,
    read other[i], `lift (· &&& ·)`, update r[i], recurse. -/
@[step]
theorem andnot_loop.spec
    (iter : core.ops.range.Range Std.Usize)
    (self other : sha3.keccak4x.Lane4) (r : Array Std.U64 4#usize)
    (hLs : self.val.length = 4) (hLo : other.val.length = 4)
    (hLr : r.val.length = 4)
    (hStart : iter.start.val ≤ iter.«end».val)
    (hEnd : iter.«end».val = 4) :
    sha3.keccak4x.Lane4.andnot_loop iter self other r
    ⦃ (r' : Array Std.U64 4#usize) =>
        r'.val.length = 4 ∧
        ∀ k, (hk : k < 4) →
          r'.val[k]'(by scalar_tac)
            = if k < iter.start.val then r.val[k]'(by scalar_tac)
              else (~~~ self.val[k]'(by scalar_tac)) &&& other.val[k]'(by scalar_tac) ⦄ := by
  unfold sha3.keccak4x.Lane4.andnot_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← IteratorRange_next_some iter hlt
    rw [hsome]
    step*
    refine ⟨r'_post1, fun k hk => ?_⟩
    have hr := r'_post2 k hk
    simp only [hstart', a_post, Std.Array.set] at hr
    by_cases hk_lt : k < iter.start.val
    · have h1 : k < iter.start.val + 1 := by scalar_tac
      rw [if_pos h1] at hr
      simp_lists at hr
      simp [hk_lt, hr]
    · by_cases hk_eq : k = iter.start.val
      · subst hk_eq
        rw [if_pos (by scalar_tac)] at hr
        simp_lists at hr
        simp [hr]; agrind
      · have h1 : ¬ k < iter.start.val + 1 := by scalar_tac
        rw [if_neg h1] at hr
        simp [hk_lt, hr]
  · let* ⟨ o, iter1, hnone, _ ⟩ ← IteratorRange_next_none iter (by scalar_tac)
    rw [hnone]; simp only [WP.spec_ok]
    refine ⟨hLr, fun k hk => ?_⟩
    have : k < iter.start.val := by scalar_tac
    simp [this]
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- **Informal proof** (`Lane4.andnot` wrapper).
    Same shape as `xor`: allocate zeros, call `andnot_loop` from 0 to 4,
    `if k < 0` collapses to false, post follows.
    Proof: `unfold andnot; step andnot_loop.spec; simp`. -/
@[step]
theorem andnot.spec (a b : sha3.keccak4x.Lane4)
    (hLa : a.val.length = 4) (hLb : b.val.length = 4) :
    sha3.keccak4x.Lane4.andnot a b
    ⦃ (r : sha3.keccak4x.Lane4) => r = (~~~ a) &&& b ⦄ := by
  unfold sha3.keccak4x.Lane4.andnot
  step*
  apply lane4_ext; intro k hk
  rw [getElem_and (~~~ a) b k hk, getElem_not a k hk]
  simp_all

/-- **Informal proof** (loop spec — `Lane4.rol` body).
    Body (`Funs.lean:22366-22383`): per-lane left-rotation by `n` bits
    via the standard `(x <<< n) ||| (x >>> (64 - n))` formula.
    Pre `0 < n < 64` ensures both `<<<` and `>>>` are valid U32 shifts;
    `64 - n` is exact since `n < 64`.

    Per-iteration computation at lane `i`:
      * `i1 := self[i]`
      * `i2 := i1 <<< n` (u64 wrapping shift; exact for n < 64)
      * `i3 := 64#u32 - n` (exact)
      * `i4 := i1 >>> i3`
      * `i5 := i2 ||| i4`
      * `r[i] := i5`

    Post equates `r'.bv[i] = self.bv[i].rotateLeft n.val` — the standard
    bitvector identity `(x <<< n) ||| (x >>> (w - n)) = x.rotateLeft n` for
    `0 < n < w`.  Discharge: `bv_decide` on the 64-bit identity, or
    `simp [BitVec.rotateLeft_def]`.

    Frame/mutation split: as for `xor_loop`. -/
@[step]
theorem rol_loop.spec
    (iter : core.ops.range.Range Std.Usize)
    (self : sha3.keccak4x.Lane4) (n : U32) (r : Array Std.U64 4#usize)
    (hLs : self.val.length = 4) (hLr : r.val.length = 4)
    (hStart : iter.start.val ≤ iter.«end».val)
    (hEnd : iter.«end».val = 4)
    (hPos : 0#u32 < n) (hLt : n < 64#u32) :
    sha3.keccak4x.Lane4.rol_loop iter self n r
    ⦃ (r' : Array Std.U64 4#usize) =>
        r'.val.length = 4 ∧
        ∀ k, (hk : k < 4) →
          (r'.val[k]'(by scalar_tac)).bv
            = if k < iter.start.val then (r.val[k]'(by scalar_tac)).bv
              else (self.val[k]'(by scalar_tac)).bv.rotateLeft n.val ⦄ := by
  unfold sha3.keccak4x.Lane4.rol_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← IteratorRange_next_some iter hlt
    rw [hsome]
    step*
    refine ⟨r'_post1, fun k hk => ?_⟩
    have hr := r'_post2 k hk
    simp only [hstart', a_post, Std.Array.set] at hr
    by_cases hk_lt : k < iter.start.val
    · have h1 : k < iter.start.val + 1 := by scalar_tac
      rw [if_pos h1] at hr
      simp_lists at hr
      simp [hk_lt, hr]
    · by_cases hk_eq : k = iter.start.val
      · subst hk_eq
        rw [if_pos (by scalar_tac)] at hr
        simp_lists at hr
        rw [hr]
        simp
        -- Goal: i5.bv = (self.val[iter.start.val]).bv.rotateLeft n.val
        -- We have: i1_post : i1 = self[iter.start.val]
        --         i2 := i1 <<< n
        --         i3 := 64 - n  (U32)
        --         i4 := i1 >>> i3
        --         i5 := i2 ||| i4
        have hn_lt_64 : n.val < 64 := by scalar_tac
        have hn_pos : 0 < n.val := by scalar_tac
        simp [i5_post2, i4_post2, i2_post2, i3_post1, i1_post,
              BitVec.rotateLeft_def, Nat.mod_eq_of_lt hn_lt_64]
      · have h1 : ¬ k < iter.start.val + 1 := by scalar_tac
        rw [if_neg h1] at hr
        simp [hk_lt, hr]
  · let* ⟨ o, iter1, hnone, _ ⟩ ← IteratorRange_next_none iter (by scalar_tac)
    rw [hnone]; simp only [WP.spec_ok]
    refine ⟨hLr, fun k hk => ?_⟩
    have : k < iter.start.val := by scalar_tac
    simp [this]
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- **Informal proof** (`Lane4.rol` wrapper).
    Body (`Funs.lean:22387-22395`): `massert (n > 0)`, `massert (n < 64)`,
    allocate zeros, call `rol_loop`.  The masserts directly correspond to
    `hPos` and `hLt`.
    Proof: `unfold rol; step rol_loop.spec; simp`. -/
@[step]
theorem rol.spec (a : sha3.keccak4x.Lane4) (n : U32)
    (hLa : a.val.length = 4) (hPos : 0#u32 < n) (hLt : n < 64#u32) :
    sha3.keccak4x.Lane4.rol a n
    ⦃ (r : sha3.keccak4x.Lane4) => r = Keccak4x.rotl4 a n ⦄ := by
  unfold sha3.keccak4x.Lane4.rol
  step*
  apply lane4_ext; intro k hk
  have hr := r1_post2 k hk
  simp only [Nat.not_lt_zero, reduceIte] at hr
  apply U64.bv_eq_imp_eq
  simp only [Keccak4x.val_rotl4, List.getElem_map, UScalar.rotate_left]
  exact hr

/-- **Informal proof** (loop spec — `Lane4.xor_assign` body).
    Body (`Funs.lean:22400-22415`): in-place XOR variant — the accumulator
    IS `self`; each iteration updates `self[i] := self[i] ^^^ other[i]`
    and recurses with `a` as the new `self`.

    Subtle vs `xor_loop`: the entry `self` IS what gets mutated.  The
    post pins `r'[k] = if k < iter.start then self[k] (frame)
                         else self[k] ^^^ other[k] (mutation)`.

    Lemma chain: `IteratorRange.next`, `Array.index_usize.spec` ×2,
    `Array.update.spec`, recursive IH. -/
@[step]
theorem xor_assign_loop.spec
    (iter : core.ops.range.Range Std.Usize)
    (self other : sha3.keccak4x.Lane4)
    (hLs : self.val.length = 4) (hLo : other.val.length = 4)
    (hStart : iter.start.val ≤ iter.«end».val)
    (hEnd : iter.«end».val = 4) :
    sha3.keccak4x.Lane4.xor_assign_loop iter self other
    ⦃ (r' : sha3.keccak4x.Lane4) =>
        r'.val.length = 4 ∧
        ∀ k, (hk : k < 4) →
          r'.val[k]'(by scalar_tac)
            = if k < iter.start.val then self.val[k]'(by scalar_tac)
              else self.val[k]'(by scalar_tac) ^^^ other.val[k]'(by scalar_tac) ⦄ := by
  unfold sha3.keccak4x.Lane4.xor_assign_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← IteratorRange_next_some iter hlt
    rw [hsome]
    step*
    refine ⟨r'_post1, fun k hk => ?_⟩
    have hr := r'_post2 k hk
    simp only [hstart', a_post, Std.Array.set] at hr
    by_cases hk_lt : k < iter.start.val
    · have h1 : k < iter.start.val + 1 := by scalar_tac
      rw [if_pos h1] at hr
      simp_lists at hr
      simp [hk_lt, hr]
    · by_cases hk_eq : k = iter.start.val
      · subst hk_eq
        rw [if_pos (by scalar_tac)] at hr
        simp_lists at hr
        simp [hr]; agrind
      · have h1 : ¬ k < iter.start.val + 1 := by scalar_tac
        rw [if_neg h1] at hr
        simp_lists at hr
        simp [hk_lt, hr]
  · let* ⟨ o, iter1, hnone, _ ⟩ ← IteratorRange_next_none iter (by scalar_tac)
    rw [hnone]; simp only [WP.spec_ok]
    refine ⟨hLs, fun k hk => ?_⟩
    have : k < iter.start.val := by scalar_tac
    simp [this]
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- **Informal proof** (`Lane4.xor_assign` wrapper).
    Body (`Funs.lean:22420-22425`): single tail call to
    `xor_assign_loop {start := 0, end := 4} self other`.
    Post equals `xor_assign_loop.spec` at `iter.start = 0`.
    Proof: `unfold xor_assign; step xor_assign_loop.spec; simp`. -/
@[step]
theorem xor_assign.spec (a b : sha3.keccak4x.Lane4)
    (hLa : a.val.length = 4) (hLb : b.val.length = 4) :
    sha3.keccak4x.Lane4.xor_assign a b
    ⦃ (r : sha3.keccak4x.Lane4) => r = a ^^^ b ⦄ := by
  unfold sha3.keccak4x.Lane4.xor_assign
  step*
  apply lane4_ext; intro k hk
  rw [getElem_xor a b k hk]
  simp_all

end Keccak4x.Lane4

/-! ## Hybrid variant — `sha3.keccak4x_hybrid.Lane4`

  Same algebraic shape as the safe variant (4 parallel u64 lanes); the
  `rol` method is replaced by the `rol4!` macro at use sites (see
  `Hybrid.lean`).  Specs are otherwise identical.

  **No loop helpers**: hybrid Lane4 ops are fully unrolled (4 explicit
  index_usize + lift calls per op; `Code/Funs.lean:23395-23459`).  All
  wrapper proofs are straight tactic walks. -/

namespace Keccak4xHybrid.Lane4

/-- **Informal proof.**
    Same as safe `splat`: `Array.repeat 4 v`, post by definition. -/
@[step]
theorem splat.spec (v : U64) :
    sha3.keccak4x_hybrid.Lane4.splat v
    ⦃ (r : sha3.keccak4x_hybrid.Lane4) =>
        r.val.length = 4 ∧
        ∀ k, (hk : k < 4) → r.val[k]'(by scalar_tac) = v ⦄ := by
  unfold sha3.keccak4x_hybrid.Lane4.splat
  simp [Array.repeat]
  intro k hk
  match k, hk with
  | 0, _ => rfl
  | 1, _ => rfl
  | 2, _ => rfl
  | 3, _ => rfl

/-- **Informal proof** (hybrid `xor`, fully unrolled — `Funs.lean:23395-23411`).
    Four explicit reads `self[0..3]`, four explicit reads `other[0..3]`,
    four `lift (· ^^^ ·)`, then `ok (Array.make 4 [i2, i5, i8, i11])`.
    Lemma chain: 8 × `Array.index_usize.spec`.
    Post: enumerate `k ∈ {0, 1, 2, 3}` (case-split via `interval_cases k`
    or `fin_cases`), each case is a direct `[i2, i5, i8, i11]`-projection
    equal to the corresponding XOR.
    Discharge: `simp [Array.make]; agrind`. -/
@[step]
theorem xor.spec (a b : sha3.keccak4x_hybrid.Lane4)
    (hLa : a.val.length = 4) (hLb : b.val.length = 4) :
    sha3.keccak4x_hybrid.Lane4.xor a b
    ⦃ (r : sha3.keccak4x_hybrid.Lane4) => r = a ^^^ b ⦄ := by
  unfold sha3.keccak4x_hybrid.Lane4.xor
  step*
  apply Keccak4xHybrid.lane4_ext; intro k hk
  rw [Keccak4xHybrid.getElem_xor a b k hk]
  simp [Array.make]
  match k, hk with
  | 0, _ => simp only [List.getElem_cons_zero]; agrind
  | 1, _ => simp only [List.getElem_cons_succ, List.getElem_cons_zero]; agrind
  | 2, _ => simp only [List.getElem_cons_succ, List.getElem_cons_zero]; agrind
  | 3, _ => simp only [List.getElem_cons_succ, List.getElem_cons_zero]; agrind

/-- **Informal proof** (hybrid `andnot`, fully unrolled — `Funs.lean:23415-23435`).
    Same pattern as hybrid `xor` but with inner op `(~~~ self[i]) &&& other[i]`.
    Proof: `unfold andnot; step ×12 (4 self reads, 4 other reads, 4 NOT-AND
    lifts); simp [Array.make]; interval_cases k; rfl`. -/
@[step]
theorem andnot.spec (a b : sha3.keccak4x_hybrid.Lane4)
    (hLa : a.val.length = 4) (hLb : b.val.length = 4) :
    sha3.keccak4x_hybrid.Lane4.andnot a b
    ⦃ (r : sha3.keccak4x_hybrid.Lane4) => r = (~~~ a) &&& b ⦄ := by
  unfold sha3.keccak4x_hybrid.Lane4.andnot
  step*
  apply Keccak4xHybrid.lane4_ext; intro k hk
  rw [Keccak4xHybrid.getElem_and (~~~ a) b k hk, Keccak4xHybrid.getElem_not a k hk]
  simp [Array.make]
  match k, hk with
  | 0, _ => simp only [List.getElem_cons_zero]; agrind
  | 1, _ => simp only [List.getElem_cons_succ, List.getElem_cons_zero]; agrind
  | 2, _ => simp only [List.getElem_cons_succ, List.getElem_cons_zero]; agrind
  | 3, _ => simp only [List.getElem_cons_succ, List.getElem_cons_zero]; agrind

/-- **Informal proof** (hybrid `xor_assign`, fully unrolled — `Funs.lean:23439-23459`).
    Four read-XOR-update steps threaded through fresh array names
    `self → a → a1 → a2 → a3`.  Each `Array.update` preserves length-4
    and pins one lane.  Post by `interval_cases k` over the 4 cases;
    each is a chain of `Array.getElem_update_*` simp lemmas.
    Proof: `unfold xor_assign; step* ; simp [Array.update_*]; interval_cases k`. -/
@[step]
theorem xor_assign.spec (a b : sha3.keccak4x_hybrid.Lane4)
    (hLa : a.val.length = 4) (hLb : b.val.length = 4) :
    sha3.keccak4x_hybrid.Lane4.xor_assign a b
    ⦃ (r : sha3.keccak4x_hybrid.Lane4) => r = a ^^^ b ⦄ := by
  unfold sha3.keccak4x_hybrid.Lane4.xor_assign
  step*
  apply Keccak4xHybrid.lane4_ext; intro k hk
  simp only [Keccak4xHybrid.val_xor, List.getElem_zipWith]
  match k, hk with
  | 0, _ => simp_lists [a3_post, a2_post, a1_post, a_post] at *; agrind
  | 1, _ => simp_lists [a3_post, a2_post, a1_post, a_post] at *; agrind
  | 2, _ => simp_lists [a3_post, a2_post, a1_post, a_post] at *; agrind
  | 3, _ => simp_lists [a3_post, a2_post, a1_post, a_post] at *; agrind

end Keccak4xHybrid.Lane4

end symcrust
