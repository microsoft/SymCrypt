/-
# Properties/SHA3/Shake4x/Append — per-instance absorb spec.

All `@[step]` theorems below have real, vacuity-checked postconditions and
are FULLY proven (`Shake4x.append.spec` and the `append_loop{0..4}` helpers).
The proof is axiom-clean (no `sorryAx`).

## Surface

`Shake4x.append self inst data` appends `data` to the absorb buffer of
instance `inst : 0..4`.  Pre: `¬ finalized`, `inst < 4`, and the
combined `absorbed[inst] + data.length < rate` (strict; preserves the
strict `Shake4x.WF.3` invariant; the bound must be strict on
Shake4x.append).

The function dispatches over `(absorbed[inst] mod 8)`:
  * `byte_off = 0` — fast path, lane-aligned writes.
  * `byte_off ≠ 0`— slow path that first fills the partial lane, then
                    falls through to the lane-aligned loop.

We expose one `@[step]` spec per public method (`append`).  The five
`append_loop{0..4}` helpers have "internal" postconditions only consumed by
`append`'s proof; they are fully proven here.

The postcondition shape: `append` advances exactly one `GhostState` (the
`inst`-th) by appending `data` to its `absorbed` buffer.  All other
`gs i` (with `i ≠ inst`) are untouched.
-/
import Symcrust.Code
import Symcrust.Properties.SHA3.Basic
import Symcrust.Properties.SHA3.Shake4x.Basic
import Symcrust.Properties.SHA3.Sponge.BridgeComp
import Symcrust.Properties.Axioms.Stdlib

namespace symcrust

open Aeneas Aeneas.Std Result
open sha3.sha3_impl

set_option linter.unusedSectionVars false
set_option linter.unusedVariables false

/-! ## Loop helpers — internal to `append`.

The 5 extracted loop helpers fall into 2 algebraic categories:

  * **Byte-packing loops** (`append_loop{0, 2, 4}`): fold `n` bytes from
    `data` into a u64 accumulator by left-shifting and OR-ing.  They
    are pure (no Keccak state).

  * **Lane-XOR loops** (`append_loop{1, 3}`): main absorb loop —
    repeatedly read 8-byte chunks from `data` starting at `offset`,
    decode as u64, XOR into successive Keccak lanes starting at
    `lane_idx`.  Returns updated state, final offset, final lane_idx.

`append_loop{0, 1, 2}` serve the `byte_off ≠ 0` (unaligned start) path;
`append_loop{3, 4}` serve the `byte_off = 0` (aligned start) path.

These specs are deliberately stated in algebraic form (folded-OR /
folded-XOR over the absorbed byte range).  They are internal to
`append`'s proof; no external caller consumes them. -/

/-- Byte-packing fold: take `m` bytes from `data` starting at `offset` and
    pack them into a u64 at byte positions `byte_off .. byte_off + m`.

    The explicit precondition `offset + m ≤ data.length` keeps indexing
    in-bounds: we use `data[offset + i]'_` rather than `data[…]?.getD 0`
    so a caller cannot silently get a zero-padded reading when the index
    escapes the slice — every caller must prove the bound. -/
def Shake4x.packBytes (data : List U8) (offset byte_off m : Nat)
    (h : offset + m ≤ data.length) : U64 :=
  Id.run do
    let mut v : U64 := 0#u64
    for hi : i in [0:m] do
      let b := (data[offset + i]'(by have := hi.upper; scalar_tac)).bv.zeroExtend 64
      v := ⟨v.bv ||| (b <<< (8 * (byte_off + i)))⟩
    return v

/-- Inductive step for `packBytes`: appending one byte at the right corresponds
    to OR-ing the appropriate shifted byte into the lower-`m` accumulator. -/
theorem Shake4x.packBytes_succ (data : List U8) (offset byte_off m : Nat)
    (h : offset + (m + 1) ≤ data.length) :
    Shake4x.packBytes data offset byte_off (m + 1) h =
    ⟨(Shake4x.packBytes data offset byte_off m (by omega)).bv |||
     ((data[offset + m]'(by omega)).bv.zeroExtend 64) <<< (8 * (byte_off + m))⟩ := by
  unfold Shake4x.packBytes
  simp [List.range'_concat, List.foldl_append, List.foldl_map]

/-- All bits of `packBytes …` at or above position `8 * (byte_off + m)` are zero. -/
theorem Shake4x.packBytes_high_zero (data : List U8) (offset byte_off m : Nat)
    (h : offset + m ≤ data.length) :
    (Shake4x.packBytes data offset byte_off m h).bv >>> (8 * (byte_off + m)) = 0 := by
  induction m with
  | zero =>
    unfold Shake4x.packBytes
    simp
  | succ k ih =>
    rw [Shake4x.packBytes_succ]
    have ih' := ih (by omega)
    have hexpand : 8 * (byte_off + (k + 1)) = 8 * (byte_off + k) + 8 := by ring
    have step1 : (Shake4x.packBytes data offset byte_off k (by omega)).bv >>>
        (8 * (byte_off + (k + 1))) = 0 := by
      rw [hexpand, BitVec.shiftRight_add, ih']; simp
    have step2 : ((data[offset + k]'(by omega)).bv.setWidth 64 <<<
        (8 * (byte_off + k))) >>> (8 * (byte_off + (k + 1))) = 0 := by
      rw [hexpand]
      apply BitVec.eq_of_getLsbD_eq
      intro i _
      simp [BitVec.getLsbD_ushiftRight, BitVec.getLsbD_shiftLeft, BitVec.getLsbD_setWidth,
            show 8 * (byte_off + k) + 8 + i - 8 * (byte_off + k) = 8 + i from by omega]
    show (_ ||| _) >>> _ = 0
    rw [BitVec.ushiftRight_or_distrib, step1, step2]; simp

/-- Subset of partial packings: if `k ≤ m` then `pack k ⊆ pack m` (bitwise),
    expressed as `pack k ||| pack m = pack m`. -/
theorem Shake4x.packBytes_subset (data : List U8) (offset byte_off k m : Nat)
    (hkm : k ≤ m) (h : offset + m ≤ data.length) :
    (Shake4x.packBytes data offset byte_off k (by omega)).bv |||
    (Shake4x.packBytes data offset byte_off m h).bv =
    (Shake4x.packBytes data offset byte_off m h).bv := by
  induction m with
  | zero =>
    have : k = 0 := by omega
    subst this; simp
  | succ j ih =>
    by_cases hkj : k ≤ j
    · rw [Shake4x.packBytes_succ]
      have ih' := ih hkj (by omega)
      show _ ||| (_ ||| _) = _ ||| _
      generalize hPk : (Shake4x.packBytes data offset byte_off k (by omega)).bv = Pk at ih'
      generalize hPj : (Shake4x.packBytes data offset byte_off j (by omega)).bv = Pj at ih'
      generalize hB : ((data[offset + j]'(by omega)).bv.setWidth 64 <<<
        (8 * (byte_off + j))) = B
      rw [show Pk ||| (Pj ||| B) = (Pk ||| Pj) ||| B by bv_decide, ih']
    · have hk_eq : k = j + 1 := by omega
      subst hk_eq; simp

/-- Disjointness of the byte placed at position `k` from the partial packing
    of the first `k` bytes. -/
theorem Shake4x.packBytes_byte_disjoint (data : List U8) (offset byte_off k : Nat)
    (h : offset + (k + 1) ≤ data.length) :
    ((data[offset + k]'(by omega)).bv.setWidth 64 <<< (8 * (byte_off + k))) &&&
    (Shake4x.packBytes data offset byte_off k (by omega)).bv = 0 := by
  have hhi := Shake4x.packBytes_high_zero data offset byte_off k (by omega)
  apply BitVec.eq_of_getLsbD_eq
  intro i hi
  simp only [BitVec.getLsbD_and, BitVec.getLsbD_shiftLeft, BitVec.getLsbD_setWidth]
  by_cases hilo : i < 8 * (byte_off + k)
  · simp [show ¬(8 * (byte_off + k) ≤ i) by omega]
  · have h_pack_bit_zero :
        (Shake4x.packBytes data offset byte_off k (by omega)).bv.getLsbD i = false := by
      have hshift_bit :
          ((Shake4x.packBytes data offset byte_off k (by omega)).bv >>>
              (8 * (byte_off + k))).getLsbD (i - 8 * (byte_off + k)) = false := by
        rw [hhi]; simp
      simpa [BitVec.getLsbD_ushiftRight,
            show 8 * (byte_off + k) + (i - 8 * (byte_off + k)) = i by omega] using hshift_bit
    simp [h_pack_bit_zero]


/-- **Informal proof** (loop spec — `append_loop0`, `Funs.lean:24789-24806`).
    Body per iteration at cursor `i`: read `data[i]`, cast u8 → u64, shift
    left by `8 * (byte_off + i)`, OR into accumulator `v`.

    **Loop invariant** (per-iteration form at cursor `iter.start`):
    `v = v₀ ||| packBytes data 0 byte_off iter.start.val`
    where `v₀` is the value passed in at the wrapper call.

    Lemma chain: `IteratorRange.next.spec`, `Slice.index_usize.spec`,
    `UScalar.cast.spec` (u8 → u64; total since 8 < 64),
    `Usize.add.spec`, `Usize.mul.spec` (byte_off+i and 8*·, both bounded
    by `byte_off + iter.end ≤ 8`), `U64.shl.spec`, `U64.or.spec`,
    recursive IH. -/
@[step]
theorem Shake4x.append_loop0.spec
    (iter : core.ops.range.Range Std.Usize)
    (data : Slice U8) (byte_off : Std.Usize) (v : U64)
    (hStart : iter.start.val ≤ iter.«end».val)
    (hData : iter.«end».val ≤ data.length)
    (hShift : byte_off.val + iter.«end».val ≤ 8) :
    sha3.shake4x.Shake4x.append_loop0 iter data byte_off v
    ⦃ (r : U64) =>
        r.bv = v.bv ||| (Shake4x.packBytes data.val 0 byte_off.val iter.«end».val
                            (by scalar_tac)).bv
                          &&& (~~~ (Shake4x.packBytes data.val 0 byte_off.val iter.start.val
                            (by scalar_tac)).bv) ⦄ := by
  unfold sha3.shake4x.Shake4x.append_loop0
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← IteratorRange_next_some iter hlt
    rw [hsome]
    step*
    -- Make iter1's components explicit in r_post.
    have hi1_start : iter1.start.val = iter.start.val + 1 := hstart'
    have hi1_end : iter1.«end» = iter.«end» := hend'
    -- packBytes proof argument is irrelevant: rewrite via proof-irrelevant helper.
    have hp : ∀ a b ha hb, a = b →
        Shake4x.packBytes data.val 0 byte_off.val a ha =
        Shake4x.packBytes data.val 0 byte_off.val b hb := by
      intros; subst_eqs; rfl
    -- Replace pack at iter1.start with pack at iter.start+1.
    rw [hp iter1.start.val (iter.start.val + 1) (by scalar_tac) (by scalar_tac) hi1_start] at r_post
    rw [hp iter1.«end».val iter.«end».val (by scalar_tac) (by scalar_tac)
       (by rw [hi1_end])] at r_post
    -- Expand pack at iter.start+1 via packBytes_succ.
    rw [Shake4x.packBytes_succ data.val 0 byte_off.val iter.start.val (by scalar_tac)] at r_post
    -- Now r_post is in terms of pack(iter.start), pack(iter.end), and byte_at_iter.start.
    -- Substitute v1.bv, i5.bv, i4.val, i2.bv via simp only.
    have hcast : i2.bv = i1.bv.zeroExtend 64 := by rw [i2_post]; rfl
    have hi4 : i4.val = 8 * (byte_off.val + iter.start.val) := by rw [i4_post, i3_post]
    have hi1eq : i1.bv = (data.val[0 + iter.start.val]'(by scalar_tac)).bv := by
      rw [i1_post]; congr 1; scalar_tac
    simp only [v1_post2, i5_post2, hcast, hi4, hi1eq] at r_post
    -- Reduce the U64-anonymous-constructor in the negated argument.
    simp only [show ∀ x : BitVec 64, (⟨x⟩ : U64).bv = x from fun _ => rfl] at r_post
    -- Now r_post is in terms of pack(iter.start), pack(iter.end), and byte_at_iter.start.
    -- Derive subset and disjointness in concrete form.
    have hsub : (Shake4x.packBytes data.val 0 byte_off.val (iter.start.val + 1)
                    (by scalar_tac)).bv |||
                (Shake4x.packBytes data.val 0 byte_off.val iter.«end».val
                    (by scalar_tac)).bv =
                (Shake4x.packBytes data.val 0 byte_off.val iter.«end».val
                    (by scalar_tac)).bv :=
      Shake4x.packBytes_subset data.val 0 byte_off.val (iter.start.val + 1) iter.«end».val
        (by scalar_tac) (by scalar_tac)
    -- Rewrite subset goal to expand pack(iter.start+1) via packBytes_succ.
    rw [Shake4x.packBytes_succ data.val 0 byte_off.val iter.start.val (by scalar_tac)] at hsub
    have hdisj :
        ((data.val[0 + iter.start.val]'(by scalar_tac)).bv.setWidth 64 <<<
          (8 * (byte_off.val + iter.start.val))) &&&
        (Shake4x.packBytes data.val 0 byte_off.val iter.start.val (by scalar_tac)).bv = 0 :=
      Shake4x.packBytes_byte_disjoint data.val 0 byte_off.val iter.start.val (by scalar_tac)
    -- Now r_post is fully concrete. Substitute into goal, then close via bv_decide.
    rw [r_post]
    -- Generalize all opaque pieces in BOTH goal and hsub/hdisj.
    generalize hS : (Shake4x.packBytes data.val 0 byte_off.val iter.start.val
                       (by scalar_tac)).bv = S
    rw [hS] at hdisj hsub
    generalize hE : (Shake4x.packBytes data.val 0 byte_off.val iter.«end».val
                       (by scalar_tac)).bv = E
    rw [hE] at hsub
    generalize hB : ((data.val[0 + iter.start.val]'(by scalar_tac)).bv.zeroExtend 64) <<<
                       (8 * (byte_off.val + iter.start.val)) = B
    rw [hB] at hsub hdisj
    -- Clean the U64-wrapper in hsub: `U64.bv ⟨X⟩ = X`.
    simp only [show ∀ x : BitVec 64, (⟨x⟩ : U64).bv = x from fun _ => rfl] at hsub
    -- Clean the same wrapper in the goal.
    show _ ||| _ ||| _ &&& ~~~ (⟨S ||| B⟩ : U64).bv = _
    show _ ||| _ ||| _ &&& ~~~ (S ||| B) = _
    -- Clear stale hypotheses that bv_decide would otherwise treat as opaque.
    clear r_post hS hE hB v1_post1 v1_post2 i5_post1 i5_post2 i4_post i3_post
      i2_post i1_post hcast hi4 hi1eq hp
    -- Use a fully-parametric lemma to avoid bv_decide's opaque handling of `v.bv`.
    have key : ∀ (V B S E : BitVec 64), B &&& S = 0 → S ||| B ||| E = E →
        V ||| B ||| E &&& ~~~ (S ||| B) = V ||| E &&& ~~~ S := by
      intros V B S E hd hs; bv_decide
    exact key v.bv B S E hdisj hsub
  · let* ⟨ o, iter1, hnone, _ ⟩ ← IteratorRange_next_none iter (by scalar_tac)
    rw [hnone]; simp only [WP.spec_ok]
    have hse : iter.start.val = iter.«end».val := by scalar_tac
    have hp : ∀ a b ha hb, a = b →
        Shake4x.packBytes data.val 0 byte_off.val a ha =
        Shake4x.packBytes data.val 0 byte_off.val b hb := by
      intros; subst_eqs; rfl
    rw [hp iter.«end».val iter.start.val (by scalar_tac) (by scalar_tac) hse.symm]
    generalize (Shake4x.packBytes data.val 0 byte_off.val iter.start.val (by scalar_tac)).bv = pS
    bv_decide
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

set_option maxHeartbeats 1600000 in
/-- **Informal proof** (loop spec — `append_loop1`, `Funs.lean:24811-24832`).
    Main absorb loop for the byte-off ≠ 0 path.  Each iteration:
      1. If `offset + 8 > data.length`, exit returning `(kxh, offset, lane_idx)`.
      2. Else read `data[offset..offset+8]`, decode LE → u64 `v`.
      3. `xor_lane kxh lane_idx inst v` → updated state.
      4. Advance offset by 8, lane_idx by 1, recurse.

    **Loop invariant** (per-iteration form at entry `(kxh, offset, lane_idx)`):
    Let `N := (data.length - offset) / 8` (number of full 8-byte chunks remaining).
    After the loop:
      * `offset' = offset + 8 * N`
      * `lane_idx' = lane_idx + N`
      * State: for `j ∈ [lane_idx, lane_idx + N)`, lane `(j, inst)` XORed with
        `LE-decode (data[offset + 8*(j-lane_idx) .. offset + 8*(j-lane_idx) + 8])`;
        all other lanes framed.

    Lemma chain: `Usize.add.spec`, `Slice.len.spec`, `Slice.index.spec` ×
    `IteratorRange.next.spec`, `Array.try_from.spec`, `Result.unwrap.spec`,
    `U64.from_le_bytes.spec`, `Keccak4xHybrid.xor_lane.spec`, recursive IH. -/
@[step]
theorem Shake4x.append_loop1.spec
    (kxh : sha3.keccak4x_hybrid.Keccak4xHybrid) (inst : Std.Usize)
    (data : Slice U8) (offset lane_idx : Std.Usize)
    (hInst : inst.val < 4)
    (hOffset : offset.val ≤ data.length)
    (hSize : data.length + 8 ≤ Std.Usize.max)
    (hLane : lane_idx.val + ((data.length - offset.val) / 8) ≤ 25) :
    sha3.shake4x.Shake4x.append_loop1 kxh inst data offset lane_idx
    ⦃ (r : sha3.keccak4x_hybrid.Keccak4xHybrid × Std.Usize × Std.Usize) =>
        let N := (data.length - offset.val) / 8
        r.2.1.val = offset.val + 8 * N ∧
        r.2.2.val = lane_idx.val + N ∧
        -- frame: lanes outside [lane_idx, lane_idx + N) × {inst} unchanged
        (∀ p : Fin 25, ∀ k : Fin 4,
          ¬ (lane_idx.val ≤ p.val ∧ p.val < lane_idx.val + N ∧ k.val = inst.val) →
          ((r.1.state[p]'(by scalar_tac)).val[k.val]'(by
              have := (r.1.state[p]'(by scalar_tac)).property; scalar_tac))
            = ((kxh.state[p]'(by scalar_tac)).val[k.val]'(by
              have := (kxh.state[p]'(by scalar_tac)).property; scalar_tac))) ∧
        -- mutation: each absorbed lane XORed with LE-decode of its 8-byte chunk
        (∀ j, (hj1 : lane_idx.val ≤ j) → (hj2 : j < lane_idx.val + N) → (hp : j < 25) →
          ((r.1.state[j]'(by scalar_tac)).val[inst.val]'(by
              have := (r.1.state[j]'(by scalar_tac)).property; scalar_tac))
            = ((kxh.state[j]'(by scalar_tac)).val[inst.val]'(by
              have := (kxh.state[j]'(by scalar_tac)).property; scalar_tac))
              ^^^ ⟨(BitVec.fromLEBytes
                    ((data.val.extract (offset.val + 8 * (j - lane_idx.val))
                                       (offset.val + 8 * (j - lane_idx.val) + 8)).map U8.bv)).setWidth 64⟩) ⦄ := by
  unfold sha3.shake4x.Shake4x.append_loop1
  have hadd_ok : offset.val + 8 ≤ Std.Usize.max := by scalar_tac
  step*
  case hmax =>
    simp only [sha3.shake4x.U64_BYTES]
    exact hadd_ok
  case h =>
    have hi_eq : (↑i : ℕ) = ↑offset + 8 := by
      have := i_post; simp [sha3.shake4x.U64_BYTES] at this; exact this
    have hs_len : s.length = 8 := by
      rw [s_post2, hi_eq]; scalar_tac
    cases hr : r with
    | Ok v => exact ⟨v, rfl⟩
    | Err _ =>
      rw [hr] at r_post
      simp at r_post
      exact absurd hs_len r_post
  case hLane =>
    have hi_eq : (↑i : ℕ) = ↑offset + 8 := by
      have := i_post; simp [sha3.shake4x.U64_BYTES] at this; exact this
    have hle : i ≤ data.len := ‹i ≤ data.len›
    have h_i_le : (↑i : ℕ) ≤ data.length := by
      have : i.val ≤ (Slice.len data).val := hle
      simpa using this
    have hN_split : (data.length - ↑i) / 8 + 1 = (data.length - ↑offset) / 8 := by
      rw [hi_eq]
      have hoff_le : ↑offset + 8 ≤ data.length := by rw [← hi_eq]; exact h_i_le
      scalar_tac
    rw [lane_idx1_post]
    have hrw : (↑lane_idx + 1) + (data.length - ↑i) / 8
             = ↑lane_idx + ((data.length - ↑i) / 8 + 1) := by ring
    rw [hrw, hN_split]
    exact hLane
  · -- main goal: compose IH (r_post1..4) + prologue posts into outer post.
    have hi_eq : (↑i : ℕ) = ↑offset + 8 := by
      have := i_post; simp [sha3.shake4x.U64_BYTES] at this; exact this
    have hle : i ≤ data.len := ‹i ≤ data.len›
    have h_i_le : (↑i : ℕ) ≤ data.length := by
      have : i.val ≤ (Slice.len data).val := hle
      simpa using this
    have hN_split : (data.length - ↑i) / 8 + 1 = (data.length - ↑offset) / 8 := by
      rw [hi_eq]
      have hoff_le : ↑offset + 8 ≤ data.length := by rw [← hi_eq]; exact h_i_le
      scalar_tac
    have hN_pos : 1 ≤ (data.length - ↑offset) / 8 := by
      rw [← hN_split]; scalar_tac
    -- Decode of a.val:
    have ha_eq_s : (↑a : List U8) = ↑s := by
      rw [a_post] at r_post; simpa using r_post.1
    have hs_eq : (↑s : List U8) = (↑data : List U8).extract ↑offset ↑i := by
      rw [s_post1]; rfl
    have ha_extract : (↑a : List U8) = (↑data : List U8).extract ↑offset ↑i := by
      rw [ha_eq_s, hs_eq]
    refine ⟨?_, ?_, ?_, ?_⟩
    · -- offset arithmetic
      rw [r_post1, ← hN_split]; scalar_tac
    · -- lane_idx arithmetic
      rw [r_post2, lane_idx1_post, ← hN_split]; ring
    · -- frame (Fin × Fin): direct chain via r_post3 + kxh1_post — PROVEN.
      intro p k hframe
      have h_ih_frame : ¬ ((↑lane_idx1 : ℕ) ≤ (↑p : ℕ) ∧ (↑p : ℕ) < ↑lane_idx1 + (data.length - ↑i) / 8 ∧ (↑k : ℕ) = ↑inst) := by
        intro ⟨h1, h2, h3⟩
        apply hframe
        rw [lane_idx1_post] at h1 h2
        refine ⟨by scalar_tac, ?_, h3⟩
        have : (↑lane_idx : ℕ) + (data.length - ↑offset) / 8
             = (↑lane_idx + 1) + (data.length - ↑i) / 8 := by
          rw [← hN_split]; ring
        rw [this]; exact h2
      have h1 := r_post3 p k h_ih_frame
      have h2 := kxh1_post p k
      have h3 : ¬ ((↑p : ℕ) = ↑lane_idx ∧ (↑k : ℕ) = ↑inst) := by
        intro ⟨hpeq, hkeq⟩
        apply hframe
        refine ⟨by rw [hpeq], ?_, hkeq⟩
        rw [hpeq]; scalar_tac
      rw [h1, h2, if_neg h3]
    · -- mutation conjunct.  Bridges the Fin-indexed `kxh1_post` (from `xor_lane.spec`,
      -- Fin 25 × Fin 4) to the Nat-indexed IH/goal via `exact hk` — the two
      -- forms are defeq but `rw` cannot match because the `[…]'(…)` proof terms differ.
      -- See FEED entry on Fin/Nat bridge for the canonical workaround.
      intro j hj1 hj2 hp
      have hinst_fin : (↑inst : ℕ) < 4 := hInst
      by_cases hjeq : j = (↑lane_idx : ℕ)
      · -- j = lane_idx case: use r_post3 (frame for kxh1, since lane_idx < lane_idx1) +
        -- kxh1_post (if_pos branch: kxh1[lane_idx][inst] = kxh[lane_idx][inst] ^^^ v) +
        -- v_post + ha_extract bridge to setWidth (fromLEBytes (data.extract offset (offset+8))).
        have h_frame_kxh1 : ¬ ((↑lane_idx1 : ℕ) ≤ (↑(⟨j, hp⟩ : Fin 25) : ℕ) ∧
                                (↑(⟨j, hp⟩ : Fin 25) : ℕ) < ↑lane_idx1 + (data.length - ↑i) / 8 ∧
                                (↑(⟨↑inst, hinst_fin⟩ : Fin 4) : ℕ) = ↑inst) := by
          intro ⟨h1, _, _⟩
          simp only [] at h1
          rw [lane_idx1_post, hjeq] at h1
          scalar_tac
        have h1 := r_post3 ⟨j, hp⟩ ⟨↑inst, hinst_fin⟩ h_frame_kxh1
        have hk := kxh1_post ⟨j, hp⟩ ⟨↑inst, hinst_fin⟩
        have hpos : (↑(⟨j, hp⟩ : Fin 25) : ℕ) = ↑lane_idx ∧
                    (↑(⟨↑inst, hinst_fin⟩ : Fin 4) : ℕ) = ↑inst := by
          refine ⟨?_, ?_⟩ <;> simp [hjeq]
        rw [if_pos hpos] at hk
        -- Bridge v to setWidth (fromLEBytes (data.extract offset (offset+8))):
        have hsub : j - (↑lane_idx : ℕ) = 0 := by rw [hjeq]; exact Nat.sub_self _
        have hbv_v : v.bv = BitVec.setWidth 64 (BitVec.fromLEBytes
                      (((↑data : List U8).extract (↑offset + 8 * (j - ↑lane_idx))
                                                  (↑offset + 8 * (j - ↑lane_idx) + 8)).map U8.bv)) := by
          rw [v_post, hsub, Nat.mul_zero, Nat.add_zero, ← hi_eq, ← ha_extract]
          apply BitVec.eq_of_getLsbD_eq
          intro k
          simp
          · intros; assumption
        have hv_eq : v = ⟨BitVec.setWidth 64 (BitVec.fromLEBytes
                      (((↑data : List U8).extract (↑offset + 8 * (j - ↑lane_idx))
                                                  (↑offset + 8 * (j - ↑lane_idx) + 8)).map U8.bv))⟩ :=
          U64.bv_eq_imp_eq _ _ hbv_v
        rw [hv_eq] at hk
        exact h1.trans hk
      · have hj1' : (↑lane_idx1 : ℕ) ≤ j := by rw [lane_idx1_post]; scalar_tac
        have hj2' : j < ↑lane_idx1 + (data.length - ↑i) / 8 := by
          have heq : (↑lane_idx1 : ℕ) + (data.length - ↑i) / 8
               = ↑lane_idx + (data.length - ↑offset) / 8 := by
            rw [lane_idx1_post, ← hN_split]; ring
          rw [heq]; exact hj2
        have h_ih := r_post4 j hj1' hj2' hp
        rw [h_ih]
        congr 1
        · have hk := kxh1_post ⟨j, hp⟩ ⟨↑inst, hinst_fin⟩
          have hne : ¬ ((↑(⟨j, hp⟩ : Fin 25) : ℕ) = ↑lane_idx ∧ (↑(⟨↑inst, hinst_fin⟩ : Fin 4) : ℕ) = ↑inst) := by
            intro ⟨h1, _⟩
            simp only [] at h1
            exact hjeq h1
          rw [if_neg hne] at hk
          exact hk
        · rw [hi_eq, lane_idx1_post]
          have hsub : j - (↑lane_idx + 1) + 1 = j - ↑lane_idx := by
            have h_ge : j ≥ ↑lane_idx + 1 := by rw [← lane_idx1_post]; exact hj1'
            scalar_tac
          have e1 : ↑offset + 8 + 8 * (j - (↑lane_idx + 1)) = ↑offset + 8 * (j - ↑lane_idx) := by
            rw [← hsub]; ring
          rw [e1]
  case h2 =>
    have hi_eq : (↑i : ℕ) = ↑offset + 8 := by
      have := i_post; simp [sha3.shake4x.U64_BYTES] at this; exact this
    have hnle : ¬ i ≤ data.len := ‹¬ i ≤ data.len›
    have hi : ¬ (↑i : ℕ) ≤ data.length := by
      intro h
      apply hnle
      have hslice : (Slice.len data).val = data.length := by simp
      show i.val ≤ (Slice.len data).val
      rw [hslice]; exact h
    have hN_zero : (data.length - ↑offset) / 8 = 0 := by
      rw [hi_eq] at hi
      scalar_tac
    refine ⟨?_, ?_, ?_, ?_⟩
    · rw [hN_zero]; ring
    · rw [hN_zero]; ring
    · intros; trivial
    · intros j hj1 hj2 hp
      exfalso
      rw [hN_zero] at hj2
      scalar_tac
  termination_by data.length - offset.val
  decreasing_by
    have hi_eq := i_post
    simp only [sha3.shake4x.U64_BYTES] at hi_eq
    have hle := ‹_ ≤ data.len›
    scalar_tac

/-- **Informal proof** (loop spec — `append_loop2`, `Funs.lean:24837-24854`).
    Tail-byte packing for the byte-off ≠ 0 path: pack remaining (< 8) bytes
    starting at `offset` into a fresh u64 at byte position `0..iter.end`.
    Algebraically same as `append_loop0` with `byte_off = 0` and shifted
    read base `offset + i`.

    **Loop invariant**:
    `v = v₀ ||| packBytes data offset 0 iter.start.val`.
    Lemma chain identical to `append_loop0.spec`. -/
@[step]
theorem Shake4x.append_loop2.spec
    (iter : core.ops.range.Range Std.Usize)
    (data : Slice U8) (offset : Std.Usize) (v : U64)
    (hStart : iter.start.val ≤ iter.«end».val)
    (hData : offset.val + iter.«end».val ≤ data.length)
    (hShift : iter.«end».val ≤ 8) :
    sha3.shake4x.Shake4x.append_loop2 iter data offset v
    ⦃ (r : U64) =>
        r.bv = v.bv ||| (Shake4x.packBytes data.val offset.val 0 iter.«end».val
                            (by scalar_tac)).bv
                          &&& (~~~ (Shake4x.packBytes data.val offset.val 0 iter.start.val
                            (by scalar_tac)).bv) ⦄ := by
  unfold sha3.shake4x.Shake4x.append_loop2
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← IteratorRange_next_some iter hlt
    rw [hsome]
    step*
    have hi1_start : iter1.start.val = iter.start.val + 1 := hstart'
    have hi1_end : iter1.«end» = iter.«end» := hend'
    have hp : ∀ a b ha hb, a = b →
        Shake4x.packBytes data.val offset.val 0 a ha =
        Shake4x.packBytes data.val offset.val 0 b hb := by
      intros; subst_eqs; rfl
    rw [hp iter1.start.val (iter.start.val + 1) (by scalar_tac) (by scalar_tac) hi1_start] at r_post
    rw [hp iter1.«end».val iter.«end».val (by scalar_tac) (by scalar_tac)
       (by rw [hi1_end])] at r_post
    rw [Shake4x.packBytes_succ data.val offset.val 0 iter.start.val (by scalar_tac)] at r_post
    have hcast : i3.bv = i2.bv.zeroExtend 64 := by rw [i3_post]; rfl
    have hi4 : i4.val = 8 * (0 + iter.start.val) := by rw [i4_post]; scalar_tac
    have hi2eq : i2.bv = (data.val[offset.val + iter.start.val]'(by scalar_tac)).bv := by
      rw [i2_post]
      have : i1.val = offset.val + iter.start.val := i1_post
      simp only [this]
    simp only [v1_post2, i5_post2, hcast, hi4, hi2eq] at r_post
    simp only [show ∀ x : BitVec 64, (⟨x⟩ : U64).bv = x from fun _ => rfl] at r_post
    have hsub : (Shake4x.packBytes data.val offset.val 0 (iter.start.val + 1)
                    (by scalar_tac)).bv |||
                (Shake4x.packBytes data.val offset.val 0 iter.«end».val
                    (by scalar_tac)).bv =
                (Shake4x.packBytes data.val offset.val 0 iter.«end».val
                    (by scalar_tac)).bv :=
      Shake4x.packBytes_subset data.val offset.val 0 (iter.start.val + 1) iter.«end».val
        (by scalar_tac) (by scalar_tac)
    rw [Shake4x.packBytes_succ data.val offset.val 0 iter.start.val (by scalar_tac)] at hsub
    have hdisj :
        ((data.val[offset.val + iter.start.val]'(by scalar_tac)).bv.setWidth 64 <<<
          (8 * (0 + iter.start.val))) &&&
        (Shake4x.packBytes data.val offset.val 0 iter.start.val (by scalar_tac)).bv = 0 :=
      Shake4x.packBytes_byte_disjoint data.val offset.val 0 iter.start.val (by scalar_tac)
    rw [r_post]
    generalize hS : (Shake4x.packBytes data.val offset.val 0 iter.start.val
                       (by scalar_tac)).bv = S
    rw [hS] at hdisj hsub
    generalize hE : (Shake4x.packBytes data.val offset.val 0 iter.«end».val
                       (by scalar_tac)).bv = E
    rw [hE] at hsub
    generalize hB : ((data.val[offset.val + iter.start.val]'(by scalar_tac)).bv.zeroExtend 64) <<<
                       (8 * (0 + iter.start.val)) = B
    rw [hB] at hsub hdisj
    simp only [show ∀ x : BitVec 64, (⟨x⟩ : U64).bv = x from fun _ => rfl] at hsub
    show _ ||| _ ||| _ &&& ~~~ (⟨S ||| B⟩ : U64).bv = _
    show _ ||| _ ||| _ &&& ~~~ (S ||| B) = _
    clear r_post hS hE hB v1_post1 v1_post2 i5_post1 i5_post2 i4_post
      i3_post i2_post i1_post hcast hi4 hi2eq hp
    have key : ∀ (V B S E : BitVec 64), B &&& S = 0 → S ||| B ||| E = E →
        V ||| B ||| E &&& ~~~ (S ||| B) = V ||| E &&& ~~~ S := by
      intros V B S E hd hs; bv_decide
    exact key v.bv B S E hdisj hsub
  · let* ⟨ o, iter1, hnone, _ ⟩ ← IteratorRange_next_none iter (by scalar_tac)
    rw [hnone]; simp only [WP.spec_ok]
    have hse : iter.start.val = iter.«end».val := by scalar_tac
    have hp : ∀ a b ha hb, a = b →
        Shake4x.packBytes data.val offset.val 0 a ha =
        Shake4x.packBytes data.val offset.val 0 b hb := by
      intros; subst_eqs; rfl
    rw [hp iter.«end».val iter.start.val (by scalar_tac) (by scalar_tac) hse.symm]
    generalize (Shake4x.packBytes data.val offset.val 0 iter.start.val (by scalar_tac)).bv = pS
    bv_decide
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- **Informal proof** (loop spec — `append_loop3`).
    Algebraically identical to `append_loop1` (the byte-off ≠ 0 main loop
    and byte-off = 0 main loop have the same Rust body). -/
@[step]
theorem Shake4x.append_loop3.spec
    (kxh : sha3.keccak4x_hybrid.Keccak4xHybrid) (inst : Std.Usize)
    (data : Slice U8) (offset lane_idx : Std.Usize)
    (hInst : inst.val < 4)
    (hOffset : offset.val ≤ data.length)
    (hSize : data.length + 8 ≤ Std.Usize.max)
    (hLane : lane_idx.val + ((data.length - offset.val) / 8) ≤ 25) :
    sha3.shake4x.Shake4x.append_loop3 kxh inst data offset lane_idx
    ⦃ (r : sha3.keccak4x_hybrid.Keccak4xHybrid × Std.Usize × Std.Usize) =>
        let N := (data.length - offset.val) / 8
        r.2.1.val = offset.val + 8 * N ∧
        r.2.2.val = lane_idx.val + N ∧
        (∀ p : Fin 25, ∀ k : Fin 4,
          ¬ (lane_idx.val ≤ p.val ∧ p.val < lane_idx.val + N ∧ k.val = inst.val) →
          ((r.1.state[p]'(by scalar_tac)).val[k.val]'(by
              have := (r.1.state[p]'(by scalar_tac)).property; scalar_tac))
            = ((kxh.state[p]'(by scalar_tac)).val[k.val]'(by
              have := (kxh.state[p]'(by scalar_tac)).property; scalar_tac))) ∧
        (∀ j, (hj1 : lane_idx.val ≤ j) → (hj2 : j < lane_idx.val + N) → (hp : j < 25) →
          ((r.1.state[j]'(by scalar_tac)).val[inst.val]'(by
              have := (r.1.state[j]'(by scalar_tac)).property; scalar_tac))
            = ((kxh.state[j]'(by scalar_tac)).val[inst.val]'(by
              have := (kxh.state[j]'(by scalar_tac)).property; scalar_tac))
              ^^^ ⟨(BitVec.fromLEBytes
                    ((data.val.extract (offset.val + 8 * (j - lane_idx.val))
                                       (offset.val + 8 * (j - lane_idx.val) + 8)).map U8.bv)).setWidth 64⟩) ⦄ := by
  unfold sha3.shake4x.Shake4x.append_loop3
  have hadd_ok : offset.val + 8 ≤ Std.Usize.max := by scalar_tac
  step*
  case hmax =>
    simp only [sha3.shake4x.U64_BYTES]
    exact hadd_ok
  case h =>
    have hi_eq : (↑i : ℕ) = ↑offset + 8 := by
      have := i_post; simp [sha3.shake4x.U64_BYTES] at this; exact this
    have hs_len : s.length = 8 := by
      rw [s_post2, hi_eq]; scalar_tac
    cases hr : r with
    | Ok v => exact ⟨v, rfl⟩
    | Err _ =>
      rw [hr] at r_post
      simp at r_post
      exact absurd hs_len r_post
  case hLane =>
    have hi_eq : (↑i : ℕ) = ↑offset + 8 := by
      have := i_post; simp [sha3.shake4x.U64_BYTES] at this; exact this
    have hle : i ≤ data.len := ‹i ≤ data.len›
    have h_i_le : (↑i : ℕ) ≤ data.length := by
      have : i.val ≤ (Slice.len data).val := hle
      simpa using this
    have hN_split : (data.length - ↑i) / 8 + 1 = (data.length - ↑offset) / 8 := by
      rw [hi_eq]
      have hoff_le : ↑offset + 8 ≤ data.length := by rw [← hi_eq]; exact h_i_le
      scalar_tac
    rw [lane_idx1_post]
    have hrw : (↑lane_idx + 1) + (data.length - ↑i) / 8
             = ↑lane_idx + ((data.length - ↑i) / 8 + 1) := by ring
    rw [hrw, hN_split]
    exact hLane
  · have hi_eq : (↑i : ℕ) = ↑offset + 8 := by
      have := i_post; simp [sha3.shake4x.U64_BYTES] at this; exact this
    have hle : i ≤ data.len := ‹i ≤ data.len›
    have h_i_le : (↑i : ℕ) ≤ data.length := by
      have : i.val ≤ (Slice.len data).val := hle
      simpa using this
    have hN_split : (data.length - ↑i) / 8 + 1 = (data.length - ↑offset) / 8 := by
      rw [hi_eq]
      have hoff_le : ↑offset + 8 ≤ data.length := by rw [← hi_eq]; exact h_i_le
      scalar_tac
    have hN_pos : 1 ≤ (data.length - ↑offset) / 8 := by
      rw [← hN_split]; scalar_tac
    have ha_eq_s : (↑a : List U8) = ↑s := by
      rw [a_post] at r_post; simpa using r_post.1
    have hs_eq : (↑s : List U8) = (↑data : List U8).extract ↑offset ↑i := by
      rw [s_post1]; rfl
    have ha_extract : (↑a : List U8) = (↑data : List U8).extract ↑offset ↑i := by
      rw [ha_eq_s, hs_eq]
    refine ⟨?_, ?_, ?_, ?_⟩
    · rw [r_post1, ← hN_split]; scalar_tac
    · rw [r_post2, lane_idx1_post, ← hN_split]; ring
    · intro p k hframe
      have h_ih_frame : ¬ ((↑lane_idx1 : ℕ) ≤ (↑p : ℕ) ∧ (↑p : ℕ) < ↑lane_idx1 + (data.length - ↑i) / 8 ∧ (↑k : ℕ) = ↑inst) := by
        intro ⟨h1, h2, h3⟩
        apply hframe
        rw [lane_idx1_post] at h1 h2
        refine ⟨by scalar_tac, ?_, h3⟩
        have : (↑lane_idx : ℕ) + (data.length - ↑offset) / 8
             = (↑lane_idx + 1) + (data.length - ↑i) / 8 := by
          rw [← hN_split]; ring
        rw [this]; exact h2
      have h1 := r_post3 p k h_ih_frame
      have h2 := kxh1_post p k
      have h3 : ¬ ((↑p : ℕ) = ↑lane_idx ∧ (↑k : ℕ) = ↑inst) := by
        intro ⟨hpeq, hkeq⟩
        apply hframe
        refine ⟨by rw [hpeq], ?_, hkeq⟩
        rw [hpeq]; scalar_tac
      rw [h1, h2, if_neg h3]
    · intro j hj1 hj2 hp
      have hinst_fin : (↑inst : ℕ) < 4 := hInst
      by_cases hjeq : j = (↑lane_idx : ℕ)
      · have h_frame_kxh1 : ¬ ((↑lane_idx1 : ℕ) ≤ (↑(⟨j, hp⟩ : Fin 25) : ℕ) ∧
                                (↑(⟨j, hp⟩ : Fin 25) : ℕ) < ↑lane_idx1 + (data.length - ↑i) / 8 ∧
                                (↑(⟨↑inst, hinst_fin⟩ : Fin 4) : ℕ) = ↑inst) := by
          intro ⟨h1, _, _⟩
          simp only [] at h1
          rw [lane_idx1_post, hjeq] at h1
          scalar_tac
        have h1 := r_post3 ⟨j, hp⟩ ⟨↑inst, hinst_fin⟩ h_frame_kxh1
        have hk := kxh1_post ⟨j, hp⟩ ⟨↑inst, hinst_fin⟩
        have hpos : (↑(⟨j, hp⟩ : Fin 25) : ℕ) = ↑lane_idx ∧
                    (↑(⟨↑inst, hinst_fin⟩ : Fin 4) : ℕ) = ↑inst := by
          refine ⟨?_, ?_⟩ <;> simp [hjeq]
        rw [if_pos hpos] at hk
        have hsub : j - (↑lane_idx : ℕ) = 0 := by rw [hjeq]; exact Nat.sub_self _
        have hbv_v : v.bv = BitVec.setWidth 64 (BitVec.fromLEBytes
                      (((↑data : List U8).extract (↑offset + 8 * (j - ↑lane_idx))
                                                  (↑offset + 8 * (j - ↑lane_idx) + 8)).map U8.bv)) := by
          rw [v_post, hsub, Nat.mul_zero, Nat.add_zero, ← hi_eq, ← ha_extract]
          apply BitVec.eq_of_getLsbD_eq
          intro k
          simp
          · intros; assumption
        have hv_eq : v = ⟨BitVec.setWidth 64 (BitVec.fromLEBytes
                      (((↑data : List U8).extract (↑offset + 8 * (j - ↑lane_idx))
                                                  (↑offset + 8 * (j - ↑lane_idx) + 8)).map U8.bv))⟩ :=
          U64.bv_eq_imp_eq _ _ hbv_v
        rw [hv_eq] at hk
        exact h1.trans hk
      · have hj1' : (↑lane_idx1 : ℕ) ≤ j := by rw [lane_idx1_post]; scalar_tac
        have hj2' : j < ↑lane_idx1 + (data.length - ↑i) / 8 := by
          have heq : (↑lane_idx1 : ℕ) + (data.length - ↑i) / 8
               = ↑lane_idx + (data.length - ↑offset) / 8 := by
            rw [lane_idx1_post, ← hN_split]; ring
          rw [heq]; exact hj2
        have h_ih := r_post4 j hj1' hj2' hp
        rw [h_ih]
        congr 1
        · have hk := kxh1_post ⟨j, hp⟩ ⟨↑inst, hinst_fin⟩
          have hne : ¬ ((↑(⟨j, hp⟩ : Fin 25) : ℕ) = ↑lane_idx ∧ (↑(⟨↑inst, hinst_fin⟩ : Fin 4) : ℕ) = ↑inst) := by
            intro ⟨h1, _⟩
            simp only [] at h1
            exact hjeq h1
          rw [if_neg hne] at hk
          exact hk
        · rw [hi_eq, lane_idx1_post]
          have hsub : j - (↑lane_idx + 1) + 1 = j - ↑lane_idx := by
            have h_ge : j ≥ ↑lane_idx + 1 := by rw [← lane_idx1_post]; exact hj1'
            scalar_tac
          have e1 : ↑offset + 8 + 8 * (j - (↑lane_idx + 1)) = ↑offset + 8 * (j - ↑lane_idx) := by
            rw [← hsub]; ring
          rw [e1]
  case h2 =>
    have hi_eq : (↑i : ℕ) = ↑offset + 8 := by
      have := i_post; simp [sha3.shake4x.U64_BYTES] at this; exact this
    have hnle : ¬ i ≤ data.len := ‹¬ i ≤ data.len›
    have hi : ¬ (↑i : ℕ) ≤ data.length := by
      intro h
      apply hnle
      have hslice : (Slice.len data).val = data.length := by simp
      show i.val ≤ (Slice.len data).val
      rw [hslice]; exact h
    have hN_zero : (data.length - ↑offset) / 8 = 0 := by
      rw [hi_eq] at hi
      scalar_tac
    refine ⟨?_, ?_, ?_, ?_⟩
    · rw [hN_zero]; ring
    · rw [hN_zero]; ring
    · intros; trivial
    · intros j hj1 hj2 hp
      exfalso
      rw [hN_zero] at hj2
      scalar_tac
  termination_by data.length - offset.val
  decreasing_by
    have hi_eq := i_post
    simp only [sha3.shake4x.U64_BYTES] at hi_eq
    have hle := ‹_ ≤ data.len›
    scalar_tac

/-- **Informal proof** (loop spec — `append_loop4`).
    Algebraically identical to `append_loop2`. -/
@[step]
theorem Shake4x.append_loop4.spec
    (iter : core.ops.range.Range Std.Usize)
    (data : Slice U8) (offset : Std.Usize) (v : U64)
    (hStart : iter.start.val ≤ iter.«end».val)
    (hData : offset.val + iter.«end».val ≤ data.length)
    (hShift : iter.«end».val ≤ 8) :
    sha3.shake4x.Shake4x.append_loop4 iter data offset v
    ⦃ (r : U64) =>
        r.bv = v.bv ||| (Shake4x.packBytes data.val offset.val 0 iter.«end».val
                            (by scalar_tac)).bv
                          &&& (~~~ (Shake4x.packBytes data.val offset.val 0 iter.start.val
                            (by scalar_tac)).bv) ⦄ := by
  unfold sha3.shake4x.Shake4x.append_loop4
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← IteratorRange_next_some iter hlt
    rw [hsome]
    step*
    have hi1_start : iter1.start.val = iter.start.val + 1 := hstart'
    have hi1_end : iter1.«end» = iter.«end» := hend'
    have hp : ∀ a b ha hb, a = b →
        Shake4x.packBytes data.val offset.val 0 a ha =
        Shake4x.packBytes data.val offset.val 0 b hb := by
      intros; subst_eqs; rfl
    rw [hp iter1.start.val (iter.start.val + 1) (by scalar_tac) (by scalar_tac) hi1_start] at r_post
    rw [hp iter1.«end».val iter.«end».val (by scalar_tac) (by scalar_tac)
       (by rw [hi1_end])] at r_post
    rw [Shake4x.packBytes_succ data.val offset.val 0 iter.start.val (by scalar_tac)] at r_post
    have hcast : i3.bv = i2.bv.zeroExtend 64 := by rw [i3_post]; rfl
    have hi4 : i4.val = 8 * (0 + iter.start.val) := by rw [i4_post]; scalar_tac
    have hi2eq : i2.bv = (data.val[offset.val + iter.start.val]'(by scalar_tac)).bv := by
      rw [i2_post]
      have : i1.val = offset.val + iter.start.val := i1_post
      simp only [this]
    simp only [v1_post2, i5_post2, hcast, hi4, hi2eq] at r_post
    simp only [show ∀ x : BitVec 64, (⟨x⟩ : U64).bv = x from fun _ => rfl] at r_post
    have hsub : (Shake4x.packBytes data.val offset.val 0 (iter.start.val + 1)
                    (by scalar_tac)).bv |||
                (Shake4x.packBytes data.val offset.val 0 iter.«end».val
                    (by scalar_tac)).bv =
                (Shake4x.packBytes data.val offset.val 0 iter.«end».val
                    (by scalar_tac)).bv :=
      Shake4x.packBytes_subset data.val offset.val 0 (iter.start.val + 1) iter.«end».val
        (by scalar_tac) (by scalar_tac)
    rw [Shake4x.packBytes_succ data.val offset.val 0 iter.start.val (by scalar_tac)] at hsub
    have hdisj :
        ((data.val[offset.val + iter.start.val]'(by scalar_tac)).bv.setWidth 64 <<<
          (8 * (0 + iter.start.val))) &&&
        (Shake4x.packBytes data.val offset.val 0 iter.start.val (by scalar_tac)).bv = 0 :=
      Shake4x.packBytes_byte_disjoint data.val offset.val 0 iter.start.val (by scalar_tac)
    rw [r_post]
    generalize hS : (Shake4x.packBytes data.val offset.val 0 iter.start.val
                       (by scalar_tac)).bv = S
    rw [hS] at hdisj hsub
    generalize hE : (Shake4x.packBytes data.val offset.val 0 iter.«end».val
                       (by scalar_tac)).bv = E
    rw [hE] at hsub
    generalize hB : ((data.val[offset.val + iter.start.val]'(by scalar_tac)).bv.zeroExtend 64) <<<
                       (8 * (0 + iter.start.val)) = B
    rw [hB] at hsub hdisj
    simp only [show ∀ x : BitVec 64, (⟨x⟩ : U64).bv = x from fun _ => rfl] at hsub
    show _ ||| _ ||| _ &&& ~~~ (⟨S ||| B⟩ : U64).bv = _
    show _ ||| _ ||| _ &&& ~~~ (S ||| B) = _
    clear r_post hS hE hB v1_post1 v1_post2 i5_post1 i5_post2 i4_post
      i3_post i2_post i1_post hcast hi4 hi2eq hp
    have key : ∀ (V B S E : BitVec 64), B &&& S = 0 → S ||| B ||| E = E →
        V ||| B ||| E &&& ~~~ (S ||| B) = V ||| E &&& ~~~ S := by
      intros V B S E hd hs; bv_decide
    exact key v.bv B S E hdisj hsub
  · let* ⟨ o, iter1, hnone, _ ⟩ ← IteratorRange_next_none iter (by scalar_tac)
    rw [hnone]; simp only [WP.spec_ok]
    have hse : iter.start.val = iter.«end».val := by scalar_tac
    have hp : ∀ a b ha hb, a = b →
        Shake4x.packBytes data.val offset.val 0 a ha =
        Shake4x.packBytes data.val offset.val 0 b hb := by
      intros; subst_eqs; rfl
    rw [hp iter.«end».val iter.start.val (by scalar_tac) (by scalar_tac) hse.symm]
    generalize (Shake4x.packBytes data.val offset.val 0 iter.start.val (by scalar_tac)).bv = pS
    bv_decide
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/- `Shake4x.append self inst data` extends instance `inst`'s absorb
    buffer by `data`, leaving every other instance unchanged.

    `inst : Std.Usize` is the per-instance selector (`inst.val ∈ {0,1,2,3}`);
    the 4 streams are **NOT** synchronized in absorb mode — different
    instances may absorb different lengths.  Lockstep only happens at
    `pad_all`/`finalize_*`/`next_block_*` (fused permute).

    **Full FC**: minimal post — fields not listed are pinned via the
    composite `Shake4x.absorbing` predicate (cf. scalar
    `KeccakState.append.spec` at `Sponge/Absorb.lean:1126`):

      * `state`, `rate`, `finalized` — via `Shake4x.absorbing result …`
                                       combined with WF bundling.
      * `rate_lanes`                 — derivable from `rate` via
                                       `WF.2.1`.
      * `buf`                        — orthogonal field; pinned explicitly.
      * `absorbed`                   — pinned explicitly via `Std.Array.set`
                                       for caller convenience (chaining
                                       appends w/o unfolding `absorbing`).

    **Informal proof** (top-level absorb-mode extension,
    `Funs.lean:25223-25324`).
    Body (≈30 monadic operations; one of the largest wrappers):
      1. `byte_off ← absorbed[inst] % 8` — head-of-lane bit offset.
      2. **Unaligned head dispatch**: if `byte_off ≠ 0`, copy up to
         `8 - byte_off` bytes into the partial lane via
         `append_loop0` (load lane), `append_loop1` (OR-in bytes from
         `data` MSB-first), `append_loop2` (mask-out tail beyond
         `data.length`).  If `byte_off = 0`, skip.
      3. **Lane-aligned middle**: as long as `≥ 8` bytes remain, run
         `append_loop3` (load 8 bytes LE → U64) and write the lane.
      4. **Tail dispatch**: any residual `< 8` bytes go through
         `append_loop4` (OR-in the residual).
      5. `absorbed[inst] += data.length` and return.

    **Post derivation**:
      * `rate`, `rate_lanes`, `buf` — orthogonal record fields; the
        body only mutates `state` and `absorbed`.  Pinned explicitly
        for callers that chain appends.
      * `absorbed = self.absorbed.set inst i'` — single `Std.Array.set`
        at step 5; other instances untouched (loops 0-4 mutate only
        the `inst`-th lane).
      * `absorbing result (Function.update gs k' …)` — composes the
        per-instance scalar `KeccakState.append` (from
        `Sponge/Absorb.lean:1126`) with the lane-XOR equations
        established by `append_loop{0..4}`.  The `Function.update`
        threads through because: (a) ghost states for `i ≠ inst` are
        unchanged (the lanes for `i ≠ inst` are unchanged); (b) ghost
        state for `i = inst` becomes `(gs k').append data.val false`
        per scalar `KeccakState.append.spec`'s post.  WF preserved:
        `rate`/`rate_lanes` unchanged; `absorbed[inst].val =
        old + data.length ≤ rate` per `hFit`.

    **Scalar bridge**: the byte-by-byte XOR equation
    established by `append_loop{0..4}` composes into the scalar
    `KeccakState.append` form.  This uses a per-lane
    `lane_append_eq` helper that translates
    `kxh.state[p][k] ^^^ packBytes data offset 0 m` into
    `(toScalar self k).state` evolved by `append data m false`.
    Lives in `Properties/SHA3/Basic.lean`. -/
/-! ## Scalar bridge: lane-XOR loops → scalar `absorbBytes` (`lane_append_eq`)

The 4x `append` mutates lane `inst` of the 4-way Keccak state via a sequence
of `xor_lane` calls whose XOR operands are built (by `append_loop{0..4}`) from
the bytes of `data`.  Projected to lane `inst`, this is exactly the scalar
`absorbByte`-per-byte XOR (no permute, since `hFit` keeps us inside one block).
The bridge below converts a *per-lane, per-bit* statement about the projected
4x state into the spec-side `toBits … ⊕ V` equation consumed by
`sha3_impl.spongeInvariant`. -/

section
open Spec.SHA3 (b w)
open scoped Spec.SHA3
open scoped Spec.Notations

/-- A projected toArray lane read (`getElem!` form, as produced by
    `toBits_getElem'`) is the underlying 4-way state lane for instance `inst`. -/
theorem projLane_toArray_getElem!
    (s : Std.Array sha3.keccak4x_hybrid.Lane4 25#usize)
    (inst : Fin 4) (m : Nat) (hm : m < 25) :
    (Keccak4xHybrid.projectLane inst s).toArray.val[m]! =
      (s.val[m]'(by scalar_tac)).val[inst.val]'(by
        have := (s.val[m]'(by scalar_tac)).property; have := inst.isLt; scalar_tac) := by
  have hlen : (Keccak4xHybrid.projectLane inst s).toArray.val.length = 25 :=
    (Keccak4xHybrid.projectLane inst s).toArray.property
  rw [getElem!_pos _ m (by rw [hlen]; exact hm)]
  have hb : (Keccak4xHybrid.projectLane inst s).toArray.val[m]'(by rw [hlen]; exact hm)
      = (Keccak4xHybrid.projectLane inst s).lane25 ⟨m, hm⟩ := by
    have : ∀ n : Fin 25, (Keccak4xHybrid.projectLane inst s).toArray.val[n.val]'(by
        have := (Keccak4xHybrid.projectLane inst s).toArray.property; have := n.isLt; scalar_tac)
        = (Keccak4xHybrid.projectLane inst s).lane25 n := by
      intro n; fin_cases n <;> rfl
    exact this ⟨m, hm⟩
  rw [hb, Keccak4xHybrid.projectLane_lane25]

/-- **Foundation bridge.**  If, lane-by-lane and bit-by-bit, the projected
    `rstate` lane equals the projected `sstate` lane XORed with `V`'s bit at
    the corresponding absolute position, then `toBits` of the two projections
    differ by `V`.  This is the load-bearing reduction from the 4-way lane
    state to the spec's bit-vector `⊕`. -/
theorem toBits_projectLane_xor
    (rstate sstate : Std.Array sha3.keccak4x_hybrid.Lane4 25#usize)
    (inst : Fin 4) (V : Vector Bool b)
    (hbit : ∀ (m : Fin 25) (c : Fin 64),
       ((rstate.val[m.val]'(by have := m.isLt; scalar_tac)).val[inst.val]'(by
          have := (rstate.val[m.val]'(by have := m.isLt; scalar_tac)).property
          have := inst.isLt; scalar_tac)).bv.getLsbD c.val
       = (((sstate.val[m.val]'(by have := m.isLt; scalar_tac)).val[inst.val]'(by
          have := (sstate.val[m.val]'(by have := m.isLt; scalar_tac)).property
          have := inst.isLt; scalar_tac)).bv.getLsbD c.val
         ^^ V[64 * m.val + c.val]'(by
            have := m.isLt; have := c.isLt; have : (b:Nat) = 1600 := rfl; omega))) :
    toBits (Keccak4xHybrid.projectLane inst rstate).toArray
      = toBits (Keccak4xHybrid.projectLane inst sstate).toArray ⊕ V := by
  apply Vector.ext
  intro n hn
  have hbN : (b:Nat) = 1600 := rfl
  have hn64 : n / 64 < 25 := by omega
  have hc64 : n % 64 < 64 := Nat.mod_lt _ (by omega)
  show (toBits _)[n] = (HXor.hXor _ _ : Vector Bool b)[n]
  simp only [HXor.hXor]
  rw [Vector.getElem_zipWith, toBits_getElem' _ n hn, toBits_getElem' _ n hn,
      show w = 64 from rfl,
      projLane_toArray_getElem! rstate inst (n/64) hn64,
      projLane_toArray_getElem! sstate inst (n/64) hn64]
  have hh := hbit ⟨n/64, hn64⟩ ⟨n%64, hc64⟩
  simp only [show (64:Nat) * (n/64) + n%64 = n from by omega] at hh
  rw [hh]

end

/-- Bit `c` of a full lane-aligned 8-byte `from_le_bytes` window is the `c%8`-th
    bit of byte `data[a + c/8]`. -/
theorem fromLEBytes_extract_getLsbD (data : List U8) (a c : Nat)
    (hc : c < 64) (ha : a + 8 ≤ data.length) :
    ((BitVec.fromLEBytes ((data.extract a (a+8)).map U8.bv)).setWidth 64).getLsbD c
    = (data[a + c/8]!).bv.getLsbD (c % 8) := by
  have hlen : ((data.extract a (a+8)).map U8.bv).length = 8 := by
    simp only [List.length_map, List.length_take, List.length_drop]; omega
  have hge : (data.extract a (a+8))[c/8]! = data[a + c/8]! := by
    have hh : c/8 < 8 := by omega
    have he8 : a+8-a = 8 := by omega
    rw [List.extract_eq_take_drop, he8]; simp_lists
  rw [BitVec.getLsbD_setWidth]
  simp only [hc, decide_true, Bool.true_and]
  rw [BitVec.getLsbD_eq_getElem (h := by rw [hlen]; omega), ← BitVec.getElem!_eq_getElem,
      BitVec.fromLEBytes_getElem!]
  simp_lists [hge]
  rfl

/-- Bit `c` of `packBytes data offset byte_off m` is the `c%8`-th bit of byte
    `data[offset + (c/8 - byte_off)]`, nonzero only inside the packed byte
    window `[8·byte_off, 8·(byte_off+m))`.  The window fits in one 64-bit lane
    (`byte_off + m ≤ 8`), which all call sites satisfy. -/
theorem packBytes_getLsbD (data : List U8) (offset byte_off : Nat) :
    ∀ (m c : Nat) (h : offset + m ≤ data.length) (hb8 : byte_off + m ≤ 8),
    (Shake4x.packBytes data offset byte_off m h).bv.getLsbD c
    = (decide (8 * byte_off ≤ c ∧ c < 8 * (byte_off + m)) &&
       (data[offset + (c / 8 - byte_off)]!).bv.getLsbD (c % 8)) := by
  intro m
  induction m with
  | zero =>
    intro c h hb8
    have hz : (Shake4x.packBytes data offset byte_off 0 h).bv = 0#64 := by
      unfold Shake4x.packBytes; simp [Id.run]; rfl
    rw [hz]; simp only [BitVec.getLsbD_zero, Nat.add_zero]
    have : ¬ (8 * byte_off ≤ c ∧ c < 8 * byte_off) := by omega
    simp [this]
  | succ k ih =>
    intro c h hb8
    rw [Shake4x.packBytes_succ data offset byte_off k (by omega)]
    show (_ ||| _ : BitVec 64).getLsbD c = _
    rw [BitVec.getLsbD_or, ih c (by omega) (by omega),
        BitVec.getLsbD_shiftLeft, BitVec.getLsbD_setWidth]
    have hbr : data[offset + k]'(by omega) = data[offset + k]! :=
      List.Inhabited_getElem_eq_getElem! _ _ (by omega)
    rw [hbr]
    by_cases hmid : 8 * (byte_off + k) ≤ c ∧ c < 8 * (byte_off + k) + 8
    · -- c lands in byte k's window
      have hcd : c / 8 - byte_off = k := by omega
      have hcsub : c - 8 * (byte_off + k) = c % 8 := by omega
      have hr1 : decide (8 * byte_off ≤ c ∧ c < 8 * (byte_off + k)) = false := by
        simp only [decide_eq_false_iff_not]; omega
      have hr2 : decide (8 * byte_off ≤ c ∧ c < 8 * (byte_off + (k+1))) = true := by
        simp only [decide_eq_true_eq]; omega
      have hlt : decide (c < 8 * (byte_off + k)) = false := by
        simp only [decide_eq_false_iff_not]; omega
      have hc64 : c < 64 := by omega
      rw [hcd, hcsub, hr1, hr2, hlt]
      simp [hc64, show c % 8 < 64 from by omega]
    · -- c outside byte k's window: shifted byte contributes nothing; ranges agree
      have hshift : data[offset + k]!.bv.getLsbD (c - 8 * (byte_off + k)) = false ∨
          decide (c < 8 * (byte_off + k)) = true := by
        by_cases hge : 8 * (byte_off + k) ≤ c
        · left; exact BitVec.getLsbD_of_ge _ _ (by omega)
        · right; simp only [decide_eq_true_eq]; omega
      have hrange : decide (8 * byte_off ≤ c ∧ c < 8 * (byte_off + k))
          = decide (8 * byte_off ≤ c ∧ c < 8 * (byte_off + (k+1))) := by
        rcases hshift with hf | hlt
        · simp only [decide_eq_decide]; omega
        · simp only [decide_eq_true_eq] at hlt; simp only [decide_eq_decide]; omega
      rcases hshift with hf | hlt
      · rw [hf, hrange]; simp
      · rw [hlt, hrange]; simp

section
open Spec.SHA3 (b w KECCAK_f)
open scoped Spec.SHA3
open scoped Spec.Notations

local macro_rules
| `(tactic| get_elem_tactic) =>
  `(tactic| first | assumption | scalar_tac | (have := Fin.isLt ‹_›; scalar_tac) | grind)

/-- Local copy of the (private) `absorbBytes_no_permute`: within a single block
    (`idx + |data| < rate`) `absorbBytes` never permutes, so it is exactly the
    no-permute fold `absorbBytesRaw`. -/
private theorem absorbBytes_no_permute' (S : Vector Bool b) (idx rate : Nat)
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
    have hidx_ne : idx + 1 ≠ rate := by simp only [List.length_cons] at hbnd; omega
    simp only [hidx_ne, ↓reduceIte]
    have hbnd' : idx + 1 + rest.length < rate := by simp only [List.length_cons] at hbnd; omega
    rw [ih (absorbByte S idx byte) (idx + 1) hbnd']
    rw [show absorbBytesRaw S idx (byte :: rest) =
            absorbBytesRaw (absorbByte S idx byte) (idx + 1) rest from by
        rw [show (byte :: rest) = [byte] ++ rest from rfl,
            absorbBytesRaw_append, absorbBytesRaw_singleton,
            show idx + [byte].length = idx + 1 from rfl]]
    simp only [List.length_cons, Prod.mk.injEq, true_and]; omega

/-- **`absorbing` reconstruction (shared step for `append.spec`).**

    Given the structural effect of `Shake4x.append` on `result` (rate / buf
    frame, `absorbed` bumped at `inst`, `finalized = false`), plus the lane
    effect expressed two ways — every instance `k ≠ inst` framed
    (`hframe`), and instance `inst`'s projected lane bits XORed with
    `chunkBits old data` (`hlane`, in the exact shape consumed by
    `toBits_projectLane_xor`) — conclude that `result` is `absorbing` with
    instance `inst`'s ghost advanced by `append data`.

    `hlane` composes through `toBits_projectLane_xor` to give the spec
    `spongeInvariant`; the no-permute simplification (`hFit`) collapses
    `absorbBytes` of `old ++ data` to `S₀ ⊕ chunkBits old data`. -/
theorem Shake4x.append_absorbing_reconstruct
    (self result : sha3.shake4x.Shake4x) (inst : Std.Usize) (data : Slice Std.U8)
    (gs : Fin 4 → GhostState)
    (hAbs : Shake4x.absorbing self gs)
    (hInst : inst.val < 4)
    (hFit : self.absorbed[(⟨inst.val, hInst⟩ : Fin 4)].val + data.length < self.rate.val)
    (hrate : result.rate = self.rate)
    (hrate_lanes : result.rate_lanes = self.rate_lanes)
    (hfin : result.finalized = false)
    (habsorbed : result.absorbed = self.absorbed.set inst
        (Usize.ofNatCore (self.absorbed[(⟨inst.val, hInst⟩ : Fin 4)].val + data.length)
          (by have ⟨hWF, _⟩ := hAbs
              rcases hWF.1 with hr | hr <;> simp only [hr] at hFit ⊢ <;> scalar_tac)))
    (hframe : ∀ (k : Fin 4), k.val ≠ inst.val →
        Keccak4xHybrid.projectLane k result.state.state
          = Keccak4xHybrid.projectLane k self.state.state)
    (hlane : ∀ (m : Fin 25) (c : Fin 64),
        ((result.state.state.val[m.val]'(by have := m.isLt; scalar_tac)).val[inst.val]'(by
            have := (result.state.state.val[m.val]'(by have := m.isLt; scalar_tac)).property
            scalar_tac)).bv.getLsbD c.val
        = (((self.state.state.val[m.val]'(by have := m.isLt; scalar_tac)).val[inst.val]'(by
            have := (self.state.state.val[m.val]'(by have := m.isLt; scalar_tac)).property
            scalar_tac)).bv.getLsbD c.val
          ^^ (chunkBits (self.absorbed[(⟨inst.val, hInst⟩ : Fin 4)].val) data.val)[64 * m.val + c.val]'(by
            have := m.isLt; have := c.isLt; have : (b:Nat) = 1600 := rfl; omega))) :
    Shake4x.absorbing result
      (Function.update gs (⟨inst.val, hInst⟩ : Fin 4)
        ((gs (⟨inst.val, hInst⟩ : Fin 4)).append data.val false)) := by
  obtain ⟨hWFself, hNotFinSelf, hConsSelf, hPerSelf⟩ := hAbs
  set k' : Fin 4 := ⟨inst.val, hInst⟩ with hk'
  set old : Nat := self.absorbed[k'].val with hold
  have hi'lt : old + data.length < self.rate.val := hFit
  -- result is well-formed
  have hWFresult : Shake4x.WF result := by
    refine ⟨by rw [hrate]; exact hWFself.1, by rw [hrate, hrate_lanes]; exact hWFself.2.1, ?_⟩
    intro i
    have hb := hWFself.2.2 i
    simp only [Fin.getElem_fin] at hb
    rw [hrate]
    simp only [habsorbed, Fin.getElem_fin]
    rcases eq_or_ne i.val inst.val with hik | hik
    · rw [Aeneas.Std.Array.getElem_Nat_set_eq (h0 := by simp) (h1 := hik.symm)]
      simp only [Usize.ofNatCore_val_eq]
      have hbridge : (self.absorbed[inst.val]'(by scalar_tac)).val = old := by
        rw [hold]; rfl
      rw [hbridge]; exact hi'lt
    · rw [Aeneas.Std.Array.getElem_Nat_set_ne (h0 := by simp) (h1 := Ne.symm hik)]
      exact hb
  refine ⟨hWFresult, by rw [hfin]; exact Bool.not_eq_true _ ▸ rfl, ?_, ?_⟩
  · -- gsConsistent: `append` preserves rate/padVal, so reduces to hConsSelf
    intro i j
    have key : ∀ l, (Function.update gs k' ((gs k').append data.val false) l).rate = (gs l).rate ∧
        (Function.update gs k' ((gs k').append data.val false) l).padVal = (gs l).padVal := by
      intro l
      by_cases hl : l = k'
      · subst hl; simp [Function.update_self, GhostState.append]
      · simp [Function.update_of_ne hl]
    obtain ⟨hri, hpi⟩ := key i
    obtain ⟨hrj, hpj⟩ := key j
    obtain ⟨hr, hp⟩ := hConsSelf i j
    exact ⟨by rw [hri, hrj]; exact hr, by rw [hpi, hpj]; exact hp⟩
  · intro i
    by_cases hi : i = k'
    · subst hi
      -- i = inst: instance `inst`'s scalar view absorbs `data` (no permute by hFit)
      rw [Function.update_self]
      obtain ⟨hweak0, hsi0, hsponge0⟩ := hPerSelf k'
      obtain ⟨hle0, hnsq0, hibs0, hpad0, hsqz0⟩ := hweak0
      have hold_lt : old < self.rate.val := by rw [hold]; exact hWFself.2.2 k'
      -- ks0.state_index.val = old (= old % rate); S0 = toBits of the projected self lane
      have hidx0v : (toScalar self k' hWFself).state_index.val = old := by
        simp only [Shake4x.toScalar, UScalar.ofNatCore_val_eq]
        rw [← hold]; exact Nat.mod_eq_of_lt hold_lt
      have hrr : result.rate.val = self.rate.val := by rw [hrate]
      -- result.absorbed[k'] = old + data.length
      have hrabs : result.absorbed[k'].val = old + data.length := by
        simp only [habsorbed, Fin.getElem_fin]
        rw [Aeneas.Std.Array.getElem_Nat_set_eq (h0 := by scalar_tac) (h1 := rfl),
            Usize.ofNatCore_val_eq]
        simp only [hold, Fin.getElem_fin, hk']
      -- result-side toScalar field values
      have hksi : (toScalar result k' hWFresult).state_index.val = old + data.length := by
        simp only [Shake4x.toScalar, UScalar.ofNatCore_val_eq, hrabs, hrr,
          Nat.mod_eq_of_lt hi'lt]
      have hkibs : (toScalar result k' hWFresult).input_block_size.val = self.rate.val := by
        simp only [Shake4x.toScalar, UScalar.ofNatCore_val_eq, hrr]
      -- normalize the self-side facts through toScalar
      simp only [Shake4x.toScalar, UScalar.ofNatCore_val_eq] at hibs0 hpad0 hnsq0
      refine ⟨⟨?_, ?_, ?_, ?_, ?_⟩, ?_, ?_⟩
      · -- state_index ≤ ibs
        rw [show ((toScalar result k' hWFresult).state_index.val) = old + data.length from hksi,
            show ((toScalar result k' hWFresult).input_block_size.val) = self.rate.val from hkibs]
        scalar_tac
      · -- ¬ squeeze_mode
        simp only [Shake4x.toScalar, hfin, Bool.false_eq_true, not_false_iff]
      · -- input_block_size = g'.rate
        simp only [GhostState.append]
        rw [show ((toScalar result k' hWFresult).input_block_size) = _ from rfl]
        simp only [Shake4x.toScalar, UScalar.ofNatCore_val_eq, hrr]
        exact hibs0
      · -- padding_value = g'.padVal
        simp only [Shake4x.toScalar, GhostState.append]; exact hpad0
      · -- squeezed = []
        simp only [GhostState.append]; exact hsqz0
      · -- state_index < ibs
        rw [show ((toScalar result k' hWFresult).state_index.val) = old + data.length from hksi,
            show ((toScalar result k' hWFresult).input_block_size.val) = self.rate.val from hkibs]
        scalar_tac
      · -- spongeInvariant: toBits = S0 ⊕ chunkBits old data; state_index = old+len
        have htb : toBits (toScalar result k' hWFresult).state
            = toBits (toScalar self k' hWFself).state ⊕ chunkBits old data.val := by
          simp only [Shake4x.toScalar]
          exact toBits_projectLane_xor result.state.state self.state.state k'
            (chunkBits old data.val) hlane
        unfold sha3.sha3_impl.spongeInvariant at hsponge0 ⊢
        obtain ⟨htb0, hix0⟩ := hsponge0
        have hix0' : (absorbBytes (Vector.replicate b false) 0 (gs k').rate (gs k').absorbed).2
            = old := by rw [← hix0]; exact hidx0v
        have hbnd : (absorbBytes (Vector.replicate b false) 0 (gs k').rate (gs k').absorbed).2
            + data.val.length < (gs k').rate := by rw [hix0', ← hibs0]; exact hi'lt
        simp only [GhostState.append, Bool.false_eq_true, ↓reduceIte]
        rw [absorbBytes_append]
        generalize hP : absorbBytes (Vector.replicate b false) 0 (gs k').rate (gs k').absorbed = P
          at htb0 hix0' hbnd ⊢
        obtain ⟨S0, idx0⟩ := P
        simp only at htb0 hix0' hbnd ⊢
        rw [absorbBytes_no_permute' _ _ _ _ hbnd, absorbBytesRaw_eq_xor]
        refine ⟨?_, ?_⟩
        · rw [htb, htb0, hix0']
        · rw [hksi, hix0']
    · -- i ≠ inst: framed instance; toScalar unchanged ⇒ inherit hPerSelf i
      have hineq : i.val ≠ inst.val := by
        intro h; exact hi (Fin.ext (by simpa using h))
      rw [Function.update_of_ne hi]
      have hsf : self.finalized = false := by simpa using hNotFinSelf
      have h2 : result.absorbed[i] = self.absorbed[i] := by
        simp only [habsorbed, Fin.getElem_fin]
        rw [Aeneas.Std.Array.getElem_Nat_set_ne (h0 := by simp) (h1 := Ne.symm hineq)]
      have htoeq : toScalar result i hWFresult = toScalar self i hWFself := by
        unfold Shake4x.toScalar
        simp only [hframe i hineq, hrate, h2, hfin, hsf]
      rw [htoeq]; exact hPerSelf i

/-- **Sanity check / non-vacuity witness for `append_absorbing_reconstruct`.**
    Instantiating the reconstruction lemma with `result := self` and empty
    `data` must round-trip `absorbing self gs` back to itself (since
    `(gs k').append [] false = gs k'` and the `absorbed` bump is `+0`).  This
    exercises every branch of the reconstruction proof (WF, gsConsistent,
    framing, the full spongeInvariant) and fails if the statement is mis-shaped
    or its `hframe`/`hlane` hypotheses are unsatisfiable — concrete evidence the
    lemma is a genuine reduction, not a disguised copy of its conclusion. -/
private theorem append_absorbing_reconstruct_selfcheck
    (self : sha3.shake4x.Shake4x) (inst : Std.Usize) (data : Slice Std.U8)
    (gs : Fin 4 → GhostState) (hAbs : Shake4x.absorbing self gs) (hInst : inst.val < 4)
    (hempty : data.val = [])
    (hFit : self.absorbed[(⟨inst.val, hInst⟩ : Fin 4)].val + data.length < self.rate.val) :
    Shake4x.absorbing self
      (Function.update gs (⟨inst.val, hInst⟩ : Fin 4)
        ((gs (⟨inst.val, hInst⟩ : Fin 4)).append data.val false)) := by
  obtain ⟨hWF, hnf, hcons, hper⟩ := hAbs
  refine Shake4x.append_absorbing_reconstruct self self inst data gs
    ⟨hWF, hnf, hcons, hper⟩ hInst hFit rfl rfl (by simpa using hnf) ?_ (fun k _ => rfl) ?_
  · have hlen0 : data.length = 0 := by simp [Slice.length, hempty]
    have hv : (Usize.ofNatCore (self.absorbed[(⟨inst.val, hInst⟩ : Fin 4)].val + data.length)
        (by have ⟨hWF', _⟩ := (⟨hWF, hnf, hcons, hper⟩ : Shake4x.absorbing self gs)
            rcases hWF'.1 with hr | hr <;> simp only [hr] at hFit ⊢ <;> scalar_tac))
        = self.absorbed[(⟨inst.val, hInst⟩ : Fin 4)] := by
      apply UScalar.eq_of_val_eq
      simp only [Usize.ofNatCore_val_eq, hlen0, Nat.add_zero]
    rw [hv]; simp only [Fin.getElem_fin]
    exact (Aeneas.Std.Array.set_getElem_eq self.absorbed inst (by scalar_tac)).symm
  · intro m c
    have : (chunkBits (self.absorbed[(⟨inst.val, hInst⟩ : Fin 4)].val) data.val)[64 * m.val + c.val]'(by
        have := m.isLt; have := c.isLt; have : (b:Nat) = 1600 := rfl; omega) = false := by
      rw [hempty]; simp [chunkBits]
    rw [this]; simp

/-- **Frame helper.**  Two 4-way states whose `k`-th lane agrees at every
    slot project to the same `Lanes25`.  Used to lift the per-lane frame
    (instance `k ≠ inst` untouched by every `xor_lane`) to the
    `projectLane`-level `hframe` consumed by `append_absorbing_reconstruct`. -/
theorem Keccak4xHybrid.projectLane_congr (k : Fin 4)
    (rs ss : Std.Array sha3.keccak4x_hybrid.Lane4 25#usize)
    (h : ∀ m : Fin 25, (rs.val[m.val]'(by scalar_tac)).val[k.val]'(by
            have := (rs.val[m.val]'(by scalar_tac)).property; have := k.isLt; scalar_tac)
          = (ss.val[m.val]'(by scalar_tac)).val[k.val]'(by
            have := (ss.val[m.val]'(by scalar_tac)).property; have := k.isLt; scalar_tac)) :
    Keccak4xHybrid.projectLane k rs = Keccak4xHybrid.projectLane k ss := by
  apply Lanes25.ext_lane25
  intro n
  rw [Keccak4xHybrid.projectLane_lane25, Keccak4xHybrid.projectLane_lane25]
  exact h n

/-- **Lane bridge (full window).**  Bit `c` of a full lane-aligned 8-byte
    `from_le_bytes` window decoded at data offset `woff` equals the spec's
    `chunkBits old data` at absolute position `64·m + c`, given the alignment
    `8·woff + 8·old = 64·m` and the window lies fully inside `data`.  Used for
    the middle (full) lanes of every absorb branch. -/
theorem Shake4x.window_lane_eq_chunkBits (data : List U8) (pos m c woff : Nat)
    (hc : c < 64)
    (hrel : 8 * woff + 8 * pos = 64 * m)
    (hwfit : woff + 8 ≤ data.length)
    (hlb : 8 * pos ≤ 64 * m + c)
    (hub : 64 * m + c < 8 * pos + 8 * data.length)
    (hidx : 64 * m + c < b) :
    ((BitVec.fromLEBytes ((data.extract woff (woff + 8)).map U8.bv)).setWidth 64).getLsbD c
      = (chunkBits pos data)[64 * m + c]'hidx := by
  rw [fromLEBytes_extract_getLsbD data woff c hc hwfit,
      chunkBits_getElem pos (64 * m + c) data hidx]
  have hdec : decide (8 * pos ≤ 64 * m + c ∧ 64 * m + c < 8 * pos + 8 * data.length) = true := by
    simp only [decide_eq_true_eq]; exact ⟨hlb, hub⟩
  rw [hdec, Bool.true_and,
      show woff + c / 8 = (64 * m + c - 8 * pos) / 8 from by omega,
      show c % 8 = (64 * m + c - 8 * pos) % 8 from by omega]

/-- **Lane bridge (tail partial lane).**  Bit `c` of `packBytes data off 0 plen`
    (the final, lane-boundary-aligned partial lane, `byte_off = 0`, packing the
    `plen = |data| - off` trailing bytes) equals `chunkBits old data` at
    `64·m + c`, given the alignment `8·old + 8·off = 64·m`. -/
theorem Shake4x.packtail_lane_eq_chunkBits (data : List U8) (pos m c off plen : Nat)
    (hc : c < 64)
    (hb8 : plen ≤ 8)
    (hrel : 8 * pos + 8 * off = 64 * m)
    (hplen : plen = data.length - off)
    (hbound : off + plen ≤ data.length)
    (hidx : 64 * m + c < b) :
    (Shake4x.packBytes data off 0 plen hbound).bv.getLsbD c
      = (chunkBits pos data)[64 * m + c]'hidx := by
  rw [packBytes_getLsbD data off 0 plen c hbound (by omega),
      chunkBits_getElem pos (64 * m + c) data hidx]
  have hdeq : decide (8 * 0 ≤ c ∧ c < 8 * (0 + plen))
            = decide (8 * pos ≤ 64 * m + c ∧ 64 * m + c < 8 * pos + 8 * data.length) := by
    apply decide_eq_decide.mpr; omega
  rw [hdeq,
      show off + (c / 8 - 0) = (64 * m + c - 8 * pos) / 8 from by omega,
      show c % 8 = (64 * m + c - 8 * pos) % 8 from by omega]

/-- **Lane bridge (start partial lane).**  Bit `c` of `packBytes data 0 boff plen`
    (the first, unaligned partial lane, `off = 0`, packing `plen` bytes into byte
    positions `[boff, boff+plen)`) equals `chunkBits old data` at `64·m + c`,
    given `8·old = 64·m + 8·boff` and that the pack ends at either the data end
    or the lane boundary (`hcov`).  Used for the `byte_off ≠ 0` start lane. -/
theorem Shake4x.packstart_lane_eq_chunkBits (data : List U8) (pos m c boff plen : Nat)
    (hc : c < 64)
    (hb8 : boff + plen ≤ 8)
    (hrel : 8 * pos = 64 * m + 8 * boff)
    (hle : plen ≤ data.length)
    (hcov : plen = data.length ∨ boff + plen = 8)
    (hbound : 0 + plen ≤ data.length)
    (hidx : 64 * m + c < b) :
    (Shake4x.packBytes data 0 boff plen hbound).bv.getLsbD c
      = (chunkBits pos data)[64 * m + c]'hidx := by
  rw [packBytes_getLsbD data 0 boff plen c hbound hb8,
      chunkBits_getElem pos (64 * m + c) data hidx]
  have hdeq : decide (8 * boff ≤ c ∧ c < 8 * (boff + plen))
            = decide (8 * pos ≤ 64 * m + c ∧ 64 * m + c < 8 * pos + 8 * data.length) := by
    apply decide_eq_decide.mpr; omega
  rw [hdeq]
  by_cases hQ : 8 * pos ≤ 64 * m + c ∧ 64 * m + c < 8 * pos + 8 * data.length
  · obtain ⟨hlo, _⟩ := hQ
    rw [show 0 + (c / 8 - boff) = (64 * m + c - 8 * pos) / 8 from by omega,
        show c % 8 = (64 * m + c - 8 * pos) % 8 from by omega]
  · rw [decide_eq_false hQ]; simp

/-- **Lane bridge (framed lane).**  Bit `c` of `chunkBits old data` at an
    absolute position `64·m + c` outside the absorbed byte range `[8·old,
    8·old + 8·|data|)` is `false` — so a framed (untouched) lane keeps its
    self value (`self bit ^^ false`). -/
theorem Shake4x.chunkBits_lane_zero (data : List U8) (pos m c : Nat)
    (hout : 64 * m + c < 8 * pos ∨ 8 * pos + 8 * data.length ≤ 64 * m + c)
    (hidx : 64 * m + c < b) :
    (chunkBits pos data)[64 * m + c]'hidx = false := by
  rw [chunkBits_getElem pos (64 * m + c) data hidx]
  have : decide (8 * pos ≤ 64 * m + c ∧ 64 * m + c < 8 * pos + 8 * data.length) = false := by
    apply decide_eq_false_iff_not.mpr; omega
  rw [this, Bool.false_and]

/-- `U64_BYTES = 8` for the solvers (the extracted constant is irreducible). -/
@[local simp, local scalar_tac_simps, local agrind =, local grind =]
theorem Shake4x.U64_BYTES_val : sha3.shake4x.U64_BYTES.val = 8 := by
  simp [sha3.shake4x.U64_BYTES]

/-- `byte_off = 0` from the aligned-branch guard (small context, avoids `simp` loops). -/
theorem Shake4x.byte_off_zero (x : Std.Usize) (h : ¬ (x != 0#usize) = true) : x.val = 0 := by
  simp only [bne_iff_ne, ne_eq, Decidable.not_not] at h; simp [h]

/-- `min a b ≤ a` for `OrdUsize.min` (small context, avoids `simp_all` loops). -/
theorem Shake4x.ordUsize_min_le_left (a b : Std.Usize) :
    (core.cmp.impls.OrdUsize.min a b).val ≤ a.val := by
  unfold core.cmp.impls.OrdUsize.min; split <;> simp_all

/-- `min a b ≤ b` for `OrdUsize.min` (small context). -/
theorem Shake4x.ordUsize_min_le_right (a b : Std.Usize) :
    (core.cmp.impls.OrdUsize.min a b).val ≤ b.val := by
  unfold core.cmp.impls.OrdUsize.min; split <;> scalar_tac

/-- `min a b` is `a` or `b` for `OrdUsize.min` (small context). -/
theorem Shake4x.ordUsize_min_cases (a b : Std.Usize) :
    (core.cmp.impls.OrdUsize.min a b).val = a.val ∨ (core.cmp.impls.OrdUsize.min a b).val = b.val := by
  unfold core.cmp.impls.OrdUsize.min; split <;> simp_all

/-- Structural `absorbed`-conjunct: the final `absorbed` array equals `self.absorbed`
    with slot `inst` bumped to `old + |data|` (proven in a small context to avoid the
    big-context `simp`/`rw` loops that arise inside the `append` body proof). -/
theorem Shake4x.abs_set_eq (self : sha3.shake4x.Shake4x) (inst i7 pos : Std.Usize)
    (data : Slice U8) (a : Std.Array Std.Usize 4#usize) (hInst : inst.val < 4)
    (a_post : a = self.absorbed.set inst i7)
    (i7_post : i7.val = pos.val + data.len.val)
    (hold : self.absorbed[(⟨inst.val, hInst⟩ : Fin 4)].val = pos.val)
    (hb : self.absorbed[(⟨inst.val, hInst⟩ : Fin 4)].val + data.length < Std.Usize.max) :
    a = self.absorbed.set inst
      (Usize.ofNatCore (self.absorbed[(⟨inst.val, hInst⟩ : Fin 4)].val + data.length)
        (by scalar_tac)) := by
  rw [a_post]; congr 1; apply UScalar.eq_of_val_eq
  rw [Usize.ofNatCore_val_eq, i7_post, hold]; scalar_tac

/-- Frame lemma for the tail branches: every `xor_lane` only touches instance `inst`,
    so the main loop's frame (`kxh_post3`) plus the tail `xor_lane` (`kxh2_post`) leave
    `projectLane k` unchanged for every `k ≠ inst`. -/
theorem Shake4x.tail_hframe
    (S K K2 : Std.Array sha3.keccak4x_hybrid.Lane4 25#usize)
    (inst lane_idx lane_idx1 : Std.Usize) (v : U64) (N : Nat) (hInst : inst.val < 4)
    (kxh_post3 : ∀ (p : Fin 25) (k : Fin 4),
        ¬(lane_idx.val ≤ p.val ∧ p.val < lane_idx.val + N ∧ k.val = inst.val) →
        (↑(K[p]) : List U64)[k.val]'(by have := (K[p]).property; have := k.isLt; scalar_tac)
          = (↑(S[p]) : List U64)[k.val]'(by have := (S[p]).property; have := k.isLt; scalar_tac))
    (kxh2_post : ∀ (p : Fin 25) (k : Fin 4),
        (↑(K2[p]) : List U64)[k.val]'(by have := (K2[p]).property; have := k.isLt; scalar_tac)
          = if p.val = lane_idx1.val ∧ k.val = inst.val then
              (↑(K[p]) : List U64)[k.val]'(by have := (K[p]).property; have := k.isLt; scalar_tac) ^^^ v
            else (↑(K[p]) : List U64)[k.val]'(by have := (K[p]).property; have := k.isLt; scalar_tac)) :
    ∀ (k : Fin 4), k.val ≠ inst.val →
      Keccak4xHybrid.projectLane k K2 = Keccak4xHybrid.projectLane k S := by
  intro k hk
  apply Keccak4xHybrid.projectLane_congr
  intro m
  have hk2 := kxh2_post m k
  rw [if_neg (by rintro ⟨_, h2⟩; exact hk h2)] at hk2
  exact hk2.trans (kxh_post3 m k (by rintro ⟨_, _, h3⟩; exact hk h3))

set_option maxHeartbeats 1000000 in
/-- Per-bit lane reconstruction for the `byte_off = 0` (aligned) tail branch:
    composing the main loop (`kxh_post3` frame + `kxh_post4` full-window mutation) and
    the tail `xor_lane`/pack (`kxh2_post`, `v_post`), every lane-`inst` bit of the final
    state equals its `self` value XOR `chunkBits old data` at the absolute position. -/
theorem Shake4x.aligned_tail_hlane
    (S K K2 : Std.Array sha3.keccak4x_hybrid.Lane4 25#usize)
    (inst lane_idx lane_idx1 offset i4 : Std.Usize) (v : U64) (data : Slice U8)
    (old N : Nat) (hInst : inst.val < 4)
    (hold8 : old = 8 * lane_idx.val)
    (hN : N = (data.length - 0) / 8)
    (hlane_idx1 : lane_idx1.val = lane_idx.val + N)
    (hoffset : offset.val = 0 + 8 * N)
    (hi4 : i4.val = data.len.val - offset.val)
    (hoff_lt : offset.val < data.length)
    (kxh_post3 : ∀ (p : Fin 25) (k : Fin 4),
        ¬(lane_idx.val ≤ p.val ∧ p.val < lane_idx.val + N ∧ k.val = inst.val) →
        (↑(K[p]) : List U64)[k.val]'(by have := (K[p]).property; have := k.isLt; scalar_tac)
          = (↑(S[p]) : List U64)[k.val]'(by have := (S[p]).property; have := k.isLt; scalar_tac))
    (kxh_post4 : ∀ (j : ℕ), lane_idx.val ≤ j → j < lane_idx.val + N → ∀ (hp : j < 25),
        (↑(K[(⟨j, hp⟩ : Fin 25)]) : List U64)[inst.val]'(by
            have := (K[(⟨j, hp⟩ : Fin 25)]).property; scalar_tac)
          = (↑(S[(⟨j, hp⟩ : Fin 25)]) : List U64)[inst.val]'(by
            have := (S[(⟨j, hp⟩ : Fin 25)]).property; scalar_tac)
          ^^^ ⟨(BitVec.fromLEBytes ((data.val.extract (0 + 8 * (j - lane_idx.val))
                (0 + 8 * (j - lane_idx.val) + 8)).map U8.bv)).setWidth 64⟩)
    (kxh2_post : ∀ (p : Fin 25) (k : Fin 4),
        (↑(K2[p]) : List U64)[k.val]'(by have := (K2[p]).property; have := k.isLt; scalar_tac)
          = if p.val = lane_idx1.val ∧ k.val = inst.val then
              (↑(K[p]) : List U64)[k.val]'(by have := (K[p]).property; have := k.isLt; scalar_tac) ^^^ v
            else (↑(K[p]) : List U64)[k.val]'(by have := (K[p]).property; have := k.isLt; scalar_tac))
    (hbnd4 : offset.val + i4.val ≤ data.length)
    (v_post : v.bv = U64.bv 0#u64 ||| (Shake4x.packBytes data.val offset.val 0 i4.val hbnd4).bv
                &&& ~~~ (Shake4x.packBytes data.val offset.val 0 0 (by scalar_tac)).bv) :
    ∀ (m : Fin 25) (c : Fin 64),
      ((↑(K2[m]) : List U64)[inst.val]'(by have := (K2[m]).property; scalar_tac)).bv.getLsbD c.val
      = ((((↑(S[m]) : List U64)[inst.val]'(by have := (S[m]).property; scalar_tac)).bv.getLsbD c.val)
        ^^ (chunkBits old data.val)[64 * m.val + c.val]'(by
            have := m.isLt; have := c.isLt; have : (b:Nat) = 1600 := rfl; omega)) := by
  intro m c
  have hdl : data.length = data.val.length := rfl
  have hdll : data.len.val = data.length := rfl
  have hidx : 64 * m.val + c.val < b := by
    have := m.isLt; have := c.isLt; have : (b:Nat) = 1600 := rfl; omega
  have hk2 := kxh2_post m ⟨inst.val, hInst⟩
  simp only [and_true] at hk2
  by_cases hm1 : m.val = lane_idx1.val
  · -- tail (partial) lane
    rw [if_pos hm1] at hk2
    have hframe := kxh_post3 m ⟨inst.val, hInst⟩ (by rintro ⟨_, h2, _⟩; omega)
    simp only [] at hframe
    rw [hframe] at hk2
    have hvchunk : v.bv.getLsbD c.val = (chunkBits old data.val)[64 * m.val + c.val]'hidx := by
      have hz : (U64.bv 0#u64).getLsbD c.val = false := by simp
      have hv0 : (Shake4x.packBytes data.val offset.val 0 0 (by omega)).bv.getLsbD c.val = false := by
        have hz : (Shake4x.packBytes data.val offset.val 0 0 (by omega)).bv = 0#64 := by
          unfold Shake4x.packBytes; simp [Id.run]; rfl
        rw [hz]; simp
      rw [v_post]
      simp only [BitVec.getLsbD_or, BitVec.getLsbD_and, BitVec.getLsbD_not, hv0, hz,
        Bool.not_false, Bool.and_true, Bool.false_or,
        decide_eq_true c.isLt]
      rw [Shake4x.packtail_lane_eq_chunkBits data.val old m.val c.val offset.val i4.val
        c.isLt (by omega) (by omega) (by omega) hbnd4 hidx]
    rw [hk2]
    simp only [UScalar.bv_xor, BitVec.getLsbD_xor, hvchunk]
  · -- not the tail lane
    rw [if_neg hm1] at hk2
    rw [hk2]
    by_cases hmid : lane_idx.val ≤ m.val ∧ m.val < lane_idx.val + N
    · -- middle (full) lane
      obtain ⟨hlo, hhi⟩ := hmid
      have hk4 : (↑(K[m]) : List U64)[inst.val]'(by have := (K[m]).property; scalar_tac)
          = (↑(S[m]) : List U64)[inst.val]'(by have := (S[m]).property; scalar_tac)
            ^^^ ⟨(BitVec.fromLEBytes ((data.val.extract (0 + 8 * (m.val - lane_idx.val))
                  (0 + 8 * (m.val - lane_idx.val) + 8)).map U8.bv)).setWidth 64⟩ :=
        kxh_post4 m.val hlo hhi m.isLt
      have hwchunk : (⟨(BitVec.fromLEBytes ((data.val.extract (0 + 8 * (m.val - lane_idx.val))
            (0 + 8 * (m.val - lane_idx.val) + 8)).map U8.bv)).setWidth 64⟩ : U64).bv.getLsbD c.val
          = (chunkBits old data.val)[64 * m.val + c.val]'hidx :=
        Shake4x.window_lane_eq_chunkBits data.val old m.val c.val (0 + 8 * (m.val - lane_idx.val))
          c.isLt (by omega) (by omega) (by omega) (by omega) hidx
      rw [hk4]
      simp only [UScalar.bv_xor, BitVec.getLsbD_xor, hwchunk]
    · -- framed lane
      have hframe := kxh_post3 m ⟨inst.val, hInst⟩ (by rintro ⟨h1, h2, _⟩; exact hmid ⟨h1, h2⟩)
      simp only [] at hframe
      rw [hframe, Shake4x.chunkBits_lane_zero data.val old m.val c.val (by omega) hidx]; simp

/-- Frame lemma for the no-tail branches: the main loop (`kxh_post3`) only touches
    instance `inst`, so `projectLane k` is unchanged for every `k ≠ inst`. -/
theorem Shake4x.loop_hframe
    (S K : Std.Array sha3.keccak4x_hybrid.Lane4 25#usize) (inst lane_idx : Std.Usize)
    (N : Nat) (hInst : inst.val < 4)
    (kxh_post3 : ∀ (p : Fin 25) (k : Fin 4),
        ¬(lane_idx.val ≤ p.val ∧ p.val < lane_idx.val + N ∧ k.val = inst.val) →
        (↑(K[p]) : List U64)[k.val]'(by have := (K[p]).property; have := k.isLt; scalar_tac)
          = (↑(S[p]) : List U64)[k.val]'(by have := (S[p]).property; have := k.isLt; scalar_tac)) :
    ∀ (k : Fin 4), k.val ≠ inst.val →
      Keccak4xHybrid.projectLane k K = Keccak4xHybrid.projectLane k S := by
  intro k hk
  apply Keccak4xHybrid.projectLane_congr
  intro m
  exact kxh_post3 m k (by rintro ⟨_, _, h3⟩; exact hk h3)

set_option maxHeartbeats 1000000 in
/-- Per-bit lane reconstruction for the `byte_off = 0` (aligned) no-tail branch:
    `data` is a whole number of 8-byte lanes (`data.length = 8·N`), so every absorbed
    lane is a full window (`kxh_post4`) and all others are framed (`kxh_post3`). -/
theorem Shake4x.aligned_notail_hlane
    (S K : Std.Array sha3.keccak4x_hybrid.Lane4 25#usize)
    (inst lane_idx : Std.Usize) (data : Slice U8)
    (old N : Nat) (hInst : inst.val < 4)
    (hold8 : old = 8 * lane_idx.val)
    (hdata8 : data.length = 8 * N)
    (kxh_post3 : ∀ (p : Fin 25) (k : Fin 4),
        ¬(lane_idx.val ≤ p.val ∧ p.val < lane_idx.val + N ∧ k.val = inst.val) →
        (↑(K[p]) : List U64)[k.val]'(by have := (K[p]).property; have := k.isLt; scalar_tac)
          = (↑(S[p]) : List U64)[k.val]'(by have := (S[p]).property; have := k.isLt; scalar_tac))
    (kxh_post4 : ∀ (j : ℕ), lane_idx.val ≤ j → j < lane_idx.val + N → ∀ (hp : j < 25),
        (↑(K[(⟨j, hp⟩ : Fin 25)]) : List U64)[inst.val]'(by
            have := (K[(⟨j, hp⟩ : Fin 25)]).property; scalar_tac)
          = (↑(S[(⟨j, hp⟩ : Fin 25)]) : List U64)[inst.val]'(by
            have := (S[(⟨j, hp⟩ : Fin 25)]).property; scalar_tac)
          ^^^ ⟨(BitVec.fromLEBytes ((data.val.extract (0 + 8 * (j - lane_idx.val))
                (0 + 8 * (j - lane_idx.val) + 8)).map U8.bv)).setWidth 64⟩) :
    ∀ (m : Fin 25) (c : Fin 64),
      ((↑(K[m]) : List U64)[inst.val]'(by have := (K[m]).property; scalar_tac)).bv.getLsbD c.val
      = ((((↑(S[m]) : List U64)[inst.val]'(by have := (S[m]).property; scalar_tac)).bv.getLsbD c.val)
        ^^ (chunkBits old data.val)[64 * m.val + c.val]'(by
            have := m.isLt; have := c.isLt; have : (b:Nat) = 1600 := rfl; omega)) := by
  intro m c
  have hdl : data.length = data.val.length := rfl
  have hidx : 64 * m.val + c.val < b := by
    have := m.isLt; have := c.isLt; have : (b:Nat) = 1600 := rfl; omega
  by_cases hmid : lane_idx.val ≤ m.val ∧ m.val < lane_idx.val + N
  · -- full lane
    obtain ⟨hlo, hhi⟩ := hmid
    have hk4 : (↑(K[m]) : List U64)[inst.val]'(by have := (K[m]).property; scalar_tac)
        = (↑(S[m]) : List U64)[inst.val]'(by have := (S[m]).property; scalar_tac)
          ^^^ ⟨(BitVec.fromLEBytes ((data.val.extract (0 + 8 * (m.val - lane_idx.val))
                (0 + 8 * (m.val - lane_idx.val) + 8)).map U8.bv)).setWidth 64⟩ :=
      kxh_post4 m.val hlo hhi m.isLt
    have hwchunk : (⟨(BitVec.fromLEBytes ((data.val.extract (0 + 8 * (m.val - lane_idx.val))
          (0 + 8 * (m.val - lane_idx.val) + 8)).map U8.bv)).setWidth 64⟩ : U64).bv.getLsbD c.val
        = (chunkBits old data.val)[64 * m.val + c.val]'hidx :=
      Shake4x.window_lane_eq_chunkBits data.val old m.val c.val (0 + 8 * (m.val - lane_idx.val))
        c.isLt (by omega) (by omega) (by omega) (by omega) hidx
    rw [hk4]
    simp only [UScalar.bv_xor, BitVec.getLsbD_xor, hwchunk]
  · -- framed lane
    have hframe := kxh_post3 m ⟨inst.val, hInst⟩ (by rintro ⟨h1, h2, _⟩; exact hmid ⟨h1, h2⟩)
    simp only [] at hframe
    rw [hframe, Shake4x.chunkBits_lane_zero data.val old m.val c.val (by omega) hidx]; simp

/-- Strip the `0 ||| P &&& ~~~Q₀` wrapper that `append_loop{0,2,4}` produce for the
    partial-lane accumulator, given the `Q₀` bit is zero (it is `packBytes … 0`). -/
theorem Shake4x.vbit_eq (v : U64) (P Q0 : BitVec 64) (c : Nat) (hc : c < 64)
    (v_post : v.bv = U64.bv 0#u64 ||| P &&& ~~~ Q0) (hQ0 : Q0.getLsbD c = false) :
    v.bv.getLsbD c = P.getLsbD c := by
  rw [v_post]
  have hz : (U64.bv 0#u64).getLsbD c = false := by simp
  simp only [BitVec.getLsbD_or, BitVec.getLsbD_and, BitVec.getLsbD_not, hQ0, hc, hz,
    Bool.not_false, Bool.and_true, decide_true, Bool.false_or]

/-- `packBytes … 0` (zero bytes packed) is the all-zero bit-vector. -/
theorem Shake4x.packBytes_zero_bit (data : List U8) (off boff c : Nat) (h : off + 0 ≤ data.length) :
    (Shake4x.packBytes data off boff 0 h).bv.getLsbD c = false := by
  have hz : (Shake4x.packBytes data off boff 0 h).bv = 0#64 := by
    unfold Shake4x.packBytes; simp [Id.run]; rfl
  rw [hz]; simp

/-- Frame lemma for the unaligned tail branch: composing the start `xor_lane`
    (`kxh_post`), the main loop frame (`kxh1_post3`) and the tail `xor_lane`
    (`kxh2_post`), `projectLane k` is unchanged for every `k ≠ inst`. -/
theorem Shake4x.unaligned_tail_hframe
    (S K K1 K2 : Std.Array sha3.keccak4x_hybrid.Lane4 25#usize)
    (inst lane_idx lane_idx1 lane_idx2 : Std.Usize) (v v1 : U64) (N1 : Nat) (hInst : inst.val < 4)
    (kxh_post : ∀ (p : Fin 25) (k : Fin 4),
        (↑(K[p]) : List U64)[k.val]'(by have := (K[p]).property; have := k.isLt; scalar_tac)
          = if p.val = lane_idx.val ∧ k.val = inst.val then
              (↑(S[p]) : List U64)[k.val]'(by have := (S[p]).property; have := k.isLt; scalar_tac) ^^^ v
            else (↑(S[p]) : List U64)[k.val]'(by have := (S[p]).property; have := k.isLt; scalar_tac))
    (kxh1_post3 : ∀ (p : Fin 25) (k : Fin 4),
        ¬(lane_idx1.val ≤ p.val ∧ p.val < lane_idx1.val + N1 ∧ k.val = inst.val) →
        (↑(K1[p]) : List U64)[k.val]'(by have := (K1[p]).property; have := k.isLt; scalar_tac)
          = (↑(K[p]) : List U64)[k.val]'(by have := (K[p]).property; have := k.isLt; scalar_tac))
    (kxh2_post : ∀ (p : Fin 25) (k : Fin 4),
        (↑(K2[p]) : List U64)[k.val]'(by have := (K2[p]).property; have := k.isLt; scalar_tac)
          = if p.val = lane_idx2.val ∧ k.val = inst.val then
              (↑(K1[p]) : List U64)[k.val]'(by have := (K1[p]).property; have := k.isLt; scalar_tac) ^^^ v1
            else (↑(K1[p]) : List U64)[k.val]'(by have := (K1[p]).property; have := k.isLt; scalar_tac)) :
    ∀ (k : Fin 4), k.val ≠ inst.val →
      Keccak4xHybrid.projectLane k K2 = Keccak4xHybrid.projectLane k S := by
  intro k hk
  apply Keccak4xHybrid.projectLane_congr
  intro m
  have h2 := kxh2_post m k
  rw [if_neg (by rintro ⟨_, h⟩; exact hk h)] at h2
  have h1 := kxh1_post3 m k (by rintro ⟨_, _, h⟩; exact hk h)
  have h0 := kxh_post m k
  rw [if_neg (by rintro ⟨_, h⟩; exact hk h)] at h0
  exact h2.trans (h1.trans h0)

set_option maxHeartbeats 2000000 in
/-- Per-bit lane reconstruction for the `byte_off ≠ 0` (unaligned) tail branch:
    three contributions — a start partial lane (`v` = `packBytes … byte_off`, completing
    the lane to its boundary), the main loop's full middle lanes, and a tail partial lane
    (`v1` = `packBytes … 0`).  All three compose to `chunkBits old data`. -/
theorem Shake4x.unaligned_tail_hlane
    (S K K1 K2 : Std.Array sha3.keccak4x_hybrid.Lane4 25#usize)
    (inst lane_idx lane_idx1 lane_idx2 byte_off take offset offset1 i5 : Std.Usize)
    (v v1 : U64) (data : Slice U8)
    (old N1 : Nat) (hInst : inst.val < 4)
    (hbo1 : 1 ≤ byte_off.val) (hbo8 : byte_off.val < 8)
    (htake : take.val = 8 - byte_off.val)
    (hold : old = 8 * lane_idx.val + byte_off.val)
    (hoff : offset.val = take.val) (hoffle : offset.val ≤ data.val.length)
    (hlane1 : lane_idx1.val = lane_idx.val + 1)
    (hlane2 : lane_idx2.val = lane_idx1.val + N1)
    (hoffset1 : offset1.val = offset.val + 8 * N1)
    (hi5 : i5.val = data.val.length - offset1.val)
    (hN1le : 8 * N1 ≤ data.val.length - offset.val)
    (hrem : data.val.length - offset1.val < 8)
    (hoffset1le : offset1.val ≤ data.val.length)
    (kxh_post : ∀ (p : Fin 25) (k : Fin 4),
        (↑(K[p]) : List U64)[k.val]'(by have := (K[p]).property; have := k.isLt; scalar_tac)
          = if p.val = lane_idx.val ∧ k.val = inst.val then
              (↑(S[p]) : List U64)[k.val]'(by have := (S[p]).property; have := k.isLt; scalar_tac) ^^^ v
            else (↑(S[p]) : List U64)[k.val]'(by have := (S[p]).property; have := k.isLt; scalar_tac))
    (hv_bnd : 0 + take.val ≤ data.val.length)
    (v_post : v.bv = U64.bv 0#u64 ||| (Shake4x.packBytes data.val 0 byte_off.val take.val (by omega)).bv
                &&& ~~~ (Shake4x.packBytes data.val 0 byte_off.val 0 (by omega)).bv)
    (kxh1_post3 : ∀ (p : Fin 25) (k : Fin 4),
        ¬(lane_idx1.val ≤ p.val ∧ p.val < lane_idx1.val + N1 ∧ k.val = inst.val) →
        (↑(K1[p]) : List U64)[k.val]'(by have := (K1[p]).property; have := k.isLt; scalar_tac)
          = (↑(K[p]) : List U64)[k.val]'(by have := (K[p]).property; have := k.isLt; scalar_tac))
    (kxh1_post4 : ∀ (j : ℕ), lane_idx1.val ≤ j → j < lane_idx1.val + N1 → ∀ (hp : j < 25),
        (↑(K1[(⟨j, hp⟩ : Fin 25)]) : List U64)[inst.val]'(by
            have := (K1[(⟨j, hp⟩ : Fin 25)]).property; scalar_tac)
          = (↑(K[(⟨j, hp⟩ : Fin 25)]) : List U64)[inst.val]'(by
            have := (K[(⟨j, hp⟩ : Fin 25)]).property; scalar_tac)
          ^^^ ⟨(BitVec.fromLEBytes ((data.val.extract (offset.val + 8 * (j - lane_idx1.val))
                (offset.val + 8 * (j - lane_idx1.val) + 8)).map U8.bv)).setWidth 64⟩)
    (kxh2_post : ∀ (p : Fin 25) (k : Fin 4),
        (↑(K2[p]) : List U64)[k.val]'(by have := (K2[p]).property; have := k.isLt; scalar_tac)
          = if p.val = lane_idx2.val ∧ k.val = inst.val then
              (↑(K1[p]) : List U64)[k.val]'(by have := (K1[p]).property; have := k.isLt; scalar_tac) ^^^ v1
            else (↑(K1[p]) : List U64)[k.val]'(by have := (K1[p]).property; have := k.isLt; scalar_tac))
    (hv1_bnd : offset1.val + 0 ≤ data.val.length)
    (v1_post : v1.bv = U64.bv 0#u64 ||| (Shake4x.packBytes data.val offset1.val 0 i5.val (by omega)).bv
                &&& ~~~ (Shake4x.packBytes data.val offset1.val 0 0 (by omega)).bv) :
    ∀ (m : Fin 25) (c : Fin 64),
      ((↑(K2[m]) : List U64)[inst.val]'(by have := (K2[m]).property; scalar_tac)).bv.getLsbD c.val
      = ((((↑(S[m]) : List U64)[inst.val]'(by have := (S[m]).property; scalar_tac)).bv.getLsbD c.val)
        ^^ (chunkBits old data.val)[64 * m.val + c.val]'(by
            have := m.isLt; have := c.isLt; have : (b:Nat) = 1600 := rfl; omega)) := by
  intro m c
  have hdl : data.length = data.val.length := rfl
  have hidx : 64 * m.val + c.val < b := by
    have := m.isLt; have := c.isLt; have : (b:Nat) = 1600 := rfl; omega
  have hk2 := kxh2_post m ⟨inst.val, hInst⟩
  simp only [and_true] at hk2
  have hkS := kxh_post m ⟨inst.val, hInst⟩
  simp only [and_true] at hkS
  by_cases hm2 : m.val = lane_idx2.val
  · -- tail (partial) lane
    rw [if_pos hm2] at hk2
    have hk1 := kxh1_post3 m ⟨inst.val, hInst⟩ (by simp only []; rintro ⟨_, h2, _⟩; omega)
    simp only [] at hk1
    have hkSm : (↑(K[m]) : List U64)[inst.val]'(by have := (K[m]).property; scalar_tac)
        = (↑(S[m]) : List U64)[inst.val]'(by have := (S[m]).property; scalar_tac) := by
      rw [hkS, if_neg (by omega)]
    rw [hk1, hkSm] at hk2
    have hv1c : v1.bv.getLsbD c.val = (chunkBits old data.val)[64 * m.val + c.val]'hidx := by
      rw [Shake4x.vbit_eq v1 _ _ c.val c.isLt v1_post
        (Shake4x.packBytes_zero_bit data.val offset1.val 0 c.val (by omega))]
      exact Shake4x.packtail_lane_eq_chunkBits data.val old m.val c.val offset1.val i5.val
        c.isLt (by omega) (by omega) (by omega) (by omega) hidx
    rw [hk2]; simp only [UScalar.bv_xor, BitVec.getLsbD_xor, hv1c]
  · rw [if_neg hm2] at hk2
    rw [hk2]
    by_cases hmid : lane_idx1.val ≤ m.val ∧ m.val < lane_idx1.val + N1
    · -- middle (full) lane
      obtain ⟨hlo, hhi⟩ := hmid
      have hk1 : (↑(K1[m]) : List U64)[inst.val]'(by have := (K1[m]).property; scalar_tac)
          = (↑(K[m]) : List U64)[inst.val]'(by have := (K[m]).property; scalar_tac)
            ^^^ ⟨(BitVec.fromLEBytes ((data.val.extract (offset.val + 8 * (m.val - lane_idx1.val))
                  (offset.val + 8 * (m.val - lane_idx1.val) + 8)).map U8.bv)).setWidth 64⟩ :=
        kxh1_post4 m.val hlo hhi m.isLt
      have hkSm : (↑(K[m]) : List U64)[inst.val]'(by have := (K[m]).property; scalar_tac)
          = (↑(S[m]) : List U64)[inst.val]'(by have := (S[m]).property; scalar_tac) := by
        rw [hkS, if_neg (by omega)]
      have hwc : (⟨(BitVec.fromLEBytes ((data.val.extract (offset.val + 8 * (m.val - lane_idx1.val))
            (offset.val + 8 * (m.val - lane_idx1.val) + 8)).map U8.bv)).setWidth 64⟩ : U64).bv.getLsbD c.val
          = (chunkBits old data.val)[64 * m.val + c.val]'hidx :=
        Shake4x.window_lane_eq_chunkBits data.val old m.val c.val (offset.val + 8 * (m.val - lane_idx1.val))
          c.isLt (by omega) (by omega) (by omega) (by omega) hidx
      rw [hk1, hkSm]; simp only [UScalar.bv_xor, BitVec.getLsbD_xor, hwc]
    · -- start lane or framed
      have hk1 := kxh1_post3 m ⟨inst.val, hInst⟩ (by
        simp only []; rintro ⟨h1, h2, _⟩; exact hmid ⟨h1, h2⟩)
      simp only [] at hk1
      rw [hk1]
      by_cases hms : m.val = lane_idx.val
      · -- start (partial) lane
        rw [hkS, if_pos hms]
        have hvc : v.bv.getLsbD c.val = (chunkBits old data.val)[64 * m.val + c.val]'hidx := by
          rw [Shake4x.vbit_eq v _ _ c.val c.isLt v_post
            (Shake4x.packBytes_zero_bit data.val 0 byte_off.val c.val (by omega))]
          exact Shake4x.packstart_lane_eq_chunkBits data.val old m.val c.val byte_off.val take.val
            c.isLt (by omega) (by omega) (by omega) (Or.inr (by omega)) (by omega) hidx
        simp only [UScalar.bv_xor, BitVec.getLsbD_xor, hvc]
      · -- framed lane
        rw [hkS, if_neg (by omega),
          Shake4x.chunkBits_lane_zero data.val old m.val c.val (by omega) hidx]; simp

/-- Frame lemma for the unaligned no-tail branches (`take ≠ remaining`, or
    `take = remaining` with `offset1 ≥ |data|`): composing the start `xor_lane`
    (`kxh_post`) and the main loop frame (`kxh1_post3`), `projectLane k` is
    unchanged for every `k ≠ inst`. -/
theorem Shake4x.unaligned_notail_hframe
    (S K K1 : Std.Array sha3.keccak4x_hybrid.Lane4 25#usize)
    (inst lane_idx lane_idx1 : Std.Usize) (v : U64) (N1 : Nat) (hInst : inst.val < 4)
    (kxh_post : ∀ (p : Fin 25) (k : Fin 4),
        (↑(K[p]) : List U64)[k.val]'(by have := (K[p]).property; have := k.isLt; scalar_tac)
          = if p.val = lane_idx.val ∧ k.val = inst.val then
              (↑(S[p]) : List U64)[k.val]'(by have := (S[p]).property; have := k.isLt; scalar_tac) ^^^ v
            else (↑(S[p]) : List U64)[k.val]'(by have := (S[p]).property; have := k.isLt; scalar_tac))
    (kxh1_post3 : ∀ (p : Fin 25) (k : Fin 4),
        ¬(lane_idx1.val ≤ p.val ∧ p.val < lane_idx1.val + N1 ∧ k.val = inst.val) →
        (↑(K1[p]) : List U64)[k.val]'(by have := (K1[p]).property; have := k.isLt; scalar_tac)
          = (↑(K[p]) : List U64)[k.val]'(by have := (K[p]).property; have := k.isLt; scalar_tac)) :
    ∀ (k : Fin 4), k.val ≠ inst.val →
      Keccak4xHybrid.projectLane k K1 = Keccak4xHybrid.projectLane k S := by
  intro k hk
  apply Keccak4xHybrid.projectLane_congr
  intro m
  have h1 := kxh1_post3 m k (by rintro ⟨_, _, h⟩; exact hk h)
  have h0 := kxh_post m k
  rw [if_neg (by rintro ⟨_, h⟩; exact hk h)] at h0
  exact h1.trans h0

set_option maxHeartbeats 2000000 in
/-- Per-bit lane reconstruction for the `byte_off ≠ 0` (unaligned) no-tail branches:
    a start partial lane (`v` = `packBytes … byte_off`) plus the main loop's full
    middle lanes, ending exactly at the data boundary (`offset + 8·N1 = |data|`).
    Covers both `take ≠ remaining` (the start lane holds all of `data`, `N1 = 0`,
    `hcov_start` left) and `take = remaining ∧ offset1 ≥ |data|` (the start lane
    completes its lane, `hcov_start` right). -/
theorem Shake4x.unaligned_notail_hlane
    (S K K1 : Std.Array sha3.keccak4x_hybrid.Lane4 25#usize)
    (inst lane_idx lane_idx1 byte_off take offset : Std.Usize) (v : U64) (data : Slice U8)
    (old N1 : Nat) (hInst : inst.val < 4)
    (hbo1 : 1 ≤ byte_off.val) (hbo8 : byte_off.val < 8)
    (hold : old = 8 * lane_idx.val + byte_off.val)
    (hmid_align : N1 = 0 ∨ 8 * offset.val + 8 * old = 64 * lane_idx1.val)
    (hstart_not_mid : ¬(lane_idx1.val ≤ lane_idx.val ∧ lane_idx.val < lane_idx1.val + N1))
    (hlane1_le : lane_idx1.val ≤ lane_idx.val + 1)
    (hcover : offset.val + 8 * N1 = data.val.length)
    (hend : 8 * old + 8 * data.val.length ≤ 64 * (lane_idx.val + 1 + N1))
    (htakele : take.val ≤ data.val.length)
    (hb8_start : byte_off.val + take.val ≤ 8)
    (hcov_start : take.val = data.val.length ∨ byte_off.val + take.val = 8)
    (kxh_post : ∀ (p : Fin 25) (k : Fin 4),
        (↑(K[p]) : List U64)[k.val]'(by have := (K[p]).property; have := k.isLt; scalar_tac)
          = if p.val = lane_idx.val ∧ k.val = inst.val then
              (↑(S[p]) : List U64)[k.val]'(by have := (S[p]).property; have := k.isLt; scalar_tac) ^^^ v
            else (↑(S[p]) : List U64)[k.val]'(by have := (S[p]).property; have := k.isLt; scalar_tac))
    (hv_bnd : 0 + take.val ≤ data.val.length)
    (v_post : v.bv = U64.bv 0#u64 ||| (Shake4x.packBytes data.val 0 byte_off.val take.val (by omega)).bv
                &&& ~~~ (Shake4x.packBytes data.val 0 byte_off.val 0 (by omega)).bv)
    (kxh1_post3 : ∀ (p : Fin 25) (k : Fin 4),
        ¬(lane_idx1.val ≤ p.val ∧ p.val < lane_idx1.val + N1 ∧ k.val = inst.val) →
        (↑(K1[p]) : List U64)[k.val]'(by have := (K1[p]).property; have := k.isLt; scalar_tac)
          = (↑(K[p]) : List U64)[k.val]'(by have := (K[p]).property; have := k.isLt; scalar_tac))
    (kxh1_post4 : ∀ (j : ℕ), lane_idx1.val ≤ j → j < lane_idx1.val + N1 → ∀ (hp : j < 25),
        (↑(K1[(⟨j, hp⟩ : Fin 25)]) : List U64)[inst.val]'(by
            have := (K1[(⟨j, hp⟩ : Fin 25)]).property; scalar_tac)
          = (↑(K[(⟨j, hp⟩ : Fin 25)]) : List U64)[inst.val]'(by
            have := (K[(⟨j, hp⟩ : Fin 25)]).property; scalar_tac)
          ^^^ ⟨(BitVec.fromLEBytes ((data.val.extract (offset.val + 8 * (j - lane_idx1.val))
                (offset.val + 8 * (j - lane_idx1.val) + 8)).map U8.bv)).setWidth 64⟩) :
    ∀ (m : Fin 25) (c : Fin 64),
      ((↑(K1[m]) : List U64)[inst.val]'(by have := (K1[m]).property; scalar_tac)).bv.getLsbD c.val
      = ((((↑(S[m]) : List U64)[inst.val]'(by have := (S[m]).property; scalar_tac)).bv.getLsbD c.val)
        ^^ (chunkBits old data.val)[64 * m.val + c.val]'(by
            have := m.isLt; have := c.isLt; have : (b:Nat) = 1600 := rfl; omega)) := by
  intro m c
  have hidx : 64 * m.val + c.val < b := by
    have := m.isLt; have := c.isLt; have : (b:Nat) = 1600 := rfl; omega
  have hkS := kxh_post m ⟨inst.val, hInst⟩
  simp only [and_true] at hkS
  by_cases hmid : lane_idx1.val ≤ m.val ∧ m.val < lane_idx1.val + N1
  · -- middle (full) lane
    obtain ⟨hlo, hhi⟩ := hmid
    have halign : 8 * offset.val + 8 * old = 64 * lane_idx1.val := hmid_align.resolve_left (by omega)
    have hk1 : (↑(K1[m]) : List U64)[inst.val]'(by have := (K1[m]).property; scalar_tac)
        = (↑(K[m]) : List U64)[inst.val]'(by have := (K[m]).property; scalar_tac)
          ^^^ ⟨(BitVec.fromLEBytes ((data.val.extract (offset.val + 8 * (m.val - lane_idx1.val))
                (offset.val + 8 * (m.val - lane_idx1.val) + 8)).map U8.bv)).setWidth 64⟩ :=
      kxh1_post4 m.val hlo hhi m.isLt
    have hkSm : (↑(K[m]) : List U64)[inst.val]'(by have := (K[m]).property; scalar_tac)
        = (↑(S[m]) : List U64)[inst.val]'(by have := (S[m]).property; scalar_tac) := by
      rw [hkS, if_neg (by omega)]
    have hwc : (⟨(BitVec.fromLEBytes ((data.val.extract (offset.val + 8 * (m.val - lane_idx1.val))
          (offset.val + 8 * (m.val - lane_idx1.val) + 8)).map U8.bv)).setWidth 64⟩ : U64).bv.getLsbD c.val
        = (chunkBits old data.val)[64 * m.val + c.val]'hidx :=
      Shake4x.window_lane_eq_chunkBits data.val old m.val c.val (offset.val + 8 * (m.val - lane_idx1.val))
        c.isLt (by omega) (by omega) (by omega) (by omega) hidx
    rw [hk1, hkSm]; simp only [UScalar.bv_xor, BitVec.getLsbD_xor, hwc]
  · -- start lane or framed
    have hk1 := kxh1_post3 m ⟨inst.val, hInst⟩ (by
      simp only []; rintro ⟨h1, h2, _⟩; exact hmid ⟨h1, h2⟩)
    simp only [] at hk1
    rw [hk1]
    by_cases hms : m.val = lane_idx.val
    · -- start (partial) lane
      rw [hkS, if_pos hms]
      have hvc : v.bv.getLsbD c.val = (chunkBits old data.val)[64 * m.val + c.val]'hidx := by
        rw [Shake4x.vbit_eq v _ _ c.val c.isLt v_post
          (Shake4x.packBytes_zero_bit data.val 0 byte_off.val c.val (by omega))]
        exact Shake4x.packstart_lane_eq_chunkBits data.val old m.val c.val byte_off.val take.val
          c.isLt hb8_start (by omega) htakele hcov_start (by omega) hidx
      simp only [UScalar.bv_xor, BitVec.getLsbD_xor, hvc]
    · -- framed lane
      rw [hkS, if_neg (by omega),
        Shake4x.chunkBits_lane_zero data.val old m.val c.val (by omega) hidx]; simp

@[step]
theorem Shake4x.append.spec
    (self : sha3.shake4x.Shake4x) (inst : Std.Usize) (data : Slice Std.U8)
    (gs : Fin 4 → GhostState)
    (hAbs : Shake4x.absorbing self gs)
    (hInst : inst.val < 4)
    (hFit : self.absorbed[(⟨inst.val, hInst⟩ : Fin 4)].val + data.length < self.rate.val) :
    sha3.shake4x.Shake4x.append self inst data
    ⦃ (result : sha3.shake4x.Shake4x) =>
        let k' := ⟨inst.val, hInst⟩
        let i' := Usize.ofNatCore ((self.absorbed[k']).val + data.length) (by agrind)
        result.rate = self.rate ∧
        result.rate_lanes = self.rate_lanes ∧
        result.buf = self.buf ∧
        result.absorbed = self.absorbed.set inst i' ∧
        Shake4x.absorbing result
          (Function.update gs k' ((gs k').append data.val false)) ⦄ := by
  -- All infrastructure is proven (foundation bit lemmas + the full
  -- `Shake4x.append_absorbing_reconstruct`).  What remains is the mechanical
  -- 4-branch composition of the extracted body.  Validated recipe:
  --   `unfold append; step*` discharges the prologue but stalls at the two
  --   data-dependent inner `if`s (`take = remaining`, `offset1 < data.len`);
  --   split each, compose the loop1/loop3 + tail loop2/loop4 posts through
  --   `xor_lane.spec`, and turn the per-lane equations (via `packBytes_getLsbD`
  --   / `fromLEBytes_extract_getLsbD` + `chunkBits_getElem`, case-split on the
  --   lane's byte range) into the `hframe` (k ≠ inst lanes untouched) and
  --   `hlane` (lane-inst bit = self bit ^^ `chunkBits old data`) hypotheses;
  --   then `exact Shake4x.append_absorbing_reconstruct …` for the `absorbing`
  --   conjunct (rate/rate_lanes/buf/absorbed conjuncts are read off the body).
  obtain ⟨hWF, hNotFin, hCons, hPer⟩ := hAbs
  have hrate_le : self.rate.val ≤ 168 := by rcases hWF.1 with h | h <;> simp [h]
  have habs_lt : ∀ i : Fin 4, self.absorbed[i].val < self.rate.val := hWF.2.2
  /- The `ofNatCore` overflow bound, established once in a small context (the
     in-body `(by scalar_tac)` would loop on the huge post-`step*` context). -/
  have hbmax : self.absorbed[(⟨inst.val, hInst⟩ : Fin 4)].val + data.length < Std.Usize.max := by
    have := habs_lt ⟨inst.val, hInst⟩; have := hFit; scalar_tac
  /- `hFit` re-expressed in the List/Nat-getElem form `step*` produces (`pos_post`
     binds `pos = (↑self.absorbed)[↑inst]`); the two getElem forms are defeq. -/
  have hFit' : ((↑self.absorbed : List Std.Usize)[inst.val]'(by
        have := self.absorbed.property; scalar_tac)).val + data.length < self.rate.val := hFit
  /- With this in context, the `get_elem_tactic` override discharges
     `self.absorbed[⟨inst, _⟩]` bounds via `assumption` — avoiding the
     `scalar_tac`/`simp_all` recursion blow-up in the huge post-`step*` context. -/
  have hlen4 : inst.val < self.absorbed.val.length := by
    have := self.absorbed.property; scalar_tac
  unfold sha3.shake4x.Shake4x.append
  step*
  · -- unaligned (byte_off ≠ 0) remainder
    have hub : sha3.shake4x.U64_BYTES.val = 8 := Shake4x.U64_BYTES_val
    have hbo1 : 1 ≤ byte_off.val := by
      have h : (byte_off != 0#usize) = true := by assumption
      simp only [bne_iff_ne, ne_eq] at h
      have : byte_off.val ≠ 0 := fun hv => h (UScalar.eq_of_val_eq (by simpa using hv))
      omega
    have hbo8 : byte_off.val < 8 := by rw [byte_off_post, hub]; exact Nat.mod_lt _ (by omega)
    have hpos8 : pos.val = 8 * lane_idx.val + byte_off.val := by
      rw [byte_off_post, lane_idx_post, hub]; omega
    have hold : self.absorbed[(⟨inst.val, hInst⟩ : Fin 4)].val = pos.val :=
      congrArg (fun u : Std.Usize => u.val) pos_post.symm
    have hdll : data.len.val = data.length := rfl
    have hdvl : data.length = data.val.length := rfl
    split
    · -- take = remaining
      have htake : take.val = 8 - byte_off.val := by
        have ht : take = remaining := by assumption
        rw [ht, remaining_post1, hub]
      have htakele : take.val ≤ data.val.length := by
        have hmin : take.val ≤ data.len.val := by
          rw [take_post]; exact Shake4x.ordUsize_min_le_left data.len remaining
        omega
      step*
      · -- offset1 < data.len  (start + middle + tail)
        have hoff : offset.val = take.val := by rw [offset_post]; omega
        have hoffle : offset.val ≤ data.val.length := by omega
        have hN1le : 8 * ((data.val.length - offset.val) / 8) ≤ data.val.length - offset.val :=
          Nat.mul_div_le _ 8 |>.trans_eq (by ring)
        have hoff1 : offset1.val = offset.val + 8 * ((data.val.length - offset.val) / 8) := by
          have := kxh1_post1; omega
        have hoff1le : offset1.val ≤ data.val.length := by rw [hoff1]; omega
        have hrem : data.val.length - offset1.val < 8 := by rw [hoff1]; omega
        have heq_abs := Shake4x.abs_set_eq self inst i7 pos data a hInst a_post i7_post hold hbmax
        refine ⟨heq_abs, ?_⟩
        refine Shake4x.append_absorbing_reconstruct self _ inst data gs
          ⟨hWF, hNotFin, hCons, hPer⟩ hInst hFit rfl rfl rfl heq_abs ?_ ?_
        · -- hframe
          exact Shake4x.unaligned_tail_hframe self.state.state kxh.state kxh1.state kxh2.state
            inst lane_idx lane_idx1 lane_idx2 v v1 ((data.val.length - offset.val) / 8) hInst
            kxh_post kxh1_post3 kxh2_post
        · -- hlane
          refine Shake4x.unaligned_tail_hlane self.state.state kxh.state kxh1.state kxh2.state
            inst lane_idx lane_idx1 lane_idx2 byte_off take offset offset1 i5 v v1 data
            (self.absorbed[(⟨inst.val, hInst⟩ : Fin 4)].val) ((data.val.length - offset.val) / 8)
            hInst hbo1 hbo8 htake (by rw [hold]; omega) hoff hoffle lane_idx1_post ?_ hoff1
            ?_ hN1le hrem hoff1le kxh_post (by omega) v_post kxh1_post3
            kxh1_post4 kxh2_post (by omega) v1_post
          · have := kxh1_post2; omega
          · have := i5_post1; omega
      · -- offset1 ≥ data.len  (start + middle, no tail)
        have hoff : offset.val = take.val := by rw [offset_post]; omega
        have hoffle : offset.val ≤ data.val.length := by omega
        have hoff1 : offset1.val = offset.val + 8 * ((data.val.length - offset.val) / 8) := by
          have := kxh1_post1; omega
        have hoff1ge : data.val.length ≤ offset1.val := by
          have h : ¬ offset1 < data.len := by assumption
          have : ¬ offset1.val < data.len.val := h
          omega
        have hN1le : 8 * ((data.val.length - offset.val) / 8) ≤ data.val.length - offset.val :=
          Nat.mul_div_le _ 8 |>.trans_eq (by ring)
        have hcover : offset.val + 8 * ((data.val.length - offset.val) / 8) = data.val.length := by omega
        have heq_abs := Shake4x.abs_set_eq self inst i5 pos data a hInst a_post i5_post hold hbmax
        refine ⟨heq_abs, ?_⟩
        refine Shake4x.append_absorbing_reconstruct self _ inst data gs
          ⟨hWF, hNotFin, hCons, hPer⟩ hInst hFit rfl rfl rfl heq_abs ?_ ?_
        · -- hframe
          exact Shake4x.unaligned_notail_hframe self.state.state kxh.state kxh1.state
            inst lane_idx lane_idx1 v ((data.val.length - offset.val) / 8) hInst kxh_post kxh1_post3
        · -- hlane
          refine Shake4x.unaligned_notail_hlane self.state.state kxh.state kxh1.state
            inst lane_idx lane_idx1 byte_off take offset v data
            (self.absorbed[(⟨inst.val, hInst⟩ : Fin 4)].val) ((data.val.length - offset.val) / 8)
            hInst hbo1 hbo8 (by rw [hold]; omega) (Or.inr (by rw [hold]; omega)) (by omega) (by omega)
            hcover (by rw [hold]; omega) htakele (by omega) (Or.inr (by omega)) kxh_post (by omega) v_post ?_ ?_
          · have := kxh1_post3; intro p k hp; exact this p k (by omega)
          · have := kxh1_post4; intro j h1 h2 hp; exact this j h1 h2 hp
    · -- take ≠ remaining  (data fits in the partial start lane; no middle, no tail)
      have htne : ¬ take = remaining := by assumption
      have htake_dl : take.val = data.len.val := by
        have hmin : take.val ≤ data.len.val := by
          rw [take_post]; exact Shake4x.ordUsize_min_le_left data.len remaining
        have hne : take.val ≠ remaining.val := fun h => htne (UScalar.eq_of_val_eq h)
        have hcase : take.val = data.len.val ∨ take.val = remaining.val := by
          rw [take_post]; exact Shake4x.ordUsize_min_cases data.len remaining
        omega
      step*
      · -- start lane only (lane_idx1 = lane_idx, N1 = 0)
        have hoff : offset.val = take.val := by rw [offset_post]; omega
        have hofflt : offset.val < 8 - byte_off.val := by
          have hrem_le : remaining.val = 8 - byte_off.val := by rw [remaining_post1, hub]
          have hne : take.val ≠ remaining.val := fun h => htne (UScalar.eq_of_val_eq h)
          have hmin2 : take.val ≤ remaining.val := by
            rw [take_post]; exact Shake4x.ordUsize_min_le_right data.len remaining
          omega
        have hoffle : offset.val ≤ data.val.length := by omega
        have hN1z : (data.val.length - offset.val) / 8 = 0 := by
          have : data.val.length = offset.val := by omega
          simp [this]
        have hcover : offset.val + 8 * ((data.val.length - offset.val) / 8) = data.val.length := by
          rw [hN1z]; omega
        have heq_abs := Shake4x.abs_set_eq self inst i5 pos data a hInst a_post i5_post hold hbmax
        refine ⟨heq_abs, ?_⟩
        refine Shake4x.append_absorbing_reconstruct self _ inst data gs
          ⟨hWF, hNotFin, hCons, hPer⟩ hInst hFit rfl rfl rfl heq_abs ?_ ?_
        · -- hframe
          exact Shake4x.unaligned_notail_hframe self.state.state kxh.state kxh1.state
            inst lane_idx lane_idx v ((data.val.length - offset.val) / 8) hInst kxh_post kxh1_post3
        · -- hlane
          refine Shake4x.unaligned_notail_hlane self.state.state kxh.state kxh1.state
            inst lane_idx lane_idx byte_off take offset v data
            (self.absorbed[(⟨inst.val, hInst⟩ : Fin 4)].val) ((data.val.length - offset.val) / 8)
            hInst hbo1 hbo8 (by rw [hold]; omega) (Or.inl hN1z) (by omega) (by omega)
            hcover (by rw [hold]; omega) (by omega) (by omega) (Or.inl (by omega)) kxh_post (by omega) v_post ?_ ?_
          · have := kxh1_post3; intro p k hp; exact this p k (by omega)
          · have := kxh1_post4; intro j h1 h2 hp; exact this j h1 h2 hp
  · -- aligned (byte_off = 0) tail final
    have hoff_lt : offset.val < data.length := by
      have h : offset < data.len := by assumption
      exact h
    have hbo : byte_off.val = 0 := Shake4x.byte_off_zero byte_off (by assumption)
    have hub : sha3.shake4x.U64_BYTES.val = 8 := Shake4x.U64_BYTES_val
    have hpos8 : pos.val = 8 * lane_idx.val := by
      rw [hub] at byte_off_post lane_idx_post; omega
    have hold : self.absorbed[(⟨inst.val, hInst⟩ : Fin 4)].val = pos.val :=
      congrArg (fun u : Std.Usize => u.val) pos_post.symm
    have hold8 : self.absorbed[(⟨inst.val, hInst⟩ : Fin 4)].val = 8 * lane_idx.val := hold.trans hpos8
    have hbnd4 : offset.val + i4.val ≤ data.length := by
      have h1 := i4_post1; have h2 := i4_post2; have hdl : data.len.val = data.length := rfl; omega
    have heq_abs := Shake4x.abs_set_eq self inst i7 pos data a hInst a_post i7_post hold hbmax
    refine ⟨heq_abs, ?_⟩
    refine Shake4x.append_absorbing_reconstruct self _ inst data gs
      ⟨hWF, hNotFin, hCons, hPer⟩ hInst hFit rfl rfl rfl heq_abs ?_ ?_
    · -- hframe
      exact Shake4x.tail_hframe self.state.state kxh.state kxh2.state inst lane_idx lane_idx1 v
        ((data.length - 0) / 8) hInst kxh_post3 kxh2_post
    · -- hlane
      exact Shake4x.aligned_tail_hlane self.state.state kxh.state kxh2.state inst lane_idx lane_idx1
        offset i4 v data (self.absorbed[(⟨inst.val, hInst⟩ : Fin 4)].val) ((data.length - 0) / 8)
        hInst hold8 rfl kxh_post2 kxh_post1 i4_post1 hoff_lt kxh_post3 kxh_post4 kxh2_post hbnd4 v_post
  · -- aligned (byte_off = 0) no-tail final
    have hbo : byte_off.val = 0 := Shake4x.byte_off_zero byte_off (by assumption)
    have hub : sha3.shake4x.U64_BYTES.val = 8 := Shake4x.U64_BYTES_val
    have hpos8 : pos.val = 8 * lane_idx.val := by
      rw [hub] at byte_off_post lane_idx_post; omega
    have hold : self.absorbed[(⟨inst.val, hInst⟩ : Fin 4)].val = pos.val :=
      congrArg (fun u : Std.Usize => u.val) pos_post.symm
    have hold8 : self.absorbed[(⟨inst.val, hInst⟩ : Fin 4)].val = 8 * lane_idx.val := hold.trans hpos8
    have hoff_ge : data.length ≤ offset.val := by
      have h : ¬ (offset < data.len) := by assumption
      have : data.len.val ≤ offset.val := by simpa using h
      simpa using this
    have hdata8 : data.length = 8 * ((data.length - 0) / 8) := by
      have hk1 := kxh_post1; omega
    have heq_abs := Shake4x.abs_set_eq self inst i4 pos data a hInst a_post i4_post hold hbmax
    refine ⟨heq_abs, ?_⟩
    refine Shake4x.append_absorbing_reconstruct self _ inst data gs
      ⟨hWF, hNotFin, hCons, hPer⟩ hInst hFit rfl rfl rfl heq_abs ?_ ?_
    · -- hframe
      exact Shake4x.loop_hframe self.state.state kxh.state inst lane_idx ((data.length - 0) / 8)
        hInst kxh_post3
    · -- hlane
      exact Shake4x.aligned_notail_hlane self.state.state kxh.state inst lane_idx data
        (self.absorbed[(⟨inst.val, hInst⟩ : Fin 4)].val) ((data.length - 0) / 8)
        hInst hold8 hdata8 kxh_post3 kxh_post4

end

end symcrust
