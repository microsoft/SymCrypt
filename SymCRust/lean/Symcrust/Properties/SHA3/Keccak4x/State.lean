/-
# Properties/SHA3/Keccak4x/State — `@[step]` specs for the per-lane and
                                 per-byte API of `sha3.keccak4x.Keccak4x`
                                 and `sha3.keccak4x_hybrid.Keccak4xHybrid`.

All `@[step]` theorems below have real, vacuity-checked
postconditions.

Surface covered:

  * `Keccak4x.new`           / `Keccak4xHybrid.new`
  * `Keccak4x.xor_lane`      / `Keccak4xHybrid.xor_lane`
  * `Keccak4x.get_lane`      / `Keccak4xHybrid.get_lane`
  * `Keccak4x.xor_bytes`     (no hybrid analogue — safe variant only)
  * `Keccak4x.extract_bytes` / `Keccak4xHybrid.extract_bytes`
  * Loop helpers: `Keccak4x.xor_bytes_loop`,
    `Keccak4x.extract_bytes_loop`, `Keccak4xHybrid.extract_bytes_loop`.

The safe (`Keccak4x`) and hybrid (`Keccak4xHybrid`) wrappers have
identical Rust semantics on these 4 methods — no AVX2 intrinsics on
this path.  Only `permute` differs (see `Permute.lean` and
`Hybrid.lean`).  Specs are therefore parallel between the two variants.

Consumers:

  * `Shake4x.new_{128,256}`   → `Keccak4xHybrid.new.spec`
  * `Shake4x.pad_all`         → `Keccak4xHybrid.xor_lane.spec` (×2)
  * `Shake4x.extract_all`     → `Keccak4xHybrid.get_lane.spec` (×4×rate_lanes)
  * External fast path        → `Keccak4xHybrid.get_lane.spec`
    (`state_ref` borrow + per-lane `u64` reads, MLKEM/MLDSA-4x)

`Keccak4x.{xor,extract}_bytes` are pub Rust surface for external
testing/KAT bridges; not consumed by Shake4x. -/
import Symcrust.Code
import Symcrust.Properties.SHA3.Basic
import Symcrust.Properties.Iterators

namespace symcrust

open Aeneas Aeneas.Std Result
open scoped Spec.Notations

set_option linter.unusedSectionVars false
set_option linter.unusedVariables false

/-! ## Safe variant — `sha3.keccak4x.Keccak4x` -/

namespace Keccak4x

/-- Helper: `BitVec.cast` and `BitVec.setWidth` agree on 64-bit `fromLEBytes`. -/
private theorem bv_cast_eq_setWidth_64 (l : List (BitVec 8)) (h : 8 * l.length = 64) :
    BitVec.cast h (BitVec.fromLEBytes l) = BitVec.setWidth 64 (BitVec.fromLEBytes l) := by
  apply BitVec.eq_of_toNat_eq
  simp [BitVec.toNat_cast, BitVec.toNat_setWidth]
  have hlt' : (BitVec.fromLEBytes l).toNat < 2 ^ 64 := h ▸ (BitVec.fromLEBytes l).isLt
  exact (Nat.mod_eq_of_lt hlt').symm

/-- **Informal proof.**
    Body (`Funs.lean:22455-22462`): the extracted `new` is
    `Default::default`, which sets every lane to `Array.repeat 4 0#u64`,
    then wraps in `Array.repeat 25 ·`.  The composed result is
    structurally `Array.repeat 25 (Array.repeat 4 0)`.
    No monadic call; mechanize: `unfold new Keccak4x.Insts.CoreDefaultDefault.default; rfl`. -/
@[step]
theorem new.spec :
    sha3.keccak4x.Keccak4x.new
    ⦃ (r : sha3.keccak4x.Keccak4x) =>
        r.state = Array.repeat 25#usize (Array.repeat 4#usize 0#u64) ⦄ := by
  unfold sha3.keccak4x.Keccak4x.new
  unfold sha3.keccak4x.Keccak4x.Insts.CoreDefaultDefault.default
  unfold sha3.keccak4x.Lane4.Insts.CoreDefaultDefault.default
  simp [WP.spec_ok]

/-- **Informal proof.**
    Body (`Funs.lean:22465-22482`): `massert (pos < 25)`, `massert (inst < 4)`,
    then read `state[pos] : Lane4`, read `lane[inst] : U64`,
    XOR with `value`, write back via `Array.update`.

    Lemma chain in call order:
      1. `Array.index_usize.spec` (read `state[pos]` — bounds from `hPos`).
      2. `Array.index_usize.spec` (read `lane[inst]` — bounds from `hInst`).
      3. `lift (i3 ^^^ value)` is pure; produces `state[pos][inst] ^^^ value`.
      4. `Array.update.spec` on inner `Lane4` (writes inst).
      5. `Array.update.spec` on outer state (writes pos).

    Post by case-split on `(p = pos, k = inst)`:
      * `(p, k) = (pos, inst)`: outer + inner update hits, returns XOR.
      * `p ≠ pos`: outer update preserves entry → original `self.state[p][k]`.
      * `p = pos, k ≠ inst`: outer hits, inner preserves → `self.state[pos][k]`.

    Discharge: `simp [Array.getElem_update_*]; agrind`. -/
@[step]
theorem xor_lane.spec
    (self : sha3.keccak4x.Keccak4x) (pos inst : Std.Usize) (value : U64)
    (hPos : pos.val < 25) (hInst : inst.val < 4) :
    sha3.keccak4x.Keccak4x.xor_lane self pos inst value
    ⦃ (r : sha3.keccak4x.Keccak4x) =>
        ∀ p : Fin 25, ∀ k : Fin 4,
          ((r.state[p]'(by scalar_tac)).val[k.val]'(by
              have := (r.state[p]'(by scalar_tac)).property; scalar_tac))
            = if p.val = pos.val ∧ k.val = inst.val then
                ((self.state[p]'(by scalar_tac)).val[k.val]'(by
                  have := (self.state[p]'(by scalar_tac)).property; scalar_tac))
                  ^^^ value
              else
                ((self.state[p]'(by scalar_tac)).val[k.val]'(by
                  have := (self.state[p]'(by scalar_tac)).property; scalar_tac)) ⦄ := by
  unfold sha3.keccak4x.Keccak4x.xor_lane
  step*
  have heq : i1 = i ^^^ value := by scalar_tac
  intro p k
  simp [l1_post2, a_post]
  by_cases hp : p.val = pos.val
  · simp_lists
    by_cases hk : k.val = inst.val
    · simp [hp, hk, heq, i_post, l_post]
    · simp [hp, hk, l1_post1]
  · simp [hp]

/-- **Informal proof.**
    Body: two `Array.index_usize` reads, return the inner u64.
    Lemma chain: `Array.index_usize.spec` ×2 (bounds from `hPos`, `hInst`).
    Proof: `unfold get_lane; step ×2; rfl`. -/
@[step]
theorem get_lane.spec
    (self : sha3.keccak4x.Keccak4x) (pos inst : Std.Usize)
    (hPos : pos.val < 25) (hInst : inst.val < 4) :
    sha3.keccak4x.Keccak4x.get_lane self pos inst
    ⦃ (r : U64) =>
        r = (self.state[pos]'(by scalar_tac)).val[inst.val]'(by
          have := (self.state[pos]'(by scalar_tac)).property; scalar_tac) ⦄ := by
  unfold sha3.keccak4x.Keccak4x.get_lane
  step*
  simp_lists [l_post, r_post]

/-! ## `#decompose` cascade for `xor_bytes_loop` -/

set_option maxRecDepth 1024 in
#decompose sha3.keccak4x.Keccak4x.xor_bytes_loop
    sha3.keccak4x.Keccak4x.xor_bytes_loop.match_helper_eq
  letRange 1 1 => sha3.keccak4x.Keccak4x.xor_bytes_loop.match_helper

set_option maxRecDepth 2048 in
#decompose sha3.keccak4x.Keccak4x.xor_bytes_loop.match_helper
    sha3.keccak4x.Keccak4x.xor_bytes_loop.match_helper_branch_eq
  branch 1 (letRange 0 12) => sha3.keccak4x.Keccak4x.xor_bytes_loop.some_body

@[step]
theorem xor_bytes_loop.some_body.spec
    (self : sha3.keccak4x.Keccak4x) (inst : Std.Usize)
    (data : Slice U8) (i : Std.Usize)
    (hInst : inst.val < 4)
    (hi : i.val < 25)
    (hData : data.length ≥ i.val * 8 + 8) :
    sha3.keccak4x.Keccak4x.xor_bytes_loop.some_body self inst data i
    ⦃ (a2 : Std.Array sha3.keccak4x.Lane4 25#usize) =>
        ∀ p : Fin 25, ∀ k : Fin 4,
          ((a2[p]'(by scalar_tac)).val[k.val]'(by
              have := (a2[p]'(by scalar_tac)).property; scalar_tac))
            = if p.val = i.val ∧ k.val = inst.val then
                ((self.state[p]'(by scalar_tac)).val[k.val]'(by
                  have := (self.state[p]'(by scalar_tac)).property; scalar_tac))
                  ^^^ ⟨(BitVec.fromLEBytes
                        ((data.val.extract (i.val * 8) (i.val * 8 + 8)).map U8.bv)).setWidth 64⟩
              else
                ((self.state[p]'(by scalar_tac)).val[k.val]'(by
                  have := (self.state[p]'(by scalar_tac)).property; scalar_tac)) ⦄ := by
  unfold sha3.keccak4x.Keccak4x.xor_bytes_loop.some_body
  step; step; step
  have hs : s.length = 8#usize.val := by simp [s_post2, i2_post, i1_post]
  have hclone : ∀ x : Std.U8, core.marker.CopyU8.cloneInst.clone x = ok x := by
    intro x; rfl
  step
  cases hr : r with
  | Err _ => simp [hr] at r_post; exact absurd hs r_post
  | Ok a₀ =>
    simp only [hr] at r_post
    obtain ⟨ha_val, ha_len⟩ := r_post
    step*
    injection a_post with ha_eq
    subst ha_eq
    intro p k
    simp only [a1_post, l1_post2]
    by_cases hp : p.val = i.val
    · simp_lists
      by_cases hk : k.val = inst.val
      · have heq : i4 = i3 ^^^ v := by scalar_tac
        simp [hp, hk, heq, i3_post, l_post]
        congr 1
        have hav : a₀.val = data.val.extract (i.val * 8) (i.val * 8 + 8) := by
          rw [ha_val, s_post1, List.slice, List.extract_eq_take_drop,
              i1_post, i2_post, i1_post]
        have hv : v.bv = (BitVec.fromLEBytes
            ((data.val.extract (i.val * 8) (i.val * 8 + 8)).map U8.bv)).setWidth 64 := by
          rw [v_post]
          rw [bv_cast_eq_setWidth_64 (List.map U8.bv a₀.val) (by simp [hav]; scalar_tac)]
          rw [hav]
        apply U64.bv_eq_imp_eq
        simpa using hv
      · simp [hp, hk, l1_post1]; rfl
    · simp [hp]

/-- **Informal proof** (loop spec — `xor_bytes_loop` body,
    `Funs.lean:23357-23383`).  Per iteration at cursor `i := iter.start`:
    read 8 LE bytes from `data[i*8..i*8+8]`, decode to u64 `v`, and XOR
    `state[i][inst] ^^^ v` into the state.

    Spec mirrors `extract_bytes_loop.spec`'s if-form: for the lane
    dimension `k = inst`, positions `p ∈ [iter.start, iter.end)` are
    XORed with the corresponding 8 bytes; all other cells frame from
    `self`.  Base case (iter.start ≥ iter.end): r = self and the
    write-branch is vacuous. -/
@[step]
theorem xor_bytes_loop.spec
    (iter : core.ops.range.Range Std.Usize) (self : sha3.keccak4x.Keccak4x)
    (inst : Std.Usize) (data : Slice U8)
    (hInst : inst.val < 4)
    (hStart : iter.start.val ≤ iter.«end».val)
    (hEnd : iter.«end».val ≤ 25)
    (hData : data.length ≥ iter.«end».val * 8) :
    sha3.keccak4x.Keccak4x.xor_bytes_loop iter self inst data
    ⦃ (r : sha3.keccak4x.Keccak4x) =>
        ∀ p : Fin 25, ∀ k : Fin 4,
          ((r.state[p]'(by scalar_tac)).val[k.val]'(by
              have := (r.state[p]'(by scalar_tac)).property; scalar_tac))
            = if iter.start.val ≤ p.val ∧ p.val < iter.«end».val ∧ k.val = inst.val then
                ((self.state[p]'(by scalar_tac)).val[k.val]'(by
                  have := (self.state[p]'(by scalar_tac)).property; scalar_tac))
                  ^^^ ⟨(BitVec.fromLEBytes
                        ((data.val.extract (p.val * 8) (p.val * 8 + 8)).map U8.bv)).setWidth 64⟩
              else
                ((self.state[p]'(by scalar_tac)).val[k.val]'(by
                  have := (self.state[p]'(by scalar_tac)).property; scalar_tac)) ⦄ := by
  rw [sha3.keccak4x.Keccak4x.xor_bytes_loop.match_helper_eq]
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← IteratorRange_next_some iter hlt
    rw [hsome]
    rw [sha3.keccak4x.Keccak4x.xor_bytes_loop.match_helper_branch_eq]
    have hi : iter.start.val < 25 := by scalar_tac
    have hData' : data.length ≥ iter.start.val * 8 + 8 := by scalar_tac
    let* ⟨ a2, h_a2 ⟩ ←
      xor_bytes_loop.some_body.spec self inst data iter.start hInst hi hData'
    have hStart1 : iter1.start.val ≤ iter1.«end».val := by
      rw [hstart', hend']; scalar_tac
    have hEnd1 : iter1.«end».val ≤ 25 := by rw [hend']; exact hEnd
    have hData1 : data.length ≥ iter1.«end».val * 8 := by rw [hend']; exact hData
    apply WP.spec_mono
      (xor_bytes_loop.spec iter1 { state := a2 } inst data hInst hStart1 hEnd1 hData1)
    intro r hr
    intro p k
    have hrk := hr p k
    have ha2 := h_a2 p k
    rw [hrk]
    simp only [hstart', hend']
    by_cases hk : k.val = inst.val
    · by_cases hp : p.val = iter.start.val
      · rw [ha2, hp]
        have h1 : ¬ (iter.start.val + 1 ≤ iter.start.val) := by scalar_tac
        simp [h1, hk, hlt]
      · rw [ha2]
        have h_ne : ¬ (p.val = iter.start.val ∧ k.val = inst.val) := fun ⟨he, _⟩ => hp he
        have h_iff : (iter.start.val + 1 ≤ p.val) ↔ (iter.start.val ≤ p.val) := by
          constructor
          · intro h; scalar_tac
          · intro h
            cases Nat.lt_or_eq_of_le h with
            | inl h' => exact h'
            | inr h' => exact absurd h'.symm hp
        simp [h_ne, h_iff]
    · rw [ha2]
      have h_ne : ¬ (p.val = iter.start.val ∧ k.val = inst.val) := fun ⟨_, he⟩ => hk he
      simp [hk]
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← IteratorRange_next_none iter (by scalar_tac)
    rw [hnone]
    rw [sha3.keccak4x.Keccak4x.xor_bytes_loop.match_helper_branch_eq]
    simp only [WP.spec_ok]
    intro p k
    have h1 : ¬ (iter.start.val ≤ p.val ∧ p.val < iter.«end».val ∧ k.val = inst.val) := by
      rintro ⟨h_lo, h_hi, _⟩
      scalar_tac
    simp [h1]

/-- **Informal proof** (`xor_bytes` wrapper — `Funs.lean:23388-23399`).
    Body: 3 `massert`s + call to `xor_bytes_loop` at iter.start=0.  Loop
    post specializes: branch `0 ≤ p < lane_count ∧ k = inst` is the XOR
    branch. -/
@[step]
theorem xor_bytes.spec
    (self : sha3.keccak4x.Keccak4x) (inst : Std.Usize)
    (data : Slice U8) (lane_count : Std.Usize)
    (hInst : inst.val < 4)
    (hData : data.length ≥ lane_count.val * 8)
    (hLanes : lane_count.val ≤ 25) :
    sha3.keccak4x.Keccak4x.xor_bytes self inst data lane_count
    ⦃ (r : sha3.keccak4x.Keccak4x) =>
        ∀ p : Fin 25, ∀ k : Fin 4,
          ((r.state[p]'(by scalar_tac)).val[k.val]'(by
              have := (r.state[p]'(by scalar_tac)).property; scalar_tac))
            = if p.val < lane_count.val ∧ k.val = inst.val then
                ((self.state[p]'(by scalar_tac)).val[k.val]'(by
                  have := (self.state[p]'(by scalar_tac)).property; scalar_tac))
                  ^^^ ⟨(BitVec.fromLEBytes
                        ((data.val.extract (p.val * 8) (p.val * 8 + 8)).map U8.bv)).setWidth 64⟩
              else
                ((self.state[p]'(by scalar_tac)).val[k.val]'(by
                  have := (self.state[p]'(by scalar_tac)).property; scalar_tac)) ⦄ := by
  unfold sha3.keccak4x.Keccak4x.xor_bytes
  step*
  rename_i p k
  have hrk := r_post p k
  simp at hrk
  exact hrk

/-! ## `#decompose` cascade for `extract_bytes_loop`

The body has two phases: iterator step + match on result.  The some-arm
performs ~10 bindings (one 8-byte window write).  We factor the some-arm
into `some_body` so the loop proof can compose a single helper with the
iterator and IH.  Mirrors the `extract_all_loop` cascade in
`Shake4x/Extract.lean`. -/

set_option maxRecDepth 1024 in
#decompose sha3.keccak4x.Keccak4x.extract_bytes_loop
    sha3.keccak4x.Keccak4x.extract_bytes_loop.match_helper_eq
  letRange 1 1 => sha3.keccak4x.Keccak4x.extract_bytes_loop.match_helper

set_option maxRecDepth 2048 in
#decompose sha3.keccak4x.Keccak4x.extract_bytes_loop.match_helper
    sha3.keccak4x.Keccak4x.extract_bytes_loop.match_helper_branch_eq
  branch 1 (letRange 0 9) => sha3.keccak4x.Keccak4x.extract_bytes_loop.some_body

/-- Per-iteration helper spec: `some_body self inst out i` writes the LE
    bytes of `self.state[i][inst]` into the 8-byte window
    `[i*8 .. i*8+8]` of `out`, returning the updated slice. -/
@[step]
theorem extract_bytes_loop.some_body.spec
    (self : sha3.keccak4x.Keccak4x) (inst : Std.Usize)
    (out : Slice U8) (i : Std.Usize)
    (hInst : inst.val < 4)
    (hi : i.val < 25)
    (hOut : out.length ≥ i.val * 8 + 8) :
    sha3.keccak4x.Keccak4x.extract_bytes_loop.some_body self inst out i
    ⦃ (r : Slice U8) =>
        r.length = out.length ∧
        r.val
          = out.val.setSlice! (i.val * 8)
              ((BitVec.toLEBytes ((self.state[i.val]'(by scalar_tac)).val[inst.val]'(by
                have := (self.state[i.val]'(by scalar_tac)).property;
                scalar_tac)).bv).map (fun bv => (⟨bv⟩ : U8))) ⦄ := by
  unfold sha3.keccak4x.Keccak4x.extract_bytes_loop.some_body
  step*
  refine ⟨?_, ?_⟩
  · simp [s_post3, List.length_setSlice!]
  · simp_lists [s_post3, s2_post, s1_post, a_post, i3_post, l_post, i1_post]

/-- **Informal proof** (loop spec — `extract_bytes_loop` body, `Funs.lean:23405-23427`).
    Per iteration at cursor `i := iter.start`:
      1. `IteratorRange.next`.
      2. `Slice.index_mut out [i*8..i*8+8]` — returns 8-byte slice + back.
      3. Two `Array.index_usize` reads (`self.state[i]`, then `lane[inst]`).
      4. `lift (U64.to_le_bytes i3)` — pure; produces `Array U8 8`.
      5. `lift (Array.to_slice a)`, `Slice.copy_from_slice s s1` — overwrites
         the 8-byte window with the LE-encoded u64.
      6. `index_mut_back s2` — reassembles `out` with the window updated.
      7. Recursive tail call with `iter1`, unchanged `self`.

    **Loop invariant** (per-iteration form, mirrors
    `Shake4x.extract_all_loop.spec`): for every lane index `k < 25`,
      * if `iter.start.val ≤ k ∧ k < iter.«end».val`, the 8-byte window
        `r.val[k*8..(k+1)*8]` equals the LE bytes of
        `self.state[k][inst]`;
      * otherwise (before iter.start, or at/after iter.end), the window
        is unchanged from the input `out`.

    Self is NOT mutated by this loop (only `out` is the accumulator).
    Discharge: see `extract_all_loop.spec` — same setSlice!-prefix /
    setSlice!-middle / setSlice!-suffix case split per `m`. -/
@[step]
theorem extract_bytes_loop.spec
    (iter : core.ops.range.Range Std.Usize) (self : sha3.keccak4x.Keccak4x)
    (inst : Std.Usize) (out : Slice U8)
    (hInst : inst.val < 4)
    (hStart : iter.start.val ≤ iter.«end».val)
    (hEnd : iter.«end».val ≤ 25)
    (hOut : out.length ≥ iter.«end».val * 8) :
    sha3.keccak4x.Keccak4x.extract_bytes_loop iter self inst out
    ⦃ (r : Slice U8) =>
        r.length = out.length ∧
        (∀ (m : Nat) (hm : m < 25),
          r.val.extract (m * 8) (m * 8 + 8)
            = if iter.start.val ≤ m ∧ m < iter.«end».val then
                (BitVec.toLEBytes ((self.state[m]'(by scalar_tac)).val[inst.val]'(by
                  have := (self.state[m]'(by scalar_tac)).property;
                  scalar_tac)).bv).map (fun bv => (⟨bv⟩ : U8))
              else
                out.val.extract (m * 8) (m * 8 + 8)) ∧
        r.val.drop (iter.«end».val * 8) = out.val.drop (iter.«end».val * 8) ⦄ := by
  rw [sha3.keccak4x.Keccak4x.extract_bytes_loop.match_helper_eq]
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← IteratorRange_next_some iter hlt
    rw [hsome]
    rw [sha3.keccak4x.Keccak4x.extract_bytes_loop.match_helper_branch_eq]
    have hi : iter.start.val < 25 := by scalar_tac
    have hOut' : out.length ≥ iter.start.val * 8 + 8 := by scalar_tac
    let* ⟨ out', h_len, h_out' ⟩ ←
      extract_bytes_loop.some_body.spec self inst out iter.start hInst hi hOut'
    have hStart1 : iter1.start.val ≤ iter1.«end».val := by
      rw [hstart', hend']; scalar_tac
    have hEnd1 : iter1.«end».val ≤ 25 := by rw [hend']; exact hEnd
    have hOut1 : out'.length ≥ iter1.«end».val * 8 := by
      rw [hend', h_len]; exact hOut
    apply WP.spec_mono
      (extract_bytes_loop.spec iter1 self inst out' hInst hStart1 hEnd1 hOut1)
    intro r ⟨hr_len, hr_extract, hr_drop⟩
    refine ⟨?_, ?_, ?_⟩
    · rw [hr_len, h_len]
    · intro m hm
      have hY : ((BitVec.toLEBytes
                    ((self.state[iter.start.val]'(by scalar_tac)).val[inst.val]'(by
                      have := (self.state[iter.start.val]'(by scalar_tac)).property;
                      scalar_tac)).bv).map (fun bv => (⟨bv⟩ : U8))).length = 8 := by
        simp [BitVec.toLEBytes]
      have hLenOut : out.val.length = out.length := rfl
      have hex := hr_extract m hm
      rw [hex, hstart', hend', h_out']
      by_cases h_eq : m = iter.start.val
      · subst h_eq
        -- LHS: middle of setSlice!; RHS: write branch.
        have h_mid : (out.val.setSlice! (iter.start.val * 8)
                        ((BitVec.toLEBytes
                          ((self.state[iter.start.val]'(by scalar_tac)).val[inst.val]'(by
                            have := (self.state[iter.start.val]'(by scalar_tac)).property;
                            scalar_tac)).bv).map (fun bv => (⟨bv⟩ : U8)))).extract
                      (iter.start.val * 8) (iter.start.val * 8 + 8)
                    = (BitVec.toLEBytes
                        ((self.state[iter.start.val]'(by scalar_tac)).val[inst.val]'(by
                          have := (self.state[iter.start.val]'(by scalar_tac)).property;
                          scalar_tac)).bv).map (fun bv => (⟨bv⟩ : U8)) := by
          simp only [List.extract_eq_take_drop]
          apply List.ext_getElem
          · simp only [List.length_take, List.length_drop, List.length_setSlice!, hLenOut, hY]
            scalar_tac
          · intro j h1 h2
            simp only [List.getElem_take, List.getElem_drop]
            have hj : j < 8 := by
              have := h1
              simp only [List.length_take, List.length_drop,
                         List.length_setSlice!, hLenOut] at this
              scalar_tac
            rw [List.getElem_setSlice!_middle _ _ _ _
                  ⟨by scalar_tac, by rw [hY]; scalar_tac, by scalar_tac⟩]
            congr 1
            scalar_tac
        rw [h_mid]
        have hne : ¬ (iter.start.val + 1 ≤ iter.start.val) := by scalar_tac
        simp [hne, hlt]
      · by_cases h_lt : m < iter.start.val
        · -- LHS: prefix of setSlice! = out.extract; RHS: frame to out.extract.
          have h_pre : (out.val.setSlice! (iter.start.val * 8)
                          ((BitVec.toLEBytes
                            ((self.state[iter.start.val]'(by scalar_tac)).val[inst.val]'(by
                              have := (self.state[iter.start.val]'(by scalar_tac)).property;
                              scalar_tac)).bv).map (fun bv => (⟨bv⟩ : U8)))).extract
                        (m * 8) (m * 8 + 8)
                      = out.val.extract (m * 8) (m * 8 + 8) := by
            simp only [List.extract_eq_take_drop]
            apply List.ext_getElem
            · simp only [List.length_take, List.length_drop, List.length_setSlice!]
            · intro j h1 h2
              simp only [List.getElem_take, List.getElem_drop]
              have hj : j < 8 := by
                have := h1
                simp only [List.length_take, List.length_drop,
                           List.length_setSlice!, hLenOut] at this
                scalar_tac
              rw [List.getElem_setSlice!_prefix _ _ _ _
                    ⟨by scalar_tac, by scalar_tac⟩]
          rw [h_pre]
          have hne1 : ¬ (iter.start.val + 1 ≤ m) := by scalar_tac
          have hne2 : ¬ (iter.start.val ≤ m) := by scalar_tac
          simp [hne1, hne2]
        · have h_gt : iter.start.val < m := by scalar_tac
          by_cases h_end : m < iter.«end».val
          · -- iter.start < m < iter.end: write branch on both sides.
            have h1 : iter.start.val + 1 ≤ m := by scalar_tac
            have h2 : iter.start.val ≤ m := by scalar_tac
            simp [h1, h2, h_end]
          · -- m ≥ iter.end: LHS via suffix = out.extract; RHS frame = out.extract.
            have h_suf : (out.val.setSlice! (iter.start.val * 8)
                            ((BitVec.toLEBytes
                              ((self.state[iter.start.val]'(by scalar_tac)).val[inst.val]'(by
                                have := (self.state[iter.start.val]'(by scalar_tac)).property;
                                scalar_tac)).bv).map (fun bv => (⟨bv⟩ : U8)))).extract
                          (m * 8) (m * 8 + 8)
                        = out.val.extract (m * 8) (m * 8 + 8) := by
              simp only [List.extract_eq_take_drop]
              apply List.ext_getElem
              · simp only [List.length_take, List.length_drop, List.length_setSlice!]
              · intro j h1 h2
                simp only [List.getElem_take, List.getElem_drop]
                have hj : j < 8 := by
                  have := h1
                  simp only [List.length_take, List.length_drop,
                             List.length_setSlice!, hLenOut] at this
                  scalar_tac
                rw [List.getElem_setSlice!_suffix _ _ _ _
                      ⟨by rw [hY]; scalar_tac, by scalar_tac⟩]
            rw [h_suf]
            simp [show ¬ m < iter.«end».val from h_end]
    · -- r.drop (iter.end*8) = out.drop (iter.end*8)
      rw [hend'] at hr_drop
      rw [hr_drop, h_out']
      -- Need: (out.setSlice! (iter.start*8) Y).drop (iter.end*8) = out.drop (iter.end*8)
      apply List.ext_getElem
      · simp [List.length_drop, List.length_setSlice!]
      · intro j h1 h2
        simp only [List.getElem_drop]
        rw [List.getElem_setSlice!_suffix _ _ _ _
              ⟨by simp [BitVec.toLEBytes]; scalar_tac, by scalar_tac⟩]
  · -- none branch: iterator exhausted; loop returns out unchanged.
    have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← IteratorRange_next_none iter (by scalar_tac)
    rw [hnone]
    rw [sha3.keccak4x.Keccak4x.extract_bytes_loop.match_helper_branch_eq]
    simp only [WP.spec_ok]
    have heq : iter.start.val = iter.«end».val := by scalar_tac
    refine ⟨?_, ?_, ?_⟩
    · trivial
    · intro m hm
      have h1 : ¬ (iter.start.val ≤ m ∧ m < iter.«end».val) := by
        rintro ⟨h_lo, h_hi⟩
        scalar_tac
      simp [h1]
    · trivial

/-- **Informal proof** (`extract_bytes` wrapper — `Funs.lean:23433-23444`).
    Body: 3 `massert`s, then call `extract_bytes_loop {start := 0, end := lane_count} self inst out`.
    Lemma chain: `extract_bytes_loop.spec` with `iter.start = 0`,
    `iter.end = lane_count` — the loop's universally-quantified
    `if 0 ≤ k < lane_count then WRITTEN else FRAME` specialises to the
    wrapper's per-`Fin lane_count.val` WRITTEN clause + the tail-frame
    `drop` clause.
    Proof: `unfold extract_bytes; step* (loop spec); refine; simp`. -/
@[step]
theorem extract_bytes.spec
    (self : sha3.keccak4x.Keccak4x) (inst : Std.Usize)
    (out : Slice U8) (lane_count : Std.Usize)
    (hInst : inst.val < 4)
    (hOut : out.length ≥ lane_count.val * 8)
    (hLanes : lane_count.val ≤ 25) :
    sha3.keccak4x.Keccak4x.extract_bytes self inst out lane_count
    ⦃ (r : Slice U8) =>
        r.length = out.length ∧
        (∀ i : Fin lane_count.val,
          (r.val.extract (i.val * 8) (i.val * 8 + 8))
            = (BitVec.toLEBytes ((self.state[i.val]'(by scalar_tac)).val[inst.val]'(by
                have := (self.state[i.val]'(by scalar_tac)).property;
                scalar_tac)).bv).map fun bv => (⟨bv⟩ : U8)) ∧
        r.val.drop (lane_count.val * 8) = out.val.drop (lane_count.val * 8) ⦄ := by
  unfold sha3.keccak4x.Keccak4x.extract_bytes
  step*

end Keccak4x

/-! ## Hybrid (AVX2) variant — `sha3.keccak4x_hybrid.Keccak4xHybrid`

Identical semantics to the safe variant on these wrappers; only
`permute` open-codes `rol` via 3 AVX2 intrinsics.  No new ghost state
or trust on this layer. -/

namespace Keccak4xHybrid

/-- **Informal proof.**
    Body (`Funs.lean:23464-23477`): same `Default::default` shape as the
    safe variant.  Proof: `unfold new; rfl`. -/
@[step]
theorem new.spec :
    sha3.keccak4x_hybrid.Keccak4xHybrid.new
    ⦃ (r : sha3.keccak4x_hybrid.Keccak4xHybrid) =>
        r.state = Array.repeat 25#usize (Array.repeat 4#usize 0#u64) ⦄ := by
  unfold sha3.keccak4x_hybrid.Keccak4xHybrid.new
  unfold sha3.keccak4x_hybrid.Keccak4xHybrid.Insts.CoreDefaultDefault.default
  unfold sha3.keccak4x_hybrid.Lane4.Insts.CoreDefaultDefault.default
  simp [WP.spec_ok]

/-- **Informal proof.**
    Body (`Funs.lean:23497-23508`): identical algebraic shape to the safe
    `xor_lane` but WITHOUT the `massert`s (the hybrid relies on caller
    discipline).  The 4 inner monadic calls are the same:
    `Array.index_usize` ×2, `lift (· ^^^ ·)`, `Array.update`, outer
    `Array.update`.

    Lemma chain identical to safe `xor_lane.spec`; preconditions `hPos`
    and `hInst` discharge the `index_usize` and `update` bounds.
    Proof: `unfold xor_lane; step ×5; simp [Array.getElem_update_*]; agrind`. -/
@[step]
theorem xor_lane.spec
    (self : sha3.keccak4x_hybrid.Keccak4xHybrid) (pos inst : Std.Usize)
    (value : U64) (hPos : pos.val < 25) (hInst : inst.val < 4) :
    sha3.keccak4x_hybrid.Keccak4xHybrid.xor_lane self pos inst value
    ⦃ (r : sha3.keccak4x_hybrid.Keccak4xHybrid) =>
        ∀ p : Fin 25, ∀ k : Fin 4,
          ((r.state[p]'(by scalar_tac)).val[k.val]'(by
              have := (r.state[p]'(by scalar_tac)).property; scalar_tac))
            = if p.val = pos.val ∧ k.val = inst.val then
                ((self.state[p]'(by scalar_tac)).val[k.val]'(by
                  have := (self.state[p]'(by scalar_tac)).property; scalar_tac))
                  ^^^ value
              else
                ((self.state[p]'(by scalar_tac)).val[k.val]'(by
                  have := (self.state[p]'(by scalar_tac)).property; scalar_tac)) ⦄ := by
  unfold sha3.keccak4x_hybrid.Keccak4xHybrid.xor_lane
  step*
  have heq : i1 = i ^^^ value := by scalar_tac
  intro p k
  simp [l1_post2, a_post]
  by_cases hp : p.val = pos.val
  · simp_lists
    by_cases hk : k.val = inst.val
    · simp [hp, hk, heq, i_post, l_post]
    · simp [hp, hk, l1_post1]
  · simp [hp]

@[step]
theorem get_lane.spec
    (self : sha3.keccak4x_hybrid.Keccak4xHybrid) (pos inst : Std.Usize)
    (hPos : pos.val < 25) (hInst : inst.val < 4) :
    sha3.keccak4x_hybrid.Keccak4xHybrid.get_lane self pos inst
    ⦃ (r : U64) =>
        r = (self.state[pos]'(by scalar_tac)).val[inst.val]'(by
          have := (self.state[pos]'(by scalar_tac)).property; scalar_tac) ⦄ := by
  unfold sha3.keccak4x_hybrid.Keccak4xHybrid.get_lane
  step*
  simp_lists [l_post, r_post]

/-! ## `#decompose` cascade for hybrid `extract_bytes_loop` (mirrors safe variant) -/

set_option maxRecDepth 1024 in
#decompose sha3.keccak4x_hybrid.Keccak4xHybrid.extract_bytes_loop
    sha3.keccak4x_hybrid.Keccak4xHybrid.extract_bytes_loop.match_helper_eq
  letRange 1 1 => sha3.keccak4x_hybrid.Keccak4xHybrid.extract_bytes_loop.match_helper

set_option maxRecDepth 2048 in
#decompose sha3.keccak4x_hybrid.Keccak4xHybrid.extract_bytes_loop.match_helper
    sha3.keccak4x_hybrid.Keccak4xHybrid.extract_bytes_loop.match_helper_branch_eq
  branch 1 (letRange 0 9) => sha3.keccak4x_hybrid.Keccak4xHybrid.extract_bytes_loop.some_body

@[step]
theorem extract_bytes_loop.some_body.spec
    (self : sha3.keccak4x_hybrid.Keccak4xHybrid) (inst : Std.Usize)
    (out : Slice U8) (i : Std.Usize)
    (hInst : inst.val < 4)
    (hi : i.val < 25)
    (hOut : out.length ≥ i.val * 8 + 8) :
    sha3.keccak4x_hybrid.Keccak4xHybrid.extract_bytes_loop.some_body self inst out i
    ⦃ (r : Slice U8) =>
        r.length = out.length ∧
        r.val
          = out.val.setSlice! (i.val * 8)
              ((BitVec.toLEBytes ((self.state[i.val]'(by scalar_tac)).val[inst.val]'(by
                have := (self.state[i.val]'(by scalar_tac)).property;
                scalar_tac)).bv).map (fun bv => (⟨bv⟩ : U8))) ⦄ := by
  unfold sha3.keccak4x_hybrid.Keccak4xHybrid.extract_bytes_loop.some_body
  step*
  refine ⟨?_, ?_⟩
  · simp [s_post3, List.length_setSlice!]
  · simp_lists [s_post3, s2_post, s1_post, a_post, i3_post, l_post, i1_post]

/-- **Informal proof** (loop spec — hybrid `extract_bytes_loop` body,
    `Funs.lean:24390-24428`).  Algebraically identical to the safe variant.
    Spec mirrors `Keccak4x.extract_bytes_loop.spec` verbatim. -/
@[step]
theorem extract_bytes_loop.spec
    (iter : core.ops.range.Range Std.Usize)
    (self : sha3.keccak4x_hybrid.Keccak4xHybrid)
    (inst : Std.Usize) (out : Slice U8)
    (hInst : inst.val < 4)
    (hStart : iter.start.val ≤ iter.«end».val)
    (hEnd : iter.«end».val ≤ 25)
    (hOut : out.length ≥ iter.«end».val * 8) :
    sha3.keccak4x_hybrid.Keccak4xHybrid.extract_bytes_loop iter self inst out
    ⦃ (r : Slice U8) =>
        r.length = out.length ∧
        (∀ (m : Nat) (hm : m < 25),
          r.val.extract (m * 8) (m * 8 + 8)
            = if iter.start.val ≤ m ∧ m < iter.«end».val then
                (BitVec.toLEBytes ((self.state[m]'(by scalar_tac)).val[inst.val]'(by
                  have := (self.state[m]'(by scalar_tac)).property;
                  scalar_tac)).bv).map (fun bv => (⟨bv⟩ : U8))
              else
                out.val.extract (m * 8) (m * 8 + 8)) ∧
        r.val.drop (iter.«end».val * 8) = out.val.drop (iter.«end».val * 8) ⦄ := by
  rw [sha3.keccak4x_hybrid.Keccak4xHybrid.extract_bytes_loop.match_helper_eq]
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← IteratorRange_next_some iter hlt
    rw [hsome]
    rw [sha3.keccak4x_hybrid.Keccak4xHybrid.extract_bytes_loop.match_helper_branch_eq]
    have hi : iter.start.val < 25 := by scalar_tac
    have hOut' : out.length ≥ iter.start.val * 8 + 8 := by scalar_tac
    let* ⟨ out', h_len, h_out' ⟩ ←
      extract_bytes_loop.some_body.spec self inst out iter.start hInst hi hOut'
    have hStart1 : iter1.start.val ≤ iter1.«end».val := by
      rw [hstart', hend']; scalar_tac
    have hEnd1 : iter1.«end».val ≤ 25 := by rw [hend']; exact hEnd
    have hOut1 : out'.length ≥ iter1.«end».val * 8 := by
      rw [hend', h_len]; exact hOut
    apply WP.spec_mono
      (extract_bytes_loop.spec iter1 self inst out' hInst hStart1 hEnd1 hOut1)
    intro r ⟨hr_len, hr_extract, hr_drop⟩
    refine ⟨?_, ?_, ?_⟩
    · rw [hr_len, h_len]
    · intro m hm
      have hY : ((BitVec.toLEBytes
                    ((self.state[iter.start.val]'(by scalar_tac)).val[inst.val]'(by
                      have := (self.state[iter.start.val]'(by scalar_tac)).property;
                      scalar_tac)).bv).map (fun bv => (⟨bv⟩ : U8))).length = 8 := by
        simp [BitVec.toLEBytes]
      have hLenOut : out.val.length = out.length := rfl
      have hex := hr_extract m hm
      rw [hex, hstart', hend', h_out']
      by_cases h_eq : m = iter.start.val
      · subst h_eq
        have h_mid : (out.val.setSlice! (iter.start.val * 8)
                        ((BitVec.toLEBytes
                          ((self.state[iter.start.val]'(by scalar_tac)).val[inst.val]'(by
                            have := (self.state[iter.start.val]'(by scalar_tac)).property;
                            scalar_tac)).bv).map (fun bv => (⟨bv⟩ : U8)))).extract
                      (iter.start.val * 8) (iter.start.val * 8 + 8)
                    = (BitVec.toLEBytes
                        ((self.state[iter.start.val]'(by scalar_tac)).val[inst.val]'(by
                          have := (self.state[iter.start.val]'(by scalar_tac)).property;
                          scalar_tac)).bv).map (fun bv => (⟨bv⟩ : U8)) := by
          simp only [List.extract_eq_take_drop]
          apply List.ext_getElem
          · simp only [List.length_take, List.length_drop, List.length_setSlice!, hLenOut, hY]
            scalar_tac
          · intro j h1 h2
            simp only [List.getElem_take, List.getElem_drop]
            have hj : j < 8 := by
              have := h1
              simp only [List.length_take, List.length_drop,
                         List.length_setSlice!, hLenOut] at this
              scalar_tac
            rw [List.getElem_setSlice!_middle _ _ _ _
                  ⟨by scalar_tac, by rw [hY]; scalar_tac, by scalar_tac⟩]
            congr 1
            scalar_tac
        rw [h_mid]
        have hne : ¬ (iter.start.val + 1 ≤ iter.start.val) := by scalar_tac
        simp [hne, hlt]
      · by_cases h_lt : m < iter.start.val
        · have h_pre : (out.val.setSlice! (iter.start.val * 8)
                          ((BitVec.toLEBytes
                            ((self.state[iter.start.val]'(by scalar_tac)).val[inst.val]'(by
                              have := (self.state[iter.start.val]'(by scalar_tac)).property;
                              scalar_tac)).bv).map (fun bv => (⟨bv⟩ : U8)))).extract
                        (m * 8) (m * 8 + 8)
                      = out.val.extract (m * 8) (m * 8 + 8) := by
            simp only [List.extract_eq_take_drop]
            apply List.ext_getElem
            · simp only [List.length_take, List.length_drop, List.length_setSlice!]
            · intro j h1 h2
              simp only [List.getElem_take, List.getElem_drop]
              have hj : j < 8 := by
                have := h1
                simp only [List.length_take, List.length_drop,
                           List.length_setSlice!, hLenOut] at this
                scalar_tac
              rw [List.getElem_setSlice!_prefix _ _ _ _
                    ⟨by scalar_tac, by scalar_tac⟩]
          rw [h_pre]
          have hne1 : ¬ (iter.start.val + 1 ≤ m) := by scalar_tac
          have hne2 : ¬ (iter.start.val ≤ m) := by scalar_tac
          simp [hne1, hne2]
        · have h_gt : iter.start.val < m := by scalar_tac
          by_cases h_end : m < iter.«end».val
          · have h1 : iter.start.val + 1 ≤ m := by scalar_tac
            have h2 : iter.start.val ≤ m := by scalar_tac
            simp [h1, h2, h_end]
          · have h_suf : (out.val.setSlice! (iter.start.val * 8)
                            ((BitVec.toLEBytes
                              ((self.state[iter.start.val]'(by scalar_tac)).val[inst.val]'(by
                                have := (self.state[iter.start.val]'(by scalar_tac)).property;
                                scalar_tac)).bv).map (fun bv => (⟨bv⟩ : U8)))).extract
                          (m * 8) (m * 8 + 8)
                        = out.val.extract (m * 8) (m * 8 + 8) := by
              simp only [List.extract_eq_take_drop]
              apply List.ext_getElem
              · simp only [List.length_take, List.length_drop, List.length_setSlice!]
              · intro j h1 h2
                simp only [List.getElem_take, List.getElem_drop]
                have hj : j < 8 := by
                  have := h1
                  simp only [List.length_take, List.length_drop,
                             List.length_setSlice!, hLenOut] at this
                  scalar_tac
                rw [List.getElem_setSlice!_suffix _ _ _ _
                      ⟨by rw [hY]; scalar_tac, by scalar_tac⟩]
            rw [h_suf]
            simp [show ¬ m < iter.«end».val from h_end]
    · rw [hend'] at hr_drop
      rw [hr_drop, h_out']
      apply List.ext_getElem
      · simp [List.length_drop, List.length_setSlice!]
      · intro j h1 h2
        simp only [List.getElem_drop]
        rw [List.getElem_setSlice!_suffix _ _ _ _
              ⟨by simp [BitVec.toLEBytes]; scalar_tac, by scalar_tac⟩]
  · have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← IteratorRange_next_none iter (by scalar_tac)
    rw [hnone]
    rw [sha3.keccak4x_hybrid.Keccak4xHybrid.extract_bytes_loop.match_helper_branch_eq]
    simp only [WP.spec_ok]
    have heq : iter.start.val = iter.«end».val := by scalar_tac
    refine ⟨?_, ?_, ?_⟩
    · trivial
    · intro m hm
      have h1 : ¬ (iter.start.val ≤ m ∧ m < iter.«end».val) := by
        rintro ⟨h_lo, h_hi⟩
        scalar_tac
      simp [h1]
    · trivial

/-- **Informal proof** (hybrid `extract_bytes` wrapper).
    Same shape as safe `extract_bytes.spec`: massertions, then call
    `extract_bytes_loop` from 0 to `lane_count`.  Not consumed by Shake4x
    (which scatters lanes manually in `extract_all`); kept for surface
    parity. -/
@[step]
theorem extract_bytes.spec
    (self : sha3.keccak4x_hybrid.Keccak4xHybrid) (inst : Std.Usize)
    (out : Slice U8) (lane_count : Std.Usize)
    (hInst : inst.val < 4)
    (hOut : out.length ≥ lane_count.val * 8)
    (hLanes : lane_count.val ≤ 25) :
    sha3.keccak4x_hybrid.Keccak4xHybrid.extract_bytes self inst out lane_count
    ⦃ (r : Slice U8) =>
        r.length = out.length ∧
        (∀ i : Fin lane_count.val,
          (r.val.extract (i.val * 8) (i.val * 8 + 8))
            = (BitVec.toLEBytes ((self.state[i.val]'(by scalar_tac)).val[inst.val]'(by
                have := (self.state[i.val]'(by scalar_tac)).property;
                scalar_tac)).bv).map fun bv => (⟨bv⟩ : U8)) ∧
        r.val.drop (lane_count.val * 8) = out.val.drop (lane_count.val * 8) ⦄ := by
  unfold sha3.keccak4x_hybrid.Keccak4xHybrid.extract_bytes
  step*

end Keccak4xHybrid

end symcrust
