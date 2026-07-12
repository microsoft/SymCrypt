/-
# Properties/SHA3/Shake4x/Extract — squeeze surface for `Shake4x`.

All `@[step]` theorems below have real, vacuity-checked
postconditions.

## Surface

  * `extract_all self`            — staging helper: writes one full rate
                                    block per instance into `self.buf`
                                    (internal helper; used by
                                    `finalize_all` and `next_block`).
  * `block self inst`             — returns `buf[inst][0..rate]` as a
                                    slice (precondition: `finalized`).
  * `next_block self`             — permute + extract_all → fresh buffers.
  * `next_block_no_extract self`  — permute only; output via `state_ref`.
  * `state_ref self`              — returns a reference to the inner
                                    `Keccak4xHybrid` so callers can read
                                    individual u64 lanes via `get_lane`.

`block i` consumes `rate` squeezed bytes from instance `i`'s ghost
state.  `next_block_*` consumes a full rate block from EVERY instance
(in lockstep, by issuing one fused permute).

The MLKEM-4x consumer pattern uses `state_ref → get_lane` for the fast
path (no buffer copy) and `block` for the buffered path.  MLDSA-4x is
expected to mirror this.
-/
import Symcrust.Code
import Symcrust.Properties.SHA3.Basic
import Symcrust.Properties.SHA3.Shake4x.Basic
import Symcrust.Properties.SHA3.Shake4x.Bridges
import Symcrust.Properties.SHA3.Shake4x.Finalize

namespace symcrust

open Aeneas Aeneas.Std Result
open sha3.sha3_impl

set_option linter.unusedSectionVars false
set_option linter.unusedVariables false
set_option maxHeartbeats 2000000

/-! **Informal proof** (loop spec — `extract_all_loop`,
    `Funs.lean:25018-25083`).
    Per iteration at cursor `lane : Std.Usize` (lanes 0..rate_lanes):
      1. `IteratorRange.next`.
      2. `Keccak4xHybrid.get_lane kxh lane 0..3` — read the 4 u64s at
         lane `lane` for each instance (apply `get_lane.spec` × 4).
      3. `lane * 8` → `off` (start of the 8-byte window in each buf).
      4. For each instance `k : Fin 4` (unrolled at lines 25037-25081):
         a. `Array.index_mut_usize a k` — get `a[k]` (= `buf[k]`).
         b. Slice it as `[off..off+8]` via `index_mut`.
         c. Read `i_k` (the just-read u64 lane for instance k) from
            the 4-element scratch array.
         d. `U64.to_le_bytes i_k` → 8-byte array.
         e. `Slice.copy_from_slice` overwrites the window.
         f. Two `index_mut_back`s reassemble `a` with `a[k]` updated.
      5. Recursive IH on `extract_all_loop iter1 kxh a'`.

    **Loop invariant** (per-iteration form at cursor `iter.start.val`):
    for every instance `k : Fin 4` and every lane index `m < 25`,
      * if `iter.start.val ≤ m ∧ m < iter.«end».val`, the 8-byte
        window `r.buf[k][m*8..(m+1)*8]` equals the LE bytes of
        `kxh.state[m].val[k.val]` (the input-state lane bits for
        instance k);
      * otherwise (before iter.start, or at/after iter.end), the
        window is unchanged from the input `a[k]`.

    **Lemma chain in call order** (per lane iteration):
      `IteratorRange.next.spec`, `Keccak4xHybrid.get_lane.spec` (×4),
      `Usize.mul.spec`, `Array.index_mut_usize.spec` (×4),
      `Array.index_mut.spec` (slice range, ×4),
      `Usize.add.spec`, `U64.to_le_bytes.spec`, `Array.to_slice.spec`,
      `Slice.copy_from_slice.spec` (×4), recursive IH. -/

/-! ## `#decompose` cascade for `extract_all_loop`

The loop body has two phases:
1. Iterator step (`IteratorRange.next`) — binding 0 of the do-block.
2. `match` on the iterator result — binding 1 (terminal).  The `some`
   arm performs 4×get_lane + 4 lane-window writes (38 monadic bindings)
   then recurses.

The cascade extracts:
- `match_helper`: the post-iterator-step match (factors out the
  iterator prologue).
- `some_body`: the 38-binding per-lane write sequence (factors out the
  recursive call), so the loop proof can compose a single `some_body.spec`
  with the iterator and IH.
-/

set_option maxRecDepth 1024 in
#decompose sha3.shake4x.Shake4x.extract_all_loop
    sha3.shake4x.Shake4x.extract_all_loop.match_helper_eq
  letRange 1 1 => sha3.shake4x.Shake4x.extract_all_loop.match_helper

set_option maxRecDepth 2048 in
#decompose sha3.shake4x.Shake4x.extract_all_loop.match_helper
    sha3.shake4x.Shake4x.extract_all_loop.match_helper_branch_eq
  branch 1 (letRange 0 38) => sha3.shake4x.Shake4x.extract_all_loop.some_body

/-- Per-lane helper spec: `some_body kxh a lane` performs the 4-instance
    write of `kxh.state[lane]`'s 4 u64 lanes into the 8-byte window
    `[lane*8 .. lane*8+8]` of each `a[k]` (instance `k : Fin 4`).
    Other byte windows are unchanged.

    The post pins `r.val[k]` as `a.val[k]` with the 8-byte window
    `[lane*8..lane*8+8]` overwritten by the LE bytes of
    `kxh.state[lane][k]`.  Consumers can derive per-window `extract`
    equations from this structural form.
-/
@[step]
theorem Shake4x.extract_all_loop.some_body.spec
    (kxh : sha3.keccak4x_hybrid.Keccak4xHybrid)
    (a : Array (Array Std.U8 168#usize) 4#usize)
    (lane : Std.Usize)
    (hLane : lane.val * 8 + 8 ≤ 168) :
    sha3.shake4x.Shake4x.extract_all_loop.some_body kxh a lane
    ⦃ (r : Array (Array Std.U8 168#usize) 4#usize) =>
        ∀ (k : Fin 4),
          (r.val[k.val]'(by have := a.property; scalar_tac)).val
            = (a.val[k.val]'(by have := a.property; scalar_tac)).val.setSlice!
                (lane.val * 8)
                ((BitVec.toLEBytes
                  ((kxh.state[lane.val]'(by scalar_tac)).val[k.val]'(by
                    have := (kxh.state[lane.val]'(by scalar_tac)).property;
                    scalar_tac)).bv).map (fun bv => (⟨bv⟩ : Std.U8))) ⦄ := by
  unfold sha3.shake4x.Shake4x.extract_all_loop.some_body
  step*
  · agrind
  · agrind
  intro k
  rw [a13_post2, a9_post2, a5_post2, a1_post2]
  fin_cases k <;> (simp [*]; (try rfl))

@[step]
theorem Shake4x.extract_all_loop.spec
    (iter : core.ops.range.Range Std.Usize)
    (kxh : sha3.keccak4x_hybrid.Keccak4xHybrid)
    (a : Array (Array Std.U8 168#usize) 4#usize)
    (hStart : iter.start.val ≤ iter.«end».val)
    (hEnd : iter.«end».val * 8 ≤ 168) :
    sha3.shake4x.Shake4x.extract_all_loop iter kxh a
    ⦃ (r : Array (Array Std.U8 168#usize) 4#usize) =>
        ∀ (k : Fin 4) (m : Nat) (hm : m < 25),
          (r.val[k.val]'(by have := a.property; scalar_tac)).val.extract
              (m * 8) (m * 8 + 8)
            = if iter.start.val ≤ m ∧ m < iter.«end».val then
                (BitVec.toLEBytes
                  ((kxh.state[m]'(by scalar_tac)).val[k.val]'(by
                    have := (kxh.state[m]'(by scalar_tac)).property;
                    scalar_tac)).bv).map (fun bv => (⟨bv⟩ : Std.U8))
              else
                (a.val[k.val]'(by have := a.property; scalar_tac)).val.extract
                  (m * 8) (m * 8 + 8) ⦄ := by
  rw [sha3.shake4x.Shake4x.extract_all_loop.match_helper_eq]
  by_cases hlt : iter.start.val < iter.«end».val
  · -- some branch: iterator yields lane = iter.start
    let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← IteratorRange_next_some iter hlt
    rw [hsome]
    rw [sha3.shake4x.Shake4x.extract_all_loop.match_helper_branch_eq]
    have hLane : iter.start.val * 8 + 8 ≤ 168 := by scalar_tac
    let* ⟨ a', h_a' ⟩ ← Shake4x.extract_all_loop.some_body.spec kxh a iter.start hLane
    -- Recurse via IH at iter1; iter1.start = iter.start + 1, iter1.end = iter.end.
    have hStart1 : iter1.start.val ≤ iter1.«end».val := by
      rw [hstart', hend']; scalar_tac
    have hEnd1 : iter1.«end».val * 8 ≤ 168 := by rw [hend']; exact hEnd
    apply WP.spec_mono
      (Shake4x.extract_all_loop.spec iter1 kxh a' hStart1 hEnd1)
    intro r hr k m hm
    have ih := hr k m hm
    have h_ak := h_a' k
    rw [ih, hstart', hend', h_ak]
    -- Now goal:
    --   if iter.start+1 ≤ m ∧ m < iter.end then write_m
    --     else (a[k].val.setSlice! (iter.start*8) Y_iter).extract (m*8) (m*8+8)
    --   = if iter.start ≤ m ∧ m < iter.end then write_m else a[k].val.extract (m*8) (m*8+8)
    have hY : ((BitVec.toLEBytes
                  ((kxh.state[iter.start.val]'(by scalar_tac)).val[k.val]'(by
                    have := (kxh.state[iter.start.val]'(by scalar_tac)).property;
                    scalar_tac)).bv).map (fun bv => (⟨bv⟩ : Std.U8))).length = 8 := by
      simp [BitVec.toLEBytes]
    have hLenA : (a.val[k.val]'(by have := a.property; scalar_tac)).val.length = 168 := by
      have := (a.val[k.val]'(by have := a.property; scalar_tac)).property
      scalar_tac
    by_cases h_eq : m = iter.start.val
    · -- m = iter.start.val: LHS via middle = Y; RHS write branch = Y.
      subst h_eq
      have h_mid : (((a.val[k.val]'(by have := a.property; scalar_tac)).val.setSlice!
                      (iter.start.val * 8)
                      ((BitVec.toLEBytes
                        ((kxh.state[iter.start.val]'(by scalar_tac)).val[k.val]'(by
                          have := (kxh.state[iter.start.val]'(by scalar_tac)).property;
                          scalar_tac)).bv).map (fun bv => (⟨bv⟩ : Std.U8)))).extract
                    (iter.start.val * 8) (iter.start.val * 8 + 8))
                  = ((BitVec.toLEBytes
                      ((kxh.state[iter.start.val]'(by scalar_tac)).val[k.val]'(by
                        have := (kxh.state[iter.start.val]'(by scalar_tac)).property;
                        scalar_tac)).bv).map (fun bv => (⟨bv⟩ : Std.U8))) := by
        simp only [List.extract_eq_take_drop]
        apply List.ext_getElem
        · simp only [List.length_take, List.length_drop, List.length_setSlice!, hLenA, hY]
          scalar_tac
        · intro j h1 h2
          simp only [List.getElem_take, List.getElem_drop]
          have hj : j < 8 := by
            have := h1
            simp only [List.length_take, List.length_drop,
                       List.length_setSlice!, hLenA] at this
            scalar_tac
          rw [List.getElem_setSlice!_middle _ _ _ _
                ⟨by scalar_tac, by rw [hY]; scalar_tac, by scalar_tac⟩]
          congr 1
          scalar_tac
      rw [h_mid]
      simp [show ¬ (iter.start.val + 1 ≤ iter.start.val) from by scalar_tac, hlt]
    · by_cases h_lt : m < iter.start.val
      · -- m < iter.start: LHS via prefix = a.extract; RHS frame = a.extract.
        have h_pre : (((a.val[k.val]'(by have := a.property; scalar_tac)).val.setSlice!
                        (iter.start.val * 8)
                        ((BitVec.toLEBytes
                          ((kxh.state[iter.start.val]'(by scalar_tac)).val[k.val]'(by
                            have := (kxh.state[iter.start.val]'(by scalar_tac)).property;
                            scalar_tac)).bv).map (fun bv => (⟨bv⟩ : Std.U8)))).extract
                      (m * 8) (m * 8 + 8))
                    = (a.val[k.val]'(by have := a.property; scalar_tac)).val.extract
                      (m * 8) (m * 8 + 8) := by
          simp only [List.extract_eq_take_drop]
          apply List.ext_getElem
          · simp only [List.length_take, List.length_drop, List.length_setSlice!]
          · intro j h1 h2
            simp only [List.getElem_take, List.getElem_drop]
            have hj : j < 8 := by
              have := h1
              simp only [List.length_take, List.length_drop,
                         List.length_setSlice!, hLenA] at this
              scalar_tac
            rw [List.getElem_setSlice!_prefix _ _ _ _
                  ⟨by scalar_tac, by scalar_tac⟩]
        rw [h_pre]
        simp [show ¬ (iter.start.val + 1 ≤ m) from by scalar_tac,
              show ¬ (iter.start.val ≤ m) from by scalar_tac]
      · -- m > iter.start.val
        have h_gt : iter.start.val < m := by scalar_tac
        by_cases h_end : m < iter.«end».val
        · -- iter.start < m < iter.end: write branch on both sides.
          simp [show iter.start.val + 1 ≤ m from by scalar_tac,
                show iter.start.val ≤ m from by scalar_tac, h_end]
        · -- m ≥ iter.end: LHS via suffix = a.extract; RHS frame = a.extract.
          have h_suf : (((a.val[k.val]'(by have := a.property; scalar_tac)).val.setSlice!
                          (iter.start.val * 8)
                          ((BitVec.toLEBytes
                            ((kxh.state[iter.start.val]'(by scalar_tac)).val[k.val]'(by
                              have := (kxh.state[iter.start.val]'(by scalar_tac)).property;
                              scalar_tac)).bv).map (fun bv => (⟨bv⟩ : Std.U8)))).extract
                        (m * 8) (m * 8 + 8))
                      = (a.val[k.val]'(by have := a.property; scalar_tac)).val.extract
                        (m * 8) (m * 8 + 8) := by
            simp only [List.extract_eq_take_drop]
            apply List.ext_getElem
            · simp only [List.length_take, List.length_drop, List.length_setSlice!]
            · intro j h1 h2
              simp only [List.getElem_take, List.getElem_drop]
              have hj : j < 8 := by
                have := h1
                simp only [List.length_take, List.length_drop,
                           List.length_setSlice!, hLenA] at this
                scalar_tac
              rw [List.getElem_setSlice!_suffix _ _ _ _
                    ⟨by rw [hY]; scalar_tac, by scalar_tac⟩]
          rw [h_suf]
          simp [show ¬ m < iter.«end».val from h_end]
  · -- none branch: iterator exhausted; loop returns a unchanged.
    have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← IteratorRange_next_none iter (by scalar_tac)
    rw [hnone]
    rw [sha3.shake4x.Shake4x.extract_all_loop.match_helper_branch_eq]
    simp only [WP.spec_ok]
    intro k m hm
    have heq : iter.start.val = iter.«end».val := by scalar_tac
    simp [show ¬ (iter.start.val ≤ m ∧ m < iter.«end».val) from by scalar_tac]
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- **Informal proof** (`Shake4x.extract_all` wrapper,
    `Funs.lean:25087-25092`).
    Body (1 monadic call + record update):
      1. `a ← extract_all_loop {start := 0, end := self.rate_lanes}
                              self.state self.buf` — apply
         `extract_all_loop.spec` with `iter.start = 0`,
         `iter.end = self.rate_lanes`.  Bounds: `rate_lanes * 8 ≤ 168`
         from precondition `hRateLanes : rate_lanes * 8 = rate ≤ 168`.
      2. `ok { self with buf := a }`.

    **Post derivation**:
      * `state = self.state`: `kxh` is the loop's input-frame
        accumulator and is not mutated; the record update sets only
        `buf`.
      * `absorbed = self.absorbed`: orthogonal field.
      * **Buf equation** (added Scaffold-3 convergence): instantiate
        `extract_all_loop.spec` at `iter.start = 0`,
        `iter.end = self.rate_lanes`, `kxh = self.state`,
        `a = self.buf`.  Since `iter.start.val = 0`, the `frame`
        branch (`iter.start ≤ m` is trivial) collapses to a single
        `m < self.rate_lanes.val` check.  Bridging in this byte
        equation at the wrapper level lets downstream consumers
        (`finalize_all.spec`, `next_block.spec`) compose
        `permute → extract_all` and derive the FIPS-202 output
        bytes (`extractOutput …`) directly, via the spec-side
        `lanesToBytes` helper.

    **Scalar bridge**: the spec-side `lanesToBytes`
    converts a `Lane25` plus a `rate_lanes`
    parameter into the LE byte sequence consumed by
    `extractOutput`.  Lives in `Properties/SHA3/Basic.lean`.

    Discharge: `step extract_all_loop.spec; agrind`. -/
@[step]
theorem Shake4x.extract_all.spec
    (self : sha3.shake4x.Shake4x)
    (hRateLanes : self.rate_lanes.val * 8 = self.rate.val)
    (hRate : self.rate.val ≤ 168) :
    sha3.shake4x.Shake4x.extract_all self
    ⦃ (result : sha3.shake4x.Shake4x) =>
        result.state = self.state ∧
        result.rate = self.rate ∧
        result.rate_lanes = self.rate_lanes ∧
        result.absorbed = self.absorbed ∧
        result.finalized = self.finalized ∧
        /- Per-lane LE-byte equation, carried up from
           `extract_all_loop.spec` at `iter.start=0,
           iter.end=self.rate_lanes`. -/
        (∀ (k : Fin 4) (m : Nat) (hm : m < 25),
          (result.buf.val[k.val]'(by have := result.buf.property; scalar_tac)).val.extract
              (m * 8) (m * 8 + 8)
            = if m < self.rate_lanes.val then
                (BitVec.toLEBytes
                  ((self.state.state[m]'(by scalar_tac)).val[k.val]'(by
                    have := (self.state.state[m]'(by scalar_tac)).property;
                    scalar_tac)).bv).map (fun bv => (⟨bv⟩ : Std.U8))
              else
                (self.buf.val[k.val]'(by have := self.buf.property; scalar_tac)).val.extract
                  (m * 8) (m * 8 + 8)) ⦄ := by
  unfold sha3.shake4x.Shake4x.extract_all
  step*

/-- **Informal proof** (`Shake4x.block` wrapper, `Funs.lean:25113-25122`).
    Body (2 monadic calls + ok):
      1. `massert self.finalized` — discharged from precondition `hFin`.
      2. `Array.index_usize self.buf inst` — read `buf_k := buf[inst]`.
         Applies `Array.index_usize.spec`; precondition
         `inst.val < 4` from `hInst`.
      3. `Array.index (SliceIndexRange) buf_k {start := 0, end := rate}`
         — produces the slice `buf_k.val.extract 0 rate.val`.  Applies
         `Array.index.spec` for `RangeUsize`; precondition
         `rate.val ≤ 168 = buf_k.val.length` from `hRate`.

    **Post derivation**: `result.val = buf[inst].val.take rate.val`
    follows directly from the second step (since `extract 0 rate =
    take rate` on an `Array U8 168` whose underlying list has length 168).

    Caller-visible FIPS-202 byte recovery: chain `block.spec` with
    `finalize_all.spec` or `next_block.spec`, both of which now pin
    `buf[k][0..rate]` to `extractOutput …` directly.  No further
    bridge is owed.

    Discharge: `step ×3; simp [List.extract_eq_take]; rfl`. -/
@[step]
theorem Shake4x.block.spec
    (self : sha3.shake4x.Shake4x) (inst : Std.Usize)
    (hFin : self.finalized = true)
    (hInst : inst.val < 4)
    (hRate : self.rate.val ≤ 168) :
    sha3.shake4x.Shake4x.block self inst
    ⦃ (result : Slice Std.U8) =>
        let k' : Fin 4 := ⟨inst.val, hInst⟩
        result.val = (self.buf[k']).val.take self.rate.val ⦄ := by
  unfold sha3.shake4x.Shake4x.block
  step*
  rw [result_post1, a_post]; rfl

/-- **Informal proof** (`Shake4x.next_block` wrapper).
    Body (mirrors `finalize_all` minus the pad step):
      1. `kxh ← Keccak4xHybrid.permute self.state` —
         `Keccak4xHybrid.permute.spec`.  Yields one full 24-round
         permute applied to the post-previous-squeeze state.
      2. `self1 ← extract_all { self with state := kxh }` —
         `Shake4x.extract_all.spec`.  Stages the post-permute lane
         bytes into `buf`.
      3. `ok self1`.

    **Post derivation**:
      * Frame conjuncts (`rate`, `rate_lanes`, `absorbed`): preserved
        through both steps (`permute` only touches `state`;
        `extract_all` preserves both per its spec).
      * `Shake4x.squeezing result (fun k => (gs k).squeezeAdvance rate)`:
        the ghost-state advance by `rate` mirrors the spec-side
        `Spec.SHA3.SPONGE_squeeze` advancing the squeezed-byte
        counter.  Per-lane derivation: the post-permute state for
        instance `k` corresponds to the next FIPS-202 squeeze block
        for the same instance, hence `squeezing` at
        `(gs k).squeezeAdvance rate`.  Bridge via
        `keccak_permute_toBits + GhostState.squeezeAdvance` per the
        scalar squeeze stream (`Properties/SHA3/Sponge/BridgeBitFC.lean`).
      * `buf[k][0..rate] = (extractOutput ((gs k).squeezeAdvance rate)
                              rate).toList`: same bridge composes the
        per-lane LE byte content with the advanced ghost.

    **Spec-side bridges**:
      * `rol4_correct`.
      * `keccak_permute_toBits`, `GhostState.squeezeAdvance`,
        `extractOutput`.

    Discharge: `step ×2; obtain ⟨hWF, _, _, _⟩ := hSqu;
    refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> agrind`. -/
@[step]
theorem Shake4x.next_block.spec
    (self : sha3.shake4x.Shake4x)
    (gs : Fin 4 → GhostState)
    (hSqu : Shake4x.squeezing self gs) :
    sha3.shake4x.Shake4x.next_block self
    ⦃ (result : sha3.shake4x.Shake4x) =>
        result.rate = self.rate ∧
        result.rate_lanes = self.rate_lanes ∧
        result.absorbed = self.absorbed ∧
        Shake4x.squeezing result
          (fun k => (gs k).squeezeAdvance self.rate.val) ∧
        (∀ k : Fin 4,
          (result.buf[k]).val.take self.rate.val
            = (extractOutput ((gs k).squeezeAdvance self.rate.val)
                self.rate.val).toList) ⦄ := by
  unfold sha3.shake4x.Shake4x.next_block
  obtain ⟨hWF, hFin, hCons, hRate, hAlign, hPer⟩ := hSqu
  step*
  case hRate => rcases hWF.1 with h | h <;> simp [h]
  -- Frame and squeezing now follow from the bridge plus a record
  -- congruence (extract_all changes only `buf`).  The buf-bytes
  -- equation remains: requires a new bridge from the per-lane LE byte
  -- output of `extract_all` to `extractOutput` over the eager-permuted
  -- squeeze stream.
  refine ⟨result_post2, result_post3, result_post4, ?_, ?_⟩
  · -- squeezing
    have hbridge := Shake4x.squeezing_advance_permute self kxh gs
      ⟨hWF, hFin, hCons, hRate, hAlign, hPer⟩ kxh_post2
    rw [hFin] at hbridge
    exact (Shake4x.squeezing_record_eq
            (self := { self with state := kxh, finalized := true })
            (self' := result)
            result_post1.symm result_post2.symm
            result_post3.symm result_post4.symm
            result_post5.symm).mp hbridge
  · -- buf equation: chain Bridge A (extractOutput → squeezeBytes), then
    -- the per-instance eager equation (from squeezing_advance_permute),
    -- then Bridge B (squeezeBytes of full block → flatMap of lane LE bytes),
    -- and finally chunk-match the LHS via result_post6 + projectLane reindex.
    intro k
    have hWFra : self.rate_lanes.val * 8 = self.rate.val := hWF.2.1
    have hWFr2 : self.rate = 168#usize ∨ self.rate = 136#usize := hWF.1
    have hrate_lanes_le : self.rate_lanes.val ≤ 25 := by
      rcases hWFr2 with h | h <;> rw [h] at hWFra <;> simp at hWFra <;> omega
    have hrate_decomp : self.rate.val = 8 * self.rate_lanes.val := by omega
    have hrate_le168 : self.rate.val ≤ 168 := by
      rcases hWFr2 with h | h <;> rw [h] <;> decide
    -- Bridge A: extractOutput → squeezeBytes
    have hRate_k : (gs k).rate = self.rate.val := hRate k
    have hAlign_k : (gs k).squeezed.length % (gs k).rate = 0 := hAlign k
    have hBridgeA :
        (extractOutput ((gs k).squeezeAdvance self.rate.val) self.rate.val).toList =
        (squeezeBytes (Shake4x.eagerSqueezeState ((gs k).squeezeAdvance self.rate.val))
                      0 self.rate.val self.rate.val).toList := by
      conv_lhs => rw [show self.rate.val = (gs k).rate from hRate_k.symm]
      conv_rhs => rw [show self.rate.val = (gs k).rate from hRate_k.symm]
      exact extractOutput_at_boundary (gs k) hAlign_k
    rw [hBridgeA]
    -- Pull the per-instance eager-state equation from squeezing_advance_permute.
    have hbridge := Shake4x.squeezing_advance_permute self kxh gs
      ⟨hWF, hFin, hCons, hRate, hAlign, hPer⟩ kxh_post2
    obtain ⟨_, _, _, _, _, hInvNew⟩ := hbridge
    have hEager_k : toBits (Keccak4xHybrid.projectLane k kxh.state).toArray =
                    Shake4x.eagerSqueezeState ((gs k).squeezeAdvance self.rate.val) :=
      (hInvNew k).1
    rw [← hEager_k]
    -- Bridge B: squeezeBytes (toBits a) 0 (8r) (8r) = flatMap of lane LE bytes.
    rw [hrate_decomp, squeezeBytes_full_block_eq_lanes _ self.rate_lanes.val hrate_lanes_le]
    -- LHS: chunk via take_eq_flatMap_extract_chunks.
    have h_buf_k_eq : (result.buf[k]).val = (result.buf.val[k.val]'(by
        have := result.buf.property; scalar_tac)).val := by rfl
    have h_buf_len : (result.buf[k]).val.length = 168 := by
      rw [h_buf_k_eq]; exact (result.buf.val[k.val]'(by
        have := result.buf.property; scalar_tac)).property
    rw [take_eq_flatMap_extract_chunks _ self.rate_lanes.val (by rw [h_buf_len]; omega)]
    -- RHS: convert `(take rl ...).flatMap g` to a finRange-indexed flatten.
    have h_lanes_len :
        (Keccak4xHybrid.projectLane k kxh.state).toArray.val.length = 25 := by
      simp [Lanes25.toArray, Array.make]
    rw [take_flatMap_eq_range_flatMap _ self.rate_lanes.val (by rw [h_lanes_len]; exact hrate_lanes_le)]
    -- Also convert LHS `(List.range rl).flatMap` into the same finRange flatten shape.
    rw [range_flatMap_eq_finRange_flatten]
    -- Now both sides have shape (finRange n).map _ |>.flatten ; reduce to pointwise.
    congr 1
    apply List.ext_getElem
    · simp
    · intro j hj1 _
      simp at hj1
      rw [List.getElem_map, List.getElem_map, List.getElem_finRange]
      have hj_25 : j < 25 := by omega
      simp only [Fin.cast_mk, Fin.val_mk]
      conv_lhs =>
        rw [show (result.buf[k]).val = (result.buf.val[k.val]'(by
              have := result.buf.property; scalar_tac)).val from rfl]
      rw [result_post6 k j hj_25]
      simp only [if_pos hj1]
      rw [projectLane_toArray_getElem k kxh.state j hj_25]
      rfl

/-! **Informal proof** (`Shake4x.finalize_all` wrapper,
    `Funs.lean:25096-25101`).

    Lives in `Extract.lean` rather than `Finalize.lean` because the
    proof composes `extract_all.spec` (declared above in this file):
    Extract imports Finalize, so the consuming spec must live downstream.

    Body (3 monadic calls + record update):
      1. `self1 ← pad_all self` — `Shake4x.pad_all.spec`.
      2. `kxh ← Keccak4xHybrid.permute self1.state` —
         `Keccak4xHybrid.permute.spec`.
      3. `self2 ← extract_all { self1 with state := kxh }` —
         `Shake4x.extract_all.spec`.
      4. `ok { self2 with finalized := true }`.

    **Post derivation**:
      * Frame conjuncts (`rate`, `rate_lanes`, `absorbed`): preserved
        through all three steps.
      * `Shake4x.squeezing result gs`: built component-by-component,
        mirroring `finalize_no_extract.spec`: WF for the post-record,
        ghost-rate match (via `(toScalar ...).input_block_size`),
        alignment (squeezed = [] so length 0), and the per-instance
        `squeezingInvariant` via `padAndPermute_per_instance`.
      * `buf[k][0..rate] = (extractOutput (gs k) rate).toList`:
        At `squeezed = []`, `eagerSqueezeState g = S_pad` and
        `extractOutput g g.rate = squeezeBytes S_pad 0 g.rate g.rate`,
        which matches Bridge B (`squeezeBytes_full_block_eq_lanes`)
        on the post-permute state.  Chain via `result_post6` from
        `extract_all.spec` (per-lane LE bytes of `kxh.state`).

    **Spec-side bridges**:
      * Existing: `padAndPermute_per_instance` (Bridges.lean:388),
        `Keccak4xHybrid.permute_toBits_per_instance`,
        `squeezeBytes_full_block_eq_lanes`,
        `Shake4x.squeezing_record_eq`,
        `take_eq_flatMap_extract_chunks`,
        `take_flatMap_eq_range_flatMap`,
        `range_flatMap_eq_finRange_flatten`,
        `projectLane_toArray_getElem`. -/
set_option maxHeartbeats 4000000 in
set_option maxRecDepth 4096 in
@[step]
theorem Shake4x.finalize_all.spec
    (self : sha3.shake4x.Shake4x)
    (gs : Fin 4 → GhostState)
    (hAbs : Shake4x.absorbing self gs) :
    sha3.shake4x.Shake4x.finalize_all self
    ⦃ (result : sha3.shake4x.Shake4x) =>
        result.rate = self.rate ∧
        result.rate_lanes = self.rate_lanes ∧
        result.absorbed = self.absorbed ∧
        Shake4x.squeezing result gs ∧
        (∀ k : Fin 4,
          (result.buf[k]).val.take self.rate.val
            = (extractOutput (gs k) self.rate.val).toList) ⦄ := by
  unfold sha3.shake4x.Shake4x.finalize_all
  obtain ⟨hWF, _hNotFin, hCons, hPer⟩ := hAbs
  -- (1) step pad_all
  step with Shake4x.pad_all.spec self gs ⟨hWF, _hNotFin, hCons, hPer⟩
  -- (2) step permute (Keccak4xHybrid.permute.spec)
  step
  -- (3) step extract_all — need to supply preconditions on
  -- `{ self1 with state := kxh }`.
  have hRateLanes1 :
      ({ self1 with state := kxh } : sha3.shake4x.Shake4x).rate_lanes.val * 8
        = ({ self1 with state := kxh } : sha3.shake4x.Shake4x).rate.val := by
    show self1.rate_lanes.val * 8 = self1.rate.val
    rw [self1_post1, self1_post2]; exact hWF.2.1
  have hRate1 :
      ({ self1 with state := kxh } : sha3.shake4x.Shake4x).rate.val ≤ 168 := by
    show self1.rate.val ≤ 168
    rw [self1_post1]
    rcases hWF.1 with h | h <;> simp [h]
  step with Shake4x.extract_all.spec _ hRateLanes1 hRate1
  -- After step extract_all + closing `ok`, goal is the 5-conjunct post on `result`.
  -- `result = { self2 with finalized := true }`.
  -- Useful intermediate facts about field chains:
  have h_self2_rate : self2.rate = self.rate := by
    rw [self2_post2]; exact self1_post1
  have h_self2_rl : self2.rate_lanes = self.rate_lanes := by
    rw [self2_post3]; exact self1_post2
  have h_self2_absorbed : self2.absorbed = self.absorbed := by
    rw [self2_post4]; exact self1_post4
  -- ghost-rate match
  have h_rate_eq : ∀ i : Fin 4, (gs i).rate = self.rate.val := by
    intro i
    have h_ibs : ((Shake4x.toScalar self i hWF).input_block_size.val) = (gs i).rate :=
      (hPer i).1.2.2.1
    have h_toScalar_ibs : (Shake4x.toScalar self i hWF).input_block_size.val
        = self.rate.val := by simp [Shake4x.toScalar]
    rw [h_toScalar_ibs] at h_ibs
    exact h_ibs.symm
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · -- result.rate = self.rate
    show self2.rate = self.rate
    exact h_self2_rate
  · -- result.rate_lanes = self.rate_lanes
    show self2.rate_lanes = self.rate_lanes
    exact h_self2_rl
  · -- result.absorbed = self.absorbed
    show self2.absorbed = self.absorbed
    exact h_self2_absorbed
  · -- Shake4x.squeezing result gs
    -- We derive squeezing on the "no-extract" record
    --   z := { self with state := kxh, finalized := true }
    -- and transfer to `result` (which has same state/rate/rate_lanes/
    -- absorbed/finalized as z, only buf differs).
    set z : sha3.shake4x.Shake4x :=
      { self with state := kxh, finalized := true } with hz
    have h_result_state : ({ self2 with finalized := true } : sha3.shake4x.Shake4x).state
        = z.state := by show self2.state = kxh; rw [self2_post1]
    have h_result_rate : ({ self2 with finalized := true } : sha3.shake4x.Shake4x).rate
        = z.rate := by show self2.rate = self.rate; exact h_self2_rate
    have h_result_rl : ({ self2 with finalized := true } : sha3.shake4x.Shake4x).rate_lanes
        = z.rate_lanes := by
      show self2.rate_lanes = self.rate_lanes; exact h_self2_rl
    have h_result_absorbed : ({ self2 with finalized := true } : sha3.shake4x.Shake4x).absorbed
        = z.absorbed := by
      show self2.absorbed = self.absorbed; exact h_self2_absorbed
    have h_result_finalized : ({ self2 with finalized := true } : sha3.shake4x.Shake4x).finalized
        = z.finalized := by show true = true; rfl
    rw [Shake4x.squeezing_record_eq h_result_state h_result_rate h_result_rl
          h_result_absorbed h_result_finalized]
    -- Drop the heavy `self2_post6`/`self2_post5` hypotheses introduced by
    -- `step extract_all` — they bloat scalar_tac's simp_all context.
    -- (Squeezing is buf-irrelevant; we only need the post-permute state.)
    clear self2_post6 self2_post5 self2_post4 self2_post3 self2_post2 self2_post1
    -- Now prove `Shake4x.squeezing z gs`.  Mirrors `finalize_no_extract.spec`.
    have hWF' : Shake4x.WF z := by
      refine ⟨?_, ?_, ?_⟩
      · show self.rate = _ ∨ self.rate = _; exact hWF.1
      · show self.rate_lanes.val * 8 = self.rate.val; exact hWF.2.1
      · intro k; show (self.absorbed[k]).val < self.rate.val; exact hWF.2.2 k
    refine ⟨hWF', rfl, hCons, h_rate_eq, ?_, ?_⟩
    · -- alignment: squeezed = [] so length 0 % rate = 0.
      intro i
      have hsq_nil : (gs i).squeezed = [] := (hPer i).1.2.2.2.2
      rw [hsq_nil]; simp
    · -- per-instance squeezingInvariant on z.
      intro i
      unfold Shake4x.squeezingInvariant
      refine ⟨?_, ?_⟩
      · -- toBits (projectLane i kxh.state).toArray = eagerSqueezeState (gs i).
        unfold Shake4x.eagerSqueezeState
        have hsq_nil : (gs i).squeezed = [] := (hPer i).1.2.2.2.2
        rw [hsq_nil]
        simp only [List.length_nil, squeezeAfter]
        have hrate_pos : 0 < (gs i).rate := (gs i).h_rate.1
        rw [if_neg (by omega : ¬ (0 = (gs i).rate))]
        have h_rate_i : (gs i).rate = self.rate.val := h_rate_eq i
        have h_pad_i : (gs i).padVal = 0x1F#u8 := by
          have h := (hPer i).1.2.2.2.1
          simp [Shake4x.toScalar] at h
          exact h.symm
        have h_sponge := (hPer i).2.2
        have h_ts_state :
            (toScalar self i hWF).state
              = (Keccak4xHybrid.projectLane i self.state.state).toArray := by
          simp [Shake4x.toScalar]
        have h_ts_idx :
            (toScalar self i hWF).state_index.val
              = self.absorbed[i].val % self.rate.val := by
          simp [Shake4x.toScalar]
        have habs_lt : self.absorbed[i].val < self.rate.val := hWF.2.2 i
        have h_mod : self.absorbed[i].val % self.rate.val = self.absorbed[i].val :=
          Nat.mod_eq_of_lt habs_lt
        -- Goal: toBits (projectLane i z.state).toArray = padAndPermute …
        show toBits (Keccak4xHybrid.projectLane i kxh.state).toArray = _
        rw [show (absorbBytes (Vector.replicate Spec.SHA3.b false) 0 (gs i).rate
                  (gs i).absorbed).2
                = self.absorbed[i].val by
              rw [← h_sponge.2, h_ts_idx, h_mod],
            ← h_sponge.1, h_ts_state, h_rate_i, h_pad_i]
        exact Shake4x.pad_permute_per_instance self self1 kxh i hWF self1_post5 kxh_post2
      · -- (gs i).squeezed = (squeezeBytes ... 0).toList.  Both are [].
        have h_squeezed_nil : (gs i).squeezed = [] := (hPer i).1.2.2.2.2
        rw [h_squeezed_nil]
        show [] = (squeezeBytes _ 0 (gs i).rate [].length).toList
        simp [squeezeBytes]
  · -- buf equation: ∀ k, result.buf[k][0..rate] = (extractOutput (gs k) rate).toList.
    intro k
    -- Show: (result.buf[k]).val.take self.rate.val
    --     = (extractOutput (gs k) self.rate.val).toList
    -- result.buf = self2.buf, with per-lane LE-bytes equation via result_post6.
    -- Spec side: at squeezed=[], extractOutput g g.rate
    --          = squeezeBytes (eagerSqueezeState g) 0 g.rate g.rate.
    -- Then Bridge B (squeezeBytes_full_block_eq_lanes) + chunk-match.
    have hWFra : self.rate_lanes.val * 8 = self.rate.val := hWF.2.1
    have hWFr2 : self.rate = 168#usize ∨ self.rate = 136#usize := hWF.1
    have hrate_lanes_le : self.rate_lanes.val ≤ 25 := by
      rcases hWFr2 with h | h <;> rw [h] at hWFra <;> simp at hWFra <;> omega
    have hrate_lanes_le_21 : self.rate_lanes.val ≤ 21 := by
      rcases hWFr2 with h | h <;> rw [h] at hWFra <;> simp at hWFra <;> omega
    have hrate_decomp : self.rate.val = 8 * self.rate_lanes.val := by omega
    have h_rate_k : (gs k).rate = self.rate.val := h_rate_eq k
    have hsq_nil : (gs k).squeezed = [] := (hPer k).1.2.2.2.2
    have hpad_k : (gs k).padVal = 0x1F#u8 := by
      have h := (hPer k).1.2.2.2.1
      simp [Shake4x.toScalar] at h
      exact h.symm
    -- Compute extractOutput (gs k) self.rate.val at squeezed = [].
    have h_sponge := (hPer k).2.2
    have h_ts_state :
        (toScalar self k hWF).state
          = (Keccak4xHybrid.projectLane k self.state.state).toArray := by
      simp [Shake4x.toScalar]
    have h_ts_idx :
        (toScalar self k hWF).state_index.val
          = self.absorbed[k].val % self.rate.val := by
      simp [Shake4x.toScalar]
    have habs_lt : self.absorbed[k].val < self.rate.val := hWF.2.2 k
    have h_mod : self.absorbed[k].val % self.rate.val = self.absorbed[k].val :=
      Nat.mod_eq_of_lt habs_lt
    -- The padAndPermute_per_instance equation (proved above for the
    -- squeezing case) gives toBits (projectLane k kxh.state).toArray
    --   = padAndPermute (toBits ...) self.absorbed[k].val self.rate.val 0x1F#u8.
    -- Re-derive it here for the buf branch (mirror the earlier block).
    have h_pad_perm :
        toBits (Keccak4xHybrid.projectLane k kxh.state).toArray =
          padAndPermute (toBits (Keccak4xHybrid.projectLane k self.state.state).toArray)
            self.absorbed[k].val self.rate.val 0x1F#u8 :=
      Shake4x.pad_permute_per_instance self self1 kxh k hWF self1_post5 kxh_post2
    -- Now reduce extractOutput at squeezed=[].
    have h_extract :
        (extractOutput (gs k) self.rate.val).toList =
          (squeezeBytes (toBits (Keccak4xHybrid.projectLane k kxh.state).toArray)
            0 self.rate.val self.rate.val).toList := by
      unfold extractOutput
      rw [hsq_nil]
      simp only [List.length_nil, squeezeAfter]
      have hrate_pos : 0 < (gs k).rate := (gs k).h_rate.1
      -- After simp, idx_cur = 0; squeezeBytes S_pad 0 rate rate.
      rw [show (absorbBytes (Vector.replicate Spec.SHA3.b false) 0 (gs k).rate
                (gs k).absorbed).2 = self.absorbed[k].val by
            rw [← h_sponge.2, h_ts_idx, h_mod],
          ← h_sponge.1, h_ts_state, h_rate_k, hpad_k, ← h_pad_perm]
    rw [h_extract]
    -- Bridge B: squeezeBytes (toBits a) 0 (8 rl) (8 rl) = flatMap of lane LE bytes.
    rw [hrate_decomp,
        squeezeBytes_full_block_eq_lanes _ self.rate_lanes.val hrate_lanes_le]
    -- LHS shape: result.buf[k].val.take (8 rl) — same chunking as next_block.
    have h_buf_k_eq :
        (({ self2 with finalized := true } : sha3.shake4x.Shake4x).buf[k]).val
          = (self2.buf.val[k.val]'(by
            have := self2.buf.property; scalar_tac)).val := by rfl
    have h_buf_len :
        (({ self2 with finalized := true } : sha3.shake4x.Shake4x).buf[k]).val.length
          = 168 := by
      rw [h_buf_k_eq]; exact (self2.buf.val[k.val]'(by
        have := self2.buf.property; scalar_tac)).property
    rw [take_eq_flatMap_extract_chunks _ self.rate_lanes.val
          (by rw [h_buf_len]; omega)]
    have h_lanes_len :
        (Keccak4xHybrid.projectLane k kxh.state).toArray.val.length = 25 := by
      simp [Lanes25.toArray, Array.make]
    rw [take_flatMap_eq_range_flatMap _ self.rate_lanes.val
          (by rw [h_lanes_len]; exact hrate_lanes_le)]
    rw [range_flatMap_eq_finRange_flatten]
    congr 1
    apply List.ext_getElem
    · simp
    · intro j hj1 _
      simp at hj1
      rw [List.getElem_map, List.getElem_map, List.getElem_finRange]
      have hj_25 : j < 25 := by omega
      simp only [Fin.cast_mk, Fin.val_mk]
      -- LHS via self2_post6: at index k, byte chunks pinned to kxh.state lanes.
      conv_lhs =>
        rw [show (({ self2 with finalized := true } : sha3.shake4x.Shake4x).buf[k]).val
              = (self2.buf.val[k.val]'(by
                have := self2.buf.property; scalar_tac)).val from rfl]
      -- Now self2.buf via extract_all's per-lane equation (self2_post6).
      -- self2_post6 has shape: (self2.buf.val[k.val]).val.extract (m*8) (m*8+8) = ...
      rw [self2_post6 k j hj_25]
      have hj_in : j < ({ self1 with state := kxh } : sha3.shake4x.Shake4x).rate_lanes.val := by
        show j < self1.rate_lanes.val
        rw [self1_post2]; exact hj1
      rw [if_pos hj_in]
      -- Now reduce RHS: the chunk is BitVec.toLEBytes of the lane at position j of
      --   ({ self1 with state := kxh }).state, which equals kxh.state.
      -- Reindex into projectLane.toArray.
      show _ = (BitVec.toLEBytes
                  ((Keccak4xHybrid.projectLane k kxh.state).toArray.val[j]'(by
                    rw [h_lanes_len]; exact hj_25)).bv).map (fun bv => (⟨bv⟩ : Std.U8))
      rw [projectLane_toArray_getElem k kxh.state j hj_25]
      rfl

/-- **Informal proof** (`Shake4x.next_block_no_extract` wrapper).
    Body (mirrors `next_block` minus the `extract_all` staging):
      1. `kxh ← Keccak4xHybrid.permute self.state` —
         `Keccak4xHybrid.permute.spec`.
      2. `ok { self with state := kxh }`.

    **Post derivation**: identical to `next_block.spec` minus the
    `buf` byte-equation; the `buf = self.buf` frame follows from the
    record update preserving `buf`.  The `squeezeAdvance rate`
    ghost-advance derivation is identical.

    Output is exposed to callers via `state_ref` (returning the
    inner `Keccak4xHybrid` for direct `get_lane` reads — the fast
    path used by MLKEM-4x and expected by MLDSA-4x).

    **Spec-side bridges**: same as `next_block.spec` minus
    `extractOutput`.

    Discharge: `step; obtain ⟨hWF, _, _, _⟩ := hSqu;
    refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> agrind`. -/
@[step]
theorem Shake4x.next_block_no_extract.spec
    (self : sha3.shake4x.Shake4x)
    (gs : Fin 4 → GhostState)
    (hSqu : Shake4x.squeezing self gs) :
    sha3.shake4x.Shake4x.next_block_no_extract self
    ⦃ (result : sha3.shake4x.Shake4x) =>
        result.rate = self.rate ∧
        result.rate_lanes = self.rate_lanes ∧
        result.buf = self.buf ∧
        result.absorbed = self.absorbed ∧
        Shake4x.squeezing result
          (fun k => (gs k).squeezeAdvance self.rate.val) ⦄ := by
  unfold sha3.shake4x.Shake4x.next_block_no_extract
  obtain ⟨hWF, hFin, hCons, hRate, hAlign, hPer⟩ := hSqu
  step*
  have hb := Shake4x.squeezing_advance_permute self kxh gs
    ⟨hWF, hFin, hCons, hRate, hAlign, hPer⟩ kxh_post2
  rw [hFin] at hb
  exact hb

/-- **Informal proof** (`Shake4x.state_ref` wrapper).
    Body: `ok self.state` (returns the inner `Keccak4xHybrid` field
    by value — Rust's `&self.state` becomes a pure read in the
    extracted Lean since there is no aliasing model at this layer).

    **Post**: `result = self.state` is immediate from the body
    (single `ok` statement, no mutation).

    The precondition `hFin : self.finalized = true` is not actually
    needed for the postcondition itself, but enforces the consumer
    contract: `state_ref` is meaningful only when the state holds
    squeeze-mode bits.  Calling it in absorb mode would let callers
    `get_lane` partially-absorbed bytes, which is semantically
    nonsensical.

    Discharge: `simp [Shake4x.state_ref]; rfl`. -/
@[step]
theorem Shake4x.state_ref.spec (self : sha3.shake4x.Shake4x)
    (hFin : self.finalized = true) :
    sha3.shake4x.Shake4x.state_ref self
    ⦃ (result : sha3.keccak4x_hybrid.Keccak4xHybrid) =>
        result = self.state ⦄ := by
  unfold sha3.shake4x.Shake4x.state_ref
  simp [WP.spec_ok]

end symcrust
