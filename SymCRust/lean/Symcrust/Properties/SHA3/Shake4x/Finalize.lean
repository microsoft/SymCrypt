/-
# Properties/SHA3/Shake4x/Finalize — pad + permute + flip `finalized`.

All `@[step]` theorems below have real, vacuity-checked
postconditions.

## Surface

  * `pad_all self`              — applies SHAKE pad10*1 to all 4 buffers
                                  (internal helper, exposed as `pub(crate)`).
  * `finalize_all self`         — `pad_all` + permute + extract_all + set finalized.
  * `finalize_no_extract self`  — `pad_all` + permute + set finalized
                                  (skips the extract step for callers that
                                  use `state_ref` for fast-path output).

After any `finalize_*`, `Shake4x.squeezing self gs` holds for `gs` that
encode each instance's absorbed bytes with `squeezed = []`.

`finalize_all` additionally fills `buf[i]` with the first `rate_lanes`
u64s squeezed out (= `rate` bytes), which `block i` later returns.
-/
import Symcrust.Code
import Symcrust.Properties.SHA3.Basic
import Symcrust.Properties.SHA3.Shake4x.Basic
import Symcrust.Properties.SHA3.Shake4x.Bridges

namespace symcrust

open Aeneas Aeneas.Std Result
open sha3.sha3_impl

set_option linter.unusedSectionVars false
set_option linter.unusedVariables false

/-- **Informal proof** (loop spec — `pad_all_loop`, `Funs.lean:24977-25006`).
    Per iteration at cursor `inst : Std.Usize` (instances 0..4):
      1. `IteratorRange.next` — advance cursor.
      2. `Array.index_usize a inst` — read `pos := absorbed[inst]`.
      3. Compute `lane_idx := pos / 8`, `byte_off := pos % 8`,
         `low_mask := 31#u64 <<< (8 * byte_off)`.
      4. `Keccak4xHybrid.xor_lane kxh lane_idx inst low_mask` — XOR the
         `0x1F` SHAKE pad byte into the right byte of the right lane
         for THIS instance only (per `xor_lane.spec` post — the
         `if p = lane_idx ∧ k = inst` clause restricts the update).
      5. Compute `last_lane := (i-1) / 8`, `last_byte := (i-1) % 8`,
         `high_mask := 128#u64 <<< (8 * last_byte)` — the `0x80`
         high-pad byte at position `rate - 1`.
      6. Second `Keccak4xHybrid.xor_lane` for the high pad bit.
      7. Recursive IH on `pad_all_loop iter1 kxh' i a`.

    **Canonical pattern**: Range loop with per-instance independent
    mutation (no cross-instance interaction).

    **Loop invariant** (per-iteration form at cursor `iter.start.val`):
    for every lane `p : Fin 25` and instance `k : Fin 4`,
    `result.state[p][k]` equals
      * `kxh.state[p][k]` if `k.val < iter.start.val ∨ iter.«end».val ≤ k.val`
        (frame — these instances were either processed before the loop
        entry by an earlier recursion step, OR are out of range);
      * otherwise (`iter.start.val ≤ k.val < iter.«end».val`),
        `kxh.state[p][k] ^^^ low_mask(p, a[k]) ^^^ high_mask(p, i-1)`
        where `low_mask(p, pos) = (if p.val = pos/8 then 31#u64 <<< (8 * (pos%8)) else 0)`
        and `high_mask(p, j) = (if p.val = j/8 then 128#u64 <<< (8 * (j%8)) else 0)`.

    Since `0x1F` and `0x80` share no bits, the XOR-XOR formulation
    correctly encodes pad10*1 even when `pos = i - 1` (collapsed case):
    the same byte ends up holding `0x1F ^^^ 0x80 = 0x9F = 0x1F ||| 0x80`.

    **Lemma chain in call order**: `IteratorRange.next.spec`,
    `Array.index_usize.spec`, `Usize.div.spec`, `Usize.rem.spec`,
    `Usize.mul.spec`, `U64.shl.spec`, `Keccak4xHybrid.xor_lane.spec`
    (×2), `Usize.sub.spec`, recursive IH.

    Discharge: `agrind`. -/
@[step]
theorem Shake4x.pad_all_loop.spec
    (iter : core.ops.range.Range Std.Usize)
    (kxh : sha3.keccak4x_hybrid.Keccak4xHybrid)
    (i : Std.Usize)
    (a : Array Std.Usize 4#usize)
    (hStart : iter.start.val ≤ iter.«end».val)
    (hEnd : iter.«end».val ≤ 4)
    (hI : 0 < i.val ∧ i.val ≤ 168)
    (hA : ∀ k : Fin 4,
            (a.val[k.val]'(by have := a.property; scalar_tac)).val < i.val) :
    sha3.shake4x.Shake4x.pad_all_loop iter kxh i a
    ⦃ (r : sha3.keccak4x_hybrid.Keccak4xHybrid) =>
        ∀ (p : Fin 25) (k : Fin 4),
          ((r.state[p]'(by scalar_tac)).val[k.val]'(by
              have := (r.state[p]'(by scalar_tac)).property; scalar_tac))
            = if k.val < iter.start.val ∨ iter.«end».val ≤ k.val then
                ((kxh.state[p]'(by scalar_tac)).val[k.val]'(by
                  have := (kxh.state[p]'(by scalar_tac)).property; scalar_tac))
              else
                let pos := (a.val[k.val]'(by have := a.property; scalar_tac)).val
                let lane_idx := pos / 8
                let byte_off := pos % 8
                let last_lane := (i.val - 1) / 8
                let last_byte := (i.val - 1) % 8
                ((kxh.state[p]'(by scalar_tac)).val[k.val]'(by
                  have := (kxh.state[p]'(by scalar_tac)).property; scalar_tac))
                  ^^^ (if p.val = lane_idx
                       then ⟨(31#u64).bv <<< (8 * byte_off)⟩
                       else 0#u64)
                  ^^^ (if p.val = last_lane
                       then ⟨(128#u64).bv <<< (8 * last_byte)⟩
                       else 0#u64) ⦄ := by
  unfold sha3.shake4x.Shake4x.pad_all_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← IteratorRange_next_some iter hlt
    rw [hsome]
    have hinst_lt4 : iter.start.val < 4 := by scalar_tac
    have hpos_lt_i :
        (a.val[iter.start.val]'(by have := a.property; scalar_tac)).val < i.val := by
      have := hA ⟨iter.start.val, hinst_lt4⟩; simpa using this
    have hi_pos : 0 < i.val := hI.1
    have hi_le : i.val ≤ 168 := hI.2
    step*
    all_goals (first | (simp only [sha3.shake4x.U64_BYTES] at *; scalar_tac) | skip)
    -- Main residual: compose IH (r_post) + xor_lane posts (kxh1_post, kxh2_post)
    rename_i p k
    rw [r_post p k]
    -- Rewrite U64_BYTES to 8 in all bindings; lane_idx = pos/8, byte_off = pos%8, etc.
    simp only [sha3.shake4x.U64_BYTES] at lane_idx_post byte_off_post last_lane_post last_byte_post
    -- Convert i2, i5 to BitVec form for matching the goal.
    have hi2_bv : i2 = (⟨(31#u64).bv <<< (8 * byte_off.val)⟩ : U64) := by
      apply U64.bv_eq_imp_eq; rw [i2_post2, i1_post]
    have hi5_bv : i5 = (⟨(128#u64).bv <<< (8 * last_byte.val)⟩ : U64) := by
      apply U64.bv_eq_imp_eq; rw [i5_post2, i4_post]
    -- Case split on k vs iter.start, iter.end.
    by_cases hk_lt_start : k.val < iter.start.val
    · -- k < iter.start: r_post then-branch (iter1.start = iter.start+1 > k)
      have hk_lt1 : k.val < iter1.start.val ∨ iter1.end.val ≤ k.val := by
        left; rw [hstart']; scalar_tac
      rw [if_pos hk_lt1]
      rw [if_pos (Or.inl hk_lt_start)]
      -- Now kxh2.state[p][k] = kxh1.state[p][k] = kxh.state[p][k] (since k ≠ iter.start)
      have hne_start : k.val ≠ iter.start.val := by scalar_tac
      rw [kxh2_post p k]
      rw [if_neg (by intro ⟨_, h2⟩; exact hne_start h2)]
      rw [kxh1_post p k]
      rw [if_neg (by intro ⟨_, h2⟩; exact hne_start h2)]
    · push Not at hk_lt_start
      by_cases hk_eq_start : k.val = iter.start.val
      · -- k = iter.start: r_post then-branch fires (iter1.start = iter.start+1 = k+1 > k).
        -- The XORs from kxh1, kxh2 land on this column; bridge via pos_post + lane_idx_post.
        have hk_lt1 : k.val < iter1.start.val ∨ iter1.end.val ≤ k.val := by
          left; rw [hstart']; scalar_tac
        rw [if_pos hk_lt1]
        -- RHS goes to else branch
        have hk_in : ¬ (k.val < iter.start.val ∨ iter.end.val ≤ k.val) := by
          push Not; refine ⟨hk_lt_start, ?_⟩
          rw [hk_eq_start]; exact hlt
        rw [if_neg hk_in]
        -- Compose kxh2_post and kxh1_post at this column.
        rw [kxh2_post p k, kxh1_post p k]
        -- The else→then conditions: need k = iter.start (have it), and p comparisons.
        -- Bridge: lane_idx = pos/8 = a[k]/8; byte_off = pos%8 = a[k]%8 (when k = iter.start, pos = a[iter.start] = a[k]).
        have hpos_k : pos = (a.val[k.val]'(by have := a.property; scalar_tac)) := by
          rw [pos_post]; congr 1; exact hk_eq_start.symm
        have hlane_idx_eq : lane_idx.val = (a.val[k.val]'(by have := a.property; scalar_tac)).val / 8 := by
          rw [lane_idx_post, hpos_k]; rfl
        have hbyte_off_eq : byte_off.val = (a.val[k.val]'(by have := a.property; scalar_tac)).val % 8 := by
          rw [byte_off_post, hpos_k]; rfl
        have hlast_lane_eq : last_lane.val = (i.val - 1) / 8 := by
          rw [last_lane_post, i3_post1]; rfl
        have hlast_byte_eq : last_byte.val = (i.val - 1) % 8 := by
          rw [last_byte_post, i3_post1]; rfl
        rw [hi2_bv, hi5_bv, hlane_idx_eq, hbyte_off_eq, hlast_lane_eq, hlast_byte_eq]
        simp only [hk_eq_start, and_true]
        split_ifs <;>
          first | rfl |
            (apply U64.bv_eq_imp_eq; simp [BitVec.xor_zero])
      · -- iter.start < k: r_post else-branch (iter1.start = iter.start+1 ≤ k).
        have hk_gt_start : iter.start.val < k.val := by scalar_tac
        by_cases hk_lt_end : k.val < iter.end.val
        · -- iter1.start ≤ k < iter1.end: r_post mutation, kxh1/kxh2 frame (k ≠ iter.start)
          have hk_in1 : ¬ (k.val < iter1.start.val ∨ iter1.end.val ≤ k.val) := by
            push Not; refine ⟨?_, ?_⟩
            · rw [hstart']; scalar_tac
            · rw [hend']; exact hk_lt_end
          rw [if_neg hk_in1]
          have hk_in : ¬ (k.val < iter.start.val ∨ iter.end.val ≤ k.val) := by
            push Not; exact ⟨hk_lt_start, hk_lt_end⟩
          rw [if_neg hk_in]
          -- kxh2.state[p][k] = kxh1.state[p][k] = kxh.state[p][k]  (k ≠ iter.start)
          have hne : k.val ≠ iter.start.val := by scalar_tac
          rw [kxh2_post p k, if_neg (by intro ⟨_, h2⟩; exact hne h2)]
          rw [kxh1_post p k, if_neg (by intro ⟨_, h2⟩; exact hne h2)]
        · -- iter.end ≤ k: r_post then-branch (iter1.end = iter.end ≤ k)
          push Not at hk_lt_end
          have hk_in1 : k.val < iter1.start.val ∨ iter1.end.val ≤ k.val := by
            right; rw [hend']; exact hk_lt_end
          rw [if_pos hk_in1]
          have hk_frame : k.val < iter.start.val ∨ iter.end.val ≤ k.val := Or.inr hk_lt_end
          rw [if_pos hk_frame]
          -- kxh2[p][k] = kxh1[p][k] = kxh[p][k]  (k ≠ iter.start since k ≥ iter.end > iter.start)
          have hne : k.val ≠ iter.start.val := by scalar_tac
          rw [kxh2_post p k, if_neg (by intro ⟨_, h2⟩; exact hne h2)]
          rw [kxh1_post p k, if_neg (by intro ⟨_, h2⟩; exact hne h2)]
  · let* ⟨ o, iter1, hnone, _ ⟩ ← IteratorRange_next_none iter (by scalar_tac)
    rw [hnone]
    intro p k
    have hk_frame : k.val < iter.start.val ∨ iter.«end».val ≤ k.val := by
      by_contra h; push Not at h; omega
    simp [hk_frame]
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- **Informal proof** (`Shake4x.pad_all` wrapper, `Funs.lean:25010-25016`).
    Body:
      1. `massert (¬ self.finalized)` — discharged via
         `(hAbs.choose_spec.left)` destruct of `Shake4x.absorbing`.
      2. `pad_all_loop {start := 0, end := 4} self.state self.rate self.absorbed`
         — apply `pad_all_loop.spec` above with `iter.start = 0`,
         `iter.end = 4`, `kxh = self.state`, `i = self.rate`,
         `a = self.absorbed`.  Pre-`hI`: `rate ∈ {168, 136}` from
         `hAbs.choose.left`; pre-`hA`: each `absorbed[k] ≤ rate` from
         `hAbs.choose.right.right` (then strict via `hAbs.choose_spec`
         + the `absorbing` ghost-state invariant
         `absorbed.val < rate` whenever the ghost is in absorb mode).
      3. `ok { self with state := kxh, finalized := false }`.

    **Post derivation**:
      * Frame conjuncts (`rate`, `rate_lanes`, `buf`, `absorbed`,
        `finalized = false`): preserved by the record update.
      * **Lane equation** (added Scaffold-3 convergence): instantiate
        `pad_all_loop.spec` at `iter.start = 0`, `iter.end = 4`,
        `kxh = self.state`, `i = self.rate`, `a = self.absorbed`.
        Since `iter.start.val = 0`, the `frame` branch of the loop
        post is unreachable; every `(k : Fin 4)` falls into the
        `mutated` branch with `kxh.state[p][k] ^^^ low_mask ^^^
        high_mask`.  Bridging in this lane equation at the wrapper
        level (instead of dropping it) lets downstream
        `finalize_all.spec` / `finalize_no_extract.spec` derive the
        FIPS-202 `KeccakState.append_pad` form without re-stating the
        loop equation — see `KeccakState.append_pad_state_eq`.
      * The `Shake4x.squeezing` predicate does not route through the
        scalar `state_index` field (eager-permute design in
        `Basic.lean`), so the post does not assert `state_index`.
        WF for `result` is recovered downstream from
        the framed `rate`/`rate_lanes`/`absorbed` fields whenever
        needed.

    **Scalar bridge**: `KeccakState.append_pad_state_eq`
    translates the per-lane XOR-XOR equation
    exposed in this wrapper post into the scalar `padPre`/
    `KeccakState.append_pad` form expected by FIPS-202.  Lives in
    `Properties/SHA3/Basic.lean`. -/
@[step]
theorem Shake4x.pad_all.spec
    (self : sha3.shake4x.Shake4x)
    (gs : Fin 4 → GhostState)
    (hAbs : Shake4x.absorbing self gs) :
    sha3.shake4x.Shake4x.pad_all self
    ⦃ (result : sha3.shake4x.Shake4x) =>
        result.rate = self.rate ∧
        result.rate_lanes = self.rate_lanes ∧
        result.buf = self.buf ∧
        result.absorbed = self.absorbed ∧
        /- Per-lane XOR-XOR pad equation, carried up from
           `pad_all_loop.spec` at `iter.start=0, iter.end=4`. -/
        (∀ (p : Fin 25) (k : Fin 4),
          ((result.state.state[p]'(by scalar_tac)).val[k.val]'(by
              have := (result.state.state[p]'(by scalar_tac)).property; scalar_tac))
            = let pos := (self.absorbed[k]).val
              let lane_idx := pos / 8
              let byte_off := pos % 8
              let last_lane := (self.rate.val - 1) / 8
              let last_byte := (self.rate.val - 1) % 8
              ((self.state.state[p]'(by scalar_tac)).val[k.val]'(by
                  have := (self.state.state[p]'(by scalar_tac)).property; scalar_tac))
                ^^^ (if p.val = lane_idx
                     then ⟨(31#u64).bv <<< (8 * byte_off)⟩
                     else 0#u64)
                ^^^ (if p.val = last_lane
                     then ⟨(128#u64).bv <<< (8 * last_byte)⟩
                     else 0#u64)) ⦄ := by
  unfold sha3.shake4x.Shake4x.pad_all
  obtain ⟨hWF, hFin, _hCons, _hPer⟩ := hAbs
  obtain ⟨hRate, _hRL, hAbsorbed⟩ := hWF
  have hRate_pos_le : 0 < self.rate.val ∧ self.rate.val ≤ 168 := by
    cases hRate with
    | inl h => rw [h]; decide
    | inr h => rw [h]; decide
  have hA_strict : ∀ k : Fin 4,
      (self.absorbed.val[k.val]'(by have := self.absorbed.property; scalar_tac)).val
        < self.rate.val := by
    intro k; have := hAbsorbed k; simpa using this
  step*
  -- Only the per-lane equation remains (frames already discharged by step*).
  intro p k
  have hk_in : ¬ ((k.val : ℕ) < 0 ∨ 4 ≤ k.val) := by
    push Not; refine ⟨by scalar_tac, k.is_lt⟩
  rw [kxh_post p k, if_neg hk_in]
  rfl

-- `Shake4x.finalize_all.spec` is defined in `Shake4x/Extract.lean`
-- (after `extract_all.spec`, which it consumes — Extract imports Finalize,
-- so the spec lives downstream where `extract_all.spec` is in scope).

/-- **Per-instance pad+permute bridge.**  Given the per-lane pad
    equation from `pad_all.spec` (`h_pad`) and the per-instance permute
    equation from `Keccak4xHybrid.permute.spec` (`h_perm`, in
    `iterateRndCore` form), derive the `padAndPermute` equation
    expected by `Shake4x.squeezing`.  Extracted from the body of
    `finalize_no_extract.spec` so callers (`finalize_no_extract.spec`,
    `finalize_all.spec`) can apply it inside a small context — calling
    `scalar_tac` from deeply nested `by`-blocks blows `maxRecDepth` when
    the surrounding context carries the extra `extract_all` hypotheses. -/
theorem Shake4x.pad_permute_per_instance
    (self self1 : sha3.shake4x.Shake4x)
    (kxh : sha3.keccak4x_hybrid.Keccak4xHybrid)
    (i : Fin 4)
    (hWF : Shake4x.WF self)
    (h_pad : ∀ (p : Fin 25) (k : Fin 4),
        ((self1.state.state[p]'(by scalar_tac)).val[k.val]'(by
            have := (self1.state.state[p]'(by scalar_tac)).property; scalar_tac))
          = let pos := (self.absorbed[k]).val
            let lane_idx := pos / 8
            let byte_off := pos % 8
            let last_lane := (self.rate.val - 1) / 8
            let last_byte := (self.rate.val - 1) % 8
            ((self.state.state[p]'(by scalar_tac)).val[k.val]'(by
                have := (self.state.state[p]'(by scalar_tac)).property; scalar_tac))
              ^^^ (if p.val = lane_idx
                   then ⟨(31#u64).bv <<< (8 * byte_off)⟩
                   else 0#u64)
              ^^^ (if p.val = last_lane
                   then ⟨(128#u64).bv <<< (8 * last_byte)⟩
                   else 0#u64))
    (h_perm : ∀ k : Fin 4,
        Keccak4xHybrid.projectLane k kxh.state =
          iterateRndCore (Keccak4xHybrid.projectLane k self1.state.state) 24) :
    toBits (Keccak4xHybrid.projectLane i kxh.state).toArray =
      padAndPermute (toBits (Keccak4xHybrid.projectLane i self.state.state).toArray)
        self.absorbed[i].val self.rate.val 0x1F#u8 := by
  have habs_lt : self.absorbed[i].val < self.rate.val := hWF.2.2 i
  refine padAndPermute_per_instance
    (Keccak4xHybrid.projectLane i self.state.state).toArray
    (Keccak4xHybrid.projectLane i self1.state.state).toArray
    (Keccak4xHybrid.projectLane i kxh.state).toArray
    self.absorbed[i].val self.rate.val 0x1F#u8
    habs_lt ?_ ?_ ?_ ?_ ?_
  · rcases hWF.1 with hr | hr <;> simp [hr]
  · rcases hWF.1 with hr | hr <;> simp [hr]
  · rcases hWF.1 with hr | hr <;> simp [hr]
  · intro p hp
    have h_toA_post :
        ((Keccak4xHybrid.projectLane i self1.state.state).toArray.val[p]'(by
          simp [Lanes25.toArray]; omega)).bv
        = ((self1.state.state.val[p]'(by scalar_tac)).val[i.val]'(by
            have := (self1.state.state.val[p]'(by scalar_tac)).property
            have := i.isLt; scalar_tac)).bv := by
      congr 1
      rcases p with _|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_ <;>
        first | rfl | (exfalso; omega)
    have h_toA_pre :
        ((Keccak4xHybrid.projectLane i self.state.state).toArray.val[p]'(by
          simp [Lanes25.toArray]; omega)).bv
        = ((self.state.state.val[p]'(by scalar_tac)).val[i.val]'(by
            have := (self.state.state.val[p]'(by scalar_tac)).property
            have := i.isLt; scalar_tac)).bv := by
      congr 1
      rcases p with _|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_ <;>
        first | rfl | (exfalso; omega)
    rw [h_toA_post, h_toA_pre]
    have h_eq := h_pad ⟨p, hp⟩ i
    have h_31 : (0x1F#u8).bv.zeroExtend Spec.SHA3.w = (31#u64).bv := by decide
    have h_128 : (0x80#u8).bv.zeroExtend Spec.SHA3.w = (128#u64).bv := by decide
    rw [h_31, h_128]
    have h_eq' :
        ((self1.state.state.val[p]'(by scalar_tac)).val[i.val]'(by
            have := (self1.state.state.val[p]'(by scalar_tac)).property
            have := i.isLt; scalar_tac)) =
        ((self.state.state.val[p]'(by scalar_tac)).val[i.val]'(by
            have := (self.state.state.val[p]'(by scalar_tac)).property
            have := i.isLt; scalar_tac) ^^^
            (if p = self.absorbed[i].val / 8
             then ⟨(31#u64).bv <<< (8 * (self.absorbed[i].val % 8))⟩
             else 0#u64)) ^^^
          (if p = (self.rate.val - 1) / 8
           then ⟨(128#u64).bv <<< (8 * ((self.rate.val - 1) % 8))⟩
           else 0#u64) := h_eq
    rw [h_eq']
    split_ifs <;> rfl
  · exact Keccak4xHybrid.permute_toBits_per_instance self1.state.state kxh.state i (h_perm i)

/-- **Informal proof** (`Shake4x.finalize_no_extract` wrapper,
    `Funs.lean:25105-25109`).
    Body (2 monadic calls + record update):
      1. `self1 ← pad_all self` — `Shake4x.pad_all.spec` as above.
      2. `kxh ← Keccak4xHybrid.permute self1.state` —
         `Keccak4xHybrid.permute.spec`.
      3. `ok { self1 with state := kxh, finalized := true }`.

    Differs from `finalize_all` only in skipping the `extract_all`
    staging step — so the `buf` field is **literally unchanged** from
    the wrapper entry (no per-instance byte equation to prove).
    Callers obtain output via `state_ref` (returning the inner
    `Keccak4xHybrid` for direct `get_lane` reads) — see
    `state_ref.spec` in `Extract.lean`.

    **Post derivation**: identical to `finalize_all.spec` minus the
    `buf` byte-equation; the `buf = self.buf` frame follows from the
    record update preserving `buf`.

    Discharge: `step ×2; obtain ⟨hWF, _, _, _⟩ := hAbs;
    refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> agrind`. -/
@[step]
theorem Shake4x.finalize_no_extract.spec
    (self : sha3.shake4x.Shake4x)
    (gs : Fin 4 → GhostState)
    (hAbs : Shake4x.absorbing self gs) :
    sha3.shake4x.Shake4x.finalize_no_extract self
    ⦃ (result : sha3.shake4x.Shake4x) =>
        result.rate = self.rate ∧
        result.rate_lanes = self.rate_lanes ∧
        result.buf = self.buf ∧
        result.absorbed = self.absorbed ∧
        Shake4x.squeezing result gs ⦄ := by
  unfold sha3.shake4x.Shake4x.finalize_no_extract
  step*
  refine ⟨self1_post1, self1_post2, self1_post3, self1_post4, ?_⟩
  -- Build Shake4x.squeezing component-by-component.
  obtain ⟨hWF, _hNotFin, hCons, hPer⟩ := hAbs
  -- (a) WF for the post-finalize record.
  have hWF' : Shake4x.WF
      { state := kxh, rate := self1.rate, rate_lanes := self1.rate_lanes,
        buf := self1.buf, absorbed := self1.absorbed, finalized := true } := by
    refine ⟨?_, ?_, ?_⟩
    · simp only [self1_post1]; exact hWF.1
    · simp only [self1_post1, self1_post2]; exact hWF.2.1
    · intro k
      simp only [self1_post4, self1_post1]; exact hWF.2.2 k
  -- (b) ∀ i, (gs i).rate = self.rate.val (then self1.rate via post1).
  have h_rate_eq : ∀ i : Fin 4, (gs i).rate = self.rate.val := by
    intro i
    have h_ibs : ((Shake4x.toScalar self i hWF).input_block_size.val) = (gs i).rate :=
      (hPer i).1.2.2.1
    have h_toScalar_ibs : (Shake4x.toScalar self i hWF).input_block_size.val = self.rate.val := by
      simp [Shake4x.toScalar]
    rw [h_toScalar_ibs] at h_ibs
    exact h_ibs.symm
  refine ⟨hWF', rfl, hCons, fun i => self1_post1 ▸ h_rate_eq i, ?_, ?_⟩
  · -- (alignment) (gs i).squeezed.length % (gs i).rate = 0.
    -- After absorb-only execution, squeezed = [] (length 0), so 0 % rate = 0.
    intro i
    have hsq_nil : (gs i).squeezed = [] := (hPer i).1.2.2.2.2
    rw [hsq_nil]
    simp
  -- (c) Per-instance squeezingInvariant.
  intro i
  unfold Shake4x.squeezingInvariant
  refine ⟨?_, ?_⟩
  · -- toBits (projectLane i kxh.state).toArray = eagerSqueezeState (gs i).
    -- Reduce eagerSqueezeState using (gs i).squeezed = [].
    unfold Shake4x.eagerSqueezeState
    have hsq_nil : (gs i).squeezed = [] := (hPer i).1.2.2.2.2
    rw [hsq_nil]
    simp only [List.length_nil, squeezeAfter]
    have hrate_pos : 0 < (gs i).rate := (gs i).h_rate.1
    rw [if_neg (by omega : ¬ (0 = (gs i).rate))]
    -- Identify ghost rate/padVal with self's via the predicate.
    have h_rate_i : (gs i).rate = self.rate.val := h_rate_eq i
    have h_pad_i : (gs i).padVal = 0x1F#u8 := by
      have h := (hPer i).1.2.2.2.1
      simp [Shake4x.toScalar] at h
      exact h.symm
    -- Identify the absorb-state via spongeInvariant on toScalar.
    have h_sponge := (hPer i).2.2
    have h_ts_state :
        (toScalar self i hWF).state = (Keccak4xHybrid.projectLane i self.state.state).toArray := by
      simp [Shake4x.toScalar]
    have h_ts_idx :
        (toScalar self i hWF).state_index.val = self.absorbed[i].val % self.rate.val := by
      simp [Shake4x.toScalar]
    have habs_lt : self.absorbed[i].val < self.rate.val := hWF.2.2 i
    have h_mod : self.absorbed[i].val % self.rate.val = self.absorbed[i].val :=
      Nat.mod_eq_of_lt habs_lt
    -- Rewrite goal to expose the bridge shape.
    rw [show (absorbBytes (Vector.replicate Spec.SHA3.b false) 0 (gs i).rate (gs i).absorbed).2
            = self.absorbed[i].val by
          rw [← h_sponge.2, h_ts_idx, h_mod],
        ← h_sponge.1, h_ts_state, h_rate_i, h_pad_i]
    -- Apply the per-instance pad+permute bridge.
    refine padAndPermute_per_instance
      (Keccak4xHybrid.projectLane i self.state.state).toArray
      (Keccak4xHybrid.projectLane i self1.state.state).toArray
      (Keccak4xHybrid.projectLane i kxh.state).toArray
      self.absorbed[i].val self.rate.val 0x1F#u8
      habs_lt ?_ ?_ ?_ ?_ ?_
    · rcases hWF.1 with hr | hr <;> simp [hr]
    · rcases hWF.1 with hr | hr <;> simp [hr]
    · rcases hWF.1 with hr | hr <;> simp [hr]
    · -- Per-lane XOR-XOR equation: derive from self1_post5.
      intro p hp
      have h_toA_post : ((Keccak4xHybrid.projectLane i self1.state.state).toArray.val[p]'(by
            simp [Lanes25.toArray]; omega)).bv
          = ((self1.state.state.val[p]'(by scalar_tac)).val[i.val]'(by
              have := (self1.state.state.val[p]'(by scalar_tac)).property
              have := i.isLt; scalar_tac)).bv := by
        congr 1
        rcases p with _|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_ <;>
          first | rfl | (exfalso; omega)
      have h_toA_pre : ((Keccak4xHybrid.projectLane i self.state.state).toArray.val[p]'(by
            simp [Lanes25.toArray]; omega)).bv
          = ((self.state.state.val[p]'(by scalar_tac)).val[i.val]'(by
              have := (self.state.state.val[p]'(by scalar_tac)).property
              have := i.isLt; scalar_tac)).bv := by
        congr 1
        rcases p with _|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_ <;>
          first | rfl | (exfalso; omega)
      rw [h_toA_post, h_toA_pre]
      have h_eq := self1_post5 ⟨p, hp⟩ i
      have h_31 : (0x1F#u8).bv.zeroExtend Spec.SHA3.w = (31#u64).bv := by decide
      have h_128 : (0x80#u8).bv.zeroExtend Spec.SHA3.w = (128#u64).bv := by decide
      rw [h_31, h_128]
      -- Forge h_eq into the list-indexed form (defeq, just retyping the LHS index).
      have h_eq' :
          ((self1.state.state.val[p]'(by scalar_tac)).val[i.val]'(by
              have := (self1.state.state.val[p]'(by scalar_tac)).property
              have := i.isLt; scalar_tac)) =
          ((self.state.state.val[p]'(by scalar_tac)).val[i.val]'(by
              have := (self.state.state.val[p]'(by scalar_tac)).property
              have := i.isLt; scalar_tac) ^^^
              (if p = self.absorbed[i].val / 8
               then ⟨(31#u64).bv <<< (8 * (self.absorbed[i].val % 8))⟩
               else 0#u64)) ^^^
            (if p = (self.rate.val - 1) / 8
             then ⟨(128#u64).bv <<< (8 * ((self.rate.val - 1) % 8))⟩
             else 0#u64) := h_eq
      rw [h_eq']
      -- Both sides now have the same XOR structure modulo `.bv` distributing over
      -- the U64-XORs and `if`s.  Split the two `if`s and discharge with `rfl`.
      split_ifs <;> rfl
    · -- KECCAK_f equation from per-instance permute bridge.
      exact Keccak4xHybrid.permute_toBits_per_instance self1.state.state kxh.state i (kxh_post2 i)
  · -- (gs i).squeezed = (squeezeBytes ... 0).toList.  Both are [].
    have h_squeezed_nil : (gs i).squeezed = [] :=
      (hPer i).1.2.2.2.2
    rw [h_squeezed_nil]
    show [] = (squeezeBytes _ 0 (gs i).rate [].length).toList
    simp [squeezeBytes]

end symcrust
