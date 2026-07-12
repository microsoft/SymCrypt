/-
# Properties/SHA3/Shake4x/Bridges — bridges for the 4x state machine

This file collects the spec-side bridge helpers consumed by
`Shake4x.{finalize,next_block}_*.spec`.  See `Shake4x/Basic.lean` for
the design rationale of the **eager-permute** squeezing predicate.

## Status

  * `Keccak4xHybrid.permute_toBits_per_instance` — CLOSED.  The simple
    permute bridge: 4x permute on the projected lanes equals scalar
    `KECCAK_f` on the per-instance bits.

  * `eager_state_advance_rate` — CLOSED.  The key arithmetic lemma:
    advancing the eager state by `rate` bytes is exactly one extra
    `KECCAK_f`.

  * `Shake4x.squeezingInvariant_advance_permute` — CLOSED.  Pulls the
    eager-permute squeezing invariant through a single `Keccak4xHybrid.permute`
    call.

  * `Shake4x.squeezing_advance_permute` — CLOSED.  Composite-level
    wrapper used by `next_block.spec` and `next_block_no_extract.spec`.
-/
import Symcrust.Properties.SHA3.Shake4x.Basic
import Symcrust.Properties.SHA3.Sponge.BridgeBitFC
import Symcrust.Properties.SHA3.Sponge.BridgeComp

namespace symcrust

open Aeneas Aeneas.Std Result
open sha3.sha3_impl
open scoped Spec.Notations

set_option linter.unusedSectionVars false
set_option linter.unusedVariables false

/-! ## Per-instance permute bridge -/

/-- **Per-instance permute bridge.**  Lifts the 4x permute postcondition
    (per-lane `projectLane i kxh = iterateRndCore (projectLane i self) 24`,
    from `Keccak4xHybrid.permute.spec`) to the scalar bit-level
    `KECCAK_f` equation expected by the per-instance scalar squeezing
    invariant.

    Composition: `iterateRndCore_toState` (per-lane → spec State) +
    `keccak_permute_toBits` (spec State → bit-level `KECCAK_f`). -/
theorem Keccak4xHybrid.permute_toBits_per_instance
    (self_state kxh_state : Std.Array sha3.keccak4x_hybrid.Lane4 25#usize)
    (i : Fin 4)
    (h : Keccak4xHybrid.projectLane i kxh_state =
         iterateRndCore (Keccak4xHybrid.projectLane i self_state) 24) :
    toBits (Keccak4xHybrid.projectLane i kxh_state).toArray =
      Spec.SHA3.KECCAK_f
        (toBits (Keccak4xHybrid.projectLane i self_state).toArray) := by
  apply keccak_permute_toBits
  rw [toState_toArray, toState_toArray, h]
  exact iterateRndCore_toState _ 24 (by omega)

/-! ## Eager-permute advance lemma -/

/-- **Eager-permute rate-shift.**  Advancing the eager state by `rate`
    more bytes is exactly one extra `KECCAK_f` on the previous eager
    state, regardless of where we started. -/
theorem eager_state_advance_rate
    (S₀ : Vector Bool Spec.SHA3.b) (rate n : Nat) (hr : 0 < rate) :
    (if (squeezeAfter S₀ 0 rate (n + rate)).2 = rate
     then Spec.SHA3.KECCAK_f (squeezeAfter S₀ 0 rate (n + rate)).1
     else (squeezeAfter S₀ 0 rate (n + rate)).1)
    =
    Spec.SHA3.KECCAK_f
      (if (squeezeAfter S₀ 0 rate n).2 = rate
       then Spec.SHA3.KECCAK_f (squeezeAfter S₀ 0 rate n).1
       else (squeezeAfter S₀ 0 rate n).1) := by
  -- Step 1: rewrite the n+rate advance as compose n with rate steps.
  rw [show squeezeAfter S₀ 0 rate (n + rate)
        = squeezeAfter (squeezeAfter S₀ 0 rate n).1
                       (squeezeAfter S₀ 0 rate n).2 rate rate
       from by rw [squeezeAfter_add]]
  set p := squeezeAfter S₀ 0 rate n with hp_def
  have hidx_le : p.2 ≤ rate := by
    rw [hp_def]; exact squeezeAfter_idx_le_rate _ _ _ _ (Nat.zero_le _) hr
  -- Case-split on p.2: boundary, zero, or strictly between.
  by_cases hbnd : p.2 = rate
  · -- Boundary: eager_n = KECCAK_f p.1.
    -- squeezeAfter p.1 rate rate rate = squeezeAfter (KECCAK_f p.1) 0 rate rate by post_full_block
    rw [hbnd, squeezeAfter_post_full_block p.1 rate rate hr hr]
    -- Then squeezeAfter (KECCAK_f p.1) 0 rate rate: no permute, ends at (KECCAK_f p.1, rate).
    rw [show squeezeAfter (Spec.SHA3.KECCAK_f p.1) 0 rate rate
          = (Spec.SHA3.KECCAK_f p.1, rate)
        from by simpa using
          (by
            have h := squeezeAfter_idx_le_rate (Spec.SHA3.KECCAK_f p.1) 0 rate rate
                       (Nat.zero_le _) hr
            -- We just need = (KECCAK_f p.1, 0 + rate) via no_permute, but that's private.
            -- Use a small inductive argument inline:
            clear h
            have : ∀ k, k ≤ rate →
                   squeezeAfter (Spec.SHA3.KECCAK_f p.1) 0 rate k =
                   (Spec.SHA3.KECCAK_f p.1, k) := by
              intro k hk
              induction k with
              | zero => simp [squeezeAfter_zero]
              | succ j ih =>
                rw [squeezeAfter_succ, ih (by omega)]
                have hne : j ≠ rate := by omega
                simp [hne]
            exact this rate (le_refl _) )]
    simp []
  · by_cases hzero : p.2 = 0
    · -- idx_n = 0: squeezeAfter p.1 0 rate rate = (p.1, rate) (no permute).
      rw [hzero]
      have heq : squeezeAfter p.1 0 rate rate = (p.1, rate) := by
        have : ∀ k, k ≤ rate → squeezeAfter p.1 0 rate k = (p.1, k) := by
          intro k hk
          induction k with
          | zero => simp [squeezeAfter_zero]
          | succ j ih =>
            rw [squeezeAfter_succ, ih (by omega)]
            have hne : j ≠ rate := by omega
            simp [hne]
        exact this rate (le_refl _)
      rw [heq]
      have hne : (0 : Nat) ≠ rate := by omega
      simp [hne]
    · -- 0 < p.2 < rate.
      have hltr : p.2 < rate := lt_of_le_of_ne hidx_le hbnd
      have hpos : 0 < p.2 := Nat.pos_of_ne_zero hzero
      -- squeezeAfter p.1 p.2 rate rate via splitting rate = (rate - p.2) + p.2:
      -- First (rate - p.2) steps no permute → (p.1, rate)
      -- Then p.2 more steps: first step triggers permute (since at boundary)
      have hsplit : rate = (rate - p.2) + p.2 := by omega
      have hpath : squeezeAfter p.1 p.2 rate rate
                 = squeezeAfter p.1 p.2 rate ((rate - p.2) + p.2) := by
        rw [← hsplit]
      rw [hpath, squeezeAfter_add]
      -- Apply no-permute for (rate - p.2) steps
      have hno : ∀ k, p.2 + k ≤ rate →
                 squeezeAfter p.1 p.2 rate k = (p.1, p.2 + k) := by
        intro k hk
        induction k with
        | zero => simp [squeezeAfter_zero]
        | succ j ih =>
          rw [squeezeAfter_succ, ih (by omega)]
          have hne : p.2 + j ≠ rate := by omega
          simp [hne]; omega
      rw [hno (rate - p.2) (by omega)]
      have heq2 : p.2 + (rate - p.2) = rate := by omega
      rw [heq2]
      dsimp only
      -- Now: squeezeAfter p.1 rate rate p.2 = squeezeAfter (KECCAK_f p.1) 0 rate p.2 (post_full_block)
      have hpost : squeezeAfter p.1 rate rate p.2 =
                   squeezeAfter (Spec.SHA3.KECCAK_f p.1) 0 rate p.2 :=
        squeezeAfter_post_full_block p.1 rate p.2 hr hpos
      simp only [hpost]
      -- Then no-permute again for p.2 steps from (KECCAK_f p.1, 0)
      have hno2 : ∀ k, k ≤ rate →
                  squeezeAfter (Spec.SHA3.KECCAK_f p.1) 0 rate k =
                  (Spec.SHA3.KECCAK_f p.1, k) := by
        intro k hk
        induction k with
        | zero => simp [squeezeAfter_zero]
        | succ j ih =>
          rw [squeezeAfter_succ, ih (by omega)]
          have hne : j ≠ rate := by omega
          simp [hne]
      rw [hno2 p.2 hidx_le]
      simp [hbnd]

/-! ## Squeeze-invariant advance through a permute -/

/-- **Per-instance eager-permute advance through a permute.**

    Given:
      * `hPer i` — the eager-permute squeeze invariant on `(self, gs i, i)`;
      * `hKxh i` — the per-lane permute bridge result
                   `toBits (projectLane i kxh') = KECCAK_f (toBits (projectLane i self.state))`;

    conclude the eager-permute invariant holds for `{self with state := kxh'}`
    against `(gs i).squeezeAdvance rate`. -/
theorem Shake4x.squeezingInvariant_advance_permute
    (self : sha3.shake4x.Shake4x)
    (kxh' : sha3.keccak4x_hybrid.Keccak4xHybrid)
    (g : GhostState) (i : Fin 4)
    (hr : 0 < g.rate)
    (hPer : Shake4x.squeezingInvariant self g i)
    (hKxh : toBits (Keccak4xHybrid.projectLane i kxh'.state).toArray =
            Spec.SHA3.KECCAK_f
              (toBits (Keccak4xHybrid.projectLane i self.state.state).toArray)) :
    Shake4x.squeezingInvariant
      { self with state := kxh' } (g.squeezeAdvance g.rate) i := by
  obtain ⟨hEager, hBytes⟩ := hPer
  refine ⟨?_, ?_⟩
  · -- Eager state: rewrite kxh' lanes via hKxh, then via hEager into KECCAK_f (eagerSqueezeState g),
    -- then unfold eagerSqueezeState on the RHS and use eager_state_advance_rate.
    show toBits (Keccak4xHybrid.projectLane i ({self with state := kxh'} : sha3.shake4x.Shake4x).state.state).toArray
       = Shake4x.eagerSqueezeState (g.squeezeAdvance g.rate)
    simp only []
    rw [hKxh, hEager]
    -- Goal: KECCAK_f (eagerSqueezeState g) = eagerSqueezeState (g.squeezeAdvance g.rate)
    -- Unfold both sides.
    simp only [Shake4x.eagerSqueezeState, GhostState.squeezeAdvance, GhostState.squeeze]
    -- After unfolding GhostState.squeeze, `absorbed` and `rate` and `padVal` are unchanged.
    -- Only `squeezed` changes: g.squeezed → g.squeezed ++ (extractOutput g g.rate).toList.
    -- length becomes g.squeezed.length + g.rate.
    have hlen : (g.squeezed ++ (extractOutput g g.rate).toList).length =
                g.squeezed.length + g.rate := by
      simp [extractOutput]
    rw [hlen]
    -- Apply eager_state_advance_rate (.symm direction)
    exact (eager_state_advance_rate _ g.rate g.squeezed.length hr).symm
  · -- Bytes equation.
    simp only [GhostState.squeezeAdvance, GhostState.squeeze]
    -- Goal: g.squeezed ++ (extractOutput g g.rate).toList = (squeezeBytes ... (...length)).toList
    -- Apply extractOutput_eq_squeezeBytes_of_squeezing? No — that needs the scalar squeezing predicate.
    -- Use the relation: extractOutput g g.rate = (squeezeBytes S_pad 0 g.rate (n + g.rate)).toList
    -- minus the first n.  Use squeezeBytes_append.
    have hlen : (g.squeezed ++ (extractOutput g g.rate).toList).length =
                g.squeezed.length + g.rate := by
      simp [extractOutput]
    rw [hlen]
    rw [squeezeBytes_append _ _ _ g.squeezed.length g.rate]
    rw [← hBytes]
    -- Goal: g.squeezed ++ (extractOutput g g.rate).toList
    --     = g.squeezed ++ (squeezeBytes (squeezeAfter S_pad 0 g.rate g.squeezed.length).1
    --                                    (squeezeAfter S_pad 0 g.rate g.squeezed.length).2
    --                                    g.rate g.rate).toList
    congr 1

/-- **Composite squeezing advance through a permute.**  Bridges
    `Shake4x.squeezing self gs` through one `Keccak4xHybrid.permute` to
    `Shake4x.squeezing {self with state := kxh'} (fun k => (gs k).squeezeAdvance self.rate.val)`.

    Used by `next_block.spec` and `next_block_no_extract.spec`.  -/
theorem Shake4x.squeezing_advance_permute
    (self : sha3.shake4x.Shake4x)
    (kxh' : sha3.keccak4x_hybrid.Keccak4xHybrid)
    (gs : Fin 4 → GhostState)
    (hSqu : Shake4x.squeezing self gs)
    (hKxhPer : ∀ i : Fin 4,
      Keccak4xHybrid.projectLane i kxh'.state =
        iterateRndCore (Keccak4xHybrid.projectLane i self.state.state) 24) :
    Shake4x.squeezing
      { self with state := kxh' }
      (fun k => (gs k).squeezeAdvance self.rate.val) := by
  obtain ⟨hWF, hFin, hCons, hRate, hAlign, hPer⟩ := hSqu
  refine ⟨hWF, hFin, ?_, ?_, ?_, ?_⟩
  · intro i j
    obtain ⟨hr, hp⟩ := hCons i j
    refine ⟨?_, ?_⟩ <;> simp [GhostState.squeezeAdvance, GhostState.squeeze, hr, hp]
  · intro i
    simp [GhostState.squeezeAdvance, GhostState.squeeze, hRate i]
  · -- Alignment is preserved: (g.squeezeAdvance rate).squeezed.length = g.squeezed.length + rate,
    -- and adding rate preserves divisibility by rate.
    intro i
    simp only [GhostState.squeezeAdvance, GhostState.squeeze, List.length_append]
    have hext : (extractOutput (gs i) self.rate.val).toList.length = self.rate.val := by
      simp
    rw [hext, hRate i, Nat.add_mod_right]
    have := hAlign i
    rw [hRate i] at this
    exact this
  · intro i
    -- Rewrite (gs i).squeezeAdvance self.rate.val to (gs i).squeezeAdvance (gs i).rate
    rw [show self.rate.val = (gs i).rate from (hRate i).symm]
    apply Shake4x.squeezingInvariant_advance_permute self kxh' (gs i) i
    · exact (gs i).h_rate.1
    · exact hPer i
    · exact Keccak4xHybrid.permute_toBits_per_instance _ _ _ (hKxhPer i)

/-! ## Buf-irrelevance helper

`Shake4x.squeezing` depends only on `state`, `rate`, `rate_lanes`,
`absorbed`, and `finalized`.  `buf` is consumer-facing scratch
space; the predicate is invariant under buf updates. -/

theorem Shake4x.squeezing_record_eq
    {self self' : sha3.shake4x.Shake4x} {gs : Fin 4 → GhostState}
    (hState : self.state = self'.state)
    (hRate : self.rate = self'.rate)
    (hRateLanes : self.rate_lanes = self'.rate_lanes)
    (hAbsorbed : self.absorbed = self'.absorbed)
    (hFinalized : self.finalized = self'.finalized) :
    Shake4x.squeezing self gs ↔ Shake4x.squeezing self' gs := by
  cases self
  cases self'
  simp only at hState hRate hRateLanes hAbsorbed hFinalized
  subst hState hRate hRateLanes hAbsorbed hFinalized
  rfl

/-! ## padAndPermute per-instance bridge

These lemmas package the lane-level XOR equation from `pad_all.spec`
(after per-instance projection) into the bit-level `padAndPermute`
shape expected by `eagerSqueezeState` at `length = 0`.

The chain has three steps:

  1. `absorbByte_bridge_xor` — lane XOR equation ⇒ bit-level
     `absorbByte`.  Variant of `Sponge.BridgeBitFC.absorbByte_bridge`
     that takes the post-state as an arbitrary `Keccak1600` (with
     a per-lane equation) rather than a literal `Array.set`.

  2. Apply (1) twice (one per `absorbByte` in `padAndPermute`) with
     an intermediate state.

  3. Compose with `Keccak4xHybrid.permute_toBits_per_instance` for
     the final `KECCAK_f`.

The end result is `Shake4x.padAndPermute_per_instance`, which
takes the raw `pad_all.spec` per-lane equation + the `permute.spec`
per-instance equation + the absorbing predicate's `spongeInvariant`
and returns the bit-level `padAndPermute` equality.
-/

/-- **Generic absorb bridge.**  Like `absorbByte_bridge` but takes the
    post-state as an arbitrary `Keccak1600` whose lane content satisfies
    the appropriate per-lane XOR equation.  Used by the 4x bridge where
    the per-lane equation arises from `pad_all.spec` rather than a
    literal `Array.set`.

    Lanes other than `idx / 8` are XOR'd with `0` (i.e., unchanged). -/
private theorem absorbByte_bridge_xor
    (a a' : Keccak1600) (idx : Nat) (val : Std.U8)
    (hbound : idx < 200)
    (h_lane : ∀ p : Nat, (hp : p < 25) →
       (a'.val[p]'(by have := a'.property; scalar_tac)).bv =
       (a.val[p]'(by have := a.property; scalar_tac)).bv ^^^
         (if p = idx / 8 then val.bv.zeroExtend Spec.SHA3.w <<< (8 * (idx % 8)) else 0)) :
    toBits a' = absorbByte (toBits a) idx val := by
  -- Construct the explicit Array.set version and bridge via absorbByte_bridge.
  let lane_idx : Std.Usize := ⟨idx / 8, by scalar_tac⟩
  let new_lane : Std.U64 :=
    ⟨(a.val[idx / 8]'(by have := a.property; scalar_tac)).bv ^^^
       val.bv.zeroExtend Spec.SHA3.w <<< (8 * (idx % 8))⟩
  have h_bridge : toBits (Std.Array.set a lane_idx new_lane) = absorbByte (toBits a) idx val :=
    absorbByte_bridge a idx val lane_idx new_lane hbound rfl rfl
  rw [← h_bridge]
  apply Vector.ext
  intro j hj
  have hjw_lt : j / Spec.SHA3.w < 25 := by
    have hw : (Spec.SHA3.w : Nat) = 64 := rfl
    rw [hw]; have : j < 1600 := hj; omega
  have h_pre_len : a.val.length = 25 := a.property
  have h_a'_len : a'.val.length = 25 := a'.property
  have h_lane_idx_val : lane_idx.val = idx / 8 := rfl
  rw [toBits_getElem' a' j hj, toBits_getElem' _ j hj]
  -- Convert a'.val[j/w]! to use h_lane.
  rw [getElem!_pos a'.val (j / Spec.SHA3.w) (by omega)]
  rw [h_lane (j / Spec.SHA3.w) hjw_lt]
  show ((a.val[j / Spec.SHA3.w]'_).bv ^^^ _).getLsbD _ =
       (Std.Array.set a lane_idx new_lane).val[j / Spec.SHA3.w]!.bv.getLsbD (j % Spec.SHA3.w)
  -- Reduce the RHS Array.set lookup.
  have h_set_len : (a.val.set lane_idx.val new_lane).length = 25 := by simp
  have h_rhs : (Std.Array.set a lane_idx new_lane).val[j / Spec.SHA3.w]!.bv =
      if j / Spec.SHA3.w = idx / 8 then new_lane.bv
      else (a.val[j / Spec.SHA3.w]'(by omega)).bv := by
    show (a.val.set lane_idx.val new_lane)[j / Spec.SHA3.w]!.bv = _
    rw [getElem!_pos _ (j / Spec.SHA3.w) (by simp; omega)]
    rw [List.getElem_set]
    by_cases heq : j / Spec.SHA3.w = idx / 8
    · rw [if_pos (by show idx / 8 = j / Spec.SHA3.w; omega), if_pos heq]
    · rw [if_neg (by show ¬ idx / 8 = j / Spec.SHA3.w; intro h; exact heq h.symm), if_neg heq]
  rw [h_rhs]
  by_cases heq : j / Spec.SHA3.w = idx / 8
  · -- Modified lane.
    rw [if_pos heq, if_pos heq]
    show ((a.val[j / Spec.SHA3.w]'_).bv ^^^ _).getLsbD _ =
         ((a.val[idx / 8]'_).bv ^^^ _).getLsbD _
    have h_lookup_eq : (a.val[j / Spec.SHA3.w]'(by omega)).bv =
        (a.val[idx / 8]'(by omega)).bv := by
      have : j / Spec.SHA3.w = idx / 8 := heq
      simp [this]
    rw [h_lookup_eq]
  · -- Unmodified lane.
    rw [if_neg heq, if_neg heq]
    show ((a.val[j / Spec.SHA3.w]'_).bv ^^^ (0 : BitVec Spec.SHA3.w)).getLsbD _ = _
    simp

/-- **padAndPermute via per-instance lane equation.**  Given:
      * a lane-XOR equation chaining two XORs (`padVal` at `idx_byte`,
        `0x80` at `rate - 1`), and
      * a per-instance `KECCAK_f` equation on the post-XOR state,
    deduce the bit-level `padAndPermute` equation expected by
    `eagerSqueezeState`.  The two intermediate stages are abstracted
    away — only the input pre-state, the final post-permute state,
    and the parameters are exposed. -/
theorem padAndPermute_per_instance
    (S_pre S_post S_perm : Keccak1600)
    (idx_byte rate : Nat) (padVal : Std.U8)
    (hidx_lt : idx_byte < rate) (hrate_pos : 0 < rate)
    (hrate_div8 : rate % 8 = 0) (hrate_max : 8 * rate < 1600)
    (h_xor : ∀ p : Nat, (hp : p < 25) →
       (S_post.val[p]'(by have := S_post.property; scalar_tac)).bv =
       ((S_pre.val[p]'(by have := S_pre.property; scalar_tac)).bv ^^^
           (if p = idx_byte / 8 then
              padVal.bv.zeroExtend Spec.SHA3.w <<< (8 * (idx_byte % 8))
            else 0)) ^^^
         (if p = (rate - 1) / 8 then
            (0x80#u8).bv.zeroExtend Spec.SHA3.w <<< (8 * ((rate - 1) % 8))
          else 0))
    (h_perm : toBits S_perm = Spec.SHA3.KECCAK_f (toBits S_post)) :
    toBits S_perm = padAndPermute (toBits S_pre) idx_byte rate padVal := by
  -- Construct the intermediate state S_mid: lane p = lane p of S_pre,
  -- XOR'd with the first mask if p = idx_byte / 8.
  -- It is convenient to use Array.set on S_pre.
  have hidx_bnd : idx_byte < 200 := by
    have h8r : 8 * rate ≤ 200 * 8 := by omega
    omega
  have hrm1_bnd : rate - 1 < 200 := by omega
  -- We synthesise S_mid via the helper `absorbByte_bridge_xor`.
  -- Build S_mid := Array.set S_pre ⟨idx_byte/8, ...⟩ new_lane_1.
  -- For absorbByte_bridge_xor, we just need any post-state satisfying
  -- the per-lane XOR equation.  Use the construction directly:
  let lane_idx_1 : Std.Usize := ⟨idx_byte / 8, by scalar_tac⟩
  let new_lane_1 : Std.U64 := ⟨
    (S_pre.val[idx_byte / 8]'(by have := S_pre.property; scalar_tac)).bv ^^^
      padVal.bv.zeroExtend Spec.SHA3.w <<< (8 * (idx_byte % 8))⟩
  let S_mid : Keccak1600 := Std.Array.set S_pre lane_idx_1 new_lane_1
  -- Show toBits S_mid = absorbByte (toBits S_pre) idx_byte padVal.
  have hbridge_a : toBits S_mid = absorbByte (toBits S_pre) idx_byte padVal := by
    apply absorbByte_bridge S_pre idx_byte padVal lane_idx_1 new_lane_1 hidx_bnd
    · rfl
    · rfl
  -- Show S_post.lane = S_mid.lane XOR (second mask if p = (rate-1)/8).
  -- This uses the chained XOR equation: cancel/fold the first XOR.
  have h_xor2 : ∀ p : Nat, (hp : p < 25) →
      (S_post.val[p]'(by have := S_post.property; scalar_tac)).bv =
      (S_mid.val[p]'(by have := S_mid.property; scalar_tac)).bv ^^^
        (if p = (rate - 1) / 8 then
           (0x80#u8).bv.zeroExtend Spec.SHA3.w <<< (8 * ((rate - 1) % 8))
         else 0) := by
    intro p hp
    have hlane_idx_val : lane_idx_1.val = idx_byte / 8 := rfl
    have h_pre_len : S_pre.val.length = 25 := S_pre.property
    rw [h_xor p hp]
    show _ = _
    have hSmid_val : (S_mid.val[p]'(by have := S_mid.property; scalar_tac)).bv =
        if p = idx_byte / 8 then
          (S_pre.val[idx_byte / 8]'(by have := S_pre.property; scalar_tac)).bv ^^^
            padVal.bv.zeroExtend Spec.SHA3.w <<< (8 * (idx_byte % 8))
        else (S_pre.val[p]'(by have := S_pre.property; scalar_tac)).bv := by
      show (Std.Array.set S_pre lane_idx_1 new_lane_1).val[p].bv = _
      simp only [Aeneas.Std.Array.set_val_eq]
      rw [List.getElem_set]
      by_cases hpeq : p = idx_byte / 8
      · have hidx_set_eq : lane_idx_1.val = p := by rw [hlane_idx_val]; omega
        rw [if_pos hidx_set_eq, if_pos hpeq, hpeq]
      · have hidx_set_ne : ¬ lane_idx_1.val = p := by rw [hlane_idx_val]; omega
        rw [if_neg hidx_set_ne, if_neg hpeq]
    rw [hSmid_val]
    by_cases hpeq : p = idx_byte / 8
    · simp [hpeq]
    · simp [hpeq]
  -- Apply absorbByte_bridge_xor for the second XOR.
  have hbridge_b : toBits S_post = absorbByte (toBits S_mid) (rate - 1) (0x80#u8) :=
    absorbByte_bridge_xor S_mid S_post (rate - 1) (0x80#u8) hrm1_bnd h_xor2
  -- Compose.
  rw [h_perm, hbridge_b, hbridge_a]
  unfold padAndPermute
  rfl

/-! ## Block-boundary extract bridge (consumed by `next_block.spec`)

These lemmas package the `extractOutput` ⇒ per-lane LE-bytes conversion
needed when the 4x state machine extracts a full block at a squeeze
boundary.  See `Shake4x.eagerSqueezeState` for the eager-permute view.

  * `extractOutput_at_boundary` — at a multiple-of-rate squeeze position,
    `extractOutput (g.squeezeAdvance rate) rate` equals `squeezeBytes` from
    the post-permute eager state (which has just been advanced by one
    extra `KECCAK_f` thanks to the new alignment).

  * `squeezeBytes_full_block_eq_lanes` — squeezing a full block of bytes
    from `(toBits a)` at position 0 equals the flat-map of per-lane
    `BitVec.toLEBytes` over the first `rate_lanes` lanes of `a`. -/

/-- Local copy of the private `squeezeAfter_no_permute` helper from
    `Sponge.BridgeBitFC`.  Within rate, advancing the squeeze index
    incurs no permute. -/
private theorem squeezeAfter_no_permute_local
    (S : Vector Bool Spec.SHA3.b) (idx rate n : Nat) (h : idx + n ≤ rate) :
    squeezeAfter S idx rate n = (S, idx + n) := by
  induction n with
  | zero => rfl
  | succ k ih =>
    have hk : idx + k ≤ rate := by omega
    rw [squeezeAfter_succ, ih hk]
    have h2 : idx + k ≠ rate := by omega
    simp [h2]; omega

/-- Squeezing exactly `rate` bytes from idx 0 lands at idx `rate` without
    a permute. -/
private theorem squeezeAfter_zero_to_rate
    (S : Vector Bool Spec.SHA3.b) (rate : Nat) :
    squeezeAfter S 0 rate rate = (S, rate) := by
  suffices h : ∀ k, k ≤ rate → squeezeAfter S 0 rate k = (S, k) by
    exact h rate (le_refl _)
  intro k hk
  induction k with
  | zero => simp [squeezeAfter_zero]
  | succ j ih =>
    rw [squeezeAfter_succ, ih (by omega)]
    have hne : j ≠ rate := by omega
    simp [hne]

/-- Squeezing `rate` more bytes from idx `rate` triggers one permute and
    lands back at idx `rate`. -/
private theorem squeezeAfter_rate_to_rate
    (S : Vector Bool Spec.SHA3.b) (rate : Nat) (hr : 0 < rate) :
    squeezeAfter S rate rate rate = (Spec.SHA3.KECCAK_f S, rate) := by
  rw [squeezeAfter_post_full_block _ _ _ hr hr]
  exact squeezeAfter_zero_to_rate _ _

/-- At any positive multiple of `rate`, advancing by one more `rate`
    leaves the squeeze index at `rate` (ready for the next permute). -/
private theorem squeezeAfter_multiple_of_rate_idx
    (S : Vector Bool Spec.SHA3.b) (rate L : Nat) (hr : 0 < rate)
    (hL : L % rate = 0) :
    (squeezeAfter S 0 rate (L + rate)).2 = rate := by
  rcases Nat.dvd_of_mod_eq_zero hL with ⟨M, hM⟩
  subst hM
  clear hL
  induction M with
  | zero =>
    show (squeezeAfter S 0 rate (0 + rate)).2 = rate
    rw [Nat.zero_add, squeezeAfter_zero_to_rate]
  | succ M ih =>
    have hsplit : rate * (M + 1) + rate = (rate * M + rate) + rate := by ring
    rw [hsplit, squeezeAfter_add]
    set p := squeezeAfter S 0 rate (rate * M + rate) with hp_def
    have hp_idx : p.2 = rate := ih
    rw [show (squeezeAfter p.1 p.2 rate rate).2 =
            (squeezeAfter p.1 rate rate rate).2 from by rw [hp_idx]]
    rw [squeezeAfter_rate_to_rate _ _ hr]

/-- **Bridge A.**  At a block-aligned squeeze position, extracting `rate`
    more bytes from a freshly-advanced `g.squeezeAdvance rate` ghost
    equals `squeezeBytes` from the eager-permute state.  The key is that
    `eagerSqueezeState` already includes the next `KECCAK_f` because the
    advanced index equals `rate` (consumed by the if-then-else).

    Consumed by `next_block.spec` to convert from the spec-side
    `extractOutput` form to the per-lane form provided by
    `extract_all_loop.spec`. -/
theorem extractOutput_at_boundary
    (g : GhostState) (hAlign : g.squeezed.length % g.rate = 0) :
    (extractOutput (g.squeezeAdvance g.rate) g.rate).toList =
    (squeezeBytes (Shake4x.eagerSqueezeState (g.squeezeAdvance g.rate))
                  0 g.rate g.rate).toList := by
  have hr : 0 < g.rate := g.h_rate.1
  have habs : (g.squeezeAdvance g.rate).absorbed = g.absorbed := rfl
  have hpad : (g.squeezeAdvance g.rate).padVal = g.padVal := rfl
  have hrate : (g.squeezeAdvance g.rate).rate = g.rate := rfl
  have hsq : (g.squeezeAdvance g.rate).squeezed.length = g.squeezed.length + g.rate := by
    show (g.squeezed ++ _).length = _
    simp [Vector.length_toList]
  simp only [extractOutput, Shake4x.eagerSqueezeState, habs, hpad, hrate, hsq]
  set S_pad := padAndPermute
                  (absorbBytes (Vector.replicate Spec.SHA3.b false) 0 g.rate g.absorbed).1
                  (absorbBytes (Vector.replicate Spec.SHA3.b false) 0 g.rate g.absorbed).2
                  g.rate g.padVal with hSpad
  have hidx : (squeezeAfter S_pad 0 g.rate (g.squeezed.length + g.rate)).2 = g.rate :=
    squeezeAfter_multiple_of_rate_idx S_pad g.rate g.squeezed.length hr hAlign
  rw [hidx]
  simp only [↓reduceIte]
  exact congrArg Vector.toList
    (squeezeBytes_post_full_block _ g.rate g.rate hr hr)

/-- Inductive form of Bridge B: squeezing `8 * n` bytes from idx 0 of
    a `(toBits a)` state with rate ≥ `8 * n` equals the flat-map of
    per-lane `BitVec.toLEBytes` over the first `n` lanes of `a`. -/
private theorem squeezeBytes_prefix_lanes
    (a : Keccak1600) (rate n : Nat)
    (hr : 8 * n ≤ rate) (hn : n ≤ 25) :
    (squeezeBytes (toBits a) 0 rate (8 * n)).toList =
      (a.val.take n).flatMap (fun u =>
        List.map (fun b => (⟨b⟩ : U8)) (BitVec.toLEBytes u.bv)) := by
  induction n with
  | zero =>
    show (squeezeBytes (toBits a) 0 rate 0).toList = _
    simp [squeezeBytes]
  | succ n ih =>
    have hrn : 8 * n ≤ rate := by omega
    have hnn : n ≤ 25 := by omega
    have hsplit : 8 * (n + 1) = 8 * n + 8 := by ring
    rw [hsplit, squeezeBytes_append, ih hrn hnn]
    have hpos : 0 + 8 * n ≤ rate := by omega
    have hsq_after :
        squeezeAfter (toBits a) 0 rate (8 * n) = (toBits a, 0 + 8 * n) :=
      squeezeAfter_no_permute_local _ _ _ _ hpos
    simp only [hsq_after, Nat.zero_add]
    have hidx_mod : (8 * n) % 8 = 0 := by omega
    have hidx_b : 8 * n + 8 ≤ 200 := by omega
    have hwithin : 8 * n + 8 ≤ rate := by omega
    rw [squeezeBytes_lane_aligned a (8 * n) rate hidx_mod hidx_b hwithin]
    have hn_lt : n < a.val.length := by simp [a.2]; omega
    have hd : 8 * n / 8 = n := by omega
    have h_lane_eq : a.val[(8 * n) / 8]'(by simp [a.2]; omega) = a.val[n]'hn_lt := by
      simp [hd]
    rw [h_lane_eq]
    have htake : a.val.take (n + 1) = a.val.take n ++ [a.val[n]'hn_lt] := by
      apply List.ext_getElem
      · simp [a.2]
      · intro j hj1 hj2
        simp at hj1
        by_cases hjn : j < n
        · rw [List.getElem_take, List.getElem_append_left (by simp; omega),
              List.getElem_take]
        · push Not at hjn
          have heq : j = n := by omega
          subst heq
          rw [List.getElem_take, List.getElem_append_right (by simp)]
          simp
    rw [htake, List.flatMap_append, List.flatMap_singleton]

/-- **Bridge B.**  Squeezing a full block of `8 * rate_lanes` bytes from
    a `(toBits a)` state at idx 0 equals the flat-map of per-lane
    `BitVec.toLEBytes` over the first `rate_lanes` lanes of `a`.

    Consumed by `next_block.spec` to bridge the spec-side
    `squeezeBytes` form (from `extractOutput_at_boundary`) to the
    per-lane form provided by `extract_all_loop.spec`. -/
theorem squeezeBytes_full_block_eq_lanes
    (a : Keccak1600) (rate_lanes : Nat) (hrl : rate_lanes ≤ 25) :
    (squeezeBytes (toBits a) 0 (8 * rate_lanes) (8 * rate_lanes)).toList =
      (a.val.take rate_lanes).flatMap (fun u =>
        List.map (fun b => (⟨b⟩ : U8)) (BitVec.toLEBytes u.bv)) :=
  squeezeBytes_prefix_lanes a (8 * rate_lanes) rate_lanes (le_refl _) hrl

/-! ## List-level shape helpers (consumed by next_block.spec)

Three small generic helpers used to bridge the per-lane LE-byte
form provided by `extract_all_loop.spec` (via `result_post6`) to the
flatMap form returned by `squeezeBytes_full_block_eq_lanes`.

* `take_eq_flatMap_extract_chunks` — rewrite `take (8n) buf` as a
  flatMap over n 8-byte extract chunks.
* `take_flatMap_eq_range_flatMap` — rewrite `(xs.take n).flatMap f`
  as `(List.range n).flatMap (fun m => f xs[m])`.
* `projectLane_toArray_getElem` — reindex
  `(projectLane k s).toArray.val[m] = s.val[m].val[k]`. -/

theorem take_eq_flatMap_extract_chunks (buf : List Aeneas.Std.U8) (n : Nat)
    (h_len : 8 * n ≤ buf.length) :
    buf.take (8 * n) =
      (List.range n).flatMap (fun m => buf.extract (m * 8) (m * 8 + 8)) := by
  induction n with
  | zero => simp
  | succ k ih =>
    have ih' := ih (by omega)
    have h1 : 8 * (k + 1) = 8 * k + 8 := by ring
    rw [h1, List.take_add, ih', List.range_succ, List.flatMap_append,
        List.flatMap_singleton]
    congr 1
    simp [List.extract_eq_take_drop]
    ring_nf

theorem range_flatMap_eq_finRange_flatten {β : Type*} (n : Nat) (f : Nat → List β) :
    (List.range n).flatMap f = ((List.finRange n).map (fun mh => f mh.val)).flatten := by
  rw [show (List.range n).flatMap f = ((List.range n).map f).flatten from rfl]
  congr 1
  apply List.ext_getElem
  · simp
  · intro j hj1 _
    simp at hj1
    rw [List.getElem_map, List.getElem_map, List.getElem_finRange, List.getElem_range]
    rfl

theorem take_flatMap_eq_range_flatMap {α β : Type*} (xs : List α) (n : Nat)
    (hn : n ≤ xs.length) (f : α → List β) :
    (xs.take n).flatMap f =
      ((List.finRange n).map (fun mh =>
        f (xs[mh.val]'(by have := mh.isLt; omega)))).flatten := by
  induction n with
  | zero => simp
  | succ k ih =>
    have hk : k ≤ xs.length := by omega
    have ih' := ih hk
    have htake : List.take (k+1) xs = xs.take k ++ [xs[k]'(by omega)] := by
      apply List.ext_getElem
      · simp
      · intro j hj1 _
        simp at hj1
        by_cases hjk : j < k
        · rw [List.getElem_take, List.getElem_append_left (by simp; omega),
              List.getElem_take]
        · have hjk' : j = k := by omega
          subst hjk'
          rw [List.getElem_take, List.getElem_append_right (by simp),
              List.getElem_singleton]
    rw [htake, List.flatMap_append, ih', List.flatMap_singleton]
    have hfin : List.finRange (k+1) =
        (List.finRange k).map (Fin.castSucc) ++ [Fin.last k] := by
      apply List.ext_getElem
      · simp
      · intro j hj1 _
        simp at hj1
        by_cases hjk : j < k
        · rw [List.getElem_append_left (by simp; omega)]
          rw [List.getElem_map, List.getElem_finRange, List.getElem_finRange]
          rfl
        · have hjk' : j = k := by omega
          subst hjk'
          rw [List.getElem_append_right (by simp), List.getElem_finRange]
          simp [Fin.last]
    rw [hfin]
    simp [List.map_append, List.flatten_append, Function.comp_def]

theorem projectLane_toArray_getElem (k : Fin 4)
    (s : Aeneas.Std.Array sha3.keccak4x_hybrid.Lane4 25#usize)
    (m : Nat) (hm : m < 25) :
    (Keccak4xHybrid.projectLane k s).toArray.val[m]'(by
      simp [Lanes25.toArray, Array.make]; omega) =
    (s.val[m]'(by simp [s.2]; omega)).val[k.val]'(by
      have := (s.val[m]'(by simp [s.2]; omega)).property
      have := k.isLt; scalar_tac) := by
  have heq : ∀ (mh : Fin 25),
      (Keccak4xHybrid.projectLane k s).toArray.val[mh.val]'(by
        have := mh.isLt; simp [Lanes25.toArray, Array.make]) =
      (Keccak4xHybrid.projectLane k s).lane25 mh := by
    intro mh; fin_cases mh <;> rfl
  rw [heq ⟨m, hm⟩, Keccak4xHybrid.projectLane_lane25]

end symcrust
