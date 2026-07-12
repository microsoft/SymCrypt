/-
# Properties/SHA3/Shake4x/Basic — per-instance projection design.

## Design

`Shake4x` carries one fused permute (`Keccak4xHybrid`) and per-instance
scalar state (`rate`, `buf[i]`, `absorbed[i]`, shared `finalized`).  Our
predicate stack is **per-instance projection**:

  * `Shake4x.WF self : Prop`                  — well-formedness
                                                (rate ∈ {136, 168};
                                                absorbed[i] < rate, strict).
  * `Shake4x.toScalar self i : KeccakState`   — synthesize the scalar
                                                KeccakState view for
                                                instance `i ∈ {0,1,2,3}`.
                                                Requires `Shake4x.WF`.
  * `Shake4x.absorbing self gs : Prop`        — `∀ i, absorbing (toScalar self i) (gs i)`.
  * `Shake4x.squeezing self gs : Prop`        — same shape for squeeze mode.

The shared `finalized` field forces `squeezing` to be all-or-nothing
across the 4 instances (an asymmetry vs the scalar API; matches the Rust
contract: `finalize_*` flips one bool for all 4 instances).

We assume all four `GhostState`s share the same `rate` and `padVal`
since the underlying SHAKE primitive enforces both at construction;
divergence would be a caller bug.

## MLKEM consumer pattern

The per-instance projection design lets MLKEM-4x consume
`Shake4x` using exactly the same proof patterns it already uses for
the scalar `KeccakState`: each instance has its own `GhostState`, and
the CBD / Expand* loops index by `i : Fin 4` and operate on
`gs i` independently.
-/
import Symcrust.Code
import Symcrust.Properties.SHA3.Basic
import Symcrust.Properties.SHA3.Keccak4x.State
import Symcrust.Properties.SHA3.Keccak4x.Hybrid
import Symcrust.Properties.SHA3.Sponge.BridgeRepr

namespace symcrust

open Aeneas Aeneas.Std Result
open sha3.sha3_impl

set_option linter.unusedSectionVars false
set_option linter.unusedVariables false

/-! ## Well-formedness -/

/-- `Shake4x.WF self` bundles all invariants we need to synthesize a
    scalar `KeccakState` view per instance:

      * `rate` is one of `{168, 136}` (SHAKE128, SHAKE256);
      * `rate_lanes = rate / 8` (constructor invariant);
      * each `absorbed[i]` does not exceed `rate`.

    `extracted Shake4x` is constructed only via `new_128` / `new_256`,
    so all reachable values satisfy this; we carry it as an explicit
    hypothesis to avoid baking `Decidable`-decoration in callers. -/
def Shake4x.WF (self : sha3.shake4x.Shake4x) : Prop :=
  (self.rate = 168#usize ∨ self.rate = 136#usize) ∧
  self.rate_lanes.val * 8 = self.rate.val ∧
  (∀ i : Fin 4, self.absorbed[i].val < self.rate.val)

/-! ## Per-instance projection

  `toScalar self i` synthesises the scalar `KeccakState` view of
  instance `i`.  Fields:

    * `state`            — the 25 projected u64 lanes, packed back into
                           the `Keccak1600 = Array U64 25` array
                           expected by the scalar layer.
    * `input_block_size` — `self.rate` truncated to u32 (always exact
                           since rate ≤ 168).
    * `state_index`      — `absorbed[i] mod rate` truncated to u32.
    * `padding_value`    — `0x1F#u8` (SHAKE; both 128 and 256).
    * `squeeze_mode`     — shared `finalized` flag.
-/
def Shake4x.toScalar (self : sha3.shake4x.Shake4x) (i : Fin 4)
    (h : Shake4x.WF self) : sha3.sha3_impl.KeccakState :=
  let proj : Lanes25 := Keccak4xHybrid.projectLane i self.state.state
  let absorbed_i := self.absorbed[i]
  /- The two bound dischargers below are discharged from `h.1`:
     `rate ∈ {168, 136}` ⇒ `rate < 2^32` and `absorbed_i mod rate < rate < 2^32`.
     They MUST be discharged inline (not `sorry`-ed): the produced UScalar
     values are part of the *term* this definition builds, so any `by sorry`
     here taints `#print axioms` of every downstream Shake4x theorem with
     `sorryAx`, even after the proof-side `sorry`s are closed. -/
  { state := proj.toArray,
    input_block_size := UScalar.ofNatCore self.rate.val
      (by rcases h.1 with hr | hr <;> simp [hr]),
    state_index := UScalar.ofNatCore (absorbed_i.val % self.rate.val)
      (by rcases h.1 with hr | hr <;> simp [hr] <;> scalar_tac),
    padding_value := 0x1F#u8,
    squeeze_mode := self.finalized }

/-- All four ghost states agree on `rate` and `padVal`.  Asserted by
    every absorb/squeeze predicate. -/
def Shake4x.gsConsistent (gs : Fin 4 → GhostState) : Prop :=
  ∀ i j : Fin 4, (gs i).rate = (gs j).rate ∧ (gs i).padVal = (gs j).padVal

/-! ## Composite absorb / squeeze predicates

`WF` is a plumbing requirement for `toScalar`'s `UScalar.ofNatCore`
bound discharger; it's not interesting to most callers, so we BAKE it
inside `absorbing`/`squeezing` rather than exposing it as a separate
hypothesis.  This keeps the user-visible API surface clean: posts say
`Shake4x.absorbing result gs'` with no `∃ hWF'`-style wrapper.

To extract `WF` inside a proof, simply destructure:

```
have ⟨hWF, hNotFin, hCons, hPer⟩ := hAbs
```
-/

/-- Composite absorb-mode predicate: each instance independently in
    `absorbing` state; shared `rate`/`padVal`; `finalized = false`.
    WF is bundled (see comment above). -/
def Shake4x.absorbing (self : sha3.shake4x.Shake4x)
    (gs : Fin 4 → GhostState) : Prop :=
  ∃ h : Shake4x.WF self,
    ¬ self.finalized ∧
    Shake4x.gsConsistent gs ∧
    ∀ i : Fin 4, sha3.sha3_impl.absorbing (Shake4x.toScalar self i h) (gs i)

/-! ### Eager-permute squeezing

The 4x state machine eagerly applies `KECCAK_f` at the end of every
`finalize_*`/`next_block_*` call (the `permute` happens *before* the
caller can read any byte), whereas the scalar `squeezing` predicate is
**lazy** — it defers permute until the next byte-extract triggers it.

We therefore cannot route `Shake4x.squeezing` through
`sha3.sha3_impl.squeezing`: at any block-boundary point (where the
scalar lazy `state_index = rate`), the 4x implementation has one MORE
`KECCAK_f` applied than the scalar invariant claims, and there is no
honest `state_index` for `toScalar` to report.

Instead we express the invariant directly in terms of `squeezeAfter`,
`squeezeBytes`, and an **eager normalization**: whenever the scalar
lazy index sits at the boundary `idx_lazy = rate`, the 4x state holds
`KECCAK_f` of the lazy state.  The output-bytes equation
(`squeezed = squeezeBytes ...`) is unchanged.

`Shake4x.WF` and `gsConsistent` are still bundled here so consumers
get the same `⟨hWF, hFin, hCons, hPer⟩` destructuring shape as
`absorbing`.  (The `∃ h` form is kept for source compatibility with
existing proofs.)
-/

/-- Eager-state normalization: the per-lane bits the 4x implementation
    holds at `(g, n)` after a `finalize_*`/`next_block_*` call.

    Equal to the scalar lazy `S_lazy` *except* at block boundaries
    (`idx_lazy = rate`), where the implementation has additionally
    applied one `KECCAK_f`.

    Note: `padAndPermute` already includes one `KECCAK_f`, so at
    `length = 0` the lazy `S_pad` already matches the post-finalize
    impl state — no eager difference there. -/
def Shake4x.eagerSqueezeState (g : GhostState) : Vector Bool Spec.SHA3.b :=
  let S_abs_pair := absorbBytes (Vector.replicate Spec.SHA3.b false) 0 g.rate g.absorbed
  let S_pad := padAndPermute S_abs_pair.1 S_abs_pair.2 g.rate g.padVal
  let lazy_pair := squeezeAfter S_pad 0 g.rate g.squeezed.length
  if lazy_pair.2 = g.rate then Spec.SHA3.KECCAK_f lazy_pair.1 else lazy_pair.1

/-- Per-instance squeeze invariant for the 4x state machine
    (eager-permute semantics).  See `Shake4x.eagerSqueezeState`. -/
def Shake4x.squeezingInvariant (self : sha3.shake4x.Shake4x)
    (g : GhostState) (i : Fin 4) : Prop :=
  let S_abs_idx := absorbBytes (Vector.replicate Spec.SHA3.b false) 0 g.rate g.absorbed
  let S_pad := padAndPermute S_abs_idx.1 S_abs_idx.2 g.rate g.padVal
  toBits (Keccak4xHybrid.projectLane i self.state.state).toArray
      = Shake4x.eagerSqueezeState g ∧
  g.squeezed = (squeezeBytes S_pad 0 g.rate g.squeezed.length).toList

/-- Composite squeeze-mode predicate (eager-permute semantics).
    WF bundled (see comment above).

    The `(gs i).rate = self.rate.val` conjunct pins the ghost-side
    rate to the implementation rate; it is the natural soundness
    requirement (the eager normalization above is otherwise
    parameterized only by the lane's own ghost rate, which would
    leave the predicate vacuously satisfied if `(gs i).rate` could
    diverge from `self.rate.val`).

    The `(gs i).squeezed.length % (gs i).rate = 0` block-alignment
    conjunct records that the 4x state machine only ever exposes
    output at block boundaries: every `next_block`/`extract_all`
    cycle consumes exactly `rate` bytes from the squeeze stream.
    This invariant is established by `finalize_*` (where
    `squeezed = []`) and preserved by `next_block_*` (because
    `(g.squeezeAdvance rate).squeezed.length = g.squeezed.length + rate`).
    It is consumed by `next_block.spec` to bridge the per-lane LE
    bytes of the post-permute state to `extractOutput`. -/
def Shake4x.squeezing (self : sha3.shake4x.Shake4x)
    (gs : Fin 4 → GhostState) : Prop :=
  ∃ _h : Shake4x.WF self,
    self.finalized ∧
    Shake4x.gsConsistent gs ∧
    (∀ i : Fin 4, (gs i).rate = self.rate.val) ∧
    (∀ i : Fin 4, (gs i).squeezed.length % (gs i).rate = 0) ∧
    ∀ i : Fin 4, Shake4x.squeezingInvariant self (gs i) i

/-! ## Constructor specs -/

/-! ### Full FC for the constructors

All 6 `Shake4x` fields are pinned:

  * `state` — fully zero, via the `absorbing` per-instance projection
    invariant (every `gs i = init` forces `projectLane i state = 0` for
    all 4 instances, which pins all 100 u64 lanes).
  * `rate`            — explicit literal.
  * `rate_lanes`      — explicit literal (= `rate / 8`).
  * `buf`             — explicit zero-initialized literal.
  * `absorbed`        — explicit zero-initialized literal.
  * `finalized`       — explicit `false`.
-/

/-- **Informal proof** (`new_128`, `Funs.lean:24752-24766`).
    Body: `let kxh ← Keccak4xHybrid.new; let i ← 168/8; let a := Array.repeat 168 0;
    let a1 := Array.repeat 4 a; let a2 := Array.repeat 4 0; ok { … }`.

    Lemma chain:
      1. `Keccak4xHybrid.new.spec` — pins `kxh.state = Array.repeat 25 (Array.repeat 4 0)`.
      2. `Usize.div.spec` on `168/8` — concrete; equals `21`.
      3. The 3 `Array.repeat` are pure literals.

    Post fields:
      * `result.rate = 168#usize` — by record construction (rfl).
      * `result.rate_lanes = 21#usize` — `i` from step 2.
      * `result.absorbed = Array.repeat 4 0` — `a2` directly.
      * `Shake4x.absorbing result (fun _ => GhostState.init 168 0x1F ·)`:
        * `WF result`: `rate ∈ {168, 136}` by `Or.inl rfl`; `rate_lanes * 8 = rate`
          by `21 * 8 = 168`; `∀ i, absorbed[i] = 0 ≤ 168 = rate` by Array.repeat
          getElem reduction.
        * `¬ finalized`: by record construction.
        * `gsConsistent (fun _ => init 168 0x1F)`: all 4 entries are the same, trivial.
        * `∀ i, absorbing (toScalar self i) (init 168 0x1F)`:
          * `toScalar self i`'s `state` is `(projectLane i (Array.repeat 25 (Array.repeat 4 0))).toArray`,
            which is all-zero 25 lanes (projecting any lane index out of a 25-lane
            all-zero state yields all-zero Lanes25), via `projectLane_zero`.
          * `toScalar self i`'s `state_index = (0 % 168) = 0`; `input_block_size = 168`;
            `padding_value = 0x1F`; `squeeze_mode = false`.
          * Matches the scalar `absorbing` predicate at the `init 168 0x1F` ghost state.

    Discharge: `agrind` for arithmetic; `simp [projectLane, Array.repeat]` for the
    state projection.

    Bound dischargers (lines 90-91 sorries in `toScalar`):
      * `self.rate.val < 2^32`: `rate ≤ 168 < 4294967296`. Proof: `agrind`.
      * `(absorbed_i.val % self.rate.val) < 2^32`: bounded by `rate ≤ 168 < 2^32`.
        Proof: `agrind`. -/
-- cost: walltime≈30s heartbeats≈2M loc=40
@[step]
theorem Shake4x.new_128.spec :
    sha3.shake4x.Shake4x.new_128
    ⦃ (result : sha3.shake4x.Shake4x) =>
        result.rate = 168#usize ∧
        result.rate_lanes = 21#usize ∧
        result.absorbed = Array.repeat 4#usize 0#usize ∧
        Shake4x.absorbing result
          (fun _ => GhostState.init 168 0x1F#u8 (by decide)) ⦄ := by
  unfold sha3.shake4x.Shake4x.new_128
  step*
  have hi21 : i = 21#usize := by scalar_tac
  subst hi21
  refine ⟨rfl, ?_⟩
  refine ⟨?WF, ?notFin, ?cons, ?perInst⟩
  case WF =>
    refine ⟨Or.inl rfl, rfl, ?_⟩
    intro j
    have h4 := j.isLt
    match j, h4 with
    | ⟨0, _⟩, _ => simp
    | ⟨1, _⟩, _ => simp
    | ⟨2, _⟩, _ => simp
    | ⟨3, _⟩, _ => simp
  case notFin => exact Bool.false_ne_true
  case cons => intro _ _; exact ⟨rfl, rfl⟩
  case perInst =>
    intro j
    simp only [sha3.sha3_impl.absorbing, sha3.sha3_impl.absorbingWeak,
               sha3.sha3_impl.spongeInvariant, Shake4x.toScalar,
               GhostState.init, kxh_post]
    rw [Keccak4xHybrid.projectLane_zero]
    have hbits :
        toBits (⟨0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64,
                  0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64,
                  0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64,
                  0#u64⟩ : Lanes25).toArray
          = Vector.replicate Spec.SHA3.b false := by
      apply toBits_allZero
      intro k; fin_cases k <;> rfl
    fin_cases j <;> simp [sha3.sha3_impl.absorbBytes, hbits]

/-- **Informal proof** (`new_256`).
    Body and proof identical to `new_128` modulo `rate = 136`, `rate_lanes = 17`
    (since `136/8 = 17`).  All steps and discharges mirror `new_128.spec`. -/
-- cost: walltime≈30s heartbeats≈2M loc=40
@[step]
theorem Shake4x.new_256.spec :
    sha3.shake4x.Shake4x.new_256
    ⦃ (result : sha3.shake4x.Shake4x) =>
        result.rate = 136#usize ∧
        result.rate_lanes = 17#usize ∧
        result.absorbed = Array.repeat 4#usize 0#usize ∧
        Shake4x.absorbing result
          (fun _ => GhostState.init 136 0x1F#u8 (by decide)) ⦄ := by
  unfold sha3.shake4x.Shake4x.new_256
  step*
  have hi17 : i = 17#usize := by scalar_tac
  subst hi17
  refine ⟨rfl, ?_⟩
  refine ⟨?WF, ?notFin, ?cons, ?perInst⟩
  case WF =>
    refine ⟨Or.inr rfl, rfl, ?_⟩
    intro j
    have h4 := j.isLt
    match j, h4 with
    | ⟨0, _⟩, _ => simp
    | ⟨1, _⟩, _ => simp
    | ⟨2, _⟩, _ => simp
    | ⟨3, _⟩, _ => simp
  case notFin => exact Bool.false_ne_true
  case cons => intro _ _; exact ⟨rfl, rfl⟩
  case perInst =>
    intro j
    simp only [sha3.sha3_impl.absorbing, sha3.sha3_impl.absorbingWeak,
               sha3.sha3_impl.spongeInvariant, Shake4x.toScalar,
               GhostState.init, kxh_post]
    rw [Keccak4xHybrid.projectLane_zero]
    have hbits :
        toBits (⟨0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64,
                  0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64,
                  0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64,
                  0#u64⟩ : Lanes25).toArray
          = Vector.replicate Spec.SHA3.b false := by
      apply toBits_allZero
      intro k; fin_cases k <;> rfl
    fin_cases j <;> simp [sha3.sha3_impl.absorbBytes, hbits]

end symcrust
