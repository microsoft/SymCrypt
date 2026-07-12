import Symcrust.Properties.SHA3.Sponge.Init
import Symcrust.Properties.SHA3.Sponge.Absorb
import Symcrust.Properties.SHA3.Sponge.Extract

/-!
# SHA-3 Verification — `ShakeState<R,B>` (StatefulXof + OneShotXof)

Functional-correctness specs for the new const-generic `ShakeState`
interface declared in `src/sha3/shake_variants.rs`.
`ShakeState<RESULT_SIZE, BLOCK_SIZE>` is a thin wrapper around `KeccakState`,
parameterized by the default output size `RESULT_SIZE : usize` and the rate
(in bytes) `BLOCK_SIZE : u32`.

This file proves the user-visible methods:

* `ShakeState::new` — initialise (calls `KeccakState::init(BLOCK_SIZE, 0x1f)`)
* `ShakeState::append` — absorb input bytes (calls `KeccakState::append`)
* `ShakeState::extract` — squeeze a slice with explicit `wipe` flag (calls
  `KeccakState::extract`)
* `ShakeState::result` — squeeze exactly `RESULT_SIZE` bytes into an array,
  always wiping (calls `KeccakState::extract _ _ true`)
* `OneShotShake::xof` — composition of `new ; append ; extract _ true`

The legacy `Shake256State` / `Shake128X4State` wrappers around `shake1x.rs`
live in [`Variants.lean`](Variants.lean) and will eventually be retired in
favour of the const-generic interface.
-/

namespace symcrust

open Aeneas Aeneas.Std Result
open Spec
open sha3.sha3_impl

namespace sha3.shake_variants

/-! ## `ShakeState.new` — initialise to absorbing state -/

/-- `ShakeState::new` builds a fresh `KeccakState` with the requested rate
    and the SHAKE padding suffix `0x1f`. The post-state is in `absorbing`
    relation with the canonical initial ghost state. -/
@[step] theorem ShakeState.new.spec
    (R : Std.Usize) (B : Std.U32)
    (h_rate : 0 < B.val ∧ 8 * B.val < SHA3.b ∧ B.val % 8 = 0) :
    ShakeState.Insts.SymcrustHashStatefulXof.new R B
    ⦃ (r : ShakeState R B) =>
      absorbing r.state (.init B.val SHAKE_PADDING_VALUE h_rate) ⦄ := by
  unfold ShakeState.Insts.SymcrustHashStatefulXof.new
  step*

/-! ## `ShakeState.append` — absorb a slice of input bytes -/

/-- `ShakeState::append` forwards directly to `KeccakState::append`; the
    `absorbing-or-squeezing → absorbing` postcondition is inherited
    verbatim. -/
@[step] theorem ShakeState.append.spec
    {R : Std.Usize} {B : Std.U32}
    (self : ShakeState R B) (data : Slice Std.U8) (g : GhostState)
    (h : absorbing self.state g ∨ squeezing self.state g) :
    ShakeState.Insts.SymcrustHashStatefulXof.append self data
    ⦃ (r : ShakeState R B) =>
      absorbing r.state (g.append data.val self.state.squeeze_mode) ⦄ := by
  unfold ShakeState.Insts.SymcrustHashStatefulXof.append
  step*

/-! ## `ShakeState.extract` — squeeze into a `Slice` with explicit `wipe` -/

/-- `ShakeState::extract` forwards directly to `KeccakState::extract`. The
    output bytes equal `extractOutput g result.length`; the post-state is
    a fresh absorbing init when `wipe`, otherwise a continuation of squeezing. -/
@[step] theorem ShakeState.extract.spec
    {R : Std.Usize} {B : Std.U32}
    (self : ShakeState R B) (result : Slice Std.U8) (wipe : Bool)
    (g : GhostState)
    (h : absorbing self.state g ∨ squeezing self.state g) :
    ShakeState.Insts.SymcrustHashStatefulXof.extract self result wipe
    ⦃ (r : ShakeState R B × Slice Std.U8) =>
      r.2.length = result.length ∧
      r.2.val = (extractOutput g result.length).toList ∧
      (if wipe then absorbing r.1.state (.init g.rate g.padVal g.h_rate)
       else squeezing r.1.state (g.squeeze r.2.val)) ⦄ := by
  unfold ShakeState.Insts.SymcrustHashStatefulXof.extract
  step*
  exact ⟨ks_post1, ks_post2, ks_post3⟩

/-! ## `ShakeState.result` — squeeze `R` bytes into an `Array` (always wipes) -/

/-- `ShakeState::result` calls `KeccakState::extract _ _ true`, so the
    post-state returns to a wiped absorbing state. The bytes equation is
    bridged from `Slice` to `Array` via `Aeneas.Std.Array.from_slice_val`. -/
@[step] theorem ShakeState.result.spec
    {R : Std.Usize} {B : Std.U32}
    (self : ShakeState R B) (output : Std.Array Std.U8 R) (g : GhostState)
    (h : absorbing self.state g ∨ squeezing self.state g) :
    ShakeState.Insts.SymcrustHashStatefulXof.result self output
    ⦃ (r : ShakeState R B × Std.Array Std.U8 R) =>
      r.2.val = (extractOutput g R.val).toList ∧
      absorbing r.1.state (.init g.rate g.padVal g.h_rate) ⦄ := by
  unfold ShakeState.Insts.SymcrustHashStatefulXof.result
  step
  let* ⟨ks, output', hlen, hbytes, hpost⟩ ←
    KeccakState.extract.spec (g := g)
  subst s_post2
  have hs_len : s.length = R.val := by
    simp only [Aeneas.Std.Slice.length, s_post1]; exact output.property
  have hlen' : (↑output' : List Std.U8).length = R.val := by
    rw [show (↑output' : List Std.U8).length = output'.length from rfl, hlen, hs_len]
  refine ⟨?_, ?_⟩
  · rw [Aeneas.Std.Array.from_slice_val output output' hlen']
    rw [hbytes, hs_len]
  · simpa using hpost

/-! ## `OneShotShake.xof` — `new ; append ; extract _ true` end-to-end -/

/-- `OneShotShake::xof` composes `new`, `append`, and `extract` with `wipe = true`.
    The structural postcondition relates `result.val` to `extractOutput` over
    the post-append ghost state. -/
@[step] theorem OneShotShake.xof.spec
    (R : Std.Usize) (B : Std.U32) (data : Slice Std.U8) (result : Slice Std.U8)
    (h_rate : 0 < B.val ∧ 8 * B.val < SHA3.b ∧ B.val % 8 = 0) :
    OneShotShake.Insts.SymcrustHashOneShotXof.xof R B data result
    ⦃ (r : Slice Std.U8) =>
      r.length = result.length ∧
      r.val = (extractOutput
                 ((GhostState.init B.val SHAKE_PADDING_VALUE h_rate).append
                   data.val false)
                 result.length).toList ⦄ := by
  unfold OneShotShake.Insts.SymcrustHashOneShotXof.xof
  let gInit : GhostState := GhostState.init B.val SHAKE_PADDING_VALUE h_rate
  let* ⟨state, hstate⟩ ← ShakeState.new.spec R B h_rate
  have hsm : state.state.squeeze_mode = false := by
    have := hstate.1.2.1; simp_all
  let* ⟨state1, hstate1⟩ ←
    ShakeState.append.spec state data gInit (Or.inl hstate)
  rw [hsm] at hstate1
  let* ⟨pair, output', hlen, hbytes, _⟩ ←
    ShakeState.extract.spec (wipe := true) state1 result
      (gInit.append data.val false) (Or.inl hstate1)
  exact ⟨hlen, hbytes⟩

end sha3.shake_variants

end symcrust
