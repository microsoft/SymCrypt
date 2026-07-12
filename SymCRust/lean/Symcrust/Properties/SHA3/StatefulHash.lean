import Symcrust.Properties.SHA3.Sponge.Init
import Symcrust.Properties.SHA3.Sponge.Absorb
import Symcrust.Properties.SHA3.Sponge.Extract

/-!
# SHA-3 Verification — `Sha3State<R,B>` (StatefulHash + OneShotHash)

Functional-correctness specs for the new const-generic `Sha3State` interface
declared in `src/sha3/sha3_variants.rs`. `Sha3State<RESULT_SIZE, BLOCK_SIZE>`
is a thin wrapper around `KeccakState`, parameterized by the digest size
`RESULT_SIZE : usize` and the rate (in bytes) `BLOCK_SIZE : u32`.

This file proves the four user-visible methods:

* `Sha3State::new` — initialise (calls `KeccakState::init(BLOCK_SIZE, 0x06)`)
* `Sha3State::append` — absorb input bytes (calls `KeccakState::append`)
* `Sha3State::result` — finalise + squeeze `RESULT_SIZE` bytes (calls
  `KeccakState::extract _ true` with wipe)
* `OneShotSha3::hash` — composition of the three above

The four `(R, B)` pairs the API will be instantiated at are
`(28, 144) / (32, 136) / (48, 104) / (64, 72)`, but the specs below are
generic in `(R, B)`: the rate validity is carried as an explicit
`h_rate : 0 < B.val ∧ 8 * B.val < SHA3.b ∧ B.val % 8 = 0` precondition.
Clients supply `h_rate` once (typically `by native_decide`) and the rest
threads through unchanged.

The corresponding `ShakeState`/`OneShotShake` specs live in
[`StatefulXof.lean`](StatefulXof.lean); the legacy `Sha3_*State` / `*Xof`
wrappers around `shake1x.rs` live in [`Variants.lean`](Variants.lean) and
will eventually be retired in favour of the const-generic interface.
-/

namespace symcrust

open Aeneas Aeneas.Std Result
open Spec
open sha3.sha3_impl

namespace sha3.sha3_variants

/-! ## `Sha3State.new` — initialise to absorbing state -/

/-- `Sha3State::new` builds a fresh `KeccakState` with the requested rate
    and the SHA-3 padding suffix `0x06`. The post-state is in `absorbing`
    relation with the canonical initial ghost state. -/
@[step] theorem Sha3State.new.spec
    (R : Std.Usize) (B : Std.U32)
    (h_rate : 0 < B.val ∧ 8 * B.val < SHA3.b ∧ B.val % 8 = 0) :
    Sha3State.Insts.SymcrustHashStatefulHash.new R B
    ⦃ (r : Sha3State R B) =>
      absorbing r.state (.init B.val SHA3_PADDING_VALUE h_rate) ⦄ := by
  unfold Sha3State.Insts.SymcrustHashStatefulHash.new
  step*

/-! ## `Sha3State.append` — absorb a slice of input bytes -/

/-- `Sha3State::append` forwards directly to `KeccakState::append`; the
    `absorbing-or-squeezing → absorbing` postcondition is inherited
    verbatim. -/
@[step] theorem Sha3State.append.spec
    {R : Std.Usize} {B : Std.U32}
    (self : Sha3State R B) (data : Slice Std.U8) (g : GhostState)
    (h : absorbing self.state g ∨ squeezing self.state g) :
    Sha3State.Insts.SymcrustHashStatefulHash.append self data
    ⦃ (r : Sha3State R B) =>
      absorbing r.state (g.append data.val self.state.squeeze_mode) ⦄ := by
  unfold Sha3State.Insts.SymcrustHashStatefulHash.append
  step*

/-! ## `Sha3State.result` — finalise + squeeze `R` bytes -/

/-- `Sha3State::result` calls `KeccakState::extract _ _ true` with `wipe = true`,
    so the post-state returns to a wiped absorbing state and the produced
    bytes equal `extractOutput g R` truncated through `from_slice_val`.

    This mirrors the existing `Sha3_256State.extract.spec` /
    `Sha3_512State.extract.spec` pattern in [`Variants.lean`](Variants.lean),
    generalised over `(R, B)`. -/
@[step] theorem Sha3State.result.spec
    {R : Std.Usize} {B : Std.U32}
    (self : Sha3State R B) (output : Std.Array Std.U8 R) (g : GhostState)
    (h : absorbing self.state g ∨ squeezing self.state g) :
    Sha3State.Insts.SymcrustHashStatefulHash.result self output
    ⦃ (r : Sha3State R B × Std.Array Std.U8 R) =>
      r.2.val = (extractOutput g R.val).toList ∧
      absorbing r.1.state (.init g.rate g.padVal g.h_rate) ⦄ := by
  unfold Sha3State.Insts.SymcrustHashStatefulHash.result
  step
  let* ⟨ks, output', hlen, hbytes, hpost⟩ ←
    KeccakState.extract.spec (g := g)
  -- `s` is `output.to_slice`, so `s.length = R.val` via `output.property`.
  have hs_len : s.length = R.val := by
    show (↑s : List Std.U8).length = R.val
    rw [s_post1]; exact output.property
  have hout'_len : (↑output' : List Std.U8).length = R.val := by
    rw [show (↑output' : List Std.U8).length = output'.length from rfl, hlen, hs_len]
  refine ⟨?_, ?_⟩
  · -- `to_slice_mut_back = output.from_slice`; commute and use `from_slice_val`.
    rw [s_post2, Aeneas.Std.Array.from_slice_val output output' hout'_len,
        hbytes, hs_len]
  · simpa using hpost

/-! ## `OneShotSha3.hash` — `new ; append ; result` end-to-end -/

/-- `OneShotSha3::hash` composes `new`, `append`, and `result`. The
    structural postcondition relates `result.val` to `extractOutput` over
    the post-append ghost state; the FIPS-202 endpoint connection (e.g.
    `result.val = SHA3.sha3_256 input` for `(R,B) = (32,136)`) is a
    monomorphic downstream step using the FIPS bridge in
    [`Sponge/BridgeBitFC.lean`](Sponge/BridgeBitFC.lean), exactly as
    [`Shake1x.lean`](Shake1x.lean) does for the legacy interface. -/
@[step] theorem OneShotSha3.hash.spec
    {R : Std.Usize} (B : Std.U32) (data : Slice Std.U8)
    (result : Std.Array Std.U8 R)
    (h_rate : 0 < B.val ∧ 8 * B.val < SHA3.b ∧ B.val % 8 = 0) :
    OneShotSha3.Insts.SymcrustHashOneShotHash.hash B data result
    ⦃ (r : Std.Array Std.U8 R) =>
      r.val = (extractOutput
                 ((GhostState.init B.val SHA3_PADDING_VALUE h_rate).append
                   data.val false)
                 R.val).toList ⦄ := by
  unfold OneShotSha3.Insts.SymcrustHashOneShotHash.hash
  let gInit : GhostState := GhostState.init B.val SHA3_PADDING_VALUE h_rate
  let* ⟨state, hstate⟩ ← Sha3State.new.spec R B h_rate
  -- The fresh state has `squeeze_mode = false` (init clears it).
  have hsm : state.state.squeeze_mode = false := by
    have := hstate.1.2.1; simp_all
  let* ⟨state1, hstate1⟩ ←
    Sha3State.append.spec state data gInit (Or.inl hstate)
  rw [hsm] at hstate1
  let* ⟨pair, hpair, hpair_eq, _⟩ ←
    Sha3State.result.spec state1 result (gInit.append data.val false)
      (Or.inl hstate1)
  exact hpair_eq

end sha3.sha3_variants

end symcrust
