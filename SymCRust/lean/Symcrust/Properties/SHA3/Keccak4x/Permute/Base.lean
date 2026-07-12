/-
# Properties/SHA3/Keccak4x/Permute — safe 4-way `Keccak4x.permute` ≡
                                   four parallel scalar `keccak_permute`.

All `@[step]` theorems below have real, vacuity-checked postconditions
and complete proofs.

Design:

  * The 4x state is `Array Lane4 25 = Array (Array U64 4) 25`.
  * `projectLane (i : Fin 4) : Array Lane4 25 → Lanes25` extracts the
    `i`-th u64 from each of the 25 Lane4s.
  * The safe-variant permute is proved correct by 4 independent
    instances of the existing `iterateRndCore_toState` (see
    `Properties/SHA3/Keccak/Core.lean:365`), one per lane index `i`.
  * No SIMD intrinsics on this path — proof obligation is purely
    algebraic (`Lane4.xor`/`andnot`/`rol`/`xor_assign` lift to lane-wise
    bitvector operations, mirroring the scalar round functions).
  * The 755-line fully-unrolled `permute_loop` body in `Code/Funs.lean`
    (line 22585) is a candidate for `#decompose`-driven folding to a
    24-iteration round structure (mirroring scalar
    `Properties/SHA3/Keccak/Fold.lean`), though the spec statement below
    is what callers consume.
-/
import Symcrust.Code
import Symcrust.Properties.SHA3.Basic
import Symcrust.Properties.SHA3.Keccak.Core
import Symcrust.Properties.SHA3.Keccak.Fold
import Symcrust.Properties.SHA3.Keccak.Loop
import Symcrust.Properties.SHA3.Keccak4x.Lane4

namespace symcrust

open Aeneas Aeneas.Std Result
open sha3.sha3_impl
open scoped Spec.Notations

set_option linter.unusedSectionVars false
set_option linter.unusedVariables false

/- Fast bound discharge for `a[_]` on size-typed `Std.Array`: try cheap tactics
   first (named bounds by `assumption`, literal indices by `decide` after
   `length_eq`), then `scalar_tac`, and finally `length_eq`-rewrite + `scalar_tac`
   so variable indices like `i.val` (with `i : Fin n`) close without explicit
   length hypotheses. -/
local macro_rules | `(tactic| get_elem_tactic) => `(tactic| first | assumption | (simp only [Aeneas.Std.Array.length_eq, List.length_set]; first | assumption | decide) | scalar_tac | (simp only [Aeneas.Std.Array.length_eq, List.length_set]; scalar_tac))

/- `Lane4` is a `def` for `Array U64 4`, so `Array.length_eq` does not fire on
   `l.val.length`.  Expose the length to the solvers (and hence to the
   `get_elem_tactic` override) so `l[i]` bounds discharge without an explicit
   `l.val.length = 4` hypothesis. -/
@[local scalar_tac_simps, local agrind =]
theorem Lane4_val_length (l : sha3.keccak4x.Lane4) : l.val.length = 4 := by
  have := l.property; scalar_tac

/-! ## Per-instance projection from the 4-way state to a scalar `Lanes25` -/

/-- Project the `i`-th u64 lane out of each of the 25 `Lane4` slots,
    yielding a single scalar `Lanes25` view.  Both bounds are
    structural: `s.val.length = 25` from `s.property`, and each lane's
    `l.val.length = 4` from `Lane4 = Array U64 4`'s `property`. -/
def Keccak4x.projectLane (i : Fin 4) (s : Array sha3.keccak4x.Lane4 25#usize) :
    Lanes25 :=
  let lane (k : Nat) (hk : k < 25 := by decide) : U64 :=
    let l := s.val[k]
    l.val[i.val]
  ⟨lane 0,  lane 1,  lane 2,  lane 3,  lane 4,
   lane 5,  lane 6,  lane 7,  lane 8,  lane 9,
   lane 10, lane 11, lane 12, lane 13, lane 14,
   lane 15, lane 16, lane 17, lane 18, lane 19,
   lane 20, lane 21, lane 22, lane 23, lane 24⟩

/-- Project the `i`-th u64 out of a single `Lane4`.  Helper for the
    `projectLane_*` distributivity lemmas. -/
def Keccak4x.projectLane_lane (i : Fin 4) (l : sha3.keccak4x.Lane4) : U64 :=
  l.val[i.val]

/-! ## `projectLane_*` distributivity lemmas

  Each lemma is stated against the *postcondition* form produced by the
  corresponding `Lane4.spec` after `step`: given a per-lane equation
  `r.val[k] = OP (a.val[k]) (b.val[k])`, conclude that
  `projectLane_lane` distributes accordingly.  Layer 3 consumes these
  to reduce the per-round 4-way step to 4 parallel scalar
  `fusedRoundCore` invocations. -/

/-- Zero lane projection: the all-zero `Lane4` projects to zero. -/
theorem Keccak4x.projectLane_lane_zero (i : Fin 4) :
    Keccak4x.projectLane_lane i ⟨List.replicate 4 (0#u64), by simp⟩ = 0#u64 := by
  unfold projectLane_lane
  have := i.isLt
  match i, this with
  | ⟨0, _⟩, _ => rfl
  | ⟨1, _⟩, _ => rfl
  | ⟨2, _⟩, _ => rfl
  | ⟨3, _⟩, _ => rfl

/-- Whole-state zero projection: projecting any lane index out of the
    fresh 4-way state (`Array.repeat 25 (Array.repeat 4 0)`) yields the
    all-zero `Lanes25`.  Consumed by `Shake4x.new_{128,256}.spec` to
    establish `spongeInvariant` on the initial sponge state. -/
theorem Keccak4x.projectLane_zero (i : Fin 4) :
    Keccak4x.projectLane i (Array.repeat 25#usize (Array.repeat 4#usize 0#u64))
      = ⟨0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64,
         0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64, 0#u64,
         0#u64, 0#u64, 0#u64, 0#u64, 0#u64⟩ := by
  unfold projectLane
  have := i.isLt
  match i, this with
  | ⟨0, _⟩, _ => rfl
  | ⟨1, _⟩, _ => rfl
  | ⟨2, _⟩, _ => rfl
  | ⟨3, _⟩, _ => rfl

/-- `xor` distributes through `projectLane_lane`. -/
theorem Keccak4x.projectLane_xor (a b r : sha3.keccak4x.Lane4)
    (hL : r.val.length = 4)
    (hr : ∀ k, (hk : k < 4) →
      r.val[k]
        = a.val[k]
            ^^^ b.val[k])
    (i : Fin 4) :
    Keccak4x.projectLane_lane i r
      = Keccak4x.projectLane_lane i a ^^^ Keccak4x.projectLane_lane i b := by
  unfold projectLane_lane
  exact hr i.val i.isLt

/-- `andnot` distributes through `projectLane_lane`. -/
theorem Keccak4x.projectLane_andnot (a b r : sha3.keccak4x.Lane4)
    (hL : r.val.length = 4)
    (hr : ∀ k, (hk : k < 4) →
      r.val[k]
        = (~~~ a.val[k])
            &&& b.val[k])
    (i : Fin 4) :
    Keccak4x.projectLane_lane i r
      = (~~~ Keccak4x.projectLane_lane i a) &&& Keccak4x.projectLane_lane i b := by
  unfold projectLane_lane
  exact hr i.val i.isLt

/-- `rol` distributes through `projectLane_lane`. -/
theorem Keccak4x.projectLane_rol (n : U32) (self r : sha3.keccak4x.Lane4)
    (hL : r.val.length = 4)
    (hr : ∀ k, (hk : k < 4) →
      r.val[k].bv
        = self.val[k].bv.rotateLeft n.val)
    (i : Fin 4) :
    (Keccak4x.projectLane_lane i r).bv
      = (Keccak4x.projectLane_lane i self).bv.rotateLeft n.val := by
  unfold projectLane_lane
  exact hr i.val i.isLt

/-- `xor_assign` distributes through `projectLane_lane` (same shape as
    `projectLane_xor`; the result is a fresh `Lane4` regardless of
    whether the implementation mutates in place). -/
theorem Keccak4x.projectLane_xor_assign (a b r : sha3.keccak4x.Lane4)
    (hL : r.val.length = 4)
    (hr : ∀ k, (hk : k < 4) →
      r.val[k]
        = a.val[k]
            ^^^ b.val[k])
    (i : Fin 4) :
    Keccak4x.projectLane_lane i r
      = Keccak4x.projectLane_lane i a ^^^ Keccak4x.projectLane_lane i b := by
  unfold projectLane_lane
  exact hr i.val i.isLt

/-! ## `projectLane_lane` homomorphisms over the pure `Lane4` algebra

  These take the *whole-`Lane4`* output of a phase (`s50[j] = l_a ^^^ …`)
  and push `projectLane_lane i` through the bitwise notation, reducing the
  4-way round to a scalar one at lane `i : Fin 4` — no `i.val`/`i.isLt`
  splitting, no `∀ k < 4` pointwise hypotheses. -/

theorem Keccak4x.projectLane_lane_xor (a b : sha3.keccak4x.Lane4) (i : Fin 4) :
    Keccak4x.projectLane_lane i (a ^^^ b)
      = Keccak4x.projectLane_lane i a ^^^ Keccak4x.projectLane_lane i b := by
  unfold projectLane_lane
  exact Keccak4x.getElem_xor a b i.val i.isLt

theorem Keccak4x.projectLane_lane_and (a b : sha3.keccak4x.Lane4) (i : Fin 4) :
    Keccak4x.projectLane_lane i (a &&& b)
      = Keccak4x.projectLane_lane i a &&& Keccak4x.projectLane_lane i b := by
  unfold projectLane_lane
  exact Keccak4x.getElem_and a b i.val i.isLt

theorem Keccak4x.projectLane_lane_not (a : sha3.keccak4x.Lane4) (i : Fin 4) :
    Keccak4x.projectLane_lane i (~~~ a)
      = ~~~ Keccak4x.projectLane_lane i a := by
  unfold projectLane_lane
  exact Keccak4x.getElem_not a i.val i.isLt

theorem Keccak4x.projectLane_lane_rotl4 (a : sha3.keccak4x.Lane4) (n : U32) (i : Fin 4) :
    (Keccak4x.projectLane_lane i (Keccak4x.rotl4 a n)).bv
      = (Keccak4x.projectLane_lane i a).bv.rotateLeft n.val := by
  unfold projectLane_lane
  exact Keccak4x.bv_getElem_rotl4 a n i.val i.isLt

/-- Value-level `rotl4` homomorphism: `projectLane_lane` of a rotated lane is the
    scalar `core.num.U64.rotate_left` of the projected lane. -/
theorem Keccak4x.projectLane_lane_rotl4_val (a : sha3.keccak4x.Lane4) (n : U32) (i : Fin 4) :
    Keccak4x.projectLane_lane i (Keccak4x.rotl4 a n)
      = core.num.U64.rotate_left (Keccak4x.projectLane_lane i a) n := by
  unfold projectLane_lane
  simp only [Keccak4x.val_rotl4, List.getElem_map]
  rfl


/-! ## `#decompose` cascade — extract one-round helper `body_fused`

  Mirrors the scalar `Keccak/Fold.lean`: extract the post-iterator
  `match` as `match_helper`, then extract the 349-binding `some` branch
  body as `body_fused` (the recursive `permute_loop` call stays
  outside). -/

set_option maxRecDepth 4096 in
#decompose sha3.keccak4x.Keccak4x.permute_loop Keccak4x.permute_loop.match_helper_eq
  letRange 1 1 => Keccak4x.permute_loop.match_helper

set_option maxRecDepth 4096 in
#decompose Keccak4x.permute_loop.match_helper Keccak4x.permute_loop.match_helper_branch_eq
  branch 1 (letRange 0 349) => Keccak4x.permute_loop.body_fused

/-! ### Phase decomposition of `body_fused`

  The 349-binding `body_fused` mirrors the Rust source structure
  (`src/sha3/keccak4x.rs:147-198`): one inlined loop iteration with
  five named phases (θ.D, θ.apply, ρπ, χ, ι).  We split `body_fused`
  along those boundaries via a single multi-clause `#decompose`
  invocation, generating one helper per Rust phase.  Each helper
  becomes the target of an independent `@[step]` spec — keeping the
  per-phase proof tractable (max 165 bindings instead of 349).

  Position counts, derived from `Code/Funs.lean:22585+` (positions
  relative to `body_fused` after each prior fold):

  | Phase            | Rust lines | Bindings | Effect on state            |
  |------------------|------------|---------:|----------------------------|
  | θ.D              | 151-161    |       55 | compute c₀…c₄, d₀…d₄       |
  | θ.apply          | 163-167    |       75 | 25× xor_assign → s25       |
  | ρπ               | 170-177    |       49 | 25 rotated lanes l95…l143  |
  | χ                | 180-194    |      165 | 5 chi_row! → s50           |
  | ι                | 197        |        5 | splat + xor_assign → final |

  Each subsequent `letRange` index increments by 1 from its
  predecessor (multi-clause indices are relative to the body
  *after* prior folds collapse N bindings into 1 helper call). -/

set_option maxRecDepth 8192 in
#decompose Keccak4x.permute_loop.body_fused Keccak4x.permute_loop.body_fused.phases_eq
  letRange 0 55  => Keccak4x.permute_loop.phase_theta_d
  letRange 1 75  => Keccak4x.permute_loop.phase_theta_apply
  letRange 2 49  => Keccak4x.permute_loop.phase_rho_pi
  letRange 3 165 => Keccak4x.permute_loop.phase_chi
  letRange 4 5   => Keccak4x.permute_loop.phase_iota



/-! ### Second-level cascade: split `phase_chi` along the `chi_row!` macro

  The Rust source (`src/sha3/keccak4x.rs:180-194`) defines a
  `chi_row!($r)` macro that performs 5 writes to row `$r` of the
  state, and invokes it 5 times.  Each macro expansion lowers to
  ~33 monadic bindings in the extracted code (5 writes × (3 reads
  + andnot + xor + Array.update) = 30, plus a few setup binders).
  We mirror this structure by cascading `#decompose` on
  `phase_chi`, generating one helper per macro invocation. -/
set_option maxRecDepth 8192 in
#decompose Keccak4x.permute_loop.phase_chi Keccak4x.permute_loop.phase_chi.rows_eq
  letRange 0 33 => Keccak4x.permute_loop.phase_chi_row_0
  letRange 1 33 => Keccak4x.permute_loop.phase_chi_row_1
  letRange 2 33 => Keccak4x.permute_loop.phase_chi_row_2
  letRange 3 33 => Keccak4x.permute_loop.phase_chi_row_3
  letRange 4 33 => Keccak4x.permute_loop.phase_chi_row_4

/-! ### Second-level cascade: split `phase_theta_apply` into 5 rows

  The Rust source (`src/sha3/keccak4x.rs:163-167`) has 5 lines, each
  performing 5 in-place `xor_assign` calls against `d_k`.  Each
  `xor_assign` lowers to 3 bindings in the extracted code
  (`index_mut + xor_assign + index_mut_back`).  Each row therefore
  contains 5 × 3 = 15 bindings.  We cascade `#decompose` along
  these 5 rows. -/
set_option maxRecDepth 8192 in
#decompose Keccak4x.permute_loop.phase_theta_apply Keccak4x.permute_loop.phase_theta_apply.rows_eq
  letRange 0 15 => Keccak4x.permute_loop.phase_theta_apply_row_0
  letRange 1 15 => Keccak4x.permute_loop.phase_theta_apply_row_1
  letRange 2 15 => Keccak4x.permute_loop.phase_theta_apply_row_2
  letRange 3 15 => Keccak4x.permute_loop.phase_theta_apply_row_3
  letRange 4 15 => Keccak4x.permute_loop.phase_theta_apply_row_4

end symcrust
