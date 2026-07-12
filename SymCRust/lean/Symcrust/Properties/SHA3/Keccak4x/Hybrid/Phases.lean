/-
# Properties/SHA3/Keccak4x/Hybrid/Phases — phase scaffolding for `Keccak4xHybrid.permute`.

This module carries the heavy half of the hybrid permute proof: the silicon-op
`@[step]` wrappers, `rol_lift`, `projectLane` infrastructure, the `#decompose`
cascade that extracts `body_fused` + the 7 `phase_*` helpers, and the seven
whole-`Lane4` phase specs.  The light composition (`body_fused.spec`,
`permute_loop.spec`, `permute.spec`) lives in the parent `Hybrid.lean`, which
imports this module.  Splitting keeps the composition file LSP-tractable
(mirrors the `Permute/` split).

The hybrid `permute_loop` body (`Code/Funs.lean:23572-23932`, 361 lines)
open-codes every Keccak `rol c k` step as

```
v   ← load_lane c                          -- Lane4 → __m256i
mi  ← _mm256_slli_epi64  k     v           -- AVX2 shift
mi1 ← _mm256_srli_epi64 (64-k) v           -- AVX2 shift
r   ← _mm256_or_si256   mi mi1             -- AVX2 or
out ← store_lane (Array.repeat 4 0) r      -- __m256i → Lane4
```

`load_lane` / `store_lane` are total `def`s in
`Code/FunsExternal.lean` using `__m256i.{u64x4, ofU64x4}` from
the Intrinsics model.

The three AVX2 ops (`_mm256_or_si256`, `_mm256_slli_epi64`,
`_mm256_srli_epi64`) are theorem-backed against the diff-tested shims in
`verify::intrinsics::x86_64::avx2` (see
`lean/Intrinsics/Properties/X86_64/Avx2.lean`).  The local wrappers below
are thin SHA3-preferred-shape (`r.u64x4.val[k]`) wrappers that consume
those facts via `step` and bridge the equality via
`Aeneas.Std.UScalar.eq_equiv_bv_eq`; SHA3 does NOT pin any fresh trust by
wrapping them.
-/
import Symcrust.Code
import Symcrust.Properties.SHA3.Basic
import Symcrust.Properties.SHA3.Keccak.Core
import Symcrust.Properties.SHA3.Keccak4x.Lane4
import Symcrust.Properties.SHA3.Keccak4x.Permute
import Intrinsics.Properties.X86_64.Avx2

namespace symcrust

open Aeneas Aeneas.Std Result
open sha3.sha3_impl
open scoped Spec.Notations
open Intrinsics.X86_64

set_option linter.unusedSectionVars false
set_option linter.unusedVariables false

/-! ## Layer 0 — Silicon-op `@[step]` wrappers + `rol4_correct`

The 3 AVX2 ops (`_mm256_or_si256`, `_mm256_slli_epi64`,
`_mm256_srli_epi64`) are theorem-backed in
`lean/Intrinsics/Properties/X86_64/Avx2.lean`
in `r.u64x4[k].bv = …` shape.  SHA3-4x consumers
expect the equivalent SHA3-preferred shape `r.u64x4.val[k] = …`.  The
three `private @[step] theorem`s below are thin wrappers that consume
those facts via `step` and bridge the equality via
`Aeneas.Std.UScalar.eq_equiv_bv_eq`.

The wrappers are `private` to this file: they are the only
`step`-eligible facts SHA3-4x needs for the silicon names, and we do
NOT want them to leak into other modules that may have their own
opinions on these axioms.

`rol4_correct` is the per-call composite identity (lane-wise
`(x <<< k) ||| (x >>> (64 - k)) = x.rotateLeft k`) consumed by the
hybrid permute proof.  It depends on the 3 wrappers via `step`
and closes via `bv_decide` after destructuring the `u64x4` view. -/

/-- `ymm.or_si256` wrapper — bitwise OR per 64-bit lane.  Bridges the
    byte-carrier `ymm.or_si256.spec` (`Properties/X86_64/Avx2.lean`)
    to the SHA3-preferred `(m256.u64x4 r).val[k]` shape. -/
@[local step]
private theorem ymm_or_si256_spec
    (a b : m256) :
    verify.intrinsics.x86_64.ymm.or_si256 a b
    ⦃ (r : m256) =>
        ∀ k, (hk : k < 4) →
          (m256.u64x4 r).val[k] = (m256.u64x4 a).val[k] ||| (m256.u64x4 b).val[k] ⦄ := by
  step with verify.intrinsics.x86_64.ymm.or_si256.spec as ⟨r, h_post⟩
  rename_i k hk
  rw [Aeneas.Std.UScalar.eq_equiv_bv_eq]
  exact h_post k hk

/-- `ymm.slli_epi64` wrapper — per-lane 64-bit shift left by immediate.
    `IMM8 ≥ 64` zeroes the lane. -/
@[local step]
private theorem ymm_slli_epi64_spec
    (IMM8 : Std.I32) (v : m256) :
    verify.intrinsics.x86_64.ymm.slli_epi64 IMM8 v
    ⦃ (r : m256) =>
        ∀ k, (hk : k < 4) →
          (m256.u64x4 r).val[k] =
            if 0 ≤ IMM8.val ∧ IMM8.val < 64
            then (⟨BitVec.shiftLeft (m256.u64x4 v).val[k].bv IMM8.toNat⟩ : U64)
            else 0#u64 ⦄ := by
  step with verify.intrinsics.x86_64.ymm.slli_epi64.spec as ⟨r, h_post⟩
  rename_i k hk
  rw [Aeneas.Std.UScalar.eq_equiv_bv_eq]
  have h := h_post k hk
  split_ifs with hIMM
  · rw [if_pos hIMM] at h; exact h
  · rw [if_neg hIMM] at h; exact h

/-- `ymm.srli_epi64` wrapper — per-lane 64-bit logical shift right by
    immediate.  `IMM8 ≥ 64` zeroes the lane. -/
@[local step]
private theorem ymm_srli_epi64_spec
    (IMM8 : Std.I32) (v : m256) :
    verify.intrinsics.x86_64.ymm.srli_epi64 IMM8 v
    ⦃ (r : m256) =>
        ∀ k, (hk : k < 4) →
          (m256.u64x4 r).val[k] =
            if 0 ≤ IMM8.val ∧ IMM8.val < 64
            then (⟨BitVec.ushiftRight (m256.u64x4 v).val[k].bv IMM8.toNat⟩ : U64)
            else 0#u64 ⦄ := by
  step with verify.intrinsics.x86_64.ymm.srli_epi64.spec as ⟨r, h_post⟩
  rename_i k hk
  rw [Aeneas.Std.UScalar.eq_equiv_bv_eq]
  have h := h_post k hk
  split_ifs with hIMM
  · rw [if_pos hIMM] at h; exact h
  · rw [if_neg hIMM] at h; exact h

/-- Per-lane "shift-left ∨ shift-right = rotate" identity that bridges
    the hybrid 3-op rotation chain
    `_mm256_or_si256 (_mm256_slli_epi64 k v) (_mm256_srli_epi64 (64 - k) v)`
    to the scalar `BitVec.rotateLeft k`.  Closed via the spec of
    `BitVec.rotateLeft` plus `Nat.mod_eq_of_lt` (the rotation amount is
    bounded so `k % 64 = k`).

    In Layer 3, this composes with the 3 silicon-op placeholders above:
    after `step` introduces the slli / srli / or postconditions on the
    `u64x4` view, the per-lane residual reduces to this identity. -/
theorem rol4_correct (b : BitVec 64) (k : Nat) (h : 0 < k ∧ k < 64) :
    BitVec.shiftLeft b k ||| BitVec.ushiftRight b (64 - k) = b.rotateLeft k := by
  show b <<< k ||| b >>> (64 - k) = b.rotateLeft k
  rw [BitVec.rotateLeft_def, Nat.mod_eq_of_lt h.2]

/-! ## D3-α `load_lane` / `store_lane` `@[step]` specs

The hybrid `rol` open-coding consumes 5 monadic ops per call:
`load_lane c; slli k v; srli (64-k) v; or mi mi1; store_lane _ r`.
We give `load_lane` / `store_lane` `@[local step]` specs so `step*`
through `body_fused` chains them with the 3 silicon-op posts
above.  Bodies are defs in `Code/FunsExternal.lean:1040-1057`; the
specs are pure unfolds + `__m256i.{u64x4_ofU64x4, ofU64x4_u64x4}`
round-trips. -/

/-- Spec for `load_lane`: returns `ofU64x4 l`, whose `m256.u64x4` view
    round-trips to `l` (Intrinsics `m256.u64x4_ofU64x4`). -/
@[local step]
private theorem load_lane.spec (l : sha3.keccak4x_hybrid.Lane4) :
    sha3.keccak4x_hybrid.load_lane l
    ⦃ (r : m256) => m256.u64x4 r = l ⦄ := by
  unfold sha3.keccak4x_hybrid.load_lane
  simp

/-- Spec for `store_lane`: discards the destination and returns the
    `m256.u64x4` view of the source register. -/
@[local step]
private theorem store_lane.spec
    (dummy : sha3.keccak4x_hybrid.Lane4)
    (m : m256) :
    sha3.keccak4x_hybrid.store_lane dummy m
    ⦃ (r : sha3.keccak4x_hybrid.Lane4) => r = m256.u64x4 m ⦄ := by
  unfold sha3.keccak4x_hybrid.store_lane
  simp

/-- **Reusable rol lift.**  The open-coded AVX2 rotation
    `out = store_lane (or_si256 (slli_epi64 N (load_lane c)) (srli_epi64 (64-N) (load_lane c)))`
    equals the whole-`Lane4` `rotl4 c N`.  Stated against the per-lane
    bv-level postconditions that `step*` leaves in scope for the 5 ops
    (after the `slli`/`srli` `if`-guards are reduced via `simp`). -/
theorem rol_lift (Ns Nr : Std.I32) (kn : Nat) (hkn : 0 < kn ∧ kn < 64)
    (hNs : (I32.toNat Ns : Nat) = kn) (hNsb : 0 ≤ Ns.val ∧ Ns.val < 64)
    (hNr : (I32.toNat Nr : Nat) = 64 - kn) (hNrb : 0 ≤ Nr.val ∧ Nr.val < 64)
    (c : sha3.keccak4x_hybrid.Lane4) (v a a1 r : m256) (out : sha3.keccak4x_hybrid.Lane4)
    (kU : U32) (hkU : kU.val = kn)
    (hv : m256.u64x4 v = c)
    (ha : ∀ k, (hk : k < 4) →
      (m256.u64x4 a).val[k] =
        if 0 ≤ Ns.val ∧ Ns.val < 64 then
          (⟨(m256.u64x4 v).val[k].bv.shiftLeft (I32.toNat Ns)⟩ : U64) else 0#u64)
    (ha1 : ∀ k, (hk : k < 4) →
      (m256.u64x4 a1).val[k] =
        if 0 ≤ Nr.val ∧ Nr.val < 64 then
          (⟨(m256.u64x4 v).val[k].bv.ushiftRight (I32.toNat Nr)⟩ : U64) else 0#u64)
    (hr : ∀ k, (hk : k < 4) →
      (m256.u64x4 r).val[k] = (m256.u64x4 a).val[k] ||| (m256.u64x4 a1).val[k])
    (hout : out = m256.u64x4 r) :
    out = Keccak4xHybrid.rotl4 c kU := by
  apply Keccak4xHybrid.lane4_ext; intro k hk
  apply U64.bv_eq_imp_eq
  simp only [Keccak4xHybrid.val_rotl4, List.getElem_map, UScalar.rotate_left, hkU]
  rw [hout, hr k hk, UScalar.bv_or]
  simp only [ha k hk, ha1 k hk, hNsb, hNrb, and_self, if_true, hNs, hNr]
  rw [rol4_correct _ kn hkn]
  simp only [hv]




/-- Project the `i`-th u64 lane from a hybrid 4-way state.  Same shape
    as the safe-variant `Keccak4x.projectLane`; we keep them distinct
    types because `sha3.keccak4x.Lane4` and `sha3.keccak4x_hybrid.Lane4`
    are nominally distinct extracted types even though their underlying
    `Array U64 4` is shared. -/
def Keccak4xHybrid.projectLane (i : Fin 4)
    (s : Array sha3.keccak4x_hybrid.Lane4 25#usize) : Lanes25 :=
  let lane (k : Nat) (hk : k < 25 := by decide) := s[k][i]
  ⟨lane 0,  lane 1,  lane 2,  lane 3,  lane 4,
   lane 5,  lane 6,  lane 7,  lane 8,  lane 9,
   lane 10, lane 11, lane 12, lane 13, lane 14,
   lane 15, lane 16, lane 17, lane 18, lane 19,
   lane 20, lane 21, lane 22, lane 23, lane 24⟩

/-- Whole-state zero projection (hybrid).  Same shape as the safe-variant
    `Keccak4x.projectLane_zero`; consumed by `Shake4x.new_{128,256}.spec`. -/
theorem Keccak4xHybrid.projectLane_zero (i : Fin 4) :
    Keccak4xHybrid.projectLane i (Array.repeat 25#usize (Array.repeat 4#usize 0#u64))
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

/-- Parametric lane-`n` access through `projectLane`.  This is the key
    bridge that enables one parametric `body_fused_bridge` (one statement,
    one premise per lane) instead of 25 per-lane bridge theorems. -/
theorem Keccak4xHybrid.projectLane_lane25 (i : Fin 4)
    (s : Std.Array sha3.keccak4x_hybrid.Lane4 25#usize) (n : Fin 25) :
    (Keccak4xHybrid.projectLane i s).lane25 n
      = (s.val[n.val]'(by scalar_tac)).val[i.val]'(by
          have := (s.val[n.val]'(by scalar_tac)).property
          have := i.isLt; scalar_tac) := by
  unfold projectLane
  fin_cases n <;> rfl

/-- Single-lane projection of a hybrid `Lane4` (the `i`-th `U64`).
    `(projectLane i s).lane25 n = projectLane_lane i s[n]` (see
    `projectLane_lane25`); the homomorphisms below push it through the
    pure `Lane4` bitwise algebra, mirroring safe `Base.lean`. -/
def Keccak4xHybrid.projectLane_lane (i : Fin 4) (l : sha3.keccak4x_hybrid.Lane4) : U64 :=
  l.val[i.val]'(by have := l.property; have := i.isLt; scalar_tac)

theorem Keccak4xHybrid.projectLane_lane_xor (a b : sha3.keccak4x_hybrid.Lane4) (i : Fin 4) :
    Keccak4xHybrid.projectLane_lane i (a ^^^ b)
      = Keccak4xHybrid.projectLane_lane i a ^^^ Keccak4xHybrid.projectLane_lane i b := by
  unfold projectLane_lane
  exact Keccak4xHybrid.getElem_xor a b i.val i.isLt

theorem Keccak4xHybrid.projectLane_lane_and (a b : sha3.keccak4x_hybrid.Lane4) (i : Fin 4) :
    Keccak4xHybrid.projectLane_lane i (a &&& b)
      = Keccak4xHybrid.projectLane_lane i a &&& Keccak4xHybrid.projectLane_lane i b := by
  unfold projectLane_lane
  exact Keccak4xHybrid.getElem_and a b i.val i.isLt

theorem Keccak4xHybrid.projectLane_lane_not (a : sha3.keccak4x_hybrid.Lane4) (i : Fin 4) :
    Keccak4xHybrid.projectLane_lane i (~~~ a)
      = ~~~ Keccak4xHybrid.projectLane_lane i a := by
  unfold projectLane_lane
  exact Keccak4xHybrid.getElem_not a i.val i.isLt

/-- Value-level `rotl4` homomorphism: `projectLane_lane` of a rotated lane is the
    scalar `core.num.U64.rotate_left` of the projected lane. -/
theorem Keccak4xHybrid.projectLane_lane_rotl4_val (a : sha3.keccak4x_hybrid.Lane4) (n : U32) (i : Fin 4) :
    Keccak4xHybrid.projectLane_lane i (Keccak4xHybrid.rotl4 a n)
      = core.num.U64.rotate_left (Keccak4xHybrid.projectLane_lane i a) n := by
  unfold projectLane_lane
  simp only [Keccak4xHybrid.val_rotl4, List.getElem_map]
  rfl

/-- Connect `projectLane`'s field accessor to `projectLane_lane`. -/
theorem Keccak4xHybrid.projectLane_lane25_eq (i : Fin 4)
    (s : Std.Array sha3.keccak4x_hybrid.Lane4 25#usize) (n : Fin 25) :
    (Keccak4xHybrid.projectLane i s).lane25 n
      = Keccak4xHybrid.projectLane_lane i (s[n.val]'(by scalar_tac)) := by
  rw [Keccak4xHybrid.projectLane_lane25]; rfl


/-! ## Fold scaffolding for `Keccak4xHybrid.permute_loop`

  Mirrors the safe-side fold (Permute.lean §"Fold scaffolding"):
  extract the post-iterator `match` as `match_helper`, then the
  `some`-branch body as `body_fused` (the recursive `permute_loop`
  call stays outside).

  **Structural difference from safe.** The hybrid source
  (`src/sha3/keccak4x_hybrid.rs:155-261`) uses an *interleaved
  chi-row schedule* (sched. comment at lines 12-19) instead of the
  safe variant's monolithic θ → θ.apply → ρπ → χ → ι sequence.
  Each chi row's per-row temps + save-ahead temps + chi writes are
  emitted in one block, then the next row's block, etc.  There is
  no clean θ.apply phase — `trp!(src, d, rot)` fuses theta-XOR
  with ρπ rotation lane-by-lane.

  The body_fused multi-clause phase split is therefore differently
  shaped from safe: 1 θ.D phase + 5 chi-row phases + 1 ι phase.
  We extract `body_fused` itself; the per-phase split is not needed here. -/

set_option maxRecDepth 4096 in
-- The extracted loop is `permute_impl_loop` (the AVX2 `#[target_feature]`
-- boundary lives in `permute`, which calls `permute_impl`). The decomposed
-- piece labels below keep the `permute_loop.*` naming; only the `#decompose`
-- target tracks the extracted def.
#decompose sha3.keccak4x_hybrid.Keccak4xHybrid.permute_impl_loop
            Keccak4xHybrid.permute_loop.match_helper_eq
  letRange 1 1 => Keccak4xHybrid.permute_loop.match_helper

set_option maxRecDepth 4096 in
#decompose Keccak4xHybrid.permute_loop.match_helper
            Keccak4xHybrid.permute_loop.match_helper_branch_eq
  branch 1 (letRange 0 345) => Keccak4xHybrid.permute_loop.body_fused

/-! ### Second-level cascade: 7-phase split of hybrid `body_fused`

  The hybrid Rust source (`src/sha3/keccak4x_hybrid.rs:155-261`)
  uses an **interleaved chi-row schedule** (see the source comment
  at lines 12-19): for each chi row `r`, the row's own ρπ temps
  are computed alongside save-ahead temps for later rows, then
  the row's 5 chi writes are emitted in-place.  This keeps peak
  register pressure at 16 YMM registers.

  The natural Rust phase boundaries are therefore:

  | Phase            | Rust lines | Bindings (est.) |
  |------------------|------------|----------------:|
  | θ.D              | 158-169    |              80 |
  | row 0 block      | 180-198    |              72 |
  | row 1 block      | 200-216    |              64 |
  | row 2 block      | 218-232    |              50 |
  | row 3 block      | 234-246    |              36 |
  | row 4 block      | 248-256    |              22 |
  | ι                | 259        |               5 |

  Per row block: row temps (4 trp! or 5 trp! including t0 for
  row 0) + save-aheads (4 for row 0, 3 for row 1, 2 for row 2,
  1 for row 3, 0 for row 4) + 5 chi writes.  Each trp! is 7
  monadic ops (xor + load_lane + slli + srli + or + Array.repeat
  + store_lane); each chi write is 3 ops (andnot + xor + update).

  Phase counts must sum to 345; numbers above are estimates that
  may need fine-tuning on contact with the actual elaborator. -/
set_option maxRecDepth 8192 in
#decompose Keccak4xHybrid.permute_loop.body_fused
            Keccak4xHybrid.permute_loop.body_fused.phases_eq
  letRange 0 80 => Keccak4xHybrid.permute_loop.phase_theta_d
  letRange 1 72 => Keccak4xHybrid.permute_loop.phase_chi_block_0
  letRange 2 64 => Keccak4xHybrid.permute_loop.phase_chi_block_1
  letRange 3 50 => Keccak4xHybrid.permute_loop.phase_chi_block_2
  letRange 4 36 => Keccak4xHybrid.permute_loop.phase_chi_block_3
  letRange 5 22 => Keccak4xHybrid.permute_loop.phase_chi_block_4
  letRange 6 5  => Keccak4xHybrid.permute_loop.phase_iota

/-! ### Per-phase specs (whole-`Lane4`)

  Seven `@[local step] private` phase specs, one per `phase_*` helper
  extracted by the 7-phase `#decompose` above.  **All seven are now
  proven** in whole-`Lane4` form: each post pins the phase's outputs to
  exact `rotl4` (rho/pi) and chi (`^^^`/`&&&`/`~~~`) expressions over the
  inputs.  They follow the safe-`Permute` operator-algebra style
  (`Lane4.lean` hybrid block + the `rol_lift` helper below).

  These specs are the leaves consumed by `body_fused.spec`.  Because each phase returns a tuple consumed by a
  destructuring `let (…) ← phase_*` bind, the composition must apply them
  via explicit `step with phase_*.spec as ⟨…⟩` (plain `step*` does
  nothing across a destructuring bind). -/

/-- Parametric BV identity for the θ d-value computation:
    the U64-level `slli/srli/or` of a 5-XOR sum equals the BV `rotateLeft 1`
    of the same sum. -/
private theorem Keccak4xHybrid.permute_loop.phase_theta_d_pointwise
    (a0 a1 a2 a3 a4 b0 b1 b2 b3 b4 : Aeneas.Std.U64) :
    ((a0 ^^^ a1 ^^^ a2 ^^^ a3 ^^^ a4 ^^^
        ((if (0:Int) ≤ (1:Int) ∧ (1:Int) < 64 then
            (b0 ^^^ b1 ^^^ b2 ^^^ b3 ^^^ b4).bv.shiftLeft (I32.toNat 1#i32)#uscalar
          else 0#u64) |||
          if (0:Int) ≤ (63:Int) ∧ (63:Int) < 64 then
            (b0 ^^^ b1 ^^^ b2 ^^^ b3 ^^^ b4).bv.ushiftRight (I32.toNat 63#i32)#uscalar
          else 0#u64)).bv) =
      a0.bv ^^^ a1.bv ^^^ a2.bv ^^^ a3.bv ^^^ a4.bv ^^^
        (b0.bv ^^^ b1.bv ^^^ b2.bv ^^^ b3.bv ^^^ b4.bv).rotateLeft 1 := by
  simp only [show ((0:Int) ≤ (1:Int) ∧ (1:Int) < 64) = True from by decide,
             show ((0:Int) ≤ (63:Int) ∧ (63:Int) < 64) = True from by decide,
             if_true, UScalar.bv_xor, UScalar.bv_or,
             show (I32.toNat 1#i32 : Nat) = 1 from by decide,
             show (I32.toNat 63#i32 : Nat) = 63 from by decide]
  rw [rol4_correct _ 1 (by decide)]

set_option maxHeartbeats 2000000 in
@[step]
theorem Keccak4xHybrid.permute_loop.phase_theta_d.spec
    (s : Array sha3.keccak4x_hybrid.Lane4 25#usize) :
    Keccak4xHybrid.permute_loop.phase_theta_d s
    ⦃ (o0, o1, o2, o3, o4, o5, o6, o7, o8, o9, o10, o11, o12, o13) =>
        o0 = s[0] ∧
        o1 = s[1] ∧
        o2 = s[6] ∧
        o3 = s[2] ∧
        o4 = s[12] ∧
        o5 = s[3] ∧
        o6 = s[18] ∧
        o7 = s[4] ∧
        o8 = s[24] ∧
        o9 = (s[4] ^^^ s[9] ^^^ s[14] ^^^ s[19] ^^^ s[24]) ^^^ Keccak4xHybrid.rotl4 (s[1] ^^^ s[6] ^^^ s[11] ^^^ s[16] ^^^ s[21]) 1#u32 ∧
        o10 = (s[0] ^^^ s[5] ^^^ s[10] ^^^ s[15] ^^^ s[20]) ^^^ Keccak4xHybrid.rotl4 (s[2] ^^^ s[7] ^^^ s[12] ^^^ s[17] ^^^ s[22]) 1#u32 ∧
        o11 = (s[1] ^^^ s[6] ^^^ s[11] ^^^ s[16] ^^^ s[21]) ^^^ Keccak4xHybrid.rotl4 (s[3] ^^^ s[8] ^^^ s[13] ^^^ s[18] ^^^ s[23]) 1#u32 ∧
        o12 = (s[2] ^^^ s[7] ^^^ s[12] ^^^ s[17] ^^^ s[22]) ^^^ Keccak4xHybrid.rotl4 (s[4] ^^^ s[9] ^^^ s[14] ^^^ s[19] ^^^ s[24]) 1#u32 ∧
        o13 = (s[3] ^^^ s[8] ^^^ s[13] ^^^ s[18] ^^^ s[23]) ^^^ Keccak4xHybrid.rotl4 (s[0] ^^^ s[5] ^^^ s[10] ^^^ s[15] ^^^ s[20]) 1#u32 ⦄ := by
  unfold Keccak4xHybrid.permute_loop.phase_theta_d
  step*
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · exact l_post
  · exact l8_post
  · exact l9_post
  · exact l16_post
  · exact l19_post
  · exact l24_post
  · exact l29_post
  · exact l32_post
  · exact l39_post
  · have hrol : out = Keccak4xHybrid.rotl4 c1 1#u32 :=
      rol_lift 1#i32 63#i32 1 (by decide) (by decide) (by decide) (by decide) (by decide)
        c1 v a a1 r out 1#u32 (by decide) v_post a_post a1_post r_post out_post
    rw [d0_post, hrol]
    simp only [c1_post, c4_post, l8_post, l9_post, l10_post, l11_post, l12_post, l13_post, l14_post, l15_post, l32_post, l33_post, l34_post, l35_post, l36_post, l37_post, l38_post, l39_post]
    rfl
  · have hrol : out1 = Keccak4xHybrid.rotl4 c2 1#u32 :=
      rol_lift 1#i32 63#i32 1 (by decide) (by decide) (by decide) (by decide) (by decide)
        c2 v1 a3 a4 r1 out1 1#u32 (by decide) v1_post a3_post a4_post r1_post out1_post
    rw [d1_post, hrol]
    simp only [c0_post, c2_post, l_post, l1_post, l2_post, l3_post, l4_post, l5_post, l6_post, l7_post, l16_post, l17_post, l18_post, l19_post, l20_post, l21_post, l22_post, l23_post]
    rfl
  · have hrol : out2 = Keccak4xHybrid.rotl4 c3 1#u32 :=
      rol_lift 1#i32 63#i32 1 (by decide) (by decide) (by decide) (by decide) (by decide)
        c3 v2 a6 a7 r2 out2 1#u32 (by decide) v2_post a6_post a7_post r2_post out2_post
    rw [d2_post, hrol]
    simp only [c1_post, c3_post, l8_post, l9_post, l10_post, l11_post, l12_post, l13_post, l14_post, l15_post, l24_post, l25_post, l26_post, l27_post, l28_post, l29_post, l30_post, l31_post]
    rfl
  · have hrol : out3 = Keccak4xHybrid.rotl4 c4 1#u32 :=
      rol_lift 1#i32 63#i32 1 (by decide) (by decide) (by decide) (by decide) (by decide)
        c4 v3 a9 a10 r3 out3 1#u32 (by decide) v3_post a9_post a10_post r3_post out3_post
    rw [d3_post, hrol]
    simp only [c2_post, c4_post, l16_post, l17_post, l18_post, l19_post, l20_post, l21_post, l22_post, l23_post, l32_post, l33_post, l34_post, l35_post, l36_post, l37_post, l38_post, l39_post]
    rfl
  · have hrol : out4 = Keccak4xHybrid.rotl4 c0 1#u32 :=
      rol_lift 1#i32 63#i32 1 (by decide) (by decide) (by decide) (by decide) (by decide)
        c0 v4 a12 a13 r4 out4 1#u32 (by decide) v4_post a12_post a13_post r4_post out4_post
    rw [d4_post, hrol]
    simp only [c0_post, c3_post, l_post, l1_post, l2_post, l3_post, l4_post, l5_post, l6_post, l7_post, l24_post, l25_post, l26_post, l27_post, l28_post, l29_post, l30_post, l31_post]
    rfl


/-! ### Sub-decompose `phase_chi_block_0` into rho/pi + chi

  The 9 rho/pi rotations dominate `phase_chi_block_0` (57 of its 72
  monadic positions): 1 binding for `t0 = l ^ d0` (no rotation) and
  8 trp! invocations for `t1, t2, t3, t4` (row-0 actuals) and
  `t5, t10, t15, t20` (save-aheads for rows 1-4).  The subsequent 15
  bindings are 5 chi writes (`state[0..4]`) consuming `t0..t4`.
  Internal `t0..t4` must be exposed to the chi residual at the U64
  level — splitting at the rho/pi → chi boundary makes them visible
  to the chi step's spec. -/
set_option maxRecDepth 4096 in
#decompose Keccak4xHybrid.permute_loop.phase_chi_block_0
            Keccak4xHybrid.permute_loop.phase_chi_block_0.split_eq
  letRange 0 57 => Keccak4xHybrid.permute_loop.phase_chi_block_0_rho_pi

set_option maxHeartbeats 2000000 in
@[local step]
private theorem Keccak4xHybrid.permute_loop.phase_chi_block_0_rho_pi.spec
    (l l8 l9 l16 l19 l24 l29 l32 l39 d0 d1 d2 d3 d4 : sha3.keccak4x_hybrid.Lane4) :
    Keccak4xHybrid.permute_loop.phase_chi_block_0_rho_pi
      l l8 l9 l16 l19 l24 l29 l32 l39 d0 d1 d2 d3 d4
    ⦃ o0 o1 o2 o3 o4 o5 o6 o7 o8 =>
        o0 = l ^^^ d0 ∧
        o1 = Keccak4xHybrid.rotl4 (l9 ^^^ d1) 44#u32 ∧
        o2 = Keccak4xHybrid.rotl4 (l19 ^^^ d2) 43#u32 ∧
        o3 = Keccak4xHybrid.rotl4 (l29 ^^^ d3) 21#u32 ∧
        o4 = Keccak4xHybrid.rotl4 (l39 ^^^ d4) 14#u32 ∧
        o5 = Keccak4xHybrid.rotl4 (l24 ^^^ d3) 28#u32 ∧
        o6 = Keccak4xHybrid.rotl4 (l8 ^^^ d1) 1#u32 ∧
        o7 = Keccak4xHybrid.rotl4 (l32 ^^^ d4) 27#u32 ∧
        o8 = Keccak4xHybrid.rotl4 (l16 ^^^ d2) 62#u32 ⦄ := by
  unfold Keccak4xHybrid.permute_loop.phase_chi_block_0_rho_pi
  step*
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · exact t0_post
  · have hrol : t1 = Keccak4xHybrid.rotl4 lane 44#u32 :=
      rol_lift 44#i32 20#i32 44 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane v5 a15 a16 r5 t1 44#u32 (by decide) v5_post a15_post a16_post r5_post t1_post
    rw [hrol, lane_post]
  · have hrol : t2 = Keccak4xHybrid.rotl4 lane1 43#u32 :=
      rol_lift 43#i32 21#i32 43 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane1 v6 a18 a19 r6 t2 43#u32 (by decide) v6_post a18_post a19_post r6_post t2_post
    rw [hrol, lane1_post]
  · have hrol : t3 = Keccak4xHybrid.rotl4 lane2 21#u32 :=
      rol_lift 21#i32 43#i32 21 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane2 v7 a21 a22 r7 t3 21#u32 (by decide) v7_post a21_post a22_post r7_post t3_post
    rw [hrol, lane2_post]
  · have hrol : t4 = Keccak4xHybrid.rotl4 lane3 14#u32 :=
      rol_lift 14#i32 50#i32 14 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane3 v8 a24 a25 r8 t4 14#u32 (by decide) v8_post a24_post a25_post r8_post t4_post
    rw [hrol, lane3_post]
  · have hrol : t5 = Keccak4xHybrid.rotl4 lane4 28#u32 :=
      rol_lift 28#i32 36#i32 28 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane4 v9 a27 a28 r9 t5 28#u32 (by decide) v9_post a27_post a28_post r9_post t5_post
    rw [hrol, lane4_post]
  · have hrol : t10 = Keccak4xHybrid.rotl4 lane5 1#u32 :=
      rol_lift 1#i32 63#i32 1 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane5 v10 a30 a31 r10 t10 1#u32 (by decide) v10_post a30_post a31_post r10_post t10_post
    rw [hrol, lane5_post]
  · have hrol : t15 = Keccak4xHybrid.rotl4 lane6 27#u32 :=
      rol_lift 27#i32 37#i32 27 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane6 v11 a33 a34 r11 t15 27#u32 (by decide) v11_post a33_post a34_post r11_post t15_post
    rw [hrol, lane6_post]
  · have hrol : t20 = Keccak4xHybrid.rotl4 lane7 62#u32 :=
      rol_lift 62#i32 2#i32 62 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane7 v12 a36 a37 r12 t20 62#u32 (by decide) v12_post a36_post a37_post r12_post t20_post
    rw [hrol, lane7_post]
set_option maxHeartbeats 2000000 in
@[step]
theorem Keccak4xHybrid.permute_loop.phase_chi_block_0.spec
    (s : Array sha3.keccak4x_hybrid.Lane4 25#usize)
    (l l8 l9 l16 l19 l24 l29 l32 l39 d0 d1 d2 d3 d4 : sha3.keccak4x_hybrid.Lane4) :
    Keccak4xHybrid.permute_loop.phase_chi_block_0 s l l8 l9 l16 l19 l24 l29 l32 l39 d0 d1 d2 d3 d4
    ⦃ (o0, o1, o2, o3, sarr) =>
        o0 = Keccak4xHybrid.rotl4 (l24 ^^^ d3) 28#u32 ∧
        o1 = Keccak4xHybrid.rotl4 (l8 ^^^ d1) 1#u32 ∧
        o2 = Keccak4xHybrid.rotl4 (l32 ^^^ d4) 27#u32 ∧
        o3 = Keccak4xHybrid.rotl4 (l16 ^^^ d2) 62#u32 ∧
        (∀ j, (hj : j < 25) → j ≠ 0 → j ≠ 1 → j ≠ 2 → j ≠ 3 → j ≠ 4 → sarr[j] = s[j]) ∧
        sarr[0] = (l ^^^ d0) ^^^ ((~~~ Keccak4xHybrid.rotl4 (l9 ^^^ d1) 44#u32) &&& Keccak4xHybrid.rotl4 (l19 ^^^ d2) 43#u32) ∧
        sarr[1] = Keccak4xHybrid.rotl4 (l9 ^^^ d1) 44#u32 ^^^ ((~~~ Keccak4xHybrid.rotl4 (l19 ^^^ d2) 43#u32) &&& Keccak4xHybrid.rotl4 (l29 ^^^ d3) 21#u32) ∧
        sarr[2] = Keccak4xHybrid.rotl4 (l19 ^^^ d2) 43#u32 ^^^ ((~~~ Keccak4xHybrid.rotl4 (l29 ^^^ d3) 21#u32) &&& Keccak4xHybrid.rotl4 (l39 ^^^ d4) 14#u32) ∧
        sarr[3] = Keccak4xHybrid.rotl4 (l29 ^^^ d3) 21#u32 ^^^ ((~~~ Keccak4xHybrid.rotl4 (l39 ^^^ d4) 14#u32) &&& (l ^^^ d0)) ∧
        sarr[4] = Keccak4xHybrid.rotl4 (l39 ^^^ d4) 14#u32 ^^^ ((~~~ (l ^^^ d0)) &&& Keccak4xHybrid.rotl4 (l9 ^^^ d1) 44#u32) ⦄ := by
  rw [Keccak4xHybrid.permute_loop.phase_chi_block_0.split_eq]
  step with Keccak4xHybrid.permute_loop.phase_chi_block_0_rho_pi.spec
    as ⟨t0, t1, t2, t3, t4, t5, t10, t15, t20,
        h0, h1, h2, h3, h4, h5, h6, h7, h8⟩
  step*
  refine ⟨h5, h6, h7, h8, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro j hj hj0 hj1 hj2 hj3 hj4
    simp_lists [s5_post, s4_post, s3_post, s2_post, s1_post]
  · simp_lists [s5_post, s4_post, s3_post, s2_post, s1_post, l41_post, l40_post]
    rw [h0, h1, h2]
  · simp_lists [s5_post, s4_post, s3_post, s2_post, s1_post, l43_post, l42_post]
    rw [h1, h2, h3]
  · simp_lists [s5_post, s4_post, s3_post, s2_post, s1_post, l45_post, l44_post]
    rw [h2, h3, h4]
  · simp_lists [s5_post, s4_post, s3_post, s2_post, s1_post, l47_post, l46_post]
    rw [h3, h4, h0]
  · simp_lists [s5_post, s4_post, s3_post, s2_post, s1_post, l49_post, l48_post]
    rw [h4, h0, h1]
/-! ### Sub-decompose `phase_chi_block_1` into rho/pi + chi

  The 7 rho/pi rotations dominate `phase_chi_block_1` (49 of its 64
  monadic positions) and produce 7 intermediate Lane4 values
  (`t6, t7, t8, t9, t11, t16, t21`). The subsequent 15 bindings do
  3 chi computations consuming `t5, t6, t7, t8, t9`.  In particular
  `t7` is **internal** to `phase_chi_block_1` — splitting at the
  natural rho/pi → chi boundary makes `t7` available to the chi
  step's spec at the U64 level (instead of forcing the post to embed
  the rolled BV form via `rol4_correct`).  This also halves the
  `step*` + `simp_lists` cost of each part. -/
set_option maxRecDepth 4096 in
#decompose Keccak4xHybrid.permute_loop.phase_chi_block_1
            Keccak4xHybrid.permute_loop.phase_chi_block_1.split_eq
  letRange 0 49 => Keccak4xHybrid.permute_loop.phase_chi_block_1_rho_pi

set_option maxHeartbeats 1600000 in
@[local step]
private theorem Keccak4xHybrid.permute_loop.phase_chi_block_1_rho_pi.spec
    (d0 d1 d2 d4 : sha3.keccak4x_hybrid.Lane4)
    (s5 : Array sha3.keccak4x_hybrid.Lane4 25#usize) :
    Keccak4xHybrid.permute_loop.phase_chi_block_1_rho_pi d0 d1 d2 d4 s5
    ⦃ o0 o1 o2 o3 o4 o5 o6 =>
        o0 = Keccak4xHybrid.rotl4 (s5[9] ^^^ d4) 20#u32 ∧
        o1 = Keccak4xHybrid.rotl4 (s5[10] ^^^ d0) 3#u32 ∧
        o2 = Keccak4xHybrid.rotl4 (s5[16] ^^^ d1) 45#u32 ∧
        o3 = Keccak4xHybrid.rotl4 (s5[22] ^^^ d2) 61#u32 ∧
        o4 = Keccak4xHybrid.rotl4 (s5[7] ^^^ d2) 6#u32 ∧
        o5 = Keccak4xHybrid.rotl4 (s5[5] ^^^ d0) 36#u32 ∧
        o6 = s5[8] ⦄ := by
  unfold Keccak4xHybrid.permute_loop.phase_chi_block_1_rho_pi
  step*
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · have hrol : t6 = Keccak4xHybrid.rotl4 lane8 20#u32 :=
      rol_lift 20#i32 44#i32 20 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane8 v13 a39 a40 r13 t6 20#u32 (by decide) v13_post a39_post a40_post r13_post t6_post
    rw [hrol, lane8_post, l50_post]
    rfl
  · have hrol : t7 = Keccak4xHybrid.rotl4 lane9 3#u32 :=
      rol_lift 3#i32 61#i32 3 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane9 v14 a42 a43 r14 t7 3#u32 (by decide) v14_post a42_post a43_post r14_post t7_post
    rw [hrol, lane9_post, l51_post]
    rfl
  · have hrol : t8 = Keccak4xHybrid.rotl4 lane10 45#u32 :=
      rol_lift 45#i32 19#i32 45 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane10 v15 a45 a46 r15 t8 45#u32 (by decide) v15_post a45_post a46_post r15_post t8_post
    rw [hrol, lane10_post, l52_post]
    rfl
  · have hrol : t9 = Keccak4xHybrid.rotl4 lane11 61#u32 :=
      rol_lift 61#i32 3#i32 61 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane11 v16 a48 a49 r16 t9 61#u32 (by decide) v16_post a48_post a49_post r16_post t9_post
    rw [hrol, lane11_post, l53_post]
    rfl
  · have hrol : t11 = Keccak4xHybrid.rotl4 lane12 6#u32 :=
      rol_lift 6#i32 58#i32 6 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane12 v17 a51 a52 r17 t11 6#u32 (by decide) v17_post a51_post a52_post r17_post t11_post
    rw [hrol, lane12_post, l54_post]
    rfl
  · have hrol : t16 = Keccak4xHybrid.rotl4 lane13 36#u32 :=
      rol_lift 36#i32 28#i32 36 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane13 v18 a54 a55 r18 t16 36#u32 (by decide) v18_post a54_post a55_post r18_post t16_post
    rw [hrol, lane13_post, l55_post]
    rfl
  · rw [l56_post]; rfl
set_option maxHeartbeats 1600000 in
@[step]
theorem Keccak4xHybrid.permute_loop.phase_chi_block_1.spec
    (d0 d1 d2 d3 d4 t5 : sha3.keccak4x_hybrid.Lane4)
    (s5 : Array sha3.keccak4x_hybrid.Lane4 25#usize) :
    Keccak4xHybrid.permute_loop.phase_chi_block_1 d0 d1 d2 d3 d4 t5 s5
    ⦃ o0 o1 o2 o3 o4 o5 sarr o7 =>
        o0 = Keccak4xHybrid.rotl4 (s5[9] ^^^ d4) 20#u32 ∧
        o1 = Keccak4xHybrid.rotl4 (s5[16] ^^^ d1) 45#u32 ∧
        o2 = Keccak4xHybrid.rotl4 (s5[22] ^^^ d2) 61#u32 ∧
        o3 = Keccak4xHybrid.rotl4 (s5[7] ^^^ d2) 6#u32 ∧
        o4 = Keccak4xHybrid.rotl4 (s5[5] ^^^ d0) 36#u32 ∧
        o5 = Keccak4xHybrid.rotl4 (s5[8] ^^^ d3) 55#u32 ∧
        (∀ j, (hj : j < 25) → j ≠ 5 → j ≠ 6 → sarr[j] = s5[j]) ∧
        sarr[5] = t5 ^^^ ((~~~ Keccak4xHybrid.rotl4 (s5[9] ^^^ d4) 20#u32) &&& Keccak4xHybrid.rotl4 (s5[10] ^^^ d0) 3#u32) ∧
        sarr[6] = Keccak4xHybrid.rotl4 (s5[9] ^^^ d4) 20#u32 ^^^ ((~~~ Keccak4xHybrid.rotl4 (s5[10] ^^^ d0) 3#u32) &&& Keccak4xHybrid.rotl4 (s5[16] ^^^ d1) 45#u32) ∧
        o7 = Keccak4xHybrid.rotl4 (s5[10] ^^^ d0) 3#u32 ^^^ ((~~~ Keccak4xHybrid.rotl4 (s5[16] ^^^ d1) 45#u32) &&& Keccak4xHybrid.rotl4 (s5[22] ^^^ d2) 61#u32) ⦄ := by
  rw [Keccak4xHybrid.permute_loop.phase_chi_block_1.split_eq]
  step with Keccak4xHybrid.permute_loop.phase_chi_block_1_rho_pi.spec
    as ⟨t6, t7, t8, t9, t11, t16, p8, h6, h7, h8, h9, h11, h16, hp8⟩
  step*
  refine ⟨h6, h8, h9, h11, h16, ?_, ?_, ?_, ?_, ?_⟩
  · have hrol : t21 = Keccak4xHybrid.rotl4 lane14 55#u32 :=
      rol_lift 55#i32 9#i32 55 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane14 v19 a57 a58 r19 t21 55#u32 (by decide) v19_post a57_post a58_post r19_post t21_post
    rw [hrol, lane14_post, hp8]
  · intro j hj hj5 hj6
    simp_lists [s7_post, s6_post]
  · simp_lists [s7_post, s6_post, l58_post, l57_post]
    rw [h6, h7]
    rfl
  · simp_lists [s7_post, s6_post, l60_post, l59_post]
    rw [h6, h7, h8]
    rfl
  · rw [l62_post, l61_post, h7, h8, h9]
set_option maxHeartbeats 1600000 in
@[step]
theorem Keccak4xHybrid.permute_loop.phase_chi_block_2.spec
    (d0 d1 d3 d4 t5 t10 t6 t8 t9 t11 : sha3.keccak4x_hybrid.Lane4)
    (s7 : Array sha3.keccak4x_hybrid.Lane4 25#usize)
    (l62 : sha3.keccak4x_hybrid.Lane4) :
    Keccak4xHybrid.permute_loop.phase_chi_block_2 d0 d1 d3 d4 t5 t10 t6 t8 t9 t11 s7 l62
    ⦃ o0 o1 o2 o3 o4 sarr =>
        o0 = Keccak4xHybrid.rotl4 (s7[13] ^^^ d3) 25#u32 ∧
        o1 = Keccak4xHybrid.rotl4 (s7[19] ^^^ d4) 8#u32 ∧
        o2 = Keccak4xHybrid.rotl4 (s7[20] ^^^ d0) 18#u32 ∧
        o3 = Keccak4xHybrid.rotl4 (s7[11] ^^^ d1) 10#u32 ∧
        o4 = Keccak4xHybrid.rotl4 (s7[14] ^^^ d4) 39#u32 ∧
        (∀ j, (hj : j < 25) → j ≠ 7 → j ≠ 8 → j ≠ 9 → j ≠ 10 → sarr[j] = s7[j]) ∧
        sarr[7] = l62 ∧
        sarr[8] = t8 ^^^ ((~~~ t9) &&& t5) ∧
        sarr[9] = t9 ^^^ ((~~~ t5) &&& t6) ∧
        sarr[10] = t10 ^^^ ((~~~ t11) &&& o0) ⦄ := by
  unfold Keccak4xHybrid.permute_loop.phase_chi_block_2
  step*
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · have hrol : t12 = Keccak4xHybrid.rotl4 lane15 25#u32 :=
      rol_lift 25#i32 39#i32 25 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane15 v20 a60 a61 r20 t12 25#u32 (by decide) v20_post a60_post a61_post r20_post t12_post
    rw [hrol, lane15_post, l67_post]
    simp_lists [s10_post, s9_post, s8_post]
  · have hrol : t13 = Keccak4xHybrid.rotl4 lane16 8#u32 :=
      rol_lift 8#i32 56#i32 8 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane16 v21 a63 a64 r21 t13 8#u32 (by decide) v21_post a63_post a64_post r21_post t13_post
    rw [hrol, lane16_post, l68_post]
    simp_lists [s10_post, s9_post, s8_post]
  · have hrol : t14 = Keccak4xHybrid.rotl4 lane17 18#u32 :=
      rol_lift 18#i32 46#i32 18 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane17 v22 a66 a67 r22 t14 18#u32 (by decide) v22_post a66_post a67_post r22_post t14_post
    rw [hrol, lane17_post, l69_post]
    simp_lists [s10_post, s9_post, s8_post]
  · have hrol : t17 = Keccak4xHybrid.rotl4 lane18 10#u32 :=
      rol_lift 10#i32 54#i32 10 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane18 v23 a69 a70 r23 t17 10#u32 (by decide) v23_post a69_post a70_post r23_post t17_post
    rw [hrol, lane18_post, l70_post]
    simp_lists [s10_post, s9_post, s8_post]
  · have hrol : t22 = Keccak4xHybrid.rotl4 lane19 39#u32 :=
      rol_lift 39#i32 25#i32 39 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane19 v24 a72 a73 r24 t22 39#u32 (by decide) v24_post a72_post a73_post r24_post t22_post
    rw [hrol, lane19_post, l71_post]
    simp_lists [s10_post, s9_post, s8_post]
  · intro j hj hj7 hj8 hj9 hj10
    simp_lists [s11_post, s10_post, s9_post, s8_post]
  · simp_lists [s11_post, s10_post, s9_post, s8_post]
  · simp_lists [s11_post, s10_post, s9_post, l64_post, l63_post]
  · simp_lists [s11_post, s10_post, l66_post, l65_post]
  · simp_lists [s11_post, l73_post, l72_post]
set_option maxHeartbeats 800000 in
@[step]
theorem Keccak4xHybrid.permute_loop.phase_chi_block_3.spec
    (d0 d2 d3 t10 t11 t12 t13 t14 : sha3.keccak4x_hybrid.Lane4)
    (s11 : Array sha3.keccak4x_hybrid.Lane4 25#usize) :
    Keccak4xHybrid.permute_loop.phase_chi_block_3 d0 d2 d3 t10 t11 t12 t13 t14 s11
    ⦃ sarr o1 o2 o3 =>
        (∀ j, (hj : j < 25) → j ≠ 11 → j ≠ 12 → j ≠ 13 → j ≠ 14 → sarr[j] = s11[j]) ∧
        sarr[11] = t11 ^^^ ((~~~ t12) &&& t13) ∧
        sarr[12] = t12 ^^^ ((~~~ t13) &&& t14) ∧
        sarr[13] = t13 ^^^ ((~~~ t14) &&& t10) ∧
        sarr[14] = t14 ^^^ ((~~~ t10) &&& t11) ∧
        o1 = Keccak4xHybrid.rotl4 (s11[17] ^^^ d2) 15#u32 ∧
        o2 = Keccak4xHybrid.rotl4 (s11[23] ^^^ d3) 56#u32 ∧
        o3 = Keccak4xHybrid.rotl4 (s11[15] ^^^ d0) 41#u32 ⦄ := by
  unfold Keccak4xHybrid.permute_loop.phase_chi_block_3
  step*
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro j hj hj11 hj12 hj13 hj14
    simp_lists [s15_post, s14_post, s13_post, s12_post]
  · simp_lists [s15_post, s14_post, s13_post, s12_post, l75_post, l74_post]
  · simp_lists [s15_post, s14_post, s13_post, l77_post, l76_post]
  · simp_lists [s15_post, s14_post, l79_post, l78_post]
  · simp_lists [s15_post, l81_post, l80_post]
  · have hrol : t18 = Keccak4xHybrid.rotl4 lane20 15#u32 :=
      rol_lift 15#i32 49#i32 15 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane20 v25 a75 a76 r25 t18 15#u32 (by decide) v25_post a75_post a76_post r25_post t18_post
    rw [hrol, lane20_post, l82_post]
    simp_lists [s15_post, s14_post, s13_post, s12_post]
  · have hrol : t19 = Keccak4xHybrid.rotl4 lane21 56#u32 :=
      rol_lift 56#i32 8#i32 56 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane21 v26 a78 a79 r26 t19 56#u32 (by decide) v26_post a78_post a79_post r26_post t19_post
    rw [hrol, lane21_post, l83_post]
    simp_lists [s15_post, s14_post, s13_post, s12_post]
  · have hrol : t23 = Keccak4xHybrid.rotl4 lane22 41#u32 :=
      rol_lift 41#i32 23#i32 41 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane22 v27 a81 a82 r27 t23 41#u32 (by decide) v27_post a81_post a82_post r27_post t23_post
    rw [hrol, lane22_post, l84_post]
    simp_lists [s15_post, s14_post, s13_post, s12_post]
@[step]
theorem Keccak4xHybrid.permute_loop.phase_chi_block_4.spec
    (d1 t15 t16 t17 : sha3.keccak4x_hybrid.Lane4)
    (s15 : Array sha3.keccak4x_hybrid.Lane4 25#usize)
    (t18 t19 : sha3.keccak4x_hybrid.Lane4) :
    Keccak4xHybrid.permute_loop.phase_chi_block_4 d1 t15 t16 t17 s15 t18 t19
    ⦃ sarr (om : m256) o22 =>
        (∀ j, (hj : j < 25) → j ≠ 15 → j ≠ 16 → j ≠ 17 → j ≠ 18 → j ≠ 19 → sarr[j] = s15[j]) ∧
        sarr[15] = t15 ^^^ ((~~~ t16) &&& t17) ∧
        sarr[16] = t16 ^^^ ((~~~ t17) &&& t18) ∧
        sarr[17] = t17 ^^^ ((~~~ t18) &&& t19) ∧
        sarr[18] = t18 ^^^ ((~~~ t19) &&& t15) ∧
        sarr[19] = t19 ^^^ ((~~~ t15) &&& t16) ∧
        m256.u64x4 om = Keccak4xHybrid.rotl4 (s15[21] ^^^ d1) 2#u32 ⦄ := by
  unfold Keccak4xHybrid.permute_loop.phase_chi_block_4
  step*
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro j hj hj15 hj16 hj17 hj18 hj19
    simp_lists [s20_post, s19_post, s18_post, s17_post, s16_post]
  · simp_lists [s20_post, s19_post, s18_post, s17_post, s16_post, l86_post, l85_post]
  · simp_lists [s20_post, s19_post, s18_post, s17_post, l88_post, l87_post]
  · simp_lists [s20_post, s19_post, s18_post, l90_post, l89_post]
  · simp_lists [s20_post, s19_post, l92_post, l91_post]
  · simp_lists [s20_post, l94_post, l93_post]
  · have hrol : m256.u64x4 r28 = Keccak4xHybrid.rotl4 lane23 2#u32 :=
      rol_lift 2#i32 62#i32 2 (by decide) (by decide) (by decide) (by decide) (by decide)
        lane23 v28 a84 a85 r28 (m256.u64x4 r28) 2#u32 (by decide) v28_post a84_post a85_post r28_post rfl
    rw [hrol, lane23_post, l95_post]
    simp_lists [s20_post, s19_post, s18_post, s17_post, s16_post]
@[step]
theorem Keccak4xHybrid.permute_loop.phase_iota.spec
    (t20 t21 t22 t23 : sha3.keccak4x_hybrid.Lane4)
    (s20 : Array sha3.keccak4x_hybrid.Lane4 25#usize)
    (r28 : m256)
    (a28 : Array (UScalar UScalarTy.U64) 4#usize) :
    Keccak4xHybrid.permute_loop.phase_iota t20 t21 t22 t23 s20 r28 a28
    ⦃ o0 sarr o2 =>
        o0 = m256.u64x4 r28 ∧
        o2 = (~~~ t22) &&& t23 ∧
        (∀ j, (hj : j < 25) → j ≠ 20 → sarr[j] = s20[j]) ∧
        sarr[20] = t20 ^^^ ((~~~ t21) &&& t22) ⦄ := by
  unfold Keccak4xHybrid.permute_loop.phase_iota
  step*
  refine ⟨t24_post, l98_post, ?_, ?_⟩
  · intro j hj hj20
    simp_lists [s21_post]
  · simp_lists [s21_post, l97_post, l96_post]
end symcrust
