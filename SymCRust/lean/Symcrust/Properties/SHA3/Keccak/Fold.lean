import Symcrust.Properties.SHA3.Keccak.Core

/-!
# Keccak-f[1600] Fold — `#decompose`-Generated Helpers

The Aeneas-translated body of `keccak_permute_opt_loop` inlines 156 monadic
let-bindings (the entire θ + ρ + π + χ + ι chain). We use `#decompose` to
factor the body into named pieces so the loop proof can step through them
without re-elaborating the chain:

- `match_helper` — the post-iterator-step `match` on the Range.next result.
- `body_fused` — the inlined θ+ρ+π+χ+ι chain as a pure 25-input → 25-output
  computation (the `some` branch of `match_helper`).
- `body_fused.spec` — `@[step]` spec pinning outputs to `fusedRoundCore`.
- `unfold_via_match_helper` — bridge between `partial_fixpoint`'s auto-
  generated `eq_def` and the `match_helper` form.

See also: the `decompose-command` skill in `aeneas-skills`.
-/

namespace symcrust

open Aeneas Aeneas.Std Result
open sha3.sha3_impl
open sha3.keccak_opt

/- Fast default for `a.val[i]` bound goals: discharge with `scalar_tac`.
   Lets us drop the deprecated `]!` and the explicit `'(by …)` proofs. -/
local macro_rules | `(tactic| get_elem_tactic) => `(tactic| scalar_tac)

/-! ## Step 1: extract `match_helper`

    `#decompose` now drives `partial_fixpoint` definitions directly — no
    need to navigate manually through `Lean.Order.fix`. We just point
    `letRange 1 1` at the second binding of the loop body (the `match`
    on the iterator-step result, after the iterator-step bind itself). -/

set_option maxRecDepth 1024 in
#decompose keccak_permute_opt_loop keccak_permute_opt_loop.match_helper_eq
  letRange 1 1 => keccak_permute_opt_loop.match_helper

/-! ## Step 2: extract the 156-binding `some` branch as `body_fused`

    The terminal recursive call `f iter1 s02 …` stays inline so the helper
    has shape `do <156 lifts>; pure (s110, …, s02)` (no recursion). -/

set_option maxRecDepth 2048 in
#decompose keccak_permute_opt_loop.match_helper keccak_permute_opt_loop.match_helper_branch_eq
  branch 1 (letRange 0 156) => keccak_permute_opt_loop.body_fused

/-- Helper: indexing a fixed-size array at a known-bounds index reduces to
    `ok (… [i.val]!)`. Used twice below (body_fused.spec for `KECCAK_IOTA_K`,
    and the wrapper prefix for the input state). -/
private theorem Array_index_usize_ok [Inhabited α] {n : Usize}
    (v : Array α n) (i : Usize) (hi : i.val < n.val) :
    v.index_usize i = ok (v.val[i.val]) := by
  unfold Array.index_usize
  have hlen : i.val < v.val.length := by have := v.property; scalar_tac
  change (match v.val[i.val]? with | none => _ | some x => ok x) = _
  rw [List.getElem?_eq_getElem hlen]

set_option maxRecDepth 2048 in
/-- `body_fused` reduces to a single `ok`-of-tuple whose components are the
    lanes of `fusedRoundCore ⟨inputs⟩ (KECCAK_IOTA_K[round]!)` (in the
    Aeneas-emitted post-iota order `(s110, s25, …, s241, s02)`). -/
private theorem keccak_permute_opt_loop.body_fused_eq
    (s0 s1 s2 s3 s4 s5 s6 s7 s8 s9
     s10 s11 s12 s13 s14 s15 s16 s17 s18 s19
     s20 s21 s22 s23 s24 : U64)
    (round : Usize) (hround : round.val < 24) :
    keccak_permute_opt_loop.body_fused
      s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19
      s20 s21 s22 s23 s24 round =
    let r := fusedRoundCore
              ⟨s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,
               s10,s11,s12,s13,s14,s15,s16,s17,s18,s19,
               s20,s21,s22,s23,s24⟩
              (KECCAK_IOTA_K.val[round.val])
    ok (r.l1, r.l2, r.l3, r.l4, r.l5, r.l6, r.l7, r.l8, r.l9,
        r.l10, r.l11, r.l12, r.l13, r.l14, r.l15, r.l16, r.l17, r.l18, r.l19,
        r.l20, r.l21, r.l22, r.l23, r.l24, r.l0) := by
  unfold keccak_permute_opt_loop.body_fused
  rw [Array_index_usize_ok KECCAK_IOTA_K round hround]
  rfl

/-! ## `@[step]` spec for `body_fused`

    Single struct equation: outputs (in post-iota order `(s02, s110, s25, …,
    s241)`) form `fusedRoundCore ⟨inputs⟩ (KECCAK_IOTA_K[round]!)` as a
    `Lanes25`. The struct shape lets the loop proof discharge the round-step
    invariant with a single `congrArg₂ fusedRoundCore hinv rfl`, instead of
    25 lane-by-lane substitutions. -/

@[step]
theorem keccak_permute_opt_loop.body_fused.spec
    (s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19
     s20 s21 s22 s23 s24 : U64)
    (round : Usize) (hround : round.val < 24) :
    keccak_permute_opt_loop.body_fused
      s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19
      s20 s21 s22 s23 s24 round
    ⦃ s110 s25 s31 s41 s51 s61 s71 s81 s91 s101 s111 s121 s131 s141 s151 s161
      s171 s181 s191 s201 s211 s221 s231 s241 s02 =>
      (⟨s02, s110, s25, s31, s41, s51, s61, s71, s81, s91, s101, s111, s121,
        s131, s141, s151, s161, s171, s181, s191, s201, s211, s221, s231, s241⟩
       : Lanes25) =
      fusedRoundCore
        ⟨s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12,s13,s14,s15,s16,s17,s18,s19,
         s20,s21,s22,s23,s24⟩
        (KECCAK_IOTA_K.val[round.val]) ⦄ := by
  rw [keccak_permute_opt_loop.body_fused_eq _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _
        _ _ _ _ _ _ _ _ _ hround]
  simp only [WP.spec_ok, WP.uncurry'_pair]

/-! ## Bridge: `keccak_permute_opt_loop` = iterator-step + `match_helper`

    With the new `#decompose`, `match_helper_eq` already states the
    iterator-step + match_helper unfold directly — no manual bridge proof
    needed. We keep `unfold_via_match_helper` as a backwards-compat
    alias for downstream proofs that already use that name. -/
theorem keccak_permute_opt_loop.unfold_via_match_helper
    (iter : core.ops.range.Range Usize)
    (s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19
     s20 s21 s22 s23 s24 : U64) :
    keccak_permute_opt_loop iter s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 s12 s13
        s14 s15 s16 s17 s18 s19 s20 s21 s22 s23 s24 =
    (do
      let (o, iter1) ← core.iter.range.IteratorRange.next core.iter.range.StepUsize iter
      keccak_permute_opt_loop.match_helper
        s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19
        s20 s21 s22 s23 s24 o iter1) :=
  keccak_permute_opt_loop.match_helper_eq iter
    s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19
    s20 s21 s22 s23 s24

/-! ## Wrapper decomposition: `keccak_permute_opt`

The wrapper has 25 monadic `Array.index_usize` reads, then the loop call,
then a single `ok (Array.make 25#usize [...])`. Factor those three pieces. -/

#decompose keccak_permute_opt keccak_permute_opt_decomp_eq
  letRange 0 25 => keccak_permute_opt_prefix

/-- The 25-read prefix returns the array entries as a tuple. -/
theorem keccak_permute_opt_prefix_eq (state : Keccak1600) :
    keccak_permute_opt_prefix state =
      ok (state.val[0], state.val[1], state.val[2], state.val[3],
          state.val[4], state.val[5], state.val[6], state.val[7],
          state.val[8], state.val[9], state.val[10], state.val[11],
          state.val[12], state.val[13], state.val[14], state.val[15],
          state.val[16], state.val[17], state.val[18], state.val[19],
          state.val[20], state.val[21], state.val[22], state.val[23],
          state.val[24]) := by
  unfold keccak_permute_opt_prefix
  repeat rw [Array_index_usize_ok state _ (by scalar_tac)]
  rfl

end symcrust
