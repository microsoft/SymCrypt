import Symcrust.Properties.SHA3.Keccak.Core
import Symcrust.Properties.SHA3.Keccak.Fold

/-!
# Keccak-f[1600] Loop — Iterator Handling and Permutation Specs

Proves the Aeneas-generated loop and wrapper functions correct:

- `IteratorRange_next_some/none`: iterator step specs (curried postcondition)
- `keccak_permute_opt_loop.spec`: 24-round loop = `iterateRndCore`
- `keccak_permute_opt.spec`: wrapper with Array↔Lanes25 packaging
-/

namespace symcrust

open Aeneas Aeneas.Std Result
open Spec
open Spec.SHA3 (w)
open sha3.sha3_impl
open scoped Spec.SHA3
open scoped Spec.Notations

/-! ## Iterator range specs -/

@[step]
theorem IteratorRange_next_some
    (range : core.ops.range.Range Usize)
    (h : range.start.val < range.«end».val) :
    core.iter.range.IteratorRange.next core.iter.range.StepUsize range
    ⦃ (o : Option Usize) (iter1 : core.ops.range.Range Usize) =>
      o = some range.start ∧
      iter1.start.val = range.start.val + 1 ∧
      iter1.«end» = range.«end» ⦄ := by
  exact core.iter.range.IteratorRange.next_Usize_some_spec range h

@[step]
theorem IteratorRange_next_none
    (range : core.ops.range.Range Usize)
    (h : range.start.val ≥ range.«end».val) :
    core.iter.range.IteratorRange.next core.iter.range.StepUsize range
    ⦃ (o : Option Usize) (iter1 : core.ops.range.Range Usize) =>
      o = none ∧ iter1 = range ⦄ := by
  simp only [core.iter.range.IteratorRange.next,
    core.iter.range.UScalarStep, core.iter.range.UScalarStep.forward_checked,
    core.cmp.impls.PartialOrdUsize.lt, liftFun2,
    show ¬ (range.start.val < range.«end».val) from by omega]
  simp [WP.spec_ok]

/-! ## Loop and permutation specs -/

namespace sha3.keccak_opt

open symcrust (iterateRndCore fusedRoundCore)

set_option maxHeartbeats 1000000 in
set_option maxRecDepth 8192 in
@[step]
theorem keccak_permute_opt_loop.spec
    (iter : core.ops.range.Range Usize)
    (s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19 s20 s21 s22 s23 s24 : U64)
    (hend : iter.«end».val = 24)
    (hstart : iter.start.val ≤ 24)
    (A₀ : Lanes25)
    (hinv : ⟨s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12,s13,s14,s15,s16,s17,s18,s19,s20,s21,s22,s23,s24⟩
     = iterateRndCore A₀ iter.start.val) :
    keccak_permute_opt_loop iter
      s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19 s20 s21 s22 s23 s24
    ⦃ r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23 r24 =>
      (⟨r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,r13,r14,r15,r16,r17,r18,r19,r20,r21,r22,r23,r24⟩ : Lanes25) =
        iterateRndCore A₀ 24 ⦄ := by
  -- Recursive-loop proof skeleton (post-`-loops-to-rec`):
  --   1. `rw [unfold_via_match_helper]` — bridge to `match_helper`-form.
  --   2. `by_cases hlt : start < end`.
  --   3. some: `let* IteratorRange_next_some` + `rw [hsome]` +
  --      `rw [match_helper_branch_eq]` — reduces match to some-arm.
  --   4. `let* body_fused.spec` — consume body, get struct equation.
  --   5. `apply WP.spec_mono (this_theorem iter1 …)` — manual IH.
  --      (`step*` cannot self-apply: there is no `loop` combinator now.)
  --   6. none: `let* IteratorRange_next_none` + `rw [hnone]` +
  --      `rw [match_helper_branch_eq]` — reduces to `ok` of inputs.
  rw [symcrust.keccak_permute_opt_loop.unfold_via_match_helper]
  by_cases hlt : iter.start.val < iter.«end».val
  · -- some: iterator yields next round index.
    let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← IteratorRange_next_some
    rw [hsome]
    rw [symcrust.keccak_permute_opt_loop.match_helper_branch_eq]
    -- Goal: do let (s110,…,s02) ← body_fused A.l0…A.l24 …; keccak_permute_opt_loop iter1 …
    let* ⟨ s110, s25, s31, s41, s51, s61, s71, s81, s91, s101, s111, s121, s131,
           s141, s151, s161, s171, s181, s191, s201, s211, s221, s231, s241, s02, _ ⟩
      ← symcrust.keccak_permute_opt_loop.body_fused.spec
    -- The 25 lane equalities (`s_i = (fusedRoundCore ⟨A.l0,…⟩ k).l_i`) are
    -- in context as anonymous hypotheses (`step` splits via `Lanes25.mk.injEq`).
    have hend1 : iter1.«end».val = 24 := by rw [hend']; exact hend
    have hstart1 : iter1.start.val ≤ 24 := by scalar_tac
    have hinv1 : (⟨s02, s110, s25, s31, s41, s51, s61, s71, s81, s91, s101, s111,
                   s121, s131, s141, s151, s161, s171, s181, s191, s201, s211,
                   s221, s231, s241⟩ : Lanes25) =
        iterateRndCore A₀ iter1.start.val := by
      have h2 : iter.start.val + 1 ≤ 24 := by scalar_tac
      simp only [hstart'] at *
      rw [iterateRndCore_succ A₀ iter.start.val h2]
      apply Eq.trans _ (congrArg₂ fusedRoundCore hinv rfl)
      simp_all only []
    apply WP.spec_mono
      (keccak_permute_opt_loop.spec iter1
        s02 s110 s25 s31 s41 s51 s61 s71 s81 s91 s101 s111 s121 s131 s141 s151
        s161 s171 s181 s191 s201 s211 s221 s231 s241 hend1 hstart1 A₀ hinv1)
    intro p heq
    simp only [WP.uncurry'] at heq ⊢
    exact heq
  · -- None case: iterator exhausted, return current state.
    have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← IteratorRange_next_none
    rw [hnone]
    rw [symcrust.keccak_permute_opt_loop.match_helper_branch_eq]
    simp only [WP.spec_ok]
    have heq : iter.start.val = 24 := by scalar_tac
    simp only [heq] at hinv; exact hinv
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

set_option maxHeartbeats 800000 in
@[step]
theorem keccak_permute_opt.spec
    (state : Keccak1600) :
    keccak_permute_opt state
    ⦃ (result : Keccak1600) =>
      toState result = iterateRnd (toState state) 24 ⦄ := by
  -- Use `#decompose`-generated prefix to fold the 25 reads + final `Array.make`
  -- into named pieces, then let `step*` thread the loop spec through.
  rw [keccak_permute_opt_decomp_eq, keccak_permute_opt_prefix_eq]
  step*
  · exact Lanes25.ofArray state
  · -- hinv at iter.start = 0
    rfl
  · -- bridge result to `iterateRnd` via `toState`
    show toState (Lanes25.mk _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _).toArray = _
    simp only [toState_toArray, s01_post, iterateRndCore_toState]; rfl

end sha3.keccak_opt

end symcrust
