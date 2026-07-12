/-
# Properties/SHA3/Keccak4x/Hybrid — AVX2-backed 4-way `Keccak4xHybrid.permute`.

The hybrid `permute_loop` body (`Code/Funs.lean:23572-23932`) open-codes every
Keccak `rol c k` step as an AVX2 shift/or sequence; the seven whole-`Lane4`
phase specs that capture this, together with the `#decompose` scaffolding and
`projectLane` infrastructure, live in `Hybrid/Phases.lean`.

This module is the **light composition layer**: it consumes the phase specs to
prove the per-round body spec (`body_fused.spec`), then chains it into the loop
spec (`permute_loop.spec`) and the public wrapper (`permute.spec`).  Keeping
this file free of the heavy phase proofs makes it LSP-tractable (mirrors the
`Permute/` split).
-/
import Symcrust.Properties.SHA3.Keccak4x.Hybrid.Phases

namespace symcrust

open Aeneas Aeneas.Std Result
open sha3.sha3_impl
open scoped Spec.Notations
open Intrinsics.X86_64

set_option linter.unusedSectionVars false
set_option linter.unusedVariables false

/- Override `get_elem_tactic` so array-bound side-conditions (incl. through
   `.set` chains) discharge automatically — mirrors `Permute/Base.lean`. -/
local macro_rules | `(tactic| get_elem_tactic) => `(tactic| first | assumption | (simp only [Aeneas.Std.Array.length_eq, List.length_set]; first | assumption | decide) | scalar_tac | (simp only [Aeneas.Std.Array.length_eq, List.length_set]; scalar_tac))

/-! ## θ d-value bridges

  Lift each whole-`Lane4` d-value (from `phase_theta_d.spec`) to its
  `fusedCore` column form on `projectLane i s`, by pushing `projectLane_lane`
  through the bitwise/`rotl4` homomorphisms.  Mirrors safe `Permute.theta_d*_eq`. -/

private theorem Keccak4xHybrid.permute_loop.theta_d0_eq
    (i : Fin 4) (s : Std.Array sha3.keccak4x_hybrid.Lane4 25#usize)
    (d0 : sha3.keccak4x_hybrid.Lane4)
    (h_d0 : d0 = (s[4] ^^^ s[9] ^^^ s[14] ^^^ s[19] ^^^ s[24]) ^^^ Keccak4xHybrid.rotl4 (s[1] ^^^ s[6] ^^^ s[11] ^^^ s[16] ^^^ s[21]) 1#u32) :
    Keccak4xHybrid.projectLane_lane i d0 =
      (Keccak4xHybrid.projectLane i s).l4 ^^^ (Keccak4xHybrid.projectLane i s).l9 ^^^ (Keccak4xHybrid.projectLane i s).l14 ^^^ (Keccak4xHybrid.projectLane i s).l19 ^^^ (Keccak4xHybrid.projectLane i s).l24 ^^^
      core.num.U64.rotate_left
        ((Keccak4xHybrid.projectLane i s).l1 ^^^ (Keccak4xHybrid.projectLane i s).l6 ^^^ (Keccak4xHybrid.projectLane i s).l11 ^^^ (Keccak4xHybrid.projectLane i s).l16 ^^^ (Keccak4xHybrid.projectLane i s).l21) 1#u32 := by
  apply_fun (fun L : sha3.keccak4x_hybrid.Lane4 => Keccak4xHybrid.projectLane_lane i L) at h_d0
  simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_rotl4_val] at h_d0
  exact h_d0

private theorem Keccak4xHybrid.permute_loop.theta_d1_eq
    (i : Fin 4) (s : Std.Array sha3.keccak4x_hybrid.Lane4 25#usize)
    (d1 : sha3.keccak4x_hybrid.Lane4)
    (h_d1 : d1 = (s[0] ^^^ s[5] ^^^ s[10] ^^^ s[15] ^^^ s[20]) ^^^ Keccak4xHybrid.rotl4 (s[2] ^^^ s[7] ^^^ s[12] ^^^ s[17] ^^^ s[22]) 1#u32) :
    Keccak4xHybrid.projectLane_lane i d1 =
      (Keccak4xHybrid.projectLane i s).l0 ^^^ (Keccak4xHybrid.projectLane i s).l5 ^^^ (Keccak4xHybrid.projectLane i s).l10 ^^^ (Keccak4xHybrid.projectLane i s).l15 ^^^ (Keccak4xHybrid.projectLane i s).l20 ^^^
      core.num.U64.rotate_left
        ((Keccak4xHybrid.projectLane i s).l2 ^^^ (Keccak4xHybrid.projectLane i s).l7 ^^^ (Keccak4xHybrid.projectLane i s).l12 ^^^ (Keccak4xHybrid.projectLane i s).l17 ^^^ (Keccak4xHybrid.projectLane i s).l22) 1#u32 := by
  apply_fun (fun L : sha3.keccak4x_hybrid.Lane4 => Keccak4xHybrid.projectLane_lane i L) at h_d1
  simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_rotl4_val] at h_d1
  exact h_d1

private theorem Keccak4xHybrid.permute_loop.theta_d2_eq
    (i : Fin 4) (s : Std.Array sha3.keccak4x_hybrid.Lane4 25#usize)
    (d2 : sha3.keccak4x_hybrid.Lane4)
    (h_d2 : d2 = (s[1] ^^^ s[6] ^^^ s[11] ^^^ s[16] ^^^ s[21]) ^^^ Keccak4xHybrid.rotl4 (s[3] ^^^ s[8] ^^^ s[13] ^^^ s[18] ^^^ s[23]) 1#u32) :
    Keccak4xHybrid.projectLane_lane i d2 =
      (Keccak4xHybrid.projectLane i s).l1 ^^^ (Keccak4xHybrid.projectLane i s).l6 ^^^ (Keccak4xHybrid.projectLane i s).l11 ^^^ (Keccak4xHybrid.projectLane i s).l16 ^^^ (Keccak4xHybrid.projectLane i s).l21 ^^^
      core.num.U64.rotate_left
        ((Keccak4xHybrid.projectLane i s).l3 ^^^ (Keccak4xHybrid.projectLane i s).l8 ^^^ (Keccak4xHybrid.projectLane i s).l13 ^^^ (Keccak4xHybrid.projectLane i s).l18 ^^^ (Keccak4xHybrid.projectLane i s).l23) 1#u32 := by
  apply_fun (fun L : sha3.keccak4x_hybrid.Lane4 => Keccak4xHybrid.projectLane_lane i L) at h_d2
  simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_rotl4_val] at h_d2
  exact h_d2

private theorem Keccak4xHybrid.permute_loop.theta_d3_eq
    (i : Fin 4) (s : Std.Array sha3.keccak4x_hybrid.Lane4 25#usize)
    (d3 : sha3.keccak4x_hybrid.Lane4)
    (h_d3 : d3 = (s[2] ^^^ s[7] ^^^ s[12] ^^^ s[17] ^^^ s[22]) ^^^ Keccak4xHybrid.rotl4 (s[4] ^^^ s[9] ^^^ s[14] ^^^ s[19] ^^^ s[24]) 1#u32) :
    Keccak4xHybrid.projectLane_lane i d3 =
      (Keccak4xHybrid.projectLane i s).l2 ^^^ (Keccak4xHybrid.projectLane i s).l7 ^^^ (Keccak4xHybrid.projectLane i s).l12 ^^^ (Keccak4xHybrid.projectLane i s).l17 ^^^ (Keccak4xHybrid.projectLane i s).l22 ^^^
      core.num.U64.rotate_left
        ((Keccak4xHybrid.projectLane i s).l4 ^^^ (Keccak4xHybrid.projectLane i s).l9 ^^^ (Keccak4xHybrid.projectLane i s).l14 ^^^ (Keccak4xHybrid.projectLane i s).l19 ^^^ (Keccak4xHybrid.projectLane i s).l24) 1#u32 := by
  apply_fun (fun L : sha3.keccak4x_hybrid.Lane4 => Keccak4xHybrid.projectLane_lane i L) at h_d3
  simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_rotl4_val] at h_d3
  exact h_d3

private theorem Keccak4xHybrid.permute_loop.theta_d4_eq
    (i : Fin 4) (s : Std.Array sha3.keccak4x_hybrid.Lane4 25#usize)
    (d4 : sha3.keccak4x_hybrid.Lane4)
    (h_d4 : d4 = (s[3] ^^^ s[8] ^^^ s[13] ^^^ s[18] ^^^ s[23]) ^^^ Keccak4xHybrid.rotl4 (s[0] ^^^ s[5] ^^^ s[10] ^^^ s[15] ^^^ s[20]) 1#u32) :
    Keccak4xHybrid.projectLane_lane i d4 =
      (Keccak4xHybrid.projectLane i s).l3 ^^^ (Keccak4xHybrid.projectLane i s).l8 ^^^ (Keccak4xHybrid.projectLane i s).l13 ^^^ (Keccak4xHybrid.projectLane i s).l18 ^^^ (Keccak4xHybrid.projectLane i s).l23 ^^^
      core.num.U64.rotate_left
        ((Keccak4xHybrid.projectLane i s).l0 ^^^ (Keccak4xHybrid.projectLane i s).l5 ^^^ (Keccak4xHybrid.projectLane i s).l10 ^^^ (Keccak4xHybrid.projectLane i s).l15 ^^^ (Keccak4xHybrid.projectLane i s).l20) 1#u32 := by
  apply_fun (fun L : sha3.keccak4x_hybrid.Lane4 => Keccak4xHybrid.projectLane_lane i L) at h_d4
  simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_rotl4_val] at h_d4
  exact h_d4

/-! ## `body_fused.spec` — per-lane projection equals scalar `fusedRoundCore`

  Composition of the seven phase specs from `Hybrid/Phases.lean`.  The hybrid
  fuses θ-apply into the ρ/π rotations inside each χ block, so (unlike the safe
  `Permute`) it never materialises a clean post-θ array; the per-cell output
  formulas instead match the fully-fused `fusedCore` directly.  Proof plan:
  push each phase's whole-`Lane4` post through the `projectLane_lane`
  homomorphisms, resolve cross-block reads/writes with explicit-index frame
  applications, and match `fusedCore` per lane.  The interleaved χ-block
  schedule forces a per-cell cross-block frame chase and read resolution
  (the safe `Permute` avoids both via whole-state phases). -/
set_option maxHeartbeats 3000000 in
@[step]
theorem Keccak4xHybrid.permute_loop.body_fused.spec
    (s : Array sha3.keccak4x_hybrid.Lane4 25#usize) (round : Std.Usize)
    (hround : round.val < 24) :
    Keccak4xHybrid.permute_loop.body_fused s round
    ⦃ (r : Array sha3.keccak4x_hybrid.Lane4 25#usize) =>
        ∀ i : Fin 4,
          Keccak4xHybrid.projectLane i r
            = fusedRoundCore (Keccak4xHybrid.projectLane i s)
                (KECCAK_IOTA_K.val[round.val]) ⦄ := by
  rw [Keccak4xHybrid.permute_loop.body_fused.phases_eq]
  step with Keccak4xHybrid.permute_loop.phase_theta_d.spec
  step with Keccak4xHybrid.permute_loop.phase_chi_block_0.spec
  step with Keccak4xHybrid.permute_loop.phase_chi_block_1.spec
  step with Keccak4xHybrid.permute_loop.phase_chi_block_2.spec
  step with Keccak4xHybrid.permute_loop.phase_chi_block_3.spec
  step with Keccak4xHybrid.permute_loop.phase_chi_block_4.spec
  step with Keccak4xHybrid.permute_loop.phase_iota.spec
  step*
  intro i
  simp only [l106_post2]
  /- Unfold the scalar round once (shared across all 25 lanes) so per-cell
     closers need not re-unfold `fusedCore`. -/
  simp only [fusedRoundCore, fusedCore]
  apply Lanes25.ext
  · -- h0 (χ-block 0 writes lane 0; ι XORs the round constant via l107)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[0]) = _
    have hv : (s25.set 0#usize l108)[0] = l108 := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
    have hl106 : l106 = s5[0] := by
      rw [l106_post1]
      simp_lists [s25_post, s24_post, s23_post, s22_post]
      exact (t24_post3 0 (by scalar_tac) (by decide)).trans
            ((s20_post1 0 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)).trans
             ((s15_post1 0 (by scalar_tac) (by decide) (by decide) (by decide) (by decide)).trans
              ((t12_post6 0 (by scalar_tac) (by decide) (by decide) (by decide) (by decide)).trans
               (t6_post7 0 (by scalar_tac) (by decide) (by decide)))))
    rw [hv, l108_post, hl106, t5_post6, l_post1, l_post3, l_post5]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d0_eq i s d0 l_post10,
        Keccak4xHybrid.permute_loop.theta_d1_eq i s d1 l_post11,
        Keccak4xHybrid.permute_loop.theta_d2_eq i s d2 l_post12]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rw [l107_post2 i.val i.isLt, i_post]
    rfl
  · -- h1 (χ-block 0 writes lane 1)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[1]) = _
    have hv : (s25.set 0#usize l108)[1] = s5[1] := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
      exact (t24_post3 1 (by scalar_tac) (by decide)).trans
            ((s20_post1 1 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)).trans
             ((s15_post1 1 (by scalar_tac) (by decide) (by decide) (by decide) (by decide)).trans
              ((t12_post6 1 (by scalar_tac) (by decide) (by decide) (by decide) (by decide)).trans
               (t6_post7 1 (by scalar_tac) (by decide) (by decide)))))
    rw [hv, t5_post7, l_post3, l_post5, l_post7]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d1_eq i s d1 l_post11,
        Keccak4xHybrid.permute_loop.theta_d2_eq i s d2 l_post12,
        Keccak4xHybrid.permute_loop.theta_d3_eq i s d3 l_post13]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h2 (χ-block 0 writes lane 2)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[2]) = _
    have hv : (s25.set 0#usize l108)[2] = s5[2] := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
      exact (t24_post3 2 (by scalar_tac) (by decide)).trans
            ((s20_post1 2 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)).trans
             ((s15_post1 2 (by scalar_tac) (by decide) (by decide) (by decide) (by decide)).trans
              ((t12_post6 2 (by scalar_tac) (by decide) (by decide) (by decide) (by decide)).trans
               (t6_post7 2 (by scalar_tac) (by decide) (by decide)))))
    rw [hv, t5_post8, l_post5, l_post7, l_post9]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d2_eq i s d2 l_post12,
        Keccak4xHybrid.permute_loop.theta_d3_eq i s d3 l_post13,
        Keccak4xHybrid.permute_loop.theta_d4_eq i s d4 l_post14]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h3 (χ-block 0 writes lane 3)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[3]) = _
    have hv : (s25.set 0#usize l108)[3] = s5[3] := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
      exact (t24_post3 3 (by scalar_tac) (by decide)).trans
            ((s20_post1 3 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)).trans
             ((s15_post1 3 (by scalar_tac) (by decide) (by decide) (by decide) (by decide)).trans
              ((t12_post6 3 (by scalar_tac) (by decide) (by decide) (by decide) (by decide)).trans
               (t6_post7 3 (by scalar_tac) (by decide) (by decide)))))
    rw [hv, t5_post9, l_post7, l_post9, l_post1]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d3_eq i s d3 l_post13,
        Keccak4xHybrid.permute_loop.theta_d4_eq i s d4 l_post14,
        Keccak4xHybrid.permute_loop.theta_d0_eq i s d0 l_post10]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h4 (χ-block 0 writes lane 4)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[4]) = _
    have hv : (s25.set 0#usize l108)[4] = s5[4] := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
      exact (t24_post3 4 (by scalar_tac) (by decide)).trans
            ((s20_post1 4 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)).trans
             ((s15_post1 4 (by scalar_tac) (by decide) (by decide) (by decide) (by decide)).trans
              ((t12_post6 4 (by scalar_tac) (by decide) (by decide) (by decide) (by decide)).trans
               (t6_post7 4 (by scalar_tac) (by decide) (by decide)))))
    rw [hv, t5_post10, l_post9, l_post1, l_post3]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d4_eq i s d4 l_post14,
        Keccak4xHybrid.permute_loop.theta_d0_eq i s d0 l_post10,
        Keccak4xHybrid.permute_loop.theta_d1_eq i s d1 l_post11]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h5 (χ-block 1 writes lane 5)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[5]) = _
    have hv : (s25.set 0#usize l108)[5] = s7[5] := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
      exact (t24_post3 5 (by scalar_tac) (by decide)).trans
            ((s20_post1 5 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)).trans
             ((s15_post1 5 (by scalar_tac) (by decide) (by decide) (by decide) (by decide)).trans
              (t12_post6 5 (by scalar_tac) (by decide) (by decide) (by decide) (by decide))))
    rw [hv, t6_post8, t5_post1, l_post6,
        t5_post5 9 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t5_post5 10 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d3_eq i s d3 l_post13,
        Keccak4xHybrid.permute_loop.theta_d4_eq i s d4 l_post14,
        Keccak4xHybrid.permute_loop.theta_d0_eq i s d0 l_post10]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h6 (χ-block 1 writes lane 6)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[6]) = _
    have hv : (s25.set 0#usize l108)[6] = s7[6] := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
      exact (t24_post3 6 (by scalar_tac) (by decide)).trans
            ((s20_post1 6 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)).trans
             ((s15_post1 6 (by scalar_tac) (by decide) (by decide) (by decide) (by decide)).trans
              (t12_post6 6 (by scalar_tac) (by decide) (by decide) (by decide) (by decide))))
    rw [hv, t6_post9,
        t5_post5 9 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t5_post5 10 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t5_post5 16 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d4_eq i s d4 l_post14,
        Keccak4xHybrid.permute_loop.theta_d0_eq i s d0 l_post10,
        Keccak4xHybrid.permute_loop.theta_d1_eq i s d1 l_post11]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h7 (χ-block 2 writes lane 7, value saved from block 1 as l62)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[7]) = _
    have hv : (s25.set 0#usize l108)[7] = s11[7] := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
      exact (t24_post3 7 (by scalar_tac) (by decide)).trans
            ((s20_post1 7 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)).trans
             (s15_post1 7 (by scalar_tac) (by decide) (by decide) (by decide) (by decide)))
    rw [hv, t12_post7, t6_post10,
        t5_post5 10 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t5_post5 16 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t5_post5 22 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d0_eq i s d0 l_post10,
        Keccak4xHybrid.permute_loop.theta_d1_eq i s d1 l_post11,
        Keccak4xHybrid.permute_loop.theta_d2_eq i s d2 l_post12]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h8 (χ-block 2 writes lane 8)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[8]) = _
    have hv : (s25.set 0#usize l108)[8] = s11[8] := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
      exact (t24_post3 8 (by scalar_tac) (by decide)).trans
            ((s20_post1 8 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)).trans
             (s15_post1 8 (by scalar_tac) (by decide) (by decide) (by decide) (by decide)))
    rw [hv, t12_post8, t6_post2, t6_post3, t5_post1,
        t5_post5 16 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t5_post5 22 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide), l_post6]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d1_eq i s d1 l_post11,
        Keccak4xHybrid.permute_loop.theta_d2_eq i s d2 l_post12,
        Keccak4xHybrid.permute_loop.theta_d3_eq i s d3 l_post13]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h9 (χ-block 2 writes lane 9)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[9]) = _
    have hv : (s25.set 0#usize l108)[9] = s11[9] := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
      exact (t24_post3 9 (by scalar_tac) (by decide)).trans
            ((s20_post1 9 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)).trans
             (s15_post1 9 (by scalar_tac) (by decide) (by decide) (by decide) (by decide)))
    rw [hv, t12_post9, t6_post3, t5_post1, t6_post1,
        t5_post5 22 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t5_post5 9 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide), l_post6]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d2_eq i s d2 l_post12,
        Keccak4xHybrid.permute_loop.theta_d3_eq i s d3 l_post13,
        Keccak4xHybrid.permute_loop.theta_d4_eq i s d4 l_post14]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h10 (χ-block 2 writes lane 10)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[10]) = _
    have hv : (s25.set 0#usize l108)[10] = s11[10] := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
      exact (t24_post3 10 (by scalar_tac) (by decide)).trans
            ((s20_post1 10 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)).trans
             (s15_post1 10 (by scalar_tac) (by decide) (by decide) (by decide) (by decide)))
    rw [hv, t12_post10, t5_post2, t6_post4, t12_post1, l_post2,
        t5_post5 7 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t6_post7 13 (by scalar_tac) (by decide) (by decide),
        t5_post5 13 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d1_eq i s d1 l_post11,
        Keccak4xHybrid.permute_loop.theta_d2_eq i s d2 l_post12,
        Keccak4xHybrid.permute_loop.theta_d3_eq i s d3 l_post13]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h11 (χ-block 3 writes lane 11)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[11]) = _
    have hv : (s25.set 0#usize l108)[11] = s15[11] := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
      exact (t24_post3 11 (by scalar_tac) (by decide)).trans
            (s20_post1 11 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide))
    rw [hv, s15_post2, t6_post4, t12_post1, t12_post2,
        t5_post5 7 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t6_post7 13 (by scalar_tac) (by decide) (by decide),
        t5_post5 13 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t6_post7 19 (by scalar_tac) (by decide) (by decide),
        t5_post5 19 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d2_eq i s d2 l_post12,
        Keccak4xHybrid.permute_loop.theta_d3_eq i s d3 l_post13,
        Keccak4xHybrid.permute_loop.theta_d4_eq i s d4 l_post14]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h12 (χ-block 3 writes lane 12)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[12]) = _
    have hv : (s25.set 0#usize l108)[12] = s15[12] := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
      exact (t24_post3 12 (by scalar_tac) (by decide)).trans
            (s20_post1 12 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide))
    rw [hv, s15_post3, t12_post1, t12_post2, t12_post3,
        t6_post7 13 (by scalar_tac) (by decide) (by decide),
        t5_post5 13 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t6_post7 19 (by scalar_tac) (by decide) (by decide),
        t5_post5 19 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t6_post7 20 (by scalar_tac) (by decide) (by decide),
        t5_post5 20 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d3_eq i s d3 l_post13,
        Keccak4xHybrid.permute_loop.theta_d4_eq i s d4 l_post14,
        Keccak4xHybrid.permute_loop.theta_d0_eq i s d0 l_post10]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h13 (χ-block 3 writes lane 13)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[13]) = _
    have hv : (s25.set 0#usize l108)[13] = s15[13] := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
      exact (t24_post3 13 (by scalar_tac) (by decide)).trans
            (s20_post1 13 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide))
    rw [hv, s15_post4, t12_post2, t12_post3, t5_post2,
        t6_post7 19 (by scalar_tac) (by decide) (by decide),
        t5_post5 19 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t6_post7 20 (by scalar_tac) (by decide) (by decide),
        t5_post5 20 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        l_post2]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d4_eq i s d4 l_post14,
        Keccak4xHybrid.permute_loop.theta_d0_eq i s d0 l_post10,
        Keccak4xHybrid.permute_loop.theta_d1_eq i s d1 l_post11]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h14 (χ-block 3 writes lane 14)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[14]) = _
    have hv : (s25.set 0#usize l108)[14] = s15[14] := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
      exact (t24_post3 14 (by scalar_tac) (by decide)).trans
            (s20_post1 14 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide))
    rw [hv, s15_post5, t12_post3, t5_post2, t6_post4,
        t6_post7 20 (by scalar_tac) (by decide) (by decide),
        t5_post5 20 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        l_post2,
        t5_post5 7 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d0_eq i s d0 l_post10,
        Keccak4xHybrid.permute_loop.theta_d1_eq i s d1 l_post11,
        Keccak4xHybrid.permute_loop.theta_d2_eq i s d2 l_post12]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h15 (χ-block 4 writes lane 15)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[15]) = _
    have hv : (s25.set 0#usize l108)[15] = s20[15] := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
      exact t24_post3 15 (by scalar_tac) (by decide)
    rw [hv, s20_post2, t5_post3, t6_post5, t12_post4, l_post8,
        t5_post5 5 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t6_post7 11 (by scalar_tac) (by decide) (by decide),
        t5_post5 11 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d4_eq i s d4 l_post14,
        Keccak4xHybrid.permute_loop.theta_d0_eq i s d0 l_post10,
        Keccak4xHybrid.permute_loop.theta_d1_eq i s d1 l_post11]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h16 (χ-block 4 writes lane 16)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[16]) = _
    have hv : (s25.set 0#usize l108)[16] = s20[16] := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
      exact t24_post3 16 (by scalar_tac) (by decide)
    rw [hv, s20_post3, t6_post5, t12_post4, s15_post6,
        t5_post5 5 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t6_post7 11 (by scalar_tac) (by decide) (by decide),
        t5_post5 11 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t12_post6 17 (by scalar_tac) (by decide) (by decide) (by decide) (by decide),
        t6_post7 17 (by scalar_tac) (by decide) (by decide),
        t5_post5 17 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d0_eq i s d0 l_post10,
        Keccak4xHybrid.permute_loop.theta_d1_eq i s d1 l_post11,
        Keccak4xHybrid.permute_loop.theta_d2_eq i s d2 l_post12]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h17 (χ-block 4 writes lane 17)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[17]) = _
    have hv : (s25.set 0#usize l108)[17] = s20[17] := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
      exact t24_post3 17 (by scalar_tac) (by decide)
    rw [hv, s20_post4, t12_post4, s15_post6, s15_post7,
        t6_post7 11 (by scalar_tac) (by decide) (by decide),
        t5_post5 11 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t12_post6 17 (by scalar_tac) (by decide) (by decide) (by decide) (by decide),
        t6_post7 17 (by scalar_tac) (by decide) (by decide),
        t5_post5 17 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t12_post6 23 (by scalar_tac) (by decide) (by decide) (by decide) (by decide),
        t6_post7 23 (by scalar_tac) (by decide) (by decide),
        t5_post5 23 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d1_eq i s d1 l_post11,
        Keccak4xHybrid.permute_loop.theta_d2_eq i s d2 l_post12,
        Keccak4xHybrid.permute_loop.theta_d3_eq i s d3 l_post13]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h18 (χ-block 4 writes lane 18)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[18]) = _
    have hv : (s25.set 0#usize l108)[18] = s20[18] := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
      exact t24_post3 18 (by scalar_tac) (by decide)
    rw [hv, s20_post5, s15_post6, s15_post7, t5_post3,
        t12_post6 17 (by scalar_tac) (by decide) (by decide) (by decide) (by decide),
        t6_post7 17 (by scalar_tac) (by decide) (by decide),
        t5_post5 17 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t12_post6 23 (by scalar_tac) (by decide) (by decide) (by decide) (by decide),
        t6_post7 23 (by scalar_tac) (by decide) (by decide),
        t5_post5 23 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        l_post8]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d2_eq i s d2 l_post12,
        Keccak4xHybrid.permute_loop.theta_d3_eq i s d3 l_post13,
        Keccak4xHybrid.permute_loop.theta_d4_eq i s d4 l_post14]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h19 (χ-block 4 writes lane 19)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[19]) = _
    have hv : (s25.set 0#usize l108)[19] = s20[19] := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
      exact t24_post3 19 (by scalar_tac) (by decide)
    rw [hv, s20_post6, s15_post7, t5_post3, t6_post5,
        t12_post6 23 (by scalar_tac) (by decide) (by decide) (by decide) (by decide),
        t6_post7 23 (by scalar_tac) (by decide) (by decide),
        t5_post5 23 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        l_post8,
        t5_post5 5 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d3_eq i s d3 l_post13,
        Keccak4xHybrid.permute_loop.theta_d4_eq i s d4 l_post14,
        Keccak4xHybrid.permute_loop.theta_d0_eq i s d0 l_post10]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h20 (ι writes lane 20)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[20]) = _
    have hv : (s25.set 0#usize l108)[20] = s21[20] := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
    rw [hv, t24_post4, t5_post4, t6_post6, t12_post5, l_post4,
        t5_post5 8 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t6_post7 14 (by scalar_tac) (by decide) (by decide),
        t5_post5 14 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d2_eq i s d2 l_post12,
        Keccak4xHybrid.permute_loop.theta_d3_eq i s d3 l_post13,
        Keccak4xHybrid.permute_loop.theta_d4_eq i s d4 l_post14]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h21 (trailing χ write, lane 21)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[21]) = _
    have hv : (s25.set 0#usize l108)[21] = l99 := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
    rw [hv, l99_post, t24_post2, t6_post6, t12_post5, s15_post8,
        t5_post5 8 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t6_post7 14 (by scalar_tac) (by decide) (by decide),
        t5_post5 14 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t12_post6 15 (by scalar_tac) (by decide) (by decide) (by decide) (by decide),
        t6_post7 15 (by scalar_tac) (by decide) (by decide),
        t5_post5 15 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d3_eq i s d3 l_post13,
        Keccak4xHybrid.permute_loop.theta_d4_eq i s d4 l_post14,
        Keccak4xHybrid.permute_loop.theta_d0_eq i s d0 l_post10]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h22 (trailing χ write, lane 22)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[22]) = _
    have hv : (s25.set 0#usize l108)[22] = l101 := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
    rw [hv, l101_post, l100_post, t12_post5, s15_post8, t24_post1, s20_post7,
        t6_post7 14 (by scalar_tac) (by decide) (by decide),
        t5_post5 14 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        t12_post6 15 (by scalar_tac) (by decide) (by decide) (by decide) (by decide),
        t6_post7 15 (by scalar_tac) (by decide) (by decide),
        t5_post5 15 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        s15_post1 21 (by scalar_tac) (by decide) (by decide) (by decide) (by decide),
        t12_post6 21 (by scalar_tac) (by decide) (by decide) (by decide) (by decide),
        t6_post7 21 (by scalar_tac) (by decide) (by decide),
        t5_post5 21 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d4_eq i s d4 l_post14,
        Keccak4xHybrid.permute_loop.theta_d0_eq i s d0 l_post10,
        Keccak4xHybrid.permute_loop.theta_d1_eq i s d1 l_post11]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h23 (trailing χ write, lane 23)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[23]) = _
    have hv : (s25.set 0#usize l108)[23] = l103 := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
    rw [hv, l103_post, l102_post, s15_post8, t24_post1, s20_post7, t5_post4,
        t12_post6 15 (by scalar_tac) (by decide) (by decide) (by decide) (by decide),
        t6_post7 15 (by scalar_tac) (by decide) (by decide),
        t5_post5 15 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        s15_post1 21 (by scalar_tac) (by decide) (by decide) (by decide) (by decide),
        t12_post6 21 (by scalar_tac) (by decide) (by decide) (by decide) (by decide),
        t6_post7 21 (by scalar_tac) (by decide) (by decide),
        t5_post5 21 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        l_post4]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d0_eq i s d0 l_post10,
        Keccak4xHybrid.permute_loop.theta_d1_eq i s d1 l_post11,
        Keccak4xHybrid.permute_loop.theta_d2_eq i s d2 l_post12]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl
  · -- h24 (trailing χ write, lane 24)
    show Keccak4xHybrid.projectLane_lane i ((s25.set 0#usize l108)[24]) = _
    have hv : (s25.set 0#usize l108)[24] = l105 := by
      simp_lists [s25_post, s24_post, s23_post, s22_post]
    rw [hv, l105_post, l104_post, t24_post1, s20_post7, t5_post4, t6_post6,
        s15_post1 21 (by scalar_tac) (by decide) (by decide) (by decide) (by decide),
        t12_post6 21 (by scalar_tac) (by decide) (by decide) (by decide) (by decide),
        t6_post7 21 (by scalar_tac) (by decide) (by decide),
        t5_post5 21 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide),
        l_post4,
        t5_post5 8 (by scalar_tac) (by decide) (by decide) (by decide) (by decide) (by decide)]
    simp only [Keccak4xHybrid.projectLane_lane_xor, Keccak4xHybrid.projectLane_lane_and,
               Keccak4xHybrid.projectLane_lane_not, Keccak4xHybrid.projectLane_lane_rotl4_val]
    rw [Keccak4xHybrid.permute_loop.theta_d1_eq i s d1 l_post11,
        Keccak4xHybrid.permute_loop.theta_d2_eq i s d2 l_post12,
        Keccak4xHybrid.permute_loop.theta_d3_eq i s d3 l_post13]
    simp only [Keccak4xHybrid.projectLane, Keccak4xHybrid.projectLane_lane,
               Fin.getElem_fin]
    rfl

/-- **Informal proof** (loop spec — hybrid `permute_loop` body, `Funs.lean:23572-23932`).
    Algebraically equivalent to `Keccak4x.permute_loop` (same per-lane
    Keccak-f round structure), but each `Lane4.rol c k` is open-coded as
      `v   := load_lane c`
      `mi  := _mm256_slli_epi64 k v`
      `mi1 := _mm256_srli_epi64 (64-k) v`
      `r   := _mm256_or_si256 mi mi1`
      `out := store_lane (Array.repeat 4 0) r`
    where `load_lane`/`store_lane` are defined in
    `Code/FunsExternal.lean:1028-1057` via `__m256i.{u64x4, ofU64x4}`.

    The proof reduces to `Keccak4x.permute_loop.spec` once the AVX2
    open-coding of `rol` is shown to satisfy the same per-lane bit-vector
    equation: a `rol4_correct` lemma stating

        store_lane (Array.repeat 4 0) (_mm256_or_si256
          (_mm256_slli_epi64 k (load_lane c))
          (_mm256_srli_epi64 (64-k) (load_lane c)))
        = sha3.keccak4x.Lane4.rol c k

    **Loop invariant**: identical to `Keccak4x.permute_loop.spec`,
    using `Keccak4xHybrid.projectLane`.

    Discharge: same chain as safe `permute_loop`; the only extra step
    is `rol4_correct` per occurrence of `rol`. -/
@[step]
theorem Keccak4xHybrid.permute_loop.spec
    (iter : core.ops.range.Range Std.Usize)
    (s A₀ : Array sha3.keccak4x_hybrid.Lane4 25#usize)
    (hEnd : iter.«end».val = 24)
    (hStart : iter.start.val ≤ iter.«end».val)
    (hinv : ∀ i : Fin 4,
      Keccak4xHybrid.projectLane i s
        = iterateRndCore (Keccak4xHybrid.projectLane i A₀) iter.start.val) :
    sha3.keccak4x_hybrid.Keccak4xHybrid.permute_impl_loop iter s
    ⦃ (r : Array sha3.keccak4x_hybrid.Lane4 25#usize) =>
        ∀ i : Fin 4,
          Keccak4xHybrid.projectLane i r
            = iterateRndCore (Keccak4xHybrid.projectLane i A₀) 24 ⦄ := by
  rw [Keccak4xHybrid.permute_loop.match_helper_eq]
  by_cases hlt : iter.start.val < iter.«end».val
  · -- some: iterator yields next round index
    let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← IteratorRange_next_some iter hlt
    rw [hsome]
    rw [Keccak4xHybrid.permute_loop.match_helper_branch_eq]
    -- Goal: do let a ← body_fused s round; permute_loop iter1 a
    have hround : iter.start.val < 24 := by scalar_tac
    let* ⟨ a, ha_post ⟩ ←
      Keccak4xHybrid.permute_loop.body_fused.spec s iter.start hround
    -- Build refreshed invariant for iter1
    have hend1 : iter1.«end».val = 24 := by rw [hend']; exact hEnd
    have hstart1 : iter1.start.val ≤ iter1.«end».val := by
      rw [hstart', hend']; scalar_tac
    have h2 : iter.start.val + 1 ≤ 24 := by scalar_tac
    have hinv1 : ∀ i : Fin 4,
        Keccak4xHybrid.projectLane i a
          = iterateRndCore (Keccak4xHybrid.projectLane i A₀) iter1.start.val := by
      intro i
      simp only [hstart']
      rw [iterateRndCore_succ (Keccak4xHybrid.projectLane i A₀) iter.start.val h2]
      apply Eq.trans (ha_post i) (congrArg₂ fusedRoundCore (hinv i) rfl)
    apply WP.spec_mono
      (Keccak4xHybrid.permute_loop.spec iter1 a A₀ hend1 hstart1 hinv1)
    intro p hp
    exact hp
  · -- none: iterator exhausted
    have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← IteratorRange_next_none iter hge
    rw [hnone]
    rw [Keccak4xHybrid.permute_loop.match_helper_branch_eq]
    simp only [WP.spec_ok]
    intro i
    have heq : iter.start.val = 24 := by scalar_tac
    simp only [heq] at hinv
    exact hinv i
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- **Informal proof** (`Keccak4xHybrid.permute` wrapper).
    Body (`Funs.lean:23933-23939`): `let s ← permute_loop {start := 0, end := 24} self.state; ok { state := s }`.
    Same shape as safe variant.

    Lemma chain: `Keccak4xHybrid.permute_loop.spec` at
    `iter.start = 0`, `A₀ = self.state`, with `hinv` discharged by
    `iterateRndCore _ 0 = id`. -/
-- cost: walltime≈5s heartbeats<1M loc=6
@[step]
theorem Keccak4xHybrid.permute.spec (self : sha3.keccak4x_hybrid.Keccak4xHybrid) :
    sha3.keccak4x_hybrid.Keccak4xHybrid.permute self
    ⦃ (r : sha3.keccak4x_hybrid.Keccak4xHybrid) =>
        r.state.val.length = 25 ∧
        ∀ i : Fin 4,
          Keccak4xHybrid.projectLane i r.state
            = iterateRndCore (Keccak4xHybrid.projectLane i self.state) 24 ⦄ := by
  unfold sha3.keccak4x_hybrid.Keccak4xHybrid.permute
    sha3.keccak4x_hybrid.Keccak4xHybrid.permute_impl
  step*
  · exact self.state
  · intro i; rfl
  · exact ⟨s.property, s_post⟩

end symcrust
