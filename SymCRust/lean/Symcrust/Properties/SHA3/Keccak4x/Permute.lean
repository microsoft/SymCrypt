import Symcrust.Properties.SHA3.Keccak4x.Permute.Theta
import Symcrust.Properties.SHA3.Keccak4x.Permute.Chi

namespace symcrust

open Aeneas Aeneas.Std Result
open sha3.sha3_impl
open scoped Spec.Notations

set_option linter.unusedSectionVars false
set_option linter.unusedVariables false

local macro_rules | `(tactic| get_elem_tactic) => `(tactic| first | assumption | (simp only [Aeneas.Std.Array.length_eq, List.length_set]; first | assumption | decide) | scalar_tac | (simp only [Aeneas.Std.Array.length_eq, List.length_set]; scalar_tac))

attribute [local scalar_tac_simps, local agrind =] Lane4_val_length




/-! ## Bridge helpers for `body_fused.spec` per-lane closure (SHA3-0097)

  Clean form: `theta_d_n_eq` consume `phase_theta_d.spec`'s BV-level
  d-value formulas (lane-xor-then-`.bv` form, `s[j][i.val]`) and produce
  the U64-level thetaCore column formula on `projectLane i s`.
  `theta_eq` composes the 5 helpers with `phase_theta_apply.spec`'s
  `s25` structure equation.  All array access uses the `[i.val]` notation
  with the file's `get_elem_tactic` override (cheap `assumption` first,
  `scalar_tac` last); `d_n[i.val]` is defeq to `phase_theta_apply`'s
  `d_n.val[i.val]'(_)` form, so `s25_post` is accepted directly. -/

/-- `d_0` column-formula bridge: whole-`Lane4` d-value -> thetaCore column form. -/
private theorem Keccak4x.permute_loop.theta_d0_eq
    (i : Fin 4) (s : Std.Array sha3.keccak4x.Lane4 25#usize)
    (d0 : sha3.keccak4x.Lane4)
    (h_d0 : d0 = (s[4] ^^^ s[9] ^^^ s[14] ^^^ s[19] ^^^ s[24]) ^^^ Keccak4x.rotl4 (s[1] ^^^ s[6] ^^^ s[11] ^^^ s[16] ^^^ s[21]) 1#u32) :
    d0[i.val] =
      (Keccak4x.projectLane i s).l4 ^^^ (Keccak4x.projectLane i s).l9 ^^^ (Keccak4x.projectLane i s).l14 ^^^ (Keccak4x.projectLane i s).l19 ^^^ (Keccak4x.projectLane i s).l24 ^^^
      core.num.U64.rotate_left
        ((Keccak4x.projectLane i s).l1 ^^^ (Keccak4x.projectLane i s).l6 ^^^ (Keccak4x.projectLane i s).l11 ^^^ (Keccak4x.projectLane i s).l16 ^^^ (Keccak4x.projectLane i s).l21) 1#u32 := by
  apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h_d0
  simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_rotl4_val] at h_d0
  exact h_d0

/-- `d_1` column-formula bridge: whole-`Lane4` d-value -> thetaCore column form. -/
private theorem Keccak4x.permute_loop.theta_d1_eq
    (i : Fin 4) (s : Std.Array sha3.keccak4x.Lane4 25#usize)
    (d1 : sha3.keccak4x.Lane4)
    (h_d1 : d1 = (s[0] ^^^ s[5] ^^^ s[10] ^^^ s[15] ^^^ s[20]) ^^^ Keccak4x.rotl4 (s[2] ^^^ s[7] ^^^ s[12] ^^^ s[17] ^^^ s[22]) 1#u32) :
    d1[i.val] =
      (Keccak4x.projectLane i s).l0 ^^^ (Keccak4x.projectLane i s).l5 ^^^ (Keccak4x.projectLane i s).l10 ^^^ (Keccak4x.projectLane i s).l15 ^^^ (Keccak4x.projectLane i s).l20 ^^^
      core.num.U64.rotate_left
        ((Keccak4x.projectLane i s).l2 ^^^ (Keccak4x.projectLane i s).l7 ^^^ (Keccak4x.projectLane i s).l12 ^^^ (Keccak4x.projectLane i s).l17 ^^^ (Keccak4x.projectLane i s).l22) 1#u32 := by
  apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h_d1
  simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_rotl4_val] at h_d1
  exact h_d1

/-- `d_2` column-formula bridge: whole-`Lane4` d-value -> thetaCore column form. -/
private theorem Keccak4x.permute_loop.theta_d2_eq
    (i : Fin 4) (s : Std.Array sha3.keccak4x.Lane4 25#usize)
    (d2 : sha3.keccak4x.Lane4)
    (h_d2 : d2 = (s[1] ^^^ s[6] ^^^ s[11] ^^^ s[16] ^^^ s[21]) ^^^ Keccak4x.rotl4 (s[3] ^^^ s[8] ^^^ s[13] ^^^ s[18] ^^^ s[23]) 1#u32) :
    d2[i.val] =
      (Keccak4x.projectLane i s).l1 ^^^ (Keccak4x.projectLane i s).l6 ^^^ (Keccak4x.projectLane i s).l11 ^^^ (Keccak4x.projectLane i s).l16 ^^^ (Keccak4x.projectLane i s).l21 ^^^
      core.num.U64.rotate_left
        ((Keccak4x.projectLane i s).l3 ^^^ (Keccak4x.projectLane i s).l8 ^^^ (Keccak4x.projectLane i s).l13 ^^^ (Keccak4x.projectLane i s).l18 ^^^ (Keccak4x.projectLane i s).l23) 1#u32 := by
  apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h_d2
  simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_rotl4_val] at h_d2
  exact h_d2

/-- `d_3` column-formula bridge: whole-`Lane4` d-value -> thetaCore column form. -/
private theorem Keccak4x.permute_loop.theta_d3_eq
    (i : Fin 4) (s : Std.Array sha3.keccak4x.Lane4 25#usize)
    (d3 : sha3.keccak4x.Lane4)
    (h_d3 : d3 = (s[2] ^^^ s[7] ^^^ s[12] ^^^ s[17] ^^^ s[22]) ^^^ Keccak4x.rotl4 (s[4] ^^^ s[9] ^^^ s[14] ^^^ s[19] ^^^ s[24]) 1#u32) :
    d3[i.val] =
      (Keccak4x.projectLane i s).l2 ^^^ (Keccak4x.projectLane i s).l7 ^^^ (Keccak4x.projectLane i s).l12 ^^^ (Keccak4x.projectLane i s).l17 ^^^ (Keccak4x.projectLane i s).l22 ^^^
      core.num.U64.rotate_left
        ((Keccak4x.projectLane i s).l4 ^^^ (Keccak4x.projectLane i s).l9 ^^^ (Keccak4x.projectLane i s).l14 ^^^ (Keccak4x.projectLane i s).l19 ^^^ (Keccak4x.projectLane i s).l24) 1#u32 := by
  apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h_d3
  simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_rotl4_val] at h_d3
  exact h_d3

/-- `d_4` column-formula bridge: whole-`Lane4` d-value -> thetaCore column form. -/
private theorem Keccak4x.permute_loop.theta_d4_eq
    (i : Fin 4) (s : Std.Array sha3.keccak4x.Lane4 25#usize)
    (d4 : sha3.keccak4x.Lane4)
    (h_d4 : d4 = (s[3] ^^^ s[8] ^^^ s[13] ^^^ s[18] ^^^ s[23]) ^^^ Keccak4x.rotl4 (s[0] ^^^ s[5] ^^^ s[10] ^^^ s[15] ^^^ s[20]) 1#u32) :
    d4[i.val] =
      (Keccak4x.projectLane i s).l3 ^^^ (Keccak4x.projectLane i s).l8 ^^^ (Keccak4x.projectLane i s).l13 ^^^ (Keccak4x.projectLane i s).l18 ^^^ (Keccak4x.projectLane i s).l23 ^^^
      core.num.U64.rotate_left
        ((Keccak4x.projectLane i s).l0 ^^^ (Keccak4x.projectLane i s).l5 ^^^ (Keccak4x.projectLane i s).l10 ^^^ (Keccak4x.projectLane i s).l15 ^^^ (Keccak4x.projectLane i s).l20) 1#u32 := by
  apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h_d4
  simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_rotl4_val] at h_d4
  exact h_d4

set_option maxHeartbeats 2000000 in
/-- **Structure-level theta bridge** for `body_fused.spec`.  Composes the 5
    `theta_d_n_eq` helpers with `phase_theta_apply.spec`'s `s25` structure
    equation to conclude `projectLane i s25 = thetaCore (projectLane i s)`. -/
private theorem Keccak4x.permute_loop.theta_eq
    (i : Fin 4)
    (s s25 : Std.Array sha3.keccak4x.Lane4 25#usize)
    (d0 d1 d2 d3 d4 : sha3.keccak4x.Lane4)
    (h_d0 : d0 = (s[4] ^^^ s[9] ^^^ s[14] ^^^ s[19] ^^^ s[24]) ^^^ Keccak4x.rotl4 (s[1] ^^^ s[6] ^^^ s[11] ^^^ s[16] ^^^ s[21]) 1#u32)
    (h_d1 : d1 = (s[0] ^^^ s[5] ^^^ s[10] ^^^ s[15] ^^^ s[20]) ^^^ Keccak4x.rotl4 (s[2] ^^^ s[7] ^^^ s[12] ^^^ s[17] ^^^ s[22]) 1#u32)
    (h_d2 : d2 = (s[1] ^^^ s[6] ^^^ s[11] ^^^ s[16] ^^^ s[21]) ^^^ Keccak4x.rotl4 (s[3] ^^^ s[8] ^^^ s[13] ^^^ s[18] ^^^ s[23]) 1#u32)
    (h_d3 : d3 = (s[2] ^^^ s[7] ^^^ s[12] ^^^ s[17] ^^^ s[22]) ^^^ Keccak4x.rotl4 (s[4] ^^^ s[9] ^^^ s[14] ^^^ s[19] ^^^ s[24]) 1#u32)
    (h_d4 : d4 = (s[3] ^^^ s[8] ^^^ s[13] ^^^ s[18] ^^^ s[23]) ^^^ Keccak4x.rotl4 (s[0] ^^^ s[5] ^^^ s[10] ^^^ s[15] ^^^ s[20]) 1#u32)
    (h_s25 : Keccak4x.projectLane i s25 =
        {
          l0 := (Keccak4x.projectLane i s).l0 ^^^ d0[i.val],
          l1 := (Keccak4x.projectLane i s).l1 ^^^ d1[i.val],
          l2 := (Keccak4x.projectLane i s).l2 ^^^ d2[i.val],
          l3 := (Keccak4x.projectLane i s).l3 ^^^ d3[i.val],
          l4 := (Keccak4x.projectLane i s).l4 ^^^ d4[i.val],
          l5 := (Keccak4x.projectLane i s).l5 ^^^ d0[i.val],
          l6 := (Keccak4x.projectLane i s).l6 ^^^ d1[i.val],
          l7 := (Keccak4x.projectLane i s).l7 ^^^ d2[i.val],
          l8 := (Keccak4x.projectLane i s).l8 ^^^ d3[i.val],
          l9 := (Keccak4x.projectLane i s).l9 ^^^ d4[i.val],
          l10 := (Keccak4x.projectLane i s).l10 ^^^ d0[i.val],
          l11 := (Keccak4x.projectLane i s).l11 ^^^ d1[i.val],
          l12 := (Keccak4x.projectLane i s).l12 ^^^ d2[i.val],
          l13 := (Keccak4x.projectLane i s).l13 ^^^ d3[i.val],
          l14 := (Keccak4x.projectLane i s).l14 ^^^ d4[i.val],
          l15 := (Keccak4x.projectLane i s).l15 ^^^ d0[i.val],
          l16 := (Keccak4x.projectLane i s).l16 ^^^ d1[i.val],
          l17 := (Keccak4x.projectLane i s).l17 ^^^ d2[i.val],
          l18 := (Keccak4x.projectLane i s).l18 ^^^ d3[i.val],
          l19 := (Keccak4x.projectLane i s).l19 ^^^ d4[i.val],
          l20 := (Keccak4x.projectLane i s).l20 ^^^ d0[i.val],
          l21 := (Keccak4x.projectLane i s).l21 ^^^ d1[i.val],
          l22 := (Keccak4x.projectLane i s).l22 ^^^ d2[i.val],
          l23 := (Keccak4x.projectLane i s).l23 ^^^ d3[i.val],
          l24 := (Keccak4x.projectLane i s).l24 ^^^ d4[i.val] }) :
    Keccak4x.projectLane i s25 = thetaCore (Keccak4x.projectLane i s) := by
  rw [h_s25]
  have e0 := Keccak4x.permute_loop.theta_d0_eq i s d0 h_d0
  have e1 := Keccak4x.permute_loop.theta_d1_eq i s d1 h_d1
  have e2 := Keccak4x.permute_loop.theta_d2_eq i s d2 h_d2
  have e3 := Keccak4x.permute_loop.theta_d3_eq i s d3 h_d3
  have e4 := Keccak4x.permute_loop.theta_d4_eq i s d4 h_d4
  rw [e0, e1, e2, e3, e4]
  unfold thetaCore
  rfl

private theorem Keccak4x.permute_loop.rho_pi_eq
    (i : Fin 4)
    (s25 : Std.Array sha3.keccak4x.Lane4 25#usize)
    (l_0 l_1 l_2 l_3 l_4 l_5 l_6 l_7 l_8 l_9 l_10 l_11 l_12 l_13 l_14 l_15 l_16 l_17 l_18 l_19 l_20 l_21 l_22 l_23 l_24 : sha3.keccak4x.Lane4)
    (h_0 : l_0 = s25[0])
    (h_1 : l_1 = Keccak4x.rotl4 s25[6] 44#u32)
    (h_2 : l_2 = Keccak4x.rotl4 s25[12] 43#u32)
    (h_3 : l_3 = Keccak4x.rotl4 s25[18] 21#u32)
    (h_4 : l_4 = Keccak4x.rotl4 s25[24] 14#u32)
    (h_5 : l_5 = Keccak4x.rotl4 s25[3] 28#u32)
    (h_6 : l_6 = Keccak4x.rotl4 s25[9] 20#u32)
    (h_7 : l_7 = Keccak4x.rotl4 s25[10] 3#u32)
    (h_8 : l_8 = Keccak4x.rotl4 s25[16] 45#u32)
    (h_9 : l_9 = Keccak4x.rotl4 s25[22] 61#u32)
    (h_10 : l_10 = Keccak4x.rotl4 s25[1] 1#u32)
    (h_11 : l_11 = Keccak4x.rotl4 s25[7] 6#u32)
    (h_12 : l_12 = Keccak4x.rotl4 s25[13] 25#u32)
    (h_13 : l_13 = Keccak4x.rotl4 s25[19] 8#u32)
    (h_14 : l_14 = Keccak4x.rotl4 s25[20] 18#u32)
    (h_15 : l_15 = Keccak4x.rotl4 s25[4] 27#u32)
    (h_16 : l_16 = Keccak4x.rotl4 s25[5] 36#u32)
    (h_17 : l_17 = Keccak4x.rotl4 s25[11] 10#u32)
    (h_18 : l_18 = Keccak4x.rotl4 s25[17] 15#u32)
    (h_19 : l_19 = Keccak4x.rotl4 s25[23] 56#u32)
    (h_20 : l_20 = Keccak4x.rotl4 s25[2] 62#u32)
    (h_21 : l_21 = Keccak4x.rotl4 s25[8] 55#u32)
    (h_22 : l_22 = Keccak4x.rotl4 s25[14] 39#u32)
    (h_23 : l_23 = Keccak4x.rotl4 s25[15] 41#u32)
    (h_24 : l_24 = Keccak4x.rotl4 s25[21] 2#u32)
    : ( { l0 := l_0[i.val], l1 := l_1[i.val], l2 := l_2[i.val], l3 := l_3[i.val], l4 := l_4[i.val], l5 := l_5[i.val], l6 := l_6[i.val], l7 := l_7[i.val], l8 := l_8[i.val], l9 := l_9[i.val], l10 := l_10[i.val], l11 := l_11[i.val], l12 := l_12[i.val], l13 := l_13[i.val], l14 := l_14[i.val], l15 := l_15[i.val], l16 := l_16[i.val], l17 := l_17[i.val], l18 := l_18[i.val], l19 := l_19[i.val], l20 := l_20[i.val], l21 := l_21[i.val], l22 := l_22[i.val], l23 := l_23[i.val], l24 := l_24[i.val] } : Lanes25) =
       piCore (rhoCore (Keccak4x.projectLane i s25)) := by
  unfold piCore rhoCore Keccak4x.projectLane
  apply Lanes25.ext <;> dsimp only
  case h0 => have h := h_0; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane] at h ⊢; exact h
  case h1 => have h := h_1; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h2 => have h := h_2; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h3 => have h := h_3; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h4 => have h := h_4; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h5 => have h := h_5; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h6 => have h := h_6; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h7 => have h := h_7; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h8 => have h := h_8; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h9 => have h := h_9; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h10 => have h := h_10; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h11 => have h := h_11; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h12 => have h := h_12; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h13 => have h := h_13; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h14 => have h := h_14; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h15 => have h := h_15; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h16 => have h := h_16; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h17 => have h := h_17; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h18 => have h := h_18; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h19 => have h := h_19; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h20 => have h := h_20; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h21 => have h := h_21; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h22 => have h := h_22; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h23 => have h := h_23; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h
  case h24 => have h := h_24; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane, Keccak4x.val_rotl4, List.getElem_map] at h; simp only [core.num.U64.rotate_left] at h ⊢; exact h

private theorem Keccak4x.permute_loop.chi_eq
    (i : Fin 4)
    (s50 : Std.Array sha3.keccak4x.Lane4 25#usize)
    (l_0 l_1 l_2 l_3 l_4 l_5 l_6 l_7 l_8 l_9 l_10 l_11 l_12 l_13 l_14 l_15 l_16 l_17 l_18 l_19 l_20 l_21 l_22 l_23 l_24 : sha3.keccak4x.Lane4)
    (h_0 : s50[0] = l_0 ^^^ ((~~~ l_1) &&& l_2))
    (h_1 : s50[1] = l_1 ^^^ ((~~~ l_2) &&& l_3))
    (h_2 : s50[2] = l_2 ^^^ ((~~~ l_3) &&& l_4))
    (h_3 : s50[3] = l_3 ^^^ ((~~~ l_4) &&& l_0))
    (h_4 : s50[4] = l_4 ^^^ ((~~~ l_0) &&& l_1))
    (h_5 : s50[5] = l_5 ^^^ ((~~~ l_6) &&& l_7))
    (h_6 : s50[6] = l_6 ^^^ ((~~~ l_7) &&& l_8))
    (h_7 : s50[7] = l_7 ^^^ ((~~~ l_8) &&& l_9))
    (h_8 : s50[8] = l_8 ^^^ ((~~~ l_9) &&& l_5))
    (h_9 : s50[9] = l_9 ^^^ ((~~~ l_5) &&& l_6))
    (h_10 : s50[10] = l_10 ^^^ ((~~~ l_11) &&& l_12))
    (h_11 : s50[11] = l_11 ^^^ ((~~~ l_12) &&& l_13))
    (h_12 : s50[12] = l_12 ^^^ ((~~~ l_13) &&& l_14))
    (h_13 : s50[13] = l_13 ^^^ ((~~~ l_14) &&& l_10))
    (h_14 : s50[14] = l_14 ^^^ ((~~~ l_10) &&& l_11))
    (h_15 : s50[15] = l_15 ^^^ ((~~~ l_16) &&& l_17))
    (h_16 : s50[16] = l_16 ^^^ ((~~~ l_17) &&& l_18))
    (h_17 : s50[17] = l_17 ^^^ ((~~~ l_18) &&& l_19))
    (h_18 : s50[18] = l_18 ^^^ ((~~~ l_19) &&& l_15))
    (h_19 : s50[19] = l_19 ^^^ ((~~~ l_15) &&& l_16))
    (h_20 : s50[20] = l_20 ^^^ ((~~~ l_21) &&& l_22))
    (h_21 : s50[21] = l_21 ^^^ ((~~~ l_22) &&& l_23))
    (h_22 : s50[22] = l_22 ^^^ ((~~~ l_23) &&& l_24))
    (h_23 : s50[23] = l_23 ^^^ ((~~~ l_24) &&& l_20))
    (h_24 : s50[24] = l_24 ^^^ ((~~~ l_20) &&& l_21))
    : Keccak4x.projectLane i s50 =
       chiCore ( { l0 := l_0[i.val], l1 := l_1[i.val], l2 := l_2[i.val], l3 := l_3[i.val], l4 := l_4[i.val], l5 := l_5[i.val], l6 := l_6[i.val], l7 := l_7[i.val], l8 := l_8[i.val], l9 := l_9[i.val], l10 := l_10[i.val], l11 := l_11[i.val], l12 := l_12[i.val], l13 := l_13[i.val], l14 := l_14[i.val], l15 := l_15[i.val], l16 := l_16[i.val], l17 := l_17[i.val], l18 := l_18[i.val], l19 := l_19[i.val], l20 := l_20[i.val], l21 := l_21[i.val], l22 := l_22[i.val], l23 := l_23[i.val], l24 := l_24[i.val] } : Lanes25) := by
  unfold chiCore Keccak4x.projectLane
  apply Lanes25.ext <;> dsimp only
  case h0 => have h := h_0; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h1 => have h := h_1; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h2 => have h := h_2; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h3 => have h := h_3; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h4 => have h := h_4; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h5 => have h := h_5; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h6 => have h := h_6; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h7 => have h := h_7; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h8 => have h := h_8; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h9 => have h := h_9; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h10 => have h := h_10; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h11 => have h := h_11; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h12 => have h := h_12; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h13 => have h := h_13; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h14 => have h := h_14; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h15 => have h := h_15; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h16 => have h := h_16; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h17 => have h := h_17; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h18 => have h := h_18; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h19 => have h := h_19; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h20 => have h := h_20; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h21 => have h := h_21; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h22 => have h := h_22; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h23 => have h := h_23; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h
  case h24 => have h := h_24; apply_fun (fun L : sha3.keccak4x.Lane4 => Keccak4x.projectLane_lane i L) at h; simp only [Keccak4x.projectLane_lane_xor, Keccak4x.projectLane_lane_and, Keccak4x.projectLane_lane_not] at h ⊢; exact h






/-! ## `body_fused.spec` — per-lane projection equals scalar `fusedRoundCore`

  Expressed as a composition of the five phase specs (each phase
  carries an independent `@[step]` post on its per-lane projection).
  `rw [phases_eq]; step*` composes them, putting in scope the per-phase
  results `d0..d4` / `s25` / `l95..l143` / `s50` / `r` and their posts.

  The four algebraic bridge lemmas above (`theta_eq`, `rho_pi_eq`,
  `chi_eq`, plus `phase_iota.spec`) lift each phase post to a `Lanes25`
  identity (`thetaCore` / `piCore ∘ rhoCore` / `chiCore` / iota); they
  are then chained via `fusedCore_eq_composed` (Keccak/Core.lean:307)
  to close the goal at the structure level. -/
@[step]
theorem Keccak4x.permute_loop.body_fused.spec
    (s : Array sha3.keccak4x.Lane4 25#usize) (round : Std.Usize)
    (hround : round.val < 24) :
    Keccak4x.permute_loop.body_fused s round
    ⦃ (r : Array sha3.keccak4x.Lane4 25#usize) =>
        ∀ i : Fin 4,
          Keccak4x.projectLane i r
            = fusedRoundCore (Keccak4x.projectLane i s)
                (KECCAK_IOTA_K.val[round.val]) ⦄ := by
  rw [Keccak4x.permute_loop.body_fused.phases_eq]
  step*
  rename_i i
  -- Bridge 1: theta_eq (whole-Lane4 d posts from phase_theta_d.spec)
  have h_theta := Keccak4x.permute_loop.theta_eq i s s25 d0 d1 d2 d3 d4
    d0_post1 d0_post2 d0_post3 d0_post4 d0_post5 (s25_post i)
  -- Bridge 2: rho_pi_eq (whole-Lane4 rotation posts)
  have h_rho_pi := Keccak4x.permute_loop.rho_pi_eq i s25
    l95 l97 l99 l101 l103 l105 l107 l109 l111 l113 l115 l117 l119 l121 l123 l125 l127 l129 l131 l133 l135 l137 l139 l141 l143
    l95_post1 l95_post2 l95_post3 l95_post4 l95_post5 l95_post6 l95_post7 l95_post8 l95_post9 l95_post10 l95_post11 l95_post12 l95_post13 l95_post14 l95_post15 l95_post16 l95_post17 l95_post18 l95_post19 l95_post20 l95_post21 l95_post22 l95_post23 l95_post24 l95_post25
  -- Bridge 3: chi_eq (whole-Lane4 chi posts)
  have h_chi := Keccak4x.permute_loop.chi_eq i s50
    l95 l97 l99 l101 l103 l105 l107 l109 l111 l113 l115 l117 l119 l121 l123 l125 l127 l129 l131 l133 l135 l137 l139 l141 l143
    s50_post1 s50_post2 s50_post3 s50_post4 s50_post5 s50_post6 s50_post7 s50_post8 s50_post9 s50_post10 s50_post11 s50_post12 s50_post13 s50_post14 s50_post15 s50_post16 s50_post17 s50_post18 s50_post19 s50_post20 s50_post21 s50_post22 s50_post23 s50_post24 s50_post25
  -- Compose: s50 = fusedCore (s)
  have h_compose : Keccak4x.projectLane i s50 = fusedCore (Keccak4x.projectLane i s) := by
    rw [h_chi, h_rho_pi, h_theta, ← fusedCore_eq_composed]
  -- Final: r = fusedRoundCore (s) rc
  rw [r_post i, h_compose]
  rfl

/-! ## `Keccak4x.permute_loop.spec`

  Mirrors the scalar `keccak_permute_opt_loop.spec` shape but per-lane.
  The loop accumulator is the 4-way state; the postcondition asserts
  per-lane that the projected state equals `iterateRndCore` of the
  projected initial state. -/

/-- **Informal proof** (loop spec — `permute_loop` body, `Funs.lean:22585`).
    The body is a 24-round Keccak fixed point per lane: each iteration
    reads 25 `Lane4` values from `s`, performs the `theta` / `rho` /
    `pi` / `chi` / `iota` cascade lane-wise via the
    `Lane4.{xor, andnot, rol, xor_assign}` primitives, and writes back
    25 updated `Lane4` values.  The round constant for round `r` is
    fixed (mirroring the scalar `fusedRoundCore r`).

    **Canonical pattern**: Range loop with state-threaded 4-way
    accumulator + per-lane projection invariant.

    **Loop invariant** (per-iteration form at cursor `iter.start.val`):
    for every lane index `i : Fin 4`,
      `projectLane i s = iterateRndCore (projectLane i A₀) iter.start.val`.

    Mirrors the scalar `keccak_permute_opt_loop.spec` (Properties/
    SHA3/Keccak/Loop.lean:70).  The 4-way version is exactly 4
    *independent* instances of the scalar invariant; `Lane4.xor` /
    `Lane4.andnot` / `Lane4.rol` / `Lane4.xor_assign` lift bit-vector
    operations from `U64 → U64` to `Lane4 → Lane4` componentwise, so
    `projectLane i (Lane4.op a b) = scalar_op (projectLane_lane i a)
    (projectLane_lane i b)`.

    **Lemma chain in call order** (per round):
      1. `IteratorRange.next.spec` — advances cursor.
      2. 25× `Array.index_usize.spec` — read every `s[k]`.
      3. ~110× `Lane4.xor.spec`, `Lane4.andnot.spec`, `Lane4.rol.spec`
         — the theta+rho+pi+chi cascade lane-wise.
      4. 25× `Array.update.spec` — write every `s[k]`.
      5. Recursive IH on `permute_loop iter1 s'`.

    **Spec-side bridges**:
      * `projectLane_xor`, `projectLane_andnot`, `projectLane_rol`,
        `projectLane_xor_assign` — show `projectLane` distributes over
        each `Lane4` primitive, reducing the round to 4 parallel scalar
        `fusedRoundCore` invocations.
      * `iterateRndCore_succ` — extends the
        invariant by one round.

    **Decomposition**: the 755-line unrolled body is a strong
    candidate for `#decompose` into 5 phases (theta, rho-pi, chi, iota,
    round_count update), though the spec below does not require it.

    Discharge: `agrind`. -/
@[step]
theorem Keccak4x.permute_loop.spec
    (iter : core.ops.range.Range Std.Usize)
    (s A₀ : Array sha3.keccak4x.Lane4 25#usize)
    (hEnd : iter.«end».val = 24)
    (hStart : iter.start.val ≤ iter.«end».val)
    (hinv : ∀ i : Fin 4,
      Keccak4x.projectLane i s
        = iterateRndCore (Keccak4x.projectLane i A₀) iter.start.val) :
    sha3.keccak4x.Keccak4x.permute_loop iter s
    ⦃ (r : Array sha3.keccak4x.Lane4 25#usize) =>
        ∀ i : Fin 4,
          Keccak4x.projectLane i r
            = iterateRndCore (Keccak4x.projectLane i A₀) 24 ⦄ := by
  rw [Keccak4x.permute_loop.match_helper_eq]
  by_cases hlt : iter.start.val < iter.«end».val
  · -- some: iterator yields next round index
    let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← IteratorRange_next_some iter hlt
    rw [hsome]
    rw [Keccak4x.permute_loop.match_helper_branch_eq]
    -- Goal: do let a ← body_fused s round; permute_loop iter1 a
    have hround : iter.start.val < 24 := by scalar_tac
    let* ⟨ a, ha_post ⟩ ← Keccak4x.permute_loop.body_fused.spec s iter.start hround
    -- Build refreshed invariant for iter1
    have hend1 : iter1.«end».val = 24 := by rw [hend']; exact hEnd
    have hstart1 : iter1.start.val ≤ iter1.«end».val := by
      rw [hstart', hend']; scalar_tac
    have h2 : iter.start.val + 1 ≤ 24 := by scalar_tac
    have hinv1 : ∀ i : Fin 4,
        Keccak4x.projectLane i a
          = iterateRndCore (Keccak4x.projectLane i A₀) iter1.start.val := by
      intro i
      simp only [hstart']
      rw [iterateRndCore_succ (Keccak4x.projectLane i A₀) iter.start.val h2]
      apply Eq.trans (ha_post i) (congrArg₂ fusedRoundCore (hinv i) rfl)
    apply WP.spec_mono
      (Keccak4x.permute_loop.spec iter1 a A₀ hend1 hstart1 hinv1)
    intro p hp
    exact hp
  · -- none: iterator exhausted
    have hge : iter.start.val ≥ iter.«end».val := by scalar_tac
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← IteratorRange_next_none iter hge
    rw [hnone]
    rw [Keccak4x.permute_loop.match_helper_branch_eq]
    simp only [WP.spec_ok]
    intro i
    have heq : iter.start.val = 24 := by scalar_tac
    simp only [heq] at hinv
    exact hinv i
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/-- **Informal proof** (`Keccak4x.permute` wrapper).
    Body: `let s ← permute_loop {start := 0, end := 24} self.state; ok { state := s }`.
    Single monadic call.

    Lemma chain: `permute_loop.spec` at `iter.start = 0`, `A₀ = self.state`.
    Precondition `hinv` reduces to
    `projectLane i self.state = iterateRndCore (projectLane i self.state) 0`,
    which is `rfl` since `iterateRndCore _ 0 = id`.
    Proof: `unfold permute; step Keccak4x.permute_loop.spec with [A₀ := self.state]; simp`. -/
-- cost: walltime≈5s heartbeats<1M loc=6
@[step]
theorem Keccak4x.permute.spec (self : sha3.keccak4x.Keccak4x) :
    sha3.keccak4x.Keccak4x.permute self
    ⦃ (r : sha3.keccak4x.Keccak4x) =>
        r.state.val.length = 25 ∧
        ∀ i : Fin 4,
          Keccak4x.projectLane i r.state
            = iterateRndCore (Keccak4x.projectLane i self.state) 24 ⦄ := by
  unfold sha3.keccak4x.Keccak4x.permute
  step*
  · exact self.state
  · intro i; rfl
  · exact ⟨s.property, s_post⟩



end symcrust
