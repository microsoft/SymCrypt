import Symcrust.Properties.SHA3.Keccak4x.Permute.Base

namespace symcrust

open Aeneas Aeneas.Std Result
open sha3.sha3_impl
open scoped Spec.Notations

set_option linter.unusedSectionVars false
set_option linter.unusedVariables false

local macro_rules | `(tactic| get_elem_tactic) => `(tactic| first | assumption | (simp only [Aeneas.Std.Array.length_eq, List.length_set]; first | assumption | decide) | scalar_tac | (simp only [Aeneas.Std.Array.length_eq, List.length_set]; scalar_tac))

attribute [local scalar_tac_simps, local agrind =] Lane4_val_length



set_option maxHeartbeats 2000000 in
@[step]
theorem Keccak4x.permute_loop.phase_theta_d.spec
    (s : Array sha3.keccak4x.Lane4 25#usize) :
    Keccak4x.permute_loop.phase_theta_d s
    ⦃ (d0, d1, d2, d3, d4) =>
        d0 = (s[4] ^^^ s[9] ^^^ s[14] ^^^ s[19] ^^^ s[24])
               ^^^ Keccak4x.rotl4 (s[1] ^^^ s[6] ^^^ s[11] ^^^ s[16] ^^^ s[21]) 1#u32 ∧
        d1 = (s[0] ^^^ s[5] ^^^ s[10] ^^^ s[15] ^^^ s[20])
               ^^^ Keccak4x.rotl4 (s[2] ^^^ s[7] ^^^ s[12] ^^^ s[17] ^^^ s[22]) 1#u32 ∧
        d2 = (s[1] ^^^ s[6] ^^^ s[11] ^^^ s[16] ^^^ s[21])
               ^^^ Keccak4x.rotl4 (s[3] ^^^ s[8] ^^^ s[13] ^^^ s[18] ^^^ s[23]) 1#u32 ∧
        d3 = (s[2] ^^^ s[7] ^^^ s[12] ^^^ s[17] ^^^ s[22])
               ^^^ Keccak4x.rotl4 (s[4] ^^^ s[9] ^^^ s[14] ^^^ s[19] ^^^ s[24]) 1#u32 ∧
        d4 = (s[3] ^^^ s[8] ^^^ s[13] ^^^ s[18] ^^^ s[23])
               ^^^ Keccak4x.rotl4 (s[0] ^^^ s[5] ^^^ s[10] ^^^ s[15] ^^^ s[20]) 1#u32 ⦄ := by
  unfold Keccak4x.permute_loop.phase_theta_d
  step*
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · simp only [d0_post, l40_post, c4_post, c1_post, l38_post, l36_post, l34_post,
      l14_post, l12_post, l10_post, l32_post, l33_post, l35_post, l37_post, l39_post,
      l8_post, l9_post, l11_post, l13_post, l15_post]; rfl
  · simp only [d1_post, l41_post, c0_post, c2_post, l6_post, l4_post, l2_post,
      l22_post, l20_post, l18_post, l_post, l1_post, l3_post, l5_post, l7_post,
      l16_post, l17_post, l19_post, l21_post, l23_post]; rfl
  · simp only [d2_post, l42_post, c1_post, c3_post, l14_post, l12_post, l10_post,
      l30_post, l28_post, l26_post, l8_post, l9_post, l11_post, l13_post, l15_post,
      l24_post, l25_post, l27_post, l29_post, l31_post]; rfl
  · simp only [d3_post, l43_post, c2_post, c4_post, l22_post, l20_post, l18_post,
      l38_post, l36_post, l34_post, l16_post, l17_post, l19_post, l21_post, l23_post,
      l32_post, l33_post, l35_post, l37_post, l39_post]; rfl
  · simp only [d4_post, l44_post, c3_post, c0_post, l30_post, l28_post, l26_post,
      l6_post, l4_post, l2_post, l24_post, l25_post, l27_post, l29_post, l31_post,
      l_post, l1_post, l3_post, l5_post, l7_post]; rfl

/-! ### `phase_iota.spec` — single-state mutation: XOR round constant into lane 0

  Smallest of the 5 phase specs (5 monadic bindings, single state mutation).
  Mirrors scalar `fusedRoundCore`'s iota step `{ s with l0 := s.l0 ^^^ rc }`. -/

@[step]
theorem Keccak4x.permute_loop.phase_iota.spec
    (round : Std.Usize) (s : Array sha3.keccak4x.Lane4 25#usize)
    (hround : round.val < 24) :
    Keccak4x.permute_loop.phase_iota round s
    ⦃ (r : Array sha3.keccak4x.Lane4 25#usize) =>
        ∀ i : Fin 4,
          Keccak4x.projectLane i r
            = { Keccak4x.projectLane i s with
                  l0 := (Keccak4x.projectLane i s).l0
                          ^^^ KECCAK_IOTA_K.val[round.val] } ⦄ := by
  unfold Keccak4x.permute_loop.phase_iota
  step*
  intro i
  unfold Keccak4x.projectLane
  simp_lists [l261_post, l260_post2, l259_post1, l259_post2, i20_post,
    Keccak4x.getElem_xor, Std.Array.set]





/-! ### `phase_theta_apply_row_*.spec` — XOR column-differences into row k

  Each row spec writes 5 lanes (positions `5k..5k+4`) of `s`, XORing in
  `d0..d4` respectively.  Same skeleton as `phase_iota.spec`, scaled to
  5 successive `index_mut + xor_assign + index_mut_back` triples per row. -/

set_option maxHeartbeats 2000000 in
@[step]
theorem Keccak4x.permute_loop.phase_theta_apply_row_0.spec
    (s : Array sha3.keccak4x.Lane4 25#usize)
    (d0 d1 d2 d3 d4 : sha3.keccak4x.Lane4)
    :
    Keccak4x.permute_loop.phase_theta_apply_row_0 s d0 d1 d2 d3 d4
    ⦃ (r : Array sha3.keccak4x.Lane4 25#usize) =>
        ∀ i : Fin 4,
          Keccak4x.projectLane i r
            = { Keccak4x.projectLane i s with
                  l0 := (Keccak4x.projectLane i s).l0 ^^^ d0[i.val]
                  l1 := (Keccak4x.projectLane i s).l1 ^^^ d1[i.val]
                  l2 := (Keccak4x.projectLane i s).l2 ^^^ d2[i.val]
                  l3 := (Keccak4x.projectLane i s).l3 ^^^ d3[i.val]
                  l4 := (Keccak4x.projectLane i s).l4 ^^^ d4[i.val] } ⦄ := by
  unfold Keccak4x.permute_loop.phase_theta_apply_row_0
  step*
  intro i
  unfold Keccak4x.projectLane
  simp_lists [l54_post, l52_post, l50_post, l48_post, l46_post,
    l53_post1, l51_post1, l49_post1, l47_post1, l45_post1,
    l53_post2, l51_post2, l49_post2, l47_post2, l45_post2,
    Keccak4x.getElem_xor, Std.Array.set]




set_option maxHeartbeats 2000000 in
@[step]
theorem Keccak4x.permute_loop.phase_theta_apply_row_1.spec
    (d0 d1 d2 d3 d4 : sha3.keccak4x.Lane4)
    (s : Array sha3.keccak4x.Lane4 25#usize)
    :
    Keccak4x.permute_loop.phase_theta_apply_row_1 d0 d1 d2 d3 d4 s
    ⦃ (r : Array sha3.keccak4x.Lane4 25#usize) =>
        ∀ i : Fin 4,
          Keccak4x.projectLane i r
            = { Keccak4x.projectLane i s with
                  l5 := (Keccak4x.projectLane i s).l5 ^^^ d0[i.val]
                  l6 := (Keccak4x.projectLane i s).l6 ^^^ d1[i.val]
                  l7 := (Keccak4x.projectLane i s).l7 ^^^ d2[i.val]
                  l8 := (Keccak4x.projectLane i s).l8 ^^^ d3[i.val]
                  l9 := (Keccak4x.projectLane i s).l9 ^^^ d4[i.val] } ⦄ := by
  unfold Keccak4x.permute_loop.phase_theta_apply_row_1
  step*
  intro i
  unfold Keccak4x.projectLane
  simp_lists [l64_post, l62_post, l60_post, l58_post, l56_post,
    l63_post1, l61_post1, l59_post1, l57_post1, l55_post1,
    l63_post2, l61_post2, l59_post2, l57_post2, l55_post2, Keccak4x.getElem_xor, Std.Array.set]


set_option maxHeartbeats 2000000 in
@[step]
theorem Keccak4x.permute_loop.phase_theta_apply_row_2.spec
    (d0 d1 d2 d3 d4 : sha3.keccak4x.Lane4)
    (s : Array sha3.keccak4x.Lane4 25#usize)
    :
    Keccak4x.permute_loop.phase_theta_apply_row_2 d0 d1 d2 d3 d4 s
    ⦃ (r : Array sha3.keccak4x.Lane4 25#usize) =>
        ∀ i : Fin 4,
          Keccak4x.projectLane i r
            = { Keccak4x.projectLane i s with
                  l10 := (Keccak4x.projectLane i s).l10 ^^^ d0[i.val]
                  l11 := (Keccak4x.projectLane i s).l11 ^^^ d1[i.val]
                  l12 := (Keccak4x.projectLane i s).l12 ^^^ d2[i.val]
                  l13 := (Keccak4x.projectLane i s).l13 ^^^ d3[i.val]
                  l14 := (Keccak4x.projectLane i s).l14 ^^^ d4[i.val] } ⦄ := by
  unfold Keccak4x.permute_loop.phase_theta_apply_row_2
  step*
  intro i
  unfold Keccak4x.projectLane
  simp_lists [l74_post, l72_post, l70_post, l68_post, l66_post,
    l73_post1, l71_post1, l69_post1, l67_post1, l65_post1,
    l73_post2, l71_post2, l69_post2, l67_post2, l65_post2, Keccak4x.getElem_xor, Std.Array.set]


set_option maxHeartbeats 2000000 in
@[step]
theorem Keccak4x.permute_loop.phase_theta_apply_row_3.spec
    (d0 d1 d2 d3 d4 : sha3.keccak4x.Lane4)
    (s : Array sha3.keccak4x.Lane4 25#usize)
    :
    Keccak4x.permute_loop.phase_theta_apply_row_3 d0 d1 d2 d3 d4 s
    ⦃ (r : Array sha3.keccak4x.Lane4 25#usize) =>
        ∀ i : Fin 4,
          Keccak4x.projectLane i r
            = { Keccak4x.projectLane i s with
                  l15 := (Keccak4x.projectLane i s).l15 ^^^ d0[i.val]
                  l16 := (Keccak4x.projectLane i s).l16 ^^^ d1[i.val]
                  l17 := (Keccak4x.projectLane i s).l17 ^^^ d2[i.val]
                  l18 := (Keccak4x.projectLane i s).l18 ^^^ d3[i.val]
                  l19 := (Keccak4x.projectLane i s).l19 ^^^ d4[i.val] } ⦄ := by
  unfold Keccak4x.permute_loop.phase_theta_apply_row_3
  step*
  intro i
  unfold Keccak4x.projectLane
  simp_lists [l84_post, l82_post, l80_post, l78_post, l76_post,
    l83_post1, l81_post1, l79_post1, l77_post1, l75_post1,
    l83_post2, l81_post2, l79_post2, l77_post2, l75_post2, Keccak4x.getElem_xor, Std.Array.set]


set_option maxHeartbeats 2000000 in
@[step]
theorem Keccak4x.permute_loop.phase_theta_apply_row_4.spec
    (d0 d1 d2 d3 d4 : sha3.keccak4x.Lane4)
    (s : Array sha3.keccak4x.Lane4 25#usize)
    :
    Keccak4x.permute_loop.phase_theta_apply_row_4 d0 d1 d2 d3 d4 s
    ⦃ (r : Array sha3.keccak4x.Lane4 25#usize) =>
        ∀ i : Fin 4,
          Keccak4x.projectLane i r
            = { Keccak4x.projectLane i s with
                  l20 := (Keccak4x.projectLane i s).l20 ^^^ d0[i.val]
                  l21 := (Keccak4x.projectLane i s).l21 ^^^ d1[i.val]
                  l22 := (Keccak4x.projectLane i s).l22 ^^^ d2[i.val]
                  l23 := (Keccak4x.projectLane i s).l23 ^^^ d3[i.val]
                  l24 := (Keccak4x.projectLane i s).l24 ^^^ d4[i.val] } ⦄ := by
  unfold Keccak4x.permute_loop.phase_theta_apply_row_4
  step*
  intro i
  unfold Keccak4x.projectLane
  simp_lists [l94_post, l92_post, l90_post, l88_post, l86_post,
    l93_post1, l91_post1, l89_post1, l87_post1, l85_post1,
    l93_post2, l91_post2, l89_post2, l87_post2, l85_post2, Keccak4x.getElem_xor, Std.Array.set]


/-! ### `phase_theta_apply.spec` — composes the 5 row specs

  Cumulative post: every lane li (i = 0..24) of the output projection is
  `(projectLane i s).li ^^^ d_{i mod 5}[i.val]`.  Proof is one-line:
  `rw [phase_theta_apply.rows_eq]; step*` lets the row-spec engine
  assemble all 5 modifications. -/

set_option maxHeartbeats 2000000 in
@[step]
theorem Keccak4x.permute_loop.phase_theta_apply.spec
    (s : Array sha3.keccak4x.Lane4 25#usize)
    (d0 d1 d2 d3 d4 : sha3.keccak4x.Lane4)
    :
    Keccak4x.permute_loop.phase_theta_apply s d0 d1 d2 d3 d4
    ⦃ (r : Array sha3.keccak4x.Lane4 25#usize) =>
        ∀ i : Fin 4,
          Keccak4x.projectLane i r
            = { l0 := (Keccak4x.projectLane i s).l0 ^^^ d0[i.val],
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
                l24 := (Keccak4x.projectLane i s).l24 ^^^ d4[i.val] } ⦄ := by
  rw [Keccak4x.permute_loop.phase_theta_apply.rows_eq]
  step*




/-! ### `phase_rho_pi.spec` — ρπ rotation+permutation: 25-tuple output

  Reads 25 lanes from `s` in the Keccak ρπ-permuted order and rotates
  each by the FIPS-202 ρ offset.  Mirrors scalar `rhoCore ∘ piCore`
  (Keccak/Core.lean:122-135).  Output is a 25-tuple of `Lane4`; per-lane
  post pins each output's `.val[k].bv` to
  `(s.val[piMap[n]]).val[k].bv.rotateLeft rhoOffset[n]`.

  Position 0 has no rotation (`l95 = s.index_usize 0`, no rol); positions
  1..24 are `l(2n+95) = (s.index_usize piMap[n]).rol rhoOffset[n]`.

  Proof: `unfold; step*; simp_lists [<24 rol posts>, <25 read posts>]` — one
  `simp_lists` closes the whole 25-conjunction (it descends under `∧`/`∀`). -/
set_option maxHeartbeats 2000000 in
@[step]
theorem Keccak4x.permute_loop.phase_rho_pi.spec
    (s : Array sha3.keccak4x.Lane4 25#usize)
    :
    Keccak4x.permute_loop.phase_rho_pi s
    ⦃ (o0, o1, o2, o3, o4, o5, o6, o7, o8, o9, o10, o11, o12, o13, o14, o15, o16, o17, o18, o19,
       o20, o21, o22, o23, o24) =>
        o0 = s[0] ∧
        o1 = Keccak4x.rotl4 s[6] 44#u32 ∧
        o2 = Keccak4x.rotl4 s[12] 43#u32 ∧
        o3 = Keccak4x.rotl4 s[18] 21#u32 ∧
        o4 = Keccak4x.rotl4 s[24] 14#u32 ∧
        o5 = Keccak4x.rotl4 s[3] 28#u32 ∧
        o6 = Keccak4x.rotl4 s[9] 20#u32 ∧
        o7 = Keccak4x.rotl4 s[10] 3#u32 ∧
        o8 = Keccak4x.rotl4 s[16] 45#u32 ∧
        o9 = Keccak4x.rotl4 s[22] 61#u32 ∧
        o10 = Keccak4x.rotl4 s[1] 1#u32 ∧
        o11 = Keccak4x.rotl4 s[7] 6#u32 ∧
        o12 = Keccak4x.rotl4 s[13] 25#u32 ∧
        o13 = Keccak4x.rotl4 s[19] 8#u32 ∧
        o14 = Keccak4x.rotl4 s[20] 18#u32 ∧
        o15 = Keccak4x.rotl4 s[4] 27#u32 ∧
        o16 = Keccak4x.rotl4 s[5] 36#u32 ∧
        o17 = Keccak4x.rotl4 s[11] 10#u32 ∧
        o18 = Keccak4x.rotl4 s[17] 15#u32 ∧
        o19 = Keccak4x.rotl4 s[23] 56#u32 ∧
        o20 = Keccak4x.rotl4 s[2] 62#u32 ∧
        o21 = Keccak4x.rotl4 s[8] 55#u32 ∧
        o22 = Keccak4x.rotl4 s[14] 39#u32 ∧
        o23 = Keccak4x.rotl4 s[15] 41#u32 ∧
        o24 = Keccak4x.rotl4 s[21] 2#u32 ⦄ := by
  unfold Keccak4x.permute_loop.phase_rho_pi
  step*
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · simp only [l95_post]; rfl
  · simp only [l97_post, l96_post]; rfl
  · simp only [l99_post, l98_post]; rfl
  · simp only [l101_post, l100_post]; rfl
  · simp only [l103_post, l102_post]; rfl
  · simp only [l105_post, l104_post]; rfl
  · simp only [l107_post, l106_post]; rfl
  · simp only [l109_post, l108_post]; rfl
  · simp only [l111_post, l110_post]; rfl
  · simp only [l113_post, l112_post]; rfl
  · simp only [l115_post, l114_post]; rfl
  · simp only [l117_post, l116_post]; rfl
  · simp only [l119_post, l118_post]; rfl
  · simp only [l121_post, l120_post]; rfl
  · simp only [l123_post, l122_post]; rfl
  · simp only [l125_post, l124_post]; rfl
  · simp only [l127_post, l126_post]; rfl
  · simp only [l129_post, l128_post]; rfl
  · simp only [l131_post, l130_post]; rfl
  · simp only [l133_post, l132_post]; rfl
  · simp only [l135_post, l134_post]; rfl
  · simp only [l137_post, l136_post]; rfl
  · simp only [l139_post, l138_post]; rfl
  · simp only [l141_post, l140_post]; rfl
  · simp only [l143_post, l142_post]; rfl

end symcrust
