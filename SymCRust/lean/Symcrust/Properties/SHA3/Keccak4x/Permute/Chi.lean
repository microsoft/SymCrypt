import Symcrust.Properties.SHA3.Keccak4x.Permute.Base

namespace symcrust

open Aeneas Aeneas.Std Result
open sha3.sha3_impl
open scoped Spec.Notations

set_option linter.unusedSectionVars false
set_option linter.unusedVariables false

local macro_rules | `(tactic| get_elem_tactic) => `(tactic| first | assumption | (simp only [Aeneas.Std.Array.length_eq, List.length_set]; first | assumption | decide) | scalar_tac | (simp only [Aeneas.Std.Array.length_eq, List.length_set]; scalar_tac))

attribute [local scalar_tac_simps, local agrind =] Lane4_val_length



/-! ### `phase_chi_row_0.spec` — chi applied to lanes [0..4]

  Reads input lanes 0..4 from the inline `Array.make 25 [l95..l143]`
  (i.e. `l95, l97, l99, l101, l103`) and writes 5 chi'd lanes back to
  positions 0..4 of `s25`.  For position p ∈ {0..4} with input lanes
  `(a, b, c, d, e) = (l95, l97, l99, l101, l103)`:
    `out[p].val[k] = lanes[p][k] ^^^ ((¬lanes[(p+1)%5][k]) &&& lanes[(p+2)%5][k])`
  Frame: positions 5..24 of `out` equal positions 5..24 of `s25`.

  Proof template: per-conjunct, unfold `out_post..s2{6..9}_post`,
  `simp only [Std.Array.set]`, `simp_lists` to reduce the chained
  `set`-then-read to the right `l{N}`, then chain the
  `xor.spec`/`andnot.spec`/`index_usize.spec` rewrites and reduce the
  `Array.make 25 [...]` index access with `simp [Std.Array.make]`. -/
set_option maxHeartbeats 2000000 in
@[step]
theorem Keccak4x.permute_loop.phase_chi_row_0.spec
    (s25 : Array sha3.keccak4x.Lane4 25#usize)
    (l95 l97 l99 l101 l103 l105 l107 l109 l111 l113 l115 l117 l119 l121
     l123 l125 l127 l129 l131 l133 l135 l137 l139 l141 l143 : sha3.keccak4x.Lane4)
    :
    Keccak4x.permute_loop.phase_chi_row_0 s25 l95 l97 l99 l101 l103 l105 l107 l109 l111 l113 l115
      l117 l119 l121 l123 l125 l127 l129 l131 l133 l135 l137 l139 l141 l143
    ⦃ (out : Array sha3.keccak4x.Lane4 25#usize) =>
        out[0] = l95 ^^^ ((~~~ l97) &&& l99) ∧
        out[1] = l97 ^^^ ((~~~ l99) &&& l101) ∧
        out[2] = l99 ^^^ ((~~~ l101) &&& l103) ∧
        out[3] = l101 ^^^ ((~~~ l103) &&& l95) ∧
        out[4] = l103 ^^^ ((~~~ l95) &&& l97) ∧
        (∀ k, (hk : 5 ≤ k ∧ k < 25) →
          out[k] = s25[k]) ⦄ := by
  unfold Keccak4x.permute_loop.phase_chi_row_0
  step*
  have hi : i.val = 1 := by simp [i_post, b_post]
  have hi1 : i1.val = 2 := by simp [i1_post, b_post]
  have hi2 : i2.val = 3 := by simp [i2_post, b_post]
  have hi3 : i3.val = 4 := by simp [i3_post, b_post]
  have hb : b.val = 0 := by simp [b_post]
  simp_lists [out_post, s29_post, s28_post, s27_post, s26_post,
    l148_post, l147_post, l153_post, l152_post, l158_post, l157_post,
    l162_post, l161_post, l166_post, l165_post,
    l144_post, l145_post, l146_post, l149_post, l150_post, l151_post,
    l154_post, l155_post, l156_post, l159_post, l160_post, l163_post, l164_post,
    hi, hi1, hi2, hi3, hb, Std.Array.set, Std.Array.make]
  simp


/-! ### `phase_chi_row_1.spec` — chi applied to lanes [5..9]

  Mirrors `phase_chi_row_0.spec`; offsets shifted by `5 * 1`,
  input lanes are `(l105, l107, l109, l111, l113)`. -/
set_option maxHeartbeats 2000000 in
@[step]
theorem Keccak4x.permute_loop.phase_chi_row_1.spec
    (l95 l97 l99 l101 l103 l105 l107 l109 l111 l113 l115 l117 l119 l121
     l123 l125 l127 l129 l131 l133 l135 l137 l139 l141 l143 : sha3.keccak4x.Lane4)
    (s30 : Array sha3.keccak4x.Lane4 25#usize)
    :
    Keccak4x.permute_loop.phase_chi_row_1 l95 l97 l99 l101 l103 l105 l107 l109 l111 l113 l115
      l117 l119 l121 l123 l125 l127 l129 l131 l133 l135 l137 l139 l141 l143 s30
    ⦃ (out : Array sha3.keccak4x.Lane4 25#usize) =>
        out[5] = l105 ^^^ ((~~~ l107) &&& l109) ∧
        out[6] = l107 ^^^ ((~~~ l109) &&& l111) ∧
        out[7] = l109 ^^^ ((~~~ l111) &&& l113) ∧
        out[8] = l111 ^^^ ((~~~ l113) &&& l105) ∧
        out[9] = l113 ^^^ ((~~~ l105) &&& l107) ∧
        (∀ k, (hk : k < 5 ∨ (10 ≤ k ∧ k < 25)) →
          out[k] = s30[k]) ⦄ := by

  unfold Keccak4x.permute_loop.phase_chi_row_1
  step*
  have hb1 : b1.val = 5 := by simp [b1_post]
  have hi4 : i4.val = 6 := by simp [i4_post, b1_post]
  have hi5 : i5.val = 7 := by simp [i5_post, b1_post]
  have hi6 : i6.val = 8 := by simp [i6_post, b1_post]
  have hi7 : i7.val = 9 := by simp [i7_post, b1_post]
  simp_lists [out_post, s34_post, s33_post, s32_post, s31_post, l171_post, l170_post, l176_post, l175_post, l181_post, l180_post, l185_post, l184_post, l189_post, l188_post, l167_post, l168_post, l169_post, l172_post, l173_post, l174_post, l177_post, l178_post, l179_post, l182_post, l183_post, l186_post, l187_post, hb1, hi4, hi5, hi6, hi7, Std.Array.set, Std.Array.make]
  simp

/-! ### `phase_chi_row_2.spec` — chi applied to lanes [10..14]

  Mirrors `phase_chi_row_0.spec`; offsets shifted by `5 * 2`,
  input lanes are `(l115, l117, l119, l121, l123)`. -/
set_option maxHeartbeats 2000000 in
@[step]
theorem Keccak4x.permute_loop.phase_chi_row_2.spec
    (l95 l97 l99 l101 l103 l105 l107 l109 l111 l113 l115 l117 l119 l121
     l123 l125 l127 l129 l131 l133 l135 l137 l139 l141 l143 : sha3.keccak4x.Lane4)
    (s35 : Array sha3.keccak4x.Lane4 25#usize)
    :
    Keccak4x.permute_loop.phase_chi_row_2 l95 l97 l99 l101 l103 l105 l107 l109 l111 l113 l115
      l117 l119 l121 l123 l125 l127 l129 l131 l133 l135 l137 l139 l141 l143 s35
    ⦃ (out : Array sha3.keccak4x.Lane4 25#usize) =>
        out[10] = l115 ^^^ ((~~~ l117) &&& l119) ∧
        out[11] = l117 ^^^ ((~~~ l119) &&& l121) ∧
        out[12] = l119 ^^^ ((~~~ l121) &&& l123) ∧
        out[13] = l121 ^^^ ((~~~ l123) &&& l115) ∧
        out[14] = l123 ^^^ ((~~~ l115) &&& l117) ∧
        (∀ k, (hk : k < 10 ∨ (15 ≤ k ∧ k < 25)) →
          out[k] = s35[k]) ⦄ := by

  unfold Keccak4x.permute_loop.phase_chi_row_2
  step*
  have hb2 : b2.val = 10 := by simp [b2_post]
  have hi8 : i8.val = 11 := by simp [i8_post, b2_post]
  have hi9 : i9.val = 12 := by simp [i9_post, b2_post]
  have hi10 : i10.val = 13 := by simp [i10_post, b2_post]
  have hi11 : i11.val = 14 := by simp [i11_post, b2_post]
  simp_lists [out_post, s39_post, s38_post, s37_post, s36_post, l194_post, l193_post, l199_post, l198_post, l204_post, l203_post, l208_post, l207_post, l212_post, l211_post, l190_post, l191_post, l192_post, l195_post, l196_post, l197_post, l200_post, l201_post, l202_post, l205_post, l206_post, l209_post, l210_post, hb2, hi8, hi9, hi10, hi11, Std.Array.set, Std.Array.make]
  simp

/-! ### `phase_chi_row_3.spec` — chi applied to lanes [15..19]

  Mirrors `phase_chi_row_0.spec`; offsets shifted by `5 * 3`,
  input lanes are `(l125, l127, l129, l131, l133)`. -/
set_option maxHeartbeats 2000000 in
@[step]
theorem Keccak4x.permute_loop.phase_chi_row_3.spec
    (l95 l97 l99 l101 l103 l105 l107 l109 l111 l113 l115 l117 l119 l121
     l123 l125 l127 l129 l131 l133 l135 l137 l139 l141 l143 : sha3.keccak4x.Lane4)
    (s40 : Array sha3.keccak4x.Lane4 25#usize)
    :
    Keccak4x.permute_loop.phase_chi_row_3 l95 l97 l99 l101 l103 l105 l107 l109 l111 l113 l115
      l117 l119 l121 l123 l125 l127 l129 l131 l133 l135 l137 l139 l141 l143 s40
    ⦃ (out : Array sha3.keccak4x.Lane4 25#usize) =>
        out[15] = l125 ^^^ ((~~~ l127) &&& l129) ∧
        out[16] = l127 ^^^ ((~~~ l129) &&& l131) ∧
        out[17] = l129 ^^^ ((~~~ l131) &&& l133) ∧
        out[18] = l131 ^^^ ((~~~ l133) &&& l125) ∧
        out[19] = l133 ^^^ ((~~~ l125) &&& l127) ∧
        (∀ k, (hk : k < 15 ∨ (20 ≤ k ∧ k < 25)) →
          out[k] = s40[k]) ⦄ := by

  unfold Keccak4x.permute_loop.phase_chi_row_3
  step*
  have hb3 : b3.val = 15 := by simp [b3_post]
  have hi12 : i12.val = 16 := by simp [i12_post, b3_post]
  have hi13 : i13.val = 17 := by simp [i13_post, b3_post]
  have hi14 : i14.val = 18 := by simp [i14_post, b3_post]
  have hi15 : i15.val = 19 := by simp [i15_post, b3_post]
  simp_lists [out_post, s44_post, s43_post, s42_post, s41_post, l217_post, l216_post, l222_post, l221_post, l227_post, l226_post, l231_post, l230_post, l235_post, l234_post, l213_post, l214_post, l215_post, l218_post, l219_post, l220_post, l223_post, l224_post, l225_post, l228_post, l229_post, l232_post, l233_post, hb3, hi12, hi13, hi14, hi15, Std.Array.set, Std.Array.make]
  simp

/-! ### `phase_chi_row_4.spec` — chi applied to lanes [20..24]

  Mirrors `phase_chi_row_0.spec`; offsets shifted by `5 * 4`,
  input lanes are `(l135, l137, l139, l141, l143)`. -/
set_option maxHeartbeats 2000000 in
@[step]
theorem Keccak4x.permute_loop.phase_chi_row_4.spec
    (l95 l97 l99 l101 l103 l105 l107 l109 l111 l113 l115 l117 l119 l121
     l123 l125 l127 l129 l131 l133 l135 l137 l139 l141 l143 : sha3.keccak4x.Lane4)
    (s45 : Array sha3.keccak4x.Lane4 25#usize)
    :
    Keccak4x.permute_loop.phase_chi_row_4 l95 l97 l99 l101 l103 l105 l107 l109 l111 l113 l115
      l117 l119 l121 l123 l125 l127 l129 l131 l133 l135 l137 l139 l141 l143 s45
    ⦃ (out : Array sha3.keccak4x.Lane4 25#usize) =>
        out[20] = l135 ^^^ ((~~~ l137) &&& l139) ∧
        out[21] = l137 ^^^ ((~~~ l139) &&& l141) ∧
        out[22] = l139 ^^^ ((~~~ l141) &&& l143) ∧
        out[23] = l141 ^^^ ((~~~ l143) &&& l135) ∧
        out[24] = l143 ^^^ ((~~~ l135) &&& l137) ∧
        (∀ k, (hk : k < 20) →
          out[k] = s45[k]) ⦄ := by

  unfold Keccak4x.permute_loop.phase_chi_row_4
  step*
  have hb4 : b4.val = 20 := by simp [b4_post]
  have hi16 : i16.val = 21 := by simp [i16_post, b4_post]
  have hi17 : i17.val = 22 := by simp [i17_post, b4_post]
  have hi18 : i18.val = 23 := by simp [i18_post, b4_post]
  have hi19 : i19.val = 24 := by simp [i19_post, b4_post]
  simp_lists [out_post, s49_post, s48_post, s47_post, s46_post, l240_post, l239_post, l245_post, l244_post, l250_post, l249_post, l254_post, l253_post, l258_post, l257_post, l236_post, l237_post, l238_post, l241_post, l242_post, l243_post, l246_post, l247_post, l248_post, l251_post, l252_post, l255_post, l256_post, hb4, hi16, hi17, hi18, hi19, Std.Array.set, Std.Array.make]
  simp


/-! ### `phase_chi.spec` — composition of all 5 chi rows

  After applying chi to all 25 lanes, the output at position `p = 5r + j`
  satisfies the standard chi identity in terms of the input lanes:
    `out[p][k] = lanes[p][k] ^ ((¬lanes[5r+(j+1)%5][k]) ∧ lanes[5r+(j+2)%5][k])`
  where `lanes` is the inline `Array.make 25 [l95..l143]`.
  Proof: `rw [phase_chi.rows_eq]; step*` lets the 5 row specs assemble
  the chain s25 → s30 → s35 → s40 → s45 → out.  Each per-position
  conjunct is then established by tracing through the appropriate row's
  bv-equality and the subsequent rows' frame conjuncts. -/
set_option maxHeartbeats 2000000 in
@[step]
theorem Keccak4x.permute_loop.phase_chi.spec
    (s25 : Array sha3.keccak4x.Lane4 25#usize)
    (l95 l97 l99 l101 l103 l105 l107 l109 l111 l113 l115 l117 l119 l121
     l123 l125 l127 l129 l131 l133 l135 l137 l139 l141 l143 : sha3.keccak4x.Lane4)
    :
    Keccak4x.permute_loop.phase_chi s25 l95 l97 l99 l101 l103 l105 l107 l109 l111 l113 l115
      l117 l119 l121 l123 l125 l127 l129 l131 l133 l135 l137 l139 l141 l143
    ⦃ (out : Array sha3.keccak4x.Lane4 25#usize) =>
        out[0] = l95 ^^^ ((~~~ l97) &&& l99) ∧
        out[1] = l97 ^^^ ((~~~ l99) &&& l101) ∧
        out[2] = l99 ^^^ ((~~~ l101) &&& l103) ∧
        out[3] = l101 ^^^ ((~~~ l103) &&& l95) ∧
        out[4] = l103 ^^^ ((~~~ l95) &&& l97) ∧
        out[5] = l105 ^^^ ((~~~ l107) &&& l109) ∧
        out[6] = l107 ^^^ ((~~~ l109) &&& l111) ∧
        out[7] = l109 ^^^ ((~~~ l111) &&& l113) ∧
        out[8] = l111 ^^^ ((~~~ l113) &&& l105) ∧
        out[9] = l113 ^^^ ((~~~ l105) &&& l107) ∧
        out[10] = l115 ^^^ ((~~~ l117) &&& l119) ∧
        out[11] = l117 ^^^ ((~~~ l119) &&& l121) ∧
        out[12] = l119 ^^^ ((~~~ l121) &&& l123) ∧
        out[13] = l121 ^^^ ((~~~ l123) &&& l115) ∧
        out[14] = l123 ^^^ ((~~~ l115) &&& l117) ∧
        out[15] = l125 ^^^ ((~~~ l127) &&& l129) ∧
        out[16] = l127 ^^^ ((~~~ l129) &&& l131) ∧
        out[17] = l129 ^^^ ((~~~ l131) &&& l133) ∧
        out[18] = l131 ^^^ ((~~~ l133) &&& l125) ∧
        out[19] = l133 ^^^ ((~~~ l125) &&& l127) ∧
        out[20] = l135 ^^^ ((~~~ l137) &&& l139) ∧
        out[21] = l137 ^^^ ((~~~ l139) &&& l141) ∧
        out[22] = l139 ^^^ ((~~~ l141) &&& l143) ∧
        out[23] = l141 ^^^ ((~~~ l143) &&& l135) ∧
        out[24] = l143 ^^^ ((~~~ l135) &&& l137) ⦄ := by
  rw [Keccak4x.permute_loop.phase_chi.rows_eq]
  step*
  agrind

end symcrust
