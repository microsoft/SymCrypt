import Symcrust.Properties.SHA3.Basic
import Symcrust.Properties.Axioms.Wipe
import Symcrust.Properties.SHA3.Sponge.Bridge

open Aeneas Aeneas.Std

namespace symcrust.sha3.sha3_impl

@[step]
theorem KeccakState.reset.spec
    (self : KeccakState)
    (h_rate : 0 < self.input_block_size.val ∧
              8 * self.input_block_size.val < Spec.SHA3.b ∧
              self.input_block_size.val % 8 = 0) :
    KeccakState.reset self
    ⦃ (result : KeccakState) =>
      absorbing result (.init self.input_block_size.val self.padding_value h_rate) ∧
      result.state_index.val = 0 ⦄ := by
  unfold KeccakState.reset
  -- The post of `Array.to_slice_mut_spec` is curried: it introduces
  -- the slice `s`, the back-closure `back`, and the two equalities directly.
  step as ⟨s, back, hsval, hback⟩
  step as ⟨s1, s1_post1, s1_post2⟩  -- wipe_slice
  refine ⟨?_, by rfl⟩
  simp only [absorbing, absorbingWeak, GhostState.init]
  -- Bridge: back s1 has all-zero lanes → toBits = Vector.replicate b false.
  have hbacklen : s1.val.length = (25#usize).val := by scalar_tac
  have hbackval : (back s1).val = s1.val := by
    rw [hback]; exact Aeneas.Std.Array.from_slice_val self.state s1 hbacklen
  -- Each lane of `back s1` is zero, by
  -- `s1_post2 : ∀ i, (h : i < s1.length) → s1[i] = default`.
  have hzeroLanes : ∀ i : Fin 25, (back s1)[i] = 0#u64 := by
    intro i
    have hlt : i.val < s1.length := by simp [Aeneas.Std.Slice.length, hbacklen]
    have h_s1_val_len : i.val < s1.val.length := by
      simp only [Aeneas.Std.Slice.length] at hlt; exact hlt
    have hi_bound : s1.val[i.val]'h_s1_val_len = (default : U64) := s1_post2 i.val hlt
    have hi : s1.val[i.val]! = (default : U64) := by
      rw [getElem!_pos s1.val i.val h_s1_val_len]; exact hi_bound
    have hibackval : (back s1).val[i.val]! = 0#u64 := by
      rw [hbackval, hi]; rfl
    have hi25 : i.val < (back s1).val.length := by
      simp [hbackval]; rw [Aeneas.Std.Slice.length] at hlt; exact hlt
    rw [show ((back s1)[i] : U64) = (back s1).val[i.val]! from by
          rw [getElem!_pos (back s1).val i.val hi25]; rfl]
    exact hibackval
  have hbits := toBits_allZero (back s1) hzeroLanes
  split_conjs
  all_goals first
    | agrind
    | -- The FC clause is (the last) spongeInvariant goal.
      agrind [spongeInvariant, absorbBytes]


@[step]
theorem KeccakState.init.spec
    (self : KeccakState)
    (input_block_size : U32) (padding_value : U8)
    (h_rate : 0 < input_block_size.val ∧
              8 * input_block_size.val < Spec.SHA3.b ∧
              input_block_size.val % 8 = 0) :
    KeccakState.init self input_block_size padding_value
    ⦃ (result : KeccakState) =>
      absorbing result (.init input_block_size.val padding_value h_rate) ∧
      result.state_index.val = 0 ⦄ := by
  unfold KeccakState.init
  step*

/-- `KeccakState::default` returns an arbitrary KeccakState; the spec only
    asserts `True` so that callers can chain it with `init` (which is what
    actually establishes the algebraic invariant). -/
@[step]
theorem KeccakState.default.spec :
    KeccakState.Insts.CoreDefaultDefault.default
    ⦃ (_ : KeccakState) => True ⦄ := by
  trivial

end symcrust.sha3.sha3_impl
