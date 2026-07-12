import Symcrust.Properties.SHA3.Keccak.Loop
import Symcrust.Properties.SHA3.Keccak.Textbook
import Symcrust.Properties.SHA3.Sponge.Bridge

/-!
# SHA-3 Verification — Sponge Padding
-/

open Aeneas Aeneas.Std
namespace symcrust.sha3.sha3_impl

open Spec

@[agrind =] private theorem U64_NUM_BYTES_val : U64_NUM_BYTES.val = 8 := by native_decide

set_option maxHeartbeats 400000 in
@[step]
theorem KeccakState.apply_padding.spec
    (self : KeccakState) (g : GhostState)
    (h : absorbing self g)
    (hroom : self.state_index.val < self.input_block_size.val) :
    KeccakState.apply_padding self
    ⦃ (result : KeccakState) =>
      squeezing result g ⦄ := by
  -- Unpack the absorbing precondition.
  have hgrpos : 0 < g.rate := g.h_rate.1
  have hgrmod : g.rate % 8 = 0 := g.h_rate.2.2
  have hgrlt : 8 * g.rate < SHA3.b := g.h_rate.2.1
  have hgr : self.input_block_size.val = g.rate := by
    have := h.1.2.2.1; scalar_tac
  have hibspos : 0 < self.input_block_size.val := by rw [hgr]; exact hgrpos
  have hibsmod : self.input_block_size.val % 8 = 0 := by rw [hgr]; exact hgrmod
  have hibsmax : self.input_block_size.val < 200 := by
    rw [hgr]; have : 8 * g.rate < 1600 := hgrlt; omega
  have hpadval : self.padding_value = g.padVal := h.1.2.2.2.1
  have hsqu : ¬ self.squeeze_mode := h.1.2.1
  have hidxLt : self.state_index.val < g.rate := by rw [← hgr]; exact hroom
  have hidxBnd : self.state_index.val < 200 := by omega
  have hsqueezed : g.squeezed = [] := h.1.2.2.2.2
  have hSI := h.2.2  -- spongeInvariant
  have htoBits : toBits self.state = (absorbBytes (Vector.replicate SHA3.b false)
                                                  0 g.rate g.absorbed).fst :=
    hSI.1
  have hidxAbs : self.state_index.val = (absorbBytes (Vector.replicate SHA3.b false)
                                                     0 g.rate g.absorbed).snd :=
    hSI.2
  -- The `input_block_size / 8 - 1` lane index where 0x80 lands.
  have hibs8 : self.input_block_size.val / 8 ≥ 1 := by
    have : self.input_block_size.val ≥ 8 := by
      rw [hgr]
      have : 8 ∣ g.rate := Nat.dvd_of_mod_eq_zero hgrmod
      omega
    omega
  unfold KeccakState.apply_padding
  step*
  refine ⟨⟨?_, ?_, ?_, ?_⟩, ?_⟩
  · -- state_index ≤ input_block_size: trivial since result.state_index = 0.
    show (0 : Nat) ≤ self.input_block_size.val
    omega
  · -- squeeze_mode = true (set by the result structure).
    rfl
  · -- input_block_size preserved.
    rw [hgr]
  · -- padding_value preserved.
    exact hpadval
  · -- squeezingInvariant: the FC content.
    simp only [squeezingInvariant, hsqueezed, List.length_nil, squeezeAfter, squeezeBytes]
    -- `squeezeBytes _ _ _ 0 = #v[]` and `squeezeAfter _ _ _ 0 = (S, idx)`.
    refine ⟨?_, ?_, ?_⟩
    · -- toBits result.state = padAndPermute (toBits self.state) state_index g.rate g.padVal
      rw [show (absorbBytes (Vector.replicate SHA3.b false) 0 g.rate g.absorbed).1
            = toBits self.state from htoBits.symm,
          show (absorbBytes (Vector.replicate SHA3.b false) 0 g.rate g.absorbed).2
            = self.state_index.val from hidxAbs.symm]
      -- Step 1: toBits a = absorbByte (toBits self.state) self.state_index.val padding_value.
      have hi5val_a : lane_pos.val = self.state_index.val / 8 := by
        rw [lane_pos_post, state_index_post]; simp [U64_NUM_BYTES_val]
      have hibv_a : i.bv = self.padding_value.bv.zeroExtend 64 := by
        rw [i_post]; rfl
      have hi1val_a : i1.val = 8 * (self.state_index.val % 8) := by
        rw [i1_post, byte_pos_post, state_index_post]; simp [U64_NUM_BYTES_val]
      have hi2bv_a : i2.bv = self.padding_value.bv.zeroExtend 64
                              <<< (8 * (self.state_index.val % 8)) := by
        have := i2_post2; rw [hibv_a, hi1val_a] at this; exact this
      have hi3bv_a : i3.bv = (self.state.val[self.state_index.val / 8]!).bv := by grind
      have hi4bv_a : i4.bv =
          (self.state.val[self.state_index.val / 8]'(by grind)).bv
            ^^^ (self.padding_value.bv.zeroExtend 64
                  <<< (8 * (self.state_index.val % 8))) := by
        grind
      have hbridge_a :
          toBits (Std.Array.set self.state lane_pos i4) =
          absorbByte (toBits self.state) self.state_index.val self.padding_value :=
        absorbByte_bridge self.state self.state_index.val self.padding_value
          lane_pos i4 hidxBnd hi5val_a hi4bv_a
      -- Step 2: toBits a1 = absorbByte (toBits a) (rate-1) 0x80.
      have hrate_minus_1_lt : self.input_block_size.val - 1 < 200 := by omega
      have hi8val : i8.val = (self.input_block_size.val - 1) / 8 := by
        have hibs8' : self.input_block_size.val ≥ 8 := by
          have : 8 ∣ self.input_block_size.val := Nat.dvd_of_mod_eq_zero hibsmod
          omega
        rw [i8_post1, i7_post, i6_post]
        simp [U64_NUM_BYTES_val]
        omega
      have hrm1_mod : (self.input_block_size.val - 1) % 8 = 7 := by
        have : 8 ∣ self.input_block_size.val := Nat.dvd_of_mod_eq_zero hibsmod
        have hibs8' : self.input_block_size.val ≥ 8 := by omega
        omega
      have hi5bv_eq : i5.bv = (0x80#u8).bv.zeroExtend 64
                                <<< (8 * ((self.input_block_size.val - 1) % 8)) := by
        have := i5_post2
        rw [hrm1_mod]
        rw [show (0x80#u8).bv.zeroExtend 64 <<< (8 * 7) = U64.bv 1#u64 <<< 63 from by decide]
        exact this
      have hi9bv : i9.bv = (a.val[i8.val]!).bv := by grind
      have hi10bv : i10.bv = (a.val[(self.input_block_size.val - 1) / 8]'(by grind)).bv
                              ^^^ ((0x80#u8).bv.zeroExtend 64
                                    <<< (8 * ((self.input_block_size.val - 1) % 8))) := by
        grind
      have hbridge_b :
          toBits (Std.Array.set a i8 i10) =
          absorbByte (toBits a) (self.input_block_size.val - 1) (0x80#u8) :=
        absorbByte_bridge a (self.input_block_size.val - 1) (0x80#u8)
          i8 i10 hrate_minus_1_lt hi8val hi10bv
      -- Step 3: toBits a2 = KECCAK_f (toBits a1).
      have hperm : toBits a2 = SHA3.KECCAK_f (toBits a1) :=
        keccak_permute_toBits a1 a2 a2_post
      -- Combine.
      rw [hperm, a1_post, hbridge_b, a_post, hbridge_a]
      unfold padAndPermute
      rw [hpadval, show self.input_block_size.val - 1 = g.rate - 1 from by rw [hgr]]
    · -- result.state_index = 0
      rfl
    · -- g.squeezed = #v[].toList = []
      rw [hsqueezed]
      rfl

end symcrust.sha3.sha3_impl
