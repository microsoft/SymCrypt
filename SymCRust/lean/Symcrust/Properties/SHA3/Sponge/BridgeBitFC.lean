import Symcrust.Properties.SHA3.Sponge.BridgeRepr
import Symcrust.Properties.SHA3.Sponge.BridgeComp

/-!
# SHA-3 Sponge Bridge — Bit-level FC

Bit-level functional-correctness theorems linking the implementation's
lane operations (XOR, shift) to the spec's bit-level operations
(`absorbByte`, `squeezeByte`, `KECCAK_f`).

These proofs are heavy and have historically caused cold-build OOMs in
the original monolithic Bridge.lean. Splitting them into their own file
isolates their elaborator state from the rest of the bridge.
-/

namespace symcrust.sha3.sha3_impl

open Aeneas Aeneas.Std Spec
open Spec (𝔹 bytesToBits bitsToBytes Bits.toNatLE)
open Spec.SHA3 (b w KECCAK_f SPONGE)
open scoped Spec.Notations

/-! ## Absorb bridge -/

/-- **Absorb bridge**: updating lane `idx / 8` in the Keccak state with the
    code's XOR result equals `absorbByte` at the spec level.

    Hypothesis `hnew` describes the code's operation: the new lane is the old lane
    XOR'd with the zero-extended byte shifted into position. -/
theorem absorbByte_bridge
    (a : Keccak1600) (idx : Nat) (val : U8)
    (lane_idx : Usize) (new_lane : U64)
    (hbound : idx < 200)
    (hlane : lane_idx.val = idx / 8)
    (hnew : new_lane.bv = a.val[idx / 8].bv ^^^
        (val.bv.zeroExtend SHA3.w <<< (8 * (idx % 8)))) :
    toBits (Std.Array.set a lane_idx new_lane) =
    absorbByte (toBits a) idx val := by
  unfold absorbByte
  apply Vector.ext
  intro j hj
  simp only [Vector.getElem_ofFn, toBits_getElem]
  have hlhs : (toBits (Std.Array.set a lane_idx new_lane))[j] =
      (Std.Array.set a lane_idx new_lane).val[j / w]!.bv.getLsbD (j % w) :=
    toBits_getElem _ ⟨j, hj⟩
  rw [hlhs]
  simp only [Aeneas.Std.Array.set_val_eq]
  have hlen : a.val.length = 25 := a.property
  have hidx8 : idx / 8 < 25 := by omega
  by_cases heq : j / w = idx / 8
  · -- Modified lane: j / w = idx / 8
    have hlane_eq : lane_idx.val = j / w := by omega
    simp_lists
    rw [hnew, BitVec.getLsbD_xor]
    suffices h : (BitVec.zeroExtend w val.bv <<< (8 * (idx % 8))).getLsbD (j % w) =
        (BitVec.zeroExtend b val.bv <<< (8 * idx)).getLsbD j by
      grind
    simp only [BitVec.getLsbD_shiftLeft, BitVec.getLsbD_setWidth,
               show SHA3.w = 64 from rfl, show SHA3.b = 1600 from rfl]
    have hj1600 : j < 1600 := hj
    have hjw : j % 64 < 64 := Nat.mod_lt _ (by omega)
    have hjwsub : j % 64 - 8 * (idx % 8) < 64 := by omega
    have hw64 : (w : Nat) = 64 := rfl
    rw [hw64] at heq
    have hj_decomp : j = 64 * (j / 64) + j % 64 := (Nat.div_add_mod j 64).symm
    have hidx_decomp : idx = 8 * (idx / 8) + idx % 8 := (Nat.div_add_mod idx 8).symm
    have hidx_mod : idx % 8 < 8 := Nat.mod_lt _ (by omega)
    have hjsub : j - 8 * idx < 1600 := by omega
    simp only [hjw, hj1600, hjsub, hjwsub, decide_true, Bool.true_and]
    have hmod_iff : (j % 64 < 8 * (idx % 8)) ↔ (j < 8 * idx) := by
      rw [hj_decomp, hidx_decomp, heq]; omega
    have hmod_sub : j % 64 - 8 * (idx % 8) = j - 8 * idx := by
      rw [hj_decomp, hidx_decomp, heq]; omega
    rw [show decide (j % 64 < 8 * (idx % 8)) = decide (j < 8 * idx) from
          by rw [decide_eq_decide]; exact hmod_iff,
        hmod_sub]
  · -- Unmodified lane: j / w ≠ idx / 8
    have hlane_ne : Nat.not_eq (↑lane_idx) (j / w) := by
      left; omega
    simp_lists
    suffices hfalse : (BitVec.zeroExtend b val.bv <<< (8 * idx)).getLsbD j = false by
      grind
    simp only [BitVec.getLsbD_shiftLeft, BitVec.getLsbD_setWidth,
               show SHA3.b = 1600 from rfl]
    have hw64 : (w : Nat) = 64 := rfl
    rw [hw64] at heq
    have hj_decomp : j = 64 * (j / 64) + j % 64 := (Nat.div_add_mod j 64).symm
    have hidx_decomp : idx = 8 * (idx / 8) + idx % 8 := (Nat.div_add_mod idx 8).symm
    have hidx_mod : idx % 8 < 8 := Nat.mod_lt _ (by omega)
    by_cases hjlt : j < 8 * idx
    · simp [hjlt]
    · push Not at hjlt
      have hge8 : j - 8 * idx ≥ 8 := by
        rw [hj_decomp, hidx_decomp]; omega
      have : BitVec.getLsbD val.bv (j - 8 * idx) = false :=
        BitVec.getLsbD_of_ge val.bv _ (by omega)
      simp [this]

/-! ## Permute bridge -/

/-- `forIn'` over `[0:n]` applying `SHA3.Rnd` is `iterateRnd`. -/
private theorem foldl_Rnd_eq_iterateRnd (A : SHA3.State) (n : Nat) :
    List.foldl (fun b a => SHA3.Rnd b a) A (List.range' 0 n) = iterateRnd A n := by
  suffices h : ∀ k, List.foldl (fun b a => SHA3.Rnd b a)
        (iterateRnd A k) (List.range' k n) = iterateRnd A (n + k) by
    have := h 0; simp at this; exact this
  induction n with
  | zero => intro k; simp
  | succ m ih =>
    intro k
    simp only [List.range'_succ, List.foldl_cons]
    have : SHA3.Rnd (iterateRnd A k) k = iterateRnd A (k + 1) := by
      simp [iterateRnd]
    rw [this, ih (k + 1)]
    fcongr 1
    scalar_tac

/-- `KECCAK_f(stateToString A) = stateToString(iterateRnd A 24)`. -/
private theorem keccak_f_eq_iterateRnd (A : SHA3.State) :
    SHA3.KECCAK_f (SHA3.stateToString A) = SHA3.stateToString (iterateRnd A 24) := by
  simp only [SHA3.KECCAK_f, SHA3.KECCAK_p, SHA3.ℓ]
  simp
  fcongr 1
  rw [SHA3.stringToState_stateToString, foldl_Rnd_eq_iterateRnd]

/-- Permute bridge: code permute = spec KECCAK_f at the bit level. -/
theorem keccak_permute_toBits (state : Keccak1600) (result : Keccak1600)
    (h : toState result = iterateRnd (toState state) 24) :
    toBits result = SHA3.KECCAK_f (toBits state) := by
  simp only [toBits]
  rw [h, keccak_f_eq_iterateRnd]

/-! ## Squeeze bridge -/

/-- **Squeeze bridge**: code-side byte extraction (lane shift + setWidth 8)
    equals spec-level `squeezeByte` on `toBits`.

    Hypothesis `hbyte` describes the code's operation: `byte.bv = (lane >>> shift).setWidth 8`
    where `shift = 8 * (idx % 8)`. Mirror of `absorbByte_bridge` — code-side
    BV equation goes IN, spec-side equality comes OUT.

    Avoids the `funext` over `Fin 8` OOM trap by stating the equation
    code→spec rather than expanding `squeezeByte` as `BitVec.ofFn`. -/
theorem squeezeByte_bridge
    (a : Keccak1600) (idx : Nat) (byte : U8)
    (hidx : idx < 200)
    (hbyte : byte.bv = (a.val[idx / 8].bv >>> (8 * (idx % 8))).setWidth 8) :
    byte = squeezeByte (toBits a) idx := by
  apply U8.bv_eq_imp_eq
  simp only [hbyte]
  show _ = (squeezeByte (toBits a) idx).bv
  unfold squeezeByte
  show (a.val[idx / 8].bv >>> (8 * (idx % 8))).setWidth 8 = BitVec.ofFn _
  apply BitVec.eq_of_getElem_eq
  intro i hi
  simp only [BitVec.getElem_ofFn]
  rw [← BitVec.getLsbD_eq_getElem hi (x := _)]
  rw [BitVec.getLsbD_setWidth, BitVec.getLsbD_ushiftRight]
  simp only [hi, decide_true, Bool.true_and]
  have hb : 8 * idx + i < SHA3.b := by show _ < 1600; omega
  rw [show (toBits a).getD (8 * idx + i) false = (toBits a)[8 * idx + i] from by
        rw [Vector.getD]
        simp [hb]]
  have := toBits_byte_bit a idx i hi hb
  grind

/-! ## Helpers for `squeezeBytes_lane_aligned` -/

/-- When `idx + n ≤ rate`, `squeezeAfter` doesn't permute and just increments the
    index. Used to characterise the within-block path. -/
private theorem squeezeAfter_no_permute
    (S : Vector Bool SHA3.b) (idx rate n : Nat) (h : idx + n ≤ rate) :
    squeezeAfter S idx rate n = (S, idx + n) := by
  induction n with
  | zero => rfl
  | succ k ih =>
    have hk : idx + k ≤ rate := by omega
    rw [squeezeAfter_succ]
    rw [ih hk]
    have h2 : idx + k ≠ rate := by omega
    simp [h2]; omega

/-- The k-th byte of `BitVec.toLEBytes` is the k-th 8-bit slice via `setWidth 8`. -/
private theorem toLEBytes_getElem_eq_shiftRight (v : BitVec 64) (k : Nat) (hk : k < 8) :
    v.toLEBytes[k] = (v >>> (8 * k)).setWidth 8 := by
  grind

/-- **Lane-aligned squeeze bridge** (extract-side dual of `absorbLane_bridge`).

When `idx % 8 = 0` and `idx + 8 ≤ rate`, squeezing 8 bytes from `(toBits a)`
at byte position `idx` (within block) equals reading lane `idx/8` from `a`
and converting it to little-endian bytes — i.e., the code-level
`(a[idx/8]).to_le_bytes` operation.

This is the foundation for `extract_lanes_loop.spec` FC body. -/
theorem squeezeBytes_lane_aligned
    (a : Keccak1600) (idx rate : Nat)
    (hidx_mod : idx % 8 = 0)
    (hidx_bound : idx + 8 ≤ 200)
    (hwithin : idx + 8 ≤ rate) :
    (squeezeBytes (toBits a) idx rate 8).toList =
    (BitVec.toLEBytes (a.val[idx / 8]).bv).map fun bv => (⟨bv⟩ : U8) := by
  have hlen : (BitVec.toLEBytes (a.val[idx / 8]).bv).length = 8 := by
    simp_lists
  apply List.ext_getElem
  · simp
  intro k hk1 _
  have hk : k < 8 := by simp at hk1; exact hk1
  rw [Vector.getElem_toList]
  rw [squeezeBytes_getElem _ idx rate 8 k hk]
  have hak : idx + k ≤ rate := by omega
  rw [squeezeAfter_no_permute _ _ _ _ hak]
  simp only
  have hne : idx + k ≠ rate := by omega
  rw [if_neg hne]
  rw [List.getElem_map]
  symm
  apply squeezeByte_bridge a (idx + k)
  swap
  · omega
  have hmod : (idx + k) % 8 = k := by omega
  have hdiv : (idx + k) / 8 = idx / 8 := by omega
  show ((BitVec.toLEBytes (a.val[idx / 8]).bv)[k]'(by rw [hlen]; exact hk)) = _
  grind

end symcrust.sha3.sha3_impl
