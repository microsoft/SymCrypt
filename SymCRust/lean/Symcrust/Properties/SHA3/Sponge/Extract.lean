import Symcrust.Properties.SHA3.Keccak.Loop
import Symcrust.Properties.SHA3.Keccak.Textbook
import Symcrust.Properties.SHA3.Sponge.Padding
import Symcrust.Properties.SHA3.Sponge.Init
import Symcrust.Properties.SHA3.Sponge.Bridge
import Symcrust.Properties.Stdlib

/-!
# SHA-3 Verification — Sponge Extract Operations

`extract` postcondition: output bytes extend the ghost's `squeezed` list,
which is a prefix of the one-shot sponge output (`squeezedValid`).
-/

open Aeneas Aeneas.Std
namespace symcrust.sha3.sha3_impl

open Spec

@[agrind =] private theorem U64_NUM_BYTES_val : U64_NUM_BYTES.val = 8 := by native_decide

/-! ## Iterator step specs are in Keccak/Loop.lean (public).
     `and7_ne_zero_imp_lt` is in Sponge/Bridge.lean (public). -/

/-- `squeezing` is invariant under `squeeze` (only checks rate/padVal). -/
private theorem squeezingStructural_squeeze {ks : KeccakState} {g : GhostState} {bytes : List U8}
    (h : squeezingStructural ks (g.squeeze bytes)) : squeezingStructural ks g := by
  rwa [squeezingStructural_squeeze_inv] at h

/-- A single-byte `List.set` equals a singleton `setSlice!`. -/
private theorem List.set_eq_setSlice!_singleton {α} [Inhabited α]
    (s : List α) (i : Nat) (x : α) (h : i < s.length) :
    s.set i x = s.setSlice! i [x] := by
  apply _root_.List.ext_getElem!
  · simp
  intro j
  by_cases hj1 : j < i
  · simp_lists
  by_cases hj2 : j = i
  · subst hj2; simp_lists
  push Not at hj1
  have h2 : i + [x].length ≤ j := by simp; omega
  rw [_root_.List.getElem!_setSlice!_suffix _ _ _ _ h2]
  simp_lists

/-- One-byte advance preserves squeezing.
    Given `squeezing self g`, with `state_index < g.rate` (no permute),
    a successor state `self1` whose `state` equals `self.state` and whose
    `state_index` is `self.state_index + 1` satisfies
    `squeezing self1 (g.squeeze [byte])`, where `byte = squeezeByte ...`. -/
private theorem squeezing_step_byte
    (self self1 : KeccakState) (g : GhostState) (byte : U8)
    (hsq : squeezing self g)
    (hstr1 : squeezingStructural self1 (g.squeeze [byte]))
    (hstate : self1.state = self.state)
    (hidx1 : self1.state_index.val = self.state_index.val + 1)
    (hsi_lt : self.state_index.val < g.rate)
    (hbyte : byte = squeezeByte (toBits self.state) self.state_index.val) :
    squeezing self1 (g.squeeze [byte]) := by
  refine ⟨hstr1, ?_⟩
  obtain ⟨_, hinv⟩ := hsq
  unfold squeezingInvariant at hinv ⊢
  simp only [GhostState.squeeze, List.length_append, List.length_singleton] at *
  set p := absorbBytes (Vector.replicate Spec.SHA3.b false) 0 g.rate g.absorbed
  set S_pad := padAndPermute p.1 p.2 g.rate g.padVal
  obtain ⟨h_state_eq, h_idx_eq, h_sqz_eq⟩ := hinv
  set p0 := squeezeAfter S_pad 0 g.rate g.squeezed.length with hp0
  have hp0_idx_ne : p0.2 ≠ g.rate := by rw [← h_idx_eq]; omega
  have hsucc : squeezeAfter S_pad 0 g.rate (g.squeezed.length + 1) = (p0.1, p0.2 + 1) := by
    rw [squeezeAfter_succ, ← hp0]; simp [hp0_idx_ne]
  refine ⟨?_, ?_, ?_⟩
  · rw [hsucc, hstate]; exact h_state_eq
  · rw [hsucc, hidx1, h_idx_eq]
  · have hlen : (g.squeezed ++ [byte]).length = g.squeezed.length + 1 := by simp
    rw [hlen]
    rw [squeezeBytes_append S_pad 0 g.rate g.squeezed.length 1]
    rw [← h_sqz_eq]
    congr 1
    -- goal: [byte] = let (Sn, idxn) := squeezeAfter S_pad 0 g.rate g.squeezed.length; ...
    apply List.ext_getElem
    · simp [squeezeBytes]
    intro k hk1 _
    have hk : k < 1 := by simpa using hk1
    have hk0 : k = 0 := by omega
    subst hk0
    simp only [List.getElem_singleton]
    show byte = (squeezeBytes p0.1 p0.2 g.rate 1).toList[0]
    have h0 : (0 : Nat) < 1 := by omega
    rw [show (squeezeBytes p0.1 p0.2 g.rate 1).toList[0]
            = (squeezeBytes p0.1 p0.2 g.rate 1)[0] from by simp ]
    rw [squeezeBytes_getElem p0.1 p0.2 g.rate 1 0 h0]
    show byte =
      (let (S_k, idx_k) := (p0.1, p0.2)
       let (S_k', idx_k') := if idx_k = g.rate then (Spec.SHA3.KECCAK_f S_k, 0) else (S_k, idx_k)
       squeezeByte S_k' idx_k')
    simp only
    rw [if_neg hp0_idx_ne]
    rw [hbyte, h_state_eq, h_idx_eq]

/-! ## Single-byte `extractOutput` specializations.

These connect the LOCAL state of a `KeccakState` (`toBits ks.state`,
`ks.state_index`) to the next byte produced by `extractOutput g 1`, when
`squeezing ks g` holds. Proved via two pure helpers `squeezeBytes_one_*`
plus the bridge `extractOutput_eq_squeezeBytes_of_squeezing` (in BridgeComp). -/

private theorem squeezeBytes_one_no_permute (S : Vector Bool Spec.SHA3.b)
    (idx rate : Nat) (h : idx ≠ rate) :
    (squeezeBytes S idx rate 1).toList = [squeezeByte S idx] := by
  apply List.ext_getElem
  · simp [squeezeBytes]
  intro k hk1 _
  have hk : k < 1 := by simpa using hk1
  have hk0 : k = 0 := by omega
  subst hk0
  rw [show (squeezeBytes S idx rate 1).toList[0] = (squeezeBytes S idx rate 1)[0] from by simp]
  rw [squeezeBytes_getElem S idx rate 1 0 (by omega), squeezeAfter_zero]
  grind

private theorem squeezeBytes_one_permute (S : Vector Bool Spec.SHA3.b)
    (rate : Nat) :
    (squeezeBytes S rate rate 1).toList =
      [squeezeByte (Spec.SHA3.KECCAK_f S) 0] := by
  apply List.ext_getElem
  · simp [squeezeBytes]
  intro k hk1 _
  have hk : k < 1 := by simpa using hk1
  have hk0 : k = 0 := by omega
  subst hk0
  rw [show (squeezeBytes S rate rate 1).toList[0]
          = (squeezeBytes S rate rate 1)[0] from by simp]
  rw [squeezeBytes_getElem S rate rate 1 0 (by omega), squeezeAfter_zero]
  grind

theorem extractOutput_one' (ks : KeccakState) (g : GhostState)
    (h : squeezing ks g) (hno : ks.state_index.val < g.rate) :
    (extractOutput g 1).toList =
      [squeezeByte (toBits ks.state) ks.state_index.val] := by
  rw [extractOutput_eq_squeezeBytes_of_squeezing h]
  exact squeezeBytes_one_no_permute _ _ _ (Nat.ne_of_lt hno)

theorem extractOutput_one_permute' (ks : KeccakState) (g : GhostState)
    (h : squeezing ks g) (hboundary : ks.state_index.val = g.rate) :
    (extractOutput g 1).toList =
      [squeezeByte (Spec.SHA3.KECCAK_f (toBits ks.state)) 0] := by
  rw [extractOutput_eq_squeezeBytes_of_squeezing h, hboundary]
  exact squeezeBytes_one_permute _ _


@[step]
theorem KeccakState.extract_byte.spec
    (self : KeccakState) (g : GhostState) (h : squeezingStructural self g)
    (hroom : self.state_index.val < self.input_block_size.val) :
    KeccakState.extract_byte self
    ⦃ (byte : U8) (result : KeccakState) =>
      squeezingStructural result (g.squeeze [byte]) ∧
      result.state = self.state ∧
      result.state_index.val = self.state_index.val + 1 ∧
      byte.bv = squeezeByte (toBits self.state) self.state_index.val ⦄ := by
  have hgr : self.input_block_size.val = g.rate := by
    have := h.2.2.1; scalar_tac
  have hgrlt : 8 * g.rate < SHA3.b := g.h_rate.2.1
  have hibsmax : self.input_block_size.val < 200 := by
    rw [hgr]; have : 8 * g.rate < 1600 := hgrlt; omega
  have hidxBnd : self.state_index.val < 200 := by omega
  unfold KeccakState.extract_byte
  step*
  refine ⟨?_, ?_, ?_⟩
  · simp only [squeezingStructural_squeeze_inv]
    simp only [squeezingStructural] at *
    split_conjs
    all_goals agrind
  · exact i6_post
  · -- FC: ret.bv = squeezeByte (toBits self.state) self.state_index.val
    have hi_val : i.val = self.state_index.val / 8 := by
      rw [i_post, state_index_post, UScalar.cast_u32_to_usize_val, U64_NUM_BYTES_val]
    have hi2_val : i2.val = self.state_index.val % 8 := by
      rw [i2_post, state_index_post, UScalar.cast_u32_to_usize_val]
    have hi3_val : i3.val = 8 * (self.state_index.val % 8) := by
      rw [i3_post, hi2_val]
    have hi1_bv : i1.bv = self.state.val[self.state_index.val / 8]!.bv := by grind
    have hi4_bv : i4.bv =
        self.state.val[self.state_index.val / 8]!.bv >>> (8 * (self.state_index.val % 8)) := by
      simp only [i4_post2, hi3_val, hi1_bv]
    have hi5_bv : i5.bv =
        self.state.val[self.state_index.val / 8]!.bv >>> (8 * (self.state_index.val % 8)) &&& 0xff := by
      simp only [i5_post2, hi4_bv]; rfl
    have hret_final : ret.bv =
        (self.state.val[self.state_index.val / 8].bv >>>
          (8 * (self.state_index.val % 8))).setWidth 8 := by
      have hr : ret.bv = i5.bv.setWidth 8 := by rw [ret_post]; rfl
      rw [hr, hi5_bv]
      apply BitVec.eq_of_getLsbD_eq
      intro k hk
      have hkbnd : k < 8 := hk
      have h0xff : ∀ j, j < 8 → ((255 : BitVec 64).getLsbD j) = true := by decide
      grind
    have hbridge := squeezeByte_bridge self.state self.state_index.val ret hidxBnd hret_final
    simp [hbridge]

/-- Specialization of `extract_loop0` for lane-aligned `state_index` (`% 8 = 0`).

    When `state_index` is lane-aligned, the loop exits immediately on the first
    iteration without calling `extract_byte`, so the result is trivially the
    inputs unchanged. Used in the boundary case of `extract.spec` where
    post-permute `state_index = 0`.

    Not tagged `@[step]` to avoid clashing with `extract_loop0.spec` (which has
    a different precondition). Invoke explicitly via `progress with`. -/
private theorem KeccakState.extract_loop0_aligned_spec
    (self : KeccakState) (output : Slice U8)
    (rem_result_len : Usize) (result_index : Usize)
    (halign : self.state_index.val % 8 = 0) :
    KeccakState.extract_loop0 self output rem_result_len result_index
    ⦃ (ks : KeccakState) (output' : Slice U8)
      (rem' : Usize) (idx' : Usize) =>
      ks = self ∧ output'.val = output.val ∧
      output'.length = output.length ∧
      rem' = rem_result_len ∧ idx' = result_index ⦄ := by
  unfold KeccakState.extract_loop0
  by_cases hrem : rem_result_len > 0#usize
  · simp only [hrem, ↓reduceIte]
    have hi_eq0 : self.state_index &&& 7#u32 = 0#u32 :=
      and7_eq_zero_of_mod8 self.state_index _ rfl halign
    rw [show (lift (self.state_index &&& 7#u32) : Result U32) =
            Result.ok (self.state_index &&& 7#u32) from rfl, hi_eq0]
    simp only [show ((Result.ok 0#u32 : Result U32) >>= fun (i : U32) =>
                if (i != 0#u32) = true then _ else _) = _ from bind_ok _ _]
    simp only [bne_self_eq_false]
    refine ⟨rfl, rfl, rfl, rfl, rfl⟩
  · simp only [hrem, ↓reduceIte]
    refine ⟨rfl, rfl, rfl, rfl, rfl⟩

/-! ### Decomposition of `extract_loop0`

The loop body is structurally a cascade of two `if`s — `rem > 0`, then
`(state_index &&& 7) ≠ 0`. We fold the inner do-block (4 bindings:
`extract_byte`, `Slice.update`, `+1`, `-1`) into a single helper
`body_fused`, leaving the outer skeleton as just two `ite`s plus the
recursive call. The helper gets its own `@[step]` spec below. -/

set_option maxRecDepth 1024 in
#decompose KeccakState.extract_loop0 KeccakState.extract_loop0.fold
  branch 0 (letRange 1 1) => KeccakState.extract_loop0.inner_ite

set_option maxRecDepth 1024 in
#decompose KeccakState.extract_loop0.inner_ite KeccakState.extract_loop0.inner_ite.fold
  branch 0 (letRange 0 4) => KeccakState.extract_loop0.body_fused

/-- **Body spec for one iteration of `extract_loop0`.**

Fully captures the effect of the inner do-block (extract_byte, write to
output, increment indices). The runtime byte equals `squeezeByte` on the
local state; `s` is `output` with that byte written at `result_index`;
indices advance by 1; and the squeezing invariant is preserved with that
byte appended to the ghost. -/
@[step]
theorem KeccakState.extract_loop0.body_fused.spec
    (self : KeccakState) (output : Slice U8)
    (rem_result_len : Usize) (result_index : Usize)
    (g : GhostState) (h : squeezing self g)
    (hsi_lt : self.state_index.val < g.rate)
    (hri_lt : result_index.val < output.length)
    (hrr_pos : 1 ≤ rem_result_len.val) :
    KeccakState.extract_loop0.body_fused self output rem_result_len result_index
    ⦃ (self1 : KeccakState) (s : Slice U8) (ri1 : Usize) (rr1 : Usize) =>
      let byte : U8 := squeezeByte (toBits self.state) self.state_index.val
      squeezing self1 (g.squeeze [byte]) ∧
      self1.input_block_size = self.input_block_size ∧
      self1.state = self.state ∧
      self1.state_index.val = self.state_index.val + 1 ∧
      s.length = output.length ∧
      s.val = output.val.setSlice! result_index.val [byte] ∧
      ri1.val = result_index.val + 1 ∧
      rr1.val = rem_result_len.val - 1 ⦄ := by
  unfold KeccakState.extract_loop0.body_fused
  have hstr : squeezingStructural self g := h.1
  have hgr : self.input_block_size.val = g.rate := by
    have := hstr.2.2.1; scalar_tac
  have hsi_lt_ibs : self.state_index.val < self.input_block_size.val := by
    rw [hgr]; exact hsi_lt
  step*
  -- Bridge the runtime byte to the spec value, then proceed.
  have hbyte_eq : i1 = squeezeByte (toBits self.state) self.state_index.val := by
    apply U8.bv_eq_imp_eq
    simpa using i1_post4
  subst hbyte_eq
  -- After subst, `byte` in the residual do-block is `squeezeByte ...`. Finish.
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · grind [squeezing_step_byte]
  · -- self1.input_block_size = self.input_block_size: both equal g.rate
    -- (from squeezingStructural's 3rd conjunct on i1_post1 and on hstr).
    apply UScalar.eq_of_val_eq
    rw [i1_post1.2.2.1]; exact hstr.2.2.1.symm
  · grind
  · grind
  · simp [s_post]
  · rw [s_post]
    exact List.set_eq_setSlice!_singleton _ _ _ hri_lt
  · exact result_index1_post
  · exact rem_result_len1_post1

/-- **Loop invariant for `extract_loop0`** — STRENGTHENED with FC.
Pre-lane-alignment byte loop: extracts bytes one at a time via `extract_byte`
until either lane-aligned (`state_index % 8 = 0`) or `rem_result_len = 0`.
NO permute branch — `extract_byte` requires `state_index < input_block_size`,
and the loop exits at lane boundaries before reaching `state_index = rate`.

FC content (output side): `output' = output.setSlice! at result_index` with
the bytes from `squeezeBytes (toBits self.state) self.state_index.val rate consumed`.
Since no permute occurs, this is equivalent to a plain bit-window read. -/
@[step]
theorem KeccakState.extract_loop0.spec
    (self : KeccakState) (output : Slice U8)
    (rem_result_len : Usize) (result_index : Usize)
    (g : GhostState) (h : squeezing self g)
    (hbound : result_index.val + rem_result_len.val ≤ output.length) :
    KeccakState.extract_loop0 self output rem_result_len result_index
    ⦃ (ks : KeccakState) (output' : Slice U8)
     (rem' : Usize) (idx' : Usize) =>
      rem'.val + idx'.val = rem_result_len.val + result_index.val ∧
      result_index.val ≤ idx'.val ∧
      output'.length = output.length ∧
      let consumed := idx'.val - result_index.val
      let bytes := (squeezeBytes (toBits self.state) self.state_index.val
                    self.input_block_size.val consumed).toList
      output'.val = output.val.setSlice! result_index.val bytes ∧
      squeezing ks (g.squeeze bytes) ∧
      ks.state_index.val = self.state_index.val + consumed ∧
      (rem'.val > 0 → ks.state_index.val % 8 = 0) ⦄ := by
  -- Common derived facts.
  have hstr : squeezingStructural self g := h.1
  have hgr : self.input_block_size.val = g.rate := by
    have := h.1.2.2.1; scalar_tac
  have hgrlt : 8 * g.rate < SHA3.b := g.h_rate.2.1
  have hgrmod : g.rate % 8 = 0 := g.h_rate.2.2
  have hibsmod : self.input_block_size.val % 8 = 0 := by rw [hgr]; exact hgrmod
  have hidx_le : self.state_index.val ≤ self.input_block_size.val := h.1.1
  rw [KeccakState.extract_loop0.fold]
  by_cases hrem : rem_result_len > 0#usize
  case neg =>
    -- ── Base case: rem = 0 ────────────────────────────────────────────
    simp only [hrem, ↓reduceIte]
    have hrem0 : rem_result_len.val = 0 := by simp at hrem; scalar_tac
    have hsub : result_index.val - result_index.val = 0 := Nat.sub_self _
    have hempty : (squeezeBytes (toBits self.state) self.state_index.val
                  self.input_block_size.val 0).toList = [] := by simp [squeezeBytes]
    refine ⟨by omega, Nat.le_refl _, rfl, ?_, ?_, ?_, ?_⟩
    · rw [hsub, hempty]; simp [List.setSlice!]
    · rw [hsub, hempty]; simpa using h
    · rw [hsub]; omega
    · intro hrr; omega
  case pos =>
    simp only [hrem, ↓reduceIte]
    -- Compute the lane offset `i = state_index &&& 7`.
    step
    have hi_eq : i.val = self.state_index.val % 8 := by
      rw [i_post1]; exact and7_val _
    rw [KeccakState.extract_loop0.inner_ite.fold]
    by_cases hi_ne : (i != 0#u32) = true
    case neg =>
      -- ── Base case: i = 0 (lane-aligned exit) ────────────────────────
      have hi_zero : i.val = 0 := by simpa [bne_iff_ne] using hi_ne
      simp only [hi_ne]
      have hsub : result_index.val - result_index.val = 0 := Nat.sub_self _
      have hempty : (squeezeBytes (toBits self.state) self.state_index.val
                    self.input_block_size.val 0).toList = [] := by simp [squeezeBytes]
      refine ⟨rfl, Nat.le_refl _, rfl, ?_, ?_, ?_, ?_⟩
      · rw [hsub, hempty]; simp [List.setSlice!]
      · rw [hsub, hempty]; simpa using h
      · simp
      · intro _; omega
    case pos =>
      -- ── Recursive case: i ≠ 0, byte extracted via `body_fused` ──────
      simp only [hi_ne, ↓reduceIte]
      have hi_pos : i.val ≠ 0 := by simpa [bne_iff_ne] using hi_ne
      have hsi_lt : self.state_index.val < g.rate := by
        have h_le : self.state_index.val ≤ g.rate := by rw [← hgr]; exact hidx_le
        have hmod : self.state_index.val % 8 ≠ 0 := by omega
        omega
      have hrr_pos : 1 ≤ rem_result_len.val := by scalar_tac
      have hri_lt : result_index.val < output.length := by omega
      -- One iteration of the body: extract a byte and write it.
      let* ⟨self1, s, ri1, rr1,
             hsq1, hibs1, hstate, hidx1, hs_len, hs_val, hri1_eq, hrr1_eq⟩
        ← KeccakState.extract_loop0.body_fused.spec
      -- Recurse: same loop spec on the post-byte state.
      have hbound_inner : ri1.val + rr1.val ≤ s.length := by
        rw [hs_len, hri1_eq, hrr1_eq]; omega
      apply WP.spec_mono
        (KeccakState.extract_loop0.spec self1 s rr1 ri1 _ hsq1 hbound_inner)
      rintro ⟨ks_inner, output_inner, rem_inner, idx_inner⟩
        ⟨hsum, hbnd, hlen_eq, hfc_inner, hsq_inner, hidx_inner, hmod_inner⟩
      -- Reassemble: outer FC = [byte] ++ inner FC.
      set byte : U8 := squeezeByte (toBits self.state) self.state_index.val with hbyte_def
      set N : Nat := idx_inner.val - result_index.val with hN_def
      set N_inner : Nat := idx_inner.val - ri1.val with hNi_def
      have hN_pos : 1 ≤ N := by rw [hN_def]; omega
      have hN_eq : N = 1 + N_inner := by rw [hN_def, hNi_def, hri1_eq]; omega
      have hne_idx : self.state_index.val ≠ self.input_block_size.val := by
        rw [hgr]; omega
      have hself1_state : toBits self1.state = toBits self.state := by rw [hstate]
      have hself1_ibs : self1.input_block_size.val = self.input_block_size.val := by rw [hibs1]
      -- `[byte] ++ inner_bytes = squeezeBytes (toBits self.state) state_index ibs N`.
      have hbytes_total :
          (squeezeBytes (toBits self.state) self.state_index.val
              self.input_block_size.val N).toList =
            [byte] ++ (squeezeBytes (toBits self1.state) self1.state_index.val
                        self1.input_block_size.val N_inner).toList := by
        rw [hN_eq, squeezeBytes_append]
        have hsa1 : squeezeAfter (toBits self.state) self.state_index.val
            self.input_block_size.val 1 = (toBits self.state, self.state_index.val + 1) := by
          rw [show (1 : Nat) = 0 + 1 from rfl, squeezeAfter_succ]
          simp [squeezeAfter_zero, hne_idx]
        rw [hsa1]; simp only
        rw [squeezeBytes_one_no_permute _ _ _ hne_idx, hbyte_def,
            hself1_state, hidx1, hself1_ibs]
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
      · rw [hri1_eq, hrr1_eq] at hsum; omega
      · rw [hri1_eq] at hbnd; omega
      · rw [hlen_eq]; exact hs_len
      · -- output side
        rw [hfc_inner, hs_val, hri1_eq, show (N_inner : Nat) = idx_inner.val - ri1.val from hNi_def]
        rw [show result_index.val + 1 = result_index.val + [byte].length from rfl]
        have hroom : result_index.val + [byte].length +
            ((squeezeBytes (toBits self1.state) self1.state_index.val
                self1.input_block_size.val (idx_inner.val - ri1.val)).toList).length ≤
            output.val.length := by
          have hlen_inner : ((squeezeBytes (toBits self1.state) self1.state_index.val
                  self1.input_block_size.val (idx_inner.val - ri1.val)).toList).length
              = idx_inner.val - ri1.val := by
            simp [squeezeBytes]
          rw [hlen_inner]
          simp only [List.length_singleton]
          rw [hri1_eq] at hbnd
          rw [hri1_eq, hrr1_eq] at hsum
          have h0 : output.val.length = output.length := rfl
          rw [h0]; omega
        rw [List.setSlice!_setSlice!_append output.val [byte] _ result_index.val hroom]
        congr 1
        rw [show idx_inner.val - result_index.val = N from by rw [hN_def],
            show idx_inner.val - ri1.val = N_inner from by rw [hNi_def],
            ← hbytes_total]
      · -- squeezing side
        rw [show (idx_inner.val - result_index.val : Nat) = N from by rw [hN_def]]
        rw [hbytes_total, ← GhostState.squeeze_append]
        exact hsq_inner
      · -- state_index = self.state_index + consumed
        rw [hidx_inner, hidx1]
        show self.state_index.val + 1 + N_inner = self.state_index.val + (idx_inner.val - result_index.val)
        rw [show idx_inner.val - result_index.val = N from rfl, hN_eq]; ring
      · exact hmod_inner
  termination_by rem_result_len.val
  decreasing_by scalar_decr_tac

/-! ## Helpers for `extract_lanes_loop.spec` -/

/-- Local copy of `squeezeAfter_no_permute` (since the original is `private`). -/
private theorem squeezeAfter_no_permute_local
    (S : Vector Bool SHA3.b) (idx rate n : Nat) (h : idx + n ≤ rate) :
    squeezeAfter S idx rate n = (S, idx + n) := by
  induction n with
  | zero => rfl
  | succ k ih =>
    have hk : idx + k ≤ rate := by omega
    rw [squeezeAfter_succ, ih hk]
    have h2 : idx + k ≠ rate := by omega
    simp [h2]; omega

/-- Boundary case: when `idx = rate`, the first squeezeAfter step permutes;
    after `n+1` steps with `n+1 ≤ rate`, we get `(KECCAK_f S, n+1)`. -/
private theorem squeezeAfter_boundary
    (S : Vector Bool SHA3.b) (rate n : Nat) (h : n + 1 ≤ rate) :
    squeezeAfter S rate rate (n + 1) = (Spec.SHA3.KECCAK_f S, n + 1) := by
  induction n with
  | zero =>
    show squeezeAfter S rate rate 1 = _
    rw [show (1 : Nat) = 0 + 1 from rfl, squeezeAfter_succ]
    simp [squeezeAfter_zero]
  | succ k ih =>
    have hk : k + 1 ≤ rate := by omega
    rw [show k + 1 + 1 = (k + 1) + 1 from rfl, squeezeAfter_succ, ih hk]
    simp only
    have hne : k + 1 ≠ rate := by omega
    simp [hne]

/-- 8-step lane-aligned squeezeAfter, unifying boundary and non-boundary cases. -/
private theorem squeezeAfter_lane_step
    (S : Vector Bool SHA3.b) (idx rate : Nat)
    (hidx_mod : idx % 8 = 0) (hidx_le : idx ≤ rate)
    (hrate_mod : rate % 8 = 0) (hr8 : 8 ≤ rate) :
    squeezeAfter S idx rate 8 =
      (if idx = rate then Spec.SHA3.KECCAK_f S else S,
       (if idx = rate then 0 else idx) + 8) := by
  by_cases hb : idx = rate
  · rw [hb]
    have h7 : 7 + 1 ≤ rate := by omega
    rw [show (8 : Nat) = 7 + 1 from rfl, squeezeAfter_boundary S rate 7 h7]
    simp
  · have hidx8 : idx + 8 ≤ rate := by omega
    rw [squeezeAfter_no_permute_local S idx rate 8 hidx8]
    simp [hb]

/-- 8-step lane-aligned squeezeBytes equals the lane bytes from the post-step state. -/
private theorem squeezeBytes_lane_step
    (a a1 : Keccak1600) (idx idx1 rate lane_idx : Nat)
    (hidx_mod : idx % 8 = 0) (hidx_le : idx ≤ rate)
    (hrate_mod : rate % 8 = 0) (hr8 : 8 ≤ rate) (hr200 : rate ≤ 200)
    (hperm_state : toBits a1 =
       if idx = rate then Spec.SHA3.KECCAK_f (toBits a) else toBits a)
    (hidx1 : idx1 = if idx = rate then 0 else idx)
    (hlane : lane_idx = idx1 / 8) :
    (squeezeBytes (toBits a) idx rate 8).toList =
    (BitVec.toLEBytes (a1.val[lane_idx]).bv).map fun bv => (⟨bv⟩ : U8) := by
  -- Show `squeezeBytes (toBits a) idx rate 8 = squeezeBytes (toBits a1) idx1 rate 8`
  -- then apply `squeezeBytes_lane_aligned`.
  have hidx1_mod : idx1 % 8 = 0 := by
    rw [hidx1]; split <;> omega
  have hidx1_bnd : idx1 + 8 ≤ 200 := by
    rw [hidx1]; split
    · omega
    · omega
  have hwithin : idx1 + 8 ≤ rate := by
    rw [hidx1]; split
    · omega
    · omega
  rw [show (squeezeBytes (toBits a) idx rate 8) = (squeezeBytes (toBits a1) idx1 rate 8) from ?_]
  · rw [squeezeBytes_lane_aligned a1 idx1 rate hidx1_mod hidx1_bnd hwithin]
    grind
  -- Bridge: byte-by-byte equality.
  apply Vector.ext
  intro k hk
  rw [squeezeBytes_getElem _ idx rate 8 k hk, squeezeBytes_getElem _ idx1 rate 8 k hk]
  simp only
  by_cases hb : idx = rate
  · -- Boundary branch: idx = rate
    have hperm_S : toBits a1 = Spec.SHA3.KECCAK_f (toBits a) := by
      rw [hperm_state, if_pos hb]
    have hidx1_eq : idx1 = 0 := by rw [hidx1, if_pos hb]
    rw [hidx1_eq]
    by_cases hk0 : k = 0
    · subst hk0
      simp only [squeezeAfter_zero]
      have hr_ne : (0 : Nat) ≠ rate := by omega
      rw [if_pos hb, if_neg hr_ne]
      simp only
      rw [hperm_S]
    · obtain ⟨k', rfl⟩ := Nat.exists_eq_succ_of_ne_zero hk0
      have hk'r : k' + 1 ≤ rate := by omega
      rw [hb]
      rw [squeezeAfter_boundary _ rate k' hk'r]
      rw [squeezeAfter_no_permute_local _ 0 rate (k' + 1) (by omega)]
      simp only
      have hkr : k' + 1 ≠ rate := by omega
      have hkr0 : 0 + (k' + 1) ≠ rate := by omega
      rw [if_neg hkr, if_neg hkr0]
      simp only [Nat.zero_add]
      rw [hperm_S]
  · -- Non-boundary branch: idx < rate, no permute
    have hperm_S : toBits a1 = toBits a := by rw [hperm_state, if_neg hb]
    have hidx1_eq : idx1 = idx := by rw [hidx1, if_neg hb]
    rw [hidx1_eq]
    rw [squeezeAfter_no_permute_local _ idx rate k (by omega)]
    rw [squeezeAfter_no_permute_local _ idx rate k (by omega)]
    simp only
    have hne : idx + k ≠ rate := by omega
    rw [if_neg hne, if_neg hne, hperm_S]

/-! ## `extract_lanes_loop.spec` via `#decompose`.

The bulk lane-copy loop. Reads 8 bytes at a time via `to_le_bytes(lane)`,
writes to `output[i2*8..i2*8+8]`. HAS a permute branch when `i1 = i` (state full).

FC content: `output'` is written at `iter.start*8..iter.end*8` with the result of
squeezing `8 * (iter.end - iter.start)` bytes from the current state.
Lane-aligned chunks are bridged via `squeezeBytes_lane_aligned`.

We decompose the loop via `#decompose` into:
  * `extract_lanes_loop.fold` — the iterator-step + `match_helper` skeleton
  * `extract_lanes_loop.body_fused` — the fused some-branch body (12 bindings)

The strong `@[step]` spec on `body_fused` consumes the entire some-branch
in one shot, leaving the main loop proof a clean ~50-line skeleton. -/
set_option maxRecDepth 2048 in
#decompose KeccakState.extract_lanes_loop KeccakState.extract_lanes_loop.fold
  letRange 1 1 => KeccakState.extract_lanes_loop.match_helper

/-! ### Step 2 — Fuse the entire some-branch body into one helper.

A naive split would put `body_pre / body_mid / body_post` around the
`(s, index_mut_back) ← index_mut …` Prod-bind. The patched `#decompose`
handles the Prod-bind correctly: one `letRange 0 12` succeeds and the
closure `index_mut_back` flows through the helper's return tuple. -/

set_option maxRecDepth 4096 in
#decompose KeccakState.extract_lanes_loop.match_helper
    KeccakState.extract_lanes_loop.match_helper.fold
  branch 1 (letRange 0 12) => KeccakState.extract_lanes_loop.body_fused

/-! ### Strong `@[step]` spec for `body_fused`.

Captures the full FC content of one loop iteration: post-permute state,
post-step counter, lane index advance, and the write-back closure. -/

@[step]
theorem KeccakState.extract_lanes_loop.body_fused.spec
    (a : Std.Array U64 25#usize) (i i1 : U32) (result : Slice U8)
    (lane_index : Usize) (i2 : Usize)
    (halign_i : i.val % 8 = 0) (halign_i1 : i1.val % 8 = 0)
    (h_le : i1.val ≤ i.val) (h_pos : 0 < i.val) (h_max : i.val ≤ 200)
    (h_lane : lane_index.val = i1.val / 8)
    (hbnd : i2.val * 8 + 8 ≤ result.length)
    (hmax : result.length ≤ Usize.max) :
    KeccakState.extract_lanes_loop.body_fused a i i1 result lane_index i2
    ⦃ (a1 : Std.Array U64 25#usize)
      (idx_back : Slice U8 → Slice U8)
      (s2 : Slice U8) (i8 : U32) (lane_index2 : Usize) =>
      squeezeAfter (toBits a) i1.val i.val 8 = (toBits a1, i8.val) ∧
      s2.val = (squeezeBytes (toBits a) i1.val i.val 8).toList ∧
      s2.length = 8 ∧
      i8.val ≤ i.val ∧
      i8.val % 8 = 0 ∧
      lane_index2.val = i8.val / 8 ∧
      (∀ t : Slice U8, idx_back t = result.setSlice! (i2.val * 8) t.val) ⦄ := by
  unfold KeccakState.extract_lanes_loop.body_fused
  have hU64 : U64_NUM_BYTES.val = 8 := by native_decide
  -- i.val is a positive multiple of 8 and ≤ 200, so i.val ≥ 8.
  have h_i_ge_8 : 8 ≤ i.val := by
    have := halign_i; have := h_pos; omega
  step  -- massert (i1 ≤ i)
  by_cases h : i1 = i
  · -- ── Permute branch: i1 = i ───────────────────────────────────────
    simp only [h, ↓reduceIte]
    have h_eq : i1.val = i.val := by rw [h]
    let* ⟨a_perm, hperm⟩ ← keccak_permute.spec
    have hperm_bits : toBits a_perm = Spec.SHA3.KECCAK_f (toBits a) :=
      keccak_permute_toBits a a_perm hperm
    step*
    . grind
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · -- squeezeAfter: goal has `i.val i.val` (after `simp only [h, ...]`),
      -- so the rewrite must use `i.val i.val` consistently.
      rw [squeezeAfter_lane_step (toBits a) i.val i.val halign_i (le_refl _) halign_i (by omega)]
      simp [hperm_bits, i8_post, i7_post, hU64]
    · -- squeezeBytes
      have hperm_state : toBits a_perm =
          if i.val = i.val then Spec.SHA3.KECCAK_f (toBits a) else toBits a := by
        simp [hperm_bits]
      have hbytes :=
        squeezeBytes_lane_step a a_perm i.val 0 i.val 0
          halign_i (le_refl _) halign_i (by omega) h_max hperm_state
          (by simp) (by decide)
      simp [hbytes, s2_post2, s1_post, a2_post, i6_post, Array.to_slice]
    · grind
    · rw [i8_post, i7_post]; simp [hU64]; omega
    · rw [i8_post, i7_post]; simp [hU64]
    · rw [lane_index2_post, i8_post, i7_post]; simp [hU64]
    · intro t; rw [s_post3 t, i4_post, hU64]
  · -- ── No-permute branch: i1 ≠ i ────────────────────────────────────
    simp only [h, ↓reduceIte]
    have hne_val : i1.val ≠ i.val := fun heq => h (UScalar.eq_of_val_eq heq)
    have hlt : i1.val < i.val := by omega
    have hli_lt : lane_index.val < 25 := by
      rw [h_lane]
      have : i1.val < 200 := by omega
      omega
    step  -- i4 (auto-named as `a1`, equation `i3 : a1 = i2 * U64_NUM_BYTES`)
    step*  -- copy_from_slice
    . grind
    -- `i8 ← i1 + i7` leaves a residual `i1 + i7 ≤ U32.max`; discharge it.
    have hi8_max : i1.val + i7.val ≤ U32.max := by
      rw [i7_post]; have h1 := h_max; have h2 := hlt
      have hU32 : (U32.max : Nat) = 4294967295 := by native_decide
      simp [hU64]; omega
    have hlane_plus : lane_index.val + 1 ≤ Usize.max := by
      have : (25 : Nat) ≤ Usize.max := by scalar_tac
      omega
    have hperm_state : toBits a =
        if i1.val = i.val then Spec.SHA3.KECCAK_f (toBits a) else toBits a := by
      simp [hne_val]
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · rw [squeezeAfter_lane_step (toBits a) i1.val i.val halign_i1 h_le halign_i (by omega)]
      simp [hne_val, i8_post, i7_post, hU64]
    · have hbytes :=
        squeezeBytes_lane_step a a i1.val i1.val i.val lane_index.val
          halign_i1 h_le halign_i (by omega) h_max hperm_state
          (by simp [hne_val]) h_lane
      simp [hbytes, s2_post2, s1_post, a2_post, i6_post, Array.to_slice]
    · grind
    · rw [i8_post, i7_post]; simp [hU64]; omega
    · rw [i8_post, i7_post]; simp [hU64]; omega
    · rw [lane_index2_post, i8_post, i7_post, h_lane]; simp [hU64]
    · intro t; rw [s_post3 t, i3, hU64]

/-! ### Helper lemmas: per-iteration spec/buffer composition.

These collapse the inductive algebra of the loop (8-lane step composes
with the (N−1)-lane tail) and the adjacent-`setSlice!` merge into named
re-usable rewrites, so the main proof's some-case stays focused on the
loop's control flow rather than open-coding the algebra. -/

private theorem squeezeAfter_lane_compose
    (S Sn : Vector Bool SHA3.b) (i1 i i8 : Nat) (N : Nat)
    (hN : 1 ≤ N) (hsa8 : squeezeAfter S i1 i 8 = (Sn, i8)) :
    squeezeAfter S i1 i (8 * N) = squeezeAfter Sn i8 i (8 * (N - 1)) := by
  have h8N : 8 * N = 8 + 8 * (N - 1) := by omega
  rw [h8N, squeezeAfter_add, hsa8]

private theorem squeezeBytes_lane_compose
    (S Sn : Vector Bool SHA3.b) (i1 i i8 : Nat) (N : Nat)
    (hN : 1 ≤ N) (hsa8 : squeezeAfter S i1 i 8 = (Sn, i8)) :
    (squeezeBytes S i1 i (8 * N)).toList =
      (squeezeBytes S i1 i 8).toList ++
      (squeezeBytes Sn i8 i (8 * (N - 1))).toList := by
  have h8N : 8 * N = 8 + 8 * (N - 1) := by omega
  rw [h8N, squeezeBytes_append]; simp only; rw [hsa8]

private theorem List.lane_setSlice!_merge
    {α : Type _} [Inhabited α] (s chunk tail : List α) (start : Nat)
    (hsl : chunk.length = 8)
    (hroom : (start + 1) * 8 + tail.length ≤ s.length) :
    (s.setSlice! (start * 8) chunk).setSlice! ((start + 1) * 8) tail =
    s.setSlice! (start * 8) (chunk ++ tail) := by
  have h_off : (start + 1) * 8 = start * 8 + chunk.length := by rw [hsl]; ring
  rw [h_off]
  apply List.setSlice!_setSlice!_append
  omega

/-! ### The main loop proof via `body_fused`.

Pure loop skeleton: rewrite via `extract_lanes_loop.fold`, case-split on
the iterator, dispatch the some-branch via `body_fused.spec`, recurse
with `WP.spec_mono`, discharge the FC bookkeeping. -/

set_option maxHeartbeats 800000 in
@[step]
theorem KeccakState.extract_lanes_loop.spec
    (iter : core.ops.range.Range Usize)
    (a : Keccak1600) (i : U32) (i1 : U32)
    (output : Slice U8) (lane_index : Usize)
    (halign_i : i.val % 8 = 0)
    (halign_i1 : i1.val % 8 = 0)
    (h_le : i1.val ≤ i.val)
    (h_pos : 0 < i.val)
    (h_max : i.val ≤ 200)
    (h_lane : lane_index.val = i1.val / 8)
    (hstart : iter.start.val ≤ iter.«end».val)
    (hcap : iter.«end».val * 8 ≤ output.length) :
    KeccakState.extract_lanes_loop iter a i i1 output lane_index
    ⦃ (a' : Keccak1600) (i1' : U32) (output' : Slice U8) =>
      output'.length = output.length ∧
      i1'.val ≤ i.val ∧ i1'.val % 8 = 0 ∧
      let n := iter.«end».val - iter.start.val
      let bytes := (squeezeBytes (toBits a) i1.val i.val (8 * n)).toList
      let (S', idx') := squeezeAfter (toBits a) i1.val i.val (8 * n)
      output'.val = output.val.setSlice! (iter.start.val * 8) bytes ∧
      toBits a' = S' ∧ i1'.val = idx' ⦄ := by
  rw [KeccakState.extract_lanes_loop.fold]
  by_cases hlt : iter.start.val < iter.«end».val
  case neg =>
    let* ⟨ o, iter1, hnone, hiter_eq ⟩ ← IteratorRange_next_none
    rw [hnone, KeccakState.extract_lanes_loop.match_helper.fold]
    have hn0 : iter.«end».val - iter.start.val = 0 := by omega
    rw [hn0]
    simp [squeezeBytes, squeezeAfter_zero, List.setSlice!, h_le, halign_i1]
  case pos =>
    let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← IteratorRange_next_some
    rw [hsome, KeccakState.extract_lanes_loop.match_helper.fold]
    let* ⟨ a1, idx_back, s2, i8, lane_index2,
           hsa8, hs2val, hs2len, hi8_le, hi8_mod, hli2val, hback ⟩
      ← KeccakState.extract_lanes_loop.body_fused.spec
    have hcap_inner : iter1.«end».val * 8 ≤ (idx_back s2).length := by
      rw [hback s2, hend']; simp_lists; exact hcap
    have hstart_inner : iter1.start.val ≤ iter1.«end».val := by grind
    apply WP.spec_mono
      (KeccakState.extract_lanes_loop.spec iter1 a1 i i8 (idx_back s2) lane_index2
        halign_i hi8_mod hi8_le h_pos h_max hli2val hstart_inner hcap_inner)
    rintro ⟨a_inner, i1_inner, output_inner⟩
      ⟨hlen_eq, hi1_le, hi1_mod, hfc_inner, hS_inner, hidx_inner⟩
    set N : Nat := iter.«end».val - iter.start.val with hN_def
    have hN_pos : 1 ≤ N := by grind
    have hN1 : iter1.«end».val - iter1.start.val = N - 1 := by grind
    have hs2len' : s2.val.length = 8 := by grind
    have hsa_total := squeezeAfter_lane_compose _ _ i1.val i.val i8.val N hN_pos hsa8
    refine ⟨?_, hi1_le, hi1_mod, ?_, ?_, ?_⟩
    · rw [hlen_eq, hback s2]; simp_lists
    · rw [hfc_inner, hback s2, hN1, hstart',
          squeezeBytes_lane_compose _ _ i1.val i.val i8.val N hN_pos hsa8, ← hs2val]
      apply List.lane_setSlice!_merge _ _ _ _ hs2len'
      grind
    · rw [hS_inner, hN1, ← hsa_total]
    · rw [hidx_inner, hN1, ← hsa_total]
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

@[step]
theorem KeccakState.extract_lanes.spec
    (self : KeccakState) (output : Slice U8) (full_lanes : Usize)
    (g : GhostState) (h : squeezing self g)
    (halign : self.state_index.val % 8 = 0)
    (hcap : 8 * full_lanes.val ≤ output.length) :
    KeccakState.extract_lanes self output full_lanes
    ⦃ (ks : KeccakState) (output' : Slice U8) =>
      output'.length = output.length ∧
      let bytes := (squeezeBytes (toBits self.state) self.state_index.val
                    self.input_block_size.val (8 * full_lanes.val)).toList
      output'.val = output.val.setSlice! 0 bytes ∧
      ks.state_index.val % 8 = 0 ∧
      squeezing ks (g.squeeze bytes) ⦄ := by
  -- Structural facts.
  have hstr : squeezingStructural self g := h.1
  have hsm : self.squeeze_mode = true := hstr.2.1
  have hgr_val : self.input_block_size.val = g.rate := by
    have := hstr.2.2.1; scalar_tac
  have hgrmod : g.rate % 8 = 0 := g.h_rate.2.2
  have hibsmod : self.input_block_size.val % 8 = 0 := by rw [hgr_val]; exact hgrmod
  have hgrlt : 8 * g.rate < SHA3.b := g.h_rate.2.1
  have hgrpos : 0 < g.rate := g.h_rate.1
  have hibsmax : self.input_block_size.val ≤ 200 := by
    rw [hgr_val]; have hb : SHA3.b = 1600 := rfl; omega
  have hibspos : 0 < self.input_block_size.val := by rw [hgr_val]; exact hgrpos
  have hidx_le : self.state_index.val ≤ self.input_block_size.val := hstr.1
  unfold KeccakState.extract_lanes
  step*
  · exact and7_eq_zero_of_mod8 _ _ (by assumption) hibsmod
  · exact and7_eq_zero_of_mod8 _ _ (by assumption) halign
  -- After step*, goal is the wrapper postcondition.
  -- step* auto-introduces `a_post1..a_post4`; the 4th is the 3-way conjunction.
  obtain ⟨hout, hSeq, hidxeq⟩ := a_post4
  -- Set abbreviations.
  set bytes := (squeezeBytes (toBits self.state) self.state_index.val
                self.input_block_size.val (8 * full_lanes.val)).toList with hbytes_def
  -- 0*8 = 0 in the loop's setSlice! offset.
  refine ⟨a_post1, ?_, ?_, ?_⟩
  · -- output' val.
    have h0_val : (0#usize : Usize).val = 0 := rfl
    rw [hout, h0_val, Nat.zero_mul, Nat.sub_zero]
  · -- ks.state_index%8 = 0 (post invariant).
    try dsimp only
    convert a_post3 using 2
  · -- squeezing.
    refine ⟨?_, ?_⟩
    · -- squeezingStructural.
      refine ⟨?_, ?_, ?_, ?_⟩
      · -- state_index ≤ input_block_size.
        dsimp only
        grind --exact hi1'_le
      · dsimp only
      · dsimp only [GhostState.squeeze]; exact hstr.2.2.1
      · dsimp only [GhostState.squeeze]; exact hstr.2.2.2
    · -- squeezingInvariant.
      have hsi : squeezingInvariant self g := h.2
      -- Set abbreviations matching the squeezingInvariant unfold.
      set S_abs := (absorbBytes (Vector.replicate SHA3.b false) 0 g.rate g.absorbed).1 with hSabs
      set idx_abs := (absorbBytes (Vector.replicate SHA3.b false) 0 g.rate g.absorbed).2 with hidxabs
      set S_pad := padAndPermute S_abs idx_abs g.rate g.padVal with hSpad
      have hself_state : toBits self.state = (squeezeAfter S_pad 0 g.rate g.squeezed.length).1 := hsi.1
      have hself_idx : self.state_index.val = (squeezeAfter S_pad 0 g.rate g.squeezed.length).2 := hsi.2.1
      have hgsq : g.squeezed = (squeezeBytes S_pad 0 g.rate g.squeezed.length).toList := hsi.2.2
      have hbytes_len : bytes.length = 8 * full_lanes.val := by
        rw [hbytes_def]; simp [squeezeBytes]
      have hgs_rate : (g.squeeze bytes).rate = g.rate := rfl
      have hgs_padVal : (g.squeeze bytes).padVal = g.padVal := rfl
      have hgs_absorbed : (g.squeeze bytes).absorbed = g.absorbed := rfl
      have hgs_squeezed : (g.squeeze bytes).squeezed = g.squeezed ++ bytes := rfl
      have hgs_sq_len : (g.squeeze bytes).squeezed.length = g.squeezed.length + bytes.length := by
        rw [hgs_squeezed]; simp
      -- Decompose squeezeAfter into pieces: g.squeezed.length + bytes.length.
      have hsa_split :
          squeezeAfter S_pad 0 g.rate (g.squeezed.length + bytes.length) =
          squeezeAfter (squeezeAfter S_pad 0 g.rate g.squeezed.length).1
                       (squeezeAfter S_pad 0 g.rate g.squeezed.length).2
                       g.rate bytes.length := by
        rw [squeezeAfter_add]
      -- Now goal: toBits {ks.state} = S_cur ∧ ks.state_index = idx_cur ∧ squeezed = bytes_back.
      refine ⟨?_, ?_, ?_⟩
      · -- toBits ks.state = ... .1
        dsimp only [GhostState.squeeze]
        rw [show (g.squeezed ++ bytes).length = g.squeezed.length + bytes.length from List.length_append ..]
        rw [← hSabs, ← hidxabs, ← hSpad, hsa_split]
        rw [hSeq, hgr_val, hself_state, hself_idx]
        congr 2
        scalar_tac
      · -- ks.state_index = ... .2
        dsimp only [GhostState.squeeze]
        rw [show (g.squeezed ++ bytes).length = g.squeezed.length + bytes.length from List.length_append ..]
        rw [← hSabs, ← hidxabs, ← hSpad, hsa_split]
        rw [hidxeq, hgr_val, hself_state, hself_idx]
        congr 2
        scalar_tac
      · -- (g.squeeze bytes).squeezed = squeezeBytes ... toList
        dsimp only [GhostState.squeeze]
        rw [show (g.squeezed ++ bytes).length = g.squeezed.length + bytes.length from List.length_append ..]
        rw [← hSabs, ← hidxabs, ← hSpad]
        rw [squeezeBytes_append S_pad 0 g.rate g.squeezed.length bytes.length]
        rw [← hgsq]
        apply congrArg (g.squeezed ++ ·)
        -- Reduce match to the inner squeezeBytes call.
        simp only
        -- Now substitute back: bytes = squeezeBytes ... (8 * full_lanes); use bytes.length = 8 * full_lanes.
        conv_rhs => rw [show bytes.length = 8 * full_lanes.val from hbytes_len]
        rw [hbytes_def, hself_state, hself_idx, hgr_val]

/-- **State-level wrapper for `extract_lanes`** — does NOT require `squeezing`.
    Takes raw alignment/bound preconditions; postcondition is purely state-level
    (`squeezeAfter`/`squeezeBytes` on `toBits self.state`).

    Used in `extract.spec` boundary case where after upfront permute,
    `state_index = 0` ≠ what `squeezing` could express. -/
@[step]
theorem KeccakState.extract_lanes_state.spec
    (self : KeccakState) (output : Slice U8) (full_lanes : Usize)
    (hsm : self.squeeze_mode = true)
    (hibsmod : self.input_block_size.val % 8 = 0)
    (halign : self.state_index.val % 8 = 0)
    (h_le : self.state_index.val ≤ self.input_block_size.val)
    (hibspos : 0 < self.input_block_size.val)
    (hibsmax : self.input_block_size.val ≤ 200)
    (hcap : 8 * full_lanes.val ≤ output.length) :
    KeccakState.extract_lanes self output full_lanes
    ⦃ (ks : KeccakState) (output' : Slice U8) =>
      output'.length = output.length ∧
      ks.input_block_size = self.input_block_size ∧
      ks.padding_value = self.padding_value ∧
      ks.squeeze_mode = true ∧
      output'.val = output.val.setSlice! 0
        (squeezeBytes (toBits self.state) self.state_index.val
                      self.input_block_size.val (8 * full_lanes.val)).toList ∧
      toBits ks.state = (squeezeAfter (toBits self.state) self.state_index.val
                          self.input_block_size.val (8 * full_lanes.val)).1 ∧
      ks.state_index.val = (squeezeAfter (toBits self.state) self.state_index.val
                             self.input_block_size.val (8 * full_lanes.val)).2 ⦄ := by
  unfold KeccakState.extract_lanes
  step*
  · exact and7_eq_zero_of_mod8 _ _ (by assumption) hibsmod
  · exact and7_eq_zero_of_mod8 _ _ (by assumption) halign
  obtain ⟨hout, hSeq, hidxeq⟩ := a_post4
  refine ⟨a_post1, ?_, ?_, ?_⟩
  · have h0_val : (0#usize : Usize).val = 0 := rfl
    rw [hout, h0_val, Nat.zero_mul, Nat.sub_zero]
  · rw [hSeq, Nat.sub_zero]
  · rw [hidxeq, Nat.sub_zero]

/-! ## Helpers for `extract_loop1.spec` -/

/-- Permute-branch counterpart of `squeezing_step_byte`. When the state hits the
    boundary (`state_index = rate`), the next byte requires a permute first; the
    new state is `KECCAK_f`-ed and `state_index` becomes `1` after reading the byte. -/
private theorem squeezing_step_byte_permute
    (self self1 : KeccakState) (g : GhostState) (byte : U8)
    (hsq : squeezing self g)
    (hstr1 : squeezingStructural self1 (g.squeeze [byte]))
    (hstate1 : toBits self1.state = Spec.SHA3.KECCAK_f (toBits self.state))
    (hidx1 : self1.state_index.val = 1)
    (hsi_eq : self.state_index.val = g.rate)
    (hbyte : byte = squeezeByte (Spec.SHA3.KECCAK_f (toBits self.state)) 0) :
    squeezing self1 (g.squeeze [byte]) := by
  refine ⟨hstr1, ?_⟩
  obtain ⟨_, hinv⟩ := hsq
  unfold squeezingInvariant at hinv ⊢
  simp only [GhostState.squeeze, List.length_append, List.length_singleton] at *
  set p := absorbBytes (Vector.replicate Spec.SHA3.b false) 0 g.rate g.absorbed
  set S_pad := padAndPermute p.1 p.2 g.rate g.padVal
  obtain ⟨h_state_eq, h_idx_eq, h_sqz_eq⟩ := hinv
  set p0 := squeezeAfter S_pad 0 g.rate g.squeezed.length with hp0
  have hp0_idx_eq : p0.2 = g.rate := by rw [← h_idx_eq]; exact hsi_eq
  have hsucc : squeezeAfter S_pad 0 g.rate (g.squeezed.length + 1) =
               (Spec.SHA3.KECCAK_f p0.1, 1) := by
    rw [squeezeAfter_succ, ← hp0]
    simp [hp0_idx_eq]
  refine ⟨?_, ?_, ?_⟩
  · rw [hsucc, hstate1, h_state_eq]
  · rw [hsucc, hidx1]
  · have hlen : (g.squeezed ++ [byte]).length = g.squeezed.length + 1 := by simp
    rw [hlen]
    rw [squeezeBytes_append S_pad 0 g.rate g.squeezed.length 1]
    rw [← h_sqz_eq]
    congr 1
    apply List.ext_getElem
    · simp [squeezeBytes]
    intro k hk1 _
    have hk : k < 1 := by simpa using hk1
    have hk0 : k = 0 := by omega
    subst hk0
    simp only [List.getElem_singleton]
    show byte = (squeezeBytes p0.1 p0.2 g.rate 1).toList[0]
    have h0 : (0 : Nat) < 1 := by omega
    rw [show (squeezeBytes p0.1 p0.2 g.rate 1).toList[0]
            = (squeezeBytes p0.1 p0.2 g.rate 1)[0] from
          by simp []]
    rw [squeezeBytes_getElem p0.1 p0.2 g.rate 1 0 h0]
    show byte =
      (let (S_k, idx_k) := (p0.1, p0.2)
       let (S_k', idx_k') := if idx_k = g.rate then (Spec.SHA3.KECCAK_f S_k, 0) else (S_k, idx_k)
       squeezeByte S_k' idx_k')
    simp only
    rw [if_pos hp0_idx_eq]
    rw [hbyte, h_state_eq]

/-! ### Decomposition of `extract_loop1`

Unlike `extract_loop0`, `extract_loop1`'s body has a cond-let permute step
*inside* the `rem > 0` branch. We fuse the entire 5-binding body
(cond-let permute + extract_byte + Slice.update + +1 + -1) into a single
helper `body_fused`. The helper's `@[step]` spec absorbs the permute /
no-permute case-split via the generic `squeezeAfter ... 1` /
`squeezeBytes ... 1` form, so callers stay uniform. -/

set_option maxRecDepth 1024 in
#decompose KeccakState.extract_loop1 KeccakState.extract_loop1.fold
  branch 0 (letRange 0 5) => KeccakState.extract_loop1.body_fused

/-- **Body spec for one iteration of `extract_loop1`.**

Captures one full iteration (optional permute + extract_byte + write +
index advance) in spec form. The post is expressed using
`squeezeBytes (toBits self.state) state_index ibs 1`  and
`squeezeAfter ... 1`, which collapse uniformly over the permute /
no-permute case-split. -/
@[step]
theorem KeccakState.extract_loop1.body_fused.spec
    (self : KeccakState) (output : Slice U8)
    (rem_result_len : Usize) (result_index : Usize)
    (g : GhostState) (h : squeezing self g)
    (hri_lt : result_index.val < output.length)
    (hrr_pos : 1 ≤ rem_result_len.val) :
    KeccakState.extract_loop1.body_fused self output rem_result_len result_index
    ⦃ (self1 : KeccakState) (s : Slice U8) (ri1 : Usize) (rr1 : Usize) =>
      let bytes : List U8 :=
        (squeezeBytes (toBits self.state) self.state_index.val
            self.input_block_size.val 1).toList
      let nextS : Vector Bool SHA3.b :=
        (squeezeAfter (toBits self.state) self.state_index.val
            self.input_block_size.val 1).1
      let nextIdx : Nat :=
        (squeezeAfter (toBits self.state) self.state_index.val
            self.input_block_size.val 1).2
      squeezing self1 (g.squeeze bytes) ∧
      self1.input_block_size = self.input_block_size ∧
      toBits self1.state = nextS ∧
      self1.state_index.val = nextIdx ∧
      s.length = output.length ∧
      s.val = output.val.setSlice! result_index.val bytes ∧
      ri1.val = result_index.val + 1 ∧
      rr1.val = rem_result_len.val - 1 ⦄ := by
  unfold KeccakState.extract_loop1.body_fused
  have hstr : squeezingStructural self g := h.1
  have hgr : self.input_block_size.val = g.rate := by
    have := hstr.2.2.1; scalar_tac
  have hgrlt : 8 * g.rate < SHA3.b := g.h_rate.2.1
  have hgrpos : 0 < g.rate := g.h_rate.1
  have hibsmax : self.input_block_size.val < 200 := by
    rw [hgr]; have : 8 * g.rate < 1600 := hgrlt; omega
  have hibspos : 0 < self.input_block_size.val := by rw [hgr]; exact hgrpos
  have hidx_le : self.state_index.val ≤ self.input_block_size.val := hstr.1
  by_cases hbnd : self.state_index = self.input_block_size
  · -- ── Permute branch: state_index = input_block_size ───────────────
    simp only [hbnd, ↓reduceIte]
    step  -- keccak_permute
    -- step auto-names the new array as `a` and its post as `i`.
    rename Std.Array U64 25#usize => x
    have hperm : toBits x = Spec.SHA3.KECCAK_f (toBits self.state) :=
      keccak_permute_toBits self.state x (by assumption)
    -- Structural for the post-permute state with current ghost.
    have hstr_pre : squeezingStructural
        { self with state := x, state_index := 0#u32 } g := by
      refine ⟨?_, hstr.2.1, hstr.2.2.1, hstr.2.2.2⟩
      show (0 : Nat) ≤ _; omega
    have hroom_pre : (0#u32 : U32).val < self.input_block_size.val := by
      show (0 : Nat) < _; omega
    step*
    -- Collect extract_byte's posts.  step* now auto-names them as
    -- `i1, self1, i1_post1, i1_post2, i1_post3, i1_post4`.
    have hbyte_eq : i1 = squeezeByte (Spec.SHA3.KECCAK_f (toBits self.state)) 0 := by
      apply U8.bv_eq_imp_eq
      have := i1_post4
      rw [hperm] at this
      simpa using this
    have hsi_eq : self.state_index.val = g.rate := by
      have h1 : self.state_index.val = self.input_block_size.val := by scalar_tac
      rw [h1, hgr]
    have hidx1' : self1.state_index.val = 1 := by
      have : self1.state_index.val = 0 + 1 := i1_post3
      omega
    have hself1_state : toBits self1.state = Spec.SHA3.KECCAK_f (toBits self.state) := by
      rw [i1_post2]; exact hperm
    have hsq1 : squeezing self1 (g.squeeze [i1]) :=
      squeezing_step_byte_permute self self1 g i1 h i1_post1 hself1_state hidx1' hsi_eq hbyte_eq
    subst hbyte_eq
    -- After step*: assemble the post.  Note: `simp only [hbnd, ↓reduceIte]`
    -- substituted `state_index → input_block_size` in the goal; state both
    -- `hsa1` and `hone` in the same form.
    have hsa1 : squeezeAfter (toBits self.state) self.input_block_size.val
        self.input_block_size.val 1 =
          (Spec.SHA3.KECCAK_f (toBits self.state), 1) := by
      rw [show (1 : Nat) = 0 + 1 from rfl, squeezeAfter_succ]
      simp [squeezeAfter_zero]
    have hone : (squeezeBytes (toBits self.state) self.input_block_size.val
                  self.input_block_size.val 1).toList =
        [squeezeByte (Spec.SHA3.KECCAK_f (toBits self.state)) 0] :=
      squeezeBytes_one_permute _ _
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · rw [hone]; exact hsq1
    · have h1 := i1_post1.2.2.1
      simp [GhostState.squeeze] at h1
      have h2 := hstr.2.2.1
      apply UScalar.eq_of_val_eq; omega
    · rw [hsa1]; exact hself1_state
    · rw [hsa1]; exact hidx1'
    · simp [s_post]
    · rw [hone, s_post]
      exact List.set_eq_setSlice!_singleton _ _ _ hri_lt
    · exact result_index1_post
    · exact rem_result_len1_post1
  · -- ── No-permute branch: state_index ≠ input_block_size ───────────
    simp only [hbnd, ↓reduceIte]
    have hsi_ne : self.state_index.val ≠ self.input_block_size.val := fun heq =>
      hbnd (UScalar.eq_of_val_eq heq)
    have hsi_lt : self.state_index.val < self.input_block_size.val := by omega
    step*
    -- step* introduces: i1, self1, i1_post1, i1_post2, i1_post3, i1_post4
    have hbyte_eq : i1 = squeezeByte (toBits self.state) self.state_index.val := by
      apply U8.bv_eq_imp_eq
      simpa using i1_post4
    have hsi_lt_rate : self.state_index.val < g.rate := by rw [← hgr]; exact hsi_lt
    have hsq1 : squeezing self1 (g.squeeze [i1]) :=
      squeezing_step_byte self self1 g i1 h i1_post1 i1_post2 i1_post3 hsi_lt_rate hbyte_eq
    subst hbyte_eq
    have hsa1 : squeezeAfter (toBits self.state) self.state_index.val
        self.input_block_size.val 1 =
          (toBits self.state, self.state_index.val + 1) := by
      rw [show (1 : Nat) = 0 + 1 from rfl, squeezeAfter_succ]
      simp [squeezeAfter_zero, hsi_ne]
    have hone : (squeezeBytes (toBits self.state) self.state_index.val
                  self.input_block_size.val 1).toList =
        [squeezeByte (toBits self.state) self.state_index.val] := by
      exact squeezeBytes_one_no_permute _ _ _ hsi_ne
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · rw [hone]; exact hsq1
    · have h1 := i1_post1.2.2.1
      simp [GhostState.squeeze] at h1
      have h2 := hstr.2.2.1
      apply UScalar.eq_of_val_eq; omega
    · rw [hsa1]; exact i1_post2 ▸ rfl
    · rw [hsa1]; exact i1_post3
    · simp [s_post]
    · rw [hone, s_post]
      exact List.set_eq_setSlice!_singleton _ _ _ hri_lt
    · exact result_index1_post
    · exact rem_result_len1_post1

/-- **Loop invariant for `extract_loop1`** — STRENGTHENED with FC.
Post-lane-alignment byte loop. Each iteration: if state_index = rate, permute
and reset; then extract_byte. HAS permute branch.

FC content: byte-by-byte squeeze with permute boundaries respected.
The proof is via a private auxiliary `extract_loop1_aux` (without `halign`),
since `halign` is consumed at the call site but not preserved across recursion. -/
private theorem extract_loop1_aux
    (self : KeccakState) (output : Slice U8)
    (rem_result_len : Usize) (result_index : Usize)
    (g : GhostState) (h : squeezing self g)
    (hbound : result_index.val + rem_result_len.val ≤ output.length) :
    KeccakState.extract_loop1 self output rem_result_len result_index
    ⦃ (ks : KeccakState) (output' : Slice U8) =>
      output'.length = output.length ∧
      let bytes := (squeezeBytes (toBits self.state) self.state_index.val
                    self.input_block_size.val rem_result_len.val).toList
      output'.val = output.val.setSlice! result_index.val bytes ∧
      squeezing ks (g.squeeze bytes) ⦄ := by
  -- Common derived facts.
  have hstr : squeezingStructural self g := h.1
  have hgr : self.input_block_size.val = g.rate := by
    have := hstr.2.2.1; scalar_tac
  rw [KeccakState.extract_loop1.fold]
  by_cases hrem : rem_result_len > 0#usize
  case neg =>
    -- ── Base case: rem = 0 ───────────────────────────────────────────
    simp only [hrem, ↓reduceIte]
    have hrem0 : rem_result_len.val = 0 := by simp at hrem; scalar_tac
    have hempty : (squeezeBytes (toBits self.state) self.state_index.val
                  self.input_block_size.val rem_result_len.val).toList = [] := by
      rw [hrem0]; simp [squeezeBytes]
    rw [hempty]
    refine ⟨rfl, ?_, ?_⟩
    · simp [List.setSlice!]
    · simpa using h
  case pos =>
    -- ── Recursive case: rem > 0 ─────────────────────────────────────
    simp only [hrem, ↓reduceIte]
    have hrr_pos : 1 ≤ rem_result_len.val := by scalar_tac
    have hri_lt : result_index.val < output.length := by omega
    -- One iteration of the body: optional permute + extract byte + write.
    let* ⟨self1, s, ri1, rr1,
           hsq1, hibs1, hself1_state, hself1_idx, hs_len, hs_val, hri1_eq, hrr1_eq⟩
      ← KeccakState.extract_loop1.body_fused.spec
    -- Recurse on the post-byte state.
    have hbound_inner : ri1.val + rr1.val ≤ s.length := by
      rw [hs_len, hri1_eq, hrr1_eq]; omega
    apply WP.spec_mono
      (extract_loop1_aux self1 s rr1 ri1 _ hsq1 hbound_inner)
    rintro ⟨ks_inner, output_inner⟩ ⟨hlen_eq, hfc_inner, hsq_inner⟩
    -- Reassemble.  `body_fused` returns one byte at the right spot;
    -- the IH covers the remaining `rem - 1` bytes; `squeezeBytes_append`
    -- glues them.
    have hself1_ibs : self1.input_block_size.val = self.input_block_size.val := by
      rw [hibs1]
    have hsplit : rem_result_len.val = 1 + rr1.val := by
      rw [hrr1_eq]; omega
    have hbytes_total :
        (squeezeBytes (toBits self.state) self.state_index.val
            self.input_block_size.val rem_result_len.val).toList =
          (squeezeBytes (toBits self.state) self.state_index.val
              self.input_block_size.val 1).toList ++
          (squeezeBytes (toBits self1.state) self1.state_index.val
              self1.input_block_size.val rr1.val).toList := by
      conv_lhs => rw [hsplit]
      rw [squeezeBytes_append]
      simp only
      rw [hself1_state, hself1_idx, hself1_ibs]
    have h1_len : ((squeezeBytes (toBits self.state) self.state_index.val
                    self.input_block_size.val 1).toList).length = 1 := by
      simp [squeezeBytes]
    have hN_inner : ((squeezeBytes (toBits self1.state) self1.state_index.val
                      self1.input_block_size.val rr1.val).toList).length = rr1.val := by
      simp [squeezeBytes]
    refine ⟨?_, ?_, ?_⟩
    · rw [hlen_eq]; exact hs_len
    · -- output side
      rw [hfc_inner, hs_val, hri1_eq, hbytes_total]
      rw [show result_index.val + 1
            = result_index.val + ((squeezeBytes (toBits self.state) self.state_index.val
                self.input_block_size.val 1).toList).length from by rw [h1_len]]
      have hroom : result_index.val + ((squeezeBytes (toBits self.state) self.state_index.val
              self.input_block_size.val 1).toList).length +
          ((squeezeBytes (toBits self1.state) self1.state_index.val
              self1.input_block_size.val rr1.val).toList).length
          ≤ output.val.length := by
        rw [h1_len, hN_inner]
        have h0 : output.val.length = output.length := rfl
        rw [h0, hrr1_eq]; omega
      rw [List.setSlice!_setSlice!_append output.val _ _ result_index.val hroom]
    · -- squeezing composition
      rw [hbytes_total, ← GhostState.squeeze_append]
      exact hsq_inner
termination_by rem_result_len.val
decreasing_by scalar_decr_tac

@[step]
theorem KeccakState.extract_loop1.spec
    (self : KeccakState) (output : Slice U8)
    (rem_result_len : Usize) (result_index : Usize)
    (g : GhostState) (h : squeezing self g)
    (_halign : self.state_index.val % 8 = 0)
    (hbound : result_index.val + rem_result_len.val ≤ output.length) :
    KeccakState.extract_loop1 self output rem_result_len result_index
    ⦃ (ks : KeccakState) (output' : Slice U8) =>
      output'.length = output.length ∧
      let bytes := (squeezeBytes (toBits self.state) self.state_index.val
                    self.input_block_size.val rem_result_len.val).toList
      output'.val = output.val.setSlice! result_index.val bytes ∧
      squeezing ks (g.squeeze bytes) ⦄ :=
  extract_loop1_aux self output rem_result_len result_index g h hbound

/-! ## `extract.spec` via `#decompose`.

The Rust `KeccakState.extract` body has eight top-level bindings.  We decompose
it into three named phases, each with its own `@[local step]` spec, so the
parent proof reduces to a clean `rw [fold]; step*; …` skeleton.

After the multi-clause `#decompose` below, the parent body is:

```
self.extract result wipe =
  let rem_result_len := result.len;
  do
    let (self3, result1, rem_result_len1, result_index) ←
      prologue self result rem_result_len
    let (self4, result2, rem_result_len2, result_index1) ←
      bulk_lanes self3 result1 rem_result_len1 result_index
    massert (rem_result_len2 < U64_NUM_BYTES)
    tail wipe self4 result2 rem_result_len2 result_index1
```

The helpers correspond to:
  * `prologue` — `apply_padding` + the optional boundary-permute +
    `extract_loop0` (the byte loop that empties the current rate-block).
    Encapsulates the three internal cases (no work, no permute, permute) so
    the post-prologue state always satisfies `squeezing self g'` for some
    `g' = g.squeeze prefix_bytes`, lane-aligned (`state_index % 8 = 0`).
  * `bulk_lanes` — `full_lanes` computation + the `if full_lanes > 0` block
    (`index_mut`, `extract_lanes`, indices update).  Consumes lane-aligned
    chunks of 8 bytes.
  * `tail` — `extract_loop1` (the post-lanes byte loop, including any internal
    boundary permute) + the trailing `if wipe then reset`.  Encapsulates the
    final wipe / no-wipe disjunct so the parent doesn't see a 3-way split. -/
set_option maxRecDepth 2048 in
#decompose KeccakState.extract KeccakState.extract.fold
  letRange 1 3 => KeccakState.extract.prologue
  letRange 2 2 => KeccakState.extract.bulk_lanes
  letRange 4 2 => KeccakState.extract.tail

/-! ### Small reusable helpers used by the parent `extract.spec` and its
boundary sub-spec.  Both encapsulate boilerplate shared across 5 (resp. 2)
sites. -/

/-- Congruence for `GhostState.init`: equal rate and padding value give equal
ghost (the `h_rate` proof is irrelevant up to propositional equality). -/
private theorem GhostState.init_congr {r1 r2 : Nat} {p1 p2 : U8}
    {h1 : 0 < r1 ∧ 8 * r1 < SHA3.b ∧ r1 % 8 = 0}
    {h2 : 0 < r2 ∧ 8 * r2 < SHA3.b ∧ r2 % 8 = 0}
    (hr : r1 = r2) (hp : p1 = p2) :
    GhostState.init r1 p1 h1 = GhostState.init r2 p2 h2 := by
  subst hr; subst hp; rfl

/-- Two-chunk extract bridge.  Given the `squeezing self_post`-style FC for a
post-state that has squeezed `P ++ T` from `g`, plus the input-side
`squeezing self`-style FC for `g.squeezed` itself, conclude that
`(extractOutput g (|P| + |T|)).toList = P ++ T`.

This packages the algebraic content of the two `h_extract_eq` blocks in
`spec_boundary` (FL>0 and FL=0 sub-cases) into one ~10-line lemma. -/
private theorem extractOutput_eq_append_of_squeezing
    (g : GhostState) (P T : List U8) (output_len : Nat)
    (hPT_len : P.length + T.length = output_len)
    (hsqz_old : g.squeezed =
      (squeezeBytes
        (padAndPermute (absorbBytes (Vector.replicate SHA3.b false) 0 g.rate g.absorbed).1
                       (absorbBytes (Vector.replicate SHA3.b false) 0 g.rate g.absorbed).2
                       g.rate g.padVal)
        0 g.rate g.squeezed.length).toList)
    (h : ((g.squeeze P).squeeze T).squeezed =
         (squeezeBytes
            (padAndPermute (absorbBytes (Vector.replicate SHA3.b false) 0 g.rate g.absorbed).1
                           (absorbBytes (Vector.replicate SHA3.b false) 0 g.rate g.absorbed).2
                           g.rate g.padVal)
            0 g.rate ((g.squeeze P).squeeze T).squeezed.length).toList) :
    (extractOutput g output_len).toList = P ++ T := by
  set S_pad := padAndPermute
    (absorbBytes (Vector.replicate SHA3.b false) 0 g.rate g.absorbed).1
    (absorbBytes (Vector.replicate SHA3.b false) 0 g.rate g.absorbed).2
    g.rate g.padVal with hSpad
  have hgF_squeezed : ((g.squeeze P).squeeze T).squeezed = g.squeezed ++ P ++ T := by
    simp only [GhostState.squeeze, List.append_assoc]
  rw [hgF_squeezed] at h
  have hlen_eq : (g.squeezed ++ P ++ T).length = g.squeezed.length + output_len := by
    simp only [List.length_append]; omega
  rw [hlen_eq] at h
  rw [squeezeBytes_append S_pad 0 g.rate g.squeezed.length output_len] at h
  rw [← hsqz_old] at h
  have h3' : P ++ T =
      (squeezeBytes (squeezeAfter S_pad 0 g.rate g.squeezed.length).1
                    (squeezeAfter S_pad 0 g.rate g.squeezed.length).2
                    g.rate output_len).toList := by
    simp only [List.append_assoc] at h
    exact List.append_cancel_left h
  unfold extractOutput
  exact h3'.symm

/-! ### Spec for `extract.bulk_lanes`.

`bulk_lanes` consumes `full_lanes := rrl / 8` complete lanes (8 bytes each)
from the current sponge state, writing them at offset `result_index` of
`result1`.  Pre-state must be `squeezing` and lane-aligned; post-state is
`squeezing` of the bytes-extended ghost, still lane-aligned, with
`rrl2.val < 8`.

Internally uses `extract_lanes.spec` on a subslice obtained via `index_mut`.
-/
@[local step]
theorem KeccakState.extract.bulk_lanes.spec
    (self3 : KeccakState) (result1 : Slice U8)
    (rem_result_len1 : Usize) (result_index : Usize)
    (g3 : GhostState) (h : squeezing self3 g3)
    (halign : rem_result_len1.val > 0 → self3.state_index.val % 8 = 0)
    (hbound : result_index.val + rem_result_len1.val ≤ result1.length) :
    KeccakState.extract.bulk_lanes self3 result1 rem_result_len1 result_index
    ⦃ (self4 : KeccakState) (result2 : Slice U8)
      (rem_result_len2 : Usize) (result_index1 : Usize) =>
      let full_lanes : Nat := rem_result_len1.val / 8
      let bytes := (squeezeBytes (toBits self3.state) self3.state_index.val
                    self3.input_block_size.val (8 * full_lanes)).toList
      result2.length = result1.length ∧
      result2.val = result1.val.setSlice! result_index.val bytes ∧
      rem_result_len2.val = rem_result_len1.val - 8 * full_lanes ∧
      rem_result_len2.val < 8 ∧
      result_index1.val = result_index.val + 8 * full_lanes ∧
      result_index1.val + rem_result_len2.val ≤ result2.length ∧
      (rem_result_len2.val > 0 → self4.state_index.val % 8 = 0) ∧
      squeezing self4 (g3.squeeze bytes) ⦄ := by
  unfold KeccakState.extract.bulk_lanes
  have hU64 : U64_NUM_BYTES.val = 8 := by native_decide
  step  -- full_lanes := rrl / 8
  have hfl_val : full_lanes.val = rem_result_len1.val / 8 := by
    rw [full_lanes_post]; simp [hU64]
  by_cases hfl : full_lanes > 0#usize
  · -- ── full_lanes > 0: take a subslice and call extract_lanes ───────
    simp only [hfl, ↓reduceIte]
    have hfl_pos : 0 < full_lanes.val := hfl
    have hfl_cap : 8 * full_lanes.val ≤ rem_result_len1.val := by
      rw [hfl_val]; have := Nat.div_mul_le_self rem_result_len1.val 8; omega
    -- full_lanes > 0 ⇒ rem_result_len1 ≥ 8 > 0, so we can extract halign.
    have hrr_pos : rem_result_len1.val > 0 := by omega
    have halign' : self3.state_index.val % 8 = 0 := halign hrr_pos
    -- Disambiguate against `extract_lanes_state.spec` (both `@[step]`):
    -- explicit calls force the FC-bearing `extract_lanes.spec`.
    let* ⟨ spair, hs_eq, hs_len, hs_back ⟩ ←
      core.slice.index.SliceIndexRangeFromUsizeSlice.index_mut.step_spec
    obtain ⟨s, idx_back⟩ := spair
    dsimp only at hs_eq hs_len hs_back ⊢
    have hcap_sub : 8 * full_lanes.val ≤ s.length := by rw [hs_len]; omega
    let* ⟨self5pair, hs1_len, hs1_val, hs1_align, hs1_sqz⟩ ←
      KeccakState.extract_lanes.spec self3 s full_lanes g3 h halign' hcap_sub
    obtain ⟨self5, s1⟩ := self5pair
    dsimp only at hs1_len hs1_val hs1_align hs1_sqz ⊢
    -- Trailing arithmetic (each `step` introduces a let-binding; some
    -- bindings come out anonymous, so we discharge by `scalar_tac`).
    step  -- i := full_lanes * U64_NUM_BYTES
    step  -- result_index2 := result_index + i
    step  -- rem_result_len3 := rem_result_len1 - i
    -- Local lemma: idx_back preserves length.
    have hib_len : ∀ s' : Slice U8, (idx_back s').length = result1.length := by
      intro s'
      show (idx_back s').val.length = result1.val.length
      rw [hs_back s']; simp
    -- Bridge: 8 * full_lanes.val = 8 * (rem_result_len1.val / 8).
    have hfl_subst : 8 * full_lanes.val = 8 * (rem_result_len1.val / 8) := by
      rw [hfl_val]
    refine ⟨hib_len s1, ?_, ?_, ?_, ?_, ?_, fun _ => hs1_align, ?_⟩
    · -- val = setSlice! result_index bytes.
      show (idx_back s1).val = _
      rw [hs_back, hs1_val, hs_eq, ← hfl_subst]
      rw [List.setSlice!_drop_setSlice! _ _ _ (by simp [squeezeBytes]; scalar_tac)]
    · scalar_tac
    · scalar_tac
    · scalar_tac
    · rw [hib_len]; scalar_tac
    · rw [← hfl_subst]; exact hs1_sqz
  · -- ── full_lanes = 0: no-op ──────────────────────────────────────
    simp only [hfl, ↓reduceIte]
    have hfl_zero : full_lanes.val = 0 := by simp at hfl; scalar_tac
    have hfl_div : rem_result_len1.val / 8 = 0 := by rw [← hfl_val]; exact hfl_zero
    have hrr_lt8 : rem_result_len1.val < 8 :=
      (Nat.div_eq_zero_iff_lt (by decide)).mp hfl_div
    have hempty : (squeezeBytes (toBits self3.state) self3.state_index.val
                  self3.input_block_size.val (8 * (rem_result_len1.val / 8))).toList = [] := by
      simp [hfl_div, squeezeBytes]
    refine ⟨rfl, ?_, ?_, hrr_lt8, ?_, hbound, halign, ?_⟩
    · simp [hempty, List.setSlice!]
    · rw [hfl_div]; omega
    · rw [hfl_div]; omega
    · simp only [hempty]
      have : g3.squeeze [] = g3 := by cases g3; simp [GhostState.squeeze]
      rw [this]; exact h

/-! ### Spec for `extract.prologue` (non-boundary, rem > 0).

`prologue` is `apply_padding` (if absorbing) + the optional boundary-permute
(if squeezing + rem > 0 + state_index = ibs) + `extract_loop0` (lane-align
or rem-drain).

This spec covers **two of the four cases** (the chainable ones):
  * **Case A** — `squeezing self g`, `rem_result_len > 0`, no boundary: byte
    loop emits `(8 - state_index % 8) % 8` bytes to lane-align.
  * **Case B** — `absorbing self g`, `rem_result_len > 0`: `apply_padding`
    then `extract_loop0` no-op (post-pad state_index = 0 is already aligned).

The **rem = 0 case** is handled inline in the parent (it requires
`extract_loop1_aux` rather than the aligned `extract_loop1.spec`, since
post-prologue alignment isn't guaranteed when no bytes are consumed).

The **boundary case** (squeezing + rem > 0 + state_index = ibs) is excluded
via the `hno_boundary` hypothesis and handled inline in the parent
`extract.spec`, since after the boundary permute the state cannot be
expressed as `squeezing _ g'` for any `g'`.

In both covered cases, the byte prefix emitted by the prologue equals
`(extractOutput g result_index.val).toList`, by
`extractOutput_eq_squeezeBytes_of_squeezing`. -/
set_option maxRecDepth 4096 in
@[local step]
theorem KeccakState.extract.prologue.spec
    (self : KeccakState) (result : Slice U8) (rem_result_len : Usize)
    (g : GhostState)
    (h : absorbing self g ∨ squeezing self g)
    (hrem : rem_result_len > 0#usize)
    (hno_boundary :
      self.squeeze_mode = true → self.state_index ≠ self.input_block_size)
    (hbound : rem_result_len.val ≤ result.length) :
    KeccakState.extract.prologue self result rem_result_len
    ⦃ (self3 : KeccakState) (result1 : Slice U8)
      (rem_result_len1 : Usize) (result_index : Usize) =>
      result1.length = result.length ∧
      rem_result_len1.val + result_index.val = rem_result_len.val ∧
      result_index.val + rem_result_len1.val ≤ result1.length ∧
      result1.val = result.val.setSlice! 0 (extractOutput g result_index.val).toList ∧
      (rem_result_len1.val > 0 → self3.state_index.val % 8 = 0) ∧
      self3.input_block_size.val = g.rate ∧
      self3.padding_value = g.padVal ∧
      squeezing self3 (g.squeeze (extractOutput g result_index.val).toList) ⦄ := by
  unfold KeccakState.extract.prologue
  have hgrpos : 0 < g.rate := g.h_rate.1
  have hgrmod : g.rate % 8 = 0 := g.h_rate.2.2
  by_cases hsm : self.squeeze_mode = true
  · -- ── Case A: Squeezing branch (no boundary) ──────────────────────
    have hsq_self : squeezing self g := by
      rcases h with hab | hsq
      · exfalso; exact hab.1.2.1 hsm
      · exact hsq
    have hstr := hsq_self.1
    have hgr_val : self.input_block_size.val = g.rate := by
      have := hstr.2.2.1; scalar_tac
    have hpadval : self.padding_value = g.padVal := hstr.2.2.2
    have hbnd_ne : self.state_index ≠ self.input_block_size := hno_boundary hsm
    -- Reduce the prologue: self1 = self, boundary if fails, self2 = self.
    simp only [hsm, ↓reduceIte, bind_tc_ok]
    simp only [hrem, ↓reduceIte]
    simp only [hbnd_ne, ↓reduceIte, bind_tc_ok]
    -- Run extract_loop0.spec on the synthetic record (= self structurally).
    have hbnd0 : 0#usize.val + rem_result_len.val ≤ result.length := by scalar_tac
    set rec : KeccakState :=
      { state := self.state, input_block_size := self.input_block_size,
        state_index := self.state_index, padding_value := self.padding_value,
        squeeze_mode := true } with hrec_def
    have hrec_eq : rec = self := by
      rw [hrec_def]; rcases self with ⟨_, _, _, _, sm⟩; cases hsm; rfl
    have hsq_rec : squeezing rec g := hrec_eq ▸ hsq_self
    let* ⟨self3, result1, rem_result_len1, result_index, hsum, hri_le, hlen3, hfc3, hsq3,
          hidx_eq, hmod3⟩ ←
      KeccakState.extract_loop0.spec rec result rem_result_len 0#usize g hsq_rec hbnd0
    -- Bridge: pre_bytes = (extractOutput g result_index.val).toList.
    have hstate_rec : rec.state = self.state := by rw [hrec_eq]
    have hibs_rec_val : rec.input_block_size.val = self.input_block_size.val := by
      rw [hrec_eq]
    have hidx_rec_val : rec.state_index.val = self.state_index.val := by rw [hrec_eq]
    have hcons_simp : result_index.val - (0#usize).val = result_index.val := by simp
    have hbridge :
        (squeezeBytes (toBits rec.state) rec.state_index.val
              rec.input_block_size.val (result_index.val - (0#usize).val)).toList =
        (extractOutput g result_index.val).toList := by
      rw [hcons_simp, hstate_rec, hidx_rec_val, hibs_rec_val]
      rw [extractOutput_eq_squeezeBytes_of_squeezing hsq_self result_index.val]
      congr 1
      rw [hgr_val]
    -- Structural facts on self3 — use the squeezing predicate.
    have hstr3 := hsq3.1
    have hibs3_eq : self3.input_block_size.val = g.rate := hstr3.2.2.1
    have hpv3_eq : self3.padding_value = g.padVal := hstr3.2.2.2
    have hsum_val : rem_result_len1.val + result_index.val = rem_result_len.val := by
      have := hsum; simp at this; exact this
    refine ⟨hlen3, hsum_val, ?_, ?_, hmod3, hibs3_eq, hpv3_eq, ?_⟩
    · -- bound preserved
      rw [hlen3]; omega
    · -- FC
      rw [hfc3, hbridge]
    · -- squeezing
      rw [← hbridge]; exact hsq3
  · -- ── Case B: Absorbing branch ────────────────────────────────────
    have hab_self : absorbing self g := by
      rcases h with hab | hsq
      · exact hab
      · exfalso; exact hsm hsq.1.2.1
    have hroom : self.state_index.val < self.input_block_size.val := hab_self.2.1
    have hsqueezed_nil : g.squeezed = [] := hab_self.1.2.2.2.2
    -- Reduce: self_pad = apply_padding self.
    have hsm_false : (self.squeeze_mode = true) = False := eq_false hsm
    simp only [hsm_false, ↓reduceIte]
    let* ⟨self_pad, hsq_pad⟩ ← KeccakState.apply_padding.spec self g hab_self hroom
    -- Derive state_index = 0 from squeezing self_pad g + g.squeezed = [].
    have hidx_pad_zero : self_pad.state_index.val = 0 := by
      have := hsq_pad.2.2.1
      rw [hsqueezed_nil] at this
      simp [squeezeAfter] at this
      exact this
    have hgr_pad_val : self_pad.input_block_size.val = g.rate := by
      have := hsq_pad.1.2.2.1; scalar_tac
    have hpv_pad : self_pad.padding_value = g.padVal := hsq_pad.1.2.2.2
    have hsm_pad : self_pad.squeeze_mode = true := hsq_pad.1.2.1
    have hibs_pad_pos : 0 < self_pad.input_block_size.val := by
      rw [hgr_pad_val]; exact hgrpos
    have hbnd_ne_pad : self_pad.state_index ≠ self_pad.input_block_size := by
      intro hbe; have := congrArg UScalar.val hbe; try simp at this
      rw [hidx_pad_zero] at this; omega
    -- Reduce inner ifs.
    simp only [hrem, ↓reduceIte]
    simp only [hbnd_ne_pad, ↓reduceIte, bind_tc_ok]
    -- Build the synthetic record `rec` with a fresh name (avoiding shadowing).
    set rec : KeccakState :=
      { state := self_pad.state, input_block_size := self_pad.input_block_size,
        state_index := self_pad.state_index, padding_value := self_pad.padding_value,
        squeeze_mode := self_pad.squeeze_mode } with hrec_def
    have hrec_eq : rec = self_pad := by
      rw [hrec_def]
    -- Call extract_loop0_aligned_spec: rec.state_index = 0 is aligned → no-op.
    have halign_rec : rec.state_index.val % 8 = 0 := by rw [hrec_eq, hidx_pad_zero]
    step with KeccakState.extract_loop0_aligned_spec
      as ⟨self3, result1, rem_result_len1, result_index,
          hself3_eq, houtval3, hlen3, hrem3_eq, hri3_eq⟩
    have hself3_pad : self3 = self_pad := hself3_eq.trans hrec_eq
    have hri3_zero : result_index.val = 0 := by rw [hri3_eq]; rfl
    have hrem1_eq : rem_result_len1.val = rem_result_len.val := by rw [hrem3_eq]
    refine ⟨hlen3, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · -- rem_result_len1 + result_index = rem_result_len
      rw [hrem1_eq, hri3_zero]; omega
    · -- bound
      rw [hlen3, hri3_zero, hrem1_eq]; omega
    · -- FC
      rw [show (extractOutput g result_index.val).toList = [] from by
          rw [hri3_zero]; exact extractOutput_zero g]
      have houtv : result1.val = result.val := houtval3
      rw [houtv]; unfold List.setSlice!; simp
    · -- aligned conditional
      intro _; rw [hself3_pad, hidx_pad_zero]
    · -- ibs.val = g.rate
      rw [hself3_pad]; exact hgr_pad_val
    · -- padding
      rw [hself3_pad]; exact hpv_pad
    · -- squeezing
      rw [show (extractOutput g result_index.val).toList = [] from by
          rw [hri3_zero]; exact extractOutput_zero g]
      rw [GhostState.squeeze_nil]
      rw [hself3_pad]; exact hsq_pad

/-! ### Spec for `extract.prologue` (rem = 0 case).

When `rem_result_len = 0`, the Rust boundary check `if rem > 0 ∧ state_index = ibs`
fires the false branch (rem = 0), so no permute happens, and `extract_loop0`
with `rem = 0` is a no-op (base case).  The post-state is squeezing the
unchanged ghost (or the post-apply_padding ghost, both equal to `g` since
no bytes were extracted). -/
set_option maxRecDepth 4096 in
private theorem KeccakState.extract.prologue.spec_zero
    (self : KeccakState) (result : Slice U8) (rem_result_len : Usize)
    (g : GhostState)
    (h : absorbing self g ∨ squeezing self g)
    (hrem0 : rem_result_len.val = 0)
    (hbound : rem_result_len.val ≤ result.length) :
    KeccakState.extract.prologue self result rem_result_len
    ⦃ (self3 : KeccakState) (result1 : Slice U8)
      (rem_result_len1 : Usize) (result_index : Usize) =>
      result1.length = result.length ∧
      rem_result_len1.val + result_index.val = rem_result_len.val ∧
      result_index.val + rem_result_len1.val ≤ result1.length ∧
      result1.val = result.val.setSlice! 0 (extractOutput g result_index.val).toList ∧
      (rem_result_len1.val > 0 → self3.state_index.val % 8 = 0) ∧
      self3.input_block_size.val = g.rate ∧
      self3.padding_value = g.padVal ∧
      squeezing self3 (g.squeeze (extractOutput g result_index.val).toList) ⦄ := by
  unfold KeccakState.extract.prologue
  have hgrpos : 0 < g.rate := g.h_rate.1
  have hgrmod : g.rate % 8 = 0 := g.h_rate.2.2
  have hrem_neg : ¬ (rem_result_len > 0#usize) := by
    intro hp; have : rem_result_len.val > 0 := hp; omega
  have hrem_false : (rem_result_len > 0#usize) = False := eq_false hrem_neg
  by_cases hsm : self.squeeze_mode = true
  · -- ── Case A: Squeezing branch (rem = 0) ─────────────────────────
    have hsq_self : squeezing self g := by
      rcases h with hab | hsq
      · exfalso; exact hab.1.2.1 hsm
      · exact hsq
    have hstr := hsq_self.1
    have hgr_val : self.input_block_size.val = g.rate := by
      have := hstr.2.2.1; scalar_tac
    have hpadval : self.padding_value = g.padVal := hstr.2.2.2
    simp only [hsm, ↓reduceIte, bind_tc_ok]
    simp only [hrem_false, ↓reduceIte]
    have hbnd0 : 0#usize.val + rem_result_len.val ≤ result.length := by scalar_tac
    let* ⟨self3, result1, rem_result_len1, result_index, hsum, hri_le, hlen3, hfc3, hsq3,
          hidx_eq, hmod3⟩ ←
      KeccakState.extract_loop0.spec self result rem_result_len 0#usize g hsq_self hbnd0
    -- rem = 0 ⇒ rem_result_len1 = 0 and result_index = 0.
    have hsum_val : rem_result_len1.val + result_index.val = rem_result_len.val := by
      have h0 := hsum; simp at h0; exact h0
    have hri_zero : result_index.val = 0 := by omega
    have hrem1_zero : rem_result_len1.val = 0 := by omega
    have hconsumed_zero : result_index.val - (0#usize : Usize).val = 0 := by
      rw [hri_zero]; rfl
    have hbytes_empty : (squeezeBytes (toBits self.state) self.state_index.val
                  self.input_block_size.val (result_index.val - (0#usize).val)).toList = [] := by
      rw [hconsumed_zero]; simp [squeezeBytes]
    have hext0 : (extractOutput g result_index.val).toList = [] := by
      rw [hri_zero]; exact extractOutput_zero g
    have hibs3_eq : self3.input_block_size.val = g.rate := hsq3.1.2.2.1
    have hpv3_eq : self3.padding_value = g.padVal := hsq3.1.2.2.2
    refine ⟨hlen3, hsum_val, ?_, ?_, hmod3, hibs3_eq, hpv3_eq, ?_⟩
    · rw [hlen3]; omega
    · rw [hfc3, hbytes_empty, hext0]
    · rw [hext0, GhostState.squeeze_nil]
      rw [show g = g.squeeze [] from (GhostState.squeeze_nil g).symm]
      rw [← hbytes_empty]
      exact hsq3
  · -- ── Case B: Absorbing branch (rem = 0) ─────────────────────────
    have hab_self : absorbing self g := by
      rcases h with hab | hsq
      · exact hab
      · exfalso; exact hsm hsq.1.2.1
    have hroom : self.state_index.val < self.input_block_size.val := hab_self.2.1
    have hsqueezed_nil : g.squeezed = [] := hab_self.1.2.2.2.2
    have hsm_false : (self.squeeze_mode = true) = False := eq_false hsm
    simp only [hsm_false, ↓reduceIte]
    let* ⟨self_pad, hsq_pad⟩ ← KeccakState.apply_padding.spec self g hab_self hroom
    have hidx_pad_zero : self_pad.state_index.val = 0 := by
      have := hsq_pad.2.2.1
      rw [hsqueezed_nil] at this
      simp [squeezeAfter] at this
      exact this
    have hgr_pad_val : self_pad.input_block_size.val = g.rate := by
      have := hsq_pad.1.2.2.1; scalar_tac
    have hpv_pad : self_pad.padding_value = g.padVal := hsq_pad.1.2.2.2
    have hsm_pad : self_pad.squeeze_mode = true := hsq_pad.1.2.1
    simp only [hrem_false, ↓reduceIte]
    set rec : KeccakState :=
      { state := self_pad.state, input_block_size := self_pad.input_block_size,
        state_index := self_pad.state_index, padding_value := self_pad.padding_value,
        squeeze_mode := self_pad.squeeze_mode } with hrec_def
    have hrec_eq : rec = self_pad := by
      rw [hrec_def]
    have halign_rec : rec.state_index.val % 8 = 0 := by rw [hrec_eq, hidx_pad_zero]
    step with KeccakState.extract_loop0_aligned_spec
      as ⟨self3, result1, rem_result_len1, result_index,
          hself3_eq, houtval3, hlen3, hrem3_eq, hri3_eq⟩
    have hself3_pad : self3 = self_pad := hself3_eq.trans hrec_eq
    have hri3_zero : result_index.val = 0 := by rw [hri3_eq]; rfl
    have hrem1_eq : rem_result_len1.val = rem_result_len.val := by rw [hrem3_eq]
    refine ⟨hlen3, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · rw [hrem1_eq, hri3_zero]; omega
    · rw [hlen3, hri3_zero, hrem1_eq]; omega
    · rw [show (extractOutput g result_index.val).toList = [] from by
          rw [hri3_zero]; exact extractOutput_zero g]
      have houtv : result1.val = result.val := houtval3
      rw [houtv]; unfold List.setSlice!; simp
    · intro hp; rw [hrem1_eq] at hp; omega
    · rw [hself3_pad]; exact hgr_pad_val
    · rw [hself3_pad]; exact hpv_pad
    · rw [show (extractOutput g result_index.val).toList = [] from by
          rw [hri3_zero]; exact extractOutput_zero g]
      rw [GhostState.squeeze_nil]
      rw [hself3_pad]; exact hsq_pad

/-! ### Spec for `extract.tail`.

`tail` is `extract_loop1` (which consumes `rem` ≤ 7 trailing bytes) followed
by the optional `reset` triggered by `wipe`.  Its FC postcondition:
  * `output'` is `result2` with the tail bytes written;
  * the final state is either `absorbing (init …)` (wipe = true) or
    `squeezing (g.squeeze bytes)` (wipe = false).

By encapsulating the `if wipe` inside this helper, the parent proof avoids
the three-goal split that `step*` would otherwise produce. -/
@[local step]
theorem KeccakState.extract.tail.spec
    (wipe : Bool) (self4 : KeccakState) (result2 : Slice U8)
    (rem_result_len2 : Usize) (result_index1 : Usize)
    (g' : GhostState) (h : squeezing self4 g')
    (hbound : result_index1.val + rem_result_len2.val ≤ result2.length) :
    KeccakState.extract.tail wipe self4 result2 rem_result_len2 result_index1
    ⦃ (ks : KeccakState) (output' : Slice U8) =>
      output'.length = result2.length ∧
      let bytes := (squeezeBytes (toBits self4.state) self4.state_index.val
                    self4.input_block_size.val rem_result_len2.val).toList
      output'.val = result2.val.setSlice! result_index1.val bytes ∧
      (if wipe then absorbing ks (.init g'.rate g'.padVal g'.h_rate)
       else squeezing ks (g'.squeeze bytes)) ⦄ := by
  unfold KeccakState.extract.tail
  let* ⟨self5, result3, hlen5, houtval5, hsq5⟩ ←
    extract_loop1_aux self4 result2 rem_result_len2 result_index1 g' h hbound
  set bytes :=
    (squeezeBytes (toBits self4.state) self4.state_index.val
                  self4.input_block_size.val rem_result_len2.val).toList with hbytes_def
  by_cases hw : wipe = true
  · -- wipe = true: apply reset.
    simp only [hw, ↓reduceIte]
    have hstr : squeezingStructural self5 (g'.squeeze bytes) := hsq5.1
    -- `(g'.squeeze bytes).rate = g'.rate` definitionally.
    have hibsv : self5.input_block_size.val = g'.rate := by
      have := hstr.2.2.1
      show self5.input_block_size.val = (g'.squeeze bytes).rate
      scalar_tac
    have hpadval : self5.padding_value = g'.padVal := hstr.2.2.2
    have hibspos : (0 : Nat) < self5.input_block_size.val := by
      rw [hibsv]; exact g'.h_rate.1
    have hibslt : 8 * self5.input_block_size.val < SHA3.b := by
      rw [hibsv]; exact g'.h_rate.2.1
    have hibsmod : self5.input_block_size.val % 8 = 0 := by
      rw [hibsv]; exact g'.h_rate.2.2
    let* ⟨self6, habs6, _hidx0⟩ ←
      KeccakState.reset.spec self5 ⟨hibspos, hibslt, hibsmod⟩
    refine ⟨hlen5, houtval5, ?_⟩
    rw [← GhostState.init_congr hibsv hpadval]; exact habs6
  · -- wipe = false: just thread through.
    simp only [show (wipe = true) = False from eq_false hw, ↓reduceIte]
    refine ⟨hlen5, houtval5, ?_⟩
    exact hsq5

/-! ### Boundary-case spec for `extract`.

The boundary case — `squeezing self g` + `output.len > 0` + `state_index = ibs` —
cannot be handled via `prologue.spec` / `bulk_lanes.spec` / `tail.spec`, because
after the up-front `keccak_permute` the resulting state has `state_index = 0`
but `(squeezeAfter S 0 rate |g.squeezed|).2 = rate` at the boundary, so no
`squeezing self_post_permute g'` predicate fits.

Instead we step through `extract`'s body directly, using:
  * `keccak_permute.spec` + `keccak_permute_toBits` (state ↦ KECCAK_f);
  * `extract_loop0_aligned_spec` (no-op since post-permute `state_index = 0`);
  * for `full_lanes > 0`: `extract_lanes_state.spec` (raw state-level spec);
  * for `full_lanes = 0`: `extract_byte.spec` + `squeezing_step_byte_permute`
    + `extract_loop1_aux`.

Squeezing is reconstructed AFTER lane (or byte) extraction via
`squeezeAfter_post_full_block` / `squeezeBytes_post_full_block` from
BridgeComp. -/
set_option maxHeartbeats 6400000 in
set_option Aeneas.Deprecated.progressWarning false in
private theorem KeccakState.extract.spec_boundary
    (self : KeccakState) (output : Slice U8) (wipe : Bool)
    (g : GhostState) (hsq_self : squeezing self g)
    (hlen_pos : output.len > 0#usize)
    (hbnd : self.state_index = self.input_block_size) :
    KeccakState.extract self output wipe
    ⦃ (ks : KeccakState) (output' : Slice U8) =>
      output'.length = output.length ∧
      output'.val = (extractOutput g output.length).toList ∧
      if wipe then absorbing ks (.init g.rate g.padVal g.h_rate)
      else squeezing ks (g.squeeze output'.val) ⦄ := by
  -- ── Setup ─────────────────────────────────────────────────────────
  have hrate : (0 : Nat) < g.rate := g.h_rate.1
  have hgrlt : 8 * g.rate < SHA3.b := g.h_rate.2.1
  have hgrmod : g.rate % 8 = 0 := g.h_rate.2.2
  have holen : output.len.val = output.length := by simp [Slice.len, Slice.length]
  have hU64 : U64_NUM_BYTES.val = (8 : Nat) := by native_decide
  have hsm : self.squeeze_mode = true := hsq_self.1.2.1
  have hstr : squeezingStructural self g := hsq_self.1
  have hibs_val : self.input_block_size.val = g.rate := by
    have := hstr.2.2.1; scalar_tac
  have hpadval_eq : self.padding_value = g.padVal := hstr.2.2.2
  have hgr_rate : (↑self.input_block_size : Nat) = g.rate := hibs_val
  have hibsmod : (↑self.input_block_size : Nat) % 8 = 0 := by rw [hgr_rate]; exact hgrmod
  have hibspos : (0 : Nat) < ↑self.input_block_size := by linarith [hgr_rate]
  have hibsmax : (↑self.input_block_size : Nat) ≤ 200 := by
    rw [hgr_rate]; have : 8 * g.rate < 1600 := hgrlt; omega
  have hidx_le : self.state_index.val ≤ self.input_block_size.val := hstr.1
  unfold KeccakState.extract
  simp only [hsm, ↓reduceIte]
  step*
  simp only [hlen_pos, ↓reduceIte]
  simp only [hbnd, ↓reduceIte]
  -- Setup useful facts.
  have hsi_eq : self.state_index.val = g.rate := by
    have h1 : self.state_index.val = self.input_block_size.val := by scalar_tac
    rw [h1, hibs_val]
  have hsqz_old : g.squeezed = (squeezeBytes
      (padAndPermute (absorbBytes (Vector.replicate SHA3.b false) 0 g.rate g.absorbed).1
        (absorbBytes (Vector.replicate SHA3.b false) 0 g.rate g.absorbed).2 g.rate g.padVal)
      0 g.rate g.squeezed.length).toList := hsq_self.2.2.2
  set S_pad := padAndPermute (absorbBytes (Vector.replicate SHA3.b false) 0 g.rate g.absorbed).1
    (absorbBytes (Vector.replicate SHA3.b false) 0 g.rate g.absorbed).2 g.rate g.padVal
    with hSpad_def
  have hself_state : toBits self.state =
      (squeezeAfter S_pad 0 g.rate g.squeezed.length).1 := hsq_self.2.1
  have hself_idx : self.state_index.val =
      (squeezeAfter S_pad 0 g.rate g.squeezed.length).2 := hsq_self.2.2.1
  -- Apply keccak_permute.spec.
  progress with keccak_permute.spec as ⟨ a, ha_post ⟩
  have hperm_state : toBits a = SHA3.KECCAK_f (toBits self.state) :=
    keccak_permute_toBits self.state a ha_post
  -- After permute: state_index = 0 (aligned). Use the aligned helper to
  -- pass through `extract_loop0` as a no-op without needing `squeezing`.
  progress with KeccakState.extract_loop0_aligned_spec
    as ⟨ks_C0, out_C0, rem_C0, idx_C0, hksC0_eq, houtC0_eq, houtC0_len, hremC0_eq, hidxC0_eq⟩
  -- Helper facts about ks_C0.
  have hksC0_idx : ks_C0.state_index = 0#u32 := by rw [hksC0_eq]
  have hksC0_idx_val : ks_C0.state_index.val = 0 := by rw [hksC0_idx]; rfl
  have hksC0_ibs : ks_C0.input_block_size = self.input_block_size := by rw [hksC0_eq]
  have hksC0_pad : ks_C0.padding_value = self.padding_value := by rw [hksC0_eq]
  have hksC0_sm : ks_C0.squeeze_mode = true := by rw [hksC0_eq]; exact hsm
  have hksC0_state : toBits ks_C0.state = SHA3.KECCAK_f (toBits self.state) := by
    rw [hksC0_eq]; exact hperm_state
  have hksC0_ibs_val : ks_C0.input_block_size.val = self.input_block_size.val := by
    rw [hksC0_ibs]
  have hksC0_ibsmod : ks_C0.input_block_size.val % 8 = 0 := by
    rw [hksC0_ibs_val]; exact hibsmod
  have hksC0_ibspos : (0 : Nat) < ks_C0.input_block_size.val := by
    rw [hksC0_ibs_val]; exact hibspos
  have hksC0_ibsmax : ks_C0.input_block_size.val ≤ 200 := by
    rw [hksC0_ibs_val]; exact hibsmax
  have hksC0_align : ks_C0.state_index.val % 8 = 0 := by rw [hksC0_idx_val]
  have hksC0_le : ks_C0.state_index.val ≤ ks_C0.input_block_size.val := by
    rw [hksC0_idx_val]; omega
  rw [hremC0_eq]
  step
  by_cases hfl : full_lanes.val > 0
  · -- Case C / FL > 0
    simp only [show (0#usize < full_lanes) = (full_lanes.val > 0) from rfl,
               hfl, ↓reduceIte]
    have hrem_ge_8 : output.len.val ≥ 8 := by
      rw [hU64] at full_lanes_post
      have h := Nat.div_mul_le_self output.len.val 8
      have hfl_pos2 : full_lanes.val ≥ 1 := hfl
      have : output.len.val / 8 ≥ 1 := by rw [← full_lanes_post]; exact hfl_pos2
      omega
    have hcap_lanes : 8 * full_lanes.val ≤ output.len.val := by
      rw [hU64] at full_lanes_post
      have h := Nat.div_mul_le_self output.len.val 8
      calc 8 * full_lanes.val = full_lanes.val * 8 := by ring
        _ = output.len.val / 8 * 8 := by rw [full_lanes_post]
        _ ≤ output.len.val := h
    rw [hidxC0_eq]
    let* ⟨ subpair, hsub_eq, hsub_len, hsub_back ⟩ ←
      core.slice.index.SliceIndexRangeFromUsizeSlice.index_mut.step_spec
    obtain ⟨sub, sub_back⟩ := subpair
    dsimp only at hsub_eq hsub_len hsub_back ⊢
    have hsub_len' : sub.length = out_C0.length := by
      rw [hsub_len]; omega
    have hcap_lanes_sub : 8 * full_lanes.val ≤ sub.length := by
      rw [hsub_len', houtC0_len, ← holen]; omega
    progress with KeccakState.extract_lanes_state.spec
      (hsm := hksC0_sm)
      (hibsmod := hksC0_ibsmod)
      (halign := hksC0_align)
      (h_le := hksC0_le)
      (hibspos := hksC0_ibspos)
      (hibsmax := hksC0_ibsmax)
      (hcap := hcap_lanes_sub)
      as ⟨kspair, hsub'_len, hibsL_eq, hpadL_eq, hsmL,
          hsub'_eq, hksL_state, hksL_idx⟩
    obtain ⟨ks_L, sub'⟩ := kspair
    dsimp only at hsub'_len hibsL_eq hpadL_eq hsmL hsub'_eq hksL_state hksL_idx
    set LANE := (squeezeBytes (toBits self.state) g.rate g.rate (8 * full_lanes.val)).toList
      with hLANE_def
    have h8FL_pos : 0 < 8 * full_lanes.val := by omega
    have hLANE_len_eq : LANE.length = 8 * full_lanes.val := by simp [hLANE_def]
    have hLANE_eq_C0 : LANE =
        (squeezeBytes (toBits ks_C0.state) ks_C0.state_index.val
          ks_C0.input_block_size.val (8 * full_lanes.val)).toList := by
      simp only [hLANE_def, hksC0_idx_val, hksC0_ibs_val, hgr_rate, hksC0_state]
      have heq := squeezeBytes_post_full_block (toBits self.state) g.rate
                    (8 * full_lanes.val) hrate h8FL_pos
      rw [heq]
    have h_after_split :
        squeezeAfter S_pad 0 g.rate (g.squeezed.length + 8 * full_lanes.val) =
        squeezeAfter (toBits ks_C0.state) ks_C0.state_index.val
            ks_C0.input_block_size.val (8 * full_lanes.val) := by
      rw [hksC0_idx_val, hksC0_ibs_val, hgr_rate, hksC0_state]
      rw [squeezeAfter_add S_pad 0 g.rate g.squeezed.length (8 * full_lanes.val)]
      simp only [← hself_state, ← hself_idx, hsi_eq]
      exact (squeezeAfter_post_full_block (toBits self.state) g.rate _ hrate h8FL_pos)
    have hksL_state' : toBits ks_L.state =
        (squeezeAfter S_pad 0 g.rate (g.squeezed.length + 8 * full_lanes.val)).1 := by
      rw [h_after_split, hksL_state]
    have hksL_idx' : ks_L.state_index.val =
        (squeezeAfter S_pad 0 g.rate (g.squeezed.length + 8 * full_lanes.val)).2 := by
      rw [h_after_split, hksL_idx]
    have hksL_idx_le : ks_L.state_index.val ≤ ks_L.input_block_size.val := by
      rw [hksL_idx, hibsL_eq]
      exact squeezeAfter_idx_le_rate (toBits ks_C0.state) ks_C0.state_index.val
               ks_C0.input_block_size.val (8 * full_lanes.val)
               hksC0_le hksC0_ibspos
    have hksL_align : ks_L.state_index.val % 8 = 0 := by
      rw [hksL_idx, hksC0_idx_val, hksC0_ibs_val, hgr_rate]
      exact squeezeAfter_idx_mod8_of_zero (toBits ks_C0.state) g.rate (8 * full_lanes.val)
        hrate hgrmod (by omega)
    have hksL_str : squeezingStructural ks_L (g.squeeze LANE) := by
      refine ⟨hksL_idx_le, ?_, ?_, ?_⟩
      · rw [hsmL]
      · rw [hibsL_eq, hksC0_ibs]; exact hstr.2.2.1
      · rw [hpadL_eq, hksC0_pad]; exact hstr.2.2.2
    have hksL_sqz : squeezing ks_L (g.squeeze LANE) := by
      refine ⟨hksL_str, ?_, ?_, ?_⟩
      · dsimp only [GhostState.squeeze]
        rw [show (g.squeezed ++ LANE).length =
              g.squeezed.length + LANE.length from List.length_append ..]
        rw [hLANE_len_eq]
        exact hksL_state'
      · dsimp only [GhostState.squeeze]
        rw [show (g.squeezed ++ LANE).length =
              g.squeezed.length + LANE.length from List.length_append ..]
        rw [hLANE_len_eq]
        exact hksL_idx'
      · dsimp only [GhostState.squeeze]
        rw [show (g.squeezed ++ LANE).length =
              g.squeezed.length + LANE.length from List.length_append ..]
        rw [hLANE_len_eq]
        rw [squeezeBytes_append S_pad 0 g.rate g.squeezed.length (8 * full_lanes.val)]
        rw [← hsqz_old]
        apply congrArg (g.squeezed ++ ·)
        simp only
        rw [show (squeezeAfter S_pad 0 g.rate g.squeezed.length).1 = toBits self.state from
              hself_state.symm]
        rw [show (squeezeAfter S_pad 0 g.rate g.squeezed.length).2 = g.rate from by
              rw [← hself_idx]; exact hsi_eq]
    step*
    -- step* leaves 4 goals (in order):
    --   0. hbound : x✝ + x ≤ (sub_back sub').length  (NEW — pre for extract_loop1)
    --   1. h_rate : reset's KeccakState.init pre  (wipe = true)
    --   2. h2 (wipe = true)  — main post via reset
    --   3. h2 (wipe = false) — main post without reset
    -- Auto-named hypotheses post step*:
    --   x✝¹ : Usize = 8 * full_lanes (= old fl8)        x_post✝
    --   x✝  : Usize = 0 + x✝¹       (= old idx_after_C) x_post
    --   x   : Usize = output.len - x✝¹                  x_post1, x_post2
    --   self5, self5_post1/2/3 from extract_loop1
    --   self6, self6_post1/2  from reset (goal 2 only)

    -- ── Goal 0: hbound for extract_loop1. (Bound: x✝ + x = output.len = (sub_back sub').length.)
    · have h_back_len : (sub_back sub').length = output.length := by
        have h := hsub_back sub'
        have h1 : (↑(sub_back sub') : List U8).length = (↑out_C0 : List U8).length := by
          rw [h]; simp [List.length_setSlice!]
        have h2 : (sub_back sub').length = (sub_back sub').val.length := by simp [Slice.length]
        have h3 : output.length = output.val.length := by simp [Slice.length]
        have h4 : out_C0.length = out_C0.val.length := by simp [Slice.length]
        rw [h2, h3, h1, ← h4]; exact houtC0_len
      rw [h_back_len, ← holen, x_post, x_post1]
      omega

    -- ── Goal 1: h_rate side goal for `KeccakState.init` (invoked by `reset` when wipe = true).
    · have hibsF_val : self5.input_block_size.val = g.rate := self5_post3.1.2.2.1
      exact ⟨by rw [hibsF_val]; exact hrate,
             by rw [hibsF_val]; exact hgrlt,
             by rw [hibsF_val]; exact hgrmod⟩

    -- ── Remaining 2 goals (both `h2`): wipe=true (via reset) and wipe=false.
    -- Both need the same byte-level math chain. Rename per-goal using rotate
    -- (counts differ: wipe=true has 11 daggered, wipe=false has 10 because the
    -- extract_loop1 binder becomes non-daggered there).
    rename_i _ fl8 _ hfl8_eq idx_after_C _ _ _ _ _ hwipe
    rotate_left
    rename_i _ fl8 _ hfl8_eq idx_after_C _ _ _ _ hwipe
    rotate_left
    all_goals (have hfl8_val : fl8.val = 8 * full_lanes.val := by
                rw [hfl8_eq, hU64]; ring)
    all_goals (have hidx_val : idx_after_C.val = 8 * full_lanes.val := by
                have hh := x_post; rw [hfl8_val] at hh; omega)
    all_goals (have hxval : x.val = output.len.val - 8 * full_lanes.val := by
                have hh := x_post1; rw [hfl8_val] at hh; omega)
    all_goals (have hsubback_len : (sub_back sub').length = output.length := by
                have h := hsub_back sub'
                have h1 : (↑(sub_back sub') : List U8).length = (↑out_C0 : List U8).length := by
                  rw [h]; simp [List.length_setSlice!]
                have h2 : (sub_back sub').length = (sub_back sub').val.length := by
                  simp [Slice.length]
                have h3 : output.length = output.val.length := by simp [Slice.length]
                have h4 : out_C0.length = out_C0.val.length := by simp [Slice.length]
                rw [h2, h3, h1, ← h4]
                exact houtC0_len)
    -- Set TAIL alias across both goals.
    all_goals (set TAIL := (squeezeBytes (toBits ks_L.state) ks_L.state_index.val
                 ks_L.input_block_size.val x.val).toList
      with hTAIL_def)
    all_goals have hTAIL_len : TAIL.length = x.val := by simp [hTAIL_def]
    all_goals have houtval_len : output.val.length = output.length := by simp [Slice.length]
    all_goals (have hfin_len_eq : result3.length = output.length := by
                rw [self5_post1, hsubback_len])
    all_goals (have hsub_drop_setSlice :
        sub.val.setSlice! 0 (squeezeBytes (toBits ks_C0.state) ks_C0.state_index.val
            ks_C0.input_block_size.val (8 * full_lanes.val)).toList =
        (List.drop 0 out_C0.val).setSlice! 0 (squeezeBytes (toBits ks_C0.state)
            ks_C0.state_index.val ks_C0.input_block_size.val (8 * full_lanes.val)).toList := by
                rw [hsub_eq])
    all_goals (have hcap_out : 0 + (squeezeBytes (toBits ks_C0.state) ks_C0.state_index.val
            ks_C0.input_block_size.val (8 * full_lanes.val)).toList.length
            ≤ out_C0.val.length := by
                simp only [Vector.length_toList]
                have hC0_len : out_C0.val.length = out_C0.length := by simp [Slice.length]
                rw [hC0_len, houtC0_len, ← holen]; omega)
    all_goals (have h_back_simpler : (sub_back sub').val = out_C0.val.setSlice! 0 LANE := by
                rw [hsub_back, hsub'_eq, hsub_drop_setSlice,
                    List.setSlice!_drop_setSlice! _ _ _ hcap_out]
                exact congrArg ((↑out_C0 : List U8).setSlice! 0) hLANE_eq_C0.symm)
    all_goals have hout_C0_val : out_C0.val = output.val := houtC0_eq
    all_goals (have h_back_to_output : (sub_back sub').val = output.val.setSlice! 0 LANE := by
                rw [h_back_simpler, hout_C0_val])
    all_goals (have hAll_room : (0 : Nat) + LANE.length + TAIL.length ≤ output.val.length := by
                simp only [hLANE_len_eq, hTAIL_len, houtval_len]
                rw [← holen]; rw [hxval]; omega)
    all_goals (have h_step_C : (output.val.setSlice! 0 LANE).setSlice! idx_after_C.val TAIL =
        output.val.setSlice! 0 (LANE ++ TAIL) := by
                have hxeq : idx_after_C.val = 0 + LANE.length := by rw [hidx_val, hLANE_len_eq]; omega
                rw [hxeq]
                exact List.setSlice!_setSlice!_append output.val LANE TAIL 0 hAll_room)
    all_goals (have h_outF_setSlice : result3.val =
        output.val.setSlice! 0 (LANE ++ TAIL) := by
                rw [self5_post2, h_back_to_output, h_step_C])
    all_goals (have h_total_len : (LANE ++ TAIL).length = output.length := by
                simp only [List.length_append, hLANE_len_eq, hTAIL_len]
                rw [← holen]; rw [hxval]; omega)
    all_goals (have h_outF_full : result3.val = LANE ++ TAIL := by
                rw [h_outF_setSlice]
                exact List.setSlice!_zero_full output.val (LANE ++ TAIL) (by rw [h_total_len, houtval_len]))
    all_goals (have h_extract_eq : (extractOutput g output.length).toList = LANE ++ TAIL := by
                refine extractOutput_eq_append_of_squeezing g LANE TAIL output.length ?_ hsqz_old
                          self5_post3.2.2.2
                simp only [hLANE_len_eq, hTAIL_len]; rw [← holen]; rw [hxval]; omega)
    all_goals (have h_outF_extract : result3.val = (extractOutput g output.length).toList := by
                rw [h_outF_full, ← h_extract_eq])

    -- ── Goal 2: `h2` (wipe = true) — uses self6_post1 from reset.
    · have hibsF_val : self5.input_block_size.val = g.rate := self5_post3.1.2.2.1
      have hpadvalF : self5.padding_value = g.padVal := self5_post3.1.2.2.2
      refine ⟨hfin_len_eq, h_outF_extract, ?_⟩
      rw [← GhostState.init_congr hibsF_val hpadvalF]; exact self6_post1

    -- ── Goal 3: `h2` (wipe = false) — direct from self5_post3.
    · refine ⟨hfin_len_eq, h_outF_extract, ?_⟩
      rw [h_outF_full]
      rw [show g.squeeze (LANE ++ TAIL) = (g.squeeze LANE).squeeze TAIL from by
            simp only [GhostState.squeeze_append]]
      exact self5_post3
  · -- Case C / FL = 0: 0 < output.len < 8.
    have hfl0 : full_lanes.val = 0 := by
      have : ¬ full_lanes.val > 0 := hfl; omega
    have hrem_lt_8 : output.len.val < 8 := by
      rw [hU64] at full_lanes_post
      have hd : output.len.val / 8 = 0 := full_lanes_post.symm.trans hfl0
      omega
    have hcond_false : ¬ (full_lanes > 0#usize) := hfl
    simp only [show (full_lanes > 0#usize) = False from eq_false hcond_false, ↓reduceIte]
    rw [hidxC0_eq]
    step  -- consume massert (output.len < 8)
    -- Manually unfold extract_loop1 once to handle the post-permute boundary.
    unfold KeccakState.extract_loop1
    simp only [show (output.len > 0#usize) = True from eq_true hlen_pos, ↓reduceIte]
    have hne_C0 : ks_C0.state_index ≠ ks_C0.input_block_size := by
      intro heq
      have hh : ks_C0.state_index.val = ks_C0.input_block_size.val := by rw [heq]
      rw [hksC0_idx_val, hksC0_ibs_val] at hh
      omega
    simp only [show (ks_C0.state_index = ks_C0.input_block_size) = False
                 from eq_false hne_C0, ↓reduceIte]
    -- Establish squeezingStructural ks_C0 g for extract_byte.spec.
    have hksC0_str : squeezingStructural ks_C0 g := by
      refine ⟨?_, hksC0_sm, ?_, ?_⟩
      · rw [hksC0_idx_val]; omega
      · rw [hksC0_ibs_val]; exact hstr.2.2.1
      · rw [hksC0_pad]; exact hstr.2.2.2
    have hroom_C0 : ks_C0.state_index.val < ks_C0.input_block_size.val := by
      rw [hksC0_idx_val, hksC0_ibs_val]; exact hibspos
    -- Use progress for extract_byte; the (byte, state) pair is left
    -- undestructured under sp5's step, so split it manually.
    progress with KeccakState.extract_byte.spec
      (g := g) (h := hksC0_str) (hroom := hroom_C0)
      as ⟨bytepair, hbyte_str, hbyte_state, hbyte_idx, hbyte_bv⟩
    obtain ⟨byte0, ks_byte0⟩ := bytepair
    dsimp only at hbyte_str hbyte_state hbyte_idx hbyte_bv ⊢
    step as ⟨s_upd, h_s_upd⟩  -- Slice.update out_C0 0 byte0
    step as ⟨ri1, hri1⟩       -- 0 + 1 (result_index1)
    step as ⟨rrl1, hrrl1⟩     -- output.len - 1 (rem_result_len1)
    -- Bind name to the slice update result.
    set s_byte0 : Slice U8 := s_upd with hsbyte0_def
    have hsbyte_eq : s_byte0 = out_C0.set 0#usize byte0 := h_s_upd
    -- byte0 = squeezeByte from KECCAK_f S_self at index 0.
    have hbyte_eq : byte0 = squeezeByte (Spec.SHA3.KECCAK_f (toBits self.state)) 0 := by
      apply U8.bv_eq_imp_eq
      rw [hksC0_idx_val, hksC0_state] at hbyte_bv
      simpa using hbyte_bv
    -- ks_byte0 properties.
    have hks_byte0_state : toBits ks_byte0.state =
        Spec.SHA3.KECCAK_f (toBits self.state) := by
      rw [hbyte_state]; exact hksC0_state
    have hks_byte0_idx : ks_byte0.state_index.val = 1 := by
      rw [hbyte_idx, hksC0_idx_val]
    have hibs_byte0 : ks_byte0.input_block_size.val = self.input_block_size.val := by
      have h1 : ks_byte0.input_block_size.val = (g.squeeze [byte0]).rate := hbyte_str.2.2.1
      simp [GhostState.squeeze] at h1
      rw [h1, hibs_val]
    -- Reconstruct squeezing on ks_byte0.
    have hsq_byte0 : squeezing ks_byte0 (g.squeeze [byte0]) :=
      squeezing_step_byte_permute self ks_byte0 g byte0 hsq_self hbyte_str
        hks_byte0_state hks_byte0_idx hsi_eq hbyte_eq
    -- Apply extract_loop1_aux for the recursive call.
    have hsbyte_len : s_byte0.length = out_C0.length := by simp [hsbyte_eq]
    have hri_lt : (0#usize : Usize).val < out_C0.val.length := by
      have h0 : out_C0.val.length = out_C0.length := rfl
      rw [h0, houtC0_len, ← holen]; show (0 : Nat) < _; omega
    have hsbyte_val : s_byte0.val = out_C0.val.setSlice! 0 [byte0] := by
      rw [hsbyte_eq]; exact List.set_eq_setSlice!_singleton _ _ _ hri_lt
    progress with extract_loop1_aux
      (g := g.squeeze [byte0]) (h := hsq_byte0)
      as ⟨ks_F, out_F, hfin_len, hfin_eq, hfin_sq⟩
    have hri1_val : ri1.val = 1 := by rw [hri1]
    rw [hri1_val, hrrl1] at hfin_eq
    rw [hrrl1] at hfin_sq
    -- Compose the byte equation: [byte0] ++ TAIL = total bytes from S_self.
    set TAIL := (squeezeBytes (toBits ks_byte0.state) ks_byte0.state_index.val
                 ks_byte0.input_block_size.val (output.len.val - 1)).toList
      with hTAIL_def
    have hTAIL_len : TAIL.length = output.len.val - 1 := by simp [hTAIL_def]
    have houtval_len : output.val.length = output.length := by simp [Slice.length]
    have hfin_len_eq : out_F.length = output.length := by
      rw [hfin_len]; exact hsbyte_len.trans houtC0_len
    have hfin_eq' : out_F.val = s_byte0.val.setSlice! 1 TAIL := hfin_eq
    have hPRE_room : (0 : Nat) + [byte0].length + TAIL.length ≤ out_C0.val.length := by
      have h0 : out_C0.val.length = output.length := by
        rw [show out_C0.val = output.val from houtC0_eq, ← houtval_len]
      simp only [List.length_singleton, hTAIL_len, h0, ← holen]; omega
    have h_step : s_byte0.val.setSlice! 1 TAIL =
                  out_C0.val.setSlice! 0 ([byte0] ++ TAIL) := by
      rw [hsbyte_val]
      rw [show (1 : Nat) = 0 + [byte0].length from by simp]
      exact List.setSlice!_setSlice!_append out_C0.val [byte0] TAIL 0 hPRE_room
    have hout_C0_val : out_C0.val = output.val := houtC0_eq
    have h_outF_setSlice : out_F.val =
        output.val.setSlice! 0 ([byte0] ++ TAIL) := by
      rw [hfin_eq', h_step, hout_C0_val]
    have h_total_len : ([byte0] ++ TAIL).length = output.length := by
      simp only [List.length_append, List.length_singleton, hTAIL_len]
      rw [← holen]; omega
    have h_outF_full : out_F.val = [byte0] ++ TAIL := by
      rw [h_outF_setSlice]
      exact List.setSlice!_zero_full output.val ([byte0] ++ TAIL)
        (by rw [h_total_len, houtval_len])
    -- [byte0] ++ TAIL = extractOutput g output.length .toList.
    have h_extract_eq : (extractOutput g output.length).toList = [byte0] ++ TAIL := by
      refine extractOutput_eq_append_of_squeezing g [byte0] TAIL output.length ?_ hsqz_old
                hfin_sq.2.2.2
      simp only [List.length_singleton, hTAIL_len]; rw [← holen]; omega
    have h_outF_extract : out_F.val = (extractOutput g output.length).toList := by
      rw [h_outF_full, ← h_extract_eq]
    split
    · -- wipe = true
      have hibsF_val : ks_F.input_block_size.val = g.rate := by
        have h := hfin_sq.1.2.2.1; exact h
      have hibsF_pos : (0 : Nat) < ks_F.input_block_size.val := by
        rw [hibsF_val]; exact hrate
      have hibsF_lt : 8 * ks_F.input_block_size.val < SHA3.b := by
        rw [hibsF_val]; exact hgrlt
      have hibsF_mod : ks_F.input_block_size.val % 8 = 0 := by
        rw [hibsF_val]; exact hgrmod
      have hpadvalF : ks_F.padding_value = g.padVal := hfin_sq.1.2.2.2
      progress with KeccakState.reset.spec
        (h_rate := ⟨hibsF_pos, hibsF_lt, hibsF_mod⟩) as ⟨self6, hself6⟩
      refine ⟨hfin_len_eq, ?_, ?_⟩
      · exact h_outF_extract
      · rw [← GhostState.init_congr hibsF_val hpadvalF]; exact hself6
    · -- wipe = false
      refine ⟨hfin_len_eq, ?_, ?_⟩
      · exact h_outF_extract
      · rw [h_outF_full]
        rw [show g.squeeze ([byte0] ++ TAIL) = (g.squeeze [byte0]).squeeze TAIL from by
              simp only [GhostState.squeeze_append]]
        exact hfin_sq

set_option maxHeartbeats 6400000 in
@[step]
theorem KeccakState.extract.spec
    (self : KeccakState) (output : Slice U8) (wipe : Bool)
    (g : GhostState) (h : absorbing self g ∨ squeezing self g) :
    KeccakState.extract self output wipe
    ⦃ (ks : KeccakState) (output' : Slice U8) =>
      output'.length = output.length ∧
      output'.val = (extractOutput g output.length).toList ∧
      if wipe then absorbing ks (.init g.rate g.padVal g.h_rate)
      else squeezing ks (g.squeeze output'.val) ⦄ := by
  -- ── Setup ─────────────────────────────────────────────────────────
  have hrate : (0 : Nat) < g.rate := g.h_rate.1
  have hgrlt : 8 * g.rate < SHA3.b := g.h_rate.2.1
  have hgrmod : g.rate % 8 = 0 := g.h_rate.2.2
  have holen : output.len.val = output.length := by simp [Slice.len, Slice.length]
  -- Common structural facts.
  have hgr_rate : (↑self.input_block_size : Nat) = g.rate := by
    rcases h with hab | hsq
    · have haw := hab.1; simp only [absorbingWeak] at haw; exact haw.2.2.1
    · have hss := hsq.1; simp only [squeezingStructural] at hss; exact hss.2.2.1
  have hpadval : self.padding_value = g.padVal := by
    rcases h with hab | hsq
    · have haw := hab.1; simp only [absorbingWeak] at haw; exact haw.2.2.2.1
    · have hss := hsq.1; simp only [squeezingStructural] at hss; exact hss.2.2.2
  have hibsmod : (↑self.input_block_size : Nat) % 8 = 0 := by rw [hgr_rate]; exact hgrmod
  have hibspos : (0 : Nat) < ↑self.input_block_size := by linarith [hgr_rate]
  -- Three-way case split: rem > 0 splits further on boundary vs non-boundary;
  -- rem = 0 is its own branch. prologue.spec handles only non-boundary rem > 0;
  -- boundary uses spec_boundary, and rem = 0 reduces to the empty FC.
  by_cases hrem_pos : output.len > 0#usize
  · -- ── rem > 0 ───────────────────────────────────────────────────
    by_cases hno_bnd : self.squeeze_mode = true → self.state_index ≠ self.input_block_size
    · -- ── Non-boundary, rem > 0: use prologue.spec ────────────────
      rw [KeccakState.extract.fold]
      have hbound_pre : output.len.val ≤ output.length := by rw [holen]
      step with KeccakState.extract.prologue.spec self output output.len g h hrem_pos hno_bnd
                hbound_pre
        as ⟨self3, result1, rem_result_len1, result_index,
            hlen1, hsum1, hbound1, hfc1, halign1, hibs1, hpv1, hsq1⟩
      -- bulk_lanes and tail accept conditional halign, so no case split.
      have hbound1' : result_index.val + rem_result_len1.val ≤ result1.length := by
        rw [hlen1]; linarith
      let g3 : GhostState := g.squeeze (extractOutput g result_index.val).toList
      step with KeccakState.extract.bulk_lanes.spec
        self3 result1 rem_result_len1 result_index g3 hsq1 halign1 hbound1'
        as ⟨self4, result2, rem_result_len2, result_index1,
            hlen2, hfc2, hrem2_eq, hrem2_lt8, hri2_eq, hbound2, halign2, hsq2⟩
      -- massert: rem_result_len2 < U64_NUM_BYTES = 8.
      have hU64 : U64_NUM_BYTES.val = (8 : Nat) := by native_decide
      have hmassert : rem_result_len2 < U64_NUM_BYTES := by scalar_tac
      simp only [hmassert, massert, ↓reduceIte, bind_tc_ok]
      -- tail.spec (no halign needed — uses extract_loop1_aux).
      let g4 : GhostState := g3.squeeze
        (squeezeBytes (toBits self3.state) self3.state_index.val
                      self3.input_block_size.val (8 * (rem_result_len1.val / 8))).toList
      step with KeccakState.extract.tail.spec wipe self4 result2 rem_result_len2 result_index1
        g4 hsq2 hbound2
        as ⟨ks_final, output_final, hlen_final, hfc_final, hpost_final⟩
      -- Now discharge the goal.  output'.length, output'.val, and the
      -- wipe disjunct.
      -- ── Common setup for FC and wipe-post bridging ──────────────
      -- Abstract names for the three byte chunks.
      set PRE := (extractOutput g result_index.val).toList with hPRE_def
      set MID := (squeezeBytes (toBits self3.state) self3.state_index.val
                  self3.input_block_size.val (8 * (rem_result_len1.val / 8))).toList
        with hMID_def
      set TAIL := (squeezeBytes (toBits self4.state) self4.state_index.val
                   self4.input_block_size.val rem_result_len2.val).toList
        with hTAIL_def
      have hPRE_len : PRE.length = result_index.val := by
        rw [hPRE_def]; simp [extractOutput, squeezeBytes]
      have hMID_len : MID.length = 8 * (rem_result_len1.val / 8) := by
        rw [hMID_def]; simp [squeezeBytes]
      have hTAIL_len : TAIL.length = rem_result_len2.val := by
        rw [hTAIL_def]; simp [squeezeBytes]
      have houtval_len : output.val.length = output.length := by simp [Slice.length]
      -- Bridge: MID = (extractOutput (g.squeeze PRE) (8 * full_lanes)).toList.
      have hibs1_rate : self3.input_block_size.val = (g.squeeze PRE).rate := hibs1
      have hMID_eq : MID = (extractOutput (g.squeeze PRE)
                              (8 * (rem_result_len1.val / 8))).toList := by
        rw [hMID_def, hibs1_rate]
        exact (extractOutput_eq_squeezeBytes_of_squeezing hsq1 _).symm
      -- Bridge: TAIL = (extractOutput ((g.squeeze PRE).squeeze MID) rem_result_len2).toList.
      have hibs2_rate : self4.input_block_size.val = ((g.squeeze PRE).squeeze MID).rate :=
        hsq2.1.2.2.1
      have hTAIL_eq : TAIL = (extractOutput ((g.squeeze PRE).squeeze MID)
                                rem_result_len2.val).toList := by
        rw [hTAIL_def, hibs2_rate]
        exact (extractOutput_eq_squeezeBytes_of_squeezing hsq2 _).symm
      -- Length sum.
      have hri1_eq_full : result_index1.val = result_index.val + 8 * (rem_result_len1.val / 8) :=
        hri2_eq
      have hdiv_mul_le : 8 * (rem_result_len1.val / 8) ≤ rem_result_len1.val := by
        have := Nat.div_mul_le_self rem_result_len1.val 8; omega
      have hsum_total : result_index.val + 8 * (rem_result_len1.val / 8) +
                        rem_result_len2.val = output.length := by
        rw [holen] at hsum1; omega
      -- ── Key relationship: g.squeeze PRE = g.squeezeAdvance result_index.val ──
      have hgsq_advance_eq : g.squeeze PRE = g.squeezeAdvance result_index.val := by
        rw [hPRE_def]; rfl
      -- ── Key relationship for the double advance ──
      have hgsq_advance_eq2 : (g.squeeze PRE).squeeze MID =
          (g.squeezeAdvance result_index.val).squeezeAdvance
            (8 * (rem_result_len1.val / 8)) := by
        rw [hgsq_advance_eq]
        show _ = (g.squeezeAdvance result_index.val).squeeze
                   (extractOutput (g.squeezeAdvance result_index.val) _).toList
        rw [← hgsq_advance_eq, ← hMID_eq]
      -- ── Chain the setSlice!s to get output_final.val = PRE ++ MID ++ TAIL ──
      have hroom1 : 0 + PRE.length + MID.length ≤ output.val.length := by
        rw [hPRE_len, hMID_len, houtval_len, Nat.zero_add]
        rw [holen] at hsum1; omega
      have hstep_B : result1.val.setSlice! result_index.val MID =
                      output.val.setSlice! 0 (PRE ++ MID) := by
        rw [hfc1]
        rw [show result_index.val = 0 + PRE.length from by rw [hPRE_len, Nat.zero_add]]
        exact List.setSlice!_setSlice!_append output.val PRE MID 0 hroom1
      have hroom2 : 0 + (PRE ++ MID).length + TAIL.length ≤ output.val.length := by
        simp only [List.length_append, hPRE_len, hMID_len, hTAIL_len, Nat.zero_add]
        rw [houtval_len]; omega
      have hstep_C : (output.val.setSlice! 0 (PRE ++ MID)).setSlice!
                        result_index1.val TAIL =
                      output.val.setSlice! 0 (PRE ++ MID ++ TAIL) := by
        rw [show result_index1.val = 0 + (PRE ++ MID).length from by
              simp only [List.length_append, hPRE_len, hMID_len, Nat.zero_add]
              exact hri1_eq_full]
        exact List.setSlice!_setSlice!_append output.val (PRE ++ MID) TAIL 0 hroom2
      have htotal_len : (PRE ++ MID ++ TAIL).length = output.val.length := by
        simp only [List.length_append, hPRE_len, hMID_len, hTAIL_len, houtval_len]
        exact hsum_total
      have houtF_full : output_final.val = PRE ++ MID ++ TAIL := by
        rw [hfc_final, hfc2, hstep_B, hstep_C,
            List.setSlice!_zero_full output.val (PRE ++ MID ++ TAIL) htotal_len]
      refine ⟨?_, ?_, ?_⟩
      · -- output.length
        rw [hlen_final, hlen2, hlen1]
      · -- FC: output_final.val = (extractOutput g output.length).toList
        rw [houtF_full]
        rw [show output.length = result_index.val + (8 * (rem_result_len1.val / 8) +
                                 rem_result_len2.val) from by omega]
        rw [extractOutput_append g result_index.val
              (8 * (rem_result_len1.val / 8) + rem_result_len2.val)]
        rw [extractOutput_append (g.squeezeAdvance result_index.val)
              (8 * (rem_result_len1.val / 8)) rem_result_len2.val]
        rw [← List.append_assoc]
        -- Rewrite the RHS to use (g.squeeze PRE) and ((g.squeeze PRE).squeeze MID).
        rw [← hgsq_advance_eq]
        rw [show (g.squeeze PRE).squeezeAdvance (8 * (rem_result_len1.val / 8)) =
                 (g.squeeze PRE).squeeze MID from by
              show (g.squeeze PRE).squeeze _ = _
              rw [← hMID_eq]]
        rw [← hMID_eq, ← hTAIL_eq]
      · -- wipe disjunct
        -- Key: ((g.squeeze PRE).squeeze MID).squeeze TAIL = g.squeeze output_final.val
        have hghost_eq : ((g.squeeze PRE).squeeze MID).squeeze TAIL =
                        g.squeeze output_final.val := by
          rw [houtF_full]
          simp only [GhostState.squeeze_append]
        -- And rate/padVal equality.
        have hrate_eq : ((g.squeeze PRE).squeeze MID).rate = g.rate := by
          simp [GhostState.squeeze]
        have hpadval_eq : ((g.squeeze PRE).squeeze MID).padVal = g.padVal := by
          simp [GhostState.squeeze]
        by_cases hw : wipe = true
        · simp only [hw, ↓reduceIte] at hpost_final ⊢
          rw [← GhostState.init_congr hrate_eq hpadval_eq]; exact hpost_final
        · simp only [hw, ↓reduceIte, Bool.false_eq_true] at hpost_final ⊢
          rw [← hghost_eq]; exact hpost_final
    · -- ── Boundary case: squeezing + state_index = ibs ─────────────
      push Not at hno_bnd
      have hsm : self.squeeze_mode = true := hno_bnd.1
      have hbnd_eq : self.state_index = self.input_block_size := hno_bnd.2
      have hsq_self : squeezing self g := by
        rcases h with hab | hsq
        · exfalso; exact hab.1.2.1 hsm
        · exact hsq
      exact KeccakState.extract.spec_boundary self output wipe g hsq_self hrem_pos hbnd_eq
  · -- ── rem = 0: output empty, everything is essentially no-op ────
    have hlen0 : output.len.val = 0 := by
      have hneg : ¬ output.len.val > 0 := by
        intro hp
        apply hrem_pos
        show (0#usize).val < output.len.val
        exact hp
      omega
    have houtlen0 : output.length = 0 := by rw [← holen]; exact hlen0
    have hext0 : (extractOutput g output.length).toList = [] := by
      rw [houtlen0]; exact extractOutput_zero g
    rw [KeccakState.extract.fold]
    have hbound_pre : output.len.val ≤ output.length := by rw [holen]
    step with KeccakState.extract.prologue.spec_zero self output output.len g h hlen0 hbound_pre
      as ⟨self3, result1, rem_result_len1, result_index,
          hlen1, hsum1, hbound1, hfc1, halign1, hibs1, hpv1, hsq1⟩
    have hri_zero : result_index.val = 0 := by rw [hlen0] at hsum1; omega
    have hrem1_zero : rem_result_len1.val = 0 := by rw [hlen0] at hsum1; omega
    let g3 : GhostState := g.squeeze (extractOutput g result_index.val).toList
    step with KeccakState.extract.bulk_lanes.spec
      self3 result1 rem_result_len1 result_index g3 hsq1 halign1 hbound1
      as ⟨self4, result2, rem_result_len2, result_index1,
          hlen2, hfc2, hrem2_eq, hrem2_lt8, hri2_eq, hbound2, halign2, hsq2⟩
    have hrem2_zero : rem_result_len2.val = 0 := by
      have hdiv : rem_result_len1.val / 8 = 0 := by rw [hrem1_zero]
      rw [hrem2_eq, hdiv]; omega
    have hU64 : U64_NUM_BYTES.val = (8 : Nat) := by native_decide
    have hmassert : rem_result_len2 < U64_NUM_BYTES := by scalar_tac
    simp only [hmassert, massert, ↓reduceIte, bind_tc_ok]
    let g4 : GhostState := g3.squeeze
      (squeezeBytes (toBits self3.state) self3.state_index.val
                    self3.input_block_size.val (8 * (rem_result_len1.val / 8))).toList
    step with KeccakState.extract.tail.spec wipe self4 result2 rem_result_len2 result_index1
      g4 hsq2 hbound2
      as ⟨ks_final, output_final, hlen_final, hfc_final, hpost_final⟩
    -- All bytes are empty; chain trivially.
    have hext_ri_zero : (extractOutput g result_index.val).toList = [] := by
      rw [hri_zero]; exact extractOutput_zero g
    have hbulk_bytes_empty : (squeezeBytes (toBits self3.state) self3.state_index.val
                  self3.input_block_size.val (8 * (rem_result_len1.val / 8))).toList = [] := by
      have hdiv : rem_result_len1.val / 8 = 0 := by rw [hrem1_zero]
      simp [hdiv, squeezeBytes]
    have htail_bytes_empty : (squeezeBytes (toBits self4.state) self4.state_index.val
                  self4.input_block_size.val rem_result_len2.val).toList = [] := by
      rw [hrem2_zero]; simp [squeezeBytes]
    have hg4_eq_g : g4 = g := by
      show (g.squeeze (extractOutput g result_index.val).toList).squeeze _ = g
      rw [hext_ri_zero, GhostState.squeeze_nil, hbulk_bytes_empty, GhostState.squeeze_nil]
    have houtput_empty : output_final.val = [] := by
      apply List.length_eq_zero_iff.mp
      have h1 : output_final.val.length = output_final.length := rfl
      have h2 : output_final.length = output.length := by rw [hlen_final, hlen2, hlen1]
      rw [h1, h2, houtlen0]
    refine ⟨?_, ?_, ?_⟩
    · rw [hlen_final, hlen2, hlen1]
    · rw [houtput_empty, hext0]
    · by_cases hw : wipe = true
      · simp only [hw, ↓reduceIte] at hpost_final ⊢
        have hg4_rate : g4.rate = g.rate := by rw [hg4_eq_g]
        have hg4_pad : g4.padVal = g.padVal := by rw [hg4_eq_g]
        rw [← GhostState.init_congr hg4_rate hg4_pad]; exact hpost_final
      · simp only [hw, ↓reduceIte, Bool.false_eq_true] at hpost_final ⊢
        rw [houtput_empty, GhostState.squeeze_nil]
        rw [htail_bytes_empty, GhostState.squeeze_nil] at hpost_final
        rw [← hg4_eq_g]; exact hpost_final

end symcrust.sha3.sha3_impl
