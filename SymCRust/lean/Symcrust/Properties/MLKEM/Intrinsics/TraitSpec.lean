/-
  Symcrust/Properties/MLKEM/Intrinsics/TraitSpec.lean — Trait-parametric
  abstraction layer for the ML-KEM NTT SIMD intrinsics interface.

  This file is the architectural pivot for the ML-KEM SIMD NTT
  intrinsics layer.  It exposes a *spec-level* typeclass
  `NttIntrinsicsSpec V Inst` that bundles, for an abstract 128-bit lane
  carrier `V` and a concrete `NttIntrinsicsInterface T V` dictionary `Inst`,
  the Hoare specifications every well-behaved instance must satisfy.

  The trait-parametric layer-spec proofs in `Vec128LayerNtt.lean` /
  `Vec128LayerIntt.lean` consume only these abstract specs.
  Per-architecture instances (XMM/SSE2 over `__m128i` in `X86_64/Sse2.lean`,
  NEON over `uint16x8_t` in `Aarch64/Neon.lean`) discharge each field of the
  class as a *theorem*, and the parametric layer-spec then composes uniformly.

  Mirrors the `HashAbs` precedent in `Properties/HKDF/Basic.lean`:
  every method gets a class field AND a top-level `@[step]` wrapper that
  projects the field so `step*` can use it directly in proofs.

  ## Trust model (shared by all SIMD-NTT instance files)

  This is the single point of reference for the trust story of the
  `X86_64/Sse2.lean`, `Aarch64/Neon.lean`, and `X86_64/Avx2LayerNtt.lean`
  instance/layer files — they each point here instead of repeating it.

  **PROVEN — zero algorithm-specific axioms.**  Every instance field
  (loads, stores, broadcast, the `mod_add`/`mod_sub`/`mont_mul` composites,
  and the AVX2 16-lane analogues) is a *theorem*.  The chain is:

  ```
  Aeneas-extracted ML-KEM SIMD dict / free fns (Code/Funs.lean)
     ↓  bodies call the per-lane silicon intrinsics and the verify
        load/store shims (transparent coefficient-slice indexing)
  Intrinsics/Properties/<arch>/*.lean  (generic Layer-1 lane-op step specs,
        each validated against SDM / ARM-ARM "Operation:" pseudocode and
        differential tests)
     ↑  composed by hand into the method specs
  THIS LAYER: per-arch NttIntrinsicsSpec instances + the trait-parametric
              / AVX2 layer specs (all proven theorems)
  ```

  The per-opcode lane specs are themselves *theorems*, so the ML-KEM SIMD
  path introduces no silicon axioms.  `#print axioms` on any instance field
  shows only `propext` / `Classical.choice` / `Quot.sound` (+ `bv_decide`
  natives on the arithmetic cores).  The load/store wrappers carry no
  silicon content at all: the verify shims index the `[u16; N]` / byte
  coefficient carrier directly (no raw pointers — see
  `src/mlkem/ntt_{xmm,neon,avx2}.rs`), so Aeneas extracts them as
  transparent `def`s proved by `unfold + step*`.

  ## Lane abstraction

  `toLanes : V → Vector U16 8` — abstract projection of a 128-bit register
  as 8 unsigned-16-bit lanes (lane 0 = bytes 0-1, lane 1 = bytes 2-3, …).
  Conforms to little-endian lane ordering used by `_mm_loadu_si128` and
  `vld1q_u16` on the two targets in scope.

  `wfVec v : Prop` — derived from `toLanes`: every lane is in `[0, q)`.

  ## Load/store width variants

  The Rust `_vec128_loop0_loop0` body has three size-class branches
  selected by `len`:

    * `len ≥ 8`  — uses `vec128_load_u16x8` / `vec128_store_u16x8`.
                    All 8 lanes are meaningful.
    * `len = 4`  — uses `vec64_load_u16x4`  / `vec64_store_u16x4`.
                    Only lanes 0-3 are meaningful; lanes 4-7 are
                    unconstrained on load and ignored on store.
    * `len ∈ {1, 2}` (extracted to `else`) — uses `vec32_load_u16x2` /
                    `vec32_store_u16x2`.  Only lanes 0-1 are meaningful.

  The 64/32 load/store specs constrain only the meaningful lower lanes,
  matching the SymCrypt convention.
-/
import Aeneas
import Symcrust.Code.Funs
import Spec.MLKEM.Spec
import Symcrust.Properties.MLKEM.Basic

open Aeneas Aeneas.Std Result
open Symcrust Spec.MLKEM

namespace Symcrust.Properties.MLKEM.Intrinsics

/- Discharge `a[i]` bound obligations with `agrind` (which knows the
   container lengths and `Vector`/`Fin` bounds), so the spec statements
   below need no inline getElem proof terms. -/
local macro_rules
| `(tactic| get_elem_tactic) => `(tactic| agrind)

/-! ## Lane projection and well-formedness -/

/-- Bundle of *specs* every concrete `NttIntrinsicsInterface` instance
must satisfy for the trait-parametric NTT layer proof to apply uniformly.

Mirrors `HashAbs` (`Properties/HKDF/Basic.lean:232`) and the AesGcm
`AesImplCorrect` pattern: a Lean-side abstraction over a Rust trait,
with one field per Hoare spec.

Parameters:
* `T` — the per-instance "self" type (e.g. `ntt_xmm.NttIntrinsicsXmm`,
  which is `Unit`); kept as `outParam` because it is uniquely determined
  by `Inst`.
* `V` — the 128-bit lane carrier (e.g. `core.core_arch.x86.__m128i` or
  `core.core_arch.arm_shared.neon.uint16x8_t`).
* `Inst` — the extracted `NttIntrinsicsInterface T V` dictionary.

Each `<method>_spec` field is the Hoare spec for the corresponding
`Inst.<method>` call.  The top-level `@[step]` wrappers below project
these so `step*` can consume them directly. -/
class NttIntrinsicsSpec
    {T : outParam Type} (V : outParam Type)
    (Inst : outParam (symcrust.mlkem.ntt.NttIntrinsicsInterface T V)) where
  /-- Abstract 8-lane `u16` view of a 128-bit register.  Lane 0 is the
      low 16 bits (bytes 0-1), lane 7 is the high 16 bits. -/
  toLanes : V → Vector Std.U16 8
  /-- Well-formedness: every lane lies in `[0, q)`.  Derived from
      `toLanes`; provided as a separate predicate to keep proof goals
      readable and to admit an instance-specific definition on the
      carrier. -/
  wfVec : V → Prop
  /-- Derivation: `wfVec` is exactly "all 8 lanes `< q`".  Concrete
      instances are free to define `wfVec` directly on the carrier
      and prove this equivalence. -/
  wfVec_iff : ∀ v, wfVec v ↔ ∀ i : Fin 8, (toLanes v)[i.val].val < q

  -- ### Loads: 128-bit (8 lanes), 64-bit (4 lanes), 32-bit (2 lanes)

  /-- Load 8 lanes from `pe[idx .. idx+8)`.  Caller must show all 8
      coefficients lie in `[0, q)` (typically via `wfPoly`) and that the
      index is in bounds. -/
  vec128_load_u16x8_spec :
    ∀ (pe : PolyElement) (idx : Std.Usize)
      (_h_wf : wfPoly pe) (h_idx : idx.val + 8 ≤ 256),
      Inst.vec128_load_u16x8 pe idx ⦃ v =>
        wfVec v ∧
        ∀ i : Fin 8, (toLanes v)[i.val] = pe.val[idx.val + i.val] ⦄

  /-- Load lanes 0-3 from `pe[idx .. idx+4)`.  The underlying intrinsics
      (`_mm_loadl_epi64`, `vld1_u16` + zero-extension) zero-fill lanes 4-7,
      so the result is fully `wfVec` even though only lanes 0-3 carry
      meaningful data.  This is required for downstream
      `vec128_mod_add`/`vec128_mod_sub`/`vec128_mont_mul` calls (which
      require `wfVec` on the full 128-bit operand). -/
  vec64_load_u16x4_spec :
    ∀ (pe : PolyElement) (idx : Std.Usize)
      (_h_wf : wfPoly pe) (h_idx : idx.val + 4 ≤ 256),
      Inst.vec64_load_u16x4 pe idx ⦃ v =>
        wfVec v ∧
        ∀ i : Fin 4, (toLanes v)[i.val] = pe.val[idx.val + i.val] ⦄

  /-- Load lanes 0-1 from `pe[idx .. idx+2)`.  Lanes 2-7 are zero-filled
      by the underlying intrinsic (same rationale as `vec64_load_u16x4`),
      so the result is `wfVec`. -/
  vec32_load_u16x2_spec :
    ∀ (pe : PolyElement) (idx : Std.Usize)
      (_h_wf : wfPoly pe) (h_idx : idx.val + 2 ≤ 256),
      Inst.vec32_load_u16x2 pe idx ⦃ v =>
        wfVec v ∧
        ∀ i : Fin 2, (toLanes v)[i.val] = pe.val[idx.val + i.val] ⦄

  -- ### Stores: 128-bit, 64-bit, 32-bit (matching load widths)

  /-- Store all 8 lanes of `v` to `pe[idx .. idx+8)`.  Result has length
      256, lanes outside the window are preserved.  Requires `wfVec v`
      so the resulting `PolyElement` remains `wfPoly`. -/
  vec128_store_u16x8_spec :
    ∀ (pe : PolyElement) (idx : Std.Usize) (v : V)
      (_h_wf : wfPoly pe) (_h_idx : idx.val + 8 ≤ 256) (_h_v : wfVec v),
      Inst.vec128_store_u16x8 pe idx v ⦃ pe' =>
        pe'.val.length = 256 ∧
        wfPoly pe' ∧
        ∀ k : Fin 256,
          pe'.val[k.val] =
            if h : idx.val ≤ k.val ∧ k.val < idx.val + 8
              then (toLanes v)[k.val - idx.val]
              else pe.val[k.val] ⦄

  /-- Store lanes 0-3 of `v` to `pe[idx .. idx+4)`.  Requires lanes 0-3
      to be `< q` (matching the partial wfVec). -/
  vec64_store_u16x4_spec :
    ∀ (pe : PolyElement) (idx : Std.Usize) (v : V)
      (_h_wf : wfPoly pe) (_h_idx : idx.val + 4 ≤ 256)
      (_h_v : ∀ i : Fin 4, (toLanes v)[i.val].val < q),
      Inst.vec64_store_u16x4 pe idx v ⦃ pe' =>
        pe'.val.length = 256 ∧
        wfPoly pe' ∧
        ∀ k : Fin 256,
          pe'.val[k.val] =
            if h : idx.val ≤ k.val ∧ k.val < idx.val + 4
              then (toLanes v)[k.val - idx.val]
              else pe.val[k.val] ⦄

  /-- Store lanes 0-1 of `v` to `pe[idx .. idx+2)`. -/
  vec32_store_u16x2_spec :
    ∀ (pe : PolyElement) (idx : Std.Usize) (v : V)
      (_h_wf : wfPoly pe) (_h_idx : idx.val + 2 ≤ 256)
      (_h_v : ∀ i : Fin 2, (toLanes v)[i.val].val < q),
      Inst.vec32_store_u16x2 pe idx v ⦃ pe' =>
        pe'.val.length = 256 ∧
        wfPoly pe' ∧
        ∀ k : Fin 256,
          pe'.val[k.val] =
            if h : idx.val ≤ k.val ∧ k.val < idx.val + 2
              then (toLanes v)[k.val - idx.val]
              else pe.val[k.val] ⦄

  -- ### Broadcast and arithmetic

  /-- Broadcast a single `u16` value to all 8 lanes.

      Unconditional: the underlying intrinsic (`_mm_set1_epi16`,
      `vdupq_n_u16`, …) replicates `x` into every lane regardless of
      its value, so the lane-equality post holds for any `x : U16`.
      `wfVec` follows only when `x.val < q`; callers that need it
      derive it via `wfVec_iff` and the lane equality (the typical
      pattern for the *value* twiddle).  The Montgomery companion
      broadcast (`x.val ≤ 65535`, no `< q` bound) only needs the
      lane equality, which is why the precondition is dropped. -/
  vec128_set_u16x8_spec :
    ∀ (x : Std.U16),
      Inst.vec128_set_u16x8 x ⦃ v =>
        ∀ i : Fin 8, (toLanes v)[i.val] = x ⦄

  /-- Lane-wise modular addition.  Both operands must be `wfVec`; the
      result is `wfVec` and each lane is the modular sum in `Zq`. -/
  vec128_mod_add_spec :
    ∀ (a b : V), wfVec a → wfVec b →
      Inst.vec128_mod_add a b ⦃ r =>
        wfVec r ∧
        ∀ i : Fin 8,
          ((toLanes r)[i.val].val : Zq) =
            ((toLanes a)[i.val].val : Zq) + ((toLanes b)[i.val].val : Zq) ⦄

  /-- Lane-wise modular subtraction.  Both operands `wfVec`. -/
  vec128_mod_sub_spec :
    ∀ (a b : V), wfVec a → wfVec b →
      Inst.vec128_mod_sub a b ⦃ r =>
        wfVec r ∧
        ∀ i : Fin 8,
          ((toLanes r)[i.val].val : Zq) =
            ((toLanes a)[i.val].val : Zq) - ((toLanes b)[i.val].val : Zq) ⦄

  /-- Lane-wise Montgomery multiplication.  `b_mont` is the precomputed
      `b · (-q⁻¹) mod R` companion of `b` (R = 2^16); see the
      `mont_mul.spec` precondition shape for the scalar analogue at
      `Ntt/ModArith.lean`.  The result equals `a · b · R⁻¹ mod q`. -/
  vec128_mont_mul_spec :
    ∀ (a b b_mont : V),
      wfVec a → wfVec b →
      (∀ i : Fin 8,
        ((toLanes b_mont)[i.val].val : ℕ) =
          ((toLanes b)[i.val].val * 3327) % 65536) →
      Inst.vec128_mont_mul a b b_mont ⦃ r =>
        wfVec r ∧
        ∀ i : Fin 8,
          ((toLanes r)[i.val].val : Zq) =
            ((toLanes a)[i.val].val : Zq) *
            ((toLanes b)[i.val].val : Zq) * Rinv ⦄

/-! ## Top-level `@[step]` wrappers

`step*` cannot pierce typeclass fields directly — it needs `@[step]`-tagged
top-level theorems whose conclusions match the Aeneas-extracted call
sites.  These wrappers project the `NttIntrinsicsSpec` fields and
re-register them.  The pattern mirrors `Properties/HKDF/Basic.lean`
(`hash_new_spec`, `hash_append_spec`, `hash_result_spec`). -/

variable {T : Type} {V : Type}
  {Inst : symcrust.mlkem.ntt.NttIntrinsicsInterface T V}
  [s : NttIntrinsicsSpec V Inst]

@[step]
theorem vec128_load_u16x8_spec (pe : PolyElement) (idx : Std.Usize)
    (h_wf : wfPoly pe) (h_idx : idx.val + 8 ≤ 256) :
    Inst.vec128_load_u16x8 pe idx ⦃ v =>
      s.wfVec v ∧
      ∀ i : Fin 8, (s.toLanes v)[i.val] = pe.val[idx.val + i.val] ⦄ :=
  s.vec128_load_u16x8_spec pe idx h_wf h_idx

@[step]
theorem vec64_load_u16x4_spec (pe : PolyElement) (idx : Std.Usize)
    (h_wf : wfPoly pe) (h_idx : idx.val + 4 ≤ 256) :
    Inst.vec64_load_u16x4 pe idx ⦃ v =>
      s.wfVec v ∧
      ∀ i : Fin 4, (s.toLanes v)[i.val] = pe.val[idx.val + i.val] ⦄ :=
  s.vec64_load_u16x4_spec pe idx h_wf h_idx

@[step]
theorem vec32_load_u16x2_spec (pe : PolyElement) (idx : Std.Usize)
    (h_wf : wfPoly pe) (h_idx : idx.val + 2 ≤ 256) :
    Inst.vec32_load_u16x2 pe idx ⦃ v =>
      s.wfVec v ∧
      ∀ i : Fin 2, (s.toLanes v)[i.val] = pe.val[idx.val + i.val] ⦄ :=
  s.vec32_load_u16x2_spec pe idx h_wf h_idx

@[step]
theorem vec128_store_u16x8_spec (pe : PolyElement) (idx : Std.Usize) (v : V)
    (h_wf : wfPoly pe) (h_idx : idx.val + 8 ≤ 256) (h_v : s.wfVec v) :
    Inst.vec128_store_u16x8 pe idx v ⦃ pe' =>
      pe'.val.length = 256 ∧
      wfPoly pe' ∧
      ∀ k : Fin 256,
        pe'.val[k.val] =
          if h : idx.val ≤ k.val ∧ k.val < idx.val + 8
            then (s.toLanes v)[k.val - idx.val]
            else pe.val[k.val] ⦄ :=
  s.vec128_store_u16x8_spec pe idx v h_wf h_idx h_v

@[step]
theorem vec64_store_u16x4_spec (pe : PolyElement) (idx : Std.Usize) (v : V)
    (h_wf : wfPoly pe) (h_idx : idx.val + 4 ≤ 256)
    (h_v : ∀ i : Fin 4, (s.toLanes v)[i.val].val < q) :
    Inst.vec64_store_u16x4 pe idx v ⦃ pe' =>
      pe'.val.length = 256 ∧
      wfPoly pe' ∧
      ∀ k : Fin 256,
        pe'.val[k.val] =
          if h : idx.val ≤ k.val ∧ k.val < idx.val + 4
            then (s.toLanes v)[k.val - idx.val]
            else pe.val[k.val] ⦄ :=
  s.vec64_store_u16x4_spec pe idx v h_wf h_idx h_v

@[step]
theorem vec32_store_u16x2_spec (pe : PolyElement) (idx : Std.Usize) (v : V)
    (h_wf : wfPoly pe) (h_idx : idx.val + 2 ≤ 256)
    (h_v : ∀ i : Fin 2, (s.toLanes v)[i.val].val < q) :
    Inst.vec32_store_u16x2 pe idx v ⦃ pe' =>
      pe'.val.length = 256 ∧
      wfPoly pe' ∧
      ∀ k : Fin 256,
        pe'.val[k.val] =
          if h : idx.val ≤ k.val ∧ k.val < idx.val + 2
            then (s.toLanes v)[k.val - idx.val]
            else pe.val[k.val] ⦄ :=
  s.vec32_store_u16x2_spec pe idx v h_wf h_idx h_v

@[step]
theorem vec128_set_u16x8_spec (x : Std.U16) :
    Inst.vec128_set_u16x8 x ⦃ v =>
      ∀ i : Fin 8, (s.toLanes v)[i.val] = x ⦄ :=
  s.vec128_set_u16x8_spec x

/-- Wf-strengthened broadcast: when `x.val < q`, the broadcast result is
    `wfVec` (all 8 lanes `< q`).  Derived from
    `vec128_set_u16x8_spec` + `wfVec_iff`. -/
theorem vec128_set_u16x8_spec_wf (x : Std.U16) (h_x : x.val < q) :
    Inst.vec128_set_u16x8 x ⦃ v =>
      s.wfVec v ∧
      ∀ i : Fin 8, (s.toLanes v)[i.val] = x ⦄ := by
  apply WP.spec_mono (s.vec128_set_u16x8_spec x)
  intro v hlane
  refine ⟨?_, hlane⟩
  rw [s.wfVec_iff]
  intro i
  rw [hlane i]; exact h_x

@[step]
theorem vec128_mod_add_spec (a b : V) (h_a : s.wfVec a) (h_b : s.wfVec b) :
    Inst.vec128_mod_add a b ⦃ r =>
      s.wfVec r ∧
      ∀ i : Fin 8,
        ((s.toLanes r)[i.val].val : Zq) =
          ((s.toLanes a)[i.val].val : Zq) + ((s.toLanes b)[i.val].val : Zq) ⦄ :=
  s.vec128_mod_add_spec a b h_a h_b

@[step]
theorem vec128_mod_sub_spec (a b : V) (h_a : s.wfVec a) (h_b : s.wfVec b) :
    Inst.vec128_mod_sub a b ⦃ r =>
      s.wfVec r ∧
      ∀ i : Fin 8,
        ((s.toLanes r)[i.val].val : Zq) =
          ((s.toLanes a)[i.val].val : Zq) - ((s.toLanes b)[i.val].val : Zq) ⦄ :=
  s.vec128_mod_sub_spec a b h_a h_b

@[step]
theorem vec128_mont_mul_spec (a b b_mont : V)
    (h_a : s.wfVec a) (h_b : s.wfVec b)
    (h_mont : ∀ i : Fin 8,
      ((s.toLanes b_mont)[i.val].val : ℕ) =
        ((s.toLanes b)[i.val].val * 3327) % 65536) :
    Inst.vec128_mont_mul a b b_mont ⦃ r =>
      s.wfVec r ∧
      ∀ i : Fin 8,
        ((s.toLanes r)[i.val].val : Zq) =
          ((s.toLanes a)[i.val].val : Zq) *
          ((s.toLanes b)[i.val].val : Zq) * Rinv ⦄ :=
  s.vec128_mont_mul_spec a b b_mont h_a h_b h_mont

end Symcrust.Properties.MLKEM.Intrinsics
