/-
  Layer-2 specs for the cross-arch lane-wise primitives defined in
  `Symcrust/Code/Funs.lean` under `verify.intrinsics.lanewise.*`.

  ## Purpose

  These primitives encode pure-Rust element-wise array operations
  (XOR/AND/OR/AND-NOT, wrapping arithmetic, comparison masks, high-half
  multiplication).  They are shared by every per-arch SIMD wrapper
  (x86_64 SSE2/AVX2, aarch64 NEON) and are the natural place to
  reason about loop content; the per-arch wrappers (layer 1) are
  then 1-line `step` invocations of these specs.

  ## Layering rule (no silicon leakage)

  Every spec below has:
   * **LHS** = the rust-model shim (`verify.intrinsics.lanewise.<op>`
     or its `_loop` partner), with the same generic `N : Std.Usize`
     binder as the extracted def;
   * **post** = pure functional, expressed via `Array.val` indexing;
   * **no reference** to `core.core_arch.x86.*`, `__m128i`, `__m256i`,
     `xmmTo*`, or any silicon-side view.

  The silicon ↔ rust-model relation lives in the per-shim
  `Intrinsics/Properties/<Arch>/<Ext>Specs.lean` files (which import
  this module to obtain the layer-2 functional posts they delegate to),
  NOT here.  See `INTRINSICS.md` for the layered architecture.

  ## Vendor-doc validation

  These are the *arch-neutral lane-op models*, not named silicon intrinsics.
  The vendor-doc (Intel SDM / Arm) validation of the semantics is recorded at
  the named-op wrapper sites that delegate here — e.g. `PADDW`/`PSUBW`/
  `PMULLW`/`PMULHUW`/`PAND`/`PANDN`/`POR` tags in
  `Intrinsics/Properties/X86_64/{Sse2,Avx2}.lean`.  Two masks whose
  all-ones/all-zeros result shape is non-obvious carry an inline SDM note
  below (`PCMPEQW`, `PCMPGTW`); the rest are cited only at the wrapper sites
  to avoid duplication.
-/
import Symcrust.Code.Funs
import Intrinsics.Simd

open Aeneas Aeneas.Std

local macro_rules
| `(tactic| get_elem_tactic) => `(tactic| first | assumption | grind)

namespace symcrust

/-! ## Loop specs — canonical Range pattern (one per primitive)

Each `_loop` spec takes a partially-filled `out` array and an index `i`
with `i ≤ N`; the result agrees with `out` on `[0, i)` and matches the
operation on `[i, N)`.  The companion entry-point spec is the `i = 0`
case (with `out` being the zero-initialised buffer; the equality on
`[0, 0)` is vacuous). -/

@[step] theorem verify.intrinsics.lanewise.lanewise_xor_u8_loop.spec
    {N : Std.Usize} (a b out : Array Std.U8 N) (i : Std.Usize)
    (hi : i.val ≤ N.val) :
  verify.intrinsics.lanewise.lanewise_xor_u8_loop a b out i
  ⦃ (r : Array Std.U8 N) =>
    (∀ k, (hk : k < i.val) → r.val[k] = out.val[k]) ∧
    (∀ k, i.val ≤ k → (hk : k < N.val) → r.val[k] = a.val[k] ^^^ b.val[k]) ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_xor_u8_loop
  split
  · step*
    refine ⟨?_, ?_⟩
    · intro k hk
      have hr := r_post1 k (by agrind)
      simp [a1_post] at hr
      rw [hr]; simp_lists
    · intro k h1 h2
      by_cases heq : k = i.val
      · have hr := r_post1 k (by agrind)
        simp [a1_post] at hr
        subst heq
        rw [hr]; simp_lists [i3_post1, i1_post, i2_post]; agrind
      · have hr := r_post2 k (by agrind) h2
        agrind
  · simp only [WP.spec_ok]
    refine ⟨fun k hk => ?_, fun k h1 h2 => ?_⟩
    · trivial
    · agrind
termination_by N.val - i.val
decreasing_by scalar_decr_tac

@[step] theorem verify.intrinsics.lanewise.lanewise_and_u8_loop.spec
    {N : Std.Usize} (a b out : Array Std.U8 N) (i : Std.Usize)
    (hi : i.val ≤ N.val) :
  verify.intrinsics.lanewise.lanewise_and_u8_loop a b out i
  ⦃ (r : Array Std.U8 N) =>
    (∀ k, (hk : k < i.val) → r.val[k] = out.val[k]) ∧
    (∀ k, i.val ≤ k → (hk : k < N.val) → r.val[k] = a.val[k] &&& b.val[k]) ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_and_u8_loop
  split
  · step*
    refine ⟨?_, ?_⟩
    · intro k hk
      have hr := r_post1 k (by agrind)
      simp [a1_post] at hr
      rw [hr]; simp_lists
    · intro k h1 h2
      by_cases heq : k = i.val
      · have hr := r_post1 k (by agrind)
        simp [a1_post] at hr
        subst heq
        rw [hr]; simp_lists [i3_post1, i1_post, i2_post]; agrind
      · have hr := r_post2 k (by agrind) h2
        agrind
  · simp only [WP.spec_ok]
    refine ⟨fun k hk => ?_, fun k h1 h2 => ?_⟩
    · trivial
    · agrind
termination_by N.val - i.val
decreasing_by scalar_decr_tac

@[step] theorem verify.intrinsics.lanewise.lanewise_or_u8_loop.spec
    {N : Std.Usize} (a b out : Array Std.U8 N) (i : Std.Usize)
    (hi : i.val ≤ N.val) :
  verify.intrinsics.lanewise.lanewise_or_u8_loop a b out i
  ⦃ (r : Array Std.U8 N) =>
    (∀ k, (hk : k < i.val) → r.val[k] = out.val[k]) ∧
    (∀ k, i.val ≤ k → (hk : k < N.val) → r.val[k] = a.val[k] ||| b.val[k]) ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_or_u8_loop
  split
  · step*
    refine ⟨?_, ?_⟩
    · intro k hk
      have hr := r_post1 k (by agrind)
      simp [a1_post] at hr
      rw [hr]; simp_lists
    · intro k h1 h2
      by_cases heq : k = i.val
      · have hr := r_post1 k (by agrind)
        simp [a1_post] at hr
        subst heq
        rw [hr]; simp_lists [i3_post1, i1_post, i2_post]; agrind
      · have hr := r_post2 k (by agrind) h2
        agrind
  · simp only [WP.spec_ok]
    refine ⟨fun k hk => ?_, fun k h1 h2 => ?_⟩
    · trivial
    · agrind
termination_by N.val - i.val
decreasing_by scalar_decr_tac

@[step] theorem verify.intrinsics.lanewise.lanewise_andnot_u8_loop.spec
    {N : Std.Usize} (a b out : Array Std.U8 N) (i : Std.Usize)
    (hi : i.val ≤ N.val) :
  verify.intrinsics.lanewise.lanewise_andnot_u8_loop a b out i
  ⦃ (r : Array Std.U8 N) =>
    (∀ k, (hk : k < i.val) → r.val[k] = out.val[k]) ∧
    (∀ k, i.val ≤ k → (hk : k < N.val) → r.val[k] = (~~~ a.val[k]) &&& b.val[k]) ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_andnot_u8_loop
  split
  · step*
    refine ⟨?_, ?_⟩
    · intro k hk
      have hr := r_post1 k (by agrind)
      simp [a1_post] at hr
      rw [hr]; simp_lists
    · intro k h1 h2
      by_cases heq : k = i.val
      · have hr := r_post1 k (by agrind)
        simp [a1_post] at hr
        subst heq
        rw [hr]; simp_lists [i4_post1, i2_post, i1_post, i3_post]; agrind
      · have hr := r_post2 k (by agrind) h2
        agrind
  · simp only [WP.spec_ok]
    refine ⟨fun k hk => ?_, fun k h1 h2 => ?_⟩
    · trivial
    · agrind
termination_by N.val - i.val
decreasing_by scalar_decr_tac

@[step] theorem verify.intrinsics.lanewise.lanewise_and_u16_loop.spec
    {N : Std.Usize} (a b out : Array Std.U16 N) (i : Std.Usize)
    (hi : i.val ≤ N.val) :
  verify.intrinsics.lanewise.lanewise_and_u16_loop a b out i
  ⦃ (r : Array Std.U16 N) =>
    (∀ k, (hk : k < i.val) → r.val[k] = out.val[k]) ∧
    (∀ k, i.val ≤ k → (hk : k < N.val) → r.val[k] = a.val[k] &&& b.val[k]) ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_and_u16_loop
  split
  · step*
    refine ⟨?_, ?_⟩
    · intro k hk
      have hr := r_post1 k (by agrind)
      simp [a1_post] at hr
      rw [hr]; simp_lists
    · intro k h1 h2
      by_cases heq : k = i.val
      · have hr := r_post1 k (by agrind)
        simp [a1_post] at hr
        subst heq
        rw [hr]; simp_lists [i3_post1, i1_post, i2_post]; agrind
      · have hr := r_post2 k (by agrind) h2
        agrind
  · simp only [WP.spec_ok]
    refine ⟨fun k hk => ?_, fun k h1 h2 => ?_⟩
    · trivial
    · agrind
termination_by N.val - i.val
decreasing_by scalar_decr_tac

@[step] theorem verify.intrinsics.lanewise.lanewise_wrapping_add_u16_loop.spec
    {N : Std.Usize} (a b out : Array Std.U16 N) (i : Std.Usize)
    (hi : i.val ≤ N.val) :
  verify.intrinsics.lanewise.lanewise_wrapping_add_u16_loop a b out i
  ⦃ (r : Array Std.U16 N) =>
    (∀ k, (hk : k < i.val) → r.val[k] = out.val[k]) ∧
    (∀ k, i.val ≤ k → (hk : k < N.val) →
      r.val[k] = core.num.U16.wrapping_add a.val[k] b.val[k]) ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_wrapping_add_u16_loop
  split
  · step*
    refine ⟨?_, ?_⟩
    · intro k hk
      have hr := r_post1 k (by agrind)
      simp [a1_post] at hr
      rw [hr]; simp_lists
    · intro k h1 h2
      by_cases heq : k = i.val
      · have hr := r_post1 k (by agrind)
        simp [a1_post] at hr
        subst heq
        rw [hr]; simp_lists [i3_post, i1_post, i2_post]
      · have hr := r_post2 k (by agrind) h2
        agrind
  · simp only [WP.spec_ok]
    refine ⟨fun k hk => ?_, fun k h1 h2 => ?_⟩
    · trivial
    · agrind
termination_by N.val - i.val
decreasing_by scalar_decr_tac

@[step] theorem verify.intrinsics.lanewise.lanewise_wrapping_sub_u16_loop.spec
    {N : Std.Usize} (a b out : Array Std.U16 N) (i : Std.Usize)
    (hi : i.val ≤ N.val) :
  verify.intrinsics.lanewise.lanewise_wrapping_sub_u16_loop a b out i
  ⦃ (r : Array Std.U16 N) =>
    (∀ k, (hk : k < i.val) → r.val[k] = out.val[k]) ∧
    (∀ k, i.val ≤ k → (hk : k < N.val) →
      r.val[k] = core.num.U16.wrapping_sub a.val[k] b.val[k]) ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_wrapping_sub_u16_loop
  split
  · step*
    refine ⟨?_, ?_⟩
    · intro k hk
      have hr := r_post1 k (by agrind)
      simp [a1_post] at hr
      rw [hr]; simp_lists
    · intro k h1 h2
      by_cases heq : k = i.val
      · have hr := r_post1 k (by agrind)
        simp [a1_post] at hr
        subst heq
        rw [hr]; simp_lists [i3_post, i1_post, i2_post]
      · have hr := r_post2 k (by agrind) h2
        agrind
  · simp only [WP.spec_ok]
    refine ⟨fun k hk => ?_, fun k h1 h2 => ?_⟩
    · trivial
    · agrind
termination_by N.val - i.val
decreasing_by scalar_decr_tac

@[step] theorem verify.intrinsics.lanewise.lanewise_wrapping_mul_u16_loop.spec
    {N : Std.Usize} (a b out : Array Std.U16 N) (i : Std.Usize)
    (hi : i.val ≤ N.val) :
  verify.intrinsics.lanewise.lanewise_wrapping_mul_u16_loop a b out i
  ⦃ (r : Array Std.U16 N) =>
    (∀ k, (hk : k < i.val) → r.val[k] = out.val[k]) ∧
    (∀ k, i.val ≤ k → (hk : k < N.val) →
      r.val[k] = core.num.U16.wrapping_mul a.val[k] b.val[k]) ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_wrapping_mul_u16_loop
  split
  · step*
    refine ⟨?_, ?_⟩
    · intro k hk
      have hr := r_post1 k (by agrind)
      simp [a1_post] at hr
      rw [hr]; simp_lists
    · intro k h1 h2
      by_cases heq : k = i.val
      · have hr := r_post1 k (by agrind)
        simp [a1_post] at hr
        subst heq
        rw [hr]; simp_lists [i3_post, i1_post, i2_post]
      · have hr := r_post2 k (by agrind) h2
        agrind
  · simp only [WP.spec_ok]
    refine ⟨fun k hk => ?_, fun k h1 h2 => ?_⟩
    · trivial
    · agrind
termination_by N.val - i.val
decreasing_by scalar_decr_tac

@[step] theorem verify.intrinsics.lanewise.lanewise_wrapping_add_u32_loop.spec
    {N : Std.Usize} (a b out : Array Std.U32 N) (i : Std.Usize)
    (hi : i.val ≤ N.val) :
  verify.intrinsics.lanewise.lanewise_wrapping_add_u32_loop a b out i
  ⦃ (r : Array Std.U32 N) =>
    (∀ k, (hk : k < i.val) → r.val[k] = out.val[k]) ∧
    (∀ k, i.val ≤ k → (hk : k < N.val) →
      r.val[k] = core.num.U32.wrapping_add a.val[k] b.val[k]) ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_wrapping_add_u32_loop
  split
  · step*
    refine ⟨?_, ?_⟩
    · intro k hk
      have hr := r_post1 k (by agrind)
      simp [a1_post] at hr
      rw [hr]; simp_lists
    · intro k h1 h2
      by_cases heq : k = i.val
      · have hr := r_post1 k (by agrind)
        simp [a1_post] at hr
        subst heq
        rw [hr]; simp_lists [i3_post, i1_post, i2_post]
      · have hr := r_post2 k (by agrind) h2
        agrind
  · simp only [WP.spec_ok]
    refine ⟨fun k hk => ?_, fun k h1 h2 => ?_⟩
    · trivial
    · agrind
termination_by N.val - i.val
decreasing_by scalar_decr_tac

/-- `mulhi_u16` returns the high 16 bits of the 32-bit product (Intel
SDM `PMULHUW` semantics).  Spec stated on `.val`, matching the body's
`cast U32` → multiply → `>>> 16` → `cast U16` pipeline. -/
@[step] theorem verify.intrinsics.lanewise.lanewise_mulhi_u16_loop.spec
    {N : Std.Usize} (a b out : Array Std.U16 N) (i : Std.Usize)
    (hi : i.val ≤ N.val) :
  verify.intrinsics.lanewise.lanewise_mulhi_u16_loop a b out i
  ⦃ (r : Array Std.U16 N) =>
    (∀ k, (hk : k < i.val) → r.val[k] = out.val[k]) ∧
    (∀ k, i.val ≤ k → (hk : k < N.val) →
      r.val[k].val = (a.val[k].val * b.val[k].val) / 65536) ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_mulhi_u16_loop
  split
  · step*
    refine ⟨?_, ?_⟩
    · intro k hk
      have hr := r_post1 k (by agrind)
      simp [a1_post] at hr
      rw [hr]; simp_lists
    · intro k h1 h2
      by_cases heq : k = i.val
      · have hr := r_post1 k (by agrind)
        simp [a1_post] at hr
        subst heq
        rw [hr]; simp_lists
        have hi1 := i1.hBounds
        have hi3 := i3.hBounds
        have h_pow16 : (2:Nat)^UScalarTy.U16.numBits = 65536 := by decide
        have h_pow32 : (2:Nat)^UScalarTy.U32.numBits = 4294967296 := by decide
        rw [h_pow16] at hi1 hi3
        have h_i2_val : i2.val = i1.val := by
          rw [i2_post, UScalar.cast_val_eq, h_pow32]; scalar_tac
        have h_i4_val : i4.val = i3.val := by
          rw [i4_post, UScalar.cast_val_eq, h_pow32]; scalar_tac
        have h_p_val : p.val = i1.val * i3.val := by
          rw [p_post, h_i2_val, h_i4_val]
        have h_i5_val : i5.val = i1.val * i3.val / 65536 := by
          have := i5_post1
          simp [Nat.shiftRight_eq_div_pow] at this
          rw [this, h_p_val]
        have h_prod_lt : i1.val * i3.val < 65536 * 65536 :=
          Nat.mul_lt_mul_of_lt_of_le hi1 (le_of_lt hi3) (by scalar_tac)
        have h_div_lt : i1.val * i3.val / 65536 < 65536 := by
          apply Nat.div_lt_iff_lt_mul (by decide) |>.mpr
          scalar_tac
        have h_i6_val : i6.val = i1.val * i3.val / 65536 := by
          rw [i6_post, UScalar.cast_val_eq, h_i5_val, h_pow16]
          exact Nat.mod_eq_of_lt h_div_lt
        rw [h_i6_val, i1_post, i3_post]
      · have hr := r_post2 k (by agrind) h2
        agrind
  · simp only [WP.spec_ok]
    refine ⟨fun k hk => ?_, fun k h1 h2 => ?_⟩
    · trivial
    · agrind
termination_by N.val - i.val
decreasing_by scalar_decr_tac

/-- `eq_mask_u16` returns `0xFFFF` if the lanes are equal, `0`
otherwise (Intel SDM `PCMPEQW` semantics). -/
@[step] theorem verify.intrinsics.lanewise.lanewise_eq_mask_u16_loop.spec
    {N : Std.Usize} (a b out : Array Std.U16 N) (i : Std.Usize)
    (hi : i.val ≤ N.val) :
  verify.intrinsics.lanewise.lanewise_eq_mask_u16_loop a b out i
  ⦃ (r : Array Std.U16 N) =>
    (∀ k, (hk : k < i.val) → r.val[k] = out.val[k]) ∧
    (∀ k, i.val ≤ k → (hk : k < N.val) →
      r.val[k] = if a.val[k] = b.val[k] then 65535#u16 else 0#u16) ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_eq_mask_u16_loop
  split
  · step*
    split
    · -- i1 = i2 branch
      have hi1eq : i1 = i2 := ‹i1 = i2›
      step*
      refine ⟨?_, ?_⟩
      · intro k hk
        have hr := r_post1 k (by agrind)
        simp [a1_post] at hr
        rw [hr]; simp_lists
      · intro k h1 h2
        by_cases heq : k = i.val
        · have hr := r_post1 k (by agrind)
          simp [a1_post] at hr
          subst heq
          rw [hr]; simp_lists
          rw [← i1_post, ← i2_post, hi1eq]; simp
        · have hr := r_post2 k (by agrind) h2
          agrind
    · -- i1 ≠ i2 branch
      have hi1neq : ¬ i1 = i2 := ‹¬ i1 = i2›
      step*
      refine ⟨?_, ?_⟩
      · intro k hk
        have hr := r_post1 k (by agrind)
        simp [a1_post] at hr
        rw [hr]; simp_lists
      · intro k h1 h2
        by_cases heq : k = i.val
        · have hr := r_post1 k (by agrind)
          simp [a1_post] at hr
          subst heq
          rw [hr]; simp_lists
          rw [← i1_post, ← i2_post]
          simp [hi1neq]
        · have hr := r_post2 k (by agrind) h2
          agrind
  · simp only [WP.spec_ok]
    refine ⟨fun k hk => ?_, fun k h1 h2 => ?_⟩
    · trivial
    · agrind
termination_by N.val - i.val
decreasing_by all_goals scalar_decr_tac

/-- `sgt_mask_i16` returns `0xFFFF` if `a > b` in signed 16-bit
arithmetic, `0` otherwise (Intel SDM `PCMPGTW` semantics).  The body
re-interprets U16 lanes as I16 via `UScalar.hcast`; the spec mirrors
that path. -/
@[step] theorem verify.intrinsics.lanewise.lanewise_sgt_mask_i16_loop.spec
    {N : Std.Usize} (a b out : Array Std.U16 N) (i : Std.Usize)
    (hi : i.val ≤ N.val) :
  verify.intrinsics.lanewise.lanewise_sgt_mask_i16_loop a b out i
  ⦃ (r : Array Std.U16 N) =>
    (∀ k, (hk : k < i.val) → r.val[k] = out.val[k]) ∧
    (∀ k, i.val ≤ k → (hk : k < N.val) →
      r.val[k] = if a.val[k].bv.toInt > b.val[k].bv.toInt
                  then 65535#u16 else 0#u16) ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_sgt_mask_i16_loop
  split
  · step*
    split
    · -- ai > bi branch
      have hgt : ai > bi := ‹ai > bi›
      step*
      refine ⟨?_, ?_⟩
      · intro k hk
        have hr := r_post1 k (by agrind)
        simp [a1_post] at hr
        rw [hr]; simp_lists
      · intro k h1 h2
        by_cases heq : k = i.val
        · have hr := r_post1 k (by agrind)
          simp [a1_post] at hr
          subst heq
          rw [hr]; simp_lists
          rw [← i1_post, ← i2_post]
          have h := hgt
          rw [ai_post, bi_post] at h
          simp only [GT.gt, LT.lt, IScalar.val, UScalar.hcast,
                     BitVec.zeroExtend_eq_setWidth, UScalarTy.U16_numBits_eq,
                     IScalarTy.I16_numBits_eq, BitVec.setWidth_eq] at h
          show 65535#u16 = if i1.bv.toInt > i2.bv.toInt then 65535#u16 else 0#u16
          rw [if_pos]
          exact h
        · have hr := r_post2 k (by agrind) h2
          agrind
    · -- ¬ai > bi branch
      have hngt : ¬ ai > bi := ‹¬ ai > bi›
      step*
      refine ⟨?_, ?_⟩
      · intro k hk
        have hr := r_post1 k (by agrind)
        simp [a1_post] at hr
        rw [hr]; simp_lists
      · intro k h1 h2
        by_cases heq : k = i.val
        · have hr := r_post1 k (by agrind)
          simp [a1_post] at hr
          subst heq
          rw [hr]; simp_lists
          rw [← i1_post, ← i2_post]
          have h := hngt
          rw [ai_post, bi_post] at h
          simp only [GT.gt, LT.lt, IScalar.val, UScalar.hcast,
                     BitVec.zeroExtend_eq_setWidth, UScalarTy.U16_numBits_eq,
                     IScalarTy.I16_numBits_eq, BitVec.setWidth_eq] at h
          show 0#u16 = if i1.bv.toInt > i2.bv.toInt then 65535#u16 else 0#u16
          rw [if_neg]
          exact h
        · have hr := r_post2 k (by agrind) h2
          agrind
  · simp only [WP.spec_ok]
    refine ⟨fun k hk => ?_, fun k h1 h2 => ?_⟩
    · trivial
    · agrind
termination_by N.val - i.val
decreasing_by all_goals scalar_decr_tac

/-! ## Entry-point specs (i = 0 case of the loop) -/

@[step] theorem verify.intrinsics.lanewise.lanewise_xor_u8.spec
    {N : Std.Usize} (a b : Array Std.U8 N) :
  verify.intrinsics.lanewise.lanewise_xor_u8 a b
  ⦃ (r : Array Std.U8 N) =>
    ∀ k, (hk : k < N.val) → r.val[k] = a.val[k] ^^^ b.val[k] ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_xor_u8
  step
  agrind

@[step] theorem verify.intrinsics.lanewise.lanewise_and_u8.spec
    {N : Std.Usize} (a b : Array Std.U8 N) :
  verify.intrinsics.lanewise.lanewise_and_u8 a b
  ⦃ (r : Array Std.U8 N) =>
    ∀ k, (hk : k < N.val) → r.val[k] = a.val[k] &&& b.val[k] ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_and_u8
  step
  agrind

@[step] theorem verify.intrinsics.lanewise.lanewise_or_u8.spec
    {N : Std.Usize} (a b : Array Std.U8 N) :
  verify.intrinsics.lanewise.lanewise_or_u8 a b
  ⦃ (r : Array Std.U8 N) =>
    ∀ k, (hk : k < N.val) → r.val[k] = a.val[k] ||| b.val[k] ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_or_u8
  step
  agrind

@[step] theorem verify.intrinsics.lanewise.lanewise_andnot_u8.spec
    {N : Std.Usize} (a b : Array Std.U8 N) :
  verify.intrinsics.lanewise.lanewise_andnot_u8 a b
  ⦃ (r : Array Std.U8 N) =>
    ∀ k, (hk : k < N.val) → r.val[k] = (~~~ a.val[k]) &&& b.val[k] ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_andnot_u8
  step
  agrind

@[step] theorem verify.intrinsics.lanewise.lanewise_and_u16.spec
    {N : Std.Usize} (a b : Array Std.U16 N) :
  verify.intrinsics.lanewise.lanewise_and_u16 a b
  ⦃ (r : Array Std.U16 N) =>
    ∀ k, (hk : k < N.val) → r.val[k] = a.val[k] &&& b.val[k] ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_and_u16
  step
  agrind

@[step] theorem verify.intrinsics.lanewise.lanewise_wrapping_add_u16.spec
    {N : Std.Usize} (a b : Array Std.U16 N) :
  verify.intrinsics.lanewise.lanewise_wrapping_add_u16 a b
  ⦃ (r : Array Std.U16 N) =>
    ∀ k, (hk : k < N.val) →
      r.val[k] = core.num.U16.wrapping_add a.val[k] b.val[k] ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_wrapping_add_u16
  step
  agrind

@[step] theorem verify.intrinsics.lanewise.lanewise_wrapping_sub_u16.spec
    {N : Std.Usize} (a b : Array Std.U16 N) :
  verify.intrinsics.lanewise.lanewise_wrapping_sub_u16 a b
  ⦃ (r : Array Std.U16 N) =>
    ∀ k, (hk : k < N.val) →
      r.val[k] = core.num.U16.wrapping_sub a.val[k] b.val[k] ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_wrapping_sub_u16
  step
  agrind

@[step] theorem verify.intrinsics.lanewise.lanewise_wrapping_mul_u16.spec
    {N : Std.Usize} (a b : Array Std.U16 N) :
  verify.intrinsics.lanewise.lanewise_wrapping_mul_u16 a b
  ⦃ (r : Array Std.U16 N) =>
    ∀ k, (hk : k < N.val) →
      r.val[k] = core.num.U16.wrapping_mul a.val[k] b.val[k] ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_wrapping_mul_u16
  step
  agrind

@[step] theorem verify.intrinsics.lanewise.lanewise_wrapping_add_u32.spec
    {N : Std.Usize} (a b : Array Std.U32 N) :
  verify.intrinsics.lanewise.lanewise_wrapping_add_u32 a b
  ⦃ (r : Array Std.U32 N) =>
    ∀ k, (hk : k < N.val) →
      r.val[k] = core.num.U32.wrapping_add a.val[k] b.val[k] ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_wrapping_add_u32
  step
  agrind

@[step] theorem verify.intrinsics.lanewise.lanewise_mulhi_u16.spec
    {N : Std.Usize} (a b : Array Std.U16 N) :
  verify.intrinsics.lanewise.lanewise_mulhi_u16 a b
  ⦃ (r : Array Std.U16 N) =>
    ∀ k, (hk : k < N.val) →
      r.val[k].val = (a.val[k].val * b.val[k].val) / 65536 ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_mulhi_u16
  step
  agrind

@[step] theorem verify.intrinsics.lanewise.lanewise_eq_mask_u16.spec
    {N : Std.Usize} (a b : Array Std.U16 N) :
  verify.intrinsics.lanewise.lanewise_eq_mask_u16 a b
  ⦃ (r : Array Std.U16 N) =>
    ∀ k, (hk : k < N.val) →
      r.val[k] = if a.val[k] = b.val[k] then 65535#u16 else 0#u16 ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_eq_mask_u16
  step
  agrind

@[step] theorem verify.intrinsics.lanewise.lanewise_sgt_mask_i16.spec
    {N : Std.Usize} (a b : Array Std.U16 N) :
  verify.intrinsics.lanewise.lanewise_sgt_mask_i16 a b
  ⦃ (r : Array Std.U16 N) =>
    ∀ k, (hk : k < N.val) →
      r.val[k] = if a.val[k].bv.toInt > b.val[k].bv.toInt
                  then 65535#u16 else 0#u16 ⦄ := by
  unfold verify.intrinsics.lanewise.lanewise_sgt_mask_i16
  step
  agrind

end symcrust
