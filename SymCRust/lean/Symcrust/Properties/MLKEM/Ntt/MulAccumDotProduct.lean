/-
  # Ntt/MulAccumDotProduct.lean — Vector dot product loop spec.

  Split from `Ntt/MulAccum.lean` so that this section can elaborate in
  parallel with `Ntt/MulAccumMontReduce.lean` (neither depends on the
  other; both depend only on the base file `Ntt/MulAccum.lean`).

  Contents:

    * `vectorDotPartial` — partial inner-product helper
    * `vectorDotPartial_eq_innerProductNTT` — bridge to spec
    * `accToPoly_after_accumulate` — bridge for accumulator updates
    * `vectorDotPartial_left_shift` — recursion lemma
    * `vector_mont_dot_product_loop.spec`
-/
import Symcrust.Properties.MLKEM.Ntt.MulAccum

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust
open Symcrust.Properties.MLKEM.Ntt (baseCaseMultiply0 baseCaseMultiply1)

namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

local macro_rules
| `(tactic| get_elem_tactic) => `(tactic| grind)

/-! ## `vector_mont_dot_product` — NTT-domain inner product

`vector_mont_dot_product pv_src1 pv_src2 pe_dst pa_tmp` computes the
inner product `Σ_{i < k} MultiplyNTTs(pv_src1[i], pv_src2[i])` and
writes it (scaled by one `Rinv` factor from the final Montgomery
reduction) into `pe_dst`.  The impl:

1. Wipes `pa_tmp` and `pe_dst` (every slot zeroed).
2. Runs `vector_mont_dot_product_loop` with `iter = Range 0 k`.
   Each iteration accumulates `MultiplyNTTs(pv_src1[i], pv_src2[i])`
   into `pa_tmp` via `poly_element_mul_and_accumulate` (no R factor:
   the eager Montgomery reduction on `a₁·b₁` is cancelled by the R
   factor stored in the ZETA table).
3. Finalizes with `montgomery_reduce_and_add_..._to_poly_element`,
   which adds `Rinv · accToPoly(pa_tmp)` into the (zero-wiped) `pe_dst`.

Net effect:
    toPoly pe_dst' = (innerProductNTT pv_src1 pv_src2).map (Rinv * ·)

Callers in Encaps/Decaps pre-scale one input by R (via `vector_mul_r`)
to absorb the `Rinv` factor (bridge: `inner_product_mont_cancel` in
`Bridges/MatrixVectorMul.lean`). -/

/-- Helper: partial inner-product sum over `count` rows starting at
index `start`.  Used by `vector_mont_dot_product_loop.spec` to express
the per-iteration accumulator state.  Mirrors `matVecPartialSum`
(`MatVec.lean`) in shape; out-of-bound indices yield `0` (vacuous case
the caller never hits). -/
noncomputable def vectorDotPartial
    (pv_src1 pv_src2 : Slice PolyElement) (start : Nat) :
    Nat → MLKEM.Polynomial
  | 0 => 0
  | n + 1 =>
      vectorDotPartial pv_src1 pv_src2 start n +
      (if h : start + n < pv_src1.length ∧ start + n < pv_src2.length then
        MLKEM.MultiplyNTTs
          (toPoly (pv_src1.val[start + n]'h.1))
          (toPoly (pv_src2.val[start + n]'h.2))
       else 0)

/-- **Bridge** — `vectorDotPartial pv_src1 pv_src2 0 kn = innerProductNTT pv_src1 pv_src2`.

For full coverage (`start = 0`, `count = kn`), the per-iteration sum
collapses to the spec inner product.

Informal proof: induction on `count`. Base `count = 0`: both sides
are `0`.  Step `count = m + 1`: unfold `vectorDotPartial`, apply IH
for the prefix, and the new term matches the corresponding summand of
`PolyVector.innerProductNTT` (which sums `MultiplyNTTs v[i] w[i]` over
`i ∈ [0, kn)`). -/
theorem vectorDotPartial_eq_innerProductNTT
    (pv_src1 pv_src2 : Slice PolyElement) (kn : MLKEM.K)
    (h_len1 : pv_src1.length = (kn : ℕ))
    (h_len2 : pv_src2.length = (kn : ℕ)) :
    vectorDotPartial pv_src1 pv_src2 0 (kn : ℕ)
      = MLKEM.PolyVector.innerProductNTT
          (toPolyVecOfLen pv_src1 kn h_len1)
          (toPolyVecOfLen pv_src2 kn h_len2) := by
  obtain ⟨kv, hkv⟩ := kn
  simp only [Set.mem_insert_iff, Set.mem_singleton_iff] at hkv
  unfold MLKEM.PolyVector.innerProductNTT
  rcases hkv with rfl | rfl | rfl <;>
  · simp only [Id.run, Aeneas.SRRange.forIn'_eq_forIn'_range', Aeneas.SRRange.size,
               show (2 - 0 + 1 - 1) / 1 = 2 from by decide,
               show (3 - 0 + 1 - 1) / 1 = 3 from by decide,
               show (4 - 0 + 1 - 1) / 1 = 4 from by decide,
               List.range', List.forIn'_cons, List.forIn'_nil, pure_bind]
    simp only [pure]
    simp only [vectorDotPartial, toPolyVecOfLen, Vector.getElem_ofFn,
               h_len1, h_len2, Nat.zero_add,
               show (1 + 1 : Nat) = 2 from rfl,
               show (1 + 1 + 1 : Nat) = 3 from rfl,
               show (0:Nat) < 2 from by decide,
               show (1:Nat) < 2 from by decide,
               show (0:Nat) < 3 from by decide,
               show (1:Nat) < 3 from by decide,
               show (2:Nat) < 3 from by decide,
               show (0:Nat) < 4 from by decide,
               show (1:Nat) < 4 from by decide,
               show (2:Nat) < 4 from by decide,
               show (3:Nat) < 4 from by decide,
               and_self, dif_pos]
    all_goals (rw [show (0 : MLKEM.Polynomial) = Polynomial.zero from rfl,
                   Polynomial.zero_add])

/-- **Bridge** — relate `accToPoly` of an accumulator that received one
`poly_element_mul_and_accumulate` body call to `accToPoly` of the input
plus `MultiplyNTTs`.

Uses `Polynomial.eq_iff'` to split into even/odd indices and matches
the body's `(v.val : Zq) = (pa.val : Zq) + baseCaseMultiply{0,1}`
hypotheses one-to-one. -/
theorem accToPoly_after_accumulate
    (pa pa1 : PolyAccumulator) (pe1 pe2 : PolyElement)
    (hZq : ∀ i (hi : i < 128),
        ((pa1.val[2*i]'(by grind)).val : Zq)
          = ((pa.val[2*i]'(by grind)).val : Zq)
            + baseCaseMultiply0 (toPoly pe1) (toPoly pe2) i ∧
        ((pa1.val[2*i+1]'(by grind)).val : Zq)
          = ((pa.val[2*i+1]'(by grind)).val : Zq)
            + baseCaseMultiply1 (toPoly pe1) (toPoly pe2) i) :
    accToPoly pa1 = accToPoly pa + MLKEM.MultiplyNTTs (toPoly pe1) (toPoly pe2) := by
  rw [Polynomial.eq_iff']
  intro i hi
  have hi_lt2 : 2*i < 256 := by grind
  have hi_lt21 : 2*i+1 < 256 := by grind
  have hZqi := hZq i hi
  have hpa_len : pa.val.length = 256 := by grind
  have hpa1_len : pa1.val.length = 256 := by grind
  refine ⟨?_, ?_⟩
  · -- Even index 2*i
    rw [Polynomial.getElem!_add]
    simp only [accToPoly]
    rw [Vector.getElem!_ofFn _ (2*i) hi_lt2,
        Vector.getElem!_ofFn _ (2*i) hi_lt2,
        Symcrust.Properties.MLKEM.Ntt.MultiplyNTTs_eq_ofFn,
        Vector.getElem!_ofFn _ (2*i) hi_lt2]
    have h2i_even : (2*i) % 2 = 0 := by agrind
    have h2i_div2 : (2*i) / 2 = i := by agrind
    simp only [h2i_even, h2i_div2, if_true, accToZq]
    exact hZqi.1
  · -- Odd index 2*i+1
    rw [Polynomial.getElem!_add]
    simp only [accToPoly]
    rw [Vector.getElem!_ofFn _ (2*i+1) hi_lt21,
        Vector.getElem!_ofFn _ (2*i+1) hi_lt21,
        Symcrust.Properties.MLKEM.Ntt.MultiplyNTTs_eq_ofFn,
        Vector.getElem!_ofFn _ (2*i+1) hi_lt21]
    have h2i_odd : (2*i+1) % 2 = 1 := by agrind
    have h2i1_div2 : (2*i+1) / 2 = i := by agrind
    simp only [h2i_odd, h2i1_div2, accToZq]
    exact hZqi.2

/-- **Left-shift recursion** for `vectorDotPartial`.

The underlying recursion is on the COUNT (right end), but for the loop
invariant we need the left-shift form: a sum over `[K, K+n+1)` equals
the body at index `K` plus a sum over `[K+1, K+1+n)`. Used in
`vector_mont_dot_product_loop.spec` to combine one body's contribution
with the IH's tail.

The "if both bounds hold" guard mirrors the underlying definition so
the statement is unconditional (no `h1 : K < pv1.length` premise) and
side-steps `rw` motive issues during induction. -/
private theorem vectorDotPartial_left_shift
    (pv1 pv2 : Slice PolyElement) (K n : Nat) :
    vectorDotPartial pv1 pv2 K (n + 1) =
      (if h : K < pv1.length ∧ K < pv2.length then
        MLKEM.MultiplyNTTs
          (toPoly (pv1.val[K]'h.1)) (toPoly (pv2.val[K]'h.2))
       else 0)
      + vectorDotPartial pv1 pv2 (K + 1) n := by
  induction n with
  | zero =>
    show vectorDotPartial pv1 pv2 K 1 = _ + vectorDotPartial pv1 pv2 (K + 1) 0
    simp only [vectorDotPartial, Nat.add_zero]
    rw [show (0 : MLKEM.Polynomial) = Polynomial.zero from rfl,
        Polynomial.zero_add, Polynomial.add_zero]
  | succ n ih =>
    show vectorDotPartial pv1 pv2 K (n + 1 + 1)
        = _ + vectorDotPartial pv1 pv2 (K + 1) (n + 1)
    -- LHS unfolds: vectorDotPartial K (n+2) =
    --   vectorDotPartial K (n+1) + (if K + (n+1) < bounds then ... else 0)
    rw [show vectorDotPartial pv1 pv2 K (n + 1 + 1)
            = vectorDotPartial pv1 pv2 K (n + 1) +
              (if h : K + (n+1) < pv1.length ∧ K + (n+1) < pv2.length then
                MLKEM.MultiplyNTTs
                  (toPoly (pv1.val[K + (n+1)]'h.1))
                  (toPoly (pv2.val[K + (n+1)]'h.2))
               else 0) from rfl]
    rw [ih]
    rw [show vectorDotPartial pv1 pv2 (K+1) (n + 1)
            = vectorDotPartial pv1 pv2 (K+1) n +
              (if h : (K+1) + n < pv1.length ∧ (K+1) + n < pv2.length then
                MLKEM.MultiplyNTTs
                  (toPoly (pv1.val[(K+1) + n]'h.1))
                  (toPoly (pv2.val[(K+1) + n]'h.2))
               else 0) from rfl]
    have hKn : K + (n+1) = (K+1) + n := by ring
    rw [hKn, Polynomial.add_assoc]

/-- **Loop spec** for `vector_mont_dot_product_loop` over the Range
cursor `iter.start.val ∈ [0, n_rows]`.  At exit, `pa_tmp` has accumulated
the row contributions for `i ∈ [iter.start.val, n_rows)`, captured by
`vectorDotPartial`.

Informal proof. Canonical Range-loop induction (proof-patterns §1)
on `iter.start.val ↦ pv_src1.length`. Body per iteration `i =
iter.start.val`: two `Slice.index`-derived reads of `pv_src1.val[i]`
and `pv_src2.val[i]`, then a delegate to
`poly_element_mul_and_accumulate.spec` which adds the per-coefficient
`baseCaseMultiply0/1` contributions. Combine the per-index post with
`MultiplyNTTs_eq_ofFn` to express the accumulator change as one
addition of `MultiplyNTTs(pv_src1[i], pv_src2[i])`. IH closes the
tail. -/
@[step]
theorem mlkem.ntt.vector_mont_dot_product_loop.spec
    (iter : core.ops.range.Range Usize)
    (pv_src1 pv_src2 : Slice PolyElement)
    (pa_tmp : PolyAccumulator)
    (h_wf1 : wfPolyVec pv_src1) (h_wf2 : wfPolyVec pv_src2)
    -- LOOSE uniform invariant: every slot is bounded by iter.start * (M+A).
    (h_acc : ∀ k (hk : k < 256),
      pa_tmp.val[k].val
        ≤ iter.start.val * (3328 * 3328 + 3494 * 3254))
    -- TIGHT-ODD parallel invariant: each odd slot is bounded by
    -- iter.start * 2M.  Combined with `h_acc` on even slots and `mlkem_M_lt_A`,
    -- this derives the STRICT c1 precondition `pa_tmp[2j+1] < 3·(M+A)`
    -- (since `K·2M < 3·(M+A)` for K ≤ 3, slack `3·(A−M) = 881,676`).
    (h_acc_tight_odd : ∀ j (hj : j < 128),
      pa_tmp.val[2*j+1].val
        ≤ iter.start.val * (2 * (3328 * 3328)))
    (h_len : pv_src1.length = pv_src2.length)
    (h_nrows : 0 < pv_src1.length ∧ pv_src1.length ≤ 4)
    (h_start : iter.start.val ≤ pv_src1.length)
    (h_end : iter.«end».val = pv_src1.length) :
    mlkem.ntt.vector_mont_dot_product_loop iter pv_src1 pv_src2 pa_tmp
      ⦃ (pa_tmp' : PolyAccumulator) =>
          accToPoly pa_tmp' = accToPoly pa_tmp +
            vectorDotPartial pv_src1 pv_src2 iter.start.val
              (pv_src1.length - iter.start.val) ∧
          (∀ k (hk : k < 256),
            pa_tmp'.val[k].val
              ≤ pv_src1.length * (3328 * 3328 + 3494 * 3254)) ∧
          (∀ j (hj : j < 128),
            pa_tmp'.val[2*j+1].val
              ≤ pv_src1.length * (2 * (3328 * 3328))) ⦄ := by
  -- Bridge total-form preconditions to `!`-form for existing proof body.
  have h_acc_bang : ∀ k, k < 256 →
      pa_tmp.val[k]!.val ≤ iter.start.val * (3328 * 3328 + 3494 * 3254) := by
    intro k hk
    rw [getElem!_pos pa_tmp.val k (by grind)]
    exact h_acc k hk
  have h_acc_tight_odd_bang : ∀ j, j < 128 →
      pa_tmp.val[2*j+1]!.val ≤ iter.start.val * (2 * (3328 * 3328)) := by
    intro j hj
    rw [getElem!_pos pa_tmp.val (2*j+1) (by grind)]
    exact h_acc_tight_odd j hj
  unfold mlkem.ntt.vector_mont_dot_product_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · -- some branch: iterator yields
    let* ⟨ o, iter1, ho, hstart', hend' ⟩ ← IteratorRange_next_Usize_some
    rw [ho]
    simp only
    have hi_lt : iter.start.val < pv_src1.length := by grind
    have hi_lt2 : iter.start.val < pv_src2.length := by rw [← h_len]; exact hi_lt
    -- a ← Slice.index_usize pv_src1 iter.start
    step as ⟨ a, ha ⟩
    have ha_eq : a = pv_src1.val[iter.start.val]! := by grind
    have ha_pos : pv_src1.val[iter.start.val]'hi_lt = a := by
      rw [ha_eq, getElem!_pos pv_src1.val iter.start.val hi_lt]
    have ha_wf : wfPoly a := by
      rw [← ha_pos]; exact h_wf1 iter.start.val hi_lt
    -- a1 ← Slice.index_usize pv_src2 iter.start
    step as ⟨ a1, ha1 ⟩
    have ha1_eq : a1 = pv_src2.val[iter.start.val]! := by grind
    have ha1_pos : pv_src2.val[iter.start.val]'hi_lt2 = a1 := by
      rw [ha1_eq, getElem!_pos pv_src2.val iter.start.val hi_lt2]
    have ha1_wf : wfPoly a1 := by
      rw [← ha1_pos]; exact h_wf2 iter.start.val hi_lt2
    -- ═══════════════════════════════════════════════════════════════
    -- strict-c1 dispatch (Tier 0, closed via tight-odd invariant)
    -- ───────────────────────────────────────────────────────────────
    -- `_accumulate.spec` requires asymmetric preconditions:
    --   * EVEN slots: LOOSE `pa_dst[2j]   ≤ 3·(M+A)`  (Rust c0 assert is `<=`)
    --   * ODD  slots: STRICT `pa_dst[2j+1] < 3·(M+A)` (Rust c1 assert is `<`)
    -- The loose case discharges directly from `h_acc` (combined with
    -- `iter.start.val ≤ 3` from `h_nrows`).
    -- The strict case discharges from the tight-odd invariant
    -- `h_acc_tight_odd : pa_tmp[2j+1] ≤ iter.start·2M` combined with
    -- `iter.start ≤ 3` and `M < A` (the `mlkem_M_lt_A` keystone fact,
    -- `Basic.lean:L100`, registered `@[scalar_tac_simps]`):
    --     pa_tmp[2j+1] ≤ 3·2M = 6M  <  3·(M+A) = 3M+3A   (since M < A).
    have hK_le_3 : iter.start.val ≤ 3 := by grind
    have h_even_loose : ∀ j (hj : j < 128),
        (pa_tmp.val[2*j]'(by grind)).val
          ≤ 3 * (3328 * 3328 + 3494 * 3254) := by
      intro j hj
      have h := h_acc (2*j) (by grind)
      have : (pa_tmp.val[2*j]'(by grind)).val
              ≤ iter.start.val * (3328 * 3328 + 3494 * 3254) := h
      grind
    have h_odd_strict : ∀ j (hj : j < 128),
        (pa_tmp.val[2*j+1]'(by grind)).val
          < 3 * (3328 * 3328 + 3494 * 3254) := by
      intro j hj
      have h := h_acc_tight_odd j hj
      -- pa_tmp[2j+1] ≤ K · 2M  ∧  K ≤ 3  ∧  M < A  ⊢  pa_tmp[2j+1] < 3·(M+A)
      grind
    -- Body call: pa_tmp1 with Zq + bound + additive postconditions.
    let* ⟨ pa_tmp1, hZq_tot, hBound_tot, hAdd_tot, hAddTight_tot ⟩ ←
      mlkem.ntt.poly_element_mul_and_accumulate.spec a a1 pa_tmp ha_wf ha1_wf
        h_even_loose h_odd_strict
    -- Bridge total-form bounds back to `!` for the existing proof body.
    have hBound : ∀ k, k < 256 →
        pa_tmp1.val[k]!.val ≤ 4 * (3328 * 3328 + 3494 * 3254) := by
      intro k hk
      rw [getElem!_pos pa_tmp1.val k (by grind)]
      exact hBound_tot k hk
    have hAdd : ∀ k, k < 256 →
        pa_tmp1.val[k]!.val ≤ pa_tmp.val[k]!.val + (3328 * 3328 + 3494 * 3254) := by
      intro k hk
      rw [getElem!_pos pa_tmp1.val k (by grind),
          getElem!_pos pa_tmp.val k (by grind)]
      exact hAdd_tot k hk
    have hAddTight : ∀ j, j < 128 →
        pa_tmp1.val[2*j+1]!.val ≤ pa_tmp.val[2*j+1]!.val + 2 * (3328 * 3328) := by
      intro j hj
      rw [getElem!_pos pa_tmp1.val (2*j+1) (by grind),
          getElem!_pos pa_tmp.val (2*j+1) (by grind)]
      exact hAddTight_tot j hj
    -- Build IH preconditions: pa_tmp1[k] ≤ iter1.start.val * (M+A) =
    --                          (iter.start.val + 1) * (M+A);  and
    --                          pa_tmp1[2j+1] ≤ iter1.start.val * 2M.
    have h_acc1 : ∀ k, k < 256 →
        pa_tmp1.val[k]!.val ≤ iter1.start.val * (3328 * 3328 + 3494 * 3254) := by
      intro k hk
      have ha := hAdd k hk
      have hi := h_acc_bang k hk
      rw [hstart']
      grind
    have h_acc1_tight_odd : ∀ j, j < 128 →
        pa_tmp1.val[2*j+1]!.val ≤ iter1.start.val * (2 * (3328 * 3328)) := by
      intro j hj
      have ha := hAddTight j hj
      have hi := h_acc_tight_odd_bang j hj
      rw [hstart']
      grind
    have h_start1 : iter1.start.val ≤ pv_src1.length := by rw [hstart']; grind
    have h_end1 : iter1.«end».val = pv_src1.length := by rw [hend']; exact h_end
    -- Bridge `!`-form invariants back to total for the recursive IH.
    have h_acc1_tot : ∀ k (hk : k < 256),
        (pa_tmp1.val[k]'(by grind)).val
          ≤ iter1.start.val * (3328 * 3328 + 3494 * 3254) := by
      intro k hk
      rw [← getElem!_pos pa_tmp1.val k (by grind)]
      exact h_acc1 k hk
    have h_acc1_tight_odd_tot : ∀ j (hj : j < 128),
        (pa_tmp1.val[2*j+1]'(by grind)).val
          ≤ iter1.start.val * (2 * (3328 * 3328)) := by
      intro j hj
      rw [← getElem!_pos pa_tmp1.val (2*j+1) (by grind)]
      exact h_acc1_tight_odd j hj
    -- IH
    apply WP.spec_mono
      (mlkem.ntt.vector_mont_dot_product_loop.spec iter1 pv_src1 pv_src2 pa_tmp1
        h_wf1 h_wf2 h_acc1_tot h_acc1_tight_odd_tot h_len h_nrows h_start1 h_end1)
    rintro pa_tmp' ⟨h_eq, h_bound, h_tight⟩
    refine ⟨?_, h_bound, h_tight⟩
    -- Goal: accToPoly pa_tmp' = accToPoly pa_tmp +
    --         vectorDotPartial pv_src1 pv_src2 iter.start.val (pv_src1.length - iter.start.val)
    rw [h_eq]
    -- accToPoly pa_tmp1 = accToPoly pa_tmp + MultiplyNTTs (toPoly a) (toPoly a1)
    have hpa1_eq : accToPoly pa_tmp1 = accToPoly pa_tmp
        + MLKEM.MultiplyNTTs (toPoly a) (toPoly a1) :=
      accToPoly_after_accumulate pa_tmp pa_tmp1 a a1 hZq_tot
    rw [hpa1_eq]
    -- Replace toPoly a / toPoly a1 with toPoly pv_src1.val[K] / pv_src2.val[K].
    rw [← ha_pos, ← ha1_pos]
    -- vectorDotPartial K (N - K) =
    --   MultiplyNTTs pv_src1[K] pv_src2[K] + vectorDotPartial (K+1) (N - K - 1)
    have hK_remain : pv_src1.length - iter.start.val =
        (pv_src1.length - iter.start.val - 1) + 1 := by grind
    have hsub_succ : pv_src1.length - (iter.start.val + 1) =
        pv_src1.length - iter.start.val - 1 := Nat.sub_add_eq _ _ _
    conv_rhs => rw [hK_remain,
      vectorDotPartial_left_shift pv_src1 pv_src2 iter.start.val
        (pv_src1.length - iter.start.val - 1)]
    have hK_in_bounds : iter.start.val < pv_src1.length ∧ iter.start.val < pv_src2.length :=
      ⟨hi_lt, hi_lt2⟩
    rw [dif_pos hK_in_bounds]
    rw [hstart', hsub_succ]
    rw [Polynomial.add_assoc]
  · -- none branch: iterator exhausted
    let* ⟨ o, iter1, hnone, _ ⟩ ← IteratorRange_next_Usize_none
    rw [hnone]
    simp only [WP.spec_ok]
    have h_start_eq : iter.start.val = pv_src1.length := by grind
    refine ⟨?_, ?_, ?_⟩
    · -- accToPoly pa_tmp = accToPoly pa_tmp + 0
      rw [h_start_eq, Nat.sub_self]
      simp only [vectorDotPartial]
      rw [show (0 : MLKEM.Polynomial) = Polynomial.zero from rfl,
          Polynomial.add_zero]
    · -- pa_tmp[k] ≤ pv_src1.length * (M+A) since pa_tmp[k] ≤ iter.start.val * (M+A)
      intro k hk
      have := h_acc k hk
      grind
    · -- pa_tmp[2j+1] ≤ pv_src1.length * 2M since pa_tmp[2j+1] ≤ iter.start.val * 2M
      intro j hj
      have := h_acc_tight_odd j hj
      grind
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

end Symcrust.Properties.MLKEM
