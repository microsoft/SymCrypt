import Spec.SHA3.XOF
import Spec.SHA3.Properties

/-!
# Properties of the Incremental Sponge API

Lemmas about the streaming squeeze operation, including:
- `squeeze3`: relationship between squeezing before and after an extra `squeeze_r`
- `squeeze_unrolled`: squeezing is invariant under extra `squeeze_r` rounds
- `squeeze_lookup`: when enough bits are buffered, `squeeze1` reduces to `lookup`

-/

namespace Spec.SHA3

open Incremental
open scoped Spec.Notations

section Lemmas

variable
  (f   : Vector Bool b → Vector Bool b)
  (r   : Nat)
  (hr  : 0 < r ∧ r < b := by decide)

lemma sponge.squeeze3 (s : sponge.state r) d :
  let t := sponge.squeeze_r f r hr s
  let u := sponge.squeeze1 f r hr s d
  let v := sponge.squeeze1 f r hr t d
  if s.Z.size + r < s.x + d then
    v = u -- u squeezes at least once, catching up on v
  else
    v = (sponge.squeeze_r f r hr u.1, u.2) -- v is still ahead by one round
  := by
    intro t u v
    have ht : t = sponge.squeeze_r f r hr s := rfl
    have hu : u = sponge.squeeze1 f r hr s d := rfl
    have hv : v = sponge.squeeze1 f r hr t d := rfl
    unfold sponge.squeeze1 at hu
    split_ifs at hu with h0
    . rw [ht] at hv
      grind

    . unfold sponge.squeeze1 at hv
      split_ifs at hv with h1
      . exfalso
        rw [ht] at h1
        unfold sponge.squeeze_r at h1
        simp [SPONGE.squeeze_step] at h0 h1
        omega

      . split_ifs
        simp at hv
        simp [hv, ht, hu, sponge.squeeze_r, SPONGE.squeeze_step]
        have eqz : s.x + d - (s.Z.size + r) = 0 := by
          apply Nat.sub_eq_zero_of_le
          apply Nat.ge_of_not_lt h0
        simp [eqz]

private lemma size_extract (A : Array α) {i size} (hsize : i + size ≤ A.size) :
  (A.extract i (i+size)).size = size := by
  let B := A.extract i (i+size)
  have hB: B.size = min (i + size) A.size - min i A.size := by
    grind [Array.extract]
  grind

lemma sponge.squeeze_unrolled (s : sponge.state r) d :
  let t := sponge.squeeze_r f r hr (sponge.squeeze_r f r hr s)
  (sponge.squeeze1 f r hr t d).2 = (sponge.squeeze1 f r hr s d).2 := by
    have h1 := squeeze3 f r hr s d
    simp at h1
    have h2 := squeeze3 f r hr (sponge.squeeze_r f r hr s) d
    simp at h2
    split_ifs at h1 h2 with h0 h3 <;> grind

lemma sponge.squeeze_lookup (s : sponge.state r) m (hm : s.x + m ≤ s.Z.size) :
  sponge.squeeze1 f r hr s m = sponge.lookup r hr s m hm := by
  unfold sponge.lookup sponge.squeeze1
  split_ifs
  . grind -- excluded branch of squeeze1
  . simp_all

/-! ## Composition of chained squeeze1 calls

The lemma needed by MLKEM `SampleNTT` (and any other incremental squeezing
consumer): `n` bits, then `m` bits, is the same as one `n + m` bit call
from the same state — both the resulting state AND the concatenated
output bits. -/

/-- A helper combining two consecutive `Array.extract` slices of the same
    underlying array into one, at the `Vector` level (i.e., with the size
    casts that `squeeze1` produces). Used to assemble `B₁ ‖ B₂` from two
    successive slices of the sponge buffer. -/
private lemma extract_concat_eq (A : Array Bool) (a n m : Nat)
    (hsz : (A.extract a (a+n)).size = n)
    (hsz' : (A.extract (a+n) (a+n+m)).size = m)
    (hsz'' : (A.extract a (a+n+m)).size = n+m) :
    ((A.extract a (a+n)).toVector.cast hsz) ‖
      ((A.extract (a+n) (a+n+m)).toVector.cast hsz') =
    ((A.extract a (a+n+m)).toVector.cast hsz'') := by
  apply Vector.toArray_inj.1
  show A.extract a (a+n) ++ A.extract (a+n) (a+n+m) = A.extract a (a+n+m)
  rw [Array.extract_append_extract]
  congr 1 <;> omega

/-- Closed form of `squeeze1` when the buffer already contains enough bits
    (no permutation required). -/
private lemma sponge.squeeze1_no_perm (s : sponge.state r) (d : Nat)
    (hd : s.x + d ≤ s.Z.size + r) :
    sponge.squeeze1 f r hr s d =
      ({ s with x := s.x + d, hx := hd },
       ((s.Z ++ (Trunc r s.S).toArray).extract s.x (s.x + d)).toVector.cast
         (by have := s.hx; simp; grind)) := by
  conv_lhs => unfold sponge.squeeze1
  rw [dif_neg (by omega)]

/-- **Chained `squeeze1` calls compose at the bit level.**
    `n` bits then `m` bits equals one `n + m` call from the same state.

    Proof is by strong induction on the well-founded measure
    `s.x + (n + m) - (s.Z.size + r)` (same measure as `squeeze1`'s
    termination). -/
theorem sponge.squeeze1_concat_bits
    (f : Vector Bool b → Vector Bool b) (r : Nat) (hr : 0 < r ∧ r < b)
    (s : sponge.state r) (n m : Nat) :
    ((sponge.squeeze1 f r hr (sponge.squeeze1 f r hr s n).1 m).1,
     (sponge.squeeze1 f r hr s n).2 ‖
       (sponge.squeeze1 f r hr (sponge.squeeze1 f r hr s n).1 m).2)
    = sponge.squeeze1 f r hr s (n + m) := by
  by_cases hA : s.x + (n + m) ≤ s.Z.size + r
  · /- Case A: neither call permutes. Both calls take the else branch
       and read from the same buffer `A = s.Z ++ Trunc r s.S`. -/
    have hAn  : s.x + n ≤ s.Z.size + r := by omega
    have hAm  : (s.x + n) + m ≤ s.Z.size + r := by omega
    have hAnm : s.x + (n + m) ≤ s.Z.size + r := hA
    rw [sponge.squeeze1_no_perm f r hr s n hAn]
    simp only []
    rw [sponge.squeeze1_no_perm f r hr _ m hAm]
    rw [sponge.squeeze1_no_perm f r hr s (n+m) hAnm]
    /- Buffer A := s.Z ++ (Trunc r s.S).toArray is the same in both
       intermediate calls and in the combined call (Z and S unchanged). -/
    simp only [Prod.mk.injEq]
    refine ⟨?_, ?_⟩
    · -- state equality: x-fields match by Nat.add_assoc, proofs irrelevant
      congr 1; omega
    · -- bit equality: convert to array level and combine extracts
      apply Vector.toArray_inj.1
      let A := s.Z ++ (Trunc r s.S).toArray
      show A.extract s.x (s.x + n) ++ A.extract (s.x + n) (s.x + n + m)
          = A.extract s.x (s.x + (n + m))
      rw [Array.extract_append_extract]
      congr 1 <;> omega
  · /- s.Z.size + r < s.x + (n + m): combined call recurses. -/
    have hA : s.Z.size + r < s.x + (n + m) := Nat.not_le.mp hA
    /- Combined call enters the then-branch and recurses on `squeeze_r s`.
       Apply the IH on `(squeeze_r s, n, m)`; the measure decreases by `r`. -/
    have hCombined :
        sponge.squeeze1 f r hr s (n + m) =
        sponge.squeeze1 f r hr (sponge.squeeze_r f r hr s) (n + m) := by
      conv_lhs => unfold sponge.squeeze1
      rw [dif_pos hA]
    have IH := sponge.squeeze1_concat_bits f r hr (sponge.squeeze_r f r hr s) n m
    by_cases hC : s.Z.size + r < s.x + n
    · /- Sub-case C: first call also recurses on `squeeze_r s`. -/
      have hFirst :
          sponge.squeeze1 f r hr s n =
          sponge.squeeze1 f r hr (sponge.squeeze_r f r hr s) n := by
        conv_lhs => unfold sponge.squeeze1
        rw [dif_pos hC]
      rw [hFirst, hCombined]
      exact IH
    · /- s.x + n ≤ s.Z.size + r: first call doesn't permute. -/
      have hC : s.x + n ≤ s.Z.size + r := Nat.not_lt.mp hC
      /- Sub-case B: first call takes the else branch, the second permutes.
         Use `squeeze3` to relate `squeeze1 (squeeze_r s) n` to `squeeze1 s n`. -/
      have hS3 := sponge.squeeze3 f r hr s n
      simp only at hS3
      rw [if_neg (by omega : ¬ s.Z.size + r < s.x + n)] at hS3
      /- `hS3 : squeeze1 (squeeze_r s) n
                = (squeeze_r (squeeze1 s n).1, (squeeze1 s n).2)` -/
      rw [hS3] at IH
      /- After else branch, `(squeeze1 s n).1` has `x = s.x + n`, `Z = s.Z`.
         The second call `squeeze1 s₁ m` has `s₁.Z.size + r < s₁.x + m`,
         so it recurses on `squeeze_r s₁`. -/
      have hSecond :
          sponge.squeeze1 f r hr (sponge.squeeze1 f r hr s n).1 m =
          sponge.squeeze1 f r hr
              (sponge.squeeze_r f r hr (sponge.squeeze1 f r hr s n).1) m := by
        rw [sponge.squeeze1_no_perm f r hr s n hC]
        conv_lhs => unfold sponge.squeeze1
        rw [dif_pos (by simp; omega)]
      rw [hSecond, hCombined]
      exact IH
termination_by s.x + (n + m) - (s.Z.size + r)
decreasing_by
  unfold sponge.squeeze_r
  simp [SPONGE.squeeze_step]
  grind

end Lemmas

/-! ## Byte-level corollary for SHAKE128

Specialise `sponge.squeeze1_concat_bits` to SHAKE128 byte chunks.
We need a distribution lemma for `bitsToBytes` over append, then
`chainedSqueeze` chains `n` byte-level calls into one. -/

/-- `bitsToBytes` distributes over bit-vector append (modulo the
    `8 * a + 8 * c = 8 * (a + c)` cast). -/
theorem bitsToBytes_append {a c : Nat}
    (xs : Vector Bool (8 * a)) (ys : Vector Bool (8 * c)) :
    bitsToBytes ((xs ‖ ys).cast (by ring)) = (bitsToBytes xs) ‖ (bitsToBytes ys) := by
  apply Vector.ext
  intro i hi
  apply Byte.ext_testBit
  intro j hj
  rw [bitsToBytes_testBit _ i hi j hj, Vector.getElem_cast]
  by_cases hia : i < a
  · have h1 : 8 * i + j < 8 * a := by omega
    show ((xs ++ ys) : Vector _ _)[8 * i + j] =
        ((bitsToBytes xs ++ bitsToBytes ys) : Vector _ _)[i].toNat.testBit j
    rw [Vector.getElem_append_left h1, Vector.getElem_append_left hia,
        bitsToBytes_testBit _ i hia j hj]
  · have hia : a ≤ i := Nat.not_lt.mp hia
    have h1 : 8 * a ≤ 8 * i + j := by omega
    show ((xs ++ ys) : Vector _ _)[8 * i + j] =
        ((bitsToBytes xs ++ bitsToBytes ys) : Vector _ _)[i].toNat.testBit j
    rw [Vector.getElem_append_right (by omega) h1,
        Vector.getElem_append_right hi hia,
        bitsToBytes_testBit _ (i - a) (by omega) j hj]
    congr 1; omega

/-- Chain `n` calls to `SHAKE128.squeeze` of `k` bytes each, accumulating
    the output bytes. -/
def chainedSqueeze (k : Nat) :
    Incremental.sponge.state (b - 256) → (n : Nat) →
    Incremental.sponge.state (b - 256) × 𝔹 (k * n)
  | s, 0     => (s, ⟨#[], by simp⟩)
  | s, n + 1 =>
    let (s',  acc) := chainedSqueeze k s n
    let (s'', bs)  := SHAKE128.squeeze s' k
    (s'', (acc ++ bs).cast (by ring))

/-- State component of `chainedSqueeze` equals state of one big `squeeze1`. -/
private theorem chainedSqueeze_fst
    (k : Nat) (s : Incremental.sponge.state (b - 256)) (n : Nat) :
    (chainedSqueeze k s n).1 =
      (Incremental.sponge.squeeze1
          KECCAK_f (r := b - 256) (hr := by decide) s (8 * (k * n))).1 := by
  induction n with
  | zero =>
    /- Pass the actual `d = 8 * (k * 0)` to `squeeze1_no_perm` (don't try to
       reduce `8 * (k * 0)` first — it isn't rfl-equal to `0` in the goal). -/
    show s = _
    rw [sponge.squeeze1_no_perm KECCAK_f (b - 256) (by decide) s (8 * (k * 0))
        (by have := s.hx; omega)]
    rfl
  | succ n ih =>
    show (Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide)
            (chainedSqueeze k s n).1 (8 * k)).1
        = (Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide) s
            (8 * (k * (n + 1)))).1
    rw [ih]
    have hC := sponge.squeeze1_concat_bits KECCAK_f (b - 256) (by decide)
                  s (8 * (k * n)) (8 * k)
    have heq : 8 * (k * (n + 1)) = 8 * (k * n) + 8 * k := by ring
    conv_rhs => rw [heq]
    exact congrArg Prod.fst hC

/-- Byte component (as an array) of `chainedSqueeze` equals
    `bitsToBytes` applied to one big `squeeze1`'s bits. -/
private theorem chainedSqueeze_snd_array
    (k : Nat) (s : Incremental.sponge.state (b - 256)) (n : Nat) :
    (chainedSqueeze k s n).2.toArray
      = (bitsToBytes (Incremental.sponge.squeeze1
          KECCAK_f (r := b - 256) (hr := by decide) s (8 * (k * n))).2).toArray := by
  induction n with
  | zero =>
    show (#[] : Array Byte) = _
    rw [sponge.squeeze1_no_perm KECCAK_f (b - 256) (by decide) s (8 * (k * 0))
        (by have := s.hx; omega)]
    rfl
  | succ n ih =>
    set U := Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide)
              s (8 * (k * n))
    set V := Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide)
              U.1 (8 * k)
    set W := Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide)
              s (8 * (k * (n + 1)))
    show ((((chainedSqueeze k s n).2 ++
            (SHAKE128.squeeze (chainedSqueeze k s n).1 k).2) :
              𝔹 _).cast (by ring)).toArray = (bitsToBytes W.2).toArray
    rw [Vector.toArray_cast, Vector.toArray_append, ih]
    simp only [SHAKE128.squeeze]
    rw [chainedSqueeze_fst]
    have hbridge : ∀ {ℓ₁ ℓ₂ : Nat} (v₁ : Vector Bool (8 * ℓ₁))
                     (v₂ : Vector Bool (8 * ℓ₂)),
        ℓ₁ = ℓ₂ → v₁.toArray = v₂.toArray →
        (bitsToBytes v₁).toArray = (bitsToBytes v₂).toArray := by
      intros ℓ₁ ℓ₂ v₁ v₂ hℓ harr
      subst hℓ
      have hv : v₁ = v₂ := Vector.toArray_inj.1 harr
      rw [hv]
    have hba := bitsToBytes_append U.2 V.2
    have hLHS : (bitsToBytes U.2).toArray ++ (bitsToBytes V.2).toArray
              = (bitsToBytes ((U.2 ‖ V.2).cast (by ring : 8 * (k*n) + 8*k = 8 * (k*n + k)))).toArray := by
      show ((bitsToBytes U.2) ‖ (bitsToBytes V.2)).toArray = _
      rw [← hba]
    rw [hLHS]
    have hC := sponge.squeeze1_concat_bits KECCAK_f (b - 256) (by decide)
                  s (8 * (k * n)) (8 * k)
    have hC2 : (U.2 ‖ V.2).toArray
             = (Incremental.sponge.squeeze1 KECCAK_f (b - 256) (by decide)
                  s (8 * (k * n) + 8 * k)).2.toArray :=
      congrArg (fun p => p.2.toArray) hC
    exact hbridge (ℓ₁ := k * n + k) (ℓ₂ := k * (n + 1)) _ _ (by ring)
      ((Vector.toArray_cast ..).trans
        (hC2.trans (by
          have : 8 * (k * n) + 8 * k = 8 * (k * (n + 1)) := by ring
          rw [this])))

/-- **Byte-level corollary of `sponge.squeeze1_concat_bits`, specialised
    to SHAKE128.** Chained `(state, k-byte)` calls compose to one
    `(state, k·n-byte)` call. -/
theorem SHAKE128.squeeze_chain_eq_batch
    (k : Nat) (s : Incremental.sponge.state (b - 256)) (n : Nat) :
    chainedSqueeze k s n =
      (Incremental.sponge.squeeze1
          KECCAK_f (r := b - 256) (hr := by decide) s (8 * (k * n))).map
        id bitsToBytes := by
  apply Prod.ext
  · exact chainedSqueeze_fst k s n
  · apply Vector.toArray_inj.1
    exact chainedSqueeze_snd_array k s n

/-! ## §2.3a — Bridge: incremental `squeeze1` ↔ functional `SPONGE.squeeze`  -/

set_option maxHeartbeats 800000 in
/-- **Element-wise characterization of `sponge.squeeze1` from `x = 0`.**
    Position `i < d` of the squeezed bits is either the buffered bit `s.Z[i]`
    (when `i < s.Z.size`) or the bit
    `(f^[(i - s.Z.size)/r] s.S)[(i - s.Z.size) % r]` extracted from the
    appropriate `f`-permuted state.

    Proof by strong induction on the well-founded measure
    `s.x + d - (s.Z.size + r)` (same measure as `sponge.squeeze1`'s
    termination). -/
theorem sponge.squeeze1_at_x_zero_aux
    (f : Vector Bool b → Vector Bool b) (r : Nat) (hr : 0 < r ∧ r < b)
    (s : sponge.state r) (d : Nat) (h_x : s.x = 0)
    (i : Nat) (hi : i < d) :
    ((sponge.squeeze1 f r hr s d).2[i]'hi) =
      if h : i < s.Z.size then s.Z[i]'h
      else (f^[(i - s.Z.size)/r] s.S)[(i - s.Z.size) % r]'(by
        have := Nat.mod_lt (i - s.Z.size) hr.1; omega) := by
  by_cases hperm : s.Z.size + r < s.x + d
  case pos =>
    have hrec :
        sponge.squeeze1 f r hr s d
          = sponge.squeeze1 f r hr (sponge.squeeze_r f r hr s) d := by
      conv_lhs => unfold sponge.squeeze1
      rw [dif_pos hperm]
    rw [hrec]
    have h_x' : (sponge.squeeze_r f r hr s).x = 0 := by
      simp [sponge.squeeze_r, h_x]
    have IH := sponge.squeeze1_at_x_zero_aux f r hr (sponge.squeeze_r f r hr s) d h_x' i hi
    rw [IH]
    have hsr_Zs : (sponge.squeeze_r f r hr s).Z.size = s.Z.size + r := by
      simp [sponge.squeeze_r, SPONGE.squeeze_step]
    have hsr_Z_eq : (sponge.squeeze_r f r hr s).Z = s.Z ++ (Trunc r s.S).toArray := by
      simp [sponge.squeeze_r, SPONGE.squeeze_step]
    have hsr_S : (sponge.squeeze_r f r hr s).S = f s.S := by
      simp [sponge.squeeze_r, SPONGE.squeeze_step]
    by_cases h1 : i < s.Z.size + r
    · have hsr_Zs_lt : i < (sponge.squeeze_r f r hr s).Z.size := hsr_Zs ▸ h1
      rw [dif_pos hsr_Zs_lt]
      simp only [hsr_Z_eq]
      by_cases h2 : i < s.Z.size
      · rw [dif_pos h2, Array.getElem_append, dif_pos h2]
      · push Not at h2
        rw [dif_neg (Nat.not_lt.mpr h2), Array.getElem_append, dif_neg (Nat.not_lt.mpr h2)]
        have hir : i - s.Z.size < r := by omega
        have hdiv : (i - s.Z.size) / r = 0 := Nat.div_eq_of_lt hir
        have hmod : (i - s.Z.size) % r = i - s.Z.size := Nat.mod_eq_of_lt hir
        simp only [hdiv, hmod, Function.iterate_zero, id]
        simp [Trunc, Spec.slice]
    · push Not at h1
      have hsr_Zs_nlt : ¬ i < (sponge.squeeze_r f r hr s).Z.size := hsr_Zs ▸ Nat.not_lt.mpr h1
      have h2 : ¬ i < s.Z.size := by omega
      rw [dif_neg hsr_Zs_nlt, dif_neg h2]
      simp only [hsr_S, hsr_Zs]
      have heq1 : (i - (s.Z.size + r)) / r + 1 = (i - s.Z.size) / r := by
        rw [show i - s.Z.size = (i - (s.Z.size + r)) + r from by omega,
            Nat.add_div_right _ hr.1]
      have heq2 : (i - (s.Z.size + r)) % r = (i - s.Z.size) % r := by
        rw [show i - s.Z.size = (i - (s.Z.size + r)) + r from by omega,
            Nat.add_mod_right]
      simp only [heq2]
      have hiter : f^[(i - (s.Z.size + r)) / r] (f s.S) =
                   f^[(i - s.Z.size) / r] s.S := by
        rw [show f^[(i - (s.Z.size + r)) / r] (f s.S) =
                f^[(i - (s.Z.size + r)) / r + 1] s.S from by
          rw [Function.iterate_succ, Function.comp_apply]]
        rw [heq1]
      simp only [hiter]
  case neg =>
    push Not at hperm
    have hd' : s.x + d ≤ s.Z.size + r := hperm
    rw [sponge.squeeze1_no_perm f r hr s d hd']
    simp only [Vector.getElem_cast, Vector.getElem_mk]
    rw [Array.getElem_extract]
    have hsxi : s.x + i = i := by rw [h_x]; omega
    simp only [hsxi]
    rw [Array.getElem_append]
    by_cases h1 : i < s.Z.size
    · rw [dif_pos h1, dif_pos h1]
    · push Not at h1
      rw [dif_neg (Nat.not_lt.mpr h1), dif_neg (Nat.not_lt.mpr h1)]
      have hir : i - s.Z.size < r := by omega
      have hdiv : (i - s.Z.size) / r = 0 := Nat.div_eq_of_lt hir
      have hmod : (i - s.Z.size) % r = i - s.Z.size := Nat.mod_eq_of_lt hir
      simp only [hdiv, hmod, Function.iterate_zero, id]
      simp [Trunc, Spec.slice]
termination_by s.x + d - (s.Z.size + r)
decreasing_by
  simp [sponge.squeeze_r, SPONGE.squeeze_step]
  grind

/-- **Corollary: from a fully-buffered fresh state (`x = 0`, `Z = #[]`),
    `sponge.squeeze1` matches `SPONGE.squeeze` bit-for-bit.** -/
theorem sponge.squeeze1_init_eq_SPONGE_squeeze
    (f : Vector Bool b → Vector Bool b) (r : Nat) (hr : 0 < r ∧ r < b)
    (s : sponge.state r) (h_x : s.x = 0) (h_Z : s.Z = #[]) (d : Nat) :
    (sponge.squeeze1 f r hr s d).2 =
      SPONGE.squeeze (d := d) f r (#v[] : Vector Bool 0) s.S hr := by
  have hk : d ≤ d * r := by
    rcases Nat.eq_zero_or_pos d with hd0 | hdpos
    · subst hd0; simp
    · have h1 : 1 ≤ r := hr.1
      calc d = d * 1 := by ring
        _ ≤ d * r := Nat.mul_le_mul_left d h1
  rw [SPONGE_squeeze_eq_trunc_blocks (k := d) f s.S hr hk]
  apply Vector.ext
  intro i hi
  rw [sponge.squeeze1_at_x_zero_aux f r hr s d h_x i hi]
  rw [Trunc_getElem' _ _ i hi]
  rw [Vector.getElem_cast]
  rw [squeezeBlocks_getElem f r hr.1 (le_of_lt hr.2) s.S d i (by
    have h1 : 1 ≤ r := hr.1
    calc i < d := hi
      _ = d * 1 := by ring
      _ ≤ d * r := Nat.mul_le_mul_left d h1)]
  have h_Zs : s.Z.size = 0 := by rw [h_Z]; simp
  simp only [h_Zs, Nat.sub_zero, dif_neg (Nat.not_lt.mpr (Nat.zero_le i))]

/-- **SHAKE128 byte-level corollary.** Bytes squeezed via the incremental
    sponge from a `SHAKE128.absorb SHAKE128.init seed` state equal
    `shake128 seed outBytes`. -/
theorem SHAKE128.bitsToBytes_squeeze1_init_eq_shake128
    {n_seed : Nat} (seed : 𝔹 n_seed) (outBytes : Nat) :
    bitsToBytes
        (Incremental.sponge.squeeze1
            KECCAK_f (r := b - 256) (hr := by decide)
            (SHAKE128.absorb SHAKE128.init seed) (8 * outBytes)).2
      = shake128 seed outBytes := by
  let s := SHAKE128.absorb SHAKE128.init seed
  have hs_x : s.x = 0 := by
    simp [s, SHAKE128.absorb, SHAKE128.init, sponge.absorb1, sponge.init]
  have hs_Z : s.Z = #[] := by
    simp [s, SHAKE128.absorb, SHAKE128.init, sponge.absorb1, sponge.init]
  have hbridge := sponge.squeeze1_init_eq_SPONGE_squeeze KECCAK_f (b - 256)
                    (by decide) s hs_x hs_Z (8 * outBytes)
  show bitsToBytes (Incremental.sponge.squeeze1 KECCAK_f (b - 256) _ s _).2 = _
  rw [hbridge]
  unfold shake128 SHAKE128 KECCAK SPONGE
  simp only [Id.run]
  congr 1

/-! ## SHAKE256 byte-level corollaries

Parallel construction to the SHAKE128 versions above.  Same proofs,
modulo `b - 256 → b - 512` and `SHAKE128.* → SHAKE256.*`. -/

/-- Chain `n` calls to `SHAKE256.squeeze` of `k` bytes each. -/
def chainedSqueeze256 (k : Nat) :
    Incremental.sponge.state (b - 512) → (n : Nat) →
    Incremental.sponge.state (b - 512) × 𝔹 (k * n)
  | s, 0     => (s, ⟨#[], by simp⟩)
  | s, n + 1 =>
    let (s',  acc) := chainedSqueeze256 k s n
    let (s'', bs)  := SHAKE256.squeeze s' k
    (s'', (acc ++ bs).cast (by ring))

/-- State component of `chainedSqueeze256` equals state of one big `squeeze1`. -/
private theorem chainedSqueeze256_fst
    (k : Nat) (s : Incremental.sponge.state (b - 512)) (n : Nat) :
    (chainedSqueeze256 k s n).1 =
      (Incremental.sponge.squeeze1
          KECCAK_f (r := b - 512) (hr := by decide) s (8 * (k * n))).1 := by
  induction n with
  | zero =>
    show s = _
    rw [sponge.squeeze1_no_perm KECCAK_f (b - 512) (by decide) s (8 * (k * 0))
        (by have := s.hx; omega)]
    rfl
  | succ n ih =>
    show (Incremental.sponge.squeeze1 KECCAK_f (b - 512) (by decide)
            (chainedSqueeze256 k s n).1 (8 * k)).1
        = (Incremental.sponge.squeeze1 KECCAK_f (b - 512) (by decide) s
            (8 * (k * (n + 1)))).1
    rw [ih]
    have hC := sponge.squeeze1_concat_bits KECCAK_f (b - 512) (by decide)
                  s (8 * (k * n)) (8 * k)
    have heq : 8 * (k * (n + 1)) = 8 * (k * n) + 8 * k := by ring
    conv_rhs => rw [heq]
    exact congrArg Prod.fst hC

/-- Byte component (as an array) of `chainedSqueeze256` equals
    `bitsToBytes` applied to one big `squeeze1`'s bits. -/
private theorem chainedSqueeze256_snd_array
    (k : Nat) (s : Incremental.sponge.state (b - 512)) (n : Nat) :
    (chainedSqueeze256 k s n).2.toArray
      = (bitsToBytes (Incremental.sponge.squeeze1
          KECCAK_f (r := b - 512) (hr := by decide) s (8 * (k * n))).2).toArray := by
  induction n with
  | zero =>
    show (#[] : Array Byte) = _
    rw [sponge.squeeze1_no_perm KECCAK_f (b - 512) (by decide) s (8 * (k * 0))
        (by have := s.hx; omega)]
    rfl
  | succ n ih =>
    set U := Incremental.sponge.squeeze1 KECCAK_f (b - 512) (by decide)
              s (8 * (k * n))
    set V := Incremental.sponge.squeeze1 KECCAK_f (b - 512) (by decide)
              U.1 (8 * k)
    set W := Incremental.sponge.squeeze1 KECCAK_f (b - 512) (by decide)
              s (8 * (k * (n + 1)))
    show ((((chainedSqueeze256 k s n).2 ++
            (SHAKE256.squeeze (chainedSqueeze256 k s n).1 k).2) :
              𝔹 _).cast (by ring)).toArray = (bitsToBytes W.2).toArray
    rw [Vector.toArray_cast, Vector.toArray_append, ih]
    simp only [SHAKE256.squeeze]
    rw [chainedSqueeze256_fst]
    have hbridge : ∀ {ℓ₁ ℓ₂ : Nat} (v₁ : Vector Bool (8 * ℓ₁))
                     (v₂ : Vector Bool (8 * ℓ₂)),
        ℓ₁ = ℓ₂ → v₁.toArray = v₂.toArray →
        (bitsToBytes v₁).toArray = (bitsToBytes v₂).toArray := by
      intros ℓ₁ ℓ₂ v₁ v₂ hℓ harr
      subst hℓ
      have hv : v₁ = v₂ := Vector.toArray_inj.1 harr
      rw [hv]
    have hba := bitsToBytes_append U.2 V.2
    have hLHS : (bitsToBytes U.2).toArray ++ (bitsToBytes V.2).toArray
              = (bitsToBytes ((U.2 ‖ V.2).cast (by ring : 8 * (k*n) + 8*k = 8 * (k*n + k)))).toArray := by
      show ((bitsToBytes U.2) ‖ (bitsToBytes V.2)).toArray = _
      rw [← hba]
    rw [hLHS]
    have hC := sponge.squeeze1_concat_bits KECCAK_f (b - 512) (by decide)
                  s (8 * (k * n)) (8 * k)
    have hC2 : (U.2 ‖ V.2).toArray
             = (Incremental.sponge.squeeze1 KECCAK_f (b - 512) (by decide)
                  s (8 * (k * n) + 8 * k)).2.toArray :=
      congrArg (fun p => p.2.toArray) hC
    exact hbridge (ℓ₁ := k * n + k) (ℓ₂ := k * (n + 1)) _ _ (by ring)
      ((Vector.toArray_cast ..).trans
        (hC2.trans (by
          have : 8 * (k * n) + 8 * k = 8 * (k * (n + 1)) := by ring
          rw [this])))

/-- **Byte-level corollary of `sponge.squeeze1_concat_bits`, specialised
    to SHAKE256.** Chained `(state, k-byte)` calls compose to one
    `(state, k·n-byte)` call. -/
theorem SHAKE256.squeeze_chain_eq_batch
    (k : Nat) (s : Incremental.sponge.state (b - 512)) (n : Nat) :
    chainedSqueeze256 k s n =
      (Incremental.sponge.squeeze1
          KECCAK_f (r := b - 512) (hr := by decide) s (8 * (k * n))).map
        id bitsToBytes := by
  apply Prod.ext
  · exact chainedSqueeze256_fst k s n
  · apply Vector.toArray_inj.1
    exact chainedSqueeze256_snd_array k s n

/-- **SHAKE256 byte-level corollary.** Bytes squeezed via the incremental
    sponge from a `SHAKE256.absorb SHAKE256.init seed` state equal
    `shake256 seed outBytes`. -/
theorem SHAKE256.bitsToBytes_squeeze1_init_eq_shake256
    {n_seed : Nat} (seed : 𝔹 n_seed) (outBytes : Nat) :
    bitsToBytes
        (Incremental.sponge.squeeze1
            KECCAK_f (r := b - 512) (hr := by decide)
            (SHAKE256.absorb SHAKE256.init seed) (8 * outBytes)).2
      = shake256 seed outBytes := by
  let s := SHAKE256.absorb SHAKE256.init seed
  have hs_x : s.x = 0 := by
    simp [s, SHAKE256.absorb, SHAKE256.init, sponge.absorb1, sponge.init]
  have hs_Z : s.Z = #[] := by
    simp [s, SHAKE256.absorb, SHAKE256.init, sponge.absorb1, sponge.init]
  have hbridge := sponge.squeeze1_init_eq_SPONGE_squeeze KECCAK_f (b - 512)
                    (by decide) s hs_x hs_Z (8 * outBytes)
  show bitsToBytes (Incremental.sponge.squeeze1 KECCAK_f (b - 512) _ s _).2 = _
  rw [hbridge]
  unfold shake256 SHAKE256 KECCAK SPONGE
  simp only [Id.run]
  congr 1

end Spec.SHA3
