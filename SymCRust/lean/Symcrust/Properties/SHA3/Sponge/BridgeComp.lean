import Symcrust.Properties.SHA3.Sponge.BridgeRepr

/-!
# SHA-3 Sponge Bridge — Composition lemmas

Pure-functional decomposition of bridge operations (`absorbBytesRaw`,
`squeezeAfter`, `squeezeBytes`, `extractOutput`, `GhostState.squeezeAdvance`)
over list/index splits. These compose sub-loop FC into wrapper FC.

Plus the slice-write composition lemma for output content reasoning.
-/

namespace symcrust.sha3.sha3_impl

open Aeneas Aeneas.Std Spec
open Spec (𝔹 bytesToBits bitsToBytes Bits.toNatLE)
open Spec.SHA3 (b w KECCAK_f SPONGE)
open scoped Spec.Notations
open scoped Spec.SHA3

/-! ## `absorbBytes` — block-aware -/

/-- The accumulator's index field after the foldl form of `absorbBytesRaw`
is just `idx + length`, regardless of state. -/
private theorem absorbBytesRaw_foldl_snd
    (S : Vector Bool SHA3.b) (j : Nat) (l : List U8) :
    (l.foldl (fun (acc : Vector Bool SHA3.b × Nat) byte =>
       (absorbByte acc.1 acc.2 byte, acc.2 + 1)) (S, j)).2 = j + l.length := by
  induction l generalizing S j with
  | nil => simp
  | cons x rest ih =>
    simp only [List.foldl_cons, List.length_cons, ih]
    omega

/-- `absorbBytesRaw` equals `absorbBytes` when no block boundary is crossed. -/
private theorem absorbBytesRaw_eq_absorbBytes (S : Vector Bool SHA3.b) (idx rate : Nat)
    (data : List U8) (h : idx + data.length < rate) :
    absorbBytesRaw S idx data = (absorbBytes S idx rate data).1 := by
  induction data generalizing S idx with
  | nil => rfl
  | cons byte rest ih =>
    have hne : idx + 1 ≠ rate := by simp [List.length] at h; omega
    -- Unfold absorbBytesRaw on cons via its foldl definition.
    unfold absorbBytesRaw
    rw [List.foldl_cons]
    -- Unfold absorbBytes on cons.
    unfold absorbBytes
    simp only [hne, ite_false]
    -- Now both sides have the form X = X via the IH (with rest).
    exact ih _ _ (by simp [List.length] at h ⊢; omega)

/-- Absorbing `d₁ ++ d₂` equals absorbing `d₁` then `d₂`. -/
theorem absorbBytes_append (S : Vector Bool SHA3.b) (idx rate : Nat)
    (d₁ d₂ : List U8) :
    absorbBytes S idx rate (d₁ ++ d₂) =
    let (S', idx') := absorbBytes S idx rate d₁
    absorbBytes S' idx' rate d₂ := by
  induction d₁ generalizing S idx with
  | nil => rfl
  | cons byte rest ih =>
    show absorbBytes S idx rate (byte :: (rest ++ d₂)) = _
    conv_lhs => rw [show absorbBytes S idx rate (byte :: (rest ++ d₂)) =
                    (let S' := absorbByte S idx byte
                     let idx' := idx + 1
                     if idx' = rate then absorbBytes (KECCAK_f S') 0 rate (rest ++ d₂)
                     else absorbBytes S' idx' rate (rest ++ d₂)) from rfl]
    conv_rhs => rw [show absorbBytes S idx rate (byte :: rest) =
                    (let S' := absorbByte S idx byte
                     let idx' := idx + 1
                     if idx' = rate then absorbBytes (KECCAK_f S') 0 rate rest
                     else absorbBytes S' idx' rate rest) from rfl]
    by_cases h : idx + 1 = rate
    · simp only [h, ↓reduceIte]
      exact ih _ _
    · simp only [h, ↓reduceIte]
      exact ih _ _

/-! ## `absorbBytesRaw` -/

@[simp]
theorem absorbBytesRaw_nil (S : Vector Bool SHA3.b) (idx : Nat) :
    absorbBytesRaw S idx [] = S := rfl

theorem absorbBytesRaw_singleton (S : Vector Bool SHA3.b) (idx : Nat) (b : U8) :
    absorbBytesRaw S idx [b] = absorbByte S idx b := rfl

theorem absorbBytesRaw_append (S : Vector Bool SHA3.b) (idx : Nat)
    (xs ys : List U8) :
    absorbBytesRaw S idx (xs ++ ys) =
      absorbBytesRaw (absorbBytesRaw S idx xs) (idx + xs.length) ys := by
  -- With `absorbBytesRaw` defined via `List.foldl`, we just need to rewrite
  -- the LHS through `List.foldl_append` and then show the outer `foldl`'s
  -- starting accumulator agrees on the `.2` component (the `.1` is `rfl`).
  unfold absorbBytesRaw
  rw [List.foldl_append]
  -- Goal: outer foldl over ys with start (xs.foldl …) = outer foldl over ys with
  -- start ((xs.foldl …).1, idx + xs.length), at .1.
  -- Both starts have the same .1; the .2 differs but is given by the helper.
  have hpair :
      (xs.foldl (fun (acc : Vector Bool SHA3.b × Nat) byte =>
         (absorbByte acc.1 acc.2 byte, acc.2 + 1)) (S, idx)) =
      ((xs.foldl (fun (acc : Vector Bool SHA3.b × Nat) byte =>
         (absorbByte acc.1 acc.2 byte, acc.2 + 1)) (S, idx)).1, idx + xs.length) := by
    apply Prod.ext
    · rfl
    · exact absorbBytesRaw_foldl_snd S idx xs
  rw [hpair]

/-! ### Algebraic decomposition: `absorbByte` / `absorbBytesRaw` as XOR -/

/-- `absorbByte S idx val` is `S` XORed with the shifted byte pattern. -/
theorem absorbByte_eq_xor (S : Vector Bool SHA3.b) (idx : Nat) (val : U8) :
    absorbByte S idx val = S ⊕ shiftedByte val idx := by
  apply Vector.ext
  intro i hi
  unfold absorbByte shiftedByte
  show (Vector.ofFn _)[i] = (Vector.zipWith (· != ·) S (Vector.ofFn _))[i]
  rw [Vector.getElem_ofFn, Vector.getElem_zipWith, Vector.getElem_ofFn]
  cases (BitVec.zeroExtend SHA3.b val.bv <<< (8 * idx)).getLsbD i <;>
    cases S[i] <;> rfl

/-- `absorbBytesRaw S idx chunk` is `S` XORed with the chunk's bit-pattern.
    This is the algebraic / concatenation-based characterisation; replaces the
    earlier element-wise `absorbBytesRaw_getElem`. -/
theorem absorbBytesRaw_eq_xor (S : Vector Bool SHA3.b) (idx : Nat) (chunk : List U8) :
    absorbBytesRaw S idx chunk = S ⊕ chunkBits idx chunk := by
  induction chunk generalizing S idx with
  | nil =>
    show absorbBytesRaw S idx [] = (S ⊕ Vector.replicate SHA3.b false : Vector Bool SHA3.b)
    have heq : absorbBytesRaw S idx [] = S := by unfold absorbBytesRaw; rfl
    rw [heq]
    apply Vector.ext; intro i hi
    show _ = (Vector.zipWith _ _ _)[i]
    rw [Vector.getElem_zipWith, Vector.getElem_replicate]
    cases S[i] <;> rfl
  | cons byte rest ih =>
    have h1 : absorbBytesRaw S idx (byte :: rest)
            = absorbBytesRaw (absorbByte S idx byte) (idx + 1) rest := by
      unfold absorbBytesRaw; rw [List.foldl_cons]
    rw [h1, ih, absorbByte_eq_xor]
    -- Goal: (S ⊕ shiftedByte byte idx) ⊕ chunkBits (idx + 1) rest
    --     = S ⊕ chunkBits idx (byte :: rest)
    -- chunkBits idx (byte :: rest) = shiftedByte byte idx ⊕ chunkBits (idx + 1) rest by def
    apply Vector.ext; intro i hi
    show (Vector.zipWith _ (Vector.zipWith _ _ _) _)[i]
       = (Vector.zipWith _ _ (Vector.zipWith _ _ _))[i]
    repeat rw [Vector.getElem_zipWith]
    cases S[i] <;> cases (shiftedByte byte idx)[i] <;>
      cases (chunkBits (idx + 1) rest)[i] <;> rfl

/-! ### Bit-level access to `chunkBits` -/

/-- `(shiftedByte val idx)[j]` extracts the bit at position `j` from the byte
    `val` placed at byte position `idx`. Outside the byte's range, gives `false`. -/
theorem shiftedByte_getElem (val : U8) (idx j : Nat) (hj : j < SHA3.b) :
    (shiftedByte val idx)[j] =
    (decide (8 * idx ≤ j ∧ j < 8 * idx + 8) && val.bv.getLsbD (j - 8 * idx)) := by
  unfold shiftedByte
  rw [Vector.getElem_ofFn, BitVec.getLsbD_shiftLeft, BitVec.getLsbD_setWidth]
  simp [hj]
  by_cases h1 : j < 8 * idx
  · simp [h1, show ¬ (8 * idx ≤ j) from by omega]
  · push Not at h1
    simp [show ¬ (j < 8 * idx) from by omega, h1]
    by_cases h2 : j - 8 * idx < 8
    · simp [show j - 8 * idx < SHA3.b from by show _ < 1600; omega,
            show j < 8 * idx + 8 from by omega]
    · push Not at h2
      simp [show ¬ (j < 8 * idx + 8) from by omega]
      have : val.bv.getLsbD (j - 8*idx) = false := BitVec.getLsbD_of_ge val.bv _ h2
      simp [this]

/-- `(chunkBits idx chunk)[j]` extracts bit `j` from the chunk's bit-pattern.
    Outside the chunk's byte range, gives `false`; inside, picks the right bit
    of the right byte. -/
theorem chunkBits_getElem (idx j : Nat) (chunk : List U8) (hj : j < SHA3.b) :
    (chunkBits idx chunk)[j] =
    (decide (8 * idx ≤ j ∧ j < 8 * idx + 8 * chunk.length) &&
     (chunk[(j - 8 * idx) / 8]!).bv.getLsbD ((j - 8 * idx) % 8)) := by
  induction chunk generalizing idx with
  | nil =>
    simp only [chunkBits, List.length_nil, Nat.mul_zero, Nat.add_zero]
    rw [Vector.getElem_replicate]
    have : ¬ (8 * idx ≤ j ∧ j < 8 * idx) := by intro ⟨_, h⟩; omega
    simp [this]
  | cons byte rest ih =>
    show (Vector.zipWith _ _ _)[j] = _
    rw [Vector.getElem_zipWith, shiftedByte_getElem _ _ _ hj, ih (idx + 1),
        show (byte :: rest).length = rest.length + 1 from rfl]
    by_cases h1 : j < 8 * idx
    · have hno : ¬ (8 * idx ≤ j ∧ j < 8 * idx + 8) := by intro ⟨_, _⟩; omega
      have hno' : ¬ (8 * (idx + 1) ≤ j ∧ j < 8 * (idx + 1) + 8 * rest.length) := by
        intro ⟨_, _⟩; omega
      have hno'' : ¬ (8 * idx ≤ j ∧ j < 8 * idx + 8 * (rest.length + 1)) := by
        intro ⟨_, _⟩; omega
      simp [hno, hno', hno'']
    · push Not at h1
      by_cases h2 : j < 8 * idx + 8
      · have hyes : 8 * idx ≤ j ∧ j < 8 * idx + 8 := ⟨h1, h2⟩
        have hno' : ¬ (8 * (idx + 1) ≤ j ∧ j < 8 * (idx + 1) + 8 * rest.length) := by
          intro ⟨_, _⟩; omega
        have hyes'' : 8 * idx ≤ j ∧ j < 8 * idx + 8 * (rest.length + 1) :=
          ⟨h1, by omega⟩
        simp only [hyes, hno', hyes'', decide_false, Bool.false_and,
                   Bool.bne_false]
        have hjdiv : (j - 8 * idx) / 8 = 0 := by
          apply Nat.div_eq_of_lt; omega
        have hjmod : (j - 8 * idx) % 8 = j - 8 * idx := by
          apply Nat.mod_eq_of_lt; omega
        simp [hjdiv, hjmod]
      · push Not at h2
        have hno : ¬ (8 * idx ≤ j ∧ j < 8 * idx + 8) := by intro ⟨_, _⟩; omega
        simp only [hno, decide_false, Bool.false_and, Bool.false_bne]
        by_cases h3 : j < 8 * (idx + 1) + 8 * rest.length
        · have hyes' : 8 * (idx + 1) ≤ j ∧ j < 8 * (idx + 1) + 8 * rest.length :=
            ⟨by omega, h3⟩
          have hyes'' : 8 * idx ≤ j ∧ j < 8 * idx + 8 * (rest.length + 1) := by
            refine ⟨h1, ?_⟩; omega
          rw [show decide (8 * (idx + 1) ≤ j ∧ j < 8 * (idx + 1) + 8 * rest.length) = true
                from decide_eq_true hyes',
              show decide (8 * idx ≤ j ∧ j < 8 * idx + 8 * (rest.length + 1)) = true
                from decide_eq_true hyes'']
          simp only [Bool.true_and]
          have hsub : j - 8 * idx = (j - 8 * (idx + 1)) + 8 := by omega
          rw [hsub]
          have hdiv : ((j - 8 * (idx + 1)) + 8) / 8 = (j - 8 * (idx + 1)) / 8 + 1 := by
            rw [Nat.add_div_right _ (by omega)]
          have hmod : ((j - 8 * (idx + 1)) + 8) % 8 = (j - 8 * (idx + 1)) % 8 := by
            rw [Nat.add_mod_right]
          rw [hdiv, hmod]
          show (byte :: rest)[(j - 8*(idx+1))/8 + 1]!.bv.getLsbD _ = _
          rw [List.getElem!_cons_succ]
        · push Not at h3
          have hno' : ¬ (8 * (idx + 1) ≤ j ∧ j < 8 * (idx + 1) + 8 * rest.length) := by
            intro ⟨_, _⟩; omega
          have hno'' : ¬ (8 * idx ≤ j ∧ j < 8 * idx + 8 * (rest.length + 1)) := by
            intro ⟨_, _⟩; omega
          simp [hno', hno'']

/-! ### Lane-level absorb bridge -/

/-- **Lane absorb bridge**: updating an aligned 8-byte lane with the code's
    `from_le_bytes` XOR equals 8 successive `absorbByte` operations on the
    bit-vector representation. -/
theorem absorbLane_bridge
    (a : Keccak1600) (idx : Nat) (bs : List U8)
    (lane_idx : Usize) (new_lane : U64)
    (hbound : idx + 8 ≤ 200)
    (halign : idx % 8 = 0)
    (hlen : bs.length = 8)
    (hlane : lane_idx.val = idx / 8)
    (hnew : ∀ k : Nat, k < 64 →
        new_lane.bv.getLsbD k =
        ((a.val[idx / 8]!).bv.getLsbD k != (bs[k / 8]!).bv.getLsbD (k % 8))) :
    toBits (Std.Array.set a lane_idx new_lane) = absorbBytesRaw (toBits a) idx bs := by
  rw [absorbBytesRaw_eq_xor]
  apply Vector.ext
  intro j hj
  show (toBits _)[j] = (Vector.zipWith _ _ _)[j]
  rw [Vector.getElem_zipWith]
  have hidx8 : idx / 8 < 25 := by omega
  have h8idx : 8 * idx = 64 * (idx / 8) := by
    have := Nat.div_add_mod idx 8; omega
  have hwidth : SHA3.w = 64 := rfl
  have hlen_a : a.val.length = 25 := a.property
  by_cases heq : j / 64 = idx / 8
  · -- j is in the modified lane
    have hjdivw : j / SHA3.w = idx / 8 := by rw [hwidth]; exact heq
    rw [toBits_getElem' _ j hj]
    show ((Std.Array.set a lane_idx new_lane).val)[j / SHA3.w]!.bv.getLsbD (j % SHA3.w) = _
    simp only [Aeneas.Std.Array.set_val_eq]
    have hlane_lt : lane_idx.val < a.val.length := by rw [hlane, hlen_a]; omega
    rw [show (j / SHA3.w) = lane_idx.val from by rw [hjdivw, hlane]]
    simp_lists
    show new_lane.bv.getLsbD (j % SHA3.w) = _
    rw [hwidth, hnew (j % 64) (Nat.mod_lt _ (by omega))]
    rw [toBits_getElem' a j hj, hwidth]
    rw [show (a.val)[idx/8]! = a.val[j/64]! from by rw [heq]]
    rw [chunkBits_getElem _ _ _ hj]
    have hin : 8 * idx ≤ j ∧ j < 8 * idx + 8 * bs.length := by
      refine ⟨?_, ?_⟩
      · rw [h8idx, ← heq]; have := Nat.div_add_mod j 64; omega
      · rw [hlen, h8idx, ← heq]
        have := Nat.div_add_mod j 64
        have : j % 64 < 64 := Nat.mod_lt _ (by omega)
        omega
    rw [show decide (8 * idx ≤ j ∧ j < 8 * idx + 8 * bs.length) = true
          from decide_eq_true hin]
    simp only [Bool.true_and]
    have hjsub : j - 8 * idx = j % 64 := by
      rw [h8idx, ← heq]; have := Nat.div_add_mod j 64; omega
    rw [hjsub]
  · -- j is NOT in the modified lane
    have hjdivw : ¬ (j / SHA3.w = idx / 8) := by rw [hwidth]; exact heq
    rw [toBits_getElem' _ j hj]
    show ((Std.Array.set a lane_idx new_lane).val)[j / SHA3.w]!.bv.getLsbD (j % SHA3.w) = _
    simp only [Aeneas.Std.Array.set_val_eq]
    have hlane_ne : Nat.not_eq lane_idx.val (j / SHA3.w) := by
      left; rw [hlane]; exact fun h => hjdivw h.symm
    simp_lists
    rw [toBits_getElem' a j hj, chunkBits_getElem _ _ _ hj]
    have hout : ¬ (8 * idx ≤ j ∧ j < 8 * idx + 8 * bs.length) := by
      rw [hlen, h8idx]
      intro ⟨h1, h2⟩
      have hjdiv2 : j < 64 * (j/64 + 1) := by
        have := Nat.div_add_mod j 64
        have : j % 64 < 64 := Nat.mod_lt _ (by omega)
        omega
      have hjdiv : 64 * (j / 64) ≤ j := by
        have := Nat.div_add_mod j 64; omega
      have : j / 64 = idx / 8 := by omega
      exact heq this
    rw [show decide (8 * idx ≤ j ∧ j < 8 * idx + 8 * bs.length) = false
          from decide_eq_false hout]
    simp

/-! ### Helpers for `absorbBytesRaw` element-wise reasoning (legacy)

These are the bit-level characterisations of `absorbByte`. The
algebraic form (`absorbBytesRaw_eq_xor`) is preferred where available. -/

/-- Bit-level access to `absorbByte`. -/
private theorem absorbByte_getElem_aux (S : Vector Bool SHA3.b) (idx : Nat) (val : U8)
    (i : Nat) (hi : i < SHA3.b) :
    ((absorbByte S idx val)[i]'hi) =
    ((S[i]'hi) ^^ ((val.bv.zeroExtend SHA3.b <<< (8 * idx)).getLsbD i)) := by
  unfold absorbByte; exact Vector.getElem_ofFn hi

private theorem shift_byte_getLsbD (val : U8) (idx i : Nat) (hi : i < SHA3.b) :
    (val.bv.zeroExtend SHA3.b <<< (8 * idx)).getLsbD i =
    (decide (8 * idx ≤ i ∧ i < 8 * idx + 8) && val.bv.getLsbD (i - 8 * idx)) := by
  rw [BitVec.getLsbD_shiftLeft, BitVec.getLsbD_setWidth]
  simp [hi]
  by_cases h1 : i < 8 * idx
  · simp [h1, show ¬ (8 * idx ≤ i) from by omega]
  · push Not at h1
    simp [show ¬ (i < 8 * idx) from by omega, h1]
    by_cases h2 : i - 8 * idx < 8
    · simp [show i - 8 * idx < SHA3.b from by show _ < 1600; omega,
            show i < 8 * idx + 8 from by omega]
    · push Not at h2
      simp [show ¬ (i < 8 * idx + 8) from by omega]
      have : val.bv.getLsbD (i - 8*idx) = false := BitVec.getLsbD_of_ge val.bv _ h2
      simp [this]

/-! ## `squeezeAfter` -/

theorem squeezeAfter_zero (S : Vector Bool SHA3.b) (idx rate : Nat) :
    squeezeAfter S idx rate 0 = (S, idx) := rfl

theorem squeezeAfter_succ (S : Vector Bool SHA3.b) (idx rate n : Nat) :
    squeezeAfter S idx rate (n + 1) =
      let (S', idx') := squeezeAfter S idx rate n
      let (S'', idx'') := if idx' = rate then (KECCAK_f S', 0) else (S', idx')
      (S'', idx'' + 1) := rfl

/-- The trailing index after `squeezeAfter` is bounded by `rate` whenever the
    starting index is and `rate ≥ 1`. -/
theorem squeezeAfter_idx_le_rate (S : Vector Bool SHA3.b) (idx rate n : Nat)
    (hidx : idx ≤ rate) (hr : 0 < rate) :
    (squeezeAfter S idx rate n).2 ≤ rate := by
  induction n with
  | zero => simpa [squeezeAfter_zero]
  | succ k ih =>
    rw [squeezeAfter_succ S idx rate k]
    by_cases h : (squeezeAfter S idx rate k).2 = rate
    · simp [h]; omega
    · simp [h]; omega

theorem squeezeAfter_add (S : Vector Bool SHA3.b) (idx rate n m : Nat) :
    squeezeAfter S idx rate (n + m) =
      let (Sn, idxn) := squeezeAfter S idx rate n
      squeezeAfter Sn idxn rate m := by
  induction m with
  | zero => simp [squeezeAfter_zero]
  | succ m ih =>
    show squeezeAfter S idx rate (n + m + 1) =
         (let (Sn, idxn) := squeezeAfter S idx rate n
          squeezeAfter Sn idxn rate (m + 1))
    rw [squeezeAfter_succ S idx rate (n + m)]
    rw [ih]
    generalize squeezeAfter S idx rate n = p
    obtain ⟨Sn, idxn⟩ := p
    show (let (S', idx') := squeezeAfter Sn idxn rate m
          let (S'', idx'') := if idx' = rate then (KECCAK_f S', 0) else (S', idx')
          (S'', idx'' + 1)) =
         squeezeAfter Sn idxn rate (m + 1)
    rw [squeezeAfter_succ]

/-- After a full block (idx = rate), squeezing `n ≥ 1` more bytes is the same as
    permuting first and squeezing `n` bytes from idx 0. -/
theorem squeezeAfter_post_full_block (S : Vector Bool SHA3.b) (rate n : Nat)
    (hr : 0 < rate) (hn : 0 < n) :
    squeezeAfter S rate rate n = squeezeAfter (KECCAK_f S) 0 rate n := by
  induction n with
  | zero => omega
  | succ k ih =>
    by_cases hk : k = 0
    · subst hk
      show squeezeAfter S rate rate 1 = squeezeAfter (KECCAK_f S) 0 rate 1
      rw [show (1 : Nat) = 0 + 1 from rfl, squeezeAfter_succ, squeezeAfter_succ]
      simp [squeezeAfter_zero, hr.ne']
    · have hk_pos : 0 < k := Nat.pos_of_ne_zero hk
      rw [squeezeAfter_succ S rate rate k, squeezeAfter_succ (KECCAK_f S) 0 rate k,
          ih hk_pos]

/-! ## `squeezeBytes` -/

theorem squeezeBytes_getElem (S : Vector Bool SHA3.b) (idx rate m : Nat)
    (k : Nat) (hk : k < m) :
    (squeezeBytes S idx rate m)[k] =
      (let (S_k, idx_k) := squeezeAfter S idx rate k
       let (S_k', idx_k') := if idx_k = rate then (KECCAK_f S_k, 0) else (S_k, idx_k)
       squeezeByte S_k' idx_k') := by
  simp only [squeezeBytes, Vector.getElem_ofFn]

/-- Companion to `squeezeAfter_post_full_block` for `squeezeBytes`. -/
theorem squeezeBytes_post_full_block (S : Vector Bool SHA3.b) (rate n : Nat)
    (hr : 0 < rate) (_hn : 0 < n) :
    squeezeBytes S rate rate n = squeezeBytes (KECCAK_f S) 0 rate n := by
  apply Vector.ext
  intro k hk
  rw [squeezeBytes_getElem _ _ _ _ k hk, squeezeBytes_getElem _ _ _ _ k hk]
  by_cases hk0 : k = 0
  · subst hk0
    simp [squeezeAfter_zero, hr.ne']
  · have hk_pos : 0 < k := Nat.pos_of_ne_zero hk0
    rw [squeezeAfter_post_full_block S rate k hr hk_pos]

/-- Characterise `squeezeAfter S 0 rate n` via `Nat.iterate KECCAK_f`.

    For `n ≥ 1`, `squeezeAfter S 0 rate n = (KECCAK_f^[(n-1)/rate] S, ((n-1) % rate) + 1)`.

    Used by `squeezeBytes_eq_SPONGE_squeeze` to expose the iteration count. -/
private theorem squeezeAfter_iterate (S : Vector Bool SHA3.b) (rate n : Nat)
    (hr : 0 < rate) (hn : 1 ≤ n) :
    squeezeAfter S 0 rate n =
      (KECCAK_f^[(n - 1) / rate] S, ((n - 1) % rate) + 1) := by
  induction n with
  | zero => omega
  | succ n ih =>
    -- Normalise `n + 1 - 1 = n` in the goal once.
    show squeezeAfter S 0 rate (n + 1) =
      (KECCAK_f^[n / rate] S, n % rate + 1)
    by_cases hn0 : n = 0
    · -- Base case: n = 0, so we are proving for n+1 = 1.
      subst hn0
      simp only [squeezeAfter_succ, squeezeAfter_zero, Nat.zero_div, Nat.zero_mod,
                 Function.iterate_zero, id]
      have : (0 : Nat) ≠ rate := Nat.ne_of_lt hr
      simp [this]
    · -- Inductive step: n ≥ 1, use IH for `squeezeAfter S 0 rate n`.
      have hnpos : 1 ≤ n := Nat.one_le_iff_ne_zero.mpr hn0
      have ih' := ih hnpos
      rw [squeezeAfter_succ, ih']
      simp only
      by_cases hb : ((n - 1) % rate) + 1 = rate
      · -- Boundary: idx hits rate, permute, idx → 1, iterate count +1.
        simp only [hb, if_true]
        have hmod : (n - 1) % rate = rate - 1 := by omega
        have hsub : n = rate * ((n - 1) / rate + 1) := by
          have h := Nat.div_add_mod (n - 1) rate
          rw [hmod] at h
          have hrhs : rate * ((n - 1) / rate + 1) = rate * ((n - 1) / rate) + rate :=
            Nat.mul_succ rate ((n - 1) / rate)
          omega
        have hdiv : n / rate = (n - 1) / rate + 1 := by
          conv_lhs => rw [hsub]
          exact Nat.mul_div_cancel_left _ hr
        have hmod0 : n % rate = 0 := by
          conv_lhs => rw [hsub]
          exact Nat.mul_mod_right _ _
        rw [hdiv, hmod0, Function.iterate_succ', Function.comp_apply]
      · -- Non-boundary: idx < rate, no permute, idx → idx + 1.
        simp only [hb, if_false]
        have hmod_lt : (n - 1) % rate + 1 < rate := by
          have := Nat.mod_lt (n - 1) hr; omega
        have hsub : n = rate * ((n - 1) / rate) + ((n - 1) % rate + 1) := by
          have h := Nat.div_add_mod (n - 1) rate; omega
        have hdiv : n / rate = (n - 1) / rate := by
          conv_lhs => rw [hsub]
          rw [Nat.mul_add_div hr, Nat.div_eq_of_lt hmod_lt, Nat.add_zero]
        have hmod : n % rate = (n - 1) % rate + 1 := by
          conv_lhs => rw [hsub]
          rw [Nat.mul_add_mod, Nat.mod_eq_of_lt hmod_lt]
        rw [hdiv, hmod]

/-- When `rate` is a multiple of 8 and we squeeze a multiple of 8 bytes from
    aligned start, the resulting index is also a multiple of 8.
    Used to discharge `halign` after `extract_lanes_state.spec` in the
    boundary case of `extract.spec`. -/
theorem squeezeAfter_idx_mod8_of_zero (S : Vector Bool SHA3.b) (rate n : Nat)
    (hr : 0 < rate) (hr8 : rate % 8 = 0) (hn8 : n % 8 = 0) :
    (squeezeAfter S 0 rate n).2 % 8 = 0 := by
  by_cases hn0 : n = 0
  · subst hn0; rfl
  · have hn_pos : 1 ≤ n := Nat.one_le_iff_ne_zero.mpr hn0
    rw [squeezeAfter_iterate S rate n hr hn_pos]
    show ((n - 1) % rate + 1) % 8 = 0
    have h78 : (n - 1) % 8 = 7 := by omega
    have hd : 8 ∣ rate := Nat.dvd_of_mod_eq_zero hr8
    have h_mod_8 : (n - 1) % rate % 8 = (n - 1) % 8 := Nat.mod_mod_of_dvd (n - 1) hd
    omega

/-- Direct byte-access form: byte k of `squeezeBytes S 0 rate m` equals
    `squeezeByte (KECCAK_f^[k/rate] S) (k % rate)`. Combines
    `squeezeBytes_getElem` + `squeezeAfter_iterate` + the boundary-permute
    case analysis (when k % rate = 0 the permute-then-read recovers the
    same form as the non-boundary case via `KECCAK_f^[(k-1)/rate + 1]
    = KECCAK_f^[k/rate]`).

    Depends on `squeezeAfter_iterate`. -/
theorem squeezeBytes_byte_eq (S : Vector Bool SHA3.b) (rate m : Nat)
    (hr : 0 < rate) (k : Nat) (hk : k < m) :
    (squeezeBytes S 0 rate m)[k] =
      squeezeByte (KECCAK_f^[k / rate] S) (k % rate) := by
  rw [squeezeBytes_getElem S 0 rate m k hk]
  simp only
  by_cases hk0 : k = 0
  · -- Base case: k = 0, squeezeAfter S 0 rate 0 = (S, 0), idx = 0 ≠ rate.
    subst hk0
    simp only [squeezeAfter_zero, Nat.zero_div, Nat.zero_mod, Function.iterate_zero, id]
    have : (0 : Nat) ≠ rate := Nat.ne_of_lt hr
    simp [this]
  · -- k ≥ 1: use squeezeAfter_iterate.
    have hkpos : 1 ≤ k := Nat.one_le_iff_ne_zero.mpr hk0
    rw [squeezeAfter_iterate S rate k hr hkpos]
    simp only
    by_cases hb : ((k - 1) % rate) + 1 = rate
    · -- Boundary: idx hits rate, permute, then squeezeByte at position 0.
      simp only [hb, if_true]
      have hmod : (k - 1) % rate = rate - 1 := by omega
      have hsub : k = rate * ((k - 1) / rate + 1) := by
        have h := Nat.div_add_mod (k - 1) rate
        rw [hmod] at h
        have hrhs : rate * ((k - 1) / rate + 1) = rate * ((k - 1) / rate) + rate :=
          Nat.mul_succ rate ((k - 1) / rate)
        omega
      have hdiv : k / rate = (k - 1) / rate + 1 := by
        conv_lhs => rw [hsub]
        exact Nat.mul_div_cancel_left _ hr
      have hmod0 : k % rate = 0 := by
        conv_lhs => rw [hsub]
        exact Nat.mul_mod_right _ _
      rw [hdiv, hmod0, Function.iterate_succ', Function.comp_apply]
    · -- Non-boundary: no permute.
      simp only [hb, if_false]
      have hmod_lt : (k - 1) % rate + 1 < rate := by
        have := Nat.mod_lt (k - 1) hr; omega
      have hsub : k = rate * ((k - 1) / rate) + ((k - 1) % rate + 1) := by
        have h := Nat.div_add_mod (k - 1) rate; omega
      have hdiv : k / rate = (k - 1) / rate := by
        conv_lhs => rw [hsub]
        rw [Nat.mul_add_div hr, Nat.div_eq_of_lt hmod_lt, Nat.add_zero]
      have hmod : k % rate = (k - 1) % rate + 1 := by
        conv_lhs => rw [hsub]
        rw [Nat.mul_add_mod, Nat.mod_eq_of_lt hmod_lt]
      rw [hdiv, hmod]

theorem squeezeBytes_append (S : Vector Bool SHA3.b) (idx rate n m : Nat) :
    (squeezeBytes S idx rate (n + m)).toList =
      (squeezeBytes S idx rate n).toList ++
        (let (Sn, idxn) := squeezeAfter S idx rate n
         (squeezeBytes Sn idxn rate m).toList) := by
  apply List.ext_getElem
  · simp
  · intro k hk _
    have hknm : k < n + m := by simp at hk; exact hk
    by_cases hkn : k < n
    · rw [List.getElem_append_left (by simp [hkn])]
      simp only [Vector.getElem_toList]
      rw [squeezeBytes_getElem S idx rate (n + m) k hknm,
          squeezeBytes_getElem S idx rate n k hkn]
    · push Not at hkn
      have hkmn : k - n < m := by
        have : k < n + m := hknm
        omega
      rw [List.getElem_append_right (by simp [hkn])]
      simp only [Vector.toList_length, Vector.getElem_toList]
      rw [squeezeBytes_getElem S idx rate (n + m) k hknm,
          squeezeBytes_getElem _ _ rate m (k - n) hkmn]
      have key : squeezeAfter S idx rate k =
                 squeezeAfter (squeezeAfter S idx rate n).1
                              (squeezeAfter S idx rate n).2 rate (k - n) := by
        rw [show k = n + (k - n) from (Nat.add_sub_cancel' hkn).symm]
        rw [squeezeAfter_add]
        simp
      rw [key]

/-! ## `extractOutput` -/

theorem extractOutput_zero (g : GhostState) :
    (extractOutput g 0).toList = [] := by
  simp [extractOutput, squeezeBytes]

/-- Given `squeezing self g`, `extractOutput g n` is exactly the next `n`
    squeezed bytes computed from the current code state. Useful for closing
    the FC equation in `extract.spec` when entering in squeeze mode. -/
theorem extractOutput_eq_squeezeBytes_of_squeezing
    {self : sha3.sha3_impl.KeccakState} {g : GhostState} (h : squeezing self g) (n : Nat) :
    (extractOutput g n).toList =
      (squeezeBytes (toBits self.state) self.state_index.val g.rate n).toList := by
  have hstr : squeezingStructural self g := h.1
  have hinv : squeezingInvariant self g := h.2
  unfold extractOutput
  set S_pad := padAndPermute
    (absorbBytes (Vector.replicate b false) 0 g.rate g.absorbed).1
    (absorbBytes (Vector.replicate b false) 0 g.rate g.absorbed).2
    g.rate g.padVal with hSpad
  set p := squeezeAfter S_pad 0 g.rate g.squeezed.length with hp_def
  have hstate : toBits self.state = p.1 := hinv.1
  have hidx : self.state_index.val = p.2 := hinv.2.1
  rw [hstate, hidx]

/-! ## `extractOutput_append` -/

theorem extractOutput_append (g : GhostState) (n m : Nat) :
    (extractOutput g (n + m)).toList =
      (extractOutput g n).toList ++ (extractOutput (g.squeezeAdvance n) m).toList := by
  unfold extractOutput
  set S_pad := padAndPermute
    (absorbBytes (Vector.replicate b false) 0 g.rate g.absorbed).1
    (absorbBytes (Vector.replicate b false) 0 g.rate g.absorbed).2
    g.rate g.padVal with hSpad
  show (squeezeBytes (squeezeAfter S_pad 0 g.rate g.squeezed.length).1
                     (squeezeAfter S_pad 0 g.rate g.squeezed.length).2 g.rate (n + m)).toList =
       (squeezeBytes (squeezeAfter S_pad 0 g.rate g.squeezed.length).1
                     (squeezeAfter S_pad 0 g.rate g.squeezed.length).2 g.rate n).toList ++
       (squeezeBytes
          (squeezeAfter S_pad 0 g.rate (g.squeezeAdvance n).squeezed.length).1
          (squeezeAfter S_pad 0 g.rate (g.squeezeAdvance n).squeezed.length).2
          g.rate m).toList
  rw [squeezeBytes_append (squeezeAfter S_pad 0 g.rate g.squeezed.length).1
        (squeezeAfter S_pad 0 g.rate g.squeezed.length).2 g.rate n m]
  have hlen : (g.squeezeAdvance n).squeezed.length = g.squeezed.length + n := by
    simp [GhostState.squeezeAdvance, GhostState.squeeze]
  rw [hlen]
  rw [show squeezeAfter S_pad 0 g.rate (g.squeezed.length + n) =
          (let (Sn, idxn) := squeezeAfter S_pad 0 g.rate g.squeezed.length
           squeezeAfter Sn idxn g.rate n)
       from squeezeAfter_add S_pad 0 g.rate g.squeezed.length n]

/-! ## `GhostState.squeezeAdvance` -/

@[simp]
private theorem GhostState.squeezeAdvance_zero (g : GhostState) :
    g.squeezeAdvance 0 = g := by
  simp [GhostState.squeezeAdvance, GhostState.squeeze, extractOutput_zero]

private theorem GhostState.squeezeAdvance_add (g : GhostState) (n m : Nat) :
    (g.squeezeAdvance n).squeezeAdvance m = g.squeezeAdvance (n + m) := by
  show { g.squeezeAdvance n with
         squeezed := (g.squeezeAdvance n).squeezed ++
                      (extractOutput (g.squeezeAdvance n) m).toList } =
       { g with squeezed := g.squeezed ++ (extractOutput g (n + m)).toList }
  rw [extractOutput_append g n m]
  show _ = ({ g with squeezed := g.squeezed ++
              ((extractOutput g n).toList ++ (extractOutput (g.squeezeAdvance n) m).toList) } :
              GhostState)
  simp only [GhostState.squeezeAdvance, GhostState.squeeze, List.append_assoc]

/-! ## `padAndPermute` reformulation as double-`absorbByte` -/

/-- The double-absorbByte form is now the *definition* of `padAndPermute`
    (see `Basic.lean`); kept as a named lemma for backward compatibility
    with consumers that referenced this characterization explicitly. -/
private theorem padAndPermute_eq_double_absorbByte (S : Vector Bool SHA3.b) (idx rate : Nat)
    (padVal : U8) (_hrate : 0 < rate) (_hmod : rate % 8 = 0)
    (_hrb : 8 * rate ≤ SHA3.b) :
    padAndPermute S idx rate padVal =
      KECCAK_f (absorbByte (absorbByte S idx padVal) (rate - 1) (0x80#u8 : U8)) := by
  rfl

/-! ## Slice composition -/

/-- Setting a full-length slice at offset 0 yields the slice. -/
theorem List.setSlice!_zero_full {α : Type _} [Inhabited α]
    (s : List α) (a : List α) (h : a.length = s.length) :
    s.setSlice! 0 a = a := by
  apply _root_.List.ext_getElem!
  · simp [_root_.List.length_setSlice!, h]
  · intro j
    by_cases h1 : j < a.length
    · simp_lists
    · simp_lists

/-- Writing back a "view-edited" drop is the same as a direct setSlice. -/
theorem List.setSlice!_drop_setSlice! {α : Type _} [Inhabited α]
    (s : List α) (i : Nat) (b : List α) (hroom : i + b.length ≤ s.length) :
    s.setSlice! i ((List.drop i s).setSlice! 0 b) = s.setSlice! i b := by
  apply _root_.List.ext_getElem!
  · simp [_root_.List.length_setSlice!]
  · intro j
    by_cases h1 : j < i
    · simp_lists
    · by_cases h2 : j < i + b.length
      · have h3 : j - i < b.length := by omega
        simp_lists
      · by_cases h4 : j < s.length
        · have hge : j - i ≥ b.length := by omega
          simp_lists_scalar
        · simp_lists

/-- Composing two consecutive `setSlice!` writes equals one combined write. -/
theorem List.setSlice!_setSlice!_append {α : Type _} [Inhabited α]
    (s : List α) (a b : List α) (i : Nat)
    (hroom : i + a.length + b.length ≤ s.length) :
    (s.setSlice! i a).setSlice! (i + a.length) b = s.setSlice! i (a ++ b) := by
  apply _root_.List.ext_getElem!
  · simp
  · intro j
    by_cases h1 : j < i
    · simp_lists
    · by_cases h2 : j < i + a.length
      · simp_lists
      · by_cases h3 : j < i + a.length + b.length
        · simp_lists
          grind
        · simp_lists

end symcrust.sha3.sha3_impl
