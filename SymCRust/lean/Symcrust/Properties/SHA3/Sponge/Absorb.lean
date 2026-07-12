import Symcrust.Properties.SHA3.Keccak.Loop
import Symcrust.Properties.SHA3.Keccak.Textbook
import Symcrust.Properties.SHA3.Sponge.Init
import Symcrust.Properties.SHA3.Sponge.Bridge
import Symcrust.Properties.Stdlib

/-!
# SHA-3 Verification — Sponge Absorb Operations

`append` postcondition: `absorbing result (g.append data.val self.squeeze_mode)`
-/

open Aeneas Aeneas.Std
namespace symcrust.sha3.sha3_impl

open Spec

@[agrind =] private theorem U64_NUM_BYTES_val : U64_NUM_BYTES.val = 8 := by native_decide

/-! ## Iterator step specs are in Keccak/Loop.lean (public). -/

/-- Every chunk in `(toChunksExact n h l).1` has length exactly `n`. (Standard
    invariant: `toChunksExact` only emits full-size chunks.) -/
private theorem _root_.List.toChunksExact_chunk_length_eq
    {α} (n : Nat) (hn : 0 < n) (l : List α) :
    ∀ c ∈ (List.toChunksExact n hn l).1, c.length = n := by
  induction l using List.toChunksExact.induct n hn with
  | case1 l hlt =>
    rw [List.toChunksExact]; simp [hlt]
  | case2 l hge _chunks _rem _heq ih =>
    rw [List.toChunksExact]; simp only [dif_neg (by omega : ¬ l.length < n)]
    intro c hc
    simp only [List.mem_cons] at hc
    rcases hc with rfl | hc
    · simp [List.length_take]; omega
    · exact ih c hc

/-- The first `k` full chunks of `toChunksExact n h l` all have length `n`.
    (Direct consequence of `toChunksExact_chunk_length_eq` and `List.mem_take`.) -/
private theorem _root_.List.toChunksExact_take_uniform_length
    {α} (n : Nat) (hn : 0 < n) (l : List α) (k : Nat) (_hk : n * k ≤ l.length) :
    ∀ c ∈ ((List.toChunksExact n hn l).1).take k, c.length = n := by
  intro c hc
  exact List.toChunksExact_chunk_length_eq n hn l c (List.mem_of_mem_take hc)

/-- Flattening the first `k` full chunks of `toChunksExact n h l` recovers
    `l.take (n * k)`, when `n * k ≤ l.length`. -/
private theorem _root_.List.toChunksExact_take_flatten
    {α} (n : Nat) (hn : 0 < n) (l : List α) (k : Nat) (hk : n * k ≤ l.length) :
    ((List.toChunksExact n hn l).1.take k).flatten = l.take (n * k) := by
  induction k generalizing l with
  | zero => simp
  | succ m ih =>
    have h_succ : n * (m + 1) = n + n * m := by ring
    have hge : n ≤ l.length := by rw [h_succ] at hk; omega
    rw [List.toChunksExact]
    simp only [dif_neg (by omega : ¬ l.length < n)]
    -- After dif_neg, the body is (l.take n :: rest, _).1 = l.take n :: rest
    simp only [List.take_succ_cons, List.flatten_cons]
    have hm : n * m ≤ (l.drop n).length := by
      rw [List.length_drop]; rw [h_succ] at hk; omega
    rw [ih (l.drop n) hm]
    -- Goal: l.take n ++ (l.drop n).take (n*m) = l.take (n*(m+1))
    rw [h_succ, List.take_add]

/-- Step spec for `core.slice.Slice.chunks_exact`: characterizes the resulting
    `ChunksExact` iterator's `chunks` field as the `.fst` of `List.toChunksExact`,
    modulo the `Slice` wrapper. (No alignment hypothesis needed; consumers
    can compose with the prefix lemmas `toChunksExact_take_uniform_length` /
    `toChunksExact_take_flatten`.) -/
@[step]
theorem chunks_exact.spec {T : Type} (s : Aeneas.Std.Slice T) (chunk_size : Usize)
    (h : 0 < chunk_size.val) :
    core.slice.Slice.chunks_exact s chunk_size
    ⦃ (ce : core.slice.iter.ChunksExact T) =>
      ce.chunks.map (fun c => c.val) =
        (List.toChunksExact chunk_size.val h s.val).1 ⦄ := by
  unfold core.slice.Slice.chunks_exact
  simp only [dif_pos h, WP.spec_ok]
  rw [List.map_map]
  show List.unattach (List.toChunksExact chunk_size.val h s.val).1.attach = _
  rw [List.unattach_attach]

/-- Composing `g.append [b] false` then `g.append rest false` equals
    `g.append ([b] ++ rest) false`. Used for loop invariant rebuilds. -/
private theorem GhostState.append_cons (g : GhostState) (b : U8) (rest : List U8) :
    (g.append [b] false).append rest false = g.append ([b] ++ rest) false := by
  simp [GhostState.append, List.append_assoc]

/-- List decomposition: drop i, take n = head :: drop (i+1), take (n-1). -/
private theorem list_drop_take_succ {α : Type} [Inhabited α] (l : List α) (i n : Nat)
    (hi : i < l.length) (hn : n > 0) (h : i + n ≤ l.length) :
    (l.drop i).take n = l[i] :: (l.drop (i + 1)).take (n - 1) := by
  induction l generalizing i n with
  | nil => simp at hi
  | cons a t ih =>
    cases i with
    | zero =>
      simp [List.drop]; cases n with | zero => omega | succ n => simp [List.take]
    | succ i =>
      grind

/-- Internal helper: when `acc1` has size in `(0, n]`, `acc2` is uniform length-n,
    and there are exactly enough elements left to fill `acc1` to size n and chunk
    the rest, then every output chunk has length n. -/
private theorem _root_.List.toChunks_go_uniform {α} (n : Nat) (hn : 0 < n) :
    ∀ (xs : List α) (acc1 : Array α) (acc2 : Array (List α)),
      0 < acc1.size → acc1.size ≤ n →
      (∀ c ∈ acc2, c.length = n) →
      (acc1.size + xs.length) % n = 0 →
      ∀ c ∈ List.toChunks.go n xs acc1 acc2, c.length = n := by
  intro xs
  induction xs with
  | nil =>
    intro acc1 acc2 hsize_pos hsize_le hacc2 hmod
    simp only [List.toChunks.go]
    have hsize : acc1.size = n := by
      simp only [List.length_nil, Nat.add_zero] at hmod
      rcases Nat.lt_or_ge acc1.size n with h | h
      · exfalso
        rw [Nat.mod_eq_of_lt h] at hmod
        omega
      · omega
    intro c hc
    rw [Array.toList_push, List.mem_append] at hc
    rcases hc with hc | hc
    · exact hacc2 c (Array.mem_def.mpr hc)
    · simp at hc; rw [hc, acc1.length_toList, hsize]
  | cons y ys ih =>
    intro acc1 acc2 hsize_pos hsize_le hacc2 hmod
    simp only [List.toChunks.go]
    by_cases hfull : acc1.size = n
    · simp only [hfull, beq_self_eq_true, ↓reduceIte]
      apply ih
      · rw [Array.size_push]; omega
      · rw [Array.size_push]; simp; omega
      · intro c hc
        rcases Array.mem_push.mp hc with h | h
        · exact hacc2 c h
        · rw [h, acc1.length_toList, hfull]
      · rw [Array.size_push]
        have hsz : (Array.mkEmpty n : Array α).size = 0 := by simp
        rw [hsz]
        have hcons : (y :: ys).length = 1 + ys.length := by simp; omega
        rw [hcons] at hmod
        rw [hfull] at hmod
        rw [show (n + (1 + ys.length)) % n = (1 + ys.length) % n from by
          rw [Nat.add_mod_left]] at hmod
        omega
    · have hbeq : (acc1.size == n) = false := by simp [hfull]
      simp only [hbeq, Bool.false_eq_true, ↓reduceIte]
      apply ih
      · rw [Array.size_push]; omega
      · rw [Array.size_push]; omega
      · exact hacc2
      · rw [Array.size_push]
        have : (acc1.size + 1) + ys.length = acc1.size + (y :: ys).length := by simp; omega
        rw [this]; exact hmod

/-- **C1 helper**: when `l.length` is divisible by `n > 0`, every chunk in
    `l.toChunks n` has length exactly `n`. Used to discharge the
    `h_chunks` invariant in `append_lanes_loop.spec` and `extract_lanes.spec`. -/
theorem _root_.List.toChunks_uniform_length {α} (n : Nat) (hn : 0 < n) (l : List α)
    (hlen : l.length % n = 0) : ∀ c ∈ l.toChunks n, c.length = n := by
  match l with
  | [] => intro c hc; simp [List.toChunks] at hc
  | x :: xs =>
    obtain ⟨k, hk⟩ : ∃ k, n = k + 1 := ⟨n - 1, by omega⟩
    rw [hk]
    show ∀ c ∈ List.toChunks (k+1) (x :: xs), c.length = k + 1
    simp only [List.toChunks]
    apply List.toChunks_go_uniform (k+1) (by omega) xs #[x] #[]
    · simp
    · simp
    · intro c hc; simp at hc
    · have hxs_one : (x :: xs).length = 1 + xs.length := by simp; omega
      rw [hk] at hlen
      rw [hxs_one] at hlen
      have h1 : ((#[x] : Array α).size) = 1 := by simp
      rw [h1]
      exact hlen

/-- The `go` accumulator decomposes: prepending `acc₂` is the same as appending. -/
private theorem toChunks_go_append
    {α : Type} (n : Nat) (xs : List α) (acc₁ : Array α) (acc₂ : Array (List α)) :
    List.toChunks.go n xs acc₁ acc₂ =
      acc₂.toList ++ List.toChunks.go n xs acc₁ #[] := by
  induction xs generalizing acc₁ acc₂ with
  | nil =>
    unfold List.toChunks.go
    simp [Array.toList_push]
  | cons y ys ih =>
    unfold List.toChunks.go
    split
    · rw [ih, ih (acc₂ := (#[] : Array (List α)).push acc₁.toList)]
      simp [Array.toList_push]
    · rw [ih, ih (acc₂ := #[])]

/-- The `go` function decomposes: first chunk + rest as `toChunks`. -/
private theorem toChunks_go_decompose
    {α : Type} (n : Nat) (xs : List α) (acc₁ : Array α)
    (hn : 0 < n) (hacc : acc₁.size ≤ n) (hxs : n - acc₁.size ≤ xs.length) :
    List.toChunks.go n xs acc₁ #[] =
      (acc₁.toList ++ xs.take (n - acc₁.size)) ::
      (xs.drop (n - acc₁.size)).toChunks n := by
  induction xs generalizing acc₁ with
  | nil =>
    simp at hxs
    have : acc₁.size = n := by omega
    unfold List.toChunks.go
    simp [List.toChunks, this]
  | cons y ys ih =>
    unfold List.toChunks.go
    by_cases hfull : (acc₁.size == n) = true
    · have heq : acc₁.size = n := by simp [BEq.beq] at hfull; exact hfull
      rw [if_pos hfull]
      rw [toChunks_go_append]
      simp only [Array.toList_push, List.nil_append]
      have hk : n - acc₁.size = 0 := by omega
      simp only [hk, List.take_zero, List.append_nil, List.drop_zero]
      cases n with
      | zero => omega
      | succ n' => simp [List.toChunks]
    · rw [if_neg hfull]
      have hlt : acc₁.size < n := by simp [BEq.beq] at hfull; omega
      have hk_succ : n - acc₁.size = (n - (acc₁.size + 1)) + 1 := by omega
      rw [ih (acc₁.push y) (by rw [Array.size_push]; omega)
            (by rw [Array.size_push]; simp only [_root_.List.length_cons] at hxs; omega)]
      simp only [Array.toList_push, Array.size_push]
      fcongr 1
      · simp [_root_.List.append_assoc, hk_succ, _root_.List.take_succ_cons]
      · rw [hk_succ, _root_.List.drop_succ_cons]

/-- Decompose `toChunks n` on a nonempty list into head chunk + rest. -/
private theorem _root_.List.toChunks_cons {α : Type} (n : Nat) (x : α) (xs : List α)
    (hn : 0 < n) (hxs : n ≤ (x :: xs).length) :
    (x :: xs).toChunks n = (x :: xs).take n :: ((x :: xs).drop n).toChunks n := by
  cases n with
  | zero => omega
  | succ n' =>
    show List.toChunks.go (n' + 1) xs #[x] #[] = _
    have h1 : (0 : Nat) < n' + 1 := by omega
    have h2 : #[x].size ≤ n' + 1 := by simp
    have h3 : n' + 1 - #[x].size ≤ xs.length := by
      show n' ≤ xs.length
      simp only [_root_.List.length_cons] at hxs; omega
    rw [toChunks_go_decompose (n' + 1) xs #[x] h1 h2 h3]
    simp

/-- Flattening the first `k` chunks of `l.toChunks n` recovers `l.take (n * k)`. -/
private theorem _root_.List.toChunks_take_flatten {α : Type} (n : Nat) (hn : 0 < n)
    (l : List α) (k : Nat) (hk : n * k ≤ l.length) :
    ((l.toChunks n).take k).flatten = l.take (n * k) := by
  induction k generalizing l with
  | zero => simp
  | succ m ih =>
    cases hl : l with
    | nil => rw [hl] at hk; simp at hk; omega
    | cons x xs =>
      rw [hl] at hk
      have hxs_len : n ≤ (x :: xs).length := by
        have hh : n * (m + 1) = n + n * m := by ring
        rw [hh] at hk; omega
      rw [_root_.List.toChunks_cons n x xs hn hxs_len]
      rw [_root_.List.take_succ_cons, _root_.List.flatten_cons]
      have hdrop_len : n * m ≤ ((x :: xs).drop n).length := by
        rw [_root_.List.length_drop]
        have hh : n * (m + 1) = n + n * m := by ring
        rw [hh] at hk; omega
      rw [ih _ hdrop_len]
      rw [show n * (m + 1) = n + n * m from by ring]
      rw [show (x :: xs).take (n + n * m) = (x :: xs).take n ++ ((x :: xs).drop n).take (n * m) from ?_]
      rw [_root_.List.take_add]

/-- The first `k` chunks of `l.toChunks n` all have length `n`, provided
    `n * k ≤ l.length`. Strictly weaker than `toChunks_uniform_length`: only
    the prefix is guaranteed uniform; the (k+1)-th chunk may be partial.
    Used to discharge the `h_chunks` invariant in `append_lanes_loop.spec`
    when the full slice is not assumed lane-aligned. -/
private theorem _root_.List.toChunks_take_uniform_length {α : Type} (n : Nat) (hn : 0 < n)
    (l : List α) (k : Nat) (hk : n * k ≤ l.length) :
    ∀ c ∈ (l.toChunks n).take k, c.length = n := by
  induction k generalizing l with
  | zero => intro c hc; simp at hc
  | succ m ih =>
    cases hl : l with
    | nil => rw [hl] at hk; simp at hk; omega
    | cons x xs =>
      rw [hl] at hk
      have hxs_len : n ≤ (x :: xs).length := by
        have hh : n * (m + 1) = n + n * m := by ring
        rw [hh] at hk; omega
      rw [_root_.List.toChunks_cons n x xs hn hxs_len, _root_.List.take_succ_cons]
      intro c hc
      simp only [_root_.List.mem_cons] at hc
      rcases hc with heq | hmem
      · rw [heq, _root_.List.length_take]
        omega
      · have hdrop_len : n * m ≤ ((x :: xs).drop n).length := by
          rw [_root_.List.length_drop]
          have hh : n * (m + 1) = n + n * m := by ring
          rw [hh] at hk; omega
        exact ih ((x :: xs).drop n) hdrop_len c hmem

@[step]
theorem KeccakState.append_byte.spec
    (self : KeccakState) (val : U8) (g : GhostState)
    (h : absorbingWeak self g)
    (hroom : self.state_index.val < self.input_block_size.val) :
    KeccakState.append_byte self val
    ⦃ (result : KeccakState) =>
      absorbingWeak result (g.append [val] false) ∧
      toBits result.state = absorbByte (toBits self.state) self.state_index.val val ∧
      result.state_index.val = self.state_index.val + 1 ⦄ := by
  -- Extract rate facts from h_rate so step* can discharge byte-level bounds.
  have hgr : self.input_block_size.val = g.rate := by
    have := h.2.2.1; scalar_tac
  have hgrlt : 8 * g.rate < SHA3.b := g.h_rate.2.1
  have hibsmax : self.input_block_size.val < 200 := by
    rw [hgr]; have : 8 * g.rate < 1600 := hgrlt; omega
  have hgrmod : g.rate % 8 = 0 := g.h_rate.2.2
  have hibsmod : self.input_block_size.val % 8 = 0 := by rw [hgr]; exact hgrmod
  have hidxBnd : self.state_index.val < 200 := by omega
  unfold KeccakState.append_byte
  step*
  refine ⟨?_, ?_, ?_⟩
  · -- Structural: absorbingWeak (preserved as before)
    simp only [absorbingWeak, GhostState.append, Bool.false_eq_true, ↓reduceIte] at *
    split_conjs
    all_goals agrind
  · -- FC: toBits a = absorbByte (toBits self.state) self.state_index.val val
    have hi5val : i5.val = self.state_index.val / 8 := by
      rw [i5_post, i4_post, UScalar.cast_u32_to_usize_val, U64_NUM_BYTES_val]
    have hibv : i.bv = val.bv.zeroExtend 64 := by
      rw [i_post]; rfl
    have hi3bv : i3.bv = val.bv.zeroExtend 64 <<< i2.val :=
      i3_post2.trans (by rw [hibv])
    have hi2val : i2.val = 8 * (self.state_index.val % 8) := by
      rw [i2_post, i1_post]
    have hi3bv' : i3.bv =
        val.bv.zeroExtend 64 <<< (8 * (self.state_index.val % 8)) :=
      hi3bv.trans (by rw [hi2val])
    have hi6bv : i6.bv = (self.state.val[self.state_index.val / 8]).bv := by grind
    have hi7bv : i7.bv =
        (self.state.val[self.state_index.val / 8]).bv ^^^
        (val.bv.zeroExtend 64 <<< (8 * (self.state_index.val % 8))) := by grind
    rw [a_post]
    exact absorbByte_bridge self.state self.state_index.val val i5 i7 hidxBnd hi5val hi7bv
  · -- state_index increment
    show i8.val = self.state_index.val + 1
    rw [i8_post]

/- **`append_bytes_loop.spec`**

Function body (Funs.lean:770-791): loop via partial_fixpoint.
Each iteration XORs one byte from `buffer` into a lane of the state array `a`.
The byte at position `j` is shifted to bit position `(state_index+j) % 8 * 8`
within lane `(state_index+j) / 8`, then XOR'd in.

The postcondition claims the result matches `absorbBytesRaw` — the spec-level
byte-by-byte XOR into the 1600-bit state. Proving this requires a single-iteration
bridge lemma: the code's lane-update (read lane, shift byte to position, XOR, write)
equals `absorbByte` applied to `toBits`. This is bit-level reasoning
(bv_tac / bvify) combined with array-to-bitvector correspondence. -/
@[step]
theorem KeccakState.append_bytes_loop.spec
    (iter : core.ops.range.Range Usize)
    (a : Keccak1600) (buffer : Slice U8) (state_index : Usize)
    (hstart : iter.start.val ≤ iter.«end».val)
    (hend : iter.«end».val ≤ buffer.length)
    (hbound : state_index.val + iter.«end».val ≤ 200) :
    KeccakState.append_bytes_loop iter a buffer state_index
    ⦃ (result : Keccak1600) =>
      let bytes := (List.range (iter.«end».val - iter.start.val)).map
        fun i => buffer[iter.start.val + i]!
      toBits result = absorbBytesRaw (toBits a)
        (state_index.val + iter.start.val) bytes ⦄ := by
  unfold KeccakState.append_bytes_loop
  by_cases hlt : iter.start.val < iter.«end».val
  · -- Some case: consume one byte and recurse
    let* ⟨ o, iter1, hsome, hstart', hend' ⟩ ← IteratorRange_next_some
    rw [hsome]
    step*
    -- Bridge the lane update to absorbByte at index (state_index + iter.start)
    have hidx : state_index.val + iter.start.val < 200 := by omega
    have hlane : i7.val = (state_index.val + iter.start.val) / 8 := by
      rw [i7_post, i3_post, U64_NUM_BYTES_val]
    have hi5val : i5.val = 8 * ((state_index.val + iter.start.val) % 8) := by
      rw [i5_post, i4_post, i3_post]
    have hi2bv : i2.bv = i1.bv.zeroExtend 64 := by rw [i2_post]; rfl
    have hi6bv : i6.bv = i1.bv.zeroExtend 64 <<<
        (8 * ((state_index.val + iter.start.val) % 8)) := by
      simp only [i6_post2, hi2bv, hi5val]
    have hi8bv : i8.bv = a.val[(state_index.val + iter.start.val) / 8].bv := by grind
    have hi9bv : i9.bv = a.val[(state_index.val + iter.start.val) / 8].bv ^^^
        (i1.bv.zeroExtend 64 <<< (8 * ((state_index.val + iter.start.val) % 8))) := by grind
    have ha1 : toBits a1 =
        absorbByte (toBits a) (state_index.val + iter.start.val) i1 := by
      rw [a1_post]
      exact absorbByte_bridge a (state_index.val + iter.start.val) i1 i7 i9
        hidx hlane hi9bv
    -- Decompose byte list and apply absorbBytesRaw cons-step
    have hN : iter.«end».val - iter.start.val =
        (iter1.«end».val - iter1.start.val) + 1 := by
      rw [hend', hstart']; omega
    rw [hN, List.range_succ_eq_map, List.map_cons, List.map_map]
    rw [show ∀ (S : Vector Bool SHA3.b) (idx : Nat) (b : U8) (rest : List U8),
            absorbBytesRaw S idx (b :: rest) =
            absorbBytesRaw (absorbByte S idx b) (idx + 1) rest from
          fun S idx b rest => by
            rw [show (b :: rest) = [b] ++ rest from rfl,
                absorbBytesRaw_append, absorbBytesRaw_singleton,
                show idx + [b].length = idx + 1 from rfl]]
    -- Reduce buffer[iter.start.val + 0]! to i1 (handle coercion variation)
    have hbi1 : buffer[iter.start.val + 0]! = i1 := by grind
    rw [hbi1, ← ha1, result_post]
    -- Match indices and the function in the map
    have hidx_eq : state_index.val + iter.start.val + 1 =
        state_index.val + iter1.start.val := by rw [hstart']; omega
    rw [hidx_eq]
    -- Match (fun i => buffer[iter.start + i]) ∘ Nat.succ = fun i => buffer[iter1.start + i]
    have hfun : (fun i => buffer[iter1.start.val + i]!) =
        ((fun i => buffer[iter.start.val + i]!) ∘ Nat.succ : Nat → U8) := by
      funext i
      simp only [Function.comp]
      congr 1
      rw [hstart']; omega
    rw [hfun]
  · -- None case: empty iterator
    have hge : iter.start.val ≥ iter.«end».val := by omega
    let* ⟨ o, iter1, hnone, _ ⟩ ← IteratorRange_next_none
    rw [hnone]; simp only [WP.spec_ok]
    have heq : iter.«end».val - iter.start.val = 0 := by omega
    simp only [heq, List.range_zero, List.map_nil, absorbBytesRaw_nil]
  termination_by iter.«end».val - iter.start.val
  decreasing_by scalar_decr_tac

/- **`append_bytes.spec` — PROVED**
Wrapper around append_bytes_loop. Postcondition is absorbingWeak (≤ not <)
since the loop can advance state_index to equal input_block_size.
Key proof step: manual extraction of cast value via
`simp only [UScalar.cast, UScalar.val, BitVec.toNat_setWidth]; simp_scalar`. -/
@[step]
theorem KeccakState.append_bytes.spec
    (self : KeccakState) (buffer : Slice U8) (g : GhostState)
    (h : absorbing self g)
    (hfit : self.state_index.val + buffer.length ≤ self.input_block_size.val) :
    KeccakState.append_bytes self buffer
    ⦃ (result : KeccakState) =>
      absorbingWeak result (g.append buffer.val false) ∧
      toBits result.state =
        absorbBytesRaw (toBits self.state) self.state_index.val buffer.val ⦄ := by
  -- Bounds for sub-spec
  have hgr : self.input_block_size.val = g.rate := by
    have := h.1.2.2.1; scalar_tac
  have hgrlt : 8 * g.rate < SHA3.b := g.h_rate.2.1
  have hibsmax : self.input_block_size.val ≤ 200 := by
    rw [hgr]; have : 8 * g.rate < 1600 := hgrlt; omega
  have hibsU32 : self.input_block_size.val ≤ U32.max := by
    have : (U32.max : Nat) = 4294967295 := by native_decide
    omega
  have habs : absorbingWeak self g := h.1
  have hpad : self.padding_value = g.padVal := habs.2.2.2.1
  have hsq : g.squeezed = [] := habs.2.2.2.2
  have hidxBnd : self.state_index.val + buffer.length ≤ 200 := by omega
  unfold KeccakState.append_bytes
  step*
  refine ⟨?_, ?_⟩
  · simp only [absorbingWeak, GhostState.append, Bool.false_eq_true, ↓reduceIte]
    have hi5val : i5.val = buffer.length := by
      rw [i5_post]
      simp only [UScalar.cast, UScalar.val, BitVec.toNat_setWidth]
      have : buffer.len.val % 2^32 = buffer.len.val := by
        apply Nat.mod_eq_of_lt; show buffer.length < _; omega
      simpa using this
    refine ⟨?_, not_false, hgr, hpad, hsq⟩
    show i6.val ≤ self.input_block_size.val
    rw [i6_post, hi5val]; omega
  · have hsi : state_index.val = self.state_index.val := by
      rw [state_index_post]
      simp only [UScalar.cast, UScalar.val, BitVec.toNat_setWidth]
      have : self.state_index.val % 2^System.Platform.numBits = self.state_index.val := by
        apply Nat.mod_eq_of_lt
        rcases System.Platform.numBits_eq with h | h <;> rw [h] <;> omega
      simpa using this
    rw [a_post, hsi, Nat.add_zero]
    have hmap : (List.range (buffer.len.val - 0)).map
        (fun i => buffer[(0 : Nat) + i]!) = buffer.val := by
      simp only [Nat.sub_zero, Nat.zero_add]
      have hlen : (List.map (fun i => buffer[i]!) (List.range buffer.len.val)).length =
          buffer.val.length := by simp [List.length_range, Slice.len]
      apply List.ext_getElem hlen
      intros n h1 h2
      simp only [List.length_map, List.length_range] at h1
      rw [List.getElem_map, List.getElem_range, Slice.getElem!_Nat_eq,
          List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem h1]
      rfl
    rw [hmap]

/-- Strengthened spec for `append_bytes` that includes state_index postcondition.
    The result's state_index equals the original plus buffer length. -/
@[step]
theorem KeccakState.append_bytes.spec_with_state_index
    (self : KeccakState) (buffer : Slice U8) (g : GhostState)
    (h : absorbing self g)
    (hfit : self.state_index.val + buffer.length ≤ self.input_block_size.val) :
    KeccakState.append_bytes self buffer
    ⦃ (result : KeccakState) =>
      absorbingWeak result (g.append buffer.val false) ∧
      toBits result.state =
        absorbBytesRaw (toBits self.state) self.state_index.val buffer.val ∧
      result.state_index.val = self.state_index.val + buffer.length ⦄ := by
  -- Bounds for sub-spec
  have hgr : self.input_block_size.val = g.rate := by
    have := h.1.2.2.1; scalar_tac
  have hgrlt : 8 * g.rate < SHA3.b := g.h_rate.2.1
  have hibsmax : self.input_block_size.val ≤ 200 := by
    rw [hgr]; have : 8 * g.rate < 1600 := hgrlt; omega
  have hibsU32 : self.input_block_size.val ≤ U32.max := by
    have : (U32.max : Nat) = 4294967295 := by native_decide
    omega
  have habs : absorbingWeak self g := h.1
  have hpad : self.padding_value = g.padVal := habs.2.2.2.1
  have hsq : g.squeezed = [] := habs.2.2.2.2
  have hidxBnd : self.state_index.val + buffer.length ≤ 200 := by omega
  unfold KeccakState.append_bytes
  step*
  have hi5val : i5.val = buffer.length := by
    rw [i5_post]
    simp only [UScalar.cast, UScalar.val, BitVec.toNat_setWidth]
    have : buffer.len.val % 2^32 = buffer.len.val := by
      apply Nat.mod_eq_of_lt; show buffer.length < _; omega
    simpa using this
  refine ⟨?_, ?_, ?_⟩
  · simp only [absorbingWeak, GhostState.append, Bool.false_eq_true, ↓reduceIte]
    refine ⟨?_, not_false, hgr, hpad, hsq⟩
    show i6.val ≤ self.input_block_size.val
    rw [i6_post, hi5val]; omega
  · have hsi : state_index.val = self.state_index.val := by
      rw [state_index_post]
      simp only [UScalar.cast, UScalar.val, BitVec.toNat_setWidth]
      have : self.state_index.val % 2^System.Platform.numBits = self.state_index.val := by
        apply Nat.mod_eq_of_lt
        rcases System.Platform.numBits_eq with h | h <;> rw [h] <;> omega
      simpa using this
    rw [a_post, hsi, Nat.add_zero]
    have hmap : (List.range (buffer.len.val - 0)).map
        (fun i => buffer[(0 : Nat) + i]!) = buffer.val := by
      simp only [Nat.sub_zero, Nat.zero_add]
      have hlen : (List.map (fun i => buffer[i]!) (List.range buffer.len.val)).length =
          buffer.val.length := by simp [List.length_range, Slice.len]
      apply List.ext_getElem hlen
      intros n h1 h2
      simp only [List.length_map, List.length_range] at h1
      rw [List.getElem_map, List.getElem_range, Slice.getElem!_Nat_eq,
          List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem h1]
      rfl
    rw [hmap]
  · -- state_index postcondition: result.state_index.val = self.state_index.val + buffer.length
    rw [i6_post, hi5val]

/-- Bytes that will be consumed by `append_lanes_loop` from the given iterator.
    The Take wrapper limits to `iter.n.val` chunks; if the underlying iterator
    has fewer, only those are consumed. Each chunk is 8 bytes (under the
    `h_chunks` invariant), so total length is `8 * min iter.n iter.iter.chunks.length`. -/
def takeChunks
    (iter : core.iter.adapters.take.Take (core.slice.iter.ChunksExact U8)) :
    List U8 :=
  ((iter.iter.chunks.take iter.n.val).map (fun s => s.val)).flatten

/-- When data fits strictly within the block, `absorbBytes` does
    `absorbBytesRaw` and just advances the index without permuting. -/
private theorem absorbBytes_within_block (S : Vector Bool SHA3.b) (idx rate : Nat)
    (data : List U8) (h : idx + data.length < rate) :
    absorbBytes S idx rate data = (absorbBytesRaw S idx data, idx + data.length) := by
  induction data generalizing S idx with
  | nil => simp [absorbBytes, absorbBytesRaw]
  | cons byte rest ih =>
    show absorbBytes S idx rate (byte :: rest) = _
    unfold absorbBytes
    have hr : idx + 1 ≠ rate := by simp at h; omega
    simp only [hr, ↓reduceIte]
    have hh : (idx + 1) + rest.length < rate := by simp at h; omega
    rw [ih (absorbByte S idx byte) (idx+1) hh]
    have hraw : absorbBytesRaw S idx (byte :: rest) =
                absorbBytesRaw (absorbByte S idx byte) (idx + 1) rest := by
      rw [show (byte :: rest) = [byte] ++ rest from rfl, absorbBytesRaw_append,
          absorbBytesRaw_singleton, show idx + [byte].length = idx + 1 from rfl]
    rw [hraw]
    show (_, _) = (_, _)
    congr 1
    simp; omega

/-- When data exactly fills the remainder of a block, `absorbBytes` does
    `absorbBytesRaw` then a single `KECCAK_f`, returning idx = 0. -/
private theorem absorbBytes_full_block (S : Vector Bool SHA3.b) (idx rate : Nat)
    (data : List U8) (hidx : idx + data.length = rate) (hpos : 0 < data.length) :
    absorbBytes S idx rate data = (SHA3.KECCAK_f (absorbBytesRaw S idx data), 0) := by
  induction data generalizing S idx with
  | nil => simp at hpos
  | cons byte rest ih =>
    show absorbBytes S idx rate (byte :: rest) = _
    unfold absorbBytes
    by_cases hr : idx + 1 = rate
    · simp only [hr, ↓reduceIte]
      cases rest with
      | nil =>
        show absorbBytes (SHA3.KECCAK_f _) 0 rate [] = _
        simp only [absorbBytes]
        show (_, 0) = (SHA3.KECCAK_f (absorbBytesRaw S idx [byte]), 0)
        rw [absorbBytesRaw_singleton]
      | cons _ _ =>
        exfalso; simp at hidx; omega
    · simp only [hr, ↓reduceIte]
      have hidx' : (idx + 1) + rest.length = rate := by simp at hidx; omega
      have hpos' : 0 < rest.length := by
        cases rest with
        | nil => exfalso; simp at hidx; omega
        | cons _ _ => simp
      rw [ih (absorbByte S idx byte) (idx + 1) hidx' hpos']
      have hraw : absorbBytesRaw S idx (byte :: rest) =
                  absorbBytesRaw (absorbByte S idx byte) (idx + 1) rest := by
        rw [show (byte :: rest) = [byte] ++ rest from rfl, absorbBytesRaw_append,
            absorbBytesRaw_singleton, show idx + [byte].length = idx + 1 from rfl]
      rw [hraw]

/-- `takeChunks` for an iterator with `n = 0` is empty. -/
private theorem takeChunks_n_zero
    (iter : core.iter.adapters.take.Take (core.slice.iter.ChunksExact U8))
    (h : iter.n.val = 0) : takeChunks iter = [] := by
  simp [takeChunks, h]

/-- `takeChunks` for an iterator whose underlying chunks list is empty is empty. -/
private theorem takeChunks_chunks_nil
    (iter : core.iter.adapters.take.Take (core.slice.iter.ChunksExact U8))
    (h : iter.iter.chunks = []) : takeChunks iter = [] := by
  simp [takeChunks, h]

/-- Decomposition: when the iterator has a chunk to consume, `takeChunks`
    splits as `head ++ takeChunks (tail-iter)`. -/
private theorem takeChunks_cons
    (iter iter' : core.iter.adapters.take.Take (core.slice.iter.ChunksExact U8))
    (c : Slice U8) (rest : List (Slice U8))
    (hn : iter.n.val ≠ 0) (hch : iter.iter.chunks = c :: rest)
    (hch' : iter'.iter.chunks = rest) (hn' : iter'.n.val = iter.n.val - 1) :
    takeChunks iter = c.val ++ takeChunks iter' := by
  simp only [takeChunks, hch, hch']
  rw [show iter.n.val = (iter.n.val - 1) + 1 from by omega]
  rw [List.take_succ_cons]
  simp [hn']

/- **`append_lanes_loop.spec` — strengthened with FC clause via `absorbBytes`.

The loop body:
  1. Reads next 8-byte chunk from iterator.
  2. Converts to U64 via `from_le_bytes`.
  3. XORs into lane at `lane_index` (= i1/8).
  4. Increments i1 by 8.
  5. If i1 reaches input_block_size: KECCAK_f, reset i1 to 0.
  6. Recurse.

Spec semantics: `absorbBytes (toBits a) i1.val rate (8-byte-chunk)` does
exactly the same thing — absorbs each byte, advancing idx, and permutes
when idx hits rate.

Per iteration uses `absorbLane_bridge` (PROVED) to relate the lane XOR
to 8 successive `absorbByte` calls. -/
set_option maxHeartbeats 1000000 in
@[step]
theorem KeccakState.append_lanes_loop.spec
    (iter : core.iter.adapters.take.Take (core.slice.iter.ChunksExact U8))
    (a : Keccak1600) (i : U32) (i1 : U32) (lane_index : Usize)
    (halign_i : i.val % 8 = 0)
    (halign_i1 : i1.val % 8 = 0)
    (h_lt : i1.val < i.val)
    (h_pos : 0 < i.val)
    (h_max : i.val ≤ 200)
    (h_lane : lane_index.val = i1.val / 8)
    (h_chunks : ∀ c ∈ iter.iter.chunks.take iter.n.val, c.length = 8) :
    KeccakState.append_lanes_loop iter a i i1 lane_index
    ⦃ (a' : Keccak1600) (i1' : U32) =>
      let consumed := takeChunks iter
      let (S', idx') := absorbBytes (toBits a) i1.val i.val consumed
      toBits a' = S' ∧ i1'.val = idx' ∧ i1'.val < i.val ∧ i1'.val % 8 = 0 ⦄ := by
  unfold KeccakState.append_lanes_loop
  let* ⟨ o, iter1, hnext ⟩ ← core.iter.adapters.take.IteratorTake.next_ChunksExact_spec
  by_cases hn : iter.n.val = 0
  · -- Terminating: iter.n = 0 ⇒ next returns none.
    simp only [hn, ↓reduceIte] at hnext
    obtain ⟨ho, hiter1_eq⟩ := hnext
    rw [ho]; simp only [WP.spec_ok]
    rw [takeChunks_n_zero iter hn]
    show toBits a = (absorbBytes _ _ _ []).1 ∧ _
    refine ⟨rfl, rfl, h_lt, halign_i1⟩
  · -- iter.n > 0; branch on whether the underlying chunks list is empty.
    simp only [hn, ↓reduceIte] at hnext
    cases hch : iter.iter.chunks with
    | nil =>
      rw [hch] at hnext
      obtain ⟨ho, _, _⟩ := hnext
      rw [ho]; simp only [WP.spec_ok]
      rw [takeChunks_chunks_nil iter hch]
      show toBits a = (absorbBytes _ _ _ []).1 ∧ _
      refine ⟨rfl, rfl, h_lt, halign_i1⟩
    | cons c rest =>
      rw [hch] at hnext
      obtain ⟨ho, hch_iter1, hn_iter1⟩ := hnext
      rw [ho]
      -- chunk c has length 8 by the (taken-prefix) iterator invariant
      have hc_len : c.val.length = 8 := by
        apply h_chunks
        rw [hch]
        obtain ⟨k, hk⟩ : ∃ k, iter.n.val = k + 1 := ⟨iter.n.val - 1, by omega⟩
        rw [hk, List.take_succ_cons]
        exact List.mem_cons_self
      have hi1_8 : i1.val + 8 ≤ i.val := by
        have hi1mod : i1.val % 8 = 0 := halign_i1
        have himod : i.val % 8 = 0 := halign_i
        omega
      have hi200 : i1.val < 200 := by omega
      have hlane_lt : lane_index.val < 25 := by
        rw [h_lane]; omega
      simp only []
      step as ⟨ r1, r1_post1, r2_post ⟩
      step as ⟨ a1, a1_post ⟩
      step as ⟨ i2, i2_post ⟩
      step as ⟨ i3, i3_post ⟩
      step as ⟨ i4, i4_post1, i4_post2 ⟩
      step as ⟨ idx_back_old, idx_back, idx_back_old_eq, idx_back_eq ⟩
      step as ⟨ i5, i5_post ⟩
      have hi5val : i5.val = 8 := by
        rw [i5_post]
        simp only [UScalar.cast, UScalar.val, BitVec.toNat_setWidth]
        native_decide
      step as ⟨ i6, i6_post ⟩
      step as ⟨ lane_index1, lane_index1_post ⟩
      -- Compute a1.val = c.val for the bridge.
      have hr1_eq : r1 = a1 := by
        rw [a1_post] at r2_post
        injection r2_post with h; exact h.symm
      rename_i hr1_val
      have ha1_val : a1.val = c.val := by rw [← hr1_eq]; exact hr1_val
      have hi3bv : i3.bv = (a.val[i1.val / 8]).bv := by grind
      have ha1_len : a1.val.length = 8 := by rw [ha1_val]; exact hc_len
      -- Bit-level computation of new_lane bv from a's lane and c's bytes.
      have hnew : ∀ k : Nat, k < 64 →
          i4.bv.getLsbD k =
          ((a.val[i1.val / 8]!).bv.getLsbD k != (c.val[k / 8]!).bv.getLsbD (k % 8)) := by
        intro k hk
        have h1 : i4.bv.getLsbD k = (i3.bv.getLsbD k != i2.bv.getLsbD k) := by
          simp only [i4_post2]
          exact BitVec.getLsbD_xor (i := k) (x := i3.bv) (y := i2.bv)
        rw [h1, hi3bv]
        congr 1
        · grind
        rw [i2_post]
        simp only [BitVec.getLsbD_cast]
        have hgetLsbD : ∀ {n : Nat} (b : BitVec n), b.getLsbD k = b[k]! := by
          intro n b; simp [BitVec.getLsbD, BitVec.getElem!_eq_testBit_toNat]
        rw [hgetLsbD]
        rw [BitVec.fromLEBytes_getElem!]
        rw [show (List.map U8.bv a1.val)[k / 8]! = U8.bv (a1.val[k / 8]!) by simp_lists]
        rw [ha1_val]
        rfl
      -- Apply absorbLane_bridge.
      have hbridge : toBits (Std.Array.set a lane_index i4) =
                     absorbBytesRaw (toBits a) i1.val c.val :=
        absorbLane_bridge a i1.val c.val lane_index i4
          (by omega) halign_i1 hc_len h_lane hnew
      clear hnew
      -- Decompose takeChunks iter = c.val ++ takeChunks iter1.
      have htc : takeChunks iter = c.val ++ takeChunks iter1 :=
        takeChunks_cons iter iter1 c rest hn hch hch_iter1 hn_iter1
      -- h_chunks for iter1 (taken prefix shrinks accordingly).
      have hch_iter1' : ∀ c ∈ iter1.iter.chunks.take iter1.n.val, c.length = 8 := by
        intro c' hc'
        apply h_chunks
        rw [hch_iter1, hn_iter1] at hc'
        rw [hch]
        obtain ⟨k, hk⟩ : ∃ k, iter.n.val = k + 1 := ⟨iter.n.val - 1, by omega⟩
        rw [hk, List.take_succ_cons]
        refine List.mem_cons_of_mem _ ?_
        have hk' : iter.n.val - 1 = k := by omega
        rw [hk'] at hc'
        exact hc'
      by_cases hperm : i6 = i
      · -- Permute branch: i6 = i, so i1.val + 8 = i.val.
        simp only [hperm, ↓reduceIte]
        have hi6val : i6.val = i.val := by rw [hperm]
        have hi1_eq_i : i1.val + 8 = i.val := by
          have hi6val' : i6.val = i1.val + 8 := by rw [i6_post, hi5val]
          omega
        step as ⟨ a3, a3_post ⟩
        have ha3_bits : toBits a3 = SHA3.KECCAK_f (toBits (idx_back i4)) :=
          keccak_permute_toBits _ _ a3_post
        step as ⟨ a4, i1_final, ha4 ⟩
        obtain ⟨ha4_bits, hi1f_eq, hi1f_lt, hi1f_mod⟩ := ha4
        have hfb : absorbBytes (toBits a) i1.val i.val c.val =
                   (SHA3.KECCAK_f (absorbBytesRaw (toBits a) i1.val c.val), 0) :=
          absorbBytes_full_block (toBits a) i1.val i.val c.val
            (by rw [hc_len]; exact hi1_eq_i) (by rw [hc_len]; omega)
        refine ⟨?_, ?_, hi1f_lt, hi1f_mod⟩
        · rw [htc, absorbBytes_append, hfb]
          simp_all
        · rw [htc, absorbBytes_append, hfb]
          simp_all
      · -- Non-permute branch: i6 ≠ i ⇒ i1.val + 8 < i.val.
        simp only [hperm, ↓reduceIte]
        have hi6val : i6.val = i1.val + 8 := by rw [i6_post, hi5val]
        have hi6_lt : i6.val < i.val := by
          have hi6_le : i6.val ≤ i.val := by rw [hi6val]; exact hi1_8
          rcases Nat.lt_or_eq_of_le hi6_le with h | h
          · exact h
          · exfalso; apply hperm
            scalar_tac
        have hi6_mod : i6.val % 8 = 0 := by rw [hi6val]; omega
        have hlane1 : lane_index1.val = i6.val / 8 := by
          rw [lane_index1_post, h_lane, hi6val]; omega
        step as ⟨ a4, i1_final, ha4 ⟩
        obtain ⟨ha4_bits, hi1f_eq, hi1f_lt, hi1f_mod⟩ := ha4
        have hwb : absorbBytes (toBits a) i1.val i.val c.val =
                   (absorbBytesRaw (toBits a) i1.val c.val, i1.val + c.val.length) :=
          absorbBytes_within_block (toBits a) i1.val i.val c.val
            (by rw [hc_len]; omega)
        have hidx_eq : i6.val = i1.val + c.val.length := by rw [hi6val, hc_len]
        have htoBits_eq : toBits (idx_back i4) = absorbBytesRaw (toBits a) i1.val c.val := by
          simp_all
        refine ⟨?_, ?_, hi1f_lt, hi1f_mod⟩
        · rw [htc, absorbBytes_append, hwb]
          rw [ha4_bits, htoBits_eq, hidx_eq]
        · rw [htc, absorbBytes_append, hwb]
          rw [hi1f_eq, htoBits_eq, hidx_eq]
  termination_by iter.n.val + iter.iter.chunks.length
  decreasing_by all_goals grind

/- **`append_lanes.spec`** — FC clause via `absorbBytes`.
   Wraps append_lanes_loop, threads ghost state. -/
@[step]
theorem KeccakState.append_lanes.spec
    (self : KeccakState) (data : Slice U8) (lane_count : Usize)
    (g : GhostState) (h : absorbing self g)
    (halign : self.state_index.val % 8 = 0)
    (hnotfull : self.state_index.val < self.input_block_size.val)
    (hdata : 8 * lane_count.val ≤ data.length) :
    KeccakState.append_lanes self data lane_count
    ⦃ (result : KeccakState) =>
      absorbing result (g.append (data.val.take (8 * lane_count.val)) false) ∧
      result.state_index.val % 8 = 0 ⦄ := by
  -- Pre-extract rate facts (input_block_size = rate, rate % 8 = 0)
  have hgr : self.input_block_size.val = g.rate := h.1.2.2.1
  have hgrmod : g.rate % 8 = 0 := g.h_rate.2.2
  have hibsmod : self.input_block_size.val % 8 = 0 := by rw [hgr]; exact hgrmod
  unfold KeccakState.append_lanes
  step*
  case _ => exact and7_eq_zero_of_mod8 _ _ (by assumption) hibsmod
  case _ => exact and7_eq_zero_of_mod8 _ _ (by assumption) halign
  case h_max =>
    have hr := h.1.2.2.1
    have hbnd := g.h_rate.2.1
    have hb : SHA3.b = 1600 := rfl
    omega
  case h_chunks =>
    rename_i ce _ ce_post _ iter_post1 iter_post2 _
    intro c hc
    -- hc : c ∈ iter.iter.chunks.take iter.n.val
    rw [iter_post1] at hc
    have hcv : c.val ∈ (ce.chunks.take iter.n.val).map (fun c => c.val) :=
      List.mem_map_of_mem hc
    rw [List.map_take, ce_post, iter_post2] at hcv
    -- hcv : c.val ∈ (toChunksExact U64_NUM_BYTES.val _ data.val).1.take lane_count.val
    show c.val.length = 8
    have hbytes_pos : 0 < U64_NUM_BYTES.val := by rw [U64_NUM_BYTES_val]; decide
    have hu := List.toChunksExact_take_uniform_length U64_NUM_BYTES.val hbytes_pos
                  data.val lane_count.val
                  (by rw [U64_NUM_BYTES_val]; simpa using hdata)
    have := hu c.val hcv
    rw [U64_NUM_BYTES_val] at this; exact this
  -- FC tail: bridge `takeChunks iter` to `data.val.take (8 * lane_count.val)`,
  -- then compose with `absorbing self g` via `absorbBytes_append`.
  -- Bridge takeChunks iter = data.val.take (8 * lane_count.val).
  have htc_eq : takeChunks iter = data.val.take (8 * lane_count.val) := by
    unfold takeChunks
    rw [iter_post1, iter_post2, List.map_take, ce_post]
    -- Goal: ((toChunksExact U64_NUM_BYTES.val _ data.val).1.take lane_count.val).flatten
    --     = data.val.take (8 * lane_count.val)
    have hbytes_pos : 0 < U64_NUM_BYTES.val := by rw [U64_NUM_BYTES_val]; decide
    have hflat := List.toChunksExact_take_flatten U64_NUM_BYTES.val hbytes_pos
                    data.val lane_count.val
                    (by rw [U64_NUM_BYTES_val]; exact hdata)
    rw [hflat, U64_NUM_BYTES_val]
  -- Decompose a_post and h. (Curried postcondition: a_post is a 4-conjunct.)
  obtain ⟨hresult_state, hresult_idx, hresult_lt, hresult_mod⟩ := a_post
  rw [htc_eq] at hresult_state hresult_idx
  obtain ⟨hweak, _, hsi⟩ := h
  obtain ⟨hstate_eq, hidx_eq⟩ := hsi
  obtain ⟨_, hnsq, hibs_rate, hpadval, hsq_nil⟩ := hweak
  -- absorbBytes_append + spongeInvariant of self.
  have hsplit :
      absorbBytes (Vector.replicate SHA3.b false) 0 g.rate
        (g.absorbed ++ data.val.take (8 * lane_count.val)) =
      absorbBytes (toBits self.state) self.state_index.val g.rate
        (data.val.take (8 * lane_count.val)) := by
    rw [absorbBytes_append]
    show absorbBytes (absorbBytes _ 0 _ _).1 (absorbBytes _ 0 _ _).2 _ _ = _
    rw [← hstate_eq, ← hidx_eq]
  refine ⟨⟨?_, ?_, ?_⟩, ?_⟩
  · -- absorbingWeak result
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · -- state_index ≤ input_block_size: x✝.val < ibs.val ⇒ ≤
      dsimp only
      omega
    · -- ¬ squeeze_mode
      dsimp only
      exact fun h => Bool.false_ne_true h
    · -- input_block_size = (g.append ...).rate
      dsimp only [GhostState.append]
      exact hibs_rate
    · -- padding_value
      dsimp only [GhostState.append]
      exact hpadval
    · -- squeezed = []
      dsimp only [GhostState.append]
      exact hsq_nil
  · -- state_index < input_block_size
    dsimp only
    exact hresult_lt
  · -- spongeInvariant
    show toBits a = _ ∧ _ = _
    dsimp only [GhostState.append]
    simp only [Bool.false_eq_true, ↓reduceIte]
    refine ⟨?_, ?_⟩
    · rw [hresult_state, hgr, ← hsplit]
    · rw [hresult_idx, hgr, ← hsplit]
  · -- result.state_index.val % 8 = 0 (from append_lanes_loop's post)
    exact hresult_mod

/- **Informal proof for `append_loop.spec`**

Function body (Funs.lean:837-855): loop via partial_fixpoint.
  1. If rem_data_len = 0: return (self, rem_data_len, data_index).
     Base case: consumed = 0, `g.append (take 0 ...) false = g.append [] false = g`.
     Needs `absorbing self g` which is hypothesis `h`. ✓
  2. `let i ← lift (self.state_index &&& 7)` — bitwise AND.
  3. If i = 0 (lane-aligned): return (self, rem_data_len, data_index).
     Same base case as above. ✓
  4. If i ≠ 0:
     a. `let i1 ← Slice.index_usize data data_index` — needs data_index < data.length.
        From hrem: data_index + rem_data_len ≤ data.length, rem_data_len > 0, so data_index < data.length. ✓
     b. `let self1 ← append_byte self i1` — by append_byte.spec.
        Precondition hroom: state_index < input_block_size. From `hroom`. ✓
        Postcondition: absorbing self1 (g.append [i1.bv] false).
     c. `data_index1 = data_index + 1`, `rem_data_len1 = rem_data_len - 1`.
     d. Recursive call: append_loop self1 data rem_data_len1 data_index1.
        Preconditions:
        - absorbing self1 (g.append [i1.bv] false): from append_byte postcondition. ✓
        - hroom: self1.state_index < self1.input_block_size.
          From absorbing: state_index ≤ input_block_size. append_byte advances by 1.
          Need: state_index + 1 ≤ input_block_size, i.e., state_index < input_block_size.
          From hroom. ✓ (but need to verify append_byte preserves the bound).
        - hrem: (data_index+1) + (rem_data_len-1) ≤ data.length.
          = data_index + rem_data_len ≤ data.length. From hrem. ✓
  5. Invariant rebuild: the recursive call gives
     `absorbing ks ((g.append [i1.bv] false).append (drop(idx+1).take consumed') false)`.
     Need: `g.append (drop(idx).take(consumed'+1)) false`.
     By GhostState.append_cons + List.drop_take_cons.

Termination: rem_data_len decreases by 1 each iteration. -/

@[step]
theorem KeccakState.append_loop.spec
    (self : KeccakState) (data : Slice U8)
    (rem_data_len : Usize) (data_index : Usize)
    (g : GhostState) (h : absorbingWeak self g)
    (hrem : data_index.val + rem_data_len.val ≤ data.length) :
    KeccakState.append_loop self data rem_data_len data_index
    ⦃ (ks : KeccakState) (rem' : Usize) (idx' : Usize) =>
      rem'.val + idx'.val = rem_data_len.val + data_index.val ∧
      data_index.val ≤ idx'.val ∧
      let consumed := idx'.val - data_index.val
      let bytes := (data.val.drop data_index.val).take consumed
      absorbingWeak ks (g.append bytes false) ∧
      toBits ks.state = absorbBytesRaw (toBits self.state) self.state_index.val bytes ∧
      ks.state_index.val = self.state_index.val + consumed ∧
      (rem'.val = 0 ∨ ks.state_index.val % 8 = 0) ⦄ := by
  unfold KeccakState.append_loop
  step*
  · -- hroom for append_byte: derive from guard + absorbingWeak
    simp only [absorbingWeak] at h
    have h1 := and7_val self.state_index
    have h2 : i.val ≠ 0 := by simp only [bne_iff_ne, ne_eq] at *; scalar_tac
    have hgr : self.input_block_size.val = g.rate := by have := h.2.2.1; scalar_tac
    have hibsmod : self.input_block_size.val % 8 = 0 := by rw [hgr]; exact g.h_rate.2.2
    have hsi_mod : self.state_index.val % 8 ≠ 0 := by
      have hi_eq : i.val = self.state_index.val % 8 := by
        rw [i_post1, and7_val]
      omega
    have hle : self.state_index.val ≤ self.input_block_size.val := h.1
    omega
  · -- recursive case post: combine append_byte FC + IH FC.
    -- step* binds the recursive call's curried postcondition as
    --   ks_post1 : rem' + idx' = rem_data_len1 + data_index1
    --   ks_post2 : data_index1 ≤ idx'
    --   ks_post3 : absorbingWeak ks ((g.append [i1] false).append … false)
    --   ks_post4 : toBits ks.state = absorbBytesRaw …
    --   ks_post5 : ks.state_index = self1.state_index + (idx' - data_index1)
    --   ks_post6 : rem' = 0 ∨ ks.state_index % 8 = 0
    set di_after : Usize := idx' with hdi_def
    have hd_lt : data_index.val < data.length := by
      have h1 : 1 ≤ rem_data_len.val := rem_data_len1_post2
      have h2 : data_index.val + rem_data_len.val ≤ data.length := hrem
      omega
    have hwin_pos : 1 ≤ di_after.val - data_index.val := by
      have hbnd' : data_index1.val ≤ di_after.val := ks_post2
      have : data_index1.val = data_index.val + 1 := data_index1_post
      omega
    have hcons :
        List.take (di_after.val - data_index.val) (List.drop data_index.val data.val) =
        i1 :: List.take (di_after.val - data_index1.val) (List.drop data_index1.val data.val) := by
      have hsub : di_after.val - data_index.val =
          (di_after.val - data_index1.val) + 1 := by
        have hbnd2 := ks_post2
        rw [data_index1_post] at hbnd2 ⊢; omega
      have hdrop : List.drop data_index.val data.val =
          data.val[data_index.val]! :: List.drop (data_index.val + 1) data.val := by
        match heq : List.drop data_index.val data.val with
        | [] =>
          have hlen : (List.drop data_index.val data.val).length = 0 := by rw [heq]; rfl
          rw [List.length_drop] at hlen
          have : data.val.length = data.length := rfl
          omega
        | y :: rest =>
          have hy : y = data.val[data_index.val]! := by
            have h0 : (List.drop data_index.val data.val)[0]! =
                data.val[data_index.val]! := by
              rw [List.getElem!_drop]; rfl
            rw [heq] at h0; simpa using h0
          have hrest : rest = List.drop (data_index.val + 1) data.val := by
            have heq2 : List.drop (data_index.val + 1) data.val =
                List.drop 1 (List.drop data_index.val data.val) := by
              rw [List.drop_drop]
            rw [heq2, heq]; rfl
          rw [hy, hrest]
      rw [hsub, hdrop, List.take_succ_cons]
      congr 1
      · grind
      · rw [data_index1_post]
    refine ⟨by have h := ks_post1; rw [data_index1_post] at h; omega, ?_, ?_, ?_, ?_, ?_⟩
    · -- data_index ≤ di_after
      have h := ks_post2
      rw [data_index1_post] at h; omega
    · rw [hcons]
      simp only [absorbingWeak, GhostState.append] at ks_post3 ⊢
      exact ks_post3
    · rw [hcons]
      rw [show ∀ (S : Vector Bool SHA3.b) (idx : Nat) (b : U8) (rest : List U8),
              absorbBytesRaw S idx (b :: rest) =
              absorbBytesRaw (absorbByte S idx b) (idx + 1) rest from
            fun S idx b rest => by
              rw [show (b :: rest) = [b] ++ rest from rfl,
                  absorbBytesRaw_append, absorbBytesRaw_singleton,
                  show idx + [b].length = idx + 1 from rfl]]
      rw [ks_post4, self1_post2, self1_post3]
    · rw [ks_post5, self1_post3, data_index1_post]; omega
    · -- termination disjunction: pass through from IH
      exact ks_post6
  · -- base case: lane-aligned (i = 0)
    refine ⟨Nat.le_refl _, ?_, ?_, ?_, ?_⟩
    · simp only [GhostState.append, Nat.sub_self, List.take_zero]; exact h
    · simp only [Nat.sub_self, List.take_zero, absorbBytesRaw_nil]
    · simp
    · -- self.state_index % 8 = 0 (from i = 0 guard)
      right
      have hi_eq : i.val = self.state_index.val % 8 := by
        rw [i_post1, and7_val]
      have hi0 : i.val = 0 := by
        rename_i hi_zero
        scalar_tac
      omega
  · -- base case: rem_data_len = 0
    refine ⟨Nat.le_refl _, ?_, ?_, ?_, ?_⟩
    · simp only [GhostState.append, Nat.sub_self, List.take_zero]; exact h
    · simp only [Nat.sub_self, List.take_zero, absorbBytesRaw_nil]
    · simp
    · -- rem' = rem_data_len = 0 (from guard ¬ rem_data_len > 0)
      left
      rename_i hrem_zero
      scalar_tac
  termination_by rem_data_len.val
  decreasing_by scalar_decr_tac

/- **`append.spec`** — top-level absorb. Composes `reset` (when transitioning
    out of squeeze mode), `append_loop` (head bytes up to the next 8-lane
    boundary), `append_lanes` + `keccak_permute` (full-rate blocks), and
    `append_bytes` (trailing partial bytes). The dispatch is laid out in
    two cases depending on whether `self.state_index = 0` after `reset`
    (the boundary case) or `self.state_index ≠ 0` (the non-boundary case);
    each case further splits on `full_lanes > 0` versus `full_lanes = 0`. -/
set_option maxHeartbeats 800000 in
@[step]
theorem KeccakState.append.spec
    (self : KeccakState) (data : Slice U8) (g : GhostState)
    (h : absorbing self g ∨ squeezing self g) :
    KeccakState.append self data
    ⦃ (result : KeccakState) =>
      absorbing result (g.append data.val self.squeeze_mode) ⦄ := by
  unfold KeccakState.append
  -- Pre-extract rate facts from absorbing OR squeezing.
  have hgr_rate : self.input_block_size.val = g.rate := by
    rcases h with hab | hsq
    · exact hab.1.2.2.1
    · exact hsq.1.2.2.1
  have hgrmod : g.rate % 8 = 0 := g.h_rate.2.2
  have hibsmod : self.input_block_size.val % 8 = 0 := by rw [hgr_rate]; exact hgrmod
  have hpadval : self.padding_value = g.padVal := by
    rcases h with hab | hsq
    · exact hab.1.2.2.2.1
    · exact hsq.1.2.2.2
  have hgrlt : 8 * g.rate < SHA3.b := g.h_rate.2.1
  have hibsmax : self.input_block_size.val ≤ 200 := by
    rw [hgr_rate]; have : 8 * g.rate < 1600 := hgrlt; omega
  have hgrpos : 0 < g.rate := g.h_rate.1
  have hibsval : self.input_block_size.val < 1600 := by
    have : 8 * g.rate < 1600 := hgrlt; omega
  have h_rate_self : 0 < self.input_block_size.val ∧
                8 * self.input_block_size.val < Spec.SHA3.b ∧
                self.input_block_size.val % 8 = 0 :=
    ⟨by rw [hgr_rate]; exact hgrpos, by rw [hgr_rate]; exact hgrlt, hibsmod⟩
  step  -- rem_data_len assignment
  step  -- i = ibs % 8 + massert (i = 0)
  by_cases hsm : self.squeeze_mode = true
  · -- squeezing branch
    have hsq : squeezing self g := by
      rcases h with hab | hsq
      · exfalso; exact (hab.1.2.1) (by rw [hsm])
      · exact hsq
    rw [if_pos hsm]
    -- step reset.spec, then massert
    step as ⟨kk, h_kk⟩
    -- Convert h_kk to absorbing kk g0 where g0 = .init g.rate g.padVal g.h_rate
    set g0 : GhostState := .init self.input_block_size.val self.padding_value h_rate_self with hg0_def
    have h_kk_abs : absorbing kk g0 := h_kk
    -- Establish derived facts on kk
    have hkk_ibs : kk.input_block_size.val = self.input_block_size.val := by
      have hh := h_kk_abs.1.2.2.1
      have : kk.input_block_size.val = g0.rate := by rw [hh]
      simpa [g0, GhostState.init] using this
    have hkk_pad : kk.padding_value = self.padding_value := by
      have hh := h_kk_abs.1.2.2.2.1
      have : kk.padding_value = g0.padVal := hh
      simpa [g0, GhostState.init] using this
    have hkk_ibs' : kk.input_block_size = self.input_block_size := by
      apply UScalar.eq_of_val_eq; exact hkk_ibs
    have hkk_si : kk.state_index.val = 0 := by
      have hbits := h_kk_abs.2.2
      have h2 : kk.state_index.val = (absorbBytes (Vector.replicate SHA3.b false) 0
                  g0.rate g0.absorbed).2 := hbits.2
      simpa [g0, GhostState.init, absorbBytes] using h2
    have hkk_align : kk.state_index.val % 8 = 0 := by rw [hkk_si]
    -- Equality between g0.append false and g.append true.
    have hg_eq : g0.append data.val false = g.append data.val self.squeeze_mode := by
      rw [hsm]
      simp only [GhostState.append, Bool.false_eq_true, ↓reduceIte]
      congr 1
    have habw : absorbingWeak kk g0 := h_kk_abs.1
    -- Use the fact that append_loop is a no-op when state_index is aligned.
    have hloop_noop : kk.append_loop data data.len 0#usize = Result.ok (kk, data.len, 0#usize) := by
      unfold KeccakState.append_loop
      have hi_eq : (kk.state_index &&& 7#u32) = 0#u32 :=
        UScalar.eq_of_val_eq (by rw [and7_val]; exact hkk_align)
      simp [hi_eq, Std.lift]
    -- Step the massert.
    step  -- massert (kk.state_index < kk.input_block_size)
    -- Substitute the append_loop with its no-op result.
    rw [hloop_noop]
    step*
    -- Skip the permute branch (kk.state_index < kk.input_block_size)
    have h_no_perm : ¬(kk.state_index = kk.input_block_size) := by
      intro heq
      have hlt : kk.state_index.val < kk.input_block_size.val := h_kk_abs.2.1
      have heqv : kk.state_index.val = kk.input_block_size.val := by rw [heq]
      omega
    rw [if_neg h_no_perm]
    step*
    -- Mirror the absorbing branch logic with kk and g0
    have hdle : 8 * full_lanes.val ≤ data.length := by
      have hfl : full_lanes.val = data.len.val / 8 := by rw [full_lanes_post, U64_NUM_BYTES_val]
      have heq : data.length = data.len.val := by
        simp only [Slice.length, Slice.len, Usize.ofNatCore, UScalar.val, UScalar.ofNatCore]; rfl
      omega
    by_cases hfl_pos : full_lanes > 0#usize
    · -- Case: full_lanes > 0
      rw [if_pos hfl_pos]
      step as ⟨sl, hsl_val, hsl_len⟩
      have hsl_eq : sl.val = data.val := by rw [hsl_val]; simp [List.drop_zero]
      have hkk_struct : (⟨kk.state, kk.input_block_size, kk.state_index,
          kk.padding_value, kk.squeeze_mode⟩ : KeccakState) = kk := by
        cases kk; rfl
      rw [hkk_struct]
      have hdata : 8 * full_lanes.val ≤ sl.length := by
        rw [hsl_len]; simp only [Nat.sub_zero]; exact hdle
      have hnotfull : kk.state_index.val < kk.input_block_size.val := h_kk_abs.2.1
      have hks2 := KeccakState.append_lanes.spec kk sl full_lanes g0 h_kk_abs hkk_align hnotfull hdata
      step as ⟨ks2, hks2_abs, hks2_align⟩
      -- Pre-compute alignment-based bound for append_bytes' fit precondition.
      have hks2_si_lt : ks2.state_index.val < ks2.input_block_size.val := hks2_abs.2.1
      have hks2_ibs_rate : ks2.input_block_size.val =
            (g0.append (sl.val.take (8 * full_lanes.val)) false).rate := hks2_abs.1.2.2.1
      have hg0_rate : g0.rate = kk.input_block_size.val := by
            simp [g0, GhostState.init, hkk_ibs]
      have hks2_ibs_eq : ks2.input_block_size.val = kk.input_block_size.val := by
            rw [hks2_ibs_rate]; simp [GhostState.append, hg0_rate]
      have hkk_ibsmod : kk.input_block_size.val % 8 = 0 := by
            rw [hkk_ibs]; exact hibsmod
      have hks2_align_lt : ks2.state_index.val + 8 ≤ ks2.input_block_size.val := by
            have hibsm : ks2.input_block_size.val % 8 = 0 := by rw [hks2_ibs_eq]; exact hkk_ibsmod
            omega
      have hfl_bnd : full_lanes.val * U64_NUM_BYTES.val ≤ Usize.max := by
            simp only [U64_NUM_BYTES_val]
            have hbnd : data.len.val ≤ Usize.max := by have := data.len.hBounds; simp [Usize.max, Usize.numBits] at *; omega
            have hfl : full_lanes.val = data.len.val / 8 := by
              rw [full_lanes_post, U64_NUM_BYTES_val]
            omega
      -- Step 3: step* does all remaining arithmetic, massert, slice, append_bytes, and final massert.
      -- Without hddiv, it leaves 4 goals: (0) data.len - 8*full_lanes side condition,
      -- (1) x < U64_NUM_BYTES massert (the trailing fragment is < 8), (2) final massert, (3) post.
      step*
      -- Under Lean v4.31 `step*` auto-discharges the two arithmetic side-goals
      -- (`8*full_lanes ≤ data.length` and the `< U64_NUM_BYTES` massert), so only
      -- the `bne` massert and the `absorbing` postcondition remain.
      -- Goals share preprocessing.
      all_goals have hs_lt : s.length < 8 := by
                  have heq : data.length = data.len.val := by
                    simp only [Slice.length, Slice.len, Usize.ofNatCore, UScalar.val, UScalar.ofNatCore]; rfl
                  rw [s_post2, x_post]
                  simp only [U64_NUM_BYTES_val] at *
                  omega
      all_goals have hs_drop : s.val = data.val.drop (8 * full_lanes.val) := by
                  rw [s_post1]
                  congr 1
                  rw [x_post]
                  simp only [Nat.zero_add, U64_NUM_BYTES_val] at *
                  omega
      all_goals have hself4_si_eq : self4.state_index.val = ks2.state_index.val + s.length :=
            self4_post3
      all_goals have hself4_ibs_rate : self4.input_block_size.val =
            ((g0.append (sl.val.take (8 * full_lanes.val)) false).append s.val false).rate :=
            self4_post1.2.2.1
      all_goals have hrates_eq : (g0.append (sl.val.take (8 * full_lanes.val)) false).rate =
            ((g0.append (sl.val.take (8 * full_lanes.val)) false).append s.val false).rate := rfl
      all_goals have hself4_ibs_eq : self4.input_block_size.val = ks2.input_block_size.val := by
                  rw [hself4_ibs_rate, ← hrates_eq, ← hks2_ibs_rate]
      · -- Goal 1: (self4.state_index != self4.input_block_size) = true
        simp only [bne_iff_ne, ne_eq]
        intro heq
        have heqv : self4.state_index.val = self4.input_block_size.val := by rw [heq]
        rw [hself4_si_eq, hself4_ibs_eq] at heqv
        omega
      · -- Goal 2: absorbing self4 (g.append data.val self.squeeze_mode)
        rw [← hg_eq]
        have hsl_take_eq : sl.val.take (8 * full_lanes.val) = data.val.take (8 * full_lanes.val) := by
          rw [hsl_eq]
        have hsplit_data : data.val.take (8 * full_lanes.val) ++ s.val = data.val := by
          rw [hs_drop]; exact List.take_append_drop _ _
        have hg_append_eq : g0.append data.val false =
            (g0.append (sl.val.take (8 * full_lanes.val)) false).append s.val false := by
          simp only [GhostState.append, Bool.false_eq_true, ↓reduceIte, List.append_assoc]
          rw [hsl_take_eq, hsplit_data]
        rw [hg_append_eq]
        refine ⟨self4_post1, ?_, ?_⟩
        · rw [hself4_si_eq, hself4_ibs_eq]; omega
        · have hks2_si := hks2_abs.2.2
          unfold spongeInvariant at hks2_si ⊢
          obtain ⟨hks2_bits, hks2_idx⟩ := hks2_si
          set g0' : GhostState := g0.append (sl.val.take (8 * full_lanes.val)) false with hg0'_def
          have h_within :
              absorbBytes (toBits ks2.state) ks2.state_index.val ks2.input_block_size.val s.val =
              (absorbBytesRaw (toBits ks2.state) ks2.state_index.val s.val,
               ks2.state_index.val + s.length) := by
            apply absorbBytes_within_block
            have hsleq : (↑s : List U8).length = s.length := rfl
            omega
          have hg0'_rate_eq : g0'.rate = ks2.input_block_size.val := hks2_ibs_rate.symm
          have happ_rate' : (g0'.append s.val false).rate = ks2.input_block_size.val := by
            simp [GhostState.append]; rw [hg0'_rate_eq]
          have hcompose :
              absorbBytes (Vector.replicate SHA3.b false) 0 (g0'.append s.val false).rate
                ((g0'.append s.val false).absorbed) =
              absorbBytes (toBits ks2.state) ks2.state_index.val ks2.input_block_size.val s.val := by
            simp only [GhostState.append, Bool.false_eq_true, ↓reduceIte]
            rw [absorbBytes_append]
            have hks2_pair : absorbBytes (Vector.replicate SHA3.b false) 0 g0'.rate g0'.absorbed
                = (toBits ks2.state, ks2.state_index.val) := by
              apply Prod.ext
              · exact hks2_bits.symm
              · exact hks2_idx.symm
            rw [hks2_pair, hg0'_rate_eq]
          refine ⟨?_, ?_⟩
          · rw [hcompose, h_within]; simp only
            rw [self4_post2]
          · rw [hself4_si_eq, hcompose, h_within]
    · -- Case: full_lanes = 0
      rw [if_neg hfl_pos]
      have hfl_zero : full_lanes.val = 0 := by simp [GT.gt] at hfl_pos; omega
      have hd_lt : data.length < 8 := by
        have hfl : full_lanes.val = data.len.val / 8 := by rw [full_lanes_post, U64_NUM_BYTES_val]
        have heq : data.length = data.len.val := by
          simp only [Slice.length, Slice.len, Usize.ofNatCore, UScalar.val, UScalar.ofNatCore]; rfl
        omega
      have hdlen_lt8 : data.len.val < 8 := by
        have heq : data.length = data.len.val := by
          simp only [Slice.length, Slice.len, Usize.ofNatCore, UScalar.val, UScalar.ofNatCore]; rfl
        omega
      step  -- massert: rem_data_len2 < U64_NUM_BYTES
      step as ⟨sl, hsl_val, hsl_len⟩
      have hsl_eq : sl.val = data.val := by rw [hsl_val]; simp [List.drop_zero]
      have hsl_len_eq : sl.length = data.length := by rw [Slice.length, hsl_eq]
      have hkkibs_pos : 8 ≤ kk.input_block_size.val := by
        have : 0 < kk.input_block_size.val := by rw [hkk_ibs]; rw [hgr_rate]; exact hgrpos
        have : kk.input_block_size.val % 8 = 0 := by rw [hkk_ibs]; exact hibsmod
        omega
      have hfit : kk.state_index.val + sl.length ≤ kk.input_block_size.val := by
        rw [hsl_len_eq, hkk_si]; omega
      have hkk_struct : (⟨kk.state, kk.input_block_size, kk.state_index,
          kk.padding_value, kk.squeeze_mode⟩ : KeccakState) = kk := by
        cases kk; rfl
      rw [hkk_struct]
      have hks4 := KeccakState.append_bytes.spec_with_state_index kk sl g0 h_kk_abs hfit
      step as ⟨ks4, hks4_weak, hks4_state, hks4_si_post⟩
      have hg0_rate : g0.rate = kk.input_block_size.val := by
        simp [g0, GhostState.init, hkk_ibs]
      have hks4_ibs_eq : ks4.input_block_size = kk.input_block_size := by
        apply UScalar.eq_of_val_eq
        rw [hks4_weak.2.2.1]; simp [GhostState.append]; rw [hg0_rate]
      have hsi_kk : spongeInvariant kk g0 := h_kk_abs.2.2
      unfold spongeInvariant at hsi_kk
      obtain ⟨hkk_bits, hkk_idx⟩ := hsi_kk
      step  -- massert: state_index < ibs (auto-discharged via ks4.state_index < ks4.input_block_size)
      rw [← hg_eq]
      refine ⟨?_, ?_, ?_⟩
      · -- absorbingWeak ks4 (g0.append data.val false)
        rw [← hsl_eq]; exact hks4_weak
      · -- state_index < input_block_size
        rw [hks4_si_post, hks4_ibs_eq, hkk_si]
        rw [hsl_len_eq]; omega
      · unfold spongeInvariant
        simp only
        have h_within :
            absorbBytes (toBits kk.state) kk.state_index.val kk.input_block_size.val sl.val =
            (absorbBytesRaw (toBits kk.state) kk.state_index.val sl.val,
             kk.state_index.val + sl.length) := by
          apply absorbBytes_within_block
          have hsleq : (↑sl : List U8).length = sl.length := rfl
          omega
        have hcompose :
            absorbBytes (Vector.replicate SHA3.b false) 0
                (g0.append data.val false).rate (g0.append data.val false).absorbed =
            absorbBytes (toBits kk.state) kk.state_index.val
                kk.input_block_size.val sl.val := by
          simp only [GhostState.append, Bool.false_eq_true, ↓reduceIte]
          rw [← hsl_eq, absorbBytes_append]
          have hkk_pair : absorbBytes (Vector.replicate SHA3.b false) 0 g0.rate g0.absorbed
              = (toBits kk.state, kk.state_index.val) := by
            apply Prod.ext
            · exact hkk_bits.symm
            · exact hkk_idx.symm
          rw [hkk_pair, hg0_rate]
        constructor
        · rw [hcompose, h_within]; simp only
          rw [hks4_state]
        · rw [hcompose, h_within]; simp only
          rw [hks4_si_post]
  · -- absorbing branch — drop halign by integrating append_loop.spec head realignment
    have hab : absorbing self g := by
      rcases h with hab | hsq
      · exact hab
      · exfalso; have hsq_mode : self.squeeze_mode = true := hsq.1.2.1; exact hsm hsq_mode
    rw [if_neg hsm]
    step
    have hns : self.squeeze_mode = false := by
      cases hsmv : self.squeeze_mode
      · rfl
      · exfalso; exact hsm hsmv
    have hg_eq : g.append data.val false = g.append data.val self.squeeze_mode := by rw [hns]
    -- HEAD LOOP via append_loop.spec
    have habw : absorbingWeak self g := hab.1
    have hd_eq_len : data.length = data.len.val := by
      simp only [Slice.length, Slice.len, Usize.ofNatCore, UScalar.val, UScalar.ofNatCore]; rfl
    have hbnd_init : (0#usize : Usize).val + data.len.val ≤ data.length := by
      show 0 + data.len.val ≤ data.length; omega
    step as ⟨ks0, rem0, idx0, hsum0, hbnd_idx0, hawk0, hbits0, hsi0_eq, hdisj0⟩
    -- ks0 facts
    have hks0_no_sm : ks0.squeeze_mode = false := by
      have := hawk0.2.1; simp at this; exact this
    have hks0_ibs_val : ks0.input_block_size.val = self.input_block_size.val := by
      have hh := hawk0.2.2.1
      rw [hh]; simp [GhostState.append, ← hgr_rate]
    have hks0_ibs_eq : ks0.input_block_size = self.input_block_size :=
      UScalar.eq_of_val_eq hks0_ibs_val
    have hks0_pad_eq : ks0.padding_value = self.padding_value := by
      have hh := hawk0.2.2.2.1
      rw [hh]; simp [GhostState.append, hpadval]
    have hks0_si_le : ks0.state_index.val ≤ ks0.input_block_size.val := hawk0.1
    have hks0_si_eq : ks0.state_index.val = self.state_index.val + idx0.val := hsi0_eq
    -- head_bytes consumed by loop
    have h_drop0 : data.val.drop 0 = data.val := by simp
    set head_bytes : List U8 := (data.val.drop 0).take idx0.val with h_hb_def
    have h_hb_take : head_bytes = data.val.take idx0.val := by rw [h_hb_def, h_drop0]
    have h_idx0_le : idx0.val ≤ data.val.length := by
      have h1 : rem0.val + idx0.val = data.len.val + 0 := hsum0
      have h2 : data.val.length = data.len.val := by rw [← hd_eq_len]
      omega
    have h_hb_len : head_bytes.length = idx0.val := by
      rw [h_hb_take, List.length_take]; omega
    -- spongeInvariant for ks0 via absorbBytes_within_block + absorbBytes_append
    have hself_si_lt : self.state_index.val < self.input_block_size.val := hab.2.1
    have hsi_self : spongeInvariant self g := hab.2.2
    obtain ⟨hself_bits, hself_idx⟩ := hsi_self
    have h_hb_fit : self.state_index.val + head_bytes.length ≤ self.input_block_size.val := by
      have : ks0.state_index.val ≤ ks0.input_block_size.val := hks0_si_le
      rw [hks0_si_eq, hks0_ibs_val] at this
      omega
    -- POST-LOOP DISPATCH: branch on whether the head loop ended at a block boundary.
    -- In each branch, derive `absorbing ksp g_head` where g_head = g.append head_bytes false,
    -- ksp.state_index % 8 = 0 (in the cases we need it), and tail-data slice from idx0.
    set g_head : GhostState := g.append head_bytes false with hg_head_def
    -- Convenience: full data split via head_bytes ++ tail
    have h_data_split : head_bytes ++ data.val.drop idx0.val = data.val := by
      rw [h_hb_take]; exact List.take_append_drop _ _
    have hg_full_eq : g.append data.val false =
        (g.append head_bytes false).append (data.val.drop idx0.val) false := by
      simp only [GhostState.append, Bool.false_eq_true, ↓reduceIte, List.append_assoc]
      rw [h_data_split]
    -- self FC, in the shape `absorbBytes_append` consumes
    have hself_pair : absorbBytes (Vector.replicate SHA3.b false) 0 g.rate g.absorbed
        = (toBits self.state, self.state_index.val) := by
      apply Prod.ext
      · exact hself_bits.symm
      · exact hself_idx.symm
    -- (g.append head_bytes false).rate = g.rate, .absorbed = g.absorbed ++ head_bytes
    have hgh_rate : g_head.rate = g.rate := by simp [g_head, GhostState.append]
    have hgh_padval : g_head.padVal = g.padVal := by simp [g_head, GhostState.append]
    have hgh_absorbed : g_head.absorbed = g.absorbed ++ head_bytes := by
      simp [g_head, GhostState.append]
    by_cases hbnd : ks0.state_index = ks0.input_block_size
    · -- Boundary case: head_bytes exactly filled the block, permute fires.
      rw [if_pos hbnd]
      -- Apply keccak_permute.spec
      step as ⟨perm_state, hperm_state⟩
      -- Bridge to KECCAK_f via keccak_permute_toBits
      have hperm_bits : toBits perm_state = SHA3.KECCAK_f (toBits ks0.state) :=
        keccak_permute_toBits _ _ hperm_state
      -- head_bytes fills the block exactly: idx0.val = ibs - self.state_index
      have h_hb_full : self.state_index.val + head_bytes.length = self.input_block_size.val := by
        have hbnd_val : ks0.state_index.val = ks0.input_block_size.val := by rw [hbnd]
        rw [hks0_si_eq, hks0_ibs_val] at hbnd_val
        omega
      have h_hb_pos : 0 < head_bytes.length := by
        rw [h_hb_len]
        -- idx0.val > 0 since self.state_index < ibs and self.state_index + idx0 = ibs
        omega
      -- absorbBytes for the head_bytes block fills exactly, returning (KECCAK_f ..., 0)
      have h_full :
          absorbBytes (toBits self.state) self.state_index.val self.input_block_size.val head_bytes =
          (SHA3.KECCAK_f (absorbBytesRaw (toBits self.state) self.state_index.val head_bytes), 0) :=
        absorbBytes_full_block _ _ _ _ h_hb_full h_hb_pos
      -- Bridge through hbits0 (toBits ks0.state = absorbBytesRaw ... head_bytes)
      have hbits0' : toBits ks0.state = absorbBytesRaw (toBits self.state) self.state_index.val head_bytes := by
        have := hbits0
        simp only [Nat.sub_zero, h_drop0] at this
        rw [h_hb_take]; exact this
      -- Define ksp = post-permute state with state_index = 0
      set ksp : KeccakState :=
        { state := perm_state, input_block_size := ks0.input_block_size,
          state_index := 0#u32, padding_value := ks0.padding_value,
          squeeze_mode := ks0.squeeze_mode } with hksp_def
      have hksp_no_sm : ksp.squeeze_mode = false := hks0_no_sm
      have hksp_ibs_val : ksp.input_block_size.val = self.input_block_size.val := hks0_ibs_val
      have hksp_ibs_eq : ksp.input_block_size = self.input_block_size := hks0_ibs_eq
      have hksp_pad_eq : ksp.padding_value = self.padding_value := hks0_pad_eq
      have hksp_si_zero : ksp.state_index.val = 0 := rfl
      have hksp_align : ksp.state_index.val % 8 = 0 := by rw [hksp_si_zero]
      -- Build absorbing ksp g_head
      have hg_squeezed : g.squeezed = [] := habw.2.2.2.2
      have hgh_squeezed : g_head.squeezed = [] := by
        simp [g_head, GhostState.append, hg_squeezed]
      have hksp_abs : absorbing ksp g_head := by
        refine ⟨?_, ?_, ?_⟩
        · -- absorbingWeak
          refine ⟨?_, ?_, ?_, ?_, ?_⟩
          · rw [hksp_si_zero]; omega
          · simp [hksp_no_sm]
          · rw [hksp_ibs_val, hgh_rate, hgr_rate]
          · rw [hksp_pad_eq, hgh_padval, hpadval]
          · exact hgh_squeezed
        · -- state_index < ibs
          rw [hksp_si_zero, hksp_ibs_val]
          have : 0 < self.input_block_size.val := by rw [hgr_rate]; exact hgrpos
          omega
        · -- spongeInvariant
          unfold spongeInvariant
          have hcompose :
              absorbBytes (Vector.replicate SHA3.b false) 0 g_head.rate g_head.absorbed =
              absorbBytes (toBits self.state) self.state_index.val
                  self.input_block_size.val head_bytes := by
            rw [hgh_rate, hgh_absorbed, absorbBytes_append, hself_pair, ← hgr_rate]
          refine ⟨?_, ?_⟩
          · rw [hcompose, h_full]
            simp only
            rw [hperm_bits, ← hbits0']
          · rw [hcompose, h_full, hksp_si_zero]
      -- Now continue with the same tail as squeezing branch (mutatis mutandis).
      -- Tail data slice has length rem0.val.
      step*
      have hdle : 8 * full_lanes.val ≤ rem0.val := by
        have hfl : full_lanes.val = rem0.val / 8 := by rw [full_lanes_post, U64_NUM_BYTES_val]
        omega
      by_cases hfl_pos : full_lanes > 0#usize
      · -- Case: full_lanes > 0
        rw [if_pos hfl_pos]
        step as ⟨sl, hsl_val, hsl_len⟩
        have hsl_eq : sl.val = data.val.drop idx0.val := hsl_val
        have hsl_len_eq : sl.length = data.val.length - idx0.val := hsl_len
        have hdata_sl : 8 * full_lanes.val ≤ sl.length := by
          rw [hsl_len_eq]
          have h2 : data.val.length = data.len.val := by rw [← hd_eq_len]
          omega
        have hnotfull : ksp.state_index.val < ksp.input_block_size.val := hksp_abs.2.1
        have hks2 := KeccakState.append_lanes.spec ksp sl full_lanes g_head hksp_abs hksp_align hnotfull hdata_sl
        step as ⟨ks2, hks2_abs, hks2_align⟩
        have hks2_si_lt : ks2.state_index.val < ks2.input_block_size.val := hks2_abs.2.1
        have hks2_ibs_rate : ks2.input_block_size.val =
              (g_head.append (sl.val.take (8 * full_lanes.val)) false).rate := hks2_abs.1.2.2.1
        have hks2_ibs_eq : ks2.input_block_size.val = ksp.input_block_size.val := by
              rw [hks2_ibs_rate]; simp [GhostState.append, hgh_rate, hksp_ibs_val, ← hgr_rate]
        have hksp_ibsmod : ksp.input_block_size.val % 8 = 0 := by rw [hksp_ibs_val]; exact hibsmod
        have hks2_align_lt : ks2.state_index.val + 8 ≤ ks2.input_block_size.val := by
              have hibsm : ks2.input_block_size.val % 8 = 0 := by rw [hks2_ibs_eq]; exact hksp_ibsmod
              omega
        have hfl_bnd : full_lanes.val * U64_NUM_BYTES.val ≤ Usize.max := by
              simp only [U64_NUM_BYTES_val]
              have hbnd : data.len.val ≤ Usize.max := by have := data.len.hBounds; simp [Usize.max, Usize.numBits] at *; omega
              have hfl : full_lanes.val = rem0.val / 8 := by
                rw [full_lanes_post, U64_NUM_BYTES_val]
              have : rem0.val ≤ data.len.val := by omega
              omega
        step as ⟨xmul, hxmul⟩
        step as ⟨xidx, hxidx⟩
        step as ⟨xrem, hxrem⟩
        -- The massert (xrem < U64_NUM_BYTES) leaves a side-goal we discharge inline.
        have hxrem_lt : xrem.val < U64_NUM_BYTES.val := by
          rw [hxrem, hxmul]
          simp only [U64_NUM_BYTES_val]
          have hfl : full_lanes.val = rem0.val / 8 := by rw [full_lanes_post, U64_NUM_BYTES_val]
          omega
        have hxrem_lt_u : xrem < U64_NUM_BYTES := by
          show xrem.val < U64_NUM_BYTES.val; exact hxrem_lt
        step  -- massert auto-discharged via hxrem_lt_u
        step as ⟨s, hs_val, hs_len⟩
        step as ⟨self4, hself4_post1, hself4_post2, hself4_post3⟩
        case hfit =>
          have hxmul_eq : xmul.val = 8 * full_lanes.val := by
            rw [hxmul]; simp [U64_NUM_BYTES_val]; ring
          have hslen_lt : s.length < 8 := by
            rw [hs_len, hxidx, hxmul_eq, hd_eq_len]
            have hfl : full_lanes.val = rem0.val / 8 := by
              rw [full_lanes_post, U64_NUM_BYTES_val]
            omega
          omega
        step  -- final massert: leaves 2 goals (massert P, absorbing post)
        -- step* leaves 2 goals: (a) final massert (state_index != ibs), (b) absorbing post.
        all_goals (have hxmul_eq : xmul.val = 8 * full_lanes.val := by
                     rw [hxmul]; simp [U64_NUM_BYTES_val]; ring)
        all_goals (have hxidx_eq : xidx.val = idx0.val + 8 * full_lanes.val := by
                     rw [hxidx, hxmul_eq])
        all_goals (have hxrem_eq : xrem.val = rem0.val - 8 * full_lanes.val := by
                     rw [hxrem, hxmul_eq])
        all_goals have hs_lt : s.length < 8 := by
                    rw [hs_len]
                    simp only [U64_NUM_BYTES_val] at *
                    have hfl : full_lanes.val = rem0.val / 8 := full_lanes_post
                    have h2 : data.val.length = data.len.val := by rw [← hd_eq_len]
                    omega
        all_goals have hs_drop : s.val = data.val.drop (idx0.val + 8 * full_lanes.val) := by
                    rw [hs_val, ← hxidx_eq]
        all_goals have hself4_si_eq : self4.state_index.val = ks2.state_index.val + s.length :=
              hself4_post3
        all_goals have hself4_ibs_rate : self4.input_block_size.val =
              ((g_head.append (sl.val.take (8 * full_lanes.val)) false).append s.val false).rate :=
              hself4_post1.2.2.1
        all_goals have hrates_eq : (g_head.append (sl.val.take (8 * full_lanes.val)) false).rate =
              ((g_head.append (sl.val.take (8 * full_lanes.val)) false).append s.val false).rate := rfl
        all_goals have hself4_ibs_eq : self4.input_block_size.val = ks2.input_block_size.val := by
                    rw [hself4_ibs_rate, ← hrates_eq, ← hks2_ibs_rate]
        · -- Goal a: (self4.state_index != self4.input_block_size) = true
          simp only [bne_iff_ne, ne_eq]
          intro heq
          have heqv : self4.state_index.val = self4.input_block_size.val := by rw [heq]
          rw [hself4_si_eq, hself4_ibs_eq] at heqv
          omega
        · -- Goal b: absorbing self4 (g.append data.val self.squeeze_mode)
          rw [← hg_eq, hg_full_eq]
          have hsl_take_eq : sl.val.take (8 * full_lanes.val) =
              (data.val.drop idx0.val).take (8 * full_lanes.val) := by
            rw [hsl_eq]
          have hsplit : (data.val.drop idx0.val).take (8 * full_lanes.val) ++ s.val =
              data.val.drop idx0.val := by
            rw [hs_drop, ← List.drop_drop]
            exact List.take_append_drop _ _
          have hg_split : g_head.append (data.val.drop idx0.val) false =
              (g_head.append (sl.val.take (8 * full_lanes.val)) false).append s.val false := by
            simp only [GhostState.append, Bool.false_eq_true, ↓reduceIte, List.append_assoc]
            rw [hsl_take_eq, hsplit]
          rw [hg_split]
          refine ⟨hself4_post1, ?_, ?_⟩
          · rw [hself4_si_eq, hself4_ibs_eq]; omega
          · have hks2_si := hks2_abs.2.2
            unfold spongeInvariant at hks2_si ⊢
            obtain ⟨hks2_bits, hks2_idx⟩ := hks2_si
            set g_lane : GhostState := g_head.append (sl.val.take (8 * full_lanes.val)) false with hg_lane_def
            have h_within :
                absorbBytes (toBits ks2.state) ks2.state_index.val ks2.input_block_size.val s.val =
                (absorbBytesRaw (toBits ks2.state) ks2.state_index.val s.val,
                 ks2.state_index.val + s.length) := by
              apply absorbBytes_within_block
              have hsleq : (↑s : List U8).length = s.length := rfl
              omega
            have hg_lane_rate : g_lane.rate = ks2.input_block_size.val := hks2_ibs_rate.symm
            have hcompose :
                absorbBytes (Vector.replicate SHA3.b false) 0 (g_lane.append s.val false).rate
                  ((g_lane.append s.val false).absorbed) =
                absorbBytes (toBits ks2.state) ks2.state_index.val ks2.input_block_size.val s.val := by
              simp only [GhostState.append, Bool.false_eq_true, ↓reduceIte]
              rw [absorbBytes_append]
              have hks2_pair : absorbBytes (Vector.replicate SHA3.b false) 0 g_lane.rate g_lane.absorbed
                  = (toBits ks2.state, ks2.state_index.val) := by
                apply Prod.ext
                · exact hks2_bits.symm
                · exact hks2_idx.symm
              rw [hks2_pair, hg_lane_rate]
            refine ⟨?_, ?_⟩
            · rw [hcompose, h_within]; simp only
              rw [hself4_post2]
            · rw [hself4_si_eq, hcompose, h_within]
      · -- Case: full_lanes = 0
        rw [if_neg hfl_pos]
        have hfl_zero : full_lanes.val = 0 := by simp [GT.gt] at hfl_pos; omega
        have hrem0_lt : rem0.val < 8 := by
          have hfl : full_lanes.val = rem0.val / 8 := by rw [full_lanes_post, U64_NUM_BYTES_val]
          omega
        step  -- massert: rem0 < U64_NUM_BYTES
        step as ⟨sl, hsl_val, hsl_len⟩
        have hsl_eq : sl.val = data.val.drop idx0.val := hsl_val
        have hsl_len_eq : sl.length = data.val.length - idx0.val := hsl_len
        have hsl_len_rem : sl.length = rem0.val := by
          have h2 : data.val.length = data.len.val := by rw [← hd_eq_len]
          rw [hsl_len_eq, h2]; omega
        have hksp_ibs_pos : 8 ≤ ksp.input_block_size.val := by
          rw [hksp_ibs_val]
          have : 0 < self.input_block_size.val := by rw [hgr_rate]; exact hgrpos
          omega
        have hfit : ksp.state_index.val + sl.length ≤ ksp.input_block_size.val := by
          rw [hsl_len_rem, hksp_si_zero]; omega
        have hks4 := KeccakState.append_bytes.spec_with_state_index ksp sl g_head hksp_abs hfit
        step as ⟨ks4, hks4_weak, hks4_state, hks4_si_post⟩
        have hks4_ibs_eq : ks4.input_block_size = ksp.input_block_size := by
          apply UScalar.eq_of_val_eq
          have hrate := hks4_weak.2.2.1
          rw [hrate, hksp_ibs_val]
          simp only [GhostState.append, Bool.false_eq_true, ↓reduceIte]
          rw [← hgr_rate]
        have hsi_ksp : spongeInvariant ksp g_head := hksp_abs.2.2
        unfold spongeInvariant at hsi_ksp
        obtain ⟨hksp_bits, hksp_idx⟩ := hsi_ksp
        step  -- final massert
        rw [← hg_eq, hg_full_eq]
        refine ⟨?_, ?_, ?_⟩
        · -- absorbingWeak
          rw [show data.val.drop idx0.val = sl.val from hsl_eq.symm]
          exact hks4_weak
        · -- state_index < ibs
          rw [hks4_si_post, hks4_ibs_eq]
          show ksp.state_index.val + sl.length < ksp.input_block_size.val
          rw [hsl_len_rem, hksp_si_zero]; omega
        · unfold spongeInvariant
          simp only
          have h_within :
              absorbBytes (toBits ksp.state) ksp.state_index.val ksp.input_block_size.val sl.val =
              (absorbBytesRaw (toBits ksp.state) ksp.state_index.val sl.val,
               ksp.state_index.val + sl.length) := by
            apply absorbBytes_within_block
            have hsleq : (↑sl : List U8).length = sl.length := rfl
            omega
          have hcompose :
              absorbBytes (Vector.replicate SHA3.b false) 0
                  (g_head.append (data.val.drop idx0.val) false).rate
                  (g_head.append (data.val.drop idx0.val) false).absorbed =
              absorbBytes (toBits ksp.state) ksp.state_index.val
                  ksp.input_block_size.val sl.val := by
            simp only [GhostState.append, Bool.false_eq_true, ↓reduceIte]
            rw [show data.val.drop idx0.val = sl.val from hsl_eq.symm, absorbBytes_append]
            have hksp_pair : absorbBytes (Vector.replicate SHA3.b false) 0 g_head.rate g_head.absorbed
                = (toBits ksp.state, ksp.state_index.val) := by
              apply Prod.ext
              · exact hksp_bits.symm
              · exact hksp_idx.symm
            rw [hksp_pair, hgh_rate, hksp_ibs_val, ← hgr_rate]
          constructor
          · rw [hcompose, h_within]; simp only
            rw [hks4_state]; rfl
          · rw [hcompose, h_within]; simp only
            rw [hks4_si_post]; rfl
    · -- Non-boundary: skip permute. ksp := ks0.
      rw [if_neg hbnd]
      -- ks0.state_index < ibs strictly
      have hks0_si_lt : ks0.state_index.val < ks0.input_block_size.val := by
        have h1 : ks0.state_index.val ≤ ks0.input_block_size.val := hks0_si_le
        have h2 : ks0.state_index ≠ ks0.input_block_size := hbnd
        have h3 : ks0.state_index.val ≠ ks0.input_block_size.val := by
          intro heq; apply h2; exact UScalar.eq_of_val_eq heq
        omega
      -- head_bytes fits strictly in block
      have h_hb_strict : self.state_index.val + head_bytes.length < self.input_block_size.val := by
        have hlt2 : ks0.state_index.val < ks0.input_block_size.val := hks0_si_lt
        rw [hks0_si_eq, hks0_ibs_val] at hlt2
        rw [h_hb_len]; omega
      have h_within_head :
          absorbBytes (toBits self.state) self.state_index.val self.input_block_size.val head_bytes =
          (absorbBytesRaw (toBits self.state) self.state_index.val head_bytes,
           self.state_index.val + head_bytes.length) := by
        apply absorbBytes_within_block
        have : (head_bytes : List U8).length = head_bytes.length := rfl
        omega
      have hbits0' : toBits ks0.state = absorbBytesRaw (toBits self.state) self.state_index.val head_bytes := by
        have := hbits0
        simp only [Nat.sub_zero, h_drop0] at this
        rw [h_hb_take]; exact this
      -- Build absorbing ks0 g_head
      have hg_squeezed : g.squeezed = [] := habw.2.2.2.2
      have hgh_squeezed : g_head.squeezed = [] := by simp [g_head, GhostState.append, hg_squeezed]
      have hks0_abs : absorbing ks0 g_head := by
        refine ⟨?_, ?_, ?_⟩
        · refine ⟨?_, ?_, ?_, ?_, ?_⟩
          · exact hks0_si_le
          · simp [hks0_no_sm]
          · rw [hks0_ibs_val, hgh_rate, hgr_rate]
          · rw [hks0_pad_eq, hgh_padval, hpadval]
          · exact hgh_squeezed
        · exact hks0_si_lt
        · unfold spongeInvariant
          simp only
          have hcompose :
              absorbBytes (Vector.replicate SHA3.b false) 0 g_head.rate g_head.absorbed =
              absorbBytes (toBits self.state) self.state_index.val
                  self.input_block_size.val head_bytes := by
            rw [hgh_rate, hgh_absorbed, absorbBytes_append, hself_pair, ← hgr_rate]
          refine ⟨?_, ?_⟩
          · rw [hcompose, h_within_head]; simp only; exact hbits0'
          · rw [hcompose, h_within_head]; simp only
            rw [hks0_si_eq, h_hb_len]
      -- Bounds for full_lanes
      step as ⟨full_lanes, full_lanes_post⟩
      have hdle : 8 * full_lanes.val ≤ rem0.val := by
        have hfl : full_lanes.val = rem0.val / 8 := by rw [full_lanes_post, U64_NUM_BYTES_val]
        omega
      by_cases hfl_pos : full_lanes > 0#usize
      · -- full_lanes > 0: rem0 > 0, so by hdisj0 we have alignment
        rw [if_pos hfl_pos]
        have hfl_pos_val : 0 < full_lanes.val := by simp [GT.gt] at hfl_pos; omega
        have hrem_pos : 0 < rem0.val := by omega
        have hks0_align : ks0.state_index.val % 8 = 0 := by
          rcases hdisj0 with h | h
          · omega
          · exact h
        step as ⟨sl, hsl_val, hsl_len⟩
        have hsl_eq : sl.val = data.val.drop idx0.val := hsl_val
        have hsl_len_eq : sl.length = data.val.length - idx0.val := hsl_len
        have hdata_sl : 8 * full_lanes.val ≤ sl.length := by
          rw [hsl_len_eq]
          have h2 : data.val.length = data.len.val := by rw [← hd_eq_len]
          omega
        have hnotfull : ks0.state_index.val < ks0.input_block_size.val := hks0_abs.2.1
        have hks2 := KeccakState.append_lanes.spec ks0 sl full_lanes g_head hks0_abs hks0_align hnotfull hdata_sl
        step as ⟨ks2, hks2_abs, hks2_align⟩
        have hks2_si_lt : ks2.state_index.val < ks2.input_block_size.val := hks2_abs.2.1
        have hks2_ibs_rate : ks2.input_block_size.val =
              (g_head.append (sl.val.take (8 * full_lanes.val)) false).rate := hks2_abs.1.2.2.1
        have hks2_ibs_eq : ks2.input_block_size.val = ks0.input_block_size.val := by
              rw [hks2_ibs_rate]; simp [GhostState.append, hgh_rate, hks0_ibs_val, ← hgr_rate]
        have hks0_ibsmod : ks0.input_block_size.val % 8 = 0 := by rw [hks0_ibs_val]; exact hibsmod
        have hks2_align_lt : ks2.state_index.val + 8 ≤ ks2.input_block_size.val := by
              have hibsm : ks2.input_block_size.val % 8 = 0 := by rw [hks2_ibs_eq]; exact hks0_ibsmod
              omega
        have hfl_bnd : full_lanes.val * U64_NUM_BYTES.val ≤ Usize.max := by
              simp only [U64_NUM_BYTES_val]
              have hbnd : data.len.val ≤ Usize.max := by
                have := data.len.hBounds
                simp only [Usize.max, Usize.numBits] at *
                rcases System.Platform.numBits_eq with hpb | hpb <;> rw [hpb] at * <;> omega
              have hfl : full_lanes.val = rem0.val / 8 := by
                rw [full_lanes_post, U64_NUM_BYTES_val]
              have : rem0.val ≤ data.len.val := by omega
              omega
        have hidx0_le : idx0.val ≤ data.len.val := by omega
        have hdb : data.len.val ≤ Usize.max := by
          have := data.len.hBounds
          simp only [Usize.max, Usize.numBits] at *
          rcases System.Platform.numBits_eq with hpb | hpb <;> rw [hpb] at * <;> omega
        have hidx0_bnd : idx0.val ≤ Usize.max := by omega
        have hxidx_bnd : idx0.val + 8 * full_lanes.val ≤ Usize.max := by omega
        have hxmul_le_rem : 8 * full_lanes.val ≤ rem0.val := hdle
        step as ⟨xmul, hxmul⟩
        step as ⟨xidx, hxidx⟩
        step as ⟨xrem, hxrem⟩
        have hxrem_lt : xrem.val < U64_NUM_BYTES.val := by
          rw [hxrem, hxmul]
          simp only [U64_NUM_BYTES_val]
          have hfl : full_lanes.val = rem0.val / 8 := by rw [full_lanes_post, U64_NUM_BYTES_val]
          omega
        have hxrem_lt_u : xrem < U64_NUM_BYTES := by
          show xrem.val < U64_NUM_BYTES.val; exact hxrem_lt
        step
        step as ⟨s, hs_val, hs_len⟩
        step as ⟨self4, hself4_post1, hself4_post2, hself4_post3⟩
        case hfit =>
          have hxmul_eq : xmul.val = 8 * full_lanes.val := by
            rw [hxmul]; simp [U64_NUM_BYTES_val]; ring
          have hslen_lt : s.length < 8 := by
            rw [hs_len, hxidx, hxmul_eq, hd_eq_len]
            have hfl : full_lanes.val = rem0.val / 8 := by
              rw [full_lanes_post, U64_NUM_BYTES_val]
            omega
          omega
        step
        all_goals (have hxmul_eq : xmul.val = 8 * full_lanes.val := by
                     rw [hxmul]; simp [U64_NUM_BYTES_val]; ring)
        all_goals (have hxidx_eq : xidx.val = idx0.val + 8 * full_lanes.val := by
                     rw [hxidx, hxmul_eq])
        all_goals (have hxrem_eq : xrem.val = rem0.val - 8 * full_lanes.val := by
                     rw [hxrem, hxmul_eq])
        all_goals have hs_lt : s.length < 8 := by
                    rw [hs_len]
                    simp only [U64_NUM_BYTES_val] at *
                    have hfl : full_lanes.val = rem0.val / 8 := full_lanes_post
                    have h2 : data.val.length = data.len.val := by rw [← hd_eq_len]
                    omega
        all_goals have hs_drop : s.val = data.val.drop (idx0.val + 8 * full_lanes.val) := by
                    rw [hs_val, ← hxidx_eq]
        all_goals have hself4_si_eq : self4.state_index.val = ks2.state_index.val + s.length :=
              hself4_post3
        all_goals have hself4_ibs_rate : self4.input_block_size.val =
              ((g_head.append (sl.val.take (8 * full_lanes.val)) false).append s.val false).rate :=
              hself4_post1.2.2.1
        all_goals have hrates_eq : (g_head.append (sl.val.take (8 * full_lanes.val)) false).rate =
              ((g_head.append (sl.val.take (8 * full_lanes.val)) false).append s.val false).rate := rfl
        all_goals have hself4_ibs_eq : self4.input_block_size.val = ks2.input_block_size.val := by
                    rw [hself4_ibs_rate, ← hrates_eq, ← hks2_ibs_rate]
        · simp only [bne_iff_ne, ne_eq]
          intro heq
          have heqv : self4.state_index.val = self4.input_block_size.val := by rw [heq]
          rw [hself4_si_eq, hself4_ibs_eq] at heqv
          omega
        · rw [← hg_eq, hg_full_eq]
          have hsl_take_eq : sl.val.take (8 * full_lanes.val) =
              (data.val.drop idx0.val).take (8 * full_lanes.val) := by
            rw [hsl_eq]
          have hsplit : (data.val.drop idx0.val).take (8 * full_lanes.val) ++ s.val =
              data.val.drop idx0.val := by
            rw [hs_drop, ← List.drop_drop]
            exact List.take_append_drop _ _
          have hg_split : g_head.append (data.val.drop idx0.val) false =
              (g_head.append (sl.val.take (8 * full_lanes.val)) false).append s.val false := by
            simp only [GhostState.append, Bool.false_eq_true, ↓reduceIte, List.append_assoc]
            rw [hsl_take_eq, hsplit]
          rw [hg_split]
          refine ⟨hself4_post1, ?_, ?_⟩
          · rw [hself4_si_eq, hself4_ibs_eq]; omega
          · have hks2_si := hks2_abs.2.2
            unfold spongeInvariant at hks2_si ⊢
            obtain ⟨hks2_bits, hks2_idx⟩ := hks2_si
            set g_lane : GhostState := g_head.append (sl.val.take (8 * full_lanes.val)) false with hg_lane_def
            have h_within :
                absorbBytes (toBits ks2.state) ks2.state_index.val ks2.input_block_size.val s.val =
                (absorbBytesRaw (toBits ks2.state) ks2.state_index.val s.val,
                 ks2.state_index.val + s.length) := by
              apply absorbBytes_within_block
              have hsleq : (↑s : List U8).length = s.length := rfl
              omega
            have hg_lane_rate : g_lane.rate = ks2.input_block_size.val := hks2_ibs_rate.symm
            have hcompose :
                absorbBytes (Vector.replicate SHA3.b false) 0 (g_lane.append s.val false).rate
                  ((g_lane.append s.val false).absorbed) =
                absorbBytes (toBits ks2.state) ks2.state_index.val ks2.input_block_size.val s.val := by
              simp only [GhostState.append, Bool.false_eq_true, ↓reduceIte]
              rw [absorbBytes_append]
              have hks2_pair : absorbBytes (Vector.replicate SHA3.b false) 0 g_lane.rate g_lane.absorbed
                  = (toBits ks2.state, ks2.state_index.val) := by
                apply Prod.ext
                · exact hks2_bits.symm
                · exact hks2_idx.symm
              rw [hks2_pair, hg_lane_rate]
            refine ⟨?_, ?_⟩
            · rw [hcompose, h_within]; simp only
              rw [hself4_post2]
            · rw [hself4_si_eq, hcompose, h_within]
      · -- full_lanes = 0
        rw [if_neg hfl_pos]
        have hfl_zero : full_lanes.val = 0 := by simp [GT.gt] at hfl_pos; omega
        have hrem0_lt : rem0.val < 8 := by
          have hfl : full_lanes.val = rem0.val / 8 := by rw [full_lanes_post, U64_NUM_BYTES_val]
          omega
        step
        step as ⟨sl, hsl_val, hsl_len⟩
        have hsl_eq : sl.val = data.val.drop idx0.val := hsl_val
        have hsl_len_eq : sl.length = data.val.length - idx0.val := hsl_len
        have hsl_len_rem : sl.length = rem0.val := by
          have h2 : data.val.length = data.len.val := by rw [← hd_eq_len]
          rw [hsl_len_eq, h2]; omega
        have hfit : ks0.state_index.val + sl.length ≤ ks0.input_block_size.val := by
          rw [hsl_len_rem]
          have hsi_lt := hks0_si_lt
          rw [hks0_ibs_val]
          rw [hks0_si_eq]
          have h2 : data.val.length = data.len.val := by rw [← hd_eq_len]
          omega
        have hks4 := KeccakState.append_bytes.spec_with_state_index ks0 sl g_head hks0_abs hfit
        step as ⟨ks4, hks4_weak, hks4_state, hks4_si_post⟩
        have hks4_ibs_eq : ks4.input_block_size = ks0.input_block_size := by
          apply UScalar.eq_of_val_eq
          have hrate := hks4_weak.2.2.1
          rw [hrate, hks0_ibs_val]
          simp only [GhostState.append, Bool.false_eq_true, ↓reduceIte]
          rw [← hgr_rate]
        have hsi_ks0 : spongeInvariant ks0 g_head := hks0_abs.2.2
        unfold spongeInvariant at hsi_ks0
        obtain ⟨hks0_bits, hks0_idx⟩ := hsi_ks0
        step
        all_goals try (
          simp only [bne_iff_ne, ne_eq]
          intro heq
          have heqv : ks4.state_index.val = ks4.input_block_size.val := by rw [heq]
          rw [hks4_si_post, hks4_ibs_eq] at heqv
          rw [hks0_ibs_val, hks0_si_eq, hsl_len_rem] at heqv
          rcases hdisj0 with h0 | h0
          · omega
          · rw [hks0_si_eq] at h0
            have hibsm : ks0.input_block_size.val % 8 = 0 := by rw [hks0_ibs_val]; exact hibsmod
            have : (self.state_index.val + idx0.val) % 8 = 0 := h0
            omega)
        rw [← hg_eq, hg_full_eq]
        refine ⟨?_, ?_, ?_⟩
        · rw [show data.val.drop idx0.val = sl.val from hsl_eq.symm]
          exact hks4_weak
        · rw [hks4_si_post, hks4_ibs_eq]
          show ks0.state_index.val + sl.length < ks0.input_block_size.val
          rw [hsl_len_rem]
          rw [hks0_ibs_val, hks0_si_eq]
          have h2 : data.val.length = data.len.val := by rw [← hd_eq_len]
          omega
        · unfold spongeInvariant
          simp only
          have h_within :
              absorbBytes (toBits ks0.state) ks0.state_index.val ks0.input_block_size.val sl.val =
              (absorbBytesRaw (toBits ks0.state) ks0.state_index.val sl.val,
               ks0.state_index.val + sl.length) := by
            apply absorbBytes_within_block
            have hsleq : (↑sl : List U8).length = sl.length := rfl
            omega
          have hcompose :
              absorbBytes (Vector.replicate SHA3.b false) 0
                  (g_head.append (data.val.drop idx0.val) false).rate
                  (g_head.append (data.val.drop idx0.val) false).absorbed =
              absorbBytes (toBits ks0.state) ks0.state_index.val
                  ks0.input_block_size.val sl.val := by
            simp only [GhostState.append, Bool.false_eq_true, ↓reduceIte]
            rw [show data.val.drop idx0.val = sl.val from hsl_eq.symm, absorbBytes_append]
            have hks0_pair : absorbBytes (Vector.replicate SHA3.b false) 0 g_head.rate g_head.absorbed
                = (toBits ks0.state, ks0.state_index.val) := by
              apply Prod.ext
              · exact hks0_bits.symm
              · exact hks0_idx.symm
            rw [hks0_pair, hgh_rate, hks0_ibs_val, ← hgr_rate]
          constructor
          · rw [hcompose, h_within]; simp only
            rw [hks4_state]
          · rw [hcompose, h_within]; simp only
            rw [hks4_si_post]
