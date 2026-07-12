/-
# `MlKemHashState` adaptor — verified specs

## Three layers

* **Layer 1** — Algorithm-aware ghost-state predicates
  (`MlKemHashState.absorbing`, `MlKemHashState.squeezing`,
  `MlKemHashState.absorbingFor`). Wrap the verified `KeccakState`-level
  `absorbing` / `squeezing` predicates with a consistency check between
  the runtime `alg` tag and the ghost `(rate, padVal)` fields.
* **Layer 2** — One theorem per `MlKemHashState` method.
* **Layer 3** — MLKEM call-pattern composites (`H_call`, `G_call`,
  `J_call`, `PRF_call`, `sampleNTT_cell`) — see
  [`HashCalls.lean`](HashCalls.lean).

The ML-KEM `(rate, padVal)` pairs are pinned by the algorithm tag:

| `MlKemHashAlg` | rate | padVal |
|---|---|---|
| `Shake128` | 168 | 0x1f |
| `Shake256` | 136 | 0x1f |
| `Sha3_256` | 136 | 0x06 |
| `Sha3_512` |  72 | 0x06 |

These match the constants in `src/sha3/sha{3,ke}_variants.rs`.
-/
import Spec.Defs
import Symcrust.Code.Funs
import Symcrust.Properties.SHA3.Basic
import Symcrust.Properties.SHA3.Sponge.Init
import Symcrust.Properties.SHA3.Sponge.Absorb
import Symcrust.Properties.SHA3.Sponge.Extract
import Symcrust.Properties.SHA3.Sponge.Bridge

namespace symcrust

open Aeneas Aeneas.Std Result
open Spec
open scoped Spec.Notations
open sha3.sha3_impl
open mlkem.hash

/-! ## Layer 1 — algorithm-aware ghost state predicates -/

namespace mlkem.hash.MlKemHashState

/-- (rate-in-bytes, padding-byte-suffix) for each `MlKemHashAlg`.
    `None` is mapped to `none` to encode that this tag must not appear in
    a valid hash session. -/
def algParams : MlKemHashAlg → Option (Nat × U8)
  | .None     => none
  | .Shake128 => some (168, 31#u8)
  | .Shake256 => some (136, 31#u8)
  | .Sha3_256 => some (136,  6#u8)
  | .Sha3_512 => some ( 72,  6#u8)

/-- `self` is in an absorbing state with alg-tag matching the ghost
    rate/padVal. `irreducible` to preserve the abstraction barrier. -/
@[irreducible]
def absorbing (self : MlKemHashState) (g : GhostState) : Prop :=
  _root_.symcrust.sha3.sha3_impl.absorbing self.state g ∧
  algParams self.alg = some (g.rate, g.padVal)

/-- `self` is in a squeezing state with alg-tag matching the ghost
    rate/padVal. -/
@[irreducible]
def squeezing (self : MlKemHashState) (g : GhostState) : Prop :=
  _root_.symcrust.sha3.sha3_impl.squeezing self.state g ∧
  algParams self.alg = some (g.rate, g.padVal)

/-- `self` is freshly init'd for `alg`, has absorbed the listed bytes,
    and has not yet squeezed. Used by Layer-3 fork-pattern lemmas. -/
def absorbingFor (self : MlKemHashState) (alg : MlKemHashAlg)
    (absorbed : List U8) : Prop :=
  ∃ (rate : Nat) (padVal : U8)
    (h_rate : 0 < rate ∧ 8 * rate < Spec.SHA3.b ∧ rate % 8 = 0),
    let g : GhostState := { rate, padVal, absorbed, squeezed := [], h_rate }
    absorbing self g ∧ self.alg = alg

/-- `self` is freshly init'd for `alg`, no input absorbed yet. -/
abbrev freshFor (self : MlKemHashState) (alg : MlKemHashAlg) : Prop :=
  absorbingFor self alg []

end mlkem.hash.MlKemHashState

/-! ## Layer 2 — method theorems -/

namespace mlkem.hash

/-! ### `MlKemHashState.set_alg` -/

@[step] theorem MlKemHashState.set_alg.spec
    (self : MlKemHashState) (alg : MlKemHashAlg) :
    MlKemHashState.set_alg self alg
    ⦃ (r : MlKemHashState) =>
      r.state = self.state ∧ r.alg = alg ⦄ := by
  unfold MlKemHashState.set_alg
  step*

/-! ### `MlKemHashState.init` -/

/-- **Block-size getter spec.** Returns the rate (block-size in bytes)
of the algorithm. Precondition `algParams self.alg = some (rate, _)`
rules out the panic branch (`MlKemHashAlg.None => fail`) and pins down
the rate constant.

Proof: unfold `get_block_size`, case on
`self.alg`, use `h_alg` to discharge the `None` panic, in each algorithm
arm `simp` the constant `BLOCK_SIZE` projection and conclude
`r.val = rate`. -/
@[step] theorem MlKemHashState.get_block_size.spec
    (self : MlKemHashState) (rate : Nat) (padVal : U8)
    (h_alg : MlKemHashState.algParams self.alg = some (rate, padVal)) :
    MlKemHashState.get_block_size self
    ⦃ (r : U32) => r.val = rate ⦄ := by
  unfold MlKemHashState.get_block_size
  rcases halg : self.alg with _ | _ | _ | _ | _ <;>
    rw [halg] at h_alg <;>
    simp only [MlKemHashState.algParams] at h_alg
  case None => cases h_alg
  case Shake128 | Shake256 =>
    rw [Option.some_inj, Prod.mk.injEq] at h_alg
    obtain ⟨hrate, _⟩ := h_alg
    simp only [_root_.symcrust.hash.OneShotXof.BLOCK_SIZE_1.default]
    step*
  case Sha3_256 | Sha3_512 =>
    rw [Option.some_inj, Prod.mk.injEq] at h_alg
    obtain ⟨hrate, _⟩ := h_alg
    simp only [_root_.symcrust.hash.OneShotHash.BLOCK_SIZE_1.default]
    step*

/-- **Padding-value getter spec.** Returns the SHAKE/SHA-3 domain
separator byte of the algorithm. Precondition shape identical to
`get_block_size.spec`.

Proof: unfold `get_padding_value`, case
on `self.alg`, discharge the panic, in each arm the body is literally
`ok SHAKE_PADDING_VALUE` (= `31#u8`) or `ok SHA3_PADDING_VALUE`
(= `6#u8`), matching `algParams` second component. -/
@[step] theorem MlKemHashState.get_padding_value.spec
    (self : MlKemHashState) (rate : Nat) (padVal : U8)
    (h_alg : MlKemHashState.algParams self.alg = some (rate, padVal)) :
    MlKemHashState.get_padding_value self
    ⦃ (r : U8) => r = padVal ⦄ := by
  unfold MlKemHashState.get_padding_value
  rcases halg : self.alg with _ | _ | _ | _ | _ <;>
    rw [halg] at h_alg <;>
    simp only [MlKemHashState.algParams] at h_alg
  case None => cases h_alg
  case Shake128 | Shake256 =>
    rw [Option.some_inj, Prod.mk.injEq] at h_alg
    obtain ⟨_, hpad⟩ := h_alg
    simp only [sha3.shake_variants.SHAKE_PADDING_VALUE]
    step*
  case Sha3_256 | Sha3_512 =>
    rw [Option.some_inj, Prod.mk.injEq] at h_alg
    obtain ⟨_, hpad⟩ := h_alg
    simp only [sha3.sha3_variants.SHA3_PADDING_VALUE]
    step*

@[step] theorem MlKemHashState.init.spec
    (self : MlKemHashState) (rate : Nat) (padVal : U8)
    (h_alg : MlKemHashState.algParams self.alg = some (rate, padVal))
    (h_rate : 0 < rate ∧ 8 * rate < Spec.SHA3.b ∧ rate % 8 = 0) :
    MlKemHashState.init self
    ⦃ (r : MlKemHashState) =>
      r.alg = self.alg ∧
      MlKemHashState.absorbing r (.init rate padVal h_rate) ⦄ := by
  unfold MlKemHashState.init
  unfold MlKemHashState.get_block_size
  unfold MlKemHashState.get_padding_value
  rcases halg : self.alg with _ | _ | _ | _ | _ <;>
    rw [halg] at h_alg <;>
    simp only [MlKemHashState.algParams] at h_alg
  case None => cases h_alg
  case Shake128 | Shake256 =>
    rw [Option.some_inj, Prod.mk.injEq] at h_alg
    obtain ⟨hrate, hpad⟩ := h_alg
    simp only [_root_.symcrust.hash.OneShotXof.BLOCK_SIZE_1.default]
    have h_rate' : 0 < _ ∧ 8 * _ < Spec.SHA3.b ∧ _ % 8 = 0 := hrate ▸ h_rate
    step with sha3.sha3_impl.KeccakState.init.spec
    simp only [MlKemHashState.absorbing, MlKemHashState.algParams]
    refine ⟨?_, ?_⟩
    · convert i_post1 using 2 <;>
        simp [sha3.shake_variants.SHAKE_PADDING_VALUE, ← hrate, ← hpad]
    · simp [GhostState.init, ← hrate, ← hpad]
  case Sha3_256 | Sha3_512 =>
    rw [Option.some_inj, Prod.mk.injEq] at h_alg
    obtain ⟨hrate, hpad⟩ := h_alg
    simp only [_root_.symcrust.hash.OneShotHash.BLOCK_SIZE_1.default]
    have h_rate' : 0 < _ ∧ 8 * _ < Spec.SHA3.b ∧ _ % 8 = 0 := hrate ▸ h_rate
    step with sha3.sha3_impl.KeccakState.init.spec
    simp only [MlKemHashState.absorbing, MlKemHashState.algParams]
    refine ⟨?_, ?_⟩
    · convert i_post1 using 2 <;>
        simp [sha3.sha3_variants.SHA3_PADDING_VALUE, ← hrate, ← hpad]
    · simp [GhostState.init, ← hrate, ← hpad]

/-! ### `MlKemHashState.append` -/

@[step] theorem MlKemHashState.get_alg.spec (self : MlKemHashState) :
    MlKemHashState.get_alg self
    ⦃ (r : MlKemHashAlg) => r = self.alg ⦄ := by
  unfold MlKemHashState.get_alg; step*

@[step] theorem MlKemHashAlg.eq.spec (self other : MlKemHashAlg) :
    MlKemHashAlg.Insts.CoreCmpPartialEqMlKemHashAlg.eq self other
    ⦃ (b : Bool) => b = (read_discriminant self = read_discriminant other) ⦄ := by
  unfold MlKemHashAlg.Insts.CoreCmpPartialEqMlKemHashAlg.eq; step*

@[step] theorem MlKemHashState.append.spec
    (self : MlKemHashState) (data : Slice U8) (g : GhostState)
    (h : MlKemHashState.absorbing self g ∨ MlKemHashState.squeezing self g) :
    MlKemHashState.append self data
    ⦃ (r : MlKemHashState) =>
      r.alg = self.alg ∧
      MlKemHashState.absorbing r (g.append data.val self.state.squeeze_mode) ⦄ := by
  unfold MlKemHashState.append
  have h_alg : algParams self.alg = some (g.rate, g.padVal) := by
    rcases h with hab | hsq
    · simp [MlKemHashState.absorbing] at hab; exact hab.2
    · simp [MlKemHashState.squeezing] at hsq; exact hsq.2
  have hks : sha3.sha3_impl.absorbing self.state g ∨ sha3.sha3_impl.squeezing self.state g := by
    rcases h with hab | hsq
    · left; simp [MlKemHashState.absorbing] at hab; exact hab.1
    · right; simp [MlKemHashState.squeezing] at hsq; exact hsq.1
  step*
  simp only [MlKemHashState.absorbing]
  refine ⟨ks_post, ?_⟩
  simp [GhostState.append, h_alg]
  split <;> simp

/-! ### `MlKemHashState.clone` -/

@[step] theorem MlKemHashState.clone.spec
    (self : MlKemHashState) :
    MlKemHashState.Insts.CoreCloneClone.clone self
    ⦃ (r : MlKemHashState) => r = self ⦄ := by
  unfold MlKemHashState.Insts.CoreCloneClone.clone
  unfold sha3.sha3_impl.KeccakState.Insts.CoreCloneClone.clone
  unfold MlKemHashAlg.Insts.CoreCloneClone.clone
  step*
  simp [Aeneas.Std.lift, core.clone.impls.CloneU32.clone,
        core.clone.impls.CloneU8.clone, ← x_post]

/-! ### `MlKemHashState.extract` -/

@[step] theorem MlKemHashState.extract.spec
    (self : MlKemHashState) (output : Slice U8) (wipe : Bool)
    (g : GhostState)
    (h : MlKemHashState.absorbing self g ∨ MlKemHashState.squeezing self g)
    (h_alg : self.alg = .Shake128 ∨ self.alg = .Shake256) :
    MlKemHashState.extract self output wipe
    ⦃ state' out =>
      state'.alg = self.alg ∧
      out.length = output.length ∧
      out.val = (extractOutput g output.length).toList ∧
      (if wipe then MlKemHashState.absorbing state' (.init g.rate g.padVal g.h_rate)
       else MlKemHashState.squeezing state' (g.squeeze out.val)) ⦄ := by
  unfold MlKemHashState.extract
  unfold MlKemHashAlg.Insts.CoreCmpPartialEqMlKemHashAlg.eq
  have h_alg_par : algParams self.alg = some (g.rate, g.padVal) := by
    rcases h with hab | hsq
    · simp [MlKemHashState.absorbing] at hab; exact hab.2
    · simp [MlKemHashState.squeezing] at hsq; exact hsq.2
  have hks : sha3.sha3_impl.absorbing self.state g ∨
             sha3.sha3_impl.squeezing self.state g := by
    rcases h with hab | hsq
    · left; simp [MlKemHashState.absorbing] at hab; exact hab.1
    · right; simp [MlKemHashState.squeezing] at hsq; exact hsq.1
  rcases halg : self.alg with _ | _ | _ | _ | _ <;>
    rw [halg] at h_alg <;> simp [*] at *
  case Shake128 | Shake256 =>
    step with sha3.sha3_impl.KeccakState.extract.spec as ⟨ks, output', hlen, hval, hpost⟩
    simp only [MlKemHashState.algParams, Option.some_inj, Prod.mk.injEq] at h_alg_par
    obtain ⟨hgrate, hgpad⟩ := h_alg_par
    refine ⟨hlen, hval, ?_⟩
    split
    next hwipe =>
      simp only [MlKemHashState.absorbing, MlKemHashState.algParams, hgrate, hgpad]
      rw [if_pos hwipe] at hpost
      exact ⟨hpost, by simp [GhostState.init]⟩
    next hwipe =>
      simp only [MlKemHashState.squeezing, MlKemHashState.algParams, hgrate, hgpad]
      rw [if_neg hwipe] at hpost
      refine ⟨?_, by simp [GhostState.squeeze]⟩
      simp only [GhostState.squeeze] at hpost
      exact hpost


/-! ### `MlKemHashState.result` -/

/-- Output size required by `result` per algorithm. -/
def MlKemHashState.resultSize : MlKemHashAlg → Nat
  | .None     => 0
  | .Shake128 => 32
  | .Shake256 => 64
  | .Sha3_256 => 32
  | .Sha3_512 => 64

/-- **Result-size getter spec.** Returns the canonical digest length
(in bytes) of the algorithm. Precondition rules out the `None` panic
via `algParams = some _`.

Proof: unfold `get_result_size`, case
on `self.alg`, discharge the panic, in each arm the body's
`.RESULT_SIZE` projection collapses to the constant matching
`resultSize`. -/
@[step] theorem MlKemHashState.get_result_size.spec
    (self : MlKemHashState) (rate : Nat) (padVal : U8)
    (h_alg : MlKemHashState.algParams self.alg = some (rate, padVal)) :
    MlKemHashState.get_result_size self
    ⦃ (r : Usize) => r.val = MlKemHashState.resultSize self.alg ⦄ := by
  unfold MlKemHashState.get_result_size
  rcases halg : self.alg with _ | _ | _ | _ | _ <;>
    rw [halg] at h_alg <;>
    simp only [MlKemHashState.algParams] at h_alg
  case None => cases h_alg
  case Shake128 | Shake256 =>
    simp only [_root_.symcrust.hash.OneShotXof.RESULT_SIZE_1.default,
               MlKemHashState.resultSize]
    step*
  case Sha3_256 | Sha3_512 =>
    simp only [_root_.symcrust.hash.OneShotHash.RESULT_SIZE_1.default,
               MlKemHashState.resultSize]
    step*

@[step] theorem MlKemHashState.result.spec
    (self : MlKemHashState) (output : Slice U8)
    (g : GhostState)
    (h : MlKemHashState.absorbing self g ∨ MlKemHashState.squeezing self g)
    (h_len : output.length = MlKemHashState.resultSize self.alg) :
    MlKemHashState.result self output
    ⦃ state' out =>
      state'.alg = self.alg ∧
      out.length = output.length ∧
      out.val = (extractOutput g output.length).toList ∧
      MlKemHashState.absorbing state' (.init g.rate g.padVal g.h_rate) ⦄ := by
  unfold MlKemHashState.result
  unfold MlKemHashState.get_result_size
  have h_alg_par : algParams self.alg = some (g.rate, g.padVal) := by
    rcases h with hab | hsq
    · simp [MlKemHashState.absorbing] at hab; exact hab.2
    · simp [MlKemHashState.squeezing] at hsq; exact hsq.2
  have hks : sha3.sha3_impl.absorbing self.state g ∨
             sha3.sha3_impl.squeezing self.state g := by
    rcases h with hab | hsq
    · left; simp [MlKemHashState.absorbing] at hab; exact hab.1
    · right; simp [MlKemHashState.squeezing] at hsq; exact hsq.1
  have h_alg_ne : self.alg ≠ MlKemHashAlg.None := by
    intro heq
    rw [heq, MlKemHashState.algParams] at h_alg_par
    cases h_alg_par
  rcases halg : self.alg with _ | _ | _ | _ | _ <;>
    rw [halg] at h_len <;> simp [MlKemHashState.resultSize, *] at *
  case Shake128 | Shake256 =>
    simp only [_root_.symcrust.hash.OneShotXof.RESULT_SIZE_1.default]
    step
    step with sha3.sha3_impl.KeccakState.extract.spec as ⟨ks, output', hlen, hval, hpost⟩
    simp only [MlKemHashState.algParams, Option.some_inj, Prod.mk.injEq] at h_alg_par
    obtain ⟨hgrate, hgpad⟩ := h_alg_par
    refine ⟨?_, hval, ?_⟩
    · simp [Slice.length] at hlen
      simp [hlen, h_len]
    simp only [MlKemHashState.absorbing, MlKemHashState.algParams, hgrate, hgpad]
    refine ⟨?_, by simp [GhostState.init]⟩
    simp only [if_true] at hpost
    convert hpost
  case Sha3_256 | Sha3_512 =>
    simp only [_root_.symcrust.hash.OneShotHash.RESULT_SIZE_1.default]
    step
    step with sha3.sha3_impl.KeccakState.extract.spec as ⟨ks, output', hlen, hval, hpost⟩
    simp only [MlKemHashState.algParams, Option.some_inj, Prod.mk.injEq] at h_alg_par
    obtain ⟨hgrate, hgpad⟩ := h_alg_par
    refine ⟨?_, hval, ?_⟩
    · simp [Slice.length] at hlen
      simp [hlen, h_len]
    simp only [MlKemHashState.absorbing, MlKemHashState.algParams, hgrate, hgpad]
    refine ⟨?_, by simp [GhostState.init]⟩
    simp only [if_true] at hpost
    convert hpost

/-! ## SHA3-256 sponge bridge

Used by `mlkem.key_compute_encapsulation_key_hash.spec` (and any other
ML-KEM hash invocation that funnels into `Spec.SHA3.sha3_256`).  The
adaptor's `init → append* → result` chain leaves the ghost `g` in
absorbing state with `g.rate = 136`, `g.padVal = 0x06`, and an empty
`squeezed` list; `result` then produces `extractOutput g 32`.  This
bridge connects that output to the spec function `Spec.SHA3.sha3_256`
applied to the absorbed bytes.

Informal proof. By definition `extractOutput g 32` runs the verified
sponge with rate `136` and padding `0x06` over `g.absorbed`, squeezing
the first `32` bytes; `Spec.SHA3.sha3_256` is the same construction by
`Spec.SHA3` definitions (`bitsToBytes (SHA3_256 (bytesToBits B))`).
The kernel `KECCAK-p[1600,24]` permutation is identical on both sides
(see `Properties/SHA3/Sponge/Extract.lean` for the verified
`KeccakState.extract.spec`).  Concretely:

1. Unfold `extractOutput`: it (a) absorbs `g.absorbed` into the b-bit
   state via `absorbBytes`, (b) pads via `padAndPermute` with `padVal =
   0x06`, then (c) squeezes the first `g.rate` byte block via
   `squeezeBytes` (truncated to 32 since `outLen = 32 < g.rate`).
2. Unfold `Spec.SHA3.sha3_256`: `bitsToBytes (SHA3_256 (bytesToBits B))`
   expands to absorb-pad-squeeze on the same `KECCAK-p[1600,24]` with
   rate 136, capacity 512, padding `0x06` (Keccak SHA3 trail).
3. Per-byte equality follows from the `Properties/SHA3/Sponge` bridge
   lemmas — specifically the SHA3-256-instance witness that `(rate=136,
   padVal=0x06)` ghosts match the spec function. -/
theorem sha3_256_extractOutput
    {n : Nat} (g : GhostState) (B : 𝔹 n)
    (h_n : g.absorbed.length = n)
    (h_bytes : ∀ (i : Fin n),
        B.get i = (g.absorbed[i.val]'(h_n ▸ i.isLt)).bv)
    (h_rate : g.rate = 136)
    (h_pad : g.padVal = 6#u8)
    (h_squeezed : g.squeezed = []) :
    (extractOutput g 32).map (·.bv) = Spec.SHA3.sha3_256 B := by
  let msg : Vector U8 n := ⟨g.absorbed.toArray, by simp [h_n]⟩
  have hmsg_toList : msg.toList = g.absorbed := by
    simp [msg, Vector.toList]
  have hmsg_eq_B : msg.map (·.bv) = B := by
    apply Vector.ext
    intro i hi
    simp only [Vector.getElem_map, msg, Vector.getElem_mk, List.getElem_toArray]
    have hb := h_bytes ⟨i, hi⟩
    simp [Vector.get] at hb
    exact hb.symm
  have hbits : bytesU8ToBits msg = Spec.bytesToBits B := by
    unfold bytesU8ToBits
    rw [hmsg_eq_B]
  unfold extractOutput
  rw [h_rate, h_pad, h_squeezed]
  simp only [List.length_nil]
  unfold squeezeAfter
  have hs : (2 : Nat) + 1 ≤ 8 := by decide
  have hsmall : (2 : Nat) + 1 < 8 := by decide
  have hr : (0 : Nat) < 136 ∧ 8 * 136 < Spec.SHA3.b := by decide
  have hpad : (6#u8 : U8) = encodePadVal Spec.SHA3.hashSuffix hs := by
    unfold encodePadVal Spec.SHA3.hashSuffix; native_decide
  rw [hpad]
  rw [show g.absorbed = msg.toList from hmsg_toList.symm]
  have hcode := code_toSpec msg Spec.SHA3.hashSuffix 136 32 hs hsmall hr
  rw [hbits] at hcode
  have h := congrArg Spec.bitsToBytes hcode
  unfold bytesU8ToBits at h
  rw [Spec.bitsToBytes_bytesToBits] at h
  unfold Spec.SHA3.sha3_256 Spec.SHA3.SHA3_256 Spec.SHA3.KECCAK
  exact h

/-! ## SHA3-512 sponge bridge

Sister of `sha3_256_extractOutput`: connects the streaming `init → append* →
result` chain (with ghost `g` satisfying `g.rate = 72`, `g.padVal = 0x06`,
`g.squeezed = []`) to `Spec.SHA3.sha3_512` applied to the absorbed bytes.
The proof mirrors `sha3_256_extractOutput` with rate `72`, output length
`64`, and the SHA3-512 spec unfolding. -/
theorem sha3_512_extractOutput
    {n : Nat} (g : GhostState) (B : 𝔹 n)
    (h_n : g.absorbed.length = n)
    (h_bytes : ∀ (i : Fin n),
        B.get i = (g.absorbed[i.val]'(h_n ▸ i.isLt)).bv)
    (h_rate : g.rate = 72)
    (h_pad : g.padVal = 6#u8)
    (h_squeezed : g.squeezed = []) :
    (extractOutput g 64).map (·.bv) = Spec.SHA3.sha3_512 B := by
  let msg : Vector U8 n := ⟨g.absorbed.toArray, by simp [h_n]⟩
  have hmsg_toList : msg.toList = g.absorbed := by
    simp [msg, Vector.toList]
  have hmsg_eq_B : msg.map (·.bv) = B := by
    apply Vector.ext
    intro i hi
    simp only [Vector.getElem_map, msg, Vector.getElem_mk, List.getElem_toArray]
    have hb := h_bytes ⟨i, hi⟩
    simp [Vector.get] at hb
    exact hb.symm
  have hbits : bytesU8ToBits msg = Spec.bytesToBits B := by
    unfold bytesU8ToBits
    rw [hmsg_eq_B]
  unfold extractOutput
  rw [h_rate, h_pad, h_squeezed]
  simp only [List.length_nil]
  unfold squeezeAfter
  have hs : (2 : Nat) + 1 ≤ 8 := by decide
  have hsmall : (2 : Nat) + 1 < 8 := by decide
  have hr : (0 : Nat) < 72 ∧ 8 * 72 < Spec.SHA3.b := by decide
  have hpad : (6#u8 : U8) = encodePadVal Spec.SHA3.hashSuffix hs := by
    unfold encodePadVal Spec.SHA3.hashSuffix; native_decide
  rw [hpad]
  rw [show g.absorbed = msg.toList from hmsg_toList.symm]
  have hcode := code_toSpec msg Spec.SHA3.hashSuffix 72 64 hs hsmall hr
  rw [hbits] at hcode
  have h := congrArg Spec.bitsToBytes hcode
  unfold bytesU8ToBits at h
  rw [Spec.bitsToBytes_bytesToBits] at h
  unfold Spec.SHA3.sha3_512 Spec.SHA3.SHA3_512 Spec.SHA3.KECCAK
  exact h

end mlkem.hash

end symcrust
