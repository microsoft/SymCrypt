import Symcrust.Properties.SHA3.Sponge.Init
import Symcrust.Properties.SHA3.Sponge.Absorb
import Symcrust.Properties.SHA3.Sponge.Extract

/-!
# SHA-3 Verification — Incremental Variant Wrappers

Functional-correctness specs for the user-visible incremental SHA-3/SHAKE
state types declared in `src/sha3/shake1x.rs`:

| Rust type        | Rate | Padding | Variant                |
|------------------|-----:|---------|------------------------|
| `HXof`           |  136 | `0x1F`  | SHAKE256 incremental   |
| `GXof`           |  168 | `0x1F`  | SHAKE128 incremental   |
| `Sha3_256State`  |  136 | `0x06`  | SHA3-256 incremental   |
| `Sha3_512State`  |   72 | `0x06`  | SHA3-512 incremental   |

Each wrapper just forwards to `KeccakState.{init, append, extract}`; these
specs simply propagate the corresponding `KeccakState.*.spec` postcondition
through the trivial `{ state := ... }` plumbing.

The fully-bridged "output equals FIPS 202 spec" theorems for the *one-shot*
APIs (`sha3_256`, `sha3_512`, `shake128`, `shake256`) live in
`Symcrust/Properties/SHA3/Shake1x.lean`. This file deliberately stops at the
`extractOutput` / `absorbing` / `squeezing` level: incremental clients may
issue several `extract` calls per `append`, so the FIPS-202 byte equality
becomes interesting only at sequence boundaries (cf. `extractOutput_append`
in [`Sponge/BridgeComp.lean`](Sponge/BridgeComp.lean)).

`Sha3_224HashState` (rate 144, padding `0x06`) is declared in
[`sha3_224.rs`](../../../src/sha3/sha3_224.rs) but is **not** in
[`Code/Funs.lean`](../Code/Funs.lean) — Aeneas elides the file because
three of its `Hash`-trait methods are stubbed with `todo!()`.
-/

namespace symcrust

open Aeneas Aeneas.Std Result
open Spec
open sha3.sha3_impl
open sha3.shake1x

namespace sha3.shake1x

/-! ## SHAKE256 incremental (HXof) — rate 136, padding 0x1F -/

@[step] theorem HXof.new.spec :
    HXof.new
    ⦃ (r : HXof) =>
      absorbing r.state (.init SHAKE256_RATE.val SHAKE_PADDING (by native_decide)) ⦄ := by
  unfold HXof.new
  step*
  · refine ⟨?_, ?_, ?_⟩ <;> native_decide

@[step] theorem HXof.append.spec
    (self : HXof) (data : Slice U8) (g : GhostState)
    (h : absorbing self.state g ∨ squeezing self.state g) :
    HXof.append self data
    ⦃ (r : HXof) =>
      absorbing r.state (g.append data.val self.state.squeeze_mode) ⦄ := by
  unfold HXof.append
  step*

@[step] theorem HXof.extract.spec
    (self : HXof) (output : Slice U8) (g : GhostState)
    (h : absorbing self.state g ∨ squeezing self.state g) :
    HXof.extract self output
    ⦃ (r : HXof × Slice U8) =>
      r.2.length = output.length ∧
      r.2.val = (extractOutput g output.length).toList ∧
      squeezing r.1.state (g.squeeze r.2.val) ⦄ := by
  unfold HXof.extract
  step*

@[step] theorem HXof.extract_and_wipe.spec
    (self : HXof) (output : Slice U8) (g : GhostState)
    (h : absorbing self.state g ∨ squeezing self.state g) :
    HXof.extract_and_wipe self output
    ⦃ (r : HXof × Slice U8) =>
      r.2.length = output.length ∧
      r.2.val = (extractOutput g output.length).toList ∧
      absorbing r.1.state (.init g.rate g.padVal g.h_rate) ⦄ := by
  unfold HXof.extract_and_wipe
  step*

/-! ## SHAKE128 incremental (GXof) — rate 168, padding 0x1F -/

@[step] theorem GXof.new.spec :
    GXof.new
    ⦃ (r : GXof) =>
      absorbing r.state (.init SHAKE128_RATE.val SHAKE_PADDING (by native_decide)) ⦄ := by
  unfold GXof.new
  step*
  · refine ⟨?_, ?_, ?_⟩ <;> native_decide

@[step] theorem GXof.append.spec
    (self : GXof) (data : Slice U8) (g : GhostState)
    (h : absorbing self.state g ∨ squeezing self.state g) :
    GXof.append self data
    ⦃ (r : GXof) =>
      absorbing r.state (g.append data.val self.state.squeeze_mode) ⦄ := by
  unfold GXof.append
  step*

@[step] theorem GXof.extract.spec
    (self : GXof) (output : Slice U8) (g : GhostState)
    (h : absorbing self.state g ∨ squeezing self.state g) :
    GXof.extract self output
    ⦃ (r : GXof × Slice U8) =>
      r.2.length = output.length ∧
      r.2.val = (extractOutput g output.length).toList ∧
      squeezing r.1.state (g.squeeze r.2.val) ⦄ := by
  unfold GXof.extract
  step*

@[step] theorem GXof.extract_and_wipe.spec
    (self : GXof) (output : Slice U8) (g : GhostState)
    (h : absorbing self.state g ∨ squeezing self.state g) :
    GXof.extract_and_wipe self output
    ⦃ (r : GXof × Slice U8) =>
      r.2.length = output.length ∧
      r.2.val = (extractOutput g output.length).toList ∧
      absorbing r.1.state (.init g.rate g.padVal g.h_rate) ⦄ := by
  unfold GXof.extract_and_wipe
  step*

/-! ## SHA3-256 incremental (Sha3_256State) — rate 136, padding 0x06 -/

@[step] theorem Sha3_256State.new.spec :
    Sha3_256State.new
    ⦃ (r : Sha3_256State) =>
      absorbing r.state (.init SHA3_256_RATE.val SHA3_PADDING (by native_decide)) ⦄ := by
  unfold Sha3_256State.new
  step*
  · refine ⟨?_, ?_, ?_⟩ <;> native_decide

@[step] theorem Sha3_256State.append.spec
    (self : Sha3_256State) (data : Slice U8) (g : GhostState)
    (h : absorbing self.state g ∨ squeezing self.state g) :
    Sha3_256State.append self data
    ⦃ (r : Sha3_256State) =>
      absorbing r.state (g.append data.val self.state.squeeze_mode) ⦄ := by
  unfold Sha3_256State.append
  step*

@[step] theorem Sha3_256State.extract.spec
    (self : Sha3_256State) (output : Array U8 32#usize) (g : GhostState)
    (h : absorbing self.state g ∨ squeezing self.state g) :
    Sha3_256State.extract self output
    ⦃ (r : Sha3_256State × Array U8 32#usize) =>
      r.2.val = (extractOutput g 32).toList ∧
      absorbing r.1.state (.init g.rate g.padVal g.h_rate) ⦄ := by
  unfold Sha3_256State.extract
  step
  let* ⟨ks, output', hlen, hbytes, hpost⟩ ←
    KeccakState.extract.spec (g := g)
  have hs_len : s.length = (32#usize).val := by
    show (↑s : List U8).length = (32#usize).val
    rw [s_post1]; exact output.property
  have hlen' : (↑output' : List U8).length = (32#usize).val := by
    rw [show (↑output' : List U8).length = output'.length from rfl, hlen, hs_len]
  refine ⟨?_, ?_⟩
  · rw [s_post2, Aeneas.Std.Array.from_slice_val output output' hlen',
        hbytes, hs_len]; rfl
  · simpa using hpost

/-! ## SHA3-512 incremental (Sha3_512State) — rate 72, padding 0x06 -/

@[step] theorem Sha3_512State.new.spec :
    Sha3_512State.new
    ⦃ (r : Sha3_512State) =>
      absorbing r.state (.init SHA3_512_RATE.val SHA3_PADDING (by native_decide)) ⦄ := by
  unfold Sha3_512State.new
  step*
  · refine ⟨?_, ?_, ?_⟩ <;> native_decide

@[step] theorem Sha3_512State.append.spec
    (self : Sha3_512State) (data : Slice U8) (g : GhostState)
    (h : absorbing self.state g ∨ squeezing self.state g) :
    Sha3_512State.append self data
    ⦃ (r : Sha3_512State) =>
      absorbing r.state (g.append data.val self.state.squeeze_mode) ⦄ := by
  unfold Sha3_512State.append
  step*

@[step] theorem Sha3_512State.extract.spec
    (self : Sha3_512State) (output : Array U8 64#usize) (g : GhostState)
    (h : absorbing self.state g ∨ squeezing self.state g) :
    Sha3_512State.extract self output
    ⦃ (r : Sha3_512State × Array U8 64#usize) =>
      r.2.val = (extractOutput g 64).toList ∧
      absorbing r.1.state (.init g.rate g.padVal g.h_rate) ⦄ := by
  unfold Sha3_512State.extract
  step
  let* ⟨ks, output', hlen, hbytes, hpost⟩ ←
    KeccakState.extract.spec (g := g)
  have hs_len : s.length = (64#usize).val := by
    show (↑s : List U8).length = (64#usize).val
    rw [s_post1]; exact output.property
  have hlen' : (↑output' : List U8).length = (64#usize).val := by
    rw [show (↑output' : List U8).length = output'.length from rfl, hlen, hs_len]
  refine ⟨?_, ?_⟩
  · rw [s_post2, Aeneas.Std.Array.from_slice_val output output' hlen',
        hbytes, hs_len]; rfl
  · simpa using hpost

end sha3.shake1x

end symcrust
