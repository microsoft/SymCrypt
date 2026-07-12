/-
  System/FFI axioms — external Rust functions that cannot be verified.

  Wrapper specs for *generic* Rust fns in `src/common.rs` that downstream
  specs rely on. Type-specific trait impls (e.g.
  `BoxDefault for mlkem::key::Key`) live in `MLKEM/Axioms/BoxDefault.lean`.

  Covered:
  - Random byte generation (`common.random`) — modeled as nondeterminism
  - Heap allocation (`common.try_new_box_{zeroed,default}`) — may fail
  - CPU-feature probes (`cpu_features_present`)

  The generic memory-wiping axiom `common.wipe_slice.spec` lives in
  `Properties/Axioms/Wipe.lean`.
-/
import Symcrust.Code.Funs
import Spec.MLKEM.Spec
import Symcrust.Properties.Axioms.Wipe
import Symcrust.Properties.Axioms.Target

open Aeneas Aeneas.Std Result

namespace symcrust

namespace mlkem

/-! **Axiom for `common.random`** (random byte generation)

Fills a byte slice with random data. Per the SymCrypt convention this call
**always succeeds** — random byte generation failures in SymCrypt are treated
as catastrophic and abort the process rather than returning an error to the
caller. We axiomatise this by fixing the returned error to `NoError`.

The post preserves the slice length, pins the error tag, and exposes the
drawn content via an existential `MLKEM.RandomTape` witness: for some tape,
the returned bytes match `tape.readBytes s.length`.  This bridges the FFI
nondeterminism to the spec's `Spec.MLKEM.RandomTape` abstraction so that
top-level FC theorems (`mlkem.key_generate.spec`, `mlkem.encapsulate.spec`)
can quantify over a `tape : RandomTape` and connect to
`MLKEM.KeyGen` / `MLKEM.Encaps`.

External FFI function defined in `Code/FunsExternal.lean`. -/

@[step]
axiom random.spec (s : Slice Std.U8) :
    common.random s
    ⦃ (err : common.Error) (s' : Slice Std.U8) =>
      err = .NoError ∧
      s'.length = s.length ∧
      ∃ (tape : Spec.MLKEM.RandomTape),
        ∀ (i : ℕ) (h_i : i < s'.length),
          s'.val[i] = tape i ⦄

end mlkem

/-! ## `common.try_new_box_{zeroed,default}` — heap allocation wrappers

Both wrappers are project-level `def`s in `Code/Funs.lean` that internally
call `core.alloc.layout.Layout.new`, `alloc.alloc.alloc_zeroed`,
`core.ptr.mut_ptr.RawPtrMutT.{cast,is_null}`, and `alloc.boxed.Box.from_raw`.
The internal pointer machinery is outside the Aeneas model of Rust
(see `Code/EXTRACTION.md` — the `BoxDefault` impls fall back to `sorry`
through `&raw mut` projections on uninitialised boxes); we therefore
axiomatize the wrapper's behaviour directly.

`try_new_box_zeroed` is generic and axiomatised here; the success branch
gives only existence (`True` on `Ok`) because every call site
uses the result strictly as a write target (`Array.index_mut` followed by
overwriting writes), so the bytewise-zero initialiser is observationally
irrelevant.

`try_new_box_default` is axiomatised **per `BoxDefault` instance** in
`MLKEM/Axioms/BoxDefault.lean` (one axiom per instance);
no generic spec is provided here, since every Rust call site supplies a
specific instance and the per-instance axioms shadow any generic spec.
The `Err` branch of every box-allocation axiom is tight:
`common.try_alloc_zeroed` only ever produces
`Err common.Error.MemoryAllocationFailure` (`Code/Funs.lean:61`). -/

/-! **Spec for `symcrust::common::try_new_box_zeroed`** (generic).

Returns either a freshly heap-allocated `T` whose bytewise representation
is zero, or `Err MemoryAllocationFailure`.  The `Ok` payload carries no
Lean-level information beyond existence — the bytewise-zero invariant is
not observable through Aeneas's type-level model of `T`, and the single
call site (`Code/Funs.lean:5287`, allocating
`Array Std.U8 1568#usize`) immediately overwrites the buffer via
`Array.index_mut` + slice writes. -/

/-- **Opaque OOM witness.**  Marker proposition recording that a heap
allocation observed a null return from the system allocator.  It is
emitted on the `Err` branch of *every* box-allocation axiom
(`common.try_new_box_zeroed` here, and the per-instance
`try_new_box_default` specs in `MLKEM/Axioms/BoxDefault.lean`) so that
top-level specs can propagate a precise
`MemoryAllocationFailure ⇒ out_of_memory` postcondition rather than a
vacuous `True`. -/
axiom out_of_memory : Prop

@[step]
axiom common.try_new_box_zeroed.spec (T : Type) :
    common.try_new_box_zeroed T
    ⦃ (r : core.result.Result T common.Error) =>
        match r with
        | core.result.Result.Ok _ => True
        | core.result.Result.Err e =>
            e = common.Error.MemoryAllocationFailure ∧ out_of_memory ⦄


/-! ## CPU-feature dispatch primitives

`common.cpu_features_present` is extracted in `Code/FunsExternal.lean` as an
`axiom` returning `Result Bool`. It is a pure runtime probe of CPU capability
bits; its spec (above) models the result as `featurePresent feat` — a
deterministic function of the queried feature bit, reflecting that the feature
set is fixed for a given machine.

The per-target dispatchers in `Properties/MLKEM/Ntt/{Ntt,Intt}.lean` and the
PCLMULQDQ dispatcher in `Properties/AesGcm/GHashAppend.lean` `step` past these
calls and `cases` on the returned `Bool` to fan out to the appropriate
architectural arm. Each arm's spec must be sound regardless of which feature
flag is actually set at runtime; the dispatcher proves the same postcondition
in every arm, so the runtime-CPU-feature predicate drops out. -/

/-- Opaque but **deterministic** CPU-feature probe result.  Modelling
    `cpu_features_present` as a pure function of the feature bit (rather than an
    arbitrary `Bool`) reflects the silicon reality — the feature set is fixed for
    a given machine — and lets a key-expansion call and a later GHASH-append call
    on the same machine observe the *same* feature flag.  This correlation is
    required to soundly verify the PCLMULQDQ GHASH path, whose key table layout
    differs from the generic path (see `specPclmulTable`). -/
opaque featurePresent : Std.U32 → Bool

@[step]
axiom common.cpu_features_present.spec (feat : Std.U32) :
    common.cpu_features_present feat
    ⦃ (result : Bool) => result = featurePresent feat ⦄

/-! ## Build target (`get_target`)

`Aeneas.Std.get_target` is an Aeneas builtin returning the compilation's target
as a `Str`.  `Symcrust.Properties.Axioms.Target` defines the single
fixed-but-arbitrary target constant `theTarget` and overrides the Aeneas spec to
the deterministic post `r = theTarget`.  The multi-target extraction
(`--targets=x86_64,i686,aarch64`, see `Code/EXTRACTION.md`) bundles all three
targets' bodies behind a `get_target` dispatcher, but a Rust compilation has
exactly one (global) target, so every theorem must hold for whichever target
`theTarget` is.

Below we record the orthogonal feature↔target facts the GHASH dispatchers need. -/

/-- **PCLMULQDQ is an x86-only ISA extension.**  If the (deterministic) PCLMULQDQ
    feature is reported present, the build target is x86 (`x86_64` or `i686`).
    Contrapositive: on any non-x86 target the feature is absent. -/
axiom featurePresent_pclmulqdq_x86_only
    (h : featurePresent common.SYMCRYPT_CPU_FEATURE_PCLMULQDQ = true) :
    theTarget = toStr "x86_64-unknown-linux-gnu"
    ∨ theTarget = toStr "i686-unknown-linux-gnu"

end symcrust
