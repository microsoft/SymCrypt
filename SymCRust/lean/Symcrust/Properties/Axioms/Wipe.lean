/-
  Wipe.lean — Secure-memory-wiping axioms.

  The Rust function `verify::common::wipe_slice<T>` (`src/verify/common.rs`)
  zeros every element of a slice via a generic `memset`-style loop.  We
  axiomatise this with a single generic `@[step]` spec; downstream consumers
  at concrete element types (`U8`, `U16`, `U32`, ...) match the same step
  by typeclass synthesis of `[Inhabited T]`.  The per-width forms are
  subsumed because `(default : UScalar ty) = (0 : UScalar ty)` is `rfl`
  (Aeneas' `Inhabited (UScalar ty)` is `UScalar.ofNat 0 _`).
-/
import Symcrust.Code.Funs

open Aeneas Aeneas.Std

namespace symcrust

/-- **Axiom for `common.wipe_slice`**

Zeros every element of the slice.  This wraps an external `memset(ptr, 0, len)`
call used for secure memory wiping.  The result has the same length as the input
and every element equals `default` (which is `0` for Aeneas unsigned scalars).

External Rust function declared in `Code/FunsExternal.lean`;
the in-Rust shim's verify-only body iterates writing `T::default()` to each element,
matching this postcondition. -/
@[step]
axiom common.wipe_slice.spec {T : Type} [Inhabited T] (s : Slice T) :
    common.wipe_slice s
    ⦃ (s' : Slice T) =>
      s'.length = s.length ∧
      ∀ i, (h : i < s'.length) → s'[i] = (default : T) ⦄

end symcrust
