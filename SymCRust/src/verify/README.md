# `src/verify/` — Verification-only scaffolding

**Everything in this directory is compiled exclusively under
`#[cfg(feature = "verify")]` and is never reachable in a production build.**

Removing this directory from the source tree leaves `cargo build` (no
features) and the production cmake build *bit-identical* to their current
outputs. The verification track relies on this "deletable" invariant — see
[`../../../README-VERIFIEDCRYPTO.md`](../../../README-VERIFIEDCRYPTO.md) and
the methodology in `../../lean/Intrinsics/INTRINSICS.md`.

## Why a separate directory?

The `SymCRust` crate is a port of SymCrypt's C cryptographic code to
Rust, intended to be Aeneas-extractable to Lean for functional-correctness
proofs. Some pieces the Rust compiler / linker need at build time cannot
be modelled by Aeneas as written:

* Hardware **intrinsics** (`std::arch::x86_64::*`, `core::arch::aarch64::*`)
  are opaque to Aeneas. We provide either *transcribed* shims (line-by-line
  of the vendor `Operation:` pseudocode) or *axiomatised* `#[verify::opaque]`
  stubs that the verifier links against an axiom rather than a Rust body.
* `derive(...)` outputs that Aeneas's trait-elaborator cannot translate
  (e.g. the `Default` workaround landed for `CSymCryptAesExpandedKey`).
* Verify-only blanket impls of sealed traits that satisfy const-generic
  where-clauses Aeneas's `trait_impl_id` machinery can't mint.

Putting these in `src/verify/` keeps the production build path free of
verification artefacts and keeps the "delete this directory → identical
non-verify build" invariant easy to audit.

## Current contents

| Path | Purpose |
|---|---|
| `mod.rs` | Module root (`#[cfg(feature = "verify")]` at the `mod` declaration in `lib.rs`). |
| `intrinsics/` | Per-`(architecture, ISA-extension)` Rust transcriptions of hardware intrinsics, organised as `intrinsics::<arch>::<ext>`. See `../../lean/Intrinsics/INTRINSICS.md`. |

## Invariants

1. **Gated at the `mod` boundary.** Every `mod` declaration that pulls
   anything from `src/verify/` lives under `#[cfg(feature = "verify")]` so
   it disappears entirely from non-verify builds.
2. **No production code may `use` anything from `crate::verify::*`.** If
   a production-path module needs symbols that also exist here, the
   intrinsic file in `crate::verify::intrinsics::...` shadows the
   production one only under `feature = "verify"`; the call site does not
   change.
3. **Adding files here must preserve invariant 1 + 2.** Anything else
   belongs outside `src/verify/`.

## See also

* [`../../../README-VERIFIEDCRYPTO.md`](../../../README-VERIFIEDCRYPTO.md) — top-level explanation of the
  verification track and its divergences from `feature/verifiedcrypto`.
* `../../lean/Intrinsics/INTRINSICS.md` — methodology and the per-intrinsic
  transcription / axiomatisation convention.
* `lean/Symcrust/` — the Aeneas-extracted Lean code and proofs that
  consume this scaffolding.
