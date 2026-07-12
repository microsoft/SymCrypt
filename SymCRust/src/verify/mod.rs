// EXPERIMENTAL CODE --- NOT YET INTEGRATED WITH SYMCRYPT
//
// Verification-only scaffolding; see `README.md` in this directory.

//! Verify-only Rust scaffolding.
//!
//! Everything under `src/verify/` is compiled exclusively under
//! `#[cfg(feature = "verify")]` and is never reachable in a production
//! build. Removing `src/verify/` from the source tree leaves
//! `cargo build` (no features) and the production cmake build
//! bit-identical to their current outputs. See `SymCRust/lean/Intrinsics/INTRINSICS.md`
//! for the methodology and the call-site convention.
//!
//! Current contents:
//!
//! * [`intrinsics`] — per-(architecture, ISA-extension) Rust transcriptions
//!   of hardware intrinsics, organised as `intrinsics::<arch>::<ext>`.
//!   Each file contains either *transcribed* shims (line-by-line of the
//!   vendor `Operation:` pseudocode) or *axiomatised* `#[verify::opaque]`
//!   stubs for irreducible cryptographic opcodes. See `SymCRust/lean/Intrinsics/INTRINSICS.md` §0.
//!
//! Future contents (placed here as they are needed):
//!
//! * Hand-rolled trait impls that replace `derive(…)` outputs Aeneas
//!   cannot translate (e.g. the `Default` workaround landed for
//!   `CSymCryptAesExpandedKey`).
//! * Verify-only blanket impls of sealed traits that satisfy const-generic
//!   where-clauses Aeneas's trait_impl_id machinery can't mint.
//! * Any other `#[verify::opaque]` stub the campaigns prove against an
//!   axiom rather than against a Rust body.
//!
//! Anything added here must remain `#[cfg(feature = "verify")]`-gated at
//! its `mod` declaration, so the "deletable" invariant of §4.3 holds.

pub mod intrinsics;
