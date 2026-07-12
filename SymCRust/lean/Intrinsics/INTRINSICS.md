# Modelling Hardware Intrinsics

> SymCRust models hardware intrinsics (SSE2, SSSE3, AVX, AVX2, AES-NI,
> PCLMULQDQ on x86_64; NEON, AES on aarch64) for verification, combining
> Rust models and Lean axioms aligned to vendor documentation. See
> [`README-VERIFIEDCRYPTO.md`](../../../README-VERIFIEDCRYPTO.md) for the
> verification landing page.

---

## 1. Methodology 

- **P1. Two layers: intrinsic vs algorithm.**
  Intrinsic semantics and their use in algorithms live in distinct
  proof layers. The intrinsic layer provides general-purpose hardware-level
  models; the algorithm layer builds and verifies composite gadgets that
  depend on specific constants and requirements.

- **P2. Redirect to `src/verify`.** 
  We rely on Cargo-feature-gated (`#[cfg(feature = "verify")]`) Rust
  code in `src/verify/` to provide verification-facing intrinsic
  definitions. Without `verify`, `cargo build` is bit-identical to a tree
  with `src/verify/` removed.

  Redirect works by keeping the algorithm body and helper structure
  unchanged, while swapping only the intrinsics they call. 
  In normal builds, names resolve to architecture-specific production
  intrinsics; in verify builds, the same names resolve to
  `crate::verify::intrinsics` shims. The goal is to
  minimize changes to production code. 
  
- **P3. Rust Model or Lean Axiom, one of two.** For each intrinsic,
  we choose either a Rust model (preferred) or an explicit Lean axiom
  (exception). Axiomatisation is a deliberate trust decision used when
  the formal spec is clearer and smaller than a faithful Rust model.

- **P4. Axioms are formally stated in `lean/Intrinsics/Axioms/**`**, 
  and limited to intrinsics that cannot be transcribed to safe Rust: 
  *unsafe* intrinsics that operate on raw memory pointers, and 
  cryptographic accelerators (AES round + key-schedule, SHA-2 round 
  + msg-schedule, PCLMULQDQ, Armv8 AES counterparts). On the Rust side,
  these are represented as `#[verify::opaque]` declarations in
  `src/verify/`, with semantics given by corresponding Lean `[step]` axioms.

- **P5. Theorems about Rust models are stated and proved in `lean/Intrinsics/Properties/**`**,
  because those files prove the executable Rust shim against the extracted
  Rust body: when a vendor operation can be transcribed, the result should
  be a theorem, not another trust commitment. In this path, the
  `src/verify/` model shim is extracted by Aeneas and discharged by a Lean
  `[step]` theorem in `lean/Intrinsics/Properties/**`.

- **P6. Citation, not assertion.** Every `axiom` carries an inline
  reference to the specific FIPS § / Intel SDM § / Arm ARM ¶ that
  defines its behaviour. The trust ledger is grep-able and
  human-auditable. (§1 P6)

- **P7. Differential tests = reproducible empirical evidence.** Rust
  shims are cross-checked against the real hardware intrinsic
  (`shim(x) == core::arch::<arch>::<intrinsic>(x)` on SDM-branch-covering
  inputs, or a NIST KAT row for axiomatised crypto opcodes) by the
  harnesses under `src/verify/tests/`.

---

## 2. Hardware Architectures and Features

This section maps architecture/feature paths to their
intrinsic verification artifacts in Rust and Lean. 

Consider for example the AVX2 code in ML-KEM: 
the Rust fast path in
`src/mlkem/ntt_avx2.rs` maps to composition proofs in
`lean/Symcrust/Properties/MLKEM/Intrinsics/X86_64/Avx2Layer{Ntt,Intt}.lean`,
which build on intrinsic facts from
`lean/Intrinsics/Properties/X86_64/*.lean`. In that path, the arithmetic
intrinsics such as `_mm256_add_epi16` and the register load/store edges
such as `_mm256_loadu_si256` and `_mm256_storeu_si256` are all
theorem-backed against the byte-level register model in `Simd.lean`, so
the shipped ML-KEM path introduces no hardware trust-boundary axioms.

Across the codebase, architecture and feature selection is a mix of
compile-time and run-time checks. Compile-time gates such as
`cfg(target_arch = ...)` and `#[target_feature(enable = ...)]` determine
which intrinsic implementations exist in a given build; run-time CPU
feature tests then choose between those implementations and scalar
fallbacks. The `Intrinsics` Lean tree follows that same partition.

For example, SSSE3 is represented by `Properties/X86_64/Ssse3.lean`,
which covers intrinsics such as `_mm_alignr_epi8` and `_mm_shuffle_epi8`
as proved facts. A feature keeps a sibling `Axioms/` file only when it
still rests on an irreducible hardware axiom (for example
`Axioms/X86_64/Aes.lean`). Shared support files sit alongside the
per-feature files: common x86_64 facts live in `X86_64/Common.lean`, and
the arch-generic byte-level register model lives in `Simd.lean` and
`Bytes.lean` (with bitvector realisation in `BVRealize.lean`).

The snapshot below lists, per feature, the number of trust-boundary
**axioms** (`Intrinsics/Axioms/**`, plus the three SHA-NI opcodes declared
inline in `Symcrust/Code/FunsExternal.lean`) and whether the feature is in
the trust base of the two primitives verified in this release (SHA-3,
ML-KEM).

| Arch | Feature | Axioms | Consumers | In SHA-3/ML-KEM base? |
|---|---|---:|---|:--:|
| x86_64 | SSE2 | 0 | ML-KEM, (SHA-2, AES, GHASH) | ✅ |
| x86_64 | AVX | 0 | ML-KEM | ✅ |
| x86_64 | AVX2 | 0 | SHA-3, ML-KEM | ✅ |
| x86_64 | SSSE3 | 0 | (SHA-2, AES, GHASH) |  |
| x86_64 | AES-NI | 6 | (AES) |  |
| x86_64 | SHA-NI | 3 | (SHA-2) |  |
| x86_64 | PCLMULQDQ | 2 | (AES, GHASH) |  |
| aarch64 | NEON | 0 | ML-KEM, (AES) | ✅ |
| aarch64 | AES | 4 | (AES) |  |
| *(any)* | AES round/key-schedule model (`Axioms/Aes.lean`) | 8 | (AES) |  |

(Parenthesised consumers are primitives not shipped in this release.)

### Scope: broad hardware support vs. the SHA-3 / ML-KEM subset

The `Intrinsics` layer is a **general-purpose** hardware-intrinsic model
for SymCrypt-Rust cryptography, covering SSE2, SSSE3, AVX, AVX2, AES-NI,
SHA-NI and PCLMULQDQ on x86_64, and NEON and the AES extension on
aarch64. It is extracted **in full**: `make extract` seeds `crate::verify`
as a whole, so every model in `src/verify/intrinsics/**` and every axiom
in `Intrinsics/Axioms/**` is present in the shipped Lean tree regardless
of which algorithm consumes it. This keeps the layer reusable across
primitives (AES, AES-GCM, SHA-2, …), several of which are staged in the
tree but are **not part of this release** (see
[`README-VERIFIEDCRYPTO.md`](../../../README-VERIFIEDCRYPTO.md) §2).

The two primitives verified in this release use only the features marked
✅ above, and — as the axiom column shows — none of those features
contributes a hardware-intrinsic axiom: the load/store and lane
operations on the shipped SSE2, AVX, AVX2 and NEON paths are all
theorem-backed against the byte-level register model. Every remaining
axiom in the table belongs to a primitive not shipped in this release.
