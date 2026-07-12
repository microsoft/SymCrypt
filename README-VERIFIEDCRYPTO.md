# Verified Cryptography in Rust

This branch of SymCrypt provides formal proofs of functional correctness and panic freedom for selected Rust implementations of cryptographic algorithms. 

The Rust code is translated to [Lean](https://lean-lang.org/) using [Aeneas](https://github.com/aeneasverif/aeneas), then verified against the formalization of the corresponding FIPS/NIST/IETF standards. The included proofs can be independently re-checked using the Lean kernel. 
This leaves essentially three questions for review: 
- Is it the right formal specification?
- Is it the right set of verified properties? 
- What trust assumptions do they rely on? 

This page is the entry point to understand **what is verified** vs
reviewed, tested, or assumed; **where the code, specs and proofs live** in the source tree; and  **how to reproduce** the build, extraction, and proof check.
Implementation and methodology notes are linked from each section.

## 1. Verification at a glance.

Verification is embedded in the Rust part of SymCrypt [SymCRust/](SymCRust/):

```
SymCRust/
├── src/                   Rust code (production crate)
│   └── verify/            verification-only shims gated with #[cfg(feature = "verify")]
└── lean/                  Formal development   
    ├── Intrinsics/        Hardware-intrinsic model
    ├── Spec/              Standard specifications and auxiliary properties
    ├── SpecTests/         Specification-level test vectors
    └── Symcrust/           
        ├── Code/          Rust model (extracted by Aeneas from src/)
        └── Properties/    Rust properties and proofs
```

Verification does not affect the way Rust code is built, tested, and integrated with SymCrypt - except 
for a new verification-only Rust feature `"verify"`, used to define specific shims and tests (e.g. for
modelling intrinsics), and to exclude code currently out of scope for verification (e.g. the C FFI).
Similarly, code in `src/verify` provides Rust executable models of intrinsics, used only
for verification and differential testing. 

The full formal development in Lean 4 is re-verified in about 15' by running `lake build` in `lean/`.


## 2. What is verified on this branch. 

The table below lists the SymCrypt-Rust cryptographic primitives and pointers to files for additional details. 
Verified means that every public function is equipped with a theorem that specifies it in terms of the algorithms in the spec, 
that their proofs are complete and valid, and that the formal specification itself has been tested and reviewed against the standard.

| Primitive | Rust code | cloc | Specification | cloc | Properties and Proofs | cloc |
|---|---|---:|---|---:|---|---:|
| SHA-3 / SHAKE      | [src/sha3/](SymCRust/src/sha3/)   | 1,656 | [Spec/SHA3/](SymCRust/lean/Spec/SHA3/REPORT.md)   |   140 | [Properties/SHA3/](SymCRust/lean/Symcrust/Properties/SHA3/VERIFIED.md)   | 15,211 |
| ML-KEM             | [src/mlkem/](SymCRust/src/mlkem/) | 2,125 | [Spec/MLKEM/](SymCRust/lean/Spec/MLKEM/REPORT.md) |   308 | [Properties/MLKEM/](SymCRust/lean/Symcrust/Properties/MLKEM/VERIFIED.md) | 37,989 |
| Intrinsics         | [src/verify/intrinsics/](SymCRust/src/verify/intrinsics/) | 1,748 | [Intrinsics/Axioms/](SymCRust/lean/Intrinsics/Axioms/) | 329 | [Intrinsics/Properties/](SymCRust/lean/Intrinsics/Properties/) | 5,177 |

LOC convention: every column reports `cloc`'s line count
(non-comment, non-blank source lines) recomputed via `SymCRust/lean/scripts/loc-verifiedcrypto.sh`.
**Rust** excludes `tests.rs` / `test.rs`. **Spec** counts only the
normative portion of the specification, excluding lemmas, examples, notations, and tests.
Infrastructure not attributed to any single primitive adds another ~1.3 kLoC of Lean.
The **Intrinsics** row is the shared hardware-intrinsic model: its *Specification* is the
trusted silicon semantics (`Intrinsics/Axioms/`, transcribed from vendor documentation — see
[INTRINSICS.md](SymCRust/lean/Intrinsics/INTRINSICS.md)), whereas its *Properties and Proofs* establish 
that their documented semantics match the executable semantics of their Rust models. 

Additional documents:

- [Code/EXTRACTION.md](SymCRust/lean/Symcrust/Code/EXTRACTION.md) records the provenance of `Code/` via AENEAS extraction: toolchain pins, make targets, post-extraction edits.
- [SymCRust/lean/Intrinsics/INTRINSICS.md](SymCRust/lean/Intrinsics/INTRINSICS.md) details our modelling of hardware intrinsics using Rust and Lean.


## 3. Trust assumptions 

Formal theorems apply only in a model of the Rust code and the system that uses it. We summarize below the main trust assumptions this entails. 

- We trust the Rust toolchain, notably its compiler and its platform-specific back-ends for x86\_64 (including SSE2/AVX2) and AArch64 (including NEON). We also trust that code that uses our verified code is safe and complies with its pre-conditions. 

- We trust the Charon/Aeneas toolchain correctly extracts code from Rust to Lean, and the soundness of its axiomatization of the Rust standard library.

- We trust the runtime platform meets the toolchain's expectations. We verify safety, panic-freedom, and functional correctness but not leakage resistance. We independently mitigate microarchitectural side channels by writing Rust code in defensive "constant-time" style.
  
- We trust the soundness of the Lean kernel that validates all proofs in our formal developments, as well as native tactics such as `bv_decide`.

- We trust our model of Intrinsics, a combination of Rust models and Lean axioms carefully aligned to reference documents from hardware vendors. See [SymCRust/lean/Intrinsics/INTRINSICS.md](SymCRust/lean/Intrinsics/INTRINSICS.md) for details.

For each algorithm, as detailed in `Properties/{Algorithm}/VERIFIED.md`:

- We trust the formal specification accurately captures the standard. To facilitate human review, 
we strive to keep the two aligned (symbol-by-symbol, line-by-line for pseudocode) and we 
test the specification itself by executing it within Lean on standard test vectors.

- We trust the verified pre- and post-conditions of its public interface capture the intended functional behaviour. Similarly, this can be reviewed by Lean theorem inspection.

Conversely, we need not review the bulk of the Lean proofs and additional lower-level helpers, properties and specs attached to the code (intermediate pre- and post-conditions, loop invariants, range hypotheses, etc)
since they are systematically checked by Lean. This enables us to delegate proof work to agents without trusting the AI machinery.

## 4. Building and reproducing

### Prerequisites and tools for reproducing extraction and proof-checking

| Component | Tool / install | Pinned version we used |
|---|---|---|
| SymCrypt (this branch)  |               | `src/` and `lean/Symcrust/Code/` (produced by `make extract`) are committed together. |
| Rust toolchain          | [rust-lang.org](https://www.rust-lang.org/) · install via [`rustup`](https://rustup.rs/)                                                                            | the project [`SymCRust/rust-toolchain.toml`](SymCRust/rust-toolchain.toml) pins the public `nightly-2026-06-01` (the `verify` feature is nightly-only). Proof-checking (`lake build`) needs no Rust toolchain. |
| Lean 4                  | [leanprover.github.io](https://leanprover.github.io/) · install via [`elan`](https://leanprover-community.github.io/get_started.html)                               | `v4.31.0` ([`SymCRust/lean/lean-toolchain`](SymCRust/lean/lean-toolchain)) |
| Aeneas                  | [github.com/AeneasVerif/aeneas](https://github.com/AeneasVerif/aeneas) · [install](https://github.com/AeneasVerif/aeneas#installation--build)                       | [`d71d2e3f`](https://github.com/AeneasVerif/aeneas/commit/d71d2e3f2cb763f7faf15ab606ac9cf32da8dead) |
| Charon                  | [github.com/AeneasVerif/charon](https://github.com/AeneasVerif/charon) · [install](https://github.com/AeneasVerif/charon#installation--build)                       | [`5a501733`](https://github.com/AeneasVerif/charon/commit/5a5017333554ec1e95cae3c4fe05f5bd90b44487) (pinned in the Aeneas `charon-pin`) |

Aeneas should be checked out adjacent to this SymCrypt repository, and Charon is typically checked out within Aeneas (see Aeneas README).

Since the Aeneas-extracted `Code/` is committed, 
reviewing and checking the Lean development only requires [Lean 4](https://leanprover-community.github.io/get_started.html),
and a checked out copy of the Aeneas repository (not full installation).

The [Lean 4 VS Code extension](https://github.com/leanprover/vscode-lean4)
(and similarly the Lean 4 mode for Emacs and the JetBrains plugin).
provides interactive goal display, hover
information on tactics and definitions, and on-the-fly proof checking,
which is the recommended way to walk through theorem statements and
proofs.

Re-running the Aeneas extraction additionally requires
an Aeneas + Charon install. See
[Aeneas installation instructions](https://github.com/AeneasVerif/aeneas#installation--build).

### Build steps

```bash
# (0) Proof-only audit — replays the committed Lean proofs against the
#     committed `Code/`. Requires Lean 4 / elan only.
cd SymCRust/lean
# optional one-time step
lake exe cache get
lake build Symcrust

# (1) Aeneas extraction  (overwrites lean/Symcrust/Code/).
cd SymCRust
make extract                         # SHA-3 + ML-KEM (incl. SIMD intrinsics)

# (2) Rebuild the Lean proofs against the freshly-extracted Code/.
cd lean
lake build Symcrust
```

### Running the Lean  spec on test vectors 

```bash
cd SymCRust/lean

# (3) Run the spec on test vectors
lake exe mlKemTests                  # ML-KEM-512 / 768 / 1024 (CAVP / ACVP)
# Analogous runners are defined alongside each verified Spec/ directory
```

### Inspecting the top-level theorems

```bash
# (4) Inspect the trust footprint of a verified top-level theorem, e.g.
lake env lean -e '
  import Symcrust.Properties.MLKEM
  open Symcrust.Properties.MLKEM
  #print axioms mlkem.encapsulate.spec
  #print axioms mlkem.decapsulate.spec
  #print axioms mlkem.key_generate.spec
'
```
