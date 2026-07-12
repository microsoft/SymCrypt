import Lake
open Lake DSL

require aeneas from "../../../aeneas/backends/lean"

package «symcrust»

/-! ## Specifications library

    `Spec` collects the FIPS / NIST specifications and supporting
    pure-math properties for the primitives shipped in this branch:
    SHA-3 family (FIPS 202) and ML-KEM (FIPS 203). Built as a
    separate root namespace so the file layout
    (`lean/Spec/<Primitive>/...`) mirrors the conceptual layer
    (audited spec vs. proof) and so reviewers can build just the specs
    via `lake build Spec`. -/
lean_lib «Spec»

/-! ## Default-built library

    `Symcrust` is the active Spec + Properties proof closure, hand-curated by
    `Symcrust.lean` → `Spec.lean` + `Symcrust/Properties.lean`. Must compile
    clean (no errors, no `sorry`s). -/

@[default_target]
lean_lib «Symcrust»

/-! ## Per-primitive convenience aliases

    Each is rooted on a top-level `<Name>.lean` file that re-exports just one
    primitive's Spec + Properties closure. Useful for fast iteration:
    `lake build MLKEM` builds the ML-KEM closure without touching SHA-3
    proofs. These aliases are subsets of `Symcrust` and so don't add
    compilations to the default `lake build` (Lake deduplicates by module). -/

lean_lib «MLKEM»
lean_lib «SHA3»

/-- Verified models of hardware intrinsics. Layered strictly above `Aeneas.*`
    and `Symcrust.Code.*`. Used by SHA-3 and ML-KEM (NTT SIMD fast paths).
    `globs` keeps all files in scope so they don't bit-rot. -/
@[default_target]
lean_lib «Intrinsics» where
  globs := #[.andSubmodules `Intrinsics]

/-! ## Spec test vectors

    `SpecTests` runs the audited specifications on standard test vectors
    (CAVP / ACVP). Not part of the default `lake build` closure; build with
    `lake build SpecTests`. The SHA-3 vectors are `#guard`s checked at
    `lake build SpecTests` time; the ML-KEM CAVP/ACVP runner is the
    `mlKemTests` executable below (`lake exe mlKemTests`). Trimmed to the
    SHA-3 + ML-KEM scope of this branch. -/
lean_lib «SpecTests» where
  globs := #[.andSubmodules `SpecTests]

lean_exe mlKemTests where
  root := `SpecTests.MLKEM.TestVectors
