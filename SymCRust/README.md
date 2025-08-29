# SymCRust (working title)

A temporary subdirectory to experiment with rewriting bits of SymCrypt in Rust, starting with
ML-KEM. The Rust in this subdirectory is built into a static library which is intended to replace
part of the SymCrypt core static library.

Vast majority of work in this directory is thanks to Jonathan Protzenko!

## Building

- To run the SymCRust unit tests, `cargo test --features std`. Currently these tests rely on some
  functionality from the SymCrypt C library, so you must build that first using CMake (see
  `BUILD.md` in the parent directory), and then set the `SYMCRYPT_LIB_PATH` environment variable
  to the output directory that contains the SymCrypt static libraries.
- To run the SymCRust benchmarks, `cargo bench --features benchmarking`
- To build SymCrypt (static lib, dynamic modules, and tests) with SymCRust implementations, from the parent directory, invoke
  CMake with `-DSYMCRYPT_SYMCRUST=ON` (or use `build.py cmake --symcrust`)

## TODOs

This build is a work in progress!

- TODO: Hook up options for running proof and automated C extraction in this context. Makefile and
  symcrust.lean are copied from experimental repo.
- TODO: Invoke SymCRust cargo build from SymCrypt MSBuild
- TODO: Figure out passing along cross-compilation from SymCrypt build system (CMake / MSBuild) to
  SymCRust.
- TODO: Add Rust build to build pipeline
- TODO: Autogenerate Rust<->C FFI (probably using bindgen) - evaluate what is good approach for
  ensuring assumptions across the boundary (currently make some assumption about KeccakState in
  hash.rs) are minimized without adding needless complexity to the internal interface
- TODO: Reintroduce constant time comparison/copying skipped in first translation
- TODO: Ensure allocation discipline (~single allocation per API call) is maintained by new code
- TODO: Ensure FIPS self-tests are invoked appropriately before first use
- TODO: Remove c_for! macro workaround
- TODO: Add intrinsics code guarded by dynamic CPU feature detection to NTT
- TODO: Refactor to have local arrays that automatically wipe when dropped, rather than needing
  manual calls to wipe_slice
