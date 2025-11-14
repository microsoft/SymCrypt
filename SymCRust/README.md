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
  symcrust.lean are copied from experimental repo. Try to avoid bringing in a dependency on nightly
  for verification.
- TODO: Invoke SymCRust cargo build from SymCrypt MSBuild
- TODO: Figure out passing along cross-compilation from SymCrypt build system (CMake / MSBuild) to
  SymCRust.
- TODO: Add Rust build to build pipeline
- TODO: Autogenerate Rust<->C FFI (probably using bindgen) - evaluate what is good approach for
  ensuring assumptions across the boundary (currently make some assumption about KeccakState in
  hash.rs) are minimized without adding needless complexity to the internal interface
- TODO: Refactor to have local arrays that automatically wipe when dropped, rather than needing
  manual calls to wipe_slice
- TODO: Ensure that a pure-Rust SymCRust would also wipe heap allocated buffers (currently guaranteed
  by the SymCRust global allocator which relies on the SymCrypt C code)
- TODO: Make SymCRust clean w.r.t. cargo clippy (TBD to choose the right level of pedantic)
  - Related - move away from Hungarian notation in ML-KEM source?
- TODO: Port the ML-KEM CASTs to SymCRust (currently invoke the C definition of the self-tests)