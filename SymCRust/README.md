# SymCRust (working title)

This directory contains Rust implementations of a subset of algorithms supported by SymCrypt. The
goal of re-implementing algorithms in Rust is to provide stronger memory safety and correctness
guarantees through the use of safe Rust wherever possible, combined with additional formal
verification. (It is not currently possible to fully implement all algorithms in safe Rust while
maintaining performance and side-channel safety.) 

The Rust code in this subdirectory will be used in two ways:
- Eventually we aim to have a standalone Rust crate that implements all of the modern cryptographic
  algorithms needed for common cryptographic scenarios such as TLS
- For existing SymCrypt callers or other C-based callers, the crate includes an optional Foreign
  Function Interface (FFI) which provides ABI-compatible implementations of existing SymCrypt
  functions. Thus, it can be compiled into a static library which replaces parts of the SymCrypt
  core static library.

## Building

- To run the SymCRust unit tests, `cargo test --features std`. Currently these tests rely on some
  functionality from the SymCrypt C library, so you must build that first using CMake (see
  `BUILD.md` in the parent directory), and then set the `SYMCRYPT_LIB_PATH` environment variable
  to the output directory that contains the SymCrypt static libraries.
- To run the SymCRust benchmarks, `cargo bench --features benchmarking`
- To build SymCrypt (static lib, dynamic modules, and tests) with SymCRust implementations, from
  the parent directory, invoke CMake with `-DSYMCRYPT_SYMCRUST=ON`
  (or use `build.py cmake --symcrust`)

## TODOs

This build is a work in progress!

- Hook up options for running proof and automated C extraction in this context. Makefile and
  symcrust.lean are copied from experimental repo. Try to avoid bringing in a dependency on nightly
  for verification.
- Invoke SymCRust cargo build from SymCrypt MSBuild
- Figure out passing along cross-compilation from SymCrypt build system (CMake / MSBuild) to
  SymCRust.
- Add Rust build to build pipeline
- Autogenerate Rust<->C FFI (probably using bindgen) - evaluate what is good approach for
  ensuring assumptions across the boundary (currently make some assumption about KeccakState in
  hash.rs) are minimized without adding needless complexity to the internal interface
- Refactor to have local arrays that automatically wipe when dropped, rather than needing
  manual calls to wipe_slice
- Ensure that a pure-Rust SymCRust would also wipe heap allocated buffers (currently guaranteed
  by the SymCRust global allocator which relies on the SymCrypt C code)
- Make SymCRust clean w.r.t. cargo clippy (TBD to choose the right level of pedantic)
  - Related - move away from Hungarian notation in ML-KEM source
- Port the ML-KEM CASTs to SymCRust (currently invoke the C definition of the self-tests)
- Update build.rs to parse version.json so that magic values can be set correctly
- Remove dependency on C code from tests, use KATs instead
- Make FFI optional (put it behind a feature flag)
  - Also make each algorithm have its own feature flag?
- Find a better way to express unsafety of functions that require specific CPU features. They should
  probably be marked as unsafe and annotated with `#[target_feature(...)]`, but this requires
  an additional wrapping function for anything that implements a trait interface, because trait
  functions cannot be unsafe.