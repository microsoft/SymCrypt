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
  to the output directory that contains the SymCrypt static libraries. If you want to run the
  AES tests as well, also pass `--features aes` (e.g. `cargo test --features aes,std`).
- To run the SymCRust benchmarks, `cargo bench --features benchmarking`
- To build SymCrypt (static lib, dynamic modules, and tests) with SymCRust implementations,
  from the parent directory, invoke CMake with `-DSYMCRUST_CONFIG=<config>` (msbuild:
  `/p:SymCRustConfig=<config>`), or use `build.py` with the `--symcrust-config <config>` option. `<config>`
  is one of:
  - `Off` (default): use the C implementations.
  - `Public`: build SymCRust with the public Rust toolchain and default cargo config.
  - `MSRust`: build SymCRust with the Microsoft internal Rust toolchain and cargo config.

## Cargo features

| Feature | Default | Description |
| --- | --- | --- |
| `std` | off | Link against `std`. Required for running unit tests and for some benchmarking paths. |
| `kernel` | off | Enable stubs required for linking to Windows kernel-mode components. |
| `benchmarking` | off | Mock out external dependencies for pure-Rust criterion benchmarks; implies `std`. |
| `aes` | off | Enable AES implementations. **x86_64 and aarch64 only**. |
| `ffi` | off | Enable FFI functions. Currently only applies to AES. |

## TODOs

This build is a work in progress!

- Hook up options for running proof and automated C extraction in this context. Makefile and
  symcrust.lean are copied from experimental repo. Try to avoid bringing in a dependency on nightly
  for verification.
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
- Extend the per-algorithm feature gating to SHA-3 and ML-KEM (currently only AES is gated by the
  `aes`/`ffi` features).
- Find a better way to express unsafety of functions that require specific CPU features. They should
  probably be marked as unsafe and annotated with `#[target_feature(...)]`, but this requires
  an additional wrapping function for anything that implements a trait interface, because trait
  functions cannot be unsafe.
- Fully enable AES-GCM in hybrid C+Rust builds (wire `SYMCRUST_AES_GCM` on the C side to suppress
  the C definitions, then enable the `aes,ffi` Cargo features in the SymCRust CI build).
- Enable SymCrust for non AMD64.
- Update `symcrypt_build_property` in `build-windows-undocked.yml` to be more deterministic like `build-azl.yml`. 
- Determine a way to configure what algos are being built with C/Rust from build time.
- Determine a better way to turn on/off rust files rather than adding/removing from `vcxproj`.
- Determine impact on external users with the new dependency on `ms-prod`.