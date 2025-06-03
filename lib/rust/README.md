# SymCRust (placeholder name)

A temporary subdirectory to experiment with rewriting bits of SymCrypt in Rust, starting with ML-KEM.
The Rust in this subdirectory is built into a static library which is intended to replace part of the
SymCrypt core static library.

Cargo is currently invoked by CMake when building with SYMCRYPT_SYMCRUST, which can in turn be invoked
by the SymCrypt build script with --symcrust

Vast majority of work in this directory is thanks to Jonathan Protzenko!


This build is a work in progress!

TODO: Hook up options for running proof and automated C extraction in this context.
Makefile and symcrust.lean are copied from experimental repo.
TODO: Invoke SymCRust cargo build from SymCrypt MSBuild
TODO: Figure out passing along cross-compilation from SymCrypt build system (CMake / MSBuild)
to SymCRust.
TODO: Add Rust build to build pipeline
TODO: Autogenerate Rust<->C FFI (probably using bindgen) - evaluate what is good approach for ensuring assumptions across the boundary (currently make some assumption about KeccakState in hash.rs) are minimized without adding needless complexity to the internal interface
TODO: Reintroduce constant time comparison/copying skipped in first translation
TODO: Ensure allocation discipline (~single allocation per API call) is maintained by new code
TODO: Ensure FIPS self-tests are invoked appropriately before first use
TODO: Remove c_for! macro workaround
TODO: Add intrinsics code guarded by dynamic CPU feature detection to NTT
TODO: Refactor to have local arrays that automatically wipe when dropped, rather than needing manual calls to wipe_slice
