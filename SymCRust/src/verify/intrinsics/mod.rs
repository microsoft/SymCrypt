//! Per-architecture intrinsic transcriptions / axiomatic stubs.
//!
//! Layout (one file per `(target_arch, target_feature)` pair):
//!
//! ```text
//! intrinsics/
//! ├── x86_64/
//! │   ├── sse2.rs     ssse3.rs    aes.rs    sha.rs    avx2.rs
//! └── aarch64/
//!     ├── neon.rs     aes.rs      sha2.rs
//! ```
//!
//! See `SymCRust/lean/Intrinsics/INTRINSICS.md` for the methodology, naming convention,
//! validation pipeline, and trust ledger.
//!
//! `lanes` holds bit-width type aliases and little-endian byte/lane
//! bitcast helpers shared across both arch families and across SSE/AVX/
//! NEON/AES extensions. `lanewise` provides the lane-wise scalar
//! primitives (bitwise, wrapping arithmetic, mask comparisons) that the
//! actual shim bodies thread through. Both modules are intentionally
//! declared at the top level (rather than under `x86_64`) so a single
//! set of step theorems covers both Intel and Armv8.

pub mod lanes;
pub mod lanewise;

// Architecture-neutral byte-carrier primitives shared by both ISAs (declared at
// the top level, like `lanes`/`lanewise`, so one set of step specs covers both
// Intel and Armv8): `aes` = the keyless AES transforms (`imc`,
// `subbytes_shiftrows`) the x86 and Armv8 AES shims both reduce to. (16-byte
// block load/store is just the identity on the byte carrier, so the AES drivers
// model `loadu_block`/`storeu_block` inline rather than via a shared op.)
pub mod aes;

pub mod x86_64;

pub mod aarch64;
