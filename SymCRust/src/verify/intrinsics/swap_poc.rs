// Reference proof-of-concept for the cfg-gated `use`-swap intrinsic style.
//
// This file is INERT: it is intentionally not declared as a module (no
// `pub mod swap_poc;` anywhere), so it is never compiled into either the
// production or the verify build. It is kept here, next to the intrinsic
// shims it exercises, as the canonical worked example of the redirection
// pattern that `src/sha2/sha2_impl.rs` now uses for the real SHA-NI path.
//
// The pattern in one sentence: write each function body ONCE over a neutral
// register type and a flat set of named ops, then bind those names with two
// cfg-gated `use` blocks --- production binds them to the real silicon types
// and intrinsics; verify binds them to the modelled lane-array shims in this
// `intrinsics` subsystem. Charon/Aeneas only ever see the verify arm, where
// every name resolves to a concrete Rust shim, so the body extracts as
// ordinary Lean with no opaque casts.
//
// The three sections below build the idea up incrementally:
//   1. `poc_add_epi32`   --- single-op redirect (one register type, one op).
//   2. `poc_add_lanes`   --- callee-side concrete<->register round-trip.
//   3. `poc_multiview`   --- the SHA-NI shape: two lane-views (dword + byte)
//                            on ONE register, reconciled entirely inside the
//                            verify shims via a single canonical carrier.

// Production: the real silicon register type + intrinsic.
#[cfg(all(target_arch = "x86_64", not(feature = "verify")))]
use core::arch::x86_64::{__m128i, _mm_add_epi32};

// Verify: `__m128i` becomes a concrete lane array and `_mm_add_epi32`
// becomes the modelled shim. Both facts stay internal to `src/verify`.
#[cfg(feature = "verify")]
use crate::verify::intrinsics::x86_64::sha::{add_epi32 as _mm_add_epi32, Dwords as __m128i};

/// ONE body, identical in both builds: "just call the intrinsic".
#[cfg(any(all(target_arch = "x86_64", not(feature = "verify")), feature = "verify"))]
#[inline]
pub fn poc_add_epi32(a: __m128i, b: __m128i) -> __m128i {
    // Production: `_mm_add_epi32` is `unsafe`. Verify: the shim is safe,
    // so the `unsafe` block is redundant there (hence `allow`).
    #[allow(unused_unsafe)]
    unsafe {
        _mm_add_epi32(a, b)
    }
}

// ---------------------------------------------------------------------------
// Callee-side concrete-type round-trip.
//
// Confirms (purely in Rust) that the register type can be converted BACK to
// a concrete Rust type at the boundary. The two `#[cfg]` arms of each
// converter are the only thing that differs:
//   * production: `__m128i` is opaque -> use a register intrinsic to
//     pack/unpack concrete lanes (`_mm_loadu_si128` / `_mm_storeu_si128`).
//   * verify: `__m128i` IS `Dwords = [u32; 4]`, so the conversion is the
//     identity -- concrete Rust types all the way down.
// ---------------------------------------------------------------------------

/// Pack 4 concrete u32 lanes into the register type.
#[cfg(all(target_arch = "x86_64", not(feature = "verify")))]
#[inline]
fn from_lanes(lanes: [u32; 4]) -> __m128i {
    unsafe { core::arch::x86_64::_mm_loadu_si128(lanes.as_ptr() as *const __m128i) }
}
#[cfg(feature = "verify")]
#[inline]
fn from_lanes(lanes: [u32; 4]) -> __m128i {
    // `__m128i == Dwords == [u32; 4]`: concrete type, identity conversion.
    lanes
}

/// Unpack the register type back into 4 concrete u32 lanes.
#[cfg(all(target_arch = "x86_64", not(feature = "verify")))]
#[inline]
fn to_lanes(v: __m128i) -> [u32; 4] {
    let mut out = [0u32; 4];
    unsafe { core::arch::x86_64::_mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, v) };
    out
}
#[cfg(feature = "verify")]
#[inline]
fn to_lanes(v: __m128i) -> [u32; 4] {
    // Identity: the register value already IS the concrete lane array.
    v
}

/// End-to-end: concrete in -> register-typed add -> concrete out.
/// The body is identical in both builds; only `from_lanes`/`to_lanes`
/// differ, and the difference is confined to those callee-side converters.
#[cfg(any(all(target_arch = "x86_64", not(feature = "verify")), feature = "verify"))]
#[inline]
pub fn poc_add_lanes(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    let va = from_lanes(a);
    let vb = from_lanes(b);
    let vr = poc_add_epi32(va, vb);
    to_lanes(vr)
}

// ===========================================================================
// MULTI-VIEW PoC: one opaque register, two different lane-views in one body.
//
// This is the SHA-NI shape that a *single-type-alias* swap cannot express:
// production mixes a dword-view op (`_mm_add_epi32`) and a byte-view op
// (`_mm_shuffle_epi8`) on the SAME `__m128i`, with no conversions (the
// silicon register needs none).
//
// The fix lives ENTIRELY behind `src/verify`: give `__m128i` ONE canonical
// carrier (`Bytes = [u8; 16]`) and let each shim reinterpret to the view it
// needs *internally* via the minimalist `bytes_to_dwords`/`dwords_to_bytes`
// converters. Both ops then present the uniform signature `Bytes -> Bytes`,
// so the driver body still "just calls the intrinsic" with zero call-site
// conversions and stays byte-identical to production.
// ===========================================================================

/// Verify-only uniform-carrier shim layer. Every wrapper takes/returns the
/// single canonical carrier `Bytes`; the lane-view choice is a private
/// implementation detail of each wrapper.
#[cfg(feature = "verify")]
mod mv {
    use crate::verify::intrinsics::lanes::{bytes_to_dwords, dwords_to_bytes, Bytes};
    use crate::verify::intrinsics::x86_64::{sse2, ssse3};

    /// Canonical carrier for `__m128i` in the verify model.
    pub type M128 = Bytes;

    /// Dword-view op behind a `Bytes -> Bytes` face: reinterpret in, run the
    /// existing `Dwords`-typed shim, reinterpret out.
    #[inline]
    pub fn add_epi32(a: M128, b: M128) -> M128 {
        dwords_to_bytes(sse2::add_epi32(bytes_to_dwords(a), bytes_to_dwords(b)))
    }

    /// Byte-view op: already operates on `Bytes`, so no conversion needed.
    #[inline]
    pub fn shuffle_epi8(a: M128, mask: M128) -> M128 {
        ssse3::shuffle_epi8(a, mask)
    }
}

// Production: real silicon types/intrinsics, `__m128i` fully opaque.
#[cfg(all(target_arch = "x86_64", not(feature = "verify")))]
use core::arch::x86_64::{_mm_add_epi32 as _mv_add, _mm_shuffle_epi8 as _mv_shuf};

// Verify: both names resolve to uniform `Bytes -> Bytes` shims; `__m128i`
// is the single canonical carrier. The redirect is invisible to the body.
#[cfg(feature = "verify")]
use mv::{add_epi32 as _mv_add, shuffle_epi8 as _mv_shuf, M128 as _Mv128};

// In production, `__m128i` is already in scope from the first `use` block
// above; in verify, alias the carrier to the same spelling locally.
#[cfg(feature = "verify")]
type _Mv = _Mv128;
#[cfg(all(target_arch = "x86_64", not(feature = "verify")))]
type _Mv = __m128i;

/// ONE body, identical in both builds, mixing two lane-views on one
/// register: dword-view add, then byte-view shuffle of the result.
#[cfg(any(all(target_arch = "x86_64", not(feature = "verify")), feature = "verify"))]
#[inline]
pub fn poc_multiview(a: _Mv, b: _Mv, mask: _Mv) -> _Mv {
    #[allow(unused_unsafe)]
    unsafe {
        let s = _mv_add(a, b); // dword view of the register
        _mv_shuf(s, mask) // byte view of the SAME register
    }
}
