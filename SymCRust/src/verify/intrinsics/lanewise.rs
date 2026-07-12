//! Lane-wise primitives shared across the architecture-specific intrinsic
//! shim files (`x86_64/{sse2,avx2,...}` and `aarch64/neon`).
//!
//! Every helper in this module is:
//!
//! 1. **Monomorphic over `T`** (one helper per `(op, lane-width)` pair).
//!    No traits, no `fn`-pointer arguments, no `Fn` generics — Aeneas
//!    extracts each helper to a single Lean definition.
//! 2. **Const-generic over `N`** (the number of lanes). The same body
//!    serves a `[u8; 16]` (SSE2) and a `[u8; 32]` (AVX2) call. Phase 4
//!    proves the helper once against a Lean spec parameterised by `N`,
//!    then `simp` instantiates at each call site.
//! 3. **Loop shape**: `while i < N { ...; i += 1 }`. This is the same
//!    shape used by all ML-KEM inner loops; the Aeneas-extracted Lean
//!    body matches the spec by `progress`-style induction.
//!
//! ### Why a shared module
//!
//! Before this file existed, each of `_mm_xor_si128`, `_mm256_xor_si256`,
//! and `veorq_u8` had its own copy of the lane-wise XOR loop. They are
//! all instances of the same `[u8; N] → [u8; N] → [u8; N]` lane-wise
//! operation; the shim should just thread the call through. Migration is
//! tracked in `SymCRust/lean/Intrinsics/INTRINSICS.md`.
//!
//! ### Operations covered (post-M2 audit)
//!
//! * **Bitwise** (view-agnostic, but typed for each lane width that
//!   actually appears as input):
//!   `lanewise_{and,or,xor,andnot}_u8`, `lanewise_and_u16`.
//! * **Wrapping arithmetic**:
//!   `lanewise_wrapping_{add,sub,mul}_u16`, `lanewise_wrapping_add_u32`.
//! * **High-half multiplication**: `lanewise_mulhi_u16`.
//! * **Mask comparisons** (result is `0xFFFF` per lane on TRUE,
//!   `0x0000` on FALSE): `lanewise_eq_mask_u16`, `lanewise_sgt_mask_i16`.
//!
//! Comparisons return their result as a `[u16; N]` mask (not a `[bool; N]`)
//! to match the underlying hardware intrinsic, which writes per-lane
//! all-ones / all-zeros patterns. The mask convention agrees with both
//! Intel SDM ("set to all ones") and Arm ACLE (`vceqq_u16` returns a
//! `uint16x8_t`).
//!
//! Status: 12 transcribed `const N`-generic lane-wise primitives, 0 axioms.
//! Phase-3 proves each helper once against a `[T; N]`-parametric Lean
//! spec; arch-specific shims that route through these helpers then
//! discharge in one `simp` step at each call site.

#![allow(dead_code)]

// ----------------------------------------------------------------------------
// Bitwise — u8 lanes
// ----------------------------------------------------------------------------

/// Lane-wise `a & b` over `N` `u8` lanes.
#[inline]
pub fn lanewise_and_u8<const N: usize>(a: [u8; N], b: [u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = a[i] & b[i];
        i += 1;
    }
    out
}

/// Lane-wise `a | b` over `N` `u8` lanes.
#[inline]
pub fn lanewise_or_u8<const N: usize>(a: [u8; N], b: [u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = a[i] | b[i];
        i += 1;
    }
    out
}

/// Lane-wise `a ^ b` over `N` `u8` lanes.
#[inline]
pub fn lanewise_xor_u8<const N: usize>(a: [u8; N], b: [u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = a[i] ^ b[i];
        i += 1;
    }
    out
}

/// Lane-wise `(!a) & b` over `N` `u8` lanes — matches Intel `andnot`
/// argument order (NOT applied to the first operand).
#[inline]
pub fn lanewise_andnot_u8<const N: usize>(a: [u8; N], b: [u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (!a[i]) & b[i];
        i += 1;
    }
    out
}

// ----------------------------------------------------------------------------
// Bitwise — u16 lanes
// ----------------------------------------------------------------------------

/// Lane-wise `a & b` over `N` `u16` lanes. Used by aarch64 `vandq_u16`
/// where the natural input view is already `[u16; 8]`.
#[inline]
pub fn lanewise_and_u16<const N: usize>(a: [u16; N], b: [u16; N]) -> [u16; N] {
    let mut out = [0u16; N];
    let mut i = 0;
    while i < N {
        out[i] = a[i] & b[i];
        i += 1;
    }
    out
}

// ----------------------------------------------------------------------------
// Wrapping arithmetic — u16 lanes
// ----------------------------------------------------------------------------

/// Lane-wise wrapping `a + b` over `N` `u16` lanes.
#[inline]
pub fn lanewise_wrapping_add_u16<const N: usize>(a: [u16; N], b: [u16; N]) -> [u16; N] {
    let mut out = [0u16; N];
    let mut i = 0;
    while i < N {
        out[i] = a[i].wrapping_add(b[i]);
        i += 1;
    }
    out
}

/// Lane-wise wrapping `a - b` over `N` `u16` lanes.
#[inline]
pub fn lanewise_wrapping_sub_u16<const N: usize>(a: [u16; N], b: [u16; N]) -> [u16; N] {
    let mut out = [0u16; N];
    let mut i = 0;
    while i < N {
        out[i] = a[i].wrapping_sub(b[i]);
        i += 1;
    }
    out
}

/// Lane-wise wrapping `a * b` (LOW 16 bits) over `N` `u16` lanes. The
/// low half is identical for signed and unsigned multiplication, so this
/// helper covers both `_mm_mullo_epi16` and `vmulq_u16`.
#[inline]
pub fn lanewise_wrapping_mul_u16<const N: usize>(a: [u16; N], b: [u16; N]) -> [u16; N] {
    let mut out = [0u16; N];
    let mut i = 0;
    while i < N {
        out[i] = a[i].wrapping_mul(b[i]);
        i += 1;
    }
    out
}

/// Lane-wise HIGH 16 bits of unsigned `a * b` over `N` `u16` lanes.
/// Matches `_mm_mulhi_epu16` / `_mm256_mulhi_epu16`.
#[inline]
pub fn lanewise_mulhi_u16<const N: usize>(a: [u16; N], b: [u16; N]) -> [u16; N] {
    let mut out = [0u16; N];
    let mut i = 0;
    while i < N {
        let p = (a[i] as u32) * (b[i] as u32);
        out[i] = (p >> 16) as u16;
        i += 1;
    }
    out
}

// ----------------------------------------------------------------------------
// Wrapping arithmetic — u32 lanes
// ----------------------------------------------------------------------------

/// Lane-wise wrapping `a + b` over `N` `u32` lanes.
#[inline]
pub fn lanewise_wrapping_add_u32<const N: usize>(a: [u32; N], b: [u32; N]) -> [u32; N] {
    let mut out = [0u32; N];
    let mut i = 0;
    while i < N {
        out[i] = a[i].wrapping_add(b[i]);
        i += 1;
    }
    out
}

// ----------------------------------------------------------------------------
// Mask comparisons — return per-lane `0xFFFF`/`0x0000`
// ----------------------------------------------------------------------------

/// Lane-wise equality on `u16` lanes; per-lane result is `0xFFFF` when
/// the inputs agree, `0x0000` otherwise. Matches Intel SDM `_mm_cmpeq_epi16`
/// / `_mm256_cmpeq_epi16`.
#[inline]
pub fn lanewise_eq_mask_u16<const N: usize>(a: [u16; N], b: [u16; N]) -> [u16; N] {
    let mut out = [0u16; N];
    let mut i = 0;
    while i < N {
        out[i] = if a[i] == b[i] { 0xFFFF } else { 0 };
        i += 1;
    }
    out
}

/// Lane-wise SIGNED greater-than on `u16` lanes viewed as `i16`; per-lane
/// result is `0xFFFF` when `(a as i16) > (b as i16)`, `0x0000` otherwise.
/// Matches Intel SDM `_mm_cmpgt_epi16` / `_mm256_cmpgt_epi16`.
#[inline]
pub fn lanewise_sgt_mask_i16<const N: usize>(a: [u16; N], b: [u16; N]) -> [u16; N] {
    let mut out = [0u16; N];
    let mut i = 0;
    while i < N {
        let ai = a[i] as i16;
        let bi = b[i] as i16;
        out[i] = if ai > bi { 0xFFFF } else { 0 };
        i += 1;
    }
    out
}

// ============================================================================
// Tests
// ============================================================================
//
// These tests pin the algebraic identities Phase 4 will rely on (lane-wise
// `xor` is involutive, `andnot` agrees with `(!a) & b`, etc.). They run as
// part of the standard `cargo test --features verify --lib` invocation; no
// host-feature requirement, since the helpers are pure scalar code.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_involutive_u8_16() {
        let a: [u8; 16] = [
            0x00, 0x01, 0x10, 0x11, 0x55, 0xAA, 0xFF, 0x7F,
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        ];
        let b: [u8; 16] = [
            0xFF, 0xFE, 0xEF, 0xEE, 0xAA, 0x55, 0x00, 0x80,
            0xED, 0xCB, 0xA9, 0x87, 0x65, 0x43, 0x21, 0x0F,
        ];
        let c = lanewise_xor_u8(a, b);
        let a2 = lanewise_xor_u8(c, b);
        assert_eq!(a2, a);
    }

    #[test]
    fn xor_involutive_u8_32() {
        let a = [0xA5u8; 32];
        let b: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
        let c = lanewise_xor_u8(a, b);
        let a2 = lanewise_xor_u8(c, b);
        assert_eq!(a2, a);
    }

    #[test]
    fn andnot_matches_not_and_u8_16() {
        let a: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(17));
        let b: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(5));
        let lhs = lanewise_andnot_u8(a, b);
        let rhs = {
            let nota: [u8; 16] = core::array::from_fn(|i| !a[i]);
            lanewise_and_u8(nota, b)
        };
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn and_or_dual_u8_16() {
        // De Morgan dual would also work; here just check shapes line up.
        let a: [u8; 16] = [1, 2, 4, 8, 16, 32, 64, 128, 3, 5, 9, 17, 33, 65, 129, 255];
        let b: [u8; 16] = [255; 16];
        assert_eq!(lanewise_and_u8(a, b), a);
        assert_eq!(lanewise_or_u8(a, b), b);
    }

    #[test]
    fn wrapping_arith_u16_8() {
        let a: [u16; 8] = [0xFFFF, 0x0001, 0x1234, 0x8000, 0x7FFF, 0x0000, 0xABCD, 0x4321];
        let b: [u16; 8] = [0x0001, 0xFFFF, 0xEDCB, 0x8000, 0x0001, 0x0000, 0x5432, 0x1234];
        let s = lanewise_wrapping_add_u16(a, b);
        assert_eq!(s[0], 0x0000); // overflow wraps
        assert_eq!(s[1], 0x0000);
        assert_eq!(s[3], 0x0000); // 0x8000+0x8000 wraps to 0
        let d = lanewise_wrapping_sub_u16(s, b);
        assert_eq!(d, a); // (a+b)-b = a
    }

    #[test]
    fn mul_low_high_compose_u16_8() {
        let a: [u16; 8] = [0, 1, 2, 0xFFFF, 0x1234, 0xABCD, 0x4321, 0x7FFF];
        let b: [u16; 8] = [0xFFFF, 0xFFFF, 0x8000, 0xFFFF, 0xDEAD, 0xBEEF, 0xCAFE, 0xBABE];
        let lo = lanewise_wrapping_mul_u16(a, b);
        let hi = lanewise_mulhi_u16(a, b);
        for i in 0..8 {
            let full = (a[i] as u32) * (b[i] as u32);
            assert_eq!(lo[i] as u32 | ((hi[i] as u32) << 16), full);
        }
    }

    #[test]
    fn wrapping_add_u32_4() {
        let a: [u32; 4] = [0xFFFF_FFFF, 0x0000_0001, 0xDEAD_BEEF, 0];
        let b: [u32; 4] = [0x0000_0001, 0xFFFF_FFFF, 0x1111_1111, 0];
        let s = lanewise_wrapping_add_u32(a, b);
        assert_eq!(s, [0, 0, 0xEFBE_D000, 0]);
    }

    #[test]
    fn eq_and_sgt_masks_u16_8() {
        let a: [u16; 8] = [0x0001, 0x0002, 0xFFFF, 0x8000, 0x7FFF, 0x0000, 0x0001, 0x0001];
        let b: [u16; 8] = [0x0001, 0x0001, 0xFFFF, 0x7FFF, 0x8000, 0x0000, 0x0000, 0x0002];
        let eq = lanewise_eq_mask_u16(a, b);
        assert_eq!(eq, [0xFFFF, 0, 0xFFFF, 0, 0, 0xFFFF, 0, 0]);
        // signed: -1 > -32768  (treating 0xFFFF/0x8000 as i16);
        // 0x8000 < 0x7FFF as signed (-32768 < 32767);
        let sgt = lanewise_sgt_mask_i16(a, b);
        // a vs b as i16:
        //   0x0001=1     vs 0x0001=1     -> not >
        //   0x0002=2     vs 0x0001=1     -> a > b
        //   0xFFFF=-1    vs 0xFFFF=-1    -> not >
        //   0x8000=-32768 vs 0x7FFF=32767 -> not > (very small > very large is false)
        //   0x7FFF=32767  vs 0x8000=-32768 -> a > b
        //   0x0000=0     vs 0x0000=0     -> not >
        //   0x0001=1     vs 0x0000=0     -> a > b
        //   0x0001=1     vs 0x0002=2     -> not >
        assert_eq!(sgt, [0, 0xFFFF, 0, 0, 0xFFFF, 0, 0xFFFF, 0]);
    }
}
