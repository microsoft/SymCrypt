//! Transcribed shims for SSSE3 (`target_feature = "ssse3"`) intrinsics used
//! by SHA-2.
//!
//! Every function below is a plain Rust transcription of the Intel SDM
//! "Operation:" pseudocode for the corresponding `core::arch::x86_64::_mm_*`
//! intrinsic. Aeneas extracts them as ordinary Lean `def`s in
//! `lean/Intrinsics/Code/Funs.lean`; the per-intrinsic step specs and
//! citations live in `lean/Intrinsics/X86_64/Ssse3.lean`. Fidelity to silicon
//! is enforced by `tests/x86_64_ssse3_hw.rs` (differential against
//! `core::arch::x86_64::_mm_*`).
//!
//! Status: 2 transcribed shims, 0 axioms.
//!
//! Coverage map (intrinsic ↔ shim):
//! ```text
//! _mm_shuffle_epi8  (PSHUFB)  ←→ shuffle_epi8
//! _mm_alignr_epi8   (PALIGNR) ←→ alignr_epi8
//! ```

#![allow(dead_code)]

pub use super::lanes::{Bytes, Dwords, bytes_to_dwords, dwords_to_bytes};

// ----------------------------------------------------------------------------
// _mm_shuffle_epi8  (SSSE3, PSHUFB)
// ----------------------------------------------------------------------------
// Operation:
//   FOR i := 0 to 15
//     IF mask[8*i + 7] == 1            ; mask byte's MSB = control bit
//       dst[8*i + 7 : 8*i] := 0
//     ELSE
//       k := mask[8*i + 3 : 8*i]       ; low 4 bits select src byte
//       dst[8*i + 7 : 8*i] := a[8*k + 7 : 8*k]
//     ENDIF
//   ENDFOR
// ----------------------------------------------------------------------------

/// Per-byte table shuffle. For each output byte `i`, if `mask[i]`'s MSB is
/// set the output byte is `0`; otherwise the low 4 bits of `mask[i]` select
/// a source byte from `a`.
#[inline]
pub fn shuffle_epi8(a: Bytes, mask: Bytes) -> Bytes {
    let mut out = [0u8; 16];
    for i in 0..16 {
        let m = mask[i];
        if m & 0x80 != 0 {
            out[i] = 0;
        } else {
            out[i] = a[(m & 0x0F) as usize];
        }
    }
    out
}

// ----------------------------------------------------------------------------
// _mm_alignr_epi8  (SSSE3, PALIGNR)
// ----------------------------------------------------------------------------
// Operation (128-bit form):
//   TEMP1[255:0] := ((a[127:0] << 128) OR b[127:0])   ; a is HIGH half
//   TEMP1[255:0] := TEMP1[255:0] >> (imm8 * 8)        ; logical, byte shift
//   dst[127:0]   := TEMP1[127:0]
//
// In particular:
//   imm8 == 0   : dst == b
//   imm8 == 16  : dst == a
//   imm8 >= 32  : dst == 0
// ----------------------------------------------------------------------------

/// Concatenate `a` (high) and `b` (low) into a 32-byte value, shift right
/// by `count` bytes, and return the low 16 bytes. `count` may be any
/// `usize`; values ≥ 32 yield `[0; 16]`.
#[inline]
pub fn alignr_epi8(a: Bytes, b: Bytes, count: usize) -> Bytes {
    let mut out = [0u8; 16];
    for i in 0..16 {
        let src = i + count;
        out[i] = if src < 16 {
            b[src]
        } else if src < 32 {
            a[src - 16]
        } else {
            0
        };
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arb()  -> Dwords { [0xDEAD_BEEFu32, 0xCAFE_F00D, 0x1234_5678, 0x9ABC_DEF0] }
    fn arb2() -> Dwords { [0x1111_2222u32, 0x3333_4444, 0x5555_6666, 0x7777_8888] }

    #[test]
    fn shuffle_epi8_zeroes_when_mask_msb_set() {
        let a = arb();
        let mut mask: Bytes = [3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12];
        mask[5] = 0x80;
        let out = shuffle_epi8(dwords_to_bytes(a), mask);
        assert_eq!(out[5], 0);
    }

    #[test]
    fn alignr_epi8_extreme_counts() {
        let a = arb();
        let b = arb2();
        let ab = dwords_to_bytes(a);
        let bb = dwords_to_bytes(b);
        assert_eq!(alignr_epi8(ab, bb, 0), bb);
        assert_eq!(alignr_epi8(ab, bb, 16), ab);
        assert_eq!(alignr_epi8(ab, bb, 32), [0u8; 16]);
        assert_eq!(alignr_epi8(ab, bb, 100), [0u8; 16]);
    }
}
