//! Cross-check the axiomatised `clmulepi64_si128` shim by comparing **silicon
//! ↔ Rust transcription** of GF(2) carry-less multiplication on each of the
//! four `imm8` halves-selection variants (00, 01, 10, 11).
//!
//! The transcription `clmul64_ref` is a plain `for`-loop implementation of
//! the SDM "Operation:" pseudocode for PCLMULQDQ; it is not part of the
//! production crate and not subject to the verify build's trust boundary.
//! This is exactly the equality the Phase-4 Lean axiom asserts.
//!
//! Run:
//!   RUSTFLAGS="-C target-feature=+pclmulqdq" cargo test --features benchmarking --test x86_64_pclmulqdq_hw
//! (full matrix: src/verify/tests/README.md)

#[cfg(target_arch = "x86_64")]
#[cfg(target_feature = "pclmulqdq")]
mod cross {
    use core::arch::x86_64::*;

    /// Reference (spec-side) GF(2) carry-less 64×64→128 multiplication.
    /// Output low 64 bits go into `r.0`, high 64 bits into `r.1` (bit 127 = 0).
    fn clmul64_ref(a: u64, b: u64) -> (u64, u64) {
        let mut tmp: u128 = 0;
        for j in 0..64 {
            if ((a >> j) & 1) != 0 { tmp ^= (b as u128) << j; }
        }
        (tmp as u64, (tmp >> 64) as u64)
    }

    /// Reference for `_mm_clmulepi64_si128(a, b, imm8)`: select halves per imm8.
    fn clmulepi64_ref(a_lo: u64, a_hi: u64, b_lo: u64, b_hi: u64, imm8: u8) -> (u64, u64) {
        let a = if (imm8 & 0x01) == 0 { a_lo } else { a_hi };
        let b = if (imm8 & 0x10) == 0 { b_lo } else { b_hi };
        clmul64_ref(a, b)
    }

    unsafe fn xmm_from_qw(lo: u64, hi: u64) -> __m128i {
        _mm_set_epi64x(hi as i64, lo as i64)
    }
    unsafe fn xmm_to_qw(v: __m128i) -> (u64, u64) {
        let mut out = [0u64; 2];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, v);
        (out[0], out[1])
    }

    fn rng(seed: u64) -> impl FnMut() -> u64 {
        let mut s = seed | 1;
        move || { s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407); s }
    }

    #[test]
    fn clmulepi64_silicon_matches_transcription_all_imm() {
        let mut g = rng(0xC0FFEE);
        for _ in 0..32 {
            let a_lo = g(); let a_hi = g();
            let b_lo = g(); let b_hi = g();
            unsafe {
                let a = xmm_from_qw(a_lo, a_hi);
                let b = xmm_from_qw(b_lo, b_hi);

                let hw00 = xmm_to_qw(_mm_clmulepi64_si128::<0x00>(a, b));
                let hw01 = xmm_to_qw(_mm_clmulepi64_si128::<0x01>(a, b));
                let hw10 = xmm_to_qw(_mm_clmulepi64_si128::<0x10>(a, b));
                let hw11 = xmm_to_qw(_mm_clmulepi64_si128::<0x11>(a, b));

                assert_eq!(hw00, clmulepi64_ref(a_lo, a_hi, b_lo, b_hi, 0x00));
                assert_eq!(hw01, clmulepi64_ref(a_lo, a_hi, b_lo, b_hi, 0x01));
                assert_eq!(hw10, clmulepi64_ref(a_lo, a_hi, b_lo, b_hi, 0x10));
                assert_eq!(hw11, clmulepi64_ref(a_lo, a_hi, b_lo, b_hi, 0x11));

                // bit 127 must be 0 (SDM "Operation:" pseudocode last line).
                for hw in &[hw00, hw01, hw10, hw11] {
                    assert_eq!(hw.1 >> 63, 0, "PCLMULQDQ bit 127 must be 0");
                }
            }
        }
    }

    #[test]
    fn clmul_corner_cases() {
        // Multiply by zero is zero; multiply by 1 is identity (in the low half).
        unsafe {
            let z = xmm_from_qw(0, 0);
            let one = xmm_from_qw(1, 0);
            let x = xmm_from_qw(0xDEAD_BEEF_CAFE_F00D, 0);
            assert_eq!(xmm_to_qw(_mm_clmulepi64_si128::<0x00>(z, x)), (0, 0));
            assert_eq!(xmm_to_qw(_mm_clmulepi64_si128::<0x00>(one, x)),
                       (0xDEAD_BEEF_CAFE_F00D, 0));
        }
    }
}
