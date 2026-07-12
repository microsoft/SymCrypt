//! Cross-check `src/verify/intrinsics/x86_64/ymm.rs` (the byte-carrier `M256`
//! YMM wrappers) against the real `_mm256_*` AVX2 hardware intrinsics.
//!
//! The `ymm::*` ops present a uniform `M256 = [u8; 32]` (byte-carrier) face and
//! delegate to the transcribed `avx2::*` shims (themselves cross-checked in
//! `x86_64_avx2_hw.rs`).  This harness pins the wrapper layer directly: for each
//! op, `ymm::op(bytes…)` must equal the byte image of the corresponding silicon
//! `_mm256_op` applied to the same register (methodology P7).
//!
//! Run:
//!   RUSTFLAGS="-C target-feature=+avx2" cargo test --features benchmarking --test x86_64_ymm_hw
//! (full matrix: src/verify/tests/README.md)

#[cfg(target_arch = "x86_64")]
#[path = "../intrinsics/lanes.rs"]
mod lanes;
#[cfg(target_arch = "x86_64")]
#[path = "../intrinsics/lanewise.rs"]
mod lanewise;
#[cfg(target_arch = "x86_64")]
#[path = "../intrinsics/x86_64/avx2.rs"]
mod avx2;
#[cfg(target_arch = "x86_64")]
#[path = "../intrinsics/x86_64/ymm.rs"]
mod ymm;

#[cfg(target_arch = "x86_64")]
#[cfg(target_feature = "avx2")]
mod cross {
    use core::arch::x86_64::*;
    use super::ymm::*;

    type M256b = [u8; 32];

    unsafe fn from_bytes(b: M256b) -> __m256i {
        _mm256_loadu_si256(b.as_ptr() as *const __m256i)
    }
    unsafe fn to_bytes(v: __m256i) -> M256b {
        let mut out = [0u8; 32];
        _mm256_storeu_si256(out.as_mut_ptr() as *mut __m256i, v);
        out
    }
    fn arb(seed: u64) -> M256b {
        let mut s = seed | 1;
        core::array::from_fn(|_| {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            s as u8
        })
    }

    #[test]
    fn setzero_si256_matches() {
        unsafe {
            assert_eq!(setzero_si256(), to_bytes(_mm256_setzero_si256()));
        }
    }

    #[test]
    fn set1_epi16_matches() {
        for &a in &[0i16, 1, -1, 0x1234, i16::MIN, i16::MAX] {
            unsafe {
                assert_eq!(set1_epi16(a), to_bytes(_mm256_set1_epi16(a)));
            }
        }
    }

    #[test]
    fn arith_epi16_matches() {
        for seed in 0u64..16 {
            let a = arb(seed);
            let b = arb(seed ^ 0xDEAD_BEEF);
            unsafe {
                let (av, bv) = (from_bytes(a), from_bytes(b));
                assert_eq!(add_epi16(a, b), to_bytes(_mm256_add_epi16(av, bv)));
                assert_eq!(sub_epi16(a, b), to_bytes(_mm256_sub_epi16(av, bv)));
                assert_eq!(mullo_epi16(a, b), to_bytes(_mm256_mullo_epi16(av, bv)));
                assert_eq!(mulhi_epu16(a, b), to_bytes(_mm256_mulhi_epu16(av, bv)));
                assert_eq!(cmpeq_epi16(a, b), to_bytes(_mm256_cmpeq_epi16(av, bv)));
                assert_eq!(cmpgt_epi16(a, b), to_bytes(_mm256_cmpgt_epi16(av, bv)));
            }
        }
    }

    #[test]
    fn bitwise_si256_matches() {
        for seed in 0u64..16 {
            let a = arb(seed);
            let b = arb(seed ^ 0x1234_5678);
            unsafe {
                let (av, bv) = (from_bytes(a), from_bytes(b));
                assert_eq!(and_si256(a, b), to_bytes(_mm256_and_si256(av, bv)));
                assert_eq!(andnot_si256(a, b), to_bytes(_mm256_andnot_si256(av, bv)));
                assert_eq!(or_si256(a, b), to_bytes(_mm256_or_si256(av, bv)));
            }
        }
    }

    #[test]
    fn shifts_epi64_matches() {
        for seed in 0u64..8 {
            let a = arb(seed);
            unsafe {
                let av = from_bytes(a);
                assert_eq!(slli_epi64::<1>(a), to_bytes(_mm256_slli_epi64::<1>(av)));
                assert_eq!(slli_epi64::<13>(a), to_bytes(_mm256_slli_epi64::<13>(av)));
                assert_eq!(srli_epi64::<1>(a), to_bytes(_mm256_srli_epi64::<1>(av)));
                assert_eq!(srli_epi64::<40>(a), to_bytes(_mm256_srli_epi64::<40>(av)));
            }
        }
    }
}
