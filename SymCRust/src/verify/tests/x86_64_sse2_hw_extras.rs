//! Cross-check the **new SSE2 shims** (`setzero` / `set1` / `set_*` /
//! `add/sub/mul/cmp_epi16` / `and/andnot/or/xor_si128` / `slli/srli_*` /
//! `cvtsi128_si32` / `cvtsi32_si128` / `loadu/storeu_si64` / `store_si128`)
//! against the real `_mm_*` hardware intrinsics on x86_64.
//!
//! Run:
//!   cargo test --features benchmarking --test x86_64_sse2_hw_extras

#[cfg(target_arch = "x86_64")]
#[path = "../intrinsics/lanes.rs"]
mod lanes;
#[cfg(target_arch = "x86_64")]
#[path = "../intrinsics/lanewise.rs"]
mod lanewise;
#[cfg(target_arch = "x86_64")]
#[path = "../intrinsics/x86_64/sse2.rs"]
mod sse2;

#[cfg(target_arch = "x86_64")]
mod cross {
    use core::arch::x86_64::*;
    use super::sse2::*;
    use super::lanes::{Bytes, Dwords, Qwords, Words,
        bytes_to_dwords, dwords_to_bytes,
        bytes_to_words, words_to_bytes,
        bytes_to_qwords, qwords_to_bytes};

    // ---- helpers ------------------------------------------------------------

    unsafe fn xmm_from_bytes(b: Bytes) -> __m128i {
        _mm_loadu_si128(b.as_ptr() as *const __m128i)
    }

    unsafe fn xmm_to_bytes(v: __m128i) -> Bytes {
        let mut out = [0u8; 16];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, v);
        out
    }

    unsafe fn xmm_from_words(w: Words) -> __m128i {
        xmm_from_bytes(words_to_bytes(w))
    }

    unsafe fn xmm_to_words(v: __m128i) -> Words {
        bytes_to_words(xmm_to_bytes(v))
    }

    unsafe fn xmm_from_dwords(d: Dwords) -> __m128i {
        xmm_from_bytes(dwords_to_bytes(d))
    }

    unsafe fn xmm_to_dwords(v: __m128i) -> Dwords {
        bytes_to_dwords(xmm_to_bytes(v))
    }

    unsafe fn xmm_from_qwords(q: Qwords) -> __m128i {
        xmm_from_bytes(qwords_to_bytes(q))
    }

    unsafe fn xmm_to_qwords(v: __m128i) -> Qwords {
        bytes_to_qwords(xmm_to_bytes(v))
    }

    // ---- constants ---------------------------------------------------------

    #[test]
    fn setzero_si128_matches() {
        unsafe {
            let hw = xmm_to_bytes(_mm_setzero_si128());
            assert_eq!(hw, setzero_si128());
        }
    }

    #[test]
    fn set1_epi16_matches() {
        for &a in &[0i16, 1, -1, 0x1234, i16::MIN, i16::MAX] {
            unsafe {
                let hw = xmm_to_words(_mm_set1_epi16(a));
                assert_eq!(hw, set1_epi16(a));
            }
        }
    }

    #[test]
    fn set1_epi32_matches() {
        for &a in &[0i32, 1, -1, 0x1234_5678, i32::MIN, i32::MAX] {
            unsafe {
                let hw = xmm_to_dwords(_mm_set1_epi32(a));
                assert_eq!(hw, set1_epi32(a));
            }
        }
    }

    #[test]
    fn set_epi32_high_first_matches() {
        unsafe {
            let hw = xmm_to_dwords(_mm_set_epi32(3, 2, 1, 0));
            assert_eq!(hw, set_epi32(3, 2, 1, 0));
            // and negative values too
            let hw = xmm_to_dwords(_mm_set_epi32(-1, -2, -3, -4));
            assert_eq!(hw, set_epi32(-1, -2, -3, -4));
        }
    }

    #[test]
    fn set_epi64x_matches() {
        unsafe {
            let hw = xmm_to_qwords(_mm_set_epi64x(0x77, 0x33));
            assert_eq!(hw, set_epi64x(0x77, 0x33));
            let hw = xmm_to_qwords(_mm_set_epi64x(i64::MIN, i64::MAX));
            assert_eq!(hw, set_epi64x(i64::MIN, i64::MAX));
        }
    }

    // ---- u16 arithmetic ----------------------------------------------------

    fn arb_words(seed: u64) -> Words {
        let mut s = seed | 1;
        core::array::from_fn(|_| { s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407); s as u16 })
    }

    #[test]
    fn add_sub_mul_epi16_matches() {
        for seed in 0u64..16 {
            let a = arb_words(seed);
            let b = arb_words(seed.wrapping_add(0xDEAD_BEEF));
            unsafe {
                let av = xmm_from_words(a);
                let bv = xmm_from_words(b);
                assert_eq!(xmm_to_words(_mm_add_epi16(av, bv)),    add_epi16(a, b));
                assert_eq!(xmm_to_words(_mm_sub_epi16(av, bv)),    sub_epi16(a, b));
                assert_eq!(xmm_to_words(_mm_mullo_epi16(av, bv)),  mullo_epi16(a, b));
                assert_eq!(xmm_to_words(_mm_mulhi_epu16(av, bv)),  mulhi_epu16(a, b));
            }
        }
    }

    #[test]
    fn cmp_epi16_matches() {
        let a: Words = [0, 1, 2, 0xFFFF, 0x8000, 0x7FFF, 5, 0];
        let b: Words = [1, 1, 1, 0xFFFF, 0x7FFF, 0x8000, 5, 0x8000];
        unsafe {
            let av = xmm_from_words(a);
            let bv = xmm_from_words(b);
            assert_eq!(xmm_to_words(_mm_cmpeq_epi16(av, bv)), cmpeq_epi16(a, b));
            assert_eq!(xmm_to_words(_mm_cmpgt_epi16(av, bv)), cmpgt_epi16(a, b));
        }
    }

    // ---- bitwise -----------------------------------------------------------

    #[test]
    fn bitwise_si128_matches() {
        let a: Bytes = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
                        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
        let b: Bytes = [0xCC; 16];
        unsafe {
            let av = xmm_from_bytes(a);
            let bv = xmm_from_bytes(b);
            assert_eq!(xmm_to_bytes(_mm_and_si128(av, bv)),    and_si128(a, b));
            assert_eq!(xmm_to_bytes(_mm_or_si128(av, bv)),     or_si128(a, b));
            assert_eq!(xmm_to_bytes(_mm_xor_si128(av, bv)),    xor_si128(a, b));
            assert_eq!(xmm_to_bytes(_mm_andnot_si128(av, bv)), andnot_si128(a, b));
        }
    }

    // ---- shifts ------------------------------------------------------------

    #[test]
    fn slli_srli_epi32_matches_for_all_imm() {
        let d: Dwords = [0xDEAD_BEEF, 0x1234_5678, 0xFFFF_FFFF, 0x8000_0001];
        unsafe {
            let v = xmm_from_dwords(d);
            macro_rules! check {
                ($n:expr) => {{
                    assert_eq!(xmm_to_dwords(_mm_slli_epi32::<$n>(v)), slli_epi32(d, $n),
                               "slli_epi32 by {}", $n);
                    assert_eq!(xmm_to_dwords(_mm_srli_epi32::<$n>(v)), srli_epi32(d, $n),
                               "srli_epi32 by {}", $n);
                }};
            }
            check!(0);  check!(1);  check!(7);  check!(8);
            check!(15); check!(16); check!(23); check!(31); check!(32);
        }
    }

    #[test]
    fn slli_epi64_matches_for_all_imm() {
        let q: Qwords = [0x0123_4567_89AB_CDEF, 1u64 << 63];
        unsafe {
            let v = xmm_from_qwords(q);
            macro_rules! check {
                ($n:expr) => {{
                    assert_eq!(xmm_to_qwords(_mm_slli_epi64::<$n>(v)), slli_epi64(q, $n),
                               "slli_epi64 by {}", $n);
                }};
            }
            check!(0);  check!(1);  check!(7);  check!(8);
            check!(31); check!(32); check!(63); check!(64);
        }
    }

    #[test]
    fn srli_si128_matches_for_all_imm() {
        let b: Bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        unsafe {
            let v = xmm_from_bytes(b);
            macro_rules! check {
                ($n:expr) => {{
                    let hw = xmm_to_bytes(_mm_srli_si128::<$n>(v));
                    let sh = srli_si128(b, $n);
                    assert_eq!(hw, sh, "srli_si128 by {}", $n);
                }};
            }
            check!(0);  check!(1);  check!(2);  check!(3);
            check!(7);  check!(8);  check!(15); check!(16);
        }
    }

    // ---- store / cvt -------------------------------------------------------

    #[test]
    fn store_si128_matches() {
        let v: Bytes = core::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(3));
        unsafe {
            let xv = xmm_from_bytes(v);
            // Aligned store: feed an aligned buffer via #[repr(align(16))].
            #[repr(align(16))]
            struct Aligned([u8; 32]);
            let mut buf = Aligned([0u8; 32]);
            _mm_store_si128(buf.0.as_mut_ptr().add(16) as *mut __m128i, xv);
            let mut shim = [0u8; 32];
            store_si128(&mut shim, 16, v);
            assert_eq!(buf.0, shim);
        }
    }

    #[test]
    fn cvts_round_trip_matches() {
        for &x in &[0i32, 1, -1, 0x7FFF_FFFF, -0x8000_0000, 0x1234_5678] {
            unsafe {
                let hw_x  = _mm_cvtsi32_si128(x);
                let shimd = cvtsi32_si128(x);
                assert_eq!(xmm_to_dwords(hw_x), shimd);
                assert_eq!(_mm_cvtsi128_si32(hw_x), cvtsi128_si32(shimd));
                assert_eq!(_mm_cvtsi128_si32(hw_x), x);
            }
        }
    }

    #[test]
    fn loadu_storeu_si64_matches() {
        let bytes: [u8; 24] = core::array::from_fn(|i| (i as u8) * 7 + 1);
        for at in 0..(24 - 8) {
            unsafe {
                let hw  = xmm_to_qwords(_mm_loadu_si64(bytes.as_ptr().add(at)));
                let sh  = loadu_si64(&bytes, at);
                assert_eq!(hw, sh);
                assert_eq!(hw[1], 0);
            }
        }
        let v: Qwords = [0x0807_0605_0403_0201, 0xDEAD_BEEF_CAFE_F00D];
        for at in 0..(24 - 8) {
            unsafe {
                let mut hw_out = [0u8; 24];
                _mm_storeu_si64(hw_out.as_mut_ptr().add(at), xmm_from_qwords(v));
                let mut shim_out = [0u8; 24];
                storeu_si64(&mut shim_out, at, v);
                assert_eq!(hw_out, shim_out);
            }
        }
    }
}
