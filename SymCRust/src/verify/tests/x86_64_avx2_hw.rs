//! Cross-check `src/verify/intrinsics/x86_64/avx2.rs` against the real
//! `_mm256_*` AVX2 hardware intrinsics.
//!
//! Run:
//!   RUSTFLAGS="-C target-feature=+avx2" cargo test --features benchmarking --test x86_64_avx2_hw
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
#[cfg(target_feature = "avx2")]
mod cross {
    use core::arch::x86_64::*;
    use super::avx2::*;

    // ---- helpers ------------------------------------------------------------

    unsafe fn ymm_from_bytes(b: Bytes256) -> __m256i {
        _mm256_loadu_si256(b.as_ptr() as *const __m256i)
    }
    unsafe fn ymm_to_bytes(v: __m256i) -> Bytes256 {
        let mut out = [0u8; 32];
        _mm256_storeu_si256(out.as_mut_ptr() as *mut __m256i, v);
        out
    }
    unsafe fn ymm_from_words(w: Words16x16) -> __m256i { ymm_from_bytes(words16x16_to_bytes256(w)) }
    unsafe fn ymm_to_words(v: __m256i)   -> Words16x16 { bytes256_to_words16x16(ymm_to_bytes(v)) }
    unsafe fn ymm_from_qwords(q: Qwords256) -> __m256i { ymm_from_bytes(qwords256_to_bytes256(q)) }
    unsafe fn ymm_to_qwords(v: __m256i)   -> Qwords256 { bytes256_to_qwords256(ymm_to_bytes(v)) }

    // ---- constants ---------------------------------------------------------

    #[test]
    fn setzero_si256_matches() {
        unsafe {
            assert_eq!(ymm_to_bytes(_mm256_setzero_si256()), setzero_si256());
        }
    }

    #[test]
    fn set1_epi16_matches() {
        for &a in &[0i16, 1, -1, 0x1234, i16::MIN, i16::MAX] {
            unsafe {
                assert_eq!(ymm_to_words(_mm256_set1_epi16(a)), set1_epi16(a));
            }
        }
    }

    // ---- u16 arithmetic over 16 lanes --------------------------------------

    fn arb_words(seed: u64) -> Words16x16 {
        let mut s = seed | 1;
        core::array::from_fn(|_| { s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407); s as u16 })
    }

    #[test]
    fn add_sub_mul_epi16_matches() {
        for seed in 0u64..16 {
            let a = arb_words(seed);
            let b = arb_words(seed ^ 0xDEAD_BEEF);
            unsafe {
                let av = ymm_from_words(a);
                let bv = ymm_from_words(b);
                assert_eq!(ymm_to_words(_mm256_add_epi16(av, bv)),    add_epi16(a, b));
                assert_eq!(ymm_to_words(_mm256_sub_epi16(av, bv)),    sub_epi16(a, b));
                assert_eq!(ymm_to_words(_mm256_mullo_epi16(av, bv)),  mullo_epi16(a, b));
                assert_eq!(ymm_to_words(_mm256_mulhi_epu16(av, bv)),  mulhi_epu16(a, b));
            }
        }
    }

    #[test]
    fn cmp_epi16_matches() {
        let a: Words16x16 = core::array::from_fn(|i| i as u16);
        let b: Words16x16 = [5; 16];
        unsafe {
            let av = ymm_from_words(a);
            let bv = ymm_from_words(b);
            assert_eq!(ymm_to_words(_mm256_cmpeq_epi16(av, bv)), cmpeq_epi16(a, b));
            assert_eq!(ymm_to_words(_mm256_cmpgt_epi16(av, bv)), cmpgt_epi16(a, b));
        }
        // Signed semantics: -1 (0xFFFF) is NOT > 0.
        let neg: Words16x16 = [0xFFFF; 16];
        let zero: Words16x16 = [0; 16];
        unsafe {
            let nv = ymm_from_words(neg);
            let zv = ymm_from_words(zero);
            assert_eq!(ymm_to_words(_mm256_cmpgt_epi16(nv, zv)), cmpgt_epi16(neg, zero));
        }
    }

    // ---- bitwise -----------------------------------------------------------

    #[test]
    fn bitwise_si256_matches() {
        let a: Bytes256 = core::array::from_fn(|i| (i as u8).wrapping_mul(31).wrapping_add(7));
        let b: Bytes256 = [0xCC; 32];
        unsafe {
            let av = ymm_from_bytes(a);
            let bv = ymm_from_bytes(b);
            assert_eq!(ymm_to_bytes(_mm256_and_si256(av, bv)),    and_si256(a, b));
            assert_eq!(ymm_to_bytes(_mm256_or_si256(av, bv)),     or_si256(a, b));
            assert_eq!(ymm_to_bytes(_mm256_andnot_si256(av, bv)), andnot_si256(a, b));
        }
    }

    // ---- shifts ------------------------------------------------------------

    #[test]
    fn slli_srli_epi64_matches_for_all_imm() {
        let q: Qwords256 = [0x0123_4567_89AB_CDEF, 1u64 << 63, 0, !0];
        unsafe {
            let v = ymm_from_qwords(q);
            macro_rules! check {
                ($n:expr) => {{
                    assert_eq!(ymm_to_qwords(_mm256_slli_epi64::<$n>(v)), slli_epi64(q, $n),
                               "slli_epi64 by {}", $n);
                    assert_eq!(ymm_to_qwords(_mm256_srli_epi64::<$n>(v)), srli_epi64(q, $n),
                               "srli_epi64 by {}", $n);
                }};
            }
            check!(0);  check!(1);  check!(7);  check!(8);
            check!(31); check!(32); check!(60); check!(63); check!(64);
        }
    }

    // ---- loads / stores ----------------------------------------------------

    #[test]
    fn loadu_storeu_si256_u64_matches() {
        let arr: [u64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        for at in 0..(8 - 4) {
            unsafe {
                let hw  = ymm_to_qwords(_mm256_loadu_si256(arr.as_ptr().add(at) as *const __m256i));
                let sh  = loadu_si256_u64(&arr, at);
                assert_eq!(hw, sh);
            }
        }
        let v: Qwords256 = [10, 20, 30, 40];
        for at in 0..(8 - 4) {
            unsafe {
                let mut hw_out = [0u64; 8];
                _mm256_storeu_si256(hw_out.as_mut_ptr().add(at) as *mut __m256i, ymm_from_qwords(v));
                let mut sh_out = [0u64; 8];
                storeu_si256_u64(&mut sh_out, at, v);
                assert_eq!(hw_out, sh_out);
            }
        }
    }

    #[test]
    fn loadu_storeu_si256_u16_matches() {
        let arr: [u16; 20] = core::array::from_fn(|i| (i as u16) * 7 + 1);
        for at in 0..(20 - 16) {
            unsafe {
                let hw = ymm_to_words(_mm256_loadu_si256(arr.as_ptr().add(at) as *const __m256i));
                let sh = loadu_si256_u16(&arr, at);
                assert_eq!(hw, sh);
            }
        }
        let v: Words16x16 = core::array::from_fn(|i| 1000 + (i as u16));
        for at in 0..(20 - 16) {
            unsafe {
                let mut hw_out = [0u16; 20];
                _mm256_storeu_si256(hw_out.as_mut_ptr().add(at) as *mut __m256i, ymm_from_words(v));
                let mut sh_out = [0u16; 20];
                storeu_si256_u16(&mut sh_out, at, v);
                assert_eq!(hw_out, sh_out);
            }
        }
    }

    // ---- aligned loads / stores --------------------------------------------
    //
    // Witness for axioms
    //   `core.core_arch.x86.avx2._mm256_load_si256`
    //   `core.core_arch.x86.avx2._mm256_store_si256`
    // (Intel SDM `VMOVDQA`).  Backs the IRREDUCIBLE-pending classification by
    // exercising round-trip behaviour on well-aligned inputs; the trust
    // boundary is the SDM contract that the aligned form behaves identically
    // to the unaligned form when the operand is 32-byte aligned.

    /// 32-byte-aligned container holding a `__m256i`-sized scratch region.
    #[repr(C, align(32))]
    struct A32 {
        data: [u8; 32],
    }

    #[test]
    fn load_store_si256_aligned_matches() {
        // Deterministic, non-trivial 32-byte payload.
        let mut payload = A32 { data: [0u8; 32] };
        for i in 0..32 {
            payload.data[i] = ((i as u32).wrapping_mul(0x9E3779B1) >> 24) as u8;
        }
        let payload_bytes = payload.data;

        unsafe {
            // Aligned-load == unaligned-load on a 32-byte-aligned pointer.
            let v_aligned = _mm256_load_si256(payload.data.as_ptr() as *const __m256i);
            let v_unalign = _mm256_loadu_si256(payload.data.as_ptr() as *const __m256i);
            assert_eq!(ymm_to_bytes(v_aligned), ymm_to_bytes(v_unalign));

            // Aligned-store round-trip matches the source bytes.
            let mut out = A32 { data: [0u8; 32] };
            _mm256_store_si256(out.data.as_mut_ptr() as *mut __m256i, v_aligned);
            assert_eq!(out.data, payload_bytes);

            // Aligned-store == unaligned-store on a 32-byte-aligned destination.
            let mut a_out = A32 { data: [0u8; 32] };
            let mut u_out = A32 { data: [0u8; 32] };
            _mm256_store_si256(a_out.data.as_mut_ptr() as *mut __m256i, v_aligned);
            _mm256_storeu_si256(u_out.data.as_mut_ptr() as *mut __m256i, v_aligned);
            assert_eq!(a_out.data, u_out.data);

            // Exercise the aligned `load_si256_u64` / `store_si256_u64` *models*
            // directly against the silicon aligned intrinsics (the unaligned
            // models are covered by `loadu_storeu_si256_u64_matches`; these
            // aliases would otherwise be untested until a future caller wires
            // them in).
            let words: [u64; 4] = [
                0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210,
                0x0000_0000_FFFF_FFFF, 0x8000_0000_0000_0001,
            ];
            let m = load_si256_u64(&words, 0);
            assert_eq!(ymm_to_qwords(_mm256_load_si256(words.as_ptr() as *const __m256i)), m);
            let mut sout = [0u64; 4];
            store_si256_u64(&mut sout, 0, m);
            assert_eq!(sout, words);
        }
    }
}
