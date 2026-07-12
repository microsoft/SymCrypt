//! Cross-check `src/verify/intrinsics/aarch64/neon.rs` against the real
//! Armv8-A NEON hardware intrinsics. Active **only on aarch64 hosts**; on
//! x86_64 the inner `cross` mod is cfg-gated out, so `cargo test` here runs
//! **0 rows** — a vacuous green that must NOT be cited as coverage.
//!
//! How to type-check (any host) and execute (aarch64 / qemu): see
//! `src/verify/tests/README.md` for the run commands. In short:
//!   # type-check for aarch64 (no execution):
//!   RUSTFLAGS="-C target-feature=+neon,+aes" cargo check --features benchmarking \
//!     --tests --target aarch64-unknown-linux-gnu
//!   # execute on a real aarch64 host or under qemu-user:
//!   RUSTFLAGS="-C target-feature=+neon,+aes" cargo test --features benchmarking \
//!     --target aarch64-unknown-linux-gnu --test aarch64_neon_hw

#[cfg(target_arch = "aarch64")]
#[path = "../intrinsics/lanes.rs"]
mod lanes;
#[cfg(target_arch = "aarch64")]
#[path = "../intrinsics/lanewise.rs"]
mod lanewise;
#[cfg(target_arch = "aarch64")]
#[path = "../intrinsics/aarch64/neon.rs"]
mod neon;

#[cfg(target_arch = "aarch64")]
mod cross {
    use core::arch::aarch64::*;
    // Import only the model TYPE(s) used unqualified; the model FUNCTIONS are
    // always called fully-qualified as `super::neon::<fn>` so they never collide
    // with the silicon intrinsics globbed in above.  (A `use super::neon::*;`
    // glob makes every shared name — `vld1q_u8`, `vst1q_u16`, … — ambiguous and
    // the harness fails to compile for aarch64.)
    use super::neon::Uint8x16;

    // ---- helpers ------------------------------------------------------------

    unsafe fn q_from_bytes(b: Uint8x16) -> uint8x16_t { vld1q_u8(b.as_ptr()) }
    unsafe fn q_to_bytes(v: uint8x16_t) -> Uint8x16 {
        let mut out = [0u8; 16]; vst1q_u8(out.as_mut_ptr(), v); out
    }

    unsafe fn q_from_u16(w: super::neon::Uint16x8) -> uint16x8_t {
        vld1q_u16(w.as_ptr())
    }
    unsafe fn q_to_u16(v: uint16x8_t) -> super::neon::Uint16x8 {
        let mut out = [0u16; 8]; vst1q_u16(out.as_mut_ptr(), v); out
    }

    unsafe fn q_from_u32(d: super::neon::Uint32x4) -> uint32x4_t {
        vld1q_u32(d.as_ptr())
    }
    unsafe fn q_to_u32(v: uint32x4_t) -> super::neon::Uint32x4 {
        let mut out = [0u32; 4]; vst1q_u32(out.as_mut_ptr(), v); out
    }

    unsafe fn d_from_u16(w: super::neon::Uint16x4) -> uint16x4_t {
        vld1_u16(w.as_ptr())
    }

    unsafe fn d_from_u32(d: super::neon::Uint32x2) -> uint32x2_t {
        vld1_u32(d.as_ptr())
    }

    fn arb_u16(seed: u64) -> super::neon::Uint16x8 {
        let mut s = seed | 1;
        core::array::from_fn(|_| { s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407); s as u16 })
    }

    // ---- arithmetic --------------------------------------------------------

    #[test]
    fn add_sub_mul_u16_matches() {
        for seed in 0u64..16 {
            let a = arb_u16(seed);
            let b = arb_u16(seed ^ 0xBEEF);
            unsafe {
                let av = q_from_u16(a);
                let bv = q_from_u16(b);
                assert_eq!(q_to_u16(core::arch::aarch64::vaddq_u16(av, bv)), super::neon::vaddq_u16(a, b));
                assert_eq!(q_to_u16(core::arch::aarch64::vsubq_u16(av, bv)), super::neon::vsubq_u16(a, b));
                assert_eq!(q_to_u16(core::arch::aarch64::vmulq_u16(av, bv)), super::neon::vmulq_u16(a, b));
            }
        }
    }

    #[test]
    fn widen_and_accumulate_matches() {
        let ah = arb_u16(7);
        let bh = arb_u16(13);
        let al: super::neon::Uint16x4 = [ah[0], ah[1], ah[2], ah[3]];
        let bl: super::neon::Uint16x4 = [bh[0], bh[1], bh[2], bh[3]];
        let acc: super::neon::Uint32x4 = [0x1234_5678, 0xDEAD_BEEF, 0xCAFE_F00D, 0x1357_9BDF];
        unsafe {
            assert_eq!(
                q_to_u32(core::arch::aarch64::vmull_u16(d_from_u16(al), d_from_u16(bl))),
                super::neon::vmull_u16(al, bl)
            );
            assert_eq!(
                q_to_u32(core::arch::aarch64::vmull_high_u16(q_from_u16(ah), q_from_u16(bh))),
                super::neon::vmull_high_u16(ah, bh)
            );
            assert_eq!(
                q_to_u32(core::arch::aarch64::vmlal_u16(q_from_u32(acc), d_from_u16(al), d_from_u16(bl))),
                super::neon::vmlal_u16(acc, al, bl)
            );
            assert_eq!(
                q_to_u32(core::arch::aarch64::vmlal_high_u16(q_from_u32(acc), q_from_u16(ah), q_from_u16(bh))),
                super::neon::vmlal_high_u16(acc, ah, bh)
            );
        }
    }

    #[test]
    fn bitwise_matches() {
        let a = arb_u16(0xAA);
        let b = arb_u16(0xCC);
        unsafe {
            assert_eq!(q_to_u16(core::arch::aarch64::vandq_u16(q_from_u16(a), q_from_u16(b))),
                       super::neon::vandq_u16(a, b));
        }
        let ab: Uint8x16 = core::array::from_fn(|i| (i as u8) ^ 0xAA);
        let bb: Uint8x16 = [0xCC; 16];
        unsafe {
            assert_eq!(q_to_bytes(core::arch::aarch64::veorq_u8(q_from_bytes(ab), q_from_bytes(bb))),
                       super::neon::veorq_u8(ab, bb));
        }
    }

    #[test]
    fn compares_matches() {
        let a = arb_u16(0x11);
        let b = arb_u16(0x77);
        unsafe {
            assert_eq!(q_to_u16(core::arch::aarch64::vcgeq_u16(q_from_u16(a), q_from_u16(b))),
                       super::neon::vcgeq_u16(a, b));
        }
        let signed: super::neon::Int16x8 = [-1, 0, -32768, 32767, 1, -2, 3, -4];
        unsafe {
            let sv = vld1q_s16(signed.as_ptr());
            assert_eq!(q_to_u16(core::arch::aarch64::vcltzq_s16(sv)),
                       super::neon::vcltzq_s16(signed));
        }
    }

    #[test]
    fn dup_and_load_store_matches() {
        unsafe {
            assert_eq!(q_to_u16(core::arch::aarch64::vdupq_n_u16(0xCAFE)), super::neon::vdupq_n_u16(0xCAFE));
            assert_eq!(q_to_u32(core::arch::aarch64::vdupq_n_u32(0xCAFEBABE)), super::neon::vdupq_n_u32(0xCAFEBABE));
        }
        let arr_u16: [u16; 12] = core::array::from_fn(|i| (i as u16) * 7 + 1);
        unsafe {
            let hw = q_to_u16(vld1q_u16(arr_u16.as_ptr().add(2)));
            assert_eq!(hw, super::neon::vld1q_u16(&arr_u16, 2));
        }
        let arr_u32: [u32; 3] = [10, 20, 30];
        unsafe {
            let hw = q_to_u32(vld1q_dup_u32(arr_u32.as_ptr().add(1)));
            assert_eq!(hw, super::neon::vld1q_dup_u32(&arr_u32, 1));
        }
    }

    #[test]
    fn shuffles_matches() {
        let a = arb_u16(0x33);
        let b = arb_u16(0x55);
        unsafe {
            assert_eq!(q_to_u16(core::arch::aarch64::vuzp2q_u16(q_from_u16(a), q_from_u16(b))),
                       super::neon::vuzp2q_u16(a, b));
        }
    }

    #[test]
    fn reinterprets_are_bit_identical() {
        let v = arb_u16(0x42);
        unsafe {
            let hw = q_to_bytes(core::arch::aarch64::vreinterpretq_u8_u16(q_from_u16(v)));
            assert_eq!(hw, super::neon::vreinterpretq_u8_u16(v));
            let back = q_to_u16(core::arch::aarch64::vreinterpretq_u16_u8(q_from_bytes(hw)));
            assert_eq!(back, super::neon::vreinterpretq_u16_u8(hw));
        }
    }

    // ---- AES-NEON / GHASH helpers (post-M2 audit gap fills) -----------------
    //
    // The intrinsics covered below are all bit-identity reinterprets,
    // u64-lane broadcasts/loads, scalar lane extracts, and lane stores
    // used by aes_neon.rs and ghash_neon.rs.  None of them perform
    // arithmetic, so the differential check needs only a handful of
    // arbitrary inputs.

    unsafe fn q_to_u64(v: uint64x2_t) -> super::neon::Uint64x2 {
        let mut out = [0u64; 2]; vst1q_u64(out.as_mut_ptr(), v); out
    }
    unsafe fn q_from_u64(q: super::neon::Uint64x2) -> uint64x2_t {
        vld1q_u64(q.as_ptr())
    }
    unsafe fn d_to_u16(v: uint16x4_t) -> super::neon::Uint16x4 {
        let mut out = [0u16; 4]; vst1_u16(out.as_mut_ptr(), v); out
    }
    unsafe fn d_to_u32(v: uint32x2_t) -> super::neon::Uint32x2 {
        let mut out = [0u32; 2]; vst1_u32(out.as_mut_ptr(), v); out
    }
    unsafe fn d_from_u32_arr(d: super::neon::Uint32x2) -> uint32x2_t {
        vld1_u32(d.as_ptr())
    }

    #[test]
    fn dupq_n_u64_matches() {
        for x in [0u64, 1, 0xDEAD_BEEF_CAFE_F00D, u64::MAX, 0x8000_0000_0000_0000] {
            unsafe {
                assert_eq!(q_to_u64(core::arch::aarch64::vdupq_n_u64(x)),
                           super::neon::vdupq_n_u64(x));
            }
        }
    }

    #[test]
    fn ld1q_dup_u64_matches() {
        let arr: [u64; 3] = [0x1111_2222_3333_4444,
                             0x5555_6666_7777_8888,
                             0x9999_AAAA_BBBB_CCCC];
        for at in 0..3 {
            unsafe {
                let hw = q_to_u64(vld1q_dup_u64(arr.as_ptr().add(at)));
                assert_eq!(hw, super::neon::vld1q_dup_u64(&arr, at));
            }
        }
    }

    #[test]
    fn getq_lane_u32_matches() {
        let v: super::neon::Uint32x4 = [0x1111_1111, 0x2222_2222,
                                        0x3333_3333, 0x4444_4444];
        unsafe {
            let hv = q_from_u32(v);
            assert_eq!(vgetq_lane_u32::<0>(hv), super::neon::vgetq_lane_u32::<0>(v));
            assert_eq!(vgetq_lane_u32::<1>(hv), super::neon::vgetq_lane_u32::<1>(v));
            assert_eq!(vgetq_lane_u32::<2>(hv), super::neon::vgetq_lane_u32::<2>(v));
            assert_eq!(vgetq_lane_u32::<3>(hv), super::neon::vgetq_lane_u32::<3>(v));
        }
    }

    #[test]
    fn get_low_u16_matches() {
        let v = arb_u16(0xC0DE);
        unsafe {
            let lo = vget_low_u16(q_from_u16(v));
            assert_eq!(d_to_u16(lo), super::neon::vget_low_u16(v));
        }
    }

    #[test]
    fn get_low_u32_matches() {
        let v: super::neon::Uint32x4 = [0xAAAA_AAAA, 0xBBBB_BBBB,
                                        0xCCCC_CCCC, 0xDDDD_DDDD];
        unsafe {
            let lo = vget_low_u32(q_from_u32(v));
            assert_eq!(d_to_u32(lo), super::neon::vget_low_u32(v));
        }
    }

    #[test]
    fn st1_u16_matches() {
        // Both sides write into the SAME buffer position and compare
        // every cell, so a model that wrote into the wrong index
        // (e.g. lane 0 instead of `at`) would be caught.
        let v: super::neon::Uint16x4 = [0x1111, 0x2222, 0x3333, 0x4444];
        for at in [0usize, 3, 8] {
            let mut hw_buf = [0u16; 16];
            let mut sw_buf = [0u16; 16];
            unsafe {
                vst1_u16(hw_buf.as_mut_ptr().add(at), d_from_u16(v));
            }
            super::neon::vst1_u16(&mut sw_buf, at, v);
            assert_eq!(hw_buf, sw_buf, "vst1_u16 mismatch at offset {}", at);
        }
    }

    #[test]
    fn st1_lane_u32_matches() {
        let v: super::neon::Uint32x2 = [0x1357_9BDF, 0x2468_ACE0];
        for at in [0usize, 1, 5] {
            // LANE = 0
            let mut hw0 = [0u32; 8];
            let mut sw0 = [0u32; 8];
            unsafe {
                vst1_lane_u32::<0>(hw0.as_mut_ptr().add(at), d_from_u32_arr(v));
            }
            super::neon::vst1_lane_u32::<0>(&mut sw0, at, v);
            assert_eq!(hw0, sw0, "vst1_lane_u32::<0> mismatch at offset {}", at);
            // LANE = 1
            let mut hw1 = [0u32; 8];
            let mut sw1 = [0u32; 8];
            unsafe {
                vst1_lane_u32::<1>(hw1.as_mut_ptr().add(at), d_from_u32_arr(v));
            }
            super::neon::vst1_lane_u32::<1>(&mut sw1, at, v);
            assert_eq!(hw1, sw1, "vst1_lane_u32::<1> mismatch at offset {}", at);
        }
    }

    #[test]
    fn reinterprets_s16_and_cross_width_bit_identical() {
        // u16 ↔ s16 — same byte pattern, just a sign re-interpretation.
        let v = arb_u16(0xBEEF);
        unsafe {
            let hw_s16: super::neon::Int16x8 = {
                let raw = core::arch::aarch64::vreinterpretq_s16_u16(q_from_u16(v));
                let mut out = [0i16; 8]; vst1q_s16(out.as_mut_ptr(), raw); out
            };
            assert_eq!(hw_s16, super::neon::vreinterpretq_s16_u16(v));
        }

        // u16 ↔ u32 — pairs of u16 lanes pack into u32 lanes (LE).
        unsafe {
            let hw_u32 = q_to_u32(core::arch::aarch64::vreinterpretq_u32_u16(q_from_u16(v)));
            assert_eq!(hw_u32, super::neon::vreinterpretq_u32_u16(v));
            let back_u16 = q_to_u16(core::arch::aarch64::vreinterpretq_u16_u32(q_from_u32(hw_u32)));
            assert_eq!(back_u16, super::neon::vreinterpretq_u16_u32(hw_u32));
        }

        // u16 ↔ u64 — quartets of u16 lanes pack into u64 lanes (LE).
        unsafe {
            let hw_u64 = q_to_u64(core::arch::aarch64::vreinterpretq_u64_u16(q_from_u16(v)));
            let back_u16 = q_to_u16(core::arch::aarch64::vreinterpretq_u16_u64(q_from_u64(hw_u64)));
            assert_eq!(back_u16, super::neon::vreinterpretq_u16_u64(hw_u64));
        }

        // u8 ↔ u32 — used by aes_neon for vaeseq_u8 input/output packing.
        let v32: super::neon::Uint32x4 = [0xDEAD_BEEF, 0xCAFE_F00D,
                                          0x1337_C0DE, 0x8BAD_F00D];
        unsafe {
            let hw_u8 = q_to_bytes(core::arch::aarch64::vreinterpretq_u8_u32(q_from_u32(v32)));
            assert_eq!(hw_u8, super::neon::vreinterpretq_u8_u32(v32));
            let back_u32 = q_to_u32(core::arch::aarch64::vreinterpretq_u32_u8(q_from_bytes(hw_u8)));
            assert_eq!(back_u32, super::neon::vreinterpretq_u32_u8(hw_u8));
        }

        // u8 ↔ u64 — used by aes_neon's `vdupq_n_u64(0)`-then-reinterpret idiom.
        let v64: super::neon::Uint64x2 = [0xDEAD_BEEF_CAFE_F00D, 0x1337_C0DE_8BAD_F00D];
        unsafe {
            let hw_u8 = q_to_bytes(core::arch::aarch64::vreinterpretq_u8_u64(q_from_u64(v64)));
            assert_eq!(hw_u8, super::neon::vreinterpretq_u8_u64(v64));
        }

        // s16 ↔ {u8, u16} — bit-identity sign re-interpretations not exercised
        // by the active ML-KEM / AES-NEON drivers, but modelled in neon.rs
        // and likely needed by future callers.  Pin them so a
        // future caller does not force a Rust test edit.
        let s16: super::neon::Int16x8 =
            [-1, 0, 1, i16::MIN, i16::MAX, -0x1234, 0x4321, -0x7fff];
        unsafe {
            let s16v = vld1q_s16(s16.as_ptr());
            // u16 ← s16  (same bytes, unsigned re-read)
            assert_eq!(
                q_to_u16(core::arch::aarch64::vreinterpretq_u16_s16(s16v)),
                super::neon::vreinterpretq_u16_s16(s16),
            );
            // u8 ← s16  (byte image of the s16 lanes)
            assert_eq!(
                q_to_bytes(core::arch::aarch64::vreinterpretq_u8_s16(s16v)),
                super::neon::vreinterpretq_u8_s16(s16),
            );
        }
        // s16 ← u8  (byte image re-read as signed words)
        let bytes: super::neon::Uint8x16 =
            core::array::from_fn(|i| ((i as u32).wrapping_mul(0x9E37_79B1) >> 24) as u8);
        unsafe {
            let hw_s16: super::neon::Int16x8 = {
                let raw = core::arch::aarch64::vreinterpretq_s16_u8(q_from_bytes(bytes));
                let mut out = [0i16; 8];
                vst1q_s16(out.as_mut_ptr(), raw);
                out
            };
            assert_eq!(hw_s16, super::neon::vreinterpretq_s16_u8(bytes));
        }
    }
}
