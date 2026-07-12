//! Cross-check the 3 SHA-NI **axiom postconditions** drafted in
//! `lean/Symcrust/Properties/SHA2/Sha2Ni.lean` against the real x86-64
//! `_mm_sha256*` hardware intrinsics. Where the per-extension SSE2/SSSE3
//! harnesses validate the **executable** verify-build shims, this file
//! validates the **algebraic axioms** for the 3 SHA crypto-extension
//! opcodes that we cannot expose as plain Rust.
//!
//! Per [`SymCRust/lean/Intrinsics/INTRINSICS.md`](../../../lean/Intrinsics/INTRINSICS.md), the 3 SHA
//! intrinsics are axiomatised as direct equations against
//! FIPS-180-4 §6.2 (round) / §6.2.2 step 1 (schedule).  This test
//! re-implements those FIPS pure functions in plain `u32` Rust and
//! asserts that the silicon answer matches the axiom's spec form
//! lane-by-lane.  Any drift between the Lean axiom and Intel silicon
//! — including SDM errata or new microcode quirks — fails
//! `cargo test` immediately.
//!
//! Run:
//!   RUSTFLAGS="-C target-feature=+sha,+sse4.1,+ssse3" cargo test --test sha_ni_intrinsics_hw
//!
//! Tests gracefully skip (no failure) on CPUs without the SHA
//! extension.  The Lean axioms remain ground truth for the
//! verification proof; this test is an early-warning system for
//! axiom-vs-silicon drift.
//!
//! Lane convention (matches `Properties/SHA2/Sha2Ni.lean::laneBitsBE`):
//!   `Dwords = [u32; 4]` with lane 0 = LOW dword (Intel `dst[31:0]`),
//!   lane 3 = HIGH dword (Intel `dst[127:96]`).

#![cfg(target_arch = "x86_64")]

mod cross {
    use core::arch::x86_64::*;

    type Dwords = [u32; 4];

    fn dwords_to_m128i(d: Dwords) -> __m128i {
        // SAFETY: Dwords (16 bytes) and __m128i (16 bytes) are layout-compatible
        // when accessed via unaligned load. The little-endian byte order matches
        // the lane convention: d[0] occupies dst[31:0], d[3] occupies dst[127:96].
        let bytes: [u8; 16] = unsafe { core::mem::transmute(d) };
        unsafe { _mm_loadu_si128(bytes.as_ptr() as *const __m128i) }
    }

    fn m128i_to_dwords(v: __m128i) -> Dwords {
        let mut bytes = [0u8; 16];
        unsafe { _mm_storeu_si128(bytes.as_mut_ptr() as *mut __m128i, v); }
        // SAFETY: 16 bytes ↔ [u32; 4]; little-endian dword decoding matches
        // the Intel convention where lane 0 is the low 32 bits.
        unsafe { core::mem::transmute(bytes) }
    }

    // ----- FIPS-180-4 §4.1.2 pure functions over u32 (round + schedule) -----

    fn rotr(x: u32, n: u32) -> u32 { x.rotate_right(n) }

    fn ch(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (!x & z) }
    fn maj(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (x & z) ^ (y & z) }

    /// FIPS-180-4 eq 4.4: Σ₀ = ROTR^2 ⊕ ROTR^13 ⊕ ROTR^22.
    fn big_sigma0(x: u32) -> u32 { rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22) }
    /// FIPS-180-4 eq 4.5: Σ₁ = ROTR^6 ⊕ ROTR^11 ⊕ ROTR^25.
    fn big_sigma1(x: u32) -> u32 { rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25) }
    /// FIPS-180-4 eq 4.6: σ₀ = ROTR^7 ⊕ ROTR^18 ⊕ SHR^3.
    fn sigma0(x: u32) -> u32 { rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3) }
    /// FIPS-180-4 eq 4.7: σ₁ = ROTR^17 ⊕ ROTR^19 ⊕ SHR^10.
    fn sigma1(x: u32) -> u32 { rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10) }

    /// FIPS-180-4 §6.2.2 step 3 — one SHA-256 compression round.
    /// `kw = K_t + W_t` (pre-summed, matching SHA-NI's `mk` lane convention).
    fn round256(state: [u32; 8], kw: u32) -> [u32; 8] {
        let [a, b, c, d, e, f, g, h] = state;
        let t1 = h.wrapping_add(big_sigma1(e))
                  .wrapping_add(ch(e, f, g))
                  .wrapping_add(kw);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
        [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g]
    }

    /// Decode `(cdgh, abef)` lane pair into the canonical SHA-256
    /// working-state `(a, b, c, d, e, f, g, h)` per the Intel SHA Extensions
    /// chapter of the SDM.  Mirrors `Sha2Ni.lean::shaniLanesToHash`.
    ///   `abef[3..0] = (A, B, E, F)`  ;  `cdgh[3..0] = (C, D, G, H)`
    fn shani_lanes_to_hash(cdgh: Dwords, abef: Dwords) -> [u32; 8] {
        [abef[3], abef[2], cdgh[3], cdgh[2],
         abef[1], abef[0], cdgh[1], cdgh[0]]
    }

    // ----- Tiny deterministic PRNG (no rand dep needed for u32 streams) -----

    /// SplitMix64 — standard mixing function, deterministic, no allocations.
    struct SplitMix64 { state: u64 }
    impl SplitMix64 {
        fn new(seed: u64) -> Self { Self { state: seed } }
        fn next_u64(&mut self) -> u64 {
            self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn next_dwords(&mut self) -> Dwords {
            let a = self.next_u64();
            let b = self.next_u64();
            [a as u32, (a >> 32) as u32, b as u32, (b >> 32) as u32]
        }
    }

    // ============================================================
    //  AXIOM 1 — `_mm_sha256rnds2_epu32`
    //
    //  Sha2Ni.lean::sha2.unsafe_intrinsics.sha256rnds2_epu32.spec :
    //    Let s' = round256kw_pair (shaniLanesToHash cdgh abef)
    //                              (mk[0]) (mk[1])
    //    Then r[3,2,1,0] = (new_a, new_b, new_e, new_f).
    // ============================================================

    /// Compute the spec-side (FIPS) result of `_mm_sha256rnds2_epu32`,
    /// returning the (a',b',e',f') quadruple expected in lanes (3,2,1,0).
    fn rnds2_spec(cdgh: Dwords, abef: Dwords, mk: Dwords) -> Dwords {
        let s0 = shani_lanes_to_hash(cdgh, abef);
        let s1 = round256(s0, mk[0]);
        let s2 = round256(s1, mk[1]);
        // Result lanes (3,2,1,0) = (A_2, B_2, E_2, F_2)
        [s2[5] /*F*/, s2[4] /*E*/, s2[1] /*B*/, s2[0] /*A*/]
    }

    fn rnds2_hw(cdgh: Dwords, abef: Dwords, mk: Dwords) -> Dwords {
        // SAFETY: target-feature gate via runtime detection in the test bodies;
        // callers must check `is_x86_feature_detected!("sha")` first.
        let r = unsafe {
            _mm_sha256rnds2_epu32(
                dwords_to_m128i(cdgh),
                dwords_to_m128i(abef),
                dwords_to_m128i(mk),
            )
        };
        m128i_to_dwords(r)
    }

    fn check_rnds2(cdgh: Dwords, abef: Dwords, mk: Dwords) {
        let hw = rnds2_hw(cdgh, abef, mk);
        let sp = rnds2_spec(cdgh, abef, mk);
        assert_eq!(hw, sp,
            "sha256rnds2_epu32: silicon ≠ axiom\n  cdgh = {:08x?}\n  abef = {:08x?}\n  mk   = {:08x?}\n  hw   = {:08x?}\n  spec = {:08x?}",
            cdgh, abef, mk, hw, sp);
    }

    #[test]
    fn sha256rnds2_epu32_canonical_inputs() {
        if !is_x86_feature_detected!("sha") { eprintln!("skip: SHA not detected"); return; }

        // Canonical literals, broad coverage of byte patterns.
        let cdgh: Dwords = [0xDEAD_BEEFu32, 0xCAFE_F00D, 0x1234_5678, 0x9ABC_DEF0];
        let abef: Dwords = [0x1111_2222u32, 0x3333_4444, 0x5555_6666, 0x7777_8888];
        // SDM: lanes 2 and 3 of mk are ignored; non-zero values must not affect
        // the result.  Encode this here too.
        let mk:   Dwords = [0xAABB_CCDDu32, 0x9988_7766, 0xDEAD_DEAD, 0xBEEF_BEEF];
        check_rnds2(cdgh, abef, mk);

        // SDM corner: high lanes of mk truly ignored — same low 64 bits, different
        // high 64 bits, must produce the same dst.
        let mk2: Dwords = [0xAABB_CCDDu32, 0x9988_7766, 0, 0];
        let h1 = rnds2_hw(cdgh, abef, mk);
        let h2 = rnds2_hw(cdgh, abef, mk2);
        assert_eq!(h1, h2, "rnds2: high 64 bits of mk must be ignored");
    }

    #[test]
    fn sha256rnds2_epu32_zero_and_max_inputs() {
        if !is_x86_feature_detected!("sha") { eprintln!("skip: SHA not detected"); return; }

        // All zeros: both Σ_0 and Σ_1 of 0 are 0; Ch(0,0,0)=0; Maj(0,0,0)=0;
        // K+W = 0 ⇒ T1 = T2 = 0 ⇒ state unchanged.  Cross-check that the
        // axiom does the right thing on the trivial fixed point.
        check_rnds2([0; 4], [0; 4], [0; 4]);

        // All ones: probes the wrapping-add chain in T1/T2 against silicon.
        check_rnds2([u32::MAX; 4], [u32::MAX; 4], [u32::MAX; 4]);

        // K+W = 0 with non-trivial state — checks that round mixing matches.
        let cdgh: Dwords = [0x6A09_E667u32, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A];
        let abef: Dwords = [0x510E_527Fu32, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19];
        check_rnds2(cdgh, abef, [0; 4]);
    }

    #[test]
    fn sha256rnds2_epu32_random_inputs() {
        if !is_x86_feature_detected!("sha") { eprintln!("skip: SHA not detected"); return; }

        let mut rng = SplitMix64::new(0xA5A5_5A5A_DEAD_BEEF);
        for _ in 0..256 {
            check_rnds2(rng.next_dwords(), rng.next_dwords(), rng.next_dwords());
        }
    }

    // ============================================================
    //  AXIOM 2 — `_mm_sha256msg1_epu32`
    //
    //  Sha2Ni.lean::sha2.unsafe_intrinsics.sha256msg1_epu32.spec :
    //    r[k] = a[k] + σ₀(a[k+1])      for k = 0, 1, 2
    //    r[3] = a[3] + σ₀(b[0])
    // ============================================================

    fn msg1_spec(a: Dwords, b: Dwords) -> Dwords {
        [
            a[0].wrapping_add(sigma0(a[1])),
            a[1].wrapping_add(sigma0(a[2])),
            a[2].wrapping_add(sigma0(a[3])),
            a[3].wrapping_add(sigma0(b[0])),
        ]
    }

    fn msg1_hw(a: Dwords, b: Dwords) -> Dwords {
        let r = unsafe {
            _mm_sha256msg1_epu32(dwords_to_m128i(a), dwords_to_m128i(b))
        };
        m128i_to_dwords(r)
    }

    fn check_msg1(a: Dwords, b: Dwords) {
        let hw = msg1_hw(a, b);
        let sp = msg1_spec(a, b);
        assert_eq!(hw, sp,
            "sha256msg1_epu32: silicon ≠ axiom\n  a    = {:08x?}\n  b    = {:08x?}\n  hw   = {:08x?}\n  spec = {:08x?}",
            a, b, hw, sp);
    }

    #[test]
    fn sha256msg1_epu32_canonical_inputs() {
        if !is_x86_feature_detected!("sha") { eprintln!("skip: SHA not detected"); return; }

        check_msg1(
            [0xDEAD_BEEFu32, 0xCAFE_F00D, 0x1234_5678, 0x9ABC_DEF0],
            [0x1111_2222u32, 0x3333_4444, 0x5555_6666, 0x7777_8888],
        );

        // SDM: lanes 1, 2, 3 of `b` are ignored; only b[0] is used (for σ₀ of
        // the lane-3 output).  Cross-check that high lanes of b don't leak.
        let a: Dwords = [0x6A09_E667u32, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A];
        let b1: Dwords = [0x510E_527Fu32, 0xDEAD_DEAD, 0xDEAD_DEAD, 0xDEAD_DEAD];
        let b2: Dwords = [0x510E_527Fu32, 0, 0, 0];
        let h1 = msg1_hw(a, b1);
        let h2 = msg1_hw(a, b2);
        assert_eq!(h1, h2, "msg1: lanes 1..3 of b must be ignored");
    }

    #[test]
    fn sha256msg1_epu32_zero_and_max_inputs() {
        if !is_x86_feature_detected!("sha") { eprintln!("skip: SHA not detected"); return; }
        check_msg1([0; 4], [0; 4]);
        check_msg1([u32::MAX; 4], [u32::MAX; 4]);
    }

    #[test]
    fn sha256msg1_epu32_random_inputs() {
        if !is_x86_feature_detected!("sha") { eprintln!("skip: SHA not detected"); return; }
        let mut rng = SplitMix64::new(0xC0FF_EE00_BAAD_F00D);
        for _ in 0..256 {
            check_msg1(rng.next_dwords(), rng.next_dwords());
        }
    }

    // ============================================================
    //  AXIOM 3 — `_mm_sha256msg2_epu32`
    //
    //  Sha2Ni.lean::sha2.unsafe_intrinsics.sha256msg2_epu32.spec :
    //    r[0] = a[0] + σ₁(b[2])
    //    r[1] = a[1] + σ₁(b[3])
    //    r[2] = a[2] + σ₁(r[0])    -- carry from freshly computed lane 0
    //    r[3] = a[3] + σ₁(r[1])    -- carry from freshly computed lane 1
    //
    //  Note SDM: lanes 0, 1 of `b` are ignored.  We assert this by
    //  confirming that perturbing b[0] / b[1] doesn't change dst.
    // ============================================================

    fn msg2_spec(a: Dwords, b: Dwords) -> Dwords {
        let r0 = a[0].wrapping_add(sigma1(b[2]));
        let r1 = a[1].wrapping_add(sigma1(b[3]));
        let r2 = a[2].wrapping_add(sigma1(r0));
        let r3 = a[3].wrapping_add(sigma1(r1));
        [r0, r1, r2, r3]
    }

    fn msg2_hw(a: Dwords, b: Dwords) -> Dwords {
        let r = unsafe {
            _mm_sha256msg2_epu32(dwords_to_m128i(a), dwords_to_m128i(b))
        };
        m128i_to_dwords(r)
    }

    fn check_msg2(a: Dwords, b: Dwords) {
        let hw = msg2_hw(a, b);
        let sp = msg2_spec(a, b);
        assert_eq!(hw, sp,
            "sha256msg2_epu32: silicon ≠ axiom\n  a    = {:08x?}\n  b    = {:08x?}\n  hw   = {:08x?}\n  spec = {:08x?}",
            a, b, hw, sp);
    }

    #[test]
    fn sha256msg2_epu32_canonical_inputs() {
        if !is_x86_feature_detected!("sha") { eprintln!("skip: SHA not detected"); return; }

        check_msg2(
            [0xDEAD_BEEFu32, 0xCAFE_F00D, 0x1234_5678, 0x9ABC_DEF0],
            [0x1111_2222u32, 0x3333_4444, 0x5555_6666, 0x7777_8888],
        );

        // SDM: lanes 0 and 1 of `b` are ignored.  Verify that perturbing them
        // doesn't change the output.
        let a: Dwords = [0x6A09_E667u32, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A];
        let b1: Dwords = [0xDEAD_DEADu32, 0xDEAD_DEAD, 0x510E_527F, 0x9B05_688C];
        let b2: Dwords = [0u32, 0, 0x510E_527F, 0x9B05_688C];
        let h1 = msg2_hw(a, b1);
        let h2 = msg2_hw(a, b2);
        assert_eq!(h1, h2, "msg2: lanes 0..1 of b must be ignored");
    }

    #[test]
    fn sha256msg2_epu32_zero_and_max_inputs() {
        if !is_x86_feature_detected!("sha") { eprintln!("skip: SHA not detected"); return; }
        check_msg2([0; 4], [0; 4]);
        check_msg2([u32::MAX; 4], [u32::MAX; 4]);
        // Cross-lane carry edge: a = 0, b drives the σ₁ chain alone.
        check_msg2([0; 4], [0xAAAA_BBBBu32, 0xCCCC_DDDD, 0xEEEE_FFFF, 0x1234_5678]);
    }

    #[test]
    fn sha256msg2_epu32_random_inputs() {
        if !is_x86_feature_detected!("sha") { eprintln!("skip: SHA not detected"); return; }
        let mut rng = SplitMix64::new(0xFEED_FACE_5EED_5EED);
        for _ in 0..256 {
            check_msg2(rng.next_dwords(), rng.next_dwords());
        }
    }

    // ============================================================
    //  END-TO-END — a full SHA-NI-style schedule + round chain
    //
    //  Builds one quad of W[16..20] from W[0..16] using
    //  msg1 + alignr + add + msg2 in the canonical SHA-NI sequence,
    //  and cross-checks against a pure-Rust SHA-256 schedule.
    //  This catches axioms that are individually correct but compose
    //  wrongly (lane-numbering drift across calls).
    // ============================================================

    /// Pure-Rust 16-word schedule extension using the FIPS recurrence.
    /// `w[0..16]` must be filled; produces `w[16..20]`.
    fn schedule_extend(w: &mut [u32; 64]) {
        for t in 16..20 {
            w[t] = sigma1(w[t-2])
                    .wrapping_add(w[t-7])
                    .wrapping_add(sigma0(w[t-15]))
                    .wrapping_add(w[t-16]);
        }
    }

    #[test]
    fn shani_quad_schedule_chain_matches_fips() {
        if !is_x86_feature_detected!("sha") { eprintln!("skip: SHA not detected"); return; }

        // Initialize W[0..16] with a deterministic pattern.
        let mut w = [0u32; 64];
        let mut rng = SplitMix64::new(0xBEEF_F00D_C0FF_EE42);
        for i in 0..16 { w[i] = rng.next_u64() as u32; }

        // FIPS schedule: produce W[16..20] in pure Rust.
        let mut fips = w;
        schedule_extend(&mut fips);
        let expected_quad: Dwords = [fips[16], fips[17], fips[18], fips[19]];

        // SHA-NI schedule sequence for the W[16..20] quad:
        //   Given m0 = (W[0], W[1], W[2], W[3]),
        //         m1 = (W[4], W[5], W[6], W[7]),
        //         m2 = (W[8], W[9], W[10], W[11]),
        //         m3 = (W[12], W[13], W[14], W[15]),
        //   compute m_new = msg2( msg1(m0,m1) + alignr<4>(m3,m2), m3 )
        //   = the next quad W[16..20].
        let m0: Dwords = [w[0], w[1], w[2], w[3]];
        let m1: Dwords = [w[4], w[5], w[6], w[7]];
        let m2: Dwords = [w[8], w[9], w[10], w[11]];
        let m3: Dwords = [w[12], w[13], w[14], w[15]];

        // alignr<4>(a, b) per Intel SDM: shift the 32-byte concat (a:b) right by
        // 4 bytes; low 16 bytes of the result are returned.  In dword view, that
        // takes (b, a) and returns (b[1], b[2], b[3], a[0]) — i.e. shifts the
        // 8-dword window by one dword.
        let m2_aligned: Dwords = [m2[1], m2[2], m2[3], m3[0]];

        // Step 1: msg1(m0, m1) = m0[k] + σ₀(m0[k+1]) for k<3, and m0[3]+σ₀(m1[0]).
        let s_msg1 = msg1_hw(m0, m1);

        // Step 2: lane-wise add of msg1 result and the alignr<4> dword (W[t-7..t-4]).
        let s_added: Dwords = [
            s_msg1[0].wrapping_add(m2_aligned[0]),
            s_msg1[1].wrapping_add(m2_aligned[1]),
            s_msg1[2].wrapping_add(m2_aligned[2]),
            s_msg1[3].wrapping_add(m2_aligned[3]),
        ];

        // Step 3: msg2(added, m3) = the next 4 schedule words.
        let new_quad = msg2_hw(s_added, m3);

        assert_eq!(new_quad, expected_quad,
            "SHA-NI schedule quad chain disagrees with FIPS recurrence:\n  hw   = {:08x?}\n  fips = {:08x?}",
            new_quad, expected_quad);
    }
}
