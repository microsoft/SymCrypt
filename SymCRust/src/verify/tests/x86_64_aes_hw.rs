//! Differential check: the real `_mm_aes*_si128` hardware intrinsics against a
//! FIPS-197 §5 transcription — the empirical witness for the byte-carrier AES
//! axioms in `lean/Intrinsics/Axioms/{Aes,X86_64/Aes}.lean`.
//!
//! Self-contained: uses only `core::arch::x86_64::_mm_*` (silicon) plus the
//! inline FIPS-197 transcription helpers below — it does NOT `#[path]`-include
//! any `src/verify/intrinsics` shim, so it compiles and runs as an ordinary
//! integration test (no `verify` feature / proc-macro needed).
//!
//! Coverage of the shared architecture-neutral axioms
//! (`verify.intrinsics.aes.{imc, subbytes_shiftrows}`):
//!   * `aesimc_silicon_matches_fips197`          witnesses `imc` (= InvMixColumns).
//!   * `subbytes_shiftrows_silicon_matches_fips197` and
//!     `aesenclast_silicon_matches_fips197`       witness `subbytes_shiftrows`
//!     (= ShiftRows∘SubBytes, the keyless core of AESENCLAST / AESE@key=0).
//! Plus `aesenc`/`aesdec`/`aesdeclast` round witnesses.
//!
//! Run:
//!   RUSTFLAGS="-C target-feature=+aes" cargo test --features benchmarking --test x86_64_aes_hw
//! (full matrix: src/verify/tests/README.md)

#[cfg(target_arch = "x86_64")]
#[cfg(target_feature = "aes")]
mod cross {
    use core::arch::x86_64::*;

    // =========================================================================
    // FIPS-197 transcription (S-box, inverse S-box, ShiftRows, MixColumns ...).
    // Used as the spec-side oracle for cross-checking the axiomatised round
    // intrinsics against silicon.
    // =========================================================================

    const SBOX: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ];

    const INV_SBOX: [u8; 256] = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
    ];

    type State = [[u8; 4]; 4];  // state[row][col]; FIPS-197 §3.4 column-major layout

    fn from_bytes(b: [u8; 16]) -> State {
        // FIPS-197 §3.4: input s[r,c] := in[r + 4c].
        let mut s = [[0u8; 4]; 4];
        for c in 0..4 { for r in 0..4 { s[r][c] = b[r + 4 * c]; } }
        s
    }
    fn to_bytes(s: State) -> [u8; 16] {
        let mut b = [0u8; 16];
        for c in 0..4 { for r in 0..4 { b[r + 4 * c] = s[r][c]; } }
        b
    }

    fn sub_bytes(s: State)     -> State { let mut o = s; for r in 0..4 { for c in 0..4 { o[r][c] = SBOX[s[r][c] as usize];     } } o }
    fn inv_sub_bytes(s: State) -> State { let mut o = s; for r in 0..4 { for c in 0..4 { o[r][c] = INV_SBOX[s[r][c] as usize]; } } o }

    fn shift_rows(s: State) -> State {
        // FIPS-197 §5.1.2: row r is rotated LEFT by r.
        let mut o = [[0u8; 4]; 4];
        for r in 0..4 {
            for c in 0..4 { o[r][c] = s[r][(c + r) % 4]; }
        }
        o
    }
    fn inv_shift_rows(s: State) -> State {
        // FIPS-197 §5.3.1: row r is rotated RIGHT by r.
        let mut o = [[0u8; 4]; 4];
        for r in 0..4 {
            for c in 0..4 { o[r][(c + r) % 4] = s[r][c]; }
        }
        o
    }

    fn xtime(b: u8) -> u8 {
        // Multiply-by-x in GF(2^8) mod x^8+x^4+x^3+x+1.
        let hi = (b >> 7) & 1;
        (b << 1) ^ (hi.wrapping_mul(0x1B))
    }

    fn gmul(a: u8, mut b: u8) -> u8 {
        // Standard Galois multiplication via xtime-doubling.
        let mut r = 0u8;
        let mut t = a;
        while b != 0 {
            if (b & 1) != 0 { r ^= t; }
            t = xtime(t);
            b >>= 1;
        }
        r
    }

    fn mix_columns(s: State) -> State {
        // FIPS-197 §5.1.3: column c multiplied by [02 03 01 01 ; 01 02 03 01 ; 01 01 02 03 ; 03 01 01 02].
        let mut o = [[0u8; 4]; 4];
        for c in 0..4 {
            let a0 = s[0][c]; let a1 = s[1][c]; let a2 = s[2][c]; let a3 = s[3][c];
            o[0][c] = gmul(2,a0) ^ gmul(3,a1) ^ a2          ^ a3;
            o[1][c] = a0          ^ gmul(2,a1) ^ gmul(3,a2) ^ a3;
            o[2][c] = a0          ^ a1          ^ gmul(2,a2) ^ gmul(3,a3);
            o[3][c] = gmul(3,a0) ^ a1          ^ a2          ^ gmul(2,a3);
        }
        o
    }
    fn inv_mix_columns(s: State) -> State {
        // FIPS-197 §5.3.3.
        let mut o = [[0u8; 4]; 4];
        for c in 0..4 {
            let a0 = s[0][c]; let a1 = s[1][c]; let a2 = s[2][c]; let a3 = s[3][c];
            o[0][c] = gmul(0x0e,a0) ^ gmul(0x0b,a1) ^ gmul(0x0d,a2) ^ gmul(0x09,a3);
            o[1][c] = gmul(0x09,a0) ^ gmul(0x0e,a1) ^ gmul(0x0b,a2) ^ gmul(0x0d,a3);
            o[2][c] = gmul(0x0d,a0) ^ gmul(0x09,a1) ^ gmul(0x0e,a2) ^ gmul(0x0b,a3);
            o[3][c] = gmul(0x0b,a0) ^ gmul(0x0d,a1) ^ gmul(0x09,a2) ^ gmul(0x0e,a3);
        }
        o
    }

    fn xor_state(a: State, b: State) -> State {
        let mut o = [[0u8; 4]; 4];
        for r in 0..4 { for c in 0..4 { o[r][c] = a[r][c] ^ b[r][c]; } }
        o
    }

    /// AES round: SubBytes → ShiftRows → MixColumns → AddRoundKey.
    /// Intel `_mm_aesenc_si128` performs all four steps on (state, key).
    fn fips_aesenc(state: [u8; 16], key: [u8; 16]) -> [u8; 16] {
        let s = from_bytes(state);
        let k = from_bytes(key);
        to_bytes(xor_state(mix_columns(shift_rows(sub_bytes(s))), k))
    }
    /// Final AES round: SubBytes → ShiftRows → AddRoundKey (no MixColumns).
    fn fips_aesenclast(state: [u8; 16], key: [u8; 16]) -> [u8; 16] {
        let s = from_bytes(state);
        let k = from_bytes(key);
        to_bytes(xor_state(shift_rows(sub_bytes(s)), k))
    }
    /// AES decryption round (equivalent inverse cipher form, FIPS-197 §5.3.5):
    /// InvShiftRows → InvSubBytes → InvMixColumns → AddRoundKey.
    fn fips_aesdec(state: [u8; 16], key: [u8; 16]) -> [u8; 16] {
        let s = from_bytes(state);
        let k = from_bytes(key);
        to_bytes(xor_state(inv_mix_columns(inv_sub_bytes(inv_shift_rows(s))), k))
    }
    /// Final AES decryption round: InvShiftRows → InvSubBytes → AddRoundKey.
    fn fips_aesdeclast(state: [u8; 16], key: [u8; 16]) -> [u8; 16] {
        let s = from_bytes(state);
        let k = from_bytes(key);
        to_bytes(xor_state(inv_shift_rows(inv_sub_bytes(s)), k))
    }
    /// Inverse MixColumns standalone.
    fn fips_aesimc(state: [u8; 16]) -> [u8; 16] {
        to_bytes(inv_mix_columns(from_bytes(state)))
    }

    // AESKEYGENASSIST (FIPS-197 §5.2 KeyExpansion primitives), transcribed over
    // the 4 little-endian dwords of the 128-bit operand. Intel SDM `AESKEYGENASSIST`:
    //   DEST.dword0 = SubWord(X1);  DEST.dword1 = RotWord(SubWord(X1)) ^ RCON
    //   DEST.dword2 = SubWord(X3);  DEST.dword3 = RotWord(SubWord(X3)) ^ RCON
    fn sub_word(w: u32) -> u32 {
        let b = w.to_le_bytes();
        u32::from_le_bytes([SBOX[b[0] as usize], SBOX[b[1] as usize],
                            SBOX[b[2] as usize], SBOX[b[3] as usize]])
    }
    fn rot_word(w: u32) -> u32 { w.rotate_right(8) }
    fn fips_aeskeygenassist(a: [u8; 16], rcon: u8) -> [u8; 16] {
        let x1 = u32::from_le_bytes([a[4], a[5], a[6], a[7]]);
        let x3 = u32::from_le_bytes([a[12], a[13], a[14], a[15]]);
        let d0 = sub_word(x1);
        let d1 = rot_word(sub_word(x1)) ^ (rcon as u32);
        let d2 = sub_word(x3);
        let d3 = rot_word(sub_word(x3)) ^ (rcon as u32);
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&d0.to_le_bytes());
        out[4..8].copy_from_slice(&d1.to_le_bytes());
        out[8..12].copy_from_slice(&d2.to_le_bytes());
        out[12..16].copy_from_slice(&d3.to_le_bytes());
        out
    }

    // ---- silicon load/store helpers ---------------------------------------

    unsafe fn xmm_from_bytes(b: [u8; 16]) -> __m128i {
        _mm_loadu_si128(b.as_ptr() as *const __m128i)
    }
    unsafe fn xmm_to_bytes(v: __m128i) -> [u8; 16] {
        let mut out = [0u8; 16];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, v);
        out
    }

    // ---- silicon ↔ FIPS-197 transcription witnesses -----------------------

    fn arb_bytes(seed: u64) -> [u8; 16] {
        let mut s = seed | 1;
        core::array::from_fn(|_| { s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407); s as u8 })
    }

    #[test]
    fn aesenc_silicon_matches_fips197() {
        for seed in 0u64..16 {
            let state = arb_bytes(seed);
            let key   = arb_bytes(seed.wrapping_add(0xC0FFEE));
            unsafe {
                let hw = xmm_to_bytes(_mm_aesenc_si128(xmm_from_bytes(state), xmm_from_bytes(key)));
                assert_eq!(hw, fips_aesenc(state, key));
            }
        }
    }

    #[test]
    fn aesenclast_silicon_matches_fips197() {
        for seed in 0u64..16 {
            let state = arb_bytes(seed);
            let key   = arb_bytes(seed.wrapping_add(0xBEEF));
            unsafe {
                let hw = xmm_to_bytes(_mm_aesenclast_si128(xmm_from_bytes(state), xmm_from_bytes(key)));
                assert_eq!(hw, fips_aesenclast(state, key));
            }
        }
    }

    #[test]
    fn aesdec_silicon_matches_fips197() {
        for seed in 0u64..16 {
            let state = arb_bytes(seed);
            let key   = arb_bytes(seed.wrapping_add(0xDEED));
            unsafe {
                let hw = xmm_to_bytes(_mm_aesdec_si128(xmm_from_bytes(state), xmm_from_bytes(key)));
                assert_eq!(hw, fips_aesdec(state, key));
            }
        }
    }

    #[test]
    fn aesdeclast_silicon_matches_fips197() {
        for seed in 0u64..16 {
            let state = arb_bytes(seed);
            let key   = arb_bytes(seed.wrapping_add(0xFADE));
            unsafe {
                let hw = xmm_to_bytes(_mm_aesdeclast_si128(xmm_from_bytes(state), xmm_from_bytes(key)));
                assert_eq!(hw, fips_aesdeclast(state, key));
            }
        }
    }

    #[test]
    fn aesimc_silicon_matches_fips197() {
        for seed in 0u64..16 {
            let state = arb_bytes(seed);
            unsafe {
                let hw = xmm_to_bytes(_mm_aesimc_si128(xmm_from_bytes(state)));
                assert_eq!(hw, fips_aesimc(state));
            }
        }
    }

    #[test]
    fn aeskeygenassist_silicon_matches_fips197() {
        for seed in 0u64..8 {
            let a = arb_bytes(seed);
            unsafe {
                macro_rules! check { ($r:expr) => {{
                    let hw = xmm_to_bytes(_mm_aeskeygenassist_si128::<$r>(xmm_from_bytes(a)));
                    assert_eq!(hw, fips_aeskeygenassist(a, $r as u8), "rcon={:#x}", $r as u8);
                }};}
                check!(0x00); check!(0x01); check!(0x02); check!(0x04);
                check!(0x08); check!(0x10); check!(0x1B); check!(0x36); check!(0xFF);
            }
        }
    }

    /// Witnesses the keyless `verify.intrinsics.aes.subbytes_shiftrows` axiom:
    /// AESENCLAST with a zero round key is exactly ShiftRows∘SubBytes (no XOR),
    /// which is what `subbytes_shiftrows.spec` commits to.
    #[test]
    fn subbytes_shiftrows_silicon_matches_fips197() {
        for seed in 0u64..16 {
            let state = arb_bytes(seed);
            unsafe {
                let hw = xmm_to_bytes(_mm_aesenclast_si128(xmm_from_bytes(state), _mm_setzero_si128()));
                assert_eq!(hw, to_bytes(shift_rows(sub_bytes(from_bytes(state)))));
            }
        }
    }

    /// FIPS-197 §C.1: full AES-128 encryption (round 1) sanity check.
    /// Plaintext  := 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
    /// Cipher key := 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
    /// State after round 1 (= aesenc(pt ⊕ rk0, rk1)) shall be the value below.
    #[test]
    fn fips197_appendix_c_round1() {
        let rk1: [u8; 16] = [0xd6,0xaa,0x74,0xfd,0xd2,0xaf,0x72,0xfa,0xda,0xa6,0x78,0xf1,0xd6,0xab,0x76,0xfe];
        // let pt: [u8; 16]  = [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff];
        // let rk0: [u8; 16] = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f];
        // FIPS-197 §C.1 line "round[ 1].start": pt ⊕ rk0.
        let after_rk0: [u8; 16] = [0x00,0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,0x90,0xa0,0xb0,0xc0,0xd0,0xe0,0xf0];
        // "round[ 1].s_box, .s_row, .m_col" — after MixColumns at round 1.
        // FIPS-197 §C.1 last entry of round 1 is "round[ 1].k_sch" = rk1.
        // The state at "round[ 2].start" = m_col ⊕ rk1 = aesenc(after_rk0, rk1).
        let expected_round2_start: [u8; 16] = [0x89,0xd8,0x10,0xe8,0x85,0x5a,0xce,0x68,0x2d,0x18,0x43,0xd8,0xcb,0x12,0x8f,0xe4];
        unsafe {
            let v = xmm_to_bytes(_mm_aesenc_si128(xmm_from_bytes(after_rk0), xmm_from_bytes(rk1)));
            assert_eq!(v, expected_round2_start, "silicon failed FIPS-197 §C.1 round 1");
            assert_eq!(fips_aesenc(after_rk0, rk1), expected_round2_start, "transcription failed FIPS-197 §C.1 round 1");
            // And the equality the Phase-4 axiom asserts:
            assert_eq!(v, fips_aesenc(after_rk0, rk1));
        }
    }
}
