// EXPERIMENTAL CODE --- NOT YET INTEGRATED WITH SYMCRYPT
//
// keccak_opt.rs   Optimized scalar Keccak-f[1600] permutation
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Optimizations over sha3_impl.rs keccak_permute:
// 1. Fused θ+ρ+π: compute rot(s[src] ^ D[col], rho_k[src]) in one pass,
//    eliminating the theta write-back (saves ~25 loads + 25 stores per round).
// 2. Interleaved chi with save-ahead: apply chi row-by-row immediately after
//    computing each row's rho+pi temps, reducing peak register pressure from
//    ~30 to ~16 live values.
// 3. All state in local variables: help LLVM's register allocator by using
//    25 named locals instead of indexing into &mut [u64; 25].
//

#![allow(dead_code)]

use super::sha3_impl::KECCAK_IOTA_K;

type Keccak1600 = [u64; 25];

/// Optimized Keccak-f[1600] permutation.
#[inline(never)]
pub(crate) fn keccak_permute_opt(state: &mut Keccak1600) {
    // Load entire state into locals — gives LLVM maximum register freedom.
    let (mut s0,  mut s1,  mut s2,  mut s3,  mut s4 ) =
        (state[ 0], state[ 1], state[ 2], state[ 3], state[ 4]);
    let (mut s5,  mut s6,  mut s7,  mut s8,  mut s9 ) =
        (state[ 5], state[ 6], state[ 7], state[ 8], state[ 9]);
    let (mut s10, mut s11, mut s12, mut s13, mut s14) =
        (state[10], state[11], state[12], state[13], state[14]);
    let (mut s15, mut s16, mut s17, mut s18, mut s19) =
        (state[15], state[16], state[17], state[18], state[19]);
    let (mut s20, mut s21, mut s22, mut s23, mut s24) =
        (state[20], state[21], state[22], state[23], state[24]);

    for round in 0..24 {
        // ── θ: column parities → D values ──
        let c0 = s0 ^ s5 ^ s10 ^ s15 ^ s20;
        let c1 = s1 ^ s6 ^ s11 ^ s16 ^ s21;
        let c2 = s2 ^ s7 ^ s12 ^ s17 ^ s22;
        let c3 = s3 ^ s8 ^ s13 ^ s18 ^ s23;
        let c4 = s4 ^ s9 ^ s14 ^ s19 ^ s24;

        let d0 = c4 ^ c1.rotate_left(1);
        let d1 = c0 ^ c2.rotate_left(1);
        let d2 = c1 ^ c3.rotate_left(1);
        let d3 = c2 ^ c4.rotate_left(1);
        let d4 = c3 ^ c0.rotate_left(1);

        // ── Fused θ+ρ+π with interleaved χ ──
        // Each row: compute 5 rho+pi temps from (state ^ D), apply chi, store back.
        // Save-ahead pattern pre-computes values from positions that chi will overwrite.

        // Row 0 temps: from s[0,6,12,18,24]
        let t0  =  s0 ^ d0;                         // rot 0
        let t1  = (s6 ^ d1).rotate_left(44);
        let t2  = (s12 ^ d2).rotate_left(43);
        let t3  = (s18 ^ d3).rotate_left(21);
        let t4  = (s24 ^ d4).rotate_left(14);

        // Save-ahead: values from s[1..4] that chi row 0 will overwrite
        let t5  = (s3 ^ d3).rotate_left(28);    // row 1 needs s[3]
        let t10 = (s1 ^ d1).rotate_left(1);     // row 2 needs s[1]
        let t15 = (s4 ^ d4).rotate_left(27);    // row 3 needs s[4]
        let t20 = (s2 ^ d2).rotate_left(62);    // row 4 needs s[2]

        // Chi row 0 → s[0..4]
        s0 = t0 ^ (!t1 & t2);
        s1 = t1 ^ (!t2 & t3);
        s2 = t2 ^ (!t3 & t4);
        s3 = t3 ^ (!t4 & t0);
        s4 = t4 ^ (!t0 & t1);

        // Row 1 temps: from s[9,10,16,22] + saved t5
        let t6  = (s9  ^ d4).rotate_left(20);
        let t7  = (s10 ^ d0).rotate_left(3);
        let t8  = (s16 ^ d1).rotate_left(45);
        let t9  = (s22 ^ d2).rotate_left(61);

        // Save-ahead: values from s[5..9] needed later
        let t11 = (s7  ^ d2).rotate_left(6);    // row 2 needs s[7]
        let t16 = (s5  ^ d0).rotate_left(36);   // row 3 needs s[5]
        let t21 = (s8  ^ d3).rotate_left(55);   // row 4 needs s[8]

        // Chi row 1 → s[5..9]
        s5 = t5 ^ (!t6 & t7);
        s6 = t6 ^ (!t7 & t8);
        s7 = t7 ^ (!t8 & t9);
        s8 = t8 ^ (!t9 & t5);
        s9 = t9 ^ (!t5 & t6);

        // Row 2 temps: from s[13,19,20] + saved t10,t11
        let t12 = (s13 ^ d3).rotate_left(25);
        let t13 = (s19 ^ d4).rotate_left(8);
        let t14 = (s20 ^ d0).rotate_left(18);

        // Save-ahead: values from s[10..14] needed later
        let t17 = (s11 ^ d1).rotate_left(10);   // row 3 needs s[11]
        let t22 = (s14 ^ d4).rotate_left(39);   // row 4 needs s[14]

        // Chi row 2 → s[10..14]
        s10 = t10 ^ (!t11 & t12);
        s11 = t11 ^ (!t12 & t13);
        s12 = t12 ^ (!t13 & t14);
        s13 = t13 ^ (!t14 & t10);
        s14 = t14 ^ (!t10 & t11);

        // Row 3 temps: from s[17,23] + saved t15,t16,t17
        let t18 = (s17 ^ d2).rotate_left(15);
        let t19 = (s23 ^ d3).rotate_left(56);

        // Save-ahead: value from s[15..19] needed by row 4
        let t23 = (s15 ^ d0).rotate_left(41);   // row 4 needs s[15]

        // Chi row 3 → s[15..19]
        s15 = t15 ^ (!t16 & t17);
        s16 = t16 ^ (!t17 & t18);
        s17 = t17 ^ (!t18 & t19);
        s18 = t18 ^ (!t19 & t15);
        s19 = t19 ^ (!t15 & t16);

        // Row 4 temps: from s[21] + saved t20,t21,t22,t23
        let t24 = (s21 ^ d1).rotate_left(2);

        // Chi row 4 → s[20..24]
        s20 = t20 ^ (!t21 & t22);
        s21 = t21 ^ (!t22 & t23);
        s22 = t22 ^ (!t23 & t24);
        s23 = t23 ^ (!t24 & t20);
        s24 = t24 ^ (!t20 & t21);

        // ι
        s0 ^= KECCAK_IOTA_K[round];
    }

    // Store back
    *state = [
        s0,  s1,  s2,  s3,  s4,
        s5,  s6,  s7,  s8,  s9,
        s10, s11, s12, s13, s14,
        s15, s16, s17, s18, s19,
        s20, s21, s22, s23, s24,
    ];
}

// ---------------------------------------------------------------------------
// Public benchmarking wrapper
// ---------------------------------------------------------------------------

#[cfg(any(feature = "benchmarking", test))]
#[inline(always)]
pub fn keccak_permute_opt_pub_wrapper(p_state: &mut Keccak1600) {
    keccak_permute_opt(p_state);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha3::sha3_impl::keccak_permute_pub_wrapper;

    #[test]
    fn test_keccak_opt_matches_original() {
        for seed in 0u64..16 {
            let mut original = [0u64; 25];
            let mut optimized = [0u64; 25];
            for i in 0..25 {
                let v = seed.wrapping_mul(0x9E3779B97F4A7C15)
                    .wrapping_add(i as u64);
                original[i] = v;
                optimized[i] = v;
            }
            keccak_permute_pub_wrapper(&mut original);
            keccak_permute_opt(&mut optimized);
            assert_eq!(original, optimized,
                "Optimized scalar mismatch at seed={}", seed);
        }
    }

    #[test]
    fn test_keccak_opt_multiple_rounds() {
        let mut original = [0u64; 25];
        let mut optimized = [0u64; 25];
        for i in 0..25 {
            original[i] = (i as u64) * 0xDEADBEEFCAFE;
            optimized[i] = original[i];
        }
        for _ in 0..10 {
            keccak_permute_pub_wrapper(&mut original);
            keccak_permute_opt(&mut optimized);
            assert_eq!(original, optimized);
        }
    }
}
