//
// ntt.rs   ML-KEM primitives taken from SymCrypt, rewritten in Rust
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

//
// ML-KEM (also known as Kyber) and ML-DSA (also known as Dilithium) are Post-Quantum algorithms based on the
// Learning-With-Errors problem over Module Lattices (or the hardness of the M-LWE problem).
//
// A Module is a generalization of a Vector Space, where the scalars are defined over a Ring instead of a Field.
// We refer to Module as MLWE in the below types to avoid naming confusion with Module as in "FIPS module".
// Though technically components acting on MLWE types could be used outside of the MLWE problem, these types
// are SymCrypt-internal, and are only currently intended for use in these MLWE-based algorithms.
//
// In ML-KEM and ML-DSA, the underlying Ring of the Module is a Polynomial Ring. That is, elements of the
// vectors and matrices of the modules are polynomials.
// For both schemes, the polynomial ring is defined modulo the polynomial (X^256 + 1). This means there is a
// representative of each polynomial ring element with 256 coefficients (c_255*X^255 + c_254*X^254 + ... + c_0).
// The coefficients themselves are modulo a small prime in both schemes. For ML-KEM the small prime is 3329
// (12-bits), and for ML-DSA the small prime is 8380417 (23-bits).
// Additionally, for both schemes there is a Number Theoretic Transform (NTT) which maps polynomial ring elements
// to a corresponding ring for efficient multiplication.
// The in-memory representation of a polynomial ring element uses the same struct regardless of whether it is in
// standard form, or the NTT form. For brevity we tend to refer to polynomial ring elements as PolyElements.
//

use crate::common::*;
use super::hash;
use super::key::*;
use core::cmp::min;



//=====================================================
//  ML-KEM internal high level types
//

pub(super) type PolyElementAccumulator = [u32; MLWE_POLYNOMIAL_COEFFICIENTS];

// Currently minimum size of MLKEM matrices is baked in, they are always square and at least 2x2.
pub(super) const MATRIX_MIN_NROWS: usize = 2;
// Currently maximum size of MLKEM matrices is baked in, they are always square and up to 4x4.
pub(super) const MATRIX_MAX_NROWS: usize = 4;

//=====================================================
//  ML-KEM primitives
//

pub(super) const Q: u32 = 3329;

// Note (Rust): caller allocates these temporaries whichever way they want, and passes us a mutable
// reference to such a struct. If we need to use several fields at once, we can use a `ref mut`
// pattern in Rust.
pub(super) struct InternalComputationTemporaries {
    pub(super) max_size_vector0: [PolyElement; MATRIX_MAX_NROWS],
    pub(super) max_size_vector1: [PolyElement; MATRIX_MAX_NROWS],
    pub(super) poly_element0: PolyElement,
    pub(super) poly_element1: PolyElement,
    pub(super) poly_element_accumulator: PolyElementAccumulator,
    pub(super) hash_state0: hash::MlKemHashState,
    pub(super) hash_state1: hash::MlKemHashState,
}

unsafe impl crate::common::BoxDefault for InternalComputationTemporaries {
    unsafe fn box_default(_ptr: *mut Self) {
        // All fields are default 0 (MlKemHashState defaults to the 0 value in its enum).
        // Could technically use try_alloc_zeroed instead of implementing the trait, but
        // this is a little bit easier to reason about given it is not obvious at first glance that
        // this struct can be zero-allocated.
    }
}

//
// ML-KEM operations acting on individual polynomial ring elements (PolyElements)
//

//
// See ML-KEM Polynomial Ring Element Decode and Decompress
//
//
// Current approach is to represent polynomial ring elements as a 512-byte buffer (256 UINT16s).
//

// Coefficients are added and subtracted when polynomials are in the NTT domain and in the lattice domain.
//
// Coefficients are only multiplied in the NTT/INTT operations, and in MulAdd which only operates on
// polynomials in NTT form.
// We choose to perform modular multiplication exclusively using Montgomery multiplication, that is, we choose
// a Montgomery divisor R, and modular multiplication always divides by R, as this make reduction logic easy
// and quick.
// i.e. MontMul(a,b) -> ((a*b) / R) mod Q
//
// For powers of Zeta used in as multiplication twiddle factors in NTT/INTT and base polynomial multiplication,
// we pre-multiply the constants by R s.t.
//  MontMul(x, twiddleForZetaToTheK) -> x*(Zeta^K) mod Q.
//
// Most other modular multiplication can be done with a fixup deferred until the INTT. The one exception is in key
// generation, where A o s + e = t, we need to pre-multiply s'

// R = 2^16
const RLOG2: u32 = 16;
const RMASK: u32 = 0xffff;

// NegQInvModR = -Q^(-1) mod R
const NEG_Q_INV_MOD_R: u32 = 3327;

// Rsqr = R^2 = (1<<32) mod Q
const RSQR: u32 = 1353;
// RsqrTimesNegQInvModR = R^2 = ((1<<32) mod Q) * -Q^(-1) mod R
const RSQR_TIMES_NEG_Q_INV_MOD_R: u32 = 44983;

//
// Zeta tables.
// Zeta = 17, which is a primitive 256-th root of unity modulo Q
//
// In ML-KEM we use powers of zeta to convert to and from NTT form
// and to perform multiplication between polynomials in NTT form
//

// This table is a lookup for (Zeta^(BitRev(index)) * R) mod Q
// Used in NTT and INTT
// i.e. element 1 is Zeta^(BitRev(1)) * (2^16) mod Q == (17^64)*(2^16) mod 3329 == 2571
//
// MlKemZetaBitRevTimesR = [ (pow(17, bitRev(i), 3329) << 16) % 3329 for i in range(128) ]
#[rustfmt::skip]
pub(super) const ZETA_BIT_REV_TIMES_R: [u16; 128] = [
    2285, 2571, 2970, 1812, 1493, 1422,  287,  202,
    3158,  622, 1577,  182,  962, 2127, 1855, 1468,
     573, 2004,  264,  383, 2500, 1458, 1727, 3199,
    2648, 1017,  732,  608, 1787,  411, 3124, 1758,
    1223,  652, 2777, 1015, 2036, 1491, 3047, 1785,
     516, 3321, 3009, 2663, 1711, 2167,  126, 1469,
    2476, 3239, 3058,  830,  107, 1908, 3082, 2378,
    2931,  961, 1821, 2604,  448, 2264,  677, 2054,
    2226,  430,  555,  843, 2078,  871, 1550,  105,
     422,  587,  177, 3094, 3038, 2869, 1574, 1653,
    3083,  778, 1159, 3182, 2552, 1483, 2727, 1119,
    1739,  644, 2457,  349,  418,  329, 3173, 3254,
     817, 1097,  603,  610, 1322, 2044, 1864,  384,
    2114, 3193, 1218, 1994, 2455,  220, 2142, 1670,
    2144, 1799, 2051,  794, 1819, 2475, 2459,  478,
    3221, 3021,  996,  991,  958, 1869, 1522, 1628,
];

// This table is a lookup for ((Zeta^(BitRev(index)) * R) mod Q) * -Q^(-1) mod R
// Used in NTT and INTT
//
// MlKemZetaBitRevTimesRTimesNegQInvModR = [ (((pow(17, bitRev(i), Q) << 16) % Q) * 3327) & 0xffff for i in range(128) ]
#[rustfmt::skip]
pub(super) const ZETA_BIT_REV_TIMES_R_TIMES_NEG_Q_INV_MOD_R: [u16; 128] = [
       19, 34037, 50790, 64748, 52011, 12402, 37345, 16694,
    20906, 37778,  3799, 15690, 54846, 64177, 11201, 34372,
     5827, 48172, 26360, 29057, 59964,  1102, 44097, 26241,
    28072, 41223, 10532, 56736, 47109, 56677, 38860, 16162,
     5689,  6516, 64039, 34569, 23564, 45357, 44825, 40455,
    12796, 38919, 49471, 12441, 56401,   649, 25986, 37699,
    45652, 28249, 15886,  8898, 28309, 56460, 30198, 47286,
    52109, 51519, 29155, 12756, 48704, 61224, 24155, 17914,
      334, 54354, 11477, 52149, 32226, 14233, 45042, 21655,
    27738, 52405, 64591,  4586, 14882, 42443, 59354, 60043,
    33525, 32502, 54905, 35218, 36360, 18741, 28761, 52897,
    18485, 45436, 47975, 47011, 14430, 46007,  5275, 12618,
    31183, 45239, 40101, 63390,  7382, 50180, 41144, 32384,
    20926,  6279, 54590, 14902, 41321, 11044, 48546, 51066,
    55200, 21497,  7933, 20198, 22501, 42325, 54629, 17442,
    33899, 23859, 36892, 20257, 41538, 57779, 17422, 42404,
];

// This table is a lookup for ((Zeta^(2*BitRev(index) + 1) * R) mod Q)
// Used in multiplication of 2 NTT-form polynomials
//
// zetaTwoTimesBitRevPlus1TimesR =  [ (pow(17, 2*bitRev(i)+1, 3329) << 16) % 3329 for i in range(128) ]
#[rustfmt::skip]
const ZETA_TWO_TIMES_BIT_REV_PLUS_1_TIMES_R: [u16; 128] = [
    2226, 1103,  430, 2899,  555, 2774,  843, 2486,
    2078, 1251,  871, 2458, 1550, 1779,  105, 3224,
     422, 2907,  587, 2742,  177, 3152, 3094,  235,
    3038,  291, 2869,  460, 1574, 1755, 1653, 1676,
    3083,  246,  778, 2551, 1159, 2170, 3182,  147,
    2552,  777, 1483, 1846, 2727,  602, 1119, 2210,
    1739, 1590,  644, 2685, 2457,  872,  349, 2980,
     418, 2911,  329, 3000, 3173,  156, 3254,   75,
     817, 2512, 1097, 2232,  603, 2726,  610, 2719,
    1322, 2007, 2044, 1285, 1864, 1465,  384, 2945,
    2114, 1215, 3193,  136, 1218, 2111, 1994, 1335,
    2455,  874,  220, 3109, 2142, 1187, 1670, 1659,
    2144, 1185, 1799, 1530, 2051, 1278,  794, 2535,
    1819, 1510, 2475,  854, 2459,  870,  478, 2851,
    3221,  108, 3021,  308,  996, 2333,  991, 2338,
     958, 2371, 1869, 1460, 1522, 1807, 1628, 1701,
];

#[inline(always)]
fn mod_reduce(a: u32) -> u32 {
    debug_assert!(a < 2 * Q);

    // In the comments below, we manipulate unbounded integers.
    // res = a - Q
    let res = a.wrapping_sub(Q); // -Q <= res < Q
    debug_assert!(((res >> 16) == 0) || ((res >> 16) == 0xffff));
    // If res < 0, then: Q & (res >> 16) = Q
    // Otherwise: Q & (res >> 16) = 0
    let res = res.wrapping_add(Q & (res >> 16));
    // 0 <= res < 2 * Q
    debug_assert!(res < Q);

    res
}

#[inline(always)]
fn mod_add(a: u32, b: u32) -> u32 {
    debug_assert!(a < Q);
    debug_assert!(b < Q);

    mod_reduce(a + b)
}

#[inline(always)]
fn mod_sub(a: u32, b: u32) -> u32 {
    debug_assert!(a < Q);
    debug_assert!(b < Q);

    // In the comments below, we manipulate unbounded integers.
    // res = a - b
    let res = a.wrapping_sub(b); // -Q < res < Q
    debug_assert!(((res >> 16) == 0) || ((res >> 16) == 0xffff));
    // If res < 0, then: Q & (res >> 16) = Q
    // Otherwise: Q & (res >> 16) = 0
    let res = res.wrapping_add(Q & (res >> 16));
    // 0 <= res < 2 * Q
    debug_assert!(res < Q);

    res
}

#[inline(always)]
fn mont_mul(a: u32, b: u32, b_mont: u32) -> u32 {
    debug_assert!(a < Q);
    debug_assert!(b < Q);
    debug_assert!(b_mont <= RMASK);
    debug_assert!(b_mont == ((b * NEG_Q_INV_MOD_R) & RMASK));

    let mut res = a * b;
    let inv = (a * b_mont) & RMASK;
    res += inv * Q;
    debug_assert!((res & RMASK) == 0);
    res >>= RLOG2;

    mod_reduce(res)
}

trait NttIntrinsicsInterface {
    type Vec128: Copy;

    fn vec128_load_u16x8(elem: &PolyElement, index: usize) -> Self::Vec128;
    fn vec64_load_u16x4(elem: &PolyElement, index: usize) -> Self::Vec128;
    fn vec32_load_u16x2(elem: &PolyElement, index: usize) -> Self::Vec128;

    fn vec128_store_u16x8(elem: &mut PolyElement, index: usize, val: Self::Vec128);
    fn vec64_store_u16x4(elem: &mut PolyElement, index: usize, val: Self::Vec128);
    fn vec32_store_u16x2(elem: &mut PolyElement, index: usize, val: Self::Vec128);

    fn vec128_set_u16x8(val: u16) -> Self::Vec128;

    fn vec128_mod_sub(a: Self::Vec128, b: Self::Vec128) -> Self::Vec128;
    fn vec128_mod_add(a: Self::Vec128, b: Self::Vec128) -> Self::Vec128;
    fn vec128_mont_mul(a: Self::Vec128, b: Self::Vec128, b_mont: Self::Vec128) -> Self::Vec128;
}


#[cfg(any(feature = "verify", target_arch = "x86_64", target_arch = "x86"))]
#[path = "ntt_xmm.rs"]
mod ntt_xmm;
#[cfg(any(feature = "verify", target_arch = "aarch64"))]
#[path = "ntt_neon.rs"]
mod ntt_neon;

#[cfg(any(feature = "verify", target_arch = "x86_64"))]
#[path = "ntt_avx2.rs"]
mod ntt_avx2;


fn poly_element_ntt_layer_vec128<T: NttIntrinsicsInterface>(pe_src: &mut PolyElement, mut k: usize, len: usize) {
    for start in (0usize..256).step_by(2*len) {
        let v_twiddle_factor      = T::vec128_set_u16x8( ZETA_BIT_REV_TIMES_R[k] );
        let v_twiddle_factor_mont = T::vec128_set_u16x8( ZETA_BIT_REV_TIMES_R_TIMES_NEG_Q_INV_MOD_R[k] );
        k += 1;

        for j in (0usize..len).step_by(8) {
            let mut v_c0 : T::Vec128;
            let mut v_c1 : T::Vec128;
            if len >= 8 {
                v_c0 = T::vec128_load_u16x8( pe_src, start+j );
                v_c1 = T::vec128_load_u16x8( pe_src, start+j+len );
            } else if len == 4 {
                v_c0 = T::vec64_load_u16x4( pe_src, start+j );
                v_c1 = T::vec64_load_u16x4( pe_src, start+j+len );
            } else /*if ( len == 2 )*/ {
                v_c0 = T::vec32_load_u16x2( pe_src, start+j );
                v_c1 = T::vec32_load_u16x2( pe_src, start+j+len );
            }

            // c1TimesTwiddle = twiddleFactor * c1 mod Q;
            let v_c1_times_twiddle = T::vec128_mont_mul( v_c1, v_twiddle_factor, v_twiddle_factor_mont );
            // c1 = c0 - c1TimesTwiddle mod Q
            v_c1 = T::vec128_mod_sub( v_c0, v_c1_times_twiddle );
            // c0 = c0 + c1TimesTwiddle mod Q
            v_c0 = T::vec128_mod_add( v_c0, v_c1_times_twiddle );

            if len >= 8 {
                T::vec128_store_u16x8( pe_src, start+j,     v_c0 );
                T::vec128_store_u16x8( pe_src, start+j+len, v_c1 );
            } else if len == 4 {
                T::vec64_store_u16x4( pe_src, start+j,     v_c0 );
                T::vec64_store_u16x4( pe_src, start+j+len, v_c1 );
            } else /*if ( len == 2 )*/ {
                T::vec32_store_u16x2( pe_src, start+j,     v_c0 );
                T::vec32_store_u16x2( pe_src, start+j+len, v_c1 );
            }
        }
    }
}

fn poly_element_ntt_layer_generic(pe_src: &mut PolyElement, mut k: usize, len: usize) {
    for start in (0usize..256).step_by(2*len) {
        let twiddle_factor: u32 = ZETA_BIT_REV_TIMES_R[k].into();
        let twiddle_factor_mont: u32 = ZETA_BIT_REV_TIMES_R_TIMES_NEG_Q_INV_MOD_R[k].into();
        k += 1;

        for j in 0usize..len {
            let mut c0: u32 = pe_src[start+j].into();
            debug_assert!( c0 < Q );
            let mut c1: u32 = pe_src[start+j+len].into();
            debug_assert!( c1 < Q );

            let c1_times_twiddle: u32 = mont_mul( c1, twiddle_factor, twiddle_factor_mont );
            c1 = mod_sub( c0, c1_times_twiddle );
            c0 = mod_add( c0, c1_times_twiddle );

            pe_src[start+j]      = c0 as u16;
            pe_src[start+j+len]  = c1 as u16;
        }
    }
}

fn poly_element_intt_layer_vec128<T: NttIntrinsicsInterface>(pe_src: &mut PolyElement, mut k: usize, len: usize) {
    for start in (0usize..256).step_by(2*len) {
        let v_twiddle_factor      = T::vec128_set_u16x8( ZETA_BIT_REV_TIMES_R[k] );
        let v_twiddle_factor_mont = T::vec128_set_u16x8( ZETA_BIT_REV_TIMES_R_TIMES_NEG_Q_INV_MOD_R[k] );
        k -= 1;

        for j in (0usize..len).step_by(8) {
            let v_c0 : T::Vec128;
            let mut v_c1 : T::Vec128;
            if len >= 8 {
                v_c0 = T::vec128_load_u16x8( pe_src, start+j );
                v_c1 = T::vec128_load_u16x8( pe_src, start+j+len );
            } else if len == 4 {
                v_c0 = T::vec64_load_u16x4( pe_src, start+j );
                v_c1 = T::vec64_load_u16x4( pe_src, start+j+len );
            } else /*if ( len == 2 )*/ {
                v_c0 = T::vec32_load_u16x2( pe_src, start+j );
                v_c1 = T::vec32_load_u16x2( pe_src, start+j+len );
            }

            // tmp = c0 + c1 mod Q
            let v_tmp = T::vec128_mod_add( v_c0, v_c1 );
            // c1 = c1 - c0 mod Q
            v_c1 = T::vec128_mod_sub( v_c1, v_c0 );
            // c1 = twiddleFactor * c1 mod Q
            v_c1 = T::vec128_mont_mul( v_c1, v_twiddle_factor, v_twiddle_factor_mont );

            if len >= 8 {
                T::vec128_store_u16x8( pe_src, start+j,     v_tmp );
                T::vec128_store_u16x8( pe_src, start+j+len, v_c1 );
            } else if len == 4 {
                T::vec64_store_u16x4( pe_src, start+j,     v_tmp );
                T::vec64_store_u16x4( pe_src, start+j+len, v_c1 );
            } else /*if ( len == 2 )*/ {
                T::vec32_store_u16x2( pe_src, start+j,     v_tmp );
                T::vec32_store_u16x2( pe_src, start+j+len, v_c1 );
            }
        }
    }
}

fn poly_element_intt_layer_generic(pe_src: &mut PolyElement, mut k: usize, len: usize) {
    for start in (0usize..256).step_by(2*len) {
        let twiddle_factor: u32 = ZETA_BIT_REV_TIMES_R[k].into();
        let twiddle_factor_mont: u32 = ZETA_BIT_REV_TIMES_R_TIMES_NEG_Q_INV_MOD_R[k].into();
        k -= 1;

        for j in 0usize..len {
            let c0: u32 = pe_src[start+j].into();
            debug_assert!( c0 < Q );
            let mut c1: u32 = pe_src[start+j+len].into();
            debug_assert!( c1 < Q );

            let tmp = mod_add( c0, c1 );
            c1 = mod_sub( c1, c0 );
            c1 = mont_mul( c1, twiddle_factor, twiddle_factor_mont );

            pe_src[start+j]      = tmp as u16;
            pe_src[start+j+len]  = c1 as u16;
        }
    }
}

#[inline(always)]
fn poly_element_ntt_layer(pe_src: &mut PolyElement, k: usize, len: usize) {
    // AVX2 fast path currently disabled
    // #[cfg(all(target_arch = "x86_64", feature = "std"))]
    // if len >= 16 && cpu_features_present(SYMCRYPT_CPU_FEATURE_AVX2) {
    //   unsafe { ntt_avx2::ntt_layer_avx2(pe_src, k, len); }
    //   return;
    // }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if cpu_features_present(SYMCRYPT_CPU_FEATURE_SSE2) {
            poly_element_ntt_layer_vec128::<ntt_xmm::NttIntrinsicsXmm>(pe_src, k, len);
            return;
        } 
    }

    #[cfg(target_arch = "aarch64")]
    {
        if cpu_features_present(SYMCRYPT_CPU_FEATURE_NEON) {
            poly_element_ntt_layer_vec128::<ntt_neon::NttIntrinsicsNeon>(pe_src, k, len);
            return;
        }
    }
    poly_element_ntt_layer_generic(pe_src, k, len);
}

#[inline(always)]
fn poly_element_intt_layer(pe_src: &mut PolyElement, k: usize, len: usize) {
    // AVX2 fast path currently disabled
    // #[cfg(all(target_arch = "x86_64", feature = "std"))]
    // if len >= 16 && cpu_features_present(SYMCRYPT_CPU_FEATURE_AVX2) {
    //   unsafe { ntt_avx2::intt_layer_avx2(pe_src, k, len); }
    //   return;
    // }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if cpu_features_present(SYMCRYPT_CPU_FEATURE_SSE2) {
        poly_element_intt_layer_vec128::<ntt_xmm::NttIntrinsicsXmm>(pe_src, k, len);
        return;
    }
    #[cfg(target_arch = "aarch64")]
    if cpu_features_present(SYMCRYPT_CPU_FEATURE_NEON) {
        poly_element_intt_layer_vec128::<ntt_neon::NttIntrinsicsNeon>(pe_src, k, len);
        return;
    }
    poly_element_intt_layer_generic(pe_src, k, len);
}

const MAX_COEFF: u32                = Q-1;
const MAX_COEFF_PRODUCT: u32        = MAX_COEFF*MAX_COEFF;

// max([ ((i*j) + ((((i*j)*NegQInvModR) & Rmask)*Q)) >> Rlog2 for i in range(Q) for j in range(Q) ])
const MAX_FIRST_STEP_REDUCTION: u32 = 3494;
// max([ ( pow(17, (2*i)+1, Q) << Rlog2 ) % Q for i in range(128) ])
const MAX_ZETA_TWO_TIMES_BIT_REV_PLUS_1_TIMES_R: u32 = 3254;
const MAX_A1_B1_ZETA_POW: u32       = MAX_FIRST_STEP_REDUCTION*MAX_ZETA_TWO_TIMES_BIT_REV_PLUS_1_TIMES_R;

fn poly_element_mul_and_accumulate(
    pe_src1: &PolyElement,
    pe_src2: &PolyElement,
    pa_dst: &mut PolyElementAccumulator,
) {
    for i in 0usize..(MLWE_POLYNOMIAL_COEFFICIENTS / 2) {
        let a0: u32 = pe_src1[2*i].into();
        debug_assert!( a0 < Q );
        let a1: u32 = pe_src1[2*i+1].into();
        debug_assert!( a1 < Q );

        let b0: u32 = pe_src2[2*i  ].into();
        debug_assert!( b0 < Q );
        let b1: u32 = pe_src2[2*i+1].into();
        debug_assert!( b1 < Q );

        let mut c0: u32 = pa_dst[2*i];
        debug_assert!( c0 <= 3*(MAX_COEFF_PRODUCT + MAX_A1_B1_ZETA_POW) );
        let mut c1: u32 = pa_dst[(2*i)+1];
        debug_assert!( c1 <= 3*(MAX_COEFF_PRODUCT + MAX_A1_B1_ZETA_POW) );

        // multiplication results in range [0, 3328*3328]
        let mut a0b0: u32 = a0 * b0;
        let a1b1 = a1 * b1;
        let mut a0b1: u32 = a0 * b1;
        let a1b0 = a1 * b0;

        // we need a1*b1*zetaTwoTimesBitRevPlus1TimesR[i]
        // eagerly reduce a1*b1 with montgomery reduction
        // a1b1 = red(a1*b1) -> range [0, MAX_FIRST_STEP_REDUCTION = 3494]
        //   (3494 is maximum result of first step of montgomery reduction of x*y for x,y in [0,3328])
        // we do not need to do final reduction yet
        let inv : u32 = (a1b1.wrapping_mul(NEG_Q_INV_MOD_R)) & RMASK;
        let a1b1: u32 = (a1b1 + (inv * Q)) >> RLOG2; // in range [0, MAX_FIRST_STEP_REDUCTION]
        debug_assert!( a1b1 <= MAX_FIRST_STEP_REDUCTION );

        // now multiply a1b1 by power of zeta
        let a1b1zetapow = a1b1 * (ZETA_TWO_TIMES_BIT_REV_PLUS_1_TIMES_R[i] as u32);
        // MAX_ZETA_TWO_TIMES_BIT_REV_PLUS_1_TIMES_R = 3254
        // MAX_A1_B1_ZETA_POW = MAX_FIRST_STEP_REDUCTION*MAX_ZETA_TWO_TIMES_BIT_REV_PLUS_1_TIMES_R = 3494*3254
        debug_assert!( a1b1zetapow <= MAX_A1_B1_ZETA_POW );

        // sum pairs of products
        a0b0 += a1b1zetapow;    // a0*b0 + red(a1*b1)*zetapower in range [0, MAX_COEFF_PRODUCT + MAX_A1_B1_ZETA_POW]
        debug_assert!( a0b0 <= MAX_COEFF_PRODUCT + MAX_A1_B1_ZETA_POW );
        a0b1 += a1b0;           // a0*b1 + a1*b0                in range [0, 2*MAX_COEFF_PRODUCT]
        debug_assert!( a0b1 <= 2*MAX_COEFF_PRODUCT );

        // We sum at most 4 pairs of products into an accumulator in ML-KEM
        const { assert!( MATRIX_MAX_NROWS <= 4 ) }
        c0 += a0b0; // in range [0,4*MAX_COEFF_PRODUCT + 4*MAX_A1_B1_ZETA_POW]
        debug_assert!( c0 <= (4*MAX_COEFF_PRODUCT) + (4*MAX_A1_B1_ZETA_POW) );
        c1 += a0b1; // in range [0,5*MAX_COEFF_PRODUCT + 3*MAX_A1_B1_ZETA_POW]
        debug_assert!( c1 < (5*MAX_COEFF_PRODUCT) + (3*MAX_A1_B1_ZETA_POW) );

        pa_dst[2*i  ] = c0;
        pa_dst[2*i+1] = c1;
    }
}

fn montgomery_reduce_and_add_poly_element_accumulator_to_poly_element(
    pa_src: &mut PolyElementAccumulator,
    pe_dst: &mut PolyElement,
) {
    for i in 0usize..MLWE_POLYNOMIAL_COEFFICIENTS {
        let mut a: u32 = pa_src[i];
        debug_assert!( a <= 4*(MAX_COEFF_PRODUCT + MAX_A1_B1_ZETA_POW) );
        pa_src[i] = 0;

        let mut c: u32 = pe_dst[i].into();
        debug_assert!( c < Q );

        // montgomery reduce sum of products
        let inv = (a.wrapping_mul(NEG_Q_INV_MOD_R)) & RMASK;
        a = (a + (inv * Q)) >> RLOG2; // in range [0, 4698]
        debug_assert!( a <= 4698 );

        // add destination
        c += a;
        debug_assert!( c <= 8026 );

        // subtraction and conditional additions for constant time range reduction
        c = c.wrapping_sub(2*Q);           // in range [-2Q, 1368]
        debug_assert!( (c >= ((-2*(Q as i32)) as u32)) || (c <= 1368) );
        c = c.wrapping_add(Q & (c >> 16)); // in range [-Q, Q-1]
        debug_assert!( (c >= (-(Q as i32) as u32)) || (c < Q) );
        c = c.wrapping_add(Q & (c >> 16)); // in range [0, Q-1]
        debug_assert!( c < Q );

        pe_dst[i] = c as u16;
    }
}

fn poly_element_mul_r(pe_src: &PolyElement, pe_dst: &mut PolyElement) {
    for i in 0usize..MLWE_POLYNOMIAL_COEFFICIENTS {
        pe_dst[i] = mont_mul(
            pe_src[i].into(), RSQR, RSQR_TIMES_NEG_Q_INV_MOD_R ) as u16;
    }
}

pub(super) fn poly_element_add_in_place(pe_src2: &PolyElement, pe_dst: &mut PolyElement) {
    for i in 0usize..MLWE_POLYNOMIAL_COEFFICIENTS {
        pe_dst[i] = mod_add( pe_dst[i].into(), pe_src2[i].into() ) as u16;
    }
}

pub(super) fn poly_element_sub_from_in_place(
    pe_src1: &PolyElement,
    pe_dst: &mut PolyElement,
) {
    for i in 0usize..MLWE_POLYNOMIAL_COEFFICIENTS {
        pe_dst[i] = mod_sub( pe_src1[i].into(), pe_dst[i].into() ) as u16;
    }
}

pub fn poly_element_ntt(pe_src: &mut PolyElement) {
    poly_element_ntt_layer(pe_src, 1, 128);
    poly_element_ntt_layer(pe_src, 2, 64);
    poly_element_ntt_layer(pe_src, 4, 32);
    poly_element_ntt_layer(pe_src, 8, 16);
    poly_element_ntt_layer(pe_src, 16, 8);
    poly_element_ntt_layer(pe_src, 32, 4);
    poly_element_ntt_layer(pe_src, 64, 2);
}

// INTTFixupTimesRsqr = R^2 * 3303 = (3303<<32) mod Q
// 3303 constant is fixup from draft FIPS 203
// Multiplied by R^2 to additionally multiply coefficients by R after montgomery reduction
const INTT_FIXUP_TIMES_RSQR: u32 = 1441;
const INTT_FIXUP_TIMES_RSQR_TIMES_NEQ_Q_INV_MOD_R: u32 = 10079;

pub fn poly_element_intt_and_mul_r(pe_src: &mut PolyElement) {
    poly_element_intt_layer(pe_src, 127, 2);
    poly_element_intt_layer(pe_src, 63, 4);
    poly_element_intt_layer(pe_src, 31, 8);
    poly_element_intt_layer(pe_src, 15, 16);
    poly_element_intt_layer(pe_src, 7, 32);
    poly_element_intt_layer(pe_src, 3, 64);
    poly_element_intt_layer(pe_src, 1, 128);

    for coeff in pe_src.iter_mut() {
        *coeff = mont_mul(
            (*coeff).into(), INTT_FIXUP_TIMES_RSQR, INTT_FIXUP_TIMES_RSQR_TIMES_NEQ_Q_INV_MOD_R ) as u16;
    }
}

// ((1<<33) / Q) rounded to nearest integer
//
// 1<<33 is the smallest power of 2 s.t. the constant has sufficient precision to round
// all inputs correctly in compression for all n_bits_per_coefficient < 12. A smaller
// constant could be used for smaller n_bits_per_coefficient for a small performance gain
//
const COMPRESS_MULCONSTANT: u32 = 0x275f6f;
const COMPRESS_SHIFTCONSTANT: u32 = 33;

pub(super) fn poly_element_compress_and_encode(
    pe_src: &PolyElement,
    n_bits_per_coefficient: u32,
    pb_dst: &mut [u8],
) {
    let mut cb_dst_written: usize = 0;
    let mut accumulator: u32 = 0;
    let mut n_bits_in_accumulator: u32 = 0;

    debug_assert!(n_bits_per_coefficient > 0);
    debug_assert!(n_bits_per_coefficient <= 12);

    for src_coeff in pe_src.iter() {
        let mut coefficient: u32 = (*src_coeff).into(); // in range [0, Q-1]
        debug_assert!( coefficient < Q );

        // first compress the coefficient
        // when n_bits_per_coefficient < 12 we compress per Compress_d in draft FIPS 203;
        if n_bits_per_coefficient < 12
        {
            // Multiply by 2^(n_bits_per_coefficient+1) / Q by multiplying by constant and shifting right
            let multiplication: u64 = (coefficient as u64) * (COMPRESS_MULCONSTANT as u64);
            coefficient = (multiplication >> (COMPRESS_SHIFTCONSTANT-(n_bits_per_coefficient+1))) as u32;

            // add "half" to round to nearest integer
            coefficient += 1;

            // final divide by two to get multiplication by 2^n_bits_per_coefficient / Q
            coefficient >>= 1;                              // in range [0, 2^n_bits_per_coefficient]
            debug_assert!(coefficient <= (1<<n_bits_per_coefficient));

            // modular reduction by masking
            coefficient &= (1<<n_bits_per_coefficient)-1;    // in range [0, 2^n_bits_per_coefficient - 1]
            debug_assert!(coefficient <  (1<<n_bits_per_coefficient));
        }

        // encode the coefficient
        // Note that the number of bits to encode is <= 12 while the accumulator has 32 bits,
        // which means that if the accumulator is full, we only need to flush it once before
        // encoding the remaining bits.
        let n_bits_to_encode = min(n_bits_per_coefficient, 32 - n_bits_in_accumulator);
        let n_bits_in_coefficient = n_bits_per_coefficient - n_bits_to_encode;

        let bits_to_encode = coefficient & ((1<<n_bits_to_encode)-1);

        accumulator |= bits_to_encode << n_bits_in_accumulator;
        n_bits_in_accumulator += n_bits_to_encode;

        // Flush the accumulator, if necessary
        if n_bits_in_accumulator == 32
        {
            pb_dst[cb_dst_written..cb_dst_written+4].copy_from_slice(&u32::to_le_bytes(accumulator));
            cb_dst_written += 4;

            // Encode the remaining bits, if there are any
            accumulator = coefficient >> n_bits_to_encode;
            n_bits_in_accumulator = n_bits_in_coefficient;
        }
    }

    debug_assert!(n_bits_in_accumulator == 0);
    debug_assert!(
        cb_dst_written
            == (n_bits_per_coefficient * (MLWE_POLYNOMIAL_COEFFICIENTS as u32 / 8)) as usize
    );
}

#[inline(always)]
fn load_u16_le(pb_src: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(pb_src[offset..offset + 2].try_into().unwrap())
}

#[inline(always)]
fn load_u32_le(pb_src: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(pb_src[offset..offset + 4].try_into().unwrap())
}

pub(super) fn poly_element_decode_and_decompress(
    // _In_reads_bytes_(n_bits_per_coefficient*(MLWE_POLYNOMIAL_COEFFICIENTS / 8))
    pb_src: &[u8],
    n_bits_per_coefficient: u32,
    pe_dst: &mut PolyElement,
) -> Error {
    let mut cb_src_read: usize = 0;
    let mut accumulator: u32 = 0;
    let mut n_bits_in_accumulator: u32 = 0;

    debug_assert!(n_bits_per_coefficient > 0);
    debug_assert!(n_bits_per_coefficient <= 12);

    for dst_coeff in pe_dst.iter_mut() {
        let mut coefficient = 0;
        let mut n_bits_in_coefficient = 0;

        // first gather and decode bits from pb_src
        while n_bits_per_coefficient > n_bits_in_coefficient
        {
            if n_bits_in_accumulator == 0
            {
                accumulator = load_u32_le(pb_src, cb_src_read);
                cb_src_read += 4;
                n_bits_in_accumulator = 32;
            }

            let n_bits_to_decode = min(n_bits_per_coefficient-n_bits_in_coefficient, n_bits_in_accumulator);
            debug_assert!(n_bits_to_decode <= n_bits_in_accumulator);

            let bits_to_decode = accumulator & ((1<<n_bits_to_decode)-1);
            accumulator >>= n_bits_to_decode;
            n_bits_in_accumulator -= n_bits_to_decode;

            coefficient |= bits_to_decode << n_bits_in_coefficient;
            n_bits_in_coefficient += n_bits_to_decode;
        }
        debug_assert!(n_bits_in_coefficient == n_bits_per_coefficient);

        // decompress the coefficient
        // when n_bits_per_coefficient < 12 we decompress per Decompress_d in draft FIPS 203
        // otherwise we perform input validation per 203 6.2 Input validation 2 (Modulus check)
        if n_bits_per_coefficient < 12
        {
            // Multiply by Q / 2^(n_bits_per_coefficient-1) by multiplying by constant and shifting right
            coefficient *= Q;
            coefficient >>= n_bits_per_coefficient-1;

            // add "half" to round to nearest integer
            coefficient += 1;

            // final divide by two to get multiplication by Q / 2^n_bits_per_coefficient
            coefficient >>= 1;  // in range [0, Q]

            // modular reduction by conditional subtraction
            coefficient = mod_reduce( coefficient );
            debug_assert!( coefficient < Q );
        }
        else if coefficient >= Q
        {
            // input validation failure - this can happen with a malformed or corrupt encapsulation
            // or decapsulation key, but this validation failure only triggers on public data; we
            // do not need to be constant time
            return Error::InvalidBlob;
        }

        *dst_coeff = coefficient as u16;
    }

    debug_assert!(n_bits_in_accumulator == 0);
    debug_assert!(
        cb_src_read
            == (n_bits_per_coefficient * (MLWE_POLYNOMIAL_COEFFICIENTS as u32 / 8)) as usize
    );

    Error::NoError
}

pub(super) fn poly_element_sample_ntt_from_shake128(
    p_state: &mut hash::MlKemHashState,
    pe_dst: &mut PolyElement,
) {
    let mut i: usize = 0;
    let mut shake_output_buf = [0u8; 3 * 8]; // Keccak likes extracting multiples of 8-bytes
    let mut curr_buf_index: usize = shake_output_buf.len();

    debug_assert!(p_state.get_alg() == hash::MlKemHashAlg::Shake128);

    while i < MLWE_POLYNOMIAL_COEFFICIENTS {
        debug_assert!(curr_buf_index <= shake_output_buf.len());
        if curr_buf_index == shake_output_buf.len() {
            // Note (Rust): shakeOutputBuf[..] seems unnecessary and trips Eurydice (FIXME, see #14)
            p_state.extract(&mut shake_output_buf, false);
            curr_buf_index = 0;
        }

        let sample0 = load_u16_le(&shake_output_buf, curr_buf_index) & 0xfff;
        let sample1 = load_u16_le(&shake_output_buf, curr_buf_index + 1) >> 4;
        curr_buf_index += 3;

        pe_dst[i] = sample0;
        i += ((sample0 as u32) < Q) as usize;

        if i < MLWE_POLYNOMIAL_COEFFICIENTS {
            pe_dst[i] = sample1;
            i += ((sample1 as u32) < Q) as usize;
        }
    }
}

pub(super) fn poly_element_sample_cbd_from_bytes(
    pb_src: &[u8],
    eta: u32,
    pe_dst: &mut PolyElement,
) {
    // Note (Rust): using an index rather than incrementing pb_src in place.
    let mut src_i = 0usize;
    debug_assert!((eta == 2) || (eta == 3));
    if eta == 3 {
        for i in (0usize..MLWE_POLYNOMIAL_COEFFICIENTS).step_by(4) {
            // unconditionally load 4 bytes into sample_bits, but only treat the load
            // as being 3 bytes (24-bits -> 4 coefficients) for eta==3 to align to
            // byte boundaries. Source buffer must be 1 byte larger than shake output
            let mut sample_bits = load_u32_le(pb_src, src_i);
            src_i += 3;

            // sum bit samples - each consecutive slice of eta bits is summed together
            sample_bits = (sample_bits&0x249249) + ((sample_bits>>1)&0x249249) + ((sample_bits>>2)&0x249249);

            for j in 0..4 {
                // each coefficient is formed by taking the difference of two consecutive slices of eta bits
                // the first eta bits are positive, the second eta bits are negative
                let mut coefficient = sample_bits & 0x3f;
                sample_bits >>= 6;
                coefficient = (coefficient&3).wrapping_sub(coefficient>>3);
                debug_assert!((coefficient >= ((-3i32) as u32)) || (coefficient <= 3));

                coefficient = coefficient.wrapping_add(Q & (coefficient >> 16));     // in range [0, Q-1]
                debug_assert!( coefficient < Q );

                pe_dst[i+j] = coefficient as u16;
            }
        }
    } else {
        for i in (0usize..MLWE_POLYNOMIAL_COEFFICIENTS).step_by(8) {
            // unconditionally load 4 bytes (32-bits -> 8 coefficients) into sample_bits
            let mut sample_bits = load_u32_le(pb_src, src_i);
            src_i += 4;

            // sum bit samples - each consecutive slice of eta bits is summed together
            sample_bits = (sample_bits&0x55555555) + ((sample_bits>>1)&0x55555555);

            for j in 0..8 {
                // each coefficient is formed by taking the difference of two consecutive slices of eta bits
                // the first eta bits are positive, the second eta bits are negative
                let mut coefficient = sample_bits & 0xf;
                sample_bits >>= 4;
                coefficient = (coefficient&3).wrapping_sub(coefficient>>2);
                debug_assert!((coefficient >= (-2i32 as u32)) || (coefficient <= 2));

                coefficient = coefficient.wrapping_add(Q & (coefficient >> 16));     // in range [0, Q-1]
                debug_assert!( coefficient < Q );

                pe_dst[i+j] = coefficient as u16;
            }
        }
    }
}

pub(super) fn matrix_transpose(pm_src: &mut Matrix, n_rows: u8) {
    let n_rows = n_rows as usize;
    debug_assert!(n_rows >= MATRIX_MIN_NROWS);
    debug_assert!(n_rows <= MATRIX_MAX_NROWS);

    for i in 0usize..n_rows {
        for j in (i+1)..n_rows {
            pm_src.swap((i*n_rows) + j, (j*n_rows) + i);
        }
    }
}

fn poly_element_mul_and_accumulate_aux(
    pm_src1: &Matrix,
    n_rows: usize,
    i: usize,
    j: usize,
    pe_src2: &PolyElement,
    pa_tmp: &mut PolyElementAccumulator,
) {
    let src1: &PolyElement = &pm_src1[(i * n_rows) + j];
    poly_element_mul_and_accumulate(src1, pe_src2, pa_tmp);
}

pub(super) fn matrix_vector_mont_mul_and_add(
    pm_src1: &Matrix,
    pv_src2: &Vector,
    pv_dst: &mut Vector,
    pa_tmp: &mut PolyElementAccumulator,
    n_rows: u8,
) {
    let n_rows = n_rows as usize;

    debug_assert!(n_rows > 0);
    debug_assert!(n_rows <= MATRIX_MAX_NROWS);
    assert_eq!(pv_src2.len(), n_rows);
    assert_eq!(pv_dst.len(), n_rows);

    // Zero pa_tmp
    crate::common::wipe_slice(pa_tmp);

    for i in 0..n_rows {
        let pe_dst = &mut pv_dst[i];
        for (j, pe_src2) in pv_src2.iter().enumerate() {
            poly_element_mul_and_accumulate_aux(pm_src1, n_rows, i, j, pe_src2, pa_tmp);
        }

        // write accumulator to dest and zero accumulator
        montgomery_reduce_and_add_poly_element_accumulator_to_poly_element( pa_tmp, pe_dst );
    }
}

pub(super) fn vector_mont_dot_product(
    pv_src1: &Vector,
    pv_src2: &Vector,
    pe_dst: &mut PolyElement,
    pa_tmp: &mut PolyElementAccumulator,
) {
    let n_rows = pv_src1.len();

    debug_assert!(n_rows > 0);
    debug_assert!(n_rows <= MATRIX_MAX_NROWS);
    debug_assert!(pv_src2.len() == n_rows);

    // Zero pa_tmp and pe_dst
    crate::common::wipe_slice(pa_tmp);
    crate::common::wipe_slice(pe_dst);

    for i in 0usize..n_rows {
        poly_element_mul_and_accumulate( &pv_src1[i], &pv_src2[i], pa_tmp );
    }

    // write accumulator to dest and zero accumulator
    montgomery_reduce_and_add_poly_element_accumulator_to_poly_element(pa_tmp, pe_dst);
}

pub(super) fn vector_set_zero(pv_src: &mut Vector) {
    let n_rows = pv_src.len();

    debug_assert!(n_rows > 0);
    debug_assert!(n_rows <= MATRIX_MAX_NROWS);

    for pe_src in pv_src.iter_mut() {
        crate::common::wipe_slice( pe_src );
    }
}

pub(super) fn vector_mul_r(pv_src: &Vector, pv_dst: &mut Vector) {
    let n_rows = pv_src.len();

    debug_assert!(n_rows > 0);
    debug_assert!(n_rows <= MATRIX_MAX_NROWS);
    debug_assert!(pv_dst.len() == n_rows);

    for i in 0usize..n_rows {
        poly_element_mul_r( & pv_src[i], &mut pv_dst[i] );
    }
}

pub(super) fn vector_ntt(pv_src: &mut Vector) {
    let n_rows = pv_src.len();

    debug_assert!(n_rows > 0);
    debug_assert!(n_rows <= MATRIX_MAX_NROWS);

    for pe_src in pv_src.iter_mut() {
        poly_element_ntt( pe_src );
    }
}

pub(super) fn vector_intt_and_mul_r(pv_src: &mut Vector) {
    let n_rows = pv_src.len();

    debug_assert!(n_rows > 0);
    debug_assert!(n_rows <= MATRIX_MAX_NROWS);

    for pe_src in pv_src.iter_mut() {
        poly_element_intt_and_mul_r( pe_src );
    }
}

pub(super) fn vector_compress_and_encode(
    pv_src: &Vector,
    n_bits_per_coefficient: u32,
    pb_dst: &mut [u8],
) {
    let n_rows = pv_src.len();

    debug_assert!(n_rows > 0);
    debug_assert!(n_rows <= MATRIX_MAX_NROWS);
    debug_assert!(n_bits_per_coefficient > 0);
    debug_assert!(n_bits_per_coefficient <= 12);
    debug_assert!(
        pb_dst.len()
            == n_rows
                * ((n_bits_per_coefficient * (MLWE_POLYNOMIAL_COEFFICIENTS as u32 / 8)) as usize)
    );

    for (i, pe_src) in pv_src.iter().enumerate() {
        let pb_dst_index = i * (n_bits_per_coefficient as usize)*(MLWE_POLYNOMIAL_COEFFICIENTS / 8);
        poly_element_compress_and_encode( pe_src, n_bits_per_coefficient, &mut pb_dst[pb_dst_index..]);
    }
}

pub(super) fn vector_decode_and_decompress(
    pb_src: &[u8],
    n_bits_per_coefficient: u32,
    pv_dst: &mut Vector,
) -> Error {
    let n_rows = pv_dst.len();

    debug_assert!(n_rows > 0);
    debug_assert!(n_rows <= MATRIX_MAX_NROWS);
    debug_assert!(n_bits_per_coefficient > 0);
    debug_assert!(n_bits_per_coefficient <= 12);
    debug_assert!(
        pb_src.len()
            == n_rows * (n_bits_per_coefficient as usize) * (MLWE_POLYNOMIAL_COEFFICIENTS / 8)
    );

    for i in 0usize..n_rows {
        let pe_dst = &mut pv_dst[i];
        let pb_src_index = i * (n_bits_per_coefficient as usize)*(MLWE_POLYNOMIAL_COEFFICIENTS / 8);
        let sc_error = poly_element_decode_and_decompress( &pb_src[pb_src_index..], n_bits_per_coefficient, pe_dst );
        match sc_error { Error::NoError => (), _ => return sc_error };
    }
    Error::NoError
}
