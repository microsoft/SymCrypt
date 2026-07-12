// EXPERIMENTAL CODE --- NOT YET INTEGRATED WITH SYMCRYPT
//
// keccak4x_hybrid.rs   4-way Keccak with AVX2 rotation + auto-vectorized logic
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// The XOR and AND-NOT operations auto-vectorize perfectly from plain Rust.
// Only the rotation de-vectorizes to scalar `rorx`. This variant uses a
// single AVX2 intrinsic helper just for rotation, keeping everything else
// as plain auto-vectorized Rust.
//
// Key optimization: interleaved chi with save-ahead computation keeps peak
// register pressure at exactly 16 YMM registers, theoretically eliminating
// all spills. The schedule is:
//   1. Compute D[0..4]
//   2. For each chi row r:
//      a. Compute the row's own temps (fused θ+ρ+π)
//      b. Save-ahead: compute temps from positions chi row r will overwrite
//      c. Apply chi row r (row temps die, freeing registers)
//

#![allow(dead_code)]

#[cfg(all(target_arch = "x86_64", not(feature = "verify")))]
use core::arch::x86_64::*;

use super::sha3_impl::KECCAK_IOTA_K;

// ---------------------------------------------------------------------------
// AVX2 op redirect (single-body cfg-swap; INTRINSICS.md §0 P6, cf. the SHA-2
// `shani_x86` pilot). `rol4!` below is written ONCE over a neutral `M256`
// register and the `slli_epi64` / `srli_epi64` / `or_si256` op names; the two
// cfg-gated `use` blocks bind those names + `M256` to either `core::arch`
// (production, `M256 = __m256i`) or the verify backend
// `crate::verify::intrinsics::x86_64::ymm` (`M256 = [u8; 32]`). All modelling
// lives in `src/verify`; this file stays a near-verbatim copy of the upstream
// production source. `feature = "verify"` appears only in this redirect and
// the cfg-split `load_lane`/`store_lane` (raw-pointer, opaque) below.
// ---------------------------------------------------------------------------

/// Production AVX2 op layer: thin `__m256i` wrappers presenting the same
/// flat surface (`M256` + named ops) as the verify shims in
/// `crate::verify::intrinsics::x86_64::ymm`, so `rol4!` is shared verbatim
/// between the two builds. This module is the *production half of the
/// redirect* — the only place the `_mm256_*` shift/or intrinsics are named.
///
/// SAFETY (whole module): each op is `#[target_feature(enable = "avx2")]` and
/// wraps one `core::arch::x86_64` AVX2 intrinsic, so it emits real AVX2 even in
/// a baseline-x86-64 build (without the attribute LLVM scalarizes the rotate).
/// Calling them is sound only on a CPU with `avx2`; the sole caller chain
/// (`permute` → `permute_avx2` → `rol4!`) is `unsafe` and reached only after the
/// caller confirms AVX2 at runtime. Under `feature = "verify"` the ops resolve
/// instead to the attribute-free `verify::intrinsics::x86_64::ymm` shims that
/// Aeneas extracts.
#[cfg(all(target_arch = "x86_64", not(feature = "verify")))]
mod ymm_prod {
    use core::arch::x86_64::*;

    /// Neutral register type: the architectural 256-bit YMM register.
    pub type M256 = __m256i;

    /// `_mm256_slli_epi64::<N>` — lane-wise logical shift left of 64-bit lanes.
    #[inline]
    #[target_feature(enable = "avx2")]
    pub fn slli_epi64<const N: i32>(a: M256) -> M256 {
        _mm256_slli_epi64::<N>(a)
    }

    /// `_mm256_srli_epi64::<N>` — lane-wise logical shift right of 64-bit lanes.
    #[inline]
    #[target_feature(enable = "avx2")]
    pub fn srli_epi64<const N: i32>(a: M256) -> M256 {
        _mm256_srli_epi64::<N>(a)
    }

    /// `_mm256_or_si256` — 256-bit bitwise OR.
    #[inline]
    #[target_feature(enable = "avx2")]
    pub fn or_si256(a: M256, b: M256) -> M256 {
        _mm256_or_si256(a, b)
    }
}

#[cfg(all(target_arch = "x86_64", not(feature = "verify")))]
use ymm_prod::{or_si256, slli_epi64, srli_epi64, M256};

#[cfg(feature = "verify")]
use crate::verify::intrinsics::x86_64::ymm::{or_si256, slli_epi64, srli_epi64, M256};

// ---------------------------------------------------------------------------
// Lane4: 4 parallel u64 lanes, AVX2-aligned, auto-vectorized ops
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
#[repr(C, align(32))]
pub(crate) struct Lane4([u64; 4]);

impl Default for Lane4 {
    #[inline(always)]
    fn default() -> Self { Lane4([0u64; 4]) }
}

impl Lane4 {
    #[inline(always)]
    fn splat(v: u64) -> Self { Lane4([v; 4]) }

    // XOR and ANDNOT auto-vectorize to vpxor / vpandn without help.
    #[inline(always)]
    fn xor(self, other: Self) -> Self {
        Lane4([
            self.0[0] ^ other.0[0], self.0[1] ^ other.0[1],
            self.0[2] ^ other.0[2], self.0[3] ^ other.0[3],
        ])
    }

    #[inline(always)]
    fn andnot(self, other: Self) -> Self {
        Lane4([
            !self.0[0] & other.0[0], !self.0[1] & other.0[1],
            !self.0[2] & other.0[2], !self.0[3] & other.0[3],
        ])
    }

    #[inline(always)]
    fn xor_assign(&mut self, other: Self) {
        self.0[0] ^= other.0[0]; self.0[1] ^= other.0[1];
        self.0[2] ^= other.0[2]; self.0[3] ^= other.0[3];
    }
}

// ---------------------------------------------------------------------------
// AVX2 rotation helper — the ONE operation that needs intrinsics
// ---------------------------------------------------------------------------
// `load_lane` / `store_lane` reinterpret a `&Lane4` (#[repr(C, align(32))])
// as a `M256` register through raw pointers; that is outside Aeneas's model
// of Rust, so they are cfg-split: a real `core::arch` body in production, an
// opaque (`#[verify::opaque]`) signature-only stub under `feature = "verify"`
// (the verify carrier `M256 = [u8; 32]` is the `Lane4` byte image, so the
// round-trip `store_lane _ (load_lane l) = l` is the axiom's intent).

#[inline]
#[cfg(all(target_arch = "x86_64", not(feature = "verify")))]
#[target_feature(enable = "avx2")]
unsafe fn load_lane(l: &Lane4) -> M256 {
    _mm256_load_si256(l.0.as_ptr() as *const __m256i)
}

#[inline]
#[cfg(all(target_arch = "x86_64", not(feature = "verify")))]
#[target_feature(enable = "avx2")]
unsafe fn store_lane(l: &mut Lane4, x: M256) {
    _mm256_store_si256(l.0.as_mut_ptr() as *mut __m256i, x);
}

#[cfg_attr(feature = "verify", verify::opaque)]
#[inline]
#[cfg(feature = "verify")]
fn load_lane(_l: &Lane4) -> M256 {
    unimplemented!()
}

#[cfg_attr(feature = "verify", verify::opaque)]
#[inline]
#[cfg(feature = "verify")]
fn store_lane(_l: &mut Lane4, _x: M256) {
    unimplemented!()
}

/// Rotate all 4 u64 lanes left by `N` bits using AVX2.
/// This is the only operation that LLVM de-vectorizes to scalar `rorx`;
/// providing it as an intrinsic forces vectorized sllq+srlq+por.
macro_rules! rol4 {
    ($lane:expr, $n:literal) => {{
        let lane: Lane4 = $lane;
        let v: M256;
        // SAFETY: Lane4 is #[repr(C, align(32))], same layout as __m256i.
        // We're reading/writing our own stack value through a pointer cast.
        // (`load_lane`/`store_lane` are `unsafe` in production and safe
        // opaque stubs under `feature = "verify"`; the `unsafe` block is a
        // no-op there but kept for the shared body.)
        #[allow(unused_unsafe)]
        unsafe {
            v = load_lane(&lane);
            let r = or_si256(
                slli_epi64::<$n>(v),
                srli_epi64::<{ 64 - $n }>(v),
            );
            let mut out = Lane4([0u64; 4]);
            store_lane(&mut out, r);
            out
        }
    }};
}

// ---------------------------------------------------------------------------
// Keccak4xHybrid: auto-vectorized logic + AVX2 rotations
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct Keccak4xHybrid {
    state: [Lane4; 25],
}

impl Default for Keccak4xHybrid {
    fn default() -> Self { Keccak4xHybrid { state: [Lane4::default(); 25] } }
}

impl Drop for Keccak4xHybrid {
    #[cfg_attr(feature = "verify", verify::opaque)]
    fn drop(&mut self) {
        for lane in self.state.iter_mut() {
            for v in lane.0.iter_mut() {
                unsafe { core::ptr::write_volatile(v, 0u64) };
            }
        }
    }
}

impl Keccak4xHybrid {
    pub fn new() -> Self { Self::default() }

    #[inline(always)]
    pub fn xor_lane(&mut self, pos: usize, instance: usize, value: u64) {
        self.state[pos].0[instance] ^= value;
    }

    #[inline(always)]
    pub fn get_lane(&self, pos: usize, instance: usize) -> u64 {
        self.state[pos].0[instance]
    }

    /// Extract `lane_count` lanes from one instance as little-endian bytes.
    #[inline]
    pub fn extract_bytes(&self, instance: usize, out: &mut [u8], lane_count: usize) {
        debug_assert!(instance < 4 && out.len() >= lane_count * 8 && lane_count <= 25);
        for i in 0..lane_count {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.state[i].0[instance].to_le_bytes());
        }
    }

    /// Public entry (production build). **Only sound on an AVX2 CPU** — the
    /// caller MUST confirm `cpu_features_present(AVX2)` before calling. Kept
    /// safe (not `unsafe fn`) so consumers match the `verify` signature; the
    /// AVX2 precondition is a documented contract, discharged by the runtime
    /// dispatch gate in the sampling paths.
    #[cfg(not(feature = "verify"))]
    #[inline]
    pub fn permute(&mut self) {
        // SAFETY: caller-confirmed AVX2 (see doc). `permute_avx2` and the ymm
        // ops it uses are `#[target_feature(enable = "avx2")]`.
        unsafe { self.permute_avx2() }
    }

    /// AVX2 body: `#[target_feature]` forces real AVX2 codegen for the `rol4!`
    /// rotations even in a baseline-x86-64 build.
    #[cfg(not(feature = "verify"))]
    #[target_feature(enable = "avx2")]
    unsafe fn permute_avx2(&mut self) {
        self.permute_impl()
    }

    /// Verified entry (extraction build): the ymm redirect ops resolve to the
    /// `verify::intrinsics` shims, which carry no `#[target_feature]`, so this
    /// path stays exactly what Aeneas extracts.
    #[cfg(feature = "verify")]
    pub fn permute(&mut self) {
        self.permute_impl()
    }

    /// Shared 4-way Keccak round loop — single source of truth for both the
    /// production (AVX2) and `verify` (shim) builds. `#[inline(always)]` so it
    /// adopts the AVX2 context when inlined into `permute_avx2`.
    #[inline(always)]
    fn permute_impl(&mut self) {
        let s = &mut self.state;
        for round in 0..24 {
            // ── θ: column parities → D values (5 regs) ──
            let c0 = s[0].xor(s[5]).xor(s[10]).xor(s[15]).xor(s[20]);
            let c1 = s[1].xor(s[6]).xor(s[11]).xor(s[16]).xor(s[21]);
            let c2 = s[2].xor(s[7]).xor(s[12]).xor(s[17]).xor(s[22]);
            let c3 = s[3].xor(s[8]).xor(s[13]).xor(s[18]).xor(s[23]);
            let c4 = s[4].xor(s[9]).xor(s[14]).xor(s[19]).xor(s[24]);

            let d0 = c4.xor(rol4!(c1, 1));
            let d1 = c0.xor(rol4!(c2, 1));
            let d2 = c1.xor(rol4!(c3, 1));
            let d3 = c2.xor(rol4!(c4, 1));
            let d4 = c3.xor(rol4!(c0, 1));
            // C values dead. Live: D[0..4] = 5

            // Fused θ+ρ+π helper: load lane, XOR with D, rotate.
            // Using a macro so the rotation amount is a compile-time constant.
            macro_rules! trp {
                ($src:expr, $d:expr, $rot:literal) => {
                    rol4!(s[$src].xor($d), $rot)
                };
            }

            // ── Row 0: t[0..4] from s[0,6,12,18,24] ── (live: 5D + 5 = 10)
            let t0  = s[0].xor(d0);                // rot 0
            let t1  = trp!( 6, d1, 44);
            let t2  = trp!(12, d2, 43);
            let t3  = trp!(18, d3, 21);
            let t4  = trp!(24, d4, 14);

            // Save-ahead: values from s[0..4] needed by later rows (live: 10+4 = 14)
            let t5  = trp!( 3, d3, 28);   // row 1, from s[3]
            let t10 = trp!( 1, d1,  1);   // row 2, from s[1]
            let t15 = trp!( 4, d4, 27);   // row 3, from s[4]
            let t20 = trp!( 2, d2, 62);   // row 4, from s[2]

            // Chi row 0 → write s[0..4], t[0..4] die (live: 14-5 = 9)
            s[0] = t0.xor(t1.andnot(t2));
            s[1] = t1.xor(t2.andnot(t3));
            s[2] = t2.xor(t3.andnot(t4));
            s[3] = t3.xor(t4.andnot(t0));
            s[4] = t4.xor(t0.andnot(t1));

            // ── Row 1: t[6..9] from s[9,10,16,22], t[5] already saved ── (live: 9+4 = 13)
            let t6  = trp!( 9, d4, 20);
            let t7  = trp!(10, d0,  3);
            let t8  = trp!(16, d1, 45);
            let t9  = trp!(22, d2, 61);

            // Save-ahead: values from s[5..9] needed by later rows (live: 13+3 = 16)
            let t11 = trp!( 7, d2,  6);   // row 2, from s[7]
            let t16 = trp!( 5, d0, 36);   // row 3, from s[5]
            let t21 = trp!( 8, d3, 55);   // row 4, from s[8]

            // Chi row 1 → write s[5..9], t[5..9] die (live: 16-5 = 11)
            s[5] = t5.xor(t6.andnot(t7));
            s[6] = t6.xor(t7.andnot(t8));
            s[7] = t7.xor(t8.andnot(t9));
            s[8] = t8.xor(t9.andnot(t5));
            s[9] = t9.xor(t5.andnot(t6));

            // ── Row 2: t[12..14] from s[13,19,20], t[10,11] already saved ── (live: 11+3 = 14)
            let t12 = trp!(13, d3, 25);
            let t13 = trp!(19, d4,  8);
            let t14 = trp!(20, d0, 18);

            // Save-ahead: values from s[10..14] needed later (live: 14+2 = 16)
            let t17 = trp!(11, d1, 10);   // row 3, from s[11]
            let t22 = trp!(14, d4, 39);   // row 4, from s[14]

            // Chi row 2 → write s[10..14], t[10..14] die (live: 16-5 = 11)
            s[10] = t10.xor(t11.andnot(t12));
            s[11] = t11.xor(t12.andnot(t13));
            s[12] = t12.xor(t13.andnot(t14));
            s[13] = t13.xor(t14.andnot(t10));
            s[14] = t14.xor(t10.andnot(t11));

            // ── Row 3: t[18,19] from s[17,23], t[15,16,17] already saved ── (live: 11+2 = 13)
            let t18 = trp!(17, d2, 15);
            let t19 = trp!(23, d3, 56);

            // Save-ahead: value from s[15..19] needed by row 4 (live: 13+1 = 14)
            let t23 = trp!(15, d0, 41);   // row 4, from s[15]

            // Chi row 3 → write s[15..19], t[15..19] die (live: 14-5 = 9)
            s[15] = t15.xor(t16.andnot(t17));
            s[16] = t16.xor(t17.andnot(t18));
            s[17] = t17.xor(t18.andnot(t19));
            s[18] = t18.xor(t19.andnot(t15));
            s[19] = t19.xor(t15.andnot(t16));

            // ── Row 4: t[24] from s[21], t[20..23] already saved ── (live: 9+1 = 10)
            let t24 = trp!(21, d1,  2);

            // Chi row 4 → write s[20..24], everything dies (live: 0)
            s[20] = t20.xor(t21.andnot(t22));
            s[21] = t21.xor(t22.andnot(t23));
            s[22] = t22.xor(t23.andnot(t24));
            s[23] = t23.xor(t24.andnot(t20));
            s[24] = t24.xor(t20.andnot(t21));

            // ι — auto-vectorized XOR
            s[0].xor_assign(Lane4::splat(KECCAK_IOTA_K[round]));
        }
    }
}

#[cfg(feature = "benchmarking")]
#[inline(always)]
pub fn keccak4x_hybrid_permute_pub_wrapper(state: &mut Keccak4xHybrid) {
    state.permute();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha3::sha3_impl::keccak_permute_pub_wrapper;

    #[test]
    fn test_keccak4x_hybrid_matches_scalar() {
        for seed in 0u64..8 {
            let mut scalar_states = [[0u64; 25]; 4];
            let mut parallel = Keccak4xHybrid::new();
            for inst in 0..4 {
                for lane in 0..25 {
                    let v = seed.wrapping_mul(0x9E3779B97F4A7C15)
                        .wrapping_add((inst as u64) * 1000 + (lane as u64));
                    scalar_states[inst][lane] = v;
                    parallel.xor_lane(lane, inst, v);
                }
            }
            for inst in 0..4 { keccak_permute_pub_wrapper(&mut scalar_states[inst]); }
            parallel.permute();
            for inst in 0..4 {
                for lane in 0..25 {
                    assert_eq!(parallel.get_lane(lane, inst), scalar_states[inst][lane],
                        "Hybrid mismatch seed={}, inst={}, lane={}", seed, inst, lane);
                }
            }
        }
    }

    #[test]
    fn test_keccak4x_hybrid_lane_independence() {
        let mut p = Keccak4xHybrid::new();
        for lane in 0..25 { for inst in 0..4 {
            p.xor_lane(lane, inst, (lane as u64).wrapping_mul(0xDEADBEEF));
        }}
        p.xor_lane(0, 2, 0xFFFFFFFFFFFFFFFF);
        p.permute();
        for lane in 0..25 {
            assert_eq!(p.get_lane(lane, 0), p.get_lane(lane, 1));
            assert_eq!(p.get_lane(lane, 0), p.get_lane(lane, 3));
        }
        assert!((0..25).any(|l| p.get_lane(l, 0) != p.get_lane(l, 2)));
    }
}
