// EXPERIMENTAL CODE --- NOT YET INTEGRATED WITH SYMCRYPT
//
// keccak4x.rs   4-way data-parallel Keccak-f[1600] in safe Rust
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Processes 4 independent Keccak-f[1600] permutations simultaneously.
// Written to auto-vectorize on x86_64 with AVX2 (4 × u64 in 256-bit registers).
// All code is safe Rust — no intrinsics, no unsafe (except volatile wipe in Drop).
//

#![allow(dead_code)]

use super::sha3_impl::KECCAK_IOTA_K;

// ---------------------------------------------------------------------------
// Lane4: 4 parallel u64 lanes, AVX2-aligned
// ---------------------------------------------------------------------------

/// Four parallel u64 values, one per Keccak instance.
/// Aligned to 32 bytes so the compiler can use aligned AVX2 loads/stores.
#[derive(Clone, Copy)]
#[repr(C, align(32))]
pub(crate) struct Lane4([u64; 4]);

impl Default for Lane4 {
    #[inline(always)]
    fn default() -> Self {
        Lane4([0u64; 4])
    }
}

impl Lane4 {
    #[inline(always)]
    fn splat(v: u64) -> Self {
        Lane4([v; 4])
    }

    #[inline(always)]
    fn xor(self, other: Self) -> Self {
        let mut r = [0u64; 4];
        for i in 0..4 {
            r[i] = self.0[i] ^ other.0[i];
        }
        Lane4(r)
    }

    /// `!a & b` — maps to AVX2 `vpandn`
    #[inline(always)]
    fn andnot(self, other: Self) -> Self {
        let mut r = [0u64; 4];
        for i in 0..4 {
            r[i] = !self.0[i] & other.0[i];
        }
        Lane4(r)
    }

    /// Rotate left by compile-time constant using explicit shift+or.
    #[inline(always)]
    fn rol(self, n: u32) -> Self {
        debug_assert!(n > 0 && n < 64);
        let mut r = [0u64; 4];
        for i in 0..4 {
            r[i] = (self.0[i] << n) | (self.0[i] >> (64 - n));
        }
        Lane4(r)
    }

    #[inline(always)]
    fn xor_assign(&mut self, other: Self) {
        for i in 0..4 {
            self.0[i] ^= other.0[i];
        }
    }
}

// ---------------------------------------------------------------------------
// 4-way Keccak-f[1600] permutation state
// ---------------------------------------------------------------------------

/// 4 independent Keccak-f[1600] states processed in parallel.
///
/// State layout: `state[5*y + x]` holds lane `(x,y)` of all 4 instances.
/// This matches the scalar `[u64; 25]` layout from `sha3_impl.rs`.
#[repr(C)]
pub struct Keccak4x {
    state: [Lane4; 25],
}

impl Default for Keccak4x {
    fn default() -> Self {
        Keccak4x {
            state: [Lane4::default(); 25],
        }
    }
}

impl Drop for Keccak4x {
    #[cfg_attr(feature = "verify", verify::opaque)]
    fn drop(&mut self) {
        for lane in self.state.iter_mut() {
            for v in lane.0.iter_mut() {
                unsafe { core::ptr::write_volatile(v, 0u64) };
            }
        }
    }
}

impl Keccak4x {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline(always)]
    pub fn xor_lane(&mut self, pos: usize, instance: usize, value: u64) {
        debug_assert!(pos < 25 && instance < 4);
        self.state[pos].0[instance] ^= value;
    }

    #[inline(always)]
    pub fn get_lane(&self, pos: usize, instance: usize) -> u64 {
        debug_assert!(pos < 25 && instance < 4);
        self.state[pos].0[instance]
    }

    pub fn xor_bytes(&mut self, instance: usize, data: &[u8], lane_count: usize) {
        debug_assert!(instance < 4 && data.len() >= lane_count * 8 && lane_count <= 25);
        for i in 0..lane_count {
            let v = u64::from_le_bytes(data[i * 8..i * 8 + 8].try_into().unwrap());
            self.state[i].0[instance] ^= v;
        }
    }

    pub fn extract_bytes(&self, instance: usize, out: &mut [u8], lane_count: usize) {
        debug_assert!(instance < 4 && out.len() >= lane_count * 8 && lane_count <= 25);
        for i in 0..lane_count {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.state[i].0[instance].to_le_bytes());
        }
    }

    /// Run 24 rounds of Keccak-f[1600] on all 4 states simultaneously.
    ///
    /// Uses a merged theta+rho+pi approach to minimize register pressure:
    /// 1. Compute theta D values (5 Lane4s)
    /// 2. Apply theta in-place
    /// 3. Read each lane, apply rho rotation, store at pi destination (into temp array)
    /// 4. Apply chi from temp, store back
    /// 5. Apply iota
    pub fn permute(&mut self) {
        let s = &mut self.state;
        for round in 0..24 {
            // ---- θ (theta) ----
            let c0 = s[0].xor(s[5]).xor(s[10]).xor(s[15]).xor(s[20]);
            let c1 = s[1].xor(s[6]).xor(s[11]).xor(s[16]).xor(s[21]);
            let c2 = s[2].xor(s[7]).xor(s[12]).xor(s[17]).xor(s[22]);
            let c3 = s[3].xor(s[8]).xor(s[13]).xor(s[18]).xor(s[23]);
            let c4 = s[4].xor(s[9]).xor(s[14]).xor(s[19]).xor(s[24]);

            let d0 = c4.xor(c1.rol(1));
            let d1 = c0.xor(c2.rol(1));
            let d2 = c1.xor(c3.rol(1));
            let d3 = c2.xor(c4.rol(1));
            let d4 = c3.xor(c0.rol(1));

            s[ 0].xor_assign(d0); s[ 1].xor_assign(d1); s[ 2].xor_assign(d2); s[ 3].xor_assign(d3); s[ 4].xor_assign(d4);
            s[ 5].xor_assign(d0); s[ 6].xor_assign(d1); s[ 7].xor_assign(d2); s[ 8].xor_assign(d3); s[ 9].xor_assign(d4);
            s[10].xor_assign(d0); s[11].xor_assign(d1); s[12].xor_assign(d2); s[13].xor_assign(d3); s[14].xor_assign(d4);
            s[15].xor_assign(d0); s[16].xor_assign(d1); s[17].xor_assign(d2); s[18].xor_assign(d3); s[19].xor_assign(d4);
            s[20].xor_assign(d0); s[21].xor_assign(d1); s[22].xor_assign(d2); s[23].xor_assign(d3); s[24].xor_assign(d4);

            // ---- ρ + π (merged) ----
            let t = [
                s[ 0],
                s[ 6].rol(44), s[12].rol(43), s[18].rol(21), s[24].rol(14),
                s[ 3].rol(28), s[ 9].rol(20), s[10].rol( 3), s[16].rol(45), s[22].rol(61),
                s[ 1].rol( 1), s[ 7].rol( 6), s[13].rol(25), s[19].rol( 8), s[20].rol(18),
                s[ 4].rol(27), s[ 5].rol(36), s[11].rol(10), s[17].rol(15), s[23].rol(56),
                s[ 2].rol(62), s[ 8].rol(55), s[14].rol(39), s[15].rol(41), s[21].rol( 2),
            ];

            // ---- χ (chi) ----
            macro_rules! chi_row {
                ($r:expr) => {{
                    let b = 5 * $r;
                    s[b]   = t[b].xor(t[b+1].andnot(t[b+2]));
                    s[b+1] = t[b+1].xor(t[b+2].andnot(t[b+3]));
                    s[b+2] = t[b+2].xor(t[b+3].andnot(t[b+4]));
                    s[b+3] = t[b+3].xor(t[b+4].andnot(t[b]));
                    s[b+4] = t[b+4].xor(t[b].andnot(t[b+1]));
                }};
            }
            chi_row!(0);
            chi_row!(1);
            chi_row!(2);
            chi_row!(3);
            chi_row!(4);

            // ---- ι (iota) ----
            s[0].xor_assign(Lane4::splat(KECCAK_IOTA_K[round]));
        }
    }
}

// ---------------------------------------------------------------------------
// Public benchmarking wrapper
// ---------------------------------------------------------------------------

#[cfg(feature = "benchmarking")]
#[inline(always)]
pub fn keccak4x_permute_pub_wrapper(state: &mut Keccak4x) {
    state.permute();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha3::sha3_impl::keccak_permute_pub_wrapper;

    #[test]
    fn test_keccak4x_matches_scalar() {
        for seed in 0u64..8 {
            let mut scalar_states = [[0u64; 25]; 4];
            let mut parallel = Keccak4x::new();

            for inst in 0..4 {
                for lane in 0..25 {
                    let v = seed
                        .wrapping_mul(0x9E3779B97F4A7C15)
                        .wrapping_add((inst as u64) * 1000 + (lane as u64));
                    scalar_states[inst][lane] = v;
                    parallel.xor_lane(lane, inst, v);
                }
            }

            for inst in 0..4 {
                keccak_permute_pub_wrapper(&mut scalar_states[inst]);
            }
            parallel.permute();

            for inst in 0..4 {
                for lane in 0..25 {
                    assert_eq!(
                        parallel.get_lane(lane, inst),
                        scalar_states[inst][lane],
                        "Mismatch at seed={}, instance={}, lane={}",
                        seed, inst, lane
                    );
                }
            }
        }
    }

    #[test]
    fn test_lane_independence() {
        let mut parallel = Keccak4x::new();
        for lane in 0..25 {
            let v = (lane as u64).wrapping_mul(0xDEADBEEF);
            for inst in 0..4 {
                parallel.xor_lane(lane, inst, v);
            }
        }
        parallel.xor_lane(0, 2, 0xFFFFFFFFFFFFFFFF);
        parallel.permute();

        for lane in 0..25 {
            let v0 = parallel.get_lane(lane, 0);
            let v1 = parallel.get_lane(lane, 1);
            let v3 = parallel.get_lane(lane, 3);
            assert_eq!(v0, v1, "Instances 0 and 1 diverged at lane {}", lane);
            assert_eq!(v0, v3, "Instances 0 and 3 diverged at lane {}", lane);
        }

        let mut any_diff = false;
        for lane in 0..25 {
            if parallel.get_lane(lane, 0) != parallel.get_lane(lane, 2) {
                any_diff = true;
                break;
            }
        }
        assert!(any_diff, "Instance 2 should differ after mutation");
    }

    #[test]
    fn test_byte_interface() {
        let mut parallel = Keccak4x::new();
        let lane_count = 17;
        let byte_count = lane_count * 8;

        for inst in 0..4 {
            let data: Vec<u8> = (0..byte_count)
                .map(|i| ((inst * 137 + i) & 0xFF) as u8)
                .collect();
            parallel.xor_bytes(inst, &data, lane_count);
        }
        parallel.permute();

        for inst in 0..4 {
            let mut scalar = [0u64; 25];
            let data: Vec<u8> = (0..byte_count)
                .map(|i| ((inst * 137 + i) & 0xFF) as u8)
                .collect();
            for i in 0..lane_count {
                scalar[i] ^= u64::from_le_bytes(data[i * 8..i * 8 + 8].try_into().unwrap());
            }
            keccak_permute_pub_wrapper(&mut scalar);

            let mut out = vec![0u8; byte_count];
            parallel.extract_bytes(inst, &mut out, lane_count);

            for i in 0..lane_count {
                let expected = scalar[i].to_le_bytes();
                assert_eq!(
                    &out[i * 8..i * 8 + 8],
                    &expected,
                    "Byte mismatch at instance={}, lane={}",
                    inst, i
                );
            }
        }
    }

    #[test]
    fn test_multiple_permutations() {
        let mut scalar_states = [[0u64; 25]; 4];
        let mut parallel = Keccak4x::new();

        for inst in 0..4 {
            for lane in 0..25 {
                let v = ((inst * 25 + lane) as u64).wrapping_mul(0x0123456789ABCDEF);
                scalar_states[inst][lane] = v;
                parallel.xor_lane(lane, inst, v);
            }
        }

        for _ in 0..5 {
            for inst in 0..4 {
                keccak_permute_pub_wrapper(&mut scalar_states[inst]);
            }
            parallel.permute();
        }

        for inst in 0..4 {
            for lane in 0..25 {
                assert_eq!(
                    parallel.get_lane(lane, inst),
                    scalar_states[inst][lane],
                    "Multi-permute mismatch at instance={}, lane={}",
                    inst, lane
                );
            }
        }
    }
}
