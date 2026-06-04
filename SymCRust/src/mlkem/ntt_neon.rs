//
// ntt_neon.rs  ML-KEM NTT/INTT implementations using NEON intrinsics
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

use super::Q;
use super::PolyElement;
use super::NttIntrinsicsInterface;

pub(super) struct NttIntrinsicsNeon;

impl NttIntrinsicsInterface for NttIntrinsicsNeon {
    #[inline(always)]
    fn vec128_load_u16x8(elem: &PolyElement, index: usize) -> uint16x8_t {
        unsafe {
            let addr = elem.as_ptr().add(index);
            vld1q_u16(addr)
        }
    }
    
    
    #[inline(always)]
    fn vec64_load_u16x4(elem: &PolyElement, index: usize) -> uint16x8_t {
        unsafe {
            let addr = elem.as_ptr().add(index);
            vreinterpretq_u16_u64(vld1q_dup_u64(addr as *const u64))
        }
    }
    
    #[inline(always)]
    fn vec32_load_u16x2(elem: &PolyElement, index: usize) -> uint16x8_t {
        unsafe {
            let addr = elem.as_ptr().add(index);
            vreinterpretq_u16_u32(vld1q_dup_u32(addr as *const u32))
        }
    }
    
    #[inline(always)]
    fn vec128_store_u16x8(elem: &mut PolyElement, index: usize, val: uint16x8_t) {
        unsafe {
            let addr = elem.as_mut_ptr().add(index);
            vst1q_u16(addr, val);
        }
    }
    
    #[inline(always)]
    fn vec64_store_u16x4(elem: &mut PolyElement, index: usize, val: uint16x8_t) {
        unsafe {
            let addr = elem.as_mut_ptr().add(index);
            vst1_u16(addr, vget_low_u16(val));
        }
    }
    
    #[inline(always)]
    fn vec32_store_u16x2(elem: &mut PolyElement, index: usize, val: uint16x8_t) {
        unsafe {
            let addr = elem.as_mut_ptr().add(index);
            vst1_lane_u32(
                addr as *mut u32,
                vget_low_u32(vreinterpretq_u32_u16(val)),
                0,
            );
        }
    }
    
    #[inline(always)]
    fn vec128_set_u16x8(val: u16) -> uint16x8_t {
        unsafe { vdupq_n_u16(val) }
    }
    
    #[inline(always)]
    fn vec128_mod_sub(a: uint16x8_t, b: uint16x8_t) -> uint16x8_t {
        unsafe {
            let v_q = Self::vec128_set_u16x8(Q as u16);
    
            /* res = a - b */
            let v_res = vsubq_u16(a, b);
            /* tmp1 = (a - b) < 0 ? -1 : 0 */
            let mut v_tmp1 = vcltzq_s16(vreinterpretq_s16_u16(v_res));
            /* tmp1 = (a - b) < 0 ? Q : 0 */
            v_tmp1 = vandq_u16(v_tmp1, v_q);
            /* return (a - b) mod Q */
            vaddq_u16(v_res, v_tmp1)
        }
    }
    
    #[inline(always)]
    fn vec128_mod_add(a: uint16x8_t, b: uint16x8_t) -> uint16x8_t {
        unsafe {
            let v_q = Self::vec128_set_u16x8(Q as u16);
    
            /* res = a + b */
            let v_res = vaddq_u16(a, b);
            /* tmp1 = (a + b) >= Q ? -1 : 0 */
            let mut v_tmp1 = vcgeq_u16(v_res, v_q);
            /* tmp1 = (a + b) >= Q ? Q : 0 */
            v_tmp1 = vandq_u16(v_tmp1, v_q);
            /* return (a + b) mod Q */
            vsubq_u16(v_res, v_tmp1)
        }
    }
    
    #[inline(always)]
    fn vec128_mont_mul(a: uint16x8_t, b: uint16x8_t, b_mont: uint16x8_t) -> uint16x8_t {
        unsafe {
            let v_q = Self::vec128_set_u16x8(Q as u16);
    
            /* tmp1 = a *low  b_mont */
            let mut v_tmp1 = vmulq_u16(a, b_mont);
            /* tmp2 = a*b [0-3]*/
            let mut v_tmp2 = vmull_u16(vget_low_u16(a), vget_low_u16(b));
            /* res  = a*b [4-7]*/
            let mut v_res = vmull_high_u16(a, b);
            /* tmp2 = a*b + inv*Q [0-3]*/
            v_tmp2 = vmlal_u16(v_tmp2, vget_low_u16(v_tmp1), vget_low_u16(v_q));
            /* res  = a*b + inv*Q [4-7]*/
            v_res = vmlal_high_u16(v_res, v_tmp1, v_q);
            /* res  = a*b + inv*Q >> 16 */
            v_tmp1 = vuzp2q_u16(vreinterpretq_u16_u32(v_tmp2), vreinterpretq_u16_u32(v_res));
            /* return (a*b + inv*Q >> 16) mod Q */
            Self::vec128_mod_sub(v_tmp1, v_q)
        }
    }
}
