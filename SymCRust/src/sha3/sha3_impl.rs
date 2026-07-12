
//
// sha3_impl.rs   SymCrypt SHA3 Rust implementation
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

///
/// Keccak state
///
/// Keccak-f\[1600\] state consists of 25 64-bit words. We represent this state as a single
/// dimensional array of 25 elements (Wi being the i^th element of the array for i=0..24)
/// with the following mapping to two dimensional coordinates. Note that in FIPS 202 Figure 2,
/// the element W0 at (x,y)=(0,0) is depicted in the middle of the 5x5 array. We set W0
/// to be the first element so that the rate part of the permutation maps to the beginning
/// of the state.
///
///```text
///       x=0  x=1  x=2  x=3  x=4
///       -----------------------
/// y=0    W0   W1   W2   W3   W4
/// y=1    W5   W6   W7   W8   W9
/// y=2   W10  W11  W12  W13  W14
/// y=3   W15  W16  W17  W18  W19
/// y=4   W20  W21  W22  W23  W24
/// ```
///

type Keccak1600 = [u64; 25];

#[repr(C)]
#[cfg_attr(any(target_arch = "x86"), repr(align(4)))]
#[cfg_attr(any(target_arch = "arm"), repr(align(8)))]
#[cfg_attr(any(target_arch = "x86_64", target_arch = "aarch64"), repr(align(16)))]
#[derive(Clone, PartialEq, Debug, Default)]
pub(crate) struct KeccakState {
    /// State for Keccak-f\[1600\] permutation
    state: Keccak1600,
    /// Rate
    input_block_size: u32,
    /// Position in the state for next merge/extract operation
    state_index: u32,
    padding_value: u8,
    squeeze_mode: bool,
}

impl Drop for KeccakState {
    fn drop(&mut self) {
        crate::common::wipe_slice(&mut self.state);
    }
}

const U64_NUM_BYTES: usize = 8;

/// Rotation constants for Keccak Rho transformation
pub(crate) const KECCAK_RHO_K: [u32; 25] = [
     0,  1, 62, 28, 27,     // y = 0
    36, 44,  6, 55, 20,     // y = 1
     3, 10, 43, 25, 39,     // y = 2
    41, 45, 15, 21,  8,     // y = 3
    18,  2, 61, 56, 14,     // y = 4
];

/// Constants for Keccak Iota transformation
pub(crate) const KECCAK_IOTA_K: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
];

#[inline(always)]
fn keccak_column_sum(state: &Keccak1600, c: usize) -> u64 {
    return state[0 + c] ^
           state[5 + c] ^
           state[10 + c] ^
           state[15 + c] ^
           state[20 + c];
}

#[inline(always)]
fn keccak_column_update(state: &mut Keccak1600, c: usize, w: u64) {
    state[0 + c] ^= w;
    state[5 + c] ^= w;
    state[10 + c] ^= w;
    state[15 + c] ^= w;
    state[20 + c] ^= w;
}

#[inline(always)]
fn keccak_theta(state: &mut Keccak1600) {
    let mut col_sum: [u64; 5] = [0; 5];
    col_sum[0] = keccak_column_sum(state, 0);
    col_sum[1] = keccak_column_sum(state, 1);
    col_sum[2] = keccak_column_sum(state, 2);
    col_sum[3] = keccak_column_sum(state, 3);
    col_sum[4] = keccak_column_sum(state, 4);

    keccak_column_update(state, 0, col_sum[4] ^ col_sum[1].rotate_left(1));
    keccak_column_update(state, 1, col_sum[0] ^ col_sum[2].rotate_left(1));
    keccak_column_update(state, 2, col_sum[1] ^ col_sum[3].rotate_left(1));
    keccak_column_update(state, 3, col_sum[2] ^ col_sum[4].rotate_left(1));
    keccak_column_update(state, 4, col_sum[3] ^ col_sum[0].rotate_left(1));
}

#[inline(always)]
fn keccak_rho_row(state: &mut Keccak1600, r: usize) {
    state[5 * r + 0] = state[5 * r + 0].rotate_left(KECCAK_RHO_K[5 * r + 0]);
    state[5 * r + 1] = state[5 * r + 1].rotate_left(KECCAK_RHO_K[5 * r + 1]);
    state[5 * r + 2] = state[5 * r + 2].rotate_left(KECCAK_RHO_K[5 * r + 2]);
    state[5 * r + 3] = state[5 * r + 3].rotate_left(KECCAK_RHO_K[5 * r + 3]);
    state[5 * r + 4] = state[5 * r + 4].rotate_left(KECCAK_RHO_K[5 * r + 4]);
}

// The first row contains a rotation by 0 on the first lane that uses a shift
// by 64 which we want to avoid. Rho operation below omits the rotation on the first lane.
#[inline(always)]
fn keccak_rho_row0(state: &mut Keccak1600) {
    state[1] = state[1].rotate_left(KECCAK_RHO_K[1]);
    state[2] = state[2].rotate_left(KECCAK_RHO_K[2]);
    state[3] = state[3].rotate_left(KECCAK_RHO_K[3]);
    state[4] = state[4].rotate_left(KECCAK_RHO_K[4]);
}

#[inline(always)]
fn keccak_rho(state: &mut Keccak1600) {
    keccak_rho_row0(state);
    keccak_rho_row(state, 1);
    keccak_rho_row(state, 2);
    keccak_rho_row(state, 3);
    keccak_rho_row(state, 4);
}

#[inline(always)]
fn keccak_pi(state: &mut Keccak1600) {
    let t: u64 = state[ 1]; state[ 1] = state[ 6]; state[ 6] = state[ 9]; state[ 9] = state[22]; state[22] = state[14];
    state[14] = state[20]; state[20] = state[ 2]; state[ 2] = state[12]; state[12] = state[13]; state[13] = state[19];
    state[19] = state[23]; state[23] = state[15]; state[15] = state[ 4]; state[ 4] = state[24]; state[24] = state[21];
    state[21] = state[ 8]; state[ 8] = state[16]; state[16] = state[ 5]; state[ 5] = state[ 3]; state[ 3] = state[18];
    state[18] = state[17]; state[17] = state[11]; state[11] = state[ 7]; state[ 7] = state[10]; state[10] = t;
}

#[inline(always)]
fn keccak_chi_row(state: &mut Keccak1600, r: usize) {
    let t1: u64 = state[5 * r + 0] ^ (!state[5 * r + 1] & state[5 * r + 2]);
    let t2: u64 = state[5 * r + 1] ^ (!state[5 * r + 2] & state[5 * r + 3]);

    state[5 * r + 2] ^= !state[5 * r + 3] & state[5 * r + 4];
    state[5 * r + 3] ^= !state[5 * r + 4] & state[5 * r + 0];
    state[5 * r + 4] ^= !state[5 * r + 0] & state[5 * r + 1];
    state[5 * r + 0] = t1;
    state[5 * r + 1] = t2;
}

#[inline(always)]
fn keccak_chi(state: &mut Keccak1600) {
    keccak_chi_row(state, 0);
    keccak_chi_row(state, 1);
    keccak_chi_row(state, 2);
    keccak_chi_row(state, 3);
    keccak_chi_row(state, 4);
}

#[inline(always)]
fn keccak_iota(state: &mut Keccak1600, rnd: usize) {
    state[0] ^= KECCAK_IOTA_K[rnd];
}

#[inline(always)]
fn keccak_perm_round(state: &mut Keccak1600, rnd: usize) {
    keccak_theta(state);
    keccak_rho(state);
    keccak_pi(state);
    keccak_chi(state);
    keccak_iota(state, rnd);
}

/// Textbook Keccak-f[1600]: the 24-round loop from FIPS 202 §3.3, in terms of
/// the five explicit step mappings (θ, ρ, π, χ, ι).
///
/// This is the production permutation: `keccak_permute` below routes through it.
/// `keccak_permute_opt` is the optimized variant, kept and proved functionally
/// equivalent in Lean (`keccak_permute_textbook_eq_opt`); it is reached only via
/// the proof harness and the in-crate cross-validation test.
fn keccak_permute_textbook(p_state: &mut Keccak1600) {
    for r in 0usize..24 {
        keccak_perm_round(p_state, r)
    }
}

fn keccak_permute(p_state: &mut Keccak1600) {
    keccak_permute_textbook(p_state);
}

//
// We normally want this to be private, but to
// access it from our benchmarking code we expose
// a public wrapper.
//
#[cfg(any(feature = "benchmarking", test))]
#[inline(always)]
pub fn keccak_permute_pub_wrapper(p_state: &mut Keccak1600) {
    keccak_permute(p_state);
}

impl KeccakState {

    /// Initializes the Keccak permutation state and sets mutable state variables
    /// to their default values.
    pub(crate) fn init(
        &mut self,
        input_block_size: u32,
        padding_value: u8,
    ) {
        self.input_block_size = input_block_size;
        self.padding_value = padding_value;

        self.reset();
    }

    /// Wipes the Keccak permutation state and sets the mutable state variables to their
    /// default values. Non-mutable state variables retain their values. State becomes
    /// re-initialized after this call.
    pub(crate) fn reset(&mut self) {
        crate::common::wipe_slice(&mut self.state);
        self.state_index = 0;
        self.squeeze_mode = false;
    }

    #[inline(always)]
    fn append_byte(
        &mut self,
        val: u8,
    ) {
        debug_assert!(!self.squeeze_mode);
        debug_assert!(self.state_index < self.input_block_size);

        self.state[(self.state_index as usize) / U64_NUM_BYTES] ^= (val as u64) << (8 * (self.state_index % 8));
        self.state_index += 1;
    }

    #[inline(always)]
    fn append_bytes(
        &mut self,
        buffer: &[u8],
    ) {
        let state_index = self.state_index as usize;

        debug_assert!(!self.squeeze_mode);
        debug_assert!((state_index + buffer.len()) <= (self.input_block_size as usize));

        for i in 0usize..buffer.len() {
            self.state[(state_index + i) / U64_NUM_BYTES] ^= (buffer[i] as u64) << (8 * ((state_index + i) % 8));
        }

        self.state_index += buffer.len() as u32;
    }

    pub(crate) fn append_lanes(
        &mut self,
        data: &[u8],
        lane_count: usize,
    ) {
        debug_assert!(!self.squeeze_mode);
        debug_assert!((self.input_block_size & 0x7) == 0);
        debug_assert!((self.state_index & 0x7) == 0);
        debug_assert!(self.state_index != self.input_block_size);

        // Locate the lane in the state for next append.
        // Currently, pState->stateIndex/sizeof(UINT64) of the lanes are used.
        let mut lane_index: usize = (self.state_index as usize) / U64_NUM_BYTES;

        for chunk in data.chunks_exact(U64_NUM_BYTES).take(lane_count) {
            self.state[lane_index] ^= u64::from_le_bytes(chunk.try_into().unwrap());
            self.state_index += U64_NUM_BYTES as u32;
            lane_index += 1;

            if self.state_index == self.input_block_size {
                keccak_permute(&mut self.state);
                self.state_index = 0;
                lane_index = 0;
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) fn zero_append_block(&mut self) {
        debug_assert!(!self.squeeze_mode);
        keccak_permute(&mut self.state);
        self.state_index = 0;
    }

    /// Appends data for the absorption phase, permuting whenever the input message block
    /// is filled. If the state is in squeeze mode, it is reset to absorb mode.
    pub(crate) fn append(
        &mut self,
        data: &[u8]
    ) {
        let mut rem_data_len : usize = data.len();

        debug_assert!(self.input_block_size % 8 == 0);

        // If we were in squeeze mode (Append is called after an Extract without wiping),
        // switch to absorb mode to start a new hash computation.
        if self.squeeze_mode {
            self.reset()
        }

        debug_assert!(self.state_index < self.input_block_size);

        // Make pState->stateIndex a multiple of 8.
        // Message block boundary will not be crossed, check
        // if permutation is needed after this part.
        let mut data_index: usize = 0;
        while (rem_data_len > 0) && (self.state_index & 0x7 != 0) {
           self.append_byte(data[data_index]);
            data_index += 1;
            rem_data_len -= 1;
        }

        // Permute if input message block is filled
        if self.state_index == self.input_block_size {
            keccak_permute(&mut self.state);
            self.state_index = 0
        }

        // Append full lanes
        let full_lanes: usize = rem_data_len / U64_NUM_BYTES;
        if full_lanes > 0 {
            self.append_lanes(&data[data_index..], full_lanes);
            data_index += full_lanes * U64_NUM_BYTES;
            rem_data_len -= full_lanes * U64_NUM_BYTES;
        }

        debug_assert!(rem_data_len < U64_NUM_BYTES);
        self.append_bytes(&data[data_index..]);

        debug_assert!(self.state_index != self.input_block_size);
    }

    /// Applies the state's initialized padding value, does a round of permutation,
    /// and then switches to squeeze mode.
    pub(crate) fn apply_padding(&mut self) {
        debug_assert!(!self.squeeze_mode);

        // Locate the lane and byte position for the padding byte
        let state_index  = self.state_index as usize;
        let lane_pos = state_index / U64_NUM_BYTES;
        let byte_pos = state_index % U64_NUM_BYTES;
        self.state[lane_pos] ^= (self.padding_value as u64) << (8 * byte_pos);

        // Pad the final 1 bit to the msb of the last lane in the rate portion of the state
        self.state[(self.input_block_size as usize) / U64_NUM_BYTES - 1] ^= 1u64 << 63;

        // Process the padded block and switch to squeeze mode
        keccak_permute(&mut self.state);
        self.state_index = 0;
        self.squeeze_mode = true;
    }

    #[inline(always)]
    fn extract_byte(
        &mut self,
    ) -> u8 {
        debug_assert!(self.squeeze_mode);
        debug_assert!(self.state_index < self.input_block_size);

        let state_index = self.state_index as usize;
        let ret: u8 = ( (self.state[state_index / U64_NUM_BYTES] >> (8 * (state_index % 8)) ) & 0xff) as u8;
        self.state_index += 1;
        return ret;
    }

    fn extract_lanes (
        &mut self,
        result: &mut [u8],
        lane_count: usize,
    ) {
        debug_assert!(self.squeeze_mode);
        debug_assert!((self.input_block_size & 0x7) == 0);
        debug_assert!((self.state_index & 0x7) == 0);

        // Locate the lane in the state for next extraction
        let mut lane_index: usize = (self.state_index as usize) / U64_NUM_BYTES;

        for i in 0usize..lane_count {
            debug_assert!(self.state_index <= self.input_block_size);

            if self.state_index == self.input_block_size {
                keccak_permute(&mut self.state);
                self.state_index = 0;
                lane_index = 0;
            }

            result[i*U64_NUM_BYTES..(i*U64_NUM_BYTES + U64_NUM_BYTES)]
                .copy_from_slice(&self.state[lane_index].to_le_bytes());
            self.state_index += U64_NUM_BYTES as u32;
            lane_index += 1;
        }
    }

    /// Extracts the hash value from the state, optionally wiping the state
    /// and resetting the hash (controlled by wipe). If the state is in absorb mode,
    /// it is first padded and permuted before swapping to squeeze mode.
    pub(crate) fn extract(
        &mut self,
        result: &mut [u8],
        wipe: bool,
    ) {
        let mut rem_result_len : usize = result.len();

        // Apply padding and switch to squeeze mode if this is the first call to Extract
        if !self.squeeze_mode{
            self.apply_padding();
        };

        // Do the permutation if there are no bytes available in the state
        if (rem_result_len > 0) && (self.state_index == self.input_block_size) {
            keccak_permute(&mut self.state);
            self.state_index = 0;
        }

        // Make state_index a multiple of 8 so that the extraction can be performed in lanes.
        // We don't call the permutation as soon as the state_index reaches input_block_size,
        // rem_result_len must also be non-zero for that. This condition is checked
        // in extract_lanes or in the 'remaining bytes' block that follows it.
        let mut result_index: usize = 0;
        while (rem_result_len > 0) && (self.state_index & 0x7 != 0) {
            result[result_index] = self.extract_byte();
            result_index += 1;
            rem_result_len -= 1;
        }

        // Extract full lanes
        let full_lanes: usize = rem_result_len / U64_NUM_BYTES;
        if full_lanes > 0 {
            self.extract_lanes(&mut result[result_index..], full_lanes);
            result_index += full_lanes * U64_NUM_BYTES;
            rem_result_len -= full_lanes * U64_NUM_BYTES;
        }

        debug_assert!(rem_result_len < U64_NUM_BYTES);

        // Extract the remaining bytes
        while rem_result_len > 0 {
            if self.state_index == self.input_block_size {
                keccak_permute(&mut self.state);
                self.state_index = 0;
            }

            result[result_index] = self.extract_byte();
            result_index += 1;
            rem_result_len -= 1;
        }

        if wipe {
            // Wipe the Keccak state and make it ready for a new hash computation
            self.reset();
        }
    }

}

#[cfg(all(test, not(feature = "benchmarking")))]
mod tests {
    use super::*;
    use rand::RngCore;

    unsafe extern "C" {
        pub(crate) fn SymCryptKeccakPermute(p_state: *mut u64);

        pub(crate) fn SymCryptKeccakInit(
            p_state: &mut KeccakState,
            input_block_size: u32,
            padding_value: u8);

        pub(crate) fn SymCryptKeccakAppend(
            p_state: &mut KeccakState,
            pb_data: *const u8,
            cb_data: usize);

        pub(crate) fn SymCryptKeccakZeroAppendBlock(p_state: &mut KeccakState);

        pub(crate) fn SymCryptKeccakExtract(
            p_state: &mut KeccakState,
            pb_result: *mut u8,
            cb_result: usize,
            b_wipe: u8);
    }

    #[test]
    fn test_keccak_permute() {
        let mut c_impl_state: Keccak1600 = [0; 25];
        let mut rust_impl_state: Keccak1600 = [0; 25];

        keccak_permute(&mut rust_impl_state);
        unsafe { SymCryptKeccakPermute(c_impl_state.as_mut_ptr()) };
        assert_eq!(rust_impl_state, c_impl_state);
    }

    /// Cross-validate the textbook FIPS 202 permutation against the optimized
    /// scalar permutation. Both must produce bit-identical state on a range of
    /// seeds; the Lean side proves the same equivalence.
    #[test]
    fn test_keccak_permute_textbook_matches_opt() {
        use rand::RngCore;
        let mut rng = rand::rng();
        for _ in 0..32 {
            let mut s_textbook: Keccak1600 = [0; 25];
            for w in s_textbook.iter_mut() { *w = rng.next_u64(); }
            let mut s_opt = s_textbook;
            keccak_permute_textbook(&mut s_textbook);
            super::super::keccak_opt::keccak_permute_opt(&mut s_opt);
            assert_eq!(s_textbook, s_opt);
        }
    }

    #[test]
    fn test_keccak_append_and_extract() {

        let mut c_keccak_state = KeccakState::default();
        let mut rust_keccak_state = KeccakState::default();

        unsafe { SymCryptKeccakInit( &mut c_keccak_state, 144, 0x06) };
        rust_keccak_state.init(144, 0x06);
        assert_eq!(c_keccak_state, rust_keccak_state);

        let mut rng = rand::rng();

        let mut data = [0u8; 1024];
        rng.fill_bytes(&mut data);

        rust_keccak_state.append(&data);
        unsafe { SymCryptKeccakAppend(&mut c_keccak_state, data.as_ptr(), data.len()) };
        assert_eq!(c_keccak_state, rust_keccak_state);

        let mut data = [0u8; 1024];
        rng.fill_bytes(&mut data);

        rust_keccak_state.append(&data);
        unsafe { SymCryptKeccakAppend(&mut c_keccak_state, data.as_ptr(), data.len()) };
        assert_eq!(c_keccak_state, rust_keccak_state);

        let mut rust_result = [0u8; 32];
        let mut c_result = [0u8; 32];

        rng.fill_bytes(&mut rust_result);
        rng.fill_bytes(&mut c_result);

        rust_keccak_state.extract(&mut rust_result, false);
        unsafe { SymCryptKeccakExtract(&mut c_keccak_state, c_result.as_mut_ptr(), c_result.len(), 0) };
        assert_eq!(c_keccak_state, rust_keccak_state);
        assert_eq!(c_result, rust_result);
    }

    #[test]
    fn test_zero_append_block() {
        let mut c_keccak_state = KeccakState::default();
        let mut rust_keccak_state = KeccakState::default();

        unsafe { SymCryptKeccakInit(&mut c_keccak_state, 144, 0x06) };
        rust_keccak_state.init(144, 0x06);
        assert_eq!(c_keccak_state, rust_keccak_state);

        let mut rng = rand::rng();

        let mut data = [0u8; 72];  // Partial block to make stateIndex != 0
        rng.fill_bytes(&mut data);

        rust_keccak_state.zero_append_block();
        unsafe { SymCryptKeccakZeroAppendBlock(&mut c_keccak_state) };

        assert_eq!(c_keccak_state, rust_keccak_state);
    }
}