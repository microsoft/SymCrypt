// EXPERIMENTAL CODE --- NOT YET INTEGRATED WITH SYMCRYPT
//
// hash_4x.rs   4-way parallel SHAKE128/256 for ML-DSA sampling
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Wraps Keccak4xHybrid to provide 4 independent SHAKE streams.
// Design: after finalize, callers access squeeze output via `block(inst)`
// which returns a &[u8] slice of the current rate block — zero copy.
// Call `next_block()` to permute all 4 and advance to the next block.
//

#![allow(dead_code)]

use crate::sha3::keccak4x_hybrid::Keccak4xHybrid;

const U64_BYTES: usize = 8;

/// 4-way parallel SHAKE XOF state with zero-copy block access.
pub(crate) struct Shake4x {
    state: Keccak4xHybrid,
    rate: usize,
    rate_lanes: usize,
    /// Per-instance squeeze output (one rate block, pre-extracted).
    buf: [[u8; 168]; 4], // 168 = max rate (SHAKE128)
    /// Bytes absorbed per instance (absorb phase only).
    absorbed: [usize; 4],
    finalized: bool,
}

impl Shake4x {
    pub(crate) fn new_128() -> Self {
        Self {
            state: Keccak4xHybrid::new(), rate: 168, rate_lanes: 168 / 8,
            buf: [[0u8; 168]; 4], absorbed: [0; 4], finalized: false,
        }
    }

    pub(crate) fn new_256() -> Self {
        Self {
            state: Keccak4xHybrid::new(), rate: 136, rate_lanes: 136 / 8,
            buf: [[0u8; 168]; 4], absorbed: [0; 4], finalized: false,
        }
    }

    pub(crate) fn append(&mut self, inst: usize, data: &[u8]) {
        debug_assert!(!self.finalized && inst < 4);
        let pos = self.absorbed[inst];
        debug_assert!(pos + data.len() <= self.rate);

        let mut offset = 0;
        let mut lane_idx = pos / U64_BYTES;
        let byte_off = pos % U64_BYTES;

        if byte_off != 0 {
            let remaining = U64_BYTES - byte_off;
            let take = data.len().min(remaining);
            let mut v = 0u64;
            for i in 0..take { v |= (data[i] as u64) << (8 * (byte_off + i)); }
            self.state.xor_lane(lane_idx, inst, v);
            offset += take;
            if take == remaining { lane_idx += 1; }
        }
        while offset + U64_BYTES <= data.len() {
            let v = u64::from_le_bytes(data[offset..offset + U64_BYTES].try_into().unwrap());
            self.state.xor_lane(lane_idx, inst, v);
            lane_idx += 1;
            offset += U64_BYTES;
        }
        if offset < data.len() {
            let mut v = 0u64;
            for i in 0..(data.len() - offset) { v |= (data[offset + i] as u64) << (8 * i); }
            self.state.xor_lane(lane_idx, inst, v);
        }
        self.absorbed[inst] = pos + data.len();
    }

    /// Apply SHAKE padding to all 4 instances (shared helper).
    fn pad_all(&mut self) {
        debug_assert!(!self.finalized);
        for inst in 0..4 {
            let pos = self.absorbed[inst];
            let lane_idx = pos / U64_BYTES;
            let byte_off = pos % U64_BYTES;
            self.state.xor_lane(lane_idx, inst, 0x1Fu64 << (8 * byte_off));
            let last_lane = (self.rate - 1) / U64_BYTES;
            let last_byte = (self.rate - 1) % U64_BYTES;
            self.state.xor_lane(last_lane, inst, 0x80u64 << (8 * last_byte));
        }
    }

    /// Apply SHAKE padding and permute, then extract the first block.
    pub(crate) fn finalize_all(&mut self) {
        self.pad_all();
        self.state.permute();
        self.extract_all();
        self.finalized = true;
    }

    /// Apply SHAKE padding and permute without extracting.
    /// Use when callers will read Lane4 words directly via `state_ref()`.
    pub(crate) fn finalize_no_extract(&mut self) {
        self.pad_all();
        self.state.permute();
        self.finalized = true;
    }

    /// Extract the current Keccak state into the 4 output buffers.
    /// Lane-major order: read each Lane4 once (contiguous), scatter to 4 buffers.
    fn extract_all(&mut self) {
        for lane in 0..self.rate_lanes {
            // Read all 4 instances of this lane in one contiguous access
            let values = [
                self.state.get_lane(lane, 0),
                self.state.get_lane(lane, 1),
                self.state.get_lane(lane, 2),
                self.state.get_lane(lane, 3),
            ];
            let off = lane * 8;
            self.buf[0][off..off + 8].copy_from_slice(&values[0].to_le_bytes());
            self.buf[1][off..off + 8].copy_from_slice(&values[1].to_le_bytes());
            self.buf[2][off..off + 8].copy_from_slice(&values[2].to_le_bytes());
            self.buf[3][off..off + 8].copy_from_slice(&values[3].to_le_bytes());
        }
    }

    /// Get the current rate block for one instance (zero-copy read).
    #[inline(always)]
    pub(crate) fn block(&self, inst: usize) -> &[u8] {
        debug_assert!(self.finalized && inst < 4);
        &self.buf[inst][..self.rate]
    }

    /// Permute all 4 instances and extract the next rate block.
    pub(crate) fn next_block(&mut self) {
        debug_assert!(self.finalized);
        self.state.permute();
        self.extract_all();
    }

    /// Permute without extracting (for callers that read lanes directly).
    pub(crate) fn next_block_no_extract(&mut self) {
        debug_assert!(self.finalized);
        self.state.permute();
    }

    /// Direct access to the underlying Keccak state (for zero-copy lane reads).
    #[inline(always)]
    pub(crate) fn state_ref(&self) -> &Keccak4xHybrid {
        &self.state
    }
}

