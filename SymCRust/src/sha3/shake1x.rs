// EXPERIMENTAL CODE --- NOT YET INTEGRATED WITH SYMCRYPT
//
// shake1x.rs   Pure-Rust single-stream SHAKE/SHA3 for ML-KEM/ML-DSA/FrodoKEM
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Provides verified SHA3/SHAKE wrappers using KeccakState directly.
// API follows init/append/extract convention matching the SymCrypt C API.
// No FFI — works in any build mode.
//

#![allow(dead_code)]

use crate::sha3::sha3_impl::KeccakState;

const SHAKE128_RATE: u32 = 168;
const SHAKE256_RATE: u32 = 136;
const SHA3_256_RATE: u32 = 136;
const SHA3_512_RATE: u32 = 72;
const SHAKE_PADDING: u8 = 0x1F;
const SHA3_PADDING: u8 = 0x06;

// ── SHAKE256 (H / PRF in MLDSA, J / PRF in MLKEM) ──

/// One-shot SHAKE256.
pub(crate) fn shake256(input: &[u8], output: &mut [u8]) {
    let mut state = KeccakState::default();
    state.init(SHAKE256_RATE, SHAKE_PADDING);
    state.append(input);
    state.extract(output, true);
}

/// Incremental SHAKE256 XOF.
pub(crate) struct HXof {
    state: KeccakState,
}

impl HXof {
    pub(crate) fn new() -> Self {
        let mut state = KeccakState::default();
        state.init(SHAKE256_RATE, SHAKE_PADDING);
        Self { state }
    }
    pub(crate) fn append(&mut self, data: &[u8]) { self.state.append(data); }
    pub(crate) fn extract(&mut self, output: &mut [u8]) { self.state.extract(output, false); }
    pub(crate) fn extract_and_wipe(&mut self, output: &mut [u8]) { self.state.extract(output, true); }
}

// ── SHAKE128 (XOF / G in MLKEM, G in MLDSA, SHAKE in FrodoKEM-640) ──

/// One-shot SHAKE128.
pub(crate) fn shake128(input: &[u8], output: &mut [u8]) {
    let mut state = KeccakState::default();
    state.init(SHAKE128_RATE, SHAKE_PADDING);
    state.append(input);
    state.extract(output, true);
}

/// Incremental SHAKE128 XOF.
pub(crate) struct GXof {
    state: KeccakState,
}

impl GXof {
    pub(crate) fn new() -> Self {
        let mut state = KeccakState::default();
        state.init(SHAKE128_RATE, SHAKE_PADDING);
        Self { state }
    }
    pub(crate) fn append(&mut self, data: &[u8]) { self.state.append(data); }
    pub(crate) fn extract(&mut self, output: &mut [u8]) { self.state.extract(output, false); }
    pub(crate) fn extract_and_wipe(&mut self, output: &mut [u8]) { self.state.extract(output, true); }
}

// ── SHA3-256 (H in MLKEM) ──

pub(crate) const SHA3_256_RESULT_SIZE: usize = 32;

/// One-shot SHA3-256.
pub(crate) fn sha3_256(input: &[u8], output: &mut [u8; SHA3_256_RESULT_SIZE]) {
    let mut state = KeccakState::default();
    state.init(SHA3_256_RATE, SHA3_PADDING);
    state.append(input);
    state.extract(output, true);
}

/// Incremental SHA3-256.
pub(crate) struct Sha3_256State {
    state: KeccakState,
}

impl Sha3_256State {
    pub(crate) fn new() -> Self {
        let mut state = KeccakState::default();
        state.init(SHA3_256_RATE, SHA3_PADDING);
        Self { state }
    }
    pub(crate) fn append(&mut self, data: &[u8]) { self.state.append(data); }
    pub(crate) fn extract(&mut self, output: &mut [u8; SHA3_256_RESULT_SIZE]) {
        self.state.extract(output, true);
    }
}

// ── SHA3-512 (G in MLKEM) ──

pub(crate) const SHA3_512_RESULT_SIZE: usize = 64;

/// One-shot SHA3-512.
pub(crate) fn sha3_512(input: &[u8], output: &mut [u8; SHA3_512_RESULT_SIZE]) {
    let mut state = KeccakState::default();
    state.init(SHA3_512_RATE, SHA3_PADDING);
    state.append(input);
    state.extract(output, true);
}

/// Incremental SHA3-512.
pub(crate) struct Sha3_512State {
    state: KeccakState,
}

impl Sha3_512State {
    pub(crate) fn new() -> Self {
        let mut state = KeccakState::default();
        state.init(SHA3_512_RATE, SHA3_PADDING);
        Self { state }
    }
    pub(crate) fn append(&mut self, data: &[u8]) { self.state.append(data); }
    pub(crate) fn extract(&mut self, output: &mut [u8; SHA3_512_RESULT_SIZE]) {
        self.state.extract(output, true);
    }
}
