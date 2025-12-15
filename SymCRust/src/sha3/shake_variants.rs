//
// shake_variants.rs   SymCrypt SHAKE variants Rust implementation
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

use crate::hash::{StatefulXof, OneShotXof, HashParams};
use crate::sha3::sha3_impl::KeccakState;

pub(crate) const SHAKE_PADDING_VALUE: u8 = 0x1f;

struct Shake128Params;
struct Shake256Params;

impl HashParams for Shake128Params {
    const RESULT_SIZE: usize = 32;
    const BLOCK_SIZE: u32 = 168;
}

impl HashParams for Shake256Params {
    const RESULT_SIZE: usize = 64;
    const BLOCK_SIZE: u32 = 136;
}

#[derive(Clone, PartialEq, Debug)]
pub struct ShakeState<const RESULT_SIZE:usize, const BLOCK_SIZE:u32> {
    pub(crate) state: KeccakState
}

impl<const RESULT_SIZE:usize, const BLOCK_SIZE:u32>
    StatefulXof<RESULT_SIZE, BLOCK_SIZE>
    for ShakeState<RESULT_SIZE, BLOCK_SIZE>
{
    fn new() -> Self {
        let mut shake_state = Self {
            state: KeccakState::default(),
        };
        shake_state.state.init(BLOCK_SIZE, SHAKE_PADDING_VALUE);

        return shake_state
    }

    fn append(&mut self, data: &[u8]) {
        self.state.append(data);
    }

    fn extract(&mut self, result: &mut[u8], wipe: bool) {
        self.state.extract(result, wipe);
    }

    fn result(&mut self, result: &mut [u8; RESULT_SIZE]) {
        self.state.extract(result, true);
    }
}

impl<const RESULT_SIZE:usize, const BLOCK_SIZE:u32>
    Default
    for ShakeState<RESULT_SIZE, BLOCK_SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

pub type Shake128State = ShakeState<{Shake128Params::RESULT_SIZE}, {Shake128Params::BLOCK_SIZE}>;
pub type Shake256State = ShakeState<{Shake256Params::RESULT_SIZE}, {Shake256Params::BLOCK_SIZE}>;

pub struct OneShotShake<const RESULT_SIZE:usize, const BLOCK_SIZE:u32>;

impl<const RESULT_SIZE:usize, const BLOCK_SIZE:u32>
    OneShotXof<RESULT_SIZE, BLOCK_SIZE>
    for OneShotShake<RESULT_SIZE, BLOCK_SIZE>
{
    fn xof(data: &[u8], result: &mut [u8]) {
        let mut state = ShakeState::<RESULT_SIZE, BLOCK_SIZE>::new();
        state.append(data);
        state.extract(result, true);
    }

    fn self_test() {
        todo!();
    }
}

pub type Shake128 = OneShotShake<{Shake128Params::RESULT_SIZE}, {Shake128Params::BLOCK_SIZE}>;
pub type Shake256 = OneShotShake<{Shake256Params::RESULT_SIZE}, {Shake256Params::BLOCK_SIZE}>;