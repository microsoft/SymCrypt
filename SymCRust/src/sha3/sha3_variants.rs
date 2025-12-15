//
// sha3_variants.rs   SymCrypt SHA3 variants Rust implementation
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

use crate::hash::{StatefulHash, OneShotHash, HashParams};
use crate::sha3::sha3_impl::KeccakState;

pub(crate) const SHA3_PADDING_VALUE : u8 = 0x06;

struct Sha3_224Params;
struct Sha3_256Params;
struct Sha3_384Params;
struct Sha3_512Params;

impl HashParams for Sha3_224Params {
    const RESULT_SIZE: usize = 28;
    const BLOCK_SIZE: u32 = 144;
}

impl HashParams for Sha3_256Params {
    const RESULT_SIZE: usize = 32;
    const BLOCK_SIZE: u32 = 136;
}

impl HashParams for Sha3_384Params {
    const RESULT_SIZE: usize = 48;
    const BLOCK_SIZE: u32 = 104;
}

impl HashParams for Sha3_512Params {
    const RESULT_SIZE: usize = 64;
    const BLOCK_SIZE: u32 = 72;
}

#[derive(Clone, PartialEq, Debug)]
pub struct Sha3State<const RESULT_SIZE:usize, const BLOCK_SIZE:u32> {
    pub(crate) state: KeccakState,
}

impl <const RESULT_SIZE:usize, const BLOCK_SIZE:u32>
    StatefulHash<RESULT_SIZE, BLOCK_SIZE>
    for Sha3State<RESULT_SIZE, BLOCK_SIZE>
{
    fn new() -> Self {
        let mut sha3_state = Self {
            state: KeccakState::default(),
        };
        sha3_state.state.init(BLOCK_SIZE, SHA3_PADDING_VALUE);

        return sha3_state
    }

    fn append(&mut self, data: &[u8]) {
        self.state.append(data);
    }

    fn result(&mut self, result: &mut [u8; RESULT_SIZE]) {
        self.state.extract(result, true);
    }

    fn export_state(&self) {
        todo!();
    }

    fn import_state(&mut self) {
        todo!();
    }
}

impl<const RESULT_SIZE:usize, const BLOCK_SIZE:u32>
    Default
    for Sha3State<RESULT_SIZE, BLOCK_SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

pub type Sha3_224State = Sha3State<{Sha3_224Params::RESULT_SIZE}, {Sha3_224Params::BLOCK_SIZE}>;
pub type Sha3_256State = Sha3State<{Sha3_256Params::RESULT_SIZE}, {Sha3_256Params::BLOCK_SIZE}>;
pub type Sha3_384State = Sha3State<{Sha3_384Params::RESULT_SIZE}, {Sha3_384Params::BLOCK_SIZE}>;
pub type Sha3_512State = Sha3State<{Sha3_512Params::RESULT_SIZE}, {Sha3_512Params::BLOCK_SIZE}>;

pub struct OneShotSha3<const RESULT_SIZE:usize, const BLOCK_SIZE:u32>;

impl<const RESULT_SIZE:usize, const BLOCK_SIZE:u32>
    OneShotHash<RESULT_SIZE, BLOCK_SIZE>
    for OneShotSha3<RESULT_SIZE, BLOCK_SIZE>
{
    fn hash(data: &[u8], result: &mut [u8; RESULT_SIZE]) {
        let mut state = Sha3State::<RESULT_SIZE, BLOCK_SIZE>::new();
        state.append(data);
        state.result(result);
    }

    fn self_test() {
        todo!();
    }
}

pub type Sha3_224 = OneShotSha3<{Sha3_224Params::RESULT_SIZE}, {Sha3_224Params::BLOCK_SIZE}>;
pub type Sha3_256 = OneShotSha3<{Sha3_256Params::RESULT_SIZE}, {Sha3_256Params::BLOCK_SIZE}>;
pub type Sha3_384 = OneShotSha3<{Sha3_384Params::RESULT_SIZE}, {Sha3_384Params::BLOCK_SIZE}>;
pub type Sha3_512 = OneShotSha3<{Sha3_512Params::RESULT_SIZE}, {Sha3_512Params::BLOCK_SIZE}>;