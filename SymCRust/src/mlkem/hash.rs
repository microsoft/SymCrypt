//
// hash.rs   Wrapper around Keccak for sharing ML-KEM Keccak states
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// Note (Rust): As an internal client, we directly act on KeccakState rather than the more
// straightforward approach of using a tagged union of our defined variants.
// This is to avoid unnecessary drops when reusing a state for different higher level algorithms.

// Previously, was:
/*union HashStateUnion {
    shake128State: shake128State,
    shake256State: shake256State,
    sha3_256State: sha3_256State,
    sha3_512State: sha3_512State,
}*/

use crate::sha3::sha3_impl::KeccakState;
use crate::sha3::{SHA3_PADDING_VALUE, SHAKE_PADDING_VALUE};
use crate::sha3::{Sha3_256, Sha3_512, Shake128, Shake256};
use crate::hash::{OneShotHash, OneShotXof};

#[derive(Default, Clone, Copy, PartialEq)]
pub(super) enum MlKemHashAlg {
    #[default]
    None,
    Shake128,
    Shake256,
    Sha3_256,
    Sha3_512,
}

///
/// A custom hash state for ML-KEM so that we can flexibly
/// swap between different hash algorithms as needed without
/// invoking drop each time.
///
#[derive(Default, Clone)]
pub(super) struct MlKemHashState {
    state: KeccakState,
    alg: MlKemHashAlg,
}

impl MlKemHashState {
    pub(super) fn set_alg(&mut self, alg: MlKemHashAlg) {
        self.alg = alg;
    }

    pub(super) fn get_alg(&self) -> MlKemHashAlg {
        return self.alg;
    }

    fn get_padding_value(&self) -> u8 {
        match self.alg {
            MlKemHashAlg::Shake128 | MlKemHashAlg::Shake256 => return SHAKE_PADDING_VALUE,
            MlKemHashAlg::Sha3_256 | MlKemHashAlg::Sha3_512 => return SHA3_PADDING_VALUE,
            _ => panic!("Invalid hash algorithm"),
        }
    }

    fn get_block_size(&self) -> u32 {
        match self.alg {
            MlKemHashAlg::Shake128 => return Shake128::BLOCK_SIZE,
            MlKemHashAlg::Shake256 => return Shake256::BLOCK_SIZE,
            MlKemHashAlg::Sha3_256 => return Sha3_256::BLOCK_SIZE,
            MlKemHashAlg::Sha3_512 => return Sha3_512::BLOCK_SIZE,
            _ => panic!("Invalid hash algorithm"),
        }
    }

    fn get_result_size(&self) -> usize {
        match self.alg {
            MlKemHashAlg::Shake128 => return Shake128::RESULT_SIZE,
            MlKemHashAlg::Shake256 => return Shake256::RESULT_SIZE,
            MlKemHashAlg::Sha3_256 => return Sha3_256::RESULT_SIZE,
            MlKemHashAlg::Sha3_512 => return Sha3_512::RESULT_SIZE,
            _ => panic!("Invalid hash algorithm"),
        }
    }

    pub(super) fn init(&mut self) {
        self.state.init(self.get_block_size(), self.get_padding_value());
    }

    pub(super) fn append(&mut self, data: &[u8]) {
        self.state.append(data);
    }

    pub(super) fn result(&mut self, result: &mut [u8]) {
        debug_assert_eq!(result.len(), self.get_result_size());
        self.state.extract(result, true);
    }

    pub(super) fn extract(&mut self, result: &mut[u8], wipe: bool) {
        debug_assert!(self.alg == MlKemHashAlg::Shake128 || self.alg == MlKemHashAlg::Shake256);
        self.state.extract(result, wipe);
    }
}
