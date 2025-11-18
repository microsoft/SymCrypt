//
// sha3_224.rs   SymCrypt SHA3 224 Rust implementation
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

use crate::hash::*;
use crate::sha3::sha3_impl::KeccakState;

pub const SHA3_224_RESULT_SIZE: usize = 28;
pub const SHA3_224_INPUT_BLOCK_SIZE: u32 = 144;
pub const SHA3_224_PADDING_VALUE: u8 = 0x06;

#[derive(Clone, PartialEq, Debug, Default)]
pub struct Sha3_224HashState {
    pub(crate) state: KeccakState,
}

impl Hash for Sha3_224HashState {

    fn hash(&mut self, data: &[u8], result: &mut [u8]) {
        *self = Sha3_224HashState::default();
        self.init();
        self.append(data);
        self.result(result);
    }

    fn init(&mut self) {
       self.state.init(SHA3_224_INPUT_BLOCK_SIZE, SHA3_224_PADDING_VALUE);
    }

    fn append(&mut self, data: &[u8]) {
        self.state.append(data);
    }

    fn result(&mut self, result: &mut [u8]) {
        self.state.extract(result, true);
    }

    fn export_state(&self) {
        todo!();
    }

    fn import_state(&mut self) {
        todo!();
    }

    fn self_test(&self) {
        todo!();
    }
}

#[cfg(all(test, not(feature = "benchmarking")))]
mod tests {
    use super::*;
    use rand::RngCore;
    use crate::sha3::ffi::CSha3_224State;

    unsafe extern "C" {
        pub(crate) fn SymCryptSha3_224(
            pb_data: *const u8,
            cbData: usize,
            pb_result: &mut [u8; crate::sha3::sha3_224::SHA3_224_RESULT_SIZE],
        );

        pub(crate) fn SymCryptSha3_224Init(p_state: &mut CSha3_224State);

        pub(crate) fn SymCryptSha3_224Append(p_state: &mut CSha3_224State, pb_data: *const u8, cbData: usize);

        pub(crate) fn SymCryptSha3_224Result(p_state: &mut CSha3_224State, pb_result: &mut [u8; crate::sha3::sha3_224::SHA3_224_RESULT_SIZE]);
    }

    #[test]
    fn test_sha224() {
        let mut c_sha3_224_state = CSha3_224State::default();
        let mut rust_sha3_224_state = Sha3_224HashState::default();

        unsafe {SymCryptSha3_224Init(&mut c_sha3_224_state);}
        rust_sha3_224_state.init();
        assert_eq!(c_sha3_224_state.state, rust_sha3_224_state.state);

        let mut rng = rand::rng();

        let mut data = [0u8; 1024];
        rng.fill_bytes(&mut data);

        unsafe {SymCryptSha3_224Append(&mut c_sha3_224_state, data.as_ptr(), data.len());}
        rust_sha3_224_state.append(&data);
        assert_eq!(c_sha3_224_state.state, rust_sha3_224_state.state);

        let mut data = [0u8; 1024];
        rng.fill_bytes(&mut data);

        unsafe {SymCryptSha3_224Append(&mut c_sha3_224_state, data.as_ptr(), data.len());}
        rust_sha3_224_state.append(&data);
        assert_eq!(c_sha3_224_state.state, rust_sha3_224_state.state);

        let mut c_result = [0u8; SHA3_224_RESULT_SIZE];
        let mut rust_result = [0u8; SHA3_224_RESULT_SIZE];

        unsafe {SymCryptSha3_224Result(&mut c_sha3_224_state, &mut c_result);}
        rust_sha3_224_state.result(&mut rust_result);
        assert_eq!(c_sha3_224_state.state, rust_sha3_224_state.state);
        assert_eq!(rust_result, c_result);

        c_result = [0u8; SHA3_224_RESULT_SIZE];
        rust_result = [0u8; SHA3_224_RESULT_SIZE];
        unsafe {SymCryptSha3_224(data.as_ptr(), data.len(), &mut c_result);}
        rust_sha3_224_state.hash(&data, &mut rust_result);
        assert_eq!(rust_result, c_result);
    }

}
