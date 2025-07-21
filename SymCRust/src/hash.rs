//
// hash.rs   Wrapper around FFI into SymCrypt hashing required for ML-KEM
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// Note (Rust): SymCrypt relies on its callers stack-allocating the various states, so we need to
// reveal the definition of the various shake and sha3 states.
// Note (Rust) fortunately, it turns out that these are all the same under the hood. This fact is
// not revealed to clients of SymCrypt, but since we are an internal client, we can leverage that
// and save the need for a tagged union in Rust.

// Previously, was:
/*union HashStateUnion {
    shake128State: shake128State,
    shake256State: shake256State,
    sha3_256State: sha3_256State,
    sha3_512State: sha3_512State,
}*/

// Not all of the bindings are used so far -- we leave them for now.
#![allow(dead_code)]

#[repr(C)]
#[repr(align(16))]
struct KeccakState {
    state: [u64; 25],      // state for Keccak-f[1600] permutation
    input_block_size: u32, // rate
    state_index: u32,      // position in the state for next merge/extract operation
    padding_value: u8,     // Keccak padding value
    squeeze_mode: bool,    // denotes whether the state is in squeeze mode
}

#[repr(C)]
#[repr(align(16))]
pub(crate) struct HashState {
    ks: KeccakState,
    magic: usize,
}

pub(crate) const UNINITIALIZED_HASH_STATE: HashState = HashState {
    ks: KeccakState {
        state: [0u64; 25],
        input_block_size: 0,
        state_index: 0,
        padding_value: 0,
        squeeze_mode: false,
    },
    magic: 0, // set by the various init* functions
};

pub const SHAKE128_RESULT_SIZE: usize = 32;
pub const SHAKE128_INPUT_BLOCK_SIZE: usize = 168;

pub const SHAKE256_RESULT_SIZE: usize = 64;
pub const SHAKE256_INPUT_BLOCK_SIZE: usize = 136;

pub const SHA3_256_RESULT_SIZE: usize = 32;
pub const SHA3_256_INPUT_BLOCK_SIZE: usize = 136;

pub const SHA3_512_RESULT_SIZE: usize = 64;
pub const SHA3_512_INPUT_BLOCK_SIZE: usize = 72;

extern "C" {
    fn SymCryptShake128Default(
        pb_data: *const u8,
        cbData: usize,
        pb_result: &mut [u8; SHAKE128_RESULT_SIZE],
    );
    fn SymCryptShake128(pb_data: *const u8, cbData: usize, pb_result: *mut u8, cbResult: usize);
    fn SymCryptShake128Init(p_state: &mut HashState);
    fn SymCryptShake128Append(p_state: &mut HashState, pb_data: *const u8, cbData: usize);
    fn SymCryptShake128Extract(
        p_state: &mut HashState,
        pb_result: *mut u8,
        cbResult: usize,
        bWipe: bool,
    );
    fn SymCryptShake128Result(p_state: &mut HashState, pb_result: &mut [u8; SHAKE128_RESULT_SIZE]);
    fn SymCryptShake128StateCopy(p_src: &HashState, p_dst: &mut HashState);

    fn SymCryptShake256Default(
        pb_data: *const u8,
        cbData: usize,
        pb_result: &mut [u8; SHAKE256_RESULT_SIZE],
    );
    fn SymCryptShake256(pb_data: *const u8, cbData: usize, pb_result: *mut u8, cbResult: usize);
    fn SymCryptShake256Init(p_state: &mut HashState);
    fn SymCryptShake256Append(p_state: &mut HashState, pb_data: *const u8, cbData: usize);
    fn SymCryptShake256Extract(
        p_state: &mut HashState,
        pb_result: *mut u8,
        cbResult: usize,
        bWipe: bool,
    );
    fn SymCryptShake256Result(p_state: &mut HashState, pb_result: &mut [u8; SHAKE256_RESULT_SIZE]);
    fn SymCryptShake256StateCopy(p_src: &HashState, p_dst: &mut HashState);

    fn SymCryptSha3_256(
        pb_data: *const u8,
        cbData: usize,
        pb_result: &mut [u8; SHA3_256_RESULT_SIZE],
    );
    fn SymCryptSha3_256Init(p_state: &mut HashState);
    fn SymCryptSha3_256Append(p_state: &mut HashState, pb_data: *const u8, cbData: usize);
    fn SymCryptSha3_256Result(p_state: &mut HashState, pb_result: &mut [u8; SHA3_256_RESULT_SIZE]);
    fn SymCryptSha3_256StateCopy(p_src: &HashState, p_dst: &mut HashState);

    fn SymCryptSha3_512(
        pb_data: *const u8,
        cbData: usize,
        pb_result: &mut [u8; SHA3_512_RESULT_SIZE],
    );
    fn SymCryptSha3_512Init(p_state: &mut HashState);
    fn SymCryptSha3_512Append(p_state: &mut HashState, pb_data: *const u8, cbData: usize);
    fn SymCryptSha3_512Result(p_state: &mut HashState, pb_result: &mut [u8; SHA3_512_RESULT_SIZE]);
    fn SymCryptSha3_512StateCopy(p_src: &HashState, p_dst: &mut HashState);
}

// SHAKE128

pub(crate) fn shake128_default(data: &[u8], dst: &mut [u8; SHAKE128_RESULT_SIZE]) {
    unsafe { SymCryptShake128Default(data.as_ptr(), data.len(), dst) }
}

pub(crate) fn shake128(pb_data: &[u8], pb_result: &mut [u8]) {
    unsafe {
        SymCryptShake128(
            pb_data.as_ptr(),
            pb_data.len(),
            pb_result.as_mut_ptr(),
            pb_result.len(),
        )
    }
}

pub(crate) fn shake128_init(p_state: &mut HashState) {
    unsafe { SymCryptShake128Init(p_state) }
}

pub(crate) fn shake128_append(p_state: &mut HashState, pb_data: &[u8]) {
    unsafe { SymCryptShake128Append(p_state, pb_data.as_ptr(), pb_data.len()) }
}

pub(crate) fn shake128_extract(p_state: &mut HashState, dst: &mut [u8], wipe: bool) {
    unsafe { SymCryptShake128Extract(p_state, dst.as_mut_ptr(), dst.len(), wipe) }
}

pub(crate) fn shake128_result(p_state: &mut HashState, pb_result: &mut [u8; SHAKE128_RESULT_SIZE]) {
    unsafe { SymCryptShake128Result(p_state, pb_result) }
}

pub(crate) fn shake128_state_copy(p_src: &HashState, p_dst: &mut HashState) {
    unsafe { SymCryptShake128StateCopy(p_src, p_dst) }
}

// SHAKE256

pub(crate) fn shake256_default(data: &[u8], dst: &mut [u8; SHAKE256_RESULT_SIZE]) {
    unsafe { SymCryptShake256Default(data.as_ptr(), data.len(), dst) }
}

pub(crate) fn shake256(pb_data: &[u8], pb_result: &mut [u8]) {
    unsafe {
        SymCryptShake256(
            pb_data.as_ptr(),
            pb_data.len(),
            pb_result.as_mut_ptr(),
            pb_result.len(),
        )
    }
}

pub(crate) fn shake256_init(p_state: &mut HashState) {
    unsafe { SymCryptShake256Init(p_state) }
}

pub(crate) fn shake256_append(p_state: &mut HashState, pb_data: &[u8]) {
    unsafe { SymCryptShake256Append(p_state, pb_data.as_ptr(), pb_data.len()) }
}

pub(crate) fn shake256_extract(p_state: &mut HashState, dst: &mut [u8], wipe: bool) {
    unsafe { SymCryptShake256Extract(p_state, dst.as_mut_ptr(), dst.len(), wipe) }
}

pub(crate) fn shake256_result(p_state: &mut HashState, pb_result: &mut [u8; SHAKE256_RESULT_SIZE]) {
    unsafe { SymCryptShake256Result(p_state, pb_result) }
}

pub(crate) fn shake256_state_copy(p_src: &HashState, p_dst: &mut HashState) {
    unsafe { SymCryptShake256StateCopy(p_src, p_dst) }
}

// SHA3_256

pub(crate) fn sha3_256(pb_data: &[u8], pb_result: &mut [u8; SHA3_256_RESULT_SIZE]) {
    unsafe { SymCryptSha3_256(pb_data.as_ptr(), pb_data.len(), pb_result) }
}

pub(crate) fn sha3_256_init(p_state: &mut HashState) {
    unsafe { SymCryptSha3_256Init(p_state) }
}

pub(crate) fn sha3_256_append(p_state: &mut HashState, pb_data: &[u8]) {
    unsafe { SymCryptSha3_256Append(p_state, pb_data.as_ptr(), pb_data.len()) }
}

pub(crate) fn sha3_256_result(p_state: &mut HashState, pb_result: &mut [u8; SHA3_256_RESULT_SIZE]) {
    unsafe { SymCryptSha3_256Result(p_state, pb_result) }
}

pub(crate) fn sha3_256_state_copy(p_src: &HashState, p_dst: &mut HashState) {
    unsafe { SymCryptSha3_256StateCopy(p_src, p_dst) }
}

// SHA3_512

pub(crate) fn sha3_512(pb_data: &[u8], pb_result: &mut [u8; SHA3_512_RESULT_SIZE]) {
    unsafe { SymCryptSha3_512(pb_data.as_ptr(), pb_data.len(), pb_result) }
}

pub(crate) fn sha3_512_init(p_state: &mut HashState) {
    unsafe { SymCryptSha3_512Init(p_state) }
}

pub(crate) fn sha3_512_append(p_state: &mut HashState, pb_data: &[u8]) {
    unsafe { SymCryptSha3_512Append(p_state, pb_data.as_ptr(), pb_data.len()) }
}

pub(crate) fn sha3_512_result(p_state: &mut HashState, pb_result: &mut [u8; SHA3_512_RESULT_SIZE]) {
    unsafe { SymCryptSha3_512Result(p_state, pb_result) }
}

pub(crate) fn sha3_512_state_copy(p_src: &HashState, p_dst: &mut HashState) {
    unsafe { SymCryptSha3_512StateCopy(p_src, p_dst) }
}
