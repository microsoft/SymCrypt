//
// tests.rs  Local Rust test module used to check parity between the Rust and C implementations of
// the SHA3 class of algorithms.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

use rand::RngCore;
use crate::sha3::ffi::{CFfiSha3_224State, CFfiSha3_256State, CFfiSha3_384State, CFfiSha3_512State, CFfiShake128State, CFfiShake256State};
use crate::sha3::{Sha3_224State, Sha3_256State, Sha3_384State, Sha3_512State, Shake128State, Shake256State};
use crate::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256};

use crate::hash::{StatefulHash, StatefulXof};
use crate::hash::{OneShotHash, OneShotXof};

unsafe extern "C" {
    // SHA3-224
    fn SymCryptSha3_224(
        pb_data: *const u8,
        cb_data: usize,
        pb_result: &mut [u8; Sha3_224::RESULT_SIZE],
    );

    fn SymCryptSha3_224Init(p_state: &mut CFfiSha3_224State);

    fn SymCryptSha3_224Append(p_state: &mut CFfiSha3_224State, pb_data: *const u8, cb_data: usize);

    fn SymCryptSha3_224Result(p_state: &mut CFfiSha3_224State, pb_result: &mut [u8; Sha3_224::RESULT_SIZE]);

    // SHA3-256
    fn SymCryptSha3_256(
        pb_data: *const u8,
        cb_data: usize,
        pb_result: &mut [u8; crate::sha3::Sha3_256::RESULT_SIZE],
    );

    fn SymCryptSha3_256Init(p_state: &mut CFfiSha3_256State);

    fn SymCryptSha3_256Append(p_state: &mut CFfiSha3_256State, pb_data: *const u8, cb_data: usize);

    fn SymCryptSha3_256Result(p_state: &mut CFfiSha3_256State, pb_result: &mut [u8; Sha3_256::RESULT_SIZE]);

    // SHA3-384
    fn SymCryptSha3_384(
        pb_data: *const u8,
        cb_data: usize,
        pb_result: &mut [u8; Sha3_384::RESULT_SIZE],
    );

    fn SymCryptSha3_384Init(p_state: &mut CFfiSha3_384State);

    fn SymCryptSha3_384Append(p_state: &mut CFfiSha3_384State, pb_data: *const u8, cb_data: usize);

    fn SymCryptSha3_384Result(p_state: &mut CFfiSha3_384State, pb_result: &mut [u8; Sha3_384::RESULT_SIZE]);

    // SHA3-512
    fn SymCryptSha3_512(
        pb_data: *const u8,
        cb_data: usize,
        pb_result: &mut [u8; Sha3_512::RESULT_SIZE],
    );

    fn SymCryptSha3_512Init(p_state: &mut CFfiSha3_512State);

    fn SymCryptSha3_512Append(p_state: &mut CFfiSha3_512State, pb_data: *const u8, cb_data: usize);

    fn SymCryptSha3_512Result(p_state: &mut CFfiSha3_512State, pb_result: &mut [u8; Sha3_512::RESULT_SIZE]);

    // SHAKE128
    fn SymCryptShake128(
        pb_data: *const u8,
        cb_data: usize,
        pb_result: *mut u8,
        cb_result: usize,
    );

    fn SymCryptShake128Init(p_state: &mut CFfiShake128State);

    fn SymCryptShake128Append(p_state: &mut CFfiShake128State, pb_data: *const u8, cb_data: usize);

    fn SymCryptShake128Extract(p_state: &mut CFfiShake128State, pb_result: *mut u8, cb_result: usize, b_wipe: bool);

    fn SymCryptShake128Result(p_state: &mut CFfiShake128State, pb_result: *mut u8);

    // SHAKE256
    fn SymCryptShake256(
        pb_data: *const u8,
        cb_data: usize,
        pb_result: *mut u8,
        cb_result: usize,
    );

    fn SymCryptShake256Init(p_state: &mut CFfiShake256State);

    fn SymCryptShake256Append(p_state: &mut CFfiShake256State, pb_data: *const u8, cb_data: usize);

    fn SymCryptShake256Extract(p_state: &mut CFfiShake256State, pb_result: *mut u8, cb_result: usize, b_wipe: bool);

    fn SymCryptShake256Result(p_state: &mut CFfiShake256State, pb_result: *mut u8);
}

#[test]
fn test_sha224() {
    let mut c_sha3_224_state = CFfiSha3_224State::default();
    let mut rust_sha3_224_state = Sha3_224State::new();

    unsafe {SymCryptSha3_224Init(&mut c_sha3_224_state);}
    assert_eq!(c_sha3_224_state.state, rust_sha3_224_state.state);

    let mut rng = rand::rng();

    let mut data = [0u8; 8192];
    rng.fill_bytes(&mut data);

    unsafe {SymCryptSha3_224Append(&mut c_sha3_224_state, data.as_ptr(), data.len());}
    rust_sha3_224_state.append(&data);
    assert_eq!(c_sha3_224_state.state, rust_sha3_224_state.state);

    let mut data = [0u8; 8192];
    rng.fill_bytes(&mut data);

    unsafe {SymCryptSha3_224Append(&mut c_sha3_224_state, data.as_ptr(), data.len());}
    rust_sha3_224_state.append(&data);
    assert_eq!(c_sha3_224_state.state, rust_sha3_224_state.state);

    let mut c_result = [0u8; Sha3_224::RESULT_SIZE];
    let mut rust_result = [0u8; Sha3_224::RESULT_SIZE];

    unsafe {SymCryptSha3_224Result(&mut c_sha3_224_state, &mut c_result);}
    rust_sha3_224_state.result(&mut rust_result);
    assert_eq!(c_sha3_224_state.state, rust_sha3_224_state.state);
    assert_eq!(rust_result, c_result);

    c_result = [0u8; Sha3_224::RESULT_SIZE];
    rust_result = [0u8; Sha3_224::RESULT_SIZE];

    unsafe {SymCryptSha3_224(data.as_ptr(), data.len(), &mut c_result);}
    Sha3_224::hash(&data, &mut rust_result);
    assert_eq!(rust_result, c_result);
}

#[test]
fn test_sha256() {
    let mut c_sha3_256_state = CFfiSha3_256State::default();
    let mut rust_sha3_256_state = Sha3_256State::default();

    unsafe {SymCryptSha3_256Init(&mut c_sha3_256_state);}
    assert_eq!(c_sha3_256_state.state, rust_sha3_256_state.state);

    let mut rng = rand::rng();

    let mut data = [0u8; 8192];
    rng.fill_bytes(&mut data);

    unsafe {SymCryptSha3_256Append(&mut c_sha3_256_state, data.as_ptr(), data.len());}
    rust_sha3_256_state.append(&data);
    assert_eq!(c_sha3_256_state.state, rust_sha3_256_state.state);

    let mut data = [0u8; 8192];
    rng.fill_bytes(&mut data);

    unsafe {SymCryptSha3_256Append(&mut c_sha3_256_state, data.as_ptr(), data.len());}
    rust_sha3_256_state.append(&data);
    assert_eq!(c_sha3_256_state.state, rust_sha3_256_state.state);

    let mut c_result = [0u8; Sha3_256::RESULT_SIZE];
    let mut rust_result = [0u8; Sha3_256::RESULT_SIZE];

    unsafe {SymCryptSha3_256Result(&mut c_sha3_256_state, &mut c_result);}
    rust_sha3_256_state.result(&mut rust_result);
    assert_eq!(c_sha3_256_state.state, rust_sha3_256_state.state);
    assert_eq!(rust_result, c_result);

    c_result = [0u8; Sha3_256::RESULT_SIZE];
    rust_result = [0u8; Sha3_256::RESULT_SIZE];

    unsafe {SymCryptSha3_256(data.as_ptr(), data.len(), &mut c_result);}
    Sha3_256::hash(&data, &mut rust_result);
    assert_eq!(rust_result, c_result);
}

#[test]
fn test_sha384() {
    let mut c_sha3_384_state = CFfiSha3_384State::default();
    let mut rust_sha3_384_state = Sha3_384State::default();

    unsafe {SymCryptSha3_384Init(&mut c_sha3_384_state);}
    assert_eq!(c_sha3_384_state.state, rust_sha3_384_state.state);

    let mut rng = rand::rng();

    let mut data = [0u8; 8192];
    rng.fill_bytes(&mut data);

    unsafe {SymCryptSha3_384Append(&mut c_sha3_384_state, data.as_ptr(), data.len());}
    rust_sha3_384_state.append(&data);
    assert_eq!(c_sha3_384_state.state, rust_sha3_384_state.state);

    let mut data = [0u8; 8192];
    rng.fill_bytes(&mut data);

    unsafe {SymCryptSha3_384Append(&mut c_sha3_384_state, data.as_ptr(), data.len());}
    rust_sha3_384_state.append(&data);
    assert_eq!(c_sha3_384_state.state, rust_sha3_384_state.state);

    let mut c_result = [0u8; Sha3_384::RESULT_SIZE];
    let mut rust_result = [0u8; Sha3_384::RESULT_SIZE];

    unsafe {SymCryptSha3_384Result(&mut c_sha3_384_state, &mut c_result);}
    rust_sha3_384_state.result(&mut rust_result);
    assert_eq!(c_sha3_384_state.state, rust_sha3_384_state.state);
    assert_eq!(rust_result, c_result);

    c_result = [0u8; Sha3_384::RESULT_SIZE];
    rust_result = [0u8; Sha3_384::RESULT_SIZE];

    unsafe {SymCryptSha3_384(data.as_ptr(), data.len(), &mut c_result);}
    Sha3_384::hash(&data, &mut rust_result);
    assert_eq!(rust_result, c_result);
}

#[test]
fn test_sha512() {
    let mut c_sha3_512_state = CFfiSha3_512State::default();
    let mut rust_sha3_512_state = Sha3_512State::default();

    unsafe {SymCryptSha3_512Init(&mut c_sha3_512_state);}
    assert_eq!(c_sha3_512_state.state, rust_sha3_512_state.state);

    let mut rng = rand::rng();

    let mut data = [0u8; 8192];
    rng.fill_bytes(&mut data);

    unsafe {SymCryptSha3_512Append(&mut c_sha3_512_state, data.as_ptr(), data.len());}
    rust_sha3_512_state.append(&data);
    assert_eq!(c_sha3_512_state.state, rust_sha3_512_state.state);

    let mut data = [0u8; 8192];
    rng.fill_bytes(&mut data);

    unsafe {SymCryptSha3_512Append(&mut c_sha3_512_state, data.as_ptr(), data.len());}
    rust_sha3_512_state.append(&data);
    assert_eq!(c_sha3_512_state.state, rust_sha3_512_state.state);

    let mut c_result = [0u8; Sha3_512::RESULT_SIZE];
    let mut rust_result = [0u8; Sha3_512::RESULT_SIZE];

    unsafe {SymCryptSha3_512Result(&mut c_sha3_512_state, &mut c_result);}
    rust_sha3_512_state.result(&mut rust_result);
    assert_eq!(c_sha3_512_state.state, rust_sha3_512_state.state);
    assert_eq!(rust_result, c_result);

    c_result = [0u8; Sha3_512::RESULT_SIZE];
    rust_result = [0u8; Sha3_512::RESULT_SIZE];

    unsafe {SymCryptSha3_512(data.as_ptr(), data.len(), &mut c_result);}
    Sha3_512::hash(&data, &mut rust_result);
    assert_eq!(rust_result, c_result);
}

#[test]
fn test_shake128() {
    let mut c_shake128_state = CFfiShake128State::default();
    let mut rust_shake128_state = Shake128State::default();

    unsafe {SymCryptShake128Init(&mut c_shake128_state);}
    assert_eq!(c_shake128_state.state, rust_shake128_state.state);

    let mut rng = rand::rng();

    let mut data = [0u8; 8192];
    rng.fill_bytes(&mut data);

    unsafe {SymCryptShake128Append(&mut c_shake128_state, data.as_ptr(), data.len());}
    rust_shake128_state.append(&data);
    assert_eq!(c_shake128_state.state, rust_shake128_state.state);

    let mut data = [0u8; 8192];
    rng.fill_bytes(&mut data);

    unsafe {SymCryptShake128Append(&mut c_shake128_state, data.as_ptr(), data.len());}
    rust_shake128_state.append(&data);
    assert_eq!(c_shake128_state.state, rust_shake128_state.state);

    let mut c_result = [0u8; Shake128::RESULT_SIZE];
    let mut rust_result = [0u8; Shake128::RESULT_SIZE];

    unsafe {SymCryptShake128Extract(&mut c_shake128_state, c_result.as_mut_ptr(), c_result.len(), false);}
    rust_shake128_state.extract(&mut rust_result, false);
    assert_eq!(c_shake128_state.state, rust_shake128_state.state);
    assert_eq!(rust_result, c_result);

    c_result = [0u8; Shake128::RESULT_SIZE];
    rust_result = [0u8; Shake128::RESULT_SIZE];

    unsafe {SymCryptShake128Extract(&mut c_shake128_state, c_result.as_mut_ptr(), c_result.len(), true);}
    rust_shake128_state.extract(&mut rust_result, true);
    assert_eq!(c_shake128_state.state, rust_shake128_state.state);
    assert_eq!(rust_result, c_result);

    let mut c_shake128_state = CFfiShake128State::default();
    let mut rust_shake128_state = Shake128State::default();

    unsafe {SymCryptShake128Init(&mut c_shake128_state);}

    unsafe {SymCryptShake128Append(&mut c_shake128_state, data.as_ptr(), data.len());}
    rust_shake128_state.append(&data);

    c_result = [0u8; Shake128::RESULT_SIZE];
    rust_result = [0u8; Shake128::RESULT_SIZE];

    unsafe {SymCryptShake128Result(&mut c_shake128_state, c_result.as_mut_ptr());}
    rust_shake128_state.result(&mut rust_result);
    assert_eq!(c_shake128_state.state, rust_shake128_state.state);
    assert_eq!(rust_result, c_result);

    c_result = [0u8; Shake128::RESULT_SIZE];
    rust_result = [0u8; Shake128::RESULT_SIZE];

    unsafe {SymCryptShake128(data.as_ptr(), data.len(), c_result.as_mut_ptr(), c_result.len());}
    Shake128::xof(&data, &mut rust_result);
    assert_eq!(rust_result, c_result);
}

#[test]
fn test_shake256() {
    let mut c_shake256_state = CFfiShake256State::default();
    let mut rust_shake256_state = Shake256State::default();

    unsafe {SymCryptShake256Init(&mut c_shake256_state);}
    assert_eq!(c_shake256_state.state, rust_shake256_state.state);

    let mut rng = rand::rng();

    let mut data = [0u8; 8192];
    rng.fill_bytes(&mut data);

    unsafe {SymCryptShake256Append(&mut c_shake256_state, data.as_ptr(), data.len());}
    rust_shake256_state.append(&data);
    assert_eq!(c_shake256_state.state, rust_shake256_state.state);

    let mut data = [0u8; 8192];
    rng.fill_bytes(&mut data);

    unsafe {SymCryptShake256Append(&mut c_shake256_state, data.as_ptr(), data.len());}
    rust_shake256_state.append(&data);
    assert_eq!(c_shake256_state.state, rust_shake256_state.state);

    let mut c_result = [0u8; Shake256::RESULT_SIZE];
    let mut rust_result = [0u8; Shake256::RESULT_SIZE];

    unsafe {SymCryptShake256Extract(&mut c_shake256_state, c_result.as_mut_ptr(), c_result.len(), false);}
    rust_shake256_state.extract(&mut rust_result, false);
    assert_eq!(c_shake256_state.state, rust_shake256_state.state);
    assert_eq!(rust_result, c_result);

    c_result = [0u8; Shake256::RESULT_SIZE];
    rust_result = [0u8; Shake256::RESULT_SIZE];

    unsafe {SymCryptShake256Extract(&mut c_shake256_state, c_result.as_mut_ptr(), c_result.len(), true);}
    rust_shake256_state.extract(&mut rust_result, true);
    assert_eq!(c_shake256_state.state, rust_shake256_state.state);
    assert_eq!(rust_result, c_result);

    let mut c_shake256_state = CFfiShake256State::default();
    let mut rust_shake256_state = Shake256State::default();

    unsafe {SymCryptShake256Init(&mut c_shake256_state);}

    unsafe {SymCryptShake256Append(&mut c_shake256_state, data.as_ptr(), data.len());}
    rust_shake256_state.append(&data);

    c_result = [0u8; Shake256::RESULT_SIZE];
    rust_result = [0u8; Shake256::RESULT_SIZE];

    unsafe {SymCryptShake256Result(&mut c_shake256_state, c_result.as_mut_ptr());}
    rust_shake256_state.result(&mut rust_result);
    assert_eq!(c_shake256_state.state, rust_shake256_state.state);
    assert_eq!(rust_result, c_result);

    c_result = [0u8; Shake256::RESULT_SIZE];
    rust_result = [0u8; Shake256::RESULT_SIZE];

    unsafe {SymCryptShake256(data.as_ptr(), data.len(), c_result.as_mut_ptr(), c_result.len());}
    Shake256::xof(&data, &mut rust_result);
    assert_eq!(rust_result, c_result);
}