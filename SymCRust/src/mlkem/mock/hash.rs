//
// hash.rs   mocks for SymCrypt hashing
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// Not all of the bindings are used so far -- we leave them for now.
#![allow(dead_code)]
#![allow(unused_variables)]

use crate::sha3::sha3_impl::KeccakState;

pub const SHAKE128_RESULT_SIZE: usize = 32;
pub const SHAKE128_INPUT_BLOCK_SIZE: usize = 168;

pub const SHAKE256_RESULT_SIZE: usize = 64;
pub const SHAKE256_INPUT_BLOCK_SIZE: usize = 136;

pub const SHA3_256_RESULT_SIZE: usize = 32;
pub const SHA3_256_INPUT_BLOCK_SIZE: usize = 136;

pub const SHA3_512_RESULT_SIZE: usize = 64;
pub const SHA3_512_INPUT_BLOCK_SIZE: usize = 72;

#[repr(C)]
#[cfg_attr(any(target_arch = "x86"), repr(align(4)))]
#[cfg_attr(any(target_arch = "arm"), repr(align(8)))]
#[cfg_attr(any(target_arch = "x86_64", target_arch = "aarch64"), repr(align(16)))]
#[derive(Default)]
pub(crate) struct CSha3HashState {
    pub(crate) state: KeccakState,
    magic: usize,
}

// SHAKE128

pub(crate) fn shake128_default(data: &[u8], dst: &mut [u8; SHAKE128_RESULT_SIZE]) {
    panic!("shake128_default not implemented in mock");
}

pub(crate) fn shake128(pb_data: &[u8], pb_result: &mut [u8]) {
    panic!("shake128 not implemented in mock");
}

pub(crate) fn shake128_init(p_state: &mut CSha3HashState) {
    panic!("shake128_init not implemented in mock");
}

pub(crate) fn shake128_append(p_state: &mut CSha3HashState, pb_data: &[u8]) {
    panic!("shake128_append not implemented in mock");
}

pub(crate) fn shake128_extract(p_state: &mut CSha3HashState, dst: &mut [u8], wipe: bool) {
    panic!("shake128_extract not implemented in mock");
}

pub(crate) fn shake128_result(p_state: &mut CSha3HashState, pb_result: &mut [u8; SHAKE128_RESULT_SIZE]) {
    panic!("shake128_result not implemented in mock");
}

pub(crate) fn shake128_state_copy(p_src: &CSha3HashState, p_dst: &mut CSha3HashState) {
    panic!("shake128_state_copy not implemented in mock");
}

// SHAKE256

pub(crate) fn shake256_default(data: &[u8], dst: &mut [u8; SHAKE256_RESULT_SIZE]) {
    panic!("shake256_default not implemented in mock");
}

pub(crate) fn shake256(pb_data: &[u8], pb_result: &mut [u8]) {
    panic!("shake256 not implemented in mock");
}

pub(crate) fn shake256_init(p_state: &mut CSha3HashState) {
    panic!("shake256_init not implemented in mock");
}

pub(crate) fn shake256_append(p_state: &mut CSha3HashState, pb_data: &[u8]) {
    panic!("shake256_append not implemented in mock");
}

pub(crate) fn shake256_extract(p_state: &mut CSha3HashState, dst: &mut [u8], wipe: bool) {
    panic!("shake256_extract not implemented in mock");
}

pub(crate) fn shake256_result(p_state: &mut CSha3HashState, pb_result: &mut [u8; SHAKE256_RESULT_SIZE]) {
    panic!("shake256_result not implemented in mock");
}

pub(crate) fn shake256_state_copy(p_src: &CSha3HashState, p_dst: &mut CSha3HashState) {
    panic!("shake256_state_copy not implemented in mock");
}

// SHA3_256

pub(crate) fn sha3_256(pb_data: &[u8], pb_result: &mut [u8; SHA3_256_RESULT_SIZE]) {
    panic!("sha3_256 not implemented in mock");
}

pub(crate) fn sha3_256_init(p_state: &mut CSha3HashState) {
    panic!("sha3_256_init not implemented in mock");
}

pub(crate) fn sha3_256_append(p_state: &mut CSha3HashState, pb_data: &[u8]) {
    panic!("sha3_256_append not implemented in mock");
}

pub(crate) fn sha3_256_result(p_state: &mut CSha3HashState, pb_result: &mut [u8; SHA3_256_RESULT_SIZE]) {
    panic!("sha3_256_result not implemented in mock");
}

pub(crate) fn sha3_256_state_copy(p_src: &CSha3HashState, p_dst: &mut CSha3HashState) {
    panic!("sha3_256_state_copy not implemented in mock");
}

// SHA3_512

pub(crate) fn sha3_512(pb_data: &[u8], pb_result: &mut [u8; SHA3_512_RESULT_SIZE]) {
    panic!("sha3_512 not implemented in mock");
}

pub(crate) fn sha3_512_init(p_state: &mut CSha3HashState) {
    panic!("sha3_512_init not implemented in mock");
}

pub(crate) fn sha3_512_append(p_state: &mut CSha3HashState, pb_data: &[u8]) {
    panic!("sha3_512_append not implemented in mock");
}

pub(crate) fn sha3_512_result(p_state: &mut CSha3HashState, pb_result: &mut [u8; SHA3_512_RESULT_SIZE]) {
    panic!("sha3_512_result not implemented in mock");
}

pub(crate) fn sha3_512_state_copy(p_src: &CSha3HashState, p_dst: &mut CSha3HashState) {
    panic!("sha3_512_state_copy not implemented in mock");
}
