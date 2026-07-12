//
// key.rs   Definition of SymCRust ML-KEM key
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// We encapsulate the key in a separate module; this allows providing a modicum of abstraction, by
// only revealing the existence of certain fields and keeping others private.
//

use crate::common::*;
use alloc::boxed::Box;
use core::result::Result;

use super::MATRIX_MAX_NROWS;
use super::vector_set_zero;

// MLKEM key formats
// ==================
//  -   The below formats apply **only to external formats**: When somebody is
//      importing a key (from test vectors, for example) or exporting a key.
//      The internal format of the keys is not visible to the caller.
pub enum Format {
    // FORMAT_NULL               = 0,
    PrivateSeed = 1,
    // 64-byte concatenation of d || z from FIPS 203. Smallest representation of a full
    // ML-KEM key.
    // On its own it is ambiguous what type of ML-KEM key this represents; callers wanting to
    // store this format must track the key type alongside the key.
    DecapsulationKey = 2,
    // Standard byte encoding of an ML-KEM Decapsulation key, per FIPS 203.
    // Size is 1632, 2400, or 3168 bytes for ML-KEM 512, 768, and 1024 respectively.
    EncapsulationKey = 3,
    // Standard byte encoding of an ML-KEM Encapsulation key, per FIPS 203.
    // Size is 800, 1184, or 1568 bytes for ML-KEM 512, 768, and 1024 respectively.
}

#[derive(PartialEq)]
pub enum Params {
    // Rust: unclear if needed
    // PARAMS_NULL          = 0,
    MlKem512 = 1,
    MlKem768 = 2,
    MlKem1024 = 3,
}

pub(super) struct InternalParams {
    pub(super) params: Params,
    // parameter set of ML-KEM being used, takes a value from Params
    pub(super) n_rows: u8,
    // corresponds to k from FIPS 203; the number of rows and columns in the matrix A,
    // and the number of rows in column vectors s and t
    pub(super) n_eta1: u8,
    // corresponds to eta_1 from FIPS 203; number of coinflips used in generating s and e
    // in keypair generation, and r in encapsulation
    pub(super) n_eta2: u8,
    // corresponds to eta_2 from FIPS 203; number of coinflips used in generating e_1 and
    // e_2 in encapsulation
    pub(super) n_bits_of_u: u8,
    // corresponds to d_u from FIPS 203; number of bits that the coefficients of the polynomial
    // ring elements of u are compressed to in encapsulation for encoding into ciphertext
    pub(super) n_bits_of_v: u8,
    // corresponds to d_v from FIPS 203; number of bits that the coefficients of the polynomial
    // ring element v is compressed to in encapsulation for encoding into ciphertext
}

const INTERNAL_PARAMS_MLKEM512: InternalParams = InternalParams {
    params: Params::MlKem512,
    n_rows: 2,
    n_eta1: 3,
    n_eta2: 2,
    n_bits_of_u: 10,
    n_bits_of_v: 4,
};

const INTERNAL_PARAMS_MLKEM768: InternalParams = InternalParams {
    params: Params::MlKem768,
    n_rows: 3,
    n_eta1: 2,
    n_eta2: 2,
    n_bits_of_u: 10,
    n_bits_of_v: 4,
};

const INTERNAL_PARAMS_MLKEM1024: InternalParams = InternalParams {
    params: Params::MlKem1024,
    n_rows: 4,
    n_eta1: 2,
    n_eta2: 2,
    n_bits_of_u: 11,
    n_bits_of_v: 5,
};

pub(super) const fn get_internal_params_from_params(params: Params) -> InternalParams {
    match params {
        Params::MlKem512 => INTERNAL_PARAMS_MLKEM512,
        Params::MlKem768 => INTERNAL_PARAMS_MLKEM768,
        Params::MlKem1024 => INTERNAL_PARAMS_MLKEM1024,
    }
}

pub(super) const MLWE_POLYNOMIAL_COEFFICIENTS: usize = 256;

// PolyElements just store the coefficients without any header.
pub(super) type PolyElement = [u16; MLWE_POLYNOMIAL_COEFFICIENTS];

// The slice length is between 1 and MATRIX_MAX_NROWS.
// Note (Rust): unlike the original C code, we de-couple what we pass around (this type) vs. the
// underlying allocation (handled by the caller).
// Note (Rust): this already keeps the length -- no need for an additional field.
pub(super) type Vector = [PolyElement];

pub(super) const KEY_MAX_SIZEOF_ENCODED_T: usize = 1536;

//
// MLKEMKEY type
//

/******************************************************************************
 * Simple option: static sized key object with maximum sizes
 ******************************************************************************/

pub struct Key {
    #[allow(dead_code)]
    algorithm_info: u32,
    // Tracks which algorithms the key can be used in
    // Also tracks which per-key selftests have been performed on this key
    // A bitwise OR of FLAG_KEY_*, FLAG_MLKEMKEY_*, and
    // SELFTEST_KEY_* values
    pub(super) has_private_seed: bool, // Set to true if key has the private seed (d)
    pub(super) has_private_key: bool,  // Set to true if key has the private key (s and z)

    // seeds
    pub(super) private_seed: [u8; 32], // private seed (d) from which entire private PKE key can be derived
    pub(super) private_random: [u8; 32], // private random (z) used in implicit rejection

    pub(super) public_seed: [u8; 32], // public seed (rho) from which A can be derived

    // misc fields
    pub(super) encoded_t: [u8; KEY_MAX_SIZEOF_ENCODED_T], // byte-encoding of public vector
    // may only use a prefix of this buffer
    pub(super) encaps_key_hash: [u8; 32], // Precomputed value of hash of ML-KEM's byte-encoding of encapsulation key

    pub(super) params: InternalParams,

    // VARIABLE-LENGTH FIELDS
    pub(super) n_rows: usize, // note that this can be deduced from algorithm_info

    // data layout:
    // a_transpose, of length n_rows * n_rows
    // t, of length n_rows
    // s, of length n_rows
    //
    // In a previous version this would actually be a DST, with a variable number of elements
    // allocated, but this proved inconvenient to work with over FFI. Instead, we allocate the
    // maximum size, and only use the prefix we need (using a bit more memory, but reducing complexity
    // and number of calls to the allocator). See ALLOCATIONS.md for more details.

    pub(super) data: [PolyElement; MATRIX_MAX_NROWS * MATRIX_MAX_NROWS + 2 * MATRIX_MAX_NROWS],
}

// (of size n_rows)
pub(super) type Matrix = [PolyElement];

impl Key {
    fn matrix_len(&self) -> usize {
        self.n_rows * self.n_rows
    }
    pub fn a_transpose(&self) -> &Matrix {
        let m_len = self.matrix_len();
        &self.data[0..m_len]
    }
    pub fn t(&self) -> &Vector {
        let m_len = self.matrix_len();
        &self.data[m_len..m_len + self.n_rows]
    }
    pub fn s(&self) -> &Vector {
        let m_len = self.matrix_len();
        &self.data[m_len + self.n_rows..m_len + 2 * self.n_rows]
    }
    pub fn a_transpose_mut(&mut self) -> &mut Matrix {
        let m_len = self.matrix_len();
        &mut self.data[0..m_len]
    }
    pub fn t_mut(&mut self) -> &mut Vector {
        let m_len = self.matrix_len();
        &mut self.data[m_len..m_len + self.n_rows]
    }
    pub fn s_mut(&mut self) -> &mut Vector {
        let m_len = self.matrix_len();
        &mut self.data[m_len + self.n_rows..m_len + 2 * self.n_rows]
    }

    // FIXME: slightly unpleasant, owing to the nature of the encoding; but perhaps this is
    // inevitable; alternatively, we could put all of the "public" fields in their own struct; and
    // then return that struct + a, s, t (so, a quadruple)
    pub fn ats_mut(&mut self) -> (&mut Matrix, &mut Vector, &mut Vector) {
        let m_len = self.matrix_len();
        let (a, ts) = self.data.split_at_mut(m_len);
        let (t, s) = ts.split_at_mut(self.n_rows);
        (a, t, s)
    }

    pub fn t_encoded_t_mut(&mut self) -> (&mut Vector, &mut [u8; KEY_MAX_SIZEOF_ENCODED_T]) {
        let m_len = self.matrix_len();
        (
            &mut self.data[m_len..m_len + self.n_rows],
            &mut self.encoded_t,
        )
    }

    pub(super) fn wipe_private_state(&mut self) {
        vector_set_zero(self.s_mut());
        crate::common::wipe_slice(&mut self.private_random);
        crate::common::wipe_slice(&mut self.private_seed);
        self.has_private_seed = false;
        self.has_private_key = false;
    }
}

unsafe impl crate::common::BoxDefault for Key {
    #[cfg_attr(feature = "verify", verify::opaque)]
    unsafe fn box_default(ptr: *mut Self) {
        let params = &raw mut (*ptr).params;
        let n_rows = &raw mut (*ptr).n_rows;

        params.write(INTERNAL_PARAMS_MLKEM1024);
        n_rows.write(MATRIX_MAX_NROWS);
    }
}

pub fn key_allocate(params: Params) -> Result<Box<Key>, Error> {
    match try_new_box_default::<Key>() {
        Result::Err(e) => Result::Err(e),
        Result::Ok(mut key) =>
            match params {
                Params::MlKem512 => {
                    key.params = INTERNAL_PARAMS_MLKEM512;
                    key.n_rows = INTERNAL_PARAMS_MLKEM512.n_rows as usize;
                    Result::Ok(key)
                }
                Params::MlKem768 => {
                    key.params = INTERNAL_PARAMS_MLKEM768;
                    key.n_rows = INTERNAL_PARAMS_MLKEM768.n_rows as usize;
                    Result::Ok(key)
                }
                Params::MlKem1024 => {
                    key.params = INTERNAL_PARAMS_MLKEM1024;
                    key.n_rows = INTERNAL_PARAMS_MLKEM1024.n_rows as usize;
                    Result::Ok(key)
                }
            }
    }
}