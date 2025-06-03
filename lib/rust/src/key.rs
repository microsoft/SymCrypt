//
// key.rs   Definition of SymCRust ML-KEM key
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// We encapsulate the key in a separate module; this allows providing a modicum of abstraction, by
// only revealing the existence of certain fields and keeping others private.
//
// We offer several implementations, as this is the design phase; but we only pick one at
// compile-time so as to not generate polymorphic code.

use crate::common::*;
use alloc::boxed::Box;
use alloc::vec;
use core::result::Result;
use core::slice;

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

pub(crate) struct InternalParams {
    pub(crate) params: Params,
    // parameter set of ML-KEM being used, takes a value from Params
    pub(crate) n_rows: u8,
    // corresponds to k from FIPS 203; the number of rows and columns in the matrix A,
    // and the number of rows in column vectors s and t
    pub(crate) n_eta1: u8,
    // corresponds to eta_1 from FIPS 203; number of coinflips used in generating s and e
    // in keypair generation, and r in encapsulation
    pub(crate) n_eta2: u8,
    // corresponds to eta_2 from FIPS 203; number of coinflips used in generating e_1 and
    // e_2 in encapsulation
    pub(crate) n_bits_of_u: u8,
    // corresponds to d_u from FIPS 203; number of bits that the coefficients of the polynomial
    // ring elements of u are compressed to in encapsulation for encoding into ciphertext
    pub(crate) n_bits_of_v: u8,
    // corresponds to d_v from FIPS 203; number of bits that the coefficients of the polynomial
    // ring element v is compressed to in encapsulation for encoding into ciphertext
}

const INTERNAL_PARAMS_ML_KEM512: InternalParams = InternalParams {
    params: Params::MlKem512,
    n_rows: 2,
    n_eta1: 3,
    n_eta2: 2,
    n_bits_of_u: 10,
    n_bits_of_v: 4,
};

const INTERNAL_PARAMS_ML_KEM768: InternalParams = InternalParams {
    params: Params::MlKem768,
    n_rows: 3,
    n_eta1: 2,
    n_eta2: 2,
    n_bits_of_u: 10,
    n_bits_of_v: 4,
};

const INTERNAL_PARAMS_ML_KEM1024: InternalParams = InternalParams {
    params: Params::MlKem1024,
    n_rows: 4,
    n_eta1: 2,
    n_eta2: 2,
    n_bits_of_u: 11,
    n_bits_of_v: 5,
};

pub(crate) const fn get_internal_params_from_params(params: Params) -> InternalParams {
    match params {
        Params::MlKem512 => INTERNAL_PARAMS_ML_KEM512,
        Params::MlKem768 => INTERNAL_PARAMS_ML_KEM768,
        Params::MlKem1024 => INTERNAL_PARAMS_ML_KEM1024,
    }
}

pub(crate) const MLWE_POLYNOMIAL_COEFFICIENTS: usize = 256;

pub(crate) const POLYELEMENT_ZERO: PolyElement = [0; MLWE_POLYNOMIAL_COEFFICIENTS];

// PolyElements just store the coefficients without any header.
pub(crate) type PolyElement = [u16; MLWE_POLYNOMIAL_COEFFICIENTS];

// The slice length is between 1 and MATRIX_MAX_NROWS.
// Note (Rust): unlike the original C code, we de-couple what we pass around (this type) vs. the
// underlying allocation (handled by the caller).
// Note (Rust): this already keeps the length -- no need for an additional field.
pub(crate) type Vector = [PolyElement];

pub(crate) const KEY_MAX_SIZEOF_ENCODED_T: usize = 1536;

//
// MLKEMKEY type
//

/******************************************************************************
 * Option 2: using a dynamically-sized type (DST), in safe Rust
 ******************************************************************************/

// This works only for ML-KEM because all of the variable-length types are arrays of POLYELEMENT.
// It also forces us to be a little more verbose because Rust does not allow allocating such a type
// when the length of the variable part is not a compile-time constant.

#[allow(dead_code)]
pub struct PreKey2<U: ?Sized> {
    pub(crate) algorithm_info: u32,
    // Tracks which algorithms the key can be used in
    // Also tracks which per-key selftests have been performed on this key
    // A bitwise OR of FLAG_KEY_*, FLAG_MLKEMKEY_*, and
    // SELFTEST_KEY_* values
    pub(crate) has_private_seed: bool, // Set to true if key has the private seed (d)
    pub(crate) has_private_key: bool,  // Set to true if key has the private key (s and z)

    // seeds
    pub(crate) private_seed: [u8; 32], // private seed (d) from which entire private PKE key can be derived
    pub(crate) private_random: [u8; 32], // private random (z) used in implicit rejection

    pub(crate) public_seed: [u8; 32], // public seed (rho) from which A can be derived

    // misc fields
    pub(crate) encoded_t: [u8; KEY_MAX_SIZEOF_ENCODED_T], // byte-encoding of public vector
    // may only use a prefix of this buffer
    pub(crate) encaps_key_hash: [u8; 32], // Precomputed value of hash of ML-KEM's byte-encoding of encapsulation key

    pub(crate) params: InternalParams,

    // VARIABLE-LENGTH FIELDS
    n_rows: usize, // note that this can be deduced from algorithm_info

    // Instantiated with U = [PolyElement], contains:
    // a_transpose, of length n_rows * n_rows
    // t, of length n_rows
    // s, of length n_rows
    data: U,
}

#[allow(dead_code)]
pub type Key2 = PreKey2<[PolyElement]>;

// (of size n_rows)
#[allow(dead_code)]
type Matrix2 = [PolyElement];

#[allow(dead_code)]
impl Key2 {
    fn matrix_len(&self) -> usize {
        self.n_rows * self.n_rows
    }
    pub fn a_transpose(&self) -> &Matrix2 {
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
    pub fn a_transpose_mut(&mut self) -> &mut Matrix2 {
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
    pub fn ats_mut(&mut self) -> (&mut Matrix2, &mut Vector, &mut Vector) {
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
}

// This works, at the expense of a big copy-paste because Rust does not allow creating DSTs when
// the length of the data is not known at compile-time.
#[allow(dead_code)]
fn key_allocate2(params: Params) -> Result<Box<Key2>, Error> {
    match params {
        Params::MlKem512 => {
            const PARAMS: InternalParams = get_internal_params_from_params(Params::MlKem512);
            const N_ROWS: usize = PARAMS.n_rows as usize;
            // !!! Make sure to build using &PreKey2, not &Key2, otherwise, the errors are really
            // hard to parse.
            match Box::try_new(PreKey2 {
                algorithm_info: 0u32,
                params: PARAMS,
                has_private_seed: false,
                has_private_key: false,
                private_seed: [0; 32],
                private_random: [0; 32],
                public_seed: [0; 32],
                encoded_t: [0u8; KEY_MAX_SIZEOF_ENCODED_T],
                encaps_key_hash: [0u8; 32],
                n_rows: N_ROWS,
                data: [POLYELEMENT_ZERO; N_ROWS * N_ROWS + 2 * N_ROWS],
            }) {
                Result::Err(_) => return Result::Err(Error::MemoryAllocationFailure),
                Result::Ok(key) => return Result::Ok(key),
            }
        }
        Params::MlKem768 => {
            const PARAMS: InternalParams = get_internal_params_from_params(Params::MlKem768);
            const N_ROWS: usize = PARAMS.n_rows as usize;
            // !!! Make sure to build using &PreKey2, not &Key2, otherwise, the errors are really
            // hard to parse.
            match Box::try_new(PreKey2 {
                algorithm_info: 0u32,
                params: PARAMS,
                has_private_seed: false,
                has_private_key: false,
                private_seed: [0; 32],
                private_random: [0; 32],
                public_seed: [0; 32],
                encoded_t: [0u8; KEY_MAX_SIZEOF_ENCODED_T],
                encaps_key_hash: [0u8; 32],
                n_rows: N_ROWS,
                data: [POLYELEMENT_ZERO; N_ROWS * N_ROWS + 2 * N_ROWS],
            }) {
                Result::Err(_) => return Result::Err(Error::MemoryAllocationFailure),
                Result::Ok(key) => return Result::Ok(key),
            }
        }
        Params::MlKem1024 => {
            const PARAMS: InternalParams = get_internal_params_from_params(Params::MlKem1024);
            const N_ROWS: usize = PARAMS.n_rows as usize;
            // !!! Make sure to build using &PreKey2, not &Key2, otherwise, the errors are really
            // hard to parse.
            match Box::try_new(PreKey2 {
                algorithm_info: 0u32,
                params: PARAMS,
                has_private_seed: false,
                has_private_key: false,
                private_seed: [0; 32],
                private_random: [0; 32],
                public_seed: [0; 32],
                encoded_t: [0u8; KEY_MAX_SIZEOF_ENCODED_T],
                encaps_key_hash: [0u8; 32],
                n_rows: N_ROWS,
                data: [POLYELEMENT_ZERO; N_ROWS * N_ROWS + 2 * N_ROWS],
            }) {
                Result::Err(_) => return Result::Err(Error::MemoryAllocationFailure),
                Result::Ok(key) => return Result::Ok(key),
            }
        }
    }
}

/******************************************************************************
 * Option 1: using the Box type
 ******************************************************************************/

// Array of pointers to PolyElements in row-major order
// Note: the extra indirection is intentional to make transposing the matrix cheap,
// given that in the MLKEM context the underlying PolyElements are relatively large
// so we don't want to move them around.
//
// Note (Rust): this will work because the thing has a fixed size and so we can declare 16
// variables in scope, borrow them all, and put them in an array (or use split_at_mut).
//
// Note (Rust): again, allocation to be handled by the caller or the owner.
// Note (Rust): to avoid a const-generic, the array of pointers to elements is possibly oversized
#[allow(dead_code)]
pub(crate) struct Matrix1 {
    pub(crate) n_rows: usize,
    pub(crate) ap_poly_elements: Box<[PolyElement]>,
}

#[allow(dead_code)]
pub(crate) struct Key1 {
    pub(crate) algorithm_info: u32,
    // Tracks which algorithms the key can be used in
    // Also tracks which per-key selftests have been performed on this key
    // A bitwise OR of FLAG_KEY_*, FLAG_MLKEMKEY_*, and
    // SELFTEST_KEY_* values
    pub(crate) has_private_seed: bool, // Set to true if key has the private seed (d)
    pub(crate) has_private_key: bool,  // Set to true if key has the private key (s and z)

    // seeds
    pub(crate) private_seed: [u8; 32], // private seed (d) from which entire private PKE key can be derived
    pub(crate) private_random: [u8; 32], // private random (z) used in implicit rejection

    pub(crate) public_seed: [u8; 32], // public seed (rho) from which A can be derived

    // misc fields
    pub(crate) encoded_t: [u8; KEY_MAX_SIZEOF_ENCODED_T], // byte-encoding of public vector
    // may only use a prefix of this buffer
    pub(crate) encaps_key_hash: [u8; 32], // Precomputed value of hash of ML-KEM's byte-encoding of encapsulation key
    pub(crate) params: InternalParams,

    // VARIABLE-LENGTH FIELDS, which we make private
    // 1. This forces clients to go through accessors, leaving us free to change the representation
    //    later on
    // 2. This prevents clients from directly building values of this type, or accessing these
    //    fields directly, helping to preserve our invariants.

    // A o s + e = t
    pm_a_transpose: Matrix1, // public matrix in NTT form (derived from publicSeed)
    pvt: Box<Vector>,        // public vector in NTT form
    pvs: Box<Vector>,        // private vector in NTT form
}

#[allow(dead_code)]
impl Key1 {
    pub fn a_transpose(&self) -> &Matrix1 {
        &self.pm_a_transpose
    }
    pub fn t(&self) -> &Vector {
        &self.pvt
    }
    pub fn s(&self) -> &Vector {
        &self.pvs
    }
    pub fn a_transpose_mut(&mut self) -> &mut Matrix1 {
        &mut self.pm_a_transpose
    }
    pub fn t_mut(&mut self) -> &mut Vector {
        &mut self.pvt
    }
    pub fn s_mut(&mut self) -> &mut Vector {
        &mut self.pvs
    }

    // FIXME: slightly unpleasant, owing to the nature of the encoding; but perhaps this is
    // inevitable; alternatively, we could put all of the "public" fields in their own struct; and
    // then return that struct + a, s, t (so, a quadruple)
    pub fn ats_mut(&mut self) -> (&mut Matrix1, &mut Vector, &mut Vector) {
        (&mut self.pm_a_transpose, &mut self.pvt, &mut self.pvs)
    }

    pub fn t_encoded_t_mut(&mut self) -> (&mut Vector, &mut [u8; KEY_MAX_SIZEOF_ENCODED_T]) {
        (&mut self.pvt, &mut self.encoded_t)
    }
}

#[allow(dead_code)]
fn key_allocate1(params: Params) -> Result<Box<Key1>, Error> {
    // Note (Rust): this function could previously fail. Now that we use an enum for the choice of
    // algorithm, match exhaustiveness checks obviate the need for an error code.
    let params = get_internal_params_from_params(params);
    let n_rows = params.n_rows;
    // Note (Rust): previously, returned a heap-allocated key. We create a Box here, but could also
    // return a value if we wanted, relying on LLVM to optimize out the copies of a large value.
    match Box::try_new(Key1 {
        algorithm_info: 0u32,
        params,
        has_private_seed: false,
        has_private_key: false,
        private_seed: [0; 32],
        private_random: [0; 32],
        public_seed: [0; 32],
        // Note (Rust): this generates four boxes, see ALLOCATION.md for discussion
        // Note (Rust): the original C code performs null-checks to see if the allocations
        // succeeded. We could presumably use an error monad (the ? operator), Box::try_new, and
        // return a Result for this function (and others who need to perform
        // comparable checks).
        pm_a_transpose: Matrix1 {
            n_rows: n_rows as usize,
            ap_poly_elements: vec![POLYELEMENT_ZERO; (n_rows * n_rows) as usize].into(),
        },
        pvt: vec![POLYELEMENT_ZERO; n_rows as usize].into(),
        pvs: vec![POLYELEMENT_ZERO; n_rows as usize].into(),
        encoded_t: [0u8; KEY_MAX_SIZEOF_ENCODED_T],
        encaps_key_hash: [0u8; 32],
    }) {
        Result::Err(_) => Result::Err(Error::MemoryAllocationFailure),
        Result::Ok(key) => Result::Ok(key),
    }
}

/******************************************************************************
 * Option 3: relying on unsafe
 ******************************************************************************/

// TODO
//
// Design notes:
// - Rust cannot allocate DSTs when the size isn't known at compile-time, i.e. KeyAllocate2, above,
//   fails without the `const` on `n_rows`
// - thus, we need to rely on unsafe to *even* create such an object;
//   https://docs.rs/slice-dst/latest/src/slice_dst/lib.rs.html#200-202 knows how to do that, we
//   should take inspiration from this code to correctly handle padding and alignment
// - speaking of which, we probably want to allocate a slice of u64s (rather than u8s) as the
//   variable-length slide at the end of the DST, so as to over-align and never worry about alignment
// - writing accessors requires the use of a cast

#[allow(dead_code)]
pub(crate) type Key3 = PreKey2<[u64]>;

#[allow(dead_code)]
impl Key3 {
    // FIXME OFFSET COMPUTATIONS INCORRECT HERE SEE KEY2, ABOVE
    pub fn a_transpose(&self) -> &Matrix2 {
        unsafe {
            slice::from_raw_parts(
                (&raw const self.data).cast::<PolyElement>(),
                2 * self.n_rows,
            )
        }
    }
    pub fn t(&self) -> &Vector {
        // Align on an 8-byte boundary, naturally.
        let t_start = (2 * self.n_rows + 7) / 8;
        unsafe {
            slice::from_raw_parts(
                (&raw const self.data[t_start..]).cast::<PolyElement>(),
                self.n_rows,
            )
        }
    }
    pub fn s(&self) -> &Vector {
        // Align on an 8-byte boundary, naturally.
        let t_start = (2 * self.n_rows + 7) / 8;
        let s_start = t_start + (self.n_rows + 7) / 8;
        unsafe {
            slice::from_raw_parts(
                (&raw const self.data[s_start..]).cast::<PolyElement>(),
                self.n_rows,
            )
        }
    }
    pub fn a_transpose_mut(&mut self) -> &mut Matrix2 {
        unsafe {
            slice::from_raw_parts_mut((&raw mut self.data).cast::<PolyElement>(), 2 * self.n_rows)
        }
    }
    pub fn t_mut(&mut self) -> &mut Vector {
        // Align on an 8-byte boundary, naturally.
        let t_start = (2 * self.n_rows + 7) / 8;
        unsafe {
            slice::from_raw_parts_mut(
                (&raw mut self.data[t_start..]).cast::<PolyElement>(),
                self.n_rows,
            )
        }
    }
    pub fn s_mut(&mut self) -> &mut Vector {
        // Align on an 8-byte boundary, naturally.
        let t_start = (2 * self.n_rows + 7) / 8;
        let s_start = t_start + (self.n_rows + 7) / 8;
        unsafe {
            slice::from_raw_parts_mut(
                (&raw mut self.data[s_start..]).cast::<PolyElement>(),
                self.n_rows,
            )
        }
    }
}

/******************************************************************************
 * API: static multiplexing
 ******************************************************************************/

// Pick your favorite option here for the sake of benchmarking
// FIXME: currently only option 2 is fully functional!

pub(crate) type Key = Key2; // EDIT HERE

pub(crate) type Matrix = Matrix2; // EDIT HERE

pub fn key_allocate(params: Params) -> Result<Box<Key>, Error> {
    key_allocate2(params) // EDIT HERE
}
