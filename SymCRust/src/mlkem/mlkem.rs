//
// mlkem.rs     High level ML-KEM functionality
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

use crate::common::*;
use crate::hash::OneShotHash;
use crate::sha3::Sha3_512;

#[cfg(not(feature = "verify"))]
mod ffi;
pub mod key;

#[cfg(all(test, not(feature = "benchmarking")))]
mod test;

// End-to-end usability workflows over the public API. Compiled for tests and
// for the `verify` extraction surface (see `workflow.rs`), but excluded from
// plain production builds.
#[cfg(any(all(test, not(feature = "benchmarking")), feature = "verify"))]
pub mod workflow;

// ML-KEM internal modules - not visible outside mlkem
mod hash;

#[cfg(not(feature = "benchmarking"))]
#[path = "ntt.rs"]
mod ntt;
// For pure Rust benchmarking, we want to make NTT APIs public
#[cfg(feature = "benchmarking")]
#[path = "ntt.rs"]
pub mod ntt;

use key::*;
use ntt::*;
use hash::*;

const fn sizeof_encoded_uncompressed_vector(_n_rows: usize) -> usize {
    384 * _n_rows
}

// d and z are each 32 bytes
const SIZEOF_FORMAT_PRIVATE_SEED: usize = 2 * 32;
// s and t are encoded uncompressed vectors
// public seed, H(encapsulation key) and z are each 32 bytes
pub const fn sizeof_format_decapsulation_key(_n_rows: usize) -> usize {
    2 * sizeof_encoded_uncompressed_vector(_n_rows) + 3 * 32
}
// t is encoded uncompressed vector
// public seed is 32 bytes
pub const fn sizeof_format_encapsulation_key(_n_rows: usize) -> usize {
    sizeof_encoded_uncompressed_vector(_n_rows) + 32
}

pub const CIPHERTEXT_SIZE_MLKEM512: usize = 768;
pub const CIPHERTEXT_SIZE_MLKEM768: usize = 1088;
pub const CIPHERTEXT_SIZE_MLKEM1024: usize = 1568;

// MLKEM key formats
// ==================
//  -   The below formats apply **only to external formats**: When somebody is
//      importing a key (from test vectors, for example) or exporting a key.
//      The internal format of the keys is not visible to the caller.

pub fn sizeof_key_format_from_params(params: Params, format: Format) -> usize {
    let internal_params = get_internal_params_from_params(params);

    match format {
        Format::PrivateSeed => SIZEOF_FORMAT_PRIVATE_SEED,
        Format::DecapsulationKey => {
            sizeof_format_decapsulation_key(internal_params.n_rows as usize)
        }
        Format::EncapsulationKey => {
            sizeof_format_encapsulation_key(internal_params.n_rows as usize)
        }
    }
}

pub fn sizeof_ciphertext_from_params(params: Params) -> usize {
    let internal_params = get_internal_params_from_params(params);

    // u vector encoded with n_bits_of_u * MLWE_POLYNOMIAL_COEFFICIENTS bits per polynomial
    let cb_u = (internal_params.n_rows as usize)
        * (internal_params.n_bits_of_u as usize)
        * (MLWE_POLYNOMIAL_COEFFICIENTS / 8);
    // v polynomial encoded with n_bits_of_v * MLWE_POLYNOMIAL_COEFFICIENTS bits
    let cb_v = (internal_params.n_bits_of_v as usize) * (MLWE_POLYNOMIAL_COEFFICIENTS / 8);

    debug_assert!(
        (internal_params.params != Params::MlKem512) || ((cb_u + cb_v) == CIPHERTEXT_SIZE_MLKEM512)
    );
    debug_assert!(
        (internal_params.params != Params::MlKem768) || ((cb_u + cb_v) == CIPHERTEXT_SIZE_MLKEM768)
    );
    debug_assert!(
        (internal_params.params != Params::MlKem1024)
            || ((cb_u + cb_v) == CIPHERTEXT_SIZE_MLKEM1024)
    );

    cb_u + cb_v
}

fn key_expand_public_matrix_from_public_seed(
    pk_mlkem_key: &mut Key,
    p_comp_temps: &mut InternalComputationTemporaries,
) {
    let mut coordinates = [0u8; 2];

    let p_shake_state_base = &mut p_comp_temps.hash_state0;
    let p_shake_state_work = &mut p_comp_temps.hash_state1;
    let n_rows = pk_mlkem_key.params.n_rows;

    p_shake_state_base.set_alg(MlKemHashAlg::Shake128);
    p_shake_state_base.init();
    p_shake_state_base.append(&pk_mlkem_key.public_seed);

    for i in 0u8..n_rows {
        coordinates[1] = i;
        for j in 0u8..n_rows {
            coordinates[0] = j;
            *p_shake_state_work = p_shake_state_base.clone();
            debug_assert!(p_shake_state_work.get_alg() == MlKemHashAlg::Shake128);
            p_shake_state_work.append(&coordinates);

            let a_transpose = pk_mlkem_key.a_transpose_mut();
            poly_element_sample_ntt_from_shake128(p_shake_state_work, &mut a_transpose[(i*n_rows+j) as usize]);
        }
    }

    // no need to wipe; everything computed here is always public
}

fn key_compute_encapsulation_key_hash(
    pk_mlkem_key: &mut Key,
    p_comp_temps: &mut InternalComputationTemporaries,
) {
    let p_state = &mut p_comp_temps.hash_state0;
    let cb_encoded_vector = sizeof_encoded_uncompressed_vector(pk_mlkem_key.params.n_rows as usize);

    p_state.set_alg(MlKemHashAlg::Sha3_256);
    p_state.init();
    p_state.append(&pk_mlkem_key.encoded_t[0..cb_encoded_vector]);
    p_state.append(&pk_mlkem_key.public_seed);
    p_state.result(&mut pk_mlkem_key.encaps_key_hash);
}

fn key_expand_from_private_seed(
    pk_mlkem_key: &mut Key,
    p_comp_temps: &mut InternalComputationTemporaries,
) {
    let mut private_seed_hash = [0u8; Sha3_512::RESULT_SIZE];
    let mut cbd_sample_buffer = [0u8; 3 * 64 + 1];
    let n_rows = pk_mlkem_key.params.n_rows;
    let n_eta1 = pk_mlkem_key.params.n_eta1;
    let cb_encoded_vector = sizeof_encoded_uncompressed_vector(n_rows as usize);

    debug_assert!(pk_mlkem_key.has_private_seed);
    debug_assert!((n_eta1 == 2) || (n_eta1 == 3));

    // Note(Rust): there's a whole lot of NULL-checking going on in C, which presumably does not
    // happen here -- the checks for NULL in the C code seem to be unreachable, because at the
    // leaves, SymCryptPolyElementCreate cannot return NULL...?

    // (rho || sigma) = G(d || k)
    // use cbd_sample_buffer to concatenate the private seed and encoding of n_rows
    cbd_sample_buffer[0..pk_mlkem_key.private_seed.len()]
        .copy_from_slice(&pk_mlkem_key.private_seed);
    cbd_sample_buffer[pk_mlkem_key.private_seed.len() /* == 32 */] = n_rows;
    Sha3_512::hash(
        &cbd_sample_buffer[0..pk_mlkem_key.private_seed.len() + 1],
        &mut private_seed_hash,
    );

    // copy public seed
    let pk_len = pk_mlkem_key.public_seed.len();
    pk_mlkem_key
        .public_seed
        .copy_from_slice(&private_seed_hash[0..pk_len]);

    // generate A from public seed
    key_expand_public_matrix_from_public_seed(pk_mlkem_key, p_comp_temps);

    // Initialize p_shake_stateBase with sigma
    p_comp_temps.hash_state0.set_alg(MlKemHashAlg::Shake256);
    p_comp_temps.hash_state0.init();
    p_comp_temps.hash_state0.append(
        &private_seed_hash[pk_mlkem_key.public_seed.len()..pk_mlkem_key.public_seed.len() + 32],
    );

    // Expand s in place
    for i in 0u8..n_rows {
        cbd_sample_buffer[0] = i;
        p_comp_temps.hash_state1 = p_comp_temps.hash_state0.clone();
        debug_assert!(p_comp_temps.hash_state1.get_alg() == MlKemHashAlg::Shake256);
        p_comp_temps.hash_state1.append(&cbd_sample_buffer[0..1]);

        p_comp_temps.hash_state1.extract(&mut cbd_sample_buffer[0..64usize*(n_eta1 as usize)], false);

        poly_element_sample_cbd_from_bytes( &cbd_sample_buffer, n_eta1 as u32, &mut pk_mlkem_key.s_mut()[i as usize]);
    }
    // Expand e in t, ready for multiply-add
    for i in 0u8..n_rows {
        cbd_sample_buffer[0] = n_rows+i;
        p_comp_temps.hash_state1 = p_comp_temps.hash_state0.clone();
        debug_assert!(p_comp_temps.hash_state1.get_alg() == MlKemHashAlg::Shake256);
        p_comp_temps.hash_state1.append(&cbd_sample_buffer[0..1]);

        p_comp_temps.hash_state1.extract(&mut cbd_sample_buffer[0..64*(n_eta1 as usize)], false);

        poly_element_sample_cbd_from_bytes( &cbd_sample_buffer, n_eta1 as u32, &mut pk_mlkem_key.t_mut()[i as usize]);
    }

    // Perform NTT on s and e
    vector_ntt(pk_mlkem_key.s_mut());
    vector_ntt(pk_mlkem_key.t_mut());

    // pv_tmp = s .* R
    let pv_tmp = &mut p_comp_temps.max_size_vector0[0..n_rows as usize];
    vector_mul_r(pk_mlkem_key.s_mut(), pv_tmp);

    // t = ((A o (s .* R)) ./ R) + e = A o s + e
    let (a, t, _s) = pk_mlkem_key.ats_mut();
    let pa_tmp = &mut p_comp_temps.poly_element_accumulator;
    matrix_vector_mont_mul_and_add(
        a,
        &p_comp_temps.max_size_vector0[0..n_rows as usize],
        t,
        pa_tmp,
        n_rows,
    );

    // transpose A
    matrix_transpose(a, n_rows);

    // precompute byte-encoding of public vector t
    let (t, encoded_t) = pk_mlkem_key.t_encoded_t_mut();
    vector_compress_and_encode(t, 12, &mut encoded_t[0..cb_encoded_vector]);

    // precompute hash of encapsulation key blob
    key_compute_encapsulation_key_hash(pk_mlkem_key, p_comp_temps);

    crate::common::wipe_slice(&mut private_seed_hash);
    crate::common::wipe_slice(&mut cbd_sample_buffer);
}

//=====================================================
// Flags for asymmetric key generation and import

// These flags are introduced primarily for FIPS purposes. For FIPS 140-3 rather than expose to the
// caller the specifics of what tests will be run with various algorithms, we are sanitizing flags
// provided on asymmetric key generation and import to enable the caller to indicate their intent,
// and for SymCrypt to perform the required testing.
// Below we define the flags that can be passed and when a caller should set them.
// The specifics of what tests will be run are likely to change over time, as FIPS requirements and
// our understanding of how best to implement them, change over time. Callers should not rely on
// specific behavior.

// Validation required by FIPS is enabled by default. This flag enables a caller to opt out of this
// validation.
const FLAG_KEY_NO_FIPS: u32 = 0x100;

// When opting out of FIPS, SymCrypt may still perform some sanity checks on key import
// In very performance sensitive situations where a caller strongly trusts the values it is passing
// to SymCrypt and does not care about FIPS (or can statically prove properties about the imported
// keys), a caller may specify FLAG_KEY_MINIMAL_VALIDATION in addition to
// FLAG_KEY_NO_FIPS to skip costly checks
const FLAG_KEY_MINIMAL_VALIDATION: u32 = 0x200;

extern "C" {
    #[cfg(not(any(feature = "benchmarking", test)))]
    fn SymCryptMlKemSelftest();
}

pub fn key_set_value(
    pb_src: &[u8],
    format: Format,
    flags: u32,
    pk_mlkem_key: &mut Key,
) -> Error {
    let mut pb_curr: usize = 0;
    let n_rows = pk_mlkem_key.params.n_rows;
    let cb_encoded_vector = sizeof_encoded_uncompressed_vector(n_rows as usize);

    // Ensure only allowed flags are specified
    let allowed_flags: u32 = FLAG_KEY_NO_FIPS | FLAG_KEY_MINIMAL_VALIDATION;

    if (flags & !allowed_flags) != 0 {
        return Error::InvalidArgument;
    }

    // Check that minimal validation flag only specified with no fips
    if ((flags & FLAG_KEY_NO_FIPS) == 0) && ((flags & FLAG_KEY_MINIMAL_VALIDATION) != 0) {
        return Error::InvalidArgument;
    }

    if (flags & FLAG_KEY_NO_FIPS) == 0 {
        // Ensure ML-KEM algorithm selftest is run before first use of ML-KEM algorithms;
        // notably _before_ first full KeyGen
        // FIXME: Skip FIPS self-test in pure-Rust testing
        #[cfg(not(any(feature = "benchmarking", test, feature = "verify")))]
        run_selftest_once( SymCryptMlKemSelftest, SelftestAlgorithm::MLKEM as u32 );
    }

    let mut p_comp_temps = match try_new_box_default::<InternalComputationTemporaries>() {
        Result::Err(_) => return Error::MemoryAllocationFailure,
        Result::Ok(p_comp_temps) => p_comp_temps,
    };

    match format {
        Format::PrivateSeed => {
            if pb_src.len() != SIZEOF_FORMAT_PRIVATE_SEED {
                return Error::WrongKeySize;
            }

            pk_mlkem_key.has_private_seed = true;
            let l = pk_mlkem_key.private_seed.len();
            pk_mlkem_key.private_seed.copy_from_slice(&pb_src[0..l]);
            pb_curr += l;

            pk_mlkem_key.has_private_key = true;
            let l = pk_mlkem_key.private_random.len();
            pk_mlkem_key
                .private_random
                .copy_from_slice(&pb_src[pb_curr..pb_curr + l]);
            pb_curr += l;

            key_expand_from_private_seed(pk_mlkem_key, &mut p_comp_temps);
        }

        Format::DecapsulationKey => {
            if pb_src.len() != sizeof_format_decapsulation_key(n_rows as usize) {
                return Error::WrongKeySize;
            }

            // decode s
            let sc_error = vector_decode_and_decompress(
                &pb_src[pb_curr..pb_curr + cb_encoded_vector],
                12,
                pk_mlkem_key.s_mut(),
            );
            if sc_error != Error::NoError {
                return sc_error;
            }
            pb_curr += cb_encoded_vector;

            // copy t and decode t
            pk_mlkem_key.encoded_t[0..cb_encoded_vector]
                .copy_from_slice(&pb_src[pb_curr..pb_curr + cb_encoded_vector]);
            pb_curr += cb_encoded_vector;
            let (t, encoded_t) = pk_mlkem_key.t_encoded_t_mut();
            let sc_error = vector_decode_and_decompress(&encoded_t[0..cb_encoded_vector], 12, t);
            if sc_error != Error::NoError {
                return sc_error;
            }

            // copy public seed and expand public matrix
            let l = pk_mlkem_key.public_seed.len();
            pk_mlkem_key
                .public_seed
                .copy_from_slice(&pb_src[pb_curr..pb_curr + l]);
            pb_curr += pk_mlkem_key.public_seed.len();
            key_expand_public_matrix_from_public_seed(pk_mlkem_key, &mut p_comp_temps);

            // transpose A
            matrix_transpose(pk_mlkem_key.a_transpose_mut(), n_rows);

            // compute hash of encapsulation key blob
            key_compute_encapsulation_key_hash(pk_mlkem_key, &mut p_comp_temps);

            // check hash of encapsulation key matches hash in the provided blob
            let l = pk_mlkem_key.encaps_key_hash.len();
            if !const_time_slices_equal(
                &pk_mlkem_key.encaps_key_hash,
                &pb_src[pb_curr..pb_curr + l],
            ) {
                return Error::InvalidBlob;
            }

            pb_curr += pk_mlkem_key.encaps_key_hash.len();

            // copy private random
            let l = pk_mlkem_key.private_random.len();
            pk_mlkem_key
                .private_random
                .copy_from_slice(&pb_src[pb_curr..pb_curr + l]);
            pb_curr += pk_mlkem_key.private_random.len();

            pk_mlkem_key.has_private_seed = false;
            pk_mlkem_key.has_private_key = true;
        }

        Format::EncapsulationKey => {
            if pb_src.len() != sizeof_format_encapsulation_key(n_rows as usize) {
                return Error::WrongKeySize;
            }

            // copy t and decode t
            pk_mlkem_key.encoded_t[0..cb_encoded_vector]
                .copy_from_slice(&pb_src[pb_curr..pb_curr + cb_encoded_vector]);
            pb_curr += cb_encoded_vector;
            let (t, encoded_t) = pk_mlkem_key.t_encoded_t_mut();
            let sc_error = vector_decode_and_decompress(&encoded_t[0..cb_encoded_vector], 12, t);
            if sc_error != Error::NoError {
                return sc_error;
            }

            // copy public seed and expand public matrix
            let l = pk_mlkem_key.public_seed.len();
            pk_mlkem_key
                .public_seed
                .copy_from_slice(&pb_src[pb_curr..pb_curr + l]);
            pb_curr += pk_mlkem_key.public_seed.len();
            key_expand_public_matrix_from_public_seed(pk_mlkem_key, &mut p_comp_temps);

            // transpose A
            matrix_transpose(pk_mlkem_key.a_transpose_mut(), n_rows);

            // precompute hash of encapsulation key blob
            key_compute_encapsulation_key_hash(pk_mlkem_key, &mut p_comp_temps);

            pk_mlkem_key.has_private_seed = false;
            pk_mlkem_key.has_private_key = false;
        }
    };

    debug_assert!(pb_curr == pb_src.len());

    Error::NoError
}

pub fn key_get_value(
    pk_mlkem_key: &Key,
    pb_dst: &mut [u8],
    format: Format,
    _flags: u32,
) -> Error {
    let mut pb_curr: usize = 0;
    let n_rows = pk_mlkem_key.params.n_rows;
    let cb_encoded_vector = sizeof_encoded_uncompressed_vector(n_rows as usize);

    match format {
        Format::PrivateSeed => {
            if pb_dst.len() != SIZEOF_FORMAT_PRIVATE_SEED {
                return Error::WrongKeySize;
            }

            if !pk_mlkem_key.has_private_seed {
                return Error::IncompatibleFormat;
            }

            pb_dst[pb_curr..pb_curr + pk_mlkem_key.private_seed.len()]
                .copy_from_slice(&pk_mlkem_key.private_seed);
            pb_curr += pk_mlkem_key.private_seed.len();

            pb_dst[pb_curr..pb_curr + pk_mlkem_key.private_random.len()]
                .copy_from_slice(&pk_mlkem_key.private_random);
            pb_curr += pk_mlkem_key.private_random.len();
        }

        Format::DecapsulationKey => {
            if pb_dst.len() != sizeof_format_decapsulation_key(n_rows as usize) {
                return Error::InvalidArgument;
            }

            if !pk_mlkem_key.has_private_key {
                return Error::InvalidArgument;
            }

            // We don't precompute byte-encoding of private key as exporting decapsulation key is not a critical path operation
            // All other fields are kept in memory
            vector_compress_and_encode(pk_mlkem_key.s(), 12, &mut pb_dst[0..cb_encoded_vector]);
            pb_curr += cb_encoded_vector;

            pb_dst[pb_curr..pb_curr + cb_encoded_vector]
                .copy_from_slice(&pk_mlkem_key.encoded_t[0..cb_encoded_vector]);
            pb_curr += cb_encoded_vector;

            pb_dst[pb_curr..pb_curr + pk_mlkem_key.public_seed.len()]
                .copy_from_slice(&pk_mlkem_key.public_seed);
            pb_curr += pk_mlkem_key.public_seed.len();

            pb_dst[pb_curr..pb_curr + pk_mlkem_key.encaps_key_hash.len()]
                .copy_from_slice(&pk_mlkem_key.encaps_key_hash);
            pb_curr += pk_mlkem_key.encaps_key_hash.len();

            pb_dst[pb_curr..pb_curr + pk_mlkem_key.private_random.len()]
                .copy_from_slice(&pk_mlkem_key.private_random);
            pb_curr += pk_mlkem_key.private_random.len();
        }

        Format::EncapsulationKey => {
            if pb_dst.len() != sizeof_format_encapsulation_key(n_rows as usize) {
                return Error::InvalidArgument;
            }

            pb_dst[pb_curr..pb_curr + cb_encoded_vector]
                .copy_from_slice(&pk_mlkem_key.encoded_t[0..cb_encoded_vector]);
            pb_curr += cb_encoded_vector;

            pb_dst[pb_curr..pb_curr + pk_mlkem_key.public_seed.len()]
                .copy_from_slice(&pk_mlkem_key.public_seed);
            pb_curr += pk_mlkem_key.public_seed.len();
        }
    }

    debug_assert!(pb_curr == pb_dst.len());

    Error::NoError
}

pub const SIZEOF_MAX_CIPHERTEXT: usize = 1568;
pub const SIZEOF_AGREED_SECRET: usize = 32;
pub const SIZEOF_ENCAPS_RANDOM: usize = 32;

pub fn key_generate(pk_mlkem_key: &mut Key, flags: u32) -> Error {
    let mut private_seed = [0u8; SIZEOF_FORMAT_PRIVATE_SEED];

    // Ensure only allowed flags are specified
    let allowed_flags: u32 = FLAG_KEY_NO_FIPS;

    if (flags & !allowed_flags) != 0 {
        return Error::InvalidArgument;
    }

    let sc_error = random(&mut private_seed);
    if sc_error != Error::NoError {
        return sc_error;
    }

    let sc_error = key_set_value(
        &private_seed,
        Format::PrivateSeed,
        flags,
        pk_mlkem_key,
    );
    if sc_error != Error::NoError {
        return sc_error;
    }

    // keySetValue ensures the self-test is run before
    // first operational use of MlKem

    if flags & FLAG_KEY_NO_FIPS == 0 {
        // PCT on key generation, encaps/decaps and check that both parties get the same shared secret with the generated key
        let n_rows = pk_mlkem_key.params.n_rows;
        let n_bits_of_u = pk_mlkem_key.params.n_bits_of_u;
        let n_bits_of_v = pk_mlkem_key.params.n_bits_of_v;

        // u vector encoded with n_bits_of_u * MLWE_POLYNOMIAL_COEFFICIENTS bits per polynomial
        let cb_u = (n_rows as usize) * (n_bits_of_u as usize) * (MLWE_POLYNOMIAL_COEFFICIENTS / 8);
        // v polynomial encoded with n_bits_of_v * MLWE_POLYNOMIAL_COEFFICIENTS bits
        let cb_v = (n_bits_of_v as usize) * (MLWE_POLYNOMIAL_COEFFICIENTS / 8);
        let cb_ciphertext = cb_u + cb_v;

        let mut pb_ciphertext_box = match try_new_box_zeroed::<[u8; SIZEOF_MAX_CIPHERTEXT]>() {
            Result::Err(_) => return Error::MemoryAllocationFailure,
            Result::Ok(t) => t,
        };

        let pb_ciphertext = &mut pb_ciphertext_box[0..cb_ciphertext];

        const { assert!( SIZEOF_FORMAT_PRIVATE_SEED >= 2*SIZEOF_AGREED_SECRET ) }

        // reuse bytes 0..31 of privateSeed buffer for encapsulation shared secret
        let sc_error = encapsulate(pk_mlkem_key, &mut private_seed[0..SIZEOF_AGREED_SECRET], pb_ciphertext);
        if sc_error != Error::NoError {
            return Error::FipsFailure;
        }

        // reuse bytes 32..63 of privateSeed buffer for decapsulation shared secret
        let sc_error = decapsulate(pk_mlkem_key, pb_ciphertext, &mut private_seed[SIZEOF_AGREED_SECRET..2*SIZEOF_AGREED_SECRET]);
        if sc_error != Error::NoError {
            return Error::FipsFailure;
        }

        if !const_time_arrays_equal::<SIZEOF_AGREED_SECRET>(
            &private_seed[0..SIZEOF_AGREED_SECRET].try_into().unwrap(),
            &private_seed[SIZEOF_AGREED_SECRET..2*SIZEOF_AGREED_SECRET].try_into().unwrap(),
        ) {
            return Error::FipsFailure;
        }

        // could track having run the PCT with a flag in pk_mlkem_key.algorithm_info
        // but currently no need to do that given we don't ever defer the PCT
    }

    crate::common::wipe_slice(&mut private_seed);

    Error::NoError
}

fn encapsulate_internal(
    pk_mlkem_key: &Key,
    pb_agreed_secret: &mut [u8],
    pb_ciphertext: &mut [u8],
    pb_random: &[u8; SIZEOF_ENCAPS_RANDOM],
    p_comp_temps: &mut InternalComputationTemporaries,
) -> Error {
    let cb_agreed_secret = pb_agreed_secret.len();
    let cb_ciphertext = pb_ciphertext.len();
    let mut cbd_sample_buffer = [0u8; 3 * 64 + 1];
    let n_rows = pk_mlkem_key.params.n_rows;
    let n_bits_of_u = pk_mlkem_key.params.n_bits_of_u;
    let n_bits_of_v = pk_mlkem_key.params.n_bits_of_v;
    let n_eta1 = pk_mlkem_key.params.n_eta1;
    let n_eta2 = pk_mlkem_key.params.n_eta2;

    // u vector encoded with n_bits_of_u * MLWE_POLYNOMIAL_COEFFICIENTS bits per polynomial
    let cb_u = (n_rows as usize) * (n_bits_of_u as usize) * (MLWE_POLYNOMIAL_COEFFICIENTS / 8);
    // v polynomial encoded with n_bits_of_v * MLWE_POLYNOMIAL_COEFFICIENTS bits
    let cb_v = (n_bits_of_v as usize) * (MLWE_POLYNOMIAL_COEFFICIENTS / 8);

    if (cb_agreed_secret != SIZEOF_AGREED_SECRET) || (cb_ciphertext != cb_u + cb_v) {
        return Error::InvalidArgument;
    }

    let pvr_inner = &mut p_comp_temps.max_size_vector0[0..n_rows as usize];
    let pv_tmp = &mut p_comp_temps.max_size_vector1[0..n_rows as usize];
    let pe_tmp0 = &mut p_comp_temps.poly_element0;
    let pe_tmp1 = &mut p_comp_temps.poly_element1;
    let pa_tmp = &mut p_comp_temps.poly_element_accumulator;

    // cbd_sample_buffer = (K || rOuter) = SHA3-512(pb_random || encapsKeyHash)
    p_comp_temps.hash_state0.set_alg(MlKemHashAlg::Sha3_512);
    p_comp_temps.hash_state0.init();
    p_comp_temps.hash_state0.append(pb_random);
    p_comp_temps.hash_state0.append(&pk_mlkem_key.encaps_key_hash);
    // Note (Rust): should we have a type that is less strict for the output of sha3_512_result?
    // Note (Rust): no debug_assert!(SIZEOF_AGREED_SECRET < SHA3_512_RESULT_SIZE)?
    p_comp_temps.hash_state0.result(
        &mut cbd_sample_buffer[0..Sha3_512::RESULT_SIZE],
    );

    // Write K to pb_agreed_secret
    pb_agreed_secret[0..SIZEOF_AGREED_SECRET]
        .copy_from_slice(&cbd_sample_buffer[0..SIZEOF_AGREED_SECRET]);

    // Initialize p_shake_stateBase with rOuter
    p_comp_temps.hash_state0.set_alg(MlKemHashAlg::Shake256);
    p_comp_temps.hash_state0.init();
    p_comp_temps.hash_state0.append(&cbd_sample_buffer[cb_agreed_secret..cb_agreed_secret + 32]);

    assert!(n_rows >= MATRIX_MIN_NROWS as u8 && n_rows <= MATRIX_MAX_NROWS as u8);

    // Expand rInner vector
    for i in 0u8..n_rows {
        cbd_sample_buffer[0] = i;
        p_comp_temps.hash_state1 = p_comp_temps.hash_state0.clone();
        debug_assert!(p_comp_temps.hash_state1.get_alg() == MlKemHashAlg::Shake256);
        p_comp_temps.hash_state1.append(&cbd_sample_buffer[0..1]);

        p_comp_temps.hash_state1.extract(&mut cbd_sample_buffer[0..64usize*(n_eta1 as usize)], false);

        poly_element_sample_cbd_from_bytes( &cbd_sample_buffer, n_eta1 as u32, &mut pvr_inner[i as usize]);
    }

    // Perform NTT on rInner
    vector_ntt(pvr_inner);

    // Set pv_tmp to 0
    vector_set_zero(pv_tmp);

    // pv_tmp = (Atranspose o rInner) ./ R
    matrix_vector_mont_mul_and_add(
        pk_mlkem_key.a_transpose(),
        pvr_inner,
        pv_tmp,
        pa_tmp,
        n_rows,
    );

    // pv_tmp = INTT(Atranspose o rInner)
    vector_intt_and_mul_r(pv_tmp);

    // Expand e1 and add it to pv_tmp - do addition PolyElement-wise to reduce memory usage
    for i in 0u8..n_rows {
        cbd_sample_buffer[0] = n_rows+i;
        p_comp_temps.hash_state1 = p_comp_temps.hash_state0.clone();
        debug_assert!(p_comp_temps.hash_state1.get_alg() == MlKemHashAlg::Shake256);
        p_comp_temps.hash_state1.append(&cbd_sample_buffer[0..1]);

        p_comp_temps.hash_state1.extract(&mut cbd_sample_buffer[0..64*(n_eta2 as usize)], false);

        poly_element_sample_cbd_from_bytes( &cbd_sample_buffer, n_eta2 as u32, pe_tmp0 );

        poly_element_add_in_place( pe_tmp0, &mut pv_tmp[i as usize] );
    }

    // pv_tmp = u = INTT(Atranspose o rInner) + e1
    // Compress and encode u into prefix of ciphertext
    vector_compress_and_encode(pv_tmp, n_bits_of_u as u32, &mut pb_ciphertext[0..cb_u]);

    // pe_tmp0 = (t o r) ./ R
    vector_mont_dot_product(pk_mlkem_key.t(), pvr_inner, pe_tmp0, pa_tmp);

    // pe_tmp0 = INTT(t o r)
    poly_element_intt_and_mul_r(pe_tmp0);

    // Expand e2 polynomial in pe_tmp1
    cbd_sample_buffer[0] = 2 * n_rows;
    p_comp_temps.hash_state1 = p_comp_temps.hash_state0.clone();
    debug_assert!(p_comp_temps.hash_state1.get_alg() == MlKemHashAlg::Shake256);
    p_comp_temps.hash_state1.append(&cbd_sample_buffer[0..1]);

    p_comp_temps.hash_state1.extract(
        &mut cbd_sample_buffer[0..64 * (n_eta2 as usize)],
        false,
    );

    poly_element_sample_cbd_from_bytes( &cbd_sample_buffer, n_eta2 as u32, pe_tmp1);

    // pe_tmp0 = INTT(t o r) + e2
    poly_element_add_in_place(pe_tmp1, pe_tmp0);

    // pe_tmp1 = mu
    poly_element_decode_and_decompress(pb_random, 1, pe_tmp1);

    // pe_tmp0 = v = INTT(t o r) + e2 + mu
    poly_element_add_in_place(pe_tmp1, pe_tmp0);

    // Compress and encode v into remainder of ciphertext
    poly_element_compress_and_encode(pe_tmp0, n_bits_of_v as u32, &mut pb_ciphertext[cb_u..]);

    crate::common::wipe_slice(&mut cbd_sample_buffer);

    Error::NoError
}

pub fn encapsulate_ex(
    pk_mlkem_key: &Key,
    pb_random: &[u8; SIZEOF_ENCAPS_RANDOM],
    pb_agreed_secret: &mut [u8],
    pb_ciphertext: &mut [u8],
) -> Error {
    let mut p_comp_temps = match try_new_box_default::<InternalComputationTemporaries>() {
        Result::Err(_) => return Error::MemoryAllocationFailure,
        Result::Ok(p_comp_temps) => p_comp_temps,
    };

    encapsulate_internal(
        pk_mlkem_key,
        pb_agreed_secret,
        pb_ciphertext,
        pb_random,
        &mut p_comp_temps,
    )
}

pub fn encapsulate(
    pk_mlkem_key: &Key,
    pb_agreed_secret: &mut [u8],
    pb_ciphertext: &mut [u8],
) -> Error {
    let mut pbm = [0u8; SIZEOF_ENCAPS_RANDOM];

    let sc_error = random(&mut pbm);
    if sc_error != Error::NoError {
        return sc_error;
    }

    let sc_error = encapsulate_ex(pk_mlkem_key, &pbm, pb_agreed_secret, pb_ciphertext);

    crate::common::wipe_slice(&mut pbm);

    sc_error
}

struct DecapsulateTemps {
    comp_temps: InternalComputationTemporaries,
    read_ciphertext: [u8; SIZEOF_MAX_CIPHERTEXT],
    reencapsulated_ciphertext: [u8; SIZEOF_MAX_CIPHERTEXT],
}

unsafe impl BoxDefault for DecapsulateTemps {
    #[cfg_attr(feature = "verify", verify::opaque)]
    unsafe fn box_default(ptr: *mut Self) {
        InternalComputationTemporaries::box_default(&raw mut (*ptr).comp_temps);
    }
}

pub fn decapsulate(pk_mlkem_key: &Key, pb_ciphertext: &[u8], pb_agreed_secret: &mut [u8]) -> Error {
    let cb_ciphertext = pb_ciphertext.len();
    let cb_agreed_secret = pb_agreed_secret.len();

    let n_rows = pk_mlkem_key.params.n_rows;
    let n_bits_of_u = pk_mlkem_key.params.n_bits_of_u;
    let n_bits_of_v = pk_mlkem_key.params.n_bits_of_v;

    // u vector encoded with n_bits_of_u * MLWE_POLYNOMIAL_COEFFICIENTS bits per polynomial
    let cb_u = n_rows as usize * n_bits_of_u as usize * (MLWE_POLYNOMIAL_COEFFICIENTS / 8);
    // v polynomial encoded with n_bits_of_v * MLWE_POLYNOMIAL_COEFFICIENTS bits
    let cb_v = n_bits_of_v as usize * (MLWE_POLYNOMIAL_COEFFICIENTS / 8);

    if (cb_agreed_secret != SIZEOF_AGREED_SECRET)
        || (cb_ciphertext != cb_u + cb_v)
        || !pk_mlkem_key.has_private_key
    {
        return Error::InvalidArgument;
    }

    let mut local_temps_box = match try_new_box_default::<DecapsulateTemps>() {
        Result::Err(_) => return Error::MemoryAllocationFailure,
        Result::Ok(local_temps_box) => local_temps_box,
    };

    let p_comp_temps = &mut local_temps_box.comp_temps;
    let pb_read_ciphertext = &mut local_temps_box.read_ciphertext[0..cb_ciphertext];
    let pb_reencapsulated_ciphertext = &mut local_temps_box.reencapsulated_ciphertext[0..cb_ciphertext];

    let mut pb_decrypted_random = [0u8; SIZEOF_ENCAPS_RANDOM];
    let mut pb_decapsulated_secret = [0u8; SIZEOF_AGREED_SECRET];
    let mut pb_implicit_rejection_secret = [0u8; SIZEOF_AGREED_SECRET];

    // Read the input ciphertext once to local pbReadCiphertext to ensure our view of ciphertext consistent
    pb_read_ciphertext.copy_from_slice(pb_ciphertext);

    let pvu = &mut p_comp_temps.max_size_vector0[0..n_rows as usize];
    let pe_tmp0 = &mut p_comp_temps.poly_element0;
    let pe_tmp1 = &mut p_comp_temps.poly_element1;
    let pa_tmp = &mut p_comp_temps.poly_element_accumulator;

    // Decode and decompress u
    let sc_error =
        vector_decode_and_decompress(&pb_read_ciphertext[0..cb_u], n_bits_of_u as u32, pvu);
    debug_assert!(sc_error == Error::NoError);

    // Perform NTT on u
    vector_ntt(pvu);

    // pe_tmp0 = (s o NTT(u)) ./ R
    vector_mont_dot_product(pk_mlkem_key.s(), pvu, pe_tmp0, pa_tmp);

    // pe_tmp0 = INTT(s o NTT(u))
    poly_element_intt_and_mul_r(pe_tmp0);

    // Decode and decompress v
    let sc_error = poly_element_decode_and_decompress(
        &pb_read_ciphertext[cb_u..],
        n_bits_of_v as u32,
        pe_tmp1,
    );
    debug_assert!(sc_error == Error::NoError);

    // pe_tmp0 = w = v - INTT(s o NTT(u))
    poly_element_sub_from_in_place(pe_tmp1, pe_tmp0);

    // pbDecryptedRandom = m' = Encoding of w
    poly_element_compress_and_encode(pe_tmp0, 1, &mut pb_decrypted_random);

    // Compute:
    //  pbDecapsulatedSecret = K' = Decapsulated secret (without implicit rejection)
    //  pbReencapsulatedCiphertext = c' = Ciphertext from re-encapsulating decrypted random value
    let sc_error = encapsulate_internal(
        pk_mlkem_key,
        &mut pb_decapsulated_secret,
        pb_reencapsulated_ciphertext,
        &pb_decrypted_random,
        p_comp_temps,
    );
    debug_assert!(sc_error == Error::NoError);

    // Compute the secret we will return if using implicit rejection
    // pbImplicitRejectionSecret = K_bar = SHAKE256( z || c )
    let p_shake_state = &mut p_comp_temps.hash_state0;
    p_shake_state.set_alg(MlKemHashAlg::Shake256);
    p_shake_state.init();
    p_shake_state.append(&pk_mlkem_key.private_random);
    p_shake_state.append(pb_read_ciphertext);
    p_shake_state.extract(&mut pb_implicit_rejection_secret, false);

    // Constant time test if re-encryption successful
    let successful_reencrypt = const_time_slices_equal(pb_reencapsulated_ciphertext, pb_read_ciphertext);

    // If not successful, perform side-channel-safe copy of Implicit Rejection secret over Decapsulated secret
    // Use constant-time selection: if successful, use pb_decapsulated_secret; otherwise use pb_implicit_rejection_secret
    let cb_copy = (successful_reencrypt as u32).wrapping_sub(1) & (SIZEOF_AGREED_SECRET as u32);
    const_time_array_copy(&pb_implicit_rejection_secret, &mut pb_decapsulated_secret, cb_copy);

    // Write agreed secret (with implicit rejection) to pb_agreed_secret
    pb_agreed_secret.copy_from_slice(&pb_decapsulated_secret);

    crate::common::wipe_slice(pb_read_ciphertext);
    crate::common::wipe_slice(pb_reencapsulated_ciphertext);
    crate::common::wipe_slice(&mut pb_decrypted_random);
    crate::common::wipe_slice(&mut pb_decapsulated_secret);
    crate::common::wipe_slice(&mut pb_implicit_rejection_secret);

    Error::NoError
}
