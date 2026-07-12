//
// test.rs  Local Rust test module used in bring up of ML-KEM code
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// use std::io::Write;
use crate::common::Error;
use alloc::boxed::Box;
use super::*;
use crate::sha3::Sha3_256;

#[test]
pub fn test_api() -> Result<(), Box<dyn std::error::Error>> {
    crate::common::init();

    // KNOWN-ANSWER TEST
    let key_generation_seed = hex::decode("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f")?;
    assert_eq!(key_generation_seed.len(), 64);

    // Allocate + key-gen
    let mut k = key::key_allocate(key::Params::MlKem768)?;
    let r = key_set_value(&key_generation_seed, key::Format::PrivateSeed, 0, &mut k);
    // TODO: ideally these would use std::result so that we can use the ? operator like we do for
    // hex::decode, below.
    if r != Error::NoError {
        return Err(Box::new(r))
    }

    // Read secret (a.k.a. decapsulation) key
    let mut secret_key = [0u8; sizeof_format_decapsulation_key(3)];
    let r = key_get_value(&k, &mut secret_key, key::Format::DecapsulationKey, 0);
    if r != Error::NoError {
        return Err(Box::new(r))
    }
    let sha3_256_hash_of_secret_key = hex::decode("7deef44965b03d76de543ad6ef9e74a2772fa5a9fa0e761120dac767cf0152ef")?;
    let mut actual_sha3_256_hash_of_secret_key = [0u8; 32];
    Sha3_256::hash(&secret_key, &mut actual_sha3_256_hash_of_secret_key);
    assert_eq!(sha3_256_hash_of_secret_key, actual_sha3_256_hash_of_secret_key);

    // Read public (a.k.a. encapsulation) key
    let mut public_key = [0u8; sizeof_format_encapsulation_key(3)];
    let r = key_get_value(&k, &mut public_key, key::Format::EncapsulationKey, 0);
    if r != Error::NoError {
        return Err(Box::new(r))
    }
    let sha3_256_hash_of_public_key = hex::decode("f57262661358cde8d3ebf990e5fd1d5b896c992ccfaadb5256b68bbf5943b132")?;
    let mut actual_sha3_256_hash_of_public_key = [0u8; 32];
    Sha3_256::hash(&public_key, &mut actual_sha3_256_hash_of_public_key);
    assert_eq!(sha3_256_hash_of_public_key, actual_sha3_256_hash_of_public_key);

    // Compute shared secret + ciphertext
    let encapsulation_random = hex::decode("147c03f7a5bebba406c8fae1874d7f13c80efe79a3a9a874cc09fe76f6997615")?;
    let mut actual_shared_secret = [0u8; 32];
    let mut cipher_text = [0u8; 1088];
    let r = encapsulate_ex(&mut k, &encapsulation_random[0..32].try_into().unwrap(), &mut actual_shared_secret, &mut cipher_text);
    if r != Error::NoError {
        return Err(Box::new(r))
    }
    let sha3_256_hash_of_ciphertext = hex::decode("6e777e2cf8054659136a971d9e70252f301226930c19c470ee0688163a63c15b")?;
    let mut actual_sha3_256_hash_of_ciphertext = [0u8; 32];
    Sha3_256::hash(&cipher_text, &mut actual_sha3_256_hash_of_ciphertext);
    assert_eq!(sha3_256_hash_of_ciphertext, actual_sha3_256_hash_of_ciphertext);
    let shared_secret = hex::decode("e7184a0975ee3470878d2d159ec83129c8aec253d4ee17b4810311d198cd0368")?;
    assert_eq!(shared_secret, actual_shared_secret);

    // Exercise decapsulation, and assert consistency
    let mut shared_secret2 = [0u8; 32];
    let r = decapsulate(&mut k, &cipher_text, &mut shared_secret2);
    if r != Error::NoError {
        return Err(Box::new(r))
    }
    assert_eq!(shared_secret2, actual_shared_secret);

    // Functional test -- should roundtrip!
    let mut k = key::key_allocate(key::Params::MlKem768)?;
    key_generate(&mut k, 0);
    let mut secret = [0u8; 32];
    let mut cipher = [0u8; 1088];
    encapsulate(&mut k, &mut secret, &mut cipher);

    let mut secret2 = [0u8; 32];
    decapsulate(&mut k, &cipher, &mut secret2);
    assert_eq!(secret, secret2);

    // Perf test -- simplistic
    let mut k = key::key_allocate(key::Params::MlKem768)?;
    for i in 0..1000u32 {
        key_generate(&mut k, 0);
        let mut secret = [(i % 256) as u8; 32];
        let mut cipher = [0u8; 1088];
        encapsulate(&mut k, &mut secret, &mut cipher);

        let mut secret2 = [(i % 256) as u8; 32];
        decapsulate(&mut k, &cipher, &mut secret2);
        assert_eq!(secret, secret2);
    }


    Ok(())
}



// Single end-to-end usability test. The whole Alice⇄Bob flow — including the
// shared-secret equality check — lives in the extractable `alice_bob_roundtrip`
// (composed from the per-party functions), so agreement is covered by that
// function's spec rather than by this test's harness. Here we just drive it on
// a fixed seed + randomness and confirm it succeeds.
#[test]
pub fn test_verified_api_usability() -> Result<(), Box<dyn std::error::Error>> {
    crate::common::init();

    let seed: workflow::Seed = hex::decode(
        "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d\
         8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f",
    )?
    .try_into()
    .unwrap();
    let random: workflow::Random =
        hex::decode("147c03f7a5bebba406c8fae1874d7f13c80efe79a3a9a874cc09fe76f6997615")?
            .try_into()
            .unwrap();

    // NoError <=> Alice and Bob derived the same shared secret (checked inside
    // the verified function via const_time_slices_equal).
    let _shared = workflow::alice_bob_roundtrip(&seed, &random)?;

    Ok(())
}
