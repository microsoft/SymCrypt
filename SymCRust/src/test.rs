//
// test.rs  Local Rust test module used in bring up of ML-KEM code
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// use std::io::Write;
use crate::common::Error;
use alloc::boxed::Box;

#[test]
pub fn test_ffi() -> Result<(), Box<dyn std::error::Error>> {
    crate::common::init();

    let mut actual = [0u8; 64];
    let expected = [
        0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5, 0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a, 0x75,
        0x6e, 0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59, 0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c,
        0x80, 0xa6, 0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c, 0x11, 0xe3, 0xe9, 0x40, 0x2c,
        0x3a, 0xc5, 0x58, 0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3, 0x01, 0x75, 0x85, 0x86,
        0x28, 0x1d, 0xcd, 0x26, 
    ];
    crate::hash::sha3_512(&[0u8; 0], &mut actual);
    assert_eq!(actual, expected);

    let mut actual = [0u8; 64];
    let mut hs = crate::hash::UNINITIALIZED_HASH_STATE;
    // println!("hs addr: {:p}", &mut hs);
    // println!("internal hash state: {:?}", hs.ks.state);
    // std::io::stdout().flush();

    crate::hash::sha3_512_init(&mut hs);
    // println!("internal hash state: {:?}", hs.ks.state);
    crate::hash::sha3_512_result(&mut hs, &mut actual);
    // println!("internal hash state: {:?}", hs.ks.state);
    assert_eq!(actual, expected);

    let mut actual = [0u8; 128];
    let dst: &mut [u8; 64] = (&mut actual[0..64]).try_into().unwrap();
    crate::hash::sha3_512(&[0u8; 0], dst);
    assert_eq!(actual[0..64], expected);

    Ok(())
}

#[test]
pub fn test_api() -> Result<(), Box<dyn std::error::Error>> {
    crate::common::init();

    // KNOWN-ANSWER TEST
    let key_generation_seed = hex::decode("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f")?;
    assert_eq!(key_generation_seed.len(), 64);

    // Allocate + key-gen
    let mut k = crate::key::key_allocate(crate::key::Params::MlKem768)?;
    let r = crate::mlkem::key_set_value(&key_generation_seed, crate::key::Format::PrivateSeed, 0, &mut k);
    // TODO: ideally these would use std::result so that we can use the ? operator like we do for
    // hex::decode, below.
    if r != Error::NoError {
        return Err(Box::new(r))
    }

    // Read secret (a.k.a. decapsulation) key
    let mut secret_key = [0u8; crate::mlkem::sizeof_format_decapsulation_key(3)];
    let r = crate::mlkem::key_get_value(&k, &mut secret_key, crate::key::Format::DecapsulationKey, 0);
    if r != Error::NoError {
        return Err(Box::new(r))
    }
    let sha3_256_hash_of_secret_key = hex::decode("7deef44965b03d76de543ad6ef9e74a2772fa5a9fa0e761120dac767cf0152ef")?;
    let mut actual_sha3_256_hash_of_secret_key = [0u8; 32];
    crate::hash::sha3_256(&secret_key, &mut actual_sha3_256_hash_of_secret_key);
    assert_eq!(sha3_256_hash_of_secret_key, actual_sha3_256_hash_of_secret_key);

    // Read public (a.k.a. encapsulation) key
    let mut public_key = [0u8; crate::mlkem::sizeof_format_encapsulation_key(3)];
    let r = crate::mlkem::key_get_value(&k, &mut public_key, crate::key::Format::EncapsulationKey, 0);
    if r != Error::NoError {
        return Err(Box::new(r))
    }
    let sha3_256_hash_of_public_key = hex::decode("f57262661358cde8d3ebf990e5fd1d5b896c992ccfaadb5256b68bbf5943b132")?;
    let mut actual_sha3_256_hash_of_public_key = [0u8; 32];
    crate::hash::sha3_256(&public_key, &mut actual_sha3_256_hash_of_public_key);
    assert_eq!(sha3_256_hash_of_public_key, actual_sha3_256_hash_of_public_key);

    // Compute shared secret + ciphertext
    let encapsulation_seed = hex::decode("147c03f7a5bebba406c8fae1874d7f13c80efe79a3a9a874cc09fe76f6997615")?;
    let mut actual_shared_secret = [0u8; 32];
    let mut cipher_text = [0u8; 1088];
    let r = crate::mlkem::encapsulate_ex(&mut k, &encapsulation_seed, &mut actual_shared_secret, &mut cipher_text);
    if r != Error::NoError {
        return Err(Box::new(r))
    }
    let sha3_256_hash_of_ciphertext = hex::decode("6e777e2cf8054659136a971d9e70252f301226930c19c470ee0688163a63c15b")?;
    let mut actual_sha3_256_hash_of_ciphertext = [0u8; 32];
    crate::hash::sha3_256(&cipher_text, &mut actual_sha3_256_hash_of_ciphertext);
    assert_eq!(sha3_256_hash_of_ciphertext, actual_sha3_256_hash_of_ciphertext);
    let shared_secret = hex::decode("e7184a0975ee3470878d2d159ec83129c8aec253d4ee17b4810311d198cd0368")?;
    assert_eq!(shared_secret, actual_shared_secret);

    // Exercise decapsulation, and assert consistency
    let mut shared_secret2 = [0u8; 32];
    let r = crate::mlkem::decapsulate(&mut k, &cipher_text, &mut shared_secret2);
    if r != Error::NoError {
        return Err(Box::new(r))
    }
    assert_eq!(shared_secret2, actual_shared_secret);

    // Functional test -- should roundtrip!
    let mut k = crate::key::key_allocate(crate::key::Params::MlKem768)?;
    crate::mlkem::key_generate(&mut k, 0);
    let mut secret = [0u8; 32];
    let mut cipher = [0u8; 1088];
    crate::mlkem::encapsulate(&mut k, &mut secret, &mut cipher);

    let mut secret2 = [0u8; 32];
    crate::mlkem::decapsulate(&mut k, &cipher, &mut secret2);
    assert_eq!(secret, secret2);

    // Perf test -- simplistic
    let mut k = crate::key::key_allocate(crate::key::Params::MlKem768)?;
    for i in 0..1000u32 {
        crate::mlkem::key_generate(&mut k, 0);
        let mut secret = [(i % 256) as u8; 32];
        let mut cipher = [0u8; 1088];
        crate::mlkem::encapsulate(&mut k, &mut secret, &mut cipher);

        let mut secret2 = [(i % 256) as u8; 32];
        crate::mlkem::decapsulate(&mut k, &cipher, &mut secret2);
        assert_eq!(secret, secret2);
    }


    Ok(())
}
