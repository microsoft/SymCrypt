use assert_hex::assert_eq_hex;
use rand::RngCore;

use super::*;
use crate::block_cipher::BlockCipher;

// For testing, we link to the SymCrypt C implementation and use it to compare our implementation
extern "C" {
    pub fn SymCryptAesExpandKey(
        key: *mut CSymCryptAesExpandedKey,
        pb_key: *const u8,
        cb_key: usize,
    ) -> Error;
    pub fn SymCryptAesEncrypt(
        key: *const CSymCryptAesExpandedKey,
        pb_src: *const u8,
        pb_dst: *mut u8,
    );
    pub fn SymCryptAesDecrypt(
        key: *const CSymCryptAesExpandedKey,
        pb_src: *const u8,
        pb_dst: *mut u8,
    );
}

#[cfg(test)]
#[no_mangle]
pub extern "C" fn SymCryptSaveYmm(_save_data: *mut u8) {
    // Not used for now, just required for linking
}

#[cfg(test)]
#[no_mangle]
pub extern "C" fn SymCryptRestoreYmm(_save_data: *mut u8) {
    // Not used for now, just required for linking
}

#[test]
fn test_aes_128() {
    crate::common::init();

    let mut key: [u8; 16] = [0; 16];
    let mut expanded_key = CSymCryptAesExpandedKey::new(16).unwrap();
    let result = unsafe {
        SymCryptAesExpandKey(
            expanded_key.as_mut().get_unchecked_mut(),
            key.as_ptr(),
            key.len(),
        )
    };
    assert_eq!(result, Error::NoError);

    let mut my_expanded_key = AesExpandedKey::<16>::zeroed().unwrap();
    my_expanded_key.expand_key(&key).unwrap();

    for i in 0..(my_expanded_key.inner.num_rounds() * 2 + 1) {
        assert_eq_hex!(
            &expanded_key.as_ref().round_keys[i],
            &my_expanded_key.inner.round_keys[i],
            "Round key {} mismatch",
            i
        );
    }

    let mut rng = rand::rng();

    for _ in 0..5 {
        rng.fill_bytes(&mut key);
        let result = unsafe {
            SymCryptAesExpandKey(
                expanded_key.as_mut().get_unchecked_mut(),
                key.as_ptr(),
                key.len(),
            )
        };
        assert_eq!(result, Error::NoError);

        my_expanded_key.expand_key(&key).unwrap();

        for i in 0..(my_expanded_key.inner.num_rounds() * 2 + 1) {
            assert_eq_hex!(
                &expanded_key.as_ref().round_keys[i],
                &my_expanded_key.inner.round_keys[i],
                "Round key {} mismatch",
                i
            );
        }

        let mut plaintext = [0u8; 16];
        rng.fill_bytes(&mut plaintext);

        let mut block_a = plaintext;
        let mut block_b = plaintext;

        unsafe {
            SymCryptAesEncrypt(
                expanded_key.as_ref().get_ref(),
                block_a.as_ptr(),
                block_a.as_mut_ptr(),
            )
        };

        <Aes as BlockCipher<16, 16>>::encrypt_block_in_place(&my_expanded_key, &mut block_b);

        assert_eq_hex!(&block_a, &block_b, "AES encryption mismatch");

        unsafe {
            SymCryptAesDecrypt(
                expanded_key.as_ref().get_ref(),
                block_a.as_ptr(),
                block_a.as_mut_ptr(),
            )
        };

        <Aes as BlockCipher<16, 16>>::decrypt_block_in_place(&my_expanded_key, &mut block_b);

        assert_eq_hex!(&block_a, &block_b, "AES decryption mismatch");

        assert_eq_hex!(
            &block_b,
            &plaintext,
            "AES decrypt(encrypt(plaintext)) != plaintext"
        );
    }
}

#[test]
fn test_aes_192() {
    crate::common::init();

    let mut key: [u8; 24] = [0; 24];
    let mut expanded_key = CSymCryptAesExpandedKey::new(24).unwrap();
    let result = unsafe {
        SymCryptAesExpandKey(
            expanded_key.as_mut().get_unchecked_mut(),
            key.as_ptr(),
            key.len(),
        )
    };
    assert_eq!(result, Error::NoError);

    let mut my_expanded_key = AesExpandedKey::<24>::zeroed().unwrap();
    my_expanded_key.expand_key(&key).unwrap();

    for i in 0..(my_expanded_key.inner.num_rounds() * 2 + 1) {
        assert_eq_hex!(
            &expanded_key.as_ref().round_keys[i],
            &my_expanded_key.inner.round_keys[i],
            "Round key {} mismatch",
            i
        );
    }

    let mut rng = rand::rng();

    for _ in 0..5 {
        rng.fill_bytes(&mut key);
        let result = unsafe {
            SymCryptAesExpandKey(
                expanded_key.as_mut().get_unchecked_mut(),
                key.as_ptr(),
                key.len(),
            )
        };
        assert_eq!(result, Error::NoError);

        my_expanded_key.expand_key(&key).unwrap();

        for i in 0..(my_expanded_key.inner.num_rounds() * 2 + 1) {
            assert_eq_hex!(
                &expanded_key.as_ref().round_keys[i],
                &my_expanded_key.inner.round_keys[i],
                "Round key {} mismatch",
                i
            );
        }

        let mut plaintext = [0u8; 16];
        rng.fill_bytes(&mut plaintext);

        let mut block_a = plaintext;
        let mut block_b = plaintext;

        unsafe {
            SymCryptAesEncrypt(
                expanded_key.as_ref().get_ref(),
                block_a.as_ptr(),
                block_a.as_mut_ptr(),
            )
        };

        <Aes as BlockCipher<16, 24>>::encrypt_block_in_place(&my_expanded_key, &mut block_b);

        assert_eq_hex!(&block_a, &block_b, "AES encryption mismatch");

        unsafe {
            SymCryptAesDecrypt(
                expanded_key.as_ref().get_ref(),
                block_a.as_ptr(),
                block_a.as_mut_ptr(),
            )
        };

        <Aes as BlockCipher<16, 24>>::decrypt_block_in_place(&my_expanded_key, &mut block_b);

        assert_eq_hex!(&block_a, &block_b, "AES decryption mismatch");

        assert_eq_hex!(
            &block_b,
            &plaintext,
            "AES decrypt(encrypt(plaintext)) != plaintext"
        );
    }
}

#[test]
fn test_aes_256() {
    crate::common::init();

    let mut key: [u8; 32] = [0; 32];
    let mut expanded_key = CSymCryptAesExpandedKey::new(32).unwrap();
    let result = unsafe {
        SymCryptAesExpandKey(
            expanded_key.as_mut().get_unchecked_mut(),
            key.as_ptr(),
            key.len(),
        )
    };
    assert_eq!(result, Error::NoError);

    let mut my_expanded_key = AesExpandedKey::<32>::zeroed().unwrap();
    my_expanded_key.expand_key(&key).unwrap();

    for i in 0..(my_expanded_key.inner.num_rounds() * 2 + 1) {
        assert_eq_hex!(
            &expanded_key.as_ref().round_keys[i],
            &my_expanded_key.inner.round_keys[i],
            "Round key {} mismatch",
            i
        );
    }

    let mut rng = rand::rng();

    for _ in 0..5 {
        rng.fill_bytes(&mut key);
        let result = unsafe {
            SymCryptAesExpandKey(
                expanded_key.as_mut().get_unchecked_mut(),
                key.as_ptr(),
                key.len(),
            )
        };
        assert_eq!(result, Error::NoError);

        my_expanded_key.expand_key(&key).unwrap();

        for i in 0..(my_expanded_key.inner.num_rounds() * 2 + 1) {
            assert_eq_hex!(
                &expanded_key.as_ref().round_keys[i],
                &my_expanded_key.inner.round_keys[i],
                "Round key {} mismatch",
                i
            );
        }

        let mut plaintext = [0u8; 16];
        rng.fill_bytes(&mut plaintext);

        let mut block_a = plaintext;
        let mut block_b = plaintext;

        unsafe {
            SymCryptAesEncrypt(
                expanded_key.as_ref().get_ref(),
                block_a.as_ptr(),
                block_a.as_mut_ptr(),
            )
        };

        <Aes as BlockCipher<16, 32>>::encrypt_block_in_place(&my_expanded_key, &mut block_b);

        assert_eq_hex!(&block_a, &block_b, "AES encryption mismatch");

        unsafe {
            SymCryptAesDecrypt(
                expanded_key.as_ref().get_ref(),
                block_a.as_ptr(),
                block_a.as_mut_ptr(),
            )
        };

        <Aes as BlockCipher<16, 32>>::decrypt_block_in_place(&my_expanded_key, &mut block_b);

        assert_eq_hex!(&block_a, &block_b, "AES decryption mismatch");

        assert_eq_hex!(
            &block_b,
            &plaintext,
            "AES decrypt(encrypt(plaintext)) != plaintext"
        );
    }
}

/// Throwaway micro-benchmarks... Calling C via FFI may be unfair.

#[test]
fn test_aes128_module_functions() {
    // Test vector from NIST FIPS 197
    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    ];

    let plaintext: [u8; 16] = [
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
    ];

    let expected_ciphertext: [u8; 16] = [
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
    ];

    // Create expanded key using aes128::new
    let expanded_key = aes128::new(&key);

    // Test aes128::encrypt_block
    let mut ciphertext = [0u8; 16];
    aes128::encrypt_block(&expanded_key, &plaintext, &mut ciphertext);
    assert_eq!(
        ciphertext, expected_ciphertext,
        "aes128::encrypt_block failed"
    );

    // Test aes128::decrypt_block
    let mut decrypted = [0u8; 16];
    aes128::decrypt_block(&expanded_key, &ciphertext, &mut decrypted);
    assert_eq!(decrypted, plaintext, "aes128::decrypt_block failed");

    // Test aes128::encrypt_block_in_place
    let mut block = plaintext;
    aes128::encrypt_block_in_place(&expanded_key, &mut block);
    assert_eq!(
        block, expected_ciphertext,
        "aes128::encrypt_block_in_place failed"
    );

    // Test aes128::decrypt_block_in_place
    aes128::decrypt_block_in_place(&expanded_key, &mut block);
    assert_eq!(block, plaintext, "aes128::decrypt_block_in_place failed");
}
