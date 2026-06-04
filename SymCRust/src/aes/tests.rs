use assert_hex::assert_eq_hex;
use libc::c_void;
use rand::RngCore;
use std::vec;

use super::*;
use crate::block_cipher::BlockCipher;
use crate::common::InPlaceOrDisjointBuffer;

#[repr(C)]
enum BlockCipherId {
    NULL = 0,
    AES = 1,
    DES = 2,
    TripleDES = 3,
    DESX = 4,
    RC2 = 5,
}

// For testing, we link to the SymCrypt C implementation and use it to compare our implementation
extern "C" {
    fn SymCryptAesExpandKey(
        key: *mut CSymCryptAesExpandedKey,
        pb_key: *const u8,
        cb_key: usize,
    ) -> Error;
    fn SymCryptAesEncrypt(key: *const CSymCryptAesExpandedKey, pb_src: *const u8, pb_dst: *mut u8);
    fn SymCryptAesDecrypt(key: *const CSymCryptAesExpandedKey, pb_src: *const u8, pb_dst: *mut u8);
    fn SymCryptCtrMsb32(
        p_block_cipher: *const c_void,
        p_expanded_key: *const CSymCryptAesExpandedKey,
        pb_chaining_value: *mut u8,
        pb_src: *const u8,
        pb_dst: *mut u8,
        cb_data: usize,
    );
    fn SymCryptGetBlockCipher(block_cipher_id: BlockCipherId) -> *const c_void;
    fn SymCryptAesGcmEncryptStitchedXmm(
        p_expanded_key: *const CSymCryptAesExpandedKey,
        pb_chaining_value: *mut u8,
        expanded_key_table: *const u128,
        p_state: *mut u128,
        pb_src: *const u8,
        pb_dst: *mut u8,
        cb_data: usize,
    );
    fn SymCryptAesGcmDecryptStitchedXmm(
        p_expanded_key: *const CSymCryptAesExpandedKey,
        pb_chaining_value: *mut u8,
        expanded_key_table: *const u128,
        p_state: *mut u128,
        pb_src: *const u8,
        pb_dst: *mut u8,
        cb_data: usize,
    );
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

    let mut my_expanded_key = AesExpandedKey::new(&key);

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

        my_expanded_key.expand_key(&key);

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

    let mut my_expanded_key = AesExpandedKey::new(&key);

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

        my_expanded_key.expand_key(&key);

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

    let mut my_expanded_key = AesExpandedKey::new(&key);

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

        my_expanded_key.expand_key(&key);

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

#[test]
fn test_ctr_msb_32() {
    crate::common::init();

    let mut key = [0u8; 16];
    let mut src = [0u8; 64];

    let mut rng = rand::rng();

    for _i in 0..5 {
        let mut expanded_key = CSymCryptAesExpandedKey::new(16).unwrap();

        unsafe {
            let result = SymCryptAesExpandKey(
                expanded_key.as_mut().get_unchecked_mut(),
                key.as_ptr(),
                key.len(),
            );
            assert_eq!(result, Error::NoError);

            let aes_block_cipher = SymCryptGetBlockCipher(BlockCipherId::AES);

            let mut chaining_value = [0u8; AES_BLOCK_SIZE];
            let mut dst = [0u8; 64];
            SymCryptCtrMsb32(
                aes_block_cipher,
                expanded_key.as_ref().get_ref(),
                chaining_value.as_mut_ptr(),
                src.as_ptr(),
                dst.as_mut_ptr(),
                src.len(),
            );

            let mut chaining_value_2 = [0u8; AES_BLOCK_SIZE];
            let mut dst_2 = [0u8; 64];
            aes_gcm::ctr_msb_32::<AES_BLOCK_SIZE, 16, Aes>(
                &AesExpandedKey::new(&key),
                &mut chaining_value_2,
                &src,
                &mut dst_2,
            );

            assert_eq_hex!(
                &chaining_value,
                &chaining_value_2,
                "CTR MSB32 chaining value mismatch"
            );
            assert_eq_hex!(&dst, &dst_2, "CTR MSB32 output mismatch");
        }

        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut src);
    }
}

#[test]
fn test_aes128_module_functions() {
    // Test vector from NIST FIPS 197
    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    let plaintext: [u8; 16] = [
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07,
        0x34,
    ];

    let expected_ciphertext: [u8; 16] = [
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b,
        0x32,
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

#[cfg(all(test, target_arch = "x86_64"))]
mod gcm_stitched_tests {
    use rand::Rng;

    use super::*;

    #[test]
    fn test_gcm_encrypt_disjoint() {
        crate::common::init();

        let mut rng = rand::rng();

        // Generate random key (AES-128)
        for _ in 0..5 {
            let mut key = [0u8; 16];
            rng.fill_bytes(&mut key);

            // Expand AES key using C implementation
            let mut c_expanded_key = CSymCryptAesExpandedKey::new(16).unwrap();
            let result = unsafe {
                SymCryptAesExpandKey(
                    c_expanded_key.as_mut().get_unchecked_mut(),
                    key.as_ptr(),
                    key.len(),
                )
            };
            assert_eq!(result, Error::NoError);

            // Expand AES key using Rust implementation
            let rust_expanded_key = AesExpandedKey::new(&key);

            // Generate random H value for GHASH
            let mut h_bytes = [0u8; 16];
            rng.fill_bytes(&mut h_bytes);

            // Expand GHASH key
            let ghash_key = ghash::GHashExpandedKey::from(&h_bytes);

            // Generate random chaining value (counter)
            let mut c_chaining_value = [0u8; 16];
            rng.fill_bytes(&mut c_chaining_value);
            let mut rust_chaining_value = c_chaining_value;

            // Initialize GHASH state
            let mut c_ghash_state = 0u128;
            let mut rust_ghash_state = 0u128;

            // Generate random plaintext
            let buffer_size = rng.random_range(1..64) * 16;
            let mut plaintext = vec![0u8; buffer_size];
            rng.fill_bytes(&mut plaintext);

            // Prepare output buffers
            let mut c_ciphertext = vec![0u8; buffer_size];
            let mut rust_ciphertext = vec![0u8; buffer_size];

            // Call C implementation
            unsafe {
                SymCryptAesGcmEncryptStitchedXmm(
                    c_expanded_key.as_ref().get_ref(),
                    c_chaining_value.as_mut_ptr(),
                    ghash_key.as_slice().as_ptr(),
                    core::ptr::from_mut(&mut c_ghash_state),
                    plaintext.as_ptr(),
                    c_ciphertext.as_mut_ptr(),
                    buffer_size,
                );
            }

            // Call Rust implementation
            let rust_buffer =
                InPlaceOrDisjointBuffer::new_disjoint_from_slices(&plaintext, &mut rust_ciphertext);

            aes_xmm::AesXmmImpl::gcm_encrypt_stitched::<11>(
                &rust_expanded_key.inner,
                &mut rust_chaining_value,
                &ghash_key,
                &mut rust_ghash_state,
                rust_buffer,
            );

            // Compare results
            assert_eq_hex!(
                &rust_ciphertext,
                &c_ciphertext,
                "Ciphertext mismatch for buffer size {}",
                buffer_size
            );

            assert_eq_hex!(
                &rust_chaining_value,
                &c_chaining_value,
                "Chaining value mismatch for buffer size {}",
                buffer_size
            );

            assert_eq_hex!(
                rust_ghash_state,
                c_ghash_state,
                "GHASH state mismatch for buffer size {}",
                buffer_size
            );
        }
    }

    /// Test helper function to compare Rust implementation against C implementation
    fn test_gcm_encrypt_stitched_with_size(buffer_size: usize) {
        crate::common::init();

        let mut rng = rand::rng();

        // Generate random key (AES-128)
        let mut key = [0u8; 16];
        rng.fill_bytes(&mut key);

        // Expand AES key using C implementation
        let mut c_expanded_key = CSymCryptAesExpandedKey::new(16).unwrap();
        let result = unsafe {
            SymCryptAesExpandKey(
                c_expanded_key.as_mut().get_unchecked_mut(),
                key.as_ptr(),
                key.len(),
            )
        };
        assert_eq!(result, Error::NoError);

        // Expand AES key using Rust implementation
        let rust_expanded_key = AesExpandedKey::new(&key);

        // Generate random H value for GHASH
        let mut h_bytes = [0u8; 16];
        rng.fill_bytes(&mut h_bytes);

        // Expand GHASH key
        let ghash_key = ghash::GHashExpandedKey::from(&h_bytes);

        // Generate random chaining value (counter)
        let mut c_chaining_value = [0u8; 16];
        rng.fill_bytes(&mut c_chaining_value);
        let mut rust_chaining_value = c_chaining_value;

        // Initialize GHASH state
        let mut c_ghash_state = 0u128;
        let mut rust_ghash_state = 0u128;

        // Generate random plaintext
        let mut plaintext = vec![0u8; buffer_size];
        rng.fill_bytes(&mut plaintext);

        // Prepare output buffers
        let mut c_ciphertext = vec![0u8; buffer_size];
        let mut rust_ciphertext = vec![0u8; buffer_size];

        // Call C implementation
        unsafe {
            SymCryptAesGcmEncryptStitchedXmm(
                c_expanded_key.as_ref().get_ref(),
                c_chaining_value.as_mut_ptr(),
                ghash_key.as_slice().as_ptr(),
                core::ptr::from_mut(&mut c_ghash_state),
                plaintext.as_ptr(),
                c_ciphertext.as_mut_ptr(),
                buffer_size,
            );
        }

        // Call Rust implementation
        let rust_buffer =
            InPlaceOrDisjointBuffer::new_disjoint_from_slices(&plaintext, &mut rust_ciphertext);

        aes_xmm::AesXmmImpl::gcm_encrypt_stitched::<11>(
            &rust_expanded_key.inner,
            &mut rust_chaining_value,
            &ghash_key,
            &mut rust_ghash_state,
            rust_buffer,
        );

        // Compare results
        assert_eq_hex!(
            &rust_ciphertext,
            &c_ciphertext,
            "Ciphertext mismatch for buffer size {}",
            buffer_size
        );

        assert_eq_hex!(
            &rust_chaining_value,
            &c_chaining_value,
            "Chaining value mismatch for buffer size {}",
            buffer_size
        );

        assert_eq_hex!(
            rust_ghash_state,
            c_ghash_state,
            "GHASH state mismatch for buffer size {}",
            buffer_size
        );
    }

    #[test]
    fn test_gcm_encrypt_stitched_0_blocks() {
        test_gcm_encrypt_stitched_with_size(0);
    }

    #[test]
    fn test_gcm_encrypt_stitched_1_block() {
        test_gcm_encrypt_stitched_with_size(16);
    }

    #[test]
    fn test_gcm_encrypt_stitched_7_blocks() {
        test_gcm_encrypt_stitched_with_size(7 * 16);
    }

    #[test]
    fn test_gcm_encrypt_stitched_8_blocks() {
        test_gcm_encrypt_stitched_with_size(8 * 16);
    }

    #[test]
    fn test_gcm_encrypt_stitched_9_blocks() {
        test_gcm_encrypt_stitched_with_size(9 * 16);
    }

    #[test]
    fn test_gcm_encrypt_stitched_15_blocks() {
        test_gcm_encrypt_stitched_with_size(15 * 16);
    }

    #[test]
    fn test_gcm_encrypt_stitched_16_blocks() {
        test_gcm_encrypt_stitched_with_size(16 * 16);
    }

    #[test]
    fn test_gcm_encrypt_stitched_17_blocks() {
        test_gcm_encrypt_stitched_with_size(17 * 16);
    }

    #[test]
    fn test_gcm_encrypt_stitched_31_blocks() {
        test_gcm_encrypt_stitched_with_size(31 * 16);
    }

    #[test]
    fn test_gcm_encrypt_stitched_32_blocks() {
        test_gcm_encrypt_stitched_with_size(32 * 16);
    }

    #[test]
    fn test_gcm_encrypt_stitched_33_blocks() {
        test_gcm_encrypt_stitched_with_size(33 * 16);
    }

    #[test]
    fn test_gcm_encrypt_stitched_127_blocks() {
        test_gcm_encrypt_stitched_with_size(127 * 16);
    }

    #[test]
    fn test_gcm_encrypt_stitched_128_blocks() {
        test_gcm_encrypt_stitched_with_size(128 * 16);
    }

    #[test]
    fn test_gcm_encrypt_stitched_129_blocks() {
        test_gcm_encrypt_stitched_with_size(129 * 16);
    }

    #[test]
    fn test_gcm_encrypt_stitched_1024_blocks() {
        test_gcm_encrypt_stitched_with_size(1024 * 16);
    }

    #[test]
    fn test_gcm_encrypt_stitched_random_sizes() {
        use rand::Rng;
        let mut rng = rand::rng();
        for _ in 0..10 {
            let num_blocks = (rng.random::<u8>() as usize) % 256;
            test_gcm_encrypt_stitched_with_size(num_blocks * 16);
        }
    }

    /// Test helper function to compare Rust implementation against C implementation for decryption
    fn test_gcm_decrypt_stitched_with_size(buffer_size: usize) {
        crate::common::init();

        let mut rng = rand::rng();

        // Generate random key (AES-128)
        let mut key = [0u8; 16];
        rng.fill_bytes(&mut key);

        // Expand AES key using C implementation
        let mut c_expanded_key = CSymCryptAesExpandedKey::new(16).unwrap();
        let result = unsafe {
            SymCryptAesExpandKey(
                c_expanded_key.as_mut().get_unchecked_mut(),
                key.as_ptr(),
                key.len(),
            )
        };
        assert_eq!(result, Error::NoError);

        // Expand AES key using Rust implementation
        let rust_expanded_key = AesExpandedKey::new(&key);

        // Generate random H value for GHASH
        let mut h_bytes = [0u8; 16];
        rng.fill_bytes(&mut h_bytes);

        // Expand GHASH key
        let ghash_key = ghash::GHashExpandedKey::from(&h_bytes);

        // Generate random chaining value (counter)
        let mut c_chaining_value = [0u8; 16];
        rng.fill_bytes(&mut c_chaining_value);
        let mut rust_chaining_value = c_chaining_value;

        // Initialize GHASH state
        let mut c_ghash_state = 0u128;
        let mut rust_ghash_state = 0u128;

        // Generate random ciphertext
        let mut ciphertext = vec![0u8; buffer_size];
        rng.fill_bytes(&mut ciphertext);

        // Prepare output buffers
        let mut c_plaintext = vec![0u8; buffer_size];
        let mut rust_plaintext = vec![0u8; buffer_size];

        // Call C implementation
        unsafe {
            SymCryptAesGcmDecryptStitchedXmm(
                c_expanded_key.as_ref().get_ref(),
                c_chaining_value.as_mut_ptr(),
                ghash_key.as_slice().as_ptr(),
                core::ptr::from_mut(&mut c_ghash_state),
                ciphertext.as_ptr(),
                c_plaintext.as_mut_ptr(),
                buffer_size,
            );
        }

        // Call Rust implementation
        let rust_buffer =
            InPlaceOrDisjointBuffer::new_disjoint_from_slices(&ciphertext, &mut rust_plaintext);

        aes_xmm::AesXmmImpl::gcm_decrypt_stitched::<11>(
            &rust_expanded_key.inner,
            &mut rust_chaining_value,
            &ghash_key,
            &mut rust_ghash_state,
            rust_buffer,
        );

        // Compare results
        assert_eq_hex!(
            &rust_plaintext,
            &c_plaintext,
            "Plaintext mismatch for buffer size {}",
            buffer_size
        );

        assert_eq_hex!(
            &rust_chaining_value,
            &c_chaining_value,
            "Chaining value mismatch for buffer size {}",
            buffer_size
        );

        assert_eq_hex!(
            rust_ghash_state,
            c_ghash_state,
            "GHASH state mismatch for buffer size {}",
            buffer_size
        );
    }

    #[test]
    fn test_gcm_decrypt_stitched_0_blocks() {
        test_gcm_decrypt_stitched_with_size(0);
    }

    #[test]
    fn test_gcm_decrypt_stitched_1_block() {
        test_gcm_decrypt_stitched_with_size(16);
    }

    #[test]
    fn test_gcm_decrypt_stitched_7_blocks() {
        test_gcm_decrypt_stitched_with_size(7 * 16);
    }

    #[test]
    fn test_gcm_decrypt_stitched_8_blocks() {
        test_gcm_decrypt_stitched_with_size(8 * 16);
    }

    #[test]
    fn test_gcm_decrypt_stitched_9_blocks() {
        test_gcm_decrypt_stitched_with_size(9 * 16);
    }

    #[test]
    fn test_gcm_decrypt_stitched_15_blocks() {
        test_gcm_decrypt_stitched_with_size(15 * 16);
    }

    #[test]
    fn test_gcm_decrypt_stitched_16_blocks() {
        test_gcm_decrypt_stitched_with_size(16 * 16);
    }

    #[test]
    fn test_gcm_decrypt_stitched_17_blocks() {
        test_gcm_decrypt_stitched_with_size(17 * 16);
    }

    #[test]
    fn test_gcm_decrypt_stitched_31_blocks() {
        test_gcm_decrypt_stitched_with_size(31 * 16);
    }

    #[test]
    fn test_gcm_decrypt_stitched_32_blocks() {
        test_gcm_decrypt_stitched_with_size(32 * 16);
    }

    #[test]
    fn test_gcm_decrypt_stitched_33_blocks() {
        test_gcm_decrypt_stitched_with_size(33 * 16);
    }

    #[test]
    fn test_gcm_decrypt_stitched_127_blocks() {
        test_gcm_decrypt_stitched_with_size(127 * 16);
    }

    #[test]
    fn test_gcm_decrypt_stitched_128_blocks() {
        test_gcm_decrypt_stitched_with_size(128 * 16);
    }

    #[test]
    fn test_gcm_decrypt_stitched_129_blocks() {
        test_gcm_decrypt_stitched_with_size(129 * 16);
    }

    #[test]
    fn test_gcm_decrypt_stitched_1024_blocks() {
        test_gcm_decrypt_stitched_with_size(1024 * 16);
    }

    #[test]
    fn test_gcm_decrypt_stitched_random_sizes() {
        use rand::Rng;
        let mut rng = rand::rng();
        for _ in 0..10 {
            let num_blocks = (rng.random::<u8>() as usize) % 256;
            test_gcm_decrypt_stitched_with_size(num_blocks * 16);
        }
    }
}
