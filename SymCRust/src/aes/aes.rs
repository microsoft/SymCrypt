//
// aes.rs  SymCrypt Rust AES implementation
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#[cfg(target_arch = "x86")]
compile_error!(
    "SymCRust AES does not support x86. Use the C SymCrypt implementation instead."
);

use alloc::boxed::Box;
use core::ops::Drop;
use core::pin::Pin;
use core::ptr::addr_of;
use libc::size_t;

use crate::block_cipher::{BlockCipher, BlockCipherExpandedKey};
use crate::common::{wipe_slice, Error, InPlaceOrDisjointBuffer};
use crate::symcryptcommon::symcrypt_magic_value;

mod aes_gcm;
#[cfg(all(
    target_arch = "aarch64",
    target_feature = "aes",
    target_feature = "neon"
))]
mod aes_neon;
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "x86"),
    all(
        target_feature = "aes",
        target_feature = "pclmulqdq",
        target_feature = "ssse3"
    )
))]
mod aes_xmm;
#[cfg(all(feature = "ffi", not(any(feature = "benchmarking", test))))]
mod ffi;
#[path = "ghash/ghash.rs"]
mod ghash;
#[cfg(all(test, not(feature = "benchmarking")))]
mod tests;

/// Specifies how an AES key will be used for encryption and/or decryption operations.
/// Some algorithms use AES for encryption only, allowing us to optimize key expansion by omitting
/// the decryption round keys. Currently this is not used in the Rust code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesKeyUsage {
    _EncryptOnly, // Currently unused
    EncryptAndDecrypt,
}

/// AES block size in bytes.
const AES_BLOCK_SIZE: usize = 16;

/// Sealed trait pattern to restrict valid AES key sizes at compile time.
/// Only 128-bit (16 bytes), 192-bit (24 bytes), and 256-bit (32 bytes) keys are valid.
mod sealed {
    pub trait ValidKeySize {}
    impl ValidKeySize for [(); 16] {}
    impl ValidKeySize for [(); 24] {}
    impl ValidKeySize for [(); 32] {}
}

/// Rust representation of the C `SymCryptAesExpandedKey` structure. This structure is only intended
/// to be used via FFI and internally in this module. Rust callers should use `AesExpandedKey`.
/// Must be pinned in memory to maintain pointer validity.
#[derive(Debug, Default)]
#[cfg_attr(any(target_arch = "x86_64", target_arch = "aarch64"), repr(align(16)))]
#[cfg_attr(any(target_arch = "arm"), repr(align(8)))]
#[cfg_attr(any(target_arch = "x86"), repr(align(4)))]
#[repr(C)]
struct CSymCryptAesExpandedKey {
    /// Round keys, first the encryption round keys in encryption order, followed by the decryption
    /// round keys in decryption order. The first decryption round key is the last encryption round
    /// key. AES-256 has 14 rounds and thus 15 round keys for encryption and 15 for decryption. As
    /// they share one round key, we need room for 29. Each round key is 16 bytes, representing a
    /// 4x4 matrix of bytes in row-major order. In C we represent this as a 2D array, but in Rust
    /// it's more convenient to represent it as a flat array since we cannot cast between 2D and
    /// flat arrays without using `unsafe`.
    round_keys: [[u8; AES_BLOCK_SIZE]; 29],
    last_enc_round_key: *const [u8; AES_BLOCK_SIZE],
    last_dec_round_key: *const [u8; AES_BLOCK_SIZE],
    magic: size_t,
}

/// Wrapper structure for AES expanded key that pins the inner C structure in memory.
pub struct AesExpandedKey<const KEY_SIZE: usize> {
    inner: Pin<Box<CSymCryptAesExpandedKey>>,
}

/// Trait for architecture-specific AES implementations
trait AesImpl {
    /// Performs 4 AES S-box lookups on a u32 word.
    fn sbox_lookup_u32(input: u32) -> u32;

    /// Creates a decryption round key from the corresponding encryption round key
    fn create_decryption_round_key(enc_round_key: &[u8; AES_BLOCK_SIZE]) -> [u8; AES_BLOCK_SIZE];

    /// Encrypt a single block. `input_buffer` is optional; when doing out-of-place encryption it
    /// can be used to provide the plaintext input, which will be encrypted into `output_buffer`.
    /// For in-place encryption, `input_buffer` can be `None`, and the plaintext is read from, and
    /// the ciphertext written back to, `output_buffer`.
    fn encrypt_block<const KEY_ROUNDS: usize>(
        expanded_key: &CSymCryptAesExpandedKey,
        input_buffer: Option<&[u8; 16]>,
        output_buffer: &mut [u8; 16],
    );

    /// Decrypt a single block. `input_buffer` is optional; when doing out-of-place decryption it
    /// can be used to provide the ciphertext input, which will be decrypted into `output_buffer`.
    /// For in-place decryption, `input_buffer` can be `None`, and the ciphertext is read from, and
    /// the plaintext written back to, `output_buffer`.
    fn decrypt_block<const KEY_ROUNDS: usize>(
        expanded_key: &CSymCryptAesExpandedKey,
        input_buffer: Option<&[u8; 16]>,
        output_buffer: &mut [u8; 16],
    );
}

/// Trait for architecture-specific AES-GCM implementations
trait AesGcmImpl {
    /// Perform "stitched" AES-GCM encryption, i.e. encryption where the GHASH computations are
    /// interleaved with the AES encryption operations for better performance.
    fn gcm_encrypt_stitched<const KEY_ROUNDS: usize>(
        expanded_key: &CSymCryptAesExpandedKey,
        chaining_value: &mut [u8; AES_BLOCK_SIZE],
        ghash_expanded_key: &ghash::GHashExpandedKey,
        ghash_state: &mut u128,
        buffer: InPlaceOrDisjointBuffer<u8>,
    );

    /// Perform "stitched" AES-GCM decryption, i.e. decryption where the GHASH computations are
    /// interleaved with the AES decryption operations for better performance.
    fn gcm_decrypt_stitched<const KEY_ROUNDS: usize>(
        expanded_key: &CSymCryptAesExpandedKey,
        chaining_value: &mut [u8; AES_BLOCK_SIZE],
        ghash_expanded_key: &ghash::GHashExpandedKey,
        ghash_state: &mut u128,
        buffer: InPlaceOrDisjointBuffer<u8>,
    );
}

/// Architecture-specific AES implementation type for x86/x86_64 platforms.
/// Uses XMM (PCLMULQDQ/AES-NI) instructions.
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "x86"),
    all(
        target_feature = "aes",
        target_feature = "pclmulqdq",
        target_feature = "ssse3"
    )
))]
type AesImplType = aes_xmm::AesXmmImpl;

/// Architecture-specific AES implementation type for aarch64 platforms.
/// Uses NEON instructions.
#[cfg(all(
    target_arch = "aarch64",
    target_feature = "aes",
    target_feature = "neon"
))]
type AesImplType = aes_neon::AesNeonImpl;

/// Zero-sized type representing the AES block cipher algorithm.
pub struct Aes;

/// Get the number of round keys for this AES key (= number of rounds + 1)
#[inline]
const fn key_rounds(key_size: usize) -> usize {
    match key_size {
        16 => 11, // AES-128
        24 => 13, // AES-192
        32 => 15, // AES-256
        _ => panic!("Invalid AES key size"),
    }
}
/// Get the number of rounds for this AES key, which corresponds to the key size
#[inline]
const fn num_rounds_from_key_size(key_size: usize) -> Result<usize, Error> {
    match key_size {
        16 => Ok(10),
        24 => Ok(12),
        32 => Ok(14),
        _ => Err(Error::WrongKeySize),
    }
}

/// Get the key size in bytes from the number of rounds
#[inline]
const fn key_size_from_num_rounds(num_rounds: usize) -> Result<usize, Error> {
    match num_rounds {
        10 => Ok(16),
        12 => Ok(24),
        14 => Ok(32),
        _ => Err(Error::WrongKeySize),
    }
}

impl CSymCryptAesExpandedKey {
    /// Creates a new `CSymCryptAesExpandedKey` with the specified key size.
    ///
    /// # Arguments
    /// * `key_size` - Size of the AES key in bytes (16, 24, or 32)
    ///
    /// # Returns
    /// A pinned boxed expanded key structure, or an error if the key size is invalid.
    ///
    /// # Errors
    /// Returns `Error::WrongKeySize` if `key_size` is not 16, 24, or 32.
    pub fn new(key_size: usize) -> Result<Pin<Box<Self>>, Error> {
        if ![16, 24, 32].contains(&key_size) {
            return Err(Error::WrongKeySize);
        }

        let temp = CSymCryptAesExpandedKey::default();

        let mut pinned = Box::pin(temp);

        pinned.as_mut().set_pointers_and_magic(key_size)?;

        Ok(pinned)
    }

    /// Get the number of rounds for this AES key. Because this value is not stored directly in
    /// the structure (due to C ABI compatibility requirements), we compute it from the round key
    /// pointers.
    #[inline]
    pub fn num_rounds(&self) -> usize {
        let base_addr = addr_of!(*self) as usize;
        let last_enc_addr = self.last_enc_round_key as usize;
        let rounds = (last_enc_addr - base_addr) / core::mem::size_of::<[u8; 16]>();

        assert!(
            [10, 12, 14].contains(&rounds),
            "Invalid number of rounds computed."
        );
        rounds
    }

    /// Get the key size in bytes for this AES key. There is a 1:1 correspondence between key size
    /// and number of rounds, so we calculate the key size based on the number of rounds.
    #[inline]
    pub fn key_size(&self) -> usize {
        key_size_from_num_rounds(self.num_rounds()).unwrap()
    }

    /// Sets internal pointers and magic value for the expanded key structure. Required for
    /// FFI compatibility. Must be called after initialization to properly configure the key for
    /// the given size.
    ///
    /// # Arguments
    /// * `key_size` - Size of the AES key in bytes
    ///
    /// # Errors
    /// Returns an error if the key size is invalid.
    #[inline]
    pub(self) fn set_pointers_and_magic(&mut self, key_size: usize) -> Result<(), Error> {
        let num_rounds = num_rounds_from_key_size(key_size)?;

        self.last_enc_round_key = self.round_keys[num_rounds..].as_ptr();
        self.last_dec_round_key = self.round_keys[(num_rounds * 2)..].as_ptr();

        self.magic = symcrypt_magic_value!(self);

        Ok(())
    }

    /// Get encryption round keys
    #[inline]
    pub fn enc_round_keys<const KEY_ROUNDS: usize>(&self) -> &[[u8; AES_BLOCK_SIZE]; KEY_ROUNDS] {
        self.round_keys[0..KEY_ROUNDS].try_into().unwrap()
    }

    /// Get decryption round keys
    #[inline]
    pub fn dec_round_keys<const KEY_ROUNDS: usize>(&self) -> &[[u8; AES_BLOCK_SIZE]; KEY_ROUNDS] {
        // There are (2 * num_rounds + 1) round keys in total, but one is shared by decryption
        // and encryption. The first decryption round key is the last encryption round key.
        self.round_keys[(KEY_ROUNDS - 1)..(2 * KEY_ROUNDS - 1)]
            .try_into()
            .unwrap()
    }

    /// Create decryption round keys from encryption round keys. Must only be called after
    /// encryption round keys have been populated.
    fn expand_decryption_round_keys<const KEY_SIZE: usize>(&mut self)
    where
        [(); KEY_SIZE]: sealed::ValidKeySize,
    {
        // rewritten in a style closer to key expansion,
        // and to avoid advanced iterators which may be hard to verify
        let key_rounds: usize = key_rounds(KEY_SIZE);

        for i in 0..key_rounds - 2 {
            let enc_key = self.round_keys[key_rounds - 2 - i]; // Copy the value (no &)
            let dec_key = AesImplType::create_decryption_round_key(&enc_key);
            self.round_keys[key_rounds + i] = dec_key;
        }
        self.round_keys[2 * key_rounds - 2] = self.round_keys[0];
    }

    /// Expands an AES key into the round keys required for encryption and decryption.
    ///
    /// # Arguments
    /// * `key` - The AES key bytes
    /// * `key_usage` - Specifies whether the key will be used for encryption only or both
    ///   encryption and decryption.
    ///
    /// # Type Parameters
    /// * `KEY_SIZE` - The size of the key in bytes (must be 16, 24, or 32).
    pub fn expand_key<const KEY_SIZE: usize>(
        &mut self,
        key: &[u8; KEY_SIZE],
        key_usage: AesKeyUsage,
    ) where
        [(); KEY_SIZE]: sealed::ValidKeySize,
    {
        const ROUND_CONSTANT: [u32; 11] = [
            0, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
        ];

        // loads a 32-bit sub-key word from the AES key
        let load_word = |offset: usize| -> u32 {
            u32::from_le_bytes(key[offset..offset + 4].try_into().unwrap())
        };

        // packs 4 32-bit sub-keys into a round key for encryption
        let round_key = |w0: u32, w1: u32, w2: u32, w3: u32| -> [u8; AES_BLOCK_SIZE] {
            let w = u128::from(w0)
                | (u128::from(w1) << 32)
                | (u128::from(w2) << 64)
                | (u128::from(w3) << 96);
            w.to_le_bytes()
        };

        // scrambles a sub-key at the end of an expansion round
        let subst_rotate_add_rcon = |w: u32, r: usize| -> u32 {
            AesImplType::sbox_lookup_u32(w).rotate_right(8) ^ ROUND_CONSTANT[r]
        };

        if KEY_SIZE == 16 {
            // AES-128: 4 words from the key + 10 4-word expansion rounds (11 x 4 words total)
            let mut w0 = load_word(0);
            let mut w1 = load_word(4);
            let mut w2 = load_word(8);
            let mut w3 = load_word(12);
            self.round_keys[0] = round_key(w0, w1, w2, w3);

            for r in 1..11 {
                w0 ^= subst_rotate_add_rcon(w3, r);
                w1 ^= w0;
                w2 ^= w1;
                w3 ^= w2;
                self.round_keys[r] = round_key(w0, w1, w2, w3);
            }
        } else if KEY_SIZE == 24 {
            // AES-192: 6 words from the key + 8 6-word expansion rounds (13 x 4 words total)
            // the last two words of the last expansion round are discarded.
            let mut w0 = load_word(0);
            let mut w1 = load_word(4);
            let mut w2 = load_word(8);
            let mut w3 = load_word(12);
            let mut w4 = load_word(16);
            let mut w5 = load_word(20);
            self.round_keys[0] = round_key(w0, w1, w2, w3);

            for i in 0..4 {
                // This loop body unfolds 2 expansion rounds (2 * i and 2 * i + 1)
                // jointly producing 3 x 4 words (for encryption rounds 3 * i + 1..3)

                w0 ^= subst_rotate_add_rcon(w5, 2 * i + 1);
                w1 ^= w0;
                self.round_keys[3 * i + 1] = round_key(w4, w5, w0, w1);

                w2 ^= w1;
                w3 ^= w2;
                w4 ^= w3;
                w5 ^= w4;
                self.round_keys[3 * i + 2] = round_key(w2, w3, w4, w5);

                w0 ^= subst_rotate_add_rcon(w5, 2 * i + 2);
                w1 ^= w0;
                w2 ^= w1;
                w3 ^= w2;
                self.round_keys[3 * i + 3] = round_key(w0, w1, w2, w3);

                w4 ^= w3;
                w5 ^= w4;
            }
        } else {
            // AES-256: 8 words from the key + 7 8-word expansion rounds (15 x 4 words total)
            // the second half of the last expansion round is skipped.
            let mut w0 = load_word(0);
            let mut w1 = load_word(4);
            let mut w2 = load_word(8);
            let mut w3 = load_word(12);
            self.round_keys[0] = round_key(w0, w1, w2, w3);

            let mut w4 = load_word(16);
            let mut w5 = load_word(20);
            let mut w6 = load_word(24);
            let mut w7 = load_word(28);
            self.round_keys[1] = round_key(w4, w5, w6, w7);

            for r in 1..8 {
                w0 ^= subst_rotate_add_rcon(w7, r);
                w1 ^= w0;
                w2 ^= w1;
                w3 ^= w2;
                self.round_keys[2 * r] = round_key(w0, w1, w2, w3);

                if r < 7 {
                    w4 ^= AesImplType::sbox_lookup_u32(w3);
                    w5 ^= w4;
                    w6 ^= w5;
                    w7 ^= w6;
                    self.round_keys[2 * r + 1] = round_key(w4, w5, w6, w7);
                }
            }
        }

        if key_usage == AesKeyUsage::EncryptAndDecrypt {
            self.expand_decryption_round_keys::<KEY_SIZE>();
        }
    }
}

impl Drop for CSymCryptAesExpandedKey {
    fn drop(&mut self) {
        wipe_slice(&mut self.round_keys);
    }
}

impl<const KEY_SIZE: usize> BlockCipherExpandedKey<KEY_SIZE> for AesExpandedKey<KEY_SIZE>
where
    [(); KEY_SIZE]: sealed::ValidKeySize,
{
    fn zeroed() -> Self {
        let key = CSymCryptAesExpandedKey::new(KEY_SIZE).unwrap();
        Self { inner: key }
    }

    fn expand_key(&mut self, key: &[u8; KEY_SIZE]) {
        self.inner
            .expand_key::<KEY_SIZE>(key, AesKeyUsage::EncryptAndDecrypt);
    }
}

/// Computing `KEY_ROUNDS` from `KEY_SIZE` is not yet enabled in stable rust,
/// so instead we use a dispatch that'll be resolved at compile time
macro_rules! dispatch {
    ($method:ident($($args:expr),*)) => {
        match KEY_SIZE {
            16 => AesImplType::$method::<11>($($args),*),
            24 => AesImplType::$method::<13>($($args),*),
            32 => AesImplType::$method::<15>($($args),*),
            _ => unreachable!("Invalid key size validated by where clause"),
        }
    };
}

impl<const KEY_SIZE: usize> BlockCipher<AES_BLOCK_SIZE, KEY_SIZE> for Aes
where
    [(); KEY_SIZE]: sealed::ValidKeySize,
{
    type Key = AesExpandedKey<KEY_SIZE>;

    fn encrypt_block_in_place(key: &Self::Key, block: &mut [u8; AES_BLOCK_SIZE]) {
        dispatch!(encrypt_block(&key.inner, None, block));
    }

    fn encrypt_block(
        key: &Self::Key,
        plain: &[u8; AES_BLOCK_SIZE],
        cipher: &mut [u8; AES_BLOCK_SIZE],
    ) {
        dispatch!(encrypt_block(&key.inner, Some(plain), cipher));
    }

    fn decrypt_block_in_place(key: &Self::Key, block: &mut [u8; AES_BLOCK_SIZE]) {
        dispatch!(decrypt_block(&key.inner, None, block));
    }

    fn decrypt_block(
        key: &Self::Key,
        cipher: &[u8; AES_BLOCK_SIZE],
        plain: &mut [u8; AES_BLOCK_SIZE],
    ) {
        dispatch!(decrypt_block(&key.inner, Some(cipher), plain));
    }
}

/// Adding helper functions for calling the 3 variants of AES
/// This is compile-time boilerplate.
pub type Aes128 = Aes;
pub type Aes192 = Aes;
pub type Aes256 = Aes;

pub mod aes128 {
    use super::{Aes128, AesExpandedKey, BlockCipher, BlockCipherExpandedKey, AES_BLOCK_SIZE};

    #[must_use]
    pub fn new(key: &[u8; 16]) -> AesExpandedKey<16> {
        AesExpandedKey::<16>::new(key)
    }

    pub fn encrypt_block(
        key: &AesExpandedKey<16>,
        plain: &[u8; AES_BLOCK_SIZE],
        cipher: &mut [u8; AES_BLOCK_SIZE],
    ) {
        <Aes128 as BlockCipher<AES_BLOCK_SIZE, 16>>::encrypt_block(key, plain, cipher);
    }

    pub fn encrypt_block_in_place(key: &AesExpandedKey<16>, block: &mut [u8; AES_BLOCK_SIZE]) {
        <Aes128 as BlockCipher<AES_BLOCK_SIZE, 16>>::encrypt_block_in_place(key, block);
    }

    pub fn decrypt_block(
        key: &AesExpandedKey<16>,
        cipher: &[u8; AES_BLOCK_SIZE],
        plain: &mut [u8; AES_BLOCK_SIZE],
    ) {
        <Aes128 as BlockCipher<AES_BLOCK_SIZE, 16>>::decrypt_block(key, cipher, plain);
    }

    pub fn decrypt_block_in_place(key: &AesExpandedKey<16>, block: &mut [u8; AES_BLOCK_SIZE]) {
        <Aes128 as BlockCipher<AES_BLOCK_SIZE, 16>>::decrypt_block_in_place(key, block);
    }
}

pub mod aes192 {
    use super::{Aes192, AesExpandedKey, BlockCipher, BlockCipherExpandedKey, AES_BLOCK_SIZE};

    #[must_use]
    pub fn new(key: &[u8; 24]) -> AesExpandedKey<24> {
        AesExpandedKey::<24>::new(key)
    }

    pub fn encrypt_block(
        key: &AesExpandedKey<24>,
        plain: &[u8; AES_BLOCK_SIZE],
        cipher: &mut [u8; AES_BLOCK_SIZE],
    ) {
        <Aes192 as BlockCipher<AES_BLOCK_SIZE, 24>>::encrypt_block(key, plain, cipher);
    }

    pub fn encrypt_block_in_place(key: &AesExpandedKey<24>, block: &mut [u8; AES_BLOCK_SIZE]) {
        <Aes192 as BlockCipher<AES_BLOCK_SIZE, 24>>::encrypt_block_in_place(key, block);
    }

    pub fn decrypt_block(
        key: &AesExpandedKey<24>,
        cipher: &[u8; AES_BLOCK_SIZE],
        plain: &mut [u8; AES_BLOCK_SIZE],
    ) {
        <Aes192 as BlockCipher<AES_BLOCK_SIZE, 24>>::decrypt_block(key, cipher, plain);
    }

    pub fn decrypt_block_in_place(key: &AesExpandedKey<24>, block: &mut [u8; AES_BLOCK_SIZE]) {
        <Aes192 as BlockCipher<AES_BLOCK_SIZE, 24>>::decrypt_block_in_place(key, block);
    }
}

pub mod aes256 {
    use super::{Aes256, AesExpandedKey, BlockCipher, BlockCipherExpandedKey, AES_BLOCK_SIZE};

    #[must_use]
    pub fn new(key: &[u8; 32]) -> AesExpandedKey<32> {
        AesExpandedKey::<32>::new(key)
    }

    pub fn encrypt_block(
        key: &AesExpandedKey<32>,
        plain: &[u8; AES_BLOCK_SIZE],
        cipher: &mut [u8; AES_BLOCK_SIZE],
    ) {
        <Aes256 as BlockCipher<AES_BLOCK_SIZE, 32>>::encrypt_block(key, plain, cipher);
    }

    pub fn encrypt_block_in_place(key: &AesExpandedKey<32>, block: &mut [u8; AES_BLOCK_SIZE]) {
        <Aes256 as BlockCipher<AES_BLOCK_SIZE, 32>>::encrypt_block_in_place(key, block);
    }

    pub fn decrypt_block(
        key: &AesExpandedKey<32>,
        cipher: &[u8; AES_BLOCK_SIZE],
        plain: &mut [u8; AES_BLOCK_SIZE],
    ) {
        <Aes256 as BlockCipher<AES_BLOCK_SIZE, 32>>::decrypt_block(key, cipher, plain);
    }

    pub fn decrypt_block_in_place(key: &AesExpandedKey<32>, block: &mut [u8; AES_BLOCK_SIZE]) {
        <Aes256 as BlockCipher<AES_BLOCK_SIZE, 32>>::decrypt_block_in_place(key, block);
    }
}
