//
// block_cipher.rs  SymCrypt Rust block cipher implementation
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

pub trait BlockCipherExpandedKey<const KEY_SIZE: usize> {
    /// Create a zeroed instance of the expanded key
    fn zeroed() -> Self
    where
        Self: Sized;

    /// Create a new expanded key from the given key bytes
    #[must_use]
    fn new(key: &[u8; KEY_SIZE]) -> Self
    where
        Self: Sized,
    {
        let mut expanded_key = Self::zeroed();
        expanded_key.expand_key(key);
        expanded_key
    }

    /// Get the key size in bytes
    fn key_size(&self) -> usize {
        KEY_SIZE
    }

    /// Expand the given key into this expanded key instance
    fn expand_key(&mut self, key: &[u8; KEY_SIZE]);
}

pub trait BlockCipher<const BLOCK_SIZE: usize, const KEY_SIZE: usize> {
    /// The expanded key type for this cipher
    type Key: BlockCipherExpandedKey<KEY_SIZE>;

    /// Encrypt a single block in-place using the given key
    fn encrypt_block_in_place(key: &Self::Key, block: &mut [u8; BLOCK_SIZE]);

    /// Encrypt a single block to a disjoint block using the given key
    fn encrypt_block(key: &Self::Key, plain: &[u8; BLOCK_SIZE], cipher: &mut [u8; BLOCK_SIZE]);

    /// Decrypt a single block in-place using the given key
    fn decrypt_block_in_place(key: &Self::Key, block: &mut [u8; BLOCK_SIZE]);

    /// Decrypt a single block to a disjoint block using the given key
    fn decrypt_block(key: &Self::Key, cipher: &[u8; BLOCK_SIZE], plain: &mut [u8; BLOCK_SIZE]);
}
