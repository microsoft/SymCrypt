//
// hash.rs   Common definitions shared across SymCrypt hash implementations
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

pub trait Hash {

    /// Hashes data according to the implemented hash function and stores it in result.
    fn hash(&mut self, data: &[u8], result: &mut [u8]);

    /// Initializes the hash state in preparation for appending data.
    fn init(&mut self);
    /// Appends data to the hash state.
    fn append(&mut self, data: &[u8]);
    /// Hashes the appended data and stores it in result.
    fn result(&mut self, result: &mut [u8]);

    //TODO: flesh out function signature
    fn import_state(&mut self);
    fn export_state(&self);
    fn self_test(&self);
}