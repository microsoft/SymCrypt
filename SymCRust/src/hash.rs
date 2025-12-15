//
// hash.rs   Common definitions shared across SymCrypt hash implementations
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

pub(crate) trait HashParams {
    const RESULT_SIZE: usize;
    const BLOCK_SIZE: u32;
}

pub trait StatefulHash<const RESULT_SIZE:usize, const BLOCK_SIZE:u32> {
    /// A constant giving the size, in bytes, of the result of the hash function.
    const RESULT_SIZE: usize = RESULT_SIZE;

    /// A constant giving the natural block size, in bytes, for the hash function.
    /// For SHA3 this is equivalent to the rate of the underlying Keccak permutation.
    const BLOCK_SIZE: u32 = BLOCK_SIZE;

    /// Creates a newly initialized state ready for use.
    fn new() -> Self;

    /// Provides more data to the ongoing hash computation specified by the state.
    /// This state must have been previously initialized with `new()` or `default()`.
    /// This function can be called multiple times on the same state to append more
    /// data.
    fn append(&mut self, data: &[u8]);

    /// Returns the hash of the data appended so far.
    /// If the state was newly initialized this returns the hash of the empty buffer.
    /// If one or more append function calls were made on this state
    /// it returns the hash of the concatenation of all the data buffers
    /// passed to append.
    ///
    /// The state is automatically re-initialized and ready for re-use after this call.
    /// The state is also wiped of any traces of old data to prevent accidental data leakage.
    fn result(&mut self, result: &mut [u8; RESULT_SIZE]);

    //TODO: flesh out function signature
    fn import_state(&mut self);
    fn export_state(&self);
}

pub trait OneShotHash<const RESULT_SIZE:usize, const BLOCK_SIZE:u32> {
    /// A constant giving the size, in bytes, of the result of the hash function.
    const RESULT_SIZE: usize = RESULT_SIZE;

    /// A constant giving the natural block size, in bytes, for the hash function.
    /// For SHA3 this is equivalent to the rate of the underlying Keccak permutation.
    const BLOCK_SIZE: u32 = BLOCK_SIZE;

    /// Computes the hash value of the data buffer.
    /// If you have all the data to be hashed in a single buffer this is the simplest function to use.
    fn hash(data: &[u8], result: &mut [u8; RESULT_SIZE]);

    fn self_test();
}

pub trait StatefulXof <const RESULT_SIZE:usize, const BLOCK_SIZE:u32> {
    /// The default output size in bytes used by the result function.
    const RESULT_SIZE: usize = RESULT_SIZE;

    /// Rate for the Keccak permutation.
    const BLOCK_SIZE: u32 = BLOCK_SIZE;

    /// Creates a newly initialized state ready for use.
    fn new() -> Self;

    /// Appends data to the XOF state.
    ///
    /// This state must have been previously initialized with `new()` or `default()`.
    /// All other uses independent of whether the state is in `append` mode or `extract`
    /// mode are well defined. If the state was previously in `extract` mode, (i.e., after
    /// an Extract call with wipe=false) it wipes/resets the state and the data is
    /// appended to a fresh state.
    fn append(&mut self, data: &[u8]);

    ///  Generates output from the XOF state.
    ///
    ///  This state must have been previously initialized with `new()` or `default()`.
    ///  All other uses independent of whether the state is in `append` mode or `extract` mode
    ///  are well defined.
    ///
    ///  If the state was in `append` mode before the Extract call, Extract switches
    ///  the state to `extract` mode and generates the requested number of bytes from
    ///  the state. Extract wipes/resets the state and transitions the state to `append`
    ///  mode if wipe=true, otherwise leaving the state in `extract` mode, available for
    ///  further extractions.
    fn extract(&mut self, result: &mut [u8], wipe: bool);

    /// Extracts RESULT_SIZE bytes from the state and wipes/resets
    /// it for a new computation.
    ///
    /// This state must have been previously initialized with `new()` or `default()`.
    /// All other uses are well defined. If it is called after an Extract call with wipe=false,
    /// it does the final extraction from the state for RESULT_SIZE bytes, effectively calling
    /// Extract with a RESULT_SIZE length result buffer and wipe=true.
    fn result(&mut self, result: &mut [u8; RESULT_SIZE]);
}

pub trait OneShotXof <const RESULT_SIZE:usize, const BLOCK_SIZE:u32> {
    /// The default output size in bytes. Note that for one-shot XOF,
    /// this is not a strict bound and is included primarily for ease
    /// of access.
    const RESULT_SIZE: usize = RESULT_SIZE;

    /// Rate for the Keccak permutation.
    const BLOCK_SIZE: u32 = BLOCK_SIZE;

    /// Does a one-shot XOF according to the implemented XOF function and fills
    /// the entire result buffer (which does not have to be RESULT_SIZE bytes long).
    fn xof(data: &[u8], result: &mut [u8]);

    fn self_test();
}