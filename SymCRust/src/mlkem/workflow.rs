//
// workflow.rs  End-to-end ML-KEM usability workflows over the verified public API.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

//! Small, **extractable** ML-KEM workflows built only from the verified public
//! API. Each function is deliberately shaped for *short* Aeneas proofs:
//!
//!   * **Bytes in, bytes out.** No key object appears in any signature — keys
//!     are internal. So each postcondition is a pure `bytes = spec-fn(bytes)`
//!     statement, and the proof is `step*` over 2–3 calls plus one rewrite; the
//!     internal `Key` is substituted away via the callee post.
//!   * **Straight-line control flow.** `ok_or(..)?` threads errors uniformly, so
//!     each spec's error side is just "propagated `Error`" and the only content
//!     is the `Ok` case. No loops, no enums, no slice indexing (the reuse
//!     workflow is unrolled) — nothing that needs an induction/invariant proof.
//!
//! Spec-level notation (FIPS 203): `slice.toSpec` is the byte-sequence view;
//! `K_PKE.KeyGen d` / `MLKEM.Encaps_internal` / `MLKEM.Decaps` are the pure
//! spec functions. Verified callee theorems (all `sorry`-free):
//! `mlkem.{key_allocate,key_set_value,key_get_value,encapsulate_ex,decapsulate}.spec`.
//!
//! Residual note: the Encap import and PrivateSeed load are full-FC, so
//! `alice_setup` and `bob_encapsulate` have residual-free bytes→bytes specs.
//! `alice_decapsulate` (DecapsulationKey *import*) is stated with the imported
//! key existential, so its proof is short too and it does not depend on the
//! documented `ByteEncode∘ByteDecode` s-vector residual ("Stage G3").
//! `alice_bob_roundtrip` composes the three and folds in the shared-secret
//! comparison, so its NoError arm *proves* agreement (equality from the
//! verified `const_time_slices_equal` guard). The one thing not proved is that
//! NoError is reached — whether ML-KEM decapsulation succeeds for a given
//! (seed, randomness) is the separate FIPS-203 correctness fact (not
//! unconditionally true — parked; `FipsFailure` on failure).

use super::*;

// Deliberately monomorphic at ML-KEM-768. The composition logic is
// param-independent, so 768 is a faithful representative; keeping the buffer
// sizes fixed makes lengths definitionally exact and the proofs short. The
// genericity that matters is already discharged in the underlying API specs,
// which are all `∀ params : ParameterSet`. Blob sizes are `const fn`s of the
// row count; switching sets would be a one-line change to `N_ROWS_768`.
const N_ROWS_768: usize = 3;
const ENCAPS_KEY_LEN: usize = sizeof_format_encapsulation_key(N_ROWS_768);
const DECAPS_KEY_LEN: usize = sizeof_format_decapsulation_key(N_ROWS_768);
const CIPHERTEXT_LEN: usize = CIPHERTEXT_SIZE_MLKEM768;

/// 64-byte private seed `d ‖ z`.
pub type Seed = [u8; SIZEOF_FORMAT_PRIVATE_SEED];
/// 32-byte encapsulation randomness `m`.
pub type Random = [u8; SIZEOF_ENCAPS_RANDOM];
/// 32-byte shared secret `K`.
pub type Secret = [u8; SIZEOF_AGREED_SECRET];
/// Encapsulation-key (public) blob.
pub type EncapsBlob = [u8; ENCAPS_KEY_LEN];
/// Decapsulation-key (private) blob.
pub type DecapsBlob = [u8; DECAPS_KEY_LEN];
/// ML-KEM-768 ciphertext.
pub type Ciphertext = [u8; CIPHERTEXT_LEN];

/// Uniform error threading: turn a SymCrypt `Error` into a `Result` so callers
/// use `ok_or(f(..))?`. Its spec is `⦃ r => r = Ok () ↔ e = NoError ⦄`, so at
/// each call site the `Ok` continuation carries `e = NoError` and the error
/// branches collapse.
#[inline]
fn ok_or(e: Error) -> Result<(), Error> {
    if e == Error::NoError { Ok(()) } else { Err(e) }
}

/// **Alice.** Full key from `seed`, exported as (public, private) blobs.
///
/// POST (Ok): `enc.toSpec = (K_PKE.KeyGen d).1` (`= encapsulationKey`) and
/// `dec.toSpec = decapsulationKey (K_PKE.KeyGen d)`. Both full-FC (no residual).
pub fn alice_setup(seed: &Seed) -> Result<(EncapsBlob, DecapsBlob), Error> {
    let mut key = key::key_allocate(key::Params::MlKem768)?;
    ok_or(key_set_value(seed, key::Format::PrivateSeed, 0, &mut key))?;

    let mut enc = [0u8; ENCAPS_KEY_LEN];
    ok_or(key_get_value(&key, &mut enc, key::Format::EncapsulationKey, 0))?;

    let mut dec = [0u8; DECAPS_KEY_LEN];
    ok_or(key_get_value(&key, &mut dec, key::Format::DecapsulationKey, 0))?;

    Ok((enc, dec))
}

/// **Bob.** Import a public blob and encapsulate.
///
/// POST (Ok): `(secret, ct) = MLKEM.Encaps_internal params ek.toSpec r.toSpec`.
/// The internal key is eliminated via `encapsulationKey key = ek.toSpec`
/// (Encap import is full-FC), so the statement is pure bytes→bytes.
pub fn bob_encapsulate(ek: &EncapsBlob, r: &Random) -> Result<(Secret, Ciphertext), Error> {
    let mut key = key::key_allocate(key::Params::MlKem768)?;
    ok_or(key_set_value(ek, key::Format::EncapsulationKey, 0, &mut key))?;

    let mut secret = [0u8; SIZEOF_AGREED_SECRET];
    let mut ct = [0u8; CIPHERTEXT_LEN];
    ok_or(encapsulate_ex(&key, r, &mut secret, &mut ct))?;

    Ok((secret, ct))
}

/// **Alice (recipient).** Load the decapsulation-key blob she exported and
/// decapsulate Bob's ciphertext.
///
/// POST (Ok): `∃ key, wfDecapKey key ∧ (key's fields = dk windows) ∧
/// MLKEM.Decaps params key.toDecapKey ct.toSpec = some secret.toSpec`. Stated
/// with the imported key existential so the proof is a short `step*` over
/// `key_set_value(Decap)` + `decapsulate`; reducing `key.toDecapKey` to
/// `dk.toSpec` would need the Stage-G3 s-round-trip lemma (not required here).
pub fn alice_decapsulate(dk: &DecapsBlob, ct: &Ciphertext) -> Result<Secret, Error> {
    let mut key = key::key_allocate(key::Params::MlKem768)?;
    ok_or(key_set_value(dk, key::Format::DecapsulationKey, 0, &mut key))?;

    let mut secret = [0u8; SIZEOF_AGREED_SECRET];
    ok_or(decapsulate(&key, ct, &mut secret))?;

    Ok(secret)
}

/// **Alice ⇄ Bob end-to-end round-trip.** Chains the three party functions and
/// checks — *inside the extractable code* — that the encapsulated and
/// decapsulated secrets agree, using the constant-time `const_time_slices_equal`
/// (already verified: `result = true ↔ a = b`). Because the comparison is part
/// of this function rather than a test-only `assert_eq!`, the agreement is
/// covered by this function's spec.
///
/// POST (Ok result), with `d = seed`, `r = random.toSpec`, `ek/dk` the keys of
/// `K_PKE.KeyGen d`:
/// ```text
///   let (K, c) := MLKEM.Encaps_internal params ek r
///   ∃ K', MLKEM.Decaps params dk c.toSpec = some K' ∧ K = K' ∧ result = K
/// ```
/// i.e. **NoError proves Alice and Bob agree** — the equality `K = K'` is
/// discharged from the `const_time_slices_equal` guard via its verified spec,
/// not assumed. What is *not* proved is that NoError is reached: whether ML-KEM
/// decapsulation succeeds for `(d, r)` is the parked FIPS-203 correctness fact
/// (on failure the function returns `FipsFailure`).
pub fn alice_bob_roundtrip(seed: &Seed, random: &Random) -> Result<Secret, Error> {
    let (enc_blob, dec_blob) = alice_setup(seed)?;
    let (secret_bob, ct) = bob_encapsulate(&enc_blob, random)?;
    let secret_alice = alice_decapsulate(&dec_blob, &ct)?;

    if !const_time_slices_equal(&secret_bob, &secret_alice) {
        return Err(Error::FipsFailure);
    }
    Ok(secret_bob)
}
