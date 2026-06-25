//
// SymCrypt_HPKE.h
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once


#ifdef __cplusplus
extern "C" {
#endif

#include "symcrypt.h"

//
// Forward declarations for Hpkekey types
//
SYMCRYPT_ASYM_ALIGN_STRUCT SYMCRYPT_HPKEKEY;
typedef struct SYMCRYPT_HPKEKEY SYMCRYPT_HPKEKEY;
typedef       SYMCRYPT_HPKEKEY * PSYMCRYPT_HPKEKEY;
typedef const SYMCRYPT_HPKEKEY * PCSYMCRYPT_HPKEKEY;

//
// SymCrypt definitions to capture HPKE's KEM, KDF, and AEAD identifiers
// per the IANA registry for HPKE: https://www.iana.org/assignments/hpke/hpke.xhtml
//
// Only IDs for algorithms supported by SymCrypt, or potentially supported in the
// near future, are included here.
//
typedef enum SYMCRYPT_HPKE_KEM_ID {
    SYMCRYPT_HPKE_KEM_ID_NULL               = 0x0000,
    SYMCRYPT_HPKE_KEM_ID_DHKEM_P256         = 0x0010,
    SYMCRYPT_HPKE_KEM_ID_DHKEM_P384         = 0x0011,
    SYMCRYPT_HPKE_KEM_ID_DHKEM_P521         = 0x0012,
    SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519       = 0x0020,
    SYMCRYPT_HPKE_KEM_ID_MLKEM_512          = 0x0040,
    SYMCRYPT_HPKE_KEM_ID_MLKEM_768          = 0x0041,
    SYMCRYPT_HPKE_KEM_ID_MLKEM_1024         = 0x0042,
    SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256      = 0x0050, // draft ietf-hpke-pq
    SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384     = 0x0051, // draft ietf-hpke-pq
    SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519    = 0x647a, // draft ietf-hpke-pq
    SYMCRYPT_HPKE_KEM_ID_XWING              = 0x647a, // alternative name for ML-KEM-768+X25519
} SYMCRYPT_HPKE_KEM_ID;

typedef enum SYMCRYPT_HPKE_KDF_ID {
    SYMCRYPT_HPKE_KDF_ID_NULL        = 0x0000,
    SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256 = 0x0001,
    SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384 = 0x0002,
    SYMCRYPT_HPKE_KDF_ID_HKDF_SHA512 = 0x0003,
    SYMCRYPT_HPKE_KDF_ID_SHAKE128    = 0x0010, // draft ietf-hpke-pq
    SYMCRYPT_HPKE_KDF_ID_SHAKE256    = 0x0011, // draft ietf-hpke-pq
} SYMCRYPT_HPKE_KDF_ID;

typedef enum SYMCRYPT_HPKE_AEAD_ID {
    SYMCRYPT_HPKE_AEAD_ID_NULL              = 0x0000,
    SYMCRYPT_HPKE_AEAD_ID_AESGCM128         = 0x0001,
    SYMCRYPT_HPKE_AEAD_ID_AESGCM256         = 0x0002,
    SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305  = 0x0003,
    SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY       = 0xFFFF,
} SYMCRYPT_HPKE_AEAD_ID;

// Note that the fields of the ciphersuite are UINT16 rather than directly
// being enums. This is because the values are externally defined by the HPKE
// IANA registry and are 16 bit integers by definition.
// A SymCrypt caller may use SYMCRYPT_HPKE_* enums for readable ciphersuite
// definitions, but may also use integers from another trusted source.
typedef struct SYMCRYPT_HPKE_CIPHERSUITE {
    UINT16 kemId;
    UINT16 kdfId;
    UINT16 aeadId;
} SYMCRYPT_HPKE_CIPHERSUITE;

// Maximum size for application-supplied buffers in SymCryptHpkeSecretExport,
// applied to both pbExporterContext (input) and pbResult (output).
// This limit is not specified by HPKE and is subject to change in future
// versions. Inputs exceeding the limit are rejected with SYMCRYPT_INVALID_ARGUMENT.
#define SYMCRYPT_HPKE_MAX_EXPORT_SIZE        (16384)

// Maximum size for the application-supplied info input to SymCryptHpkeSetupSender
// and SymCryptHpkeSetupRecipient. This limit is not specified by HPKE and is
// subject to change in future versions. Inputs exceeding the limit are rejected
// with SYMCRYPT_INVALID_ARGUMENT.
#define SYMCRYPT_HPKE_MAX_INFO_SIZE         SYMCRYPT_HPKE_MAX_EXPORT_SIZE

PSYMCRYPT_HPKEKEY
SYMCRYPT_CALL
SymCryptHpkekeyAllocate(
    SYMCRYPT_HPKE_CIPHERSUITE params );
//
// Allocate and create a new HPKEKEY object sized according to the specified parameters.
//
// The params struct specifies the KEM, KDF, and AEAD algorithms to be used, per the
// HPKE specification, if an unsupported combination is specified, NULL is returned.
//
// This call does not initialize the key. It should be followed by a call to
// SymCryptHpkekeyGenerate, SymCryptHpkekeyDerive, or SymCryptHpkekeySetValue.
//

VOID
SYMCRYPT_CALL
SymCryptHpkekeyFree(
    _Inout_ PSYMCRYPT_HPKEKEY pkHpkekey );

// HPKE key formats
// ==================
// The below formats apply **only to external formats**: When somebody is importing or exporting
// a key. The internal format of the keys is not visible to the caller.
typedef enum SYMCRYPT_HPKEKEY_FORMAT {
    SYMCRYPT_HPKEKEY_FORMAT_NULL        = 0,
    SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY = 1,
    SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY  = 2,
} SYMCRYPT_HPKEKEY_FORMAT;

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeSizeofKeyFormatFromParams(
            SYMCRYPT_HPKE_CIPHERSUITE   params,
            SYMCRYPT_HPKEKEY_FORMAT     hpkeKeyFormat,
    _Out_   SIZE_T*                     pcbKeyFormat );
//
// Gives the size in bytes of the key blob for the given HPKE ciphersuite and the specified
// key format.
// Returns SYMCRYPT_INCOMPATIBLE_FORMAT if hpkeKeyFormat is an unsupported value,
// or SYMCRYPT_NOT_IMPLEMENTED if the ciphersuite identifies an unsupported KEM.
//

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeSizeofEncapsCiphertextFromParams(
            SYMCRYPT_HPKE_CIPHERSUITE   params,
    _Out_   SIZE_T*                     pcbEncapsCiphertext );
//
// Gives the size in bytes of the Encaps ciphertext for the given HPKE ciphersuite.
// Returns SYMCRYPT_NOT_IMPLEMENTED if the ciphersuite identifies an unsupported KEM.
//

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeSizeofAeadOverheadFromParams(
            SYMCRYPT_HPKE_CIPHERSUITE   params,
    _Out_   SIZE_T*                     pcbAeadOverhead );
//
// Gives the size in bytes of the AEAD overhead (tag size Nt) for the given HPKE ciphersuite.
// The caller must account for this overhead when sizing Seal/Open output buffers:
//   cbCiphertext = cbPlaintext + Nt  (for Seal)
//   cbPlaintext  = cbCiphertext - Nt (for Open)
// Returns SYMCRYPT_NOT_IMPLEMENTED if the ciphersuite identifies an unsupported AEAD,
// or SYMCRYPT_INVALID_ARGUMENT if the AEAD is Export-Only.
//
// Remarks:
// - For all currently defined AEAD ciphersuites, the overhead is 16 bytes.
//

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkekeyGenerate(
    _Inout_ PSYMCRYPT_HPKEKEY   pkHpkekey,
            UINT32              flags );
//
// Generate a new random HPKE key using the information from the
// parameters passed to SymCryptHpkekeyAllocate.
//
// Allowed flags:
//
// - SYMCRYPT_FLAG_KEY_NO_FIPS
//   Opt-out of performing validation required for FIPS
//
// Described in more detail in the "Flags for asymmetric key generation and import" section in SymCrypt.h
//

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkekeyDerive(
    _In_reads_bytes_( cbIkm )   PCBYTE                  pbIkm,
                                SIZE_T                  cbIkm,
    _Inout_                     PSYMCRYPT_HPKEKEY       pkHpkekey,
                                UINT32                  flags );
//
// Derive an HPKE key pair from the input keying material (Ikm) provided, following the
// DeriveKeyPair process specified in the HPKE standard(s). The arguments are the following:
//  - (pbIkm, cbIkm): a buffer containing the Ikm
//  - pkHpkekey: the HPKE key object
//  - flags: must be 0
//
// Remarks:
// - cbIkm must be in [1, 128]. SymCrypt does not enforce a KEM-specific minimum;
//   the caller is responsible for supplying sufficient entropy for the security
//   level of the KEM being used.
//

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkekeySetValue(
    _In_reads_bytes_( cbSrc )   PCBYTE                  pbSrc,
                                SIZE_T                  cbSrc,
                                SYMCRYPT_HPKEKEY_FORMAT hpkeKeyFormat,
                                UINT32                  flags,
    _Inout_                     PSYMCRYPT_HPKEKEY       pkHpkekey );
//
// Import key material to an HPKE key object. The arguments are the following:
//  - (pbSrc, cbSrc): a buffer containing a representation of an HPKE key,
//    in format specified by hpkeKeyFormat.
//  - hpkeKeyFormat: format of the input
//  - pkHpkekey: the HPKE key object
//
// Allowed flags:
//
// - SYMCRYPT_FLAG_KEY_NO_FIPS
//   Opt-out of performing validation required for FIPS
//
// - SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION
//   Opt-out of performing almost all validation - must be specified with SYMCRYPT_FLAG_KEY_NO_FIPS
//
// Remarks:
// - cbSrc must be equal to the cbKeyFormat returned from
//   SymCryptHpkeSizeofKeyFormatFromParams(params, hpkeKeyFormat, &cbKeyFormat)
//

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkekeyGetValue(
    _In_                        PCSYMCRYPT_HPKEKEY      pkHpkekey,
    _Out_writes_bytes_( cbDst ) PBYTE                   pbDst,
                                SIZE_T                  cbDst,
                                SYMCRYPT_HPKEKEY_FORMAT hpkeKeyFormat,
                                UINT32                  flags );
//
// Export key material from an HPKE key object. The arguments are the following:
//  - (pbDst, cbDst): a buffer into which a representation of an HPKE key is
//    written, in the format specified by hpkeKeyFormat.
//  - hpkeKeyFormat: format of the output
//  - flags: must be 0
//
//  Remarks:
//  - If the key object does not have the information required to export to the format
//    specified by hpkeKeyFormat this function will return SYMCRYPT_INCOMPATIBLE_FORMAT.
//  - cbDst must be equal to the cbKeyFormat returned from
//    SymCryptHpkeSizeofKeyFormatFromParams(params, hpkeKeyFormat, &cbKeyFormat)
//

//
// Forward declarations for Hpkecontext types
//
SYMCRYPT_ASYM_ALIGN_STRUCT SYMCRYPT_HPKECONTEXT;
typedef struct SYMCRYPT_HPKECONTEXT SYMCRYPT_HPKECONTEXT;
typedef       SYMCRYPT_HPKECONTEXT * PSYMCRYPT_HPKECONTEXT;
typedef const SYMCRYPT_HPKECONTEXT * PCSYMCRYPT_HPKECONTEXT;

PSYMCRYPT_HPKECONTEXT
SYMCRYPT_CALL
SymCryptHpkeContextAllocate(
    SYMCRYPT_HPKE_CIPHERSUITE  params );
//
// Allocate and create a new HPKE context object sized according to the specified parameters.
//
// The params struct specifies the KEM, KDF, and AEAD algorithms to be used, per the
// HPKE specification, if an unsupported combination is specified, NULL is returned.
//
// This call does not initialize the context. It should be followed by a call to
// SymCryptHpkeSetupSender or SymCryptHpkeSetupRecipient.
//

VOID
SYMCRYPT_CALL
SymCryptHpkeContextFree(
    _Inout_ PSYMCRYPT_HPKECONTEXT pHpkeContext );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeSetupSender(
    _Inout_                         PSYMCRYPT_HPKECONTEXT   pHpkeContext,
    _In_                            PCSYMCRYPT_HPKEKEY      pkHpkekey,
    _In_reads_bytes_opt_( cbInfo )  PCBYTE                  pbInfo,
                                    SIZE_T                  cbInfo,
    _In_reads_bytes_opt_( cbPsk )   PCBYTE                  pbPsk,
                                    SIZE_T                  cbPsk,
    _In_reads_bytes_opt_( cbPskId ) PCBYTE                  pbPskId,
                                    SIZE_T                  cbPskId,
    _Out_writes_bytes_( cbEnc )     PBYTE                   pbEnc,
                                    SIZE_T                  cbEnc,
                                    UINT32                  flags );
//
// Setup an HPKE sender context object and produce the encapsulated secret required
// for the HPKE recipient to setup its context.
//
// Parameters:
//  - pHpkeContext: the HPKE context object to Setup as a sender
//  - pkHpkekey: the recipient's HPKE public key
//  - (pbInfo, cbInfo): optional public application-specific information to be used in the key schedule
//  - (pbPsk, cbPsk): optional pre-shared secret key (held by both sender and recipient) to be used in
//    the key schedule
//  - (pbPskId, cbPskId): optional identifier for the pre-shared key to be used in the key schedule
//  - (pbEnc, cbEnc): buffer into which the encapsulated secret is written
//  - flags: must be 0
//
// Return values:
// - SYMCRYPT_NO_ERROR on success
// - SYMCRYPT_INVALID_ARGUMENT if any parameter is invalid
//
// Remarks:
// - The ciphersuite parameters for the context must match those of the recipient's HPKE key.
// - (pbPsk, cbPsk) and (pbPskId, cbPskId) must either both be provided or both be (NULL, 0).
// - cbEnc must be exactly the size returned by SymCryptHpkeSizeofEncapsCiphertextFromParams(params, &cbEnc).
// - On success, the HPKE context object is ready for Seal, OpenUnordered, or SecretExport operations, it may not
//   be used for Open operations.
//

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeSetupRecipient(
    _Inout_                         PSYMCRYPT_HPKECONTEXT   pHpkeContext,
    _In_                            PCSYMCRYPT_HPKEKEY      pkHpkekey,
    _In_reads_bytes_( cbEnc )       PCBYTE                  pbEnc,
                                    SIZE_T                  cbEnc,
    _In_reads_bytes_opt_( cbInfo )  PCBYTE                  pbInfo,
                                    SIZE_T                  cbInfo,
    _In_reads_bytes_opt_( cbPsk )   PCBYTE                  pbPsk,
                                    SIZE_T                  cbPsk,
    _In_reads_bytes_opt_( cbPskId ) PCBYTE                  pbPskId,
                                    SIZE_T                  cbPskId,
                                    UINT32                  flags );
//
// Setup an HPKE recipient context object using the encapsulated secret provided by the sender.
//
// Parameters:
//  - pHpkeContext: the HPKE context object to Setup as a recipient
//  - pkHpkekey: the recipient's HPKE private key
//  - (pbEnc, cbEnc): the encapsulated secret received from the sender
//  - (pbInfo, cbInfo): optional public application-specific information to be used in the key schedule
//  - (pbPsk, cbPsk): optional pre-shared secret key (held by both sender and recipient) to be used in
//    the key schedule
//  - (pbPskId, cbPskId): optional identifier for the pre-shared key to be used in the key schedule
//  - flags: must be 0
//
// Return values:
// - SYMCRYPT_NO_ERROR on success
// - SYMCRYPT_INVALID_ARGUMENT if any parameter is invalid
//
// Remarks:
// - The ciphersuite parameters for the context must match those of the recipient's HPKE key.
// - (pbPsk, cbPsk) and (pbPskId, cbPskId) must either both be provided or both be (NULL, 0).
// - On success, the HPKE context object is ready for Open, OpenUnordered, or SecretExport operations, it may not
//   be used for Seal operations.
//

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeSeal(
    _Inout_                                 PSYMCRYPT_HPKECONTEXT   pHpkeContext,
    _In_reads_bytes_opt_( cbAuthData )      PCBYTE                  pbAuthData,
                                            SIZE_T                  cbAuthData,
    _In_reads_bytes_opt_( cbSrc )           PCBYTE                  pbSrc,
                                            SIZE_T                  cbSrc,
    _Out_writes_bytes_( cbDst )             PBYTE                   pbDst,
                                            SIZE_T                  cbDst,
    _Out_opt_                               UINT64*                 pu64SeqNumber );
//
// Seal a plaintext buffer, using a Sender's HPKE context object.
// Internally an AEAD encryption is performed, with the resulting ciphertext being tied to an
// atomically-incremented sequence number which is contained in the HPKE context object (the
// HPKE context is stateful).
// The intent is that the Sender generates an ordered sequence of ciphertexts which the Recipient can
// Open in the same order.
//
// To relax the requirements on the Sender, this operation is thread-safe, so multiple threads may use
// a single HPKE context object. If multiple threads do use the same Sender context, the returned sequence
// numbers must be used to correctly order the ciphertexts for the Recipient.
//
// Parameters:
//  - pHpkeContext: the Sender's HPKE context object to use
//  - (pbAuthData, cbAuthData): optional additional authenticated data to be included in the AEAD
//  - (pbSrc, cbSrc): plaintext buffer to be sealed, or (NULL, 0) for authentication-only.
//    The source and destination buffers may overlap only if pbDst == pbSrc (in-place encryption
//    with tag appended), or be non-overlapping; they may not partially overlap.
//  - (pbDst, cbDst): ciphertext output of Seal operation. cbDst must equal cbSrc + cbTag, where
//    cbTag is the AEAD tag size returned by SymCryptHpkeSizeofAeadOverheadFromParams.
//  - pu64SeqNumber: optional pointer to variable which receives the sequence number used for this
//    operation
//
// Return values:
// - SYMCRYPT_NO_ERROR on success
// - SYMCRYPT_INVALID_ARGUMENT if any parameter is invalid, or cbDst != cbSrc + cbTag
//
// Remarks:
// - The HPKE context object must have been previously setup as a Sender using SymCryptHpkeSetupSender
// - On success, the sequence number inside the context is incremented by 1.
// - If too many Seal operations have been performed (2^64 - 2^32) with this context, the context will
//   always return SYMCRYPT_INVALID_ARGUMENT, but this should never occur in real use.
//

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeOpen(
    _Inout_                                 PSYMCRYPT_HPKECONTEXT   pHpkeContext,
    _In_reads_bytes_opt_( cbAuthData )      PCBYTE                  pbAuthData,
                                            SIZE_T                  cbAuthData,
    _In_reads_bytes_( cbSrc )               PCBYTE                  pbSrc,
                                            SIZE_T                  cbSrc,
    _Out_writes_bytes_( cbDst )             PBYTE                   pbDst,
                                            SIZE_T                  cbDst );
//
// Open a ciphertext buffer using a Recipient's HPKE context object.
// Internally an AEAD decryption is performed, with the decryption attempt being tied to a
// sequence number contained in the HPKE context object (the HPKE context is stateful).
// The intent is that the Recipient opens an ordered sequence of ciphertexts produced by the
// Sender in the same order.
//
// This API is not thread-safe, as the ciphertexts must be provided to Open in the same order as
// they were produced by Seal to ensure successful decryption. The benefit of this is that the
// application does not need to explicitly track sequence numbers for each ciphertext, and there
// is some protection against replay or reordering attacks.
// The SymCryptHpkeOpenUnordered function can be used instead to allow multiple threads to Open
// ciphertexts associated with caller-specified sequence numbers if needed by the caller and the
// trade-off of securely managing sequence numbers in the calling application is acceptable.
//
// Parameters:
//  - pHpkeContext: the Recipient's HPKE context object to use
//  - (pbAuthData, cbAuthData): optional additional authenticated data to be included in the AEAD
//  - (pbSrc, cbSrc): ciphertext buffer to be opened. The source and destination buffers may
//      overlap only if pbDst == pbSrc (in-place decryption), or be non-overlapping; they may
//      not partially overlap.
//  - (pbDst, cbDst): plaintext output of Open operation. cbDst must equal cbSrc - cbTag, where
//    cbTag is the AEAD tag size returned by SymCryptHpkeSizeofAeadOverheadFromParams.
//    For authentication-only ciphertexts (where cbSrc == cbTag), cbDst must be 0 and pbDst may be NULL.
//
// Return values:
// - SYMCRYPT_NO_ERROR on success
// - SYMCRYPT_INVALID_ARGUMENT if any parameter is invalid, or cbDst != cbSrc - cbTag
// - SYMCRYPT_AUTHENTICATION_FAILURE if the AEAD authentication fails
//
// Remarks:
// - The HPKE context object must have been previously setup as a Recipient using SymCryptHpkeSetupRecipient
// - The HPKE context is only modified on success: the sequence number is incremented by 1.
//   On failure the context is unchanged.
// - If too many successful Open operations have been performed (2^64 - 2^32) with this context, the context will
//   always return SYMCRYPT_INVALID_ARGUMENT, but this should never occur in real use.
// - When SYMCRYPT_AUTHENTICATION_FAILURE is returned, the pbDst buffer does not contain decrypted content.
//   Note: While checking the authentication the purported plaintext may be stored in pbDst. It is not safe to reveal
//   purported plaintext when the authentication has not been checked. (Doing so would reveal key stream information
//   that can be used to decrypt any message encrypted with the same nonce value.) Thus, users should be careful
//   to not reveal the pbDst buffer until this function returns (e.g. through other threads or sharing memory).
//

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeOpenUnordered(
    _In_                                    PCSYMCRYPT_HPKECONTEXT  pHpkeContext,
                                            UINT64                  u64SeqNumber,
    _In_reads_bytes_opt_( cbAuthData )      PCBYTE                  pbAuthData,
                                            SIZE_T                  cbAuthData,
    _In_reads_bytes_( cbSrc )               PCBYTE                  pbSrc,
                                            SIZE_T                  cbSrc,
    _Out_writes_bytes_( cbDst )             PBYTE                   pbDst,
                                            SIZE_T                  cbDst );
//
// Open a ciphertext buffer using an HPKE context object (Sender or Recipient) and a caller-specified sequence number.
// Internally an AEAD decryption is performed, with the decryption attempt being tied to the provided
// sequence number.
//
// This API is thread-safe, as the caller provides the sequence number for each Open operation, but the
// caller must ensure that the sequence numbers provided match those used by the Sender when producing
// the ciphertexts via Seal. The application is responsible for securely managing the sequence numbers to
// prevent replay or reordering attacks.
//
// Parameters:
//  - pHpkeContext: the HPKE context object to use
//  - u64SeqNumber: the Sequence number to use for this Open operation
//  - (pbAuthData, cbAuthData): optional additional authenticated data to be included in the AEAD
//  - (pbSrc, cbSrc): ciphertext buffer to be opened. The source and destination buffers may
//    overlap only if pbDst == pbSrc (in-place decryption), or be non-overlapping; they may
//    not partially overlap.
//  - (pbDst, cbDst): plaintext output of Open operation. cbDst must equal cbSrc - cbTag, where
//    cbTag is the AEAD tag size returned by SymCryptHpkeSizeofAeadOverheadFromParams.
//    For authentication-only ciphertexts (where cbSrc == cbTag), cbDst must be 0 and pbDst may be NULL.
//
// Return values:
// - SYMCRYPT_NO_ERROR on success
// - SYMCRYPT_INVALID_ARGUMENT if any parameter is invalid, or cbDst != cbSrc - cbTag
// - SYMCRYPT_AUTHENTICATION_FAILURE if the AEAD authentication fails
//
// Remarks:
// - The HPKE context object must have been previously setup using SymCryptHpkeSetupSender
//   or SymCryptHpkeSetupRecipient
// - Normally this function would be used by a Recipient Opening messages out of order, but it may also
//   be used by a Sender that wants to verify a ciphertext it just produced can be successfully decrypted.
// - This function does not modify the sequence number stored in the context object
// - u64SeqNumber must be less than 2^64 - 2^32
// - When SYMCRYPT_AUTHENTICATION_FAILURE is returned, the pbDst buffer does not contain decrypted content.
//   Note: While checking the authentication the purported plaintext may be stored in pbDst. It is not safe to reveal
//   purported plaintext when the authentication has not been checked. (Doing so would reveal key stream information
//   that can be used to decrypt any message encrypted with the same nonce value.) Thus, users should be careful
//   to not reveal the pbDst buffer until this function returns (e.g. through other threads or sharing memory).
//

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeSecretExport(
    _In_                                        PCSYMCRYPT_HPKECONTEXT  pHpkeContext,
    _In_reads_bytes_opt_( cbExporterContext )   PCBYTE                  pbExporterContext,
                                                SIZE_T                  cbExporterContext,
    _Out_writes_bytes_( cbResult )              PBYTE                   pbResult,
                                                UINT16                  cbResult );
//
// Derive a secret from an HPKE context object (Sender or Recipient). Takes an exporter
// context buffer as input to bind the exported secret to application-specific context (i.e
// so that different uses of SecretExport with the same HPKE context yield unrelated secrets).
// Internally uses the KDF specified in the HPKE ciphersuite to derive the secret from the
// KEM shared secret established in the HPKE context Setup.
//
// This is intended to allow the application to derive additional secrets from an HPKE
// KEM, for use outside of the Seal/Open (Sender encryption to Recipient) flow defined
// explicitly by HPKE.
//
// Parameters:
//  - pHpkeContext: the HPKE context object to use
//  - (pbExporterContext, cbExporterContext): application-specific context used to uniquely
//    bind the exported secret to a specific use
//  - (pbResult, cbResult): buffer into which the exported secret is written
//
// Return values:
// - SYMCRYPT_NO_ERROR on success
// - SYMCRYPT_INVALID_ARGUMENT if any parameter is invalid
//
// Remarks:
// - The HPKE context object must have been previously setup using SymCryptHpkeSetupSender
//   or SymCryptHpkeSetupRecipient
// - cbResult cannot be larger than the maximum output size for the KDF specified in the
//   HPKE ciphersuite, which is typically less than the UINT16 bound imposed by HPKE.
// - cbExporterContext and cbResult are also bounded by an implementation-defined limit
//   (currently SYMCRYPT_HPKE_MAX_EXPORT_SIZE). The limit is not specified by HPKE and is
//   subject to change in future versions. Inputs exceeding the limit are rejected with
//   SYMCRYPT_INVALID_ARGUMENT.
// - Multiple calls to SecretExport with the same parameters will yield the same output secret.
//   It is the caller's responsibility to ensure that (HpkeContext, ExporterContext) pairs are
//   unique when deriving multiple secrets
//

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeSealSingleShot(
    _In_                                    PCSYMCRYPT_HPKEKEY      pkHpkekey,
    _In_reads_bytes_opt_( cbInfo )          PCBYTE                  pbInfo,
                                            SIZE_T                  cbInfo,
    _In_reads_bytes_opt_( cbPsk )           PCBYTE                  pbPsk,
                                            SIZE_T                  cbPsk,
    _In_reads_bytes_opt_( cbPskId )         PCBYTE                  pbPskId,
                                            SIZE_T                  cbPskId,
    _In_reads_bytes_opt_( cbAuthData )      PCBYTE                  pbAuthData,
                                            SIZE_T                  cbAuthData,
    _In_reads_bytes_opt_( cbSrc )           PCBYTE                  pbSrc,
                                            SIZE_T                  cbSrc,
    _Out_writes_bytes_( cbEnc )             PBYTE                   pbEnc,
                                            SIZE_T                  cbEnc,
    _Out_writes_bytes_( cbDst )             PBYTE                   pbDst,
                                            SIZE_T                  cbDst,
                                            UINT32                  flags );
//
// Single-shot Seal: combines SetupSender + Seal into a single call.
// Internally allocates a temporary HPKE context on the stack, performs SetupSender and Seal,
// then wipes the context before returning.
//
// Parameters:
//  - pkHpkekey: the recipient's HPKE public key
//  - (pbInfo, cbInfo): optional application-specific info for the key schedule
//  - (pbPsk, cbPsk): optional pre-shared key
//  - (pbPskId, cbPskId): optional PSK identifier
//  - (pbAuthData, cbAuthData): optional additional authenticated data for the AEAD
//  - (pbSrc, cbSrc): plaintext to seal, or (NULL, 0) for authentication-only
//  - (pbEnc, cbEnc): buffer for encapsulated secret; cbEnc must be exactly the size
//    returned by SymCryptHpkeSizeofEncapsCiphertextFromParams
//  - (pbDst, cbDst): buffer for AEAD ciphertext output; cbDst must equal cbSrc + cbTag, where
//    cbTag is the AEAD tag size returned by SymCryptHpkeSizeofAeadOverheadFromParams.
//  - flags: must be 0
//
// Return values:
// - SYMCRYPT_NO_ERROR on success
// - SYMCRYPT_INVALID_ARGUMENT if any parameter is invalid
//

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeOpenSingleShot(
    _In_                                    PCSYMCRYPT_HPKEKEY      pkHpkekey,
    _In_reads_bytes_( cbEnc )               PCBYTE                  pbEnc,
                                            SIZE_T                  cbEnc,
    _In_reads_bytes_opt_( cbInfo )          PCBYTE                  pbInfo,
                                            SIZE_T                  cbInfo,
    _In_reads_bytes_opt_( cbPsk )           PCBYTE                  pbPsk,
                                            SIZE_T                  cbPsk,
    _In_reads_bytes_opt_( cbPskId )         PCBYTE                  pbPskId,
                                            SIZE_T                  cbPskId,
    _In_reads_bytes_opt_( cbAuthData )      PCBYTE                  pbAuthData,
                                            SIZE_T                  cbAuthData,
    _In_reads_bytes_( cbSrc )               PCBYTE                  pbSrc,
                                            SIZE_T                  cbSrc,
    _Out_writes_bytes_( cbDst )             PBYTE                   pbDst,
                                            SIZE_T                  cbDst,
                                            UINT32                  flags );
//
// Single-shot Open: combines SetupRecipient + Open into a single call.
// Internally allocates a temporary HPKE context on the stack, performs SetupRecipient and Open,
// then wipes the context before returning.
//
// Parameters:
//  - pkHpkekey: the recipient's HPKE private key
//  - (pbEnc, cbEnc): the encapsulated secret from the sender
//  - (pbInfo, cbInfo): optional application-specific info for the key schedule
//  - (pbPsk, cbPsk): optional pre-shared key
//  - (pbPskId, cbPskId): optional PSK identifier
//  - (pbAuthData, cbAuthData): optional additional authenticated data for the AEAD
//  - (pbSrc, cbSrc): ciphertext to open
//  - (pbDst, cbDst): buffer for plaintext output; cbDst must equal cbSrc - cbTag, where
//    cbTag is the AEAD tag size returned by SymCryptHpkeSizeofAeadOverheadFromParams.
//    For authentication-only ciphertexts (where cbSrc == cbTag), cbDst must be 0 and pbDst may be NULL.
//  - flags: must be 0
//
// Return values:
// - SYMCRYPT_NO_ERROR on success
// - SYMCRYPT_INVALID_ARGUMENT if any parameter is invalid
// - SYMCRYPT_AUTHENTICATION_FAILURE if the AEAD authentication fails
//
// Remarks:
// - When SYMCRYPT_AUTHENTICATION_FAILURE is returned, the pbDst buffer is wiped of any plaintext.
//


#ifdef __cplusplus
}
#endif

