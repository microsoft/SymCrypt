//
// hpke_internal.h
//
// Internal types and constants for symcrypt_plus HPKE implementation.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

//
// HPKE Constants
//
// Maximum sizes across all supported ciphersuites.
// These are used for stack-allocated buffers in the implementation.
//

//
// KEM-related size bounds.
//

// Max KEM shared secret size. (Nsecret)
// ML-KEM / Composite-ML-KEM is always 32 bytes.
// DHKEM shared secrets: P-256=32, P-384=48, P-521=64, X25519=32
#define SYMCRYPT_HPKE_KEM_MAX_SHARED_SECRET_SIZE        (64)

// Max KEM encapsulated secret size. (Nenc)
// MLKEM1024-P384 ciphertext is 1665 bytes (the largest).
#define SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE    (1665)

// Max KEM public key size. (Npk)
// MLKEM1024-P384 public key is 1665 bytes.
#define SYMCRYPT_HPKE_KEM_MAX_PUBLIC_KEY_SIZE           (1665)

// DHKEM HPKE-level shared_secret sizes. (Nsecret)
#define SYMCRYPT_HPKE_DHKEM_P256_SHARED_SECRET_SIZE     (32)
#define SYMCRYPT_HPKE_DHKEM_P384_SHARED_SECRET_SIZE     (48)
#define SYMCRYPT_HPKE_DHKEM_P521_SHARED_SECRET_SIZE     (64)
#define SYMCRYPT_HPKE_DHKEM_X25519_SHARED_SECRET_SIZE   (32)

// DHKEM private scalar and IETF public-key encoding sizes.
#define SYMCRYPT_HPKE_DHKEM_P256_SCALAR_SIZE            (32)
#define SYMCRYPT_HPKE_DHKEM_P384_SCALAR_SIZE            (48)
#define SYMCRYPT_HPKE_DHKEM_P521_SCALAR_SIZE            (66)
#define SYMCRYPT_HPKE_DHKEM_X25519_SCALAR_SIZE          (32)

#define SYMCRYPT_HPKE_DHKEM_SEC1_TAG_SIZE               (1)
#define SYMCRYPT_HPKE_DHKEM_P256_PUBLIC_KEY_SIZE        (SYMCRYPT_HPKE_DHKEM_SEC1_TAG_SIZE + 2 * SYMCRYPT_HPKE_DHKEM_P256_SCALAR_SIZE)
#define SYMCRYPT_HPKE_DHKEM_P384_PUBLIC_KEY_SIZE        (SYMCRYPT_HPKE_DHKEM_SEC1_TAG_SIZE + 2 * SYMCRYPT_HPKE_DHKEM_P384_SCALAR_SIZE)
#define SYMCRYPT_HPKE_DHKEM_P521_PUBLIC_KEY_SIZE        (SYMCRYPT_HPKE_DHKEM_SEC1_TAG_SIZE + 2 * SYMCRYPT_HPKE_DHKEM_P521_SCALAR_SIZE)
#define SYMCRYPT_HPKE_DHKEM_X25519_PUBLIC_KEY_SIZE      (32)

//
// KDF-related size bounds.
//

// Max KDF hash output size. (Nh)
// SHA-256=32, SHA-384=48, SHA-512=64, SHAKE128=32, SHAKE256=64
#define SYMCRYPT_HPKE_KDF_MAX_HASH_SIZE                 (64)

// Maximum caller-provided IKM size for LabeledExtract.
// Applies to info, psk, and psk_id inputs; RFC 9180 imposes no explicit limit.
#define SYMCRYPT_HPKE_KDF_MAX_IKM_SIZE                  (128)

//
// AEAD-related size bounds.
//

// Max AEAD key size. (Nk)
// AES-128-GCM=16, AES-256-GCM=32, ChaCha20Poly1305=32
#define SYMCRYPT_HPKE_AEAD_MAX_KEY_SIZE                 (32)

// Max AEAD nonce size. (Nn)
// All currently supported AEADs use 12-byte nonces.
#define SYMCRYPT_HPKE_AEAD_MAX_NONCE_SIZE               (12)

// Max AEAD authentication tag size. (Nt)
// AES-128-GCM=16, AES-256-GCM=16, ChaCha20-Poly1305=16.
#define SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE                 (16)

// HPKE version label
#define SYMCRYPT_HPKE_VERSION_LABEL         "HPKE-v1"
#define SYMCRYPT_HPKE_VERSION_LABEL_SIZE    (7)

// HPKE suite_id prefix sizes
#define SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE     (5)     // "KEM" + 2 bytes kem_id
#define SYMCRYPT_HPKE_SUITE_ID_SIZE         (10)    // "HPKE" + 2 + 2 + 2

// Sequence number limit: 2^64 - 2^32. Leaves 2^32 headroom above the per-call
// counter for the unconditional-increment race documented in SymCryptHpkeSeal.
#define SYMCRYPT_HPKE_SEQ_LIMIT             (0xFFFFFFFF00000000ULL)

// HPKE modes
#define SYMCRYPT_HPKE_MODE_BASE             (0x00)
#define SYMCRYPT_HPKE_MODE_PSK              (0x01)

//
// KEM parameters
//
// Each KEM type has a corresponding parameter entry that is looked up by KEM ID.
// KEM operations are dispatched via switch statements with direct calls to avoid
// indirect branches (speculative execution concerns, CFG overhead).
//
// Size fields are UINT16: these are all internal, ciphersuite-defined sizes
// (max observed ~3.2KB for full-form ML-KEM-1024 private keys, comfortably under
// 65535). Storing as UINT16 keeps the params struct compact for cache locality
// and is consistent with other I2OSP(L,2)-encoded fields in HPKE.
//
typedef struct SYMCRYPT_HPKE_KEM_PARAMS
{
    UINT16      kemId;
    UINT16      cbSharedSecret;             // Nsecret (KEM shared secret size; encoded as I2OSP(L,2) by LabeledExpand)
    UINT16      cbEnc;                      // Nenc (encapsulated secret size)
    UINT16      cbPublicKey;                // Npk (public key size)
    UINT16      cbPrivateKey;               // Nsk (private key size)
} SYMCRYPT_HPKE_KEM_PARAMS;

typedef const SYMCRYPT_HPKE_KEM_PARAMS* PCSYMCRYPT_HPKE_KEM_PARAMS;

// Opaque DHKEM key state, defined in hpke_kem_dhkem.c.
typedef struct SYMCRYPT_HPKE_DHKEMKEY SYMCRYPT_HPKE_DHKEMKEY;
typedef       SYMCRYPT_HPKE_DHKEMKEY * PSYMCRYPT_HPKE_DHKEMKEY;
typedef const SYMCRYPT_HPKE_DHKEMKEY * PCSYMCRYPT_HPKE_DHKEMKEY;

//
// HPKE AEAD parameters
//
typedef struct SYMCRYPT_HPKE_AEAD_PARAMS
{
    UINT16  aeadId;
    UINT16  cbKey;      // Nk  (AEAD key size; encoded as I2OSP(L,2) by LabeledExpand)
    UINT16  cbNonce;    // Nn  (AEAD nonce size; encoded as I2OSP(L,2) by LabeledExpand)
    UINT16  cbTag;      // Nt  (AEAD authentication tag size)
} SYMCRYPT_HPKE_AEAD_PARAMS;

typedef const SYMCRYPT_HPKE_AEAD_PARAMS* PCSYMCRYPT_HPKE_AEAD_PARAMS;

//
// SYMCRYPT_HPKEKEY internal structure
//
SYMCRYPT_ASYM_ALIGN_STRUCT SYMCRYPT_HPKEKEY
{
    SYMCRYPT_HPKE_CIPHERSUITE   ciphersuite;
    SYMCRYPT_HPKE_KEM_PARAMS    kemParams;

    // KEM-specific key data (opaque, managed via switch dispatch).
    // For ML-KEM / Composite-ML-KEM: PSYMCRYPT_MLKEMKEY / PSYMCRYPT_COMPOSITE_MLKEMKEY.
    // For DHKEM: HPKE-private PSYMCRYPT_HPKE_DHKEMKEY.
    PVOID                       pKemKeyData;

    SYMCRYPT_MAGIC_FIELD
};

//
// HPKE context lifecycle / role.
//
// UNINITIALIZED must be 0 so that a freshly wiped (zeroed) context is
// uninitialized. SymCryptHpkeFinishSetup sets the field once, to the role the
// context was established with; Seal requires SENDER, Open requires RECIPIENT,
// and SecretExport/OpenUnordered accept either.
//
typedef enum SYMCRYPT_HPKE_CONTEXT_STATE {
    SYMCRYPT_HPKE_CONTEXT_STATE_UNINITIALIZED = 0,
    SYMCRYPT_HPKE_CONTEXT_STATE_SENDER        = 1,
    SYMCRYPT_HPKE_CONTEXT_STATE_RECIPIENT     = 2,
} SYMCRYPT_HPKE_CONTEXT_STATE;

//
// SYMCRYPT_HPKECONTEXT internal structure
//
// Concurrency contract:
//
//   - All ciphersuite/parameter fields (ciphersuite, aeadParams,
//     cbKey, cbNonce) are write-once during ContextInit.
//   - All derived key material (key, baseNonce, exporterSecret), the context
//     role (state), and any cached AEAD expanded keys (gcmExpandedKey,
//     fGcmKeyExpanded; and any future per-AEAD cache, e.g. ChaCha20-Poly1305)
//     are write-once during SymCryptHpkeFinishSetup (called from SetupSender /
//     SetupRecipient).
//   - After Setup returns successfully, the only mutable field is seqNum.
//     seqNum is mutated only by Seal (atomic) and Open / ordered (non-atomic;
//     Open(ordered) is documented thread-unsafe). OpenUnordered and
//     SecretExport never touch seqNum.
//
// Consequence: a fully-initialized context is safe to share across threads
// for any combination of concurrent OpenUnordered + SecretExport + Seal calls.
// Open(ordered) is the only API that must be serialized externally.
//
// When adding a new cached AEAD field (e.g. ChaCha20-Poly1305 expanded key),
// preserve this contract: write only in KeySchedule, never mutate later.
//
SYMCRYPT_ASYM_ALIGN_STRUCT SYMCRYPT_HPKECONTEXT
{
    SYMCRYPT_HPKE_CIPHERSUITE       ciphersuite;
    SYMCRYPT_HPKE_AEAD_PARAMS       aeadParams;

    // Derived key material from key schedule
    BYTE                            key[SYMCRYPT_HPKE_AEAD_MAX_KEY_SIZE];
    BYTE                            baseNonce[SYMCRYPT_HPKE_AEAD_MAX_NONCE_SIZE];
    BYTE                            exporterSecret[SYMCRYPT_HPKE_KDF_MAX_HASH_SIZE];

    // Cached AEAD expanded key (AES-GCM only; ChaCha20-Poly1305 uses raw key)
    SYMCRYPT_GCM_EXPANDED_KEY       gcmExpandedKey;
    BOOLEAN                         fGcmKeyExpanded;

    // Sequence number (atomically incremented for Seal). 8-byte aligned
    // because UINT64's default alignment is only 4 bytes on 32-bit targets;
    // SYMCRYPT_ATOMIC_ADD64_POST_RELAXED requires 8-byte alignment to avoid
    // a torn / lock-bus-traffic penalty (-Watomic-alignment on Clang x86).
    SYMCRYPT_ALIGN_AT(8) UINT64     seqNum;

    // Context lifecycle / role, set once by SymCryptHpkeFinishSetup.
    // UNINITIALIZED (0) until Setup; SENDER or RECIPIENT afterward.
    SYMCRYPT_HPKE_CONTEXT_STATE     state;

    SYMCRYPT_MAGIC_FIELD
};

//
// Internal helper function declarations
//

// Look up KEM parameters from KEM ID.
PCSYMCRYPT_HPKE_KEM_PARAMS
SYMCRYPT_CALL
SymCryptHpkeKemParamsFromId(
    SYMCRYPT_HPKE_KEM_ID    kemId );

// DHKEM key lifecycle / KEM operations. SYMCRYPT_HPKE_DHKEMKEY is defined
// in hpke_kem_dhkem.c and carried opaquely in pKemKeyData.
PSYMCRYPT_HPKE_DHKEMKEY
SYMCRYPT_CALL
SymCryptHpkeDhkemkeyAllocate(
    UINT16  kemId );

VOID
SYMCRYPT_CALL
SymCryptHpkeDhkemkeyFree(
    _Inout_ PSYMCRYPT_HPKE_DHKEMKEY pkDhkemkey );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeDhkemkeyGenerate(
    _Inout_ PSYMCRYPT_HPKE_DHKEMKEY pkDhkemkey,
            UINT32                  flags );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeDhkemkeySetValue(
    _In_reads_bytes_( cbSrc )   PCBYTE                  pbSrc,
                                SIZE_T                  cbSrc,
                                SYMCRYPT_HPKEKEY_FORMAT hpkeKeyFormat,
                                UINT32                  flags,
    _Inout_                     PSYMCRYPT_HPKE_DHKEMKEY pkDhkemkey );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeDhkemkeyGetValue(
    _In_                        PCSYMCRYPT_HPKE_DHKEMKEY    pkDhkemkey,
    _Out_writes_bytes_( cbDst ) PBYTE                       pbDst,
                                SIZE_T                      cbDst,
                                SYMCRYPT_HPKEKEY_FORMAT     hpkeKeyFormat,
                                UINT32                      flags );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeDhkemDeriveKeyPair(
    _In_reads_bytes_( cbIkm )   PCBYTE                  pbIkm,
                                SIZE_T                  cbIkm,
    _Inout_                     PSYMCRYPT_HPKE_DHKEMKEY pkDhkemkey );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeDhkemEncapsulate(
    _In_                                        PCSYMCRYPT_HPKEKEY  pkRecipientKey,
    _Out_writes_bytes_( cbSharedSecret )        PBYTE               pbSharedSecret,
                                                UINT16              cbSharedSecret,
    _Out_writes_bytes_( cbEnc )                 PBYTE               pbEnc,
                                                SIZE_T              cbEnc );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeDhkemEncapsulateEx(
    _In_                                        PCSYMCRYPT_HPKEKEY  pkRecipientKey,
    _In_reads_bytes_opt_( cbIkmE )              PCBYTE              pbIkmE,
                                                SIZE_T              cbIkmE,
    _Out_writes_bytes_( cbSharedSecret )        PBYTE               pbSharedSecret,
                                                UINT16              cbSharedSecret,
    _Out_writes_bytes_( cbEnc )                 PBYTE               pbEnc,
                                                SIZE_T              cbEnc );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeDhkemDecapsulate(
    _In_                                        PCSYMCRYPT_HPKEKEY  pkRecipientKey,
    _In_reads_bytes_( cbEnc )                   PCBYTE              pbEnc,
                                                SIZE_T              cbEnc,
    _Out_writes_bytes_( cbSharedSecret )        PBYTE               pbSharedSecret,
                                                UINT16              cbSharedSecret );

// Get AEAD parameters from AEAD ID.
PCSYMCRYPT_HPKE_AEAD_PARAMS
SYMCRYPT_CALL
SymCryptHpkeAeadParamsFromId( SYMCRYPT_HPKE_AEAD_ID aeadId );

// Validate a ciphersuite (KEM, KDF and AEAD must all be supported) and return
// the corresponding internal params structs.
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeValidateCiphersuite(
                SYMCRYPT_HPKE_CIPHERSUITE   params,
    _Out_opt_   SYMCRYPT_HPKE_KEM_PARAMS*   pKemParams,
    _Out_opt_   SYMCRYPT_HPKE_AEAD_PARAMS*  pAeadParams );

// suite_id = "KEM" || I2OSP(kem_id, 2).
VOID
SYMCRYPT_CALL
SymCryptHpkeBuildKemSuiteId(
                                                            UINT16  kemId,
    _Out_writes_bytes_( SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE )   PBYTE   pbSuiteId );

// Get the hash output size (Nh) for the KDF from its ID.
UINT16
SYMCRYPT_CALL
SymCryptHpkeKdfOutputSizeFromId(
    SYMCRYPT_HPKE_KDF_ID    kdfId );

// LabeledExtract(salt, label, ikm) per draft-ietf-hpke-hpke-03. Two-stage path.
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeLabeledExtract(
                                    SYMCRYPT_HPKE_KDF_ID    kdfId,
    _In_reads_bytes_( cbSuiteId )   PCBYTE                  pbSuiteId,
                                    SIZE_T                  cbSuiteId,
    _In_reads_bytes_opt_( cbSalt )  PCBYTE                  pbSalt,
                                    SIZE_T                  cbSalt,
    _In_reads_bytes_( cbLabel )     PCBYTE                  pbLabel,
                                    SIZE_T                  cbLabel,
    _In_reads_bytes_opt_( cbIkm )   PCBYTE                  pbIkm,
                                    SIZE_T                  cbIkm,
    _Out_writes_bytes_( cbPrk )     PBYTE                   pbPrk,
                                    SIZE_T                  cbPrk );

// LabeledExpand(prk, label, info, L) per draft-ietf-hpke-hpke-03. Two-stage path.
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeLabeledExpand(
                                    SYMCRYPT_HPKE_KDF_ID    kdfId,
    _In_reads_bytes_( cbSuiteId )   PCBYTE                  pbSuiteId,
                                    SIZE_T                  cbSuiteId,
    _In_reads_bytes_( cbPrk )       PCBYTE                  pbPrk,
                                    SIZE_T                  cbPrk,
    _In_reads_bytes_( cbLabel )     PCBYTE                  pbLabel,
                                    SIZE_T                  cbLabel,
    _In_reads_bytes_opt_( cbInfo )  PCBYTE                  pbInfo,
                                    SIZE_T                  cbInfo,
    _Out_writes_bytes_( cbResult )  PBYTE                   pbResult,
                                    UINT16                  cbResult );

// LabeledDerive_OneStage per draft-ietf-hpke-hpke-03 for SHAKE-backed KDFs.
VOID
SYMCRYPT_CALL
SymCryptHpkeLabeledDeriveOneStage(
                                        SYMCRYPT_HPKE_KDF_ID    kdfId,
    _In_reads_bytes_( cbSuiteId )       PCBYTE                  pbSuiteId,
                                        SIZE_T                  cbSuiteId,
    _In_reads_bytes_( cbIkm )           PCBYTE                  pbIkm,
                                        SIZE_T                  cbIkm,
    _In_reads_bytes_( cbLabel )         PCBYTE                  pbLabel,
                                        UINT16                  cbLabel,
    _In_reads_bytes_opt_( cbContext )   PCBYTE                  pbContext,
                                        SIZE_T                  cbContext,
    _Out_writes_bytes_( cbResult )      PBYTE                   pbResult,
                                        UINT16                  cbResult );

// KEM Encapsulate / Decapsulate dispatch helpers. These return the HPKE-level
// shared_secret; DHKEM's raw DH output and ExtractAndExpand step are internal
// to the DHKEM helper. Caller is responsible for ensuring output buffer sizes
// match pkHpkekey->kemParams.cbSharedSecret and pkHpkekey->kemParams.cbEnc.
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeKemEncapsulate(
    _In_                                    PCSYMCRYPT_HPKEKEY  pkHpkekey,
    _Out_writes_bytes_( cbSharedSecret )    PBYTE               pbSharedSecret,
                                            UINT16              cbSharedSecret,
    _Out_writes_bytes_( cbEnc )             PBYTE               pbEnc,
                                            SIZE_T              cbEnc );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeKemDecapsulate(
    _In_                                    PCSYMCRYPT_HPKEKEY  pkHpkekey,
    _In_reads_bytes_( cbEnc )               PCBYTE              pbEnc,
                                            SIZE_T              cbEnc,
    _Out_writes_bytes_( cbSharedSecret )    PBYTE               pbSharedSecret,
                                            UINT16              cbSharedSecret );

// CombineSecrets paths used by the HPKE key schedule.
VOID
SYMCRYPT_CALL
SymCryptHpkeCombineSecretsOneStage(
    _Inout_                             PSYMCRYPT_HPKECONTEXT   pHpkeContext,
                                        BYTE                    mode,
    _In_reads_bytes_( cbSharedSecret )  PCBYTE                  pbSharedSecret,
                                        UINT16                  cbSharedSecret,
    _In_reads_bytes_opt_( cbInfo )      PCBYTE                  pbInfo,
                                        UINT16                  cbInfo,
    _In_reads_bytes_opt_( cbPsk )       PCBYTE                  pbPsk,
                                        UINT16                  cbPsk,
    _In_reads_bytes_opt_( cbPskId )     PCBYTE                  pbPskId,
                                        UINT16                  cbPskId );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeCombineSecretsTwoStage(
    _Inout_                             PSYMCRYPT_HPKECONTEXT   pHpkeContext,
                                        BYTE                    mode,
    _In_reads_bytes_( cbSharedSecret )  PCBYTE                  pbSharedSecret,
                                        UINT16                  cbSharedSecret,
    _In_reads_bytes_opt_( cbInfo )      PCBYTE                  pbInfo,
                                        UINT16                  cbInfo,
    _In_reads_bytes_opt_( cbPsk )       PCBYTE                  pbPsk,
                                        UINT16                  cbPsk,
    _In_reads_bytes_opt_( cbPskId )     PCBYTE                  pbPskId,
                                        UINT16                  cbPskId );

// Finish HPKE sender/recipient setup given a precomputed KEM shared secret.
// Used after Encap/Decap by SymCryptHpkeSetupSender / SymCryptHpkeSetupRecipient.
// role must be SYMCRYPT_HPKE_CONTEXT_STATE_SENDER or _RECIPIENT; it becomes the
// context's role on success.
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeFinishSetup(
    _Inout_                             PSYMCRYPT_HPKECONTEXT       pHpkeContext,
                                        SYMCRYPT_HPKE_CONTEXT_STATE role,
    _In_reads_bytes_opt_( cbInfo )      PCBYTE                      pbInfo,
                                        SIZE_T                      cbInfo,
    _In_reads_bytes_opt_( cbPsk )       PCBYTE                      pbPsk,
                                        SIZE_T                      cbPsk,
    _In_reads_bytes_opt_( cbPskId )     PCBYTE                      pbPskId,
                                        SIZE_T                      cbPskId,
    _In_reads_bytes_( cbSharedSecret )  PCBYTE                      pbSharedSecret,
                                        UINT16                      cbSharedSecret );
