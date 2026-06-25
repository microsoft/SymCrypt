//
// hpke_kdf.c
//
// HPKE KDF primitives and the key-schedule support that composes them:
// LabeledExtract/LabeledExpand (two-stage HKDF) and the OneStage SHAKE-backed
// equivalent, plus suite_id construction, CombineSecrets_{One,Two}Stage, and
// SecretExport.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

#include "hpke_internal.h"

static PCSYMCRYPT_MAC
SYMCRYPT_CALL
SymCryptHpkeHkdfMacFromId(
    SYMCRYPT_HPKE_KDF_ID    kdfId )
{
    switch ( kdfId )
    {
    case SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256:
        return SymCryptGetMacAlgorithm( SYMCRYPT_MAC_ID_HMAC_SHA256 );
    case SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384:
        return SymCryptGetMacAlgorithm( SYMCRYPT_MAC_ID_HMAC_SHA384 );
    case SYMCRYPT_HPKE_KDF_ID_HKDF_SHA512:
        return SymCryptGetMacAlgorithm( SYMCRYPT_MAC_ID_HMAC_SHA512 );
    default:
        SYMCRYPT_ASSERT( FALSE );
        return NULL;
    }
}

//
// Get the hash output size (Nh) for the KDF from its ID.
//
UINT16
SYMCRYPT_CALL
SymCryptHpkeKdfOutputSizeFromId(
    SYMCRYPT_HPKE_KDF_ID    kdfId )
{
    switch ( kdfId )
    {
    case SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256:  return 32;
    case SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384:  return 48;
    case SYMCRYPT_HPKE_KDF_ID_HKDF_SHA512:  return 64;
    case SYMCRYPT_HPKE_KDF_ID_SHAKE128:     return 32;
    case SYMCRYPT_HPKE_KDF_ID_SHAKE256:     return 64;
    default:
        SYMCRYPT_ASSERT( FALSE );
        return 0;
    }
}

VOID
SYMCRYPT_CALL
SymCryptHpkeBuildKemSuiteId(
                                                            UINT16  kemId,
    _Out_writes_bytes_( SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE )   PBYTE   pbSuiteId )
{
    // suite_id = "KEM" || I2OSP(kem_id, 2)
    memcpy( pbSuiteId, "KEM", 3 );
    SYMCRYPT_STORE_MSBFIRST16( pbSuiteId + 3, kemId );
}

static VOID
SYMCRYPT_CALL
SymCryptHpkeBuildHpkeSuiteId(
                                                        UINT16  kemId,
                                                        UINT16  kdfId,
                                                        UINT16  aeadId,
    _Out_writes_bytes_( SYMCRYPT_HPKE_SUITE_ID_SIZE )   PBYTE   pbSuiteId )
{
    // suite_id = "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)
    memcpy( pbSuiteId, "HPKE", 4 );
    SYMCRYPT_STORE_MSBFIRST16( pbSuiteId + 4, kemId );
    SYMCRYPT_STORE_MSBFIRST16( pbSuiteId + 6, kdfId );
    SYMCRYPT_STORE_MSBFIRST16( pbSuiteId + 8, aeadId );
}

//
// LabeledExtract / LabeledExpand: two-stage HKDF wrappers. SHAKE-based KDFs
// use the OneStage path below.
//
//   Longest current label is "shared_secret" (13 chars).
//
#define SYMCRYPT_HPKE_MAX_LABEL_SIZE        (13)

//
// labeled_ikm = "HPKE-v1" || suite_id || label || ikm
// Maximum: version(7) + suite_id(10) + label(13) + ikm(128) = 158
//
#define SYMCRYPT_HPKE_LABELED_IKM_MAX \
    (SYMCRYPT_HPKE_VERSION_LABEL_SIZE + SYMCRYPT_HPKE_SUITE_ID_SIZE + SYMCRYPT_HPKE_MAX_LABEL_SIZE + SYMCRYPT_HPKE_KDF_MAX_IKM_SIZE)

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
                                    SIZE_T                  cbPrk )
{
    SYMCRYPT_ERROR scError;
    BYTE labeledIkm[SYMCRYPT_HPKE_LABELED_IKM_MAX];

    if ( cbIkm > SYMCRYPT_HPKE_KDF_MAX_IKM_SIZE )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    SYMCRYPT_ASSERT( cbSuiteId <= SYMCRYPT_HPKE_SUITE_ID_SIZE );
    SYMCRYPT_ASSERT( cbLabel <= SYMCRYPT_HPKE_MAX_LABEL_SIZE );

    //
    // Build labeled_ikm = "HPKE-v1" || suite_id || label || ikm
    //
    PBYTE pbCurr = labeledIkm;

    memcpy( pbCurr, SYMCRYPT_HPKE_VERSION_LABEL, SYMCRYPT_HPKE_VERSION_LABEL_SIZE );
    pbCurr += SYMCRYPT_HPKE_VERSION_LABEL_SIZE;

    memcpy( pbCurr, pbSuiteId, cbSuiteId );
    pbCurr += cbSuiteId;

    memcpy( pbCurr, pbLabel, cbLabel );
    pbCurr += cbLabel;

    if ( cbIkm > 0 )
    {
        memcpy( pbCurr, pbIkm, cbIkm );
        pbCurr += cbIkm;
    }

    SIZE_T cbLabeledIkm = (SIZE_T)( pbCurr - labeledIkm );
    SYMCRYPT_ASSERT( cbLabeledIkm <= sizeof(labeledIkm) );

    //
    // Extract(salt, labeled_ikm) via SymCrypt HKDF API.
    // When pbSalt is NULL and cbSalt is 0, SymCryptHkdfExtractPrk
    // uses a string of zeroes of length HashLen per the HMAC specification.
    //
    scError = SymCryptHkdfExtractPrk(
        SymCryptHpkeHkdfMacFromId( kdfId ), labeledIkm, cbLabeledIkm, pbSalt, cbSalt, pbPrk, cbPrk );

cleanup:
    SymCryptWipeKnownSize( labeledIkm, sizeof(labeledIkm) );
    return scError;
}


//
// labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info
// Prefix max: 2 + version(7) + suite_id(10) + label(13) = 32. Caller info up
// to SYMCRYPT_HPKE_MAX_INFO_SIZE; small info uses the stack buffer below,
// larger info heap-allocates.
//
#define SYMCRYPT_HPKE_LABELED_INFO_PREFIX_MAX \
    (2 + SYMCRYPT_HPKE_VERSION_LABEL_SIZE + SYMCRYPT_HPKE_SUITE_ID_SIZE + SYMCRYPT_HPKE_MAX_LABEL_SIZE)

#define SYMCRYPT_HPKE_LABELED_INFO_STACK_THRESHOLD  (128)

#define SYMCRYPT_HPKE_LABELED_INFO_STACK_SIZE \
    (SYMCRYPT_HPKE_LABELED_INFO_PREFIX_MAX + SYMCRYPT_HPKE_LABELED_INFO_STACK_THRESHOLD)

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
                                    UINT16                  cbResult )
{
    SYMCRYPT_ERROR scError;
    SYMCRYPT_HKDF_EXPANDED_KEY hkdfKey;
    BYTE stackBuf[SYMCRYPT_HPKE_LABELED_INFO_STACK_SIZE];
    PBYTE pbLabeledInfo = NULL;
    PBYTE pbHeapBuf = NULL;
    SIZE_T cbLabeledInfo = 0;

    if ( cbInfo > SYMCRYPT_HPKE_MAX_INFO_SIZE )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    SYMCRYPT_ASSERT( cbLabel <= SYMCRYPT_HPKE_MAX_LABEL_SIZE );

    //
    // Compute labeled_info size and select stack or heap buffer
    //
    cbLabeledInfo = 2 + SYMCRYPT_HPKE_VERSION_LABEL_SIZE + cbSuiteId + cbLabel + cbInfo;

    if ( cbLabeledInfo <= sizeof(stackBuf) )
    {
        pbLabeledInfo = stackBuf;
    }
    else
    {
        pbHeapBuf = (PBYTE) SymCryptCallbackAlloc( cbLabeledInfo );
        if ( pbHeapBuf == NULL )
        {
            scError = SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
            goto cleanup;
        }
        pbLabeledInfo = pbHeapBuf;
    }

    //
    // Build labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info
    //
    PBYTE pbCurr = pbLabeledInfo;

    SYMCRYPT_STORE_MSBFIRST16( pbCurr, cbResult );
    pbCurr += 2;

    memcpy( pbCurr, SYMCRYPT_HPKE_VERSION_LABEL, SYMCRYPT_HPKE_VERSION_LABEL_SIZE );
    pbCurr += SYMCRYPT_HPKE_VERSION_LABEL_SIZE;

    memcpy( pbCurr, pbSuiteId, cbSuiteId );
    pbCurr += cbSuiteId;

    memcpy( pbCurr, pbLabel, cbLabel );
    pbCurr += cbLabel;

    if ( cbInfo > 0 )
    {
        memcpy( pbCurr, pbInfo, cbInfo );
        pbCurr += cbInfo;
    }

    SYMCRYPT_ASSERT( (SIZE_T)( pbCurr - pbLabeledInfo ) == cbLabeledInfo );

    //
    // Expand(prk, labeled_info, L) via SymCrypt HKDF API
    //
    scError = SymCryptHkdfPrkExpandKey( &hkdfKey, SymCryptHpkeHkdfMacFromId( kdfId ), pbPrk, cbPrk );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    scError = SymCryptHkdfDerive( &hkdfKey, pbLabeledInfo, cbLabeledInfo, pbResult, cbResult );

cleanup:
    SymCryptWipeKnownSize( &hkdfKey, sizeof(hkdfKey) );
    if ( pbHeapBuf != NULL )
    {
        SymCryptWipe( pbHeapBuf, cbLabeledInfo );
        SymCryptCallbackFree( pbHeapBuf );
    }
    else
    {
        SymCryptWipeKnownSize( stackBuf, sizeof(stackBuf) );
    }
    return scError;
}


//
// One-stage KDF state and primitives for SHAKE-backed HPKE KDFs.
//

typedef union _SYMCRYPT_HPKE_ONESTAGE_STATE
{
    SYMCRYPT_SHAKE128_STATE shake128;
    SYMCRYPT_SHAKE256_STATE shake256;
} SYMCRYPT_HPKE_ONESTAGE_STATE, *PSYMCRYPT_HPKE_ONESTAGE_STATE;

static VOID
SYMCRYPT_CALL
SymCryptHpkeOneStageInit(
    _In_    SYMCRYPT_HPKE_KDF_ID            kdfId,
    _Out_   PSYMCRYPT_HPKE_ONESTAGE_STATE   pState )
{
    switch ( kdfId )
    {
    case SYMCRYPT_HPKE_KDF_ID_SHAKE128:
        SymCryptShake128Init( &pState->shake128 );
        break;

    case SYMCRYPT_HPKE_KDF_ID_SHAKE256:
        SymCryptShake256Init( &pState->shake256 );
        break;

    default:
        SYMCRYPT_ASSERT( FALSE );
        break;
    }
}

static VOID
SYMCRYPT_CALL
SymCryptHpkeOneStageAppend(
    _In_                            SYMCRYPT_HPKE_KDF_ID            kdfId,
    _Inout_                         PSYMCRYPT_HPKE_ONESTAGE_STATE   pState,
    _In_reads_bytes_( cbData )      PCBYTE                          pbData,
                                    SIZE_T                          cbData )
{
    switch ( kdfId )
    {
    case SYMCRYPT_HPKE_KDF_ID_SHAKE128:
        SymCryptShake128Append( &pState->shake128, pbData, cbData );
        break;

    case SYMCRYPT_HPKE_KDF_ID_SHAKE256:
        SymCryptShake256Append( &pState->shake256, pbData, cbData );
        break;

    default:
        SYMCRYPT_ASSERT( FALSE );
        break;
    }
}

static VOID
SYMCRYPT_CALL
SymCryptHpkeOneStageExtract(
    _In_                                SYMCRYPT_HPKE_KDF_ID            kdfId,
    _Inout_                             PSYMCRYPT_HPKE_ONESTAGE_STATE   pState,
    _Out_writes_bytes_( cbResult )      PBYTE                           pbResult,
                                        SIZE_T                          cbResult,
                                        BOOLEAN                         bWipe )
{
    switch ( kdfId )
    {
    case SYMCRYPT_HPKE_KDF_ID_SHAKE128:
        SymCryptShake128Extract( &pState->shake128, pbResult, cbResult, bWipe );
        break;

    case SYMCRYPT_HPKE_KDF_ID_SHAKE256:
        SymCryptShake256Extract( &pState->shake256, pbResult, cbResult, bWipe );
        break;

    default:
        SYMCRYPT_ASSERT( FALSE );
        break;
    }
}

//
// LabeledDerive_OneStage from draft-ietf-hpke-hpke-03:
//   KDF( ikm || "HPKE-v1" || suite_id ||
//        I2OSP(len(label), 2) || label || I2OSP(L, 2) || context, L )
//
VOID
SYMCRYPT_CALL
SymCryptHpkeLabeledDeriveOneStage(
                                        SYMCRYPT_HPKE_KDF_ID            kdfId,
    _In_reads_bytes_( cbSuiteId )       PCBYTE                          pbSuiteId,
                                        SIZE_T                          cbSuiteId,
    _In_reads_bytes_( cbIkm )           PCBYTE                          pbIkm,
                                        SIZE_T                          cbIkm,
    _In_reads_bytes_( cbLabel )         PCBYTE                          pbLabel,
                                        UINT16                          cbLabel,
    _In_reads_bytes_opt_( cbContext )   PCBYTE                          pbContext,
                                        SIZE_T                          cbContext,
    _Out_writes_bytes_( cbResult )      PBYTE                           pbResult,
                                        UINT16                          cbResult )
{
    SYMCRYPT_HPKE_ONESTAGE_STATE state;
    BYTE lengthBuf[2];

    SymCryptHpkeOneStageInit( kdfId, &state );

    if ( cbIkm > 0 )
    {
        SymCryptHpkeOneStageAppend( kdfId, &state, pbIkm, cbIkm );
    }

    SymCryptHpkeOneStageAppend( kdfId, &state, (PCBYTE) SYMCRYPT_HPKE_VERSION_LABEL, SYMCRYPT_HPKE_VERSION_LABEL_SIZE );
    SymCryptHpkeOneStageAppend( kdfId, &state, pbSuiteId, cbSuiteId );

    SYMCRYPT_STORE_MSBFIRST16( lengthBuf, cbLabel );
    SymCryptHpkeOneStageAppend( kdfId, &state, lengthBuf, 2 );
    if ( cbLabel > 0 )
    {
        SymCryptHpkeOneStageAppend( kdfId, &state, pbLabel, cbLabel );
    }

    SYMCRYPT_STORE_MSBFIRST16( lengthBuf, cbResult );
    SymCryptHpkeOneStageAppend( kdfId, &state, lengthBuf, 2 );

    if ( cbContext > 0 )
    {
        SymCryptHpkeOneStageAppend( kdfId, &state, pbContext, cbContext );
    }

    SymCryptHpkeOneStageExtract( kdfId, &state, pbResult, cbResult, TRUE );
}

//
// CombineSecrets_OneStage from draft-ietf-hpke-hpke-03 for SHAKE-backed KDFs.
// Output is consumed in order as key, base_nonce, and exporter_secret.
//
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
                                        UINT16                  cbPskId )
{
    SYMCRYPT_HPKE_KDF_ID kdfId = (SYMCRYPT_HPKE_KDF_ID) pHpkeContext->ciphersuite.kdfId;
    UINT16 cbKdfOutput = SymCryptHpkeKdfOutputSizeFromId( kdfId );
    UINT16 cbSecret = pHpkeContext->aeadParams.cbKey + pHpkeContext->aeadParams.cbNonce + cbKdfOutput;
    BYTE lengthBuf[2];
    BYTE hpkeSuiteId[SYMCRYPT_HPKE_SUITE_ID_SIZE];
    SYMCRYPT_HPKE_ONESTAGE_STATE state;

    SymCryptHpkeBuildHpkeSuiteId(
        pHpkeContext->ciphersuite.kemId, pHpkeContext->ciphersuite.kdfId,
        pHpkeContext->ciphersuite.aeadId, hpkeSuiteId );

    //
    // CombineSecrets_OneStage from draft-ietf-hpke-hpke-03:
    //   secrets = I2OSP(len(psk), 2) || psk ||
    //             I2OSP(len(shared_secret), 2) || shared_secret
    //   context = mode || I2OSP(len(psk_id), 2) || psk_id ||
    //             I2OSP(len(info), 2) || info
    //   L = Nk + Nn + Nh
    //   secret = LabeledDerive(suite_id, secrets, "secret", context, L)
    // The output is consumed in order as key, base_nonce, and exporter_secret.
    //

    SymCryptHpkeOneStageInit( kdfId, &state );

    SYMCRYPT_STORE_MSBFIRST16( lengthBuf, (UINT16) cbPsk );
    SymCryptHpkeOneStageAppend( kdfId, &state, lengthBuf, 2 );
    if ( cbPsk > 0 )
    {
        SymCryptHpkeOneStageAppend( kdfId, &state, pbPsk, cbPsk );
    }

    SYMCRYPT_STORE_MSBFIRST16( lengthBuf, (UINT16) cbSharedSecret );
    SymCryptHpkeOneStageAppend( kdfId, &state, lengthBuf, 2 );
    SymCryptHpkeOneStageAppend( kdfId, &state, pbSharedSecret, cbSharedSecret );

    SymCryptHpkeOneStageAppend( kdfId, &state, (PCBYTE) SYMCRYPT_HPKE_VERSION_LABEL, SYMCRYPT_HPKE_VERSION_LABEL_SIZE );
    SymCryptHpkeOneStageAppend( kdfId, &state, hpkeSuiteId, SYMCRYPT_HPKE_SUITE_ID_SIZE );
    SYMCRYPT_STORE_MSBFIRST16( lengthBuf, 6 );
    SymCryptHpkeOneStageAppend( kdfId, &state, lengthBuf, 2 );
    SymCryptHpkeOneStageAppend( kdfId, &state, (PCBYTE)"secret", 6 );
    SYMCRYPT_STORE_MSBFIRST16( lengthBuf, cbSecret );
    SymCryptHpkeOneStageAppend( kdfId, &state, lengthBuf, 2 );

    SymCryptHpkeOneStageAppend( kdfId, &state, &mode, sizeof(mode) );
    SYMCRYPT_STORE_MSBFIRST16( lengthBuf, (UINT16) cbPskId );
    SymCryptHpkeOneStageAppend( kdfId, &state, lengthBuf, 2 );
    if ( cbPskId > 0 )
    {
        SymCryptHpkeOneStageAppend( kdfId, &state, pbPskId, cbPskId );
    }
    SYMCRYPT_STORE_MSBFIRST16( lengthBuf, (UINT16) cbInfo );
    SymCryptHpkeOneStageAppend( kdfId, &state, lengthBuf, 2 );
    if ( cbInfo > 0 )
    {
        SymCryptHpkeOneStageAppend( kdfId, &state, pbInfo, cbInfo );
    }

    if ( pHpkeContext->aeadParams.cbKey > 0 )
    {
        SymCryptHpkeOneStageExtract( kdfId, &state, pHpkeContext->key, pHpkeContext->aeadParams.cbKey, FALSE );
    }
    if ( pHpkeContext->aeadParams.cbNonce > 0 )
    {
        SymCryptHpkeOneStageExtract( kdfId, &state, pHpkeContext->baseNonce, pHpkeContext->aeadParams.cbNonce, FALSE );
    }
    SymCryptHpkeOneStageExtract( kdfId, &state, pHpkeContext->exporterSecret, cbKdfOutput, TRUE );
}

//
// CombineSecrets_TwoStage from draft-ietf-hpke-hpke-03 for HKDF-based KDFs.
//
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
                                        UINT16                  cbPskId )
{
    SYMCRYPT_ERROR scError;
    SYMCRYPT_HPKE_KDF_ID kdfId = (SYMCRYPT_HPKE_KDF_ID) pHpkeContext->ciphersuite.kdfId;
    UINT16 cbKdfOutput = SymCryptHpkeKdfOutputSizeFromId( kdfId );

    // ks_context = mode(1) || psk_id_hash(Nh) || info_hash(Nh)
    // Maximum size: 1 + 2*64 = 129
    BYTE ksContext[1 + 2 * SYMCRYPT_HPKE_KDF_MAX_HASH_SIZE];
    UINT16 cbKsContext = 1 + 2 * cbKdfOutput;

    BYTE secret[SYMCRYPT_HPKE_KDF_MAX_HASH_SIZE];
    BYTE hpkeSuiteId[SYMCRYPT_HPKE_SUITE_ID_SIZE];

    SymCryptHpkeBuildHpkeSuiteId(
        pHpkeContext->ciphersuite.kemId, pHpkeContext->ciphersuite.kdfId,
        pHpkeContext->ciphersuite.aeadId, hpkeSuiteId );

    //
    // Step 1: psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
    //
    ksContext[0] = mode;

    scError = SymCryptHpkeLabeledExtract(
        kdfId,
        hpkeSuiteId, SYMCRYPT_HPKE_SUITE_ID_SIZE,
        NULL, 0, // empty salt
        (PCBYTE)"psk_id_hash", 11,
        pbPskId, cbPskId,
        ksContext + 1, cbKdfOutput );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    //
    // Step 2: info_hash = LabeledExtract("", "info_hash", info)
    //
    scError = SymCryptHpkeLabeledExtract(
        kdfId,
        hpkeSuiteId, SYMCRYPT_HPKE_SUITE_ID_SIZE,
        NULL, 0,
        (PCBYTE)"info_hash", 9,
        pbInfo, cbInfo,
        ksContext + 1 + cbKdfOutput, cbKdfOutput );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    //
    // Step 3: secret = LabeledExtract(shared_secret, "secret", psk)
    //
    scError = SymCryptHpkeLabeledExtract(
        kdfId,
        hpkeSuiteId, SYMCRYPT_HPKE_SUITE_ID_SIZE,
        pbSharedSecret, cbSharedSecret, // shared_secret as salt
        (PCBYTE)"secret", 6,
        pbPsk, cbPsk,
        secret, cbKdfOutput );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    //
    // Step 4: key = LabeledExpand(secret, "key", ks_context, Nk)
    //   (Skip for Export-Only mode where Nk = 0)
    //
    if ( pHpkeContext->aeadParams.cbKey > 0 )
    {
        scError = SymCryptHpkeLabeledExpand(
            kdfId,
            hpkeSuiteId, SYMCRYPT_HPKE_SUITE_ID_SIZE,
            secret, cbKdfOutput,
            (PCBYTE)"key", 3,
            ksContext, cbKsContext,
            pHpkeContext->key, pHpkeContext->aeadParams.cbKey );
        if ( scError != SYMCRYPT_NO_ERROR )
        {
            goto cleanup;
        }
    }

    //
    // Step 5: base_nonce = LabeledExpand(secret, "base_nonce", ks_context, Nn)
    //   (Skip for Export-Only mode where Nn = 0)
    //
    if ( pHpkeContext->aeadParams.cbNonce > 0 )
    {
        scError = SymCryptHpkeLabeledExpand(
            kdfId,
            hpkeSuiteId, SYMCRYPT_HPKE_SUITE_ID_SIZE,
            secret, cbKdfOutput,
            (PCBYTE)"base_nonce", 10,
            ksContext, cbKsContext,
            pHpkeContext->baseNonce, pHpkeContext->aeadParams.cbNonce );
        if ( scError != SYMCRYPT_NO_ERROR )
        {
            goto cleanup;
        }
    }

    //
    // Step 6: exporter_secret = LabeledExpand(secret, "exp", ks_context, Nh)
    //
    scError = SymCryptHpkeLabeledExpand(
        kdfId,
        hpkeSuiteId, SYMCRYPT_HPKE_SUITE_ID_SIZE,
        secret, cbKdfOutput,
        (PCBYTE)"exp", 3,
        ksContext, cbKsContext,
        pHpkeContext->exporterSecret, cbKdfOutput );

cleanup:
    SymCryptWipeKnownSize( ksContext, sizeof(ksContext) );
    SymCryptWipeKnownSize( secret, sizeof(secret) );
    return scError;
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeSecretExport(
    _In_                                        PCSYMCRYPT_HPKECONTEXT  pHpkeContext,
    _In_reads_bytes_opt_( cbExporterContext )   PCBYTE                  pbExporterContext,
                                                SIZE_T                  cbExporterContext,
    _Out_writes_bytes_( cbResult )              PBYTE                   pbResult,
                                                UINT16                  cbResult )
{
    SYMCRYPT_CHECK_MAGIC( pHpkeContext );
    SYMCRYPT_ASSERT( pbExporterContext != NULL || cbExporterContext == 0 );

    if ( pHpkeContext->state == SYMCRYPT_HPKE_CONTEXT_STATE_UNINITIALIZED )
    {
        return SYMCRYPT_INVALID_ARGUMENT;
    }

    if ( cbExporterContext > SYMCRYPT_HPKE_MAX_EXPORT_SIZE ||
         cbResult          > SYMCRYPT_HPKE_MAX_EXPORT_SIZE )
    {
        return SYMCRYPT_INVALID_ARGUMENT;
    }

    BYTE hpkeSuiteId[SYMCRYPT_HPKE_SUITE_ID_SIZE];
    SymCryptHpkeBuildHpkeSuiteId(
        pHpkeContext->ciphersuite.kemId, pHpkeContext->ciphersuite.kdfId,
        pHpkeContext->ciphersuite.aeadId, hpkeSuiteId );

    SYMCRYPT_HPKE_KDF_ID kdfId = (SYMCRYPT_HPKE_KDF_ID) pHpkeContext->ciphersuite.kdfId;

    switch ( kdfId )
    {
    case SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256:
    case SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384:
    case SYMCRYPT_HPKE_KDF_ID_HKDF_SHA512:
        return SymCryptHpkeLabeledExpand(
            kdfId,
            hpkeSuiteId, SYMCRYPT_HPKE_SUITE_ID_SIZE,
            pHpkeContext->exporterSecret,
            SymCryptHpkeKdfOutputSizeFromId( kdfId ),
            (PCBYTE)"sec", 3,
            pbExporterContext,
            cbExporterContext,
            pbResult, cbResult );

    case SYMCRYPT_HPKE_KDF_ID_SHAKE128:
    case SYMCRYPT_HPKE_KDF_ID_SHAKE256:
        SymCryptHpkeLabeledDeriveOneStage(
            kdfId,
            hpkeSuiteId, SYMCRYPT_HPKE_SUITE_ID_SIZE,
            pHpkeContext->exporterSecret,
            SymCryptHpkeKdfOutputSizeFromId( kdfId ),
            (PCBYTE)"sec", 3,
            pbExporterContext,
            cbExporterContext,
            pbResult, cbResult );
        return SYMCRYPT_NO_ERROR;

    default:
        SYMCRYPT_ASSERT( FALSE );
        return SYMCRYPT_NOT_IMPLEMENTED;
    }
}
