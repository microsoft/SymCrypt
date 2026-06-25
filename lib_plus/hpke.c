//
// HPKE (Hybrid Public Key Encryption) for SymCrypt.
//
// Implements draft-ietf-hpke-hpke-03 with DHKEM and ML-KEM support from
// draft-ietf-hpke-pq.
//
//   Modes:    Base (0x00), PSK (0x01)
//   KEMs:     DHKEM P-256/P-384/P-521/X25519, ML-KEM-{512,768,1024},
//             MLKEM768-P256, MLKEM1024-P384, MLKEM768-X25519
//   KDFs:     HKDF-SHA{256,384,512}, SHAKE128, SHAKE256
//   AEADs:    AES-{128,256}-GCM, ChaCha20-Poly1305, Export-Only
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

#include "hpke_internal.h"

//
// Initialize an HPKECONTEXT from a pre-validated ciphersuite. Used by
// HpkeContextAllocate and by the SingleShot APIs which stack-allocate the
// context.
//
static VOID
SymCryptHpkeContextInit(
    _Out_   PSYMCRYPT_HPKECONTEXT       pHpkeContext,
            SYMCRYPT_HPKE_CIPHERSUITE   ciphersuite,
            SYMCRYPT_HPKE_AEAD_PARAMS   aeadParams )
{
    SymCryptWipe( (PBYTE) pHpkeContext, sizeof(*pHpkeContext) );

    pHpkeContext->ciphersuite = ciphersuite;
    pHpkeContext->aeadParams  = aeadParams;
    // fGcmKeyExpanded (FALSE) and state (UNINITIALIZED) are already 0 from the wipe.

    SYMCRYPT_SET_MAGIC( pHpkeContext );
}

PSYMCRYPT_HPKECONTEXT
SYMCRYPT_CALL
SymCryptHpkeContextAllocate( SYMCRYPT_HPKE_CIPHERSUITE params )
{
    SYMCRYPT_ERROR scError;
    PSYMCRYPT_HPKECONTEXT pHpkeContext = NULL;
    SYMCRYPT_HPKE_AEAD_PARAMS aeadParams;

    scError = SymCryptHpkeValidateCiphersuite( params, NULL, &aeadParams );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        return NULL;
    }

    pHpkeContext = (PSYMCRYPT_HPKECONTEXT) SymCryptCallbackAlloc( sizeof(SYMCRYPT_HPKECONTEXT) );
    if ( pHpkeContext == NULL )
    {
        return NULL;
    }

    SymCryptHpkeContextInit( pHpkeContext, params, aeadParams );
    return pHpkeContext;
}

VOID
SYMCRYPT_CALL
SymCryptHpkeContextFree( _Inout_ PSYMCRYPT_HPKECONTEXT pHpkeContext )
{
    if ( pHpkeContext == NULL )
    {
        return;
    }

    SYMCRYPT_CHECK_MAGIC( pHpkeContext );

    SymCryptWipeKnownSize( (PBYTE) pHpkeContext, sizeof(SYMCRYPT_HPKECONTEXT) );
    SymCryptCallbackFree( pHpkeContext );
}

// Wipe a context's derived key material and any cached AEAD-expanded state.
static VOID
SymCryptHpkeContextWipe( _Inout_ PSYMCRYPT_HPKECONTEXT pHpkeContext )
{
    SYMCRYPT_CHECK_MAGIC( pHpkeContext );
    SymCryptHpkeContextInit(
        pHpkeContext,
        pHpkeContext->ciphersuite,
        pHpkeContext->aeadParams );
}

//
// Validate a ciphersuite (KEM, KDF and AEAD must all be supported) and return
// the corresponding internal params structs.
//
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeValidateCiphersuite(
                SYMCRYPT_HPKE_CIPHERSUITE   params,
    _Out_opt_   SYMCRYPT_HPKE_KEM_PARAMS*   pKemParams,
    _Out_opt_   SYMCRYPT_HPKE_AEAD_PARAMS*  pAeadParams )
{
    PCSYMCRYPT_HPKE_KEM_PARAMS pKemParamsFromId = SymCryptHpkeKemParamsFromId( (SYMCRYPT_HPKE_KEM_ID) params.kemId );
    if ( pKemParamsFromId == NULL )
    {
        return SYMCRYPT_NOT_IMPLEMENTED;
    }
    if ( pKemParams != NULL )
    {
        *pKemParams = *pKemParamsFromId;
    }

    // Validate the KDF is supported.
    switch ( (SYMCRYPT_HPKE_KDF_ID) params.kdfId )
    {
    case SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256:
    case SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384:
    case SYMCRYPT_HPKE_KDF_ID_HKDF_SHA512:
    case SYMCRYPT_HPKE_KDF_ID_SHAKE128:
    case SYMCRYPT_HPKE_KDF_ID_SHAKE256:
        break;

    default:
        return SYMCRYPT_NOT_IMPLEMENTED;
    }

    PCSYMCRYPT_HPKE_AEAD_PARAMS pAeadParamsFromId = SymCryptHpkeAeadParamsFromId( (SYMCRYPT_HPKE_AEAD_ID) params.aeadId );
    if ( pAeadParamsFromId == NULL )
    {
        return SYMCRYPT_NOT_IMPLEMENTED;
    }
    if ( pAeadParams != NULL )
    {
        *pAeadParams = *pAeadParamsFromId;
    }

    return SYMCRYPT_NO_ERROR;
}

//
// Common tail of SetupSender/SetupRecipient after the KEM has produced the
// shared secret. Determines mode from PSK presence and runs the key schedule.
//
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
                                        UINT16                      cbSharedSecret )
{
    SYMCRYPT_ERROR scError;
    SYMCRYPT_HPKE_KDF_ID kdfId = (SYMCRYPT_HPKE_KDF_ID) pHpkeContext->ciphersuite.kdfId;
    BYTE mode;

    SYMCRYPT_ASSERT( role == SYMCRYPT_HPKE_CONTEXT_STATE_SENDER ||
                     role == SYMCRYPT_HPKE_CONTEXT_STATE_RECIPIENT );

    // PSK and PSK ID must both be provided, or both omitted.
    if ((pbPsk != NULL && pbPskId == NULL) ||
        (pbPsk == NULL && pbPskId != NULL))
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    if ( cbInfo > SYMCRYPT_HPKE_KDF_MAX_IKM_SIZE ||
         cbPsk > SYMCRYPT_HPKE_KDF_MAX_IKM_SIZE ||
         cbPskId > SYMCRYPT_HPKE_KDF_MAX_IKM_SIZE )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    if ( pbPsk != NULL )
    {
        mode = SYMCRYPT_HPKE_MODE_PSK;
    }
    else
    {
        mode = SYMCRYPT_HPKE_MODE_BASE;
        SYMCRYPT_ASSERT( cbPsk == 0 );
        SYMCRYPT_ASSERT( pbPskId == NULL );
        SYMCRYPT_ASSERT( cbPskId == 0 );
    }

    if ( pHpkeContext->state != SYMCRYPT_HPKE_CONTEXT_STATE_UNINITIALIZED )
    {
        SymCryptHpkeContextWipe( pHpkeContext );
    }

    switch ( kdfId )
    {
    case SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256:
    case SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384:
    case SYMCRYPT_HPKE_KDF_ID_HKDF_SHA512:
        scError = SymCryptHpkeCombineSecretsTwoStage(
            pHpkeContext,
            mode,
            pbSharedSecret, cbSharedSecret,
            pbInfo, (UINT16)cbInfo,
            pbPsk, (UINT16)cbPsk,
            pbPskId, (UINT16)cbPskId );
        break;

    case SYMCRYPT_HPKE_KDF_ID_SHAKE128:
    case SYMCRYPT_HPKE_KDF_ID_SHAKE256:
        SymCryptHpkeCombineSecretsOneStage(
            pHpkeContext,
            mode,
            pbSharedSecret, cbSharedSecret,
            pbInfo, (UINT16)cbInfo,
            pbPsk, (UINT16)cbPsk,
            pbPskId, (UINT16)cbPskId );
        scError = SYMCRYPT_NO_ERROR;
        break;

    default:
        SYMCRYPT_ASSERT( FALSE );
        scError = SYMCRYPT_NOT_IMPLEMENTED;
        break;
    }

    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    SYMCRYPT_ASSERT( pHpkeContext->fGcmKeyExpanded == FALSE );
    if ( pHpkeContext->aeadParams.aeadId == SYMCRYPT_HPKE_AEAD_ID_AESGCM128 ||
         pHpkeContext->aeadParams.aeadId == SYMCRYPT_HPKE_AEAD_ID_AESGCM256 )
    {
        scError = SymCryptGcmExpandKey(
            &pHpkeContext->gcmExpandedKey,
            SymCryptGetBlockCipher( SYMCRYPT_BLOCKCIPHER_ID_AES ),
            pHpkeContext->key,
            pHpkeContext->aeadParams.cbKey );
        if ( scError != SYMCRYPT_NO_ERROR )
        {
            goto cleanup;
        }
        pHpkeContext->fGcmKeyExpanded = TRUE;
    }

    pHpkeContext->seqNum = 0;
    pHpkeContext->state = role;

cleanup:
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        SymCryptHpkeContextWipe( pHpkeContext );
    }
    return scError;
}

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
                                    UINT32                  flags )
{
    SYMCRYPT_ERROR scError;
    BYTE sharedSecret[SYMCRYPT_HPKE_KEM_MAX_SHARED_SECRET_SIZE];
    UINT16 cbSharedSecret;

    SYMCRYPT_CHECK_MAGIC( pHpkeContext );
    SYMCRYPT_CHECK_MAGIC( pkHpkekey );

    if ( (pbInfo  == NULL && cbInfo  != 0) ||
         (pbPsk   == NULL && cbPsk   != 0) ||
         (pbPskId == NULL && cbPskId != 0) )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    if ( flags != 0 )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    if ( pHpkeContext->ciphersuite.kemId  != pkHpkekey->ciphersuite.kemId ||
         pHpkeContext->ciphersuite.kdfId  != pkHpkekey->ciphersuite.kdfId ||
         pHpkeContext->ciphersuite.aeadId != pkHpkekey->ciphersuite.aeadId )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    if ( cbEnc != pkHpkekey->kemParams.cbEnc )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    cbSharedSecret = pkHpkekey->kemParams.cbSharedSecret;

    scError = SymCryptHpkeKemEncapsulate(
        pkHpkekey,
        sharedSecret, cbSharedSecret,
        pbEnc, cbEnc );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    scError = SymCryptHpkeFinishSetup(
        pHpkeContext,
        SYMCRYPT_HPKE_CONTEXT_STATE_SENDER,
        pbInfo, cbInfo,
        pbPsk, cbPsk,
        pbPskId, cbPskId,
        sharedSecret, cbSharedSecret );

cleanup:
    SymCryptWipeKnownSize( sharedSecret, sizeof(sharedSecret) );
    return scError;
}

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
                                    UINT32                  flags )
{
    SYMCRYPT_ERROR scError;
    BYTE sharedSecret[SYMCRYPT_HPKE_KEM_MAX_SHARED_SECRET_SIZE];
    UINT16 cbSharedSecret;

    SYMCRYPT_CHECK_MAGIC( pHpkeContext );
    SYMCRYPT_CHECK_MAGIC( pkHpkekey );

    if ( (pbInfo  == NULL && cbInfo  != 0) ||
         (pbPsk   == NULL && cbPsk   != 0) ||
         (pbPskId == NULL && cbPskId != 0) )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    if ( flags != 0 )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    if ( pHpkeContext->ciphersuite.kemId  != pkHpkekey->ciphersuite.kemId ||
         pHpkeContext->ciphersuite.kdfId  != pkHpkekey->ciphersuite.kdfId ||
         pHpkeContext->ciphersuite.aeadId != pkHpkekey->ciphersuite.aeadId )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    if ( cbEnc != pkHpkekey->kemParams.cbEnc )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    cbSharedSecret = pkHpkekey->kemParams.cbSharedSecret;

    scError = SymCryptHpkeKemDecapsulate(
        pkHpkekey,
        pbEnc, cbEnc,
        sharedSecret, cbSharedSecret );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    scError = SymCryptHpkeFinishSetup(
        pHpkeContext,
        SYMCRYPT_HPKE_CONTEXT_STATE_RECIPIENT,
        pbInfo, cbInfo,
        pbPsk, cbPsk,
        pbPskId, cbPskId,
        sharedSecret, cbSharedSecret );

cleanup:
    SymCryptWipeKnownSize( sharedSecret, sizeof(sharedSecret) );
    return scError;
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeSealSingleShot(
    _In_                                PCSYMCRYPT_HPKEKEY  pkHpkekey,
    _In_reads_bytes_opt_( cbInfo )      PCBYTE              pbInfo,
                                        SIZE_T              cbInfo,
    _In_reads_bytes_opt_( cbPsk )       PCBYTE              pbPsk,
                                        SIZE_T              cbPsk,
    _In_reads_bytes_opt_( cbPskId )     PCBYTE              pbPskId,
                                        SIZE_T              cbPskId,
    _In_reads_bytes_opt_( cbAuthData )  PCBYTE              pbAuthData,
                                        SIZE_T              cbAuthData,
    _In_reads_bytes_opt_( cbSrc )       PCBYTE              pbSrc,
                                        SIZE_T              cbSrc,
    _Out_writes_bytes_( cbEnc )         PBYTE               pbEnc,
                                        SIZE_T              cbEnc,
    _Out_writes_bytes_( cbDst )         PBYTE               pbDst,
                                        SIZE_T              cbDst,
                                        UINT32              flags )
{
    SYMCRYPT_ERROR scError;
    SYMCRYPT_HPKECONTEXT ctx;
    SYMCRYPT_HPKE_AEAD_PARAMS aeadParams;

    scError = SymCryptHpkeValidateCiphersuite(
        pkHpkekey->ciphersuite, NULL, &aeadParams );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        return SYMCRYPT_INVALID_ARGUMENT;
    }

    SymCryptHpkeContextInit( &ctx, pkHpkekey->ciphersuite, aeadParams );

    scError = SymCryptHpkeSetupSender(
        &ctx,
        pkHpkekey,
        pbInfo, cbInfo,
        pbPsk, cbPsk,
        pbPskId, cbPskId,
        pbEnc, cbEnc,
        flags );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    scError = SymCryptHpkeSeal(
        &ctx,
        pbAuthData, cbAuthData,
        pbSrc, cbSrc,
        pbDst, cbDst,
        NULL );

cleanup:
    SymCryptWipeKnownSize( &ctx, sizeof(ctx) );
    return scError;
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeOpenSingleShot(
    _In_                                PCSYMCRYPT_HPKEKEY  pkHpkekey,
    _In_reads_bytes_( cbEnc )           PCBYTE              pbEnc,
                                        SIZE_T              cbEnc,
    _In_reads_bytes_opt_( cbInfo )      PCBYTE              pbInfo,
                                        SIZE_T              cbInfo,
    _In_reads_bytes_opt_( cbPsk )       PCBYTE              pbPsk,
                                        SIZE_T              cbPsk,
    _In_reads_bytes_opt_( cbPskId )     PCBYTE              pbPskId,
                                        SIZE_T              cbPskId,
    _In_reads_bytes_opt_( cbAuthData )  PCBYTE              pbAuthData,
                                        SIZE_T              cbAuthData,
    _In_reads_bytes_( cbSrc )           PCBYTE              pbSrc,
                                        SIZE_T              cbSrc,
    _Out_writes_bytes_( cbDst )         PBYTE               pbDst,
                                        SIZE_T              cbDst,
                                        UINT32              flags )
{
    SYMCRYPT_ERROR scError;
    SYMCRYPT_HPKECONTEXT ctx;
    SYMCRYPT_HPKE_AEAD_PARAMS aeadParams;

    scError = SymCryptHpkeValidateCiphersuite(
        pkHpkekey->ciphersuite, NULL, &aeadParams );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        return SYMCRYPT_INVALID_ARGUMENT;
    }

    SymCryptHpkeContextInit( &ctx, pkHpkekey->ciphersuite, aeadParams );

    scError = SymCryptHpkeSetupRecipient(
        &ctx,
        pkHpkekey,
        pbEnc, cbEnc,
        pbInfo, cbInfo,
        pbPsk, cbPsk,
        pbPskId, cbPskId,
        flags );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    scError = SymCryptHpkeOpen(
        &ctx,
        pbAuthData, cbAuthData,
        pbSrc, cbSrc,
        pbDst, cbDst );

cleanup:
    SymCryptWipeKnownSize( &ctx, sizeof(ctx) );
    return scError;
}
