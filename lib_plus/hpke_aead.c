//
// hpke_aead.c
//
// HPKE AEAD layer: parameter lookup, nonce construction, Seal / Open /
// OpenUnordered, and the public AEAD-overhead size query.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

#include "hpke_internal.h"


static const SYMCRYPT_HPKE_AEAD_PARAMS SymCryptHpkeAeadParamsAesGcm128 =
{
    .aeadId     = SYMCRYPT_HPKE_AEAD_ID_AESGCM128,
    .cbKey      = 16,
    .cbNonce    = 12,
    .cbTag      = 16,
};

static const SYMCRYPT_HPKE_AEAD_PARAMS SymCryptHpkeAeadParamsAesGcm256 =
{
    .aeadId     = SYMCRYPT_HPKE_AEAD_ID_AESGCM256,
    .cbKey      = 32,
    .cbNonce    = 12,
    .cbTag      = 16,
};

static const SYMCRYPT_HPKE_AEAD_PARAMS SymCryptHpkeAeadParamsChacha20Poly1305 =
{
    .aeadId     = SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305,
    .cbKey      = 32,
    .cbNonce    = 12,
    .cbTag      = 16,
};

static const SYMCRYPT_HPKE_AEAD_PARAMS SymCryptHpkeAeadParamsExportOnly =
{
    .aeadId     = SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY,
    .cbKey      = 0,
    .cbNonce    = 0,
    .cbTag      = 0,
};

PCSYMCRYPT_HPKE_AEAD_PARAMS
SYMCRYPT_CALL
SymCryptHpkeAeadParamsFromId( SYMCRYPT_HPKE_AEAD_ID aeadId )
{
    PCSYMCRYPT_HPKE_AEAD_PARAMS pParams = NULL;

    switch ( aeadId )
    {
    case SYMCRYPT_HPKE_AEAD_ID_AESGCM128:
        pParams = &SymCryptHpkeAeadParamsAesGcm128;
        break;

    case SYMCRYPT_HPKE_AEAD_ID_AESGCM256:
        pParams = &SymCryptHpkeAeadParamsAesGcm256;
        break;

    case SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305:
        pParams = &SymCryptHpkeAeadParamsChacha20Poly1305;
        break;

    case SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY:
        pParams = &SymCryptHpkeAeadParamsExportOnly;
        break;

    default:
        return NULL;
    }

    SYMCRYPT_ASSERT( pParams->cbKey   <= SYMCRYPT_HPKE_AEAD_MAX_KEY_SIZE );
    SYMCRYPT_ASSERT( pParams->cbNonce <= SYMCRYPT_HPKE_AEAD_MAX_NONCE_SIZE );

    return pParams;
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeSizeofAeadOverheadFromParams(
            SYMCRYPT_HPKE_CIPHERSUITE   params,
    _Out_   SIZE_T*                     pcbAeadOverhead )
{
    PCSYMCRYPT_HPKE_AEAD_PARAMS pAeadParams;
    SYMCRYPT_HPKE_AEAD_ID aeadId = (SYMCRYPT_HPKE_AEAD_ID) params.aeadId;

    if ( aeadId == SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY )
    {
        return SYMCRYPT_INVALID_ARGUMENT;
    }

    pAeadParams = SymCryptHpkeAeadParamsFromId( aeadId );
    if ( pAeadParams == NULL )
    {
        return SYMCRYPT_NOT_IMPLEMENTED;
    }

    *pcbAeadOverhead = pAeadParams->cbTag;
    return SYMCRYPT_NO_ERROR;
}

//
// AEAD nonce construction: nonce = base_nonce XOR I2OSP(seq, Nn).
//
static VOID
SymCryptHpkeComputeNonce(
    _In_reads_bytes_( cbNonce )     PCBYTE  pbBaseNonce,
                                    SIZE_T  cbNonce,
                                    UINT64  seqNum,
    _Out_writes_bytes_( cbNonce )   PBYTE   pbNonce )
{
    SIZE_T cbPrefix = cbNonce - 8;

    SYMCRYPT_ASSERT( cbNonce >= 8 );
    SYMCRYPT_ASSERT( cbNonce <= SYMCRYPT_HPKE_AEAD_MAX_NONCE_SIZE );

    // For cbNonce > 8 the leading (cbNonce - 8) bytes of the I2OSP encoding are
    // implicitly zero, so the XOR with base_nonce reduces to a memcpy there.
    memcpy( pbNonce, pbBaseNonce, cbPrefix );
    SYMCRYPT_STORE_MSBFIRST64( pbNonce+cbPrefix, seqNum ^ SYMCRYPT_LOAD_MSBFIRST64( pbBaseNonce+cbPrefix ) );
}

static
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeAeadValidateBufferSizes(
    _In_    PCSYMCRYPT_HPKECONTEXT  pHpkeContext,
            SIZE_T                  cbPlaintext,
            SIZE_T                  cbCiphertext,
            SIZE_T                  cbAuthData )
{
    if ( cbCiphertext < pHpkeContext->aeadParams.cbTag )
    {
        return SYMCRYPT_INVALID_ARGUMENT;
    }

    if ( cbPlaintext != cbCiphertext - pHpkeContext->aeadParams.cbTag )
    {
        return SYMCRYPT_INVALID_ARGUMENT;
    }

    switch ( pHpkeContext->aeadParams.aeadId )
    {
    case SYMCRYPT_HPKE_AEAD_ID_AESGCM128:
    case SYMCRYPT_HPKE_AEAD_ID_AESGCM256:
        if ( ((UINT64)cbPlaintext > SYMCRYPT_GCM_MAX_DATA_SIZE  ) ||
             (((UINT64)cbAuthData >> 61) > 0) )
        {
            return SYMCRYPT_WRONG_DATA_SIZE;
        }
        return SYMCRYPT_NO_ERROR;

    case SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305:
        if ( (UINT64)cbPlaintext > SYMCRYPT_CHACHA20_POLY1305_MAX_DATA_SIZE )
        {
            return SYMCRYPT_WRONG_DATA_SIZE;
        }
        return SYMCRYPT_NO_ERROR;

    case SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY:
        return SYMCRYPT_INVALID_ARGUMENT;

    default:
        SYMCRYPT_ASSERT( FALSE );
        return SYMCRYPT_INVALID_ARGUMENT;
    }
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeSeal(
    _Inout_                             PSYMCRYPT_HPKECONTEXT   pHpkeContext,
    _In_reads_bytes_opt_( cbAuthData )  PCBYTE                  pbAuthData,
                                        SIZE_T                  cbAuthData,
    _In_reads_bytes_opt_( cbSrc )       PCBYTE                  pbSrc,
                                        SIZE_T                  cbSrc,
    _Out_writes_bytes_( cbDst )         PBYTE                   pbDst,
                                        SIZE_T                  cbDst,
    _Out_opt_                           UINT64*                 pu64SeqNumber )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    BYTE nonce[SYMCRYPT_HPKE_AEAD_MAX_NONCE_SIZE];
    UINT64 seqNum;

    SYMCRYPT_CHECK_MAGIC( pHpkeContext );

    if ( pHpkeContext->state != SYMCRYPT_HPKE_CONTEXT_STATE_SENDER )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    if ( (pbSrc      == NULL && cbSrc      != 0) ||
         (pbAuthData == NULL && cbAuthData != 0) )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    // Validate AEAD size limits before consuming a sequence number.
    scError = SymCryptHpkeAeadValidateBufferSizes( pHpkeContext, cbSrc, cbDst, cbAuthData );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    //
    // Atomically increment sequence number and get the value before increment.
    // This makes Seal thread-safe.
    //
    // Note: The atomic increment is unconditional, contrary to the HPKE spec which
    // uses a check-then-increment approach. If more than 2^32 calls exceed
    // SYMCRYPT_HPKE_SEQ_LIMIT, the 64-bit counter could wrap back to a valid range.
    // In practice we will never see seqNum >= SYMCRYPT_HPKE_SEQ_LIMIT, as it would
    // require close to 2^64 dependent increments. A CAS loop would eliminate this
    // theoretical window but adds overhead to the hot path.
    //
    seqNum = (UINT64) SYMCRYPT_ATOMIC_ADD64_POST_RELAXED( &pHpkeContext->seqNum, 1 ) - 1;
    if ( seqNum >= SYMCRYPT_HPKE_SEQ_LIMIT )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;       // Sequence number exhausted
        goto cleanup;
    }

    SymCryptHpkeComputeNonce(
        pHpkeContext->baseNonce, pHpkeContext->aeadParams.cbNonce, seqNum, nonce );

    switch ( (SYMCRYPT_HPKE_AEAD_ID) pHpkeContext->aeadParams.aeadId )
    {
    case SYMCRYPT_HPKE_AEAD_ID_AESGCM128:
    case SYMCRYPT_HPKE_AEAD_ID_AESGCM256:
        SYMCRYPT_ASSERT( pHpkeContext->fGcmKeyExpanded );

        SymCryptGcmEncrypt(
            &pHpkeContext->gcmExpandedKey,
            nonce, pHpkeContext->aeadParams.cbNonce,
            pbAuthData, cbAuthData,
            pbSrc, pbDst, cbSrc,
            pbDst + cbSrc, pHpkeContext->aeadParams.cbTag );
        break;

    case SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305:
        SYMCRYPT_ASSERT( !pHpkeContext->fGcmKeyExpanded );

        scError = SymCryptChaCha20Poly1305Encrypt(
            pHpkeContext->key, pHpkeContext->aeadParams.cbKey,
            nonce, pHpkeContext->aeadParams.cbNonce,
            pbAuthData, cbAuthData,
            pbSrc, pbDst, cbSrc,
            pbDst + cbSrc, pHpkeContext->aeadParams.cbTag );
        SYMCRYPT_ASSERT( scError == SYMCRYPT_NO_ERROR );
        break;

    default:
        SYMCRYPT_ASSERT( FALSE );
        scError = SYMCRYPT_NOT_IMPLEMENTED;
        goto cleanup;
    }

    if ( pu64SeqNumber != NULL )
    {
        *pu64SeqNumber = seqNum;
    }

cleanup:
    SymCryptWipeKnownSize( nonce, sizeof(nonce) );
    return scError;
}


SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeOpen(
    _Inout_                             PSYMCRYPT_HPKECONTEXT   pHpkeContext,
    _In_reads_bytes_opt_( cbAuthData )  PCBYTE                  pbAuthData,
                                        SIZE_T                  cbAuthData,
    _In_reads_bytes_( cbSrc )           PCBYTE                  pbSrc,
                                        SIZE_T                  cbSrc,
    _Out_writes_bytes_( cbDst )         PBYTE                   pbDst,
                                        SIZE_T                  cbDst )
{
    SYMCRYPT_ERROR scError;
    BYTE nonce[SYMCRYPT_HPKE_AEAD_MAX_NONCE_SIZE];
    UINT64 seqNum;

    SYMCRYPT_CHECK_MAGIC( pHpkeContext );

    if ( pHpkeContext->state != SYMCRYPT_HPKE_CONTEXT_STATE_RECIPIENT )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }
    
    if ( pbAuthData == NULL && cbAuthData != 0 )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    scError = SymCryptHpkeAeadValidateBufferSizes( pHpkeContext, cbDst, cbSrc, cbAuthData );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    // Open (ordered) is NOT thread-safe by design.
    seqNum = (UINT64) pHpkeContext->seqNum;
    if ( seqNum >= SYMCRYPT_HPKE_SEQ_LIMIT )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    SymCryptHpkeComputeNonce(
        pHpkeContext->baseNonce, pHpkeContext->aeadParams.cbNonce, seqNum, nonce );

    switch ( (SYMCRYPT_HPKE_AEAD_ID) pHpkeContext->aeadParams.aeadId )
    {
    case SYMCRYPT_HPKE_AEAD_ID_AESGCM128:
    case SYMCRYPT_HPKE_AEAD_ID_AESGCM256:
        SYMCRYPT_ASSERT( pHpkeContext->fGcmKeyExpanded );

        scError = SymCryptGcmDecrypt(
            &pHpkeContext->gcmExpandedKey,
            nonce, pHpkeContext->aeadParams.cbNonce,
            pbAuthData, cbAuthData,
            pbSrc, pbDst, cbDst,
            pbSrc + cbDst, pHpkeContext->aeadParams.cbTag );
        break;

    case SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305:
        SYMCRYPT_ASSERT( !pHpkeContext->fGcmKeyExpanded );

        scError = SymCryptChaCha20Poly1305Decrypt(
            pHpkeContext->key, pHpkeContext->aeadParams.cbKey,
            nonce, pHpkeContext->aeadParams.cbNonce,
            pbAuthData, cbAuthData,
            pbSrc, pbDst, cbDst,
            pbSrc + cbDst, pHpkeContext->aeadParams.cbTag );
        break;

    default:
        SYMCRYPT_ASSERT( FALSE );
        scError = SYMCRYPT_NOT_IMPLEMENTED;
        break;
    }

    if ( scError == SYMCRYPT_NO_ERROR )
    {
        // Only increment sequence number on successful decryption
        pHpkeContext->seqNum = seqNum + 1;
    }

cleanup:
    SymCryptWipeKnownSize( nonce, sizeof(nonce) );
    return scError;
}


SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeOpenUnordered(
    _In_                                PCSYMCRYPT_HPKECONTEXT  pHpkeContext,
                                        UINT64                  u64SeqNumber,
    _In_reads_bytes_opt_( cbAuthData )  PCBYTE                  pbAuthData,
                                        SIZE_T                  cbAuthData,
    _In_reads_bytes_( cbSrc )           PCBYTE                  pbSrc,
                                        SIZE_T                  cbSrc,
    _Out_writes_bytes_( cbDst )         PBYTE                   pbDst,
                                        SIZE_T                  cbDst )
{
    SYMCRYPT_ERROR scError;
    BYTE nonce[SYMCRYPT_HPKE_AEAD_MAX_NONCE_SIZE];

    SYMCRYPT_CHECK_MAGIC( pHpkeContext );

    if ( pHpkeContext->state == SYMCRYPT_HPKE_CONTEXT_STATE_UNINITIALIZED )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    if ( u64SeqNumber >= SYMCRYPT_HPKE_SEQ_LIMIT )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }
    
    if ( pbAuthData == NULL && cbAuthData != 0 )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    scError = SymCryptHpkeAeadValidateBufferSizes( pHpkeContext, cbDst, cbSrc, cbAuthData );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    SymCryptHpkeComputeNonce(
        pHpkeContext->baseNonce, pHpkeContext->aeadParams.cbNonce, u64SeqNumber, nonce );

    switch ( (SYMCRYPT_HPKE_AEAD_ID) pHpkeContext->aeadParams.aeadId )
    {
    case SYMCRYPT_HPKE_AEAD_ID_AESGCM128:
    case SYMCRYPT_HPKE_AEAD_ID_AESGCM256:
        SYMCRYPT_ASSERT( pHpkeContext->fGcmKeyExpanded );

        scError = SymCryptGcmDecrypt(
            &pHpkeContext->gcmExpandedKey,
            nonce, pHpkeContext->aeadParams.cbNonce,
            pbAuthData, cbAuthData,
            pbSrc, pbDst, cbDst,
            pbSrc + cbDst, pHpkeContext->aeadParams.cbTag );
        break;

    case SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305:
        SYMCRYPT_ASSERT( !pHpkeContext->fGcmKeyExpanded );

        scError = SymCryptChaCha20Poly1305Decrypt(
            pHpkeContext->key, pHpkeContext->aeadParams.cbKey,
            nonce, pHpkeContext->aeadParams.cbNonce,
            pbAuthData, cbAuthData,
            pbSrc, pbDst, cbDst,
            pbSrc + cbDst, pHpkeContext->aeadParams.cbTag );
        break;

    default:
        SYMCRYPT_ASSERT( FALSE );
        scError = SYMCRYPT_NOT_IMPLEMENTED;
        break;
    }

cleanup:
    SymCryptWipeKnownSize( nonce, sizeof(nonce) );
    return scError;
}
