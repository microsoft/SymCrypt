//
// hpke_kem_dhkem.c
//
// HPKE DHKEM support: DHKEM key lifecycle, deterministic key derivation,
// DHKEM Encap/Decap, and DHKEM ExtractAndExpand.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

#include "hpke_internal.h"


#define SYMCRYPT_HPKE_DHKEM_MAX_PRIVATE_KEY_SIZE       (SYMCRYPT_HPKE_DHKEM_P521_SCALAR_SIZE)
#define SYMCRYPT_HPKE_DHKEM_MAX_PUBLIC_KEY_SIZE        (SYMCRYPT_HPKE_DHKEM_P521_PUBLIC_KEY_SIZE)
#define SYMCRYPT_HPKE_DHKEM_MAX_KEM_CONTEXT_SIZE       (2 * SYMCRYPT_HPKE_DHKEM_MAX_PUBLIC_KEY_SIZE)
#define SYMCRYPT_HPKE_DHKEM_MAX_RAW_SHARED_SECRET_SIZE (SYMCRYPT_HPKE_DHKEM_P521_SCALAR_SIZE)


typedef struct SYMCRYPT_HPKE_DHKEM_PARAMS
{
    UINT16                                  kemId;
    UINT16                                  kdfId;
    UINT16                                  cbRawSharedSecret;
    UINT16                                  cbPrivateKey;
    UINT16                                  cbPublicKey;
    SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT   publicKeyFormat;
    SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT  privateKeyFormat;
    SYMCRYPT_NUMBER_FORMAT                  privateKeyNumberFormat;
    SYMCRYPT_ECPOINT_FORMAT                 ecPointFormat;
    SYMCRYPT_ECURVE_ID                      ecurveId;
} SYMCRYPT_HPKE_DHKEM_PARAMS;

typedef const SYMCRYPT_HPKE_DHKEM_PARAMS * PCSYMCRYPT_HPKE_DHKEM_PARAMS;

struct SYMCRYPT_HPKE_DHKEMKEY
{
    PCSYMCRYPT_HPKE_DHKEM_PARAMS pParams;
    PSYMCRYPT_ECURVE    pCurve;
    PSYMCRYPT_ECKEY     pEckey;
};

static const SYMCRYPT_HPKE_DHKEM_PARAMS SymCryptHpkeDhkemParamsP256 =
{
    .kemId                  = SYMCRYPT_HPKE_KEM_ID_DHKEM_P256,
    .kdfId                  = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256,
    .cbRawSharedSecret      = SYMCRYPT_HPKE_DHKEM_P256_SCALAR_SIZE,
    .cbPrivateKey           = SYMCRYPT_HPKE_DHKEM_P256_SCALAR_SIZE,
    .cbPublicKey            = SYMCRYPT_HPKE_DHKEM_P256_PUBLIC_KEY_SIZE,
    .publicKeyFormat        = SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED,
    .privateKeyFormat       = SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NIST_SCALAR,
    .privateKeyNumberFormat = SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
    .ecPointFormat          = SYMCRYPT_ECPOINT_FORMAT_XY,
    .ecurveId               = SYMCRYPT_ECURVE_ID_NIST_P256,
};

static const SYMCRYPT_HPKE_DHKEM_PARAMS SymCryptHpkeDhkemParamsP384 =
{
    .kemId                  = SYMCRYPT_HPKE_KEM_ID_DHKEM_P384,
    .kdfId                  = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384,
    .cbRawSharedSecret      = SYMCRYPT_HPKE_DHKEM_P384_SCALAR_SIZE,
    .cbPrivateKey           = SYMCRYPT_HPKE_DHKEM_P384_SCALAR_SIZE,
    .cbPublicKey            = SYMCRYPT_HPKE_DHKEM_P384_PUBLIC_KEY_SIZE,
    .publicKeyFormat        = SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED,
    .privateKeyFormat       = SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NIST_SCALAR,
    .privateKeyNumberFormat = SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
    .ecPointFormat          = SYMCRYPT_ECPOINT_FORMAT_XY,
    .ecurveId               = SYMCRYPT_ECURVE_ID_NIST_P384,
};

static const SYMCRYPT_HPKE_DHKEM_PARAMS SymCryptHpkeDhkemParamsP521 =
{
    .kemId                  = SYMCRYPT_HPKE_KEM_ID_DHKEM_P521,
    .kdfId                  = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA512,
    .cbRawSharedSecret      = SYMCRYPT_HPKE_DHKEM_P521_SCALAR_SIZE,
    .cbPrivateKey           = SYMCRYPT_HPKE_DHKEM_P521_SCALAR_SIZE,
    .cbPublicKey            = SYMCRYPT_HPKE_DHKEM_P521_PUBLIC_KEY_SIZE,
    .publicKeyFormat        = SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED,
    .privateKeyFormat       = SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NIST_SCALAR,
    .privateKeyNumberFormat = SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
    .ecPointFormat          = SYMCRYPT_ECPOINT_FORMAT_XY,
    .ecurveId               = SYMCRYPT_ECURVE_ID_NIST_P521,
};

static const SYMCRYPT_HPKE_DHKEM_PARAMS SymCryptHpkeDhkemParamsX25519 =
{
    .kemId                  = SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519,
    .kdfId                  = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256,
    .cbRawSharedSecret      = SYMCRYPT_HPKE_DHKEM_X25519_SCALAR_SIZE,
    .cbPrivateKey           = SYMCRYPT_HPKE_DHKEM_X25519_SCALAR_SIZE,
    .cbPublicKey            = SYMCRYPT_HPKE_DHKEM_X25519_PUBLIC_KEY_SIZE,
    .publicKeyFormat        = SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_RAW_X_LE,
    .privateKeyFormat       = SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_C25519,
    .privateKeyNumberFormat = SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
    .ecPointFormat          = SYMCRYPT_ECPOINT_FORMAT_X,
    .ecurveId               = SYMCRYPT_ECURVE_ID_CURVE25519,
};

static PCSYMCRYPT_HPKE_DHKEM_PARAMS
SYMCRYPT_CALL
SymCryptHpkeDhkemParamsFromId(
    UINT16  kemId )
{
    switch ( kemId )
    {
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P256:
        return &SymCryptHpkeDhkemParamsP256;
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P384:
        return &SymCryptHpkeDhkemParamsP384;
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P521:
        return &SymCryptHpkeDhkemParamsP521;
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519:
        return &SymCryptHpkeDhkemParamsX25519;
    default:
        return NULL;
    }
}

PSYMCRYPT_HPKE_DHKEMKEY
SYMCRYPT_CALL
SymCryptHpkeDhkemkeyAllocate(
    UINT16  kemId )
{
    PSYMCRYPT_HPKE_DHKEMKEY pResult = NULL;
    PSYMCRYPT_HPKE_DHKEMKEY pkDhkemkey = NULL;
    PSYMCRYPT_ECURVE pCurve = NULL;
    PSYMCRYPT_ECKEY pEckey = NULL;
    PCSYMCRYPT_HPKE_DHKEM_PARAMS pParams = SymCryptHpkeDhkemParamsFromId( kemId );
    PCSYMCRYPT_ECURVE_PARAMS pCurveParams;

    if ( pParams == NULL )
    {
        goto cleanup;
    }

    pCurveParams = SymCryptGetEcurveParams( pParams->ecurveId );
    if ( pCurveParams == NULL )
    {
        goto cleanup;
    }

    // We could lazy-initialize global Ecurve structs as composites do, but
    // duplicating that infrastructure in symcrypt_plus is overkill for now.
    pCurve = SymCryptEcurveAllocate( pCurveParams, 0 );
    if ( pCurve == NULL )
    {
        goto cleanup;
    }

    pEckey = SymCryptEckeyAllocate( pCurve );
    if ( pEckey == NULL )
    {
        goto cleanup;
    }

    pkDhkemkey = (PSYMCRYPT_HPKE_DHKEMKEY) SymCryptCallbackAlloc( sizeof(*pkDhkemkey) );
    if ( pkDhkemkey == NULL )
    {
        goto cleanup;
    }
    SymCryptWipeKnownSize( (PBYTE) pkDhkemkey, sizeof(*pkDhkemkey) );

    pkDhkemkey->pParams = pParams;
    pkDhkemkey->pCurve = pCurve;
    pkDhkemkey->pEckey = pEckey;

    pResult = pkDhkemkey;
    pCurve = NULL;
    pEckey = NULL;
    pkDhkemkey = NULL;

cleanup:
    if ( pEckey != NULL )
    {
        SymCryptEckeyFree( pEckey );
    }
    if ( pCurve != NULL )
    {
        SymCryptEcurveFree( pCurve );
    }
    if ( pkDhkemkey != NULL )
    {
        SymCryptWipeKnownSize( (PBYTE) pkDhkemkey, sizeof(*pkDhkemkey) );
        SymCryptCallbackFree( pkDhkemkey );
    }

    return pResult;
}

VOID
SYMCRYPT_CALL
SymCryptHpkeDhkemkeyFree(
    _Inout_ PSYMCRYPT_HPKE_DHKEMKEY pkDhkemkey )
{
    if ( pkDhkemkey == NULL )
    {
        return;
    }

    if ( pkDhkemkey->pEckey != NULL )
    {
        SymCryptEckeyFree( pkDhkemkey->pEckey );
    }
    if ( pkDhkemkey->pCurve != NULL )
    {
        SymCryptEcurveFree( pkDhkemkey->pCurve );
    }

    SymCryptWipeKnownSize( (PBYTE) pkDhkemkey, sizeof(*pkDhkemkey) );
    SymCryptCallbackFree( pkDhkemkey );
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeDhkemkeyGenerate(
    _Inout_ PSYMCRYPT_HPKE_DHKEMKEY pkDhkemkey,
            UINT32                  flags )
{
    return SymCryptEckeySetRandom(
        SYMCRYPT_FLAG_ECKEY_ECDH | flags,
        pkDhkemkey->pEckey );
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeDhkemkeySetValue(
    _In_reads_bytes_( cbSrc )   PCBYTE                          pbSrc,
                                SIZE_T                          cbSrc,
                                SYMCRYPT_HPKEKEY_FORMAT         hpkeKeyFormat,
                                UINT32                          flags,
    _Inout_                     PSYMCRYPT_HPKE_DHKEMKEY         pkDhkemkey )
{
    switch ( hpkeKeyFormat )
    {
    case SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY:
        return SymCryptEckeySetValueIetfPrivateKey(
            pbSrc, cbSrc,
            pkDhkemkey->pParams->privateKeyFormat,
            SYMCRYPT_FLAG_ECKEY_ECDH | flags,
            pkDhkemkey->pEckey );

    case SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY:
        return SymCryptEckeySetValueIetfPublicKey(
            pbSrc, cbSrc,
            pkDhkemkey->pParams->publicKeyFormat,
            SYMCRYPT_FLAG_ECKEY_ECDH | flags,
            pkDhkemkey->pEckey );

    default:
        return SYMCRYPT_INVALID_ARGUMENT;
    }
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeDhkemkeyGetValue(
    _In_                        PCSYMCRYPT_HPKE_DHKEMKEY    pkDhkemkey,
    _Out_writes_bytes_( cbDst ) PBYTE                       pbDst,
                                SIZE_T                      cbDst,
                                SYMCRYPT_HPKEKEY_FORMAT     hpkeKeyFormat,
                                UINT32                      flags )
{
    if ( flags != 0 )
    {
        return SYMCRYPT_INVALID_ARGUMENT;
    }

    switch ( hpkeKeyFormat )
    {
    case SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY:
        if ( cbDst != pkDhkemkey->pParams->cbPrivateKey )
        {
            return SYMCRYPT_WRONG_KEY_SIZE;
        }
        return SymCryptEckeyGetValue(
            pkDhkemkey->pEckey,
            pbDst, cbDst,
            NULL, 0,
            pkDhkemkey->pParams->privateKeyNumberFormat,
            pkDhkemkey->pParams->ecPointFormat,
            0 );

    case SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY:
        return SymCryptEckeyGetValueIetfPublicKey(
            pkDhkemkey->pEckey,
            pkDhkemkey->pParams->publicKeyFormat,
            pbDst, cbDst );

    default:
        return SYMCRYPT_INVALID_ARGUMENT;
    }
}

static SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeDhkemDeriveNistKeyPair(
    _In_reads_bytes_( cbIkm )   PCBYTE                  pbIkm,
                                SIZE_T                  cbIkm,
    _Inout_                     PSYMCRYPT_HPKE_DHKEMKEY pkDhkemkey )
{
    SYMCRYPT_ERROR scError;
    BYTE kemSuiteId[SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE];
    BYTE dkpPrk[SYMCRYPT_MAC_MAX_RESULT_SIZE];
    BYTE candidate[SYMCRYPT_HPKE_DHKEM_MAX_PRIVATE_KEY_SIZE];
    UINT32 counter;
    BOOLEAN fFound = FALSE;
    PCSYMCRYPT_HPKE_DHKEM_PARAMS pParams = pkDhkemkey->pParams;
    SYMCRYPT_HPKE_KDF_ID kdfId = (SYMCRYPT_HPKE_KDF_ID) pParams->kdfId;
    UINT16 cbDkpPrk = SymCryptHpkeKdfOutputSizeFromId( kdfId );

    SymCryptHpkeBuildKemSuiteId( pParams->kemId, kemSuiteId );

    scError = SymCryptHpkeLabeledExtract(
        kdfId,
        kemSuiteId, SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE,
        NULL, 0,
        (PCBYTE)"dkp_prk", 7,
        pbIkm, cbIkm,
        dkpPrk, cbDkpPrk );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    for ( counter = 0; counter <= 255; counter++ )
    {
        BYTE counterByte = (BYTE) counter;

        scError = SymCryptHpkeLabeledExpand(
            kdfId,
            kemSuiteId, SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE,
            dkpPrk, cbDkpPrk,
            (PCBYTE)"candidate", 9,
            &counterByte, 1,
            candidate, pParams->cbPrivateKey );
        if ( scError != SYMCRYPT_NO_ERROR )
        {
            goto cleanup;
        }

        // Special case for P521 because its group order is 521-bits which is
        // 1 modulo 8; we must mask out the most-significant 7 bits
        if ( pParams->kemId == SYMCRYPT_HPKE_KEM_ID_DHKEM_P521 )
        {
            candidate[0] &= 0x01;
        }

        scError = SymCryptEckeySetValue(
            candidate, pParams->cbPrivateKey,
            NULL, 0,
            pParams->privateKeyNumberFormat,
            pParams->ecPointFormat,
            SYMCRYPT_FLAG_ECKEY_ECDH,
            pkDhkemkey->pEckey );
        if ( scError == SYMCRYPT_NO_ERROR )
        {
            fFound = TRUE;
            break;
        }

        // The only way that import would be expected to fail would be due
        // to range validation which returns invalid argument
        // Failure like memory allocation failure will break deterministic key
        // generation so must fail the whole call
        SYMCRYPT_ASSERT( scError == SYMCRYPT_INVALID_ARGUMENT );
        if ( scError != SYMCRYPT_INVALID_ARGUMENT )
        {
            goto cleanup;
        }
    }

    if ( !fFound )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

cleanup:
    SymCryptWipeKnownSize( candidate, sizeof(candidate) );
    SymCryptWipeKnownSize( dkpPrk, sizeof(dkpPrk) );
    return scError;
}

static SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeDhkemDeriveX25519KeyPair(
    _In_reads_bytes_( cbIkm )   PCBYTE                  pbIkm,
                                SIZE_T                  cbIkm,
    _Inout_                     PSYMCRYPT_HPKE_DHKEMKEY pkDhkemkey )
{
    SYMCRYPT_ERROR scError;
    BYTE kemSuiteId[SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE];
    BYTE dkpPrk[SYMCRYPT_MAC_MAX_RESULT_SIZE];
    BYTE privateScalar[SYMCRYPT_HPKE_DHKEM_X25519_SCALAR_SIZE];
    PCSYMCRYPT_HPKE_DHKEM_PARAMS pParams = pkDhkemkey->pParams;
    SYMCRYPT_HPKE_KDF_ID kdfId = (SYMCRYPT_HPKE_KDF_ID) pParams->kdfId;
    UINT16 cbDkpPrk = SymCryptHpkeKdfOutputSizeFromId( kdfId );

    SymCryptHpkeBuildKemSuiteId( pParams->kemId, kemSuiteId );

    scError = SymCryptHpkeLabeledExtract(
        kdfId,
        kemSuiteId, SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE,
        NULL, 0,
        (PCBYTE)"dkp_prk", 7,
        pbIkm, cbIkm,
        dkpPrk, cbDkpPrk );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    scError = SymCryptHpkeLabeledExpand(
        kdfId,
        kemSuiteId, SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE,
        dkpPrk, cbDkpPrk,
        (PCBYTE)"sk", 2,
        NULL, 0,
        privateScalar, sizeof(privateScalar) );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    scError = SymCryptEckeySetValueIetfPrivateKey(
        privateScalar, sizeof(privateScalar),
        pParams->privateKeyFormat,
        SYMCRYPT_FLAG_ECKEY_ECDH,
        pkDhkemkey->pEckey );

cleanup:
    SymCryptWipeKnownSize( privateScalar, sizeof(privateScalar) );
    SymCryptWipeKnownSize( dkpPrk, sizeof(dkpPrk) );
    return scError;
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeDhkemDeriveKeyPair(
    _In_reads_bytes_( cbIkm )   PCBYTE  pbIkm,
                                SIZE_T  cbIkm,
    _Inout_                     PSYMCRYPT_HPKE_DHKEMKEY pkDhkemkey )
{
    switch ( pkDhkemkey->pParams->kemId )
    {
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P256:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P384:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P521:
        return SymCryptHpkeDhkemDeriveNistKeyPair( pbIkm, cbIkm, pkDhkemkey );
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519:
        return SymCryptHpkeDhkemDeriveX25519KeyPair( pbIkm, cbIkm, pkDhkemkey );
    default:
        SYMCRYPT_ASSERT( FALSE );
        return SYMCRYPT_NOT_IMPLEMENTED;
    }
}

static SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeDhkemDeriveSharedSecret(
    _In_                                    PCSYMCRYPT_HPKEKEY      pkRecipientKey,
    _In_reads_bytes_( cbRawSharedSecret )   PCBYTE                  pbRawSharedSecret,
                                            SIZE_T                  cbRawSharedSecret,
    _In_reads_bytes_( cbEnc )               PCBYTE                  pbEnc,
                                            SIZE_T                  cbEnc,
    _Out_writes_bytes_( cbSharedSecret )    PBYTE                   pbSharedSecret,
                                            UINT16                  cbSharedSecret )
{
    SYMCRYPT_ERROR scError;
    BYTE prk[SYMCRYPT_MAC_MAX_RESULT_SIZE];
    BYTE kemSuiteId[SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE];
    BYTE kemContext[SYMCRYPT_HPKE_DHKEM_MAX_KEM_CONTEXT_SIZE]; // enc || pkR
    SIZE_T cbKemContext;
    PCSYMCRYPT_HPKE_DHKEMKEY pkDhkemkey = (PCSYMCRYPT_HPKE_DHKEMKEY) pkRecipientKey->pKemKeyData;
    PCSYMCRYPT_HPKE_DHKEM_PARAMS pParams = pkDhkemkey->pParams;
    SYMCRYPT_HPKE_KDF_ID kdfId = (SYMCRYPT_HPKE_KDF_ID) pParams->kdfId;
    SIZE_T cbPrk;

    SYMCRYPT_ASSERT( pParams->kemId == pkRecipientKey->ciphersuite.kemId );

    cbPrk = SymCryptHpkeKdfOutputSizeFromId( kdfId );

    SymCryptHpkeBuildKemSuiteId( pkRecipientKey->ciphersuite.kemId, kemSuiteId );

    //
    // kem_context = enc || SerializePublicKey(pkR)
    //
    cbKemContext = cbEnc + pParams->cbPublicKey;
    SYMCRYPT_ASSERT( cbKemContext <= sizeof(kemContext) );

    memcpy( kemContext, pbEnc, cbEnc );
    scError = SymCryptHpkeDhkemkeyGetValue(
        pkDhkemkey,
        kemContext + cbEnc,
        pParams->cbPublicKey,
        SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY,
        0 );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    //
    // eae_prk = LabeledExtract("", "eae_prk", dh)
    //
    scError = SymCryptHpkeLabeledExtract(
        kdfId,
        kemSuiteId, SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE,
        NULL, 0, // empty salt
        (PCBYTE)"eae_prk", 7,
        pbRawSharedSecret, cbRawSharedSecret,
        prk, cbPrk );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    //
    // shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)
    //
    scError = SymCryptHpkeLabeledExpand(
        kdfId,
        kemSuiteId, SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE,
        prk, cbPrk,
        (PCBYTE)"shared_secret", 13,
        kemContext, cbKemContext,
        pbSharedSecret, cbSharedSecret );

cleanup:
    SymCryptWipeKnownSize( prk, sizeof(prk) );
    SymCryptWipeKnownSize( kemContext, sizeof(kemContext) );
    return scError;
}


SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeDhkemEncapsulate(
    _In_                                        PCSYMCRYPT_HPKEKEY  pkRecipientKey,
    _Out_writes_bytes_( cbSharedSecret )        PBYTE               pbSharedSecret,
                                                UINT16              cbSharedSecret,
    _Out_writes_bytes_( cbEnc )                 PBYTE               pbEnc,
                                                SIZE_T              cbEnc )
{
    return SymCryptHpkeDhkemEncapsulateEx(
        pkRecipientKey, NULL, 0, pbSharedSecret, cbSharedSecret, pbEnc, cbEnc );
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeDhkemEncapsulateEx(
    _In_                                        PCSYMCRYPT_HPKEKEY  pkRecipientKey,
    _In_reads_bytes_opt_( cbIkmE )              PCBYTE              pbIkmE,
                                                SIZE_T              cbIkmE,
    _Out_writes_bytes_( cbSharedSecret )        PBYTE               pbSharedSecret,
                                                UINT16              cbSharedSecret,
    _Out_writes_bytes_( cbEnc )                 PBYTE               pbEnc,
                                                SIZE_T              cbEnc )
{
    SYMCRYPT_ERROR scError;
    PCSYMCRYPT_HPKE_DHKEMKEY pkRecipientDhkemKey = (PCSYMCRYPT_HPKE_DHKEMKEY) pkRecipientKey->pKemKeyData;
    PSYMCRYPT_ECKEY pkEphemeralEckey = NULL;
    BYTE rawSharedSecret[SYMCRYPT_HPKE_DHKEM_MAX_RAW_SHARED_SECRET_SIZE];
    PCSYMCRYPT_HPKE_DHKEM_PARAMS pParams = pkRecipientDhkemKey->pParams;

    SYMCRYPT_ASSERT( pParams->kemId == pkRecipientKey->ciphersuite.kemId );

    pkEphemeralEckey = SymCryptEckeyAllocate( pkRecipientDhkemKey->pCurve );
    if ( pkEphemeralEckey == NULL )
    {
        scError = SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        goto cleanup;
    }

    if ( pbIkmE != NULL )
    {
        SYMCRYPT_HPKE_DHKEMKEY senderDhkemKey;
        senderDhkemKey.pParams = pkRecipientDhkemKey->pParams;
        senderDhkemKey.pCurve  = pkRecipientDhkemKey->pCurve;
        senderDhkemKey.pEckey  = pkEphemeralEckey;
        scError = SymCryptHpkeDhkemDeriveKeyPair( pbIkmE, cbIkmE, &senderDhkemKey );
    }
    else
    {
        scError = SymCryptEckeySetRandom( SYMCRYPT_FLAG_ECKEY_ECDH, pkEphemeralEckey );
    }
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    scError = SymCryptEcDhSecretAgreement(
        pkEphemeralEckey,
        pkRecipientDhkemKey->pEckey,
        pParams->privateKeyNumberFormat,
        0,
        rawSharedSecret, pParams->cbRawSharedSecret );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    scError = SymCryptEckeyGetValueIetfPublicKey(
        pkEphemeralEckey,
        pParams->publicKeyFormat,
        pbEnc, cbEnc );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    scError = SymCryptHpkeDhkemDeriveSharedSecret(
        pkRecipientKey,
        rawSharedSecret, pParams->cbRawSharedSecret,
        pbEnc, cbEnc,
        pbSharedSecret, cbSharedSecret );

cleanup:
    if ( pkEphemeralEckey != NULL )
    {
        SymCryptEckeyFree( pkEphemeralEckey );
    }
    SymCryptWipeKnownSize( rawSharedSecret, sizeof(rawSharedSecret) );
    return scError;
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeDhkemDecapsulate(
    _In_                                        PCSYMCRYPT_HPKEKEY  pkRecipientKey,
    _In_reads_bytes_( cbEnc )                   PCBYTE              pbEnc,
                                                SIZE_T              cbEnc,
    _Out_writes_bytes_( cbSharedSecret )        PBYTE               pbSharedSecret,
                                                UINT16              cbSharedSecret )
{
    SYMCRYPT_ERROR scError;
    PCSYMCRYPT_HPKE_DHKEMKEY pkRecipientDhkemKey = (PCSYMCRYPT_HPKE_DHKEMKEY) pkRecipientKey->pKemKeyData;
    PSYMCRYPT_ECKEY pkEphemeralEckey = NULL;
    BYTE rawSharedSecret[SYMCRYPT_HPKE_DHKEM_MAX_RAW_SHARED_SECRET_SIZE];
    PCSYMCRYPT_HPKE_DHKEM_PARAMS pParams = pkRecipientDhkemKey->pParams;

    SYMCRYPT_ASSERT( pParams->kemId == pkRecipientKey->ciphersuite.kemId );

    pkEphemeralEckey = SymCryptEckeyAllocate( pkRecipientDhkemKey->pCurve );
    if ( pkEphemeralEckey == NULL )
    {
        scError = SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        goto cleanup;
    }

    scError = SymCryptEckeySetValueIetfPublicKey(
        pbEnc, cbEnc,
        pParams->publicKeyFormat,
        SYMCRYPT_FLAG_ECKEY_ECDH,
        pkEphemeralEckey );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    scError = SymCryptEcDhSecretAgreement(
        pkRecipientDhkemKey->pEckey,
        pkEphemeralEckey,
        pParams->privateKeyNumberFormat,
        0,
        rawSharedSecret, pParams->cbRawSharedSecret );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    scError = SymCryptHpkeDhkemDeriveSharedSecret(
        pkRecipientKey,
        rawSharedSecret, pParams->cbRawSharedSecret,
        pbEnc, cbEnc,
        pbSharedSecret, cbSharedSecret );

cleanup:
    if ( pkEphemeralEckey != NULL )
    {
        SymCryptEckeyFree( pkEphemeralEckey );
    }
    SymCryptWipeKnownSize( rawSharedSecret, sizeof(rawSharedSecret) );
    return scError;
}
