//
// hpke_kem.c
//
// HPKE KEM layer: per-KEM parameter table and ID lookup, Hpkekey lifecycle,
// KEM Encapsulate / Decapsulate dispatch, and KEM-dependent public size queries.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

#include "hpke_internal.h"

static SYMCRYPT_MLKEMKEY_FORMAT
SYMCRYPT_CALL
SymCryptHpkeToMlKemKeyFormat(
    SYMCRYPT_HPKEKEY_FORMAT format )
{
    switch ( format )
    {
    case SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY:
        return SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED;
    case SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY:
        return SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY;
    default:
        return SYMCRYPT_MLKEMKEY_FORMAT_NULL;
    }
}

static SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT
SYMCRYPT_CALL
SymCryptHpkeToCompositeMlKemKeyFormat(
    SYMCRYPT_HPKEKEY_FORMAT format )
{
    switch ( format )
    {
    case SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY:
        return SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_IRTF_PRIVATE_SEED;
    case SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY:
        return SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_PUBLIC_KEY;
    default:
        return SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_NULL;
    }
}

static const SYMCRYPT_HPKE_KEM_PARAMS SymCryptHpkeKemParamsDhkemP256 =
{
    .kemId              = SYMCRYPT_HPKE_KEM_ID_DHKEM_P256,
    .cbSharedSecret     = SYMCRYPT_HPKE_DHKEM_P256_SHARED_SECRET_SIZE,
    .cbEnc              = SYMCRYPT_HPKE_DHKEM_P256_PUBLIC_KEY_SIZE,
    .cbPublicKey        = SYMCRYPT_HPKE_DHKEM_P256_PUBLIC_KEY_SIZE,
    .cbPrivateKey       = SYMCRYPT_HPKE_DHKEM_P256_SCALAR_SIZE,
};

static const SYMCRYPT_HPKE_KEM_PARAMS SymCryptHpkeKemParamsDhkemP384 =
{
    .kemId              = SYMCRYPT_HPKE_KEM_ID_DHKEM_P384,
    .cbSharedSecret     = SYMCRYPT_HPKE_DHKEM_P384_SHARED_SECRET_SIZE,
    .cbEnc              = SYMCRYPT_HPKE_DHKEM_P384_PUBLIC_KEY_SIZE,
    .cbPublicKey        = SYMCRYPT_HPKE_DHKEM_P384_PUBLIC_KEY_SIZE,
    .cbPrivateKey       = SYMCRYPT_HPKE_DHKEM_P384_SCALAR_SIZE,
};

static const SYMCRYPT_HPKE_KEM_PARAMS SymCryptHpkeKemParamsDhkemP521 =
{
    .kemId              = SYMCRYPT_HPKE_KEM_ID_DHKEM_P521,
    .cbSharedSecret     = SYMCRYPT_HPKE_DHKEM_P521_SHARED_SECRET_SIZE,
    .cbEnc              = SYMCRYPT_HPKE_DHKEM_P521_PUBLIC_KEY_SIZE,
    .cbPublicKey        = SYMCRYPT_HPKE_DHKEM_P521_PUBLIC_KEY_SIZE,
    .cbPrivateKey       = SYMCRYPT_HPKE_DHKEM_P521_SCALAR_SIZE,
};

static const SYMCRYPT_HPKE_KEM_PARAMS SymCryptHpkeKemParamsDhkemX25519 =
{
    .kemId              = SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519,
    .cbSharedSecret     = SYMCRYPT_HPKE_DHKEM_X25519_SHARED_SECRET_SIZE,
    .cbEnc              = SYMCRYPT_HPKE_DHKEM_X25519_PUBLIC_KEY_SIZE,
    .cbPublicKey        = SYMCRYPT_HPKE_DHKEM_X25519_PUBLIC_KEY_SIZE,
    .cbPrivateKey       = SYMCRYPT_HPKE_DHKEM_X25519_SCALAR_SIZE,
};

static const SYMCRYPT_HPKE_KEM_PARAMS SymCryptHpkeKemParamsMlKem512 =
{
    .kemId              = SYMCRYPT_HPKE_KEM_ID_MLKEM_512,
    .cbSharedSecret     = SYMCRYPT_MLKEM_AGREED_SECRET_SIZE,                // 32
    .cbEnc              = SYMCRYPT_MLKEM_CIPHERTEXT_SIZE_MLKEM512,          // 768
    .cbPublicKey        = SYMCRYPT_MLKEM_ENCAPSULATION_KEY_SIZE_MLKEM512,   // 800
    .cbPrivateKey       = SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE,                 // 64 (d||z)
};

static const SYMCRYPT_HPKE_KEM_PARAMS SymCryptHpkeKemParamsMlKem768 =
{
    .kemId              = SYMCRYPT_HPKE_KEM_ID_MLKEM_768,
    .cbSharedSecret     = SYMCRYPT_MLKEM_AGREED_SECRET_SIZE,
    .cbEnc              = SYMCRYPT_MLKEM_CIPHERTEXT_SIZE_MLKEM768,          // 1088
    .cbPublicKey        = SYMCRYPT_MLKEM_ENCAPSULATION_KEY_SIZE_MLKEM768,   // 1184
    .cbPrivateKey       = SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE,
};

static const SYMCRYPT_HPKE_KEM_PARAMS SymCryptHpkeKemParamsMlKem1024 =
{
    .kemId              = SYMCRYPT_HPKE_KEM_ID_MLKEM_1024,
    .cbSharedSecret     = SYMCRYPT_MLKEM_AGREED_SECRET_SIZE,
    .cbEnc              = SYMCRYPT_MLKEM_CIPHERTEXT_SIZE_MLKEM1024,         // 1568
    .cbPublicKey        = SYMCRYPT_MLKEM_ENCAPSULATION_KEY_SIZE_MLKEM1024,  // 1568
    .cbPrivateKey       = SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE,
};

static const SYMCRYPT_HPKE_KEM_PARAMS SymCryptHpkeKemParamsCompositeMlKem768P256 =
{
    .kemId              = SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256,
    .cbSharedSecret     = 32,
    .cbEnc              = SYMCRYPT_COMPOSITE_MLKEM_CIPHERTEXT_SIZE_MLKEM768_P256,    // 1153
    .cbPublicKey        = SYMCRYPT_COMPOSITE_MLKEM_PUBLIC_KEY_SIZE_MLKEM768_P256,    // 1249
    .cbPrivateKey       = SYMCRYPT_COMPOSITE_MLKEM_IRTF_PRIVATE_SEED_SIZE,           // 32
};

static const SYMCRYPT_HPKE_KEM_PARAMS SymCryptHpkeKemParamsCompositeMlKem1024P384 =
{
    .kemId              = SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384,
    .cbSharedSecret     = 32,
    .cbEnc              = SYMCRYPT_COMPOSITE_MLKEM_CIPHERTEXT_SIZE_MLKEM1024_P384,   // 1665
    .cbPublicKey        = SYMCRYPT_COMPOSITE_MLKEM_PUBLIC_KEY_SIZE_MLKEM1024_P384,   // 1665
    .cbPrivateKey       = SYMCRYPT_COMPOSITE_MLKEM_IRTF_PRIVATE_SEED_SIZE,
};

static const SYMCRYPT_HPKE_KEM_PARAMS SymCryptHpkeKemParamsCompositeMlKem768X25519 =
{
    .kemId              = SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519,
    .cbSharedSecret     = 32,
    .cbEnc              = SYMCRYPT_COMPOSITE_MLKEM_CIPHERTEXT_SIZE_MLKEM768_X25519,  // 1120
    .cbPublicKey        = SYMCRYPT_COMPOSITE_MLKEM_PUBLIC_KEY_SIZE_MLKEM768_X25519,  // 1216
    .cbPrivateKey       = SYMCRYPT_COMPOSITE_MLKEM_IRTF_PRIVATE_SEED_SIZE,
};


PCSYMCRYPT_HPKE_KEM_PARAMS
SYMCRYPT_CALL
SymCryptHpkeKemParamsFromId(
    SYMCRYPT_HPKE_KEM_ID    kemId )
{
    switch ( kemId )
    {
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P256:
        return &SymCryptHpkeKemParamsDhkemP256;
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P384:
        return &SymCryptHpkeKemParamsDhkemP384;
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P521:
        return &SymCryptHpkeKemParamsDhkemP521;
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519:
        return &SymCryptHpkeKemParamsDhkemX25519;
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_512:
        return &SymCryptHpkeKemParamsMlKem512;
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_768:
        return &SymCryptHpkeKemParamsMlKem768;
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_1024:
        return &SymCryptHpkeKemParamsMlKem1024;
    case SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256:
        return &SymCryptHpkeKemParamsCompositeMlKem768P256;
    case SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384:
        return &SymCryptHpkeKemParamsCompositeMlKem1024P384;
    case SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519:
        return &SymCryptHpkeKemParamsCompositeMlKem768X25519;
    default:
        return NULL;
    }
}


PSYMCRYPT_HPKEKEY
SYMCRYPT_CALL
SymCryptHpkekeyAllocate( SYMCRYPT_HPKE_CIPHERSUITE params )
{
    SYMCRYPT_ERROR scError;
    PSYMCRYPT_HPKEKEY pKey = NULL;
    SYMCRYPT_HPKE_KEM_PARAMS kemParams;

    scError = SymCryptHpkeValidateCiphersuite( params, &kemParams, NULL );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        return NULL;
    }

    pKey = (PSYMCRYPT_HPKEKEY) SymCryptCallbackAlloc( sizeof(SYMCRYPT_HPKEKEY) );
    if ( pKey == NULL )
    {
        return NULL;
    }

    SymCryptWipe( (PBYTE) pKey, sizeof(SYMCRYPT_HPKEKEY) );

    pKey->ciphersuite  = params;
    pKey->kemParams    = kemParams;

    switch ( params.kemId )
    {
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P256:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P384:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P521:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519:
        pKey->pKemKeyData = (PVOID) SymCryptHpkeDhkemkeyAllocate( params.kemId );
        break;
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_512:
        pKey->pKemKeyData = (PVOID) SymCryptMlKemkeyAllocate( SYMCRYPT_MLKEM_PARAMS_MLKEM512 );
        break;
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_768:
        pKey->pKemKeyData = (PVOID) SymCryptMlKemkeyAllocate( SYMCRYPT_MLKEM_PARAMS_MLKEM768 );
        break;
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_1024:
        pKey->pKemKeyData = (PVOID) SymCryptMlKemkeyAllocate( SYMCRYPT_MLKEM_PARAMS_MLKEM1024 );
        break;
    case SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256:
        pKey->pKemKeyData = (PVOID) SymCryptCompositeMlKemkeyAllocate( SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM768_P256 );
        break;
    case SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384:
        pKey->pKemKeyData = (PVOID) SymCryptCompositeMlKemkeyAllocate( SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM1024_P384 );
        break;
    case SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519:
        pKey->pKemKeyData = (PVOID) SymCryptCompositeMlKemkeyAllocate( SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM768_X25519 );
        break;
    default:
        // Unreachable: ValidateCiphersuite already rejected unsupported kemId.
        SYMCRYPT_ASSERT( FALSE );
        break;
    }
    if ( pKey->pKemKeyData == NULL )
    {
        SymCryptCallbackFree( pKey );
        return NULL;
    }

    SYMCRYPT_SET_MAGIC( pKey );
    return pKey;
}

VOID
SYMCRYPT_CALL
SymCryptHpkekeyFree(
    _Inout_ PSYMCRYPT_HPKEKEY   pkHpkekey )
{
    if ( pkHpkekey == NULL )
    {
        return;
    }

    SYMCRYPT_CHECK_MAGIC( pkHpkekey );

    if ( pkHpkekey->pKemKeyData != NULL )
    {
        switch ( pkHpkekey->ciphersuite.kemId )
        {
        case SYMCRYPT_HPKE_KEM_ID_DHKEM_P256:
        case SYMCRYPT_HPKE_KEM_ID_DHKEM_P384:
        case SYMCRYPT_HPKE_KEM_ID_DHKEM_P521:
        case SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519:
            SymCryptHpkeDhkemkeyFree( (PSYMCRYPT_HPKE_DHKEMKEY) pkHpkekey->pKemKeyData );
            break;
        case SYMCRYPT_HPKE_KEM_ID_MLKEM_512:
        case SYMCRYPT_HPKE_KEM_ID_MLKEM_768:
        case SYMCRYPT_HPKE_KEM_ID_MLKEM_1024:
            SymCryptMlKemkeyFree( (PSYMCRYPT_MLKEMKEY) pkHpkekey->pKemKeyData );
            break;
        case SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256:
        case SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384:
        case SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519:
            SymCryptCompositeMlKemkeyFree( (PSYMCRYPT_COMPOSITE_MLKEMKEY) pkHpkekey->pKemKeyData );
            break;
        default:
            SYMCRYPT_ASSERT( FALSE );
            break;
        }
    }

    SymCryptWipe( (PBYTE) pkHpkekey, sizeof(SYMCRYPT_HPKEKEY) );
    SymCryptCallbackFree( pkHpkekey );
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkekeyGenerate(
    _Inout_ PSYMCRYPT_HPKEKEY   pkHpkekey,
            UINT32              flags )
{
    SYMCRYPT_CHECK_MAGIC( pkHpkekey );

    switch ( pkHpkekey->ciphersuite.kemId )
    {
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P256:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P384:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P521:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519:
        return SymCryptHpkeDhkemkeyGenerate( (PSYMCRYPT_HPKE_DHKEMKEY) pkHpkekey->pKemKeyData, flags );
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_512:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_768:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_1024:
        return SymCryptMlKemkeyGenerate( (PSYMCRYPT_MLKEMKEY) pkHpkekey->pKemKeyData, flags );
    case SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519:
        return SymCryptCompositeMlKemkeyGenerate( (PSYMCRYPT_COMPOSITE_MLKEMKEY) pkHpkekey->pKemKeyData, flags );
    default:
        SYMCRYPT_ASSERT( FALSE );
        return SYMCRYPT_NOT_IMPLEMENTED;
    }
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkekeySetValue(
    _In_reads_bytes_( cbSrc )   PCBYTE                  pbSrc,
                                SIZE_T                  cbSrc,
                                SYMCRYPT_HPKEKEY_FORMAT hpkeKeyFormat,
                                UINT32                  flags,
    _Inout_                     PSYMCRYPT_HPKEKEY       pkHpkekey )
{
    SYMCRYPT_MLKEMKEY_FORMAT mlKemFormat;
    SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT compositeMlKemFormat;

    SYMCRYPT_CHECK_MAGIC( pkHpkekey );

    if ( hpkeKeyFormat == SYMCRYPT_HPKEKEY_FORMAT_NULL )
    {
        return SYMCRYPT_INVALID_ARGUMENT;
    }

    switch ( pkHpkekey->ciphersuite.kemId )
    {
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P256:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P384:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P521:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519:
        return SymCryptHpkeDhkemkeySetValue(
            pbSrc, cbSrc,
            hpkeKeyFormat,
            flags,
            (PSYMCRYPT_HPKE_DHKEMKEY) pkHpkekey->pKemKeyData );
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_512:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_768:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_1024:
        mlKemFormat = SymCryptHpkeToMlKemKeyFormat( hpkeKeyFormat );
        if ( mlKemFormat == SYMCRYPT_MLKEMKEY_FORMAT_NULL )
        {
            return SYMCRYPT_INVALID_ARGUMENT;
        }
        return SymCryptMlKemkeySetValue(
            pbSrc, cbSrc,
            mlKemFormat,
            flags,
            (PSYMCRYPT_MLKEMKEY) pkHpkekey->pKemKeyData );
    case SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519:
        compositeMlKemFormat = SymCryptHpkeToCompositeMlKemKeyFormat( hpkeKeyFormat );
        if ( compositeMlKemFormat == SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_NULL )
        {
            return SYMCRYPT_INVALID_ARGUMENT;
        }
        return SymCryptCompositeMlKemkeySetValue(
            pbSrc, cbSrc,
            compositeMlKemFormat,
            flags,
            (PSYMCRYPT_COMPOSITE_MLKEMKEY) pkHpkekey->pKemKeyData );
    default:
        SYMCRYPT_ASSERT( FALSE );
        return SYMCRYPT_NOT_IMPLEMENTED;
    }
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkekeyGetValue(
    _In_                        PCSYMCRYPT_HPKEKEY      pkHpkekey,
    _Out_writes_bytes_( cbDst ) PBYTE                   pbDst,
                                SIZE_T                  cbDst,
                                SYMCRYPT_HPKEKEY_FORMAT hpkeKeyFormat,
                                UINT32                  flags )
{
    SYMCRYPT_MLKEMKEY_FORMAT mlKemFormat;
    SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT compositeMlKemFormat;

    SYMCRYPT_CHECK_MAGIC( pkHpkekey );

    if ( hpkeKeyFormat == SYMCRYPT_HPKEKEY_FORMAT_NULL )
    {
        return SYMCRYPT_INVALID_ARGUMENT;
    }

    switch ( pkHpkekey->ciphersuite.kemId )
    {
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P256:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P384:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P521:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519:
        return SymCryptHpkeDhkemkeyGetValue(
            (PCSYMCRYPT_HPKE_DHKEMKEY) pkHpkekey->pKemKeyData,
            pbDst, cbDst,
            hpkeKeyFormat,
            flags );
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_512:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_768:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_1024:
        mlKemFormat = SymCryptHpkeToMlKemKeyFormat( hpkeKeyFormat );
        if ( mlKemFormat == SYMCRYPT_MLKEMKEY_FORMAT_NULL )
        {
            return SYMCRYPT_INVALID_ARGUMENT;
        }
        return SymCryptMlKemkeyGetValue(
            (PCSYMCRYPT_MLKEMKEY) pkHpkekey->pKemKeyData,
            pbDst, cbDst, mlKemFormat, flags );
    case SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519:
        compositeMlKemFormat = SymCryptHpkeToCompositeMlKemKeyFormat( hpkeKeyFormat );
        if ( compositeMlKemFormat == SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_NULL )
        {
            return SYMCRYPT_INVALID_ARGUMENT;
        }
        return SymCryptCompositeMlKemkeyGetValue(
            (PCSYMCRYPT_COMPOSITE_MLKEMKEY) pkHpkekey->pKemKeyData,
            pbDst, cbDst, compositeMlKemFormat, flags );
    default:
        SYMCRYPT_ASSERT( FALSE );
        return SYMCRYPT_NOT_IMPLEMENTED;
    }
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkekeyDerive(
    _In_reads_bytes_( cbIkm )   PCBYTE              pbIkm,
                                SIZE_T              cbIkm,
    _Inout_                     PSYMCRYPT_HPKEKEY   pkHpkekey,
                                UINT32              flags )
{
    SYMCRYPT_ERROR scError;
    BYTE seed[SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE];
    BYTE kemSuiteId[SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE];

    SYMCRYPT_CHECK_MAGIC( pkHpkekey );

    if ( flags != 0 )
    {
        return SYMCRYPT_INVALID_ARGUMENT;
    }

    if ( cbIkm == 0 || cbIkm > SYMCRYPT_HPKE_KDF_MAX_IKM_SIZE )
    {
        return SYMCRYPT_INVALID_ARGUMENT;
    }

    SymCryptHpkeBuildKemSuiteId( pkHpkekey->ciphersuite.kemId, kemSuiteId );

    switch ( pkHpkekey->ciphersuite.kemId )
    {
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_512:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_768:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_1024:
        SymCryptHpkeLabeledDeriveOneStage(
            SYMCRYPT_HPKE_KDF_ID_SHAKE256,
            kemSuiteId, SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE,
            pbIkm, cbIkm,
            (PCBYTE)"DeriveKeyPair", 13,
            NULL, 0,
            seed, sizeof(seed) );

        scError = SymCryptMlKemkeySetValue(
            seed, sizeof(seed),
            SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED,
            0,
            (PSYMCRYPT_MLKEMKEY) pkHpkekey->pKemKeyData );
        goto cleanup;

    case SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519:
        SymCryptHpkeLabeledDeriveOneStage(
            SYMCRYPT_HPKE_KDF_ID_SHAKE256,
            kemSuiteId, SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE,
            pbIkm, cbIkm,
            (PCBYTE)"DeriveKeyPair", 13,
            NULL, 0,
            seed, SYMCRYPT_COMPOSITE_MLKEM_IRTF_PRIVATE_SEED_SIZE );

        scError = SymCryptCompositeMlKemkeySetValue(
            seed, SYMCRYPT_COMPOSITE_MLKEM_IRTF_PRIVATE_SEED_SIZE,
            SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_IRTF_PRIVATE_SEED,
            0,
            (PSYMCRYPT_COMPOSITE_MLKEMKEY) pkHpkekey->pKemKeyData );
        goto cleanup;

    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P256:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P384:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P521:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519:
        scError = SymCryptHpkeDhkemDeriveKeyPair(
            pbIkm, cbIkm,
            (PSYMCRYPT_HPKE_DHKEMKEY) pkHpkekey->pKemKeyData );
        goto cleanup;

    default:
        SYMCRYPT_ASSERT( FALSE );
        scError = SYMCRYPT_NOT_IMPLEMENTED;
        goto cleanup;
    }

cleanup:
    SymCryptWipeKnownSize( seed, sizeof(seed) );
    return scError;
}


SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeSizeofKeyFormatFromParams(
            SYMCRYPT_HPKE_CIPHERSUITE   params,
            SYMCRYPT_HPKEKEY_FORMAT     hpkeKeyFormat,
    _Out_   SIZE_T*                     pcbKeyFormat )
{
    PCSYMCRYPT_HPKE_KEM_PARAMS pKemParams;

    pKemParams = SymCryptHpkeKemParamsFromId( (SYMCRYPT_HPKE_KEM_ID) params.kemId );
    if ( pKemParams == NULL )
    {
        return SYMCRYPT_NOT_IMPLEMENTED;
    }

    switch ( hpkeKeyFormat )
    {
    case SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY:
        *pcbKeyFormat = pKemParams->cbPrivateKey;
        return SYMCRYPT_NO_ERROR;
    case SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY:
        *pcbKeyFormat = pKemParams->cbPublicKey;
        return SYMCRYPT_NO_ERROR;
    default:
        return SYMCRYPT_INCOMPATIBLE_FORMAT;
    }
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeSizeofEncapsCiphertextFromParams(
            SYMCRYPT_HPKE_CIPHERSUITE   params,
    _Out_   SIZE_T*                     pcbEncapsCiphertext )
{
    PCSYMCRYPT_HPKE_KEM_PARAMS pKemParams;

    pKemParams = SymCryptHpkeKemParamsFromId( (SYMCRYPT_HPKE_KEM_ID) params.kemId );
    if ( pKemParams == NULL )
    {
        return SYMCRYPT_NOT_IMPLEMENTED;
    }

    *pcbEncapsCiphertext = pKemParams->cbEnc;
    return SYMCRYPT_NO_ERROR;
}

// Caller is responsible for ensuring pbSharedSecret / pbEnc buffer sizes
// match pkHpkekey->kemParams.cbSharedSecret and pkHpkekey->kemParams.cbEnc.
//
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeKemEncapsulate(
    _In_                                        PCSYMCRYPT_HPKEKEY  pkHpkekey,
    _Out_writes_bytes_( cbSharedSecret )        PBYTE               pbSharedSecret,
                                                UINT16              cbSharedSecret,
    _Out_writes_bytes_( cbEnc )                 PBYTE               pbEnc,
                                                SIZE_T              cbEnc )
{
    switch ( pkHpkekey->ciphersuite.kemId )
    {
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P256:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P384:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P521:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519:
        return SymCryptHpkeDhkemEncapsulate(
            pkHpkekey,
            pbSharedSecret, cbSharedSecret,
            pbEnc, cbEnc );
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_512:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_768:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_1024:
        return SymCryptMlKemEncapsulate(
            (PCSYMCRYPT_MLKEMKEY) pkHpkekey->pKemKeyData,
            pbSharedSecret, cbSharedSecret,
            pbEnc, cbEnc );
    case SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519:
        return SymCryptCompositeMlKemEncapsulate(
            (PCSYMCRYPT_COMPOSITE_MLKEMKEY) pkHpkekey->pKemKeyData,
            pbSharedSecret, cbSharedSecret,
            pbEnc, cbEnc );
    default:
        SYMCRYPT_ASSERT( FALSE );
        return SYMCRYPT_NOT_IMPLEMENTED;
    }
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptHpkeKemDecapsulate(
    _In_                                        PCSYMCRYPT_HPKEKEY  pkHpkekey,
    _In_reads_bytes_( cbEnc )                   PCBYTE              pbEnc,
                                                SIZE_T              cbEnc,
    _Out_writes_bytes_( cbSharedSecret )        PBYTE               pbSharedSecret,
                                                UINT16              cbSharedSecret )
{
    switch ( pkHpkekey->ciphersuite.kemId )
    {
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P256:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P384:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_P521:
    case SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519:
        return SymCryptHpkeDhkemDecapsulate(
            pkHpkekey,
            pbEnc, cbEnc,
            pbSharedSecret, cbSharedSecret );
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_512:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_768:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM_1024:
        return SymCryptMlKemDecapsulate(
            (PCSYMCRYPT_MLKEMKEY) pkHpkekey->pKemKeyData,
            pbEnc, cbEnc,
            pbSharedSecret, cbSharedSecret );
    case SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384:
    case SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519:
        return SymCryptCompositeMlKemDecapsulate(
            (PCSYMCRYPT_COMPOSITE_MLKEMKEY) pkHpkekey->pKemKeyData,
            pbEnc, cbEnc,
            pbSharedSecret, cbSharedSecret );
    default:
        SYMCRYPT_ASSERT( FALSE );
        return SYMCRYPT_NOT_IMPLEMENTED;
    }
}
