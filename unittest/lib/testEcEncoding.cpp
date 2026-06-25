//
// testEcEncoding.cpp
//
// Tests for SymCryptEckey{Set,Get}ValueIetfPublicKey (symcrypt_plus).
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

typedef struct _TEST_EC_ENCODING_CURVE_PARAMS {
    PCSYMCRYPT_ECURVE_PARAMS                pCurveParams;
    SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT   format;
    SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT  privateFormat;
    LPCSTR                                  pszCurveName;
} TEST_EC_ENCODING_CURVE_PARAMS;

static const TEST_EC_ENCODING_CURVE_PARAMS rgTestEcEncodingCurveParams[] = {
    { SymCryptEcurveParamsNistP256,   SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED, SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NIST_SCALAR, "nistP256"   },
    { SymCryptEcurveParamsNistP384,   SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED, SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NIST_SCALAR, "nistP384"   },
    { SymCryptEcurveParamsNistP521,   SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED, SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NIST_SCALAR, "nistP521"   },
    { SymCryptEcurveParamsCurve25519, SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_RAW_X_LE,          SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_C25519,    "curve25519" },
};

#define MAX_ENCODED_IETF_PK_SIZE    (1 + 2 * 66)    // 0x04 || X || Y for P-521
#define MAX_ENCODED_IETF_SK_SIZE    (66)            // P-521 scalar

VOID
testEcIetfPublicKeyEncoding()
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    iprint( "    > EC IETF Public Key Encoding Tests\n" );

    for ( const TEST_EC_ENCODING_CURVE_PARAMS &params : rgTestEcEncodingCurveParams )
    {
        PSYMCRYPT_ECURVE pCurve;
        PSYMCRYPT_ECKEY pEckey;
        PSYMCRYPT_ECKEY pEckeyDecoded;

        BYTE rgbEncodedPk[MAX_ENCODED_IETF_PK_SIZE];
        SIZE_T cbEncodedPk;
        BYTE rgbEncodedSk[MAX_ENCODED_IETF_SK_SIZE];
        SIZE_T cbEncodedSk;
        SYMCRYPT_NUMBER_FORMAT privateNumFormat;
        SYMCRYPT_ECPOINT_FORMAT privateEcPointFormat;

        PBYTE pbScratch;
        SIZE_T cbScratch;

        iprint( "        Testing curve %s\n", params.pszCurveName );

        pCurve = SymCryptEcurveAllocate( params.pCurveParams, 0 );
        CHECK3( pCurve != NULL, "SymCryptEcurveAllocate failed for curve %s", params.pszCurveName );

        cbScratch = SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_ECURVE_OPERATIONS( pCurve );
        pbScratch = (PBYTE) SymCryptCallbackAlloc( cbScratch );
        CHECK( pbScratch != NULL, "Scratch allocation failed" );

        pEckey = SymCryptEckeyAllocate( pCurve );
        CHECK3( pEckey != NULL, "SymCryptEckeyAllocate failed for curve %s", params.pszCurveName );

        pEckeyDecoded = SymCryptEckeyAllocate( pCurve );
        CHECK3( pEckeyDecoded != NULL, "SymCryptEckeyAllocate failed for curve %s", params.pszCurveName );

        // Compute the expected encoded size for the curve+format pair.
        switch ( params.format )
        {
        case SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED:
            cbEncodedPk = 1 + SymCryptEckeySizeofPublicKey( pEckey, SYMCRYPT_ECPOINT_FORMAT_XY );
            break;
        case SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_RAW_X_LE:
            cbEncodedPk = SymCryptEckeySizeofPublicKey( pEckey, SYMCRYPT_ECPOINT_FORMAT_X );
            break;
        default:
            cbEncodedPk = 0;
            CHECK( FALSE, "Unexpected format" );
            break;
        }
        CHECK( cbEncodedPk <= MAX_ENCODED_IETF_PK_SIZE, "MAX_ENCODED_IETF_PK_SIZE is too small" );

        switch ( params.privateFormat )
        {
        case SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NIST_SCALAR:
            privateNumFormat = SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
            privateEcPointFormat = SYMCRYPT_ECPOINT_FORMAT_XY;
            break;
        case SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_C25519:
            privateNumFormat = SYMCRYPT_NUMBER_FORMAT_LSB_FIRST;
            privateEcPointFormat = SYMCRYPT_ECPOINT_FORMAT_X;
            break;
        default:
            privateNumFormat = SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
            privateEcPointFormat = SYMCRYPT_ECPOINT_FORMAT_XY;
            CHECK( FALSE, "Unexpected private format" );
            break;
        }
        cbEncodedSk = SymCryptEckeySizeofPrivateKey( pEckey );
        CHECK( cbEncodedSk <= MAX_ENCODED_IETF_SK_SIZE, "MAX_ENCODED_IETF_SK_SIZE is too small" );

        for ( UINT32 iter = 0; iter < 10; iter++ )
        {
            scError = SymCryptEckeySetRandom( SYMCRYPT_FLAG_ECKEY_ECDH, pEckey );
            CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptEckeySetRandom failed for curve %s", params.pszCurveName );

            // Get with the wrong size must fail.
            scError = SymCryptEckeyGetValueIetfPublicKey( pEckey, params.format, rgbEncodedPk, cbEncodedPk + 1 );
            CHECK3( scError == SYMCRYPT_WRONG_KEY_SIZE,
                "SymCryptEckeyGetValueIetfPublicKey should fail with incorrect size (curve %s)", params.pszCurveName );

            // Get with the right size succeeds and (for SEC1) writes the 0x04 tag.
            scError = SymCryptEckeyGetValueIetfPublicKey( pEckey, params.format, rgbEncodedPk, cbEncodedPk );
            CHECK3( scError == SYMCRYPT_NO_ERROR,
                "SymCryptEckeyGetValueIetfPublicKey failed for curve %s", params.pszCurveName );

            if ( params.format == SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED )
            {
                CHECK3( rgbEncodedPk[0] == 0x04,
                    "Expected SEC1 uncompressed tag for curve %s", params.pszCurveName );
            }

            // Set with the wrong size must fail.
            scError = SymCryptEckeySetValueIetfPublicKey( rgbEncodedPk, cbEncodedPk + 1, params.format, SYMCRYPT_FLAG_ECKEY_ECDH, pEckeyDecoded );
            CHECK3( scError == SYMCRYPT_WRONG_KEY_SIZE,
                "SymCryptEckeySetValueIetfPublicKey should fail with incorrect size (curve %s)", params.pszCurveName );

            // Round-trip Set succeeds and produces the same public point.
            scError = SymCryptEckeySetValueIetfPublicKey( rgbEncodedPk, cbEncodedPk, params.format, SYMCRYPT_FLAG_ECKEY_ECDH, pEckeyDecoded );
            CHECK3( scError == SYMCRYPT_NO_ERROR,
                "SymCryptEckeySetValueIetfPublicKey failed for curve %s", params.pszCurveName );

            CHECK( SymCryptEcpointIsEqual( pCurve, pEckeyDecoded->poPublicKey, pEckey->poPublicKey, 0, pbScratch, cbScratch ),
                "Decoded public key does not match original" );

            scError = SymCryptEckeyGetValue(
                pEckey,
                rgbEncodedSk, cbEncodedSk,
                NULL, 0,
                privateNumFormat,
                privateEcPointFormat,
                0 );
            CHECK3( scError == SYMCRYPT_NO_ERROR,
                "SymCryptEckeyGetValue private key failed for curve %s", params.pszCurveName );

            scError = SymCryptEckeySetValueIetfPrivateKey(
                rgbEncodedSk, cbEncodedSk + 1,
                params.privateFormat,
                SYMCRYPT_FLAG_ECKEY_ECDH,
                pEckeyDecoded );
            CHECK3( scError == SYMCRYPT_WRONG_KEY_SIZE,
                "SymCryptEckeySetValueIetfPrivateKey should fail with incorrect size (curve %s)", params.pszCurveName );

            scError = SymCryptEckeySetValueIetfPrivateKey(
                rgbEncodedSk, cbEncodedSk,
                params.privateFormat,
                SYMCRYPT_FLAG_ECKEY_ECDH,
                pEckeyDecoded );
            CHECK3( scError == SYMCRYPT_NO_ERROR,
                "SymCryptEckeySetValueIetfPrivateKey failed for curve %s", params.pszCurveName );

            CHECK( SymCryptEcpointIsEqual( pCurve, pEckeyDecoded->poPublicKey, pEckey->poPublicKey, 0, pbScratch, cbScratch ),
                "Decoded private key public point does not match original" );
        }

        // SEC1-tag corruption check (SEC1 format only).
        if ( params.format == SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED )
        {
            scError = SymCryptEckeySetRandom( SYMCRYPT_FLAG_ECKEY_ECDH, pEckey );
            CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptEckeySetRandom failed" );

            scError = SymCryptEckeyGetValueIetfPublicKey( pEckey, params.format, rgbEncodedPk, cbEncodedPk );
            CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptEckeyGetValueIetfPublicKey failed" );

            rgbEncodedPk[0] ^= 0x01;
            scError = SymCryptEckeySetValueIetfPublicKey( rgbEncodedPk, cbEncodedPk, params.format, SYMCRYPT_FLAG_ECKEY_ECDH, pEckeyDecoded );
            CHECK3( scError == SYMCRYPT_INVALID_BLOB,
                "SymCryptEckeySetValueIetfPublicKey should reject corrupted SEC1 tag (curve %s)", params.pszCurveName );
        }

        // Invalid-format checks.
        scError = SymCryptEckeyGetValueIetfPublicKey( pEckey, SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_NULL, rgbEncodedPk, cbEncodedPk );
        CHECK( scError == SYMCRYPT_INVALID_ARGUMENT,
            "SymCryptEckeyGetValueIetfPublicKey should reject NULL format" );

        scError = SymCryptEckeySetValueIetfPublicKey( rgbEncodedPk, cbEncodedPk, SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_NULL, SYMCRYPT_FLAG_ECKEY_ECDH, pEckeyDecoded );
        CHECK( scError == SYMCRYPT_INVALID_ARGUMENT,
            "SymCryptEckeySetValueIetfPublicKey should reject NULL format" );

        scError = SymCryptEckeySetValueIetfPrivateKey( rgbEncodedSk, cbEncodedSk, SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NULL, SYMCRYPT_FLAG_ECKEY_ECDH, pEckeyDecoded );
        CHECK( scError == SYMCRYPT_INVALID_ARGUMENT,
            "SymCryptEckeySetValueIetfPrivateKey should reject NULL format" );

        SymCryptEckeyFree( pEckeyDecoded );
        SymCryptEckeyFree( pEckey );
        SymCryptWipe( pbScratch, cbScratch );
        SymCryptCallbackFree( pbScratch );
        SymCryptEcurveFree( pCurve );
    }
}

VOID
testEcEncoding()
{
    INT64 nOutstandingAllocs = 0;

    iprint( "    EC Encoding\n" );

    testEcIetfPublicKeyEncoding();

    nOutstandingAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64( &g_nOutstandingCheckedAllocs );
    CHECK3( nOutstandingAllocs == 0, "Memory leak, %d outstanding", nOutstandingAllocs );
}
