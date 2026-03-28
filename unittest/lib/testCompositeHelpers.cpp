//
// TestCompositeHelpers.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

typedef struct _TEST_COMPOSITE_EC_CURVE_PARAMS {
    SYMCRYPT_CACHED_ECURVE_ID   curveId;
    LPCSTR                      pszCurveName;
} TEST_COMPOSITE_EC_CURVE_PARAMS;

TEST_COMPOSITE_EC_CURVE_PARAMS rgTestCompositeCurveParams[] = {
    { SYMCRYPT_CACHED_ECURVE_ID_NIST_P256, "nistP256" },
    { SYMCRYPT_CACHED_ECURVE_ID_NIST_P384, "nistP384" },
    { SYMCRYPT_CACHED_ECURVE_ID_CURVE_25519, "curve25519" },
};

#define MAX_ENCODED_EC_SK_SIZE  (64)
#define MAX_ENCODED_EC_PK_SIZE  (97)

VOID
testEcKeyEncoding()
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    iprint( "    > EC Key Encoding Tests\n" );

    for( TEST_COMPOSITE_EC_CURVE_PARAMS testCurveParams : rgTestCompositeCurveParams )
    {
        PCSYMCRYPT_ECURVE pCurve;
        PSYMCRYPT_ECKEY pEckey;

        BYTE rgbEncodedSk[MAX_ENCODED_EC_SK_SIZE];
        SIZE_T cbEncodedSk;
        BYTE rgbEncodedPk[MAX_ENCODED_EC_PK_SIZE];
        SIZE_T cbEncodedPk;

        PSYMCRYPT_ECKEY pEckeyDecodedSk;
        PSYMCRYPT_ECKEY pEckeyDecodedPk;

        PBYTE pbScratch;
        SIZE_T cbScratch;

        iprint( "        Testing curve %s\n", testCurveParams.pszCurveName );

        pCurve = SymCryptGetCachedEcurve( testCurveParams.curveId );
        CHECK3( pCurve != NULL, "SymCryptGetCachedEcurve failed for curve %s", testCurveParams.pszCurveName );

        // Sanity check that we receive the same cached curve on second invocation
        CHECK3( pCurve == SymCryptGetCachedEcurve( testCurveParams.curveId ),
            "SymCryptGetCachedEcurve returned different instances for curve %s", testCurveParams.pszCurveName );

        cbScratch = SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_ECURVE_OPERATIONS( pCurve );
        pbScratch = (PBYTE) SymCryptCallbackAlloc( cbScratch );
        CHECK( pbScratch != NULL, "Scratch allocation failed" );

        pEckey = SymCryptEckeyAllocate( pCurve );
        CHECK3( pEckey != NULL, "SymCryptEckeyAllocate failed for curve %s", testCurveParams.pszCurveName );

        pEckeyDecodedSk = SymCryptEckeyAllocate( pCurve );
        CHECK3( pEckeyDecodedSk != NULL, "SymCryptEckeyAllocate failed for curve %s", testCurveParams.pszCurveName );

        pEckeyDecodedPk = SymCryptEckeyAllocate( pCurve );
        CHECK3( pEckeyDecodedPk != NULL, "SymCryptEckeyAllocate failed for curve %s", testCurveParams.pszCurveName );

        for ( UINT32 iter = 0; iter < 10; iter++ )
        {
            scError = SymCryptEckeySetRandom( SYMCRYPT_FLAG_ECKEY_ECDH, pEckey );
            CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptEckeySetRandom failed for curve %s", testCurveParams.pszCurveName );

            // Test encoding/decoding for the private key

            cbEncodedSk = SymCryptCompositeGetSizeOfEncodedEcSk( testCurveParams.curveId );
            CHECK3( cbEncodedSk != 0, "Invalid encoded size for curve %s", testCurveParams.pszCurveName );

            // First test incorrect size handling
            scError = SymCryptEckeyGetValueCompositeEncodingSk( pEckey, testCurveParams.curveId, rgbEncodedSk, cbEncodedSk+1 );
            CHECK3( scError == SYMCRYPT_WRONG_KEY_SIZE, "SymCryptEckeyGetValueCompositeEncodingSk should fail with incorrect size (curve %s)", testCurveParams.pszCurveName );

            scError = SymCryptEckeyGetValueCompositeEncodingSk( pEckey, testCurveParams.curveId, rgbEncodedSk, cbEncodedSk );
            CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptEckeyGetValueCompositeEncodingSk failed for curve %s", testCurveParams.pszCurveName );

            scError = SymCryptEckeySetValueCompositeEncodingSk( testCurveParams.curveId, rgbEncodedSk, cbEncodedSk, SYMCRYPT_FLAG_ECKEY_ECDH, pEckeyDecodedSk );
            CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptEckeySetValueCompositeEncodingSk failed for curve %s", testCurveParams.pszCurveName );

            CHECK( SymCryptIntIsEqual(pEckeyDecodedSk->piPrivateKey, pEckey->piPrivateKey), "Decoded private key does not match original private key" );
            CHECK( SymCryptEcpointIsEqual(pCurve, pEckeyDecodedSk->poPublicKey, pEckey->poPublicKey, 0, pbScratch, cbScratch), "Decoded public key does not match original public key" );

            // Test encoding/decoding for the public key

            cbEncodedPk = SymCryptCompositeGetSizeOfEncodedEcPk( testCurveParams.curveId );
            CHECK3( cbEncodedPk != 0, "Invalid encoded size for curve %s", testCurveParams.pszCurveName );

            // First test incorrect size handling
            scError = SymCryptEckeyGetValueCompositeEncodingPk( pEckey, testCurveParams.curveId, rgbEncodedPk, cbEncodedPk+1 );
            CHECK3( scError == SYMCRYPT_WRONG_KEY_SIZE, "SymCryptEckeyGetValueCompositeEncodingPk should fail with incorrect size (curve %s)", testCurveParams.pszCurveName );

            scError = SymCryptEckeyGetValueCompositeEncodingPk( pEckey, testCurveParams.curveId, rgbEncodedPk, cbEncodedPk );
            CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptEckeyGetValueCompositeEncodingPk failed for curve %s", testCurveParams.pszCurveName );

            scError = SymCryptEckeySetValueCompositeEncodingPk( testCurveParams.curveId, rgbEncodedPk, cbEncodedPk, SYMCRYPT_FLAG_ECKEY_ECDH, pEckeyDecodedPk );
            CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptEckeySetValueCompositeEncodingPk failed for curve %s", testCurveParams.pszCurveName );

            CHECK( SymCryptEcpointIsEqual(pCurve, pEckeyDecodedPk->poPublicKey, pEckey->poPublicKey, 0, pbScratch, cbScratch), "Decoded public key does not match original public key" );
        }

        // Test incorrectly formatted encodings. We skip 25519 since there is no special
        // encoding like for the other curves.
        if ( testCurveParams.curveId != SYMCRYPT_CACHED_ECURVE_ID_CURVE_25519 )
        {
            scError = SymCryptEckeySetRandom( SYMCRYPT_FLAG_ECKEY_ECDH, pEckey );
            CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptEckeySetRandom failed for curve %s", testCurveParams.pszCurveName );

            // Private key encoding corruption checks
            scError = SymCryptEckeyGetValueCompositeEncodingSk( pEckey, testCurveParams.curveId, rgbEncodedSk, cbEncodedSk );
            CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptEckeyGetValueCompositeEncodingSk failed for curve %s", testCurveParams.pszCurveName );
            SIZE_T cbSk = SymCryptEckeySizeofPrivateKey( pEckey );
            SIZE_T cbSkOffset = 2 + 3 + 2; // Sequence + version + private key octet string header
            for ( SIZE_T i = 0; i < cbEncodedSk; i++ )
            {
                // Skip the private key bytes themselves since corrupting them may still produce a valid key
                if ( i >= cbSkOffset && i < cbSkOffset + cbSk )
                {
                    continue;
                }

                rgbEncodedSk[i] ^= 0xFF;
                scError = SymCryptEckeySetValueCompositeEncodingSk( testCurveParams.curveId, rgbEncodedSk, cbEncodedSk, SYMCRYPT_FLAG_ECKEY_ECDH, pEckeyDecodedSk );
                CHECK4( scError == SYMCRYPT_INVALID_BLOB,
                    "SymCryptEckeySetValueCompositeEncodingSk should fail with corrupted byte %zu for curve %s", i, testCurveParams.pszCurveName );
                rgbEncodedSk[i] ^= 0xFF;
            }

            // Public key encoding corruption checks
            scError = SymCryptEckeyGetValueCompositeEncodingPk( pEckey, testCurveParams.curveId, rgbEncodedPk, cbEncodedPk );
            CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptEckeyGetValueCompositeEncodingPk failed for curve %s", testCurveParams.pszCurveName );

            rgbEncodedPk[0] ^= 0xFF; // Corrupt the uncompressed tag
            scError = SymCryptEckeySetValueCompositeEncodingPk( testCurveParams.curveId, rgbEncodedPk, cbEncodedPk, SYMCRYPT_FLAG_ECKEY_ECDH, pEckeyDecodedPk );
            CHECK3( scError == SYMCRYPT_INVALID_BLOB,
                "SymCryptEckeySetValueCompositeEncodingPk should fail with corrupted uncompressed tag for curve %s", testCurveParams.pszCurveName );
            rgbEncodedPk[0] ^= 0xFF;
        }

        SymCryptEckeyFree( pEckeyDecodedSk );
        SymCryptEckeyFree( pEckeyDecodedPk );
        SymCryptEckeyFree( pEckey );

        SymCryptWipe( pbScratch, cbScratch );
        SymCryptCallbackFree( pbScratch );
    }
}

VOID
testCompositeHelpers()
{
    iprint( "    Composite Helpers\n" );
    testEcKeyEncoding();
}