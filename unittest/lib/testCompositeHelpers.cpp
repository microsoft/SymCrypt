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

//
// Ecdsa-Sig-Value encoding/decoding tests
//

#define DER_TAG_SEQUENCE            0x30
#define DER_TAG_INTEGER             0x02
#define MAX_SINGLE_BYTE_LENGTH      127

#define TEST_SIG_RAW_INTEGER_MAX_SIZE       61
#define TEST_SIG_ENCODED_INTEGER_MAX_SIZE   64  // 2 + 62
#define TEST_SIG_ENCODED_TOTAL_MAX_SIZE     (129 + 1) // Maximum size of encoded data +1 for testing invalid length
#define TEST_SIG_DECODED_TOTAL_MAX_SIZE     ( 2 * TEST_SIG_RAW_INTEGER_MAX_SIZE )

typedef struct _TEST_COMPOSITE_MLDSA_EC_SIG_DATA {
    BYTE rgbRaw[2][TEST_SIG_DECODED_TOTAL_MAX_SIZE];
    SIZE_T cbRaw;
    BYTE rgbEncoded[2][TEST_SIG_ENCODED_TOTAL_MAX_SIZE];
    SIZE_T cbEncoded;

    template< SIZE_T cbRawInteger, SIZE_T cbEncodedSequence, SIZE_T cbEncodedInteger1, SIZE_T cbEncodedInteger2 >
    constexpr _TEST_COMPOSITE_MLDSA_EC_SIG_DATA(
        const BYTE (&rgbRawInteger1)[cbRawInteger],
        const BYTE (&rgbRawInteger2)[cbRawInteger],
        const BYTE (&rgbEncodedSequence)[cbEncodedSequence],
        const BYTE (&rgbEncodedInteger1)[cbEncodedInteger1],
        const BYTE (&rgbEncodedInteger2)[cbEncodedInteger2] )
        :
            rgbRaw{},
            cbRaw( 2 * cbRawInteger ),
            rgbEncoded{},
            cbEncoded( cbEncodedSequence + cbEncodedInteger1 + cbEncodedInteger2 )
    {
        static_assert( cbRawInteger <= TEST_SIG_RAW_INTEGER_MAX_SIZE );
        static_assert( cbEncodedSequence == 2 );
        static_assert( cbEncodedInteger1 <= TEST_SIG_ENCODED_INTEGER_MAX_SIZE );
        static_assert( cbEncodedInteger2 <= TEST_SIG_ENCODED_INTEGER_MAX_SIZE );
        static_assert( ( cbEncodedSequence + cbEncodedInteger1 + cbEncodedInteger2 ) <= TEST_SIG_ENCODED_TOTAL_MAX_SIZE );

        for( SIZE_T i = 0; i < cbRawInteger; i++ )
        {
            rgbRaw[0][i] = rgbRawInteger1[i];
            rgbRaw[0][cbRawInteger + i] = rgbRawInteger2[i];
            rgbRaw[1][i] = rgbRawInteger2[i];
            rgbRaw[1][cbRawInteger + i] = rgbRawInteger1[i];
        }

        for( SIZE_T i = 0; i < cbEncodedSequence; i++ )
        {
            rgbEncoded[0][i] = rgbEncodedSequence[i];
            rgbEncoded[1][i] = rgbEncodedSequence[i];
        }

        for( SIZE_T i = 0; i < cbEncodedInteger1; i++ )
        {
            rgbEncoded[0][cbEncodedSequence + i] = rgbEncodedInteger1[i];
            rgbEncoded[1][cbEncodedSequence + cbEncodedInteger2 + i] = rgbEncodedInteger1[i];
        }

        for( SIZE_T i = 0; i < cbEncodedInteger2; i++ )
        {
            rgbEncoded[0][cbEncodedSequence + cbEncodedInteger1 + i] = rgbEncodedInteger2[i];
            rgbEncoded[1][cbEncodedSequence + i] = rgbEncodedInteger2[i];
        }
    }

    template< SIZE_T cbEncodedSequence, SIZE_T cbEncodedInteger1, SIZE_T cbEncodedInteger2 >
    constexpr _TEST_COMPOSITE_MLDSA_EC_SIG_DATA(
        const BYTE (&rgbEncodedSequence)[cbEncodedSequence],
        const BYTE (&rgbEncodedInteger1)[cbEncodedInteger1],
        const BYTE (&rgbEncodedInteger2)[cbEncodedInteger2] )
        :
            rgbRaw{},
            cbRaw( 0 ),
            rgbEncoded{},
            cbEncoded( cbEncodedSequence + cbEncodedInteger1 + cbEncodedInteger2 )
    {
        static_assert( cbEncodedInteger1 <= TEST_SIG_ENCODED_INTEGER_MAX_SIZE );
        static_assert( cbEncodedInteger2 <= TEST_SIG_ENCODED_INTEGER_MAX_SIZE );
        static_assert( ( cbEncodedSequence + cbEncodedInteger1 + cbEncodedInteger2 ) <= TEST_SIG_ENCODED_TOTAL_MAX_SIZE );

        for( SIZE_T i = 0; i < cbEncodedSequence; i++ )
        {
            rgbEncoded[0][i] = rgbEncodedSequence[i];
            rgbEncoded[1][i] = rgbEncodedSequence[i];
        }

        for( SIZE_T i = 0; i < cbEncodedInteger1; i++ )
        {
            rgbEncoded[0][cbEncodedSequence + i] = rgbEncodedInteger1[i];
            rgbEncoded[1][cbEncodedSequence + cbEncodedInteger2 + i] = rgbEncodedInteger1[i];
        }

        for( SIZE_T i = 0; i < cbEncodedInteger2; i++ )
        {
            rgbEncoded[0][cbEncodedSequence + cbEncodedInteger1 + i] = rgbEncodedInteger2[i];
            rgbEncoded[1][cbEncodedSequence + i] = rgbEncodedInteger2[i];
        }
    }
} TEST_COMPOSITE_MLDSA_EC_SIG_DATA, * PTEST_COMPOSITE_MLDSA_EC_SIG_DATA;

//
// Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } per Section 2.2.3 of [RFC3279]
//
static constexpr TEST_COMPOSITE_MLDSA_EC_SIG_DATA g_rgSigTestsPassEncodeDecode[] = {
    //
    // Simple cases
    //
    {
        {0x7a},
        {0x7b},
        {DER_TAG_SEQUENCE, 6},
        {DER_TAG_INTEGER, 1, 0x7a},
        {DER_TAG_INTEGER, 1, 0x7b}
    },
    {
        {0x7a, 0x7b},
        {0x7c, 0x7d},
        {DER_TAG_SEQUENCE, 8},
        {DER_TAG_INTEGER, 2, 0x7a, 0x7b},
        {DER_TAG_INTEGER, 2, 0x7c, 0x7d}
    },
    {
        {0x7a, 0x7b, 0x7c},
        {0x7d, 0x7e, 0x7f},
        {DER_TAG_SEQUENCE, 10},
        {DER_TAG_INTEGER, 3, 0x7a, 0x7b, 0x7c},
        {DER_TAG_INTEGER, 3, 0x7d, 0x7e, 0x7f}
    },

    //
    // Pad with 0 to make integers unsigned
    //
    {
        {0x8a},
        {0x7a},
        {DER_TAG_SEQUENCE, 7},
        {DER_TAG_INTEGER, 2, 0x00, 0x8a},
        {DER_TAG_INTEGER, 1, 0x7a}
    },
    {
        {0x8a},
        {0x8b},
        {DER_TAG_SEQUENCE, 8},
        {DER_TAG_INTEGER, 2, 0x00, 0x8a},
        {DER_TAG_INTEGER, 2, 0x00, 0x8b}
    },
    {
        {0x00, 0x8a},
        {0x00, 0x8b},
        {DER_TAG_SEQUENCE, 8},
        {DER_TAG_INTEGER, 2, 0x00, 0x8a},
        {DER_TAG_INTEGER, 2, 0x00, 0x8b}
    },
    {
        {0x00, 0x8a},
        {0x7a, 0x8b},
        {DER_TAG_SEQUENCE, 8},
        {DER_TAG_INTEGER, 2, 0x00, 0x8a},
        {DER_TAG_INTEGER, 2, 0x7a, 0x8b}
    },
    {
        {0x7a, 0x7b},
        {0x8b, 0x7c},
        {DER_TAG_SEQUENCE, 9},
        {DER_TAG_INTEGER, 2, 0x7a, 0x7b},
        {DER_TAG_INTEGER, 3, 0x00, 0x8b, 0x7c}
    },
    {
        {0x7a, 0x7b},
        {0x8b, 0x8c},
        {DER_TAG_SEQUENCE, 9},
        {DER_TAG_INTEGER, 2, 0x7a, 0x7b},
        {DER_TAG_INTEGER, 3, 0x00, 0x8b, 0x8c}
    },
    {
        {0x8a, 0x7a},
        {0x8b, 0x7b},
        {DER_TAG_SEQUENCE, 10},
        {DER_TAG_INTEGER, 3, 0x00, 0x8a, 0x7a},
        {DER_TAG_INTEGER, 3, 0x00, 0x8b, 0x7b}
    },
    {
        {0x00, 0x8a, 0x7a},
        {0x00, 0x7b, 0x7c},
        {DER_TAG_SEQUENCE, 9},
        {DER_TAG_INTEGER, 3, 0x00, 0x8a, 0x7a},
        {DER_TAG_INTEGER, 2, 0x7b, 0x7c}
    },
    {
        {0x00, 0x8a, 0x7a},
        {0x00, 0x7b, 0x8b},
        {DER_TAG_SEQUENCE, 9},
        {DER_TAG_INTEGER, 3, 0x00, 0x8a, 0x7a},
        {DER_TAG_INTEGER, 2, 0x7b, 0x8b}
    },
    {
        {0x00, 0x8a, 0x7a},
        {0x00, 0x8b, 0x7b},
        {DER_TAG_SEQUENCE, 10},
        {DER_TAG_INTEGER, 3, 0x00, 0x8a, 0x7a},
        {DER_TAG_INTEGER, 3, 0x00, 0x8b, 0x7b}
    },

    //
    // Trim leading 0s but preserve unsigned
    //
    {
        {0x00, 0x7a},
        {0x00, 0x7b},
        {DER_TAG_SEQUENCE, 6},
        {DER_TAG_INTEGER, 1, 0x7a},
        {DER_TAG_INTEGER, 1, 0x7b}
    },
    {
        {0x00, 0x7a},
        {0x7b, 0x7c},
        {DER_TAG_SEQUENCE, 7},
        {DER_TAG_INTEGER, 1, 0x7a},
        {DER_TAG_INTEGER, 2, 0x7b, 0x7c}
    },
    {
        {0x00, 0x7a, 0x00},
        {0x00, 0x7b, 0x00},
        {DER_TAG_SEQUENCE, 8},
        {DER_TAG_INTEGER, 2, 0x7a, 0x00},
        {DER_TAG_INTEGER, 2, 0x7b, 0x00}
    },
    {
        {0x00, 0x8a, 0x7a, 0x00},
        {0x00, 0x00, 0x7b, 0x00},
        {DER_TAG_SEQUENCE, 10},
        {DER_TAG_INTEGER, 4, 0x00, 0x8a, 0x7a, 0x00},
        {DER_TAG_INTEGER, 2, 0x7b, 0x00}
    },
    {
        {0x00, 0x00, 0x00, 0x7a},
        {0x00, 0x00, 0x8a, 0x7b},
        {DER_TAG_SEQUENCE, 8},
        {DER_TAG_INTEGER, 1, 0x7a},
        {DER_TAG_INTEGER, 3, 0x00, 0x8a, 0x7b}
    },

    //
    // Maximum lengths
    //
    {
        {
            0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a,
            0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a,
            0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a,
            0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a
        },
        {
            0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b,
            0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b,
            0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b,
            0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b
        },
        {DER_TAG_SEQUENCE, MAX_SINGLE_BYTE_LENGTH-1},
        {DER_TAG_INTEGER, 61,
            0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a,
            0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a,
            0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a,
            0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a
        },
        {DER_TAG_INTEGER, 61,
            0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b,
            0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b,
            0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b,
            0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b
        }
    },
    {
        {
            0x8a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a,
            0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a,
            0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a,
            0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a
        },
        {
            0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b,
            0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b,
            0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b,
            0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b
        },
        {DER_TAG_SEQUENCE, MAX_SINGLE_BYTE_LENGTH},
        {DER_TAG_INTEGER, 62,
            0x00,
            0x8a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a,
            0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a,
            0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a,
            0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a
        },
        {DER_TAG_INTEGER, 61,
            0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b,
            0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b,
            0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b,
            0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b
        }
    },
};

//
// Decoding invalid Ecdsa-Sig-Values should fail
//
static constexpr TEST_COMPOSITE_MLDSA_EC_SIG_DATA g_rgSigTestsFailDecode[] = {
    //
    // Missing 0 padding
    //
    {
        {0x8a},
        {0x7a},
        {DER_TAG_SEQUENCE, 6},
        {DER_TAG_INTEGER, 1, 0x8a},
        {DER_TAG_INTEGER, 1, 0x7a}
    },
    {
        {0x00, 0x8a},
        {0x00, 0x7a},
        {DER_TAG_SEQUENCE, 6},
        {DER_TAG_INTEGER, 1, 0x8a},
        {DER_TAG_INTEGER, 1, 0x7a}
    },
    {
        {0x8a},
        {0x8b},
        {DER_TAG_SEQUENCE, 6},
        {DER_TAG_INTEGER, 1, 0x8a},
        {DER_TAG_INTEGER, 1, 0x8b}
    },
    {
        {0x00, 0x8a},
        {0x00, 0x8b},
        {DER_TAG_SEQUENCE, 6},
        {DER_TAG_INTEGER, 1, 0x8a},
        {DER_TAG_INTEGER, 1, 0x8b}
    },
    {
        {0x8a, 0x7a},
        {0x8b, 0x7b},
        {DER_TAG_SEQUENCE, 8},
        {DER_TAG_INTEGER, 2, 0x8a, 0x7a},
        {DER_TAG_INTEGER, 2, 0x8b, 0x7b}
    },
    {
        {0x8a, 0x7a},
        {0x8b, 0x8c},
        {DER_TAG_SEQUENCE, 8},
        {DER_TAG_INTEGER, 2, 0x8a, 0x7a},
        {DER_TAG_INTEGER, 2, 0x8b, 0x8c}
    },
    {
        {0x8a, 0x8b},
        {0x8c, 0x8d},
        {DER_TAG_SEQUENCE, 8},
        {DER_TAG_INTEGER, 2, 0x8a, 0x8b},
        {DER_TAG_INTEGER, 2, 0x8c, 0x8d}
    },
    {
        {0x00, 0x8a, 0x7a},
        {0x8b, 0x7b, 0x7c},
        {DER_TAG_SEQUENCE, 10},
        {DER_TAG_INTEGER, 3, 0x00, 0x8a, 0x7a},
        {DER_TAG_INTEGER, 3, 0x8b, 0x7b, 0x7c}
    },

    //
    // Un-trimmed leading 0s
    //
    {
        {0x00, 0x7a},
        {0x00, 0x7b},
        {DER_TAG_SEQUENCE, 8},
        {DER_TAG_INTEGER, 2, 0x00, 0x7a},
        {DER_TAG_INTEGER, 2, 0x00, 0x7b}
    },
    {
        {0x00, 0x8a},
        {0x00, 0x7a},
        {DER_TAG_SEQUENCE, 8},
        {DER_TAG_INTEGER, 2, 0x00, 0x8a},
        {DER_TAG_INTEGER, 2, 0x00, 0x7a}
    },
    {
        {0x00, 0x7a},
        {0x7b, 0x7c},
        {DER_TAG_SEQUENCE, 8},
        {DER_TAG_INTEGER, 2, 0x00, 0x7a},
        {DER_TAG_INTEGER, 2, 0x7b, 0x7c}
    },
    {
        {0x00, 0x7a, 0x00},
        {0x00, 0x7b, 0x00},
        {DER_TAG_SEQUENCE, 10},
        {DER_TAG_INTEGER, 3, 0x00, 0x7a, 0x00},
        {DER_TAG_INTEGER, 3, 0x00, 0x7b, 0x00}
    },
    {
        {0x00, 0x8a, 0x7a, 0x00},
        {0x00, 0x00, 0x7b, 0x00},
        {DER_TAG_SEQUENCE, 12},
        {DER_TAG_INTEGER, 4, 0x00, 0x8a, 0x7a, 0x00},
        {DER_TAG_INTEGER, 4, 0x00, 0x00, 0x7b, 0x00}
    },
    {
        {0x00, 0x00, 0x00, 0x7a},
        {0x00, 0x00, 0x8a, 0x7b},
        {DER_TAG_SEQUENCE, 12},
        {DER_TAG_INTEGER, 4, 0x00, 0x00, 0x00, 0x7a},
        {DER_TAG_INTEGER, 4, 0x00, 0x00, 0x8a, 0x7b}
    },

    //
    // 0 values
    //
    {
        {0x00},
        {0x00},
        {DER_TAG_SEQUENCE, 6},
        {DER_TAG_INTEGER, 1, 0x00},
        {DER_TAG_INTEGER, 1, 0x00}
    },
    {
        {0x00, 0x00},
        {0x00, 0x00},
        {DER_TAG_SEQUENCE, 6},
        {DER_TAG_INTEGER, 1, 0x00},
        {DER_TAG_INTEGER, 1, 0x00}
    },
    {
        {0x00, 0x00, 0x00},
        {0x00, 0x00, 0x00},
        {DER_TAG_SEQUENCE, 6},
        {DER_TAG_INTEGER, 1, 0x00},
        {DER_TAG_INTEGER, 1, 0x00}
    },
    {
        {0x00, 0x8a},
        {0x00, 0x00},
        {DER_TAG_SEQUENCE, 7},
        {DER_TAG_INTEGER, 2, 0x00, 0x8a},
        {DER_TAG_INTEGER, 1, 0x00}
    },
    {
        {0x00, 0x7a},
        {0x00, 0x00},
        {DER_TAG_SEQUENCE, 6},
        {DER_TAG_INTEGER, 1, 0x7a},
        {DER_TAG_INTEGER, 1, 0x00}
    },

    //
    // Incorrect DER tags
    //
    {
        {DER_TAG_SEQUENCE, 6},
        {DER_TAG_INTEGER+1, 1, 0x7a},
        {DER_TAG_INTEGER, 1, 0x7b}
    },
    {
        {DER_TAG_SEQUENCE+1, 6},
        {DER_TAG_INTEGER+1, 1, 0x7a},
        {DER_TAG_INTEGER, 1, 0x7b}
    },
    {
        {DER_TAG_SEQUENCE+1, 6},
        {DER_TAG_INTEGER+1, 1, 0x7a},
        {DER_TAG_INTEGER+1, 1, 0x7b}
    },
    {
        {DER_TAG_SEQUENCE, 6},
        {DER_TAG_SEQUENCE, 1, 0x7a},
        {DER_TAG_INTEGER, 1, 0x7b}
    },
    {
        {DER_TAG_INTEGER, 6},
        {DER_TAG_INTEGER, 1, 0x7a},
        {DER_TAG_INTEGER, 1, 0x7b}
    },
    {
        {DER_TAG_INTEGER, 6},
        {DER_TAG_SEQUENCE, 1, 0x7a},
        {DER_TAG_INTEGER, 1, 0x7b}
    },

    //
    // Lengths that are too small
    //
    {
        {DER_TAG_SEQUENCE, 0},
        {DER_TAG_INTEGER, 1, 0x7a},
        {DER_TAG_INTEGER, 1, 0x7b}
    },
    {
        {DER_TAG_SEQUENCE, 5},
        {DER_TAG_INTEGER, 0},
        {DER_TAG_INTEGER, 1, 0x7b}
    },
    {
        {DER_TAG_SEQUENCE, 5},
        {DER_TAG_INTEGER, 1, 0x7a},
        {DER_TAG_INTEGER, 1, 0x7b}
    },

    //
    // Lengths that exceed buffer size
    //
    {
        {DER_TAG_SEQUENCE, 7},
        {DER_TAG_INTEGER, 1, 0x7a},
        {DER_TAG_INTEGER, 1, 0x7b}
    },
    {
        {0x7a},
        {0x7b},
        {DER_TAG_SEQUENCE, 7},
        {DER_TAG_INTEGER, 1, 0x7a},
        {DER_TAG_INTEGER, 1, 0x7b, 0x7c}
    },
    {
        {DER_TAG_SEQUENCE, 6},
        {DER_TAG_INTEGER, 7, 0x7a},
        {DER_TAG_INTEGER, 1, 0x7b}
    },
    {
        {DER_TAG_SEQUENCE, 7},
        {DER_TAG_INTEGER, 7, 0x7a},
        {DER_TAG_INTEGER, 1, 0x7b}
    },
    {
        {DER_TAG_SEQUENCE, MAX_SINGLE_BYTE_LENGTH},
        {DER_TAG_INTEGER, 1, 0x7a},
        {DER_TAG_INTEGER, 1, 0x7b}
    },
    {
        {DER_TAG_SEQUENCE, 6},
        {DER_TAG_INTEGER, MAX_SINGLE_BYTE_LENGTH, 0x7a},
        {DER_TAG_INTEGER, 1, 0x7b}
    },
    {
        {DER_TAG_SEQUENCE, MAX_SINGLE_BYTE_LENGTH},
        {DER_TAG_INTEGER, MAX_SINGLE_BYTE_LENGTH, 0x7a},
        {DER_TAG_INTEGER, 1, 0x7b}
    },

    //
    // Superfluous 0 padding (untrimmed leading 0) that exceeds the raw integer size
    //
    {
        {0x8a},
        {0x7a},
        {DER_TAG_SEQUENCE, 8},
        {DER_TAG_INTEGER, 2, 0x00, 0x8a},
        {DER_TAG_INTEGER, 2, 0x00, 0x7a}
    },
    {
        {0x7a},
        {0x7b},
        {DER_TAG_SEQUENCE, 8},
        {DER_TAG_INTEGER, 2, 0x00, 0x7a},
        {DER_TAG_INTEGER, 2, 0x00, 0x7b}
    },
    {
        {0x00, 0x8a},
        {0x00, 0x7a},
        {DER_TAG_SEQUENCE, 9},
        {DER_TAG_INTEGER, 2, 0x00, 0x8a},
        {DER_TAG_INTEGER, 3, 0x00, 0x00, 0x7a}
    },

    //
    // Lengths that exceed the maximum value that can be encoded in a single byte
    //
    {
        {
            0x8a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a,
            0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a,
            0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a,
            0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a
        },
        {
            0x8b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b,
            0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b,
            0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b,
            0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b
        },
        {DER_TAG_SEQUENCE, MAX_SINGLE_BYTE_LENGTH+1},
        {DER_TAG_INTEGER, 62,
            0x00,
            0x8a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a,
            0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a,
            0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a,
            0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a
        },
        {DER_TAG_INTEGER, 62,
            0x00,
            0x8b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b,
            0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b,
            0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b,
            0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b
        }
    },
};

static
VOID
printByteArray(
    _In_ LPCSTR pcszPrefix,
    _In_reads_bytes_( cbData ) PCBYTE pcbData,
    SIZE_T cbData )
{
    printf( "%s", pcszPrefix );

    for( SIZE_T i = 0; i < cbData; i++ )
    {
        printf( "0x%02X ", pcbData[i] );
    }

    printf( "\n" );
}

static
VOID
testEcSignatureEncodingUnitPassEncodeDecode(
    _In_reads_bytes_( cbRawSignature ) PCBYTE pcbRawSignature,
    SIZE_T cbRawSignature,
    _In_reads_bytes_( cbEncodedSignature ) PCBYTE pcbEncodedSignature,
    SIZE_T cbEncodedSignature )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    std::vector<BYTE> vbBuffer;
    SIZE_T cbResult = 0;

    vbBuffer.resize( cbEncodedSignature );

    scError = SymCryptEcdsaSigValueCompositeEncode(
                pcbRawSignature,
                cbRawSignature,
                vbBuffer.data(),
                vbBuffer.size(),
                &cbResult );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        printByteArray( "Known Decoded: ", pcbRawSignature, cbRawSignature );
        printByteArray( "Known Encoded: ", pcbEncodedSignature, cbEncodedSignature );

        FATAL2( "SymCryptEcdsaSigValueCompositeEncode failed with %x", scError );
    }
    else if( memcmp( vbBuffer.data(), pcbEncodedSignature, cbEncodedSignature ) != 0 )
    {
        printByteArray( "Known Decoded: ", pcbRawSignature, cbRawSignature );
        printByteArray( "Known Encoded: ", pcbEncodedSignature, cbEncodedSignature );
        printByteArray( " Test Encoded: ", vbBuffer.data(), vbBuffer.size() );

        FATAL( "SymCryptEcdsaSigValueCompositeEncode produced incorrect Ecdsa-Sig-Value" );
    }

    vbBuffer.resize( cbRawSignature );

    scError = SymCryptEcdsaSigValueCompositeDecode(
        pcbEncodedSignature,
        cbEncodedSignature,
        vbBuffer.data(),
        vbBuffer.size() );

    if( scError != SYMCRYPT_NO_ERROR )
    {
        printByteArray( "Known Encoded: ", pcbEncodedSignature, cbEncodedSignature );
        printByteArray( "Known Decoded: ", pcbRawSignature, cbRawSignature );

        FATAL2( "SymCryptEcdsaSigValueCompositeDecode failed with %x", scError );
    }
    else if( memcmp( vbBuffer.data(), pcbRawSignature, cbRawSignature ) != 0 )
    {
        printByteArray( "Known Encoded: ", pcbEncodedSignature, cbEncodedSignature );
        printByteArray( "Known Decoded: ", pcbRawSignature, cbRawSignature );
        printByteArray( " Test Decoded: ", vbBuffer.data(), vbBuffer.size() );

        FATAL( "SymCryptEcdsaSigValueCompositeDecode produced incorrect data" );
    }
}

static
VOID
testEcSignatureEncodingUnitFailDecode(
    SIZE_T cbRawSignature,
    _In_reads_bytes_( cbEncodedSignature ) PCBYTE pcbEncodedSignature,
    SIZE_T cbEncodedSignature )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    std::vector<BYTE> vbBuffer( cbRawSignature );

    scError = SymCryptEcdsaSigValueCompositeDecode(
        pcbEncodedSignature,
        cbEncodedSignature,
        vbBuffer.data(),
        vbBuffer.size() );
    if( scError == SYMCRYPT_NO_ERROR )
    {
        printByteArray( "Known Encoded: ", pcbEncodedSignature, cbEncodedSignature );
        printByteArray( " Test Decoded: ", vbBuffer.data(), vbBuffer.size() );

        FATAL( "SymCryptEcdsaSigValueCompositeDecode succeeded for invalid Ecdsa-Sig-Value" );
    }
}

static
VOID
testEcSignatureEncodingUnit()
{
    printf( "        Test successfully encoding and decoding valid data\n" );

    for( const auto& test : g_rgSigTestsPassEncodeDecode )
    {
        for( int i = 0; i < 2; i++ )
        {
            testEcSignatureEncodingUnitPassEncodeDecode(
                test.rgbRaw[i],
                test.cbRaw,
                test.rgbEncoded[i],
                test.cbEncoded );
        }
    }

    printf( "        Test expected failures when decoding invalid data\n" );

    for( const auto& test : g_rgSigTestsFailDecode )
    {
        for( int i = 0; i < 2; i++ )
        {
            testEcSignatureEncodingUnitFailDecode(
                ( test.cbRaw > 0 ? test.cbRaw : TEST_SIG_DECODED_TOTAL_MAX_SIZE ),
                test.rgbEncoded[i],
                test.cbEncoded );
        }
    }
}

#define SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_SIGNATURE_P256_MAX     (72)
#define SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_SIGNATURE_P384_MAX     (104)

typedef struct _TEST_COMPOSITE_MLDSA_EC_SIG_PARAMS {
    LPCSTR pcszCurveName;
    SYMCRYPT_CACHED_ECURVE_ID eCurveId;
    SIZE_T cbEncodedSignatureMax;
} TEST_COMPOSITE_MLDSA_EC_SIG_PARAMS, * PTEST_COMPOSITE_MLDSA_EC_SIG_PARAMS;

static const TEST_COMPOSITE_MLDSA_EC_SIG_PARAMS g_rgSigTestParams[] = {
    {
        "nistP256",
        SYMCRYPT_CACHED_ECURVE_ID_NIST_P256,
        SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_SIGNATURE_P256_MAX
    },
    {
        "nistP384",
        SYMCRYPT_CACHED_ECURVE_ID_NIST_P384,
        SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_SIGNATURE_P384_MAX
    },
};

static
VOID
testEcSignatureEncodingFunctionalTest(
    SYMCRYPT_CACHED_ECURVE_ID eCurveId,
    SIZE_T cbSignatureEncodedMax )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PCSYMCRYPT_ECURVE pCurve = NULL;
    PSYMCRYPT_ECKEY pkEckey = NULL;
    BYTE rgbMessage[64];
    BYTE rgbSignatureRaw[TEST_SIG_DECODED_TOTAL_MAX_SIZE];
    SIZE_T cbSignatureRaw = 0;
    BYTE rgbSignatureEncoded[TEST_SIG_ENCODED_TOTAL_MAX_SIZE];
    SIZE_T cbSignatureEncoded = cbSignatureEncodedMax;
    BYTE rgbSignatureDecoded[TEST_SIG_DECODED_TOTAL_MAX_SIZE];
    SIZE_T cbSignatureDecoded = 0;

    for( int i = 0; i < sizeof( rgbMessage ); i++ )
    {
        rgbMessage[i] = g_rng.byte();
    }

    pCurve = SymCryptGetCachedEcurve( eCurveId );
    CHECK( pCurve != NULL, "SymCryptGetCachedEcurve failed" );

    pkEckey = SymCryptEckeyAllocate( pCurve );
    CHECK( pkEckey != NULL, "SymCryptEckeyAllocate failed" );

    scError = SymCryptEckeySetRandom( SYMCRYPT_FLAG_ECKEY_ECDSA, pkEckey );
    CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptEckeySetRandom failed with %x", scError );

    cbSignatureRaw = 2 * SymCryptEcurveSizeofFieldElement( pCurve );
    cbSignatureDecoded = cbSignatureRaw;

    //
    // Produce raw ECC signature
    //
    scError = SymCryptEcDsaSign(
                pkEckey,
                rgbMessage,
                sizeof( rgbMessage ),
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0, // flags
                rgbSignatureRaw,
                cbSignatureRaw );
    CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptEcDsaSign failed with %x", scError );

    //
    // DER-encode and decode the ECC signature
    //
    scError = SymCryptEcdsaSigValueCompositeEncode(
                rgbSignatureRaw,
                cbSignatureRaw,
                rgbSignatureEncoded,
                cbSignatureEncoded,
                &cbSignatureEncoded );
    CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptEcdsaSigValueCompositeEncode failed with %x", scError );

    scError = SymCryptEcdsaSigValueCompositeDecode(
                rgbSignatureEncoded,
                cbSignatureEncoded,
                rgbSignatureDecoded,
                cbSignatureDecoded);
    CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptEcdsaSigValueCompositeDecode failed with %x", scError );

    //
    // Decoded signature should be identical to the original one
    //
    CHECK( memcmp( rgbSignatureRaw, rgbSignatureDecoded, cbSignatureDecoded ) == 0, "Incorrect decoded signature" );

    scError = SymCryptEcDsaVerify(
                pkEckey,
                rgbMessage,
                sizeof( rgbMessage ),
                rgbSignatureDecoded,
                cbSignatureDecoded,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0 ); // flags
    CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptEcDsaVerify failed with %x", scError );

    SymCryptEckeyFree( pkEckey );
}

static
VOID
testEcSignatureEncodingFunctional()
{
    for( const auto& test : g_rgSigTestParams )
    {
        printf( "        Test encoding and decoding for curve %s\n", test.pcszCurveName );

        for( int i = 0; i < 100; i++ )
        {
            testEcSignatureEncodingFunctionalTest( test.eCurveId, test.cbEncodedSignatureMax );
        }
    }
}

static
VOID
testEcSignatureEncoding()
{
    iprint( "    > Ecdsa-Sig-Value Encoding and Decoding Tests\n" );

    INT64 nOutstandingAllocs = 0;

    nOutstandingAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nOutstandingCheckedAllocs);
    CHECK3( nOutstandingAllocs  == 0, "Memory leak %d outstanding", nOutstandingAllocs );

    testEcSignatureEncodingUnit();
    testEcSignatureEncodingFunctional();

    nOutstandingAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nOutstandingCheckedAllocs);
    CHECK3( nOutstandingAllocs == 0, "Memory leak, %d outstanding", nOutstandingAllocs );
}

VOID
testCompositeHelpers()
{
    iprint( "    Composite Helpers\n" );
    testEcKeyEncoding();
    testEcSignatureEncoding();
}
