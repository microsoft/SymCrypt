//
// Test Montgomery Curve
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

// Test vectors

static BYTE private_key_1[32] = {    // *** MSB first
 0x6A, 0x2C, 0xB9, 0x1D, 0xA5, 0xFB, 0x77, 0xB1, 0x2A, 0x99, 0xC0, 0xEB, 0x87, 0x2F, 0x4C, 0xDF,
 0x45, 0x66, 0xB2, 0x51, 0x72, 0xC1, 0x16, 0x3C, 0x7D, 0xA5, 0x18, 0x73, 0x0A, 0x6D, 0x07, 0x70
};

static BYTE public_key_1[32] = {     // *** LSB first
 0x85, 0x20, 0xF0, 0x09, 0x89, 0x30, 0xA7, 0x54, 0x74, 0x8B, 0x7D, 0xDC, 0xB4, 0x3E, 0xF7, 0x5A,
 0x0D, 0xBF, 0x3A, 0x0D, 0x26, 0x38, 0x1A, 0xF4, 0xEB, 0xA4, 0xA9, 0x8E, 0xAA, 0x9B, 0x4E, 0x6A
};

static BYTE public_key_1_xy[64] = {     // *** LSB first
 0x85, 0x20, 0xF0, 0x09, 0x89, 0x30, 0xA7, 0x54, 0x74, 0x8B, 0x7D, 0xDC, 0xB4, 0x3E, 0xF7, 0x5A,
 0x0D, 0xBF, 0x3A, 0x0D, 0x26, 0x38, 0x1A, 0xF4, 0xEB, 0xA4, 0xA9, 0x8E, 0xAA, 0x9B, 0x4E, 0x6A,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static BYTE private_key_2[32] = {    // *** MSB first
 0x6B, 0xE0, 0x88, 0xFF, 0x27, 0x8B, 0x2F, 0x1C, 0xFD, 0xB6, 0x18, 0x26, 0x29, 0xB1, 0x3B, 0x6F,
 0xE6, 0x0E, 0x80, 0x83, 0x8B, 0x7F, 0xE1, 0x79, 0x4B, 0x8A, 0x4A, 0x62, 0x7E, 0x08, 0xAB, 0x58
};


static BYTE public_key_2[32] = {     // *** LSB first
 0xDE, 0x9E, 0xDB, 0x7D, 0x7B, 0x7D, 0xC1, 0xB4, 0xD3, 0x5B, 0x61, 0xC2, 0xEC, 0xE4, 0x35, 0x37,
 0x3F, 0x83, 0x43, 0xC8, 0x5B, 0x78, 0x67, 0x4D, 0xAD, 0xFC, 0x7E, 0x14, 0x6F, 0x88, 0x2B, 0x4F
};

static BYTE public_key_2_xy[64] = {     // *** LSB first
 0xDE, 0x9E, 0xDB, 0x7D, 0x7B, 0x7D, 0xC1, 0xB4, 0xD3, 0x5B, 0x61, 0xC2, 0xEC, 0xE4, 0x35, 0x37,
 0x3F, 0x83, 0x43, 0xC8, 0x5B, 0x78, 0x67, 0x4D, 0xAD, 0xFC, 0x7E, 0x14, 0x6F, 0x88, 0x2B, 0x4F,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


static BYTE shared_secret[32] = {    // *** LSB first
 0x4A, 0x5D, 0x9D, 0x5B, 0xA4, 0xCE, 0x2D, 0xE1, 0x72, 0x8E, 0x3B, 0xF4, 0x80, 0x35, 0x0F, 0x25,
 0xE0, 0x7E, 0x21, 0xC9, 0x47, 0xD1, 0x9E, 0x33, 0x76, 0xF0, 0x9B, 0x3C, 0x1E, 0x16, 0x17, 0x42
};

VOID
testSymCryptMontgomeryPointScalarMul(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_INT      piScalar,
    _In_    PCSYMCRYPT_ECPOINT  poSrc,
    _In_    UINT32              flags,
    _In_    PSYMCRYPT_ECPOINT   poDst,
    _In_    PBYTE               pbResult,
    _In_    UINT32              cbResult,
    _In_    PBYTE               pbScratch,
    _In_    SIZE_T              cbScratch)
{
    SYMCRYPT_ERROR  scError = SYMCRYPT_NO_ERROR;
    BYTE pbX[64];

    scError = SymCryptEcpointScalarMul(
                  pCurve,
                  piScalar,
                  poSrc,
                  flags,
                  poDst,
                  pbScratch,
                  cbScratch);

    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptMontgomeryPointScalarMul failed.\n");

    scError = SymCryptEcpointGetValue(
                 pCurve,
                 poDst,
                 SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
                 SYMCRYPT_ECPOINT_FORMAT_XY,
                 pbX,
                 64,
                 g_rng.uint32() & SYMCRYPT_FLAG_DATA_PUBLIC,
                 pbScratch,
                 cbScratch);

    CHECK( memcmp(pbX, pbResult, cbResult) == 0, "Fail");

    vprint( g_verbose, "Success\n");
}

VOID
testMontgomery(PSYMCRYPT_ECURVE  pCurve)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    UINT32  msbCounter = NUM_OF_HIGH_BIT_RESTRICTION_ITERATIONS;
    UINT32  msbNumOfBits = 0;
    UINT32  msbValue = 0;
    UINT32  msbMask = 0;
    UINT32  msbActual = 0;

    vprint( g_verbose, "    ..................................................................................................\n");
    vprint( g_verbose, "    %-41s","Operation");
    vprint( g_verbose, " %-40s","Method");
    vprint( g_verbose, "Result\n");
    vprint( g_verbose, "    ..................................................................................................\n");

    SIZE_T cbScratch = SYMCRYPT_SCRATCH_BYTES_FOR_SCALAR_ECURVE_OPERATIONS(pCurve);

    PBYTE  pbScratch = (PBYTE)SymCryptCallbackAlloc(cbScratch);
    if (pbScratch == NULL)
    {
        vprint( g_verbose, " Memory allocation failed in Test.");
        return;
    }

    PSYMCRYPT_INT       piScalar = SymCryptIntAllocate(SymCryptEcurveDigitsofScalarMultiplier(pCurve));
    PSYMCRYPT_ECPOINT   poSrc = SymCryptEcpointAllocate(pCurve);
    PSYMCRYPT_ECPOINT   poDst = SymCryptEcpointAllocate(pCurve);
    PSYMCRYPT_ECPOINT   poDst2 = SymCryptEcpointAllocate(pCurve);
    PSYMCRYPT_ECKEY     pkKey1 = SymCryptEckeyAllocate(pCurve);

    vprint( g_verbose, "    %-41s", "G_x * private_key_1");
    vprint( g_verbose, " %-40s", "SymCryptEcpointScalarMul");
    SymCryptIntSetValue(private_key_1, 32, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piScalar);
    SymCryptEcpointSetDistinguishedPoint(pCurve, poSrc, pbScratch, cbScratch);

    testSymCryptMontgomeryPointScalarMul(
        pCurve,
        piScalar,
        poSrc,
        0,
        poDst,
        public_key_1,
        32,
        pbScratch,
        cbScratch);

    vprint( g_verbose, "    %-41s", "G_x * private_key_2");
    vprint( g_verbose, " %-40s", "SymCryptEcpointScalarMul");
    SymCryptIntSetValue(private_key_2, 32, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piScalar);
    testSymCryptMontgomeryPointScalarMul(
        pCurve,
        piScalar,
        NULL, // test that NULL source point is converted to G
        0,
        poDst,
        public_key_2,
        32,
        pbScratch,
        cbScratch);

    vprint( g_verbose, "    %-41s", "public_key_1 * private_key2");
    vprint( g_verbose, " %-40s", "SymCryptEcpointScalarMul");
    SymCryptIntSetValue(private_key_2, 32, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piScalar);
    SymCryptEcpointSetValue(
        pCurve,
        public_key_1_xy,
        64,
        SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        poSrc,
        g_rng.uint32() & SYMCRYPT_FLAG_DATA_PUBLIC,
        pbScratch,
        cbScratch);

    testSymCryptMontgomeryPointScalarMul(
        pCurve,
        piScalar,
        poSrc,
        0,
        poDst,
        shared_secret,
        32,
        pbScratch,
        cbScratch);

    vprint( g_verbose, "    %-41s", "public_key_2 * private_key1");
    vprint( g_verbose, " %-40s", "SymCryptEcpointScalarMul");
    SymCryptIntSetValue(private_key_1, 32, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piScalar);
    SymCryptEcpointSetValue(pCurve,
        public_key_2_xy,
        64,
        SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        poSrc,
        g_rng.uint32() & SYMCRYPT_FLAG_DATA_PUBLIC,
        pbScratch,
        cbScratch);

    testSymCryptMontgomeryPointScalarMul(
        pCurve,
        piScalar,
        poSrc,
        0,
        poDst2,
        shared_secret,
        32,
        pbScratch,
        cbScratch);

    vprint( g_verbose, "    %-41s", "public_key_1 * private_key2 == public_key_2 * private_key1");
    vprint( g_verbose, " %-40s", "SymCryptEcpointIsEqual");

    CHECK( SymCryptEcpointIsEqual(pCurve, poDst, poDst, 0, pbScratch, cbScratch ), "poDst != poDst" );
    CHECK( SymCryptEcpointIsEqual(pCurve, poDst, poDst2, 0, pbScratch, cbScratch ), "poDst != poDst2");
    CHECK( !SymCryptEcpointIsEqual(pCurve, poSrc, poDst, 0, pbScratch, cbScratch ), "poSrc == poDst");

    // =================================
    // Check that the high bit restriction is obeyed
    vprint( g_verbose, "    %-41s", "Set K1 to a uniformly random eckey" );
    vprint( g_verbose, " %-40s", "SymCryptEckeySetRandom");

    // Retrieve the high bit restriction values
    msbNumOfBits = SymCryptEcurveHighBitRestrictionNumOfBits( pCurve );
    CHECK( msbNumOfBits < 33, "Invalid high bit restriction num of bits");

    if ( msbNumOfBits != 0 )
    {
        msbMask = ((UINT32)(-1)) << (32-msbNumOfBits);
        msbValue = SymCryptEcurveHighBitRestrictionValue( pCurve ) << (32-msbNumOfBits);
    }

    do
    {
        scError = SymCryptEckeySetRandom( SYMCRYPT_FLAG_ECKEY_ECDH, pkKey1 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Set random key failed" );

        scError = SymCryptEcpointScalarMul( pCurve, pkKey1->piPrivateKey, NULL, 0, poSrc, pbScratch, cbScratch );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Scalar Multiplying private key failed" );

        scError = SymCryptEckeyGetValue(
                            pkKey1,
                            pbScratch,
                            SymCryptEckeySizeofPrivateKey( pkKey1 ),
                            NULL,
                            0,
                            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                            SYMCRYPT_ECPOINT_FORMAT_XY,
                            0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptEckeyGetValue private key failed" );

        // Check that the high bits are correct
        msbActual = (((UINT32)pbScratch[0]) << 24) | ((UINT32) pbScratch[1] << 16) | ((UINT32) pbScratch[2] << 8) | ((UINT32) pbScratch[3]);

        CHECK5( (msbActual & msbMask) == msbValue,
        "High bit restriction failed. \n  Recvd: 0x%04X\n  Mask : 0x%04X\n  Bits : 0x%04X", msbActual, msbMask, msbValue);

        msbCounter--;
    } while ((msbCounter > 0) && (msbNumOfBits>0));

    vprint( g_verbose, "Success\n");
    // =================================

    vprint( g_verbose, "    %-41s", "Wiping and freeing stuff ");
    vprint( g_verbose, " %-40s", "SymCryptWipe");
    SymCryptIntFree(piScalar);
    SymCryptEcpointFree(pCurve, poSrc);
    SymCryptEcpointFree(pCurve, poDst);
    SymCryptEcpointFree(pCurve, poDst2);
    SymCryptEckeyFree(pkKey1);

    SymCryptWipe(pbScratch, cbScratch);
    SymCryptCallbackFree(pbScratch);
    vprint( g_verbose, "Success\n");
}