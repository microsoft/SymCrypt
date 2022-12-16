//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

VOID
testEccEcdsaKats();

////////////////////////////////////////////////////////////////////
//
//  SymCrypt Internal Curves
//
////////////////////////////////////////////////////////////////////

#define SYMCRYPT_ECC_CURVE_25519              "curve25519"

#define SYMCRYPT_ECC_CURVE_NISTP192           "nistP192"
#define SYMCRYPT_ECC_CURVE_NISTP224           "nistP224"
#define SYMCRYPT_ECC_CURVE_NISTP256           "nistP256"
#define SYMCRYPT_ECC_CURVE_NISTP384           "nistP384"
#define SYMCRYPT_ECC_CURVE_NISTP521           "nistP521"

#define SYMCRYPT_ECC_CURVE_NUMSP256T1         "numsP256t1"
#define SYMCRYPT_ECC_CURVE_NUMSP384T1         "numsP384t1"
#define SYMCRYPT_ECC_CURVE_NUMSP512T1         "numsP512t1"

typedef struct _SYMCRYPT_ECC_CURVES {
    LPSTR                       pszCurveName;
    PCSYMCRYPT_ECURVE_PARAMS    pParams;
    PSYMCRYPT_ECURVE            pCurve;
} SYMCRYPT_ECC_CURVES;

SYMCRYPT_ECC_CURVES rgbInternalCurves[] = {
    //pszCurveName                     //pParams
    { SYMCRYPT_ECC_CURVE_NISTP192,     SymCryptEcurveParamsNistP192,    NULL},
    { SYMCRYPT_ECC_CURVE_NISTP224,     SymCryptEcurveParamsNistP224,    NULL},
    { SYMCRYPT_ECC_CURVE_NISTP256,     SymCryptEcurveParamsNistP256,    NULL},
    { SYMCRYPT_ECC_CURVE_NISTP384,     SymCryptEcurveParamsNistP384,    NULL},
    { SYMCRYPT_ECC_CURVE_NISTP521,     SymCryptEcurveParamsNistP521,    NULL},
    { SYMCRYPT_ECC_CURVE_NUMSP256T1,   SymCryptEcurveParamsNumsP256t1,  NULL},
    { SYMCRYPT_ECC_CURVE_NUMSP384T1,   SymCryptEcurveParamsNumsP384t1,  NULL},
    { SYMCRYPT_ECC_CURVE_NUMSP512T1,   SymCryptEcurveParamsNumsP512t1,  NULL},
    { SYMCRYPT_ECC_CURVE_25519,        SymCryptEcurveParamsCurve25519,  NULL},
};

#define NUM_OF_INTERNAL_CURVES       (sizeof(rgbInternalCurves) / sizeof(rgbInternalCurves[0]))

////////////////////////////////////////////////////////////////////
//
//  SymCrypt Hash Algorithms for ECDSA Tests
//
////////////////////////////////////////////////////////////////////

#define SYMCRYPT_ECC_SHA1                     "SHA1"
#define SYMCRYPT_ECC_SHA224                   "SHA224"
#define SYMCRYPT_ECC_SHA256                   "SHA256"
#define SYMCRYPT_ECC_SHA384                   "SHA384"
#define SYMCRYPT_ECC_SHA512                   "SHA512"

BOOL getHashAlgorithm(LPCSTR pszHashName, ULONGLONG line, PCSYMCRYPT_HASH* ppHash)
{
    if( strcmp( pszHashName, SYMCRYPT_ECC_SHA1 ) == 0 )
    {
        *ppHash = ScDispatchSymCryptSha1Algorithm;
    }
    else if( strcmp( pszHashName, SYMCRYPT_ECC_SHA224 ) == 0 )
    {
        dprint( "Ecdsa record at line %lld is skipped due to unsupported hash function (%s).\n", line, pszHashName );
        return FALSE;
    }
    else if( strcmp( pszHashName, SYMCRYPT_ECC_SHA256 ) == 0 )
    {
        *ppHash = ScDispatchSymCryptSha256Algorithm;
    }
    else if( strcmp( pszHashName, SYMCRYPT_ECC_SHA384 ) == 0 )
    {
        *ppHash = ScDispatchSymCryptSha384Algorithm;
    }
    else if( strcmp( pszHashName, SYMCRYPT_ECC_SHA512 ) == 0 )
    {
        *ppHash = ScDispatchSymCryptSha512Algorithm;
    }
    else
    {
        dprint( "Assuming no hash function at line %lld for unknown hash function (%s).\n", line, pszHashName );
        *ppHash = NULL;
    }

    return TRUE;
}

////////////////////////////////////////////////////////////////////
//
//  Secret Key Format Names
//
////////////////////////////////////////////////////////////////////

LPSTR rgbPrivateKeyFormatNames[] = {
    "Null",
    "Canonical",
    "DivH",
    "DivHTimesH",
    "TimesH",
};

////////////////////////////////////////////////////////////////////

VOID
testEccArithmetic( _In_ PCSYMCRYPT_ECURVE pCurve )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    // Group Order
    PCSYMCRYPT_MODULUS pmGOrd = SymCryptEcurveGroupOrder(pCurve);

    // Temporary SymCrypt objects
    PSYMCRYPT_ECPOINT   poP1 = NULL;
    PSYMCRYPT_ECPOINT   poP2 = NULL;
    PSYMCRYPT_ECPOINT   poP3 = NULL;
    PSYMCRYPT_INT       piSc1 = NULL;
    PSYMCRYPT_INT       piSc2 = NULL;
    PSYMCRYPT_INT       piLarge = NULL;     // Larger integer to hold the sum of both INTs

    UINT32 carry = 0;

#define MULTIMUL_POINTS     (2)
    PCSYMCRYPT_ECPOINT  poTable[MULTIMUL_POINTS] = { 0 };
    PCSYMCRYPT_INT      piTable[MULTIMUL_POINTS] = { 0 };

    PSYMCRYPT_ECKEY     pkKey1 = NULL;

    // Temporary Object sizes
    SIZE_T  cbEcpointSize = 0;
    SIZE_T  cbIntScalarSize = 0;
    SIZE_T  cbIntLargeSize = 0;
    SIZE_T  cbEckeySize = 0;

    // EcDsa buffers
    BYTE                pbHashValue[2*SYMCRYPT_SHA512_RESULT_SIZE] = { 0 };
    BYTE                pbMessage[] = { 'h', 'e', 'l', 'l', 'o' };

    // Pointers to memory sections
    //  Scratch:        Scratch space for all
    //  ScratchMul:     Scratch space for multiplication ops
    //  ScratchMultiMul:Scratch space for the multi multiplication operation
    //  ScratchGetSet:  Scratch space for get/set value ecpoint operations
    //  Signature:      Space for the signature (and the get/set value operations)
    //  Buffer:         Space for the get/set value operations (and or printing points)
    //  WorkSpace:      Entire allocated memory
    PBYTE   pbScratch = NULL;
    SIZE_T  cbScratch = 0;
    PBYTE   pbScratchMul = NULL;
    SIZE_T  cbScratchMul = 0;
    PBYTE   pbScratchMultiMul = NULL;
    SIZE_T  cbScratchMultiMul = 0;
    PBYTE   pbScratchGetSet = NULL;
    SIZE_T  cbScratchGetSet = 0;
    PBYTE   pbSignature = NULL;
    SIZE_T  cbSignature = 0;
    PBYTE   pbBuffer = NULL;
    SIZE_T  cbBuffer = 0;
    PBYTE   pbWorkSpace = NULL;
    SIZE_T  cbWorkSpace = 0;

    PBYTE   pCurr;

    UINT32  msbCounter = NUM_OF_HIGH_BIT_RESTRICTION_ITERATIONS;
    UINT32  msbNumOfBits = 0;
    UINT32  msbValue = 0;
    UINT32  msbMask = 0;
    UINT32  msbActual = 0;

    // =================================
    // Size calculations
    cbEcpointSize = SymCryptSizeofEcpointFromCurve( pCurve );
    cbIntScalarSize = SymCryptSizeofIntFromDigits( SymCryptEcurveDigitsofScalarMultiplier(pCurve) );
    cbIntLargeSize = SymCryptSizeofIntFromDigits( SymCryptEcurveDigitsofScalarMultiplier(pCurve) + 1 );
    cbEckeySize = SymCryptSizeofEckeyFromCurve( pCurve );

    cbScratch = SYMCRYPT_MAX( SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_ECURVE_OPERATIONS( pCurve ),
                SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD( SymCryptEcurveDigitsofScalarMultiplier(pCurve) + 1, pCurve->GOrdDigits ) );
    cbScratchMul = SYMCRYPT_SCRATCH_BYTES_FOR_SCALAR_ECURVE_OPERATIONS( pCurve );
    cbScratchMultiMul = SYMCRYPT_SCRATCH_BYTES_FOR_MULTI_SCALAR_ECURVE_OPERATIONS( pCurve, MULTIMUL_POINTS );
    cbScratchGetSet = SYMCRYPT_SCRATCH_BYTES_FOR_GETSET_VALUE_ECURVE_OPERATIONS( pCurve );
    cbSignature = 2 * SymCryptEcurveSizeofFieldElement( pCurve );
    cbBuffer = cbSignature; // This is due to the fact that ecdsa and XY format both use 2 field elements

    cbWorkSpace = 3 * cbEcpointSize + 2 * cbIntScalarSize + cbIntLargeSize + cbEckeySize + cbScratch + cbScratchMul + cbScratchMultiMul + cbScratchGetSet + cbSignature + cbBuffer;

    // =================================
    // Allocation

    pbWorkSpace = (PBYTE) SymCryptCallbackAlloc( cbWorkSpace );
    CHECK( pbWorkSpace != NULL, "Memory allocation failed" );

    // =================================
    // Object creation

    pCurr = pbWorkSpace;

    poP1 = SymCryptEcpointCreate( pCurr, cbEcpointSize, pCurve );
    CHECK( poP1 != NULL, "P1 creation failed" );
    pCurr += cbEcpointSize;

    poP2 = SymCryptEcpointCreate( pCurr, cbEcpointSize, pCurve );
    CHECK( poP2 != NULL, "P2 creation failed" );
    pCurr += cbEcpointSize;

    poP3 = SymCryptEcpointCreate( pCurr, cbEcpointSize, pCurve );
    CHECK( poP3 != NULL, "P3 creation failed" );
    pCurr += cbEcpointSize;

    piSc1 = SymCryptIntCreate( pCurr, cbIntScalarSize, SymCryptEcurveDigitsofScalarMultiplier(pCurve) );
    CHECK( piSc1 != NULL, "S1 allocation failed" );
    pCurr += cbIntScalarSize;

    piSc2 = SymCryptIntCreate( pCurr, cbIntScalarSize, SymCryptEcurveDigitsofScalarMultiplier(pCurve) );
    CHECK( piSc2 != NULL, "S2 allocation failed" );
    pCurr += cbIntScalarSize;

    piLarge = SymCryptIntCreate( pCurr, cbIntLargeSize, SymCryptEcurveDigitsofScalarMultiplier(pCurve) + 1 );
    CHECK( piLarge != NULL, "S2 allocation failed" );
    pCurr += cbIntLargeSize;

    pkKey1 = SymCryptEckeyCreate( pCurr, cbEckeySize, pCurve );
    CHECK( pkKey1 != NULL, "Eckey allocation failed" );
    pCurr += cbEckeySize;

    pbScratch = pCurr;
    pbScratchMul = pbScratch + cbScratch;
    pbScratchMultiMul = pbScratchMul + cbScratchMul;
    pbScratchGetSet = pbScratchMultiMul + cbScratchMultiMul;
    pbSignature = pbScratchGetSet + cbScratchGetSet;
    pbBuffer = pbSignature + cbSignature;

    poTable[0] = poP1;
    poTable[1] = poP2;

    piTable[0] = piSc1;
    piTable[1] = piSc2;

    // =================================
    // Test start

    vprint( g_verbose, "    ..................................................................................................\n");
    vprint( g_verbose, "    %-41s","Operation");
    vprint( g_verbose, " %-40s","Method");
    vprint( g_verbose, "Result\n");
    vprint( g_verbose, "    ..................................................................................................\n");

    // =================================
    vprint( g_verbose, "    %-41s", "Setting P1 to zero point");
    vprint( g_verbose, " %-40s", "SymCryptEcpointSetZero");
    SymCryptEcpointSetZero( pCurve, poP1, pbScratch, cbScratch );

    CHECK( SymCryptEcpointOnCurve( pCurve, poP1, pbScratch, cbScratch ), "Zero point is not on curve!");
    CHECK( SymCryptEcpointIsZero( pCurve, poP1, pbScratch, cbScratch ), "Zero point is not zero!");

    vprint( g_verbose, "Success\n");

    // =================================
    vprint( g_verbose, "    %-41s", "Setting P1 to distinguished point G");
    vprint( g_verbose, " %-40s", "SymCryptEcpointSetDistinguishedPoint");
    SymCryptEcpointSetDistinguishedPoint( pCurve, poP1, pbScratch, cbScratch );

    CHECK( SymCryptEcpointOnCurve( pCurve, poP1, pbScratch, cbScratch ), "Distinguished point is not on curve!");
    CHECK( !SymCryptEcpointIsZero( pCurve, poP1, pbScratch, cbScratch ), "Distinguished point is zero!");

    vprint( g_verbose, "Success\n");

    // =================================
    vprint( g_verbose, "    %-41s", "P2 := 2 * P1  = 2*G");
    vprint( g_verbose, " %-40s", "SymCryptEcpointDouble");
    SymCryptEcpointDouble( pCurve, poP1, poP2, 0, pbScratch, cbScratch );

    CHECK( SymCryptEcpointOnCurve( pCurve, poP2, pbScratch, cbScratch ), "Doubled point not on curve!");
    vprint( g_verbose, "Success\n");

    // =================================
    vprint( g_verbose, "    %-41s", "P2 := P1 + P2 = 3*G");
    vprint( g_verbose, " %-40s", "SymCryptEcpointAddDiffNonZero");
    SymCryptEcpointAddDiffNonZero( pCurve, poP1, poP2, poP2, pbScratch, cbScratch );

    CHECK( SymCryptEcpointOnCurve( pCurve, poP2, pbScratch, cbScratch ), "Tripled point not on curve!");
    vprint( g_verbose, "Success\n");

    // =================================
    vprint( g_verbose, "    %-41s", "P3 := 3 * P1  = 3*G" );
    vprint( g_verbose, " %-40s", "SymCryptEcpointScalarMul");
    SymCryptIntSetValueUint32( 3, piSc1 );
    scError = SymCryptEcpointScalarMul( pCurve, piSc1, poP1, 0, poP3, pbScratchMul, cbScratchMul );

    CHECK( scError == SYMCRYPT_NO_ERROR, "Scalar Multiplying P1 failed" );
    CHECK( SymCryptEcpointOnCurve( pCurve, poP3, pbScratch, cbScratch ), "Multiplied point not on curve!");
    vprint( g_verbose, "Success\n");

    vprint( g_verbose, "    %-41s", "Checking P2 == P3 ?" );
    vprint( g_verbose, " %-40s", "SymCryptEcpointIsEqual");
    CHECK( SymCryptEcpointIsEqual( pCurve, poP2, poP3, 0, pbScratch, cbScratch ), " P2 != P3 " );
    vprint( g_verbose, "Success\n");

    // =================================
    vprint( g_verbose, "    %-41s", "P3 := 5 * P1  = 5*G" );
    vprint( g_verbose, " %-40s", "SymCryptEcpointScalarMul");
    SymCryptIntSetValueUint32( 5, piSc2 );
    scError = SymCryptEcpointScalarMul( pCurve, piSc2, poP1, 0, poP3, pbScratchMul, cbScratchMul );

    CHECK( scError == SYMCRYPT_NO_ERROR, "Scalar Multiplying P1 failed" );
    CHECK( SymCryptEcpointOnCurve( pCurve, poP3, pbScratch, cbScratch ), "Multiplied point not on curve!");
    vprint( g_verbose, "Success\n");

    // =================================
    vprint( g_verbose, "    %-41s", "P2 := P2 + P3 = 8*G" );
    vprint( g_verbose, " %-40s", "SymCryptEcpointAdd");
    SymCryptEcpointAdd( pCurve, poP2, poP3, poP2, 0, pbScratch, cbScratch );

    CHECK( SymCryptEcpointOnCurve( pCurve, poP2, pbScratch, cbScratch ), "P2 not on curve!");
    vprint( g_verbose, "Success\n");

    // =================================
    vprint( g_verbose, "    %-41s", "P3 := 8 * P1  = 8*G" );
    vprint( g_verbose, " %-40s", "SymCryptEcpointScalarMul");
    SymCryptIntSetValueUint32( 8, piSc1 );
    scError = SymCryptEcpointScalarMul( pCurve, piSc1, poP1, 0, poP3, pbScratchMul, cbScratchMul );

    CHECK( scError == SYMCRYPT_NO_ERROR, "Scalar Multiplying P1 failed" );
    CHECK( SymCryptEcpointOnCurve( pCurve, poP3, pbScratch, cbScratch ), "Multiplied point not on curve!");
    vprint( g_verbose, "Success\n");

    vprint( g_verbose, "    %-41s", "Checking P2 == P3 ?" );
    vprint( g_verbose, " %-40s", "SymCryptEcpointIsEqual");
    CHECK( SymCryptEcpointIsEqual( pCurve, poP2, poP3, 0, pbScratch, cbScratch ), " P2 != P3 " );
    vprint( g_verbose, "Success\n");

    // =================================
    vprint( g_verbose, "    %-41s", "P3 := 8 * P1 + 0 * P2" );
    vprint( g_verbose, " %-40s", "SymCryptEcpointMultiScalarMul");
    SymCryptIntSetValueUint32( 8, piSc1 );
    SymCryptIntSetValueUint32( 0, piSc2 );
    scError = SymCryptEcpointMultiScalarMul( pCurve, piTable, poTable, MULTIMUL_POINTS, SYMCRYPT_FLAG_DATA_PUBLIC, poP3, pbScratchMultiMul, cbScratchMultiMul );

    CHECK( scError == SYMCRYPT_NO_ERROR, "Multi Scalar Multiplying failed" );
    CHECK( SymCryptEcpointOnCurve( pCurve, poP3, pbScratch, cbScratch ), "Multiplied point not on curve!");
    vprint( g_verbose, "Success\n");

    vprint( g_verbose, "    %-41s", "Checking P2 == P3 ?" );
    vprint( g_verbose, " %-40s", "SymCryptEcpointIsEqual");
    CHECK( SymCryptEcpointIsEqual( pCurve, poP2, poP3, 0, pbScratch, cbScratch ), " P2 != P3 " );
    vprint( g_verbose, "Success\n");

    vprint( g_verbose, "    %-41s", "P3 := 6 * P1 + 17 * P2" );
    vprint( g_verbose, " %-40s", "SymCryptEcpointMultiScalarMul");
    SymCryptIntSetValueUint32( 6, piSc1 );
    SymCryptIntSetValueUint32( 17, piSc2 );
    scError = SymCryptEcpointMultiScalarMul( pCurve, piTable, poTable, MULTIMUL_POINTS, SYMCRYPT_FLAG_DATA_PUBLIC, poP3, pbScratchMultiMul, cbScratchMultiMul );

    CHECK( scError == SYMCRYPT_NO_ERROR, "Multi Scalar Multiplying failed" );
    CHECK( SymCryptEcpointOnCurve( pCurve, poP3, pbScratch, cbScratch ), "Multiplied point not on curve!");
    vprint( g_verbose, "Success\n");

    SymCryptIntSetValueUint32( 142, piSc1 );
    scError = SymCryptEcpointScalarMul( pCurve, piSc1, poP1, 0, poP2, pbScratchMul, cbScratchMul );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Scalar Multiplying P1 failed" );
    CHECK( SymCryptEcpointOnCurve( pCurve, poP2, pbScratch, cbScratch ), "Multiplied point not on curve!");

    vprint( g_verbose, "    %-41s", "Checking P3 == 142 * G ?" );
    vprint( g_verbose, " %-40s", "SymCryptEcpointIsEqual");
    CHECK( SymCryptEcpointIsEqual( pCurve, poP2, poP3, 0, pbScratch, cbScratch ), " P2 != P3 " );
    vprint( g_verbose, "Success\n");

    // =================================
    vprint( g_verbose, "    %-41s", "P2 := rand1 * G" );
    vprint( g_verbose, " %-40s", "SymCryptEcpointSetRandom");
    SymCryptEcpointSetRandom( pCurve, piSc1, poP2, pbScratchMul, cbScratchMul );
    CHECK( SymCryptEcpointOnCurve( pCurve, poP2, pbScratch, cbScratch ), "Random not on curve!");
    vprint( g_verbose, "Success\n");

    // =================================
    vprint( g_verbose, "    %-41s", "P3 := rand2 * G" );
    vprint( g_verbose, " %-40s", "SymCryptEcpointSetRandom");
    SymCryptEcpointSetRandom( pCurve, piSc2, poP3, pbScratchMul, cbScratchMul );
    CHECK( SymCryptEcpointOnCurve( pCurve, poP3, pbScratch, cbScratch ), "Random not on curve!");
    vprint( g_verbose, "Success\n");

    // =================================
    vprint( g_verbose, "    %-41s", "P2 := P2 + P3 = rand1*G + rand2*G");
    vprint( g_verbose, " %-40s", "SymCryptEcpointAdd");
    SymCryptEcpointAdd( pCurve, poP2, poP3, poP2, 0, pbScratch, cbScratch );

    CHECK( SymCryptEcpointOnCurve( pCurve, poP2, pbScratch, cbScratch ), "Random not on curve!");
    vprint( g_verbose, "Success\n");

    // =================================
    vprint( g_verbose, "    %-41s", "P3 := (rand1 + rand2) * P1" );
    vprint( g_verbose, " %-40s", "SymCryptEcpointScalarMul");

    carry = SymCryptIntAddMixedSize( piSc1, piSc2, piLarge );
    CHECK( carry == 0, "Adding the two scalars cannot fit the larger integer");

    SymCryptIntDivMod( piLarge, SymCryptDivisorFromModulus((PSYMCRYPT_MODULUS)pmGOrd), NULL, piSc2, pbScratch, cbScratch );
    scError = SymCryptEcpointScalarMul( pCurve, piSc2, poP1, 0, poP3, pbScratchMul, cbScratchMul );

    CHECK( scError == SYMCRYPT_NO_ERROR, "Scalar Multiplying P1 failed" );
    CHECK( SymCryptEcpointOnCurve( pCurve, poP3, pbScratch, cbScratch ), "Multiplied point not on curve!");
    vprint( g_verbose, "Success\n");

    vprint( g_verbose, "    %-41s", "Checking P2 == P3 ?" );
    vprint( g_verbose, " %-40s", "SymCryptEcpointIsEqual");
    CHECK( SymCryptEcpointIsEqual( pCurve, poP2, poP3, 0, pbScratch, cbScratch ), " P2 != P3 " );
    vprint( g_verbose, "Success\n");
    // =================================
    vprint( g_verbose, "    %-41s", "P3 := (GOrd-1) * P2" );
    vprint( g_verbose, " %-40s", "SymCryptEcpointScalarMul");

    SymCryptIntCopy( SymCryptIntFromModulus((PSYMCRYPT_MODULUS)pmGOrd), piSc1 );
    SymCryptIntSubUint32( piSc1, 1, piSc1 );

    scError = SymCryptEcpointScalarMul( pCurve, piSc1, poP2, 0, poP3, pbScratchMul, cbScratchMul );

    CHECK( scError == SYMCRYPT_NO_ERROR, "Scalar Multiplying P2 failed" );
    CHECK( SymCryptEcpointOnCurve( pCurve, poP3, pbScratch, cbScratch ), "Multiplied point not on curve!");
    vprint( g_verbose, "Success\n");

    vprint( g_verbose, "    %-41s", "Checking P2 == - P3 ?" );
    vprint( g_verbose, " %-40s", "SymCryptEcpointIsEqual");
    CHECK( SymCryptEcpointIsEqual( pCurve, poP2, poP3, SYMCRYPT_FLAG_ECPOINT_NEG_EQUAL, pbScratch, cbScratch ), " P2 != -P3 " );
    vprint( g_verbose, "Success\n");

    // =================================
    vprint( g_verbose, "    %-41s", "Get / Set value" );
    vprint( g_verbose, " %-40s", "Ecpoint Get/Set Value");

    scError = SymCryptEcpointGetValue(pCurve, poP2, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, SYMCRYPT_ECPOINT_FORMAT_XY, pbSignature, cbSignature, g_rng.uint32() & SYMCRYPT_FLAG_DATA_PUBLIC, pbScratchGetSet, cbScratchGetSet);
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptEcpointGetValue failed" );

    scError = SymCryptEcpointSetValue(pCurve, pbSignature, cbSignature, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, SYMCRYPT_ECPOINT_FORMAT_XY, poP3, g_rng.uint32() & SYMCRYPT_FLAG_DATA_PUBLIC, pbScratchGetSet, cbScratchGetSet);

    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptEcpointSetValue failed" );
    CHECK( SymCryptEcpointIsEqual( pCurve, poP2, poP3, SYMCRYPT_FLAG_ECPOINT_EQUAL, pbScratch, cbScratch ), " P2 != P3 " );

    SymCryptEcpointSetRandom( pCurve, piSc2, poP2, pbScratchMul, cbScratchMul );
    CHECK( SymCryptEcpointOnCurve( pCurve, poP2, pbScratch, cbScratch ), "Random point not on curve!");

    SymCryptEcpointAdd( pCurve, poP2, poP3, poP3, 0, pbScratch, cbScratch );
    CHECK( SymCryptEcpointOnCurve( pCurve, poP3, pbScratch, cbScratch ), "P2 + P3 not on curve!");

    scError = SymCryptEcpointScalarMul( pCurve, piSc1, poP2, 0, poP2, pbScratchMul, cbScratchMul );  // Multiply by -1
    CHECK( scError == SYMCRYPT_NO_ERROR, "Scalar Multiplying P2 failed" );

    SymCryptEcpointAdd( pCurve, poP2, poP3, poP3, 0, pbScratch, cbScratch );
    CHECK( SymCryptEcpointOnCurve( pCurve, poP3, pbScratch, cbScratch ), "P2 + P3 not on curve!");

    scError = SymCryptEcpointGetValue(pCurve, poP3, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, SYMCRYPT_ECPOINT_FORMAT_XY, pbBuffer, cbBuffer, g_rng.uint32() & SYMCRYPT_FLAG_DATA_PUBLIC, pbScratchGetSet, cbScratchGetSet);
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptEcpointGetValue failed" );

    CHECK( cbSignature == cbBuffer, "Wrong signature sizes");
    CHECK( memcmp( pbSignature, pbBuffer, cbSignature ) == 0, "Mismatch on get / set value ops");

    vprint( g_verbose, "Success\n");

    // =================================
    vprint( g_verbose, "    %-41s", "P3 :=  0 * P1" );
    vprint( g_verbose, " %-40s", "SymCryptEcpointScalarMul");
    SymCryptIntSetValueUint32( 0, piSc1 );
    scError = SymCryptEcpointScalarMul( pCurve, piSc1, poP1, 0, poP3, pbScratchMul, cbScratchMul );

    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptEcpointScalarMul failed" );
    CHECK( SymCryptEcpointIsZero( pCurve, poP3, pbScratch, cbScratch ), "Result is not zero!");
    vprint( g_verbose, "Success\n");

    vprint( g_verbose, "    %-41s", "P3 := 35 *  O" );
    vprint( g_verbose, " %-40s", "SymCryptEcpointScalarMul");
    SymCryptIntSetValueUint32( 35, piSc1 );
    SymCryptEcpointSetZero( pCurve, poP1, pbScratch, cbScratch );
    scError = SymCryptEcpointScalarMul( pCurve, piSc1, poP1, 0, poP3, pbScratchMul, cbScratchMul );

    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptEcpointScalarMul failed" );
    CHECK( SymCryptEcpointIsZero( pCurve, poP3, pbScratch, cbScratch ), "Result is not zero!");
    vprint( g_verbose, "Success\n");

    // =================================
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
        scError = SymCryptEckeySetRandom( SYMCRYPT_FLAG_ECKEY_ECDSA | SYMCRYPT_FLAG_ECKEY_ECDH, pkKey1 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Set random key failed" );

        CHECK( SymCryptEcpointOnCurve( pCurve, pkKey1->poPublicKey, pbScratch, cbScratch), "Public key not on curve");
        scError = SymCryptEcpointScalarMul( pCurve, pkKey1->piPrivateKey, NULL, SYMCRYPT_FLAG_ECC_LL_COFACTOR_MUL, poP3, pbScratchMul, cbScratchMul );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Scalar Multiplying private key failed" );
        CHECK( SymCryptEcpointIsEqual( pCurve, pkKey1->poPublicKey, poP3, 0, pbScratch, cbScratch ), " P2 != P3 " );

        scError = SymCryptEckeyGetValue(
                            pkKey1,
                            pbSignature,
                            SymCryptEckeySizeofPrivateKey( pkKey1 ),
                            NULL,
                            0,
                            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                            SYMCRYPT_ECPOINT_FORMAT_XY,
                            0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptEckeyGetValue private key failed" );

        // Check that the high bits are correct
        msbActual = (((UINT32)pbSignature[0]) << 24) | ((UINT32) pbSignature[1] << 16) | ((UINT32) pbSignature[2] << 8) | ((UINT32) pbSignature[3]);

        CHECK5( (msbActual & msbMask) == msbValue,
        "High bit restriction failed. \n  Recvd: 0x%04X\n  Mask : 0x%04X\n  Bits : 0x%04X", msbActual, msbMask, msbValue);

        msbCounter--;
    } while ((msbCounter > 0) && (msbNumOfBits>0));

    vprint( g_verbose, "Success\n");

    // =================================
    vprint( g_verbose, "    %-41s", "Sign a message with ECDSA" );
    vprint( g_verbose, " %-40s", "SymCryptEcDsaSign");

    SymCryptSha512( pbMessage, sizeof( pbMessage ), pbHashValue );
    memcpy( pbHashValue + SYMCRYPT_SHA512_RESULT_SIZE, pbHashValue, SYMCRYPT_SHA512_RESULT_SIZE );    // Make it bigger than 512 so that the two truncation methods give different result

    scError = SymCryptEcDsaSign(
                    pkKey1,
                    pbHashValue,
                    sizeof(pbHashValue),
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0,
                    pbSignature,
                    cbSignature );

    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptEcDsaSign failed" );
    vprint( g_verbose, "Success\n");

    // =================================
    vprint( g_verbose, "    %-41s", "Verify the signature" );
    vprint( g_verbose, " %-40s", "SymCryptEcDsaVerify");
    scError = SymCryptEcDsaVerify(
                    pkKey1,
                    pbHashValue,
                    sizeof(pbHashValue),
                    pbSignature,
                    cbSignature,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0 );

    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptEcDsaVerify failed" );
    vprint( g_verbose, "Success\n");

    // =================================
    vprint( g_verbose, "    %-41s", "Sign a message with old CNG ECDSA" );
    vprint( g_verbose, " %-40s", "SymCryptEcDsaSign");

    scError = SymCryptEcDsaSign(
                    pkKey1,
                    pbHashValue,
                    sizeof(pbHashValue),
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    SYMCRYPT_FLAG_ECDSA_NO_TRUNCATION,
                    pbSignature,
                    cbSignature );

    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptEcDsaSign failed" );
    vprint( g_verbose, "Success\n");

    // =================================
    vprint( g_verbose, "    %-41s", "Verify the signature" );
    vprint( g_verbose, " %-40s", "SymCryptEcDsaVerify");

    scError = SymCryptEcDsaVerify(
                    pkKey1,
                    pbHashValue,
                    sizeof(pbHashValue),
                    pbSignature,
                    cbSignature,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    SYMCRYPT_FLAG_ECDSA_NO_TRUNCATION );

    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptEcDsaVerify failed" );

    vprint( g_verbose, "Success\n");

    // =================================
    vprint( g_verbose, "    %-41s", "ECDH Algorithm" );
    vprint( g_verbose, " %-40s", "SymCryptEcDhSecretAgreement");
    scError = SymCryptEcDhSecretAgreement(
                    pkKey1,
                    pkKey1,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0,
                    pbSignature,
                    cbSignature/2 );

    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptEcDhSecretAgreement failed" );
    vprint( g_verbose, "Success\n");

    SymCryptEcpointSetZero(pCurve, pkKey1->poPublicKey, pbScratchMul, cbScratchMul);

    vprint( g_verbose, "    %-41s", "Verify signature with 0 public key" );
    vprint( g_verbose, " %-40s", "SymCryptEcDsaVerify");
    scError = SymCryptEcDsaVerify(
                    pkKey1,
                    pbHashValue,
                    sizeof(pbHashValue),
                    pbSignature,
                    cbSignature,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0 );

    CHECK( scError != SYMCRYPT_NO_ERROR, "SymCryptEcDsaVerify should have failed but succeeded" );
    vprint( g_verbose, "Success\n");

    // =================================
    vprint( g_verbose, "    %-41s", "Wiping and freeing stuff ");
    vprint( g_verbose, " %-40s", "SymCryptWipe");
    SymCryptWipe( pbWorkSpace, cbWorkSpace );
    SymCryptCallbackFree( pbWorkSpace );

    vprint( g_verbose, "Success\n");
}

BOOL
testCurveParamsValid( PSYMCRYPT_ECURVE_PARAMS pParams, SIZE_T cbData )
{
    // We test whether the parameters are valid by trying them with random data
    // several times.
    // Exception: we set the cofactor to 1 so that it is a power of 2

    BOOL res = FALSE;

    for( int i=0; i<1000; i++ )
    {
        // Add random data + set cofactor to 1
        GENRANDOM( (PBYTE)(pParams + 1), (UINT32)cbData - sizeof( *pParams ) );
        ((PBYTE)(pParams + 1))[5 * pParams->cbFieldLength + pParams->cbSubgroupOrder] = 1;

        PSYMCRYPT_ECURVE eCurve = SymCryptEcurveAllocate( pParams, 0 );
        if( eCurve != NULL )
        {
            SymCryptEcurveFree( eCurve );
            res = TRUE;
            break;
        }
    }
    return res;
}


VOID
testBadCurveParams()
{
    const SIZE_T cbBuf = 1 << 20;
    PVOID pBuf = malloc( cbBuf );

    CHECK( pBuf != NULL, "Out of memory" );

    PSYMCRYPT_ECURVE_PARAMS pParams = (PSYMCRYPT_ECURVE_PARAMS) pBuf;

    GENRANDOM( pBuf, cbBuf );

    pParams->version = 1;
    pParams->type = SYMCRYPT_ECURVE_TYPE_SHORT_WEIERSTRASS;
    pParams->algId = SYMCRYPT_ECURVE_GEN_ALG_ID_NULL;
    pParams->cbFieldLength = 32;
    pParams->cbSubgroupOrder = 32;
    pParams->cbCofactor = 1;
    pParams->cbSeed = 0;

    CHECK( testCurveParamsValid( pParams, cbBuf ), "Params invalid" );

    pParams->cbFieldLength = 128;
    CHECK( testCurveParamsValid( pParams, cbBuf ), "Params invalid" );

    pParams->cbFieldLength = 129;
    CHECK( !testCurveParamsValid( pParams, cbBuf ), "Params valid" );

    pParams->cbFieldLength = 32;

    pParams->cbSubgroupOrder = 130;  // Can be 64 + 1 as subgroup can be larger than the field.
    CHECK( !testCurveParamsValid( pParams, cbBuf ), "Params valid" );

    pParams->cbSubgroupOrder = 32;

    pParams->cbCofactor = 3;
    CHECK( !testCurveParamsValid( pParams, cbBuf ), "Params valid" );
    pParams->cbCofactor = 1;

    pParams->cbSeed = 256;
    CHECK( testCurveParamsValid( pParams, cbBuf ), "Params invalid" );
    pParams->cbSeed = 257;
    CHECK( !testCurveParamsValid( pParams, cbBuf ), "Params valid" );
    pParams->cbSeed = 0;

    CHECK( testCurveParamsValid( pParams, cbBuf ), "Params invalid" );

    if( pBuf != NULL )
    {
        free( pBuf );
        pBuf = NULL;
    }
}

static UINT32 skippedKats = 0;

VOID
testEcc()
{
    static BOOL hasRun = FALSE;

    PSYMCRYPT_ECURVE            pCurve  = NULL;
    PCSYMCRYPT_ECURVE_PARAMS    pParams = NULL;

    INT64 nAllocs = 0;
    INT64 nOutstandingAllocs = 0;

    if( hasRun )
    {
        return;
    }
    hasRun = TRUE;

    // Skip if there is no Ec* algorithm to test.
    if( !isAlgorithmPresent( "Ec", TRUE ) )
    {
        return;
    }

    iprint( "    Elliptic Curve Crypto\n" );

    nOutstandingAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nOutstandingCheckedAllocs);
    CHECK3( nOutstandingAllocs  == 0, "Memory leak %d", nOutstandingAllocs );

    iprint("    > Functional testing");
    vprint(!g_verbose, ": ");
    vprint(g_verbose, "\n");

    for (int i=0; i<NUM_OF_INTERNAL_CURVES; i++)
    {
        vprint( g_verbose, "    > Curve ");
        iprint("%s", rgbInternalCurves[i].pszCurveName );
        if (i<NUM_OF_INTERNAL_CURVES-1)
        {
            vprint(!g_verbose, ", ");
        }
        vprint(g_verbose, "\n");

        nAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nAllocs);
        pParams = rgbInternalCurves[i].pParams;
        pCurve = SymCryptEcurveAllocate( pParams, 0 );
        CHECK( pCurve != NULL, "Curve allocation failed" );
        CHECK( (INT64) SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nAllocs) == nAllocs + 2, "Undesired allocation" );

        rgbInternalCurves[i].pCurve = pCurve;

        vprint( g_verbose, "    Field Modulus bitsize   : %d\n", SymCryptEcurveBitsizeofFieldModulus( pCurve ) );
        vprint( g_verbose, "    Group Order bitsize     : %d\n", SymCryptEcurveBitsizeofGroupOrder( pCurve ) );
        vprint( g_verbose, "    Ecpoint size in bytes   : %d\n", SymCryptSizeofEcpointFromCurve( pCurve ) );
        vprint( g_verbose, "    F. element size in bytes: %d\n", SymCryptEcurveSizeofFieldElement( pCurve ) );
        vprint( g_verbose, "    Private key default form: %s\n", rgbPrivateKeyFormatNames[SymCryptEcurvePrivateKeyDefaultFormat( pCurve ) ] );
        vprint( g_verbose, "    High bit restriction #Bs: %d\n", SymCryptEcurveHighBitRestrictionNumOfBits( pCurve ) );
        vprint( g_verbose, "    High bit restriction Pos: %d\n", SymCryptEcurveHighBitRestrictionPosition( pCurve ) );
        vprint( g_verbose, "    High bit restriction Val: 0x%X\n", SymCryptEcurveHighBitRestrictionValue( pCurve ) );


        if (pParams->type == SYMCRYPT_ECURVE_TYPE_SHORT_WEIERSTRASS ||
            pParams->type == SYMCRYPT_ECURVE_TYPE_TWISTED_EDWARDS)
        {
            testEccArithmetic( pCurve );
        }
        else if (pParams->type == SYMCRYPT_ECURVE_TYPE_MONTGOMERY)
        {
            testMontgomery( pCurve );
        }

        vprint( g_verbose, "\n");
    }

    iprint("\n    > KAT testing       : ");
    skippedKats = 0;
    testEccEcdsaKats();
    print( "    %d skipped KATS\n", skippedKats);

    for (int i=0; i<NUM_OF_INTERNAL_CURVES; i++)
    {
        SymCryptEcurveFree( rgbInternalCurves[i].pCurve );
    }

    nOutstandingAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nOutstandingCheckedAllocs);
    CHECK3( nOutstandingAllocs == 0, "Memory leak, %d outstanding", nOutstandingAllocs );

    if (g_dynamicSymCryptModuleHandle != NULL)
    {
        print("    testEccEcdsaKats dynamic\n");
        g_useDynamicFunctionsInTestCall = TRUE;

        for (int i=0; i<NUM_OF_INTERNAL_CURVES; i++)
        {
            vprint( g_verbose, "    > Curve ");
            iprint("%s", rgbInternalCurves[i].pszCurveName );
            if (i<NUM_OF_INTERNAL_CURVES-1)
            {
                vprint(!g_verbose, ", ");
            }
            vprint(g_verbose, "\n");

            nAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nAllocs);
            pParams = rgbInternalCurves[i].pParams;
            pCurve = ScDispatchSymCryptEcurveAllocate( pParams, 0 );
            CHECK( pCurve != NULL, "Curve allocation failed" );
            CHECK( (INT64) SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nAllocs) == nAllocs, "Undesired allocation" );

            rgbInternalCurves[i].pCurve = pCurve;
        }

        skippedKats = 0;
        testEccEcdsaKats();
        print( "    %d skipped KATS\n", skippedKats);

        for (int i=0; i<NUM_OF_INTERNAL_CURVES; i++)
        {
            ScDispatchSymCryptEcurveFree( rgbInternalCurves[i].pCurve );
        }
        g_useDynamicFunctionsInTestCall = FALSE;
    }

    // Put under an if( algorithm_present ) when we refactor this
    testBadCurveParams();

    iprint("\n");
}

SYMCRYPT_ERROR
printPoint(
    PCSYMCRYPT_ECURVE   pCurve,
    PCSYMCRYPT_ECPOINT  poPoint,
    PBYTE               pbBuffer,
    SIZE_T              cbBuffer,
    PBYTE               pbScratch,
    SIZE_T              cbScratch,
    BOOLEAN             fPrint )
{
    SYMCRYPT_ERROR  scError = SYMCRYPT_NO_ERROR;

    scError = SymCryptEcpointGetValue(
            pCurve,
            poPoint,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            SYMCRYPT_ECPOINT_FORMAT_XY,
            pbBuffer,
            cbBuffer,
            0,
            pbScratch,
            cbScratch);

    if (scError == SYMCRYPT_NO_ERROR)
    {
        if ( fPrint )
        {
            print("      >> X: ");
            printHex( pbBuffer, cbBuffer / 2 );
            print("\n");

            print("      >> Y: ");
            printHex( pbBuffer + cbBuffer / 2, cbBuffer / 2 );
            print("\n");
        }
    }
    else
    {
        print("      >> An error happened with GetValue : %d\n", (UINT32)scError );
    }

    return scError;
}


//
// ECDSA KAT Test code
//

#define SYMCRYPT_BITSIZE_P521       (521)       // This is the bitsize of the largest curve

VOID
testEcdsaVerify(
        PSYMCRYPT_ECURVE        pCurve,
        PCSYMCRYPT_HASH         pHash,
    _In_reads_( cbMsg )
        PCBYTE                  pbMsg,
        SIZE_T                  cbMsg,
    _In_reads_( cbQx )
        PCBYTE                  pbQx,
        SIZE_T                  cbQx,
    _In_reads_( cbQy )
        PCBYTE                  pbQy,
        SIZE_T                  cbQy,
    _In_reads_( cbR )
        PCBYTE                  pbR,
        SIZE_T                  cbR,
    _In_reads_( cbS )
        PCBYTE                  pbS,
        SIZE_T                  cbS,
    _In_reads_( cbResult )
        PCBYTE                  pbResult,
        SIZE_T                  cbResult,
        LONGLONG                line)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    PSYMCRYPT_ECKEY pkPublic = NULL;

    BYTE pbHashValue[SYMCRYPT_SHA512_RESULT_SIZE] = { 0 };
    PCBYTE pbDigest = NULL;
    UINT32 cbDigest = 0;
    BYTE pbSignature[2 * ((SYMCRYPT_BITSIZE_P521 + 7)/8)] = { 0 };             // big enough to hold any signature
    BYTE pbPublicKey[2 * ((SYMCRYPT_BITSIZE_P521 + 7)/8)] = { 0 };             // or the X,Y coordinates of a public key

    if( !SCTEST_LOOKUP_DISPATCHSYM(SymCryptEckeyAllocate) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptHash) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptHashResultSize) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptEckeySetValue) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptEcDsaVerify) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptEckeyFree) )
    {
        skippedKats++;
        return;
    }

    // Allocate the public key
    pkPublic = ScDispatchSymCryptEckeyAllocate( pCurve );
    CHECK3( pkPublic!=NULL, "Failure to allocate public key for ECDSA record at line %lld", line );

    // Hash the message
    if( pHash != NULL )
    {
        cbDigest = (UINT32) ScDispatchSymCryptHashResultSize( pHash );
        CHECK3( SYMCRYPT_SHA512_RESULT_SIZE >= cbDigest, "Hash result too big for ECDSA record at line %lld", line );
        ScDispatchSymCryptHash( pHash, pbMsg, cbMsg, pbHashValue, cbDigest );
        pbDigest = &pbHashValue[0];
    } else {
        pbDigest = pbMsg;
        cbDigest = (UINT32) cbMsg;
    }

    // Set the public key
    memcpy(pbPublicKey, pbQx, cbQx);
    memcpy(pbPublicKey+cbQx, pbQy, cbQy);

    scError = ScDispatchSymCryptEckeySetValue(
                nullptr,
                0,
                pbPublicKey,
                cbQx + cbQy,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                SYMCRYPT_ECPOINT_FORMAT_XY,
                SYMCRYPT_FLAG_ECKEY_ECDSA,
                pkPublic );
    CHECK3( scError == SYMCRYPT_NO_ERROR, "Public key set value failed for ECDSA record at line %lld", line );

    // Get the signature
    memcpy(pbSignature, pbR, cbR);
    memcpy(pbSignature+cbR, pbS, cbS);

    // Verify
    scError = ScDispatchSymCryptEcDsaVerify(
                        pkPublic,
                        pbDigest,
                        cbDigest,
                        pbSignature,
                        cbR + cbS,
                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                        0 );
    CHECK3( (scError == SYMCRYPT_NO_ERROR) || (scError == SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE),
            "EcDsaVerify failed for ECDSA record at line %lld", line );

    // Check the result
    CHECK3( cbResult > 0 , "Wrong format result for ECDSA record at line %lld", line );
    CHECK3( ((pbResult[0] == 'F') || (pbResult[0] == 'P')), "Unknown result value for ECDSA record at line %lld", line );
    if (pbResult[0] == 'F')
    {
        CHECK3( scError == SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE, "Wrong EcDsaVerify result for ECDSA record at line %lld", line );
    }
    else
    {
        CHECK3( scError == SYMCRYPT_NO_ERROR, "Wrong EcDsaVerify result for ECDSA record at line %lld", line );
    }

    ScDispatchSymCryptEckeyFree( pkPublic );

    dprint("EcdsaVerify dataset at line %lld was successful.\n", line);
}

VOID
testEcdsaSign(
        PSYMCRYPT_ECURVE        pCurve,
        PCSYMCRYPT_HASH         pHash,
    _In_reads_( cbMsg )
        PCBYTE                  pbMsg,
        SIZE_T                  cbMsg,
    _In_reads_( cbD )
        PCBYTE                  pbD,
        SIZE_T                  cbD,
    _In_reads_( cbQx )
        PCBYTE                  pbQx,
        SIZE_T                  cbQx,
    _In_reads_( cbQy )
        PCBYTE                  pbQy,
        SIZE_T                  cbQy,
    _In_reads_( cbK )
        PCBYTE                  pbK,
        SIZE_T                  cbK,
    _In_reads_( cbR )
        PCBYTE                  pbR,
        SIZE_T                  cbR,
    _In_reads_( cbS )
        PCBYTE                  pbS,
        SIZE_T                  cbS,
        LONGLONG                line)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    PSYMCRYPT_ECKEY pkPrivate = NULL;
    PSYMCRYPT_INT   piK = NULL;

    BYTE pbHashValue[SYMCRYPT_SHA512_RESULT_SIZE] = { 0 };
    PCBYTE pbDigest = NULL;
    UINT32 cbDigest = 0;
    BYTE pbSignature[2 * ((SYMCRYPT_BITSIZE_P521 + 7)/8)] = { 0 };             // big enough to hold any signature

    if (!SCTEST_LOOKUP_DISPATCHSYM(SymCryptEckeyAllocate) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptIntAllocate) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptHash) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptEckeySetValue) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptEckeyGetValue) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptEckeySizeofPublicKey) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptIntSetValue) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptEcDsaSignEx) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptEcurveSizeofScalarMultiplier) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptIntFree) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptEckeyFree) )
    {
        skippedKats++;
        return;
    }

    // Allocate the private key and the random exponent K
    pkPrivate = ScDispatchSymCryptEckeyAllocate( pCurve );
    CHECK3( pkPrivate!=NULL, "Failure to allocate private key for ECDSA record at line %lld", line );
    piK = ScDispatchSymCryptIntAllocate( ScDispatchSymCryptEcurveDigitsofScalarMultiplier(pCurve) );
    CHECK3( piK!=NULL, "Failure to allocate random exponent K for ECDSA record at line %lld", line );

    // Hash the message
    CHECK( pHash != NULL, "Unsupported test case for ECDSA sign")

    pbDigest = &pbHashValue[0];
    cbDigest = (UINT32) ScDispatchSymCryptHashResultSize( pHash );

    CHECK3( SYMCRYPT_SHA512_RESULT_SIZE >= cbDigest, "Hash result too big for ECDSA record at line %lld", line );
    ScDispatchSymCryptHash( pHash, pbMsg, cbMsg, pbHashValue, cbDigest );

    // Set the new key
    scError = ScDispatchSymCryptEckeySetValue(
                pbD,
                cbD,
                nullptr,
                0,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                SYMCRYPT_ECPOINT_FORMAT_XY,
                SYMCRYPT_FLAG_ECKEY_ECDSA,
                pkPrivate );
    CHECK3( scError == SYMCRYPT_NO_ERROR, "Private key set value failed for ECDSA record at line %lld", line );

    // Check if the public key created is correct
    scError = ScDispatchSymCryptEckeyGetValue(
                pkPrivate,
                nullptr,
                0,
                pbSignature,
                ScDispatchSymCryptEckeySizeofPublicKey( pkPrivate, SYMCRYPT_ECPOINT_FORMAT_XY ),
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                SYMCRYPT_ECPOINT_FORMAT_XY,
                0 );
    CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptEckeyGetValue failed for ECDSA record at line %lld", line );

    CHECK3( memcmp( pbQx, pbSignature, cbQx ) == 0, "Qx doesn't match for ECDSA record at line %lld", line );
    CHECK3( memcmp( pbQy, pbSignature + cbQx, cbQy ) == 0, "Qy doesn't match for ECDSA record at line %lld", line );

    // Set the modelement K
    scError = ScDispatchSymCryptIntSetValue( pbK, cbK, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piK );
    CHECK3( scError == SYMCRYPT_NO_ERROR, "Modelement K failed to set value for ECDSA record at line %lld", line );

    // Sign
    scError = ScDispatchSymCryptEcDsaSignEx(
                        pkPrivate,
                        pbDigest,
                        cbDigest,
                        piK,
                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                        0,
                        pbSignature,
                        2 * ScDispatchSymCryptEcurveSizeofScalarMultiplier( pCurve ) );
    CHECK3( scError == SYMCRYPT_NO_ERROR, "EcDsaSignEx failed for ECDSA record at line %lld", line );

    // Check the result
    CHECK3( memcmp( pbR, pbSignature, cbR ) == 0, "Test vector R doesn't match for ECDSA record at line %lld", line );
    CHECK3( memcmp( pbS, pbSignature + cbR, cbS ) == 0, "Test vector S doesn't match for ECDSA record at line %lld", line );

    ScDispatchSymCryptIntFree( piK );
    ScDispatchSymCryptEckeyFree( pkPrivate );
}

VOID
testEcdh(
        PSYMCRYPT_ECURVE        pCurve,
    _In_reads_( cbSa )
        PCBYTE                  pbSa,
        SIZE_T                  cbSa,
    _In_reads_( cbQxa )
        PCBYTE                  pbQxa,
        SIZE_T                  cbQxa,
    _In_reads_( cbQya )
        PCBYTE                  pbQya,
        SIZE_T                  cbQya,
    _In_reads_( cbQxb )
        PCBYTE                  pbQxb,
        SIZE_T                  cbQxb,
    _In_reads_( cbQyb )
        PCBYTE                  pbQyb,
        SIZE_T                  cbQyb,
    _In_reads_( cbSS )
        PCBYTE                  pbSs,
        SIZE_T                  cbSs,
        UINT32                  secretAgreementFlags,
        LONGLONG                line)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    PSYMCRYPT_ECKEY pkPrivate = NULL;
    PSYMCRYPT_ECKEY pkPublic = NULL;

    BYTE pbSharedSecret[((SYMCRYPT_BITSIZE_P521 + 7)/8)] = { 0 };   // big enough to hold any shared secret
    BYTE pbPublicKey[2 * ((SYMCRYPT_BITSIZE_P521 + 7)/8)] = { 0 };  // or the X,Y coordinates of a public key
    PCBYTE pbOptPublicKey = NULL;
    SIZE_T cbOptPublicKey = 0;
    BYTE randByte = g_rng.byte();
    UINT32 flags = SYMCRYPT_FLAG_ECKEY_ECDH;

    if (!SCTEST_LOOKUP_DISPATCHSYM(SymCryptEckeyAllocate) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptEckeySetValue) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptEckeyGetValue) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptEckeySizeofPublicKey) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptEcDhSecretAgreement) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptEcurveSizeofFieldElement) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptEckeyFree) )
    {
        skippedKats++;
        return;
    }

    // Allocate the keys
    pkPrivate = ScDispatchSymCryptEckeyAllocate( pCurve );
    CHECK3( pkPrivate!=NULL, "Failure to allocate private key for ECDH record at line %lld", line );
    pkPublic = ScDispatchSymCryptEckeyAllocate( pCurve );
    CHECK3( pkPublic!=NULL, "Failure to allocate public key for ECDH record at line %lld", line );

    // Set the private and public key for party A
    // Randomize flags and whether we provide the public key to exercise more codepaths
    if (randByte & 0x1)
    {
        flags |= SYMCRYPT_FLAG_KEY_NO_FIPS;
    }
    if (randByte & 0x2)
    {
        flags |= SYMCRYPT_FLAG_ECKEY_ECDSA;
    }
    if (randByte & 0x4)
    {
        memcpy(pbPublicKey, pbQxa, cbQxa);
        memcpy(pbPublicKey+cbQxa, pbQya, cbQya);
        pbOptPublicKey = pbPublicKey;
        cbOptPublicKey = cbQxa + cbQya;
    }

    scError = ScDispatchSymCryptEckeySetValue(
                pbSa,
                cbSa,
                pbOptPublicKey,
                cbOptPublicKey,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                SYMCRYPT_ECPOINT_FORMAT_XY,
                flags,
                pkPrivate );
    CHECK3( scError == SYMCRYPT_NO_ERROR, "Private key set value failed for ECDH record at line %lld", line );

    // Check if the set public key is correct
    scError = ScDispatchSymCryptEckeyGetValue(
                pkPrivate,
                nullptr,
                0,
                pbPublicKey,
                ScDispatchSymCryptEckeySizeofPublicKey( pkPrivate, SYMCRYPT_ECPOINT_FORMAT_XY ),
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                SYMCRYPT_ECPOINT_FORMAT_XY,
                0 );
    CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptEckeyGetValue failed for ECDH record at line %lld", line );

    CHECK3( memcmp( pbQxa, pbPublicKey, cbQxa ) == 0, "Qx doesn't match for ECDH record at line %lld", line );
    CHECK3( memcmp( pbQya, pbPublicKey + cbQxa, cbQya ) == 0, "Qy doesn't match for ECDH record at line %lld", line );

    // Set the public key for party B
    // Randomize flags to exercise more codepaths
    flags = SYMCRYPT_FLAG_ECKEY_ECDH;
    if (randByte & 0x10)
    {
        flags |= SYMCRYPT_FLAG_KEY_NO_FIPS;
    }
    if ((randByte & 0x20) && (flags & SYMCRYPT_FLAG_KEY_NO_FIPS))
    {
        flags |= SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION;
    }
    if (randByte & 0x40)
    {
        flags |= SYMCRYPT_FLAG_ECKEY_ECDSA;
    }
    memcpy(pbPublicKey, pbQxb, cbQxb);
    memcpy(pbPublicKey+cbQxb, pbQyb, cbQyb);

    scError = ScDispatchSymCryptEckeySetValue(
                nullptr,
                0,
                pbPublicKey,
                cbQxb + cbQyb,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                SYMCRYPT_ECPOINT_FORMAT_XY,
                flags,
                pkPublic );
    CHECK3( scError == SYMCRYPT_NO_ERROR, "Public key set value failed for ECDH record at line %lld", line );

    // Call Ecdh
    scError = ScDispatchSymCryptEcDhSecretAgreement(
                pkPrivate,
                pkPublic,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                secretAgreementFlags,
                pbSharedSecret,
                ScDispatchSymCryptEcurveSizeofFieldElement( pCurve ));
    CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptEcDhSecretAgreement failed for ECDH record at line %lld", line );

    CHECK3( memcmp( pbSs, pbSharedSecret, cbSs ) == 0, "Shared secret doesn't match for ECDH record at line %lld", line );

    ScDispatchSymCryptEckeyFree( pkPublic );
    ScDispatchSymCryptEckeyFree( pkPrivate );
}

VOID
testEccEcdsaKats()
{
    std::unique_ptr<KatData> katEcc( getCustomResource( "kat_ecdsa.dat", "KAT_ECDSA" ) );
    KAT_ITEM katItem;

    String sep = "";

    int i = 0;
    BOOLEAN bCurveFound = FALSE;
    PSYMCRYPT_ECURVE pCurve = NULL;
    PCSYMCRYPT_HASH pHash = NULL;

    UINT32 cEcdsaSignSamples = 0;
    UINT32 cEcdsaVrfySamples = 0;
    UINT32 cEcdhSamples = 0;

    while( 1 )
    {
        katEcc->getKatItem( & katItem );
        ULONGLONG line = katItem.line;

        if( katItem.type == KAT_TYPE_END )
        {
            break;
        }

        if( katItem.type == KAT_TYPE_CATEGORY )
        {
            // We never skip data and the algorithm is
            // specified by the data item.
            iprint( "%s%s", sep.c_str(), katItem.categoryName.c_str() );
            sep = ", ";
        }

        if( katItem.type == KAT_TYPE_DATASET )
        {
            // Find the curve (it has to be pre-allocated)
            const KAT_DATA_ITEM * pKatCurve = findDataItem( katItem, "curve" );
            CHECK3( pKatCurve != NULL, "No curve data item in ECDSA record at line %lld", line );

            bCurveFound = FALSE;
            for( i=0; i < NUM_OF_INTERNAL_CURVES; i++ )
            {
                // Compare with the curve name excluding the first and last character (they are ")
                if ( strcmp( pKatCurve->data.substr(1,pKatCurve->data.size()-2).c_str(), rgbInternalCurves[i].pszCurveName ) == 0 )
                {
                    bCurveFound = TRUE;
                    break;
                }
            }
            if (!bCurveFound)
            {
                dprint( "Ecdsa record at line %lld is skipped due to unknown curve.\n", line);
                continue;   // Skip this record if the curve is not in SymCrypt
            }

            pCurve = rgbInternalCurves[i].pCurve;
            CHECK3( pCurve != NULL, "Curve not allocated for ECDSA record at line %lld", line );

            if (katIsFieldPresent( katItem, "result" ) )
            {
                //
                // EcdsaVerify
                //
                CHECK3( katItem.dataItems.size() == 8, "Wrong number of items in ECDSA Verify record at line %lld", line );

                // Find the hash algorithm
                const KAT_DATA_ITEM * pKatHash = findDataItem( katItem, "hash" );
                CHECK3( pKatHash != NULL, "No hash data item in ECDSA record at line %lld", line );

                if( !getHashAlgorithm( pKatHash->data.substr(1,pKatHash->data.size()-2).c_str(), line, &pHash ) )
                {
                    continue; // skip this record
                }

                BString katMsg = katParseData( katItem, "msg" );
                BString katQx = katParseData( katItem, "qx" );
                BString katQy = katParseData( katItem, "qy" );
                BString katR = katParseData( katItem, "r" );
                BString katS = katParseData( katItem, "s" );
                BString katResult = katParseData( katItem, "result" );

                testEcdsaVerify(
                        pCurve,
                        pHash,
                        katMsg.data(), katMsg.size(),
                        katQx.data(), katQx.size(),
                        katQy.data(), katQy.size(),
                        katR.data(), katR.size(),
                        katS.data(), katS.size(),
                        katResult.data(), katResult.size(),
                        katEcc->m_line);

                cEcdsaVrfySamples++;
                continue;
            }
            else if (katIsFieldPresent( katItem, "ziut" ))
            {
                //
                // Ecdh
                //
                CHECK3( katItem.dataItems.size() == 9, "Wrong number of items in ECDH record at line %lld", line );

                BString katDiut = katParseData( katItem, "diut" );
                BString katQiutX = katParseData( katItem, "qiutx" );
                BString katQiutY = katParseData( katItem, "qiuty" );
                BString katQcavsX = katParseData( katItem, "qcavsx" );
                BString katQcavsY = katParseData( katItem, "qcavsy" );
                BString katZiut = katParseData( katItem, "ziut" );
                BString katDivH = katParseData( katItem, "flags" );

                testEcdh(
                        pCurve,
                        katDiut.data(), katDiut.size(),
                        katQiutX.data(), katQiutX.size(),
                        katQiutY.data(), katQiutY.size(),
                        katQcavsX.data(), katQcavsX.size(),
                        katQcavsY.data(), katQcavsY.size(),
                        katZiut.data(), katZiut.size(),
                        (UINT32) katDivH.data()[0],
                        katEcc->m_line);

                cEcdhSamples++;
                continue;
            }
            else
            {
                //
                // EcdsaSign
                //
                CHECK3( katItem.dataItems.size() == 9, "Wrong number of items in ECDSA Verify record at line %lld", line );

                // Find the hash algorithm
                const KAT_DATA_ITEM * pKatHash = findDataItem( katItem, "hash" );
                CHECK3( pKatHash != NULL, "No hash data item in ECDSA record at line %lld", line );

                if( !getHashAlgorithm( pKatHash->data.substr(1,pKatHash->data.size()-2).c_str(), line, &pHash ) )
                {
                    continue; // skip this record
                }

                BString katMsg = katParseData( katItem, "msg" );
                BString katD = katParseData( katItem, "d" );
                BString katQx = katParseData( katItem, "qx" );
                BString katQy = katParseData( katItem, "qy" );
                BString katK = katParseData( katItem, "k" );
                BString katR = katParseData( katItem, "r" );
                BString katS = katParseData( katItem, "s" );

                testEcdsaSign(
                        pCurve,
                        pHash,
                        katMsg.data(), katMsg.size(),
                        katD.data(), katD.size(),
                        katQx.data(), katQx.size(),
                        katQy.data(), katQy.size(),
                        katK.data(), katK.size(),
                        katR.data(), katR.size(),
                        katS.data(), katS.size(),
                        katEcc->m_line);

                cEcdsaSignSamples++;
                dprint("EcdsaSign dataset at line %lld was successful.\n", line);
                continue;
            }

            FATAL2( "Unknown data record at line %lld", line );
        }
    }

    iprint( "\n        Total samples: %d EcdsaSign, %d EcdsaVerify, %d Ecdh\n", cEcdsaSignSamples, cEcdsaVrfySamples, cEcdhSamples);
}
