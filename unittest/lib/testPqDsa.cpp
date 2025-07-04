//
// testPqDsa.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Test code for post-quantum digital signature algorithms.
//

#include "test_lib.h"

extern "C" {

extern const SYMCRYPT_MLDSA_INTERNAL_PARAMS SymCryptMlDsaInternalParams44;
extern const SYMCRYPT_MLDSA_INTERNAL_PARAMS SymCryptMlDsaInternalParams65;
extern const SYMCRYPT_MLDSA_INTERNAL_PARAMS SymCryptMlDsaInternalParams87;

}

#define SYMCRYPT_MLDSA_44_PARAMS_NAME  "ML-DSA-44"
#define SYMCRYPT_MLDSA_65_PARAMS_NAME  "ML-DSA-65"
#define SYMCRYPT_MLDSA_87_PARAMS_NAME  "ML-DSA-87"

typedef struct _SYMCRYPT_TEST_MLDSA_PARAMS {
    LPSTR                   pszParamsName;
    SYMCRYPT_MLDSA_PARAMS   params;
} SYMCRYPT_TEST_MLDSA_PARAMS, *PSYMCRYPT_TEST_MLDSA_PARAMS;

SYMCRYPT_TEST_MLDSA_PARAMS rgTestMlDsaParams[] = {
    //pszParamsName                     //params
    { SYMCRYPT_MLDSA_44_PARAMS_NAME,   SYMCRYPT_MLDSA_PARAMS_MLDSA44 },
    { SYMCRYPT_MLDSA_65_PARAMS_NAME,   SYMCRYPT_MLDSA_PARAMS_MLDSA65 },
    { SYMCRYPT_MLDSA_87_PARAMS_NAME,   SYMCRYPT_MLDSA_PARAMS_MLDSA87 },
};

#define NUM_OF_MLDSA_TEST_PARAMS       (sizeof(rgTestMlDsaParams) / sizeof(rgTestMlDsaParams[0]))

typedef struct _SYMCRYPT_MLWE_PARAMS {
    UINT16 nCoefficients;
    UINT8 rLog2;
    UINT32 modulus;
    UINT32 modulusInv;
} SYMCRYPT_MLWE_PARAMS, *PSYMCRYPT_MLWE_PARAMS;

constexpr SYMCRYPT_MLWE_PARAMS SYMCRYPT_MLWE_PARAMS_TEST = { 2, 16, 17, 0 };
constexpr SYMCRYPT_MLWE_PARAMS SYMCRYPT_MLWE_PARAMS_TEST2 = { 5, 16, 17, 0 };
constexpr SYMCRYPT_MLWE_PARAMS SYMCRYPT_MLWE_PARAMS_MLDSA = { 256, 32, 8380417, 58728449 };

typedef SYMCRYPT_ASYM_ALIGN_STRUCT _SYMCRYPT_TEST_POLYELEMENT {
    // PolyElements just store the coefficients without any header.
    UINT16    coeffs[SYMCRYPT_MLWE_PARAMS_TEST.nCoefficients];
} SYMCRYPT_TEST_POLYELEMENT, *PSYMCRYPT_TEST_POLYELEMENT;

typedef SYMCRYPT_ASYM_ALIGN_STRUCT _SYMCRYPT_TEST_POLYELEMENT_2 {
    // PolyElements just store the coefficients without any header.
    UINT16    coeffs[SYMCRYPT_MLWE_PARAMS_TEST2.nCoefficients];
} SYMCRYPT_TEST_POLYELEMENT_2, *PSYMCRYPT_TEST_POLYELEMENT_2;

const UINT32 MLDSA_ZETA_BITREV[256] = {
    1, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987,
    7778734, 3542485, 2682288, 2129892, 3764867, 7375178, 557458, 7159240,
    5010068, 4317364, 2663378, 6705802, 4855975, 7946292, 676590, 7044481,
    5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639, 2283733,
    3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875,
    394148, 928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050,
    3415069, 1759347, 7562881, 4805951, 3756790, 6444618, 6663429, 4430364,
    5483103, 3192354, 556856, 3870317, 2917338, 1853806, 3345963, 1858416,
    3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977, 8106357,
    2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088,
    1528066, 482649, 1148858, 5418153, 7814814, 169688, 2462444, 5046034,
    4213992, 4892034, 1987814, 5183169, 1736313, 235407, 5130263, 3258457,
    5801164, 1787943, 5989328, 6125690, 3482206, 4197502, 7080401, 6018354,
    7062739, 2461387, 3035980, 621164, 3901472, 7153756, 2925816, 3374250,
    1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254,
    348812, 8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507,
    1753, 6444997, 5720892, 6924527, 2660408, 6600190, 8321269, 2772600,
    1182243, 87208, 636927, 4415111, 4423672, 6084020, 5095502, 4663471,
    8352605, 822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952,
    6695264, 4969849, 2678278, 4611469, 4829411, 635956, 8129971, 5925040,
    4234153, 6607829, 2192938, 6653329, 2387513, 4768667, 8111961, 5199961,
    3747250, 2296099, 1239911, 4541938, 3195676, 2642980, 1254190, 8368000,
    2998219, 141835, 8291116, 2513018, 7025525, 613238, 7070156, 6161950,
    7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452,
    6757063, 2105286, 6006015, 6346610, 586241, 7200804, 527981, 5637006,
    6903432, 1994046, 2491325, 6987258, 507927, 7192532, 7655613, 6545891,
    5346675, 8041997, 2647994, 3009748, 5767564, 4148469, 749577, 4357667,
    3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598, 5011144,
    3994671, 8368538, 7009900, 3020393, 3363542, 214880, 545376, 7609976,
    3105558, 7277073, 508145, 7826699, 860144, 3430436, 140244, 6866265,
    6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054, 7987710,
    8077412, 3531229, 4405932, 4606686, 1900052, 7598542, 1054478, 7648983
};

const UINT32 MLDSA_ZETA_BITREV_NEGATIVE[256] = {
    8380416, 3572223, 4614810, 4618904, 3201494, 2883726, 3145678, 3201430,
    601683, 4837932, 5698129, 6250525, 4615550, 1005239, 7822959, 1221177,
    3370349, 4063053, 5717039, 1674615, 3524442, 434125, 7703827, 1335936,
    3227876, 6666122, 5926434, 6919699, 642628, 3585098, 5564778, 6096684,
    4778199, 5197539, 5639874, 3586446, 3110818, 6279007, 4675594, 7220542,
    7986269, 7451668, 7284949, 3506380, 6308588, 4018989, 5138445, 6224367,
    4965348, 6621070, 817536, 3574466, 4623627, 1935799, 1716988, 3950053,
    2897314, 5188063, 7823561, 4510100, 5463079, 6526611, 5034454, 6522001,
    5307408, 7102792, 2635473, 4528402, 4197045, 3222807, 3121440, 274060,
    5871437, 6352299, 6442847, 3815725, 5569126, 2983781, 1109516, 4222329,
    6852351, 7897768, 7231559, 2962264, 565603, 8210729, 5917973, 3334383,
    4166425, 3488383, 6392603, 3197248, 6644104, 8145010, 3250154, 5121960,
    2579253, 6592474, 2391089, 2254727, 4898211, 4182915, 1300016, 2362063,
    1317678, 5919030, 5344437, 7759253, 4478945, 1226661, 5454601, 5006167,
    7023969, 2775755, 5697147, 2778788, 3467665, 6067579, 653275, 459163,
    8031605, 327848, 7369194, 2354215, 3818627, 1922253, 2236726, 6635910,
    8378664, 1935420, 2659525, 1455890, 5720009, 1780227, 59148, 5607817,
    7198174, 8293209, 7743490, 3965306, 3956745, 2296397, 3284915, 3716946,
    27812, 7557876, 7371052, 2454145, 1979497, 6783595, 3956944, 3759465,
    1685153, 3410568, 5702139, 3768948, 3551006, 7744461, 250446, 2455377,
    4146264, 1772588, 6187479, 1727088, 5992904, 3611750, 268456, 3180456,
    4633167, 6084318, 7140506, 3838479, 5184741, 5737437, 7126227, 12417,
    5382198, 8238582, 89301, 5867399, 1354892, 7767179, 1310261, 2218467,
    458740, 1921994, 4340221, 3472069, 6341273, 1879878, 818761, 2178965,
    1623354, 6275131, 2374402, 2033807, 7794176, 1179613, 7852436, 2743411,
    1476985, 6386371, 5889092, 1393159, 7872490, 1187885, 724804, 1834526,
    3033742, 338420, 5732423, 5370669, 2612853, 4231948, 7630840, 4022750,
    4399818, 5811406, 1615530, 6657188, 6715099, 6352379, 7216819, 3369273,
    4385746, 11879, 1370517, 5360024, 5016875, 8165537, 7835041, 770441,
    5274859, 1103344, 7872272, 553718, 7520273, 4949981, 8240173, 1514152,
    2185084, 5256655, 6022044, 2193087, 3014420, 1716814, 5454363, 392707,
    303005, 4849188, 3974485, 3773731, 6480365, 781875, 7325939, 731434
};

template<const SYMCRYPT_MLWE_PARAMS *Params, typename PolyElement>
VOID
printPoly(
    PolyElement* pe )
{
    iprint("{%u, %u, %u, ... %u}", pe->coeffs[0], pe->coeffs[1], pe->coeffs[2], pe->coeffs[Params->nCoefficients - 1]);
}

constexpr auto printSymCryptMlDsaPolyElement = printPoly< &SYMCRYPT_MLWE_PARAMS_MLDSA, SYMCRYPT_MLDSA_POLYELEMENT >;

VOID
printVector(
    PCSYMCRYPT_MLDSA_VECTOR pvVec)
{
    iprint("[\n");
    for(UINT32 i = 0; i < pvVec->nElems; ++i)
    {
        printSymCryptMlDsaPolyElement( SYMCRYPT_INTERNAL_MLDSA_VECTOR_ELEMENT( i, pvVec ) );
        iprint(",\n");
    }
    iprint("]\n");
}

VOID
printMatrix(
    PCSYMCRYPT_MLDSA_MATRIX pmMat)
{
    iprint("[\n");
    for(UINT32 i = 0; i < pmMat->nRows; ++i)
    {
        for(UINT32 j = 0; j < pmMat->nCols; ++j)
        {
            printSymCryptMlDsaPolyElement( SYMCRYPT_INTERNAL_MLDSA_MATRIX_ELEMENT( i, j, pmMat ) );
            iprint(", ");
        }
        iprint("\n");
    }
    iprint("]\n");
}

//
// IMPORTANT: The test functions below are not side-channel safe and must only be used in testing.
//

template<const SYMCRYPT_MLWE_PARAMS *Params, typename PolyElement>
BOOL
testSymCryptPolyElementEqual(
    const PolyElement* peA,
    const PolyElement* peB )
{
    for(UINT32 i=0; i < Params->nCoefficients; i++)
    {
        if(peA->coeffs[i] != peB->coeffs[i])
        {
            return FALSE;
        }
    }

    return TRUE;
}

constexpr auto testSymCryptMlDsaPolyElementEqual = testSymCryptPolyElementEqual< &SYMCRYPT_MLWE_PARAMS_MLDSA, SYMCRYPT_MLDSA_POLYELEMENT >;

template<const SYMCRYPT_MLWE_PARAMS *Params, typename PolyElement, typename CoeffWidth, typename ProductWidth>
VOID
testSymCryptNaivePolyMul(
    PolyElement* peA,
    PolyElement* peB,
    PolyElement* peResult )
{
    UINT32 i, j;
    CoeffWidth a, b, c;
    ProductWidth ab;

    for( i=0; i < Params->nCoefficients; i++ )
    {
        peResult->coeffs[i] = 0;
    }

    for( i=0; i < Params->nCoefficients; i++ )
    {
        for( j=0; j < Params->nCoefficients; j++ )
        {
            a = peA->coeffs[i];
            b = peB->coeffs[j];
            ab = ((ProductWidth) a * b) % Params->modulus;
            
            c = peResult->coeffs[(i+j) % Params->nCoefficients];

            if(i + j < Params->nCoefficients)
            {
                c += (CoeffWidth) ab;

            }
            else
            {
                if(ab > c)
                {
                    c += (CoeffWidth) (Params->modulus - (CoeffWidth) ab);
                }
                else
                {
                    c -= (CoeffWidth) ab;
                }
            }

            c %= Params->modulus;

            peResult->coeffs[(i+j) % Params->nCoefficients] = (UINT32) c;
        }
    }
}

constexpr auto testSymCryptMlDsaNaivePolyMul = testSymCryptNaivePolyMul< &SYMCRYPT_MLWE_PARAMS_MLDSA, SYMCRYPT_MLDSA_POLYELEMENT, UINT32, UINT64 >;

UINT32
SYMCRYPT_CALL
testSymCryptMlDsaModulo( INT64 a )
{
    INT32 r = (INT32) (a % SYMCRYPT_MLDSA_Q);
    if(r < 0)
    {
        r += SYMCRYPT_MLDSA_Q;
    }

    SYMCRYPT_ASSERT(r >= 0 && ((UINT32) r) < SYMCRYPT_MLDSA_Q);
    return (UINT32) r;
}

VOID
SYMCRYPT_CALL
testSymCryptMlDsaMatrixSetElement(
    _In_    PCSYMCRYPT_MLDSA_POLYELEMENT peSrc,
            UINT32                       row,
            UINT32                       col,
    _Inout_ PSYMCRYPT_MLDSA_MATRIX       pmDst)
{
    SYMCRYPT_ASSERT( row < pmDst->nRows );
    SYMCRYPT_ASSERT( col < pmDst->nCols );

    PSYMCRYPT_MLDSA_POLYELEMENT peDst = SYMCRYPT_INTERNAL_MLDSA_MATRIX_ELEMENT( row, col, pmDst );
    memcpy( peDst, peSrc, SYMCRYPT_INTERNAL_MLDSA_SIZEOF_POLYELEMENT );
}

VOID
SYMCRYPT_CALL
testSymCryptMlDsaPolyElementNTT(
    _Inout_ PSYMCRYPT_MLDSA_POLYELEMENT peSrc )
{
    UINT32 k = 0;

    for(UINT32 len = 128; len >= 1; len /= 2)
    {
        for(UINT32 start = 0; start < 256; start += 2 * len)
        {
            k++;
            UINT64 twiddleFactor = MLDSA_ZETA_BITREV[k];

            for(UINT32 j = start; j < start + len; j++)
            {
                UINT32 t = testSymCryptMlDsaModulo(twiddleFactor * peSrc->coeffs[j + len]);
                peSrc->coeffs[j + len] = testSymCryptMlDsaModulo(peSrc->coeffs[j] + SYMCRYPT_MLDSA_Q - t);
                peSrc->coeffs[j] = testSymCryptMlDsaModulo(peSrc->coeffs[j] + t);
            }
        }
    }
}

VOID
SYMCRYPT_CALL
testSymCryptMlDsaPolyElementINTT(
    _Inout_ PSYMCRYPT_MLDSA_POLYELEMENT peSrc )
{
    UINT32 k = 256;

    for(UINT32 len = 1; len < 256; len *= 2)
    {
        for(UINT32 start = 0; start < 256; start += 2 * len)
        {
            k--;
            UINT64 twiddleFactor = MLDSA_ZETA_BITREV_NEGATIVE[k];

            for(UINT32 j = start; j < start + len; j++)
            {
                UINT32 t = peSrc->coeffs[j]; //SymCryptMlDsaMontMul(twiddleFactor, peSrc->coeffs[j + len]);
                peSrc->coeffs[j] = testSymCryptMlDsaModulo(t + peSrc->coeffs[j + len]);
                peSrc->coeffs[j + len] = testSymCryptMlDsaModulo(t + SYMCRYPT_MLDSA_Q - peSrc->coeffs[j + len]);
                peSrc->coeffs[j + len] = testSymCryptMlDsaModulo(twiddleFactor * peSrc->coeffs[j + len]);
            }
        }
    }

    for(UINT32 j = 0; j < 256; j++)
    {
        peSrc->coeffs[j] = testSymCryptMlDsaModulo((UINT64) 8347681 * peSrc->coeffs[j]); // From FIPS-204: f = 256^-1 mod Q
    }
}

VOID
testNaiveImpls()
{
    ////////////////////////////////////////////////////////////////////////////////
    // Known answer tests for naive multiplication of short polynomials
    ////////////////////////////////////////////////////////////////////////////////

    SYMCRYPT_TEST_POLYELEMENT a = { 0, 4 };
    SYMCRYPT_TEST_POLYELEMENT b = { 13, 4 };
    SYMCRYPT_TEST_POLYELEMENT c;
    SYMCRYPT_TEST_POLYELEMENT expected = { 1, 1 };

    testSymCryptNaivePolyMul< &SYMCRYPT_MLWE_PARAMS_TEST, SYMCRYPT_TEST_POLYELEMENT, UINT16, UINT32 >(&a, &b, &c);
    // iprint("a * b = (%ux^0 + %ux^1)\n", c.coeffs[0], c.coeffs[1]);
    if(!testSymCryptPolyElementEqual< &SYMCRYPT_MLWE_PARAMS_TEST, SYMCRYPT_TEST_POLYELEMENT >(&c, &expected))
    {
        CHECK(FALSE, "Polynomial 1 mismatch!\n");
    }

    SYMCRYPT_TEST_POLYELEMENT_2 a2 = { 13, 13, 10, 7, 7 };
    SYMCRYPT_TEST_POLYELEMENT_2 b2 = { 5, 7, 2, 16, 13 };
    SYMCRYPT_TEST_POLYELEMENT_2 c2;
    SYMCRYPT_TEST_POLYELEMENT_2 expected2 = { 13, 2, 15, 10, 5 };

    testSymCryptNaivePolyMul< &SYMCRYPT_MLWE_PARAMS_TEST2, SYMCRYPT_TEST_POLYELEMENT_2, UINT16, UINT32 >(&a2, &b2, &c2);
    // iprint("a * b = (%ux^0 + %ux^1 + %ux^2 + %ux^3 + %ux^4)\n", c2.coeffs[0], c2.coeffs[1], c2.coeffs[2], c2.coeffs[3], c2.coeffs[4]);
    if(!testSymCryptPolyElementEqual< &SYMCRYPT_MLWE_PARAMS_TEST2, SYMCRYPT_TEST_POLYELEMENT_2 >(&c2, &expected2))
    {
        CHECK(FALSE, "Polynomial 2 mismatch!\n");
    }

    SYMCRYPT_TEST_POLYELEMENT_2 a3 = { 3, 14, 5, 16, 6 };
    SYMCRYPT_TEST_POLYELEMENT_2 b3 = { 8, 12, 6, 16, 15 };
    SYMCRYPT_TEST_POLYELEMENT_2 c3;
    SYMCRYPT_TEST_POLYELEMENT_2 expected3 = { 8, 2, 9, 9, 12 };

    testSymCryptNaivePolyMul< &SYMCRYPT_MLWE_PARAMS_TEST2, SYMCRYPT_TEST_POLYELEMENT_2, UINT16, UINT32 >(&a3, &b3, &c3);
    // iprint("a * b = (%ux^0 + %ux^1 + %ux^2 + %ux^3 + %ux^4)\n", c3.coeffs[0], c3.coeffs[1], c3.coeffs[2], c3.coeffs[3], c3.coeffs[4]);
    if(!testSymCryptPolyElementEqual< &SYMCRYPT_MLWE_PARAMS_TEST2, SYMCRYPT_TEST_POLYELEMENT_2 >(&c3, &expected3))
    {
        CHECK(FALSE, "Polynomial 3 mismatch!\n");
    }

    ////////////////////////////////////////////////////////////////////////////////
    // Naive polynomial NTT and multiplication tests
    ////////////////////////////////////////////////////////////////////////////////

    const UINT32 elementCount = 4;
    PBYTE polyBuf = (PBYTE) SymCryptCallbackAlloc(sizeof(SYMCRYPT_MLDSA_POLYELEMENT) * elementCount);
    CHECK( polyBuf != nullptr, "SymCryptCallbackAlloc failed\n" );

    PSYMCRYPT_MLDSA_POLYELEMENT peZero, peOne, peOneNtt, peDst;

    {
        PSYMCRYPT_MLDSA_POLYELEMENT peElements[elementCount];

        for(int i = 0; i < elementCount; ++i)
        {
            peElements[i] = SymCryptMlDsaPolyElementCreate(
                polyBuf + i * sizeof(SYMCRYPT_MLDSA_POLYELEMENT), sizeof(SYMCRYPT_MLDSA_POLYELEMENT));
        }

        peZero = peElements[0];
        peOne = peElements[1];
        peOneNtt = peElements[2];

        peDst = peElements[3];
    }

    for( int i=0; i<SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS; i++ )
    {
        peZero->coeffs[i] = 0;
        peOne->coeffs[i] = 0;
        peOneNtt->coeffs[i] = 0;
    }

    peOne->coeffs[0] = 1;
    peOneNtt->coeffs[0] = 1;

    testSymCryptMlDsaPolyElementNTT(peZero);
    for(int i = 0; i < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS; ++i)
    {
        CHECK(peZero->coeffs[i] == 0, "Naive NTT(0) != 0");
    }

    testSymCryptMlDsaPolyElementNTT(peOneNtt);
    for(int i = 0; i < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS; ++i)
    {
        CHECK(peOneNtt->coeffs[i] == 1, "Naive NTT({1, 0, 0, ...}) != {1, 1, 1, ...}");
    }

    memcpy(peDst, peOneNtt, sizeof(SYMCRYPT_MLDSA_POLYELEMENT));

    testSymCryptMlDsaPolyElementINTT(peDst);
    CHECK(peDst->coeffs[0] == 1, "INTT(NTT({1, 1, 1, ...})) != {1, 0, 0, ...}");
    for(int i = 1; i < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS; ++i)
    {
        CHECK(peDst->coeffs[i] == 0, "Naive INTT(NTT({1, 1, 1, ...})) != {1, 0, 0, ...}");
    }

    testSymCryptMlDsaNaivePolyMul(peOne, peOne, peDst);
    CHECK(testSymCryptMlDsaPolyElementEqual( peOne, peDst ), "Naive poly mul (1, 1) != 1");

    testSymCryptMlDsaNaivePolyMul(peOne, peZero, peDst);
    CHECK(testSymCryptMlDsaPolyElementEqual( peZero, peDst ), "Naive poly mul (1, 0) != 0");

    testSymCryptMlDsaNaivePolyMul(peZero, peZero, peDst);
    CHECK(testSymCryptMlDsaPolyElementEqual( peZero, peDst ), "Naive poly mul (0, 0) != 0");

    SymCryptWipe(polyBuf, sizeof(SYMCRYPT_MLDSA_POLYELEMENT) * elementCount);

    SymCryptCallbackFree(polyBuf);

    // iprint("        ML-DSA naive implementation tests successful!\n");
}

void
testMlDsaPolyArithmetic()
{
    const UINT32 elementCount = 9;
    PBYTE polyBuf = (PBYTE) SymCryptCallbackAlloc(sizeof(SYMCRYPT_MLDSA_POLYELEMENT) * elementCount);
    CHECK( polyBuf != nullptr, "SymCryptCallbackAlloc failed\n" );

    PSYMCRYPT_MLDSA_POLYELEMENT peZero, peOne, peOneNtt;
    PSYMCRYPT_MLDSA_POLYELEMENT peA, peB, peC, peD, peE, peF;

    {
        PSYMCRYPT_MLDSA_POLYELEMENT peElements[elementCount];

        for(int i = 0; i < elementCount; ++i)
        {
            peElements[i] = SymCryptMlDsaPolyElementCreate(
                polyBuf + i * sizeof(SYMCRYPT_MLDSA_POLYELEMENT), sizeof(SYMCRYPT_MLDSA_POLYELEMENT));
        }

        peZero = peElements[0];
        peOne = peElements[1];
        peOneNtt = peElements[2];

        peA = peElements[3];
        peB = peElements[4];
        peC = peElements[5];
        peD = peElements[6];
        peE = peElements[7];
        peF = peElements[8];
    }

    SymCryptMlDsaPolyElementSetZero(peZero);
    SymCryptMlDsaPolyElementSetZero(peOne);
    SymCryptMlDsaPolyElementSetZero(peOneNtt);

    peOne->coeffs[0] = 1;
    peOneNtt->coeffs[0] = 1;

    SymCryptMlDsaPolyElementNTT(peZero);
    for(int i = 0; i < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS; ++i)
    {
        CHECK(peZero->coeffs[i] == 0, "NTT(0) != 0");
    }

    SymCryptMlDsaPolyElementINTT(peZero);
    for(int i = 0; i < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS; ++i)
    {
        CHECK(peZero->coeffs[i] == 0, "INTT(0) != 0");
    }

    SymCryptMlDsaPolyElementNTT(peOneNtt);
    for(int i = 0; i < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS; ++i)
    {
        CHECK(peOneNtt->coeffs[i] == 1, "NTT({1, 0, 0, ...}) != {1, 1, 1, ...}");
    }

    memcpy(peC, peOneNtt, sizeof(SYMCRYPT_MLDSA_POLYELEMENT)); // peOneNtt = peC

    SymCryptMlDsaPolyElementINTT(peC);
    CHECK(peC->coeffs[0] == 1, "INTT(NTT({1, 1, 1, ...})) != {1, 0, 0, ...}");
    for(int i = 1; i < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS; ++i)
    {
        CHECK(peC->coeffs[i] == 0, "INTT(NTT({1, 1, 1, ...})) != {1, 0, 0, ...}");
    }

    SymCryptMlDsaPolyElementAdd( peZero, peZero, peC );
    CHECK(testSymCryptMlDsaPolyElementEqual( peZero, peC ), "(0 + 0) != 0");

    SymCryptMlDsaPolyElementAdd( peOne, peZero, peC );
    CHECK(testSymCryptMlDsaPolyElementEqual( peOne, peC ), "(1 + 0) != 1");

    SymCryptMlDsaPolyElementMulR(peOneNtt);

    SymCryptMlDsaPolyElementMontMul(peOneNtt, peOneNtt, peC);
    CHECK(testSymCryptMlDsaPolyElementEqual( peOneNtt, peC ), "NTT poly mul (1, 1) != 1");

    for(UINT32 i = 0; i < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS; ++i)
    {
        peOneNtt->coeffs[i] = SymCryptMlDsaMontReduce(peOneNtt->coeffs[i]);
        CHECK(peOneNtt->coeffs[i] == 1, "Montgomery reduction of peOneNtt did not yield original value");
    }

    SymCryptMlDsaPolyElementMontMul(peOneNtt, peZero, peC);
    CHECK(testSymCryptMlDsaPolyElementEqual( peZero, peC ), "NTT poly mul (1, 0) != 0");

    SymCryptMlDsaPolyElementMontMul(peZero, peZero, peC);
    CHECK(testSymCryptMlDsaPolyElementEqual( peZero, peC ), "NTT poly mul (0, 0) != 0");

    // Random value tests
    // iprint("        Random value tests\n");
    for(UINT32 i = 0; i < 10000; ++i)
    {
        for(UINT32 j = 0; j < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS; ++j)
        {
            peA->coeffs[j] = g_rng.uint32() % SYMCRYPT_MLWE_PARAMS_MLDSA.modulus;
            peB->coeffs[j] = g_rng.uint32() % SYMCRYPT_MLWE_PARAMS_MLDSA.modulus; 
        }

        memcpy(peD, peA, sizeof(SYMCRYPT_MLDSA_POLYELEMENT)); // peD = peA
        memcpy(peE, peB, sizeof(SYMCRYPT_MLDSA_POLYELEMENT)); // peE = peB

        SymCryptMlDsaPolyElementMulR(peD);
        SymCryptMlDsaPolyElementNTT(peD);
        SymCryptMlDsaPolyElementNTT(peE);

        SymCryptMlDsaPolyElementMontMul(peD, peE, peF);

        SymCryptMlDsaPolyElementINTT(peF);

        testSymCryptMlDsaNaivePolyMul(peA, peB, peC);
        CHECK(testSymCryptMlDsaPolyElementEqual( peC, peF ), "Naive poly mul (A, B) != NTT poly mul (A, B)");
    }

    // iprint("        Random offset adjacent value tests\n");

    // Iteration limit for the inner and outer loops
    // Total iteration count = loopLimit^2
    // Increase this for more coverage, but substantially slower tests
    const UINT32 loopLimit = 100;

    const UINT32 offsetA = g_rng.uint32() % SYMCRYPT_MLDSA_Q;
    const UINT32 offsetB = g_rng.uint32() % SYMCRYPT_MLDSA_Q;

    for(UINT32 i = 0; i < loopLimit; ++i)
    {
        for(UINT32 k = 0; k < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS; ++k)
        {
            peA->coeffs[k] = (offsetA + (i * SYMCRYPT_MLDSA_Q / loopLimit) + k) % SYMCRYPT_MLDSA_Q;
        }

        SymCryptMlDsaPolyElementAdd(peA, peZero, peC);
        CHECK(testSymCryptMlDsaPolyElementEqual( peA, peC ), "(A + 0) != A");

        SymCryptMlDsaPolyElementAdd(peZero, peA, peC);
        CHECK(testSymCryptMlDsaPolyElementEqual( peA, peC ), "(0 + A) != A");

        memcpy(peD, peA, sizeof(SYMCRYPT_MLDSA_POLYELEMENT)); // D = A
        memcpy(peE, peA, sizeof(SYMCRYPT_MLDSA_POLYELEMENT)); // E = A

        SymCryptMlDsaPolyElementNTT(peD);                     // D = NTT(A)
        testSymCryptMlDsaPolyElementNTT(peE);                 // E = NTT(A)
        CHECK(testSymCryptMlDsaPolyElementEqual( peD, peE ), "Naive NTT(A) != NTT(A)");

        memcpy(peF, peD, sizeof(SYMCRYPT_MLDSA_POLYELEMENT)); // F = D = NTT(A)

        SymCryptMlDsaPolyElementINTT(peF);                    // F = INTT(NTT(A)) = A
        testSymCryptMlDsaPolyElementINTT(peE);                // E = INTT(NTT(A)) = A
        CHECK(testSymCryptMlDsaPolyElementEqual( peF, peE ), "Naive INTT(Naive NTT(A)) != INTT(NTT(A))");
        CHECK(testSymCryptMlDsaPolyElementEqual( peA, peF ), "INTT(NTT(A)) != A");

        memcpy(peF, peD, sizeof(SYMCRYPT_MLDSA_POLYELEMENT)); // F = D = NTT(A)

        SymCryptMlDsaPolyElementMulR(peF);                // F = NTT(A) * R
        SymCryptMlDsaPolyElementMontMul(peF, peZero, peF);    // F = NTT(A) * R * 0 = 0
        CHECK(testSymCryptMlDsaPolyElementEqual( peZero, peF ), "INTT((NTT(A) * R) * 0 ./ R) != 0");

        memcpy(peF, peD, sizeof(SYMCRYPT_MLDSA_POLYELEMENT)); // F = D = NTT(A)

        SymCryptMlDsaPolyElementMulR(peF);                // F = NTT(A) * R
        SymCryptMlDsaPolyElementMontMul(peF, peOneNtt, peC);  // C = NTT(A) * R * NTT(1) = NTT(A)
        CHECK(testSymCryptMlDsaPolyElementEqual( peC, peD ), "(NTT(A) * R) * 1)  != NTT(A)");

        for(UINT32 j = 0; j < loopLimit; ++j)
        {
            for(UINT32 k = 0; k < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS; ++k)
            {
                peB->coeffs[k] = (offsetB + (j * SYMCRYPT_MLDSA_Q / loopLimit) + 3*k) % SYMCRYPT_MLDSA_Q;
            }

            SymCryptMlDsaPolyElementAdd(peA, peB, peC); // C = A + B
            SymCryptMlDsaPolyElementAdd(peB, peA, peD); // D = B + A
            CHECK(testSymCryptMlDsaPolyElementEqual( peC, peD ), "A + B != B + A");

            memcpy(peD, peA, sizeof(SYMCRYPT_MLDSA_POLYELEMENT)); // D = A
            memcpy(peE, peB, sizeof(SYMCRYPT_MLDSA_POLYELEMENT)); // E = B

            SymCryptMlDsaPolyElementNTT(peD);
            SymCryptMlDsaPolyElementNTT(peE);

            SymCryptMlDsaPolyElementAdd(peD, peE, peF); // F = NTT(A) + NTT(B)
            SymCryptMlDsaPolyElementINTT(peF);
            CHECK(testSymCryptMlDsaPolyElementEqual( peC, peF ), "INTT(NTT(A) + NTT(B)) != A + B");

            SymCryptMlDsaPolyElementMulR(peD);          // D = R * NTT(A)
            SymCryptMlDsaPolyElementMontMul(peD, peE, peF); // F = R * NTT(A) * NTT(B)
            SymCryptMlDsaPolyElementINTT(peF);

            testSymCryptMlDsaNaivePolyMul(peA, peB, peC);
            CHECK(testSymCryptMlDsaPolyElementEqual( peC, peF ), "Naive poly mul (A, B) != NTT poly mul (A, B)");
        }
    }

    SymCryptWipe(polyBuf, sizeof(SYMCRYPT_MLDSA_POLYELEMENT) * elementCount);
    SymCryptCallbackFree(polyBuf);

    // iprint("        ML-DSA polynomial arithmetic tests successful!\n");

}

VOID
testMlDsaMatrixVectorArithmetic()
{
    PCSYMCRYPT_MLDSA_INTERNAL_PARAMS pParams = &SymCryptMlDsaInternalParams44;

    const UINT32 polyCount = 5;
    UINT32 cbPolyBuf = sizeof(SYMCRYPT_MLDSA_POLYELEMENT) * polyCount;
    PBYTE polyBuf = (PBYTE) SymCryptCallbackAlloc(cbPolyBuf);
    CHECK( polyBuf != nullptr, "SymCryptCallbackAlloc failed\n" );

    PSYMCRYPT_MLDSA_POLYELEMENT peZero, peOne, peOneNttTimesR;
    PSYMCRYPT_MLDSA_POLYELEMENT peSrc, peDst;
    {
        PSYMCRYPT_MLDSA_POLYELEMENT peElements[polyCount];

        for(UINT32 i = 0; i < polyCount; ++i)
        {
            peElements[i] = SymCryptMlDsaPolyElementCreate(
                polyBuf + i * sizeof(SYMCRYPT_MLDSA_POLYELEMENT), sizeof(SYMCRYPT_MLDSA_POLYELEMENT));
            CHECK( peElements[i] != nullptr, "SymCryptMlDsaPolyElementCreate failed");
        }

        peZero = peElements[0];
        peOne = peElements[1];
        peOneNttTimesR = peElements[2];

        peSrc = peElements[3];
        peDst = peElements[4];

        SymCryptMlDsaPolyElementSetZero(peZero);

        SymCryptMlDsaPolyElementSetZero(peOne);

        for( UINT32 i = 0; i < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS; ++i )
        {
            peOne->coeffs[i] = 1;
        }

        SymCryptMlDsaPolyElementSetZero(peOneNttTimesR);
        
        peOneNttTimesR->coeffs[0] = 1;

        SymCryptMlDsaPolyElementNTT(peOneNttTimesR);
        SymCryptMlDsaPolyElementMulR(peOneNttTimesR);
    }

    const UINT32 vectorCount = 4;
    UINT32 cbVectorBuf = pParams->cbRowVector * vectorCount;
    PBYTE vectorBuf = (PBYTE) SymCryptCallbackAlloc(cbVectorBuf);
    CHECK( vectorBuf != nullptr, "SymCryptCallbackAlloc failed\n" );

    PSYMCRYPT_MLDSA_VECTOR pvZero, pvOne;
    PSYMCRYPT_MLDSA_VECTOR pvSrc, pvDst;
    {
        PSYMCRYPT_MLDSA_VECTOR pvVectors[vectorCount];

        for(int i = 0; i < vectorCount; ++i)
        {
            pvVectors[i] = SymCryptMlDsaVectorCreate(
                vectorBuf + i * pParams->cbRowVector,
                pParams->cbRowVector,
                pParams->nRows);
            CHECK( pvVectors[i] != nullptr, "SymCryptMlDsaVectorCreate failed");
        }

        pvZero = pvVectors[0];
        pvOne = pvVectors[1];

        pvSrc = pvVectors[2];
        pvDst = pvVectors[3];

        SymCryptMlDsaVectorSetZero(pvZero);

        SymCryptMlDsaVectorSetZero(pvOne);

        for(UINT32 i = 0; i < 4; ++i)
        {
            PSYMCRYPT_MLDSA_POLYELEMENT peTmp = SYMCRYPT_INTERNAL_MLDSA_VECTOR_ELEMENT( i, pvOne );
            memcpy( peTmp, peOneNttTimesR, SYMCRYPT_INTERNAL_MLDSA_SIZEOF_POLYELEMENT );
        }
    }

    UINT32 cbMatrixBuf = pParams->cbMatrix;
    PBYTE matrixBuf = (PBYTE) SymCryptCallbackAlloc(cbMatrixBuf);
    CHECK( matrixBuf != nullptr, "SymCryptCallbackAlloc failed\n" );

    SymCryptWipe( matrixBuf, cbMatrixBuf );

    PSYMCRYPT_MLDSA_MATRIX pmMatrix = SymCryptMlDsaMatrixCreate(
        matrixBuf, cbMatrixBuf, pParams->nRows, pParams->nCols);
    CHECK( pmMatrix != nullptr, "SymCryptMlDsaMatrixCreate failed");

    SymCryptMlDsaMatrixVectorMontMul(pmMatrix, pvZero, pvDst, peSrc);
    for(UINT32 i = 0; i < 4; ++i)
    {
        CHECK( testSymCryptMlDsaPolyElementEqual( SYMCRYPT_INTERNAL_MLDSA_VECTOR_ELEMENT(i, pvDst), peZero), "0 matrix * 0 vector != 0 vector");
    }

    SymCryptMlDsaMatrixVectorMontMul(pmMatrix, pvOne, pvDst, peSrc);
    for(UINT32 i = 0; i < 4; ++i)
    {
        CHECK( testSymCryptMlDsaPolyElementEqual( SYMCRYPT_INTERNAL_MLDSA_VECTOR_ELEMENT(i, pvDst), peZero), "0 matrix * 1 vector != 0 vector");
    }

    // Set matrix to identity matrix
    for(UINT32 i = 0; i < 4; ++i)
    {
        testSymCryptMlDsaMatrixSetElement(peOneNttTimesR, i, i, pmMatrix);
    }

    SymCryptMlDsaMatrixVectorMontMul(pmMatrix, pvZero, pvDst, peSrc);
    for(UINT32 i = 0; i < 4; ++i)
    {
        CHECK( testSymCryptMlDsaPolyElementEqual( SYMCRYPT_INTERNAL_MLDSA_VECTOR_ELEMENT(i, pvDst), peZero), "I matrix * 0 vector != 0 vector");
    }

    SymCryptMlDsaMatrixVectorMontMul(pmMatrix, pvOne, pvDst, peSrc);
    for(UINT32 i = 0; i < 4; ++i)
    {
        if(!testSymCryptMlDsaPolyElementEqual( SYMCRYPT_INTERNAL_MLDSA_VECTOR_ELEMENT(i, pvDst), peOneNttTimesR))
        {
            iprint("Source matrix:\n");
            printMatrix(pmMatrix);
            iprint("Source vector:\n");
            printVector(pvOne);
            iprint("Destination vector:\n");
            printVector(pvDst);
            CHECK(FALSE, "I matrix * 1 vector != 1 vector");
        }
    }

    SymCryptWipe(matrixBuf, cbMatrixBuf);
    SymCryptCallbackFree(matrixBuf);

    SymCryptWipe(vectorBuf, cbVectorBuf);
    SymCryptCallbackFree(vectorBuf);

    SymCryptWipe(polyBuf, cbPolyBuf);
    SymCryptCallbackFree(polyBuf);

    // iprint("        ML-DSA matrix/vector arithmetic tests successful!\n");
}

////////////////////////////////////////////////
// Multi-implementation testing
////////////////////////////////////////////////

class PqDsaMultiImp : public PqDsaImplementation
{
public:
    PqDsaMultiImp( String algName );
    ~PqDsaMultiImp();

private:
    PqDsaMultiImp( const PqDsaMultiImp & ) = delete;
    VOID operator=( const PqDsaMultiImp & ) = delete;

public:
    typedef std::vector<PqDsaImplementation *> ImpPtrVector;

    ImpPtrVector m_imps;    // Implementations being used
    ImpPtrVector m_comps;   // Subset of m_imps; set of ongoing computations

public:
    virtual NTSTATUS setKey(
        _In_                    PCPQDSAKEY_TESTBLOB pcKeyBlob ) override;

    virtual NTSTATUS getBlobFromKey(
                                UINT32              keyFormat,
        _Out_writes_( cbBlob )  PBYTE               pbBlob,
                                SIZE_T              cbBlob ) override;

    virtual NTSTATUS sign(
        _In_reads_bytes_( cbMessage )                       PCBYTE                  pbMessage,
                                                            SIZE_T                  cbMessage,
        _In_reads_bytes_opt_( cbContext )                   PCBYTE                  pbContext,
        _In_range_( 0, SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH )  SIZE_T                  cbContext,
        _Out_writes_bytes_( cbSignature )                   PBYTE                   pbSignature,
                                                            SIZE_T                  cbSignature ) override;

    virtual NTSTATUS signExternalMu(
        _In_reads_bytes_( cbMu )                            PCBYTE                  pbMu,
                                                            SIZE_T                  cbMu,
        _Out_writes_bytes_( cbSignature )                   PBYTE                   pbSignature,
                                                            SIZE_T                  cbSignature ) override;

    virtual NTSTATUS signHash(
                                                            SYMCRYPT_PQDSA_HASH_ID  hashId,
        _In_reads_bytes_( cbHash )                          PCBYTE                  pbHash,
                                                            SIZE_T                  cbHash,
        _In_reads_bytes_opt_( cbContext )                   PCBYTE                  pbContext,
        _In_range_( 0, SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH )  SIZE_T                  cbContext,
        _Out_writes_bytes_( cbSignature )                   PBYTE                   pbSignature,
                                                            SIZE_T                  cbSignature ) override;

    virtual NTSTATUS signEx(
                                                            SYMCRYPT_PQDSA_HASH_ID  hashId,
        _In_reads_bytes_( cbInput )                         PCBYTE                  pbInput,
                                                            SIZE_T                  cbInput,
        _In_reads_bytes_opt_( cbContext )                   PCBYTE                  pbContext,
        _In_range_( 0, SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH )  SIZE_T                  cbContext,
        _In_reads_bytes_( cbRandom )                        PCBYTE                  pbRandom,
                                                            SIZE_T                  cbRandom,
                                                            UINT32                  flags,
        _Out_writes_bytes_( cbSignature )                   PBYTE                   pbSignature,
                                                            SIZE_T                  cbSignature ) override;

    virtual NTSTATUS verify(
        _In_reads_bytes_( cbMessage )                       PCBYTE                  pbMessage,
                                                            SIZE_T                  cbMessage,
        _In_reads_bytes_opt_( cbContext )                   PCBYTE                  pbContext,
        _In_range_( 0, SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH )  SIZE_T                  cbContext,
        _In_reads_bytes_( cbSignature )                     PCBYTE                  pbSignature,
                                                            SIZE_T                  cbSignature ) override;

    virtual NTSTATUS verifyExternalMu(
        _In_reads_bytes_( cbMu )                            PCBYTE                  pbMu,
                                                            SIZE_T                  cbMu,
        _In_reads_bytes_( cbSignature )                     PCBYTE                  pbSignature,
                                                            SIZE_T                  cbSignature ) override;

    virtual NTSTATUS verifyHash(
                                                            SYMCRYPT_PQDSA_HASH_ID  hashId,
        _In_reads_bytes_( cbHash )                          PCBYTE                  pbHash,
                                                            SIZE_T                  cbHash,
        _In_reads_bytes_opt_( cbContext )                   PCBYTE                  pbContext,
        _In_range_( 0, SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH )  SIZE_T                  cbContext,
        _In_reads_bytes_( cbSignature )                     PCBYTE                  pbSignature,
                                                            SIZE_T                  cbSignature ) override;
};

PqDsaMultiImp::PqDsaMultiImp( String algName )
{
    m_algorithmName = algName;

    getAllImplementations<PqDsaImplementation>( algName, &m_imps );
}

PqDsaMultiImp::~PqDsaMultiImp()
{
    //
    // Propagate the # KAT failures to the individual algorithms.
    //
    for( auto i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        (*i)->m_nErrorKatFailure += m_nErrorKatFailure;
    }
}

_Use_decl_annotations_
NTSTATUS
PqDsaMultiImp::setKey(
    PCPQDSAKEY_TESTBLOB pcKeyBlob )
{
    m_comps.clear();

    for( auto i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        if( NT_SUCCESS( (*i)->setKey( pcKeyBlob ) ) )
        {
            m_comps.push_back( *i );
        }
    }

    return m_comps.size() == 0 ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PqDsaMultiImp::getBlobFromKey(
    UINT32  keyFormat,
    PBYTE   pbBlob,
    SIZE_T  cbBlob )
{
    BYTE abBlob[SYMCRYPT_TEST_MLDSA_MAX_KEY_SIZE + 1];
    ResultMerge resAgreedKey;
    NTSTATUS status;

    CHECK( cbBlob < sizeof(abBlob), "Buffer too small" );

    for( auto i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memset( abBlob, 'b', cbBlob + 1 );
        status = (*i)->getBlobFromKey( keyFormat, abBlob, cbBlob );
        CHECK( (status == STATUS_SUCCESS) || (status == STATUS_NOT_SUPPORTED), "Failed to get ML-DSA key blob" );
        CHECK( abBlob[cbBlob] == 'b', "Buffer overflow" );

        if( NT_SUCCESS( status ) )
        {
            resAgreedKey.addResult( (*i), abBlob, cbBlob );
        }
    }

    resAgreedKey.getResult( pbBlob, cbBlob );

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PqDsaMultiImp::sign(
    PCBYTE  pbMessage,
    SIZE_T  cbMessage,
    PCBYTE  pbContext,
    SIZE_T  cbContext,
    PBYTE   pbSignature,
    SIZE_T  cbSignature )
{
    // Signing is not deterministic, so we do the following:
    // - Have every implementation sign
    // - Have every implementation verify each signature
    // - Return a random signature
    NTSTATUS status;
    BYTE abSignature[SYMCRYPT_TEST_MLDSA_MAX_SIG_SIZE + 1];
    UINT32 nSignatures = 0;

    CHECK( cbSignature < sizeof(abSignature), "Buffer too small" );

    for( auto i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memset( abSignature, 'b', cbSignature + 1 );
        status = (*i)->sign( pbMessage, cbMessage, pbContext, cbContext, abSignature, cbSignature );
        CHECK( NT_SUCCESS(status), "ML-DSA sign failed" );
        CHECK( abSignature[cbSignature] == 'b', "Buffer overflow" );

        for( auto j = m_comps.begin(); j != m_comps.end(); ++j )
        {
            status = (*j)->verify( pbMessage, cbMessage, pbContext, cbContext, abSignature, cbSignature );
            CHECK4( NT_SUCCESS(status), "ML-DSA sign -> verify failed %s, %s",
                (*i)->m_implementationName.c_str(),
                (*j)->m_implementationName.c_str() );
        }

        // Copy a random signature to the output
        // Note: the first iteration will always copy since anything % 1 == 0
        nSignatures++;
        if( g_rng.byte() % nSignatures == 0 )
        {
            memcpy( pbSignature, abSignature, cbSignature );
        }
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PqDsaMultiImp::signExternalMu(
    PCBYTE  pbMu,
    SIZE_T  cbMu,
    PBYTE   pbSignature,
    SIZE_T  cbSignature )
{
    // Signing is not deterministic, so we do the following:
    // - Have every implementation sign
    // - Have every implementation verify each signature
    // - Return a random signature
    NTSTATUS status;
    BYTE abSignature[SYMCRYPT_TEST_MLDSA_MAX_SIG_SIZE + 1];
    UINT32 nSignatures = 0;

    CHECK( cbSignature < sizeof(abSignature), "Buffer too small" );

    for( auto i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memset( abSignature, 'b', cbSignature + 1 );
        status = (*i)->signExternalMu( pbMu, cbMu, abSignature, cbSignature );
        CHECK3( NT_SUCCESS(status), "ExternalMu-ML-DSA sign failed %s",
            (*i)->m_implementationName.c_str() );
        CHECK( abSignature[cbSignature] == 'b', "Buffer overflow" );

        for( auto j = m_comps.begin(); j != m_comps.end(); ++j )
        {
            status = (*j)->verifyExternalMu( pbMu, cbMu, abSignature, cbSignature );
            CHECK4( NT_SUCCESS(status), "ExternalMu-ML-DSA verify failed %s, %s",
                (*i)->m_implementationName.c_str(),
                (*j)->m_implementationName.c_str() );
        }

        // Copy a random signature to the output
        // Note: the first iteration will always copy since anything % 1 == 0
        nSignatures++;
        if( g_rng.byte() % nSignatures == 0 )
        {
            memcpy( pbSignature, abSignature, cbSignature );
        }
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PqDsaMultiImp::signHash(
    SYMCRYPT_PQDSA_HASH_ID  hashId,
    PCBYTE                  pbHash,
    SIZE_T                  cbHash,
    PCBYTE                  pbContext,
    SIZE_T                  cbContext,
    PBYTE                   pbSignature,
    SIZE_T                  cbSignature )
{
    // As above, we cross-validate results since signing is not deterministic
    NTSTATUS status;
    BYTE abSignature[SYMCRYPT_TEST_MLDSA_MAX_SIG_SIZE + 1];
    UINT32 nSignatures = 0;

    CHECK( cbSignature < sizeof(abSignature), "Buffer too small" );

    for( auto i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memset( abSignature, 'b', cbSignature + 1 );
        status = (*i)->signHash( hashId, pbHash, cbHash, pbContext, cbContext, abSignature, cbSignature );
        CHECK( NT_SUCCESS(status), "HashML-DSA sign failed" );
        CHECK( abSignature[cbSignature] == 'b', "Buffer overflow" );

        for( auto j = m_comps.begin(); j != m_comps.end(); ++j )
        {
            status = (*j)->verifyHash( hashId, pbHash, cbHash, pbContext, cbContext, abSignature, cbSignature );
            CHECK4( NT_SUCCESS(status), "HashML-DSA sign -> verify failed %s, %s",
                (*i)->m_implementationName.c_str(),
                (*j)->m_implementationName.c_str() );
        }

        // Copy a random signature to the output
        // Note: the first iteration will always copy since anything % 1 == 0
        nSignatures++;
        if( g_rng.byte() % nSignatures == 0 )
        {
            memcpy( pbSignature, abSignature, cbSignature );
        }
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PqDsaMultiImp::signEx(
    SYMCRYPT_PQDSA_HASH_ID  hashId,
    PCBYTE                  pbInput,
    SIZE_T                  cbInput,
    PCBYTE                  pbContext,
    SIZE_T                  cbContext,
    PCBYTE                  pbRandom,
    SIZE_T                  cbRandom,
    UINT32                  flags,
    PBYTE                   pbSignature,
    SIZE_T                  cbSignature )
{
    // SignEx _is_ deterministic since it takes a caller-provided random value, so no need to
    // cross-validate here
    NTSTATUS status;
    BYTE abSignature[SYMCRYPT_TEST_MLDSA_MAX_SIG_SIZE + 1];
    ResultMerge resAgreedSignature;

    CHECK( cbSignature < sizeof(abSignature), "Buffer too small" );

    for( auto i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        memset( abSignature, 'b', cbSignature + 1 );
        status = (*i)->signEx(
            hashId,
            pbInput, cbInput,
            pbContext, cbContext,
            pbRandom, cbRandom,
            flags,
            abSignature, cbSignature );
        CHECK( abSignature[cbSignature] == 'b', "Buffer overflow" );

        if( status == STATUS_NOT_SUPPORTED )
        {
            continue;
        }

        CHECK( NT_SUCCESS(status), "ML-DSA SignEx failed" );

        resAgreedSignature.addResult( (*i), abSignature, cbSignature );
    }

    resAgreedSignature.getResult( pbSignature, cbSignature );

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PqDsaMultiImp::verify(
    PCBYTE pbMessage,
    SIZE_T cbMessage,
    PCBYTE pbContext,
    SIZE_T cbContext,
    PCBYTE pbSignature,
    SIZE_T cbSignature )
{
    ResultMerge resStatus;
    NTSTATUS status;
    BYTE statusBuffer[4];

    for( auto i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        status = (*i)->verify( pbMessage, cbMessage, pbContext, cbContext, pbSignature, cbSignature );

        // Store status as MSBfirst array to get errors to print correctly.
        SYMCRYPT_STORE_MSBFIRST32( statusBuffer, status );
        resStatus.addResult( (*i), statusBuffer, sizeof(statusBuffer) );
    }

    resStatus.getResult( statusBuffer, sizeof(statusBuffer), FALSE );
    status = SYMCRYPT_LOAD_MSBFIRST32( statusBuffer );

    return status;
}

_Use_decl_annotations_
NTSTATUS
PqDsaMultiImp::verifyExternalMu(
    PCBYTE pbMu,
    SIZE_T cbMu,
    PCBYTE pbSignature,
    SIZE_T cbSignature )
{
    ResultMerge resStatus;
    NTSTATUS status;
    BYTE statusBuffer[4];

    for( auto i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        status = (*i)->verifyExternalMu( pbMu, cbMu, pbSignature, cbSignature );

        // Store status as MSBfirst array to get errors to print correctly.
        SYMCRYPT_STORE_MSBFIRST32( statusBuffer, status );
        resStatus.addResult( (*i), statusBuffer, sizeof(statusBuffer) );
    }

    resStatus.getResult( statusBuffer, sizeof(statusBuffer), FALSE );
    status = SYMCRYPT_LOAD_MSBFIRST32( statusBuffer );

    return status;
}

_Use_decl_annotations_
NTSTATUS
PqDsaMultiImp::verifyHash(
    SYMCRYPT_PQDSA_HASH_ID  hashId,
    PCBYTE                  pbHash,
    SIZE_T                  cbHash,
    PCBYTE                  pbContext,
    SIZE_T                  cbContext,
    PCBYTE                  pbSignature,
    SIZE_T                  cbSignature )
{
    ResultMerge resStatus;
    NTSTATUS status;
    BYTE statusBuffer[4];

    for( auto i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        status = (*i)->verifyHash( hashId, pbHash, cbHash, pbContext, cbContext, pbSignature, cbSignature );

        // Store status as MSBfirst array to get errors to print correctly.
        SYMCRYPT_STORE_MSBFIRST32( statusBuffer, status );
        resStatus.addResult( (*i), statusBuffer, sizeof(statusBuffer) );
    }

    resStatus.getResult( statusBuffer, sizeof(statusBuffer), FALSE );
    status = SYMCRYPT_LOAD_MSBFIRST32( statusBuffer );

    return status;
}

VOID
testMlDsaRandom()
{
    constexpr SIZE_T cbMessageMax = 1024;

    NTSTATUS status = STATUS_SUCCESS;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    auto pMlDsaImp = std::make_unique<PqDsaMultiImp>("MlDsa");

    SIZE_T cbSignature;
    std::vector<BYTE> signature;
    std::vector<BYTE> signature2;
    std::vector<BYTE> muSignature;
    std::vector<BYTE> hashSignature;

    std::vector<BYTE> message( cbMessageMax );
    std::vector<BYTE> context( SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH );

    std::array<BYTE, SYMCRYPT_SHA512_RESULT_SIZE> hash;
    std::array<BYTE, SYMCRYPT_SHAKE256_RESULT_SIZE> mu;

    MLDSAKEY_TESTBLOB keyTestBlobFull{};
    MLDSAKEY_TESTBLOB keyTestBlobPriv{};
    MLDSAKEY_TESTBLOB keyTestBlobPub{};

    keyTestBlobFull.format = SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED;
    keyTestBlobPriv.format = SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY;
    keyTestBlobPub.format = SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY;

    // PqDsaImp functions take PQDSAKEY_TESTBLOB pointers, but we use MLDSAKEY_TESTBLOBs for
    // brevity; assert that the latter is a union member of the former.
    C_ASSERT( offsetof( PQDSAKEY_TESTBLOB, mlDsakey ) == 0 );

    PQDSAKEY_TESTBLOB* pKeyTestBlobFull = reinterpret_cast<PQDSAKEY_TESTBLOB*>(&keyTestBlobFull);
    PQDSAKEY_TESTBLOB* pKeyTestBlobPriv = reinterpret_cast<PQDSAKEY_TESTBLOB*>(&keyTestBlobPriv);
    PQDSAKEY_TESTBLOB* pKeyTestBlobPub = reinterpret_cast<PQDSAKEY_TESTBLOB*>(&keyTestBlobPub);

    for( SYMCRYPT_TEST_MLDSA_PARAMS testParams : rgTestMlDsaParams )
    {
        SYMCRYPT_MLDSA_PARAMS params = testParams.params;

        keyTestBlobFull.params = params;
        keyTestBlobPriv.params = params;
        keyTestBlobPub.params = params;

        scError = SymCryptMlDsaSizeofSignatureFromParams( params, &cbSignature );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Failed to get signature size" );

        signature.resize( cbSignature );
        signature2.resize( cbSignature );
        muSignature.resize( cbSignature );
        hashSignature.resize( cbSignature );

        scError = SymCryptMlDsaSizeofKeyFormatFromParams( params, keyTestBlobFull.format, &keyTestBlobFull.cbKeyBlob );
        CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptMlDsaSizeofKeyFormatFromParams SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED failed with 0x%x", scError );
        CHECK( keyTestBlobFull.cbKeyBlob <= sizeof(keyTestBlobFull.abKeyBlob), "SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED size too large" );

        scError = SymCryptMlDsaSizeofKeyFormatFromParams( params, keyTestBlobPriv.format, &keyTestBlobPriv.cbKeyBlob );
        CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptMlDsaSizeofKeyFormatFromParams SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY failed with 0x%x", scError );
        CHECK( keyTestBlobFull.cbKeyBlob <= sizeof(keyTestBlobPriv.abKeyBlob), "SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY size too large" )

        scError = SymCryptMlDsaSizeofKeyFormatFromParams( params, keyTestBlobPub.format, &keyTestBlobPub.cbKeyBlob );
        CHECK3( scError == SYMCRYPT_NO_ERROR, "SymCryptMlDsaSizeofKeyFormatFromParams SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY failed with 0x%x", scError );
        CHECK( keyTestBlobFull.cbKeyBlob <= sizeof(keyTestBlobPub.abKeyBlob), "SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY size too large" )

        for( UINT32 i = 0; i < 100; i++ )
        {
            GENRANDOM( keyTestBlobFull.abKeyBlob, (UINT32) keyTestBlobFull.cbKeyBlob );

            //
            // Tests with full key from private seed
            //
            status = pMlDsaImp->setKey( pKeyTestBlobFull );
            CHECK( NT_SUCCESS( status ), "Failed to set key" );

            status = pMlDsaImp->getBlobFromKey( SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY, keyTestBlobPriv.abKeyBlob, keyTestBlobPriv.cbKeyBlob );
            CHECK( NT_SUCCESS( status ), "Failed to get private key" );

            status = pMlDsaImp->getBlobFromKey( SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY, keyTestBlobPub.abKeyBlob, keyTestBlobPub.cbKeyBlob );
            CHECK( NT_SUCCESS( status ), "Failed to get public key" );

            // Generate a random message to sign
            message.resize( g_rng.sizet( cbMessageMax + 1 ) );
            GENRANDOM( message.data(), (UINT32) message.size() );

            // Generate a random context
            context.resize( g_rng.byte() );
            GENRANDOM( context.data(), (UINT32) context.size() );

            // Hash the message for HashML-DSA signing
            SymCryptSha512( message.data(), message.size(), hash.data() );

            // Pre-hash the message representative for External Mu signing
            {
                SYMCRYPT_SHAKE256_STATE shake256State;
                UINT8 modeId = 0; // 0 for pure ML-DSA
                UINT8 cbContextByte = (UINT8) context.size();
                std::array<BYTE, SYMCRYPT_SHAKE256_RESULT_SIZE> pkHash;

                SymCryptShake256Default( keyTestBlobPub.abKeyBlob, keyTestBlobPub.cbKeyBlob, pkHash.data() );

                SymCryptShake256Init( &shake256State );
                SymCryptShake256Append( &shake256State, pkHash.data(), pkHash.size() );
                SymCryptShake256Append( &shake256State, &modeId, sizeof( modeId ) );
                SymCryptShake256Append( &shake256State, &cbContextByte, sizeof( cbContextByte ) );
                SymCryptShake256Append( &shake256State, context.data(), context.size() );
                SymCryptShake256Append( &shake256State, NULL, 0 ); // pbHashOid, cbHashOid
                SymCryptShake256Append( &shake256State, message.data(), message.size() );
                SymCryptShake256Result( &shake256State, mu.data() );
            }

            status = pMlDsaImp->sign(
                message.data(), message.size(),
                context.data(), context.size(),
                signature.data(), signature.size() );
            CHECK( NT_SUCCESS( status ), "Failed to sign" );

            status = pMlDsaImp->verify(
                message.data(), message.size(),
                context.data(), context.size(),
                signature.data(), signature.size() );
            CHECK( NT_SUCCESS( status ), "Failed to verify with full key" );

            status = pMlDsaImp->signExternalMu(
                mu.data(), mu.size(),
                muSignature.data(), muSignature.size() );
            CHECK( NT_SUCCESS( status ), "Failed to sign External Mu" );

            status = pMlDsaImp->verify(
                message.data(), message.size(),
                context.data(), context.size(),
                muSignature.data(), muSignature.size() );
            CHECK( NT_SUCCESS( status ), "Failed to verify External Mu with full key" );

            status = pMlDsaImp->verifyExternalMu(
                mu.data(), mu.size(),
                muSignature.data(), muSignature.size() );
            CHECK( NT_SUCCESS( status ), "Failed to verify External Mu with full key" );

            status = pMlDsaImp->signHash(
                SYMCRYPT_PQDSA_HASH_ID_SHA512,
                hash.data(), hash.size(),
                context.data(), context.size(),
                hashSignature.data(), hashSignature.size() );
            CHECK( NT_SUCCESS( status ), "Failed to sign hash" );

            status = pMlDsaImp->verifyHash(
                SYMCRYPT_PQDSA_HASH_ID_SHA512,
                hash.data(), hash.size(),
                context.data(), context.size(),
                hashSignature.data(), hashSignature.size() );
            CHECK( NT_SUCCESS( status ), "Failed to verify hash with full key" );

            //
            // Tests with key from private key blob (same as full key, but missing private seed)
            //
            status = pMlDsaImp->setKey( pKeyTestBlobPriv );
            CHECK( NT_SUCCESS( status ), "Failed to set private key" );

            status = pMlDsaImp->sign(
                message.data(), message.size(),
                context.data(), context.size(),
                signature2.data(), signature2.size() );
            CHECK( NT_SUCCESS( status ), "Failed to sign with private key" );

            status = pMlDsaImp->verify(
                message.data(), message.size(),
                context.data(), context.size(),
                signature.data(), signature.size() );
            CHECK( NT_SUCCESS( status ), "Failed to verify with private key" );

            status = pMlDsaImp->verify(
                message.data(), message.size(),
                context.data(), context.size(),
                muSignature.data(), muSignature.size() );
            CHECK( NT_SUCCESS( status ), "Failed to verify External Mu with private key" );

            status = pMlDsaImp->verifyExternalMu(
                mu.data(), mu.size(),
                muSignature.data(), muSignature.size() );
            CHECK( NT_SUCCESS( status ), "Failed to verify External Mu with private key" );

            status = pMlDsaImp->verifyHash(
                SYMCRYPT_PQDSA_HASH_ID_SHA512,
                hash.data(), hash.size(),
                context.data(), context.size(),
                hashSignature.data(), hashSignature.size() );
            CHECK( NT_SUCCESS( status ), "Failed to verify hash with private key" );

            //
            // Tests with public key only
            //
            status = pMlDsaImp->setKey( pKeyTestBlobPub );
            CHECK( NT_SUCCESS( status ), "Failed to set public key" );

            status = pMlDsaImp->verify(
                message.data(), message.size(),
                context.data(), context.size(),
                signature.data(), signature.size() );
            CHECK( NT_SUCCESS( status ), "Failed to verify with public key" );

            status = pMlDsaImp->verify(
                message.data(), message.size(),
                context.data(), context.size(),
                muSignature.data(), muSignature.size() );
            CHECK( NT_SUCCESS( status ), "Failed to verify External Mu with public key" );

            status = pMlDsaImp->verifyExternalMu(
                mu.data(), mu.size(),
                muSignature.data(), muSignature.size() );
            CHECK( NT_SUCCESS( status ), "Failed to verify External Mu with public key" );

            status = pMlDsaImp->verifyHash(
                SYMCRYPT_PQDSA_HASH_ID_SHA512,
                hash.data(), hash.size(),
                context.data(), context.size(),
                hashSignature.data(), hashSignature.size() );
            CHECK( NT_SUCCESS( status ), "Failed to verify hash with public key" );

            // Modify the signature and ensure that verification fails
            UINT32 t = g_rng.uint32();
            signature[ (t/8) % signature.size() ] ^= 1 << (t%8);
            muSignature[ (t/8) % muSignature.size() ] ^= 1 << (t%8);
            hashSignature[ (t/8) % hashSignature.size() ] ^= 1 << (t%8);

            status = pMlDsaImp->verify(
                message.data(), message.size(),
                context.data(), context.size(),
                signature.data(), signature.size() );
            CHECK( status == STATUS_INVALID_SIGNATURE, "Tampered signature verified successfully?" );

            status = pMlDsaImp->verify(
                message.data(), message.size(),
                context.data(), context.size(),
                muSignature.data(), muSignature.size() );
            CHECK( status == STATUS_INVALID_SIGNATURE, "Tampered External Mu signature verified successfully?" );

            status = pMlDsaImp->verifyExternalMu(
                mu.data(), mu.size(),
                muSignature.data(), muSignature.size() );
            CHECK( status == STATUS_INVALID_SIGNATURE, "Tampered External Mu signature verified successfully?" );

            status = pMlDsaImp->verifyHash(
                SYMCRYPT_PQDSA_HASH_ID_SHA512,
                hash.data(), hash.size(),
                context.data(), context.size(),
                hashSignature.data(), hashSignature.size() );
            CHECK( status == STATUS_INVALID_SIGNATURE, "Tampered hash signature verified successfully?" );
        }
    }

    status = pMlDsaImp->setKey( nullptr );
    CHECK( NT_SUCCESS( status ), "Failed to free key" );
}

VOID
testMlDsaNegative()
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PSYMCRYPT_MLDSAKEY pKey = nullptr;
    PCSYMCRYPT_MLDSA_INTERNAL_PARAMS pParams = &SymCryptMlDsaInternalParams44;
    std::vector<BYTE> privateKeyBlob( pParams->cbEncodedPrivateKey );
    std::vector<BYTE> signature( pParams->cbEncodedSignature );

    pKey = SymCryptMlDsakeyAllocate( SYMCRYPT_MLDSA_PARAMS_MLDSA44 );
    CHECK( pKey != nullptr, "Failed to allocate key" );

    scError = SymCryptMlDsakeyGenerate( pKey, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Failed to generate key" );

    // Generate a signature to tamper with and verify that it fails verification
    // Tampered signature verification is also tested in testMlDsaRandom, but here we're testing
    // a specific case of modifying the signature such that the infinity norm is invalid
    // Note: signing an empty message is valid
    scError = SymCryptMlDsaSign(
        pKey,
        nullptr, 0, // (pbMessage, cbMessage)
        nullptr, 0, // (pbContext, cbContext)
        0, // flags
        signature.data(),
        signature.size() );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Failed to sign" );

    // Modify the signature to have an invalid response infinity norm (>= gamma_1 - beta).
    // But note that coefficients in the response vector are encoded in 18 bits, then mapped to a
    // signed 32-bit integer in the range [-gamma_1 + 1, gamma_1]. The mapping from signed to
    // unsigned is (gamma_1 - value). So the encoded value we want to set is
    // (gamma_1 - (gamma_1 - beta)) = beta = (nChallengeNonZeroCoeffs * privateKeyRange)
    const UINT32 badInfinityNorm = (UINT32) pParams->nChallengeNonZeroCoeffs * pParams->privateKeyRange;

    UINT32 newVal = SYMCRYPT_LOAD_LSBFIRST32( signature.data() + pParams->cbCommitmentHash );
    newVal &= ~((1 << (pParams->maskCoefficientRangeLog2 + 1)) - 1);
    newVal |= badInfinityNorm;
    SYMCRYPT_STORE_LSBFIRST32( signature.data() + pParams->cbCommitmentHash, newVal );

    scError = SymCryptMlDsaVerify(
        pKey,
        nullptr, 0, // (pbMessage, cbMessage)
        nullptr, 0, // (pbContext, cbContext)
        signature.data(),
        signature.size(),
        0 ); // flags
    CHECK( scError == SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE, "Invalid signature verified successfully" );

    // Test tampering with the encoded private key and verify that it fails import
    scError = SymCryptMlDsakeyGetValue(
        pKey,
        privateKeyBlob.data(),
        privateKeyBlob.size(),
        SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY,
        0 ); // flags
    CHECK( scError == SYMCRYPT_NO_ERROR, "Failed to get private key" );

    // The private key format is:
    // Public seed rho  (32 bytes) || Private signing seed K (32 bytes) || Public key hash tr (64 bytes) || s1 || s2 || t0
    // For ML-DSA-44, the s1 and s2 vectors 4 polynomials long where each polynomial has 256
    // coefficients, and each coefficient is encoded in 3 bits. Thus, the total encoded length of
    // the vectors is (256 coefficients * 3 bits per coefficient * 8 polynomials / 8 bits per byte).
    // Encoded coefficients are in the range [0, 4]; any greater value is invalid. We'll set some
    // of the coefficients to an invalid value, which should cause an error on import.
    const SIZE_T offset = 
        SYMCRYPT_MLDSA_PUBLIC_SEED_SIZE +
        SYMCRYPT_MLDSA_PRIVATE_SIGNING_SEED_SIZE +
        SYMCRYPT_MLDSA_PUBLIC_KEY_HASH_SIZE +
        g_rng.uint32() % ( SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS * 3 );

    privateKeyBlob[offset] = 0xFF;

    scError = SymCryptMlDsakeySetValue(
        privateKeyBlob.data(),
        privateKeyBlob.size(),
        SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY,
        0, // flags
        pKey );
    CHECK( scError == SYMCRYPT_INVALID_BLOB, "Imported invalid private key" );

    SymCryptMlDsakeyFree( pKey );
}

VOID
testMlDsaKeyGen(
    PqDsaImplementation* pPqDsaImplementation,
    SYMCRYPT_MLDSA_PARAMS params,
    const BString& katSeed,
    const BString& katPubKey,
    const BString& katPrivKey,
    ULONGLONG line)
{
    NTSTATUS status = STATUS_SUCCESS;
    PQDSAKEY_TESTBLOB keyBlob{};
    SIZE_T cbPubKey = 0;
    SIZE_T cbPrivKey = 0;

    CHECK(
        SymCryptMlDsaSizeofKeyFormatFromParams(params, SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY, &cbPubKey) == SYMCRYPT_NO_ERROR,
        "Failed to get expected public key size" );

    CHECK(
        SymCryptMlDsaSizeofKeyFormatFromParams(params, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY, &cbPrivKey) == SYMCRYPT_NO_ERROR,
        "Failed to get expected private key size" );

    CHECK4( katSeed.size() == SYMCRYPT_MLDSA_ROOT_SEED_SIZE, "Invalid seed size %lld at line %lld", katSeed.size(), line );
    CHECK4( katPubKey.size() == cbPubKey, "Invalid public key size %lld at line %lld", katPubKey.size(), line );
    CHECK4( katPrivKey.size() == cbPrivKey, "Invalid private key size %lld at line %lld", katPrivKey.size(), line );

    keyBlob.mlDsakey.params = params;
    keyBlob.mlDsakey.format = SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED;
    keyBlob.mlDsakey.cbKeyBlob = katSeed.size();
    memcpy(keyBlob.mlDsakey.abKeyBlob, katSeed.data(), katSeed.size());

    status = pPqDsaImplementation->setKey( &keyBlob );
    CHECK3( NT_SUCCESS( status ), "Failed to set key at line %lld", line );

    std::vector<BYTE> pubKey(cbPubKey);
    std::vector<BYTE> privKey(cbPrivKey);

    status = pPqDsaImplementation->getBlobFromKey( SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY, pubKey.data(), cbPubKey );
    CHECK3( NT_SUCCESS( status ), "Failed to get public key at line %lld", line );
    CHECK3( memcmp( pubKey.data(), katPubKey.data(), cbPubKey ) == 0, "Public key mismatch at line %lld", line );

    status = pPqDsaImplementation->getBlobFromKey( SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY, privKey.data(), cbPrivKey );
    CHECK3( NT_SUCCESS( status ), "Failed to get private key at line %lld", line );
    CHECK3( memcmp( privKey.data(), katPrivKey.data(), cbPrivKey ) == 0, "Private key mismatch at line %lld", line );

    status = pPqDsaImplementation->setKey( nullptr );
    CHECK( NT_SUCCESS(status), "Failed to free key" );
    
}

VOID
testMlDsaSignVerify(
    PqDsaImplementation* pPqDsaImplementation,
    SYMCRYPT_MLDSA_PARAMS params,
    const BString& katRnd,
    const BString& katPrivKey,
    const BString& katPubKey,
    const BString& katMsg,
    const BString& katSig,
    const BString& katCtx,
    ULONGLONG line)
{
    NTSTATUS status = STATUS_SUCCESS;
    PQDSAKEY_TESTBLOB keyBlob{};
    SIZE_T cbPrivKey = 0;
    SIZE_T cbPubKey = 0;
    SIZE_T cbSig = 0;

    CHECK(
        SymCryptMlDsaSizeofKeyFormatFromParams(params, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY, &cbPrivKey) == SYMCRYPT_NO_ERROR,
        "Failed to get expected private key size" );

    CHECK(
        SymCryptMlDsaSizeofKeyFormatFromParams(params, SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY, &cbPubKey) == SYMCRYPT_NO_ERROR,
        "Failed to get expected public key size" );

    CHECK(
        SymCryptMlDsaSizeofSignatureFromParams(params, &cbSig) == SYMCRYPT_NO_ERROR,
        "Failed to get expected signature size" );

    CHECK4( katPrivKey.size() == cbPrivKey, "Invalid private key size %lld at line %lld", katPrivKey.size(), line );
    CHECK4( katPubKey.size() == cbPubKey, "Invalid public key size %lld at line %lld", katPubKey.size(), line );
    CHECK4( katRnd.size() == SYMCRYPT_MLDSA_SIGNING_RANDOM_SIZE, "Invalid random size %lld at line %lld", katRnd.size(), line );
    CHECK4( katCtx.size() <= SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH, "Invalid context size %lld at line %lld", katCtx.size(), line );
    CHECK4( katSig.size() == cbSig, "Invalid signature size %lld at line %lld", katSig.size(), line );

    keyBlob.mlDsakey.params = params;
    keyBlob.mlDsakey.format = SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY;
    keyBlob.mlDsakey.cbKeyBlob = katPrivKey.size();
    memcpy(keyBlob.mlDsakey.abKeyBlob, katPrivKey.data(), katPrivKey.size());

    status = pPqDsaImplementation->setKey( &keyBlob );
    CHECK3( NT_SUCCESS( status ), "Failed to set private key at line %lld", line );

    std::vector<BYTE> signature(cbSig);

    status = pPqDsaImplementation->signEx(
        SYMCRYPT_PQDSA_HASH_ID_NULL,
        katMsg.data(),
        katMsg.size(),
        katCtx.data(),
        katCtx.size(),
        katRnd.data(),
        katRnd.size(),
        0, // flags
        signature.data(),
        signature.size() );
    CHECK3( NT_SUCCESS( status ), "Signing failed at line %lld", line );
    CHECK3( memcmp( signature.data(), katSig.data(), cbSig ) == 0, "Signature mismatch at line %lld", line );

    // Reset the key so that we can use the public key for verification
    keyBlob.mlDsakey.format = SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY;
    keyBlob.mlDsakey.cbKeyBlob = katPubKey.size();
    memcpy(keyBlob.mlDsakey.abKeyBlob, katPubKey.data(), katPubKey.size());

    status = pPqDsaImplementation->setKey( &keyBlob );
    CHECK3( NT_SUCCESS( status ), "Failed to set public key at line %lld", line );

    status = pPqDsaImplementation->verify(
        katMsg.data(),
        katMsg.size(),
        katCtx.data(),
        katCtx.size(),
        signature.data(),
        signature.size() );
    CHECK3( NT_SUCCESS( status ), "Verification failed at line %lld", line );

    status = pPqDsaImplementation->setKey( nullptr );
    CHECK( NT_SUCCESS(status), "Failed to free key" );
}

VOID
testExternalMuMlDsaSignVerify(
    PqDsaImplementation* pPqDsaImplementation,
    SYMCRYPT_MLDSA_PARAMS params,
    const BString& katRnd,
    const BString& katPrivKey,
    const BString& katPubKey,
    const BString& katMu,
    const BString& katSig,
    ULONGLONG line)
{
    NTSTATUS status = STATUS_SUCCESS;
    PQDSAKEY_TESTBLOB keyBlob{};
    SIZE_T cbPrivKey = 0;
    SIZE_T cbPubKey = 0;
    SIZE_T cbSig = 0;

    CHECK(
        SymCryptMlDsaSizeofKeyFormatFromParams(params, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY, &cbPrivKey) == SYMCRYPT_NO_ERROR,
        "Failed to get expected private key size" );

    CHECK(
        SymCryptMlDsaSizeofKeyFormatFromParams(params, SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY, &cbPubKey) == SYMCRYPT_NO_ERROR,
        "Failed to get expected public key size" );

    CHECK(
        SymCryptMlDsaSizeofSignatureFromParams(params, &cbSig) == SYMCRYPT_NO_ERROR,
        "Failed to get expected signature size" );

    CHECK4( katPrivKey.size() == cbPrivKey, "Invalid private key size %lld at line %lld", katPrivKey.size(), line );
    CHECK4( katPubKey.size() == cbPubKey, "Invalid public key size %lld at line %lld", katPubKey.size(), line );
    CHECK4( katRnd.size() == SYMCRYPT_MLDSA_SIGNING_RANDOM_SIZE, "Invalid random size %lld at line %lld", katRnd.size(), line );
    CHECK4( katMu.size() == SYMCRYPT_SHAKE256_RESULT_SIZE, "Invalid mu size %lld at line %lld", katMu.size(), line );
    CHECK4( katSig.size() == cbSig, "Invalid signature size %lld at line %lld", katSig.size(), line );

    keyBlob.mlDsakey.params = params;
    keyBlob.mlDsakey.format = SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY;
    keyBlob.mlDsakey.cbKeyBlob = katPrivKey.size();
    memcpy(keyBlob.mlDsakey.abKeyBlob, katPrivKey.data(), katPrivKey.size());

    status = pPqDsaImplementation->setKey( &keyBlob );
    CHECK3( NT_SUCCESS( status ), "Failed to set private key at line %lld", line );

    std::vector<BYTE> signature(cbSig);

    status = pPqDsaImplementation->signEx(
        SYMCRYPT_PQDSA_HASH_ID_NULL,
        katMu.data(),
        katMu.size(),
        NULL,
        0,
        katRnd.data(),
        katRnd.size(),
        SYMCRYPT_FLAG_MLDSA_EXTERNALMU,
        signature.data(),
        signature.size() );

    CHECK3( NT_SUCCESS( status ), "Signing failed at line %lld", line );
    CHECK3( memcmp( signature.data(), katSig.data(), cbSig ) == 0, "Signature mismatch at line %lld", line );

    // Reset the key so that we can use the public key for verification
    keyBlob.mlDsakey.format = SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY;
    keyBlob.mlDsakey.cbKeyBlob = katPubKey.size();
    memcpy(keyBlob.mlDsakey.abKeyBlob, katPubKey.data(), katPubKey.size());

    status = pPqDsaImplementation->setKey( &keyBlob );
    CHECK3( NT_SUCCESS( status ), "Failed to set public key at line %lld", line );

    status = pPqDsaImplementation->verifyExternalMu(
        katMu.data(),
        katMu.size(),
        signature.data(),
        signature.size() );
    CHECK3( NT_SUCCESS( status ), "Verification failed at line %lld", line );

    status = pPqDsaImplementation->setKey( nullptr );
    CHECK( NT_SUCCESS(status), "Failed to free key" );
}

VOID
testHashMlDsaSignVerify(
    PqDsaImplementation* pPqDsaImplementation,
    SYMCRYPT_MLDSA_PARAMS params,
    const BString& katRnd,
    const BString& katPrivKey,
    const BString& katPubKey,
    const BString& katHash,
    const BString& katHashAlg,
    const BString& katSig,
    const BString& katCtx,
    ULONGLONG line)
{
    NTSTATUS status = STATUS_SUCCESS;
    PQDSAKEY_TESTBLOB keyBlob{};
    SIZE_T cbPrivKey = 0;
    SIZE_T cbPubKey = 0;
    SIZE_T cbSig = 0;
    SYMCRYPT_PQDSA_HASH_ID hashId = SYMCRYPT_PQDSA_HASH_ID_NULL;

    // KAT infrastructure treats all values as non-null-terminated byte strings, so these need
    // to be the same
    // TODO: Add KATs for SHAKE
    const BString sha256 = {'s', 'h', 'a', '2', '5', '6'};
    const BString sha384 = {'s', 'h', 'a', '3', '8', '4'};
    const BString sha512 = {'s', 'h', 'a', '5', '1', '2'};

    CHECK(
        SymCryptMlDsaSizeofKeyFormatFromParams(params, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY, &cbPrivKey) == SYMCRYPT_NO_ERROR,
        "Failed to get expected private key size" );

    CHECK(
        SymCryptMlDsaSizeofKeyFormatFromParams(params, SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY, &cbPubKey) == SYMCRYPT_NO_ERROR,
        "Failed to get expected public key size" );

    CHECK(
        SymCryptMlDsaSizeofSignatureFromParams(params, &cbSig) == SYMCRYPT_NO_ERROR,
        "Failed to get expected signature size" );

    CHECK4( katPrivKey.size() == cbPrivKey, "Invalid private key size %lld at line %lld", katPrivKey.size(), line );
    CHECK4( katPubKey.size() == cbPubKey, "Invalid public key size %lld at line %lld", katPubKey.size(), line );
    CHECK4( katRnd.size() == SYMCRYPT_MLDSA_SIGNING_RANDOM_SIZE, "Invalid random size %lld at line %lld", katRnd.size(), line );
    CHECK4( katCtx.size() <= SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH, "Invalid context size %lld at line %lld", katCtx.size(), line );
    CHECK4( katSig.size() == cbSig, "Invalid signature size %lld at line %lld", katSig.size(), line );

    if( katHashAlg == sha256 )
    {
        hashId = SYMCRYPT_PQDSA_HASH_ID_SHA256;
    }
    else if( katHashAlg == sha384 )
    {
        hashId = SYMCRYPT_PQDSA_HASH_ID_SHA384;
    }
    else if( katHashAlg == sha512 )
    {
        hashId = SYMCRYPT_PQDSA_HASH_ID_SHA512;
    }
    else
    {
        CHECK4( FALSE, "Unknown hash algorithm %s at line %lld", katHashAlg.c_str(), line );
    }

    keyBlob.mlDsakey.params = params;
    keyBlob.mlDsakey.format = SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY;
    keyBlob.mlDsakey.cbKeyBlob = katPrivKey.size();
    memcpy(keyBlob.mlDsakey.abKeyBlob, katPrivKey.data(), katPrivKey.size());

    status = pPqDsaImplementation->setKey( &keyBlob );
    CHECK3( NT_SUCCESS( status ), "Failed to set private key at line %lld", line );

    std::vector<BYTE> signature(cbSig);

    status = pPqDsaImplementation->signEx(
        hashId,
        katHash.data(),
        katHash.size(),
        katCtx.data(),
        katCtx.size(),
        katRnd.data(),
        katRnd.size(),
        0, // flags
        signature.data(),
        signature.size() );

    CHECK3( NT_SUCCESS( status ), "Signing failed at line %lld", line );
    CHECK3( memcmp( signature.data(), katSig.data(), cbSig ) == 0, "Signature mismatch at line %lld", line );

    // Reset the key so that we can use the public key for verification
    keyBlob.mlDsakey.format = SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY;
    keyBlob.mlDsakey.cbKeyBlob = katPubKey.size();
    memcpy(keyBlob.mlDsakey.abKeyBlob, katPubKey.data(), katPubKey.size());

    status = pPqDsaImplementation->setKey( &keyBlob );
    CHECK3( NT_SUCCESS( status ), "Failed to set public key at line %lld", line );

    status = pPqDsaImplementation->verifyHash(
        hashId,
        katHash.data(),
        katHash.size(),
        katCtx.data(),
        katCtx.size(),
        signature.data(),
        signature.size() );
    CHECK3( NT_SUCCESS( status ), "Verification failed at line %lld", line );

    status = pPqDsaImplementation->setKey( nullptr );
    CHECK( NT_SUCCESS(status), "Failed to free key" );
}

VOID
testMlDsaKats()
{
    std::unique_ptr<KatData> katMlDsa( getCustomResource( "kat_pqdsa.dat", "KAT_PQDSA" ) );
    KAT_ITEM katItem;

    String sep = "";

    SIZE_T i = 0;
    BOOLEAN bParamsFound = FALSE;

    SYMCRYPT_MLDSA_PARAMS params = SYMCRYPT_MLDSA_PARAMS_NULL;

    UINT32 cMlDsaKeyGenSamples = 0;
    UINT32 cMlDsaSignVerifySamples = 0;
    UINT32 cHashMlDsaSignVerifySamples = 0;
    UINT32 cExternalMuMlDsaSignVerifySamples = 0;

    auto pMlDsaImp = std::make_unique<PqDsaMultiImp>("MlDsa");

    while( 1 )
    {
        katMlDsa->getKatItem( & katItem );
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

            bParamsFound = FALSE;
            for( i=0; i < NUM_OF_MLDSA_TEST_PARAMS; i++ )
            {
                // Compare with the category name with known ML-DSA params
                if ( strcmp( katItem.categoryName.c_str(), rgTestMlDsaParams[i].pszParamsName ) == 0 )
                {
                    bParamsFound = TRUE;
                    break;
                }
            }
            CHECK3( bParamsFound, "ML-DSA header at line %lld specifies unknown params!", line ) ;
            
            params = rgTestMlDsaParams[i].params;
        }

        if( katItem.type == KAT_TYPE_DATASET )
        {
            if ( katIsFieldPresent( katItem, "seed" ) )
            {
                //
                // KeyGen
                //
                CHECK3( katItem.dataItems.size() == 3, "Wrong number of items in record at line %lld", line );

                BString katSeed = katParseData( katItem, "seed" );
                BString katPubKey = katParseData( katItem, "pk" );
                BString katPrivKey = katParseData( katItem, "sk" );

                testMlDsaKeyGen( pMlDsaImp.get(), params, katSeed, katPubKey, katPrivKey, line );
                cMlDsaKeyGenSamples++;

                continue;
            }
            else if( katIsFieldPresent( katItem, "mu" ) )
            {
                //
                // ExternalMu ML-DSA signing/verification
                //
                CHECK3( katItem.dataItems.size() == 5, "Wrong number of items in record at line %lld", line );

                BString katRnd = katParseData( katItem, "rnd" );
                BString katPrivKey = katParseData( katItem, "sk" );
                BString katPubKey = katParseData( katItem, "pk" );
                BString katMu = katParseData( katItem, "mu" );
                BString katSig = katParseData( katItem, "sig" );

                testExternalMuMlDsaSignVerify(
                    pMlDsaImp.get(),
                    params,
                    katRnd,
                    katPrivKey,
                    katPubKey,
                    katMu,
                    katSig,
                    line );

                cExternalMuMlDsaSignVerifySamples++;
                continue;

            }
            else if( katIsFieldPresent( katItem, "hash" ) )
            {
                //
                // Hash ML-DSA signing/verification
                //
                CHECK3( katItem.dataItems.size() == 7, "Wrong number of items in record at line %lld", line );

                BString katRnd = katParseData( katItem, "rnd" );
                BString katPrivKey = katParseData( katItem, "sk" );
                BString katPubKey = katParseData( katItem, "pk" );
                BString katHash = katParseData( katItem, "hash" );
                BString katHashAlg = katParseData( katItem, "hashalg" );
                BString katSig = katParseData( katItem, "sig" );
                BString katCtx = katParseData( katItem, "ctx" );

                testHashMlDsaSignVerify(
                    pMlDsaImp.get(),
                    params,
                    katRnd,
                    katPrivKey,
                    katPubKey,
                    katHash,
                    katHashAlg,
                    katSig,
                    katCtx,
                    line );

                cHashMlDsaSignVerifySamples++;
                continue;

            }
            else if( katIsFieldPresent( katItem, "rnd" ) )
            {
                //
                // Pure ML-DSA Signing/verifciation
                //
                CHECK3( katItem.dataItems.size() == 6, "Wrong number of items in record at line %lld", line );

                BString katRnd = katParseData( katItem, "rnd" );
                BString katPrivKey = katParseData( katItem, "sk" );
                BString katPubKey = katParseData( katItem, "pk" );
                BString katMsg = katParseData( katItem, "msg" );
                BString katSig = katParseData( katItem, "sig" );
                BString katCtx = katParseData( katItem, "ctx" );

                testMlDsaSignVerify(
                    pMlDsaImp.get(),
                    params,
                    katRnd,
                    katPrivKey,
                    katPubKey,
                    katMsg,
                    katSig,
                    katCtx,
                    line );

                cMlDsaSignVerifySamples++;
                continue;

            }

            FATAL2( "Unknown data record at line %lld", line );
        }
    }

    iprint( "\n        Total samples: %d MlDsaKeyGen, %d MlDsaSignVerify, %d ExternalMuMlDsaSignVerify, %d HashMlDsaSignVerify\n",
        cMlDsaKeyGenSamples, cMlDsaSignVerifySamples, cExternalMuMlDsaSignVerifySamples, cHashMlDsaSignVerifySamples );
}

VOID
testPqDsa()
{
    INT64 nOutstandingAllocs = 0;

    nOutstandingAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nOutstandingCheckedAllocs);
    CHECK3( nOutstandingAllocs  == 0, "Memory leak %d outstanding", nOutstandingAllocs );

    if( !isAlgorithmPresent( "MlDsa", TRUE ) )
    {
        iprint( "    Skipping ML-DSA tests\n" );
        return;
    }

    iprint( "    ML-DSA arithmetic\n" );
    // testNaiveImpls();
    testMlDsaPolyArithmetic();
    testMlDsaMatrixVectorArithmetic();

    iprint( "    ML-DSA\n" );
    testMlDsaRandom();
    testMlDsaNegative();
    testMlDsaKats();

    nOutstandingAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nOutstandingCheckedAllocs);
    CHECK3( nOutstandingAllocs == 0, "Memory leak, %d outstanding", nOutstandingAllocs );
}