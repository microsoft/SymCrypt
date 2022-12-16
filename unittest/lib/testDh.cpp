//
// TestDh.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//


#include "precomp.h"

// There is a bit of duplicate work and data structures here.
// The test for DH and DSA were re-written to fit the overall structure;
// some tests were carried over from the old tests, and they duplicate some minor
// things like structures for key sizes.

typedef struct {
    UINT32  nBitsOfP;
    UINT32  nBitsOfQ;
} TEST_DL_BITSIZEENTRY, * PTEST_DL_BITSIZEENTRY;

const TEST_DL_BITSIZEENTRY g_DlBitSizes[] = {
    { 512, 160 },
    { 768, 160 },
    { 960, 160 },       // Multiple of 64
    { 1024, 160 },
    { 1536, 256 },
    { 2048, 256 },
};

DLGROUP_TESTBLOB g_DlGroup[ MAX_TEST_DLGROUPS ] = {0};
UINT32 g_nDlgroups = 0;
UINT32 g_nDhNamedGroups = 0;

// Creating DL groups for all DH and DSA tests that need random groups

VOID
addDlgroupToGlobalTestBlobArray( UINT32 nBitsP, PSYMCRYPT_DLGROUP pGroup, PCSTR pcstrHashAlgName )
{
    SYMCRYPT_ERROR scError;
    PDLGROUP_TESTBLOB pBlob = &g_DlGroup[ g_nDlgroups++ ];
    SymCryptWipe( (PBYTE) pBlob, sizeof( *pBlob ) );

    SIZE_T cbP;
    SIZE_T cbQ;
    SIZE_T cbSeed;
    SymCryptDlgroupGetSizes(    pGroup,
                                &cbP,
                                &cbQ,
                                NULL,
                                &cbSeed );
    pBlob->cbPrimeP = (UINT32) cbP;
    pBlob->cbPrimeQ = (UINT32) cbQ;
    pBlob->cbSeed = (UINT32)cbSeed;

    pBlob->nBitsP = nBitsP;
    pBlob->fipsStandard = pGroup->eFipsStandard;

    pBlob->fHasPrimeQ = pGroup->fHasPrimeQ;
    pBlob->isSafePrimeGroup = pGroup->isSafePrimeGroup;
    pBlob->pcstrHashAlgName = pcstrHashAlgName;

    scError = SymCryptDlgroupGetValue(  pGroup,
                                        &pBlob->abPrimeP[0], pBlob->cbPrimeP,
                                        &pBlob->abPrimeQ[0], pBlob->cbPrimeQ,
                                        &pBlob->abGenG[0], pBlob->cbPrimeP,
                                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                        &pBlob->pHashAlgorithm,
                                        &pBlob->abSeed[0], pBlob->cbSeed,
                                        &pBlob->genCounter );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Failure to get DLGROUP value" );

    SymCryptDlgroupFree( pGroup );
}

VOID
addOneDlgroup( UINT32 nBitsP, BOOL randomQsize )
{
    // nBitsP = size of P
    SYMCRYPT_ERROR scError;
    PCSYMCRYPT_HASH hashAlgorithm;
    PCSTR pcstrHashAlgName;
    SYMCRYPT_DLGROUP_FIPS fipsStandard;
    UINT32 nBitsQ = 0;

    CHECK( g_nDlgroups < MAX_TEST_DLGROUPS, "?" );

    CHECK3( nBitsP >= 160 && nBitsP <= 4096 , "Bad parameters %d", nBitsP );

    // We must pick a random nBitsQ, fips standard, and hash algorithm that satisfy the requirements.
    // We do this the easy and brute-force way:
    // Generate a random combination and try again if we fail any of the criteria
    for(;;) {
        BYTE b = g_rng.byte();

        fipsStandard = SYMCRYPT_DLGROUP_FIPS_NONE;
        switch( b % 3 )
        {
        case 0:
            fipsStandard = SYMCRYPT_DLGROUP_FIPS_NONE;
            break;
        case 1:
            fipsStandard = SYMCRYPT_DLGROUP_FIPS_186_2;
            break;
        case 2:
            fipsStandard = SYMCRYPT_DLGROUP_FIPS_186_3;
        }

        hashAlgorithm = NULL;
        pcstrHashAlgName = NULL;
        switch( b % 5 )
        {
        case 0:
            hashAlgorithm = SymCryptSha1Algorithm;
            pcstrHashAlgName = "SHA1";
            break;
        case 1:
            hashAlgorithm = SymCryptSha256Algorithm;
            pcstrHashAlgName = "SHA256";
            break;
        case 2:
            hashAlgorithm = SymCryptSha384Algorithm;
            pcstrHashAlgName = "SHA384";
            break;
        case 3:
            hashAlgorithm = SymCryptSha512Algorithm;
            pcstrHashAlgName = "SHA512";
            break;
        case 4:
            hashAlgorithm = NULL;
            pcstrHashAlgName = NULL;
            break;
        }

        // Hash algorithm defaults to SHA-1
        SIZE_T nBitsHash = hashAlgorithm == NULL ? 160 : 8 * SymCryptHashResultSize( hashAlgorithm );

        if( randomQsize )
        {
            nBitsQ = (UINT32) g_rng.sizet( 128, hashAlgorithm != NULL ? nBitsHash + 1 : (nBitsP-1) );
        } else {
            nBitsQ = 0;
        }

        // Fail if hash alg is provided for FIPS 186-2 or not for any other mode
        if( (fipsStandard == SYMCRYPT_DLGROUP_FIPS_186_2 && hashAlgorithm != NULL ) ||
            (fipsStandard != SYMCRYPT_DLGROUP_FIPS_186_2 && hashAlgorithm == NULL ) )
        {
            continue;
        }
        // Fail if P is smaller than the hash size
        if( nBitsP < nBitsHash  )
        {
            continue;
        }

        // Fail if nBitsQ > hash size
        if( (nBitsQ > 0 && nBitsQ > nBitsHash) ||
            (nBitsQ == 0 && nBitsP > 1024 && nBitsHash < 256 ) )
        {
            continue;
        }

        break;
    }

    //iprint( "[%d, %d, %d, %d]", nBitsP, nBitsQ, hashAlgorithm == NULL ? 0 : SymCryptHashResultSize( hashAlgorithm ), fipsStandard );

    PSYMCRYPT_DLGROUP pGroup = SymCryptDlgroupAllocate( nBitsP, nBitsQ );
    CHECK( pGroup != NULL, "?" );

    scError = SymCryptDlgroupGenerate( hashAlgorithm, fipsStandard, pGroup );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error generating DL group" );

    addDlgroupToGlobalTestBlobArray( nBitsP, pGroup, pcstrHashAlgName );
}

const int g_maxSafePrimeGroupBitSize = 8192;

const SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE g_safePrimeTypes[] =
{
    SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_IKE_3526,
    SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_TLS_7919,
};

SYMCRYPT_ASYM_ALIGN BYTE g_dlGroupScratch[1 << 22]; // Scratch space used by generateDlGroups

VOID generateDlGroups()
{
    // Fill up our array of key blobs with generated keys
    UINT32 desiredFixedGroupSizes[] = {
        (4096 << 16) + 1, // 1 keys of 4096 bits
        (3072 << 16) + 2, // 2 keys of 3072 bits
        (2048 << 16) + 5,
        (1536 << 16) + 2,
        (1024 << 16) + 5,
        (768  << 16) + 2,
        (512  << 16) + 2,
        0,
        };
    UINT32 bitSize;
    UINT32 primResult;

    char * sep = " [group safeprime:";
    UINT32 previousSize = 0;

    if( g_nDlgroups >= MAX_TEST_DLGROUPS )
    {
        goto cleanup;
    }

    for( int i = 0; i<ARRAY_SIZE(g_safePrimeTypes); i++)
    {
        SYMCRYPT_ERROR scError;
        SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE eDhSafePrimeType = g_safePrimeTypes[i];

        iprint( sep );
        switch(eDhSafePrimeType)
        {
        case SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_IKE_3526:
            sep = " IKE";
            break;
        case SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_TLS_7919:
            sep = " TLS";
            break;
        default:
            sep = " ???";
            break;
        }

        UINT32 maxBitSize = g_maxSafePrimeGroupBitSize;
        while( TRUE )
        {
            PSYMCRYPT_DLGROUP pGroup = SymCryptDlgroupAllocate( maxBitSize, maxBitSize );
            CHECK( pGroup != NULL, "?" );

            scError = SymCryptDlgroupSetValueSafePrime( eDhSafePrimeType, pGroup );
            // Assume we've reached the minimum supported size
            if( scError == SYMCRYPT_INVALID_ARGUMENT )
            {
                SymCryptDlgroupFree( pGroup );
                break;
            }

            CHECK( scError == SYMCRYPT_NO_ERROR, "Error setting DL safe-prime group" );

            CHECK(pGroup->isSafePrimeGroup, "DL safe-prime group initialized incorrectly")
            CHECK(pGroup->nBitsOfP <= maxBitSize,   "DL safe-prime group P is wrong size");
            CHECK(pGroup->nBitsOfQ <= maxBitSize-1, "DL safe-prime group Q is wrong size");

            iprint( "%s%d", sep, pGroup->nBitsOfP );
            sep = ",";
            maxBitSize = pGroup->nBitsOfP-1;

            // Check that the constants selected by SetValueSafePrime are indeed prime
            primResult = SymCryptIntMillerRabinPrimalityTest(
                SymCryptIntFromModulus( pGroup->pmP ),
                pGroup->nBitsOfP,
                8, // nIterations - reduce runtime overhead as this should always pass
                SYMCRYPT_FLAG_DATA_PUBLIC, //flags
                g_dlGroupScratch,
                SYMCRYPT_SCRATCH_BYTES_FOR_INT_IS_PRIME( pGroup->pmP->nDigits ) );
            CHECK(primResult != 0, "Primality test failed for DL safe-prime group P");

            primResult = SymCryptIntMillerRabinPrimalityTest(
                SymCryptIntFromModulus( pGroup->pmQ ),
                pGroup->nBitsOfQ,
                8, // nIterations - reduce runtime overhead as this should always pass
                SYMCRYPT_FLAG_DATA_PUBLIC, //flags
                g_dlGroupScratch,
                SYMCRYPT_SCRATCH_BYTES_FOR_INT_IS_PRIME( pGroup->pmQ->nDigits ) );
            CHECK(primResult != 0, "Primality test failed for DL safe-prime group Q");

            // Need to enable DH keypairs larger than 4096b in CNG before testing with these groups
            if (pGroup->nBitsOfP <= 4096)
            {
                g_nDhNamedGroups++;
                addDlgroupToGlobalTestBlobArray( pGroup->nBitsOfP, pGroup, NULL );
            }
            else
            {
                SymCryptDlgroupFree( pGroup );
            }
        }
    }

    sep = "]\n     [group gen: ";

    for( int i = 0; desiredFixedGroupSizes[i] != 0; i++ )
    {
        bitSize = desiredFixedGroupSizes[i] >> 16;
        int n = desiredFixedGroupSizes[i] & 0xff;
        while( n-- && g_nDlgroups < MAX_TEST_DLGROUPS )
        {
            if( bitSize == previousSize )
            {
                iprint( "." );
            } else {
                iprint( "%s%d", sep, bitSize );
                sep = ",";
                previousSize = bitSize;
            }

            addOneDlgroup( bitSize, FALSE );
        }
    }

    // And we fill the rest with randomly-sized keys
    // For performance we favor the smaller key sizes.
    while( g_nDlgroups < MAX_TEST_DLGROUPS )
    {
        UINT32 r = g_rng.uint32();
        // We use prime moduli as they are almost independent
        if( (r % 51) == 0 )
        {
            bitSize = (UINT32) g_rng.sizet( 2048, 4096 );
        } else if ( (r % 5) == 0 ) {
            bitSize = (UINT32) g_rng.sizet( 1024, 2049 );
        } else {
            bitSize = (UINT32) g_rng.sizet( 512, 1025 );
        }

        if( bitSize == previousSize )
        {
            iprint( "." );
        } else {
            iprint( "%s%d", sep, bitSize );
            sep = ",";
            previousSize = bitSize;
        }

        addOneDlgroup( bitSize, TRUE );
    }

    iprint( "]" );

cleanup:
    return;
}

PCDLGROUP_TESTBLOB
dlgroupRandom()
{
    return &g_DlGroup[ g_rng.sizet( g_nDlgroups ) ];
}

PCDLGROUP_TESTBLOB
dlgroupForSize( SIZE_T nBits, BOOLEAN forDiffieHellman )
{
    // If not DH, skip the DH named safe-prime groups at the start
    UINT32 i = forDiffieHellman ? 0 : g_nDhNamedGroups;

    for( ; i<g_nDlgroups; i++ )
    {
        if( g_DlGroup[i].nBitsP == nBits )
        {
            return &g_DlGroup[i];
        }
    }
    CHECK3( FALSE, "Could not find group for %d bits", nBits );
    return NULL;
}

SYMCRYPT_DLGROUP_FIPS testDlRandomFips()
{
    BYTE rand = 0;

    do
    {
        rand = g_rng.byte() & 0x03;
    } while (rand > 2);

    switch (rand)
    {
        case (0):
            return SYMCRYPT_DLGROUP_FIPS_NONE;
            break;
        case (1):
            return SYMCRYPT_DLGROUP_FIPS_186_2;
            break;
        case (2):
            return SYMCRYPT_DLGROUP_FIPS_186_3;
            break;
        default:
            CHECK(FALSE, "?");
            return SYMCRYPT_DLGROUP_FIPS_NONE;
            break;
    }
}

VOID testDlSimple()
// This test is inherited from the previous tests for Discrete Log
// It tests both DL and DSA, but we include it here as all the DL general
// tests are in the testDh.cpp.
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PSYMCRYPT_DLGROUP pDlgroup = NULL;
    PSYMCRYPT_DLKEY pkDlkey = NULL;

    SYMCRYPT_DLGROUP_FIPS eFipsStandard = SYMCRYPT_DLGROUP_FIPS_NONE;
    PCSYMCRYPT_HASH pHashAlgorithm = NULL;

    UINT32 nBitsOfP = 0;
    UINT32 nBitsOfQ = 0;
    UINT32 nBitsOfQActual = 0;

    // Variables for exported parameters
    SIZE_T cbExpP = 0;
    SIZE_T cbExpQ = 0;
    SIZE_T cbExpG = 0;
    SIZE_T cbExpS = 0;
    PCSYMCRYPT_HASH pExpH = NULL;
    UINT32 dwExpC = 0;

    PBYTE pbBlob = NULL;
    SIZE_T cbBlob = 0;

    BYTE rbHashValue[SYMCRYPT_HASH_MAX_RESULT_SIZE] = { 0 };
    SIZE_T cbHashValue = 0;

    BYTE rbSignature[2*DLKEY_MAXKEYSIZE];
    SIZE_T cbSignature = 0;

    if( !SCTEST_LOOKUP_DISPATCHSYM(SymCryptSha1Algorithm)           ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptSha256Algorithm)         ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptSha384Algorithm)         ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptSha512Algorithm)         ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptDlgroupAllocate)         ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptDlgroupGenerate)         ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptDlkeyAllocate)           ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptDlkeyGenerate)           ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptDlkeySizeofPrivateKey)   ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptDsaSign)                 ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptDsaVerify)               ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptDlgroupGetSizes)         ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptDlgroupGetValue)         ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptDlgroupSetValue)         ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptDlkeyFree)               ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptDlgroupFree)             ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptWipe) )
    {
        print("    skipped\n");
        return;
    }

    for (UINT32 i = 0; i<ARRAY_SIZE(g_DlBitSizes); i++)
    {
        nBitsOfP = g_DlBitSizes[i].nBitsOfP;
        nBitsOfQ = g_DlBitSizes[i].nBitsOfQ;
        nBitsOfQActual = nBitsOfQ;

        // Pick a random FIPS standard (unless nBitsOfQ > 160)
        if (nBitsOfQActual <= 160)
        {
            eFipsStandard = testDlRandomFips();
        }
        else
        {
            eFipsStandard = SYMCRYPT_DLGROUP_FIPS_LATEST;
        }

        // Pick a random hash algorithm (or if FIPS 186-2 pick NULL)
        if (eFipsStandard == SYMCRYPT_DLGROUP_FIPS_186_2)
        {
            pHashAlgorithm = NULL;
            cbHashValue = SYMCRYPT_SHA256_RESULT_SIZE;
        }
        else
        {
            do
            {
                // Pick a random hash algorithm
                switch( g_rng.byte() % 4 )
                {
                case 0:
                    pHashAlgorithm = ScDispatchSymCryptSha1Algorithm;
                    cbHashValue = 20;
                    break;
                case 1:
                    pHashAlgorithm = ScDispatchSymCryptSha256Algorithm;
                    cbHashValue = 32;
                    break;
                case 2:
                    pHashAlgorithm = ScDispatchSymCryptSha384Algorithm;
                    cbHashValue = 48;
                    break;
                case 3:
                    pHashAlgorithm = ScDispatchSymCryptSha512Algorithm;
                    cbHashValue = 64;
                    break;
                default:
                    CHECK( FALSE, "?" );
                }
            } while ((8*cbHashValue < nBitsOfQActual) ||
                     (8*cbHashValue > nBitsOfP) );
        }

        // Allocate and generate a DLGROUP
        pDlgroup = ScDispatchSymCryptDlgroupAllocate( nBitsOfP, nBitsOfQ );
        CHECK( pDlgroup!=NULL, "?");

        scError = ScDispatchSymCryptDlgroupGenerate( pHashAlgorithm, eFipsStandard, pDlgroup );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

        vprint(g_verbose, "\nGenerated ");
        //printDlGroup( pDlgroup );

        // DLKEY
        pkDlkey = ScDispatchSymCryptDlkeyAllocate( pDlgroup );
        CHECK( pkDlkey!=NULL, "?");

        scError = ScDispatchSymCryptDlkeyGenerate( SYMCRYPT_FLAG_DLKEY_DSA, pkDlkey );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

        //printDlKey( pkDlkey );

        // DSA sign and verify
        scError = SymCryptCallbackRandom(rbHashValue, cbHashValue);
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

        cbSignature = 2*ScDispatchSymCryptDlkeySizeofPrivateKey(pkDlkey);

        scError = ScDispatchSymCryptDsaSign(
                        pkDlkey,
                        rbHashValue,
                        cbHashValue,
                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                        0,
                        rbSignature,
                        cbSignature );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

        scError = ScDispatchSymCryptDsaVerify(
                        pkDlkey,
                        rbHashValue,
                        cbHashValue,
                        rbSignature,
                        cbSignature,
                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                        0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

        // Flip the first byte of the message
        rbHashValue[0] ^= 0xff;
        scError = ScDispatchSymCryptDsaVerify(
                        pkDlkey,
                        rbHashValue,
                        cbHashValue,
                        rbSignature,
                        cbSignature,
                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                        0 );
        CHECK( scError == SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE, "?" );

        // Get the group parameters in a blob
        ScDispatchSymCryptDlgroupGetSizes(
            pDlgroup,
            &cbExpP,
            &cbExpQ,
            &cbExpG,
            &cbExpS );

        cbBlob = cbExpP + cbExpQ + cbExpG + cbExpS;
        pbBlob = (PBYTE) SymCryptCallbackAlloc( cbBlob );
        CHECK( pbBlob != NULL, "?" );

        scError = ScDispatchSymCryptDlgroupGetValue(
                        pDlgroup,
                        pbBlob,
                        cbExpP,
                        pbBlob + cbExpP,
                        cbExpQ,
                        pbBlob + cbExpP + cbExpQ,
                        cbExpG,
                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                        &pExpH,
                        pbBlob + cbExpP + cbExpQ + cbExpG,
                        cbExpS,
                        &dwExpC );
        CHECK( scError==SYMCRYPT_NO_ERROR, "?" );

        // Set its value with only P (it should fail as it cannot generate G)
        scError = ScDispatchSymCryptDlgroupSetValue(
                        pbBlob,
                        cbExpP,
                        nullptr,
                        0,
                        nullptr,
                        0,
                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                        nullptr,
                        nullptr,
                        0,
                        0,
                        SYMCRYPT_DLGROUP_FIPS_NONE,
                        pDlgroup );
        CHECK( scError==SYMCRYPT_INVALID_ARGUMENT, "?" );

        // Set its value with P and G (it should succeed)
        scError = ScDispatchSymCryptDlgroupSetValue(
                        pbBlob,
                        cbExpP,
                        nullptr,
                        0,
                        pbBlob + cbExpP + cbExpQ,
                        cbExpG,
                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                        nullptr,
                        nullptr,
                        0,
                        0,
                        SYMCRYPT_DLGROUP_FIPS_NONE,
                        pDlgroup );
        CHECK( scError==SYMCRYPT_NO_ERROR, "?" );

        vprint(g_verbose, "\n(P, -, G) ");
        //printDlGroup( pDlgroup );

        // Create a new key and make sure it is mod P
        scError = ScDispatchSymCryptDlkeyGenerate( SYMCRYPT_FLAG_DLKEY_DSA | SYMCRYPT_FLAG_KEY_NO_FIPS, pkDlkey );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

        CHECK(ScDispatchSymCryptDlkeySizeofPrivateKey(pkDlkey) == cbExpP, "?")

        //printDlKey( pkDlkey );

        // Set its value with P and Q (it should succeed and generate a new G)
        scError = ScDispatchSymCryptDlgroupSetValue(
                        pbBlob,
                        cbExpP,
                        pbBlob + cbExpP,
                        cbExpQ,
                        nullptr,
                        0,
                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                        nullptr,
                        nullptr,
                        0,
                        0,
                        SYMCRYPT_DLGROUP_FIPS_NONE,
                        pDlgroup );
        CHECK( scError==SYMCRYPT_NO_ERROR, "?" );

        //vprint(g_verbose, "\n(P, Q, G) ");
        //printDlGroup( pDlgroup );

        // Flip one byte of the seed
        *(&pbBlob[cbExpP + cbExpQ + cbExpG]) = *(&pbBlob[cbExpP + cbExpQ + cbExpG]) ^ 0xff;

        // Set its value with P, Q, and G with bogus seed but no verify flag.
        // It should succeed
        scError = ScDispatchSymCryptDlgroupSetValue(
                        pbBlob,
                        cbExpP,
                        pbBlob + cbExpP,
                        cbExpQ,
                        pbBlob + cbExpP + cbExpQ,
                        cbExpG,
                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                        pExpH,
                        pbBlob + cbExpP + cbExpQ + cbExpG,
                        cbExpS,
                        dwExpC,
                        SYMCRYPT_DLGROUP_FIPS_NONE,
                        pDlgroup );
        CHECK( scError==SYMCRYPT_NO_ERROR, "?" );

        //vprint(g_verbose, "\n(P,Q,G) w/o Ver. ");
        //printDlGroup( pDlgroup );

        // Set its value with P, Q, and G with bogus seed and verify flag.
        // It should fail
        scError = ScDispatchSymCryptDlgroupSetValue(
                        pbBlob,
                        cbExpP,
                        pbBlob + cbExpP,
                        cbExpQ,
                        pbBlob + cbExpP + cbExpQ,
                        cbExpG,
                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                        pExpH,
                        pbBlob + cbExpP + cbExpQ + cbExpG,
                        cbExpS,
                        dwExpC,
                        (eFipsStandard==SYMCRYPT_DLGROUP_FIPS_NONE)
                            ?SYMCRYPT_DLGROUP_FIPS_LATEST
                            :eFipsStandard,
                        pDlgroup );
        CHECK( scError==SYMCRYPT_AUTHENTICATION_FAILURE, "?" );

        // Flip the byte of the seed back
        *(&pbBlob[cbExpP + cbExpQ + cbExpG]) = *(&pbBlob[cbExpP + cbExpQ + cbExpG]) ^ 0xff;

        // Set its value with P, Q, and G with proper verification data and verify flag.
        // It should succeed
        scError = ScDispatchSymCryptDlgroupSetValue(
                        pbBlob,
                        cbExpP,
                        pbBlob + cbExpP,
                        cbExpQ,
                        pbBlob + cbExpP + cbExpQ,
                        cbExpG,
                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                        pExpH,
                        pbBlob + cbExpP + cbExpQ + cbExpG,
                        cbExpS,
                        dwExpC,
                        (eFipsStandard==SYMCRYPT_DLGROUP_FIPS_NONE)
                            ?SYMCRYPT_DLGROUP_FIPS_LATEST
                            :eFipsStandard,
                        pDlgroup );
        CHECK( scError==SYMCRYPT_NO_ERROR, "?" );

        //vprint(g_verbose, "\n(P,Q,G) w/ Ver. ");
        //printDlGroup( pDlgroup );

        // Create a new key and use the mod P flag
        scError = ScDispatchSymCryptDlkeyGenerate(
            SYMCRYPT_FLAG_DLKEY_DSA | SYMCRYPT_FLAG_DLKEY_GEN_MODP | SYMCRYPT_FLAG_KEY_NO_FIPS,
            pkDlkey);
        CHECK(scError == SYMCRYPT_NO_ERROR, "?");

        CHECK(ScDispatchSymCryptDlkeySizeofPrivateKey(pkDlkey) == cbExpP, "?")

        //printDlKey( pkDlkey );

        ScDispatchSymCryptDlkeyFree( pkDlkey );
        ScDispatchSymCryptDlgroupFree( pDlgroup );

        ScDispatchSymCryptWipe(pbBlob, cbBlob);
        SymCryptCallbackFree(pbBlob);
    }
}


class DhMultiImp: public DhImplementation
{
public:
    DhMultiImp( String algName );       // AlgName not needed, but kept for symmetry with other algorithm classes
    ~DhMultiImp();

private:
    DhMultiImp( const DhMultiImp & );
    VOID operator=( const DhMultiImp & );

public:
    typedef std::vector<DhImplementation *> ImpPtrVector;

    ImpPtrVector m_imps;        // Implementations being tested
    ImpPtrVector m_comps;       // Implementations for current computation

    virtual NTSTATUS setKey(
        _In_    PCDLKEY_TESTBLOB    pcKeyBlob );    // Returns an error if this key can't be handled.

    virtual NTSTATUS sharedSecret(
        _In_                        PCDLKEY_TESTBLOB    pcPubkey,   // Must be on same group
        _Out_writes_( cbSecret )    PBYTE               pbSecret,
                                    SIZE_T              cbSecret );
};

DhMultiImp::DhMultiImp( String algName )
{
    m_algorithmName = algName;

    getAllImplementations<DhImplementation>( algName, &m_imps );
}

DhMultiImp::~DhMultiImp()
{
    //
    // Propagate the # KAT failures to the individual algorithms.
    //
    for( ImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        (*i)->m_nErrorKatFailure += m_nErrorKatFailure;
    }
}

NTSTATUS
DhMultiImp::setKey(
        _In_    PCDLKEY_TESTBLOB    pcKeyBlob )
{
    m_comps.clear();

    for( ImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        if( (*i)->setKey( pcKeyBlob ) == STATUS_SUCCESS )
        {
            m_comps.push_back( *i );
        }
    }

    return m_comps.size() == 0 ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;

}

NTSTATUS
DhMultiImp::sharedSecret(
        _In_                        PCDLKEY_TESTBLOB    pcPubkey,   // Must be on same group
        _Out_writes_( cbSecret )    PBYTE               pbSecret,
                                    SIZE_T              cbSecret )
{
    BYTE buf[ DLKEY_MAXKEYSIZE ];
    NTSTATUS ntStatus;

    ResultMerge res;

    CHECK( cbSecret <= DLKEY_MAXKEYSIZE, "?" );

    GENRANDOM( buf, sizeof( buf ) );
    for( ImpPtrVector::iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        buf[0]++;
        ntStatus = (*i)->sharedSecret( pcPubkey, buf, cbSecret );
        CHECK( NT_SUCCESS( ntStatus ), "Error computing shared DH secret" );
        res.addResult( *i, buf, cbSecret );
    }

    res.getResult( pbSecret, cbSecret );
    return STATUS_SUCCESS;
}

VOID
createKatFileSingleDh( FILE * f, PCDLGROUP_TESTBLOB pBlob )
{
    SYMCRYPT_ERROR scError;
    BYTE buf[ DLKEY_MAXKEYSIZE ];
    BYTE privKey[ DLKEY_MAXKEYSIZE ];

    PSYMCRYPT_DLGROUP pGroup = dlgroupObjectFromTestBlob<ImpSc>( pBlob );

    PSYMCRYPT_DLKEY pKey1 = SymCryptDlkeyAllocate( pGroup );
    PSYMCRYPT_DLKEY pKey2 = SymCryptDlkeyAllocate( pGroup );

    scError = SymCryptDlkeyGenerate( SYMCRYPT_FLAG_DLKEY_DH, pKey1 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error generating DH key" );

    scError = SymCryptDlkeyGenerate( SYMCRYPT_FLAG_DLKEY_DH, pKey2 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error generating DH key" );

    UINT32 cbPrivKey1 = SymCryptDlkeySizeofPrivateKey( pKey1 );
    UINT32 cbPrivKey2 = SymCryptDlkeySizeofPrivateKey( pKey2 );

    fprintf( f, "P  = " );
    fprintHex( f, pBlob->abPrimeP, pBlob->cbPrimeP );
    fprintf( f, "G  = " );
    fprintHex( f, pBlob->abGenG, pBlob->cbPrimeP );

    if( pBlob->cbPrimeQ > 0 )
    {
        fprintf( f, "Q  = " );
        fprintHex( f, pBlob->abPrimeQ, pBlob->cbPrimeQ );
    }

    scError = SymCryptDlkeyGetValue(    pKey1,
                                        privKey, cbPrivKey1,
                                        buf, pBlob->cbPrimeP,
                                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                        0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error reading DH key" );
    fprintf( f, "X1 = " );
    fprintHex( f, privKey, cbPrivKey1 );
    fprintf( f, "H1 = " );
    fprintHex( f, buf, pBlob->cbPrimeP );

    scError = SymCryptDlkeyGetValue(    pKey2,
                                        privKey, cbPrivKey2,
                                        buf, pBlob->cbPrimeP,
                                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                        0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error reading DH key" );
    fprintf( f, "X2 = " );
    fprintHex( f, privKey, cbPrivKey2 );
    fprintf( f, "H2 = " );
    fprintHex( f, buf, pBlob->cbPrimeP );

    scError = SymCryptDhSecretAgreement(    pKey1,
                                            pKey2,
                                            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                            0,
                                            buf, pBlob->cbPrimeP );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error creating shared secret" );
    fprintf( f, "SS = " );
    fprintHex( f, buf, pBlob->cbPrimeP );

    scError = SymCryptDhSecretAgreement(    pKey2,
                                            pKey1,
                                            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                            0,
                                            privKey, pBlob->cbPrimeP );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error creating shared secret" );
    CHECK( memcmp( buf, privKey, pBlob->cbPrimeP ) == 0, "Shared secret disagreement" );

    fprintf( f, "\n" );

    SymCryptDlkeyFree( pKey1 );
    pKey1 = NULL;

    SymCryptDlkeyFree( pKey2 );
    pKey2 = NULL;

    SymCryptDlgroupFree( pGroup );
    pGroup = NULL;
}


VOID
createKatFileDh()
// This function is not normally used, but available for use whenever we want to re-generate
// new test vectors.
{
    FILE * f = fopen( "generated_kat_dh.dat", "wt" );
    CHECK( f != NULL, "Could not create output file" );

    fprintf( f, "#\n"
                "# DO NOT EDIT: Generated test vectors for DH\n"
                "#\n"
                "\n"
                );
    fprintf( f, "[Dh]\n\n" );

    generateDlGroups();
    for( int i=0; i<MAX_TEST_DLGROUPS; i++ )
    {
        createKatFileSingleDh( f, &g_DlGroup[ i ] );
    }

    fprintf( f, "\n"
                "rnd = 1\n"
                "\n"
                );

    fclose( f );

    // Generating test vectors is not normal program flow, so we abort here to avoid getting into
    // non-standard states.
    CHECK( FALSE, "Written DH test vector file" );
}


VOID
testDhSingle(
                                DhImplementation  * pDh,
    _In_                        PCDLKEY_TESTBLOB    pKey1,
    _In_                        PCDLKEY_TESTBLOB    pKey2,
    _In_reads_( cbShared )      PCBYTE              pbShared,
                                SIZE_T              cbShared )
{
    NTSTATUS ntStatus;
    BYTE buf[DLKEY_MAXKEYSIZE];

    // We require that two keys are on the same group objects; we don't have the case where we
    // have to compare two groups to see if they are the same.
    CHECK( pKey1->pGroup == pKey2->pGroup, "Two DH keys are on different DL group objects" );

    SIZE_T cbP = pKey1->pGroup->cbPrimeP;
    CHECK( cbP <= DLKEY_MAXKEYSIZE, "?" );
    CHECK( cbShared == cbP, "Wrong shared secret size" );

    ntStatus = pDh->setKey( pKey1 );
    CHECK( NT_SUCCESS( ntStatus ), "Error setting key" );

    ntStatus = pDh->sharedSecret( pKey2, buf, cbP );
    CHECK( NT_SUCCESS( ntStatus ), "Error getting shared secret" );

    CHECK( memcmp( buf, pbShared, cbP ) == 0, "Shared secret mismatch" );

    ntStatus = pDh->setKey( pKey2 );
    CHECK( NT_SUCCESS( ntStatus ), "Error setting key" );

    ntStatus = pDh->sharedSecret( pKey1, buf, cbP );
    CHECK( NT_SUCCESS( ntStatus ), "Error getting shared secret" );

    CHECK( memcmp( buf, pbShared, cbP ) == 0, "Shared secret mismatch" );

    CHECK( pDh->setKey( NULL ) == STATUS_SUCCESS, "Failed to clear key" );
}

VOID
testDhtestGroups( DhImplementation  * pDh, INT64 line )
{
    BYTE buf1[DLKEY_MAXKEYSIZE];
    BYTE buf2[DLKEY_MAXKEYSIZE];
    SYMCRYPT_ERROR scError;
    NTSTATUS ntStatus;
    UINT32 nBitsPriv;
    UINT32 nBitsPrivGenerated = 0;

    UNREFERENCED_PARAMETER( line );

    generateDlGroups();

    for( int i=0; i<MAX_TEST_DLGROUPS; i++ )
    {
        PCDLGROUP_TESTBLOB pGroupBlob = &g_DlGroup[i];

        // We have a group; to test the DH implementation we need to create two keys
        PSYMCRYPT_DLGROUP pGroup = SymCryptDlgroupAllocate( pGroupBlob->nBitsP, 8*pGroupBlob->cbPrimeQ );
        CHECK( pGroup != NULL, "Error allocating Symcr")

        SIZE_T cbP = pGroupBlob->cbPrimeP;

        scError = SymCryptDlgroupSetValue(
                    &pGroupBlob->abPrimeP[0], cbP,
                    &pGroupBlob->abPrimeQ[0], pGroupBlob->cbPrimeQ,
                    &pGroupBlob->abGenG[0], cbP,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    pGroupBlob->pHashAlgorithm,
                    &pGroupBlob->abSeed[0], pGroupBlob->cbSeed,
                    pGroupBlob->genCounter,
                    pGroupBlob->fipsStandard,
                    pGroup );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Error setting group object" );

        PSYMCRYPT_DLKEY pKey1 = SymCryptDlkeyAllocate( pGroup );
        PSYMCRYPT_DLKEY pKey2 = SymCryptDlkeyAllocate( pGroup );
        CHECK( pKey1 != NULL && pKey2 != NULL, "Could not create keys" );

        nBitsPriv = 0;
        if( pGroup->isSafePrimeGroup )
        {
            // 50% chance to set private key lengths to random values in range [2s, len(q)] rather
            // than using the default value
            if( g_rng.byte() & 1 )
            {
                // Set nBitsPriv in range [2s, len(q)]
                nBitsPriv = (UINT32) g_rng.sizet(pGroup->nMinBitsPriv, pGroup->nBitsOfQ + 1 );
                scError = SymCryptDlkeySetPrivateKeyLength( pKey1, nBitsPriv, 0 );
                CHECK4( scError == SYMCRYPT_NO_ERROR, "Error setting private key length nBitsPriv %d cbP %d", nBitsPriv, cbP );
            }
        }

        scError = SymCryptDlkeyGenerate( SYMCRYPT_FLAG_DLKEY_DH | SYMCRYPT_FLAG_KEY_NO_FIPS, pKey1 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Error generating key" );
        scError = SymCryptDlkeyGenerate( SYMCRYPT_FLAG_DLKEY_DH | (pGroup->isSafePrimeGroup ? 0 : SYMCRYPT_FLAG_KEY_NO_FIPS), pKey1 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Error generating key" );
        scError = SymCryptDlkeyGenerate( SYMCRYPT_FLAG_DLKEY_DH | SYMCRYPT_FLAG_KEY_NO_FIPS | SYMCRYPT_FLAG_DLKEY_GEN_MODP, pKey2 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Error generating key" );

        DLKEY_TESTBLOB  blob1;
        DLKEY_TESTBLOB  blob2;

        blob1.pGroup = pGroupBlob;
        blob2.pGroup = pGroupBlob;

        blob1.nBitsPriv = nBitsPriv;
        blob2.nBitsPriv = 0;

        blob1.cbPrivKey = SymCryptDlkeySizeofPrivateKey( pKey1 );
        blob2.cbPrivKey = SymCryptDlkeySizeofPrivateKey( pKey2 );

        blob1.fPrivateModP = FALSE;
        blob2.fPrivateModP = TRUE;

        scError = SymCryptDlkeyGetValue(
                pKey1,
                &blob1.abPrivKey[0], blob1.cbPrivKey,
                &blob1.abPubKey[0], cbP,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Error exporting key" );

        scError = SymCryptDlkeyGetValue(
                pKey2,
                &blob2.abPrivKey[0], blob2.cbPrivKey,
                &blob2.abPubKey[0], cbP,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Error exporting key" );

        if( nBitsPriv != 0 )
        {
            // If we set private key length, check our validation logic for importing private keys
            nBitsPrivGenerated = SymCryptIntBitsizeOfValue(pKey1->piPrivateKey);

            // We should always be able to import blob1 into pKey1 - nBitsPrivGenerated <= nBitsPriv
            scError = SymCryptDlkeySetValue(
                    &blob1.abPrivKey[0], blob1.cbPrivKey,
                    &blob1.abPubKey[0], cbP,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    SYMCRYPT_FLAG_DLKEY_DH,
                    pKey1 );
            CHECK4( scError == SYMCRYPT_NO_ERROR, "Error (%d) importing key - nBitsPriv %d", scError, nBitsPriv );

            // Try to import generated key when we have set the private key to be explicitly shorter
            if( nBitsPrivGenerated > pGroup->nMinBitsPriv )
            {
                scError = SymCryptDlkeySetPrivateKeyLength( pKey1, nBitsPrivGenerated-1, 0 );
                CHECK( scError == SYMCRYPT_NO_ERROR, "Error setting private key length" );

                scError = SymCryptDlkeySetValue(
                        &blob1.abPrivKey[0], blob1.cbPrivKey,
                        &blob1.abPubKey[0], cbP,
                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                        SYMCRYPT_FLAG_DLKEY_DH,
                        pKey1 );
                CHECK5( scError == SYMCRYPT_INVALID_ARGUMENT, "Unexpected return (%d) importing key - nBitsPrivGenerated %d nBitsPriv %d", scError, nBitsPrivGenerated, nBitsPriv );
            }

            // Try to import generated key when we have set the private key to be explicitly longer
            if( nBitsPrivGenerated < pGroup->nBitsOfQ )
            {
                scError = SymCryptDlkeySetPrivateKeyLength( pKey1, SYMCRYPT_MAX(nBitsPrivGenerated+1, pGroup->nMinBitsPriv), 0 );
                CHECK4( scError == SYMCRYPT_NO_ERROR, "Error setting private key length nBitsPrivGenerated+1 %d cbP %d", nBitsPrivGenerated+1, cbP );

                scError = SymCryptDlkeySetValue(
                        &blob1.abPrivKey[0], blob1.cbPrivKey,
                        &blob1.abPubKey[0], cbP,
                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                        SYMCRYPT_FLAG_DLKEY_DH,
                        pKey1 );
                CHECK5( scError == SYMCRYPT_NO_ERROR, "Error (%d) importing key - nBitsPrivGenerated %d nBitsPriv %d", scError, nBitsPrivGenerated, nBitsPriv );
            }
        }

        GENRANDOM( buf1, sizeof( buf1 ) );
        GENRANDOM( buf2, sizeof( buf2 ) );

        ntStatus = pDh->setKey( &blob1 );
        CHECK( NT_SUCCESS( ntStatus ), "Error setting key" );

        ntStatus = pDh->sharedSecret( &blob2, buf1, cbP );
        CHECK( NT_SUCCESS( ntStatus ), "Error getting secret" );

        ntStatus = pDh->setKey( &blob2 );
        CHECK( NT_SUCCESS( ntStatus ), "Error setting key" );

        ntStatus = pDh->sharedSecret( &blob1, buf2, cbP );
        CHECK( NT_SUCCESS( ntStatus ), "Error getting secret" );

        CHECK( memcmp( buf1, buf2, cbP ) == 0, "Shared secret mismatch" );

        SymCryptDlkeyFree( pKey1 );
        pKey1 = NULL;

        SymCryptDlkeyFree( pKey2 );
        pKey2 = NULL;

        SymCryptDlgroupFree( pGroup );
        pGroup = NULL;
    }

    // Clear the key
    pDh->setKey( NULL );
}


VOID
testDhKats()
{
    // fix this.
    KatData *katDh = getCustomResource( "kat_dh.dat", "KAT_DH" );
    KAT_ITEM katItem;

    static String g_currentCategory;
    BOOL skipData = TRUE;
    String sep = "    ";
    BOOL doneAnything = FALSE;

    std::unique_ptr<DhMultiImp> pDhMultiImp;

    while( 1 )
    {
        katDh->getKatItem( & katItem );
        if( katItem.type == KAT_TYPE_END )
        {
            break;
        }

        if( katItem.type == KAT_TYPE_CATEGORY )
        {
            g_currentCategory = katItem.categoryName;
            pDhMultiImp.reset( new DhMultiImp( g_currentCategory ) );

            //
            // If we have no algorithms, we skip all the data until the next category
            //
            skipData = (pDhMultiImp->m_imps.size() == 0);
            if( !skipData )
            {
                iprint( "%s%s", sep.c_str(), g_currentCategory.c_str() );
                sep = ", ";
                doneAnything = TRUE;
            }

            //print( "%s, %d\n", g_currentCategory.c_str(), pDhMultiImp->m_imps.size() );
        }

        if( katItem.type == KAT_TYPE_DATASET && !skipData )
        {
            if( katIsFieldPresent( katItem, "p" ) )
            {
                BString P = katParseData( katItem, "p" );
                BString G = katParseData( katItem, "g" );
                BString Q;
                if( katIsFieldPresent( katItem, "q" ) )
                {
                    Q = katParseData( katItem, "q" );
                }
                BString X1 = katParseData( katItem, "x1" );
                BString H1 = katParseData( katItem, "h1" );
                BString X2 = katParseData( katItem, "x2" );
                BString H2 = katParseData( katItem, "h2" );
                BString secret = katParseData( katItem, "ss" );

                DLGROUP_TESTBLOB bGroup = {0};
                DLKEY_TESTBLOB bKey1;
                DLKEY_TESTBLOB bKey2;

                bGroup.nBitsP = (UINT32) P.size() * 8;
                bGroup.cbPrimeP = (UINT32) P.size();
                bGroup.cbPrimeQ = (UINT32) Q.size();

                CHECK( G.size() == bGroup.cbPrimeP, "Generator length mismatch" );

                memcpy( bGroup.abPrimeP, P.data(), bGroup.cbPrimeP );
                memcpy( bGroup.abPrimeQ, Q.data(), bGroup.cbPrimeQ );
                memcpy( bGroup.abGenG, G.data(), bGroup.cbPrimeP );

                bKey1.pGroup = &bGroup;
                bKey2.pGroup = &bGroup;

                bKey1.nBitsPriv = 0;
                bKey2.nBitsPriv = 0;

                bKey1.cbPrivKey = (UINT32) X1.size();
                bKey2.cbPrivKey = (UINT32) X2.size();

                CHECK( H1.size() == bGroup.cbPrimeP && H2.size() == bGroup.cbPrimeP, "Wrong public key sizes" );

                memcpy( bKey1.abPubKey, H1.data(), bGroup.cbPrimeP );
                memcpy( bKey2.abPubKey, H2.data(), bGroup.cbPrimeP );

                memcpy( bKey1.abPrivKey, X1.data(), bKey1.cbPrivKey );
                memcpy( bKey2.abPrivKey, X2.data(), bKey2.cbPrivKey );

                testDhSingle( pDhMultiImp.get(), &bKey1, &bKey2, secret.data(), secret.size() );

            } else if( katIsFieldPresent( katItem, "rnd" ) )
            {
                generateDlGroups();
                testDhtestGroups( pDhMultiImp.get(), katItem.line );
            } else {
                CHECK( FALSE, "Invalid KAT record" );
            }
        }
    }

    if( doneAnything )
    {
        iprint( "\n" );
    }

    delete katDh;
}

VOID
testDhAlgorithms()
{
    String sep;

    // Uncomment this function to generate a new KAT file
    //createKatFileDh();

    if( isAlgorithmPresent( "Dh", TRUE )  )
    {
        print("    testDlSimple static\n");
        testDlSimple();

        if (g_dynamicSymCryptModuleHandle != NULL)
        {
            print("    testDlSimple dynamic\n");
            g_useDynamicFunctionsInTestCall = TRUE;
            testDlSimple();
            g_useDynamicFunctionsInTestCall = FALSE;
        }
    }

    testDhKats();

    INT64 nOutstandingAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nOutstandingCheckedAllocs);
    CHECK3( nOutstandingAllocs == 0, "Memory leak %d", nOutstandingAllocs );
}

