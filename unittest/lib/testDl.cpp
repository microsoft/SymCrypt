//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"
#include "testInterop.h"

TEST_DL_BITSIZEENTRY g_DlBitSizes[] = {
    { 512, 160 },
    { 768, 0 },
    { 960, 160 },       // Multiple of 64
    { 1024, 160 },
    { 1536, 256 },
    { 2048, 256 },
};

#define TEST_DL_KEYSIZES                (ARRAY_SIZE(g_DlBitSizes))
#define TEST_DL_NUMOF_ENTRIES           (TEST_DL_KEYSIZES * TEST_INTEROP_NUMOF_IMPS)
#define TEST_DL_NUMOF_RANDOM_TRIES      (20)

// List with all the RSA keys
TEST_DL_KEYENTRY g_DlKeyEntries[TEST_DL_NUMOF_ENTRIES] = { 0 };

// List with all the functional DL implementations
AlgorithmImplementationVector g_DlAlgList;

// This is needed for the test to find out which
// hash algorithm to pick when nBitsOfQ == 0.
struct _NBITSOFQ_CUTOFFS {
    UINT32 nBitsOfP;
    UINT32 nBitsOfQ;
} g_nBitsOfQ_Cutoffs[] = {
    { 1024, 160 },
    { 2048, 256 },
    { UINT32_MAX, 256 },
};

UINT32
SYMCRYPT_CALL
testDlCalculateBitsizeOfQ( UINT32 nBitsOfP )
{
    UINT32 i = 0;
    while ( (i<ARRAY_SIZE(g_nBitsOfQ_Cutoffs) - 1) &&
            (g_nBitsOfQ_Cutoffs[i].nBitsOfP < nBitsOfP) )
    {
        i++;
    };

    return g_nBitsOfQ_Cutoffs[i].nBitsOfQ;
}

VOID printOneDlParam( PBYTE pbBlob, SIZE_T cbBlob)
{
    if (cbBlob > 32)
    {
        vprint(g_verbose, "%02X%02X...%02X", pbBlob[0], pbBlob[1], pbBlob[cbBlob-1]);
    }
    else
    {
        for (UINT32 i=0; i<cbBlob; i++)
        {
            vprint(g_verbose, "%02X", pbBlob[i]);
        }
    }
    vprint(g_verbose, "\n");
}

VOID printDlGroup( PCSYMCRYPT_DLGROUP pDlgroup )
{
    SYMCRYPT_ERROR scError;

    PBYTE  pbPrimeP = 0;
    SIZE_T cbPrimeP = 0;
    PBYTE  pbPrimeQ = 0;
    SIZE_T cbPrimeQ = 0;
    PBYTE  pbGenG = 0;
    SIZE_T cbGenG = 0;
    PBYTE  pbSeed = 0;
    SIZE_T cbSeed = 0;

    PCSYMCRYPT_HASH pHashAlgorithm = NULL;
    UINT32 genCounter = 0;

    PBYTE pbBlob = NULL;
    SIZE_T cbBlob = 0;

    SymCryptDlgroupGetSizes(
            pDlgroup,
            &cbPrimeP,
            &cbPrimeQ,
            &cbGenG,
            &cbSeed );

    cbBlob = cbPrimeP + cbPrimeQ + cbGenG + cbSeed;
    pbBlob = (PBYTE) SymCryptCallbackAlloc( cbBlob );
    CHECK( pbBlob != NULL, "?" );

    // Set the pointers
    pbPrimeP = pbBlob;
    pbPrimeQ = (cbPrimeQ==0)?(NULL):(&pbBlob[cbPrimeP]);
    pbGenG = &pbBlob[cbPrimeP + cbPrimeQ];
    pbSeed = (cbSeed==0)?(NULL):(&pbBlob[cbPrimeP+cbPrimeQ+cbGenG]);

    scError = SymCryptDlgroupGetValue(
                    pDlgroup,
                    pbPrimeP,
                    cbPrimeP,
                    pbPrimeQ,
                    cbPrimeQ,
                    pbGenG,
                    cbGenG,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    &pHashAlgorithm,
                    pbSeed,
                    cbSeed,
                    &genCounter );
    CHECK( scError==SYMCRYPT_NO_ERROR, "?" );

    vprint(g_verbose, "DlGroup (L,N)=(%d,%d) %s @ %d \n", pDlgroup->nBitsOfP, pDlgroup->nBitsOfQ, testInteropHashAlgToString(pHashAlgorithm), genCounter);

    vprint(g_verbose, "  P          (%3d): ", cbPrimeP );
    printOneDlParam( pbPrimeP, cbPrimeP );

    if (pbPrimeQ!=NULL)
    {
        vprint(g_verbose, "  Q          (%3d): ", cbPrimeQ );
        printOneDlParam( pbPrimeQ, cbPrimeQ );
    }
    else
    {
        vprint(g_verbose, "  Q          (  0): -\n" );
    }

    vprint(g_verbose, "  G          (%3d): ", cbGenG );
    printOneDlParam( pbGenG, cbGenG );

    if (pbSeed!=NULL)
    {
        vprint(g_verbose, "  Seed       (%3d): ", cbSeed );
        printOneDlParam( pbSeed, cbSeed );
    }
    else
    {
        vprint(g_verbose, "  Seed       (  0): -\n" );
    }

    SymCryptWipe( pbBlob, cbBlob );
    SymCryptCallbackFree( pbBlob );
}

VOID printDlKey( PSYMCRYPT_DLKEY pkDlkey )
{
    SYMCRYPT_ERROR scError;

    SIZE_T cbPublicKey = 0;
    SIZE_T cbPrivateKey = 0;

    PBYTE pbBlob = NULL;
    SIZE_T cbBlob = 0;

    cbPublicKey = SymCryptDlkeySizeofPublicKey( pkDlkey );
    cbPrivateKey = SymCryptDlkeySizeofPrivateKey( pkDlkey );

    cbBlob = cbPublicKey + cbPrivateKey;
    pbBlob = (PBYTE) SymCryptCallbackAlloc( cbBlob );
    CHECK( pbBlob != NULL, "?" );

    scError = SymCryptDlkeyGetValue(
                    pkDlkey,
                    pbBlob,
                    cbPrivateKey,
                    pbBlob + cbPrivateKey,
                    cbPublicKey,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0 );
    CHECK( scError==SYMCRYPT_NO_ERROR, "?" );

    vprint(g_verbose, "  Private Key(%3d): ", cbPrivateKey );
    printOneDlParam( &pbBlob[0], cbPrivateKey );

    vprint(g_verbose, "  Public Key (%3d): ", cbPublicKey );
    printOneDlParam( &pbBlob[cbPrivateKey], cbPublicKey );

    SymCryptWipe( pbBlob, cbBlob );
    SymCryptCallbackFree( pbBlob );
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

    BYTE rbSignature[2*TEST_DL_MAX_NUMOF_BYTES];
    SIZE_T cbSignature = 0;

    for (UINT32 i = 0; i<ARRAY_SIZE(g_DlBitSizes); i++)
    {
        nBitsOfP = g_DlBitSizes[i].nBitsOfP;
        nBitsOfQ = g_DlBitSizes[i].nBitsOfQ;
        nBitsOfQActual = (nBitsOfQ==0)?testDlCalculateBitsizeOfQ( nBitsOfP ):nBitsOfQ;

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
                pHashAlgorithm = testInteropRandomHash();
                cbHashValue = SymCryptHashResultSize(pHashAlgorithm);
            } while ((8*cbHashValue < nBitsOfQActual) ||
                     (8*cbHashValue > nBitsOfP) );
        }

        // Allocate and generate a DLGROUP
        pDlgroup = SymCryptDlgroupAllocate( nBitsOfP, nBitsOfQ );
        CHECK( pDlgroup!=NULL, "?");

        scError = SymCryptDlgroupGenerate( pHashAlgorithm, eFipsStandard, pDlgroup );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

        vprint(g_verbose, "\nGenerated ");
        printDlGroup( pDlgroup );

        // DLKEY
        pkDlkey = SymCryptDlkeyAllocate( pDlgroup );
        CHECK( pkDlkey!=NULL, "?");

        scError = SymCryptDlkeyGenerate( SYMCRYPT_FLAG_DLKEY_DSA, pkDlkey );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

        printDlKey( pkDlkey );

        // DSA sign and verify
        scError = SymCryptCallbackRandom(rbHashValue, cbHashValue);
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

        cbSignature = 2*SymCryptDlkeySizeofPrivateKey(pkDlkey);

        scError = SymCryptDsaSign(
                        pkDlkey,
                        rbHashValue,
                        cbHashValue,
                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                        0,
                        rbSignature,
                        cbSignature );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

        scError = SymCryptDsaVerify(
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
        scError = SymCryptDsaVerify(
                        pkDlkey,
                        rbHashValue,
                        cbHashValue,
                        rbSignature,
                        cbSignature,
                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                        0 );
        CHECK( scError == SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE, "?" );

        // Get the group parameters in a blob
        SymCryptDlgroupGetSizes(
            pDlgroup,
            &cbExpP,
            &cbExpQ,
            &cbExpG,
            &cbExpS );

        cbBlob = cbExpP + cbExpQ + cbExpG + cbExpS;
        pbBlob = (PBYTE) SymCryptCallbackAlloc( cbBlob );
        CHECK( pbBlob != NULL, "?" );

        scError = SymCryptDlgroupGetValue(
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
        scError = SymCryptDlgroupSetValue(
                        pbBlob,
                        cbExpP,
                        NULL,
                        0,
                        NULL,
                        0,
                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                        NULL,
                        NULL,
                        0,
                        0,
                        SYMCRYPT_DLGROUP_FIPS_NONE,
                        pDlgroup );
        CHECK( scError==SYMCRYPT_INVALID_ARGUMENT, "?" );

        // Set its value with P and G (it should succeed)
        scError = SymCryptDlgroupSetValue(
                        pbBlob,
                        cbExpP,
                        NULL,
                        0,
                        pbBlob + cbExpP + cbExpQ,
                        cbExpG,
                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                        NULL,
                        NULL,
                        0,
                        0,
                        SYMCRYPT_DLGROUP_FIPS_NONE,
                        pDlgroup );
        CHECK( scError==SYMCRYPT_NO_ERROR, "?" );

        vprint(g_verbose, "\n(P, -, G) ");
        printDlGroup( pDlgroup );

        // Create a new key and make sure it is mod P
        scError = SymCryptDlkeyGenerate( SYMCRYPT_FLAG_DLKEY_DSA, pkDlkey );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

        CHECK(SymCryptDlkeySizeofPrivateKey(pkDlkey) == cbExpP, "?")

        printDlKey( pkDlkey );

        // Set its value with P and Q (it should succeed and generate a new G)
        scError = SymCryptDlgroupSetValue(
                        pbBlob,
                        cbExpP,
                        pbBlob + cbExpP,
                        cbExpQ,
                        NULL,
                        0,
                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                        NULL,
                        NULL,
                        0,
                        0,
                        SYMCRYPT_DLGROUP_FIPS_NONE,
                        pDlgroup );
        CHECK( scError==SYMCRYPT_NO_ERROR, "?" );

        vprint(g_verbose, "\n(P, Q, G) ");
        printDlGroup( pDlgroup );

        // Flip one byte of the seed
        *(&pbBlob[cbExpP + cbExpQ + cbExpG]) = *(&pbBlob[cbExpP + cbExpQ + cbExpG]) ^ 0xff;

        // Set its value with P, Q, and G with bogus seed but no verify flag.
        // It should succeed
        scError = SymCryptDlgroupSetValue(
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

        vprint(g_verbose, "\n(P,Q,G) w/o Ver. ");
        printDlGroup( pDlgroup );

        // Set its value with P, Q, and G with bogus seed and verify flag.
        // It should fail
        scError = SymCryptDlgroupSetValue(
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
        scError = SymCryptDlgroupSetValue(
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

        vprint(g_verbose, "\n(P,Q,G) w/ Ver. ");
        printDlGroup( pDlgroup );

        // Create a new key and use the mod P flag
        scError = SymCryptDlkeyGenerate( SYMCRYPT_FLAG_DLKEY_GEN_MODP | SYMCRYPT_FLAG_DLKEY_DSA, pkDlkey );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

        CHECK(SymCryptDlkeySizeofPrivateKey(pkDlkey) == cbExpP, "?")

        printDlKey( pkDlkey );

        SymCryptDlkeyFree( pkDlkey );
        SymCryptDlgroupFree( pDlgroup );

        SymCryptWipe(pbBlob, cbBlob);
        SymCryptCallbackFree(pbBlob);
    }
}

VOID testDlFillKeyEntryParameters( PTEST_DL_KEYENTRY pKeyEntry, PTEST_DL_BITSIZEENTRY pBitSizeEntry )
{
    UINT32 nBitsOfP = pBitSizeEntry->nBitsOfP;
    UINT32 nBitsOfQSet = pBitSizeEntry->nBitsOfQ;
    UINT32 nBitsOfQ = (nBitsOfQSet==0)?testDlCalculateBitsizeOfQ(nBitsOfP):nBitsOfQSet;

    pKeyEntry->nBitsOfP = nBitsOfP;
    pKeyEntry->cbPrimeP = (nBitsOfP+7)/8;

    CHECK(pKeyEntry->cbPrimeP<=TEST_DL_MAX_NUMOF_BYTES, "?");

    pKeyEntry->nBitsOfQ = nBitsOfQ;
    pKeyEntry->cbPrimeQ = (nBitsOfQ+7)/8;

    CHECK(pKeyEntry->cbPrimeQ<=TEST_DL_MAX_NUMOF_BYTES, "?");

    pKeyEntry->nBitsOfQSet = nBitsOfQSet;

    // Pick the hash algorithm and the standard according to CNG's hard coded values
    if (nBitsOfP > 1024)
    {
        pKeyEntry->eFipsStandard = SYMCRYPT_DLGROUP_FIPS_186_3;
        pKeyEntry->pHashAlgorithm = SymCryptSha256Algorithm;
    }
    else
    {
        pKeyEntry->eFipsStandard = SYMCRYPT_DLGROUP_FIPS_186_2;
        pKeyEntry->pHashAlgorithm = NULL;
    }
}

VOID testDlGenerateOneKey( PTEST_DL_KEYENTRY pKeyEntry, UINT32 iImpl )
{
    vprint( g_verbose,  "    > KeyGen (Proper) -- (L,N) = (%4d,%4d) Impl: %s\n",
             pKeyEntry->nBitsOfP,
             pKeyEntry->nBitsOfQ,
             g_Implementations[iImpl].name );

    switch( iImpl )
    {
        // SymCrypt
        case 0:
            algImpTestInteropGenerateKeyEntry<ImpSc>((PBYTE)pKeyEntry);
            algImpTestInteropFillKeyEntryBuffers<ImpSc>((PBYTE)pKeyEntry);
            break;

        // MsBignum
        case 1:
            algImpTestInteropGenerateKeyEntry<ImpMsBignum>((PBYTE)pKeyEntry);
            algImpTestInteropFillKeyEntryBuffers<ImpMsBignum>((PBYTE)pKeyEntry);
            break;

        // Cng
        case 2:
            algImpTestInteropGenerateKeyEntry<ImpCng>((PBYTE)pKeyEntry);
            algImpTestInteropFillKeyEntryBuffers<ImpCng>((PBYTE)pKeyEntry);
            break;

        default:
            CHECK3(FALSE, "TestDl: Unknown implementation %d\n", iImpl);
    }
}

VOID testDlImportOneKey( PTEST_DL_KEYENTRY pKeyEntry, UINT32  iImpl )
{
    vprint( g_verbose,  "    >>>> Import to: %s\n", g_Implementations[iImpl].name );

    switch (iImpl)
    {
        // SymCrypt
        case 0:
            algImpTestInteropImportKeyEntryBuffers<ImpSc>((PBYTE)pKeyEntry);
            break;

        // MsBignum
        case 1:
            algImpTestInteropImportKeyEntryBuffers<ImpMsBignum>((PBYTE)pKeyEntry);
            break;

        // Cng
        case 2:
            algImpTestInteropImportKeyEntryBuffers<ImpCng>((PBYTE)pKeyEntry);
            break;

        default:
            CHECK3(FALSE, "TestDl: Unknown implementation %d\n", iImpl);
    }
}

VOID testDlGenerateKeys()
{
    vprint( g_verbose, "\n");

    // Allocating the keys
    for ( UINT32 iSize = 0; iSize<TEST_DL_KEYSIZES; iSize++ )
    {
        for( UINT32 iImplFrom = 0; iImplFrom<TEST_INTEROP_NUMOF_IMPS; iImplFrom++ )
        {
            UINT32 iKeyEntry = iSize*TEST_INTEROP_NUMOF_IMPS + iImplFrom;

            testDlFillKeyEntryParameters(&g_DlKeyEntries[iKeyEntry], &g_DlBitSizes[iSize] );

            testDlGenerateOneKey(&g_DlKeyEntries[iKeyEntry], iImplFrom);

            // Convert it to other implementations
            for (UINT32 iImplTo = 0; iImplTo<TEST_INTEROP_NUMOF_IMPS; iImplTo++)
            {
                if (iImplFrom != iImplTo)
                {
                    testDlImportOneKey(&g_DlKeyEntries[iKeyEntry], iImplTo );
                }
            }
        }
    }
}

VOID testDlPopulateAlgorithms()
{
    // The order specifies the order of the from implementations

    addImplementationToList<FunctionalInteropImp<ImpSc, AlgDsaSign>>(&g_DlAlgList);
    addImplementationToList<FunctionalInteropImp<ImpMsBignum, AlgDsaSign>>(&g_DlAlgList);
    addImplementationToList<FunctionalInteropImp<ImpCng, AlgDsaSign>>(&g_DlAlgList);

    addImplementationToList<FunctionalInteropImp<ImpSc, AlgDh>>(&g_DlAlgList);
    addImplementationToList<FunctionalInteropImp<ImpCng, AlgDh>>(&g_DlAlgList);

}

VOID testDlRunAlgs()
{
    BYTE    rbInput[TEST_DL_MAX_NUMOF_BYTES] = { 0 };
    SIZE_T  cbInput = 0;

    BYTE    rbOutput[2*TEST_DL_MAX_NUMOF_BYTES] = { 0 };
    SIZE_T  cbOutput = 0;

    BYTE    rbExtra[TEST_DL_MAX_NUMOF_BYTES] = { 0 };
    SIZE_T  cbExtra = 0;

    PCSYMCRYPT_HASH pHashAlgorithm = NULL;

    InteropRandFn randFunc = NULL;
    InteropDataFn queryFn = NULL;      // Sign function
    InteropDataFn replyFn = NULL;      // Verify function

    UINT32 iImplFrom = 0;
    UINT32 iImplTo = 0;

    vprint( g_verbose, "\n");

    for( std::vector<AlgorithmImplementation *>::iterator i = g_DlAlgList.begin(); i != g_DlAlgList.end(); i++ )
    {
        iImplFrom = testInteropImplToInd( *i );

        vprint( g_verbose,  "    > Algorithm: %s From: %s\n", (*i)->m_algorithmName.c_str(), g_Implementations[iImplFrom].name );

        randFunc = ((FunctionalInteropImplementation *)(*i))->m_RandFunction;
        CHECK( randFunc != NULL, "No randomizing function.\n");

        queryFn = ((FunctionalInteropImplementation *)(*i))->m_QueryFunction;
        CHECK( queryFn != NULL, "No encryption / signing function.\n");

        for( std::vector<AlgorithmImplementation *>::iterator j = g_DlAlgList.begin(); j != g_DlAlgList.end(); j++ )
        {
            // Run tests if the algorithms are the same and at least one implementation is SymCrypt
            if (( (*i)->m_algorithmName == (*j)->m_algorithmName ) &&
                ( ((*i)->m_implementationName == ImpSc::name) || ((*j)->m_implementationName == ImpSc::name) ))
            {
                iImplTo = testInteropImplToInd( *j );

                replyFn = ((FunctionalInteropImplementation *)(*j))->m_ReplyFunction;
                CHECK( replyFn != NULL, "No decryption/verify function.\n");

                vprint( g_verbose,  "    >>>> To: %s\n", g_Implementations[iImplTo].name );

                for (UINT32 entry = 0; entry < TEST_DL_NUMOF_ENTRIES; entry++)
                {
                    for (UINT32 nTries = 0; nTries<TEST_DL_NUMOF_RANDOM_TRIES; nTries++)
                    {
                        (*randFunc)(
                            (PBYTE) &g_DlKeyEntries[entry],
                            rbInput,
                            &cbInput,
                            rbOutput,
                            &cbOutput,
                            rbExtra,
                            &cbExtra,
                            &pHashAlgorithm );

                        (*queryFn)(
                            (PBYTE) &g_DlKeyEntries[entry],
                            rbInput,
                            cbInput,
                            rbOutput,
                            cbOutput,
                            rbExtra,
                            cbExtra,
                            pHashAlgorithm );

                        (*replyFn)(
                            (PBYTE) &g_DlKeyEntries[entry],
                            rbInput,
                            cbInput,
                            rbOutput,
                            cbOutput,
                            rbExtra,
                            cbExtra,
                            pHashAlgorithm );

                        (*i)->m_nResults ++;
                    }
                }
            }
        }
    }
}

VOID testDlCleanKeys()
{
    for (UINT32 i = 0; i<TEST_DL_NUMOF_ENTRIES; i++)
    {
        algImpTestInteropCleanKeyEntry<ImpSc>((PBYTE)&g_DlKeyEntries[i]);
        algImpTestInteropCleanKeyEntry<ImpMsBignum>((PBYTE)&g_DlKeyEntries[i]);
        algImpTestInteropCleanKeyEntry<ImpCng>((PBYTE)&g_DlKeyEntries[i]);
    }
}

VOID testDlPrintResults()
{
    iprint("\n    Total Verified Interop Samples\n    ==============================\n");
    iprint("    %12s/%-8s   %s\n", "Algorithm", "FromImpl", "#");
    for( std::vector<AlgorithmImplementation *>::iterator i = g_DlAlgList.begin(); i != g_DlAlgList.end(); i++ )
    {
        iprint( "    %12s/%-8s : %llu\n", (*i)->m_algorithmName.c_str(), (*i)->m_implementationName.c_str(), (*i)->m_nResults );
    }
}

VOID testDl()
{
    static BOOL hasRun = FALSE;

    INT64 nAllocs = 0;

    //SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    if( hasRun )
    {
        return;
    }
    hasRun = TRUE;

    // Skip if there is no Dsa or Dh algorithm to test.
    if( !isAlgorithmPresent( "Dsa", TRUE ) && !isAlgorithmPresent( "Dh", TRUE ) )
    {
        return;
    }

    iprint( "    Discrete Log (DSA and DH)\n" );

    nAllocs = g_nAllocs;

    CHECK( g_nOutstandingCheckedAllocs == 0, "Memory leak" );
    CHECK( g_nOutstandingCheckedAllocsMsBignum == 0, "Memory leak MsBignum" );

    testDlSimple();

    testDlGenerateKeys();

    testDlPopulateAlgorithms();

    testDlRunAlgs();

    testDlCleanKeys();

    CHECK3( g_nOutstandingCheckedAllocs == 0, "Memory leak, %d outstanding", (unsigned) g_nOutstandingCheckedAllocs );
    CHECK3( g_nOutstandingCheckedAllocsMsBignum == 0, "Memory leak MsBignum, %d outstanding", (unsigned) g_nOutstandingCheckedAllocsMsBignum );

    testDlPrintResults();

    iprint( "\n" );
}