//
// TestDh.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//


#include "precomp.h"

DLGROUP_TESTBLOB g_DlGroup[ MAX_TEST_DLGROUPS ] = {0};
UINT32 g_nDlgroups = 0;

// Creating DL groups for all DH and DSA tests that need random groups


VOID
addOneDlgroup( UINT32 nBitsP, BOOL randomQsize )
{
    // nBitsP = size of P
    SYMCRYPT_ERROR scError;
    PCSYMCRYPT_HASH hashAlgorithm;
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
        switch( b % 5 )
        {
        case 0: hashAlgorithm = SymCryptSha1Algorithm; break;
        case 1: hashAlgorithm = SymCryptSha256Algorithm; break;
        case 2: hashAlgorithm = SymCryptSha384Algorithm; break;
        case 3: hashAlgorithm = SymCryptSha512Algorithm; break;
        case 4: hashAlgorithm = NULL; break;
        }

        // Hash algorithm defaults to SHA-1
        SIZE_T nBitsHash = hashAlgorithm == NULL ? 160 : 8 * SymCryptHashResultSize( hashAlgorithm );

        if( randomQsize )
        {
            nBitsQ = (UINT32) g_rng.sizet( 128, hashAlgorithm != NULL ? nBitsHash + 1 : nBitsP );
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
    pGroup = NULL;
}

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

    char * sep = " [group gen: ";
    UINT32 previousSize = 0;

    if( g_nDlgroups >= MAX_TEST_DLGROUPS )
    {
        goto cleanup;
    }

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

PSYMCRYPT_DLGROUP
dlgroupObjectFromTestBlob( PCDLGROUP_TESTBLOB pBlob )
{
    SYMCRYPT_ERROR scError;

    PSYMCRYPT_DLGROUP pGroup = NULL;

    pGroup = SymCryptDlgroupAllocate( pBlob->nBitsP, 8*pBlob->cbPrimeQ );
    CHECK( pGroup != NULL, "Could not create group" );

    scError = SymCryptDlgroupSetValue(
        &pBlob->abPrimeP[0], pBlob->cbPrimeP,
        pBlob->cbPrimeQ == 0 ? NULL : &pBlob->abPrimeQ[0], pBlob->cbPrimeQ,
        &pBlob->abGenG[0], pBlob->cbPrimeP,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        pBlob->pHashAlgorithm,
        pBlob->cbSeed == 0 ? NULL : &pBlob->abSeed[0], pBlob->cbSeed,
        pBlob->genCounter,
        pBlob->fipsStandard,
        pGroup );

    CHECK( scError == SYMCRYPT_NO_ERROR, "Error setting group values" );

    return pGroup;
}

PCDLGROUP_TESTBLOB
dlgroupRandom()
{
    return &g_DlGroup[ g_rng.sizet( g_nDlgroups ) ];
}

PCDLGROUP_TESTBLOB
dlgroupForSize( SIZE_T nBits )
{
    for( UINT32 i=0; i<g_nDlgroups; i++ )
    {
        if( g_DlGroup[i].nBitsP == nBits )
        {
            return &g_DlGroup[i];
        }
    }
    CHECK3( FALSE, "Could not find group for %d bits", nBits );
    return NULL;
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

    PSYMCRYPT_DLGROUP pGroup = dlgroupObjectFromTestBlob( pBlob );

    PSYMCRYPT_DLKEY pKey1 = SymCryptDlkeyAllocate( pGroup );
    PSYMCRYPT_DLKEY pKey2 = SymCryptDlkeyAllocate( pGroup );
    
    scError = SymCryptDlkeyGenerate( 0, pKey1 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error generating DH key" );

    scError = SymCryptDlkeyGenerate( 0, pKey2 );
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

        scError = SymCryptDlkeyGenerate( 0, pKey1 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Error generating key" );
        scError = SymCryptDlkeyGenerate( SYMCRYPT_FLAG_DLKEY_GEN_MODP, pKey2 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Error generating key" );
        
        DLKEY_TESTBLOB  blob1;
        DLKEY_TESTBLOB  blob2;

        blob1.pGroup = pGroupBlob;
        blob2.pGroup = pGroupBlob;

        blob1.cbPrivKey = SymCryptDlkeySizeofPrivateKey( pKey1 );
        blob2.cbPrivKey = SymCryptDlkeySizeofPrivateKey( pKey2 );

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

    std::auto_ptr<DhMultiImp> pDhMultiImp;

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

    testDhKats();

    CHECK3( g_nOutstandingCheckedAllocs == 0, "Memory leak %d", g_nOutstandingCheckedAllocs );
}

