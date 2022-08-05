//
// TestDsa.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//


#include "precomp.h"


class DsaMultiImp: public DsaImplementation
{
public:
    DsaMultiImp( String algName );       // AlgName not needed, but kept for symmetry with other algorithm classes
    ~DsaMultiImp();

private:
    DsaMultiImp( const DsaMultiImp & );
    VOID operator=( const DsaMultiImp & );

public:
    typedef std::vector<DsaImplementation *> ImpPtrVector;

    virtual NTSTATUS setKey(
        _In_    PCDLKEY_TESTBLOB    pcKeyBlob ); // Returns an error if this key can't be handled.

    virtual NTSTATUS sign(
        _In_reads_( cbHash)     PCBYTE  pbHash,
                                SIZE_T  cbHash,             // Can be any size, but often = size of Q
        _Out_writes_( cbSig )   PBYTE   pbSig,
                                SIZE_T  cbSig );        // cbSig == cbModulus of group

    virtual NTSTATUS verify(
        _In_reads_( cbHash)     PCBYTE  pbHash,
                                SIZE_T  cbHash,
        _In_reads_( cbSig )     PCBYTE  pbSig,
                                SIZE_T  cbSig );

    ImpPtrVector m_imps;        // Implementations being tested
    ImpPtrVector m_comps;       // Implementations for current computation

};

DsaMultiImp::DsaMultiImp( String algName )
{
    m_algorithmName = algName;

    getAllImplementations<DsaImplementation>( algName, &m_imps );
}

DsaMultiImp::~DsaMultiImp()
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
DsaMultiImp::setKey(
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
DsaMultiImp::sign(
        _In_reads_( cbHash)     PCBYTE  pbHash,
                                SIZE_T  cbHash,
        _Out_writes_( cbSig )   PBYTE   pbSig,
                                SIZE_T  cbSig )
{
    // DSA signatures are not deterministic so we do the following:
    // - Have every implementation sign
    // - Have every implementation verify each signature
    // - return a random signature
    BYTE    sig[ DLKEY_MAXKEYSIZE ];
    int nSigs = 0;
    NTSTATUS ntStatus;

    CHECK( cbSig <= sizeof( sig ), "?" );

    GENRANDOM( sig, sizeof( sig ) );

    for( ImpPtrVector::iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        sig[0]++;
        ntStatus = (*i)->sign( pbHash, cbHash, &sig[0], cbSig );
        if( ntStatus == STATUS_NOT_SUPPORTED )
        {
            continue;
        }

        CHECK( ntStatus == STATUS_SUCCESS, "Failure during DSA signature" );
        for( ImpPtrVector::iterator j = m_comps.begin(); j != m_comps.end(); ++j )
        {
            ntStatus = (*j)->verify( pbHash, cbHash, &sig[0], cbSig );
            if( ntStatus == STATUS_NOT_SUPPORTED )
            {
                continue;
            }
            CHECK4( ntStatus == STATUS_SUCCESS, "DSA sig verification failure %s, %s",
                    (*i)->m_implementationName.c_str(),
                    (*j)->m_implementationName.c_str() );
        }

        // Copy a random sig to the output
        nSigs += 1;
        if( (g_rng.byte() % nSigs) == 0 )
        {
            memcpy( pbSig, &sig[0], cbSig );
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
DsaMultiImp::verify(
        _In_reads_( cbHash)     PCBYTE  pbHash,
                                SIZE_T  cbHash,
        _In_reads_( cbSig )     PCBYTE  pbSig,
                                SIZE_T  cbSig )
{
    ResultMerge res;
    NTSTATUS ntStatus;
    BYTE b[4];

    for( ImpPtrVector::iterator i = m_comps.begin(); i != m_comps.end(); ++i )
    {
        ntStatus = (*i)->verify( pbHash, cbHash, pbSig, cbSig );
        if( ntStatus == STATUS_NOT_SUPPORTED )
        {
            continue;
        }
        SYMCRYPT_STORE_MSBFIRST32( b, ntStatus );
        res.addResult( *i, b, 4 );
    }

    res.getResult( b, 4 );
    ntStatus = SYMCRYPT_LOAD_MSBFIRST32( b );
    return ntStatus;
}


VOID
createKatFileSingleDsa( FILE * f, PCDLGROUP_TESTBLOB pBlob )
{
    SYMCRYPT_ERROR scError;
    BYTE buf[ DLKEY_MAXKEYSIZE ];
    BYTE sig[ DLKEY_MAXKEYSIZE ];
    BYTE privKey[ DLKEY_MAXKEYSIZE ];

    PSYMCRYPT_DLGROUP pGroup = dlgroupObjectFromTestBlob<ImpSc>( pBlob );

    PSYMCRYPT_DLKEY pKey = SymCryptDlkeyAllocate( pGroup );

    scError = SymCryptDlkeyGenerate( SYMCRYPT_FLAG_DLKEY_DSA, pKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error generating DL key" );

    UINT32 cbPrivKey = SymCryptDlkeySizeofPrivateKey( pKey );

    fprintf( f, "P    = " );
    fprintHex( f, pBlob->abPrimeP, pBlob->cbPrimeP );
    fprintf( f, "G    = " );
    fprintHex( f, pBlob->abGenG, pBlob->cbPrimeP );

    CHECK( pBlob->cbPrimeQ > 0, "Can't do DSA without having Q" );
    fprintf( f, "Q    = " );
    fprintHex( f, pBlob->abPrimeQ, pBlob->cbPrimeQ );

    scError = SymCryptDlkeyGetValue(    pKey,
                                        privKey, cbPrivKey,
                                        buf, pBlob->cbPrimeP,
                                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                        0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error reading DL key" );
    fprintf( f, "X    = " );
    fprintHex( f, privKey, cbPrivKey );
    fprintf( f, "H    = " );
    fprintHex( f, buf, pBlob->cbPrimeP );

    UINT32 r = g_rng.uint32();
    UINT32 cbHash = 0;
    // Pick a random hash size.
    //
    switch( r % 11)
    {
    case 0: cbHash = 20; break;
    case 1: cbHash = 32; break;
    case 2: cbHash = 48; break;
    case 3: cbHash = 64; break;
    case 4: cbHash = (r % 59) + 6; break;   // 59 is prime, so this is orthoginal to the switch case

    case 5: case 6: case 7: case 8: case 9: case 10:
            cbHash = pBlob->cbPrimeQ;       // Customary and only size that CNG supports
            break;
    default: CHECK( FALSE, "?" );
    }

    GENRANDOM( buf, cbHash );
    scError = SymCryptDsaSign(  pKey,
                                buf, cbHash,
                                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                0,
                                sig, 2 * pBlob->cbPrimeQ );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error signing DSA" );

    fprintf( f, "Hash = " );
    fprintHex( f, buf, cbHash );

    fprintf( f, "Sig  = " );
    fprintHex( f, sig, 2 * pBlob->cbPrimeQ );

    fprintf( f, "\n" );

    SymCryptDlkeyFree( pKey );
    pKey = NULL;

    SymCryptDlgroupFree( pGroup );
    pGroup = NULL;
}


VOID
createKatFileDsa()
// This function is not normally used, but available for use whenever we want to re-generate
// new test vectors.
{
    FILE * f = fopen( "generated_kat_dsa.dat", "wt" );
    CHECK( f != NULL, "Could not create output file" );

    fprintf( f, "#\n"
                "# DO NOT EDIT: Generated test vectors for DSA\n"
                "#\n"
                "\n"
                );
    fprintf( f, "[Dsa]\n\n" );

    generateDlGroups();
    for( int i=g_nDhNamedGroups; i<MAX_TEST_DLGROUPS; i++ )
    {
        if( g_DlGroup[i].cbPrimeQ != 0 )
        {
            createKatFileSingleDsa( f, &g_DlGroup[ i ] );
        }
    }

    fprintf( f, "\n"
                "rnd = 1\n"
                "\n"
                );

    fclose( f );

    // Generating test vectors is not normal program flow, so we abort here to avoid getting into
    // non-standard states.
    CHECK( FALSE, "Written DSA test vector file" );
}


VOID
testDsaSingle(
                                DsaImplementation  * pDsa,
    _In_                        PCDLKEY_TESTBLOB    pKey,
    _In_reads_( cbHash)         PCBYTE  pbHash,
                                SIZE_T  cbHash,
    _In_reads_( cbSig )         PCBYTE  pbSig,
                                SIZE_T  cbSig,
                                UINT64  line )
{
    NTSTATUS ntStatus;
    BYTE buf[DLKEY_MAXKEYSIZE];

    UNREFERENCED_PARAMETER( line );
    // iprint( "<%d>", (UINT32)line );

    CHECK( cbHash < DLKEY_MAXKEYSIZE && cbSig < DLKEY_MAXKEYSIZE, "?" );

    SIZE_T cbP = pKey->pGroup->cbPrimeP;
    CHECK( cbP <= DLKEY_MAXKEYSIZE, "?" );

    ntStatus = pDsa->setKey( pKey );
    CHECK( NT_SUCCESS( ntStatus ), "Error setting key" );

    ntStatus = pDsa->verify( pbHash, cbHash, pbSig, cbSig );
    CHECK( NT_SUCCESS( ntStatus ), "Error verifying DSA signature" );

    // We have to be careful with modifying the hash value.
    // DSA truncates the hash, so the modification must be within the range of Q
    // As the truncation is to the bit size, we introduce a difference in the bytes
    // that are always relevant.
    memcpy( buf, pbHash, cbHash );
    buf[g_rng.sizet( SYMCRYPT_MIN( cbHash, pKey->pGroup->cbPrimeQ - 1 ) )]++;
    ntStatus = pDsa->verify( buf, cbHash, pbSig, cbSig );
    CHECK( !NT_SUCCESS( ntStatus ), "Success verifying modified DSA signature" );

    memcpy( buf, pbSig, cbSig );
    buf[g_rng.sizet( cbSig )]++;
    ntStatus = pDsa->verify( pbHash, cbHash, buf, cbSig );
    CHECK( !NT_SUCCESS( ntStatus ), "Success verifying modified DSA signature" );

    CHECK( pDsa->setKey( NULL ) == STATUS_SUCCESS, "Failed to clear key" );
}

VOID
testDsatestGroups( DsaImplementation  * pDsa, INT64 line )
{
    BYTE hash[DLKEY_MAXKEYSIZE];
    BYTE sig[DLKEY_MAXKEYSIZE];
    SYMCRYPT_ERROR scError;
    NTSTATUS ntStatus;

    UNREFERENCED_PARAMETER( line );

    generateDlGroups();

    for( int i=g_nDhNamedGroups; i<MAX_TEST_DLGROUPS; i++ )
    {
        PCDLGROUP_TESTBLOB pGroupBlob = &g_DlGroup[i];

        // We have a group; generate a key
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

        PSYMCRYPT_DLKEY pKey = SymCryptDlkeyAllocate( pGroup );
        CHECK( pKey != NULL, "Could not create keys" );

        scError = SymCryptDlkeyGenerate( SYMCRYPT_FLAG_DLKEY_DSA, pKey );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Error generating key" );

        DLKEY_TESTBLOB  blob;

        blob.pGroup = pGroupBlob;
        blob.nBitsPriv = 0;

        blob.cbPrivKey = SymCryptDlkeySizeofPrivateKey( pKey );

        scError = SymCryptDlkeyGetValue(
                pKey,
                &blob.abPrivKey[0], blob.cbPrivKey,
                &blob.abPubKey[0], cbP,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "Error exporting key" );

        ntStatus = pDsa->setKey( &blob );
        CHECK( NT_SUCCESS( ntStatus ), "Error setting key" );

        UINT32 r = g_rng.uint32();
        UINT32 cbHash = 0;
        switch( r % 11)
        {
        case 0: cbHash = 20; break;
        case 1: cbHash = 32; break;
        case 2: cbHash = 48; break;
        case 3: cbHash = 64; break;
        case 4: cbHash = (r % 59) + 6; break;   // 59 is prime, so this is orthoginal to the switch case

        case 5: case 6: case 7: case 8: case 9: case 10:
                cbHash = pGroupBlob->cbPrimeQ;       // Customary and only size that CNG supports
                break;
        default: CHECK( FALSE, "?" );
        }

        GENRANDOM( hash, cbHash );

        UINT32 cbSig = 2 * pGroupBlob->cbPrimeQ;
        CHECK( cbSig > 0, "?" );

        ntStatus = pDsa->sign( hash, cbHash, sig, cbSig );
        CHECK( NT_SUCCESS( ntStatus ), "?" );

        // Modify the hash, but only in the bytes that are known to be used
        SIZE_T j = g_rng.sizet( SYMCRYPT_MIN( cbHash, pGroupBlob->cbPrimeQ - 1) );
        hash[j]++;
        ntStatus = pDsa->verify( hash, cbHash, sig, cbSig );
        hash[j]--;
        CHECK( !NT_SUCCESS( ntStatus ), "?" );

        j = g_rng.sizet( cbSig );
        sig[j]--;
        ntStatus = pDsa->verify( hash, cbHash, sig, cbSig );
        sig[j]++;
        CHECK( !NT_SUCCESS( ntStatus ), "?" );

        ntStatus = pDsa->verify( hash, cbHash, sig, cbSig );
        CHECK( NT_SUCCESS( ntStatus ), "?" );

        SymCryptDlkeyFree( pKey );
        pKey = NULL;

        SymCryptDlgroupFree( pGroup );
        pGroup = NULL;
    }

    // Clear the key
    pDsa->setKey( NULL );
}


VOID
testDsaKats()
{
    // fix this.
    KatData *katDsa = getCustomResource( "kat_dsa.dat", "KAT_DSA" );
    KAT_ITEM katItem;

    static String g_currentCategory;
    BOOL skipData = TRUE;
    String sep = "    ";
    BOOL doneAnything = FALSE;

    std::unique_ptr<DsaMultiImp> pDsaMultiImp;

    while( 1 )
    {
        katDsa->getKatItem( & katItem );
        if( katItem.type == KAT_TYPE_END )
        {
            break;
        }

        if( katItem.type == KAT_TYPE_CATEGORY )
        {
            g_currentCategory = katItem.categoryName;
            pDsaMultiImp.reset( new DsaMultiImp( g_currentCategory ) );

            //
            // If we have no algorithms, we skip all the data until the next category
            //
            skipData = (pDsaMultiImp->m_imps.size() == 0);
            if( !skipData )
            {
                iprint( "%s%s", sep.c_str(), g_currentCategory.c_str() );
                sep = ", ";
                doneAnything = TRUE;
            }

            //print( "%s, %d\n", g_currentCategory.c_str(), pDsaMultiImp->m_imps.size() );
        }

        if( katItem.type == KAT_TYPE_DATASET && !skipData )
        {
            if( katIsFieldPresent( katItem, "p" ) )
            {
                BString P = katParseData( katItem, "p" );
                BString G = katParseData( katItem, "g" );
                BString Q = katParseData( katItem, "q" );

                BString X = katParseData( katItem, "x" );
                BString H = katParseData( katItem, "h" );
                BString Hash = katParseData( katItem, "hash" );
                BString Sig = katParseData( katItem, "sig" );

                DLGROUP_TESTBLOB bGroup = {0};
                DLKEY_TESTBLOB bKey;

                bGroup.nBitsP = (UINT32) P.size() * 8;
                bGroup.cbPrimeP = (UINT32) P.size();
                bGroup.cbPrimeQ = (UINT32) Q.size();

                CHECK( G.size() == bGroup.cbPrimeP, "Generator length mismatch" );

                memcpy( bGroup.abPrimeP, P.data(), bGroup.cbPrimeP );
                memcpy( bGroup.abPrimeQ, Q.data(), bGroup.cbPrimeQ );
                memcpy( bGroup.abGenG, G.data(), bGroup.cbPrimeP );

                bKey.pGroup = &bGroup;
                bKey.nBitsPriv = 0;

                bKey.cbPrivKey = (UINT32) X.size();

                CHECK( H.size() == bGroup.cbPrimeP, "Wrong public key sizes" );

                memcpy( bKey.abPubKey, H.data(), bGroup.cbPrimeP );
                memcpy( bKey.abPrivKey, X.data(), bKey.cbPrivKey );

                testDsaSingle( pDsaMultiImp.get(), &bKey, Hash.data(), Hash.size(), Sig.data(), Sig.size(), katItem.line );

            } else if( katIsFieldPresent( katItem, "rnd" ) )
            {
                generateDlGroups();
                testDsatestGroups( pDsaMultiImp.get(), katItem.line );
            } else {
                CHECK( FALSE, "Invalid KAT record" );
            }
        }
    }

    if( doneAnything )
    {
        iprint( "\n" );
    }

    delete katDsa;
}


VOID
testDsaAlgorithms()
{

    // Uncomment this function to generate a new KAT file
    // createKatFileDsa();

    testDsaKats();

    INT64 nOutstandingAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64( &g_nOutstandingCheckedAllocs );
    CHECK3( nOutstandingAllocs == 0, "Memory leak %d", nOutstandingAllocs );
}

