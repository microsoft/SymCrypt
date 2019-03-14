//
// TestIEEE802_11SaeCustom.cpp
//
// Copyright (c) Microsoft Corporation.  All rights reserved.
//

#include "precomp.h"

VOID
testSaeCustom(
        ArithImplementation *       pAlgImp,
    _In_reads_(cbPassword)  PCBYTE  pbPassword,
                            SIZE_T  cbPassword,                
    _In_reads_(6)           PCBYTE  pbMACa,
    _In_reads_(6)           PCBYTE  pbMACb,
                            BYTE    bCounter,
    _In_reads_(32)          PCBYTE  pbRandom,
    _In_reads_(32)          PCBYTE  pbMask,
    _In_reads_(32)          PCBYTE  pbCommitScalar,
    _In_reads_(64)          PCBYTE  pbCommitElement,
    _In_reads_(32)          PCBYTE  pbPeerScalar,
    _In_reads_(64)          PCBYTE  pbPeerElement,
    _In_reads_(32)          PCBYTE  pbSharedSecret,
    _In_reads_(32)          PCBYTE  pbScalarSum )
{
    SYMCRYPT_802_11_SAE_CUSTOM_STATE state;
    SYMCRYPT_ERROR scError;
    BYTE cnt;
    BYTE abScalar[32];
    BYTE abElement[64];
    BYTE abSharedSecret[32];
    BYTE abScalarSum[32];

    scError = SymCrypt802_11SaeCustomInit(  &state,
                                            pbMACa,
                                            pbMACb,
                                            pbPassword,
                                            cbPassword,
                                            &cnt,
                                            (PBYTE) pbRandom,
                                            (PBYTE) pbMask );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in 802_11SaeCustomInit" );

    CHECK4( cnt == bCounter, "Counter mismatch %02x, %02x", cnt, bCounter );

    scError = SymCrypt802_11SaeCustomCommitCreate( &state, abScalar, abElement );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in 802_11SaeCustomCommitCreate" );

    //iprint( "\n" );
    //printHex( abScalar, 32 );
    //iprint( "\n" );
    //printHex( abElement, 64 );
    //iprint( "\n" );

    CHECK( memcmp( abScalar, pbCommitScalar, 32) == 0, "Commit scalar error" );
    CHECK( memcmp( abElement, pbCommitElement, 64) == 0, "Commit element error" );


    scError = SymCrypt802_11SaeCustomCommitProcess( &state, pbPeerScalar, pbPeerElement, abSharedSecret, abScalarSum );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in 802_11SaeCustomCommitProcess" );

    CHECK( memcmp( abScalarSum, pbScalarSum, 32) == 0, "Scalar sum error" );
    CHECK( memcmp( abSharedSecret, pbSharedSecret, 32) == 0, "Shared secret error" );

    pAlgImp->m_nResults++;
}

VOID
testSaeCustomConsistency( ArithImplementation * pAlgImp )
{
    BYTE abMac1[6];
    BYTE abMac2[6];
    BYTE abPassword[32];
    SIZE_T cbPassword;

    SYMCRYPT_802_11_SAE_CUSTOM_STATE stateA;
    SYMCRYPT_802_11_SAE_CUSTOM_STATE stateB;

    BYTE abCommitScalarA[ 32 ];
    BYTE abCommitElementA[ 64 ];
    BYTE abCommitScalarB[ 32 ];
    BYTE abCommitElementB[ 64 ];
    BYTE abSharedA[ 32 ];
    BYTE abSumA[ 32 ];
    BYTE abSharedB[ 32 ];
    BYTE abSumB[ 32 ];

    for( int iTest = 0; iTest < 100; iTest++ )
    {
        GENRANDOM( abMac1, sizeof( abMac1 ) );
        GENRANDOM( abMac2, sizeof( abMac2 ) );
        GENRANDOM( &cbPassword, sizeof( cbPassword ) );
        cbPassword &= 31;
        GENRANDOM( abPassword, sizeof( abPassword ) );

        // Actor A creates a commit
        SymCrypt802_11SaeCustomInit( &stateA, abMac1, abMac2, abPassword, cbPassword, NULL, NULL, NULL );
        SymCrypt802_11SaeCustomCommitCreate( &stateA, abCommitScalarA, abCommitElementA );

        // Actor B processes it
        SymCrypt802_11SaeCustomInit( &stateB, abMac2, abMac1, abPassword, cbPassword, NULL, NULL, NULL );
        SymCrypt802_11SaeCustomCommitCreate( &stateB, abCommitScalarB, abCommitElementB );
        SymCrypt802_11SaeCustomCommitProcess( &stateB, abCommitScalarA, abCommitElementA, abSharedB, abSumB );

        SymCrypt802_11SaeCustomCommitProcess( &stateA, abCommitScalarB, abCommitElementB, abSharedA, abSumA );

        CHECK( memcmp( abSharedA, abSharedB, 32 ) == 0, "Shared secret mismatch" );
        CHECK( memcmp( abSumA, abSumB, 32 ) == 0, "Scalar sum mismatch" );

        pAlgImp->m_nResults++;
    }
}

VOID
testSaeCustomNegative( 
                    ArithImplementation *   pAlgImp,
    _In_reads_(32)  PCBYTE                  pbPeerScalar,
    _In_reads_(64)  PCBYTE                  pbPeerElement )
{
    BYTE abMac1[6];
    BYTE abMac2[6];
    BYTE abPassword[32];
    SIZE_T cbPassword;
    SYMCRYPT_ERROR scError;

    SYMCRYPT_802_11_SAE_CUSTOM_STATE stateA;

    BYTE abCommitScalarA[ 32 ];
    BYTE abCommitElementA[ 64 ];
    BYTE abSharedA[ 32 ];
    BYTE abSumA[ 32 ];

    GENRANDOM( abMac1, sizeof( abMac1 ) );
    GENRANDOM( abMac2, sizeof( abMac2 ) );
    GENRANDOM( &cbPassword, sizeof( cbPassword ) );
    cbPassword &= 31;
    GENRANDOM( abPassword, sizeof( abPassword ) );

    // Actor A creates a commit
    SymCrypt802_11SaeCustomInit( &stateA, abMac1, abMac2, abPassword, cbPassword, NULL, NULL, NULL );
    SymCrypt802_11SaeCustomCommitCreate( &stateA, abCommitScalarA, abCommitElementA );

    // Process the fake reply
    scError = SymCrypt802_11SaeCustomCommitProcess( &stateA, pbPeerScalar, pbPeerElement, abSharedA, abSumA );

    CHECK( scError != SYMCRYPT_NO_ERROR, "No error when receiving invalid peer commit scalar or element" );

    pAlgImp->m_nResults++;
}


VOID
testIEEE802_11SaeCustomKats()
{
    std::auto_ptr<KatData> katData( getCustomResource( "kat_IEEE802_11SaeCustom.dat", "KAT_SAE_CUSTOM" ) );
    KAT_ITEM katItem;
    std::vector<ArithImplementation *> ImpPtrVector;

    static String g_currentCategory;
    BOOL skipData = TRUE;
    String sep = "    ";
    BOOL doneAnything = FALSE;

    while( 1 )
    {
        katData->getKatItem( & katItem );
        if( katItem.type == KAT_TYPE_END )
        {
            break;
        }

        if( katItem.type == KAT_TYPE_CATEGORY )
        {
            g_currentCategory = katItem.categoryName;
            getAllImplementations<ArithImplementation>( g_currentCategory, &ImpPtrVector );

            skipData = (ImpPtrVector.size() == 0);
            if( !skipData )
            {
                iprint( "%s%s", sep.c_str(), g_currentCategory.c_str() );
                sep = ", ";
                doneAnything = TRUE;
            }
        }

        if( katItem.type == KAT_TYPE_DATASET && !skipData )
        {
            if( katIsFieldPresent( katItem, "password" ) )
            {
                BString password = katParseData( katItem, "password" );
                BString MACa = katParseData( katItem, "maca" );
                BString MACb = katParseData( katItem, "macb" );
                UINT64 counter = katParseInteger( katItem, "count" );
                BString random = katParseData( katItem, "random" );
                BString mask = katParseData( katItem, "mask" );
                BString commitScalar = katParseData( katItem, "commitscalar" );
                BString commitElement = katParseData( katItem, "commitelement" );
                BString peerScalar = katParseData( katItem, "peerscalar" );
                BString peerElement = katParseData( katItem, "peerelement" );
                BString sharedSecret = katParseData( katItem, "sharedsecret" );
                BString scalarSum = katParseData( katItem, "scalarsum" );

                CHECK3( MACa.size() == 6, "Inavlid length for MACa at line %lld", katData->m_line );
                CHECK3( MACb.size() == 6, "Invalid length for MACb at line %lld", katData->m_line );
                CHECK3( random.size() == 32, "Invalid length for random at line %lld", katData->m_line );
                CHECK3( mask.size() == 32, "Invalid length for mask at line %lld", katData->m_line );
                CHECK3( commitScalar.size()  == 32, "Invalid length for commitScalar at line %lld", katData->m_line );
                CHECK3( commitElement.size() == 64, "Invalid length for commitElement at line %lld", katData->m_line );
                CHECK3( peerScalar.size()    == 32, "Invalid length for peerScalar at line %lld", katData->m_line );
                CHECK3( peerElement.size()   == 64, "Invalid length for peerElement at line %lld", katData->m_line );
                CHECK3( sharedSecret.size() == 32, "Invalid length for sharedSecret at line %lld", katData->m_line );
                CHECK3( scalarSum.size() == 32, "Invalid length for scalarSum at line %lld", katData->m_line );

                CHECK3( counter <= 0xff, "Invalid counter at line %lld", katItem.line );

                testSaeCustom( *(ImpPtrVector.begin()),
                            password.data(), password.size(), MACa.data(), MACb.data(), (BYTE) counter, random.data(), mask.data(), commitScalar.data(), commitElement.data(),
                            peerScalar.data(), peerElement.data(), sharedSecret.data(), scalarSum.data() );

                (*(ImpPtrVector.begin()))->m_nResults++;
            } 
            else if( katIsFieldPresent( katItem, "selfconsistent" ) )
            {
                testSaeCustomConsistency( *(ImpPtrVector.begin()) );
            } 
            else if( katIsFieldPresent( katItem, "negativetest" ) )
            {
                BString peerScalar = katParseData( katItem, "peerscalar" );
                BString peerElement = katParseData( katItem, "peerelement" );

                CHECK3( peerScalar.size()    == 32, "Invalid length for peerScalar at line %lld", katData->m_line );
                CHECK3( peerElement.size()   == 64, "Invalid length for peerElement at line %lld", katData->m_line );

                testSaeCustomNegative( *(ImpPtrVector.begin()), peerScalar.data(), peerElement.data() );
            } 
            else
            {
                FATAL2( "Unknown data record ending at line %lld", katItem.line );
            }
        }
    }

    if( doneAnything )
    {
        iprint( "\n" );
    }
}


VOID
testIEEE802_11SaeCustom()
{
    testIEEE802_11SaeCustomKats();

}

