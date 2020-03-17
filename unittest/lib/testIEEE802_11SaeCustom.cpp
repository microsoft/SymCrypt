//
// TestIEEE802_11SaeCustom.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
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
    _In_reads_(64)  PCBYTE                  pbPeerElement,
                    LONGLONG                line )
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

    CHECK3( scError != SYMCRYPT_NO_ERROR, "No error when receiving invalid peer commit scalar or element at line %lld", line );

    pAlgImp->m_nResults++;
}


VOID
testIEEE802_11SaeCustomKats()
{
    std::unique_ptr<KatData> katData( getCustomResource( "kat_IEEE802_11SaeCustom.dat", "KAT_SAE_CUSTOM" ) );
    KAT_ITEM katItem;
    std::vector<ArithImplementation *> ImpPtrVector;

    static String g_currentCategory;
    BOOL skipData = TRUE;
    String sep = "    ";
    BOOL doneAnything = FALSE;

    while( 1 )
    {
        katData->getKatItem( & katItem );
        LONGLONG line = katItem.line;
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

                CHECK3( MACa.size() == 6, "Inavlid length for MACa at line %lld", line );
                CHECK3( MACb.size() == 6, "Invalid length for MACb at line %lld", line );
                CHECK3( random.size() == 32, "Invalid length for random at line %lld", line );
                CHECK3( mask.size() == 32, "Invalid length for mask at line %lld", line );
                CHECK3( commitScalar.size()  == 32, "Invalid length for commitScalar at line %lld", line );
                CHECK3( commitElement.size() == 64, "Invalid length for commitElement at line %lld", line );
                CHECK3( peerScalar.size()    == 32, "Invalid length for peerScalar at line %lld", line );
                CHECK3( peerElement.size()   == 64, "Invalid length for peerElement at line %lld", line );
                CHECK3( sharedSecret.size() == 32, "Invalid length for sharedSecret at line %lld", line );
                CHECK3( scalarSum.size() == 32, "Invalid length for scalarSum at line %lld", line );

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

                CHECK3( peerScalar.size()    == 32, "Invalid length for peerScalar at line %lld", line );
                CHECK3( peerElement.size()   == 64, "Invalid length for peerElement at line %lld", line );

                testSaeCustomNegative( *(ImpPtrVector.begin()), peerScalar.data(), peerElement.data(), line );
            }
            else
            {
                FATAL2( "Unknown data record ending at line %lld", line );
            }
        }
    }

    if( doneAnything )
    {
        iprint( "\n" );
    }
}

VOID
testIEEE802_11SaeCustomH2E()
{
    const BYTE abExpectedPT[] =
    {
        // X
        0xb6, 0xe3, 0x8c, 0x98, 0x75, 0x0c, 0x68, 0x4b, 0x5d, 0x17, 0xc3, 0xd8, 0xc9, 0xa4, 0x10, 0x0b,
        0x39, 0x93, 0x12, 0x79, 0x18, 0x7c, 0xa6, 0xcc, 0xed, 0x5f, 0x37, 0xef, 0x46, 0xdd, 0xfa, 0x97,
        // Y
        0x56, 0x87, 0xe9, 0x72, 0xe5, 0x0f, 0x73, 0xe3, 0x89, 0x88, 0x61, 0xe7, 0xed, 0xad, 0x21, 0xbe,
        0xa7, 0xd5, 0xf6, 0x22, 0xdf, 0x88, 0x24, 0x3b, 0xb8, 0x04, 0x92, 0x0a, 0xe8, 0xe6, 0x47, 0xfa
    };

    const BYTE abExpectedPWE[] =
    {
        // X
        0xc9, 0x30, 0x49, 0xb9, 0xe6, 0x40, 0x00, 0xf8, 0x48, 0x20, 0x16, 0x49, 0xe9, 0x99, 0xf2, 0xb5,
        0xc2, 0x2d, 0xea, 0x69, 0xb5, 0x63, 0x2c, 0x9d, 0xf4, 0xd6, 0x33, 0xb8, 0xaa, 0x1f, 0x6c, 0x1e,
        // Y
        0x73, 0x63, 0x4e, 0x94, 0xb5, 0x3d, 0x82, 0xe7, 0x38, 0x3a, 0x8d, 0x25, 0x81, 0x99, 0xd9, 0xdc,
        0x1a, 0x5e, 0xe8, 0x26, 0x9d, 0x06, 0x03, 0x82, 0xcc, 0xbf, 0x33, 0xe6, 0x14, 0xff, 0x59, 0xa0
    };

    SYMCRYPT_802_11_SAE_CUSTOM_STATE state = { 0 };
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    const CHAR ssid[] = "byteme";
    const CHAR identifier[] = "psk4internet";
    const CHAR password[] = "mekmitasdigoat";
    const BYTE abMacA[] = { 0x00, 0x09, 0x5b, 0x66, 0xec, 0x1e };
    const BYTE abMacB[] = { 0x00, 0x0b, 0x6b, 0xd9, 0x02, 0x46 };

    BYTE abPT[64] = { 0 };
    BYTE abPWE[64] = { 0 };
    BYTE abScalar[32] = { 0 };
    BYTE abElement[64] = { 0 };
    // BYTE abSharedSecret[32] = { 0 };
    // BYTE abScalarSum[32] = { 0 };

    scError = SymCrypt802_11SaeCustomCreatePT(
        ( PCBYTE )ssid,
        sizeof( ssid ) - 1, // No null terminator
        ( PCBYTE )password,
        sizeof( password ) - 1, // No null terminator
        ( PCBYTE )identifier,
        sizeof( identifier ) - 1, // No null terminator
        abPT);

    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in 802_11SaeCustomCreatePT" );
    CHECK( SymCryptEqual( abPT, abExpectedPT, sizeof( abExpectedPT )), "Incorrect PT value" );

    scError = SymCrypt802_11SaeCustomInitH2E(
        &state,
        abPT,
        abMacA,
        abMacB,
        NULL,
        NULL );

    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in 802_11SaeCustomInitH2E" );

    SIZE_T cbScratch = SYMCRYPT_SCRATCH_BYTES_FOR_GETSET_VALUE_ECURVE_OPERATIONS( state.pCurve );
    PBYTE pbScratch = (PBYTE) SymCryptCallbackAlloc( cbScratch );

    CHECK( pbScratch != NULL, "Failed to allocate scratch space" );

    scError = SymCryptEcpointGetValue( state.pCurve,
                                       state.poPWE,
                                       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                       SYMCRYPT_ECPOINT_FORMAT_XY,
                                       abPWE,
                                       sizeof( abPWE ),
                                       0,
                                       pbScratch,
                                       cbScratch );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Failed to get PWE XY value" );

    CHECK( SymCryptEqual( abPWE, abExpectedPWE, sizeof( abExpectedPWE ) ), "Incorrect PWE value" );

    scError = SymCrypt802_11SaeCustomCommitCreate( &state, abScalar, abElement );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in 802_11SaeCustomCommitCreate" );

    // TO DO: Process fake reply

    SymCryptWipe( pbScratch, cbScratch );
    SymCryptCallbackFree( pbScratch );
}

VOID
testIEEE802_11SaeCustomH2E_2()
{
    SYMCRYPT_802_11_SAE_CUSTOM_STATE state = { 0 };
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    const CHAR ssid[] = "sae_ap";
    const CHAR password[] = "Admin!98-1";
    const BYTE abMacA[] = { 0x9c, 0xda, 0x3e, 0xf2, 0x7d, 0xd5 };
    const BYTE abMacB[] = { 0x34, 0x13, 0xe8, 0xb2, 0x81, 0x30 };

    BYTE abPT[64] = { 0 };
    BYTE abPWE[64] = { 0 };
    BYTE abScalar[32] = { 0 };
    BYTE abElement[64] = { 0 };
    // BYTE abSharedSecret[32] = { 0 };
    // BYTE abScalarSum[32] = { 0 };

    scError = SymCrypt802_11SaeCustomCreatePT(
        ( PCBYTE ) ssid,
        sizeof( ssid ) - 1, // No null terminator
        ( PCBYTE )password,
        sizeof( password ) - 1, // No null terminator
        NULL,
        0,
        abPT );

    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in 802_11SaeCustomCreatePT" );

    scError = SymCrypt802_11SaeCustomInitH2E(
        &state,
        abPT,
        abMacA,
        abMacB,
        NULL,
        NULL );

    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in 802_11SaeCustomInitH2E" );

    SIZE_T cbScratch = SYMCRYPT_SCRATCH_BYTES_FOR_GETSET_VALUE_ECURVE_OPERATIONS( state.pCurve );
    PBYTE pbScratch = ( PBYTE )SymCryptCallbackAlloc( cbScratch );

    CHECK( pbScratch != NULL, "Failed to allocate scratch space" );

    scError = SymCryptEcpointGetValue( state.pCurve,
        state.poPWE,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        abPWE,
        sizeof( abPWE ),
        0,
        pbScratch,
        cbScratch );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Failed to get PWE XY value" );

    scError = SymCrypt802_11SaeCustomCommitCreate( &state, abScalar, abElement );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in 802_11SaeCustomCommitCreate" );

    // TO DO: Process fake reply

    SymCryptWipe( pbScratch, cbScratch );
    SymCryptCallbackFree( pbScratch );
}

VOID
testIEEE802_11SaeCustom()
{
    testIEEE802_11SaeCustomKats();

    testIEEE802_11SaeCustomH2E();
    testIEEE802_11SaeCustomH2E_2();
}

