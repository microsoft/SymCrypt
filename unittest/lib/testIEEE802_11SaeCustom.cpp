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

    scError = ScDispatchSymCrypt802_11SaeCustomInit(  &state,
                                            pbMACa,
                                            pbMACb,
                                            pbPassword,
                                            cbPassword,
                                            &cnt,
                                            (PBYTE) pbRandom,
                                            (PBYTE) pbMask );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in 802_11SaeCustomInit" );

    CHECK4( cnt == bCounter, "Counter mismatch %02x, %02x", cnt, bCounter );

    scError = ScDispatchSymCrypt802_11SaeCustomCommitCreate( &state, abScalar, abElement );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in 802_11SaeCustomCommitCreate" );

    //iprint( "\n" );
    //printHex( abScalar, 32 );
    //iprint( "\n" );
    //printHex( abElement, 64 );
    //iprint( "\n" );

    CHECK( memcmp( abScalar, pbCommitScalar, 32) == 0, "Commit scalar error" );
    CHECK( memcmp( abElement, pbCommitElement, 64) == 0, "Commit element error" );


    scError = ScDispatchSymCrypt802_11SaeCustomCommitProcess( &state, pbPeerScalar, pbPeerElement, abSharedSecret, abScalarSum );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in 802_11SaeCustomCommitProcess" );

    CHECK( memcmp( abScalarSum, pbScalarSum, 32) == 0, "Scalar sum error" );
    CHECK( memcmp( abSharedSecret, pbSharedSecret, 32) == 0, "Shared secret error" );

    ScDispatchSymCrypt802_11SaeCustomDestroy(&state);

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
        ScDispatchSymCrypt802_11SaeCustomInit( &stateA, abMac1, abMac2, abPassword, cbPassword, nullptr, nullptr, nullptr );
        ScDispatchSymCrypt802_11SaeCustomCommitCreate( &stateA, abCommitScalarA, abCommitElementA );

        // Actor B processes it
        ScDispatchSymCrypt802_11SaeCustomInit( &stateB, abMac2, abMac1, abPassword, cbPassword, nullptr, nullptr, nullptr );
        ScDispatchSymCrypt802_11SaeCustomCommitCreate( &stateB, abCommitScalarB, abCommitElementB );
        ScDispatchSymCrypt802_11SaeCustomCommitProcess( &stateB, abCommitScalarA, abCommitElementA, abSharedB, abSumB );

        ScDispatchSymCrypt802_11SaeCustomCommitProcess( &stateA, abCommitScalarB, abCommitElementB, abSharedA, abSumA );

        CHECK( memcmp( abSharedA, abSharedB, 32 ) == 0, "Shared secret mismatch" );
        CHECK( memcmp( abSumA, abSumB, 32 ) == 0, "Scalar sum mismatch" );

        ScDispatchSymCrypt802_11SaeCustomDestroy(&stateA);
        ScDispatchSymCrypt802_11SaeCustomDestroy(&stateB);

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
    ScDispatchSymCrypt802_11SaeCustomInit( &stateA, abMac1, abMac2, abPassword, cbPassword, nullptr, nullptr, nullptr );
    ScDispatchSymCrypt802_11SaeCustomCommitCreate( &stateA, abCommitScalarA, abCommitElementA );

    // Process the fake reply
    scError = ScDispatchSymCrypt802_11SaeCustomCommitProcess( &stateA, pbPeerScalar, pbPeerElement, abSharedA, abSumA );

    CHECK3(scError != SYMCRYPT_NO_ERROR, "No error when receiving invalid peer commit scalar or element at line %lld", line);

    ScDispatchSymCrypt802_11SaeCustomDestroy(&stateA);

    pAlgImp->m_nResults++;
}

VOID
testSaeCustomH2E_PWE(
                                                        ArithImplementation* pAlgImp,
    _In_                                                SYMCRYPT_802_11_SAE_GROUP group,
    _In_reads_(cbSsid)                                  PCBYTE pbSsid,
    _In_                                                SIZE_T cbSsid,
    _In_reads_(cbPassword)                              PCBYTE pbPassword,
    _In_                                                SIZE_T cbPassword,
    _In_reads_opt_(cbIdentifier)                        PCBYTE pbIdentifier,
    _In_                                                SIZE_T cbIdentifier,
    _In_reads_(6)                                       PCBYTE pbMacA,
    _In_reads_(6)                                       PCBYTE pbMacB,
    _In_reads_(SYMCRYPT_SAE_MAX_EC_POINT_SIZE_BYTES)    PCBYTE pbExpectedPT,
    _In_reads_( SYMCRYPT_SAE_MAX_EC_POINT_SIZE_BYTES )  PCBYTE pbExpectedPWE)
{
    SYMCRYPT_802_11_SAE_CUSTOM_STATE state = { 0 };
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    BYTE abPT[SYMCRYPT_SAE_MAX_EC_POINT_SIZE_BYTES] = { 0 };
    BYTE abPWE[SYMCRYPT_SAE_MAX_EC_POINT_SIZE_BYTES] = { 0 };
    SIZE_T cbScalar = {};
    SIZE_T cbPoint = {};

    ScDispatchSymCrypt802_11SaeGetGroupSizes( group, &cbScalar, &cbPoint );
    CHECK( cbScalar != 0, "Invalid field element size" );
    CHECK( cbPoint != 0, "Invalid elliptic curve point size" );

    scError = ScDispatchSymCrypt802_11SaeCustomCreatePTGeneric(
        group,
        pbSsid,
        cbSsid,
        pbPassword,
        cbPassword,
        pbIdentifier,
        cbIdentifier,
        abPT,
        cbPoint );

    CHECK(scError == SYMCRYPT_NO_ERROR, "Error in 802_11SaeCustomCreatePT");

    CHECK(ScDispatchSymCryptEqual(abPT, pbExpectedPT, cbPoint), "Incorrect PT value");

    scError = ScDispatchSymCrypt802_11SaeCustomInitH2EGeneric(
        &state,
        group,
        abPT,
        cbPoint,
        pbMacA,
        pbMacB,
        nullptr,
        0,
        nullptr,
        0 );

    CHECK(scError == SYMCRYPT_NO_ERROR, "Error in 802_11SaeCustomInitH2E");

    SIZE_T cbScratch = SYMCRYPT_SCRATCH_BYTES_FOR_GETSET_VALUE_ECURVE_OPERATIONS(state.pCurve);
    PBYTE pbScratch = (PBYTE)SymCryptCallbackAlloc(cbScratch);

    CHECK(pbScratch != NULL, "Failed to allocate scratch space");

    scError = ScDispatchSymCryptEcpointGetValue(
        state.pCurve,
        state.poPWE,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        abPWE,
        cbPoint,
        0,
        pbScratch,
        cbScratch);

    CHECK(scError == SYMCRYPT_NO_ERROR, "Failed to get PWE XY value");

    CHECK(ScDispatchSymCryptEqual(abPWE, pbExpectedPWE, cbPoint), "Incorrect PWE value");

    ScDispatchSymCrypt802_11SaeCustomDestroy(&state);
    ScDispatchSymCryptWipe(pbScratch, cbScratch);
    SymCryptCallbackFree(pbScratch);

    pAlgImp->m_nResults++;
}


VOID testSaeCustomSimulateKeyExchange(
            ArithImplementation* pAlgImp,
            SYMCRYPT_802_11_SAE_GROUP group,
            UINT64 uTests
   )
{
    const UINT32 MACID_SIZE = 6;
    const UINT32 MAX_SSID_SIZE = 16;
    const UINT32 MAX_PASSWORD_SIZE = 32;
    const UINT32 MAX_IDENTIFIER_SIZE = 32;
    const UINT32 MAX_SCALAR_SIZE = SYMCRYPT_SAE_MAX_MOD_SIZE_BYTES;
    const UINT32 MAX_EC_POINT_SIZE = 2 * SYMCRYPT_SAE_MAX_EC_POINT_SIZE_BYTES;
    SIZE_T cbScalar{ };
    SIZE_T cbPoint{ };

    ScDispatchSymCrypt802_11SaeGetGroupSizes( group, &cbScalar, &cbPoint );
    CHECK( cbScalar != 0, "Invalid field element size" );
    CHECK( cbPoint != 0, "Invalid elliptic curve point size" );

    // Returns an unsigned random integer in the range [min, max]
    // Ignores the bias when the size of the range is not a power of 2
    auto GetRandomInteger = []( SIZE_T min, SIZE_T max ) {

        SIZE_T value;

        GENRANDOM( &value, sizeof( value ) );

        value %= ( max - min + 1 );
        value += min;

        return value;
    };

    for ( UINT32 i = 0; i < uTests; i++ )
    {
        BYTE abMacA[MACID_SIZE] = {};
        BYTE abMacB[MACID_SIZE] = {};
        BYTE abSsid[MAX_SSID_SIZE] = {};
        BYTE abPassword[MAX_PASSWORD_SIZE] = {};
        BYTE abIdentifier[MAX_IDENTIFIER_SIZE] = {};
        BYTE abRandA[MAX_SCALAR_SIZE] = {};
        BYTE abMaskA[MAX_SCALAR_SIZE] = {};
        BYTE abRandB[MAX_SCALAR_SIZE] = {};
        BYTE abMaskB[MAX_SCALAR_SIZE] = {};
        BYTE abCommitScalarA[MAX_SCALAR_SIZE] = {};
        BYTE abCommitElementA[MAX_EC_POINT_SIZE] = {};
        BYTE abCommitScalarB[MAX_SCALAR_SIZE] = {};
        BYTE abCommitElementB[MAX_EC_POINT_SIZE] = {};
        BYTE abSharedSecretA[MAX_SCALAR_SIZE] = {};
        BYTE abSharedSecretB[MAX_SCALAR_SIZE] = {};
        BYTE abScalarSumA[MAX_EC_POINT_SIZE] = {};
        BYTE abScalarSumB[MAX_EC_POINT_SIZE] = {};

        SYMCRYPT_802_11_SAE_CUSTOM_STATE stateA = {}, stateB = {};
        BYTE abPTA[MAX_EC_POINT_SIZE] = {};
        BYTE abPTB[MAX_EC_POINT_SIZE] = {};

        GENRANDOM( abMacA, MACID_SIZE );
        GENRANDOM( abMacB, MACID_SIZE );

        SIZE_T cbSsid = GetRandomInteger( 1, MAX_SSID_SIZE );
        GENRANDOM( abSsid, ( ULONG )cbSsid );

        SIZE_T cbPassword = GetRandomInteger( 1, MAX_PASSWORD_SIZE );
        GENRANDOM( abPassword, ( ULONG )cbPassword );

        SIZE_T cbIdentifier = GetRandomInteger( 0, MAX_IDENTIFIER_SIZE );
        GENRANDOM( abIdentifier, ( ULONG )cbIdentifier );

        SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

        //
        // Peer A
        //
        {
            scError = ScDispatchSymCrypt802_11SaeCustomCreatePTGeneric(
                group,
                abSsid,
                cbSsid,
                abPassword,
                cbPassword,
                abIdentifier,
                cbIdentifier,
                abPTA,
                cbPoint );

            CHECK3( scError == SYMCRYPT_NO_ERROR, "Error in 802_11SaeCustomCreatePT : %x", scError );

            scError = ScDispatchSymCrypt802_11SaeCustomInitH2EGeneric(
                &stateA,
                group,
                abPTA,
                cbPoint,
                abMacA,
                abMacB,
                abRandA,
                cbScalar,
                abMaskA,
                cbScalar );

            CHECK3( scError == SYMCRYPT_NO_ERROR, "Error in 802_11SaeCustomInitH2E : %x", scError );

            scError = ScDispatchSymCrypt802_11SaeCustomCommitCreateGeneric(
                &stateA,
                abCommitScalarA,
                cbScalar,
                abCommitElementA,
                cbPoint );

            CHECK3( scError == SYMCRYPT_NO_ERROR, "Error in 802_11SaeCustomCommitCreate : %x", scError );
        }

        //
        // Peer B
        //
        {
            scError = ScDispatchSymCrypt802_11SaeCustomCreatePTGeneric(
                group,
                abSsid,
                cbSsid,
                abPassword,
                cbPassword,
                abIdentifier,
                cbIdentifier,
                abPTB,
                cbPoint );

            CHECK3( scError == SYMCRYPT_NO_ERROR, "Error in 802_11SaeCustomCreatePT : %x", scError );

            scError = ScDispatchSymCrypt802_11SaeCustomInitH2EGeneric(
                &stateB,
                group,
                abPTB,
                cbPoint,
                abMacA,
                abMacB,
                abRandB,
                cbScalar,
                abMaskB,
                cbScalar );

            CHECK3( scError == SYMCRYPT_NO_ERROR, "Error in 802_11SaeCustomInitH2E : %x", scError );

            scError = ScDispatchSymCrypt802_11SaeCustomCommitCreateGeneric(
                &stateB,
                abCommitScalarB,
                cbScalar,
                abCommitElementB,
                cbPoint );

            CHECK3( scError == SYMCRYPT_NO_ERROR, "Error in 802_11SaeCustomCommitCreate : %x", scError );
        }

        //
        // Final phase
        //
        {
            scError = ScDispatchSymCrypt802_11SaeCustomCommitProcessGeneric(
                &stateA,
                abCommitScalarB,
                cbScalar,
                abCommitElementB,
                cbPoint,
                abSharedSecretA,
                cbScalar,
                abScalarSumA,
                cbScalar );

            CHECK3( scError == SYMCRYPT_NO_ERROR, "Error in 802_11SaeCustomCommitProcess : %x", scError );

            scError = ScDispatchSymCrypt802_11SaeCustomCommitProcessGeneric(
                &stateB,
                abCommitScalarA,
                cbScalar,
                abCommitElementA,
                cbPoint,
                abSharedSecretB,
                cbScalar,
                abScalarSumB,
                cbScalar );

            CHECK3( scError == SYMCRYPT_NO_ERROR, "Error in 802_11SaeCustomCommitProcess : %x", scError );
        }

        // The sizes of SharedSecret and ScalarSum will vary depending on the group selected. We can compare the produced shared values
        // by comparing the whole buffer since the buffer is initialized to zero and the generated values have the same size.
        CHECK( memcmp( abSharedSecretA, abSharedSecretB, MAX_SCALAR_SIZE ) == 0, "Shared secret mismatch" );
        CHECK( memcmp( abScalarSumA, abScalarSumB, MAX_EC_POINT_SIZE ) == 0, "Scalar sum mismatch" );

        ScDispatchSymCrypt802_11SaeCustomDestroy( &stateA );
        ScDispatchSymCrypt802_11SaeCustomDestroy( &stateB );

        if ( pAlgImp != NULL )
        {
            pAlgImp->m_nResults++;
        }
    }
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
            if ( katIsFieldPresent(katItem, "h2epwetest") )
            {
                SYMCRYPT_802_11_SAE_GROUP group = (SYMCRYPT_802_11_SAE_GROUP)katParseInteger(katItem, "group");
                BString ssid = katParseData(katItem, "ssid");
                BString password = katParseData(katItem, "password");
                BString identifier = katParseData(katItem, "identifier");
                BString MACa = katParseData(katItem, "maca");
                BString MACb = katParseData(katItem, "macb");
                BString PT = katParseData(katItem, "pt");
                BString PWE = katParseData(katItem, "pwe");

                CHECK3(MACa.size() == 6, "Invalid length for MACa at line %lld", line);
                CHECK3(MACb.size() == 6, "Invalid length for MACb at line %lld", line);

                testSaeCustomH2E_PWE(
                    *(ImpPtrVector.begin()),
                    group,
                    ssid.data(),
                    ssid.size(),
                    password.data(),
                    password.size(),
                    identifier.data(),
                    identifier.size(),
                    MACa.data(),
                    MACb.data(),
                    PT.data(),
                    PWE.data());
            }
            else if ( katIsFieldPresent( katItem, "h2eselfconsistent" ) )
            {
                SYMCRYPT_802_11_SAE_GROUP group = ( SYMCRYPT_802_11_SAE_GROUP )katParseInteger( katItem, "group" );
                UINT64 count = katParseInteger( katItem, "count" );

                testSaeCustomSimulateKeyExchange(
                    *( ImpPtrVector.begin() ),
                    group,
                    count );
            }
            else if( katIsFieldPresent( katItem, "password" ) )
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

                CHECK3( MACa.size() == 6, "Invalid length for MACa at line %lld", line );
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
testIEEE802_11SaeCustom()
{
    if( !SCTEST_LOOKUP_DISPATCHSYM(SymCrypt802_11SaeCustomInit) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCrypt802_11SaeCustomInitH2EGeneric) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCrypt802_11SaeCustomCreatePTGeneric) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCrypt802_11SaeCustomCommitCreate) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCrypt802_11SaeCustomCommitCreateGeneric) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCrypt802_11SaeCustomCommitProcess) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCrypt802_11SaeCustomCommitProcessGeneric) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCrypt802_11SaeCustomDestroy) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCrypt802_11SaeGetGroupSizes) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptEcpointGetValue) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptEqual) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptWipe) )
    {
        print("    testIEEE802_11SaeCustom skipped\n");
        return;
    }

    testIEEE802_11SaeCustomKats();

    INT64 nOutstandingAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nOutstandingCheckedAllocs);
    CHECK3(nOutstandingAllocs == 0, "Memory leak %d", nOutstandingAllocs);
}
