//
// cng_imp_macpattern.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

BCRYPT_ALG_HANDLE MacImpState<ImpXxx, AlgXxx>::hAlg;


MacImp<ImpXxx, AlgXxx>::MacImp()
{
    NTSTATUS status;

    status = CngOpenAlgorithmProviderFn( &state.hAlg, MAC_PROVIDER_NAME( ALG_NAME ), NULL, BCOAP_FLAGS | bcoapReusableFlag() );
    if( !NT_SUCCESS( status ) )
    {
        if( g_osVersion < 0x0602 && wcscmp( MAC_PROVIDER_NAME( ALG_NAME ), BCRYPT_AES_CMAC_ALGORITHM ) == 0 )
        {
            //
            // We know this is not supported; throw an exception which will eliminate this implementation
            // from the set to be tested.
            //
            throw status;
        }
        CHECK( FALSE, "Could not open CNG/" STRING( ALG_NAME ) );
    }
    state.hHash = 0;
    m_perfDataFunction = &algImpDataPerfFunction<ImpXxx, AlgXxx>;
    m_perfKeyFunction = &algImpKeyPerfFunction<ImpXxx, AlgXxx>;
    m_perfCleanFunction = &algImpCleanPerfFunction<ImpXxx, AlgXxx>;
}

template<>
MacImp<ImpXxx, AlgXxx>::~MacImp()
{
    CHECK( state.hHash == 0, "Handle leak" );
    CHECK( NT_SUCCESS( CngCloseAlgorithmProviderFn( state.hAlg, 0 )), "Could not close CNG/" STRING( ALG_Name ) );
    state.hAlg = 0;
}

SIZE_T MacImp<ImpXxx, AlgXxx>::inputBlockLen()
{
    ULONG   len;
    ULONG   res;
    CHECK( NT_SUCCESS( CngGetPropertyFn( state.hAlg, BCRYPT_HASH_BLOCK_LENGTH, (PBYTE) &len, sizeof( len ), &res, 0 ) ),
        "Could not query input size CNG/" STRING( ALG_Name ) );
    CHECK( res == sizeof( len ), "??" );
    return len;
}

SIZE_T MacImp<ImpXxx, AlgXxx>::resultLen()
{
    ULONG   len;
    ULONG   res;
    CHECK( NT_SUCCESS( CngGetPropertyFn( state.hAlg, BCRYPT_HASH_LENGTH, (PBYTE) &len, sizeof( len ), &res, 0 ) ),
        "Could not query hash size CNG/" STRING( ALG_Name ) );
    CHECK( res == sizeof( len ), "??" );
    return len;
}


NTSTATUS MacImp<ImpXxx, AlgXxx>::init( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( state.hHash == 0, "Hash already exists CNG/" STRING( ALG_Name ) );
    CHECK( NT_SUCCESS( CngCreateHashFn(     state.hAlg, 
                                            &state.hHash, 
                                            state.hashObjectBuffer,
                                            sizeof( state.hashObjectBuffer ),
                                            (PBYTE) pbKey,
                                            (ULONG) cbKey,
                                            0) ),
            "Error creating hash CNG/" STRING( ALG_Name ) );
    
    return STATUS_SUCCESS;
}

VOID MacImp<ImpXxx, AlgXxx>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    CHECK( NT_SUCCESS( CngHashDataFn( state.hHash, (PBYTE) pbData, (ULONG) cbData, 0 ) ),
        "Error hashing CNG/" STRING( ALG_Name ) );
}

VOID MacImp<ImpXxx, AlgXxx>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    CHECK( NT_SUCCESS( CngFinishHashFn( state.hHash, pbResult, (ULONG) cbResult, 0 ) ),
        "Error finalizing CNG/" STRING( ALG_Name ) );
    CHECK( NT_SUCCESS( CngDestroyHashFn( state.hHash ) ), "Error destoring CNG/" STRING( ALG_Name ) );
    state.hHash = 0;
}

NTSTATUS
MacImp<ImpXxx, AlgXxx>::mac( 
    _In_reads_( cbKey )      PCBYTE pbKey,   SIZE_T cbKey, 
    _In_reads_( cbData )     PCBYTE pbData,  SIZE_T cbData, 
    _Out_writes_( cbResult )  PBYTE pbResult, SIZE_T cbResult )
{
    return MacImplementation::mac( pbKey, cbKey, pbData, cbData, pbResult, cbResult );
}


//
// Performance is a bit strange.
// On Win8 & beyond we can use re-usable hash objects to move the key expansion to the keying phase.
// On Win7 and earlier this doesn't work. Our perf functions adapt, this adds a very small additional overhead,
// but that is very minor compared to the actual work, and gives a much better representation of the actual
// cost of each computation.
//

VOID 
algImpKeyPerfFunction<ImpXxx, AlgXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf2 );

    //
    // On Win8 & beyond we can pre-expand
    //
    if( g_osVersion >= 0x0602 )
    {
        CHECK( NT_SUCCESS(CngCreateHashFn( MacImpState<ImpXxx, AlgXxx>::hAlg, (BCRYPT_HASH_HANDLE *)buf1, buf1 + 16, PERF_BUFFER_SIZE - 16, buf3, (ULONG)keySize, 0 )), "" );
    } else {
            //
            // All we can do is save the key size
            //
            *(SIZE_T *) buf1 = keySize;
    }
}

VOID
algImpCleanPerfFunction<ImpXxx, AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    if( g_osVersion >= 0x0602 )
    {
        CHECK( NT_SUCCESS(CngDestroyHashFn( *(BCRYPT_HASH_HANDLE *) buf1 )), "" );
    }
}

VOID 
algImpDataPerfFunction<ImpXxx, AlgXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    BCRYPT_HASH_HANDLE h;

    if( g_osVersion >= 0x0602 )
    {
        h = *(BCRYPT_HASH_HANDLE *) buf1;
        CHECK( NT_SUCCESS(CngHashDataFn  ( h, buf2, (ULONG) dataSize, 0 )), "" );
        CHECK( NT_SUCCESS(CngFinishHashFn( h, buf3, (ULONG)(SYMCRYPT_XXX_RESULT_SIZE), 0 )), "" );
    } else {
        CHECK( NT_SUCCESS(CngCreateHashFn( MacImpState<ImpXxx, AlgXxx>::hAlg, &h, buf1 + 16, PERF_BUFFER_SIZE, buf3, (ULONG)*(SIZE_T *)buf1, 0 )), "" );
        CHECK( NT_SUCCESS(CngHashDataFn  ( h, buf2, (ULONG) dataSize, 0 )), "" );
        CHECK( NT_SUCCESS(CngFinishHashFn( h, buf3, (ULONG)(SYMCRYPT_XXX_RESULT_SIZE), 0 )), "" );
        CHECK( NT_SUCCESS(CngDestroyHashFn( h )), "" );
    }
}


