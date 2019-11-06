//
// Cng_imp_hashpattern.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

BCRYPT_ALG_HANDLE HashImpState<ImpXxx, AlgXxx>::hAlg;


HashImp<ImpXxx, AlgXxx>::HashImp()
{
    CHECK( CngOpenAlgorithmProviderFn( &state.hAlg, LSTRING( ALG_NAME ), NULL, bcoapReusableFlag() ) == STATUS_SUCCESS, 
        "Could not open CNG/" STRING( ALG_Name ) );
    state.hHash = 0;
    m_perfDataFunction = &algImpDataPerfFunction<ImpXxx, AlgXxx>;
    m_perfKeyFunction = &algImpKeyPerfFunction<ImpXxx, AlgXxx>;
    m_perfCleanFunction = &algImpCleanPerfFunction<ImpXxx, AlgXxx>;
}

template<>
HashImp<ImpXxx, AlgXxx>::~HashImp()
{
    CHECK( state.hHash == 0, "Handle leak" );
    
    CHECK( NT_SUCCESS( CngCloseAlgorithmProviderFn( state.hAlg, 0 )), "Could not close CNG/" STRING( ALG_Name ) );
    state.hAlg = 0;
}

SIZE_T HashImp<ImpXxx, AlgXxx>::inputBlockLen()
{
    ULONG   len;
    ULONG   res;
    CHECK( NT_SUCCESS( CngGetPropertyFn( state.hAlg, BCRYPT_HASH_BLOCK_LENGTH, (PBYTE) &len, sizeof( len ), &res, 0 ) ),
        "Could not query input size CNG/" STRING( ALG_Name ) );
    CHECK( res == sizeof( len ), "??" );
    return len;
}

SIZE_T HashImp<ImpXxx, AlgXxx>::resultLen()
{
    ULONG   len;
    ULONG   res;
    CHECK( NT_SUCCESS( CngGetPropertyFn( state.hAlg, BCRYPT_HASH_LENGTH, (PBYTE) &len, sizeof( len ), &res, 0 ) ),
        "Could not query hash size CNG/" STRING( ALG_Name ) );
    CHECK( res == sizeof( len ), "??" );
    return len;
}


VOID HashImp<ImpXxx, AlgXxx>::init()
{
    CHECK( state.hHash == 0, "Handle leak");
    CHECK( NT_SUCCESS( CngCreateHashFn(    state.hAlg, 
                                            &state.hHash, 
                                            state.hashObjectBuffer,
                                            sizeof( state.hashObjectBuffer ),
                                            NULL,
                                            0,
                                            0) ),
            "Error creating hash CNG/" STRING( ALG_Name ) );
}

VOID HashImp<ImpXxx, AlgXxx>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    CHECK( NT_SUCCESS( CngHashDataFn( state.hHash, (PBYTE) pbData, (ULONG) cbData, 0 ) ),
        "Error hashing CNG/" STRING( ALG_Name ) );
}

VOID HashImp<ImpXxx, AlgXxx>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    CHECK( NT_SUCCESS( CngFinishHashFn( state.hHash, pbResult, (ULONG) cbResult, 0 ) ),
        "Error finalizing CNG/" STRING( ALG_Name ) );
    CHECK( NT_SUCCESS( CngDestroyHashFn( state.hHash ) ), "Error destoring CNG/" STRING( ALG_Name ) );
    state.hHash = 0;
}

/*
VOID HashImp<ImpXxx, AlgXxx>::hash( PCBYTE pbData, SIZE_T cbData, PBYTE pbResult, SIZE_T cbResult )
{
    BYTE buf[384];
    BCRYPT_HASH_HANDLE hHash;

    CHECK( NT_SUCCESS( CngCreateHashFn( state.hAlg, &hHash, buf, sizeof( buf ), NULL, 0, 0 ) ), "Error hash 1 CNG/" STRING( ALG_Name ) );
    CHECK( NT_SUCCESS( CngHashDataFn( hHash, (PBYTE) pbData, (ULONG) cbData, 0 ) ),  "Error hash 2 CNG/" STRING( ALG_Name ) );
    CHECK( NT_SUCCESS( CngFinishHashFn( hHash, pbResult, (ULONG) cbResult, 0 ) ), "Error hash 3 CNG/" STRING( ALG_Name ) );
    CHECK( NT_SUCCESS( CngDestroyHashFn( hHash ) ), "Error hash 4 CNG/" STRING( ALG_Name ) );
}
*/

NTSTATUS HashImp<ImpXxx, AlgXxx>::initWithLongMessage( ULONGLONG nBytes )
{
    UNREFERENCED_PARAMETER( nBytes );

    return STATUS_NOT_SUPPORTED;
}

NTSTATUS HashImp<ImpXxx,AlgXxx>::exportSymCryptFormat( PBYTE pbResult, SIZE_T cbResultBufferSize, SIZE_T * pcbResult )
{
    UNREFERENCED_PARAMETER( pbResult );
    UNREFERENCED_PARAMETER( cbResultBufferSize );
    UNREFERENCED_PARAMETER( pcbResult );

    return STATUS_NOT_SUPPORTED;
}

VOID HashImp<ImpXxx, AlgXxx>::hash( 
        _In_reads_( cbData )       PCBYTE pbData, 
                                    SIZE_T cbData, 
        _Out_writes_( cbResult )    PBYTE pbResult, 
                                    SIZE_T cbResult )
{
    HashImplementation::hash( pbData, cbData, pbResult, cbResult );
}



//
// Performance is a bit strange.
// On Win8 & beyond we can use re-usable hash objects to move the key expansion to the keying phase.
// On Win7 and earlier this doesn't work. Our perf functions adapt, this adds a very small additional overhead,
// but that is very minor compared to the actual work, and gives a much better representation of the actual
// cost of each computation.
//
// To measure the cost of the setup separately, we pretend to use a key as that matches the perf infrastructure.
//

VOID 
algImpKeyPerfFunction<ImpXxx, AlgXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( keySize );

    //
    // On Win8 & beyond we can pre-expand
    //
    if( g_osVersion >= 0x0602 )
    {
        CHECK( NT_SUCCESS(CngCreateHashFn( HashImpState<ImpXxx, AlgXxx>::hAlg, (BCRYPT_HASH_HANDLE *)buf1, buf1 + 16, PERF_BUFFER_SIZE - 16, NULL, 0, 0 )), "" );
    } else {
        //
        // No initialization on Win7 and below
        //
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
        *(BCRYPT_HASH_HANDLE *)buf1 = NULL;
    }
}

VOID 
algImpDataPerfFunction<ImpXxx, AlgXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    BCRYPT_HASH_HANDLE h;

    if( g_osVersion >= 0x0602 )
    {
        NTSTATUS status;

        h = *(BCRYPT_HASH_HANDLE *) buf1;
        status =  CngHashDataFn( h, buf2, (ULONG) dataSize, 0 );
        CHECK( NT_SUCCESS( status ), "?" );
        //CHECK5( NT_SUCCESS(CngHashDataFn  ( h, buf2, (ULONG) dataSize, 0 )), "h = %08x, buf1=%08x, status=%08x", h, buf1,status );
        CHECK( NT_SUCCESS(CngFinishHashFn( h, buf3, (ULONG)(SYMCRYPT_XXX_RESULT_SIZE), 0 )), "" );
    } else {
        CHECK( NT_SUCCESS(CngCreateHashFn( HashImpState<ImpXxx, AlgXxx>::hAlg, &h, buf1 + 1600, PERF_BUFFER_SIZE - 1600, NULL, 0, 0 )), "" );
        CHECK( NT_SUCCESS(CngHashDataFn  ( h, buf2, (ULONG) dataSize, 0 )), "" );
        CHECK( NT_SUCCESS(CngFinishHashFn( h, buf3, (ULONG)(SYMCRYPT_XXX_RESULT_SIZE), 0 )), "" );
        CHECK( NT_SUCCESS(CngDestroyHashFn( h )), "" );
    }
}

