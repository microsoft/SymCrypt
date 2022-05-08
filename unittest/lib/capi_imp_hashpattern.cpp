//
// capi_imp_hahspattern.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

template<>
SIZE_T HashImp<ImpXxx, AlgXxx>::inputBlockLen()
{
    return SYMCRYPT_XXX_INPUT_BLOCK_SIZE;
}

template<>
SIZE_T HashImp<ImpXxx, AlgXxx>::resultLen()
{
    HCRYPTHASH h;
    DWORD result;
    DWORD dataLen = sizeof( result );

    CHECK( CryptCreateHash( g_capiProvider, CAPI_CALG( ALG_NAME ), 0, 0, &h ), "error create CAPI " STRING( ALG_Name ) );
    CHECK( CryptGetHashParam( h, HP_HASHSIZE, (PBYTE) &result, &dataLen, 0 ), "error result size query CAPI " STRING( ALG_Name ) );
    CHECK( dataLen == sizeof( result ), "??" );
    CHECK( CryptDestroyHash( h ), "error destroy hash CAPI " STRING( ALG_Name ) );

    return result;
}



template<>
VOID HashImp<ImpXxx, AlgXxx>::init()
{
    CHECK( state.hHash == 0, "Handle leak" );
    CHECK( CryptCreateHash( g_capiProvider, CAPI_CALG( ALG_NAME ), 0, 0, &state.hHash ), "error create CAPI" STRING( ALG_Name ) );
}

template<>
VOID HashImp<ImpXxx, AlgXxx>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    CryptHashData( state.hHash, (PBYTE) pbData, (ULONG) cbData, 0 );
}

template<>
VOID HashImp<ImpXxx, AlgXxx>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    DWORD resLen = (DWORD) cbResult;
    CHECK( CryptGetHashParam( state.hHash, HP_HASHVAL, pbResult, &resLen, 0 ), "CryptGetHashParam failed" );
    CHECK( resLen == cbResult, "Wrong result length in CAPI " STRING( ALG_Name ) );
    CHECK( CryptDestroyHash( state.hHash ), "Failed to destroy CAPI " STRING( ALG_Name ) );
    state.hHash = 0;
}

template<>
NTSTATUS HashImp<ImpXxx, AlgXxx>::initWithLongMessage( ULONGLONG nBytes )
{
    UNREFERENCED_PARAMETER( nBytes );

    return STATUS_NOT_SUPPORTED;
}

template<>
VOID HashImp<ImpXxx, AlgXxx>::hash(
        _In_reads_( cbData )       PCBYTE pbData, 
                                    SIZE_T cbData, 
        _Out_writes_( cbResult )    PBYTE pbResult, 
                                    SIZE_T cbResult )
{
    HashImplementation::hash( pbData, cbData, pbResult, cbResult );
}

template<>
NTSTATUS HashImp<ImpXxx,AlgXxx>::exportSymCryptFormat( PBYTE pbResult, SIZE_T cbResultBufferSize, SIZE_T * pcbResult )
{
    UNREFERENCED_PARAMETER( pbResult );
    UNREFERENCED_PARAMETER( cbResultBufferSize );
    UNREFERENCED_PARAMETER( pcbResult );

    return STATUS_NOT_SUPPORTED;
}

template<>
VOID
algImpDataPerfFunction<ImpXxx, AlgXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf3 );

    HCRYPTHASH h;
    DWORD reslen = PERF_BUFFER_SIZE;
    CHECK( CryptCreateHash( g_capiProvider, CAPI_CALG( ALG_NAME ), 0, 0, &h ), "" );
    CHECK( CryptHashData( h, buf1, (ULONG) dataSize, 0 ), "" );
    CHECK( CryptGetHashParam( h, HP_HASHVAL, buf2, &reslen, 0 ), "" );
    CHECK( CryptDestroyHash( h ), "" );
}

template<>
HashImp<ImpXxx, AlgXxx>::HashImp()
{
    state.hHash = 0;
    m_perfDataFunction = &algImpDataPerfFunction<ImpXxx, AlgXxx>;
}

template<>
HashImp<ImpXxx, AlgXxx>::~HashImp()
{
    CHECK( state.hHash == 0, "Handle leak" );
}