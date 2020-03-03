//
// capi_imp_hahspattern.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

MacImp<ImpXxx, AlgXxx>::MacImp()
{
    state.hHash = 0;
    state.hKey = 0;
    m_perfDataFunction = &algImpDataPerfFunction <ImpXxx, AlgXxx>;
    m_perfKeyFunction  = &algImpKeyPerfFunction  <ImpXxx, AlgXxx>;
    m_perfCleanFunction= &algImpCleanPerfFunction<ImpXxx, AlgXxx>;
}

template<>
MacImp<ImpXxx, AlgXxx>::~MacImp()
{
    CHECK( state.hKey == 0, "Handle leak" );
    CHECK( state.hHash == 0, "Handle leak" );
}

SIZE_T MacImp<ImpXxx, AlgXxx>::inputBlockLen()
{
    return SYMCRYPT_XXX_INPUT_BLOCK_SIZE;
}

SIZE_T MacImp<ImpXxx, AlgXxx>::resultLen()
{
    return SYMCRYPT_XXX_RESULT_SIZE;
}



NTSTATUS 
MacImp<ImpXxx, AlgXxx>::init( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( state.hHash == 0, "Handle leak" );

    CHECK( state.hKey == 0, "?" );    
    
    //
    // Importing an HMAC key is convoluted
    //
    BYTE        importBuf[1024];
    BLOBHEADER *pBlob = (BLOBHEADER *) &importBuf[0];

    pBlob->bType = PLAINTEXTKEYBLOB;
    pBlob->bVersion = CUR_BLOB_VERSION;
    pBlob->reserved = 0;
    pBlob->aiKeyAlg = CALG_RC2;       // An ugly hack: you use RC2 as the generic algorithm to import plaintext keys.
    CHECK( cbKey < sizeof( importBuf ) - sizeof( *pBlob ) - sizeof( ULONG ), "Key too large for CAPI blob" );
    *(ULONG *)( &importBuf[sizeof( *pBlob )]) = (ULONG) cbKey;
    memcpy( &importBuf[0] + sizeof( *pBlob ) + sizeof( ULONG ), pbKey, cbKey );

    if( !CryptImportKey( g_capiProvider, importBuf, (DWORD)(cbKey + sizeof( *pBlob ) + sizeof( ULONG )), 0, CRYPT_IPSEC_HMAC_KEY, &state.hKey ) )
    {
        return STATUS_NOT_SUPPORTED;
    }
    
    HMAC_INFO   hmacInfo;
    hmacInfo.HashAlgid = CAPI_CALG( ALG_NAME );       
    hmacInfo.cbInnerString = 0;
    hmacInfo.cbOuterString = 0;
    
    CHECK( CryptCreateHash( g_capiProvider, CALG_HMAC, state.hKey, 0, &state.hHash ), "error create CAPI/" STRING( ALG_Name ) );
    CHECK( CryptSetHashParam( state.hHash, HP_HMAC_INFO, (PBYTE)&hmacInfo, 0 ), "Failed to set HMAC info" );
    
    return STATUS_SUCCESS;
}

VOID MacImp<ImpXxx, AlgXxx>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    CryptHashData( state.hHash, (PBYTE) pbData, (ULONG) cbData, 0 );
}

VOID MacImp<ImpXxx, AlgXxx>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    DWORD resLen = (DWORD) cbResult;
    CHECK( CryptGetHashParam( state.hHash, HP_HASHVAL, pbResult, &resLen, 0 ), "CryptGetHashParam failed" );
    CHECK( resLen == cbResult, "Wrong result length in CAPI " STRING( ALG_Name ) );
    CHECK( CryptDestroyHash( state.hHash ), "Failed to destroy hash" );
    state.hHash = 0;
    CHECK( CryptDestroyKey( state.hKey ), "Failed to delete key" );
    state.hKey = 0;
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
// Perf Invariant: buf 1 contains the key handle
//
VOID
algImpKeyPerfFunction<ImpXxx, AlgXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    //
    // Importing an HMAC key is convoluted
    //
    BYTE        importBuf[128];
    BLOBHEADER *pBlob = (BLOBHEADER *) &importBuf[0];
    SYMCRYPT_ASSERT( keySize <= 64 );

    pBlob->bType = PLAINTEXTKEYBLOB;
    pBlob->bVersion = CUR_BLOB_VERSION;
    pBlob->reserved = 0;
    pBlob->aiKeyAlg = CALG_RC2;       // An ugly hack: you use RC2 as the generic algorithm to import plaintext keys.
    //CHECK( cbKey < sizeof( importBuf ) - sizeof( *pBlob ) - sizeof( ULONG ), "Key too large for CAPI blob" );
    *(ULONG *)( &importBuf[sizeof( *pBlob )]) = (ULONG) keySize;
    memcpy( &importBuf[0] + sizeof( *pBlob ) + sizeof( ULONG ), buf2, keySize );

    CHECK( CryptImportKey(  g_capiProvider, 
                            importBuf, 
                            (DWORD)( keySize + sizeof( *pBlob ) + sizeof( ULONG )), 
                            0, 
                            CRYPT_IPSEC_HMAC_KEY, 
                            (HCRYPTKEY *) buf1 
                          ),
            "" );
    
}

VOID
algImpCleanPerfFunction<ImpXxx, AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    CHECK( CryptDestroyKey( *(HCRYPTKEY *) buf1 ), "" );
}

VOID 
algImpDataPerfFunction<ImpXxx, AlgXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    HCRYPTHASH h;
    HMAC_INFO   hmacInfo;
    hmacInfo.HashAlgid = CAPI_CALG( ALG_NAME );       
    hmacInfo.cbInnerString = 0;
    hmacInfo.cbOuterString = 0;
    
    CHECK( CryptCreateHash( g_capiProvider, CALG_HMAC, *(HCRYPTKEY *)buf1, 0, &h ), "" );
    CHECK( CryptSetHashParam( h, HP_HMAC_INFO, (PBYTE)&hmacInfo, 0 ), "" );
    DWORD reslen = PERF_BUFFER_SIZE;
    CHECK( CryptHashData( h, buf3, (ULONG) dataSize, 0 ), "" );
    CHECK( CryptGetHashParam( h, HP_HASHVAL, buf2, &reslen, 0 ), "" );
    CHECK( CryptDestroyHash( h ), "" );
}

