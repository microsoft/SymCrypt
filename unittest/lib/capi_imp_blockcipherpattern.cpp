//
// capi_imp_blockcipherpattern.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

//
// Perf Invariant: buf 1 contains the key handle
//
template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgXxx, ModeXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    HCRYPTKEY hKey;
    struct {
        BLOBHEADER header;
        DWORD      klen;
        BYTE       key[CAPI_MAX_KEY_SIZE];
    } capiKeyBlob;

    capiKeyBlob.header.bType = PLAINTEXTKEYBLOB;
    capiKeyBlob.header.bVersion = CUR_BLOB_VERSION;
    capiKeyBlob.header.reserved = 0;
    capiKeyBlob.klen = (ULONG) keySize;
    if( BlockCipherImpState<ImpXxx,AlgXxx,ModeXxx>::calg[ keySize ] == -1 )
    {
        // We don't have a CALG for this key size.
        return;
    }
    
    capiKeyBlob.header.aiKeyAlg = BlockCipherImpState<ImpXxx,AlgXxx,ModeXxx>::calg[ keySize ];
    
    SYMCRYPT_ASSERT( keySize <= CAPI_MAX_KEY_SIZE );
    memcpy( &capiKeyBlob.key[0], buf2, keySize );

    CHECK( CryptImportKey( g_capiProvider, (PBYTE) &capiKeyBlob, sizeof( capiKeyBlob ), 0, 0, &hKey ),
        "CAPI key import failure" );

    CHECK( NT_SUCCESS( CapiRc2KeySupport<AlgXxx>( hKey ) ), "CAPI RC2 key support failure" );

    DWORD mode = CAPI_MODE( ALG_MODE );
    if( mode != CRYPT_MODE_CBC )
    {
        CHECK( CryptSetKeyParam( hKey, KP_MODE, (PBYTE) &mode, 0 ), "Failed to set mode" );
    }
    *(HCRYPTKEY *) buf1 = hKey;
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgXxx, ModeXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    CHECK( CryptDestroyKey( *(HCRYPTKEY *) buf1 ), "Failed to destroy key" );
}

template<>
VOID 
algImpDataPerfFunction<ImpXxx, AlgXxx, ModeXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );

    ULONG len = (ULONG) dataSize;
    CHECK( CryptEncrypt( *(HCRYPTKEY*) buf1, 0, FALSE, 0, buf3, &len, len ), "Encryption failure" );
}

template<>
VOID 
algImpDecryptPerfFunction<ImpXxx, AlgXxx, ModeXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );

    ULONG len = (ULONG) dataSize;
    CHECK( CryptDecrypt( *(HCRYPTKEY*) buf1, 0, FALSE, 0, buf3, &len ), "Decryption failure" );
}



BlockCipherImp<ImpXxx, AlgXxx, ModeXxx>::BlockCipherImp()
{
    state.hKey = 0;

    CapiSetCalgArray<AlgXxx>( &state.calg[0] );
    
    m_perfDataFunction    = &algImpDataPerfFunction    <ImpXxx, AlgXxx, ModeXxx>;
    m_perfDecryptFunction = &algImpDecryptPerfFunction <ImpXxx, AlgXxx, ModeXxx>;
    m_perfKeyFunction     = &algImpKeyPerfFunction     <ImpXxx, AlgXxx, ModeXxx>;
    m_perfCleanFunction   = &algImpCleanPerfFunction   <ImpXxx, AlgXxx, ModeXxx>;
}

template<>
BlockCipherImp<ImpXxx, AlgXxx, ModeXxx>::~BlockCipherImp()
{
    if( state.hKey != 0 )
    {
        CryptDestroyKey( state.hKey );
        state.hKey = 0;
    }
}

SIZE_T BlockCipherImp<ImpXxx, AlgXxx, ModeXxx>::coreBlockLen()
{
    return SYMCRYPT_XXX_BLOCK_SIZE;
}

ULONG BlockCipherImpState<ImpXxx,AlgXxx,ModeXxx>::calg[CAPI_CALG_ARRAY_SIZE];

NTSTATUS 
BlockCipherImp<ImpXxx, AlgXxx, ModeXxx>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    if( state.hKey != 0 )
    {
        CHECK( CryptDestroyKey( state.hKey ), "?" );
        state.hKey = 0;
    }

    struct {
        BLOBHEADER header;
        DWORD      klen;
        BYTE       key[CAPI_MAX_KEY_SIZE];
    } capiKeyBlob;

    if( (ModeXxx::flags & MODE_FLAG_CFB) != 0 && g_modeCfbShiftParam != 1 )
    {
        return STATUS_NOT_SUPPORTED;
    }

    capiKeyBlob.header.bType = PLAINTEXTKEYBLOB;
    capiKeyBlob.header.bVersion = CUR_BLOB_VERSION;
    capiKeyBlob.header.reserved = 0;
    capiKeyBlob.klen = (ULONG) cbKey;
    CHECK( cbKey < ARRAY_SIZE( state.calg ), "Key too long" );
    if( state.calg[ cbKey ] == -1 || g_rc2EffectiveKeyLength > 128 || g_rc2EffectiveKeyLength < 16 )
    {
        // We don't have a CALG for this key size, or the effective key size is too large
        return STATUS_NOT_SUPPORTED;
    }
    
    capiKeyBlob.header.aiKeyAlg = state.calg[ cbKey ];
    
    CHECK( cbKey < sizeof( capiKeyBlob.key ), "Key too large for CAPI blob" );
    memcpy( &capiKeyBlob.key[0], pbKey, cbKey );

    CHECK3( CryptImportKey( g_capiProvider, (PBYTE) &capiKeyBlob, sizeof( capiKeyBlob ), 0, 0, &state.hKey ),
        "CAPI key import failure %08x", GetLastError() );

    CHECK3( NT_SUCCESS(CapiRc2KeySupport<AlgXxx>( state.hKey )) , "Rc2 key support failure %d", g_rc2EffectiveKeyLength );

    DWORD mode = CAPI_MODE( ALG_MODE );
    CHECK( CryptSetKeyParam( state.hKey, KP_MODE, (PBYTE) &mode, 0 ), "Failed to set mode" );
    
    return STATUS_SUCCESS;
}

VOID BlockCipherImp<ImpXxx, AlgXxx, ModeXxx>::encrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    BYTE buf[32];
    ULONG len;
    SIZE_T coreBlockLength = coreBlockLen();
    SIZE_T cbWhole;
    SIZE_T cbPartial;

    //
    // You can set a new IV value, but it is only picked up if CAPI thinks you starting a new encryption.
    // To do that we have to call Encrypt with the final flag.
    //
    if( cbChain > 0 )
    {
        CHECK( cbChain == chainBlockLen(), "?" );
        len = 0;
        CHECK( CryptEncrypt( state.hKey, 0, TRUE, 0, buf, &len, 32 ), "Failed encrypt with final=TRUE" );
        CHECK3( CryptSetKeyParam( state.hKey, KP_IV, pbChain, 0 ), "Failed to set IV %08x", GetLastError() );
    }
    memcpy( pbDst, pbSrc, cbData );

    cbPartial = cbData % coreBlockLength;

    if( ( ModeXxx::flags & MODE_FLAG_CFB ) != 0 && cbPartial > 0 )
    {
        CHECK( cbChain == coreBlockLength, "?" );

        //
        // CFB mode can have arbitrary length messages, but CAPI doesn't support that.
        // To help test SymCrypt we implement it here using messages that are a multiple of the block size.
        //
        // First we do the whole blocks
        //

        cbWhole = cbData - cbPartial;
        if( cbWhole > 0 )
        {
            len = (DWORD) cbWhole;
            CHECK( CryptEncrypt( state.hKey, 0, FALSE, 0, pbDst, &len, len ), "Encryption failure" );
            CHECK( len == cbWhole, "Length failure" );
        }

        //
        // Then the remaining bytes
        //
        CHECK( cbPartial < coreBlockLength, "??" );

        memcpy( buf, pbDst + cbWhole, cbPartial );
        len = (DWORD) coreBlockLength;
        CHECK( CryptEncrypt( state.hKey, 0, FALSE, 0, buf, &len, len ), "Encryption failure" );
        CHECK( len == coreBlockLength, "Length failure" );
        memcpy( pbDst + cbWhole, buf, cbPartial );

        //
        // Now we have to re-construct the proper chaining value
        //
        if( cbData >= coreBlockLength )
        {
            memcpy( pbChain, pbDst + cbData - cbChain, cbChain );
        }
        else
        {
            memcpy( pbChain, pbChain + cbData, cbChain - cbData );
            memcpy( pbChain + cbChain - cbData, pbDst, cbData );
        }

        //
        // And set the chaining state inside CAPI
        //
        //len = 0;
        //CHECK( CryptEncrypt( state.hKey, 0, TRUE, 0, buf, &len, 32 ), "Failed encrypt with final=TRUE" );
        //CHECK3( CryptSetKeyParam( state.hKey, KP_IV, pbChain, 0 ), "Failed to set IV %08x", GetLastError() );

    }
    else
    {
        len = (ULONG) cbData;
        CHECK( CryptEncrypt( state.hKey, 0, FALSE, 0, pbDst, &len, len ), "Encryption failure" );
        CHECK( len == cbData, "Length failure" );

        if( cbChain > 0 && cbData > 0 )
        {
            CHECK( cbChain <= cbData, "?" );
            memcpy( pbChain, pbDst + cbData - cbChain, cbChain );
        }
    }
}

VOID BlockCipherImp<ImpXxx, AlgXxx, ModeXxx>::decrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    BYTE buf[32];
    ULONG len;
    SIZE_T coreBlockLength = coreBlockLen();
    SIZE_T cbWhole;
    SIZE_T cbPartial;

    //
    // You can set a new IV value, but it is only picked up if CAPI thinks you starting a new encryption.
    // To do that we have to call Encrypt with the final flag.
    //
    if( cbChain > 0 && cbData > 0)
    {
        len = 0;
        CHECK( CryptEncrypt( state.hKey, 0, TRUE, 0, buf, &len, 32 ), "Failed encrypt with final=TRUE" );
        CHECK( CryptSetKeyParam( state.hKey, KP_IV, pbChain, 0 ), "Failed to set IV" );
        CHECK( cbChain <= sizeof( buf ), "?" );

        if( cbData < cbChain )
        {
            memcpy( pbChain, pbChain + cbData, cbChain - cbData );
            memcpy( pbChain + cbChain - cbData, pbSrc, cbData );
        }
        else
        {
            memcpy( pbChain, pbSrc + cbData - cbChain, cbChain );
        }
    }

    memcpy( pbDst, pbSrc, cbData );
    cbPartial = cbData % coreBlockLength;

    if( ( ModeXxx::flags & MODE_FLAG_CFB ) != 0 && cbPartial > 0 )
    {
        CHECK( cbChain == coreBlockLength, "?" );

        cbWhole = cbData -cbPartial;

        if( cbWhole > 0 )
        {
            len = (DWORD) cbWhole;
            CHECK( CryptDecrypt( state.hKey, 0, FALSE, 0, pbDst, &len ), "Decryption failure" );
            CHECK( len == cbWhole, "Length failure" );
        }

        memcpy( buf, pbDst + cbWhole, cbPartial );
        len = (DWORD) coreBlockLength;
        CHECK( CryptDecrypt( state.hKey, 0, FALSE, 0, buf, &len ), "Decryption failure" );
        CHECK( len == coreBlockLength, "Length failure" );
        memcpy( pbDst + cbWhole, buf, cbPartial );

        //
        // Se the proper chaining value again
        //
        //len = 0;
        //CHECK( CryptEncrypt( state.hKey, 0, TRUE, 0, buf, &len, 32 ), "Failed Encrypt with final=TRUE" );
        //CHECK( CryptSetKeyParam( state.hKey, KP_IV, pbChain, 0 ), "Failed to set IV" );
        //
    }
    else
    {
        len = (ULONG) cbData;
        CHECK( CryptDecrypt( state.hKey, 0, FALSE, 0, pbDst, &len ), "Decryption failure" );
        CHECK( len == cbData, "Length failure" );
    }
}


