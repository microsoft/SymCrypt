//
// cng_imp_blockcipherpattern.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

BCRYPT_ALG_HANDLE BlockCipherImpState<ImpXxx, AlgXxx, ModeXxx>::hAlg;

template<>
VOID 
algImpKeyPerfFunction<ImpXxx, AlgXxx, ModeXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    BCRYPT_KEY_HANDLE hKey; 
    BCRYPT_ALG_HANDLE hAlg = BlockCipherImpState<ImpXxx, AlgXxx, ModeXxx>::hAlg;
    UNREFERENCED_PARAMETER( buf3 );

    CHECK( NT_SUCCESS( CngRc2KeySupport<AlgXxx>( hAlg, keySize ) ), "Error setting eff key len" );
    CHECK( NT_SUCCESS( CngGenerateSymmetricKeyFn(
                            hAlg,
                            &hKey,
                            buf1 + 16, 768,
                            buf2, (ULONG) keySize,
                            g_cngKeySizeFlag ) ), 
           "Error importing key" );
    
    
    *(BCRYPT_KEY_HANDLE *) buf1 = hKey;
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgXxx, ModeXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    CHECK( NT_SUCCESS( CngDestroyKeyFn( *(BCRYPT_KEY_HANDLE *) buf1 ) ), "?" );
}

template<>
VOID 
algImpDataPerfFunction<ImpXxx, AlgXxx, ModeXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    NTSTATUS status;
    ULONG res;
    status = CngEncryptFn( *(BCRYPT_KEY_HANDLE *)buf1, buf2, (ULONG) dataSize, NULL, NULL, 0, buf3, (ULONG) dataSize, &res, 0 );
    CHECK3( NT_SUCCESS( status ), "BcryptEncrypt error %08x", status );
}

template<>
VOID 
algImpDecryptPerfFunction<ImpXxx, AlgXxx, ModeXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    NTSTATUS status;
    ULONG res;
    status = CngDecryptFn( *(BCRYPT_KEY_HANDLE *)buf1, buf2, (ULONG) dataSize, NULL, NULL, 0, buf3, (ULONG) dataSize, &res, 0 );
    CHECK3( NT_SUCCESS( status ), "BcryptEncrypt error %08x", status );
}



template<>
BlockCipherImp<ImpXxx, AlgXxx, ModeXxx>::BlockCipherImp()
{
    DWORD   res;

    CHECK( CngOpenAlgorithmProviderFn( &state.hAlg, PROVIDER_NAME( ALG_NAME ), NULL, 0 ) == STATUS_SUCCESS, 
        "Could not open CNG/" STRING( ALG_Name ) );
    CHECK( CngSetPropertyFn( state.hAlg, BCRYPT_CHAINING_MODE, (PBYTE) CNG_XXX_CHAIN_MODE, sizeof( CNG_XXX_CHAIN_MODE ), 0 ) == STATUS_SUCCESS, 
        "Could not set CNG/" STRING( ALG_Name ) STRING( ALG_Mode ) "mode" );

    CHECK( CngGetPropertyFn( state.hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&state.keyObjSize, sizeof( DWORD ), &res, 0 ) == STATUS_SUCCESS && res == sizeof( DWORD ),
        "Could not get Authenc small object size" );

    state.hKey = 0;

    m_perfKeyFunction = &algImpKeyPerfFunction<ImpXxx, AlgXxx, ModeXxx>;
    m_perfCleanFunction = &algImpCleanPerfFunction<ImpXxx, AlgXxx, ModeXxx>;
    m_perfDataFunction = &algImpDataPerfFunction<ImpXxx, AlgXxx, ModeXxx>;
    m_perfDecryptFunction = &algImpDecryptPerfFunction<ImpXxx, AlgXxx, ModeXxx>;
}

template<>
BlockCipherImp<ImpXxx, AlgXxx, ModeXxx>::~BlockCipherImp()
{
    if( state.hKey != 0 )
    {
        CHECK( NT_SUCCESS( CngDestroyKeyFn( state.hKey ) ), "Could not destroy key" );
        state.hKey = 0;
        CHECK( *state.pMagic == 'ntft', "Magic marker overwritten" );
    }
    CHECK( NT_SUCCESS( CngCloseAlgorithmProviderFn( state.hAlg, 0 )), "Could not close CNG/" STRING( ALG_Name ) );
    state.hAlg = 0;
}

SIZE_T BlockCipherImp<ImpXxx, AlgXxx, ModeXxx>::coreBlockLen()
{
    ULONG   len;
    ULONG   res;
    
    CHECK( NT_SUCCESS( CngGetPropertyFn( state.hAlg, BCRYPT_BLOCK_LENGTH, (PBYTE) &len, sizeof( len ), &res, 0 ) ),
        "Could not query block length CNG/" STRING( ALG_Name ) );
    CHECK( res == sizeof( len ), "??" );
    
    return len;
}

NTSTATUS BlockCipherImp<ImpXxx, AlgXxx, ModeXxx>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    NTSTATUS status = STATUS_SUCCESS;
    DWORD tmp, tmp2;
    BYTE blob[1024];
    ULONG cbBlob;
    static int keyType = 0;
    PBYTE   pKeyObject;
    DWORD   cbKeyObject;

    if( state.hKey != 0 )
    {
        CHECK( NT_SUCCESS( CngDestroyKeyFn( state.hKey ) ), "Could not destroy key" );
        state.hKey = 0;
        CHECK( *state.pMagic == 'ntft', "Magic marker overwritten" );
    }

    status = CngRc2KeySupport<AlgXxx>( state.hAlg, cbKey );
    if( !NT_SUCCESS( status ) )
    {
        goto Cleanup;
    }

    keyType = (keyType + 1) % 2;
    switch( keyType )
    {
    case 0:
        pKeyObject = &state.keyObjectBuffer[0];
        cbKeyObject = state.keyObjSize;
        break;
    case 1:
        pKeyObject = NULL;
        cbKeyObject = 0;
        break;
    default:
        CHECK( FALSE, "?" );
        goto Cleanup;
    }
    //iprint( "%c", '0' + keyType );

    CHECK( cbKeyObject <= sizeof( state.keyObjectBuffer ) - 4, "?" );
    state.pMagic = (ULONG *) &state.keyObjectBuffer[cbKeyObject];

    *state.pMagic = 'ntft';

    status = CngGenerateSymmetricKeyFn(
                            state.hAlg,
                            &state.hKey,
                            pKeyObject, cbKeyObject,
                            (PBYTE) pbKey, (ULONG) cbKey,
                            g_cngKeySizeFlag );

    if( !NT_SUCCESS( status ) )
    {
        return status;
    }

    if( (ModeXxx::flags & MODE_FLAG_CFB) != 0 )
    {
        tmp = (DWORD) g_modeCfbShiftParam;
        status = CngSetPropertyFn(
                    state.hKey,
                    BCRYPT_MESSAGE_BLOCK_LENGTH,
                    (PBYTE)&tmp,
                    sizeof( tmp ),
                    0 );
        if( !NT_SUCCESS( status ) )
        {
            CHECK( g_osVersion < 0x0602, "CFB parameter set-property failed on W8" );

            if( g_modeCfbShiftParam == 1 )
            {
                //
                // Original CFB implementation still works for shiftParam == 1
                //
                status = STATUS_SUCCESS;
            }
            goto Cleanup;
        }

        //
        // Tests below can be removed once it is in the CNG BVTs
        //
        tmp = 0;
        CHECK( NT_SUCCESS( CngGetPropertyFn(
                            state.hKey,
                            BCRYPT_MESSAGE_BLOCK_LENGTH,
                            (PBYTE)&tmp,
                            sizeof( tmp ),
                            &tmp2,
                            0 )),
                    "Error getting CFB shift param" );
        CHECK( tmp == g_modeCfbShiftParam, "?" );

    }

    //
    // Test the opaque blob import/export
    // Can be removed once this is part of the CNG BVTs
    //
    
    CHECK( *state.pMagic == 'ntft', "Magic marker overwritten" );

    CHECK( NT_SUCCESS( CngExportKeyFn( state.hKey, NULL, BCRYPT_OPAQUE_KEY_BLOB, blob, sizeof( blob ), &cbBlob, 0 ) ), "Opaque blob export error" );
    CHECK( NT_SUCCESS( CngDestroyKeyFn( state.hKey ) ), "Could not destroy key" );
    CHECK( *state.pMagic == 'ntft', "Magic marker overwritten" );
    CHECK( NT_SUCCESS( CngImportKeyFn( state.hAlg, NULL, BCRYPT_OPAQUE_KEY_BLOB, &state.hKey, pKeyObject, cbKeyObject, blob, cbBlob, 0 ) ), "Opaque blob import error" );
    
    CHECK( *state.pMagic == 'ntft', "Magic marker overwritten" );

Cleanup:
    return status;        
    
}


VOID
BlockCipherImp<ImpXxx, AlgXxx, ModeXxx>::encrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    ULONG res;
    PBYTE pbIv = (cbChain == 0) ? NULL : (PBYTE) pbChain;
    if( cbData == 0 )
    {
        // Vista doesn't like 0-length requests
        return;
    }
    CHECK( NT_SUCCESS( CngEncryptFn( state.hKey, (PBYTE) pbSrc, (ULONG) cbData, NULL, pbIv, (ULONG) cbChain, pbDst, (ULONG) cbData, &res, 0 ) ),
        "Encryption error" );
    CHECK( res == cbData, "?" );
}

VOID
BlockCipherImp<ImpXxx, AlgXxx, ModeXxx>::decrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    NTSTATUS status;
    ULONG res;
    PBYTE pbIv = (cbChain == 0) ? NULL : (PBYTE) pbChain;

    if( cbData == 0 )
    {
        // Vista doesn't like 0-length requests
        return;
    }
    status = CngDecryptFn( state.hKey, (PBYTE) pbSrc, (ULONG) cbData, NULL, pbIv, (ULONG) cbChain, pbDst, (ULONG) cbData, &res, 0 );
    if( !NT_SUCCESS( status ) )
    {
        print( "\nkey: %p, pbSrc: %p, cbData:%d, pbIv: %p, cbChain:%d, pbDst:%p, cbData:%d, res:%d\n",
            state.hKey, pbSrc, (ULONG) cbData, pbIv, (ULONG) cbChain, pbDst, (ULONG) cbData, res );
    }
        
    CHECK( NT_SUCCESS( status ), "Decryption error" );
    CHECK( res == cbData, "?" );
}


