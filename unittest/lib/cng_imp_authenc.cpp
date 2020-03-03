//
// cng_imp_authenc.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

BCRYPT_ALG_HANDLE AuthEncImpState<ImpXxx, AlgXxx, ModeXxx>::hAlg;

template<>
VOID 
algImpKeyPerfFunction< ImpXxx, AlgXxx, ModeXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    BCRYPT_KEY_HANDLE hKey; 
    BCRYPT_ALG_HANDLE hAlg = AuthEncImpState<ImpXxx, AlgXxx, ModeXxx>::hAlg;
    UNREFERENCED_PARAMETER( buf3 );

    CHECK( NT_SUCCESS( CngGenerateSymmetricKeyFn(
                            hAlg,
                            &hKey,
                            buf1 + 16, 1 << 12,     // 4 kB for key object
                            buf2, (ULONG) keySize,
                            g_cngKeySizeFlag ) ), 
           "Error importing key" );
    
    
    *(BCRYPT_KEY_HANDLE *) buf1 = hKey;
}

template<>
VOID
algImpDataPerfFunction<ImpXxx,AlgXxx, ModeXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    NTSTATUS status;
    ULONG res;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;

    BCRYPT_INIT_AUTH_MODE_INFO( authInfo );

    authInfo.pbNonce = buf2;
    authInfo.cbNonce = 12;              // 12 is a valid nonce size for both CCM and GCM
    //authInfo.pbAuthData = NULL;
    //authInfo.cbAuthData = 0;
    authInfo.pbTag = buf2+16;
    authInfo.cbTag = 16;
    //authInfo.pbMacContext = NULL;
    //authInfo.cbMacContext = 0;
    //authInfo.cbAAD = 0;
    //authInfo.cbData = 0;
    //authInfo.dwFlags = 0;
    
    
    status = CngEncryptFn( *(BCRYPT_KEY_HANDLE *)buf1, buf2 + 32, (ULONG) dataSize, &authInfo, NULL, 0, buf3, (ULONG) dataSize, &res, 0 );
    CHECK3( NT_SUCCESS( status ), "BcryptEncrypt error %08x", status );
}

template<>
VOID
algImpDecryptPerfFunction<ImpXxx,AlgXxx, ModeXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    NTSTATUS status;
    ULONG res;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;

    BCRYPT_INIT_AUTH_MODE_INFO( authInfo );

    authInfo.pbNonce = buf2;
    authInfo.cbNonce = 12;
    //authInfo.pbAuthData = NULL;
    //authInfo.cbAuthData = 0;
    authInfo.pbTag = buf2+16;
    authInfo.cbTag = 16;
    //authInfo.pbMacContext = NULL;
    //authInfo.cbMacContext = 0;
    //authInfo.cbAAD = 0;
    //authInfo.cbData = 0;
    //authInfo.dwFlags = 0;
    
#pragma prefast( suppress: 28193, "Do not test return status as this is a performance measurement function" );
    status = CngDecryptFn( *(BCRYPT_KEY_HANDLE *)buf1, buf3, (ULONG) dataSize, &authInfo, NULL, 0, buf2+32, (ULONG) dataSize, &res, 0 );
    (void) status;
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgXxx, ModeXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    CHECK( NT_SUCCESS( CngDestroyKeyFn( *(BCRYPT_KEY_HANDLE *) buf1 ) ), "?" );
}

template<>
AuthEncImp<ImpXxx, AlgXxx, ModeXxx>::AuthEncImp()
{
    DWORD res;
    CHECK( CngOpenAlgorithmProviderFn( &state.hAlg, BCRYPT_AES_ALGORITHM, NULL, 0 ) == STATUS_SUCCESS, 
        "Could not open CNG/AES" );

    CHECK( CngOpenAlgorithmProviderFn( &state.hAlgNoMode, BCRYPT_AES_ALGORITHM, NULL, 0 ) == STATUS_SUCCESS, 
        "Could not open CNG/AES" );

    CHECK( CngGetPropertyFn( state.hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&state.keyObjSizeSmall, sizeof( DWORD ), &res, 0 ) == STATUS_SUCCESS && res == sizeof( DWORD ),
        "Could not get Authenc small object size" );

    CHECK( CngSetPropertyFn( state.hAlg, BCRYPT_CHAINING_MODE, (PBYTE) BCRYPT_CHAIN_MODE_XXX, sizeof( BCRYPT_CHAIN_MODE_XXX ), 0 ) == STATUS_SUCCESS, 
        "Could not set CNG/AES[GC]CMmode" );

    CHECK( CngGetPropertyFn( state.hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&state.keyObjSizeBig, sizeof( DWORD ), &res, 0 ) == STATUS_SUCCESS && res == sizeof( DWORD ),
        "Could not get Authenc big object size" );

    CHECK( state.keyObjSizeSmall <= state.keyObjSizeBig, "CNG authenc key object size mismatch" );

    //iprint( "AES-%s: %d, %d\n", s_modeName.c_str(), state.keyObjSizeSmall, state.keyObjSizeBig );

    state.hKey = 0;
    state.pMagic = NULL;

    BCRYPT_INIT_AUTH_MODE_INFO( state.authInfo );

    m_perfKeyFunction     = &algImpKeyPerfFunction    <ImpXxx, AlgXxx, ModeXxx>;
    m_perfCleanFunction   = &algImpCleanPerfFunction  <ImpXxx, AlgXxx, ModeXxx>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpXxx, AlgXxx, ModeXxx>;
    m_perfDecryptFunction = &algImpDecryptPerfFunction<ImpXxx, AlgXxx, ModeXxx>;
}

template<>
AuthEncImp<ImpXxx, AlgXxx, ModeXxx>::~AuthEncImp()
{
    if( state.hKey != 0 )
    {
        CHECK( NT_SUCCESS( CngDestroyKeyFn( state.hKey ) ), "Could not destroy key" );
        state.hKey = 0;
    }

    CHECK( state.hAlg != 0 && state.hAlgNoMode != 0, "Uninitialized alg handles" );

    CHECK( NT_SUCCESS( CngCloseAlgorithmProviderFn( state.hAlg, 0 )), "Could not close CNG/AES" );
    state.hAlg = 0;

    CHECK( NT_SUCCESS( CngCloseAlgorithmProviderFn( state.hAlgNoMode, 0 )), "Could not close CNG/AES" );
    state.hAlgNoMode = 0;

    CHECK( state.pMagic == NULL || *state.pMagic == 'ntft', "Magic marker overwritten" );
}


template<>
std::set<SIZE_T>
AuthEncImp<ImpXxx, AlgXxx, ModeXxx>::getKeySizes()
{
    BCRYPT_KEY_LENGTHS_STRUCT cngKeyLengths;
    
    std::set<SIZE_T> res;
    ULONG resLen;

    CHECK( NT_SUCCESS( CngGetPropertyFn( state.hAlg, BCRYPT_KEY_LENGTHS, (PBYTE) &cngKeyLengths, sizeof( cngKeyLengths ), &resLen, 0 ) ),
        "Could not query key lengths CNG/AESCCM" );
    CHECK( resLen == sizeof( cngKeyLengths ), "?" );

    for( SIZE_T i= cngKeyLengths.dwMinLength; i <= cngKeyLengths.dwMaxLength; i += cngKeyLengths.dwIncrement )
    {
        //
        // Key lengths are in bits, so we divide by 8 to get byte sizes.
        //
        res.insert( i/8 );
    }
    
    return res;
}


template<>
std::set<SIZE_T>
AuthEncImp<ImpXxx, AlgXxx, ModeXxx>::getTagSizes()
{
    BCRYPT_AUTH_TAG_LENGTHS_STRUCT cngTagLengths;
    
    std::set<SIZE_T> res;
    ULONG resLen;

    CHECK( NT_SUCCESS( CngGetPropertyFn( state.hAlg, BCRYPT_AUTH_TAG_LENGTH, (PBYTE) &cngTagLengths, sizeof( cngTagLengths ), &resLen, 0 ) ),
        "Could not query key lengths CNG/AESCCM" );
    CHECK( resLen == sizeof( cngTagLengths ), "?" );

    for( SIZE_T i= cngTagLengths.dwMinLength; i <= cngTagLengths.dwMaxLength; i += cngTagLengths.dwIncrement )
    {
        res.insert( i );
    }
    
    return res;
}


template<>
NTSTATUS
AuthEncImp<ImpXxx, AlgXxx, ModeXxx>::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    static int keyType = 0;
    PBYTE   pKeyObject;
    DWORD   cbKeyObject;
    BCRYPT_ALG_HANDLE  hAlg;
    NTSTATUS status = STATUS_SUCCESS;

    if( state.hKey != 0 )
    {
        CHECK( NT_SUCCESS( CngDestroyKeyFn( state.hKey ) ), "Could not destroy key" );
        state.hKey = 0;
        CHECK( *state.pMagic == 'ntft', "Magic marker overwritten" );
    }

    //
    // We go through the 4 different ways of generating a key in turn...
    //
    keyType = (keyType + 1) % 6;
    if( g_osVersion <= 0x0601 )
    {
        // Win7 and below doesn't let you set the chaining mode on the key
        keyType = keyType % 3;
    }
    switch( keyType )
    {
    case 0:
        hAlg = state.hAlg;
        pKeyObject = &state.keyObjectBuffer[0];
        cbKeyObject = state.keyObjSizeSmall;
        break;
    case 1:
        hAlg = state.hAlg;
        pKeyObject = &state.keyObjectBuffer[0];
        cbKeyObject = state.keyObjSizeBig;
        break;
    case 2:
        hAlg = state.hAlg;
        pKeyObject = NULL;
        cbKeyObject = 0;
        break;
    case 3:
        hAlg = state.hAlgNoMode;
        pKeyObject = &state.keyObjectBuffer[0];
        cbKeyObject = state.keyObjSizeSmall;
        break;
    case 4:
        hAlg = state.hAlgNoMode;
        pKeyObject = &state.keyObjectBuffer[0];
        cbKeyObject = state.keyObjSizeBig;
        break;
    case 5:
        hAlg = state.hAlgNoMode;
        pKeyObject = NULL;
        cbKeyObject = 0;
        break;
    default:
        CHECK( FALSE, "?" );
        goto cleanup;
    }
    //iprint( "%c", '0' + keyType );

    //
    // We always place the magic marker in the key object buffer, even if we have the key object 
    // elsewhere.
    //
    CHECK( cbKeyObject <= sizeof( state.keyObjectBuffer ) - 4, "?" );
    state.pMagic = (ULONG *) &state.keyObjectBuffer[cbKeyObject];

    *state.pMagic = 'ntft';

    status = CngGenerateSymmetricKeyFn(
                            hAlg,
                            &state.hKey,
                            pKeyObject, cbKeyObject,
                            (PBYTE) pbKey, (ULONG) cbKey,
                            g_cngKeySizeFlag );

    if( g_osVersion == 0x0600 && !NT_SUCCESS( status ) )
    {
        //
        // For some reason this fails on Vista. Haven't figured out why yet, isn't important enough to investigate.
        //
        goto cleanup;
    }

    if( !NT_SUCCESS( status ) )
    {
        print( "\n hAlg:%s, hKey:%p, pKeyObj:%p, cbKeyObj:%d, pbKey:%p, cbKey:%d, flag:%x, status:%x",
                hAlg == state.hAlg ? "hAlg" : "hAlgNoMode", &state.hKey, pKeyObject, (ULONG) cbKeyObject, pbKey, (ULONG) cbKey, g_cngKeySizeFlag, status );
    }

    CHECK( NT_SUCCESS( status ),  "Error importing key" );

    if( hAlg == state.hAlgNoMode )
    {
        status = CngSetPropertyFn( state.hKey, BCRYPT_CHAINING_MODE, (PBYTE) BCRYPT_CHAIN_MODE_XXX, sizeof( BCRYPT_CHAIN_MODE_XXX ), 0 );
        CHECK3( status == STATUS_SUCCESS, "Could not set CNG/AES[GC]CMmode %08x", status );
    }

    CHECK( *state.pMagic == 'ntft', "Magic marker overwritten" );

    state.inComputation = FALSE;

    status = STATUS_SUCCESS;

cleanup:
    return status;        
}

template<>
VOID
AuthEncImp<ImpXxx, AlgXxx, ModeXxx>::setTotalCbData( SIZE_T cbData )
{
    state.totalCbData = cbData;
}

template<>
NTSTATUS
AuthEncImp<ImpXxx, AlgXxx, ModeXxx>::encrypt(
        _In_reads_( cbNonce )       PCBYTE  pbNonce,      
                                    SIZE_T  cbNonce, 
        _In_reads_( cbAuthData )    PCBYTE  pbAuthData, 
                                    SIZE_T  cbAuthData, 
        _In_reads_( cbData )        PCBYTE  pbSrc, 
        _Out_writes_( cbData )      PBYTE   pbDst, 
                                    SIZE_T  cbData,
        _Out_writes_( cbTag )       PBYTE   pbTag, 
                                    SIZE_T  cbTag,
                                    ULONG   flags )
{
    NTSTATUS status = STATUS_SUCCESS;

    CHECK( (flags & ~AUTHENC_FLAG_PARTIAL) == 0, "Unknown flag" );

    BOOL partial = (flags & AUTHENC_FLAG_PARTIAL) != 0;
    BOOL last = pbTag != NULL;

    // Ignore the CNG errors related to chained authenticated encryption
    // with AES GCM and CCM until/if they are fixed on the CNG side.
    //
    // The former does not accept NULL IV while the latter never worked.
    // Also they require the input size to be multiple of the AES blocksize
    // which is not required by SymCrypt and not enforced in our tests.
    if (partial)
    {
        status = STATUS_NOT_IMPLEMENTED;
        return status;
    }

    if( !state.inComputation )
    {
        // Only init the authInfo if we are starting a new computation
        BCRYPT_INIT_AUTH_MODE_INFO( state.authInfo );
        // This sets cbAAD, cbData and dwFlags to 0 in the authinfo
    }

    // Set/update Nonce, AAD, and Tag info
    state.authInfo.pbNonce = (PBYTE) pbNonce;
    state.authInfo.cbNonce = (ULONG) cbNonce;
    state.authInfo.pbAuthData = (PBYTE) pbAuthData;
    state.authInfo.cbAuthData = (ULONG) cbAuthData;
    state.authInfo.pbTag = pbTag;
    state.authInfo.cbTag = (ULONG) cbTag;

    if( partial )
    {
        state.authInfo.pbMacContext = &state.abMacContext[0];
        state.authInfo.cbMacContext = sizeof( state.abMacContext );
        if( last )
        {
            state.authInfo.dwFlags &= ~BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
        } else {
            state.authInfo.dwFlags |= BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
        }
    }

    ULONG res;
    status = CngEncryptFn( state.hKey, (PBYTE) pbSrc, (ULONG) cbData, &state.authInfo, NULL, 0, pbDst, (ULONG) cbData, &res, 0 );
    CHECK( NT_SUCCESS( status ), "Encryption error" );
    CHECK( res == cbData, "?" );


    if( last )
    {
        state.inComputation = FALSE;
    }

    return status;
}


template<>
NTSTATUS
AuthEncImp<ImpXxx, AlgXxx, ModeXxx>::decrypt(
        _In_reads_( cbNonce )       PCBYTE  pbNonce,      
                                    SIZE_T  cbNonce, 
        _In_reads_( cbAuthData )    PCBYTE  pbAuthData, 
                                    SIZE_T  cbAuthData, 
        _In_reads_( cbData )        PCBYTE  pbSrc, 
        _Out_writes_( cbData )      PBYTE   pbDst, 
                                    SIZE_T  cbData,
        _In_reads_( cbTag )         PCBYTE  pbTag, 
                                    SIZE_T  cbTag,
                                    ULONG   flags )
{

    NTSTATUS status;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO( authInfo );

    if( flags != 0 )
    {
        status = STATUS_NOT_SUPPORTED;
        goto cleanup;
    }

    authInfo.pbNonce = (PBYTE) pbNonce;
    authInfo.cbNonce = (ULONG) cbNonce;
    authInfo.pbAuthData = (PBYTE) pbAuthData;
    authInfo.cbAuthData = (ULONG) cbAuthData;
    authInfo.pbTag = (PBYTE) pbTag;
    authInfo.cbTag = (ULONG) cbTag;
    //authInfo.pbMacContext = NULL;
    //authInfo.cbMacContext = 0;
    //authInfo.cbAAD = 0;
    //authInfo.cbData = 0;
    //authInfo.dwFlags = 0;

    ULONG res;
    status = CngDecryptFn( state.hKey, (PBYTE) pbSrc, (ULONG) cbData, &authInfo, NULL, 0, pbDst, (ULONG) cbData, &res, 0 );

    if( !NT_SUCCESS( status ) )
    {
        //
        // Mimic SymCrypt and wipe the result buffer.
        //
        memset( pbDst, 0, cbData );
    }
    else
    {
        CHECK( res == cbData, "?" );
    }

cleanup:    
    return status;
}


