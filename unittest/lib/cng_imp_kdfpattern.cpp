//
// Pattern file for the CNG KDF implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

BCRYPT_ALG_HANDLE KdfImpState<ImpXxx, AlgXxx, BaseAlgXxx>::hAlg;

//
// Empty constructor. 
//
template<>
KdfImp<ImpXxx, AlgXxx, BaseAlgXxx>::KdfImp()
{
    CHECK( CngOpenAlgorithmProviderFn( &state.hAlg, PROVIDER_NAME( ALG_NAME ), NULL, 0 ) == STATUS_SUCCESS, 
        "Could not open CNG/" STRING( ALG_Name ) );

    CHECK3( CngOpenAlgorithmProviderFn( &state.hBaseAlg, CNG_XXX_HASH_ALG_NAMEU, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG  ) == STATUS_SUCCESS, 
        "Could not open CNG/%s", CNG_XXX_HASH_ALG_NAMEU );

    m_perfDataFunction = &algImpDataPerfFunction <ImpXxx, AlgXxx, BaseAlgXxx>;
    m_perfKeyFunction  = &algImpKeyPerfFunction  <ImpXxx, AlgXxx, BaseAlgXxx>;
    m_perfCleanFunction= &algImpCleanPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>;
}

template<>
KdfImp<ImpXxx, AlgXxx, BaseAlgXxx>::~KdfImp()
{
    CHECK3( NT_SUCCESS( CngCloseAlgorithmProviderFn( state.hAlg    , 0 )), "Could not close CNG/%s", STRING( ALG_Name ) );
    CHECK3( NT_SUCCESS( CngCloseAlgorithmProviderFn( state.hBaseAlg, 0 )), "Could not close CNG/%s", CNG_XXX_HASH_ALG_NAMEU );
    state.hAlg = 0;
}


VOID 
algImpKeyPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    BCRYPT_KEY_HANDLE hKey;
    BCRYPT_ALG_HANDLE hAlg = KdfImpState<ImpXxx, AlgXxx, BaseAlgXxx>::hAlg;
    UNREFERENCED_PARAMETER( buf3 );

    CHECK( NT_SUCCESS( CngGenerateSymmetricKeyFn(
                            hAlg,
                            &hKey,
                            buf1 + 16, 1 << 12,     // 4 kB for key object
                            buf2, (ULONG) keySize,
                            0 ) ), 
           "Error importing key" );
    
    *(BCRYPT_KEY_HANDLE *) buf1 = hKey;
}

VOID 
algImpCleanPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    CHECK( NT_SUCCESS( CngDestroyKeyFn( *(BCRYPT_KEY_HANDLE *) buf1 ) ), "?" );
}


