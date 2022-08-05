//
// Pattern file for the SymCrypt block cipher implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

template<>
VOID 
algImpKeyPerfFunction<ImpXxx, AlgXxx, ModeXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    SYMCRYPT_XxxExpandKey( (SYMCRYPT_XXX_EXPANDED_KEY *) buf1, buf2, keySize );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx, AlgXxx, ModeXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_EncryptTest<ImpXxx, AlgXxx, ModeXxx>(
        (SYMCRYPT_XXX_EXPANDED_KEY*)buf1, buf2 + PERF_BUFFER_SIZE / 2, buf2, buf3, dataSize);
}

template<>
VOID
algImpDecryptPerfFunction<ImpXxx, AlgXxx, ModeXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_DecryptTest<ImpXxx, AlgXxx, ModeXxx>(
        (SYMCRYPT_XXX_EXPANDED_KEY*)buf1, buf2 + PERF_BUFFER_SIZE / 2, buf2, buf3, dataSize);
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgXxx, ModeXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptWipeKnownSize( buf1, sizeof( SYMCRYPT_XXX_EXPANDED_KEY ) );
}


template<>
BlockCipherImp<ImpXxx, AlgXxx, ModeXxx>::BlockCipherImp()
{
    m_perfKeyFunction     = &algImpKeyPerfFunction    <ImpXxx, AlgXxx, ModeXxx>;
    m_perfCleanFunction   = &algImpCleanPerfFunction  <ImpXxx, AlgXxx, ModeXxx>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpXxx, AlgXxx, ModeXxx>;
    m_perfDecryptFunction = &algImpDecryptPerfFunction<ImpXxx, AlgXxx, ModeXxx>;
}

//
// Empty destructor
//
template<>
BlockCipherImp<ImpXxx, AlgXxx, ModeXxx>::~BlockCipherImp<ImpXxx, AlgXxx, ModeXxx>()
{
}

template<>
SIZE_T
BlockCipherImp<ImpXxx, AlgXxx, ModeXxx>::coreBlockLen()
{
    return SYMCRYPT_XXX_BLOCK_SIZE;
}

template<>
NTSTATUS
BlockCipherImp<ImpXxx, AlgXxx, ModeXxx>::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    SYMCRYPT_ERROR e;

#if ALG_Rc2SetKeyOverride
    //
    // An ugly hack, we re-map the RC2 key expansion to use the global key size variable.
    //
    e = ScShimSymCryptRc2ExpandKeyEx( &state.key, pbKey, cbKey, g_rc2EffectiveKeyLength ? g_rc2EffectiveKeyLength : 8 * (ULONG)cbKey);
#else
    e = SYMCRYPT_XxxExpandKey( &state.key, pbKey, cbKey);
#endif

    if( e != SYMCRYPT_NO_ERROR )
    {
        return STATUS_NOT_SUPPORTED;
    }

    return STATUS_SUCCESS;
}

template<>
VOID
BlockCipherImp<ImpXxx, AlgXxx, ModeXxx>::encrypt( PBYTE pbChain, SIZE_T cbChain, PCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData )
{
    
    CHECK( cbData % msgBlockLen() == 0, "Wrong data length" );
    CHECK( cbChain == chainBlockLen(), "Wrong chain len" );

    SYMCRYPT_EncryptTest<ImpXxx, AlgXxx, ModeXxx>( &state.key, pbChain, pbSrc, pbDst, cbData );
}

template<>
VOID
BlockCipherImp<ImpXxx, AlgXxx, ModeXxx>::decrypt( PBYTE pbChain, SIZE_T cbChain, PCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData )
{
    
    CHECK( cbData % msgBlockLen() == 0, "Wrong data length" );
    CHECK( cbChain == chainBlockLen(), "Wrong chain len" );

    SYMCRYPT_DecryptTest<ImpXxx, AlgXxx, ModeXxx>( &state.key, pbChain, pbSrc, pbDst, cbData );
}

