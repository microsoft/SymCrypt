//
// Pattern file for the SymCrypt KDF implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

template<> VOID algImpKeyPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize );
template<> VOID algImpCleanPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3 );
template<> VOID algImpDataPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize );

//
// Empty constructor. 
//
template<>
KdfImp<ImpXxx, AlgXxx, BaseAlgXxx>::KdfImp()
{
    m_perfDataFunction = &algImpDataPerfFunction <ImpXxx, AlgXxx, BaseAlgXxx>;
    m_perfKeyFunction  = &algImpKeyPerfFunction  <ImpXxx, AlgXxx, BaseAlgXxx>;
    m_perfCleanFunction= &algImpCleanPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>;
}

template<>
KdfImp<ImpXxx, AlgXxx, BaseAlgXxx>::~KdfImp<ImpXxx, AlgXxx, BaseAlgXxx>()
{
}

template<>
VOID 
algImpKeyPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );
    SYMCRYPT_XxxExpandKey( (SYMCRYPT_XXX_EXPANDED_KEY *) buf1, SYMCRYPT_BaseXxxAlgorithm, buf2, keySize );
}

template<>
VOID 
algImpCleanPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    SymCryptWipeKnownSize( buf1, sizeof( SYMCRYPT_XXX_EXPANDED_KEY ) );
}


