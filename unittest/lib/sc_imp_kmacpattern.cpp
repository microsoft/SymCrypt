//
// Pattern file for the SymCrypt Kmac implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//


template<> VOID algImpKeyPerfFunction< ImpXxx, AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize );
template<> VOID algImpDataPerfFunction<ImpXxx,AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize );
template<> VOID algImpCleanPerfFunction<ImpXxx,AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3 );

//
// Empty constructor. 
//
template<>
KmacImp<ImpXxx, AlgXxx>::KmacImp()
{
    m_perfDataFunction = &algImpDataPerfFunction <ImpXxx, AlgXxx>;
    m_perfKeyFunction  = &algImpKeyPerfFunction  <ImpXxx, AlgXxx>;
    m_perfCleanFunction= &algImpCleanPerfFunction<ImpXxx, AlgXxx>;
}

//
// Empty destructor
//
template<>
KmacImp<ImpXxx, AlgXxx>::~KmacImp<ImpXxx, AlgXxx>()
{
}

template<>
SIZE_T KmacImp<ImpXxx, AlgXxx>::inputBlockLen()
{
    //
    // The macro expands to <IMPNAME>_<ALGNAME>_INPUT_BLOCK_SIZE
    //
    return SYMCRYPT_XXX_INPUT_BLOCK_SIZE;
}

//
// Compute MAC output directly
// 
template<>
VOID KmacImp<ImpXxx, AlgXxx>::mac(
    _In_reads_(cbCustomizationStr) PCBYTE pbCustomizationStr, SIZE_T cbCustomizationStr,
    _In_reads_( cbKey )      PCBYTE pbKey,   SIZE_T cbKey, 
    _In_reads_( cbData )     PCBYTE pbData,  SIZE_T cbData, 
    _Out_writes_( cbResult )  PBYTE pbResult, SIZE_T cbResult )
{
    SYMCRYPT_XxxExpandKeyEx( &state.key, pbKey, cbKey, pbCustomizationStr, cbCustomizationStr );

    SYMCRYPT_XxxInit(&state.state, &state.key);
    SYMCRYPT_XxxAppend(&state.state, pbData, cbData);
    SYMCRYPT_XxxResultEx( &state.state, pbResult, cbResult );
}

//
// Compute XOF output directly
// 
template<>
VOID KmacImp<ImpXxx, AlgXxx>::xof(
    _In_reads_(cbCustomizationStr) PCBYTE pbCustomizationStr, SIZE_T cbCustomizationStr,
    _In_reads_(cbKey)      PCBYTE pbKey, SIZE_T cbKey,
    _In_reads_(cbData)     PCBYTE pbData, SIZE_T cbData,
    _Out_writes_(cbResult)  PBYTE pbResult, SIZE_T cbResult)
{
    SYMCRYPT_XxxExpandKeyEx(&state.key, pbKey, cbKey, pbCustomizationStr, cbCustomizationStr);

    SYMCRYPT_XxxInit(&state.state, &state.key);
    SYMCRYPT_XxxAppend(&state.state, pbData, cbData);
    SYMCRYPT_XxxExtract(&state.state, pbResult, cbResult, true);
}


//
// The init/append/result functions map directly to SymCrypt calls
// We use macros to generate the correct function names
//

template<>
VOID KmacImp<ImpXxx, AlgXxx>::init( 
    _In_reads_(cbCustomizationStr) PCBYTE pbCustomizationStr, SIZE_T cbCustomizationStr,
    _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    SYMCRYPT_XxxExpandKeyEx( &state.key, pbKey, cbKey, pbCustomizationStr, cbCustomizationStr );
    SYMCRYPT_XxxInit( &state.state, &state.key );
}

template<>
VOID KmacImp<ImpXxx, AlgXxx>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    SYMCRYPT_XxxAppend( &state.state, pbData, cbData );
}

template<>
VOID KmacImp<ImpXxx, AlgXxx>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    SYMCRYPT_XxxResultEx( &state.state, pbResult, cbResult );
}

template<>
VOID KmacImp<ImpXxx, AlgXxx>::extract(_Out_writes_(cbResult) PBYTE pbResult, SIZE_T cbResult, BOOLEAN bWipe)
{
    SYMCRYPT_XxxExtract(&state.state, pbResult, cbResult, bWipe);
}

template<>
VOID 
algImpKeyPerfFunction< ImpXxx, AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    SYMCRYPT_XxxExpandKey( (SYMCRYPT_XXX_EXPANDED_KEY *) buf1, buf2, keySize );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx,AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_Xxx( (SYMCRYPT_XXX_EXPANDED_KEY *) buf1, buf2, dataSize, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptWipeKnownSize( buf1, sizeof( SYMCRYPT_XXX_EXPANDED_KEY ) );
}
