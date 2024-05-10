//
// Pattern file for the SymCrypt mac implementations.
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
MacImp<ImpXxx, AlgXxx>::MacImp()
{
    m_perfDataFunction = &algImpDataPerfFunction <ImpXxx, AlgXxx>;
    m_perfKeyFunction  = &algImpKeyPerfFunction  <ImpXxx, AlgXxx>;
    m_perfCleanFunction= &algImpCleanPerfFunction<ImpXxx, AlgXxx>;
}

//
// Empty destructor
//
template<>
MacImp<ImpXxx, AlgXxx>::~MacImp<ImpXxx, AlgXxx>()
{
}

template<>
SIZE_T MacImp<ImpXxx, AlgXxx>::inputBlockLen()
{
    //
    // The macro expands to <IMPNAME>_<ALGNAME>_INPUT_BLOCK_SIZE
    //
    return SCSHIM_XXX_INPUT_BLOCK_SIZE;
}

template<>
SIZE_T MacImp<ImpXxx, AlgXxx>::resultLen()
{
    //
    // The macro expands to <IMPNAME>_<ALGNAME>_RESULT_SIZE
    //
    return SCSHIM_XXX_RESULT_SIZE;
}

//
// Compute a mac directly
// 
template<>
NTSTATUS MacImp<ImpXxx, AlgXxx>::mac( 
    _In_reads_( cbKey )      PCBYTE pbKey,   SIZE_T cbKey, 
    _In_reads_( cbData )     PCBYTE pbData,  SIZE_T cbData, 
    _Out_writes_( cbResult )  PBYTE pbResult, SIZE_T cbResult )
{
    BYTE splitResult[SCSHIM_XXX_RESULT_SIZE];
    SCSHIM_XXX_EXPANDED_KEY key1;
    SCSHIM_XXX_EXPANDED_KEY key2;
    SCSHIM_XXX_STATE  state1;
    SCSHIM_XXX_STATE  state2;
    SIZE_T halfSize = cbData >> 1;

    CHECK( cbResult == SCSHIM_XXX_RESULT_SIZE, "Result len error in SymCrypt" STRING( MAC_Name ) );

    SCSHIM_XxxExpandKey( &state.key, pbKey, cbKey );

    SCSHIM_Xxx( &state.key, pbData, cbData, pbResult );

    //
    // Test the key & state duplication functions
    //
    SCSHIM_XxxExpandKey( &key1, pbKey, cbKey );
    SCSHIM_XxxKeyCopy( &key1, &key2 );
    SymCryptWipeKnownSize( &key1, sizeof( key1 ) );

    SCSHIM_XxxInit( &state1, &key2 );
    SCSHIM_XxxAppend( &state1, pbData, halfSize );
    SCSHIM_XxxStateCopy( &state1, nullptr, &state2 );
    SCSHIM_XxxAppend( &state2, pbData+halfSize, cbData-halfSize );
    SCSHIM_XxxResult( &state2, splitResult );
    CHECK( memcmp( splitResult, pbResult, SCSHIM_XXX_RESULT_SIZE ) == 0, "State copy error in SymCrypt" STRING( ALG_Name ) );

    SCSHIM_XxxStateCopy( &state1, &state.key, &state2 );
    SCSHIM_XxxAppend( &state2, pbData+halfSize, cbData-halfSize );
    SCSHIM_XxxResult( &state2, splitResult );
    CHECK( memcmp( splitResult, pbResult, SCSHIM_XXX_RESULT_SIZE ) == 0, "State copy error in SymCrypt" STRING( ALG_Name ) );

    SymCryptWipeKnownSize( &state.key, sizeof( state.key ) );
    SymCryptWipeKnownSize( &state1, sizeof( state1 ) );
    SymCryptWipeKnownSize( &state2, sizeof( state2 ) );
    
    return STATUS_SUCCESS;
}


//
// The init/append/result functions map directly to SymCrypt calls
// We use macros to generate the correct function names
//

template<>
NTSTATUS MacImp<ImpXxx, AlgXxx>::init( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    SCSHIM_XxxExpandKey( &state.key, pbKey, cbKey );
    SCSHIM_XxxInit( &state.state, &state.key );

    return STATUS_SUCCESS;
}

template<>
VOID MacImp<ImpXxx, AlgXxx>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    SCSHIM_XxxAppend( &state.state, pbData, cbData );
}

template<>
VOID MacImp<ImpXxx, AlgXxx>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    CHECK( cbResult == SCSHIM_XXX_RESULT_SIZE, "Result len error in SymCrypt " STRING( MAC_Name ) );

    SCSHIM_XxxResult( &state.state, pbResult );
}

template<>
VOID 
algImpKeyPerfFunction< ImpXxx, AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    SCSHIM_XxxExpandKey( (SCSHIM_XXX_EXPANDED_KEY *) buf1, buf2, keySize );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx,AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SCSHIM_Xxx( (SCSHIM_XXX_EXPANDED_KEY *) buf1, buf2, dataSize, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptWipeKnownSize( buf1, sizeof( SCSHIM_XXX_EXPANDED_KEY ) );
}
