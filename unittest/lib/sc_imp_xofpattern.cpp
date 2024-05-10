//
// Pattern file for the SymCrypt XOF implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#define SYMCRYPT_XOF_MAX_RESULT_SIZE    1024

template<> VOID algImpKeyPerfFunction<ImpXxx,AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize );
template<> VOID algImpDataPerfFunction<ImpXxx,AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize );
template<> VOID algImpCleanPerfFunction<ImpXxx,AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3 );

//
// Empty constructor. 
//
template<> 
XofImp< ImpXxx, AlgXxx >::XofImp()
{

    m_perfDataFunction = &algImpDataPerfFunction <ImpXxx, AlgXxx>;
    m_perfKeyFunction  = &algImpKeyPerfFunction  <ImpXxx, AlgXxx>;
    m_perfCleanFunction= &algImpCleanPerfFunction<ImpXxx, AlgXxx>;

    state.isReset = FALSE;
}

//
// Empty destructor
//
template<>
XofImp<ImpXxx,AlgXxx>::~XofImp<ImpXxx, AlgXxx>()
{
}

template<>
SIZE_T XofImp<ImpXxx,AlgXxx>::inputBlockLen()
{
    return SCSHIM_XXX_INPUT_BLOCK_SIZE;
}

//
// Compute a Xof directly
// 
template<>
VOID XofImp<ImpXxx,AlgXxx>::xof( 
        _In_reads_( cbData )        PCBYTE  pbData, 
                                    SIZE_T  cbData, 
        _Out_writes_( cbResult )    PBYTE   pbResult, 
                                    SIZE_T  cbResult )
{
    BYTE splitResult[SYMCRYPT_XOF_MAX_RESULT_SIZE];

    SCSHIM_XXX_STATE  state1;
    SCSHIM_XXX_STATE  state2;
    SIZE_T halfSize = cbData >> 1;

    CHECK(cbResult <= SYMCRYPT_XOF_MAX_RESULT_SIZE, "Result len too large in SymCrypt " STRING(ALG_Name));

    SCSHIM_Xxx( pbData, cbData, pbResult, cbResult );

    SCSHIM_XxxInit( &state1 );
    SCSHIM_XxxAppend( &state1, pbData, halfSize );
    SCSHIM_XxxStateCopy( &state1, &state2 );
    SCSHIM_XxxAppend( &state2, pbData+halfSize, cbData-halfSize );
    SCSHIM_XxxExtract( &state2, splitResult, cbResult, true );
    CHECK( memcmp( splitResult, pbResult, cbResult ) == 0, "State copy error in SymCrypt" STRING( ALG_Name ) );
}


//
// The init/append/result functions map directly to SymCrypt calls
// We use macros to generate the correct function names
//

template<>
VOID XofImp<ImpXxx,AlgXxx>::init()
{
    if( !state.isReset || (g_rng.byte() & 1) == 0 )
    {
        SCSHIM_XxxInit( &state.sc );
    }
    state.isReset = TRUE;
}

template<>
VOID XofImp<ImpXxx,AlgXxx>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    SCSHIM_XxxAppend( &state.sc, pbData, cbData );
    state.isReset = FALSE;
}

template<>
VOID XofImp<ImpXxx,AlgXxx>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    CHECK( cbResult <= SYMCRYPT_XOF_MAX_RESULT_SIZE, "Result len too large in SymCrypt " STRING( ALG_Name ) );
    SCSHIM_XxxExtract( &state.sc, pbResult, cbResult, true );
    state.isReset = TRUE;
}

template<>
VOID XofImp<ImpXxx, AlgXxx>::extract(_Out_writes_(cbResult) PBYTE pbResult, SIZE_T cbResult, BOOLEAN bWipe)
{
    CHECK( cbResult <= SYMCRYPT_XOF_MAX_RESULT_SIZE, "Result len too large in SymCrypt " STRING( ALG_Name ) );
    SCSHIM_XxxExtract( &state.sc, pbResult, cbResult, bWipe );
    state.isReset = bWipe;
}

template<>
VOID 
algImpKeyPerfFunction< ImpXxx, AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( keySize );

    SCSHIM_XxxInit( (SCSHIM_XXX_STATE *) buf1 );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx,AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SCSHIM_XxxAppend( (SCSHIM_XXX_STATE *) buf1, buf2, dataSize );
    SCSHIM_XxxResult( (SCSHIM_XXX_STATE *) buf1, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptWipeKnownSize( buf1, sizeof( SCSHIM_XXX_STATE ) );
}
