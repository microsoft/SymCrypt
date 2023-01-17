//
// Pattern file for the SymCrypt hash implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

template<> VOID algImpKeyPerfFunction<ImpXxx,AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize );
template<> VOID algImpDataPerfFunction<ImpXxx,AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize );
template<> VOID algImpCleanPerfFunction<ImpXxx,AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3 );

//
// Empty constructor. 
//
template<> 
HashImp< ImpXxx, AlgXxx >::HashImp()
{

    m_perfDataFunction = &algImpDataPerfFunction <ImpXxx, AlgXxx>;
    m_perfKeyFunction  = &algImpKeyPerfFunction  <ImpXxx, AlgXxx>;
    m_perfCleanFunction= &algImpCleanPerfFunction<ImpXxx, AlgXxx>;

    //
    // Check SymCrypt state import errors
    //
    SYMCRYPT_XXX_STATE hashState;
    BYTE exportBlob[SYMCRYPT_XXX_STATE_EXPORT_SIZE];

    SYMCRYPT_XxxInit( &hashState );
    for( int i=0; i<200; i++ )
    {
        SYMCRYPT_XxxAppend( &hashState, (PCBYTE) &i, sizeof( i ) );
    }
    SYMCRYPT_XxxStateExport( &hashState, &exportBlob[0] );

    for( int i=0; i<SYMCRYPT_XXX_STATE_EXPORT_SIZE; i++ )
    {
        exportBlob[i]++;
        CHECK3( SYMCRYPT_XxxStateImport( &hashState, &exportBlob[0] ) == SYMCRYPT_INVALID_BLOB, "SymCrypt hash state import success on corrupt blob %d", i );
        exportBlob[i]--;
    }
    CHECK( SYMCRYPT_XxxStateImport( &hashState, &exportBlob[0] ) == SYMCRYPT_NO_ERROR, "??" );

    CHECK( ScShimSymCryptHashStateSize( SYMCRYPT_XxxAlgorithm ) == sizeof( SYMCRYPT_XXX_STATE ), "State size mismatch" );

    state.isReset = FALSE;
}

//
// Empty destructor
//
template<>
HashImp<ImpXxx,AlgXxx>::~HashImp<ImpXxx, AlgXxx>()
{
}

template<>
SIZE_T HashImp<ImpXxx,AlgXxx>::inputBlockLen()
{
    CHECK( SYMCRYPT_XXX_INPUT_BLOCK_SIZE == ScShimSymCryptHashInputBlockSize(SYMCRYPT_XxxAlgorithm), "?" );

    return SYMCRYPT_XXX_INPUT_BLOCK_SIZE;
}

template<>
SIZE_T HashImp<ImpXxx,AlgXxx>::resultLen()
{
    CHECK( SYMCRYPT_XXX_RESULT_SIZE == ScShimSymCryptHashResultSize(SYMCRYPT_XxxAlgorithm), "?" );
    //
    // The macro expands to <IMPNAME>_<ALGNAME>_RESULT_SIZE
    //
    return SYMCRYPT_XXX_RESULT_SIZE;
}

//
// Compute a hash directly
// 
template<>
VOID HashImp<ImpXxx,AlgXxx>::hash( 
        _In_reads_( cbData )       PCBYTE pbData, 
                                    SIZE_T cbData, 
        _Out_writes_( cbResult )    PBYTE pbResult, 
                                    SIZE_T cbResult )
{
    BYTE splitResult[SYMCRYPT_XXX_RESULT_SIZE];
    BYTE exportBlob[SYMCRYPT_XXX_STATE_EXPORT_SIZE];

    SYMCRYPT_XXX_STATE  state1;
    SYMCRYPT_XXX_STATE  state2;
    SIZE_T halfSize = cbData >> 1;

    CHECK( cbResult == SYMCRYPT_XXX_RESULT_SIZE, "Result len error in SymCrypt" STRING( ALG_Name ) );
    SYMCRYPT_Xxx( pbData, cbData, pbResult );

    ScShimSymCryptHash( SYMCRYPT_XxxAlgorithm, pbData, cbData, splitResult, cbResult);
    CHECK(memcmp(splitResult, pbResult, SYMCRYPT_XXX_RESULT_SIZE) == 0, "Generic hash error in SymCrypt" STRING(ALG_Name));

    SYMCRYPT_XxxInit( &state1 );
    SYMCRYPT_XxxAppend( &state1, pbData, halfSize );
    SYMCRYPT_XxxStateCopy( &state1, &state2 );
    SYMCRYPT_XxxAppend( &state2, pbData+halfSize, cbData-halfSize );
    SYMCRYPT_XxxResult( &state2, splitResult );
    CHECK( memcmp( splitResult, pbResult, SYMCRYPT_XXX_RESULT_SIZE ) == 0, "State copy error in SymCrypt" STRING( ALG_Name ) );

    SYMCRYPT_XxxInit( &state1 );
    SYMCRYPT_XxxAppend( &state1, pbData, halfSize );
    SYMCRYPT_XxxStateExport( &state1, &exportBlob[0] );

    ScShimSymCryptWipe( &state2, sizeof( state2 ) );
    CHECK( SYMCRYPT_XxxStateImport( &state2, &exportBlob[0] ) == SYMCRYPT_NO_ERROR , "SymCrypt hash state import error" );
    SYMCRYPT_XxxAppend( &state2, pbData+halfSize, cbData-halfSize );
    SYMCRYPT_XxxResult( &state2, splitResult );
    CHECK( memcmp( splitResult, pbResult, SYMCRYPT_XXX_RESULT_SIZE ) == 0, "Import/Export error in SymCrypt" STRING( ALG_Name ) );

}


//
// The init/append/result functions map directly to SymCrypt calls
// We use macros to generate the correct function names
//

template<>
VOID HashImp<ImpXxx,AlgXxx>::init()
{
    if( !state.isReset || (g_rng.byte() & 1) == 0 )
    {
        SYMCRYPT_XxxInit( &state.sc );
        ScShimSymCryptHashInit( SYMCRYPT_XxxAlgorithm, &state.scHash );
    }
    state.isReset = TRUE;
}

template<>
VOID HashImp<ImpXxx,AlgXxx>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    SYMCRYPT_XxxAppend( &state.sc, pbData, cbData );
    ScShimSymCryptHashAppend( SYMCRYPT_XxxAlgorithm, &state.scHash, pbData, cbData );
    state.isReset = FALSE;
}

template<>
VOID HashImp<ImpXxx,AlgXxx>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    BYTE    buf[SYMCRYPT_HASH_MAX_RESULT_SIZE];

    CHECK( cbResult == SYMCRYPT_XXX_RESULT_SIZE, "Result len error in SymCrypt " STRING( ALG_Name ) );
    SYMCRYPT_XxxResult( &state.sc, pbResult );
    ScShimSymCryptHashResult( SYMCRYPT_XxxAlgorithm, &state.scHash, buf, sizeof( buf ) );
    CHECK( memcmp( pbResult, buf, cbResult ) == 0, "Inconsistent result" );
    state.isReset = TRUE;
}

template<>
NTSTATUS HashImp<ImpXxx,AlgXxx>::exportSymCryptFormat( 
    _Out_writes_bytes_to_( cbResultBufferSize, *pcbResult ) PBYTE   pbResult, 
    _In_                                                    SIZE_T  cbResultBufferSize, 
    _Out_                                                   SIZE_T *pcbResult )
{
    CHECK( cbResultBufferSize >= SYMCRYPT_XXX_STATE_EXPORT_SIZE, "Export buffer too small" );

    SYMCRYPT_XxxStateExport( &state.sc, pbResult );
    *pcbResult = SYMCRYPT_XXX_STATE_EXPORT_SIZE;
    SymCryptWipeKnownSize( &state.sc, sizeof( state.sc ) );
    SYMCRYPT_XxxStateImport( &state.sc, pbResult );
    return STATUS_SUCCESS;
}

template<>
VOID 
algImpKeyPerfFunction< ImpXxx, AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( keySize );

    SYMCRYPT_XxxInit( (SYMCRYPT_XXX_STATE *) buf1 );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx,AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_XxxAppend( (SYMCRYPT_XXX_STATE *) buf1, buf2, dataSize );
    SYMCRYPT_XxxResult( (SYMCRYPT_XXX_STATE *) buf1, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptWipeKnownSize( buf1, sizeof( SYMCRYPT_XXX_STATE ) );
}

template<>
NTSTATUS HashImp<ImpXxx, AlgXxx>::initWithLongMessage( ULONGLONG nBytes )
{

//
// This test is not meaningful for SHA-3 hash functions as their state does not
// store the length of the message. Still, this function performs in a similar 
// fashion in order for the test to execute.
//
// SHA-3 state is different from the state of other hash functions, we need to 
// separate its implementation at compile time.
#if defined(HashImpSha3_256) || defined(HashImpSha3_384) || defined(HashImpSha3_512)
        memset( &state.sc.state, 'b', sizeof( state.sc.state ) );
        state.sc.stateIndex = nBytes % state.sc.inputBlockSize;
#else
        memset( &state.sc.chain, 'b', sizeof( state.sc.chain ) );
        state.sc.dataLengthL = nBytes;
        state.sc.dataLengthH = 0;
        state.sc.bytesInBuffer = nBytes & 0x3f;
#endif

    SYMCRYPT_XxxStateCopy( &state.sc, &state.scHash.CONCAT2(ALG_name, State) );
    return STATUS_SUCCESS;
}