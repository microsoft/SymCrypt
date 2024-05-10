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
    SCSHIM_XXX_STATE hashState;
    BYTE exportBlob[SCSHIM_XXX_STATE_EXPORT_SIZE];

    SCSHIM_XxxInit( &hashState );
    for( int i=0; i<200; i++ )
    {
        SCSHIM_XxxAppend( &hashState, (PCBYTE) &i, sizeof( i ) );
    }
    SCSHIM_XxxStateExport( &hashState, &exportBlob[0] );

    for( int i=0; i<SCSHIM_XXX_STATE_EXPORT_SIZE; i++ )
    {
        exportBlob[i]++;
        CHECK3( SCSHIM_XxxStateImport( &hashState, &exportBlob[0] ) == SYMCRYPT_INVALID_BLOB, "SymCrypt hash state import success on corrupt blob %d", i );
        exportBlob[i]--;
    }
    CHECK( SCSHIM_XxxStateImport( &hashState, &exportBlob[0] ) == SYMCRYPT_NO_ERROR, "??" );

    CHECK( ScShimSymCryptHashStateSize( SCSHIM_XxxAlgorithm ) == sizeof( SCSHIM_XXX_STATE ), "State size mismatch" );

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
    CHECK( SCSHIM_XXX_INPUT_BLOCK_SIZE == ScShimSymCryptHashInputBlockSize(SCSHIM_XxxAlgorithm), "?" );

    return SCSHIM_XXX_INPUT_BLOCK_SIZE;
}

template<>
SIZE_T HashImp<ImpXxx,AlgXxx>::resultLen()
{
    CHECK( SCSHIM_XXX_RESULT_SIZE == ScShimSymCryptHashResultSize(SCSHIM_XxxAlgorithm), "?" );
    //
    // The macro expands to <IMPNAME>_<ALGNAME>_RESULT_SIZE
    //
    return SCSHIM_XXX_RESULT_SIZE;
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
    BYTE splitResult[SCSHIM_XXX_RESULT_SIZE];
    BYTE exportBlob[SCSHIM_XXX_STATE_EXPORT_SIZE];

    SCSHIM_XXX_STATE  state1;
    SCSHIM_XXX_STATE  state2;
    SIZE_T halfSize = cbData >> 1;

    CHECK( cbResult == SCSHIM_XXX_RESULT_SIZE, "Result len error in SymCrypt" STRING( ALG_Name ) );
    SCSHIM_Xxx( pbData, cbData, pbResult );

    ScShimSymCryptHash( SCSHIM_XxxAlgorithm, pbData, cbData, splitResult, cbResult);
    CHECK(memcmp(splitResult, pbResult, SCSHIM_XXX_RESULT_SIZE) == 0, "Generic hash error in SymCrypt" STRING(ALG_Name));

    SCSHIM_XxxInit( &state1 );
    SCSHIM_XxxAppend( &state1, pbData, halfSize );
    SCSHIM_XxxStateCopy( &state1, &state2 );
    SCSHIM_XxxAppend( &state2, pbData+halfSize, cbData-halfSize );
    SCSHIM_XxxResult( &state2, splitResult );
    CHECK( memcmp( splitResult, pbResult, SCSHIM_XXX_RESULT_SIZE ) == 0, "State copy error in SymCrypt" STRING( ALG_Name ) );

    SCSHIM_XxxInit( &state1 );
    SCSHIM_XxxAppend( &state1, pbData, halfSize );
    SCSHIM_XxxStateExport( &state1, &exportBlob[0] );

    ScShimSymCryptWipe( &state2, sizeof( state2 ) );
    CHECK( SCSHIM_XxxStateImport( &state2, &exportBlob[0] ) == SYMCRYPT_NO_ERROR , "SymCrypt hash state import error" );
    SCSHIM_XxxAppend( &state2, pbData+halfSize, cbData-halfSize );
    SCSHIM_XxxResult( &state2, splitResult );
    CHECK( memcmp( splitResult, pbResult, SCSHIM_XXX_RESULT_SIZE ) == 0, "Import/Export error in SymCrypt" STRING( ALG_Name ) );

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
        SCSHIM_XxxInit( &state.sc );
        ScShimSymCryptHashInit( SCSHIM_XxxAlgorithm, &state.scHash );
    }
    state.isReset = TRUE;
}

template<>
VOID HashImp<ImpXxx,AlgXxx>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    SCSHIM_XxxAppend( &state.sc, pbData, cbData );
    ScShimSymCryptHashAppend( SCSHIM_XxxAlgorithm, &state.scHash, pbData, cbData );
    state.isReset = FALSE;
}

template<>
VOID HashImp<ImpXxx,AlgXxx>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    BYTE    buf[SYMCRYPT_HASH_MAX_RESULT_SIZE];

    CHECK( cbResult == SCSHIM_XXX_RESULT_SIZE, "Result len error in SymCrypt " STRING( ALG_Name ) );
    SCSHIM_XxxResult( &state.sc, pbResult );
    ScShimSymCryptHashResult( SCSHIM_XxxAlgorithm, &state.scHash, buf, sizeof( buf ) );
    CHECK( memcmp( pbResult, buf, cbResult ) == 0, "Inconsistent result" );
    state.isReset = TRUE;
}

template<>
NTSTATUS HashImp<ImpXxx,AlgXxx>::exportSymCryptFormat( 
    _Out_writes_bytes_to_( cbResultBufferSize, *pcbResult ) PBYTE   pbResult, 
    _In_                                                    SIZE_T  cbResultBufferSize, 
    _Out_                                                   SIZE_T *pcbResult )
{
    CHECK( cbResultBufferSize >= SCSHIM_XXX_STATE_EXPORT_SIZE, "Export buffer too small" );

    SCSHIM_XxxStateExport( &state.sc, pbResult );
    *pcbResult = SCSHIM_XXX_STATE_EXPORT_SIZE;
    SymCryptWipeKnownSize( &state.sc, sizeof( state.sc ) );
    SCSHIM_XxxStateImport( &state.sc, pbResult );
    return STATUS_SUCCESS;
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

template<>
NTSTATUS HashImp<ImpXxx, AlgXxx>::initWithLongMessage( ULONGLONG nBytes )
{
    // Discard this test for dynamic modules as it modifies state internals
    if constexpr ( std::is_same<ImpXxx, ImpScDynamic>::value )
    {
        return STATUS_NOT_SUPPORTED;
    }

    //
    // Long message initialization for MD/SHA family of hash functions.
    // Needs to be guarded as not every hash state (e.g., SHA-3) has those members.
    //
#ifdef SYMCRYPT_HASH_MD_SHA
    memset( &state.sc.chain, 'b', sizeof( state.sc.chain ) );
    state.sc.dataLengthL = nBytes;
    state.sc.dataLengthH = 0;
    state.sc.bytesInBuffer = nBytes % sizeof( state.sc.buffer );
#else
    UNREFERENCED_PARAMETER( nBytes );
    // We don't perform the long message test for non-MD/SHA algorithms,
    // they should not have the 'Long' entry in the KAT file to trigger it.
    // This block needs to be updated when the long message test is enabled
    // for other hash functions in the future.
    SymCryptFatal('lmsg');
#endif

    SCSHIM_XxxStateCopy( &state.sc, &state.scHash.CONCAT2(ALG_name, State) );
    return STATUS_SUCCESS;
}