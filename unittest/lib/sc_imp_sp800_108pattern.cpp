//
// Pattern file for the SymCrypt Sp800_108 implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

template<>
VOID
KdfImp<ImpXxx,AlgSp800_108,BaseAlgXxx>::derive(
        _In_reads_( cbKey )     PCBYTE          pbKey,
                                SIZE_T          cbKey,
        _In_                    PKDF_ARGUMENTS  pArgs,
        _Out_writes_( cbDst )   PBYTE           pbDst, 
                                SIZE_T          cbDst )
{
    BYTE buf1[1024];
    BYTE buf2[ sizeof( buf1 ) ];
    SYMCRYPT_ERROR scError;
    SYMCRYPT_SP800_108_EXPANDED_KEY expandedKey;
    BYTE expandedKeyChecksum[SYMCRYPT_MARVIN32_RESULT_SIZE];

    PCBYTE  pbLabel;
    SIZE_T  cbLabel;
    PCBYTE  pbContext;
    SIZE_T  cbContext;

    CHECK( cbDst <= sizeof( buf1 ), "SP800_108 output too large" );

    switch( pArgs->argType )
    {
    case KdfArgumentGeneric:
        pbLabel = NULL;
        cbLabel = (SIZE_T) -1;              // special value recognized by the SymCrypt implementation.
        pbContext = pArgs->uGeneric.pbSelector;
        cbContext = pArgs->uGeneric.cbSelector;
        break;

    case KdfArgumentSp800_108:
        pbLabel = pArgs->uSp800_108.pbLabel;
        cbLabel = pArgs->uSp800_108.cbLabel;
        pbContext = pArgs->uSp800_108.pbContext;
        cbContext = pArgs->uSp800_108.cbContext;
        break;

    default: 
        CHECK( FALSE, "Unknown argument type for SP800_108" );
        return;
    }

    scError = ScShimSymCryptSp800_108(
            SYMCRYPT_BaseXxxAlgorithm,
            pbKey,  cbKey,
            pbLabel, cbLabel,
            pbContext, cbContext,
            &buf1[0], cbDst );

    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in SymCrypt SP800_108" );

    scError = ScShimSymCryptSp800_108ExpandKey(
        &expandedKey,
        SYMCRYPT_BaseXxxAlgorithm,
        pbKey, cbKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in SymCrypt SP800_108" );

    ScShimSymCryptMarvin32( ScShimSymCryptMarvin32DefaultSeed, (PCBYTE) &expandedKey, sizeof( expandedKey ), expandedKeyChecksum );

    scError = ScShimSymCryptSp800_108Derive(
        &expandedKey,
        pbLabel, cbLabel,
        pbContext, cbContext,
        &buf2[0], cbDst );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in SymCrypt SP800_108" );

    CHECK( memcmp( buf1, buf2, cbDst ) == 0, "SymCrypt SP800_108 calling versions disagree" );

    ScShimSymCryptMarvin32( ScShimSymCryptMarvin32DefaultSeed, (PCBYTE) &expandedKey, sizeof( expandedKey ), buf2 );
    CHECK( memcmp( expandedKeyChecksum, buf2, SYMCRYPT_MARVIN32_RESULT_SIZE ) == 0, "SymCrypt SP800_108 modified expanded key" );

    memcpy( pbDst, buf1, cbDst );

}

template<>
VOID
algImpDataPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ScShimSymCryptSp800_108Derive( (PCSYMCRYPT_SP800_108_EXPANDED_KEY) buf1, nullptr, 0, buf2, 32, buf3, dataSize );
}
