//
// Pattern file for the SymCrypt PBKDF2 implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

template<>
VOID
KdfImp<ImpXxx,AlgPbkdf2,BaseAlgXxx>::derive(
        _In_reads_( cbKey )     PCBYTE          pbKey,
                                SIZE_T          cbKey,
        _In_                    PKDF_ARGUMENTS  pArgs,
        _Out_writes_( cbDst )   PBYTE           pbDst, 
                                SIZE_T          cbDst )
{
    PCBYTE pbSalt;
    SIZE_T cbSalt;
    ULONGLONG iterationCnt;
    BYTE buf1[1024];
    BYTE buf2[ sizeof( buf1 ) ];
    SYMCRYPT_ERROR scError;
    SYMCRYPT_PBKDF2_EXPANDED_KEY expandedKey;
    BYTE expandedKeyChecksum[SYMCRYPT_MARVIN32_RESULT_SIZE];

    switch( pArgs->argType )
    {
    case KdfArgumentGeneric:
        pbSalt = pArgs->uGeneric.pbSelector;
        cbSalt = pArgs->uGeneric.cbSelector;
        iterationCnt = 1;
        break;

    case KdfArgumentPbkdf2:
        pbSalt = pArgs->uPbkdf2.pbSalt;
        cbSalt = pArgs->uPbkdf2.cbSalt;
        iterationCnt = pArgs->uPbkdf2.iterationCnt;
        break;

    default: 
        CHECK( FALSE, "Unknown argument type for PBKDF2" );
        return;
    }

    CHECK( cbDst <= sizeof( buf1 ), "PBKDF2 output too large" );

    scError = ScShimSymCryptPbkdf2(
        SYMCRYPT_BaseXxxAlgorithm,
        pbKey,  cbKey,
        pbSalt,  cbSalt,
        iterationCnt,
        &buf1[0], cbDst );

    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in SymCrypt PBKDF2" );

    scError = ScShimSymCryptPbkdf2ExpandKey(
        &expandedKey,
        SYMCRYPT_BaseXxxAlgorithm,
        pbKey, cbKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in SymCrypt PBKDF2" );

    ScShimSymCryptMarvin32( ScShimSymCryptMarvin32DefaultSeed, (PCBYTE) &expandedKey, sizeof( expandedKey ), expandedKeyChecksum );

    scError = ScShimSymCryptPbkdf2Derive(
        &expandedKey,
        pbSalt, cbSalt,
        iterationCnt,
        &buf2[0], cbDst );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in SymCrypt PBKDF2" );

    CHECK( memcmp( buf1, buf2, cbDst ) == 0, "SymCrypt PBKDF2 calling versions disagree" );

    ScShimSymCryptMarvin32( ScShimSymCryptMarvin32DefaultSeed, (PCBYTE) &expandedKey, sizeof( expandedKey ), buf2 );
    CHECK( memcmp( expandedKeyChecksum, buf2, SYMCRYPT_MARVIN32_RESULT_SIZE ) == 0, "SymCrypt PBKDF2 modified expanded key" );

    memcpy( pbDst, buf1, cbDst );

}

template<>
VOID
algImpDataPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ScShimSymCryptPbkdf2Derive( (PCSYMCRYPT_PBKDF2_EXPANDED_KEY) buf1, buf2, 32, 1, buf3, dataSize );
}
