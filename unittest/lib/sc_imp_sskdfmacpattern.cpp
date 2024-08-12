//
// Pattern file for the Symcrypt SSKDF mac implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

//
// The following (up to // <<<<<<<) is (almost) duplicate code from the sc_imp_kdfpattern.cpp file.
// We add it here due to the uniqueness of the expand salt algorithm, which is used instead of the
// expand key algorithm.
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
    m_perfDataFunction  = &algImpDataPerfFunction <ImpXxx, AlgXxx, BaseAlgXxx>;
    m_perfKeyFunction   = &algImpKeyPerfFunction  <ImpXxx, AlgXxx, BaseAlgXxx>;
    m_perfCleanFunction = &algImpCleanPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>;
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
    ScShimSymCryptSskdfMacExpandSalt( (PSYMCRYPT_SSKDF_MAC_EXPANDED_SALT)buf1, SCSHIM_BaseXxxAlgorithm, buf2, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    SymCryptWipeKnownSize( buf1, sizeof(SYMCRYPT_SSKDF_MAC_EXPANDED_SALT) );
}

// <<<<<<<<<<<<<<<<

template<>
void
KdfImp<ImpXxx, AlgSskdfMac, BaseAlgXxx>::derive(
    _In_reads_(cbKey)   PCBYTE          pbKey,
                        SIZE_T          cbKey,
    _In_                PKDF_ARGUMENTS  pArgs,
    _Out_writes_(cbDst) PBYTE           pbDst,
                        SIZE_T          cbDst)
{
    SYMCRYPT_ERROR scError;
    SYMCRYPT_SSKDF_MAC_EXPANDED_SALT expandedSalt;
    BYTE buf1[1024];
    BYTE buf2[sizeof( buf1 )];
    BYTE expandedSaltChecksum1[SYMCRYPT_MARVIN32_RESULT_SIZE];
    BYTE expandedSaltChecksum2[SYMCRYPT_MARVIN32_RESULT_SIZE];
    PCSYMCRYPT_MAC pcmBaseAlgorithm = SCSHIM_BaseXxxAlgorithm;

    PCBYTE  pbSalt;
    SIZE_T  cbSalt;
    PCBYTE  pbInfo;
    SIZE_T  cbInfo;

    CHECK( cbDst <= sizeof(buf1), "SSKDF output too large" );

    switch ( pArgs->argType )
    {
        case KdfArgumentSskdf:
            pbSalt = pArgs->uSskdf.pbSalt;
            cbSalt = pArgs->uSskdf.cbSalt;
            pbInfo = pArgs->uSskdf.pbInfo;
            cbInfo = pArgs->uSskdf.cbInfo;
            break;

        default:
            CHECK( FALSE, "Unknown argument type for SSKDF" );
            return;
    }

    scError = ScShimSymCryptSskdfMac(
        pcmBaseAlgorithm,
        0,
        pbKey, cbKey,
        pbSalt, cbSalt,
        pbInfo, cbInfo,
        &buf1[0], cbDst );

    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in SymCryptSskdfMac" );

    scError = ScShimSymCryptSskdfMacExpandSalt(
        &expandedSalt,
        pcmBaseAlgorithm,
        pbSalt, cbSalt );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in SymCryptSskdfMacExpandSalt" );

    ScShimSymCryptMarvin32( ScShimSymCryptMarvin32DefaultSeed, (PCBYTE)&expandedSalt, sizeof( expandedSalt ), expandedSaltChecksum1 );

    scError = ScShimSymCryptSskdfMacDerive(
        &expandedSalt,
        0,
        pbKey, cbKey,
        pbInfo, cbInfo,
        &buf2[0], cbDst );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in SymCryptSskdfMacDerive" );

    ScShimSymCryptMarvin32( ScShimSymCryptMarvin32DefaultSeed, (PCBYTE)&expandedSalt, sizeof( expandedSalt ), expandedSaltChecksum2 );

    CHECK( memcmp( expandedSaltChecksum1, expandedSaltChecksum2, SYMCRYPT_MARVIN32_RESULT_SIZE ) == 0, "SymCryptSskdfDerive modified expanded salt" );

    CHECK( memcmp( buf1, buf2, cbDst ) == 0, "SymCrypt SSKDF calling versions disagree" );

    memcpy( pbDst, buf1, cbDst );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ScShimSymCryptSskdfMacDerive(
        (PSYMCRYPT_SSKDF_MAC_EXPANDED_SALT)buf1,
        0,
        buf2, 32,
        buf2, 32,
        buf3, dataSize);
}