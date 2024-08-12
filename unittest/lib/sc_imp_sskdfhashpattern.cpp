//
// Pattern file for the Symcrypt SSKDF hash implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

//
// The following (up to // <<<<<<<) is (almost) duplicate code from the sc_imp_kdfpattern.cpp file.
// We add it here due to the lack of an expand key algorithm for SSKDF hash.
//

template<> VOID algImpDataPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize );

//
// Empty constructor.
//
template<>
KdfImp<ImpXxx, AlgXxx, BaseAlgXxx>::KdfImp()
{
    m_perfDataFunction  = &algImpDataPerfFunction <ImpXxx, AlgXxx, BaseAlgXxx>;
    m_perfKeyFunction   = NULL;
    m_perfCleanFunction = NULL;
}

template<>
KdfImp<ImpXxx, AlgXxx, BaseAlgXxx>::~KdfImp<ImpXxx, AlgXxx, BaseAlgXxx>()
{
}

// <<<<<<<<<<<<<<<<

template<>
void
KdfImp<ImpXxx, AlgSskdfHash, BaseAlgXxx>::derive(
    _In_reads_(cbKey)   PCBYTE          pbKey,
                        SIZE_T          cbKey,
    _In_                PKDF_ARGUMENTS  pArgs,
    _Out_writes_(cbDst) PBYTE           pbDst,
                        SIZE_T          cbDst)
{
    SYMCRYPT_ERROR scError;

    PCSYMCRYPT_HASH pHashAlgorithm = SCSHIM_BaseXxxAlgorithm;
    PCBYTE  pbInfo;
    SIZE_T  cbInfo;

    switch ( pArgs->argType )
    {
        case KdfArgumentSskdf:
            pbInfo = pArgs->uSskdf.pbInfo;
            cbInfo = pArgs->uSskdf.cbInfo;
            break;

        default:
            CHECK( FALSE, "Unknown argument type for SSKDF" );
            return;
    }

    scError = ScShimSymCryptSskdfHash(
        pHashAlgorithm,
        0,
        pbKey, cbKey,
        pbInfo, cbInfo,
        pbDst, cbDst );

    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in SymCryptSskdfMac" );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf1 );

    ScShimSymCryptSskdfHash(
        SCSHIM_BaseXxxAlgorithm,
        0,
        buf2, 32,
        buf2, 32,
        buf3, dataSize );
}