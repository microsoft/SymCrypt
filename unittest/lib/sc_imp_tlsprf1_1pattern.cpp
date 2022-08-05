//
// Pattern file for the SymCrypt TLS PRF 1.1 implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

//
// The following (up to // <<<<<<<) is (almost) duplicate code from the sc_imp_kdfpattern.cpp file.
// We add it here due to the uniqueness of the expand key algorithm (It does not take 
// as input a base algorithm.
// 

template<> VOID algImpKeyPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize);
template<> VOID algImpCleanPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3);
template<> VOID algImpDataPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize);

//
// Empty constructor. 
//
template<>
KdfImp<ImpXxx, AlgXxx, BaseAlgXxx>::KdfImp()
{
    m_perfDataFunction = &algImpDataPerfFunction <ImpXxx, AlgXxx, BaseAlgXxx>;
    m_perfKeyFunction = &algImpKeyPerfFunction  <ImpXxx, AlgXxx, BaseAlgXxx>;
    m_perfCleanFunction = &algImpCleanPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>;
}

template<>
KdfImp<ImpXxx, AlgXxx, BaseAlgXxx>::~KdfImp<ImpXxx, AlgXxx, BaseAlgXxx>()
{
}

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize)
{
    UNREFERENCED_PARAMETER(buf3);
    SYMCRYPT_XxxExpandKey((SYMCRYPT_XXX_EXPANDED_KEY *)buf1, buf2, keySize);
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3)
{
    UNREFERENCED_PARAMETER(buf2);
    UNREFERENCED_PARAMETER(buf3);
    SymCryptWipeKnownSize(buf1, sizeof(SYMCRYPT_XXX_EXPANDED_KEY));
}

// <<<<<<<<<<<<<<<<

template<>
VOID
KdfImp<ImpXxx, AlgTlsPrf1_1, BaseAlgXxx>::derive(
    _In_reads_(cbKey)       PCBYTE          pbKey,
                            SIZE_T          cbKey,
    _In_                    PKDF_ARGUMENTS  pArgs,
    _Out_writes_(cbDst)     PBYTE           pbDst,
                            SIZE_T          cbDst)
{
    BYTE buf1[1024];
    BYTE buf2[sizeof(buf1)];
    SYMCRYPT_ERROR scError;
    SYMCRYPT_TLSPRF1_1_EXPANDED_KEY expandedKey;
    BYTE expandedKeyChecksum[SYMCRYPT_MARVIN32_RESULT_SIZE];

    PCBYTE  pbLabel;
    SIZE_T  cbLabel;
    PCBYTE  pbSeed;
    SIZE_T  cbSeed;

    CHECK(cbDst <= sizeof(buf1), "TLS PRF 1.1 output too large");

    switch (pArgs->argType)
    {
        case KdfArgumentTlsPrf:
            pbLabel = pArgs->uTlsPrf.pbLabel;
            cbLabel = pArgs->uTlsPrf.cbLabel;
            pbSeed = pArgs->uTlsPrf.pbSeed;
            cbSeed = pArgs->uTlsPrf.cbSeed;
            break;

        default:
            CHECK(FALSE, "Unknown argument type for TLS PRF 1.1");
            return;
    }

    scError = ScShimSymCryptTlsPrf1_1(
        pbKey, cbKey,
        pbLabel, cbLabel,
        pbSeed, cbSeed,
        &buf1[0], cbDst);

    CHECK(scError == SYMCRYPT_NO_ERROR, "Error in SymCrypt TLS PRF 1.1");

    scError = ScShimSymCryptTlsPrf1_1ExpandKey(
        &expandedKey,
        pbKey, cbKey);
    CHECK(scError == SYMCRYPT_NO_ERROR, "Error in SymCrypt TLS PRF 1.1");

    ScShimSymCryptMarvin32(ScShimSymCryptMarvin32DefaultSeed, (PCBYTE)&expandedKey, sizeof(expandedKey), expandedKeyChecksum);

    scError = ScShimSymCryptTlsPrf1_1Derive(
        &expandedKey,
        pbLabel, cbLabel,
        pbSeed, cbSeed,
        &buf2[0], cbDst);
    CHECK(scError == SYMCRYPT_NO_ERROR, "Error in SymCrypt TLS PRF 1.1");

    CHECK(memcmp(buf1, buf2, cbDst) == 0, "SymCrypt TLS PRF 1.1 calling versions disagree");

    ScShimSymCryptMarvin32(ScShimSymCryptMarvin32DefaultSeed, (PCBYTE)&expandedKey, sizeof(expandedKey), buf2);
    CHECK(memcmp(expandedKeyChecksum, buf2, SYMCRYPT_MARVIN32_RESULT_SIZE) == 0, "SymCrypt TLS PRF 1.1 modified expanded key");

    memcpy(pbDst, buf1, cbDst);

}

template<>
VOID
algImpDataPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize)
{
    ScShimSymCryptTlsPrf1_1Derive((PCSYMCRYPT_TLSPRF1_1_EXPANDED_KEY)buf1, nullptr, 0, buf2, 32, buf3, dataSize);
}

