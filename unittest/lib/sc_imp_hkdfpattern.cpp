//
// Pattern file for the SymCrypt HKDF implementation.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

//
// The following (up to // <<<<<<<) is (almost) duplicate code from the sc_imp_kdfpattern.cpp file.
// We add it here due to the uniqueness of the expand key algorithm (It takes as input the salt which
// for the perf function we set it of size equal to keySize).
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
    SYMCRYPT_XxxExpandKey( (SYMCRYPT_XXX_EXPANDED_KEY *) buf1, SYMCRYPT_BaseXxxAlgorithm, buf2, keySize, buf3, keySize);
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
KdfImp<ImpXxx, AlgHkdf, BaseAlgXxx>::derive(
    _In_reads_(cbKey)       PCBYTE          pbKey,
                            SIZE_T          cbKey,
    _In_                    PKDF_ARGUMENTS  pArgs,
    _Out_writes_(cbDst)     PBYTE           pbDst,
                            SIZE_T          cbDst)
{
    BYTE buf1[1024];
    BYTE buf2[sizeof(buf1)];
    SYMCRYPT_ERROR scError;
    SYMCRYPT_ALIGN BYTE rbPrk[SYMCRYPT_MAC_MAX_RESULT_SIZE] = { 0 };
    SYMCRYPT_HKDF_EXPANDED_KEY expandedKey;
    BYTE expandedKeyChecksum[SYMCRYPT_MARVIN32_RESULT_SIZE];
    PCSYMCRYPT_MAC pcmBaseAlgorithm = SYMCRYPT_BaseXxxAlgorithm;

    PCBYTE  pbSalt;
    SIZE_T  cbSalt;
    PCBYTE  pbInfo;
    SIZE_T  cbInfo;

    CHECK(cbDst <= sizeof(buf1), "HKDF output too large");

    switch (pArgs->argType)
    {
        case KdfArgumentHkdf:
            pbSalt = pArgs->uHkdf.pbSalt;
            cbSalt = pArgs->uHkdf.cbSalt;
            pbInfo = pArgs->uHkdf.pbInfo;
            cbInfo = pArgs->uHkdf.cbInfo;
            break;

        default:
            CHECK(FALSE, "Unknown argument type for HKDF");
            return;
    }

    // 1) Full HKDF
    scError = ScShimSymCryptHkdf(
        pcmBaseAlgorithm,
        pbKey, cbKey,
        pbSalt, cbSalt,
        pbInfo, cbInfo,
        &buf1[0], cbDst);

    CHECK(scError == SYMCRYPT_NO_ERROR, "Error in SymCrypt HKDF");

    // 2) ExpandKey then Derive
    scError = ScShimSymCryptHkdfExpandKey(
        &expandedKey,
        pcmBaseAlgorithm,
        pbKey, cbKey,
        pbSalt, cbSalt );
    CHECK(scError == SYMCRYPT_NO_ERROR, "Error in SymCrypt HKDF");

    ScShimSymCryptMarvin32(ScShimSymCryptMarvin32DefaultSeed, (PCBYTE)&expandedKey, sizeof(expandedKey), expandedKeyChecksum);

    scError = ScShimSymCryptHkdfDerive(
        &expandedKey,
        pbInfo, cbInfo,
        &buf2[0], cbDst);
    CHECK(scError == SYMCRYPT_NO_ERROR, "Error in SymCrypt HKDF");

    CHECK(memcmp(buf1, buf2, cbDst) == 0, "SymCrypt HKDF calling versions disagree");

    ScShimSymCryptMarvin32(ScShimSymCryptMarvin32DefaultSeed, (PCBYTE)&expandedKey, sizeof(expandedKey), buf2);
    CHECK(memcmp(expandedKeyChecksum, buf2, SYMCRYPT_MARVIN32_RESULT_SIZE) == 0, "SymCrypt HKDF modified expanded key");

    // 3) ExtractPrk then PrkExpandKey then Derive
    scError = ScShimSymCryptHkdfExtractPrk(
        pcmBaseAlgorithm,
        pbKey, cbKey,
        pbSalt, cbSalt,
        rbPrk, SYMCRYPT_XXX_BASE_RESULT_SIZE );
    CHECK(scError == SYMCRYPT_NO_ERROR, "Error in SymCrypt HKDF");

    scError = ScShimSymCryptHkdfPrkExpandKey(
        &expandedKey,
        pcmBaseAlgorithm,
        rbPrk, SYMCRYPT_XXX_BASE_RESULT_SIZE );
    CHECK(scError == SYMCRYPT_NO_ERROR, "Error in SymCrypt HKDF");

    ScShimSymCryptMarvin32(ScShimSymCryptMarvin32DefaultSeed, (PCBYTE)&expandedKey, sizeof(expandedKey), expandedKeyChecksum);

    scError = ScShimSymCryptHkdfDerive(
        &expandedKey,
        pbInfo, cbInfo,
        &buf2[0], cbDst);
    CHECK(scError == SYMCRYPT_NO_ERROR, "Error in SymCrypt HKDF");

    CHECK(memcmp(buf1, buf2, cbDst) == 0, "SymCrypt HKDF calling versions disagree");

    ScShimSymCryptMarvin32(ScShimSymCryptMarvin32DefaultSeed, (PCBYTE)&expandedKey, sizeof(expandedKey), buf2);
    CHECK(memcmp(expandedKeyChecksum, buf2, SYMCRYPT_MARVIN32_RESULT_SIZE) == 0, "SymCrypt HKDF modified expanded key");

    memcpy(pbDst, buf1, cbDst);

}

template<>
VOID
algImpDataPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize)
{
    // The size of the Info parameter is set constant to 32 bytes.
    ScShimSymCryptHkdfDerive((PCSYMCRYPT_HKDF_EXPANDED_KEY)buf1, buf2, 32, buf3, dataSize);
}

