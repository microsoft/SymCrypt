//
// Pattern file for the Symcrypt SRTP-KDF implementations.
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
    UNREFERENCED_PARAMETER(buf3);
    SYMCRYPT_XxxExpandKey((SYMCRYPT_XXX_EXPANDED_KEY*)buf1, buf2, keySize);
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
KdfImp<ImpXxx, AlgSrtpKdf, BaseAlgXxx>::derive(
    _In_reads_(cbKey)       PCBYTE          pbKey,
                            SIZE_T          cbKey,
    _In_                    PKDF_ARGUMENTS  pArgs,
    _Out_writes_(cbDst)     PBYTE           pbDst,
                            SIZE_T          cbDst)
{
    SYMCRYPT_ERROR scError;
    SYMCRYPT_SRTPKDF_EXPANDED_KEY expandedKey;
    BYTE buffer1[1024];
    BYTE buffer2[sizeof(buffer1)];
    BYTE expandedKeyChecksum1[SYMCRYPT_MARVIN32_RESULT_SIZE];
    BYTE expandedKeyChecksum2[SYMCRYPT_MARVIN32_RESULT_SIZE];

    CHECK(cbDst <= sizeof(buffer1), "SRTP-KDF output too large");


    switch (pArgs->argType)
    {
        case KdfArgumentSrtpKdf:
            break;

        default:
            CHECK(FALSE, "Unknown argument type for SRTP-KDF");
            return;
    }

    scError = ScShimSymCryptSrtpKdfExpandKey(&expandedKey, pbKey, cbKey);
    CHECK(scError == SYMCRYPT_NO_ERROR, "Error in SymCryptSrtpKdfExpandKey");

    ScShimSymCryptMarvin32(ScShimSymCryptMarvin32DefaultSeed, (PCBYTE)&expandedKey, sizeof(expandedKey), expandedKeyChecksum1);

    // Note: Test vectors use 32-bit SRTCP index values
    scError = ScShimSymCryptSrtpKdfDerive(&expandedKey,
                                            pArgs->uSrtpKdf.pbSalt, pArgs->uSrtpKdf.cbSalt, 
                                            pArgs->uSrtpKdf.uKeyDerivationRate, 
                                            pArgs->uSrtpKdf.uIndex, pArgs->uSrtpKdf.label < 3 ? 48 : 32,
                                            pArgs->uSrtpKdf.label, 
                                            buffer1, cbDst);
    CHECK(scError == SYMCRYPT_NO_ERROR, "Error in SymCryptSrtpKdfDerive");

    ScShimSymCryptMarvin32(ScShimSymCryptMarvin32DefaultSeed, (PCBYTE)&expandedKey, sizeof(expandedKey), expandedKeyChecksum2);
    CHECK(memcmp(expandedKeyChecksum1, expandedKeyChecksum2, SYMCRYPT_MARVIN32_RESULT_SIZE) == 0, "SymCryptSrtpKdfDerive modified expanded key");

    scError = ScShimSymCryptSrtpKdf(pbKey, cbKey,
                                    pArgs->uSrtpKdf.pbSalt, pArgs->uSrtpKdf.cbSalt,
                                    pArgs->uSrtpKdf.uKeyDerivationRate,
                                    pArgs->uSrtpKdf.uIndex, pArgs->uSrtpKdf.label < 3 ? 48 : 32,
                                    pArgs->uSrtpKdf.label,
                                    buffer2, cbDst);
    CHECK(scError == SYMCRYPT_NO_ERROR, "Error in SymCryptSrtpKdf");

    CHECK(memcmp(buffer1, buffer2, cbDst) == 0, "SymCrypt SRTP-KDF calling versions disagree");

    memcpy(pbDst, buffer1, cbDst);
}

template<>
VOID
algImpDataPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize)
{
    ScShimSymCryptSrtpKdfDerive((PCSYMCRYPT_SRTPKDF_EXPANDED_KEY)buf1,
                            buf2,       // pbSalt
                            112 / 8,    // cbSalt
                            0,          // uKeyDerivationRate
                            0,          // uIndex
                            48,         // uIndexWidth
                            (BYTE)0,    // label
                            buf3, dataSize);
}

