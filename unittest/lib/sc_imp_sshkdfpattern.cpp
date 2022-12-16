//
// Pattern file for the Symcrypt SSH-KDF implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//


template<>
VOID
KdfImp<ImpXxx, AlgSshKdf, BaseAlgXxx>::derive(
    _In_reads_(cbKey)       PCBYTE          pbKey,
                            SIZE_T          cbKey,
    _In_                    PKDF_ARGUMENTS  pArgs,
    _Out_writes_(cbDst)     PBYTE           pbDst,
                            SIZE_T          cbDst)
{
    SYMCRYPT_ERROR scError;
    SYMCRYPT_SSHKDF_EXPANDED_KEY expandedKey;
    BYTE buffer1[1024];
    BYTE buffer2[sizeof(buffer1)];
    BYTE expandedKeyChecksum1[SYMCRYPT_MARVIN32_RESULT_SIZE];
    BYTE expandedKeyChecksum2[SYMCRYPT_MARVIN32_RESULT_SIZE];
    PCSYMCRYPT_HASH pHash = nullptr;

    CHECK(cbDst <= sizeof(buffer1), "SSH-KDF output too large");


    switch (pArgs->argType)
    {
        case KdfArgumentSshKdf:
            break;

        default:
            CHECK(FALSE, "Unknown argument type for SSH-KDF");
            return;
    }

    if (!strcmp(pArgs->uSshKdf.hashName, "SHA-1"))
    {
        pHash = ScShimSymCryptSha1Algorithm;
    }
    else if (!strcmp(pArgs->uSshKdf.hashName, "SHA-256"))
    {
        pHash = ScShimSymCryptSha256Algorithm;
    }
    else if (!strcmp(pArgs->uSshKdf.hashName, "SHA-384"))
    {
        pHash = ScShimSymCryptSha384Algorithm;
    }
    else if (!strcmp(pArgs->uSshKdf.hashName, "SHA-512"))
    {
        pHash = ScShimSymCryptSha512Algorithm;
    }

    CHECK3(pHash != nullptr, "Unexpected hash function (%s) for SSH-KDF", pArgs->uSshKdf.hashName);

    scError = ScShimSymCryptSshKdfExpandKey(&expandedKey, pHash, pbKey, cbKey);
    CHECK(scError == SYMCRYPT_NO_ERROR, "Error in SymCryptSshKdfExpandKey");

    ScShimSymCryptMarvin32(ScShimSymCryptMarvin32DefaultSeed, (PCBYTE)&expandedKey, sizeof(expandedKey), expandedKeyChecksum1);

    scError = ScShimSymCryptSshKdfDerive(&expandedKey,
                                        pArgs->uSshKdf.pbHashValue, pArgs->uSshKdf.cbHashValue,
                                        pArgs->uSshKdf.label,
                                        pArgs->uSshKdf.pbSessionId, pArgs->uSshKdf.cbSessionId,
                                        buffer1, cbDst);
    CHECK(scError == SYMCRYPT_NO_ERROR, "Error in SymCryptSshKdfDerive");

    ScShimSymCryptMarvin32(ScShimSymCryptMarvin32DefaultSeed, (PCBYTE)&expandedKey, sizeof(expandedKey), expandedKeyChecksum2);
    CHECK(memcmp(expandedKeyChecksum1, expandedKeyChecksum2, SYMCRYPT_MARVIN32_RESULT_SIZE) == 0, "SymCryptSshKdfDerive modified expanded key");

    scError = ScShimSymCryptSshKdf(pHash,
                                    pbKey, cbKey,
                                    pArgs->uSshKdf.pbHashValue, pArgs->uSshKdf.cbHashValue,
                                    pArgs->uSshKdf.label,
                                    pArgs->uSshKdf.pbSessionId, pArgs->uSshKdf.cbSessionId,
                                    buffer2, cbDst);
    CHECK(scError == SYMCRYPT_NO_ERROR, "Error in SymCryptSshKdf");

    CHECK(memcmp(buffer1, buffer2, cbDst) == 0, "SymCrypt SSH-KDF calling versions disagree");

    memcpy(pbDst, buffer1, cbDst);
}

template<>
VOID
algImpDataPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize)
{
    PCSYMCRYPT_SSHKDF_EXPANDED_KEY pExpandedKey = (PCSYMCRYPT_SSHKDF_EXPANDED_KEY)buf1;

    ScShimSymCryptSshKdfDerive(pExpandedKey,
                                buf2, SYMCRYPT_XXX_BASE_RESULT_SIZE,
                                (BYTE)SYMCRYPT_SSHKDF_ENCRYPTION_KEY_CLIENT_TO_SERVER,
                                buf2, SYMCRYPT_XXX_BASE_RESULT_SIZE,
                                buf3, dataSize);
}

