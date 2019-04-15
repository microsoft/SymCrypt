//
// Pattern file for the CNG TLS PRF 1.2 implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

VOID
KdfImp<ImpCng, AlgTlsPrf1_2, BaseAlgXxx>::derive(
    _In_reads_(cbKey)       PCBYTE          pbKey,
                            SIZE_T          cbKey,
    _In_                    PKDF_ARGUMENTS  pArgs,
    _Out_writes_(cbDst)     PBYTE           pbDst,
                            SIZE_T          cbDst)
{
    BCRYPT_KEY_HANDLE hKey;

    BCryptBuffer        buffer[5];
    BCryptBufferDesc    bufferDesc;

    CHECK3(NT_SUCCESS(CngGenerateSymmetricKeyFn(state.hAlg, &hKey, NULL, 0, (PBYTE)pbKey, (ULONG)cbKey, 0)), "Could not generate key for TLS-PRF-%s", STRING(ALG_Base));

    bufferDesc.ulVersion = BCRYPTBUFFER_VERSION;
    bufferDesc.cBuffers = 0;
    bufferDesc.pBuffers = &buffer[0];

    AddBCryptBuffer(&bufferDesc, KDF_HASH_ALGORITHM, CNG_XXX_HASH_ALG_NAMEU, (wcslen(CNG_XXX_HASH_ALG_NAMEU) + 1) * sizeof(WCHAR)); // Must pass null-terminated byte length.

    switch (pArgs->argType)
    {
    case KdfArgumentTlsPrf:
        AddBCryptBuffer(&bufferDesc, KDF_TLS_PRF_LABEL, pArgs->uTlsPrf.pbLabel, pArgs->uTlsPrf.cbLabel);
        AddBCryptBuffer(&bufferDesc, KDF_TLS_PRF_SEED, pArgs->uTlsPrf.pbSeed, pArgs->uTlsPrf.cbSeed);
        break;
    default:
        CHECK(FALSE, "Unknown argument type for TLS PRF 1.2");
        return;
    }

    ULONG cbResult;
    CHECK(NT_SUCCESS((*CngKeyDerivationFn)(hKey, &bufferDesc, pbDst, (ULONG)cbDst, &cbResult, 0)), "Failure in CNG TLS PRF 1.2 call");
    CHECK(cbResult == cbDst, "TLS PRF 1.2 result size mismatch");
}

VOID
algImpDataPerfFunction<ImpXxx, AlgXxx, BaseAlgXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize)
{
    BCryptBuffer        buffer[5];
    BCryptBufferDesc    bufferDesc;
    ULONG               cbResult;

    BCRYPT_KEY_HANDLE hKey = *(BCRYPT_KEY_HANDLE *)buf1;

    bufferDesc.ulVersion = BCRYPTBUFFER_VERSION;
    bufferDesc.cBuffers = 0;
    bufferDesc.pBuffers = &buffer[0];

    AddBCryptBuffer(&bufferDesc, KDF_HASH_ALGORITHM, CNG_XXX_HASH_ALG_NAMEU, 2 * wcslen(CNG_XXX_HASH_ALG_NAMEU));
    AddBCryptBuffer(&bufferDesc, KDF_TLS_PRF_SEED, buf2, 32);

    (*CngKeyDerivationFn)(hKey, &bufferDesc, buf3, (ULONG)dataSize, &cbResult, 0);
}

