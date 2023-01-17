//
// shake_pattern.c
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//


//
// This source file implements SHAKE128 and SHAKE256
//
// See the symcrypt.h file for documentation on what the various functions do.
//

//
// SymCryptShake
//
VOID
SYMCRYPT_CALL
SYMCRYPT_XxxDefault(
    _In_reads_( cbData )                            PCBYTE  pbData,
                                                    SIZE_T  cbData,
    _Out_writes_( SYMCRYPT_SHAKEXXX_RESULT_SIZE )   PBYTE   pbResult)
{
    SYMCRYPT_Xxx(pbData, cbData, pbResult, SYMCRYPT_SHAKEXXX_RESULT_SIZE);
}

//
// SymCryptShakeEx
//
VOID
SYMCRYPT_CALL
SYMCRYPT_Xxx(
    _In_reads_( cbData )        PCBYTE  pbData,
                                SIZE_T  cbData,
    _Out_writes_( cbResult )    PBYTE   pbResult,
                                SIZE_T  cbResult)
{
    SYMCRYPT_XXX_STATE state;

    SYMCRYPT_XxxInit(&state);
    SYMCRYPT_XxxAppend(&state, pbData, cbData);
    SYMCRYPT_XxxExtract(&state, pbResult, cbResult, TRUE);
}

//
// SymCryptShakeStateCopy
//
VOID
SYMCRYPT_CALL
SYMCRYPT_XxxStateCopy(_In_ const SYMCRYPT_XXX_STATE* pSrc, _Out_ SYMCRYPT_XXX_STATE* pDst)
{
    SYMCRYPT_CHECK_MAGIC(pSrc);
    *pDst = *pSrc;
    SYMCRYPT_SET_MAGIC(pDst);
}

//
// SymCryptShakeInit
//
VOID
SYMCRYPT_CALL
SYMCRYPT_XxxInit(_Out_ PSYMCRYPT_XXX_STATE pState)
{
    SymCryptKeccakInit(pState,
                        SYMCRYPT_SHAKEXXX_INPUT_BLOCK_SIZE,
                        SYMCRYPT_SHAKE_PADDING_VALUE);
}

//
// SymCryptShakeAppend
//
VOID
SYMCRYPT_CALL
SYMCRYPT_XxxAppend(
    _Inout_             PSYMCRYPT_XXX_STATE pState,
    _In_reads_(cbData)  PCBYTE              pbData,
                        SIZE_T              cbData)
{
    SymCryptKeccakAppend(pState, pbData, cbData);
}

//
// SymCryptShakeExtract
//
VOID
SYMCRYPT_CALL
SYMCRYPT_XxxExtract(
    _Inout_                 PSYMCRYPT_XXX_STATE pState,
    _Out_writes_(cbResult)  PBYTE               pbResult,
                            SIZE_T              cbResult,
                            BOOLEAN             bWipe)
{
    SymCryptKeccakExtract(pState, pbResult, cbResult, bWipe);
}

//
// SymCryptShakeResult
//
VOID
SYMCRYPT_CALL
SYMCRYPT_XxxResult(
    _Inout_                                     PSYMCRYPT_XXX_STATE pState,
    _Out_writes_(SYMCRYPT_SHAKEXXX_RESULT_SIZE) PBYTE               pbResult)
{
    SymCryptKeccakExtract(pState, pbResult, SYMCRYPT_SHAKEXXX_RESULT_SIZE, TRUE);
}

#if 0
//
// SymCryptShakeStateExport
//
VOID
SYMCRYPT_CALL
SYMCRYPT_XxxStateExport(
    _In_                                                    PCSYMCRYPT_XXX_STATE    pState,
    _Out_writes_bytes_(SYMCRYPT_SHAKEXXX_STATE_EXPORT_SIZE) PBYTE                   pbBlob)
{
    SymCryptKeccakStateExport(SYMCRYPT_BLOB_TYPE_XXX, pState, pbBlob);
}

//
// SymCryptShakeStateImport
//
SYMCRYPT_ERROR
SYMCRYPT_CALL
SYMCRYPT_XxxStateImport(
    _Out_                                                   PSYMCRYPT_XXX_STATE pState,
    _In_reads_bytes_(SYMCRYPT_SHAKEXXX_STATE_EXPORT_SIZE)   PCBYTE              pbBlob)
{
    return SymCryptKeccakStateImport(SYMCRYPT_BLOB_TYPE_XXX, pState, pbBlob);
}
#endif
