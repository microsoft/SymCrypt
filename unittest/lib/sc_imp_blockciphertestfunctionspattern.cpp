//
// Pattern file for defining test functions which wrap the SymCrypt block cipher implementations with
// a unified API.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

template<>
VOID
SYMCRYPT_CALL
SYMCRYPT_EncryptTest<ImpXxx, AlgXxx, ModeEcb>(
    _In_                                    PVOID   pExpandedKey,
    _In_reads_( SCSHIM_XXX_BLOCK_SIZE )   PBYTE   pbChainingValue,
    _In_reads_( cbData )                    PCBYTE  pbSrc,
    _Out_writes_( cbData )                  PBYTE   pbDst,
                                            SIZE_T  cbData )
{
    UNREFERENCED_PARAMETER( pbChainingValue );

    ScShimSymCryptEcbEncrypt(
        SymCryptBlockCipherXxx,
        (SCSHIM_XXX_EXPANDED_KEY*)pExpandedKey,
        pbSrc,
        pbDst,
        cbData);
}

template<>
VOID
SYMCRYPT_CALL
SYMCRYPT_DecryptTest<ImpXxx, AlgXxx, ModeEcb>(
    _In_                                    PVOID   pExpandedKey,
    _In_reads_( SCSHIM_XXX_BLOCK_SIZE )   PBYTE   pbChainingValue,
    _In_reads_( cbData )                    PCBYTE  pbSrc,
    _Out_writes_( cbData )                  PBYTE   pbDst,
                                            SIZE_T  cbData )
{

    UNREFERENCED_PARAMETER( pbChainingValue );

    ScShimSymCryptEcbDecrypt(
        SymCryptBlockCipherXxx,
        (SCSHIM_XXX_EXPANDED_KEY*)pExpandedKey,
        pbSrc,
        pbDst,
        cbData);
}

template<>
VOID
SYMCRYPT_CALL
SYMCRYPT_EncryptTest<ImpXxx, AlgXxx, ModeCbc>(
    _In_                                    PVOID   pExpandedKey,
    _In_reads_( SCSHIM_XXX_BLOCK_SIZE )   PBYTE   pbChainingValue,
    _In_reads_( cbData )                    PCBYTE  pbSrc,
    _Out_writes_( cbData )                  PBYTE   pbDst,
                                            SIZE_T  cbData )
{
    if constexpr ( std::is_same<ImpXxx, ImpSc>::value || std::is_same<ImpXxx, ImpScStatic>::value )
    {
        SYMCRYPT_ASSERT( SymCryptBlockCipherXxx->blockSize == SCSHIM_XXX_BLOCK_SIZE );
    }

    ScShimSymCryptCbcEncrypt(
        SymCryptBlockCipherXxx,
        (SCSHIM_XXX_EXPANDED_KEY*)pExpandedKey,
        pbChainingValue,
        pbSrc,
        pbDst,
        cbData);
}

template<>
VOID
SYMCRYPT_CALL
SYMCRYPT_DecryptTest<ImpXxx, AlgXxx, ModeCbc>(
    _In_                                    PVOID   pExpandedKey,
    _In_reads_( SCSHIM_XXX_BLOCK_SIZE )   PBYTE   pbChainingValue,
    _In_reads_( cbData )                    PCBYTE  pbSrc,
    _Out_writes_( cbData )                  PBYTE   pbDst,
                                            SIZE_T  cbData )
{
    if constexpr ( std::is_same<ImpXxx, ImpSc>::value || std::is_same<ImpXxx, ImpScStatic>::value )
    {
        SYMCRYPT_ASSERT( SymCryptBlockCipherXxx->blockSize == SCSHIM_XXX_BLOCK_SIZE );
    }

    ScShimSymCryptCbcDecrypt(
        SymCryptBlockCipherXxx,
        (SCSHIM_XXX_EXPANDED_KEY*)pExpandedKey,
        pbChainingValue,
        pbSrc,
        pbDst,
        cbData);
}

template<>
VOID
SYMCRYPT_CALL
SYMCRYPT_EncryptTest<ImpXxx, AlgXxx, ModeCfb>(
    _In_                                    PVOID   pExpandedKey,
    _In_reads_( SCSHIM_XXX_BLOCK_SIZE )   PBYTE   pbChainingValue,
    _In_reads_( cbData )                    PCBYTE  pbSrc,
    _Out_writes_( cbData )                  PBYTE   pbDst,
                                            SIZE_T  cbData )
{
    if constexpr ( std::is_same<ImpXxx, ImpSc>::value || std::is_same<ImpXxx, ImpScStatic>::value )
    {
        SYMCRYPT_ASSERT( SymCryptBlockCipherXxx->blockSize == SCSHIM_XXX_BLOCK_SIZE );
    }

    ScShimSymCryptCfbEncrypt(
        SymCryptBlockCipherXxx,
        g_modeCfbShiftParam,
        (SCSHIM_XXX_EXPANDED_KEY*)pExpandedKey,
        pbChainingValue,
        pbSrc,
        pbDst,
        cbData);
}

template<>
VOID
SYMCRYPT_CALL
SYMCRYPT_DecryptTest<ImpXxx, AlgXxx, ModeCfb>(
    _In_                                    PVOID   pExpandedKey,
    _In_reads_( SCSHIM_XXX_BLOCK_SIZE )   PBYTE   pbChainingValue,
    _In_reads_( cbData )                    PCBYTE  pbSrc,
    _Out_writes_( cbData )                  PBYTE   pbDst,
                                            SIZE_T  cbData )
{
    if constexpr ( std::is_same<ImpXxx, ImpSc>::value || std::is_same<ImpXxx, ImpScStatic>::value )
    {
        SYMCRYPT_ASSERT( SymCryptBlockCipherXxx->blockSize == SCSHIM_XXX_BLOCK_SIZE );
    }

    ScShimSymCryptCfbDecrypt(
        SymCryptBlockCipherXxx,
        g_modeCfbShiftParam,
        (SCSHIM_XXX_EXPANDED_KEY*)pExpandedKey,
        pbChainingValue,
        pbSrc,
        pbDst,
        cbData);
}
