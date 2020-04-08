//
// SymCrypt implementation classes
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

//
// These ECB functions are not confused with the ones in Symcrypt.h because they have the pbChainingValue
// extra parameter, and C++ handles the function overloads.
//
VOID
SYMCRYPT_CALL
SymCryptAesEcbEncrypt(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    UNREFERENCED_PARAMETER( pbChainingValue );

    SymCryptAesEcbEncrypt( pExpandedKey, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCryptAesEcbDecrypt(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    UNREFERENCED_PARAMETER( pbChainingValue );

    SymCryptAesEcbDecrypt( pExpandedKey, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCryptAesCfbEncrypt(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    _Analysis_assume_( SymCryptAesBlockCipher->blockSize == SYMCRYPT_AES_BLOCK_SIZE );
    SymCryptCfbEncrypt( SymCryptAesBlockCipher,
                        g_modeCfbShiftParam,
                        pExpandedKey,
                        pbChainingValue,
                        pbSrc,
                        pbDst,
                        cbData );
}

VOID
SYMCRYPT_CALL
SymCryptAesCfbDecrypt(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    _Analysis_assume_( SymCryptAesBlockCipher->blockSize == SYMCRYPT_AES_BLOCK_SIZE );
    SymCryptCfbDecrypt( SymCryptAesBlockCipher,
                        g_modeCfbShiftParam,
                        pExpandedKey,
                        pbChainingValue,
                        pbSrc,
                        pbDst,
                        cbData );
}

VOID
SYMCRYPT_CALL
SymCryptDesEcbEncrypt(
    _In_                                    PCSYMCRYPT_DES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_DES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    UNREFERENCED_PARAMETER( pbChainingValue );

    SymCryptEcbEncrypt( SymCryptDesBlockCipher, pExpandedKey, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCryptDesEcbDecrypt(
    _In_                                    PCSYMCRYPT_DES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_DES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    UNREFERENCED_PARAMETER( pbChainingValue );

    SymCryptEcbDecrypt( SymCryptDesBlockCipher, pExpandedKey, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCryptDesCbcEncrypt(
    _In_                                    PCSYMCRYPT_DES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_DES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    _Analysis_assume_( SymCryptDesBlockCipher.blockSize == SYMCRYPT_DES_BLOCK_SIZE );
    SymCryptCbcEncrypt( SymCryptDesBlockCipher, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCryptDesCbcDecrypt(
    _In_                                    PCSYMCRYPT_DES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_DES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    _Analysis_assume_( SymCryptDesBlockCipher.blockSize == SYMCRYPT_DES_BLOCK_SIZE );
    SymCryptCbcDecrypt( SymCryptDesBlockCipher, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCryptDesCfbEncrypt(
    _In_                                    PCSYMCRYPT_DES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_DES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    _Analysis_assume_( SymCryptDesBlockCipher.blockSize == SYMCRYPT_DES_BLOCK_SIZE );
    SymCryptCfbEncrypt( SymCryptDesBlockCipher, g_modeCfbShiftParam, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCryptDesCfbDecrypt(
    _In_                                    PCSYMCRYPT_DES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_DES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    _Analysis_assume_( SymCryptDesBlockCipher.blockSize == SYMCRYPT_DES_BLOCK_SIZE );
    SymCryptCfbDecrypt( SymCryptDesBlockCipher, g_modeCfbShiftParam, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
}


VOID
SYMCRYPT_CALL
SymCrypt2DesEcbEncrypt(
    _In_                                    PCSYMCRYPT_3DES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_DES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    UNREFERENCED_PARAMETER( pbChainingValue );

    SymCryptEcbEncrypt( SymCrypt3DesBlockCipher, pExpandedKey, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCrypt2DesEcbDecrypt(
    _In_                                    PCSYMCRYPT_3DES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_DES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    UNREFERENCED_PARAMETER( pbChainingValue );

    SymCryptEcbDecrypt( SymCrypt3DesBlockCipher, pExpandedKey, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCrypt2DesCbcEncrypt(
    _In_                                    PCSYMCRYPT_3DES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_DES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    _Analysis_assume_( SymCrypt3DesBlockCipher.blockSize == SYMCRYPT_DES_BLOCK_SIZE );
    SymCryptCbcEncrypt( SymCrypt3DesBlockCipher, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCrypt2DesCbcDecrypt(
    _In_                                    PCSYMCRYPT_3DES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_DES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    _Analysis_assume_( SymCrypt3DesBlockCipher.blockSize == SYMCRYPT_DES_BLOCK_SIZE );
    SymCryptCbcDecrypt( SymCrypt3DesBlockCipher, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCrypt2DesCfbEncrypt(
    _In_                                    PCSYMCRYPT_3DES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_DES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    _Analysis_assume_( SymCrypt3DesBlockCipher.blockSize == SYMCRYPT_DES_BLOCK_SIZE );
    SymCryptCfbEncrypt( SymCrypt3DesBlockCipher, g_modeCfbShiftParam, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCrypt2DesCfbDecrypt(
    _In_                                    PCSYMCRYPT_3DES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_DES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    _Analysis_assume_( SymCrypt3DesBlockCipher.blockSize == SYMCRYPT_DES_BLOCK_SIZE );
    SymCryptCfbDecrypt( SymCrypt3DesBlockCipher, g_modeCfbShiftParam, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCrypt3DesEcbEncrypt(
    _In_                                    PCSYMCRYPT_3DES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_DES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    UNREFERENCED_PARAMETER( pbChainingValue );

    SymCryptEcbEncrypt( SymCrypt3DesBlockCipher, pExpandedKey, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCrypt3DesEcbDecrypt(
    _In_                                    PCSYMCRYPT_3DES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_DES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    UNREFERENCED_PARAMETER( pbChainingValue );

    SymCryptEcbDecrypt( SymCrypt3DesBlockCipher, pExpandedKey, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCrypt3DesCfbEncrypt(
    _In_                                    PCSYMCRYPT_3DES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_DES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    _Analysis_assume_( SymCrypt3DesBlockCipher.blockSize == SYMCRYPT_DES_BLOCK_SIZE );
    SymCryptCfbEncrypt( SymCrypt3DesBlockCipher, g_modeCfbShiftParam, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCrypt3DesCfbDecrypt(
    _In_                                    PCSYMCRYPT_3DES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_DES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    _Analysis_assume_( SymCrypt3DesBlockCipher.blockSize == SYMCRYPT_DES_BLOCK_SIZE );
    SymCryptCfbDecrypt( SymCrypt3DesBlockCipher, g_modeCfbShiftParam, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
}


VOID
SYMCRYPT_CALL
SymCryptDesxEcbEncrypt(
    _In_                                    PCSYMCRYPT_DESX_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_DESX_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    UNREFERENCED_PARAMETER( pbChainingValue );

    SymCryptEcbEncrypt( SymCryptDesxBlockCipher, pExpandedKey, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCryptDesxEcbDecrypt(
    _In_                                    PCSYMCRYPT_DESX_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_DESX_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    UNREFERENCED_PARAMETER( pbChainingValue );

    SymCryptEcbDecrypt( SymCryptDesxBlockCipher, pExpandedKey, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCryptDesxCbcEncrypt(
    _In_                                    PCSYMCRYPT_DESX_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_DESX_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    _Analysis_assume_( SymCryptDesxBlockCipher.blockSize == SYMCRYPT_DESX_BLOCK_SIZE );
    SymCryptCbcEncrypt( SymCryptDesxBlockCipher, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCryptDesxCbcDecrypt(
    _In_                                    PCSYMCRYPT_DESX_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_DESX_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    _Analysis_assume_( SymCryptDesxBlockCipher.blockSize == SYMCRYPT_DESX_BLOCK_SIZE );
    SymCryptCbcDecrypt( SymCryptDesxBlockCipher, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCryptDesxCfbEncrypt(
    _In_                                    PCSYMCRYPT_DESX_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_DESX_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    _Analysis_assume_( SymCryptDesxBlockCipher.blockSize == SYMCRYPT_DESX_BLOCK_SIZE );
    SymCryptCfbEncrypt( SymCryptDesxBlockCipher, g_modeCfbShiftParam, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCryptDesxCfbDecrypt(
    _In_                                    PCSYMCRYPT_DESX_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_DESX_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    _Analysis_assume_( SymCryptDesxBlockCipher.blockSize == SYMCRYPT_DESX_BLOCK_SIZE );
    SymCryptCfbDecrypt( SymCryptDesxBlockCipher, g_modeCfbShiftParam, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
}


VOID
SYMCRYPT_CALL
SymCryptRc2EcbEncrypt(
    _In_                                    PCSYMCRYPT_RC2_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_RC2_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    UNREFERENCED_PARAMETER( pbChainingValue );

    SymCryptEcbEncrypt( SymCryptRc2BlockCipher, pExpandedKey, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCryptRc2EcbDecrypt(
    _In_                                    PCSYMCRYPT_RC2_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_RC2_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    UNREFERENCED_PARAMETER( pbChainingValue );

    SymCryptEcbDecrypt( SymCryptRc2BlockCipher, pExpandedKey, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCryptRc2CbcEncrypt(
    _In_                                    PCSYMCRYPT_RC2_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_RC2_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    _Analysis_assume_( SymCryptRc2BlockCipher.blockSize == SYMCRYPT_RC2_BLOCK_SIZE );
    SymCryptCbcEncrypt( SymCryptRc2BlockCipher, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCryptRc2CbcDecrypt(
    _In_                                    PCSYMCRYPT_RC2_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_RC2_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    _Analysis_assume_( SymCryptRc2BlockCipher.blockSize == SYMCRYPT_RC2_BLOCK_SIZE );
    SymCryptCbcDecrypt( SymCryptRc2BlockCipher, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCryptRc2CfbEncrypt(
    _In_                                    PCSYMCRYPT_RC2_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_RC2_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    _Analysis_assume_( SymCryptRc2BlockCipher.blockSize == SYMCRYPT_RC2_BLOCK_SIZE );
    SymCryptCfbEncrypt( SymCryptRc2BlockCipher, g_modeCfbShiftParam, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
}

VOID
SYMCRYPT_CALL
SymCryptRc2CfbDecrypt(
    _In_                                    PCSYMCRYPT_RC2_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_RC2_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    _Analysis_assume_( SymCryptRc2BlockCipher.blockSize == SYMCRYPT_RC2_BLOCK_SIZE );
    SymCryptCfbDecrypt( SymCryptRc2BlockCipher, g_modeCfbShiftParam, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData );
}

//
// An ugly hack, we re-map the RC2 key expansion to use the global key size variable.
//
#define SymCryptRc2ExpandKey( pKey, pbKey, cbKey ) SymCryptRc2ExpandKeyEx( pKey, pbKey, cbKey, g_rc2EffectiveKeyLength ? g_rc2EffectiveKeyLength : 8*(ULONG)cbKey );


#define SYMCRYPT_2DES_EXPANDED_KEY  SYMCRYPT_3DES_EXPANDED_KEY
#define SymCrypt2DesExpandKey       SymCrypt3DesExpandKey

char * ImpSc::name = "SymCrypt";

#define IMP_NAME    SYMCRYPT
#define IMP_Name    Sc

#define ALG_NAME    MD2
#define ALG_Name    Md2
#include "sc_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME   MD4
#define ALG_Name   Md4
#include "sc_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME   MD5
#define ALG_Name   Md5
#include "sc_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME   SHA1
#define ALG_Name   Sha1
#include "sc_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME   SHA256
#define ALG_Name   Sha256
#include "sc_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME   SHA384
#define ALG_Name   Sha384
#include "sc_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME   SHA512
#define ALG_Name   Sha512
#include "sc_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name


#define ALG_NAME    HMAC_MD5
#define ALG_Name    HmacMd5
#include "sc_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    HMAC_SHA1
#define ALG_Name    HmacSha1
#include "sc_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    HMAC_SHA256
#define ALG_Name    HmacSha256
#include "sc_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    HMAC_SHA384
#define ALG_Name    HmacSha384
#include "sc_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    HMAC_SHA512
#define ALG_Name    HmacSha512
#include "sc_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    AES_CMAC
#define ALG_Name    AesCmac
#include "sc_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    MARVIN32
#define ALG_Name    Marvin32
#include "sc_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name


#define ALG_NAME    AES
#define ALG_Name    Aes

#define ALG_Mode    Ecb
#include "sc_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cbc
#include "sc_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cfb
#include "sc_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    DES
#define ALG_Name    Des

#define ALG_Mode    Ecb
#include "sc_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cbc
#include "sc_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cfb
#include "sc_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    2DES
#define ALG_Name    2Des

#define ALG_Mode    Ecb
#include "sc_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cbc
#include "sc_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cfb
#include "sc_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    3DES
#define ALG_Name    3Des

#define ALG_Mode    Ecb
#include "sc_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cbc
#include "sc_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cfb
#include "sc_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    DESX
#define ALG_Name    Desx

#define ALG_Mode    Ecb
#include "sc_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cbc
#include "sc_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cfb
#include "sc_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    RC2
#define ALG_Name    Rc2

#define ALG_Mode    Ecb
#include "sc_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cbc
#include "sc_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cfb
#include "sc_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#undef ALG_NAME
#undef ALG_Name


#define ALG_NAME    PBKDF2
#define ALG_Name    Pbkdf2

#define ALG_Base    HmacMd5
#include "sc_imp_kdfpattern.cpp"
#include "sc_imp_pbkdf2pattern.cpp"
#undef ALG_Base

#define ALG_Base    HmacSha1
#include "sc_imp_kdfpattern.cpp"
#include "sc_imp_pbkdf2pattern.cpp"
#undef ALG_Base

#define ALG_Base    HmacSha256
#include "sc_imp_kdfpattern.cpp"
#include "sc_imp_pbkdf2pattern.cpp"
#undef ALG_Base

#define ALG_Base    HmacSha384
#include "sc_imp_kdfpattern.cpp"
#include "sc_imp_pbkdf2pattern.cpp"
#undef ALG_Base

#define ALG_Base    HmacSha512
#include "sc_imp_kdfpattern.cpp"
#include "sc_imp_pbkdf2pattern.cpp"
#undef ALG_Base

#define ALG_Base    AesCmac
#include "sc_imp_kdfpattern.cpp"
#include "sc_imp_pbkdf2pattern.cpp"
#undef ALG_Base

#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    SP800_108
#define ALG_Name    Sp800_108

#define ALG_Base    HmacMd5
#include "sc_imp_kdfpattern.cpp"
#include "sc_imp_sp800_108pattern.cpp"
#undef ALG_Base

#define ALG_Base    HmacSha1
#include "sc_imp_kdfpattern.cpp"
#include "sc_imp_sp800_108pattern.cpp"
#undef ALG_Base

#define ALG_Base    HmacSha256
#include "sc_imp_kdfpattern.cpp"
#include "sc_imp_sp800_108pattern.cpp"
#undef ALG_Base

#define ALG_Base    HmacSha384
#include "sc_imp_kdfpattern.cpp"
#include "sc_imp_sp800_108pattern.cpp"
#undef ALG_Base

#define ALG_Base    HmacSha512
#include "sc_imp_kdfpattern.cpp"
#include "sc_imp_sp800_108pattern.cpp"
#undef ALG_Base

#define ALG_Base    AesCmac
#include "sc_imp_kdfpattern.cpp"
#include "sc_imp_sp800_108pattern.cpp"
#undef ALG_Base

#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    TLSPRF1_1
#define ALG_Name    TlsPrf1_1

#define ALG_Base    HmacMd5
#include "sc_imp_tlsprf1_1pattern.cpp"
#undef ALG_Base

#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    TLSPRF1_2
#define ALG_Name    TlsPrf1_2

#define ALG_Base    HmacSha256
#include "sc_imp_kdfpattern.cpp"
#include "sc_imp_tlsprf1_2pattern.cpp"
#undef ALG_Base

#define ALG_Base    HmacSha384
#include "sc_imp_kdfpattern.cpp"
#include "sc_imp_tlsprf1_2pattern.cpp"
#undef ALG_Base

#define ALG_Base    HmacSha512
#include "sc_imp_kdfpattern.cpp"
#include "sc_imp_tlsprf1_2pattern.cpp"
#undef ALG_Base

#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    HKDF
#define ALG_Name    Hkdf

#define ALG_Base    HmacSha256
#include "sc_imp_hkdfpattern.cpp"
#undef ALG_Base

#define ALG_Base    HmacSha1
#include "sc_imp_hkdfpattern.cpp"
#undef ALG_Base

#undef ALG_NAME
#undef ALG_Name

#undef IMP_NAME
#undef IMP_Name

template<>
NTSTATUS HashImp<ImpSc, AlgMd2>::initWithLongMessage( ULONGLONG nBytes )
{
    UNREFERENCED_PARAMETER( nBytes );

    memset( &state.sc.chain, 'b', sizeof( state.sc.chain ) );
    state.sc.dataLengthL = nBytes;
    state.sc.dataLengthH = 0;
    state.sc.bytesInBuffer = nBytes & 0x3f;

    SymCryptMd2StateCopy( &state.sc, &state.scHash.md2State );
    return STATUS_SUCCESS;
}

template<>
NTSTATUS HashImp<ImpSc, AlgMd4>::initWithLongMessage( ULONGLONG nBytes )
{
    memset( &state.sc.chain, 'b', sizeof( state.sc.chain ) );
    state.sc.dataLengthL = nBytes;
    state.sc.dataLengthH = 0;
    state.sc.bytesInBuffer = nBytes & 0x3f;

    SymCryptMd4StateCopy( &state.sc, &state.scHash.md4State );
    return STATUS_SUCCESS;
}

template<>
NTSTATUS HashImp<ImpSc, AlgMd5>::initWithLongMessage( ULONGLONG nBytes )
{
    memset( &state.sc.chain, 'b', sizeof( state.sc.chain ) );
    state.sc.dataLengthL = nBytes;
    state.sc.dataLengthH = 0;
    state.sc.bytesInBuffer = nBytes & 0x3f;

    SymCryptMd5StateCopy( &state.sc, &state.scHash.md5State );
    return STATUS_SUCCESS;
}

template<>
NTSTATUS HashImp<ImpSc, AlgSha1>::initWithLongMessage( ULONGLONG nBytes )
{
    memset( &state.sc.chain, 'b', sizeof( state.sc.chain ) );
    state.sc.dataLengthL = nBytes;
    state.sc.dataLengthH = 0;
    state.sc.bytesInBuffer = nBytes & 0x3f;

    SymCryptSha1StateCopy( &state.sc, &state.scHash.sha1State );
    return STATUS_SUCCESS;
}

template<>
NTSTATUS HashImp<ImpSc, AlgSha256>::initWithLongMessage( ULONGLONG nBytes )
{
    memset( &state.sc.chain, 'b', sizeof( state.sc.chain ) );
    state.sc.dataLengthL = nBytes;
    state.sc.dataLengthH = 0;
    state.sc.bytesInBuffer = nBytes & 0x3f;

    SymCryptSha256StateCopy( &state.sc, &state.scHash.sha256State );
    return STATUS_SUCCESS;
}

template<>
NTSTATUS HashImp<ImpSc, AlgSha384>::initWithLongMessage( ULONGLONG nBytes )
{
    memset( &state.sc.chain, 'b', sizeof( state.sc.chain ) );
    state.sc.dataLengthL = nBytes;
    state.sc.dataLengthH = 0;
    state.sc.bytesInBuffer = nBytes & 0x3f;

    SymCryptSha384StateCopy( &state.sc, &state.scHash.sha384State );
    return STATUS_SUCCESS;
}

template<>
NTSTATUS HashImp<ImpSc, AlgSha512>::initWithLongMessage( ULONGLONG nBytes )
{
    memset( &state.sc.chain, 'b', sizeof( state.sc.chain ) );
    state.sc.dataLengthL = nBytes;
    state.sc.dataLengthH = 0;
    state.sc.bytesInBuffer = nBytes & 0x3f;

    SymCryptSha512StateCopy( &state.sc, &state.scHash.sha512State );
    return STATUS_SUCCESS;
}


//
// There is not enough structure to the CCM & GCM modes to share an implementation
//

template<>
VOID
algImpKeyPerfFunction< ImpSc, AlgAes, ModeCcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptAesExpandKey( (SYMCRYPT_AES_EXPANDED_KEY *) buf1, buf2, keySize );
}

template<>
VOID
algImpDataPerfFunction<ImpSc,AlgAes, ModeCcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SymCryptCcmEncrypt( SymCryptAesBlockCipher, (SYMCRYPT_AES_EXPANDED_KEY *)buf1,
        buf2, 12, NULL, 0, buf2+16, buf2+16, dataSize, buf3, 16 );
}

template<>
VOID
algImpDecryptPerfFunction<ImpSc,AlgAes, ModeCcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SymCryptCcmDecrypt( SymCryptAesBlockCipher, (SYMCRYPT_AES_EXPANDED_KEY *)buf1,
        buf2, 12, NULL, 0, buf2 + 16, buf2 + 16, dataSize, buf3, 16 );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgAes, ModeCcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptWipeKnownSize( buf1, sizeof( SYMCRYPT_AES_EXPANDED_KEY ) );
}

template<>
AuthEncImp<ImpSc, AlgAes, ModeCcm>::AuthEncImp()
{
    m_perfKeyFunction     = &algImpKeyPerfFunction    <ImpSc, AlgAes, ModeCcm>;
    m_perfCleanFunction   = &algImpCleanPerfFunction  <ImpSc, AlgAes, ModeCcm>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpSc, AlgAes, ModeCcm>;
    m_perfDecryptFunction = &algImpDecryptPerfFunction<ImpSc, AlgAes, ModeCcm>;
}

template<>
AuthEncImp<ImpSc, AlgAes, ModeCcm>::~AuthEncImp()
{
}

template<>
std::set<SIZE_T>
AuthEncImp<ImpSc, AlgAes, ModeCcm>::getKeySizes()
{
    std::set<SIZE_T> res;

    res.insert( 16 );
    res.insert( 24 );
    res.insert( 32 );

    return res;
}


template<>
std::set<SIZE_T>
AuthEncImp<ImpSc, AlgAes, ModeCcm>::getNonceSizes()
{
    std::set<SIZE_T> res;

    for( int i=7; i<=13; i++ )
    {
        res.insert( i );
    }

    return res;
}


template<>
std::set<SIZE_T>
AuthEncImp<ImpSc, AlgAes, ModeCcm>::getTagSizes()
{
    std::set<SIZE_T> res;

    for( int i=4; i<=16; i += 2 )
    {
        res.insert( i );
    }

    return res;
}

template<>
NTSTATUS
AuthEncImp<ImpSc, AlgAes, ModeCcm>::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 16 || cbKey == 24 || cbKey == 32, "?" );
    initXmmRegisters();
    SymCryptAesExpandKey( &state.key, pbKey, cbKey );
    verifyXmmRegisters();

    state.inComputation = FALSE;
    return STATUS_SUCCESS;
}

template<>
VOID
AuthEncImp<ImpSc, AlgAes, ModeCcm>::setTotalCbData( SIZE_T cbData )
{
    state.totalCbData = cbData;
}

template<>
NTSTATUS
AuthEncImp<ImpSc, AlgAes, ModeCcm>::encrypt(
        _In_reads_( cbNonce )       PCBYTE  pbNonce,
                                    SIZE_T  cbNonce,
        _In_reads_( cbAuthData )    PCBYTE  pbAuthData,
                                    SIZE_T  cbAuthData,
        _In_reads_( cbData )        PCBYTE  pbSrc,
        _Out_writes_( cbData )      PBYTE   pbDst,
                                    SIZE_T  cbData,
        _Out_writes_( cbTag )       PBYTE   pbTag,
                                    SIZE_T  cbTag,
                                    ULONG   flags )
{
    NTSTATUS status = STATUS_SUCCESS;

    // print( "cbNonce = %d, cbAuthData = %d, cbData = %d, cbTag = %d\n", (ULONG)cbNonce, (ULONG) cbAuthData, (ULONG) cbData, (ULONG) cbTag );

    CHECK( (flags & ~AUTHENC_FLAG_PARTIAL) == 0, "Unknown flag" );

    if( (flags & AUTHENC_FLAG_PARTIAL) == 0 )
    {
        // simple straight CCM computation.
        initXmmRegisters();
        CHECK( SymCryptCcmValidateParameters(   SymCryptAesBlockCipher,
            cbNonce,
            cbAuthData,
            cbData,
            cbTag ) == SYMCRYPT_NO_ERROR, "?" );
        verifyXmmRegisters();

        SymCryptCcmEncrypt( SymCryptAesBlockCipher, &state.key,
            pbNonce, cbNonce, pbAuthData, cbAuthData,
            pbSrc, pbDst, cbData,
            pbTag, cbTag );
        verifyXmmRegisters();

        // Done
        goto cleanup;
    }

    if( !state.inComputation )
    {
        CHECK( (flags & AUTHENC_FLAG_PARTIAL) != 0, "?" );
        // total cbData is passed in the cbTag parameter in the first partial call
        initXmmRegisters();
        SymCryptCcmInit( &state.ccmState, SymCryptAesBlockCipher, &state.key, pbNonce, cbNonce, pbAuthData, cbAuthData, state.totalCbData, cbTag );
        verifyXmmRegisters();

        state.inComputation = TRUE;
    }

    // We can process the next part before we decide whether to produce the tag.
    initXmmRegisters();
    SymCryptCcmEncryptPart( &state.ccmState, pbSrc, pbDst, cbData );
    verifyXmmRegisters();

    if( pbTag != NULL )
    {
        initXmmRegisters();
        SymCryptCcmEncryptFinal( &state.ccmState, pbTag, cbTag );
        verifyXmmRegisters();

        state.inComputation = FALSE;
    }

cleanup:
    return status;

}


template<>
NTSTATUS
AuthEncImp<ImpSc, AlgAes, ModeCcm>::decrypt(
        _In_reads_( cbNonce )       PCBYTE  pbNonce,
                                    SIZE_T  cbNonce,
        _In_reads_( cbAuthData )    PCBYTE  pbAuthData,
                                    SIZE_T  cbAuthData,
        _In_reads_( cbData )        PCBYTE  pbSrc,
        _Out_writes_( cbData )      PBYTE   pbDst,
                                    SIZE_T  cbData,
        _In_reads_( cbTag )         PCBYTE  pbTag,
                                    SIZE_T  cbTag,
                                    ULONG   flags )
{
    NTSTATUS status = STATUS_SUCCESS;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    // print( "cbNonce = %d, cbAuthData = %d, cbData = %d, cbTag = %d\n", (ULONG)cbNonce, (ULONG) cbAuthData, (ULONG) cbData, (ULONG) cbTag );

    CHECK( (flags & ~AUTHENC_FLAG_PARTIAL) == 0, "Unknown flag" );

    if( (flags & AUTHENC_FLAG_PARTIAL) == 0 )
    {
        // simple straight CCM computation.
        initXmmRegisters();
        CHECK( SymCryptCcmValidateParameters(   SymCryptAesBlockCipher,
            cbNonce,
            cbAuthData,
            cbData,
            cbTag ) == SYMCRYPT_NO_ERROR, "?" );
        verifyXmmRegisters();

        scError = SymCryptCcmDecrypt( SymCryptAesBlockCipher, &state.key,
            pbNonce, cbNonce, pbAuthData, cbAuthData,
            pbSrc, pbDst, cbData,
            pbTag, cbTag );
        verifyXmmRegisters();

        if( scError == SYMCRYPT_AUTHENTICATION_FAILURE )
        {
            status = STATUS_AUTH_TAG_MISMATCH;
        } else {
            CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
        }

        // Done
        goto cleanup;
    }

    if( !state.inComputation )
    {
        // First call of a partial computation.
        initXmmRegisters();
        SymCryptCcmInit( &state.ccmState, SymCryptAesBlockCipher, &state.key, pbNonce, cbNonce, pbAuthData, cbAuthData, state.totalCbData, cbTag );
        verifyXmmRegisters();

        state.inComputation = TRUE;
    }

    // We can process the next part before we decide whether to produce the tag.
    initXmmRegisters();
    SymCryptCcmDecryptPart( &state.ccmState, pbSrc, pbDst, cbData );
    verifyXmmRegisters();

    if( pbTag != NULL )
    {
        initXmmRegisters();
        scError = SymCryptCcmDecryptFinal( &state.ccmState, pbTag, cbTag );
        if( scError == SYMCRYPT_AUTHENTICATION_FAILURE )
        {
            status = STATUS_AUTH_TAG_MISMATCH;
        } else {
            CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
        }
        verifyXmmRegisters();

        state.inComputation = FALSE;
    }

cleanup:
    return status;
}


//////////////////////////
// GCM

//
// There is not enough structure to the CCM & GCM modes to share an implementation
//

template<>
VOID
algImpKeyPerfFunction< ImpSc, AlgAes, ModeGcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptGcmExpandKey( (PSYMCRYPT_GCM_EXPANDED_KEY) buf1,
                          SymCryptAesBlockCipher,
                          buf2, keySize );
}

template<>
VOID
algImpDataPerfFunction<ImpSc,AlgAes, ModeGcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SymCryptGcmEncrypt( (PCSYMCRYPT_GCM_EXPANDED_KEY) buf1,
                            buf2, 12,
                            NULL, 0,
                            buf2+16, buf2+16, dataSize,
                            buf3, 16 );
}

template<>
VOID
algImpDecryptPerfFunction<ImpSc,AlgAes, ModeGcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SymCryptGcmDecrypt( (PCSYMCRYPT_GCM_EXPANDED_KEY) buf1,
                            buf2, 12,
                            NULL, 0,
                            buf2+16, buf2+16, dataSize,
                            buf3, 16 );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgAes, ModeGcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptWipeKnownSize( buf1, sizeof( SYMCRYPT_GCM_EXPANDED_KEY ) );
}

template<>
AuthEncImp<ImpSc, AlgAes, ModeGcm>::AuthEncImp()
{
    m_perfKeyFunction     = &algImpKeyPerfFunction    <ImpSc, AlgAes, ModeGcm>;
    m_perfCleanFunction   = &algImpCleanPerfFunction  <ImpSc, AlgAes, ModeGcm>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpSc, AlgAes, ModeGcm>;
    m_perfDecryptFunction = &algImpDecryptPerfFunction<ImpSc, AlgAes, ModeGcm>;
}

template<>
AuthEncImp<ImpSc, AlgAes, ModeGcm>::~AuthEncImp()
{
    SymCryptWipeKnownSize( &state.key, sizeof( state.key ) );
}

template<>
std::set<SIZE_T>
AuthEncImp<ImpSc, AlgAes, ModeGcm>::getKeySizes()
{
    std::set<SIZE_T> res;

    res.insert( 16 );
    res.insert( 24 );
    res.insert( 32 );

    return res;
}


template<>
std::set<SIZE_T>
AuthEncImp<ImpSc, AlgAes, ModeGcm>::getNonceSizes()
{
    std::set<SIZE_T> res;

    res.insert( 12 );

    return res;
}


template<>
std::set<SIZE_T>
AuthEncImp<ImpSc, AlgAes, ModeGcm>::getTagSizes()
{
    std::set<SIZE_T> res;

    for( int i=12; i<=16; i ++ )
    {
        res.insert( i );
    }

    return res;
}

template<>
NTSTATUS
AuthEncImp<ImpSc, AlgAes, ModeGcm>::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 16 || cbKey == 24 || cbKey == 32, "?" );

    initXmmRegisters();
    SymCryptGcmExpandKey( &state.key, SymCryptAesBlockCipher, pbKey, cbKey );
    verifyXmmRegisters();

    state.inComputation = FALSE;
    return STATUS_SUCCESS;
}

template<>
VOID
AuthEncImp<ImpSc, AlgAes, ModeGcm>::setTotalCbData( SIZE_T cbData )
{
    state.totalCbData = cbData;
}

template<>
NTSTATUS
AuthEncImp<ImpSc, AlgAes, ModeGcm>::encrypt(
        _In_reads_( cbNonce )       PCBYTE  pbNonce,
                                    SIZE_T  cbNonce,
        _In_reads_( cbAuthData )    PCBYTE  pbAuthData,
                                    SIZE_T  cbAuthData,
        _In_reads_( cbData )        PCBYTE  pbSrc,
        _Out_writes_( cbData )      PBYTE   pbDst,
                                    SIZE_T  cbData,
        _Out_writes_( cbTag )       PBYTE   pbTag,
                                    SIZE_T  cbTag,
                                    ULONG   flags )
{
    NTSTATUS status = STATUS_SUCCESS;

    CHECK( (flags & ~AUTHENC_FLAG_PARTIAL) == 0, "Unknown flag" );

    if( (flags & AUTHENC_FLAG_PARTIAL) == 0 )
    {
        // simple straight CCM computation.
        initXmmRegisters();
        CHECK( SymCryptGcmValidateParameters(   SymCryptAesBlockCipher,
            cbNonce,
            cbAuthData,
            cbData,
            cbTag ) == SYMCRYPT_NO_ERROR, "?" );
        verifyXmmRegisters();

        SymCryptGcmEncrypt( &state.key,
            pbNonce, cbNonce, pbAuthData, cbAuthData,
            pbSrc, pbDst, cbData,
            pbTag, cbTag );
        verifyXmmRegisters();

        // Done
        goto cleanup;
    }

    // We can process the next part before we decide whether to produce the tag.
    SYMCRYPT_GCM_EXPANDED_KEY gcmKey2;
    SYMCRYPT_GCM_STATE gcmState1;

    SymCryptGcmKeyCopy( &state.key, &gcmKey2 );

    if( !state.inComputation )
    {
        CHECK( (flags & AUTHENC_FLAG_PARTIAL) != 0, "?" );
        // total cbData is passed in the cbTag parameter in the first partial call
        initXmmRegisters();
        SymCryptGcmInit( &gcmState1, (g_rng.byte() & 1) ? &state.key : &gcmKey2, pbNonce, cbNonce );
        verifyXmmRegisters();

        SIZE_T bytesDone = 0;
        while( bytesDone != cbAuthData )
        {
            SIZE_T bytesThisLoop = g_rng.sizet( cbAuthData - bytesDone + 1);
            initXmmRegisters();
            SymCryptGcmAuthPart( &gcmState1, &pbAuthData[bytesDone], bytesThisLoop );
            verifyXmmRegisters();
            bytesDone += bytesThisLoop;
        }

        state.inComputation = TRUE;
    } else {
        initXmmRegisters();
        SymCryptGcmStateCopy( &state.gcmState, (g_rng.byte() & 1) ? &gcmKey2 : NULL , &gcmState1 );
        verifyXmmRegisters();
    }
    // Using gcmState1 which is using gcmKey2 or state.key.

    initXmmRegisters();
    SymCryptGcmEncryptPart( &gcmState1, pbSrc, pbDst, cbData );
    verifyXmmRegisters();

    if( pbTag != NULL )
    {
        initXmmRegisters();
        SymCryptGcmEncryptFinal( &gcmState1, pbTag, cbTag );
        verifyXmmRegisters();

        state.inComputation = FALSE;
    } else {
        // Copy the state back into the object
        SymCryptGcmStateCopy( &gcmState1, &state.key, &state.gcmState );
    }


cleanup:
    return status;
}

template<>
NTSTATUS
AuthEncImp<ImpSc, AlgAes, ModeGcm>::decrypt(
        _In_reads_( cbNonce )       PCBYTE  pbNonce,
                                    SIZE_T  cbNonce,
        _In_reads_( cbAuthData )    PCBYTE  pbAuthData,
                                    SIZE_T  cbAuthData,
        _In_reads_( cbData )        PCBYTE  pbSrc,
        _Out_writes_( cbData )      PBYTE   pbDst,
                                    SIZE_T  cbData,
        _In_reads_( cbTag )         PCBYTE  pbTag,
                                    SIZE_T  cbTag,
                                    ULONG   flags )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    CHECK( (flags & ~AUTHENC_FLAG_PARTIAL) == 0, "Unknown flag" );

    if( (flags & AUTHENC_FLAG_PARTIAL) == 0 )
    {
        // simple straight CCM computation.
        initXmmRegisters();
        CHECK( SymCryptGcmValidateParameters(   SymCryptAesBlockCipher,
            cbNonce,
            cbAuthData,
            cbData,
            cbTag ) == SYMCRYPT_NO_ERROR, "?" );
        verifyXmmRegisters();

        scError = SymCryptGcmDecrypt( &state.key,
            pbNonce, cbNonce, pbAuthData, cbAuthData,
            pbSrc, pbDst, cbData,
            pbTag, cbTag );
        verifyXmmRegisters();

        // Done
        goto cleanup;
    }

    // We can process the next part before we decide whether to produce the tag.
    SYMCRYPT_GCM_EXPANDED_KEY gcmKey2;
    SYMCRYPT_GCM_STATE gcmState1;

    SymCryptGcmKeyCopy( &state.key, &gcmKey2 );

    if( !state.inComputation )
    {
        CHECK( (flags & AUTHENC_FLAG_PARTIAL) != 0, "?" );
        // total cbData is passed in the cbTag parameter in the first partial call
        initXmmRegisters();
        SymCryptGcmInit( &gcmState1, (g_rng.byte() & 1) ? &state.key : &gcmKey2, pbNonce, cbNonce );
        verifyXmmRegisters();

        SIZE_T bytesDone = 0;
        while( bytesDone != cbAuthData )
        {
            SIZE_T bytesThisLoop = g_rng.sizet( cbAuthData - bytesDone + 1);
            initXmmRegisters();
            SymCryptGcmAuthPart( &gcmState1, &pbAuthData[bytesDone], bytesThisLoop );
            verifyXmmRegisters();
            bytesDone += bytesThisLoop;
        }

        state.inComputation = TRUE;
    } else {
        initXmmRegisters();
        SymCryptGcmStateCopy( &state.gcmState, (g_rng.byte() & 1) ? &gcmKey2 : NULL , &gcmState1 );
        verifyXmmRegisters();
    }
    // Using gcmState1 which is using gcmKey2 or state.key.

    initXmmRegisters();
    SymCryptGcmDecryptPart( &gcmState1, pbSrc, pbDst, cbData );
    verifyXmmRegisters();

    if( pbTag != NULL )
    {
        initXmmRegisters();
        scError = SymCryptGcmDecryptFinal( &gcmState1, pbTag, cbTag );
        verifyXmmRegisters();

        state.inComputation = FALSE;
    } else {
        // Copy the state back into the object
        SymCryptGcmStateCopy( &gcmState1, &state.key, &state.gcmState );
    }

cleanup:
    return scError == SYMCRYPT_NO_ERROR ? 0 : STATUS_AUTH_TAG_MISMATCH;
}


//////////////////////////
// CHACHA20POLY1305

//template<>
//VOID
//algImpKeyPerfFunction< ImpSc, AlgChaCha20Poly1305, ModeNone>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
//{
//    UNREFERENCED_PARAMETER( buf1 );
//    UNREFERENCED_PARAMETER( buf2 );
//    UNREFERENCED_PARAMETER( buf3 );
//    UNREFERENCED_PARAMETER( KeySize );
//}

template<>
VOID
algImpDataPerfFunction<ImpSc, AlgChaCha20Poly1305, ModeNone>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SymCryptChaCha20Poly1305Encrypt( buf1, 32,
                                     buf2, 12,
                                     NULL, 0,
                                     buf2 + 16, buf2 + 16, dataSize,
                                     buf3, 16 );
}

template<>
VOID
algImpDecryptPerfFunction<ImpSc, AlgChaCha20Poly1305, ModeNone>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SymCryptChaCha20Poly1305Decrypt( buf1, 32,
                                     buf2, 12,
                                     NULL, 0,
                                     buf2 + 16, buf2 + 16, dataSize,
                                     buf3, 16 );
}

//template<>
//VOID
//algImpCleanPerfFunction<ImpSc, AlgChaCha20Poly1305, ModeNone>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
//{
//    UNREFERENCED_PARAMETER( buf1 );
//    UNREFERENCED_PARAMETER( buf2 );
//    UNREFERENCED_PARAMETER( buf3 );
//}

template<>
AuthEncImp<ImpSc, AlgChaCha20Poly1305, ModeNone>::AuthEncImp()
{
    m_perfKeyFunction     = NULL;
    m_perfCleanFunction   = NULL;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpSc, AlgChaCha20Poly1305, ModeNone>;
    m_perfDecryptFunction = &algImpDecryptPerfFunction<ImpSc, AlgChaCha20Poly1305, ModeNone>;
}

template<>
AuthEncImp<ImpSc, AlgChaCha20Poly1305, ModeNone>::~AuthEncImp()
{
    SymCryptWipeKnownSize( state.key, sizeof( state.key ) );
}

template<>
std::set<SIZE_T>
AuthEncImp<ImpSc, AlgChaCha20Poly1305, ModeNone>::getKeySizes()
{
    std::set<SIZE_T> res;

    res.insert( 32 );

    return res;
}


template<>
std::set<SIZE_T>
AuthEncImp<ImpSc, AlgChaCha20Poly1305, ModeNone>::getNonceSizes()
{
    std::set<SIZE_T> res;

    res.insert( 12 );

    return res;
}


template<>
std::set<SIZE_T>
AuthEncImp<ImpSc, AlgChaCha20Poly1305, ModeNone>::getTagSizes()
{
    std::set<SIZE_T> res;

    res.insert( 16 );

    return res;
}

template<>
NTSTATUS
AuthEncImp<ImpSc, AlgChaCha20Poly1305, ModeNone>::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 32, "?" );
    memcpy( state.key, pbKey, cbKey );

    return STATUS_SUCCESS;
}

template<>
VOID
AuthEncImp<ImpSc, AlgChaCha20Poly1305, ModeNone>::setTotalCbData( SIZE_T cbData )
{
    UNREFERENCED_PARAMETER( cbData );
}

template<>
NTSTATUS
AuthEncImp<ImpSc, AlgChaCha20Poly1305, ModeNone>::encrypt(
        _In_reads_( cbNonce )                     PCBYTE  pbNonce,
                                                  SIZE_T  cbNonce,
        _In_reads_( cbAuthData )                  PCBYTE  pbAuthData,
                                                  SIZE_T  cbAuthData,
        _In_reads_( cbData )                      PCBYTE  pbSrc,
        _Out_writes_( cbData )                    PBYTE   pbDst,
                                                  SIZE_T  cbData,
        _Out_writes_( cbTag )                     PBYTE   pbTag,
                                                  SIZE_T  cbTag,
                                                  ULONG   flags )
{
    UNREFERENCED_PARAMETER( flags );

    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    scError = SymCryptChaCha20Poly1305Encrypt( state.key, sizeof( state.key ),
                                               pbNonce, cbNonce, pbAuthData, cbAuthData,
                                               pbSrc, pbDst, cbData,
                                               pbTag, cbTag );

    return scError == SYMCRYPT_NO_ERROR ? 0 : STATUS_ENCRYPTION_FAILED;
}

template<>
NTSTATUS
AuthEncImp<ImpSc, AlgChaCha20Poly1305, ModeNone>::decrypt(
        _In_reads_( cbNonce )                     PCBYTE  pbNonce,
                                                  SIZE_T  cbNonce,
        _In_reads_( cbAuthData )                  PCBYTE  pbAuthData,
                                                  SIZE_T  cbAuthData,
        _In_reads_( cbData )                      PCBYTE  pbSrc,
        _Out_writes_( cbData )                    PBYTE   pbDst,
                                                  SIZE_T  cbData,
        _In_reads_( cbTag )                       PCBYTE  pbTag,
                                                  SIZE_T  cbTag,
                                                  ULONG   flags )
{
    UNREFERENCED_PARAMETER( flags );

    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    scError = SymCryptChaCha20Poly1305Decrypt( state.key, sizeof( state.key ),
                                               pbNonce, cbNonce, pbAuthData, cbAuthData,
                                               pbSrc, pbDst, cbData,
                                               pbTag, cbTag );

    return scError == SYMCRYPT_NO_ERROR ? 0 : STATUS_AUTH_TAG_MISMATCH;
}


//////////////////////////
// RC4


template<>
VOID
algImpKeyPerfFunction< ImpSc, AlgRc4>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptRc4Init( (PSYMCRYPT_RC4_STATE) buf1, buf2, keySize );
}

template<>
VOID
algImpDataPerfFunction<ImpSc,AlgRc4>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SymCryptRc4Crypt( (PSYMCRYPT_RC4_STATE) buf1, buf2, buf3, dataSize );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgRc4>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptWipeKnownSize( buf1, sizeof( PSYMCRYPT_RC4_STATE ) );
}

template<>
StreamCipherImp<ImpSc, AlgRc4>::StreamCipherImp()
{
    m_perfKeyFunction     = &algImpKeyPerfFunction    <ImpSc, AlgRc4>;
    m_perfCleanFunction   = &algImpCleanPerfFunction  <ImpSc, AlgRc4>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpSc, AlgRc4>;
}

template<>
StreamCipherImp<ImpSc, AlgRc4>::~StreamCipherImp()
{
    SymCryptWipeKnownSize( &state.state, sizeof( state.state ) );
}

template<>
std::set<SIZE_T> StreamCipherImp<ImpSc, AlgRc4>::getNonceSizes()
{
    std::set<SIZE_T> res;

    // No nonce sizes supported for RC4

    return res;
}

template<>
std::set<SIZE_T> StreamCipherImp<ImpSc, AlgRc4>::getKeySizes()
{
    std::set<SIZE_T> res;
    SIZE_T maxKeySize = 256;

    for( SIZE_T i=1; i<=maxKeySize; i++ )
    {
        res.insert( i );
    }

    return res;
}

template<>
NTSTATUS
StreamCipherImp<ImpSc, AlgRc4>::setNonce( PCBYTE pbNonce, SIZE_T cbNonce )
{
    UNREFERENCED_PARAMETER( pbNonce );

    CHECK( cbNonce == 0, "RC4 does not take a nonce" );

    return STATUS_SUCCESS;
}

template<>
VOID
StreamCipherImp< ImpSc, AlgRc4>::setOffset( UINT64 offset )
{
    UNREFERENCED_PARAMETER( offset );
    CHECK( FALSE, "RC4 is not random access" );
}

template<>
NTSTATUS
StreamCipherImp<ImpSc, AlgRc4>::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey > 0 && cbKey <= 256, "?" );
    CHECK( SymCryptRc4Init( &state.state, pbKey, cbKey ) == SYMCRYPT_NO_ERROR, "??" );
    return STATUS_SUCCESS;
}

template<>
VOID
StreamCipherImp<ImpSc, AlgRc4>::encrypt( PCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData )
{

    SymCryptRc4Crypt( &state.state, pbSrc, pbDst, cbData );
}


//////////////////////////
// CHACHA20

template<>
VOID
algImpKeyPerfFunction< ImpSc, AlgChaCha20>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( keySize );

    SymCryptChaCha20Init( (PSYMCRYPT_CHACHA20_STATE) buf1, buf2, 32, buf3, 12, 0 );
}

template<>
VOID
algImpDataPerfFunction<ImpSc,AlgChaCha20>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SymCryptChaCha20Crypt( (PSYMCRYPT_CHACHA20_STATE) buf1, buf2, buf3, dataSize );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgChaCha20>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptWipeKnownSize( buf1, sizeof( PSYMCRYPT_CHACHA20_STATE ) );
}

template<>
StreamCipherImp<ImpSc, AlgChaCha20>::StreamCipherImp()
{
    m_perfKeyFunction     = &algImpKeyPerfFunction    <ImpSc, AlgChaCha20>;
    m_perfCleanFunction   = &algImpCleanPerfFunction  <ImpSc, AlgChaCha20>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpSc, AlgChaCha20>;
}

template<>
StreamCipherImp<ImpSc, AlgChaCha20>::~StreamCipherImp()
{
    SymCryptWipeKnownSize( &state.state, sizeof( state.state ) );
}

template<>
std::set<SIZE_T> StreamCipherImp<ImpSc, AlgChaCha20>::getNonceSizes()
{
    std::set<SIZE_T> res;

    res.insert( 12 );

    return res;
}

template<>
std::set<SIZE_T> StreamCipherImp<ImpSc, AlgChaCha20>::getKeySizes()
{
    std::set<SIZE_T> res;

    res.insert( 32 );

    return res;
}

template<>
NTSTATUS
StreamCipherImp<ImpSc, AlgChaCha20>::setNonce( PCBYTE pbNonce, SIZE_T cbNonce )
{
    CHECK( cbNonce == 12, "ChaCha20 takes a 12-byte nonce" );

    memcpy( state.nonce, pbNonce, cbNonce );
    state.offset = 0;

    CHECK( SymCryptChaCha20Init( &state.state, state.key, 32, state.nonce, 12, state.offset ) == SYMCRYPT_NO_ERROR,
        "ChaCha20 init error" );

    return STATUS_SUCCESS;
}

template<>
VOID
StreamCipherImp< ImpSc, AlgChaCha20>::setOffset( UINT64 offset )
{
    state.offset = offset;

    SymCryptChaCha20SetOffset( &state.state, offset );
}

template<>
NTSTATUS
StreamCipherImp<ImpSc, AlgChaCha20>::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 32, "ChaCha20 takes a 32-byte key" );

    memcpy( state.key, pbKey, cbKey );
    SymCryptWipe( state.nonce, sizeof( state.nonce ) );
    state.offset = 0;

    CHECK( SymCryptChaCha20Init( &state.state, state.key, 32, state.nonce, 12, state.offset ) == SYMCRYPT_NO_ERROR,
        "ChaCha20 init error" );
    return STATUS_SUCCESS;
}

template<>
VOID
StreamCipherImp<ImpSc, AlgChaCha20>::encrypt( PCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData )
{

    SymCryptChaCha20Crypt( &state.state, pbSrc, pbDst, cbData );
}

///////////////////////////////////////////////////////
// Poly1305

/*
template<>
VOID
algImpKeyPerfFunction< ImpSc, AlgPoly1305>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    // No per-key operations for Poly1305
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgPoly1305>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

*/

template<>
VOID
algImpDataPerfFunction<ImpSc,AlgPoly1305>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SymCryptPoly1305( buf1, buf2, dataSize, buf3 );
}

template<>
MacImp<ImpSc, AlgPoly1305>::MacImp()
{
    m_perfKeyFunction     = NULL;   // &algImpKeyPerfFunction    <ImpSc, AlgPoly1305>;
    m_perfCleanFunction   = NULL;   //&algImpCleanPerfFunction  <ImpSc, AlgPoly1305>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpSc, AlgPoly1305>;
}

template<>
MacImp<ImpSc, AlgPoly1305>::~MacImp<ImpSc, AlgPoly1305>()
{
}

template<>
NTSTATUS MacImp<ImpSc, AlgPoly1305>::mac(
    _In_reads_( cbKey )      PCBYTE pbKey,   SIZE_T cbKey,
    _In_reads_( cbData )     PCBYTE pbData,  SIZE_T cbData,
    _Out_writes_( cbResult )  PBYTE pbResult, SIZE_T cbResult )
{
    CHECK( cbKey == 32, "?" );
    CHECK( cbResult == 16, "?" );

    SymCryptPoly1305( pbKey, pbData, cbData, pbResult );

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
MacImp<ImpSc, AlgPoly1305>::init( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 32, "?" );
    SymCryptPoly1305Init( &state.state, pbKey );

    return STATUS_SUCCESS;
}

template<>
VOID MacImp<ImpSc, AlgPoly1305>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    SymCryptPoly1305Append( &state.state, pbData, cbData );
}

template<>
VOID MacImp<ImpSc, AlgPoly1305>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    CHECK( cbResult == 16, "Result len error SC/Poly1305" );
    SymCryptPoly1305Result( &state.state, pbResult );
}

template<>
SIZE_T MacImp<ImpSc, AlgPoly1305>::inputBlockLen()
{
    return SYMCRYPT_POLY1305_RESULT_SIZE;
}

template<>
SIZE_T MacImp<ImpSc, AlgPoly1305>::resultLen()
{
    return SYMCRYPT_POLY1305_RESULT_SIZE;
}



///////////////////////////////////////////////////////
// AES-CTR_DRBG
//


template<>
VOID
algImpKeyPerfFunction< ImpSc, AlgAesCtrDrbg>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptRngAesInstantiate( (PSYMCRYPT_RNG_AES_STATE) buf1, buf2, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgAesCtrDrbg>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptRngAesUninstantiate( (PSYMCRYPT_RNG_AES_STATE) buf1 );
}

template<>
VOID
algImpDataPerfFunction<ImpSc,AlgAesCtrDrbg>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );

    SymCryptRngAesGenerate( (PSYMCRYPT_RNG_AES_STATE) buf1, buf3, dataSize );
}

template<>
RngSp800_90Imp<ImpSc, AlgAesCtrDrbg>::RngSp800_90Imp()
{
    m_perfKeyFunction     = &algImpKeyPerfFunction    <ImpSc, AlgAesCtrDrbg>;
    m_perfCleanFunction   = &algImpCleanPerfFunction  <ImpSc, AlgAesCtrDrbg>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpSc, AlgAesCtrDrbg>;
}

template<>
RngSp800_90Imp<ImpSc, AlgAesCtrDrbg>::~RngSp800_90Imp()
{
    SymCryptRngAesUninstantiate( &state.state );
}

template<>
NTSTATUS
RngSp800_90Imp<ImpSc, AlgAesCtrDrbg>::instantiate( _In_reads_( cbEntropy ) PCBYTE pbEntropy, SIZE_T cbEntropy )
{
    SYMCRYPT_ERROR scError;

    initXmmRegisters();
    scError = SymCryptRngAesInstantiate( &state.state, pbEntropy, cbEntropy );
    verifyXmmRegisters();

    CHECK( scError == SYMCRYPT_NO_ERROR, "Error during instantiation" );

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
RngSp800_90Imp<ImpSc, AlgAesCtrDrbg>::reseed( _In_reads_( cbEntropy ) PCBYTE pbEntropy, SIZE_T cbEntropy )
{
    SYMCRYPT_ERROR scError;

    initXmmRegisters();
    scError = SymCryptRngAesReseed( &state.state, pbEntropy, cbEntropy );
    verifyXmmRegisters();

    CHECK3( scError == SYMCRYPT_NO_ERROR, "Error during reseed, len=%lld", (ULONGLONG) cbEntropy );

    return STATUS_SUCCESS;
}

template<>
VOID
RngSp800_90Imp<ImpSc, AlgAesCtrDrbg>::generate(  _Out_writes_( cbData ) PBYTE pbData, SIZE_T cbData )
{

    initXmmRegisters();
    SymCryptRngAesGenerate( &state.state, pbData, cbData );
    verifyXmmRegisters();
}




template<>
VOID
algImpKeyPerfFunction< ImpSc, AlgAesCtrF142>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptRngAesFips140_2Instantiate( (PSYMCRYPT_RNG_AES_FIPS140_2_STATE) buf1, buf2, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgAesCtrF142>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptRngAesFips140_2Uninstantiate( (PSYMCRYPT_RNG_AES_FIPS140_2_STATE) buf1 );
}

template<>
VOID
algImpDataPerfFunction<ImpSc,AlgAesCtrF142>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );

    SymCryptRngAesFips140_2Generate( (PSYMCRYPT_RNG_AES_FIPS140_2_STATE) buf1, buf3, dataSize );
}

template<>
RngSp800_90Imp<ImpSc, AlgAesCtrF142>::RngSp800_90Imp()
{
    m_perfKeyFunction     = &algImpKeyPerfFunction    <ImpSc, AlgAesCtrF142>;
    m_perfCleanFunction   = &algImpCleanPerfFunction  <ImpSc, AlgAesCtrF142>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpSc, AlgAesCtrF142>;
}

template<>
RngSp800_90Imp<ImpSc, AlgAesCtrF142>::~RngSp800_90Imp()
{
    SymCryptRngAesFips140_2Uninstantiate( &state.state );
}

template<>
NTSTATUS
RngSp800_90Imp<ImpSc, AlgAesCtrF142>::instantiate( _In_reads_( cbEntropy ) PCBYTE pbEntropy, SIZE_T cbEntropy )
{
    SYMCRYPT_ERROR scError;

    initXmmRegisters();
    scError = SymCryptRngAesFips140_2Instantiate( &state.state, pbEntropy, cbEntropy );
    verifyXmmRegisters();

    CHECK( scError == SYMCRYPT_NO_ERROR, "Error during instantiation" );

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
RngSp800_90Imp<ImpSc, AlgAesCtrF142>::reseed( _In_reads_( cbEntropy ) PCBYTE pbEntropy, SIZE_T cbEntropy )
{
    SYMCRYPT_ERROR scError;

    initXmmRegisters();
    scError = SymCryptRngAesFips140_2Reseed( &state.state, pbEntropy, cbEntropy );
    verifyXmmRegisters();

    CHECK3( scError == SYMCRYPT_NO_ERROR, "Error during reseed, len=%lld", (ULONGLONG) cbEntropy );

    return STATUS_SUCCESS;
}

template<>
VOID
RngSp800_90Imp<ImpSc, AlgAesCtrF142>::generate(  _Out_writes_( cbData ) PBYTE pbData, SIZE_T cbData )
{

    initXmmRegisters();
    SymCryptRngAesFips140_2Generate( &state.state, pbData, cbData );
    verifyXmmRegisters();
}


//=============================================================================
// Parallel hashing
//

#define N_PARALLEL_FOR_PERF 8

template<>
VOID
algImpKeyPerfFunction<ImpSc,AlgParallelSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( dataSize );

    SymCryptParallelSha256Init( (PSYMCRYPT_SHA256_STATE) buf1, N_PARALLEL_FOR_PERF );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgParallelSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpSc,AlgParallelSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    int i;
    PSYMCRYPT_SHA256_STATE pState = (PSYMCRYPT_SHA256_STATE) buf1;
    PSYMCRYPT_PARALLEL_HASH_OPERATION pOperations = (PSYMCRYPT_PARALLEL_HASH_OPERATION) buf2;
    PSYMCRYPT_PARALLEL_HASH_OPERATION pOp = pOperations;

    PBYTE pSrc = buf3;
    PBYTE pDst = buf3 + PERF_BUFFER_SIZE / 2;

    for( i=0; i<N_PARALLEL_FOR_PERF; i++ )
    {
        pOp->iHash = i;
        pOp->hashOperation = SYMCRYPT_HASH_OPERATION_APPEND;
        pOp->pbBuffer = pSrc;
        pOp->cbBuffer = dataSize / N_PARALLEL_FOR_PERF;

        pOp++;
        pSrc += dataSize / N_PARALLEL_FOR_PERF;

        pOp->iHash = i;
        pOp->hashOperation = SYMCRYPT_HASH_OPERATION_RESULT;
        pOp->pbBuffer = pDst;
        pOp->cbBuffer = 32;

        pOp++;
        pDst += 32;
    }
    SymCryptParallelSha256Process( pState, N_PARALLEL_FOR_PERF, pOperations, 2*N_PARALLEL_FOR_PERF, buf1 + PERF_BUFFER_SIZE / 2, PERF_BUFFER_SIZE / 2 );
}

template<>
ParallelHashImp<ImpSc, AlgParallelSha256>::ParallelHashImp()
{
    m_perfDataFunction = &algImpDataPerfFunction <ImpSc, AlgParallelSha256>;
    m_perfKeyFunction  = &algImpKeyPerfFunction  <ImpSc, AlgParallelSha256>;
    m_perfCleanFunction= &algImpCleanPerfFunction<ImpSc, AlgParallelSha256>;

    state.nHashes = 0;
};

template<>
ParallelHashImp<ImpSc, AlgParallelSha256>::~ParallelHashImp() {};

template<>
PCSYMCRYPT_HASH
ParallelHashImp<ImpSc, AlgParallelSha256>::SymCryptHash()
{
    return SymCryptSha256Algorithm;
}

template<>
SIZE_T ParallelHashImp<ImpSc, AlgParallelSha256>::resultLen()
{
    return SYMCRYPT_SHA256_RESULT_SIZE;
}

template<>
SIZE_T ParallelHashImp<ImpSc, AlgParallelSha256>::inputBlockLen()
{
    return SYMCRYPT_SHA256_INPUT_BLOCK_SIZE;
}


template<>
VOID
ParallelHashImp<ImpSc, AlgParallelSha256>::init( SIZE_T nHashes )
{
    CHECK( nHashes <= MAX_PARALLEL_HASH_STATES, "Too many hash states requested" );
    state.nHashes = nHashes;

    initYmmRegisters();
    SymCryptParallelSha256Init( &state.sc[0], nHashes );
    verifyYmmRegisters();
}

template<>
VOID
ParallelHashImp<ImpSc, AlgParallelSha256>::process(
        _In_reads_( nOperations )   BCRYPT_MULTI_HASH_OPERATION *   pOperations,
                                    SIZE_T                          nOperations )
{
    SYMCRYPT_PARALLEL_HASH_OPERATION    op[MAX_PARALLEL_HASH_OPERATIONS];
    BYTE                                scratch[SYMCRYPT_PARALLEL_SHA256_FIXED_SCRATCH + SYMCRYPT_PARALLEL_HASH_PER_STATE_SCRATCH * MAX_PARALLEL_HASH_STATES + 128];

    CHECK( nOperations <= MAX_PARALLEL_HASH_OPERATIONS, "Too many operations" );

    for( SIZE_T i=0; i<nOperations; i++ )
    {
        op[i].iHash = pOperations[i].iHash;
        op[i].hashOperation = pOperations[i].hashOperation == BCRYPT_HASH_OPERATION_HASH_DATA ? SYMCRYPT_HASH_OPERATION_APPEND : SYMCRYPT_HASH_OPERATION_RESULT;
        op[i].pbBuffer = pOperations[i].pbBuffer;
        op[i].cbBuffer = pOperations[i].cbBuffer;

        CHECK( op[i].iHash < state.nHashes, "?" );
    }

    SIZE_T scratchOffset = g_rng.sizet( 64 );
    BYTE sentinel = g_rng.byte();
    SIZE_T nScratch = SYMCRYPT_PARALLEL_SHA256_FIXED_SCRATCH + state.nHashes * SYMCRYPT_PARALLEL_HASH_PER_STATE_SCRATCH;
    CHECK( nScratch + scratchOffset <= sizeof( scratch ), "?" );
    _Analysis_assume_( nScratch + scratchOffset < sizeof( scratch ) );

    scratch[scratchOffset + nScratch] = sentinel;

    _Analysis_assume_( state.nHashes <= MAX_PARALLEL_HASH_STATES );
    initYmmRegisters();
    SymCryptParallelSha256Process( &state.sc[0],
                                    state.nHashes,
                                    &op[0],
                                    nOperations,
                                    &scratch[scratchOffset],
                                    nScratch );
    verifyYmmRegisters();
    CHECK( scratch[scratchOffset + nScratch] == sentinel, "Parallel SHA256 used too much scratch space" );
}

template<>
NTSTATUS
ParallelHashImp<ImpSc, AlgParallelSha256>::initWithLongMessage( ULONGLONG nBytes )
{
    CHECK( nBytes % 64 == 0, "Odd bytes in initWithLongMessage" );
    CHECK( state.nHashes <= MAX_PARALLEL_HASH_STATES, "?" );

    for( SIZE_T i=0; i<state.nHashes; i++ )
    {
        memset( &state.sc[i].chain, 'b', sizeof( state.sc[i].chain ) );
        state.sc[i].dataLengthL = nBytes;
        state.sc[i].dataLengthH = 0;
        state.sc[i].bytesInBuffer = 0;
    }

    return STATUS_SUCCESS;
}


template<>
VOID
algImpKeyPerfFunction<ImpSc,AlgParallelSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( dataSize );

    SymCryptParallelSha384Init( (PSYMCRYPT_SHA384_STATE) buf1, N_PARALLEL_FOR_PERF );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgParallelSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpSc,AlgParallelSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    int i;
    PSYMCRYPT_SHA384_STATE pState = (PSYMCRYPT_SHA384_STATE) buf1;
    PSYMCRYPT_PARALLEL_HASH_OPERATION pOperations = (PSYMCRYPT_PARALLEL_HASH_OPERATION) buf2;
    PSYMCRYPT_PARALLEL_HASH_OPERATION pOp = pOperations;

    PBYTE pSrc = buf3;
    PBYTE pDst = buf3 + PERF_BUFFER_SIZE / 2;

    for( i=0; i<N_PARALLEL_FOR_PERF; i++ )
    {
        pOp->iHash = i;
        pOp->hashOperation = SYMCRYPT_HASH_OPERATION_APPEND;
        pOp->pbBuffer = pSrc;
        pOp->cbBuffer = dataSize / N_PARALLEL_FOR_PERF;

        pOp++;
        pSrc += dataSize / N_PARALLEL_FOR_PERF;

        pOp->iHash = i;
        pOp->hashOperation = SYMCRYPT_HASH_OPERATION_RESULT;
        pOp->pbBuffer = pDst;
        pOp->cbBuffer = 48;

        pOp++;
        pDst += 48;
    }
    SymCryptParallelSha384Process( pState, N_PARALLEL_FOR_PERF, pOperations, 2*N_PARALLEL_FOR_PERF, buf1 + PERF_BUFFER_SIZE / 2, PERF_BUFFER_SIZE / 2 );
}

template<>
ParallelHashImp<ImpSc, AlgParallelSha384>::ParallelHashImp()
{
    m_perfDataFunction = &algImpDataPerfFunction <ImpSc, AlgParallelSha384>;
    m_perfKeyFunction  = &algImpKeyPerfFunction  <ImpSc, AlgParallelSha384>;
    m_perfCleanFunction= &algImpCleanPerfFunction<ImpSc, AlgParallelSha384>;

    state.nHashes = 0;
};

template<>
ParallelHashImp<ImpSc, AlgParallelSha384>::~ParallelHashImp() {};

template<>
PCSYMCRYPT_HASH
ParallelHashImp<ImpSc, AlgParallelSha384>::SymCryptHash()
{
    return SymCryptSha384Algorithm;
}

template<>
SIZE_T ParallelHashImp<ImpSc, AlgParallelSha384>::resultLen()
{
    return SYMCRYPT_SHA384_RESULT_SIZE;
}

template<>
SIZE_T ParallelHashImp<ImpSc, AlgParallelSha384>::inputBlockLen()
{
    return SYMCRYPT_SHA384_INPUT_BLOCK_SIZE;
}


template<>
VOID
ParallelHashImp<ImpSc, AlgParallelSha384>::init( SIZE_T nHashes )
{
    CHECK( nHashes <= MAX_PARALLEL_HASH_STATES, "Too many hash states requested" );
    state.nHashes = nHashes;
    initYmmRegisters();
    SymCryptParallelSha384Init( &state.sc[0], nHashes );
    verifyYmmRegisters();
}

template<>
VOID
ParallelHashImp<ImpSc, AlgParallelSha384>::process(
        _In_reads_( nOperations )   BCRYPT_MULTI_HASH_OPERATION *   pOperations,
                                    SIZE_T                          nOperations )
{
    SYMCRYPT_PARALLEL_HASH_OPERATION    op[MAX_PARALLEL_HASH_OPERATIONS];
    BYTE                                scratch[SYMCRYPT_PARALLEL_SHA384_FIXED_SCRATCH + SYMCRYPT_PARALLEL_HASH_PER_STATE_SCRATCH * MAX_PARALLEL_HASH_STATES + 128];

    CHECK( nOperations <= MAX_PARALLEL_HASH_OPERATIONS, "Too many operations" );

    for( SIZE_T i=0; i<nOperations; i++ )
    {
        op[i].iHash = pOperations[i].iHash;
        op[i].hashOperation = pOperations[i].hashOperation == BCRYPT_HASH_OPERATION_HASH_DATA ? SYMCRYPT_HASH_OPERATION_APPEND : SYMCRYPT_HASH_OPERATION_RESULT;
        op[i].pbBuffer = pOperations[i].pbBuffer;
        op[i].cbBuffer = pOperations[i].cbBuffer;

        CHECK( op[i].iHash < state.nHashes, "?" );
    }

    SIZE_T scratchOffset = g_rng.sizet( 64 );
    BYTE sentinel = g_rng.byte();
    SIZE_T nScratch = SYMCRYPT_PARALLEL_SHA384_FIXED_SCRATCH + state.nHashes * SYMCRYPT_PARALLEL_HASH_PER_STATE_SCRATCH;
    CHECK( nScratch + scratchOffset <= sizeof( scratch ), "?" );
    _Analysis_assume_( nScratch + scratchOffset < sizeof( scratch ) );

    scratch[scratchOffset + nScratch] = sentinel;

    _Analysis_assume_( state.nHashes <= MAX_PARALLEL_HASH_STATES );
    initYmmRegisters();
    SymCryptParallelSha384Process( &state.sc[0],
                                    state.nHashes,
                                    &op[0],
                                    nOperations,
                                    &scratch[scratchOffset],
                                    nScratch );
    verifyYmmRegisters();
    CHECK( scratch[scratchOffset + nScratch] == sentinel, "Parallel SHA384 used too much scratch space" );
}

template<>
NTSTATUS
ParallelHashImp<ImpSc, AlgParallelSha384>::initWithLongMessage( ULONGLONG nBytes )
{
    CHECK( nBytes % 128 == 0, "Odd bytes in initWithLongMessage" );
    CHECK( state.nHashes <= MAX_PARALLEL_HASH_STATES, "?" );

    for( SIZE_T i=0; i<state.nHashes; i++ )
    {
        memset( &state.sc[i].chain, 'b', sizeof( state.sc[i].chain ) );
        state.sc[i].dataLengthL = nBytes;
        state.sc[i].dataLengthH = 0;
        state.sc[i].bytesInBuffer = 0;
    }

    return STATUS_SUCCESS;
}


template<>
VOID
algImpKeyPerfFunction<ImpSc,AlgParallelSha512>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( dataSize );

    SymCryptParallelSha512Init( (PSYMCRYPT_SHA512_STATE) buf1, N_PARALLEL_FOR_PERF );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgParallelSha512>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpSc,AlgParallelSha512>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    int i;
    PSYMCRYPT_SHA512_STATE pState = (PSYMCRYPT_SHA512_STATE) buf1;
    PSYMCRYPT_PARALLEL_HASH_OPERATION pOperations = (PSYMCRYPT_PARALLEL_HASH_OPERATION) buf2;
    PSYMCRYPT_PARALLEL_HASH_OPERATION pOp = pOperations;

    PBYTE pSrc = buf3;
    PBYTE pDst = buf3 + PERF_BUFFER_SIZE / 2;

    for( i=0; i<N_PARALLEL_FOR_PERF; i++ )
    {
        pOp->iHash = i;
        pOp->hashOperation = SYMCRYPT_HASH_OPERATION_APPEND;
        pOp->pbBuffer = pSrc;
        pOp->cbBuffer = dataSize / N_PARALLEL_FOR_PERF;

        pOp++;
        pSrc += dataSize / N_PARALLEL_FOR_PERF;

        pOp->iHash = i;
        pOp->hashOperation = SYMCRYPT_HASH_OPERATION_RESULT;
        pOp->pbBuffer = pDst;
        pOp->cbBuffer = 64;

        pOp++;
        pDst += 64;
    }
    SymCryptParallelSha512Process( pState, N_PARALLEL_FOR_PERF, pOperations, 2*N_PARALLEL_FOR_PERF, buf1 + PERF_BUFFER_SIZE / 2, PERF_BUFFER_SIZE / 2 );
}

template<>
ParallelHashImp<ImpSc, AlgParallelSha512>::ParallelHashImp()
{
    m_perfDataFunction = &algImpDataPerfFunction <ImpSc, AlgParallelSha512>;
    m_perfKeyFunction  = &algImpKeyPerfFunction  <ImpSc, AlgParallelSha512>;
    m_perfCleanFunction= &algImpCleanPerfFunction<ImpSc, AlgParallelSha512>;

    state.nHashes = 0;
};

template<>
ParallelHashImp<ImpSc, AlgParallelSha512>::~ParallelHashImp() {};

template<>
PCSYMCRYPT_HASH
ParallelHashImp<ImpSc, AlgParallelSha512>::SymCryptHash()
{
    return SymCryptSha512Algorithm;
}

template<>
SIZE_T ParallelHashImp<ImpSc, AlgParallelSha512>::resultLen()
{
    return SYMCRYPT_SHA512_RESULT_SIZE;
}

template<>
SIZE_T ParallelHashImp<ImpSc, AlgParallelSha512>::inputBlockLen()
{
    return SYMCRYPT_SHA512_INPUT_BLOCK_SIZE;
}


template<>
VOID
ParallelHashImp<ImpSc, AlgParallelSha512>::init( SIZE_T nHashes )
{
    CHECK( nHashes <= MAX_PARALLEL_HASH_STATES, "Too many hash states requested" );
    state.nHashes = nHashes;
    initYmmRegisters();
    SymCryptParallelSha512Init( &state.sc[0], nHashes );
    verifyYmmRegisters();
}

template<>
VOID
ParallelHashImp<ImpSc, AlgParallelSha512>::process(
        _In_reads_( nOperations )   BCRYPT_MULTI_HASH_OPERATION *   pOperations,
                                    SIZE_T                          nOperations )
{
    SYMCRYPT_PARALLEL_HASH_OPERATION    op[MAX_PARALLEL_HASH_OPERATIONS];
    BYTE                                scratch[SYMCRYPT_PARALLEL_SHA512_FIXED_SCRATCH + SYMCRYPT_PARALLEL_HASH_PER_STATE_SCRATCH * MAX_PARALLEL_HASH_STATES + 128];

    CHECK( nOperations <= MAX_PARALLEL_HASH_OPERATIONS, "Too many operations" );

    for( SIZE_T i=0; i<nOperations; i++ )
    {
        op[i].iHash = pOperations[i].iHash;
        op[i].hashOperation = pOperations[i].hashOperation == BCRYPT_HASH_OPERATION_HASH_DATA ? SYMCRYPT_HASH_OPERATION_APPEND : SYMCRYPT_HASH_OPERATION_RESULT;
        op[i].pbBuffer = pOperations[i].pbBuffer;
        op[i].cbBuffer = pOperations[i].cbBuffer;

        CHECK( op[i].iHash < state.nHashes, "?" );
    }

    SIZE_T scratchOffset = g_rng.sizet( 64 );
    BYTE sentinel = g_rng.byte();
    SIZE_T nScratch = SYMCRYPT_PARALLEL_SHA512_FIXED_SCRATCH + state.nHashes * SYMCRYPT_PARALLEL_HASH_PER_STATE_SCRATCH;
    CHECK( nScratch + scratchOffset <= sizeof( scratch ), "?" );
    _Analysis_assume_( nScratch + scratchOffset < sizeof( scratch ) );

    scratch[scratchOffset + nScratch] = sentinel;

    _Analysis_assume_( state.nHashes <= MAX_PARALLEL_HASH_STATES );
    initYmmRegisters();
    SymCryptParallelSha512Process( &state.sc[0],
                                    state.nHashes,
                                    &op[0],
                                    nOperations,
                                    &scratch[scratchOffset],
                                    nScratch );
    verifyYmmRegisters();
    CHECK( scratch[scratchOffset + nScratch] == sentinel, "Parallel SHA512 used too much scratch space" );
}

template<>
NTSTATUS
ParallelHashImp<ImpSc, AlgParallelSha512>::initWithLongMessage( ULONGLONG nBytes )
{
    CHECK( nBytes % 128 == 0, "Odd bytes in initWithLongMessage" );
    CHECK( state.nHashes <= MAX_PARALLEL_HASH_STATES, "?" );

    for( SIZE_T i=0; i<state.nHashes; i++ )
    {
        memset( &state.sc[i].chain, 'b', sizeof( state.sc[i].chain ) );
        state.sc[i].dataLengthL = nBytes;
        state.sc[i].dataLengthH = 0;
        state.sc[i].bytesInBuffer = 0;
    }

    return STATUS_SUCCESS;
}



//////////////////////////////////////////////////////////////////////////////////////////////
//  XTS-AES
//

template<>
VOID
algImpKeyPerfFunction< ImpSc, AlgXtsAes>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptXtsAesExpandKey( (SYMCRYPT_XTS_AES_EXPANDED_KEY *) buf1, buf2, keySize );
}

template<>
VOID
algImpDataPerfFunction<ImpSc,AlgXtsAes>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SymCryptXtsAesEncrypt( (SYMCRYPT_XTS_AES_EXPANDED_KEY *) buf1,
                            512,
                            'twek',
                            buf2,
                            buf3,
                            dataSize );
}

template<>
VOID
algImpDecryptPerfFunction<ImpSc,AlgXtsAes>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SymCryptXtsAesDecrypt( (SYMCRYPT_XTS_AES_EXPANDED_KEY *) buf1,
                            512,
                            'twek',
                            buf2,
                            buf3,
                            dataSize );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgXtsAes>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptWipeKnownSize( buf1, sizeof( SYMCRYPT_XTS_AES_EXPANDED_KEY ) );
}


template<>
XtsImp<ImpSc, AlgXtsAes>::XtsImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgXtsAes>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpSc, AlgXtsAes>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgXtsAes>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgXtsAes>;
}

template<>
XtsImp<ImpSc, AlgXtsAes>::~XtsImp()
{
    SymCryptWipeKnownSize( &state.key, sizeof( state.key ) );
}

template<>
NTSTATUS
XtsImp<ImpSc, AlgXtsAes>::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    SYMCRYPT_ERROR scError;

    initXmmRegisters();
    scError = SymCryptXtsAesExpandKey( &state.key, pbKey, cbKey );
    verifyXmmRegisters();

    return scError == SYMCRYPT_NO_ERROR ? 0 : STATUS_NOT_SUPPORTED;
}

template<>
VOID
XtsImp<ImpSc, AlgXtsAes>::encrypt(
                                        SIZE_T      cbDataUnit,
                                        ULONGLONG   tweak,
        _In_reads_( cbData )            PCBYTE      pbSrc,
        _Out_writes_( cbData )          PBYTE       pbDst,
                                        SIZE_T      cbData )
{
    initXmmRegisters();
    SymCryptXtsAesEncrypt( &state.key,
                            cbDataUnit,
                            tweak,
                            pbSrc,
                            pbDst,
                            cbData );
    verifyXmmRegisters();
}

template<>
VOID
XtsImp<ImpSc, AlgXtsAes>::decrypt(
                                        SIZE_T      cbDataUnit,
                                        ULONGLONG   tweak,
        _In_reads_( cbData )            PCBYTE      pbSrc,
        _Out_writes_( cbData )          PBYTE       pbDst,
                                        SIZE_T      cbData )
{
    initXmmRegisters();
    SymCryptXtsAesDecrypt( &state.key,
                            cbDataUnit,
                            tweak,
                            pbSrc,
                            pbDst,
                            cbData );
    verifyXmmRegisters();
}


///////////////////////
//  TlsCbcHmacSha256

template<> VOID algImpKeyPerfFunction<ImpSc, AlgTlsCbcHmacSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize );
template<> VOID algImpCleanPerfFunction<ImpSc, AlgTlsCbcHmacSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3 );
template<> VOID algImpDataPerfFunction<ImpSc, AlgTlsCbcHmacSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize );
template<> VOID algImpDecryptPerfFunction<ImpSc, AlgTlsCbcHmacSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize );

template<>
TlsCbcHmacImp<ImpSc, AlgTlsCbcHmacSha256>::TlsCbcHmacImp()
{
    m_perfKeyFunction       = &algImpKeyPerfFunction    <ImpSc, AlgTlsCbcHmacSha256>;
    m_perfCleanFunction     = &algImpCleanPerfFunction  <ImpSc, AlgTlsCbcHmacSha256>;
    m_perfDataFunction      = &algImpDataPerfFunction   <ImpSc, AlgTlsCbcHmacSha256>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpSc, AlgTlsCbcHmacSha256>;
}

template<>
TlsCbcHmacImp<ImpSc, AlgTlsCbcHmacSha256>::~TlsCbcHmacImp<ImpSc, AlgTlsCbcHmacSha256>()
{
}

template<>
NTSTATUS
TlsCbcHmacImp<ImpSc, AlgTlsCbcHmacSha256>::verify(
    _In_reads_( cbKey )     PCBYTE  pbKey,
                            SIZE_T  cbKey,
    _In_reads_( cbHeader )  PCBYTE  pbHeader,
                            SIZE_T  cbHeader,
    _In_reads_( cbData )    PCBYTE  pbData,
                            SIZE_T  cbData )
{
    SYMCRYPT_HMAC_SHA256_EXPANDED_KEY   key;
    SYMCRYPT_HMAC_SHA256_STATE          state;
    SYMCRYPT_ERROR scError;
    NTSTATUS status;

    SymCryptHmacSha256ExpandKey( &key, pbKey, cbKey );
    SymCryptHmacSha256Init( &state, &key );

    SymCryptHmacSha256Append( &state, pbHeader, cbHeader );
    scError = SymCryptTlsCbcHmacVerify( SymCryptHmacSha256Algorithm, &key, &state, pbData, cbData );

    status = scError == SYMCRYPT_NO_ERROR ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

    return status;
}

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgTlsCbcHmacSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );
    SymCryptHmacSha256ExpandKey( (SYMCRYPT_HMAC_SHA256_EXPANDED_KEY *) buf1, buf2, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgTlsCbcHmacSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    SymCryptWipeKnownSize( buf1, sizeof( SYMCRYPT_HMAC_SHA256_EXPANDED_KEY ) );
}


template<>
VOID
algImpDataPerfFunction<ImpSc, AlgTlsCbcHmacSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_HMAC_SHA256_STATE state;
    UINT32 paddingSize;

    SymCryptHmacSha256Init( &state, (SYMCRYPT_HMAC_SHA256_EXPANDED_KEY *) buf1 );
    SymCryptHmacSha256Append( &state, buf3, 13 );       // typical header is 13 bytes
    SymCryptHmacSha256Append( &state, buf2, dataSize );
    SymCryptHmacSha256Result( &state, &buf2[ dataSize ] );

    paddingSize = 15 - (dataSize & 15);

    memset( &buf2[dataSize + SYMCRYPT_HMAC_SHA256_RESULT_SIZE], (BYTE) paddingSize, paddingSize + 1);
}

template<>
VOID
algImpDecryptPerfFunction<ImpSc, AlgTlsCbcHmacSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_HMAC_SHA256_STATE  state;
    SYMCRYPT_ERROR scError;

    SymCryptHmacSha256Init( &state, (SYMCRYPT_HMAC_SHA256_EXPANDED_KEY *) buf1 );
    SymCryptHmacSha256Append( &state, buf3, 13 );


    scError = SymCryptTlsCbcHmacVerify(
        SymCryptHmacSha256Algorithm,
        (SYMCRYPT_HMAC_SHA256_EXPANDED_KEY *) buf1,
        &state,
        buf2,
        ((dataSize + 16) & ~15) + SYMCRYPT_HMAC_SHA256_RESULT_SIZE);

    SYMCRYPT_HARD_ASSERT( scError == SYMCRYPT_NO_ERROR );
}



///////////////////////
//  TlsCbcHmacSha1

template<> VOID algImpKeyPerfFunction<ImpSc, AlgTlsCbcHmacSha1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize );
template<> VOID algImpCleanPerfFunction<ImpSc, AlgTlsCbcHmacSha1>( PBYTE buf1, PBYTE buf2, PBYTE buf3 );
template<> VOID algImpDataPerfFunction<ImpSc, AlgTlsCbcHmacSha1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize );
template<> VOID algImpDecryptPerfFunction<ImpSc, AlgTlsCbcHmacSha1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize );

template<>
TlsCbcHmacImp<ImpSc, AlgTlsCbcHmacSha1>::TlsCbcHmacImp()
{
    m_perfKeyFunction       = &algImpKeyPerfFunction    <ImpSc, AlgTlsCbcHmacSha1>;
    m_perfCleanFunction     = &algImpCleanPerfFunction  <ImpSc, AlgTlsCbcHmacSha1>;
    m_perfDataFunction      = &algImpDataPerfFunction   <ImpSc, AlgTlsCbcHmacSha1>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpSc, AlgTlsCbcHmacSha1>;
}

template<>
TlsCbcHmacImp<ImpSc, AlgTlsCbcHmacSha1>::~TlsCbcHmacImp<ImpSc, AlgTlsCbcHmacSha1>()
{
}

template<>
NTSTATUS
TlsCbcHmacImp<ImpSc, AlgTlsCbcHmacSha1>::verify(
    _In_reads_( cbKey )     PCBYTE  pbKey,
    SIZE_T  cbKey,
    _In_reads_( cbHeader )  PCBYTE  pbHeader,
    SIZE_T  cbHeader,
    _In_reads_( cbData )    PCBYTE  pbData,
    SIZE_T  cbData )
{
    SYMCRYPT_HMAC_SHA1_EXPANDED_KEY   key;
    SYMCRYPT_HMAC_SHA1_STATE          state;
    SYMCRYPT_ERROR scError;
    NTSTATUS status;

    SymCryptHmacSha1ExpandKey( &key, pbKey, cbKey );
    SymCryptHmacSha1Init( &state, &key );

    SymCryptHmacSha1Append( &state, pbHeader, cbHeader );
    scError = SymCryptTlsCbcHmacVerify( SymCryptHmacSha1Algorithm, &key, &state, pbData, cbData );

    status = scError == SYMCRYPT_NO_ERROR ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

    return status;
}

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgTlsCbcHmacSha1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );
    SymCryptHmacSha1ExpandKey( (SYMCRYPT_HMAC_SHA1_EXPANDED_KEY *) buf1, buf2, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgTlsCbcHmacSha1>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    SymCryptWipeKnownSize( buf1, sizeof( SYMCRYPT_HMAC_SHA1_EXPANDED_KEY ) );
}


template<>
VOID
algImpDataPerfFunction<ImpSc, AlgTlsCbcHmacSha1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_HMAC_SHA1_STATE state;
    UINT32 paddingSize;

    SymCryptHmacSha1Init( &state, (SYMCRYPT_HMAC_SHA1_EXPANDED_KEY *) buf1 );
    SymCryptHmacSha1Append( &state, buf3, 13 );       // typical header is 13 bytes
    SymCryptHmacSha1Append( &state, buf2, dataSize );
    SymCryptHmacSha1Result( &state, &buf2[ dataSize ] );

    paddingSize = 15 - ((dataSize + SYMCRYPT_HMAC_SHA1_RESULT_SIZE) & 15);

    memset( &buf2[dataSize + SYMCRYPT_HMAC_SHA1_RESULT_SIZE], (BYTE) paddingSize, paddingSize + 1);
}

template<>
VOID
algImpDecryptPerfFunction<ImpSc, AlgTlsCbcHmacSha1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_HMAC_SHA1_STATE  state;
    SYMCRYPT_ERROR scError;

    SymCryptHmacSha1Init( &state, (SYMCRYPT_HMAC_SHA1_EXPANDED_KEY *) buf1 );
    SymCryptHmacSha1Append( &state, buf3, 13 );

    scError = SymCryptTlsCbcHmacVerify(
        SymCryptHmacSha1Algorithm,
        (SYMCRYPT_HMAC_SHA1_EXPANDED_KEY *) buf1,
        &state,
        buf2,
        ((dataSize + SYMCRYPT_HMAC_SHA1_RESULT_SIZE + 16) & ~15));

    SYMCRYPT_HARD_ASSERT( scError == SYMCRYPT_NO_ERROR );
}


///////////////////////
//  TlsCbcHmacSha384

template<> VOID algImpKeyPerfFunction<ImpSc, AlgTlsCbcHmacSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize );
template<> VOID algImpCleanPerfFunction<ImpSc, AlgTlsCbcHmacSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3 );
template<> VOID algImpDataPerfFunction<ImpSc, AlgTlsCbcHmacSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize );
template<> VOID algImpDecryptPerfFunction<ImpSc, AlgTlsCbcHmacSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize );

template<>
TlsCbcHmacImp<ImpSc, AlgTlsCbcHmacSha384>::TlsCbcHmacImp()
{
    m_perfKeyFunction       = &algImpKeyPerfFunction    <ImpSc, AlgTlsCbcHmacSha384>;
    m_perfCleanFunction     = &algImpCleanPerfFunction  <ImpSc, AlgTlsCbcHmacSha384>;
    m_perfDataFunction      = &algImpDataPerfFunction   <ImpSc, AlgTlsCbcHmacSha384>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpSc, AlgTlsCbcHmacSha384>;
}

template<>
TlsCbcHmacImp<ImpSc, AlgTlsCbcHmacSha384>::~TlsCbcHmacImp<ImpSc, AlgTlsCbcHmacSha384>()
{
}

template<>
NTSTATUS
TlsCbcHmacImp<ImpSc, AlgTlsCbcHmacSha384>::verify(
    _In_reads_( cbKey )     PCBYTE  pbKey,
    SIZE_T  cbKey,
    _In_reads_( cbHeader )  PCBYTE  pbHeader,
    SIZE_T  cbHeader,
    _In_reads_( cbData )    PCBYTE  pbData,
    SIZE_T  cbData )
{
    SYMCRYPT_HMAC_SHA384_EXPANDED_KEY   key;
    SYMCRYPT_HMAC_SHA384_STATE          state;
    SYMCRYPT_ERROR scError;
    NTSTATUS status;

    SymCryptHmacSha384ExpandKey( &key, pbKey, cbKey );
    SymCryptHmacSha384Init( &state, &key );

    SymCryptHmacSha384Append( &state, pbHeader, cbHeader );
    scError = SymCryptTlsCbcHmacVerify( SymCryptHmacSha384Algorithm, &key, &state, pbData, cbData );

    status = scError == SYMCRYPT_NO_ERROR ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

    return status;
}

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgTlsCbcHmacSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );
    SymCryptHmacSha384ExpandKey( (SYMCRYPT_HMAC_SHA384_EXPANDED_KEY *) buf1, buf2, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgTlsCbcHmacSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    SymCryptWipeKnownSize( buf1, sizeof( SYMCRYPT_HMAC_SHA384_EXPANDED_KEY ) );
}


template<>
VOID
algImpDataPerfFunction<ImpSc, AlgTlsCbcHmacSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_HMAC_SHA384_STATE state;
    UINT32 paddingSize;

    SymCryptHmacSha384Init( &state, (SYMCRYPT_HMAC_SHA384_EXPANDED_KEY *) buf1 );
    SymCryptHmacSha384Append( &state, buf3, 13 );       // typical header is 13 bytes
    SymCryptHmacSha384Append( &state, buf2, dataSize );
    SymCryptHmacSha384Result( &state, &buf2[ dataSize ] );

    paddingSize = 15 - (dataSize & 15);

    memset( &buf2[dataSize + SYMCRYPT_HMAC_SHA384_RESULT_SIZE], (BYTE) paddingSize, paddingSize + 1);
}

template<>
VOID
algImpDecryptPerfFunction<ImpSc, AlgTlsCbcHmacSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_HMAC_SHA384_STATE  state;
    SYMCRYPT_ERROR scError;

    SymCryptHmacSha384Init( &state, (SYMCRYPT_HMAC_SHA384_EXPANDED_KEY *) buf1 );
    SymCryptHmacSha384Append( &state, buf3, 13 );


    scError = SymCryptTlsCbcHmacVerify(
        SymCryptHmacSha384Algorithm,
        (SYMCRYPT_HMAC_SHA384_EXPANDED_KEY *) buf1,
        &state,
        buf2,
        ((dataSize + 16) & ~15) + SYMCRYPT_HMAC_SHA384_RESULT_SIZE);

    SYMCRYPT_HARD_ASSERT( scError == SYMCRYPT_NO_ERROR );
}

/////////////////////////
// Big integer
//


#define SCRATCH_BUF_OFFSET  (1 << 15)
#define SCRATCH_BUF_SIZE    (1 << 15)

VOID
setupPerfInt( PBYTE pb, SIZE_T cb, UINT32 nDigits )
{
    *(PSYMCRYPT_INT *)pb = SymCryptIntCreate( pb + SYMCRYPT_ASYM_ALIGN_VALUE, cb - SYMCRYPT_ASYM_ALIGN_VALUE, nDigits );
}

VOID
setupIntsForPerfFunction( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T inSize, UINT32 outFactor )
{
    BYTE buf[2048];

    CHECK( 2*inSize <= sizeof( buf ), "?" );
    GENRANDOM( buf, (UINT32)(2*inSize) );

    UINT32 nDigitsIn = SymCryptDigitsFromBits( (UINT32) (8 * inSize) );
    UINT32 nDigitsOut = outFactor * nDigitsIn;

    setupPerfInt( buf1, SCRATCH_BUF_OFFSET, nDigitsIn );
    setupPerfInt( buf2, SCRATCH_BUF_OFFSET, nDigitsIn );
    setupPerfInt( buf3, SCRATCH_BUF_OFFSET, nDigitsOut );

    SymCryptIntSetValue( buf, (UINT32) inSize, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, *(PSYMCRYPT_INT *) buf1 );
    SymCryptIntSetValue( buf+inSize, (UINT32) inSize, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, *(PSYMCRYPT_INT *) buf2 );
}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgIntAdd>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    setupIntsForPerfFunction( buf1, buf2, buf3, keySize, 1 );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgIntAdd>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgIntAdd>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    SymCryptIntAddSameSize( *(PSYMCRYPT_INT *) buf1, *(PSYMCRYPT_INT *) buf2, *(PSYMCRYPT_INT *) buf3 );
}


template<>
ArithImp<ImpSc, AlgIntAdd>::ArithImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgIntAdd>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgIntAdd>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgIntAdd>;
}

template<>
ArithImp<ImpSc, AlgIntAdd>::~ArithImp()
{
}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgIntSub>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    setupIntsForPerfFunction( buf1, buf2, buf3, keySize, 1 );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgIntSub>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgIntSub>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    SymCryptIntSubSameSize( *(PSYMCRYPT_INT *) buf1, *(PSYMCRYPT_INT *) buf2, *(PSYMCRYPT_INT *) buf3 );
}


template<>
ArithImp<ImpSc, AlgIntSub>::ArithImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgIntSub>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgIntSub>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgIntSub>;
}

template<>
ArithImp<ImpSc, AlgIntSub>::~ArithImp()
{
}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgIntMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    setupIntsForPerfFunction( buf1, buf2, buf3, keySize, 2 );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgIntMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgIntMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    SymCryptIntMulSameSize( *(PSYMCRYPT_INT *) buf1, *(PSYMCRYPT_INT *) buf2, *(PSYMCRYPT_INT *) buf3, buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );
}


template<>
ArithImp<ImpSc, AlgIntMul>::ArithImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgIntMul>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgIntMul>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgIntMul>;
}

template<>
ArithImp<ImpSc, AlgIntMul>::~ArithImp()
{
}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgIntSquare>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    setupIntsForPerfFunction( buf1, buf2, buf3, keySize, 2 );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgIntSquare>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgIntSquare>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    UNREFERENCED_PARAMETER( buf2 );
    SymCryptIntSquare( *(PSYMCRYPT_INT *) buf1, *(PSYMCRYPT_INT *) buf3, buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );
}


template<>
ArithImp<ImpSc, AlgIntSquare>::ArithImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgIntSquare>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgIntSquare>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgIntSquare>;
}

template<>
ArithImp<ImpSc, AlgIntSquare>::~ArithImp()
{
}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgIntDivMod>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    BYTE buf[4096];

    CHECK3( 3*keySize <= sizeof( buf ), "keySize too big %08x", keySize );
    GENRANDOM( buf, (UINT32)(3*keySize) );

    UINT32 nDigits = SymCryptDigitsFromBits( (UINT32) (8 * keySize) );
    UINT32 numSize = SymCryptSizeofIntFromDigits( 2*nDigits );

    *(PSYMCRYPT_DIVISOR *) buf2 = SymCryptDivisorCreate( buf2 + SYMCRYPT_ASYM_ALIGN_VALUE, PERF_BUFFER_SIZE-SYMCRYPT_ASYM_ALIGN_VALUE, nDigits );
    ((PSYMCRYPT_INT *) buf1)[0] = SymCryptIntCreate( buf1 + SYMCRYPT_ASYM_ALIGN_VALUE, numSize, nDigits * 2 );

    buf[0] |= 0x80;     // Make sure highest bit in divisor is set (using MSByte first for simplicity)
    SymCryptIntSetValue( buf, (UINT32) keySize, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, SymCryptIntFromDivisor( *(PSYMCRYPT_DIVISOR *) buf2 ) );
    SymCryptIntToDivisor( SymCryptIntFromDivisor(*(PSYMCRYPT_DIVISOR *) buf2), *(PSYMCRYPT_DIVISOR *)buf2,  1000, 0, buf3, PERF_BUFFER_SIZE );

    SymCryptIntSetValue( buf+keySize, (UINT32) 2*keySize, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, *(PSYMCRYPT_INT *) buf1 );

    ((PSYMCRYPT_INT *) buf3)[0] = SymCryptIntCreate( buf3 + SYMCRYPT_ASYM_ALIGN_VALUE, numSize, nDigits * 2 );
    ((PSYMCRYPT_INT *) buf3)[1] = SymCryptIntCreate( buf3 + SYMCRYPT_ASYM_ALIGN_VALUE + numSize, numSize, nDigits );
    CHECK( 2*numSize + SYMCRYPT_ASYM_ALIGN_VALUE <= SCRATCH_BUF_OFFSET, "DivMod destinations overlap scratch buffer" );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgIntDivMod>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgIntDivMod>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    UNREFERENCED_PARAMETER( buf2 );
    SymCryptIntDivMod( *(PSYMCRYPT_INT *) buf1, *(PSYMCRYPT_DIVISOR *) buf2,  ((PSYMCRYPT_INT *) buf3)[0],  ((PSYMCRYPT_INT *) buf3)[1],  buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );
}


template<>
ArithImp<ImpSc, AlgIntDivMod>::ArithImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgIntDivMod>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgIntDivMod>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgIntDivMod>;
}

template<>
ArithImp<ImpSc, AlgIntDivMod>::~ArithImp()
{
}

//
// SetupModulus
// Initializes a modulus of the desired keysize & features
//
// *((PSYMCRYPT_MODULUS *) buf1) will contain a pointer to the modulus, which is also in buf1.
// buf3 is used as scratch
//
VOID
setupModulus( PBYTE buf1, PBYTE buf3, SIZE_T keySize )
{
    UINT32 keyBytes = (UINT32) keySize & 0x00ffffff;
    UINT32 keyFlags = (UINT32) keySize & 0xff000000;

    UINT32 nDigits = SymCryptDigitsFromBits( 8 * keyBytes );


    PSYMCRYPT_MODULUS pmMod = SymCryptModulusCreate( buf1 + SYMCRYPT_ASYM_ALIGN_VALUE, PERF_BUFFER_SIZE - SYMCRYPT_ASYM_ALIGN_VALUE, nDigits );

    SymCryptIntSetValue(    getPerfTestModulus( (UINT32)keySize ),
                            ((UINT32) keySize) & 0x00ffffff,
                            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                            SymCryptIntFromModulus( pmMod ) );

    UINT32 flags = 0;
    switch( keyFlags & ~PERF_KEY_PRIME )
    {
    case PERF_KEY_SECRET:   flags = 0; break;
    case PERF_KEY_PUB_ODD:  flags = SYMCRYPT_FLAG_MODULUS_PARITY_PUBLIC; break;
    case PERF_KEY_PUBLIC:   flags = SYMCRYPT_FLAG_DATA_PUBLIC; break;
    case PERF_KEY_PUB_PM:   flags = SYMCRYPT_FLAG_DATA_PUBLIC; break;
    case PERF_KEY_PUB_NIST: flags = SYMCRYPT_FLAG_DATA_PUBLIC; break;
    default: CHECK(FALSE, "?" );
    }

    flags |= SYMCRYPT_FLAG_MODULUS_PRIME;   // All our moduli are prime values, and Inv requires it at the moment.

    SymCryptIntToModulus( SymCryptIntFromModulus( pmMod ), pmMod, 10000, flags, buf3, PERF_BUFFER_SIZE );

    *((PSYMCRYPT_MODULUS *) buf1) = pmMod;
}

//
// setupModOperations
// Initializes a modulus in buf1, two modElements in buf2, and one modElement in buf3.
// The modElements in buf2 are set to random values
//
void
setupModOperations( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    BYTE buf[4096];
    SYMCRYPT_ERROR scError;

    UINT32 keyBytes = (UINT32) keySize & 0x00ffffff;
    CHECK( 2 * keyBytes <= sizeof( buf ), "?" );
    GENRANDOM( buf, (2*keyBytes) );

    setupModulus( buf1, buf3, keySize );
    PCSYMCRYPT_MODULUS pmMod = *((PCSYMCRYPT_MODULUS *)buf1);

    UINT32 modElSize = SymCryptSizeofModElementFromModulus( pmMod );
    PSYMCRYPT_MODELEMENT * pPtrs = ((PSYMCRYPT_MODELEMENT *) buf2);
    pPtrs[0] = SymCryptModElementCreate( buf2 + SYMCRYPT_ASYM_ALIGN_VALUE, modElSize, pmMod );
    pPtrs[1] = SymCryptModElementCreate( buf2 + SYMCRYPT_ASYM_ALIGN_VALUE + modElSize, modElSize, pmMod );

    ((PSYMCRYPT_MODELEMENT *) buf3)[0] = SymCryptModElementCreate( buf3 + SYMCRYPT_ASYM_ALIGN_VALUE, modElSize, pmMod );

    CHECK( modElSize + SYMCRYPT_ASYM_ALIGN_VALUE <= SCRATCH_BUF_OFFSET, "ModElement overlaps with scratch buffer" );

    scError = SymCryptModElementSetValue( buf, modElSize, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, pmMod, pPtrs[0], buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    scError = SymCryptModElementSetValue( buf+modElSize, modElSize, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, pmMod, pPtrs[1], buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgModAdd>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    setupModOperations( buf1, buf2, buf3, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgModAdd>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgModAdd>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    SymCryptModAdd( *(PSYMCRYPT_MODULUS *) buf1, ((PSYMCRYPT_MODELEMENT *) buf2)[0], ((PSYMCRYPT_MODELEMENT *) buf2)[1], ((PSYMCRYPT_MODELEMENT *) buf3)[0],  buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );
}


template<>
ArithImp<ImpSc, AlgModAdd>::ArithImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgModAdd>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgModAdd>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgModAdd>;
}

template<>
ArithImp<ImpSc, AlgModAdd>::~ArithImp()
{
}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgModSub>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    setupModOperations( buf1, buf2, buf3, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgModSub>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgModSub>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    SymCryptModSub( *(PSYMCRYPT_MODULUS *) buf1, ((PSYMCRYPT_MODELEMENT *) buf2)[0], ((PSYMCRYPT_MODELEMENT *) buf2)[1], ((PSYMCRYPT_MODELEMENT *) buf3)[0],  buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );
}


template<>
ArithImp<ImpSc, AlgModSub>::ArithImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgModSub>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgModSub>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgModSub>;
}

template<>
ArithImp<ImpSc, AlgModSub>::~ArithImp()
{
}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgModMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    setupModOperations( buf1, buf2, buf3, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgModMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgModMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    SymCryptModMul( *(PSYMCRYPT_MODULUS *) buf1, ((PSYMCRYPT_MODELEMENT *) buf2)[0], ((PSYMCRYPT_MODELEMENT *) buf2)[1], ((PSYMCRYPT_MODELEMENT *) buf3)[0],  buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );
}


template<>
ArithImp<ImpSc, AlgModMul>::ArithImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgModMul>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgModMul>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgModMul>;
}

template<>
ArithImp<ImpSc, AlgModMul>::~ArithImp()
{
}



template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgModExp>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    BYTE buf[4096];
    UINT32 keyBytes = (UINT32) keySize & 0x00ffffff;
    UINT32 nDigits = 0;

    setupModOperations( buf1, buf2, buf3, keySize );

    CHECK( keyBytes <= sizeof( buf ), "?" );
    GENRANDOM( buf, keyBytes );

    nDigits = SymCryptDigitsFromBits(8 * keyBytes);

    ((PSYMCRYPT_INT *) buf2)[1] = SymCryptIntCreate( (PBYTE)(((PSYMCRYPT_INT *) buf2)[1]) + SYMCRYPT_ASYM_ALIGN_VALUE, SCRATCH_BUF_OFFSET - SYMCRYPT_ASYM_ALIGN_VALUE, nDigits );

    SymCryptIntSetValue( buf, keyBytes, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, ((PSYMCRYPT_INT *) buf2)[1] );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgModExp>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpSc, AlgModExp>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );

    SymCryptModExp(
                *(PSYMCRYPT_MODULUS *) buf1,
                ((PSYMCRYPT_MODELEMENT *) buf2)[0],
                ((PSYMCRYPT_INT *) buf2)[1],
                SymCryptIntBitsizeOfValue(SymCryptIntFromModulus(*(PSYMCRYPT_MODULUS *) buf1)),
                0,      // Default flags: Side-channel safe
                ((PSYMCRYPT_MODELEMENT *) buf3)[0],
                buf3 + SCRATCH_BUF_OFFSET,
                SCRATCH_BUF_SIZE );
}


template<>
ArithImp<ImpSc, AlgModExp>::ArithImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgModExp>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgModExp>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgModExp>;
}

template<>
ArithImp<ImpSc, AlgModExp>::~ArithImp()
{
}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgModSquare>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    setupModOperations( buf1, buf2, buf3, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgModSquare>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgModSquare>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    SymCryptModSquare( *(PSYMCRYPT_MODULUS *) buf1, ((PSYMCRYPT_MODELEMENT *) buf2)[0], ((PSYMCRYPT_MODELEMENT *) buf3)[0],  buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );
}


template<>
ArithImp<ImpSc, AlgModSquare>::ArithImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgModSquare>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgModSquare>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgModSquare>;
}

template<>
ArithImp<ImpSc, AlgModSquare>::~ArithImp()
{
}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgModInv>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    setupModOperations( buf1, buf2, buf3, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgModInv>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgModInv>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    SYMCRYPT_ERROR scError;
    scError = SymCryptModInv(   *(PSYMCRYPT_MODULUS *) buf1,
                                ((PSYMCRYPT_MODELEMENT *) buf2)[0],
                                ((PSYMCRYPT_MODELEMENT *) buf3)[0],
                                0,
                                buf3 + SCRATCH_BUF_OFFSET,
                                SCRATCH_BUF_SIZE );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in perf test case" );
}


template<>
ArithImp<ImpSc, AlgModInv>::ArithImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgModInv>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgModInv>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgModInv>;
}

template<>
ArithImp<ImpSc, AlgModInv>::~ArithImp()
{
}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgScsTable>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UINT32 nElements = 32;
    PSYMCRYPT_SCSTABLE  pTable = (PSYMCRYPT_SCSTABLE) buf1;

    UINT32 cbBuffer = SymCryptScsTableInit( pTable, nElements, (UINT32) keySize );
    SymCryptScsTableSetBuffer( pTable, buf2, cbBuffer );

    for( UINT32 i=0; i<nElements; i++ )
    {
        GENRANDOM( buf3, (UINT32) keySize );
        SymCryptScsTableStore( pTable, i, buf3, (UINT32) keySize );
    }
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgScsTable>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgScsTable>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    UNREFERENCED_PARAMETER( buf2 );
    PSYMCRYPT_SCSTABLE  pTable = (PSYMCRYPT_SCSTABLE) buf1;
    SymCryptScsTableLoad( pTable, 7, buf3, pTable->elementSize );
}


template<>
ArithImp<ImpSc, AlgScsTable>::ArithImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgScsTable>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgScsTable>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgScsTable>;
}

template<>
ArithImp<ImpSc, AlgScsTable>::~ArithImp()
{
}

//============================
// The DeveloperTest algorithm is just for tests during active development.

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgDeveloperTest>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgDeveloperTest>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

//extern "C" { VOID SYMCRYPT_CALL SymCryptTestMulx(); }

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgDeveloperTest>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    //SymCryptTestMulx();
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( dataSize );
}


template<>
ArithImp<ImpSc, AlgDeveloperTest>::ArithImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgDeveloperTest>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgDeveloperTest>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgDeveloperTest>;
}

template<>
ArithImp<ImpSc, AlgDeveloperTest>::~ArithImp()
{
}

//============================

VOID
trialDivisionSetFakePrime( PSYMCRYPT_TRIALDIVISION_PRIME p)
{
    p->invMod2e64 = 0x5a5a5a5a5a5a5a5b; // Fake, doesn't matter as long as it is odd and not too small to be especially fast...
    p->compareLimit = 0;        // This makes the trial division never 'hit' unless the input is all-zeroes.
}

VOID
createFakeTrialDivisionContext( PBYTE pBuf, UINT32 primesPerGroup )
{
    PBYTE pAlloc= pBuf;
    UINT32 nGroups = 1000;
    UINT32 nPrimes = nGroups * primesPerGroup;

    PSYMCRYPT_TRIALDIVISION_CONTEXT pContext = (PSYMCRYPT_TRIALDIVISION_CONTEXT) pAlloc;
    pAlloc += sizeof( *pContext );

    pContext->pGroupList = (PSYMCRYPT_TRIALDIVISION_GROUP) pAlloc;
    pAlloc += (nGroups + 1) * sizeof( SYMCRYPT_TRIALDIVISION_GROUP );

    pContext->pPrimeList = (PSYMCRYPT_TRIALDIVISION_PRIME) pAlloc;
    pAlloc += (nPrimes + 1) * sizeof( SYMCRYPT_TRIALDIVISION_PRIME );

    pContext->pPrimes = (PUINT32) pAlloc;
    pAlloc += (nPrimes + 1) * sizeof( UINT32 );

    pContext->nBytesAlloc = pAlloc - pBuf;

    // The special primes hinder our measurements a bit, but only by something like 0.3%.
    trialDivisionSetFakePrime( &pContext->Primes3_5_17[0] );
    trialDivisionSetFakePrime( &pContext->Primes3_5_17[1] );
    trialDivisionSetFakePrime( &pContext->Primes3_5_17[2] );

    UINT32 i;
    for( i=0; i<nPrimes; i++ )
    {
        trialDivisionSetFakePrime( &pContext->pPrimeList[i] );
    }

    for( i=0; i<nGroups; i++ )
    {
        pContext->pGroupList[i].nPrimes = primesPerGroup;
        memset( &pContext->pGroupList[i].factor[0], 0xa5, 9 * sizeof( UINT32 ) );
    }

    pContext->pGroupList[nGroups].nPrimes = 0;
}

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgTrialDivision>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    // We create two fake trial division contexts to measure the performance of both the group modulo reduction
    // and the actual per-prime test.
    // One context has 1000 groups of 11 primes each.
    // One context has 1000 groups of 1 prime each.
    // Together these measurements allow us to determine the cost per group and cost per prime which we need
    // to tune the choice of trial division limit.

    // First create the input in buf3.
    // But make sure it is odd because the prime fake doesn't work on 2

    createFakeTrialDivisionContext( buf1, 1 );
    createFakeTrialDivisionContext( buf2, 11 );

    PSYMCRYPT_INT piSrc = SymCryptIntCreate( buf3 + 64, PERF_BUFFER_SIZE - 64, SymCryptDigitsFromBits( (UINT32)keySize * 8 ) );

    PBYTE p = buf3 + PERF_BUFFER_SIZE/2;
    GENRANDOM( p, (ULONG) keySize );
    p[0] |= 1;   // Make sure it is odd so we don't get zeroes...
    SymCryptIntSetValue( p, keySize, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, piSrc );

    *(PSYMCRYPT_INT *) buf3 = piSrc;
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgTrialDivision>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgTrialDivision>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( dataSize );

    PCSYMCRYPT_TRIALDIVISION_CONTEXT pContext = (PCSYMCRYPT_TRIALDIVISION_CONTEXT) buf1;
    PCSYMCRYPT_INT piSrc = *(PCSYMCRYPT_INT *) buf3;

    *(PUINT32) (buf3 + PERF_BUFFER_SIZE/2) = SymCryptIntFindSmallDivisor( pContext, piSrc, NULL, 0 );
}

template<>
VOID
algImpDecryptPerfFunction< ImpSc, AlgTrialDivision>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( dataSize );

    PCSYMCRYPT_TRIALDIVISION_CONTEXT pContext = (PCSYMCRYPT_TRIALDIVISION_CONTEXT) buf2;
    PCSYMCRYPT_INT piSrc = *(PCSYMCRYPT_INT *) buf3;

    *(PUINT32) (buf3 + PERF_BUFFER_SIZE/2) = SymCryptIntFindSmallDivisor( pContext, piSrc, NULL, 0 );
}


template<>
ArithImp<ImpSc, AlgTrialDivision>::ArithImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgTrialDivision>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction  <ImpSc, AlgTrialDivision>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgTrialDivision>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgTrialDivision>;
}

template<>
ArithImp<ImpSc, AlgTrialDivision>::~ArithImp()
{
}

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgTrialDivisionContext>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    *(UINT32 *) buf2 = (UINT32) keySize;
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgTrialDivisionContext>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    *(PCSYMCRYPT_TRIALDIVISION_CONTEXT *) buf1 = NULL;
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgTrialDivisionContext>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( dataSize );

    PCSYMCRYPT_TRIALDIVISION_CONTEXT context;

    context = SymCryptCreateTrialDivisionContext( SymCryptDigitsFromBits( 8 * *(UINT32 *) buf2 ) );

    // Save a copy of the pointer to stop the compiler from optimizing the whole thing away.
    *(PCSYMCRYPT_TRIALDIVISION_CONTEXT *) buf1 = context;

    SymCryptFreeTrialDivisionContext( context );
}


template<>
ArithImp<ImpSc, AlgTrialDivisionContext>::ArithImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgTrialDivisionContext>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgTrialDivisionContext>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgTrialDivisionContext>;
}

template<>
ArithImp<ImpSc, AlgTrialDivisionContext>::~ArithImp()
{
}


//============================

// Table with the RSA keys' sizes and pointers to keys
struct {
    SIZE_T                      keySize;
    PSYMCRYPT_RSAKEY            pkRsakey;
} g_precomputedRsaKeys[] = {
    {  32, NULL },
    {  64, NULL },
    { 128, NULL },
    { 256, NULL },
    { 384, NULL },
    { 512, NULL },
    {1024, NULL },
};

void
SetupRsaKey( PBYTE buf1, SIZE_T keySize )
{
    int i = 0;
    BOOLEAN bFound = FALSE;

    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    for( i=0; i < ARRAY_SIZE(g_precomputedRsaKeys); i++ )
    {
        if ( keySize == g_precomputedRsaKeys[i].keySize )
        {
            bFound = TRUE;

            if ( g_precomputedRsaKeys[i].pkRsakey == NULL )
            {
                SYMCRYPT_RSA_PARAMS rsaParams = { 0 };
                PSYMCRYPT_RSAKEY pkRsakey = NULL;

                // Set the parameters
                rsaParams.version = 1;
                rsaParams.nBitsOfModulus = ((UINT32)keySize) * 8;
                rsaParams.nPrimes = 2;
                rsaParams.nPubExp = 1;

                pkRsakey = SymCryptRsakeyAllocate( &rsaParams, 0 );
                CHECK( pkRsakey != NULL, "?" );

                scError = SymCryptRsakeyGenerate( pkRsakey, NULL, 0, 0 );   // Use default exponent
                CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

                g_precomputedRsaKeys[i].pkRsakey = pkRsakey;
            }

            break;
        }
    }

    CHECK( bFound, "?" );

    *((PSYMCRYPT_RSAKEY *) buf1) = g_precomputedRsaKeys[i].pkRsakey;
}

void
sc_RsaKeyPerf( PBYTE buf1, PBYTE buf2, SIZE_T keySize )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    SetupRsaKey( buf1, keySize );

    buf2[0] = 0;
    scError = SymCryptCallbackRandom( buf2 + 1, keySize - 1 );  // Don't fill it up so that it is smaller than the modulus
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
}

//================================================

typedef struct _HASH_INFO {
    PCSTR   name;
    PCSYMCRYPT_HASH pcHash;
    PCSYMCRYPT_OID  pcOids;
    UINT32          nOids;
} HASH_INFO;
typedef const HASH_INFO * PCHASH_INFO;

const HASH_INFO hashInfoTable[] = {
    {   "MD5",      SymCryptMd5Algorithm,       SymCryptMd5OidList,     SYMCRYPT_MD5_OID_COUNT },
    {   "SHA1",     SymCryptSha1Algorithm,      SymCryptSha1OidList,    SYMCRYPT_SHA1_OID_COUNT},
    {   "SHA256",   SymCryptSha256Algorithm,    SymCryptSha256OidList,  SYMCRYPT_SHA256_OID_COUNT},
    {   "SHA384",   SymCryptSha384Algorithm,    SymCryptSha384OidList,  SYMCRYPT_SHA384_OID_COUNT},
    {   "SHA512",   SymCryptSha512Algorithm,    SymCryptSha512OidList,  SYMCRYPT_SHA512_OID_COUNT},
    { NULL },
};

PCHASH_INFO getHashInfo( PCSTR pcstrName )
{
    for( int i=0; hashInfoTable[i].name != NULL; i++ )
    {
        if( STRICMP( pcstrName, hashInfoTable[i].name ) == 0 )
        {
            return &hashInfoTable[i];
        }
    }
    CHECK( FALSE, "?" );
    return NULL;
}


// Rsa Pkcs1 Sign
template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgRsaSignPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SIZE_T cbDst = 0;

    sc_RsaKeyPerf( buf1, buf2, keySize );

    scError = SymCryptRsaPkcs1Sign(
                    *((PSYMCRYPT_RSAKEY *) buf1),
                    buf2,
                    PERF_RSA_HASH_ALG_SIZE,
                    PERF_RSA_HASH_ALG_OIDS_SC,
                    PERF_RSA_HASH_ALG_NOIDS_SC,
                    0,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    buf3,
                    keySize,
                    &cbDst );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    CHECK( cbDst == keySize, "?" );

    scError = SymCryptRsaPkcs1Verify(
                    *((PSYMCRYPT_RSAKEY *) buf1),
                    buf2,
                    PERF_RSA_HASH_ALG_SIZE,
                    buf3,
                    keySize,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    PERF_RSA_HASH_ALG_OIDS_SC,
                    PERF_RSA_HASH_ALG_NOIDS_SC,
                    0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgRsaSignPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgRsaSignPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SIZE_T cbDst = 0;

    SymCryptRsaPkcs1Sign(
            *((PSYMCRYPT_RSAKEY *) buf1),
            buf2,
            PERF_RSA_HASH_ALG_SIZE,
            PERF_RSA_HASH_ALG_OIDS_SC,
            PERF_RSA_HASH_ALG_NOIDS_SC,
            0,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            buf3,
            dataSize,
            &cbDst );
}

template<>
VOID
algImpDecryptPerfFunction< ImpSc, AlgRsaSignPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_ERROR scError;

    scError = SymCryptRsaPkcs1Verify(
                    *((PSYMCRYPT_RSAKEY *) buf1),
                    buf2,
                    PERF_RSA_HASH_ALG_SIZE,
                    buf3,
                    dataSize,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    PERF_RSA_HASH_ALG_OIDS_SC,
                    PERF_RSA_HASH_ALG_NOIDS_SC,
                    0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
}

template<>
RsaSignImp<ImpSc, AlgRsaSignPkcs1>::RsaSignImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgRsaSignPkcs1>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction< ImpSc, AlgRsaSignPkcs1>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgRsaSignPkcs1>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgRsaSignPkcs1>;

    state.pKey = NULL;
}

template<>
RsaSignImp<ImpSc, AlgRsaSignPkcs1>::~RsaSignImp()
{
    if( state.pKey != NULL )
    {
        SymCryptRsakeyFree( state.pKey );
        state.pKey = NULL;
    }
}

template<>
NTSTATUS
RsaSignImp<ImpSc, AlgRsaSignPkcs1>::setKey( PCRSAKEY_TESTBLOB pcKeyBlob )
{
    SYMCRYPT_ERROR scError;

    if( state.pKey != NULL )
    {
        SymCryptRsakeyFree( state.pKey );
        state.pKey = NULL;
    }

    if( pcKeyBlob == NULL )
    {
        // Just used to clear the key state to do leak detection
        return STATUS_SUCCESS;
    }

    SYMCRYPT_RSA_PARAMS params;
    params.version = 1;
    params.nBitsOfModulus = pcKeyBlob->nBitsModulus;
    params.nPrimes = 2;
    params.nPubExp = 1;

    state.pKey = SymCryptRsakeyAllocate( &params, 0 );
    CHECK( state.pKey != NULL, "?" );

    PCBYTE ppPrime[2] = {&pcKeyBlob->abPrime1[0], &pcKeyBlob->abPrime2[0] };
    SIZE_T cbPrime[2] = {pcKeyBlob->cbPrime1, pcKeyBlob->cbPrime2 };

    scError = SymCryptRsakeySetValue(
        &pcKeyBlob->abModulus[0], pcKeyBlob->cbModulus,
        &pcKeyBlob->u64PubExp, 1,
        ppPrime, cbPrime, 2,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
        state.pKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
RsaSignImp<ImpSc, AlgRsaSignPkcs1>::sign(
    _In_reads_( cbHash)     PCBYTE  pbHash,
                            SIZE_T  cbHash,
                            PCSTR   pcstrHashAlgName,
                            UINT32  u32Other,
    _Out_writes_( cbSig )   PBYTE   pbSig,
                            SIZE_T  cbSig )
{
    PCHASH_INFO pInfo;
    SYMCRYPT_ERROR scError;
    SIZE_T cbTmp;

    UNREFERENCED_PARAMETER( u32Other );

    pInfo = getHashInfo( pcstrHashAlgName);
    scError = SymCryptRsaPkcs1Sign(
                    state.pKey,
                    pbHash,
                    cbHash,
                    pInfo->pcOids,
                    pInfo->nOids,
                    0,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    pbSig,
                    cbSig,
                    &cbTmp );
    CHECK( scError == SYMCRYPT_NO_ERROR && cbTmp == cbSig, "?" );

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
RsaSignImp<ImpSc, AlgRsaSignPkcs1>::verify(
    _In_reads_( cbHash)     PCBYTE  pbHash,
                            SIZE_T  cbHash,
    _In_reads_( cbSig )     PCBYTE  pbSig,
                            SIZE_T  cbSig,
                            PCSTR   pcstrHashAlgName,
                            UINT32  u32Other )
{
    SYMCRYPT_ERROR scError;
    NTSTATUS ntStatus;
    PCHASH_INFO pInfo;

    UNREFERENCED_PARAMETER( u32Other );

    pInfo = getHashInfo( pcstrHashAlgName);
    scError = SymCryptRsaPkcs1Verify(
                    state.pKey,
                    pbHash,
                    cbHash,
                    pbSig,
                    cbSig,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    pInfo->pcOids,
                    pInfo->nOids,
                    0 );

    switch( scError )
    {
    case SYMCRYPT_NO_ERROR:
        ntStatus = STATUS_SUCCESS;
        break;
    case SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE:
        ntStatus = STATUS_INVALID_SIGNATURE;
        break;
    case SYMCRYPT_INVALID_ARGUMENT:
        ntStatus = STATUS_INVALID_PARAMETER;
        break;
    default:
        iprint( "Unexpected SymCrypt error %08x, %d, %d, %s\n", scError, cbHash, cbSig, pcstrHashAlgName );
        CHECK( FALSE, "?" );
        ntStatus = STATUS_UNSUCCESSFUL;
    }

    return ntStatus;
}


// Rsa Pss Sign
template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgRsaSignPss>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SIZE_T cbDst = 0;

    sc_RsaKeyPerf( buf1, buf2, keySize );

    scError = SymCryptRsaPssSign(
                    *((PSYMCRYPT_RSAKEY *) buf1),
                    buf2,
                    PERF_RSA_HASH_ALG_SIZE,
                    PERF_RSA_HASH_ALG_SC,
                    PERF_RSA_HASH_ALG_SIZE,
                    0,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    buf3,
                    keySize,
                    &cbDst );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    CHECK( cbDst == keySize, "?" );

    scError = SymCryptRsaPssVerify(
                    *((PSYMCRYPT_RSAKEY *) buf1),
                    buf2,
                    PERF_RSA_HASH_ALG_SIZE,
                    buf3,
                    keySize,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    PERF_RSA_HASH_ALG_SC,
                    PERF_RSA_HASH_ALG_SIZE,
                    0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgRsaSignPss>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgRsaSignPss>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SIZE_T cbDst = 0;

    SymCryptRsaPssSign(
        *((PSYMCRYPT_RSAKEY *) buf1),
        buf2,
        PERF_RSA_HASH_ALG_SIZE,
        PERF_RSA_HASH_ALG_SC,
        PERF_RSA_HASH_ALG_SIZE,
        0,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        buf3,
        dataSize,
        &cbDst );
}

template<>
VOID
algImpDecryptPerfFunction< ImpSc, AlgRsaSignPss>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_ERROR scError;

    scError = SymCryptRsaPssVerify(
                    *((PSYMCRYPT_RSAKEY *) buf1),
                    buf2,
                    PERF_RSA_HASH_ALG_SIZE,
                    buf3,
                    dataSize,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    PERF_RSA_HASH_ALG_SC,
                    PERF_RSA_HASH_ALG_SIZE,
                    0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
}

template<>
RsaSignImp<ImpSc, AlgRsaSignPss>::RsaSignImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgRsaSignPss>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction< ImpSc, AlgRsaSignPss>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgRsaSignPss>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgRsaSignPss>;

    state.pKey = NULL;
}

template<>
RsaSignImp<ImpSc, AlgRsaSignPss>::~RsaSignImp()
{
    if( state.pKey != NULL )
    {
        SymCryptRsakeyFree( state.pKey );
        state.pKey = NULL;
    }
}

template<>
NTSTATUS
RsaSignImp<ImpSc, AlgRsaSignPss>::setKey( PCRSAKEY_TESTBLOB pcKeyBlob )
{
    SYMCRYPT_ERROR scError;

    if( state.pKey != NULL )
    {
        SymCryptRsakeyFree( state.pKey );
        state.pKey = NULL;
    }

    if( pcKeyBlob == NULL )
    {
        // Just used to clear the key state to do leak detection
        return STATUS_SUCCESS;
    }

    SYMCRYPT_RSA_PARAMS params;
    params.version = 1;
    params.nBitsOfModulus = pcKeyBlob->nBitsModulus;
    params.nPrimes = 2;
    params.nPubExp = 1;

    state.pKey = SymCryptRsakeyAllocate( &params, 0 );
    CHECK( state.pKey != NULL, "?" );

    PCBYTE ppPrime[2] = {&pcKeyBlob->abPrime1[0], &pcKeyBlob->abPrime2[0] };
    SIZE_T cbPrime[2] = {pcKeyBlob->cbPrime1, pcKeyBlob->cbPrime2 };

    scError = SymCryptRsakeySetValue(
        &pcKeyBlob->abModulus[0], pcKeyBlob->cbModulus,
        &pcKeyBlob->u64PubExp, 1,
        ppPrime, cbPrime, 2,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
        state.pKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
RsaSignImp<ImpSc, AlgRsaSignPss>::sign(
    _In_reads_( cbHash)     PCBYTE  pbHash,
                            SIZE_T  cbHash,
                            PCSTR   pcstrHashAlgName,
                            UINT32  u32Other,
    _Out_writes_( cbSig )   PBYTE   pbSig,
                            SIZE_T  cbSig )
{
    PCHASH_INFO pInfo;
    SYMCRYPT_ERROR scError;
    SIZE_T cbTmp;

    pInfo = getHashInfo( pcstrHashAlgName);
    scError = SymCryptRsaPssSign(
                    state.pKey,
                    pbHash,
                    cbHash,
                    pInfo->pcHash,
                    u32Other,
                    0,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    pbSig,
                    cbSig,
                    &cbTmp );
    CHECK( scError == SYMCRYPT_NO_ERROR && cbTmp == cbSig, "?" );

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
RsaSignImp<ImpSc, AlgRsaSignPss>::verify(
    _In_reads_( cbHash)     PCBYTE  pbHash,
                            SIZE_T  cbHash,
    _In_reads_( cbSig )     PCBYTE  pbSig,
                            SIZE_T  cbSig,
                            PCSTR   pcstrHashAlgName,
                            UINT32  u32Other )
{
    SYMCRYPT_ERROR scError;
    NTSTATUS ntStatus;
    PCHASH_INFO pInfo;

    pInfo = getHashInfo( pcstrHashAlgName);
    scError = SymCryptRsaPssVerify(
                    state.pKey,
                    pbHash,
                    cbHash,
                    pbSig,
                    cbSig,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    pInfo->pcHash,
                    u32Other,
                    0 );

    switch( scError )
    {
    case SYMCRYPT_NO_ERROR:
        ntStatus = STATUS_SUCCESS;
        break;
    case SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE:
        ntStatus = STATUS_INVALID_SIGNATURE;
        break;
    case SYMCRYPT_INVALID_ARGUMENT:
        ntStatus = STATUS_INVALID_PARAMETER;
        break;
    default:
        iprint( "Unexpected SymCrypt error %08x, %d, %d, %s\n", scError, cbHash, cbSig, pcstrHashAlgName );
        CHECK( FALSE, "?" );
        ntStatus = STATUS_UNSUCCESSFUL;
    }

    return ntStatus;
}



// Rsa Encryption

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgRsaEncRaw>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    sc_RsaKeyPerf( buf1, buf2, keySize );

    scError = SymCryptRsaRawEncrypt(
                    *((PSYMCRYPT_RSAKEY *) buf1),
                    buf2,
                    keySize,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0,
                    buf3,
                    keySize );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    scError = SymCryptRsaRawDecrypt(
                    *((PSYMCRYPT_RSAKEY *) buf1),
                    buf3,
                    keySize,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0,
                    buf2 + keySize,
                    keySize );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    CHECK( memcmp(buf2, buf2 + keySize, keySize) == 0, "?" );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgRsaEncRaw>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgRsaEncRaw>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SymCryptRsaRawEncrypt(
            *((PSYMCRYPT_RSAKEY *) buf1),
            buf2,
            dataSize,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0,
            buf3,
            dataSize );
}

template<>
VOID
algImpDecryptPerfFunction< ImpSc, AlgRsaEncRaw>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_ERROR scError;

    scError = SymCryptRsaRawDecrypt(
                    *((PSYMCRYPT_RSAKEY *) buf1),
                    buf3,
                    dataSize,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0,
                    buf2 + dataSize,
                    dataSize );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
}


template<>
RsaEncImp<ImpSc, AlgRsaEncRaw>::RsaEncImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgRsaEncRaw>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpSc, AlgRsaEncRaw>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgRsaEncRaw>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgRsaEncRaw>;

    state.pKey = NULL;
}

template<>
RsaEncImp<ImpSc, AlgRsaEncRaw>::~RsaEncImp()
{
    if( state.pKey != NULL )
    {
        SymCryptRsakeyFree( state.pKey );
        state.pKey = NULL;
    }
}

template<>
NTSTATUS
RsaEncImp<ImpSc, AlgRsaEncRaw>::setKey( PCRSAKEY_TESTBLOB pcKeyBlob )
{
    SYMCRYPT_ERROR scError;

    if( state.pKey != NULL )
    {
        SymCryptRsakeyFree( state.pKey );
        state.pKey = NULL;
    }

    if( pcKeyBlob == NULL )
    {
        // Just used to clear the key state to do leak detection
        return STATUS_SUCCESS;
    }

    SYMCRYPT_RSA_PARAMS params;
    params.version = 1;
    params.nBitsOfModulus = pcKeyBlob->nBitsModulus;
    params.nPrimes = 2;
    params.nPubExp = 1;

    state.pKey = SymCryptRsakeyAllocate( &params, 0 );
    CHECK( state.pKey != NULL, "?" );

    PCBYTE ppPrime[2] = {&pcKeyBlob->abPrime1[0], &pcKeyBlob->abPrime2[0] };
    SIZE_T cbPrime[2] = {pcKeyBlob->cbPrime1, pcKeyBlob->cbPrime2 };

    scError = SymCryptRsakeySetValue(
        &pcKeyBlob->abModulus[0], pcKeyBlob->cbModulus,
        &pcKeyBlob->u64PubExp, 1,
        ppPrime, cbPrime, 2,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
        state.pKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
RsaEncImp<ImpSc, AlgRsaEncRaw>::encrypt(
    _In_reads_( cbMsg )             PCBYTE  pbMsg,
                                    SIZE_T  cbMsg,
                                    PCSTR   pcstrHashAlgName,
                                    PCBYTE  pbLabel,
                                    SIZE_T  cbLabel,
    _Out_writes_( cbCiphertext )    PBYTE   pbCiphertext,
                                    SIZE_T  cbCiphertext )
{
    SYMCRYPT_ERROR scError;

    UNREFERENCED_PARAMETER( pcstrHashAlgName );
    UNREFERENCED_PARAMETER( pbLabel );
    UNREFERENCED_PARAMETER( cbLabel );

    SIZE_T cbKey = SymCryptRsakeySizeofModulus( state.pKey );
    CHECK( cbCiphertext == cbKey, "Wrong ciphertext size" );
    CHECK( cbMsg == cbKey, "Wrong message size" );

    scError = SymCryptRsaRawEncrypt(    state.pKey,
                                        pbMsg, cbMsg,
                                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                        0,
                                        pbCiphertext, cbCiphertext );

    return scError == SYMCRYPT_NO_ERROR ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

template<>
NTSTATUS
RsaEncImp<ImpSc, AlgRsaEncRaw>::decrypt(
        _In_reads_( cbCiphertext )      PCBYTE  pbCiphertext,
                                        SIZE_T  cbCiphertext,
                                        PCSTR   pcstrHashAlgName,
                                        PCBYTE  pbLabel,
                                        SIZE_T  cbLabel,
        _Out_writes_to_(cbMsg,*pcbMsg)  PBYTE   pbMsg,
                                        SIZE_T  cbMsg,
                                        SIZE_T *pcbMsg )
{
    SYMCRYPT_ERROR scError;

    UNREFERENCED_PARAMETER( pcstrHashAlgName );
    UNREFERENCED_PARAMETER( pbLabel );
    UNREFERENCED_PARAMETER( cbLabel );

    SIZE_T cbKey = SymCryptRsakeySizeofModulus( state.pKey );
    CHECK( cbCiphertext == cbKey, "Wrong ciphertext size" );
    CHECK( cbMsg >= cbKey, "Wrong message size" );

    scError = SymCryptRsaRawDecrypt(    state.pKey,
                                        pbCiphertext, cbCiphertext,
                                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                        0,
                                        pbMsg, cbKey );

    *pcbMsg = cbKey;

    return scError == SYMCRYPT_NO_ERROR ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}


// RSA PKCS1 encryption

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgRsaEncPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SIZE_T cbDst = 0;

    sc_RsaKeyPerf( buf1, buf2, keySize );

    scError = SymCryptRsaPkcs1Encrypt(
                    *((PSYMCRYPT_RSAKEY *) buf1),
                    buf2,
                    keySize - PERF_RSA_PKCS1_LESS_BYTES,        // This is the maximum size for PKCS1
                    0,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    buf3,
                    keySize,
                    &cbDst );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    CHECK( cbDst == keySize, "?" );

    scError = SymCryptRsaPkcs1Decrypt(
                    *((PSYMCRYPT_RSAKEY *) buf1),
                    buf3,
                    keySize,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0,
                    buf2 + keySize,
                    keySize,
                    &cbDst );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    CHECK( cbDst == keySize - PERF_RSA_PKCS1_LESS_BYTES, "?" );
    CHECK( memcmp(buf2, buf2 + keySize, cbDst) == 0, "?" );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgRsaEncPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgRsaEncPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SIZE_T cbDst = 0;

    SymCryptRsaPkcs1Encrypt(
            *((PSYMCRYPT_RSAKEY *) buf1),
            buf2,
            dataSize - PERF_RSA_PKCS1_LESS_BYTES,
            0,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            buf3,
            dataSize,
            &cbDst );
}

template<>
VOID
algImpDecryptPerfFunction< ImpSc, AlgRsaEncPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_ERROR scError;
    SIZE_T cbDst;

    scError = SymCryptRsaPkcs1Decrypt(
                    *((PSYMCRYPT_RSAKEY *) buf1),
                    buf3,
                    dataSize,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0,
                    buf2 + dataSize,
                    dataSize,
                    &cbDst );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    CHECK( cbDst == dataSize - PERF_RSA_PKCS1_LESS_BYTES, "?" );
}


template<>
RsaEncImp<ImpSc, AlgRsaEncPkcs1>::RsaEncImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgRsaEncPkcs1>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpSc, AlgRsaEncPkcs1>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgRsaEncPkcs1>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgRsaEncPkcs1>;

    state.pKey = NULL;
}

template<>
RsaEncImp<ImpSc, AlgRsaEncPkcs1>::~RsaEncImp()
{
    if( state.pKey != NULL )
    {
        SymCryptRsakeyFree( state.pKey );
        state.pKey = NULL;
    }
}

template<>
NTSTATUS
RsaEncImp<ImpSc, AlgRsaEncPkcs1>::setKey( PCRSAKEY_TESTBLOB pcKeyBlob )
{
    SYMCRYPT_ERROR scError;

    if( state.pKey != NULL )
    {
        SymCryptRsakeyFree( state.pKey );
        state.pKey = NULL;
    }

    if( pcKeyBlob == NULL )
    {
        // Just used to clear the key state to do leak detection
        return STATUS_SUCCESS;
    }

    SYMCRYPT_RSA_PARAMS params;
    params.version = 1;
    params.nBitsOfModulus = pcKeyBlob->nBitsModulus;
    params.nPrimes = 2;
    params.nPubExp = 1;

    state.pKey = SymCryptRsakeyAllocate( &params, 0 );
    CHECK( state.pKey != NULL, "?" );

    PCBYTE ppPrime[2] = {&pcKeyBlob->abPrime1[0], &pcKeyBlob->abPrime2[0] };
    SIZE_T cbPrime[2] = {pcKeyBlob->cbPrime1, pcKeyBlob->cbPrime2 };

    scError = SymCryptRsakeySetValue(
        &pcKeyBlob->abModulus[0], pcKeyBlob->cbModulus,
        &pcKeyBlob->u64PubExp, 1,
        ppPrime, cbPrime, 2,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
        state.pKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
RsaEncImp<ImpSc, AlgRsaEncPkcs1>::encrypt(
    _In_reads_( cbMsg )             PCBYTE  pbMsg,
                                    SIZE_T  cbMsg,
                                    PCSTR   pcstrHashAlgName,
                                    PCBYTE  pbLabel,
                                    SIZE_T  cbLabel,
    _Out_writes_( cbCiphertext )    PBYTE   pbCiphertext,
                                    SIZE_T  cbCiphertext )
{
    SYMCRYPT_ERROR scError;
    SIZE_T cbResult;

    UNREFERENCED_PARAMETER( pcstrHashAlgName );
    UNREFERENCED_PARAMETER( pbLabel );
    UNREFERENCED_PARAMETER( cbLabel );

    SIZE_T cbKey = SymCryptRsakeySizeofModulus( state.pKey );
    CHECK( cbCiphertext == cbKey, "Wrong ciphertext size" );

    scError = SymCryptRsaPkcs1Encrypt(  state.pKey,
                                        pbMsg, cbMsg,
                                        0,
                                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                        pbCiphertext, cbCiphertext,
                                        &cbResult );

    CHECK( cbResult == cbKey, "Unexpected ciphertext size" );

    return scError == SYMCRYPT_NO_ERROR ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

template<>
NTSTATUS
RsaEncImp<ImpSc, AlgRsaEncPkcs1>::decrypt(
        _In_reads_( cbCiphertext )      PCBYTE  pbCiphertext,
                                        SIZE_T  cbCiphertext,
                                        PCSTR   pcstrHashAlgName,
                                        PCBYTE  pbLabel,
                                        SIZE_T  cbLabel,
        _Out_writes_to_(cbMsg,*pcbMsg)  PBYTE   pbMsg,
                                        SIZE_T  cbMsg,
                                        SIZE_T *pcbMsg )
{
    SYMCRYPT_ERROR scError;
    SIZE_T cbResult;

    UNREFERENCED_PARAMETER( pcstrHashAlgName );
    UNREFERENCED_PARAMETER( pbLabel );
    UNREFERENCED_PARAMETER( cbLabel );

    SIZE_T cbKey = SymCryptRsakeySizeofModulus( state.pKey );
    CHECK( cbCiphertext == cbKey, "Wrong ciphertext size" );

    scError = SymCryptRsaPkcs1Decrypt(  state.pKey,
                                        pbCiphertext, cbCiphertext,
                                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                        0,
                                        pbMsg, cbMsg,
                                        &cbResult );

    *pcbMsg = cbResult;

    return scError == SYMCRYPT_NO_ERROR ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

// RSA OAEP encryption

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgRsaEncOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SIZE_T cbDst = 0;

    sc_RsaKeyPerf( buf1, buf2, keySize );

    scError = SymCryptRsaOaepEncrypt(
                    *((PSYMCRYPT_RSAKEY *) buf1),
                    buf2,
                    keySize - PERF_RSA_OAEP_LESS_BYTES, // This is the maximum size for OAEP
                    PERF_RSA_HASH_ALG_SC,
                    buf2 + keySize,                     // Use buf2 bytes as the label
                    PERF_RSA_LABEL_LENGTH,
                    0,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    buf3,
                    keySize,
                    &cbDst );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    CHECK( cbDst == keySize, "?" );

    scError = SymCryptRsaOaepDecrypt(
                    *((PSYMCRYPT_RSAKEY *) buf1),
                    buf3,
                    keySize,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    PERF_RSA_HASH_ALG_SC,
                    buf2 + keySize,
                    PERF_RSA_LABEL_LENGTH,
                    0,
                    buf3 + keySize,
                    keySize,
                    &cbDst );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    CHECK( cbDst == keySize - PERF_RSA_OAEP_LESS_BYTES, "?" );
    CHECK( memcmp(buf2, buf3 + keySize, cbDst) == 0, "?" );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgRsaEncOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgRsaEncOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SIZE_T cbDst = 0;
    SYMCRYPT_ERROR scError;

    scError = SymCryptRsaOaepEncrypt(
                    *((PSYMCRYPT_RSAKEY *) buf1),
                    buf2,
                    dataSize - PERF_RSA_OAEP_LESS_BYTES, // This is the maximum size for OAEP
                    PERF_RSA_HASH_ALG_SC,
                    buf2 + dataSize,                     // Use buf2 bytes as the label
                    PERF_RSA_LABEL_LENGTH,
                    0,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    buf3,
                    dataSize,
                    &cbDst );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    CHECK( cbDst == dataSize, "?" );
}

template<>
VOID
algImpDecryptPerfFunction< ImpSc, AlgRsaEncOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_ERROR scError;
    SIZE_T cbDst;

    scError = SymCryptRsaOaepDecrypt(
                    *((PSYMCRYPT_RSAKEY *) buf1),
                    buf3,
                    dataSize,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    PERF_RSA_HASH_ALG_SC,
                    buf2 + dataSize,    // label
                    PERF_RSA_LABEL_LENGTH,
                    0,
                    buf3 + dataSize,
                    dataSize,
                    &cbDst );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    CHECK( cbDst == dataSize - PERF_RSA_OAEP_LESS_BYTES, "?" );
}


template<>
RsaEncImp<ImpSc, AlgRsaEncOaep>::RsaEncImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgRsaEncOaep>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpSc, AlgRsaEncOaep>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgRsaEncOaep>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgRsaEncOaep>;

    state.pKey = NULL;
}

template<>
RsaEncImp<ImpSc, AlgRsaEncOaep>::~RsaEncImp()
{
    if( state.pKey != NULL )
    {
        SymCryptRsakeyFree( state.pKey );
        state.pKey = NULL;
    }
}

template<>
NTSTATUS
RsaEncImp<ImpSc, AlgRsaEncOaep>::setKey( PCRSAKEY_TESTBLOB pcKeyBlob )
{
    SYMCRYPT_ERROR scError;

    if( state.pKey != NULL )
    {
        SymCryptRsakeyFree( state.pKey );
        state.pKey = NULL;
    }

    if( pcKeyBlob == NULL )
    {
        // Just used to clear the key state to do leak detection
        return STATUS_SUCCESS;
    }

    SYMCRYPT_RSA_PARAMS params;
    params.version = 1;
    params.nBitsOfModulus = pcKeyBlob->nBitsModulus;
    params.nPrimes = 2;
    params.nPubExp = 1;

    state.pKey = SymCryptRsakeyAllocate( &params, 0 );
    CHECK( state.pKey != NULL, "?" );

    PCBYTE ppPrime[2] = {&pcKeyBlob->abPrime1[0], &pcKeyBlob->abPrime2[0] };
    SIZE_T cbPrime[2] = {pcKeyBlob->cbPrime1, pcKeyBlob->cbPrime2 };

    scError = SymCryptRsakeySetValue(
        &pcKeyBlob->abModulus[0], pcKeyBlob->cbModulus,
        &pcKeyBlob->u64PubExp, 1,
        ppPrime, cbPrime, 2,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
        state.pKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
RsaEncImp<ImpSc, AlgRsaEncOaep>::encrypt(
    _In_reads_( cbMsg )             PCBYTE  pbMsg,
                                    SIZE_T  cbMsg,
                                    PCSTR   pcstrHashAlgName,
                                    PCBYTE  pbLabel,
                                    SIZE_T  cbLabel,
    _Out_writes_( cbCiphertext )    PBYTE   pbCiphertext,
                                    SIZE_T  cbCiphertext )
{
    SYMCRYPT_ERROR scError;
    SIZE_T cbResult;
    PCHASH_INFO pInfo;

    UNREFERENCED_PARAMETER( pcstrHashAlgName );
    UNREFERENCED_PARAMETER( pbLabel );
    UNREFERENCED_PARAMETER( cbLabel );

    SIZE_T cbKey = SymCryptRsakeySizeofModulus( state.pKey );
    CHECK( cbCiphertext == cbKey, "Wrong ciphertext size" );

    pInfo = getHashInfo( pcstrHashAlgName);
    scError = SymCryptRsaOaepEncrypt(   state.pKey,
                                        pbMsg, cbMsg,
                                        pInfo->pcHash,
                                        pbLabel, cbLabel,
                                        0,
                                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                        pbCiphertext, cbCiphertext,
                                        &cbResult );

    CHECK( cbResult == cbKey, "Unexpected ciphertext size" );

    return scError == SYMCRYPT_NO_ERROR ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

template<>
NTSTATUS
RsaEncImp<ImpSc, AlgRsaEncOaep>::decrypt(
        _In_reads_( cbCiphertext )      PCBYTE  pbCiphertext,
                                        SIZE_T  cbCiphertext,
                                        PCSTR   pcstrHashAlgName,
                                        PCBYTE  pbLabel,
                                        SIZE_T  cbLabel,
        _Out_writes_to_(cbMsg,*pcbMsg)  PBYTE   pbMsg,
                                        SIZE_T  cbMsg,
                                        SIZE_T *pcbMsg )
{
    SYMCRYPT_ERROR scError;
    SIZE_T cbResult;
    PCHASH_INFO pInfo;

    UNREFERENCED_PARAMETER( pcstrHashAlgName );
    UNREFERENCED_PARAMETER( pbLabel );
    UNREFERENCED_PARAMETER( cbLabel );

    SIZE_T cbKey = SymCryptRsakeySizeofModulus( state.pKey );
    CHECK( cbCiphertext == cbKey, "Wrong ciphertext size" );

    pInfo = getHashInfo( pcstrHashAlgName);
    scError = SymCryptRsaOaepDecrypt(   state.pKey,
                                        pbCiphertext, cbCiphertext,
                                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                        pInfo->pcHash,
                                        pbLabel, cbLabel,
                                        0,
                                        pbMsg, cbMsg,
                                        &cbResult );

    *pcbMsg = cbResult;

    return scError == SYMCRYPT_NO_ERROR ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}


// Rsa Pkcs1 Encryption
/*
template<>
RsaImp<ImpSc, AlgRsaEncPkcs1>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgRsaEncPkcs1>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgRsaEncPkcs1>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgRsaEncPkcs1>;
}

template<>
RsaImp<ImpSc, AlgRsaEncPkcs1>::~RsaImp()
{
}

// Rsa Pkcs1 Decryption

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgRsaDecPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SIZE_T cbDst = 0;

    SymCryptRsaPkcs1Decrypt(
            *((PSYMCRYPT_RSAKEY *) buf1),
            buf3,
            dataSize,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0,
            buf2,
            dataSize,
            &cbDst );
}

template<>
RsaImp<ImpSc, AlgRsaDecPkcs1>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgRsaDecPkcs1>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgRsaEncPkcs1>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgRsaEncPkcs1>;
}

template<>
RsaImp<ImpSc, AlgRsaDecPkcs1>::~RsaImp()
{
}
*/

// Rsa Oaep Encryption
/*
template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgRsaEncOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    BYTE rbResult[1024] = { 0 };
    SIZE_T cbDst = 0;

    sc_RsaKeyPerf( buf1, buf2, keySize );

    scError = SymCryptRsaOaepEncrypt(
                    *((PSYMCRYPT_RSAKEY *) buf1),
                    buf2,
                    keySize - PERF_RSA_OAEP_LESS_BYTES, // This is the maximum size for OAEP
                    PERF_RSA_HASH_ALG_SC,
                    buf2,                               // Use buf2 bytes as the label
                    PERF_RSA_LABEL_LENGTH,
                    0,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    buf3,
                    keySize,
                    &cbDst );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    CHECK( cbDst == keySize, "?" );

    CHECK( sizeof(rbResult) >= keySize, "?" );

    scError = SymCryptRsaOaepDecrypt(
                    *((PSYMCRYPT_RSAKEY *) buf1),
                    buf3,
                    keySize,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    PERF_RSA_HASH_ALG_SC,
                    buf2,                            // Use buf2 bytes as label
                    PERF_RSA_LABEL_LENGTH,
                    0,
                    rbResult,
                    keySize,
                    &cbDst );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    CHECK( cbDst == keySize - PERF_RSA_OAEP_LESS_BYTES, "?" );
    CHECK( memcmp(buf2, rbResult, cbDst) == 0, "?" );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgRsaEncOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgRsaEncOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SIZE_T cbDst = 0;

    SymCryptRsaOaepEncrypt(
            *((PSYMCRYPT_RSAKEY *) buf1),
            buf2,
            dataSize - PERF_RSA_OAEP_LESS_BYTES,    // This is the maximum size for OAEP
            PERF_RSA_HASH_ALG_SC,
            buf2,                                   // Use buf2 bytes as label
            PERF_RSA_LABEL_LENGTH,
            0,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            buf3,
            dataSize,
            &cbDst );
}
*/

/*
template<>
RsaImp<ImpSc, AlgRsaEncOaep>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgRsaEncOaep>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgRsaEncOaep>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgRsaEncOaep>;
}

template<>
RsaImp<ImpSc, AlgRsaEncOaep>::~RsaImp()
{
}

// Rsa Oaep Decryption

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgRsaDecOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SIZE_T cbDst = 0;

    SymCryptRsaOaepDecrypt(
            *((PSYMCRYPT_RSAKEY *) buf1),
            buf3,
            dataSize,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            PERF_RSA_HASH_ALG_SC,
            buf2,                            // Use buf2 bytes as label
            PERF_RSA_LABEL_LENGTH,
            0,
            buf2,
            dataSize,
            &cbDst );
}

template<>
RsaImp<ImpSc, AlgRsaDecOaep>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgRsaDecOaep>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgRsaEncOaep>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgRsaEncOaep>;
}

template<>
RsaImp<ImpSc, AlgRsaDecOaep>::~RsaImp()
{
}

template<>
RsaImp<ImpSc, AlgRsaSignPkcs1>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgRsaSignPkcs1>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgRsaSignPkcs1>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgRsaSignPkcs1>;
}

template<>
RsaImp<ImpSc, AlgRsaSignPkcs1>::~RsaImp()
{
}

// Rsa Pkcs1 Verify

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgRsaVerifyPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SymCryptRsaPkcs1Verify(
            *((PSYMCRYPT_RSAKEY *) buf1),
            buf2,
            PERF_RSA_HASH_ALG_SIZE,
            buf3,
            dataSize,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            (PSYMCRYPT_OID) (buf2+PERF_RSA_HASH_ALG_SIZE),
            1,
            0 );
}

template<>
RsaImp<ImpSc, AlgRsaVerifyPkcs1>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgRsaVerifyPkcs1>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgRsaSignPkcs1>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgRsaSignPkcs1>;
}

template<>
RsaImp<ImpSc, AlgRsaVerifyPkcs1>::~RsaImp()
{
}

template<>
RsaImp<ImpSc, AlgRsaSignPss>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgRsaSignPss>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgRsaSignPss>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgRsaSignPss>;
}

template<>
RsaImp<ImpSc, AlgRsaSignPss>::~RsaImp()
{
}

// Rsa Pss Verify

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgRsaVerifyPss>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SymCryptRsaPssVerify(
            *((PSYMCRYPT_RSAKEY *) buf1),
            buf2,
            PERF_RSA_HASH_ALG_SIZE,
            buf3,
            dataSize,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            PERF_RSA_HASH_ALG_SC,
            PERF_RSA_SALT_LENGTH,
            0 );
}

template<>
RsaImp<ImpSc, AlgRsaVerifyPss>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgRsaVerifyPss>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgRsaSignPss>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgRsaSignPss>;
}

template<>
RsaImp<ImpSc, AlgRsaVerifyPss>::~RsaImp()
{
}
*/

//============================

VOID
DlgroupSetup( PBYTE buf1, SIZE_T keySize )
{
    SYMCRYPT_ERROR scError;

    PCDLGROUP_TESTBLOB pBlob = dlgroupForSize( keySize * 8 );

    CHECK( pBlob != NULL, "?" );

    PSYMCRYPT_DLGROUP pGroup = SymCryptDlgroupCreate( buf1 + 64, PERF_BUFFER_SIZE/2, pBlob->nBitsP, 8*pBlob->cbPrimeQ );

    CHECK( pGroup != NULL, "Could not create group" );

    scError = SymCryptDlgroupSetValue(
        &pBlob->abPrimeP[0], pBlob->cbPrimeP,
        pBlob->cbPrimeQ == 0 ? NULL : &pBlob->abPrimeQ[0], pBlob->cbPrimeQ,
        &pBlob->abGenG[0], pBlob->cbPrimeP,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        pBlob->pHashAlgorithm,
        &pBlob->abSeed[0], pBlob->cbSeed,
        pBlob->genCounter,
        pBlob->fipsStandard,
        pGroup );

    CHECK( scError == SYMCRYPT_NO_ERROR, "Error setting group values" );

    *((PSYMCRYPT_DLGROUP *) buf1) = pGroup;
}



// Table with the DL groups sizes and pointers to the groups
struct {
    SIZE_T              keySize;        // Always equal to cbPrimeP
    PSYMCRYPT_DLGROUP   pDlgroup;
} g_precomputedDlGroups[] = {
    {  64, NULL },
    { 128, NULL },
    { 256, NULL },
};

void
SetupDlGroup( PBYTE buf1, SIZE_T keySize )
{
    int i = 0;
    BOOLEAN bFound = FALSE;

    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PSYMCRYPT_DLGROUP pDlgroup = NULL;

    for( i=0; i < ARRAY_SIZE(g_precomputedDlGroups); i++ )
    {
        if ( keySize == g_precomputedDlGroups[i].keySize )
        {
            bFound = TRUE;

            if ( g_precomputedDlGroups[i].pDlgroup == NULL )
            {
                pDlgroup = SymCryptDlgroupAllocate( 8*((UINT32)g_precomputedDlGroups[i].keySize), 0 );
                CHECK( pDlgroup != NULL, "?" );

                scError = SymCryptDlgroupGenerate( SymCryptSha256Algorithm, SYMCRYPT_DLGROUP_FIPS_LATEST, pDlgroup );      // This algorithm is safe for all our sizes
                CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

                g_precomputedDlGroups[i].pDlgroup = pDlgroup;
            }

            break;
        }
    }

    CHECK( bFound, "?" );

    *((PSYMCRYPT_DLGROUP *) buf1) = g_precomputedDlGroups[i].pDlgroup;
}

void
SetupSymCryptDsaAndDh( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    PCSYMCRYPT_DLGROUP pDlgroup = *((PCSYMCRYPT_DLGROUP *)buf1);

    PSYMCRYPT_DLKEY * pPtrs = ((PSYMCRYPT_DLKEY *) buf2);

    SIZE_T buff2Offset = ((2*sizeof(PSYMCRYPT_DLKEY) + SYMCRYPT_ASYM_ALIGN_VALUE - 1)/SYMCRYPT_ASYM_ALIGN_VALUE )*SYMCRYPT_ASYM_ALIGN_VALUE;
    UINT32 dlkeysize = SymCryptSizeofDlkeyFromDlgroup( pDlgroup );

    SIZE_T buff3Offset = sizeof(UINT32);
    UINT32 signatureSize = 0;
    PUINT32 puiSignatureSize = NULL;

    pPtrs[0] = SymCryptDlkeyCreate( buf2 + buff2Offset, dlkeysize, pDlgroup );
    scError = SymCryptDlkeyGenerate( 0, pPtrs[0] );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    pPtrs[1] = SymCryptDlkeyCreate( buf2 + buff2Offset + dlkeysize, dlkeysize, pDlgroup );
    scError = SymCryptDlkeyGenerate( 0, pPtrs[1] );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    signatureSize = 2*SymCryptDlkeySizeofPrivateKey( pPtrs[0] );
    puiSignatureSize = (PUINT32) buf3;

    CHECK( buff3Offset + SYMCRYPT_MAX( signatureSize, SymCryptDlkeySizeofPublicKey( pPtrs[0] ) ) <= SCRATCH_BUF_SIZE,
           "Destination buffer cannot fit the DSA signature or the DH secret" );

    *puiSignatureSize = signatureSize;

    // Verify that DH can work
    scError = SymCryptDhSecretAgreement(
                ((PSYMCRYPT_DLKEY *) buf2)[0],
                ((PSYMCRYPT_DLKEY *) buf2)[1],
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0,
                buf3 + sizeof(UINT32),
                SymCryptDlkeySizeofPublicKey( pPtrs[0] ));
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptDhSecretAgreement failed" );

    // Same for DSA
    scError = SymCryptDsaSign(
                ((PSYMCRYPT_DLKEY *) buf2)[0],
                buf2,           // Sign the keys' buffer
                SymCryptDlkeySizeofPrivateKey( ((PSYMCRYPT_DLKEY *)buf2)[0] ),
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0,
                buf3 + sizeof(UINT32),
                *((PUINT32) buf3) ) ;
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptDsaSign failed" );

    // Verify the signature to make sure everything is ok
    scError = SymCryptDsaVerify(
                ((PSYMCRYPT_DLKEY *) buf2)[0],
                buf2,           // Sign the keys' buffer
                SymCryptDlkeySizeofPrivateKey( ((PSYMCRYPT_DLKEY *)buf2)[0] ),
                buf3 + sizeof(UINT32),
                *((PUINT32) buf3),
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptDsaVerify failed" );
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgDsaSign>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    SetupDlGroup( buf1, keySize );

    SetupSymCryptDsaAndDh( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgDsaSign>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgDsaSign>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( dataSize );

    SymCryptDsaSign(
                ((PSYMCRYPT_DLKEY *) buf2)[0],
                buf2,           // Sign the keys' buffer
                SymCryptDlkeySizeofPrivateKey( ((PSYMCRYPT_DLKEY *)buf2)[0] ),
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0,
                buf3 + sizeof(UINT32),
                *((PUINT32) buf3) );
}

template<>
DlImp<ImpSc, AlgDsaSign>::DlImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgDsaSign>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgDsaSign>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgDsaSign>;
}

template<>
DlImp<ImpSc, AlgDsaSign>::~DlImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgDsaVerify>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    SetupDlGroup( buf1, keySize );
    SetupSymCryptDsaAndDh( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgDsaVerify>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgDsaVerify>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( dataSize );

    SymCryptDsaVerify(
                ((PSYMCRYPT_DLKEY *) buf2)[0],
                buf2,           // Sign the keys' buffer
                SymCryptDlkeySizeofPrivateKey( ((PSYMCRYPT_DLKEY *)buf2)[0] ),
                buf3 + sizeof(UINT32),
                *((PUINT32) buf3),
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0 );
}

template<>
DlImp<ImpSc, AlgDsaVerify>::DlImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgDsaVerify>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgDsaVerify>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgDsaVerify>;
}

template<>
DlImp<ImpSc, AlgDsaVerify>::~DlImp()
{
}

//============================

PSYMCRYPT_DLKEY
dlkeyObjectFromTestBlob( PCSYMCRYPT_DLGROUP pGroup, PCDLKEY_TESTBLOB pBlob )
{
    PSYMCRYPT_DLKEY pRes;
    SYMCRYPT_ERROR scError;

    pRes = SymCryptDlkeyAllocate( pGroup );
    CHECK( pRes != NULL, "?" );

    scError = SymCryptDlkeySetValue(    &pBlob->abPrivKey[0], pBlob->cbPrivKey,
                                        &pBlob->abPubKey[0], pBlob->pGroup->cbPrimeP,
                                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                        SYMCRYPT_FLAG_DLKEY_VERIFY,     // Verify the key is correct
                                        pRes );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error importing key" );

    return pRes;
}

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgDh>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SYMCRYPT_ERROR scError;

    UNREFERENCED_PARAMETER( buf3 );

    DlgroupSetup( buf1, keySize );

    // Set up two keys in buf2
    PSYMCRYPT_DLGROUP pGroup = *(PSYMCRYPT_DLGROUP *) buf1;

    PSYMCRYPT_DLKEY pKey1 = SymCryptDlkeyCreate( buf2 + 64, PERF_BUFFER_SIZE/4, pGroup );
    PSYMCRYPT_DLKEY pKey2 = SymCryptDlkeyCreate( buf2 + 64 + PERF_BUFFER_SIZE/4, PERF_BUFFER_SIZE/4, pGroup );

    CHECK( pKey1 != NULL && pKey2 != NULL, "Failed to create keys" );

    scError = SymCryptDlkeyGenerate( 0, pKey1 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    scError = SymCryptDlkeyGenerate( 0, pKey2 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    ((PSYMCRYPT_DLKEY *) buf2)[0] = pKey1;
    ((PSYMCRYPT_DLKEY *) buf2)[1] = pKey2;
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgDh>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}


template<>
VOID
algImpDataPerfFunction< ImpSc, AlgDh>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_ERROR scError;

    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( dataSize );

    PSYMCRYPT_DLGROUP pGroup = *(PSYMCRYPT_DLGROUP *) buf1;

    PSYMCRYPT_DLKEY pKey = SymCryptDlkeyCreate( buf3, (1 << 16), pGroup );
    CHECK( pKey != NULL, "?" );

    scError = SymCryptDlkeyGenerate( 0, pKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    scError = SymCryptDlkeyGetValue( pKey, NULL, 0, buf3 + (1 << 16), pGroup->cbPrimeP, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
}

template<>
VOID
algImpDecryptPerfFunction< ImpSc, AlgDh>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf1 );

    SymCryptDhSecretAgreement(
                ((PSYMCRYPT_DLKEY *) buf2)[0],
                ((PSYMCRYPT_DLKEY *) buf2)[1],
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0,
                buf3,
                dataSize );     // This will be the same as the key size
}

template<>
DhImp<ImpSc, AlgDh>::DhImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgDh>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction< ImpSc, AlgDh>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgDh>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgDh>;

    state.pGroup = NULL;
    state.pKey = NULL;
}

template<>
DhImp<ImpSc, AlgDh>::~DhImp()
{
    if( state.pKey != NULL )
    {
        SymCryptDlkeyFree( state.pKey );
        state.pKey = NULL;
    }
    if( state.pGroup != NULL )
    {
        SymCryptDlgroupFree( state.pGroup );
        state.pGroup = NULL;
    }
}

template<>
NTSTATUS
DhImp<ImpSc, AlgDh>::setKey( _In_    PCDLKEY_TESTBLOB    pcKeyBlob )
{
    if( state.pKey != NULL )
    {
        SymCryptDlkeyFree( state.pKey );
        state.pKey = NULL;
    }
    if( state.pGroup != NULL )
    {
        SymCryptDlgroupFree( state.pGroup );
        state.pGroup = NULL;
    }

    if( pcKeyBlob != NULL )
    {
        state.pGroup = dlgroupObjectFromTestBlob( pcKeyBlob->pGroup );
        state.pKey = dlkeyObjectFromTestBlob( state.pGroup, pcKeyBlob );

        CHECK( state.pGroup != NULL && state.pKey != NULL, "?" );
    }

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
DhImp<ImpSc, AlgDh>::sharedSecret(
        _In_                        PCDLKEY_TESTBLOB    pcPubkey,
        _Out_writes_( cbSecret )    PBYTE               pbSecret,
                                    SIZE_T              cbSecret )
{
    PSYMCRYPT_DLKEY pKey2;
    SYMCRYPT_ERROR scError;

    pKey2 = dlkeyObjectFromTestBlob( state.pGroup, pcPubkey );
    CHECK( pKey2 != NULL, "?")

    scError = SymCryptDhSecretAgreement(    state.pKey,
                                            pKey2,
                                            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                            0,
                                            pbSecret, cbSecret );

    SymCryptDlkeyFree( pKey2 );

    return scError == SYMCRYPT_NO_ERROR ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}


template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgDsa>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SYMCRYPT_ERROR scError;

    UNREFERENCED_PARAMETER( buf3 );

    DlgroupSetup( buf1, keySize );  // Set buf1 to contain a DL group of size keySize

    // Set up a keys in buf2
    PSYMCRYPT_DLGROUP pGroup = *(PSYMCRYPT_DLGROUP *) buf1;

    PSYMCRYPT_DLKEY pKey = SymCryptDlkeyCreate( buf2 + 64, PERF_BUFFER_SIZE/4, pGroup );

    CHECK( pKey != NULL, "Failed to create key" );

    scError = SymCryptDlkeyGenerate( 0, pKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    ((PSYMCRYPT_DLKEY *) buf2)[0] = pKey;
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgDsa>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}


template<>
VOID
algImpDataPerfFunction< ImpSc, AlgDsa>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_ERROR scError;

    UNREFERENCED_PARAMETER( dataSize );

    PSYMCRYPT_DLKEY pKey = *(PSYMCRYPT_DLKEY *) buf2;
    PSYMCRYPT_DLGROUP pGroup = *(PSYMCRYPT_DLGROUP *) buf1;

    scError = SymCryptDsaSign(  pKey,
                                buf3, 32,
                                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                0,
                                buf3 + 64, 2 * pGroup->cbPrimeQ );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
}

template<>
VOID
algImpDecryptPerfFunction< ImpSc, AlgDsa>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_ERROR scError;

    UNREFERENCED_PARAMETER( dataSize );

    PSYMCRYPT_DLKEY pKey = *(PSYMCRYPT_DLKEY *) buf2;
    PSYMCRYPT_DLGROUP pGroup = *(PSYMCRYPT_DLGROUP *) buf1;

    scError = SymCryptDsaVerify(pKey,
                                buf3, 32,
                                buf3 + 64, 2 * pGroup->cbPrimeQ,
                                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
}

template<>
DsaImp<ImpSc, AlgDsa>::DsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgDsa>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction< ImpSc, AlgDsa>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgDsa>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgDsa>;

    state.pGroup = NULL;
    state.pKey = NULL;
}

template<>
DsaImp<ImpSc, AlgDsa>::~DsaImp()
{
    if( state.pKey != NULL )
    {
        SymCryptDlkeyFree( state.pKey );
        state.pKey = NULL;
    }
    if( state.pGroup != NULL )
    {
        SymCryptDlgroupFree( state.pGroup );
        state.pGroup = NULL;
    }
}

template<>
NTSTATUS
DsaImp<ImpSc, AlgDsa>::setKey( _In_    PCDLKEY_TESTBLOB    pcKeyBlob )
{
    if( state.pKey != NULL )
    {
        SymCryptDlkeyFree( state.pKey );
        state.pKey = NULL;
    }
    if( state.pGroup != NULL )
    {
        SymCryptDlgroupFree( state.pGroup );
        state.pGroup = NULL;
    }

    if( pcKeyBlob != NULL )
    {
        state.pGroup = dlgroupObjectFromTestBlob( pcKeyBlob->pGroup );
        state.pKey = dlkeyObjectFromTestBlob( state.pGroup, pcKeyBlob );

        CHECK( state.pGroup != NULL && state.pKey != NULL, "?" );
    }

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
DsaImp<ImpSc, AlgDsa>::sign(
        _In_reads_( cbHash)     PCBYTE  pbHash,
                                SIZE_T  cbHash,             // Can be any size, but often = size of Q
        _Out_writes_( cbSig )   PBYTE   pbSig,
                                SIZE_T  cbSig )
{
    SYMCRYPT_ERROR scError;

    scError = SymCryptDsaSign(  state.pKey,
                                pbHash, cbHash,
                                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                0,
                                pbSig, cbSig );

    return scError == SYMCRYPT_NO_ERROR ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

template<>
NTSTATUS
DsaImp<ImpSc, AlgDsa>::verify(
    _In_reads_( cbHash)     PCBYTE  pbHash,
                            SIZE_T  cbHash,
    _In_reads_( cbSig )     PCBYTE  pbSig,
                            SIZE_T  cbSig )
{
    SYMCRYPT_ERROR scError;

    scError = SymCryptDsaVerify(    state.pKey,
                                    pbHash, cbHash,
                                    pbSig, cbSig,
                                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                    0 );

    return scError == SYMCRYPT_NO_ERROR ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}



template<>
DlImp<ImpSc, AlgDh>::DlImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgDh>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgDh>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgDh>;
}

template<>
DlImp<ImpSc, AlgDh>::~DlImp()
{
}

//============================

// Global table with the curve pointers (same size as the g_exKeyToCurve)
PCSYMCRYPT_ECURVE   g_pCurves[ARRAY_SIZE(g_exKeyToCurve)] = { 0 };

void
SetupSymCryptCurves( PBYTE buf1, SIZE_T keySize )
{
    int i = 0;
    BOOLEAN bKeyFound = FALSE;
    PCSYMCRYPT_ECURVE pCurve = NULL;

    for( i=0; i < ARRAY_SIZE(g_exKeyToCurve); i++ )
    {
        if ( keySize == g_exKeyToCurve[i].exKeyParam )
        {
            bKeyFound = TRUE;
            break;
        }
    }

    CHECK( bKeyFound, "?" );

    if (g_pCurves[i] == NULL)
    {
        pCurve = SymCryptEcurveAllocate( g_exKeyToCurve[i].pParams, 0 );

        g_pCurves[i] = pCurve;
    }
    else
    {
        pCurve = g_pCurves[i];
    }

    CHECK( pCurve != NULL, "?");

    *((PCSYMCRYPT_ECURVE *) buf1) = pCurve;
}

void
SetupSymCryptEcpoints( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    PSYMCRYPT_INT piScalar;

    PCSYMCRYPT_ECURVE pCurve = *((PCSYMCRYPT_ECURVE *)buf1);

    UINT32 ecpointSize = SymCryptSizeofEcpointFromCurve( pCurve );
    UINT32 scalarSize = SymCryptSizeofIntFromDigits( SymCryptEcurveDigitsofScalarMultiplier(pCurve) );

    PSYMCRYPT_ECPOINT * pPtrs = ((PSYMCRYPT_ECPOINT *) buf2);
    pPtrs[0] = SymCryptEcpointCreate( buf2 + 32, ecpointSize, pCurve );
    pPtrs[1] = SymCryptEcpointCreate( buf2 + 32 + ecpointSize, ecpointSize, pCurve );

    piScalar = SymCryptIntCreate( buf2 + 32 + 2*ecpointSize, scalarSize, SymCryptEcurveDigitsofScalarMultiplier(pCurve) );
    pPtrs[2] = (PSYMCRYPT_ECPOINT) piScalar;

    ((PSYMCRYPT_ECPOINT *) buf3)[0] = SymCryptEcpointCreate( buf3 + 32, ecpointSize, pCurve );

    CHECK( ecpointSize + 32 <= SCRATCH_BUF_OFFSET, "Destination ECPOINT overlaps with scratch buffer" );

    SymCryptEcpointSetRandom( pCurve, piScalar, pPtrs[0], buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );

    SymCryptEcpointSetRandom( pCurve, piScalar, pPtrs[1], buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );

    if( pCurve->type != SYMCRYPT_ECURVE_TYPE_MONTGOMERY )
    {
        SymCryptEcpointSetZero( pCurve, ((PSYMCRYPT_ECPOINT *) buf3)[0], buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );
    }
}

void
SetupSymCryptEcdsaAndEcdh( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    PCSYMCRYPT_ECURVE pCurve = *((PCSYMCRYPT_ECURVE *)buf1);

    UINT32 eckeySize = SymCryptSizeofEckeyFromCurve( pCurve );
    UINT32 signatureSize = 2 * SymCryptEcurveSizeofFieldElement( pCurve );

    PSYMCRYPT_ECKEY * pPtrs = ((PSYMCRYPT_ECKEY *) buf2);
    pPtrs[0] = SymCryptEckeyCreate( buf2 + 32, eckeySize, pCurve );

    scError = SymCryptEckeySetRandom( 0, pPtrs[0] );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    pPtrs[1] = (PSYMCRYPT_ECKEY) ((PBYTE)buf2 + 32 + eckeySize);    // This will hold the hash of the message

    CHECK( 32 + eckeySize + SYMCRYPT_SHA512_RESULT_SIZE <= SCRATCH_BUF_SIZE, "ECKEY and hash cannot fit into scratch buffer" );
    GENRANDOM( (PBYTE)pPtrs[1], SYMCRYPT_SHA512_RESULT_SIZE );

    PUINT32 puiSignatureSize = (PUINT32) buf3;

    CHECK( sizeof(UINT32) + signatureSize <= SCRATCH_BUF_SIZE, "Destination buffer cannot fit the signature" );

    *puiSignatureSize = signatureSize;

    // Verify that ECDH can work
    CHECK( SymCryptEcurveSizeofFieldElement( *(PSYMCRYPT_ECURVE *) buf1 ) <= *((PUINT32)buf3), "Buffer 3 too small for ECDH");
    scError = SymCryptEcDhSecretAgreement(
                ((PSYMCRYPT_ECKEY *) buf2)[0],
                ((PSYMCRYPT_ECKEY *) buf2)[0],      // Same private and public key
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0,
                buf3 + sizeof(UINT32),
                SymCryptEcurveSizeofFieldElement( *(PSYMCRYPT_ECURVE *) buf1 ));
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptEcDhSecretAgreement failed" );

    // Same for ECDSA
    scError = SymCryptEcDsaSign(
                    pPtrs[0],
                    (PBYTE) pPtrs[1],
                    SYMCRYPT_SHA512_RESULT_SIZE,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0,
                    buf3 + sizeof(UINT32),
                    signatureSize );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptEcDsaSign failed" );

    if (pCurve->type != SYMCRYPT_ECURVE_TYPE_MONTGOMERY)
    {
        // Verify the signature to make sure everything is ok
        scError = SymCryptEcDsaVerify(
                    ((PSYMCRYPT_ECKEY *) buf2)[0],
                    ((PBYTE *) buf2)[1],
                    SYMCRYPT_SHA512_RESULT_SIZE,
                    buf3 + sizeof(UINT32),
                    *((PUINT32)buf3),
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0 );
        CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptEcDsaVerify failed" );
    }
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgEcurveAllocate>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    int i = 0;
    BOOLEAN bKeyFound = FALSE;

    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    for( i=0; i < ARRAY_SIZE(g_exKeyToCurve); i++ )
    {
        if ( keySize == g_exKeyToCurve[i].exKeyParam )
        {
            bKeyFound = TRUE;
            break;
        }
    }

    CHECK( bKeyFound, "?" );

    *((PCSYMCRYPT_ECURVE_PARAMS *) buf1) = g_exKeyToCurve[i].pParams;
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgEcurveAllocate>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );

    SymCryptEcurveFree( *((PSYMCRYPT_ECURVE *) buf3) );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgEcurveAllocate>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( dataSize );

    *((PSYMCRYPT_ECURVE *) buf3) = SymCryptEcurveAllocate( *((PCSYMCRYPT_ECURVE_PARAMS *) buf1), 0 );
}


template<>
EccImp<ImpSc, AlgEcurveAllocate>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgEcurveAllocate>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgEcurveAllocate>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgEcurveAllocate>;
}

template<>
EccImp<ImpSc, AlgEcurveAllocate>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgEcpointSetZero>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves( buf1, keySize );
    SetupSymCryptEcpoints( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgEcpointSetZero>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgEcpointSetZero>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( dataSize );

    SymCryptEcpointSetZero(
        *(PSYMCRYPT_ECURVE *) buf1,
        ((PSYMCRYPT_ECPOINT *) buf3)[0],
        buf3 + SCRATCH_BUF_OFFSET,
        SCRATCH_BUF_SIZE );
}


template<>
EccImp<ImpSc, AlgEcpointSetZero>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgEcpointSetZero>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgEcpointSetZero>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgEcpointSetZero>;
}

template<>
EccImp<ImpSc, AlgEcpointSetZero>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgEcpointSetDistinguished>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves( buf1, keySize );
    SetupSymCryptEcpoints( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgEcpointSetDistinguished>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgEcpointSetDistinguished>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( dataSize );

    SymCryptEcpointSetDistinguishedPoint(
        *(PSYMCRYPT_ECURVE *) buf1,
        ((PSYMCRYPT_ECPOINT *) buf3)[0],
        buf3 + SCRATCH_BUF_OFFSET,
        SCRATCH_BUF_SIZE );
}


template<>
EccImp<ImpSc, AlgEcpointSetDistinguished>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgEcpointSetDistinguished>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgEcpointSetDistinguished>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgEcpointSetDistinguished>;
}

template<>
EccImp<ImpSc, AlgEcpointSetDistinguished>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgEcpointSetRandom>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves( buf1, keySize );
    SetupSymCryptEcpoints( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgEcpointSetRandom>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgEcpointSetRandom>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );

    SymCryptEcpointSetRandom(
                    *(PSYMCRYPT_ECURVE *) buf1,
                    ((PSYMCRYPT_INT *) buf2)[2],
                    ((PSYMCRYPT_ECPOINT *) buf3)[0],
                    buf3 + SCRATCH_BUF_OFFSET,
                    SCRATCH_BUF_SIZE );
}


template<>
EccImp<ImpSc, AlgEcpointSetRandom>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgEcpointSetRandom>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgEcpointSetRandom>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgEcpointSetRandom>;
}

template<>
EccImp<ImpSc, AlgEcpointSetRandom>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgEcpointIsEqual>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves( buf1, keySize );
    SetupSymCryptEcpoints( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgEcpointIsEqual>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgEcpointIsEqual>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( dataSize );

    SymCryptEcpointIsEqual(
        *(PSYMCRYPT_ECURVE *) buf1,
        ((PSYMCRYPT_ECPOINT *) buf2)[0],
        ((PSYMCRYPT_ECPOINT *) buf2)[1],
        SYMCRYPT_FLAG_ECPOINT_EQUAL | SYMCRYPT_FLAG_ECPOINT_NEG_EQUAL,
        buf3 + SCRATCH_BUF_OFFSET,
        SCRATCH_BUF_SIZE );
}


template<>
EccImp<ImpSc, AlgEcpointIsEqual>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgEcpointIsEqual>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgEcpointIsEqual>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgEcpointIsEqual>;
}

template<>
EccImp<ImpSc, AlgEcpointIsEqual>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgEcpointIsZero>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves( buf1, keySize );
    SetupSymCryptEcpoints( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgEcpointIsZero>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgEcpointIsZero>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( dataSize );

    SymCryptEcpointIsZero(
        *(PSYMCRYPT_ECURVE *) buf1,
        ((PSYMCRYPT_ECPOINT *) buf2)[0],
        buf3 + SCRATCH_BUF_OFFSET,
        SCRATCH_BUF_SIZE );
}


template<>
EccImp<ImpSc, AlgEcpointIsZero>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgEcpointIsZero>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgEcpointIsZero>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgEcpointIsZero>;
}

template<>
EccImp<ImpSc, AlgEcpointIsZero>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgEcpointOnCurve>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves( buf1, keySize );
    SetupSymCryptEcpoints( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgEcpointOnCurve>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgEcpointOnCurve>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( dataSize );

    SymCryptEcpointOnCurve(
        *(PSYMCRYPT_ECURVE *) buf1,
        ((PSYMCRYPT_ECPOINT *) buf2)[0],
        buf3 + SCRATCH_BUF_OFFSET,
        SCRATCH_BUF_SIZE );
}


template<>
EccImp<ImpSc, AlgEcpointOnCurve>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgEcpointOnCurve>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgEcpointOnCurve>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgEcpointOnCurve>;
}

template<>
EccImp<ImpSc, AlgEcpointOnCurve>::~EccImp()
{
}


//============================

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgEcpointAdd>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves( buf1, keySize );
    SetupSymCryptEcpoints( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgEcpointAdd>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgEcpointAdd>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );

    SymCryptEcpointAdd(
        *(PSYMCRYPT_ECURVE *) buf1,
        ((PSYMCRYPT_ECPOINT *) buf2)[0],
        ((PSYMCRYPT_ECPOINT *) buf2)[1],
        ((PSYMCRYPT_ECPOINT *) buf3)[0],
        0,                                  // Side-channel safe version
        buf3 + SCRATCH_BUF_OFFSET,
        SCRATCH_BUF_SIZE );
}


template<>
EccImp<ImpSc, AlgEcpointAdd>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgEcpointAdd>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgEcpointAdd>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgEcpointAdd>;
}

template<>
EccImp<ImpSc, AlgEcpointAdd>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgEcpointAddDiffNz>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves( buf1, keySize );

    do {
        SetupSymCryptEcpoints( buf1, buf2, buf3 );
    }
    while (SymCryptEcpointIsEqual(
                *(PSYMCRYPT_ECURVE *) buf1,
                ((PSYMCRYPT_ECPOINT *) buf2)[0],
                ((PSYMCRYPT_ECPOINT *) buf2)[1],
                SYMCRYPT_FLAG_ECPOINT_EQUAL | SYMCRYPT_FLAG_ECPOINT_NEG_EQUAL,
                buf3 + SCRATCH_BUF_OFFSET,
                SCRATCH_BUF_SIZE ) );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgEcpointAddDiffNz>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgEcpointAddDiffNz>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );

    SymCryptEcpointAddDiffNonZero(
        *(PSYMCRYPT_ECURVE *) buf1,
        ((PSYMCRYPT_ECPOINT *) buf2)[0],
        ((PSYMCRYPT_ECPOINT *) buf2)[1],
        ((PSYMCRYPT_ECPOINT *) buf3)[0],
        buf3 + SCRATCH_BUF_OFFSET,
        SCRATCH_BUF_SIZE );
}


template<>
EccImp<ImpSc, AlgEcpointAddDiffNz>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgEcpointAddDiffNz>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgEcpointAddDiffNz>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgEcpointAddDiffNz>;
}

template<>
EccImp<ImpSc, AlgEcpointAddDiffNz>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgEcpointDouble>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves( buf1, keySize );

    do {
        SetupSymCryptEcpoints( buf1, buf2, buf3 );
    }
    while (SymCryptEcpointIsEqual(
                *(PSYMCRYPT_ECURVE *) buf1,
                ((PSYMCRYPT_ECPOINT *) buf2)[0],
                ((PSYMCRYPT_ECPOINT *) buf3)[0],        // buf3 is set to the zero point in SetupSymCryptEcpoints
                SYMCRYPT_FLAG_ECPOINT_EQUAL | SYMCRYPT_FLAG_ECPOINT_NEG_EQUAL,
                buf3 + SCRATCH_BUF_OFFSET,
                SCRATCH_BUF_SIZE ) );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgEcpointDouble>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgEcpointDouble>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );

    SymCryptEcpointDouble(
        *(PSYMCRYPT_ECURVE *) buf1,
        ((PSYMCRYPT_ECPOINT *) buf2)[0],
        ((PSYMCRYPT_ECPOINT *) buf3)[0],
        0,                                  // Side-channel safe version
        buf3 + SCRATCH_BUF_OFFSET,
        SCRATCH_BUF_SIZE );
}


template<>
EccImp<ImpSc, AlgEcpointDouble>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgEcpointDouble>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgEcpointDouble>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgEcpointDouble>;
}

template<>
EccImp<ImpSc, AlgEcpointDouble>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgEcpointScalarMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves( buf1, keySize );
    SetupSymCryptEcpoints( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgEcpointScalarMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgEcpointScalarMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );

    SymCryptEcpointScalarMul(
                *(PSYMCRYPT_ECURVE *) buf1,
                ((PSYMCRYPT_INT *) buf2)[2],
                ((PSYMCRYPT_ECPOINT *) buf2)[0],
                0,
                ((PSYMCRYPT_ECPOINT *) buf3)[0],
                buf3 + SCRATCH_BUF_OFFSET,
                SCRATCH_BUF_SIZE );
}


template<>
EccImp<ImpSc, AlgEcpointScalarMul>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgEcpointScalarMul>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgEcpointScalarMul>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgEcpointScalarMul>;
}

template<>
EccImp<ImpSc, AlgEcpointScalarMul>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgEcdsaSign>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves( buf1, keySize );
    SetupSymCryptEcdsaAndEcdh( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgEcdsaSign>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpSc, AlgEcdsaSign>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( dataSize );

    SymCryptEcDsaSign(
                    ((PSYMCRYPT_ECKEY *) buf2)[0],
                    ((PBYTE *) buf2)[1],
                    SYMCRYPT_SHA512_RESULT_SIZE,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0,
                    buf3 + sizeof(UINT32),
                    *((PUINT32)buf3) );
}


template<>
EccImp<ImpSc, AlgEcdsaSign>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgEcdsaSign>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgEcdsaSign>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgEcdsaSign>;
}

template<>
EccImp<ImpSc, AlgEcdsaSign>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgEcdsaVerify>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves( buf1, keySize );
    SetupSymCryptEcdsaAndEcdh( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgEcdsaVerify>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpSc, AlgEcdsaVerify>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( dataSize );

    SymCryptEcDsaVerify(
                    ((PSYMCRYPT_ECKEY *) buf2)[0],
                    ((PBYTE *) buf2)[1],
                    SYMCRYPT_SHA512_RESULT_SIZE,
                    buf3 + sizeof(UINT32),
                    *((PUINT32)buf3),
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0 );
}


template<>
EccImp<ImpSc, AlgEcdsaVerify>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgEcdsaVerify>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgEcdsaVerify>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgEcdsaVerify>;
}

template<>
EccImp<ImpSc, AlgEcdsaVerify>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgEcdh>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves( buf1, keySize );
    SetupSymCryptEcdsaAndEcdh( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc, AlgEcdh>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpSc, AlgEcdh>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );

    SymCryptEcDhSecretAgreement(
                ((PSYMCRYPT_ECKEY *) buf2)[0],
                ((PSYMCRYPT_ECKEY *) buf2)[0],      // Same private and public key
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0,
                buf3 + sizeof(UINT32),
                SymCryptEcurveSizeofFieldElement( *(PSYMCRYPT_ECURVE *) buf1 ));
}


template<>
EccImp<ImpSc, AlgEcdh>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgEcdh>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgEcdh>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgEcdh>;
}

template<>
EccImp<ImpSc, AlgEcdh>::~EccImp()
{
}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpSc, AlgIEEE802_11SaeCustom>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SymCrypt802_11SaeCustomInit( (PSYMCRYPT_802_11_SAE_CUSTOM_STATE) buf1, &buf2[0], &buf2[6], &buf2[12], keySize, NULL, NULL, NULL );

    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpSc,AlgIEEE802_11SaeCustom>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    SymCrypt802_11SaeCustomDestroy( (PSYMCRYPT_802_11_SAE_CUSTOM_STATE) buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpSc, AlgIEEE802_11SaeCustom>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SymCrypt802_11SaeCustomCommitCreate( (PSYMCRYPT_802_11_SAE_CUSTOM_STATE) buf1, buf2, buf3 );

    UNREFERENCED_PARAMETER( dataSize );
}

template<>
VOID
algImpDecryptPerfFunction<ImpSc,AlgIEEE802_11SaeCustom>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SymCrypt802_11SaeCustomCommitProcess( (PSYMCRYPT_802_11_SAE_CUSTOM_STATE) buf1, buf2, buf3, &buf3[1024], &buf3[2048] );

    UNREFERENCED_PARAMETER( dataSize );
}

template<>
ArithImp<ImpSc, AlgIEEE802_11SaeCustom>::ArithImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpSc, AlgIEEE802_11SaeCustom>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpSc, AlgIEEE802_11SaeCustom>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpSc, AlgIEEE802_11SaeCustom>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpSc, AlgIEEE802_11SaeCustom>;
}

template<>
ArithImp<ImpSc, AlgIEEE802_11SaeCustom>::~ArithImp()
{
}



VOID
addSymCryptAlgs()
{
    SymCryptInit();

    //
    // We use a tempate function to decide which algorithm implementations to
    // run.
    // We could make each algorithm auto-register using static initializers,
    // but this is test code and we want to be able to test (and dynamically disable)
    // the initializer code. So we do it manually once.
    //

    addImplementationToGlobalList<HashImp<ImpSc, AlgMd2>>();
    addImplementationToGlobalList<HashImp<ImpSc, AlgMd4>>();
    addImplementationToGlobalList<HashImp<ImpSc, AlgMd5>>();
    addImplementationToGlobalList<HashImp<ImpSc, AlgSha1>>();
    addImplementationToGlobalList<HashImp<ImpSc, AlgSha256>>();
    addImplementationToGlobalList<HashImp<ImpSc, AlgSha384>>();
    addImplementationToGlobalList<HashImp<ImpSc, AlgSha512>>();

    addImplementationToGlobalList<MacImp<ImpSc, AlgHmacMd5>>();
    addImplementationToGlobalList<MacImp<ImpSc, AlgHmacSha1>>();
    addImplementationToGlobalList<MacImp<ImpSc, AlgHmacSha256>>();
    addImplementationToGlobalList<MacImp<ImpSc, AlgHmacSha384>>();
    addImplementationToGlobalList<MacImp<ImpSc, AlgHmacSha512>>();
    addImplementationToGlobalList<MacImp<ImpSc, AlgAesCmac>>();
    addImplementationToGlobalList<MacImp<ImpSc, AlgMarvin32>>();
    addImplementationToGlobalList<MacImp<ImpSc, AlgPoly1305>>();

    addImplementationToGlobalList<BlockCipherImp<ImpSc, AlgAes, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpSc, AlgAes, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpSc, AlgAes, ModeCfb>>();

    addImplementationToGlobalList<BlockCipherImp<ImpSc, AlgDes, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpSc, AlgDes, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpSc, AlgDes, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpSc, Alg2Des, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpSc, Alg2Des, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpSc, Alg2Des, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpSc, Alg3Des, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpSc, Alg3Des, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpSc, Alg3Des, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpSc, AlgDesx, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpSc, AlgDesx, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpSc, AlgDesx, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpSc, AlgRc2, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpSc, AlgRc2, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpSc, AlgRc2, ModeCfb>>();

    addImplementationToGlobalList<AuthEncImp<ImpSc, AlgAes, ModeCcm>>();
    addImplementationToGlobalList<AuthEncImp<ImpSc, AlgAes, ModeGcm>>();
    addImplementationToGlobalList<AuthEncImp<ImpSc, AlgChaCha20Poly1305, ModeNone>>();

    addImplementationToGlobalList<StreamCipherImp<ImpSc, AlgRc4>>();
    addImplementationToGlobalList<StreamCipherImp<ImpSc, AlgChaCha20>>();

    addImplementationToGlobalList<ParallelHashImp<ImpSc, AlgParallelSha256>>();
    addImplementationToGlobalList<ParallelHashImp<ImpSc, AlgParallelSha384>>();
    addImplementationToGlobalList<ParallelHashImp<ImpSc, AlgParallelSha512>>();

    addImplementationToGlobalList<XtsImp<ImpSc, AlgXtsAes>>();

    addImplementationToGlobalList<RngSp800_90Imp<ImpSc, AlgAesCtrDrbg>>();
    addImplementationToGlobalList<RngSp800_90Imp<ImpSc, AlgAesCtrF142>>();

    addImplementationToGlobalList<KdfImp<ImpSc , AlgPbkdf2, AlgHmacMd5>>();
    addImplementationToGlobalList<KdfImp<ImpSc , AlgPbkdf2, AlgHmacSha1>>();
    addImplementationToGlobalList<KdfImp<ImpSc , AlgPbkdf2, AlgHmacSha256>>();
    addImplementationToGlobalList<KdfImp<ImpSc , AlgPbkdf2, AlgHmacSha384>>();
    addImplementationToGlobalList<KdfImp<ImpSc , AlgPbkdf2, AlgHmacSha512>>();
    addImplementationToGlobalList<KdfImp<ImpSc , AlgPbkdf2, AlgAesCmac>>();

    addImplementationToGlobalList<KdfImp<ImpSc , AlgSp800_108, AlgHmacMd5>>();
    addImplementationToGlobalList<KdfImp<ImpSc , AlgSp800_108, AlgHmacSha1>>();
    addImplementationToGlobalList<KdfImp<ImpSc , AlgSp800_108, AlgHmacSha256>>();
    addImplementationToGlobalList<KdfImp<ImpSc , AlgSp800_108, AlgHmacSha384>>();
    addImplementationToGlobalList<KdfImp<ImpSc , AlgSp800_108, AlgHmacSha512>>();
    addImplementationToGlobalList<KdfImp<ImpSc , AlgSp800_108, AlgAesCmac>>();

    addImplementationToGlobalList<KdfImp<ImpSc, AlgTlsPrf1_1, AlgHmacMd5>>();
    addImplementationToGlobalList<KdfImp<ImpSc, AlgTlsPrf1_2, AlgHmacSha256>>();
    addImplementationToGlobalList<KdfImp<ImpSc, AlgTlsPrf1_2, AlgHmacSha384>>();
    addImplementationToGlobalList<KdfImp<ImpSc, AlgTlsPrf1_2, AlgHmacSha512>>();

    addImplementationToGlobalList<KdfImp<ImpSc, AlgHkdf, AlgHmacSha256>>();
    addImplementationToGlobalList<KdfImp<ImpSc, AlgHkdf, AlgHmacSha1>>();

    addImplementationToGlobalList<TlsCbcHmacImp<ImpSc, AlgTlsCbcHmacSha1>>();
    addImplementationToGlobalList<TlsCbcHmacImp<ImpSc, AlgTlsCbcHmacSha256>>();
    addImplementationToGlobalList<TlsCbcHmacImp<ImpSc, AlgTlsCbcHmacSha384>>();

    addImplementationToGlobalList<ArithImp<ImpSc, AlgIntAdd>>();
    addImplementationToGlobalList<ArithImp<ImpSc, AlgIntSub>>();
    addImplementationToGlobalList<ArithImp<ImpSc, AlgIntMul>>();
    addImplementationToGlobalList<ArithImp<ImpSc, AlgIntSquare>>();
    addImplementationToGlobalList<ArithImp<ImpSc, AlgIntDivMod>>();

    addImplementationToGlobalList<ArithImp<ImpSc, AlgModExp>>();
    addImplementationToGlobalList<ArithImp<ImpSc, AlgModAdd>>();
    addImplementationToGlobalList<ArithImp<ImpSc, AlgModSub>>();
    addImplementationToGlobalList<ArithImp<ImpSc, AlgModMul>>();
    addImplementationToGlobalList<ArithImp<ImpSc, AlgModSquare>>();
    addImplementationToGlobalList<ArithImp<ImpSc, AlgModInv>>();

    addImplementationToGlobalList<ArithImp<ImpSc, AlgScsTable>>();

    //addImplementationToGlobalList<RsaImp<ImpSc, AlgRsaEncRaw>>();
    //addImplementationToGlobalList<RsaImp<ImpSc, AlgRsaDecRaw>>();
    //addImplementationToGlobalList<RsaImp<ImpSc, AlgRsaEncPkcs1>>();
    //addImplementationToGlobalList<RsaImp<ImpSc, AlgRsaDecPkcs1>>();
    //addImplementationToGlobalList<RsaImp<ImpSc, AlgRsaEncOaep>>();
    //addImplementationToGlobalList<RsaImp<ImpSc, AlgRsaDecOaep>>();

    addImplementationToGlobalList<RsaSignImp<ImpSc, AlgRsaSignPkcs1>>();
    addImplementationToGlobalList<RsaSignImp<ImpSc, AlgRsaSignPss>>();

    addImplementationToGlobalList<RsaEncImp<ImpSc, AlgRsaEncRaw>>();
    addImplementationToGlobalList<RsaEncImp<ImpSc, AlgRsaEncPkcs1>>();
    addImplementationToGlobalList<RsaEncImp<ImpSc, AlgRsaEncOaep>>();

    //addImplementationToGlobalList<RsaImp<ImpSc, AlgRsaSignPkcs1>>();
    //addImplementationToGlobalList<RsaImp<ImpSc, AlgRsaVerifyPkcs1>>();
    //addImplementationToGlobalList<RsaImp<ImpSc, AlgRsaSignPss>>();
    //addImplementationToGlobalList<RsaImp<ImpSc, AlgRsaVerifyPss>>();

    addImplementationToGlobalList<DhImp<ImpSc, AlgDh>>();
    addImplementationToGlobalList<DsaImp<ImpSc, AlgDsa>>();

    //addImplementationToGlobalList<DlImp<ImpSc, AlgDsaSign>>();
    //addImplementationToGlobalList<DlImp<ImpSc, AlgDsaVerify>>();
    //addImplementationToGlobalList<DlImp<ImpSc, AlgDh>>();

    addImplementationToGlobalList<ArithImp<ImpSc, AlgTrialDivisionContext>>();
    addImplementationToGlobalList<ArithImp<ImpSc, AlgTrialDivision>>();

    addImplementationToGlobalList<EccImp<ImpSc, AlgEcurveAllocate>>();

    addImplementationToGlobalList<EccImp<ImpSc, AlgEcpointSetZero>>();
    addImplementationToGlobalList<EccImp<ImpSc, AlgEcpointSetDistinguished>>();
    addImplementationToGlobalList<EccImp<ImpSc, AlgEcpointSetRandom>>();
    addImplementationToGlobalList<EccImp<ImpSc, AlgEcpointIsEqual>>();
    addImplementationToGlobalList<EccImp<ImpSc, AlgEcpointIsZero>>();
    addImplementationToGlobalList<EccImp<ImpSc, AlgEcpointOnCurve>>();

    addImplementationToGlobalList<EccImp<ImpSc, AlgEcpointAdd>>();
    addImplementationToGlobalList<EccImp<ImpSc, AlgEcpointAddDiffNz>>();
    addImplementationToGlobalList<EccImp<ImpSc, AlgEcpointDouble>>();
    addImplementationToGlobalList<EccImp<ImpSc, AlgEcpointScalarMul>>();

    addImplementationToGlobalList<EccImp<ImpSc, AlgEcdsaSign>>();
    addImplementationToGlobalList<EccImp<ImpSc, AlgEcdsaVerify>>();
    addImplementationToGlobalList<EccImp<ImpSc, AlgEcdh>>();

    addImplementationToGlobalList<ArithImp<ImpSc, AlgIEEE802_11SaeCustom>>();

    addImplementationToGlobalList<ArithImp<ImpSc, AlgDeveloperTest>>();
}
