//
// Pattern file for the SymCrypt implementations. Shared between static and dynamically linked
// SymCrypt implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#define ALG_NAME   MD2
#define ALG_Name   Md2
#define ALG_name   md2
#include "sc_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name
#undef ALG_name

#define ALG_NAME   MD4
#define ALG_Name   Md4
#define ALG_name   md4
#include "sc_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name
#undef ALG_name

#define ALG_NAME   MD5
#define ALG_Name   Md5
#define ALG_name   md5
#include "sc_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name
#undef ALG_name

#define ALG_NAME   SHA1
#define ALG_Name   Sha1
#define ALG_name   sha1
#include "sc_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name
#undef ALG_name

#define ALG_NAME   SHA256
#define ALG_Name   Sha256
#define ALG_name   sha256
#include "sc_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name
#undef ALG_name

#define ALG_NAME   SHA384
#define ALG_Name   Sha384
#define ALG_name   sha384
#include "sc_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name
#undef ALG_name

#define ALG_NAME   SHA512
#define ALG_Name   Sha512
#define ALG_name   sha512
#include "sc_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name
#undef ALG_name

#define ALG_NAME   SHA3_256
#define ALG_Name   Sha3_256
#define ALG_name   sha3_256
#define HashImpSha3_256
#include "sc_imp_hashpattern.cpp"
#undef HashImpSha3_256
#undef ALG_NAME
#undef ALG_Name
#undef ALG_name

#define ALG_NAME   SHA3_384
#define ALG_Name   Sha3_384
#define ALG_name   sha3_384
#define HashImpSha3_384
#include "sc_imp_hashpattern.cpp"
#undef HashImpSha3_384
#undef ALG_NAME
#undef ALG_Name
#undef ALG_name

#define ALG_NAME   SHA3_512
#define ALG_Name   Sha3_512
#define ALG_name   sha3_512
#define HashImpSha3_512
#include "sc_imp_hashpattern.cpp"
#undef HashImpSha3_512
#undef ALG_NAME
#undef ALG_Name
#undef ALG_name

 #define ALG_NAME   SHAKE128
 #define ALG_Name   Shake128
 #define ALG_name   shake128
 #include "sc_imp_xofpattern.cpp"
 #undef ALG_NAME
 #undef ALG_Name
 #undef ALG_name

 #define ALG_NAME   SHAKE256
 #define ALG_Name   Shake256
 #define ALG_name   shake256
 #include "sc_imp_xofpattern.cpp"
 #undef ALG_NAME
 #undef ALG_Name
 #undef ALG_name

 #define ALG_NAME   CSHAKE128
 #define ALG_Name   CShake128
 #define ALG_name   cshake128
 #include "sc_imp_cxofpattern.cpp"
 #undef ALG_NAME
 #undef ALG_Name
 #undef ALG_name

 #define ALG_NAME   CSHAKE256
 #define ALG_Name   CShake256
 #define ALG_name   cshake256
 #include "sc_imp_cxofpattern.cpp"
 #undef ALG_NAME
 #undef ALG_Name
 #undef ALG_name

 #define ALG_NAME   KMAC128
 #define ALG_Name   Kmac128
 #define ALG_name   kmac128
 #include "sc_imp_kmacpattern.cpp"
 #undef ALG_NAME
 #undef ALG_Name
 #undef ALG_name

 #define ALG_NAME   KMAC256
 #define ALG_Name   Kmac256
 #define ALG_name   kmac256
 #include "sc_imp_kmacpattern.cpp"
 #undef ALG_NAME
 #undef ALG_Name
 #undef ALG_name

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

#define SymCryptBlockCipherXxx ScShimSymCryptAesBlockCipher
#include "sc_imp_blockciphertestfunctionspattern.cpp"
#undef SymCryptBlockCipherXxx

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

#define SymCryptBlockCipherXxx ScShimSymCryptDesBlockCipher
#include "sc_imp_blockciphertestfunctionspattern.cpp"
#undef SymCryptBlockCipherXxx

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

#define SymCryptBlockCipherXxx ScShimSymCrypt3DesBlockCipher
#include "sc_imp_blockciphertestfunctionspattern.cpp"
#undef SymCryptBlockCipherXxx

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

#define SymCryptBlockCipherXxx ScShimSymCrypt3DesBlockCipher
#include "sc_imp_blockciphertestfunctionspattern.cpp"
#undef SymCryptBlockCipherXxx

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

#define SymCryptBlockCipherXxx ScShimSymCryptDesxBlockCipher
#include "sc_imp_blockciphertestfunctionspattern.cpp"
#undef SymCryptBlockCipherXxx

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
#define ALG_Rc2SetKeyOverride (1)

#define SymCryptBlockCipherXxx ScShimSymCryptRc2BlockCipher
#include "sc_imp_blockciphertestfunctionspattern.cpp"
#undef SymCryptBlockCipherXxx

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
#undef ALG_Rc2SetKeyOverride

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
#define SYMCRYPT_XXX_BASE_RESULT_SIZE   SYMCRYPT_HMAC_SHA256_RESULT_SIZE
#include "sc_imp_hkdfpattern.cpp"
#undef SYMCRYPT_XXX_BASE_RESULT_SIZE
#undef ALG_Base

#define ALG_Base    HmacSha1
#define SYMCRYPT_XXX_BASE_RESULT_SIZE   SYMCRYPT_HMAC_SHA1_RESULT_SIZE
#include "sc_imp_hkdfpattern.cpp"
#undef SYMCRYPT_XXX_BASE_RESULT_SIZE
#undef ALG_Base

#undef ALG_NAME
#undef ALG_Name


#define ALG_NAME    SSHKDF
#define ALG_Name    SshKdf

#define ALG_Base    Sha1
#define SYMCRYPT_XXX_BASE_RESULT_SIZE   SYMCRYPT_SHA1_RESULT_SIZE
#include "sc_imp_kdfpattern.cpp"
#include "sc_imp_sshkdfpattern.cpp"
#undef SYMCRYPT_XXX_BASE_RESULT_SIZE
#undef ALG_Base

#define ALG_Base    Sha256
#define SYMCRYPT_XXX_BASE_RESULT_SIZE   SYMCRYPT_SHA256_RESULT_SIZE
#include "sc_imp_kdfpattern.cpp"
#include "sc_imp_sshkdfpattern.cpp"
#undef SYMCRYPT_XXX_BASE_RESULT_SIZE
#undef ALG_Base

#define ALG_Base    Sha384
#define SYMCRYPT_XXX_BASE_RESULT_SIZE   SYMCRYPT_SHA384_RESULT_SIZE
#include "sc_imp_kdfpattern.cpp"
#include "sc_imp_sshkdfpattern.cpp"
#undef SYMCRYPT_XXX_BASE_RESULT_SIZE
#undef ALG_Base

#define ALG_Base    Sha512
#define SYMCRYPT_XXX_BASE_RESULT_SIZE   SYMCRYPT_SHA512_RESULT_SIZE
#include "sc_imp_kdfpattern.cpp"
#include "sc_imp_sshkdfpattern.cpp"
#undef SYMCRYPT_XXX_BASE_RESULT_SIZE
#undef ALG_Base

#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    SRTPKDF
#define ALG_Name    SrtpKdf

#define ALG_Base    Aes
#include "sc_imp_srtpkdfpattern.cpp"
#undef ALG_Base

#undef ALG_NAME
#undef ALG_Name

//
// There is not enough structure to the CCM & GCM modes to share an implementation
//

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgAes, ModeCcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    ScShimSymCryptAesExpandKey( (SYMCRYPT_AES_EXPANDED_KEY *) buf1, buf2, keySize );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx, AlgAes, ModeCcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ScShimSymCryptCcmEncrypt(
        ScShimSymCryptAesBlockCipher, (SYMCRYPT_AES_EXPANDED_KEY*)buf1,
        buf2, 12, nullptr, 0, buf2 + 16, buf3 + 16, dataSize, buf3, 16);
}

template<>
VOID
algImpDecryptPerfFunction<ImpXxx, AlgAes, ModeCcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ScShimSymCryptCcmDecrypt(
        ScShimSymCryptAesBlockCipher, (SYMCRYPT_AES_EXPANDED_KEY*)buf1,
        buf2, 12, nullptr, 0, buf3 + 16, buf2 + 16, dataSize, buf3, 16);
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgAes, ModeCcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptWipeKnownSize( buf1, sizeof( SYMCRYPT_AES_EXPANDED_KEY ) );
}

template<>
AuthEncImp<ImpXxx, AlgAes, ModeCcm>::AuthEncImp()
{
    m_perfKeyFunction     = &algImpKeyPerfFunction    <ImpXxx, AlgAes, ModeCcm>;
    m_perfCleanFunction   = &algImpCleanPerfFunction  <ImpXxx, AlgAes, ModeCcm>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpXxx, AlgAes, ModeCcm>;
    m_perfDecryptFunction = &algImpDecryptPerfFunction<ImpXxx, AlgAes, ModeCcm>;
}

template<>
AuthEncImp<ImpXxx, AlgAes, ModeCcm>::~AuthEncImp()
{
}

template<>
std::set<SIZE_T>
AuthEncImp<ImpXxx, AlgAes, ModeCcm>::getKeySizes()
{
    std::set<SIZE_T> res;

    res.insert( 16 );
    res.insert( 24 );
    res.insert( 32 );

    return res;
}


template<>
std::set<SIZE_T>
AuthEncImp<ImpXxx, AlgAes, ModeCcm>::getNonceSizes()
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
AuthEncImp<ImpXxx, AlgAes, ModeCcm>::getTagSizes()
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
AuthEncImp<ImpXxx, AlgAes, ModeCcm>::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 16 || cbKey == 24 || cbKey == 32, "?" );
    ScShimSymCryptAesExpandKey( &state.key, pbKey, cbKey );

    state.inComputation = FALSE;
    return STATUS_SUCCESS;
}

template<>
VOID
AuthEncImp<ImpXxx, AlgAes, ModeCcm>::setTotalCbData( SIZE_T cbData )
{
    state.totalCbData = cbData;
}

template<>
NTSTATUS
AuthEncImp<ImpXxx, AlgAes, ModeCcm>::encrypt(
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
        CHECK( ScShimSymCryptCcmValidateParameters(
            ScShimSymCryptAesBlockCipher,
            cbNonce,
            cbAuthData,
            cbData,
            cbTag ) == SYMCRYPT_NO_ERROR, "?" );

        ScShimSymCryptCcmEncrypt(
            ScShimSymCryptAesBlockCipher, &state.key,
            pbNonce, cbNonce, pbAuthData, cbAuthData,
            pbSrc, pbDst, cbData,
            pbTag, cbTag );

        // Done
        goto cleanup;
    }

    if( !state.inComputation )
    {
        CHECK( (flags & AUTHENC_FLAG_PARTIAL) != 0, "?" );
        // total cbData is passed in the cbTag parameter in the first partial call
        ScShimSymCryptCcmInit(
            &state.ccmState, ScShimSymCryptAesBlockCipher, &state.key,
            pbNonce, cbNonce, pbAuthData, cbAuthData,
            state.totalCbData, cbTag);

        state.inComputation = TRUE;
    }

    // We can process the next part before we decide whether to produce the tag.
    ScShimSymCryptCcmEncryptPart( &state.ccmState, pbSrc, pbDst, cbData );

    if( pbTag != nullptr )
    {
        ScShimSymCryptCcmEncryptFinal( &state.ccmState, pbTag, cbTag );

        state.inComputation = FALSE;
    }

cleanup:
    return status;

}


template<>
NTSTATUS
AuthEncImp<ImpXxx, AlgAes, ModeCcm>::decrypt(
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
        CHECK( ScShimSymCryptCcmValidateParameters(
            ScShimSymCryptAesBlockCipher,
            cbNonce,
            cbAuthData,
            cbData,
            cbTag ) == SYMCRYPT_NO_ERROR, "?" );

        scError = ScShimSymCryptCcmDecrypt(
            ScShimSymCryptAesBlockCipher, &state.key,
            pbNonce, cbNonce, pbAuthData, cbAuthData,
            pbSrc, pbDst, cbData,
            pbTag, cbTag );

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
        ScShimSymCryptCcmInit(
            &state.ccmState, ScShimSymCryptAesBlockCipher, &state.key,
            pbNonce, cbNonce, pbAuthData, cbAuthData,
            state.totalCbData, cbTag );

        state.inComputation = TRUE;
    }

    // We can process the next part before we decide whether to produce the tag.
    ScShimSymCryptCcmDecryptPart( &state.ccmState, pbSrc, pbDst, cbData );

    if( pbTag != nullptr )
    {
        scError = ScShimSymCryptCcmDecryptFinal( &state.ccmState, pbTag, cbTag );
        if( scError == SYMCRYPT_AUTHENTICATION_FAILURE )
        {
            status = STATUS_AUTH_TAG_MISMATCH;
        } else {
            CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
        }

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
algImpKeyPerfFunction< ImpXxx, AlgAes, ModeGcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    ScShimSymCryptGcmExpandKey( (PSYMCRYPT_GCM_EXPANDED_KEY) buf1,
                        ScShimSymCryptAesBlockCipher,
                        buf2, keySize );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx,AlgAes, ModeGcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ScShimSymCryptGcmEncrypt( (PCSYMCRYPT_GCM_EXPANDED_KEY) buf1,
                            buf2, 12,
                            nullptr, 0,
                            buf2 + 16, buf3 + 16, dataSize,
                            buf3, 16 );
}

template<>
VOID
algImpDecryptPerfFunction<ImpXxx,AlgAes, ModeGcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ScShimSymCryptGcmDecrypt( (PCSYMCRYPT_GCM_EXPANDED_KEY) buf1,
                            buf2, 12,
                            nullptr, 0,
                            buf3 + 16, buf2 + 16, dataSize,
                            buf3, 16 );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgAes, ModeGcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptWipeKnownSize( buf1, sizeof( SYMCRYPT_GCM_EXPANDED_KEY ) );
}

template<>
AuthEncImp<ImpXxx, AlgAes, ModeGcm>::AuthEncImp()
{
    m_perfKeyFunction     = &algImpKeyPerfFunction    <ImpXxx, AlgAes, ModeGcm>;
    m_perfCleanFunction   = &algImpCleanPerfFunction  <ImpXxx, AlgAes, ModeGcm>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpXxx, AlgAes, ModeGcm>;
    m_perfDecryptFunction = &algImpDecryptPerfFunction<ImpXxx, AlgAes, ModeGcm>;
}

template<>
AuthEncImp<ImpXxx, AlgAes, ModeGcm>::~AuthEncImp()
{
    SymCryptWipeKnownSize( &state.key, sizeof( state.key ) );
}

template<>
std::set<SIZE_T>
AuthEncImp<ImpXxx, AlgAes, ModeGcm>::getKeySizes()
{
    std::set<SIZE_T> res;

    res.insert( 16 );
    res.insert( 24 );
    res.insert( 32 );

    return res;
}


template<>
std::set<SIZE_T>
AuthEncImp<ImpXxx, AlgAes, ModeGcm>::getNonceSizes()
{
    std::set<SIZE_T> res;

    res.insert( 12 );

    return res;
}


template<>
std::set<SIZE_T>
AuthEncImp<ImpXxx, AlgAes, ModeGcm>::getTagSizes()
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
AuthEncImp<ImpXxx, AlgAes, ModeGcm>::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 16 || cbKey == 24 || cbKey == 32, "?" );

    ScShimSymCryptGcmExpandKey( &state.key, ScShimSymCryptAesBlockCipher, pbKey, cbKey );

    state.inComputation = FALSE;
    return STATUS_SUCCESS;
}

template<>
VOID
AuthEncImp<ImpXxx, AlgAes, ModeGcm>::setTotalCbData( SIZE_T cbData )
{
    state.totalCbData = cbData;
}

template<>
NTSTATUS
AuthEncImp<ImpXxx, AlgAes, ModeGcm>::encrypt(
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
        // simple straight GCM computation.
        CHECK( ScShimSymCryptGcmValidateParameters(
            ScShimSymCryptAesBlockCipher,
            cbNonce,
            cbAuthData,
            cbData,
            cbTag ) == SYMCRYPT_NO_ERROR, "?" );

        ScShimSymCryptGcmEncrypt( &state.key,
            pbNonce, cbNonce, pbAuthData, cbAuthData,
            pbSrc, pbDst, cbData,
            pbTag, cbTag );

        // Done
        goto cleanup;
    }

    // We can process the next part before we decide whether to produce the tag.
    SYMCRYPT_GCM_EXPANDED_KEY gcmKey2;
    SYMCRYPT_GCM_STATE gcmState1;

    ScShimSymCryptGcmKeyCopy( &state.key, &gcmKey2 );

    if( !state.inComputation )
    {
        CHECK( (flags & AUTHENC_FLAG_PARTIAL) != 0, "?" );
        // total cbData is passed in the cbTag parameter in the first partial call
        ScShimSymCryptGcmInit(
            &gcmState1, (g_rng.byte() & 1) ? &state.key : &gcmKey2,
            pbNonce, cbNonce );

        SIZE_T bytesDone = 0;
        while( bytesDone != cbAuthData )
        {
            SIZE_T bytesThisLoop = g_rng.sizet( cbAuthData - bytesDone + 1);
            ScShimSymCryptGcmAuthPart( &gcmState1, &pbAuthData[bytesDone], bytesThisLoop );
            bytesDone += bytesThisLoop;
        }

        state.inComputation = TRUE;
    } else {
        ScShimSymCryptGcmStateCopy( &state.gcmState, (g_rng.byte() & 1) ? &gcmKey2 : nullptr , &gcmState1 );
    }
    // Using gcmState1 which is using gcmKey2 or state.key.

    ScShimSymCryptGcmEncryptPart( &gcmState1, pbSrc, pbDst, cbData );

    if( pbTag != nullptr )
    {
        ScShimSymCryptGcmEncryptFinal( &gcmState1, pbTag, cbTag );

        state.inComputation = FALSE;
    } else {
        // Copy the state back into the object
        ScShimSymCryptGcmStateCopy( &gcmState1, &state.key, &state.gcmState );
    }


cleanup:
    return status;
}

template<>
NTSTATUS
AuthEncImp<ImpXxx, AlgAes, ModeGcm>::decrypt(
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
        // simple straight GCM computation.
        CHECK( ScShimSymCryptGcmValidateParameters(
            ScShimSymCryptAesBlockCipher,
            cbNonce,
            cbAuthData,
            cbData,
            cbTag ) == SYMCRYPT_NO_ERROR, "?" );

        scError = ScShimSymCryptGcmDecrypt( &state.key,
            pbNonce, cbNonce, pbAuthData, cbAuthData,
            pbSrc, pbDst, cbData,
            pbTag, cbTag );

        // Done
        goto cleanup;
    }

    // We can process the next part before we decide whether to produce the tag.
    SYMCRYPT_GCM_EXPANDED_KEY gcmKey2;
    SYMCRYPT_GCM_STATE gcmState1;

    ScShimSymCryptGcmKeyCopy( &state.key, &gcmKey2 );

    if( !state.inComputation )
    {
        CHECK( (flags & AUTHENC_FLAG_PARTIAL) != 0, "?" );
        // total cbData is passed in the cbTag parameter in the first partial call
        ScShimSymCryptGcmInit(
            &gcmState1, (g_rng.byte() & 1) ? &state.key : &gcmKey2,
            pbNonce, cbNonce );

        SIZE_T bytesDone = 0;
        while( bytesDone != cbAuthData )
        {
            SIZE_T bytesThisLoop = g_rng.sizet( cbAuthData - bytesDone + 1);
            ScShimSymCryptGcmAuthPart( &gcmState1, &pbAuthData[bytesDone], bytesThisLoop );
            bytesDone += bytesThisLoop;
        }

        state.inComputation = TRUE;
    } else {
        ScShimSymCryptGcmStateCopy( &state.gcmState, (g_rng.byte() & 1) ? &gcmKey2 : nullptr , &gcmState1 );
    }
    // Using gcmState1 which is using gcmKey2 or state.key.

    ScShimSymCryptGcmDecryptPart( &gcmState1, pbSrc, pbDst, cbData );

    if( pbTag != nullptr )
    {
        scError = ScShimSymCryptGcmDecryptFinal( &gcmState1, pbTag, cbTag );

        state.inComputation = FALSE;
    } else {
        // Copy the state back into the object
        ScShimSymCryptGcmStateCopy( &gcmState1, &state.key, &state.gcmState );
    }

cleanup:
    return scError == SYMCRYPT_NO_ERROR ? 0 : STATUS_AUTH_TAG_MISMATCH;
}


//////////////////////////
// CHACHA20POLY1305

//template<>
//VOID
//algImpKeyPerfFunction< ImpXxx, AlgChaCha20Poly1305, ModeNone>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
//{
//    UNREFERENCED_PARAMETER( buf1 );
//    UNREFERENCED_PARAMETER( buf2 );
//    UNREFERENCED_PARAMETER( buf3 );
//    UNREFERENCED_PARAMETER( KeySize );
//}

template<>
VOID
algImpDataPerfFunction<ImpXxx, AlgChaCha20Poly1305, ModeNone>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ScShimSymCryptChaCha20Poly1305Encrypt(
                        buf1, 32,
                        buf2, 12,
                        nullptr, 0,
                        buf2 + 16, buf3 + 16, dataSize,
                        buf3, 16 );
}

template<>
VOID
algImpDecryptPerfFunction<ImpXxx, AlgChaCha20Poly1305, ModeNone>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ScShimSymCryptChaCha20Poly1305Decrypt(
                        buf1, 32,
                        buf2, 12,
                        nullptr, 0,
                        buf3 + 16, buf2 + 16, dataSize,
                        buf3, 16 );
}

//template<>
//VOID
//algImpCleanPerfFunction<ImpXxx, AlgChaCha20Poly1305, ModeNone>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
//{
//    UNREFERENCED_PARAMETER( buf1 );
//    UNREFERENCED_PARAMETER( buf2 );
//    UNREFERENCED_PARAMETER( buf3 );
//}

template<>
AuthEncImp<ImpXxx, AlgChaCha20Poly1305, ModeNone>::AuthEncImp()
{
    m_perfKeyFunction     = nullptr;
    m_perfCleanFunction   = nullptr;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpXxx, AlgChaCha20Poly1305, ModeNone>;
    m_perfDecryptFunction = &algImpDecryptPerfFunction<ImpXxx, AlgChaCha20Poly1305, ModeNone>;
}

template<>
AuthEncImp<ImpXxx, AlgChaCha20Poly1305, ModeNone>::~AuthEncImp()
{
    SymCryptWipeKnownSize( state.key, sizeof( state.key ) );
}

template<>
std::set<SIZE_T>
AuthEncImp<ImpXxx, AlgChaCha20Poly1305, ModeNone>::getKeySizes()
{
    std::set<SIZE_T> res;

    res.insert( 32 );

    return res;
}


template<>
std::set<SIZE_T>
AuthEncImp<ImpXxx, AlgChaCha20Poly1305, ModeNone>::getNonceSizes()
{
    std::set<SIZE_T> res;

    res.insert( 12 );

    return res;
}


template<>
std::set<SIZE_T>
AuthEncImp<ImpXxx, AlgChaCha20Poly1305, ModeNone>::getTagSizes()
{
    std::set<SIZE_T> res;

    res.insert( 16 );

    return res;
}

template<>
NTSTATUS
AuthEncImp<ImpXxx, AlgChaCha20Poly1305, ModeNone>::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 32, "?" );
    memcpy( state.key, pbKey, cbKey );

    return STATUS_SUCCESS;
}

template<>
VOID
AuthEncImp<ImpXxx, AlgChaCha20Poly1305, ModeNone>::setTotalCbData( SIZE_T cbData )
{
    UNREFERENCED_PARAMETER( cbData );
}

template<>
NTSTATUS
AuthEncImp<ImpXxx, AlgChaCha20Poly1305, ModeNone>::encrypt(
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

    scError = ScShimSymCryptChaCha20Poly1305Encrypt(
                            state.key, sizeof(state.key),
                            pbNonce, cbNonce, pbAuthData, cbAuthData,
                            pbSrc, pbDst, cbData,
                            pbTag, cbTag );

    return scError == SYMCRYPT_NO_ERROR ? 0 : STATUS_ENCRYPTION_FAILED;
}

template<>
NTSTATUS
AuthEncImp<ImpXxx, AlgChaCha20Poly1305, ModeNone>::decrypt(
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

    scError = ScShimSymCryptChaCha20Poly1305Decrypt(
                            state.key, sizeof(state.key),
                            pbNonce, cbNonce, pbAuthData, cbAuthData,
                            pbSrc, pbDst, cbData,
                            pbTag, cbTag );

    return scError == SYMCRYPT_NO_ERROR ? 0 : STATUS_AUTH_TAG_MISMATCH;
}



//////////////////////////
// RC4


template<>
VOID
algImpKeyPerfFunction< ImpXxx, AlgRc4>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    ScShimSymCryptRc4Init( (PSYMCRYPT_RC4_STATE) buf1, buf2, keySize );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx,AlgRc4>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ScShimSymCryptRc4Crypt( (PSYMCRYPT_RC4_STATE) buf1, buf2, buf3, dataSize );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgRc4>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptWipeKnownSize( buf1, sizeof( PSYMCRYPT_RC4_STATE ) );
}

template<>
StreamCipherImp<ImpXxx, AlgRc4>::StreamCipherImp()
{
    m_perfKeyFunction     = &algImpKeyPerfFunction    <ImpXxx, AlgRc4>;
    m_perfCleanFunction   = &algImpCleanPerfFunction  <ImpXxx, AlgRc4>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpXxx, AlgRc4>;
}

template<>
StreamCipherImp<ImpXxx, AlgRc4>::~StreamCipherImp()
{
    SymCryptWipeKnownSize( &state.state, sizeof( state.state ) );
}

template<>
std::set<SIZE_T> StreamCipherImp<ImpXxx, AlgRc4>::getNonceSizes()
{
    std::set<SIZE_T> res;

    // No nonce sizes supported for RC4

    return res;
}

template<>
std::set<SIZE_T> StreamCipherImp<ImpXxx, AlgRc4>::getKeySizes()
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
StreamCipherImp<ImpXxx, AlgRc4>::setNonce( PCBYTE pbNonce, SIZE_T cbNonce )
{
    UNREFERENCED_PARAMETER( pbNonce );

    CHECK( cbNonce == 0, "RC4 does not take a nonce" );

    return STATUS_SUCCESS;
}

template<>
VOID
StreamCipherImp< ImpXxx, AlgRc4>::setOffset( UINT64 offset )
{
    UNREFERENCED_PARAMETER( offset );
    CHECK( FALSE, "RC4 is not random access" );
}

template<>
NTSTATUS
StreamCipherImp<ImpXxx, AlgRc4>::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey > 0 && cbKey <= 256, "?" );
    CHECK( ScShimSymCryptRc4Init( &state.state, pbKey, cbKey ) == SYMCRYPT_NO_ERROR, "??" );
    return STATUS_SUCCESS;
}

template<>
VOID
StreamCipherImp<ImpXxx, AlgRc4>::encrypt( PCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData )
{
    ScShimSymCryptRc4Crypt( &state.state, pbSrc, pbDst, cbData );
}


//////////////////////////
// CHACHA20

template<>
VOID
algImpKeyPerfFunction< ImpXxx, AlgChaCha20>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( keySize );

    ScShimSymCryptChaCha20Init( (PSYMCRYPT_CHACHA20_STATE) buf1, buf2, 32, buf3, 12, 0 );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx,AlgChaCha20>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ScShimSymCryptChaCha20Crypt( (PSYMCRYPT_CHACHA20_STATE) buf1, buf2, buf3, dataSize );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgChaCha20>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptWipeKnownSize( buf1, sizeof( PSYMCRYPT_CHACHA20_STATE ) );
}

template<>
StreamCipherImp<ImpXxx, AlgChaCha20>::StreamCipherImp()
{
    m_perfKeyFunction     = &algImpKeyPerfFunction    <ImpXxx, AlgChaCha20>;
    m_perfCleanFunction   = &algImpCleanPerfFunction  <ImpXxx, AlgChaCha20>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpXxx, AlgChaCha20>;
}

template<>
StreamCipherImp<ImpXxx, AlgChaCha20>::~StreamCipherImp()
{
    SymCryptWipeKnownSize( &state.state, sizeof( state.state ) );
}

template<>
std::set<SIZE_T> StreamCipherImp<ImpXxx, AlgChaCha20>::getNonceSizes()
{
    std::set<SIZE_T> res;

    res.insert( 12 );

    return res;
}

template<>
std::set<SIZE_T> StreamCipherImp<ImpXxx, AlgChaCha20>::getKeySizes()
{
    std::set<SIZE_T> res;

    res.insert( 32 );

    return res;
}

template<>
NTSTATUS
StreamCipherImp<ImpXxx, AlgChaCha20>::setNonce( PCBYTE pbNonce, SIZE_T cbNonce )
{
    CHECK( cbNonce == 12, "ChaCha20 takes a 12-byte nonce" );

    memcpy( state.nonce, pbNonce, cbNonce );
    state.offset = 0;

    CHECK( ScShimSymCryptChaCha20Init(
        &state.state, state.key, 32, state.nonce, 12, state.offset) == SYMCRYPT_NO_ERROR,
        "ChaCha20 init error" );

    return STATUS_SUCCESS;
}

template<>
VOID
StreamCipherImp< ImpXxx, AlgChaCha20>::setOffset( UINT64 offset )
{
    state.offset = offset;

    ScShimSymCryptChaCha20SetOffset( &state.state, offset );
}

template<>
NTSTATUS
StreamCipherImp<ImpXxx, AlgChaCha20>::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 32, "ChaCha20 takes a 32-byte key" );

    memcpy( state.key, pbKey, cbKey );
    SymCryptWipeKnownSize( state.nonce, sizeof( state.nonce ) );
    state.offset = 0;

    CHECK( ScShimSymCryptChaCha20Init(
        &state.state, state.key, 32, state.nonce, 12, state.offset) == SYMCRYPT_NO_ERROR,
        "ChaCha20 init error");
    return STATUS_SUCCESS;
}

template<>
VOID
StreamCipherImp<ImpXxx, AlgChaCha20>::encrypt( PCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData )
{

    ScShimSymCryptChaCha20Crypt( &state.state, pbSrc, pbDst, cbData );
}

///////////////////////////////////////////////////////
// Poly1305

/*
template<>
VOID
algImpKeyPerfFunction< ImpXxx, AlgPoly1305>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    // No per-key operations for Poly1305
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgPoly1305>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

*/

template<>
VOID
algImpDataPerfFunction<ImpXxx,AlgPoly1305>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ScShimSymCryptPoly1305( buf1, buf2, dataSize, buf3 );
}

template<>
MacImp<ImpXxx, AlgPoly1305>::MacImp()
{
    m_perfKeyFunction     = NULL;   // &algImpKeyPerfFunction    <ImpXxx, AlgPoly1305>;
    m_perfCleanFunction   = NULL;   //&algImpCleanPerfFunction  <ImpXxx, AlgPoly1305>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpXxx, AlgPoly1305>;
}

template<>
MacImp<ImpXxx, AlgPoly1305>::~MacImp<ImpXxx, AlgPoly1305>()
{
}

template<>
NTSTATUS MacImp<ImpXxx, AlgPoly1305>::mac(
    _In_reads_( cbKey )      PCBYTE pbKey,   SIZE_T cbKey,
    _In_reads_( cbData )     PCBYTE pbData,  SIZE_T cbData,
    _Out_writes_( cbResult )  PBYTE pbResult, SIZE_T cbResult )
{
    CHECK( cbKey == 32, "?" );
    CHECK( cbResult == 16, "?" );

    ScShimSymCryptPoly1305( pbKey, pbData, cbData, pbResult );

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
MacImp<ImpXxx, AlgPoly1305>::init( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 32, "?" );
    ScShimSymCryptPoly1305Init( &state.state, pbKey );

    return STATUS_SUCCESS;
}

template<>
VOID MacImp<ImpXxx, AlgPoly1305>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    ScShimSymCryptPoly1305Append( &state.state, pbData, cbData );
}

template<>
VOID MacImp<ImpXxx, AlgPoly1305>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    CHECK( cbResult == 16, "Result len error SC/Poly1305" );
    ScShimSymCryptPoly1305Result( &state.state, pbResult );
}

template<>
SIZE_T MacImp<ImpXxx, AlgPoly1305>::inputBlockLen()
{
    return SYMCRYPT_POLY1305_RESULT_SIZE;
}

template<>
SIZE_T MacImp<ImpXxx, AlgPoly1305>::resultLen()
{
    return SYMCRYPT_POLY1305_RESULT_SIZE;
}



///////////////////////////////////////////////////////
// AES-CTR_DRBG
//


template<>
VOID
algImpKeyPerfFunction< ImpXxx, AlgAesCtrDrbg>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    ScShimSymCryptRngAesInstantiate( (PSYMCRYPT_RNG_AES_STATE) buf1, buf2, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgAesCtrDrbg>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    ScShimSymCryptRngAesUninstantiate( (PSYMCRYPT_RNG_AES_STATE) buf1 );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx,AlgAesCtrDrbg>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );

    ScShimSymCryptRngAesGenerate( (PSYMCRYPT_RNG_AES_STATE) buf1, buf3, dataSize );
}

template<>
RngSp800_90Imp<ImpXxx, AlgAesCtrDrbg>::RngSp800_90Imp()
{
    m_perfKeyFunction     = &algImpKeyPerfFunction    <ImpXxx, AlgAesCtrDrbg>;
    m_perfCleanFunction   = &algImpCleanPerfFunction  <ImpXxx, AlgAesCtrDrbg>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpXxx, AlgAesCtrDrbg>;
}

template<>
RngSp800_90Imp<ImpXxx, AlgAesCtrDrbg>::~RngSp800_90Imp()
{
    ScShimSymCryptRngAesUninstantiate( &state.state );
}

template<>
NTSTATUS
RngSp800_90Imp<ImpXxx, AlgAesCtrDrbg>::instantiate( _In_reads_( cbEntropy ) PCBYTE pbEntropy, SIZE_T cbEntropy )
{
    SYMCRYPT_ERROR scError;

    scError = ScShimSymCryptRngAesInstantiate( &state.state, pbEntropy, cbEntropy );

    CHECK( scError == SYMCRYPT_NO_ERROR, "Error during instantiation" );

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
RngSp800_90Imp<ImpXxx, AlgAesCtrDrbg>::reseed( _In_reads_( cbEntropy ) PCBYTE pbEntropy, SIZE_T cbEntropy )
{
    SYMCRYPT_ERROR scError;

    scError = ScShimSymCryptRngAesReseed( &state.state, pbEntropy, cbEntropy );

    CHECK3( scError == SYMCRYPT_NO_ERROR, "Error during reseed, len=%lld", (ULONGLONG) cbEntropy );

    return STATUS_SUCCESS;
}

template<>
VOID
RngSp800_90Imp<ImpXxx, AlgAesCtrDrbg>::generate(  _Out_writes_( cbData ) PBYTE pbData, SIZE_T cbData )
{
    ScShimSymCryptRngAesGenerate( &state.state, pbData, cbData );
}




template<>
VOID
algImpKeyPerfFunction< ImpXxx, AlgAesCtrF142>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    ScShimSymCryptRngAesFips140_2Instantiate( (PSYMCRYPT_RNG_AES_FIPS140_2_STATE) buf1, buf2, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgAesCtrF142>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    ScShimSymCryptRngAesFips140_2Uninstantiate( (PSYMCRYPT_RNG_AES_FIPS140_2_STATE) buf1 );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx,AlgAesCtrF142>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );

    ScShimSymCryptRngAesFips140_2Generate( (PSYMCRYPT_RNG_AES_FIPS140_2_STATE) buf1, buf3, dataSize );
}

template<>
RngSp800_90Imp<ImpXxx, AlgAesCtrF142>::RngSp800_90Imp()
{
    m_perfKeyFunction     = &algImpKeyPerfFunction    <ImpXxx, AlgAesCtrF142>;
    m_perfCleanFunction   = &algImpCleanPerfFunction  <ImpXxx, AlgAesCtrF142>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpXxx, AlgAesCtrF142>;
}

template<>
RngSp800_90Imp<ImpXxx, AlgAesCtrF142>::~RngSp800_90Imp()
{
    ScShimSymCryptRngAesFips140_2Uninstantiate( &state.state );
}

template<>
NTSTATUS
RngSp800_90Imp<ImpXxx, AlgAesCtrF142>::instantiate( _In_reads_( cbEntropy ) PCBYTE pbEntropy, SIZE_T cbEntropy )
{
    SYMCRYPT_ERROR scError;

    scError = ScShimSymCryptRngAesFips140_2Instantiate( &state.state, pbEntropy, cbEntropy );

    CHECK( scError == SYMCRYPT_NO_ERROR, "Error during instantiation" );

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
RngSp800_90Imp<ImpXxx, AlgAesCtrF142>::reseed( _In_reads_( cbEntropy ) PCBYTE pbEntropy, SIZE_T cbEntropy )
{
    SYMCRYPT_ERROR scError;

    scError = ScShimSymCryptRngAesFips140_2Reseed( &state.state, pbEntropy, cbEntropy );

    CHECK3( scError == SYMCRYPT_NO_ERROR, "Error during reseed, len=%lld", (ULONGLONG) cbEntropy );

    return STATUS_SUCCESS;
}

template<>
VOID
RngSp800_90Imp<ImpXxx, AlgAesCtrF142>::generate(  _Out_writes_( cbData ) PBYTE pbData, SIZE_T cbData )
{
    ScShimSymCryptRngAesFips140_2Generate( &state.state, pbData, cbData );
}

#if IMP_UseSymCryptRandom
///////////////////////////////////////////////////////
// Dynamic Random
//

template<>
VOID
algImpKeyPerfFunction<ImpXxx,AlgDynamicRandom>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );

    ScShimSymCryptProvideEntropy( buf3, keySize );
}


template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgDynamicRandom>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx,AlgDynamicRandom>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );

    ScShimSymCryptRandom( buf3, dataSize );
}

template<>
RngSp800_90Imp<ImpXxx, AlgDynamicRandom>::RngSp800_90Imp()
{
    m_perfKeyFunction     = &algImpKeyPerfFunction<ImpXxx, AlgDynamicRandom>;
    m_perfCleanFunction   = &algImpCleanPerfFunction<ImpXxx, AlgDynamicRandom>;
    m_perfDataFunction    = &algImpDataPerfFunction<ImpXxx, AlgDynamicRandom>;
}

template<>
RngSp800_90Imp<ImpXxx, AlgDynamicRandom>::~RngSp800_90Imp()
{
}

template<>
NTSTATUS
RngSp800_90Imp<ImpXxx, AlgDynamicRandom>::instantiate( _In_reads_( cbEntropy ) PCBYTE pbEntropy, SIZE_T cbEntropy )
{
    ScShimSymCryptProvideEntropy( pbEntropy, cbEntropy );

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
RngSp800_90Imp<ImpXxx, AlgDynamicRandom>::reseed( _In_reads_( cbEntropy ) PCBYTE pbEntropy, SIZE_T cbEntropy )
{
    ScShimSymCryptProvideEntropy( pbEntropy, cbEntropy );

    return STATUS_SUCCESS;
}

template<>
VOID
RngSp800_90Imp<ImpXxx, AlgDynamicRandom>::generate(  _Out_writes_( cbData ) PBYTE pbData, SIZE_T cbData )
{
    ScShimSymCryptRandom( pbData, cbData );
}
#endif

//=============================================================================
// Parallel hashing
//

#define N_PARALLEL_FOR_PERF 8

template<>
VOID
algImpKeyPerfFunction<ImpXxx,AlgParallelSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( dataSize );

    ScShimSymCryptParallelSha256Init( (PSYMCRYPT_SHA256_STATE) buf1, N_PARALLEL_FOR_PERF );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgParallelSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx,AlgParallelSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
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
    ScShimSymCryptParallelSha256Process(
        pState, N_PARALLEL_FOR_PERF, pOperations, 2 * N_PARALLEL_FOR_PERF, buf1 + PERF_BUFFER_SIZE / 2, PERF_BUFFER_SIZE / 2);
}

template<>
ParallelHashImp<ImpXxx, AlgParallelSha256>::ParallelHashImp()
{
    m_perfDataFunction = &algImpDataPerfFunction <ImpXxx, AlgParallelSha256>;
    m_perfKeyFunction  = &algImpKeyPerfFunction  <ImpXxx, AlgParallelSha256>;
    m_perfCleanFunction= &algImpCleanPerfFunction<ImpXxx, AlgParallelSha256>;

    state.nHashes = 0;
};

template<>
ParallelHashImp<ImpXxx, AlgParallelSha256>::~ParallelHashImp() {};

template<>
PCSYMCRYPT_HASH
ParallelHashImp<ImpXxx, AlgParallelSha256>::SymCryptHash()
{
    return ScShimSymCryptSha256Algorithm;
}

template<>
SIZE_T ParallelHashImp<ImpXxx, AlgParallelSha256>::resultLen()
{
    return SYMCRYPT_SHA256_RESULT_SIZE;
}

template<>
SIZE_T ParallelHashImp<ImpXxx, AlgParallelSha256>::inputBlockLen()
{
    return SYMCRYPT_SHA256_INPUT_BLOCK_SIZE;
}


template<>
VOID
ParallelHashImp<ImpXxx, AlgParallelSha256>::init( SIZE_T nHashes )
{
    CHECK( nHashes <= MAX_PARALLEL_HASH_STATES, "Too many hash states requested" );
    state.nHashes = nHashes;

    ScShimSymCryptParallelSha256Init( &state.sc[0], nHashes );
}

template<>
VOID
ParallelHashImp<ImpXxx, AlgParallelSha256>::process(
        _In_reads_( nOperations )   BCRYPT_MULTI_HASH_OPERATION *   pOperations,
                                    SIZE_T                          nOperations )
{
    SYMCRYPT_ERROR                      scError;
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
    SYMCRYPT_ASSERT( nScratch + scratchOffset < sizeof( scratch ) );

    scratch[scratchOffset + nScratch] = sentinel;

    SYMCRYPT_ASSERT( state.nHashes <= MAX_PARALLEL_HASH_STATES );
    scError = ScShimSymCryptParallelSha256Process(
                                &state.sc[0],
                                state.nHashes,
                                &op[0],
                                nOperations,
                                &scratch[scratchOffset],
                                nScratch );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Parallel SHA256 returned an error" );
    CHECK( scratch[scratchOffset + nScratch] == sentinel, "Parallel SHA256 used too much scratch space" );
}

template<>
NTSTATUS
ParallelHashImp<ImpXxx, AlgParallelSha256>::initWithLongMessage( ULONGLONG nBytes )
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
algImpKeyPerfFunction<ImpXxx,AlgParallelSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( dataSize );

    ScShimSymCryptParallelSha384Init( (PSYMCRYPT_SHA384_STATE) buf1, N_PARALLEL_FOR_PERF );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgParallelSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx,AlgParallelSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
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
    ScShimSymCryptParallelSha384Process(
        pState, N_PARALLEL_FOR_PERF, pOperations, 2 * N_PARALLEL_FOR_PERF, buf1 + PERF_BUFFER_SIZE / 2, PERF_BUFFER_SIZE / 2);
}

template<>
ParallelHashImp<ImpXxx, AlgParallelSha384>::ParallelHashImp()
{
    m_perfDataFunction = &algImpDataPerfFunction <ImpXxx, AlgParallelSha384>;
    m_perfKeyFunction  = &algImpKeyPerfFunction  <ImpXxx, AlgParallelSha384>;
    m_perfCleanFunction= &algImpCleanPerfFunction<ImpXxx, AlgParallelSha384>;

    state.nHashes = 0;
};

template<>
ParallelHashImp<ImpXxx, AlgParallelSha384>::~ParallelHashImp() {};

template<>
PCSYMCRYPT_HASH
ParallelHashImp<ImpXxx, AlgParallelSha384>::SymCryptHash()
{
    return ScShimSymCryptSha384Algorithm;
}

template<>
SIZE_T ParallelHashImp<ImpXxx, AlgParallelSha384>::resultLen()
{
    return SYMCRYPT_SHA384_RESULT_SIZE;
}

template<>
SIZE_T ParallelHashImp<ImpXxx, AlgParallelSha384>::inputBlockLen()
{
    return SYMCRYPT_SHA384_INPUT_BLOCK_SIZE;
}


template<>
VOID
ParallelHashImp<ImpXxx, AlgParallelSha384>::init( SIZE_T nHashes )
{
    CHECK( nHashes <= MAX_PARALLEL_HASH_STATES, "Too many hash states requested" );
    state.nHashes = nHashes;
    ScShimSymCryptParallelSha384Init( &state.sc[0], nHashes );
}

template<>
VOID
ParallelHashImp<ImpXxx, AlgParallelSha384>::process(
        _In_reads_( nOperations )   BCRYPT_MULTI_HASH_OPERATION *   pOperations,
                                    SIZE_T                          nOperations )
{
    SYMCRYPT_ERROR                      scError;
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
    SYMCRYPT_ASSERT( nScratch + scratchOffset < sizeof( scratch ) );

    scratch[scratchOffset + nScratch] = sentinel;

    SYMCRYPT_ASSERT( state.nHashes <= MAX_PARALLEL_HASH_STATES );
    scError = ScShimSymCryptParallelSha384Process(
                                &state.sc[0],
                                state.nHashes,
                                &op[0],
                                nOperations,
                                &scratch[scratchOffset],
                                nScratch );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Parallel SHA384 returned an error" );
    CHECK( scratch[scratchOffset + nScratch] == sentinel, "Parallel SHA384 used too much scratch space" );
}

template<>
NTSTATUS
ParallelHashImp<ImpXxx, AlgParallelSha384>::initWithLongMessage( ULONGLONG nBytes )
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
algImpKeyPerfFunction<ImpXxx,AlgParallelSha512>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( dataSize );

    ScShimSymCryptParallelSha512Init( (PSYMCRYPT_SHA512_STATE) buf1, N_PARALLEL_FOR_PERF );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgParallelSha512>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx,AlgParallelSha512>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
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
    ScShimSymCryptParallelSha512Process(
        pState, N_PARALLEL_FOR_PERF, pOperations, 2 * N_PARALLEL_FOR_PERF, buf1 + PERF_BUFFER_SIZE / 2, PERF_BUFFER_SIZE / 2);
}

template<>
ParallelHashImp<ImpXxx, AlgParallelSha512>::ParallelHashImp()
{
    m_perfDataFunction = &algImpDataPerfFunction <ImpXxx, AlgParallelSha512>;
    m_perfKeyFunction  = &algImpKeyPerfFunction  <ImpXxx, AlgParallelSha512>;
    m_perfCleanFunction= &algImpCleanPerfFunction<ImpXxx, AlgParallelSha512>;

    state.nHashes = 0;
};

template<>
ParallelHashImp<ImpXxx, AlgParallelSha512>::~ParallelHashImp() {};

template<>
PCSYMCRYPT_HASH
ParallelHashImp<ImpXxx, AlgParallelSha512>::SymCryptHash()
{
    return ScShimSymCryptSha512Algorithm;
}

template<>
SIZE_T ParallelHashImp<ImpXxx, AlgParallelSha512>::resultLen()
{
    return SYMCRYPT_SHA512_RESULT_SIZE;
}

template<>
SIZE_T ParallelHashImp<ImpXxx, AlgParallelSha512>::inputBlockLen()
{
    return SYMCRYPT_SHA512_INPUT_BLOCK_SIZE;
}


template<>
VOID
ParallelHashImp<ImpXxx, AlgParallelSha512>::init( SIZE_T nHashes )
{
    CHECK( nHashes <= MAX_PARALLEL_HASH_STATES, "Too many hash states requested" );
    state.nHashes = nHashes;
    ScShimSymCryptParallelSha512Init( &state.sc[0], nHashes );
}

template<>
VOID
ParallelHashImp<ImpXxx, AlgParallelSha512>::process(
        _In_reads_( nOperations )   BCRYPT_MULTI_HASH_OPERATION *   pOperations,
                                    SIZE_T                          nOperations )
{
    SYMCRYPT_ERROR                      scError;
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
    SYMCRYPT_ASSERT( nScratch + scratchOffset < sizeof( scratch ) );

    scratch[scratchOffset + nScratch] = sentinel;

    SYMCRYPT_ASSERT( state.nHashes <= MAX_PARALLEL_HASH_STATES );
    scError = ScShimSymCryptParallelSha512Process(
                                &state.sc[0],
                                state.nHashes,
                                &op[0],
                                nOperations,
                                &scratch[scratchOffset],
                                nScratch );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Parallel SHA512 returned an error" );
    CHECK( scratch[scratchOffset + nScratch] == sentinel, "Parallel SHA512 used too much scratch space" );
}

template<>
NTSTATUS
ParallelHashImp<ImpXxx, AlgParallelSha512>::initWithLongMessage( ULONGLONG nBytes )
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
algImpKeyPerfFunction< ImpXxx, AlgXtsAes>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    ScShimSymCryptXtsAesExpandKey( (SYMCRYPT_XTS_AES_EXPANDED_KEY *) buf1, buf2, keySize );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx,AlgXtsAes>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ScShimSymCryptXtsAesEncrypt(
                        (SYMCRYPT_XTS_AES_EXPANDED_KEY*)buf1,
                        512,
                        'twek',
                        buf2,
                        buf3,
                        dataSize );
}

template<>
VOID
algImpDecryptPerfFunction<ImpXxx,AlgXtsAes>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ScShimSymCryptXtsAesDecrypt(
                        (SYMCRYPT_XTS_AES_EXPANDED_KEY*)buf1,
                        512,
                        'twek',
                        buf2,
                        buf3,
                        dataSize );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgXtsAes>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    SymCryptWipeKnownSize( buf1, sizeof( SYMCRYPT_XTS_AES_EXPANDED_KEY ) );
}


template<>
XtsImp<ImpXxx, AlgXtsAes>::XtsImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgXtsAes>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpXxx, AlgXtsAes>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgXtsAes>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgXtsAes>;
}

template<>
XtsImp<ImpXxx, AlgXtsAes>::~XtsImp()
{
    SymCryptWipeKnownSize( &state.key, sizeof( state.key ) );
}

template<>
NTSTATUS
XtsImp<ImpXxx, AlgXtsAes>::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    SYMCRYPT_ERROR scError;

    scError = ScShimSymCryptXtsAesExpandKey( &state.key, pbKey, cbKey );

    return scError == SYMCRYPT_NO_ERROR ? 0 : STATUS_NOT_SUPPORTED;
}

template<>
VOID
XtsImp<ImpXxx, AlgXtsAes>::encrypt(
                                        SIZE_T      cbDataUnit,
                                        ULONGLONG   tweak,
        _In_reads_( cbData )            PCBYTE      pbSrc,
        _Out_writes_( cbData )          PBYTE       pbDst,
                                        SIZE_T      cbData )
{
    ScShimSymCryptXtsAesEncrypt(
                        &state.key,
                        cbDataUnit,
                        tweak,
                        pbSrc,
                        pbDst,
                        cbData );
}

template<>
VOID
XtsImp<ImpXxx, AlgXtsAes>::decrypt(
                                        SIZE_T      cbDataUnit,
                                        ULONGLONG   tweak,
        _In_reads_( cbData )            PCBYTE      pbSrc,
        _Out_writes_( cbData )          PBYTE       pbDst,
                                        SIZE_T      cbData )
{
    ScShimSymCryptXtsAesDecrypt(
                        &state.key,
                        cbDataUnit,
                        tweak,
                        pbSrc,
                        pbDst,
                        cbData );
}


///////////////////////
//  TlsCbcHmacSha256

template<> VOID algImpKeyPerfFunction<ImpXxx, AlgTlsCbcHmacSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize );
template<> VOID algImpCleanPerfFunction<ImpXxx, AlgTlsCbcHmacSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3 );
template<> VOID algImpDataPerfFunction<ImpXxx, AlgTlsCbcHmacSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize );
template<> VOID algImpDecryptPerfFunction<ImpXxx, AlgTlsCbcHmacSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize );

template<>
TlsCbcHmacImp<ImpXxx, AlgTlsCbcHmacSha256>::TlsCbcHmacImp()
{
    m_perfKeyFunction       = &algImpKeyPerfFunction    <ImpXxx, AlgTlsCbcHmacSha256>;
    m_perfCleanFunction     = &algImpCleanPerfFunction  <ImpXxx, AlgTlsCbcHmacSha256>;
    m_perfDataFunction      = &algImpDataPerfFunction   <ImpXxx, AlgTlsCbcHmacSha256>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpXxx, AlgTlsCbcHmacSha256>;
}

template<>
TlsCbcHmacImp<ImpXxx, AlgTlsCbcHmacSha256>::~TlsCbcHmacImp<ImpXxx, AlgTlsCbcHmacSha256>()
{
}

template<>
NTSTATUS
TlsCbcHmacImp<ImpXxx, AlgTlsCbcHmacSha256>::verify(
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

    ScShimSymCryptHmacSha256ExpandKey( &key, pbKey, cbKey );
    ScShimSymCryptHmacSha256Init( &state, &key );

    ScShimSymCryptHmacSha256Append( &state, pbHeader, cbHeader );
    scError = ScShimSymCryptTlsCbcHmacVerify( ScShimSymCryptHmacSha256Algorithm, &key, &state, pbData, cbData );

    status = scError == SYMCRYPT_NO_ERROR ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

    return status;
}

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgTlsCbcHmacSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );
    ScShimSymCryptHmacSha256ExpandKey( (SYMCRYPT_HMAC_SHA256_EXPANDED_KEY *) buf1, buf2, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgTlsCbcHmacSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    SymCryptWipeKnownSize( buf1, sizeof( SYMCRYPT_HMAC_SHA256_EXPANDED_KEY ) );
}


template<>
VOID
algImpDataPerfFunction<ImpXxx, AlgTlsCbcHmacSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_HMAC_SHA256_STATE state;
    UINT32 paddingSize;

    ScShimSymCryptHmacSha256Init( &state, (SYMCRYPT_HMAC_SHA256_EXPANDED_KEY *) buf1 );
    ScShimSymCryptHmacSha256Append( &state, buf3, 13 );       // typical header is 13 bytes
    ScShimSymCryptHmacSha256Append( &state, buf2, dataSize );
    ScShimSymCryptHmacSha256Result( &state, &buf2[ dataSize ] );

    paddingSize = 15 - (dataSize & 15);

    memset( &buf2[dataSize + SYMCRYPT_HMAC_SHA256_RESULT_SIZE], (BYTE) paddingSize, paddingSize + 1);
}

template<>
VOID
algImpDecryptPerfFunction<ImpXxx, AlgTlsCbcHmacSha256>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_HMAC_SHA256_STATE  state;
    SYMCRYPT_ERROR scError;

    ScShimSymCryptHmacSha256Init( &state, (SYMCRYPT_HMAC_SHA256_EXPANDED_KEY *) buf1 );
    ScShimSymCryptHmacSha256Append( &state, buf3, 13 );


    scError = ScShimSymCryptTlsCbcHmacVerify(
        ScShimSymCryptHmacSha256Algorithm,
        (SYMCRYPT_HMAC_SHA256_EXPANDED_KEY *) buf1,
        &state,
        buf2,
        ((dataSize + 16) & ~15) + SYMCRYPT_HMAC_SHA256_RESULT_SIZE);

    SYMCRYPT_ASSERT( scError == SYMCRYPT_NO_ERROR );
}



///////////////////////
//  TlsCbcHmacSha1

template<> VOID algImpKeyPerfFunction<ImpXxx, AlgTlsCbcHmacSha1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize );
template<> VOID algImpCleanPerfFunction<ImpXxx, AlgTlsCbcHmacSha1>( PBYTE buf1, PBYTE buf2, PBYTE buf3 );
template<> VOID algImpDataPerfFunction<ImpXxx, AlgTlsCbcHmacSha1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize );
template<> VOID algImpDecryptPerfFunction<ImpXxx, AlgTlsCbcHmacSha1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize );

template<>
TlsCbcHmacImp<ImpXxx, AlgTlsCbcHmacSha1>::TlsCbcHmacImp()
{
    m_perfKeyFunction       = &algImpKeyPerfFunction    <ImpXxx, AlgTlsCbcHmacSha1>;
    m_perfCleanFunction     = &algImpCleanPerfFunction  <ImpXxx, AlgTlsCbcHmacSha1>;
    m_perfDataFunction      = &algImpDataPerfFunction   <ImpXxx, AlgTlsCbcHmacSha1>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpXxx, AlgTlsCbcHmacSha1>;
}

template<>
TlsCbcHmacImp<ImpXxx, AlgTlsCbcHmacSha1>::~TlsCbcHmacImp<ImpXxx, AlgTlsCbcHmacSha1>()
{
}

template<>
NTSTATUS
TlsCbcHmacImp<ImpXxx, AlgTlsCbcHmacSha1>::verify(
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

    ScShimSymCryptHmacSha1ExpandKey( &key, pbKey, cbKey );
    ScShimSymCryptHmacSha1Init( &state, &key );

    ScShimSymCryptHmacSha1Append( &state, pbHeader, cbHeader );
    scError = ScShimSymCryptTlsCbcHmacVerify( ScShimSymCryptHmacSha1Algorithm, &key, &state, pbData, cbData );

    status = scError == SYMCRYPT_NO_ERROR ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

    return status;
}

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgTlsCbcHmacSha1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );
    ScShimSymCryptHmacSha1ExpandKey( (SYMCRYPT_HMAC_SHA1_EXPANDED_KEY *) buf1, buf2, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgTlsCbcHmacSha1>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    SymCryptWipeKnownSize( buf1, sizeof( SYMCRYPT_HMAC_SHA1_EXPANDED_KEY ) );
}


template<>
VOID
algImpDataPerfFunction<ImpXxx, AlgTlsCbcHmacSha1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_HMAC_SHA1_STATE state;
    UINT32 paddingSize;

    ScShimSymCryptHmacSha1Init( &state, (SYMCRYPT_HMAC_SHA1_EXPANDED_KEY *) buf1 );
    ScShimSymCryptHmacSha1Append( &state, buf3, 13 );       // typical header is 13 bytes
    ScShimSymCryptHmacSha1Append( &state, buf2, dataSize );
    ScShimSymCryptHmacSha1Result( &state, &buf2[ dataSize ] );

    paddingSize = 15 - ((dataSize + SYMCRYPT_HMAC_SHA1_RESULT_SIZE) & 15);

    memset( &buf2[dataSize + SYMCRYPT_HMAC_SHA1_RESULT_SIZE], (BYTE) paddingSize, paddingSize + 1);
}

template<>
VOID
algImpDecryptPerfFunction<ImpXxx, AlgTlsCbcHmacSha1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_HMAC_SHA1_STATE  state;
    SYMCRYPT_ERROR scError;

    ScShimSymCryptHmacSha1Init( &state, (SYMCRYPT_HMAC_SHA1_EXPANDED_KEY *) buf1 );
    ScShimSymCryptHmacSha1Append( &state, buf3, 13 );

    scError = ScShimSymCryptTlsCbcHmacVerify(
        ScShimSymCryptHmacSha1Algorithm,
        (SYMCRYPT_HMAC_SHA1_EXPANDED_KEY *) buf1,
        &state,
        buf2,
        ((dataSize + SYMCRYPT_HMAC_SHA1_RESULT_SIZE + 16) & ~15));

    SYMCRYPT_ASSERT( scError == SYMCRYPT_NO_ERROR );
}


///////////////////////
//  TlsCbcHmacSha384

template<> VOID algImpKeyPerfFunction<ImpXxx, AlgTlsCbcHmacSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize );
template<> VOID algImpCleanPerfFunction<ImpXxx, AlgTlsCbcHmacSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3 );
template<> VOID algImpDataPerfFunction<ImpXxx, AlgTlsCbcHmacSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize );
template<> VOID algImpDecryptPerfFunction<ImpXxx, AlgTlsCbcHmacSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize );

template<>
TlsCbcHmacImp<ImpXxx, AlgTlsCbcHmacSha384>::TlsCbcHmacImp()
{
    m_perfKeyFunction       = &algImpKeyPerfFunction    <ImpXxx, AlgTlsCbcHmacSha384>;
    m_perfCleanFunction     = &algImpCleanPerfFunction  <ImpXxx, AlgTlsCbcHmacSha384>;
    m_perfDataFunction      = &algImpDataPerfFunction   <ImpXxx, AlgTlsCbcHmacSha384>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpXxx, AlgTlsCbcHmacSha384>;
}

template<>
TlsCbcHmacImp<ImpXxx, AlgTlsCbcHmacSha384>::~TlsCbcHmacImp<ImpXxx, AlgTlsCbcHmacSha384>()
{
}

template<>
NTSTATUS
TlsCbcHmacImp<ImpXxx, AlgTlsCbcHmacSha384>::verify(
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

    ScShimSymCryptHmacSha384ExpandKey( &key, pbKey, cbKey );
    ScShimSymCryptHmacSha384Init( &state, &key );

    ScShimSymCryptHmacSha384Append( &state, pbHeader, cbHeader );
    scError = ScShimSymCryptTlsCbcHmacVerify( ScShimSymCryptHmacSha384Algorithm, &key, &state, pbData, cbData );

    status = scError == SYMCRYPT_NO_ERROR ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

    return status;
}

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgTlsCbcHmacSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );
    ScShimSymCryptHmacSha384ExpandKey( (SYMCRYPT_HMAC_SHA384_EXPANDED_KEY *) buf1, buf2, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgTlsCbcHmacSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    SymCryptWipeKnownSize( buf1, sizeof( SYMCRYPT_HMAC_SHA384_EXPANDED_KEY ) );
}


template<>
VOID
algImpDataPerfFunction<ImpXxx, AlgTlsCbcHmacSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_HMAC_SHA384_STATE state;
    UINT32 paddingSize;

    ScShimSymCryptHmacSha384Init( &state, (SYMCRYPT_HMAC_SHA384_EXPANDED_KEY *) buf1 );
    ScShimSymCryptHmacSha384Append( &state, buf3, 13 );       // typical header is 13 bytes
    ScShimSymCryptHmacSha384Append( &state, buf2, dataSize );
    ScShimSymCryptHmacSha384Result( &state, &buf2[ dataSize ] );

    paddingSize = 15 - (dataSize & 15);

    memset( &buf2[dataSize + SYMCRYPT_HMAC_SHA384_RESULT_SIZE], (BYTE) paddingSize, paddingSize + 1);
}

template<>
VOID
algImpDecryptPerfFunction<ImpXxx, AlgTlsCbcHmacSha384>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_HMAC_SHA384_STATE  state;
    SYMCRYPT_ERROR scError;

    ScShimSymCryptHmacSha384Init( &state, (SYMCRYPT_HMAC_SHA384_EXPANDED_KEY *) buf1 );
    ScShimSymCryptHmacSha384Append( &state, buf3, 13 );

    scError = ScShimSymCryptTlsCbcHmacVerify(
        ScShimSymCryptHmacSha384Algorithm,
        (SYMCRYPT_HMAC_SHA384_EXPANDED_KEY *) buf1,
        &state,
        buf2,
        ((dataSize + 16) & ~15) + SYMCRYPT_HMAC_SHA384_RESULT_SIZE);

    SYMCRYPT_ASSERT( scError == SYMCRYPT_NO_ERROR );
}

//============================
// The DeveloperTest algorithm is just for tests during active development.

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgDeveloperTest>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgDeveloperTest>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

//extern "C" { VOID SYMCRYPT_CALL SymCryptTestMulx(); }

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgDeveloperTest>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    //SymCryptTestMulx();
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( dataSize );
}


template<>
ArithImp<ImpXxx, AlgDeveloperTest>::ArithImp()
{
    // if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptTestMulx))
    // {
    //     throw STATUS_NOT_SUPPORTED;
    // }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgDeveloperTest>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgDeveloperTest>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgDeveloperTest>;
}

template<>
ArithImp<ImpXxx, AlgDeveloperTest>::~ArithImp()
{
}



//============================

// Table with the RSA keys' sizes and pointers to keys
struct {
    SIZE_T                      keySize;
    UINT32                      generateFlags;
    PSYMCRYPT_RSAKEY            pkRsakey;
} CONCAT2(g_precomputedRsaKeys, ImpXxx)[] = {
    {  32, SYMCRYPT_FLAG_RSAKEY_SIGN, NULL },
    {  64, SYMCRYPT_FLAG_RSAKEY_SIGN, NULL },
    { 128, SYMCRYPT_FLAG_RSAKEY_SIGN, NULL },
    { 256, SYMCRYPT_FLAG_RSAKEY_SIGN, NULL },
    { 384, SYMCRYPT_FLAG_RSAKEY_SIGN, NULL },
    { 512, SYMCRYPT_FLAG_RSAKEY_SIGN, NULL },
    {1024, SYMCRYPT_FLAG_RSAKEY_SIGN, NULL },
    {  32, SYMCRYPT_FLAG_RSAKEY_ENCRYPT, NULL },
    {  64, SYMCRYPT_FLAG_RSAKEY_ENCRYPT, NULL },
    { 128, SYMCRYPT_FLAG_RSAKEY_ENCRYPT, NULL },
    { 256, SYMCRYPT_FLAG_RSAKEY_ENCRYPT, NULL },
    { 384, SYMCRYPT_FLAG_RSAKEY_ENCRYPT, NULL },
    { 512, SYMCRYPT_FLAG_RSAKEY_ENCRYPT, NULL },
    {1024, SYMCRYPT_FLAG_RSAKEY_ENCRYPT, NULL },
};

template<>
void
SetupSymCryptRsaKey<ImpXxx>( PBYTE buf1, SIZE_T keySize, UINT32 generateFlags )
{
    int i = 0;
    BOOLEAN bFound = FALSE;

    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    for( i=0; i < ARRAY_SIZE(CONCAT2(g_precomputedRsaKeys, ImpXxx)); i++ )
    {
        if ( keySize == CONCAT2(g_precomputedRsaKeys, ImpXxx)[i].keySize &&
             generateFlags == CONCAT2(g_precomputedRsaKeys, ImpXxx)[i].generateFlags )
        {
            bFound = TRUE;

            if ( CONCAT2(g_precomputedRsaKeys, ImpXxx)[i].pkRsakey == NULL )
            {
                SYMCRYPT_RSA_PARAMS rsaParams = { 0 };
                PSYMCRYPT_RSAKEY pkRsakey = NULL;

                // Set the parameters
                rsaParams.version = 1;
                rsaParams.nBitsOfModulus = ((UINT32)keySize) * 8;
                rsaParams.nPrimes = 2;
                rsaParams.nPubExp = 1;

                pkRsakey = ScShimSymCryptRsakeyAllocate( &rsaParams, 0 );
                CHECK( pkRsakey != NULL, "?" );

                if ( rsaParams.nBitsOfModulus < SYMCRYPT_RSAKEY_FIPS_MIN_BITSIZE_MODULUS )
                {
                    generateFlags |= SYMCRYPT_FLAG_KEY_NO_FIPS;
                }

                // Use default exponent
                scError = ScShimSymCryptRsakeyGenerate( pkRsakey, nullptr, 0, generateFlags );
                CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

                CONCAT2(g_precomputedRsaKeys, ImpXxx)[i].pkRsakey = pkRsakey;
            }

            break;
        }
    }

    CHECK( bFound, "?" );

    *((PSYMCRYPT_RSAKEY *) buf1) = CONCAT2(g_precomputedRsaKeys, ImpXxx)[i].pkRsakey;
}

template<>
void
sc_RsaKeyPerf<ImpXxx>( PBYTE buf1, PBYTE buf2, SIZE_T keySize, UINT32 generateFlags )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    SetupSymCryptRsaKey<ImpXxx>( buf1, keySize, generateFlags );

    buf2[0] = 0;
    // Don't fill it up so that it is smaller than the modulus
#if IMP_UseSymCryptRandom
    ScShimSymCryptRandom( buf2 + 1, keySize - 1 );
#else
    scError = ScShimSymCryptCallbackRandom( buf2 + 1, keySize - 1 );
#endif
    CHECK(scError == SYMCRYPT_NO_ERROR, "?");
}

//================================================


HASH_INFO CONCAT2(hashInfoTable, ImpXxx)[9] = { 0 };

template<>
PCHASH_INFO getHashInfo<ImpXxx>(PCSTR pcstrName)
{
    if( CONCAT2(hashInfoTable, ImpXxx)[0].name == NULL )
    {
        CONCAT2(hashInfoTable, ImpXxx)[0] = { "MD5",    ScShimSymCryptMd5Algorithm,     ScShimSymCryptMd5OidList,    SYMCRYPT_MD5_OID_COUNT };
        CONCAT2(hashInfoTable, ImpXxx)[1] = { "SHA1",   ScShimSymCryptSha1Algorithm,    ScShimSymCryptSha1OidList,   SYMCRYPT_SHA1_OID_COUNT };
        CONCAT2(hashInfoTable, ImpXxx)[2] = { "SHA256", ScShimSymCryptSha256Algorithm,  ScShimSymCryptSha256OidList, SYMCRYPT_SHA256_OID_COUNT };
        CONCAT2(hashInfoTable, ImpXxx)[3] = { "SHA384", ScShimSymCryptSha384Algorithm,  ScShimSymCryptSha384OidList, SYMCRYPT_SHA384_OID_COUNT };
        CONCAT2(hashInfoTable, ImpXxx)[4] = { "SHA512", ScShimSymCryptSha512Algorithm,  ScShimSymCryptSha512OidList, SYMCRYPT_SHA512_OID_COUNT };
        CONCAT2(hashInfoTable, ImpXxx)[5] = { "SHA3_256", ScShimSymCryptSha3_256Algorithm,  ScShimSymCryptSha3_256OidList, SYMCRYPT_SHA3_256_OID_COUNT };
        CONCAT2(hashInfoTable, ImpXxx)[6] = { "SHA3_384", ScShimSymCryptSha3_384Algorithm,  ScShimSymCryptSha3_384OidList, SYMCRYPT_SHA3_384_OID_COUNT };
        CONCAT2(hashInfoTable, ImpXxx)[7] = { "SHA3_512", ScShimSymCryptSha3_512Algorithm,  ScShimSymCryptSha3_512OidList, SYMCRYPT_SHA3_512_OID_COUNT };
    }

    for (int i = 0; CONCAT2(hashInfoTable, ImpXxx)[i].name != NULL; i++)
    {
        if( STRICMP( pcstrName, CONCAT2(hashInfoTable, ImpXxx)[i].name ) == 0 )
        {
            return &CONCAT2(hashInfoTable, ImpXxx)[i];
        }
    }
    CHECK( FALSE, "?" );
    return NULL;
}

// Rsa Pkcs1 Sign
template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgRsaSignPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SIZE_T cbDst = 0;

    sc_RsaKeyPerf<ImpXxx>( buf1, buf2, keySize, SYMCRYPT_FLAG_RSAKEY_SIGN );

    scError = ScShimSymCryptRsaPkcs1Sign(
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

    scError = ScShimSymCryptRsaPkcs1Verify(
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
algImpCleanPerfFunction<ImpXxx, AlgRsaSignPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgRsaSignPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SIZE_T cbDst = 0;

    ScShimSymCryptRsaPkcs1Sign(
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
algImpDecryptPerfFunction< ImpXxx, AlgRsaSignPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_ERROR scError;

    scError = ScShimSymCryptRsaPkcs1Verify(
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
RsaSignImp<ImpXxx, AlgRsaSignPkcs1>::RsaSignImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgRsaSignPkcs1>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction< ImpXxx, AlgRsaSignPkcs1>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgRsaSignPkcs1>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgRsaSignPkcs1>;

    state.pKey = NULL;
}

template<>
RsaSignImp<ImpXxx, AlgRsaSignPkcs1>::~RsaSignImp()
{
    if( state.pKey != NULL )
    {
        ScShimSymCryptRsakeyFree( state.pKey );
        state.pKey = NULL;
    }
}

template<>
NTSTATUS
RsaSignImp<ImpXxx, AlgRsaSignPkcs1>::setKey( PCRSAKEY_TESTBLOB pcKeyBlob )
{
    SYMCRYPT_ERROR scError;

    if( state.pKey != NULL )
    {
        ScShimSymCryptRsakeyFree( state.pKey );
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

    state.pKey = ScShimSymCryptRsakeyAllocate( &params, 0 );
    CHECK( state.pKey != NULL, "?" );

    PCBYTE ppPrime[2] = {&pcKeyBlob->abPrime1[0], &pcKeyBlob->abPrime2[0] };
    SIZE_T cbPrime[2] = {pcKeyBlob->cbPrime1, pcKeyBlob->cbPrime2 };

    scError = ScShimSymCryptRsakeySetValue(
        &pcKeyBlob->abModulus[0], pcKeyBlob->cbModulus,
        &pcKeyBlob->u64PubExp, 1,
        ppPrime, cbPrime, 2,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_FLAG_RSAKEY_SIGN,
        state.pKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
RsaSignImp<ImpXxx, AlgRsaSignPkcs1>::sign(
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

    pInfo = getHashInfo<ImpXxx>( pcstrHashAlgName);
    scError = ScShimSymCryptRsaPkcs1Sign(
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
RsaSignImp<ImpXxx, AlgRsaSignPkcs1>::verify(
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

    pInfo = getHashInfo<ImpXxx>( pcstrHashAlgName);
    scError = ScShimSymCryptRsaPkcs1Verify(
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
algImpKeyPerfFunction<ImpXxx, AlgRsaSignPss>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SIZE_T cbDst = 0;

    sc_RsaKeyPerf<ImpXxx>( buf1, buf2, keySize, SYMCRYPT_FLAG_RSAKEY_SIGN );

    scError = ScShimSymCryptRsaPssSign(
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

    scError = ScShimSymCryptRsaPssVerify(
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
algImpCleanPerfFunction<ImpXxx, AlgRsaSignPss>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgRsaSignPss>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SIZE_T cbDst = 0;

    ScShimSymCryptRsaPssSign(
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
algImpDecryptPerfFunction< ImpXxx, AlgRsaSignPss>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_ERROR scError;

    scError = ScShimSymCryptRsaPssVerify(
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
RsaSignImp<ImpXxx, AlgRsaSignPss>::RsaSignImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgRsaSignPss>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction< ImpXxx, AlgRsaSignPss>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgRsaSignPss>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgRsaSignPss>;

    state.pKey = NULL;
}

template<>
RsaSignImp<ImpXxx, AlgRsaSignPss>::~RsaSignImp()
{
    if( state.pKey != NULL )
    {
        ScShimSymCryptRsakeyFree( state.pKey );
        state.pKey = NULL;
    }
}

template<>
NTSTATUS
RsaSignImp<ImpXxx, AlgRsaSignPss>::setKey( PCRSAKEY_TESTBLOB pcKeyBlob )
{
    SYMCRYPT_ERROR scError;

    if( state.pKey != NULL )
    {
        ScShimSymCryptRsakeyFree( state.pKey );
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

    state.pKey = ScShimSymCryptRsakeyAllocate( &params, 0 );
    CHECK( state.pKey != NULL, "?" );

    PCBYTE ppPrime[2] = {&pcKeyBlob->abPrime1[0], &pcKeyBlob->abPrime2[0] };
    SIZE_T cbPrime[2] = {pcKeyBlob->cbPrime1, pcKeyBlob->cbPrime2 };

    scError = ScShimSymCryptRsakeySetValue(
        &pcKeyBlob->abModulus[0], pcKeyBlob->cbModulus,
        &pcKeyBlob->u64PubExp, 1,
        ppPrime, cbPrime, 2,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_FLAG_RSAKEY_SIGN,
        state.pKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
RsaSignImp<ImpXxx, AlgRsaSignPss>::sign(
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

    pInfo = getHashInfo<ImpXxx>( pcstrHashAlgName);
    scError = ScShimSymCryptRsaPssSign(
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
RsaSignImp<ImpXxx, AlgRsaSignPss>::verify(
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

    pInfo = getHashInfo<ImpXxx>( pcstrHashAlgName);
    scError = ScShimSymCryptRsaPssVerify(
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
        // saml 2022/04:
        // In order to update error message returned from SymCryptRsaPssVerify and not break
        // multi-implementation test of SymCrypt vs. CNG, we must map SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE
        // to STATUS_INVALID_PARAMETER rather than STATUS_INVALID_SIGNATURE for now.
        // Once both CNG and SymCrypt are updated reliably we can reintroduce testing that the two
        // error responses cohere - but for now they won't.
    case SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE:
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
algImpKeyPerfFunction<ImpXxx, AlgRsaEncRaw>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    sc_RsaKeyPerf<ImpXxx>( buf1, buf2, keySize, SYMCRYPT_FLAG_RSAKEY_ENCRYPT );

    scError = ScShimSymCryptRsaRawEncrypt(
                    *((PSYMCRYPT_RSAKEY *) buf1),
                    buf2,
                    keySize,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0,
                    buf3,
                    keySize );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    scError = ScShimSymCryptRsaRawDecrypt(
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
algImpCleanPerfFunction<ImpXxx, AlgRsaEncRaw>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgRsaEncRaw>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ScShimSymCryptRsaRawEncrypt(
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
algImpDecryptPerfFunction< ImpXxx, AlgRsaEncRaw>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_ERROR scError;

    scError = ScShimSymCryptRsaRawDecrypt(
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
RsaEncImp<ImpXxx, AlgRsaEncRaw>::RsaEncImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgRsaEncRaw>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpXxx, AlgRsaEncRaw>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgRsaEncRaw>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgRsaEncRaw>;

    state.pKey = NULL;
}

template<>
RsaEncImp<ImpXxx, AlgRsaEncRaw>::~RsaEncImp()
{
    if( state.pKey != NULL )
    {
        ScShimSymCryptRsakeyFree( state.pKey );
        state.pKey = NULL;
    }
}

template<>
NTSTATUS
RsaEncImp<ImpXxx, AlgRsaEncRaw>::setKey( PCRSAKEY_TESTBLOB pcKeyBlob )
{
    SYMCRYPT_ERROR scError;

    if( state.pKey != NULL )
    {
        ScShimSymCryptRsakeyFree( state.pKey );
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

    state.pKey = ScShimSymCryptRsakeyAllocate( &params, 0 );
    CHECK( state.pKey != NULL, "?" );

    PCBYTE ppPrime[2] = {&pcKeyBlob->abPrime1[0], &pcKeyBlob->abPrime2[0] };
    SIZE_T cbPrime[2] = {pcKeyBlob->cbPrime1, pcKeyBlob->cbPrime2 };

    scError = ScShimSymCryptRsakeySetValue(
        &pcKeyBlob->abModulus[0], pcKeyBlob->cbModulus,
        &pcKeyBlob->u64PubExp, 1,
        ppPrime, cbPrime, 2,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_FLAG_RSAKEY_ENCRYPT,
        state.pKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
RsaEncImp<ImpXxx, AlgRsaEncRaw>::encrypt(
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

    SIZE_T cbKey = ScShimSymCryptRsakeySizeofModulus( state.pKey );
    CHECK( cbCiphertext == cbKey, "Wrong ciphertext size" );
    CHECK( cbMsg == cbKey, "Wrong message size" );

    scError = ScShimSymCryptRsaRawEncrypt(
                                state.pKey,
                                pbMsg, cbMsg,
                                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                0,
                                pbCiphertext, cbCiphertext );

    return scError == SYMCRYPT_NO_ERROR ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

template<>
NTSTATUS
RsaEncImp<ImpXxx, AlgRsaEncRaw>::decrypt(
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

    SIZE_T cbKey = ScShimSymCryptRsakeySizeofModulus( state.pKey );
    CHECK( cbCiphertext == cbKey, "Wrong ciphertext size" );
    CHECK( cbMsg >= cbKey, "Wrong message size" );

    scError = ScShimSymCryptRsaRawDecrypt(
                                state.pKey,
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
algImpKeyPerfFunction<ImpXxx, AlgRsaEncPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SIZE_T cbDst = 0;

    sc_RsaKeyPerf<ImpXxx>( buf1, buf2, keySize, SYMCRYPT_FLAG_RSAKEY_ENCRYPT );

    scError = ScShimSymCryptRsaPkcs1Encrypt(
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

    scError = ScShimSymCryptRsaPkcs1Decrypt(
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
algImpCleanPerfFunction<ImpXxx, AlgRsaEncPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgRsaEncPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SIZE_T cbDst = 0;

    ScShimSymCryptRsaPkcs1Encrypt(
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
algImpDecryptPerfFunction< ImpXxx, AlgRsaEncPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_ERROR scError;
    SIZE_T cbDst;

    scError = ScShimSymCryptRsaPkcs1Decrypt(
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
RsaEncImp<ImpXxx, AlgRsaEncPkcs1>::RsaEncImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgRsaEncPkcs1>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpXxx, AlgRsaEncPkcs1>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgRsaEncPkcs1>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgRsaEncPkcs1>;

    state.pKey = NULL;
}

template<>
RsaEncImp<ImpXxx, AlgRsaEncPkcs1>::~RsaEncImp()
{
    if( state.pKey != NULL )
    {
        ScShimSymCryptRsakeyFree( state.pKey );
        state.pKey = NULL;
    }
}

template<>
NTSTATUS
RsaEncImp<ImpXxx, AlgRsaEncPkcs1>::setKey( PCRSAKEY_TESTBLOB pcKeyBlob )
{
    SYMCRYPT_ERROR scError;

    if( state.pKey != NULL )
    {
        ScShimSymCryptRsakeyFree( state.pKey );
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

    state.pKey = ScShimSymCryptRsakeyAllocate( &params, 0 );
    CHECK( state.pKey != NULL, "?" );

    PCBYTE ppPrime[2] = {&pcKeyBlob->abPrime1[0], &pcKeyBlob->abPrime2[0] };
    SIZE_T cbPrime[2] = {pcKeyBlob->cbPrime1, pcKeyBlob->cbPrime2 };

    scError = ScShimSymCryptRsakeySetValue(
        &pcKeyBlob->abModulus[0], pcKeyBlob->cbModulus,
        &pcKeyBlob->u64PubExp, 1,
        ppPrime, cbPrime, 2,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_FLAG_RSAKEY_ENCRYPT,
        state.pKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
RsaEncImp<ImpXxx, AlgRsaEncPkcs1>::encrypt(
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

    SIZE_T cbKey = ScShimSymCryptRsakeySizeofModulus( state.pKey );
    CHECK( cbCiphertext == cbKey, "Wrong ciphertext size" );

    scError = ScShimSymCryptRsaPkcs1Encrypt(
                                state.pKey,
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
RsaEncImp<ImpXxx, AlgRsaEncPkcs1>::decrypt(
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

    SIZE_T cbKey = ScShimSymCryptRsakeySizeofModulus( state.pKey );
    CHECK( cbCiphertext == cbKey, "Wrong ciphertext size" );

    scError = ScShimSymCryptRsaPkcs1Decrypt(
                                state.pKey,
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
algImpKeyPerfFunction<ImpXxx, AlgRsaEncOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SIZE_T cbDst = 0;

    sc_RsaKeyPerf<ImpXxx>( buf1, buf2, keySize, SYMCRYPT_FLAG_RSAKEY_ENCRYPT );

    scError = ScShimSymCryptRsaOaepEncrypt(
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

    scError = ScShimSymCryptRsaOaepDecrypt(
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
algImpCleanPerfFunction<ImpXxx, AlgRsaEncOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgRsaEncOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SIZE_T cbDst = 0;
    SYMCRYPT_ERROR scError;

    scError = ScShimSymCryptRsaOaepEncrypt(
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
algImpDecryptPerfFunction< ImpXxx, AlgRsaEncOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_ERROR scError;
    SIZE_T cbDst;

    scError = ScShimSymCryptRsaOaepDecrypt(
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
RsaEncImp<ImpXxx, AlgRsaEncOaep>::RsaEncImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgRsaEncOaep>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpXxx, AlgRsaEncOaep>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgRsaEncOaep>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgRsaEncOaep>;

    state.pKey = NULL;
}

template<>
RsaEncImp<ImpXxx, AlgRsaEncOaep>::~RsaEncImp()
{
    if( state.pKey != NULL )
    {
        ScShimSymCryptRsakeyFree( state.pKey );
        state.pKey = NULL;
    }
}

template<>
NTSTATUS
RsaEncImp<ImpXxx, AlgRsaEncOaep>::setKey( PCRSAKEY_TESTBLOB pcKeyBlob )
{
    SYMCRYPT_ERROR scError;

    if( state.pKey != NULL )
    {
        ScShimSymCryptRsakeyFree( state.pKey );
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

    state.pKey = ScShimSymCryptRsakeyAllocate( &params, 0 );
    CHECK( state.pKey != NULL, "?" );

    PCBYTE ppPrime[2] = {&pcKeyBlob->abPrime1[0], &pcKeyBlob->abPrime2[0] };
    SIZE_T cbPrime[2] = {pcKeyBlob->cbPrime1, pcKeyBlob->cbPrime2 };

    scError = ScShimSymCryptRsakeySetValue(
        &pcKeyBlob->abModulus[0], pcKeyBlob->cbModulus,
        &pcKeyBlob->u64PubExp, 1,
        ppPrime, cbPrime, 2,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_FLAG_RSAKEY_ENCRYPT,
        state.pKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
RsaEncImp<ImpXxx, AlgRsaEncOaep>::encrypt(
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

    SIZE_T cbKey = ScShimSymCryptRsakeySizeofModulus( state.pKey );
    CHECK( cbCiphertext == cbKey, "Wrong ciphertext size" );

    pInfo = getHashInfo<ImpXxx>( pcstrHashAlgName );
    scError = ScShimSymCryptRsaOaepEncrypt(
                                state.pKey,
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
RsaEncImp<ImpXxx, AlgRsaEncOaep>::decrypt(
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

    SIZE_T cbKey = ScShimSymCryptRsakeySizeofModulus( state.pKey );
    CHECK( cbCiphertext == cbKey, "Wrong ciphertext size" );

    pInfo = getHashInfo<ImpXxx>( pcstrHashAlgName );
    scError = ScShimSymCryptRsaOaepDecrypt(
                                state.pKey,
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
RsaImp<ImpXxx, AlgRsaEncPkcs1>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgRsaEncPkcs1>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgRsaEncPkcs1>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgRsaEncPkcs1>;
}

template<>
RsaImp<ImpXxx, AlgRsaEncPkcs1>::~RsaImp()
{
}

// Rsa Pkcs1 Decryption

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgRsaDecPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SIZE_T cbDst = 0;

    ScShimSymCryptRsaPkcs1Decrypt(
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
RsaImp<ImpXxx, AlgRsaDecPkcs1>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgRsaDecPkcs1>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgRsaEncPkcs1>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgRsaEncPkcs1>;
}

template<>
RsaImp<ImpXxx, AlgRsaDecPkcs1>::~RsaImp()
{
}
*/

// Rsa Oaep Encryption
/*
template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgRsaEncOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    BYTE rbResult[1024] = { 0 };
    SIZE_T cbDst = 0;

    sc_RsaKeyPerf<ImpXxx>( buf1, buf2, keySize, SYMCRYPT_FLAG_RSAKEY_ENCRYPT );

    scError = ScShimSymCryptRsaOaepEncrypt(
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

    scError = ScShimSymCryptRsaOaepDecrypt(
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
algImpCleanPerfFunction<ImpXxx, AlgRsaEncOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgRsaEncOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SIZE_T cbDst = 0;

    ScShimSymCryptRsaOaepEncrypt(
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
RsaImp<ImpXxx, AlgRsaEncOaep>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgRsaEncOaep>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgRsaEncOaep>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgRsaEncOaep>;
}

template<>
RsaImp<ImpXxx, AlgRsaEncOaep>::~RsaImp()
{
}

// Rsa Oaep Decryption

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgRsaDecOaep>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SIZE_T cbDst = 0;

    ScShimSymCryptRsaOaepDecrypt(
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
RsaImp<ImpXxx, AlgRsaDecOaep>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgRsaDecOaep>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgRsaEncOaep>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgRsaEncOaep>;
}

template<>
RsaImp<ImpXxx, AlgRsaDecOaep>::~RsaImp()
{
}

template<>
RsaImp<ImpXxx, AlgRsaSignPkcs1>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgRsaSignPkcs1>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgRsaSignPkcs1>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgRsaSignPkcs1>;
}

template<>
RsaImp<ImpXxx, AlgRsaSignPkcs1>::~RsaImp()
{
}

// Rsa Pkcs1 Verify

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgRsaVerifyPkcs1>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ScShimSymCryptRsaPkcs1Verify(
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
RsaImp<ImpXxx, AlgRsaVerifyPkcs1>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgRsaVerifyPkcs1>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgRsaSignPkcs1>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgRsaSignPkcs1>;
}

template<>
RsaImp<ImpXxx, AlgRsaVerifyPkcs1>::~RsaImp()
{
}

template<>
RsaImp<ImpXxx, AlgRsaSignPss>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgRsaSignPss>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgRsaSignPss>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgRsaSignPss>;
}

template<>
RsaImp<ImpXxx, AlgRsaSignPss>::~RsaImp()
{
}

// Rsa Pss Verify

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgRsaVerifyPss>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ScShimSymCryptRsaPssVerify(
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
RsaImp<ImpXxx, AlgRsaVerifyPss>::RsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgRsaVerifyPss>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgRsaSignPss>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgRsaSignPss>;
}

template<>
RsaImp<ImpXxx, AlgRsaVerifyPss>::~RsaImp()
{
}
*/

//============================

template<>
VOID
DlgroupSetup<ImpXxx>( PBYTE buf1, SIZE_T keySize, BOOLEAN forDiffieHellman )
{
    SYMCRYPT_ERROR scError;
    PDLGROUP_INFO pInfo = (PDLGROUP_INFO)buf1;

    PCDLGROUP_TESTBLOB pBlob = dlgroupForSize( keySize * 8, forDiffieHellman );

    PCSYMCRYPT_HASH pHashAlgorithm = NULL;
    if( pBlob->pcstrHashAlgName != NULL )
    {
        pHashAlgorithm = getHashInfo<ImpXxx>(pBlob->pcstrHashAlgName)->pcHash;
    }

    CHECK( pBlob != NULL, "?" );

    PSYMCRYPT_DLGROUP pGroup = ScShimSymCryptDlgroupCreate( buf1 + 64, PERF_BUFFER_SIZE/2, pBlob->nBitsP, 8*pBlob->cbPrimeQ );

    CHECK( pGroup != NULL, "Could not create group" );

    scError = ScShimSymCryptDlgroupSetValue(
        &pBlob->abPrimeP[0], pBlob->cbPrimeP,
        pBlob->cbPrimeQ == 0 ? NULL : &pBlob->abPrimeQ[0], pBlob->cbPrimeQ,
        &pBlob->abGenG[0], pBlob->cbPrimeP,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        pHashAlgorithm,
        &pBlob->abSeed[0], pBlob->cbSeed,
        pBlob->genCounter,
        pBlob->fipsStandard,
        pGroup );

    CHECK( scError == SYMCRYPT_NO_ERROR, "Error setting group values" );

    pInfo->pBlob = pBlob;
    pInfo->pGroup = pGroup;
}

// Table with the DL groups sizes and pointers to the groups
struct {
    SIZE_T              keySize;        // Always equal to cbPrimeP
    PSYMCRYPT_DLGROUP   pDlgroup;
} CONCAT2(g_precomputedDlGroups, ImpXxx)[] = {
    {  64, NULL },
    { 128, NULL },
    { 256, NULL },
};

template<>
void
SetupDlGroup<ImpXxx>( PBYTE buf1, SIZE_T keySize )
{
    int i = 0;
    BOOLEAN bFound = FALSE;

    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PSYMCRYPT_DLGROUP pDlgroup = NULL;

    for( i=0; i < ARRAY_SIZE(CONCAT2(g_precomputedDlGroups, ImpXxx)); i++ )
    {
        if ( keySize == CONCAT2(g_precomputedDlGroups, ImpXxx)[i].keySize )
        {
            bFound = TRUE;

            if ( CONCAT2(g_precomputedDlGroups, ImpXxx)[i].pDlgroup == NULL )
            {
                pDlgroup = ScShimSymCryptDlgroupAllocate( 8*((UINT32)CONCAT2(g_precomputedDlGroups, ImpXxx)[i].keySize), 0 );
                CHECK( pDlgroup != NULL, "?" );

                scError = ScShimSymCryptDlgroupGenerate(
                    ScShimSymCryptSha256Algorithm, SYMCRYPT_DLGROUP_FIPS_LATEST, pDlgroup );
                    // This algorithm is safe for all our sizes
                CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

                CONCAT2(g_precomputedDlGroups, ImpXxx)[i].pDlgroup = pDlgroup;
            }

            break;
        }
    }

    CHECK( bFound, "?" );

    *((PSYMCRYPT_DLGROUP *) buf1) = CONCAT2(g_precomputedDlGroups, ImpXxx)[i].pDlgroup;
}

template<>
void
SetupSymCryptDsa<ImpXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    PCSYMCRYPT_DLGROUP pDlgroup = *((PCSYMCRYPT_DLGROUP *)buf1);

    PSYMCRYPT_DLKEY * pPtrs = ((PSYMCRYPT_DLKEY *) buf2);

    SIZE_T buff2Offset = ((2*sizeof(PSYMCRYPT_DLKEY) + SYMCRYPT_ASYM_ALIGN_VALUE - 1)/SYMCRYPT_ASYM_ALIGN_VALUE )*SYMCRYPT_ASYM_ALIGN_VALUE;
    UINT32 dlkeysize = ScShimSymCryptSizeofDlkeyFromDlgroup( pDlgroup );

    SIZE_T buff3Offset = sizeof(UINT32);
    UINT32 signatureSize = 0;
    PUINT32 puiSignatureSize = NULL;
    UINT32 cbAgreedSecret, cbHashValue;

    UINT32 generateFlags = SYMCRYPT_FLAG_DLKEY_DSA;

    pPtrs[0] = ScShimSymCryptDlkeyCreate( buf2 + buff2Offset, dlkeysize, pDlgroup );
    scError = ScShimSymCryptDlkeyGenerate( generateFlags, pPtrs[0] );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    pPtrs[1] = ScShimSymCryptDlkeyCreate( buf2 + buff2Offset + dlkeysize, dlkeysize, pDlgroup );
    scError = ScShimSymCryptDlkeyGenerate( generateFlags, pPtrs[1] );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    signatureSize = 2*ScShimSymCryptDlkeySizeofPrivateKey( pPtrs[0] );
    puiSignatureSize = (PUINT32) buf3;

    cbAgreedSecret = ScShimSymCryptDlkeySizeofPublicKey( pPtrs[0] );
    CHECK( buff3Offset + SYMCRYPT_MAX( signatureSize, cbAgreedSecret ) <= SCRATCH_BUF_SIZE,
           "Destination buffer cannot fit the DSA signature or the DH secret" );

    *puiSignatureSize = signatureSize;

    // Verify that DSA can work
    cbHashValue = ScShimSymCryptDlkeySizeofPrivateKey( ((PSYMCRYPT_DLKEY *)buf2)[0] );
    scError = ScShimSymCryptDsaSign(
                ((PSYMCRYPT_DLKEY *) buf2)[0],
                buf2,           // Sign the keys' buffer
                cbHashValue,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0,
                buf3 + sizeof(UINT32),
                *((PUINT32) buf3) ) ;
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptDsaSign failed" );

    // Verify the signature to make sure everything is ok
    scError = ScShimSymCryptDsaVerify(
                ((PSYMCRYPT_DLKEY *) buf2)[0],
                buf2,           // Verify the keys' buffer
                cbHashValue,
                buf3 + sizeof(UINT32),
                *((PUINT32) buf3),
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptDsaVerify failed" );
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgDsaSign>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    SetupDlGroup<ImpXxx>( buf1, keySize );
    SetupSymCryptDsa<ImpXxx>( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgDsaSign>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgDsaSign>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( dataSize );

    UINT32 cbHashValue = ScShimSymCryptDlkeySizeofPrivateKey( ((PSYMCRYPT_DLKEY *)buf2)[0] );

    ScShimSymCryptDsaSign(
                ((PSYMCRYPT_DLKEY *) buf2)[0],
                buf2,           // Sign the keys' buffer
                cbHashValue,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0,
                buf3 + sizeof(UINT32),
                *((PUINT32) buf3) );
}

template<>
DlImp<ImpXxx, AlgDsaSign>::DlImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgDsaSign>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgDsaSign>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgDsaSign>;
}

template<>
DlImp<ImpXxx, AlgDsaSign>::~DlImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgDsaVerify>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    SetupDlGroup<ImpXxx>( buf1, keySize );
    SetupSymCryptDsa<ImpXxx>( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgDsaVerify>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgDsaVerify>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( dataSize );

    UINT32 cbHashValue = ScShimSymCryptDlkeySizeofPrivateKey( ((PSYMCRYPT_DLKEY *)buf2)[0] );

    ScShimSymCryptDsaVerify(
                ((PSYMCRYPT_DLKEY *) buf2)[0],
                buf2,           // Sign the keys' buffer
                cbHashValue,
                buf3 + sizeof(UINT32),
                *((PUINT32) buf3),
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0 );
}

template<>
DlImp<ImpXxx, AlgDsaVerify>::DlImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgDsaVerify>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgDsaVerify>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgDsaVerify>;
}

template<>
DlImp<ImpXxx, AlgDsaVerify>::~DlImp()
{
}

//============================

template<>
PSYMCRYPT_DLGROUP
dlgroupObjectFromTestBlob<ImpXxx>( PCDLGROUP_TESTBLOB pBlob )
{
    SYMCRYPT_ERROR scError;

    PSYMCRYPT_DLGROUP pGroup = NULL;

    PCSYMCRYPT_HASH pHashAlgorithm = NULL;
    if( pBlob->pcstrHashAlgName != NULL )
    {
        pHashAlgorithm = getHashInfo<ImpXxx>(pBlob->pcstrHashAlgName)->pcHash;
    }

    pGroup = ScShimSymCryptDlgroupAllocate( pBlob->nBitsP, 8*pBlob->cbPrimeQ );
    CHECK( pGroup != NULL, "Could not create group" );

    scError = ScShimSymCryptDlgroupSetValue(
        &pBlob->abPrimeP[0], pBlob->cbPrimeP,
        pBlob->cbPrimeQ == 0 ? NULL : &pBlob->abPrimeQ[0], pBlob->cbPrimeQ,
        &pBlob->abGenG[0], pBlob->cbPrimeP,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        pHashAlgorithm,
        pBlob->cbSeed == 0 ? NULL : &pBlob->abSeed[0], pBlob->cbSeed,
        pBlob->genCounter,
        pBlob->fipsStandard,
        pGroup );

    CHECK( scError == SYMCRYPT_NO_ERROR, "Error setting group values" );

    return pGroup;
}

template<>
PSYMCRYPT_DLKEY
dlkeyObjectFromTestBlob<ImpXxx>( PCSYMCRYPT_DLGROUP pGroup, PCDLKEY_TESTBLOB pBlob, UINT32 algFlags, BOOL setPrivate /*= TRUE*/ )
{
    PSYMCRYPT_DLKEY pRes;
    SYMCRYPT_ERROR scError;
    UINT32 flags = algFlags;
    PCBYTE pbPrivKey = NULL;
    SIZE_T cbPrivKey = 0;
    PCBYTE pbPubKey = NULL;
    SIZE_T cbPubKey = 0;

    pRes = ScShimSymCryptDlkeyAllocate( pGroup );
    CHECK( pRes != NULL, "?" );

    // We want to exercise the various code paths semi-randomly in tests - we will be hitting this function 100s of times
    // in unit tests, and there are only 16 combinations of code paths we want to exercise, so we should get decent coverage

    BYTE randByte = g_rng.byte();

    if (!pBlob->pGroup->fHasPrimeQ ||
        pBlob->fPrivateModP ||
        ((algFlags == SYMCRYPT_FLAG_DLKEY_DH) && (!pBlob->pGroup->isSafePrimeGroup)) ||
        ((algFlags == SYMCRYPT_FLAG_DLKEY_DSA) && (pBlob->pGroup->isSafePrimeGroup)) ||
        (randByte & 0x1))
    {
        flags |= SYMCRYPT_FLAG_KEY_NO_FIPS;
        if (randByte & 0x2)
        {
            flags |= SYMCRYPT_FLAG_DLKEY_DSA;
            flags |= SYMCRYPT_FLAG_DLKEY_DH;
        }
    }

    if (setPrivate || (randByte & 0x4))
    {
        pbPrivKey = &pBlob->abPrivKey[0];
        cbPrivKey = pBlob->cbPrivKey;

        if (pBlob->nBitsPriv != 0)
        {
            scError = ScShimSymCryptDlkeySetPrivateKeyLength( pRes, pBlob->nBitsPriv, 0 );
            CHECK4( scError == SYMCRYPT_NO_ERROR, "Error setting private key length pBlob->nBitsPriv %d pBlob->pGroup->cbPrimeP %d",
                    pBlob->nBitsPriv, pBlob->pGroup->cbPrimeP );
        }
    }

    if (((flags & SYMCRYPT_FLAG_KEY_NO_FIPS) != 0) && (randByte & 0x8))
    {
        flags |= SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION;
    }

    if (!setPrivate)
    {
        pbPubKey = &pBlob->abPubKey[0];
        cbPubKey = pBlob->pGroup->cbPrimeP;
    }

    scError = ScShimSymCryptDlkeySetValue(
                                pbPrivKey, cbPrivKey,
                                pbPubKey, cbPubKey,
                                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                flags, // Do as much verification that the key is correct as possible
                                pRes );

    CHECK( scError == SYMCRYPT_NO_ERROR, "Error importing key" );

    return pRes;
}

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgDh>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SYMCRYPT_ERROR scError;

    UNREFERENCED_PARAMETER( buf3 );

    DlgroupSetup<ImpXxx>( buf1, keySize, TRUE );

    // Set up two keys in buf2
    PDLGROUP_INFO pInfo = (PDLGROUP_INFO) buf1;
    PSYMCRYPT_DLGROUP pGroup = pInfo->pGroup;

    PSYMCRYPT_DLKEY pKey1 = ScShimSymCryptDlkeyCreate( buf2 + 64, PERF_BUFFER_SIZE/4, pGroup );
    PSYMCRYPT_DLKEY pKey2 = ScShimSymCryptDlkeyCreate( buf2 + 64 + PERF_BUFFER_SIZE/4, PERF_BUFFER_SIZE/4, pGroup );

    UINT32 generateFlags = SYMCRYPT_FLAG_DLKEY_DH | (pInfo->pBlob->isSafePrimeGroup ? 0 : SYMCRYPT_FLAG_KEY_NO_FIPS);

    CHECK( pKey1 != NULL && pKey2 != NULL, "Failed to create keys" );

    scError = ScShimSymCryptDlkeyGenerate( generateFlags, pKey1 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    scError = ScShimSymCryptDlkeyGenerate( generateFlags, pKey2 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    ((PSYMCRYPT_DLKEY *) buf2)[0] = pKey1;
    ((PSYMCRYPT_DLKEY *) buf2)[1] = pKey2;
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgDh>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}


template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgDh>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_ERROR scError;

    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( dataSize );

    PDLGROUP_INFO pInfo = (PDLGROUP_INFO) buf1;
    PSYMCRYPT_DLGROUP pGroup = pInfo->pGroup;

    UINT32 generateFlags = SYMCRYPT_FLAG_DLKEY_DH | (pInfo->pBlob->isSafePrimeGroup ? 0 : SYMCRYPT_FLAG_KEY_NO_FIPS);

    PSYMCRYPT_DLKEY pKey = ScShimSymCryptDlkeyCreate( buf3, (1 << 16), pGroup );
    CHECK( pKey != NULL, "?" );

    scError = ScShimSymCryptDlkeyGenerate( generateFlags, pKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    scError = ScShimSymCryptDlkeyGetValue( pKey, nullptr, 0, buf3 + (1 << 16), pInfo->pBlob->cbPrimeP, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
}

template<>
VOID
algImpDecryptPerfFunction< ImpXxx, AlgDh>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf1 );

    ScShimSymCryptDhSecretAgreement(
                ((PSYMCRYPT_DLKEY *) buf2)[0],
                ((PSYMCRYPT_DLKEY *) buf2)[1],
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0,
                buf3,
                dataSize );     // This will be the same as the key size
}

template<>
DhImp<ImpXxx, AlgDh>::DhImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgDh>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction< ImpXxx, AlgDh>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgDh>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgDh>;

    state.pGroup = NULL;
    state.pKey = NULL;
}

template<>
DhImp<ImpXxx, AlgDh>::~DhImp()
{
    if( state.pKey != NULL )
    {
        ScShimSymCryptDlkeyFree( state.pKey );
        state.pKey = NULL;
    }
    if( state.pGroup != NULL )
    {
        ScShimSymCryptDlgroupFree( state.pGroup );
        state.pGroup = NULL;
    }
}

template<>
NTSTATUS
DhImp<ImpXxx, AlgDh>::setKey( _In_    PCDLKEY_TESTBLOB    pcKeyBlob )
{
    if( state.pKey != NULL )
    {
        ScShimSymCryptDlkeyFree( state.pKey );
        state.pKey = NULL;
    }
    if( state.pGroup != NULL )
    {
        ScShimSymCryptDlgroupFree( state.pGroup );
        state.pGroup = NULL;
    }

    if( pcKeyBlob != NULL )
    {
        state.pGroup = dlgroupObjectFromTestBlob<ImpXxx>( pcKeyBlob->pGroup );
        state.pKey = dlkeyObjectFromTestBlob<ImpXxx>( state.pGroup, pcKeyBlob, SYMCRYPT_FLAG_DLKEY_DH );

        CHECK( state.pGroup != NULL && state.pKey != NULL, "?" );
    }

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
DhImp<ImpXxx, AlgDh>::sharedSecret(
        _In_                        PCDLKEY_TESTBLOB    pcPubkey,
        _Out_writes_( cbSecret )    PBYTE               pbSecret,
                                    SIZE_T              cbSecret )
{
    PSYMCRYPT_DLKEY pKey2;
    SYMCRYPT_ERROR scError;

    pKey2 = dlkeyObjectFromTestBlob<ImpXxx>( state.pGroup, pcPubkey, SYMCRYPT_FLAG_DLKEY_DH, /*setPrivate=*/ FALSE );
    CHECK( pKey2 != NULL, "?")

        scError = ScShimSymCryptDhSecretAgreement(
                                    state.pKey,
                                    pKey2,
                                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                    0,
                                    pbSecret, cbSecret );

    ScShimSymCryptDlkeyFree( pKey2 );

    return scError == SYMCRYPT_NO_ERROR ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}


template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgDsa>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SYMCRYPT_ERROR scError;

    UNREFERENCED_PARAMETER( buf3 );

    DlgroupSetup<ImpXxx>( buf1, keySize, FALSE );  // Set buf1 to contain a DL group of size keySize

    // Set up a key in buf2
    PSYMCRYPT_DLGROUP pGroup = ((PDLGROUP_INFO) buf1)->pGroup;

    PSYMCRYPT_DLKEY pKey = ScShimSymCryptDlkeyCreate( buf2 + 64, PERF_BUFFER_SIZE/4, pGroup );

    CHECK( pKey != NULL, "Failed to create key" );

    scError = ScShimSymCryptDlkeyGenerate( SYMCRYPT_FLAG_DLKEY_DSA, pKey );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    ((PSYMCRYPT_DLKEY *) buf2)[0] = pKey;
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgDsa>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}


template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgDsa>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_ERROR scError;

    UNREFERENCED_PARAMETER( dataSize );

    PSYMCRYPT_DLKEY pKey = *(PSYMCRYPT_DLKEY *) buf2;
    PDLGROUP_INFO pInfo = (PDLGROUP_INFO) buf1;

    scError = ScShimSymCryptDsaSign(
                                pKey,
                                buf3, 32,
                                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                0,
                                buf3 + 64, 2 * pInfo->pBlob->cbPrimeQ );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
}

template<>
VOID
algImpDecryptPerfFunction< ImpXxx, AlgDsa>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    SYMCRYPT_ERROR scError;

    UNREFERENCED_PARAMETER( dataSize );

    PSYMCRYPT_DLKEY pKey = *(PSYMCRYPT_DLKEY *) buf2;
    PDLGROUP_INFO pInfo = (PDLGROUP_INFO) buf1;

    scError = ScShimSymCryptDsaVerify(
                                pKey,
                                buf3, 32,
                                buf3 + 64, 2 * pInfo->pBlob->cbPrimeQ,
                                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                0 );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
}

template<>
DsaImp<ImpXxx, AlgDsa>::DsaImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgDsa>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction< ImpXxx, AlgDsa>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgDsa>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgDsa>;

    state.pGroup = NULL;
    state.pKey = NULL;
}

template<>
DsaImp<ImpXxx, AlgDsa>::~DsaImp()
{
    if( state.pKey != NULL )
    {
        ScShimSymCryptDlkeyFree( state.pKey );
        state.pKey = NULL;
    }
    if( state.pGroup != NULL )
    {
        ScShimSymCryptDlgroupFree( state.pGroup );
        state.pGroup = NULL;
    }
}

template<>
NTSTATUS
DsaImp<ImpXxx, AlgDsa>::setKey( _In_    PCDLKEY_TESTBLOB    pcKeyBlob )
{
    if( state.pKey != NULL )
    {
        ScShimSymCryptDlkeyFree( state.pKey );
        state.pKey = NULL;
    }
    if( state.pGroup != NULL )
    {
        ScShimSymCryptDlgroupFree( state.pGroup );
        state.pGroup = NULL;
    }

    if( pcKeyBlob != NULL )
    {
        state.pGroup = dlgroupObjectFromTestBlob<ImpXxx>( pcKeyBlob->pGroup );
        state.pKey = dlkeyObjectFromTestBlob<ImpXxx>( state.pGroup, pcKeyBlob, SYMCRYPT_FLAG_DLKEY_DSA );

        CHECK( state.pGroup != NULL && state.pKey != NULL, "?" );
    }

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
DsaImp<ImpXxx, AlgDsa>::sign(
        _In_reads_( cbHash)     PCBYTE  pbHash,
                                SIZE_T  cbHash,             // Can be any size, but often = size of Q
        _Out_writes_( cbSig )   PBYTE   pbSig,
                                SIZE_T  cbSig )
{
    SYMCRYPT_ERROR scError;

    scError = ScShimSymCryptDsaSign(
                                state.pKey,
                                pbHash, cbHash,
                                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                0,
                                pbSig, cbSig );

    return scError == SYMCRYPT_NO_ERROR ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

template<>
NTSTATUS
DsaImp<ImpXxx, AlgDsa>::verify(
    _In_reads_( cbHash)     PCBYTE  pbHash,
                            SIZE_T  cbHash,
    _In_reads_( cbSig )     PCBYTE  pbSig,
                            SIZE_T  cbSig )
{
    SYMCRYPT_ERROR scError;

    scError = ScShimSymCryptDsaVerify(
                                state.pKey,
                                pbHash, cbHash,
                                pbSig, cbSig,
                                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                0 );

    return scError == SYMCRYPT_NO_ERROR ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}



template<>
DlImp<ImpXxx, AlgDh>::DlImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgDh>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgDh>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgDh>;
}

template<>
DlImp<ImpXxx, AlgDh>::~DlImp()
{
}

//============================
// Global table with the curve pointers (same size as the g_exKeyToCurve)
//
// These curves are allocated on demand as they are needed in tests and all deallocated by a single
// call to CleanupSymCryptCurves performed in the destructor for AlgEcpointSetZero (which is called
// once at the end of the unit tests). A more robust solution for freeing the curves with reference
// counts in each algorithm using the global curves and a critical sections to avoid double freeing
// at program end could be done, but just doing the simplest thing to avoid memory leaks in the unit
// tests for now.
PCSYMCRYPT_ECURVE   CONCAT2(g_pCurves, ImpXxx)[ARRAY_SIZE(g_exKeyToCurve)] = { 0 };

template<>
void
CleanupSymCryptCurves<ImpXxx>()
{
    int i = 0;
    for( i=0; i < ARRAY_SIZE(g_exKeyToCurve); i++ )
    {
        if (CONCAT2(g_pCurves, ImpXxx)[i] != NULL)
        {
            ScShimSymCryptEcurveFree( (PSYMCRYPT_ECURVE) CONCAT2(g_pCurves, ImpXxx)[i] );
            CONCAT2(g_pCurves, ImpXxx)[i] = NULL;
        }
    }
}

template<>
void
SetupSymCryptCurves<ImpXxx>( PBYTE buf1, SIZE_T keySize )
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

    if (CONCAT2(g_pCurves, ImpXxx)[i] == NULL)
    {
        pCurve = ScShimSymCryptEcurveAllocate( g_exKeyToCurve[i].pParams, 0 );

        CONCAT2(g_pCurves, ImpXxx)[i] = pCurve;
    }
    else
    {
        pCurve = CONCAT2(g_pCurves, ImpXxx)[i];
    }

    CHECK( pCurve != NULL, "?");

    *((PCSYMCRYPT_ECURVE *) buf1) = pCurve;
}

template<>
void
SetupSymCryptEckey<ImpXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, UINT32 setRandomFlags )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    PCSYMCRYPT_ECURVE pCurve = *((PCSYMCRYPT_ECURVE *)buf1);

    UINT32 eckeySize = ScShimSymCryptSizeofEckeyFromCurve( pCurve );
    UINT32 signatureSize = 2 * ScShimSymCryptEcurveSizeofFieldElement( pCurve );

    PSYMCRYPT_ECKEY * pPtrs = ((PSYMCRYPT_ECKEY *) buf2);
    pPtrs[0] = ScShimSymCryptEckeyCreate( buf2 + 32, eckeySize, pCurve );

    scError = ScShimSymCryptEckeySetRandom( setRandomFlags, pPtrs[0] );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    pPtrs[1] = (PSYMCRYPT_ECKEY) ((PBYTE)buf2 + 32 + eckeySize);    // This will hold the hash of the message

    CHECK( 32 + eckeySize + SYMCRYPT_SHA512_RESULT_SIZE <= SCRATCH_BUF_SIZE, "ECKEY and hash cannot fit into scratch buffer" );
    GENRANDOM( (PBYTE)pPtrs[1], SYMCRYPT_SHA512_RESULT_SIZE );

    PUINT32 puiSignatureSize = (PUINT32) buf3;

    CHECK( sizeof(UINT32) + signatureSize <= SCRATCH_BUF_SIZE, "Destination buffer cannot fit the signature" );

    *puiSignatureSize = signatureSize;

    // Verify that ECDH can work
    if ( setRandomFlags & SYMCRYPT_FLAG_ECKEY_ECDH )
    {
        UINT32 cbAgreedSecret = ScShimSymCryptEcurveSizeofFieldElement( *(PSYMCRYPT_ECURVE *) buf1 );
        CHECK( cbAgreedSecret <= *((PUINT32)buf3), "Buffer 3 too small for ECDH");
        scError = ScShimSymCryptEcDhSecretAgreement(
                    ((PSYMCRYPT_ECKEY *) buf2)[0],
                    ((PSYMCRYPT_ECKEY *) buf2)[0],      // Same private and public key
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0,
                    buf3 + sizeof(UINT32),
                    cbAgreedSecret);
        CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptEcDhSecretAgreement failed" );
    }

    // Verify that ECDSA can work
    if ( (setRandomFlags & SYMCRYPT_FLAG_ECKEY_ECDSA) != 0 )
    {
        scError = ScShimSymCryptEcDsaSign(
                        pPtrs[0],
                        (PBYTE) pPtrs[1],
                        SYMCRYPT_SHA512_RESULT_SIZE,
                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                        0,
                        buf3 + sizeof(UINT32),
                        signatureSize );
        CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptEcDsaSign failed" );

        // Verify the signature to make sure everything is ok
        scError = ScShimSymCryptEcDsaVerify(
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
algImpKeyPerfFunction<ImpXxx, AlgEcurveAllocate>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
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
algImpCleanPerfFunction<ImpXxx, AlgEcurveAllocate>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgEcurveAllocate>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( dataSize );

    *((PSYMCRYPT_ECURVE *) buf3) = ScShimSymCryptEcurveAllocate( *((PCSYMCRYPT_ECURVE_PARAMS *) buf1), 0 );
    ScShimSymCryptEcurveFree( *((PSYMCRYPT_ECURVE *) buf3) );
}


template<>
EccImp<ImpXxx, AlgEcurveAllocate>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgEcurveAllocate>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgEcurveAllocate>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgEcurveAllocate>;
}

template<>
EccImp<ImpXxx, AlgEcurveAllocate>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgEcdsaSign>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves<ImpXxx>( buf1, keySize );
    SetupSymCryptEckey<ImpXxx>( buf1, buf2, buf3, SYMCRYPT_FLAG_ECKEY_ECDSA );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgEcdsaSign>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx, AlgEcdsaSign>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( dataSize );

    ScShimSymCryptEcDsaSign(
                    ((PSYMCRYPT_ECKEY *) buf2)[0],
                    ((PBYTE *) buf2)[1],
                    SYMCRYPT_SHA512_RESULT_SIZE,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0,
                    buf3 + sizeof(UINT32),
                    *((PUINT32)buf3) );
}


template<>
EccImp<ImpXxx, AlgEcdsaSign>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgEcdsaSign>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgEcdsaSign>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgEcdsaSign>;
}

template<>
EccImp<ImpXxx, AlgEcdsaSign>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgEcdsaVerify>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves<ImpXxx>( buf1, keySize );
    SetupSymCryptEckey<ImpXxx>( buf1, buf2, buf3, SYMCRYPT_FLAG_ECKEY_ECDSA );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgEcdsaVerify>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx, AlgEcdsaVerify>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( dataSize );

    ScShimSymCryptEcDsaVerify(
                    ((PSYMCRYPT_ECKEY *) buf2)[0],
                    ((PBYTE *) buf2)[1],
                    SYMCRYPT_SHA512_RESULT_SIZE,
                    buf3 + sizeof(UINT32),
                    *((PUINT32)buf3),
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    0 );
}


template<>
EccImp<ImpXxx, AlgEcdsaVerify>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgEcdsaVerify>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgEcdsaVerify>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgEcdsaVerify>;
}

template<>
EccImp<ImpXxx, AlgEcdsaVerify>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgEcdh>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves<ImpXxx>( buf1, keySize );
    SetupSymCryptEckey<ImpXxx>( buf1, buf2, buf3, SYMCRYPT_FLAG_ECKEY_ECDH );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgEcdh>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx, AlgEcdh>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    UINT32 cbAgreedSecret = ScShimSymCryptEcurveSizeofFieldElement( *(PSYMCRYPT_ECURVE*)buf1);

    ScShimSymCryptEcDhSecretAgreement(
                ((PSYMCRYPT_ECKEY *) buf2)[0],
                ((PSYMCRYPT_ECKEY *) buf2)[0],      // Same private and public key
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0,
                buf3 + sizeof(UINT32),
                cbAgreedSecret );
}


template<>
EccImp<ImpXxx, AlgEcdh>::EccImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgEcdh>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgEcdh>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgEcdh>;
}

template<>
EccImp<ImpXxx, AlgEcdh>::~EccImp()
{
}

//============================
#if SYMCRYPT_MS_VC
template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgIEEE802_11SaeCustom>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    ScShimSymCrypt802_11SaeCustomInit(
        (PSYMCRYPT_802_11_SAE_CUSTOM_STATE) buf1, &buf2[0], &buf2[6], &buf2[12], keySize, nullptr, nullptr, nullptr );

    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgIEEE802_11SaeCustom>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    ScShimSymCrypt802_11SaeCustomDestroy(
        (PSYMCRYPT_802_11_SAE_CUSTOM_STATE) buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgIEEE802_11SaeCustom>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ScShimSymCrypt802_11SaeCustomCommitCreate(
        (PSYMCRYPT_802_11_SAE_CUSTOM_STATE) buf1, buf2, buf3 );

    UNREFERENCED_PARAMETER( dataSize );
}

template<>
VOID
algImpDecryptPerfFunction<ImpXxx,AlgIEEE802_11SaeCustom>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    ScShimSymCrypt802_11SaeCustomCommitProcess(
        (PSYMCRYPT_802_11_SAE_CUSTOM_STATE) buf1, buf2, buf3, &buf3[1024], &buf3[2048] );

    UNREFERENCED_PARAMETER( dataSize );
}

template<>
ArithImp<ImpXxx, AlgIEEE802_11SaeCustom>::ArithImp()
{
    if( !SCTEST_LOOKUP_SCIMPSYM(SymCrypt802_11SaeCustomInit) )
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgIEEE802_11SaeCustom>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpXxx, AlgIEEE802_11SaeCustom>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgIEEE802_11SaeCustom>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgIEEE802_11SaeCustom>;
}

template<>
ArithImp<ImpXxx, AlgIEEE802_11SaeCustom>::~ArithImp()
{
}
#endif


/////////////////////////
// Big integer
//


template<>
VOID
setupPerfInt<ImpXxx>( PBYTE pb, SIZE_T cb, UINT32 nDigits )
{
    *(PSYMCRYPT_INT*)pb = ScShimSymCryptIntCreate(
        pb + SYMCRYPT_ASYM_ALIGN_VALUE, cb - SYMCRYPT_ASYM_ALIGN_VALUE, nDigits);
}

template<>
VOID
setupIntsForPerfFunction<ImpXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T inSize, UINT32 outFactor )
{
    BYTE buf[2048];

    CHECK( 2*inSize <= sizeof( buf ), "?" );
    GENRANDOM( buf, (UINT32)(2*inSize) );

    UINT32 nDigitsIn = ScShimSymCryptDigitsFromBits( (UINT32) (8 * inSize) );
    UINT32 nDigitsOut = outFactor * nDigitsIn;

    setupPerfInt<ImpXxx>( buf1, SCRATCH_BUF_OFFSET, nDigitsIn );
    setupPerfInt<ImpXxx>( buf2, SCRATCH_BUF_OFFSET, nDigitsIn );
    setupPerfInt<ImpXxx>( buf3, SCRATCH_BUF_OFFSET, nDigitsOut );

    ScShimSymCryptIntSetValue( buf, (UINT32) inSize, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, *(PSYMCRYPT_INT *) buf1 );
    ScShimSymCryptIntSetValue( buf+inSize, (UINT32) inSize, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, *(PSYMCRYPT_INT *) buf2 );
}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgIntAdd>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    setupIntsForPerfFunction<ImpXxx>( buf1, buf2, buf3, keySize, 1 );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgIntAdd>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgIntAdd>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    ScShimSymCryptIntAddSameSize( *(PSYMCRYPT_INT *) buf1, *(PSYMCRYPT_INT *) buf2, *(PSYMCRYPT_INT *) buf3 );
}


template<>
ArithImp<ImpXxx, AlgIntAdd>::ArithImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptIntAddSameSize))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgIntAdd>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgIntAdd>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgIntAdd>;
}

template<>
ArithImp<ImpXxx, AlgIntAdd>::~ArithImp()
{
}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgIntSub>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    setupIntsForPerfFunction<ImpXxx>( buf1, buf2, buf3, keySize, 1 );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgIntSub>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgIntSub>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    ScShimSymCryptIntSubSameSize( *(PSYMCRYPT_INT *) buf1, *(PSYMCRYPT_INT *) buf2, *(PSYMCRYPT_INT *) buf3 );
}


template<>
ArithImp<ImpXxx, AlgIntSub>::ArithImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptIntSubSameSize))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgIntSub>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgIntSub>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgIntSub>;
}

template<>
ArithImp<ImpXxx, AlgIntSub>::~ArithImp()
{
}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgIntMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    setupIntsForPerfFunction<ImpXxx>( buf1, buf2, buf3, keySize, 2 );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgIntMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgIntMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    ScShimSymCryptIntMulSameSize( *(PSYMCRYPT_INT *) buf1, *(PSYMCRYPT_INT *) buf2, *(PSYMCRYPT_INT *) buf3, buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );
}


template<>
ArithImp<ImpXxx, AlgIntMul>::ArithImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptIntMulSameSize))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgIntMul>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgIntMul>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgIntMul>;
}

template<>
ArithImp<ImpXxx, AlgIntMul>::~ArithImp()
{
}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgIntSquare>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    setupIntsForPerfFunction<ImpXxx>( buf1, buf2, buf3, keySize, 2 );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgIntSquare>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgIntSquare>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    UNREFERENCED_PARAMETER( buf2 );
    ScShimSymCryptIntSquare( *(PSYMCRYPT_INT *) buf1, *(PSYMCRYPT_INT *) buf3, buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );
}


template<>
ArithImp<ImpXxx, AlgIntSquare>::ArithImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptIntSquare))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgIntSquare>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgIntSquare>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgIntSquare>;
}

template<>
ArithImp<ImpXxx, AlgIntSquare>::~ArithImp()
{
}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgIntDivMod>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    BYTE buf[4096];
    PSYMCRYPT_INT piDiv;

    CHECK3( 3*keySize <= sizeof( buf ), "keySize too big %08x", keySize );
    GENRANDOM( buf, (UINT32)(3*keySize) );

    UINT32 nDigits = ScShimSymCryptDigitsFromBits( (UINT32) (8 * keySize) );
    UINT32 numSize = ScShimSymCryptSizeofIntFromDigits( 2*nDigits );

    *(PSYMCRYPT_DIVISOR *) buf2 = ScShimSymCryptDivisorCreate( buf2 + SYMCRYPT_ASYM_ALIGN_VALUE, PERF_BUFFER_SIZE-SYMCRYPT_ASYM_ALIGN_VALUE, nDigits );
    ((PSYMCRYPT_INT *) buf1)[0] = ScShimSymCryptIntCreate( buf1 + SYMCRYPT_ASYM_ALIGN_VALUE, numSize, nDigits * 2 );

    buf[0] |= 0x80;     // Make sure highest bit in divisor is set (using MSByte first for simplicity)
    piDiv = ScShimSymCryptIntFromDivisor( *(PSYMCRYPT_DIVISOR*)buf2 );
    ScShimSymCryptIntSetValue( buf, (UINT32)keySize, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piDiv );
    ScShimSymCryptIntToDivisor( piDiv, *(PSYMCRYPT_DIVISOR *)buf2, 1000, 0, buf3, PERF_BUFFER_SIZE );

    ScShimSymCryptIntSetValue( buf+keySize, (UINT32) 2*keySize, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, *(PSYMCRYPT_INT *) buf1 );

    ((PSYMCRYPT_INT *) buf3)[0] = ScShimSymCryptIntCreate( buf3 + SYMCRYPT_ASYM_ALIGN_VALUE, numSize, nDigits * 2 );
    ((PSYMCRYPT_INT *) buf3)[1] = ScShimSymCryptIntCreate( buf3 + SYMCRYPT_ASYM_ALIGN_VALUE + numSize, numSize, nDigits );
    CHECK( 2*numSize + SYMCRYPT_ASYM_ALIGN_VALUE <= SCRATCH_BUF_OFFSET, "DivMod destinations overlap scratch buffer" );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgIntDivMod>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgIntDivMod>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    UNREFERENCED_PARAMETER( buf2 );
    ScShimSymCryptIntDivMod( *(PSYMCRYPT_INT*)buf1, *(PSYMCRYPT_DIVISOR*)buf2, ((PSYMCRYPT_INT*)buf3)[0], ((PSYMCRYPT_INT*)buf3)[1], buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );
}


template<>
ArithImp<ImpXxx, AlgIntDivMod>::ArithImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptIntDivMod))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgIntDivMod>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgIntDivMod>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgIntDivMod>;
}

template<>
ArithImp<ImpXxx, AlgIntDivMod>::~ArithImp()
{
}

//
// SetupModulus
// Initializes a modulus of the desired keysize & features
//
// *((PSYMCRYPT_MODULUS *) buf1) will contain a pointer to the modulus, which is also in buf1.
// buf3 is used as scratch
//
template<>
VOID
setupModulus<ImpXxx>( PBYTE buf1, PBYTE buf3, SIZE_T keySize )
{
    UINT32 keyBytes = (UINT32) keySize & 0x00ffffff;
    UINT32 keyFlags = (UINT32) keySize & 0xff000000;

    UINT32 nDigits = ScShimSymCryptDigitsFromBits( 8 * keyBytes );
    PSYMCRYPT_INT piMod;

    PSYMCRYPT_MODULUS pmMod = ScShimSymCryptModulusCreate( buf1 + SYMCRYPT_ASYM_ALIGN_VALUE, PERF_BUFFER_SIZE - SYMCRYPT_ASYM_ALIGN_VALUE, nDigits );

    piMod = ScShimSymCryptIntFromModulus( pmMod );
    ScShimSymCryptIntSetValue(
                        getPerfTestModulus((UINT32)keySize),
                        ((UINT32)keySize) & 0x00ffffff,
                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                        piMod );

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

    ScShimSymCryptIntToModulus( piMod, pmMod, 10000, flags, buf3, PERF_BUFFER_SIZE );

    *((PSYMCRYPT_MODULUS *) buf1) = pmMod;
}

//
// setupModOperations
// Initializes a modulus in buf1, two modElements in buf2, and one modElement in buf3.
// The modElements in buf2 are set to random values
//
template<>
void
setupModOperations<ImpXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    BYTE buf[4096];
    SYMCRYPT_ERROR scError;

    UINT32 keyBytes = (UINT32) keySize & 0x00ffffff;
    CHECK( 2 * keyBytes <= sizeof( buf ), "?" );
    GENRANDOM( buf, (2*keyBytes) );

    setupModulus<ImpXxx>( buf1, buf3, keySize );
    PCSYMCRYPT_MODULUS pmMod = *((PCSYMCRYPT_MODULUS *)buf1);

    UINT32 modElSize = ScShimSymCryptSizeofModElementFromModulus( pmMod );
    PSYMCRYPT_MODELEMENT * pPtrs = ((PSYMCRYPT_MODELEMENT *) buf2);
    pPtrs[0] = ScShimSymCryptModElementCreate( buf2 + SYMCRYPT_ASYM_ALIGN_VALUE, modElSize, pmMod );
    pPtrs[1] = ScShimSymCryptModElementCreate( buf2 + SYMCRYPT_ASYM_ALIGN_VALUE + modElSize, modElSize, pmMod );

    ((PSYMCRYPT_MODELEMENT *) buf3)[0] = ScShimSymCryptModElementCreate( buf3 + SYMCRYPT_ASYM_ALIGN_VALUE, modElSize, pmMod );

    CHECK( modElSize + SYMCRYPT_ASYM_ALIGN_VALUE <= SCRATCH_BUF_OFFSET, "ModElement overlaps with scratch buffer" );

    scError = ScShimSymCryptModElementSetValue( buf, modElSize, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, pmMod, pPtrs[0], buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    scError = ScShimSymCryptModElementSetValue( buf+modElSize, modElSize, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, pmMod, pPtrs[1], buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgModAdd>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    setupModOperations<ImpXxx>( buf1, buf2, buf3, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgModAdd>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgModAdd>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    ScShimSymCryptModAdd( *(PSYMCRYPT_MODULUS *) buf1, ((PSYMCRYPT_MODELEMENT *) buf2)[0], ((PSYMCRYPT_MODELEMENT *) buf2)[1], ((PSYMCRYPT_MODELEMENT *) buf3)[0],  buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );
}


template<>
ArithImp<ImpXxx, AlgModAdd>::ArithImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptModAdd))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgModAdd>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgModAdd>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgModAdd>;
}

template<>
ArithImp<ImpXxx, AlgModAdd>::~ArithImp()
{
}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgModSub>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    setupModOperations<ImpXxx>( buf1, buf2, buf3, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgModSub>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgModSub>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    ScShimSymCryptModSub( *(PSYMCRYPT_MODULUS *) buf1, ((PSYMCRYPT_MODELEMENT *) buf2)[0], ((PSYMCRYPT_MODELEMENT *) buf2)[1], ((PSYMCRYPT_MODELEMENT *) buf3)[0],  buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );
}


template<>
ArithImp<ImpXxx, AlgModSub>::ArithImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptModSub))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgModSub>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgModSub>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgModSub>;
}

template<>
ArithImp<ImpXxx, AlgModSub>::~ArithImp()
{
}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgModMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    setupModOperations<ImpXxx>( buf1, buf2, buf3, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgModMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgModMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    ScShimSymCryptModMul( *(PSYMCRYPT_MODULUS *) buf1, ((PSYMCRYPT_MODELEMENT *) buf2)[0], ((PSYMCRYPT_MODELEMENT *) buf2)[1], ((PSYMCRYPT_MODELEMENT *) buf3)[0],  buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );
}


template<>
ArithImp<ImpXxx, AlgModMul>::ArithImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptModMul))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgModMul>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgModMul>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgModMul>;
}

template<>
ArithImp<ImpXxx, AlgModMul>::~ArithImp()
{
}



template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgModExp>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    BYTE buf[4096];
    UINT32 keyBytes = (UINT32) keySize & 0x00ffffff;
    UINT32 nDigits = 0;

    setupModOperations<ImpXxx>( buf1, buf2, buf3, keySize );

    CHECK( keyBytes <= sizeof( buf ), "?" );
    GENRANDOM( buf, keyBytes );

    nDigits = ScShimSymCryptDigitsFromBits( 8 * keyBytes);

    ((PSYMCRYPT_INT *) buf2)[1] = ScShimSymCryptIntCreate(
        (PBYTE)(((PSYMCRYPT_INT *) buf2)[1]) + SYMCRYPT_ASYM_ALIGN_VALUE, SCRATCH_BUF_OFFSET - SYMCRYPT_ASYM_ALIGN_VALUE, nDigits );

    ScShimSymCryptIntSetValue( buf, keyBytes, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, ((PSYMCRYPT_INT *) buf2)[1] );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgModExp>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx, AlgModExp>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    PSYMCRYPT_INT piMod = ScShimSymCryptIntFromModulus( *(PSYMCRYPT_MODULUS *) buf1 );
    UINT32 nBitsExp = ScShimSymCryptIntBitsizeOfValue( piMod );

    ScShimSymCryptModExp(
                *(PSYMCRYPT_MODULUS *) buf1,
                ((PSYMCRYPT_MODELEMENT *) buf2)[0],
                ((PSYMCRYPT_INT *) buf2)[1],
                nBitsExp,
                0,      // Default flags: Side-channel safe
                ((PSYMCRYPT_MODELEMENT *) buf3)[0],
                buf3 + SCRATCH_BUF_OFFSET,
                SCRATCH_BUF_SIZE );
}


template<>
ArithImp<ImpXxx, AlgModExp>::ArithImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptModExp))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgModExp>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgModExp>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgModExp>;
}

template<>
ArithImp<ImpXxx, AlgModExp>::~ArithImp()
{
}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgModSquare>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    setupModOperations<ImpXxx>( buf1, buf2, buf3, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgModSquare>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgModSquare>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    ScShimSymCryptModSquare( *(PSYMCRYPT_MODULUS *) buf1, ((PSYMCRYPT_MODELEMENT *) buf2)[0], ((PSYMCRYPT_MODELEMENT *) buf3)[0],  buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );
}


template<>
ArithImp<ImpXxx, AlgModSquare>::ArithImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptModSquare))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgModSquare>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgModSquare>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgModSquare>;
}

template<>
ArithImp<ImpXxx, AlgModSquare>::~ArithImp()
{
}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgModInv>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    setupModOperations<ImpXxx>( buf1, buf2, buf3, keySize );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgModInv>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgModInv>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    SYMCRYPT_ERROR scError;
    scError = ScShimSymCryptModInv(
                                *(PSYMCRYPT_MODULUS *) buf1,
                                ((PSYMCRYPT_MODELEMENT *) buf2)[0],
                                ((PSYMCRYPT_MODELEMENT *) buf3)[0],
                                0,
                                buf3 + SCRATCH_BUF_OFFSET,
                                SCRATCH_BUF_SIZE );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Error in perf test case" );
}


template<>
ArithImp<ImpXxx, AlgModInv>::ArithImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptModInv))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgModInv>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgModInv>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgModInv>;
}

template<>
ArithImp<ImpXxx, AlgModInv>::~ArithImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgTrialDivision>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
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

    UINT32 numDigits = ScShimSymCryptDigitsFromBits( (UINT32)keySize * 8 );

    PSYMCRYPT_INT piSrc = ScShimSymCryptIntCreate( buf3 + 64, PERF_BUFFER_SIZE - 64, numDigits );

    PBYTE p = buf3 + PERF_BUFFER_SIZE/2;
    GENRANDOM( p, (ULONG) keySize );
    p[0] |= 1;   // Make sure it is odd so we don't get zeroes...
    ScShimSymCryptIntSetValue( p, keySize, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, piSrc );

    *(PSYMCRYPT_INT *) buf3 = piSrc;
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgTrialDivision>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgTrialDivision>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( dataSize );

    PCSYMCRYPT_TRIALDIVISION_CONTEXT pContext = (PCSYMCRYPT_TRIALDIVISION_CONTEXT) buf1;
    PCSYMCRYPT_INT piSrc = *(PCSYMCRYPT_INT *) buf3;

    *(PUINT32) (buf3 + PERF_BUFFER_SIZE/2) = ScShimSymCryptIntFindSmallDivisor( pContext, piSrc, nullptr, 0 );
}

template<>
VOID
algImpDecryptPerfFunction< ImpXxx, AlgTrialDivision>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( dataSize );

    PCSYMCRYPT_TRIALDIVISION_CONTEXT pContext = (PCSYMCRYPT_TRIALDIVISION_CONTEXT) buf2;
    PCSYMCRYPT_INT piSrc = *(PCSYMCRYPT_INT *) buf3;

    *(PUINT32) (buf3 + PERF_BUFFER_SIZE/2) = ScShimSymCryptIntFindSmallDivisor( pContext, piSrc, nullptr, 0 );
}


template<>
ArithImp<ImpXxx, AlgTrialDivision>::ArithImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptIntFindSmallDivisor))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgTrialDivision>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction  <ImpXxx, AlgTrialDivision>;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgTrialDivision>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgTrialDivision>;
}

template<>
ArithImp<ImpXxx, AlgTrialDivision>::~ArithImp()
{
}

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgTrialDivisionContext>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    *(UINT32 *) buf2 = (UINT32) keySize;
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgTrialDivisionContext>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    *(PCSYMCRYPT_TRIALDIVISION_CONTEXT *) buf1 = NULL;
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgTrialDivisionContext>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( dataSize );

    PCSYMCRYPT_TRIALDIVISION_CONTEXT context;

    UINT32 numDigits = ScShimSymCryptDigitsFromBits( 8 * *(UINT32 *) buf2 );
    context = ScShimSymCryptCreateTrialDivisionContext( numDigits );

    // Save a copy of the pointer to stop the compiler from optimizing the whole thing away.
    *(PCSYMCRYPT_TRIALDIVISION_CONTEXT *) buf1 = context;

    ScShimSymCryptFreeTrialDivisionContext( context );
}


template<>
ArithImp<ImpXxx, AlgTrialDivisionContext>::ArithImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptCreateTrialDivisionContext))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgTrialDivisionContext>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgTrialDivisionContext>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgTrialDivisionContext>;
}

template<>
ArithImp<ImpXxx, AlgTrialDivisionContext>::~ArithImp()
{
}



template<>
void
SetupSymCryptEcpoints<ImpXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    PSYMCRYPT_INT piScalar;

    PCSYMCRYPT_ECURVE pCurve = *((PCSYMCRYPT_ECURVE *)buf1);

    UINT32 ecpointSize = ScShimSymCryptSizeofEcpointFromCurve( pCurve );
    UINT32 numDigits = ScShimSymCryptEcurveDigitsofScalarMultiplier( pCurve );
    UINT32 scalarSize = ScShimSymCryptSizeofIntFromDigits( numDigits );

    PSYMCRYPT_ECPOINT * pPtrs = ((PSYMCRYPT_ECPOINT *) buf2);
    pPtrs[0] = ScShimSymCryptEcpointCreate( buf2 + 32, ecpointSize, pCurve );
    pPtrs[1] = ScShimSymCryptEcpointCreate( buf2 + 32 + ecpointSize, ecpointSize, pCurve );

    piScalar = ScShimSymCryptIntCreate( buf2 + 32 + 2*ecpointSize, scalarSize, numDigits );
    pPtrs[2] = (PSYMCRYPT_ECPOINT) piScalar;

    ((PSYMCRYPT_ECPOINT *) buf3)[0] = ScShimSymCryptEcpointCreate( buf3 + 32, ecpointSize, pCurve );

    CHECK( ecpointSize + 32 <= SCRATCH_BUF_OFFSET, "Destination ECPOINT overlaps with scratch buffer" );

    ScShimSymCryptEcpointSetRandom( pCurve, piScalar, pPtrs[0], buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );

    ScShimSymCryptEcpointSetRandom( pCurve, piScalar, pPtrs[1], buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );

    if( pCurve->type != SYMCRYPT_ECURVE_TYPE_MONTGOMERY )
    {
        ScShimSymCryptEcpointSetZero( pCurve, ((PSYMCRYPT_ECPOINT *) buf3)[0], buf3 + SCRATCH_BUF_OFFSET, SCRATCH_BUF_SIZE );
    }
}


//============================

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgEcpointSetZero>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves<ImpXxx>( buf1, keySize );
    SetupSymCryptEcpoints<ImpXxx>( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgEcpointSetZero>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgEcpointSetZero>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( dataSize );

    ScShimSymCryptEcpointSetZero(
        *(PSYMCRYPT_ECURVE *) buf1,
        ((PSYMCRYPT_ECPOINT *) buf3)[0],
        buf3 + SCRATCH_BUF_OFFSET,
        SCRATCH_BUF_SIZE );
}


template<>
EccImp<ImpXxx, AlgEcpointSetZero>::EccImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptEcpointSetZero))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgEcpointSetZero>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgEcpointSetZero>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgEcpointSetZero>;
}

template<>
EccImp<ImpXxx, AlgEcpointSetZero>::~EccImp()
{
    // We free the global curves in just this destructor (which is called once at the end of the
    // unit tests) to avoid memory leaks. See the comments by g_pCurves declaration above.
    CleanupSymCryptCurves<ImpXxx>();
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgEcpointSetDistinguished>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves<ImpXxx>( buf1, keySize );
    SetupSymCryptEcpoints<ImpXxx>( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgEcpointSetDistinguished>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgEcpointSetDistinguished>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( dataSize );

    ScShimSymCryptEcpointSetDistinguishedPoint(
        *(PSYMCRYPT_ECURVE *) buf1,
        ((PSYMCRYPT_ECPOINT *) buf3)[0],
        buf3 + SCRATCH_BUF_OFFSET,
        SCRATCH_BUF_SIZE );
}


template<>
EccImp<ImpXxx, AlgEcpointSetDistinguished>::EccImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptEcpointSetDistinguishedPoint))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgEcpointSetDistinguished>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgEcpointSetDistinguished>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgEcpointSetDistinguished>;
}

template<>
EccImp<ImpXxx, AlgEcpointSetDistinguished>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgEcpointSetRandom>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves<ImpXxx>( buf1, keySize );
    SetupSymCryptEcpoints<ImpXxx>( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgEcpointSetRandom>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgEcpointSetRandom>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );

    ScShimSymCryptEcpointSetRandom(
                    *(PSYMCRYPT_ECURVE *) buf1,
                    ((PSYMCRYPT_INT *) buf2)[2],
                    ((PSYMCRYPT_ECPOINT *) buf3)[0],
                    buf3 + SCRATCH_BUF_OFFSET,
                    SCRATCH_BUF_SIZE );
}


template<>
EccImp<ImpXxx, AlgEcpointSetRandom>::EccImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptEcpointSetRandom))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgEcpointSetRandom>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgEcpointSetRandom>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgEcpointSetRandom>;
}

template<>
EccImp<ImpXxx, AlgEcpointSetRandom>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgEcpointIsEqual>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves<ImpXxx>( buf1, keySize );
    SetupSymCryptEcpoints<ImpXxx>( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgEcpointIsEqual>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgEcpointIsEqual>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( dataSize );

    ScShimSymCryptEcpointIsEqual(
        *(PSYMCRYPT_ECURVE *) buf1,
        ((PSYMCRYPT_ECPOINT *) buf2)[0],
        ((PSYMCRYPT_ECPOINT *) buf2)[1],
        SYMCRYPT_FLAG_ECPOINT_EQUAL | SYMCRYPT_FLAG_ECPOINT_NEG_EQUAL,
        buf3 + SCRATCH_BUF_OFFSET,
        SCRATCH_BUF_SIZE );
}


template<>
EccImp<ImpXxx, AlgEcpointIsEqual>::EccImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptEcpointIsEqual))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgEcpointIsEqual>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgEcpointIsEqual>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgEcpointIsEqual>;
}

template<>
EccImp<ImpXxx, AlgEcpointIsEqual>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgEcpointIsZero>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves<ImpXxx>( buf1, keySize );
    SetupSymCryptEcpoints<ImpXxx>( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgEcpointIsZero>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgEcpointIsZero>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( dataSize );

    ScShimSymCryptEcpointIsZero(
        *(PSYMCRYPT_ECURVE *) buf1,
        ((PSYMCRYPT_ECPOINT *) buf2)[0],
        buf3 + SCRATCH_BUF_OFFSET,
        SCRATCH_BUF_SIZE );
}


template<>
EccImp<ImpXxx, AlgEcpointIsZero>::EccImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptEcpointIsZero))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgEcpointIsZero>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgEcpointIsZero>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgEcpointIsZero>;
}

template<>
EccImp<ImpXxx, AlgEcpointIsZero>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgEcpointOnCurve>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves<ImpXxx>( buf1, keySize );
    SetupSymCryptEcpoints<ImpXxx>( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgEcpointOnCurve>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgEcpointOnCurve>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( dataSize );

    ScShimSymCryptEcpointOnCurve(
        *(PSYMCRYPT_ECURVE *) buf1,
        ((PSYMCRYPT_ECPOINT *) buf2)[0],
        buf3 + SCRATCH_BUF_OFFSET,
        SCRATCH_BUF_SIZE );
}


template<>
EccImp<ImpXxx, AlgEcpointOnCurve>::EccImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptEcpointOnCurve))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgEcpointOnCurve>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgEcpointOnCurve>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgEcpointOnCurve>;
}

template<>
EccImp<ImpXxx, AlgEcpointOnCurve>::~EccImp()
{
}


//============================

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgEcpointAdd>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves<ImpXxx>( buf1, keySize );
    SetupSymCryptEcpoints<ImpXxx>( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgEcpointAdd>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgEcpointAdd>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );

    ScShimSymCryptEcpointAdd(
        *(PSYMCRYPT_ECURVE *) buf1,
        ((PSYMCRYPT_ECPOINT *) buf2)[0],
        ((PSYMCRYPT_ECPOINT *) buf2)[1],
        ((PSYMCRYPT_ECPOINT *) buf3)[0],
        0,                                  // Side-channel safe version
        buf3 + SCRATCH_BUF_OFFSET,
        SCRATCH_BUF_SIZE );
}


template<>
EccImp<ImpXxx, AlgEcpointAdd>::EccImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptEcpointAdd))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgEcpointAdd>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgEcpointAdd>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgEcpointAdd>;
}

template<>
EccImp<ImpXxx, AlgEcpointAdd>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgEcpointAddDiffNz>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves<ImpXxx>( buf1, keySize );

    do {
        SetupSymCryptEcpoints<ImpXxx>( buf1, buf2, buf3 );
    }
    while (ScShimSymCryptEcpointIsEqual(
                *(PSYMCRYPT_ECURVE *) buf1,
                ((PSYMCRYPT_ECPOINT *) buf2)[0],
                ((PSYMCRYPT_ECPOINT *) buf2)[1],
                SYMCRYPT_FLAG_ECPOINT_EQUAL | SYMCRYPT_FLAG_ECPOINT_NEG_EQUAL,
                buf3 + SCRATCH_BUF_OFFSET,
                SCRATCH_BUF_SIZE ) );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgEcpointAddDiffNz>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgEcpointAddDiffNz>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );

    ScShimSymCryptEcpointAddDiffNonZero(
        *(PSYMCRYPT_ECURVE *) buf1,
        ((PSYMCRYPT_ECPOINT *) buf2)[0],
        ((PSYMCRYPT_ECPOINT *) buf2)[1],
        ((PSYMCRYPT_ECPOINT *) buf3)[0],
        buf3 + SCRATCH_BUF_OFFSET,
        SCRATCH_BUF_SIZE );
}


template<>
EccImp<ImpXxx, AlgEcpointAddDiffNz>::EccImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptEcpointAddDiffNonZero))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgEcpointAddDiffNz>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgEcpointAddDiffNz>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgEcpointAddDiffNz>;
}

template<>
EccImp<ImpXxx, AlgEcpointAddDiffNz>::~EccImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgEcpointDouble>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves<ImpXxx>( buf1, keySize );

    do {
        SetupSymCryptEcpoints<ImpXxx>( buf1, buf2, buf3 );
    }
    while (ScShimSymCryptEcpointIsEqual(
                *(PSYMCRYPT_ECURVE *) buf1,
                ((PSYMCRYPT_ECPOINT *) buf2)[0],
                ((PSYMCRYPT_ECPOINT *) buf3)[0],        // buf3 is set to the zero point in SetupSymCryptEcpoints<ImpXxx>
                SYMCRYPT_FLAG_ECPOINT_EQUAL | SYMCRYPT_FLAG_ECPOINT_NEG_EQUAL,
                buf3 + SCRATCH_BUF_OFFSET,
                SCRATCH_BUF_SIZE ) );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgEcpointDouble>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgEcpointDouble>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );

    ScShimSymCryptEcpointDouble(
        *(PSYMCRYPT_ECURVE *) buf1,
        ((PSYMCRYPT_ECPOINT *) buf2)[0],
        ((PSYMCRYPT_ECPOINT *) buf3)[0],
        0,                                  // Side-channel safe version
        buf3 + SCRATCH_BUF_OFFSET,
        SCRATCH_BUF_SIZE );
}


template<>
EccImp<ImpXxx, AlgEcpointDouble>::EccImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptEcpointDouble))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgEcpointDouble>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgEcpointDouble>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgEcpointDouble>;
}

template<>
EccImp<ImpXxx, AlgEcpointDouble>::~EccImp()
{
}

//============================
template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgScsTable>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UINT32 nElements = 32;
    PSYMCRYPT_SCSTABLE  pTable = (PSYMCRYPT_SCSTABLE) buf1;

    UINT32 cbBuffer = ScShimSymCryptScsTableInit( pTable, nElements, (UINT32) keySize );
    ScShimSymCryptScsTableSetBuffer( pTable, buf2, cbBuffer );

    for( UINT32 i=0; i<nElements; i++ )
    {
        GENRANDOM( buf3, (UINT32) keySize );
        ScShimSymCryptScsTableStore( pTable, i, buf3, (UINT32) keySize );
    }
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx,AlgScsTable>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction<ImpXxx, AlgScsTable>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );
    UNREFERENCED_PARAMETER( buf2 );
    PSYMCRYPT_SCSTABLE  pTable = (PSYMCRYPT_SCSTABLE) buf1;
    ScShimSymCryptScsTableLoad( pTable, 7, buf3, pTable->elementSize );
}


template<>
ArithImp<ImpXxx, AlgScsTable>::ArithImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptScsTableLoad))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction      = &algImpDataPerfFunction <ImpXxx, AlgScsTable>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgScsTable>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgScsTable>;
}

template<>
ArithImp<ImpXxx, AlgScsTable>::~ArithImp()
{
}

//============================

template<>
VOID
algImpKeyPerfFunction<ImpXxx, AlgEcpointScalarMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    SetupSymCryptCurves<ImpXxx>( buf1, keySize );
    SetupSymCryptEcpoints<ImpXxx>( buf1, buf2, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpXxx, AlgEcpointScalarMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf1 );
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
}

template<>
VOID
algImpDataPerfFunction< ImpXxx, AlgEcpointScalarMul>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( dataSize );

    ScShimSymCryptEcpointScalarMul(
                *(PSYMCRYPT_ECURVE *) buf1,
                ((PSYMCRYPT_INT *) buf2)[2],
                ((PSYMCRYPT_ECPOINT *) buf2)[0],
                0,
                ((PSYMCRYPT_ECPOINT *) buf3)[0],
                buf3 + SCRATCH_BUF_OFFSET,
                SCRATCH_BUF_SIZE );
}


template<>
EccImp<ImpXxx, AlgEcpointScalarMul>::EccImp()
{
    if (!SCTEST_LOOKUP_SCIMPSYM(SymCryptEcpointScalarMul))
    {
        throw STATUS_NOT_SUPPORTED;
    }

    m_perfDataFunction = &algImpDataPerfFunction <ImpXxx, AlgEcpointScalarMul>;
    m_perfDecryptFunction   = NULL;
    m_perfKeyFunction       = &algImpKeyPerfFunction  <ImpXxx, AlgEcpointScalarMul>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpXxx, AlgEcpointScalarMul>;
}

template<>
EccImp<ImpXxx, AlgEcpointScalarMul>::~EccImp()
{
}