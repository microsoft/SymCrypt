//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <algorithm>

char * ImpOpenssl::name = "OpenSSL";


bool addcarry_u64(UINT64 a, UINT64 b, UINT64 *result) {
    UINT64 additionResult = a+b;
    *result = additionResult;
    return additionResult < a;
}

std::string getOpensslError()
{
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf;
    size_t len = BIO_get_mem_data(bio, &buf);
    std::string ret(buf, len);
    BIO_free(bio);
    return ret;
}

#define CHECK_OPENSSL_SUCCESS(osslInvocation) CHECK(((osslInvocation) == 1), getOpensslError().data())

// AlgXtsAes

struct ExpandedKeyContext
{
    EVP_CIPHER_CTX* encCtx;
    EVP_CIPHER_CTX* decCtx;
    SIZE_T dataUnitSize;
};

template<>
VOID
algImpKeyPerfFunction<ImpOpenssl, AlgXtsAes>( PBYTE expandedKey, PBYTE keyBytes, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    // SymCryptXtsAesExpandKey( (SYMCRYPT_XTS_AES_EXPANDED_KEY *) expandedKey, keyBytes, keySize );
    SIZE_T actualKeySize = keySize & ~PERF_KEY_FLAGS_MASK;
    SIZE_T dataUnitSize = 512;
    if( (keySize & PERF_KEY_FLAGS_MASK) == PERF_KEY_XTS_DATA_UNIT_4096 )
    {
        dataUnitSize = 4096;
    }

    const EVP_CIPHER *cipher = NULL;
    if (actualKeySize == 32)
    {
        cipher = EVP_aes_128_xts();
    }
    else if (actualKeySize == 64)
    {
        cipher = EVP_aes_256_xts();
    }
    CHECK(cipher != NULL, "Unsupported key length");

    // Ideally we could Init the key context for encrypt or decrypt here, but at least in the functional testing, it seems like using one context to:
    // init the cipher and key once, then perform multiple encryptions with different IVs specified in the Init calls is OK
    // init the cipher and key once, then perform multiple decryptions with different IVs specified in the Init calls is OK
    // init the cipher and key once, then perform a mixture of encryptions and decryptions with different IVs specified in the Init calls fails.
    // So for safety I created two separate contexts, one for encrypt and one for decrypt. This means the key expansion performance number
    // looks worse than it would in an application which only ever encrypted or decrypted.


    EVP_CIPHER_CTX* encCtx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX* decCtx = EVP_CIPHER_CTX_new();
    keyBytes[0] = 1;
    keyBytes[actualKeySize/2] = 0;
    CHECK_OPENSSL_SUCCESS(EVP_EncryptInit_ex(encCtx, cipher, NULL, keyBytes, NULL));
    CHECK_OPENSSL_SUCCESS(EVP_DecryptInit_ex(decCtx, cipher, NULL, keyBytes, NULL));

    ExpandedKeyContext *pContext = (ExpandedKeyContext *)expandedKey;
    pContext->encCtx = encCtx;
    pContext->decCtx = decCtx;
    pContext->dataUnitSize = dataUnitSize;
}

template<>
VOID
algImpDataPerfFunction<ImpOpenssl, AlgXtsAes>( PBYTE expandedKey, PBYTE pbSrc, PBYTE pbDst, SIZE_T cbData )
{
    ExpandedKeyContext *pContext = (ExpandedKeyContext *)expandedKey;
    EVP_CIPHER_CTX* encCtx = pContext->encCtx;
    int dataUnitSize = (int)pContext->dataUnitSize;

    int outl = 0;
    int totaloutl = outl;

    SYMCRYPT_ALIGN BYTE tweakBuf[SYMCRYPT_AES_BLOCK_SIZE];
    SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[0], 'twek');
    SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[8], 0);

    while (cbData >= dataUnitSize)
    {
        CHECK_OPENSSL_SUCCESS(EVP_EncryptInit_ex(encCtx, NULL, NULL, NULL, tweakBuf));
        CHECK_OPENSSL_SUCCESS(EVP_CipherUpdate(encCtx, pbDst + totaloutl, &outl, pbSrc + totaloutl, dataUnitSize));

        UINT64 tweakLow64 = SYMCRYPT_LOAD_LSBFIRST64(tweakBuf);
        SYMCRYPT_STORE_LSBFIRST64(tweakBuf, tweakLow64 + 1);

        totaloutl += outl;
        cbData -= outl;
    }
}

template<>
VOID
algImpDecryptPerfFunction<ImpOpenssl, AlgXtsAes>( PBYTE expandedKey, PBYTE pbSrc, PBYTE pbDst, SIZE_T cbData )
{
    ExpandedKeyContext *pContext = (ExpandedKeyContext *)expandedKey;
    EVP_CIPHER_CTX* decCtx = pContext->decCtx;
    int dataUnitSize = (int)pContext->dataUnitSize;

    int outl = 0;
    int totaloutl = outl;

    SYMCRYPT_ALIGN BYTE tweakBuf[SYMCRYPT_AES_BLOCK_SIZE];
    SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[0], 'twek');
    SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[8], 0);

    while (cbData >= dataUnitSize)
    {
        CHECK_OPENSSL_SUCCESS(EVP_DecryptInit_ex(decCtx, NULL, NULL, NULL, tweakBuf));
        CHECK_OPENSSL_SUCCESS(EVP_CipherUpdate(decCtx, pbDst + totaloutl, &outl, pbSrc + totaloutl, dataUnitSize));

        UINT64 tweakLow64 = SYMCRYPT_LOAD_LSBFIRST64(tweakBuf);
        SYMCRYPT_STORE_LSBFIRST64(tweakBuf, tweakLow64 + 1);

        totaloutl += outl;
        cbData -= outl;
    }
}

template<>
VOID
algImpCleanPerfFunction<ImpOpenssl, AlgXtsAes>( PBYTE expandedKey, PBYTE buf2, PBYTE buf3 )
{
    ExpandedKeyContext *pContext = (ExpandedKeyContext *)expandedKey;
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    EVP_CIPHER_CTX_free(pContext->encCtx);
    EVP_CIPHER_CTX_free(pContext->decCtx);
}

template<>
XtsImp<ImpOpenssl, AlgXtsAes>::XtsImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction<ImpOpenssl, AlgXtsAes>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpOpenssl, AlgXtsAes>;
    m_perfKeyFunction       = &algImpKeyPerfFunction<ImpOpenssl, AlgXtsAes>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpOpenssl, AlgXtsAes>;
    state.encCtx = EVP_CIPHER_CTX_new();
    state.decCtx = EVP_CIPHER_CTX_new();
}

template<>
XtsImp<ImpOpenssl, AlgXtsAes>::~XtsImp()
{
    EVP_CIPHER_CTX_free(state.encCtx);
    EVP_CIPHER_CTX_free(state.decCtx);
}

template<>
NTSTATUS
XtsImp<ImpOpenssl, AlgXtsAes>::setKey( PCBYTE pbKey, SIZE_T cbKey, UINT32 flags )
{
    const EVP_CIPHER *cipher = NULL;

    if (cbKey == 32)
    {
        cipher = EVP_aes_128_xts();
    }
    else if (cbKey == 64)
    {
        cipher = EVP_aes_256_xts();
    }
    else
    {
        return STATUS_NOT_SUPPORTED;
    }

    if( SymCryptEqual( pbKey, pbKey+(cbKey/2), (cbKey/2) ) )
    {
        return STATUS_NOT_SUPPORTED;
    }

    CHECK(EVP_EncryptInit_ex(state.encCtx, cipher, NULL, pbKey, NULL) == 1, getOpensslError().data());
    CHECK(EVP_DecryptInit_ex(state.decCtx, cipher, NULL, pbKey, NULL) == 1, getOpensslError().data());

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
XtsImp<ImpOpenssl, AlgXtsAes>::encrypt(
                                        SIZE_T      cbDataUnit,
                                        ULONGLONG   tweak,
        _In_reads_( cbData )            PCBYTE      pbSrc,
        _Out_writes_( cbData )          PBYTE       pbDst,
                                        SIZE_T      cbData )
{
    SYMCRYPT_ASSERT( cbData % cbDataUnit == 0 );
    SYMCRYPT_ALIGN BYTE tweakBuf[SYMCRYPT_AES_BLOCK_SIZE];
    SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[0], tweak);
    SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[8], 0);

    int outl = 0;
    int totaloutl = outl;

    while (cbData >= cbDataUnit)
    {
        CHECK_OPENSSL_SUCCESS(EVP_EncryptInit_ex(state.encCtx, NULL, NULL, NULL, tweakBuf));
        CHECK_OPENSSL_SUCCESS(EVP_EncryptUpdate(state.encCtx, pbDst + totaloutl, &outl, pbSrc + totaloutl, (int)cbDataUnit));

        UINT64 tweakLow64 = SYMCRYPT_LOAD_LSBFIRST64(tweakBuf);
        SYMCRYPT_STORE_LSBFIRST64(tweakBuf, tweakLow64 + 1);

        totaloutl += outl;
        cbData -= outl;
    }

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
XtsImp<ImpOpenssl, AlgXtsAes>::decrypt(
                                        SIZE_T      cbDataUnit,
                                        ULONGLONG   tweak,
        _In_reads_( cbData )            PCBYTE      pbSrc,
        _Out_writes_( cbData )          PBYTE       pbDst,
                                        SIZE_T      cbData )
{
    SYMCRYPT_ASSERT( cbData % cbDataUnit == 0 );
    SYMCRYPT_ALIGN BYTE tweakBuf[SYMCRYPT_AES_BLOCK_SIZE];
    SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[0], tweak);
    SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[8], 0);

    int outl = 0;
    int totaloutl = outl;

    while (cbData >= cbDataUnit)
    {
        CHECK_OPENSSL_SUCCESS(EVP_DecryptInit_ex(state.decCtx, NULL, NULL, NULL, tweakBuf));
        CHECK_OPENSSL_SUCCESS(EVP_DecryptUpdate(state.decCtx, pbDst + totaloutl, &outl, pbSrc + totaloutl, (int)cbDataUnit));

        UINT64 tweakLow64 = SYMCRYPT_LOAD_LSBFIRST64(tweakBuf);
        SYMCRYPT_STORE_LSBFIRST64(tweakBuf, tweakLow64 + 1);

        totaloutl += outl;
        cbData -= outl;
    }

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
XtsImp<ImpOpenssl, AlgXtsAes>::encryptWith128bTweak(
                                                SIZE_T  cbDataUnit,
        _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PCBYTE  pbTweak,
        _In_reads_( cbData )                    PCBYTE  pbSrc,
        _Out_writes_( cbData )                  PBYTE   pbDst,
                                                SIZE_T  cbData )
{
    SYMCRYPT_ASSERT( cbData % cbDataUnit == 0 );

    BYTE tweakBuf[SYMCRYPT_AES_BLOCK_SIZE];
    SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[0], SYMCRYPT_LOAD_LSBFIRST64(pbTweak));
    SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[8], SYMCRYPT_LOAD_LSBFIRST64(pbTweak+8));

    int outl = 0;
    int totaloutl = outl;

    while (cbData >= cbDataUnit)
    {
        CHECK_OPENSSL_SUCCESS(EVP_EncryptInit_ex(state.encCtx, NULL, NULL, NULL, tweakBuf));
        CHECK_OPENSSL_SUCCESS(EVP_EncryptUpdate(state.encCtx, pbDst + totaloutl, &outl, pbSrc + totaloutl, (int)cbDataUnit));

        UINT64 tweakLow64 = SYMCRYPT_LOAD_LSBFIRST64(tweakBuf);
        if (addcarry_u64(tweakLow64, 1, &tweakLow64))
        {
            UINT64 tweakHigh64 = SYMCRYPT_LOAD_LSBFIRST64(tweakBuf + 8);
            SYMCRYPT_STORE_LSBFIRST64(tweakBuf + 8, tweakHigh64 + 1);
        }
        SYMCRYPT_STORE_LSBFIRST64(tweakBuf, tweakLow64);

        totaloutl += outl;
        cbData -= outl;
    }

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
XtsImp<ImpOpenssl, AlgXtsAes>::decryptWith128bTweak(
                                                SIZE_T  cbDataUnit,
        _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PCBYTE  pbTweak,
        _In_reads_( cbData )                    PCBYTE  pbSrc,
        _Out_writes_( cbData )                  PBYTE   pbDst,
                                                SIZE_T  cbData )
{
    SYMCRYPT_ASSERT( cbData % cbDataUnit == 0 );

    BYTE tweakBuf[SYMCRYPT_AES_BLOCK_SIZE];
    SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[0], SYMCRYPT_LOAD_LSBFIRST64(pbTweak));
    SYMCRYPT_STORE_LSBFIRST64(&tweakBuf[8], SYMCRYPT_LOAD_LSBFIRST64(pbTweak+8));

    int outl = 0;
    int totaloutl = outl;

    while (cbData >= cbDataUnit)
    {
        CHECK_OPENSSL_SUCCESS(EVP_DecryptInit_ex(state.decCtx, NULL, NULL, NULL, tweakBuf));
        CHECK_OPENSSL_SUCCESS(EVP_DecryptUpdate(state.decCtx, pbDst + totaloutl, &outl, pbSrc + totaloutl, (int)cbDataUnit));

        UINT64 tweakLow64 = SYMCRYPT_LOAD_LSBFIRST64(tweakBuf);
        if (addcarry_u64(tweakLow64, 1, &tweakLow64))
        {
            UINT64 tweakHigh64 = SYMCRYPT_LOAD_LSBFIRST64(tweakBuf + 8);
            SYMCRYPT_STORE_LSBFIRST64(tweakBuf + 8, tweakHigh64 + 1);
        }
        SYMCRYPT_STORE_LSBFIRST64(tweakBuf, tweakLow64);

        totaloutl += outl;
        cbData -= outl;
    }

    return STATUS_SUCCESS;
}

// AlgXtsAes end

// ModeGcm

template<>
VOID
algImpKeyPerfFunction< ImpOpenssl, AlgAes, ModeGcm>( PBYTE expandedKey, PBYTE keyBytes, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    // SymCryptGcmExpandKey( (PSYMCRYPT_GCM_EXPANDED_KEY) expandedKey,
    //                     SymCryptAesBlockCipher,
    //                     keyBytes, keySize );

    const EVP_CIPHER *cipher = NULL;

    if (keySize == 32)
    {
        cipher = EVP_aes_256_gcm();
    }
    else if (keySize == 24)
    {
        cipher = EVP_aes_192_gcm();
    }
    else if (keySize == 16)
    {
        cipher = EVP_aes_128_gcm();
    }
    CHECK(cipher != NULL, "Unsupported key length");

    EVP_CIPHER_CTX* encCtx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX* decCtx = EVP_CIPHER_CTX_new();
    CHECK_OPENSSL_SUCCESS(EVP_EncryptInit_ex(encCtx, cipher, NULL, keyBytes, NULL));
    CHECK_OPENSSL_SUCCESS(EVP_DecryptInit_ex(decCtx, cipher, NULL, keyBytes, NULL));

    ExpandedKeyContext *pContext = (ExpandedKeyContext *)expandedKey;
    pContext->encCtx = encCtx;
    pContext->decCtx = decCtx;
}

template<>
VOID
algImpDataPerfFunction<ImpOpenssl,AlgAes, ModeGcm>( PBYTE expandedKey, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    // SymCryptGcmEncrypt( (PCSYMCRYPT_GCM_EXPANDED_KEY) expandedKey,
    //                         buf2, 12,
    //                         nullptr, 0,
    //                         buf2 + 16, buf3 + 16, dataSize,
    //                         buf3, 16 );

    int outlen = 0;
    PCBYTE pbNonce = buf2;
    PCBYTE  pbSrc = buf2 + 16;
    PBYTE   pbDst = buf3 + 16;
    SIZE_T  cbData = dataSize;
    PBYTE   pbTag = buf3;
    SIZE_T  cbTag = 16;
    ExpandedKeyContext *pContext = (ExpandedKeyContext *)expandedKey;

    // Default nonce size is 12.
    CHECK(EVP_EncryptInit_ex2(pContext->encCtx, NULL, NULL, pbNonce, NULL) == 1, getOpensslError().data());
    CHECK(EVP_EncryptUpdate(pContext->encCtx, pbDst, &outlen, pbSrc, (int)cbData) == 1, getOpensslError().data());
    CHECK(EVP_EncryptFinal_ex(pContext->encCtx, pbDst, &outlen) == 1, getOpensslError().data());
    CHECK(EVP_CIPHER_CTX_ctrl(pContext->encCtx, EVP_CTRL_AEAD_GET_TAG, (int)cbTag, pbTag) > 0, getOpensslError().data());
}

template<>
VOID
algImpDecryptPerfFunction<ImpOpenssl,AlgAes, ModeGcm>( PBYTE expandedKey, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    // SymCryptGcmDecrypt( (PCSYMCRYPT_GCM_EXPANDED_KEY) buf1,
    //                         buf2, 12,
    //                         nullptr, 0,
    //                         buf3 + 16, buf2 + 16, dataSize,
    //                         buf3, 16 );
    int outlen = 0;
    PCBYTE pbNonce = buf2;
    PCBYTE  pbSrc = buf3 + 16;
    PBYTE   pbDst = buf2 + 16;
    SIZE_T  cbData = dataSize;
    PBYTE   pbTag = buf3;
    SIZE_T  cbTag = 16;
    ExpandedKeyContext *pContext = (ExpandedKeyContext *)expandedKey;

    // Default nonce size is 12.
    CHECK(EVP_DecryptInit_ex2(pContext->decCtx, NULL, NULL, pbNonce, NULL) == 1, getOpensslError().data());
    CHECK(EVP_DecryptUpdate(pContext->decCtx, pbDst, &outlen, pbSrc, (int)cbData) == 1, getOpensslError().data());
    CHECK(EVP_CIPHER_CTX_ctrl(pContext->decCtx, EVP_CTRL_AEAD_SET_TAG,
                                               (int)cbTag, (void *)pbTag) > 0, getOpensslError().data());
    CHECK(EVP_DecryptFinal_ex(pContext->decCtx, pbDst, &outlen) == 1, getOpensslError().data());
}

template<>
VOID
algImpCleanPerfFunction<ImpOpenssl,AlgAes, ModeGcm>( PBYTE expandedKey, PBYTE buf2, PBYTE buf3 )
{
    ExpandedKeyContext *pContext = (ExpandedKeyContext *)expandedKey;
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    EVP_CIPHER_CTX_free(pContext->encCtx);
    EVP_CIPHER_CTX_free(pContext->decCtx);
}

template<>
AuthEncImp<ImpOpenssl, AlgAes, ModeGcm>::AuthEncImp()
{
    m_perfKeyFunction     = &algImpKeyPerfFunction<ImpOpenssl, AlgAes, ModeGcm>;
    m_perfCleanFunction   = &algImpCleanPerfFunction<ImpOpenssl, AlgAes, ModeGcm>;
    m_perfDataFunction    = &algImpDataPerfFunction<ImpOpenssl, AlgAes, ModeGcm>;
    m_perfDecryptFunction = &algImpDecryptPerfFunction<ImpOpenssl, AlgAes, ModeGcm>;
    state.encCtx          = EVP_CIPHER_CTX_new();
    state.decCtx          = EVP_CIPHER_CTX_new();
}

template<>
AuthEncImp<ImpOpenssl, AlgAes, ModeGcm>::~AuthEncImp()
{
    EVP_CIPHER_CTX_free(state.encCtx);
    EVP_CIPHER_CTX_free(state.decCtx);
}

template<>
std::set<SIZE_T>
AuthEncImp<ImpOpenssl, AlgAes, ModeGcm>::getKeySizes()
{
    std::set<SIZE_T> res;

    res.insert( 16 );
    res.insert( 24 );
    res.insert( 32 );

    return res;
}


template<>
std::set<SIZE_T>
AuthEncImp<ImpOpenssl, AlgAes, ModeGcm>::getNonceSizes()
{
    std::set<SIZE_T> res;

    for(int i = 1; i <= 256; ++i)
    {
        res.insert( i );
    }

    return res;
}


template<>
std::set<SIZE_T>
AuthEncImp<ImpOpenssl, AlgAes, ModeGcm>::getTagSizes()
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
AuthEncImp<ImpOpenssl, AlgAes, ModeGcm>::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    const EVP_CIPHER *cipher = NULL;

    if (cbKey == 32)
    {
        cipher = EVP_aes_256_gcm();
    }
    else if (cbKey == 24)
    {
        cipher = EVP_aes_192_gcm();
    }
    else if (cbKey == 16)
    {
        cipher = EVP_aes_128_gcm();
    }
    else
    {
        return STATUS_NOT_SUPPORTED;
    }

    CHECK(EVP_EncryptInit_ex2(state.encCtx, cipher, pbKey, NULL, NULL) == 1, getOpensslError().data());
    CHECK(EVP_DecryptInit_ex2(state.decCtx, cipher, pbKey, NULL, NULL) == 1, getOpensslError().data());


    // SymCryptGcmExpandKey( &state.key, SymCryptAesBlockCipher, pbKey, cbKey );

    state.inComputation = FALSE;
    return STATUS_SUCCESS;
}

template<>
VOID
AuthEncImp<ImpOpenssl, AlgAes, ModeGcm>::setTotalCbData( SIZE_T )
{
}

template<>
NTSTATUS
AuthEncImp<ImpOpenssl, AlgAes, ModeGcm>::encrypt(
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
    int outlen = 0;

    CHECK( (flags & ~AUTHENC_FLAG_PARTIAL) == 0, "Unknown flag" );

    const int GCM_IV_MAX_SIZE = (1024 / 8);
    if( cbNonce > GCM_IV_MAX_SIZE )
    {
        return STATUS_NOT_SUPPORTED;
    }

    if( (flags & AUTHENC_FLAG_PARTIAL) == 0 )
    {
        // simple straight GCM computation.
        // CHECK( SymCryptGcmValidateParameters(
        //     SymCryptAesBlockCipher,
        //     cbNonce,
        //     cbAuthData,
        //     cbData,
        //     cbTag ) == SYMCRYPT_NO_ERROR, "?" );

        // SymCryptGcmEncrypt( &state.key,
        //     pbNonce, cbNonce, pbAuthData, cbAuthData,
        //     pbSrc, pbDst, cbData,
        //     pbTag, cbTag );
        OSSL_PARAM params[2] = {
            OSSL_PARAM_END, OSSL_PARAM_END
        };

        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                            &cbNonce);
        CHECK(EVP_EncryptInit_ex2(state.encCtx, NULL, NULL, pbNonce, params) == 1, getOpensslError().data());
        CHECK(EVP_EncryptUpdate(state.encCtx, NULL, &outlen, pbAuthData, (int)cbAuthData) == 1, getOpensslError().data());
        CHECK(EVP_EncryptUpdate(state.encCtx, pbDst, &outlen, pbSrc, (int)cbData) == 1, getOpensslError().data());
        CHECK(EVP_EncryptFinal_ex(state.encCtx, pbDst, &outlen) == 1, getOpensslError().data());
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                  pbTag, cbTag);

        CHECK(EVP_CIPHER_CTX_get_params(state.encCtx, params) == 1, getOpensslError().data());

        // Done
        goto cleanup;
    }

    if( !state.inComputation )
    {
        OSSL_PARAM params[2] = {
            OSSL_PARAM_END, OSSL_PARAM_END
        };

        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                            &cbNonce);
        CHECK(EVP_EncryptInit_ex2(state.encCtx, NULL, NULL, pbNonce, params) == 1, getOpensslError().data());
        CHECK(EVP_EncryptUpdate(state.encCtx, NULL, &outlen, pbAuthData, (int)cbAuthData) == 1, getOpensslError().data());
        state.inComputation = TRUE;
    }

    CHECK(EVP_EncryptUpdate(state.encCtx, pbDst, &outlen, pbSrc, (int)cbData) == 1, getOpensslError().data());

    if( pbTag != nullptr )
    {
        CHECK(EVP_EncryptFinal_ex(state.encCtx, pbDst, &outlen) == 1, getOpensslError().data());
        EVP_CIPHER_CTX_ctrl(state.encCtx, EVP_CTRL_AEAD_GET_TAG, (int)cbTag, pbTag);
        state.inComputation = FALSE;
    }

cleanup:
    return status;
}

template<>
NTSTATUS
AuthEncImp<ImpOpenssl, AlgAes, ModeGcm>::decrypt(
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
    int scError = 1;
    int outlen = 0;

    CHECK( (flags & ~AUTHENC_FLAG_PARTIAL) == 0, "Unknown flag" );
    const int GCM_IV_MAX_SIZE = (1024 / 8);
    if( cbNonce > GCM_IV_MAX_SIZE )
    {
        return STATUS_NOT_SUPPORTED;
    }

    if( (flags & AUTHENC_FLAG_PARTIAL) == 0 )
    {
        // simple straight GCM computation.
        // CHECK( SymCryptGcmValidateParameters(
        //     SymCryptAesBlockCipher,
        //     cbNonce,
        //     cbAuthData,
        //     cbData,
        //     cbTag ) == SYMCRYPT_NO_ERROR, "?" );

        // scError = SymCryptGcmDecrypt( &state.key,
        //     pbNonce, cbNonce, pbAuthData, cbAuthData,
        //     pbSrc, pbDst, cbData,
        //     pbTag, cbTag );

        OSSL_PARAM params[2] = {
            OSSL_PARAM_END, OSSL_PARAM_END
        };

        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                            &cbNonce);

        CHECK(EVP_DecryptInit_ex2(state.decCtx, NULL, NULL, pbNonce, params) == 1, getOpensslError().data());
        CHECK(EVP_DecryptUpdate(state.decCtx, NULL, &outlen, pbAuthData, (int)cbAuthData) == 1, getOpensslError().data());
        CHECK(EVP_DecryptUpdate(state.decCtx, pbDst, &outlen, pbSrc, (int)cbData) == 1, getOpensslError().data());
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                  (void *)pbTag, cbTag);

        CHECK(EVP_CIPHER_CTX_set_params(state.decCtx, params) == 1, getOpensslError().data());
        scError = EVP_DecryptFinal_ex(state.decCtx, pbDst, &outlen);

        // Done
        goto cleanup;
    }

    if( !state.inComputation )
    {
        OSSL_PARAM params[2] = {
            OSSL_PARAM_END, OSSL_PARAM_END
        };

        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                            &cbNonce);
        CHECK(EVP_DecryptInit_ex2(state.decCtx, NULL, NULL, pbNonce, params) == 1, getOpensslError().data());
        CHECK(EVP_DecryptUpdate(state.decCtx, NULL, &outlen, pbAuthData, (int)cbAuthData) == 1, getOpensslError().data());
        state.inComputation = TRUE;
    }
    CHECK(EVP_DecryptUpdate(state.decCtx, pbDst, &outlen, pbSrc, (int)cbData) == 1, getOpensslError().data());

    if( pbTag != nullptr )
    {
        // OSSL_PARAM params[2] = {
        //     OSSL_PARAM_END, OSSL_PARAM_END
        // };

        // params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
        //                                             (void *)pbTag, cbTag);
        EVP_CIPHER_CTX_ctrl(state.decCtx, EVP_CTRL_AEAD_SET_TAG,
                                               (int)cbTag, (void *)pbTag);
        scError = EVP_DecryptFinal_ex(state.decCtx, pbDst, &outlen);
        state.inComputation = FALSE;
    }

cleanup:
    return scError > 0 ? 0 : STATUS_AUTH_TAG_MISMATCH;
}

// ModeGcm end


VOID
addOpensslAlgs()
{
    addImplementationToGlobalList<XtsImp<ImpOpenssl, AlgXtsAes>>();
    addImplementationToGlobalList<AuthEncImp<ImpOpenssl, AlgAes, ModeGcm>>();
    // addImplementationToGlobalList<RsaSignImp<ImpOpenssl, AlgRsaSignPss>>();
    // addImplementationToGlobalList<HashImp<ImpOpenssl, AlgSha256>>();
    // addImplementationToGlobalList<HashImp<ImpOpenssl, AlgSha384>>();
    // addImplementationToGlobalList<HashImp<ImpOpenssl, AlgSha512>>();
    // addImplementationToGlobalList<HashImp<ImpOpenssl, AlgSha3_256>>();
    // addImplementationToGlobalList<HashImp<ImpOpenssl, AlgSha3_384>>();
    // addImplementationToGlobalList<HashImp<ImpOpenssl, AlgSha3_512>>();
    // addImplementationToGlobalList<MacImp<ImpOpenssl, AlgHmacSha256>>();
    // addImplementationToGlobalList<MacImp<ImpOpenssl, AlgHmacSha384>>();
    // addImplementationToGlobalList<MacImp<ImpOpenssl, AlgHmacSha512>>();
}
