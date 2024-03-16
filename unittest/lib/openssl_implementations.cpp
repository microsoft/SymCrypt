//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"
#include <openssl/err.h>
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

VOID
addOpensslAlgs()
{
    addImplementationToGlobalList<XtsImp<ImpOpenssl, AlgXtsAes>>();
    // addImplementationToGlobalList<AuthEncImp<ImpOpenssl, AlgAes, ModeGcm>>();
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
