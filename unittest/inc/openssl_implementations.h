//
// Openssl implementation classes
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <symcrypt.h>
#include <stdint.h>
#include <vector>
class ImpOpenssl {
public:
    static constexpr const char * name = "OpenSSL";
};

template<>
class XtsImpState<ImpOpenssl, AlgXtsAes> {
public:
    EVP_CIPHER_CTX* encCtx;
    EVP_CIPHER_CTX* decCtx;
};

template<>
class AuthEncImpState<ImpOpenssl, AlgAes, ModeGcm> {
public:
    EVP_CIPHER_CTX* encCtx;
    EVP_CIPHER_CTX* decCtx;
    BOOLEAN inComputation;
};

template<>
class RsaSignImpState<ImpOpenssl, AlgRsaSignPss> {
public:
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *pkey_ctx;
};

template<>
class HashImpState<ImpOpenssl, AlgSha256> {
public:
    BOOLEAN isReset;
    EVP_MD *md;
    EVP_MD_CTX *mdCtx;
    struct constants_t {
        static constexpr SIZE_T inputBlockLen = SYMCRYPT_SHA256_INPUT_BLOCK_SIZE;
        static constexpr SIZE_T resultLen = SYMCRYPT_SHA256_RESULT_SIZE;
        static constexpr const char *const algorithm = "SHA2-256";
    } constants;
};

template<>
class HashImpState<ImpOpenssl, AlgSha384> {
public:
    BOOLEAN isReset;
    EVP_MD *md;
    EVP_MD_CTX *mdCtx;
    struct constants_t {
        static constexpr SIZE_T inputBlockLen = SYMCRYPT_SHA384_INPUT_BLOCK_SIZE;
        static constexpr SIZE_T resultLen = SYMCRYPT_SHA384_RESULT_SIZE;
        static constexpr const char *const algorithm = "SHA2-384";
    } constants;
};

template<>
class HashImpState<ImpOpenssl, AlgSha512> {
public:
    BOOLEAN isReset;
    EVP_MD *md;
    EVP_MD_CTX *mdCtx;
    struct constants_t {
        static constexpr SIZE_T inputBlockLen = SYMCRYPT_SHA512_INPUT_BLOCK_SIZE;
        static constexpr SIZE_T resultLen = SYMCRYPT_SHA512_RESULT_SIZE;
        static constexpr const char *const algorithm = "SHA2-512";
    } constants;
};

template<>
class HashImpState<ImpOpenssl, AlgSha3_256> {
public:
    BOOLEAN isReset;
    EVP_MD *md;
    EVP_MD_CTX *mdCtx;
    struct constants_t {
        static constexpr SIZE_T inputBlockLen = SYMCRYPT_SHA3_256_INPUT_BLOCK_SIZE;
        static constexpr SIZE_T resultLen = SYMCRYPT_SHA3_256_RESULT_SIZE;
        static constexpr const char *const algorithm = "SHA3-256";
    } constants;
};

template<>
class HashImpState<ImpOpenssl, AlgSha3_384> {
public:
    BOOLEAN isReset;
    EVP_MD *md;
    EVP_MD_CTX *mdCtx;
    struct constants_t {
        static constexpr SIZE_T inputBlockLen = SYMCRYPT_SHA3_384_INPUT_BLOCK_SIZE;
        static constexpr SIZE_T resultLen = SYMCRYPT_SHA3_384_RESULT_SIZE;
        static constexpr const char *const algorithm = "SHA3-384";
    } constants;
};

template<>
class HashImpState<ImpOpenssl, AlgSha3_512> {
public:
    BOOLEAN isReset;
    EVP_MD *md;
    EVP_MD_CTX *mdCtx;
    struct constants_t {
        static constexpr SIZE_T inputBlockLen = SYMCRYPT_SHA3_512_INPUT_BLOCK_SIZE;
        static constexpr SIZE_T resultLen = SYMCRYPT_SHA3_512_RESULT_SIZE;
        static constexpr const char *const algorithm = "SHA3-512";
    } constants;
};


VOID
addOpensslAlgs();
