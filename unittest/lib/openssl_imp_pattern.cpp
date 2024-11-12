//
// Pattern file for the Openssl implementations. Shared between static and dynamically linked
// Openssl implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// AlgShaXXX

#define HANDLE_PATTERN( x ) CONCAT2( global_Handle_ , x )
#define PARAMS_PATTERN( x ) CONCAT2( x , _params)
struct HashContext
{ 
    EVP_MD *pmd;
    EVP_MD_CTX *pmdCtx;
};

//
// fetch the gobal hash handle
VOID fetchGlobalHashAlgHandle(EVP_MD **ppmd, const char* pszAlgorithm) 
{
    if(*ppmd == NULL)
    {
        *ppmd = EVP_MD_fetch(NULL, pszAlgorithm, NULL); // no additional parameters needed
        CHECK(*ppmd != NULL, "EVP_MD_fetch() returned NULL");
    }
}

#define ALG_NAME   SHA256
#define ALG_Name   Sha256
#define ALG_name   sha256
#include "openssl_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name
#undef ALG_name

#define ALG_NAME   SHA384
#define ALG_Name   Sha384
#define ALG_name   sha384
#include "openssl_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name
#undef ALG_name

#define ALG_NAME   SHA512
#define ALG_Name   Sha512
#define ALG_name   sha512
#include "openssl_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name
#undef ALG_name

#define ALG_NAME   SHA3_256
#define ALG_Name   Sha3_256
#define ALG_name   sha3_256
#include "openssl_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name
#undef ALG_name

#define ALG_NAME   SHA3_384
#define ALG_Name   Sha3_384
#define ALG_name   sha3_384
#include "openssl_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name
#undef ALG_name

#define ALG_NAME   SHA3_512
#define ALG_Name   Sha3_512
#define ALG_name   sha3_512
#include "openssl_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name
#undef ALG_name

struct MacContext
{
    EVP_MAC *pMac;
    EVP_MAC_CTX *pMacCtx;
    SIZE_T keySize;
};

//
// fetch the gobal mac handle and associated parameters string
//
VOID fetchGlobalMacAlgHandle( EVP_MAC **ppMac, 
                              const char *pszAlgorithm, 
                              const char *digest,
                              OSSL_PARAM **params ) 
{
    if(*ppMac == NULL)
    {
        *params = (OSSL_PARAM *) SymCryptCallbackAlloc(4 * sizeof(OSSL_PARAM));
        
        OSSL_PARAM *p = *params;
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char*)digest, sizeof(digest));
        *p = OSSL_PARAM_construct_end();

        *ppMac = EVP_MAC_fetch(NULL, pszAlgorithm, NULL);
        CHECK(*ppMac != NULL, "EVP_MAC_fetch() returned NULL");
    }
}

#define ALG_NAME    HMAC_SHA256
#define ALG_Name    HmacSha256
#include "openssl_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    HMAC_SHA384
#define ALG_Name    HmacSha384
#include "openssl_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    HMAC_SHA512
#define ALG_Name    HmacSha512
#include "openssl_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    HMAC_SHA3_256
#define ALG_Name    HmacSha3_256
#include "openssl_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    HMAC_SHA3_384
#define ALG_Name    HmacSha3_384
#include "openssl_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    HMAC_SHA3_512
#define ALG_Name    HmacSha3_512
#include "openssl_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name
