//
// Openssl implementation classes
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

//
// Header files for msbignum
//

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>

class ImpOpenssl {
public:
    static char * name;
};

template<>
class XtsImpState<ImpOpenssl, AlgXtsAes> {
public:
    EVP_CIPHER_CTX* encCtx;
    EVP_CIPHER_CTX* decCtx;
};

VOID
addOpensslAlgs();