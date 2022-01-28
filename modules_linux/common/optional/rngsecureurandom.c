//
// rngsecureurandom.c
// Defines secure entropy functions using urandom as the source
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"
#include <sys/random.h>

// Nothing to init
VOID
SYMCRYPT_CALL
SymCryptEntropySecureInit(){}

// Nothing to uninit
VOID
SYMCRYPT_CALL
SymCryptEntropySecureUninit(){}

// urandom is our secure entropy source.
VOID
SYMCRYPT_CALL
SymCryptEntropySecureGet( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    SIZE_T result;
    result = getrandom( pbResult, cbResult, 0 );
    if (result != cbResult )
    {
        // If the entropy pool has been initialized and the request size is small
        // (buflen <= 256), then getrandom() will not fail with EINTR,
        // but we check anyway as it's not safe to continue if we don't
        // receive the right amount of entropy.
        SymCryptFatal( 'rngs' );
    }
}