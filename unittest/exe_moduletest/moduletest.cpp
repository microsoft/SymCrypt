//
// moduletest.cpp
// Test executable for SymCrypt module smoke tests
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "symcrypt.h"

const UINT32 SymCryptSelftestRsaKeySizeBits = 2048;

_Analysis_noreturn_
VOID
SYMCRYPT_CALL
SymCryptFatal(UINT32 fatalCode)
{
    abort();
}

extern "C"
{
    int oe_sgx_get_additional_host_entropy(uint8_t* data, size_t size)
    {
        return 1;
    }
}

int
main( int argc, _In_reads_( argc ) char * argv[] )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    SYMCRYPT_MODULE_INIT();

    if( !(SYMCRYPT_DO_FIPS_SELFTESTS) )
    {
        printf("SYMCRYPT_DO_FIPS_SELFTESTS is false; skipping self-test verification.\n");
    }
    else
    {
        SYMCRYPT_FIPS_ASSERT( (g_SymCryptFipsSelftestsPerformed & SYMCRYPT_SELFTEST_STARTUP) != 0 );

        SymCryptDhSecretAgreementSelftest();
        SymCryptEcDhSecretAgreementSelftest();
        SymCryptDsaSelftest();
        SymCryptEcDsaSelftest();
        SymCryptRsaSelftest();
    }

    printf( "Success!\n" );

    return 0;
}