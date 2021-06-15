//
// moduletest.cpp
// Test executable for SymCrypt module smoke tests
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <stddef.h>
#include <stdio.h>

#include "symcrypt.h"

const UINT32 SymCryptSelftestRsaKeySizeBits = 2048;

_Analysis_noreturn_
VOID
SYMCRYPT_CALL
SymCryptFatal(UINT32 fatalCode)
{
    abort();
}

VOID
SymCryptModuleTestDsaPairwise()
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PSYMCRYPT_DLGROUP pDlgroup = NULL;
    PSYMCRYPT_DLKEY pkDlkey = NULL;

    pDlgroup = SymCryptDlgroupAllocate( 
        2048, 
        0 );
    SYMCRYPT_FIPS_ASSERT( pDlgroup != NULL );

    scError = SymCryptDlgroupGenerate( SymCryptSha256Algorithm, SYMCRYPT_DLGROUP_FIPS_LATEST, pDlgroup );
    SYMCRYPT_FIPS_ASSERT( scError == SYMCRYPT_NO_ERROR );

    pkDlkey = SymCryptDlkeyAllocate( pDlgroup );
    SYMCRYPT_FIPS_ASSERT( pkDlkey != NULL );

    // SymCryptDlkeyGenerate will call the selftest
    scError = SymCryptDlkeyGenerate( 0, pkDlkey );
    SYMCRYPT_FIPS_ASSERT( scError == SYMCRYPT_NO_ERROR );

    // Verify that the selftest flag was set
    SYMCRYPT_FIPS_ASSERT( (g_SymCryptFipsSelftestsPerformed & SYMCRYPT_SELFTEST_DSA) != 0);


    SymCryptDlkeyFree( pkDlkey );
    SymCryptDlgroupFree( pDlgroup );
}

VOID
SymCryptModuleTestEcDsaPairwise()
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PSYMCRYPT_ECURVE pCurve = NULL;
    PSYMCRYPT_ECKEY pkKey = NULL;

    pCurve = SymCryptEcurveAllocate( SymCryptEcurveParamsNistP256, 0 );
    SYMCRYPT_FIPS_ASSERT( pCurve != NULL );

    pkKey = SymCryptEckeyAllocate( pCurve );
    SYMCRYPT_FIPS_ASSERT( pkKey != NULL );

    // SymCryptEckeySetRandom will call the selftest
    scError = SymCryptEckeySetRandom( 0, pkKey );
    SYMCRYPT_FIPS_ASSERT( scError == SYMCRYPT_NO_ERROR );

    // Verify that the selftest flag was set
    SYMCRYPT_FIPS_ASSERT( (g_SymCryptFipsSelftestsPerformed & SYMCRYPT_SELFTEST_ECDSA) != 0 );

    SymCryptEckeyFree( pkKey );
    SymCryptEcurveFree( pCurve );
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
        SymCryptModuleTestDsaPairwise();
        SymCryptModuleTestEcDsaPairwise();
        SymCryptRsaPairwiseSelftest();
    }
    
    printf( "Success!\n" );

    return 0;
}