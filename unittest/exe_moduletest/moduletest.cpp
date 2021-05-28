//
// moduletest.cpp
// Test executable for SymCrypt module smoke tests
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <stddef.h>
#include <stdio.h>
#include "symcrypt.h"

const UINT SymCryptSelftestDlGroupBitsOfP = 2048;
const UINT SymCryptSelftestDlGroupBitsOfQ = 256;

SYMCRYPT_ERROR
SymCryptModuleTestDhSecretAgreement()
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PSYMCRYPT_DLGROUP pDlgroup = NULL;
    PSYMCRYPT_DLKEY pkDlkey = NULL;

    pDlgroup = SymCryptDlgroupAllocate( SymCryptSelftestDlGroupBitsOfP, SymCryptSelftestDlGroupBitsOfQ );
    if( pDlgroup == NULL )
    {
        scError = SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        goto cleanup;
    }

    scError = SymCryptDlgroupGenerate(
        SymCryptSha256Algorithm,
        SYMCRYPT_DLGROUP_FIPS_LATEST,
        pDlgroup );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    pkDlkey = SymCryptDlkeyAllocate( pDlgroup );
    if( pkDlkey == NULL )
    {
        scError = SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        goto cleanup;
    }

    scError = SymCryptDlkeyGenerate(0, pkDlkey );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    scError = SymCryptDhSecretAgreementSelftest( pkDlkey );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

cleanup:

    if( pkDlkey != NULL )
    {
        SymCryptDlkeyFree( pkDlkey );
        pkDlkey = NULL;
    }

    if( pDlgroup != NULL )
    {
        SymCryptDlgroupFree( pDlgroup );
        pDlgroup = NULL;
    }

    return scError;
}

SYMCRYPT_ERROR
SymCryptModuleTestEcDhSecretAgreement()
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PSYMCRYPT_ECURVE pCurve = NULL;
    PSYMCRYPT_ECKEY pkEckey = NULL;

    pCurve = SymCryptEcurveAllocate( SymCryptEcurveParamsNistP256, 0 );
    if( pCurve == NULL )
    {
        scError = SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        goto cleanup;
    }

    pkEckey = SymCryptEckeyAllocate( pCurve );
    if( pkEckey == NULL )
    {
        scError = SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        goto cleanup;
    }

    scError = SymCryptEckeySetRandom( 0, pkEckey );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    scError = SymCryptEcDhSecretAgreementSelftest( pkEckey );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

cleanup:

    if( pkEckey != NULL )
    {
        SymCryptEckeyFree( pkEckey );
        pkEckey = NULL;
    }

    if( pCurve != NULL )
    {
        SymCryptEcurveFree( pCurve );
        pCurve = NULL;
    }

    return scError;
}

int
main( int argc, _In_reads_( argc ) char * argv[] )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    SYMCRYPT_MODULE_INIT();

    scError = SymCryptModuleTestDhSecretAgreement();
    if( scError != SYMCRYPT_NO_ERROR )
    {
        printf( "DH secret agreement selftest failed!\n" );
        return scError;
    }

    scError = SymCryptModuleTestEcDhSecretAgreement();
    if( scError != SYMCRYPT_NO_ERROR )
    {
        printf( "ECDH secret agreement selftest failed!\n" );
        return scError;
    }
    
    printf( "Success!\n" );

    return 0;
}