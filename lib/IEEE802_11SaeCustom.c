//
// IEEE802_11SaeCustom.c  Implementation of the custom crypto of IEEE 802.11 SAE
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// 

#include "precomp.h"

SYMCRYPT_ERROR
SymCrypt802_11SaeCustomInit(
    _Out_                       PSYMCRYPT_802_11_SAE_CUSTOM_STATE   pState,
    _In_reads_( 6 )             PCBYTE                              pbMac1,
    _In_reads_( 6 )             PCBYTE                              pbMac2,
    _In_reads_( cbPassword )    PCBYTE                              pbPassword,
                                SIZE_T                              cbPassword,
    _Out_opt_                   PBYTE                               pbCounter,
    _Inout_updates_opt_( 32 )   PBYTE                               pbRand,
    _Inout_updates_opt_( 32 )   PBYTE                               pbMask )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    BYTE counter;
    UINT32 notFoundMask;
    UINT32 solutionMask;
    UINT32 negMask;
    BYTE abSeed[SYMCRYPT_HMAC_SHA256_RESULT_SIZE];
    BYTE abValue[SYMCRYPT_HMAC_SHA256_RESULT_SIZE];
    BYTE abSeedKey[16];     // Need only 12, but the extra bytes make the code easier.
    SYMCRYPT_HMAC_SHA256_EXPANDED_KEY hmacSeedKey;
    SYMCRYPT_HMAC_SHA256_EXPANDED_KEY hmacValueKey;
    SYMCRYPT_HMAC_SHA256_STATE hmacState;
    BYTE abTmp[2];
    BYTE pointBuf[ 64 ];
    PBYTE pbScratch = NULL;
    SIZE_T cbScratch = 0;
    UINT64 minMac;
    UINT64 maxMac;
    
    UINT32  nDigits;
    PSYMCRYPT_ECURVE        pCurve;             // Only a cache, pState->pCurve owns the allocation
    PSYMCRYPT_INT           piTmp = NULL;
    PSYMCRYPT_MODELEMENT    peX = NULL;
    PSYMCRYPT_MODELEMENT    peY = NULL;
    PSYMCRYPT_MODELEMENT    peCubic = NULL;
    PSYMCRYPT_MODELEMENT    peTmp = NULL;
    PSYMCRYPT_ECPOINT       poPWECandidate = NULL;

    // Set state to 0 so that our pointers have valid values.
    SymCryptWipe( pState, sizeof( *pState ) );

    // Per IEEE 802.11-2016 section 12.4.4.1 the madatory-to-implement curve is 
    // number 19 from the IANA Group description for RFC 2409 (IKE)
    // The IANA website maps this to a 256-bit Random ECP group in RFC 5903.
    // RFC 5903 specifies this group to be identical to the NIST P256 curve.
    pCurve = SymCryptEcurveAllocate( SymCryptEcurveParamsNistP256, 0 );
    pState->pCurve = pCurve;
    if( pCurve == NULL )
    {
        scError = SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        goto cleanup;
    }

    pState->peRand = SymCryptModElementAllocate( pCurve->GOrd );
    if( pState->peRand == NULL )
    {
        scError = SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        goto cleanup;
    }

    pState->peMask = SymCryptModElementAllocate( pCurve->GOrd );
    if( pState->peMask == NULL )
    {
        scError = SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        goto cleanup;
    }

    pState->poPWE = SymCryptEcpointAllocate( pCurve );
    if( pState->poPWE == NULL )
    {
        scError = SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        goto cleanup;
    }

    nDigits = SymCryptDigitsFromBits( 256 );

    cbScratch = max( SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ), 
                max( SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP( nDigits ),
                     SYMCRYPT_SCRATCH_BYTES_FOR_GETSET_VALUE_ECURVE_OPERATIONS( pCurve ) ) );
    pbScratch = SymCryptCallbackAlloc( cbScratch );

    piTmp = SymCryptIntAllocate( nDigits );
    peX = SymCryptModElementAllocate( pCurve->FMod );
    peY = SymCryptModElementAllocate( pCurve->FMod );
    peCubic = SymCryptModElementAllocate( pCurve->FMod );
    peTmp = SymCryptModElementAllocate( pCurve->FMod );
    poPWECandidate = SymCryptEcpointAllocate( pCurve );

    if( pbScratch == NULL || piTmp == NULL || peX == NULL || peY == NULL || peCubic == NULL || peTmp == NULL || poPWECandidate == NULL )
    {
        scError = SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        goto cleanup;
    }

    SymCryptWipeKnownSize( abSeedKey, sizeof( abSeedKey ) );
    memcpy( &abSeedKey[0], pbMac1, 6 );
    minMac = SYMCRYPT_LOAD_MSBFIRST64( abSeedKey );
    memcpy( &abSeedKey[0], pbMac2, 6 );
    maxMac = SYMCRYPT_LOAD_MSBFIRST64( abSeedKey );

    if( minMac > maxMac )
    {
        // MAC values are public, no side-channel issues with this if()
        // Swap the two values
        minMac ^= maxMac;
        maxMac ^= minMac;
        minMac ^= maxMac;
    }

    // Now we write the two MACs into the buffer.
    // Note the slight overlap, and the use of 14 bytes rather than 12
    SYMCRYPT_STORE_MSBFIRST64( &abSeedKey[0], maxMac );
    SYMCRYPT_STORE_MSBFIRST64( &abSeedKey[6], minMac );         // This writes up to abSeedKey[14]

    SymCryptHmacSha256ExpandKey( &hmacSeedKey, abSeedKey, 12 );
    SymCryptWipeKnownSize( abSeedKey, sizeof( abSeedKey ) );    // Not strictly speaking a secret, but good general hygiene

    notFoundMask = (UINT32)-1;
    counter = 0;

    // We exit the loop only after 40 or more iterations
    // This greatly reduces the side-channel of how often we run this loop.
    while( notFoundMask != 0 || counter < 40 ) 
    {
        counter += 1;
        SYMCRYPT_HARD_ASSERT( counter != 0 );

        // pwd-seed = Hmac-sha256( MacA || MacB , Password || counter )
        SymCryptHmacSha256Init( &hmacState, &hmacSeedKey );
        SymCryptHmacSha256Append( &hmacState, pbPassword, cbPassword );
        SymCryptHmacSha256Append( &hmacState, &counter, 1 );
        SymCryptHmacSha256Result( &hmacState, abSeed );

        // pwd-value
        SymCryptHmacSha256ExpandKey( &hmacValueKey, abSeed, sizeof( abSeed ) );
        SymCryptHmacSha256Init( &hmacState, &hmacValueKey );

        SYMCRYPT_STORE_LSBFIRST16( abTmp, 1 );
        SymCryptHmacSha256Append( &hmacState, abTmp, 2 );   // i value = 1
        // Spec is unclear on whether there should be a terminating 0 on the context
        // There are 23 characters in the string, so using len=24 gives us a zero
        SymCryptHmacSha256Append( &hmacState, (PCBYTE) "SAE Hunting and Pecking", 23 );

        // Pick up the byte representation of p from the parameters
        SymCryptHmacSha256Append( &hmacState, (BYTE *)(SymCryptEcurveParamsNistP256 + 1), 32 );

        SYMCRYPT_STORE_LSBFIRST16( abTmp, 256 );
        SymCryptHmacSha256Append( &hmacState, abTmp, 2 );   // Length value = 256
        SymCryptHmacSha256Result( &hmacState, abValue );

        // Get the pwd-value into an integer
        scError = SymCryptIntSetValue( abValue, sizeof( abValue ), SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piTmp );
        SYMCRYPT_HARD_ASSERT( scError == SYMCRYPT_NO_ERROR );

        // Check that it is less than P
        if( !SymCryptIntIsLessThan( piTmp, SymCryptIntFromModulus( pCurve->FMod ) ) )
        {
            // This is a slight side-channel, but our prime P starts with FFFFFFFF so the probability of
            // hitting this case is < 2^-32.
            continue;
        }

        // Compute x^3 + A*x + B
        SymCryptIntToModElement( piTmp, pCurve->FMod, peX, pbScratch, cbScratch );
        SymCryptModSquare( pCurve->FMod, peX, peCubic, pbScratch, cbScratch );
        SymCryptModAdd( pCurve->FMod, peCubic, pCurve->A, peCubic, pbScratch, cbScratch );
        SymCryptModMul( pCurve->FMod, peCubic, peX, peCubic, pbScratch, cbScratch );
        SymCryptModAdd( pCurve->FMod, peCubic, pCurve->B, peCubic, pbScratch, cbScratch );

        // Sqrt( v ) = v^{(P+1)/4} mod P when P = 3 mod 4 as it is here
        SymCryptIntCopy( SymCryptIntFromModulus(pCurve->FMod), piTmp );
        SymCryptIntAddUint32( piTmp, 1, piTmp );      // No overflow as our prime is not 2^256 - 1

        SYMCRYPT_ASSERT( (SymCryptIntGetValueLsbits32( piTmp ) & 3) == 0 );
        SymCryptIntDivPow2( piTmp, 2, piTmp );
        // iX = (P+1)/4
        
        // Compute Sqrt( X^3 + aX + B ) if it exists
        SymCryptModExp( pCurve->FMod, peCubic, piTmp, 254, 0, peY, pbScratch, cbScratch );

        SymCryptModSquare( pCurve->FMod, peY, peTmp, pbScratch, cbScratch );
        solutionMask = SymCryptModElementIsEqual( pCurve->FMod, peTmp, peCubic );
        solutionMask &= notFoundMask;

        // Pick Y or -Y according to the LSbits
        SymCryptModElementToInt( pCurve->FMod, peY, piTmp, pbScratch, cbScratch );
        SymCryptModNeg( pCurve->FMod, peY, peTmp, pbScratch, cbScratch );

        negMask = 0 - ((abSeed[ sizeof( abSeed ) - 1 ] ^ SymCryptIntGetValueLsbits32( piTmp ) ) & 1);
        SymCryptModElementMaskedCopy( pCurve->FMod, peTmp, peY, negMask );

        SymCryptModElementGetValue( pCurve->FMod, peX, &pointBuf[ 0], 32, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pbScratch, cbScratch );
        SymCryptModElementGetValue( pCurve->FMod, peY, &pointBuf[32], 32, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pbScratch, cbScratch );
        scError = SymCryptEcpointSetValue(  pCurve, 
                                            pointBuf, 
                                            sizeof( pointBuf ), 
                                            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 
                                            SYMCRYPT_ECPOINT_FORMAT_XY, 
                                            poPWECandidate, 
                                            0,
                                            pbScratch,
                                            cbScratch );
        SYMCRYPT_HARD_ASSERT( scError == SYMCRYPT_NO_ERROR );

        SymCryptEcpointMaskedCopy( pCurve, poPWECandidate, pState->poPWE, solutionMask );
        pState->counter |= (BYTE)(counter & solutionMask);

        notFoundMask &= ~solutionMask;
    }

    SymCryptModElementSetValueUint32( 0, pCurve->GOrd, pState->peRand, pbScratch, cbScratch );
    if( pbRand != NULL )
    {
        scError = SymCryptModElementSetValue( pbRand, 32, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pCurve->GOrd, pState->peRand, pbScratch, cbScratch );
        if( scError != SYMCRYPT_NO_ERROR )
        {
            goto cleanup;
        }
    }

    if( SymCryptModElementIsZero( pCurve->GOrd, pState->peRand ) )
    {
        SymCryptModSetRandom( pCurve->GOrd, pState->peRand, SYMCRYPT_FLAG_MODRANDOM_ALLOW_MINUSONE, pbScratch, cbScratch );
    }

    if( pbRand != NULL )
    {
        scError = SymCryptModElementGetValue( pCurve->GOrd, pState->peRand, pbRand, 32, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pbScratch, cbScratch );
        if( scError != SYMCRYPT_NO_ERROR )
        {
            goto cleanup;
        }
    }

    SymCryptModElementSetValueUint32( 0, pCurve->GOrd, pState->peMask, pbScratch, cbScratch );
    if( pbMask != NULL )
    {
        scError = SymCryptModElementSetValue( pbMask, 32, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pCurve->GOrd, pState->peMask, pbScratch, cbScratch );
        if( scError != SYMCRYPT_NO_ERROR )
        {
            goto cleanup;
        }
    }

    if( SymCryptModElementIsZero( pCurve->GOrd, pState->peMask ) )
    {
        SymCryptModSetRandom( pCurve->GOrd, pState->peMask, SYMCRYPT_FLAG_MODRANDOM_ALLOW_MINUSONE, pbScratch, cbScratch );
    }

    if( pbMask != NULL )
    {
        scError = SymCryptModElementGetValue( pCurve->GOrd, pState->peMask, pbMask, 32, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pbScratch, cbScratch );
        if( scError != SYMCRYPT_NO_ERROR )
        {
            goto cleanup;
        }
    }

    //
    // The standard calls for checking that peRand and peMask are not 0 or 1, and peRand + peMask is not 0 or 1.
    // When the caller specifies the values we don't want to do any checking as they might be helpful in test vectors.
    // When this code generates the random values, we avoid 0 or 1 (by not passing the flags allowing 0 and 1).
    // We don't check that peRand + peMask > 1 because the probability of that occurring randomly is about 2^{-254} so the
    // risk of this happening on any machine ever in the world is much smaller than the risk associated with adding several lines of code.
    //

    if( pbCounter != NULL )
    {
        *pbCounter = pState->counter;
    }

cleanup:

    SymCryptWipe( &hmacSeedKey, sizeof( hmacSeedKey ) );
    SymCryptWipe( &hmacValueKey, sizeof( hmacValueKey ) );
    SymCryptWipe( abSeed, sizeof( abSeed ) );
    SymCryptWipe( abValue, sizeof( abValue ) );
    SymCryptWipe( pointBuf, sizeof( pointBuf ) );

    if( piTmp != NULL )
    {
        SymCryptIntFree( piTmp );
        piTmp = NULL;
    }

    if( peX != NULL )
    {
        SymCryptModElementFree( pCurve->FMod, peX );
        peX = NULL;
    }

    if( peY != NULL )
    {
        SymCryptModElementFree( pCurve->FMod, peY );
        peY = NULL;
    }

    if( peCubic != NULL )
    {
        SymCryptModElementFree( pCurve->FMod, peCubic );
        peCubic = NULL;
    }

    if( peTmp != NULL )
    {
        SymCryptModElementFree( pCurve->FMod, peTmp );
        peTmp = NULL;
    }

    if( poPWECandidate != NULL )
    {
        SymCryptEcpointFree( pCurve, poPWECandidate );
        poPWECandidate = NULL;
    }

    if( scError != SYMCRYPT_NO_ERROR )
    {
        SymCrypt802_11SaeCustomDestroy( pState );
    }

    if( pbScratch != NULL )
    {
        SymCryptWipe( pbScratch, cbScratch );
        SymCryptCallbackFree( pbScratch );
        pbScratch = NULL;
    }

    return scError;
}



VOID
SymCrypt802_11SaeCustomDestroy( 
    _Out_   PSYMCRYPT_802_11_SAE_CUSTOM_STATE   pState )
{
    PSYMCRYPT_ECURVE pCurve = pState->pCurve;

    if( pState->poPWE != NULL )
    {
        SymCryptEcpointFree( pCurve, pState->poPWE );
    }

    if( pState->peMask != NULL )
    {
        SymCryptModElementFree( pCurve->GOrd, pState->peMask );
    }

    if( pState->peRand != NULL )
    {
        SymCryptModElementFree( pCurve->GOrd, pState->peRand );
    }

    if( pCurve != NULL )
    {
        SymCryptEcurveFree( pCurve );
    }

    SymCryptWipeKnownSize( pState, sizeof( *pState ) );
}


SYMCRYPT_ERROR
SymCrypt802_11SaeCustomCommitCreate(
    _In_                        PCSYMCRYPT_802_11_SAE_CUSTOM_STATE  pState,
    _Out_writes_( 32 )          PBYTE                               pbCommitScalar,
    _Out_writes_( 64 )          PBYTE                               pbCommitElement )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PSYMCRYPT_MODELEMENT peTmp = NULL;
    PSYMCRYPT_INT piTmp = NULL;
    PSYMCRYPT_ECPOINT poPoint = NULL;
    PBYTE pbScratch = NULL;
    SIZE_T cbScratch;
    SIZE_T nDigits;

    PCSYMCRYPT_ECURVE pCurve = pState->pCurve;

    nDigits = SymCryptDigitsFromBits( 256 );
    cbScratch = max( SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ), 
                max( SYMCRYPT_SCRATCH_BYTES_FOR_SCALAR_ECURVE_OPERATIONS( pCurve ),
                     SYMCRYPT_SCRATCH_BYTES_FOR_GETSET_VALUE_ECURVE_OPERATIONS( pCurve ) ) );

    pbScratch = SymCryptCallbackAlloc( cbScratch );

    peTmp = SymCryptModElementAllocate( pCurve->GOrd );
    piTmp = SymCryptIntAllocate( SymCryptEcurveDigitsofScalarMultiplier( pCurve ) );
    poPoint = SymCryptEcpointAllocate( pCurve );

    if( peTmp == NULL || piTmp == NULL || poPoint == NULL || pbScratch == NULL )
    {
        scError = SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        goto cleanup;
    }

    SymCryptModAdd( pCurve->GOrd, pState->peRand, pState->peMask, peTmp, pbScratch, cbScratch );
    scError = SymCryptModElementGetValue( pCurve->GOrd, peTmp, pbCommitScalar, 32, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pbScratch, cbScratch );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    SymCryptModElementToInt( pCurve->GOrd, pState->peMask, piTmp, pbScratch, cbScratch );
    scError = SymCryptEcpointScalarMul( pCurve,
                                        piTmp,
                                        pState->poPWE,
                                        0,
                                        poPoint,
                                        pbScratch,
                                        cbScratch );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    // Now we have mask * PWE, but we need the negative...
    SymCryptEcpointNegate( pCurve, poPoint, (UINT32)-1, pbScratch, cbScratch );

    scError = SymCryptEcpointGetValue(  pCurve, 
                                        poPoint,                                     
                                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 
                                        SYMCRYPT_ECPOINT_FORMAT_XY, 
                                        pbCommitElement, 
                                        64,
                                        0,
                                        pbScratch,
                                        cbScratch );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

cleanup:

    if( piTmp != NULL )
    {
        SymCryptIntFree( piTmp );
        piTmp = NULL;
    }

    if( peTmp != NULL )
    {
        SymCryptModElementFree( pCurve->GOrd, peTmp );
        peTmp = NULL;
    }

    if( poPoint != NULL )
    {
        SymCryptEcpointFree( pCurve, poPoint );
        poPoint = NULL;
    }

    if( pbScratch != NULL )
    {
        SymCryptWipe( pbScratch, cbScratch );
        SymCryptCallbackFree( pbScratch );
        pbScratch = NULL;
    }

    return scError;
}

SYMCRYPT_ERROR
SymCrypt802_11SaeCustomCommitProcess(
    _In_                        PCSYMCRYPT_802_11_SAE_CUSTOM_STATE  pState,
    _In_reads_( 32 )            PCBYTE                              pbPeerCommitScalar,
    _In_reads_( 64 )            PCBYTE                              pbPeerCommitElement,
    _Out_writes_( 32 )          PBYTE                               pbSharedSecret,
    _Out_writes_( 32 )          PBYTE                               pbScalarSum )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    PSYMCRYPT_ECURVE pCurve = pState->pCurve;
    PSYMCRYPT_MODELEMENT    peCommitScalarSum = NULL;
    PSYMCRYPT_ECPOINT       poPeerCommitElement = NULL;
    PSYMCRYPT_ECPOINT       poTmp = NULL;
    PSYMCRYPT_INT           piTmp = NULL;
    UINT32                  nDigits;

    PBYTE pbScratch = NULL;
    SIZE_T cbScratch;

    nDigits = SymCryptDigitsFromBits( 256 );
    cbScratch = max( SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ), 
                max( SYMCRYPT_SCRATCH_BYTES_FOR_SCALAR_ECURVE_OPERATIONS( pCurve ),
                max( SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_ECURVE_OPERATIONS( pCurve ), 
                     SYMCRYPT_SCRATCH_BYTES_FOR_GETSET_VALUE_ECURVE_OPERATIONS( pCurve ) ) ) );
    pbScratch = SymCryptCallbackAlloc( cbScratch );

    peCommitScalarSum = SymCryptModElementAllocate( pCurve->GOrd );
    poPeerCommitElement = SymCryptEcpointAllocate( pCurve );
    poTmp = SymCryptEcpointAllocate( pCurve );
    piTmp = SymCryptIntAllocate( SymCryptEcurveDigitsofScalarMultiplier( pCurve ) );

    if( pbScratch == NULL || peCommitScalarSum == NULL || poPeerCommitElement == NULL || poTmp == NULL || piTmp == NULL )
    {
        scError = SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        goto cleanup;
    }

    // piTmp = peer commit value
    scError = SymCryptIntSetValue( pbPeerCommitScalar, 32, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piTmp );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    // The Standard requires a check that the Peer commit value must be 1 < peer-commit < r where r is the group order.
    if( !SymCryptIntIsLessThan( piTmp, SymCryptIntFromModulus( pCurve->GOrd ) ) ||
        SymCryptIntIsEqualUint32( piTmp, 0 ) ||
        SymCryptIntIsEqualUint32( piTmp, 1 ) )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    SymCryptIntToModElement( piTmp, pCurve->GOrd, peCommitScalarSum, pbScratch, cbScratch );

    // Now compute the sum of the scalar commit values
    SymCryptModAdd( pCurve->GOrd, peCommitScalarSum, pState->peRand, peCommitScalarSum, pbScratch, cbScratch );
    SymCryptModAdd( pCurve->GOrd, peCommitScalarSum, pState->peMask, peCommitScalarSum, pbScratch, cbScratch );

    scError = SymCryptEcpointSetValue(  pCurve, 
                                        pbPeerCommitElement, 
                                        64, 
                                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 
                                        SYMCRYPT_ECPOINT_FORMAT_XY, 
                                        poPeerCommitElement,
                                        0,
                                        pbScratch,
                                        cbScratch );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    // The EcPointSetValue routine returns an error if either coordinate is >= P.
    // We need to check that the point is on the curve and not the zero point of the curve
    // (The zero point is sometimes called the 'point at infinity'.)

    if( !SymCryptEcpointOnCurve( pCurve, poPeerCommitElement, pbScratch, cbScratch ) ||
        SymCryptEcpointIsZero( pCurve, poPeerCommitElement, pbScratch, cbScratch ) )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }


    scError = SymCryptEcpointScalarMul( pCurve,
                                        piTmp,
                                        pState->poPWE,
                                        0,
                                        poTmp,
                                        pbScratch,
                                        cbScratch );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    SymCryptEcpointAdd( pCurve, poTmp, poPeerCommitElement, poTmp, 0, pbScratch, cbScratch );

    SymCryptModElementToInt( pCurve->GOrd, pState->peRand, piTmp, pbScratch, cbScratch );
    scError = SymCryptEcpointScalarMul( pCurve,
                                        piTmp,
                                        poTmp,
                                        0,
                                        poTmp,
                                        pbScratch,
                                        cbScratch );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    scError = SymCryptEcpointGetValue(  pCurve, 
                                        poTmp, 
                                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 
                                        SYMCRYPT_ECPOINT_FORMAT_X, 
                                        pbSharedSecret, 
                                        32, 
                                        0, 
                                        pbScratch, 
                                        cbScratch );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    scError = SymCryptModElementGetValue( pCurve->GOrd, peCommitScalarSum, pbScalarSum, 32, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pbScratch, cbScratch );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

cleanup:

    if( peCommitScalarSum != NULL )
    {
        SymCryptModElementFree( pCurve->GOrd, peCommitScalarSum );
        peCommitScalarSum = NULL;
    }

    if( poPeerCommitElement != NULL )
    {
        SymCryptEcpointFree( pCurve, poPeerCommitElement );
        poPeerCommitElement = NULL;
    }

    if( poTmp != NULL )
    {
        SymCryptEcpointFree( pCurve, poTmp );
        poTmp = NULL;
    }

    if( piTmp != NULL )
    {
        SymCryptIntFree( piTmp );
        piTmp = NULL;
    }

    if( pbScratch != NULL )
    {
        SymCryptWipe( pbScratch, cbScratch );
        SymCryptCallbackFree( pbScratch );
        pbScratch = NULL;
    }

    return scError;
}
