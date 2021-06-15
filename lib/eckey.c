//
// eckey.c   Functions for the ECKEY object
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
//

#include "precomp.h"

PSYMCRYPT_ECKEY
SYMCRYPT_CALL
SymCryptEckeyAllocate( _In_ PCSYMCRYPT_ECURVE pCurve )
{
    PVOID               p;
    SIZE_T              cb;
    PSYMCRYPT_ECKEY     res = NULL;

    cb = SymCryptSizeofEckeyFromCurve( pCurve );

    p = SymCryptCallbackAlloc( cb );

    if ( p==NULL )
    {
        goto cleanup;
    }

    res = SymCryptEckeyCreate( p, cb, pCurve );

cleanup:
    return res;
}

VOID
SYMCRYPT_CALL
SymCryptEckeyFree( _Out_ PSYMCRYPT_ECKEY pkObj )
{
    SYMCRYPT_CHECK_MAGIC( pkObj );
    SymCryptEckeyWipe( pkObj );
    SymCryptCallbackFree( pkObj );
}

UINT32
SYMCRYPT_CALL
SymCryptSizeofEckeyFromCurve( _In_ PCSYMCRYPT_ECURVE pCurve )
{
    //
    // From symcrypt_internal.h we have:
    //      - sizeof results are upper bounded by 2^19
    //      - SYMCRYPT_SCRATCH_BYTES results are upper bounded by 2^27 (including RSA and ECURVE)
    //      - SymCryptSizeofEcpointFromCurve outputs the size of up to 4 modelements + some overhead
    // Thus the following calculation does not overflow the result.
    //
    return sizeof(SYMCRYPT_ECKEY) + SymCryptSizeofEcpointFromCurve( pCurve ) + SymCryptSizeofIntFromDigits(SymCryptEcurveDigitsofScalarMultiplier(pCurve));
}

PSYMCRYPT_ECKEY
SYMCRYPT_CALL
SymCryptEckeyCreate(
    _Out_writes_bytes_( cbBuffer )  PBYTE               pbBuffer,
                                    SIZE_T              cbBuffer,
                                    PCSYMCRYPT_ECURVE   pCurve )
{
    PSYMCRYPT_ECKEY         pkObj = NULL;
    UINT32 privateKeyDigits = SymCryptEcurveDigitsofScalarMultiplier(pCurve);

    UNREFERENCED_PARAMETER( cbBuffer );     // only referenced in an ASSERT...

    SYMCRYPT_ASSERT( pCurve != NULL );
    SYMCRYPT_ASSERT( cbBuffer >=  SymCryptSizeofEckeyFromCurve( pCurve ) );

    SYMCRYPT_ASSERT_ASYM_ALIGNED( pbBuffer );

    pkObj = (PSYMCRYPT_ECKEY) pbBuffer;

    pkObj->hasPrivateKey = FALSE;
    pkObj->pCurve = pCurve;

    pkObj->poPublicKey = SymCryptEcpointCreate(
                        pbBuffer + sizeof(SYMCRYPT_ECKEY),
                        SymCryptSizeofEcpointFromCurve( pCurve ),
                        pCurve );
    SYMCRYPT_ASSERT( pkObj->poPublicKey != NULL );

    pkObj->piPrivateKey = SymCryptIntCreate(
                        pbBuffer + sizeof(SYMCRYPT_ECKEY) + SymCryptSizeofEcpointFromCurve( pCurve ),
                        SymCryptSizeofIntFromDigits( privateKeyDigits ),
                        privateKeyDigits );
    SYMCRYPT_ASSERT( pkObj->piPrivateKey );

    // Setting the magic
    SYMCRYPT_SET_MAGIC( pkObj );

    return pkObj;
}

VOID
SYMCRYPT_CALL
SymCryptEckeyWipe( _Out_ PSYMCRYPT_ECKEY pkDst )
{
    // Wipe the whole structure in one go.
    SymCryptWipe( pkDst, SymCryptSizeofEckeyFromCurve( pkDst->pCurve ) );
}

VOID
SymCryptEckeyCopy(
    _In_    PCSYMCRYPT_ECKEY  pkSrc,
    _Out_   PSYMCRYPT_ECKEY   pkDst )
{
    //
    // in-place copy is somewhat common...
    //
    if( pkSrc != pkDst )
    {
        // Copy the hasPrivateKey flag
        pkDst->hasPrivateKey = pkSrc->hasPrivateKey;

        // Copy the public key
        SymCryptEcpointCopy( pkSrc->pCurve, pkSrc->poPublicKey, pkDst->poPublicKey );

        // Copy the private key
        SymCryptIntCopy( pkSrc->piPrivateKey, pkDst->piPrivateKey );
    }
}

UINT32
SYMCRYPT_CALL
SymCryptEckeySizeofPublicKey(
    _In_ PCSYMCRYPT_ECKEY           pkEckey,
    _In_ SYMCRYPT_ECPOINT_FORMAT    ecPointFormat )
{
    //
    // From symcrypt_internal.h we have:
    //      - sizeof results are upper bounded by 2^19
    //      - SYMCRYPT_SCRATCH_BYTES results are upper bounded by 2^27 (including RSA and ECURVE)
    //      - SymCryptEcpointFormatNumberofElements returns up to 4 elements.
    //
    // Thus the following calculation does not overflow cbScratch.
    //
    return SymCryptEcpointFormatNumberofElements[ecPointFormat] * SymCryptEcurveSizeofFieldElement( pkEckey->pCurve );
}

UINT32
SYMCRYPT_CALL
SymCryptEckeySizeofPrivateKey( _In_ PCSYMCRYPT_ECKEY pkEckey )
{
    return SymCryptEcurveSizeofScalarMultiplier( pkEckey->pCurve );
}

BOOLEAN
SYMCRYPT_CALL
SymCryptEckeyHasPrivateKey( _In_ PCSYMCRYPT_ECKEY pkEckey )
{
    return pkEckey->hasPrivateKey;
}

_Success_(return == SYMCRYPT_NO_ERROR)
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptEckeyPerformPublicKeyValidation(
    _In_                            PCSYMCRYPT_ECKEY        pEckey,
    _In_                            UINT32                  flags,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    PCSYMCRYPT_ECURVE   pCurve = pEckey->pCurve;

    PSYMCRYPT_ECPOINT   poNPub = NULL;
    UINT32              cbNPub = 0;

    // This is an excessive amount of space to require, but all callers can currently provide it, and it's easy to phrase
    SYMCRYPT_ASSERT( cbScratch >= SYMCRYPT_INTERNAL_SCRATCH_BYTES_FOR_ECKEY_ECURVE_OPERATIONS( pCurve ) );

    // Check if Public key is O
    if ( SymCryptEcpointIsZero( pCurve, pEckey->poPublicKey, pbScratch, cbScratch ) )
    {
        return SYMCRYPT_INVALID_ARGUMENT;
    }

    // Public key is represented by Modelements of the underlying finite field for the curve
    // If we have reached this point we have either:
    // Constructed the Public key to have coordinates in the field (Generate case), or
    // Verified the Public key has coordinates in the field (SetValue case)

    // Check that Public key is on the curve
    // Skip check for Montgomery curves as we do not have an EcpointOnCurve function for them
    if ( pCurve->type != SYMCRYPT_ECURVE_TYPE_MONTGOMERY &&
        !SymCryptEcpointOnCurve( pCurve, pEckey->poPublicKey, pbScratch, cbScratch ) )
    {
        return SYMCRYPT_INVALID_ARGUMENT;
    }

    // Perform validation that Public key is in a subgroup of order GOrd.
    if ( (flags & SYMCRYPT_FLAG_KEY_VALIDATION_MASK) == SYMCRYPT_FLAG_KEY_RANGE_AND_PUBLIC_KEY_ORDER_VALIDATION )
    {
        if ( SymCryptIntIsEqualUint32( pCurve->H, 1 ) )
        {
            // If cofactor is 1 then to validate that Public key has order GOrd
            // it is sufficient to validate Public key is on the curve
            // We just performed this check - so we are done.
        }
        else
        {
            // Ensure GOrd*(Public key) == O
            cbNPub = SymCryptSizeofEcpointFromCurve( pCurve );
            poNPub = SymCryptEcpointCreate( pbScratch, cbNPub, pCurve );
            pbScratch += cbNPub;
            cbScratch -= cbNPub;

            SYMCRYPT_ASSERT( poNPub != NULL );

            // Do the multiplication
            scError = SymCryptEcpointScalarMul(
                pCurve,
                SymCryptIntFromModulus( pCurve->GOrd ),
                pEckey->poPublicKey,
                0, // Do not multiply by cofactor!
                poNPub,
                pbScratch,
                cbScratch );
            if ( scError != SYMCRYPT_NO_ERROR )
            {
                return scError;
            }

            if ( !SymCryptEcpointIsZero( pCurve, poNPub, pbScratch, cbScratch ) )
            {
                return SYMCRYPT_INVALID_ARGUMENT;
            }
        }
    }

    return SYMCRYPT_NO_ERROR;
}

_Success_(return == SYMCRYPT_NO_ERROR)
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptEckeySetValue(
    _In_reads_bytes_( cbPrivateKey )
            PCBYTE                  pbPrivateKey,
            SIZE_T                  cbPrivateKey,
    _In_reads_bytes_( cbPublicKey )
            PCBYTE                  pbPublicKey,
            SIZE_T                  cbPublicKey,
            SYMCRYPT_NUMBER_FORMAT  numFormat,
            SYMCRYPT_ECPOINT_FORMAT ecPointFormat,
            UINT32                  flags,
    _Inout_ PSYMCRYPT_ECKEY         pEckey )
{
    SYMCRYPT_ERROR      scError = SYMCRYPT_NO_ERROR;
    PBYTE               pbScratch = NULL;
    UINT32              cbScratch = 0;
    PBYTE               pbScratchInternal = NULL;
    UINT32              cbScratchInternal = 0;

    PCSYMCRYPT_ECURVE   pCurve = pEckey->pCurve;

    PSYMCRYPT_ECPOINT   poTmp = NULL;
    UINT32              cbTmp = 0;

    PSYMCRYPT_INT           piTmpInteger = NULL;
    UINT32                  cbTmpInteger = 0;
    PSYMCRYPT_MODELEMENT    peTmpModElement = NULL;
    UINT32                  cbTmpModElement = pCurve->cbModElement;

    UINT32 privateKeyDigits = SymCryptEcurveDigitsofScalarMultiplier(pCurve);

    BOOLEAN performRangeValidation = FALSE;

	// dcl - again, we require the results of these functions below, so why not check them in release?
    SYMCRYPT_ASSERT( (cbPrivateKey==0) || (cbPrivateKey == SymCryptEcurveSizeofScalarMultiplier( pEckey->pCurve )) );
    SYMCRYPT_ASSERT( (cbPublicKey==0) || (cbPublicKey == SymCryptEckeySizeofPublicKey( pEckey, ecPointFormat)) );

    // Ensure only the correct flags are specified
    // Check if a flag with bits outside of the expected flags is specified
    // All bit combinations using the expected flags are valid, so no more flag validation required
    if ( ( flags & ~(   SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION |
                        SYMCRYPT_FLAG_KEY_RANGE_VALIDATION |
                        SYMCRYPT_FLAG_KEY_RANGE_AND_PUBLIC_KEY_ORDER_VALIDATION |
                        SYMCRYPT_FLAG_KEY_KEYPAIR_REGENERATION_VALIDATION ) ) != 0 )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    performRangeValidation = ((flags & SYMCRYPT_FLAG_KEY_VALIDATION_MASK) == SYMCRYPT_FLAG_KEY_RANGE_VALIDATION) ||
            ((flags & SYMCRYPT_FLAG_KEY_VALIDATION_MASK) == SYMCRYPT_FLAG_KEY_RANGE_AND_PUBLIC_KEY_ORDER_VALIDATION);

    if ( ( ( cbPrivateKey == 0 ) && ( cbPublicKey == 0 ) ) ||
         ( ( cbPrivateKey != 0 ) && ( cbPrivateKey != SymCryptEcurveSizeofScalarMultiplier( pEckey->pCurve ) ) ) ||
         ( ( cbPublicKey != 0 )  && ( cbPublicKey != SymCryptEckeySizeofPublicKey( pEckey, ecPointFormat ) ) ) )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    // Allocate scratch space
    cbScratch = SYMCRYPT_INTERNAL_SCRATCH_BYTES_FOR_ECKEY_ECURVE_OPERATIONS( pCurve );
    pbScratch = SymCryptCallbackAlloc( cbScratch );
    if ( pbScratch == NULL )
    {
        scError = SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        goto cleanup;
    }

    if ( pbPrivateKey != NULL )
    {
        //
        // Private key calculations
        //

        pbScratchInternal = pbScratch;
        cbScratchInternal = cbScratch;

        // Allocate the integer
        cbTmpInteger = SymCryptSizeofIntFromDigits( privateKeyDigits );
        piTmpInteger = SymCryptIntCreate( pbScratchInternal, cbTmpInteger, privateKeyDigits );
        SYMCRYPT_ASSERT( piTmpInteger != NULL );

        pbScratchInternal += cbTmpInteger;
        cbScratchInternal -= cbTmpInteger;

        // Allocate the modelement
        peTmpModElement = SymCryptModElementCreate( pbScratchInternal, cbTmpModElement, pCurve->GOrd );
        SYMCRYPT_ASSERT( peTmpModElement != NULL );

        pbScratchInternal += cbTmpModElement;
        cbScratchInternal -= cbTmpModElement;

        // Get the "raw" private key
        scError = SymCryptIntSetValue( pbPrivateKey, cbPrivateKey, numFormat, piTmpInteger );
        if (scError != SYMCRYPT_NO_ERROR)
        {
            goto cleanup;
        }

        // Validation steps
        if ( !((flags & SYMCRYPT_FLAG_KEY_VALIDATION_MASK) == SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION) )
        {
            // Perform range validation on imported Private key if it is in canonical format
            if ( performRangeValidation &&
                (pCurve->PrivateKeyDefaultFormat == SYMCRYPT_ECKEY_PRIVATE_FORMAT_CANONICAL) )
            {
                // Check if Private key is greater than or equal to GOrd
                if ( !SymCryptIntIsLessThan( piTmpInteger, SymCryptIntFromModulus( pCurve->GOrd ) ) )
                {
                    scError = SYMCRYPT_INVALID_ARGUMENT;
                    goto cleanup;
                }
            }

            // "TimesH" formats
            // IntGetBits requirements:
            //      We know that coFactorPower is up to SYMCRYPT_ECURVE_MAX_COFACTOR_POWER. Thus
            //      less than 32 and less than the digits size in bits.
            if ( (pCurve->coFactorPower>0) &&
                (pCurve->PrivateKeyDefaultFormat == SYMCRYPT_ECKEY_PRIVATE_FORMAT_DIVH_TIMESH) &&
                (SymCryptIntGetBits( piTmpInteger, 0, pCurve->coFactorPower) != 0) )
            {
                scError = SYMCRYPT_INVALID_ARGUMENT;
                goto cleanup;
            }


            // High bit restrictions
            // IntGetBits requirements:
            //      Satisfied by asserting that
            //      HighBitRestrictionPosition + HighBitRestrictionNumOfBits <= GOrdBitsize + coFactorPower
            //      during EcurveAllocate.
            if ( (pCurve->HighBitRestrictionNumOfBits>0) &&
                (SymCryptIntGetBits(
                    piTmpInteger,
                    pCurve->HighBitRestrictionPosition,
                    pCurve->HighBitRestrictionNumOfBits) != pCurve->HighBitRestrictionValue) )
            {
                scError = SYMCRYPT_INVALID_ARGUMENT;
                goto cleanup;
            }
        }

        // Convert the private key to "DivH" format
        if (pCurve->coFactorPower>0)
        {
            // "TimesH" format: Divide the input private key with the cofactor
            // by shifting right the appropriate number of bits
            if (pCurve->PrivateKeyDefaultFormat == SYMCRYPT_ECKEY_PRIVATE_FORMAT_DIVH_TIMESH)
            {
                SymCryptIntDivPow2( piTmpInteger, pCurve->coFactorPower, piTmpInteger );
            }

            // "Canonical" format: Divide by h modulo GOrd
            if (pCurve->PrivateKeyDefaultFormat == SYMCRYPT_ECKEY_PRIVATE_FORMAT_CANONICAL)
            {
                SymCryptIntToModElement( piTmpInteger, pCurve->GOrd, peTmpModElement, pbScratchInternal, cbScratchInternal );
                SymCryptModDivPow2( pCurve->GOrd, peTmpModElement, pCurve->coFactorPower, peTmpModElement, pbScratchInternal, cbScratchInternal );
                SymCryptModElementToInt( pCurve->GOrd, peTmpModElement, piTmpInteger, pbScratchInternal, cbScratchInternal );
            }
        }

        // Divide the input private key since it could be larger than subgroup order
        SymCryptIntDivMod(
            piTmpInteger,
            SymCryptDivisorFromModulus(pCurve->GOrd),
            NULL,
            piTmpInteger,
            pbScratchInternal,
            cbScratchInternal );

        if ( !((flags & SYMCRYPT_FLAG_KEY_VALIDATION_MASK) == SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION) )
        {
            // Check if Private key is 0 after dividing it by the subgroup order
            // Other part of range validation
            if (SymCryptIntIsEqualUint32( piTmpInteger, 0 ))
            {
                scError = SYMCRYPT_INVALID_ARGUMENT;
                goto cleanup;
            }
        }

        // Copy into the ECKEY
        SymCryptIntCopy( piTmpInteger, pEckey->piPrivateKey );

        pEckey->hasPrivateKey = TRUE;
    }

    if ( pbPublicKey != NULL )
    {
        scError = SymCryptEcpointSetValue(
                            pCurve,
                            pbPublicKey,
                            cbPublicKey,
                            numFormat,
                            ecPointFormat,
                            pEckey->poPublicKey,
                            SYMCRYPT_FLAG_DATA_PUBLIC,
                            pbScratch,
                            cbScratch );
        if ( scError != SYMCRYPT_NO_ERROR )
        {
            goto cleanup;
        }

        // Perform Public key validation on imported Public key.
        if ( !((flags & SYMCRYPT_FLAG_KEY_VALIDATION_MASK) == SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION) )
        {
            scError = SymCryptEckeyPerformPublicKeyValidation(
                pEckey,
                flags,
                pbScratch,
                cbScratch );
            if ( scError != SYMCRYPT_NO_ERROR )
            {
                goto cleanup;
            }
        }
    }

    // Calculating the public key if no key was provided
    // or if needed for keypair regeneration validation
    if ( (pbPublicKey==NULL) ||
         ( ( (flags & SYMCRYPT_FLAG_KEY_KEYPAIR_REGENERATION_VALIDATION) != 0 ) &&
          (pbPrivateKey!=NULL) && (pbPublicKey!=NULL) ) )
    {
        // Calculate the public key from the private key
        pbScratchInternal = pbScratch;
        cbScratchInternal = cbScratch;

        // By default calculate the Public key directly where it will be persisted
        poTmp = pEckey->poPublicKey;

        if ( pbPublicKey != NULL )
        {
            // If doing regeneration validation calculate the Public key in scratch
            cbTmp = SymCryptSizeofEcpointFromCurve( pCurve );
            poTmp = SymCryptEcpointCreate( pbScratchInternal, cbTmp, pCurve );
            pbScratchInternal += cbTmp;
            cbScratchInternal -= cbTmp;
        }

        SYMCRYPT_ASSERT( poTmp != NULL );

        // Always multiply by the cofactor since the internal format is "DIVH"
        scError = SymCryptEcpointScalarMul(
            pCurve,
            pEckey->piPrivateKey,
            NULL,
            SYMCRYPT_FLAG_ECC_LL_COFACTOR_MUL,
            poTmp,
            pbScratchInternal,
            cbScratchInternal );
        if ( scError != SYMCRYPT_NO_ERROR )
        {
            goto cleanup;
        }

        if ( pbPublicKey != NULL )
        {
            if ( !SymCryptEcpointIsEqual( pCurve, poTmp, pEckey->poPublicKey, 0, pbScratchInternal, cbScratchInternal ) )
            {
                scError = SYMCRYPT_INVALID_ARGUMENT;
                goto cleanup;
            }
        }
        else if ( !((flags & SYMCRYPT_FLAG_KEY_VALIDATION_MASK) == SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION) )
        {
            // Perform Public key validation on generated Public key.
            scError = SymCryptEckeyPerformPublicKeyValidation(
                pEckey,
                flags,
                pbScratch,
                cbScratch );
            if ( scError != SYMCRYPT_NO_ERROR )
            {
                goto cleanup;
            }
        }
    }

cleanup:

    if ( pbScratch != NULL )
    {
        SymCryptWipe( pbScratch, cbScratch );
        SymCryptCallbackFree( pbScratch );
    }

    return scError;
}

_Success_(return == SYMCRYPT_NO_ERROR)
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptEckeyGetValue(
    _In_    PCSYMCRYPT_ECKEY        pEckey,
    _Out_writes_bytes_( cbPrivateKey )
            PBYTE                   pbPrivateKey,
            SIZE_T                  cbPrivateKey,
    _Out_writes_bytes_( cbPublicKey )
            PBYTE                   pbPublicKey,
            SIZE_T                  cbPublicKey,
            SYMCRYPT_NUMBER_FORMAT  numFormat,
            SYMCRYPT_ECPOINT_FORMAT ecPointFormat,
            UINT32                  flags )
{
    SYMCRYPT_ERROR      scError = SYMCRYPT_NO_ERROR;
    PBYTE               pbScratch = NULL;
    UINT32              cbScratch = 0;
    PBYTE               pbScratchInternal = NULL;
    UINT32              cbScratchInternal = 0;

    PCSYMCRYPT_ECURVE   pCurve = pEckey->pCurve;

    PSYMCRYPT_INT           piTmpInteger = NULL;
    UINT32                  cbTmpInteger = 0;
    PSYMCRYPT_MODELEMENT    peTmpModElement = NULL;
    UINT32                  cbTmpModElement = pCurve->cbModElement;

    UINT32 privateKeyDigits = SymCryptEcurveDigitsofScalarMultiplier(pCurve);

    SYMCRYPT_ASSERT( (cbPrivateKey==0) || (cbPrivateKey == SymCryptEcurveSizeofScalarMultiplier( pEckey->pCurve )) );
    SYMCRYPT_ASSERT( (cbPublicKey==0) || (cbPublicKey == SymCryptEckeySizeofPublicKey( pEckey, ecPointFormat)) );

    // Make sure we only specify the correct flags
    if (flags != 0)
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    // Allocate scratch space
    cbScratch = SYMCRYPT_INTERNAL_SCRATCH_BYTES_FOR_ECKEY_ECURVE_OPERATIONS( pCurve );
    pbScratch = SymCryptCallbackAlloc( cbScratch );
    if ( pbScratch == NULL )
    {
        scError = SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        goto cleanup;
    }

    pbScratchInternal = pbScratch;
    cbScratchInternal = cbScratch;

    // Allocate the integer
    cbTmpInteger = SymCryptSizeofIntFromDigits( privateKeyDigits );
    piTmpInteger = SymCryptIntCreate( pbScratchInternal, cbTmpInteger, privateKeyDigits );
    SYMCRYPT_ASSERT( piTmpInteger != NULL );

    pbScratchInternal += cbTmpInteger;
    cbScratchInternal -= cbTmpInteger;

    // Allocate the modelement
    peTmpModElement = SymCryptModElementCreate( pbScratchInternal, cbTmpModElement, pCurve->GOrd );
    SYMCRYPT_ASSERT( peTmpModElement != NULL );

    pbScratchInternal += cbTmpModElement;
    cbScratchInternal -= cbTmpModElement;

    if ((cbPrivateKey == 0) && (cbPublicKey == 0))
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    if (cbPrivateKey != 0)
    {
        if (!pEckey->hasPrivateKey)
        {
            scError = SYMCRYPT_INVALID_BLOB;
            goto cleanup;
        }

        // Copy the key into the temporary integer
        SymCryptIntCopy( pEckey->piPrivateKey, piTmpInteger );

        // Convert the "DivH" format into the external format
        if (pCurve->coFactorPower>0)
        {
            // For the "Canonical" format: Multiply the integer by h
            // and then take the result modulo GOrd
            if (pCurve->PrivateKeyDefaultFormat == SYMCRYPT_ECKEY_PRIVATE_FORMAT_CANONICAL)
            {
                SymCryptIntMulPow2( piTmpInteger, pCurve->coFactorPower, piTmpInteger );
                SymCryptIntDivMod(
                    piTmpInteger,
                    SymCryptDivisorFromModulus(pCurve->GOrd),
                    NULL,
                    piTmpInteger,
                    pbScratch,
                    cbScratchInternal );
            }

            // For the "TimesH" format: Multiply the integer by h again by shifting
            if (pCurve->PrivateKeyDefaultFormat == SYMCRYPT_ECKEY_PRIVATE_FORMAT_DIVH_TIMESH)
            {
                SymCryptIntMulPow2( piTmpInteger, pCurve->coFactorPower, piTmpInteger );
            }
        }

        scError = SymCryptIntGetValue( piTmpInteger, pbPrivateKey, cbPrivateKey, numFormat );
        if (scError != SYMCRYPT_NO_ERROR)
        {
            goto cleanup;
        }
    }

    if (cbPublicKey != 0)
    {
        scError = SymCryptEcpointGetValue(
                            pCurve,
                            pEckey->poPublicKey,
                            numFormat,
                            ecPointFormat,
                            pbPublicKey,
                            cbPublicKey,
                            SYMCRYPT_FLAG_DATA_PUBLIC,
                            pbScratch,
                            cbScratch );
    }

cleanup:

    if ( pbScratch != NULL )
    {
        SymCryptWipe( pbScratch, cbScratch );
        SymCryptCallbackFree( pbScratch );
    }

    return scError;
}

#define SYMCRYPT_ECPOINT_SET_RANDOM_MAX_TRIES   (1000)

_Success_(return == SYMCRYPT_NO_ERROR)
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptEckeySetRandom(
    _In_    UINT32                  flags,
    _Inout_ PSYMCRYPT_ECKEY         pEckey )
{
    SYMCRYPT_ERROR      scError = SYMCRYPT_NO_ERROR;
    PBYTE               pbScratch = NULL;
    UINT32              cbScratch = 0;
    PBYTE               pbScratchInternal = NULL;
    UINT32              cbScratchInternal = 0;

    PCSYMCRYPT_ECURVE   pCurve = pEckey->pCurve;

    INT32 cntr = SYMCRYPT_ECPOINT_SET_RANDOM_MAX_TRIES;

    PSYMCRYPT_MODELEMENT peScalar = NULL;
    PSYMCRYPT_INT        piScalar = NULL;
    UINT32               cbScalar = 0;

    UINT32 highBitRestrictionPosition = pCurve->HighBitRestrictionPosition;

    if( SYMCRYPT_DO_FIPS_SELFTESTS &&
        ((g_SymCryptFipsSelftestsPerformed & SYMCRYPT_SELFTEST_ECDSA) == 0) )
    {
        SymCryptEcDsaPairwiseSelftest( );

        ATOMIC_OR32( &g_SymCryptFipsSelftestsPerformed, SYMCRYPT_SELFTEST_ECDSA );
    }

    // Ensure only the correct flags are specified
    // Check if a flag with bits outside of the expected flags is specified
    // Check if a flag is specified using bits expected, but not one of the expected flags
    if ( ( ( flags & ~( SYMCRYPT_FLAG_KEY_RANGE_AND_PUBLIC_KEY_ORDER_VALIDATION ) ) != 0 ) ||
        ( flags != 0 &&
        !((flags & SYMCRYPT_FLAG_KEY_VALIDATION_MASK) == SYMCRYPT_FLAG_KEY_RANGE_AND_PUBLIC_KEY_ORDER_VALIDATION) ) )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    //
    // From symcrypt_internal.h we have:
    //      - sizeof results are upper bounded by 2^19
    //      - SYMCRYPT_SCRATCH_BYTES results are upper bounded by 2^27 (including RSA and ECURVE)
    // Thus the following calculation does not overflow cbScratch.
    //
    cbScratch = SYMCRYPT_INTERNAL_SCRATCH_BYTES_FOR_ECKEY_ECURVE_OPERATIONS( pCurve );
    pbScratch = SymCryptCallbackAlloc( cbScratch );
    if ( pbScratch == NULL )
    {
        scError = SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        goto cleanup;
    }

    // Allocating temporaries
    pbScratchInternal = pbScratch;
    cbScratchInternal = cbScratch;

    peScalar = SymCryptModElementCreate( pbScratchInternal, pCurve->cbModElement, pCurve->GOrd );
    SYMCRYPT_ASSERT( peScalar != NULL );

    pbScratchInternal += pCurve->cbModElement;
    cbScratchInternal -= pCurve->cbModElement;

    cbScalar = SymCryptSizeofIntFromDigits( SymCryptEcurveDigitsofScalarMultiplier(pCurve) );
    piScalar = SymCryptIntCreate( pbScratchInternal, cbScalar, SymCryptEcurveDigitsofScalarMultiplier(pCurve) );

    pbScratchInternal += cbScalar;
    cbScratchInternal -= cbScalar;

    // Shift the high bit position if the format is "TIMESH"
    //  Note:   Do not actually multiply the integer as we will check if it is
    //          less than the group order
    if (pCurve->PrivateKeyDefaultFormat == SYMCRYPT_ECKEY_PRIVATE_FORMAT_DIVH_TIMESH)
    {
        highBitRestrictionPosition -= pCurve->coFactorPower;
    }

    // Main loop
    do
    {
        // We perform Private key range validation by construction
        // Setting a random mod element in the [1, SubgroupOrder-1] set
        // This will be the "DivH" format of the private key. This means
        // that PublicKey = h * PrivateKey * G
        SymCryptModSetRandom(
            pCurve->GOrd,
            peScalar,
            (SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE|SYMCRYPT_FLAG_MODRANDOM_ALLOW_MINUSONE),
            pbScratchInternal,
            cbScratchInternal );

        // Converting to "canonical" format
        if (pCurve->PrivateKeyDefaultFormat == SYMCRYPT_ECKEY_PRIVATE_FORMAT_CANONICAL)
        {
            for (UINT32 i=0; i<pCurve->coFactorPower; i++)
            {
                SymCryptModAdd( pCurve->GOrd, peScalar, peScalar, peScalar, pbScratchInternal, cbScratchInternal );
            }
        }

        // Set the temporary scalar to verify the format
        SymCryptModElementToInt( pCurve->GOrd, peScalar, piScalar, pbScratchInternal, cbScratchInternal );

        if (pCurve->HighBitRestrictionNumOfBits > 0)
        {
            // Set the desired bits
            SymCryptIntSetBits(
                    piScalar,
                    pCurve->HighBitRestrictionValue,
                    highBitRestrictionPosition,
                    pCurve->HighBitRestrictionNumOfBits );

            // Make sure we didn't exceed the group order
            if ( SymCryptIntIsLessThan(
                    piScalar,
                    SymCryptIntFromModulus( pCurve->GOrd )) )
            {
                break;
            }
        }
        else
        {
            // No high bit restriction was specified
            break;
        }

        cntr--;
    }
    while (cntr>0);

    if (cntr <= 0)
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    // Here piScalar has a private key that satisfies the restriction(s)
    // Move it to the modelement
    SymCryptIntToModElement( piScalar, pCurve->GOrd, peScalar, pbScratchInternal, cbScratchInternal );

    // Convert the private key back to "DIVH" format
    if (pCurve->PrivateKeyDefaultFormat == SYMCRYPT_ECKEY_PRIVATE_FORMAT_CANONICAL)
    {
        SymCryptModDivPow2( pCurve->GOrd, peScalar, pCurve->coFactorPower, peScalar, pbScratchInternal, cbScratchInternal );
    }

    // Set the private key
    SymCryptModElementToInt( pCurve->GOrd, peScalar, pEckey->piPrivateKey, pbScratchInternal, cbScratchInternal );

    // Do the multiplication (pass over the entire scratch space as it is not needed anymore)
    scError = SymCryptEcpointScalarMul(
        pCurve,
        pEckey->piPrivateKey,
        NULL,
        SYMCRYPT_FLAG_ECC_LL_COFACTOR_MUL,
        pEckey->poPublicKey,
        pbScratch,
        cbScratch );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    // Perform range and public key order validation on generated Public key.
    if ( (flags & SYMCRYPT_FLAG_KEY_VALIDATION_MASK) == SYMCRYPT_FLAG_KEY_RANGE_AND_PUBLIC_KEY_ORDER_VALIDATION )
    {
        // Perform Public key validation.
        // Always perform range validation
        // May also perform validation that Public key is in subgroup of order GOrd, depending on flags
        scError = SymCryptEckeyPerformPublicKeyValidation(
            pEckey,
            flags,
            pbScratch,
            cbScratch );
        if ( scError != SYMCRYPT_NO_ERROR )
        {
            goto cleanup;
        }
    }

    pEckey->hasPrivateKey = TRUE;

cleanup:

    if ( pbScratch != NULL )
    {
        SymCryptWipe( pbScratch, cbScratch );
        SymCryptCallbackFree( pbScratch );
    }

    return scError;
}
