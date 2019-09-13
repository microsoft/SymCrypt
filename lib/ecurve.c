//
// ecurve.c   Ecurve functions
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
//

#include "precomp.h"

// Approximate number of consecutive operations with the modulus and the
// (sub)group order of the curve. These numbers can trigger special optimizations
// on the underlying code, e.g. use of Montgomery multiplication or not.
#define SYMCRYPT_INTERNAL_ECURVE_MODULUS_NUMOF_OPERATIONS( _bitsize )      ( 100 * (_bitsize) )
#define SYMCRYPT_INTERNAL_ECURVE_GROUP_ORDER_NUMOF_OPERATIONS              ( 1 )

PSYMCRYPT_ECURVE
SYMCRYPT_CALL
SymCryptEcurveAllocate(
    _In_    PCSYMCRYPT_ECURVE_PARAMS    pParams,
    _In_    UINT32                      flags )
{
    BOOLEAN         fSuccess = FALSE;
    SYMCRYPT_ERROR  scError = SYMCRYPT_NO_ERROR;

    PSYMCRYPT_ECURVE pCurve = NULL;
    PBYTE            pDst = NULL;   // Destination pointer
    PBYTE            pSrc = NULL;   // Source pointer

    PBYTE            pSrcGenerator = NULL;  // We have to set the generator point
                                            // only after we have fully initialized the curve

    UINT32  cbAlloc = 0;
    UINT32  cbModulus = 0;
    UINT32  cbModElement = 0;
    UINT32  cbEcpoint = 0;
    UINT32  cbSubgroupOrder = 0;
    UINT32  cbCoFactor = 0;

    UINT32  nDigitsFieldLength = 0;
    UINT32  nDigitsSubgroupOrder = 0;
    UINT32  nDigitsCoFactor = 0;

    PSYMCRYPT_INT   pTempInt = 0;
    PBYTE           pbScratch = NULL;
    UINT32          cbScratch = 0;

    PSYMCRYPT_MODELEMENT  peTemp = NULL;

    SYMCRYPT_ECPOINT_COORDINATES     eCoordinates;

    PCSYMCRYPT_ECURVE_PARAMS_V2_EXTENSION   pcParamsV2Ext = NULL;

    UNREFERENCED_PARAMETER( flags );

    // Check that the parameters are well formatted
    SYMCRYPT_ASSERT( pParams != NULL );
    SYMCRYPT_ASSERT( (pParams->version == 1) || (pParams->version == 2) );
    SYMCRYPT_ASSERT( pParams->cbFieldLength != 0 );
    SYMCRYPT_ASSERT( pParams->cbSubgroupOrder != 0 );
    SYMCRYPT_ASSERT( pParams->cbCofactor != 0 );
    SYMCRYPT_ASSERT( (pParams->type == SYMCRYPT_ECURVE_TYPE_SHORT_WEIERSTRASS) ||
                     (pParams->type == SYMCRYPT_ECURVE_TYPE_TWISTED_EDWARDS) ||
                     (pParams->type == SYMCRYPT_ECURVE_TYPE_MONTGOMERY) );

    // Getting the # of digits of the various parameters
    nDigitsFieldLength = SymCryptDigitsFromBits( pParams->cbFieldLength * 8 );
    nDigitsSubgroupOrder = SymCryptDigitsFromBits( pParams->cbSubgroupOrder * 8 );
    nDigitsCoFactor = SymCryptDigitsFromBits( pParams->cbCofactor * 8 );

    // -----------------------------------------------
    // Getting the byte sizes of different objects
    // -----------------------------------------------
    cbModulus = SymCryptSizeofModulusFromDigits( nDigitsFieldLength );
    cbSubgroupOrder = SymCryptSizeofModulusFromDigits( nDigitsSubgroupOrder );
    cbCoFactor =  SymCryptSizeofIntFromDigits( nDigitsCoFactor );

    // ModElement: The modulus is not initialized yet, we call the macro but
    // make sure it does not create an invalid value.
    if ( pParams->cbFieldLength > SYMCRYPT_INT_MAX_BITS/8 )
    {
        SymCryptFatal( 'ecrv' );
    }
    cbModElement = SYMCRYPT_SIZEOF_MODELEMENT_FROM_BITS( pParams->cbFieldLength * 8 );

    // EcPoint: The curve is not initialized yet, we call the helper function.
    // It depends on the default format of each curve type
    switch (pParams->type)
    {
    case (SYMCRYPT_ECURVE_TYPE_SHORT_WEIERSTRASS):
        eCoordinates = SYMCRYPT_ECPOINT_COORDINATES_JACOBIAN;
        break;
    case (SYMCRYPT_ECURVE_TYPE_TWISTED_EDWARDS):
        eCoordinates = SYMCRYPT_ECPOINT_COORDINATES_EXTENDED_PROJECTIVE;
        break;
    case (SYMCRYPT_ECURVE_TYPE_MONTGOMERY):
        eCoordinates = SYMCRYPT_ECPOINT_COORDINATES_SINGLE_PROJECTIVE;
        break;
    default:
        goto cleanup;
    }

    cbEcpoint = SymCryptSizeofEcpointEx( cbModElement, SYMCRYPT_INTERNAL_NUMOF_COORDINATES( eCoordinates ) );
    // -----------------------------------------------

    // Allocating the memory for the curve
    //
    // From symcrypt_internal.h we have:
    //      - sizeof results are upper bounded by 2^19
    // Thus the following calculation does not overflow cbAlloc.
    //
    cbAlloc =   sizeof( SYMCRYPT_ECURVE ) +
                cbModulus +
                2 * cbModElement +
                cbSubgroupOrder +
                cbCoFactor;

    if ( (pParams->type == SYMCRYPT_ECURVE_TYPE_SHORT_WEIERSTRASS) ||
         (pParams->type == SYMCRYPT_ECURVE_TYPE_TWISTED_EDWARDS) )
    {
        // If the curve's type is short Weierstrass allocate space for 2^(w-2) ECPOINTs
        // at the end of the curve's structure, where w is the width of the window.
        //
        // Note: The window width is fixed now. In later versions we can pass it in as a parameter.
        // SYMCRYPT_ASSERT( (1 << (SYMCRYPT_ECURVE_SW_DEF_WINDOW-2)) <= SYMCRYPT_ECURVE_SW_MAX_NPRECOMP_POINTS );
        cbAlloc += (1 << (SYMCRYPT_ECURVE_SW_DEF_WINDOW-2))*cbEcpoint;
    }
    else
    {
        // Otherwise just allocate space for just the distinguished point
        cbAlloc += cbEcpoint;
    }

    pCurve = SymCryptCallbackAlloc( cbAlloc );
    if ( pCurve == NULL )
    {
        goto cleanup;
    }

    // Allocating internal scratch space for this function
    // **   We have to calculate it here ourselves as the curve object does not have 
    //      any fields initialized here **
    // EcpointSetValue and SymCryptOfflinePrecomputation

    //
    // From symcrypt_internal.h we have:
    //      - sizeof results are upper bounded by 2^19
    //      - SYMCRYPT_SCRATCH_BYTES results are upper bounded by 2^27 (including RSA and ECURVE)
    //      - SymCryptSizeofEcpointEx is bounded by 2^20
    // Thus the following calculation does not overflow cbScratch.
    //
    cbScratch = SymCryptSizeofEcpointEx( cbModElement, SYMCRYPT_ECPOINT_FORMAT_MAX_LENGTH ) +
                8 * cbModElement +
                max( SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigitsFieldLength ),
                     SYMCRYPT_SCRATCH_BYTES_FOR_MODINV( nDigitsFieldLength ) );
    // IntToModulus( FMod and GOrd )
    cbScratch = max( cbScratch,
                     SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_MODULUS( max(nDigitsFieldLength, nDigitsSubgroupOrder) ) );
    // ModElementSetValue( FMod )
    cbScratch = max( cbScratch,
                     SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigitsFieldLength ) );

    pbScratch = SymCryptCallbackAlloc( cbScratch );
    if ( pbScratch == NULL )
    {
        goto cleanup;
    }

    // -----------------------------------------------
    // Populating the fields of the curve object
    // -----------------------------------------------

    // Version of curve structure
    pCurve->version = SYMCRYPT_INTERNAL_ECURVE_VERSION_LATEST;

    // Type of curve
    pCurve->type = pParams->type;

    // Curve point format
    pCurve->eCoordinates = eCoordinates;

    // Number of digits of the field modulus
    pCurve->FModDigits = nDigitsFieldLength;

    // Number of digits of the group order
    pCurve->GOrdDigits = nDigitsSubgroupOrder;

    // Byte size of field elements
    pCurve->FModBytesize = (UINT32)pParams->cbFieldLength;

    // Byte size of group elements
    SYMCRYPT_ASSERT( pParams->cbSubgroupOrder < UINT32_MAX );
    pCurve->GOrdBytesize = (UINT32)pParams->cbSubgroupOrder;

    // Byte size of mod elements
    pCurve->cbModElement = cbModElement;

    // Total bytesize of the curve (used to free the curve object)
    pCurve->cbAlloc = cbAlloc;

    // Set destination and source pointers
    pDst = ((PBYTE) pCurve) + sizeof( SYMCRYPT_ECURVE );
    pSrc = ((PBYTE) pParams) + sizeof( SYMCRYPT_ECURVE_PARAMS );

    // Field Modulus
    pCurve->FMod = SymCryptModulusCreate( pDst, cbModulus, nDigitsFieldLength );
    if ( pCurve->FMod == NULL )
    {
        goto cleanup;
    }

    pTempInt = SymCryptIntFromModulus( pCurve->FMod );
    if ( pTempInt == NULL)
    {
        goto cleanup;
    }

    scError = SymCryptIntSetValue( pSrc, pParams->cbFieldLength, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pTempInt );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    // Field Modulus Bitsize
    pCurve->FModBitsize = SymCryptIntBitsizeOfValue( pTempInt );
    if (pCurve->FModBitsize < SYMCRYPT_ECURVE_MIN_BITSIZE_FMOD)
    {
        scError = SYMCRYPT_WRONG_KEY_SIZE;
        goto cleanup;
    }

    if( (SymCryptIntGetValueLsbits32( pTempInt ) & 1) == 0 )
    {
        // 'prime' must be odd to avoid fatal errors
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    // IntToModulus requirement:
    //      FModBitsize >= SYMCRYPT_ECURVE_MIN_BITSIZE_FMOD --> pTempInt > 0
    SymCryptIntToModulus(
                    pTempInt,
                    pCurve->FMod,
                    SYMCRYPT_INTERNAL_ECURVE_MODULUS_NUMOF_OPERATIONS( 8 * pParams->cbFieldLength ),
                    SYMCRYPT_FLAG_DATA_PUBLIC | SYMCRYPT_FLAG_MODULUS_PRIME,
                    pbScratch,
                    cbScratch );
    
    pDst += cbModulus;
    pSrc += pParams->cbFieldLength;

    // A constant
    pCurve->A = SymCryptModElementCreate( pDst, cbModElement, pCurve->FMod );
    if ( pCurve->A == NULL )
    {
        goto cleanup;
    }
    scError = SymCryptModElementSetValue(
                    pSrc,
                    pParams->cbFieldLength,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    pCurve->FMod,
                    pCurve->A,
                    pbScratch,
                    cbScratch );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }
    pDst += cbModElement;
    pSrc += pParams->cbFieldLength;

    // B constant
    pCurve->B = SymCryptModElementCreate( pDst, cbModElement, pCurve->FMod );
    if ( pCurve->B == NULL )
    {
        goto cleanup;
    }
    scError = SymCryptModElementSetValue(
                    pSrc,
                    pParams->cbFieldLength,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    pCurve->FMod,
                    pCurve->B,
                    pbScratch,
                    cbScratch );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }
    pDst += cbModElement;
    pSrc += pParams->cbFieldLength;
    
    // Skip over the distinguished point until we fix all the parameters and scratch space sizes
    pSrcGenerator = pSrc;
    pSrc += pParams->cbFieldLength * 2;

    // Subgroup Order
    pCurve->GOrd = SymCryptModulusCreate( pDst, cbSubgroupOrder, nDigitsSubgroupOrder );
    if ( pCurve->GOrd == NULL )
    {
        goto cleanup;
    }

    pTempInt = SymCryptIntFromModulus( pCurve->GOrd);
    if ( pTempInt == NULL)
    {
        goto cleanup;
    }

    scError = SymCryptIntSetValue( pSrc, pParams->cbSubgroupOrder, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pTempInt );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    // Subgroup Order Bitsize
    pCurve->GOrdBitsize = SymCryptIntBitsizeOfValue( pTempInt );
    if (pCurve->GOrdBitsize < SYMCRYPT_ECURVE_MIN_BITSIZE_GORD)
    {
        scError = SYMCRYPT_WRONG_KEY_SIZE;
        goto cleanup;
    }

    if( (SymCryptIntGetValueLsbits32( pTempInt ) & 1) == 0 )
    {
        // 'Prime' must be odd to avoid fatal errors
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    // IntToModulus requirement:
    //      GOrdBitsize >= SYMCRYPT_ECURVE_MIN_BITSIZE_GORD --> pTempInt > 0
    SymCryptIntToModulus(
            pTempInt,
            pCurve->GOrd,
            SYMCRYPT_INTERNAL_ECURVE_GROUP_ORDER_NUMOF_OPERATIONS,
            SYMCRYPT_FLAG_DATA_PUBLIC | SYMCRYPT_FLAG_MODULUS_PRIME,
            pbScratch,
            cbScratch );

    pDst += cbSubgroupOrder;
    pSrc += pParams->cbSubgroupOrder;

    // Cofactor
    pCurve->H = SymCryptIntCreate( pDst, cbCoFactor, nDigitsCoFactor );
    if ( pCurve->H == NULL )
    {
        goto cleanup;
    }
    scError = SymCryptIntSetValue(
                    pSrc,
                    pParams->cbCofactor,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    pCurve->H );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }


    // Make sure that the cofactor is not too big
    pCurve->coFactorPower = SymCryptIntBitsizeOfValue( pCurve->H ) - 1;
    if (pCurve->coFactorPower > SYMCRYPT_ECURVE_MAX_COFACTOR_POWER)
    {
        scError = SYMCRYPT_WRONG_KEY_SIZE;
        goto cleanup;
    }

    // Validate that the cofactor is a power of two
    if (!SymCryptIntIsEqualUint32( pCurve->H, 1<<(pCurve->coFactorPower) ))
    {
        goto cleanup;
    }

    pDst += cbCoFactor;
    pSrc += pParams->cbCofactor;

    // Calculate scratch spaces' sizes
    if (pParams->type == SYMCRYPT_ECURVE_TYPE_SHORT_WEIERSTRASS)
    {
        pCurve->info.sw.window = SYMCRYPT_ECURVE_SW_DEF_WINDOW;
        pCurve->info.sw.nPrecompPoints = (1 << (SYMCRYPT_ECURVE_SW_DEF_WINDOW-2));
        pCurve->info.sw.nRecodedDigits = pCurve->GOrdBitsize + 1;               // This is the maximum - used by the wNAF Interleaving method

        SymCryptShortWeierstrassFillScratchSpaces( pCurve );
    }
    else if ( pParams->type == SYMCRYPT_ECURVE_TYPE_TWISTED_EDWARDS )
    {
        pCurve->info.sw.window = SYMCRYPT_ECURVE_SW_DEF_WINDOW;
        pCurve->info.sw.nPrecompPoints = (1 << (SYMCRYPT_ECURVE_SW_DEF_WINDOW-2));
        pCurve->info.sw.nRecodedDigits = pCurve->GOrdBitsize + 1;               // This is the maximum - used by the wNAF Interleaving method

        SymCryptTwistedEdwardsFillScratchSpaces( pCurve );
    }
    else if ( pParams->type == SYMCRYPT_ECURVE_TYPE_MONTGOMERY )
    {
        SymCryptMontgomeryFillScratchSpaces( pCurve );
    }

    // Now set the distinguished point
    pCurve->G = SymCryptEcpointCreate( pDst, cbEcpoint, pCurve );
    if ( pCurve->G == NULL )
    {
        goto cleanup;
    }
    scError = SymCryptEcpointSetValue(
                    pCurve,
                    pSrcGenerator,
                    pParams->cbFieldLength * 2,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    SYMCRYPT_ECPOINT_FORMAT_XY,
                    pCurve->G,
                    SYMCRYPT_FLAG_DATA_PUBLIC,
                    pbScratch,
                    cbScratch );
    if ( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }
    pDst += cbEcpoint;

    // Fill the precomputed table
    if ( (pParams->type == SYMCRYPT_ECURVE_TYPE_SHORT_WEIERSTRASS) ||
         (pParams->type == SYMCRYPT_ECURVE_TYPE_TWISTED_EDWARDS) )
    {
        // The first point of the table is the generator
        pCurve->info.sw.poPrecompPoints[0] = pCurve->G;

        for (UINT32 i=1; i<pCurve->info.sw.nPrecompPoints; i++)
        {
            pCurve->info.sw.poPrecompPoints[i] = SymCryptEcpointCreate( pDst, cbEcpoint, pCurve );
            if ( pCurve->info.sw.poPrecompPoints[i] == NULL )
            {
                goto cleanup;
            }
            pDst += cbEcpoint;
        }

        SymCryptOfflinePrecomputation( pCurve, pbScratch, cbScratch );
    }

    // For Montgomery curve, we calculate A = (A + 2) / 4
    if (pParams->type == SYMCRYPT_ECURVE_TYPE_MONTGOMERY)
    {
        peTemp = SymCryptModElementCreate( pbScratch, cbModElement, pCurve->FMod );

        // SetValueUint32 requirements:
        //  FMod > 2 since it has more than SYMCRYPT_ECURVE_MIN_BITSIZE_FMOD bits
        SymCryptModElementSetValueUint32( 2, pCurve->FMod, peTemp, pbScratch + cbModElement, cbScratch - cbModElement );
        SymCryptModAdd (pCurve->FMod, pCurve->A, peTemp, pCurve->A, pbScratch + cbModElement, cbScratch - cbModElement );   // A = A + 2;
        SymCryptModDivPow2( pCurve->FMod, pCurve->A, 2, pCurve->A, pbScratch + cbModElement, cbScratch - cbModElement );    // A = (A + 2) / 4
    }

    // Set the default curve policy for parameters of version 2
    if (pParams->version == 2)
    {
        // Skip over the seed (if any)
        pSrc += pParams->cbSeed;

        // Copy the extension info (it can be unaligned)
        pcParamsV2Ext = (PCSYMCRYPT_ECURVE_PARAMS_V2_EXTENSION) pSrc;
    }
    else
    {
        // Set the defaults for version 1
        if (pParams->type == SYMCRYPT_ECURVE_TYPE_SHORT_WEIERSTRASS)
        {
            pcParamsV2Ext = SymCryptEcurveParamsV2ExtensionShortWeierstrass;
        }
        else if ( pParams->type == SYMCRYPT_ECURVE_TYPE_TWISTED_EDWARDS )
        {
            pcParamsV2Ext = SymCryptEcurveParamsV2ExtensionTwistedEdwards;
        }
        else if ( pParams->type == SYMCRYPT_ECURVE_TYPE_MONTGOMERY )
        {
            pcParamsV2Ext = SymCryptEcurveParamsV2ExtensionMontgomery;
        }
    }

    pCurve->PrivateKeyDefaultFormat = pcParamsV2Ext->PrivateKeyDefaultFormat;
    pCurve->HighBitRestrictionNumOfBits = pcParamsV2Ext->HighBitRestrictionNumOfBits;
    pCurve->HighBitRestrictionPosition = pcParamsV2Ext->HighBitRestrictionPosition;
    pCurve->HighBitRestrictionValue = pcParamsV2Ext->HighBitRestrictionValue;

    // Make sure that the HigBitRestrictions make sense
    // (see SymCryptIntGet/SetBits)
    if ( (pCurve->HighBitRestrictionNumOfBits>32) ||
         ((pCurve->HighBitRestrictionNumOfBits>0) &&
          (pCurve->HighBitRestrictionPosition + pCurve->HighBitRestrictionNumOfBits > pCurve->GOrdBitsize + pCurve->coFactorPower)) )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    // Setting the magic
    SYMCRYPT_SET_MAGIC( pCurve );

    fSuccess = TRUE;

cleanup:
    if ( pbScratch != NULL )
    {
        SymCryptWipe( pbScratch, cbScratch );
        SymCryptCallbackFree( pbScratch );
    }

    if ((!fSuccess) && (pCurve != NULL))
    {
        SymCryptWipe( (PBYTE) pCurve, cbAlloc );
        SymCryptCallbackFree( pCurve );
        pCurve = NULL;
    }

    return pCurve;
}

VOID
SYMCRYPT_CALL
SymCryptEcurveFree( _Out_ PSYMCRYPT_ECURVE pCurve )
{
    SYMCRYPT_CHECK_MAGIC( pCurve );

    SymCryptWipe( (PBYTE) pCurve, pCurve->cbAlloc );

    SymCryptCallbackFree( pCurve );
}

UINT32
SYMCRYPT_CALL
SymCryptEcurveBitsizeofFieldModulus( _In_ PCSYMCRYPT_ECURVE pCurve )
{
    return pCurve->FModBitsize;
}

UINT32
SYMCRYPT_CALL
SymCryptEcurveBitsizeofGroupOrder( _In_ PCSYMCRYPT_ECURVE pCurve )
{
    return pCurve->GOrdBitsize;
}

UINT32
SYMCRYPT_CALL
SymCryptEcurveDigitsofFieldElement( _In_ PCSYMCRYPT_ECURVE pCurve )
{
    return pCurve->FModDigits;
}

UINT32
SYMCRYPT_CALL
SymCryptEcurveSizeofFieldElement( _In_ PCSYMCRYPT_ECURVE pCurve )
{
    return pCurve->FModBytesize;
}

UINT32
SYMCRYPT_CALL
SymCryptEcurveSizeofScalarMultiplier( _In_ PCSYMCRYPT_ECURVE pCurve )
{
    return pCurve->GOrdBytesize;
}

PCSYMCRYPT_MODULUS
SYMCRYPT_CALL
SymCryptEcurveGroupOrder( _In_    PCSYMCRYPT_ECURVE   pCurve )
{
    return pCurve->GOrd;
}

UINT32
SYMCRYPT_CALL
SymCryptEcurveDigitsofScalarMultiplier( _In_    PCSYMCRYPT_ECURVE   pCurve )
{
    return SymCryptDigitsFromBits( pCurve->GOrdBitsize + pCurve->coFactorPower );
}

UINT32
SYMCRYPT_CALL
SymCryptEcurvePrivateKeyDefaultFormat( _In_ PCSYMCRYPT_ECURVE pCurve )
{
    return pCurve->PrivateKeyDefaultFormat;
}

UINT32
SYMCRYPT_CALL
SymCryptEcurveHighBitRestrictionNumOfBits( _In_ PCSYMCRYPT_ECURVE pCurve )
{
    return pCurve->HighBitRestrictionNumOfBits;
}

UINT32
SYMCRYPT_CALL
SymCryptEcurveHighBitRestrictionPosition( _In_ PCSYMCRYPT_ECURVE pCurve )
{
    return pCurve->HighBitRestrictionPosition;
}

UINT32
SYMCRYPT_CALL
SymCryptEcurveHighBitRestrictionValue( _In_ PCSYMCRYPT_ECURVE pCurve )
{
    return pCurve->HighBitRestrictionValue;
}

BOOLEAN
SYMCRYPT_CALL
SymCryptEcurveIsSame(
    _In_    PCSYMCRYPT_ECURVE  pCurve1,
    _In_    PCSYMCRYPT_ECURVE  pCurve2)
{
    BOOLEAN fIsSameCurve = FALSE;

    if ( pCurve1 == pCurve2 )
    {
        fIsSameCurve = TRUE;
        goto cleanup;
    }

    if ( !SymCryptIntIsEqual (
              SymCryptIntFromModulus( pCurve1->FMod ),
              SymCryptIntFromModulus( pCurve2->FMod ) ) ||
         !SymCryptModElementIsEqual ( pCurve1->FMod, pCurve1->A, pCurve2->A ) ||
         !SymCryptModElementIsEqual ( pCurve1->FMod, pCurve1->B, pCurve2->B ))
    {
        goto cleanup;
    }

    fIsSameCurve = TRUE;

cleanup:
    return fIsSameCurve;
}