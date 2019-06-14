//
// ecpoint.c   Ecpoint functions
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
//

#include "precomp.h"

// Table with the number of field elements for each point format
const UINT32 SymCryptEcpointFormatNumberofElements[] = { 
    0,
    1,      // SYMCRYPT_ECPOINT_FORMAT_X
    2,      // SYMCRYPT_ECPOINT_FORMAT_XY
};

UINT32
SYMCRYPT_CALL
SymCryptSizeofEcpointEx(
    UINT32 cbModElement,
    UINT32 numOfCoordinates )
{
	if ( numOfCoordinates > SYMCRYPT_ECPOINT_FORMAT_MAX_LENGTH )
    {
        SymCryptFatal( 'ecp4' );
    }

    // Since the maximum number of coordinates is 4 this result is bounded
    // by 4*2^17 + ovehead ~ 2^20
    return sizeof(SYMCRYPT_ECPOINT) + numOfCoordinates * cbModElement;
}

UINT32
SYMCRYPT_CALL
SymCryptSizeofEcpointFromCurve( PCSYMCRYPT_ECURVE pCurve )
{
    // Same bound as SymCryptSizeofEcpointEx
    return SymCryptSizeofEcpointEx( pCurve->cbModElement, SYMCRYPT_INTERNAL_NUMOF_COORDINATES(pCurve->eCoordinates) );
}

PSYMCRYPT_ECPOINT
SYMCRYPT_CALL
SymCryptEcpointAllocate( _In_ PCSYMCRYPT_ECURVE pCurve )
{
    PVOID               p;
    SIZE_T              cb;
    PSYMCRYPT_ECPOINT   res = NULL;

    cb = SymCryptSizeofEcpointFromCurve( pCurve );

    p = SymCryptCallbackAlloc( cb );

    if ( p==NULL )
    {
        goto cleanup;
    }

    res = SymCryptEcpointCreate( p, cb, pCurve );

cleanup:
    return res;
}

VOID
SYMCRYPT_CALL
SymCryptEcpointFree(
     _In_ PCSYMCRYPT_ECURVE pCurve,
     _Out_ PSYMCRYPT_ECPOINT poDst )
{
    SYMCRYPT_CHECK_MAGIC( poDst );
    SymCryptEcpointWipe( pCurve, poDst );
    SymCryptCallbackFree( poDst );
}

PSYMCRYPT_ECPOINT
SYMCRYPT_CALL
SymCryptEcpointCreateEx(
    _Out_writes_bytes_( cbBuffer )  PBYTE               pbBuffer,
                                    SIZE_T              cbBuffer,
                                    PCSYMCRYPT_ECURVE   pCurve,
                                    UINT32              numOfCoordinates )
{
    PSYMCRYPT_ECPOINT       poPoint = NULL;

    PSYMCRYPT_MODELEMENT    pmTmp = NULL;
    UINT32                  cbModElement = 0;

    UNREFERENCED_PARAMETER( cbBuffer );     // only referenced in an ASSERT...

    SYMCRYPT_ASSERT( pCurve->FMod != 0 );
    SYMCRYPT_ASSERT( pCurve->cbModElement != 0 );
	// dcl - this is not an expensive call, and could be checked in release, just one mul and one add
    SYMCRYPT_ASSERT( cbBuffer >=  SymCryptSizeofEcpointEx( pCurve->cbModElement, numOfCoordinates ) );

    SYMCRYPT_ASSERT_ASYM_ALIGNED( pbBuffer );

    cbModElement = pCurve->cbModElement;

    poPoint = (PSYMCRYPT_ECPOINT) pbBuffer;

    pbBuffer += sizeof(SYMCRYPT_ECPOINT);

    // Setting the point coordinates
    for (UINT32 i=0; i<numOfCoordinates; i++)
    {
        pmTmp = SymCryptModElementCreate( pbBuffer, cbModElement, pCurve->FMod );
        if ( pmTmp == NULL )
        {
            pmTmp = NULL;
            goto cleanup;
        }
        pbBuffer += cbModElement;
    }

    // Setting the normalized flag
    poPoint->normalized = 0;

    // Setting the magic
    SYMCRYPT_SET_MAGIC( poPoint );

cleanup:
    return poPoint;
}

PSYMCRYPT_ECPOINT
SYMCRYPT_CALL
SymCryptEcpointCreate(
    _Out_writes_bytes_( cbBuffer )  PBYTE               pbBuffer,
                                    SIZE_T              cbBuffer,
                                    PCSYMCRYPT_ECURVE   pCurve )
{

    SYMCRYPT_ASSERT( pCurve->eCoordinates != 0 );

    return SymCryptEcpointCreateEx( pbBuffer, cbBuffer, pCurve, SYMCRYPT_INTERNAL_NUMOF_COORDINATES(pCurve->eCoordinates) );
}

PSYMCRYPT_ECPOINT
SYMCRYPT_CALL
SymCryptEcpointRetrieveHandle( _In_  PBYTE   pbBuffer )
{
    SYMCRYPT_ASSERT_ASYM_ALIGNED( pbBuffer );

    return (PSYMCRYPT_ECPOINT) pbBuffer;
}

VOID
SYMCRYPT_CALL
SymCryptEcpointWipe( _In_ PCSYMCRYPT_ECURVE pCurve, _Out_ PSYMCRYPT_ECPOINT poDst )
{
    // Wipe the whole structure in one go.
    SymCryptWipe( poDst, SymCryptSizeofEcpointFromCurve( pCurve ) );
}

VOID
SymCryptEcpointCopy(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_ECPOINT  poSrc,
    _Out_   PSYMCRYPT_ECPOINT   poDst )
{
    SymCryptEcpointMaskedCopy( pCurve, poSrc, poDst, 0xffffffff );
}

VOID
SymCryptEcpointMaskedCopy(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_ECPOINT  poSrc,
    _Out_   PSYMCRYPT_ECPOINT   poDst,
            UINT32              mask )
{
	// dcl - hope you realize that this allows 0xffffffff and 0
	// If that's actually what you wanted to accomplish, it would be easier to read
	// if it were written as:
	// SYMCRYPT_ASSERT( (mask == 0) || (mask == 0xffffffff) );
    SYMCRYPT_ASSERT( (mask + 1) < 2 );

    poDst->normalized = (poSrc->normalized & mask) | (poDst->normalized & ~mask);
    
	// dcl - this looks like the equivalent of memcpy
	// should be proven that arguments cannot be the result of an integer overflow
    SymCryptFdefMaskedCopy((PCBYTE)poSrc + sizeof(SYMCRYPT_ECPOINT), (PBYTE)poDst + sizeof(SYMCRYPT_ECPOINT), SYMCRYPT_INTERNAL_NUMOF_COORDINATES(pCurve->eCoordinates) * pCurve->FModDigits, mask );
}

//
// SymCryptEcpointTransform: Internal function to transform an ECPOINT
// from one coordinate representation to another. One point has the default
// format of the curve. The other point has a format large enough for the external 
// SYMCRYPT_ECPOINT_FORMAT. 
//
// When the boolean setValue is set to TRUE, the source point is the one with
// the external format eformat, and the destination point has the default 
// format of the curve. If setValue = FALSE the roles are reversed.
// This function is only called by the Get / Set Value functions.
//
_Success_(return == SYMCRYPT_NO_ERROR)
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptEcpointTransform(
    _In_    PCSYMCRYPT_ECURVE               pCurve,
    _In_    PCSYMCRYPT_ECPOINT              poSrc,
    _Out_   PSYMCRYPT_ECPOINT               poDst,
            SYMCRYPT_ECPOINT_FORMAT         eformat,
            BOOLEAN                         setValue,
            UINT32                          flags,
    _Out_writes_bytes_( cbScratch ) 
            PBYTE                           pbScratch,
            SIZE_T                          cbScratch )
{
    SYMCRYPT_ERROR          scError = SYMCRYPT_NO_ERROR;

    PSYMCRYPT_MODELEMENT    peSrc = NULL;
    PSYMCRYPT_MODELEMENT    peDst = NULL;
    PSYMCRYPT_MODELEMENT    peX = NULL;
    PSYMCRYPT_MODELEMENT    peY = NULL;

    SYMCRYPT_ECPOINT_COORDINATES    coFrom = SYMCRYPT_ECPOINT_COORDINATES_INVALID;
    SYMCRYPT_ECPOINT_COORDINATES    coTo = SYMCRYPT_ECPOINT_COORDINATES_INVALID;

    PSYMCRYPT_MODELEMENT peT[2] = { 0 };    // Temporaries

    SYMCRYPT_ASSERT( (flags & ~SYMCRYPT_FLAG_DATA_PUBLIC) == 0 );
    SYMCRYPT_ASSERT( cbScratch >= max(  SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( pCurve->FModDigits ), 
                                        SYMCRYPT_SCRATCH_BYTES_FOR_MODINV( pCurve->FModDigits )) +
                                  2 * pCurve->cbModElement );

    // Get the assumed representation from the external format
    switch (eformat)
    {
    case (SYMCRYPT_ECPOINT_FORMAT_X):
        coFrom = SYMCRYPT_ECPOINT_COORDINATES_SINGLE;
        break;
    case (SYMCRYPT_ECPOINT_FORMAT_XY):
        coFrom = SYMCRYPT_ECPOINT_COORDINATES_AFFINE;
        break;
    default:
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    // Find out whether we are setting or getting the value of the ECPOINT
    if (setValue)
    {
        coTo = pCurve->eCoordinates;
    }
    else
    {
        coTo = coFrom;
        coFrom = pCurve->eCoordinates;
    }

    // Take all the possible supported transformations:
    //      - From SYMCRYPT_ECPOINT_COORDINATES_SINGLE to 
    //          * SYMCRYPT_ECPOINT_COORDINATES_SINGLE (identity transformation)
    //          * SYMCRYPT_ECPOINT_COORDINATES_AFFINE (** Set all zeros to the Y coordinate **)
    //          * SYMCRYPT_ECPOINT_COORDINATES_SINGLE_PROJECTIVE
    //      - From SYMCRYPT_ECPOINT_COORDINATES_AFFINE to 
    //          * SYMCRYPT_ECPOINT_COORDINATES_SINGLE (** Ignore Y coordinate **)
    //          * SYMCRYPT_ECPOINT_COORDINATES_AFFINE (identity transformation)
    //          * SYMCRYPT_ECPOINT_COORDINATES_JACOBIAN
    //          * SYMCRYPT_ECPOINT_COORDINATES_EXTENDED_PROJECTIVE
    //          * SYMCRYPT_ECPOINT_COORDINATES_SINGLE_PROJECTIVE (** Ignore Y coordinate **)
    //      - From SYMCRYPT_ECPOINT_COORDINATES_JACOBIAN to
    //          * SYMCRYPT_ECPOINT_COORDINATES_SINGLE
    //          * SYMCRYPT_ECPOINT_COORDINATES_AFFINE
    //          * SYMCRYPT_ECPOINT_COORDINATES_JACOBIAN (identity transformation)
    //      - From SYMCRYPT_ECPOINT_COORDINATES_EXTENDED_PROJECTIVE to
    //          * SYMCRYPT_ECPOINT_COORDINATES_SINGLE
    //          * SYMCRYPT_ECPOINT_COORDINATES_AFFINE
    //          * SYMCRYPT_ECPOINT_COORDINATES_EXTENDED_PROJECTIVE (identity transformation)
    //      - From SYMCRYPT_ECPOINT_COORDINATES_SINGLE_PROJECTIVE
    //          * SYMCRYPT_ECPOINT_COORDINATES_SINGLE
    //          * SYMCRYPT_ECPOINT_COORDINATES_AFFINE (** Set all zeros to the Y coordinate **)
    //          * SYMCRYPT_ECPOINT_COORDINATES_SINGLE_PROJECTIVE (identity transformation)

	// dcl - this appears that it might be a candidate for refactoring. Lots of code that looks
	// duplicated across sections. Maybe some number of small functions would make it less fragile?
    if ( coFrom == coTo )
    {
        SymCryptEcpointCopy( pCurve, poSrc, poDst );    // All the identity transformations.
    }
    else if (coFrom == SYMCRYPT_ECPOINT_COORDINATES_SINGLE)
    {
        if (coTo == SYMCRYPT_ECPOINT_COORDINATES_AFFINE)
        {
            // Copy X
            peX = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 0, pCurve, poSrc );
            SYMCRYPT_ASSERT( peX != NULL );

            peDst = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 0, pCurve, poDst );
            SYMCRYPT_ASSERT( peDst != NULL );

            SymCryptModElementCopy( pCurve->FMod, peX, peDst );

            // Set Y to 0
            peDst = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 1, pCurve, poDst );
            SYMCRYPT_ASSERT( peDst != NULL );

            SymCryptModElementSetValueUint32( 0, pCurve->FMod, peDst, pbScratch, cbScratch );
        }
        else if (coTo == SYMCRYPT_ECPOINT_COORDINATES_SINGLE_PROJECTIVE)
        {
            // Copy X
            peX = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 0, pCurve, poSrc );
            SYMCRYPT_ASSERT( peX != NULL );

            peDst = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 0, pCurve, poDst );
            SYMCRYPT_ASSERT( peDst != NULL );

            SymCryptModElementCopy( pCurve->FMod, peX, peDst );

            // Set Y to 1
            peDst = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 1, pCurve, poDst );
            SYMCRYPT_ASSERT( peDst != NULL );

            SymCryptModElementSetValueUint32( 1, pCurve->FMod, peDst, pbScratch, cbScratch );

            // Setting the normalized flag
            poDst->normalized = (UINT32)(-1);
        }
        else
        {
            scError = SYMCRYPT_NOT_IMPLEMENTED;
            goto cleanup;
        }
    }
    else if (coFrom == SYMCRYPT_ECPOINT_COORDINATES_AFFINE)
    {
        if ( (coTo == SYMCRYPT_ECPOINT_COORDINATES_SINGLE) ||
             (coTo == SYMCRYPT_ECPOINT_COORDINATES_JACOBIAN) ||
             (coTo == SYMCRYPT_ECPOINT_COORDINATES_EXTENDED_PROJECTIVE) ||
             (coTo == SYMCRYPT_ECPOINT_COORDINATES_SINGLE_PROJECTIVE)
           )
        {
            // Copy X
            peX = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 0, pCurve, poSrc );
            SYMCRYPT_ASSERT( peX != NULL );

            peDst = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 0, pCurve, poDst );
            SYMCRYPT_ASSERT( peDst != NULL );

            SymCryptModElementCopy( pCurve->FMod, peX, peDst );

            if ( (coTo == SYMCRYPT_ECPOINT_COORDINATES_JACOBIAN) ||
                 (coTo == SYMCRYPT_ECPOINT_COORDINATES_EXTENDED_PROJECTIVE) )
            {
                // Copy Y
                peY = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 1, pCurve, poSrc );
                SYMCRYPT_ASSERT( peY != NULL );

                peDst = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 1, pCurve, poDst );
                SYMCRYPT_ASSERT( peDst != NULL );

                SymCryptModElementCopy( pCurve->FMod, peY, peDst );

                // Set Z to 1
                peDst = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 2, pCurve, poDst );
                SYMCRYPT_ASSERT( peDst != NULL );

                SymCryptModElementSetValueUint32( 1, pCurve->FMod, peDst, pbScratch, cbScratch );

                if (coTo == SYMCRYPT_ECPOINT_COORDINATES_EXTENDED_PROJECTIVE)
                {
                    // T = x * y * z
                    peDst = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 3, pCurve, poDst );
                    SYMCRYPT_ASSERT( peDst != NULL );

                    SymCryptModMul( pCurve->FMod, peX, peY, peDst, pbScratch, cbScratch );
                }

                // Setting the normalized flag
                poDst->normalized = (UINT32)(-1);
            }
            else if (coTo == SYMCRYPT_ECPOINT_COORDINATES_SINGLE_PROJECTIVE)
            {
                // Set Y to 1 (Ignore the second coordinate of the source point)
                peDst = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 1, pCurve, poDst );
                SYMCRYPT_ASSERT( peDst != NULL );

                SymCryptModElementSetValueUint32( 1, pCurve->FMod, peDst, pbScratch, cbScratch );

                // Setting the normalized flag
                poDst->normalized = (UINT32)(-1);
            }
        }
        else
        {
            scError = SYMCRYPT_NOT_IMPLEMENTED;
            goto cleanup;
        }
    }
    else if (coFrom == SYMCRYPT_ECPOINT_COORDINATES_JACOBIAN)
    {
        if ( (coTo == SYMCRYPT_ECPOINT_COORDINATES_SINGLE) ||
             (coTo == SYMCRYPT_ECPOINT_COORDINATES_AFFINE) )
        {
            // Creating temporaries
            for (UINT32 i=0; i<2; i++)
            {
                peT[i] = SymCryptModElementCreate( pbScratch, pCurve->cbModElement, pCurve->FMod );
                SYMCRYPT_ASSERT( peT[i] != NULL);

                pbScratch += pCurve->cbModElement;
            }

            cbScratch -= 2*pCurve->cbModElement;

            // Get the Z coordinate of the source point
            peSrc = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 2, pCurve, poSrc );
            SYMCRYPT_ASSERT( peSrc != NULL );

            // Check if Z is equal to 0 (i.e. the point is the point at infinity)
            if (SymCryptModElementIsZero(pCurve->FMod, peSrc))
            {
                scError = SYMCRYPT_INCOMPATIBLE_FORMAT;
                goto cleanup;
            }

            // Calculation
            // T0 := 1  / Z
            scError = SymCryptModInv( pCurve->FMod, peSrc, peT[0], flags, pbScratch, cbScratch ); 
            if( scError != SYMCRYPT_NO_ERROR )
            {
                goto cleanup;
            }

            SymCryptModMul( pCurve->FMod, peT[0], peT[0], peT[1], pbScratch, cbScratch );           // T1 := T0 * T0 = 1/Z^2

            // Get the X coordinates
            peSrc = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 0, pCurve, poSrc );
            SYMCRYPT_ASSERT( peSrc != NULL );

            peDst = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 0, pCurve, poDst );
            SYMCRYPT_ASSERT( peDst != NULL );

            // Set the new X
            SymCryptModMul( pCurve->FMod, peSrc, peT[1], peDst, pbScratch, cbScratch );       // X2 := X * T1 = X/Z^2

            if (coTo == SYMCRYPT_ECPOINT_COORDINATES_AFFINE)
            {
                SymCryptModMul( pCurve->FMod, peT[0], peT[1], peT[1], pbScratch, cbScratch );     // T1 := T0 * T1 = 1/Z^3

                // Get the Y coordinates
                peSrc = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 1, pCurve, poSrc );
                SYMCRYPT_ASSERT( peSrc != NULL );

                peDst = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 1, pCurve, poDst );
                SYMCRYPT_ASSERT( peDst != NULL );

                // Set the new Y
                SymCryptModMul( pCurve->FMod, peSrc, peT[1], peDst, pbScratch, cbScratch );       // Y2 := Y * T1 = Y/Z^3
            }
        }
        else
        {
            scError = SYMCRYPT_NOT_IMPLEMENTED;
            goto cleanup;
        }
    }
    else if ( coFrom == SYMCRYPT_ECPOINT_COORDINATES_EXTENDED_PROJECTIVE )
    {

        if ( (coTo == SYMCRYPT_ECPOINT_COORDINATES_SINGLE) ||
             (coTo == SYMCRYPT_ECPOINT_COORDINATES_AFFINE) )
        {
            // Creating temporary
            peT[0] = SymCryptModElementCreate( pbScratch, pCurve->cbModElement, pCurve->FMod );
            SYMCRYPT_ASSERT( peT[0] != NULL);
            pbScratch += pCurve->cbModElement;
            cbScratch -= 2*pCurve->cbModElement;

            // Get the Z coordinate of the source point
            peSrc = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 2, pCurve, poSrc );
            SYMCRYPT_ASSERT( peSrc != NULL );

            // Check if Z is equal to 0 (i.e. the point is the point at infinity)
            if (SymCryptModElementIsZero(pCurve->FMod, peSrc))
            {
                scError = SYMCRYPT_INCOMPATIBLE_FORMAT;
                goto cleanup;
            }

            // peT[0] = 1 / Z
            scError = SymCryptModInv( pCurve->FMod, peSrc, peT[0], flags, pbScratch, cbScratch );
            if( scError != SYMCRYPT_NO_ERROR )
            {
                goto cleanup;
            }

            // Get the X coordinates
            peSrc = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 0, pCurve, poSrc );
            SYMCRYPT_ASSERT( peSrc != NULL );

            peDst = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 0, pCurve, poDst );
            SYMCRYPT_ASSERT( peDst != NULL );

            // x = X * (1 / Z)
            SymCryptModMul( pCurve->FMod, peSrc, peT[0], peDst, pbScratch, cbScratch );

            if (coTo == SYMCRYPT_ECPOINT_COORDINATES_AFFINE)
            {
                // Get the Y coordinates
                peSrc = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 1, pCurve, poSrc );
                SYMCRYPT_ASSERT( peSrc != NULL );

                peDst = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 1, pCurve, poDst );
                SYMCRYPT_ASSERT( peDst != NULL );

                // y = Y * (1 / Z)
                SymCryptModMul( pCurve->FMod, peSrc, peT[0], peDst, pbScratch, cbScratch );
            }
        }
        else
        {
            scError = SYMCRYPT_NOT_IMPLEMENTED;
            goto cleanup;
        }
    }
    else if (coFrom == SYMCRYPT_ECPOINT_COORDINATES_SINGLE_PROJECTIVE)
    {
        if ( (coTo == SYMCRYPT_ECPOINT_COORDINATES_SINGLE) ||
             (coTo == SYMCRYPT_ECPOINT_COORDINATES_AFFINE) )
        {
            // Creating temporary
            peT[0] = SymCryptModElementCreate( pbScratch, pCurve->cbModElement, pCurve->FMod );
            SYMCRYPT_ASSERT( peT[0] != NULL);

            pbScratch += pCurve->cbModElement;
            cbScratch -= pCurve->cbModElement;

            // Get the Y coordinate of the source point
            peSrc = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 1, pCurve, poSrc );
            SYMCRYPT_ASSERT( peSrc != NULL );

            // Check if Y is equal to 0 (i.e. the point is the point at infinity)
            if (SymCryptModElementIsZero(pCurve->FMod, peSrc))
            {
                scError = SYMCRYPT_INCOMPATIBLE_FORMAT;
                goto cleanup;
            }

            // Calculation
            scError = SymCryptModInv( pCurve->FMod, peSrc, peT[0], flags, pbScratch, cbScratch );              // T0 := 1 / Y
            if( scError != SYMCRYPT_NO_ERROR )
            {
                goto cleanup;
            }

            // Get the X coordinates
            peSrc = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 0, pCurve, poSrc );
            SYMCRYPT_ASSERT( peSrc != NULL );

            peDst = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 0, pCurve, poDst );
            SYMCRYPT_ASSERT( peDst != NULL );

            // Set the new X
            SymCryptModMul( pCurve->FMod, peSrc, peT[0], peDst, pbScratch, cbScratch );       // X2 := X * T0 = X/Y

            if (coTo == SYMCRYPT_ECPOINT_COORDINATES_AFFINE)
            {
                // Set Y to 0
                peDst = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 1, pCurve, poDst );
                SYMCRYPT_ASSERT( peDst != NULL );

                SymCryptModElementSetValueUint32( 0, pCurve->FMod, peDst, pbScratch, cbScratch );
            }
        }
    }
    else
    {
        scError = SYMCRYPT_NOT_IMPLEMENTED;
        goto cleanup;
    }

cleanup:

    return scError;
}

_Success_(return == SYMCRYPT_NO_ERROR)
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptEcpointSetValue(
    _In_                            PCSYMCRYPT_ECURVE       pCurve,
    _In_reads_bytes_(cbSrc)         PCBYTE                  pbSrc,
                                    SIZE_T                  cbSrc,
                                    SYMCRYPT_NUMBER_FORMAT  nformat,
                                    SYMCRYPT_ECPOINT_FORMAT eformat,
    _Out_                           PSYMCRYPT_ECPOINT       poDst,
                                    UINT32                  flags,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    SYMCRYPT_ERROR          scError = SYMCRYPT_NOT_IMPLEMENTED;
    PSYMCRYPT_MODELEMENT    peTmp = NULL;       // Temporary MODELEMENT handle
    PSYMCRYPT_ECPOINT       poLarge = NULL;     // ECPOINT with the largest format available
    UINT32                  cbLarge = 0;
    PSYMCRYPT_INT           piTemp = NULL;
    UINT32                  cbTemp = 0;
    UINT32                  publicKeyDigits = SymCryptEcurveDigitsofFieldElement( pCurve );

    SYMCRYPT_ASSERT( (flags & ~SYMCRYPT_FLAG_DATA_PUBLIC) == 0 );

    SYMCRYPT_ASSERT( pCurve->FMod != 0 );
    SYMCRYPT_ASSERT( pCurve->eCoordinates != 0 );
    SYMCRYPT_ASSERT( pCurve->cbModElement != 0 );

    SYMCRYPT_ASSERT( cbScratch >= SYMCRYPT_SCRATCH_BYTES_FOR_GETSET_VALUE_ECURVE_OPERATIONS( pCurve ) );

    // Check that the buffer is of correct size
    if ( cbSrc != SymCryptEcpointFormatNumberofElements[ eformat ] * SymCryptEcurveSizeofFieldElement( pCurve ) )
    {
        scError = SYMCRYPT_BUFFER_TOO_SMALL;
        goto cleanup;
    }
    cbSrc = cbSrc / SymCryptEcpointFormatNumberofElements[ eformat ];

    cbTemp = SymCryptSizeofIntFromDigits( publicKeyDigits );
    SYMCRYPT_ASSERT( cbTemp < cbScratch );

    piTemp = SymCryptIntCreate( pbScratch, cbTemp, publicKeyDigits );

    // Validate the coordinate of the input public key is less than the field modulus
    for ( UINT32 i = 0; i < SymCryptEcpointFormatNumberofElements[eformat]; i++ )
    {
        scError = SymCryptIntSetValue( pbSrc + i * cbSrc, cbSrc, nformat, piTemp );
        if (scError != SYMCRYPT_NO_ERROR)
        {
            goto cleanup;
        }

        if ( !SymCryptIntIsLessThan( piTemp, SymCryptIntFromModulus( pCurve->FMod ) ) )
        {
            scError = SYMCRYPT_INVALID_ARGUMENT;
            goto cleanup;
        }
    }

    // Create the large point
    cbLarge = SymCryptSizeofEcpointEx( pCurve->cbModElement, SYMCRYPT_ECPOINT_FORMAT_MAX_LENGTH );
    poLarge = SymCryptEcpointCreateEx( pbScratch, cbLarge, pCurve, SYMCRYPT_ECPOINT_FORMAT_MAX_LENGTH );
    if ( poLarge == NULL )
    {
        scError = SYMCRYPT_INVALID_BLOB;
        goto cleanup;
    }

    // Setting the point coordinates into the big point
    for (UINT32 i=0; i<SymCryptEcpointFormatNumberofElements[eformat]; i++)
    {
        peTmp = (PSYMCRYPT_MODELEMENT)((PBYTE)poLarge + SYMCRYPT_INTERNAL_ECPOINT_COORDINATE_OFFSET( pCurve, i ));
        if ( peTmp == NULL )
        {
            scError = SYMCRYPT_INVALID_BLOB;
            goto cleanup;
        }

        scError = SymCryptModElementSetValue(
                            pbSrc,
                            cbSrc,
                            nformat,
                            pCurve->FMod,
                            peTmp,
                            pbScratch + cbLarge,
                            cbScratch - cbLarge );
        if ( scError != SYMCRYPT_NO_ERROR )
        {
            goto cleanup;
        }
        pbSrc += cbSrc;
    }

    // Transform the big point into the destination point
    scError = SymCryptEcpointTransform( pCurve, poLarge, poDst, eformat, TRUE, flags, pbScratch + cbLarge, cbScratch - cbLarge);

cleanup:
    return scError;
}

_Success_(return == SYMCRYPT_NO_ERROR)
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptEcpointGetValue(
    _In_                            PCSYMCRYPT_ECURVE       pCurve,
    _In_                            PCSYMCRYPT_ECPOINT      poSrc,
                                    SYMCRYPT_NUMBER_FORMAT  nformat,
                                    SYMCRYPT_ECPOINT_FORMAT eformat,
    _Out_writes_bytes_(cbDst)       PBYTE                   pbDst,
                                    SIZE_T                  cbDst,
                                    UINT32                  flags,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    SYMCRYPT_ERROR          scError = SYMCRYPT_NOT_IMPLEMENTED;
    PSYMCRYPT_MODELEMENT    peTmp = NULL;       // Temporary MODELEMENT handle
    PSYMCRYPT_ECPOINT       poLarge = NULL;     // ECPOINT with the largest format available
    UINT32                  cbLarge = 0;

    SYMCRYPT_ASSERT( (flags & ~SYMCRYPT_FLAG_DATA_PUBLIC) == 0 );
    SYMCRYPT_ASSERT( pCurve->FMod != 0 );
    SYMCRYPT_ASSERT( pCurve->eCoordinates != 0 );
    SYMCRYPT_ASSERT( pCurve->cbModElement != 0 );

    SYMCRYPT_ASSERT( cbScratch >= SYMCRYPT_SCRATCH_BYTES_FOR_GETSET_VALUE_ECURVE_OPERATIONS( pCurve ) );

    // Check that the buffer is of correct size
    if ( cbDst != SymCryptEcpointFormatNumberofElements[ eformat ] * SymCryptEcurveSizeofFieldElement( pCurve ) )
    {
        scError = SYMCRYPT_BUFFER_TOO_SMALL;
        goto cleanup;
    }
    cbDst = cbDst / SymCryptEcpointFormatNumberofElements[ eformat ];

    // Create the big point
    cbLarge = SymCryptSizeofEcpointEx( pCurve->cbModElement, SYMCRYPT_ECPOINT_FORMAT_MAX_LENGTH );
    poLarge = SymCryptEcpointCreateEx( pbScratch, cbLarge, pCurve, SYMCRYPT_ECPOINT_FORMAT_MAX_LENGTH );
    if ( poLarge == NULL )
    {
        scError = SYMCRYPT_INVALID_BLOB;
        goto cleanup;
    }

    // Transform the source point into the big point if needed
    scError = SymCryptEcpointTransform( pCurve, poSrc, poLarge, eformat, FALSE, flags, pbScratch + cbLarge, cbScratch - cbLarge);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        goto cleanup;
    }

    // Getting the point coordinates into the destination buffer
    for (UINT32 i=0; i<SymCryptEcpointFormatNumberofElements[eformat]; i++)
    {
        peTmp = (PSYMCRYPT_MODELEMENT)( (PBYTE)poLarge + SYMCRYPT_INTERNAL_ECPOINT_COORDINATE_OFFSET( pCurve, i ) );
        if ( peTmp == NULL )
        {
            scError = SYMCRYPT_INVALID_BLOB;
            goto cleanup;
        }

        scError = SymCryptModElementGetValue(
                            pCurve->FMod,
                            peTmp,
                            pbDst,
                            cbDst,
                            nformat,
                            pbScratch + cbLarge,
                            cbScratch - cbLarge );
        if ( scError != SYMCRYPT_NO_ERROR )
        {
            goto cleanup;
        }
        pbDst += cbDst;
    }

cleanup:

    return scError;
}