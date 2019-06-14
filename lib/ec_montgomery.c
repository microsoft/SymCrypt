//
// ec_montgomery.c   Montgomery Implementation
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

VOID
SYMCRYPT_CALL
SymCryptMontgomeryFillScratchSpaces(_In_ PSYMCRYPT_ECURVE pCurve)
{
    UINT32 nDigits = SymCryptDigitsFromBits( pCurve->FModBitsize );
    UINT32 nBytes = SymCryptSizeofModElementFromModulus( pCurve->FMod );
    UINT32 nCommon = max( SymCryptSizeofIntFromDigits( nDigits ), max( SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ), SYMCRYPT_SCRATCH_BYTES_FOR_MODINV( nDigits ) ) );
    UINT32 cbModElement = pCurve->cbModElement;
    UINT32 nDigitsFieldLength = pCurve->FModDigits;

    //
    // All the scratch space computations are upper bounded by the SizeofXXX bound (2^19) and
    // the SCRATCH_BYTES_FOR_XXX bound (2^24) (see symcrypt_internal.h).
    //
    // One caveat is SymCryptSizeofEcpointEx which calculates the size of EcPoint with
    // 4 coordinates (each one a modelement of max size 2^17). Thus upper bounded by 2^20.
    //

    pCurve->cbScratchCommon = nCommon;
    pCurve->cbScratchScalar = 
        SymCryptSizeofIntFromDigits(nDigits) +
        6 * nBytes +
        nCommon;

    pCurve->cbScratchScalarMulti = 0;
    pCurve->cbScratchGetSetValue = 
        SymCryptSizeofEcpointEx( cbModElement, SYMCRYPT_ECPOINT_FORMAT_MAX_LENGTH ) +
        2 * cbModElement +
        max( SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigitsFieldLength ),
             SYMCRYPT_SCRATCH_BYTES_FOR_MODINV( nDigitsFieldLength ) );

    pCurve->cbScratchGetSetValue = max( pCurve->cbScratchGetSetValue, SymCryptSizeofIntFromDigits( nDigits ) ); 

    pCurve->cbScratchEckey = pCurve->cbModElement + SymCryptSizeofIntFromDigits(SymCryptEcurveDigitsofScalarMultiplier(pCurve)) +
        max( pCurve->cbScratchScalar, pCurve->cbScratchGetSetValue );
}

VOID
SYMCRYPT_CALL
SymCryptMontgomerySetDistinguished(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _Out_   PSYMCRYPT_ECPOINT   poDst,
    _Out_writes_bytes_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch )
{
    SYMCRYPT_ASSERT( pCurve->type == SYMCRYPT_ECURVE_TYPE_MONTGOMERY );

    UNREFERENCED_PARAMETER( pbScratch );
    UNREFERENCED_PARAMETER( cbScratch );

    SymCryptEcpointCopy( pCurve, pCurve->G, poDst );
}

UINT32
SYMCRYPT_CALL
SymCryptMontgomeryIsZero(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_ECPOINT  poSrc,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch )
{
    PCSYMCRYPT_MODULUS FMod = pCurve->FMod;
    PSYMCRYPT_MODELEMENT peZ = NULL;    // Pointer to Z

    SYMCRYPT_ASSERT( pCurve->type == SYMCRYPT_ECURVE_TYPE_MONTGOMERY );

    UNREFERENCED_PARAMETER( pbScratch );
    UNREFERENCED_PARAMETER( cbScratch );

    // Getting pointer to Z of the source point
    peZ = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 1,  pCurve, poSrc );

    return SymCryptModElementIsZero( FMod, peZ );
}

VOID
SymCryptMontgomeryDoubleAndAdd(
    _In_                           PCSYMCRYPT_MODULUS    pmMod,
    _In_                           PSYMCRYPT_MODELEMENT  peX1,
    _In_                           PSYMCRYPT_MODELEMENT  peA24,
    _In_                           PSYMCRYPT_MODELEMENT  peX2,
    _In_                           PSYMCRYPT_MODELEMENT  peZ2,
    _In_                           PSYMCRYPT_MODELEMENT  peX3,
    _In_                           PSYMCRYPT_MODELEMENT  peZ3,
    _In_                           PSYMCRYPT_MODELEMENT  peTemp1,
    _In_                           PSYMCRYPT_MODELEMENT  peTemp2,
    _Out_writes_bytes_(cbScratch)  PBYTE                 pbScratch,
                                   SIZE_T                cbScratch)
/*
We use the notation of the current RFC draft for TLS use of curve25519
However, this is a generic Montgomery ladder implementation.

The (X,Z) values represent an x-coordinate (X/Z) but it avoids the modular division.
In our case, we don't need the general (X1,Z1) form for the first input, so we do not allow it.

The value a24 is such that 4*a24 = a+2 where a is one of the Montgomery curve parameters.
Thus, a24 = (a+2)/4. For curve25519, A = 486662, so a24 = 121666 (=0x01db42)

Algorithm (from RFC draft), with all operations expanded
   A  = X2 + Z2
   AA = A^2
   B  = X2 - Z2
   BB = B^2
   E  = AA - BB
   C  = X3 + Z3
   D  = X3 - Z3
   DA = D * A
   CB = C * B
   X5 = (DA + CB)^2:
        DApCB = DA + CB
        X5 = DApCB^2
   Z5 = X1 * (DA - CB)^2
        DAmCB = DA - CB
        DAmCB2 = DAmCB ^ 2
        Z5 = X1 * DAmCB2
   X4 = AA * BB
   Z4 = E * (BB + a24 * E)
        A24E = A24 * E
        BAE = BB + A24 * E
        Z4 = E * BAE

If we write a = (X2,Z2) and b = (X3,Z3), then this algorithm computes (2*a) and (a+b) into (X4, Z4) and (X5,Z5).
The Montgomery ladder uses this as follows:
- Store xP and (x+1)P
- To process a 0 bit in the scalar, apply the DoubleAndAdd to (xP,(x+1)P) to get (2xP, (2x+1)P)
- To process a 1 bit in the scalar, apply the DoubleAndAdd to ((x+1)P, xP) to get ((2x+2)P, (2x+1)P)
This updates the state to either (2xP, (2x+1)P) or to ((2x+1)P, (2x+2)P) and corresponds to updating
x to either 2x or 2x+1.

The starting value is (0,P), represented as ((1,0),(P_x,1)
The algorithm above, when applied to (1, 0, X, 1) produces:
    A = 1, AA = 1, B = 1, BB = 1, E = 0,
    C = X+1, D = X-1, DA = X-1, CB = X+1,
    X5 = 4X^2, Z5 = 4X
    X4 = 1, Z4 = 0
for an output of (1, 0, 4X^2, 4X)
But (4X^2, 4X) is just another representation of (X,1) as only the quotient of the two numbers is significant.
So even if an exponent starts with a bunch of 0 bits, the DoubleAndAdd-based function computes the right result in constant time.

*/
{
    // Temp1 =          A = X2 + Z2
    SymCryptModAdd( pmMod, peX2, peZ2, peTemp1, pbScratch, cbScratch );

    // Z2 =             B = X2 - Z2
    SymCryptModSub( pmMod, peX2, peZ2, peZ2, pbScratch, cbScratch );

    // Temp2 =          C = X3 + Z3
    SymCryptModAdd( pmMod, peX3, peZ3, peTemp2, pbScratch, cbScratch );

    // Z3 =             D = X3 - Z3
    SymCryptModSub( pmMod, peX3, peZ3, peZ3, pbScratch, cbScratch );

    // X3 =             CB = C * B      = Temp2 * Z2
    SymCryptModMul( pmMod, peTemp2, peZ2, peX3, pbScratch, cbScratch );

    // Z3 =             DA = D * A      = Z3 * Temp1
    SymCryptModMul( pmMod, peZ3, peTemp1, peZ3, pbScratch, cbScratch );

    // From this point on, the outputs (X5,Z5) depend only on (X3,Z3) and X1
    // and the outputs (X4,Z4) only on (Temp1,Z2) and A24
    // We'll do the (X4,Z4) first

    // X2 =             AA = A * A      = Temp1 * Temp1
    SymCryptModSquare( pmMod, peTemp1, peX2, pbScratch, cbScratch );

    // Temp1 =          BB = B * B      = Z2 * Z2
    SymCryptModSquare( pmMod, peZ2, peTemp1, pbScratch, cbScratch );

    // Temp2 =          E = AA - BB     = X2 - Temp1
    SymCryptModSub( pmMod, peX2, peTemp1, peTemp2, pbScratch, cbScratch );

    // X2 =             X4 = AA * BB    = X2 * Temp1
    SymCryptModMul( pmMod, peX2, peTemp1, peX2, pbScratch, cbScratch );

    // Z2 =             A24E = A24 * E    = A24 * Temp2
    SymCryptModMul( pmMod, peA24, peTemp2, peZ2, pbScratch, cbScratch );

    // Z2 =             BAE = (BB + a24 * E) = BB + A24E = Temp1 + Z2
    SymCryptModAdd( pmMod, peTemp1, peZ2, peZ2, pbScratch, cbScratch );

    // Z2 =             Z4 = E * BAE        = Temp2 + Z2
    SymCryptModMul( pmMod, peTemp2, peZ2, peZ2, pbScratch, cbScratch );

    // Now we compute (X5, Z5)

    // Temp1 =          DApCB = DA + CB     = Z3 + X3
    SymCryptModAdd( pmMod, peZ3, peX3, peTemp1, pbScratch, cbScratch );

    // Z3 =             DAmCB = DA - CB     = Z3 - X3
    SymCryptModSub( pmMod, peZ3, peX3, peZ3, pbScratch, cbScratch );

    // X3 =             X5 = DApCB^2         = Temp1 ^ 2
    SymCryptModSquare( pmMod, peTemp1, peX3, pbScratch, cbScratch );

    // Z3 =             DAmCB2 = DAmCB ^ 2  = Z3 ^ 2
    SymCryptModSquare( pmMod, peZ3, peZ3, pbScratch, cbScratch );

    // Z3 =             Z5 = X1 * DAmCB2        = X1 * Z3
    SymCryptModMul( pmMod, peX1, peZ3, peZ3, pbScratch, cbScratch );
}

//
// Montgomery point multiplication only works on X-coordinates.
// We ignore the Y-coordinates.
//
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptMontgomeryPointScalarMul(
    _In_    PCSYMCRYPT_ECURVE      pCurve,
    _In_    PCSYMCRYPT_INT         piScalar,
    _In_opt_
            PCSYMCRYPT_ECPOINT     poSrc,
    _In_    UINT32                 flags,
    _Out_   PSYMCRYPT_ECPOINT      poDst,
    _Out_writes_bytes_(cbScratch)
            PBYTE                  pbScratch,
            SIZE_T                 cbScratch)
{
    SYMCRYPT_ERROR        scError = SYMCRYPT_NO_ERROR;

    PSYMCRYPT_MODULUS     pmMod;
    PSYMCRYPT_MODELEMENT  peX1, peA24, peX2, peZ2, peX3, peZ3, peTemp1, peTemp2, peResult;
    UINT32                i, nBytes, nDigits, cond, newcond, nCommon;
    PBYTE                 pBegin;
    SIZE_T                cbAllScratch;

    SYMCRYPT_ASSERT( pCurve->type == SYMCRYPT_ECURVE_TYPE_MONTGOMERY );

    // Make sure we only specify the correct flags
    if ((flags & ~SYMCRYPT_FLAG_ECC_LL_COFACTOR_MUL) != 0)
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    if (poSrc == NULL)
    {
        poSrc = pCurve->G;
    }

    //
    // Set up structure for X2, Z2, X3, Z3, Temp1, and Temp2, and the scratch space.
    //
    pmMod = pCurve->FMod;

    nDigits = SymCryptDigitsFromBits( pCurve->FModBitsize );
    nBytes = SymCryptSizeofModElementFromModulus( pmMod );
    nCommon = max( SymCryptSizeofIntFromDigits(nDigits), max(SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits), SYMCRYPT_SCRATCH_BYTES_FOR_MODINV(nDigits)));
 
    SYMCRYPT_ASSERT( cbScratch >= 6 * nBytes + nCommon );

    cbAllScratch = cbScratch;
    pBegin = pbScratch;

    //
    // Create mod elements
    //
    peX2 = SymCryptModElementCreate( pbScratch, nBytes, pmMod );
    pbScratch += nBytes;

    peZ2 = SymCryptModElementCreate( pbScratch, nBytes, pmMod );
    pbScratch += nBytes;

    peX3 = SymCryptModElementCreate( pbScratch, nBytes, pmMod );
    pbScratch += nBytes;

    peZ3 = SymCryptModElementCreate( pbScratch, nBytes, pmMod );
    pbScratch += nBytes;

    peTemp1 = SymCryptModElementCreate( pbScratch, nBytes, pmMod );
    pbScratch += nBytes;

    peTemp2 = SymCryptModElementCreate( pbScratch, nBytes, pmMod );
    pbScratch += nBytes;

    cbScratch = nCommon;

    //
    // Set up values
    //
   
    peA24 = pCurve->A;

    // X1 = X
    peX1 = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 0, pCurve, poSrc);

    // Normalize the point from (X,Z) to X
    if (!poSrc->normalized)
    {
        peResult = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 1, pCurve, poSrc);
        scError = SymCryptModInv( pmMod, peResult, peResult, 0, pbScratch, cbScratch ); // 1/Z
        if( scError != SYMCRYPT_NO_ERROR )
        {
            goto cleanup;
        }

        SymCryptModMul( pmMod, peX1, peResult, peX1, pbScratch, cbScratch );            // X = X/Z
        SymCryptModElementSetValueUint32( 1, pmMod, peResult, pbScratch, cbScratch );   // Set Z to 1
    }

    // X2 = 1, Z2 = 0, X3 = X (base point) Z3 = 1
    SymCryptModElementSetValueUint32( 1, pmMod, peX2, pbScratch, cbScratch );
    SymCryptModElementSetValueUint32( 0, pmMod, peZ2, pbScratch, cbScratch );
    SymCryptModElementCopy( pmMod, peX1, peX3 );
    SymCryptModElementSetValueUint32( 1, pmMod, peZ3, pbScratch, cbScratch );

    //
    //  Montgomery ladder scalar multiplication
    //

    i = (pCurve->GOrdBitsize + pCurve->coFactorPower);
    cond = 0;
    while ( i != 0 )
    {
        // If cond = 0, we have (X2, Z2, X3, Z3)
        // if cond = 1, we have (X3, Z3, X2, Z2)
        i--;
        newcond = SymCryptIntGetBit( piScalar, i );
        cond ^= newcond;

        SymCryptModElementConditionalSwap( pmMod, peX2, peX3, cond);
        SymCryptModElementConditionalSwap( pmMod, peZ2, peZ3, cond);

        cond = newcond;

        SymCryptMontgomeryDoubleAndAdd( pmMod, peX1, peA24, peX2, peZ2, peX3, peZ3, peTemp1, peTemp2, pbScratch, cbScratch );
    }

    // Now put them back in the normal order
    SymCryptModElementConditionalSwap( pmMod, peX2, peX3, cond);
    SymCryptModElementConditionalSwap( pmMod, peZ2, peZ3, cond);

    // Multiply by the cofactor (if needed) by continuing the doubling
    if ((flags & SYMCRYPT_FLAG_ECC_LL_COFACTOR_MUL) != 0)
    {
        i = pCurve->coFactorPower;
        while (i!=0)
        {
            i--;
            SymCryptMontgomeryDoubleAndAdd( pmMod, peX1, peA24, peX2, peZ2, peX3, peZ3, peTemp1, peTemp2, pbScratch, cbScratch );
        }
    }

    // Set X coordinate
    peResult = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 0, pCurve, poDst);
    SymCryptModElementCopy( pCurve->FMod, peX2, peResult );

    // Set Z coordinate
    peResult = SYMCRYPT_INTERNAL_ECPOINT_COORDINATE( 1, pCurve, poDst);
    SymCryptModElementCopy( pCurve->FMod, peZ2, peResult );

    poDst->normalized = 0;

    scError = SYMCRYPT_NO_ERROR;

cleanup:
    return scError;
}