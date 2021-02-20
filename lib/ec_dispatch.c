//
// ec_dispatch.c   Dispatch file for elliptic curve crypto functions
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
//

#include "precomp.h"

// Table with all the pointers to SYMCRYPT_ECURVE_FUNCTIONS
const SYMCRYPT_ECURVE_FUNCTIONS SymCryptEcurveAllFunctionPointers[] =
{
    // NULL Type
    {
        NULL,       // SymCryptEcpointSetZeroNotImplemented,
        NULL,       // SymCryptEcpointSetDistinguishedPointNotImplemented,
        NULL,       // SymCryptEcpointSetRandomNotImplemented,
        NULL,       // SymCryptEcpointIsEqualNotImplemented,
        NULL,       // SymCryptEcpointIsZeroNotImplemented,
        NULL,       // SymCryptEcpointOnCurveNotImplemented,
        NULL,       // SymCryptEcpointAddNotImplemented,
        NULL,       // SymCryptEcpointAddDiffNonZeroNotImplemented,
        NULL,       // SymCryptEcpointDoubleNotImplemented,
        NULL,       // SymCryptEcpointNegateNotImplemented,
        NULL,       // SymCryptEcpointScalarMulNotImplemented,
        NULL,       // SymCryptEcpointMultiScalarMulNotImplemented,
    },
    // Short Weierstrass
    {
        SymCryptShortWeierstrassSetZero,
        SymCryptShortWeierstrassSetDistinguished,
        SymCryptEcpointGenericSetRandom,
        SymCryptShortWeierstrassIsEqual,
        SymCryptShortWeierstrassIsZero,
        SymCryptShortWeierstrassOnCurve,
        SymCryptShortWeierstrassAdd,
        SymCryptShortWeierstrassAddDiffNonZero,
        SymCryptShortWeierstrassDouble,
        SymCryptShortWeierstrassNegate,
        SymCryptEcpointScalarMulFixedWindow,
        SymCryptEcpointMultiScalarMulWnafWithInterleaving,
    },
    // Twisted Edwards
    {
        SymCryptTwistedEdwardsSetZero,
        SymCryptTwistedEdwardsSetDistinguished,
        SymCryptEcpointGenericSetRandom,
        SymCryptTwistedEdwardsIsEqual,
        SymCryptTwistedEdwardsIsZero,
        SymCryptTwistedEdwardsOnCurve,
        SymCryptTwistedEdwardsAdd,
        SymCryptTwistedEdwardsAddDiffNonZero,
        SymCryptTwistedEdwardsDouble,
        SymCryptTwistedEdwardsNegate,
        SymCryptEcpointScalarMulFixedWindow,
        SymCryptEcpointMultiScalarMulWnafWithInterleaving,
    },
    // Montgomery
    {
        NULL,       // SymCryptEcpointSetZeroNotImplemented,
        SymCryptMontgomerySetDistinguished,
        SymCryptEcpointGenericSetRandom,
        SymCryptMontgomeryIsEqual,
        SymCryptMontgomeryIsZero,
        NULL,       // SymCryptEcpointOnCurveNotImplemented,
        NULL,       // SymCryptEcpointAddNotImplemented,
        NULL,       // SymCryptEcpointAddDiffNonZeroNotImplemented,
        NULL,       // SymCryptEcpointDoubleNotImplemented,
        NULL,       // SymCryptEcpointNegateNotImplemented,
        SymCryptMontgomeryPointScalarMul,
        NULL,       // SymCryptEcpointMultiScalarMulNotImplemented,
    },
};

// Main functions
SYMCRYPT_DISABLE_CFG
VOID
SYMCRYPT_CALL
SymCryptEcpointSetZero(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _Out_   PSYMCRYPT_ECPOINT   poDst,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch )
{
    SymCryptEcurveAllFunctionPointers[ (pCurve->type) & 3 ].setZeroFunc( pCurve, poDst, pbScratch, cbScratch );
}

SYMCRYPT_DISABLE_CFG
VOID
SYMCRYPT_CALL
SymCryptEcpointSetDistinguishedPoint(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _Out_   PSYMCRYPT_ECPOINT   poDst,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch )
{
    SymCryptEcurveAllFunctionPointers[ (pCurve->type) & 3 ].setDistinguishedFunc( pCurve, poDst, pbScratch, cbScratch );
}

SYMCRYPT_DISABLE_CFG
VOID
SYMCRYPT_CALL
SymCryptEcpointSetRandom(
    _In_    PCSYMCRYPT_ECURVE       pCurve,
    _Out_   PSYMCRYPT_INT           piScalar,
    _Out_   PSYMCRYPT_ECPOINT       poDst,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE                   pbScratch,
            SIZE_T                  cbScratch )
{
    SymCryptEcurveAllFunctionPointers[ (pCurve->type) & 3 ].setRandomFunc( pCurve, piScalar, poDst, pbScratch, cbScratch );
}

SYMCRYPT_DISABLE_CFG
UINT32
SYMCRYPT_CALL
SymCryptEcpointIsEqual(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_ECPOINT  poSrc1,
    _In_    PCSYMCRYPT_ECPOINT  poSrc2,
            UINT32              flags,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch )
{
    return SymCryptEcurveAllFunctionPointers[ (pCurve->type) & 3 ].isEqualFunc( pCurve, poSrc1, poSrc2, flags, pbScratch, cbScratch );
}

SYMCRYPT_DISABLE_CFG
UINT32
SYMCRYPT_CALL
SymCryptEcpointIsZero(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_ECPOINT  poSrc,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch )
{
    return SymCryptEcurveAllFunctionPointers[ (pCurve->type) & 3 ].isZeroFunc( pCurve, poSrc, pbScratch, cbScratch );
}

SYMCRYPT_DISABLE_CFG
UINT32
SYMCRYPT_CALL
SymCryptEcpointOnCurve(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_ECPOINT  poSrc,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch )
{
    return SymCryptEcurveAllFunctionPointers[ (pCurve->type) & 3 ].onCurveFunc( pCurve, poSrc, pbScratch, cbScratch );
}

SYMCRYPT_DISABLE_CFG
VOID
SYMCRYPT_CALL
SymCryptEcpointAdd(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_ECPOINT  poSrc1,
    _In_    PCSYMCRYPT_ECPOINT  poSrc2,
    _Out_   PSYMCRYPT_ECPOINT   poDst,
    _In_    UINT32              flags,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch )
{
    SymCryptEcurveAllFunctionPointers[ (pCurve->type) & 3 ].addFunc( pCurve, poSrc1, poSrc2, poDst, flags, pbScratch, cbScratch );
}

SYMCRYPT_DISABLE_CFG
VOID
SYMCRYPT_CALL
SymCryptEcpointAddDiffNonZero(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_ECPOINT  poSrc1,
    _In_    PCSYMCRYPT_ECPOINT  poSrc2,
    _Out_   PSYMCRYPT_ECPOINT   poDst,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch )
{
    SymCryptEcurveAllFunctionPointers[ (pCurve->type) & 3 ].addDiffFunc( pCurve, poSrc1, poSrc2, poDst, pbScratch, cbScratch );
}

SYMCRYPT_DISABLE_CFG
VOID
SYMCRYPT_CALL
SymCryptEcpointDouble(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_ECPOINT  poSrc,
    _Out_   PSYMCRYPT_ECPOINT   poDst,
    _In_    UINT32              flags,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch )
{
    SymCryptEcurveAllFunctionPointers[ (pCurve->type) & 3 ].doubleFunc( pCurve, poSrc, poDst, flags, pbScratch, cbScratch );
}

SYMCRYPT_DISABLE_CFG
VOID
SYMCRYPT_CALL
SymCryptEcpointNegate(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _Inout_ PSYMCRYPT_ECPOINT   poSrc,
            UINT32              mask,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch )
{
    SymCryptEcurveAllFunctionPointers[ (pCurve->type) & 3 ].negateFunc( pCurve, poSrc, mask, pbScratch, cbScratch );
}

SYMCRYPT_DISABLE_CFG
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptEcpointScalarMul(
    _In_    PCSYMCRYPT_ECURVE       pCurve,
    _In_    PCSYMCRYPT_INT          piScalar,
    _In_opt_
            PCSYMCRYPT_ECPOINT      poSrc,
    _In_    UINT32                  flags,
    _Out_   PSYMCRYPT_ECPOINT       poDst,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch )
{
    return SymCryptEcurveAllFunctionPointers[ (pCurve->type) & 3 ].scalarMulFunc( pCurve, piScalar, poSrc, flags, poDst, pbScratch, cbScratch );
}

SYMCRYPT_DISABLE_CFG
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptEcpointMultiScalarMul(
    _In_    PCSYMCRYPT_ECURVE       pCurve,
    _In_    PCSYMCRYPT_INT *        piSrcScalarArray,
    _In_    PCSYMCRYPT_ECPOINT *    poSrcEcpointArray,
    _In_    UINT32                  nPoints,
    _In_    UINT32                  flags,
    _Out_   PSYMCRYPT_ECPOINT       poDst,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch )
{
    return SymCryptEcurveAllFunctionPointers[ (pCurve->type) & 3 ].multiScalarMulFunc( pCurve, piSrcScalarArray, poSrcEcpointArray, nPoints, flags, poDst, pbScratch, cbScratch );
}