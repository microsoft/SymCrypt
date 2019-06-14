//
// fdef_int.c   INT functions for default number format
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

PSYMCRYPT_MODULUS
SYMCRYPT_CALL
SymCryptFdefModulusAllocate( UINT32 nDigits )
{
    PVOID               p;
    UINT32              cb;
    PSYMCRYPT_MODULUS   res = NULL;

    //
    // The nDigits requirements are enforced by SymCryptFdefSizeofModulusFromDigits. Thus
    // the result does not overflow and is upper bounded by 2^19.
    //
    cb = SymCryptFdefSizeofModulusFromDigits( nDigits );

    p = SymCryptCallbackAlloc( cb );

    if( p == NULL )
    {
        goto cleanup;
    }

    res = SymCryptFdefModulusCreate( p, cb, nDigits );

cleanup:
    return res;
}

VOID
SYMCRYPT_CALL
SymCryptFdefModulusFree( _Out_ PSYMCRYPT_MODULUS pmObj )
{
    SymCryptModulusWipe( pmObj );
    SymCryptCallbackFree( pmObj );
}

UINT32
SYMCRYPT_CALL
SymCryptFdefSizeofModulusFromDigits( UINT32 nDigits )
{
    // Room for the Modulus structure, the Divisor, and the R^2 Montgomery factor
    //
    // The nDigits requirements are enforced by SymCryptFdefSizeofDivisorFromDigits. Thus
    // the result does not overflow and is upper bounded by 2^19.
    //
    return SYMCRYPT_FIELD_OFFSET( SYMCRYPT_MODULUS, Divisor ) + SymCryptFdefSizeofDivisorFromDigits( nDigits ) + nDigits * SYMCRYPT_FDEF_DIGIT_SIZE;
}

PSYMCRYPT_MODULUS
SYMCRYPT_CALL
SymCryptFdefModulusCreate( 
    _Out_writes_bytes_( cbBuffer )  PBYTE   pbBuffer, 
                                    SIZE_T  cbBuffer, 
                                    UINT32  nDigits )
{
    PSYMCRYPT_MODULUS pmMod = (PSYMCRYPT_MODULUS) pbBuffer;
    UINT32 cb = SymCryptFdefSizeofModulusFromDigits( nDigits );

    const UINT32 offset = SYMCRYPT_FIELD_OFFSET( SYMCRYPT_MODULUS, Divisor );

    if ( cbBuffer < cb )
    {
        SymCryptFatal( 'modc' );
    }

    SYMCRYPT_ASSERT_ASYM_ALIGNED( pbBuffer );

    pmMod->type = 'gM' << 16;
    pmMod->nDigits = nDigits;

    //
    // The nDigits requirements are enforced by SymCryptFdefSizeofModulusFromDigits. Thus
    // the result does not overflow and is upper bounded by 2^19.
    //
    pmMod->cbSize = cb;
    pmMod->flags = 0;

    // The following is bounded by 2^17
    pmMod->cbModElement = nDigits * SYMCRYPT_FDEF_DIGIT_SIZE;

    SymCryptFdefDivisorCreate( pbBuffer + offset, cbBuffer - offset, nDigits );

    // We don't have a modulus value yet, so we don't create/initialize any implementation-specific things.

    SYMCRYPT_SET_MAGIC( pmMod );

    return pmMod;
}

VOID 
SYMCRYPT_CALL 
SymCryptFdefModulusInitGeneric(
    _Inout_                         PSYMCRYPT_MODULUS       pmMod,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    UNREFERENCED_PARAMETER( pmMod );
    UNREFERENCED_PARAMETER( pbScratch );
    UNREFERENCED_PARAMETER( cbScratch );
}


VOID
SymCryptFdefModulusCopy( 
    _In_    PCSYMCRYPT_MODULUS  pmSrc, 
    _Out_   PSYMCRYPT_MODULUS   pmDst )
{
    SYMCRYPT_ASSERT( pmSrc->nDigits == pmDst->nDigits );

    memcpy( pmDst, pmSrc, pmDst->cbSize );

    SymCryptFdefDivisorCopyFixup( &pmSrc->Divisor, &pmDst->Divisor );

    // Copy the type-specific fields
    SYMCRYPT_MOD_CALL( pmSrc ) modulusCopyFixup( pmSrc, pmDst );

    SYMCRYPT_SET_MAGIC( pmDst );
}

VOID
SYMCRYPT_CALL
SymCryptFdefModulusCopyFixupGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmSrc,
    _Out_                           PSYMCRYPT_MODULUS       pmDst )
{
    // Only have to handle the type-specific fields, which we don't have any of.
    UNREFERENCED_PARAMETER( pmSrc );
    UNREFERENCED_PARAMETER( pmDst );
}


PSYMCRYPT_MODELEMENT
SYMCRYPT_CALL
SymCryptFdefModElementAllocate( _In_ PCSYMCRYPT_MODULUS pmMod )
{
    PVOID                   p;
    UINT32                  cb;
    PSYMCRYPT_MODELEMENT    res = NULL;

    //
    // The nDigits requirements are enforced by the modulus object. Thus
    // the result does not overflow and is upper bounded by 2^17.
    //
    cb = SymCryptFdefSizeofModElementFromModulus( pmMod );

    p = SymCryptCallbackAlloc( cb );

    if( p == NULL )
    {
        goto cleanup;
    }

    res = SymCryptFdefModElementCreate( p, cb, pmMod );

cleanup:
    return res;
}

VOID
SYMCRYPT_CALL
SymCryptFdefModElementFree( 
    _In_    PCSYMCRYPT_MODULUS      pmMod,      
    _Out_   PSYMCRYPT_MODELEMENT    peObj )
{
    SymCryptFdefModElementWipe( pmMod, peObj );
    SymCryptCallbackFree( peObj );
}

UINT32
SYMCRYPT_CALL
SymCryptFdefSizeofModElementFromModulus( PCSYMCRYPT_MODULUS pmMod )
{
    // Upper bounded by 2^17 since the modulus is up to SYMCRYPT_INT_MAXBITS = 2^20 bits.
    return pmMod->cbModElement;
}

PSYMCRYPT_MODELEMENT
SYMCRYPT_CALL
SymCryptFdefModElementCreate( 
    _Out_writes_bytes_( cbBuffer )  PBYTE               pbBuffer, 
                                    SIZE_T              cbBuffer, 
                                    PCSYMCRYPT_MODULUS  pmMod )
{
    PSYMCRYPT_MODELEMENT pDst = (PSYMCRYPT_MODELEMENT) pbBuffer;

    UNREFERENCED_PARAMETER( pmMod );
    UNREFERENCED_PARAMETER( cbBuffer );

    SYMCRYPT_ASSERT_ASYM_ALIGNED( pbBuffer );
    SYMCRYPT_ASSERT( cbBuffer >= SymCryptFdefSizeofModElementFromModulus( pmMod ) );

    //
    // We have various optimizations where we use only part of the last digit
    // Simple and fast solution: always wipe the last digit
    //
#if (SYMCRYPT_CPU_AMD64 | SYMCRYPT_CPU_ARM64)
    UINT32 nDigits = pmMod->nDigits;

    SymCryptWipeKnownSize( pbBuffer + (nDigits-1) * SYMCRYPT_FDEF_DIGIT_SIZE, SYMCRYPT_FDEF_DIGIT_SIZE );
#endif

    // There is nothing to initialize...

    return pDst;
}

VOID
SYMCRYPT_CALL
SymCryptFdefModElementWipe( 
    _In_    PCSYMCRYPT_MODULUS      pmMod,
    _Out_   PSYMCRYPT_MODELEMENT    peDst )
{
    SymCryptWipe( peDst, pmMod->cbModElement );
}

VOID
SymCryptFdefModElementCopy( 
    _In_    PCSYMCRYPT_MODULUS      pmMod,
    _In_    PCSYMCRYPT_MODELEMENT   peSrc, 
    _Out_   PSYMCRYPT_MODELEMENT    peDst )
{
    memcpy( peDst, peSrc, pmMod->cbModElement );
}

VOID
SymCryptFdefModElementMaskedCopy(
    _In_    PCSYMCRYPT_MODULUS      pmMod,
    _In_    PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_   PSYMCRYPT_MODELEMENT    peDst,
            UINT32                  mask )
{
    SymCryptFdefMaskedCopy( (PCBYTE) peSrc, (PBYTE) peDst, pmMod->nDigits, mask );
}


PSYMCRYPT_DIVISOR
SYMCRYPT_CALL
SymCryptFdefDivisorFromModulus( _In_ PSYMCRYPT_MODULUS pmSrc )
{
    return &pmSrc->Divisor;
}

VOID
SymCryptFdefModElementConditionalSwap(
    _In_       PCSYMCRYPT_MODULUS    pmMod,
    _Inout_    PSYMCRYPT_MODELEMENT  peData1,
    _Inout_    PSYMCRYPT_MODELEMENT  peData2,
    _In_       UINT32                cond )
{
    SymCryptFdefConditionalSwap( (PBYTE) &peData1->d.uint32[0], (PBYTE) &peData2->d.uint32[0], pmMod->nDigits, cond );
}

PSYMCRYPT_INT
SYMCRYPT_CALL
SymCryptFdefIntFromModulus( _In_ PSYMCRYPT_MODULUS pmSrc )
{

    return SymCryptFdefIntFromDivisor( &pmSrc->Divisor );
}

UINT32
SYMCRYPT_CALL
SymCryptFdefDecideModulusType( PCSYMCRYPT_INT piSrc, UINT32 nDigits, UINT32 averageOperations, UINT32 flags )
{
    UINT32 res = 0;
    BOOLEAN disableMontgomery = 0;
    PSYMCRYPT_MODULUS_TYPE_SELECTION_ENTRY pEntry;

    UINT32 nBitsizeOfValue = SymCryptIntBitsizeOfValue( piSrc );
    UINT32 modulusFeatures = 0;

    if( !disableMontgomery && 
        ( flags & (SYMCRYPT_FLAG_DATA_PUBLIC | SYMCRYPT_FLAG_MODULUS_PARITY_PUBLIC)) != 0 &&
        (SymCryptIntGetValueLsbits32( piSrc ) & 1) == 1 && 
        averageOperations >= 10 )
    {
        modulusFeatures |= SYMCRYPT_MODULUS_FEATURE_MONTGOMERY;
    }

    pEntry = SymCryptModulusTypeSelections;

    for(;;)
    {
        if( SYMCRYPT_CPU_FEATURES_PRESENT( pEntry->cpuFeatures ) &&
            (pEntry->maxBits == 0 || (nDigits <= SymCryptDigitsFromBits( pEntry->maxBits ) && nBitsizeOfValue <= pEntry->maxBits )) &&
            (pEntry->modulusFeatures & ~modulusFeatures) == 0
            )
        {
            res = pEntry->type;
            break;
        }
        pEntry++;
    }

    return res;
}

VOID 
SYMCRYPT_CALL 
SymCryptFdefModSetPostGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Inout_                         PSYMCRYPT_MODELEMENT    peObj,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    UNREFERENCED_PARAMETER( pmMod );
    UNREFERENCED_PARAMETER( peObj );
    UNREFERENCED_PARAMETER( pbScratch );
    UNREFERENCED_PARAMETER( cbScratch );
}

PCUINT32
SYMCRYPT_CALL
SymCryptFdefModPreGetGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peObj,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    UNREFERENCED_PARAMETER( pmMod );
    UNREFERENCED_PARAMETER( pbScratch );
    UNREFERENCED_PARAMETER( cbScratch );

    return &peObj->d.uint32[0];
}



VOID
SYMCRYPT_CALL
SymCryptFdefIntToModulus(
    _In_                            PCSYMCRYPT_INT      piSrc,
    _Out_                           PSYMCRYPT_MODULUS   pmDst,
                                    UINT32              averageOperations,
                                    UINT32              flags,
    _Out_writes_bytes_( cbScratch ) PBYTE               pbScratch,
                                    SIZE_T              cbScratch )
{
    pmDst->flags = flags;
    SymCryptIntToDivisor( piSrc, &pmDst->Divisor, averageOperations, flags & SYMCRYPT_FLAG_DATA_PUBLIC, pbScratch, cbScratch );

    pmDst->type = SymCryptFdefDecideModulusType( piSrc, pmDst->nDigits, averageOperations, flags );

    SYMCRYPT_MOD_CALL( pmDst ) modulusInit( pmDst, pbScratch, cbScratch );
}

VOID
SYMCRYPT_CALL
SymCryptFdefIntToModElement(
    _In_                            PCSYMCRYPT_INT          piSrc,
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    SymCryptFdefRawDivMod(
        SYMCRYPT_FDEF_INT_PUINT32( piSrc ),
        piSrc->nDigits,
        &pmMod->Divisor,
        NULL,                   // throw away the quotient
        &peDst->d.uint32[0],
        pbScratch,
        cbScratch );

    SYMCRYPT_MOD_CALL( pmMod ) modSetPost( pmMod, peDst, pbScratch, cbScratch );
}

VOID
SYMCRYPT_CALL
SymCryptFdefModElementToIntGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCUINT32                pSrc,
    _Out_                           PSYMCRYPT_INT           piDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    memcpy( SYMCRYPT_FDEF_INT_PUINT32( piDst ), pSrc, pmMod->nDigits * SYMCRYPT_FDEF_DIGIT_SIZE );

    SymCryptWipe( &SYMCRYPT_FDEF_INT_PUINT32( piDst )[pmMod->nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32], (piDst->nDigits - pmMod->nDigits) * SYMCRYPT_FDEF_DIGIT_SIZE );

    SymCryptFdefClaimScratch( pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( pmMod->nDigits ) );
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptFdefModElementSetValueGeneric( 
    _In_reads_bytes_( cbSrc )       PCBYTE                  pbSrc, 
                                    SIZE_T                  cbSrc, 
                                    SYMCRYPT_NUMBER_FORMAT  format, 
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    SYMCRYPT_ERROR scError;
    UINT32  nDigits = pmMod->nDigits;

    SymCryptFdefClaimScratch( pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ) );

    SYMCRYPT_ASSERT( cbSrc <= nDigits * SYMCRYPT_FDEF_DIGIT_SIZE );

    scError = SymCryptFdefRawSetValue( pbSrc, cbSrc, format, &peDst->d.uint32[0], nDigits );
    if( scError != SYMCRYPT_NO_ERROR )
    {
        goto cleanup;
    }

    SymCryptFdefRawDivMod(
        &peDst->d.uint32[0], 
        nDigits,
        &pmMod->Divisor,
        NULL,
        &peDst->d.uint32[0], 
        pbScratch, 
        cbScratch );

    scError = SYMCRYPT_NO_ERROR;

cleanup:
    return scError;
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptFdefModElementGetValue( 
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_writes_bytes_( cbDst )     PBYTE                   pbDst, 
                                    SIZE_T                  cbDst, 
                                    SYMCRYPT_NUMBER_FORMAT  format,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    SYMCRYPT_ERROR scError;
    PCUINT32 pUint32;
    UINT32  nDigits = pmMod->nDigits;
    

    SymCryptFdefClaimScratch( pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ) );

    SYMCRYPT_ASSERT( cbDst <= nDigits * SYMCRYPT_FDEF_DIGIT_SIZE );

    pUint32 = SYMCRYPT_MOD_CALL( pmMod ) modPreGet( pmMod, peSrc, pbScratch, cbScratch );

    scError = SymCryptFdefRawGetValue( pUint32, nDigits, pbDst, cbDst, format );

    return scError;
}

UINT32
SYMCRYPT_CALL
SymCryptFdefModElementIsEqual(
    _In_    PCSYMCRYPT_MODULUS     pmMod,
    _In_    PCSYMCRYPT_MODELEMENT  peSrc1,
    _In_    PCSYMCRYPT_MODELEMENT  peSrc2 )
{
    UINT32 d;
    UINT32 i;

    d = 0;
    for( i=0; i < pmMod->nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32 ; i++ )
    {
        d |= peSrc1->d.uint32[i] ^ peSrc2->d.uint32[i];
    }

    return SYMCRYPT_MASK32_ZERO( d );
}

UINT32
SYMCRYPT_CALL
SymCryptFdefModElementIsZero(
    _In_    PCSYMCRYPT_MODULUS     pmMod,
    _In_    PCSYMCRYPT_MODELEMENT  peSrc )
{
    UINT32 d;
    UINT32 i;

    d = 0;
    for( i=0; i < pmMod->nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32 ; i++ )
    {
        d |= peSrc->d.uint32[i];        // Check that all bits are zero
    }

    return SYMCRYPT_MASK32_ZERO( d );
}

VOID
SYMCRYPT_CALL
SymCryptFdefModAddGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    UINT32 c;
    UINT32 d;
    UINT32 nDigits = pmMod->nDigits;

    SymCryptFdefClaimScratch( pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ) );

    //
    // Doing add/cmp/sub might be faster or not.
    // Masked add is hard because the mask operations destroy the carry flag.
    // 

	// dcl - cleanup?

//    c = SymCryptFdefRawAdd( &pSrc1->uint32[0], &pSrc2->uint32[0], &pDst->uint32[0], nDigits);
//    d = SymCryptFdefRawSub( &pDst->uint32[0], &pMod->Divisor.Int.uint32[0], &pDst->uint32[0], nDigits );
//    e = SymCryptFdefRawMaskedAdd( &pDst->uint32[0], &pMod->Divisor.Int.uint32[0], 0 - (c^d), nDigits );

    c = SymCryptFdefRawAdd( &peSrc1->d.uint32[0], &peSrc2->d.uint32[0], &peDst->d.uint32[0], nDigits );
    d = SymCryptFdefRawSub( &peDst->d.uint32[0], SYMCRYPT_FDEF_INT_PUINT32( &pmMod->Divisor.Int ), (PUINT32) pbScratch, nDigits );
    SymCryptFdefMaskedCopy( pbScratch, (PBYTE) &peDst->d.uint32[0], nDigits, (c^d) - 1 );

    // We can't have a carry in the first addition, and no carry in the subtraction. 
    SYMCRYPT_ASSERT( !( c == 1 && d == 0 ) );
}

VOID
SYMCRYPT_CALL
SymCryptFdefModSubGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    UINT32 c;
    UINT32 d;
    UINT32 nDigits = pmMod->nDigits;

    SymCryptFdefClaimScratch( pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ) );

    c = SymCryptFdefRawSub( &peSrc1->d.uint32[0], &peSrc2->d.uint32[0], &peDst->d.uint32[0], nDigits );
    d = SymCryptFdefRawAdd( &peDst->d.uint32[0], SYMCRYPT_FDEF_INT_PUINT32( &pmMod->Divisor.Int ), (PUINT32) pbScratch, nDigits );
    SymCryptFdefMaskedCopy( pbScratch, (PBYTE) &peDst->d.uint32[0], nDigits, 0 - c );

    SYMCRYPT_ASSERT( !(c == 1 && d == 0) );
}


VOID
SYMCRYPT_CALL
SymCryptFdefModNegGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    UINT32 nDigits = pmMod->nDigits;
    UINT32 isZero;
    UINT32 i;

    SymCryptFdefClaimScratch( pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ) );

    //
    // We have to be careful to handle the value 0 properly as it does NOT map to Modulus - Value.
    //
    isZero = SymCryptFdefRawIsEqualUint32( &peSrc->d.uint32[0], nDigits , 0 );
    SymCryptFdefRawSub( SYMCRYPT_FDEF_INT_PUINT32( &pmMod->Divisor.Int ), &peSrc->d.uint32[0], &peDst->d.uint32[0], nDigits );

    // Now we set the result to zero if the input was zero
    for( i=0; i< nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32; i++ )
    {
        peDst->d.uint32[i] &= ~isZero;
    }
}

VOID
SYMCRYPT_CALL
SymCryptFdefModElementSetValueUint32Generic( 
                                    UINT32                  value, 
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    UINT32 nDigits = pmMod->nDigits;

    SymCryptFdefClaimScratch( pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ) );

    if( pmMod->Divisor.nBits <= 32 && value >= SYMCRYPT_FDEF_INT_PUINT32( &pmMod->Divisor.Int )[0] )
        {
            // The value is >=  the modulus; this is not supported
            SymCryptFatal( 'stvm' );
        }

    peDst->d.uint32[0] = value;

    SymCryptWipe( &peDst->d.uint32[1], nDigits * SYMCRYPT_FDEF_DIGIT_SIZE - sizeof( UINT32 ) );
}

VOID
SYMCRYPT_CALL
SymCryptFdefModElementSetValueNegUint32( 
                                    UINT32                  value, 
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    UINT32 nDigits = pmMod->nDigits;

    SymCryptFdefClaimScratch( pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ) );

    if( pmMod->Divisor.nBits <= 32 && value >= SYMCRYPT_FDEF_INT_PUINT32( &pmMod->Divisor.Int )[0] )
    {
        // The value is >=  the modulus; this is not supported
        SymCryptFatal( 'stvn' );
    }

    if( value == 0 )
    {
        SymCryptWipe( &peDst->d.uint32[0], nDigits * SYMCRYPT_FDEF_DIGIT_SIZE );
    } else {
        SymCryptFdefRawSubUint32( SYMCRYPT_FDEF_INT_PUINT32( &pmMod->Divisor.Int ), value, &peDst->d.uint32[0], nDigits );
    }

    //
    // Possible future optimization: we can optimize the value==0 and value==1 cases on a per-type basis
    //
    SYMCRYPT_MOD_CALL( pmMod ) modSetPost( pmMod, peDst, pbScratch, cbScratch );
}

#define FDEF_MOD_SET_RANDOM_GENERIC_LIMIT   (1000)

VOID
SYMCRYPT_CALL
SymCryptFdefModSetRandomGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
                                    UINT32                  flags,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    UINT32 offset;
    UINT32 ulimit;
    UINT32 nDigits = pmMod->nDigits;
    UINT32 nUsedBytes;
    BOOLEAN tryAgain;
    UINT32 mask;
    UINT32 i;
    UINT32 c;
    UINT32 cntr;
    PUINT32 pDst = &peDst->d.uint32[0];
    PCUINT32 pMod = SYMCRYPT_FDEF_INT_PUINT32( &pmMod->Divisor.Int );

    SymCryptFdefClaimScratch( pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ) );

    if( (flags & SYMCRYPT_FLAG_MODRANDOM_ALLOW_ZERO) != 0 && (flags & SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE) == 0 )
    {
        // It is invalid to allow 0 but not 1
        SymCryptFatal( 'unsp' );
    }

    if( (flags & SYMCRYPT_FLAG_MODRANDOM_ALLOW_ZERO) != 0 )
    {
        offset = 0;
    } else if( (flags & SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE) != 0 )
    {
        offset = 1;
    } else
    {
        offset = 2;
    }

    if( (flags & SYMCRYPT_FLAG_MODRANDOM_ALLOW_MINUSONE ) )
    {
        ulimit = 0;
    } else {
        ulimit = 1;
    }

    //
    // Special cases for the divisor:
    //  -   When it is 1, the only allowable return value is
    //      0. So we can only have offset==0 and ulimit==0.
    //  -   When it is 2, the only allowable return values are
    //      0 and 1. So we can have offset==0 (regardless
    //      of ulimit) or (offset==1 and ulimit==0).
    //  -   When it is 3, the only allowable return values are
    //      0,1, and 2. So everything other than offset==2 and
    //      ulimit==1 is allowed.
    //
    if ( (pmMod->Divisor.nBits < 3) &&
         (offset + ulimit >= pMod[0]) )
    {
        SymCryptFatal( 'rndX' );
    }

    nUsedBytes = (pmMod->Divisor.nBits + 7)/8;

    for(cntr=0; cntr<FDEF_MOD_SET_RANDOM_GENERIC_LIMIT; cntr++)
    {
        // Wipe all the digits
        SymCryptWipe( pDst, nDigits * SYMCRYPT_FDEF_DIGIT_SIZE );

        // Try random values until we get one we like
        SymCryptCallbackRandom( (PBYTE)pDst, nUsedBytes );
        mask = 0x100 >> ( (8-pmMod->Divisor.nBits) & 7);
        mask -= 1;
        ((PBYTE)pDst)[nUsedBytes-1] &= (BYTE) mask;

        // Add offset + ulimit; later we will subtract ulimit again.
        c = SymCryptFdefRawAddUint32( pDst, offset + ulimit, pDst, nDigits );
        if( c != 0 )
        {
            // We have a carry. The number is too large.
            // At best our final result is one smaller (ulimit) than our current value, but that would still be greater or
            // equal to the modulus.
            // Try again with a new random value.
            continue;
        }

        // Compare to modulus and reject if >= modulus. We can use an efficient early-out algorithm for this
        i = nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;

        tryAgain = FALSE;
        while( i > 0 )
        {
            i--;
            if( pDst[i] > pMod[i] )
            {
                tryAgain = TRUE;
                break;
            }
            if( pDst[i] < pMod[i] )
            {
                tryAgain = FALSE;
                break;
            }
            // Two uint32 values are equal
            if( i == 0 )
            {
                tryAgain = TRUE;
                break;
            }
        }
        if( tryAgain )
        {
            continue;
        }
        // Value is < modulus here
        break;
    }

    if (cntr >= FDEF_MOD_SET_RANDOM_GENERIC_LIMIT)
    {
        SymCryptFatal( 'rndc' );
    }

    // Subtract the ulimit which allows us to avoid Mod-1 if required.
    c = SymCryptFdefRawSubUint32( pDst, ulimit, pDst, nDigits );
    SYMCRYPT_ASSERT( c == 0 );
}

VOID
SYMCRYPT_CALL
SymCryptFdefModDivPow2(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
                                    UINT32                  exp,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    UINT32 nDigits = pmMod->nDigits;
    UINT32 mask;
    UINT64 t;
    UINT64 u;
    UINT32 i;
    PCUINT32 pMod = SYMCRYPT_FDEF_INT_PUINT32( &pmMod->Divisor.Int );

    SymCryptFdefClaimScratch( pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ) );

    // mod must be odd
    SYMCRYPT_ASSERT( (pMod[0] & 1) != 0 );

    if( exp > 1 )
    {
        // If more than one bit, we copy to the destination and work in a loop in-place.
        memcpy( &peDst->d.uint32[0], &peSrc->d.uint32[0], nDigits * SYMCRYPT_FDEF_DIGIT_SIZE );
        peSrc = peDst;
    }

    while( exp > 0 )
    {
        mask = (UINT32)0 - (peSrc->d.uint32[0] & 1);

        t = (UINT64) peSrc->d.uint32[0] + (pMod[0] & mask);
        u = (UINT32) t;
        t >>= 32;

        for( i = 1; i < nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32; i++ )
        {
            t += pMod[i] & mask;
            t += peSrc->d.uint32[i];

            u |= t << 32;

            peDst->d.uint32[i-1] = (UINT32)(u >> 1);
            t >>= 32;
            u >>= 32;
        }
        u |= t << 32;
        peDst->d.uint32[i-1] = (UINT32)( u >> 1 );

        exp -= 1;
    }

    return;
}

VOID
SYMCRYPT_CALL
SymCryptFdefModMulGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    UINT32 nDigits = pmMod->nDigits;
    PUINT32 pTmp = (PUINT32) pbScratch;
    UINT32  scratchOffset = 2 * nDigits * SYMCRYPT_FDEF_DIGIT_SIZE;

    SymCryptFdefClaimScratch( pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ) );
    SYMCRYPT_ASSERT( SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ) >= scratchOffset + SYMCRYPT_FDEF_SCRATCH_BYTES_FOR_INT_DIVMOD( 2 * nDigits, nDigits ) );
    SYMCRYPT_ASSERT_ASYM_ALIGNED( pbScratch );

    // Tmp space is enough for the product plus the DivMod scratch
    
    SymCryptFdefRawMul( &peSrc1->d.uint32[0], nDigits, &peSrc2->d.uint32[0], nDigits, pTmp );
    
    SymCryptFdefRawDivMod( pTmp, 2*nDigits, &pmMod->Divisor, NULL, &peDst->d.uint32[0], pbScratch + scratchOffset, cbScratch - scratchOffset );
}

VOID
SYMCRYPT_CALL
SymCryptFdefModSquareGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    UINT32 nDigits = pmMod->nDigits;
    PUINT32 pTmp = (PUINT32) pbScratch;
    UINT32  scratchOffset = 2 * nDigits * SYMCRYPT_FDEF_DIGIT_SIZE;

    SymCryptFdefClaimScratch( pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ) );
    SYMCRYPT_ASSERT( SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ) >= scratchOffset + SYMCRYPT_FDEF_SCRATCH_BYTES_FOR_INT_DIVMOD( 2 * nDigits, nDigits ) );
    SYMCRYPT_ASSERT_ASYM_ALIGNED( pbScratch );

    // Tmp space is enough for the product plus the DivMod scratch

    SymCryptFdefRawSquare( &peSrc->d.uint32[0], nDigits, pTmp );

    SymCryptFdefRawDivMod( pTmp, 2*nDigits, &pmMod->Divisor, NULL, &peDst->d.uint32[0], pbScratch + scratchOffset, cbScratch - scratchOffset );
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptFdefModInvGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
                                    UINT32                  flags,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    UINT32 nDigits = pmMod->nDigits;
    UINT32 nBytes;
    UINT32 c;

    //
    // This function is called on Montgomery moduli, so it is very careful to only use the generic modular operations.
    //

    SYMCRYPT_ASSERT( cbScratch >= SYMCRYPT_SCRATCH_BYTES_FOR_MODINV( nDigits ) );

    if( (pmMod->flags & (SYMCRYPT_FLAG_DATA_PUBLIC | SYMCRYPT_FLAG_MODULUS_PRIME )) != (SYMCRYPT_FLAG_DATA_PUBLIC | SYMCRYPT_FLAG_MODULUS_PRIME ) )
    {
        // Inversion over non-public or non-prime moduli currently not supported. 
        // Our blinding below only works for prime moduli.
        // As the modulus cannot be blinded, it requires a fully side-channel safe algorithm which is much more complicated and
        // slower.
        // When this is necessary, we will add a second ModInv implementation for those cases.
        SymCryptFatal( 'unsp' );    
    }

    //
    // Algorithm:
    // R = random nonzero value mod Mod
    // X := Src * R (mod Mod)
    // A = X
    // B = Mod      
    // Va = 1
    // Vb = 0
    // invariant: A = Va*X (mod Mod), B = Vb*X (mod Mod), 
    //
    // if( A == 0 ): error
    // 
    // verify (A | B) is odd
    // if B even: swap (A,B), swap( Va, Vb)
    //
    //  repeat:
    //      while( A even ):
    //          A /= 2; Va /= 2 (mod Mod)
    //      if( A == 1 ): break1
    //      (A, Va, B, Vb) = (B-A, Vb - Va, A, Va)
    //      if( A == 0 ): error (not co-prime)

    nBytes = SymCryptSizeofModElementFromModulus( pmMod );
	
    SYMCRYPT_ASSERT( cbScratch >= 4*nBytes );
    PSYMCRYPT_MODELEMENT peR = SymCryptModElementCreate( pbScratch, nBytes, pmMod );
    pbScratch += nBytes;
    PSYMCRYPT_MODELEMENT peX = SymCryptModElementCreate( pbScratch, nBytes, pmMod );
    pbScratch += nBytes;
    PSYMCRYPT_MODELEMENT peVa = SymCryptModElementCreate( pbScratch, nBytes, pmMod );
    pbScratch += nBytes;
    PSYMCRYPT_MODELEMENT peVb = SymCryptModElementCreate( pbScratch, nBytes, pmMod );
    pbScratch += nBytes;
    cbScratch -= 4*nBytes;

    PSYMCRYPT_MODELEMENT peVtmpPtr;

    nBytes = SymCryptSizeofIntFromDigits( nDigits );
    SYMCRYPT_ASSERT( cbScratch >= 3 * nBytes );
    PSYMCRYPT_INT piA = SymCryptIntCreate( pbScratch, nBytes, nDigits );
    pbScratch += nBytes;
    PSYMCRYPT_INT piB = SymCryptIntCreate( pbScratch, nBytes, nDigits );
    pbScratch += nBytes;
    PSYMCRYPT_INT piT = SymCryptIntCreate( pbScratch, nBytes, nDigits );
    pbScratch += nBytes;
    cbScratch -= 3*nBytes;

    PSYMCRYPT_INT piTmpPtr;

    SYMCRYPT_ASSERT( cbScratch >= SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ) );

    // If the data is not public, multiply by a random blinding factor; otherwise copy the value
    if( (flags & SYMCRYPT_FLAG_DATA_PUBLIC) == 0 )
    {
        SymCryptFdefModSetRandomGeneric( pmMod, peR, SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE | SYMCRYPT_FLAG_MODRANDOM_ALLOW_MINUSONE, pbScratch, cbScratch );   //R = random
        SymCryptFdefModMulGeneric( pmMod, peR, peSrc, peX, pbScratch, cbScratch );     // X = R * Src
    } else
    {
        SymCryptFdefModElementCopy( pmMod, peSrc, peX );
    }

    // Set up piA and piB
    SymCryptFdefModElementToIntGeneric( pmMod, &peX->d.uint32[0], piA, pbScratch, cbScratch );   // A = X
    SymCryptIntCopy( SymCryptIntFromModulus( (PSYMCRYPT_MODULUS) pmMod ), piB );          // B = Mod

    // Reject if A = 0, B = 0, or A and B both even
    if( SymCryptIntIsEqualUint32( piA, 0 ) | 
        SymCryptIntIsEqualUint32( piB, 0 ) | 
        (((SymCryptIntGetValueLsbits32( piA ) | SymCryptIntGetValueLsbits32( piB )) & 1) ^ 1) )
    {
        scError = SYMCRYPT_INVALID_ARGUMENT;
        goto cleanup;
    }

    if( SymCryptIntIsEqualUint32( piB, 2 ) )
    {
        // Mod = 2 is a valid input. Luckilly, modular inversion is easy.
        // The rest of the code assumes that Mod is odd. Other even values are not prime.
        SymCryptModElementCopy( pmMod, peSrc, peDst);
        goto cleanup;
    }

    SymCryptFdefModElementSetValueUint32Generic( 1, pmMod, peVa, pbScratch, cbScratch );               // Va = 1
    SymCryptFdefModElementSetValueUint32Generic( 0, pmMod, peVb, pbScratch, cbScratch );               // Vb = 0

    for(;;)
    {
        // invariant: A = Va*X (mod Mod), B = Vb*X (mod Mod), A != 0, B > 1.
        // Remove factors of 2 from A. This loop terminates because A != 0
        // We can speed this up by counting how many times we will do this loop, and then updating A and VA once
        while( (SymCryptIntGetValueLsbits32( piA ) & 1) == 0 )
        {
            SymCryptIntDivPow2( piA, 1, piA );
            SymCryptModDivPow2( pmMod, peVa, 1, peVa, pbScratch, cbScratch );
        }

        if( SymCryptIntIsEqualUint32( piA, 1 ) )
        {
            // A = 1 = Va * X (mod Mod), so Va is the inverse of X
            break;
        }

        c = SymCryptIntSubSameSize( piB, piA, piT );

        // If A != 1 and A=B, then A is the GCD of the original inputs, and there is no inverse
        if( SymCryptIntIsEqualUint32( piT, 0 ) )
        {
            scError = SYMCRYPT_INVALID_ARGUMENT;
            goto cleanup;
        }

        if( c == 0 )
        {
            // B > A, we set B to B-A and swap (B,A)
            // that way we continue our halving on B-A

            SymCryptIntCopy( piT, piB );
            SymCryptFdefModSubGeneric( pmMod, peVb, peVa, peVb, pbScratch, cbScratch );

            piTmpPtr  = piB;  piB  = piA;  piA  = piTmpPtr;
            peVtmpPtr = peVb; peVb = peVa; peVa = peVtmpPtr;
        } else {
            // B < A, Set A to A-B and continue halving A
            SymCryptIntNeg( piT, piA );
            SymCryptFdefModSubGeneric( pmMod, peVa, peVb, peVa, pbScratch, cbScratch );
        }
    }

    // 1 = A = Va * X (mod Mod), so Va is the inverse of X
    // Check computation that we can test in the debugger
    SymCryptFdefModMulGeneric( pmMod, peVa, peX, peVb, pbScratch, cbScratch );
    
    // Actual answer

    // If the data is not public, multiply by the random blinding factor; otherwise copy the value
    if( (flags & SYMCRYPT_FLAG_DATA_PUBLIC) == 0 )
    {
        SymCryptFdefModMulGeneric( pmMod, peVa, peR, peDst, pbScratch, cbScratch );
    } else
    {
        SymCryptFdefModElementCopy( pmMod, peVa, peDst );
    }

cleanup:
    return scError;
}


//=============================
// Montgomery representation

VOID
SYMCRYPT_CALL
SymCryptFdefModulusInitMontgomeryInternal(
    _Inout_                         PSYMCRYPT_MODULUS       pmMod,
                                    UINT32                  nUint32Used,           // R = 2^{32 * this parameter}
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    // Scratch space is big enough for an nDigit+1 byte value + sufficient divmod scratch
    PUINT32 pR2;
    UINT32  cbR2;
    UINT32 nDigits;
    PCUINT32 pMvalue;

    UINT64 M64;
    UINT32 M32;
    PUINT32 modR2;

    nDigits = pmMod->nDigits;
    pMvalue = SYMCRYPT_FDEF_INT_PUINT32( &pmMod->Divisor.Int );
    modR2 = (PUINT32)((PBYTE)&pmMod->Divisor + SymCryptFdefSizeofDivisorFromDigits( nDigits ));

    M32 = pMvalue[0];
    M64 = M32 | ((UINT64)pMvalue[1] << 32);

    SYMCRYPT_ASSERT_ASYM_ALIGNED( pbScratch );

    pmMod->tm.montgomery.Rsqr = modR2;
	// dcl - cleanup?
    //pmMod->tm.montgomery.nUint32Used = nUint32Used;

    // We pre-compute R^2 mod M

    pR2 = (PUINT32) pbScratch;
    cbR2 = (2*nDigits + 1) * SYMCRYPT_FDEF_DIGIT_SIZE;
    SYMCRYPT_ASSERT( cbScratch >= cbR2 );

    // Set it to R^2
    SymCryptWipe( pR2, cbR2 );
    pR2[ 2 * nUint32Used ] = 1;
    SymCryptFdefRawDivMod( pR2, 2*nDigits + 1, &pmMod->Divisor, NULL, modR2, pbScratch + cbR2, cbScratch - cbR2 );

    pmMod->tm.montgomery.inv64 = 0 - SymCryptInverseMod2e64( M64 );
}

VOID
SYMCRYPT_CALL
SymCryptFdefModulusInitMontgomery(
    _Inout_                         PSYMCRYPT_MODULUS       pmMod,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    SymCryptFdefModulusInitMontgomeryInternal( pmMod, pmMod->nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32, pbScratch, cbScratch );
}

VOID
SymCryptFdefMontgomeryReduceC(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PUINT32                 pSrc,
    _Out_                           PUINT32                 pDst )
{
    UINT32 nDigits = pmMod->nDigits;
    UINT32 nWords = nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;
    PCUINT32 pMod = SYMCRYPT_FDEF_INT_PUINT32( &pmMod->Divisor.Int );

    UINT32 hc = 0;
    for( UINT32 i=0; i<nWords; i++ )
    {
        UINT32 m = (UINT32)pmMod->tm.montgomery.inv64 * pSrc[0];
        UINT64 c = 0;
        for( UINT32 j = 0; j < nWords; j++ )
        {
            // Invariant: c < 2^32
            c += SYMCRYPT_MUL32x32TO64( pMod[j], m );
            c += pSrc[j];
            // There is no overflow on C because the max value is
            // (2^32 - 1) * (2^32 - 1) + 2^32 - 1 + 2^32 - 1 = 2^64 - 1.
            pSrc[j] = (UINT32) c;
            c >>= 32;
        }
        c = c + pSrc[nWords] + hc;
        pSrc[nWords] = (UINT32) c;
        hc = c >> 32;
        pSrc++;
    }
    SYMCRYPT_ASSERT( hc < 2 );

    UINT32 d = SymCryptFdefRawSub( pSrc, pMod, pDst, nDigits );

    SYMCRYPT_ASSERT( hc <= d );     // if hc = 1, then d = 1 is mandatory

    SymCryptFdefMaskedCopy( (PCBYTE) pSrc, (PBYTE) pDst, nDigits, hc - (hc | d) );  // copy only if hc=0, d=1
}

VOID
SymCryptFdefMontgomeryReduce(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PUINT32                 pSrc,
    _Out_                           PUINT32                 pDst )
{
#if SYMCRYPT_CPU_AMD64
    if( SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURES_FOR_MULX ) )
    {
        SymCryptFdefMontgomeryReduceMulx( pmMod, pSrc, pDst );
    } else {
        SymCryptFdefMontgomeryReduceAsm( pmMod, pSrc, pDst );
    }
#elif SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_ARM64 | SYMCRYPT_CPU_ARM
    SymCryptFdefMontgomeryReduceAsm( pmMod, pSrc, pDst );
#else
    SymCryptFdefMontgomeryReduceC( pmMod, pSrc, pDst );
#endif
}


VOID 
SYMCRYPT_CALL 
SymCryptFdefModSetPostMontgomery(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Inout_                         PSYMCRYPT_MODELEMENT    peObj,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    // Montgomery representation for X is R*X mod M where R = 2^<nDigits * bits-per-digit>
    // Montgomery reduction performs an implicit division by R
    // This function converts to the internal representation by multiplying by R^2 mod M and then performing a Montgomery reduction
    UINT32 nDigits = pmMod->nDigits;

	// dcl - this should not incur significant cost, consider checking always
    SYMCRYPT_ASSERT( cbScratch >= nDigits * 2 * SYMCRYPT_FDEF_DIGIT_SIZE );
    UNREFERENCED_PARAMETER( cbScratch );

    SymCryptFdefRawMul( &peObj->d.uint32[0], nDigits, pmMod->tm.montgomery.Rsqr, nDigits, (PUINT32) pbScratch );
    SymCryptFdefMontgomeryReduce( pmMod, (PUINT32) pbScratch, &peObj->d.uint32[0] );
}

PCUINT32
SYMCRYPT_CALL
SymCryptFdefModPreGetMontgomery(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peObj,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    PUINT32 pTmp = (PUINT32) pbScratch;
    UINT32 nDigits = pmMod->nDigits;

	// dcl - this should not incur significant cost, consider checking always
    SYMCRYPT_ASSERT( cbScratch >= nDigits * 2 * SYMCRYPT_FDEF_DIGIT_SIZE );
    UNREFERENCED_PARAMETER( cbScratch );

    memcpy( pTmp, &peObj->d.uint32[0], nDigits * SYMCRYPT_FDEF_DIGIT_SIZE );
    SymCryptWipe( pTmp + nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32, nDigits * SYMCRYPT_FDEF_DIGIT_SIZE );
    SymCryptFdefMontgomeryReduce( pmMod, pTmp, pTmp );

    return pTmp;
}

VOID 
SYMCRYPT_CALL 
SymCryptFdefModulusCopyFixupMontgomery(
    _In_                            PCSYMCRYPT_MODULUS      pmSrc,
    _Out_                           PSYMCRYPT_MODULUS       pmDst )
{
    // We only have to fix up the Montgomery-specific stuff here
	// dcl - not sure I understand why you pass pmSrc here
    UNREFERENCED_PARAMETER( pmSrc );
    pmDst->tm.montgomery.Rsqr = (PUINT32)((PBYTE)&pmDst->Divisor + SymCryptFdefSizeofDivisorFromDigits( pmDst->nDigits ));
}

VOID 
SYMCRYPT_CALL 
SymCryptFdefModMulMontgomery(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    UINT32 nDigits = pmMod->nDigits;
    PUINT32 pTmp = (PUINT32) pbScratch;

	// dcl - missing assert?
    UNREFERENCED_PARAMETER( cbScratch );

    SymCryptFdefRawMul( &peSrc1->d.uint32[0], nDigits, &peSrc2->d.uint32[0], nDigits, pTmp );
    SymCryptFdefMontgomeryReduce( pmMod, pTmp, &peDst->d.uint32[0] );
}

#if SYMCRYPT_CPU_AMD64
VOID 
SYMCRYPT_CALL 
SymCryptFdefModMulMontgomeryMulx(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    UINT32 nDigits = pmMod->nDigits;
    PUINT32 pTmp = (PUINT32) pbScratch;

    UNREFERENCED_PARAMETER( cbScratch );

    SymCryptFdefRawMulMulx( &peSrc1->d.uint32[0], nDigits, &peSrc2->d.uint32[0], nDigits, pTmp );
    SymCryptFdefMontgomeryReduceMulx( pmMod, pTmp, &peDst->d.uint32[0] );
}

VOID 
SYMCRYPT_CALL 
SymCryptFdefModMulMontgomeryMulx1024(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    UINT32 nDigits = pmMod->nDigits;
    PUINT32 pTmp = (PUINT32) pbScratch;

    UNREFERENCED_PARAMETER( cbScratch );

    SymCryptFdefRawMulMulx1024( &peSrc1->d.uint32[0], &peSrc2->d.uint32[0], nDigits, pTmp );
    SymCryptFdefMontgomeryReduceMulx1024( pmMod, pTmp, &peDst->d.uint32[0] );
}
#endif


VOID 
SYMCRYPT_CALL 
SymCryptFdefModSquareMontgomery(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    UINT32 nDigits = pmMod->nDigits;
    PUINT32 pTmp = (PUINT32) pbScratch;

    UNREFERENCED_PARAMETER( cbScratch );

    SymCryptFdefRawSquare( &peSrc->d.uint32[0], nDigits, pTmp );
    SymCryptFdefMontgomeryReduce( pmMod, pTmp, &peDst->d.uint32[0] );
}


#if SYMCRYPT_CPU_AMD64
VOID 
SYMCRYPT_CALL 
SymCryptFdefModSquareMontgomeryMulx(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    UINT32 nDigits = pmMod->nDigits;
    PUINT32 pTmp = (PUINT32) pbScratch;

    UNREFERENCED_PARAMETER( cbScratch );

    SymCryptFdefRawSquareMulx( &peSrc->d.uint32[0], nDigits, pTmp );
    SymCryptFdefMontgomeryReduceMulx( pmMod, pTmp, &peDst->d.uint32[0] );
}

VOID 
SYMCRYPT_CALL 
SymCryptFdefModSquareMontgomeryMulx1024(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    UINT32 nDigits = pmMod->nDigits;
    PUINT32 pTmp = (PUINT32) pbScratch;

    UNREFERENCED_PARAMETER( cbScratch );

    SymCryptFdefRawSquareMulx1024( &peSrc->d.uint32[0], nDigits, pTmp );
    SymCryptFdefMontgomeryReduceMulx1024( pmMod, pTmp, &peDst->d.uint32[0] );
}
#endif

SYMCRYPT_ERROR
SYMCRYPT_CALL 
SymCryptFdefModInvMontgomery(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
                                    UINT32                  flags,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    UINT32 nDigits = pmMod->nDigits;
    UINT32 nBytes = nDigits * SYMCRYPT_FDEF_DIGIT_SIZE;
    PUINT32 pTmp = (PUINT32) pbScratch;

    SYMCRYPT_ASSERT_ASYM_ALIGNED( pTmp );

    //
    // We have R*X; we first apply the montgomery reduction twice to get X/R, and then invert that
    // using the generic inversion to get R/X.
    //
	SYMCRYPT_ASSERT( cbScratch >= 2 * nBytes );
    memcpy( pTmp, &peSrc->d.uint32[0], nBytes );

    SymCryptWipe( (PBYTE)pTmp + nBytes, nBytes );
    SymCryptFdefMontgomeryReduce( pmMod, pTmp, pTmp );

    SymCryptWipe( (PBYTE)pTmp + nBytes, nBytes );
    SymCryptFdefMontgomeryReduce( pmMod, pTmp, &peDst->d.uint32[0] );

    scError = SymCryptFdefModInvGeneric( pmMod, peDst, peDst, flags, pbScratch, cbScratch );

    return scError;
}

#if SYMCRYPT_CPU_AMD64

//=====================================
// 256-bit Montgomery modulus code
//

VOID
SYMCRYPT_CALL
SymCryptFdefModAdd256Test(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    SYMCRYPT_ASYM_ALIGN BYTE    buf1[128];
    SYMCRYPT_ASYM_ALIGN BYTE    buf2[128];
    PSYMCRYPT_MODELEMENT peTmp1 = SymCryptModElementCreate( SYMCRYPT_ASYM_ALIGN_UP( buf1 ), sizeof( buf1 ) - SYMCRYPT_ASYM_ALIGN_VALUE, pmMod );
    PSYMCRYPT_MODELEMENT peTmp2 = SymCryptModElementCreate( SYMCRYPT_ASYM_ALIGN_UP( buf2 ), sizeof( buf2 ) - SYMCRYPT_ASYM_ALIGN_VALUE, pmMod );

    (VOID) peTmp1;
    (VOID) peTmp2;

    SymCryptFdefModAdd256Asm( pmMod, peSrc1, peSrc2, peTmp1, pbScratch, cbScratch );
    SymCryptFdefModAddGeneric( pmMod, peSrc1, peSrc2, peTmp2, pbScratch, cbScratch );

    if( memcmp( peTmp1, peTmp2, 64 ) != 0 )
    {
        SymCryptFatal( 42 );
    }

    SymCryptFdefModAdd256Asm( pmMod, peSrc1, peSrc2, peDst, pbScratch, cbScratch );
}

VOID
SYMCRYPT_CALL
SymCryptFdefModMulMontgomery256Test(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    SYMCRYPT_ASYM_ALIGN BYTE    buf1[128];
    SYMCRYPT_ASYM_ALIGN BYTE    buf2[128];
    PSYMCRYPT_MODELEMENT peTmp1 = SymCryptModElementCreate( SYMCRYPT_ASYM_ALIGN_UP( buf1 ), sizeof( buf1 ) - SYMCRYPT_ASYM_ALIGN_VALUE, pmMod );
    PSYMCRYPT_MODELEMENT peTmp2 = SymCryptModElementCreate( SYMCRYPT_ASYM_ALIGN_UP( buf2 ), sizeof( buf2 ) - SYMCRYPT_ASYM_ALIGN_VALUE, pmMod );

    (VOID) peTmp1;
    (VOID) peTmp2;

    SymCryptFdefModMulMontgomery256Asm( pmMod, peSrc1, peSrc2, peTmp1, pbScratch, cbScratch );
    //SymCryptFdefModMulMontgomery( pmMod, peSrc1, peSrc2, peTmp2, pbScratch, cbScratch ); *** This doesn't produce the same result as it reduces a whole digit, not 256 bits

    if( memcmp( peTmp1, peTmp2, 64 ) != 0 )
    {
    //    SymCryptFatal( 42 );
    }

    SymCryptFdefModMulMontgomery256Asm( pmMod, peSrc1, peSrc2, peDst, pbScratch, cbScratch );
}

VOID 
SYMCRYPT_CALL 
SymCryptFdefModSquareMontgomery256(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    SymCryptFdefModMulMontgomery256Asm( pmMod, peSrc, peSrc, peDst, pbScratch, cbScratch );
}

SYMCRYPT_ERROR
SYMCRYPT_CALL 
SymCryptFdefModInvMontgomery256(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
                                    UINT32                  flags,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    UINT32 nBytes = 32;
    PUINT32 pTmp = (PUINT32) pbScratch;

    SYMCRYPT_ASSERT_ASYM_ALIGNED( pTmp );

    //
    // We have R*X; we first apply the montgomery reduction twice to get X/R, and then invert that
    // using the generic inversion to get R/X.
    //
    SYMCRYPT_ASSERT( cbScratch >= 2 * nBytes );
    memcpy( pTmp, &peSrc->d.uint32[0], nBytes );

    SymCryptWipe( (PBYTE)pTmp + nBytes, nBytes );
    SymCryptFdefMontgomeryReduce256Asm( pmMod, pTmp, pTmp );

    SymCryptWipe( (PBYTE)pTmp + nBytes, nBytes );
    SymCryptFdefMontgomeryReduce256Asm( pmMod, pTmp, &peDst->d.uint32[0] );

    scError = SymCryptFdefModInvGeneric( pmMod, peDst, peDst, flags, pbScratch, cbScratch );

    return scError;
}

VOID 
SYMCRYPT_CALL 
SymCryptFdefModSetPostMontgomery256(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Inout_                         PSYMCRYPT_MODELEMENT    peObj,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    // Montgomery representation for X is R*X mod M where R = 2^<nDigits * bits-per-digit>
    // Montgomery reduction performs an implicit division by R
    // This function converts to the internal representation by multiplying by R^2 mod M and then performing a Montgomery reduction
    UINT32 nDigits = pmMod->nDigits;

	// dcl - consider runtime check?
    SYMCRYPT_ASSERT( cbScratch >= nDigits * 2 * SYMCRYPT_FDEF_DIGIT_SIZE );
    UNREFERENCED_PARAMETER( cbScratch );
    UNREFERENCED_PARAMETER( nDigits );

    SymCryptFdefModMulMontgomery256Asm( pmMod, (PSYMCRYPT_MODELEMENT) pmMod->tm.montgomery.Rsqr, peObj, peObj, pbScratch, cbScratch );
}

PCUINT32
SYMCRYPT_CALL
SymCryptFdefModPreGetMontgomery256(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peObj,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    PUINT32 pTmp = (PUINT32) pbScratch;
    UINT32 nDigits = 1;

	// dcl - consider runtime check?
    SYMCRYPT_ASSERT( cbScratch >= nDigits * 2 * SYMCRYPT_FDEF_DIGIT_SIZE );
    UNREFERENCED_PARAMETER( cbScratch );

    memcpy( pTmp, &peObj->d.uint32[0], nDigits * SYMCRYPT_FDEF_DIGIT_SIZE );
    SymCryptWipe( pTmp + nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32, nDigits * SYMCRYPT_FDEF_DIGIT_SIZE );
    SymCryptFdefMontgomeryReduce256Asm( pmMod, pTmp, pTmp );

    // This gives the right result, but it isn't the size that is expected
    // on AMD64 when digits are 512 bits. Wipe the extra bytes
    SymCryptWipeKnownSize( pTmp + 32, 32 );

    return pTmp;
}

VOID
SYMCRYPT_CALL
SymCryptFdefModulusInitMontgomery256(
    _Inout_                         PSYMCRYPT_MODULUS       pmMod,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    SymCryptFdefModulusInitMontgomeryInternal( pmMod, 8, pbScratch, cbScratch );
}

//=====================================
// 512-bit Montgomery modulus code
//

VOID
SYMCRYPT_CALL
SymCryptFdefModMulMontgomery512(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    UINT32 nDigits = pmMod->nDigits;
    PUINT32 pTmp = (PUINT32) pbScratch;

	// dcl - missing assert?
    UNREFERENCED_PARAMETER( cbScratch );

    SymCryptFdefRawMul512Asm( &peSrc1->d.uint32[0], &peSrc2->d.uint32[0], nDigits, pTmp );
    SymCryptFdefMontgomeryReduce512Asm( pmMod, pTmp, &peDst->d.uint32[0] );
}

VOID
SYMCRYPT_CALL
SymCryptFdefModSquareMontgomery512(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    UINT32 nDigits = pmMod->nDigits;
    PUINT32 pTmp = (PUINT32) pbScratch;

    UNREFERENCED_PARAMETER( cbScratch );

    SymCryptFdefRawSquare512Asm( &peSrc->d.uint32[0], nDigits, pTmp );
    SymCryptFdefMontgomeryReduce512Asm( pmMod, pTmp, &peDst->d.uint32[0] );
}

//=====================================
// 1024-bit Montgomery modulus code
//

VOID
SYMCRYPT_CALL
SymCryptFdefModMulMontgomery1024(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    UINT32 nDigits = pmMod->nDigits;
    PUINT32 pTmp = (PUINT32) pbScratch;

	// dcl - missing assert?
    UNREFERENCED_PARAMETER( cbScratch );

    SymCryptFdefRawMul1024Asm( &peSrc1->d.uint32[0], &peSrc2->d.uint32[0], nDigits, pTmp );
    SymCryptFdefMontgomeryReduce1024Asm( pmMod, pTmp, &peDst->d.uint32[0] );
}

VOID
SYMCRYPT_CALL
SymCryptFdefModSquareMontgomery1024(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch )
{
    UINT32 nDigits = pmMod->nDigits;
    PUINT32 pTmp = (PUINT32) pbScratch;

    UNREFERENCED_PARAMETER( cbScratch );

    SymCryptFdefRawSquare1024Asm( &peSrc->d.uint32[0], nDigits, pTmp );
    SymCryptFdefMontgomeryReduce1024Asm( pmMod, pTmp, &peDst->d.uint32[0] );
}

#endif
