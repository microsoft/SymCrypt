//
// Reference implementations
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"


#if INCLUDE_IMPL_REF

char * ImpRef::name = "Ref";

///////////////////////////////////////////////////////
// Poly1305
// For Poly1305 there is a risk that the SymCrypt implementation contains a carry
// propagation error that triggers with probability 2^{-32} or lower.
// The published test vectors are not sufficient to detect issues like that.
// The pseudo-random test vector might not even trigger such an error because it is
// running the same tests every time.
//
// We implement a reference implementation based on the normal big-integer arithmetic,
// and add a truly random test run (that changes every time you run it)./
// Over time, this will run more and more tests, increasing the detection probability of
// even very improbable bugs.
// The random test run has no known answer, but the SymCrypt and reference implementations
// are run side-by-side which provides validation.
//

VOID
RefPoly1305Init( 
    _Out_                                       PREF_POLY1305_STATE pState,
    _In_reads_( SYMCRYPT_POLY1305_KEY_SIZE )    PCBYTE              pbKey )
{
    BYTE key[32];
    SYMCRYPT_ASYM_ALIGN  BYTE scratch[2048];         // Lazy, should be big enough.

    // Copy key to local buffer so that we can clamp it
    memcpy( key, pbKey, 32 );

    // Clamping, directly from the RFC
    key[ 3] &= 15;     
    key[ 7] &= 15;     
    key[11] &= 15;     
    key[15] &= 15;     
    key[ 4] &= 252;     
    key[ 8] &= 252;     
    key[12] &= 252;

    UINT32 nDigits = SymCryptDigitsFromBits( 130 + 1 );     // +1 to deal with the Acc + S addition

    pState->pmMod = SymCryptModulusAllocate( nDigits );
    pState->peAcc = SymCryptModElementAllocate( pState->pmMod );
    pState->peR   = SymCryptModElementAllocate( pState->pmMod );
    pState->peData= SymCryptModElementAllocate( pState->pmMod );
    pState->piS   = SymCryptIntAllocate( nDigits );
    pState->piAcc = SymCryptIntAllocate( nDigits );

    pState->bytesInBuffer = 0;

    // Get the INT object inside the modulus to create the value before we create the modulus
    PSYMCRYPT_INT piP = SymCryptIntFromModulus( pState->pmMod );
    SymCryptIntSetValueUint32( 0, piP );    // P = 0
    SymCryptIntSetBits( piP, 1, 130, 1 );   // P = 2^130
    SymCryptIntSubUint32( piP, 5, piP );    // P = 2^130 - 5

    // Convert integer to modulus. 
    // We specify 10 operation per import/export which isn't quite correct.
    // But it ends up using the Montgomery form which is more optimized for 256-bit operations
    // and gives a 2x perf boost on amd64 which is our primary testing platform.
    SymCryptIntToModulus( piP, pState->pmMod, 10, SYMCRYPT_FLAG_DATA_PUBLIC | SYMCRYPT_FLAG_MODULUS_PRIME, scratch, sizeof( scratch ) );
    piP = NULL; // Can't use this anymore once the modulus object it resides in is initialized.

    // Acc = 0
    SymCryptModElementSetValueUint32( 0, pState->pmMod, pState->peAcc, scratch, sizeof( scratch ) );

    // Set R, S
    SymCryptModElementSetValue( key, 16, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, pState->pmMod, pState->peR, scratch, sizeof( scratch ) );
    SymCryptIntSetValue( key + 16, 16, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, pState->piS );

    SymCryptWipeKnownSize( key, sizeof( key ) );
    SymCryptWipeKnownSize( scratch, sizeof( scratch ) );
}

VOID
RefPoly1305ProcessBlock( 
    _Inout_                 PREF_POLY1305_STATE pState,
    _In_reads_( cbData )    PCBYTE              pbData,
                            SIZE_T              cbData )
{
    SYMCRYPT_ASYM_ALIGN BYTE scratch[2048];         // Lazy, should be big enough.

    CHECK( cbData <= 17, "Block too large" );

    SymCryptModElementSetValue( pbData,
                                cbData,
                                SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, 
                                pState->pmMod,
                                pState->peData, 
                                scratch, 
                                sizeof( scratch ) );
    SymCryptModAdd( pState->pmMod, pState->peAcc, pState->peData, pState->peAcc, scratch, sizeof( scratch ) );
    SymCryptModMul( pState->pmMod, pState->peAcc, pState->peR, pState->peAcc, scratch, sizeof( scratch ) );
    pState->bytesInBuffer = 0;

    SymCryptWipeKnownSize( scratch, sizeof( scratch ) );
}

VOID
RefPoly1305Append(
    _Inout_                 PREF_POLY1305_STATE pState,
    _In_reads_( cbData )    PCBYTE              pbData,
                            SIZE_T              cbData )
{
    while( cbData > 0 )
    {
        pState->block[ pState->bytesInBuffer++ ] = *pbData++;
        cbData --;

        if( pState->bytesInBuffer == 16 )
        {
            pState->block[ pState->bytesInBuffer ] = 1;
            RefPoly1305ProcessBlock( pState, pState->block, pState->bytesInBuffer + 1 );
            pState->bytesInBuffer = 0;
        }
    }
}

VOID
RefPoly1305Result( 
    _Inout_                                         PREF_POLY1305_STATE pState,
    _Out_writes_( SYMCRYPT_POLY1305_RESULT_SIZE )   PBYTE               pbResult )
{
    SYMCRYPT_ASYM_ALIGN BYTE scratch[ 2048 ];

    if( pState->bytesInBuffer != 0 )
    {
        pState->block[ pState->bytesInBuffer ] = 1;
        RefPoly1305ProcessBlock( pState, pState->block, pState->bytesInBuffer + 1 );
        pState->bytesInBuffer = 0;
    }

    SymCryptModElementToInt( pState->pmMod, pState->peAcc, pState->piAcc, scratch, sizeof( scratch ) );
    SymCryptIntAddSameSize( pState->piAcc, pState->piS, pState->piAcc );

    SymCryptIntGetValue( pState->piAcc, pState->block, 17, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST );
    memcpy( pbResult, pState->block, 16 );

    SymCryptWipeKnownSize( scratch, sizeof( scratch ) );

    SymCryptIntFree( pState->piAcc );
    SymCryptIntFree( pState->piS );
    SymCryptModElementFree( pState->pmMod, pState->peData );
    SymCryptModElementFree( pState->pmMod, pState->peR );
    SymCryptModElementFree( pState->pmMod, pState->peAcc );
    SymCryptModulusFree( pState->pmMod );

    SymCryptWipeKnownSize( (PBYTE) pState, sizeof( *pState ) );
}

VOID
RefPoly1305( 
    _In_reads_( SYMCRYPT_POLY1305_KEY_SIZE )        PCBYTE  pbKey,
    _In_reads_( cbData )                            PCBYTE  pbData,
                                                    SIZE_T  cbData,
    _Out_writes_( SYMCRYPT_POLY1305_RESULT_SIZE )   PBYTE   pbResult )
{
    REF_POLY1305_STATE state;

    RefPoly1305Init( &state, pbKey );
    RefPoly1305Append( &state, pbData, cbData );
    RefPoly1305Result( &state, pbResult );
}


template<>
VOID
algImpDataPerfFunction<ImpRef,AlgPoly1305>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    RefPoly1305( buf1, buf2, dataSize, buf3 );
}

template<>
MacImp<ImpRef, AlgPoly1305>::MacImp()
{
    m_perfKeyFunction     = NULL;   // &algImpKeyPerfFunction    <ImpRef, AlgPoly1305>;
    m_perfCleanFunction   = NULL;   //&algImpCleanPerfFunction  <ImpRef, AlgPoly1305>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpRef, AlgPoly1305>;
}

template<>
MacImp<ImpRef, AlgPoly1305>::~MacImp<ImpRef, AlgPoly1305>()
{
}

template<>
NTSTATUS MacImp<ImpRef, AlgPoly1305>::mac( 
    _In_reads_( cbKey )      PCBYTE pbKey,   SIZE_T cbKey, 
    _In_reads_( cbData )     PCBYTE pbData,  SIZE_T cbData, 
    _Out_writes_( cbResult )  PBYTE pbResult, SIZE_T cbResult )
{
    CHECK( cbKey == 32, "?" );
    CHECK( cbResult == 16, "?" );

    RefPoly1305( pbKey, pbData, cbData, pbResult );

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
MacImp<ImpRef, AlgPoly1305>::init( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey ) 
{
    CHECK( cbKey == 32, "?" );
    RefPoly1305Init( &state.state, pbKey );

    return STATUS_SUCCESS;
}

template<>
VOID MacImp<ImpRef, AlgPoly1305>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    RefPoly1305Append( &state.state, pbData, cbData );
}

template<>
VOID MacImp<ImpRef, AlgPoly1305>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    CHECK( cbResult == 16, "Result len error Ref/Poly1305" );
    RefPoly1305Result( &state.state, pbResult );
}

template<>
SIZE_T MacImp<ImpRef, AlgPoly1305>::inputBlockLen()
{
    return SYMCRYPT_POLY1305_RESULT_SIZE;
}

template<>
SIZE_T MacImp<ImpRef, AlgPoly1305>::resultLen()
{
    return SYMCRYPT_POLY1305_RESULT_SIZE;
}


/////////////////////////////////////////////////////////////////////////////////////
// Primality test
// 
// To test the primality-test function of SymCrypt, we need something to compare it against.
// We implement Rabin-Miller in the simple (and insecure) way.
//

BOOL
SYMCRYPT_CALL
RefIsPossiblePrime(
    _In_                            PCSYMCRYPT_INT  piSrc,
    _Out_writes_bytes_( cbScratch ) PBYTE           pbScratch,
                                    SIZE_T          cbScratch )
// If piSrc is a prime, this function returns TRUE.
// If piSrc is a composite, this function returns FALSE at least 75% of the time.
{
    UINT32 nD;
    PSYMCRYPT_MODULUS pmMod = NULL;
    PSYMCRYPT_MODELEMENT peBase = NULL;
    PSYMCRYPT_MODELEMENT peTmp = NULL;
    UINT32 lwb;
    BOOL res = FALSE;
    UINT32 stopBit;
    UINT32 currentBit;
    
    lwb = SymCryptIntGetValueLsbits32( piSrc );

    // Handle small values that confuse the later code
    if( SymCryptIntBitsizeOfValue( piSrc ) < 10 )
    {
        if( lwb < 2  )
        {
            // 0 and 1
            res = FALSE;
            goto cleanup;
        }
        if( lwb <= 3 )
        {
            // 2 and 3
            res = TRUE;
            goto cleanup;
        }
    }

    // Other even numbers are not prime
    if( (lwb & 1) == 0 )
    {
        res = FALSE;
        goto cleanup;
    }

    // Here we know piSrc is odd and > 3

    // Create a modulus
    nD = SymCryptIntDigitsizeOfObject( piSrc );
    pmMod = SymCryptModulusAllocate( nD );
    CHECK( pmMod != NULL, "Out of memory" );    
    SymCryptIntToModulus( piSrc, pmMod, 0, 0, pbScratch, cbScratch );

    // Create a mod elements
    peBase = SymCryptModElementAllocate( pmMod );
    peTmp = SymCryptModElementAllocate( pmMod );
    CHECK( peBase != NULL && peTmp != NULL, "Out of memory" );

    // Pick a random base. Do not allow 0, 1, or -1 as they never show a number to be composite.
    SymCryptModSetRandom( pmMod, peBase, 0, pbScratch, cbScratch );

    // Find the stop bit for the base exponentiation. This is the first nonzero bit closest to the parity bit
    stopBit = 1;
    while( SymCryptIntGetBit( piSrc, stopBit ) == 0 )
    {
        // This loops ends because the value is >= 3;
        stopBit += 1;
    }

    currentBit = SymCryptIntBitsizeOfValue( piSrc ) - 1;
    CHECK( SymCryptIntGetBit( piSrc, currentBit ) == 1, "?" );
    SymCryptModElementCopy( pmMod, peBase, peTmp );

    // Do the basic exponentiation
    // Invariant: peTmp = base ^ piSrc[*..currentBit] (inclusive of currentBit)
    while( currentBit > stopBit )
    {
        currentBit -= 1;
        SymCryptModSquare( pmMod, peTmp, peTmp, pbScratch, cbScratch );
        if( SymCryptIntGetBit( piSrc, currentBit ) != 0 )
        {
            SymCryptModMul( pmMod, peTmp, peBase, peTmp, pbScratch, cbScratch );
        }
    }
    // Now we have currentBit = stopBit, so the basic exponentiation is done

    // We don't need peBase anymore, so we use it as scratch
    SymCryptModElementSetValueUint32( 1, pmMod, peBase, pbScratch, cbScratch );
    if( SymCryptModElementIsEqual( pmMod, peBase, peTmp ) )
    {
        // base exponentiation resulted in 1, this could be a prime.
        res = TRUE;
        goto cleanup;
    }

    // Now we need to see a -1 before we reach 1 as we keep squaring
    SymCryptModElementSetValueNegUint32( 1, pmMod, peBase, pbScratch, cbScratch );
    for(;;)
    {
        // We only check that we reach -1. If we get to 1 before we reach -1, then
        // we'll keep looping with Tmp = 1 until we reach the currentBit limit at which point we
        // conclude Src is a composite.
    
        if( SymCryptModElementIsEqual( pmMod, peBase, peTmp ) )
        {
            // found -1, piSrc could be prime
            res = TRUE;
            goto cleanup;
        }

        if( currentBit == 0 )
        {
            // We've reached base^(Src-1) and not found -1 or 1. Src is not a composite
            res = FALSE;
            goto cleanup;
        }

        // square
        SymCryptModSquare( pmMod, peTmp, peTmp, pbScratch, cbScratch );
        currentBit -= 1;
    }

cleanup:
    if( peTmp != NULL )
    {
        SymCryptModElementFree( pmMod, peTmp );
        peTmp = NULL;
    }

    if( peBase != NULL )
    {
        SymCryptModElementFree( pmMod, peBase );
        peBase = NULL;
    }

    if( pmMod != NULL )
    {
        SymCryptModulusFree( pmMod );
        pmMod = NULL;
    }

    return res;
}                                    

BOOL
SYMCRYPT_CALL
RefIsPrime(
    _In_                            PCSYMCRYPT_INT  piSrc,
    _Out_writes_bytes_( cbScratch ) PBYTE           pbScratch,
                                    SIZE_T          cbScratch )
{
    // Just iterate the probabalistic test 64 times to achieve an error rate of 2^-128.
    for( int i=0; i<64; i++ )
    {
        if( !RefIsPossiblePrime( piSrc, pbScratch, cbScratch ) )
        {
            return FALSE;
        }
    }
    return TRUE;
}

//////////////////////////////////////////////////////////////////////////
// AddAlgs
//


VOID
addRefAlgs()
{
    // Ref algorithms use SymCrypt, so we initialize it (again)
    SymCryptInit();

    //
    // We use a tempate function to decide which algorithm implementations to
    // run.
    // We could make each algorithm auto-register using static initializers,
    // but this is test code and we want to be able to test (and dynamically disable)
    // the initializer code. So we do it manually once.
    //

    addImplementationToGlobalList<MacImp<ImpRef, AlgPoly1305>>();
}

#endif //INCLUDE_IMPL_REF
