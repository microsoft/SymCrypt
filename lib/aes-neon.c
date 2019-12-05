//
// aes-neon.c   code for AES implementation
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// All NEON-based code for AES operations
//

#include "precomp.h"

#if SYMCRYPT_CPU_ARM64

static const __n128 n128_zero = {0};
//#define vzeroq()    (n128_zero)
#define vzeroq()    vdupq_n_u64(0)


VOID
SYMCRYPT_CALL
SymCryptAes4SboxNeon( _In_reads_(4) PCBYTE pIn, _Out_writes_(4) PBYTE pOut )
{
    /*
    __m128i x;

    x = _mm_set1_epi32( *(int *) pIn );

    x = _mm_aeskeygenassist_si128( x, 0 );

    *(unsigned *) pOut = x.m128i_u32[0];
    */
    __n128 x;

    //
    // There is no pure S-box lookup instruction, but the AESE instruction
    // does a ShiftRow followed by a SubBytes.
    // If we duplicate the input value to all 4 lanes, then the ShiftRow does nothing
    // and the SubBytes will do the S-box lookup.
    //
    x = vdupq_n_u32( *(unsigned int *) pIn );
    x = aese_u8( x, vzeroq() );
    vst1q_lane_s32( pOut, x, 0 );
    //*(unsigned int *) pOut = x.n128_u32[0];
}


VOID
SYMCRYPT_CALL
SymCryptAesCreateDecryptionRoundKeyNeon(
    _In_reads_(16)      PCBYTE  pEncryptionRoundKey,
    _Out_writes_(16)    PBYTE   pDecryptionRoundKey )
{
    *(__n128 *) pDecryptionRoundKey = aesimc_u8( *(__n128 *)pEncryptionRoundKey );
}

//
// When doing a full round of AES encryption, make sure to give compiler opportunity to schedule dependent
// aese/aesmc pairs to enable instruction fusion in many arm64 CPUs
//
#define AESE_AESMC( c, rk ) \
{ \
    c = aese_u8( c, rk ); \
    c = aesmc_u8( c ); \
};

#define AES_ENCRYPT_1( pExpandedKey, c0 ) \
{ \
    const __n128 *keyPtr; \
    const __n128 *keyLimit; \
    __n128 roundKey; \
\
    keyPtr = (const __n128 *)&pExpandedKey->RoundKey[0]; \
    keyLimit = ((const __n128 *)pExpandedKey->lastEncRoundKey) - 1; \
\
    roundKey = *keyPtr++; \
\
    while ( keyPtr < keyLimit ) \
    { \
        AESE_AESMC( c0, roundKey ) \
        roundKey = *keyPtr++; \
    } \
\
    c0 = aese_u8( c0, roundKey ); \
    roundKey = *keyPtr; \
    c0 = veorq_u8( c0, roundKey ); \
};

#define AES_ENCRYPT_4( pExpandedKey, c0, c1, c2, c3 ) \
{ \
    const __n128 *keyPtr; \
    const __n128 *keyLimit; \
    __n128 roundKey; \
\
    keyPtr = (const __n128 *)&pExpandedKey->RoundKey[0]; \
    keyLimit = ((const __n128 *)pExpandedKey->lastEncRoundKey) - 1; \
\
    roundKey = *keyPtr++; \
\
    while ( keyPtr < keyLimit ) \
    { \
        AESE_AESMC( c0, roundKey ) \
        AESE_AESMC( c1, roundKey ) \
        AESE_AESMC( c2, roundKey ) \
        AESE_AESMC( c3, roundKey ) \
        roundKey = *keyPtr++; \
    } \
\
    c0 = aese_u8( c0, roundKey ); \
    c1 = aese_u8( c1, roundKey ); \
    c2 = aese_u8( c2, roundKey ); \
    c3 = aese_u8( c3, roundKey ); \
    roundKey = *keyPtr; \
    c0 = veorq_u8( c0, roundKey ); \
    c1 = veorq_u8( c1, roundKey ); \
    c2 = veorq_u8( c2, roundKey ); \
    c3 = veorq_u8( c3, roundKey ); \
};

#define AES_ENCRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 ) \
{ \
    const __n128 *keyPtr; \
    const __n128 *keyLimit; \
    __n128 roundKey; \
\
    keyPtr = (const __n128 *)&pExpandedKey->RoundKey[0]; \
    keyLimit = ((const __n128 *)pExpandedKey->lastEncRoundKey) - 1; \
\
    roundKey = *keyPtr++; \
\
    while ( keyPtr < keyLimit ) \
    { \
        AESE_AESMC( c0, roundKey ) \
        AESE_AESMC( c1, roundKey ) \
        AESE_AESMC( c2, roundKey ) \
        AESE_AESMC( c3, roundKey ) \
        AESE_AESMC( c4, roundKey ) \
        AESE_AESMC( c5, roundKey ) \
        AESE_AESMC( c6, roundKey ) \
        AESE_AESMC( c7, roundKey ) \
        roundKey = *keyPtr++; \
    } \
\
    c0 = aese_u8( c0, roundKey ); \
    c1 = aese_u8( c1, roundKey ); \
    c2 = aese_u8( c2, roundKey ); \
    c3 = aese_u8( c3, roundKey ); \
    c4 = aese_u8( c4, roundKey ); \
    c5 = aese_u8( c5, roundKey ); \
    c6 = aese_u8( c6, roundKey ); \
    c7 = aese_u8( c7, roundKey ); \
    roundKey = *keyPtr; \
    c0 = veorq_u8( c0, roundKey ); \
    c1 = veorq_u8( c1, roundKey ); \
    c2 = veorq_u8( c2, roundKey ); \
    c3 = veorq_u8( c3, roundKey ); \
    c4 = veorq_u8( c4, roundKey ); \
    c5 = veorq_u8( c5, roundKey ); \
    c6 = veorq_u8( c6, roundKey ); \
    c7 = veorq_u8( c7, roundKey ); \
};

//
// When doing a full round of AES decryption, make sure to give compiler opportunity to schedule dependent
// aesd/aesimc pairs to enable instruction fusion in many arm64 CPUs
//
#define AESD_AESIMC( c, rk ) \
{ \
    c = aesd_u8( c, rk ); \
    c = aesimc_u8( c ); \
};

#define AES_DECRYPT_1( pExpandedKey, c0 ) \
{ \
    const __n128 *keyPtr; \
    const __n128 *keyLimit; \
    __n128 roundKey; \
\
    keyPtr = (const __n128 *)pExpandedKey->lastEncRoundKey; \
    keyLimit = ((const __n128 *)pExpandedKey->lastDecRoundKey) - 1; \
\
    roundKey = *keyPtr++; \
\
    while ( keyPtr < keyLimit ) \
    { \
        AESD_AESIMC( c0, roundKey ) \
        roundKey = *keyPtr++; \
    } \
\
    c0 = aesd_u8( c0, roundKey ); \
    roundKey = *keyPtr; \
    c0 = veorq_u8( c0, roundKey ); \
};

#define AES_DECRYPT_4( pExpandedKey, c0, c1, c2, c3 ) \
{ \
    const __n128 *keyPtr; \
    const __n128 *keyLimit; \
    __n128 roundKey; \
\
    keyPtr = (const __n128 *)pExpandedKey->lastEncRoundKey; \
    keyLimit = ((const __n128 *)pExpandedKey->lastDecRoundKey) - 1; \
\
    roundKey = *keyPtr++; \
\
    while ( keyPtr < keyLimit ) \
    { \
        AESD_AESIMC( c0, roundKey ) \
        AESD_AESIMC( c1, roundKey ) \
        AESD_AESIMC( c2, roundKey ) \
        AESD_AESIMC( c3, roundKey ) \
        roundKey = *keyPtr++; \
    } \
\
    c0 = aesd_u8( c0, roundKey ); \
    c1 = aesd_u8( c1, roundKey ); \
    c2 = aesd_u8( c2, roundKey ); \
    c3 = aesd_u8( c3, roundKey ); \
    roundKey = *keyPtr; \
    c0 = veorq_u8( c0, roundKey ); \
    c1 = veorq_u8( c1, roundKey ); \
    c2 = veorq_u8( c2, roundKey ); \
    c3 = veorq_u8( c3, roundKey ); \
};

#define AES_DECRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 ) \
{ \
    const __n128 *keyPtr; \
    const __n128 *keyLimit; \
    __n128 roundKey; \
\
    keyPtr = (const __n128 *)pExpandedKey->lastEncRoundKey; \
    keyLimit = ((const __n128 *)pExpandedKey->lastDecRoundKey) - 1; \
\
    roundKey = *keyPtr++; \
\
    while ( keyPtr < keyLimit ) \
    { \
        AESD_AESIMC( c0, roundKey ) \
        AESD_AESIMC( c1, roundKey ) \
        AESD_AESIMC( c2, roundKey ) \
        AESD_AESIMC( c3, roundKey ) \
        AESD_AESIMC( c4, roundKey ) \
        AESD_AESIMC( c5, roundKey ) \
        AESD_AESIMC( c6, roundKey ) \
        AESD_AESIMC( c7, roundKey ) \
        roundKey = *keyPtr++; \
    } \
\
    c0 = aesd_u8( c0, roundKey ); \
    c1 = aesd_u8( c1, roundKey ); \
    c2 = aesd_u8( c2, roundKey ); \
    c3 = aesd_u8( c3, roundKey ); \
    c4 = aesd_u8( c4, roundKey ); \
    c5 = aesd_u8( c5, roundKey ); \
    c6 = aesd_u8( c6, roundKey ); \
    c7 = aesd_u8( c7, roundKey ); \
    roundKey = *keyPtr; \
    c0 = veorq_u8( c0, roundKey ); \
    c1 = veorq_u8( c1, roundKey ); \
    c2 = veorq_u8( c2, roundKey ); \
    c3 = veorq_u8( c3, roundKey ); \
    c4 = veorq_u8( c4, roundKey ); \
    c5 = veorq_u8( c5, roundKey ); \
    c6 = veorq_u8( c6, roundKey ); \
    c7 = veorq_u8( c7, roundKey ); \
};



VOID
SYMCRYPT_CALL
SymCryptAesEncryptNeon(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PCBYTE                      pbSrc,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE ) PBYTE                       pbDst )
{
    __n128 c;

    c = *( __n128 * ) pbSrc;

    AES_ENCRYPT_1( pExpandedKey, c );

    *(__n128 *) pbDst = c;
}

VOID
SYMCRYPT_CALL
SymCryptAesDecryptNeon(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PCBYTE                      pbSrc,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE ) PBYTE                       pbDst )
{
    __n128 c;

    c = *( __n128 * ) pbSrc;

    AES_DECRYPT_1( pExpandedKey, c );

    *(__n128 *) pbDst = c;
}


VOID
SYMCRYPT_CALL
SymCryptAesCbcEncryptNeon(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    __n128 c = *(__n128 *)pbChainingValue;
    __n128 d;

    while( cbData >= SYMCRYPT_AES_BLOCK_SIZE )
    {
        d = *(__n128 *)pbSrc;
        c = veorq_u8( c, d );
        AES_ENCRYPT_1( pExpandedKey, c );
        *(__n128 *)pbDst = c;

        pbSrc += SYMCRYPT_AES_BLOCK_SIZE;
        pbDst += SYMCRYPT_AES_BLOCK_SIZE;
        cbData -= SYMCRYPT_AES_BLOCK_SIZE;
    }
    *(__n128 *)pbChainingValue = c;
}

// Disable warnings and VC++ runtime checks for use of uninitialized values (by design)
#pragma warning(push)
#pragma warning( disable: 6001 4701 )
#pragma runtime_checks( "u", off )
VOID
SYMCRYPT_CALL
SymCryptAesCbcDecryptNeon(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    __n128 chain;
    __n128 c0, c1, c2, c3, c4, c5, c6, c7;
    __n128 d0, d1, d2, d3, d4, d5, d6, d7;
    const __n128 * pSrc = (const __n128 *) pbSrc;
    __n128 * pDst = (__n128 *) pbDst;
    SIZE_T  cData = cbData / SYMCRYPT_AES_BLOCK_SIZE;

    if( cData < 1 )
    {
        return;
    }

    chain = *(__n128 *) pbChainingValue;

    //
    // First we do all multiples of 8 blocks
    //

    while( cData >= 8 )
    {
        d0 = c0 = pSrc[0];
        d1 = c1 = pSrc[1];
        d2 = c2 = pSrc[2];
        d3 = c3 = pSrc[3];
        d4 = c4 = pSrc[4];
        d5 = c5 = pSrc[5];
        d6 = c6 = pSrc[6];
        d7 = c7 = pSrc[7];

        AES_DECRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 );

        c0 = veorq_u8( c0, chain );
        c1 = veorq_u8( c1, d0 );
        c2 = veorq_u8( c2, d1 );
        c3 = veorq_u8( c3, d2 );
        c4 = veorq_u8( c4, d3 );
        c5 = veorq_u8( c5, d4 );
        c6 = veorq_u8( c6, d5 );
        c7 = veorq_u8( c7, d6 );
        chain = d7;

        pDst[0] = c0;
        pDst[1] = c1;
        pDst[2] = c2;
        pDst[3] = c3;
        pDst[4] = c4;
        pDst[5] = c5;
        pDst[6] = c6;
        pDst[7] = c7;

        pSrc   += 8;
        pDst   += 8;
        cData  -= 8;
    }

    if( cData >= 1 )
    {
        //
        // There is remaining work to be done
        //
        d0 = c0 = pSrc[0];
        if( cData >= 2 )
        {
        d1 = c1 = pSrc[1];
            if( cData >= 3 )
            {
        d2 = c2 = pSrc[2];
                if( cData >= 4 )
                {
        d3 = c3 = pSrc[3];
                    if( cData >= 5 )
                    {
        d4 = c4 = pSrc[4];
                        if( cData >= 6 )
                        {
        d5 = c5 = pSrc[5];
                            if( cData >= 7 )
                            {
        d6 = c6 = pSrc[6];
                            }
                        }
                    }
                }
            }
        }

        //
        // Decrypt 1, 4, or 8 blocks in AES-CBC mode. This might decrypt uninitialized registers,
        // but those will not be used when we store the results.
        //
        if( cData > 4 )
        {
            AES_DECRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 );
            c0 = veorq_u8( c0, chain );
            c1 = veorq_u8( c1, d0 );
            c2 = veorq_u8( c2, d1 );
            c3 = veorq_u8( c3, d2 );
            c4 = veorq_u8( c4, d3 );
            c5 = veorq_u8( c5, d4 );
            c6 = veorq_u8( c6, d5 );
        }
        else if( cData > 1 )
        {
            AES_DECRYPT_4( pExpandedKey, c0, c1, c2, c3 );
            c0 = veorq_u8( c0, chain );
            c1 = veorq_u8( c1, d0 );
            c2 = veorq_u8( c2, d1 );
            c3 = veorq_u8( c3, d2 );
        } else
        {
            AES_DECRYPT_1( pExpandedKey, c0 );
            c0 = veorq_u8( c0, chain );
        }

        chain = pSrc[ cData - 1];
        pDst[0] = c0;
        if( cData >= 2 )
        {
        pDst[1] = c1;
            if( cData >= 3 )
            {
        pDst[2] = c2;
                if( cData >= 4 )
                {
        pDst[3] = c3;
                    if( cData >= 5 )
                    {
        pDst[4] = c4;
                        if( cData >= 6 )
                        {
        pDst[5] = c5;
                            if( cData >= 7 )
                            {
        pDst[6] = c6;
                            }
                        }
                    }
                }
            }
        }
    }

    *(__n128 *)pbChainingValue = chain;

    return;
}
#pragma runtime_checks( "u", restore )
#pragma warning( pop )



VOID
SYMCRYPT_CALL
SymCryptAesCbcMacNeon(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbData,
                                                SIZE_T                      cbData )
{
    __n128 c = *(__n128 *)pbChainingValue;
    __n128 d;

    while( cbData >= SYMCRYPT_AES_BLOCK_SIZE )
    {
        d = *(__n128 *)pbData;
        c = veorq_u8( c, d );
        AES_ENCRYPT_1( pExpandedKey, c );

        pbData += SYMCRYPT_AES_BLOCK_SIZE;
        cbData -= SYMCRYPT_AES_BLOCK_SIZE;
    }
    *(__n128 *)pbChainingValue = c;
}

// Disable warnings and VC++ runtime checks for use of uninitialized values (by design)
#pragma warning(push)
#pragma warning( disable: 6001 4701 )
#pragma runtime_checks( "u", off )
VOID
SYMCRYPT_CALL
SymCryptAesEcbEncryptNeon(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
    __n128 c0, c1, c2, c3, c4, c5, c6, c7;
    const __n128 * pSrc = (const __n128 *) pbSrc;
    __n128 * pDst = (__n128 *) pbDst;

    while( cbData >= 8 * SYMCRYPT_AES_BLOCK_SIZE )
    {
        c0 = pSrc[0];
        c1 = pSrc[1];
        c2 = pSrc[2];
        c3 = pSrc[3];
        c4 = pSrc[4];
        c5 = pSrc[5];
        c6 = pSrc[6];
        c7 = pSrc[7];

        AES_ENCRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 );

        pDst[0] = c0;
        pDst[1] = c1;
        pDst[2] = c2;
        pDst[3] = c3;
        pDst[4] = c4;
        pDst[5] = c5;
        pDst[6] = c6;
        pDst[7] = c7;

        pSrc  += 8;
        pDst  += 8;
        cbData -= 8 * SYMCRYPT_AES_BLOCK_SIZE;
    }

    if( cbData < 16 )
    {
        return;
    }

    c0 = pSrc[0];
    if( cbData >= 32 )
    {
    c1 = pSrc[1];
        if( cbData >= 48 )
        {
    c2 = pSrc[2];
            if( cbData >= 64 )
            {
    c3 = pSrc[3];
                if( cbData >= 80 )
                {
    c4 = pSrc[4];
                    if( cbData >= 96 )
                    {
    c5 = pSrc[5];
                        if( cbData >= 112 )
                        {
    c6 = pSrc[6];
                        }
                    }
                }
            }
        }
    }

    if( cbData >= 5 * SYMCRYPT_AES_BLOCK_SIZE )
    {
        AES_ENCRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 );
    }
    else if( cbData >= 2 * SYMCRYPT_AES_BLOCK_SIZE )
    {
        AES_ENCRYPT_4( pExpandedKey, c0, c1, c2, c3 );
    }
    else
    {
        AES_ENCRYPT_1( pExpandedKey, c0 );
    }

    pDst[0] = c0;
    if( cbData >= 32 )
    {
    pDst[1] = c1;
        if( cbData >= 48 )
        {
    pDst[2] = c2;
            if( cbData >= 64 )
            {
    pDst[3] = c3;
                if( cbData >= 80 )
                {
    pDst[4] = c4;
                    if( cbData >= 96 )
                    {
    pDst[5] = c5;
                        if( cbData >= 112 )
                        {
    pDst[6] = c6;
                        }
                    }
                }
            }
        }
    }
}
#pragma runtime_checks( "u", restore)
#pragma warning( pop )

#pragma warning(push)
#pragma warning( disable:4701 ) // "Use of uninitialized variable"
#pragma runtime_checks( "u", off )

VOID
SYMCRYPT_CALL
SymCryptAesCtrMsb64Neon(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    __n128          chain = *(__n128 *)pbChainingValue;
    const __n128 *  pSrc = (const __n128 *) pbSrc;
    __n128 *        pDst = (__n128 *) pbDst;

    __prefetch( &pSrc[0] );
    __prefetch( &pSrc[2] );
    __prefetch( &pSrc[4] );
    __prefetch( &pSrc[6] );


    // See section 6.7.8 of the C standard for details on this initializer usage.
    const __n128 chainIncrement1 = (__n128) {.n128_u64 = {0, 1}};   // use {0,1} to initialize the n128_u64 element of the __n128 union.
    const __n128 chainIncrement2 = (__n128) {.n128_u64 = {0, 2}};
    const __n128 chainIncrement3 = (__n128) {.n128_u64 = {0, 3}};

    __n128 c0, c1, c2, c3, c4, c5, c6, c7;

    cbData &= ~(SYMCRYPT_AES_BLOCK_SIZE - 1);

    // Our chain variable is in integer format, not the MSBfirst format loaded from memory.
    chain = vrev64q_u8( chain );

/*
    while cbData >= 5 * block
        generate 8 blocks of key stream
        if cbData < 8 * block
            break;
        process 8 blocks
    if cbData >= 5 * block
        process 5-7 blocks
        done
    if cbData > 1 block
        generate 4 blocks of key stream
        process 2-4 blocks
        done
    if cbData >= 1 block
        generate 1 block of key stream
        process block
*/
    while( cbData >= 5 * SYMCRYPT_AES_BLOCK_SIZE )
    {
        c0 = chain;
        c1 = vaddq_u64( chain, chainIncrement1 );
        c2 = vaddq_u64( chain, chainIncrement2 );
        c3 = vaddq_u64( c1, chainIncrement2 );
        c4 = vaddq_u64( c2, chainIncrement2 );
        c5 = vaddq_u64( c3, chainIncrement2 );
        c6 = vaddq_u64( c4, chainIncrement2 );
        c7 = vaddq_u64( c5, chainIncrement2 );
        chain = vaddq_u64( c6, chainIncrement2 );

        c0 = vrev64q_u8( c0 );
        c1 = vrev64q_u8( c1 );
        c2 = vrev64q_u8( c2 );
        c3 = vrev64q_u8( c3 );
        c4 = vrev64q_u8( c4 );
        c5 = vrev64q_u8( c5 );
        c6 = vrev64q_u8( c6 );
        c7 = vrev64q_u8( c7 );

        AES_ENCRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 );

        if( cbData < 8 * SYMCRYPT_AES_BLOCK_SIZE )
        {
            break;
        }

        pDst[0] = veorq_u64( pSrc[0], c0 ); __prefetch( &pSrc[ 8] );
        pDst[1] = veorq_u64( pSrc[1], c1 );
        pDst[2] = veorq_u64( pSrc[2], c2 ); __prefetch( &pSrc[10] );
        pDst[3] = veorq_u64( pSrc[3], c3 );
        pDst[4] = veorq_u64( pSrc[4], c4 ); __prefetch( &pSrc[12] );
        pDst[5] = veorq_u64( pSrc[5], c5 );
        pDst[6] = veorq_u64( pSrc[6], c6 ); __prefetch( &pSrc[14] );
        pDst[7] = veorq_u64( pSrc[7], c7 );

        pDst  += 8;
        pSrc  += 8;
        cbData -= 8 * SYMCRYPT_AES_BLOCK_SIZE;
    }

    //
    // At this point we have one of the two following cases:
    // - cbData >= 5 * 16 and we have 8 blocks of key stream in c0-c7. chain is set to c7 + 1
    // - cbData < 5 * 16 and we have no blocks of key stream, with chain the next value to use
    //

    if( cbData >= SYMCRYPT_AES_BLOCK_SIZE ) // quick exit of function if the request was a multiple of 8 blocks
    {
        if( cbData >= 5 * SYMCRYPT_AES_BLOCK_SIZE )
        {
            //
            // We already have the key stream
            //
            pDst[0] = veorq_u64( pSrc[0], c0 );
            pDst[1] = veorq_u64( pSrc[1], c1 );
            pDst[2] = veorq_u64( pSrc[2], c2 );
            pDst[3] = veorq_u64( pSrc[3], c3 );
            pDst[4] = veorq_u64( pSrc[4], c4 );
            chain = vsubq_u64( chain, chainIncrement3 );

            if( cbData >= 96 )
            {
            chain = vaddq_u64( chain, chainIncrement1 );
            pDst[5] = veorq_u64( pSrc[5], c5 );
                if( cbData >= 112 )
                {
            chain = vaddq_u64( chain, chainIncrement1 );
            pDst[6] = veorq_u64( pSrc[6], c6 );
                }
            }
        }
        else if( cbData >= 2 * SYMCRYPT_AES_BLOCK_SIZE )
        {
            // Produce 4 blocks of key stream

            c0 = chain;
            c1 = vaddq_u64( chain, chainIncrement1 );
            c2 = vaddq_u64( chain, chainIncrement2 );
            c3 = vaddq_u64( c1, chainIncrement2 );
            chain = c2;             // chain is only incremented by 2 for now

            c0 = vrev64q_u8( c0 );
            c1 = vrev64q_u8( c1 );
            c2 = vrev64q_u8( c2 );
            c3 = vrev64q_u8( c3 );

            AES_ENCRYPT_4( pExpandedKey, c0, c1, c2, c3 );

            pDst[0] = veorq_u64( pSrc[0], c0 );
            pDst[1] = veorq_u64( pSrc[1], c1 );
            if( cbData >= 48 )
            {
            chain = vaddq_u64( chain, chainIncrement1 );
            pDst[2] = veorq_u64( pSrc[2], c2 );
                if( cbData >= 64 )
                {
            chain = vaddq_u64( chain, chainIncrement1 );
            pDst[3] = veorq_u64( pSrc[3], c3 );
                }
            }
        }
        else
        {
            // Exactly 1 block to process
            c0 = chain;
            chain = vaddq_u64( chain, chainIncrement1 );

            c0 = vrev64q_u8( c0 );

            AES_ENCRYPT_1( pExpandedKey, c0 );
            pDst[0] = veorq_u64( pSrc[0], c0 );
        }
    }

    chain = vrev64q_u8( chain );
    *(__n128 *)pbChainingValue = chain;
}
#pragma runtime_checks( "u", restore )
#pragma warning(pop)


//
// Multiply by alpha
//
// <</>> indicate shifts on 128-bit values
// <<<</>>>> indicate shifts on 32-bit values
//

// Multiply by ALPHA
// t1 = Input <<<< 1                        words shifted left by 1
// t2 = Input >>>> 31                       words shifted right by 31
// t1 = t1 ^ (t2 << 32)                     t1 = S << 1
// t2 = t2 >> 96                            t2 = highest bit of S
// t2 = (t2 <<<< 7) + (t2 <<<<3) - (t2)     multiply polynomially by 0x87 , we can use - because we only have one bit input
// res = t1 ^ t2
//
#define XTS_MUL_ALPHA_old( _in, _res ) \
{\
    __n128 _t1, _t2;\
\
    _t1 = vshlq_n_u32( _in, 1 ); \
    _t2 = vshrq_n_u32( _in, 31); \
    _t1 = veorq_u32( _t1, vextq_u32( vZero, _t2, 3 )); \
    _t2 = vextq_u32( _t2, vZero, 3); \
    _t2 = vsubq_u32( vaddq_u32( vshlq_n_u32( _t2, 7 ), vshlq_n_u32( _t2, 3 ) ), _t2 ); \
    _res = veorq_u32( _t1, _t2 ); \
}

//
// Another approach, use signed shift right to duplicate the bits of the leftmost byte
// and an AND to mask the modulo reduction and the extraneous bits in the other bytes at the same time.
// vAlphaMask = (1, 1, ..., 1, 0x87 )
//
SYMCRYPT_ALIGN_AT( 16 ) const BYTE g_SymCryptXtsNeonAlphaMask[16] = {0x87, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,};

#define XTS_MUL_ALPHA( _in, _res ) \
{\
    __n128 _t1, _t2;\
\
    _t1 = vshlq_n_u8( _in, 1 ); \
    _t2 = vshrq_n_s8( _in, 7 ); \
    _t2 = vextq_u8( _t2, _t2, 15 ); \
    _t2 = vandq_u8( _t2, vAlphaMask ); \
    _res = veorq_u8( _t2, _t1 ); \
}


// Multiply by ALPHA^2
// t1 = Input <<<< 2
// t2 = Input >>>> 30
// t1 = t1 ^ (t2 << 32)
// t2 = t2 >> 96
// t2 = (t2 <<<< 7) ^ (t2 <<<< 2) ^ (t2 <<<< 1) ^ t2
// res = t1 ^ t2
#define XTS_MUL_ALPHA2( _in, _res ) \
{\
    __n128 _t1, _t2;\
\
    _t1 = vshlq_n_u32( _in, 2 ); \
    _t2 = vshrq_n_u32( _in, 30); \
    _t1 = veorq_u32( _t1, vextq_u32( vZero, _t2, 3 )); \
    _t2 = vextq_u32( _t2, vZero, 3 ); \
    _t2 = veorq_u32( veorq_u32( veorq_u32( _t2, vshlq_n_u32( _t2, 7 )), vshlq_n_u32( _t2, 2 ) ), vshlq_n_u32( _t2, 1 ) ); \
    _res = veorq_u32( _t1, _t2 ); \
}

// Multiply by ALPHA^4
// t1 = Input <<<< 4
// t2 = Input >>>> 28
// t1 = t1 ^ (t2 << 32)
// t2 = t2 >> 96
// t2 = (t2 <<<< 7) ^ (t2 <<<< 2) ^ (t2 <<<< 1) ^ t2
// res = t1 ^ t2
#define XTS_MUL_ALPHA4( _in, _res ) \
{\
    __n128 _t1, _t2;\
\
    _t1 = vshlq_n_u32( _in, 4 ); \
    _t2 = vshrq_n_u32( _in, 28); \
    _t1 = veorq_u32( _t1, vextq_u32( vZero, _t2, 3 )); \
    _t2 = vextq_u32( _t2, vZero, 3 ); \
    _t2 = veorq_u32( veorq_u32( veorq_u32( _t2, vshlq_n_u32( _t2, 7 )), vshlq_n_u32( _t2, 2 ) ), vshlq_n_u32( _t2, 1 ) ); \
    _res = veorq_u32( _t1, _t2 ); \
}

#define XTS_MUL_ALPHA5( _in, _res ) \
{\
    __n128 _t1, _t2;\
\
    _t1 = vshlq_n_u32( _in, 5 ); \
    _t2 = vshrq_n_u32( _in, 27); \
    _t1 = veorq_u32( _t1, vextq_u32( vZero, _t2, 3 )); \
    _t2 = vextq_u32( _t2, vZero, 3 ); \
    _t2 = veorq_u32( veorq_u32( veorq_u32( _t2, vshlq_n_u32( _t2, 7 )), vshlq_n_u32( _t2, 2 ) ), vshlq_n_u32( _t2, 1 ) ); \
    _res = veorq_u32( _t1, _t2 ); \
}

// Multiply by ALPHA^8
// res = (Input << 8) | (Input >> 120)
// t2 = (Input >> 120) * 0x86
//      i.e. ((Input >> 120) <<<< 7) ^ ((Input >> 120) <<<< 2) ^ ((Input >> 120) <<<< 1)
//           the 0x01 component is already in res where we want it
// res = res ^ t2
//
// vAlphaMultiplier = (0, 0, ..., 0, 0x86 )
SYMCRYPT_ALIGN_AT( 8 ) const BYTE g_SymCryptXtsNeonAlphaMultiplier[8] = {0x86, 0, 0, 0, 0, 0, 0, 0,};

#define XTS_MUL_ALPHA8( _in, _res ) \
{\
    __n128 _t2;\
\
    _res = vextq_u8( _in, _in, 15 ); \
    _t2 = vmull_p8( _res, vAlphaMultiplier ) \
    _res = veorq_u32( _res, _t2 ); \
}


VOID
SYMCRYPT_CALL
SymCryptXtsAesEncryptDataUnitNeon(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_(SYMCRYPT_AES_BLOCK_SIZE)PBYTE                       pbTweakBlock,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    __n128 t0, t1, t2, t3, t4, t5, t6, t7;
    __n128 c0, c1, c2, c3, c4, c5, c6, c7;

    const __n128 *  pSrc;
    __n128 *        pDst;
    const __n128 vZero = neon_moviqb(0);
    const __n128 vAlphaMask = *(__n128 *) g_SymCryptXtsNeonAlphaMask;
    const __n128 vAlphaMultiplier = vld1_u8(g_SymCryptXtsNeonAlphaMultiplier);

    if( cbData < 8 * SYMCRYPT_AES_BLOCK_SIZE )
    {
        SymCryptXtsAesEncryptDataUnitC( pExpandedKey, pbTweakBlock, pbSrc, pbDst, cbData );
        return;
    }

    pSrc = (const __n128 *) pbSrc;
    t0 = *(__n128 *)pbTweakBlock;

    XTS_MUL_ALPHA4( t0, t4 );
    XTS_MUL_ALPHA ( t0, t1 );
    XTS_MUL_ALPHA ( t4, t5 );
    XTS_MUL_ALPHA ( t1, t2 );
    XTS_MUL_ALPHA ( t5, t6 );
    XTS_MUL_ALPHA ( t2, t3 );
    XTS_MUL_ALPHA ( t6, t7 );

    c0 = veorq_u32( t0, pSrc[0] );
    c1 = veorq_u32( t1, pSrc[1] );
    c2 = veorq_u32( t2, pSrc[2] );
    c3 = veorq_u32( t3, pSrc[3] );
    c4 = veorq_u32( t4, pSrc[4] );
    c5 = veorq_u32( t5, pSrc[5] );
    c6 = veorq_u32( t6, pSrc[6] );
    c7 = veorq_u32( t7, pSrc[7] );

    for(;;)
    {
        pbSrc += 8 * SYMCRYPT_AES_BLOCK_SIZE;

        AES_ENCRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 );

        cbData -= 8 * SYMCRYPT_AES_BLOCK_SIZE;
        if( cbData < 8 * SYMCRYPT_AES_BLOCK_SIZE )
        {
            break;
        }

        // Interleave the final xor, write, and compute next tweak block, and load, and first xor.
        // This reduces register pressure and is more efficient.
        pDst = (__n128 *) pbDst;
        pSrc = (const __n128 *) pbSrc;
        pDst[0] = veorq_u32( c0, t0 );
        pDst[1] = veorq_u32( c1, t1 );
        pDst[2] = veorq_u32( c2, t2 );
        pDst[3] = veorq_u32( c3, t3 );
        pDst[4] = veorq_u32( c4, t4 );
        pDst[5] = veorq_u32( c5, t5 );
        pDst[6] = veorq_u32( c6, t6 );
        pDst[7] = veorq_u32( c7, t7 );

        XTS_MUL_ALPHA8( t0, t0 );
        XTS_MUL_ALPHA8( t1, t1 );
        XTS_MUL_ALPHA8( t2, t2 );
        XTS_MUL_ALPHA8( t3, t3 );
        XTS_MUL_ALPHA8( t4, t4 );
        XTS_MUL_ALPHA8( t5, t5 );
        XTS_MUL_ALPHA8( t6, t6 );
        XTS_MUL_ALPHA8( t7, t7 );

        c0 = veorq_u32( pSrc[0], t0 );
        c1 = veorq_u32( pSrc[1], t1 );
        c2 = veorq_u32( pSrc[2], t2 );
        c3 = veorq_u32( pSrc[3], t3 );
        c4 = veorq_u32( pSrc[4], t4 );
        c5 = veorq_u32( pSrc[5], t5 );
        c6 = veorq_u32( pSrc[6], t6 );
        c7 = veorq_u32( pSrc[7], t7 );

        pbDst += 8 * SYMCRYPT_AES_BLOCK_SIZE;
    }

    // We won't do another 8-block set so we don't update the tweak blocks
    pDst = (__n128 *) pbDst;
    pDst[0] = veorq_u32( c0, t0 );
    pDst[1] = veorq_u32( c1, t1 );
    pDst[2] = veorq_u32( c2, t2 );
    pDst[3] = veorq_u32( c3, t3 );
    pDst[4] = veorq_u32( c4, t4 );
    pDst[5] = veorq_u32( c5, t5 );
    pDst[6] = veorq_u32( c6, t6 );
    pDst[7] = veorq_u32( c7, t7 );
    pbDst += 8 * SYMCRYPT_AES_BLOCK_SIZE;

    if( cbData > 0  )
    {
        //
        // This is a rare case: the data unit length is not a multiple of 128 bytes.
        // We do this in the default C implementation.
        // Fix up the tweak block first
        //

        XTS_MUL_ALPHA8( t0, t0 );
        *(__n128 *)pbTweakBlock = t0;
        SymCryptXtsAesEncryptDataUnitC( pExpandedKey, pbTweakBlock, pbSrc, pbDst, cbData );
    }

}


VOID
SYMCRYPT_CALL
SymCryptXtsAesDecryptDataUnitNeon(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_(SYMCRYPT_AES_BLOCK_SIZE)PBYTE                       pbTweakBlock,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    __n128 t0, t1, t2, t3, t4, t5, t6, t7;
    __n128 c0, c1, c2, c3, c4, c5, c6, c7;
    const __n128 *  pSrc;
    __n128 *        pDst;
    const __n128 vZero = neon_moviqb(0);
    const __n128 vAlphaMask = *(__n128 *) g_SymCryptXtsNeonAlphaMask;
    const __n128 vAlphaMultiplier = vld1_u8(g_SymCryptXtsNeonAlphaMultiplier);

    if( cbData < 8 * SYMCRYPT_AES_BLOCK_SIZE )
    {
        SymCryptXtsAesDecryptDataUnitC( pExpandedKey, pbTweakBlock, pbSrc, pbDst, cbData );
        return;
    }

    pSrc = (const __n128 *) pbSrc;
    t0 = *(__n128 *)pbTweakBlock;

    XTS_MUL_ALPHA4( t0, t4 );
    XTS_MUL_ALPHA ( t0, t1 );
    XTS_MUL_ALPHA ( t4, t5 );
    XTS_MUL_ALPHA ( t1, t2 );
    XTS_MUL_ALPHA ( t5, t6 );
    XTS_MUL_ALPHA ( t2, t3 );
    XTS_MUL_ALPHA ( t6, t7 );

    c0 = veorq_u32( t0, pSrc[0] );
    c1 = veorq_u32( t1, pSrc[1] );
    c2 = veorq_u32( t2, pSrc[2] );
    c3 = veorq_u32( t3, pSrc[3] );
    c4 = veorq_u32( t4, pSrc[4] );
    c5 = veorq_u32( t5, pSrc[5] );
    c6 = veorq_u32( t6, pSrc[6] );
    c7 = veorq_u32( t7, pSrc[7] );

    for(;;)
    {
        pbSrc += 8 * SYMCRYPT_AES_BLOCK_SIZE;

        AES_DECRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 );

        cbData -= 8 * SYMCRYPT_AES_BLOCK_SIZE;
        if( cbData < 8 * SYMCRYPT_AES_BLOCK_SIZE )
        {
            break;
        }

        // Interleave the final xor, write, and compute next tweak block, and load, and first xor.
        // This reduces register pressure and is more efficient.
        pDst = (__n128 *) pbDst;
        pSrc = (const __n128 *) pbSrc;
        pDst[0] = veorq_u32( c0, t0 );
        pDst[1] = veorq_u32( c1, t1 );
        pDst[2] = veorq_u32( c2, t2 );
        pDst[3] = veorq_u32( c3, t3 );
        pDst[4] = veorq_u32( c4, t4 );
        pDst[5] = veorq_u32( c5, t5 );
        pDst[6] = veorq_u32( c6, t6 );
        pDst[7] = veorq_u32( c7, t7 );

        XTS_MUL_ALPHA8( t0, t0 );
        XTS_MUL_ALPHA8( t1, t1 );
        XTS_MUL_ALPHA8( t2, t2 );
        XTS_MUL_ALPHA8( t3, t3 );
        XTS_MUL_ALPHA8( t4, t4 );
        XTS_MUL_ALPHA8( t5, t5 );
        XTS_MUL_ALPHA8( t6, t6 );
        XTS_MUL_ALPHA8( t7, t7 );

        c0 = veorq_u32( pSrc[0], t0 );
        c1 = veorq_u32( pSrc[1], t1 );
        c2 = veorq_u32( pSrc[2], t2 );
        c3 = veorq_u32( pSrc[3], t3 );
        c4 = veorq_u32( pSrc[4], t4 );
        c5 = veorq_u32( pSrc[5], t5 );
        c6 = veorq_u32( pSrc[6], t6 );
        c7 = veorq_u32( pSrc[7], t7 );

        pbDst += 8 * SYMCRYPT_AES_BLOCK_SIZE;
    }

    // We won't do another 8-block set so we don't update the tweak blocks
    pDst = (__n128 *) pbDst;
    pDst[0] = veorq_u32( c0, t0 );
    pDst[1] = veorq_u32( c1, t1 );
    pDst[2] = veorq_u32( c2, t2 );
    pDst[3] = veorq_u32( c3, t3 );
    pDst[4] = veorq_u32( c4, t4 );
    pDst[5] = veorq_u32( c5, t5 );
    pDst[6] = veorq_u32( c6, t6 );
    pDst[7] = veorq_u32( c7, t7 );
    pbDst += 8 * SYMCRYPT_AES_BLOCK_SIZE;

    if( cbData > 0  )
    {
        //
        // This is a rare case: the data unit length is not a multiple of 128 bytes.
        // We do this in the default C implementation.
        // Fix up the tweak block first
        //

        XTS_MUL_ALPHA8( t0, t0 );
        *(__n128 *)pbTweakBlock = t0;
        SymCryptXtsAesDecryptDataUnitC( pExpandedKey, pbTweakBlock, pbSrc, pbDst, cbData );
    }

}



#endif
