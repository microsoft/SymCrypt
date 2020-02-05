//
// aes-xmm.c   code for AES implementation
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// All XMM code for AES operations
//

#include "precomp.h"

#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64

VOID
SYMCRYPT_CALL
SymCryptAes4SboxXmm( _In_reads_(4) PCBYTE pIn, _Out_writes_(4) PBYTE pOut )
{
    __m128i x;

    x = _mm_set1_epi32( *(int *) pIn );

    x = _mm_aeskeygenassist_si128( x, 0 );

    *(unsigned *) pOut = x.m128i_u32[0];
}

VOID
SYMCRYPT_CALL
SymCryptAesCreateDecryptionRoundKeyXmm(
    _In_reads_(16)      PCBYTE  pEncryptionRoundKey,
    _Out_writes_(16)    PBYTE   pDecryptionRoundKey )
{
    //
    // On x86 our key structure is only 4-aligned (the best we can do) so we use unaligned load/stores.
    // On Amd64 our round keys are aligned, but recent CPUs have fast unaligned load/store if the address is
    // actually aligned properly.
    //
    _mm_storeu_si128( (__m128i *) pDecryptionRoundKey, _mm_aesimc_si128( _mm_loadu_si128( (__m128i *)pEncryptionRoundKey ) ) );
}

//
// The latency of AES instruction has increased up to 8 cycles in Ivy Bridge,
// and back to 7 in Haswell.
// We use 8-parallel code to expose the maximum parallelism to the CPU.
// On x86 it will introduce some register spilling, but the load/stores
// should be able to hide behind the AES instruction latencies.
// Silvermont x86 CPUs has AES-NI with latency = 8 and throughput = 5, so there
// the CPU parallelism is low.
// For things like BitLocker that is fine, but other uses, such as GCM & AES_CTR_DRBG
// use odd sizes.
// We try to do 5-8 blocks in 8-parallel code, 2-4 blocks in 4-parallel code, and
// 1 block in 1-parallel code.
// This is a compromise; the big cores can do 8 parallel in about the time of a 4-parallel,
// but Silvermont cannot and would pay a big price on small requests if we only use 8-parallel.
// Doing only 8-parallel and then 1-parallel would penalize the big cores a lot.
//
// We used to have 7-parallel code, but common request sizes are not multiples of 7
// blocks so we end up doing a lot of extra work. This is especially expensive on
// Silvermont where the extra work isn't hidden in the latencies.
//

#define AES_ENCRYPT_1( pExpandedKey, c0 ) \
{ \
    const BYTE (*keyPtr)[4][4]; \
    const BYTE (*keyLimit)[4][4]; \
    __m128i roundkey; \
\
    keyPtr = &pExpandedKey->RoundKey[0]; \
    keyLimit = pExpandedKey->lastEncRoundKey; \
\
    roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
    keyPtr ++; \
\
    c0 = _mm_xor_si128( c0, roundkey ); \
\
    roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
    keyPtr ++; \
\
    c0 = _mm_aesenc_si128( c0, roundkey ); \
\
    while( keyPtr < keyLimit ) \
    { \
        roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
        keyPtr ++; \
        c0 = _mm_aesenc_si128( c0, roundkey ); \
        roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
        keyPtr ++; \
        c0 = _mm_aesenc_si128( c0, roundkey ); \
    } \
\
    roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
\
    c0 = _mm_aesenclast_si128( c0, roundkey ); \
};

#define AES_ENCRYPT_4( pExpandedKey, c0, c1, c2, c3 ) \
{ \
    const BYTE (*keyPtr)[4][4]; \
    const BYTE (*keyLimit)[4][4]; \
    __m128i roundkey; \
\
    keyPtr = &pExpandedKey->RoundKey[0]; \
    keyLimit = pExpandedKey->lastEncRoundKey; \
\
    roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
    keyPtr ++; \
\
    c0 = _mm_xor_si128( c0, roundkey ); \
    c1 = _mm_xor_si128( c1, roundkey ); \
    c2 = _mm_xor_si128( c2, roundkey ); \
    c3 = _mm_xor_si128( c3, roundkey ); \
\
    while( keyPtr < keyLimit ) \
    { \
        roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
        keyPtr ++; \
        c0 = _mm_aesenc_si128( c0, roundkey ); \
        c1 = _mm_aesenc_si128( c1, roundkey ); \
        c2 = _mm_aesenc_si128( c2, roundkey ); \
        c3 = _mm_aesenc_si128( c3, roundkey ); \
    } \
\
    roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
\
    c0 = _mm_aesenclast_si128( c0, roundkey ); \
    c1 = _mm_aesenclast_si128( c1, roundkey ); \
    c2 = _mm_aesenclast_si128( c2, roundkey ); \
    c3 = _mm_aesenclast_si128( c3, roundkey ); \
};

#define AES_ENCRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 ) \
{ \
    const BYTE (*keyPtr)[4][4]; \
    const BYTE (*keyLimit)[4][4]; \
    __m128i roundkey; \
\
    keyPtr = &pExpandedKey->RoundKey[0]; \
    keyLimit = pExpandedKey->lastEncRoundKey; \
\
    roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
    keyPtr ++; \
\
    c0 = _mm_xor_si128( c0, roundkey ); \
    c1 = _mm_xor_si128( c1, roundkey ); \
    c2 = _mm_xor_si128( c2, roundkey ); \
    c3 = _mm_xor_si128( c3, roundkey ); \
    c4 = _mm_xor_si128( c4, roundkey ); \
    c5 = _mm_xor_si128( c5, roundkey ); \
    c6 = _mm_xor_si128( c6, roundkey ); \
    c7 = _mm_xor_si128( c7, roundkey ); \
\
    while( keyPtr < keyLimit ) \
    { \
        roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
        keyPtr ++; \
        c0 = _mm_aesenc_si128( c0, roundkey ); \
        c1 = _mm_aesenc_si128( c1, roundkey ); \
        c2 = _mm_aesenc_si128( c2, roundkey ); \
        c3 = _mm_aesenc_si128( c3, roundkey ); \
        c4 = _mm_aesenc_si128( c4, roundkey ); \
        c5 = _mm_aesenc_si128( c5, roundkey ); \
        c6 = _mm_aesenc_si128( c6, roundkey ); \
        c7 = _mm_aesenc_si128( c7, roundkey ); \
    } \
\
    roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
\
    c0 = _mm_aesenclast_si128( c0, roundkey ); \
    c1 = _mm_aesenclast_si128( c1, roundkey ); \
    c2 = _mm_aesenclast_si128( c2, roundkey ); \
    c3 = _mm_aesenclast_si128( c3, roundkey ); \
    c4 = _mm_aesenclast_si128( c4, roundkey ); \
    c5 = _mm_aesenclast_si128( c5, roundkey ); \
    c6 = _mm_aesenclast_si128( c6, roundkey ); \
    c7 = _mm_aesenclast_si128( c7, roundkey ); \
};

#define AES_DECRYPT_1( pExpandedKey, c0 ) \
{ \
    const BYTE (*keyPtr)[4][4]; \
    const BYTE (*keyLimit)[4][4]; \
    __m128i roundkey; \
\
    keyPtr = pExpandedKey->lastEncRoundKey; \
    keyLimit = pExpandedKey->lastDecRoundKey; \
\
    roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
    keyPtr ++; \
\
    c0 = _mm_xor_si128( c0, roundkey ); \
\
    roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
    keyPtr ++; \
    c0 = _mm_aesdec_si128( c0, roundkey ); \
\
    while( keyPtr < keyLimit ) \
    { \
        roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
        keyPtr ++; \
        c0 = _mm_aesdec_si128( c0, roundkey ); \
        roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
        keyPtr ++; \
        c0 = _mm_aesdec_si128( c0, roundkey ); \
    } \
\
    roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
\
    c0 = _mm_aesdeclast_si128( c0, roundkey ); \
};

#define AES_DECRYPT_4( pExpandedKey, c0, c1, c2, c3 ) \
{ \
    const BYTE (*keyPtr)[4][4]; \
    const BYTE (*keyLimit)[4][4]; \
    __m128i roundkey; \
\
    keyPtr = pExpandedKey->lastEncRoundKey; \
    keyLimit = pExpandedKey->lastDecRoundKey; \
\
    roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
    keyPtr ++; \
\
    c0 = _mm_xor_si128( c0, roundkey ); \
    c1 = _mm_xor_si128( c1, roundkey ); \
    c2 = _mm_xor_si128( c2, roundkey ); \
    c3 = _mm_xor_si128( c3, roundkey ); \
\
    while( keyPtr < keyLimit ) \
    { \
        roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
        keyPtr ++; \
        c0 = _mm_aesdec_si128( c0, roundkey ); \
        c1 = _mm_aesdec_si128( c1, roundkey ); \
        c2 = _mm_aesdec_si128( c2, roundkey ); \
        c3 = _mm_aesdec_si128( c3, roundkey ); \
    } \
\
    roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
\
    c0 = _mm_aesdeclast_si128( c0, roundkey ); \
    c1 = _mm_aesdeclast_si128( c1, roundkey ); \
    c2 = _mm_aesdeclast_si128( c2, roundkey ); \
    c3 = _mm_aesdeclast_si128( c3, roundkey ); \
};

#define AES_DECRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 ) \
{ \
    const BYTE (*keyPtr)[4][4]; \
    const BYTE (*keyLimit)[4][4]; \
    __m128i roundkey; \
\
    keyPtr = pExpandedKey->lastEncRoundKey; \
    keyLimit = pExpandedKey->lastDecRoundKey; \
\
    roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
    keyPtr ++; \
\
    c0 = _mm_xor_si128( c0, roundkey ); \
    c1 = _mm_xor_si128( c1, roundkey ); \
    c2 = _mm_xor_si128( c2, roundkey ); \
    c3 = _mm_xor_si128( c3, roundkey ); \
    c4 = _mm_xor_si128( c4, roundkey ); \
    c5 = _mm_xor_si128( c5, roundkey ); \
    c6 = _mm_xor_si128( c6, roundkey ); \
    c7 = _mm_xor_si128( c7, roundkey ); \
\
    while( keyPtr < keyLimit ) \
    { \
        roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
        keyPtr ++; \
        c0 = _mm_aesdec_si128( c0, roundkey ); \
        c1 = _mm_aesdec_si128( c1, roundkey ); \
        c2 = _mm_aesdec_si128( c2, roundkey ); \
        c3 = _mm_aesdec_si128( c3, roundkey ); \
        c4 = _mm_aesdec_si128( c4, roundkey ); \
        c5 = _mm_aesdec_si128( c5, roundkey ); \
        c6 = _mm_aesdec_si128( c6, roundkey ); \
        c7 = _mm_aesdec_si128( c7, roundkey ); \
    } \
\
    roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
\
    c0 = _mm_aesdeclast_si128( c0, roundkey ); \
    c1 = _mm_aesdeclast_si128( c1, roundkey ); \
    c2 = _mm_aesdeclast_si128( c2, roundkey ); \
    c3 = _mm_aesdeclast_si128( c3, roundkey ); \
    c4 = _mm_aesdeclast_si128( c4, roundkey ); \
    c5 = _mm_aesdeclast_si128( c5, roundkey ); \
    c6 = _mm_aesdeclast_si128( c6, roundkey ); \
    c7 = _mm_aesdeclast_si128( c7, roundkey ); \
};

//
// The EncryptXmm code is tested through the CFB mode encryption which has no further optimizations.
//
VOID
SYMCRYPT_CALL
SymCryptAesEncryptXmm(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PCBYTE                      pbSrc,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE ) PBYTE                       pbDst )
{
    __m128i c;

    c = _mm_loadu_si128( ( __m128i * ) pbSrc);

    AES_ENCRYPT_1( pExpandedKey, c );

    _mm_storeu_si128( (__m128i *) pbDst, c );
}

//
// The DecryptXmm code is tested through the EcbDecrypt calls which has no further optimizations.
//
VOID
SYMCRYPT_CALL
SymCryptAesDecryptXmm(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PCBYTE                      pbSrc,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE ) PBYTE                       pbDst )
{
    __m128i c;

    c = _mm_loadu_si128( ( __m128i * ) pbSrc);

    AES_DECRYPT_1( pExpandedKey, c );

    _mm_storeu_si128( (__m128i *) pbDst, c );
}

// Disable warnings and VC++ runtime checks for use of uninitialized values (by design)
#pragma warning(push)
#pragma warning( disable: 6001 4701 )
#pragma runtime_checks( "u", off )
VOID
SYMCRYPT_CALL
SymCryptAesEcbEncryptXmm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
    __m128i c0, c1, c2, c3, c4, c5, c6, c7;

    while( cbData >= 8 * SYMCRYPT_AES_BLOCK_SIZE )
    {
        c0 = _mm_loadu_si128( ( __m128i * ) (pbSrc +  0 ));
        c1 = _mm_loadu_si128( ( __m128i * ) (pbSrc + 16 ));
        c2 = _mm_loadu_si128( ( __m128i * ) (pbSrc + 32 ));
        c3 = _mm_loadu_si128( ( __m128i * ) (pbSrc + 48 ));
        c4 = _mm_loadu_si128( ( __m128i * ) (pbSrc + 64 ));
        c5 = _mm_loadu_si128( ( __m128i * ) (pbSrc + 80 ));
        c6 = _mm_loadu_si128( ( __m128i * ) (pbSrc + 96 ));
        c7 = _mm_loadu_si128( ( __m128i * ) (pbSrc +112 ));

        AES_ENCRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 );

        _mm_storeu_si128( (__m128i *) (pbDst +  0 ), c0 );
        _mm_storeu_si128( (__m128i *) (pbDst + 16 ), c1 );
        _mm_storeu_si128( (__m128i *) (pbDst + 32 ), c2 );
        _mm_storeu_si128( (__m128i *) (pbDst + 48 ), c3 );
        _mm_storeu_si128( (__m128i *) (pbDst + 64 ), c4 );
        _mm_storeu_si128( (__m128i *) (pbDst + 80 ), c5 );
        _mm_storeu_si128( (__m128i *) (pbDst + 96 ), c6 );
        _mm_storeu_si128( (__m128i *) (pbDst +112 ), c7 );

        pbSrc   += 8 * SYMCRYPT_AES_BLOCK_SIZE;
        pbDst   += 8 * SYMCRYPT_AES_BLOCK_SIZE;
        cbData  -= 8 * SYMCRYPT_AES_BLOCK_SIZE;
    }

    if( cbData < 16 )
    {
        return;
    }

    c0 = _mm_loadu_si128( ( __m128i * ) (pbSrc + 0 ));
    if( cbData >= 32 )
    {
    c1 = _mm_loadu_si128( ( __m128i * ) (pbSrc + 16 ));
        if( cbData >= 48 )
        {
    c2 = _mm_loadu_si128( ( __m128i * ) (pbSrc + 32 ));
            if( cbData >= 64 )
            {
    c3 = _mm_loadu_si128( ( __m128i * ) (pbSrc + 48 ));
                if( cbData >= 80 )
                {
    c4 = _mm_loadu_si128( ( __m128i * ) (pbSrc + 64 ));
                    if( cbData >= 96 )
                    {
    c5 = _mm_loadu_si128( ( __m128i * ) (pbSrc + 80 ));
                        if( cbData >= 112 )
                        {
    c6 = _mm_loadu_si128( ( __m128i * ) (pbSrc + 96 ));
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

    _mm_storeu_si128( (__m128i *) (pbDst + 0  ), c0 );
    if( cbData >= 32 )
    {
    _mm_storeu_si128( (__m128i *) (pbDst + 16 ), c1 );
        if( cbData >= 48 )
        {
    _mm_storeu_si128( (__m128i *) (pbDst + 32 ), c2 );
            if( cbData >= 64 )
            {
    _mm_storeu_si128( (__m128i *) (pbDst + 48 ), c3 );
                if( cbData >= 80 )
                {
    _mm_storeu_si128( (__m128i *) (pbDst + 64 ), c4 );
                    if( cbData >= 96 )
                    {
    _mm_storeu_si128( (__m128i *) (pbDst + 80 ), c5 );
                        if( cbData >= 112 )
                        {
    _mm_storeu_si128( (__m128i *) (pbDst + 96 ), c6 );
                        }
                    }
                }
            }
        }
    }
}
#pragma runtime_checks( "u", restore )
#pragma warning( pop )



VOID
SYMCRYPT_CALL
SymCryptAesCbcEncryptXmm(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    __m128i c = _mm_loadu_si128( (__m128i *) pbChainingValue );
    __m128i d;

    while( cbData >= SYMCRYPT_AES_BLOCK_SIZE )
    {
        d = _mm_loadu_si128( (__m128i *) pbSrc );
        c = _mm_xor_si128( c, d );
        AES_ENCRYPT_1( pExpandedKey, c );
        _mm_storeu_si128( (__m128i *) pbDst, c );

        pbSrc += SYMCRYPT_AES_BLOCK_SIZE;
        pbDst += SYMCRYPT_AES_BLOCK_SIZE;
        cbData -= SYMCRYPT_AES_BLOCK_SIZE;
    }
    _mm_storeu_si128( (__m128i *) pbChainingValue, c );
}

// Disable warnings and VC++ runtime checks for use of uninitialized values (by design)
#pragma warning(push)
#pragma warning( disable: 6001 4701 )
#pragma runtime_checks( "u", off )
VOID
SYMCRYPT_CALL
SymCryptAesCbcDecryptXmm(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    __m128i chain;
    __m128i c0, c1, c2, c3, c4, c5, c6, c7;
    __m128i d0, d1, d2, d3, d4, d5, d6, d7;

    if( cbData < SYMCRYPT_AES_BLOCK_SIZE )
    {
        return;
    }

    chain = _mm_loadu_si128( (__m128i *) pbChainingValue );

    //
    // First we do all multiples of 8 blocks
    //

    while( cbData >= 8 * SYMCRYPT_AES_BLOCK_SIZE )
    {
        d0 = c0 = _mm_loadu_si128( (__m128i *) (pbSrc + 0 * SYMCRYPT_AES_BLOCK_SIZE ) );
        d1 = c1 = _mm_loadu_si128( (__m128i *) (pbSrc + 1 * SYMCRYPT_AES_BLOCK_SIZE ) );
        d2 = c2 = _mm_loadu_si128( (__m128i *) (pbSrc + 2 * SYMCRYPT_AES_BLOCK_SIZE ) );
        d3 = c3 = _mm_loadu_si128( (__m128i *) (pbSrc + 3 * SYMCRYPT_AES_BLOCK_SIZE ) );
        d4 = c4 = _mm_loadu_si128( (__m128i *) (pbSrc + 4 * SYMCRYPT_AES_BLOCK_SIZE ) );
        d5 = c5 = _mm_loadu_si128( (__m128i *) (pbSrc + 5 * SYMCRYPT_AES_BLOCK_SIZE ) );
        d6 = c6 = _mm_loadu_si128( (__m128i *) (pbSrc + 6 * SYMCRYPT_AES_BLOCK_SIZE ) );
        d7 = c7 = _mm_loadu_si128( (__m128i *) (pbSrc + 7 * SYMCRYPT_AES_BLOCK_SIZE ) );

        AES_DECRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 );

        c0 = _mm_xor_si128( c0, chain );
        c1 = _mm_xor_si128( c1, d0 );
        c2 = _mm_xor_si128( c2, d1 );
        c3 = _mm_xor_si128( c3, d2 );
        c4 = _mm_xor_si128( c4, d3 );
        c5 = _mm_xor_si128( c5, d4 );
        c6 = _mm_xor_si128( c6, d5 );
        c7 = _mm_xor_si128( c7, d6 );
        chain = d7;

        _mm_storeu_si128( (__m128i *) (pbDst + 0 * SYMCRYPT_AES_BLOCK_SIZE ), c0 );
        _mm_storeu_si128( (__m128i *) (pbDst + 1 * SYMCRYPT_AES_BLOCK_SIZE ), c1 );
        _mm_storeu_si128( (__m128i *) (pbDst + 2 * SYMCRYPT_AES_BLOCK_SIZE ), c2 );
        _mm_storeu_si128( (__m128i *) (pbDst + 3 * SYMCRYPT_AES_BLOCK_SIZE ), c3 );
        _mm_storeu_si128( (__m128i *) (pbDst + 4 * SYMCRYPT_AES_BLOCK_SIZE ), c4 );
        _mm_storeu_si128( (__m128i *) (pbDst + 5 * SYMCRYPT_AES_BLOCK_SIZE ), c5 );
        _mm_storeu_si128( (__m128i *) (pbDst + 6 * SYMCRYPT_AES_BLOCK_SIZE ), c6 );
        _mm_storeu_si128( (__m128i *) (pbDst + 7 * SYMCRYPT_AES_BLOCK_SIZE ), c7 );

        pbSrc  += 8 * SYMCRYPT_AES_BLOCK_SIZE;
        pbDst  += 8 * SYMCRYPT_AES_BLOCK_SIZE;
        cbData -= 8 * SYMCRYPT_AES_BLOCK_SIZE;
    }

    if( cbData >= 16 )
    {
        //
        // There is remaining work to be done
        //
        d0 = c0 = _mm_loadu_si128( (__m128i *) (pbSrc + 0 * SYMCRYPT_AES_BLOCK_SIZE ) );
        if( cbData >= 32 )
        {
        d1 = c1 = _mm_loadu_si128( (__m128i *) (pbSrc + 1 * SYMCRYPT_AES_BLOCK_SIZE ) );
            if( cbData >= 48 )
            {
        d2 = c2 = _mm_loadu_si128( (__m128i *) (pbSrc + 2 * SYMCRYPT_AES_BLOCK_SIZE ) );
                if( cbData >= 64 )
                {
        d3 = c3 = _mm_loadu_si128( (__m128i *) (pbSrc + 3 * SYMCRYPT_AES_BLOCK_SIZE ) );
                    if( cbData >= 80 )
                    {
        d4 = c4 = _mm_loadu_si128( (__m128i *) (pbSrc + 4 * SYMCRYPT_AES_BLOCK_SIZE ) );
                        if( cbData >= 96 )
                        {
        d5 = c5 = _mm_loadu_si128( (__m128i *) (pbSrc + 5 * SYMCRYPT_AES_BLOCK_SIZE ) );
                            if( cbData >= 112 )
                            {
        d6 = c6 = _mm_loadu_si128( (__m128i *) (pbSrc + 6 * SYMCRYPT_AES_BLOCK_SIZE ) );
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
        if( cbData > 4 * SYMCRYPT_AES_BLOCK_SIZE )
        {
            AES_DECRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 );
            c0 = _mm_xor_si128( c0, chain );
            c1 = _mm_xor_si128( c1, d0 );
            c2 = _mm_xor_si128( c2, d1 );
            c3 = _mm_xor_si128( c3, d2 );
            c4 = _mm_xor_si128( c4, d3 );
            c5 = _mm_xor_si128( c5, d4 );
            c6 = _mm_xor_si128( c6, d5 );
        }
        else if( cbData > SYMCRYPT_AES_BLOCK_SIZE )
        {
            AES_DECRYPT_4( pExpandedKey, c0, c1, c2, c3 );
            c0 = _mm_xor_si128( c0, chain );
            c1 = _mm_xor_si128( c1, d0 );
            c2 = _mm_xor_si128( c2, d1 );
            c3 = _mm_xor_si128( c3, d2 );
        } else
        {
            AES_DECRYPT_1( pExpandedKey, c0 );
            c0 = _mm_xor_si128( c0, chain );
        }

        chain = _mm_loadu_si128( (__m128i *) (pbSrc + cbData - SYMCRYPT_AES_BLOCK_SIZE ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 0 * SYMCRYPT_AES_BLOCK_SIZE ), c0 );
        if( cbData >= 32 )
        {
        _mm_storeu_si128( (__m128i *) (pbDst + 1 * SYMCRYPT_AES_BLOCK_SIZE ), c1 );
            if( cbData >= 48 )
            {
        _mm_storeu_si128( (__m128i *) (pbDst + 2 * SYMCRYPT_AES_BLOCK_SIZE ), c2 );
                if( cbData >= 64 )
                {
        _mm_storeu_si128( (__m128i *) (pbDst + 3 * SYMCRYPT_AES_BLOCK_SIZE ), c3 );
                    if( cbData >= 80 )
                    {
        _mm_storeu_si128( (__m128i *) (pbDst + 4 * SYMCRYPT_AES_BLOCK_SIZE ), c4 );
                        if( cbData >= 96 )
                        {
        _mm_storeu_si128( (__m128i *) (pbDst + 5 * SYMCRYPT_AES_BLOCK_SIZE ), c5 );
                            if( cbData >= 112 )
                            {
        _mm_storeu_si128( (__m128i *) (pbDst + 6 * SYMCRYPT_AES_BLOCK_SIZE ), c6 );
                            }
                        }
                    }
                }
            }
        }
    }

    _mm_storeu_si128( (__m128i *) pbChainingValue, chain );

    return;
}
#pragma runtime_checks( "u", restore )
#pragma warning( pop )

VOID
SYMCRYPT_CALL
SymCryptAesCbcMacXmm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbData,
                                                SIZE_T                      cbData )
{
    __m128i c = _mm_loadu_si128( (__m128i *) pbChainingValue );
    __m128i d;

    while( cbData >= SYMCRYPT_AES_BLOCK_SIZE )
    {
        d = _mm_loadu_si128( (__m128i *) pbData );
        c = _mm_xor_si128( c, d );
        AES_ENCRYPT_1( pExpandedKey, c );

        pbData += SYMCRYPT_AES_BLOCK_SIZE;
        cbData -= SYMCRYPT_AES_BLOCK_SIZE;
    }
    _mm_storeu_si128( (__m128i *) pbChainingValue, c );

}


#pragma warning(push)
#pragma warning( disable:4701 ) // "Use of uninitialized variable"
#pragma runtime_checks( "u", off )

VOID
SYMCRYPT_CALL
SymCryptAesCtrMsb64Xmm(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    __m128i chain = _mm_loadu_si128( (__m128i *) pbChainingValue );

    __m128i BYTE_REVERSE_ORDER = _mm_set_epi8(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 );

    __m128i chainIncrement1 = _mm_set_epi32( 0, 0, 0, 1 );
    __m128i chainIncrement2 = _mm_set_epi32( 0, 0, 0, 2 );
    __m128i chainIncrement3 = _mm_set_epi32( 0, 0, 0, 3 );
    //__m128i chainIncrement8 = _mm_set_epi32( 0, 0, 0, 8 );

    __m128i c0, c1, c2, c3, c4, c5, c6, c7;

    cbData &= ~(SYMCRYPT_AES_BLOCK_SIZE - 1);

    chain = _mm_shuffle_epi8( chain, BYTE_REVERSE_ORDER );

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
    if cbData == 1 block
        generate 1 block of key stream
        process block
*/
    while( cbData >= 5 * SYMCRYPT_AES_BLOCK_SIZE )
    {
        c0 = chain;
        c1 = _mm_add_epi64( chain, chainIncrement1 );
        c2 = _mm_add_epi64( chain, chainIncrement2 );
        c3 = _mm_add_epi64( c1, chainIncrement2 );
        c4 = _mm_add_epi64( c2, chainIncrement2 );
        c5 = _mm_add_epi64( c3, chainIncrement2 );
        c6 = _mm_add_epi64( c4, chainIncrement2 );
        c7 = _mm_add_epi64( c5, chainIncrement2 );
        chain = _mm_add_epi64( c6, chainIncrement2 );

        c0 = _mm_shuffle_epi8( c0, BYTE_REVERSE_ORDER );
        c1 = _mm_shuffle_epi8( c1, BYTE_REVERSE_ORDER );
        c2 = _mm_shuffle_epi8( c2, BYTE_REVERSE_ORDER );
        c3 = _mm_shuffle_epi8( c3, BYTE_REVERSE_ORDER );
        c4 = _mm_shuffle_epi8( c4, BYTE_REVERSE_ORDER );
        c5 = _mm_shuffle_epi8( c5, BYTE_REVERSE_ORDER );
        c6 = _mm_shuffle_epi8( c6, BYTE_REVERSE_ORDER );
        c7 = _mm_shuffle_epi8( c7, BYTE_REVERSE_ORDER );

        AES_ENCRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 );

        if( cbData < 8 * SYMCRYPT_AES_BLOCK_SIZE )
        {
            break;
        }

        _mm_storeu_si128( (__m128i *) (pbDst +  0), _mm_xor_si128( c0, _mm_loadu_si128( ( __m128i * ) (pbSrc +  0 ) ) ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 16), _mm_xor_si128( c1, _mm_loadu_si128( ( __m128i * ) (pbSrc + 16 ) ) ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 32), _mm_xor_si128( c2, _mm_loadu_si128( ( __m128i * ) (pbSrc + 32 ) ) ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 48), _mm_xor_si128( c3, _mm_loadu_si128( ( __m128i * ) (pbSrc + 48 ) ) ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 64), _mm_xor_si128( c4, _mm_loadu_si128( ( __m128i * ) (pbSrc + 64 ) ) ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 80), _mm_xor_si128( c5, _mm_loadu_si128( ( __m128i * ) (pbSrc + 80 ) ) ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 96), _mm_xor_si128( c6, _mm_loadu_si128( ( __m128i * ) (pbSrc + 96 ) ) ) );
        _mm_storeu_si128( (__m128i *) (pbDst +112), _mm_xor_si128( c7, _mm_loadu_si128( ( __m128i * ) (pbSrc +112 ) ) ) );
        pbDst  += 8 * SYMCRYPT_AES_BLOCK_SIZE ;
        pbSrc  += 8 * SYMCRYPT_AES_BLOCK_SIZE;
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
            _mm_storeu_si128( (__m128i *) (pbDst +  0), _mm_xor_si128( c0, _mm_loadu_si128( ( __m128i * ) (pbSrc +  0 ) ) ) );
            _mm_storeu_si128( (__m128i *) (pbDst + 16), _mm_xor_si128( c1, _mm_loadu_si128( ( __m128i * ) (pbSrc + 16 ) ) ) );
            _mm_storeu_si128( (__m128i *) (pbDst + 32), _mm_xor_si128( c2, _mm_loadu_si128( ( __m128i * ) (pbSrc + 32 ) ) ) );
            _mm_storeu_si128( (__m128i *) (pbDst + 48), _mm_xor_si128( c3, _mm_loadu_si128( ( __m128i * ) (pbSrc + 48 ) ) ) );
            _mm_storeu_si128( (__m128i *) (pbDst + 64), _mm_xor_si128( c4, _mm_loadu_si128( ( __m128i * ) (pbSrc + 64 ) ) ) );
            chain = _mm_sub_epi64( chain, chainIncrement3 );

            if( cbData >= 96 )
            {
            chain = _mm_add_epi64( chain, chainIncrement1 );
            _mm_storeu_si128( (__m128i *) (pbDst + 80), _mm_xor_si128( c5, _mm_loadu_si128( ( __m128i * ) (pbSrc + 80 ) ) ) );
                if( cbData >= 112 )
                {
            chain = _mm_add_epi64( chain, chainIncrement1 );
            _mm_storeu_si128( (__m128i *) (pbDst + 96), _mm_xor_si128( c6, _mm_loadu_si128( ( __m128i * ) (pbSrc + 96 ) ) ) );
                }
            }
        }
        else if( cbData >= 2 * SYMCRYPT_AES_BLOCK_SIZE )
        {
            // Produce 4 blocks of key stream

            c0 = chain;
            c1 = _mm_add_epi64( chain, chainIncrement1 );
            c2 = _mm_add_epi64( chain, chainIncrement2 );
            c3 = _mm_add_epi64( c1, chainIncrement2 );
            chain = c2;             // chain is only incremented by 2 for now

            c0 = _mm_shuffle_epi8( c0, BYTE_REVERSE_ORDER );
            c1 = _mm_shuffle_epi8( c1, BYTE_REVERSE_ORDER );
            c2 = _mm_shuffle_epi8( c2, BYTE_REVERSE_ORDER );
            c3 = _mm_shuffle_epi8( c3, BYTE_REVERSE_ORDER );

            AES_ENCRYPT_4( pExpandedKey, c0, c1, c2, c3 );

            _mm_storeu_si128( (__m128i *) (pbDst +  0), _mm_xor_si128( c0, _mm_loadu_si128( ( __m128i * ) (pbSrc +  0 ) ) ) );
            _mm_storeu_si128( (__m128i *) (pbDst + 16), _mm_xor_si128( c1, _mm_loadu_si128( ( __m128i * ) (pbSrc + 16 ) ) ) );
            if( cbData >= 48 )
            {
            chain = _mm_add_epi64( chain, chainIncrement1 );
            _mm_storeu_si128( (__m128i *) (pbDst + 32), _mm_xor_si128( c2, _mm_loadu_si128( ( __m128i * ) (pbSrc + 32 ) ) ) );
                if( cbData >= 64 )
                {
            chain = _mm_add_epi64( chain, chainIncrement1 );
            _mm_storeu_si128( (__m128i *) (pbDst + 48), _mm_xor_si128( c3, _mm_loadu_si128( ( __m128i * ) (pbSrc + 48 ) ) ) );
                }
            }
        }
        else
        {
            // Exactly 1 block to process
            c0 = chain;
            chain = _mm_add_epi64( chain, chainIncrement1 );

            c0 = _mm_shuffle_epi8( c0, BYTE_REVERSE_ORDER );

            AES_ENCRYPT_1( pExpandedKey, c0 );
            _mm_storeu_si128( (__m128i *) (pbDst +  0), _mm_xor_si128( c0, _mm_loadu_si128( ( __m128i * ) (pbSrc +  0 ) ) ) );
        }
    }

    chain = _mm_shuffle_epi8( chain, BYTE_REVERSE_ORDER );
    _mm_storeu_si128( (__m128i *) pbChainingValue, chain );
}
#pragma runtime_checks( "u", off )
#pragma warning(pop)

/*
    if( cbData >= 16 )
    {
        if( cbData >= 32 )
        {
            if( cbData >= 48 )
            {
                if( cbData >= 64 )
                {
                    if( cbData >= 80 )
                    {
                        if( cbData >= 96 )
                        {
                            if( cbData >= 112 )
                            {
                            }
                        }
                    }
                }
            }
        }
    }
*/

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
#define XTS_MUL_ALPHA_old( _in, _res ) \
{\
    __m128i _t1, _t2;\
\
    _t1 = _mm_slli_epi32( _in, 1 ); \
    _t2 = _mm_srli_epi32( _in, 31); \
    _t1 = _mm_xor_si128( _t1, _mm_slli_si128( _t2, 4 )); \
    _t2 = _mm_srli_si128( _t2, 12 ); \
    _t2 = _mm_sub_epi32( _mm_add_epi32( _mm_slli_epi32( _t2, 7 ), _mm_slli_epi32( _t2, 3 ) ), _t2 ); \
    _res = _mm_xor_si128( _t1, _t2 ); \
}

// An improved approach; use arithmetic shift-right to duplicate the carry-out, PSHUFD to re-arrange, and an AND to
// implement both the polynomial and mask the other words down to 1 bit again.
#define XTS_MUL_ALPHA( _in, _res ) \
{\
    __m128i _t1, _t2;\
\
    _t1 = _mm_slli_epi32( _in, 1 ); \
    _t2 = _mm_srai_epi32( _in, 31); \
    _t2 = _mm_shuffle_epi32( _t2, _MM_SHUFFLE( 2, 1, 0, 3 ) ); \
    _t2 = _mm_and_si128( _t2, XTS_ALPHA_MASK ); \
    _res = _mm_xor_si128( _t1, _t2 ); \
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
    __m128i _t1, _t2;\
\
    _t1 = _mm_slli_epi32( _in, 2 ); \
    _t2 = _mm_srli_epi32( _in, 30); \
    _t1 = _mm_xor_si128( _t1, _mm_slli_si128( _t2, 4 )); \
    _t2 = _mm_srli_si128( _t2, 12 ); \
    _t2 = _mm_xor_si128( _mm_xor_si128( _mm_xor_si128( _mm_slli_epi32( _t2, 7 ), _mm_slli_epi32( _t2, 2 ) ), _mm_slli_epi32( _t2, 1 )), _t2 ); \
    _res = _mm_xor_si128( _t1, _t2 ); \
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
    __m128i _t1, _t2;\
\
    _t1 = _mm_slli_epi32( _in, 4 ); \
    _t2 = _mm_srli_epi32( _in, 28); \
    _t1 = _mm_xor_si128( _t1, _mm_slli_si128( _t2, 4 )); \
    _t2 = _mm_srli_si128( _t2, 12 ); \
    _t2 = _mm_xor_si128( _mm_xor_si128( _mm_xor_si128( _mm_slli_epi32( _t2, 7 ), _mm_slli_epi32( _t2, 2 ) ), _mm_slli_epi32( _t2, 1 )), _t2 ); \
    _res = _mm_xor_si128( _t1, _t2 ); \
}

#define XTS_MUL_ALPHA5( _in, _res ) \
{\
    __m128i _t1, _t2;\
\
    _t1 = _mm_slli_epi32( _in, 5 ); \
    _t2 = _mm_srli_epi32( _in, 27); \
    _t1 = _mm_xor_si128( _t1, _mm_slli_si128( _t2, 4 )); \
    _t2 = _mm_srli_si128( _t2, 12 ); \
    _t2 = _mm_xor_si128( _mm_xor_si128( _mm_xor_si128( _mm_slli_epi32( _t2, 7 ), _mm_slli_epi32( _t2, 2 ) ), _mm_slli_epi32( _t2, 1 )), _t2 ); \
    _res = _mm_xor_si128( _t1, _t2 ); \
}


// Multiply by ALPHA^8
// t2 = Input >> 120
// t2 = (t2 <<<< 7) ^ (t2 <<<< 2) ^ (t2 <<<< 1) ^ t2
// res = (Input << 8) ^ t2
// Expected to be marginally faster than new XTS_MUL_ALPHA on CPUs where clmul
// instruction corresponds to a single uop - unused for now.
//
// __m128i XTS_ALPHA_MULTIPLIER = _mm_set_epi32( 0, 0, 0, 0x87 );
#define XTS_MUL_ALPHA8( _in, _res ) \
{\
    __m128i _t2;\
\
    _t2 = _mm_srli_si128( _in, 15 ); \
    _res = _mm_slli_si128( _in, 1); \
    _t2 = _mm_clmulepi64_si128( _t2, XTS_ALPHA_MULTIPLIER, 0x00 ); \
    _res = _mm_xor_si128( _res, _t2 ); \
}




VOID
SYMCRYPT_CALL
SymCryptXtsAesEncryptDataUnitXmm(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_(SYMCRYPT_AES_BLOCK_SIZE)PBYTE                       pbTweakBlock,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    __m128i t0, t1, t2, t3, t4, t5, t6, t7;
    __m128i c0, c1, c2, c3, c4, c5, c6, c7;
    __m128i XTS_ALPHA_MASK = _mm_set_epi32( 1, 1, 1, 0x87 );


    if( cbData < 8 * SYMCRYPT_AES_BLOCK_SIZE )
    {
        SymCryptXtsAesEncryptDataUnitC( pExpandedKey, pbTweakBlock, pbSrc, pbDst, cbData );
        return;
    }

    t0 = _mm_loadu_si128( (__m128i *) pbTweakBlock );

    XTS_MUL_ALPHA4( t0, t4 );

    for(;;)
    {
        // At loop entry, t0 and t4 have the right values.
        XTS_MUL_ALPHA ( t0, t1 );
        XTS_MUL_ALPHA ( t4, t5 );
        XTS_MUL_ALPHA ( t1, t2 );
        XTS_MUL_ALPHA ( t5, t6 );
        XTS_MUL_ALPHA ( t2, t3 );
        XTS_MUL_ALPHA ( t6, t7 );

        c0 = _mm_xor_si128( t0, _mm_loadu_si128( ( __m128i * ) (pbSrc +    0 ) ) );
        c1 = _mm_xor_si128( t1, _mm_loadu_si128( ( __m128i * ) (pbSrc +   16 ) ) );
        c2 = _mm_xor_si128( t2, _mm_loadu_si128( ( __m128i * ) (pbSrc +   32 ) ) );
        c3 = _mm_xor_si128( t3, _mm_loadu_si128( ( __m128i * ) (pbSrc +   48 ) ) );
        c4 = _mm_xor_si128( t4, _mm_loadu_si128( ( __m128i * ) (pbSrc +   64 ) ) );
        c5 = _mm_xor_si128( t5, _mm_loadu_si128( ( __m128i * ) (pbSrc +   80 ) ) );
        c6 = _mm_xor_si128( t6, _mm_loadu_si128( ( __m128i * ) (pbSrc +   96 ) ) );
        c7 = _mm_xor_si128( t7, _mm_loadu_si128( ( __m128i * ) (pbSrc +  112 ) ) );

        pbSrc += 8 * SYMCRYPT_AES_BLOCK_SIZE;

        AES_ENCRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 );

        _mm_storeu_si128( (__m128i *) (pbDst +   0 ), _mm_xor_si128( c0, t0 ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  16 ), _mm_xor_si128( c1, t1 ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  32 ), _mm_xor_si128( c2, t2 ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  48 ), _mm_xor_si128( c3, t3 ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  64 ), _mm_xor_si128( c4, t4 ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  80 ), _mm_xor_si128( c5, t5 ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  96 ), _mm_xor_si128( c6, t6 ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 112 ), _mm_xor_si128( c7, t7 ) );

        pbDst += 8*SYMCRYPT_AES_BLOCK_SIZE;

        cbData -= 8 * SYMCRYPT_AES_BLOCK_SIZE;
        if( cbData < 8 * SYMCRYPT_AES_BLOCK_SIZE )
        {
            break;
        }

        XTS_MUL_ALPHA ( t7, t0 );
        XTS_MUL_ALPHA5( t7, t4 );
    }

    // We won't do another 8-block set so we don't update the tweak blocks

    if( cbData > 0  )
    {
        //
        // This is a rare case: the data unit length is not a multiple of 128 bytes.
        // We do this in the default C implementation.
        // Fix up the tweak block first
        //

        XTS_MUL_ALPHA( t7, t0 );
        _mm_storeu_si128( (__m128i *) pbTweakBlock, t0 );
        SymCryptXtsAesEncryptDataUnitC( pExpandedKey, pbTweakBlock, pbSrc, pbDst, cbData );
    }

}

VOID
SYMCRYPT_CALL
SymCryptXtsAesDecryptDataUnitXmm(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_(SYMCRYPT_AES_BLOCK_SIZE)PBYTE                       pbTweakBlock,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    __m128i t0, t1, t2, t3, t4, t5, t6, t7;
    __m128i c0, c1, c2, c3, c4, c5, c6, c7;
    __m128i XTS_ALPHA_MASK = _mm_set_epi32( 1, 1, 1, 0x87 );


    if( cbData < 8 * SYMCRYPT_AES_BLOCK_SIZE )
    {
        SymCryptXtsAesDecryptDataUnitC( pExpandedKey, pbTweakBlock, pbSrc, pbDst, cbData );
        return;
    }

    t0 = _mm_loadu_si128( (__m128i *) pbTweakBlock );

    XTS_MUL_ALPHA4( t0, t4 );

    for(;;)
    {
        // At loop entry, t0 and t4 have the right values.
        XTS_MUL_ALPHA ( t0, t1 );
        XTS_MUL_ALPHA ( t4, t5 );
        XTS_MUL_ALPHA ( t1, t2 );
        XTS_MUL_ALPHA ( t5, t6 );
        XTS_MUL_ALPHA ( t2, t3 );
        XTS_MUL_ALPHA ( t6, t7 );

        c0 = _mm_xor_si128( t0, _mm_loadu_si128( ( __m128i * ) (pbSrc +    0 ) ) );
        c1 = _mm_xor_si128( t1, _mm_loadu_si128( ( __m128i * ) (pbSrc +   16 ) ) );
        c2 = _mm_xor_si128( t2, _mm_loadu_si128( ( __m128i * ) (pbSrc +   32 ) ) );
        c3 = _mm_xor_si128( t3, _mm_loadu_si128( ( __m128i * ) (pbSrc +   48 ) ) );
        c4 = _mm_xor_si128( t4, _mm_loadu_si128( ( __m128i * ) (pbSrc +   64 ) ) );
        c5 = _mm_xor_si128( t5, _mm_loadu_si128( ( __m128i * ) (pbSrc +   80 ) ) );
        c6 = _mm_xor_si128( t6, _mm_loadu_si128( ( __m128i * ) (pbSrc +   96 ) ) );
        c7 = _mm_xor_si128( t7, _mm_loadu_si128( ( __m128i * ) (pbSrc +  112 ) ) );

        pbSrc += 8 * SYMCRYPT_AES_BLOCK_SIZE;

        AES_DECRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 );

        _mm_storeu_si128( (__m128i *) (pbDst +   0 ), _mm_xor_si128( c0, t0 ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  16 ), _mm_xor_si128( c1, t1 ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  32 ), _mm_xor_si128( c2, t2 ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  48 ), _mm_xor_si128( c3, t3 ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  64 ), _mm_xor_si128( c4, t4 ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  80 ), _mm_xor_si128( c5, t5 ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  96 ), _mm_xor_si128( c6, t6 ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 112 ), _mm_xor_si128( c7, t7 ) );

        pbDst += 8*SYMCRYPT_AES_BLOCK_SIZE;

        cbData -= 8 * SYMCRYPT_AES_BLOCK_SIZE;
        if( cbData < 8 * SYMCRYPT_AES_BLOCK_SIZE )
        {
            break;
        }

        XTS_MUL_ALPHA ( t7, t0 );
        XTS_MUL_ALPHA5( t7, t4 );
    }

    // We won't do another 8-block set so we don't update the tweak blocks

    if( cbData > 0  )
    {
        //
        // This is a rare case: the data unit length is not a multiple of 128 bytes.
        // We do this in the default C implementation.
        // Fix up the tweak block first
        //

        XTS_MUL_ALPHA( t7, t0 );
        _mm_storeu_si128( (__m128i *) pbTweakBlock, t0 );
        SymCryptXtsAesDecryptDataUnitC( pExpandedKey, pbTweakBlock, pbSrc, pbDst, cbData );
    }

}



#endif // CPU_X86 | CPU_AMD64

