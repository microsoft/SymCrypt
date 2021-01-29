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


// Perform AES encryption without the first round key and with a specified last round key
//
// For algorithms where performance is dominated by a chain of dependent AES rounds (i.e. CBC encryption, CCM, CMAC)
// we can gain a reasonable performance uplift by computing (last round key ^ next plaintext block ^ first round key)
// off the critical path and using this computed value in place of last round key in AESENCLAST instructions.
#define AES_ENCRYPT_1_CHAIN( pExpandedKey, cipherState, mergedLastRoundKey ) \
{ \
    const BYTE (*keyPtr)[4][4]; \
    const BYTE (*keyLimit)[4][4]; \
    __m128i roundkey; \
\
    keyPtr = &pExpandedKey->RoundKey[1]; \
    keyLimit = pExpandedKey->lastEncRoundKey; \
\
    roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
    keyPtr ++; \
\
    cipherState = _mm_aesenc_si128( cipherState, roundkey ); \
\
    while( keyPtr < keyLimit ) \
    { \
        roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
        keyPtr ++; \
        cipherState = _mm_aesenc_si128( cipherState, roundkey ); \
        roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
        keyPtr ++; \
        cipherState = _mm_aesenc_si128( cipherState, roundkey ); \
    } \
\
    cipherState = _mm_aesenclast_si128( cipherState, mergedLastRoundKey ); \
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

// c0, c1, c2, and c3 are __m512i
#define AES_ENCRYPT_ZMM_2048( pExpandedKey, c0, c1, c2, c3 ) \
{ \
    const BYTE (*keyPtr)[4][4]; \
    const BYTE (*keyLimit)[4][4]; \
    __m512i roundkeys; \
\
    keyPtr = pExpandedKey->RoundKey; \
    keyLimit = pExpandedKey->lastEncRoundKey; \
\
    roundkeys = _mm512_broadcast_i32x4( _mm_loadu_si128( (__m128i *) keyPtr ) ); \
    keyPtr ++; \
\
    c0 = _mm512_xor_si512( c0, roundkeys ); \
    c1 = _mm512_xor_si512( c1, roundkeys ); \
    c2 = _mm512_xor_si512( c2, roundkeys ); \
    c3 = _mm512_xor_si512( c3, roundkeys ); \
\
    while( keyPtr < keyLimit ) \
    { \
        roundkeys = _mm512_broadcast_i32x4( _mm_loadu_si128( (__m128i *) keyPtr ) ); \
        keyPtr ++; \
        c0 = _mm512_aesenc_epi128( c0, roundkeys ); \
        c1 = _mm512_aesenc_epi128( c1, roundkeys ); \
        c2 = _mm512_aesenc_epi128( c2, roundkeys ); \
        c3 = _mm512_aesenc_epi128( c3, roundkeys ); \
    } \
\
    roundkeys = _mm512_broadcast_i32x4( _mm_loadu_si128( (__m128i *) keyPtr ) ); \
\
    c0 = _mm512_aesenclast_epi128( c0, roundkeys ); \
    c1 = _mm512_aesenclast_epi128( c1, roundkeys ); \
    c2 = _mm512_aesenclast_epi128( c2, roundkeys ); \
    c3 = _mm512_aesenclast_epi128( c3, roundkeys ); \
};

#define AES_ENCRYPT_YMM_2048( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 ) \
{ \
    const BYTE (*keyPtr)[4][4]; \
    const BYTE (*keyLimit)[4][4]; \
    __m256i roundkeys; \
\
    keyPtr = pExpandedKey->RoundKey; \
    keyLimit = pExpandedKey->lastEncRoundKey; \
\
    /* _mm256_broadcastsi128_si256 requires AVX2 */ \
    roundkeys =  _mm256_broadcastsi128_si256( *( (const __m128i *) keyPtr ) ); \
    keyPtr ++; \
\
    /* _mm256_xor_si256 requires AVX2 */ \
    c0 = _mm256_xor_si256( c0, roundkeys ); \
    c1 = _mm256_xor_si256( c1, roundkeys ); \
    c2 = _mm256_xor_si256( c2, roundkeys ); \
    c3 = _mm256_xor_si256( c3, roundkeys ); \
    c4 = _mm256_xor_si256( c4, roundkeys ); \
    c5 = _mm256_xor_si256( c5, roundkeys ); \
    c6 = _mm256_xor_si256( c6, roundkeys ); \
    c7 = _mm256_xor_si256( c7, roundkeys ); \
\
    while( keyPtr < keyLimit ) \
    { \
        roundkeys =  _mm256_broadcastsi128_si256( *( (const __m128i *) keyPtr ) ); \
        keyPtr ++; \
        c0 = _mm256_aesenc_epi128( c0, roundkeys ); \
        c1 = _mm256_aesenc_epi128( c1, roundkeys ); \
        c2 = _mm256_aesenc_epi128( c2, roundkeys ); \
        c3 = _mm256_aesenc_epi128( c3, roundkeys ); \
        c4 = _mm256_aesenc_epi128( c4, roundkeys ); \
        c5 = _mm256_aesenc_epi128( c5, roundkeys ); \
        c6 = _mm256_aesenc_epi128( c6, roundkeys ); \
        c7 = _mm256_aesenc_epi128( c7, roundkeys ); \
    } \
\
    roundkeys =  _mm256_broadcastsi128_si256( *( (const __m128i *) keyPtr ) ); \
\
    c0 = _mm256_aesenclast_epi128( c0, roundkeys ); \
    c1 = _mm256_aesenclast_epi128( c1, roundkeys ); \
    c2 = _mm256_aesenclast_epi128( c2, roundkeys ); \
    c3 = _mm256_aesenclast_epi128( c3, roundkeys ); \
    c4 = _mm256_aesenclast_epi128( c4, roundkeys ); \
    c5 = _mm256_aesenclast_epi128( c5, roundkeys ); \
    c6 = _mm256_aesenclast_epi128( c6, roundkeys ); \
    c7 = _mm256_aesenclast_epi128( c7, roundkeys ); \
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

// c0, c1, c2, and c3 are __m512i
#define AES_DECRYPT_ZMM_2048( pExpandedKey, c0, c1, c2, c3 ) \
{ \
    const BYTE (*keyPtr)[4][4]; \
    const BYTE (*keyLimit)[4][4]; \
    __m512i roundkeys; \
\
    keyPtr = pExpandedKey->lastEncRoundKey; \
    keyLimit = pExpandedKey->lastDecRoundKey; \
\
    roundkeys = _mm512_broadcast_i32x4( _mm_loadu_si128( (__m128i *) keyPtr ) ); \
    keyPtr ++; \
\
    /* _mm512_xor_si512 requires AVX512F */ \
    c0 = _mm512_xor_si512( c0, roundkeys ); \
    c1 = _mm512_xor_si512( c1, roundkeys ); \
    c2 = _mm512_xor_si512( c2, roundkeys ); \
    c3 = _mm512_xor_si512( c3, roundkeys ); \
\
    while( keyPtr < keyLimit ) \
    { \
        roundkeys = _mm512_broadcast_i32x4( _mm_loadu_si128( (__m128i *) keyPtr ) ); \
        keyPtr ++; \
        c0 = _mm512_aesdec_epi128( c0, roundkeys ); \
        c1 = _mm512_aesdec_epi128( c1, roundkeys ); \
        c2 = _mm512_aesdec_epi128( c2, roundkeys ); \
        c3 = _mm512_aesdec_epi128( c3, roundkeys ); \
    } \
\
    roundkeys = _mm512_broadcast_i32x4( _mm_loadu_si128( (__m128i *) keyPtr ) ); \
\
    c0 = _mm512_aesdeclast_epi128( c0, roundkeys ); \
    c1 = _mm512_aesdeclast_epi128( c1, roundkeys ); \
    c2 = _mm512_aesdeclast_epi128( c2, roundkeys ); \
    c3 = _mm512_aesdeclast_epi128( c3, roundkeys ); \
};

#define AES_DECRYPT_YMM_2048( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 ) \
{ \
    const BYTE (*keyPtr)[4][4]; \
    const BYTE (*keyLimit)[4][4]; \
    __m256i roundkeys; \
\
    keyPtr = pExpandedKey->lastEncRoundKey; \
    keyLimit = pExpandedKey->lastDecRoundKey; \
\
    /* _mm256_broadcastsi128_si256 requires AVX2 */ \
    roundkeys =  _mm256_broadcastsi128_si256( *( (const __m128i *) keyPtr ) ); \
    keyPtr ++; \
\
    /* _mm256_xor_si256 requires AVX2 */ \
    c0 = _mm256_xor_si256( c0, roundkeys ); \
    c1 = _mm256_xor_si256( c1, roundkeys ); \
    c2 = _mm256_xor_si256( c2, roundkeys ); \
    c3 = _mm256_xor_si256( c3, roundkeys ); \
    c4 = _mm256_xor_si256( c4, roundkeys ); \
    c5 = _mm256_xor_si256( c5, roundkeys ); \
    c6 = _mm256_xor_si256( c6, roundkeys ); \
    c7 = _mm256_xor_si256( c7, roundkeys ); \
\
    while( keyPtr < keyLimit ) \
    { \
        roundkeys =  _mm256_broadcastsi128_si256( *( (const __m128i *) keyPtr ) ); \
        keyPtr ++; \
        c0 = _mm256_aesdec_epi128( c0, roundkeys ); \
        c1 = _mm256_aesdec_epi128( c1, roundkeys ); \
        c2 = _mm256_aesdec_epi128( c2, roundkeys ); \
        c3 = _mm256_aesdec_epi128( c3, roundkeys ); \
        c4 = _mm256_aesdec_epi128( c4, roundkeys ); \
        c5 = _mm256_aesdec_epi128( c5, roundkeys ); \
        c6 = _mm256_aesdec_epi128( c6, roundkeys ); \
        c7 = _mm256_aesdec_epi128( c7, roundkeys ); \
    } \
\
    roundkeys =  _mm256_broadcastsi128_si256( *( (const __m128i *) keyPtr ) ); \
\
    c0 = _mm256_aesdeclast_epi128( c0, roundkeys ); \
    c1 = _mm256_aesdeclast_epi128( c1, roundkeys ); \
    c2 = _mm256_aesdeclast_epi128( c2, roundkeys ); \
    c3 = _mm256_aesdeclast_epi128( c3, roundkeys ); \
    c4 = _mm256_aesdeclast_epi128( c4, roundkeys ); \
    c5 = _mm256_aesdeclast_epi128( c5, roundkeys ); \
    c6 = _mm256_aesdeclast_epi128( c6, roundkeys ); \
    c7 = _mm256_aesdeclast_epi128( c7, roundkeys ); \
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
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
    __m128i c = _mm_loadu_si128( (__m128i *) pbChainingValue );
    __m128i rk0 = _mm_loadu_si128( (__m128i *) &pExpandedKey->RoundKey[0] );
    __m128i rkLast = _mm_loadu_si128( (__m128i *) pExpandedKey->lastEncRoundKey );
    __m128i d;

    if (cbData < SYMCRYPT_AES_BLOCK_SIZE)
        return;

    // This algorithm is dominated by chain of dependent AES rounds, so we want to avoid XOR
    // instructions on the critical path where possible
    // We can compute (last round key ^ next plaintext block ^ first round key) off the critical
    // path and use this with AES_ENCRYPT_1_CHAIN so that only AES instructions write to c in
    // the main loop
    d = _mm_xor_si128( _mm_loadu_si128( (__m128i *) pbSrc ), rk0 );
    c = _mm_xor_si128( c, d );
    pbSrc += SYMCRYPT_AES_BLOCK_SIZE;
    cbData -= SYMCRYPT_AES_BLOCK_SIZE;

    while( cbData >= SYMCRYPT_AES_BLOCK_SIZE )
    {
        d = _mm_xor_si128( _mm_loadu_si128( (__m128i *) pbSrc ), rk0 );
        AES_ENCRYPT_1_CHAIN( pExpandedKey, c, _mm_xor_si128(d, rkLast ) );
        _mm_storeu_si128( (__m128i *) pbDst, _mm_xor_si128(c, d) );

        pbSrc += SYMCRYPT_AES_BLOCK_SIZE;
        pbDst += SYMCRYPT_AES_BLOCK_SIZE;
        cbData -= SYMCRYPT_AES_BLOCK_SIZE;
    }
    AES_ENCRYPT_1_CHAIN( pExpandedKey, c, rkLast );
    _mm_storeu_si128( (__m128i *) pbDst, c );
    _mm_storeu_si128( (__m128i *) pbChainingValue, c );
}

// Disable warnings and VC++ runtime checks for use of uninitialized values (by design)
#pragma warning(push)
#pragma warning( disable: 6001 4701 )
#pragma runtime_checks( "u", off )
VOID
SYMCRYPT_CALL
SymCryptAesCbcDecryptXmm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
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
    __m128i rk0 = _mm_loadu_si128( (__m128i *) &pExpandedKey->RoundKey[0] );
    __m128i rkLast = _mm_loadu_si128( (__m128i *) pExpandedKey->lastEncRoundKey );
    __m128i d, rk0AndLast;

    if (cbData < SYMCRYPT_AES_BLOCK_SIZE)
        return;

    // This algorithm is dominated by chain of dependent AES rounds, so we want to avoid XOR
    // instructions on the critical path where possible
    // We can compute (last round key ^ next plaintext block ^ first round key) off the critical
    // path and use this with AES_ENCRYPT_1_CHAIN so that only AES instructions write to c in
    // the main loop
    d = _mm_xor_si128( _mm_loadu_si128( (__m128i *) pbData ), rk0 );
    c = _mm_xor_si128( c, d );
    pbData += SYMCRYPT_AES_BLOCK_SIZE;
    cbData -= SYMCRYPT_AES_BLOCK_SIZE;

    // As we don't compute ciphertext here, we only need to XOR rk0 and rkLast once
    rk0AndLast = _mm_xor_si128( rk0, rkLast );

    while( cbData >= SYMCRYPT_AES_BLOCK_SIZE )
    {
        d = _mm_xor_si128( _mm_loadu_si128( (__m128i *) pbData ), rk0AndLast );
        AES_ENCRYPT_1_CHAIN( pExpandedKey, c, d );

        pbData += SYMCRYPT_AES_BLOCK_SIZE;
        cbData -= SYMCRYPT_AES_BLOCK_SIZE;
    }
    AES_ENCRYPT_1_CHAIN( pExpandedKey, c, rkLast );
    _mm_storeu_si128( (__m128i *) pbChainingValue, c );
}


#pragma warning(push)
#pragma warning( disable:4701 ) // "Use of uninitialized variable"
#pragma runtime_checks( "u", off )

VOID
SYMCRYPT_CALL
SymCryptAesCtrMsb64Xmm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
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
        pbDst  += 8 * SYMCRYPT_AES_BLOCK_SIZE;
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
// <<<</>>>> indicate shifts on 32-bit values (a word)
//

// Multiply by ALPHA
// Since there's no instruction to shift the 128 bit register left by one, the following shifts do the trick.
// All shifts are zero extended
// t1 = _in <<<< 1                          words shifted left by 1, this is almost a _in << 1 but there are
//                                          gaps at first bit of each word, the following two shifts fixes that.
// t2 = _in >>>> 31                         words shifted right by 31
// t1 = t1 ^ (t2 << 32)                     t1 = _in << 1, note ^ could be |
// Do the special case for first byte of _in where last carry means xor with 135 for first byte.
// t2 = t2 >> 96                            t2 = _in >> 127, i.e., last bit of _in is placed in first bit
// t2 = (t2 <<<< 7) + (t2 <<<<3) - (t2)     t2 = 135 if last bit of t2 is set
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

// Like XTS_MUL_ALPHA_old but operate on __m512i for _in and _res.
// TODO: do this with VSHUFPS.
#define XTS_MUL_ALPHA_ZMM_old( _in, _res ) \
{\
    __m512i _t1, _t2;\
\
    _t1 = _mm512_slli_epi32( _in, 1 ); \
    _t2 = _mm512_srli_epi32( _in, 31); \
    _t1 = _mm512_xor_si512( _t1, _mm512_bslli_epi128( _t2, 4 )); \
    _t2 = _mm512_bsrli_epi128( _t2, 12 ); \
    _t2 = _mm512_sub_epi32( _mm512_add_epi32( _mm512_slli_epi32( _t2, 7 ), _mm512_slli_epi32( _t2, 3 ) ), _t2 ); \
    _res = _mm512_xor_si512( _t1, _t2 ); \
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
//
// Only currently used with VPCLMULQDQ (in Ymm / Zmm versions) as support for non-vectorized PCLMULQDQ is not always supported with AESNI,
// and is sometimes slower than shift+xor

// __m256i XTS_ALPHA_MULTIPLIER_Ymm = _mm256_set_epi64x( 0, 0x87, 0, 0x87);
#define XTS_MUL_ALPHA8_YMM( _in, _res ) \
{\
    __m256i _t2;\
\
    _t2 = _mm256_srli_si256( _in, 15); /* AVX2 */ \
    _res = _mm256_slli_si256( _in, 1 ); \
    _t2 = _mm256_clmulepi64_epi128( _t2, XTS_ALPHA_MULTIPLIER_Ymm, 0x00 ); \
    _res = _mm256_xor_si256(_res, _t2 ); \
}

#define XTS_MUL_ALPHA16_YMM( _in, _res ) \
{\
    __m256i _t2;\
\
    _t2 = _mm256_srli_si256( _in, 14); /* AVX2 */ \
    _res = _mm256_slli_si256( _in, 2 ); \
    _t2 = _mm256_clmulepi64_epi128( _t2, XTS_ALPHA_MULTIPLIER_Ymm, 0x00 ); \
    _res = _mm256_xor_si256(_res, _t2 ); \
}

// __m512i XTS_ALPHA_MULTIPLIER_Zmm = _mm512_set_epi64( 0, 0x87, 0, 0x87, 0, 0x87, 0, 0x87 );
#define XTS_MUL_ALPHA8_ZMM( _in, _res ) \
{\
    __m512i _t2; \
\
    _t2 = _mm512_bsrli_epi128( _in, 15); \
    _res = _mm512_bslli_epi128( _in, 1); \
    _t2 = _mm512_clmulepi64_epi128( _t2, XTS_ALPHA_MULTIPLIER_Zmm, 0x00 ); \
    _res = _mm512_xor_si512( _res, _t2 ); \
}

#define XTS_MUL_ALPHA16_ZMM( _in, _res ) \
{\
    __m512i _t2; \
\
    _t2 = _mm512_bsrli_epi128( _in, 14); \
    _res = _mm512_bslli_epi128( _in, 2); \
    _t2 = _mm512_clmulepi64_epi128( _t2, XTS_ALPHA_MULTIPLIER_Zmm, 0x00 ); \
    _res = _mm512_xor_si512( _res, _t2 ); \
}

// Currently only use UINT64 for x86 and amd64 - this does regress perf on x86
// but we don't expect a lot of XTS in x86. If the regression causes any real problems
// we can consider introducing another variant. Not doing this now to avoid code bloat
#define XTS_MUL_ALPHA_Scalar( _inout_low_u64, _inout_high_u64 ) \
{ \
    UINT64 tmp = (UINT64) ((INT64)_inout_high_u64 >> 63); \
    \
    _inout_high_u64 = (_inout_high_u64 << 1) ^ (_inout_low_u64 >> 63); \
    _inout_low_u64 = (_inout_low_u64 << 1) ^ (tmp & 0x87); \
}

VOID
SYMCRYPT_CALL
SymCryptXtsAesEncryptDataUnitXmm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )       PBYTE                       pbTweakBlock,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE*16 )  PBYTE                       pbScratch,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
    __m128i t0;
    __m128i c0, c1, c2, c3, c4, c5, c6, c7;
    __m128i roundkey, firstRoundKey, lastRoundKey;
    __m128i XTS_ALPHA_MASK = _mm_set_epi32( 1, 1, 1, 0x87 );
    SYMCRYPT_GF128_ELEMENT* tweakBuffer = (SYMCRYPT_GF128_ELEMENT*) pbScratch;

    const BYTE (*keyPtr)[4][4];
    const BYTE (*keyLimit)[4][4] = pExpandedKey->lastEncRoundKey;
    UINT64 lastTweakLow, lastTweakHigh;
    int aesEncryptXtsLoop;

    c0 = _mm_loadu_si128( (__m128i *) pbTweakBlock );
    XTS_MUL_ALPHA( c0, c1 );
    XTS_MUL_ALPHA( c1, c2 );
    XTS_MUL_ALPHA( c2, c3 );

    XTS_MUL_ALPHA4( c0, c4 );
    XTS_MUL_ALPHA ( c4, c5 );
    XTS_MUL_ALPHA ( c5, c6 );
    XTS_MUL_ALPHA ( c6, c7 );

    tweakBuffer[0].m128i = c0;
    tweakBuffer[1].m128i = c1;
    tweakBuffer[2].m128i = c2;
    tweakBuffer[3].m128i = c3;
    tweakBuffer[4].m128i = c4;
    tweakBuffer[5].m128i = c5;
    tweakBuffer[6].m128i = c6;
    tweakBuffer[7].m128i = c7;
    lastTweakLow  = tweakBuffer[7].ull[0];
    lastTweakHigh = tweakBuffer[7].ull[1];

    firstRoundKey = _mm_loadu_si128( (__m128i *) &pExpandedKey->RoundKey[0] );
    lastRoundKey = _mm_loadu_si128( (__m128i *) pExpandedKey->lastEncRoundKey );

    while( cbData >= 8 * SYMCRYPT_AES_BLOCK_SIZE )
    {
        // At loop entry, tweakBuffer[0-7] are tweakValues for the next 8 blocks
        c0 = _mm_xor_si128( tweakBuffer[0].m128i, firstRoundKey );
        c1 = _mm_xor_si128( tweakBuffer[1].m128i, firstRoundKey );
        c2 = _mm_xor_si128( tweakBuffer[2].m128i, firstRoundKey );
        c3 = _mm_xor_si128( tweakBuffer[3].m128i, firstRoundKey );
        c4 = _mm_xor_si128( tweakBuffer[4].m128i, firstRoundKey );
        c5 = _mm_xor_si128( tweakBuffer[5].m128i, firstRoundKey );
        c6 = _mm_xor_si128( tweakBuffer[6].m128i, firstRoundKey );
        c7 = _mm_xor_si128( tweakBuffer[7].m128i, firstRoundKey );

        c0 = _mm_xor_si128( c0, _mm_loadu_si128( ( __m128i * ) (pbSrc +   0) ) );
        c1 = _mm_xor_si128( c1, _mm_loadu_si128( ( __m128i * ) (pbSrc +  16) ) );
        c2 = _mm_xor_si128( c2, _mm_loadu_si128( ( __m128i * ) (pbSrc +  32) ) );
        c3 = _mm_xor_si128( c3, _mm_loadu_si128( ( __m128i * ) (pbSrc +  48) ) );
        c4 = _mm_xor_si128( c4, _mm_loadu_si128( ( __m128i * ) (pbSrc +  64) ) );
        c5 = _mm_xor_si128( c5, _mm_loadu_si128( ( __m128i * ) (pbSrc +  80) ) );
        c6 = _mm_xor_si128( c6, _mm_loadu_si128( ( __m128i * ) (pbSrc +  96) ) );
        c7 = _mm_xor_si128( c7, _mm_loadu_si128( ( __m128i * ) (pbSrc + 112) ) );

        keyPtr = &pExpandedKey->RoundKey[1];

        // Do 8 full rounds (AES-128|AES-192|AES-256) with stitched XTS (peformed in scalar registers)
        for( aesEncryptXtsLoop = 0; aesEncryptXtsLoop < 8; aesEncryptXtsLoop++ )
        {
            roundkey = _mm_loadu_si128( (__m128i *) keyPtr );
            keyPtr ++;
            c0 = _mm_aesenc_si128( c0, roundkey );
            c1 = _mm_aesenc_si128( c1, roundkey );
            c2 = _mm_aesenc_si128( c2, roundkey );
            c3 = _mm_aesenc_si128( c3, roundkey );
            c4 = _mm_aesenc_si128( c4, roundkey );
            c5 = _mm_aesenc_si128( c5, roundkey );
            c6 = _mm_aesenc_si128( c6, roundkey );
            c7 = _mm_aesenc_si128( c7, roundkey );

            // Prepare tweakBuffer[8-15] with tweak^lastRoundKey
            tweakBuffer[ 8+aesEncryptXtsLoop ].m128i = _mm_xor_si128( tweakBuffer[ aesEncryptXtsLoop ].m128i, lastRoundKey );
            // Prepare tweakBuffer[0-7] with tweaks for next 8 blocks
            XTS_MUL_ALPHA_Scalar( lastTweakLow, lastTweakHigh );
            tweakBuffer[ aesEncryptXtsLoop ].ull[0] = lastTweakLow;
            tweakBuffer[ aesEncryptXtsLoop ].ull[1] = lastTweakHigh;
        }

        do
        {
            roundkey = _mm_loadu_si128( (__m128i *) keyPtr );
            keyPtr ++;
            c0 = _mm_aesenc_si128( c0, roundkey );
            c1 = _mm_aesenc_si128( c1, roundkey );
            c2 = _mm_aesenc_si128( c2, roundkey );
            c3 = _mm_aesenc_si128( c3, roundkey );
            c4 = _mm_aesenc_si128( c4, roundkey );
            c5 = _mm_aesenc_si128( c5, roundkey );
            c6 = _mm_aesenc_si128( c6, roundkey );
            c7 = _mm_aesenc_si128( c7, roundkey );
        } while( keyPtr < keyLimit );

        _mm_storeu_si128( (__m128i *) (pbDst +   0), _mm_aesenclast_si128( c0, tweakBuffer[ 8].m128i ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  16), _mm_aesenclast_si128( c1, tweakBuffer[ 9].m128i ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  32), _mm_aesenclast_si128( c2, tweakBuffer[10].m128i ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  48), _mm_aesenclast_si128( c3, tweakBuffer[11].m128i ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  64), _mm_aesenclast_si128( c4, tweakBuffer[12].m128i ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  80), _mm_aesenclast_si128( c5, tweakBuffer[13].m128i ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  96), _mm_aesenclast_si128( c6, tweakBuffer[14].m128i ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 112), _mm_aesenclast_si128( c7, tweakBuffer[15].m128i ) );

        pbSrc += 8 * SYMCRYPT_AES_BLOCK_SIZE;
        pbDst += 8 * SYMCRYPT_AES_BLOCK_SIZE;
        cbData -= 8 * SYMCRYPT_AES_BLOCK_SIZE;
    }

    // Rare case, with data unit length not being multiple of 128 bytes, handle the tail one block at a time
    // NOTE: we enforce that cbData is a multiple of SYMCRYPT_AES_BLOCK_SIZE for XTS
    if( cbData >= SYMCRYPT_AES_BLOCK_SIZE)
    {
        t0 = tweakBuffer[0].m128i;

        do
        {
            c0 = _mm_xor_si128( t0, _mm_loadu_si128( ( __m128i * ) pbSrc ) );
            pbSrc += SYMCRYPT_AES_BLOCK_SIZE;
            AES_ENCRYPT_1( pExpandedKey, c0 );
            _mm_storeu_si128( (__m128i *) pbDst, _mm_xor_si128( c0, t0 ) );
            pbDst += SYMCRYPT_AES_BLOCK_SIZE;
            XTS_MUL_ALPHA ( t0, t0 );
            cbData -= SYMCRYPT_AES_BLOCK_SIZE;
        } while( cbData >= SYMCRYPT_AES_BLOCK_SIZE );
    }
}

VOID
SYMCRYPT_CALL
SymCryptXtsAesDecryptDataUnitXmm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )       PBYTE                       pbTweakBlock,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE*16 )  PBYTE                       pbScratch,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
    __m128i t0;
    __m128i c0, c1, c2, c3, c4, c5, c6, c7;
    __m128i roundkey, firstRoundKey, lastRoundKey;
    __m128i XTS_ALPHA_MASK = _mm_set_epi32( 1, 1, 1, 0x87 );
    SYMCRYPT_GF128_ELEMENT* tweakBuffer = (SYMCRYPT_GF128_ELEMENT*) pbScratch;

    const BYTE (*keyPtr)[4][4];
    const BYTE (*keyLimit)[4][4] = pExpandedKey->lastDecRoundKey;
    UINT64 lastTweakLow, lastTweakHigh;
    int aesDecryptXtsLoop;

    c0 = _mm_loadu_si128( (__m128i *) pbTweakBlock );
    XTS_MUL_ALPHA( c0, c1 );
    XTS_MUL_ALPHA( c1, c2 );
    XTS_MUL_ALPHA( c2, c3 );

    XTS_MUL_ALPHA4( c0, c4 );
    XTS_MUL_ALPHA ( c4, c5 );
    XTS_MUL_ALPHA ( c5, c6 );
    XTS_MUL_ALPHA ( c6, c7 );

    tweakBuffer[0].m128i = c0;
    tweakBuffer[1].m128i = c1;
    tweakBuffer[2].m128i = c2;
    tweakBuffer[3].m128i = c3;
    tweakBuffer[4].m128i = c4;
    tweakBuffer[5].m128i = c5;
    tweakBuffer[6].m128i = c6;
    tweakBuffer[7].m128i = c7;
    lastTweakLow  = tweakBuffer[7].ull[0];
    lastTweakHigh = tweakBuffer[7].ull[1];

    firstRoundKey = _mm_loadu_si128( (__m128i *) pExpandedKey->lastEncRoundKey );
    lastRoundKey = _mm_loadu_si128( (__m128i *) pExpandedKey->lastDecRoundKey );

    while( cbData >= 8 * SYMCRYPT_AES_BLOCK_SIZE )
    {
        // At loop entry, tweakBuffer[0-7] are tweakValues for the next 8 blocks
        c0 = _mm_xor_si128( tweakBuffer[0].m128i, firstRoundKey );
        c1 = _mm_xor_si128( tweakBuffer[1].m128i, firstRoundKey );
        c2 = _mm_xor_si128( tweakBuffer[2].m128i, firstRoundKey );
        c3 = _mm_xor_si128( tweakBuffer[3].m128i, firstRoundKey );
        c4 = _mm_xor_si128( tweakBuffer[4].m128i, firstRoundKey );
        c5 = _mm_xor_si128( tweakBuffer[5].m128i, firstRoundKey );
        c6 = _mm_xor_si128( tweakBuffer[6].m128i, firstRoundKey );
        c7 = _mm_xor_si128( tweakBuffer[7].m128i, firstRoundKey );

        c0 = _mm_xor_si128( c0, _mm_loadu_si128( ( __m128i * ) (pbSrc +   0) ) );
        c1 = _mm_xor_si128( c1, _mm_loadu_si128( ( __m128i * ) (pbSrc +  16) ) );
        c2 = _mm_xor_si128( c2, _mm_loadu_si128( ( __m128i * ) (pbSrc +  32) ) );
        c3 = _mm_xor_si128( c3, _mm_loadu_si128( ( __m128i * ) (pbSrc +  48) ) );
        c4 = _mm_xor_si128( c4, _mm_loadu_si128( ( __m128i * ) (pbSrc +  64) ) );
        c5 = _mm_xor_si128( c5, _mm_loadu_si128( ( __m128i * ) (pbSrc +  80) ) );
        c6 = _mm_xor_si128( c6, _mm_loadu_si128( ( __m128i * ) (pbSrc +  96) ) );
        c7 = _mm_xor_si128( c7, _mm_loadu_si128( ( __m128i * ) (pbSrc + 112) ) );

        keyPtr = pExpandedKey->lastEncRoundKey + 1;

        // Do 8 full rounds (AES-128|AES-192|AES-256) with stitched XTS (peformed in scalar registers)
        for( aesDecryptXtsLoop = 0; aesDecryptXtsLoop < 8; aesDecryptXtsLoop++ )
        {
            roundkey = _mm_loadu_si128( (__m128i *) keyPtr );
            keyPtr ++;
            c0 = _mm_aesdec_si128( c0, roundkey );
            c1 = _mm_aesdec_si128( c1, roundkey );
            c2 = _mm_aesdec_si128( c2, roundkey );
            c3 = _mm_aesdec_si128( c3, roundkey );
            c4 = _mm_aesdec_si128( c4, roundkey );
            c5 = _mm_aesdec_si128( c5, roundkey );
            c6 = _mm_aesdec_si128( c6, roundkey );
            c7 = _mm_aesdec_si128( c7, roundkey );

            // Prepare tweakBuffer[8-15] with tweak^lastRoundKey
            tweakBuffer[ 8+aesDecryptXtsLoop ].m128i = _mm_xor_si128( tweakBuffer[ aesDecryptXtsLoop ].m128i, lastRoundKey );
            // Prepare tweakBuffer[0-7] with tweaks for next 8 blocks
            XTS_MUL_ALPHA_Scalar( lastTweakLow, lastTweakHigh );
            tweakBuffer[ aesDecryptXtsLoop ].ull[0] = lastTweakLow;
            tweakBuffer[ aesDecryptXtsLoop ].ull[1] = lastTweakHigh;
        }

        do
        {
            roundkey = _mm_loadu_si128( (__m128i *) keyPtr );
            keyPtr ++;
            c0 = _mm_aesdec_si128( c0, roundkey );
            c1 = _mm_aesdec_si128( c1, roundkey );
            c2 = _mm_aesdec_si128( c2, roundkey );
            c3 = _mm_aesdec_si128( c3, roundkey );
            c4 = _mm_aesdec_si128( c4, roundkey );
            c5 = _mm_aesdec_si128( c5, roundkey );
            c6 = _mm_aesdec_si128( c6, roundkey );
            c7 = _mm_aesdec_si128( c7, roundkey );
        } while( keyPtr < keyLimit );

        _mm_storeu_si128( (__m128i *) (pbDst +   0), _mm_aesdeclast_si128( c0, tweakBuffer[ 8].m128i ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  16), _mm_aesdeclast_si128( c1, tweakBuffer[ 9].m128i ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  32), _mm_aesdeclast_si128( c2, tweakBuffer[10].m128i ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  48), _mm_aesdeclast_si128( c3, tweakBuffer[11].m128i ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  64), _mm_aesdeclast_si128( c4, tweakBuffer[12].m128i ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  80), _mm_aesdeclast_si128( c5, tweakBuffer[13].m128i ) );
        _mm_storeu_si128( (__m128i *) (pbDst +  96), _mm_aesdeclast_si128( c6, tweakBuffer[14].m128i ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 112), _mm_aesdeclast_si128( c7, tweakBuffer[15].m128i ) );

        pbSrc += 8 * SYMCRYPT_AES_BLOCK_SIZE;
        pbDst += 8 * SYMCRYPT_AES_BLOCK_SIZE;
        cbData -= 8 * SYMCRYPT_AES_BLOCK_SIZE;
    }

    // Rare case, with data unit length not being multiple of 128 bytes, handle the tail one block at a time
    // NOTE: we enforce that cbData is a multiple of SYMCRYPT_AES_BLOCK_SIZE for XTS
    if( cbData >= SYMCRYPT_AES_BLOCK_SIZE)
    {
        t0 = tweakBuffer[0].m128i;

        do
        {
            c0 = _mm_xor_si128( t0, _mm_loadu_si128( ( __m128i * ) pbSrc ) );
            pbSrc += SYMCRYPT_AES_BLOCK_SIZE;
            AES_DECRYPT_1( pExpandedKey, c0 );
            _mm_storeu_si128( (__m128i *) pbDst, _mm_xor_si128( c0, t0 ) );
            pbDst += SYMCRYPT_AES_BLOCK_SIZE;
            XTS_MUL_ALPHA ( t0, t0 );
            cbData -= SYMCRYPT_AES_BLOCK_SIZE;
        } while( cbData >= SYMCRYPT_AES_BLOCK_SIZE );
    }
}

VOID
SYMCRYPT_CALL
SymCryptXtsAesEncryptDataUnitZmm_2048(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbTweakBlock,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE*16 )  PBYTE                       pbScratch,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
    __m128i t0, t1, t2, t3, t4, t5, t6, t7;
    __m512i c0, c1, c2, c3;
    __m128i XTS_ALPHA_MASK;
    __m512i XTS_ALPHA_MULTIPLIER_Zmm;

    // Load tweaks into big T
    __m512i T0, T1, T2, T3;

    if( cbData < 16 * SYMCRYPT_AES_BLOCK_SIZE )
    {
        SymCryptXtsAesEncryptDataUnitXmm( pExpandedKey, pbTweakBlock, pbScratch, pbSrc, pbDst, cbData );
        return;
    }

    t0 = _mm_loadu_si128( (__m128i *) pbTweakBlock );
    XTS_ALPHA_MASK = _mm_set_epi32( 1, 1, 1, 0x87 );
    XTS_ALPHA_MULTIPLIER_Zmm = _mm512_set_epi64( 0, 0x87, 0, 0x87, 0, 0x87, 0, 0x87 );

    // Do not stall.
    XTS_MUL_ALPHA4( t0, t4 );
    XTS_MUL_ALPHA ( t0, t1 );
    XTS_MUL_ALPHA ( t4, t5 );
    XTS_MUL_ALPHA ( t1, t2 );
    XTS_MUL_ALPHA ( t5, t6 );
    XTS_MUL_ALPHA ( t2, t3 );
    XTS_MUL_ALPHA ( t6, t7 );

    T0 = _mm512_castsi128_si512( t0 );
    T0 = _mm512_inserti64x2( T0, t1, 1 );
    T0 = _mm512_inserti64x2( T0, t2, 2 );
    T0 = _mm512_inserti64x2( T0, t3, 3 );

    T1 = _mm512_castsi128_si512( t4 );
    T1 = _mm512_inserti64x2( T1, t5, 1 );
    T1 = _mm512_inserti64x2( T1, t6, 2 );
    T1 = _mm512_inserti64x2( T1, t7, 3 );

    XTS_MUL_ALPHA8_ZMM(T0, T2);
    XTS_MUL_ALPHA8_ZMM(T1, T3);

    for(;;)
    {
        c0 = _mm512_xor_si512( T0, _mm512_loadu_si512( ( pbSrc +                           0 ) ) );
        c1 = _mm512_xor_si512( T1, _mm512_loadu_si512( ( pbSrc +   4*SYMCRYPT_AES_BLOCK_SIZE ) ) );
        c2 = _mm512_xor_si512( T2, _mm512_loadu_si512( ( pbSrc +   8*SYMCRYPT_AES_BLOCK_SIZE ) ) );
        c3 = _mm512_xor_si512( T3, _mm512_loadu_si512( ( pbSrc +  12*SYMCRYPT_AES_BLOCK_SIZE ) ) );

        pbSrc += 16 * SYMCRYPT_AES_BLOCK_SIZE;

        AES_ENCRYPT_ZMM_2048( pExpandedKey, c0, c1, c2, c3 );
        _mm512_store_si512( ( pbDst +                          0 ), _mm512_xor_si512( c0, T0 ) );
        _mm512_store_si512( ( pbDst +  4*SYMCRYPT_AES_BLOCK_SIZE ), _mm512_xor_si512( c1, T1 ) );
        _mm512_store_si512( ( pbDst +  8*SYMCRYPT_AES_BLOCK_SIZE ), _mm512_xor_si512( c2, T2 ) );
        _mm512_store_si512( ( pbDst + 12*SYMCRYPT_AES_BLOCK_SIZE ), _mm512_xor_si512( c3, T3 ) );

        pbDst += 16 * SYMCRYPT_AES_BLOCK_SIZE;

        cbData -= 16 * SYMCRYPT_AES_BLOCK_SIZE;
        if( cbData < 16 * SYMCRYPT_AES_BLOCK_SIZE )
        {
            break;
        }

        XTS_MUL_ALPHA16_ZMM(T0, T0);
        XTS_MUL_ALPHA16_ZMM(T1, T1);
        XTS_MUL_ALPHA16_ZMM(T2, T2);
        XTS_MUL_ALPHA16_ZMM(T3, T3);
    }

    // We won't do another 16-block set so we don't update the tweak blocks

    if( cbData > 0  )
    {
        //
        // This is a rare case: the data unit length is not a multiple of 256 bytes.
        // We do this in the Xmm implementation.
        // Fix up the tweak block first
        //
        t7 = _mm512_extracti64x2_epi64( T3, 3 /* Highest 128 bits */ );
        _mm256_zeroupper();
        XTS_MUL_ALPHA( t7, t0 );
        _mm_storeu_si128( (__m128i *) pbTweakBlock, t0 );

        SymCryptXtsAesEncryptDataUnitXmm( pExpandedKey, pbTweakBlock, pbScratch, pbSrc, pbDst, cbData );
    }
    else {
        _mm256_zeroupper();
    }
}

VOID
SYMCRYPT_CALL
SymCryptXtsAesDecryptDataUnitZmm_2048(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbTweakBlock,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE*16 )  PBYTE                       pbScratch,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
    __m128i t0, t1, t2, t3, t4, t5, t6, t7;
    __m512i c0, c1, c2, c3;
    __m128i XTS_ALPHA_MASK;
    __m512i XTS_ALPHA_MULTIPLIER_Zmm;

    // Load tweaks into big T
    __m512i T0, T1, T2, T3;

    if( cbData < 16 * SYMCRYPT_AES_BLOCK_SIZE )
    {
        SymCryptXtsAesDecryptDataUnitXmm( pExpandedKey, pbTweakBlock, pbScratch, pbSrc, pbDst, cbData );
        return;
    }

    t0 = _mm_loadu_si128( (__m128i *) pbTweakBlock );
    XTS_ALPHA_MASK = _mm_set_epi32( 1, 1, 1, 0x87 );
    XTS_ALPHA_MULTIPLIER_Zmm = _mm512_set_epi64( 0, 0x87, 0, 0x87, 0, 0x87, 0, 0x87 );

    // Do not stall.
    XTS_MUL_ALPHA4( t0, t4 );
    XTS_MUL_ALPHA ( t0, t1 );
    XTS_MUL_ALPHA ( t4, t5 );
    XTS_MUL_ALPHA ( t1, t2 );
    XTS_MUL_ALPHA ( t5, t6 );
    XTS_MUL_ALPHA ( t2, t3 );
    XTS_MUL_ALPHA ( t6, t7 );

    T0 = _mm512_castsi128_si512( t0 );
    T0 = _mm512_inserti64x2( T0, t1, 1 );
    T0 = _mm512_inserti64x2( T0, t2, 2 );
    T0 = _mm512_inserti64x2( T0, t3, 3 );

    T1 = _mm512_castsi128_si512( t4 );
    T1 = _mm512_inserti64x2( T1, t5, 1 );
    T1 = _mm512_inserti64x2( T1, t6, 2 );
    T1 = _mm512_inserti64x2( T1, t7, 3 );

    XTS_MUL_ALPHA8_ZMM(T0, T2);
    XTS_MUL_ALPHA8_ZMM(T1, T3);

    for(;;)
    {
        c0 = _mm512_xor_si512( T0, _mm512_loadu_si512( ( pbSrc +                           0 ) ) );
        c1 = _mm512_xor_si512( T1, _mm512_loadu_si512( ( pbSrc +   4*SYMCRYPT_AES_BLOCK_SIZE ) ) );
        c2 = _mm512_xor_si512( T2, _mm512_loadu_si512( ( pbSrc +   8*SYMCRYPT_AES_BLOCK_SIZE ) ) );
        c3 = _mm512_xor_si512( T3, _mm512_loadu_si512( ( pbSrc +  12*SYMCRYPT_AES_BLOCK_SIZE ) ) );

        pbSrc += 16 * SYMCRYPT_AES_BLOCK_SIZE;

        AES_DECRYPT_ZMM_2048( pExpandedKey, c0, c1, c2, c3 );
        _mm512_store_si512( ( pbDst +                          0 ), _mm512_xor_si512( c0, T0 ) );
        _mm512_store_si512( ( pbDst +  4*SYMCRYPT_AES_BLOCK_SIZE ), _mm512_xor_si512( c1, T1 ) );
        _mm512_store_si512( ( pbDst +  8*SYMCRYPT_AES_BLOCK_SIZE ), _mm512_xor_si512( c2, T2 ) );
        _mm512_store_si512( ( pbDst + 12*SYMCRYPT_AES_BLOCK_SIZE ), _mm512_xor_si512( c3, T3 ) );

        pbDst += 16 * SYMCRYPT_AES_BLOCK_SIZE;

        cbData -= 16 * SYMCRYPT_AES_BLOCK_SIZE;
        if( cbData < 16 * SYMCRYPT_AES_BLOCK_SIZE )
        {
            break;
        }

        XTS_MUL_ALPHA16_ZMM(T0, T0);
        XTS_MUL_ALPHA16_ZMM(T1, T1);
        XTS_MUL_ALPHA16_ZMM(T2, T2);
        XTS_MUL_ALPHA16_ZMM(T3, T3);
    }

    // We won't do another 16-block set so we don't update the tweak blocks

    if( cbData > 0  )
    {
        //
        // This is a rare case: the data unit length is not a multiple of 256 bytes.
        // We do this in the Xmm implementation.
        // Fix up the tweak block first
        //
        t7 = _mm512_extracti64x2_epi64( T3, 3 /* Highest 128 bits */ );
        _mm256_zeroupper();
        XTS_MUL_ALPHA( t7, t0 );
        _mm_storeu_si128( (__m128i *) pbTweakBlock, t0 );

        SymCryptXtsAesDecryptDataUnitXmm( pExpandedKey, pbTweakBlock, pbScratch, pbSrc, pbDst, cbData );
    }
    else {
        _mm256_zeroupper();
    }
}

VOID
SYMCRYPT_CALL
SymCryptXtsAesEncryptDataUnitYmm_2048(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbTweakBlock,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE*16 )  PBYTE                       pbScratch,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
    __m128i t0, t1, t2, t3, t4, t5, t6, t7;
    __m256i c0, c1, c2, c3, c4, c5, c6, c7;
    __m128i XTS_ALPHA_MASK;
    __m256i XTS_ALPHA_MULTIPLIER_Ymm;

    // Load tweaks into big T
    __m256i T0, T1, T2, T3, T4, T5, T6, T7;

    if( cbData < 16 * SYMCRYPT_AES_BLOCK_SIZE )
    {
        SymCryptXtsAesEncryptDataUnitXmm( pExpandedKey, pbTweakBlock, pbScratch, pbSrc, pbDst, cbData );
        return;
    }

    t0 = _mm_loadu_si128( (__m128i *) pbTweakBlock );
    XTS_ALPHA_MASK = _mm_set_epi32( 1, 1, 1, 0x87 );
    XTS_ALPHA_MULTIPLIER_Ymm = _mm256_set_epi64x( 0, 0x87, 0, 0x87 );

    // Do not stall.
    XTS_MUL_ALPHA4( t0, t4 );
    XTS_MUL_ALPHA ( t0, t1 );
    XTS_MUL_ALPHA ( t4, t5 );
    XTS_MUL_ALPHA ( t1, t2 );
    XTS_MUL_ALPHA ( t5, t6 );
    XTS_MUL_ALPHA ( t2, t3 );
    XTS_MUL_ALPHA ( t6, t7 );

    T0 = _mm256_insertf128_si256( _mm256_castsi128_si256( t0 ), t1, 1 ); // AVX
    T1 = _mm256_insertf128_si256( _mm256_castsi128_si256( t2 ), t3, 1 );
    T2 = _mm256_insertf128_si256( _mm256_castsi128_si256( t4 ), t5, 1 );
    T3 = _mm256_insertf128_si256( _mm256_castsi128_si256( t6 ), t7, 1 );
    XTS_MUL_ALPHA8_YMM(T0, T4);
    XTS_MUL_ALPHA8_YMM(T1, T5);
    XTS_MUL_ALPHA8_YMM(T2, T6);
    XTS_MUL_ALPHA8_YMM(T3, T7);

    for(;;)
    {
        c0 = _mm256_xor_si256( T0, _mm256_loadu_si256( ( __m256i * ) ( pbSrc +                           0 ) ) );
        c1 = _mm256_xor_si256( T1, _mm256_loadu_si256( ( __m256i * ) ( pbSrc +   2*SYMCRYPT_AES_BLOCK_SIZE ) ) );
        c2 = _mm256_xor_si256( T2, _mm256_loadu_si256( ( __m256i * ) ( pbSrc +   4*SYMCRYPT_AES_BLOCK_SIZE ) ) );
        c3 = _mm256_xor_si256( T3, _mm256_loadu_si256( ( __m256i * ) ( pbSrc +   6*SYMCRYPT_AES_BLOCK_SIZE ) ) );
        c4 = _mm256_xor_si256( T4, _mm256_loadu_si256( ( __m256i * ) ( pbSrc +   8*SYMCRYPT_AES_BLOCK_SIZE ) ) );
        c5 = _mm256_xor_si256( T5, _mm256_loadu_si256( ( __m256i * ) ( pbSrc +  10*SYMCRYPT_AES_BLOCK_SIZE ) ) );
        c6 = _mm256_xor_si256( T6, _mm256_loadu_si256( ( __m256i * ) ( pbSrc +  12*SYMCRYPT_AES_BLOCK_SIZE ) ) );
        c7 = _mm256_xor_si256( T7, _mm256_loadu_si256( ( __m256i * ) ( pbSrc +  14*SYMCRYPT_AES_BLOCK_SIZE ) ) );

        pbSrc += 16 * SYMCRYPT_AES_BLOCK_SIZE;

        AES_ENCRYPT_YMM_2048( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 );

        _mm256_store_si256( ( __m256i * ) ( pbDst +                          0 ), _mm256_xor_si256( c0, T0 ) );
        _mm256_store_si256( ( __m256i * ) ( pbDst +  2*SYMCRYPT_AES_BLOCK_SIZE ), _mm256_xor_si256( c1, T1 ) );
        _mm256_store_si256( ( __m256i * ) ( pbDst +  4*SYMCRYPT_AES_BLOCK_SIZE ), _mm256_xor_si256( c2, T2 ) );
        _mm256_store_si256( ( __m256i * ) ( pbDst +  6*SYMCRYPT_AES_BLOCK_SIZE ), _mm256_xor_si256( c3, T3 ) );
        _mm256_store_si256( ( __m256i * ) ( pbDst +  8*SYMCRYPT_AES_BLOCK_SIZE ), _mm256_xor_si256( c4, T4 ) );
        _mm256_store_si256( ( __m256i * ) ( pbDst + 10*SYMCRYPT_AES_BLOCK_SIZE ), _mm256_xor_si256( c5, T5 ) );
        _mm256_store_si256( ( __m256i * ) ( pbDst + 12*SYMCRYPT_AES_BLOCK_SIZE ), _mm256_xor_si256( c6, T6 ) );
        _mm256_store_si256( ( __m256i * ) ( pbDst + 14*SYMCRYPT_AES_BLOCK_SIZE ), _mm256_xor_si256( c7, T7 ) );

        pbDst += 16 * SYMCRYPT_AES_BLOCK_SIZE;

        cbData -= 16 * SYMCRYPT_AES_BLOCK_SIZE;
        if( cbData < 16 * SYMCRYPT_AES_BLOCK_SIZE )
        {
            break;
        }

        XTS_MUL_ALPHA16_YMM(T0, T0);
        XTS_MUL_ALPHA16_YMM(T1, T1);
        XTS_MUL_ALPHA16_YMM(T2, T2);
        XTS_MUL_ALPHA16_YMM(T3, T3);
        XTS_MUL_ALPHA16_YMM(T4, T4);
        XTS_MUL_ALPHA16_YMM(T5, T5);
        XTS_MUL_ALPHA16_YMM(T6, T6);
        XTS_MUL_ALPHA16_YMM(T7, T7);
    }

    // We won't do another 16-block set so we don't update the tweak blocks

    if( cbData > 0  )
    {
        //
        // This is a rare case: the data unit length is not a multiple of 256 bytes.
        // We do this in the Xmm implementation.
        // Fix up the tweak block first
        //
        t7 = _mm256_extracti128_si256 ( T7, 1 /* Highest 128 bits */ ); // AVX2
        _mm256_zeroupper();
        XTS_MUL_ALPHA( t7, t0 );
        _mm_storeu_si128( (__m128i *) pbTweakBlock, t0 );

        SymCryptXtsAesEncryptDataUnitXmm( pExpandedKey, pbTweakBlock, pbScratch, pbSrc, pbDst, cbData );
    }
    else {
        _mm256_zeroupper();
    }
}

VOID
SYMCRYPT_CALL
SymCryptXtsAesDecryptDataUnitYmm_2048(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbTweakBlock,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE*16 )  PBYTE                       pbScratch,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData )
{
    __m128i t0, t1, t2, t3, t4, t5, t6, t7;
    __m256i c0, c1, c2, c3, c4, c5, c6, c7;
    __m128i XTS_ALPHA_MASK;
    __m256i XTS_ALPHA_MULTIPLIER_Ymm;

    // Load tweaks into big T
    __m256i T0, T1, T2, T3, T4, T5, T6, T7;

    if( cbData < 16 * SYMCRYPT_AES_BLOCK_SIZE )
    {
        SymCryptXtsAesDecryptDataUnitXmm( pExpandedKey, pbTweakBlock, pbScratch, pbSrc, pbDst, cbData );
        return;
    }

    t0 = _mm_loadu_si128( (__m128i *) pbTweakBlock );
    XTS_ALPHA_MASK = _mm_set_epi32( 1, 1, 1, 0x87 );
    XTS_ALPHA_MULTIPLIER_Ymm = _mm256_set_epi64x( 0, 0x87, 0, 0x87 );

    // Do not stall.
    XTS_MUL_ALPHA4( t0, t4 );
    XTS_MUL_ALPHA ( t0, t1 );
    XTS_MUL_ALPHA ( t4, t5 );
    XTS_MUL_ALPHA ( t1, t2 );
    XTS_MUL_ALPHA ( t5, t6 );
    XTS_MUL_ALPHA ( t2, t3 );
    XTS_MUL_ALPHA ( t6, t7 );

    T0 = _mm256_insertf128_si256( _mm256_castsi128_si256( t0 ), t1, 1); // AVX
    T1 = _mm256_insertf128_si256( _mm256_castsi128_si256( t2 ), t3, 1);
    T2 = _mm256_insertf128_si256( _mm256_castsi128_si256( t4 ), t5, 1);
    T3 = _mm256_insertf128_si256( _mm256_castsi128_si256( t6 ), t7, 1);
    XTS_MUL_ALPHA8_YMM(T0, T4);
    XTS_MUL_ALPHA8_YMM(T1, T5);
    XTS_MUL_ALPHA8_YMM(T2, T6);
    XTS_MUL_ALPHA8_YMM(T3, T7);

    for(;;)
    {
        c0 = _mm256_xor_si256( T0, _mm256_loadu_si256( ( __m256i * ) ( pbSrc +                           0 ) ) );
        c1 = _mm256_xor_si256( T1, _mm256_loadu_si256( ( __m256i * ) ( pbSrc +   2*SYMCRYPT_AES_BLOCK_SIZE ) ) );
        c2 = _mm256_xor_si256( T2, _mm256_loadu_si256( ( __m256i * ) ( pbSrc +   4*SYMCRYPT_AES_BLOCK_SIZE ) ) );
        c3 = _mm256_xor_si256( T3, _mm256_loadu_si256( ( __m256i * ) ( pbSrc +   6*SYMCRYPT_AES_BLOCK_SIZE ) ) );
        c4 = _mm256_xor_si256( T4, _mm256_loadu_si256( ( __m256i * ) ( pbSrc +   8*SYMCRYPT_AES_BLOCK_SIZE ) ) );
        c5 = _mm256_xor_si256( T5, _mm256_loadu_si256( ( __m256i * ) ( pbSrc +  10*SYMCRYPT_AES_BLOCK_SIZE ) ) );
        c6 = _mm256_xor_si256( T6, _mm256_loadu_si256( ( __m256i * ) ( pbSrc +  12*SYMCRYPT_AES_BLOCK_SIZE ) ) );
        c7 = _mm256_xor_si256( T7, _mm256_loadu_si256( ( __m256i * ) ( pbSrc +  14*SYMCRYPT_AES_BLOCK_SIZE ) ) );

        pbSrc += 16 * SYMCRYPT_AES_BLOCK_SIZE;

        AES_DECRYPT_YMM_2048( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 );

        _mm256_store_si256( ( __m256i * ) ( pbDst +                          0 ), _mm256_xor_si256( c0, T0 ) );
        _mm256_store_si256( ( __m256i * ) ( pbDst +  2*SYMCRYPT_AES_BLOCK_SIZE ), _mm256_xor_si256( c1, T1 ) );
        _mm256_store_si256( ( __m256i * ) ( pbDst +  4*SYMCRYPT_AES_BLOCK_SIZE ), _mm256_xor_si256( c2, T2 ) );
        _mm256_store_si256( ( __m256i * ) ( pbDst +  6*SYMCRYPT_AES_BLOCK_SIZE ), _mm256_xor_si256( c3, T3 ) );
        _mm256_store_si256( ( __m256i * ) ( pbDst +  8*SYMCRYPT_AES_BLOCK_SIZE ), _mm256_xor_si256( c4, T4 ) );
        _mm256_store_si256( ( __m256i * ) ( pbDst + 10*SYMCRYPT_AES_BLOCK_SIZE ), _mm256_xor_si256( c5, T5 ) );
        _mm256_store_si256( ( __m256i * ) ( pbDst + 12*SYMCRYPT_AES_BLOCK_SIZE ), _mm256_xor_si256( c6, T6 ) );
        _mm256_store_si256( ( __m256i * ) ( pbDst + 14*SYMCRYPT_AES_BLOCK_SIZE ), _mm256_xor_si256( c7, T7 ) );

        pbDst += 16 * SYMCRYPT_AES_BLOCK_SIZE;

        cbData -= 16 * SYMCRYPT_AES_BLOCK_SIZE;
        if( cbData < 16 * SYMCRYPT_AES_BLOCK_SIZE )
        {
            break;
        }

        XTS_MUL_ALPHA16_YMM(T0, T0);
        XTS_MUL_ALPHA16_YMM(T1, T1);
        XTS_MUL_ALPHA16_YMM(T2, T2);
        XTS_MUL_ALPHA16_YMM(T3, T3);
        XTS_MUL_ALPHA16_YMM(T4, T4);
        XTS_MUL_ALPHA16_YMM(T5, T5);
        XTS_MUL_ALPHA16_YMM(T6, T6);
        XTS_MUL_ALPHA16_YMM(T7, T7);
    }

    // We won't do another 16-block set so we don't update the tweak blocks

    if( cbData > 0  )
    {
        //
        // This is a rare case: the data unit length is not a multiple of 256 bytes.
        // We do this in the Xmm implementation.
        // Fix up the tweak block first
        //
        t7 = _mm256_extracti128_si256 ( T7, 1 /* Highest 128 bits */ ); // AVX2
        _mm256_zeroupper();
        XTS_MUL_ALPHA( t7, t0 );
        _mm_storeu_si128( (__m128i *) pbTweakBlock, t0 );

        SymCryptXtsAesDecryptDataUnitXmm( pExpandedKey, pbTweakBlock, pbScratch, pbSrc, pbDst, cbData );
    }
    else {
        _mm256_zeroupper();
    }
}

#include "ghash_definitions.h"

#define AES_FULLROUND_4_GHASH_1( roundkey, keyPtr, c0, c1, c2, c3, r0, t0, t1, gHashPointer, byteReverseOrder, gHashExpandedKeyTable, todo, resl, resm, resh ) \
{ \
    roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
    keyPtr ++; \
    c0 = _mm_aesenc_si128( c0, roundkey ); \
    c1 = _mm_aesenc_si128( c1, roundkey ); \
    c2 = _mm_aesenc_si128( c2, roundkey ); \
    c3 = _mm_aesenc_si128( c3, roundkey ); \
\
    r0 = _mm_loadu_si128( (__m128i *) gHashPointer ); \
    r0 = _mm_shuffle_epi8( r0, byteReverseOrder ); \
    gHashPointer += 16; \
\
    t1 = _mm_loadu_si128( (__m128i *) &GHASH_H_POWER(gHashExpandedKeyTable, todo) ); \
    t0 = _mm_clmulepi64_si128( r0, t1, 0x00 ); \
    t1 = _mm_clmulepi64_si128( r0, t1, 0x11 ); \
\
    resl = _mm_xor_si128( resl, t0 ); \
    resh = _mm_xor_si128( resh, t1 ); \
\
    t0 = _mm_srli_si128( r0, 8 ); \
    r0 = _mm_xor_si128( r0, t0 ); \
    t1 = _mm_loadu_si128( (__m128i *) &GHASH_Hx_POWER(gHashExpandedKeyTable, todo) ); \
    t1 = _mm_clmulepi64_si128( r0, t1, 0x00 ); \
\
    resm = _mm_xor_si128( resm, t1 ); \
    todo --; \
};

#define AES_GCM_ENCRYPT_4( pExpandedKey, c0, c1, c2, c3, gHashPointer, ghashRounds, byteReverseOrder, gHashExpandedKeyTable, todo, resl, resm, resh ) \
{ \
    const BYTE (*keyPtr)[4][4]; \
    const BYTE (*keyLimit)[4][4]; \
    __m128i roundkey; \
    __m128i t0, t1; \
    __m128i r0; \
    SIZE_T aesEncryptGhashLoop; \
\
    keyPtr = &pExpandedKey->RoundKey[0]; \
    keyLimit = pExpandedKey->lastEncRoundKey; \
\
    roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
    keyPtr ++; \
    c0 = _mm_xor_si128( c0, roundkey ); \
    c1 = _mm_xor_si128( c1, roundkey ); \
    c2 = _mm_xor_si128( c2, roundkey ); \
    c3 = _mm_xor_si128( c3, roundkey ); \
\
    /* Do ghashRounds full rounds (AES-128|AES-192|AES-256) with stitched GHASH */ \
    for( aesEncryptGhashLoop = 0; aesEncryptGhashLoop < ghashRounds; aesEncryptGhashLoop++ ) \
    { \
        AES_FULLROUND_4_GHASH_1( roundkey, keyPtr, c0, c1, c2, c3, r0, t0, t1, gHashPointer, byteReverseOrder, gHashExpandedKeyTable, todo, resl, resm, resh ); \
    } \
\
    do \
    { \
        roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
        keyPtr ++; \
        c0 = _mm_aesenc_si128( c0, roundkey ); \
        c1 = _mm_aesenc_si128( c1, roundkey ); \
        c2 = _mm_aesenc_si128( c2, roundkey ); \
        c3 = _mm_aesenc_si128( c3, roundkey ); \
    } while( keyPtr < keyLimit ); \
\
    roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
\
    c0 = _mm_aesenclast_si128( c0, roundkey ); \
    c1 = _mm_aesenclast_si128( c1, roundkey ); \
    c2 = _mm_aesenclast_si128( c2, roundkey ); \
    c3 = _mm_aesenclast_si128( c3, roundkey ); \
};

#define AES_FULLROUND_8_GHASH_1( roundkey, keyPtr, c0, c1, c2, c3, c4, c5, c6, c7, r0, t0, t1, gHashPointer, byteReverseOrder, gHashExpandedKeyTable, todo, resl, resm, resh ) \
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
\
    r0 = _mm_loadu_si128( (__m128i *) gHashPointer ); \
    r0 = _mm_shuffle_epi8( r0, byteReverseOrder ); \
    gHashPointer += 16; \
\
    t1 = _mm_loadu_si128( (__m128i *) &GHASH_H_POWER(gHashExpandedKeyTable, todo) ); \
    t0 = _mm_clmulepi64_si128( r0, t1, 0x00 ); \
    t1 = _mm_clmulepi64_si128( r0, t1, 0x11 ); \
\
    resl = _mm_xor_si128( resl, t0 ); \
    resh = _mm_xor_si128( resh, t1 ); \
\
    t0 = _mm_srli_si128( r0, 8 ); \
    r0 = _mm_xor_si128( r0, t0 ); \
    t1 = _mm_loadu_si128( (__m128i *) &GHASH_Hx_POWER(gHashExpandedKeyTable, todo) ); \
    t1 = _mm_clmulepi64_si128( r0, t1, 0x00 ); \
\
    resm = _mm_xor_si128( resm, t1 ); \
    todo --; \
};

#define AES_GCM_ENCRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7, gHashPointer, ghashRounds, byteReverseOrder, gHashExpandedKeyTable, todo, resl, resm, resh ) \
{ \
    const BYTE (*keyPtr)[4][4]; \
    const BYTE (*keyLimit)[4][4]; \
    __m128i roundkey; \
    __m128i t0, t1; \
    __m128i r0; \
    SIZE_T aesEncryptGhashLoop; \
\
    keyPtr = &pExpandedKey->RoundKey[0]; \
    keyLimit = pExpandedKey->lastEncRoundKey; \
\
    roundkey = _mm_loadu_si128( (__m128i *) keyPtr ); \
    keyPtr ++; \
    c0 = _mm_xor_si128( c0, roundkey ); \
    c1 = _mm_xor_si128( c1, roundkey ); \
    c2 = _mm_xor_si128( c2, roundkey ); \
    c3 = _mm_xor_si128( c3, roundkey ); \
    c4 = _mm_xor_si128( c4, roundkey ); \
    c5 = _mm_xor_si128( c5, roundkey ); \
    c6 = _mm_xor_si128( c6, roundkey ); \
    c7 = _mm_xor_si128( c7, roundkey ); \
\
    /* Do ghashRounds full rounds (AES-128|AES-192|AES-256) with stitched GHASH */ \
    for( aesEncryptGhashLoop = 0; aesEncryptGhashLoop < ghashRounds; aesEncryptGhashLoop++ ) \
    { \
        AES_FULLROUND_8_GHASH_1( roundkey, keyPtr, c0, c1, c2, c3, c4, c5, c6, c7, r0, t0, t1, gHashPointer, byteReverseOrder, gHashExpandedKeyTable, todo, resl, resm, resh ); \
    } \
\
    do \
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
    } while( keyPtr < keyLimit ); \
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

// This call is functionally identical to:
// SymCryptAesCtrMsb64Xmm( pExpandedKey,
//                         pbChainingValue,
//                         pbSrc,
//                         pbDst,
//                         cbData );
// SymCryptGHashAppendDataPclmulqdq(   expandedKeyTable,
//                                     pState,
//                                     pbDst,
//                                     cbData );
VOID
SYMCRYPT_CALL
SymCryptAesGcmEncryptStitchedXmm(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( SYMCRYPT_GF128_FIELD_SIZE ) PCSYMCRYPT_GF128_ELEMENT    expandedKeyTable,
    _Inout_                                 PSYMCRYPT_GF128_ELEMENT     pState,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    __m128i chain = _mm_loadu_si128( (__m128i *) pbChainingValue );

    __m128i BYTE_REVERSE_ORDER = _mm_set_epi8(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 );
    __m128i vMultiplicationConstant = _mm_set_epi32( 0, 0, 0xc2000000, 0 );

    __m128i chainIncrement1 = _mm_set_epi32( 0, 0, 0, 1 );
    __m128i chainIncrement2 = _mm_set_epi32( 0, 0, 0, 2 );
    __m128i chainIncrement8 = _mm_set_epi32( 0, 0, 0, 8 );

    __m128i c0, c1, c2, c3, c4, c5, c6, c7;
    __m128i r0, r1;

    __m128i state;
    __m128i a0, a1, a2;
    SIZE_T nBlocks = cbData / SYMCRYPT_GF128_BLOCK_SIZE;
    SIZE_T todo;
    PCBYTE pbGhashSrc = pbDst;

    chain = _mm_shuffle_epi8( chain, BYTE_REVERSE_ORDER );
    state = _mm_loadu_si128( (__m128i *) pState );

    todo = SYMCRYPT_MIN( nBlocks, SYMCRYPT_GHASH_PCLMULQDQ_HPOWERS );
    CLMUL_3( state, GHASH_H_POWER(expandedKeyTable, todo), GHASH_Hx_POWER(expandedKeyTable, todo), a0, a1, a2 );

    // Do 8 blocks of CTR either for tail (if total blocks <8) or for encryption of first 8 blocks
    c0 = chain;
    c1 = _mm_add_epi64( chain, chainIncrement1 );
    c2 = _mm_add_epi64( chain, chainIncrement2 );
    c3 = _mm_add_epi64( c1, chainIncrement2 );
    c4 = _mm_add_epi64( c2, chainIncrement2 );
    c5 = _mm_add_epi64( c3, chainIncrement2 );
    c6 = _mm_add_epi64( c4, chainIncrement2 );
    c7 = _mm_add_epi64( c5, chainIncrement2 );

    c0 = _mm_shuffle_epi8( c0, BYTE_REVERSE_ORDER );
    c1 = _mm_shuffle_epi8( c1, BYTE_REVERSE_ORDER );
    c2 = _mm_shuffle_epi8( c2, BYTE_REVERSE_ORDER );
    c3 = _mm_shuffle_epi8( c3, BYTE_REVERSE_ORDER );
    c4 = _mm_shuffle_epi8( c4, BYTE_REVERSE_ORDER );
    c5 = _mm_shuffle_epi8( c5, BYTE_REVERSE_ORDER );
    c6 = _mm_shuffle_epi8( c6, BYTE_REVERSE_ORDER );
    c7 = _mm_shuffle_epi8( c7, BYTE_REVERSE_ORDER );

    AES_ENCRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 );

    if( nBlocks >= 8 )
    {
        // Encrypt first 8 blocks - update chain
        chain = _mm_add_epi64( chain, chainIncrement8 );

        _mm_storeu_si128( (__m128i *) (pbDst +  0), _mm_xor_si128( c0, _mm_loadu_si128( ( __m128i * ) (pbSrc +  0) ) ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 16), _mm_xor_si128( c1, _mm_loadu_si128( ( __m128i * ) (pbSrc + 16) ) ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 32), _mm_xor_si128( c2, _mm_loadu_si128( ( __m128i * ) (pbSrc + 32) ) ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 48), _mm_xor_si128( c3, _mm_loadu_si128( ( __m128i * ) (pbSrc + 48) ) ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 64), _mm_xor_si128( c4, _mm_loadu_si128( ( __m128i * ) (pbSrc + 64) ) ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 80), _mm_xor_si128( c5, _mm_loadu_si128( ( __m128i * ) (pbSrc + 80) ) ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 96), _mm_xor_si128( c6, _mm_loadu_si128( ( __m128i * ) (pbSrc + 96) ) ) );
        _mm_storeu_si128( (__m128i *) (pbDst +112), _mm_xor_si128( c7, _mm_loadu_si128( ( __m128i * ) (pbSrc +112) ) ) );

        pbDst  += 8 * SYMCRYPT_AES_BLOCK_SIZE;
        pbSrc  += 8 * SYMCRYPT_AES_BLOCK_SIZE;

        while( nBlocks >= 16 )
        {
            // In this loop we always have 8 blocks to encrypt and we have already encrypted the previous 8 blocks ready for GHASH
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

            AES_GCM_ENCRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7, pbGhashSrc, 8, BYTE_REVERSE_ORDER, expandedKeyTable, todo, a0, a1, a2 );

            _mm_storeu_si128( (__m128i *) (pbDst +  0), _mm_xor_si128( c0, _mm_loadu_si128( ( __m128i * ) (pbSrc +  0) ) ) );
            _mm_storeu_si128( (__m128i *) (pbDst + 16), _mm_xor_si128( c1, _mm_loadu_si128( ( __m128i * ) (pbSrc + 16) ) ) );
            _mm_storeu_si128( (__m128i *) (pbDst + 32), _mm_xor_si128( c2, _mm_loadu_si128( ( __m128i * ) (pbSrc + 32) ) ) );
            _mm_storeu_si128( (__m128i *) (pbDst + 48), _mm_xor_si128( c3, _mm_loadu_si128( ( __m128i * ) (pbSrc + 48) ) ) );
            _mm_storeu_si128( (__m128i *) (pbDst + 64), _mm_xor_si128( c4, _mm_loadu_si128( ( __m128i * ) (pbSrc + 64) ) ) );
            _mm_storeu_si128( (__m128i *) (pbDst + 80), _mm_xor_si128( c5, _mm_loadu_si128( ( __m128i * ) (pbSrc + 80) ) ) );
            _mm_storeu_si128( (__m128i *) (pbDst + 96), _mm_xor_si128( c6, _mm_loadu_si128( ( __m128i * ) (pbSrc + 96) ) ) );
            _mm_storeu_si128( (__m128i *) (pbDst +112), _mm_xor_si128( c7, _mm_loadu_si128( ( __m128i * ) (pbSrc +112) ) ) );

            pbDst  += 8 * SYMCRYPT_AES_BLOCK_SIZE;
            pbSrc  += 8 * SYMCRYPT_AES_BLOCK_SIZE;
            nBlocks -= 8;

            if( todo == 0 )
            {
                CLMUL_3_POST( a0, a1, a2 );
                MODREDUCE( vMultiplicationConstant, a0, a1, a2, state );

                todo = SYMCRYPT_MIN( nBlocks, SYMCRYPT_GHASH_PCLMULQDQ_HPOWERS );
                CLMUL_3( state, GHASH_H_POWER(expandedKeyTable, todo), GHASH_Hx_POWER(expandedKeyTable, todo), a0, a1, a2 );
            }
        }

        // We now have at least 8 blocks of encrypted data to GHASH and at most 7 blocks left to encrypt
        // Do 8 blocks of GHASH in parallel with generating 0, 4, or 8 AES-CTR blocks for tail encryption
        nBlocks -= 8;
        if (nBlocks > 0)
        {
            c0 = chain;
            c1 = _mm_add_epi64( chain, chainIncrement1 );
            c2 = _mm_add_epi64( chain, chainIncrement2 );
            c3 = _mm_add_epi64( c1, chainIncrement2 );
            c4 = _mm_add_epi64( c2, chainIncrement2 );

            c0 = _mm_shuffle_epi8( c0, BYTE_REVERSE_ORDER );
            c1 = _mm_shuffle_epi8( c1, BYTE_REVERSE_ORDER );
            c2 = _mm_shuffle_epi8( c2, BYTE_REVERSE_ORDER );
            c3 = _mm_shuffle_epi8( c3, BYTE_REVERSE_ORDER );

            if (nBlocks > 4)
            {
                // Do 8 rounds of AES-CTR for tail in parallel with 8 rounds of GHASH
                c5 = _mm_add_epi64( c4, chainIncrement1 );
                c6 = _mm_add_epi64( c4, chainIncrement2 );

                c4 = _mm_shuffle_epi8( c4, BYTE_REVERSE_ORDER );
                c5 = _mm_shuffle_epi8( c5, BYTE_REVERSE_ORDER );
                c6 = _mm_shuffle_epi8( c6, BYTE_REVERSE_ORDER );

                AES_GCM_ENCRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7, pbGhashSrc, 8, BYTE_REVERSE_ORDER, expandedKeyTable, todo, a0, a1, a2 );
            }
            else
            {
                // Do 4 rounds of AES-CTR for tail in parallel with 8 rounds of GHASH
                AES_GCM_ENCRYPT_4( pExpandedKey, c0, c1, c2, c3, pbGhashSrc, 8, BYTE_REVERSE_ORDER, expandedKeyTable, todo, a0, a1, a2 );
            }

            if( todo == 0)
            {
                CLMUL_3_POST( a0, a1, a2 );
                MODREDUCE( vMultiplicationConstant, a0, a1, a2, state );

                todo = SYMCRYPT_MIN( nBlocks, SYMCRYPT_GHASH_PCLMULQDQ_HPOWERS );
                CLMUL_3( state, GHASH_H_POWER(expandedKeyTable, todo), GHASH_Hx_POWER(expandedKeyTable, todo), a0, a1, a2 );
            }
        }
        else
        {
            // Just do the final 8 rounds of GHASH
            for( todo=8; todo>0; todo-- )
            {
                r0 = _mm_shuffle_epi8( _mm_loadu_si128( (__m128i *) (pbGhashSrc +  0) ), BYTE_REVERSE_ORDER );
                pbGhashSrc += SYMCRYPT_AES_BLOCK_SIZE;

                CLMUL_ACC_3( r0, GHASH_H_POWER(expandedKeyTable, todo), GHASH_Hx_POWER(expandedKeyTable, todo), a0, a1, a2 );
            }

            CLMUL_3_POST( a0, a1, a2 );
            MODREDUCE( vMultiplicationConstant, a0, a1, a2, state );
        }
    }

    if( nBlocks > 0 )
    {
        // Encrypt 1-7 blocks with pre-generated AES-CTR blocks and GHASH the results
        while( nBlocks >= 2 )
        {
            chain = _mm_add_epi64( chain, chainIncrement2 );

            r0 = _mm_xor_si128( c0, _mm_loadu_si128( ( __m128i * ) (pbSrc +  0) ) );
            r1 = _mm_xor_si128( c1, _mm_loadu_si128( ( __m128i * ) (pbSrc + 16) ) );

            _mm_storeu_si128( (__m128i *) (pbDst +  0), r0 );
            _mm_storeu_si128( (__m128i *) (pbDst + 16), r1 );

            r0 = _mm_shuffle_epi8( r0, BYTE_REVERSE_ORDER );
            r1 = _mm_shuffle_epi8( r1, BYTE_REVERSE_ORDER );

            CLMUL_ACC_3( r0, GHASH_H_POWER(expandedKeyTable, todo - 0), GHASH_Hx_POWER(expandedKeyTable, todo - 0), a0, a1, a2 );
            CLMUL_ACC_3( r1, GHASH_H_POWER(expandedKeyTable, todo - 1), GHASH_Hx_POWER(expandedKeyTable, todo - 1), a0, a1, a2 );

            pbDst   += 2*SYMCRYPT_AES_BLOCK_SIZE;
            pbSrc   += 2*SYMCRYPT_AES_BLOCK_SIZE;
            todo    -= 2;
            nBlocks -= 2;
            c0 = c2;
            c1 = c3;
            c2 = c4;
            c3 = c5;
            c4 = c6;
        }

        if( nBlocks > 0 )
        {
            chain = _mm_add_epi64( chain, chainIncrement1 );

            r0 = _mm_xor_si128( c0, _mm_loadu_si128( ( __m128i * ) (pbSrc +  0) ) );

            _mm_storeu_si128( (__m128i *) (pbDst +  0), r0 );

            r0 = _mm_shuffle_epi8( r0, BYTE_REVERSE_ORDER );

            CLMUL_ACC_3( r0, GHASH_H_POWER(expandedKeyTable, 1), GHASH_Hx_POWER(expandedKeyTable, 1), a0, a1, a2 );
        }

        CLMUL_3_POST( a0, a1, a2 );
        MODREDUCE( vMultiplicationConstant, a0, a1, a2, state );
    }

    chain = _mm_shuffle_epi8( chain, BYTE_REVERSE_ORDER );
    _mm_storeu_si128( (__m128i *) pbChainingValue, chain );
    _mm_storeu_si128( (__m128i *) pState, state );
}

// This call is functionally identical to:
// SymCryptGHashAppendDataPclmulqdq(   expandedKeyTable,
//                                     pState,
//                                     pbSrc,
//                                     cbData );
// SymCryptAesCtrMsb64Xmm( pExpandedKey,
//                         pbChainingValue,
//                         pbSrc,
//                         pbDst,
//                         cbData );
VOID
SYMCRYPT_CALL
SymCryptAesGcmDecryptStitchedXmm(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( SYMCRYPT_GF128_FIELD_SIZE ) PCSYMCRYPT_GF128_ELEMENT    expandedKeyTable,
    _Inout_                                 PSYMCRYPT_GF128_ELEMENT     pState,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    __m128i chain = _mm_loadu_si128( (__m128i *) pbChainingValue );

    __m128i BYTE_REVERSE_ORDER = _mm_set_epi8(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 );
    __m128i vMultiplicationConstant = _mm_set_epi32( 0, 0, 0xc2000000, 0 );

    __m128i chainIncrement1 = _mm_set_epi32( 0, 0, 0, 1 );
    __m128i chainIncrement2 = _mm_set_epi32( 0, 0, 0, 2 );

    __m128i c0, c1, c2, c3, c4, c5, c6, c7;

    __m128i state;
    __m128i a0, a1, a2;
    SIZE_T nBlocks = cbData / SYMCRYPT_GF128_BLOCK_SIZE;
    SIZE_T todo = 0;
    PCBYTE pbGhashSrc = pbSrc;

    chain = _mm_shuffle_epi8( chain, BYTE_REVERSE_ORDER );
    state = _mm_loadu_si128( (__m128i *) pState );

    todo = SYMCRYPT_MIN( nBlocks, SYMCRYPT_GHASH_PCLMULQDQ_HPOWERS );
    CLMUL_3( state, GHASH_H_POWER(expandedKeyTable, todo), GHASH_Hx_POWER(expandedKeyTable, todo), a0, a1, a2 );

    while( nBlocks >= 8 )
    {
        // In this loop we always have 8 blocks to decrypt and GHASH
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

        AES_GCM_ENCRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7, pbGhashSrc, 8, BYTE_REVERSE_ORDER, expandedKeyTable, todo, a0, a1, a2 );

        _mm_storeu_si128( (__m128i *) (pbDst +  0), _mm_xor_si128( c0, _mm_loadu_si128( ( __m128i * ) (pbSrc +  0) ) ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 16), _mm_xor_si128( c1, _mm_loadu_si128( ( __m128i * ) (pbSrc + 16) ) ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 32), _mm_xor_si128( c2, _mm_loadu_si128( ( __m128i * ) (pbSrc + 32) ) ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 48), _mm_xor_si128( c3, _mm_loadu_si128( ( __m128i * ) (pbSrc + 48) ) ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 64), _mm_xor_si128( c4, _mm_loadu_si128( ( __m128i * ) (pbSrc + 64) ) ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 80), _mm_xor_si128( c5, _mm_loadu_si128( ( __m128i * ) (pbSrc + 80) ) ) );
        _mm_storeu_si128( (__m128i *) (pbDst + 96), _mm_xor_si128( c6, _mm_loadu_si128( ( __m128i * ) (pbSrc + 96) ) ) );
        _mm_storeu_si128( (__m128i *) (pbDst +112), _mm_xor_si128( c7, _mm_loadu_si128( ( __m128i * ) (pbSrc +112) ) ) );

        pbDst  += 8 * SYMCRYPT_AES_BLOCK_SIZE;
        pbSrc  += 8 * SYMCRYPT_AES_BLOCK_SIZE;
        nBlocks -= 8;

        if ( todo == 0 )
        {
            CLMUL_3_POST( a0, a1, a2 );
            MODREDUCE( vMultiplicationConstant, a0, a1, a2, state );

            if ( nBlocks > 0 )
            {
                todo = SYMCRYPT_MIN( nBlocks, SYMCRYPT_GHASH_PCLMULQDQ_HPOWERS );
                CLMUL_3( state, GHASH_H_POWER(expandedKeyTable, todo), GHASH_Hx_POWER(expandedKeyTable, todo), a0, a1, a2 );
            }
        }
    }

    if( nBlocks > 0 )
    {
        // We have 1-7 blocks to GHASH and decrypt
        // Do the exact number of GHASH blocks we need in parallel with generating either 4 or 8 blocks of AES-CTR
        c0 = chain;
        c1 = _mm_add_epi64( chain, chainIncrement1 );
        c2 = _mm_add_epi64( chain, chainIncrement2 );
        c3 = _mm_add_epi64( c1, chainIncrement2 );
        c4 = _mm_add_epi64( c2, chainIncrement2 );

        c0 = _mm_shuffle_epi8( c0, BYTE_REVERSE_ORDER );
        c1 = _mm_shuffle_epi8( c1, BYTE_REVERSE_ORDER );
        c2 = _mm_shuffle_epi8( c2, BYTE_REVERSE_ORDER );
        c3 = _mm_shuffle_epi8( c3, BYTE_REVERSE_ORDER );

        if( nBlocks > 4 )
        {
            c5 = _mm_add_epi64( c4, chainIncrement1 );
            c6 = _mm_add_epi64( c4, chainIncrement2 );

            c4 = _mm_shuffle_epi8( c4, BYTE_REVERSE_ORDER );
            c5 = _mm_shuffle_epi8( c5, BYTE_REVERSE_ORDER );
            c6 = _mm_shuffle_epi8( c6, BYTE_REVERSE_ORDER );

            AES_GCM_ENCRYPT_8( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7, pbGhashSrc, nBlocks, BYTE_REVERSE_ORDER, expandedKeyTable, todo, a0, a1, a2 );
        } else {
            AES_GCM_ENCRYPT_4( pExpandedKey, c0, c1, c2, c3, pbGhashSrc, nBlocks, BYTE_REVERSE_ORDER, expandedKeyTable, todo, a0, a1, a2 );
        }

        CLMUL_3_POST( a0, a1, a2 );
        MODREDUCE( vMultiplicationConstant, a0, a1, a2, state );

        // Decrypt 1-7 blocks with pre-generated AES-CTR blocks
        while( nBlocks >= 2 )
        {
            chain = _mm_add_epi64( chain, chainIncrement2 );

            _mm_storeu_si128( (__m128i *) (pbDst +  0), _mm_xor_si128( c0, _mm_loadu_si128( ( __m128i * ) (pbSrc +  0) ) ) );
            _mm_storeu_si128( (__m128i *) (pbDst + 16), _mm_xor_si128( c1, _mm_loadu_si128( ( __m128i * ) (pbSrc + 16) ) ) );

            pbDst   += 2*SYMCRYPT_AES_BLOCK_SIZE;
            pbSrc   += 2*SYMCRYPT_AES_BLOCK_SIZE;
            nBlocks -= 2;
            c0 = c2;
            c1 = c3;
            c2 = c4;
            c3 = c5;
            c4 = c6;
        }

        if( nBlocks > 0 )
        {
            chain = _mm_add_epi64( chain, chainIncrement1 );

            _mm_storeu_si128( (__m128i *) (pbDst +  0), _mm_xor_si128( c0, _mm_loadu_si128( ( __m128i * ) (pbSrc +  0) ) ) );
        }
    }

    chain = _mm_shuffle_epi8( chain, BYTE_REVERSE_ORDER );
    _mm_storeu_si128( (__m128i *) pbChainingValue, chain );
    _mm_storeu_si128((__m128i *)pState, state );
}

#define GCM_YMM_MINBLOCKS 16

#define AES_FULLROUND_16_GHASH_2_Ymm( roundkeys, keyPtr, c0, c1, c2, c3, c4, c5, c6, c7, r0, t0, t1, gHashPointer, byteReverseOrder, gHashExpandedKeyTable, todo, resl, resm, resh ) \
{ \
    roundkeys =  _mm256_broadcastsi128_si256( *( (const __m128i *) keyPtr ) ); \
    keyPtr ++; \
    c0 = _mm256_aesenc_epi128( c0, roundkeys ); \
    c1 = _mm256_aesenc_epi128( c1, roundkeys ); \
    c2 = _mm256_aesenc_epi128( c2, roundkeys ); \
    c3 = _mm256_aesenc_epi128( c3, roundkeys ); \
    c4 = _mm256_aesenc_epi128( c4, roundkeys ); \
    c5 = _mm256_aesenc_epi128( c5, roundkeys ); \
    c6 = _mm256_aesenc_epi128( c6, roundkeys ); \
    c7 = _mm256_aesenc_epi128( c7, roundkeys ); \
\
    r0 = _mm256_loadu_si256( (__m256i *) gHashPointer ); \
    r0 = _mm256_shuffle_epi8( r0, byteReverseOrder ); \
    gHashPointer += 32; \
\
    t1 = _mm256_loadu_si256( (__m256i *) &GHASH_H_POWER(gHashExpandedKeyTable, todo) ); \
    t0 = _mm256_clmulepi64_epi128( r0, t1, 0x00 ); \
    t1 = _mm256_clmulepi64_epi128( r0, t1, 0x11 ); \
\
    resl = _mm256_xor_si256( resl, t0 ); \
    resh = _mm256_xor_si256( resh, t1 ); \
\
    t0 = _mm256_srli_si256( r0, 8 ); \
    r0 = _mm256_xor_si256( r0, t0 ); \
    t1 = _mm256_loadu_si256( (__m256i *) &GHASH_Hx_POWER(gHashExpandedKeyTable, todo) ); \
    t1 = _mm256_clmulepi64_epi128( r0, t1, 0x00 ); \
\
    resm = _mm256_xor_si256( resm, t1 ); \
    todo -= 2; \
};

#define AES_GCM_ENCRYPT_16_Ymm( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7, gHashPointer, byteReverseOrder, gHashExpandedKeyTable, todo, resl, resm, resh ) \
{ \
    const BYTE (*keyPtr)[4][4]; \
    const BYTE (*keyLimit)[4][4]; \
    __m256i roundkeys; \
    __m256i t0, t1; \
    __m256i r0; \
    int aesEncryptGhashLoop; \
\
    keyPtr = pExpandedKey->RoundKey; \
    keyLimit = pExpandedKey->lastEncRoundKey; \
\
    /* _mm256_broadcastsi128_si256 requires AVX2 */ \
    roundkeys =  _mm256_broadcastsi128_si256( *( (const __m128i *) keyPtr ) ); \
    keyPtr ++; \
\
    /* _mm256_xor_si256 requires AVX2 */ \
    c0 = _mm256_xor_si256( c0, roundkeys ); \
    c1 = _mm256_xor_si256( c1, roundkeys ); \
    c2 = _mm256_xor_si256( c2, roundkeys ); \
    c3 = _mm256_xor_si256( c3, roundkeys ); \
    c4 = _mm256_xor_si256( c4, roundkeys ); \
    c5 = _mm256_xor_si256( c5, roundkeys ); \
    c6 = _mm256_xor_si256( c6, roundkeys ); \
    c7 = _mm256_xor_si256( c7, roundkeys ); \
\
    /* Do 8(x2) full rounds (AES-128|AES-192|AES-256) with stitched GHASH */ \
    for( aesEncryptGhashLoop = 0; aesEncryptGhashLoop < 4; aesEncryptGhashLoop++ ) \
    { \
        AES_FULLROUND_16_GHASH_2_Ymm( roundkeys, keyPtr, c0, c1, c2, c3, c4, c5, c6, c7, r0, t0, t1, gHashPointer, byteReverseOrder, gHashExpandedKeyTable, todo, resl, resm, resh ); \
        AES_FULLROUND_16_GHASH_2_Ymm( roundkeys, keyPtr, c0, c1, c2, c3, c4, c5, c6, c7, r0, t0, t1, gHashPointer, byteReverseOrder, gHashExpandedKeyTable, todo, resl, resm, resh ); \
    } \
\
    do \
    { \
        roundkeys =  _mm256_broadcastsi128_si256( *( (const __m128i *) keyPtr ) ); \
        keyPtr ++; \
        c0 = _mm256_aesenc_epi128( c0, roundkeys ); \
        c1 = _mm256_aesenc_epi128( c1, roundkeys ); \
        c2 = _mm256_aesenc_epi128( c2, roundkeys ); \
        c3 = _mm256_aesenc_epi128( c3, roundkeys ); \
        c4 = _mm256_aesenc_epi128( c4, roundkeys ); \
        c5 = _mm256_aesenc_epi128( c5, roundkeys ); \
        c6 = _mm256_aesenc_epi128( c6, roundkeys ); \
        c7 = _mm256_aesenc_epi128( c7, roundkeys ); \
    } while( keyPtr < keyLimit ); \
\
    roundkeys =  _mm256_broadcastsi128_si256( *( (const __m128i *) keyPtr ) ); \
\
    c0 = _mm256_aesenclast_epi128( c0, roundkeys ); \
    c1 = _mm256_aesenclast_epi128( c1, roundkeys ); \
    c2 = _mm256_aesenclast_epi128( c2, roundkeys ); \
    c3 = _mm256_aesenclast_epi128( c3, roundkeys ); \
    c4 = _mm256_aesenclast_epi128( c4, roundkeys ); \
    c5 = _mm256_aesenclast_epi128( c5, roundkeys ); \
    c6 = _mm256_aesenclast_epi128( c6, roundkeys ); \
    c7 = _mm256_aesenclast_epi128( c7, roundkeys ); \
};

VOID
SYMCRYPT_CALL
SymCryptAesGcmEncryptStitchedYmm_2048(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( SYMCRYPT_GF128_FIELD_SIZE ) PCSYMCRYPT_GF128_ELEMENT    expandedKeyTable,
    _Inout_                                 PSYMCRYPT_GF128_ELEMENT     pState,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    __m128i chain = _mm_loadu_si128( (__m128i *) pbChainingValue );

    __m128i BYTE_REVERSE_ORDER_xmm = _mm_set_epi8(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 );
    __m256i BYTE_REVERSE_ORDER = _mm256_set_epi64x( 0x0001020304050607, 0x08090a0b0c0d0e0f, 0x0001020304050607, 0x08090a0b0c0d0e0f );
    __m128i vMultiplicationConstant = _mm_set_epi32( 0, 0, 0xc2000000, 0 );

    __m256i chainIncrementUpper1  = _mm256_set_epi64x( 0,  1, 0,  0 );
    __m256i chainIncrement2  = _mm256_set_epi64x( 0,  2, 0,  2 );
    __m256i chainIncrement4  = _mm256_set_epi64x( 0,  4, 0,  4 );
    __m256i chainIncrement16 = _mm256_set_epi64x( 0, 16, 0, 16 );

    __m256i ctr0, ctr1, ctr2, ctr3, ctr4, ctr5, ctr6, ctr7;
    __m256i c0, c1, c2, c3, c4, c5, c6, c7;
    __m256i r0, r1, r2, r3, r4, r5, r6, r7;
    __m256i Hi, Hix;

    __m128i state;
    __m128i a0_xmm, a1_xmm, a2_xmm;
    __m256i a0, a1, a2;
    SIZE_T nBlocks = cbData / SYMCRYPT_GF128_BLOCK_SIZE;
    SIZE_T todo;
    PCBYTE pbGhashSrc = pbDst;

    if ( nBlocks < GCM_YMM_MINBLOCKS )
    {
        SymCryptAesGcmEncryptStitchedXmm( pExpandedKey, pbChainingValue, expandedKeyTable, pState, pbSrc, pbDst, cbData);
        return;
    }

    todo = SYMCRYPT_MIN( nBlocks, SYMCRYPT_GHASH_PCLMULQDQ_HPOWERS ) & ~(GCM_YMM_MINBLOCKS-1);
    chain = _mm_shuffle_epi8( chain, BYTE_REVERSE_ORDER_xmm );

    state = _mm_loadu_si128( (__m128i *) pState );
    ctr0 = _mm256_insertf128_si256( _mm256_castsi128_si256( chain ), chain, 1); // AVX
    ctr0 = _mm256_add_epi64( ctr0, chainIncrementUpper1 );
    ctr1 = _mm256_add_epi64( ctr0, chainIncrement2 );
    ctr2 = _mm256_add_epi64( ctr0, chainIncrement4 );
    ctr3 = _mm256_add_epi64( ctr1, chainIncrement4 );
    ctr4 = _mm256_add_epi64( ctr2, chainIncrement4 );
    ctr5 = _mm256_add_epi64( ctr3, chainIncrement4 );
    ctr6 = _mm256_add_epi64( ctr4, chainIncrement4 );
    ctr7 = _mm256_add_epi64( ctr5, chainIncrement4 );

    CLMUL_3( state, GHASH_H_POWER(expandedKeyTable, todo), GHASH_Hx_POWER(expandedKeyTable, todo), a0_xmm, a1_xmm, a2_xmm );
    a0 = a1 = a2 = _mm256_setzero_si256();

    c0 = _mm256_shuffle_epi8( ctr0, BYTE_REVERSE_ORDER );
    c1 = _mm256_shuffle_epi8( ctr1, BYTE_REVERSE_ORDER );
    c2 = _mm256_shuffle_epi8( ctr2, BYTE_REVERSE_ORDER );
    c3 = _mm256_shuffle_epi8( ctr3, BYTE_REVERSE_ORDER );
    c4 = _mm256_shuffle_epi8( ctr4, BYTE_REVERSE_ORDER );
    c5 = _mm256_shuffle_epi8( ctr5, BYTE_REVERSE_ORDER );
    c6 = _mm256_shuffle_epi8( ctr6, BYTE_REVERSE_ORDER );
    c7 = _mm256_shuffle_epi8( ctr7, BYTE_REVERSE_ORDER );

    ctr0 = _mm256_add_epi64( ctr0, chainIncrement16 );
    ctr1 = _mm256_add_epi64( ctr1, chainIncrement16 );
    ctr2 = _mm256_add_epi64( ctr2, chainIncrement16 );
    ctr3 = _mm256_add_epi64( ctr3, chainIncrement16 );
    ctr4 = _mm256_add_epi64( ctr4, chainIncrement16 );
    ctr5 = _mm256_add_epi64( ctr5, chainIncrement16 );
    ctr6 = _mm256_add_epi64( ctr6, chainIncrement16 );
    ctr7 = _mm256_add_epi64( ctr7, chainIncrement16 );

    AES_ENCRYPT_YMM_2048( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7 );

    _mm256_storeu_si256( (__m256i *) (pbDst +  0), _mm256_xor_si256( c0, _mm256_loadu_si256( ( __m256i * ) (pbSrc +  0) ) ) );
    _mm256_storeu_si256( (__m256i *) (pbDst + 32), _mm256_xor_si256( c1, _mm256_loadu_si256( ( __m256i * ) (pbSrc + 32) ) ) );
    _mm256_storeu_si256( (__m256i *) (pbDst + 64), _mm256_xor_si256( c2, _mm256_loadu_si256( ( __m256i * ) (pbSrc + 64) ) ) );
    _mm256_storeu_si256( (__m256i *) (pbDst + 96), _mm256_xor_si256( c3, _mm256_loadu_si256( ( __m256i * ) (pbSrc + 96) ) ) );
    _mm256_storeu_si256( (__m256i *) (pbDst +128), _mm256_xor_si256( c4, _mm256_loadu_si256( ( __m256i * ) (pbSrc +128) ) ) );
    _mm256_storeu_si256( (__m256i *) (pbDst +160), _mm256_xor_si256( c5, _mm256_loadu_si256( ( __m256i * ) (pbSrc +160) ) ) );
    _mm256_storeu_si256( (__m256i *) (pbDst +192), _mm256_xor_si256( c6, _mm256_loadu_si256( ( __m256i * ) (pbSrc +192) ) ) );
    _mm256_storeu_si256( (__m256i *) (pbDst +224), _mm256_xor_si256( c7, _mm256_loadu_si256( ( __m256i * ) (pbSrc +224) ) ) );

    pbDst  += 16 * SYMCRYPT_AES_BLOCK_SIZE;
    pbSrc  += 16 * SYMCRYPT_AES_BLOCK_SIZE;

    while( nBlocks >= 2*GCM_YMM_MINBLOCKS )
    {
        c0 = _mm256_shuffle_epi8( ctr0, BYTE_REVERSE_ORDER );
        c1 = _mm256_shuffle_epi8( ctr1, BYTE_REVERSE_ORDER );
        c2 = _mm256_shuffle_epi8( ctr2, BYTE_REVERSE_ORDER );
        c3 = _mm256_shuffle_epi8( ctr3, BYTE_REVERSE_ORDER );
        c4 = _mm256_shuffle_epi8( ctr4, BYTE_REVERSE_ORDER );
        c5 = _mm256_shuffle_epi8( ctr5, BYTE_REVERSE_ORDER );
        c6 = _mm256_shuffle_epi8( ctr6, BYTE_REVERSE_ORDER );
        c7 = _mm256_shuffle_epi8( ctr7, BYTE_REVERSE_ORDER );

        ctr0 = _mm256_add_epi64( ctr0, chainIncrement16 );
        ctr1 = _mm256_add_epi64( ctr1, chainIncrement16 );
        ctr2 = _mm256_add_epi64( ctr2, chainIncrement16 );
        ctr3 = _mm256_add_epi64( ctr3, chainIncrement16 );
        ctr4 = _mm256_add_epi64( ctr4, chainIncrement16 );
        ctr5 = _mm256_add_epi64( ctr5, chainIncrement16 );
        ctr6 = _mm256_add_epi64( ctr6, chainIncrement16 );
        ctr7 = _mm256_add_epi64( ctr7, chainIncrement16 );

        AES_GCM_ENCRYPT_16_Ymm( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7, pbGhashSrc, BYTE_REVERSE_ORDER, expandedKeyTable, todo, a0, a1, a2 );

        _mm256_storeu_si256( (__m256i *) (pbDst +  0), _mm256_xor_si256( c0, _mm256_loadu_si256( ( __m256i * ) (pbSrc +  0) ) ) );
        _mm256_storeu_si256( (__m256i *) (pbDst + 32), _mm256_xor_si256( c1, _mm256_loadu_si256( ( __m256i * ) (pbSrc + 32) ) ) );
        _mm256_storeu_si256( (__m256i *) (pbDst + 64), _mm256_xor_si256( c2, _mm256_loadu_si256( ( __m256i * ) (pbSrc + 64) ) ) );
        _mm256_storeu_si256( (__m256i *) (pbDst + 96), _mm256_xor_si256( c3, _mm256_loadu_si256( ( __m256i * ) (pbSrc + 96) ) ) );
        _mm256_storeu_si256( (__m256i *) (pbDst +128), _mm256_xor_si256( c4, _mm256_loadu_si256( ( __m256i * ) (pbSrc +128) ) ) );
        _mm256_storeu_si256( (__m256i *) (pbDst +160), _mm256_xor_si256( c5, _mm256_loadu_si256( ( __m256i * ) (pbSrc +160) ) ) );
        _mm256_storeu_si256( (__m256i *) (pbDst +192), _mm256_xor_si256( c6, _mm256_loadu_si256( ( __m256i * ) (pbSrc +192) ) ) );
        _mm256_storeu_si256( (__m256i *) (pbDst +224), _mm256_xor_si256( c7, _mm256_loadu_si256( ( __m256i * ) (pbSrc +224) ) ) );

        pbDst  += 16 * SYMCRYPT_AES_BLOCK_SIZE;
        pbSrc  += 16 * SYMCRYPT_AES_BLOCK_SIZE;
        nBlocks -= 16;

        if ( todo == 0 )
        {
            a0_xmm = _mm_xor_si128( a0_xmm, _mm256_extracti128_si256 ( a0, 0 /* Lowest 128 bits */ ));
            a1_xmm = _mm_xor_si128( a1_xmm, _mm256_extracti128_si256 ( a1, 0 /* Lowest 128 bits */ ));
            a2_xmm = _mm_xor_si128( a2_xmm, _mm256_extracti128_si256 ( a2, 0 /* Lowest 128 bits */ ));

            a0_xmm = _mm_xor_si128( a0_xmm, _mm256_extracti128_si256 ( a0, 1 /* Highest 128 bits */ ));
            a1_xmm = _mm_xor_si128( a1_xmm, _mm256_extracti128_si256 ( a1, 1 /* Highest 128 bits */ ));
            a2_xmm = _mm_xor_si128( a2_xmm, _mm256_extracti128_si256 ( a2, 1 /* Highest 128 bits */ ));
            CLMUL_3_POST( a0_xmm, a1_xmm, a2_xmm );
            MODREDUCE( vMultiplicationConstant, a0_xmm, a1_xmm, a2_xmm, state );

            todo = SYMCRYPT_MIN( nBlocks, SYMCRYPT_GHASH_PCLMULQDQ_HPOWERS ) & ~(GCM_YMM_MINBLOCKS-1);
            CLMUL_3( state, GHASH_H_POWER(expandedKeyTable, todo), GHASH_Hx_POWER(expandedKeyTable, todo), a0_xmm, a1_xmm, a2_xmm );
            a0 = a1 = a2 = _mm256_setzero_si256();
        }
    }

    r0 = _mm256_shuffle_epi8( _mm256_loadu_si256( (__m256i *) (pbGhashSrc +  0) ), BYTE_REVERSE_ORDER );
    r1 = _mm256_shuffle_epi8( _mm256_loadu_si256( (__m256i *) (pbGhashSrc + 32) ), BYTE_REVERSE_ORDER );
    r2 = _mm256_shuffle_epi8( _mm256_loadu_si256( (__m256i *) (pbGhashSrc + 64) ), BYTE_REVERSE_ORDER );
    r3 = _mm256_shuffle_epi8( _mm256_loadu_si256( (__m256i *) (pbGhashSrc + 96) ), BYTE_REVERSE_ORDER );
    r4 = _mm256_shuffle_epi8( _mm256_loadu_si256( (__m256i *) (pbGhashSrc +128) ), BYTE_REVERSE_ORDER );
    r5 = _mm256_shuffle_epi8( _mm256_loadu_si256( (__m256i *) (pbGhashSrc +160) ), BYTE_REVERSE_ORDER );
    r6 = _mm256_shuffle_epi8( _mm256_loadu_si256( (__m256i *) (pbGhashSrc +192) ), BYTE_REVERSE_ORDER );
    r7 = _mm256_shuffle_epi8( _mm256_loadu_si256( (__m256i *) (pbGhashSrc +224) ), BYTE_REVERSE_ORDER );

    Hi  = _mm256_loadu_si256( (__m256i *)  &GHASH_H_POWER(expandedKeyTable, todo - 0) );
    Hix = _mm256_loadu_si256( (__m256i *) &GHASH_Hx_POWER(expandedKeyTable, todo - 0) );
    CLMUL_ACC_3_Ymm( r0, Hi, Hix, a0, a1, a2 );
    Hi  = _mm256_loadu_si256( (__m256i *)  &GHASH_H_POWER(expandedKeyTable, todo - 2) );
    Hix = _mm256_loadu_si256( (__m256i *) &GHASH_Hx_POWER(expandedKeyTable, todo - 2) );
    CLMUL_ACC_3_Ymm( r1, Hi, Hix, a0, a1, a2 );
    Hi  = _mm256_loadu_si256( (__m256i *)  &GHASH_H_POWER(expandedKeyTable, todo - 4) );
    Hix = _mm256_loadu_si256( (__m256i *) &GHASH_Hx_POWER(expandedKeyTable, todo - 4) );
    CLMUL_ACC_3_Ymm( r2, Hi, Hix, a0, a1, a2 );
    Hi  = _mm256_loadu_si256( (__m256i *)  &GHASH_H_POWER(expandedKeyTable, todo - 6) );
    Hix = _mm256_loadu_si256( (__m256i *) &GHASH_Hx_POWER(expandedKeyTable, todo - 6) );
    CLMUL_ACC_3_Ymm( r3, Hi, Hix, a0, a1, a2 );
    Hi  = _mm256_loadu_si256( (__m256i *)  &GHASH_H_POWER(expandedKeyTable, todo - 8) );
    Hix = _mm256_loadu_si256( (__m256i *) &GHASH_Hx_POWER(expandedKeyTable, todo - 8) );
    CLMUL_ACC_3_Ymm( r4, Hi, Hix, a0, a1, a2 );
    Hi  = _mm256_loadu_si256( (__m256i *)  &GHASH_H_POWER(expandedKeyTable, todo -10) );
    Hix = _mm256_loadu_si256( (__m256i *) &GHASH_Hx_POWER(expandedKeyTable, todo -10) );
    CLMUL_ACC_3_Ymm( r5, Hi, Hix, a0, a1, a2 );
    Hi  = _mm256_loadu_si256( (__m256i *)  &GHASH_H_POWER(expandedKeyTable, todo -12) );
    Hix = _mm256_loadu_si256( (__m256i *) &GHASH_Hx_POWER(expandedKeyTable, todo -12) );
    CLMUL_ACC_3_Ymm( r6, Hi, Hix, a0, a1, a2 );
    Hi  = _mm256_loadu_si256( (__m256i *)  &GHASH_H_POWER(expandedKeyTable, todo -14) );
    Hix = _mm256_loadu_si256( (__m256i *) &GHASH_Hx_POWER(expandedKeyTable, todo -14) );
    CLMUL_ACC_3_Ymm( r7, Hi, Hix, a0, a1, a2 );

    a0_xmm = _mm_xor_si128( a0_xmm, _mm256_extracti128_si256 ( a0, 0 /* Lowest 128 bits */ ));
    a1_xmm = _mm_xor_si128( a1_xmm, _mm256_extracti128_si256 ( a1, 0 /* Lowest 128 bits */ ));
    a2_xmm = _mm_xor_si128( a2_xmm, _mm256_extracti128_si256 ( a2, 0 /* Lowest 128 bits */ ));

    a0_xmm = _mm_xor_si128( a0_xmm, _mm256_extracti128_si256 ( a0, 1 /* Highest 128 bits */ ));
    a1_xmm = _mm_xor_si128( a1_xmm, _mm256_extracti128_si256 ( a1, 1 /* Highest 128 bits */ ));
    a2_xmm = _mm_xor_si128( a2_xmm, _mm256_extracti128_si256 ( a2, 1 /* Highest 128 bits */ ));
    CLMUL_3_POST( a0_xmm, a1_xmm, a2_xmm );
    MODREDUCE( vMultiplicationConstant, a0_xmm, a1_xmm, a2_xmm, state );

    chain = _mm256_extracti128_si256 ( ctr0, 0 /* Lowest 128 bits */ );
    _mm256_zeroupper();

    chain = _mm_shuffle_epi8( chain, BYTE_REVERSE_ORDER_xmm );
    _mm_storeu_si128((__m128i *) pbChainingValue, chain );
    _mm_storeu_si128((__m128i *) pState, state );

    cbData &= ( GCM_YMM_MINBLOCKS*SYMCRYPT_AES_BLOCK_SIZE ) - 1;
    if ( cbData >= SYMCRYPT_AES_BLOCK_SIZE )
    {
        SymCryptAesGcmEncryptStitchedXmm( pExpandedKey, pbChainingValue, expandedKeyTable, pState, pbSrc, pbDst, cbData);
    }
}

VOID
SYMCRYPT_CALL
SymCryptAesGcmDecryptStitchedYmm_2048(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( SYMCRYPT_GF128_FIELD_SIZE ) PCSYMCRYPT_GF128_ELEMENT    expandedKeyTable,
    _Inout_                                 PSYMCRYPT_GF128_ELEMENT     pState,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData )
{
    __m128i chain = _mm_loadu_si128( (__m128i *) pbChainingValue );

    __m128i BYTE_REVERSE_ORDER_xmm = _mm_set_epi8(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 );
    __m256i BYTE_REVERSE_ORDER = _mm256_set_epi64x( 0x0001020304050607, 0x08090a0b0c0d0e0f, 0x0001020304050607, 0x08090a0b0c0d0e0f );
    __m128i vMultiplicationConstant = _mm_set_epi32( 0, 0, 0xc2000000, 0 );

    __m256i chainIncrementUpper1  = _mm256_set_epi64x( 0,  1, 0,  0 );
    __m256i chainIncrement2  = _mm256_set_epi64x( 0,  2, 0,  2 );
    __m256i chainIncrement4  = _mm256_set_epi64x( 0,  4, 0,  4 );
    __m256i chainIncrement16 = _mm256_set_epi64x( 0, 16, 0, 16 );

    __m256i ctr0, ctr1, ctr2, ctr3, ctr4, ctr5, ctr6, ctr7;
    __m256i c0, c1, c2, c3, c4, c5, c6, c7;

    __m128i state;
    __m128i a0_xmm, a1_xmm, a2_xmm;
    __m256i a0, a1, a2;
    SIZE_T nBlocks = cbData / SYMCRYPT_GF128_BLOCK_SIZE;
    SIZE_T todo;
    PCBYTE pbGhashSrc = pbSrc;

    if ( nBlocks < GCM_YMM_MINBLOCKS )
    {
        SymCryptAesGcmDecryptStitchedXmm( pExpandedKey, pbChainingValue, expandedKeyTable, pState, pbSrc, pbDst, cbData);
        return;
    }

    todo = SYMCRYPT_MIN( nBlocks, SYMCRYPT_GHASH_PCLMULQDQ_HPOWERS ) & ~(GCM_YMM_MINBLOCKS-1);
    chain = _mm_shuffle_epi8( chain, BYTE_REVERSE_ORDER_xmm );

    state = _mm_loadu_si128( (__m128i *) pState );
    ctr0 = _mm256_insertf128_si256( _mm256_castsi128_si256( chain ), chain, 1); // AVX
    ctr0 = _mm256_add_epi64( ctr0, chainIncrementUpper1 );
    ctr1 = _mm256_add_epi64( ctr0, chainIncrement2 );
    ctr2 = _mm256_add_epi64( ctr0, chainIncrement4 );
    ctr3 = _mm256_add_epi64( ctr1, chainIncrement4 );
    ctr4 = _mm256_add_epi64( ctr2, chainIncrement4 );
    ctr5 = _mm256_add_epi64( ctr3, chainIncrement4 );
    ctr6 = _mm256_add_epi64( ctr4, chainIncrement4 );
    ctr7 = _mm256_add_epi64( ctr5, chainIncrement4 );

    CLMUL_3( state, GHASH_H_POWER(expandedKeyTable, todo), GHASH_Hx_POWER(expandedKeyTable, todo), a0_xmm, a1_xmm, a2_xmm );
    a0 = a1 = a2 = _mm256_setzero_si256();

    while( nBlocks >= GCM_YMM_MINBLOCKS )
    {
        c0 = _mm256_shuffle_epi8( ctr0, BYTE_REVERSE_ORDER );
        c1 = _mm256_shuffle_epi8( ctr1, BYTE_REVERSE_ORDER );
        c2 = _mm256_shuffle_epi8( ctr2, BYTE_REVERSE_ORDER );
        c3 = _mm256_shuffle_epi8( ctr3, BYTE_REVERSE_ORDER );
        c4 = _mm256_shuffle_epi8( ctr4, BYTE_REVERSE_ORDER );
        c5 = _mm256_shuffle_epi8( ctr5, BYTE_REVERSE_ORDER );
        c6 = _mm256_shuffle_epi8( ctr6, BYTE_REVERSE_ORDER );
        c7 = _mm256_shuffle_epi8( ctr7, BYTE_REVERSE_ORDER );

        ctr0 = _mm256_add_epi64( ctr0, chainIncrement16 );
        ctr1 = _mm256_add_epi64( ctr1, chainIncrement16 );
        ctr2 = _mm256_add_epi64( ctr2, chainIncrement16 );
        ctr3 = _mm256_add_epi64( ctr3, chainIncrement16 );
        ctr4 = _mm256_add_epi64( ctr4, chainIncrement16 );
        ctr5 = _mm256_add_epi64( ctr5, chainIncrement16 );
        ctr6 = _mm256_add_epi64( ctr6, chainIncrement16 );
        ctr7 = _mm256_add_epi64( ctr7, chainIncrement16 );

        AES_GCM_ENCRYPT_16_Ymm( pExpandedKey, c0, c1, c2, c3, c4, c5, c6, c7, pbGhashSrc, BYTE_REVERSE_ORDER, expandedKeyTable, todo, a0, a1, a2 );

        _mm256_storeu_si256( (__m256i *) (pbDst +  0), _mm256_xor_si256( c0, _mm256_loadu_si256( ( __m256i * ) (pbSrc +  0) ) ) );
        _mm256_storeu_si256( (__m256i *) (pbDst + 32), _mm256_xor_si256( c1, _mm256_loadu_si256( ( __m256i * ) (pbSrc + 32) ) ) );
        _mm256_storeu_si256( (__m256i *) (pbDst + 64), _mm256_xor_si256( c2, _mm256_loadu_si256( ( __m256i * ) (pbSrc + 64) ) ) );
        _mm256_storeu_si256( (__m256i *) (pbDst + 96), _mm256_xor_si256( c3, _mm256_loadu_si256( ( __m256i * ) (pbSrc + 96) ) ) );
        _mm256_storeu_si256( (__m256i *) (pbDst +128), _mm256_xor_si256( c4, _mm256_loadu_si256( ( __m256i * ) (pbSrc +128) ) ) );
        _mm256_storeu_si256( (__m256i *) (pbDst +160), _mm256_xor_si256( c5, _mm256_loadu_si256( ( __m256i * ) (pbSrc +160) ) ) );
        _mm256_storeu_si256( (__m256i *) (pbDst +192), _mm256_xor_si256( c6, _mm256_loadu_si256( ( __m256i * ) (pbSrc +192) ) ) );
        _mm256_storeu_si256( (__m256i *) (pbDst +224), _mm256_xor_si256( c7, _mm256_loadu_si256( ( __m256i * ) (pbSrc +224) ) ) );

        pbDst  += 16 * SYMCRYPT_AES_BLOCK_SIZE;
        pbSrc  += 16 * SYMCRYPT_AES_BLOCK_SIZE;
        nBlocks -= 16;

        if ( todo == 0 )
        {
            a0_xmm = _mm_xor_si128( a0_xmm, _mm256_extracti128_si256 ( a0, 0 /* Lowest 128 bits */ ));
            a1_xmm = _mm_xor_si128( a1_xmm, _mm256_extracti128_si256 ( a1, 0 /* Lowest 128 bits */ ));
            a2_xmm = _mm_xor_si128( a2_xmm, _mm256_extracti128_si256 ( a2, 0 /* Lowest 128 bits */ ));

            a0_xmm = _mm_xor_si128( a0_xmm, _mm256_extracti128_si256 ( a0, 1 /* Highest 128 bits */ ));
            a1_xmm = _mm_xor_si128( a1_xmm, _mm256_extracti128_si256 ( a1, 1 /* Highest 128 bits */ ));
            a2_xmm = _mm_xor_si128( a2_xmm, _mm256_extracti128_si256 ( a2, 1 /* Highest 128 bits */ ));
            CLMUL_3_POST( a0_xmm, a1_xmm, a2_xmm );
            MODREDUCE( vMultiplicationConstant, a0_xmm, a1_xmm, a2_xmm, state );

            if ( nBlocks > 0 )
            {
                todo = SYMCRYPT_MIN( nBlocks, SYMCRYPT_GHASH_PCLMULQDQ_HPOWERS ) & ~(GCM_YMM_MINBLOCKS-1);
                CLMUL_3( state, GHASH_H_POWER(expandedKeyTable, todo), GHASH_Hx_POWER(expandedKeyTable, todo), a0_xmm, a1_xmm, a2_xmm );
                a0 = a1 = a2 = _mm256_setzero_si256();
            }
        }
    }

    chain = _mm256_extracti128_si256 ( ctr0, 0 /* Lowest 128 bits */ );
    _mm256_zeroupper();

    chain = _mm_shuffle_epi8( chain, BYTE_REVERSE_ORDER_xmm );
    _mm_storeu_si128((__m128i *) pbChainingValue, chain );
    _mm_storeu_si128((__m128i *) pState, state );

    cbData &= ( GCM_YMM_MINBLOCKS*SYMCRYPT_AES_BLOCK_SIZE ) - 1;
    if ( cbData >= SYMCRYPT_AES_BLOCK_SIZE )
    {
        SymCryptAesGcmDecryptStitchedXmm( pExpandedKey, pbChainingValue, expandedKeyTable, pState, pbSrc, pbDst, cbData);
    }
}

#endif // CPU_X86 | CPU_AMD64

