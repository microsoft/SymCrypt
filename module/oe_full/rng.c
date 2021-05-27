//
// rng.c
// Implements RNG for OE version of module
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"
#include <pthread.h>

// Size of small entropy request cache, same as Windows
#define  RANDOM_NUM_CACHE_SIZE         128
#define  MAX_GENERATE_BEFORE_RESEED    8192

SYMCRYPT_RNG_AES_STATE   g_AesRngState;
pthread_mutex_t          g_rngLock;
BYTE                     g_randomBytesCache[RANDOM_NUM_CACHE_SIZE];
SIZE_T                   g_cbRandomBytesCache = 0;
int                      g_rngCounter = 0;


// This function must be called during module initialization. It sets up
// the internal SymCrypt RNG state by seeding with RDSEED
VOID
SYMCRYPT_CALL
SymCryptRngInit()
{
    SYMCRYPT_ERROR error = SYMCRYPT_NO_ERROR;
    BYTE seed[SYMCRYPT_RNG_AES_MIN_INSTANTIATE_SIZE];

    pthread_mutex_init( &g_rngLock, NULL );

    // Get instantiate seed from RDSEED
    SymCryptRdseedGet(
        seed,
        sizeof(seed)
    );

    // Instantiate internal RNG state
    error = SymCryptRngAesInstantiate(
        &g_AesRngState,
        seed,
        sizeof(seed)
    );

    if( error != SYMCRYPT_NO_ERROR )
    {
        pthread_mutex_destroy( &g_rngLock );
        SymCryptFatal( 'rngi' );
    }
}

// This function must be called during module uninitialization. Cleans
// up the RNG state and lock
VOID
SYMCRYPT_CALL
SymCryptRngUninit()
{
    SymCryptRngAesUninstantiate( &g_AesRngState );
    pthread_mutex_destroy( &g_rngLock );
}

// This function fills pbRandom with cbRandom bytes. For small requests,
// we use a cache of pre-generated random bits. For large requests, we call
// the AesRngState's generate function directly
VOID
SYMCRYPT_CALL
SymCryptRandom(PBYTE pbRandom, SIZE_T cbRandom)
{

    SYMCRYPT_ERROR error = SYMCRYPT_NO_ERROR;
    SIZE_T cbRandomTmp = cbRandom;
    SIZE_T mask;
    BYTE seed[SYMCRYPT_RNG_AES_MAX_SEED_SIZE];
    SIZE_T cbFill;

    if( cbRandom == 0 )
    {
        return;
    }

    pthread_mutex_lock( &g_rngLock );

    // If counter is high enough, we reseed the RNG state via RDSEED
    ++g_rngCounter;
    if( g_rngCounter > MAX_GENERATE_BEFORE_RESEED )
    {
        SymCryptRdseedGet(
            seed,
            sizeof(seed)
        );

        error = SymCryptRngAesReseed(
            &g_AesRngState,
            seed,
            sizeof(seed)
        );

        if( error != SYMCRYPT_NO_ERROR )
        {
            // Should never fail. Fatal if so as RNG isn't functioning properly
            SymCryptFatal( 'rngg' );
        }

        g_rngCounter = 0;
        g_cbRandomBytesCache = 0;
    }

    // Big or small request?
    if( cbRandom < RANDOM_NUM_CACHE_SIZE )
    {
        // small request, use cache
        if( g_cbRandomBytesCache > 0 )
        {
            // bytes already in cache, use them
            cbFill = SYMCRYPT_MIN( cbRandomTmp, g_cbRandomBytesCache );
            memcpy(
                pbRandom,
                &g_randomBytesCache[g_cbRandomBytesCache - cbFill],
                cbFill
            );
            SymCryptWipe(
                &g_randomBytesCache[g_cbRandomBytesCache - cbFill],
                cbFill
            );
            g_cbRandomBytesCache -= cbFill;

            pbRandom += cbFill;
            cbRandomTmp -= cbFill;
        }

        if( cbRandomTmp > 0 )
        {
            // cache empty, repopulate it and continue to fill
            SymCryptRngAesGenerate(
                &g_AesRngState,
                g_randomBytesCache,
                RANDOM_NUM_CACHE_SIZE
            );

            g_cbRandomBytesCache = RANDOM_NUM_CACHE_SIZE;

            memcpy(
                pbRandom,
                &g_randomBytesCache[g_cbRandomBytesCache - cbRandomTmp],
                cbRandomTmp
            );
            SymCryptWipe(
                &g_randomBytesCache[g_cbRandomBytesCache - cbRandomTmp],
                cbRandomTmp
            );
            g_cbRandomBytesCache -= cbRandomTmp;

            // If we never throw away some bytes, then we could have long-lasting alignment
            // problems which slow everything down.
            // If an application ever asks for a single random byte,
            // and then only for 16 bytes at a time, then every memcpy from the cache
            // would incur alignment penalties.
            // We throw away some bytes to get aligned with the current request size,
            // up to 16-alignment. This tends to align our cache with the alignment of the common
            // request sizes.
            // We throw away at most 15 bytes out of 128.

            mask = cbRandom;            //                              xxxx100...0
            mask = mask ^ (mask - 1);   // set lsbset + all lower bits  0000111...1
            mask = (mask >> 1) & 15;    // bits to mask out             0000011...1 limited to 4 bits
            g_cbRandomBytesCache &= ~mask;
        }

    }
    else
    {
        // Large request, call generate directly
        SymCryptRngAesGenerate(
            &g_AesRngState,
            pbRandom,
            cbRandom
        );
    }

    pthread_mutex_unlock( &g_rngLock );

    return;
}

// This function reseeds the RNG state with pbEntropy. This function
// is allowed to fail as the caller may provide entropy that is too small
// or large. (SYMCRYPT_RNG_AES_MIN_SEED_SIZE <= cbEntropy <= SYMCRYPT_RNG_AES_MAX_SEED_SIZE)
VOID
SYMCRYPT_CALL
SymCryptProvideEntropy(PCBYTE pbEntropy, SIZE_T cbEntropy)
{
    SYMCRYPT_ERROR error;
    BYTE hash[SYMCRYPT_SHA256_RESULT_SIZE];

    // Hash entropy to a size that SymCryptRngAesReseed will accept
    SymCryptSha256( pbEntropy, cbEntropy, hash );

    pthread_mutex_lock( &g_rngLock );

    error = SymCryptRngAesReseed( &g_AesRngState, hash, sizeof(hash) );

    if( error != SYMCRYPT_NO_ERROR )
    {
        SymCryptFatal( 'rngr' );
    }

    g_cbRandomBytesCache = 0;

    pthread_mutex_unlock( &g_rngLock );
}