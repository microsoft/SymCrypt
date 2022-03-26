//
// rng.c
// Implements common RNG infrastructure for modules
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"
#include "rng.h"


// Size of small entropy request cache, same as Windows
#define  RANDOM_NUM_CACHE_SIZE         128
#define  MAX_GENERATE_BEFORE_RESEED    8192

pthread_mutex_t g_rngLock; // lock around access to g_AesRngState
SYMCRYPT_RNG_AES_STATE g_AesRngState;

BYTE g_randomBytesCache[RANDOM_NUM_CACHE_SIZE];
SIZE_T g_cbRandomBytesCache = 0;

UINT32 g_rngCounter = 0; // reseed when counter exceeds MAX_GENERATE_BEFORE_RESEED, increments 1 per generate

// Helper function for reseeding with entropy from Fips and secure sources, and user-provided pbEntropy
VOID
SymCryptRngReseed( PCBYTE pbEntropy, SIZE_T cbEntropy );

// This function must be called during module initialization. It sets up
// the internal SymCrypt RNG state by seeding from Fips and secure entropy sources.
// First 64 bytes are from Fips source and last 64 are from the secure source, as per
// SP800-90A section 10.2.1.3.2.
// The Fips input constitutes the entropy_input and nonce, while secure input is
// the personalization_string.
VOID
SYMCRYPT_CALL
SymCryptRngInit()
{
    SYMCRYPT_ERROR error = SYMCRYPT_NO_ERROR;
    BYTE seed[128];

    if( pthread_mutex_init( &g_rngLock, NULL ) != 0)
    {
        SymCryptFatal( 'rngi' );
    }

    // Initialize both entropy sources
    SymCryptEntropyFipsInit();
    SymCryptEntropySecureInit();

    // Get entropy and nonce from Fips entropy source
    SymCryptEntropyFipsGet( seed, 64 );

    // Get personalization string from secure entropy source
    SymCryptEntropySecureGet( seed + 64, 64 );

    // Instantiate internal RNG state
    error = SymCryptRngAesInstantiate(
        &g_AesRngState,
        seed,
        sizeof(seed)
    );

    if( error != SYMCRYPT_NO_ERROR )
    {
        // Instantiate only fails if cbSeedMaterial is a bad size, and if it does,
        // SymCrypt cannot continue safely
        SymCryptFatal( 'rngi' );
    }

    SymCryptWipeKnownSize( seed, sizeof(seed) );
}

// This function must be called during module uninitialization. Cleans
// up the RNG state and lock.
// Note: bytes in g_randomBytesCache are not wiped, as they have never been
// output and so are not secret
VOID
SYMCRYPT_CALL
SymCryptRngUninit()
{
    SymCryptEntropyFipsUninit();
    SymCryptEntropySecureUninit();
    SymCryptRngAesUninstantiate( &g_AesRngState );
    pthread_mutex_destroy( &g_rngLock );
}

// This function fills pbRandom with cbRandom bytes. For small requests,
// we use a cache of pre-generated random bits. For large requests, we call
// the AesRngState's generate function directly
VOID
SYMCRYPT_CALL
SymCryptRandom( PBYTE pbRandom, SIZE_T cbRandom )
{
    SIZE_T cbRandomTmp = cbRandom;
    SIZE_T mask;
    SIZE_T cbFill;

    if( cbRandom == 0 )
    {
        return;
    }

    pthread_mutex_lock( &g_rngLock );

    // If counter is high enough, we reseed the RNG state
    ++g_rngCounter;
    if( g_rngCounter > MAX_GENERATE_BEFORE_RESEED )
    {
        // Call the Module reseed function defined below - this will reseed for us with
        // Fips and secure entropy sources
        SymCryptRngReseed( NULL, 0 );

        g_rngCounter = 0;
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

// This function reseeds the RNG state using the Fips entropy source, pbEntropy that the user provides,
// and the secure entropy source.
// Seed is constructed as per SP800-90A for CTR_DRBG with a derivation function, that is
// entropy_input || additional_input, where entropy input is the SP800-90B compliant (if applicable) Fips entropy source and the additional
// input is the hash of pbEntropy and the secure entropy source.
VOID
SYMCRYPT_CALL
SymCryptProvideEntropy( PCBYTE pbEntropy, SIZE_T cbEntropy )
{
    pthread_mutex_lock( &g_rngLock );

    SymCryptRngReseed( pbEntropy, cbEntropy );

    pthread_mutex_unlock( &g_rngLock );
}

// RNG reseed function, no locking, used in SymCryptProvideEntropy and SymCryptRandom since they
// both use this same flow of reseeding.
// This function reseeds the RNG state using the Fips entropy source, pbEntropy that the user provides,
// and the secure entropy source.
// Seed is constructed as per SP800-90A for CTR_DRBG with a derivation function, that is
// entropy_input || additional_input, where entropy input is the SP800-90B compliant (if applicable) Fips entropy source and the additional
// input is the hash of pbEntropy and the secure entropy source.
VOID
SymCryptRngReseed( PCBYTE pbEntropy, SIZE_T cbEntropy )
{
    BYTE seed[128]; // 256 bits of entropy input and 256 bits of additional input
    BYTE* hash = seed + 64; // Second half of seed will be output of SHA256 below
    SYMCRYPT_SHA256_STATE hashState;

    // Second half of seed is 'additional input' of SP800-90A for DRBG. We hash together pbEntropy and secure
    // entropy source to force it to size 256 bits
    SymCryptSha256Init( &hashState );
    SymCryptSha256Append( &hashState, pbEntropy, cbEntropy );

    // Mix in data from secure entropy source. Place in first half of seed buffer to store until we hash it
    SymCryptEntropySecureGet( seed, 64 );
    SymCryptSha256Append( &hashState, seed, 64 );

    // Get hash result
    SymCryptSha256Result( &hashState, hash );

    // Fill first half of seed with SP800-90B compliant (if applicable) Fips entropy source
    SymCryptEntropyFipsGet( seed, 64 );

    // Perform the reseed
    SymCryptRngAesReseed( &g_AesRngState, seed, sizeof(seed) );

    // Don't use any existing cached random data
    g_cbRandomBytesCache = 0;

    SymCryptWipeKnownSize( seed, sizeof(seed) );

    return;
}