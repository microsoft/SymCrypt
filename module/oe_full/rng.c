//
// rng.c
// Implements RNG for OE version of module
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"
#include <pthread.h>
#include <sys/random.h>

// Size of small entropy request cache, same as Windows
#define  RANDOM_NUM_CACHE_SIZE         128
#define  MAX_GENERATE_BEFORE_RESEED    8192

pthread_mutex_t g_rngLock; // lock around access to g_AesRngState
SYMCRYPT_RNG_AES_STATE g_AesRngState;

BYTE g_randomBytesCache[RANDOM_NUM_CACHE_SIZE];
SIZE_T g_cbRandomBytesCache = 0;

UINT32 g_rngCounter = 0; // reseed when counter exceeds MAX_GENERATE_BEFORE_RESEED, increments 1 per generate

// Forward declare, get host entropy from urandom
int oe_sgx_get_additional_host_entropy(uint8_t* data, size_t size);

// Helper function for reseeding with RDSEED, urandom, and user-provided pbEntropy
VOID
SymCryptModuleReseed( PCBYTE pbEntropy, SIZE_T cbEntropy );

// This function must be called during module initialization. It sets up
// the internal SymCrypt RNG state by seeding with RDSEED and urandom.
// Max seed size for SymCryptRngAesInstantiate is 64 bytes, so first 48
// are from RDSEED and last 16 are urandom, as per SP800-90A section 10.2.1.3.2
// The RDSEED input constitutes the entropy_input and nonce, while urandom is
// the personalization_string
VOID
SYMCRYPT_CALL
SymCryptRngInit()
{
    SYMCRYPT_ERROR error = SYMCRYPT_NO_ERROR;

    BYTE seed[64];
    UINT32 result;

    pthread_mutex_init( &g_rngLock, NULL );

    // Get entropy and nonce from RDSEED
    SymCryptRdseedGet(
        seed,
        48
    );

    // Get personalization string from urandom
    result = oe_sgx_get_additional_host_entropy( seed + 48, 16 );
    if ( result != 1 )
    {
        SymCryptFatal( 'rngu' );
    }

    // Instantiate internal RNG state
    error = SymCryptRngAesInstantiate(
        &g_AesRngState,
        seed,
        sizeof(seed)
    );

    if( error != SYMCRYPT_NO_ERROR )
    {
        SymCryptFatal( 'rngi' );
    }

    // Reseed as well so there is sufficient entropy from urandom
    // Explanation: if RDRAND were to silenty fail, we would only be relying
    // on 16 bytes of entropy from urandom, which isn't enough. During the
    // reseed function below, 32 bytes from urandom are used.
    SymCryptModuleReseed( NULL, 0 );

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
        // RDSEED and urandom
        SymCryptModuleReseed( NULL, 0 );

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

// This function reseeds the RNG state using RDSEED, pbEntropy that the user provides, and urandom from Linux.
// Seed is constructed as per SP800-90A for CTR_DRBG with a derivation function, that is
// entropy_input || additional_input, where entropy input is the SP800-90B compliant RDSEED and the additional
// input is the hash of pbEntropy and urandom
VOID
SYMCRYPT_CALL
SymCryptProvideEntropy( PCBYTE pbEntropy, SIZE_T cbEntropy )
{
    pthread_mutex_lock( &g_rngLock );

    SymCryptModuleReseed( pbEntropy, cbEntropy );

    pthread_mutex_unlock( &g_rngLock );
}

// Module-specific reseed function, no locking, used in SymCryptProvideEntropy and SymCryptRandom since they
// both use this same flow of reseeding.
// This function reseeds the RNG state using RDSEED, pbEntropy that the user provides, and urandom from Linux.
// Seed is constructed as per SP800-90A for CTR_DRBG with a derivation function, that is
// entropy_input || additional_input, where entropy input is the SP800-90B compliant RDSEED and the additional
// input is the hash of pbEntropy and urandom
VOID
SymCryptModuleReseed( PCBYTE pbEntropy, SIZE_T cbEntropy )
{
    BYTE seed[64]; // 256 bits of entropy input and 256 bits of additional input
    BYTE* hash = seed + 32; // Second half of seed will be output of SHA256 below
    UINT32 result;

    SYMCRYPT_SHA256_STATE hashState;


    // Second half of seed is 'additional input' of SP800-90A for DRBG. We hash together pbEntropy and urandom
    // to force it to size 256 bits
    SymCryptSha256Init( &hashState );
    SymCryptSha256Append( &hashState, pbEntropy, cbEntropy );

    // Mix in data from urandom. Place in first half of seed buffer to store until we hash it
    result = oe_sgx_get_additional_host_entropy( seed, 32 );
    if ( result != 1 )
    {
        SymCryptFatal( 'rngu' );
    }
    SymCryptSha256Append( &hashState, seed, 32 );

    // Get hash result (OK if user passes empty pbEntropy and urandom fails - additional input is optional and
    // RDSEED is only critical source)
    SymCryptSha256Result( &hashState, hash );

    // Fill first half of seed with SP800-90B compliant RDSEED
    SymCryptRdseedGet( seed, 32 );

    // Perform the reseed
    SymCryptRngAesReseed( &g_AesRngState, seed, sizeof(seed) );

    // Don't use any existing cached random data
    g_cbRandomBytesCache = 0;
    
    SymCryptWipeKnownSize( seed, sizeof(seed) );

    return;
}