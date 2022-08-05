/*
SymCrypt main_gen.cpp
Program to generate the various constants & tables for the SymCrypt code
Copyright (c) Microsoft Corporation. Licensed under the MIT license.
*/

#include <ntstatus.h>

// Ensure that windows.h doesn't re-define the status_* symbols
#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#include <winioctl.h>

//
// Hack to get all the BCrypt declarations even though our binaries target down-level platforms.
//
#pragma push_macro("NTDDI_VERSION")
#undef NTDDI_VERSION
#define NTDDI_VERSION NTDDI_WINTHRESHOLD
#include <bcrypt.h>
#pragma pop_macro("NTDDI_VERSION")

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <powrprof.h>

#include <vector>
#include <string>
#include <memory>
#include <algorithm>
#include <map>
#include <strstream>
#include <set>
#include <strsafe.h>

#include "symcrypt.h"

#define MAX_PRIMES  100000

_Analysis_noreturn_
VOID
fatal( _In_ PSTR file, ULONG line, _In_ PSTR format, ... )
{
    va_list vl;

    fprintf( stdout, "*\n\n***** FATAL ERROR %s(%d): ", file, line );

    va_start( vl, format );

    vfprintf( stdout, format, vl );
    fprintf ( stdout, "\n" );

    exit( -1 );
}

#define FATAL( text ) {fatal( __FILE__, __LINE__, text );}
#define FATAL2( text, a ) {fatal( __FILE__, __LINE__, text, a );}
#define FATAL3( text, a, b ) {fatal( __FILE__, __LINE__, text, a, b );}
#define FATAL4( text, a, b, c  ) {fatal( __FILE__, __LINE__, text, a, b, c );}
#define FATAL5( text, a, b, c, d ) {fatal( __FILE__, __LINE__, text, a, b, c, d );}
#define FATAL6( text, a, b, c, d, e ) {fatal( __FILE__, __LINE__, text, a, b, c, d, e );}
#define CHECK( cond, text )           { if( !(cond) ) { fatal(__FILE__, __LINE__, text          );}; _Analysis_assume_( cond );}
#define CHECK3( cond, text, a )       { if( !(cond) ) { fatal(__FILE__, __LINE__, text, a       );}; _Analysis_assume_( cond );}
#define CHECK4( cond, text, a, b )    { if( !(cond) ) { fatal(__FILE__, __LINE__, text, a, b    );}; _Analysis_assume_( cond );}
#define CHECK5( cond, text, a, b, c ) { if( !(cond) ) { fatal(__FILE__, __LINE__, text, a, b, c );}; _Analysis_assume_( cond );}


UINT32 g_smallPrimes[MAX_PRIMES];

UINT32 g_nSmallPrimes;
UINT32 g_nGroups;

VOID
generateSmallPrimes()
{
    g_smallPrimes[0] = 2;
    g_smallPrimes[1] = 3;

    UINT32 nPrimes = 2;

    UINT32 n = 3;

    while( nPrimes < MAX_PRIMES )
    {
        n += 2; // next candidate
        for( UINT32 i=1; i<=nPrimes; i++ )
        {
            UINT32 p = g_smallPrimes[i];
            if( p*p > n )
            {
                // found a prime!
                g_smallPrimes[nPrimes++] = n;
                break;
            }
            if( n % p == 0 )
            {
                // found a composite
                break;
            }
        }
    }
}

VOID
printSmallPrimes( FILE * f, UINT32 primeLimit )
{
    fprintf( f, "//\n" );
    fprintf( f, "// Table of small primes <= %d\n", primeLimit );
    fprintf( f, "// Copyright (c) Microsoft Corporation. Licensed under the MIT license.\n" );
    fprintf( f, "//\n" );
    fprintf( f, "\n" );
    fprintf( f, "const %s g_smallPrimes[] = {", primeLimit <= 65535 ? "UINT16" : "UINT32" );
    UINT32 i = 0;
    while( i < MAX_PRIMES && g_smallPrimes[i] <= primeLimit )
    {
        if( (i%8) == 0 ) {
            fprintf( f, "\n    " );
        } else {
            fprintf( f, " " );
        }
        fprintf( f, "%6d,", g_smallPrimes[i] );
        i++;
    }
    CHECK( i < MAX_PRIMES, "Not enough primes generated" );
    g_nSmallPrimes = i;
    fprintf( f, "\n}; // There are %d primes <= %d\n", i, primeLimit );
}

VOID
printFileHeader( FILE * f )
{
    fprintf( f,
        "//\n"
        "// Parameters for trial division mechanism\n"
        "// Copyright (c) Microsoft Corporation. Licensed under the MIT license.\n"
        "// GENERATED FILE, DO NOT EDIT.\n"
        "//\n"
        "\n" );
}

VOID
printSmallPrimeDifferences( FILE * f, UINT32 primeLimit )
{
    fprintf( f,
        "//\n"
        "// Table of small primes differences for primes <= %d\n"
        "// Copyright (c) Microsoft Corporation. Licensed under the MIT license.\n"
        "// GENERATED FILE, DO NOT EDIT.\n"
        "//\n"
        "// Table encodes small primes except 2, 3, 5, and 17 which are handled separately\n"
        "// Read the bytes in order, and split each byte into nibbles LSnibble first.\n"
        "// Set p = 3 and for each nibble:\n"
        "//     if nibble != 0, next prime is p + 2*nibble\n"
        "//     if nibble == 0, set p = p + 30 and goto next nibble, no prime is specified\n"
        "//     if p == SYMCRYPT_MAX_SMALL_PRIME you've read the last nibble in the table\n"
        "// SYMCYRPT_N_SMALL_PRIMES_ENCODED is the # primes encoded in the table\n"
        "//\n"
        "\n",
        primeLimit );

    fprintf( f, "const BYTE g_SymCryptSmallPrimeDifferenceNibbles[] = {" );

    UINT32 prev;
    UINT32 i;
    UINT32 nCache = 0;
    UINT32 nNibbles = 0;
    char * sep = NULL;
    UINT32 nib;
    UINT32 diff;
    UINT32 nBytes = 0;
    UINT32 nPrimes = 0;
    double filterRate = 1.0;

    prev = 3;
    i = 0;
    while( i < MAX_PRIMES && g_smallPrimes[i] <= primeLimit )
    {
        UINT32 p = g_smallPrimes[i];
        i++;
        filterRate *= (double) (p-1) / p;
        if( p == 2 || p == 3 || p == 5 || p == 17 )
        {
            // We ignore primes 2, 3, 5, and 17 in this encoding
            continue;
        }
        diff = p - prev;
        prev = p;

        nPrimes++;

        while( diff > 0 )
        {
            if( diff >= 32 )
            {
                nib = 0; diff -= 30;
            } else {
                nib = diff/2;
                diff = 0;
            }
            if( (nNibbles & 1) == 0 )
            {
                nCache = nib;
            } else {
                sep = ((nNibbles % 32) == 1) ? "\n    " : " ";
                fprintf( f, "%s0x%02x,", sep, (nib << 4) | nCache );
                nBytes++;
            }
            nNibbles++;
        }
    }

    if( (nNibbles & 1 ) != 0 )
    {
        sep = ((nNibbles % 32) == 1) ? "\n    " : " ";
        fprintf( f, "%s0x%x,", sep, nCache );
        nBytes++;
    }
    fprintf( f,
        "\n"
        "}; // encodes %d primes <= %d in %d bytes\n", nPrimes, primeLimit, nBytes );
    fprintf( f,
        "// Trial division (including 2,3,5,17) will pass %2.3f%% of inputs.\n", filterRate * 100 );
    fprintf( f,
        "\n"
        "#define SYMCRYPT_MAX_SMALL_PRIME (%d)\n"
        , prev );
    fprintf( f,
        "\n"
        "#define SYMCRYPT_N_SMALL_PRIMES_ENCODED (%d)\n"
        , nPrimes );
}

VOID
printPrimeGroupSpec( FILE *f, UINT64 productLimit )
{
    fprintf( f,
        "\n"
        "//\n"
        "// The primes are put into groups of consecutive primes (skipping 2, 3, 5, and 17).\n"
        "// Each group has a product less than SYMCRYPT_MAX_SMALL_PRIME_GROUP_PRODUCT which is\n"
        "// chosen to avoid overflows in the modular reduction computation.\n"
        "//\n"
        "\n"
        "typedef struct _SYMCRYPT_SMALL_PRIME_GROUPS_SPEC {\n"
        "    UINT16 nGroups;    // # groups of this size \n"
        "    UINT8  nPrimes;    // # primes in the group \n"
        "    UINT32 maxPrime;   // largest prime in the last group \n"
        "} SYMCRYPT_SMALL_PRIME_GROUPS_SPEC;\n"
        "\n"
        );

    fprintf( f, "#define SYMCRYPT_MAX_SMALL_PRIME_GROUP_PRODUCT    (0x%I64xU)\n\n", productLimit );



    fprintf( f, "const SYMCRYPT_SMALL_PRIME_GROUPS_SPEC g_SymCryptSmallPrimeGroupsSpec[] = {\n" );
    UINT32 nPrevGroups = 0;
    UINT32 nPrevPrimes = 1000;
    UINT32 prevMaxPrime = 0;

    UINT64 m = 1;
    UINT32 nPrimesInThisGroup = 0;
    UINT32 maxPrime = 0;
    UINT32 i = 1;
    UINT32 nGroups = 0;
    UINT32 p = 0;
    while( i < MAX_PRIMES && nPrevPrimes >= 2 )
    {
        p = g_smallPrimes[i];
        i++;
        if( p == 2 || p == 3 || p == 5 || p == 17 )
        {
            // We ignore primes 2, 3, 5, and 17 as they are handles differently
            continue;
        }
        if( m <= productLimit / p )
        {
            //fprintf( f, "[%d]", p );
            m *= p;
            nPrimesInThisGroup++;
            continue;
        }
        // We have found a group
        //printf( "/" );
        maxPrime = g_smallPrimes[i-2];  // largest prime of the group we just found
        nGroups++;
        if( nPrimesInThisGroup != nPrevPrimes )
        {
            if(  prevMaxPrime != 0 )
            {
                fprintf( f, "    { %5d, %2d, %d },\n", nPrevGroups, nPrevPrimes, prevMaxPrime );
            }
            nPrevGroups = 1;
            nPrevPrimes = nPrimesInThisGroup;
            prevMaxPrime = maxPrime;
            if( nPrimesInThisGroup == 2 && productLimit > 0xffffffff )
            {
                break;
            }
        } else {
            nPrevGroups++;
            prevMaxPrime = maxPrime;
        }
        //fprintf( f, "[%d]", p );
        m = p;
        nPrimesInThisGroup = 1;
    }

    // We still have to process the last group
    nGroups++;
    if( nPrimesInThisGroup != nPrevPrimes )
    {
        if(  nPrevPrimes != 0 )
        {
                fprintf( f, "    { %5d, %2d, %d },\n", nPrevGroups, nPrevPrimes, prevMaxPrime );
        }
        nPrevGroups = 1;
        nPrevPrimes = nPrimesInThisGroup;
        prevMaxPrime = p;
    } else {
        nPrevGroups++;
    }

    fprintf( f, "    { %5d, %2d, 0x%x },\n", 0, nPrimesInThisGroup, 0xffffffff );

    fprintf( f, "};\n" );

    fprintf( f, "\n" );
}

VOID
createFile( UINT32 bitSize /*, UINT32 primeLimit */)
{
    CHECK( bitSize == 32 || bitSize == 64, "?" );

    char * fileName = bitSize == 32 ? "smallPrimes32.h_gen" : "smallPrimes64.h_gen";
    FILE * f = fopen( fileName, "wt" );
    CHECK3( f != NULL, "Could not create file %s", fileName );

    printFileHeader( f );
    printFileHeader( stdout );

	// dcl - cleanup?
    //printSmallPrimeDifferences( f, primeLimit );
    //printSmallPrimeDifferences( stdout, primeLimit );

	// dcl - on 64-bit, productLimit should initialize to 0x8000000000000000
	// Then when we multiply by 2, it becomes zero, and then very large
	// Not sure if that's really what you intended.
    UINT64 productLimit = (UINT64)1 << (bitSize-1); // Can't shift by 64...
    productLimit *= 2;
    productLimit -= 1;
    productLimit /= 9;

    printPrimeGroupSpec( f, productLimit );
    printPrimeGroupSpec( stdout, productLimit );

    fclose( f );
}


typedef struct {
    UINT32  prime;
    UINT32  selectivity;    // 1/selectivity items pass this filter
    double  signalPerByte;  // # bits of signal per byte of table space
} IFX_TPM_WEAK_KEY_PRIME_INFO;

int compareIfxPrimeSelectivity( const void * a, const void * b )
{
    IFX_TPM_WEAK_KEY_PRIME_INFO *pA = (IFX_TPM_WEAK_KEY_PRIME_INFO *)a;
    IFX_TPM_WEAK_KEY_PRIME_INFO *pB = (IFX_TPM_WEAK_KEY_PRIME_INFO *)b;

    if( pA->selectivity < pB->selectivity ) return 1;
    if( pA->selectivity == pB->selectivity ) return (int)(pA->prime) - (int)(pB->prime);
    if( pA->selectivity > pB->selectivity ) return -1;

    CHECK( FALSE, "?" );
    return 0;
}

int SYMCRYPT_CDECL compareIfxPrimeEfficiency( const void * a, const void * b )
{
    IFX_TPM_WEAK_KEY_PRIME_INFO *pA = (IFX_TPM_WEAK_KEY_PRIME_INFO *)a;
    IFX_TPM_WEAK_KEY_PRIME_INFO *pB = (IFX_TPM_WEAK_KEY_PRIME_INFO *)b;

    // Compare identical if within 0.1% of each other
    if( abs( pA->signalPerByte / pB->signalPerByte - 1.0 ) < 0.0001 ) return 0;
    if( pA->signalPerByte < pB -> signalPerByte ) return 1;
    return -1;
}


#define IFX_N_PRIMES_IN_KEYGEN  (126)

VOID
buildGeneratorBitmap( UINT32 prime, UINT32 generator, BYTE * buf, UINT32 * pCnt )
{
    UINT32 nBytes = (prime + 7) / 8;

    memset( buf, 0, nBytes );

    UINT32 s = 1;
    UINT32 cnt = 0;

    while( ( (buf[s/8] >> (s % 8)) & 1 ) == 0 )
    {
        buf[s/8] |= 1 << (s%8);
        cnt++;
        s = (s * generator) % prime;
    }

    *pCnt = cnt;
}

BYTE workBuffer[ 1<<20 ];

VOID
printIfxTpmWeakKeyTable( FILE * f )
{
    fprintf( f,
        "//\n"
        "// Some Infineon TPMs generate(d) RSA keys where the primes and modulus, when taken\n"
        "// modulo any of the first 126 primes, is a power of 65537\n"
        "// These keys are insecure.\n"
        "// This file contains information used to detect the modulus of these weak keys.\n"
        "// Copyright (c) Microsoft Corporation. Licensed under the MIT license.\n"
        "// GENERATED FILE, DO NOT EDIT.\n"
        "//\n"
        "\n"
        "//\n"
        "// Detection is by checking whether the modulus is in the subgroup generated by \n"
        "// 65537 modulo a set of small primes. Only primes where 65537 is not a generator of \n"
        "// the multiplicative subgroup are used. To reduce footprint, we select primes\n"
        "// with the best selectivity per byte of table space for a false-positive rate of\n"
        "// less than 2^{-80}. We then sorted the primes with these most selective one first\n"
        "// to optimize performance.\n"
        "// A good key is detected as soon as we hit a prime where the key is not in the subgroup\n"
        "// generated by 65537. Almost all good keys are detected by the very first prime which \n"
        "// only lets 1:165 good keys through.\n"
        "// Weak keys have to go through all primes in the table, and are the slowest, but we don't\n"
        "// care about the performance of the weak key case.\n"
        "//\n"
        "\n"
    );

    // Look at all the primes and measure their selectivity for the detection
    IFX_TPM_WEAK_KEY_PRIME_INFO primeInfo[IFX_N_PRIMES_IN_KEYGEN];
    for( int i=0; i<IFX_N_PRIMES_IN_KEYGEN; i++ )
    {
        UINT32 p = g_smallPrimes[i];
        UINT32 count = 0;

        // Count how many values modulo p are generated by 65537
        buildGeneratorBitmap( p, 65537, &workBuffer[0], &count );
        primeInfo[i].prime = p;
        CHECK( (p-1) % count == 0, "Math error" );
        primeInfo[i].selectivity = (p-1) / count;
        primeInfo[i].signalPerByte = (log( (double) primeInfo[i].selectivity ) / log((double)2)) / (2.0 + (UINT32)((p+7)/8) );
        // p-1 is always a multiple of count because the order of an element is a divisor of the order of a group
        //printf( "Raw: %3d, %3d, %0.6f\n", primeInfo[i].prime, primeInfo[i].selectivity, primeInfo[i].signalPerByte );
    }

    // Sort them by decreasing efficiency
    qsort( &primeInfo[0], IFX_N_PRIMES_IN_KEYGEN, sizeof( primeInfo[0] ), compareIfxPrimeEfficiency );

    UINT32 nPrimesToFilter = 0;
    double filterLog = 0.0;
    while( filterLog < 80.0 )
    {
        CHECK( nPrimesToFilter < IFX_N_PRIMES_IN_KEYGEN, "Filter requirement too selective" );
        filterLog += log( (double)primeInfo[nPrimesToFilter].selectivity ) / log( (double) 2 );
        // UINT32 i = nPrimesToFilter;
        //printf( "Select: %3d, %3d, %0.6f\n", primeInfo[i].prime, primeInfo[i].selectivity, primeInfo[i].signalPerByte );
        nPrimesToFilter++;
    }

    // Sort them by decreasing selectivity
    qsort( &primeInfo[0], nPrimesToFilter, sizeof( primeInfo[0] ), compareIfxPrimeSelectivity );

    UINT32 nBytesTotal = 0;

    for( UINT32 i=0; i<nPrimesToFilter; i++ )
    {
        nBytesTotal += (primeInfo[i].prime + 7)/8 + 2;
        //printf( "Tables: %3d, %3d, %0.6f\n", primeInfo[i].prime, primeInfo[i].selectivity, primeInfo[i].signalPerByte );
    }

    fprintf( f, "// %d primes using %d bytes give a false-positive rate of 2^-%3.2f\n\n", nPrimesToFilter, nBytesTotal, filterLog );

    fprintf( f, "UINT16 g_SymCryptIfxTpmWeakKeysDetectionPrimeTable[] = {\n" );
    for( UINT32 i=0; i<nPrimesToFilter; i++ )
    {
        UINT32 nBytes = (primeInfo[i].prime + 7)/8 + 2;
        fprintf( f, "    %3d,    // filters 1:%3d, %2d bytes, signal/byte = %1.3f\n",
            primeInfo[i].prime, primeInfo[i].selectivity, nBytes, primeInfo[i].signalPerByte );
    }
    fprintf( f,
        "      0,    // Sentinel\n"
        "};\n"
        "\n"
    );

    fprintf( f,
        "// Bitmask table.\n"
        "// For each prime p, there is a bitmask of (p+7)/8 bytes, with the i'th bit in the bitmask\n"
        "// indicating that the value i is generated by 65537 modulo p. These bitmasks are stored \n"
        "// consecutively in this array, in the order of the primes in the table above.\n"
        "BYTE g_SymCryptIfxTpmWeakKeyDetectionBitmasks[] = {"
        );

    for( UINT32 i=0; i<nPrimesToFilter; i++ )
    {
        UINT32 p = primeInfo[i].prime;
        UINT32 nBytes = (p + 7)/8;
        UINT32 count;
        char * sep = "";

        fprintf( f, "\n\n    // %d\n    ", p );
        buildGeneratorBitmap( p, 65537, &workBuffer[0], &count );
        for( UINT32 j=0; j<nBytes; j++ )
        {
            fprintf( f, "%s0x%02x,", sep, workBuffer[j] );
            sep = (j%16)==15 ? "\n    " : " ";
        }
    }
    fprintf( f, "\n};\n" );


    /*
    double logProb = 0;
    UINT32 nFilterPrimes = 0;

    for( UINT32 i=1; i<=nPrimesUsed; i++ ) // 126 primes were used in \PI
    {
        BYTE  buf[1024];
        memset( buf, 0, sizeof( buf ) );

        UINT32 p = g_smallPrimes[i];
        UINT32 s = 1;
        UINT32 n = 0;

        while( ( (buf[s/8] >> (s % 8)) & 1 ) == 0 )
        {
            buf[s/8] |= 1 << (s%8);
            n++;
            s = (s * 65537) % p;
        }

        if( n < p-1 )
        {
            fprintf( f, "{ %3d, ", p);
            char * sep = "{";
            for( UINT32 j=0; j<nBytesInTable; j++ )
            {
                fprintf( f, "%s 0x%02x", sep, buf[j] );
                sep = j % 16 != 15 ? "," : "\n        ";
            }
            double bitFiltered = (log( (double) p-1 ) - log( (double) n ) ) / log( (double) 2);
            fprintf( f, " } }; // %1.1f bits filtered\n", bitFiltered );
            logProb += bitFiltered;
            nFilterPrimes += 1;
        }
    }
    fprintf( f, "};\n" );

    fprintf( f, "// # filter primes = %d\n", nFilterPrimes );
    fprintf( f, "// 2-log of false-positive rate = %2.1f\n", logProb );

    double piLen = 0;
    for( UINT32 i=0; i<130; i++ )
    {
        piLen += log( (double) g_smallPrimes[i] ) / log( (double) 2 );
        printf( "%3d: %3d, %5f\n", i, g_smallPrimes[i], piLen );
    }
    */
}

VOID
createIfxTpmWeakKeyTable()
{
    char * fileName = "IfxTpmWeakKeyTables.h_gen";
    FILE * f = fopen( fileName, "wt" );
    CHECK3( f != NULL, "Could not create file %s", fileName );

    printIfxTpmWeakKeyTable( stdout );
    printIfxTpmWeakKeyTable( f );
    fclose( f );
}

int SYMCRYPT_CDECL
main( int argc, _In_reads_( argc ) char * argv[] )
{
    printf( "SymCrypt constants generation program\n" );

    generateSmallPrimes();

    UNREFERENCED_PARAMETER( argc );
    UNREFERENCED_PARAMETER( argv );

    createFile( 32 );        // primes <= 21845 can still be 2 to a group in 32 bits mode
    createFile( 64 );        // extra 30 ensures the last group is 'full', which is more efficient.

    createIfxTpmWeakKeyTable();

    exit(0);
}
