//
// Test & performance of utility functions
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"

VOID
testBitByteSize()
{
    UINT64 v;
    if (!SCTEST_LOOKUP_DISPATCHSYM(SymCryptUint64Bitsize)   ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptUint64Bytesize)  ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptUint32Bitsize)   ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptUint32Bytesize) )
    {
        print("    testBitByteSize skipped\n");
        return;
    }

    CHECK( NT_SUCCESS( GENRANDOM( &v, sizeof( v ) ) ), "?" );
    v |= ((UINT64)1) << 63;

    UINT32 bits = 64;
    while( bits != (UINT32) -1 )
    {
        UINT32 bytes = (bits + 7)/8;
        CHECK( ScDispatchSymCryptUint64Bitsize( v ) == bits, "Wrong bitsize 64" );
        CHECK( ScDispatchSymCryptUint64Bytesize( v ) == bytes, "Wrong bytesize 64" );

        if( bits <= 32 )
        {
            CHECK( ScDispatchSymCryptUint32Bitsize( (UINT32)v ) == bits, "Wrong bitsize 32" );
            CHECK( ScDispatchSymCryptUint32Bytesize( (UINT32) v ) == bytes, "Wrong bytesize 32" );
        }
        v >>= 1;
        bits -= 1;
    }
}

VOID
testLoadStore()
{
    BYTE val[12];
    BYTE buf1[12];
    BYTE buf2[12];
    BYTE buf3[12];
    BYTE buf4[12];
    SYMCRYPT_ERROR sc1;
    SYMCRYPT_ERROR sc2;
    SYMCRYPT_ERROR sc3;
    SYMCRYPT_ERROR sc4;
    UINT32 v32;
    UINT64 v64;
    UINT32 w32;
    UINT64 w64;

    if (!SCTEST_LOOKUP_DISPATCHSYM(SymCryptWipe)                ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptLoadLsbFirstUint64)  ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptLoadLsbFirstUint32)  ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptLoadMsbFirstUint64)  ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptLoadMsbFirstUint64) )
    {
        print("    testLoadStore skipped\n");
        return;
    }

    // Try each byte size
    for( UINT32 nBytes = 0; nBytes <= 8; nBytes++ )
    {
        // Generate a random value, and extend to 12 bytes
        CHECK( NT_SUCCESS( GENRANDOM( val, sizeof( val ) )), "?" );
        ScDispatchSymCryptWipe( &val[nBytes], sizeof(val) - nBytes );

        // Make sure the size is tight.
        if( nBytes > 0 )
        {
            val[nBytes-1] |= 0x1;
        }

        for( UINT32 n = 0; n <= 12; n++ )
        {
            // n = size of destination buffer

            v64 = SYMCRYPT_LOAD_LSBFIRST64( val );
            v32 = (UINT32) v64;

            // Store all 4 sizes
            memset( buf1, 'n', 12 );
            memset( buf2, 'n', 12 );
            memset( buf3, 'n', 12 );
            memset( buf4, 'n', 12 );
            sc1 = ScDispatchSymCryptStoreLsbFirstUint64( v64, buf1, n );
            sc2 = ScDispatchSymCryptStoreLsbFirstUint32( v32, buf2, n );
            sc3 = ScDispatchSymCryptStoreMsbFirstUint64( v64, buf3, n );
            sc4 = ScDispatchSymCryptStoreMsbFirstUint32( v32, buf4, n );
            CHECK( n == 12 || (buf1[n] == 'n' && buf2[n] == 'n' && buf3[n] == 'n' && buf4[n] == 'n'), "?" );

            // Check that we get the right error conditions
            CHECK( (sc1 == SYMCRYPT_NO_ERROR) == (n >= nBytes), "?" );
            CHECK( (sc3 == SYMCRYPT_NO_ERROR) == (n >= nBytes), "?" );
            if( nBytes <= 4 )
            {
                CHECK( (sc2 == SYMCRYPT_NO_ERROR) == (n >= nBytes), "?" );
                CHECK( (sc4 == SYMCRYPT_NO_ERROR) == (n >= nBytes), "?" );
            }

            // Check we got the right values
            for( UINT32 j=0; j<n; j++ )
            {
                CHECK( (sc1 != SYMCRYPT_NO_ERROR) || buf1[j] == val[j], "?" );
                CHECK( (sc3 != SYMCRYPT_NO_ERROR) || buf3[j] == val[ n - j - 1], "?" );

                if( nBytes <= 4 )
                {
                    CHECK( (sc2 != SYMCRYPT_NO_ERROR) || buf2[j] == val[j], "?" );
                    CHECK( (sc4 != SYMCRYPT_NO_ERROR) || buf4[j] == val[ n - j - 1], "?" );
                }
            }

            // Now we try the loads
            sc1 = ScDispatchSymCryptLoadLsbFirstUint64( buf1, n, &v64 );
            sc2 = ScDispatchSymCryptLoadLsbFirstUint32( buf2, n, &v32 );
            sc3 = ScDispatchSymCryptLoadMsbFirstUint64( buf3, n, &w64 );
            sc4 = ScDispatchSymCryptLoadMsbFirstUint32( buf4, n, &w32 );

                // Check the results
            CHECK( sc1 == SYMCRYPT_NO_ERROR && sc2 == SYMCRYPT_NO_ERROR && sc3 == SYMCRYPT_NO_ERROR && sc4 == SYMCRYPT_NO_ERROR, "?" );
            CHECK( v64 == w64 && v32 == w32, "?" );
            CHECK( (UINT32) v64 == v32, "?" );
            CHECK( (n < nBytes) || (v64 == SYMCRYPT_LOAD_LSBFIRST64( val )), "?" );
        }
    }

    // Remains to check the errors on the loads
    for( UINT32 j=0; j < 12; j++ )
    {
        ScDispatchSymCryptWipe( buf1, sizeof( buf1 ) );
        buf1[ j ] = 1;

        sc1 = ScDispatchSymCryptLoadLsbFirstUint64( buf1, 12, &v64 );
        sc2 = ScDispatchSymCryptLoadLsbFirstUint32( buf1, 12, &v32 );
        sc3 = ScDispatchSymCryptLoadMsbFirstUint64( buf1, 12, &w64 );
        sc4 = ScDispatchSymCryptLoadMsbFirstUint32( buf1, 12, &w32 );
        CHECK( (sc1 == SYMCRYPT_NO_ERROR) == (j < 8), "?" );
        CHECK( (sc2 == SYMCRYPT_NO_ERROR) == (j < 4), "?" );
        CHECK( (sc3 == SYMCRYPT_NO_ERROR) == (j >= 4), "?" );
        CHECK( (sc4 == SYMCRYPT_NO_ERROR) == (j >= 8), "?" );
    }

}

VOID
testUint64Gcd()
{
    UINT64 a;
    UINT64 b;
    UINT64 gcd;
    UINT64 t;

    if ( !SCTEST_LOOKUP_DISPATCHSYM(SymCryptUint64Gcd) )
    {
        print("    testUint64Gcd skipped\n");
        return;
    }

    // First we just test that the GCD result is a divisor of both inputs
    // The probability that a GCD != 1 is about 40% so we will hit this
    for( int i=0; i<64*64; i++ )
    {
        GENRANDOM( &a, sizeof( a ) );
        GENRANDOM( &b, sizeof( b ) );

        // Check different sizes, we just try all combinations.
        a >>= i % 64;
        b >>= (i/64) % 64;

        if( ((a | b) & 1) == 0 )
        {
            // make one of them odd, re-using a bit of a for the random selection
            t = (a >> 14) & 1;
            a |= t;
            b |= 1-t;
        }

        gcd = ScDispatchSymCryptUint64Gcd( a, b, SYMCRYPT_FLAG_GCD_INPUTS_NOT_BOTH_EVEN );

        CHECK( gcd != 0 && a % gcd == 0 && b % gcd == 0, "Wrong GCD output from SymCryptUint64Gcd()" );
    }

    // Now we check that any common factors are in fact found
    for( int i=0; i<64 * 64; i++ )
    {
        // Generate a random joint factor, which must be odd (as one input must be odd)
        GENRANDOM( &t, sizeof( t ) );
        t >>= (i % 64);
        t |= 1;

        // Generate a & b until at least one of them is odd
        do {
            GENRANDOM( &a, sizeof( a ) );
            GENRANDOM( &b, sizeof( b ) );

            // make a and b a multiple of t
            a -= a % t;
            b -= b % t;
        } while( ((a | b) & 1) == 0 );

        gcd = ScDispatchSymCryptUint64Gcd( a, b, SYMCRYPT_FLAG_GCD_INPUTS_NOT_BOTH_EVEN );

        // Check that the factor t was found; there might be other common factors.
        CHECK( gcd >= t && gcd % t == 0, "SymCryptUint64Gcd did not detect a common factor" );
    }

    // Test a usecase that uses the max # iterations
    // This case uses 63 iterations to change 1<<63 to 1,
    // Another 63 to reduce the 2nd number to 1, and one more to get (0,1)
    CHECK( ScDispatchSymCryptUint64Gcd( (UINT64)1 << 63, ((UINT64)1 << 31) + 1, SYMCRYPT_FLAG_GCD_INPUTS_NOT_BOTH_EVEN) == 1, "Wrong uint64GCD result" );
}


VOID
testCountLeadingTrailingZeros()
{
    //
    // Test SymCryptCountLeadingZeros32 and SymCryptCountTrailingZeros32
    //

    // Zero input
    CHECK( SymCryptCountLeadingZeros32( 0 ) == 32, "CLZ32(0) should be 32" );
    CHECK( SymCryptCountTrailingZeros32( 0 ) == 32, "CTZ32(0) should be 32" );

    // Single bit set at each position
    for( UINT32 i = 0; i < 32; i++ )
    {
        UINT32 v = (UINT32)1 << i;
        CHECK3( SymCryptCountLeadingZeros32( v ) == 31 - i, "CLZ32(1<<%d) wrong", i );
        CHECK3( SymCryptCountTrailingZeros32( v ) == i, "CTZ32(1<<%d) wrong", i );
    }

    // All bits set
    CHECK( SymCryptCountLeadingZeros32( 0xFFFFFFFF ) == 0, "CLZ32(0xFFFFFFFF) should be 0" );
    CHECK( SymCryptCountTrailingZeros32( 0xFFFFFFFF ) == 0, "CTZ32(0xFFFFFFFF) should be 0" );

    // Values with known leading/trailing structure
    CHECK( SymCryptCountLeadingZeros32( 0x00010000 ) == 15, "CLZ32(0x00010000)" );
    CHECK( SymCryptCountTrailingZeros32( 0x00010000 ) == 16, "CTZ32(0x00010000)" );

    // Random values: verify CLZ32 and CTZ32 are consistent with bit positions
    for( int i = 0; i < 1000; i++ )
    {
        UINT32 v;
        GENRANDOM( &v, sizeof(v) );
        if( v == 0 ) continue;

        UINT32 clz = SymCryptCountLeadingZeros32( v );
        UINT32 ctz = SymCryptCountTrailingZeros32( v );

        // The bit at position (31 - clz) must be set (MSB)
        CHECK( (v >> (31 - clz)) & 1, "CLZ32 inconsistent with value" );
        // No higher bit should be set
        if( clz > 0 )
        {
            CHECK( (v >> (32 - clz)) == 0, "CLZ32 too large" );
        }

        // The bit at position ctz must be set (LSB)
        CHECK( (v >> ctz) & 1, "CTZ32 inconsistent with value" );
        // No lower bit should be set
        if( ctz > 0 )
        {
            CHECK( (v & (((UINT32)1 << ctz) - 1)) == 0, "CTZ32 too large" );
        }
    }

    //
    // Test SymCryptCountLeadingZeros64 and SymCryptCountTrailingZeros64
    //

    // Zero input
    CHECK( SymCryptCountLeadingZeros64( 0 ) == 64, "CLZ64(0) should be 64" );
    CHECK( SymCryptCountTrailingZeros64( 0 ) == 64, "CTZ64(0) should be 64" );

    // Single bit set at each position
    for( UINT32 i = 0; i < 64; i++ )
    {
        UINT64 v = (UINT64)1 << i;
        CHECK3( SymCryptCountLeadingZeros64( v ) == 63 - i, "CLZ64(1<<%d) wrong", i );
        CHECK3( SymCryptCountTrailingZeros64( v ) == i, "CTZ64(1<<%d) wrong", i );
    }

    // All bits set
    CHECK( SymCryptCountLeadingZeros64( 0xFFFFFFFFFFFFFFFF ) == 0, "CLZ64(UINT64_MAX) should be 0" );
    CHECK( SymCryptCountTrailingZeros64( 0xFFFFFFFFFFFFFFFF ) == 0, "CTZ64(UINT64_MAX) should be 0" );

    // Values crossing the 32-bit boundary (exercises 32-bit fallback paths)
    CHECK( SymCryptCountLeadingZeros64( 0x0000000100000000 ) == 31, "CLZ64(1<<32)" );
    CHECK( SymCryptCountTrailingZeros64( 0x0000000100000000 ) == 32, "CTZ64(1<<32)" );
    CHECK( SymCryptCountLeadingZeros64( 0x00000000FFFFFFFF ) == 32, "CLZ64(0xFFFFFFFF)" );
    CHECK( SymCryptCountTrailingZeros64( 0x8000000000000000 ) == 63, "CTZ64(1<<63)" );

    // Random values: verify CLZ64 and CTZ64 are consistent with bit positions
    for( int i = 0; i < 1000; i++ )
    {
        UINT64 v;
        GENRANDOM( &v, sizeof(v) );
        if( v == 0 ) continue;

        UINT32 clz = SymCryptCountLeadingZeros64( v );
        UINT32 ctz = SymCryptCountTrailingZeros64( v );

        // The bit at position (63 - clz) must be set (MSB)
        CHECK( (v >> (63 - clz)) & 1, "CLZ64 inconsistent with value" );
        // No higher bit should be set
        if( clz > 0 )
        {
            CHECK( (v >> (64 - clz)) == 0, "CLZ64 too large" );
        }

        // The bit at position ctz must be set (LSB)
        CHECK( (v >> ctz) & 1, "CTZ64 inconsistent with value" );
        // No lower bit should be set
        if( ctz > 0 )
        {
            CHECK( (v & (((UINT64)1 << ctz) - 1)) == 0, "CTZ64 too large" );
        }
    }
}

VOID
testUtil()
{
    print( "    utilities\n" );

    testBitByteSize();

    testLoadStore();

    testUint64Gcd();

    testCountLeadingTrailingZeros();
}

VOID
testModuleInitEx()
{
    if( !g_dynamicSymCryptModuleHandle )
    {
        print("    testModuleInitEx skipped (no dynamic module loaded)\n");
        return;
    }

    auto pfnSymCryptModuleInitEx = SCTEST_LOOKUP_DYNSYM(SymCryptModuleInitEx, FALSE);
    if( pfnSymCryptModuleInitEx == NULL )
    {
        print("    testModuleInitEx skipped (symbol not available)\n");
        return;
    }

    // Success: requesting the current version should succeed
    CHECK( pfnSymCryptModuleInitEx( SYMCRYPT_CODE_VERSION_API, SYMCRYPT_CODE_VERSION_MINOR ) == SYMCRYPT_NO_ERROR,
           "SymCryptModuleInitEx should succeed with current version" );

    // Failure: requesting a newer API version should return SYMCRYPT_INVALID_ARGUMENT
    CHECK( pfnSymCryptModuleInitEx( SYMCRYPT_CODE_VERSION_API + 1, 0 ) == SYMCRYPT_INVALID_ARGUMENT,
           "SymCryptModuleInitEx should fail when requested API version is newer than module" );

    // Failure: requesting a newer minor version should return SYMCRYPT_INVALID_ARGUMENT
    CHECK( pfnSymCryptModuleInitEx( SYMCRYPT_CODE_VERSION_API, SYMCRYPT_CODE_VERSION_MINOR + 1 ) == SYMCRYPT_INVALID_ARGUMENT,
           "SymCryptModuleInitEx should fail when requested minor version is newer than module" );

    print("    testModuleInitEx passed\n");
}





