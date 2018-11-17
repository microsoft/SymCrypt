//
// Test & performance of utility functions
//
// Copyright (c) Microsoft Corporation.  All rights reserved.
//

#include "precomp.h"

VOID
testBitByteSize()
{
    UINT64 v;

    CHECK( NT_SUCCESS( GENRANDOM( &v, sizeof( v ) ) ), "?" );
    v |= ((UINT64)1) << 63;

    UINT32 bits = 64;
    while( bits != (UINT32) -1 )
    {
        UINT32 bytes = (bits + 7)/8;
        CHECK( SymCryptUint64Bitsize(v) == bits, "Wrong bitsize 64" );
        CHECK( SymCryptUint64Bytesize(v) == bytes, "Wrong bytesize 64" );

        if( bits <= 32 )
        {
            CHECK( SymCryptUint32Bitsize( (UINT32)v ) == bits, "Wrong bitsize 32" );
            CHECK( SymCryptUint32Bytesize( (UINT32) v ) == bytes, "Wrong bytesize 32" );
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

    // Try each byte size
    for( UINT32 nBytes = 0; nBytes <= 8; nBytes++ )
    {
        // Generate a random value, and extend to 12 bytes
        CHECK( NT_SUCCESS( GENRANDOM( val, sizeof( val ) )), "?" );
        SymCryptWipe( &val[nBytes], sizeof(val) - nBytes );

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
            sc1 = SymCryptStoreLsbFirstUint64( v64, buf1, n );
            sc2 = SymCryptStoreLsbFirstUint32( v32, buf2, n );
            sc3 = SymCryptStoreMsbFirstUint64( v64, buf3, n );
            sc4 = SymCryptStoreMsbFirstUint32( v32, buf4, n );
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
            sc1 = SymCryptLoadLsbFirstUint64( buf1, n, &v64 );
            sc2 = SymCryptLoadLsbFirstUint32( buf2, n, &v32 );
            sc3 = SymCryptLoadMsbFirstUint64( buf3, n, &w64 );
            sc4 = SymCryptLoadMsbFirstUint32( buf4, n, &w32 );

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
        SymCryptWipe( buf1, sizeof( buf1 ) );
        buf1[ j ] = 1;

        sc1 = SymCryptLoadLsbFirstUint64( buf1, 12, &v64 );
        sc2 = SymCryptLoadLsbFirstUint32( buf1, 12, &v32 );
        sc3 = SymCryptLoadMsbFirstUint64( buf1, 12, &w64 );
        sc4 = SymCryptLoadMsbFirstUint32( buf1, 12, &w32 );
        CHECK( (sc1 == SYMCRYPT_NO_ERROR) == (j < 8), "?" );
        CHECK( (sc2 == SYMCRYPT_NO_ERROR) == (j < 4), "?" );
        CHECK( (sc3 == SYMCRYPT_NO_ERROR) == (j >= 4), "?" );
        CHECK( (sc4 == SYMCRYPT_NO_ERROR) == (j >= 8), "?" );
    }
   

}


VOID
testUtil()
{
    print( "    utilities" );

    testBitByteSize();

    testLoadStore();
    
    print ( "\n" );
}





