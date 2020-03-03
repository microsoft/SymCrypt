//
// TestTlsCbcHmac.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"


VOID
testScsRotateBuffer()
{
    UINT32 bufSize;
    BYTE buf1[1 << 13];
    BYTE buf2[sizeof( buf1 )];

    for( bufSize = 32; bufSize <= sizeof( buf1 ); bufSize *= 2 )
    {
        GENRANDOM( buf1, bufSize );

        for( UINT32 s = 0; s < bufSize; s ++ )
        {
            memcpy( buf2, buf1, bufSize );
            SymCryptScsRotateBuffer( buf2, bufSize, s );

            for( UINT32 i = 0; i < bufSize; i++ )
            {
                CHECK4( buf2[i] == buf1[ (i + s) % bufSize ], "Buffer rotation error %d, %d", bufSize, s );
            }
        }
    }
}

VOID
testScsCopy()
{
    BYTE buf1[ 1 << 10 ];
    BYTE buf2[ sizeof( buf1 ) ];
    BYTE hashValue[ SYMCRYPT_SHA256_RESULT_SIZE ];

    for( UINT32 i = 0; i < 1000; i++ )
    {
        UINT32 nSrc;
        UINT32 nDst;
        GENRANDOM( &nSrc, sizeof( nSrc ) );
        GENRANDOM( &nDst, sizeof( nDst ) );

        nSrc = nSrc % sizeof( buf1 );
        nDst = nDst % sizeof( buf1 );
        UINT32 nCopied = SYMCRYPT_MIN( nSrc, nDst );

        GENRANDOM( buf1, sizeof( buf1 ) );
        GENRANDOM( buf2, sizeof( buf2 ) ); 

        // Checksum to check we don't write past the Dst buffer
        SymCryptSha256( &buf2[nCopied], sizeof( buf2 ) - nCopied, &hashValue[0] );

        SymCryptScsCopy( buf1, nSrc, buf2, nDst );

        CHECK( memcmp( buf1, buf2, nCopied) == 0, "Value not copied properly" );
        SymCryptSha256( &buf2[nCopied], sizeof( buf2 ) - nCopied, buf1 );
        CHECK( memcmp( buf1, hashValue, sizeof( hashValue )) == 0, "Copy overran destination buffer" );
    }
}

VOID
testBasicMaskFunctions()
{
    UINT64 a64;
    UINT64 b64;
    UINT32 a32;
    UINT32 b32;
    UINT32 a31;
    UINT32 b31;

    UINT32 rnd;

    for( UINT32 i=0; i<1000; i++ )
    {
        // Generate two random values to compare
        GENRANDOM( &a64, sizeof( a64 ) );
        GENRANDOM( &b64, sizeof( b64 ) );

        GENRANDOM( &rnd, sizeof( rnd ) );

        // Generate corner cases with some reasonable probability
        if( rnd % 17 == 0 )
        {
            a64 &= 7;      // Pick small values
            if( rnd % 5 == 0 )
            {
                a64 = 0 - a64;  // And sometimes very large ones
            }
        }        

        if( rnd % 11 == 0 )
        {
            b64 = a64;
            if( rnd % 3 == 0 )
            {
                b64 = 0 - b64;
            }
        }

        if( rnd % 19 == 0 )
        {
            b64 &= 7;
            if( rnd % 7 == 0 )
            {
                b64 = 0 - b64;
            }
        } 

        a32 = (UINT32) a64;
        b32 = (UINT32) b64;
        a31 = a32 & 0x7fffffff;
        b31 = b32 & 0x7fffffff;

        CHECK( SymCryptMask32IsZeroU31( a31 )    == 0 - (UINT32)(a31 == 0), "SymCryptMask32IsZeroU31" );
        CHECK( SymCryptMask32IsNonzeroU31( a31 ) == 0 - (UINT32)(a31 != 0), "SymCryptMask32IsZeroU31" );

        CHECK5( SymCryptMask32EqU32( a32, b32 )  == 0 - (UINT32)(a32 == b32), "SymCryptMask32EqU32( %04x, %04x ), %d", a32, b32, i );

        CHECK( SymCryptMask32NeqU31( a31, b31 )  == 0 - (UINT32)(a31 != b31), "SymCryptMask32NeqU31" );
        CHECK( SymCryptMask32LtU31( a31, b31 )   == 0 - (UINT32)(a31 < b31), "SymCryptMask32LtU31" );
    }

}


VOID
testScsTools()
{
    testScsRotateBuffer();

    testScsCopy();

    testBasicMaskFunctions();
}
