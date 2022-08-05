//
// TestTlsCbcHmac.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"

#define MAX_MAP_UINT32_LEN 99

VOID
testScsRotateBuffer()
{
    UINT32 bufSize;
    BYTE buf1[1 << 13];
    BYTE buf2[sizeof( buf1 )];

    if (!SCTEST_LOOKUP_DISPATCHSYM(SymCryptScsRotateBuffer))
    {
        print("    testScsRotateBuffer skipped\n");
        return;
    }

    for( bufSize = 32; bufSize <= sizeof( buf1 ); bufSize *= 2 )
    {
        GENRANDOM( buf1, bufSize );

        for( UINT32 s = 0; s < bufSize; s ++ )
        {
            memcpy( buf2, buf1, bufSize );
            ScDispatchSymCryptScsRotateBuffer( buf2, bufSize, s );

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

    if (!SCTEST_LOOKUP_DISPATCHSYM(SymCryptSha256) ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptScsCopy))
    {
        print("    testScsCopy skipped\n");
        return;
    }

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
        ScDispatchSymCryptSha256( &buf2[nCopied], sizeof( buf2 ) - nCopied, &hashValue[0] );

        ScDispatchSymCryptScsCopy( buf1, nSrc, buf2, nDst );

        CHECK( memcmp( buf1, buf2, nCopied) == 0, "Value not copied properly" );
        ScDispatchSymCryptSha256( &buf2[nCopied], sizeof( buf2 ) - nCopied, buf1 );
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

    if (!SCTEST_LOOKUP_DISPATCHSYM(SymCryptMask32IsZeroU31)     ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptMask32IsNonzeroU31)  ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptMask32EqU32)         ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptMask32NeqU31)        ||
        !SCTEST_LOOKUP_DISPATCHSYM(SymCryptMask32LtU31))
    {
        print("    testBasicMaskFunctions skipped\n");
        return;
    }

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

        CHECK( ScDispatchSymCryptMask32IsZeroU31( a31 )    == 0 - (UINT32)(a31 == 0), "SymCryptMask32IsZeroU31" );
        CHECK( ScDispatchSymCryptMask32IsNonzeroU31( a31 ) == 0 - (UINT32)(a31 != 0), "SymCryptMask32IsZeroU31" );

        CHECK5( ScDispatchSymCryptMask32EqU32( a32, b32 )  == 0 - (UINT32)(a32 == b32), "SymCryptMask32EqU32( %04x, %04x ), %d", a32, b32, i );

        CHECK( ScDispatchSymCryptMask32NeqU31( a31, b31 )  == 0 - (UINT32)(a31 != b31), "SymCryptMask32NeqU31" );
        CHECK( ScDispatchSymCryptMask32LtU31( a31, b31 )   == 0 - (UINT32)(a31 < b31), "SymCryptMask32LtU31" );
    }

}

VOID 
initMapUint32(PSYMCRYPT_UINT32_MAP pMap, UINT32 uMapLen)
{
    UINT32 uDuplication;
    GENRANDOM(&uDuplication, sizeof(uDuplication));

    // Limiting the number of duplicates of 'from' values to be at most uMapLen
    uDuplication = uDuplication % uMapLen;

    // Generating fully random map
    for (UINT32 i = 0; i < uMapLen; ++i)
    {
        GENRANDOM(&(pMap[i].from), sizeof(pMap[i].from));
        GENRANDOM(&(pMap[i].to), sizeof(pMap[i].to));
    }

    // forcing duplications
    for (UINT32 i = 0; i < uDuplication; ++i)
    {
        UINT32 copyFromEntry;
        UINT32 copyToEntry;

        GENRANDOM(&copyFromEntry, sizeof(copyFromEntry));
        GENRANDOM(&copyToEntry, sizeof(copyToEntry));

        copyFromEntry = copyFromEntry % uMapLen;
        copyToEntry = copyToEntry % uMapLen;

        pMap[copyToEntry].from = pMap[copyFromEntry].from;
    }
}

bool
validateMapping(UINT32 u32Input, PCSYMCRYPT_UINT32_MAP pMap, UINT32 uMapLen)
{
    UINT32 u32Default;
    UINT32 u32Result;

    bool result = false;
    bool exists = false;

    GENRANDOM(&u32Default, sizeof(u32Default));

    u32Result = ScDispatchSymCryptMapUint32(u32Input, u32Default, pMap, uMapLen);

    for (UINT32 i = 0; i < uMapLen; ++i)
    {
        if (pMap[i].from == u32Input)
        {
            exists = true;
            if (pMap[i].to == u32Result)
            {
                result = true;
                break;
            }
        }
    }

    if (!exists && u32Result == u32Default)
    {
        result = true;
    }

    return result;
}

VOID
testScsMapUint32()
{
    UINT32 uMapLen;
    GENRANDOM(&uMapLen, sizeof(uMapLen));

    if (!SCTEST_LOOKUP_DISPATCHSYM(SymCryptMapUint32))
    {
        print("    testScsMapUint32 skipped\n");
        return;
    }

    // Limiting the length of the map to be between 1 to 100.
    // We want to avoid a creation of huge map.
    uMapLen = (uMapLen % MAX_MAP_UINT32_LEN) + 1;

    PSYMCRYPT_UINT32_MAP pMap = new SYMCRYPT_UINT32_MAP[uMapLen];
    CHECK(pMap != NULL, "Out of memory");

    // Initiating map with random values
    initMapUint32(pMap, uMapLen);

    // Validating SymCryptMapUint32 result for every 'from' value in map
    for (UINT32 i = 0; i < uMapLen; ++i)
    {
        CHECK(validateMapping(pMap[i].from, pMap, uMapLen), "SymCryptMapUint32");
    }

    // Validating SymCryptMapUint32 result for random inputs

    for (UINT32 i = 0; i < MAX_MAP_UINT32_LEN; ++i)
    {
        UINT32 u32RndInput;
        GENRANDOM(&u32RndInput, sizeof(u32RndInput));
        CHECK(validateMapping(u32RndInput, pMap, uMapLen), "SymCryptMapUint32");
    }

    //cleanup
    delete [] pMap;
}

VOID
testScsTools()
{
    testScsRotateBuffer();

    testScsCopy();

    testBasicMaskFunctions();

    testScsMapUint32();
}
