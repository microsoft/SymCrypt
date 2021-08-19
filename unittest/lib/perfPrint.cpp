//
// PerfPrint.cpp
// Printing output without affecting performance measurements
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"


//
// We don't want to print while we are still running tests, as the
// console updates trigger other threads in the system to start doing work.
// This module allows us to print output without disturbing the performance measurements.
//

#define MAX_OUTPUT_SIZE (1<<23)
CHAR Output[MAX_OUTPUT_SIZE];
SIZE_T OutputOffset=0;

VOID
print( String s )
{
    print( s.c_str() );
}

VOID
print( const char *format, ...)
{
    va_list vl;
    int res;

    va_start( vl, format );

    res = VSNPRINTF_S( &Output[OutputOffset], MAX_OUTPUT_SIZE - OutputOffset, _TRUNCATE, format, vl );

    CHECK( res >= 0 , "WHOA!!!" );

    OutputOffset += res;
}

VOID
printHex( PCBYTE pbData, SIZE_T cbData )
{
    for( SIZE_T i=0; i<cbData; i++ )
    {
        print( "%02x", pbData[i] );
    }
}

String
formatNumber( double v )
{
    char buf1[100];
    String res;
    ULONG s;

    if( v < 0 )
    {
        return "-" + formatNumber( -v );
    }

    if( isnan(v) )
    {
        return "NAN  ";
    }

    CHECK3( v < 1e24, "Number too large %f", v );

    bool fSmallInt = floor(v) == v && v < 10000;

    s = 0;
    if( v >= 10000 )
    {
        while( v >= 10000 )
        {
            v /= 1000;
            s++;
        }
    }

    // there doesn't seem to be a way to do a fixed-size result with the format specifiers
    // Our output is always 5 characters long
    if( v < 1 && !fSmallInt )
    {
        SNPRINTF_S( buf1, sizeof( buf1 ), _TRUNCATE, ".%03d",
            (int) ( 1000.0 * v) );
    } else if( v < 10 && !fSmallInt )
    {
        SNPRINTF_S( buf1, sizeof( buf1 ), _TRUNCATE, "%1d.%02d",
            (int)floor(v), (int) ( 100.0 * fmod( v, 1 ) ) );
    } else if( v < 100 && !fSmallInt )
    {
        SNPRINTF_S( buf1, sizeof( buf1 ), _TRUNCATE, "%2d.%01d",
            (int)floor(v), (int) ( 10.0 * fmod( v, 1 ) ) );
    } else if( v < 1000 ) {
        SNPRINTF_S( buf1, sizeof( buf1 ), _TRUNCATE, " %3d",
            (int)floor(v) );
    } else {
        SNPRINTF_S( buf1, sizeof( buf1 ), _TRUNCATE, "%4d",
            (int)floor(v) );
    }

    //SNPRINTF_S( buf1, sizeof( buf1 ), _TRUNCATE, "%4f", v );

    res = buf1;
    res += " kMGTPEZ"[s];

    return " " + res;
}

VOID
iprint( const char *format, ...)
{
    va_list vl;
    int res;

    va_start( vl, format );

    res = VSNPRINTF_S( &Output[OutputOffset], MAX_OUTPUT_SIZE - OutputOffset, _TRUNCATE, format, vl );

    CHECK( res >= 0 , "WHOA!!!" );

    OutputOffset += res;
    printOutput( 0 );
}

VOID
dprint( const char * format, ... )
{
#if 0
    va_list vl;
    int res;

    va_start( vl, format );

    res = _vsnprintf_s( &Output[OutputOffset], MAX_OUTPUT_SIZE - OutputOffset, _TRUNCATE, format, vl );

    CHECK( res >= 0 , "WHOA!!!" );

    OutputOffset += res;
    printOutput( 0 );
#else
    UNREFERENCED_PARAMETER( format );
#endif
}

VOID printOutput( int delayMilliSeconds )
{
    Output[MAX_OUTPUT_SIZE-1] = 0;
    fputs( Output, stdout );
    OutputOffset = 0;
    Output[0] = 0;
    SLEEP( delayMilliSeconds );
}

VOID
vprint(BOOL bPrint, const char *format, ...)
{
    va_list vl;
    int res;

    if (bPrint)
    {
        va_start( vl, format );

        res = VSNPRINTF_S( &Output[OutputOffset], MAX_OUTPUT_SIZE - OutputOffset, _TRUNCATE, format, vl );

        CHECK( res >= 0 , "WHOA!!!" );

        OutputOffset += res;
        printOutput( 0 );
    }
}