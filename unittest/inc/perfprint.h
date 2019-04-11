//
// PerfPrint.h
// Printing output without affecting performance measurements
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//


VOID
print( const char *format, ...);

VOID
print( String s );

VOID
printHex( PCBYTE pbData, SIZE_T cbData );

String
formatNumber( double v );

VOID
iprint( const char *format, ...);

VOID
dprint( const char *format, ...);   // Only prints if #if is modified in source code, used for debugging.

VOID printOutput( int delayMilliSeconds );

VOID
vprint( BOOL bPrint, const char *format, ...);   // Only prints if bPrint == TRUE