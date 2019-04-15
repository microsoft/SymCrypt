//
// Test & performance of wiping
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"

VOID
testWipe()
{
    BYTE    b;
    BYTE    buf[128];
    SIZE_T  i,len,j;

    print( "    wipe" );

    for( len=0; len<sizeof( buf ); len++ )
    {
        for( i=0; i<sizeof( buf ) - len; i++ )
        {
            memset( buf, 'n', sizeof( buf ) );
            SymCryptWipe( &buf[i], len );
            for( j=0; j<sizeof( buf ); j++ )
            {
                b = buf[j];
                if( j<i || j>= i+len ){
                    b ^= 'n';
                }
                CHECK4( b == 0, "SymCryptWipe error len=%d offset=%d", len, i );
            }
            memset( buf, 'n', sizeof( buf ) );
            SymCryptWipeKnownSize( &buf[i], len );
            for( j=0; j<sizeof( buf ); j++ )
            {
                b = buf[j];
                if( j<i || j>= i+len ){
                    b ^= 'n';
                }
                CHECK4( b == 0, "SymCryptWipeKnownSize error len=%d offset=%d", len, i );
            }
        }
    }
    
    print ( "\n" );
}





