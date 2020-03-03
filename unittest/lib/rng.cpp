//
// rng.cpp Implementation of test RNG
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//
// THIS IS NOT A CRYPTOGRAPHIC RNG.
// We use it only to generate pseudo-random test cases.
//

#include "precomp.h"

Rng::Rng()
{
    m_blockCtr = (ULONGLONG) -1;
    m_bytesInBuf = 0;
}

Rng::~Rng()
{
    SECUREZEROMEMORY( m_seed, sizeof( m_seed ) );
    SECUREZEROMEMORY( m_buf, sizeof( m_buf ) );
}

VOID Rng::reset( PCBYTE pbData, SIZE_T cbData )
{
    SymCryptSha1( pbData, cbData, m_seed );
    m_blockCtr = 0;
    m_bytesInBuf = 0;
}

BYTE Rng::byte()
{
    CHECK( m_blockCtr != -1, "Use of unseeded Rng object" );

    if( m_bytesInBuf == 0 )
    {
        SYMCRYPT_SHA1_STATE sha1;

        SymCryptSha1Init( &sha1 );
        SymCryptSha1Append( &sha1, m_seed, sizeof( m_seed ) );
        SymCryptSha1Append( &sha1, (PBYTE)&m_blockCtr, sizeof( m_blockCtr ) );
        SymCryptSha1Result( &sha1, m_buf );
        ++m_blockCtr;
        m_bytesInBuf = SYMCRYPT_SHA1_RESULT_SIZE;
    }

    BYTE res = m_buf[ SYMCRYPT_SHA1_RESULT_SIZE - m_bytesInBuf ];
    --m_bytesInBuf;
    return res;
}

UINT32 Rng::uint32()
{
    CHECK( m_blockCtr != -1, "Use of unseeded Rng object" );

    if( m_bytesInBuf < 4 )
    {
        SYMCRYPT_SHA1_STATE sha1;

        SymCryptSha1Init( &sha1 );
        SymCryptSha1Append( &sha1, m_seed, sizeof( m_seed ) );
        SymCryptSha1Append( &sha1, (PBYTE)&m_blockCtr, sizeof( m_blockCtr ) );
        SymCryptSha1Result( &sha1, m_buf );
        ++m_blockCtr;
        m_bytesInBuf = SYMCRYPT_SHA1_RESULT_SIZE;
    }

    UINT32 res = *(UINT32 *)&m_buf[ SYMCRYPT_SHA1_RESULT_SIZE - m_bytesInBuf ];
    m_bytesInBuf -= 4;
    return res;
}

_Ret_range_( min, upb-1 )
SIZE_T 
Rng::sizet( SIZE_T min, SIZE_T upb )
{
    CHECK( upb >= min, "Can't generate random value in empty range" );
    return min + sizet( upb - min );
}

_Ret_range_( 0, upb-1 )
SIZE_T 
Rng::sizet( SIZE_T upb )
{
    ULONG msBit;
    CHECK( BitScanReverseSizeT( &msBit, upb ), "Can't generate random value in empty range" );

    //
    // Convert to mask without causing overflow
    //
    SIZE_T mask = ((SIZE_T)1 << msBit);
    mask |= mask - 1;
    
    ULONG nBytes = (msBit + 8)/8;
    SIZE_T val;
    for(;;)
    {
        val = 0;
        for( ULONG i=0; i<nBytes; i++ )
        {
            val = (val << 8) | byte();
        }
        val &= mask;
        if( val < upb )
        {
            break;
        }
    }
    return val;
}

_Ret_range_( 0, upb-1 )
SIZE_T 
Rng::sizetNonUniform( SIZE_T upb, SIZE_T uniformLimit, ULONG logIncrease )
{
    CHECK(  logIncrease != 0 
                && logIncrease <= 4 
                && upb >> (8*logIncrease) <= uniformLimit,
            "Unsuitable parameters" );
    BYTE prob = byte();
    SIZE_T limit = uniformLimit;
    while( prob & 1 && limit < upb )
    {
        prob >>= 1;
        limit <<= logIncrease;
    }
    limit = SYMCRYPT_MIN( upb, limit );
    return sizet( limit );
}

VOID Rng::randomSubRange( SIZE_T bufSize, SIZE_T * pStart, SIZE_T * pLen )
{
    SIZE_T a = sizet( bufSize );
    SIZE_T b = sizet( bufSize );
    *pStart = SYMCRYPT_MIN( a, b );
    *pLen = SYMCRYPT_MAX( a, b ) - SYMCRYPT_MIN( a, b);
}

