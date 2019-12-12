//
// TestTlsCbcHmac.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

#define MAX_TLS_RECORD_LEN  (1<<14)

class TlsCbcHmacMultiImp: public TlsCbcHmacImplementation
{
public:
    TlsCbcHmacMultiImp( String algName );
    ~TlsCbcHmacMultiImp();

private:
    TlsCbcHmacMultiImp( const TlsCbcHmacMultiImp & );
    VOID operator=( const TlsCbcHmacMultiImp & );

public:

    typedef std::vector<TlsCbcHmacImplementation *> TlsCbcHmacImpPtrVector;

    TlsCbcHmacImpPtrVector m_imps;                    // Implementations we use

    virtual NTSTATUS verify(
        _In_reads_( cbKey )     PCBYTE  pbKey,
                                SIZE_T  cbKey,
        _In_reads_( cbHeader )  PCBYTE  pbHeader,
                                SIZE_T  cbHeader,
        _In_reads_( cbData )    PCBYTE  pbData,
                                SIZE_T  cbData );

};

TlsCbcHmacMultiImp::TlsCbcHmacMultiImp( String algName )
{
    getAllImplementations<TlsCbcHmacImplementation>( algName, &m_imps );
    m_algorithmName = algName;

    String sumImpName;
    char * sepStr = "<";

    for( TlsCbcHmacImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        sumImpName += sepStr + (*i)->m_implementationName;
        sepStr = "+";
    }
    m_implementationName = sumImpName + ">";
}

TlsCbcHmacMultiImp::~TlsCbcHmacMultiImp()
{
    //
    // Propagate the # KAT failures to the individual algorithms.
    //
    for( TlsCbcHmacImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        (*i)->m_nErrorKatFailure += m_nErrorKatFailure;
    }
}


NTSTATUS
TlsCbcHmacMultiImp::verify(
        _In_reads_( cbKey )     PCBYTE  pbKey,
                                SIZE_T  cbKey,
        _In_reads_( cbHeader )  PCBYTE  pbHeader,
                                SIZE_T  cbHeader,
        _In_reads_( cbData )    PCBYTE  pbData,
                                SIZE_T  cbData )
{
    ResultMerge res;
    NTSTATUS status;
    BYTE b;

    for( TlsCbcHmacImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i )
    {
        status = (*i)->verify( pbKey, cbKey, pbHeader, cbHeader, pbData, cbData );
        b = NT_SUCCESS( status ) ? 1 : 0;
        res.addResult( (*i), &b, 1 );
    }

    res.getResult( &b, 1 );

    return b == 0 ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

VOID
testTlsCbcHmacSingle(
    TlsCbcHmacImplementation *  pImp,
    PCSYMCRYPT_MAC              pMac )
{
    BYTE                        header[256];
    BYTE                        key[64];
    BYTE                        buf[ MAX_TLS_RECORD_LEN + 48 + 255 + 1];    // record, HMAC, padding, padding_length
    SYMCRYPT_MAC_EXPANDED_KEY   expandedKey;
    SYMCRYPT_MAC_STATE          state;

    for( int iTest = 0; iTest < 1000; iTest++ )
    {
        SIZE_T headerLen = g_rng.byte();
        SIZE_T recordLen = g_rng.sizetNonUniform( MAX_TLS_RECORD_LEN, 256, 1 );
        BYTE padLen = g_rng.byte();
        SIZE_T macLen;
        SIZE_T totalLen;
        SIZE_T byteLocation;
        BYTE b;

        memset( buf, 0, sizeof( buf ) );        // Easier debugging.
        memset( header, 0, sizeof( header ) );

        if( iTest == 0 )
        {
            // Easy way to specify a consistent test vector when debugging

            headerLen = 0;
            recordLen = 0;
            padLen = 0;
            //iprint( "(%d,%d,%d)", headerLen, recordLen, padLen );

            memset( key, 'K', sizeof( key ) );
            for( SIZE_T i=0; i<headerLen; i++ ) { header[i] = (BYTE)('H' + i); };
            for( SIZE_T i=0; i<recordLen; i++ ) { buf[i] = (BYTE)('d' + i); };
        } else {
            CHECK( NT_SUCCESS( GENRANDOM( key, sizeof( key ) )), "?" );;
            CHECK( NT_SUCCESS( GENRANDOM( header, (UINT32)headerLen )), "?" );;
            CHECK( NT_SUCCESS( GENRANDOM( buf, (UINT32)recordLen )), "?" );
        }

        macLen = pMac->resultSize;
        totalLen = recordLen + macLen + padLen + 1;

        // Now we create the test vector
        (*pMac->expandKeyFunc)( &expandedKey, key, sizeof( key ) );
        (*pMac->initFunc)( &state, &expandedKey );
        (*pMac->appendFunc)( &state, header, headerLen );
        (*pMac->appendFunc)( &state, buf, recordLen );
        (*pMac->resultFunc)( &state, &buf[ recordLen ] );

        memset( &buf[recordLen + macLen], padLen, padLen + 1 );

        CHECK3( NT_SUCCESS(pImp->verify( key, sizeof( key ), header, headerLen, buf, totalLen )), "TlsCbcHmac verify failure %d", iTest );

        // Pick a random byte to mutate, 50% of changes in the padding itself as changing the message or MAC is
        // less interesting to test
        if( (g_rng.byte() & 1) == 0 )
        {
            byteLocation = recordLen + macLen + g_rng.sizet( padLen + 1 );
        } else {
            byteLocation = g_rng.sizet( totalLen );
        }

        // Pick a byte change pattern
        do { b = g_rng.byte(); } while( b == 0 );

        buf[ byteLocation ] ^= b;
        // iprint( "[%d^%02x]", byteLocation, b );

        CHECK( !NT_SUCCESS(pImp->verify( key, sizeof( key ), header, headerLen, buf, totalLen )), "TlsCbcHmac verify success" );
    }
}

VOID
testTlsCbcHmacAlgorithms()
{
    std::unique_ptr<TlsCbcHmacMultiImp> pImp;
       
    char * sep = "    ";
    BOOL doneAnything = FALSE;

    pImp.reset( new TlsCbcHmacMultiImp( "TlsCbcHmacSha1" ) );
    if( pImp->m_imps.size() > 0 )
    {
        iprint( "%s%s", sep, "TlsCbcHmacSha1" );
        sep = ", ";
        doneAnything = TRUE;
        testTlsCbcHmacSingle( pImp.get(), SymCryptHmacSha1Algorithm );
    }

    pImp.reset( new TlsCbcHmacMultiImp( "TlsCbcHmacSha256" ) );
    if( pImp->m_imps.size() > 0 )
    {
        iprint( "%s%s", sep, "TlsCbcHmacSha256" );
        sep = ", ";
        doneAnything = TRUE;
        testTlsCbcHmacSingle( pImp.get(), SymCryptHmacSha256Algorithm );
    }

    pImp.reset( new TlsCbcHmacMultiImp( "TlsCbcHmacSha384" ) );
    if( pImp->m_imps.size() > 0 )
    {
        iprint( "%s%s", sep, "TlsCbcHmacSha384" );
        sep = ", ";
        doneAnything = TRUE;
        testTlsCbcHmacSingle( pImp.get(), SymCryptHmacSha384Algorithm );
    }

    if( doneAnything )
    {
        iprint( "\n" );
    }
}

