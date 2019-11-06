//
// CAPI implementation classes
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"

#if INCLUDE_IMPL_CAPI

HCRYPTPROV g_capiProvider;

char * ImpCapi::name = "Capi";

#define CAPI_CALG( x )   CONCAT2( CALG_, x )

#define CAPI_MODE( x )  CONCAT2( CRYPT_MODE_, x )

#define CALG_SHA256 CALG_SHA_256
#define CALG_SHA384 CALG_SHA_384
#define CALG_SHA512 CALG_SHA_512    

//
// We map the HMAC CALGs to the hash CALGs due to the way the CAPI interface works.
//
#define CALG_HMAC_MD5       CALG_MD5
#define CALG_HMAC_SHA1      CALG_SHA1
#define CALG_HMAC_SHA256    CALG_SHA256
#define CALG_HMAC_SHA384    CALG_SHA384
#define CALG_HMAC_SHA512    CALG_SHA512

#define IMP_NAME    CAPI
#define IMP_Name    Capi

#define ALG_NAME    MD2
#define ALG_Name    Md2
#include "capi_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    MD4
#define ALG_Name    Md4
#include "capi_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    MD5
#define ALG_Name    Md5
#include "capi_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    SHA1
#define ALG_Name    Sha1
#include "capi_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    SHA256
#define ALG_Name    Sha256
#include "capi_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    SHA384
#define ALG_Name    Sha384
#include "capi_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    SHA512
#define ALG_Name    Sha512
#include "capi_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name


#define ALG_NAME    HMAC_MD5
#define ALG_Name    HmacMd5
#include "capi_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    HMAC_SHA1
#define ALG_Name    HmacSha1
#include "capi_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    HMAC_SHA256
#define ALG_Name    HmacSha256
#include "capi_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    HMAC_SHA384
#define ALG_Name    HmacSha384
#include "capi_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    HMAC_SHA512
#define ALG_Name    HmacSha512
#include "capi_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name


template<class Algorithm>
VOID
CapiSetCalgArray( ULONG * calg );

template<class Algorithm>
NTSTATUS
CapiRc2KeySupport( HCRYPTKEY hKey );


VOID
CapiSetCalgArray( _Inout_updates_( CAPI_CALG_ARRAY_SIZE )ULONG * calg )
{
    for( int i=0; i< CAPI_CALG_ARRAY_SIZE; i++ )
    {
        calg[i] = (ULONG)-1;
    }
    return;
}

template<>
VOID
CapiSetCalgArray<AlgAes>( _Inout_updates_( CAPI_CALG_ARRAY_SIZE )ULONG * calg )
{
    CapiSetCalgArray( calg );
    calg[16] = CALG_AES_128;
    calg[24] = CALG_AES_192;
    calg[32] = CALG_AES_256;
}

template<>
VOID
CapiSetCalgArray<AlgDes>( _Inout_updates_( CAPI_CALG_ARRAY_SIZE )ULONG * calg )
{
    CapiSetCalgArray( calg );
    calg[8] = CALG_DES;
}

template<>
VOID
CapiSetCalgArray<Alg2Des>( _Inout_updates_( CAPI_CALG_ARRAY_SIZE )ULONG * calg )
{
    CapiSetCalgArray( calg );
    calg[16] = CALG_3DES_112;
       
}

template<>
VOID
CapiSetCalgArray<Alg3Des>( _Inout_updates_( CAPI_CALG_ARRAY_SIZE )ULONG * calg )
{
    CapiSetCalgArray( calg );
    calg[24] = CALG_3DES;
       
}

template<>
VOID
CapiSetCalgArray<AlgDesx>( _Inout_updates_( CAPI_CALG_ARRAY_SIZE )ULONG * calg )
{
    CapiSetCalgArray( calg );
    calg[24] = CALG_DESX;
}

template<>
VOID
CapiSetCalgArray<AlgRc2>( _Inout_updates_( CAPI_CALG_ARRAY_SIZE ) ULONG * calg )
{
    CapiSetCalgArray( calg );
    for( int i=5; i<=16; i++ )
    {
        calg[i] = CALG_RC2;
    }
}

template<>
NTSTATUS
CapiRc2KeySupport<AlgRc2>( HCRYPTKEY hKey )
{
    NTSTATUS status = STATUS_SUCCESS;

    if( g_rc2EffectiveKeyLength != 0 )
    {
        status = CryptSetKeyParam( hKey, KP_EFFECTIVE_KEYLEN, (PBYTE) &g_rc2EffectiveKeyLength, 0 );
    }
    return status;
}

template<class Algorithm>
NTSTATUS
CapiRc2KeySupport( HCRYPTKEY hKey )
{
    UNREFERENCED_PARAMETER( hKey );

    return STATUS_SUCCESS;
};


#define ALG_NAME    AES
#define ALG_Name    Aes

#define ALG_Mode    Ecb
#define ALG_MODE    ECB
#include "capi_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Cbc
#define ALG_MODE    CBC
#include "capi_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Cfb
#define ALG_MODE    CFB
#include "capi_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#undef ALG_Name
#undef ALG_NAME

#define ALG_NAME    DES
#define ALG_Name    Des

#define ALG_Mode    Ecb
#define ALG_MODE    ECB
#include "capi_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Cbc
#define ALG_MODE    CBC
#include "capi_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Cfb
#define ALG_MODE    CFB
#include "capi_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#undef ALG_Name
#undef ALG_NAME


#define ALG_NAME    2DES
#define ALG_Name    2Des

#define ALG_Mode    Ecb
#define ALG_MODE    ECB
#include "capi_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Cbc
#define ALG_MODE    CBC
#include "capi_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Cfb
#define ALG_MODE    CFB
#include "capi_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#undef ALG_Name
#undef ALG_NAME


#define ALG_NAME    3DES
#define ALG_Name    3Des

#define ALG_Mode    Ecb
#define ALG_MODE    ECB
#include "capi_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Cbc
#define ALG_MODE    CBC
#include "capi_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Cfb
#define ALG_MODE    CFB
#include "capi_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#undef ALG_Name
#undef ALG_NAME

#define ALG_NAME    RC2
#define ALG_Name    Rc2

#define ALG_Mode    Ecb
#define ALG_MODE    ECB
#include "capi_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Cbc
#define ALG_MODE    CBC
#include "capi_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#define ALG_Mode    Cfb
#define ALG_MODE    CFB
#include "capi_imp_blockcipherpattern.cpp"
#undef ALG_MODE
#undef ALG_Mode

#undef ALG_Name
#undef ALG_NAME



#undef IMP_NAME
#undef IMP_Name




//////////////////////////
// RC4


template<>
VOID 
algImpKeyPerfFunction< ImpCapi, AlgRc4>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    HCRYPTKEY hKey;
    struct {
        BLOBHEADER header;
        DWORD      klen;
        BYTE       key[CAPI_MAX_KEY_SIZE];
    } capiKeyBlob;

    SYMCRYPT_ASSERT( keySize <= CAPI_MAX_KEY_SIZE );

    capiKeyBlob.header.bType = PLAINTEXTKEYBLOB;
    capiKeyBlob.header.bVersion = CUR_BLOB_VERSION;
    capiKeyBlob.header.reserved = 0;
    capiKeyBlob.klen = (ULONG) keySize;
    
    capiKeyBlob.header.aiKeyAlg = CALG_RC4;
    
    memcpy( &capiKeyBlob.key[0], buf2, keySize );

    CHECK( CryptImportKey( g_capiProvider, (PBYTE) &capiKeyBlob, sizeof( capiKeyBlob ), 0, 0, &hKey ),
        "CAPI key import failure" );

    *(HCRYPTKEY *) buf1 = hKey;
    
}

template<>
VOID
algImpDataPerfFunction<ImpCapi,AlgRc4>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );

    ULONG len = (ULONG) dataSize;
    CHECK( CryptEncrypt( *(HCRYPTKEY*) buf1, 0, FALSE, 0, buf3, &len, len ), "Encryption failure" );
}

template<>
VOID
algImpCleanPerfFunction<ImpCapi,AlgRc4>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    CHECK( CryptDestroyKey( *(HCRYPTKEY *) buf1 ), "Failed to destroy key" );
}


StreamCipherImp<ImpCapi, AlgRc4>::StreamCipherImp()
{
    state.hKey = 0;
    
    m_perfKeyFunction     = &algImpKeyPerfFunction    <ImpCapi, AlgRc4>;
    m_perfCleanFunction   = &algImpCleanPerfFunction  <ImpCapi, AlgRc4>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpCapi, AlgRc4>;
}

template<>
StreamCipherImp<ImpCapi, AlgRc4>::~StreamCipherImp()
{
    if( state.hKey != 0 )
    {
        CryptDestroyKey( state.hKey );
        state.hKey = 0;
    }
}

template<>
std::set<SIZE_T> StreamCipherImp<ImpCapi, AlgRc4>::getNonceSizes()
{
    std::set<SIZE_T> res;

    // No nonce sizes supported for RC4

    return res;
}

template<>
std::set<SIZE_T> StreamCipherImp<ImpCapi, AlgRc4>::getKeySizes()
{
    std::set<SIZE_T> res;

    // CAPI supports key sizes 5-16
    for( SIZE_T i=5; i<=16; i++ )
    {
        res.insert( i );
    }

    return res;
}

template<>
NTSTATUS
StreamCipherImp<ImpCapi, AlgRc4>::setNonce( PCBYTE pbNonce, SIZE_T cbNonce )
{
    UNREFERENCED_PARAMETER( pbNonce );

    CHECK( cbNonce == 0, "RC4 does not take a nonce" );

    return STATUS_SUCCESS;
}

template<>
VOID
StreamCipherImp< ImpCapi, AlgRc4>::setOffset( UINT64 offset )
{
    UNREFERENCED_PARAMETER( offset );
    CHECK( FALSE, "RC4 is not random access" );
}

template<>
NTSTATUS
StreamCipherImp<ImpCapi, AlgRc4>::setKey( PCBYTE pbKey, SIZE_T cbKey )
{
    if( state.hKey != 0 )
    {
        CHECK( CryptDestroyKey( state.hKey ), "?" );
        state.hKey = 0;
    }

    if( cbKey <= 5 || cbKey > 16 )
    {
        //
        // Capi doesn't handle RC4 keys of < 5 bytes or > 16 bytes.
        // Also, it pads 5-byte keys internally, so it isn't compatible with proper RC4.
        //
        return STATUS_NOT_SUPPORTED;
    }

    struct {
        BLOBHEADER header;
        DWORD      klen;
        BYTE       key[CAPI_MAX_KEY_SIZE];
    } capiKeyBlob;

    capiKeyBlob.header.bType = PLAINTEXTKEYBLOB;
    capiKeyBlob.header.bVersion = CUR_BLOB_VERSION;
    capiKeyBlob.header.reserved = 0;
    capiKeyBlob.klen = (ULONG) cbKey;
    
    capiKeyBlob.header.aiKeyAlg = CALG_RC4;
    
    CHECK( cbKey < sizeof( capiKeyBlob.key ), "Key too large for CAPI blob" );
    memcpy( &capiKeyBlob.key[0], pbKey, cbKey );

    CHECK3( CryptImportKey( g_capiProvider, (PBYTE) &capiKeyBlob, sizeof( capiKeyBlob ), 0, 0, &state.hKey ),
        "CAPI key import failure %08x", GetLastError() );

    return STATUS_SUCCESS;
}

template<>
VOID
StreamCipherImp<ImpCapi, AlgRc4>::encrypt( PCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData )
{

    ULONG len;

    memcpy( pbDst, pbSrc, cbData );
    
    len = (ULONG) cbData;
    CHECK( CryptEncrypt( state.hKey, 0, FALSE, 0, pbDst, &len, len ), "Encryption failure" );
}

VOID
addCapiAlgs()
{
    CHECK( CryptAcquireContext( &g_capiProvider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT ), "Could not acquire CAPI provider" );

    addImplementationToGlobalList<HashImp<ImpCapi, AlgMd2>>();
    addImplementationToGlobalList<HashImp<ImpCapi, AlgMd4>>();
    addImplementationToGlobalList<HashImp<ImpCapi, AlgMd5>>();
    addImplementationToGlobalList<HashImp<ImpCapi, AlgSha1>>();
    addImplementationToGlobalList<HashImp<ImpCapi, AlgSha256>>();
    addImplementationToGlobalList<HashImp<ImpCapi, AlgSha384>>();
    addImplementationToGlobalList<HashImp<ImpCapi, AlgSha512>>();

    addImplementationToGlobalList<MacImp<ImpCapi, AlgHmacMd5>>();
    addImplementationToGlobalList<MacImp<ImpCapi, AlgHmacSha1>>();
    addImplementationToGlobalList<MacImp<ImpCapi, AlgHmacSha256>>();
    addImplementationToGlobalList<MacImp<ImpCapi, AlgHmacSha384>>();
    addImplementationToGlobalList<MacImp<ImpCapi, AlgHmacSha512>>();

    addImplementationToGlobalList<BlockCipherImp<ImpCapi, AlgAes, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCapi, AlgAes, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCapi, AlgAes, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCapi, AlgDes, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCapi, AlgDes, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCapi, AlgDes, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCapi, Alg2Des, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCapi, Alg2Des, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCapi, Alg2Des, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCapi, Alg3Des, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCapi, Alg3Des, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCapi, Alg3Des, ModeCfb>>();
    // CAPI does not support DESX
    addImplementationToGlobalList<BlockCipherImp<ImpCapi, AlgRc2, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCapi, AlgRc2, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpCapi, AlgRc2, ModeCfb>>();

    addImplementationToGlobalList<StreamCipherImp<ImpCapi, AlgRc4>>();
}

#endif //INCLUDE_IMPL_CAPI







