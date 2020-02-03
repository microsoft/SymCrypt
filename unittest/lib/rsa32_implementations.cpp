//
// RSA32 implementation classes
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"

#if INCLUDE_IMPL_RSA32



char * ImpRsa32::name = "Rsa32";

char * ImpRsa32b::name = "Rsa32b";


#define RSA32_2DES_BLOCK_SIZE    RSA32_DES_BLOCK_SIZE
#define RSA32_DESX_BLOCK_SIZE    RSA32_DES_BLOCK_SIZE

#define IMP_NAME    RSA32
#define IMP_Name    Rsa32

#define ALG_NAME   MD2
#define ALG_Name   Md2
#include "rsa32_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME   MD4
#define ALG_Name   Md4
#include "rsa32_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME   MD5
#define ALG_Name   Md5
#include "rsa32_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME   SHA1
#define ALG_Name   Sha1
#include "rsa32_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME   SHA256
#define ALG_Name   Sha256
#include "rsa32_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME   SHA384
#define ALG_Name   Sha384
#include "rsa32_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME   SHA512
#define ALG_Name   Sha512
#include "rsa32_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name



#define ALG_NAME    HMAC_SHA1
#define ALG_Name    HmacSha1
#include "rsa32_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name


#define ALG_NAME    HMAC_MD5
#define ALG_Name    HmacMd5
#include "rsa32_imp_macpattern.cpp"
#undef ALG_NAME
#undef ALG_Name



#define ALG_NAME    AES
#define ALG_Name    Aes

#define ALG_Mode    Ecb
#include "rsa32_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cbc
#include "rsa32_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#undef ALG_NAME
#undef ALG_Name


#define ALG_NAME    DES
#define ALG_Name    Des

#define ALG_Mode    Ecb
#include "rsa32_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cbc
#include "rsa32_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cfb
#include "rsa32_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#undef ALG_NAME
#undef ALG_Name


#define ALG_NAME    2DES
#define ALG_Name    2Des

#define ALG_Mode    Ecb
#include "rsa32_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cbc
#include "rsa32_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cfb
#include "rsa32_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    3DES
#define ALG_Name    3Des

#define ALG_Mode    Ecb
#include "rsa32_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cbc
#include "rsa32_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cfb
#include "rsa32_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    DESX
#define ALG_Name    Desx

#define ALG_Mode    Ecb
#include "rsa32_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cbc
#include "rsa32_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cfb
#include "rsa32_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#undef ALG_NAME
#undef ALG_Name


#define ALG_NAME    RC2
#define ALG_Name    Rc2

#define ALG_Mode    Ecb
#include "rsa32_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cbc
#include "rsa32_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cfb
#include "rsa32_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#undef ALG_NAME
#undef ALG_Name






#undef IMP_NAME         // RSA32
#undef IMP_Name



#define IMP_NAME    RSA32B
#define IMP_Name    Rsa32b

#define ALG_NAME    MD4
#define ALG_Name    Md4
#include "rsa32_imp_hashpattern.cpp"
#undef ALG_NAME
#undef ALG_Name

#define ALG_NAME    AES
#define ALG_Name    Aes

#define ALG_Mode Ecb
#include "rsa32_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cbc
#include "rsa32_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#define ALG_Mode    Cfb
#include "rsa32_imp_blockcipherpattern.cpp"
#undef ALG_Mode

#undef ALG_NAME
#undef ALG_Name


#undef IMP_NAME
#undef IMP_Name



VOID
CFBAnyLen(
         void   RSA32API Cipher(UCHAR *, UCHAR *, void *, int),
         ULONG  dwBlockLen,
         UCHAR   *output,
         UCHAR   *input,
         void   *keyTable,
         int    op,
         UCHAR   *feedback,
         SIZE_T cbData
         )
{
    BYTE    buf[32];
    BYTE    oldFeedback[32];
    SIZE_T todo = dwBlockLen;

    while( cbData > 0 )
    {
        todo = SYMCRYPT_MIN( cbData, dwBlockLen );
        memcpy( buf, input, todo );
        memcpy( oldFeedback, feedback, dwBlockLen );
        CFB( Cipher, dwBlockLen, buf, buf, keyTable, op, feedback );
        memcpy( output, buf, todo );
        input += todo;
        output += todo;
        cbData -= todo;
    }
    if( todo < dwBlockLen )
    {
        memmove( feedback + dwBlockLen - todo, feedback, todo );
        memcpy( feedback, oldFeedback + todo, dwBlockLen - todo );
    }
}




VOID 
HashImp<ImpRsa32,AlgMd2>::init( )
{
    memset( &state.ctx, 0, sizeof( state.ctx ) );
}

VOID
HashImp<ImpRsa32,AlgMd2>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    MD2Update( &state.ctx, (PBYTE) pbData, (ULONG) cbData );
}

VOID
HashImp<ImpRsa32,AlgMd2>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    CHECK( cbResult == 16, "Wrong len in RSA32 MD2 result" );
    MD2Final( &state.ctx );
    memcpy( pbResult, &state.ctx.state, 16 );
}


NTSTATUS
HashImp<ImpRsa32, AlgMd2>::initWithLongMessage( ULONGLONG nBytes )
{
    UNREFERENCED_PARAMETER( nBytes );

    memset( &state.ctx, 'b', sizeof( state.ctx ) );
    state.ctx.count = 0;
    return STATUS_SUCCESS;
}

VOID
algImpDataPerfFunction<ImpRsa32,AlgMd2>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf3 );

    MD2_CTX ctx;
    memset( &ctx, 0, sizeof( ctx ) );
    MD2Update( &ctx, buf1, (ULONG) dataSize );
    MD2Final( &ctx );
    memcpy( buf2, &ctx.state, 16 );

}


VOID
HashImp<ImpRsa32, AlgMd4>::init()
{
    MD4Init( &state.ctx );
}

VOID
HashImp<ImpRsa32, AlgMd4>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    MD4Update( &state.ctx, (PBYTE) pbData, (ULONG) cbData );
}

VOID
HashImp<ImpRsa32, AlgMd4>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    CHECK( cbResult == 16, "Wrong len in RSA32 MD4 result" );
    MD4Final( &state.ctx );
    memcpy( pbResult, state.ctx.digest, cbResult );
}

NTSTATUS
HashImp<ImpRsa32, AlgMd4>::initWithLongMessage( ULONGLONG nBytes )
{
    memset( &state.ctx, 'b', sizeof( state.ctx ) );
    state.ctx.count[0] = (ULONG) (nBytes * 8);
    state.ctx.count[1] = (ULONG) (nBytes >> 29);
    return STATUS_SUCCESS;
}

VOID
algImpDataPerfFunction<ImpRsa32,AlgMd4>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf3 );

    MD4_CTX ctx;
    
    MD4Init( &ctx );
    MD4Update( &ctx, buf1, (ULONG) dataSize );
    MD4Final( &ctx );
    memcpy( buf2, &ctx.digest, 16 );
}


VOID
HashImp<ImpRsa32b, AlgMd4>::init()
{
    state.bytesInBuf = 0;
    MDbegin( &state.md4 );
}

VOID
HashImp<ImpRsa32b, AlgMd4>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    while( cbData )
    {
        state.buf[state.bytesInBuf++] = *pbData++;
        cbData--;
        if( state.bytesInBuf == RSA32B_MD4_INPUT_BLOCK_SIZE )
        {
            CHECK( MDupdate( &state.md4, &state.buf[0], MD4BYTESTOBITS( MD4BLOCKSIZE ) ) == MD4_SUCCESS,
                "Failure in old RSA32 MD4 update function" );
            state.bytesInBuf = 0;
        }
    }
}

VOID
HashImp<ImpRsa32b, AlgMd4>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    CHECK( cbResult == 16, "Wrong result len in RSA32B MD4" );
    CHECK( MDupdate( &state.md4, &state.buf[0], MD4BYTESTOBITS( (ULONG) state.bytesInBuf ) ) == MD4_SUCCESS,
        "Failure in old RSA32 MD4 final update" );
    memcpy( pbResult, &state.md4, MD4DIGESTLEN );
}

NTSTATUS
HashImp<ImpRsa32b, AlgMd4>::initWithLongMessage( ULONGLONG nBytes )
{
    memset( &state.md4, 'b', sizeof( state.md4 ) );
    ((unsigned int *)state.md4.count)[0] = (ULONG) (nBytes * 8);
    ((unsigned int *)state.md4.count)[1] = (ULONG) (nBytes >> 29);
    state.md4.done = 0;
    state.bytesInBuf = 0;
    return STATUS_SUCCESS;
}

VOID
algImpDataPerfFunction<ImpRsa32b,AlgMd4>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf3 );

    MDstruct md;

    MDbegin( &md );
    while( dataSize >= MD4BLOCKSIZE )
    {
        MDupdate( &md, buf1, MD4BYTESTOBITS( MD4BLOCKSIZE ) );
        buf1 += MD4BLOCKSIZE;
        dataSize -= MD4BLOCKSIZE;
    }
    MDupdate( &md, buf1, MD4BYTESTOBITS( (ULONG) dataSize ) );
    memcpy( buf2, &md, MD4DIGESTLEN );
}


VOID
HashImp<ImpRsa32, AlgMd5>::init()
{
    MD5Init( &state.ctx );
}

VOID
HashImp<ImpRsa32, AlgMd5>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    MD5Update( &state.ctx, (PBYTE) pbData, (ULONG) cbData );
}

VOID
HashImp<ImpRsa32, AlgMd5>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    CHECK( cbResult == 16, "Wrong len in RSA32 MD5 result" );
    MD5Final( &state.ctx );
    memcpy( pbResult, state.ctx.digest, cbResult );
}

NTSTATUS
HashImp<ImpRsa32, AlgMd5>::initWithLongMessage( ULONGLONG nBytes )
{
    memset( &state.ctx, 'b', sizeof( state.ctx ) );
    state.ctx.i[0] = (ULONG) (nBytes * 8);
    state.ctx.i[1] = (ULONG) (nBytes >> 29);
    return STATUS_SUCCESS;
}

VOID
algImpDataPerfFunction<ImpRsa32,AlgMd5>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf3 );

    MD5_CTX ctx;

    MD5Init( &ctx );
    MD5Update( &ctx, buf1, (ULONG) dataSize );
    MD5Final( &ctx );
    memcpy( buf2, ctx.digest, RSA32_MD5_RESULT_SIZE );
}


VOID
HashImp<ImpRsa32, AlgSha1>::init()
{
    A_SHAInit( &state.ctx );
}

VOID
HashImp<ImpRsa32, AlgSha1>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    A_SHAUpdate( &state.ctx, (PBYTE) pbData, (ULONG) cbData );
}

VOID
HashImp<ImpRsa32, AlgSha1>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    CHECK( cbResult == 20, "Wrong len in RSA32 SHA1 result" );
    A_SHAFinal( &state.ctx, pbResult );
}

NTSTATUS
HashImp<ImpRsa32, AlgSha1>::initWithLongMessage( ULONGLONG nBytes )
{
    memset( &state.ctx, 'b', sizeof( state.ctx ) );
    state.ctx.count[1] = (ULONG) (nBytes );
    state.ctx.count[0] = (ULONG) (nBytes >> 32);
    return STATUS_SUCCESS;
}

VOID
algImpDataPerfFunction<ImpRsa32,AlgSha1>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf3 );

    A_SHA_CTX   ctx;
    
    A_SHAInit( &ctx );
    A_SHAUpdate( &ctx, buf1, (ULONG) dataSize );
    A_SHAFinal( &ctx, buf2 );
}


VOID
HashImp<ImpRsa32, AlgSha256>::init()
{
    SHA256Init( &state.ctx );
}

VOID
HashImp<ImpRsa32, AlgSha256>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    SHA256Update( &state.ctx, (PBYTE) pbData, (ULONG) cbData );
}

VOID
HashImp<ImpRsa32, AlgSha256>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    CHECK( cbResult == 32, "Wrong len in RSA32 SHA256 result" );
    SHA256Final( &state.ctx, pbResult );
}

NTSTATUS
HashImp<ImpRsa32, AlgSha256>::initWithLongMessage( ULONGLONG nBytes )
{
    memset( &state.ctx, 'b', sizeof( state.ctx ) );
    state.ctx.count[1] = (ULONG) nBytes;
    state.ctx.count[0] = (ULONG) (nBytes >> 32);
    return STATUS_SUCCESS;
}

VOID
algImpDataPerfFunction<ImpRsa32,AlgSha256>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf3 );

    SHA256_CTX   ctx;
    
    SHA256Init( &ctx );
    SHA256Update( &ctx, buf1, (ULONG) dataSize );
    SHA256Final( &ctx, buf2 );
}



VOID
HashImp<ImpRsa32, AlgSha384>::init()
{
    SHA384Init( &state.ctx );
}

VOID
HashImp<ImpRsa32, AlgSha384>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    SHA384Update( &state.ctx, (PBYTE) pbData, (ULONG) cbData );
}

VOID
HashImp<ImpRsa32, AlgSha384>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    CHECK( cbResult == 48, "Wrong len in RSA32 SHA384 result" );
    SHA384Final( &state.ctx, pbResult );
}

NTSTATUS
HashImp<ImpRsa32, AlgSha384>::initWithLongMessage( ULONGLONG nBytes )
{
    memset( &state.ctx, 'b', sizeof( state.ctx ) );
    state.ctx.count[1] = nBytes;
    state.ctx.count[0] = 0;
    return STATUS_SUCCESS;
}

VOID
algImpDataPerfFunction<ImpRsa32,AlgSha384>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf3 );

    SHA384_CTX   ctx;
    
    SHA384Init( &ctx );
    SHA384Update( &ctx, buf1, (ULONG) dataSize );
    SHA384Final( &ctx, buf2 );
}


VOID
HashImp<ImpRsa32, AlgSha512>::init()
{
    SHA512Init( &state.ctx );
}

VOID
HashImp<ImpRsa32, AlgSha512>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    SHA512Update( &state.ctx, (PBYTE) pbData, (ULONG) cbData );
}

VOID
HashImp<ImpRsa32, AlgSha512>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    CHECK( cbResult == 64, "Wrong len in RSA32 SHA512 result" );
    SHA512Final( &state.ctx, pbResult );
}

NTSTATUS
HashImp<ImpRsa32, AlgSha512>::initWithLongMessage( ULONGLONG nBytes )
{
    memset( &state.ctx, 'b', sizeof( state.ctx ) );
    state.ctx.count[1] = nBytes;
    state.ctx.count[0] = 0;
    return STATUS_SUCCESS;
}

VOID
algImpDataPerfFunction<ImpRsa32,AlgSha512>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf3 );

    SHA512_CTX   ctx;
    
    SHA512Init( &ctx );
    SHA512Update( &ctx, buf1, (ULONG) dataSize );
    SHA512Final( &ctx, buf2 );
}




NTSTATUS
MacImp<ImpRsa32,AlgHmacMd5>::init( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    if( cbKey > 64 )
    {
        return STATUS_NOT_SUPPORTED;
    }
    HMACMD5Init( &state.keyCtx, (PBYTE) pbKey, (ULONG) cbKey );
    state.macCtx = state.keyCtx;
    return STATUS_SUCCESS;
}

VOID
MacImp<ImpRsa32,AlgHmacMd5>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    HMACMD5Update( &state.macCtx, (PBYTE) pbData, (ULONG) cbData );
};

VOID
MacImp<ImpRsa32,AlgHmacMd5>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    CHECK( cbResult == 16, "Wrong len in RSA32 HmacMd5 result" );
    HMACMD5Final( &state.macCtx, pbResult );
}

VOID
algImpKeyPerfFunction<ImpRsa32,AlgHmacMd5>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf2 );

    HMACMD5Init( (HMACMD5_CTX *)buf1, buf3, (ULONG)keySize );
}

VOID
algImpDataPerfFunction<ImpRsa32,AlgHmacMd5>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    memcpy( buf2, buf1, sizeof( HMACMD5_CTX ) );
    HMACMD5Update( (HMACMD5_CTX *) buf2, buf3, (ULONG)dataSize );
    HMACMD5Final( (HMACMD5_CTX *) buf2, buf3 );
}

VOID algImpCleanPerfFunction<ImpRsa32,AlgHmacMd5>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( buf2 );

    RtlSecureZeroMemory( buf1, sizeof( HMACMD5_CTX ) );
}

NTSTATUS
MacImp<ImpRsa32,AlgHmacSha1>::init( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    HMACSHAInit( &state.keyCtx, (PBYTE) pbKey, (ULONG) cbKey );
    state.macCtx = state.keyCtx;
    return STATUS_SUCCESS;
}

VOID
MacImp<ImpRsa32,AlgHmacSha1>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    HMACSHAUpdate( &state.macCtx, (PBYTE) pbData, (ULONG) cbData );
};

VOID
MacImp<ImpRsa32,AlgHmacSha1>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    CHECK( cbResult == 20, "Wrong len in RSA32 HmacSha1 result" );
    HMACSHAFinal( &state.macCtx, pbResult );
}

VOID
algImpKeyPerfFunction<ImpRsa32,AlgHmacSha1>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf2 );

    HMACSHAInit( (HMACSHA_CTX *)buf1, buf3, (ULONG)keySize );
}

VOID
algImpDataPerfFunction<ImpRsa32,AlgHmacSha1>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    memcpy( buf2, buf1, sizeof( HMACSHA_CTX ) );
    HMACSHAUpdate( (HMACSHA_CTX *) buf2, buf3, (ULONG)dataSize );
    HMACSHAFinal( (HMACSHA_CTX *) buf2, buf3 );
}

VOID
algImpCleanPerfFunction<ImpRsa32,AlgHmacSha1>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( buf2 );

    RtlSecureZeroMemory( buf1, sizeof( HMACSHA_CTX ) );
}


NTSTATUS
BlockCipherImp<ImpRsa32,AlgAes,ModeEcb>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 16 || cbKey == 24 || cbKey == 32, "?" );
    
    AesExpandKey( &state.key, pbKey, cbKey );   

    return STATUS_SUCCESS;
}

NTSTATUS
BlockCipherImp<ImpRsa32,AlgAes,ModeCbc>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 16 || cbKey == 24 || cbKey == 32, "?" );
    
    AesExpandKey( &state.key, pbKey, cbKey );   

    return STATUS_SUCCESS;
}

NTSTATUS
BlockCipherImp<ImpRsa32,AlgAes,ModeCfb>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 16 || cbKey == 24 || cbKey == 32, "?" );

    if( g_modeCfbShiftParam != 1 )
    {
        return STATUS_NOT_SUPPORTED;
    }

    AesExpandKey( &state.key, pbKey, cbKey );   

    return STATUS_SUCCESS;
}


VOID
BlockCipherImp<ImpRsa32, AlgAes, ModeEcb>::encrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
 {
    UNREFERENCED_PARAMETER( pbChain );

    CHECK( cbData % RSA32_AES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == 0, "Unneeded chain value" );

    while( cbData > 0 )
    {
        AesEncrypt( &state.key, pbSrc, pbDst );
        pbSrc += RSA32_AES_BLOCK_SIZE;
        pbDst += RSA32_AES_BLOCK_SIZE;
        cbData -= RSA32_AES_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32, AlgAes, ModeCbc>::encrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbData % RSA32_AES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == 16, "Unneeded chain value" );

    memcpy( pbDst, pbSrc, cbData );
    AesCbcEncrypt( &state.key, pbChain, pbDst, cbData );
    if( cbData > 0 )
    {
        memcpy( pbChain, pbDst + cbData - 16, 16 );
    }
}

VOID
BlockCipherImp<ImpRsa32, AlgAes, ModeEcb>::decrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    UNREFERENCED_PARAMETER( pbChain );

    CHECK( cbData % RSA32_AES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == 0, "Unneeded chain value" );

    while( cbData > 0 )
    {
        AesDecrypt( &state.key, pbSrc, pbDst );
        pbSrc += RSA32_AES_BLOCK_SIZE;
        pbDst += RSA32_AES_BLOCK_SIZE;
        cbData -= RSA32_AES_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32, AlgAes, ModeCbc>::decrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbData % RSA32_AES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == 16, "Unneeded chain value" );

    memcpy( pbDst, pbSrc, cbData );
    BYTE    chain[16];
    if( cbData > 0 )
    {
        memcpy( chain, pbDst + cbData - 16, 16 );
        AesCbcDecrypt( &state.key, pbChain, pbDst, cbData );
        memcpy( pbChain, chain, 16 );
    }
}


VOID
algImpKeyPerfFunction<ImpRsa32,AlgAes,ModeEcb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    AesExpandKey( (AES_KEY *)buf1, buf2, keySize );
}

VOID
algImpKeyPerfFunction<ImpRsa32,AlgAes,ModeCbc>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    AesExpandKey( (AES_KEY *)buf1, buf2, keySize );
}

VOID
algImpDataPerfFunction<ImpRsa32,AlgAes,ModeEcb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        AesEncrypt( (AES_KEY *) buf1, buf2, buf3 );
        buf2 += RSA32_AES_BLOCK_SIZE;
        buf3 += RSA32_AES_BLOCK_SIZE;
        dataSize -= RSA32_AES_BLOCK_SIZE;
    }
}

VOID
algImpDataPerfFunction<ImpRsa32,AlgAes,ModeCbc>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    AesCbcEncrypt( (AES_KEY *)buf1, buf2, buf3, dataSize );
}

VOID
algImpDecryptPerfFunction<ImpRsa32,AlgAes,ModeEcb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        AesDecrypt( (AES_KEY *) buf1, buf2, buf3 );
        buf2 += RSA32_AES_BLOCK_SIZE;
        buf3 += RSA32_AES_BLOCK_SIZE;
        dataSize -= RSA32_AES_BLOCK_SIZE;
    }
}

VOID
algImpDecryptPerfFunction<ImpRsa32,AlgAes,ModeCbc>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    AesCbcDecrypt( (AES_KEY *)buf1, buf2, buf3, dataSize );
}

VOID
algImpCleanPerfFunction<ImpRsa32,AlgAes,ModeEcb>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( buf2 );

    RtlSecureZeroMemory( buf1, sizeof( AES_KEY ) );
}

VOID
algImpCleanPerfFunction<ImpRsa32,AlgAes,ModeCbc>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( buf2 );

    RtlSecureZeroMemory( buf1, sizeof( AES_KEY ) );
}




NTSTATUS
BlockCipherImp<ImpRsa32b,AlgAes,ModeEcb>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 16 || cbKey == 24 || cbKey == 32, "?" );
    
    aeskey( &state.key, (PBYTE) pbKey, 6 + (int)cbKey/4 );

    return STATUS_SUCCESS;
}

NTSTATUS
BlockCipherImp<ImpRsa32b,AlgAes,ModeCbc>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 16 || cbKey == 24 || cbKey == 32, "?" );
    
    aeskey( &state.key, (PBYTE) pbKey, 6 + (int)cbKey/4 );

    return STATUS_SUCCESS;
}

NTSTATUS
BlockCipherImp<ImpRsa32b,AlgAes,ModeCfb>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 16 || cbKey == 24 || cbKey == 32, "?" );
    
    if( g_modeCfbShiftParam != 1 )
    {
        return STATUS_NOT_SUPPORTED;
    }

    aeskey( &state.key, (PBYTE) pbKey, 6 + (int)cbKey/4 );

    return STATUS_SUCCESS;
}



VOID
BlockCipherImp<ImpRsa32b, AlgAes,ModeEcb>::encrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    UNREFERENCED_PARAMETER( pbChain );

    SYMCRYPT_ALIGN BYTE buf[RSA32_AES_BLOCK_SIZE];
    
    CHECK( cbData % RSA32_AES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == 0, "Unneeded chain value" );

    while( cbData > 0 )
    {
        //
        // RSA32 requries that plaintext/ciphertext are aligned, though this only leads
        // to errors on IA_64 and possibly ARM.
        //
        memcpy( buf, pbSrc, RSA32_AES_BLOCK_SIZE );
        aes( buf, buf, &state.key, ENCRYPT );
        memcpy( pbDst, buf, RSA32_AES_BLOCK_SIZE );
        pbSrc += RSA32_AES_BLOCK_SIZE;
        pbDst += RSA32_AES_BLOCK_SIZE;
        cbData -= RSA32_AES_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32b, AlgAes,ModeCbc>::encrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbData % RSA32_AES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == 16, "Unneeded chain value" );

    while( cbData > 0 )
    {
        CBC( aes, 16, pbDst, (PBYTE) pbSrc, &state.key, ENCRYPT, pbChain );
        pbSrc += RSA32_AES_BLOCK_SIZE;
        pbDst += RSA32_AES_BLOCK_SIZE;
        cbData -= RSA32_AES_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32b, AlgAes,ModeCfb>::encrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbChain == 16, "Unneeded chain value" );

    CFBAnyLen( aes, 16, pbDst, (PBYTE) pbSrc, &state.key, ENCRYPT, pbChain, cbData );
}


VOID
BlockCipherImp<ImpRsa32b, AlgAes,ModeEcb>::decrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    UNREFERENCED_PARAMETER( pbChain );

    SYMCRYPT_ALIGN BYTE buf[RSA32_AES_BLOCK_SIZE];
        
    CHECK( cbData % RSA32_AES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == 0, "Unneeded chain value" );

    while( cbData > 0 )
    {
        memcpy( buf, pbSrc, RSA32_AES_BLOCK_SIZE );
        aes( buf, buf, &state.key, DECRYPT );
        memcpy( pbDst, buf, RSA32_AES_BLOCK_SIZE );
        pbSrc += RSA32_AES_BLOCK_SIZE;
        pbDst += RSA32_AES_BLOCK_SIZE;
        cbData -= RSA32_AES_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32b, AlgAes,ModeCbc>::decrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbData % RSA32_AES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == 16, "Unneeded chain value" );

    while( cbData > 0 )
    {
        CBC( aes, 16, pbDst, (PBYTE) pbSrc, &state.key, DECRYPT, pbChain );
        pbSrc += RSA32_AES_BLOCK_SIZE;
        pbDst += RSA32_AES_BLOCK_SIZE;
        cbData -= RSA32_AES_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32b, AlgAes,ModeCfb>::decrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbChain == 16, "Unneeded chain value" );

    CFBAnyLen( aes, 16, pbDst, (PBYTE) pbSrc, &state.key, DECRYPT, pbChain, cbData );
}



VOID
algImpKeyPerfFunction<ImpRsa32b,AlgAes,ModeEcb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    aeskey( (AESTable *)buf1, buf2, 6 + (int)keySize/4 );
}

VOID
algImpKeyPerfFunction<ImpRsa32b,AlgAes,ModeCbc>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    aeskey( (AESTable *)buf1, buf2, 6 + (int)keySize/4 );
}

VOID
algImpKeyPerfFunction<ImpRsa32b,AlgAes,ModeCfb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    aeskey( (AESTable *)buf1, buf2, 6 + (int)keySize/4 );
}

VOID
algImpDataPerfFunction<ImpRsa32b,AlgAes,ModeEcb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        aes( buf2, buf3, (AESTable *)buf1, ENCRYPT );
        buf2 += RSA32_AES_BLOCK_SIZE;
        buf3 += RSA32_AES_BLOCK_SIZE;
        dataSize -= RSA32_AES_BLOCK_SIZE;
    }
}

VOID
algImpDataPerfFunction<ImpRsa32b,AlgAes,ModeCbc>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CBC( aes, 16, buf2, buf3, (AESTable *)buf1, ENCRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_AES_BLOCK_SIZE;
        buf3 += RSA32_AES_BLOCK_SIZE;
        dataSize -= RSA32_AES_BLOCK_SIZE;
    }
}

VOID
algImpDataPerfFunction<ImpRsa32b,AlgAes,ModeCfb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CFB( aes, 16, buf2, buf3, (AESTable *)buf1, ENCRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_AES_BLOCK_SIZE;
        buf3 += RSA32_AES_BLOCK_SIZE;
        dataSize -= RSA32_AES_BLOCK_SIZE;
    }
}

VOID
algImpDecryptPerfFunction<ImpRsa32b,AlgAes,ModeEcb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        aes( buf2, buf3, (AESTable *)buf1, DECRYPT );
        buf2 += RSA32_AES_BLOCK_SIZE;
        buf3 += RSA32_AES_BLOCK_SIZE;
        dataSize -= RSA32_AES_BLOCK_SIZE;
    }
}

VOID
algImpDecryptPerfFunction<ImpRsa32b,AlgAes,ModeCbc>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CBC( aes, 16, buf2, buf3, (AESTable *)buf1, DECRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_AES_BLOCK_SIZE;
        buf3 += RSA32_AES_BLOCK_SIZE;
        dataSize -= RSA32_AES_BLOCK_SIZE;
    }
}

VOID
algImpDecryptPerfFunction<ImpRsa32b,AlgAes,ModeCfb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CFB( aes, 16, buf2, buf3, (AESTable *)buf1, DECRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_AES_BLOCK_SIZE;
        buf3 += RSA32_AES_BLOCK_SIZE;
        dataSize -= RSA32_AES_BLOCK_SIZE;
    }
}


VOID
algImpCleanPerfFunction<ImpRsa32b,AlgAes,ModeEcb>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( buf2 );

    RtlSecureZeroMemory( buf1, sizeof( AESTable ) );
}

VOID
algImpCleanPerfFunction<ImpRsa32b,AlgAes,ModeCbc>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( buf2 );

    RtlSecureZeroMemory( buf1, sizeof( AESTable ) );
}

VOID
algImpCleanPerfFunction<ImpRsa32b,AlgAes,ModeCfb>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( buf2 );

    RtlSecureZeroMemory( buf1, sizeof( AESTable ) );
}




NTSTATUS
BlockCipherImp<ImpRsa32,AlgDes,ModeEcb>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 8, "?" );
    
    deskey( &state.key, (PBYTE) pbKey );

    return STATUS_SUCCESS;
}

NTSTATUS
BlockCipherImp<ImpRsa32,AlgDes,ModeCbc>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 8, "?" );
    
    deskey( &state.key, (PBYTE) pbKey );

    return STATUS_SUCCESS;
}

NTSTATUS
BlockCipherImp<ImpRsa32,AlgDes,ModeCfb>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 8, "?" );
    
    if( g_modeCfbShiftParam != 1 )
    {
        return STATUS_NOT_SUPPORTED;
    }

    deskey( &state.key, (PBYTE) pbKey );

    return STATUS_SUCCESS;
}




VOID
BlockCipherImp<ImpRsa32, AlgDes,ModeEcb>::encrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    UNREFERENCED_PARAMETER( pbChain );

    CHECK( cbData % RSA32_DES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == 0, "Unneeded chain value" );

    while( cbData > 0 )
    {
        des( pbDst, (PBYTE) pbSrc, &state.key, ENCRYPT );
        pbSrc += RSA32_DES_BLOCK_SIZE;
        pbDst += RSA32_DES_BLOCK_SIZE;
        cbData -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32, AlgDes,ModeCbc>::encrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbData % RSA32_DES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == RSA32_DES_BLOCK_SIZE, "Unneeded chain value" );

    while( cbData > 0 )
    {
        CBC( des, RSA32_DES_BLOCK_SIZE, pbDst, (PBYTE) pbSrc, &state.key, ENCRYPT, pbChain );
        pbSrc += RSA32_DES_BLOCK_SIZE;
        pbDst += RSA32_DES_BLOCK_SIZE;
        cbData -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32, AlgDes,ModeCfb>::encrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbChain == RSA32_DES_BLOCK_SIZE, "Unneeded chain value" );

    CFBAnyLen( des, RSA32_DES_BLOCK_SIZE, pbDst, (PBYTE) pbSrc, &state.key, ENCRYPT, pbChain, cbData );
}


VOID
BlockCipherImp<ImpRsa32, AlgDes,ModeEcb>::decrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    UNREFERENCED_PARAMETER( pbChain );

    CHECK( cbData % RSA32_DES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == 0, "Unneeded chain value" );

    while( cbData > 0 )
    {
        des( pbDst, (PBYTE) pbSrc, &state.key, DECRYPT );
        pbSrc += RSA32_DES_BLOCK_SIZE;
        pbDst += RSA32_DES_BLOCK_SIZE;
        cbData -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32, AlgDes,ModeCbc>::decrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbData % RSA32_DES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == RSA32_DES_BLOCK_SIZE, "Unneeded chain value" );

    while( cbData > 0 )
    {
        CBC( des, RSA32_DES_BLOCK_SIZE, pbDst, (PBYTE) pbSrc, &state.key, DECRYPT, pbChain );
        pbSrc += RSA32_DES_BLOCK_SIZE;
        pbDst += RSA32_DES_BLOCK_SIZE;
        cbData -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32, AlgDes,ModeCfb>::decrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbChain == RSA32_DES_BLOCK_SIZE, "Unneeded chain value" );

    CFBAnyLen( des, RSA32_DES_BLOCK_SIZE, pbDst, (PBYTE) pbSrc, &state.key, DECRYPT, pbChain, cbData );
}



VOID
algImpKeyPerfFunction<ImpRsa32,AlgDes,ModeEcb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( keySize );

    deskey( (DESTable *)buf1, buf2 );
}

VOID
algImpKeyPerfFunction<ImpRsa32,AlgDes,ModeCbc>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( keySize );

    deskey( (DESTable *)buf1, buf2 );
}

VOID
algImpKeyPerfFunction<ImpRsa32,AlgDes,ModeCfb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( keySize );

    deskey( (DESTable *)buf1, buf2 );
}

VOID
algImpDataPerfFunction<ImpRsa32,AlgDes,ModeEcb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        des( buf2, buf3, (DESTable *)buf1, ENCRYPT );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
algImpDataPerfFunction<ImpRsa32,AlgDes,ModeCbc>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CBC( des, RSA32_DES_BLOCK_SIZE, buf2, buf3, (DESTable *)buf1, ENCRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
algImpDataPerfFunction<ImpRsa32,AlgDes,ModeCfb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CFB( des, RSA32_DES_BLOCK_SIZE, buf2, buf3, (DESTable *)buf1, ENCRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
algImpDecryptPerfFunction<ImpRsa32,AlgDes,ModeEcb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        des( buf2, buf3, (DESTable *)buf1, DECRYPT );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
algImpDecryptPerfFunction<ImpRsa32,AlgDes,ModeCbc>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CBC( des, RSA32_DES_BLOCK_SIZE, buf2, buf3, (DESTable *)buf1, DECRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
algImpDecryptPerfFunction<ImpRsa32,AlgDes,ModeCfb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CFB( des, RSA32_DES_BLOCK_SIZE, buf2, buf3, (DESTable *)buf1, DECRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}


VOID
algImpCleanPerfFunction<ImpRsa32,AlgDes,ModeEcb>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( buf2 );

    RtlSecureZeroMemory( buf1, sizeof( DESTable ) );
}

VOID
algImpCleanPerfFunction<ImpRsa32,AlgDes,ModeCbc>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( buf2 );

    RtlSecureZeroMemory( buf1, sizeof( DESTable ) );
}

VOID
algImpCleanPerfFunction<ImpRsa32,AlgDes,ModeCfb>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( buf2 );

    RtlSecureZeroMemory( buf1, sizeof( DESTable ) );
}




NTSTATUS
BlockCipherImp<ImpRsa32,Alg2Des,ModeEcb>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 16, "?" );
    
    tripledes2key( &state.key, (PBYTE) pbKey );

    return STATUS_SUCCESS;
}

NTSTATUS
BlockCipherImp<ImpRsa32,Alg2Des,ModeCbc>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 16, "?" );
    
    tripledes2key( &state.key, (PBYTE) pbKey );

    return STATUS_SUCCESS;
}

NTSTATUS
BlockCipherImp<ImpRsa32,Alg2Des,ModeCfb>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 16, "?" );
    
    if( g_modeCfbShiftParam != 1 )
    {
        return STATUS_NOT_SUPPORTED;
    }

  tripledes2key( &state.key, (PBYTE) pbKey );

    return STATUS_SUCCESS;
}


VOID
BlockCipherImp<ImpRsa32, Alg2Des,ModeEcb>::encrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    UNREFERENCED_PARAMETER( pbChain );

    CHECK( cbData % RSA32_DES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == 0, "Unneeded chain value" );

    while( cbData > 0 )
    {
        tripledes( pbDst, (PBYTE) pbSrc, &state.key, ENCRYPT );
        pbSrc += RSA32_DES_BLOCK_SIZE;
        pbDst += RSA32_DES_BLOCK_SIZE;
        cbData -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32, Alg2Des,ModeCbc>::encrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbData % RSA32_DES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == RSA32_DES_BLOCK_SIZE, "Unneeded chain value" );

    while( cbData > 0 )
    {
        CBC( tripledes, RSA32_DES_BLOCK_SIZE, pbDst, (PBYTE) pbSrc, &state.key, ENCRYPT, pbChain );
        pbSrc += RSA32_DES_BLOCK_SIZE;
        pbDst += RSA32_DES_BLOCK_SIZE;
        cbData -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32, Alg2Des,ModeCfb>::encrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbChain == RSA32_DES_BLOCK_SIZE, "Unneeded chain value" );

    CFBAnyLen( tripledes, RSA32_DES_BLOCK_SIZE, pbDst, (PBYTE) pbSrc, &state.key, ENCRYPT, pbChain, cbData );
}


VOID
BlockCipherImp<ImpRsa32, Alg2Des,ModeEcb>::decrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    UNREFERENCED_PARAMETER( pbChain );

    CHECK( cbData % RSA32_DES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == 0, "Unneeded chain value" );

    while( cbData > 0 )
    {
        tripledes( pbDst, (PBYTE) pbSrc, &state.key, DECRYPT );
        pbSrc += RSA32_DES_BLOCK_SIZE;
        pbDst += RSA32_DES_BLOCK_SIZE;
        cbData -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32, Alg2Des,ModeCbc>::decrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbData % RSA32_DES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == RSA32_DES_BLOCK_SIZE, "Unneeded chain value" );

    while( cbData > 0 )
    {
        CBC( tripledes, RSA32_DES_BLOCK_SIZE, pbDst, (PBYTE) pbSrc, &state.key, DECRYPT, pbChain );
        pbSrc += RSA32_DES_BLOCK_SIZE;
        pbDst += RSA32_DES_BLOCK_SIZE;
        cbData -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32, Alg2Des,ModeCfb>::decrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbChain == RSA32_DES_BLOCK_SIZE, "Unneeded chain value" );

    CFBAnyLen( tripledes, RSA32_DES_BLOCK_SIZE, pbDst, (PBYTE) pbSrc, &state.key, DECRYPT, pbChain, cbData );
}



VOID
algImpKeyPerfFunction<ImpRsa32,Alg2Des,ModeEcb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( keySize );

    tripledes2key( (DES3TABLE *)buf1, buf2 );
}

VOID
algImpKeyPerfFunction<ImpRsa32,Alg2Des,ModeCbc>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( keySize );

    tripledes2key( (DES3TABLE *)buf1, buf2 );
}

VOID
algImpKeyPerfFunction<ImpRsa32,Alg2Des,ModeCfb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( keySize );

    tripledes2key( (DES3TABLE *)buf1, buf2 );
}

VOID
algImpDataPerfFunction<ImpRsa32,Alg2Des,ModeEcb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        tripledes( buf2, buf3, (DESTable *)buf1, ENCRYPT );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
algImpDataPerfFunction<ImpRsa32,Alg2Des,ModeCbc>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CBC( tripledes, RSA32_DES_BLOCK_SIZE, buf2, buf3, (DESTable *)buf1, ENCRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
algImpDataPerfFunction<ImpRsa32,Alg2Des,ModeCfb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CFB( tripledes, RSA32_DES_BLOCK_SIZE, buf2, buf3, (DESTable *)buf1, ENCRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
algImpDecryptPerfFunction<ImpRsa32,Alg2Des,ModeEcb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        tripledes( buf2, buf3, (DESTable *)buf1, DECRYPT );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
algImpDecryptPerfFunction<ImpRsa32,Alg2Des,ModeCbc>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CBC( tripledes, RSA32_DES_BLOCK_SIZE, buf2, buf3, (DESTable *)buf1, DECRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
algImpDecryptPerfFunction<ImpRsa32,Alg2Des,ModeCfb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CFB( tripledes, RSA32_DES_BLOCK_SIZE, buf2, buf3, (DESTable *)buf1, DECRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}


VOID
algImpCleanPerfFunction<ImpRsa32,Alg2Des,ModeEcb>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( buf2 );

    RtlSecureZeroMemory( buf1, sizeof( DES3TABLE ) );
}

VOID
algImpCleanPerfFunction<ImpRsa32,Alg2Des,ModeCbc>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( buf2 );

    RtlSecureZeroMemory( buf1, sizeof( DES3TABLE ) );
}

VOID
algImpCleanPerfFunction<ImpRsa32,Alg2Des,ModeCfb>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( buf2 );

    RtlSecureZeroMemory( buf1, sizeof( DES3TABLE ) );
}






NTSTATUS
BlockCipherImp<ImpRsa32,Alg3Des,ModeEcb>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 24, "?" );
    
    tripledes3key( &state.key, (PBYTE) pbKey );

    return STATUS_SUCCESS;
}

NTSTATUS
BlockCipherImp<ImpRsa32,Alg3Des,ModeCbc>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 24, "?" );
    
    tripledes3key( &state.key, (PBYTE) pbKey );

    return STATUS_SUCCESS;
}

NTSTATUS
BlockCipherImp<ImpRsa32,Alg3Des,ModeCfb>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 24, "?" );
    
    if( g_modeCfbShiftParam != 1 )
    {
        return STATUS_NOT_SUPPORTED;
    }

    tripledes3key( &state.key, (PBYTE) pbKey );

    return STATUS_SUCCESS;
}


VOID
BlockCipherImp<ImpRsa32, Alg3Des,ModeEcb>::encrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    UNREFERENCED_PARAMETER( pbChain );

    CHECK( cbData % RSA32_DES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == 0, "Unneeded chain value" );

    while( cbData > 0 )
    {
        tripledes( pbDst, (PBYTE) pbSrc, &state.key, ENCRYPT );
        pbSrc += RSA32_DES_BLOCK_SIZE;
        pbDst += RSA32_DES_BLOCK_SIZE;
        cbData -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32, Alg3Des,ModeCbc>::encrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbData % RSA32_DES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == RSA32_DES_BLOCK_SIZE, "Unneeded chain value" );

    while( cbData > 0 )
    {
        CBC( tripledes, RSA32_DES_BLOCK_SIZE, pbDst, (PBYTE) pbSrc, &state.key, ENCRYPT, pbChain );
        pbSrc += RSA32_DES_BLOCK_SIZE;
        pbDst += RSA32_DES_BLOCK_SIZE;
        cbData -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32, Alg3Des,ModeCfb>::encrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbChain == RSA32_DES_BLOCK_SIZE, "Unneeded chain value" );

    CFBAnyLen( tripledes, RSA32_DES_BLOCK_SIZE, pbDst, (PBYTE) pbSrc, &state.key, ENCRYPT, pbChain, cbData );
}


VOID
BlockCipherImp<ImpRsa32, Alg3Des,ModeEcb>::decrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    UNREFERENCED_PARAMETER( pbChain );

    CHECK( cbData % RSA32_DES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == 0, "Unneeded chain value" );

    while( cbData > 0 )
    {
        tripledes( pbDst, (PBYTE) pbSrc, &state.key, DECRYPT );
        pbSrc += RSA32_DES_BLOCK_SIZE;
        pbDst += RSA32_DES_BLOCK_SIZE;
        cbData -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32, Alg3Des,ModeCbc>::decrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbData % RSA32_DES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == RSA32_DES_BLOCK_SIZE, "Unneeded chain value" );

    while( cbData > 0 )
    {
        CBC( tripledes, RSA32_DES_BLOCK_SIZE, pbDst, (PBYTE) pbSrc, &state.key, DECRYPT, pbChain );
        pbSrc += RSA32_DES_BLOCK_SIZE;
        pbDst += RSA32_DES_BLOCK_SIZE;
        cbData -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32, Alg3Des,ModeCfb>::decrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbChain == RSA32_DES_BLOCK_SIZE, "Unneeded chain value" );

    CFBAnyLen( tripledes, RSA32_DES_BLOCK_SIZE, pbDst, (PBYTE) pbSrc, &state.key, DECRYPT, pbChain, cbData );
}



VOID
algImpKeyPerfFunction<ImpRsa32,Alg3Des,ModeEcb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( keySize );

    tripledes3key( (DES3TABLE *)buf1, buf2 );
}

VOID
algImpKeyPerfFunction<ImpRsa32,Alg3Des,ModeCbc>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( keySize );

    tripledes3key( (DES3TABLE *)buf1, buf2 );
}

VOID
algImpKeyPerfFunction<ImpRsa32,Alg3Des,ModeCfb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( keySize );

    tripledes3key( (DES3TABLE *)buf1, buf2 );
}

VOID
algImpDataPerfFunction<ImpRsa32,Alg3Des,ModeEcb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        tripledes( buf2, buf3, (DESTable *)buf1, ENCRYPT );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
algImpDataPerfFunction<ImpRsa32,Alg3Des,ModeCbc>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CBC( tripledes, RSA32_DES_BLOCK_SIZE, buf2, buf3, (DESTable *)buf1, ENCRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
algImpDataPerfFunction<ImpRsa32,Alg3Des,ModeCfb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CFB( tripledes, RSA32_DES_BLOCK_SIZE, buf2, buf3, (DESTable *)buf1, ENCRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
algImpDecryptPerfFunction<ImpRsa32,Alg3Des,ModeEcb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        tripledes( buf2, buf3, (DESTable *)buf1, DECRYPT );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
algImpDecryptPerfFunction<ImpRsa32,Alg3Des,ModeCbc>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CBC( tripledes, RSA32_DES_BLOCK_SIZE, buf2, buf3, (DESTable *)buf1, DECRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
algImpDecryptPerfFunction<ImpRsa32,Alg3Des,ModeCfb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CFB( tripledes, RSA32_DES_BLOCK_SIZE, buf2, buf3, (DESTable *)buf1, DECRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}


VOID
algImpCleanPerfFunction<ImpRsa32,Alg3Des,ModeEcb>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( buf2 );

    RtlSecureZeroMemory( buf1, sizeof( DES3TABLE ) );
}

VOID
algImpCleanPerfFunction<ImpRsa32,Alg3Des,ModeCbc>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( buf2 );

    RtlSecureZeroMemory( buf1, sizeof( DES3TABLE ) );
}

VOID
algImpCleanPerfFunction<ImpRsa32,Alg3Des,ModeCfb>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( buf2 );

    RtlSecureZeroMemory( buf1, sizeof( DES3TABLE ) );
}







NTSTATUS
BlockCipherImp<ImpRsa32,AlgDesx,ModeEcb>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 24, "?" );
    
    desxkey( &state.key, (PBYTE) pbKey );

    return STATUS_SUCCESS;
}

NTSTATUS
BlockCipherImp<ImpRsa32,AlgDesx,ModeCbc>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 24, "?" );
    
    desxkey( &state.key, (PBYTE) pbKey );

    return STATUS_SUCCESS;
}

NTSTATUS
BlockCipherImp<ImpRsa32,AlgDesx,ModeCfb>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 24, "?" );
    
    if( g_modeCfbShiftParam != 1 )
    {
        return STATUS_NOT_SUPPORTED;
    }

    desxkey( &state.key, (PBYTE) pbKey );

    return STATUS_SUCCESS;
}


VOID
BlockCipherImp<ImpRsa32, AlgDesx,ModeEcb>::encrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
 {
    UNREFERENCED_PARAMETER( pbChain );

    CHECK( cbData % RSA32_DES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == 0, "Unneeded chain value" );

    while( cbData > 0 )
    {
        desx( pbDst, (PBYTE) pbSrc, &state.key, ENCRYPT );
        pbSrc += RSA32_DES_BLOCK_SIZE;
        pbDst += RSA32_DES_BLOCK_SIZE;
        cbData -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32, AlgDesx,ModeCbc>::encrypt(
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbData % RSA32_DES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == RSA32_DES_BLOCK_SIZE, "Unneeded chain value" );

    while( cbData > 0 )
    {
        CBC( desx, RSA32_DES_BLOCK_SIZE, pbDst, (PBYTE) pbSrc, &state.key, ENCRYPT, pbChain );
        pbSrc += RSA32_DES_BLOCK_SIZE;
        pbDst += RSA32_DES_BLOCK_SIZE;
        cbData -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32, AlgDesx,ModeCfb>::encrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbChain == RSA32_DES_BLOCK_SIZE, "Unneeded chain value" );

    CFBAnyLen( desx, RSA32_DES_BLOCK_SIZE, pbDst, (PBYTE) pbSrc, &state.key, ENCRYPT, pbChain, cbData );
}


VOID
BlockCipherImp<ImpRsa32, AlgDesx,ModeEcb>::decrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    UNREFERENCED_PARAMETER( pbChain );

    CHECK( cbData % RSA32_DES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == 0, "Unneeded chain value" );

    while( cbData > 0 )
    {
        desx( pbDst, (PBYTE) pbSrc, &state.key, DECRYPT );
        pbSrc += RSA32_DES_BLOCK_SIZE;
        pbDst += RSA32_DES_BLOCK_SIZE;
        cbData -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32, AlgDesx,ModeCbc>::decrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbData % RSA32_DES_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == RSA32_DES_BLOCK_SIZE, "Unneeded chain value" );

    while( cbData > 0 )
    {
        CBC( desx, RSA32_DES_BLOCK_SIZE, pbDst, (PBYTE) pbSrc, &state.key, DECRYPT, pbChain );
        pbSrc += RSA32_DES_BLOCK_SIZE;
        pbDst += RSA32_DES_BLOCK_SIZE;
        cbData -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32, AlgDesx,ModeCfb>::decrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbChain == RSA32_DES_BLOCK_SIZE, "Unneeded chain value" );

    CFBAnyLen( desx, RSA32_DES_BLOCK_SIZE, pbDst, (PBYTE) pbSrc, &state.key, DECRYPT, pbChain, cbData );
}


VOID
algImpKeyPerfFunction<ImpRsa32,AlgDesx,ModeEcb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( keySize );

    desxkey( (DESXTable *)buf1, buf2 );
}

VOID
algImpKeyPerfFunction<ImpRsa32,AlgDesx,ModeCbc>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( keySize );

    desxkey( (DESXTable *)buf1, buf2 );
}

VOID
algImpKeyPerfFunction<ImpRsa32,AlgDesx,ModeCfb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( keySize );

    desxkey( (DESXTable *)buf1, buf2 );
}

VOID
algImpDataPerfFunction<ImpRsa32,AlgDesx,ModeEcb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        desx( buf2, buf3, (DESTable *)buf1, ENCRYPT );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
algImpDataPerfFunction<ImpRsa32,AlgDesx,ModeCbc>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CBC( desx, RSA32_DES_BLOCK_SIZE, buf2, buf3, (DESTable *)buf1, ENCRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
algImpDataPerfFunction<ImpRsa32,AlgDesx,ModeCfb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CFB( desx, RSA32_DES_BLOCK_SIZE, buf2, buf3, (DESTable *)buf1, ENCRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
algImpDecryptPerfFunction<ImpRsa32,AlgDesx,ModeEcb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        desx( buf2, buf3, (DESTable *)buf1, DECRYPT );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
algImpDecryptPerfFunction<ImpRsa32,AlgDesx,ModeCbc>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CBC( desx, RSA32_DES_BLOCK_SIZE, buf2, buf3, (DESTable *)buf1, DECRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}

VOID
algImpDecryptPerfFunction<ImpRsa32,AlgDesx,ModeCfb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CFB( desx, RSA32_DES_BLOCK_SIZE, buf2, buf3, (DESTable *)buf1, DECRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_DES_BLOCK_SIZE;
        buf3 += RSA32_DES_BLOCK_SIZE;
        dataSize -= RSA32_DES_BLOCK_SIZE;
    }
}


VOID
algImpCleanPerfFunction<ImpRsa32,AlgDesx,ModeEcb>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( buf2 );

    RtlSecureZeroMemory( buf1, sizeof( DESXTable ) );
}

VOID
algImpCleanPerfFunction<ImpRsa32,AlgDesx,ModeCbc>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( buf2 );

    RtlSecureZeroMemory( buf1, sizeof( DESXTable ) );
}

VOID
algImpCleanPerfFunction<ImpRsa32,AlgDesx,ModeCfb>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( buf2 );

    RtlSecureZeroMemory( buf1, sizeof( DESXTable ) );
}




NTSTATUS
BlockCipherImp<ImpRsa32,AlgRc2,ModeEcb>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    RC2KeyEx( &state.key.key[0], (PBYTE) pbKey, (ULONG) cbKey, g_rc2EffectiveKeyLength ? g_rc2EffectiveKeyLength : 8*(ULONG)cbKey );

    return STATUS_SUCCESS;
}

NTSTATUS
BlockCipherImp<ImpRsa32,AlgRc2,ModeCbc>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    RC2KeyEx( &state.key.key[0], (PBYTE) pbKey, (ULONG) cbKey, g_rc2EffectiveKeyLength ? g_rc2EffectiveKeyLength : 8*(ULONG)cbKey );

    return STATUS_SUCCESS;
}

NTSTATUS
BlockCipherImp<ImpRsa32,AlgRc2,ModeCfb>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    if( g_modeCfbShiftParam != 1 )
    {
        return STATUS_NOT_SUPPORTED;
    }

    RC2KeyEx( &state.key.key[0], (PBYTE) pbKey, (ULONG) cbKey, g_rc2EffectiveKeyLength ? g_rc2EffectiveKeyLength : 8*(ULONG)cbKey );

    return STATUS_SUCCESS;
}


VOID
BlockCipherImp<ImpRsa32, AlgRc2,ModeEcb>::encrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    UNREFERENCED_PARAMETER( pbChain );

    CHECK( cbData % RSA32_RC2_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == 0, "Unneeded chain value" );

    while( cbData > 0 )
    {
        RC2( pbDst, (PBYTE) pbSrc, &state.key, ENCRYPT );
        pbSrc += RSA32_RC2_BLOCK_SIZE;
        pbDst += RSA32_RC2_BLOCK_SIZE;
        cbData -= RSA32_RC2_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32, AlgRc2,ModeCbc>::encrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
 {
    CHECK( cbData % RSA32_RC2_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == RSA32_RC2_BLOCK_SIZE, "Unneeded chain value" );

    while( cbData > 0 )
    {
        CBC( RC2, RSA32_RC2_BLOCK_SIZE, pbDst, (PBYTE) pbSrc, &state.key, ENCRYPT, pbChain );
        pbSrc += RSA32_RC2_BLOCK_SIZE;
        pbDst += RSA32_RC2_BLOCK_SIZE;
        cbData -= RSA32_RC2_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32, AlgRc2,ModeCfb>::encrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbChain == RSA32_RC2_BLOCK_SIZE, "Unneeded chain value" );

    CFBAnyLen( RC2, RSA32_RC2_BLOCK_SIZE, pbDst, (PBYTE) pbSrc, &state.key, ENCRYPT, pbChain, cbData );
}


VOID
BlockCipherImp<ImpRsa32, AlgRc2,ModeEcb>::decrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    UNREFERENCED_PARAMETER( pbChain );

    CHECK( cbData % RSA32_RC2_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == 0, "Unneeded chain value" );

    while( cbData > 0 )
    {
        RC2( pbDst, (PBYTE) pbSrc, &state.key, DECRYPT );
        pbSrc += RSA32_RC2_BLOCK_SIZE;
        pbDst += RSA32_RC2_BLOCK_SIZE;
        cbData -= RSA32_RC2_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32, AlgRc2,ModeCbc>::decrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbData % RSA32_RC2_BLOCK_SIZE == 0, "Wrong data length" );
    CHECK( cbChain == RSA32_RC2_BLOCK_SIZE, "Unneeded chain value" );

    while( cbData > 0 )
    {
        CBC( RC2, RSA32_RC2_BLOCK_SIZE, pbDst, (PBYTE) pbSrc, &state.key, DECRYPT, pbChain );
        pbSrc += RSA32_RC2_BLOCK_SIZE;
        pbDst += RSA32_RC2_BLOCK_SIZE;
        cbData -= RSA32_RC2_BLOCK_SIZE;
    }
}

VOID
BlockCipherImp<ImpRsa32, AlgRc2,ModeCfb>::decrypt( 
        _Inout_updates_opt_( cbChain )   PBYTE pbChain, 
                                        SIZE_T cbChain, 
        _In_reads_( cbData )           PCBYTE pbSrc, 
        _Out_writes_( cbData )          PBYTE pbDst, 
                                        SIZE_T cbData )
{
    CHECK( cbChain == RSA32_RC2_BLOCK_SIZE, "Unneeded chain value" );

    CFBAnyLen( RC2, RSA32_RC2_BLOCK_SIZE, pbDst, (PBYTE) pbSrc, &state.key, DECRYPT, pbChain, cbData );
}

VOID
algImpKeyPerfFunction<ImpRsa32,AlgRc2,ModeEcb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    RC2KeyEx( (WORD *)buf1, buf2, (ULONG) keySize, g_rc2EffectiveKeyLength );
}

VOID
algImpKeyPerfFunction<ImpRsa32,AlgRc2,ModeCbc>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    RC2KeyEx( (WORD *)buf1, buf2, (ULONG) keySize, g_rc2EffectiveKeyLength );
}

VOID
algImpKeyPerfFunction<ImpRsa32,AlgRc2,ModeCfb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    RC2KeyEx( (WORD *)buf1, buf2, (ULONG) keySize, g_rc2EffectiveKeyLength );
}

VOID
algImpDataPerfFunction<ImpRsa32,AlgRc2,ModeEcb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        RC2( buf2, buf3, buf1, ENCRYPT );
        buf2 += RSA32_RC2_BLOCK_SIZE;
        buf3 += RSA32_RC2_BLOCK_SIZE;
        dataSize -= RSA32_RC2_BLOCK_SIZE;
    }
}

VOID
algImpDataPerfFunction<ImpRsa32,AlgRc2,ModeCbc>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CBC( RC2, RSA32_RC2_BLOCK_SIZE, buf2, buf3, buf1, ENCRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_RC2_BLOCK_SIZE;
        buf3 += RSA32_RC2_BLOCK_SIZE;
        dataSize -= RSA32_RC2_BLOCK_SIZE;
    }
}

VOID
algImpDataPerfFunction<ImpRsa32,AlgRc2,ModeCfb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CFB( RC2, RSA32_RC2_BLOCK_SIZE, buf2, buf3, buf1, ENCRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_RC2_BLOCK_SIZE;
        buf3 += RSA32_RC2_BLOCK_SIZE;
        dataSize -= RSA32_RC2_BLOCK_SIZE;
    }
}

VOID
algImpDecryptPerfFunction<ImpRsa32,AlgRc2,ModeEcb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        RC2( buf2, buf3, (WORD *)buf1, DECRYPT );
        buf2 += RSA32_RC2_BLOCK_SIZE;
        buf3 += RSA32_RC2_BLOCK_SIZE;
        dataSize -= RSA32_RC2_BLOCK_SIZE;
    }
}

VOID
algImpDecryptPerfFunction<ImpRsa32,AlgRc2,ModeCbc>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CBC( RC2, RSA32_RC2_BLOCK_SIZE, buf2, buf3, buf1, DECRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_RC2_BLOCK_SIZE;
        buf3 += RSA32_RC2_BLOCK_SIZE;
        dataSize -= RSA32_RC2_BLOCK_SIZE;
    }
}

VOID
algImpDecryptPerfFunction<ImpRsa32,AlgRc2,ModeCfb>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    while( dataSize > 0 )
    {
        CFB( RC2, RSA32_RC2_BLOCK_SIZE, buf2, buf3, buf1, DECRYPT, buf1 + PERF_BUFFER_SIZE / 2 );
        buf2 += RSA32_RC2_BLOCK_SIZE;
        buf3 += RSA32_RC2_BLOCK_SIZE;
        dataSize -= RSA32_RC2_BLOCK_SIZE;
    }
}


VOID
algImpCleanPerfFunction<ImpRsa32,AlgRc2,ModeEcb>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    RtlSecureZeroMemory( buf1, sizeof( RSA32_RC2_KEY ) );
}

VOID
algImpCleanPerfFunction<ImpRsa32,AlgRc2,ModeCbc>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    RtlSecureZeroMemory( buf1, sizeof( RSA32_RC2_KEY ) );
}

VOID
algImpCleanPerfFunction<ImpRsa32,AlgRc2,ModeCfb>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    RtlSecureZeroMemory( buf1, sizeof( RSA32_RC2_KEY ) );
}

//
// CCM
//


template<>
VOID 
algImpKeyPerfFunction<ImpRsa32, AlgAes, ModeCcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    AesExpandKey( (AES_KEY *) buf1, buf2, keySize );
}

template<>
VOID
algImpDataPerfFunction<ImpRsa32,AlgAes, ModeCcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    AesCcmComputeUnencryptedTag( (AES_KEY *)buf1, buf2, 12, NULL, 0, buf2 + 16, dataSize, buf3, 16 );
    AesCcmEncryptDecrypt( (AES_KEY *) buf1, buf2, 12, buf2 + 16, dataSize, buf3, 16 );
}

template<>
VOID
algImpDecryptPerfFunction<ImpRsa32,AlgAes, ModeCcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    BYTE tagBuf[16];
    BYTE tmp[16];

    memcpy( tagBuf, buf3, 16 );
    AesCcmEncryptDecrypt( (AES_KEY *) buf1, buf2, 12, buf2 + 16, dataSize, tagBuf, 16 );
    AesCcmComputeUnencryptedTag( (AES_KEY *)buf1, buf2, 12, NULL, 0, buf2 + 16, dataSize, tmp, 16 );

    //
    // We don't actually get proper tag values for perf measurements, but we still want to fake the 
    // necessary comparison. So we do the comparison and store the result; the compiler won't be smart enough
    // to optimize this away.
    //
    *(int *) buf3 = memcmp( tagBuf, tmp, 16 );
}

template<>
VOID
algImpCleanPerfFunction<ImpRsa32,AlgAes, ModeCcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    RtlSecureZeroMemory( buf1, sizeof( AES_KEY ) );
}


AuthEncImp<ImpRsa32, AlgAes, ModeCcm>::AuthEncImp()
{
    m_perfKeyFunction     = &algImpKeyPerfFunction    <ImpRsa32, AlgAes, ModeCcm>;
    m_perfCleanFunction   = &algImpCleanPerfFunction  <ImpRsa32, AlgAes, ModeCcm>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpRsa32, AlgAes, ModeCcm>;
    m_perfDecryptFunction = &algImpDecryptPerfFunction<ImpRsa32, AlgAes, ModeCcm>;
}

template<>
AuthEncImp<ImpRsa32, AlgAes, ModeCcm>::~AuthEncImp()
{
}

template<>
std::set<SIZE_T>
AuthEncImp<ImpRsa32, AlgAes, ModeCcm>::getKeySizes()
{
    std::set<SIZE_T> res;

    res.insert( 16 );
    res.insert( 24 );
    res.insert( 32 );
    
    return res;
}


template<>
std::set<SIZE_T>
AuthEncImp<ImpRsa32, AlgAes, ModeCcm>::getNonceSizes()
{
    std::set<SIZE_T> res;

    for( int i=7; i<=13; i++ )
    {
        res.insert( i );
    }

    return res;
}


template<>
std::set<SIZE_T>
AuthEncImp<ImpRsa32, AlgAes, ModeCcm>::getTagSizes()
{
    std::set<SIZE_T> res;

    for( int i=4; i<=16; i += 2 )
    {
        res.insert( i );
    }

    return res;
}

template<>
NTSTATUS
AuthEncImp<ImpRsa32, AlgAes, ModeCcm>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 16 || cbKey == 24 || cbKey == 32, "?" );
    AesExpandKey( &state.key, pbKey, cbKey );
    return STATUS_SUCCESS;
}

template<>
VOID
AuthEncImp<ImpRsa32, AlgAes, ModeCcm>::setTotalCbData( SIZE_T cbData )
{
    UNREFERENCED_PARAMETER( cbData );
}

template<>
NTSTATUS
AuthEncImp<ImpRsa32, AlgAes, ModeCcm>::encrypt(
        _In_reads_( cbNonce )       PCBYTE  pbNonce,      
                                    SIZE_T  cbNonce, 
        _In_reads_( cbAuthData )    PCBYTE  pbAuthData, 
                                    SIZE_T  cbAuthData, 
        _In_reads_( cbData )        PCBYTE  pbSrc, 
        _Out_writes_( cbData )      PBYTE   pbDst, 
                                    SIZE_T  cbData,
        _Out_writes_( cbTag )       PBYTE   pbTag, 
                                    SIZE_T  cbTag,
                                    ULONG   flags )
{
    NTSTATUS status = STATUS_SUCCESS;

    if( flags != 0 )
    {
        status = STATUS_NOT_SUPPORTED;
        goto cleanup;
    }

    CHECK( AesCcmValidateParameters( cbNonce, cbAuthData, cbData, cbTag ), "Invalid CCM params" );

    memcpy( pbDst, pbSrc, cbData );
    
    AesCcmComputeUnencryptedTag( &state.key, pbNonce, cbNonce, pbAuthData, cbAuthData,
                                pbDst, cbData, pbTag, cbTag );
    AesCcmEncryptDecrypt( &state.key, pbNonce, cbNonce, pbDst, cbData, pbTag, cbTag );

cleanup:
    return status;
}


template<>
NTSTATUS
AuthEncImp<ImpRsa32, AlgAes, ModeCcm>::decrypt(
        _In_reads_( cbNonce )       PCBYTE  pbNonce,      
                                    SIZE_T  cbNonce, 
        _In_reads_( cbAuthData )    PCBYTE  pbAuthData, 
                                    SIZE_T  cbAuthData, 
        _In_reads_( cbData )        PCBYTE  pbSrc, 
        _Out_writes_( cbData )      PBYTE   pbDst, 
                                    SIZE_T  cbData,
        _In_reads_( cbTag )         PCBYTE  pbTag, 
                                    SIZE_T  cbTag,
                                    ULONG   flags )
{
    NTSTATUS status = STATUS_SUCCESS;

    BYTE    tagBuf[16];
    BYTE    tmp[16];
        
    if( flags != 0 )
    {
        status = STATUS_NOT_SUPPORTED;
        goto cleanup;
    }

    CHECK( AesCcmValidateParameters( cbNonce, cbAuthData, cbData, cbTag ), "Invalid CCM params" );
    CHECK( cbTag <= 16, "?" );
    
    memcpy( pbDst, pbSrc, cbData );
    memcpy( tagBuf, pbTag, cbTag );
    AesCcmEncryptDecrypt( &state.key, pbNonce, cbNonce, pbDst, cbData, tagBuf, cbTag );
    AesCcmComputeUnencryptedTag( &state.key, pbNonce, cbNonce, pbAuthData, cbAuthData,
                                pbDst, cbData, tmp, cbTag );

    if( memcmp( tmp, tagBuf, cbTag ) != 0 )
    {
        memset( pbDst, 0, cbData );
        return STATUS_UNSUCCESSFUL;
    }

cleanup:
    return status;

}



//
// GCM
//


template<>
VOID 
algImpKeyPerfFunction<ImpRsa32, AlgAes, ModeGcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    AesExpandKey( (AES_KEY *) buf1, buf2, keySize );
}

template<>
VOID
algImpDataPerfFunction<ImpRsa32,AlgAes, ModeGcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    AesGcm( (AES_KEY *)buf1,    // pKey
            NULL,               // pContext
            16,                 // dwBlockSize
            buf2, 12,           // IV
            buf2+16, (ULONG) dataSize,  // Input
            buf2+16 + PERF_BUFFER_SIZE/2,            // output
            NULL, 0,            // AuthData
            buf3, 16,           // Tag
            ENCRYPT );
}

template<>
VOID
algImpDecryptPerfFunction<ImpRsa32,AlgAes, ModeGcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    AesGcm( (AES_KEY *)buf1,    // pKey
            NULL,               // pContext
            16,                 // dwBlockSize
            buf2, 12,           // IV
            buf2+16 + PERF_BUFFER_SIZE/2, (ULONG) dataSize,  // Input
            buf2+16,            // output
            NULL, 0,            // AuthData
            buf3, 16,           // Tag
            DECRYPT );
}

template<>
VOID
algImpCleanPerfFunction<ImpRsa32,AlgAes, ModeGcm>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    RtlSecureZeroMemory( buf1, sizeof( AES_KEY ) );
}


AuthEncImp<ImpRsa32, AlgAes, ModeGcm>::AuthEncImp()
{
    m_perfKeyFunction     = &algImpKeyPerfFunction    <ImpRsa32, AlgAes, ModeGcm>;
    m_perfCleanFunction   = &algImpCleanPerfFunction  <ImpRsa32, AlgAes, ModeGcm>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpRsa32, AlgAes, ModeGcm>;
    m_perfDecryptFunction = &algImpDecryptPerfFunction<ImpRsa32, AlgAes, ModeGcm>;
}

template<>
AuthEncImp<ImpRsa32, AlgAes, ModeGcm>::~AuthEncImp()
{
}

template<>
std::set<SIZE_T>
AuthEncImp<ImpRsa32, AlgAes, ModeGcm>::getKeySizes()
{
    std::set<SIZE_T> res;

    res.insert( 16 );
    res.insert( 24 );
    res.insert( 32 );
    
    return res;
}


template<>
std::set<SIZE_T>
AuthEncImp<ImpRsa32, AlgAes, ModeGcm>::getNonceSizes()
{
    std::set<SIZE_T> res;

    res.insert( 12 );

    return res;
}


template<>
std::set<SIZE_T>
AuthEncImp<ImpRsa32, AlgAes, ModeGcm>::getTagSizes()
{
    std::set<SIZE_T> res;

    for( int i=12; i<=16; i ++ )
    {
        res.insert( i );
    }

    return res;
}

template<>
NTSTATUS
AuthEncImp<ImpRsa32, AlgAes, ModeGcm>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 16 || cbKey == 24 || cbKey == 32, "?" );
    AesExpandKey( &state.key, pbKey, cbKey );
    return STATUS_SUCCESS;
}

template<>
VOID
AuthEncImp<ImpRsa32, AlgAes, ModeGcm>::setTotalCbData( SIZE_T cbData )
{
    UNREFERENCED_PARAMETER( cbData );
}

template<>
NTSTATUS
AuthEncImp<ImpRsa32, AlgAes, ModeGcm>::encrypt(
        _In_reads_( cbNonce )       PCBYTE  pbNonce,      
                                    SIZE_T  cbNonce, 
        _In_reads_( cbAuthData )    PCBYTE  pbAuthData, 
                                    SIZE_T  cbAuthData, 
        _In_reads_( cbData )        PCBYTE  pbSrc, 
        _Out_writes_( cbData )      PBYTE   pbDst, 
                                    SIZE_T  cbData,
        _Out_writes_( cbTag )       PBYTE   pbTag, 
                                    SIZE_T  cbTag,
                                    ULONG   flags )
{
    NTSTATUS status = STATUS_SUCCESS;

    if( flags != 0 )
    {
        status = STATUS_NOT_SUPPORTED;
        goto cleanup;
    }

    status = AesGcm (   &state.key,
                         NULL,
                         16,
                         (PBYTE) pbNonce, (ULONG) cbNonce,
                         (PBYTE) pbSrc, (ULONG) cbData, pbDst,
                         (PBYTE) pbAuthData, (ULONG) cbAuthData,
                         pbTag, (ULONG) cbTag,
                         ENCRYPT );
    CHECK( NT_SUCCESS( status ), "GCM encrypt failure" );

cleanup:
    return status;
}


template<>
NTSTATUS
AuthEncImp<ImpRsa32, AlgAes, ModeGcm>::decrypt(
        _In_reads_( cbNonce )       PCBYTE  pbNonce,      
                                    SIZE_T  cbNonce, 
        _In_reads_( cbAuthData )    PCBYTE  pbAuthData, 
                                    SIZE_T  cbAuthData, 
        _In_reads_( cbData )        PCBYTE  pbSrc, 
        _Out_writes_( cbData )      PBYTE   pbDst, 
                                    SIZE_T  cbData,
        _In_reads_( cbTag )         PCBYTE  pbTag, 
                                    SIZE_T  cbTag,
                                    ULONG   flags )
{
    NTSTATUS status = STATUS_SUCCESS;

    if( flags != 0 )
    {
        status = STATUS_NOT_SUPPORTED;
        goto cleanup;
    }

    status = AesGcm (   &state.key,
                         NULL,
                         16,
                         (PBYTE) pbNonce, (ULONG) cbNonce,
                         (PBYTE) pbSrc, (ULONG) cbData, pbDst,
                         (PBYTE) pbAuthData, (ULONG) cbAuthData,
                         (PBYTE) pbTag, (ULONG) cbTag,
                         DECRYPT );

    if( !NT_SUCCESS( status ) )
    {
        memset( pbDst, 0, cbData );
    }

cleanup:
    return status;
}



//////////////////////////
// RC4


template<>
VOID 
algImpKeyPerfFunction< ImpRsa32, AlgRc4>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    rc4_key( (RC4_KEYSTRUCT *) buf1, (unsigned int) keySize, buf2 );
}

template<>
VOID
algImpDataPerfFunction<ImpRsa32,AlgRc4>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf2 );

    rc4( (RC4_KEYSTRUCT *) buf1, (unsigned int) dataSize, buf3 );
}

template<>
VOID
algImpCleanPerfFunction<ImpRsa32,AlgRc4>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    RtlSecureZeroMemory( buf1, sizeof( RC4_KEYSTRUCT ) );
}


StreamCipherImp<ImpRsa32, AlgRc4>::StreamCipherImp()
{
    m_perfKeyFunction     = &algImpKeyPerfFunction    <ImpRsa32, AlgRc4>;
    m_perfCleanFunction   = &algImpCleanPerfFunction  <ImpRsa32, AlgRc4>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpRsa32, AlgRc4>;
}

template<>
StreamCipherImp<ImpRsa32, AlgRc4>::~StreamCipherImp()
{
    RtlSecureZeroMemory( &state.state, sizeof( state.state ) ); 
}

template<>
std::set<SIZE_T> StreamCipherImp<ImpRsa32, AlgRc4>::getNonceSizes()
{
    std::set<SIZE_T> res;

    // No nonce sizes supported for RC4

    return res;
}

template<>
std::set<SIZE_T> StreamCipherImp<ImpRsa32, AlgRc4>::getKeySizes()
{
    std::set<SIZE_T> res;
    SIZE_T maxKeySize = 256;

    for( SIZE_T i=1; i<=maxKeySize; i++ )
    {
        res.insert( i );
    }

    return res;
}

template<>
NTSTATUS
StreamCipherImp<ImpRsa32, AlgRc4>::setNonce( PCBYTE pbNonce, SIZE_T cbNonce )
{
    UNREFERENCED_PARAMETER( pbNonce );

    CHECK( cbNonce == 0, "RC4 does not take a nonce" );

    return STATUS_SUCCESS;
}

template<>
VOID
StreamCipherImp< ImpRsa32, AlgRc4>::setOffset( UINT64 offset )
{
    UNREFERENCED_PARAMETER( offset );
    CHECK( FALSE, "RC4 is not random access" );
}

template<>
NTSTATUS
StreamCipherImp<ImpRsa32, AlgRc4>::setKey( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey > 0 && cbKey <= 256, "?" );
    rc4_key( &state.state, (unsigned int) cbKey, (PBYTE) pbKey );
    return STATUS_SUCCESS;
}

template<>
VOID
StreamCipherImp<ImpRsa32, AlgRc4>::encrypt( 
    _In_reads_( cbData )   PCBYTE pbSrc, 
    _Out_writes_( cbData )  PBYTE pbDst, 
                            SIZE_T cbData )
{
    memcpy( pbDst, pbSrc, cbData );
    rc4( &state.state, (unsigned int) cbData, pbDst );
}

VOID
addRsa32Algs()
{
    //
    // RSA32.lib fast AES needs initializing.
    //
    AesInitialize();

    addImplementationToGlobalList<HashImp<ImpRsa32,AlgMd2>>();
    addImplementationToGlobalList<HashImp<ImpRsa32,AlgMd4>>();
    addImplementationToGlobalList<HashImp<ImpRsa32b,AlgMd4>>();     // Old MD4 implementation in RSA32.lib
    addImplementationToGlobalList<HashImp<ImpRsa32,AlgMd5>>();
    addImplementationToGlobalList<HashImp<ImpRsa32,AlgSha1>>();
    addImplementationToGlobalList<HashImp<ImpRsa32,AlgSha256>>();
    addImplementationToGlobalList<HashImp<ImpRsa32,AlgSha384>>();
    addImplementationToGlobalList<HashImp<ImpRsa32,AlgSha512>>();

    addImplementationToGlobalList<MacImp<ImpRsa32, AlgHmacMd5>>();
    addImplementationToGlobalList<MacImp<ImpRsa32, AlgHmacSha1>>();

    addImplementationToGlobalList<BlockCipherImp<ImpRsa32, AlgAes, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpRsa32, AlgAes, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpRsa32b, AlgAes, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpRsa32b, AlgAes, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpRsa32b, AlgAes, ModeCfb>>();

    addImplementationToGlobalList<BlockCipherImp<ImpRsa32, AlgDes, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpRsa32, AlgDes, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpRsa32, AlgDes, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpRsa32, Alg2Des, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpRsa32, Alg2Des, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpRsa32, Alg2Des, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpRsa32, Alg3Des, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpRsa32, Alg3Des, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpRsa32, Alg3Des, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpRsa32, AlgDesx, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpRsa32, AlgDesx, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpRsa32, AlgDesx, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpRsa32, AlgRc2, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpRsa32, AlgRc2, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpRsa32, AlgRc2, ModeCfb>>();

    addImplementationToGlobalList<AuthEncImp<ImpRsa32, AlgAes, ModeCcm>>();
    addImplementationToGlobalList<AuthEncImp<ImpRsa32, AlgAes, ModeGcm>>();

    addImplementationToGlobalList<StreamCipherImp<ImpRsa32, AlgRc4>>();
}

#endif //INCLUDE_IMPL_RSA32






