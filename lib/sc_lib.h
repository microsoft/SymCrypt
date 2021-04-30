//
// sc_lib.h
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//


//#define SYMCRYPT_DISABLE_CFG
#if SYMCRYPT_MS_VC
#define SYMCRYPT_DISABLE_CFG    __declspec(guard(nocf))
#else
#define SYMCRYPT_DISABLE_CFG
#endif

#include "sc_lib-testhooks.h"

#include <symcrypt_low_level.h>

// Types

typedef int                 BOOL;

#if !defined(TRUE)
#define TRUE  (1)
#endif

#if !defined(FALSE)
#define FALSE (0)
#endif

#if !defined(UNREFERENCED_PARAMETER)
#define UNREFERENCED_PARAMETER(x)   ((void)x)
#endif

#if !defined(FAST_FAIL_CRYPTO_LIBRARY)
#define FAST_FAIL_CRYPTO_LIBRARY    22
#endif

//
// Our Wipe code uses FORCE_WRITE* which are implemented using
// WriteNoFence* functions. Unfortunately, they declare their parameter
// to be interlocked, and the compiler complains when we also access the variable
// using non-interlocked code.
// This warning is nonsensical in our situation, so we disable it.
// The second warning is about accessing a local variable via an interlocked ptr.
//
#pragma prefast( disable:28112 )
#pragma prefast( disable:28113 )
#pragma warning( disable: 4702 )        // unreachable code. The compilers are not equally smart, and some complain
                                        // about 'function must return a value' and some about 'unreachable code'


//
// Internal definitions for the symcrypt library.
// This include file is used only for the files inside the library, not by
// the code that calls the library.
//

//
// These macros allow a bunch of generic code to be written.
// For example, the Hash append function is written once generically
// using these macros.
//

#define CONCAT_I2( a, b )       a##b
#define CONCAT_I3( a, b, c )    a##b##c


#define CONCAT2( a, b )         CONCAT_I2( a, b )
#define CONCAT3( a, b, c )      CONCAT_I3( a, b, c )
//#define CONCAT4( a, b, c, d)    a##b##c##d



#define SYMCRYPT_XXX_STATE              CONCAT3( SYMCRYPT_, ALG, _STATE )

#define SYMCRYPT_Xxx                    CONCAT2( SymCrypt, Alg )

#define SYMCRYPT_XxxStateCopy           CONCAT3( SymCrypt, Alg, StateCopy )
#define SYMCRYPT_XxxInit                CONCAT3( SymCrypt, Alg, Init )
#define SYMCRYPT_XxxAppend              CONCAT3( SymCrypt, Alg, Append )
#define SYMCRYPT_XxxResult              CONCAT3( SymCrypt, Alg, Result )
#define SYMCRYPT_XxxAppendBlocks        CONCAT3( SymCrypt, Alg, AppendBlocks )

#define SYMCRYPT_HmacXxx                CONCAT2( SymCryptHmac, Alg )
#define SYMCRYPT_HmacXxxStateCopy       CONCAT3( SymCryptHmac, Alg, StateCopy )
#define SYMCRYPT_HmacXxxKeyCopy         CONCAT3( SymCryptHmac, Alg, KeyCopy )
#define SYMCRYPT_HmacXxxExpandKey       CONCAT3( SymCryptHmac, Alg, ExpandKey )
#define SYMCRYPT_HmacXxxInit            CONCAT3( SymCryptHmac, Alg, Init )
#define SYMCRYPT_HmacXxxAppend          CONCAT3( SymCryptHmac, Alg, Append )
#define SYMCRYPT_HmacXxxResult          CONCAT3( SymCryptHmac, Alg, Result )


#define SYMCRYPT_XXX_INPUT_BLOCK_SIZE   CONCAT3( SYMCRYPT_, ALG, _INPUT_BLOCK_SIZE )
#define SYMCRYPT_XXX_RESULT_SIZE        CONCAT3( SYMCRYPT_, ALG, _RESULT_SIZE )

#define SYMCRYPT_HMAC_XXX_INPUT_BLOCK_SIZE  SYMCRYPT_XXX_INPUT_BLOCK_SIZE
#define SYMCRYPT_HMAC_XXX_RESULT_SIZE       SYMCRYPT_XXX_RESULT_SIZE

#define PSYMCRYPT_HMAC_XXX_EXPANDED_KEY     CONCAT3( PSYMCRYPT_HMAC_, ALG, _EXPANDED_KEY )
#define PCSYMCRYPT_HMAC_XXX_EXPANDED_KEY    CONCAT3( PCSYMCRYPT_HMAC_, ALG, _EXPANDED_KEY )
#define SYMCRYPT_HMAC_XXX_STATE             CONCAT3( SYMCRYPT_HMAC_, ALG, _STATE )
#define PSYMCRYPT_HMAC_XXX_STATE            CONCAT3( PSYMCRYPT_HMAC_, ALG, _STATE )
#define PCSYMCRYPT_HMAC_XXX_STATE            CONCAT3( PCSYMCRYPT_HMAC_, ALG, _STATE )


//==============================================================================================
//  PLATFORM SPECIFICS
//==============================================================================================

#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64

//
// The XMM save/restore functions need to be passed a buffer in which they can store their data.
// We have two different places where we use this, in kernel mode and in user mode (while testing)
// We can't declare a union of the two structs as we can't include the kernel-mode headers in this file
// when compiled for a user-mode app.
// Instead we define a structure with reserved space, and have each environment check the size and
// cast the pointer.
//
// We always use the KeSaveExtendedProcessorState call, and not the KeSaveFloatingPointState as it
// allows us to save only the XMM registers and not touch the X87/MMX registers which should
// save time.
//
#if SYMCRYPT_CPU_X86

//
// The XSTATE_SAVE structure consists of a union between
//  struct:
//      - INT64             8
//      - INT32             4
//      - Pointer           4
//      - Pointer           4
//      - Pointer           4
//      - Pointer           4
//      - BYTE              1 + 3 padding
//                          32 total
// - XSTATE_CONTEXT
//      - UINT64            8
//      - UINT32            4
//      - UINT32            4
//      - Pointer + UINT32  8
//      - Pointer + UINT32  8
//                          32 total
//
// Experimentally: need 4 more bytes, don't know why yet.
// Should have a look with the debugger when I have time.
//

#define SYMCRYPT_XSTATE_SAVE_SIZE    (32)

#elif SYMCRYPT_CPU_AMD64

//
// The XSTATE_SAVE structure consists of
// - pointer            8
// - pointer            8
// - BYTE               1 + 7 padding
// - XSTATE_CONTEXT
//      - UINT64        8
//      - UINT32        4
//      - UINT32        4
//      - Pointer       8
//      - Pointer       8
//
#define SYMCRYPT_XSTATE_SAVE_SIZE    (56)

#endif

typedef
SYMCRYPT_ALIGN
struct _SYMCRYPT_EXTENDED_SAVE_DATA {
    SYMCRYPT_ALIGN  BYTE    data[SYMCRYPT_XSTATE_SAVE_SIZE];
                    SYMCRYPT_MAGIC_FIELD
} SYMCRYPT_EXTENDED_SAVE_DATA, *PSYMCRYPT_EXTENDED_SAVE_DATA;


//
// Two functions to save/restore the XMM registers.
// These must ALWAYS be called in pairs, even if the SaveXmm function returned an error.
// XMM registers cannot be used if the save function returned an error.
// If the SYMCRYPT_CPU_FEATURE_SAVEXMM_NOFAIL feature is present, then the
// SymCryptSaveXmm function will never return an error.
//

//
// Functions to save/restore the XMM or YMM registers.
// If the Save*mm function is called and succeeds, then the corresponding
// Restore*mm function MUST be called later on the same thread.
// The extended registers cannot be called if the Save function returns an error.
//

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptSaveXmm( _Out_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveData );

VOID
SYMCRYPT_CALL
SymCryptRestoreXmm( _Inout_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveData );


SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptSaveYmm( _Out_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveData );

VOID
SYMCRYPT_CALL
SymCryptRestoreYmm( _Inout_ PSYMCRYPT_EXTENDED_SAVE_DATA pSaveData );
#endif


//==============================================================================================
//  Library declarations
//==============================================================================================

//
// Function to check that the library has been initialized
//
#if defined( DBG )

VOID
SYMCRYPT_CALL
SymCryptLibraryWasNotInitialized();

FORCEINLINE
VOID
SYMCRYPT_CALL
SymCryptCheckLibraryInitialized()
{
    if( !(g_SymCryptFlags & SYMCRYPT_FLAG_LIB_INITIALIZED)  )
    {
        SymCryptLibraryWasNotInitialized();
    }
}
#else
FORCEINLINE
VOID
SYMCRYPT_CALL
SymCryptCheckLibraryInitialized()
{
}
#endif

#define HMAC_IPAD_BYTE   0x36
#define HMAC_OPAD_BYTE   0x5c

// SYMCRYPT_CPU_FEATURES
#define SYMCRYPT_CPU_FEATURES_FOR_PCLMULQDQ_CODE  (SYMCRYPT_CPU_FEATURE_PCLMULQDQ | SYMCRYPT_CPU_FEATURE_SSSE3 | SYMCRYPT_CPU_FEATURE_SAVEXMM_NOFAIL )

#define SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE (SYMCRYPT_CPU_FEATURE_SSSE3 | SYMCRYPT_CPU_FEATURE_AESNI)
#define SYMCRYPT_CPU_FEATURES_FOR_AESNI_PCLMULQDQ_CODE (SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE | SYMCRYPT_CPU_FEATURES_FOR_PCLMULQDQ_CODE)
#define SYMCRYPT_CPU_FEATURES_FOR_VAES_256_CODE (SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE | SYMCRYPT_CPU_FEATURE_VAES_256)
#define SYMCRYPT_CPU_FEATURES_FOR_VAES_512_CODE (SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE | SYMCRYPT_CPU_FEATURE_VAES_512)

#define SYMCRYPT_CPU_FEATURES_FOR_SHANI_CODE (SYMCRYPT_CPU_FEATURE_SSSE3 | SYMCRYPT_CPU_FEATURE_SHANI)

#define SYMCRYPT_CPU_FEATURES_FOR_MULX (SYMCRYPT_CPU_FEATURE_BMI2 | SYMCRYPT_CPU_FEATURE_ADX | SYMCRYPT_CPU_FEATURE_SSE2 )

//
// ROTATE OPERATIONS
//
//
// If this lib is ever ported to a platform that doesn't have the _rotx functions
// the macros can be replaced by portable definitions just like the ROL16/ROR16
//

#define ROL16( x, n ) ((UINT16)( ( ((x) << (n)) | ((x) >> (16-(n))) ) ))
#define ROR16( x, n ) ((UINT16)( ( ((x) >> (n)) | ((x) << (16-(n))) ) ))

#if SYMCRYPT_MS_VC
    #define ROL32( x, n ) _rotl( (x), (n) )
    #define ROR32( x, n ) _rotr( (x), (n) )
    #define ROL64( x, n ) _rotl64( (x), (n) )
    #define ROR64( x, n ) _rotr64( (x), (n) )
#elif SYMCRYPT_APPLE_CC || SYMCRYPT_GNUC
    #define ROL32( x, n ) ((UINT32)( ( ((x) << (n)) | ((x) >> (32-(n))) ) ))
    #define ROR32( x, n ) ((UINT32)( ( ((x) >> (n)) | ((x) << (32-(n))) ) ))
    #define ROL64( x, n ) ((UINT64)( ( ((x) << (n)) | ((x) >> (64-(n))) ) ))
    #define ROR64( x, n ) ((UINT64)( ( ((x) >> (n)) | ((x) << (64-(n))) ) ))
#else
    #error Unknown compiler
#endif


#define SYMCRYPT_ARRAY_SIZE(_x)     (sizeof(_x)/sizeof(_x[0]))

enum{
    STATE_NEXT = 0,         // starting state = 0, set by structure wipe.
    STATE_DATA_START,
    STATE_DATA_END,
    STATE_RESULT2,          // 2nd phase of result computation (1st phase is at STATE_NEXT when the result operation is found)
    STATE_RESULT_DONE,      // 3rd phase of result computation
};



//==========================================================================
// Inline implementations ...
//==========================================================================

//
// These are a bunch of functions to convert between an array of
// 32 or 64-bit integers to an array of bytes in LSBfirst or MSBfirst convention.
// Not all variations have been implemented yet. We add them as they are
// needed.
//

//
// These implementations are optimized for inlining, especially when the
// size of the data to be convered is a compile-time constant.
//

//
// SymCryptUint32ToMsbFirst & SymCryptMsbFirstToUint32.
// This is used by the SHA family
//
#if SYMCRYPT_CPU_AMD64

//
// On AMD64 we can do 2 UINT32s at once by doing a ROL(x,32) and a BSWAP.
//
FORCEINLINE
VOID
SYMCRYPT_CALL
SymCryptUint32ToMsbFirst( _In_reads_(cuData)     PCUINT32 puData,
                          _Out_writes_(4*cuData) PBYTE    pbResult,
                                                 SIZE_T   cuData )
{
    while( cuData >= 2 )
    {
        SYMCRYPT_STORE_MSBFIRST64( pbResult, ROL64( *(UINT64*)puData, 32 ));
        pbResult += 8;
        puData += 2;
        cuData -= 2;
    }

    if( cuData != 0 )
    {
        SYMCRYPT_STORE_MSBFIRST32( pbResult, *puData );
    }
}

#else // not _AMD64_

FORCEINLINE
VOID
SYMCRYPT_CALL
SymCryptUint32ToMsbFirst( _In_reads_(cuData)     PCUINT32 puData,
                          _Out_writes_(4*cuData) PBYTE    pbResult,
                                                 SIZE_T   cuData )
{
    while( cuData != 0 )
    {
        SYMCRYPT_STORE_MSBFIRST32( pbResult, *puData );
        puData++;
        pbResult += 4;
        cuData--;
    }
}
#endif // platform switch for SymCryptUint32ToMsbFirst

FORCEINLINE
VOID
SYMCRYPT_CALL
SymCryptMsbFirstToUint32( _In_reads_(4*cuResult) PCBYTE  pbData,
                          _Out_writes_(cuResult) PUINT32 puResult,
                                                 SIZE_T  cuResult )
{
    while( cuResult != 0 )
    {
        *puResult = SYMCRYPT_LOAD_MSBFIRST32( pbData );
        puResult++;
        pbData += 4;
        cuResult--;
    }
}


//
// SymCryptUint32ToLsbFirst & SymCryptLsbFirstToUint32
// These are used by the MD4 and MD5 hash functions
//
#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64 | SYMCRYPT_CPU_ARM | SYMCRYPT_CPU_ARM64

//
// On AMD64, X86, and ARM this is just a memcpy
//
FORCEINLINE
VOID
SYMCRYPT_CALL
SymCryptUint32ToLsbFirst( _In_reads_(cuData)     PCUINT32 puData,
                          _Out_writes_(4*cuData) PBYTE    pbResult,
                                                 SIZE_T   cuData )

{
    memcpy( pbResult, puData, 4*cuData );
}

FORCEINLINE
VOID
SYMCRYPT_CALL
SymCryptLsbFirstToUint32( _In_reads_(4*cuResult) PCBYTE  pbData,
                          _Out_writes_(cuResult) PUINT32 puResult,
                                                 SIZE_T  cuResult )
{
    memcpy( puResult, pbData, 4*cuResult );
}

#else // not AMD64_ or X86_

FORCEINLINE
VOID
SYMCRYPT_CALL
SymCryptUint32ToLsbFirst( _In_reads_(cuData)     PCUINT32 puData,
                          _Out_writes_(4*cuData) PBYTE    pbResult,
                                                 SIZE_T   cuData )
{
    while( cuData != 0 )
    {
        SYMCRYPT_STORE_LSBFIRST32( pbResult, *puData );
        puData++;
        pbResult += 4;
        cuData--;
    }
}

FORCEINLINE
VOID
SYMCRYPT_CALL
SymCryptLsbFirstToUint32( _In_reads_(4*cuResult) PCBYTE  pbData,
                          _Out_writes_(cuResult) PUINT32 puResult,
                                                 SIZE_T  cuResult )
{
    while( cuResult != 0 )
    {
        *puResult = SYMCRYPT_LOAD_LSBFIRST32( pbData );
        pbData += 4;
        puResult++;
        cuResult--;
    }
}

#endif // Platform switch for SymCryptUint32ToLsbFirst



//
// SymCryptUint64ToMsbFirst & SymCryptMsbFirstToUint64
//
FORCEINLINE
VOID
SYMCRYPT_CALL
SymCryptUint64ToMsbFirst( _In_reads_(cuData)     PCUINT64    puData,
                          _Out_writes_(8*cuData) PBYTE       pbResult,
                                                 SIZE_T      cuData )
{
    while( cuData != 0 )
    {
        SYMCRYPT_STORE_MSBFIRST64( pbResult, *puData );
        pbResult += 8;
        puData ++;
        cuData --;
    }
}

FORCEINLINE
VOID
SYMCRYPT_CALL
SymCryptMsbFirstToUint64( _In_reads_(8*cuResult) PCBYTE      pbData,
                          _Out_writes_(cuResult) PUINT64  puResult,
                                                 SIZE_T      cuResult )
{
    while( cuResult != 0 )
    {
        *puResult = SYMCRYPT_LOAD_MSBFIRST64( pbData );
        puResult++;
        pbData += 8;
        cuResult--;
    }
}

////////////////////////////////////////////////////////////////////////////////////
//  Internal function prototypes
//

//
// SymCryptSha1AppendBlocks
//
// Updates the chaining state of the hash function with one or more blocks of data.
// Each block is 64 bytes long, the natural size of a SHA256 input block.
//
// cbData must be a multiple of 64.
//
VOID
SYMCRYPT_CALL
SymCryptSha1AppendBlocks(
    _Inout_                 SYMCRYPT_SHA1_CHAINING_STATE  * pChain,
    _In_reads_( cbData )    PCBYTE                          pbData,
                            SIZE_T                          cbData,
    _Out_                   SIZE_T                        * pcbRemaining );

//
// SymCryptSha256AppendBlocks
//
// Updates the chaining state of the hash function with one or more blocks of data.
// Each block is 64 bytes long, the natural size of a SHA256 input block.
//
// cbData must be a multiple of 64.
//
VOID
SYMCRYPT_CALL
SymCryptSha256AppendBlocks(
    _Inout_                 SYMCRYPT_SHA256_CHAINING_STATE    * pChain,
    _In_reads_( cbData )    PCBYTE                              pbData,
                            SIZE_T                              cbData,
    _Out_                   SIZE_T                            * pcbRemaining );


//
// SymCryptSha512AppendBlocks
//
// Updates the chaining state of the hash function with one or more blocks of data.
// Each block is 128 bytes long, the natural size of a SHA512 input block.
//
// cbData must be a multiple of 128.
//
VOID
SYMCRYPT_CALL
SymCryptSha512AppendBlocks(
    _Inout_                 SYMCRYPT_SHA512_CHAINING_STATE    * pChain,
    _In_reads_( cbData )    PCBYTE                              pbData,
                            SIZE_T                              cbData,
    _Out_                   SIZE_T                            * pcbRemaining );


VOID
SYMCRYPT_CALL
SymCryptSha512AppendBlocks_xmm(
    _Inout_                 SYMCRYPT_SHA512_CHAINING_STATE  *   pChain,
    _In_reads_(cbData)      PCBYTE                              pbData,
                            SIZE_T                              cbData,
    _Out_                   SIZE_T                            * pcbRemaining );

//
// SymCryptMd5AppendBlocks
//
// Updates the chaining state of the hash function with one or more blocks of data.
// Each block is 64 bytes long, the natural size of a MD5 input block.
//
// cbData must be a multiple of 64.
//
VOID
SYMCRYPT_CALL
SymCryptMd5AppendBlocks(
    _Inout_                 SYMCRYPT_MD5_CHAINING_STATE   * pChain,
    _In_reads_( cbData )    PCBYTE                          pbData,
                            SIZE_T                          cbData,
    _Out_                   SIZE_T                        * pcbRemaining );


//
// SymCryptMd4AppendBlocks
//
// Updates the chaining state of the hash function with one or more blocks of data.
// Each block is 64 bytes long, the natural size of a MD5 input block.
//
// cbData must be a multiple of 64.
//
VOID
SYMCRYPT_CALL
SymCryptMd4AppendBlocks(
    _Inout_                 SYMCRYPT_MD4_CHAINING_STATE   * pChain,
    _In_reads_( cbData )    PCBYTE                          pbData,
                            SIZE_T                          cbData,
    _Out_                   SIZE_T                        * pcbRemaining );


//
// SymCryptMd2AppendBlock
//
// Update the C and X state based on the message block in the buffer.
//
VOID
SYMCRYPT_CALL
SymCryptMd2AppendBlocks(
    _Inout_                 SYMCRYPT_MD2_CHAINING_STATE   * pChain,
    _In_reads_( cbData )    PCBYTE                          pbData,
                            SIZE_T                          cbData,
    _Out_                   SIZE_T                        * pcbRemaining );


//
// SymCryptUint32ToMsbFirst
//
// Convert an array of UINT32s to 4-byte values stored MSB first (big-endian) conversion.
// Note that the count is the number of UINT32s to convert, not the number
// of bytes. This is somewhat unusual, but it avoids any confusion about
// converting an odd number of bytes.
//
VOID
SYMCRYPT_CALL
SymCryptUint32ToMsbFirst( _In_reads_(cuData)     PCUINT32 puData,
                          _Out_writes_(4*cuData) PBYTE    pbResult,
                                                 SIZE_T   cuData );

//
// SymCryptUint32ToLsbFirst
//
// Convert an array of UINT32s to 4-byte values stored LSB first (little-endian) conversion.
// Note that the count is the number of UINT32s to convert, not the number
// of bytes. This is somewhat unusual, but it avoids any confusion about
// converting an odd number of bytes.
//
VOID
SYMCRYPT_CALL
SymCryptUint32ToLsbFirst( _In_reads_(cuData)     PCUINT32 puData,
                          _Out_writes_(4*cuData) PBYTE    pbResult,
                                                 SIZE_T   cuData );

//
// SymCryptMsbFirstToUint32
//
// Convert an array of 4-byte values stored MSB first to an array of UINT32s
// (big-endian) conversion.
// Note that the count is the number of UINT32s to convert, not the number
// of bytes. This is somewhat unusual, but it avoids any confusion about
// converting an odd number of bytes.
//
VOID
SYMCRYPT_CALL
SymCryptMsbFirstToUint32( _In_reads_(4*cuResult) PCBYTE   pbData,
                          _Out_writes_(cuResult) PUINT32  puResult,
                                                 SIZE_T   cuResult );

//
// SymCryptLsbFirstToUint32
//
// Convert an array of 4-byte values stored LSB first to an array of UINT32s
// (little-endian) conversion.
// Note that the count is the number of UINT32s to convert, not the number
// of bytes. This is somewhat unusual, but it avoids any confusion about
// converting an odd number of bytes.
//
VOID
SYMCRYPT_CALL
SymCryptLsbFirstToUint32( _In_reads_(4*cuResult) PCBYTE  pbData,
                          _Out_writes_(cuResult) PUINT32 puResult,
                                                 SIZE_T  cuResult );

//
// SymCryptUint64ToMsbFirst
//
// Convert an array of UINT64s to an array of bytes using the MSB first
// (big-endian) conversion.
//
VOID
SYMCRYPT_CALL
SymCryptUint64ToMsbFirst( _In_reads_(cuData)     PCUINT64    puData,
                          _Out_writes_(8*cuData) PBYTE       pbResult,
                                                 SIZE_T      cuData );

//
// SymCryptMsbFirstToUint64
//
// Convert an array of 4-byte values stored MSB first to an array of UINT64s
// (big-endian) conversion.
// Note that the count is the number of UINT64s to convert, not the number
// of bytes. This is somewhat unusual, but it avoids any confusion about
// converting an odd number of bytes.
//
VOID
SYMCRYPT_CALL
SymCryptMsbFirstToUint64( _In_reads_(8*cuResult) PCBYTE      pbData,
                          _Out_writes_(cuResult) PUINT64      puResult,
                                                 SIZE_T      cuResult );



//============================================================================
// HMAC macros and inline functions.
//
#define REPEAT_BYTE_TO_UINT32( x ) (((UINT32)x << 24) | ((UINT32)x << 16) | ((UINT32)x << 8) | x)
#define REPEAT_BYTE_TO_UINT64( x ) ( ((UINT64)REPEAT_BYTE_TO_UINT32(x) << 32) | REPEAT_BYTE_TO_UINT32(x) )

//
// The XorByteIntoBuffer function is a platform-optimized function to xor a byte
// repeatedly into a buffer.
// Note that the buffer length must be a multiple of 8.
//
#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64 | SYMCRYPT_CPU_ARM | SYMCRYPT_CPU_ARM64
FORCEINLINE
VOID
SYMCRYPT_CALL
XorByteIntoBuffer( _Inout_updates_( 8*cqBuf ) PBYTE pbBuf, SIZE_T cqBuf, BYTE v )
{
    SIZE_T i;
    const UINT64 v64 = REPEAT_BYTE_TO_UINT64( v );

    for( i=0; i<cqBuf; i++ )
    {
        ((UINT64 *)pbBuf)[i] ^= v64;
    }
}
#else
FORCEINLINE
VOID
SYMCRYPT_CALL
XorByteIntoBuffer( _Inout_updates_( 8*cqBuf ) PBYTE pbBuf, SIZE_T cqBuf, BYTE v )
{
    SIZE_T i;

    for( i=0; i<8*cqBuf; i++ )
    {
        pbBuf[i] ^= v;
    }
}
#endif

//
// GHASH
//

VOID
SYMCRYPT_CALL
SymCryptGHashExpandKey(
    _Out_                                       PSYMCRYPT_GHASH_EXPANDED_KEY    expandedKey,
    _In_reads_( SYMCRYPT_GF128_BLOCK_SIZE )     PCBYTE                          pH );

VOID
SYMCRYPT_CALL
SymCryptGHashExpandKeyC(
    _Out_writes_( SYMCRYPT_GF128_FIELD_SIZE )   PSYMCRYPT_GF128_ELEMENT expandedKey,
    _In_reads_( SYMCRYPT_GF128_BLOCK_SIZE )     PCBYTE                  pH );

VOID
SYMCRYPT_CALL
SymCryptGHashExpandKeyX86(
    _Out_                                   PSYMCRYPT_GHASH_EXPANDED_KEY    expandedKey,
   _In_reads_( SYMCRYPT_GF128_BLOCK_SIZE )  PCBYTE                          pH );

VOID
SYMCRYPT_CALL
SymCryptGHashExpandKeyAmd64(
    _Out_writes_( SYMCRYPT_GF128_FIELD_SIZE )   PSYMCRYPT_GF128_ELEMENT expandedKey,
    _In_reads_( SYMCRYPT_GF128_BLOCK_SIZE )     PCBYTE                  pH );

VOID
SYMCRYPT_CALL
SymCryptGHashAppendData(
    _In_                    PCSYMCRYPT_GHASH_EXPANDED_KEY   expandedKey,
    _Inout_                 PSYMCRYPT_GF128_ELEMENT         pState,
    _In_reads_( cbData )    PCBYTE                          pbData,
    _In_                    SIZE_T                          cbData );

VOID
SYMCRYPT_CALL
SymCryptGHashAppendDataC(
    _In_reads_( SYMCRYPT_GF128_FIELD_SIZE )     PCSYMCRYPT_GF128_ELEMENT    expandedKeyTable,
    _Inout_                                     PSYMCRYPT_GF128_ELEMENT     pState,
    _In_reads_( cbData )                        PCBYTE                      pbData,
    _In_                                        SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptGHashAppendDataXmm(
    _In_reads_( SYMCRYPT_GF128_FIELD_SIZE ) PCSYMCRYPT_GF128_ELEMENT    expandedKeyTable,
    _Inout_                                 PSYMCRYPT_GF128_ELEMENT     pState,
    _In_reads_( cbData )                    PCBYTE                      pbData,
    _In_                                    SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptGHashAppendDataNeon(
    _In_reads_( SYMCRYPT_GF128_FIELD_SIZE )     PCSYMCRYPT_GF128_ELEMENT    expandedKeyTable,
    _Inout_                                     PSYMCRYPT_GF128_ELEMENT     pState,
    _In_reads_( cbData )                        PCBYTE                      pbData,
    _In_                                        SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptGHashAppendDataPclmulqdq(
    _In_reads_( SYMCRYPT_GF128_FIELD_SIZE ) PCSYMCRYPT_GF128_ELEMENT    expandedKeyTable,
    _Inout_                                 PSYMCRYPT_GF128_ELEMENT     pState,
    _In_reads_( cbData )                    PCBYTE                      pbData,
    _In_                                    SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptGHashResult(
    _In_                                        PCSYMCRYPT_GF128_ELEMENT    pState,
    _Out_writes_( SYMCRYPT_GF128_BLOCK_SIZE )   PBYTE                       pbResult );


VOID
SYMCRYPT_CALL
SymCryptMarvin32AppendBlocks(
    _Inout_                 PSYMCRYPT_MARVIN32_CHAINING_STATE   pChain,
    _In_reads_( cbData )    PCBYTE                              pbData,
                            SIZE_T                              cbData );




//
// See symcrypt_testsupport.h for more details of the testing support infrastructure.
//

extern const BYTE SymCryptTestMsg3[3];
extern const BYTE SymCryptTestMsg16[16];
extern const BYTE SymCryptTestKey32[32];

VOID
SYMCRYPT_CALL
SymCryptInjectError( PBYTE pbData, SIZE_T cbData );


#define SYMCRYPT_CPUID_DETECT_FLAG_CHECK_OS_SUPPORT_FOR_YMM  1      // enable checking of OSXSAVE bit & XGETBV logic

VOID
SYMCRYPT_CALL
SymCryptDetectCpuFeaturesByCpuid( UINT32 flags );

VOID
SYMCRYPT_CALL
SymCryptDetectCpuFeaturesFromRegisters();

VOID
SYMCRYPT_CALL
SymCryptDetectCpuFeaturesFromRegistersNoTry();

VOID
SYMCRYPT_CALL
SymCryptDetectCpuFeaturesFromIsProcessorFeaturePresent();

VOID
SYMCRYPT_CALL
SymCryptCpuidExFunc( int cpuInfo[4], int function_id, int subfunction_id );

////////////////////////////////////////////////////////////////////////////
// Export blob formats
////////////////////////////////////////////////////////////////////////

//==========================================================
// BLOBS
//
// SYMCRYPT_BLOB_HEADER
// Generic header for all exported blobs from SymCrypt
//

typedef enum _SYMCRYPT_BLOB_TYPE {
    SymCryptBlobTypeUnknown     = 0,
    SymCryptBlobTypeHashState   = 0x100,
    SymCryptBlobTypeMd2State    = SymCryptBlobTypeHashState + 1,       // explicit constants as these have to remain the same forever.
    SymCryptBlobTypeMd4State    = SymCryptBlobTypeHashState + 2,
    SymCryptBlobTypeMd5State    = SymCryptBlobTypeHashState + 3,
    SymCryptBlobTypeSha1State   = SymCryptBlobTypeHashState + 4,
    SymCryptBlobTypeSha256State = SymCryptBlobTypeHashState + 5,
    SymCryptBlobTypeSha384State = SymCryptBlobTypeHashState + 6,
    SymCryptBlobTypeSha512State = SymCryptBlobTypeHashState + 7,
} SYMCRYPT_BLOB_TYPE;

#define SYMCRYPT_BLOB_MAGIC ('cmys')

//
// We define all export structures with pack=1 so that there are no padding bytes.
//
#pragma pack(push, 1)

typedef struct _SYMCRYPT_BLOB_HEADER {
    UINT32              magic;              // 'cmys'
    UINT32              size;               // total size of blob
    UINT32              type;               // SYMCRYPT_BLOB_TYPE: type of blob
} SYMCRYPT_BLOB_HEADER, *PSYMCRYPT_BLOB_HEADER;

typedef struct _SYMCRYPT_BLOB_TRAILER {
    BYTE                checksum[8];        // contains the Marvin32 checksum of the rest of the blob
} SYMCRYPT_BLOB_TRAILER, *PSYMCRYPT_BLOB_TRAILER;

typedef struct _SYMCRYPT_MD2_STATE_EXPORT_BLOB {
    SYMCRYPT_BLOB_HEADER    header;
    BYTE                    C[16];
    BYTE                    X[16];
    UINT32                  bytesInBuffer;
    BYTE                    buffer[16];
    BYTE                    rfu[8];             // rfu = Reserved for Future Use.
    SYMCRYPT_BLOB_TRAILER   trailer;
} SYMCRYPT_MD2_STATE_EXPORT_BLOB;

C_ASSERT( sizeof( SYMCRYPT_MD2_STATE_EXPORT_BLOB ) == SYMCRYPT_MD2_STATE_EXPORT_SIZE );


typedef struct _SYMCRYPT_MD4_STATE_EXPORT_BLOB {
    SYMCRYPT_BLOB_HEADER    header;
    BYTE                    chain[16];          // In the same format used for the final hash value of MD4
    UINT64                  dataLength;
    BYTE                    buffer[64];
    BYTE                    rfu[8];             // rfu = Reserved for Future Use.
    SYMCRYPT_BLOB_TRAILER   trailer;
} SYMCRYPT_MD4_STATE_EXPORT_BLOB;

C_ASSERT( sizeof( SYMCRYPT_MD4_STATE_EXPORT_BLOB ) == SYMCRYPT_MD4_STATE_EXPORT_SIZE );


typedef struct _SYMCRYPT_MD5_STATE_EXPORT_BLOB {
    SYMCRYPT_BLOB_HEADER    header;
    BYTE                    chain[16];          // In the same format used for the final hash value of MD5
    UINT64                  dataLength;
    BYTE                    buffer[64];
    BYTE                    rfu[8];             // rfu = Reserved for Future Use.
    SYMCRYPT_BLOB_TRAILER   trailer;
} SYMCRYPT_MD5_STATE_EXPORT_BLOB;

C_ASSERT( sizeof( SYMCRYPT_MD5_STATE_EXPORT_BLOB ) == SYMCRYPT_MD5_STATE_EXPORT_SIZE );


typedef struct _SYMCRYPT_SHA1_STATE_EXPORT_BLOB {
    SYMCRYPT_BLOB_HEADER    header;
    BYTE                    chain[20];          // in the same format used for the final hash value of SHA-1
    UINT64                  dataLength;
    BYTE                    buffer[64];
    BYTE                    rfu[8];             // rfu = Reserved for Future Use.
    SYMCRYPT_BLOB_TRAILER   trailer;
} SYMCRYPT_SHA1_STATE_EXPORT_BLOB;

C_ASSERT( sizeof( SYMCRYPT_SHA1_STATE_EXPORT_BLOB ) == SYMCRYPT_SHA1_STATE_EXPORT_SIZE );


typedef struct _SYMCRYPT_SHA256_STATE_EXPORT_BLOB {
    SYMCRYPT_BLOB_HEADER    header;
    BYTE                    chain[32];          // in the same format used for the final hash value of SHA-256
    UINT64                  dataLength;
    BYTE                    buffer[64];
    BYTE                    rfu[8];             // rfu = Reserved for Future Use.
    SYMCRYPT_BLOB_TRAILER   trailer;
} SYMCRYPT_SHA256_STATE_EXPORT_BLOB;

C_ASSERT( sizeof( SYMCRYPT_SHA256_STATE_EXPORT_BLOB ) == SYMCRYPT_SHA256_STATE_EXPORT_SIZE );


typedef struct _SYMCRYPT_SHA512_STATE_EXPORT_BLOB {
    SYMCRYPT_BLOB_HEADER    header;
    BYTE                    chain[64];          // in the same format used for the final hash value of SHA-512
    UINT64                  dataLengthL;        // low 64 bits of data length
    UINT64                  dataLengthH;        // high 64 bits of data length
    BYTE                    buffer[128];
    BYTE                    rfu[8];             // rfu = Reserved for Future Use.
    SYMCRYPT_BLOB_TRAILER   trailer;
} SYMCRYPT_SHA512_STATE_EXPORT_BLOB;

C_ASSERT( sizeof( SYMCRYPT_SHA512_STATE_EXPORT_BLOB ) == SYMCRYPT_SHA512_STATE_EXPORT_SIZE );

#pragma pack(pop)

/////////////////////////////////////////////
// AES internal functions

extern const SYMCRYPT_BLOCKCIPHER SymCryptAesBlockCipherNoOpt;

VOID
SYMCRYPT_CALL
SymCryptAes4Sbox(
    _In_reads_(4)   PCBYTE  pIn,
    _Out_writes_(4) PBYTE   pOut,
                    BOOL    UseSimd );

VOID
SYMCRYPT_CALL
SymCryptAes4SboxC(
    _In_reads_(4)   PCBYTE  pIn,
    _Out_writes_(4) PBYTE   pOut );

VOID
SYMCRYPT_CALL
SymCryptAes4SboxXmm(
    _In_reads_(4)   PCBYTE  pIn,
    _Out_writes_(4) PBYTE   pOut );

VOID
SYMCRYPT_CALL
SymCryptAes4SboxNeon(
    _In_reads_(4)   PCBYTE  pIn,
    _Out_writes_(4) PBYTE   pOut );

VOID
SYMCRYPT_CALL
SymCryptAesCreateDecryptionRoundKey(
    _In_reads_(16)      PCBYTE  pEncryptionRoundKey,
    _Out_writes_(16)    PBYTE   pDecryptionRoundKey,
                        BOOL    UseSimd );

VOID
SYMCRYPT_CALL
SymCryptAesCreateDecryptionRoundKeyC(
    _In_reads_(16)     PCBYTE  pEncryptionRoundKey,
    _Out_writes_(16)    PBYTE   pDecryptionRoundKey );

VOID
SYMCRYPT_CALL
SymCryptAesCreateDecryptionRoundKeyXmm(
    _In_reads_(16)     PCBYTE  pEncryptionRoundKey,
    _Out_writes_(16)    PBYTE   pDecryptionRoundKey );

VOID
SYMCRYPT_CALL
SymCryptAesCreateDecryptionRoundKeyNeon(
    _In_reads_(16)     PCBYTE  pEncryptionRoundKey,
    _Out_writes_(16)    PBYTE   pDecryptionRoundKey );

VOID
SYMCRYPT_CALL
SymCryptAesEncryptC(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PCBYTE                      pbSrc,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE ) PBYTE                       pbDst );

VOID
SYMCRYPT_CALL
SymCryptAesEncryptAsm(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PCBYTE                      pbSrc,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE ) PBYTE                       pbDst );

VOID
SYMCRYPT_CALL
SymCryptAesEncryptXmm(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PCBYTE                      pbSrc,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE ) PBYTE                       pbDst );

VOID
SYMCRYPT_CALL
SymCryptAesEncryptNeon(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PCBYTE                      pbSrc,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE ) PBYTE                       pbDst );

VOID
SYMCRYPT_CALL
SymCryptAesDecryptC(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PCBYTE                      pbSrc,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE ) PBYTE                       pbDst );

VOID
SYMCRYPT_CALL
SymCryptAesDecryptAsm(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PCBYTE                      pbSrc,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE ) PBYTE                       pbDst );

VOID
SYMCRYPT_CALL
SymCryptAesDecryptXmm(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PCBYTE                      pbSrc,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE ) PBYTE                       pbDst );

VOID
SYMCRYPT_CALL
SymCryptAesDecryptNeon(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PCBYTE                      pbSrc,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE ) PBYTE                       pbDst );

VOID
SYMCRYPT_CALL
SymCryptAesEcbEncryptC(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );
VOID
SYMCRYPT_CALL
SymCryptAesEcbEncryptAsm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );
VOID
SYMCRYPT_CALL
SymCryptAesEcbEncryptXmm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptAesEcbEncryptNeon(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptAesEcbDecryptC(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptAesCbcEncryptAsm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );
VOID
SYMCRYPT_CALL
SymCryptAesCbcEncryptXmm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptAesCbcEncryptNeon(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptAesCbcDecryptAsm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptAesCbcDecryptXmm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptAesCbcDecryptNeon(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptAesCbcMacXmm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbData,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptAesCbcMacNeon(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbData,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptAesCtrMsb64Asm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptAesCtrMsb64Xmm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptAesCtrMsb64Neon(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbChainingValue,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptXtsAesEncryptDataUnitC(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbTweakBlock,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptXtsAesDecryptDataUnitC(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbTweakBlock,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptXtsAesEncryptDataUnitAsm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbTweakBlock,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptXtsAesDecryptDataUnitAsm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbTweakBlock,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

// pbScratch must currently be 16B aligned
VOID
SYMCRYPT_CALL
SymCryptXtsAesEncryptDataUnitXmm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )       PBYTE                       pbTweakBlock,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE*16 )  PBYTE                       pbScratch,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

// pbScratch must currently be 16B aligned
VOID
SYMCRYPT_CALL
SymCryptXtsAesDecryptDataUnitXmm(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )       PBYTE                       pbTweakBlock,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE*16 )  PBYTE                       pbScratch,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptXtsAesEncryptDataUnitZmm_2048(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbTweakBlock,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE*16 )  PBYTE                       pbScratch,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptXtsAesDecryptDataUnitZmm_2048(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbTweakBlock,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE*16 )  PBYTE                       pbScratch,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptXtsAesEncryptDataUnitYmm_2048(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbTweakBlock,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE*16 )  PBYTE                       pbScratch,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptXtsAesDecryptDataUnitYmm_2048(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbTweakBlock,
    _Out_writes_( SYMCRYPT_AES_BLOCK_SIZE*16 )  PBYTE                       pbScratch,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptXtsAesEncryptDataUnitNeon(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbTweakBlock,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptXtsAesDecryptDataUnitNeon(
    _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _Inout_updates_( SYMCRYPT_AES_BLOCK_SIZE )  PBYTE                       pbTweakBlock,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptXtsEncryptDataUnit(
    _In_                                        PCSYMCRYPT_BLOCKCIPHER      pBlockCipher,
    _In_                                        PCVOID                      pExpandedKey,
    _Inout_updates_( pBlockCipher->blockSize )  PBYTE                       pbTweakBlock,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptXtsDecryptDataUnit(
    _In_                                        PCSYMCRYPT_BLOCKCIPHER      pBlockCipher,
    _In_                                        PCVOID                      pExpandedKey,
    _Inout_updates_( pBlockCipher->blockSize )  PBYTE                       pbTweakBlock,
    _In_reads_( cbData )                        PCBYTE                      pbSrc,
    _Out_writes_( cbData )                      PBYTE                       pbDst,
                                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptAesGcmEncryptStitchedXmm(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( SYMCRYPT_GF128_FIELD_SIZE ) PCSYMCRYPT_GF128_ELEMENT    expandedKeyTable,
    _Inout_                                 PSYMCRYPT_GF128_ELEMENT     pState,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptAesGcmEncryptStitchedYmm_2048(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( SYMCRYPT_GF128_FIELD_SIZE ) PCSYMCRYPT_GF128_ELEMENT    expandedKeyTable,
    _Inout_                                 PSYMCRYPT_GF128_ELEMENT     pState,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptAesGcmDecryptStitchedXmm(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( SYMCRYPT_GF128_FIELD_SIZE ) PCSYMCRYPT_GF128_ELEMENT    expandedKeyTable,
    _Inout_                                 PSYMCRYPT_GF128_ELEMENT     pState,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptAesGcmDecryptStitchedYmm_2048(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( SYMCRYPT_GF128_FIELD_SIZE ) PCSYMCRYPT_GF128_ELEMENT    expandedKeyTable,
    _Inout_                                 PSYMCRYPT_GF128_ELEMENT     pState,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptAesGcmEncryptStitchedNeon(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( SYMCRYPT_GF128_FIELD_SIZE ) PCSYMCRYPT_GF128_ELEMENT    expandedKeyTable,
    _Inout_                                 PSYMCRYPT_GF128_ELEMENT     pState,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptAesGcmDecryptStitchedNeon(
    _In_                                    PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
    _In_reads_( SYMCRYPT_AES_BLOCK_SIZE )   PBYTE                       pbChainingValue,
    _In_reads_( SYMCRYPT_GF128_FIELD_SIZE ) PCSYMCRYPT_GF128_ELEMENT    expandedKeyTable,
    _Inout_                                 PSYMCRYPT_GF128_ELEMENT     pState,
    _In_reads_( cbData )                    PCBYTE                      pbSrc,
    _Out_writes_( cbData )                  PBYTE                       pbDst,
                                            SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptAesGcmEncryptPart(
    _Inout_                 PSYMCRYPT_GCM_STATE pState,
    _In_reads_( cbData )    PCBYTE              pbSrc,
    _Out_writes_( cbData )  PBYTE               pbDst,
                            SIZE_T              cbData );

VOID
SYMCRYPT_CALL
SymCryptAesGcmDecryptPart(
    _Inout_                 PSYMCRYPT_GCM_STATE pState,
    _In_reads_( cbData )    PCBYTE              pbSrc,
    _Out_writes_( cbData )  PBYTE               pbDst,
                            SIZE_T              cbData );

VOID
SYMCRYPT_CALL
SymCryptGcmEncryptPartTwoPass(
    _Inout_                 PSYMCRYPT_GCM_STATE pState,
    _In_reads_( cbData )    PCBYTE              pbSrc,
    _Out_writes_( cbData )  PBYTE               pbDst,
                            SIZE_T              cbData );

VOID
SYMCRYPT_CALL
SymCryptGcmDecryptPartTwoPass(
    _Inout_                 PSYMCRYPT_GCM_STATE pState,
    _In_reads_( cbData )    PCBYTE              pbSrc,
    _Out_writes_( cbData )  PBYTE               pbDst,
                            SIZE_T              cbData );

VOID
SYMCRYPT_CALL
SymCryptParallelHashProcess_serial(
    _In_                                                            PCSYMCRYPT_PARALLEL_HASH            pParHash,
    _Inout_updates_bytes_( nStates * pParHash->pHash->stateSize )   PVOID                               pStates,
                                                                    SIZE_T                              nStates,
    _Inout_updates_( nOperations )                                  PSYMCRYPT_PARALLEL_HASH_OPERATION   pOperations,
                                                                    SIZE_T                              nOperations,
    _Out_writes_( cbScratch )                                       PBYTE                               pbScratch,
                                                                    SIZE_T                              cbScratch );

VOID
SYMCRYPT_CALL
SymCryptParallelHashProcess(
    _In_                                                            PCSYMCRYPT_PARALLEL_HASH            pParHash,
    _Inout_updates_bytes_( nStates * pParHash->pHash->stateSize )   PVOID                               pStates,
                                                                    SIZE_T                              nStates,
    _Inout_updates_( nOperations )                                  PSYMCRYPT_PARALLEL_HASH_OPERATION   pOperations,
                                                                    SIZE_T                              nOperations,
    _Out_writes_( cbScratch )                                       PBYTE                               pbScratch,
                                                                    SIZE_T                              cbScratch,
                                                                    UINT32                              maxParallel );

VOID
SYMCRYPT_CALL
SymCryptHashAppendInternal(
    _In_                        PCSYMCRYPT_HASH             pHash,
    _Inout_                     PSYMCRYPT_COMMON_HASH_STATE pState,
    _In_reads_bytes_( cbData )  PCBYTE                      pbData,
                                SIZE_T                      cbData );

VOID
SYMCRYPT_CALL
SymCryptHashCommonPaddingMd4Style(
    _In_                        PCSYMCRYPT_HASH             pHash,
    _Inout_                     PSYMCRYPT_COMMON_HASH_STATE pState );


extern const PCSYMCRYPT_PARALLEL_HASH SymCryptParallelSha256Algorithm;
extern const PCSYMCRYPT_PARALLEL_HASH SymCryptParallelSha384Algorithm;
extern const PCSYMCRYPT_PARALLEL_HASH SymCryptParallelSha512Algorithm;

#define PAR_SCRATCH_ELEMENTS_256    (4+8+64)    // # scratch elements our parallel SHA256 implementations need
#define PAR_SCRATCH_ELEMENTS_512    (4+8+80)    // # scratch elements our parallel SHA512 implementations need

// pScratch must be 32B aligned, as it is used as an array of __m256i
VOID
SYMCRYPT_CALL
SymCryptParallelSha256AppendBlocks_ymm(
    _Inout_updates_( 8 )                                PSYMCRYPT_SHA256_CHAINING_STATE   * pChain,
    _Inout_updates_( 8 )                                PCBYTE                            * ppByte,
                                                        SIZE_T                              nBytes,
    _Out_writes_( PAR_SCRATCH_ELEMENTS_256 * 32 )       PBYTE                               pScratch );

// pScratch must be 32B aligned, as it is used as an array of __m256i
VOID
SYMCRYPT_CALL
SymCryptParallelSha512AppendBlocks_ymm(
    _Inout_updates_( 4 )                                PSYMCRYPT_SHA512_CHAINING_STATE   * pChain,
    _Inout_updates_( 4 )                                PCBYTE                            * ppByte,
                                                        SIZE_T                              nBytes,
    _Out_writes_( PAR_SCRATCH_ELEMENTS_512 * 32 )       PBYTE                               pScratch );

extern const SYMCRYPT_HASH SymCryptSha256Algorithm_default;
extern const SYMCRYPT_HASH SymCryptSha384Algorithm_default;
extern const SYMCRYPT_HASH SymCryptSha512Algorithm_default;

VOID
SYMCRYPT_CALL
SymCryptFatalIntercept( UINT32 fatalCode );

extern const BYTE SymCryptSha256KATAnswer[32];
extern const BYTE SymCryptSha384KATAnswer[48];
extern const BYTE SymCryptSha512KATAnswer[64];

//
// Arithmetic
//

#define SYMCRYPT_ASSERT_ASYM_ALIGNED( _p )           SYMCRYPT_ASSERT( ((ULONG_PTR)(_p) & (SYMCRYPT_ASYM_ALIGN_VALUE - 1)) == 0 );


//typedef const UINT32 * PCUINT32;


#define SYMCRYPT_FDEF_DIGIT_NUINT32             ((UINT32)(SYMCRYPT_FDEF_DIGIT_SIZE / sizeof( UINT32 ) ))

#define SYMCRYPT_OBJ_NDIGITS( _p )              ((_p)->nDigits)
#define SYMCRYPT_OBJ_NBYTES( _p )               ((_p)->nDigits * SYMCRYPT_FDEF_DIGIT_SIZE)
#define SYMCRYPT_OBJ_NUINT32( _p )              ((_p)->nDigits * SYMCRYPT_FDEF_DIGIT_SIZE / sizeof( UINT32 ))

#if SYMCRYPT_MS_VC
#define SYMCRYPT_MUL32x32TO64( _a, _b )         UInt32x32To64( (_a), (_b) )
#elif SYMCRYPT_GNUC
#define SYMCRYPT_MUL32x32TO64( _a, _b )         ( (unsigned long)(_a)*(unsigned long)(_b) )
#else
    #error Unknown compiler
#endif
typedef VOID (SYMCRYPT_CALL * SYMCRYPT_MOD_BINARY_OP_FN)(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

typedef VOID (SYMCRYPT_CALL * SYMCRYPT_MOD_UNARY_OP_FN)(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

typedef SYMCRYPT_ERROR (SYMCRYPT_CALL * SYMCRYPT_MOD_UNARY_OP_FLAG_STATUS_FN)(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
                                    UINT32                  flags,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

typedef VOID (SYMCRYPT_CALL * SYMCRYPT_MOD_SET_POST_FN)(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Inout_                         PSYMCRYPT_MODELEMENT    peObj,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

typedef PCUINT32 (SYMCRYPT_CALL * SYMCRYPT_MOD_PRE_GET_FN)(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peObj,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

typedef VOID (SYMCRYPT_CALL * SYMCRYPT_MOD_COPY_FN)(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst );

typedef VOID (SYMCRYPT_CALL * SYMCRYPT_MODULUS_COPYFIXUP_FN)(
    _In_                            PCSYMCRYPT_MODULUS      pmSrc,
    _Out_                           PSYMCRYPT_MODULUS       pmDst );

typedef VOID (SYMCRYPT_CALL * SYMCRYPT_MODULUS_INIT_FN)(
    _Inout_                         PSYMCRYPT_MODULUS       pmObj,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

//
// In the future we might want to implement a 'prepare divisor' for people who want to do one or more modular divisions.
// In EC projective coordinates you have a value stored as (X,Z) with X/Z being the actual value that needs to be exported.
// In Montgomery format, this is stored as (RX, RZ), and just doing RX * (1/RZ) gets you the value to be exported.
// There seem to be many tricks here to get some more speed; maybe we just need to define export functions for each
// point format and allow the Modulus to contain special optimizations.
//
// The SetPost function is the post-processing function of any SetValue operation. The SetValue operation will store the
// modElement in the normal integer format into the ModElement. The SetPost function post-proccesses it into the proper
// representation for that modulus.
//
// The PreGet function is the pre-processing function to any GetValue operation. It returns a pointer to the proper value
// stored in standard integer format. This pointer can either be into the ModElement itself, or into the scratch space.
//

typedef struct _SYMCRYPT_MODULAR_FUNCTIONS {
    SYMCRYPT_MOD_BINARY_OP_FN               modAdd;
    SYMCRYPT_MOD_BINARY_OP_FN               modSub;
    SYMCRYPT_MOD_UNARY_OP_FN                modNeg;
    SYMCRYPT_MOD_BINARY_OP_FN               modMul;
    SYMCRYPT_MOD_UNARY_OP_FN                modSquare;
    SYMCRYPT_MOD_UNARY_OP_FLAG_STATUS_FN    modInv;
    SYMCRYPT_MOD_SET_POST_FN                modSetPost;
    SYMCRYPT_MOD_PRE_GET_FN                 modPreGet;
    SYMCRYPT_MODULUS_COPYFIXUP_FN           modulusCopyFixup;   // non-generic fixup after memcpy
    SYMCRYPT_MODULUS_INIT_FN                modulusInit;
    PVOID                                   slack[6];
} SYMCRYPT_MODULAR_FUNCTIONS;

#define SYMCRYPT_MODULAR_FUNCTIONS_SIZE    (sizeof( SYMCRYPT_MODULAR_FUNCTIONS ) )

extern const SYMCRYPT_MODULAR_FUNCTIONS g_SymCryptModFns[];
extern const UINT32 g_SymCryptModFnsMask;

//
// Table entry that contains the information about an implementation.
// Allows generic code to make the decision.
// First entry in the table that is allowed is chosen, last entry always matches everything
//

#define SYMCRYPT_MODULUS_FEATURE_MONTGOMERY         1       // Modulus is suitable for Montgomery processing
// #define SYMCRYPT_MODULUS_FEATURE_PSEUDO_MERSENNE    2       // Modulus is suitable for Pseudo-Mersenne processing
// #define SYMCRYPT_MODULUS_FEATURE_NISTP256           4       // Modulus is the NIST P256 curve prime

typedef struct _SYMCRYPT_MODULUS_TYPE_SELECTION_ENTRY
{
    UINT32                  type;               // Type value of this solution
    SYMCRYPT_CPU_FEATURES   cpuFeatures;        // Required CPU features
    UINT32                  maxBits;            // Max # bits that the actual value of the modulus is, 0 = no limit
    UINT32                  modulusFeatures;    // Required features of the modulus
} SYMCRYPT_MODULUS_TYPE_SELECTION_ENTRY, *PSYMCRYPT_MODULUS_TYPE_SELECTION_ENTRY;
typedef const SYMCRYPT_MODULUS_TYPE_SELECTION_ENTRY* PCSYMCRYPT_MODULUS_TYPE_SELECTION_ENTRY;

extern const SYMCRYPT_MODULUS_TYPE_SELECTION_ENTRY SymCryptModulusTypeSelections[];       // Array can be any size...


// Check that the size is a power of 2
C_ASSERT( (SYMCRYPT_MODULAR_FUNCTIONS_SIZE & (SYMCRYPT_MODULAR_FUNCTIONS_SIZE-1)) == 0 );

// The macro that we use to call modular functions
#define SYMCRYPT_MOD_CALL(v) ((SYMCRYPT_MODULAR_FUNCTIONS *)(( SYMCRYPT_FORCE_READ32( &(v)->type) & g_SymCryptModFnsMask) + (PBYTE)(&g_SymCryptModFns) ))->

#define SYMCRYPT_MOD_FUNCTIONS_FDEF_GENERIC {\
    &SymCryptFdefModAddGeneric,\
    &SymCryptFdefModSubGeneric,\
    &SymCryptFdefModNegGeneric,\
    &SymCryptFdefModMulGeneric,\
    &SymCryptFdefModSquareGeneric,\
    &SymCryptFdefModInvGeneric,\
    &SymCryptFdefModSetPostGeneric,\
    &SymCryptFdefModPreGetGeneric,\
    &SymCryptFdefModulusCopyFixupGeneric,\
    &SymCryptFdefModulusInitGeneric,\
}

#define SYMCRYPT_MOD_FUNCTIONS_FDEF_MONTGOMERY {\
    &SymCryptFdefModAddGeneric,\
    &SymCryptFdefModSubGeneric,\
    &SymCryptFdefModNegGeneric,\
    &SymCryptFdefModMulMontgomery,\
    &SymCryptFdefModSquareMontgomery,\
    &SymCryptFdefModInvMontgomery,\
    &SymCryptFdefModSetPostMontgomery,\
    &SymCryptFdefModPreGetMontgomery,\
    &SymCryptFdefModulusCopyFixupMontgomery,\
    &SymCryptFdefModulusInitMontgomery,\
}

#define SYMCRYPT_MOD_FUNCTIONS_FDEF_MONTGOMERY256 {\
    &SymCryptFdefModAdd256Asm,\
    &SymCryptFdefModSub256Asm,\
    &SymCryptFdefModNegGeneric,\
    &SymCryptFdefModMulMontgomery256Asm,\
    &SymCryptFdefModSquareMontgomery256Asm,\
    &SymCryptFdefModInvMontgomery256,\
    &SymCryptFdefModSetPostMontgomery256,\
    &SymCryptFdefModPreGetMontgomery256,\
    &SymCryptFdefModulusCopyFixupMontgomery,\
    &SymCryptFdefModulusInitMontgomery256,\
}

#define SYMCRYPT_MOD_FUNCTIONS_FDEF369_MONTGOMERY {\
    &SymCryptFdef369ModAddGeneric,\
    &SymCryptFdef369ModSubGeneric,\
    &SymCryptFdefModNegGeneric,\
    &SymCryptFdef369ModMulMontgomery,\
    &SymCryptFdef369ModSquareMontgomery,\
    &SymCryptFdef369ModInvMontgomery,\
    &SymCryptFdef369ModSetPostMontgomery,\
    &SymCryptFdef369ModPreGetMontgomery,\
    &SymCryptFdefModulusCopyFixupMontgomery,\
    &SymCryptFdef369ModulusInitMontgomery,\
}

#define SYMCRYPT_MOD_FUNCTIONS_FDEF_MONTGOMERY_MULX {\
    &SymCryptFdefModAddGeneric,\
    &SymCryptFdefModSubGeneric,\
    &SymCryptFdefModNegGeneric,\
    &SymCryptFdefModMulMontgomeryMulx,\
    &SymCryptFdefModSquareMontgomeryMulx,\
    &SymCryptFdefModInvMontgomery,\
    &SymCryptFdefModSetPostMontgomery,\
    &SymCryptFdefModPreGetMontgomery,\
    &SymCryptFdefModulusCopyFixupMontgomery,\
    &SymCryptFdefModulusInitMontgomery,\
}

#define SYMCRYPT_MOD_FUNCTIONS_FDEF_MONTGOMERY512 {\
    &SymCryptFdefModAddGeneric,\
    &SymCryptFdefModSubGeneric,\
    &SymCryptFdefModNegGeneric,\
    &SymCryptFdefModMulMontgomery512,\
    &SymCryptFdefModSquareMontgomery512,\
    &SymCryptFdefModInvMontgomery,\
    &SymCryptFdefModSetPostMontgomery,\
    &SymCryptFdefModPreGetMontgomery,\
    &SymCryptFdefModulusCopyFixupMontgomery,\
    &SymCryptFdefModulusInitMontgomery,\
}

#define SYMCRYPT_MOD_FUNCTIONS_FDEF_MONTGOMERY1024 {\
    &SymCryptFdefModAddGeneric,\
    &SymCryptFdefModSubGeneric,\
    &SymCryptFdefModNegGeneric,\
    &SymCryptFdefModMulMontgomery1024,\
    &SymCryptFdefModSquareMontgomery1024,\
    &SymCryptFdefModInvMontgomery,\
    &SymCryptFdefModSetPostMontgomery,\
    &SymCryptFdefModPreGetMontgomery,\
    &SymCryptFdefModulusCopyFixupMontgomery,\
    &SymCryptFdefModulusInitMontgomery,\
}

#define SYMCRYPT_MOD_FUNCTIONS_FDEF_MONTGOMERY_MULX1024 {\
    &SymCryptFdefModAddGeneric,\
    &SymCryptFdefModSubGeneric,\
    &SymCryptFdefModNegGeneric,\
    &SymCryptFdefModMulMontgomeryMulx1024,\
    &SymCryptFdefModSquareMontgomeryMulx1024,\
    &SymCryptFdefModInvMontgomery,\
    &SymCryptFdefModSetPostMontgomery,\
    &SymCryptFdefModPreGetMontgomery,\
    &SymCryptFdefModulusCopyFixupMontgomery,\
    &SymCryptFdefModulusInitMontgomery,\
}

VOID
SYMCRYPT_CALL
SymCryptFdefMaskedCopy(
    _In_reads_bytes_( nDigits*SYMCRYPT_FDEF_DIGIT_SIZE )        PCBYTE      pbSrc,
    _Inout_updates_bytes_( nDigits*SYMCRYPT_FDEF_DIGIT_SIZE )   PBYTE       pbDst,
                                                                UINT32      nDigits,
                                                                UINT32      mask );
//
// Copies Src to Dst under mask.
// Requirements:
//  - mask == 0 or mask == 0xffffffff
//  - cbData must be a multple of the size of a digit, or a multiple of the size of a ModElement.
//  - pbSrc and pbDst must be SYMCRYPT_ALIGNed
// if mask == 0 this function does nothing.
// if mask == 0xffffffff this function is a memcpy from Src to Dst.
// This function is side-channel safe; the value of mask is not revealed
// through the memory access patterns.
//

VOID
SYMCRYPT_CALL
SymCryptFdefConditionalSwap(
    _Inout_updates_bytes_( nDigits*SYMCRYPT_FDEF_DIGIT_SIZE )   PBYTE       pbSrc1,
    _Inout_updates_bytes_( nDigits*SYMCRYPT_FDEF_DIGIT_SIZE )   PBYTE       pbSrc2,
                                                                UINT32      nDigits,
                                                                UINT32      cond );

//
// Swaps the bytes of Src1 with the bytes of Src2 under a condition.
// Requirements:
//  - cond = 0 or cond = 1 .
//  - cbData must be a multple of the size of a digit, or a multiple of the size of a ModElement.
//  - pbSrc1 and pbSrc2 must be SYMCRYPT_ALIGNed
// if cond == 0 this function does nothing.
// if cond == 1 this function swaps the bytes of Src1 with the bytes of Src2.
// This function is side-channel safe; the value of cond is not revealed
// through the memory access patterns.
//

VOID
SYMCRYPT_CALL
SymCryptFdefClaimScratch( PBYTE pbScratch, SIZE_T cbScratch, SIZE_T cbMin );

UINT32
SymCryptFdefDigitsFromBits( UINT32 nBits );

PSYMCRYPT_INT
SYMCRYPT_CALL
SymCryptFdefIntAllocate( UINT32 nDigits );

UINT32
SYMCRYPT_CALL
SymCryptFdefSizeofIntFromDigits( UINT32 nDigits );

PSYMCRYPT_INT
SYMCRYPT_CALL
SymCryptFdefIntCreate(
    _Out_writes_bytes_( cbBuffer )  PBYTE   pbBuffer,
                                    SIZE_T  cbBuffer,
                                    UINT32  nDigits );

VOID
SymCryptFdefIntCopy(
    _In_    PCSYMCRYPT_INT  piSrc,
    _Out_   PSYMCRYPT_INT   piDst );

VOID
SymCryptFdefIntMaskedCopy(
    _In_    PCSYMCRYPT_INT  piSrc,
    _Inout_ PSYMCRYPT_INT   piDst,
            UINT32          mask );

VOID
SYMCRYPT_CALL
SymCryptFdefIntConditionalCopy(
    _In_    PCSYMCRYPT_INT  piSrc,
    _Inout_ PSYMCRYPT_INT   piDst,
            UINT32          cond );

VOID
SYMCRYPT_CALL
SymCryptFdefIntConditionalSwap(
    _Inout_ PSYMCRYPT_INT   piSrc1,
    _Inout_ PSYMCRYPT_INT   piSrc2,
            UINT32          cond );

UINT32
SYMCRYPT_CALL
SymCryptFdefIntBitsizeOfObject( _In_ PCSYMCRYPT_INT  piSrc );

UINT32
SYMCRYPT_CALL
SymCryptFdefNumberofDigitsFromInt( _In_ PCSYMCRYPT_INT piSrc );

SYMCRYPT_ERROR
SymCryptFdefIntCopyMixedSize(
    _In_    PCSYMCRYPT_INT  piSrc,
    _Out_   PSYMCRYPT_INT   piDst );

UINT32
SYMCRYPT_CALL
SymCryptFdefIntBitsizeOfValue( _In_ PCSYMCRYPT_INT piSrc );

VOID
SYMCRYPT_CALL
SymCryptFdefIntSetValueUint32(
            UINT32          u32Src,
    _Out_   PSYMCRYPT_INT   piDst );

VOID
SYMCRYPT_CALL
SymCryptFdefIntSetValueUint64(
            UINT64          u64Src,
    _Out_   PSYMCRYPT_INT   piDst );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptFdefIntSetValue(
    _In_reads_bytes_(cbSrc)     PCBYTE                  pbSrc,
                                SIZE_T                  cbSrc,
                                SYMCRYPT_NUMBER_FORMAT  format,
    _Out_                       PSYMCRYPT_INT           piDst );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptFdefIntGetValue(
    _In_                        PCSYMCRYPT_INT          piSrc,
    _Out_writes_bytes_(cbDst)   PBYTE                   pbDst,
                                SIZE_T                  cbDst,
                                SYMCRYPT_NUMBER_FORMAT  format );

UINT32
SYMCRYPT_CALL
SymCryptFdefIntGetValueLsbits32( _In_  PCSYMCRYPT_INT piSrc );

UINT64
SYMCRYPT_CALL
SymCryptFdefIntGetValueLsbits64( _In_  PCSYMCRYPT_INT piSrc );

UINT32
SYMCRYPT_CALL
SymCryptFdefIntAddUint32(
    _In_    PCSYMCRYPT_INT  piSrc1,
            UINT32          u32Src2,
    _Out_   PSYMCRYPT_INT   piDst );

UINT32
SYMCRYPT_CALL
SymCryptFdefIntAddSameSize(
    _In_    PCSYMCRYPT_INT piSrc1,
    _In_    PCSYMCRYPT_INT piSrc2,
    _Out_   PSYMCRYPT_INT  piDst );

UINT32
SYMCRYPT_CALL
SymCryptFdefIntAddMixedSize(
    _In_    PCSYMCRYPT_INT piSrc1,
    _In_    PCSYMCRYPT_INT piSrc2,
    _Out_   PSYMCRYPT_INT  piDst );

UINT32
SYMCRYPT_CALL
SymCryptFdefIntSubUint32(
    _In_    PCSYMCRYPT_INT  piSrc1,
            UINT32          u32Src2,
    _Out_   PSYMCRYPT_INT   piDst );

UINT32
SYMCRYPT_CALL
SymCryptFdefIntSubSameSize(
    _In_    PCSYMCRYPT_INT piSrc1,
    _In_    PCSYMCRYPT_INT piSrc2,
    _Out_   PSYMCRYPT_INT  piDst );

UINT32
SYMCRYPT_CALL
SymCryptFdefIntSubMixedSize(
    _In_    PCSYMCRYPT_INT piSrc1,
    _In_    PCSYMCRYPT_INT piSrc2,
    _Out_   PSYMCRYPT_INT  piDst );

VOID
SYMCRYPT_CALL
SymCryptFdefIntNeg(
    _In_    PCSYMCRYPT_INT  piSrc,
    _Out_   PSYMCRYPT_INT   piDst );


VOID
SYMCRYPT_CALL
SymCryptFdefIntMulPow2(
    _In_    PCSYMCRYPT_INT  piSrc,
            SIZE_T          Exp,
    _Out_   PSYMCRYPT_INT   piDst );

VOID
SYMCRYPT_CALL
SymCryptFdefIntDivPow2(
    _In_    PCSYMCRYPT_INT  piSrc,
            SIZE_T          exp,
    _Out_   PSYMCRYPT_INT   piDst );

VOID
SYMCRYPT_CALL
SymCryptFdefIntShr1(
            UINT32          highestBit,
    _In_    PCSYMCRYPT_INT  piSrc,
    _Out_   PSYMCRYPT_INT   piDst );

VOID
SYMCRYPT_CALL
SymCryptFdefIntModPow2(
    _In_    PCSYMCRYPT_INT  piSrc,
            SIZE_T          exp,
    _Out_   PSYMCRYPT_INT   piDst );

UINT32
SYMCRYPT_CALL
SymCryptFdefIntGetBit(
    _In_    PCSYMCRYPT_INT  piSrc,
            UINT32          iBit );

UINT32
SYMCRYPT_CALL
SymCryptFdefIntGetBits(
    _In_    PCSYMCRYPT_INT  piSrc,
            UINT32          iBit,
            UINT32          nBits );

VOID
SYMCRYPT_CALL
SymCryptFdefIntSetBits(
    _In_    PSYMCRYPT_INT   piDst,
            UINT32          value,
            UINT32          iBit,
            UINT32          nBits );

UINT32
SYMCRYPT_CALL
SymCryptFdefIntIsEqualUint32(
    _In_    PCSYMCRYPT_INT  piSrc1,
    _In_    UINT32          u32Src2 );

UINT32
SYMCRYPT_CALL
SymCryptFdefIntIsEqual(
    _In_    PCSYMCRYPT_INT  piSrc1,
    _In_    PCSYMCRYPT_INT  piSrc2 );

UINT32
SYMCRYPT_CALL
SymCryptFdefIntIsLessThan(
    _In_    PCSYMCRYPT_INT  piSrc1,
    _In_    PCSYMCRYPT_INT  piSrc2 );

UINT32
SYMCRYPT_CALL
SymCryptFdefIntMulUint32(
    _In_                            PCSYMCRYPT_INT  piSrc1,
                                    UINT32          Src2,
    _Out_                           PSYMCRYPT_INT   piDst );

VOID
SYMCRYPT_CALL
SymCryptFdefIntMulSameSize(
    _In_                            PCSYMCRYPT_INT  piSrc1,
    _In_                            PCSYMCRYPT_INT  piSrc2,
    _Out_                           PSYMCRYPT_INT   piDst,
    _Out_writes_bytes_( cbScratch ) PBYTE           pbScratch,
                                    SIZE_T          cbScratch );
VOID
SYMCRYPT_CALL
SymCryptFdefIntSquare(
    _In_                            PCSYMCRYPT_INT  piSrc,
    _Out_                           PSYMCRYPT_INT   piDst,
    _Out_writes_bytes_( cbScratch ) PBYTE           pbScratch,
                                    SIZE_T          cbScratch );
VOID
SYMCRYPT_CALL
SymCryptFdefIntMulMixedSize(
    _In_                            PCSYMCRYPT_INT  piSrc1,
    _In_                            PCSYMCRYPT_INT  piSrc2,
    _Out_                           PSYMCRYPT_INT   piDst,
    _Out_writes_bytes_( cbScratch ) PBYTE           pbScratch,
                                    SIZE_T          cbScratch );

PSYMCRYPT_DIVISOR
SYMCRYPT_CALL
SymCryptFdefDivisorAllocate( UINT32 nDigits );

UINT32
SYMCRYPT_CALL
SymCryptFdefSizeofDivisorFromDigits( UINT32 nDigits );

PSYMCRYPT_DIVISOR
SYMCRYPT_CALL
SymCryptFdefDivisorCreate(
    _Out_writes_bytes_( cbBuffer )  PBYTE   pbBuffer,
                                    SIZE_T  cbBuffer,
                                    UINT32  nDigits );

PSYMCRYPT_DIVISOR
SYMCRYPT_CALL
SymCryptFdefDivisorRetrieveHandle( _In_ PBYTE pbBuffer );

VOID
SymCryptFdefDivisorCopy(
    _In_    PCSYMCRYPT_DIVISOR  pdSrc,
    _Out_   PSYMCRYPT_DIVISOR   pdDst );

VOID
SymCryptFdefDivisorCopyFixup(
    _In_    PCSYMCRYPT_DIVISOR  pSrc,
    _Out_   PSYMCRYPT_DIVISOR   pDst );

PSYMCRYPT_INT
SYMCRYPT_CALL
SymCryptFdefIntFromDivisor( _In_ PSYMCRYPT_DIVISOR pdSrc );

VOID
SYMCRYPT_CALL
SymCryptFdefIntToDivisor(
    _In_                            PCSYMCRYPT_INT      piSrc,
    _Out_                           PSYMCRYPT_DIVISOR   pdDst,
                                    UINT32              totalOperations,
                                    UINT32              flags,
    _Out_writes_bytes_( cbScratch ) PBYTE               pbScratch,
                                    SIZE_T              cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefIntDivMod(
    _In_                            PCSYMCRYPT_INT      piSrc,
    _In_                            PCSYMCRYPT_DIVISOR  pdDivisor,
    _Out_opt_                       PSYMCRYPT_INT       piQuotient,
    _Out_opt_                       PSYMCRYPT_INT       piRemainder,
    _Out_writes_bytes_( cbScratch ) PBYTE               pbScratch,
                                    SIZE_T              cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefRawDivMod(
    _In_reads_(nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32)           PCUINT32            pNum,
                                                                UINT32              nDigits,
    _In_                                                        PCSYMCRYPT_DIVISOR  pDivisor,
    _Out_writes_opt_(nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32)     PUINT32             pQuotient,
    _Out_writes_opt_(SYMCRYPT_FDEF_INT_NUINT32(&pDivisor->Int)) PUINT32             pRemainder,
    _Out_writes_bytes_( cbScratch )                             PBYTE               pbScratch,
                                                                SIZE_T              cbScratch );


PSYMCRYPT_MODULUS
SYMCRYPT_CALL
SymCryptFdefModulusAllocate( UINT32 nDigits );

VOID
SYMCRYPT_CALL
SymCryptFdefModulusFree( _Out_ PSYMCRYPT_MODULUS pmObj );

UINT32
SYMCRYPT_CALL
SymCryptFdefSizeofModulusFromDigits( UINT32 nDigits );

PSYMCRYPT_MODULUS
SYMCRYPT_CALL
SymCryptFdefModulusCreate(
    _Out_writes_bytes_( cbBuffer )  PBYTE   pbBuffer,
                                    SIZE_T  cbBuffer,
                                    UINT32  nDigits );

PSYMCRYPT_MODULUS
SYMCRYPT_CALL
SymCryptFdefModulusRetrieveHandle( _In_ PBYTE pbBuffer );


VOID
SymCryptFdefModulusCopy(
    _In_    PCSYMCRYPT_MODULUS  pmSrc,
    _Out_   PSYMCRYPT_MODULUS   pmDst );

PSYMCRYPT_MODELEMENT
SYMCRYPT_CALL
SymCryptFdefModElementAllocate( _In_ PCSYMCRYPT_MODULUS pmMod );

VOID
SYMCRYPT_CALL
SymCryptFdefModElementFree(
    _In_    PCSYMCRYPT_MODULUS      pmMod,
    _Out_   PSYMCRYPT_MODELEMENT    peObj );

UINT32
SYMCRYPT_CALL
SymCryptFdefSizeofModElementFromModulus( PCSYMCRYPT_MODULUS pmMod );

PSYMCRYPT_MODELEMENT
SYMCRYPT_CALL
SymCryptFdefModElementCreate(
    _Out_writes_bytes_( cbBuffer )  PBYTE               pbBuffer,
                                    SIZE_T              cbBuffer,
                                    PCSYMCRYPT_MODULUS   pmMod );

PSYMCRYPT_MODELEMENT
SYMCRYPT_CALL
SymCryptFdefModElementRetrieveHandle( _In_ PBYTE pbBuffer );

VOID
SYMCRYPT_CALL
SymCryptFdefModElementWipe(
    _In_    PCSYMCRYPT_MODULUS      pmMod,
    _Out_   PSYMCRYPT_MODELEMENT    peDst );

VOID
SymCryptFdefModElementCopy(
    _In_    PCSYMCRYPT_MODULUS      pmMod,
    _In_    PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_   PSYMCRYPT_MODELEMENT    peDst );

VOID
SymCryptFdefModElementMaskedCopy(
    _In_    PCSYMCRYPT_MODULUS      pmMod,
    _In_    PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_   PSYMCRYPT_MODELEMENT    peDst,
            UINT32                  mask );

PSYMCRYPT_DIVISOR
SYMCRYPT_CALL
SymCryptFdefDivisorFromModulus( _In_ PSYMCRYPT_MODULUS pmSrc );

VOID
SymCryptFdefModElementConditionalSwap(
    _In_       PCSYMCRYPT_MODULUS    pmMod,
    _Inout_    PSYMCRYPT_MODELEMENT  peData1,
    _Inout_    PSYMCRYPT_MODELEMENT  peData2,
    _In_       UINT32                cond );

PSYMCRYPT_INT
SYMCRYPT_CALL
SymCryptFdefIntFromModulus( _In_ PSYMCRYPT_MODULUS pmSrc );

VOID
SYMCRYPT_CALL
SymCryptFdefIntToModulus(
    _In_                            PCSYMCRYPT_INT      piSrc,
    _Out_                           PSYMCRYPT_MODULUS   pmDst,
                                    UINT32              averageOperations,
                                    UINT32              flags,
    _Out_writes_bytes_( cbScratch ) PBYTE               pbScratch,
                                    SIZE_T              cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefIntToModElement(
    _In_                            PCSYMCRYPT_INT          piSrc,
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModElementToIntGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCUINT32                pSrc,
    _Out_                           PSYMCRYPT_INT           piDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptFdefRawSetValue(
    _In_reads_bytes_(cbSrc)                             PCBYTE                  pbSrc,
                                                        SIZE_T                  cbSrc,
                                                        SYMCRYPT_NUMBER_FORMAT  format,
    _Out_writes_(nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32) PUINT32                 pDst,
                                                        UINT32                  nDigits );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptFdefModElementSetValueGeneric(
    _In_reads_bytes_( cbSrc )       PCBYTE                  pbSrc,
                                    SIZE_T                  cbSrc,
                                    SYMCRYPT_NUMBER_FORMAT  format,
                                    PCSYMCRYPT_MODULUS      pmMod,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModElementSetValueUint32Generic(
                                    UINT32                  value,
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModElementSetValueNegUint32(
                                    UINT32                  value,
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptFdefRawGetValue(
    _In_reads_(nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32)   PCUINT32                pSrc,
                                                        UINT32                  nDigits,
    _Out_writes_bytes_(cbBytes)                         PBYTE                   pbDst,
                                                        SIZE_T                  cbDst,
                                                        SYMCRYPT_NUMBER_FORMAT  format );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptFdefModElementGetValue(
                                    PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_writes_bytes_( cbDst )     PBYTE                   pbDst,
                                    SIZE_T                  cbDst,
                                    SYMCRYPT_NUMBER_FORMAT  format,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

UINT32
SYMCRYPT_CALL
SymCryptFdefModElementIsEqual(
    _In_    PCSYMCRYPT_MODULUS     pmMod,
    _In_    PCSYMCRYPT_MODELEMENT  peSrc1,
    _In_    PCSYMCRYPT_MODELEMENT  peSrc2 );

UINT32
SYMCRYPT_CALL
SymCryptFdefModElementIsZero(
    _In_    PCSYMCRYPT_MODULUS     pmMod,
    _In_    PCSYMCRYPT_MODELEMENT  peSrc );

VOID
SYMCRYPT_CALL
SymCryptFdefModAddGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModAdd256Asm(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdef369ModAddGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModSubGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdef369ModSubGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModSub256Asm(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModNegGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdef369ModNegGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModSetPostGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Inout_                         PSYMCRYPT_MODELEMENT    peObj,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModSetPostMontgomery(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Inout_                         PSYMCRYPT_MODELEMENT    peObj,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModSetPostMontgomery256(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Inout_                         PSYMCRYPT_MODELEMENT    peObj,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdef369ModSetPostMontgomery(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Inout_                         PSYMCRYPT_MODELEMENT    peObj,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

PCUINT32
SYMCRYPT_CALL
SymCryptFdefModPreGetGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peObj,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

PCUINT32
SYMCRYPT_CALL
SymCryptFdefModPreGetMontgomery(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peObj,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

PCUINT32
SYMCRYPT_CALL
SymCryptFdefModPreGetMontgomery256(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peObj,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

PCUINT32
SYMCRYPT_CALL
SymCryptFdef369ModPreGetMontgomery(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peObj,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModulusCopyFixupGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmSrc,
    _Out_                           PSYMCRYPT_MODULUS       pmDst );

VOID
SYMCRYPT_CALL
SymCryptFdefModulusCopyFixupMontgomery(
    _In_                            PCSYMCRYPT_MODULUS      pmSrc,
    _Out_                           PSYMCRYPT_MODULUS       pmDst );

VOID
SYMCRYPT_CALL
SymCryptFdefModulusInitGeneric(
    _Inout_                         PSYMCRYPT_MODULUS       pmObj,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModulusInitMontgomeryInternal(
    _Inout_                         PSYMCRYPT_MODULUS       pmObj,
                                    UINT32                  nUint32Used,            // R = 2^{32 * this parameter}
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModulusInitMontgomery(
    _Inout_                         PSYMCRYPT_MODULUS       pmObj,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModulusInitMontgomery256(
    _Inout_                         PSYMCRYPT_MODULUS       pmObj,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdef369ModulusInitMontgomery(
    _Inout_                         PSYMCRYPT_MODULUS       pmObj,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );
UINT32
SYMCRYPT_CALL
SymCryptFdefRawAdd(
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    Src1,
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    Src2,
    _Out_writes_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE ) PUINT32     Dst,
                                                            UINT32      nDigits );

UINT32
SYMCRYPT_CALL
SymCryptFdefRawSub(
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    pSrc1,
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    pSrc2,
    _Out_writes_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE ) PUINT32     pDst,
                                                            UINT32      nDigits );
UINT32
SYMCRYPT_CALL
SymCryptFdefRawSubUint32(
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    pSrc1,
                                                            UINT32      Src2,
    _Out_writes_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE ) PUINT32     pDst,
                                                            UINT32      nDigits );

VOID
SYMCRYPT_CALL
SymCryptFdefModMulGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pMod,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    pDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModMulMontgomery(
    _In_                            PCSYMCRYPT_MODULUS      pMod,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    pDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModMulMontgomery256Asm(
    _In_                            PCSYMCRYPT_MODULUS      pMod,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    pDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdef369ModMulMontgomery(
    _In_                            PCSYMCRYPT_MODULUS      pMod,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    pDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModMulMontgomeryMulx(
    _In_                            PCSYMCRYPT_MODULUS      pMod,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    pDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModMulMontgomeryMulx1024(
    _In_                            PCSYMCRYPT_MODULUS      pMod,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    pDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModMulMontgomery512(
    _In_                            PCSYMCRYPT_MODULUS      pMod,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    pDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModMulMontgomery1024(
    _In_                            PCSYMCRYPT_MODULUS      pMod,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc1,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc2,
    _Out_                           PSYMCRYPT_MODELEMENT    pDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModSquareGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pMod,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    pDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModSquareMontgomery(
    _In_                            PCSYMCRYPT_MODULUS      pMod,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    pDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModSquareMontgomery256(
    _In_                            PCSYMCRYPT_MODULUS      pMod,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    pDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModSquareMontgomery256Asm(
    _In_                            PCSYMCRYPT_MODULUS      pMod,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    pDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdef369ModSquareMontgomery(
    _In_                            PCSYMCRYPT_MODULUS      pMod,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    pDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModSquareMontgomeryMulx(
    _In_                            PCSYMCRYPT_MODULUS      pMod,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    pDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModSquareMontgomeryMulx1024(
    _In_                            PCSYMCRYPT_MODULUS      pMod,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    pDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModSquareMontgomery512(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModSquareMontgomery1024(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );


VOID
SYMCRYPT_CALL
SymCryptFdefRawMul(
    _In_reads_(nDigits1*SYMCRYPT_FDEF_DIGIT_NUINT32)                PCUINT32    pSrc1,
                                                                    UINT32      nDigits1,
    _In_reads_(nDigits2*SYMCRYPT_FDEF_DIGIT_NUINT32)                PCUINT32    pSrc2,
                                                                    UINT32      nDigits2,
    _Out_writes_((nDigits1+nDigits2)*SYMCRYPT_FDEF_DIGIT_NUINT32)   PUINT32     pDst );

VOID
SYMCRYPT_CALL
SymCryptFdefRawMulMulx(
    _In_reads_(nDigits1*SYMCRYPT_FDEF_DIGIT_NUINT32)                PCUINT32    pSrc1,
                                                                    UINT32      nDigits1,
    _In_reads_(nDigits2*SYMCRYPT_FDEF_DIGIT_NUINT32)                PCUINT32    pSrc2,
                                                                    UINT32      nDigits2,
    _Out_writes_((nDigits1+nDigits2)*SYMCRYPT_FDEF_DIGIT_NUINT32)   PUINT32     pDst );

VOID
SYMCRYPT_CALL
SymCryptFdefRawMulMulx1024(
    _In_reads_(nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32)     PCUINT32    pSrc1,
    _In_reads_(nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32)     PCUINT32    pSrc2,
                                                        UINT32      nDigits,
    _Out_writes_(2*nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32) PUINT32     pDst );

VOID
SYMCRYPT_CALL
SymCryptFdefRawSquare(
    _In_reads_(nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32)         PCUINT32    pSrc,
                                                            UINT32      nDigits,
    _Out_writes_(2*nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32)     PUINT32     pDst );

VOID
SYMCRYPT_CALL
SymCryptFdefRawSquareMulx(
    _In_reads_(nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32)         PCUINT32    pSrc,
                                                            UINT32      nDigits,
    _Out_writes_(2*nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32)     PUINT32     pDst );

VOID
SYMCRYPT_CALL
SymCryptFdefRawSquareMulx1024(
    _In_reads_(nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32)         PCUINT32    pSrc,
                                                            UINT32      nDigits,
    _Out_writes_(2*nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32)     PUINT32     pDst );

VOID
SYMCRYPT_CALL
SymCryptFdef369RawMul(
    _In_reads_(nDigits1*SYMCRYPT_FDEF_DIGIT_NUINT32)                PCUINT32    pSrc1,
                                                                    UINT32      nDigits1,
    _In_reads_(nDigits2*SYMCRYPT_FDEF_DIGIT_NUINT32)                PCUINT32    pSrc2,
                                                                    UINT32      nDigits2,
    _Out_writes_((nDigits1+nDigits2)*SYMCRYPT_FDEF_DIGIT_NUINT32)   PUINT32     pDst );

UINT32
SYMCRYPT_CALL
SymCryptFdefRawIsEqualUint32(
    _In_    PCUINT32        pSrc1,
            UINT32          nDigits,
    _In_    UINT32          u32Src2 );

UINT32
SYMCRYPT_CALL
SymCryptFdefRawNeg(
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    pSrc1,
                                                            UINT32      carryIn,
    _Out_writes_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE ) PUINT32     pDst,
                                                            UINT32      nDigits );

UINT32
SYMCRYPT_CALL
SymCryptFdefRawMaskedAdd(
    _Inout_updates_( nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32 )  PUINT32     pAcc,
    _In_reads_( nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32 )       PCUINT32    pSrc,
                                                            UINT32      mask,
                                                            UINT32      nDigits );

UINT32
SYMCRYPT_CALL
SymCryptFdefRawMaskedSub(
    _Inout_updates_( nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32 )  PUINT32     pAcc,
    _In_reads_( nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32 )       PCUINT32    pSrc,
                                                            UINT32      mask,
                                                            UINT32      nDigits );

VOID
SYMCRYPT_CALL
SymCryptFdefModDivPow2(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peSrc,
                                    UINT32                  exp,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptFdefModInvGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pMod,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    pDst,
                                    UINT32                  flags,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptFdefModInvMontgomery(
    _In_                            PCSYMCRYPT_MODULUS      pMod,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    pDst,
                                    UINT32                  flags,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptFdefModInvMontgomery256(
    _In_                            PCSYMCRYPT_MODULUS      pMod,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    pDst,
                                    UINT32                  flags,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptFdef369ModInvMontgomery(
    _In_                            PCSYMCRYPT_MODULUS      pMod,
    _In_                            PCSYMCRYPT_MODELEMENT   pSrc,
    _Out_                           PSYMCRYPT_MODELEMENT    pDst,
                                    UINT32                  flags,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptModExpGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT   peBase,
    _In_                            PCSYMCRYPT_INT          piExp,
                                    UINT32                  nBitsExp,
                                    UINT32                  flags,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptModMultiExpGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _In_                            PCSYMCRYPT_MODELEMENT * peBaseArray,
    _In_                            PCSYMCRYPT_INT *        piExpArray,
                                    UINT32                  nBases,
                                    UINT32                  nBitsExp,
                                    UINT32                  flags,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefModSetRandomGeneric(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Out_                           PSYMCRYPT_MODELEMENT    peDst,
                                    UINT32                  flags,
    _Out_writes_bytes_( cbScratch ) PBYTE                   pbScratch,
                                    SIZE_T                  cbScratch );

UINT32
SYMCRYPT_CALL
SymCryptFdefRawAddUint32(
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    Src1,
                                                            UINT32      Src2,
    _Out_writes_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE ) PUINT32     Dst,
                                                            UINT32      nDigits );

UINT32
SYMCRYPT_CALL
SymCryptFdefRawAddAsm(
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    Src1,
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    Src2,
    _Out_writes_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE ) PUINT32     Dst,
                                                            UINT32      nDigits );

UINT32
SYMCRYPT_CALL
SymCryptFdef369RawAddAsm(
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    Src1,
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    Src2,
    _Out_writes_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE ) PUINT32     Dst,
                                                            UINT32      nDigits );

UINT32
SYMCRYPT_CALL
SymCryptFdefRawSubAsm(
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    pSrc1,
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    pSrc2,
    _Out_writes_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE ) PUINT32     pDst,
                                                            UINT32      nDigits );

UINT32
SYMCRYPT_CALL
SymCryptFdef369RawSubAsm(
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    pSrc1,
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    pSrc2,
    _Out_writes_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE ) PUINT32     pDst,
                                                            UINT32      nDigits );

UINT32
SYMCRYPT_CALL
SymCryptFdefRawIsLessThan(
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    pSrc1,
    _In_reads_bytes_(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE )   PCUINT32    pSrc2,
                                                            UINT32      nDigits );

VOID
SYMCRYPT_CALL
SymCryptFdefMaskedCopyAsm(
    _In_reads_bytes_( nDigits*SYMCRYPT_FDEF_DIGIT_SIZE )        PCBYTE      pbSrc,
    _Inout_updates_bytes_( nDigits*SYMCRYPT_FDEF_DIGIT_SIZE )   PBYTE       pbDst,
                                                                UINT32      nDigits,
                                                                UINT32      mask );

VOID
SYMCRYPT_CALL
SymCryptFdef369MaskedCopyAsm(
    _In_reads_bytes_( nDigits*SYMCRYPT_FDEF_DIGIT_SIZE )        PCBYTE      pbSrc,
    _Inout_updates_bytes_( nDigits*SYMCRYPT_FDEF_DIGIT_SIZE )   PBYTE       pbDst,
                                                                UINT32      nDigits,
                                                                UINT32      mask );

VOID
SYMCRYPT_CALL
SymCryptFdefRawMulAsm(
    _In_reads_(nDigits1*SYMCRYPT_FDEF_DIGIT_NUINT32)                PCUINT32    pSrc1,
                                                                    UINT32      nDigits1,
    _In_reads_(nDigits2*SYMCRYPT_FDEF_DIGIT_NUINT32)                PCUINT32    pSrc2,
                                                                    UINT32      nDigits2,
    _Out_writes_((nDigits1+nDigits2)*SYMCRYPT_FDEF_DIGIT_NUINT32)   PUINT32     pDst );

VOID
SYMCRYPT_CALL
SymCryptFdefRawSquareAsm(
    _In_reads_(nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32)     PCUINT32    pSrc,
                                                        UINT32      nDigits,
    _Out_writes_(2*nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32) PUINT32     pDst );

VOID
SYMCRYPT_CALL
SymCryptFdef369RawMulAsm(
    _In_reads_(nDigits1*SYMCRYPT_FDEF_DIGIT_NUINT32)                PCUINT32    pSrc1,
                                                                    UINT32      nDigits1,
    _In_reads_(nDigits2*SYMCRYPT_FDEF_DIGIT_NUINT32)                PCUINT32    pSrc2,
                                                                    UINT32      nDigits2,
    _Out_writes_((nDigits1+nDigits2)*SYMCRYPT_FDEF_DIGIT_NUINT32)   PUINT32     pDst );

VOID
SYMCRYPT_CALL
SymCryptFdefRawMul512Asm(
    _In_reads_(nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32)     PCUINT32    pSrc1,
    _In_reads_(nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32)     PCUINT32    pSrc2,
                                                        UINT32      nDigits,
    _Out_writes_(2*nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32) PUINT32     pDst );

VOID
SYMCRYPT_CALL
SymCryptFdefRawSquare512Asm(
    _In_reads_(nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32)     PCUINT32    pSrc,
                                                        UINT32      nDigits,
    _Out_writes_(2*nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32) PUINT32     pDst );

VOID
SYMCRYPT_CALL
SymCryptFdefRawMul1024Asm(
    _In_reads_(nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32)     PCUINT32    pSrc1,
    _In_reads_(nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32)     PCUINT32    pSrc2,
                                                        UINT32      nDigits,
    _Out_writes_(2*nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32) PUINT32     pDst );

VOID
SYMCRYPT_CALL
SymCryptFdefRawSquare1024Asm(
    _In_reads_(nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32)     PCUINT32    pSrc,
                                                        UINT32      nDigits,
    _Out_writes_(2*nDigits*SYMCRYPT_FDEF_DIGIT_NUINT32) PUINT32     pDst );

VOID
SYMCRYPT_CALL
SymCryptFdefMontgomeryReduceAsm(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Inout_                         PUINT32                 pSrc,
    _Out_                           PUINT32                 pDst );

VOID
SYMCRYPT_CALL
SymCryptFdefMontgomeryReduce256Asm(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Inout_                         PUINT32                 pSrc,
    _Out_                           PUINT32                 pDst );

VOID
SYMCRYPT_CALL
SymCryptFdefMontgomeryReduce512Asm(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Inout_                         PUINT32                 pSrc,
    _Out_                           PUINT32                 pDst );

VOID
SYMCRYPT_CALL
SymCryptFdefMontgomeryReduce1024Asm(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Inout_                         PUINT32                 pSrc,
    _Out_                           PUINT32                 pDst );

VOID
SYMCRYPT_CALL
SymCryptFdef369MontgomeryReduce(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Inout_                         PUINT32                 pSrc,
    _Out_                           PUINT32                 pDst );

VOID
SYMCRYPT_CALL
SymCryptFdef369MontgomeryReduceAsm(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Inout_                         PUINT32                 pSrc,
    _Out_                           PUINT32                 pDst );

VOID
SYMCRYPT_CALL
SymCryptFdefMontgomeryReduceMulx(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Inout_                         PUINT32                 pSrc,
    _Out_                           PUINT32                 pDst );

VOID
SYMCRYPT_CALL
SymCryptFdefMontgomeryReduceMulx1024(
    _In_                            PCSYMCRYPT_MODULUS      pmMod,
    _Inout_                         PUINT32                 pSrc,
    _Out_                           PUINT32                 pDst );

// Helper macro for checking for specific key validation flag using bits 4 and 5 in a flags variable
// Must be updated if SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION, SYMCRYPT_FLAG_KEY_RANGE_VALIDATION, or
// SYMCRYPT_FLAG_KEY_RANGE_AND_PUBLIC_KEY_ORDER_VALIDATION are updated.
#define SYMCRYPT_FLAG_KEY_VALIDATION_MASK   SYMCRYPT_FLAG_KEY_RANGE_AND_PUBLIC_KEY_ORDER_VALIDATION

typedef struct _SYMCRYPT_DLGROUP_DH_SAFEPRIME_PARAMS {
    SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE eDhSafePrimeType;

    PCBYTE  pcbPrimeP;

    UINT32  nBitsOfP;  // nBitsOfQ == nBitsOfP-1
    UINT32  nBitsPriv; // nBitsOfQ >= nBitsPriv >= 2s
                       // nBitsPriv will be the enforced maximum length of private keys using this Dlgroup
                       // where s is the maximum security strength supported based on SP800-56Arev3
} SYMCRYPT_DLGROUP_DH_SAFEPRIME_PARAMS;
typedef const SYMCRYPT_DLGROUP_DH_SAFEPRIME_PARAMS * PCSYMCRYPT_DLGROUP_DH_SAFEPRIME_PARAMS;
//
// SYMCRYPT_DLGROUP_DH_SAFEPRIME_PARAMS is used to specify all the parameters needed for creation
// of a Dlgroup based on a safe-prime group (i.e. p = 2q+1, and g = 2).
// Currently this is used exclusively internally, and the interface for explicitly specifying use of
// safe-prime group in SymCrypt is to use

// Internally supported Safe Prime groups
extern const PCSYMCRYPT_DLGROUP_DH_SAFEPRIME_PARAMS SymCryptDlgroupDhSafePrimeParamsModp2048;
extern const PCSYMCRYPT_DLGROUP_DH_SAFEPRIME_PARAMS SymCryptDlgroupDhSafePrimeParamsModp3072;
extern const PCSYMCRYPT_DLGROUP_DH_SAFEPRIME_PARAMS SymCryptDlgroupDhSafePrimeParamsModp4096;
extern const PCSYMCRYPT_DLGROUP_DH_SAFEPRIME_PARAMS SymCryptDlgroupDhSafePrimeParamsModp6144;
extern const PCSYMCRYPT_DLGROUP_DH_SAFEPRIME_PARAMS SymCryptDlgroupDhSafePrimeParamsModp8192;

extern const PCSYMCRYPT_DLGROUP_DH_SAFEPRIME_PARAMS SymCryptDlgroupDhSafePrimeParamsffdhe2048;
extern const PCSYMCRYPT_DLGROUP_DH_SAFEPRIME_PARAMS SymCryptDlgroupDhSafePrimeParamsffdhe3072;
extern const PCSYMCRYPT_DLGROUP_DH_SAFEPRIME_PARAMS SymCryptDlgroupDhSafePrimeParamsffdhe4096;
extern const PCSYMCRYPT_DLGROUP_DH_SAFEPRIME_PARAMS SymCryptDlgroupDhSafePrimeParamsffdhe6144;
extern const PCSYMCRYPT_DLGROUP_DH_SAFEPRIME_PARAMS SymCryptDlgroupDhSafePrimeParamsffdhe8192;

#define SYMCRYPT_DH_SAFEPRIME_GROUP_COUNT (10)

// Note, we rely on the ordering of the parameters from smallest to largest within each named set of
// safe-prime groups as we iterate through them assuming this order in SymCryptDlgroupSetValueSafePrime
extern const PCSYMCRYPT_DLGROUP_DH_SAFEPRIME_PARAMS SymCryptNamedSafePrimeGroups[SYMCRYPT_DH_SAFEPRIME_GROUP_COUNT];

//
// Functions for the each type of curve
//

//--------------------------------------------------------
//--------- Short Weierstrass ----------------------------
//--------------------------------------------------------

extern const PCSYMCRYPT_ECURVE_PARAMS_V2_EXTENSION SymCryptEcurveParamsV2ExtensionShortWeierstrass;

VOID
SYMCRYPT_CALL
SymCryptShortWeierstrassFillScratchSpaces( _In_ PSYMCRYPT_ECURVE pCurve );

VOID
SYMCRYPT_CALL
SymCryptShortWeierstrassSetZero(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _Out_   PSYMCRYPT_ECPOINT   poDst,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch );

VOID
SYMCRYPT_CALL
SymCryptShortWeierstrassSetDistinguished(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _Out_   PSYMCRYPT_ECPOINT   poDst,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch );

UINT32
SYMCRYPT_CALL
SymCryptShortWeierstrassIsEqual(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_ECPOINT  poSrc1,
    _In_    PCSYMCRYPT_ECPOINT  poSrc2,
            UINT32              flags,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch );

UINT32
SYMCRYPT_CALL
SymCryptShortWeierstrassIsZero(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_ECPOINT  poSrc,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch );

UINT32
SYMCRYPT_CALL
SymCryptShortWeierstrassOnCurve(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_ECPOINT  poSrc,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch );

VOID
SYMCRYPT_CALL
SymCryptShortWeierstrassAdd(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_ECPOINT  poSrc1,
    _In_    PCSYMCRYPT_ECPOINT  poSrc2,
    _Out_   PSYMCRYPT_ECPOINT   poDst,
    _In_    UINT32              flags,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch );

VOID
SYMCRYPT_CALL
SymCryptShortWeierstrassAddDiffNonZero(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_ECPOINT  poSrc1,
    _In_    PCSYMCRYPT_ECPOINT  poSrc2,
    _Out_   PSYMCRYPT_ECPOINT   poDst,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch );

VOID
SYMCRYPT_CALL
SymCryptShortWeierstrassDouble(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_ECPOINT  poSrc,
    _Out_   PSYMCRYPT_ECPOINT   poDst,
    _In_    UINT32              flags,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch );

VOID
SYMCRYPT_CALL
SymCryptShortWeierstrassNegate(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _Inout_ PSYMCRYPT_ECPOINT   poSrc,
            UINT32              mask,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch );

//--------------------------------------------------------
//--------- Twisted Edwards ------------------------------
//--------------------------------------------------------

extern const PCSYMCRYPT_ECURVE_PARAMS_V2_EXTENSION SymCryptEcurveParamsV2ExtensionTwistedEdwards;

VOID
SYMCRYPT_CALL
SymCryptTwistedEdwardsFillScratchSpaces( _In_ PSYMCRYPT_ECURVE pCurve );

VOID
SYMCRYPT_CALL
SymCryptTwistedEdwardsSetDistinguished(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _Out_   PSYMCRYPT_ECPOINT   poDst,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch);

VOID
SYMCRYPT_CALL
SymCryptTwistedEdwardsAdd(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_ECPOINT  poSrc1,
    _In_    PCSYMCRYPT_ECPOINT  poSrc2,
    _Out_   PSYMCRYPT_ECPOINT   poDst,
    _In_    UINT32              flags,
    _Out_writes_bytes_opt_(cbScratch)
            PBYTE               pbScratch,
            SIZE_T              cbProvidedScratch);

VOID
SYMCRYPT_CALL
SymCryptTwistedEdwardsAddDiffNonZero(
     _In_    PCSYMCRYPT_ECURVE   pCurve,
     _In_    PCSYMCRYPT_ECPOINT  poSrc1,
     _In_    PCSYMCRYPT_ECPOINT  poSrc2,
     _Out_   PSYMCRYPT_ECPOINT   poDst,
     _Out_writes_bytes_opt_(cbScratch)
             PBYTE               pbScratch,
             SIZE_T              cbScratch );

VOID
SYMCRYPT_CALL
SymCryptTwistedEdwardsDouble(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_ECPOINT  poSrc,
    _Out_   PSYMCRYPT_ECPOINT   poDst,
    _In_    UINT32              flags,
    _Out_writes_bytes_opt_(cbScratch)
    PBYTE                       pbScratch,
    SIZE_T                      cbScratch);

UINT32
SYMCRYPT_CALL
SymCryptTwistedEdwardsIsEqual(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_ECPOINT  poSrc1,
    _In_    PCSYMCRYPT_ECPOINT  poSrc2,
            UINT32              flags,
     _Out_writes_bytes_opt_(cbScratch)
            PBYTE               pbScratch,
            SIZE_T              cbScratch);

UINT32
SYMCRYPT_CALL
SymCryptTwistedEdwardsOnCurve(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_ECPOINT  poSrc,
    _Out_writes_bytes_opt_(cbScratch)
    PBYTE                       pbScratch,
    SIZE_T                      cbScratch);

UINT32
SYMCRYPT_CALL
SymCryptTwistedEdwardsIsZero(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_ECPOINT  poSrc,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch);

VOID
SYMCRYPT_CALL
SymCryptTwistedEdwardsSetZero(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _Out_   PSYMCRYPT_ECPOINT   poDst,
    _Out_writes_bytes_opt_(cbScratch)
            PBYTE               pbScratch,
            SIZE_T              cbScratch);

VOID
SYMCRYPT_CALL
SymCryptTwistedEdwardsNegate(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _Inout_ PSYMCRYPT_ECPOINT   poSrc,
            UINT32              mask,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch );

//--------------------------------------------------------
//--------- Montgomery -----------------------------------
//--------------------------------------------------------

extern const PCSYMCRYPT_ECURVE_PARAMS_V2_EXTENSION SymCryptEcurveParamsV2ExtensionMontgomery;

VOID
SYMCRYPT_CALL
SymCryptMontgomeryFillScratchSpaces( _In_ PSYMCRYPT_ECURVE pCurve );

VOID
SYMCRYPT_CALL
SymCryptMontgomerySetDistinguished(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _Out_   PSYMCRYPT_ECPOINT   poDst,
    _Out_writes_bytes_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch );

UINT32
SYMCRYPT_CALL
SymCryptMontgomeryIsEqual(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_ECPOINT  poSrc1,
    _In_    PCSYMCRYPT_ECPOINT  poSrc2,
            UINT32              flags,
     _Out_writes_bytes_opt_(cbScratch)
            PBYTE               pbScratch,
            SIZE_T              cbScratch);

UINT32
SYMCRYPT_CALL
SymCryptMontgomeryIsZero(
    _In_    PCSYMCRYPT_ECURVE   pCurve,
    _In_    PCSYMCRYPT_ECPOINT  poSrc,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptMontgomeryPointScalarMul(
    _In_    PCSYMCRYPT_ECURVE       pCurve,
    _In_    PCSYMCRYPT_INT          piScalar,
    _In_opt_
            PCSYMCRYPT_ECPOINT      poSrc,
    _In_    UINT32                  flags,
    _Out_   PSYMCRYPT_ECPOINT       poDst,
    _Out_writes_bytes_(cbScratch)
            PBYTE               pbScratch,
            SIZE_T              cbScratch);

//--------------------------------------------------------
//--------- Generic multiplication-related functions -----
//--------------------------------------------------------

VOID
SYMCRYPT_CALL
SymCryptOfflinePrecomputation(
    _In_ PSYMCRYPT_ECURVE pCurve,
    _Out_writes_bytes_( cbScratch )
            PBYTE         pbScratch,
            SIZE_T        cbScratch );

_Success_(return == SYMCRYPT_NO_ERROR)
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptEcpointScalarMulFixedWindow(
    _In_    PCSYMCRYPT_ECURVE       pCurve,
    _In_    PCSYMCRYPT_INT          piScalar,
    _In_opt_
            PCSYMCRYPT_ECPOINT      poSrc,
    _In_    UINT32                  flags,
    _Out_   PSYMCRYPT_ECPOINT       poDst,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch );

_Success_(return == SYMCRYPT_NO_ERROR)
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptEcpointMultiScalarMulWnafWithInterleaving(
    _In_    PCSYMCRYPT_ECURVE       pCurve,
    _In_    PCSYMCRYPT_INT *        piSrcScalarArray,
    _In_    PCSYMCRYPT_ECPOINT *    poSrcEcpointArray,
    _In_    UINT32                  nPoints,
    _In_    UINT32                  flags,
    _Out_   PSYMCRYPT_ECPOINT       poDst,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE               pbScratch,
            SIZE_T              cbScratch );

VOID
SYMCRYPT_CALL
SymCryptEcpointGenericSetRandom(
    _In_    PCSYMCRYPT_ECURVE       pCurve,
    _Out_   PSYMCRYPT_INT           piScalar,
    _Out_   PSYMCRYPT_ECPOINT       poDst,
    _Out_writes_bytes_opt_( cbScratch )
            PBYTE                   pbScratch,
            SIZE_T                  cbScratch );
//--------------------------------------------------------
//--------------------------------------------------------

// Table with the number of field elements for each point format (in ecpoint.c)
extern const UINT32 SymCryptEcpointFormatNumberofElements[4];

UINT32
SYMCRYPT_CALL
SymCryptSizeofEcpointEx(
    UINT32 cbModElement,
    UINT32 numOfCoordinates );


PCSYMCRYPT_TRIALDIVISION_CONTEXT
SYMCRYPT_CALL
SymCryptFdefCreateTrialDivisionContext( UINT32 nDigits );

UINT32
SYMCRYPT_CALL
SymCryptFdefIntFindSmallDivisor(
    _In_                            PCSYMCRYPT_TRIALDIVISION_CONTEXT    pContext,
    _In_                            PCSYMCRYPT_INT                      piSrc,
    _Out_writes_bytes_( cbScratch ) PBYTE                               pbScratch,
                                    SIZE_T                              cbScratch );

VOID
SYMCRYPT_CALL
SymCryptFdefFreeTrialDivisionContext( PCSYMCRYPT_TRIALDIVISION_CONTEXT pContext );

UINT64
SymCryptInverseMod2e64( UINT64 v );


//--------------------------------------------------------
//--------------------------------------------------------

// Recoding algorithms
VOID
SYMCRYPT_CALL
SymCryptFixedWindowRecoding(
            UINT32          W,
    _Inout_ PSYMCRYPT_INT   piK,
    _Inout_ PSYMCRYPT_INT   piTmp,
    _Out_writes_( nRecodedDigits )
            PUINT32         absofKIs,
    _Out_writes_( nRecodedDigits )
            PUINT32         sigofKIs,
            UINT32          nRecodedDigits );

VOID
SYMCRYPT_CALL
SymCryptWidthNafRecoding(
            UINT32          W,
    _Inout_ PSYMCRYPT_INT   piK,
    _Out_writes_( nRecodedDigits )
            PUINT32         absofKIs,
    _Out_writes_( nRecodedDigits )
            PUINT32         sigofKIs,
            UINT32          nRecodedDigits );

VOID
SYMCRYPT_CALL
SymCryptPositiveWidthNafRecoding(
            UINT32          W,
    _In_    PCSYMCRYPT_INT  piK,
            UINT32          nBitsExp,
    _Out_writes_( nRecodedDigits )
            PUINT32         absofKIs,
            UINT32          nRecodedDigits );


#if !SYMCRYPT_MS_VC

// Ingnore the incompatible pointer types void * to PSYMCRYPT_XXX
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"

#define FIELD_OFFSET(type,field)    ((UINT32)(uintptr_t)&(((type *)0)->field))

#define __fastfail(x)               (*((volatile int *)(0)) = (int) (x))

#endif

// Atomics.
#if SYMCRYPT_MS_VC
#include <intrin.h>
#define ATOMIC_OR32(_dest, _val)     _InterlockedOr( (volatile LONG *)(_dest), (LONG)(_val) )
#elif SYMCRYPT_APPLE_CC
#include <libkern/OSAtomic.h>   // atomic operations
#define ATOMIC_OR32(_dest, _val)     OSAtomicOr32Barrier( (uint32_t)(_val), (volatile uint32_t *)(_dest) )
#elif SYMCRYPT_GNUC
#define ATOMIC_OR32(_dest, _val)     __sync_fetch_and_or( (volatile uint32_t *)(_dest), (uint32_t)(_val) )
#endif