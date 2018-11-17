//
// SymCrypt_types.h
//
// Copyright (c) Microsoft Corporation.  All rights reserved.
//

//
// Datatypes used by the SymCrypt library. This ensures compatibility
// with multiple environments, such as Windows, iOS, and Android.
//

#ifdef WIN32

    //
    // Types included in intsafe.h:
    //      BYTE,
    //      INT16, UINT16,
    //      INT32, UINT32,
    //      INT64, UINT64,
    //      UINT_PTR
    // and macro: 
    //      UINT32_MAX
    //
    #include <intsafe.h>

#else
    
    #include <stdint.h>
    
    typedef uint8_t         BYTE;
    
    typedef int16_t         INT16;
    typedef uint16_t        UINT16;
    
    typedef int32_t         INT32;
    typedef uint32_t        UINT32;
    
    typedef int64_t         INT64;
    typedef uint64_t        UINT64;
    
    typedef uintptr_t       UINT_PTR;
    
    #ifndef UINT32_MAX
    #define UINT32_MAX      (0xffffffff)
    #endif
    
    // Boolean
    typedef BYTE            BOOLEAN;

    #ifndef TRUE
    #define TRUE            0x01
    #endif

    #ifndef FALSE
    #define FALSE           0x00
    #endif

    // Size_t
    typedef size_t          SIZE_T;
    
#endif //WIN32

//
// Pointer types
//
typedef BYTE *          PBYTE;
typedef const BYTE *    PCBYTE;

typedef UINT16 *        PUINT16;
typedef const UINT16 *  PCUINT16;

typedef UINT32 *        PUINT32;
typedef const UINT32 *  PCUINT32;

typedef UINT64 *        PUINT64;
typedef const UINT64 *  PCUINT64;

// Void

#ifndef VOID
#define VOID void
#endif

typedef void *          PVOID;
typedef const void *    PCVOID;

