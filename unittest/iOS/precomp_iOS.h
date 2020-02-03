// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

// Ignore the multi-character character constant warnings
#pragma GCC diagnostic ignored "-Wmultichar"

// Ignore the ISO C++ 11 does allow conversion from string literal to PSTR
#pragma GCC diagnostic ignored "-Wc++11-compat-deprecated-writable-strings"

// Ignore the unused entity issue with UNREFERENCED PARAMETER
#pragma GCC diagnostic ignored "-Wunused-value"


#define ULONG       UINT32
#define DWORD       UINT32

#define PSTR        char *
#define PCSTR       CONST PSTR
#define LPSTR       PSTR
#define LPCSTR      CONST PSTR

#define PUCHAR      unsigned char *

#define WCHAR       wchar_t
#define PWSTR       wchar_t *
#define LPWSTR      PWSTR

#define CONST       const
#define CHAR        char
#define LONGLONG    INT64
#define ULONGLONG   UINT64

#define ULONG_PTR   UINT_PTR

#define BOOL        BOOLEAN

#define NTSTATUS    INT32

#define STATUS_NOT_SUPPORTED             ((NTSTATUS)0xC00000BBL)
#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L) 
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define NT_SUCCESS(Status)               (((NTSTATUS)(Status)) >= 0)  

#define UNREFERENCED_PARAMETER(x)       (x)

typedef enum {  
    BCRYPT_HASH_OPERATION_HASH_DATA = 1,  
    BCRYPT_HASH_OPERATION_FINISH_HASH = 2,  
} BCRYPT_HASH_OPERATION_TYPE;  
  
typedef struct _BCRYPT_MULTI_HASH_OPERATION {  
                            uint32_t                        iHash;          // index of hash object                               
                            BCRYPT_HASH_OPERATION_TYPE      hashOperation;  // operation to be performed      
                            PUCHAR                          pbBuffer;       // data to be hashed, or result buffer                              
                            uint32_t                           cbBuffer;         
} BCRYPT_MULTI_HASH_OPERATION;
