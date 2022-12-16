//
// SymCryptKernelTestModule_IoctlDefs.h
// Definitions for IOCTL contract to the test driver
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

//
// Define the IOCTLs, and the structures to be passed in and out of the IOCTLs.
//

#define KMTEST_DEVICE_NAME     L"\\Device\\SymCryptKernelTestModule"

#define IOCTL_INIT CTL_CODE( FILE_DEVICE_UNKNOWN, 0, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_LOOKUP_SYMBOL CTL_CODE( FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_RUN_FUNCTION CTL_CODE( FILE_DEVICE_UNKNOWN, 2, METHOD_BUFFERED, FILE_ANY_ACCESS )


#pragma pack(push, 8 )

#define SCKTM_FATAL_BUFFER_LENGTH (1024)

typedef _Return_type_success_( return == SCKTM_NO_ERROR ) enum
{
    SCKTM_NO_ERROR = 0,
    SCKTM_UNUSED = 0xc000, // Start our error codes here so they're easier to distinguish
    SCKTM_FATAL,
    SCKTM_INVALID_ARGUMENT,
    SCKTM_VECTOR_SAVE_RESTORE,
    SCKTM_NOT_IMPLEMENTED,
} SCKTM_ERROR;

typedef struct _SCKTM_INIT_INPUT
{
    SYMCRYPT_CPU_FEATURES disable;  // which CPU features to disable
    UINT32 api;
    UINT32 minor;
} SCKTM_INIT_INPUT;

typedef struct _SCKTM_INIT_RESULT
{
    SYMCRYPT_CPU_FEATURES featuresMaskUsed; // indicates which CPU features were disabled in running the function
    SCKTM_ERROR scktmError;
    BYTE fatalBuffer[SCKTM_FATAL_BUFFER_LENGTH];
} SCKTM_INIT_RESULT;

typedef struct _SCKTM_LOOKUP_SYMBOL_INPUT
{
    PCSTR pcstrSymCryptSymbolName;
} SCKTM_LOOKUP_SYMBOL_INPUT;

typedef struct _SCKTM_LOOKUP_SYMBOL_RESULT
{
    SCKTM_ERROR scktmError;
    PCVOID pSymbol;
    BYTE fatalBuffer[SCKTM_FATAL_BUFFER_LENGTH];
} SCKTM_LOOKUP_SYMBOL_RESULT;

typedef struct _SCKTM_FUNCTION_INPUT
{
    PCSTR pcstrSymCryptFunctionName;
    PVOID pArgs;
    UINT32 cArgs;
} SCKTM_FUNCTION_INPUT;

typedef struct _SCKTM_FUNCTION_RESULT
{
    SCKTM_ERROR scktmError;
    UINT64 result;
    BYTE fatalBuffer[SCKTM_FATAL_BUFFER_LENGTH];
} SCKTM_FUNCTION_RESULT;

#pragma pack(pop)
