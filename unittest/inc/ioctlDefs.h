//
// ioctlDefs.h
// Definitions for IOCTL contract to the test driver
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

//
// Define the IOCTL, and the two structures to be passed in and out of the IOCTL.
//

#define DEVICE_NAME     L"\\Device\\SymCryptTest"

#define IOCTL_RUN_TEST CTL_CODE( FILE_DEVICE_UNKNOWN, 0, METHOD_BUFFERED, FILE_ANY_ACCESS )


#pragma pack(push, 8 )

typedef struct _KM_TEST_INPUT {
    SYMCRYPT_CPU_FEATURES   disable;        // which CPU features to disable
} KM_TEST_INPUT;

typedef struct _KM_TEST_RESULT {
    SYMCRYPT_CPU_FEATURES   featuresUsed;
    ULONG   firstSymCryptError;             // 0 if no error, otherwise the first fatalCode encountered
    ULONG   mainThreadError;                // 0 if no error, or an NTSTATUS if the main thread had an error
    ULONGLONG nTestCases;                   // # test cases run 
    ULONGLONG nDpcsOnCpu[64];               // # DPCs run on each logical CPU
} KM_TEST_RESULT;

#pragma pack(pop)
