//
// main_sys.cpp
// Main file for SymCryptKernelTestModule
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <ntddk.h>
#include <ntstrsafe.h>
#include <windef.h>
#include <symcrypt.h>
#include <symcrypt_low_level.h>
#include <bcrypt.h>

#include "SymCryptKernelTestModule_IoctlDefs.h"

SYMCRYPT_ENVIRONMENT_WINDOWS_KERNELMODE_LATEST;

#define GENRANDOM(pbBuf, cbBuf)     BCryptGenRandom( NULL, (PBYTE) (pbBuf), (UINT32) (cbBuf), BCRYPT_USE_SYSTEM_PREFERRED_RNG )

SYMCRYPT_CPU_FEATURES   g_originalCpuFeatures;
BYTE    g_bAllocFill;
UINT64  g_magic;

BYTE    g_bFatalBuffer;

BYTE            g_FatalBuff[SCKTM_FATAL_BUFFER_LENGTH];
NTSTRSAFE_PSTR  g_FatalNext;

#define FATAL( text )           {fatal( __FILE__, __LINE__, text );}
#define FATAL3( text, a, b )    {fatal( __FILE__, __LINE__, text, a, b );}
#define CHECK( cond, text )     { if( !(cond) ) { fatal(__FILE__, __LINE__, text );}; _Analysis_assume_( cond );}

#define SCKTM_MAXIMUM_OUTSTANDING_ALLOCS (64)
FAST_MUTEX g_AllocationMutex;

// Every allocation in the driver must be kept in this array and removed when it is freed
// This allows us to catch memory leaks in unit tests, and cleanup all outstanding allocations
// on driver unload if the unit tests crash
PBYTE g_OutstandingAllocationsArray[SCKTM_MAXIMUM_OUTSTANDING_ALLOCS];

VOID
SYMCRYPT_CALL
AllocWithChecksInit()
{
    ExInitializeFastMutex(&g_AllocationMutex);
    memset(g_OutstandingAllocationsArray, 0, sizeof(g_OutstandingAllocationsArray));
    GENRANDOM( (PBYTE) &g_bAllocFill, sizeof( g_bAllocFill ) );
    GENRANDOM( (PBYTE) &g_magic, sizeof( g_magic ) );
}

VOID
SYMCRYPT_CALL
AllocWithChecksCleanup()
{
    PBYTE p;
    UINT i;
    for( i = 0; i < SCKTM_MAXIMUM_OUTSTANDING_ALLOCS; i++ )
    {
        p = g_OutstandingAllocationsArray[i];
        if( p != NULL )
        {
            ExFreePoolWithTag( p, 'bCCS' );
        }
    }
}

VOID
ResetFatalGlobals()
{
    memset( g_FatalBuff, 0, sizeof(g_FatalBuff) );
    g_FatalNext = (NTSTRSAFE_PSTR) &g_FatalBuff[0];
}

VOID
fatal(_In_ PCSTR file, ULONG line, _In_ PCSTR text, ...)
{
    size_t remainingBytes = sizeof(g_FatalBuff) - ((PBYTE)g_FatalNext - &g_FatalBuff[0]);
    va_list vl;

    // This function intercepts calls to fatal and converts them to reporting the first errors in globals.
    RtlStringCchPrintfExA(g_FatalNext, remainingBytes, &g_FatalNext, &remainingBytes, 0, "*\n\n***** FATAL ERROR %s(%lu): ", file, line);

    va_start( vl, text );
    RtlStringCchVPrintfExA( g_FatalNext, remainingBytes, &g_FatalNext, &remainingBytes, 0, text, vl );
    va_end( vl );
}

typedef struct _SYMCRYPT_SYMBOL_INFO
{
    PCSTR   symbolName;
    PCVOID  symbolAddress;
} SYMCRYPT_SYMBOL_INFO, * PSYMCRYPT_SYMBOL_INFO;
typedef const SYMCRYPT_SYMBOL_INFO* PCSYMCRYPT_SYMBOL_INFO;

#define INFO_LINE(SymCryptSymbol) { #SymCryptSymbol, (PCVOID)SymCryptSymbol }


const SYMCRYPT_SYMBOL_INFO g_SymCryptSymbolTable[] =
{
#define SYMBOL(SymbolName)      INFO_LINE(SymbolName),
#define FUNCTION(FunctionName)  INFO_LINE(FunctionName),
#include "SymCryptKernelTestModule_FuncList.h"
#undef FUNCTION
#undef SYMBOL
    { NULL, NULL },
};

ULONG
initSymCrypt(
    PBYTE   pbBuffer,
    ULONG   cbInput,
    ULONG   cbOutput )
//
// pbBuffer/cbBuffer is the IOCTL input
// result is placed in pbBuffer/cbBuffer, and # bytes of the answer is returned from
// the function.
//
{
    SCKTM_INIT_RESULT result;
    SCKTM_INIT_INPUT input;

    memset( &result, 0, sizeof( result ) );

    if( pbBuffer == NULL || cbInput != sizeof( SCKTM_INIT_INPUT ) || cbOutput != sizeof( SCKTM_INIT_RESULT ) )
    {
        result.scktmError = SCKTM_INVALID_ARGUMENT;
        goto cleanup;
    }

    memcpy( &input, pbBuffer, cbInput );
    ResetFatalGlobals();

    //
    // Ugly hack, we directly manipulate the CPU features flags.
    // If we want to support concurrent testing with multiple user processes initializing
    // test driver separate sessions, we can't have the unit tests manipulate the features
    // independently as this can lead to inconsistent key states. For now we require 1
    // instance of SymCryptKernelTestModule_UM.dll creating and using 1 instance of
    // SymCryptKernelTestModule.sys, and we are free to manipulate the global state here.
    //
    g_SymCryptCpuFeaturesNotPresent = input.disable | g_originalCpuFeatures;
    result.featuresMaskUsed = g_SymCryptCpuFeaturesNotPresent | SymCryptCpuFeaturesNeverPresent();

    if( input.api != SYMCRYPT_CODE_VERSION_API ||
        (input.api == SYMCRYPT_CODE_VERSION_API && input.minor > SYMCRYPT_CODE_VERSION_MINOR) )
    {
        FATAL( "SymCrypt version mismatch" );
    }

    SymCryptRngAesInstantiateSelftest();
    SymCryptRngAesReseedSelftest();
    SymCryptRngAesGenerateSelftest();

    SymCrypt3DesSelftest();

    SymCryptAesSelftest( SYMCRYPT_AES_SELFTEST_ALL );
    SymCryptAesCmacSelftest();
    SymCryptCcmSelftest();
    SymCryptGcmSelftest();
    SymCryptXtsAesSelftest();

    SymCryptHmacSha1Selftest();
    SymCryptHmacSha256Selftest();
    SymCryptHmacSha384Selftest();
    SymCryptHmacSha512Selftest();

    SymCryptParallelSha256Selftest();
    SymCryptParallelSha512Selftest();

    SymCryptTlsPrf1_1SelfTest();
    SymCryptTlsPrf1_2SelfTest();

    SymCryptHkdfSelfTest();

    SymCryptSp800_108_HmacSha1SelfTest();
    SymCryptSp800_108_HmacSha256SelfTest();
    SymCryptSp800_108_HmacSha384SelfTest();
    SymCryptSp800_108_HmacSha512SelfTest();

    SymCryptPbkdf2_HmacSha1SelfTest();

    SymCryptSrtpKdfSelfTest();

    SymCryptSshKdfSha256SelfTest();
    SymCryptSshKdfSha512SelfTest();

    SymCryptSha3_256Selftest();

    g_SymCryptFipsSelftestsPerformed |= SYMCRYPT_SELFTEST_ALGORITHM_STARTUP;
    result.scktmError = SCKTM_NO_ERROR;

    // Copy any fatal errors to result
    if ((PBYTE)g_FatalNext - &g_FatalBuff[0] > 0)
    {
        result.scktmError = SCKTM_FATAL;
        memcpy(result.fatalBuffer, g_FatalBuff, SCKTM_FATAL_BUFFER_LENGTH);
        ResetFatalGlobals();
    }

cleanup:
    memcpy( pbBuffer, &result, sizeof( result ) );
    return sizeof( result );
}

ULONG
lookupSymCryptSymbol(
    PBYTE   pbBuffer,
    ULONG   cbInput,
    ULONG   cbOutput )
//
// pbBuffer/cbBuffer is the IOCTL input
// result is placed in pbBuffer/cbBuffer, and # bytes of the answer is returned from
// the function.
//
{
    SCKTM_LOOKUP_SYMBOL_RESULT result;
    SCKTM_LOOKUP_SYMBOL_INPUT input;

    memset( &result, 0, sizeof( result ) );

    if( pbBuffer == NULL || cbInput != sizeof( SCKTM_LOOKUP_SYMBOL_INPUT ) || cbOutput != sizeof( SCKTM_LOOKUP_SYMBOL_RESULT ))
    {
        result.scktmError = SCKTM_INVALID_ARGUMENT;
        goto cleanup;
    }

    memcpy( &input, pbBuffer, cbInput );

    PCSYMCRYPT_SYMBOL_INFO pSymbolInfo = &g_SymCryptSymbolTable[0];
    while( pSymbolInfo->symbolName != NULL )
    {
        if( strcmp(input.pcstrSymCryptSymbolName, pSymbolInfo->symbolName) == 0 )
        {
            result.pSymbol = pSymbolInfo->symbolAddress;
            result.scktmError = SCKTM_NO_ERROR;
            goto cleanup;
        }
        pSymbolInfo++;
    }

    result.scktmError = SCKTM_NOT_IMPLEMENTED;

cleanup:
    memcpy( pbBuffer, &result, sizeof( result ) );
    return sizeof( result );
}

#if SYMCRYPT_CPU_AMD64
/////////////////////////////////////////////////////////////
//
// Code to set up the Vector registers for testing

#define SYMCRYPT_XSTATE_SAVE_SIZE    (56)

typedef
SYMCRYPT_ALIGN
struct _SYMCRYPT_EXTENDED_SAVE_DATA {
    SYMCRYPT_ALIGN  BYTE    data[SYMCRYPT_XSTATE_SAVE_SIZE];
                    SYMCRYPT_MAGIC_FIELD
} SYMCRYPT_EXTENDED_SAVE_DATA, *PSYMCRYPT_EXTENDED_SAVE_DATA;

#include "immintrin.h"

__m256i g_ymmSaveState[16];
__m256i g_ymmStartState[16];
__m256i g_ymmTestState[16];

SYMCRYPT_EXTENDED_SAVE_DATA g_SaveData;
BOOL g_vectorTestActive = FALSE;

extern "C" {
VOID SYMCRYPT_CALL SymCryptEnvKmTestSaveYmmRegistersAsm( __m256i* buffer );
VOID SYMCRYPT_CALL SymCryptEnvKmTestRestoreYmmRegistersAsm( __m256i* buffer );
}

VOID
verifyVectorRegisters()
{
    if( g_vectorTestActive )
    {
        g_vectorTestActive = FALSE;

        SymCryptEnvKmTestSaveYmmRegistersAsm( g_ymmTestState );

        //
        // We want to test that the top half of the Ymm registers have been preserved.
        // For MSFT x64 ABI Xmm6-Xmm15 are non-volatile so should be preserved. We also check this
        // is done, which gives us confidence none of our assembly breaks the ABI.
        //
        for( int i=0; i<sizeof( g_ymmStartState ); i++ )
        {
            if( ((volatile BYTE * )&g_ymmStartState[0])[i] != ((volatile BYTE * )&g_ymmTestState[0])[i] &&
                (((i & 16) == 16 ) || (i > 6*sizeof( g_ymmStartState[0] )))
                )
            {
                FATAL3( "Ymm registers modified without proper save/restore Ymm%d[%d]", i>>5, i&31);
                break;
            }
        }
        SymCryptEnvKmTestRestoreYmmRegistersAsm( g_ymmSaveState );

        SymCryptRestoreYmm(&g_SaveData);
    }
}

VOID
initVectorRegisters()
{
    // To perform Ymm save/restore test we need to have AVX support
    // We also need to inform the OS that we are about to manipulate the Ymm registers in kernel mode
    if ( SYMCRYPT_CPU_FEATURES_PRESENT(SYMCRYPT_CPU_FEATURE_AVX2) &&
        SymCryptSaveYmm(&g_SaveData) == SYMCRYPT_NO_ERROR)
    {
        g_vectorTestActive = TRUE;
        //
        // Explicitly save current state to local area - we are about to overwrite non-volatile registers
        // by intentionally writing random values to all of the Ymm state (ignoring ABI), we will need to
        // restore these values ourselves as the kernel Save/Restore mechanism still expects us to respect
        // the ABI.
        //
        SymCryptEnvKmTestSaveYmmRegistersAsm( g_ymmSaveState );
        //
        // Do the memsets outside the save area as it might use vector registers
        // Set the initial Ymm registers to a non-trivial value. It is likely (for performance
        // reasons) that the upper halves are already zero-ed and will be re-zeroed by any function
        // we call.
        //
        memset( g_ymmTestState, 17, sizeof( g_ymmTestState ) );
        memset( g_ymmStartState, (__rdtsc() & 255) ^ 0x42, sizeof( g_ymmStartState ) );
        SymCryptEnvKmTestRestoreYmmRegistersAsm( g_ymmStartState );
    }
}

#endif


ULONG
runSymCryptFunction(
    PBYTE   pbBuffer,
    ULONG   cbInput,
    ULONG   cbOutput )
//
// pbBuffer/cbBuffer is the IOCTL input
// result is placed in pbBuffer/cbBuffer, and # bytes of the answer is returned from
// the function.
//
{
    SCKTM_FUNCTION_RESULT result;
    SCKTM_FUNCTION_INPUT input;
    PUINT64 pArgs;

    memset( &result, 0, sizeof( result ) );

    if( pbBuffer == 0 || cbInput != sizeof( SCKTM_FUNCTION_INPUT ) || cbOutput != sizeof( SCKTM_FUNCTION_RESULT ))
    {
        result.scktmError = SCKTM_INVALID_ARGUMENT;
        goto cleanup;
    }

    memcpy( &input, pbBuffer, cbInput );
    ResetFatalGlobals();

    PCSYMCRYPT_SYMBOL_INFO pSymbolInfo = &g_SymCryptSymbolTable[0];
    while( pSymbolInfo->symbolName != NULL )
    {
        if( strcmp(input.pcstrSymCryptFunctionName, pSymbolInfo->symbolName) == 0 )
        {
            break;
        }
        pSymbolInfo++;
    }

    if( pSymbolInfo->symbolName == NULL )
    {
        result.scktmError = SCKTM_NOT_IMPLEMENTED;
        goto cleanup;
    }

    pArgs = (PUINT64)input.pArgs;

#if SYMCRYPT_CPU_AMD64
    initVectorRegisters();
#endif

    switch ( input.cArgs )
    {
    case 0:
        result.result = ((UINT64 (*)())pSymbolInfo->symbolAddress)(
            );
        break;
    case 1:
        result.result = ((UINT64 (*)(UINT64))pSymbolInfo->symbolAddress)(
            pArgs[0]);
        break;
    case 2:
        result.result = ((UINT64 (*)(UINT64, UINT64))pSymbolInfo->symbolAddress)(
            pArgs[0], pArgs[1]);
        break;
    case 3:
        result.result = ((UINT64 (*)(UINT64, UINT64, UINT64))pSymbolInfo->symbolAddress)(
            pArgs[0], pArgs[1], pArgs[2]);
        break;
    case 4:
        result.result = ((UINT64 (*)(UINT64, UINT64, UINT64, UINT64))pSymbolInfo->symbolAddress)(
            pArgs[0], pArgs[1], pArgs[2], pArgs[3]);
        break;
    case 5:
        result.result = ((UINT64 (*)(UINT64, UINT64, UINT64, UINT64, UINT64))pSymbolInfo->symbolAddress)(
            pArgs[0], pArgs[1], pArgs[2], pArgs[3], pArgs[4]);
        break;
    case 6:
        result.result = ((UINT64 (*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))pSymbolInfo->symbolAddress)(
            pArgs[0], pArgs[1], pArgs[2], pArgs[3], pArgs[4], pArgs[5]);
        break;
    case 7:
        result.result = ((UINT64 (*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))pSymbolInfo->symbolAddress)(
            pArgs[0], pArgs[1], pArgs[2], pArgs[3], pArgs[4], pArgs[5], pArgs[6]);
        break;
    case 8:
        result.result = ((UINT64 (*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))pSymbolInfo->symbolAddress)(
            pArgs[0], pArgs[1], pArgs[2], pArgs[3], pArgs[4], pArgs[5], pArgs[6], pArgs[7]);
        break;
    case 9:
        result.result = ((UINT64 (*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))pSymbolInfo->symbolAddress)(
            pArgs[0], pArgs[1], pArgs[2], pArgs[3], pArgs[4], pArgs[5], pArgs[6], pArgs[7], pArgs[8]);
        break;
    case 10:
        result.result = ((UINT64 (*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))pSymbolInfo->symbolAddress)(
            pArgs[0], pArgs[1], pArgs[2], pArgs[3], pArgs[4], pArgs[5], pArgs[6], pArgs[7], pArgs[8], pArgs[9]);
        break;
    case 11:
        result.result = ((UINT64 (*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))pSymbolInfo->symbolAddress)(
            pArgs[0], pArgs[1], pArgs[2], pArgs[3], pArgs[4], pArgs[5], pArgs[6], pArgs[7], pArgs[8], pArgs[9], pArgs[10]);
        break;
    case 12:
        result.result = ((UINT64 (*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))pSymbolInfo->symbolAddress)(
            pArgs[0], pArgs[1], pArgs[2], pArgs[3], pArgs[4], pArgs[5], pArgs[6], pArgs[7], pArgs[8], pArgs[9], pArgs[10], pArgs[11]);
        break;
    case 13:
        result.result = ((UINT64 (*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))pSymbolInfo->symbolAddress)(
            pArgs[0], pArgs[1], pArgs[2], pArgs[3], pArgs[4], pArgs[5], pArgs[6], pArgs[7], pArgs[8], pArgs[9], pArgs[10], pArgs[11], pArgs[12]);
        break;
    case 14:
        result.result = ((UINT64 (*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))pSymbolInfo->symbolAddress)(
            pArgs[0], pArgs[1], pArgs[2], pArgs[3], pArgs[4], pArgs[5], pArgs[6], pArgs[7], pArgs[8], pArgs[9], pArgs[10], pArgs[11], pArgs[12], pArgs[13]);
        break;
    case 15:
        result.result = ((UINT64 (*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))pSymbolInfo->symbolAddress)(
            pArgs[0], pArgs[1], pArgs[2], pArgs[3], pArgs[4], pArgs[5], pArgs[6], pArgs[7], pArgs[8], pArgs[9], pArgs[10], pArgs[11], pArgs[12], pArgs[13], pArgs[14]);
        break;
    case 16:
        result.result = ((UINT64 (*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))pSymbolInfo->symbolAddress)(
            pArgs[0], pArgs[1], pArgs[2], pArgs[3], pArgs[4], pArgs[5], pArgs[6], pArgs[7], pArgs[8], pArgs[9], pArgs[10], pArgs[11], pArgs[12], pArgs[13], pArgs[14], pArgs[15]);
        break;

    default:
        result.scktmError = SCKTM_INVALID_ARGUMENT;
        break;
    }

    result.scktmError = SCKTM_NO_ERROR;

#if SYMCRYPT_CPU_AMD64
    verifyVectorRegisters();
#endif

    // Copy any fatal errors to result
    if ((PBYTE)g_FatalNext - &g_FatalBuff[0] > 0)
    {
        result.scktmError = SCKTM_FATAL;
        memcpy(result.fatalBuffer, g_FatalBuff, SCKTM_FATAL_BUFFER_LENGTH);
        ResetFatalGlobals();
    }

cleanup:
    memcpy( pbBuffer, &result, sizeof( result ) );
    return sizeof( result );
}

DRIVER_UNLOAD DrvUnload;
DRIVER_DISPATCH DrvDispatch;
DRIVER_ADD_DEVICE DrvAddDevice;

_Use_decl_annotations_
NTSTATUS
DrvAddDevice(
    struct _DRIVER_OBJECT  *DriverObject,
    struct _DEVICE_OBJECT  *PhysicalDeviceObject
    )
{
    UNREFERENCED_PARAMETER( DriverObject );
    UNREFERENCED_PARAMETER( PhysicalDeviceObject );

    return STATUS_SUCCESS;
}

extern "C" {
;   // fake semicolon to make the IDE have the proper indent.

NTSTATUS
DriverEntry(
    _In_  struct _DRIVER_OBJECT *DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    static UNICODE_STRING nameString = RTL_CONSTANT_STRING(KMTEST_DEVICE_NAME);
    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS Status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER( RegistryPath );

    //
    // Initialize various entry points in the Driver object...
    //
    DriverObject->DriverStartIo = NULL;
    DriverObject->DriverUnload = DrvUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]                   = DrvDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]                    = DrvDispatch;
    DriverObject->MajorFunction[IRP_MJ_READ]                     = DrvDispatch;
    DriverObject->MajorFunction[IRP_MJ_WRITE]                    = DrvDispatch;
    DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION]        = DrvDispatch;
    DriverObject->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION] = DrvDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]           = DrvDispatch;

    //
    // If you set this function, the Service control manager can no longer
    // stop this driver. Don't know why yet.
    //
    //DriverObject->DriverExtension->AddDevice = DrvAddDevice;

    //
    // Create and initialize the Device object.
    //

    Status = IoCreateDevice(
                    DriverObject,
                    0L,
                    &nameString,
                    FILE_DEVICE_UNKNOWN,
                    FILE_DEVICE_SECURE_OPEN,
                    TRUE,                       // exclusive, only one handle is allowed.
                    &deviceObject
                    );
    if (!NT_SUCCESS( Status ))
    {
        goto cleanup;
    }

    SymCryptInit();

    g_originalCpuFeatures = g_SymCryptCpuFeaturesNotPresent;

    AllocWithChecksInit();

cleanup:

    return Status;
}

}   // extern "C"

_Use_decl_annotations_
VOID
DrvUnload(
    _In_  struct _DRIVER_OBJECT *DriverObject )
{
    AllocWithChecksCleanup();

    IoDeleteDevice( DriverObject->DeviceObject );
}

_Use_decl_annotations_
NTSTATUS
DrvDispatch(
    struct _DEVICE_OBJECT   *DeviceObject,
    struct _IRP             *Irp )
{
    NTSTATUS status;
    PIO_STACK_LOCATION irpSp;
    ULONG nBytesReturned;
    ULONG ControlCode;


    UNREFERENCED_PARAMETER( DeviceObject );

    //
    // Get a pointer to the current stack location in the IRP.  This is where
    // the function codes and parameters are stored.
    //

    irpSp = IoGetCurrentIrpStackLocation( Irp );

    //
    // Case on the function that is being performed by the requestor.  If the
    // operation is a valid one for this device, then make it look like it was
    // successfully completed, where possible.
    //

    switch (irpSp->MajorFunction) {

        //
        // For both create/open and close operations, simply set the information
        // field of the I/O status block and complete the request.
        //

        case IRP_MJ_CREATE:
        case IRP_MJ_CLOSE:
            Irp->IoStatus.Status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 0L;
            break;

        //
        // For read operations, set the information field of the I/O status
        // block, set an end-of-file status, and complete the request.
        //

        case IRP_MJ_READ:
            Irp->IoStatus.Status = STATUS_END_OF_FILE;
            Irp->IoStatus.Information = 0L;
            break;

        //
        // For write operations, set the information field of the I/O status
        // block to the number of bytes which were supposed to have been written
        // to the file and complete the request.
        //

        case IRP_MJ_WRITE:
            Irp->IoStatus.Status = STATUS_SUCCESS;
            Irp->IoStatus.Information = irpSp->Parameters.Write.Length;
            break;

        case IRP_MJ_DEVICE_CONTROL:

            ControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;

            if( ControlCode == IOCTL_INIT )
            {
                nBytesReturned = initSymCrypt( (PBYTE) Irp->AssociatedIrp.SystemBuffer,
                                        irpSp->Parameters.DeviceIoControl.InputBufferLength,
                                        irpSp->Parameters.DeviceIoControl.OutputBufferLength );
            }
            else if (ControlCode == IOCTL_LOOKUP_SYMBOL)
            {
                nBytesReturned = lookupSymCryptSymbol( (PBYTE) Irp->AssociatedIrp.SystemBuffer,
                                        irpSp->Parameters.DeviceIoControl.InputBufferLength,
                                        irpSp->Parameters.DeviceIoControl.OutputBufferLength );
            }
            else if( ControlCode == IOCTL_RUN_FUNCTION )
            {
                nBytesReturned = runSymCryptFunction( (PBYTE) Irp->AssociatedIrp.SystemBuffer,
                                        irpSp->Parameters.DeviceIoControl.InputBufferLength,
                                        irpSp->Parameters.DeviceIoControl.OutputBufferLength );
            }
            else
            {
                Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                Irp->IoStatus.Information = 0;
                break;
            }

            Irp->IoStatus.Status = STATUS_SUCCESS;
            Irp->IoStatus.Information = nBytesReturned;
            break;

        default:
            Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
            Irp->IoStatus.Information = 0;
    }

    //
    // Copy the final status into the return status, complete the request and
    // get out of here.
    //

    status = Irp->IoStatus.Status;
    IoCompleteRequest( Irp, 0 );
    return status;
}

PVOID
SYMCRYPT_CALL
SymCryptCallbackAlloc( SIZE_T nBytes )
{
    PBYTE p;
    PBYTE res;
    ULONG offset;
    SIZE_T nAllocated;
    UINT i;

    CHECK( g_bAllocFill != 0, "AllocFill not initialized" );

    nAllocated = nBytes + SYMCRYPT_ASYM_ALIGN_VALUE + 16 + 8;   // alignment + 16 byte prefix + 8 byte postfix
    CHECK( (ULONG) nAllocated == nAllocated, "?" );

    p = (PBYTE)ExAllocatePoolZero( NonPagedPoolNx, nAllocated, 'bCCS' );

    // We randomize the fill value a bit to ensure that unused space isn't fully predictable.
    // (We had a bug where ModElementIsEqual tested equality of uninitialized space, and it worked...)
    memset( p, g_bAllocFill, nAllocated );

    // Result is first aligned value at least 16 bytes into the buffer
    res = (PBYTE) (((ULONG_PTR)p + 16 + SYMCRYPT_ASYM_ALIGN_VALUE - 1) & ~(SYMCRYPT_ASYM_ALIGN_VALUE-1) );

    offset = (ULONG)(res - p);
    CHECK( offset >= 16 && offset < 256, "?" );

    *(UINT64 *) &res[-8] = (SIZE_T) res ^ 'strt';
    *(UINT64 *) &res[nBytes ] = (SIZE_T) res ^ 'end.';
    *(UINT32 *) &res[-12] = (UINT32) nBytes;
    *(UINT32 *) &res[-16] = offset;

    ExAcquireFastMutex(&g_AllocationMutex);

    for( i = 0; i < SCKTM_MAXIMUM_OUTSTANDING_ALLOCS; i++ )
    {
        if( g_OutstandingAllocationsArray[i] == NULL )
        {
            g_OutstandingAllocationsArray[i] = p;
            break;
        }
    }
    if( i == SCKTM_MAXIMUM_OUTSTANDING_ALLOCS )
    {
        ExFreePoolWithTag(p, 'bCCS');
        FATAL("Too many outstanding allocations in kernel module!");
    }

    ExReleaseFastMutex(&g_AllocationMutex);

    return res;
}

VOID
SYMCRYPT_CALL
SymCryptCallbackFree(PVOID ptr)
{
    PBYTE p;
    SIZE_T nBytes;
    UINT i;

    p = (PBYTE)ptr;
    nBytes = *(UINT32*)&p[-12];

    CHECK(*(ULONGLONG*)&p[-8] == ((SIZE_T)p ^ 'strt'), "Left magic corrupted");
    CHECK(*(ULONGLONG*)&p[nBytes] == ((SIZE_T)p ^ 'end.'), "Right magic corrupted");
    p = p - *(UINT32 *)&p[-16];
    ExFreePoolWithTag( p, 'bCCS' );

    ExAcquireFastMutex(&g_AllocationMutex);

    for( i = 0; i < SCKTM_MAXIMUM_OUTSTANDING_ALLOCS; i++ )
    {
        if( g_OutstandingAllocationsArray[i] == p )
        {
            g_OutstandingAllocationsArray[i] = NULL;
            break;
        }
    }
    if( i == SCKTM_MAXIMUM_OUTSTANDING_ALLOCS )
    {
        FATAL("Freed a pointer which was not tracked as an outstanding allocation!");
    }

    ExReleaseFastMutex(&g_AllocationMutex);
}

VOID
SYMCRYPT_CALL
SymCryptProvideEntropy(
    _In_reads_(cbEntropy)   PCBYTE  pbEntropy,
                            SIZE_T  cbEntropy )
{
    UNREFERENCED_PARAMETER(pbEntropy);
    UNREFERENCED_PARAMETER(cbEntropy);
}

VOID
SYMCRYPT_CALL
SymCryptRandom(
    _Out_writes_bytes_( cbBuffer )  PBYTE   pbBuffer,
                                    SIZE_T  cbBuffer )
{
    CHECK( cbBuffer < 0xffffffff, "Random buffer too large" );

    GENRANDOM( pbBuffer, cbBuffer );
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptCallbackRandom(
    _Out_writes_bytes_( cbBuffer )  PBYTE   pbBuffer,
                                    SIZE_T  cbBuffer )
{
    NTSTATUS status = STATUS_SUCCESS;

    CHECK( cbBuffer < 0xffffffff, "Random buffer too large" );

    status = GENRANDOM( pbBuffer, cbBuffer );

    return NT_SUCCESS( status ) ? SYMCRYPT_NO_ERROR : SYMCRYPT_EXTERNAL_FAILURE;
}

PVOID
SYMCRYPT_CALL
SymCryptCallbackAllocateMutexFastInproc()
{
    PFAST_MUTEX pFastMutex = (PFAST_MUTEX) ExAllocatePoolZero( NonPagedPoolNx, sizeof(FAST_MUTEX), 'uMCS' );
    ExInitializeFastMutex(pFastMutex);
    return (PVOID)pFastMutex;
}

VOID
SYMCRYPT_CALL
SymCryptCallbackFreeMutexFastInproc( PVOID pMutex )
{
    ExFreePoolWithTag( (PBYTE)pMutex, 'uMCS' );
}

VOID
SYMCRYPT_CALL
SymCryptCallbackAcquireMutexFastInproc( PVOID pMutex )
{
    ExAcquireFastMutex((PFAST_MUTEX)pMutex);
}

VOID
SYMCRYPT_CALL
SymCryptCallbackReleaseMutexFastInproc( PVOID pMutex )
{
    ExReleaseFastMutex((PFAST_MUTEX)pMutex);
}
