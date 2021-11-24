//
// Main_test.cpp
// Main file for SymCrypt unit test program
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

//#include <wdm.h>
//#include <ntosp.h>
#include <ntddk.h>
#include <windef.h>
#include <symcrypt.h>
#include <bcrypt.h>

#include "ioctlDefs.h"


typedef VOID (SYMCRYPT_CALL * SelfTestFn)();
typedef struct _SELFTEST_INFO
{
    SelfTestFn  f;
    LPSTR       name;
} SELFTEST_INFO;

ULONGLONG g_nDpcsOnCpu[64];


SYMCRYPT_CPU_FEATURES   g_originalCpuFeatures;

#include "selftestFuncList.cpp"


#define N_THREADS_TO_RUN    (64)

BOOLEAN g_fExitMultithreadTest = FALSE;

ULONGLONG g_nMultithreadTestsRun = 0;
ULONG g_nThreadsFinishing = 0;
SYMCRYPT_CPU_FEATURES g_cpuFeaturesUsed;


extern const SELFTEST_INFO g_selfTests[];

VOID
runTestThread( VOID * seed );

KDEFERRED_ROUTINE drvDpcFunc;

VOID drvDpcFunc(
    PKDPC           pDpc,
    PVOID           deferredContext,
    PVOID           s1,
    PVOID           s2 )
{
    UNREFERENCED_PARAMETER( s1 );
    UNREFERENCED_PARAMETER( s2 );

    ((SelfTestFn) deferredContext)();

    ExFreePoolWithTag( pDpc, 'TcCS' );

    InterlockedIncrement64( (LONGLONG volatile *) &g_nDpcsOnCpu[ KeGetCurrentProcessorNumber() % 64 ] );
}


VOID
scheduleAsyncTest( SelfTestFn f, BYTE rnd )
{
    PKDPC   pDpc;

    pDpc = (PKDPC) ExAllocatePoolZero( NonPagedPoolNx, sizeof( KDPC ), 'TcCS' );
    if( pDpc == NULL )
    {
        return;
    }

    KeInitializeDpc( pDpc, drvDpcFunc, f );
    KeSetTargetProcessorDpc( pDpc, rnd % KeQueryActiveProcessorCount( NULL ) );

    KeInsertQueueDpc( pDpc, 0, 0 );
}


ULONG g_FirstSymCryptErrorCode;

extern "C" {

VOID
SYMCRYPT_CALL
SymCryptFatalIntercept( ULONG fatalCode )
{
    // This function intercepts calls to SymCryptFatal and
    // converts them to killing the current thread after reporting the 
    // first error code in a global.
    InterlockedCompareExchange( (LONG volatile *)&g_FirstSymCryptErrorCode, (LONG) fatalCode, 0 );

    PsTerminateSystemThread( fatalCode );

    //
    // If the thread terminate fails, we fall into the normal fatal handling which will bugcheck.
    //
}

}

KSTART_ROUTINE kmThreadFunc;

VOID 
kmThreadFunc( PVOID startContext )
{
    runTestThread( startContext );
}

NTSTATUS
runKmThreadTest( SYMCRYPT_CPU_FEATURES disable )
{
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS error = 0;
    BCRYPT_ALG_HANDLE rndAlg = 0;
    PVOID seed;
    HANDLE threads[N_THREADS_TO_RUN];
    SIZE_T nThreads = 0;
    LARGE_INTEGER lInt;
    PVOID objPtr;

    g_FirstSymCryptErrorCode = 0;
    g_fExitMultithreadTest = FALSE;
    g_nThreadsFinishing = 0;
    g_nMultithreadTestsRun = 0;


    RtlZeroMemory( g_nDpcsOnCpu, sizeof( g_nDpcsOnCpu ) );

    //
    // Ugly hack, we directly manipulate the CPU features flags.
    //
    g_SymCryptCpuFeaturesNotPresent = disable | g_originalCpuFeatures;
    g_cpuFeaturesUsed = g_SymCryptCpuFeaturesNotPresent | SymCryptCpuFeaturesNeverPresent();

    //
    // We want random numbers, in a way that works on Vista...
    //
    status = BCryptOpenAlgorithmProvider( &rndAlg, BCRYPT_RNG_ALGORITHM, NULL, 0 );
    if( !NT_SUCCESS( status ) )
    {
        goto cleanup;
    }

    //
    // We launch system threads to run the SymCrypt test in. 
    // The Fatal Intercept will convert a SymCrypt fatal to killing the thread so
    // that we don't bugcheck the machine.
    //
    while( nThreads < N_THREADS_TO_RUN )
    {
        status = BCryptGenRandom( rndAlg, (PBYTE) &seed, sizeof( seed), 0 );
        if( !NT_SUCCESS( status ) )
        {
            break;
        }

        status = PsCreateSystemThread( &threads[nThreads], GENERIC_ALL, NULL, NULL, NULL, kmThreadFunc, seed  );
        if( !NT_SUCCESS( status ) )
        {
            break;
        }
        nThreads++;
    }

    if( NT_SUCCESS( status ) )
    {
        lInt.QuadPart = -10 * 1000 * 1000 * 10; // 10 seconds in 100 ns units
        status = KeDelayExecutionThread( KernelMode, FALSE, &lInt );
    }

    g_fExitMultithreadTest = TRUE;

cleanup:

    if( !NT_SUCCESS( status ) && error == 0 )
    {
        error = status;
    }

    while( nThreads > 0 )
    {
        nThreads--;
        status = ObReferenceObjectByHandle( threads[nThreads], SYNCHRONIZE, NULL, KernelMode, &objPtr, NULL );
        if( !NT_SUCCESS( status ) && error == 0 )
        {
            error = status;
            continue;
        }

        lInt.QuadPart = -1 * 1000 * 1000 * 10;   // 1 seconds in 100 ns units.
        status = KeWaitForSingleObject( objPtr, Executive, KernelMode, FALSE, &lInt );
        ObDereferenceObject( objPtr );
        if( status != STATUS_SUCCESS && error == 0 )
        {
            error = status;
        }
    }

    if( rndAlg != 0 )
    {
        BCryptCloseAlgorithmProvider( rndAlg, 0 );
        rndAlg = 0;
    }

    g_SymCryptCpuFeaturesNotPresent = g_originalCpuFeatures;

    return error;
}

VOID
runTestThread( VOID * seed )
{
    BYTE rnd[SYMCRYPT_SHA512_RESULT_SIZE];
    ULONGLONG n = 0;

    memcpy( rnd, &seed, sizeof( seed ) );

    int nTests = 0;

    while( g_selfTests[nTests].f != NULL )
    {
        nTests++;
    }

    while( !g_fExitMultithreadTest )
    {
        SymCryptSha512( rnd, sizeof(rnd), rnd );
        // Run 62 self-tests identified by bytes 2..63.
        for( int i=2; i<SYMCRYPT_SHA512_RESULT_SIZE; i++ )
        {
            g_selfTests[ rnd[i] % nTests ].f();
            n++;
        }
        // Use bytes 0&1 to select the async test.
        scheduleAsyncTest( g_selfTests[ rnd[0] % nTests ].f, rnd[1] );
    }

    InterlockedAdd64( (LONGLONG volatile *) &g_nMultithreadTestsRun, n );
    InterlockedIncrement( (LONG volatile *) &g_nThreadsFinishing );
}

ULONG
runKmTest(
    PBYTE   pbBuffer,
    ULONG   cbInput,
    ULONG   cbOutput )
//
// pbBuffer/cbBuffer is the IOCTL input
// result is placed in pbBuffer/cbBuffer, and # bytes of the answer is returned from 
// the function.
//
{
    KM_TEST_RESULT result;
    KM_TEST_INPUT input;
    int i;
    NTSTATUS status = STATUS_SUCCESS;

    memset( &result, 0, sizeof( result ) );

    if( pbBuffer == 0 || cbInput != sizeof( KM_TEST_INPUT ) || cbOutput != sizeof( KM_TEST_RESULT ))
    {
        status = STATUS_INVALID_PARAMETER;
        goto cleanup;
    }

    memcpy( &input, pbBuffer, cbInput );

    status = runKmThreadTest( input.disable );

cleanup:
    
    result.featuresUsed = g_cpuFeaturesUsed;
    result.firstSymCryptError = g_FirstSymCryptErrorCode;
    result.mainThreadError = status;
    result.nTestCases = g_nMultithreadTestsRun;
    for( i=0; i<64; i++ )
    {
        result.nDpcsOnCpu[i] = g_nDpcsOnCpu[i];
    }

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
    IN PUNICODE_STRING RegistryPath
    )
{
    static UNICODE_STRING nameString=RTL_CONSTANT_STRING(DEVICE_NAME);
    PDEVICE_OBJECT deviceObject=NULL;
    NTSTATUS Status=STATUS_SUCCESS;

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

cleanup:

    return Status;
}

}   // extern "C"

_Use_decl_annotations_
VOID
DrvUnload(
    _In_  struct _DRIVER_OBJECT *DriverObject )
{
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

            if( ControlCode != IOCTL_RUN_TEST )
            {
                Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                Irp->IoStatus.Information = 0;
                break;
            }

            nBytesReturned = runKmTest( (PBYTE) Irp->AssociatedIrp.SystemBuffer, 
                                        irpSp->Parameters.DeviceIoControl.InputBufferLength, 
                                        irpSp->Parameters.DeviceIoControl.OutputBufferLength );

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

