//
// module.cpp
// Main file for SymCrypt DLL/shared object library.
// Acts as intermediary between symcryptunittest and SymCryptKernelTestModule.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"
#include "SymCryptKernelTestModule_IoctlDefs.h"
#include <unordered_map>

HANDLE hDevice = 0;

#define PATH_BUFFER_LEN (300)

PSTR testDriverName = "SymCryptKernelTestModule.sys";

SC_HANDLE scManager = 0;
SC_HANDLE scService = 0;
BOOL serviceStarted = FALSE;

UINT32 g_initApi;
UINT32 g_initMinor;

PVOID SymCryptKmFipsGetSelftestsPerformed;

std::unordered_map<LPCSTR, FARPROC> symbolAddresses;

extern "C" {
__declspec(dllexport)
FARPROC SctestGetSymbolAddress(HMODULE hModule, LPCSTR lpProcName, SCTEST_DYNSYM_TYPE symbolType);
}

VOID SYMCRYPT_CALL SymCryptKernelTestModuleStashApiVersions( UINT32 api, UINT32 minor );
// Our implementation of SymCryptModuleInit

SYMCRYPT_CPU_FEATURES SymCryptKernelTestModuleInit( SYMCRYPT_CPU_FEATURES disable );
// Our implementation of SctestDisableCpuFeatures

FARPROC SctestGetFunctionAddress( HMODULE hModule, LPCSTR lpProcName );

FARPROC SctestGetSymbolAddress( HMODULE hModule, LPCSTR lpProcName, SCTEST_DYNSYM_TYPE symbolType )
{
    if( symbolType == SCTEST_DYNSYM_FUNCTION_PTR )
    {
        return SctestGetFunctionAddress(hModule, lpProcName);
    }

    SCKTM_LOOKUP_SYMBOL_INPUT lookupInput;
    SCKTM_LOOKUP_SYMBOL_RESULT lookupResult;
    BOOL res;
    DWORD tmp;
    FARPROC pointerToSymbolAddress = NULL;
    auto cachedSymbolAddress = symbolAddresses.find(lpProcName);
    BOOL lookupArrayAddress = (symbolType==SCTEST_DYNSYM_ARRAY);

    if( cachedSymbolAddress != symbolAddresses.end() )
    {
        if( cachedSymbolAddress->second != NULL )
        {
            if(lookupArrayAddress)
            {
                pointerToSymbolAddress = cachedSymbolAddress->second;
            } else {
                pointerToSymbolAddress = (FARPROC)&(cachedSymbolAddress->second);
            }
        }
        goto cleanup;
    }

    lookupInput.pcstrSymCryptSymbolName = lpProcName;
    res = DeviceIoControl ( hDevice,
                            IOCTL_LOOKUP_SYMBOL,
                            &lookupInput, sizeof( lookupInput ),
                            &lookupResult, sizeof( lookupResult ),
                            &tmp,
                            NULL );
    if( res == 0 )
    {
        fprintf( stdout, "  IOCTL_LOOKUP_SYMBOL (%s) failed, %d, %08x, %d\n", lpProcName, res, GetLastError(), tmp );
        goto cleanup;
    }
    if( lookupResult.scktmError != SCKTM_NO_ERROR )
    {
        // fprintf( stdout, "  IOCTL_LOOKUP_SYMBOL (%s) did not succeed, %d\n", lpProcName, lookupResult.scktmError );

        symbolAddresses.insert({lpProcName, (FARPROC)NULL});
        pointerToSymbolAddress = NULL;
        goto cleanup;
    }

    symbolAddresses.insert({lpProcName, (FARPROC)lookupResult.pSymbol});
    if( lookupArrayAddress )
    {
        pointerToSymbolAddress = symbolAddresses[lpProcName];
    } else {
        pointerToSymbolAddress = (FARPROC)&(symbolAddresses[lpProcName]);
    }

cleanup:
    return pointerToSymbolAddress;
}

#if SYMCRYPT_CPU_X86
// Temporarily needed while external SymCrypt API does not consistently use SYMCRYPT_CALL for function definition
template <typename R, typename ... Types>
constexpr std::integral_constant<unsigned, sizeof ...(Types)> getArgumentCount( R(*f)(Types ...) )
{
    return std::integral_constant<unsigned, sizeof...(Types)>{};
}
#endif

template <typename R, typename ... Types>
constexpr std::integral_constant<unsigned, sizeof ...(Types)> getArgumentCount( R(SYMCRYPT_CALL *f)(Types ...) )
{
    return std::integral_constant<unsigned, sizeof...(Types)>{};
}

CHAR g_KernelDispatchFunctionSuffix[] = "KernelDispatch";
// Make wrapper function around SymCrypt function to dispatch call into Kernel Test Driver
// Wrapper functions always take 16 UINT64 arguments and return a UINT64
// Only a prefix of the arguments are set by the unit tests and used by the code in the driver
//
#define MAKE_KERNEL_DISPATCH_FN(SymCryptFunctionName) \
extern "C" \
{ \
    __declspec(dllexport) auto SYMCRYPT_CALL \
        SymCryptFunctionName##KernelDispatch(UINT64 p0, UINT64 p1, UINT64 p2, UINT64 p3, UINT64 p4, UINT64 p5, UINT64 p6, UINT64 p7, UINT64 p8, UINT64 p9, UINT64 p10, UINT64 p11, UINT64 p12, UINT64 p13, UINT64 p14, UINT64 p15); \
} \
\
auto SYMCRYPT_CALL \
SymCryptFunctionName##KernelDispatch(UINT64 p0, UINT64 p1, UINT64 p2, UINT64 p3, UINT64 p4, UINT64 p5, UINT64 p6, UINT64 p7, UINT64 p8, UINT64 p9, UINT64 p10, UINT64 p11, UINT64 p12, UINT64 p13, UINT64 p14, UINT64 p15) \
{ \
    SCKTM_FUNCTION_INPUT functionInput; \
    SCKTM_FUNCTION_RESULT functionResult; \
    BOOL res; \
    DWORD tmp; \
    UINT64 args[16] = {p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13, p14, p15}; \
    functionInput.pcstrSymCryptFunctionName = #SymCryptFunctionName; \
    functionInput.pArgs = args; \
    functionInput.cArgs = decltype(getArgumentCount(SymCryptFunctionName))::value; \
\
    res = DeviceIoControl(hDevice, \
                            IOCTL_RUN_FUNCTION, \
                            &functionInput, sizeof(functionInput), \
                            &functionResult, sizeof(functionResult), \
                            &tmp, \
                            NULL); \
    if (res == 0) \
    { \
        fprintf(stdout, "  IOCTL_RUN_FUNCTION (%s) failed, %d, %08x, %d", #SymCryptFunctionName, res, GetLastError(), tmp); \
        goto cleanup; \
    } \
    if (functionResult.scktmError != SCKTM_NO_ERROR) \
    { \
        fprintf(stdout, "  IOCTL_RUN_FUNCTION (%s) did not succeed, %d", #SymCryptFunctionName, functionResult.scktmError); \
        if( functionResult.scktmError == SCKTM_FATAL ) \
        { \
            FATAL3( "%.*s", SCKTM_FATAL_BUFFER_LENGTH, functionResult.fatalBuffer ); \
        } \
        goto cleanup; \
    } \
\
cleanup: \
    return functionResult.result; \
}

#define SYMBOL(SymbolName)
#define FUNCTION(FunctionName) MAKE_KERNEL_DISPATCH_FN(FunctionName);
#include "SymCryptKernelTestModule_FuncList.h"
#undef SYMBOL
#undef FUNCTION

FARPROC SctestGetFunctionAddress( HMODULE hModule, LPCSTR lpProcName )
{
    BYTE lpExtendedName[500];
    SIZE_T origLength;

    // The first function that will be looked up in the module (after SctestGetSymbolAddress) are
    // SymCryptModuleInit and SctestDisableCpuFeatures.
    // We want to return the address of a pair of special locally defined functions here,
    // rather than a normal wrapper around a RPC into the kernel driver.
    if( strcmp(lpProcName, "SymCryptModuleInit") == 0 )
    {
        return (FARPROC)&SymCryptKernelTestModuleStashApiVersions;
    }
    if( strcmp(lpProcName, "SctestDisableCpuFeatures") == 0 )
    {
        return (FARPROC)&SymCryptKernelTestModuleInit;
    }

    origLength = strnlen(lpProcName, sizeof(lpExtendedName) - 1);
    if( origLength > sizeof(lpExtendedName) - sizeof(g_KernelDispatchFunctionSuffix) )
    {
        fprintf( stdout, "  SctestGetSymbolAddress function name too long, (%.*s)", (int)origLength, lpProcName );
        return NULL;
    }

    memcpy(lpExtendedName, lpProcName, origLength);
    memcpy(lpExtendedName + origLength, g_KernelDispatchFunctionSuffix, sizeof(g_KernelDispatchFunctionSuffix));

    return GetProcAddress(hModule, (LPCSTR)lpExtendedName);
}

// On unit tests call to "SymCryptModuleInit" defer kernel module initialization
// We need to know what CPU features we want to disable in the INIT_IOCTL
// which we'll get in the subsequent call to "SctestDisableCpuFeatures"
VOID SYMCRYPT_CALL SymCryptKernelTestModuleStashApiVersions( UINT32 api, UINT32 minor )
{
    g_initApi = api;
    g_initMinor = minor;
}

// On unit tests call to "SctestDisableCpuFeatures"
// Ensure that any existing SymCryptKernelTestModule service is deleted
// Create and start a new SymCryptKernelTestModule service then run the Init IOCTL on the newly created service
SYMCRYPT_CPU_FEATURES SymCryptKernelTestModuleInit(SYMCRYPT_CPU_FEATURES disable)
{
    int index;
    DWORD dw;
    NTSTATUS status;
    UNICODE_STRING DriverName;
    OBJECT_ATTRIBUTES ObjA;
    IO_STATUS_BLOCK IOSB;
    BOOL res;
    DWORD tmp;

    fprintf( stdout, "Setting up test service\n" );
    CHAR quotedPathName[PATH_BUFFER_LEN];

    index = 0;

    dw = GetCurrentDirectory( PATH_BUFFER_LEN - index, &quotedPathName[index] );
    if( dw == 0 )
    {
        FATAL2( "Failed to get current directory, error = %08x", GetLastError() );
        goto cleanup;
    }
    index += dw;
    if( index + strnlen(testDriverName, 100) > PATH_BUFFER_LEN )
    {
        FATAL( "Path name too long\n" );
        goto cleanup;
    }

    quotedPathName[index++] = '\\';

    if( StringCchCopyExA( &quotedPathName[index], PATH_BUFFER_LEN - index, testDriverName, NULL, NULL, 0 ) != S_OK )
    {
        FATAL( "Concat failed\n" );
    }

    fprintf( stdout, "Creating service using path (%s)\n", quotedPathName);

    scManager = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
    if( scManager == NULL )
    {
        FATAL2( "Failed to open service control manager, error = %08x.   (Not running as Admin?)\n", GetLastError() );
    }

    // Double check we have deleted any previous copy of the service by opening a handle just to delete it
    scService = OpenService(
                    scManager,
                    "SymCryptKernelTestModule",
                    DELETE);

    if( scService != 0 )
    {
        if( !DeleteService( scService ) )
        {
            // Don't print an error if the error is that the service is marked for deletion
            if( GetLastError() != 0x430 )
            {
                fprintf( stdout, "Failed to delete service, error = %08x\n", GetLastError() );
            }
        }

        if( !CloseServiceHandle( scService ) )
        {
            fprintf( stdout, "Failed to close service handle, error = %08x\n", GetLastError() );
        }

        scService = 0;
    }

    scService = CreateService(
                    scManager,
                    "SymCryptKernelTestModule",
                    NULL, //"SymCrypt test driver",
                    SERVICE_ALL_ACCESS,
                    SERVICE_KERNEL_DRIVER,
                    SERVICE_DEMAND_START,
                    SERVICE_ERROR_IGNORE,
                    quotedPathName,
                    NULL,           // loadOrderGroup
                    NULL,           // TagId
                    NULL,           // dependencies
                    NULL,           // driver object name
                    NULL );         // password

    if( scService == 0 )
    {
        FATAL2( "Failed to create service, error = %08x\n", GetLastError() );
    }

    serviceStarted = StartService( scService, 0, NULL );
    if( !serviceStarted )
    {
        FATAL2( "Failed to start service, error = %08x\n", GetLastError() );
    }

    Sleep( 2000 );

    //
    // have to use the Nt flavor of the file open call because it's a base
    // device not aliased to \DosDevices
    //

    RtlInitUnicodeString( &DriverName, KMTEST_DEVICE_NAME );
    InitializeObjectAttributes(
                &ObjA,
                &DriverName,
                OBJ_CASE_INSENSITIVE,
                0,
                0
                );

    //
    // needs to be non-alertable, else, the DeviceIoControl may return
    // STATUS_USER_APC.
    //

    status = NtOpenFile(
                &hDevice,
                SYNCHRONIZE | FILE_READ_DATA,
                &ObjA,
                &IOSB,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_SYNCHRONOUS_IO_NONALERT
                );
    if( !NT_SUCCESS(status) )
    {
        FATAL2( "Failed to open device %08x", status );
    }

    SCKTM_INIT_INPUT initInput;
    SCKTM_INIT_RESULT initResult;

    initInput.api = g_initApi;
    initInput.minor = g_initMinor;
    initInput.disable = disable;
    res = DeviceIoControl ( hDevice,
                            IOCTL_INIT,
                            &initInput, sizeof( initInput ),
                            &initResult, sizeof( initResult ),
                            &tmp,
                            NULL );
    if( res == 0 )
    {
        FATAL4( "IOCTL_INIT failed, %d, %08x, %d", res, GetLastError(), tmp );
    }
    if( initResult.scktmError != SCKTM_NO_ERROR )
    {
        if( initResult.scktmError == SCKTM_FATAL )
        {
            fprintf(stdout, "IOCTL_INIT\n%.*s", SCKTM_FATAL_BUFFER_LENGTH, initResult.fatalBuffer );
        }

        FATAL2( "IOCTL_INIT did not succeed, %d", initResult.scktmError );
    }

    SymCryptKmFipsGetSelftestsPerformed = SctestGetSymbolAddress(0, "SymCryptFipsGetSelftestsPerformed", SCTEST_DYNSYM_SYMBOL_PTR);
    fprintf( stdout, "SymCryptFipsGetSelftestsPerformed is at %llx\n", *(UINT64*)SymCryptKmFipsGetSelftestsPerformed );

cleanup:
    return initResult.featuresMaskUsed;
}

// Stop the current SymCryptKernelTestModule service and mark it for deletion
VOID SYMCRYPT_CALL SymCryptKernelTestModuleDestroy()
{
    BOOL success;
    SERVICE_STATUS serviceStatus;

    if( serviceStarted )
    {
        success = ControlService( scService, SERVICE_CONTROL_STOP, &serviceStatus );
        if( !success )
        {
            fprintf( stdout, "Failed to stop service, error = %08x\n", GetLastError() );
        }
    }

    if( scService != 0 )
    {
        if( !DeleteService( scService ) )
        {
            fprintf( stdout, "Failed to delete service, error = %08x\n", GetLastError() );
        }

        if( !CloseServiceHandle( scService ) )
        {
            fprintf( stdout, "Failed to close service handle, error = %08x\n", GetLastError() );
        }

        scService = 0;
    }

    if( scManager != NULL )
    {
        if( !CloseServiceHandle( scManager ) )
        {
            fprintf( stdout, "Failed to close service manager handle, error = %08x\n", GetLastError() );
        }
        scManager = 0;
    }
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved )  // reserved
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);
    if( fdwReason == DLL_PROCESS_DETACH )
    {
        // Always try to clean up the created kernel service when the mode is unloaded
        SymCryptKernelTestModuleDestroy();
    }
    return TRUE;
}

_Analysis_noreturn_
VOID
fatal( _In_ PCSTR file, ULONG line, _In_ PCSTR format, ... )
{
    va_list vl;

    fprintf( stdout, "*\n\n***** FATAL ERROR %s(%lu): ", file, line );

    va_start( vl, format );

    vfprintf( stdout, format, vl );
    fprintf( stdout, "\n" );

    exit( -1 );
}
