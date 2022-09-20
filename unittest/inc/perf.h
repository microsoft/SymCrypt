//
// Performance measuring infrastructure header
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//


//
// The performance infrastructure has some flexibility to use different clocks.
//
// On Windows we use HW counters when the target architecture is known, and QueryPerformanceCounter when it is not.
// On Linux we use rdtscp directly for x86/AMD64, and clock_gettime otherwise.
//

// Perf clock scaling uses a fixed function with cycle latency known at compile time as a measuring stick
// to scale an arbitrary wall clock into a cycle clock (detecting CPU frequency changes and retaking measurements
// as appropriate)
// We currently only do not use this for ARM and ARM64 on Windows, where we can guarantee to access a raw CPU cycle counter
#define ENABLE_PERF_CLOCK_SCALING ((BOOLEAN) TRUE)
#define FIXED_TIME_LOOP() fixedTimeLoopPerfFunction( NULL, NULL, NULL, 0 )

#if (SYMCRYPT_MS_VC || SYMCRYPT_GNUC) && (SYMCRYPT_CPU_AMD64 || SYMCRYPT_CPU_X86)
    // Windows or Linux, x86 or AMD64
    #if SYMCRYPT_MS_VC
        #include <intrin.h>
    #else
        #include <x86intrin.h>
    #endif

    FORCEINLINE
    ULONGLONG
    GET_PERF_CLOCK()
    {
        // Use rdtscp instead of rdtsc as it ensures earlier (non-store) instructions complete before it executes
        // This does not have the performance impact of serializing with cpuid
        unsigned int ui;
        ULONGLONG timestamp = __rdtscp(&ui);
        // Use lfence to prevent speculative execution of instructions _after_ the rdtscp (assumes lfence is serializing which is true after spectre mitigations)
        _mm_lfence();
        return timestamp;
    }

    #define PERF_UNIT   "cycles"

#elif SYMCRYPT_MS_VC && (SYMCRYPT_CPU_ARM || SYMCRYPT_CPU_ARM64)
    // Windows, Arm or Arm64
    #undef ENABLE_PERF_CLOCK_SCALING
    #define ENABLE_PERF_CLOCK_SCALING ((BOOLEAN) FALSE)
    #undef FIXED_TIME_LOOP

    #define FIXED_TIME_LOOP() nullPerfFunction( NULL, NULL, NULL, 0 )

    #if SYMCRYPT_CPU_ARM
        // Windows, Arm
        #define GET_PERF_CLOCK() __rdpmccntr64()
    #elif SYMCRYPT_CPU_ARM64
        // Windows, Arm64
        #define GET_PERF_CLOCK() _ReadStatusReg(ARM64_PMCCNTR_EL0)
    #endif
    #define PERF_UNIT   "cycles"

#elif SYMCRYPT_MS_VC
    // Windows, Generic (no architecture specified at compile time)
    FORCEINLINE
    ULONGLONG
    GET_PERF_CLOCK()
    {
        LARGE_INTEGER t;
        QueryPerformanceCounter( &t );
        return (ULONGLONG) t.QuadPart;
    }

    // We rely on performance scaling logic to convert the raw nanoseconds readings into cycles
    #define PERF_UNIT   "cycles"

#elif SYMCRYPT_GNUC
    // Linux, not x86 or AMD64
    FORCEINLINE
    ULONGLONG
    GET_PERF_CLOCK()
    {
        struct timespec time;
        clock_gettime(CLOCK_MONOTONIC, &time);
        return time.tv_nsec;
    }

    // We rely on performance scaling logic to convert the raw nanoseconds readings into cycles
    #define PERF_UNIT   "cycles"
#endif

//
// The perf measuring is complicated. The P4 has all kind of alignment issues; 
// The L1 cache can't hold two cache lines that are aliased mod 64 kB. This leads
// to huge perf differences that are all bogus if you try to compare implementations.
// 
// We solve this by running measurements using many different addresses.
// Each perf function can use up to four memory addresses, each of which is at least
// one MB large. We chose random pointer addresses and run the tests many times.
// We also move the stack around, as the code is unmovable.
//

//
// For algorithms that specify a keying function the keying function will be called before the data 
// function. The keying function should set up any necessary expanded key.
//

typedef VOID (*PerfKeyFn  )( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T  keySize );
typedef VOID (*PerfDataFn )( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize );
typedef VOID (*PerfCleanFn)( PBYTE buf1, PBYTE buf2, PBYTE buf3 );

#define PERF_BUFFER_SIZE    (1<<18)

VOID measurePerf();

extern PSTR g_perfUnits;

