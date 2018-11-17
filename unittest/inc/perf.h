//
// Performance measuring infrastructure header
//
// Copyright (c) Microsoft Corporation.  All rights reserved.
//


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

