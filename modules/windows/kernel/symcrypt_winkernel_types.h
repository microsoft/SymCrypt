//
// SymCrypt_winkernel_types.h
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

//
// This file contains type definitions that are specific to the Windows kernel module
// without including any dependencies directly.
//

#pragma once

//////////////////////////////////////////////////////////
//
// SymCryptEntropyAccumulator
//

//
// Struct for quickly accumulating low entropy counter values into high entropy source.
// Currently implemented with a cycle counter read in interrupts, but could theoretically
// be fed with any other non-deterministic HW counter read in a periodic way.
//
// The accumulator contains 2 segments in a single contiguous block of memory.
// A DPC collects data from one segment while the other one is being accumulated into.
//

#define SYMCRYPT_ENTROPY_ACCUMULATOR_SEGMENT_COUNT            (2)
#define SYMCRYPT_ENTROPY_ACCUMULATOR_SEGMENT_SIZE             (128)

// We currently always accumulate 1 sample per bit of the segment regardless of the sample size
// (i.e. with 64-bit counters we accumulate 64 counters to one 64-bit slot in the segment),
// so the number of samples we accumulate per segment is 8x the segment size in bytes
#define SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_SEGMENT      (8 * SYMCRYPT_ENTROPY_ACCUMULATOR_SEGMENT_SIZE)

#define SYMCRYPT_ENTROPY_ACCUMULATOR_BUFFER_SIZE              (SYMCRYPT_ENTROPY_ACCUMULATOR_SEGMENT_COUNT * \
                                                               SYMCRYPT_ENTROPY_ACCUMULATOR_SEGMENT_SIZE)

#define SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_BUFFER       (SYMCRYPT_ENTROPY_ACCUMULATOR_SEGMENT_COUNT * \
                                                               SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_SEGMENT)

typedef struct _SYMCRYPT_ENTROPY_RAW_SAMPLE {
    UINT64 sampleIndex; // This struct represents the sampleIndex'th raw sample accumulated
    UINT64 sampleValue; // The value of the raw sample
} SYMCRYPT_ENTROPY_RAW_SAMPLE;
typedef       SYMCRYPT_ENTROPY_RAW_SAMPLE * PSYMCRYPT_ENTROPY_RAW_SAMPLE;
typedef const SYMCRYPT_ENTROPY_RAW_SAMPLE * PCSYMCRYPT_ENTROPY_RAW_SAMPLE;

typedef struct DECLSPEC_CACHEALIGN _SYMCRYPT_ENTROPY_ACCUMULATOR_STATE {
    UCHAR                           buffer[SYMCRYPT_ENTROPY_ACCUMULATOR_BUFFER_SIZE];
    KDPC                            Dpc;
    UINT64                          nSamplesAccumulated;    // The number of samples accumulated
    UINT64                          nHealthTestFailures;    // Number of times the continuous health test has failed
    PSYMCRYPT_ENTROPY_RAW_SAMPLE    pRawSampleBuffer;       // Pointer to a raw sample buffer (normally NULL)
    UINT64                          nRawSamples;            // The number of raw samples to collect (normally 0)
    UINT32                          accumulatorId;
} SYMCRYPT_ENTROPY_ACCUMULATOR_STATE;
typedef       SYMCRYPT_ENTROPY_ACCUMULATOR_STATE * PSYMCRYPT_ENTROPY_ACCUMULATOR_STATE;
typedef const SYMCRYPT_ENTROPY_ACCUMULATOR_STATE * PCSYMCRYPT_ENTROPY_ACCUMULATOR_STATE;
