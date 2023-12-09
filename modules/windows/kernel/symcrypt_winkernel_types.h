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

#ifndef BYTE
typedef UCHAR BYTE;
#endif

//////////////////////////////////////////////////////////
//
// SymCryptEntropyAccumulator
//

//
// Struct for quickly accumulating low entropy counter values into high entropy source.
// Currently implemented with a cycle counter read in interrupts, but could theoretically
// be fed with any other non-deterministic HW counter read in a periodic way.
//
// The accumulator contains 2 logical entropy buffers.
// A DPC collects data from one buffer while the other one is being accumulated into.
//

#define SYMCRYPT_ENTROPY_ACCUMULATOR_LOGICAL_BUFFERS            (2)
#define SYMCRYPT_ENTROPY_ACCUMULATOR_LOGICAL_BUFFER_SIZE        (128)

// We currently always accumulate 1 sample per bit of the logical buffer regardless of the
// sample size (i.e. with 64-bit counters we accumulate 64 counters to one 64-bit slot in the
// logical buffer), so the number of samples we accumulate per logical buffer is 8x the buffer
// size in bytes
#define SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_LOGICAL_BUFFER (8 * SYMCRYPT_ENTROPY_ACCUMULATOR_LOGICAL_BUFFER_SIZE)

#define SYMCRYPT_ENTROPY_ACCUMULATOR_ACTUAL_BUFFER_SIZE         (SYMCRYPT_ENTROPY_ACCUMULATOR_LOGICAL_BUFFERS * \
                                                                 SYMCRYPT_ENTROPY_ACCUMULATOR_LOGICAL_BUFFER_SIZE)

#define SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_ACTUAL_BUFFER  (SYMCRYPT_ENTROPY_ACCUMULATOR_LOGICAL_BUFFERS * \
                                                                 SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_LOGICAL_BUFFER)

typedef struct _SYMCRYPT_ENTROPY_RAW_SAMPLE {
    UINT64 sampleIndex; // This struct represents the sampleIndex'th raw sample accumulated
    UINT64 sampleValue; // The value of the raw sample
} SYMCRYPT_ENTROPY_RAW_SAMPLE;
typedef       SYMCRYPT_ENTROPY_RAW_SAMPLE * PSYMCRYPT_ENTROPY_RAW_SAMPLE;
typedef const SYMCRYPT_ENTROPY_RAW_SAMPLE * PCSYMCRYPT_ENTROPY_RAW_SAMPLE;

typedef DECLSPEC_CACHEALIGN struct _SYMCRYPT_ENTROPY_ACCUMULATOR_STATE {
    BYTE                            buffer[SYMCRYPT_ENTROPY_ACCUMULATOR_ACTUAL_BUFFER_SIZE];
    KDPC                            Dpc;
    UINT64                          nSamplesAccumulated;    // The number of samples accumulated (read/written in interrupt handler)
    UINT64                          nSamplesProcessed;      // The number of samples that have been processed (read/written in DPC)
                                                            // The following invariants should always hold.
                                                            // nSamplesProcessed <= nSamplesAccumulated and
                                                            // nSamplesProcessed + SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_ACTUAL_BUFFER > nSamplesAccumulated
    PSYMCRYPT_ENTROPY_RAW_SAMPLE    pRawSampleBuffer;       // Pointer to a raw sample buffer (normally NULL)
    PSYMCRYPT_ENTROPY_RAW_SAMPLE    pRawSampleBufferToFree; // Pointer to a raw sample buffer that needs to be cleared/freed (normally NULL)
    UINT32                          accumulatorId;
} SYMCRYPT_ENTROPY_ACCUMULATOR_STATE;
typedef       SYMCRYPT_ENTROPY_ACCUMULATOR_STATE * PSYMCRYPT_ENTROPY_ACCUMULATOR_STATE;
typedef const SYMCRYPT_ENTROPY_ACCUMULATOR_STATE * PCSYMCRYPT_ENTROPY_ACCUMULATOR_STATE;
