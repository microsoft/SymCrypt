//
// SymCrypt_winkernel.h
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

//
// This file contains definitions that are specific to the Windows kernel module.
// Note that this header requires inclusion of symcrypt.h to be compiled, whilst
// symcrypt_winkernel_types.h does not.
//

#pragma once

#include <symcrypt.h>
#include "symcrypt_winkernel_types.h"

//////////////////////////////////////////////////////////
//
// SymCryptEntropyAccumulator
//

//
// The struct and associated functions are exposed from the Windows Kernel SymCrypt module
// to enable certification of this entropy source within the module.
//

// Check at compile time that constants are powers of 2
C_ASSERT((SYMCRYPT_ENTROPY_ACCUMULATOR_LOGICAL_BUFFER_SIZE        & (SYMCRYPT_ENTROPY_ACCUMULATOR_LOGICAL_BUFFER_SIZE-1))        == 0);
C_ASSERT((SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_LOGICAL_BUFFER & (SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_LOGICAL_BUFFER-1)) == 0);
C_ASSERT((SYMCRYPT_ENTROPY_ACCUMULATOR_ACTUAL_BUFFER_SIZE         & (SYMCRYPT_ENTROPY_ACCUMULATOR_ACTUAL_BUFFER_SIZE-1))         == 0);
C_ASSERT((SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_ACTUAL_BUFFER  & (SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_ACTUAL_BUFFER-1))  == 0);

#define SYMCRYPT_FLAG_ENTROPY_ACCUMULATOR_ALLOW_RAW_SAMPLE_COLLECTION (0x01)

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptEntropyAccumulatorInit(
    _Out_   PSYMCRYPT_ENTROPY_ACCUMULATOR_STATE pState,
            UINT32                              flags );
//
// Initialize a SYMCRYPT_ENTROPY_ACCUMULATOR_STATE for subsequent use.
//
// - pState points to a SYMCRYPT_ENTROPY_ACCUMULATOR_STATE
// - flags must be 0 or SYMCRYPT_FLAG_ENTROPY_ACCUMULATOR_ALLOW_RAW_SAMPLE_COLLECTION
//   SYMCRYPT_FLAG_ENTROPY_ACCUMULATOR_ALLOW_RAW_SAMPLE_COLLECTION will enable the entropy
//   accumulator to log raw samples if the configuration read at time of
//   SymCryptEntropyAccumulatorSetCallbackProvideEntropyFn also allows it.
//   It is expected that the release kernel sets this flag only for logical processor 0
//   and only when test signing is enabled in the boot configuration.
//
//  Returns SYMCRYPT_NO_ERROR on successful initialization.
//

VOID
SYMCRYPT_CALL
SymCryptEntropyAccumulatorAccumulateSample(
    _Inout_ PSYMCRYPT_ENTROPY_ACCUMULATOR_STATE pState );
//
// Accumulate a timestamp counter into the given accumulator state. This may potentially trigger
// further processing in a DPC.
//


//
// Callback routine
//
typedef
VOID
(SYMCRYPT_CALL * PSYMCRYPT_CALLBACK_ENTROPY_ACCUMULATOR_PROVIDE_ENTROPY_FUNC) (
    _In_reads_( cbData )        PCBYTE                          pbData,
                                SIZE_T                          cbData,
                                UINT32                          entropyEstimateInMilliBits,
    _In_reads_opt_( nSamples )  PCSYMCRYPT_ENTROPY_RAW_SAMPLE   pRawSampleBuffer,
                                SIZE_T                          nSamples,
                                UINT32                          accumulatorId,
                                UINT64                          nSamplesProcessed );
// The form of the callback function to be defined by our caller to process entropy produced
// by any initialized entropy accumulators
//
// - pbData is a pointer to a buffer of bytes containing entropy
// - cbData is the number of bytes in the buffer
// - entropyEstimateInMilliBits is the number of millibits of entropy that the entropy accumulator
//   asserts is in the entropy buffer
// - pRawSampleBuffer is a pointer to a buffer of raw samples (may be NULL depending on config)
// - nSamples is the number of raw samples in the raw sample buffer
// - accumulatorId is the identifier of the entropy accumulator (this will be unique per instantiated
//   entropy accumulator)
// - nSamplesProcessed is the number of samples the entropy accumulator has processed since it was
//   instantiated. This should increment by SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_LOGICAL_BUFFER each
//   time an entropy accumulator calls this callback function, but it may not start at 0, depending on
//   how many samples are accumulated before the callback is set.

BOOLEAN
SYMCRYPT_CALL
SymCryptEntropyAccumulatorSetCallbackProvideEntropyFn(
    _In_ PSYMCRYPT_CALLBACK_ENTROPY_ACCUMULATOR_PROVIDE_ENTROPY_FUNC provideEntropyCallbackFn );
//
// Sets the callback function that all entropy accumulators initialized by the module will call into periodically
// to provide entropy buffers to the caller; see documentation of
// PSYMCRYPT_CALLBACK_ENTROPY_ACCUMULATOR_PROVIDE_ENTROPY_FUNC.
//
// This can only be set once, and returns TRUE when it is set.
//
