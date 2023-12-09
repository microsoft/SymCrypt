//
// entropy_accumulator.c
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <ntddk.h>
#include "symcrypt_winkernel.h"
#include "sc_lib.h"

// The next accumulator ID to be used when an entropy accumulator is initialized. Atomically incremented in each initialization.
UINT32 g_SymCryptEntropyAccumulatorNextId = 0;

// Callback function entropy accumulators call in DPC to provide entropy and raw samples to other components
PSYMCRYPT_CALLBACK_ENTROPY_ACCUMULATOR_PROVIDE_ENTROPY_FUNC g_SymCryptCallbackEntropyAccumulatorProvideEntropy = NULL;

// Flag indicating whether configuration read at time of setting callback indicates that raw samples should be collected
BOOLEAN g_SymCryptEntropyAccumulatorCollectRawSamples = FALSE;

VOID
SYMCRYPT_CALL
SymCryptEntropyAccumulatorDpcRoutine(
    _In_        PKDPC   Dpc,
    _In_opt_    PVOID   Context,
    _In_opt_    PVOID   SystemArgument1,
    _In_opt_    PVOID   SystemArgument2 );

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptEntropyAccumulatorInit(
    _Out_   PSYMCRYPT_ENTROPY_ACCUMULATOR_STATE pState,
            UINT32                              flags )
{
    UINT32 accumulatorId;

    if( (flags & ~SYMCRYPT_FLAG_ENTROPY_ACCUMULATOR_ALLOW_RAW_SAMPLE_COLLECTION) != 0 )
    {
        return SYMCRYPT_INVALID_ARGUMENT;
    }

    SymCryptWipeKnownSize(pState->buffer, SYMCRYPT_ENTROPY_ACCUMULATOR_ACTUAL_BUFFER_SIZE);

    // The first logical buffer we will process will be when nSamplesAccumulated == SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_LOGICAL_BUFFER
    //
    // The initial value of nSamplesAccumulated is biased by the accumulatorId in order
    // to avoid having a large number of processors deliver entropy at a single point in
    // time. This can cause issues on a large system where many processors do not receive
    // independent device interrupts and therefore remain in sync with respect to clock
    // interrupts or profiling interrupts.
    // The bias is a small value which effectively means the first logical buffer processed
    // may not be full of entropy.
    accumulatorId = SYMCRYPT_ATOMIC_ADD32_PRE_RELAXED(&g_SymCryptEntropyAccumulatorNextId, 1);
    pState->nSamplesAccumulated = (accumulatorId * 3) % SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_LOGICAL_BUFFER;
    pState->nSamplesProcessed = 0;
    pState->accumulatorId = accumulatorId;
    pState->pRawSampleBuffer = NULL;
    pState->pRawSampleBufferToFree = NULL;

    // The intent is that we collect raw samples only for logical processor 0, when test signing is enabled, a regkey
    // with restricted control has a value with specific data, and we successfully delete the value.
    //
    // Unfortunately there is no public API we can call to query test signing which will be available at the time in
    // boot when this function will be called (NtQuerySystemInformation with SystemCodeIntegrityInformation cannot be
    // used at this point in boot, and also might not be stable across Windows versions).
    // Instead we rely on the kernel to pass us a flag indicating whether test signing is enabled, and based on that
    // we will allocate a raw sample buffer and begin collecting raw samples to it.
    //
    // We also cannot query the registry yet when this function is called, so we defer interacting with the registry
    // to later, when SymCryptEntropyAccumulatorSetCallbackProvideEntropyFn is called.
    // At that point based on our interaction with the registry we may either mark all allocated raw sample buffers to
    // be wiped and freed, or keep them and provide the raw samples to the callback so it may log them for certification
    // or testing purposes.
    if(flags & SYMCRYPT_FLAG_ENTROPY_ACCUMULATOR_ALLOW_RAW_SAMPLE_COLLECTION)
    {
        pState->pRawSampleBuffer = ExAllocatePool2(NonPagedPoolNx,
                                                sizeof(SYMCRYPT_ENTROPY_RAW_SAMPLE) *
                                                SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_ACTUAL_BUFFER,
                                                'aeCS');
    }
    KeInitializeDpc(&pState->Dpc,
                    &SymCryptEntropyAccumulatorDpcRoutine,
                    pState);

    return SYMCRYPT_NO_ERROR;
}

FORCEINLINE
UINT64
SYMCRYPT_CALL
SymCryptReadTimeStampCounter(void)
{
#if SYMCRYPT_CPU_AMD64
    return __rdtsc();
#elif SYMCRYPT_CPU_ARM64
    return (UINT64)_ReadStatusReg(ARM64_PMCCNTR_EL0);
#else
    #error Unexpected CPU (Only AMD64 / Arm64 supported in SymCrypt Kernel Module)
#endif
}

VOID
SYMCRYPT_CALL
SymCryptEntropyAccumulatorAccumulateSample(
    _Inout_ PSYMCRYPT_ENTROPY_ACCUMULATOR_STATE pState )
{
    UINT64 sample = SymCryptReadTimeStampCounter();
    UINT64 nSamplesAccumulated = pState->nSamplesAccumulated;

    //
    // Compute the UINT64-index at which to store the current sample.
    // The entropy accumulator code mixes 64 consecutive samples into a single UINT64.
    //
    SIZE_T bufferIndex = (nSamplesAccumulated & (SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_ACTUAL_BUFFER - 1)) / 64;
    PUINT64 bufferTarget = ((PUINT64)(&pState->buffer[0])) + bufferIndex;

    *bufferTarget = ROR64(*bufferTarget, 19) ^ sample;

    //
    // Save raw sample to raw sample buffer if raw sample buffer exists.
    // This is only used in certification or testing. The DPC will copy the portion of this buffer
    // corresponding to a logical buffer to the raw sample collection logic.
    //
    if( pState->pRawSampleBuffer != NULL )
    {
        PSYMCRYPT_ENTROPY_RAW_SAMPLE pRawSample = &pState->pRawSampleBuffer[nSamplesAccumulated & (SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_ACTUAL_BUFFER - 1)];
        pRawSample->sampleIndex = nSamplesAccumulated;
        pRawSample->sampleValue = sample;
    }

    //
    // Trigger entropy processing if sufficient samples have been collected to fill a logical buffer.
    //
    nSamplesAccumulated++;

    if( (nSamplesAccumulated & (SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_LOGICAL_BUFFER - 1)) == 0 )
    {
        // Schedule DPC to process the accumulated samples
        if( KeInsertQueueDpc(&pState->Dpc, NULL, NULL) == FALSE )
        {
            //
            // If KeInsertQueueDpc returns FALSE, this indicates that the DPC is already queued
            // (i.e. the processing of a previous logical buffer is still in progress)
            //
            // This is an unexpected case. To make it easy to keep a 1:1 correspondence between
            // collected raw samples and the accumulated samples in the logical buffers, we discard
            // the logical buffer we just filled, and reuse it, starting from a zero-ed state.
            // We do this by resetting nSamplesAccumulated and wiping the logical buffer.
            // If we are collecting raw samples, we do not need to wipe the raw sample buffer as
            // it is written to destructively, rather than accumulated into.
            //
            nSamplesAccumulated -= SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_LOGICAL_BUFFER;

            // Compute the byte-index we will next accumulate into; this is the start of logical buffer we wish to wipe
            // As we know nSamplesAccumulated is a multiple of 128, we can just align to the nearest byte
            bufferIndex = (nSamplesAccumulated & (SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_ACTUAL_BUFFER - 1)) / 8;

            // use memset here because the compiler can't optimize it away, and it should have the best codegen.
            // SymCryptWipeKnownSize would also work but it is not optimized for buffers this large.
            memset( &pState->buffer[bufferIndex], 0, SYMCRYPT_ENTROPY_ACCUMULATOR_LOGICAL_BUFFER_SIZE );
        }
    }

    //
    // Store the updated sample count.
    //
    pState->nSamplesAccumulated = nSamplesAccumulated;
}

// For entropy estimation purposes, we estimate 6 bits of entropy per byte of logical buffer.
// This corresponds to each raw sample having a little more than 0.75 bits of entropy.
// This value can be tweaked later based on observed data and what is allowed by health tests.
#define SYMCRYPT_ENTROPY_ACCUMULATOR_ENTROPY_ESTIMATE_PER_BYTE (6000)

VOID
SYMCRYPT_CALL
SymCryptEntropyAccumulatorDpcRoutine(
    _In_        PKDPC   Dpc,
    _In_opt_    PVOID   Context,
    _In_opt_    PVOID   SystemArgument1,
    _In_opt_    PVOID   SystemArgument2 )
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    PSYMCRYPT_ENTROPY_ACCUMULATOR_STATE pState = (PSYMCRYPT_ENTROPY_ACCUMULATOR_STATE)Context;
    UINT64 nSamplesProcessed = pState->nSamplesProcessed;
    SIZE_T logicalBuffer;
    SIZE_T i;
    PUINT64 pu64LogicalBuffer;
    UINT32 entropyEstimateInMilliBits = SYMCRYPT_ENTROPY_ACCUMULATOR_LOGICAL_BUFFER_SIZE * SYMCRYPT_ENTROPY_ACCUMULATOR_ENTROPY_ESTIMATE_PER_BYTE;

    // 
    // Conceptually we have a series of up to 2^(54) logical buffers, each logical buffer being filled by accumulating
    // 2^(10) consecutive samples.
    // In reality we keep 1 actual buffer consisting of 2 logical buffers at any given time.
    //
    // As this DPC runs at a lower IRQL (and could even run on a different logical processor) than the sample accumulation
    // logic, it is possible that in a scenario with a large number of interrupts, we do not complete this DPC before another
    // logical buffer is filled. If this ever happens, the following logical buffer is simply discarded and refilled.
    //

    SYMCRYPT_ASSERT( pState->nSamplesProcessed+SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_LOGICAL_BUFFER <= pState->nSamplesAccumulated );
    SYMCRYPT_ASSERT( pState->nSamplesProcessed+(2*SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_LOGICAL_BUFFER) > pState->nSamplesAccumulated );

    //
    // Compute the starting offset of the logical buffer we will process
    //
    logicalBuffer = (nSamplesProcessed / SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_LOGICAL_BUFFER) %
                        SYMCRYPT_ENTROPY_ACCUMULATOR_LOGICAL_BUFFERS;
    pu64LogicalBuffer = (PUINT64) &pState->buffer[logicalBuffer * SYMCRYPT_ENTROPY_ACCUMULATOR_LOGICAL_BUFFER_SIZE];

    //
    // FIPS health tests
    //
    // The raw samples are 64-bit counter values which monotonically increase.
    // Logical buffers are initialized to 0, and each 64-bit value within the logical buffer is constructed
    // by rotation and exclusive-or of 64 consecutive counter values.
    //
    // We can guarantee to detect if any counter value is repeated 127 times consecutively, by checking if
    // each 64-bit logical value is 0 or -1. If a repeated counter value has an even number of set bits, then one
    // 64-bit value in the logical buffer will take a value of 0, if the repeated counter has an odd number of set
    // bits then the 64-bit value in the logical buffer will take a value of -1.
    //
    // This corresponds to a Developer-Defined Alternative continuous health test with:
    // a) The probability of detecting a single value appearing consecutively more than ceil(100/0.75) = 133 > 127 being
    // 100% (with a ~2^-63 false positive rate)
    // b) Given the counter is monotonic, the only way the probability of a specific sample being observed would increase
    // is if the counter was stuck. If a stuck counter has as 2^(-0.375) probability of being observed across 50000
    // consecutive samples then we are talking about 1000s of consecutive samples having this specific value - again much
    // greater than 127 that we are _guaranteed_ to detect. So we also have 100% chance of detecting this condition.
    //

    // 
    // If there are any 64-bit 0 or -1 values in the buffer, then mark the buffer as having no entropy to indicate failure.
    //
    for (i = 0; i < (SYMCRYPT_ENTROPY_ACCUMULATOR_LOGICAL_BUFFER_SIZE / sizeof(UINT64)); i++)
    {
        if( pu64LogicalBuffer[i] + 1 <= 1 )
        {
            entropyEstimateInMilliBits = 0;
        }
    }

    // If entropy pool ready (callback is set), feed the logical buffer into it
    // Load callback function pointer with atomic acquire semantics to ensure that we have updated view
    // of g_SymCryptEntropyAccumulatorCollectRawSamples
    if( SYMCRYPT_ATOMIC_LOADPTR_ACQUIRE(&g_SymCryptCallbackEntropyAccumulatorProvideEntropy) != NULL )
    {
        PCSYMCRYPT_ENTROPY_RAW_SAMPLE pLogicalRawSampleBuffer = NULL;
        SIZE_T nSamples = 0;

        if( pState->pRawSampleBuffer != NULL )
        {
            if( g_SymCryptEntropyAccumulatorCollectRawSamples )
            {
                pLogicalRawSampleBuffer = pState->pRawSampleBuffer + (logicalBuffer * SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_LOGICAL_BUFFER);
                nSamples = SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_LOGICAL_BUFFER;
            } else {
                // In this case this is the first DPC after callbacks were set and the config read at callback
                // setting time indicates that we should not collect raw samples even though the kernel indicated
                // test signing is enabled.
                //
                // Ideally we could wipe and free pRawSampleBuffer here, but this could lead to a race with a
                // simultaneous interrupt which is accumulating a sample, which could cause a use-after-free issue.
                // Instead we save pRawSampleBuffer to the separate field pRawSampleBufferToFree and set pRawSampleBuffer
                // to NULL here. It is guaranteed that no interrupt is using pRawSampleBuffer in the subsequent DPC.
                // Synchronizing this way avoids having to use any locks in the interrupt handler.
                pState->pRawSampleBufferToFree = pState->pRawSampleBuffer;
                pState->pRawSampleBuffer = NULL;
            }
        }
        else if( pState->pRawSampleBufferToFree != NULL )
        {
            // This is a special case to wipe and free an unused raw sample buffer without use-after-free issues.
            // It should only be hit in the second DPC after the callback is set.
            // See longer comment above.
            SymCryptWipeKnownSize(
                pState->pRawSampleBufferToFree, sizeof(SYMCRYPT_ENTROPY_RAW_SAMPLE) * SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_ACTUAL_BUFFER);
            ExFreePool2(pState->pRawSampleBufferToFree, 'aeCS', NULL, 0);
            pState->pRawSampleBufferToFree = NULL;
        }

        g_SymCryptCallbackEntropyAccumulatorProvideEntropy(
            (PCBYTE)pu64LogicalBuffer,
            SYMCRYPT_ENTROPY_ACCUMULATOR_LOGICAL_BUFFER_SIZE,
            entropyEstimateInMilliBits,
            pLogicalRawSampleBuffer,
            nSamples,
            pState->accumulatorId,
            nSamplesProcessed );
    }

    // Zero the logical buffer
    SymCryptWipeKnownSize(pu64LogicalBuffer, SYMCRYPT_ENTROPY_ACCUMULATOR_LOGICAL_BUFFER_SIZE);

    // Update nSamplesProcessed
    pState->nSamplesProcessed = nSamplesProcessed + SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_LOGICAL_BUFFER;
}

#define SYMCRYPT_ENTROPY_ANALYSIS_KEY_NAME (L"\\Registry\\Machine\\SYSTEM\\RNG\\EntropyAnalysis")
#define SYMCRYPT_ENTROPY_ANALYSIS_ENABLE_VALUE_NAME (L"EnableEntropyAnalysis")
// We check the read value is 1 so we have the option to gate alternative behavior on other values in future
#define SYMCRYPT_ENTROPY_ANALYSIS_ENABLE_VALUE_DATA (1)

//
// Read time-stamp counter sample collection configuration from registry to determine
// if raw sample collection is enabled
//
// Only return true if we successfully read the correct value and delete it.
//
BOOLEAN
SYMCRYPT_CALL
SymCryptEntropyAccumulatorConfigEnablesRawSampleCollection()
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG AttributeFlags = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE | OBJ_FORCE_ACCESS_CHECK;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE hKey = NULL;
    UNICODE_STRING SubKeyName;
    UNICODE_STRING ValueName;
    BYTE queryBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(UINT32)];
    ULONG cbValueInfo;
    PKEY_VALUE_PARTIAL_INFORMATION pPartialInfo;

    BOOLEAN enableRawSampleCollection = FALSE;

    RtlInitUnicodeString(&SubKeyName, SYMCRYPT_ENTROPY_ANALYSIS_KEY_NAME);
    RtlInitUnicodeString(&ValueName, SYMCRYPT_ENTROPY_ANALYSIS_ENABLE_VALUE_NAME);

    InitializeObjectAttributes(
        &ObjectAttributes, &SubKeyName,
        AttributeFlags,
        NULL, NULL);

    // Fail if we can't open the Entropy Analysis subkey
    status = ZwOpenKey(&hKey, KEY_READ | KEY_WRITE | READ_CONTROL | DELETE, &ObjectAttributes);
    if(!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    // Fail if we can't read the enable value
    status = ZwQueryValueKey(   hKey,
                                &ValueName,
                                KeyValuePartialInformation,
                                queryBuffer,
                                sizeof( queryBuffer ),
                                &cbValueInfo );
    if(!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    // Fail if we can't delete the enable value
    status = ZwDeleteValueKey(hKey, &ValueName);
    if(!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    // Fail if the enable value was the wrong type
    pPartialInfo = (PKEY_VALUE_PARTIAL_INFORMATION) &queryBuffer[0];
    if( pPartialInfo->Type != REG_DWORD_LITTLE_ENDIAN || pPartialInfo->DataLength != sizeof(UINT32) )
    {
        goto cleanup;
    }

    // Fail if the enable value had the wrong data
    if( SYMCRYPT_LOAD_LSBFIRST32(&(pPartialInfo->Data[0])) != SYMCRYPT_ENTROPY_ANALYSIS_ENABLE_VALUE_DATA )
    {
        goto cleanup;
    }

    enableRawSampleCollection = TRUE;

cleanup:
    if(hKey)
    {
        ZwClose(hKey);
    }

    return enableRawSampleCollection;
}

BOOLEAN
SYMCRYPT_CALL
SymCryptEntropyAccumulatorSetCallbackProvideEntropyFn(
    _In_ PSYMCRYPT_CALLBACK_ENTROPY_ACCUMULATOR_PROVIDE_ENTROPY_FUNC provideEntropyCallbackFn )
{
    // The provide entropy callback function can only be set once
    if( g_SymCryptCallbackEntropyAccumulatorProvideEntropy != NULL )
    {
        return FALSE;
    }

    //
    // Read config to determine whether raw samples should be collected
    //
    g_SymCryptEntropyAccumulatorCollectRawSamples = SymCryptEntropyAccumulatorConfigEnablesRawSampleCollection();

    //
    // Set the global pointer to the callback function
    //
    // Use atomic store with release semantics to ensure that other threads which observe a non-NULL
    // g_SymCryptCallbackEntropyAccumulatorProvideEntropy also observe the updated value of
    // g_SymCryptEntropyAccumulatorCollectRawSamples
    //
    // We could use a compare-exchange if we wanted to guarantee only one caller sees success, but we
    // should only have one caller
    //
    SYMCRYPT_ATOMIC_STOREPTR_RELEASE(&g_SymCryptCallbackEntropyAccumulatorProvideEntropy, provideEntropyCallbackFn);
    return TRUE;
}
