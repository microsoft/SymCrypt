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

typedef enum _SYMCRYPT_ENTROPY_ACCUMULATOR_RAW_SAMPLE_COLLECTION_TYPE {
    SYMCRYPT_ENTROPY_ACCUMULATOR_RAW_SAMPLE_COLLECTION_UNINITIALIZED = 0,
    SYMCRYPT_ENTROPY_ACCUMULATOR_RAW_SAMPLE_COLLECTION_ON            = 1,
    SYMCRYPT_ENTROPY_ACCUMULATOR_RAW_SAMPLE_COLLECTION_OFF           = 2,
} SYMCRYPT_ENTROPY_ACCUMULATOR_RAW_SAMPLE_COLLECTION_TYPE;

// Enum indicating whether configuration read from registry indicates that raw samples should be collected
UINT32 g_SymCryptEntropyAccumulatorCollectRawSamples = SYMCRYPT_ENTROPY_ACCUMULATOR_RAW_SAMPLE_COLLECTION_UNINITIALIZED;

// Callback function entropy accumulators call in DPC to provide entropy and raw samples to other components
PSYMCRYPT_CALLBACK_ENTROPY_ACCUMULATOR_PROVIDE_ENTROPY_FUNC g_SymCryptCallbackEntropyAccumulatorProvideEntropy = NULL;

VOID
SYMCRYPT_CALL
SymCryptEntropyAccumulatorDpcRoutine(
    _In_        PKDPC   Dpc,
    _In_opt_    PVOID   Context,
    _In_        PVOID   SystemArgument1,
    _In_opt_    PVOID   SystemArgument2 );
    
VOID
SYMCRYPT_CALL
SymCryptEntropyAccumulatorInit0(
    _Out_   PSYMCRYPT_ENTROPY_ACCUMULATOR_STATE pState )
{
    KeInitializeDpc(&pState->Dpc,
                    &SymCryptEntropyAccumulatorDpcRoutine,
                    pState);
    pState->pRawSampleBuffer = NULL;
    pState->nRawSamples = 0;
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptEntropyAccumulatorInit1(
    _Out_   PSYMCRYPT_ENTROPY_ACCUMULATOR_STATE pState,
            UINT64                              config )
{
    UINT32 accumulatorId = SYMCRYPT_ATOMIC_ADD32_PRE_RELAXED(&g_SymCryptEntropyAccumulatorNextId, 1);
    pState->accumulatorId = accumulatorId;

    // The intent is that we collect raw samples only for logical processor 0, when test signing is enabled, a regkey
    // with restricted control has a value with specific data, and we successfully delete the value.
    //
    // Unfortunately there is no public API we can call to query test signing which will be available at the time in
    // boot when this function will be called (NtQuerySystemInformation with SystemCodeIntegrityInformation cannot be
    // used at this point in boot, and also might not be stable across Windows versions).
    // Instead we rely on the kernel to pass us a config UINT64 value read from the registry.
    //
    // As we cannot query the registry yet when this function is called, we defer interacting with the registry to later,
    // when SymCryptEntropyAccumulatorGlobalInitFromRegistry is called.
    // At that point based on our interaction with the registry we may either mark all allocated raw sample buffers to
    // be wiped, or log them for certification or testing purposes.

    // For now we just take the config value provided to us to indicate the number of samples to collect for logical processor 0.
    if( (accumulatorId == 0) && config )
    {
        pState->pRawSampleBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, config * sizeof(SYMCRYPT_ENTROPY_RAW_SAMPLE), 'aeCS');
        pState->nRawSamples = config;
    }

    // Discard any interrupt data up to this point; we cannot use it because we cannot get raw samples for it
    // We reset here in case there are any interrupts in ExAllocatePool2.
    // In practice we discard low 10s of samples only for logical processor 0.
    SymCryptWipeKnownSize(pState->buffer, SYMCRYPT_ENTROPY_ACCUMULATOR_BUFFER_SIZE);

    // The first segment will be processed when nSamplesAccumulated == SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_SEGMENT
    //
    // The initial value of nSamplesAccumulated is biased by the accumulatorId in order
    // to avoid having a large number of processors deliver entropy at a single point in
    // time. This can cause issues on a large system where many processors do not receive
    // independent device interrupts and therefore remain in sync with respect to clock
    // interrupts or profiling interrupts.
    // The bias is a small value which effectively means the first segment processed
    // may not be full of entropy.
    pState->nSamplesAccumulated = (accumulatorId * 3) % SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_SEGMENT;
    pState->nHealthTestFailures = 0;

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
    SIZE_T bufferIndex = (nSamplesAccumulated & (SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_BUFFER - 1)) / 64;
    PUINT64 bufferTarget = ((PUINT64)(&pState->buffer[0])) + bufferIndex;

    *bufferTarget = ROR64(*bufferTarget, 19) ^ sample;

    //
    // Save raw sample to raw sample buffer if raw sample buffer exists.
    // This is only used in certification or testing.
    //
    if( pState->pRawSampleBuffer != NULL )
    {
        if( nSamplesAccumulated < pState->nRawSamples )
        {
            PSYMCRYPT_ENTROPY_RAW_SAMPLE pRawSample = &pState->pRawSampleBuffer[nSamplesAccumulated];
            pRawSample->sampleIndex = nSamplesAccumulated;
            pRawSample->sampleValue = sample;
        }
    }

    //
    // Trigger entropy processing if sufficient samples have been collected to fill a segment.
    //
    nSamplesAccumulated++;

    if( (nSamplesAccumulated & (SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_SEGMENT - 1)) == 0 )
    {
        // Schedule DPC to process the accumulated samples
        if( KeInsertQueueDpc(&pState->Dpc, (PVOID) nSamplesAccumulated, NULL) == FALSE )
        {
            //
            // If KeInsertQueueDpc returns FALSE, this indicates that the DPC is already queued
            // (i.e. the processing of a previous segment is still in progress)
            //
            // This is an unexpected case. To make it easy to keep a 1:1 correspondence between
            // collected raw samples and the accumulated samples in the segment, we discard
            // the segment we just filled, and reuse it, starting from a zero-ed state.
            // We do this by resetting nSamplesAccumulated and wiping the segment.
            // If we are collecting raw samples, we do not need to wipe the raw sample buffer as
            // it is written to destructively, rather than accumulated into.
            //
            nSamplesAccumulated -= SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_SEGMENT;

            // Compute the byte-index we will next accumulate into; this is the start of segment we wish to wipe
            // As we know nSamplesAccumulated is a multiple of 128, we can just align to the nearest byte
            bufferIndex = (nSamplesAccumulated & (SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_BUFFER - 1)) / 8;

            // use memset here because the compiler can't optimize it away, and it should have the best codegen.
            // SymCryptWipeKnownSize would also work but it is not optimized for buffers this large.
            memset( &pState->buffer[bufferIndex], 0, SYMCRYPT_ENTROPY_ACCUMULATOR_SEGMENT_SIZE );
        }
    }

    //
    // Store the updated sample count.
    //
    pState->nSamplesAccumulated = nSamplesAccumulated;
}

VOID
SYMCRYPT_CALL
SymCryptEntropyAccumulatorLogRawSamples(
    PCSYMCRYPT_ENTROPY_RAW_SAMPLE   pRawSampleBuffer,
    SIZE_T                          nSamples,
    UINT32                          accumulatorId,
    SIZE_T                          nSamplesProcessed )
{
    SIZE_T i;
    UINT64 prevSample = 0;

    // NOT INTENDED FOR PRODUCTION!
    // Don't do anything with the data just yet; just fatal if it has an unexpected form
    // Really this should queue some work item to write the data to a file specified by the registry.

    if( accumulatorId != 0 )
    {
        // collecting raw samples for an unexpected accumulator!
        SymCryptFatal('eaai');
    }

    for(i = 0; i < nSamples; i++)
    {
        if( pRawSampleBuffer[i].sampleIndex != (nSamplesProcessed + i) )
        {
            // samples are not from the expected period of time!
            SymCryptFatal('easi');
        }
        if( prevSample > pRawSampleBuffer[i].sampleValue )
        {
            // samples are not monotonic increasing!
            SymCryptFatal('eami');
        }
        prevSample = pRawSampleBuffer[i].sampleValue;
    }
}

// For entropy estimation purposes, we estimate 6 bits of entropy per byte of the buffer.
// This corresponds to each raw sample having a little more than 0.75 bits of entropy.
// This value can be tweaked later based on observed data and what is allowed by health tests.
#define SYMCRYPT_ENTROPY_ACCUMULATOR_ENTROPY_ESTIMATE_PER_BYTE (6000)

VOID
SYMCRYPT_CALL
SymCryptEntropyAccumulatorDpcRoutine(
    _In_        PKDPC   Dpc,
    _In_opt_    PVOID   Context,
    _In_        PVOID   SystemArgument1,
    _In_opt_    PVOID   SystemArgument2 )
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument2);

    PSYMCRYPT_ENTROPY_ACCUMULATOR_STATE pState = (PSYMCRYPT_ENTROPY_ACCUMULATOR_STATE)Context;
    const UINT64 nSamplesAtDpcQueueTime = (UINT64)SystemArgument1;
    const UINT64 nSamplesProcessed = nSamplesAtDpcQueueTime - SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_SEGMENT;
    SIZE_T segmentId;
    SIZE_T i;
    PUINT64 pu64SampleSegment;
    UINT32 entropyEstimateInMilliBits = SYMCRYPT_ENTROPY_ACCUMULATOR_SEGMENT_SIZE * SYMCRYPT_ENTROPY_ACCUMULATOR_ENTROPY_ESTIMATE_PER_BYTE;

    // 
    // Conceptually we have a series of up to 2^(54) accumulators, each being filled by accumulating 2^(10) consecutive samples.
    // In reality we keep 1 actual buffer consisting of 2 segments at any given time.
    //
    // As this DPC runs at a lower IRQL (and could even run on a different logical processor) than the sample accumulation
    // logic, it is possible that in a scenario with a large number of interrupts, we do not complete this DPC before the other
    // segment is filled. If this ever happens, the following segment is simply discarded and refilled.
    //

    SYMCRYPT_ASSERT( nSamplesAtDpcQueueTime >= SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_SEGMENT );
    SYMCRYPT_ASSERT( (nSamplesAtDpcQueueTime & (SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_SEGMENT - 1)) == 0 );

    //
    // Compute the starting offset of the segment we will process
    //
    segmentId = (nSamplesProcessed / SYMCRYPT_ENTROPY_ACCUMULATOR_SAMPLES_PER_SEGMENT) %
                        SYMCRYPT_ENTROPY_ACCUMULATOR_SEGMENT_COUNT;
    pu64SampleSegment = (PUINT64) &pState->buffer[segmentId * SYMCRYPT_ENTROPY_ACCUMULATOR_SEGMENT_SIZE];

    //
    // FIPS health tests
    //
    // The raw samples are 64-bit counter values which monotonically increase.
    // Segments are initialized to 0, and each 64-bit value within the segment is constructed
    // by rotation and exclusive-or of 64 consecutive counter values.
    //
    // We can guarantee to detect if any counter value is repeated 127 times consecutively, by checking if
    // each 64-bit value is 0 or -1. If a repeated counter value has an even number of set bits, then one
    // 64-bit value in the segment will take a value of 0. If the repeated counter has an odd number of set
    // bits then one 64-bit value in the segment will take a value of -1.
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
    for(i = 0; i < (SYMCRYPT_ENTROPY_ACCUMULATOR_SEGMENT_SIZE / sizeof(UINT64)); i++)
    {
        if( pu64SampleSegment[i] + 1 <= 1 )
        {
            entropyEstimateInMilliBits = 0;
            pState->nHealthTestFailures++;
            break;
        }
    }

    // If entropy pool ready (callback is set), feed the segment into it
    if( g_SymCryptCallbackEntropyAccumulatorProvideEntropy != NULL )
    {
        if( pState->pRawSampleBuffer != NULL )
        {
            if( g_SymCryptEntropyAccumulatorCollectRawSamples == SYMCRYPT_ENTROPY_ACCUMULATOR_RAW_SAMPLE_COLLECTION_ON )
            {
                if( nSamplesAtDpcQueueTime >= pState->nRawSamples )
                {
                    SymCryptEntropyAccumulatorLogRawSamples(
                        pState->pRawSampleBuffer,
                        pState->nRawSamples,
                        pState->accumulatorId,
                        nSamplesAtDpcQueueTime );

                    pState->pRawSampleBuffer = NULL; // Only log raw samples once!
                }
            }
            else if( g_SymCryptEntropyAccumulatorCollectRawSamples == SYMCRYPT_ENTROPY_ACCUMULATOR_RAW_SAMPLE_COLLECTION_OFF )
            {
                // In this case this is the first DPC after callbacks were set and the config read in 
                // SymCryptEntropyAccumulatorGlobalInitFromRegistry indicates that we should not collect raw samples even though
                // the config we were passed at SymCryptEntropyAccumulatorInit time indicated we should allocate a raw sample
                // buffer.
                //
                // We simply discard the pointer to our raw sample buffer, though we technically leak the sample buffer in this
                // case, freeing it would introduce more complexity than is worth it given that we should not allocate at all
                // in the real world.
                //
                // We also wipe the buffer here. This does not guarantee that the unused raw sample buffer is completely
                // zero-ed for the rest of time, as we may race with concurrent interrupts, but the window of time in which
                // raw samples can be preserved in the unused buffer is shortened significantly.
                PSYMCRYPT_ENTROPY_RAW_SAMPLE pRawSampleBufferToWipe = pState->pRawSampleBuffer;
                SIZE_T nSamplesToWipe = SYMCRYPT_MIN(nSamplesAtDpcQueueTime, pState->nRawSamples);
                pState->pRawSampleBuffer = NULL;
                SymCryptWipe(pRawSampleBufferToWipe, nSamplesToWipe * sizeof(SYMCRYPT_ENTROPY_RAW_SAMPLE));
            }
        }

        g_SymCryptCallbackEntropyAccumulatorProvideEntropy(
            (PCBYTE)pu64SampleSegment,
            SYMCRYPT_ENTROPY_ACCUMULATOR_SEGMENT_SIZE,
            entropyEstimateInMilliBits );
    }

    // Zero the logical buffer
    SymCryptWipeKnownSize(pu64SampleSegment, SYMCRYPT_ENTROPY_ACCUMULATOR_SEGMENT_SIZE);
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


VOID
SYMCRYPT_CALL
SymCryptEntropyAccumulatorGlobalInitFromRegistry( VOID )
{
    if( g_SymCryptEntropyAccumulatorCollectRawSamples == SYMCRYPT_ENTROPY_ACCUMULATOR_RAW_SAMPLE_COLLECTION_UNINITIALIZED )
    {
        //
        // Read config to determine whether raw samples should be collected
        //
        if( SymCryptEntropyAccumulatorConfigEnablesRawSampleCollection() )
        {
            g_SymCryptEntropyAccumulatorCollectRawSamples = SYMCRYPT_ENTROPY_ACCUMULATOR_RAW_SAMPLE_COLLECTION_ON;
        } else {
            g_SymCryptEntropyAccumulatorCollectRawSamples = SYMCRYPT_ENTROPY_ACCUMULATOR_RAW_SAMPLE_COLLECTION_OFF;
        }
    }
}

BOOLEAN
SYMCRYPT_CALL
SymCryptEntropyAccumulatorGlobalSetCallbackProvideEntropyFn(
    _In_ PSYMCRYPT_CALLBACK_ENTROPY_ACCUMULATOR_PROVIDE_ENTROPY_FUNC provideEntropyCallbackFn )
{
    // The provide entropy callback function can only be set once, and currently only
    // after the raw sample collection config has been set.
    if( g_SymCryptEntropyAccumulatorCollectRawSamples == SYMCRYPT_ENTROPY_ACCUMULATOR_RAW_SAMPLE_COLLECTION_UNINITIALIZED )
    {
        return FALSE;
    }

    if( g_SymCryptCallbackEntropyAccumulatorProvideEntropy != NULL )
    {
        return FALSE;
    }

    //
    // Set the global pointer to the callback function
    //
    g_SymCryptCallbackEntropyAccumulatorProvideEntropy = provideEntropyCallbackFn;

    return TRUE;
}
