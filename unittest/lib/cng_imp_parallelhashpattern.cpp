//
// Cng_imp_parallelhashpattern.cpp
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

BCRYPT_ALG_HANDLE ParallelHashImpState<ImpXxx, AlgXxx>::hAlg;

//
// We compile with down-level targets, so we have to add some prototypes
//
#ifndef BCRYPT_MULTI_FLAG
#define BCRYPT_MULTI_FLAG                       0x00000040
#endif

ParallelHashImp<ImpXxx, AlgXxx>::ParallelHashImp()
{
    CHECK( CngOpenAlgorithmProviderFn( &state.hAlg, AlgXxx::pwstrBasename, NULL, BCRYPT_MULTI_FLAG ) == STATUS_SUCCESS, 
        "Could not open CNG/" STRING( ALG_Name ) );
    state.hHash = 0;
    m_perfDataFunction = &algImpDataPerfFunction<ImpXxx, AlgXxx>;
    m_perfKeyFunction = &algImpKeyPerfFunction<ImpXxx, AlgXxx>;
    m_perfCleanFunction = &algImpCleanPerfFunction<ImpXxx, AlgXxx>;
}

template<>
ParallelHashImp<ImpXxx, AlgXxx>::~ParallelHashImp()
{
    if( state.hHash != 0 )
    {
        CHECK( NT_SUCCESS( CngDestroyHashFn( state.hHash ) ), "Could not destroy multi-hash" );
        state.hHash = 0;
    }
    
    CHECK( NT_SUCCESS( CngCloseAlgorithmProviderFn( state.hAlg, 0 )), "Could not close CNG/" STRING( ALG_Name ) );
    state.hAlg = 0;
}

template<>
PCSYMCRYPT_HASH
ParallelHashImp<ImpXxx, AlgXxx>::SymCryptHash()
{
    return NULL;
}

template<>
SIZE_T ParallelHashImp<ImpXxx, AlgXxx>::resultLen()
{
    ULONG   len;
    ULONG   res;
    CHECK( NT_SUCCESS( CngGetPropertyFn( state.hAlg, BCRYPT_HASH_LENGTH, (PBYTE) &len, sizeof( len ), &res, 0 ) ),
        "Could not query hash size CNG/" STRING( ALG_Name ) );
    CHECK( res == sizeof( len ), "??" );
    return len;
}

SIZE_T ParallelHashImp<ImpXxx, AlgXxx>::inputBlockLen()
{
    ULONG   len;
    ULONG   res;
    CHECK( NT_SUCCESS( CngGetPropertyFn( state.hAlg, BCRYPT_HASH_BLOCK_LENGTH, (PBYTE) &len, sizeof( len ), &res, 0 ) ),
        "Could not query input size CNG/" STRING( ALG_Name ) );
    CHECK( res == sizeof( len ), "??" );
    return len;
}

VOID ParallelHashImp<ImpXxx, AlgXxx>::init( SIZE_T nHashes )
{
    if( nHashes == 0 )
    {
        return;
    }

    if( state.hHash != 0 )
    {
        CHECK( NT_SUCCESS( CngDestroyHashFn( state.hHash ) ), "Could not destroy multi-hash" );
        state.hHash = 0;
    }
    
    CHECK( NT_SUCCESS( CngCreateMultiHashFn(    state.hAlg, 
                                                &state.hHash,
                                                (ULONG)nHashes,
                                                state.hashObjectBuffer,
                                                sizeof( state.hashObjectBuffer ),
                                                NULL,
                                                0,
                                                0) ),
            "Error creating hash CNG/" STRING( ALG_Name ) );
}

VOID ParallelHashImp<ImpXxx, AlgXxx>::process( 
        _In_reads_( nOperations )   BCRYPT_MULTI_HASH_OPERATION *   pOperations,
                                    SIZE_T                          nOperations )
{
    if( nOperations == 0 )
    {
        return;
    }
    CHECK( state.hHash != 0, "No hash state in CNG multi-hash process()" );
    CHECK( NT_SUCCESS( CngProcessMultiOperationsFn( state.hHash, 
                                                    BCRYPT_OPERATION_TYPE_HASH,
                                                    pOperations,
                                                    (ULONG)(nOperations * sizeof( *pOperations )),
                                                    0 )), "Failed CNG multi-operation" );
}

NTSTATUS ParallelHashImp<ImpXxx, AlgXxx>::initWithLongMessage( ULONGLONG nBytes )
{
    UNREFERENCED_PARAMETER( nBytes );

    return STATUS_NOT_SUPPORTED;
}


#define N_PARALLEL_FOR_PERF 8

VOID 
algImpKeyPerfFunction<ImpXxx, AlgXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( keySize );

    CHECK( NT_SUCCESS( CngCreateMultiHashFn(    ParallelHashImpState<ImpXxx,AlgXxx>::hAlg,
                                                (BCRYPT_HASH_HANDLE *) buf1,
                                                N_PARALLEL_FOR_PERF,
                                                buf1 + 16,
                                                PERF_BUFFER_SIZE - 16,
                                                NULL, 0, 0 ) ), "" );
}

VOID
algImpCleanPerfFunction<ImpXxx, AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );

    CHECK( NT_SUCCESS( CngDestroyHashFn( *(BCRYPT_HASH_HANDLE *) buf1 )), "" );
}


VOID 
algImpDataPerfFunction<ImpXxx, AlgXxx>(PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    BCRYPT_MULTI_HASH_OPERATION * pOperations = (BCRYPT_MULTI_HASH_OPERATION *) buf2;
    BCRYPT_MULTI_HASH_OPERATION * pOp = pOperations;
    PBYTE pSrc = buf3;
    PBYTE pDst = buf3 + PERF_BUFFER_SIZE / 2;
    ULONG i;

    for( i=0; i<N_PARALLEL_FOR_PERF; i++ )
    {
        pOp->iHash = i;
        pOp->hashOperation = BCRYPT_HASH_OPERATION_HASH_DATA;
        pOp->pbBuffer = pSrc;
        pOp->cbBuffer = (ULONG)dataSize / N_PARALLEL_FOR_PERF;

        pSrc += pOp->cbBuffer;
        pOp++;

        pOp->iHash = i;
        pOp->hashOperation = BCRYPT_HASH_OPERATION_FINISH_HASH;
        pOp->pbBuffer = pDst;
        pOp->cbBuffer = SYMCRYPT_XXX_RESULT_SIZE;

        pDst += pOp->cbBuffer;
        pOp++;
    }

    CHECK( NT_SUCCESS( CngProcessMultiOperationsFn( *(BCRYPT_HASH_HANDLE *) buf1,
                                                    BCRYPT_OPERATION_TYPE_HASH,
                                                    pOperations, 
                                                    2 * N_PARALLEL_FOR_PERF * sizeof( *pOperations ),
                                                    0 )), "CNG Parallel ops failed" );

}

