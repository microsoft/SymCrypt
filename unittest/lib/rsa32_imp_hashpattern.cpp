//
// Pattern file for the RSA32 hash implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

//
// This only implements the constructor, destructor, inputBlockLen, and resultLen methods.
// The RSA32 API is not structured enough to create a generic implementation.
//

HashImp<ImpXxx, AlgXxx>::HashImp()
{
    m_perfDataFunction = &algImpDataPerfFunction<ImpXxx, AlgXxx>;
}

template<>
HashImp<ImpXxx, AlgXxx>::~HashImp()
{
}

SIZE_T HashImp<ImpXxx, AlgXxx>::inputBlockLen()
{
    return RSA32_XXX_INPUT_BLOCK_SIZE;
}

SIZE_T HashImp<ImpXxx, AlgXxx>::resultLen()
{
    return RSA32_XXX_RESULT_SIZE;
}

NTSTATUS HashImp<ImpXxx,AlgXxx>::exportSymCryptFormat( PBYTE pbResult, SIZE_T cbResultBufferSize, SIZE_T * pcbResult )
{
    UNREFERENCED_PARAMETER( pbResult );
    UNREFERENCED_PARAMETER( cbResultBufferSize );
    UNREFERENCED_PARAMETER( pcbResult );

    return STATUS_NOT_SUPPORTED;
}

VOID HashImp<ImpXxx, AlgXxx>::hash( 
        _In_reads_( cbData )       PCBYTE pbData, 
                                    SIZE_T cbData, 
        _Out_writes_( cbResult )    PBYTE pbResult, 
                                    SIZE_T cbResult )
{
    HashImplementation::hash( pbData, cbData, pbResult, cbResult );
}



