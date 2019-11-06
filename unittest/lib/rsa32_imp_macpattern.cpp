//
// Pattern file for the RSA32 mac implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

//
// This only implements the constructor, destructor, inputBlockLen, and resultLen methods.
// The RSA32 API is not structured enough to create a generic implementation.
//

MacImp<ImpXxx, AlgXxx>::MacImp()
{
    m_perfDataFunction = &algImpDataPerfFunction <ImpXxx, AlgXxx>;
    m_perfKeyFunction  = &algImpKeyPerfFunction  <ImpXxx, AlgXxx>;
    m_perfCleanFunction= &algImpCleanPerfFunction<ImpXxx, AlgXxx>;
}

template<>
MacImp<ImpXxx, AlgXxx>::~MacImp()
{
}

SIZE_T MacImp<ImpXxx, AlgXxx>::inputBlockLen()
{
    return RSA32_XXX_INPUT_BLOCK_SIZE;
}

SIZE_T MacImp<ImpXxx, AlgXxx>::resultLen()
{
    return RSA32_XXX_RESULT_SIZE;
}

NTSTATUS
MacImp<ImpXxx, AlgXxx>::mac( 
        _In_reads_( cbKey )        PCBYTE pbKey, 
                                    SIZE_T cbKey, 
        _In_reads_( cbData )       PCBYTE pbData, 
                                    SIZE_T cbData, 
        _Out_writes_( cbResult )    PBYTE pbResult, 
                                    SIZE_T cbResult )
{
    return MacImplementation::mac( pbKey, cbKey, pbData, cbData, pbResult, cbResult );
}




