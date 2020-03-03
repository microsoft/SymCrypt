//
// Pattern file for the RSA32 block cipher implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//


template<>
BlockCipherImp<ImpXxx, AlgXxx, ModeXxx>::BlockCipherImp()
{
    m_perfKeyFunction     = &algImpKeyPerfFunction    <ImpXxx, AlgXxx, ModeXxx>;
    m_perfCleanFunction   = &algImpCleanPerfFunction  <ImpXxx, AlgXxx, ModeXxx>;
    m_perfDataFunction    = &algImpDataPerfFunction   <ImpXxx, AlgXxx, ModeXxx>;
    m_perfDecryptFunction = &algImpDecryptPerfFunction<ImpXxx, AlgXxx, ModeXxx>;
}

template<>
BlockCipherImp<ImpXxx, AlgXxx, ModeXxx>::~BlockCipherImp()
{
}

SIZE_T BlockCipherImp<ImpXxx, AlgXxx, ModeXxx>::coreBlockLen()
{
    return RSA32_XXX_BLOCK_SIZE;
}




