//
// Pattern file for the Openssl hash implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#define GLOBAL_ALG_HANDLE HANDLE_PATTERN( ALG_NAME ) // global_Handle_SHAXXX

EVP_MD * GLOBAL_ALG_HANDLE = NULL;

template<>
VOID algImpKeyPerfFunction<ImpOpenssl, AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( keySize );
    
    HashContext *pLocalHashCtx = (HashContext *)buf1;

    fetchGlobalHashAlgHandle(&(GLOBAL_ALG_HANDLE), (HashImpState<ImpOpenssl, AlgXxx>::constants_t::pszAlgId));
    pLocalHashCtx->pmd = GLOBAL_ALG_HANDLE;
    CHECK(pLocalHashCtx->pmd != NULL, "fetchGlobalHashAlgHandle() returned NULL");

    pLocalHashCtx->pmdCtx = EVP_MD_CTX_new();
    CHECK(pLocalHashCtx->pmdCtx != NULL, "EVP_MD_CTX_new() returned NULL");
    return;
}

template<>
VOID algImpDataPerfFunction<ImpOpenssl, AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    HashContext *pLocalHashCtx = (HashContext *)buf1;

    CHECK_OPENSSL_SUCCESS(EVP_DigestInit_ex(pLocalHashCtx->pmdCtx, pLocalHashCtx->pmd, NULL));
    CHECK_OPENSSL_SUCCESS(EVP_DigestUpdate(pLocalHashCtx->pmdCtx, buf2, dataSize));
    
    unsigned int mdlen;
    CHECK_OPENSSL_SUCCESS(EVP_DigestFinal_ex(pLocalHashCtx->pmdCtx, buf3, &mdlen));
}

template<>
VOID algImpCleanPerfFunction<ImpOpenssl, AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{
    UNREFERENCED_PARAMETER( buf2 );
    UNREFERENCED_PARAMETER( buf3 );
    HashContext *pLocalHashCtx = (HashContext *)buf1;

    EVP_MD_CTX_free(pLocalHashCtx->pmdCtx);
    
}

template<>
class HashImp<ImpOpenssl, AlgXxx>: public HashImplementation
{
public:
    static constexpr const char * s_algName = AlgXxx::name;             // Algorithm name
    static constexpr char * s_modeName = "";
    static constexpr const char * s_impName = ImpOpenssl::name;         // Implementation name
    HashImpState<ImpOpenssl, AlgXxx> state;

    HashImp()
    {
        m_perfDataFunction  = algImpDataPerfFunction<ImpOpenssl, AlgXxx>;
        m_perfKeyFunction   = algImpKeyPerfFunction<ImpOpenssl, AlgXxx>;
        m_perfCleanFunction = algImpCleanPerfFunction<ImpOpenssl, AlgXxx>;
        state.isReset = FALSE;

        state.pmd = EVP_MD_fetch(NULL, AlgXxx::name, NULL);
        CHECK_OPENSSL_NONNULL(state.pmd);
        state.pmdCtx = NULL;
    }

    ~HashImp<ImpOpenssl, AlgXxx>()
    {
        EVP_MD_free(state.pmd);
        if (state.pmdCtx != NULL)
        {
            EVP_MD_CTX_free(state.pmdCtx);
        }
    }

    SIZE_T inputBlockLen()
    {
        return state.constants.cbInputBlockLen;
    }

    SIZE_T resultLen()
    {
        return state.constants.cbResultLen;
    }

    //
    // Compute a hash directly
    //
    VOID hash(
            _In_reads_( cbData )        PCBYTE pbData,
                                        SIZE_T cbData,
            _Out_writes_( cbResult )    PBYTE pbResult,
                                        SIZE_T cbResult )
    {
        unsigned int mdlen = 0;
        CHECK(cbResult == state.constants.cbResultLen, "incorrect cbResult length.");
        CHECK_OPENSSL_SUCCESS(EVP_Digest(pbData, cbData, pbResult, &mdlen, state.pmd, NULL));
        CHECK(mdlen == state.constants.cbResultLen, "incorrect mdlen.");
    }

    VOID init()
    {
        if( !state.isReset )
        {
            if (state.pmdCtx != NULL)
            {
                EVP_MD_CTX_free(state.pmdCtx);
            }
            state.pmdCtx = EVP_MD_CTX_new();
            CHECK_OPENSSL_NONNULL(state.pmdCtx);
            CHECK_OPENSSL_SUCCESS(EVP_DigestInit_ex(state.pmdCtx, state.pmd, NULL));
        }
        state.isReset = TRUE;
    }

    VOID append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
    {
        state.isReset = FALSE;
        CHECK_OPENSSL_SUCCESS(EVP_DigestUpdate(state.pmdCtx, pbData, cbData));
    }

    VOID result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
    {
        state.isReset = FALSE;

        CHECK(cbResult >= state.constants.cbResultLen, "cbResult too small.");
        unsigned int mdLen;
        CHECK_OPENSSL_SUCCESS(EVP_DigestFinal_ex(state.pmdCtx, pbResult, &mdLen));
        CHECK(mdLen == state.constants.cbResultLen, "mdLen too small.");
    }

    NTSTATUS exportSymCryptFormat(
        _Out_writes_bytes_to_( cbResultBufferSize, *pcbResult ) PBYTE   pbResult,
        _In_                                                    SIZE_T  cbResultBufferSize,
        _Out_                                                   SIZE_T *pcbResult )
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS initWithLongMessage( ULONGLONG nBytes )
    {
        return STATUS_NOT_SUPPORTED;
    }
};

#undef GLOBAL_ALG_HANDLE