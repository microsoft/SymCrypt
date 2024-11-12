//
// Pattern file for the Openssl mac implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#define GLOBAL_ALG_HANDLE HANDLE_PATTERN( ALG_NAME ) // global_handle_HMAC_SHAXXX
#define GLOBAL_ALG_PARAMS PARAMS_PATTERN( ALG_NAME ) // HMAC_SHAXXX_params

EVP_MAC * GLOBAL_ALG_HANDLE = NULL;
OSSL_PARAM * GLOBAL_ALG_PARAMS = NULL;

template<>
VOID algImpKeyPerfFunction<ImpOpenssl,AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );
    UNREFERENCED_PARAMETER( keySize );
    MacContext *pLocalCtx = (MacContext *)buf1;

    const char *digest = MacImpState<ImpOpenssl,AlgXxx>::constants_t::pszDigest;
    fetchGlobalMacAlgHandle( &( GLOBAL_ALG_HANDLE ) , "HMAC", digest, &( GLOBAL_ALG_PARAMS ) );

    pLocalCtx->pMac = GLOBAL_ALG_HANDLE;
    pLocalCtx->pMacCtx = EVP_MAC_CTX_new( pLocalCtx->pMac );
    CHECK(pLocalCtx->pMacCtx, "EVP_MAC_CTX_new() returned NULL");

    pLocalCtx->keySize = keySize;
    return;
}

template<>
VOID algImpDataPerfFunction<ImpOpenssl, AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    UNREFERENCED_PARAMETER( buf3 );
    MacContext *pLocalCtx = (MacContext *)buf1;

    SIZE_T outLen;

    // EVP_MAC_init() adds about 10k cycles of overhead (on Intel i7 1370P).
    //  In practice, this would only be done once at the beginning of the MAC lifecycle.
    //  Ideally the OpenSSL API would allow a caller to initialize a MAC context once for a given MAC key 
    //  and reuse that context for several different MAC computations. This would allow us to show a 
    //  performance impact more commensurable with SymCrypt / CNG.
    //  Unfortunately there is no way with the existing OpenSSL API to do this, 
    //  and either the key needs to be ingested for every MAC computation (using EVP_MAC_init), 
    //  or a new MAC context needs to be allocated and freed for every MAC computation (using EVP_MAC_CTX_dup). 
    //  Both approaches have a high fixed cost overhead. Using EVP_MAC_init at least means that a realistic E2E cost 
    //  can be computed for OpenSSL's MAC when adding up the key and data performance costs.
    CHECK( EVP_MAC_init( pLocalCtx->pMacCtx, buf2, pLocalCtx->keySize, GLOBAL_ALG_PARAMS ), "EVP_MAC_init() failed in performance test." );
    CHECK( EVP_MAC_update( pLocalCtx->pMacCtx, buf2, dataSize), "EVP_MAC_update() failed in performance test." );
    CHECK( EVP_MAC_final(pLocalCtx->pMacCtx, NULL, &outLen, 0), "EVP_MAC_final failed in performance test." );
    CHECK( EVP_MAC_final(pLocalCtx->pMacCtx, buf3, &outLen, outLen), "EVP_MAC_final failed in performance test." );
    return;
}

template<>
VOID algImpCleanPerfFunction<ImpOpenssl,AlgXxx>( PBYTE buf1, PBYTE buf2, PBYTE buf3 )
{  

    UNREFERENCED_PARAMETER(buf2);
    UNREFERENCED_PARAMETER(buf3);

    MacContext *pLocalCtx = (MacContext *)buf1;
    EVP_MAC_CTX_free( pLocalCtx->pMacCtx );

    // intentionally leaking 4 global variables.
    // free(GLOBAL_ALG_PARAMS);
    // EVP_MAC_free(pLocalCtx->pMac);
}

template<>
class MacImp<ImpOpenssl,AlgXxx> : public MacImplementation
{
public:
    static constexpr const char *s_algName = AlgXxx::name; // Algorithm name
    static constexpr char *s_modeName = "";
    static constexpr const char *s_impName = ImpOpenssl::name; // Implementation name
    MacImpState<ImpOpenssl,AlgXxx> state;

    MacImp()
    {
        m_perfDataFunction  = &algImpDataPerfFunction<ImpOpenssl,AlgXxx>;
        m_perfKeyFunction   = &algImpKeyPerfFunction<ImpOpenssl,AlgXxx>;
        m_perfCleanFunction = &algImpCleanPerfFunction<ImpOpenssl,AlgXxx>;
        state.isReset = FALSE;

        // Fetch the HMAC implementation using the default library context.
        state.pMac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        CHECK( state.pMac != NULL , "EVP_MAC_fetch() returned NULL");
        state.pMacCtx = NULL;

    }

    //
    // Empty destructor
    //
    ~MacImp<ImpOpenssl,AlgXxx>()
    {

        EVP_MAC_free(state.pMac);
        if( state.pMacCtx != NULL ) 
        {
            EVP_MAC_CTX_free(state.pMacCtx);
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
    // Compute a mac directly
    //
    NTSTATUS mac(
        _In_reads_( cbKey )         PCBYTE pbKey,   
                                    SIZE_T cbKey, 
        _In_reads_( cbData )        PCBYTE pbData,  
                                    SIZE_T cbData, 
        _Out_writes_( cbResult )    PBYTE pbResult, 
                                    SIZE_T cbResult )
    { 
        CHECK(
            EVP_Q_mac(  NULL,                       // (optional) library context   
                        "HMAC",                     //            algorithm name    
                        NULL,                       // (optional) properties            
                        state.constants.pszDigest,  // (optional) digest name
                        NULL,                       // (optional) parameters 
                        pbKey, cbKey,               // key
                        pbData, cbData,             // data
                        pbResult, cbResult,         // output buffer
                        NULL ),                     // (optional) output length pointer
        "EVP_Q_mac returned 0" ); 
        
        return STATUS_SUCCESS;
    }

    NTSTATUS init(_In_reads_(cbKey) PCBYTE pbKey, SIZE_T cbKey)
    {
        if( !state.isReset )
        {
            if (state.pMacCtx != NULL)
            {
                EVP_MAC_CTX_free(state.pMacCtx);
            }

            OSSL_PARAM osslParams[4], *p=NULL;
            p = osslParams;
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char*)state.constants.pszDigest, sizeof(state.constants.pszDigest) );
            *p = OSSL_PARAM_construct_end();

            // Create a context for the HMAC operation.
            state.pMacCtx = EVP_MAC_CTX_new(state.pMac);
            CHECK( state.pMacCtx != NULL, "EVP_MAC_CTX_new() returned NULL in init()");

            // Initialize with openssl
            CHECK( EVP_MAC_init( state.pMacCtx, pbKey, cbKey, osslParams ), "EVP_MAC_init() failed in init()" );
        }
        state.isReset = TRUE;
        return STATUS_SUCCESS;
    }

    VOID append(_In_reads_(cbData) PCBYTE pbData, SIZE_T cbData)
    {
        CHECK( EVP_MAC_update(state.pMacCtx, pbData, cbData), "EVP_MAC_update() failed in append()" );
    }

    VOID result(_Out_writes_(cbResult) PBYTE pbResult, SIZE_T cbResult)
    {
        state.isReset = FALSE;
        SIZE_T outLen = 0;
        
        // Make a call to the final with a NULL buffer to get the length of the MAC
        EVP_MAC_final(state.pMacCtx, NULL, &outLen, 0);
        CHECK( EVP_MAC_final(state.pMacCtx, pbResult, &outLen, outLen), "EVP_MAC_final() failed in result()" );
    }

    NTSTATUS exportSymCryptFormat(
        _Out_writes_bytes_to_(cbResultBufferSize, *pcbResult) PBYTE pbResult,
        _In_ SIZE_T cbResultBufferSize,
        _Out_ SIZE_T *pcbResult)
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS initWithLongMessage(ULONGLONG nBytes)
    {
        return STATUS_NOT_SUPPORTED;
    }
    
};
#undef GLOBAL_ALG_HANDLE