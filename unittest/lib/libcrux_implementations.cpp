#include "precomp.h"

#include "libcrux_kyber512.h"
#include "libcrux_kyber768.h"
#include "libcrux_kyber1024.h"

#if INCLUDE_IMPL_LIBCRUX

// CPU feature detection glue for libcrux
extern "C" {
void EverCrypt_AutoConfig2_init(void) {}

bool EverCrypt_AutoConfig2_has_avx2(void)
{
#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
  // Does not save/restore YMM state - only suitable for testing.
  return SYMCRYPT_CPU_FEATURES_PRESENT( SYMCRYPT_CPU_FEATURE_AVX2 );
#endif
  return false;
}
};

char * ImpLibcrux::name = "Libcrux";

struct LibcruxMlKemContext
{
    SIZE_T keySize;
};

union NormalLibcruxMlKemKey
{
    libcrux_kyber_types_MlKemKeyPair___1632size_t_800size_t key512;
    libcrux_kyber_types_MlKemKeyPair___2400size_t_1184size_t key768;
    libcrux_kyber_types_MlKemKeyPair___3168size_t_1568size_t key1024;
};

union UnpackedLibcruxMlKemKey
{
    K___libcrux_kyber_MlKemState__2size_t___libcrux_kyber_types_MlKemPublicKey__800size_t__ key512;
    K___libcrux_kyber_MlKemState__3size_t___libcrux_kyber_types_MlKemPublicKey__1184size_t__ key768;
    K___libcrux_kyber_MlKemState__4size_t___libcrux_kyber_types_MlKemPublicKey__1568size_t__ key1024;
};

union LibCruxMlKemCipherText
{
    K___libcrux_kyber_types_MlKemCiphertext__768size_t___uint8_t_32size_t_ ct768;
    K___libcrux_kyber_types_MlKemCiphertext__1088size_t___uint8_t_32size_t_ ct1088;
    K___libcrux_kyber_types_MlKemCiphertext__1568size_t___uint8_t_32size_t_ ct1568;
};

template<>
class KemImpState<ImpLibcrux, AlgMlKem> {
public:
    UINT32 type;
    SYMCRYPT_MLKEMKEY_FORMAT format;
    BYTE randomSeed[64];
    UnpackedLibcruxMlKemKey unpackedKey; // used when we generate a key from a seed
    NormalLibcruxMlKemKey normalKey; // used when setting a key from a blob
};

template<>
VOID
algImpKeyPerfFunction<ImpLibcrux, AlgMlKem>( PBYTE pbKey, PBYTE pbContext, PBYTE buf3, SIZE_T keySize )
{
    UNREFERENCED_PARAMETER( buf3 );

    BYTE random[64];
    SYMCRYPT_ERROR scError = SymCryptCallbackRandom( random, sizeof( random ) );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptCallbackRandom failed" );

    UnpackedLibcruxMlKemKey* pKey = (UnpackedLibcruxMlKemKey*) pbKey;

    switch(keySize)
    {
        case PERF_KEY_MLKEM_512:
            pKey->key512 = libcrux_kyber_kyber512_generate_key_pair_unpacked(random);
            break;
        case PERF_KEY_MLKEM_768:
            pKey->key768 = libcrux_kyber_kyber768_generate_key_pair_unpacked(random);
            break;
        case PERF_KEY_MLKEM_1024:
            pKey->key1024 = libcrux_kyber_kyber1024_generate_key_pair_unpacked(random);
            break;
        default:
            CHECK( FALSE, "Invalid ML-KEM parameter set (key size)" );
            break;
    }

    ((LibcruxMlKemContext*) pbContext)->keySize = keySize;
}

template<>
VOID
algImpDataPerfFunction<ImpLibcrux, AlgMlKem>( PBYTE pbKey, PBYTE pbContext, PBYTE pbCipherText, SIZE_T cbData )
{
    BYTE random[32];
    SYMCRYPT_ERROR scError = SymCryptCallbackRandom( random, sizeof( random ) );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptCallbackRandom failed" );

    UnpackedLibcruxMlKemKey* pKey = (UnpackedLibcruxMlKemKey*) pbKey;
    LibcruxMlKemContext* pContext = (LibcruxMlKemContext*) pbContext;
    LibCruxMlKemCipherText* pCipherText = (LibCruxMlKemCipherText*) pbCipherText;

    switch(pContext->keySize)
    {
        case PERF_KEY_MLKEM_512:
            pCipherText->ct768 = libcrux_kyber_kyber512_encapsulate((uint8_t (*)[800]) pKey->key512.snd, random);
            break;
        case PERF_KEY_MLKEM_768:
            pCipherText->ct1088 = libcrux_kyber_kyber768_encapsulate((uint8_t (*)[1184]) pKey->key768.snd, random);
            break;
        case PERF_KEY_MLKEM_1024:
            pCipherText->ct1568 = libcrux_kyber_kyber1024_encapsulate((uint8_t (*)[1568]) pKey->key1024.snd, random);
            break;
        default:
            CHECK( FALSE, "Invalid ML-KEM parameter set (key size)" );
            break;
    }
}

template<>
VOID
algImpDecryptPerfFunction<ImpLibcrux, AlgMlKem>( PBYTE pbKey, PBYTE pbContext, PBYTE pbCipherText, SIZE_T cbData )
{
    UnpackedLibcruxMlKemKey* pKey = (UnpackedLibcruxMlKemKey*) pbKey;
    LibcruxMlKemContext* pContext = (LibcruxMlKemContext*) pbContext;
    LibCruxMlKemCipherText* pCipherText = (LibCruxMlKemCipherText*) pbCipherText;

    BYTE expectedSecret[32];
    BYTE secret[32];

    switch(pContext->keySize)
    {
        case PERF_KEY_MLKEM_512:
            libcrux_kyber_kyber512_decapsulate_unpacked(&(pKey->key512.fst), (uint8_t (*)[768]) pCipherText->ct768.fst, secret);
            memcpy( expectedSecret, pCipherText->ct768.snd, 32 );
            break;
        case PERF_KEY_MLKEM_768:
            libcrux_kyber_kyber768_decapsulate_unpacked(&(pKey->key768.fst), (uint8_t (*)[1088]) pCipherText->ct1088.fst, secret);
            memcpy( expectedSecret, pCipherText->ct1088.snd, 32 );
            break;
        case PERF_KEY_MLKEM_1024:
            libcrux_kyber_kyber1024_decapsulate_unpacked(&(pKey->key1024.fst), (uint8_t (*)[1568]) pCipherText->ct1568.fst, secret);
            memcpy( expectedSecret, pCipherText->ct1568.snd, 32 );
            break;
        default:
            CHECK( FALSE, "Invalid ML-KEM parameter set (key size)" );
            break;
    }

    CHECK( memcmp( secret, expectedSecret, 32 ) == 0, "Decapsulation failed (secrets do not match)" );
}

template<>
VOID
algImpCleanPerfFunction<ImpLibcrux, AlgMlKem>( PBYTE pbKey, PBYTE pbContext, PBYTE pbCipherText )
{
    SymCryptWipe( pbKey, sizeof(UnpackedLibcruxMlKemKey) );
    SymCryptWipe( pbContext, sizeof(LibcruxMlKemContext) );
    SymCryptWipe( pbCipherText, sizeof(LibCruxMlKemCipherText) );
}

template<>
KemImp<ImpLibcrux, AlgMlKem>::KemImp()
{
    m_perfDataFunction      = &algImpDataPerfFunction<ImpLibcrux, AlgMlKem>;
    m_perfDecryptFunction   = &algImpDecryptPerfFunction<ImpLibcrux, AlgMlKem>;
    m_perfKeyFunction       = &algImpKeyPerfFunction<ImpLibcrux, AlgMlKem>;
    m_perfCleanFunction     = &algImpCleanPerfFunction<ImpLibcrux, AlgMlKem>;
}

template<>
KemImp<ImpLibcrux, AlgMlKem>::~KemImp() = default;

template<>
NTSTATUS
KemImp<ImpLibcrux, AlgMlKem>::setKeyFromTestBlob(
        _In_reads_bytes_( cbTestKeyBlob )       PCBYTE              pcbTestKeyBlob,
                                                SIZE_T              cbTestKeyBlob,
                                                BOOL                canDecapsulate )
{
    UNREFERENCED_PARAMETER( canDecapsulate );

    PCMLKEMKEY_TESTBLOB pcKeyBlob = (PCMLKEMKEY_TESTBLOB) pcbTestKeyBlob;

    if( pcKeyBlob == NULL )
    {
        // Just used to clear the key state to do leak detection
        return STATUS_SUCCESS;
    }
    
    CHECK( cbTestKeyBlob == sizeof(MLKEMKEY_TESTBLOB), "Invalid key blob size" );

    state.params = pcKeyBlob->params;
    state.format = pcKeyBlob->format;

    if( state.format == SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED )
    {
        CHECK( pcKeyBlob->cbKeyBlob == 64, "Invalid private seed blob size" );
        memcpy( state.randomSeed, pcKeyBlob->abKeyBlob, 64 );

        switch(state.params)
        {
            case SYMCRYPT_MLKEM_PARAMS_MLKEM512:
                state.unpackedKey.key512 = libcrux_kyber_kyber512_generate_key_pair_unpacked(state.randomSeed);
                state.normalKey.key512 = libcrux_kyber_kyber512_generate_key_pair(state.randomSeed);
                break;
            case SYMCRYPT_MLKEM_PARAMS_MLKEM768:
                state.unpackedKey.key768 = libcrux_kyber_kyber768_generate_key_pair_unpacked(state.randomSeed);
                state.normalKey.key768 = libcrux_kyber_kyber768_generate_key_pair(state.randomSeed);
                break;
            case SYMCRYPT_MLKEM_PARAMS_MLKEM1024:
                state.unpackedKey.key1024 = libcrux_kyber_kyber1024_generate_key_pair_unpacked(state.randomSeed);
                state.normalKey.key1024 = libcrux_kyber_kyber1024_generate_key_pair(state.randomSeed);
                break;
            default:
                CHECK( FALSE, "Invalid ML-KEM parameter set (key size)" );
                break;
        }
    }
    else if( state.format == SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY )
    {
        switch(state.params)
        {
            case SYMCRYPT_MLKEM_PARAMS_MLKEM512:
                CHECK( pcKeyBlob->cbKeyBlob == 1632, "Invalid decapsulation key blob size" );
                memcpy( state.normalKey.key512.sk, pcKeyBlob->abKeyBlob, 1632);
                memcpy( state.normalKey.key512.pk, pcKeyBlob->abKeyBlob+768, 800);
                break;
            case SYMCRYPT_MLKEM_PARAMS_MLKEM768:
                CHECK( pcKeyBlob->cbKeyBlob == 2400, "Invalid decapsulation key blob size" );
                memcpy( state.normalKey.key768.sk, pcKeyBlob->abKeyBlob, 2400);
                memcpy( state.normalKey.key768.pk, pcKeyBlob->abKeyBlob+1152, 1184);
                break;
            case SYMCRYPT_MLKEM_PARAMS_MLKEM1024:
                CHECK( pcKeyBlob->cbKeyBlob == 3168, "Invalid decapsulation key blob size" );
                memcpy( state.normalKey.key1024.sk, pcKeyBlob->abKeyBlob, 3168);
                memcpy( state.normalKey.key1024.pk, pcKeyBlob->abKeyBlob+1536, 1568);
                break;
            default:
                CHECK( FALSE, "Invalid ML-KEM parameter set (key size)" );
                break;
        }
    }
    else if( state.format == SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY )
    {
        switch(state.params)
        {
            case SYMCRYPT_MLKEM_PARAMS_MLKEM512:
                CHECK( pcKeyBlob->cbKeyBlob == 800, "Invalid encapsulation key blob size" );
                memcpy( state.normalKey.key512.pk, pcKeyBlob->abKeyBlob, 800);
                break;
            case SYMCRYPT_MLKEM_PARAMS_MLKEM768:
                CHECK( pcKeyBlob->cbKeyBlob == 1184, "Invalid encapsulation key blob size" );
                memcpy( state.normalKey.key768.pk, pcKeyBlob->abKeyBlob, 1184);
                break;
            case SYMCRYPT_MLKEM_PARAMS_MLKEM1024:
                CHECK( pcKeyBlob->cbKeyBlob == 1568, "Invalid encapsulation key blob size" );
                memcpy( state.normalKey.key1024.pk, pcKeyBlob->abKeyBlob, 1568);
                break;
            default:
                CHECK( FALSE, "Invalid ML-KEM parameter set (key size)" );
                break;
        }
    }
    else
    {
        CHECK( FALSE, "Invalid ML-KEM format" );
    }

    return STATUS_SUCCESS;
}


template<>
NTSTATUS
KemImp<ImpLibcrux, AlgMlKem>::getBlobFromKey(
                                                UINT32              blobType,
        _Out_writes_bytes_( cbBlob )            PBYTE               pbBlob,
                                                SIZE_T              cbBlob )
{
    switch((SYMCRYPT_MLKEMKEY_FORMAT)blobType)
    {
        case SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED:
            CHECK( state.format == SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED, "Cannot get private seed from key with no private seed" );
            CHECK( cbBlob == sizeof(state.randomSeed), "Invalid private seed length" );
            memcpy( pbBlob, state.randomSeed, sizeof(state.randomSeed) );
            break;
        case SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY:
            CHECK( state.format != SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY, "Cannot get decapsulation key blob from encapsulation key" );
            switch(state.params)
            {
                case SYMCRYPT_MLKEM_PARAMS_MLKEM512:
                    CHECK( cbBlob == 1632, "Invalid decapsulation key blob size" );
                    memcpy( pbBlob, state.normalKey.key512.sk, 1632);
                    break;
                case SYMCRYPT_MLKEM_PARAMS_MLKEM768:
                    CHECK( cbBlob == 2400, "Invalid decapsulation key blob size" );
                    memcpy( pbBlob, state.normalKey.key768.sk, 2400);
                    break;
                case SYMCRYPT_MLKEM_PARAMS_MLKEM1024:
                    CHECK( cbBlob == 3168, "Invalid decapsulation key blob size" );
                    memcpy( pbBlob, state.normalKey.key1024.sk, 3168);
                    break;
                default:
                    CHECK( FALSE, "Invalid ML-KEM parameter set (key size)" );
                    break;
            }
            break;
        case SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY:
            switch(state.params)
            {
                case SYMCRYPT_MLKEM_PARAMS_MLKEM512:
                    CHECK( cbBlob == 800, "Invalid encapsulation key blob size" );
                    memcpy( pbBlob, state.normalKey.key512.pk, 800);
                    break;
                case SYMCRYPT_MLKEM_PARAMS_MLKEM768:
                    CHECK( cbBlob == 1184, "Invalid encapsulation key blob size" );
                    memcpy( pbBlob, state.normalKey.key768.pk, 1184);
                    break;
                case SYMCRYPT_MLKEM_PARAMS_MLKEM1024:
                    CHECK( cbBlob == 1568, "Invalid encapsulation key blob size" );
                    memcpy( pbBlob, state.normalKey.key1024.pk, 1568);
                    break;
                default:
                    CHECK( FALSE, "Invalid ML-KEM parameter set (key size)" );
                    break;
            }
            break;
        default:
            CHECK( FALSE, "Invalid ML-KEM format" );
    }

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
KemImp<ImpLibcrux, AlgMlKem>::encapsulateEx(
    _In_reads_bytes_( cbRandom )            PCBYTE              pbRandom,
                                            SIZE_T              cbRandom,
    _Out_writes_bytes_( cbAgreedSecret )    PBYTE               pbAgreedSecret,
                                            SIZE_T              cbAgreedSecret, 
    _Out_writes_bytes_( cbCiphertext )      PBYTE               pbCiphertext,
                                            SIZE_T              cbCiphertext )
{
    CHECK( cbAgreedSecret == 32, "Invalid secret size" );
    CHECK( cbRandom == 32, "Invalid random size" );

    LibCruxMlKemCipherText cipherText;
    BYTE random[32];
    memcpy( random, pbRandom, 32 );

    switch(state.params)
    {
        case SYMCRYPT_MLKEM_PARAMS_MLKEM512:
            cipherText.ct768 = libcrux_kyber_kyber512_encapsulate((uint8_t (*)[800]) state.normalKey.key512.pk, random);
            CHECK( cbCiphertext == 768, "Invalid ciphertext size" );
            memcpy( pbAgreedSecret, cipherText.ct768.snd, 32 );
            memcpy( pbCiphertext, cipherText.ct768.fst, 768 );
            break;
        case SYMCRYPT_MLKEM_PARAMS_MLKEM768:
            cipherText.ct1088 = libcrux_kyber_kyber768_encapsulate((uint8_t (*)[1184]) state.normalKey.key768.pk, random);
            CHECK( cbCiphertext == 1088, "Invalid ciphertext size" );
            memcpy( pbAgreedSecret, cipherText.ct1088.snd, 32 );
            memcpy( pbCiphertext, cipherText.ct1088.fst, 1088 );
            break;
        case SYMCRYPT_MLKEM_PARAMS_MLKEM1024:
            cipherText.ct1568 = libcrux_kyber_kyber1024_encapsulate((uint8_t (*)[1568]) state.normalKey.key1024.pk, random);
            CHECK( cbCiphertext == 1568, "Invalid ciphertext size" )
            memcpy( pbAgreedSecret, cipherText.ct1568.snd, 32 );
            memcpy( pbCiphertext, cipherText.ct1568.fst, 1568 );
            break;
        default:
            CHECK( FALSE, "Invalid ML-KEM parameter set (key size)" );
            break;
    }

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
KemImp<ImpLibcrux, AlgMlKem>::encapsulate(
    _Out_writes_bytes_( cbAgreedSecret )    PBYTE               pbAgreedSecret,
                                            SIZE_T              cbAgreedSecret, 
    _Out_writes_bytes_( cbCiphertext )      PBYTE               pbCiphertext,
                                            SIZE_T              cbCiphertext )
{
    CHECK( cbAgreedSecret == 32, "Invalid secret size" );

    BYTE random[32];
    SYMCRYPT_ERROR scError = SymCryptCallbackRandom( random, sizeof( random ) );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptCallbackRandom failed" );

    return encapsulateEx(
        random, sizeof(random),
        pbAgreedSecret, cbAgreedSecret,
        pbCiphertext, cbCiphertext );
}

template<>
NTSTATUS
KemImp<ImpLibcrux, AlgMlKem>::decapsulate(
    _In_reads_bytes_( cbCiphertext )        PCBYTE              pbCiphertext,
                                            SIZE_T              cbCiphertext,
    _Out_writes_bytes_( cbAgreedSecret )    PBYTE               pbAgreedSecret,
                                            SIZE_T              cbAgreedSecret )
{
    BYTE decapsulatedSecret[32];

    if(state.format == SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED)
    {
        switch(state.params)
        {
            case SYMCRYPT_MLKEM_PARAMS_MLKEM512:
                CHECK( cbCiphertext == 768, "Invalid ciphertext size" );
                libcrux_kyber_kyber512_decapsulate_unpacked(&(state.unpackedKey.key512.fst), (uint8_t (*)[768]) pbCiphertext, decapsulatedSecret);
                break;
            case SYMCRYPT_MLKEM_PARAMS_MLKEM768:
                CHECK( cbCiphertext == 1088, "Invalid ciphertext size" );
                libcrux_kyber_kyber768_decapsulate_unpacked(&(state.unpackedKey.key768.fst), (uint8_t (*)[1088]) pbCiphertext, decapsulatedSecret);
                break;
            case SYMCRYPT_MLKEM_PARAMS_MLKEM1024:
                CHECK( cbCiphertext == 1568, "Invalid ciphertext size" )
                libcrux_kyber_kyber1024_decapsulate_unpacked(&(state.unpackedKey.key1024.fst), (uint8_t (*)[1568]) pbCiphertext, decapsulatedSecret);
                break;
            default:
                CHECK( FALSE, "Invalid ML-KEM parameter set (key size)" );
                break;
        }
    }
    else if(state.format == SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY)
    {
        switch(state.params)
        {
            case SYMCRYPT_MLKEM_PARAMS_MLKEM512:
                CHECK( cbCiphertext == 768, "Invalid ciphertext size" );
                libcrux_kyber_kyber512_decapsulate(&(state.normalKey.key512.sk), (uint8_t (*)[768]) pbCiphertext, decapsulatedSecret);
                break;
            case SYMCRYPT_MLKEM_PARAMS_MLKEM768:
                CHECK( cbCiphertext == 1088, "Invalid ciphertext size" );
                libcrux_kyber_kyber768_decapsulate(&(state.normalKey.key768.sk), (uint8_t (*)[1088]) pbCiphertext, decapsulatedSecret);
                break;
            case SYMCRYPT_MLKEM_PARAMS_MLKEM1024:
                CHECK( cbCiphertext == 1568, "Invalid ciphertext size" )
                libcrux_kyber_kyber1024_decapsulate(&(state.normalKey.key1024.sk), (uint8_t (*)[1568]) pbCiphertext, decapsulatedSecret);
                break;
            default:
                CHECK( FALSE, "Invalid ML-KEM parameter set (key size)" );
                break;
        }
    }
    else
    {
        return STATUS_INVALID_PARAMETER;
    }

    memcpy( pbAgreedSecret, decapsulatedSecret, sizeof(decapsulatedSecret) );

    return STATUS_SUCCESS;
}

VOID
addLibcruxAlgs()
{
    addImplementationToGlobalList<KemImp<ImpLibcrux, AlgMlKem>>();
}

#endif // INCLUDE_IMPL_LIBCRUX