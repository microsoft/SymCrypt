//
// Test Hash-based Signatures
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"

extern
"C"
{
    VOID
    SYMCRYPT_CALL
    SymCryptHbsGetWinternitzLengths(
        UINT32  n,              // blob size in bytes
        UINT32  w,              // digit length in bits (Winternitz coefficient)
        _Out_   PUINT32 puLen1, // number of w-bit digits in n
        _Out_   PUINT32 puLen2  // number of w-bit digits to store the checksum <= len1 * (2^w - 1)
    );

    UINT32
    SymCryptCountLeadingZeros32( UINT32 value );
}

typedef struct _SYMCRYPT_WINTERNITZ_LENGTHS
{
    UINT32  n;
    UINT32  w;
    UINT32  len1;
    UINT32  len2;
} SYMCRYPT_WINTERNITZ_LENGTHS, * PSYMCRYPT_WINTERNITZ_LENGTHS;

//
// Precomputed digit counts in Excel
// 
// len1 = CEILING.MATH(8 * n / w)
// len2 = FLOOR.MATH(LOG(len1 * (POWER(2, w) - 1), 2) / w) + 1
//
static const SYMCRYPT_WINTERNITZ_LENGTHS _SymCryptWinternitzLengths[] = {

    //  n   w   len1    len2   
    {   24, 1,  192,    8   },
    {   24, 2,  96,     5   },
    {   24, 3,  64,     3   },
    {   24, 4,  48,     3   },
    {   24, 5,  39,     3   },
    {   24, 6,  32,     2   },
    {   24, 7,  28,     2   },
    {   24, 8,  24,     2   },

    {   32, 1,  256,    9   },
    {   32, 2,  128,    5   },
    {   32, 3,  86,     4   },
    {   32, 4,  64,     3   },
    {   32, 5,  52,     3   },
    {   32, 6,  43,     2   },
    {   32, 7,  37,     2   },
    {   32, 8,  32,     2   },

    {   64, 1,  512,    10  },
    {   64, 2,  256,    5   },
    {   64, 3,  171,    4   },
    {   64, 4,  128,    3   },
    {   64, 5,  103,    3   },
    {   64, 6,  86,     3   },
    {   64, 7,  74,     2   },
    {   64, 8,  64,     2   },
};

VOID
testWinternitzLengths()
{
    for (UINT32 i = 0; i < sizeof(_SymCryptWinternitzLengths) / sizeof(_SymCryptWinternitzLengths[0]); i++)
    {
        UINT32 len1, len2;

        SymCryptHbsGetWinternitzLengths(
            _SymCryptWinternitzLengths[i].n,
            _SymCryptWinternitzLengths[i].w,
            &len1,
            &len2);

        CHECK4( len1 == _SymCryptWinternitzLengths[i].len1,
                "Incorrect Winternitz digit count for len1: expecting %d got %d", 
                _SymCryptWinternitzLengths[i].len1,
                len1);

        CHECK4( len2 == _SymCryptWinternitzLengths[i].len2,
                "Incorrect Winternitz digit count for len2: expecting %d got %d",
                _SymCryptWinternitzLengths[i].len2,
                len2);
    }
}


class HbsMultiImp : public HbsImplementation
{
public:
    HbsMultiImp( String algName );
    virtual ~HbsMultiImp();

private:
    HbsMultiImp(const HbsMultiImp&);
    VOID operator=(const HbsMultiImp&);

public:

    typedef std::vector<HbsImplementation*> HbsImpPtrVector;

    HbsImpPtrVector m_imps;                    // Implementations we use

    HbsImpPtrVector m_comps;                   // Subset of m_imps; set of ongoing computations

    VOID addImplementation(HbsImplementation* pImp );
    VOID setImpName();

    virtual NTSTATUS setKey(UINT32, BOOL, PCBYTE, SIZE_T, BOOL);
    virtual NTSTATUS sign(PCBYTE, SIZE_T, PBYTE, SIZE_T);
    virtual NTSTATUS verify(PCBYTE, SIZE_T, PCBYTE, SIZE_T);
};

VOID
HbsMultiImp::setImpName()
{
    String sumAlgName;
    char* sepStr = "<";

    for (HbsImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i)
    {
        sumAlgName += sepStr + (*i)->m_algorithmName;
        sepStr = "+";
    }
    m_implementationName = sumAlgName + ">";
}

HbsMultiImp::HbsMultiImp(String algName)
{
    m_algorithmName = algName;

    getAllImplementations<HbsImplementation>(algName, &m_imps);
}

VOID
HbsMultiImp::addImplementation(HbsImplementation* pImp)
{
    m_imps.push_back(pImp);
    setImpName();
}


HbsMultiImp::~HbsMultiImp()
{
    //
    // Propagate the # KAT failures to the individual algorithms.
    //
    for (HbsImpPtrVector::iterator i = m_imps.begin(); i != m_imps.end(); ++i)
    {
        (*i)->m_nErrorKatFailure += m_nErrorKatFailure;
    }
}


NTSTATUS
HbsMultiImp::setKey(
    UINT32  uAlgId,
    BOOL    fMultitree,
    PCBYTE  pbSrc,
    SIZE_T  cbSrc,
    BOOL    fVerify )
{
    m_comps.clear();

    for (HbsImpPtrVector::const_iterator i = m_imps.begin(); i != m_imps.end(); ++i)
    {
        if ((*i)->setKey(uAlgId, fMultitree, pbSrc, cbSrc, fVerify) == STATUS_SUCCESS)
        {
            m_comps.push_back(*i);
        }
    }

    return m_comps.size() == 0 ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
}

NTSTATUS
HbsMultiImp::sign(
    PCBYTE  pbMsg,
    SIZE_T  cbMsg,
    PBYTE   pbSignature,
    SIZE_T  cbSignature )
{
    NTSTATUS status = STATUS_SUCCESS;
    ResultMerge res;
    PBYTE pbBuffer = NULL;
    
    pbBuffer = new BYTE[cbSignature];

    CHECK(pbBuffer != nullptr, "Memory allocation error");

    for (HbsImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i)
    {
        SymCryptWipe(pbBuffer, cbSignature);
        if ((*i)->sign(pbMsg, cbMsg, pbBuffer, cbSignature) != STATUS_SUCCESS)
        {
            CHECK(FALSE, "Signature generation error");
            continue;
        }
        res.addResult((*i), pbBuffer, cbSignature);
    }

    res.getResult(pbSignature, cbSignature);

    delete[] pbBuffer;

    return status;
}


NTSTATUS
HbsMultiImp::verify(
    PCBYTE  pbMsg,
    SIZE_T  cbMsg,
    PCBYTE  pbSignature,
    SIZE_T  cbSignature )
{
    NTSTATUS status = STATUS_SUCCESS;
    ResultMerge res;
    BYTE b[4];

    for (HbsImpPtrVector::const_iterator i = m_comps.begin(); i != m_comps.end(); ++i)
    {
        status = (*i)->verify(pbMsg, cbMsg, pbSignature, cbSignature);
        SYMCRYPT_STORE_MSBFIRST32(b, status);
        res.addResult((*i), b, 4);
    }

    res.getResult(b, 4);
    status = SYMCRYPT_LOAD_MSBFIRST32(b);
    return status;
}

VOID
testHbsVerify(
                            HbsImplementation*      pHbs,
                            UINT32                  AlgId,
                            BOOL                    fMultitree,
    _In_reads_(cbMsg)       PCBYTE                  pbMsg,
                            SIZE_T                  cbMsg,
    _In_reads_(cbPubkey)    PCBYTE                  pbPubkey,
                            SIZE_T                  cbPubkey,
    _In_reads_(cbSig)       PCBYTE                  pbSig,
                            SIZE_T                  cbSig,
                            LONGLONG                line )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(line);

    status = pHbs->setKey(AlgId, fMultitree, pbPubkey, cbPubkey, FALSE);
    CHECK3(status == STATUS_SUCCESS, "Hbs setKey failed for algid = %u", AlgId);

    status = pHbs->verify(pbMsg, cbMsg, pbSig, cbSig);
    CHECK3(status == STATUS_SUCCESS, "Hbs verify failed for algid = %u", AlgId);
}

VOID
testHbsSign(
                            HbsImplementation*  pHbs,
                            UINT32              AlgId,
                            BOOL                fMultitree,
    _In_reads_(cbMsg)       PCBYTE              pbMsg,
                            SIZE_T              cbMsg,
    _In_reads_(cbPrvkey)    PCBYTE              pbPrvkey,
                            SIZE_T              cbPrvkey,
    _In_reads_(cbSig)       PCBYTE              pbSig,
                            SIZE_T              cbSig,
                            LONGLONG            line )
{
    NTSTATUS status;
    PBYTE pbSig2 = nullptr;

    UNREFERENCED_PARAMETER(line);

    pbSig2 = new BYTE[cbSig];
    CHECK3(pbSig2 != nullptr, "Memory allocation failed for %u bytes", cbSig);

    status = pHbs->setKey(AlgId, fMultitree, pbPrvkey, cbPrvkey, FALSE);
    CHECK3(status == STATUS_SUCCESS, "Hbs setKey failed for algid = %u", AlgId);

    status = pHbs->sign(pbMsg, cbMsg, pbSig2, cbSig);
    CHECK3(status == STATUS_SUCCESS, "Hbs sign failed for algid = %u", AlgId);

    int bMatch = memcmp(pbSig, pbSig2, cbSig) == 0;
    CHECK3(bMatch == TRUE, "generated signature does not match the given one for alg id %d", AlgId);

    delete[] pbSig2;
}

VOID
testHbsKeygen(
                            HbsImplementation*  pHbs,
                            UINT32              AlgId,
                            BOOL                fMultitree,
    _In_reads_(cbPrvkey)    PCBYTE              pbPrvkey,
                            SIZE_T              cbPrvkey,
                            LONGLONG            line )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(line);

    status = pHbs->setKey(AlgId, fMultitree, pbPrvkey, cbPrvkey, TRUE);
    CHECK3(status == STATUS_SUCCESS, "Hbs setKey failed for algid = %u", AlgId);
}

VOID
testHbsKats()
{
    KatData* katHbs = getCustomResource("kat_hbs.dat", "KAT_HBS");
    KAT_ITEM katItem;

    static String g_currentCategory;
    BOOL skipData = TRUE;
    String sep = "    ";
    BOOL doneAnything = FALSE;

    std::unique_ptr<HbsMultiImp> pHbsMultiImp;

    while (1)
    {
        katHbs->getKatItem(&katItem);

        if (katItem.type == KAT_TYPE_END)
        {
            break;
        }

        if (katItem.type == KAT_TYPE_CATEGORY)
        {
            g_currentCategory = katItem.categoryName;
            
            pHbsMultiImp.reset(new HbsMultiImp(g_currentCategory));

            skipData = (pHbsMultiImp->m_imps.size() == 0);

            if (!skipData)
            {
                iprint("%s%s", sep.c_str(), g_currentCategory.c_str());
                sep = ", ";
                doneAnything = TRUE;
            }
        }

        if (skipData)
        {
            continue;
        }

        if (katItem.type == KAT_TYPE_DATASET)
        {
            if (katIsFieldPresent(katItem, "pubkey"))
            {
                //
                // Signature verification test
                //
                BOOL fMultitree = FALSE;
                UINT32 nExpectedItems = 4;

                if (katIsFieldPresent(katItem, "multitree"))
                {
                    fMultitree = katParseInteger(katItem, "multitree") > 0;
                    nExpectedItems++;
                }

                CHECK3(katItem.dataItems.size() == nExpectedItems, "Incorrect number of items in Hbs signature verification record ending at line %lld", katHbs->m_line);

                UINT32 algId = (UINT32)katParseInteger(katItem, "algid");
                BString katMsg = katParseData(katItem, "msg");
                BString katPubkey = katParseData(katItem, "pubkey");
                BString katSig = katParseData(katItem, "sig");
                
                testHbsVerify(
                    pHbsMultiImp.get(),
                    algId,
                    fMultitree,
                    (PCBYTE)katMsg.data(), 
                    katMsg.size(),
                    (PCBYTE)katPubkey.data(),
                    katPubkey.size(),
                    (PCBYTE)katSig.data(),
                    katSig.size(),
                    katHbs->m_line);

                continue;
            }

            
            if (katIsFieldPresent(katItem, "prvkey"))
            {
                if (katIsFieldPresent(katItem, "msg"))
                {
                    //
                    // Signature generation test
                    //
                    BOOL fMultitree = FALSE;
                    UINT32 nExpectedItems = 4;

                    if (katIsFieldPresent(katItem, "multitree"))
                    {
                        fMultitree = katParseInteger(katItem, "multitree") > 0;
                        nExpectedItems++;
                    }

                    CHECK3(katItem.dataItems.size() == nExpectedItems, "Incorrect number of items in Hbs signature verification record ending at line %lld", katHbs->m_line);

                    UINT32 algId = (UINT32)katParseInteger(katItem, "algid");
                    BString katMsg = katParseData(katItem, "msg");
                    BString katPrvkey = katParseData(katItem, "prvkey");
                    BString katSig = katParseData(katItem, "sig");

                    testHbsSign(
                        pHbsMultiImp.get(),
                        algId,
                        fMultitree,
                        (PCBYTE)katMsg.data(),
                        katMsg.size(),
                        (PCBYTE)katPrvkey.data(),
                        katPrvkey.size(),
                        (PCBYTE)katSig.data(),
                        katSig.size(),
                        katHbs->m_line);
                }
                else
                {
                    //
                    // Key generation test
                    //
                    BOOL fMultitree = FALSE;
                    UINT32 nExpectedItems = 2;

                    if (katIsFieldPresent(katItem, "multitree"))
                    {
                        fMultitree = katParseInteger(katItem, "multitree") > 0;
                        nExpectedItems++;
                    }

                    CHECK3(katItem.dataItems.size() == nExpectedItems, "Incorrect number of items in Hbs signature verification record ending at line %lld", katHbs->m_line);

                    UINT32 algId = (UINT32)katParseInteger(katItem, "algid");
                    BString katPrvkey = katParseData(katItem, "prvkey");

                    testHbsKeygen(
                        pHbsMultiImp.get(),
                        algId,
                        fMultitree,
                        (PCBYTE)katPrvkey.data(),
                        katPrvkey.size(),
                        katHbs->m_line);
                }

                continue;
            }
            
            FATAL2("Unknown data record ending at line %lld", katHbs->m_line);
        }
    }

    if (doneAnything)
    {
        iprint("\n");
    }

    delete katHbs;

}


VOID
testXmssCustomParameters()
{
    SYMCRYPT_XMSS_PARAMS params;
    PSYMCRYPT_XMSS_KEY pKey;
    PBYTE pbSignature;
    SYMCRYPT_ERROR scError;
    SIZE_T cbSignature;
    BYTE msg[] = { 0x00, 0x01, 0x03, 0x04 };
    PCSYMCRYPT_HASH pHash = SymCryptSha256Algorithm;

    //
    // Test varying Winternitz lengths with custom tree heights
    //
    for (UINT8 w = 1; w <= 8; w <<= 1)
    {
        for (UINT8 h = 1; h <= 4; h++)
        {
            ScDispatchSymCryptWipe(&params, sizeof(SYMCRYPT_XMSS_PARAMS));

            scError = ScDispatchSymCryptXmssSetParams(
                &params,
                0,                          // alg id
                pHash,                      // hash alg.
                (UINT8)pHash->resultSize,   // n
                w,                          // w
                h,                          // h
                (UINT8)1,                   // d
                (UINT8)pHash->resultSize);  // cbPrefix
            CHECK(scError == SYMCRYPT_NO_ERROR, "?");

            pKey = ScDispatchSymCryptXmsskeyAllocate(&params, 0);
            CHECK(pKey != nullptr, "?");

            scError = ScDispatchSymCryptXmsskeyGenerate(pKey, 0);
            CHECK(scError == SYMCRYPT_NO_ERROR, "?");

            cbSignature = ScDispatchSymCryptXmssSizeofSignatureFromParams(&params);
            pbSignature = new BYTE[cbSignature];
            CHECK(pbSignature != nullptr, "?");

            // Sign and Verify with each WOTSP key
            for (UINT32 idx = 0; idx < (1UL << h); idx++)
            {
                scError = ScDispatchSymCryptXmssSign(pKey, msg, sizeof(msg), 0, pbSignature, cbSignature);
                CHECK(scError == SYMCRYPT_NO_ERROR, "?");

                scError = ScDispatchSymCryptXmssVerify(pKey, msg, sizeof(msg), 0, pbSignature, cbSignature);
                CHECK(scError == SYMCRYPT_NO_ERROR, "?");

                // Modify the signature and expect verification failure
                UINT32 nModifyPos = g_rng.uint32() % cbSignature;
                pbSignature[nModifyPos] ^= 1;

                scError = ScDispatchSymCryptXmssVerify(pKey, msg, sizeof(msg), 0, pbSignature, cbSignature);
                CHECK(scError != SYMCRYPT_NO_ERROR, "?");
            }

            // All one-time signatures are consumed above, we shouldn't be able to sign anymore
            scError = ScDispatchSymCryptXmssSign(pKey, msg, sizeof(msg), 0, pbSignature, cbSignature);
            CHECK(scError == SYMCRYPT_HBS_NO_OTS_KEYS_LEFT, "?");

            delete[] pbSignature;

            ScDispatchSymCryptXmsskeyFree(pKey);
        }
    }
}


VOID
testXmssImportExport()
{
    SYMCRYPT_XMSS_PARAMS params;
    PSYMCRYPT_XMSS_KEY pKeyPrivate;
    PSYMCRYPT_XMSS_KEY pKeyPublic;
    SYMCRYPT_ERROR scError;
    PBYTE pbPrivateKeyBlob;
    PBYTE pbPublicKeyBlob;
    SIZE_T cbPrivateKey;
    SIZE_T cbPublicKey;
    PBYTE pbSignature;
    PBYTE pbSignature2;
    SIZE_T cbSignature;
    BYTE msg[] = { 0x01 };

    scError = ScDispatchSymCryptXmssParamsFromAlgId(SYMCRYPT_XMSS_SHA2_10_256, &params);
    CHECK(scError == SYMCRYPT_NO_ERROR, "?");

    // Create a private key
    pKeyPrivate = ScDispatchSymCryptXmsskeyAllocate(&params, 0);
    CHECK(pKeyPrivate != nullptr, "?");
    scError = ScDispatchSymCryptXmsskeyGenerate(pKeyPrivate, 0);
    CHECK(scError == SYMCRYPT_NO_ERROR, "?");

    scError = ScDispatchSymCryptXmssSizeofKeyBlobFromParams(&params, SYMCRYPT_XMSSKEY_TYPE_PUBLIC, &cbPublicKey);
    CHECK(scError == SYMCRYPT_NO_ERROR, "?");

    scError = ScDispatchSymCryptXmssSizeofKeyBlobFromParams(&params, SYMCRYPT_XMSSKEY_TYPE_PRIVATE, &cbPrivateKey);
    CHECK(scError == SYMCRYPT_NO_ERROR, "?");

    // Export private key
    pbPrivateKeyBlob = new BYTE[cbPrivateKey];
    CHECK(pbPrivateKeyBlob != nullptr, "?");
    scError = ScDispatchSymCryptXmsskeyGetValue(pKeyPrivate, SYMCRYPT_XMSSKEY_TYPE_PRIVATE, 0, pbPrivateKeyBlob, cbPrivateKey);
    CHECK(scError == SYMCRYPT_NO_ERROR, "?");

    // Export public key
    pbPublicKeyBlob = new BYTE[cbPublicKey];
    CHECK(pbPublicKeyBlob != nullptr, "?");
    scError = ScDispatchSymCryptXmsskeyGetValue(pKeyPrivate, SYMCRYPT_XMSSKEY_TYPE_PUBLIC, 0, pbPublicKeyBlob, cbPublicKey);
    CHECK(scError == SYMCRYPT_NO_ERROR, "?");

    // Sign and verify a message
    cbSignature = ScDispatchSymCryptXmssSizeofSignatureFromParams(&params);
    pbSignature = new BYTE[cbSignature];
    CHECK(pbSignature != nullptr, "?");

    scError = ScDispatchSymCryptXmssSign(pKeyPrivate, msg, sizeof(msg), 0, pbSignature, cbSignature);
    CHECK(scError == SYMCRYPT_NO_ERROR, "?");
    scError = ScDispatchSymCryptXmssVerify(pKeyPrivate, msg, sizeof(msg), 0, pbSignature, cbSignature);
    CHECK(scError == SYMCRYPT_NO_ERROR, "?");

    // Done with the original private key
    ScDispatchSymCryptXmsskeyFree(pKeyPrivate);

    // Import the private key from the key blob
    pKeyPrivate = ScDispatchSymCryptXmsskeyAllocate(&params, 0);
    CHECK(pKeyPrivate != nullptr, "?");
    scError = ScDispatchSymCryptXmsskeySetValue(pbPrivateKeyBlob, cbPrivateKey, SYMCRYPT_XMSSKEY_TYPE_PRIVATE, 0, pKeyPrivate);
    CHECK(scError == SYMCRYPT_NO_ERROR, "?");

    // Sign the message again with the imported private key and check if the same signature is produced
    pbSignature2 = new BYTE[cbSignature];
    CHECK(pbSignature2 != nullptr, "?");

    scError = ScDispatchSymCryptXmssSign(pKeyPrivate, msg, sizeof(msg), 0, pbSignature2, cbSignature);
    CHECK(scError == SYMCRYPT_NO_ERROR, "?");
    CHECK(memcmp(pbSignature, pbSignature2, cbSignature) == 0, "?");

    ScDispatchSymCryptXmsskeyFree(pKeyPrivate);

    // Import the public key and verify the signature
    pKeyPublic = ScDispatchSymCryptXmsskeyAllocate(&params, 0);
    CHECK(pKeyPublic != nullptr, "?");
    scError = ScDispatchSymCryptXmsskeySetValue(pbPublicKeyBlob, cbPublicKey, SYMCRYPT_XMSSKEY_TYPE_PUBLIC, 0, pKeyPublic);
    CHECK(scError == SYMCRYPT_NO_ERROR, "?");

    scError = ScDispatchSymCryptXmssVerify(pKeyPublic, msg, sizeof(msg), 0, pbSignature, cbSignature);
    CHECK(scError == SYMCRYPT_NO_ERROR, "?");

    ScDispatchSymCryptXmsskeyFree(pKeyPublic);

    delete[] pbSignature2;
    delete[] pbSignature;
    delete[] pbPublicKeyBlob;
    delete[] pbPrivateKeyBlob;
}


VOID
testXmssMultitree()
{
    SYMCRYPT_XMSS_PARAMS params;
    PSYMCRYPT_XMSS_KEY pKey;
    PBYTE pbSignature;
    SYMCRYPT_ERROR scError;
    SIZE_T cbSignature;
    BYTE msg[] = { 0x00, 0x01, 0x03, 0x04 };
    PCSYMCRYPT_HASH pHash = SymCryptSha256Algorithm;
    const UINT8 H = 6;
    const UINT8 LayerHeights[] = { 1, 2, 3 };

    //
    // Total tree height is 6
    //
    // Test all possible layer heights 1, 2, 3, corresponding to
    // number of layers 6, 3, 2.
    //

    for (UINT32 i = 0; i < sizeof(LayerHeights); i++)
    {
        scError = ScDispatchSymCryptXmssSetParams(
            &params,
            0,
            pHash,
            (UINT8)pHash->resultSize,
            (UINT8)4,
            H,
            (UINT8)(H / LayerHeights[i]),
            (UINT8)pHash->resultSize);
        CHECK(scError == SYMCRYPT_NO_ERROR, "?");

        pKey = ScDispatchSymCryptXmsskeyAllocate(&params, 0);
        CHECK(pKey != nullptr, "?");

        scError = ScDispatchSymCryptXmsskeyGenerate(pKey, 0);
        CHECK(scError == SYMCRYPT_NO_ERROR, "?");

        cbSignature = ScDispatchSymCryptXmssSizeofSignatureFromParams(&params);
        pbSignature = new BYTE[cbSignature];
        CHECK(pbSignature != nullptr, "?");

        // Sign and Verify with each WOTSP key
        for (UINT32 idx = 0; idx < (1UL << H); idx++)
        {
            scError = ScDispatchSymCryptXmssSign(pKey, msg, sizeof(msg), 0, pbSignature, cbSignature);
            CHECK(scError == SYMCRYPT_NO_ERROR, "?");

            scError = ScDispatchSymCryptXmssVerify(pKey, msg, sizeof(msg), 0, pbSignature, cbSignature);
            CHECK(scError == SYMCRYPT_NO_ERROR, "?");

            // Modify the signature and expect verification failure
            UINT32 nModifyPos = g_rng.uint32() % cbSignature;
            pbSignature[nModifyPos] ^= 1;

            scError = ScDispatchSymCryptXmssVerify(pKey, msg, sizeof(msg), 0, pbSignature, cbSignature);
            CHECK(scError != SYMCRYPT_NO_ERROR, "?");
        }

        // All one-time signatures are consumed above, we shouldn't be able to sign anymore
        scError = ScDispatchSymCryptXmssSign(pKey, msg, sizeof(msg), 0, pbSignature, cbSignature);
        CHECK(scError == SYMCRYPT_HBS_NO_OTS_KEYS_LEFT , "?");

        ScDispatchSymCryptXmsskeyFree(pKey);

        delete[] pbSignature;
    }
}

VOID
testXmss()
{
    testWinternitzLengths();    

    testXmssCustomParameters();

    testXmssMultitree();

    testXmssImportExport();
}


VOID
testHbs()
{
    testXmss();

    testHbsKats();
}