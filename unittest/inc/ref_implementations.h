//
// ref_implementations.h Header file for reference implementations
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

//
// Stub classes used as selector in templates. This class is never instantiated.
//
class ImpRef{
public:
    static char * name;
};

typedef struct _REF_POLY1305_STATE {
    PSYMCRYPT_MODULUS       pmMod;
    PSYMCRYPT_MODELEMENT    peAcc;
    PSYMCRYPT_MODELEMENT    peR;
    PSYMCRYPT_MODELEMENT    peData;
    PSYMCRYPT_INT           piS;
    PSYMCRYPT_INT           piAcc;      // Used for final addition

    BYTE                    block[17];
    SIZE_T                  bytesInBuffer;  
} REF_POLY1305_STATE, *PREF_POLY1305_STATE;



template<>
class MacImpState<ImpRef, AlgPoly1305> {
public:
    REF_POLY1305_STATE state;
};

