//
// MsBignum implementation classes
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

//
// Header files for msbignum
//


#include <msbignum.h>
#include <ms_rsa.h>
#include <ecurve.h>
#include <ms_generic_ecc.h>

class ImpMsBignum{
public:
    static char * name;
};

template<>
class RsaEncImpState<ImpMsBignum, AlgRsaEncRaw> {
public:
    SIZE_T      cbKey;      // Size of modulus
    RSA_PRIVATE_KEY key;
};

template<>
class DhImpState<ImpMsBignum, AlgDh> {
public:
    // TBD;
};
