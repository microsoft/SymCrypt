//
// SymCrypt implementation classes
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

//
// The Marvin API names use 'seed' instead of 'key'.
// Map them so that our infrastructure works
//
typedef SYMCRYPT_MARVIN32_EXPANDED_SEED SYMCRYPT_MARVIN32_EXPANDED_KEY, *PSYMCRYPT_MARVIN32_EXPANDED_KEY;

class ImpSc{
public:
    static char * name;
};

class ImpScStatic{
public:
    static char * name;
};

class ImpScDynamic{
public:
    static char * name;
};

#define IMP_Name Sc

#include "sc_implementations_pattern.h"

#undef IMP_Name

#define IMP_Name ScStatic

#include "sc_implementations_pattern.h"

#undef IMP_Name

#define IMP_Name ScDynamic

#include "sc_implementations_pattern.h"

#undef IMP_Name
